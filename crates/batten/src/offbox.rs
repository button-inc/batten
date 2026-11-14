//! Off-box session state: whether this machine can reach the state repository
//! (CLOUD-2717, CLOUD-2718).
//!
//! # Why this module exists
//!
//! Everything a session knows lives on one disk, and a reclaimed container loses
//! all of it. The store therefore has to be somewhere else: one repository for
//! the whole fleet, named by [`crate::session::STATE_REPO_ENV`]. This module is
//! the root of that chain — it reads the variable, derives the remote, and says
//! whether the remote can be written. Nothing here pushes, snapshots or restores.
//!
//! # Unset is inert
//!
//! The variable is the feature's only switch (ruling 2). Unset — or set to
//! nothing — [`status`] answers [`Status::Off`] before it derives a URL, makes a
//! network call or touches the state directory, so a machine that never asked for
//! the feature pays nothing for it and has nothing written under its name.
//!
//! # No repository is named here
//!
//! The remote is the project origin's scheme and host with the path replaced by
//! the variable's value. So the core carries no host and no repository name
//! (non-negotiable rule 1): both arrive from the clone and from the environment.
//! Only an `http` or `https` origin qualifies, because the transport is
//! [`crate::lease`]'s smart-HTTP and an `ssh` or local-path origin gives it no
//! host to speak to.
//!
//! # `unattached` cannot tell two causes apart
//!
//! Measured through an agent proxy on 2026-11-14: discovery answered `200` once
//! the repository was attached to the session, `403` before, and `403` for a
//! name that does not exist. So a refusal means "not attached, or misspelled",
//! and [`attach_note`] says both, along with both remedies — Batten cannot tell
//! a cloud container from a local machine either.
//!
//! # No gate
//!
//! An unreachable repository denies nothing (ruling 12). [`Status::code`] maps a
//! refusal to [`ExitCode::Usage`], never [`ExitCode::Violation`], and
//! `policy/module-layering.rego` forbids the `hook -> offbox` edge so no
//! mediated call can come to depend on a network answer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::Result;
use crate::exit::ExitCode;
use crate::gitwrite::{self, Content};
use crate::lease::{self, Service};
use crate::sessions::{Cursor, Fidelity, REPLACED, SessionRef, SessionSource};

/// The directory under [`crate::state::state_root`] the off-box feature owns.
///
/// Named here so the one writer and every reader spell it once. [`status`] never
/// creates it: the feature being off must leave no trace.
pub const DIR: &str = crate::offbox_watch::DIR;

/// What `batten offbox status` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The variable is unset or empty: the feature is off.
    Off,
    /// The variable is set and the project has no `http(s)` origin to derive a
    /// remote from.
    NoHttpOrigin,
    /// Discovery answered `401`, `403` or `404`: not attached, or misspelled.
    Unattached,
    /// Discovery answered `200`: the repository can be written.
    Attached,
}

impl Status {
    /// The one word printed on stdout — a token, never the remote's answer.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Status::Off => "off",
            Status::NoHttpOrigin => "no-http-origin",
            Status::Unattached => "unattached",
            Status::Attached => "attached",
        }
    }

    /// The exit this status leaves with.
    ///
    /// Never [`ExitCode::Violation`]: this is a diagnosis of the machine, not a
    /// policy verdict over the work, so no harness can read it as a deny.
    #[must_use]
    pub const fn code(self) -> ExitCode {
        match self {
            Status::Off | Status::Attached => ExitCode::Success,
            Status::NoHttpOrigin | Status::Unattached => ExitCode::Usage,
        }
    }
}

/// The state repository's URL: `origin`'s scheme and host, with the path
/// replaced by `value`.
///
/// `None` where `origin` is not `http(s)` or names no host. Any userinfo the
/// origin carries is dropped — the credential is [`crate::lease`]'s to attach,
/// and one copied out of a clone's config would travel into every error line
/// that names the remote.
#[must_use]
pub fn remote_for(origin: &str, value: &str) -> Option<String> {
    let (scheme, rest) = origin.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}/{}", value.trim_matches('/')))
}

/// Whether the state repository named by `value` can be written from here.
///
/// `value` is the variable as read, and `origin` the project origin's URL where
/// there is one. Both are passed in rather than read here so the decision is a
/// pure function of them plus one discovery call.
///
/// The probe is over receive-pack, because the question is whether this machine
/// can WRITE: a repository attached read-only answers upload-pack and would read
/// as attached to a feature that can never push to it.
///
/// # Errors
///
/// A transport failure, or a status that is none of `200`, `401`, `403` and
/// `404` — both could-not-look (exit `3`), never a refusal.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT unset-still-probes|s@^    if value.is_empty() {$@    if false {@|unset_is_off_and_makes_no_call
//MUTANT unattached-reads-attached|s@^        401 \x7c 403 \x7c 404 => Ok(Status::Unattached),$@        401 \x7c 403 \x7c 404 => Ok(Status::Attached),@|a_refused_discovery_is_unattached
//MUTANT transport-failure-reads-unattached|s@^    let answered = lease::probe(&remote, Service::ReceivePack)?;$@    let answered = lease::probe(\&remote, Service::ReceivePack).unwrap_or(403);@|a_transport_failure_is_an_error_and_never_a_refusal
//MUTANT attach-note-omits-the-repo|s@^    let repo = format!("the state repository {value}");$@    let repo = format!("the state repository{value:.0}");@|the_attach_note_names_the_repo_and_both_remedies
//MUTANT-SUITE crates/batten/tests/it/offbox_status.rs
//MUTANT unset-creates-the-state-dir|s@^    if value.is_empty() {$@    let _ = crate::state::state_root().map(\x7croot\x7c std::fs::create_dir_all(root.join(DIR))); if value.is_empty() {@|unset_is_off_and_leaves_no_directory
pub fn status(value: Option<&str>, origin: Option<&str>) -> Result<Status> {
    let value = value.map(str::trim).unwrap_or_default();
    if value.is_empty() {
        return Ok(Status::Off);
    }
    let Some(remote) = origin.and_then(|origin| remote_for(origin, value)) else {
        return Ok(Status::NoHttpOrigin);
    };
    let answered = lease::probe(&remote, Service::ReceivePack)?;
    match answered {
        200 => Ok(Status::Attached),
        401 | 403 | 404 => Ok(Status::Unattached),
        other => Err(anyhow::anyhow!(
            "offbox: state repository discovery answered {other}, which is neither attached nor a refusal"
        )),
    }
}

/// The one line that tells an agent how to get access to the repository `value`
/// names.
///
/// The same on every harness, and it says both remedies and the misspelling,
/// because a `403` is all three cases at once (see the module header).
#[must_use]
pub fn attach_note(value: &str) -> String {
    let repo = format!("the state repository {value}");
    format!(
        "offbox: {repo} cannot be written from here. \
         Attach it to this session with push access, or give this machine a git credential for it; \
         it may also be misspelled in `{}`.",
        crate::session::STATE_REPO_ENV
    )
}

// --- the snapshot (CLOUD-2719) -------------------------------------------------

/// The directory, under the per-checkout off-box directory, that holds one
/// directory per session.
const SESSIONS: &str = "sessions";

/// A session's local snapshot repository, inside its session directory.
const REPO: &str = "repo.git";

/// The ref, in a session's local repository, naming the commit last pushed or
/// absorbed. The push slice moves it; a snapshot only reads it.
pub const LAST: &str = "refs/offbox/last";

/// The file recording, for each feed, how far it has been shipped.
const CURSORS: &str = "cursor.json";

/// Scratch for redaction, removed on every path out.
const STAGING: &str = "staging";

/// The staged file new transcript records are redacted in before they are
/// appended to a segment.
pub const INCOMING: &str = "incoming.jsonl";

/// One mebibyte.
const MIB: u64 = 1024 * 1024;

/// A segment file is closed at the first record boundary at or past this.
const SEGMENT: u64 = MIB;

/// A record larger than this is cut into files of this size. GitHub refuses an
/// object over 100 MB, and this keeps every file under it.
const PART: usize = 50 * 1024 * 1024;

/// How many record bytes are asked of a source at a time, whatever the cap.
const READ: u64 = 8 * MIB;

/// The entries of the state directory that are stores. An allow-list of one:
/// everything else there is rebuilt (`provision/`, `cache/`) or is this
/// feature's own working state.
const STATE_STORES: [&str; 1] = ["captures"];

/// The prefix every store in the project's git directory carries.
const GIT_STORE_PREFIX: &str = "batten-";

/// `batten-*` entries of the git directory that are NOT stores: two locks, a
/// per-process ledger, a pid registry, and this module's own request file. An
/// exclude-list, so a store added later is included by default.
const GIT_EXCLUDED: [&str; 5] = [
    "batten-singleton",
    "batten-mcp-spawns",
    "batten-land-lock",
    "batten-tasks",
    "batten-push-",
];

/// The tree roots whose files are only ever added, never rewritten: carried
/// forward file by file, where a store is carried forward whole.
const APPENDED: [&str; 3] = ["transcript", "history", "absorbed"];

/// Who a snapshot belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// The harness's name.
    pub harness: String,
    /// The real session id, as the harness spells it.
    pub session: String,
    /// The project origin's path, `<owner>/<name>`.
    pub origin: String,
}

/// One session whose records go into a snapshot.
#[allow(missing_debug_implementations)]
pub struct Feed<'a> {
    /// Where its records go in the tree: `transcript/<key>` for the live
    /// session, `history/<leaf>/transcript/<key>` for an imported one.
    pub prefix: String,
    /// Where its records come from.
    pub source: &'a dyn SessionSource,
    /// Which of the source's sessions it is.
    pub session: SessionRef,
}

/// Why no snapshot was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The pinned scanner is not declared or not installed.
    ScannerAbsent,
    /// The scanner ran and its answer could not be trusted.
    ScannerFailed,
}

/// What [`snapshot`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Snapshot {
    /// One orphan commit in the session's local repository.
    Built {
        /// The commit.
        commit: String,
        /// Its tree, which is what tells two snapshots apart: it does not
        /// depend on the commit time.
        tree: String,
        /// The record bytes this call appended.
        new_bytes: u64,
        /// How many spans were replaced by a marker.
        spans_redacted: usize,
        /// The feed prefixes whose last read returned no further record.
        ended: Vec<String>,
    },
    /// Nothing was committed: nothing unredacted may be.
    Refused(Refusal),
}

/// The last segment of a session's ref, and the name of its local directory:
/// `<harness>-<hash>`, the hash being the first sixteen hex digits of the
/// BLAKE3 of the session id. Session ids are harness-defined and may not be
/// valid in a ref name; a digest always is.
#[must_use]
pub fn leaf(harness: &str, session: &str) -> String {
    crate::offbox_watch::leaf(harness, session)
}

/// Where a session's local snapshot files live:
/// `<repo_state_dir>/offbox/sessions/<leaf>/`.
///
/// **Per session, because the ref is.** A later session in the same checkout
/// starts with an empty directory and inherits none of the earlier one's
/// transcript, cursors or last-pushed commit.
///
/// # Errors
///
/// A project root whose state directory cannot be named.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT session-files-shared-across-sessions|s@^        .join(leaf(\&meta.harness, \&meta.session)))$@        .join("shared"))@|a_second_session_in_one_checkout_gets_its_own_directory
pub fn session_dir(project_root: &Path, meta: &Meta) -> Result<PathBuf> {
    Ok(crate::state::repo_state_dir(project_root)?
        .join(DIR)
        .join(SESSIONS)
        .join(leaf(&meta.harness, &meta.session)))
}

/// A session's local bare repository.
#[must_use]
pub fn local_repo(session_dir: &Path) -> PathBuf {
    session_dir.join(REPO)
}

/// How far one feed has been shipped: the source's own cursor, and the segment
/// file and byte length the records before that cursor reached.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Position {
    /// The source's cursor, hex-encoded: it is opaque bytes.
    cursor: String,
    /// Which directory of segments is being written. It goes up when a source
    /// is replaced, and the old generation's files stay.
    generation: u64,
    /// The segment file being appended to, if any has been started.
    file: Option<String>,
    /// How long that file is, as far as this cursor covers.
    length: u64,
    /// Why the source could not be read in full, where it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fidelity: Option<String>,
}

type Cursors = BTreeMap<String, Position>;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok())
        .collect()
}

fn load_cursors(dir: &Path) -> Cursors {
    std::fs::read(dir.join(CURSORS))
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .unwrap_or_default()
}

fn cursors_bytes(cursors: &Cursors) -> Result<Vec<u8>> {
    let mut body = serde_json::to_vec_pretty(cursors)
        .map_err(|err| anyhow::anyhow!("offbox: the cursor file will not serialise: {err}"))?;
    body.push(b'\n');
    Ok(body)
}

fn persist(dir: &Path, cursors: &Cursors) -> Result<()> {
    crate::durable::replace(dir.join(CURSORS), cursors_bytes(cursors)?)
        .map_err(|err| anyhow::anyhow!("offbox: the cursor file will not write: {err}"))
}

/// Every regular file under `root`, as its `/`-separated path relative to
/// `root` and where it is. Sorted, and a link is never followed or listed.
fn files_under(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    let mut pending = vec![(String::new(), root.to_path_buf())];
    while let Some((prefix, next)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push((relative, entry.path())),
                Ok(kind) if kind.is_file() => found.push((relative, entry.path())),
                _ => {}
            }
        }
    }
    found.sort();
    found
}

/// A segment file's number, off its `NNNNNN.<ext>` name.
fn segment_index(name: &str) -> Option<u64> {
    name.split('.').next()?.parse().ok()
}

/// Put a feed's segment files back to what its cursor entry covers: a file
/// longer than the entry says is cut to that length, and a file the entry does
/// not reach is removed.
///
/// **This is what makes a kill harmless.** Records are appended first and the
/// cursor is replaced after, so a crash leaves bytes the cursor does not cover
/// — bytes the source will hand back, because the source's cursor did not move
/// either. Cutting them is what stops a record being stored twice.
fn recover(dir: &Path, prefix: &str, position: &Position) -> Result<()> {
    let generation = dir.join(prefix).join(position.generation.to_string());
    let current = position.file.as_deref().and_then(segment_index);
    for (name, path) in files_under(&generation) {
        let Some(index) = segment_index(&name) else {
            continue;
        };
        let refused =
            |err: std::io::Error| anyhow::anyhow!("offbox: a segment will not be put back: {err}");
        match current {
            Some(current) if index < current => {}
            Some(current) if index == current => {
                if std::fs::metadata(&path).map_err(refused)?.len() > position.length {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .map_err(refused)?
                        .set_len(position.length)
                        .map_err(refused)?;
                }
            }
            _ => std::fs::remove_file(&path).map_err(refused)?,
        }
    }
    Ok(())
}

/// Append `stream` — records, each followed by a newline — to a feed's segment
/// files, and return how many bytes were written.
///
/// A file is closed at the first record boundary at or past [`SEGMENT`]. A
/// record larger than [`PART`] starts a new file and is cut every [`PART`]
/// bytes; a file that does not end at a record boundary is named `.part`.
/// Concatenating a generation's files in name order gives the stream back
/// exactly. A file already has its final name while it is being appended to,
/// and a closed file is never written again — so its blob id is stable and it
/// is sent once.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT closed-segment-rewritten|s@^            .filter(\x7cname\x7c name.ends_with(".jsonl") \&\& position.length < SEGMENT);$@            .filter(\x7cname\x7c name.ends_with(".jsonl"));@|the_tree_holds_the_stores_and_the_transcript_in_segments
//MUTANT oversized-record-replaced-by-a-digest|s@^            for (at, chunk) in piece.chunks(PART).enumerate() {$@            for (at, chunk) in piece.chunks(PART).take(1).enumerate() {@|an_oversized_record_is_cut_into_parts_and_never_replaced
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the names compared are this function's own, written three lines below in lower case"
)]
fn append_stream(dir: &Path, prefix: &str, position: &mut Position, stream: &[u8]) -> Result<u64> {
    use std::io::Write as _;

    let generation = dir.join(prefix).join(position.generation.to_string());
    let refused = |err: std::io::Error| anyhow::anyhow!("offbox: a segment will not write: {err}");
    std::fs::create_dir_all(&generation).map_err(refused)?;
    let mut next = position
        .file
        .as_deref()
        .and_then(segment_index)
        .map_or(0, |index| index + 1);
    let mut written = 0_u64;
    for piece in stream.split_inclusive(|byte| *byte == b'\n') {
        if piece.len() > PART {
            let parts = piece.len().div_ceil(PART);
            for (at, chunk) in piece.chunks(PART).enumerate() {
                let ending = if at + 1 == parts { "jsonl" } else { "part" };
                let name = format!("{next:06}.{ending}");
                next += 1;
                std::fs::write(generation.join(&name), chunk).map_err(refused)?;
                position.file = Some(name);
                position.length = chunk.len() as u64;
                written += chunk.len() as u64;
            }
            continue;
        }
        let open = position
            .file
            .clone()
            .filter(|name| name.ends_with(".jsonl") && position.length < SEGMENT);
        let name = open.unwrap_or_else(|| {
            let name = format!("{next:06}.jsonl");
            next += 1;
            position.length = 0;
            name
        });
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(generation.join(&name))
            .map_err(refused)?;
        file.write_all(piece).map_err(refused)?;
        position.file = Some(name);
        position.length += piece.len() as u64;
        written += piece.len() as u64;
    }
    Ok(written)
}

/// Redact `paths` under `staging`, sorting a failure into the two refusals.
///
/// A usage error is the scanner not being there; anything else is the scanner
/// having run and its answer not being trustworthy. Neither may be read as
/// "nothing to redact".
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT scanner-failure-still-builds|s@^        Err(_) => Err(Refusal::ScannerFailed),$@        Err(_) => Ok(0),@|a_missing_or_failing_scanner_refuses_and_writes_nothing
fn scrub(
    provisions: &[crate::provision::Provision],
    project_root: &Path,
    staging: &Path,
    paths: &[String],
) -> std::result::Result<usize, Refusal> {
    match crate::secrets::redact(provisions, project_root, staging, paths) {
        Ok(spans) => Ok(spans),
        Err(err) if err.downcast_ref::<crate::error::UsageError>().is_some() => {
            Err(Refusal::ScannerAbsent)
        }
        Err(_) => Err(Refusal::ScannerFailed),
    }
}

/// The store a tree path belongs to: its first two segments, for a path under
/// `state/` or `git/`. A store moves whole, so this is the unit a carry-forward
/// decides over.
fn store_of(path: &str) -> Option<&str> {
    if !path.starts_with("state/") && !path.starts_with("git/") {
        return None;
    }
    let second = path.match_indices('/').nth(1).map(|(at, _)| at);
    Some(second.map_or(path, |at| &path[..at]))
}

/// Whether a `batten-*` entry of the git directory is one of the few that are
/// not stores.
fn git_excluded(entry: &str) -> bool {
    GIT_EXCLUDED
        .iter()
        .any(|name| entry == *name || (name.ends_with('-') && entry.starts_with(name)))
}

/// Every store file this checkout has, as its tree path and where it is.
///
/// `state/<entry>/…` from the state directory, by allow-list; `git/<entry>/…`
/// from the project's per-worktree git directory, by exclude-list.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT provision-dir-included|s@^            if !STATE_STORES.contains(\&entry.as_str()) {$@            if false {@|the_tree_holds_the_stores_and_the_transcript_in_segments
//MUTANT lock-entry-included|s@^            if excluded \x7c\x7c relative.ends_with(".lock") {$@            if excluded {@|the_tree_holds_the_stores_and_the_transcript_in_segments
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "a lock is named by the code that takes it, always `.lock` in lower case"
)]
fn store_files(project_root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    if let Ok(state) = crate::state::repo_state_dir(project_root) {
        for (relative, path) in files_under(&state) {
            let entry = relative.split('/').next().unwrap_or_default().to_owned();
            if !STATE_STORES.contains(&entry.as_str()) {
                continue;
            }
            // A lock is never content, wherever it sits.
            if relative.ends_with(".lock") {
                continue;
            }
            found.push((format!("state/{relative}"), path));
        }
    }
    if let Ok(git) = crate::git::git_dir(project_root) {
        for (relative, path) in files_under(&git) {
            let entry = relative.split('/').next().unwrap_or_default();
            if !entry.starts_with(GIT_STORE_PREFIX) {
                continue;
            }
            let excluded = git_excluded(entry);
            if excluded || relative.ends_with(".lock") {
                continue;
            }
            found.push((format!("git/{relative}"), path));
        }
    }
    found.sort();
    found
}

/// The size of every local segment file that is not in the last snapshot's
/// tree: what a push that was not applied has left waiting.
fn pending_bytes(dir: &Path, last: &BTreeMap<String, String>) -> u64 {
    APPENDED
        .iter()
        .flat_map(|root| {
            files_under(&dir.join(root))
                .into_iter()
                .map(move |(relative, path)| (format!("{root}/{relative}"), path))
        })
        .filter(|(tree_path, _)| !last.contains_key(tree_path))
        .filter_map(|(_, path)| std::fs::metadata(path).ok())
        .map(|meta| meta.len())
        .sum()
}

/// Build one snapshot of a session as an orphan commit in its local repository
/// (CLOUD-2719).
///
/// The tree is `meta.json`, `cursor.json`, every store under `state/` and
/// `git/` whole, and the session's records under `transcript/` and `history/`
/// in immutable segment files, with whatever another writer left under
/// `absorbed/`.
///
/// **Each snapshot holds everything the previous one held**, which is what
/// makes replacing the session's ref safe. A store that is absent locally is
/// carried forward whole from the last snapshot by blob id; a store that exists
/// is taken as it is now, so a file the store removed itself is gone. Segment,
/// history and absorbed files are never rewritten, so those are carried forward
/// file by file.
///
/// **Nothing unredacted is committed.** The stores are copied to a staging
/// directory and redacted on every call, and new records are redacted once,
/// whole, before they are cut into segments. The stores go first: a scanner
/// that is absent or fails refuses the snapshot before any cursor entry is
/// written or any record read.
///
/// **This function reads no clock.** `time` is the commit time, and `byte_cap`
/// the most new record bytes this call may add — counted together with what an
/// unapplied push has already left waiting, so a snapshot never grows past the
/// cap between two applied pushes. Stores are always included whole.
///
/// # Errors
///
/// A file that will not read or write, or a repository that will not take the
/// commit. A scanner that is absent or fails is not an error: it is
/// [`Snapshot::Refused`].
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT unredacted-bytes-committed|s@^            let redacted = std::fs::read(staging.join(INCOMING)).map_err(unread)?;$@            let redacted = stream;@|matched_spans_are_redacted_in_stores_and_records
//MUTANT cursor-entry-written-after-the-first-append|s@^    persist(\&dir, \&cursors)?; // every feed has its entry before any append$@@|a_killed_append_is_cut_back_and_no_record_is_stored_twice
//MUTANT unread-feed-has-no-cursor-entry|s@^        cursors.entry(feed.prefix.clone()).or_default();$@@|a_feed_the_cap_never_reached_still_has_a_cursor_entry
//MUTANT cap-ignores-pending-bytes|s@^    let pending = pending_bytes(\&dir, \&last);$@    let pending = 0;@|the_byte_cap_counts_what_an_unapplied_push_left_waiting
//MUTANT crash-tail-kept-and-reread|s@^        recover(\&dir, \&feed.prefix, \&position)?;$@@|a_killed_append_is_cut_back_and_no_record_is_stored_twice
//MUTANT replaced-source-overwrites-its-generation|s@^                    position.generation += 1;$@@|a_replaced_source_starts_a_new_generation
//MUTANT second-snapshot-drops-a-path|s@^        if appended \x7c\x7c absent_store {$@        if absent_store {@|a_second_snapshot_holds_everything_the_first_did
//MUTANT locally-deleted-store-dropped|s@^        if appended \x7c\x7c absent_store {$@        if appended {@|a_store_deleted_locally_is_carried_forward_whole
//MUTANT file-a-store-removed-is-resurrected|s@^        if appended \x7c\x7c absent_store {$@        if appended \x7c\x7c store.is_some() {@|a_file_a_store_removed_itself_stays_removed
pub fn snapshot(
    project_root: &Path,
    provisions: &[crate::provision::Provision],
    meta: &Meta,
    feeds: &[Feed<'_>],
    time: i64,
    byte_cap: u64,
) -> Result<Snapshot> {
    let dir = session_dir(project_root, meta)?;
    let repo = local_repo(&dir);
    let staging = dir.join(STAGING);
    let unwritten =
        |err: std::io::Error| anyhow::anyhow!("offbox: a snapshot file will not write: {err}");
    let unread =
        |err: std::io::Error| anyhow::anyhow!("offbox: a snapshot file will not read: {err}");
    std::fs::create_dir_all(&dir).map_err(unwritten)?;
    gitwrite::init_bare(&repo)?;
    // A staging directory a killed call left behind is scratch, never content.
    let _ = std::fs::remove_dir_all(&staging);
    let outcome = build(
        project_root,
        provisions,
        meta,
        feeds,
        (time, byte_cap),
        (&dir, &repo, &staging),
        (&unwritten, &unread),
    );
    let _ = std::fs::remove_dir_all(&staging);
    outcome
}

/// [`snapshot`]'s body, apart from it so the staging directory is removed on
/// every path out — a refusal and an error as much as a build.
#[allow(clippy::too_many_lines)]
fn build(
    project_root: &Path,
    provisions: &[crate::provision::Provision],
    meta: &Meta,
    feeds: &[Feed<'_>],
    (time, byte_cap): (i64, u64),
    (dir, repo, staging): (&Path, &Path, &Path),
    (unwritten, unread): (
        &dyn Fn(std::io::Error) -> anyhow::Error,
        &dyn Fn(std::io::Error) -> anyhow::Error,
    ),
) -> Result<Snapshot> {
    let dir = dir.to_path_buf();
    let last_commit = crate::git::resolve_ref(repo, LAST)?;
    let last: BTreeMap<String, String> = match last_commit.as_deref() {
        Some(commit) => gitwrite::tree_index(repo, commit)?.into_iter().collect(),
        None => BTreeMap::new(),
    };
    let mut entries: BTreeMap<String, Content> = BTreeMap::new();
    let mut spans_redacted = 0_usize;

    // THE STORES FIRST, AND `meta.json` WITH THEM, so the scanner has run — or
    // refused — before any cursor entry is written or any record is read.
    let meta_body = serde_json::to_vec_pretty(&serde_json::json!({
        "harness": meta.harness,
        "session": meta.session,
        "origin": meta.origin,
        "writer": env!("CARGO_PKG_VERSION"),
    }))
    .map_err(|err| anyhow::anyhow!("offbox: the snapshot's meta will not serialise: {err}"))?;
    let stores = store_files(project_root);
    let mut staged: Vec<String> = vec![String::from("meta.json")];
    std::fs::create_dir_all(staging).map_err(unwritten)?;
    std::fs::write(staging.join("meta.json"), &meta_body).map_err(unwritten)?;
    for (tree_path, source) in &stores {
        let target = staging.join(tree_path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(unwritten)?;
        }
        std::fs::copy(source, &target).map_err(unread)?;
        staged.push(tree_path.clone());
    }
    match scrub(provisions, project_root, staging, &staged) {
        Ok(spans) => spans_redacted += spans,
        Err(refusal) => return Ok(Snapshot::Refused(refusal)),
    }
    let local_stores: BTreeSet<String> = stores
        .iter()
        .filter_map(|(tree_path, _)| store_of(tree_path).map(str::to_owned))
        .collect();
    for tree_path in &staged {
        let bytes = std::fs::read(staging.join(tree_path)).map_err(unread)?;
        let id = gitwrite::write_blob(repo, &bytes)?;
        entries.insert(tree_path.clone(), Content::Blob(id));
    }

    // EVERY FEED GIVEN GETS A CURSOR ENTRY BEFORE ANY BYTE OF IT IS APPENDED,
    // so a directory holding segment files and no entry can only have come
    // from another writer.
    let mut cursors = load_cursors(&dir);
    for feed in feeds {
        cursors.entry(feed.prefix.clone()).or_default();
    }
    persist(&dir, &cursors)?; // every feed has its entry before any append

    let pending = pending_bytes(&dir, &last);
    let mut added = 0_u64;
    let mut ended = Vec::new();
    for feed in feeds {
        if pending + added >= byte_cap {
            // The cap is spent: a feed not reached keeps the entry it was given.
            break;
        }
        let mut position = cursors.get(&feed.prefix).cloned().unwrap_or_default();
        recover(&dir, &feed.prefix, &position)?;
        while pending + added < byte_cap {
            let room = (byte_cap - pending - added).min(READ);
            let batch = feed
                .source
                .read(&feed.session, &Cursor(unhex(&position.cursor)), room)?;
            match batch.fidelity {
                Fidelity::Unavailable(token) => {
                    position.fidelity = Some(token.to_owned());
                    break;
                }
                Fidelity::Partial(token) if token == REPLACED => {
                    // A NEW DIRECTORY, AND THE OLD ONE STAYS: what was read
                    // from the file that is gone is still the session's.
                    position.generation += 1;
                    position.cursor = hex(&batch.cursor.0);
                    position.file = None;
                    position.length = 0;
                    position.fidelity = None;
                    cursors.insert(feed.prefix.clone(), position.clone());
                    persist(&dir, &cursors)?;
                    continue;
                }
                Fidelity::Partial(token) => position.fidelity = Some(token.to_owned()),
                Fidelity::Full => position.fidelity = None,
            }
            if batch.records.is_empty() {
                if batch.fidelity == Fidelity::Full {
                    ended.push(feed.prefix.clone());
                }
                break;
            }
            // REDACTED WHOLE, BEFORE IT IS CUT, so a span cannot straddle two
            // files unseen.
            let mut stream = Vec::new();
            for record in &batch.records {
                stream.extend_from_slice(&record.bytes);
                stream.push(b'\n');
            }
            std::fs::write(staging.join(INCOMING), &stream).map_err(unwritten)?;
            match scrub(provisions, project_root, staging, &[String::from(INCOMING)]) {
                Ok(spans) => spans_redacted += spans,
                Err(refusal) => return Ok(Snapshot::Refused(refusal)),
            }
            let redacted = std::fs::read(staging.join(INCOMING)).map_err(unread)?;
            // APPENDED FIRST, THE CURSOR REPLACED AFTER: a kill between the two
            // leaves bytes `recover` cuts, never a cursor past what is stored.
            added += append_stream(&dir, &feed.prefix, &mut position, &redacted)?;
            position.cursor = hex(&batch.cursor.0);
            cursors.insert(feed.prefix.clone(), position.clone());
            persist(&dir, &cursors)?;
        }
        cursors.insert(feed.prefix.clone(), position);
    }
    persist(&dir, &cursors)?;
    entries.insert(
        String::from(CURSORS),
        Content::Blob(gitwrite::write_blob(repo, &cursors_bytes(&cursors)?)?),
    );

    // THE APPENDED ROOTS, one file at a time. A file the last snapshot already
    // holds, and that no feed is still appending to, is named by the id it had:
    // it is never rewritten, so it is never read again.
    let open: BTreeSet<String> = cursors
        .iter()
        .filter_map(|(prefix, position)| {
            let file = position.file.as_ref()?;
            Some(format!("{prefix}/{}/{file}", position.generation))
        })
        .collect();
    for root in APPENDED {
        for (relative, path) in files_under(&dir.join(root)) {
            let tree_path = format!("{root}/{relative}");
            let fresh = open.contains(&tree_path) || !last.contains_key(&tree_path);
            let id = if fresh {
                gitwrite::write_blob(repo, &std::fs::read(&path).map_err(unread)?)?
            } else {
                last.get(&tree_path).cloned().unwrap_or_default()
            };
            entries.insert(tree_path, Content::Blob(id));
        }
    }

    // CARRIED FORWARD. Per file for the appended roots; per STORE for the rest,
    // and only for a store that is absent locally altogether.
    for (path, id) in &last {
        if entries.contains_key(path) || foreign(&dir, last_commit.as_deref(), path) {
            continue;
        }
        let appended = APPENDED
            .iter()
            .any(|root| path.starts_with(&format!("{root}/")));
        let store = store_of(path);
        let absent_store = store.is_some_and(|store| !local_stores.contains(store));
        if appended || absent_store {
            entries.insert(path.clone(), Content::Blob(id.clone()));
        }
    }

    let listed: Vec<(String, Content)> = entries.into_iter().collect();
    let (commit, tree) = gitwrite::commit_tree(repo, &listed, &[], time, "snapshot")?;
    Ok(Snapshot::Built {
        commit,
        tree,
        new_bytes: added,
        spans_redacted,
        ended,
    })
}

// --- the push (CLOUD-2720) -----------------------------------------------------

/// The most new record bytes one push may add.
pub const BYTE_CAP: u64 = 100 * MIB;

/// The harness name whose source is the one file `--transcript` names.
const NEUTRAL: &str = "exit-code";

/// How many times one call tries the swap before it reports contention.
const ATTEMPTS: usize = 3;

/// The file recording how far this session's own ref has got: the
/// `cursor.json` of the snapshot last applied.
pub const PUSHED: &str = "pushed.json";

/// The directory another writer's content is kept under, keyed by the commit it
/// came from — locally and in the tree alike.
const ABSORBED: &str = "absorbed";

/// The path of an http(s) origin, `<owner>/<name>`: what a session's ref is
/// keyed by. `None` for any other origin, [`remote_for`]'s way.
#[must_use]
pub fn origin_path(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let (_, path) = rest.split_once('/')?;
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    (!path.is_empty()).then(|| path.to_owned())
}

/// The ref a session's snapshots are the value of:
/// `refs/heads/session/<owner>/<name>/<harness>-<hash>`.
///
/// The session id never appears in it — [`leaf`] is a digest — so an id no ref
/// name could carry still gives a valid one. The real id is in `meta.json`.
#[must_use]
pub fn reference(meta: &Meta) -> String {
    format!(
        "refs/heads/session/{}/{}",
        meta.origin,
        leaf(&meta.harness, &meta.session)
    )
}

/// One session, as a push needs it.
#[allow(missing_debug_implementations)]
pub struct Session<'a> {
    /// The project's root directory.
    pub project_root: &'a Path,
    /// The scanner's provision rows, loaded at the verb's entry.
    pub provisions: &'a [crate::provision::Provision],
    /// Whose snapshot it is.
    pub meta: Meta,
    /// The state repository's URL.
    pub remote: String,
    /// The transcript path the harness named, where it named one.
    pub transcript: Option<PathBuf>,
    /// The commit time, read at the caller's boundary.
    pub time: i64,
}

/// What one push came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// The swap was applied: the session's ref now names this snapshot.
    Applied,
    /// The remote already holds this snapshot; nothing was sent.
    Unchanged,
    /// The swap was rejected on every attempt.
    Contended,
    /// The forge said to slow down. Nothing waits here: the caller owns the wait.
    Throttled(lease::Throttled),
    /// Discovery answered that this machine may not write the repository.
    Unattached,
    /// No snapshot was built, so nothing unredacted was sent.
    Refused(Refusal),
}

impl Pushed {
    /// The one stdout token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Pushed::Applied => "pushed",
            Pushed::Unchanged => "unchanged",
            Pushed::Contended => "contended",
            Pushed::Throttled(_) => "throttled",
            Pushed::Unattached => Status::Unattached.token(),
            Pushed::Refused(_) => "no-scanner",
        }
    }

    /// The exit that goes with it. A lost race and a throttle are the one
    /// verdict this verb has: the state is not off this machine yet.
    #[must_use]
    pub const fn code(self) -> ExitCode {
        match self {
            Pushed::Applied | Pushed::Unchanged => ExitCode::Success,
            Pushed::Contended | Pushed::Throttled(_) => ExitCode::Violation,
            Pushed::Unattached | Pushed::Refused(_) => ExitCode::Usage,
        }
    }
}

/// A push's outcome, with the feeds whose last read returned no further record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// What happened.
    pub outcome: Pushed,
    /// The snapshot's `ended` list; empty where no snapshot was built.
    pub ended: Vec<String>,
}

impl Push {
    fn only(outcome: Pushed) -> Self {
        Push {
            outcome,
            ended: Vec::new(),
        }
    }
}

/// `Ok(throttle)` where `err` is the forge saying slow down, `err` back
/// otherwise: a throttle is an outcome here, never a failure.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT throttled-probe-reads-as-failure|s@^        Some(throttled) => Ok(Push::only(Pushed::Throttled(\*throttled))),$@        Some(_) => Err(err),@|a_throttled_probe_is_throttled_and_sends_nothing
fn throttled(err: anyhow::Error) -> Result<Push> {
    match err.downcast_ref::<lease::Throttled>() {
        Some(throttled) => Ok(Push::only(Pushed::Throttled(*throttled))),
        None => Err(err),
    }
}

/// A path segment for a subagent's sub-key: its own characters where a path and
/// a ref can carry them, `_` where they cannot.
fn segment(sub: &str) -> String {
    let cleaned: String = sub
        .chars()
        .map(|each| {
            if each.is_ascii_alphanumeric() || matches!(each, '-' | '_' | '.') {
                each
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.trim_matches('.').is_empty() {
        String::from("_")
    } else {
        cleaned
    }
}

/// The feeds of one push: the session's own, from its harness's source, then
/// `extra` in the order given.
fn feeds_of<'a>(
    session: &Session<'_>,
    source: Option<&'a dyn SessionSource>,
    extra: &[Feed<'a>],
) -> Result<Vec<Feed<'a>>> {
    let mut feeds: Vec<Feed<'_>> = Vec::new();
    if let Some(source) = source {
        let listed = match source.list() {
            Ok(listed) => listed,
            // A source that cannot be read gives no feed, and the stores still go.
            Err(err) if err.downcast_ref::<crate::sessions::Unavailable>().is_some() => Vec::new(),
            Err(err) => return Err(err),
        };
        // The neutral source is one file the caller named for THIS session, so
        // whatever it lists is the session's; a harness's own source lists
        // every session on the machine, and only this one's files are fed.
        let named = session.meta.harness == NEUTRAL;
        for found in listed {
            if !named && found.id != session.meta.session {
                continue;
            }
            let prefix = if found.sub.is_empty() {
                String::from("transcript/main")
            } else {
                format!("transcript/{}", segment(&found.sub))
            };
            feeds.push(Feed {
                prefix,
                source,
                session: found,
            });
        }
    }
    for feed in extra {
        feeds.push(Feed {
            prefix: feed.prefix.clone(),
            source: feed.source,
            session: feed.session.clone(),
        });
    }
    Ok(feeds)
}

/// Build one snapshot of `session` and make it the value of the session's ref
/// on the state repository (CLOUD-2720).
///
/// The session's own feeds come from its harness's source; `extra` are added
/// after them, in the order given. The swap is receive-pack's compare-and-swap
/// under a lease: it replaces the ref only while it reads what this repository
/// last pushed or absorbed, or is absent. A rejected swap fetches the other
/// writer's snapshot, [`absorb`]s it, and tries again — three attempts in all.
///
/// **A throttle returns at once** with the forge's two values. Nothing was
/// lost: the local files are as the snapshot left them, and the next push
/// carries them.
///
/// # Errors
///
/// A transport failure, a scanner that ran and failed, or a local file that
/// will not read or write.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT admit-accepts-any-tip|s@^        let admit = \x7cold: \&str\x7c old == lease::ZERO \x7c\x7c last.as_deref() == Some(old);$@        let admit = \x7c_: \&str\x7c true;@|a_rejected_push_fetches_absorbs_and_is_applied
//MUTANT admit-refuses-an-absent-ref|s@^        let admit = \x7cold: \&str\x7c old == lease::ZERO \x7c\x7c last.as_deref() == Some(old);$@        let admit = \x7cold: \&str\x7c last.as_deref() == Some(old);@|a_ref_rotated_away_is_recreated_on_the_first_attempt
//MUTANT throttled-push-retried-at-once|s@^                return Ok(Push::only(Pushed::Throttled(throttle)));$@                let _ = throttle;@|a_throttled_push_returns_at_once_and_loses_nothing
//MUTANT unchanged-snapshot-still-sent|s@^        if unchanged {$@        if false {@|a_second_push_with_nothing_changed_sends_nothing
//MUTANT pushed-cursor-recorded-before-the-swap|s@^        let outcome = lease::push(\&session.remote, \&repo, \&name, \&commit, \&admit)?;$@        record_pushed(\&dir, \&repo, \&commit)?; let outcome = lease::push(\&session.remote, \&repo, \&name, \&commit, \&admit)?;@|a_throttled_push_returns_at_once_and_loses_nothing
//MUTANT rejected-swap-retried-without-bound|s@^    for attempt in 1..=ATTEMPTS {$@    for attempt in 1..=ATTEMPTS + 2 {@|three_rejected_swaps_are_contended_after_three_posts
pub fn push_once(session: &Session<'_>, extra: &[Feed<'_>]) -> Result<Push> {
    match lease::probe(&session.remote, Service::ReceivePack) {
        Ok(200) => {}
        Ok(401 | 403 | 404) => return Ok(Push::only(Pushed::Unattached)),
        Ok(other) => {
            return Err(anyhow::anyhow!(
                "offbox: the state repository answered {other} to discovery"
            ));
        }
        Err(err) => return throttled(err),
    }
    let dir = session_dir(session.project_root, &session.meta)?;
    let repo = local_repo(&dir);
    let name = reference(&session.meta);

    let source =
        crate::sessions::source_named(&session.meta.harness, session.transcript.as_deref());
    let feeds = feeds_of(session, source.as_deref(), extra)?;

    let mut ended = Vec::new();
    for attempt in 1..=ATTEMPTS {
        let built = snapshot(
            session.project_root,
            session.provisions,
            &session.meta,
            &feeds,
            session.time,
            BYTE_CAP,
        )?;
        let (commit, tree) = match built {
            Snapshot::Built {
                commit,
                tree,
                ended: now,
                ..
            } => {
                ended = now;
                (commit, tree)
            }
            Snapshot::Refused(refusal) => return Ok(Push::only(Pushed::Refused(refusal))),
        };
        let last = crate::git::resolve_ref(&repo, LAST)?;
        let unchanged = match last.as_deref() {
            Some(last) => gitwrite::tree_id(&repo, last)? == tree,
            None => false,
        };
        if unchanged {
            return Ok(Push {
                outcome: Pushed::Unchanged,
                ended,
            });
        }
        // WHAT THIS PUSH MAY REPLACE: the value this repository last pushed or
        // absorbed, or nothing at all. An absent ref has nothing to lose — it
        // is a first push, or the branch was rotated away.
        let admit = |old: &str| old == lease::ZERO || last.as_deref() == Some(old);
        let outcome = lease::push(&session.remote, &repo, &name, &commit, &admit)?;
        match outcome {
            lease::Outcome::Applied => {
                gitwrite::set_ref(&repo, LAST, &commit)?;
                // AFTER THE REF, never before: a kill between the two leaves
                // this file behind the ref, which only has another daemon
                // import records the ref already holds.
                record_pushed(&dir, &repo, &commit)?;
                return Ok(Push {
                    outcome: Pushed::Applied,
                    ended,
                });
            }
            lease::Outcome::Throttled {
                retry_after,
                reset_at,
            } => {
                let throttle = lease::Throttled {
                    retry_after,
                    reset_at,
                };
                return Ok(Push::only(Pushed::Throttled(throttle)));
            }
            lease::Outcome::Rejected { .. } => {}
        }
        if attempt == ATTEMPTS {
            break;
        }
        // REJECTED: another writer holds the ref. Take what it wrote, keep all
        // of it, and build again on top.
        let theirs = match lease::advertise(&session.remote, Service::ReceivePack) {
            Ok(advertisement) => advertisement.head_of(&name).to_owned(),
            Err(err) => return throttled(err),
        };
        if theirs == lease::ZERO || last.as_deref() == Some(theirs.as_str()) {
            continue;
        }
        if let Err(err) = lease::fetch_shallow(&session.remote, &repo, &theirs) {
            return throttled(err);
        }
        absorb(session.project_root, &session.meta, &theirs, true)?;
        gitwrite::set_ref(&repo, LAST, &theirs)?;
    }
    Ok(Push {
        outcome: Pushed::Contended,
        ended,
    })
}

/// Replace `pushed.json` with the `cursor.json` the snapshot `commit` carried.
fn record_pushed(dir: &Path, repo: &Path, commit: &str) -> Result<()> {
    let index = gitwrite::tree_index(repo, commit)?;
    let Some((_, id)) = index.iter().find(|(path, _)| path == CURSORS) else {
        return Ok(());
    };
    crate::durable::replace(dir.join(PUSHED), gitwrite::read_blob(repo, id)?)
        .map_err(|err| anyhow::anyhow!("offbox: the pushed cursor will not write: {err}"))
}

/// Whether every segment of a tree path is an ordinary name. A tree another
/// writer built is data: a path that climbs out of its destination is refused.
fn ordinary(path: &str) -> bool {
    !path.is_empty()
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\\'))
}

/// `base` itself for an empty `relative`, the file under it otherwise.
fn under(base: &Path, relative: &str) -> PathBuf {
    if relative.is_empty() {
        base.to_path_buf()
    } else {
        base.join(relative)
    }
}

/// The files a local destination holds: itself where it is a file, everything
/// under it where it is a directory, nothing where it is absent.
fn held(destination: &Path) -> Vec<(String, PathBuf)> {
    if destination.is_file() {
        return vec![(String::new(), destination.to_path_buf())];
    }
    files_under(destination)
}

/// Where a store of another writer's snapshot lives on this machine, or `None`
/// for an entry this build does not know as a store — which is kept aside
/// whole, and never written into the state or git directory on a tree's say-so.
fn destination(project_root: &Path, store: &str) -> Option<PathBuf> {
    let (root, entry) = store.split_once('/')?;
    match root {
        "state" if STATE_STORES.contains(&entry) => {
            Some(crate::state::repo_state_dir(project_root).ok()?.join(entry))
        }
        "git" if entry.starts_with(GIT_STORE_PREFIX) && !git_excluded(entry) => {
            Some(crate::git::git_dir(project_root).ok()?.join(entry))
        }
        _ => None,
    }
}

/// One group of another writer's files: each as its path relative to the
/// group's root, and its blob id.
type Group = Vec<(String, String)>;

/// Another writer's snapshot, read one file at a time.
struct Theirs<'a> {
    repo: &'a Path,
    /// `absorbed/<commit>/`, where what cannot go in place is kept whole.
    aside: PathBuf,
    /// Whether anything was written under `aside`.
    kept_aside: bool,
}

impl Theirs<'_> {
    fn read(&self, id: &str) -> Result<Vec<u8>> {
        gitwrite::read_blob(self.repo, id)
    }

    /// Write one file where no file is. **No existing local file is modified.**
    fn place(&self, target: &Path, id: &str) -> Result<()> {
        if target.exists() {
            return Ok(());
        }
        let refused =
            |err: std::io::Error| anyhow::anyhow!("offbox: an absorbed file will not write: {err}");
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(refused)?;
        }
        crate::durable::replace(target, self.read(id)?).map_err(refused)
    }

    /// Write a whole group under `base`.
    fn place_all(&self, base: &Path, group: &Group) -> Result<()> {
        for (relative, id) in group {
            self.place(&under(base, relative), id)?;
        }
        Ok(())
    }

    /// Keep a whole group aside, at `root` under this snapshot's own entry.
    fn keep_aside(&mut self, root: &str, group: &Group) -> Result<()> {
        self.kept_aside = true;
        self.place_all(&self.aside.join(root), group)
    }

    /// Whether every file of `group` equals the local file at the same place.
    fn all_equal(&self, base: &Path, group: &Group) -> Result<bool> {
        for (relative, id) in group {
            let Ok(local) = std::fs::read(under(base, relative)) else {
                return Ok(false);
            };
            if local != self.read(id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Copy another writer's snapshot `commit` into local files (CLOUD-2720).
///
/// `own` says the commit was read from this session's own ref. The commit must
/// already be in the session's local repository.
///
/// 1. **A store** whose local destination is absent or empty is written there,
///    whole. One with equal bytes writes nothing. One that differs leaves the
///    local store untouched and is written whole under
///    `absorbed/<commit>/`. **Stores are never merged**: the findings journal is
///    rewritten whole under a lock, and a line-wise union of two is neither.
/// 2. **`transcript/`**: with `own` and no local transcript, the files and their
///    cursor entries become the local ones, and the session continues the same
///    record stream. Equal files write nothing. Otherwise all of it is kept
///    aside. **Records are never merged between writers.**
/// 3. **`history/<leaf>/`**: absent locally it is written in place — with its
///    cursor entries, when `own`; different, it is kept aside.
/// 4. **`absorbed/<X>/`** inside the commit is written to the local
///    `absorbed/<X>/` where that is absent. An entry is keyed by the commit it
///    came from, so one already here cannot differ, and nothing is ever nested
///    inside another entry.
///
/// Whenever anything was kept aside, the commit's `meta.json` and `cursor.json`
/// are written there too. A later absorb adds an entry and never replaces one.
///
/// # Errors
///
/// A tree path that is not an ordinary relative path, or a file that will not
/// read or write.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT absorb-overwrites-a-local-store|s@^        if here.is_empty() {$@        if true {@|a_rejected_push_fetches_absorbs_and_is_applied
//MUTANT absorb-discards-their-differing-store|s@^            theirs.keep_aside(store, group)?; // a differing store$@@|a_rejected_push_fetches_absorbs_and_is_applied
//MUTANT later-absorb-replaces-an-earlier-one|s@^        aside: dir.join(ABSORBED).join(commit),$@        aside: dir.join(ABSORBED).join("latest"),@|a_second_rejected_push_adds_a_second_entry
//MUTANT absorbed-entry-nested-in-another|s@^            theirs.place_all(\&dir.join(ABSORBED).join(entry), group)?;$@            theirs.place_all(\&theirs.aside.join(ABSORBED).join(entry), group)?;@|an_absorbed_entry_is_never_nested_in_another
//MUTANT foreign-transcript-appended-to-the-local-one|s@^        } else if !theirs.all_equal(\&local, \&transcript)? {$@        } else if false {@|transcripts_are_never_merged_between_writers
pub fn absorb(project_root: &Path, meta: &Meta, commit: &str, own: bool) -> Result<()> {
    let dir = session_dir(project_root, meta)?;
    let repo = local_repo(&dir);
    let index = gitwrite::tree_index(&repo, commit)?;
    if let Some((path, _)) = index.iter().find(|(path, _)| !ordinary(path)) {
        return Err(anyhow::anyhow!(
            "offbox: the snapshot {commit} names {} bytes of path that are not an ordinary relative path",
            path.len()
        ));
    }
    let mut theirs = Theirs {
        repo: &repo,
        aside: dir.join(ABSORBED).join(commit),
        kept_aside: false,
    };

    let mut stores: BTreeMap<String, Group> = BTreeMap::new();
    let mut transcript: Group = Vec::new();
    let mut history: BTreeMap<String, Group> = BTreeMap::new();
    let mut absorbed: BTreeMap<String, Group> = BTreeMap::new();
    for (path, id) in &index {
        if let Some(store) = store_of(path) {
            let relative = path[store.len()..].trim_start_matches('/');
            stores
                .entry(store.to_owned())
                .or_default()
                .push((relative.to_owned(), id.clone()));
        } else if let Some(rest) = path.strip_prefix("transcript/") {
            transcript.push((rest.to_owned(), id.clone()));
        } else if let Some((entry, rest)) = keyed(path, "history/") {
            history.entry(entry).or_default().push((rest, id.clone()));
        } else if let Some((entry, rest)) = keyed(path, "absorbed/") {
            absorbed.entry(entry).or_default().push((rest, id.clone()));
        }
    }

    for (store, group) in &stores {
        let Some(local) = destination(project_root, store) else {
            theirs.keep_aside(store, group)?;
            continue;
        };
        let here = held(&local);
        if here.is_empty() {
            theirs.place_all(&local, group)?;
        } else if here.len() != group.len() || !theirs.all_equal(&local, group)? {
            theirs.keep_aside(store, group)?; // a differing store
        }
    }

    let mut adopted: Vec<String> = Vec::new();
    if !transcript.is_empty() {
        let local = dir.join("transcript");
        if own && files_under(&local).is_empty() {
            theirs.place_all(&local, &transcript)?;
            adopted.push(String::from("transcript/"));
        } else if !theirs.all_equal(&local, &transcript)? {
            theirs.keep_aside("transcript", &transcript)?;
        }
    }
    for (entry, group) in &history {
        let local = dir.join("history").join(entry);
        if files_under(&local).is_empty() {
            theirs.place_all(&local, group)?;
            if own {
                adopted.push(format!("history/{entry}/"));
            }
        } else if !theirs.all_equal(&local, group)? {
            theirs.keep_aside(&format!("history/{entry}"), group)?;
        }
    }
    for (entry, group) in &absorbed {
        if !dir.join(ABSORBED).join(entry).exists() {
            theirs.place_all(&dir.join(ABSORBED).join(entry), group)?;
        }
    }

    let carried = |name: &str| index.iter().find(|(path, _)| path == name);
    if theirs.kept_aside {
        for name in ["meta.json", CURSORS] {
            if let Some((_, id)) = carried(name) {
                theirs.place(&theirs.aside.join(name), id)?;
            }
        }
    }
    // THE STREAMS TAKEN IN PLACE ARE CONTINUED, so their cursor entries come
    // with them: where this writer's next read starts is where theirs stopped.
    if !adopted.is_empty()
        && let Some((_, id)) = carried(CURSORS)
    {
        let entries: Cursors = serde_json::from_slice(&theirs.read(id)?).unwrap_or_default();
        let mut cursors = load_cursors(&dir);
        for (prefix, position) in entries {
            if adopted.iter().any(|root| prefix.starts_with(root.as_str())) {
                cursors.insert(prefix, position);
            }
        }
        persist(&dir, &cursors)?;
    }
    Ok(())
}

/// Split `path` under `root` into its first segment and the rest:
/// `history/<leaf>/<rest>` gives `(<leaf>, <rest>)`.
fn keyed(path: &str, root: &str) -> Option<(String, String)> {
    let (entry, rest) = path.strip_prefix(root)?.split_once('/')?;
    Some((entry.to_owned(), rest.to_owned()))
}

/// Whether the snapshot `last` held `path` as another writer's stream that the
/// absorb kept aside — in which case it is carried from `absorbed/<last>/` and
/// never mixed into this session's own files by path.
fn foreign(dir: &Path, last: Option<&str>, path: &str) -> bool {
    let Some(last) = last else {
        return false;
    };
    let aside = dir.join(ABSORBED).join(last);
    if path.starts_with("transcript/") {
        return aside.join("transcript").exists();
    }
    keyed(path, "history/").is_some_and(|(entry, _)| aside.join("history").join(entry).exists())
}

// --- the daemon (CLOUD-2721) ---------------------------------------------------

/// The lock one daemon per checkout holds for its life, under [`DIR`].
pub const LOCK: &str = crate::offbox_watch::LOCK;

/// The daemon's status file, under [`DIR`]: one `key value` per line.
pub const STATUS: &str = crate::offbox_watch::STATUS;

/// The file the hook appends one line to per tool call. Only its length is read.
pub const INBOX: &str = crate::offbox_watch::INBOX;

/// The one line telling an agent how to attach the state repository.
pub const NOTE: &str = crate::offbox_watch::NOTE;

/// How often the loop wakes, in seconds.
const WAKE: u64 = 5;

/// The least time between two push attempts, in seconds.
const FLOOR: u64 = 60;

/// How long with no word from the hook before a push is tried anyway.
const TIMER: u64 = 600;

/// The longest base wait, the cap the REST tier's own backoff uses.
const MAX_WAIT: u64 = 3600;

/// How long to wait after a snapshot the scanner refused.
const REFUSED_WAIT: u64 = 600;

/// The first attempt after start is delayed by up to this many seconds.
const SPREAD: u64 = 60;

/// How many times a starting daemon tries the lock, and how long between
/// tries: one second in all. The hook holds the lock for an instant on every
/// tool call, so one failed try is not another daemon.
const LOCK_TRIES: u32 = 20;
const LOCK_PAUSE_MS: u64 = 50;

/// What one push attempt, or one probe, came to — as the backoff reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// Applied, or nothing had changed.
    Done,
    /// The forge said to slow down.
    Throttled(lease::Throttled),
    /// A transport failure, or the remote would not be written.
    Failed,
    /// The swap was rejected on every attempt.
    Contended,
    /// No snapshot was built: the scanner is absent or failed.
    Refused,
}

/// The seconds to wait after `result` before the next request (CLOUD-2721).
///
/// **GitHub decides the rate.** `Retry-After` is honoured; failing that, the
/// reset instant; failing that, a minute and then exponentially longer — its
/// published rule. `throttles` and `failures` count consecutive results of
/// their kind, starting at 1, and are the caller's to keep.
///
/// The base is capped at [`MAX_WAIT`], and a uniformly random extra of up to
/// half the base is added from `random`, so daemons throttled together do not
/// come back together. This reads no clock: `now` is the caller's.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT retry-after-ignored|s@^            (Some(seconds), _) => seconds,$@            (Some(_), _) => 0,@|next_wait_follows_the_forge_then_doubles
//MUTANT backoff-does-not-double|s@^    60_u64.saturating_mul(1_u64 << exponent)$@    60_u64@|next_wait_follows_the_forge_then_doubles
//MUTANT backoff-exceeds-the-cap|s@^    let base = base.min(MAX_WAIT);$@@|next_wait_follows_the_forge_then_doubles
#[must_use]
pub fn next_wait(result: Attempt, throttles: u32, failures: u32, now: i64, random: u64) -> u64 {
    let base = match result {
        Attempt::Done | Attempt::Contended => 0,
        Attempt::Refused => REFUSED_WAIT,
        Attempt::Throttled(throttle) => match (throttle.retry_after, throttle.reset_at) {
            (Some(seconds), _) => seconds,
            (None, Some(reset)) => {
                u64::try_from(i64::try_from(reset).unwrap_or(i64::MAX).saturating_sub(now))
                    .unwrap_or(0)
            }
            (None, None) => doubling(throttles),
        },
        Attempt::Failed => doubling(failures),
    };
    let base = base.min(MAX_WAIT);
    base + random % (base / 2 + 1)
}

/// A minute, doubled once for each consecutive result after the first.
fn doubling(count: u32) -> u64 {
    let exponent = count.saturating_sub(1).min(32);
    60_u64.saturating_mul(1_u64 << exponent)
}

/// Whether to push now (CLOUD-2721): something may be new, the floor has
/// passed, and no wait is in force.
///
/// `grew` is the hook's word that a tool call happened; the timer is the other
/// trigger, so a hook that says nothing still gets a push every ten minutes.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT push-inside-the-floor|s@^    wait_left == 0 \&\& since_last >= FLOOR \&\& (grew \x7c\x7c since_last >= TIMER)$@    wait_left == 0 \&\& (grew \x7c\x7c since_last >= TIMER)@|the_decision_to_push_needs_a_trigger_the_floor_and_no_wait
//MUTANT timer-never-triggers-a-push|s@^    wait_left == 0 \&\& since_last >= FLOOR \&\& (grew \x7c\x7c since_last >= TIMER)$@    wait_left == 0 \&\& since_last >= FLOOR \&\& grew@|the_decision_to_push_needs_a_trigger_the_floor_and_no_wait
#[must_use]
pub const fn should_push(grew: bool, since_last: u64, wait_left: u64) -> bool {
    wait_left == 0 && since_last >= FLOOR && (grew || since_last >= TIMER)
}

/// How long the first attempt after start is held back, so sessions that start
/// together do not push together.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT first-push-is-immediate|s@^    random % (SPREAD + 1)$@    0 * random@|the_first_attempt_is_spread_over_a_minute
#[must_use]
pub const fn first_delay(random: u64) -> u64 {
    random % (SPREAD + 1)
}

/// The daemon's status file, as its keys.
///
/// A reader ignores a key it does not know, so a later slice can add one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusFile {
    /// The daemon's process id.
    pub pid: u32,
    /// `<harness>-<hash>` of the session this daemon serves.
    pub session: String,
    /// The byte length of the inbox the daemon has seen.
    pub inbox_read: u64,
    /// The commit id last applied, or `-`.
    pub pushed: String,
    /// Consecutive throttled attempts.
    pub throttles: u32,
    /// Consecutive failed attempts.
    pub failures: u32,
    /// The epoch second before which the daemon makes no request; 0 for none.
    pub wait_until: i64,
    /// `yes`, `no`, `no-origin` or `unknown`.
    pub attached: String,
    /// `pending`, `yes`, `none` or `unavailable`.
    pub restored: String,
    /// `ok`, `not-surveyed` or `unavailable`.
    pub source: String,
}

//MUTANT-SUITE crates/batten/tests/it/offbox_daemon.rs
//MUTANT status-written-without-a-pid|s@^        let mut text = format!("pid {}\\n", self.pid);$@        let mut text = String::new();@|the_status_file_names_the_daemons_pid_and_session
//MUTANT status-names-no-session|s@^        let _ = writeln!(text, "session {}", self.session);$@@|the_status_file_names_the_daemons_pid_and_session
impl StatusFile {
    /// The file's text. **`pid` first, then `session`**: the two lines a reader
    /// needs before any other, written before anything else is known.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut text = format!("pid {}\n", self.pid);
        let _ = writeln!(text, "session {}", self.session);
        let _ = writeln!(text, "inbox_read {}", self.inbox_read);
        let _ = writeln!(text, "pushed {}", self.pushed);
        let _ = writeln!(text, "throttles {}", self.throttles);
        let _ = writeln!(text, "failures {}", self.failures);
        let _ = writeln!(text, "wait_until {}", self.wait_until);
        let _ = writeln!(text, "attached {}", self.attached);
        let _ = writeln!(text, "restored {}", self.restored);
        let _ = writeln!(text, "source {}", self.source);
        text
    }

    /// Read a status file's text. A key that is absent or will not parse takes
    /// its empty value, and an unknown key is skipped.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut read = StatusFile {
            pid: 0,
            session: String::new(),
            inbox_read: 0,
            pushed: String::from("-"),
            throttles: 0,
            failures: 0,
            wait_until: 0,
            attached: String::from("unknown"),
            restored: String::from("none"),
            source: String::from("ok"),
        };
        for line in text.lines() {
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "pid" => read.pid = value.parse().unwrap_or(0),
                "session" => value.clone_into(&mut read.session),
                "inbox_read" => read.inbox_read = value.parse().unwrap_or(0),
                "pushed" => value.clone_into(&mut read.pushed),
                "throttles" => read.throttles = value.parse().unwrap_or(0),
                "failures" => read.failures = value.parse().unwrap_or(0),
                "wait_until" => read.wait_until = value.parse().unwrap_or(0),
                "attached" => value.clone_into(&mut read.attached),
                "restored" => value.clone_into(&mut read.restored),
                "source" => value.clone_into(&mut read.source),
                _ => {}
            }
        }
        read
    }
}

/// What the daemon takes from outside itself: the clock, the pause between
/// wakes, and randomness. The verb supplies the real ones; a test supplies a
/// clock that a pause advances.
pub trait World {
    /// The current epoch second.
    fn now(&mut self) -> i64;
    /// Wait this many milliseconds.
    fn pause(&mut self, millis: u64);
    /// Sixty-four random bits.
    fn random(&mut self) -> u64;
}

/// How a launch ended, for the two cases in which it ends at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// Another daemon holds this checkout's lock.
    Running,
    /// The loop ran the number of wakes it was asked for. Only a test asks.
    Stopped,
}

impl Launch {
    /// The one stdout token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Launch::Running => "running",
            Launch::Stopped => "stopped",
        }
    }
}

/// What a daemon is launched with.
#[allow(missing_debug_implementations)]
pub struct Launching<'a> {
    /// The project's root directory.
    pub project_root: &'a Path,
    /// The scanner's provision rows.
    pub provisions: &'a [crate::provision::Provision],
    /// The harness's name and the session's own id.
    pub harness: &'a str,
    /// The session's own id, as the harness spells it.
    pub session: &'a str,
    /// The transcript path the harness named, where it named one.
    pub transcript: Option<&'a Path>,
    /// The state repository's value, as the environment spells it.
    pub value: &'a str,
    /// The project's origin URL, where it has one.
    pub origin: Option<&'a str>,
    /// How many wakes to run before returning; `None` runs until killed.
    pub wakes: Option<u64>,
}

/// The per-checkout directory the daemon's own files live in.
fn daemon_dir(project_root: &Path) -> Result<PathBuf> {
    Ok(crate::state::repo_state_dir(project_root)?.join(DIR))
}

/// Take this checkout's daemon lock, or `None` where another daemon holds it.
///
/// The hook probes the lock for an instant on every tool call, so a failed try
/// is retried every 50 ms for one second before it is read as another daemon.
//MUTANT-SUITE crates/batten/tests/it/offbox_daemon.rs
//MUTANT second-daemon-also-runs|s@^    let held_elsewhere = true;$@    let held_elsewhere = false;@|a_second_daemon_in_one_checkout_says_running_and_exits
//MUTANT lock-probe-makes-the-daemon-exit|s@^    for attempt in 0..LOCK_TRIES {$@    for attempt in 0..1 {@|a_lock_probed_at_start_does_not_stop_the_daemon
fn take_lock(dir: &Path, world: &mut dyn World) -> Result<Option<std::fs::File>> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: the daemon lock will not open: {err}");
    std::fs::create_dir_all(dir).map_err(refused)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK))
        .map_err(refused)?;
    for attempt in 0..LOCK_TRIES {
        if fs4::FileExt::try_lock(&file).is_ok() {
            return Ok(Some(file));
        }
        if attempt + 1 < LOCK_TRIES {
            world.pause(LOCK_PAUSE_MS);
        }
    }
    let held_elsewhere = true;
    Ok((!held_elsewhere).then_some(file))
}

/// The running daemon: what it was launched with, and what it remembers
/// between wakes. Everything it must not lose is in the status file.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT applied-push-keeps-the-backoff|s@^                self.status.throttles = 0;$@@|a_throttled_daemon_waits_as_told_and_resets_on_an_applied_push
struct Daemon<'a> {
    launching: &'a Launching<'a>,
    dir: PathBuf,
    meta: Option<Meta>,
    remote: Option<String>,
    status: StatusFile,
    /// The status text last written, so the file is rewritten only on change.
    written: String,
    /// When a push was last attempted, and the inbox length it saw.
    last_attempt: Option<i64>,
    inbox_at_attempt: u64,
    /// Whether the last attempt left something unpushed.
    owed: bool,
    /// The first attempt is not made before this.
    not_before: i64,
}

impl Daemon<'_> {
    fn write_status(&mut self) -> Result<()> {
        let text = self.status.render();
        if text == self.written {
            return Ok(());
        }
        crate::durable::replace(self.dir.join(STATUS), &text)
            .map_err(|err| anyhow::anyhow!("offbox: the status file will not write: {err}"))?;
        self.written = text;
        Ok(())
    }

    /// Count `result`, and store how long the forge and the backoff say to wait.
    fn settle(&mut self, result: Attempt, world: &mut dyn World) {
        match result {
            Attempt::Done => {
                self.status.throttles = 0;
                self.status.failures = 0;
            }
            Attempt::Throttled(_) => self.status.throttles += 1,
            Attempt::Failed => self.status.failures += 1,
            Attempt::Contended | Attempt::Refused => {}
        }
        let now = world.now();
        let wait = next_wait(
            result,
            self.status.throttles,
            self.status.failures,
            now,
            world.random(),
        );
        self.status.wait_until = if wait == 0 {
            0
        } else {
            now.saturating_add(i64::try_from(wait).unwrap_or(i64::MAX))
        };
        self.owed = result != Attempt::Done;
    }

    /// Ask the remote whether this machine may write it, once.
    fn probe(&mut self, world: &mut dyn World) -> Result<()> {
        let Some(remote) = self.remote.clone() else {
            return Ok(());
        };
        let result = match lease::probe(&remote, Service::ReceivePack) {
            Ok(200) => {
                "yes".clone_into(&mut self.status.attached);
                Attempt::Done
            }
            Ok(401 | 403 | 404) => {
                self.unattached()?;
                Attempt::Failed
            }
            Ok(_) => {
                "unknown".clone_into(&mut self.status.attached);
                Attempt::Failed
            }
            Err(err) => {
                if let Some(throttle) = err.downcast_ref::<lease::Throttled>() {
                    Attempt::Throttled(*throttle)
                } else {
                    "unknown".clone_into(&mut self.status.attached);
                    Attempt::Failed
                }
            }
        };
        // A probe that answered leaves nothing owed; only its counts and its
        // wait are kept.
        let owed = self.owed;
        self.settle(result, world);
        self.owed = owed;
        Ok(())
    }

    /// The remote will not be written from here: say so, and how to fix it.
    /// **Nothing is denied for it** — the daemon keeps running and asks again.
    fn unattached(&mut self) -> Result<()> {
        "no".clone_into(&mut self.status.attached);
        let mut note = attach_note(self.launching.value.trim());
        note.push('\n');
        crate::durable::replace(self.dir.join(NOTE), note)
            .map_err(|err| anyhow::anyhow!("offbox: the attach note will not write: {err}"))
    }

    /// One push attempt.
    fn push(&mut self, world: &mut dyn World) -> Result<()> {
        let (Some(meta), Some(remote)) = (self.meta.clone(), self.remote.clone()) else {
            return Ok(());
        };
        let now = world.now();
        self.last_attempt = Some(now);
        self.inbox_at_attempt = self.status.inbox_read;
        let session = Session {
            project_root: self.launching.project_root,
            provisions: self.launching.provisions,
            meta,
            remote,
            transcript: self.launching.transcript.map(Path::to_path_buf),
            time: now,
        };
        let result = match push_once(&session, &[]) {
            Ok(push) => match push.outcome {
                Pushed::Applied | Pushed::Unchanged => {
                    let repo = local_repo(&session_dir(session.project_root, &session.meta)?);
                    if let Some(commit) = crate::git::resolve_ref(&repo, LAST)? {
                        self.status.pushed = commit;
                    }
                    "yes".clone_into(&mut self.status.attached);
                    Attempt::Done
                }
                Pushed::Contended => Attempt::Contended,
                Pushed::Throttled(throttle) => Attempt::Throttled(throttle),
                Pushed::Unattached => {
                    self.unattached()?;
                    Attempt::Failed
                }
                Pushed::Refused(_) => {
                    "unavailable".clone_into(&mut self.status.source);
                    Attempt::Refused
                }
            },
            // A transport failure is a result, never the daemon's end.
            Err(_) => Attempt::Failed,
        };
        self.settle(result, world);
        Ok(())
    }

    /// One wake of the loop.
    fn wake(&mut self, world: &mut dyn World) -> Result<()> {
        self.status.inbox_read =
            std::fs::metadata(self.dir.join(INBOX)).map_or(0, |meta| meta.len());
        let now = world.now();
        let wait_left = u64::try_from(self.status.wait_until.saturating_sub(now)).unwrap_or(0);
        if self.remote.is_some() && self.status.attached != "yes" {
            // Not known to be writable yet: ask, once any wait has run out.
            if wait_left == 0 {
                self.probe(world)?;
            }
        } else if self.remote.is_some() && now >= self.not_before {
            let grew = self.status.inbox_read > self.inbox_at_attempt || self.owed;
            // Never attempted reads as the timer having run out.
            let since_last = self.last_attempt.map_or(TIMER, |last| {
                u64::try_from(now.saturating_sub(last)).unwrap_or(0)
            });
            if should_push(grew, since_last, wait_left) {
                self.push(world)?;
            }
        }
        self.write_status()
    }
}

/// Run the off-box daemon for one session until it is killed (CLOUD-2721).
///
/// **Crash-only.** There is no shutdown path. Every piece of the daemon's state
/// is a file under the checkout's off-box directory, replaced whole, so killing
/// it at any instant loses nothing a restart does not recover.
///
/// **One per checkout**, by an exclusive lock held for the daemon's life; a
/// second launch answers [`Launch::Running`].
///
/// On start it keeps the previous status file's `throttles`, `failures` and
/// `wait_until` whatever session wrote them — a wait the forge asked for binds
/// the machine, not the session — and its `pushed` only when the session is its
/// own. Then it writes its `pid` and `session`, empties the inbox, and begins
/// to wake every five seconds.
///
/// # Errors
///
/// A lock or a status file that will not open or write. A failed push is not
/// an error: it is counted, waited out, and tried again.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT restart-forgets-the-wait|s@^        status.wait_until = previous.wait_until;$@@|a_restart_inside_a_wait_still_honours_it
//MUTANT new-session-inherits-the-old-status|s@^        if previous.session == status.session {$@        if true {@|a_restart_inside_a_wait_still_honours_it
pub fn run(launching: &Launching<'_>, world: &mut dyn World) -> Result<Launch> {
    let dir = daemon_dir(launching.project_root)?;
    let Some(_lock) = take_lock(&dir, world)? else {
        return Ok(Launch::Running);
    };

    let named = launching.origin.and_then(|origin| {
        Some((
            remote_for(origin, launching.value.trim())?,
            origin_path(origin)?,
        ))
    });
    let (remote, meta) = match named {
        Some((remote, origin)) => (
            Some(remote),
            Some(Meta {
                harness: launching.harness.to_owned(),
                session: launching.session.to_owned(),
                origin,
            }),
        ),
        None => (None, None),
    };
    let surveyed = crate::sessions::source_named(launching.harness, launching.transcript).is_some();

    let previous = std::fs::read_to_string(dir.join(STATUS))
        .map(|text| StatusFile::parse(&text))
        .ok();
    let mut status = StatusFile::parse("");
    status.pid = std::process::id();
    status.session = leaf(launching.harness, launching.session);
    if remote.is_none() {
        "no-origin".clone_into(&mut status.attached);
    }
    if !surveyed {
        "not-surveyed".clone_into(&mut status.source);
    }
    if let Some(previous) = previous {
        status.throttles = previous.throttles;
        status.failures = previous.failures;
        status.wait_until = previous.wait_until;
        if previous.session == status.session {
            status.pushed = previous.pushed;
        }
    }

    let now = world.now();
    let mut daemon = Daemon {
        launching,
        dir: dir.clone(),
        meta,
        remote,
        status,
        written: String::new(),
        last_attempt: None,
        inbox_at_attempt: 0,
        owed: false,
        not_before: now.saturating_add(i64::try_from(first_delay(world.random())).unwrap_or(0)),
    };
    daemon.write_status()?;
    crate::durable::replace(dir.join(INBOX), "")
        .map_err(|err| anyhow::anyhow!("offbox: the inbox will not write: {err}"))?;

    let mut wakes = 0_u64;
    loop {
        if launching.wakes.is_some_and(|limit| wakes >= limit) {
            return Ok(Launch::Stopped);
        }
        daemon.wake(world)?;
        wakes += 1;
        world.pause(WAKE * 1000);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fetch::{self, Response};
    use std::cell::Cell;
    use std::rc::Rc;

    /// The origin every case derives its remote from.
    const ORIGIN: &str = "https://forge.invalid/acme/widgets.git";

    /// Stand a remote up that answers every discovery with `status`, and count
    /// the calls it was asked.
    fn answering(status: u16) -> Rc<Cell<usize>> {
        let calls = Rc::new(Cell::new(0));
        let seen = Rc::clone(&calls);
        fetch::stand_in(Box::new(move |asked: &[fetch::Call<'_>]| {
            seen.set(seen.get() + asked.len());
            Ok(asked
                .iter()
                .map(|_| Response {
                    status,
                    body: Vec::new(),
                    headers: Vec::new(),
                })
                .collect())
        }));
        calls
    }

    /// Fails by: an unset variable reaching the network.
    #[test]
    fn unset_is_off_and_makes_no_call() {
        let calls = answering(200);
        assert_eq!(status(None, Some(ORIGIN)).unwrap(), Status::Off);
        assert_eq!(status(Some("  "), Some(ORIGIN)).unwrap(), Status::Off);
        assert_eq!(calls.get(), 0, "off must not probe");
    }

    /// Fails by: a served discovery reading as anything but attached.
    #[test]
    fn a_served_discovery_is_attached() {
        let calls = answering(200);
        let found = status(Some("example/state"), Some(ORIGIN)).unwrap();
        assert_eq!(found, Status::Attached);
        assert_eq!(found.code(), ExitCode::Success);
        assert_eq!(calls.get(), 1);
    }

    /// Fails by: a refusal reading as attached.
    #[test]
    fn a_refused_discovery_is_unattached() {
        for refusal in [401, 403, 404] {
            answering(refusal);
            let found = status(Some("example/state"), Some(ORIGIN)).unwrap();
            assert_eq!(found, Status::Unattached, "{refusal}");
            assert_eq!(found.code(), ExitCode::Usage);
        }
    }

    /// Fails by: could-not-look being reported as a refusal the agent can fix.
    #[test]
    fn a_transport_failure_is_an_error_and_never_a_refusal() {
        fetch::stand_in(Box::new(|_: &[fetch::Call<'_>]| {
            Err(anyhow::anyhow!("the wire is down"))
        }));
        assert!(status(Some("example/state"), Some(ORIGIN)).is_err());
        answering(500);
        assert!(status(Some("example/state"), Some(ORIGIN)).is_err());
    }

    /// Fails by: probing a host the project never named.
    #[test]
    fn only_an_http_origin_gives_a_remote() {
        let calls = answering(200);
        for origin in [
            None,
            Some("/srv/git/widgets.git"),
            Some("git@forge.invalid:acme/widgets.git"),
            Some("ssh://git@forge.invalid/acme/widgets.git"),
            Some("https:///acme/widgets.git"),
        ] {
            assert_eq!(
                status(Some("example/state"), origin).unwrap(),
                Status::NoHttpOrigin,
                "{origin:?}"
            );
        }
        assert_eq!(calls.get(), 0);
    }

    /// Fails by: the origin's path, or its credential, surviving into the remote.
    #[test]
    fn the_remote_is_the_origins_host_with_the_path_replaced() {
        assert_eq!(
            remote_for(ORIGIN, "example/state").as_deref(),
            Some("https://forge.invalid/example/state")
        );
        assert_eq!(
            remote_for(
                "HTTP://user:secret@forge.invalid:8443/a/b",
                "/example/state/"
            )
            .as_deref(),
            Some("http://forge.invalid:8443/example/state")
        );
    }

    /// Fails by: a note an agent cannot act on.
    #[test]
    fn the_attach_note_names_the_repo_and_both_remedies() {
        let note = attach_note("example/state");
        assert!(note.contains("example/state"), "{note}");
        assert!(note.contains("push access"), "{note}");
        assert!(note.contains("git credential"), "{note}");
        assert!(note.contains("misspelled"), "{note}");
        assert!(!note.contains('\n'), "one line: {note}");
    }
}

/// The push and the absorb (CLOUD-2720), over the transport stand-in.
///
/// Each writer is a real project repository with its own state directory, its
/// own stores and its own transcript file; the remote is `lease`'s stand-in,
/// which keeps what a push sends and serves it back to a shallow fetch.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod push_tests {
    use super::*;
    use crate::lease::testing::{Canned, Kind, Moved, REMOTE, Shared, standing};
    use std::os::unix::fs::PermissionsExt as _;

    const TIME: i64 = 1_700_000_000;

    /// One checkout pushing a session.
    struct Writer {
        root: PathBuf,
        provisions: Vec<crate::provision::Provision>,
        meta: Meta,
        transcript: PathBuf,
    }

    #[derive(serde::Deserialize)]
    struct Rows {
        provision: Vec<crate::provision::Provision>,
    }

    /// A scratch directory with the state root contained under it.
    fn base(name: &str) -> PathBuf {
        let dir = crate::scratch::scratch(name);
        crate::testing::contain_state(&dir.join("state"));
        dir
    }

    fn put(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn add(path: &Path, body: &str) {
        let mut held = std::fs::read_to_string(path).unwrap_or_default();
        held.push_str(body);
        put(path, &held);
    }

    impl Writer {
        /// A project under `base` named `name`, pushing `session`, with a clean
        /// scanner installed where `provision` would have put it.
        fn new(base: &Path, name: &str, session: &str) -> Self {
            let root = base.join(name);
            std::fs::create_dir_all(&root).unwrap();
            gitwrite::init_on_main(&root).unwrap();
            let root = crate::git::canonical(&root);
            let rows: Rows = toml::from_str(
                "[[provision]]\nname = \"ripsecrets\"\nversion = \"0.0.0-stub\"\n\
                 url = 'file:///nonexistent/ripsecrets'\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n\
                 binary = \"ripsecrets\"\n",
            )
            .unwrap();
            let binary = crate::provision::binary_path(&root, &rows.provision[0]).unwrap();
            put(&binary, "#!/bin/sh\nexit 0\n");
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
            let transcript = base.join(format!("{name}.jsonl"));
            Writer {
                root,
                provisions: rows.provision,
                meta: Meta {
                    harness: String::from("exit-code"),
                    session: session.to_owned(),
                    origin: String::from("acme/widgets"),
                },
                transcript,
            }
        }

        fn git_file(&self, path: &str, body: &str) {
            put(&self.root.join(".git").join(path), body);
        }

        fn read_git(&self, path: &str) -> Option<String> {
            std::fs::read_to_string(self.root.join(".git").join(path)).ok()
        }

        fn push(&self) -> Push {
            push_once(
                &Session {
                    project_root: &self.root,
                    provisions: &self.provisions,
                    meta: self.meta.clone(),
                    remote: REMOTE.to_owned(),
                    transcript: Some(self.transcript.clone()),
                    time: TIME,
                },
                &[],
            )
            .expect("the push runs")
        }

        fn dir(&self) -> PathBuf {
            session_dir(&self.root, &self.meta).unwrap()
        }

        fn repo(&self) -> PathBuf {
            local_repo(&self.dir())
        }

        fn last(&self) -> Option<String> {
            crate::git::resolve_ref(&self.repo(), LAST).unwrap()
        }

        /// The tree of a commit this writer's repository holds, path to bytes.
        fn tree(&self, commit: &str) -> BTreeMap<String, Vec<u8>> {
            gitwrite::tree_index(&self.repo(), commit)
                .unwrap()
                .into_iter()
                .map(|(path, id)| {
                    let bytes = gitwrite::read_blob(&self.repo(), &id).unwrap();
                    (path, bytes)
                })
                .collect()
        }

        /// Every file under the session directory's `root`, path to bytes.
        fn local(&self, root: &str) -> BTreeMap<String, Vec<u8>> {
            files_under(&self.dir().join(root))
                .into_iter()
                .map(|(path, at)| (path, std::fs::read(at).unwrap()))
                .collect()
        }
    }

    fn head(stand: &Shared, meta: &Meta) -> String {
        stand.borrow().head_of(&reference(meta))
    }

    fn receives(stand: &Shared) -> usize {
        stand.borrow().receives
    }

    /// Two writers of one session whose stores and transcripts differ: the
    /// first has pushed, and the second — which has never seen the ref — has
    /// pushed after it. Returns the first writer's commit too.
    fn two_writers(name: &str) -> (Shared, Writer, Writer, String) {
        let base = base(name);
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        one.git_file("batten-receipts/r.json", "one\n");
        one.git_file("batten-receipts/s.json", "only one has this file\n");
        one.git_file("batten-only/x.json", "only\n");
        put(
            &one.transcript,
            "{\"from\":\"one\",\"n\":1}\n{\"from\":\"one\",\"n\":2}\n",
        );
        assert_eq!(one.push().outcome, Pushed::Applied);
        let first = head(&stand, &one.meta);

        let two = Writer::new(&base, "two", "s");
        two.git_file("batten-receipts/r.json", "two\n");
        put(&two.transcript, "{\"from\":\"two\",\"n\":1}\n");
        assert_eq!(two.push().outcome, Pushed::Applied);
        (stand, one, two, first)
    }

    /// Fails by: two sessions sharing a ref, a snapshot with a parent, or a
    /// session id reaching the ref name.
    #[test]
    fn two_session_ids_give_two_orphan_refs() {
        let base = base("offbox-push-two-refs");
        let stand = standing(&[], Vec::new());
        let plain = Writer::new(&base, "plain", "s");
        let awkward = Writer::new(&base, "awkward", "a ../ b");
        assert_eq!(plain.push().outcome, Pushed::Applied);
        assert_eq!(awkward.push().outcome, Pushed::Applied);

        let stand = stand.borrow();
        assert_eq!(stand.refs.len(), 2, "{:?}", stand.refs);
        for (name, id) in &stand.refs {
            assert!(name.starts_with("refs/heads/session/acme/widgets/exit-code-"));
            assert!(!name.contains("..") && !name.contains(' '), "{name}");
            let commit = stand.objects.iter().find(|held| &held.id == id).unwrap();
            let text = String::from_utf8_lossy(&commit.body);
            assert!(!text.lines().any(|line| line.starts_with("parent ")));
        }
        assert_eq!(
            origin_path("https://forge.invalid/acme/widgets.git").as_deref(),
            Some("acme/widgets")
        );
        assert_eq!(origin_path("git@forge.invalid:acme/widgets.git"), None);
    }

    /// Fails by: a writer that never saw the ref overwriting it, a local store
    /// changed by another writer's, or the other writer's store dropped.
    #[test]
    fn a_rejected_push_fetches_absorbs_and_is_applied() {
        let (stand, _one, two, first) = two_writers("offbox-push-rejected");

        // Rejected by `admit` before anything was sent, so one POST each.
        assert_eq!(receives(&stand), 2);
        assert_eq!(stand.borrow().uploads, 1, "one shallow fetch");
        assert_eq!(
            two.read_git("batten-receipts/r.json").as_deref(),
            Some("two\n")
        );
        assert_eq!(
            two.read_git("batten-receipts/s.json"),
            None,
            "not merged in"
        );
        let aside = two.local(&format!("absorbed/{first}"));
        assert_eq!(aside["git/batten-receipts/r.json"], b"one\n");
        assert!(aside.contains_key("git/batten-receipts/s.json"));
        assert!(aside.contains_key("meta.json") && aside.contains_key("cursor.json"));
        // A store only the first writer had is now where a store lives.
        assert_eq!(
            two.read_git("batten-only/x.json").as_deref(),
            Some("only\n")
        );

        let now = head(&stand, &two.meta);
        assert_ne!(now, first);
        assert_eq!(two.last().as_deref(), Some(now.as_str()));
        let tree = two.tree(&now);
        assert_eq!(tree["git/batten-receipts/r.json"], b"two\n");
        assert_eq!(
            tree[&format!("absorbed/{first}/git/batten-receipts/r.json")],
            b"one\n"
        );
    }

    /// Fails by: one writer's records appearing in another's stream.
    #[test]
    fn transcripts_are_never_merged_between_writers() {
        let (stand, one, two, first) = two_writers("offbox-push-transcripts");

        let mine = std::fs::read(&two.transcript).unwrap();
        let local = two.local("transcript");
        assert_eq!(local.len(), 1);
        assert_eq!(local["main/0/000000.jsonl"], mine);
        let aside = two.local(&format!("absorbed/{first}"));
        assert_eq!(
            aside["transcript/main/0/000000.jsonl"],
            std::fs::read(&one.transcript).unwrap()
        );
        assert!(aside.contains_key("cursor.json"));

        let tree = two.tree(&head(&stand, &two.meta));
        let stream: Vec<&String> = tree
            .keys()
            .filter(|path| path.starts_with("transcript/"))
            .collect();
        assert_eq!(stream, ["transcript/main/0/000000.jsonl"]);
        assert_eq!(tree["transcript/main/0/000000.jsonl"], mine);
    }

    /// Fails by: a restored session starting a second stream beside its own, or
    /// another session's records being taken as this one's.
    #[test]
    fn own_ref_with_no_local_transcript_continues_the_stream() {
        let base = base("offbox-push-own");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n{\"n\":2}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        let first = head(&stand, &one.meta);
        let theirs = one.tree(&first);

        for (name, own) in [("mine", true), ("other", false)] {
            let fresh = Writer::new(&base, name, "s");
            std::fs::create_dir_all(fresh.dir()).unwrap();
            gitwrite::init_bare(&fresh.repo()).unwrap();
            lease::fetch_shallow(REMOTE, &fresh.repo(), &first).unwrap();
            absorb(&fresh.root, &fresh.meta, &first, own).unwrap();

            let local = fresh.local("transcript");
            let aside = fresh.local(&format!("absorbed/{first}"));
            if own {
                assert_eq!(
                    local["main/0/000000.jsonl"],
                    theirs["transcript/main/0/000000.jsonl"]
                );
                assert!(aside.is_empty(), "{:?}", aside.keys());
                let taken = load_cursors(&fresh.dir());
                let given: Cursors = serde_json::from_slice(&theirs["cursor.json"]).unwrap();
                assert_eq!(taken["transcript/main"], given["transcript/main"]);
            } else {
                assert!(local.is_empty());
                assert_eq!(
                    aside["transcript/main/0/000000.jsonl"],
                    theirs["transcript/main/0/000000.jsonl"]
                );
                assert!(load_cursors(&fresh.dir()).is_empty());
            }
        }
    }

    /// Fails by: a push after an absorb being rejected again, or dropping what
    /// was absorbed.
    #[test]
    fn a_push_after_an_absorb_is_applied_first_time_and_keeps_what_it_absorbed() {
        let (stand, _one, two, first) = two_writers("offbox-push-third");
        let before = receives(&stand);
        add(&two.transcript, "{\"from\":\"two\",\"n\":2}\n");

        assert_eq!(two.push().outcome, Pushed::Applied);

        assert_eq!(receives(&stand), before + 1);
        let tree = two.tree(&head(&stand, &two.meta));
        assert_eq!(
            tree[&format!("absorbed/{first}/git/batten-receipts/r.json")],
            b"one\n"
        );
        assert_eq!(
            tree["transcript/main/0/000000.jsonl"],
            std::fs::read(&two.transcript).unwrap()
        );
    }

    /// Both writers, after each has absorbed the other once more.
    fn crossed(name: &str) -> (Writer, Writer, String, BTreeMap<String, Vec<u8>>) {
        let (stand, one, two, first) = two_writers(name);
        let entry = two.local(&format!("absorbed/{first}"));
        // The first writer pushes again: the ref now holds the second's value.
        one.git_file("batten-receipts/r.json", "one again\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        // And the second once more.
        two.git_file("batten-receipts/r.json", "two again\n");
        assert_eq!(two.push().outcome, Pushed::Applied);
        drop(stand);
        (one, two, first, entry)
    }

    /// Fails by: a later absorb replacing or changing an earlier entry.
    #[test]
    fn a_second_rejected_push_adds_a_second_entry() {
        let (_one, two, first, entry) = crossed("offbox-push-second-entry");

        assert_eq!(two.local(&format!("absorbed/{first}")), entry);
        let entries: BTreeSet<String> = two
            .local("absorbed")
            .keys()
            .filter_map(|path| path.split('/').next().map(str::to_owned))
            .collect();
        assert!(entries.len() >= 2, "{entries:?}");
        assert!(entries.contains(&first));
    }

    /// Fails by: another writer's absorbed entry stored inside this one's.
    #[test]
    fn an_absorbed_entry_is_never_nested_in_another() {
        let (one, two, first, _) = crossed("offbox-push-nesting");

        // The first writer absorbed a snapshot that itself held `absorbed/<first>/`.
        assert!(one.dir().join(ABSORBED).join(&first).is_dir());
        for writer in [&one, &two] {
            for path in writer.local("absorbed").keys() {
                assert!(!path.contains("/absorbed/"), "{path}");
            }
            let tree = writer.tree(&writer.last().unwrap());
            for path in tree.keys() {
                assert_eq!(
                    path.matches("absorbed/").count().min(2),
                    usize::from(path.starts_with("absorbed/")),
                    "{path}"
                );
            }
        }
    }

    /// Fails by: an absent ref refusing the push that would recreate it.
    #[test]
    fn a_ref_rotated_away_is_recreated_on_the_first_attempt() {
        let base = base("offbox-push-rotated");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        // THE PREMISE: `last` is set, so only the zero-id arm can admit this.
        assert!(one.last().is_some());
        stand.borrow_mut().refs.clear();
        add(&one.transcript, "{\"n\":2}\n");

        assert_eq!(one.push().outcome, Pushed::Applied);

        assert_eq!(receives(&stand), 2);
        assert_eq!(Some(head(&stand, &one.meta)), one.last());
    }

    /// Fails by: a throttled push being retried here, moving `last` or the
    /// pushed cursor, or a record being sent twice once the forge accepts.
    #[test]
    fn a_throttled_push_returns_at_once_and_loses_nothing() {
        let base = base("offbox-push-throttled");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        let (last, pushed) = (one.last(), std::fs::read(one.dir().join(PUSHED)).unwrap());
        // After an applied push the file is that snapshot's `cursor.json`.
        assert_eq!(pushed, one.tree(last.as_deref().unwrap())["cursor.json"]);
        add(&one.transcript, "{\"n\":2}\n");
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Receive,
            left: 1,
            status: 429,
            headers: vec![(String::from("retry-after"), String::from("120"))],
        });

        let outcome = one.push().outcome;

        assert_eq!(
            outcome,
            Pushed::Throttled(lease::Throttled {
                retry_after: Some(120),
                reset_at: None,
            })
        );
        assert_eq!(receives(&stand), 2, "exactly one POST was throttled");
        assert_eq!(one.last(), last);
        assert_eq!(std::fs::read(one.dir().join(PUSHED)).unwrap(), pushed);

        assert_eq!(one.push().outcome, Pushed::Applied);
        let tree = one.tree(&head(&stand, &one.meta));
        assert_eq!(
            tree["transcript/main/0/000000.jsonl"],
            b"{\"n\":1}\n{\"n\":2}\n"
        );
        assert_eq!(
            std::fs::read(one.dir().join(PUSHED)).unwrap(),
            tree["cursor.json"]
        );
    }

    /// Fails by: a snapshot the remote already holds being sent again.
    #[test]
    fn a_second_push_with_nothing_changed_sends_nothing() {
        let base = base("offbox-push-unchanged");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        let first = one.push();
        assert_eq!(first.outcome, Pushed::Applied);
        assert_eq!(first.ended, ["transcript/main"]);

        let second = one.push();

        assert_eq!(second.outcome, Pushed::Unchanged);
        assert_eq!(second.outcome.token(), "unchanged");
        assert_eq!(second.ended, ["transcript/main"]);
        assert_eq!(receives(&stand), 1);
    }

    /// Fails by: a throttle at discovery reading as a failure, or anything
    /// being sent after it.
    #[test]
    fn a_throttled_probe_is_throttled_and_sends_nothing() {
        let base = base("offbox-push-probe");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Discovery,
            left: 1,
            status: 429,
            headers: Vec::new(),
        });

        let outcome = one.push().outcome;

        assert!(matches!(outcome, Pushed::Throttled(_)), "{outcome:?}");
        assert_eq!(outcome.code(), ExitCode::Violation);
        assert_eq!(receives(&stand), 0);
        assert!(!one.dir().exists(), "nothing was built");
    }

    /// Fails by: discovery's refusal reading as anything but unattached.
    #[test]
    fn a_refused_discovery_is_unattached_and_builds_nothing() {
        let base = base("offbox-push-unattached");
        let stand = standing(&[], Vec::new());
        stand.borrow_mut().status = 403;
        let one = Writer::new(&base, "one", "s");

        let outcome = one.push().outcome;

        assert_eq!(outcome, Pushed::Unattached);
        assert_eq!(outcome.code(), ExitCode::Usage);
        assert_eq!(receives(&stand), 0);
    }

    /// Every object `commit` reaches in `repo`, as the stand-in holds objects.
    fn objects_of(repo: &Path, commit: &str) -> Vec<lease::Object> {
        let reader = crate::git::ObjectReader::open(repo).unwrap();
        crate::git::object_ids_to_send(repo, None, commit)
            .unwrap()
            .iter()
            .map(|id| {
                let raw = reader.read(id).unwrap();
                lease::Object {
                    id: raw.id,
                    kind: raw.kind,
                    body: raw.body,
                }
            })
            .collect()
    }

    /// Fails by: a swap that keeps losing being retried without bound, or a
    /// lost race moving the pushed cursor.
    #[test]
    fn three_rejected_swaps_are_contended_after_three_posts() {
        let base = base("offbox-push-contended");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        let pushed = std::fs::read(one.dir().join(PUSHED)).unwrap();

        // Three other writers' snapshots, each moved in ahead of one swap.
        let elsewhere = base.join("elsewhere.git");
        gitwrite::init_bare(&elsewhere).unwrap();
        let mut others = Vec::new();
        for index in 0..3 {
            let entries = vec![(
                String::from("git/batten-receipts/r.json"),
                Content::Bytes(format!("other {index}\n").into_bytes()),
            )];
            let (commit, _) =
                gitwrite::commit_tree(&elsewhere, &entries, &[], TIME, "snapshot").unwrap();
            stand
                .borrow_mut()
                .objects
                .extend(objects_of(&elsewhere, &commit));
            others.push(commit);
        }
        stand.borrow_mut().moved = Some(Moved {
            left: 3,
            name: reference(&one.meta),
            id: others[0].clone(),
            then: others[1..].to_vec(),
        });
        add(&one.transcript, "{\"n\":2}\n");

        let outcome = one.push().outcome;

        assert_eq!(outcome, Pushed::Contended);
        assert_eq!(outcome.code(), ExitCode::Violation);
        assert_eq!(receives(&stand), 1 + 3);
        assert_eq!(std::fs::read(one.dir().join(PUSHED)).unwrap(), pushed);
        // What was absorbed on the way is kept for the next push: the
        // first store went where a store lives, the second differed from it.
        assert_eq!(
            one.read_git("batten-receipts/r.json").as_deref(),
            Some("other 0\n")
        );
        assert!(one.dir().join(ABSORBED).join(&others[1]).is_dir());
    }

    // --- the daemon (CLOUD-2721) ----------------------------------------------

    /// A clock a pause advances, a fixed source of randomness, and a look at the
    /// world after each wake.
    struct Sim<'a> {
        now: i64,
        random: u64,
        after_wake: Box<dyn FnMut(i64) + 'a>,
    }

    impl World for Sim<'_> {
        fn now(&mut self) -> i64 {
            self.now
        }

        fn pause(&mut self, millis: u64) {
            if millis >= 1000 {
                (self.after_wake)(self.now);
            }
            self.now += i64::try_from(millis / 1000).unwrap();
        }

        fn random(&mut self) -> u64 {
            self.random
        }
    }

    impl Writer {
        /// Run this writer's daemon for `wakes` wakes of a simulated clock
        /// starting at `now`, and return the clock's reading when it stopped.
        fn daemon(&self, now: i64, wakes: u64, after_wake: impl FnMut(i64)) -> i64 {
            let mut sim = Sim {
                now,
                random: 0,
                after_wake: Box::new(after_wake),
            };
            let launch = run(
                &Launching {
                    project_root: &self.root,
                    provisions: &self.provisions,
                    harness: &self.meta.harness,
                    session: &self.meta.session,
                    transcript: Some(&self.transcript),
                    value: "acme/state",
                    origin: Some(REMOTE),
                    wakes: Some(wakes),
                },
                &mut sim,
            )
            .expect("the daemon runs");
            assert_eq!(launch, Launch::Stopped);
            sim.now
        }

        fn status_path(&self) -> PathBuf {
            daemon_dir(&self.root).unwrap().join(STATUS)
        }

        fn status(&self) -> StatusFile {
            StatusFile::parse(&std::fs::read_to_string(self.status_path()).unwrap())
        }
    }

    /// Fails by: the forge's own wait being ignored, a backoff that does not
    /// grow, or one that grows past the cap.
    #[test]
    fn next_wait_follows_the_forge_then_doubles() {
        let throttled = |retry_after, reset_at| {
            Attempt::Throttled(lease::Throttled {
                retry_after,
                reset_at,
            })
        };
        let most = u64::MAX;
        assert_eq!(next_wait(Attempt::Done, 3, 3, 0, most), 0);
        assert_eq!(next_wait(Attempt::Contended, 0, 0, 0, most), 0);
        assert_eq!(next_wait(Attempt::Refused, 0, 0, 0, 0), 600);
        // `Retry-After` 120: that, plus at most half of it.
        assert_eq!(next_wait(throttled(Some(120), None), 1, 0, 0, 0), 120);
        assert_eq!(next_wait(throttled(Some(120), Some(9)), 1, 0, 0, 60), 180);
        assert_eq!(next_wait(throttled(Some(120), None), 1, 0, 0, 61), 120);
        // Only a reset instant, 300 seconds ahead.
        assert_eq!(next_wait(throttled(None, Some(1300)), 1, 0, 1000, 0), 300);
        assert_eq!(next_wait(throttled(None, Some(1300)), 1, 0, 1000, 150), 450);
        // A reset that is not ahead of now is no wait at all.
        assert_eq!(next_wait(throttled(None, Some(900)), 1, 0, 1000, most), 0);
        // Neither: a minute, then doubling, then the cap.
        for (count, base) in [(1, 60), (2, 120), (3, 240), (10, 3600), (40, 3600)] {
            assert_eq!(next_wait(throttled(None, None), count, 0, 0, 0), base);
            assert_eq!(
                next_wait(throttled(None, None), count, 0, 0, base / 2),
                base + base / 2
            );
            // A transport failure doubles the same way, on its own count.
            assert_eq!(next_wait(Attempt::Failed, 0, count, 0, 0), base);
        }
        assert_eq!(next_wait(throttled(Some(9000), None), 1, 0, 0, 0), 3600);
    }

    /// Fails by: a push with no trigger, inside the floor, or inside a wait.
    #[test]
    fn the_decision_to_push_needs_a_trigger_the_floor_and_no_wait() {
        assert!(!should_push(false, 599, 0));
        assert!(should_push(false, 600, 0));
        assert!(!should_push(true, 59, 0));
        assert!(should_push(true, 60, 0));
        assert!(!should_push(true, 60, 1));
    }

    /// Fails by: every session that starts together pushing together.
    #[test]
    fn the_first_attempt_is_spread_over_a_minute() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut delays = BTreeSet::new();
        for _ in 0..100 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let delay = first_delay(seed >> 11);
            assert!(delay <= 60, "{delay}");
            delays.insert(delay);
        }
        assert!(delays.len() > 1, "{delays:?}");
    }

    /// Fails by: a relaunch forgetting a wait the forge asked for, or a new
    /// session taking the old one's last-pushed commit as its own.
    #[test]
    fn a_restart_inside_a_wait_still_honours_it() {
        let base = base("offbox-daemon-restart");
        let stand = standing(&[], Vec::new());
        for (name, own) in [("own", true), ("other", false)] {
            let writer = Writer::new(&base, name, "s");
            let mut left = StatusFile::parse("");
            left.session = if own {
                leaf("exit-code", "s")
            } else {
                String::from("exit-code-0000000000000000")
            };
            left.pushed = String::from("0123456789abcdef0123456789abcdef01234567");
            left.throttles = 2;
            left.failures = 1;
            left.wait_until = 1100;
            put(&writer.status_path(), &left.render());
            let before = stand.borrow().asked.len();

            // 19 wakes from 1000 end at 1095: all inside the wait.
            let stopped = writer.daemon(1000, 19, |_| {});

            assert_eq!(stand.borrow().asked.len(), before, "{name}: no request");
            let kept = writer.status();
            assert_eq!((kept.throttles, kept.failures), (2, 1), "{name}");
            assert_eq!(kept.wait_until, 1100, "{name}");
            assert_eq!(kept.pushed == left.pushed, own, "{name}: {}", kept.pushed);
            assert_eq!(kept.session, leaf("exit-code", "s"));
            assert_eq!(kept.pid, std::process::id());

            // And once it has passed, the daemon asks.
            writer.daemon(stopped, 3, |_| {});
            assert!(stand.borrow().asked.len() > before, "{name}: it asks after");
        }
    }

    /// Fails by: a throttled daemon coming back before it was told to, or
    /// keeping its backoff after a push that was applied.
    #[test]
    fn a_throttled_daemon_waits_as_told_and_resets_on_an_applied_push() {
        let base = base("offbox-daemon-throttled");
        let stand = standing(&[], Vec::new());
        let writer = Writer::new(&base, "one", "s");
        put(&writer.transcript, "{\"n\":1}\n");
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Receive,
            left: 2,
            status: 429,
            headers: vec![(String::from("retry-after"), String::from("120"))],
        });
        let mut posts: Vec<i64> = Vec::new();
        let mut throttles: Vec<u32> = Vec::new();
        let status = writer.status_path();

        writer.daemon(1000, 80, |now| {
            if stand.borrow().receives > posts.len() {
                posts.push(now);
            }
            let seen = StatusFile::parse(&std::fs::read_to_string(&status).unwrap()).throttles;
            if throttles.last() != Some(&seen) {
                throttles.push(seen);
            }
        });

        assert_eq!(posts.len(), 3, "{posts:?}");
        assert_eq!(receives(&stand), 3);
        assert!(posts[1] - posts[0] >= 120, "{posts:?}");
        assert!(posts[2] - posts[1] >= 120, "{posts:?}");
        assert_eq!(throttles, [0, 1, 2, 0]);
        let last = writer.status();
        assert_eq!(Some(last.pushed), writer.last());
        assert_eq!(last.wait_until, 0);
        assert_eq!(last.attached, "yes");
        assert_eq!(last.source, "ok");
    }

    /// Fails by: an unwritable remote being pushed to, or the agent not being
    /// told how to attach it.
    #[test]
    fn an_unattached_remote_is_noted_and_never_pushed_to() {
        let base = base("offbox-daemon-unattached");
        let stand = standing(&[], Vec::new());
        stand.borrow_mut().status = 403;
        let writer = Writer::new(&base, "one", "s");

        writer.daemon(1000, 3, |_| {});

        let status = writer.status();
        assert_eq!(status.attached, "no");
        assert_eq!(status.failures, 1);
        assert!(status.wait_until > 1000);
        let note = std::fs::read_to_string(daemon_dir(&writer.root).unwrap().join(NOTE)).unwrap();
        assert_eq!(note, format!("{}\n", attach_note("acme/state")));
        assert_eq!(receives(&stand), 0);
    }
}
