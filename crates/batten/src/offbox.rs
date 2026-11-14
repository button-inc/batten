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
pub const DIR: &str = "offbox";

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
    let digest = blake3::hash(session.as_bytes()).to_hex();
    format!("{harness}-{}", &digest[..16])
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
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .map_err(refused)?;
                if file.metadata().map_err(refused)?.len() > position.length {
                    file.set_len(position.length).map_err(refused)?;
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
            found.push((format!("state/{relative}"), path));
        }
    }
    if let Ok(git) = crate::git::git_dir(project_root) {
        for (relative, path) in files_under(&git) {
            let entry = relative.split('/').next().unwrap_or_default();
            if !entry.starts_with(GIT_STORE_PREFIX) {
                continue;
            }
            let excluded = GIT_EXCLUDED
                .iter()
                .any(|name| entry == *name || (name.ends_with('-') && entry.starts_with(name)));
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
    let last: BTreeMap<String, String> = match crate::git::resolve_ref(repo, LAST)? {
        Some(commit) => gitwrite::tree_index(repo, &commit)?.into_iter().collect(),
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
        if entries.contains_key(path) {
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
