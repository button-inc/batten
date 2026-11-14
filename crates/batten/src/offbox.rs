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
const SESSIONS: &str = crate::offbox_watch::SESSIONS;

/// A session's local snapshot repository, inside its session directory.
const REPO: &str = "repo.git";

/// The ref, in a session's local repository, naming the commit last pushed or
/// absorbed. The push slice moves it; a snapshot only reads it.
pub const LAST: &str = "refs/offbox/last";

/// The ref naming the commit a push is about to send, written before the
/// request: what tells this machine's own commit, applied by the remote and
/// never recorded here, from another writer's.
const SENT: &str = "refs/offbox/sent";

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

/// The entries of the state directory that are NOT stores. An exclude-list, as
/// [`GIT_EXCLUDED`] is and for its reason: a store added later is shipped by
/// default, and leaving one out is a decision somebody wrote down here.
///
/// It was once an allow-list of one, `captures`, on the claim that everything
/// else was rebuilt. The journal, the receipts, the findings, the session
/// stamps and the drain records are not rebuilt, and none of them left the
/// machine.
///
/// - `cache`, `provision`: rebuilt from the tree and from pinned downloads.
/// - `offbox` and every entry whose name starts with it: this feature's own
///   working state — where the snapshot is built from, its lock and its
///   record of which sessions it has imported — which cannot be in it.
/// - `identity`: a secret key. It is never content and never leaves the
///   machine, whatever the scanner would have made of it.
/// - `store.json`: where this checkout is on this machine, written on first
///   use; another machine's is wrong here.
/// - `mutate`: a staged checkout and a build directory, apart from the files
///   [`STATE_FILES_UNDER`] names.
const STATE_EXCLUDED: [&str; 6] = [
    "cache",
    "provision",
    "offbox",
    "identity",
    "store.json",
    "mutate",
];

/// Whether an entry of the state directory is a store: any name of one path
/// segment that [`STATE_EXCLUDED`] does not list.
fn state_store(entry: &str) -> bool {
    !entry.is_empty()
        && entry != "."
        && entry != ".."
        && !entry.contains(['/', '\\'])
        && !entry.starts_with("offbox")
        && !STATE_EXCLUDED.contains(&entry)
}

/// State entries taken in part: only the files DIRECTLY under each prefix
/// (CLOUD-2723). The mutation sweep's verdict journal and reach seal live
/// there, beside a staged checkout, a source snapshot and a build directory
/// that are rebuilt and must not be shipped.
const STATE_FILES_UNDER: [&str; 1] = ["mutate/schema/"];

/// Whether a state-relative path is a file directly under a listed prefix.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT mutate-tree-dir-included|s@^            .is_some_and(\x7crest\x7c !rest.is_empty() \&\& !rest.contains('/'))$@            .is_some_and(\x7crest\x7c !rest.is_empty())@|the_mutation_stores_are_carried_and_their_work_directories_are_not
fn listed_file(relative: &str) -> bool {
    STATE_FILES_UNDER.iter().any(|prefix| {
        relative
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
    })
}

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
///
/// **EVERY FILE THIS TOUCHES IS REPLACED WHOLE, AND SYNCED, BEFORE IT RETURNS.**
/// The caller replaces the cursor only after, so the cursor never covers a
/// byte that is not on the disk: a kill leaves a file as it was or as it is
/// to be, and a machine going down takes nothing the cursor had counted. An
/// open file is at most a segment long, so replacing it costs one segment.
///
/// # Errors
///
/// Where the open file is SHORTER than its cursor entry says. That is content
/// gone from under the cursor, which nothing here can put back, and it is
/// refused aloud: appending would bury the hole under new records.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT closed-segment-rewritten|s@^            .filter(\x7cname\x7c name.ends_with(".jsonl") \&\& position.length < SEGMENT);$@            .filter(\x7cname\x7c name.ends_with(".jsonl"));@|the_tree_holds_the_stores_and_the_transcript_in_segments
//MUTANT oversized-record-replaced-by-a-digest|s@^            for (at, chunk) in piece.chunks(PART).enumerate() {$@            for (at, chunk) in piece.chunks(PART).take(1).enumerate() {@|an_oversized_record_is_cut_into_parts_and_never_replaced
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the names compared are this function's own, written three lines below in lower case"
)]
fn append_stream(dir: &Path, prefix: &str, position: &mut Position, stream: &[u8]) -> Result<u64> {
    let generation = dir.join(prefix).join(position.generation.to_string());
    let refused = |err: std::io::Error| anyhow::anyhow!("offbox: a segment will not write: {err}");
    std::fs::create_dir_all(&generation).map_err(refused)?;
    let mut next = position
        .file
        .as_deref()
        .and_then(segment_index)
        .map_or(0, |index| index + 1);
    let mut written = 0_u64;
    // Every file this call touches, oldest first, with ALL it is to hold.
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for piece in stream.split_inclusive(|byte| *byte == b'\n') {
        if piece.len() > PART {
            let parts = piece.len().div_ceil(PART);
            for (at, chunk) in piece.chunks(PART).enumerate() {
                let ending = if at + 1 == parts { "jsonl" } else { "part" };
                let name = format!("{next:06}.{ending}");
                next += 1;
                files.push((name.clone(), chunk.to_vec()));
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
        match open {
            Some(name) if files.last().is_some_and(|(last, _)| *last == name) => {}
            Some(name) => {
                // OPENED BY AN EARLIER CALL: what the cursor covers of it, and
                // not a byte past — a kill's leftovers are cut here.
                let mut held = std::fs::read(generation.join(&name)).map_err(refused)?;
                let covered = usize::try_from(position.length).unwrap_or(usize::MAX);
                if held.len() < covered {
                    return Err(anyhow::anyhow!(
                        "offbox: {prefix}/{}/{name} holds {} bytes and its cursor covers {covered}",
                        position.generation,
                        held.len()
                    ));
                }
                held.truncate(covered);
                files.push((name, held));
            }
            None => {
                let name = format!("{next:06}.jsonl");
                next += 1;
                position.length = 0;
                position.file = Some(name.clone());
                files.push((name, Vec::new()));
            }
        }
        if let Some((_, held)) = files.last_mut() {
            held.extend_from_slice(piece);
        }
        position.length += piece.len() as u64;
        written += piece.len() as u64;
    }
    for (name, held) in &files {
        crate::durable::replace(generation.join(name), held).map_err(refused)?;
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
/// `state/<entry>/…` from the state directory and `git/<entry>/…` from the
/// project's per-worktree git directory, each by exclude-list.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT provision-dir-included|s@^            if !state_store(\&entry) \&\& !listed_file(\&relative) {$@            if false {@|the_tree_holds_the_stores_and_the_transcript_in_segments
//MUTANT secret-key-shipped|s@^    "identity",$@    "identity-is-shipped",@|every_state_store_ships_and_the_secret_key_never_does
//MUTANT state-stores-allow-listed|s@^        \&\& !STATE_EXCLUDED.contains(\&entry)$@        \&\& entry == "captures"@|every_state_store_ships_and_the_secret_key_never_does
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
            if !state_store(&entry) && !listed_file(&relative) {
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

/// Put back, from the last snapshot, every file of a feed that this disk holds
/// LESS of than that snapshot did.
///
/// A feed's files only grow. One that is shorter here than in the last
/// snapshot — or, for the file a feed is still appending to, not here at all —
/// is content this machine lost: a disk that went down with it unwritten, a
/// directory emptied by hand. The tree is built from the disk, so without this
/// the next push would take the loss to the remote and call it the session.
/// With it, the disk is made whole from what was pushed BEFORE anything is
/// appended, and the next snapshot holds everything the last one did.
///
/// A closed file that is absent altogether is left absent: it is carried
/// forward by the id it had, and nothing is appended to it.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT local-loss-pushed-over-the-remote|s@^            if held > have.unwrap_or(0) {$@            if false {@|a_file_this_disk_lost_part_of_is_put_back_and_never_pushed_short
fn heal(
    dir: &Path,
    repo: &Path,
    cursors: &Cursors,
    (last_commit, last): (Option<&str>, &BTreeMap<String, String>),
) -> Result<()> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: a segment will not be put back: {err}");
    for (prefix, position) in cursors {
        let under = format!("{prefix}/{}/", position.generation);
        for (path, id) in last.range(under.clone()..) {
            let Some(name) = path.strip_prefix(&under) else {
                break;
            };
            // ANOTHER WRITER'S STREAM AT THIS PATH IS NOT THIS DISK'S FILE: the
            // absorb kept it aside, and it is longer or shorter than ours for
            // no reason that is a loss.
            if foreign(dir, last_commit, path) {
                continue;
            }
            let local = dir.join(path);
            let have = std::fs::metadata(&local).map(|meta| meta.len()).ok();
            let open = position.file.as_deref() == Some(name);
            if have.is_none() && !open {
                continue;
            }
            let Some(held) = gitwrite::blob_len(repo, id) else {
                continue;
            };
            if held > have.unwrap_or(0) {
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent).map_err(refused)?;
                }
                crate::durable::replace(&local, gitwrite::read_blob(repo, id)?).map_err(refused)?;
            }
        }
    }
    Ok(())
}

/// [`snapshot`]'s body, apart from it so the staging directory is removed on
/// every path out — a refusal and an error as much as a build.
//MUTANT-SUITE crates/batten/tests/it/offbox_snapshot.rs
//MUTANT appended-file-named-by-the-last-tree|s@^            let id = gitwrite::write_blob(repo, \&std::fs::read(\&path).map_err(unread)?)?;$@            let id = match last.get(\&format!("{root}/{relative}")) { Some(id) => id.clone(), None => gitwrite::write_blob(repo, \&std::fs::read(\&path).map_err(unread)?)? };@|every_snapshot_holds_the_source_whole_whatever_closed_in_between
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
    crate::durable::replace(staging.join("meta.json"), &meta_body).map_err(unwritten)?;
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
    heal(&dir, repo, &cursors, (last_commit.as_deref(), &last))?;

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
            crate::durable::replace(staging.join(INCOMING), &stream).map_err(unwritten)?;
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

    // THE APPENDED ROOTS: EVERY FILE ON DISK, NAMED BY ITS OWN BYTES, EVERY
    // TIME. Nothing is remembered about a file from the snapshot before, so
    // there is nothing to fall out of step with it: the tree is a function of
    // the directory, and a snapshot built after a kill, a restore or a rejected
    // push is the one built after none of them.
    //
    // It was once otherwise — a file the last tree held, and no feed was still
    // appending to, kept the id it had. A file open at one snapshot that had
    // filled and closed by the next was neither open nor new, and every record
    // appended to it in between was left out of every later snapshot.
    //
    // Naming a file costs a read and a hash and no write: the odb is asked for
    // the id first, and a blob it holds is not stored again.
    for root in APPENDED {
        for (relative, path) in files_under(&dir.join(root)) {
            let id = gitwrite::write_blob(repo, &std::fs::read(&path).map_err(unread)?)?;
            entries.insert(format!("{root}/{relative}"), Content::Blob(id));
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
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT history-fed-before-live-data|s@^    feeds.extend(later);$@    drop(feeds.splice(0..0, later));@|the_feed_list_has_the_live_feeds_before_any_history
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
            feeds.push(Feed {
                prefix: own_prefix(&found.sub),
                source,
                session: found,
            });
        }
    }
    // LIVE DATA FIRST (CLOUD-2735): the cap is spent in feed order, so what
    // comes after takes only what the session's own records left.
    let later = extra.iter().map(|feed| Feed {
        prefix: feed.prefix.clone(),
        source: feed.source,
        session: feed.session.clone(),
    });
    feeds.extend(later);
    Ok(feeds)
}

/// Where one of a session's own files goes in its snapshot: `transcript/main`,
/// or `transcript/<key>` for a subagent's.
fn own_prefix(sub: &str) -> String {
    if sub.is_empty() {
        String::from("transcript/main")
    } else {
        format!("transcript/{}", segment(sub))
    }
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
//MUTANT push-ignores-the-push-lock|s@^    if pushing.is_none() {$@    if false {@|a_push_waits_for_the_push_lock_and_writes_nothing
//MUTANT prune-after-a-failed-push|s@^                return Ok(Push::only(Pushed::Throttled(throttle)));$@                gitwrite::prune_unreachable(\&repo, std::slice::from_ref(\&commit))?; return Ok(Push::only(Pushed::Throttled(throttle)));@|nothing_is_pruned_after_a_throttled_or_a_rejected_push
//MUTANT throttled-push-retried-at-once|s@^                return Ok(Push::only(Pushed::Throttled(throttle)));$@                let _ = throttle;@|a_throttled_push_returns_at_once_and_loses_nothing
//MUTANT unchanged-snapshot-still-sent|s@^        if unchanged \&\& last.as_deref() == Some(tip.as_str()) {$@        if false {@|a_second_push_with_nothing_changed_sends_nothing
//MUTANT unchanged-said-from-memory|s@^        if unchanged \&\& last.as_deref() == Some(tip.as_str()) {$@        if unchanged {@|unchanged_is_never_said_of_a_remote_that_lost_the_ref
//MUTANT pushed-cursor-recorded-before-the-swap|s@^        let outcome = lease::push(\&session.remote, \&repo, \&name, \&commit, \&admit)?;$@        record_pushed(\&dir, \&repo, \&commit)?; let outcome = lease::push(\&session.remote, \&repo, \&name, \&commit, \&admit)?;@|a_throttled_push_returns_at_once_and_loses_nothing
//MUTANT rejected-swap-retried-without-bound|s@^    for _ in 0..ATTEMPTS {$@    for _ in 0..ATTEMPTS + 2 {@|three_rejected_swaps_are_contended_after_three_posts
pub fn push_once(session: &Session<'_>, extra: &[Feed<'_>]) -> Result<Push> {
    push_capped(session, extra, BYTE_CAP)
}

/// [`push_once`] with the most new record bytes it may add named outright.
fn push_capped(session: &Session<'_>, extra: &[Feed<'_>], byte_cap: u64) -> Result<Push> {
    let advertised = match lease::survey(&session.remote, Service::ReceivePack) {
        Ok(Ok(advertised)) => advertised,
        Ok(Err(401 | 403 | 404)) => return Ok(Push::only(Pushed::Unattached)),
        Ok(Err(other)) => {
            return Err(anyhow::anyhow!(
                "offbox: the state repository answered {other} to discovery"
            ));
        }
        Err(err) => return throttled(err),
    };
    let dir = session_dir(session.project_root, &session.meta)?;
    let repo = local_repo(&dir);
    let name = reference(&session.meta);
    // WHAT THE REMOTE HOLDS, FROM THE REMOTE. Every decision below that says
    // the two sides agree is made against this, never against what this
    // machine remembers having pushed.
    let mut tip = advertised.head_of(&name).to_owned();
    // ONE PUSHER AT A TIME (CLOUD-2738), for the whole run: the prune below
    // must never meet a commit another process is part-way through building.
    let pushing = take_push_lock(&dir)?;
    if pushing.is_none() {
        return Ok(Push::only(Pushed::Contended));
    }

    own_push_recorded(&dir, &repo, &tip)?;

    let source =
        crate::sessions::source_named(&session.meta.harness, session.transcript.as_deref());
    let feeds = feeds_of(session, source.as_deref(), extra)?;

    let mut ended = Vec::new();
    for _ in 0..ATTEMPTS {
        let built = snapshot(
            session.project_root,
            session.provisions,
            &session.meta,
            &feeds,
            session.time,
            byte_cap,
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
        // `UNCHANGED` IS A STATEMENT ABOUT THE REMOTE: its ref names a commit
        // whose tree is this directory's. A tree equal to the one this machine
        // remembers pushing says nothing where the remote's ref is gone, or is
        // another writer's; the push goes on, and either recreates the ref or
        // is rejected into the fetch below.
        if unchanged && last.as_deref() == Some(tip.as_str()) {
            return Ok(Push {
                outcome: Pushed::Unchanged,
                ended,
            });
        }
        // WHAT THIS PUSH MAY REPLACE: the value this repository last pushed or
        // absorbed, or nothing at all. An absent ref has nothing to lose — it
        // is a first push, or the branch was rotated away.
        let admit = |old: &str| old == lease::ZERO || last.as_deref() == Some(old);
        // THE INTENT, BEFORE THE REQUEST. A kill after the remote applied the
        // swap and before `LAST` moved leaves the remote holding a commit this
        // machine does not remember pushing; this ref is how the next run
        // knows it for its own, where it would otherwise absorb its own
        // session as another writer's.
        gitwrite::set_ref(&repo, SENT, &commit)?;
        crate::testing::step()?; // the request is a step: a kill before it sends nothing
        let outcome = lease::push(&session.remote, &repo, &name, &commit, &admit)?;
        crate::testing::step()?; // and so is its answer: a kill here is a reply never read
        match outcome {
            lease::Outcome::Applied => {
                gitwrite::set_ref(&repo, LAST, &commit)?;
                // ONLY NOW, AND ONLY HERE (CLOUD-2738): the remote holds this
                // commit, and it holds everything the one before it held, so
                // what it does not reach is a cache of superseded objects.
                gitwrite::prune_unreachable(&repo, std::slice::from_ref(&commit))?;
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
        // REJECTED: another writer holds the ref. Take what it wrote, keep all
        // of it, and build again on top. After the last attempt too: THE LOOP'S
        // BOUND IS THE ONLY BOUND, and what the last rival wrote is then here
        // for the next push to build on.
        let theirs = match lease::advertise(&session.remote, Service::ReceivePack) {
            Ok(advertisement) => advertisement.head_of(&name).to_owned(),
            Err(err) => return throttled(err),
        };
        tip.clone_from(&theirs);
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

/// Record a push the remote applied and this machine never did: where the
/// remote's ref is the commit [`SENT`] names, and this repository holds it,
/// `LAST` and the pushed cursor are moved to it.
///
/// A kill between the remote applying a swap and `LAST` moving leaves exactly
/// that. Without this the next push meets a ref it does not remember writing,
/// is rejected, and absorbs its own session as another writer's.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT own-push-absorbed-as-anothers|s@^    if sent.as_deref() != Some(tip) \x7c\x7c last.as_deref() == Some(tip) {$@    if true {@|a_push_the_remote_applied_and_this_machine_never_recorded_is_its_own
fn own_push_recorded(dir: &Path, repo: &Path, tip: &str) -> Result<()> {
    if !repo.exists() {
        return Ok(()); // a first push: nothing was ever sent from here
    }
    let sent = crate::git::resolve_ref(repo, SENT)?;
    let last = crate::git::resolve_ref(repo, LAST)?;
    if sent.as_deref() != Some(tip) || last.as_deref() == Some(tip) {
        return Ok(());
    }
    if gitwrite::tree_id(repo, tip).is_err() {
        return Ok(());
    }
    gitwrite::set_ref(repo, LAST, tip)?;
    record_pushed(dir, repo, tip)
}

/// The lock a push or a restore of one session holds for its whole run, in the
/// session's own directory.
const PUSH_LOCK: &str = "push.lock";

/// Take the session's push lock, or `None` where another process holds it: the
/// daemon and a hand-run `batten offbox push` are the two this keeps apart.
fn take_push_lock(dir: &Path) -> Result<Option<std::fs::File>> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: the push lock will not open: {err}");
    std::fs::create_dir_all(dir).map_err(refused)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(PUSH_LOCK))
        .map_err(refused)?;
    let taken = fs4::FileExt::try_lock(&file).is_ok();
    Ok(taken.then_some(file))
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
        "state"
            if state_store(entry)
                || STATE_FILES_UNDER
                    .iter()
                    .any(|prefix| prefix.split('/').next() == Some(entry)) =>
        {
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

    /// Take a whole stream as this writer's own under `base`: every file is
    /// written, over whatever is there.
    ///
    /// Only for a stream this writer has no cursor progress in. A file there
    /// can then only be a file an earlier, killed adoption of this stream put
    /// there, or bytes a killed first append left that no cursor covers and
    /// the source hands back — and neither is content that would be lost.
    fn adopt_all(&self, base: &Path, group: &Group) -> Result<()> {
        let refused =
            |err: std::io::Error| anyhow::anyhow!("offbox: an adopted file will not write: {err}");
        for (relative, id) in group {
            let target = under(base, relative);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(refused)?;
            }
            crate::durable::replace(&target, self.read(id)?).map_err(refused)?;
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
//MUTANT adoption-judged-by-the-files|s@^        if own \&\& !progressed("transcript/") {$@        if own \&\& files_under(\&local).is_empty() {@|a_kill_at_any_step_of_a_restore_into_a_new_container_loses_nothing
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

    // WHETHER A STREAM IS THIS WRITER'S IS READ FROM ITS CURSOR, NEVER FROM
    // WHETHER FILES ARE THERE. An adoption writes the files and then the cursor
    // entries; killed between the two, it leaves files and no entry. Judged by
    // the files, the next start took them for a local stream, adopted no
    // cursor, and the snapshot after it — whose own cursor started from
    // nothing — removed them as leftovers and pushed over the only copy.
    // Judged by the cursor, a stream with no progress is adopted again, whole,
    // and the second adoption finishes what the first began.
    let progressed = |root: &str| {
        load_cursors(&dir).iter().any(|(prefix, position)| {
            prefix.starts_with(root) && (!position.cursor.is_empty() || position.file.is_some())
        })
    };
    let mut adopted: Vec<String> = Vec::new();
    if !transcript.is_empty() {
        let local = dir.join("transcript");
        if own && !progressed("transcript/") {
            theirs.adopt_all(&local, &transcript)?;
            adopted.push(String::from("transcript/"));
        } else if !theirs.all_equal(&local, &transcript)? {
            theirs.keep_aside("transcript", &transcript)?;
        }
    }
    for (entry, group) in &history {
        let local = dir.join("history").join(entry);
        let root = format!("history/{entry}/");
        if own && !progressed(&root) {
            theirs.adopt_all(&local, group)?;
            adopted.push(root);
        } else if files_under(&local).is_empty() {
            theirs.place_all(&local, group)?;
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

// --- the import (CLOUD-2735) ---------------------------------------------------

/// The directory, under the machine's state root, that holds one marker per
/// session whose records are known to be in the state repository.
///
/// Per machine, and not per checkout or per session: an imported session has no
/// ref of its own, so the marker is what stops another session or another
/// checkout here from uploading the same history again.
const IMPORTED: &str = "offbox-imported";

/// The lock one importing daemon per machine holds, beside the markers.
const IMPORT_LOCK: &str = "offbox-import.lock";

/// The tree root, and the local directory, imported sessions are kept under.
const HISTORY: &str = "history";

/// An imported session's own description, beside its segment files.
const HISTORY_META: &str = "meta.json";

/// One session a source lists, other than the live one, with all its files.
struct Listed<'a> {
    harness: &'a str,
    source: &'a dyn SessionSource,
    id: String,
    leaf: String,
    /// The project directory the agent recorded, where it recorded one.
    project: Option<PathBuf>,
    files: Vec<SessionRef>,
}

/// Every session the sources list on this machine, other than the live one —
/// `live` is its harness and its id. A source that will not list gives none:
/// what it holds is looked for again before the next push.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT live-session-imported-as-history|s@^            if harness == live.0 \&\& file.id == live.1 {$@            if false {@|the_live_session_is_not_imported_and_the_others_are
fn listed<'a>(history: &'a [crate::sessions::Named], live: (&str, &str)) -> Vec<Listed<'a>> {
    let mut found = Vec::new();
    for (harness, source) in history {
        let mut sessions: BTreeMap<String, Listed<'a>> = BTreeMap::new();
        for file in source.list().unwrap_or_default() {
            if harness == live.0 && file.id == live.1 {
                continue;
            }
            let session = sessions.entry(file.id.clone()).or_insert_with(|| Listed {
                harness,
                source: source.as_ref(),
                id: file.id.clone(),
                leaf: leaf(harness, &file.id),
                project: None,
                files: Vec::new(),
            });
            // The main file's directory, where the session has a main file.
            if file.project.is_some() && (file.sub.is_empty() || session.project.is_none()) {
                session.project.clone_from(&file.project);
            }
            session.files.push(file);
        }
        found.extend(sessions.into_values());
    }
    found
}

/// Where a listed session stands, by local files alone: nothing here asks the
/// remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// Its marker exists.
    Marked,
    /// Its own daemon is running and pushing it; looked at again next push.
    Live,
    /// Known to be stored without this daemon importing it; to be marked.
    Stored,
    /// To be imported.
    Owed,
}

/// The main checkout a recorded project directory is in, where it is in one.
fn checkout_of(project: Option<&Path>) -> Option<PathBuf> {
    crate::git::repo_root(project?).ok()
}

/// Whether the push record at `pushed` — the cursors its session's own daemon
/// last pushed — covers every file the source lists for `session`, each read to
/// the end of its source.
///
/// A listed file with no entry, a source that will not read, and one replaced
/// under its cursor all answer no. Entries under `history/` are never looked at.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT unlisted-file-counts-as-pushed|s@^            return false; // a file the push never saw$@            return true;@|a_file_the_push_never_saw_is_imported_and_not_marked
//MUTANT partly-pushed-session-marked-stored|s@^        read.is_ok_and(\x7cbatch\x7c batch.is_ended())$@        read.is_ok()@|a_partly_pushed_session_with_no_daemon_is_imported_whole
fn pushed_whole(session: &Listed<'_>, pushed: &Path) -> bool {
    let Ok(body) = std::fs::read(pushed) else {
        return false;
    };
    let Ok(cursors) = serde_json::from_slice::<Cursors>(&body) else {
        return false;
    };
    session.files.iter().all(|file| {
        let Some(position) = cursors.get(&own_prefix(&file.sub)) else {
            return false; // a file the push never saw
        };
        let from = Cursor(unhex(&position.cursor));
        let read = session.source.read(file, &from, 1);
        read.is_ok_and(|batch| batch.is_ended())
    })
}

/// Where `session` stands (CLOUD-2735). `checkout` is the checkout its project
/// directory is in, `dir` this daemon's session directory with `cursors` its
/// cursor file, and `machine` the machine's state root.
///
/// In order: its marker; **then whether its own daemon is alive**, before any
/// check that could mark it, so a live session is never marked however far its
/// push record has got; then a local `history/<leaf>/` with no cursor entry
/// under it, which only another writer's snapshot leaves behind — [`snapshot`]
/// writes the entry for every feed it is given before that feed's first byte;
/// then its own daemon's push record.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT live-session-marked-stored|s@^    if live_elsewhere {$@    if false {@|a_session_live_elsewhere_is_neither_imported_nor_marked
//MUTANT session-live-elsewhere-imported|s@^        return Standing::Live;$@        return Standing::Owed;@|a_session_live_elsewhere_is_neither_imported_nor_marked
//MUTANT absorbed-history-imported-again|s@^    if absorbed_here {$@    if false {@|history_absorbed_from_another_writer_is_marked_and_not_imported
//MUTANT fully-pushed-session-imported-again|s@^    if whole {$@    if false {@|a_session_its_own_daemon_pushed_whole_is_marked_and_not_imported
fn standing_of(
    session: &Listed<'_>,
    checkout: Option<&Path>,
    dir: &Path,
    cursors: &Cursors,
    machine: &Path,
) -> Standing {
    if machine.join(IMPORTED).join(&session.leaf).exists() {
        return Standing::Marked;
    }
    let theirs = checkout
        .and_then(|root| crate::state::repo_state_dir(root).ok())
        .map(|state| state.join(DIR));
    let live_elsewhere = theirs.as_deref().is_some_and(|theirs| {
        crate::offbox_watch::probe(theirs, Some(&session.leaf))
            == crate::offbox_watch::Liveness::Alive
    });
    if live_elsewhere {
        return Standing::Live;
    }
    let under = format!("{HISTORY}/{}/", session.leaf);
    let absorbed_here = dir.join(HISTORY).join(&session.leaf).exists()
        && !cursors.keys().any(|prefix| prefix.starts_with(&under));
    if absorbed_here {
        return Standing::Stored;
    }
    let whole = theirs.is_some_and(|theirs| {
        pushed_whole(
            session,
            &theirs.join(SESSIONS).join(&session.leaf).join(PUSHED),
        )
    });
    if whole {
        return Standing::Stored;
    }
    Standing::Owed
}

/// Write `leaf`'s marker under `machine`.
fn mark(machine: &Path, leaf: &str) -> Result<()> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: an import marker will not write: {err}");
    let markers = machine.join(IMPORTED);
    std::fs::create_dir_all(&markers).map_err(refused)?;
    crate::durable::replace(markers.join(leaf), "").map_err(refused)
}

/// Take the machine's import lock, or `None` where another daemon holds it.
/// Without it, every agent on one machine would upload the same history.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT second-importer-runs|s@^    let importing_elsewhere = fs4::FileExt::try_lock(\&file).is_err();$@    let importing_elsewhere = false;@|a_daemon_without_the_import_lock_imports_nothing_until_it_is_free
fn take_import_lock(machine: &Path) -> Result<Option<std::fs::File>> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: the import lock will not open: {err}");
    std::fs::create_dir_all(machine).map_err(refused)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(machine.join(IMPORT_LOCK))
        .map_err(refused)?;
    let importing_elsewhere = fs4::FileExt::try_lock(&file).is_err();
    Ok((!importing_elsewhere).then_some(file))
}

/// One session a push is given the feeds of.
struct Fed {
    leaf: String,
    /// Its feeds' prefixes: `history/<leaf>/transcript/<key>`.
    prefixes: Vec<String>,
    /// Whether its `meta.json` was already written when the push began, so the
    /// push's snapshot carries it.
    described: bool,
    /// What its `meta.json` holds.
    meta: Vec<u8>,
}

/// What one push imports, and what the sources listed.
#[derive(Default)]
struct Import<'a> {
    /// One feed per file of each session still to import, in listed order.
    feeds: Vec<Feed<'a>>,
    fed: Vec<Fed>,
    /// How many sessions the sources listed, the live one apart.
    listed: u64,
    /// The leaves of the listed sessions that are marked.
    marked: Vec<String>,
}

/// Decide what the next push imports (CLOUD-2735): one feed per file of every
/// listed session that is not marked, not live elsewhere, and not found stored
/// — and mark the ones found stored.
///
/// **A project that does not resolve is still imported.** A recorded directory
/// that is gone, is no checkout, or has no http(s) origin gives a `meta.json`
/// whose `origin` is null; nothing is skipped for lack of one.
///
/// # Errors
///
/// A marker that will not write.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT unresolved-project-skipped|s@^        let checkout = checkout_of(session.project.as_deref());$@        let checkout = checkout_of(session.project.as_deref()); if checkout.is_none() { continue; }@|a_session_whose_project_is_gone_is_imported_with_no_origin
//MUTANT marker-written-before-the-push|s@^                import.fed.push(fed);$@                mark(machine, \&fed.leaf)?; import.fed.push(fed);@|a_throttled_push_marks_nothing_and_the_next_applied_one_does
fn plan_import<'a>(
    history: &'a [crate::sessions::Named],
    live: (&str, &str),
    dir: &Path,
    machine: &Path,
) -> Result<Import<'a>> {
    let cursors = load_cursors(dir);
    let mut import = Import::default();
    for session in listed(history, live) {
        import.listed += 1;
        let checkout = checkout_of(session.project.as_deref());
        match standing_of(&session, checkout.as_deref(), dir, &cursors, machine) {
            Standing::Marked => import.marked.push(session.leaf),
            Standing::Live => {}
            Standing::Stored => {
                mark(machine, &session.leaf)?;
                import.marked.push(session.leaf);
            }
            Standing::Owed => {
                let origin = checkout.as_deref().and_then(|root| {
                    let remotes = crate::git::remotes(root).ok()?;
                    let (_, url) = remotes.into_iter().find(|(name, _)| name == "origin")?;
                    origin_path(&url)
                });
                let mut meta = serde_json::to_vec_pretty(&serde_json::json!({
                    "harness": session.harness,
                    "session": session.id,
                    "project": session.project,
                    "origin": origin,
                }))
                .map_err(|err| {
                    anyhow::anyhow!("offbox: an imported session's meta will not serialise: {err}")
                })?;
                meta.push(b'\n');
                let under = format!("{HISTORY}/{}", session.leaf);
                let mut prefixes = Vec::new();
                for file in session.files {
                    let prefix = format!("{under}/{}", own_prefix(&file.sub));
                    prefixes.push(prefix.clone());
                    import.feeds.push(Feed {
                        prefix,
                        source: session.source,
                        session: file,
                    });
                }
                let fed = Fed {
                    described: dir.join(&under).join(HISTORY_META).exists(),
                    leaf: session.leaf,
                    prefixes,
                    meta,
                };
                import.fed.push(fed);
            }
        }
    }
    Ok(import)
}

/// After a push that was given `import`'s feeds: write each new session's
/// `meta.json`, and mark each session the push finished. Returns the leaves it
/// marked, and whether any imported feed moved.
///
/// **A session is finished by a push that found nothing new in it.** The push
/// was applied, or changed nothing; its snapshot read every feed of the session
/// to the end of its source; none of those feeds' cursors moved in it — so
/// every record was already in an earlier snapshot, and this push carried them
/// all; and its `meta.json` was written before the push began. A session
/// another agent is still writing never reaches that while it grows.
///
/// **`meta.json` is written only once the cursor file names the session's
/// feeds**, so a `history/<leaf>/` with no cursor entry stays what only another
/// writer's snapshot leaves.
///
/// `before` is the cursor file as the push found it; `ended` the prefixes its
/// snapshot read to the end, where it was applied or changed nothing.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT unread-session-marked-imported|s@^        let read_out = fed.prefixes.iter().all(\x7cprefix\x7c ended.contains(prefix));$@        let read_out = true;@|history_is_imported_behind_live_data_inside_the_cap
fn finish_import(
    import: &Import<'_>,
    dir: &Path,
    machine: &Path,
    before: &Cursors,
    ended: Option<&[String]>,
) -> Result<(Vec<String>, bool)> {
    let refused = |err: std::io::Error| {
        anyhow::anyhow!("offbox: an imported session's meta will not write: {err}")
    };
    let after = load_cursors(dir);
    let mut marked = Vec::new();
    let mut moved = false;
    for fed in &import.fed {
        let named = fed.prefixes.iter().all(|prefix| after.contains_key(prefix));
        let quiet = fed
            .prefixes
            .iter()
            .all(|prefix| before.contains_key(prefix) && before.get(prefix) == after.get(prefix));
        moved |= !quiet;
        if !fed.described && named {
            let held = dir.join(HISTORY).join(&fed.leaf);
            std::fs::create_dir_all(&held).map_err(refused)?;
            crate::durable::replace(held.join(HISTORY_META), &fed.meta).map_err(refused)?;
        }
        let Some(ended) = ended else {
            continue;
        };
        let read_out = fed.prefixes.iter().all(|prefix| ended.contains(prefix));
        if fed.described && quiet && read_out {
            mark(machine, &fed.leaf)?;
            marked.push(fed.leaf.clone());
        }
    }
    Ok((marked, moved))
}

/// What one push that imported came to.
struct Imported {
    /// The push itself.
    pushed: Result<Push>,
    /// How many sessions the sources listed, the live one apart.
    listed: u64,
    /// The leaves that were marked when the push began.
    stored: Vec<String>,
    /// The leaves this push finished and marked.
    marked: Vec<String>,
    /// Whether any imported feed moved, so that a later push has to confirm it.
    moved: bool,
}

/// One push of `session` with the machine's other sessions riding in it
/// (CLOUD-2735): [`plan_import`], the push, [`finish_import`]. An import costs
/// no push of its own and creates no ref.
///
/// # Errors
///
/// A marker or a `meta.json` that will not write. A failed push is not an
/// error here: it is `pushed`.
fn import_push(
    session: &Session<'_>,
    history: &[crate::sessions::Named],
    machine: &Path,
    byte_cap: u64,
) -> Result<Imported> {
    let dir = session_dir(session.project_root, &session.meta)?;
    let live = (session.meta.harness.as_str(), session.meta.session.as_str());
    let import = plan_import(history, live, &dir, machine)?;
    let before = load_cursors(&dir);
    let pushed = push_capped(session, &import.feeds, byte_cap);
    let ended = match &pushed {
        Ok(push) if matches!(push.outcome, Pushed::Applied | Pushed::Unchanged) => {
            Some(push.ended.as_slice())
        }
        _ => None,
    };
    let (marked, moved) = finish_import(&import, &dir, machine, &before, ended)?;
    Ok(Imported {
        pushed,
        listed: import.listed,
        stored: import.marked,
        marked,
        moved,
    })
}

// --- the restore (CLOUD-2723) --------------------------------------------------

/// A session's restore record, in its own directory: the commit id restored,
/// or [`NOTHING_RESTORED`].
pub const RESTORED: &str = crate::offbox_watch::RESTORED;

/// What the restore record holds when there was nothing to restore from.
pub const NOTHING_RESTORED: &str = "none";

/// The ref the rotation job keeps every rotated session reachable from.
pub const ARCHIVE: &str = "refs/heads/archive";

/// The key of a session ref in the archive: the first sixteen hex digits of
/// the BLAKE3 of its full name. Of the whole name, so it includes the project.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT key-ignores-the-project|s@^    blake3::hash(reference.as_bytes()).to_hex()\[..16\].to_owned()$@    blake3::hash(reference.rsplit('/').next().unwrap_or_default().as_bytes()).to_hex()[..16].to_owned()@|two_projects_with_one_session_name_have_two_keys
//MUTANT index-path-uses-one-level|s@^    format!("{root}/{}/{}/{key}", \&key\[..2\], \&key\[2..4\])$@    format!("{root}/{}/{key}", \&key[..2])@|the_index_path_is_two_levels_and_its_first_line_is_the_ref
#[must_use]
pub fn archive_key(reference: &str) -> String {
    blake3::hash(reference.as_bytes()).to_hex()[..16].to_owned()
}

/// Where the archive's tree keeps `root` — `index` or `observed` — for a
/// session ref: `<root>/<aa>/<bb>/<key>`. Fixed at two levels, never split or
/// moved, so a reader can compute it.
#[must_use]
pub fn archive_path(root: &str, reference: &str) -> String {
    let key = archive_key(reference);
    format!("{root}/{}/{}/{key}", &key[..2], &key[2..4])
}

/// What one restore came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restored {
    /// A snapshot was put back; its commit id.
    Snapshot(String),
    /// There was nothing to restore from.
    Nothing,
    /// The forge said to slow down; no answer was reached and none is recorded.
    Throttled(lease::Throttled),
    /// Discovery answered that this machine may not read the repository.
    Unattached,
    /// Another process holds the session's push lock; nothing was done and
    /// nothing is recorded (CLOUD-2738).
    Contended,
}

impl Restored {
    /// The one stdout token.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            Restored::Snapshot(_) => "restored",
            Restored::Nothing => NOTHING_RESTORED,
            Restored::Throttled(_) => "throttled",
            Restored::Unattached => Status::Unattached.token(),
            Restored::Contended => "contended",
        }
    }

    /// The exit that goes with it.
    #[must_use]
    pub const fn code(&self) -> ExitCode {
        match self {
            Restored::Snapshot(_) | Restored::Nothing => ExitCode::Success,
            Restored::Throttled(_) | Restored::Contended => ExitCode::Violation,
            Restored::Unattached => ExitCode::Usage,
        }
    }
}

/// Make the session's local repository, where a restore is the first thing to
/// need it.
fn prepare(repo: &Path) -> Result<()> {
    std::fs::create_dir_all(repo)
        .map_err(|err| anyhow::anyhow!("offbox: the session repository will not create: {err}"))?;
    gitwrite::init_bare(repo)
}

/// Where a snapshot to restore was found.
struct Found {
    commit: String,
    /// Read from the session's own live ref, so the next push may replace it.
    live: bool,
}

/// The newest snapshot of the session whose ref is `name`: its live ref, else
/// the last line of its archive index file.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT archived-session-not-found|s@^    let Some((_, blob)) = index.iter().find(\x7c(path, _)\x7c path == \&wanted) else {$@    let Some((_, blob)) = index.iter().find(\x7c(path, _)\x7c path == "nowhere") else {@|a_rotated_session_is_restored_from_the_archive_index
//MUTANT older-archived-snapshot-restored|s@^        .last()$@        .next()@|the_last_line_of_an_index_file_is_the_one_restored
fn newest(
    remote: &str,
    repo: &Path,
    refs: &lease::Advertisement,
    name: &str,
) -> Result<Option<Found>> {
    let live = refs.head_of(name);
    if live != lease::ZERO {
        return Ok(Some(Found {
            commit: live.to_owned(),
            live: true,
        }));
    }
    let archive = refs.head_of(ARCHIVE);
    if archive == lease::ZERO {
        return Ok(None);
    }
    prepare(repo)?;
    lease::fetch_shallow(remote, repo, archive)?;
    let index = gitwrite::tree_index(repo, archive)?;
    let wanted = archive_path("index", name);
    let Some((_, blob)) = index.iter().find(|(path, _)| path == &wanted) else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&gitwrite::read_blob(repo, blob)?).into_owned();
    // The first line is the ref's name; each later one is a snapshot's commit
    // id, oldest first.
    let commit = text
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .last()
        .map(str::to_owned);
    Ok(commit.map(|commit| Found {
        commit,
        live: false,
    }))
}

/// Put the session's pushed snapshot back where the snapshot read it, in a
/// container that does not have it (CLOUD-2723).
///
/// Looked for in order: the session's own live ref; the archive, where the
/// rotation job keeps a session it rotated away; then the same two for
/// `predecessor`, the session this one continues. [`absorb`] does all the
/// copying — `own` for the session's own snapshots, so its record stream is
/// continued, and not for a predecessor's, whose transcript is kept aside.
///
/// `refs/offbox/last` is set only for a snapshot read from the session's own
/// live ref: that is the one value the next push replaces. After an archive or
/// predecessor restore the live ref is absent, and a push is admitted over
/// nothing.
///
/// **The restore record is written whenever an answer was reached** — the
/// commit id, or `none` — and never otherwise: a throttle or an unreadable
/// repository is not "nothing to restore", and recording it as that would stop
/// the daemon ever trying again.
///
/// # Errors
///
/// A transport failure, or a local file that will not read or write.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT archive-restore-sets-last|s@^        if found.live \&\& own {$@        if true {@|a_rotated_session_is_restored_from_the_archive_index
//MUTANT predecessor-transcript-adopted-as-own|s@^        absorb(session.project_root, \&session.meta, \&found.commit, own)?;$@        absorb(session.project_root, \&session.meta, \&found.commit, true)?;@|a_predecessors_snapshot_is_absorbed_and_its_transcript_kept_aside
//MUTANT nothing-found-leaves-restored-unwritten|s@^    record_restored(\&dir, NOTHING_RESTORED)?;$@@|nothing_to_restore_from_is_recorded_as_none
//MUTANT snapshot-already-here-restored-again|s@^        if here {$@        if false {@|a_daemon_that_finds_the_restore_record_does_not_restore_again
//MUTANT restore-ignores-the-push-lock|s@^    if restoring.is_none() {$@    if false {@|a_restore_waits_for_the_push_lock
//MUTANT throttled-restore-recorded-as-none|s@^        Some(throttle) => Ok(Restored::Throttled(\*throttle)),$@        Some(_) => Ok(Restored::Nothing),@|a_throttled_restore_records_nothing
pub fn restore_once(session: &Session<'_>, predecessor: Option<&str>) -> Result<Restored> {
    match restore(session, predecessor) {
        Ok(restored) => Ok(restored),
        Err(err) => restore_throttled(err),
    }
}

/// `Ok(throttled)` where `err` is the forge saying slow down, `err` back
/// otherwise.
fn restore_throttled(err: anyhow::Error) -> Result<Restored> {
    match err.downcast_ref::<lease::Throttled>() {
        Some(throttle) => Ok(Restored::Throttled(*throttle)),
        None => Err(err),
    }
}

fn record_restored(dir: &Path, value: &str) -> Result<()> {
    let refused =
        |err: std::io::Error| anyhow::anyhow!("offbox: the restore record will not write: {err}");
    std::fs::create_dir_all(dir).map_err(refused)?;
    crate::durable::replace(dir.join(RESTORED), format!("{value}\n")).map_err(refused)
}

/// [`restore_once`]'s body; a throttle met anywhere in it is an error here
/// and an outcome there.
fn restore(session: &Session<'_>, predecessor: Option<&str>) -> Result<Restored> {
    match lease::probe(&session.remote, Service::UploadPack)? {
        200 => {}
        401 | 403 | 404 => return Ok(Restored::Unattached),
        other => {
            return Err(anyhow::anyhow!(
                "offbox: the state repository answered {other} to discovery"
            ));
        }
    }
    let dir = session_dir(session.project_root, &session.meta)?;
    let repo = local_repo(&dir);
    // THE PUSH LOCK, for the whole run (CLOUD-2738): a restore writes fetched
    // objects that nothing reaches yet, and a push's prune must not meet them.
    let restoring = take_push_lock(&dir)?;
    if restoring.is_none() {
        return Ok(Restored::Contended);
    }
    let refs = lease::advertise(&session.remote, Service::UploadPack)?;
    // A PUSH THE REMOTE APPLIED AND THIS MACHINE NEVER RECORDED is recorded
    // first, so the question below — is the remote's snapshot already here —
    // is asked of the truth.
    own_push_recorded(&dir, &repo, refs.head_of(&reference(&session.meta)))?;
    // WHAT IS ALREADY HERE IS DECIDED FROM WHAT IS HERE, on every start: the
    // commit the local repository last pushed or absorbed, and the one commit
    // this directory last restored from. A restore therefore runs at every
    // start and a second one changes nothing — where it once ran only while a
    // record of the first was absent, and, run again, kept the session's own
    // last push aside as another writer's.
    let last = if repo.exists() {
        crate::git::resolve_ref(&repo, LAST)?
    } else {
        None
    };
    let taken = std::fs::read_to_string(dir.join(RESTORED))
        .ok()
        .map(|record| record.trim().to_owned());

    // This session's own snapshots first; then the predecessor's, by the same
    // two steps, under its own ref name.
    let mut candidates = vec![(reference(&session.meta), true)];
    if let Some(predecessor) = predecessor.filter(|id| !id.is_empty()) {
        let mut meta = session.meta.clone();
        predecessor.clone_into(&mut meta.session);
        candidates.push((reference(&meta), false));
    }
    for (name, own) in candidates {
        let Some(found) = newest(&session.remote, &repo, &refs, &name)? else {
            continue;
        };
        let here = last.as_deref() == Some(found.commit.as_str())
            || taken.as_deref() == Some(found.commit.as_str());
        if here {
            record_restored(&dir, &found.commit)?;
            return Ok(Restored::Snapshot(found.commit));
        }
        prepare(&repo)?;
        lease::fetch_shallow(&session.remote, &repo, &found.commit)?;
        absorb(session.project_root, &session.meta, &found.commit, own)?;
        if found.live && own {
            gitwrite::set_ref(&repo, LAST, &found.commit)?;
        }
        record_restored(&dir, &found.commit)?;
        return Ok(Restored::Snapshot(found.commit));
    }
    record_restored(&dir, NOTHING_RESTORED)?;
    Ok(Restored::Nothing)
}

// --- the daemon (CLOUD-2721) ---------------------------------------------------

/// The lock one daemon per checkout holds for its life, under [`DIR`].
pub const LOCK: &str = crate::offbox_watch::LOCK;

// --- the rotation (CLOUD-2724) -------------------------------------------------

/// How many consecutive passes a session ref must go unchanged before a pass
/// rotates it, where `--quiet-runs` does not say.
pub const QUIET_RUNS: u64 = 6;

/// The prefix every session ref has. A ref of any shape under it is a session.
const SESSION_REFS: &str = "refs/heads/session/";

/// The archive tree's root of one file per rotated session: the ref's name,
/// then one snapshot commit id a line, oldest first.
const INDEX: &str = "index";

/// The archive tree's root of one file per live session ref: the tip last
/// seen, then how many consecutive passes it has not changed.
const OBSERVED: &str = "observed";

/// What one rotation pass came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotated {
    /// The pass was applied; how many sessions it rotated, which may be none.
    Done(usize),
    /// The forge said to slow down; nothing was changed.
    Throttled,
    /// The atomic push was refused because a ref moved; nothing was changed.
    Contended,
}

impl Rotated {
    /// The one stdout token.
    #[must_use]
    pub fn token(self) -> String {
        match self {
            Rotated::Done(count) => format!("rotated {count}"),
            Rotated::Throttled => String::from("throttled"),
            Rotated::Contended => String::from("contended"),
        }
    }

    /// The exit that goes with it. **A throttled pass is a success**: the next
    /// scheduled pass simply tries again, and the wait between passes is far
    /// longer than any backoff the forge asks for.
    #[must_use]
    pub const fn code(self) -> ExitCode {
        match self {
            Rotated::Done(_) | Rotated::Throttled => ExitCode::Success,
            Rotated::Contended => ExitCode::Violation,
        }
    }
}

/// How many consecutive passes `tip` has now gone unchanged, given the
/// `observed` file the last pass left for its ref: the tip it saw, then its
/// count. A changed tip starts again at 0.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT changed-ref-keeps-its-quiet-count|s@^    if seen != tip {$@    if false {@|a_ref_whose_tip_changed_starts_its_count_again
fn quiet_passes(observed: &str, tip: &str) -> u64 {
    let mut lines = observed.lines();
    let seen = lines.next().unwrap_or_default().trim();
    if seen != tip {
        return 0;
    }
    let count: u64 = lines
        .next()
        .and_then(|line| line.trim().parse().ok())
        .unwrap_or(0);
    count.saturating_add(1)
}

/// One rotation pass over the state repository at `remote` (CLOUD-2724):
/// finished sessions go into the archive and their branches are removed,
/// discarding nothing.
///
/// 1. **Read** the ref advertisement, and the archive's tip at depth 1 into the
///    bare repository at `scratch`. With no archive ref the previous tree is
///    empty.
/// 2. **Observe.** Every session ref's `observed` entry is brought up to date:
///    an unchanged tip adds one to its count, a changed tip sets it to 0, a new
///    ref starts at 0. No clock decides anything: "finished" is a count of
///    passes.
/// 3. **Select** each session ref whose count has reached `quiet_runs`.
/// 4. **Archive.** One new commit: its parents are the previous archive tip,
///    then the tip of every selected session — which is what keeps a rotated
///    snapshot reachable — and its tree is the previous tree by blob id, except
///    that each selected session's index file gains one line and its `observed`
///    entry is left out. No session commit is fetched and no session blob is
///    read.
/// 5. **One atomic push:** the archive ref from its old tip to the new commit,
///    and the removal of each selected ref, each conditioned on the exact tip
///    that was archived. If any condition fails nothing is applied, so a
///    session that pushed while the pass ran is never lost.
///
/// `time` is the commit time; this function reads no clock.
///
/// # Errors
///
/// A transport failure, a remote that does not offer an atomic push, or a
/// local file that will not read or write. A throttle met anywhere is
/// [`Rotated::Throttled`], and a refused push [`Rotated::Contended`].
pub fn rotate_once(remote: &str, scratch: &Path, quiet_runs: u64, time: i64) -> Result<Rotated> {
    match rotate(remote, scratch, quiet_runs, time) {
        Err(err) if err.downcast_ref::<lease::Throttled>().is_some() => Ok(Rotated::Throttled),
        other => other,
    }
}

/// [`rotate_once`]'s body; a throttle met on a read is an error here and an
/// outcome there.
//MUTANT-SUITE crates/batten/src/offbox.rs
//MUTANT oddly-named-ref-skipped|s@^        .filter(\x7c(name, _)\x7c name.starts_with(SESSION_REFS))$@        .filter(\x7c(name, _)\x7c name.starts_with(SESSION_REFS) \&\& name.contains('-'))@|a_ref_of_any_shape_under_the_session_prefix_is_rotated
//MUTANT second-rotation-overwrites-the-index-line|s@^            let mut lines = held.unwrap_or_else(\x7c\x7c format!("{name}\\n"));$@            let mut lines = held.map_or_else(\x7c\x7c format!("{name}\\n"), \x7c_\x7c format!("{name}\\n"));@|a_session_rotated_twice_has_two_index_lines_oldest_first
//MUTANT previous-archive-tip-not-a-parent|s@^    let mut parents: Vec<String> = previous_tip.into_iter().collect();$@    let mut parents: Vec<String> = Vec::new();@|a_quiet_session_is_archived_and_its_ref_removed
//MUTANT ref-removed-without-archiving|s@^    parents.extend(selected.iter().map(\x7c(_, tip)\x7c tip.clone()));$@@|a_quiet_session_is_archived_and_its_ref_removed
//MUTANT removal-not-conditioned-on-the-tip|s@^            old: tip.clone(),$@            old: lease::ZERO.to_owned(),@|a_quiet_session_is_archived_and_its_ref_removed
//MUTANT throttled-pass-removes-a-ref|s@^        lease::Outcome::Throttled { .. } => Ok(Rotated::Throttled),$@        lease::Outcome::Throttled { .. } => { lease::swap_many(remote, scratch, \&updates)?; Ok(Rotated::Throttled) }@|a_throttled_pass_changes_nothing_and_exits_clean
fn rotate(remote: &str, scratch: &Path, quiet_runs: u64, time: i64) -> Result<Rotated> {
    let refs = lease::advertise(remote, Service::ReceivePack)?;
    let archive = refs.head_of(ARCHIVE);
    let sessions: Vec<(&String, &String)> = refs
        .refs
        .iter()
        .filter(|(name, _)| name.starts_with(SESSION_REFS))
        .collect();
    if sessions.is_empty() {
        return Ok(Rotated::Done(0));
    }
    gitwrite::init_bare(scratch)?;
    let previous_tip = (archive != lease::ZERO).then(|| archive.to_owned());
    let previous: BTreeMap<String, String> = match &previous_tip {
        Some(tip) => {
            lease::fetch_shallow(remote, scratch, tip)?;
            gitwrite::tree_index(scratch, tip)?.into_iter().collect()
        }
        None => BTreeMap::new(),
    };
    let held = |path: &str| -> Result<Option<String>> {
        let Some(blob) = previous.get(path) else {
            return Ok(None);
        };
        let bytes = gitwrite::read_blob(scratch, blob)?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    };

    // EVERY ENTRY OF THE PREVIOUS TREE, BY BLOB ID: nothing the archive holds
    // is read again or rewritten, apart from the files this pass changes.
    let mut entries: BTreeMap<String, Content> = previous
        .iter()
        .map(|(path, blob)| (path.clone(), Content::Blob(blob.clone())))
        .collect();
    let mut selected: Vec<(String, String)> = Vec::new();
    for (name, tip) in sessions {
        let observed = archive_path(OBSERVED, name);
        let quiet = match held(&observed)? {
            Some(seen) => quiet_passes(&seen, tip),
            None => 0,
        };
        if quiet < quiet_runs {
            let body = format!("{tip}\n{quiet}\n").into_bytes();
            entries.insert(observed, Content::Bytes(body));
        } else {
            entries.remove(&observed);
            let index = archive_path(INDEX, name);
            let held = held(&index)?;
            let mut lines = held.unwrap_or_else(|| format!("{name}\n"));
            lines.push_str(tip);
            lines.push('\n');
            entries.insert(index, Content::Bytes(lines.into_bytes()));
            selected.push((name.clone(), tip.clone()));
        }
    }

    // THE PARENTS ARE WHAT KEEP A ROTATED SNAPSHOT: a ref is removed only in
    // the push that makes its commit one of these.
    let mut parents: Vec<String> = previous_tip.into_iter().collect();
    parents.extend(selected.iter().map(|(_, tip)| tip.clone()));
    // Two refs may name one commit; a commit names each parent once.
    let mut named = BTreeSet::new();
    parents.retain(|parent| named.insert(parent.clone()));
    let listed: Vec<(String, Content)> = entries.into_iter().collect();
    let (commit, _) = gitwrite::commit_tree(scratch, &listed, &parents, time, "rotate")?;

    let mut updates = vec![lease::Update {
        old: archive.to_owned(),
        new: commit.clone(),
        name: ARCHIVE.to_owned(),
    }];
    for (name, tip) in &selected {
        updates.push(lease::Update {
            old: tip.clone(),
            new: lease::ZERO.to_owned(),
            name: name.clone(),
        });
    }
    match lease::swap_many(remote, scratch, &updates)? {
        lease::Outcome::Applied => {
            // The scratch repository is a cache of the archive's tip alone.
            gitwrite::prune_unreachable(scratch, std::slice::from_ref(&commit))?;
            Ok(Rotated::Done(selected.len()))
        }
        lease::Outcome::Rejected { .. } => Ok(Rotated::Contended),
        lease::Outcome::Throttled { .. } => Ok(Rotated::Throttled),
    }
}

/// The workflow `--print-workflow` prints, with its three values still named.
const ROTATE_WORKFLOW: &str = r#"# Printed by `batten offbox rotate --print-workflow`. Install it on the default
# branch of the state repository: a scheduled workflow runs from there alone.
name: offbox-rotate
on:
  schedule:
    - cron: "17 * * * *"
permissions:
  contents: write
concurrency:
  group: offbox-rotate
  cancel-in-progress: false
jobs:
  rotate:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Install batten __VERSION__
        env:
          BATTEN_VERSION: v__VERSION__
          INSTALL_URL: "__INSTALL_URL__"
        run: curl -sSfL --retry 3 "$INSTALL_URL" | sh
      - name: Rotate finished sessions into the archive
        env:
          GH_TOKEN: ${{ github.token }}
        run: batten offbox rotate --remote "${{ github.server_url }}/${{ github.repository }}" --quiet-runs __QUIET_RUNS__
"#;

/// The workflow file that runs [`rotate_once`] on a schedule in the state
/// repository (CLOUD-2724). It is printed, never kept in this crate: the
/// repository it is installed in is the one it rotates.
///
/// * **Its only trigger is `schedule`.** On push it would start once for every
///   session push.
/// * **It grants `contents: write` and nothing else**, and hands the run's own
///   token to `batten` as the credential every forge call here reads.
/// * **It installs the version that printed it**, by the install script at
///   `install_url`. The URL is an argument because no repository address is
///   written in this crate.
/// * **`rotate` carries the file forward**: a pass keeps every entry of the
///   archive's tree by blob id, so a workflow installed on the archive branch
///   stays there.
//MUTANT-SUITE crates/batten/tests/it/offbox_rotate.rs
//MUTANT workflow-triggers-on-push|s@^  schedule:$@  push:@|the_printed_workflow_runs_on_a_schedule_alone_and_pins_this_version
//MUTANT workflow-installs-an-unpinned-batten|s@^          BATTEN_VERSION: v__VERSION__$@          BATTEN_UNPINNED: v__VERSION__@|the_printed_workflow_runs_on_a_schedule_alone_and_pins_this_version
#[must_use]
pub fn rotate_workflow(install_url: &str, version: &str) -> String {
    ROTATE_WORKFLOW
        .replace("__VERSION__", version)
        .replace("__INSTALL_URL__", install_url)
        .replace("__QUIET_RUNS__", &QUIET_RUNS.to_string())
}

// --- the daemon's files (CLOUD-2721), continued --------------------------------

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
    /// The import of this machine's other sessions (CLOUD-2735): `ok`,
    /// `lock-held` where another daemon is the machine's importer, or
    /// `not-surveyed` where this session's harness has no source to list them.
    pub history: String,
    /// How many sessions the sources listed, the live one apart.
    pub history_listed: u64,
    /// How many of them this daemon marked after importing them.
    pub history_imported: u64,
    /// How many are marked because they were found already stored.
    pub history_stored: u64,
    /// How many are not yet marked.
    pub history_remaining: u64,
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
        let _ = writeln!(text, "history {}", self.history);
        let _ = writeln!(text, "history_listed {}", self.history_listed);
        let _ = writeln!(text, "history_imported {}", self.history_imported);
        let _ = writeln!(text, "history_stored {}", self.history_stored);
        let _ = writeln!(text, "history_remaining {}", self.history_remaining);
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
            history: String::from("ok"),
            history_listed: 0,
            history_imported: 0,
            history_stored: 0,
            history_remaining: 0,
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
                "history" => value.clone_into(&mut read.history),
                "history_listed" => read.history_listed = value.parse().unwrap_or(0),
                "history_imported" => read.history_imported = value.parse().unwrap_or(0),
                "history_stored" => read.history_stored = value.parse().unwrap_or(0),
                "history_remaining" => read.history_remaining = value.parse().unwrap_or(0),
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
    /// The session this one continues, where the environment names one: what
    /// a restore falls back to when the session has no snapshot of its own.
    pub predecessor: Option<&'a str>,
    /// How many wakes to run before returning; `None` runs until killed.
    pub wakes: Option<u64>,
    /// The sources that list this machine's sessions, by harness name: what
    /// the daemon imports the other sessions from (CLOUD-2735).
    pub history: &'a [crate::sessions::Named],
    /// The most new record bytes one push may add: [`BYTE_CAP`].
    pub byte_cap: u64,
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
//MUTANT marker-kept-per-session|s@^        let machine = crate::state::state_root()?;$@        let machine = session_dir(session.project_root, \&session.meta)?;@|a_session_one_daemon_marked_is_not_imported_by_another_on_the_machine
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
    /// The machine's import lock, once this daemon has it.
    import_lock: Option<std::fs::File>,
    /// The leaves of the sessions this daemon marked after importing them.
    imported: BTreeSet<String>,
}

impl<'a> Daemon<'a> {
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

    /// Whether the restore has yet to reach an answer.
    fn unrestored(&self) -> bool {
        matches!(self.status.restored.as_str(), "pending" | "unavailable")
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
        let machine = crate::state::state_root()?;
        let history = self.importing(&machine)?;
        let done = import_push(&session, history, &machine, self.launching.byte_cap)?;
        self.imported.extend(done.marked.iter().cloned());
        self.count(&done);
        let moved = done.moved;
        let result = match done.pushed {
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
        // AN IMPORT THAT MOVED IS NOT FINISHED: the push after it is the one
        // that can find nothing new and mark, so it is not left to the timer.
        self.owed |= moved;
        Ok(())
    }

    /// The sources this push imports from, with the machine's import lock
    /// taken, or tried again (CLOUD-2735). Without the lock, none: the daemon
    /// that holds it is the machine's importer.
    fn importing(&mut self, machine: &Path) -> Result<&'a [crate::sessions::Named]> {
        let launching = self.launching;
        if launching.history.is_empty() {
            "not-surveyed".clone_into(&mut self.status.history);
            return Ok(&[]);
        }
        if self.import_lock.is_none() {
            self.import_lock = take_import_lock(machine)?;
        }
        if self.import_lock.is_none() {
            "lock-held".clone_into(&mut self.status.history);
            return Ok(&[]);
        }
        // A harness with no source is skipped, and this says so when it is the
        // session's own: its other sessions are not among the ones listed.
        let own = launching
            .history
            .iter()
            .any(|(harness, _)| harness == launching.harness);
        if own { "ok" } else { "not-surveyed" }.clone_into(&mut self.status.history);
        Ok(launching.history)
    }

    /// The status file's counts of sessions, after the push `done`.
    fn count(&mut self, done: &Imported) {
        let marked = done.stored.len() + done.marked.len();
        let by_this_daemon = done
            .stored
            .iter()
            .chain(&done.marked)
            .filter(|leaf| self.imported.contains(*leaf))
            .count();
        let as_count = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
        self.status.history_listed = done.listed;
        self.status.history_imported = as_count(by_this_daemon);
        self.status.history_stored = as_count(marked - by_this_daemon);
        self.status.history_remaining = done.listed.saturating_sub(as_count(marked));
    }

    /// Restore, once, before the first push (CLOUD-2723).
    ///
    /// An answer — a snapshot, or nothing to restore from — is recorded by
    /// [`restore_once`] and never asked for again. No answer is `unavailable`:
    /// the daemon waits as the backoff says and tries again, and by then the
    /// session has been stamped, so what it restores lands under `absorbed/`.
    fn restore(&mut self, world: &mut dyn World) -> Result<()> {
        let (Some(meta), Some(remote)) = (self.meta.clone(), self.remote.clone()) else {
            return Ok(());
        };
        let session = Session {
            project_root: self.launching.project_root,
            provisions: self.launching.provisions,
            meta,
            remote,
            transcript: self.launching.transcript.map(Path::to_path_buf),
            time: world.now(),
        };
        let result = match restore_once(&session, self.launching.predecessor) {
            Ok(Restored::Snapshot(_)) => {
                "yes".clone_into(&mut self.status.restored);
                Attempt::Done
            }
            Ok(Restored::Nothing) => {
                NOTHING_RESTORED.clone_into(&mut self.status.restored);
                Attempt::Done
            }
            Ok(Restored::Throttled(throttle)) => Attempt::Throttled(throttle),
            Ok(Restored::Unattached) => {
                self.unattached()?;
                Attempt::Failed
            }
            // A push by hand holds the lock: still pending, and asked again
            // on the next wake.
            Ok(Restored::Contended) => Attempt::Contended,
            Err(_) => Attempt::Failed,
        };
        match result {
            Attempt::Done => {}
            Attempt::Contended => "pending".clone_into(&mut self.status.restored),
            _ => "unavailable".clone_into(&mut self.status.restored),
        }
        let owed = self.owed;
        self.settle(result, world);
        self.owed = owed;
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
        } else if self.remote.is_some() && self.unrestored() {
            // BEFORE ANY PUSH: a push first would be rejected over a snapshot
            // this container has not seen, and absorb it as a rival's.
            if wait_left == 0 {
                self.restore(world)?;
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
//MUTANT start-skips-the-restore|s@^        String::from("pending")$@        String::from("yes")@|a_start_restores_whatever_the_last_run_recorded
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
    // EVERY START BEGINS WITH THE RESTORE, whatever the last run recorded and
    // however it ended. The start is the recovery: what is already here is
    // decided by `restore` from the local repository and the remote's refs,
    // so a start after a clean run, a kill or a reclaimed container takes the
    // one path, and a restore with nothing to do fetches nothing.
    status.restored = if meta.is_some() {
        String::from("pending")
    } else {
        String::from(NOTHING_RESTORED)
    };
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
        import_lock: None,
        imported: BTreeSet::new(),
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
        /// What its daemon imports from, and the cap its pushes run under.
        history: Vec<crate::sessions::Named>,
        byte_cap: u64,
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
                history: Vec::new(),
                byte_cap: BYTE_CAP,
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

    /// Fails by: `unchanged` answered from what this machine remembers pushing
    /// while the remote no longer has the ref.
    #[test]
    fn unchanged_is_never_said_of_a_remote_that_lost_the_ref() {
        let base = base("offbox-push-unchanged-gone");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        stand.borrow_mut().refs.clear();

        assert_eq!(one.push().outcome, Pushed::Applied);

        assert_eq!(Some(head(&stand, &one.meta)), one.last());
        assert_eq!(one.push().outcome, Pushed::Unchanged);
    }

    /// Fails by: `unchanged` answered while the remote's ref is another
    /// writer's, or that writer's snapshot replaced unread.
    #[test]
    fn unchanged_is_never_said_over_another_writers_ref() {
        let (stand, one, two, _) = two_writers("offbox-push-unchanged-theirs");
        let theirs = head(&stand, &two.meta);
        // THE PREMISE: `one` has nothing new, and the ref is not what it pushed.
        assert_ne!(one.last(), Some(theirs.clone()));

        assert_eq!(one.push().outcome, Pushed::Applied);

        let tree = one.tree(&head(&stand, &one.meta));
        assert!(
            tree.keys()
                .any(|path| path.starts_with(&format!("absorbed/{theirs}/"))),
            "the other writer's snapshot is kept: {:?}",
            tree.keys().collect::<Vec<_>>()
        );
        assert_eq!(Some(head(&stand, &one.meta)), one.last());
        assert_eq!(one.push().outcome, Pushed::Unchanged);
    }

    /// Fails by: a push the remote applied, whose reply never arrived, absorbed
    /// on the next run as another writer's — the session stored twice.
    #[test]
    fn a_push_the_remote_applied_and_this_machine_never_recorded_is_its_own() {
        let base = base("offbox-push-own-unrecorded");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, "{\"n\":1}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        let first = one.last();
        add(&one.transcript, "{\"n\":2}\n");
        stand.borrow_mut().lose_next_reply = true;
        let _ = push_once(&one.session(), &[]);
        // THE PREMISE: the remote moved and this machine did not record it.
        assert_eq!(one.last(), first);
        assert_ne!(Some(head(&stand, &one.meta)), first);
        add(&one.transcript, "{\"n\":3}\n");

        assert_eq!(one.push().outcome, Pushed::Applied);

        let tree = one.tree(&head(&stand, &one.meta));
        assert!(
            !tree.keys().any(|path| path.starts_with("absorbed/")),
            "its own push is not another writer's: {:?}",
            tree.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            tree["transcript/main/0/000000.jsonl"],
            std::fs::read(&one.transcript).unwrap()
        );
    }

    /// Fails by: ANY durable step of a start — the restore, then the push — at
    /// which a kill leaves the next start short of the one end state: the
    /// remote holding the source whole and once, every store as it is on the
    /// disk, nothing of the session's own kept aside as another writer's, and
    /// a push that has nothing left to say.
    ///
    /// The kill is moved one step later each round until a start finishes
    /// unkilled, so no step is left to the author's imagination. The transcript
    /// crosses a segment boundary between the two pushes, and a store changes.
    #[test]
    fn a_kill_before_any_durable_step_is_recovered_by_the_next_start() {
        let mut steps = None;
        for kill_at in 0..600_u64 {
            let base = base(&format!("offbox-kill-{kill_at}"));
            let stand = standing(&[], Vec::new());
            let one = Writer::new(&base, "one", "s");
            one.git_file("batten-receipts/r.json", "receipt\n");
            one.state_file("journal/merged.jsonl", "{}\n");
            put(&one.transcript, &records(0..700, 1000));
            assert_eq!(one.push().outcome, Pushed::Applied);
            add(&one.transcript, &records(700..1900, 1000));
            one.git_file("batten-receipts/r.json", "receipt, changed\n");

            // THE START THAT IS KILLED.
            crate::testing::kill_after(Some(kill_at));
            let _ = restore_once(&one.session(), None);
            let _ = push_once(&one.session(), &[]);
            let killed = crate::testing::killed();
            crate::testing::kill_after(None);

            // THE SESSION GOES ON WHILE ITS DAEMON IS DOWN, as a live one does:
            // a recovery that only holds for a session that stood still is one
            // that keeps the session's own push aside the moment it has not.
            add(&one.transcript, &records(1900..1910, 1000));
            one.git_file("batten-receipts/r.json", "receipt, changed again\n");

            // THE NEXT START, which is all the recovery there is.
            one.restore(None);
            let recovered = one.push().outcome;
            assert!(
                matches!(recovered, Pushed::Applied | Pushed::Unchanged),
                "kill at {kill_at}: the next start {recovered:?}"
            );
            assert_eq!(
                one.push().outcome,
                Pushed::Unchanged,
                "kill at {kill_at}: the two sides agree"
            );
            let tree = one.tree(&head(&stand, &one.meta));
            let stored: Vec<u8> = tree
                .iter()
                .filter(|(path, _)| path.starts_with("transcript/main/0/"))
                .flat_map(|(_, bytes)| bytes.clone())
                .collect();
            assert!(
                stored == std::fs::read(&one.transcript).unwrap(),
                "kill at {kill_at}: the remote's transcript is not the source"
            );
            assert_eq!(
                tree["git/batten-receipts/r.json"], b"receipt, changed again\n",
                "kill at {kill_at}"
            );
            assert_eq!(
                tree["state/journal/merged.jsonl"], b"{}\n",
                "kill at {kill_at}"
            );
            let aside: Vec<&String> = tree
                .keys()
                .filter(|path| path.starts_with("absorbed/"))
                .collect();
            assert!(aside.is_empty(), "kill at {kill_at}: kept aside: {aside:?}");
            if !killed {
                steps = Some(kill_at);
                break;
            }
        }
        let steps = steps.expect("a start finishes unkilled inside the bound");
        assert!(steps > 8, "the premise: a start takes many steps: {steps}");
    }

    /// Fails by: ANY durable step of a start in a container that does not have
    /// the session — the fetch, the files put in place one by one, the push
    /// over it — at which a kill costs a record or a store of either side.
    ///
    /// The new container has records of its own, as one that began work before
    /// its daemon did has. Whatever the kill left half-placed, the next start
    /// must leave the remote holding every record the first container pushed
    /// and every record this one wrote, and both of the stores, in place or
    /// kept aside.
    #[test]
    fn a_kill_at_any_step_of_a_restore_into_a_new_container_loses_nothing() {
        let mut steps = None;
        for kill_at in 0..600_u64 {
            let base = base(&format!("offbox-kill-restore-{kill_at}"));
            let stand = standing(&[], Vec::new());
            let _ = pushed_once(&base, &stand, "s");
            let fresh = Writer::new(&base, "fresh", "s");
            put(&fresh.transcript, "{\"n\":10}\n");

            crate::testing::kill_after(Some(kill_at));
            let _ = restore_once(&fresh.session(), None);
            let _ = push_once(&fresh.session(), &[]);
            let killed = crate::testing::killed();
            crate::testing::kill_after(None);

            add(&fresh.transcript, "{\"n\":11}\n");
            fresh.restore(None);
            let recovered = fresh.push().outcome;
            assert!(
                matches!(recovered, Pushed::Applied | Pushed::Unchanged),
                "kill at {kill_at}: the next start {recovered:?}"
            );
            assert_eq!(
                fresh.push().outcome,
                Pushed::Unchanged,
                "kill at {kill_at}: the two sides agree"
            );
            let tree = fresh.tree(&head(&stand, &fresh.meta));
            let records: String = tree
                .iter()
                .filter(|(path, _)| path.contains("transcript/"))
                .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
                .collect();
            for record in FIRST.lines().chain(["{\"n\":10}", "{\"n\":11}"]) {
                assert!(
                    records.contains(record),
                    "kill at {kill_at}: {record} is nowhere on the remote: {:?}",
                    tree.keys().collect::<Vec<_>>()
                );
            }
            for (ending, body) in [
                ("git/batten-receipts/r.json", &b"receipt\n"[..]),
                ("state/captures/a/one.txt", &b"captured\n"[..]),
            ] {
                assert!(
                    tree.iter()
                        .any(|(path, bytes)| path.ends_with(ending) && bytes == body),
                    "kill at {kill_at}: {ending} is nowhere on the remote whole"
                );
            }
            if !killed {
                steps = Some(kill_at);
                break;
            }
        }
        let steps = steps.expect("a start finishes unkilled inside the bound");
        assert!(steps > 8, "the premise: a start takes many steps: {steps}");
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
        let (own, held) = (one.last().unwrap(), one.repo());

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
        // Nothing was applied, so nothing was pruned (CLOUD-2738): the
        // snapshot this writer last pushed is still whole here.
        assert!(gitwrite::tree_index(&held, &own).is_ok());
        // What was absorbed on the way is kept for the next push: the
        // first store went where a store lives, the second differed from it.
        assert_eq!(
            one.read_git("batten-receipts/r.json").as_deref(),
            Some("other 0\n")
        );
        assert!(one.dir().join(ABSORBED).join(&others[1]).is_dir());
        // The last rival's too, so the push after it is admitted first time.
        assert!(one.dir().join(ABSORBED).join(&others[2]).is_dir());
        assert_eq!(one.push().outcome, Pushed::Applied);
        assert_eq!(receives(&stand), 1 + 3 + 1);
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
                    predecessor: None,
                    wakes: Some(wakes),
                    history: &self.history,
                    byte_cap: self.byte_cap,
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

    // --- the restore (CLOUD-2723) ---------------------------------------------

    impl Writer {
        fn state_file(&self, path: &str, body: &str) {
            put(
                &crate::state::repo_state_dir(&self.root).unwrap().join(path),
                body,
            );
        }

        fn restore(&self, predecessor: Option<&str>) -> Restored {
            restore_once(
                &Session {
                    project_root: &self.root,
                    provisions: &self.provisions,
                    meta: self.meta.clone(),
                    remote: REMOTE.to_owned(),
                    transcript: Some(self.transcript.clone()),
                    time: TIME,
                },
                predecessor,
            )
            .expect("the restore runs")
        }

        fn restored(&self) -> Option<String> {
            std::fs::read_to_string(self.dir().join(RESTORED)).ok()
        }
    }

    const FIRST: &str = "{\"n\":1}\n{\"n\":2}\n";

    /// A writer that has pushed two stores and a transcript, and its commit.
    fn pushed_once(base: &Path, stand: &Shared, session: &str) -> (Writer, String) {
        let one = Writer::new(base, &format!("first-{session}"), session);
        one.git_file("batten-receipts/r.json", "receipt\n");
        one.state_file("captures/a/one.txt", "captured\n");
        put(&one.transcript, FIRST);
        assert_eq!(one.push().outcome, Pushed::Applied);
        let commit = head(stand, &one.meta);
        (one, commit)
    }

    /// Rotate `meta`'s session away, as the cleanup job does: its ref gone,
    /// and an archive whose index file lists `commits`, oldest first.
    fn rotate_away(base: &Path, stand: &Shared, meta: &Meta, commits: &[&str]) {
        let name = reference(meta);
        let scratch = base.join(format!("archive-{}.git", commits.len()));
        gitwrite::init_bare(&scratch).unwrap();
        let mut index = format!("{name}\n");
        for commit in commits {
            index.push_str(commit);
            index.push('\n');
        }
        let entries = vec![(
            archive_path("index", &name),
            Content::Bytes(index.into_bytes()),
        )];
        let (tip, _) = gitwrite::commit_tree(&scratch, &entries, &[], TIME, "archive").unwrap();
        let mut stand = stand.borrow_mut();
        stand.objects.extend(objects_of(&scratch, &tip));
        stand.refs.retain(|(held, _)| held != &name);
        stand.refs.push((ARCHIVE.to_owned(), tip));
    }

    fn assert_stores_back(fresh: &Writer) {
        assert_eq!(
            fresh.read_git("batten-receipts/r.json").as_deref(),
            Some("receipt\n")
        );
        let captured = crate::state::repo_state_dir(&fresh.root)
            .unwrap()
            .join("captures/a/one.txt");
        assert_eq!(std::fs::read_to_string(captured).unwrap(), "captured\n");
    }

    /// Fails by: a store not put back, the record stream not continued, or the
    /// push after a restore being rejected.
    #[test]
    fn an_own_live_ref_is_restored_in_place_and_the_next_push_applies() {
        let base = base("offbox-restore-own");
        let stand = standing(&[], Vec::new());
        let (one, commit) = pushed_once(&base, &stand, "s");
        let theirs = one.tree(&commit);
        let fresh = Writer::new(&base, "fresh", "s");

        assert_eq!(fresh.restore(None), Restored::Snapshot(commit.clone()));

        assert_stores_back(&fresh);
        assert_eq!(
            fresh.local("transcript")["main/0/000000.jsonl"],
            FIRST.as_bytes()
        );
        let given: Cursors = serde_json::from_slice(&theirs["cursor.json"]).unwrap();
        assert_eq!(
            load_cursors(&fresh.dir())["transcript/main"],
            given["transcript/main"]
        );
        assert_eq!(
            fresh.restored().as_deref(),
            Some(format!("{commit}\n").as_str())
        );
        assert_eq!(fresh.last().as_deref(), Some(commit.as_str()));

        // The same stream, one line on, in this container's own file.
        put(&fresh.transcript, &format!("{FIRST}{{\"n\":3}}\n"));
        let before = receives(&stand);
        assert_eq!(fresh.push().outcome, Pushed::Applied);
        assert_eq!(receives(&stand), before + 1, "applied on its first attempt");
        let tree = fresh.tree(&head(&stand, &fresh.meta));
        assert_eq!(
            tree["transcript/main/0/000000.jsonl"],
            format!("{FIRST}{{\"n\":3}}\n").as_bytes()
        );
    }

    /// Fails by: a session the cleanup job rotated away not being found, or an
    /// archived snapshot being taken for the live ref's value.
    #[test]
    fn a_rotated_session_is_restored_from_the_archive_index() {
        let base = base("offbox-restore-archive");
        let stand = standing(&[], Vec::new());
        let (one, commit) = pushed_once(&base, &stand, "s");
        rotate_away(&base, &stand, &one.meta, &[&commit]);
        let fresh = Writer::new(&base, "fresh", "s");

        assert_eq!(fresh.restore(None), Restored::Snapshot(commit.clone()));

        assert_stores_back(&fresh);
        assert_eq!(
            fresh.restored().as_deref(),
            Some(format!("{commit}\n").as_str())
        );
        assert_eq!(
            fresh.last(),
            None,
            "the live ref is absent, so nothing is `last`"
        );

        let before = receives(&stand);
        assert_eq!(fresh.push().outcome, Pushed::Applied);
        assert_eq!(receives(&stand), before + 1);
        assert_ne!(
            head(&stand, &fresh.meta),
            lease::ZERO,
            "the live ref is back"
        );
    }

    /// Fails by: an older snapshot of a session rotated twice being restored.
    #[test]
    fn the_last_line_of_an_index_file_is_the_one_restored() {
        let base = base("offbox-restore-index");
        let stand = standing(&[], Vec::new());
        let (one, older) = pushed_once(&base, &stand, "s");
        add(&one.transcript, "{\"n\":3}\n");
        assert_eq!(one.push().outcome, Pushed::Applied);
        let newer = head(&stand, &one.meta);
        rotate_away(&base, &stand, &one.meta, &[&older, &newer]);
        let fresh = Writer::new(&base, "fresh", "s");

        assert_eq!(fresh.restore(None), Restored::Snapshot(newer));
        assert_eq!(
            fresh.local("transcript")["main/0/000000.jsonl"],
            format!("{FIRST}{{\"n\":3}}\n").as_bytes()
        );
    }

    /// Fails by: a predecessor's records being continued as this session's own.
    #[test]
    fn a_predecessors_snapshot_is_absorbed_and_its_transcript_kept_aside() {
        let base = base("offbox-restore-predecessor");
        let stand = standing(&[], Vec::new());
        let (_, commit) = pushed_once(&base, &stand, "before");
        let fresh = Writer::new(&base, "fresh", "after");

        assert_eq!(
            fresh.restore(Some("before")),
            Restored::Snapshot(commit.clone())
        );

        assert_stores_back(&fresh);
        assert!(
            fresh.local("transcript").is_empty(),
            "not this session's stream"
        );
        assert_eq!(
            fresh.local(&format!("absorbed/{commit}"))["transcript/main/0/000000.jsonl"],
            FIRST.as_bytes()
        );
        assert_eq!(fresh.last(), None);
        assert_eq!(
            fresh.restored().as_deref(),
            Some(format!("{commit}\n").as_str())
        );
    }

    /// Fails by: an answer of "nothing" going unrecorded, so it is asked again
    /// on every start.
    #[test]
    fn nothing_to_restore_from_is_recorded_as_none() {
        let base = base("offbox-restore-nothing");
        let _stand = standing(&[], Vec::new());
        let fresh = Writer::new(&base, "fresh", "s");

        let restored = fresh.restore(Some("nobody"));

        assert_eq!(restored, Restored::Nothing);
        assert_eq!(restored.token(), "none");
        assert_eq!(restored.code(), ExitCode::Success);
        assert_eq!(fresh.restored().as_deref(), Some("none\n"));
        let left: Vec<String> = files_under(&fresh.dir())
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        assert_eq!(left, [PUSH_LOCK, RESTORED], "nothing else was written");
    }

    /// Fails by: a throttle being recorded as nothing to restore.
    #[test]
    fn a_throttled_restore_records_nothing() {
        let base = base("offbox-restore-throttled");
        let stand = standing(&[], Vec::new());
        let (_, _) = pushed_once(&base, &stand, "s");
        let fresh = Writer::new(&base, "fresh", "s");
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Discovery,
            left: 1,
            status: 429,
            headers: vec![(String::from("retry-after"), String::from("30"))],
        });

        let restored = fresh.restore(None);

        assert!(matches!(restored, Restored::Throttled(_)), "{restored:?}");
        assert_eq!(restored.code(), ExitCode::Violation);
        assert_eq!(fresh.restored(), None);

        // The upload itself throttled, after discovery answered: the same.
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Upload,
            left: 1,
            status: 429,
            headers: Vec::new(),
        });
        assert!(matches!(fresh.restore(None), Restored::Throttled(_)));
        assert_eq!(fresh.restored(), None);
    }

    /// Fails by: every relaunch absorbing the session's own last push again.
    #[test]
    fn a_daemon_that_finds_the_restore_record_does_not_restore_again() {
        let base = base("offbox-restore-relaunch");
        let stand = standing(&[], Vec::new());
        let (_, commit) = pushed_once(&base, &stand, "s");
        let fresh = Writer::new(&base, "fresh", "s");
        put(&fresh.transcript, FIRST);
        assert_eq!(fresh.restore(None), Restored::Snapshot(commit));
        let uploads = stand.borrow().uploads;

        fresh.daemon(1000, 4, |_| {});

        assert_eq!(stand.borrow().uploads, uploads, "no fetch");
        assert_eq!(fresh.status().restored, "yes");
        assert!(fresh.local("absorbed").is_empty());

        // And a daemon with no record restores once, then says so.
        let other = Writer::new(&base, "other", "s");
        other.daemon(1000, 4, |_| {});
        assert_eq!(other.status().restored, "yes");
        assert!(other.restored().is_some());
    }

    /// Fails by: a start trusting the record an earlier run left — `none`,
    /// written while the remote was empty — over what the remote holds now.
    #[test]
    fn a_start_restores_whatever_the_last_run_recorded() {
        let base = base("offbox-restore-every-start");
        let stand = standing(&[], Vec::new());
        let fresh = Writer::new(&base, "fresh", "s");
        assert_eq!(fresh.restore(None), Restored::Nothing);
        assert_eq!(fresh.restored().as_deref().map(str::trim), Some("none"));
        let (_, commit) = pushed_once(&base, &stand, "s");

        fresh.daemon(1000, 4, |_| {});

        assert_eq!(
            fresh.restored().as_deref().map(str::trim),
            Some(commit.as_str())
        );
        assert_eq!(fresh.status().restored, "yes");
    }

    /// Fails by: the sweep's rebuilt directories shipped with its journal.
    #[test]
    fn the_mutation_stores_are_carried_and_their_work_directories_are_not() {
        let base = base("offbox-restore-mutate");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        one.state_file("mutate/schema/journal.jsonl", "{}\n");
        one.state_file("mutate/schema/reach.seal", "seal\n");
        one.state_file("mutate/schema/tree/src/lib.rs", "staged\n");
        one.state_file("mutate/schema/pristine/src/lib.rs", "source\n");
        one.state_file("mutate/schema/target/debug/x", "built\n");
        one.state_file("mutate/other/y", "not listed\n");
        assert_eq!(one.push().outcome, Pushed::Applied);

        let tree = one.tree(&head(&stand, &one.meta));
        let carried: Vec<&String> = tree
            .keys()
            .filter(|path| path.starts_with("state/mutate/"))
            .collect();
        assert_eq!(
            carried,
            [
                "state/mutate/schema/journal.jsonl",
                "state/mutate/schema/reach.seal"
            ]
        );

        // And a container without them gets them back in place.
        let fresh = Writer::new(&base, "fresh", "s");
        assert!(matches!(fresh.restore(None), Restored::Snapshot(_)));
        let back = crate::state::repo_state_dir(&fresh.root)
            .unwrap()
            .join("mutate/schema/journal.jsonl");
        assert_eq!(std::fs::read_to_string(back).unwrap(), "{}\n");
    }

    // --- the prune (CLOUD-2738) -----------------------------------------------

    /// The loose objects a repository holds, by id.
    fn loose(repo: &Path) -> BTreeSet<String> {
        files_under(&repo.join("objects"))
            .into_iter()
            .filter(|(path, _)| path.len() == 41 && path.as_bytes()[2] == b'/')
            .map(|(path, _)| path.replace('/', ""))
            .collect()
    }

    fn hold_push_lock(dir: &Path) -> std::fs::File {
        std::fs::create_dir_all(dir).unwrap();
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(PUSH_LOCK))
            .unwrap();
        fs4::FileExt::try_lock(&lock).unwrap();
        lock
    }

    /// Fails by: superseded objects left behind after an applied push, or a
    /// carried-forward segment's blob pruned from under the next one.
    #[test]
    fn the_local_repository_holds_only_the_last_pushed_snapshot() {
        const OPEN: &str = "transcript/main/0/000001.jsonl";
        let base = base("offbox-prune-bounded");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        // More than one segment, so the first is closed and carried by id.
        put(&one.transcript, &records(0..1200, 1000));
        let mut commits = Vec::new();
        let mut open = Vec::new();
        for round in 0..3 {
            add(&one.transcript, &records(5000 + round..5001 + round, 4));
            assert_eq!(one.push().outcome, Pushed::Applied, "round {round}");
            let last = one.last().unwrap();
            let index = gitwrite::tree_index(&one.repo(), &last).unwrap();
            let (_, blob) = index.into_iter().find(|(path, _)| path == OPEN).unwrap();
            open.push(blob);
            commits.push(last);
        }

        let repo = one.repo();
        for superseded in &open[..2] {
            assert!(gitwrite::read_blob(&repo, superseded).is_err());
        }
        for superseded in &commits[..2] {
            assert!(gitwrite::tree_id(&repo, superseded).is_err());
        }
        assert!(gitwrite::read_blob(&repo, &open[2]).is_ok());
        // Exactly what `last` reaches: a prune of the same commit finds nothing.
        let held = loose(&repo);
        assert_eq!(
            gitwrite::prune_unreachable(&repo, &commits[2..]).unwrap(),
            0
        );
        assert_eq!(loose(&repo), held);

        // And the next push still builds on it, its closed segment sent by id.
        add(&one.transcript, &records(6000..6001, 4));
        assert_eq!(one.push().outcome, Pushed::Applied);
        let tree = one.remote(&stand);
        let sent: String = ["transcript/main/0/000000.jsonl", OPEN]
            .iter()
            .map(|path| String::from_utf8_lossy(&tree[*path]).into_owned())
            .collect();
        assert_eq!(sent, text(&one.transcript));
    }

    /// Fails by: a prune after a push the forge did not take, which removes
    /// what `last` — still the older snapshot — is read from.
    #[test]
    fn nothing_is_pruned_after_a_throttled_or_a_rejected_push() {
        let base = base("offbox-prune-failed");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, &records(0..2, 4));
        assert_eq!(one.push().outcome, Pushed::Applied);
        let (last, held) = (one.last().unwrap(), loose(&one.repo()));
        add(&one.transcript, &records(2..3, 4));
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Receive,
            left: 1,
            status: 429,
            headers: Vec::new(),
        });

        assert!(matches!(one.push().outcome, Pushed::Throttled(_)));

        assert!(loose(&one.repo()).is_superset(&held));
        assert_eq!(one.tree(&last).len(), 3, "meta, cursors, one segment");
        // The rejected half is `three_rejected_swaps_are_contended_after_three_posts`.
    }

    /// Fails by: another writer's fetched snapshot kept in the local
    /// repository after its files were copied out and a push was applied.
    #[test]
    fn an_absorbed_snapshot_is_released_once_a_push_is_applied() {
        let (_stand, _one, two, first) = two_writers("offbox-prune-absorbed");

        assert!(gitwrite::tree_id(&two.repo(), &first).is_err());
        assert!(two.dir().join(ABSORBED).join(&first).is_dir());
        let last = two.last().unwrap();
        assert_eq!(
            gitwrite::prune_unreachable(&two.repo(), &[last]).unwrap(),
            0
        );
    }

    /// Fails by: two processes building in one repository at once, so one's
    /// prune meets the other's half-built commit.
    #[test]
    fn a_push_waits_for_the_push_lock_and_writes_nothing() {
        let base = base("offbox-prune-push-lock");
        let stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");
        put(&one.transcript, &records(0..2, 4));
        assert_eq!(one.push().outcome, Pushed::Applied);
        let held = loose(&one.repo());
        add(&one.transcript, &records(2..3, 4));
        let lock = hold_push_lock(&one.dir());

        let outcome = one.push().outcome;

        assert_eq!(outcome, Pushed::Contended);
        assert_eq!(loose(&one.repo()), held);
        assert_eq!(receives(&stand), 1);
        drop(lock);
        assert_eq!(one.push().outcome, Pushed::Applied);
    }

    /// Fails by: a restore writing fetched objects into a repository a push is
    /// building in.
    #[test]
    fn a_restore_waits_for_the_push_lock() {
        let base = base("offbox-prune-restore-lock");
        let stand = standing(&[], Vec::new());
        let (_writer, _) = pushed_once(&base, &stand, "s");
        let fresh = Writer::new(&base, "fresh", "s");
        let lock = hold_push_lock(&fresh.dir());
        let uploads = stand.borrow().uploads;

        let waited = fresh.restore(None);

        assert_eq!(waited, Restored::Contended);
        assert_eq!(waited.token(), "contended");
        assert_eq!(waited.code(), ExitCode::Violation);
        assert_eq!(stand.borrow().uploads, uploads, "no upload-pack POST");
        assert_eq!(fresh.restored(), None);
        drop(lock);
        assert!(matches!(fresh.restore(None), Restored::Snapshot(_)));
    }

    // --- the import (CLOUD-2735) ----------------------------------------------

    /// A source over the files a test names.
    struct Fixture(Vec<SessionRef>);

    impl SessionSource for Fixture {
        fn list(&self) -> Result<Vec<SessionRef>> {
            Ok(self.0.clone())
        }

        fn read(
            &self,
            session: &SessionRef,
            from: &Cursor,
            max_bytes: u64,
        ) -> Result<crate::sessions::Batch> {
            Ok(crate::sessions::read_jsonl(
                Path::new(&session.locator),
                from,
                max_bytes,
            ))
        }
    }

    /// One listed file: its session's id, its sub-key, the project directory
    /// recorded for it, and where it is.
    type Listing<'a> = (&'a str, &'a str, Option<&'a Path>, &'a Path);

    /// The sources a daemon is given: one, under the writers' own harness name.
    fn listing(files: &[Listing<'_>]) -> Vec<crate::sessions::Named> {
        let sessions = files
            .iter()
            .map(|(id, sub, project, path)| SessionRef {
                id: (*id).to_owned(),
                project: project.map(Path::to_path_buf),
                locator: path.to_string_lossy().into_owned(),
                sub: (*sub).to_owned(),
            })
            .collect();
        vec![(String::from("exit-code"), Box::new(Fixture(sessions)))]
    }

    /// Records numbered over `range`, each padded by `pad` bytes.
    fn records(range: std::ops::Range<usize>, pad: usize) -> String {
        use std::fmt::Write as _;
        let padding = "x".repeat(pad);
        range.fold(String::new(), |mut out, n| {
            let _ = writeln!(out, "{{\"n\":{n},\"pad\":\"{padding}\"}}");
            out
        })
    }

    fn text(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn machine() -> PathBuf {
        crate::state::state_root().unwrap()
    }

    fn history_leaf(id: &str) -> String {
        leaf("exit-code", id)
    }

    fn marked(id: &str) -> bool {
        machine().join(IMPORTED).join(history_leaf(id)).exists()
    }

    /// The records a tree holds for one file of an imported session, in order.
    fn imported(tree: &BTreeMap<String, Vec<u8>>, id: &str, key: &str) -> String {
        let under = format!("history/{}/transcript/{key}/", history_leaf(id));
        tree.iter()
            .filter(|(path, _)| path.starts_with(&under))
            .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
            .collect()
    }

    fn history_meta(tree: &BTreeMap<String, Vec<u8>>, id: &str) -> serde_json::Value {
        let path = format!("history/{}/meta.json", history_leaf(id));
        serde_json::from_slice(&tree[&path]).unwrap()
    }

    impl Writer {
        fn session(&self) -> Session<'_> {
            Session {
                project_root: &self.root,
                provisions: &self.provisions,
                meta: self.meta.clone(),
                remote: REMOTE.to_owned(),
                transcript: Some(self.transcript.clone()),
                time: TIME,
            }
        }

        /// One push with this writer's history riding in it.
        fn import(&self) -> Imported {
            import_push(&self.session(), &self.history, &machine(), self.byte_cap)
                .expect("the import runs")
        }

        fn plan(&self) -> Import<'_> {
            plan_import(
                &self.history,
                (&self.meta.harness, &self.meta.session),
                &self.dir(),
                &machine(),
            )
            .expect("the plan is made")
        }

        /// The remote's snapshot of this writer's session.
        fn remote(&self, stand: &Shared) -> BTreeMap<String, Vec<u8>> {
            self.tree(&head(stand, &self.meta))
        }

        /// Whether this writer's cursor file names any imported feed.
        fn imports(&self) -> bool {
            load_cursors(&self.dir())
                .keys()
                .any(|prefix| prefix.starts_with("history/"))
        }
    }

    fn outcome(done: &Imported) -> &Pushed {
        &done.pushed.as_ref().expect("the push ran").outcome
    }

    /// A second writer whose daemon has pushed all of its session `t`.
    fn pushed_whole_elsewhere(base: &Path) -> Writer {
        let two = Writer::new(base, "two", "t");
        put(&two.transcript, &records(0..3, 4));
        assert_eq!(two.push().outcome, Pushed::Applied);
        two
    }

    /// Fails by: the live session imported as history, a listed session left
    /// out, or a session marked before a push found nothing new in it.
    #[test]
    fn the_live_session_is_not_imported_and_the_others_are() {
        let base = base("offbox-import-all");
        let stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        put(&one.transcript, &records(0..2, 4));
        let (a, b, c) = (
            base.join("a.jsonl"),
            base.join("b.jsonl"),
            base.join("c.jsonl"),
        );
        let sub = base.join("c-agent.jsonl");
        put(&a, &records(10..13, 4));
        put(&b, &records(20..22, 4));
        put(&c, &records(30..31, 4));
        put(&sub, &records(40..42, 4));
        one.history = listing(&[
            ("s", "", None, &one.transcript),
            ("a", "", None, &a),
            ("b", "", None, &b),
            ("c", "", None, &c),
            ("c", "agent 1", None, &sub),
        ]);

        let first = one.import();
        assert_eq!(outcome(&first), &Pushed::Applied);
        assert_eq!(first.listed, 3);
        assert!(first.marked.is_empty() && first.moved);
        assert!(!marked("a") && !marked("b") && !marked("c"));

        let second = one.import();
        assert_eq!(outcome(&second), &Pushed::Applied, "it carries the metas");
        assert_eq!(second.marked.len(), 3);
        assert!(!second.moved);

        let tree = one.remote(&stand);
        for (id, file) in [("a", &a), ("b", &b), ("c", &c)] {
            assert_eq!(imported(&tree, id, "main"), text(file), "{id}");
            assert_eq!(history_meta(&tree, id)["session"], id);
            assert!(marked(id), "{id}");
        }
        assert_eq!(imported(&tree, "c", "agent_1"), text(&sub));
        let leaves: BTreeSet<&str> = tree
            .keys()
            .filter_map(|path| path.strip_prefix("history/")?.split('/').next())
            .collect();
        assert_eq!(leaves.len(), 3, "{leaves:?}");
        assert!(!leaves.contains(history_leaf("s").as_str()));
        assert!(!marked("s"));

        // With every session marked the next push has nothing to carry.
        let third = one.import();
        assert_eq!(outcome(&third), &Pushed::Unchanged);
        assert_eq!(third.stored.len(), 3);
    }

    /// Fails by: history read before the session's own records, so the cap is
    /// spent on it first.
    #[test]
    fn the_feed_list_has_the_live_feeds_before_any_history() {
        let base = base("offbox-import-order");
        let mut one = Writer::new(&base, "one", "s");
        put(&one.transcript, &records(0..1, 4));
        let a = base.join("a.jsonl");
        put(&a, &records(10..11, 4));
        one.history = listing(&[("a", "", None, &a)]);

        let plan = one.plan();
        let source = crate::sessions::source_named("exit-code", Some(&one.transcript));
        let feeds = feeds_of(&one.session(), source.as_deref(), &plan.feeds).unwrap();

        let prefixes: Vec<&str> = feeds.iter().map(|feed| feed.prefix.as_str()).collect();
        let history = format!("history/{}/transcript/main", history_leaf("a"));
        assert_eq!(prefixes, ["transcript/main", history.as_str()]);
    }

    /// Fails by: a session skipped because its project is gone, or an origin
    /// invented for it.
    #[test]
    fn a_session_whose_project_is_gone_is_imported_with_no_origin() {
        let base = base("offbox-import-origin");
        let stand = standing(&[], Vec::new());
        let two = Writer::new(&base, "two", "t");
        add(
            &two.root.join(".git").join("config"),
            "[remote \"origin\"]\n\turl = https://forge.invalid/acme/gadgets.git\n",
        );
        let mut one = Writer::new(&base, "one", "s");
        let (a, b) = (base.join("a.jsonl"), base.join("b.jsonl"));
        put(&a, &records(10..12, 4));
        put(&b, &records(20..22, 4));
        let gone = Path::new("/nonexistent/offbox-import/gone");
        one.history = listing(&[("a", "", Some(gone), &a), ("b", "", Some(&two.root), &b)]);

        one.import();
        one.import();

        let tree = one.remote(&stand);
        assert_eq!(imported(&tree, "a", "main"), text(&a));
        let meta = history_meta(&tree, "a");
        assert_eq!(meta["project"], gone.to_string_lossy().as_ref());
        assert!(meta["origin"].is_null(), "{meta}");
        assert_eq!(history_meta(&tree, "b")["origin"], "acme/gadgets");
        assert!(marked("a") && marked("b"));
    }

    /// Fails by: a session its own daemon pushed whole uploaded again, or the
    /// checks that decide it asking the remote anything.
    #[test]
    fn a_session_its_own_daemon_pushed_whole_is_marked_and_not_imported() {
        let base = base("offbox-import-pushed");
        let stand = standing(&[], Vec::new());
        let two = pushed_whole_elsewhere(&base);
        let mut one = Writer::new(&base, "one", "s");
        let a = base.join("a.jsonl");
        put(&a, &records(10..12, 4));
        one.history = listing(&[
            ("t", "", Some(&two.root), &two.transcript),
            ("a", "", None, &a),
        ]);
        let asked = stand.borrow().asked.len();

        let plan = one.plan();

        assert_eq!(stand.borrow().asked.len(), asked, "no request was made");
        assert_eq!(plan.marked, [history_leaf("t")]);
        assert_eq!(plan.feeds.len(), 1, "only the session nobody pushed");
        assert!(marked("t"));
        drop(plan);
        one.import();
        let held = one.local("history");
        assert!(!held.keys().any(|path| path.starts_with(&history_leaf("t"))));
    }

    /// Fails by: a session whose daemon died before its last push read as
    /// stored, losing the records its own ref never received.
    #[test]
    fn a_partly_pushed_session_with_no_daemon_is_imported_whole() {
        let base = base("offbox-import-partly");
        let stand = standing(&[], Vec::new());
        let two = pushed_whole_elsewhere(&base);
        add(&two.transcript, &records(3..4, 4));
        let mut one = Writer::new(&base, "one", "s");
        one.history = listing(&[("t", "", Some(&two.root), &two.transcript)]);

        let first = one.import();
        assert!(first.stored.is_empty() && !marked("t"));
        one.import();

        assert_eq!(
            imported(&one.remote(&stand), "t", "main"),
            text(&two.transcript),
            "from its first record"
        );
        assert!(marked("t"));
    }

    /// Fails by: a session its own daemon is still pushing imported, or marked
    /// because its push record happens to be at the end.
    #[test]
    fn a_session_live_elsewhere_is_neither_imported_nor_marked() {
        let base = base("offbox-import-live");
        let _stand = standing(&[], Vec::new());
        let two = pushed_whole_elsewhere(&base);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(daemon_dir(&two.root).unwrap().join(LOCK))
            .unwrap();
        fs4::FileExt::try_lock(&lock).unwrap();
        let mut serving = StatusFile::parse("");
        serving.session = history_leaf("t");
        put(&two.status_path(), &serving.render());
        let mut one = Writer::new(&base, "one", "s");
        one.history = listing(&[("t", "", Some(&two.root), &two.transcript)]);

        let live = one.import();

        assert_eq!(live.listed, 1);
        assert!(live.stored.is_empty() && live.marked.is_empty());
        assert!(!marked("t") && !one.imports());
        assert!(one.local("history").is_empty());

        // Its daemon gone and its push record at the end: stored, not imported.
        drop(lock);
        let after = one.import();
        assert_eq!(after.stored, [history_leaf("t")]);
        assert!(marked("t") && !one.imports());
    }

    /// Fails by: a subagent file its session's daemon never pushed counted as
    /// pushed because the main file was.
    #[test]
    fn a_file_the_push_never_saw_is_imported_and_not_marked() {
        let base = base("offbox-import-unseen");
        let stand = standing(&[], Vec::new());
        let two = pushed_whole_elsewhere(&base);
        let sub = base.join("t-agent.jsonl");
        put(&sub, &records(50..52, 4));
        let mut one = Writer::new(&base, "one", "s");
        one.history = listing(&[
            ("t", "", Some(&two.root), &two.transcript),
            ("t", "agent-1", Some(&two.root), &sub),
        ]);

        let first = one.import();

        assert!(first.stored.is_empty() && !marked("t"));
        let tree = one.remote(&stand);
        assert_eq!(imported(&tree, "t", "agent-1"), text(&sub));
        assert_eq!(imported(&tree, "t", "main"), text(&two.transcript));
    }

    /// Fails by: a source that will not read taken as one read to its end.
    #[test]
    fn a_push_record_the_source_cannot_be_read_against_marks_nothing() {
        let base = base("offbox-import-unreadable");
        let _stand = standing(&[], Vec::new());
        let two = pushed_whole_elsewhere(&base);
        let mut one = Writer::new(&base, "one", "s");
        // A directory opens and will not read: the source answers unavailable.
        one.history = listing(&[("t", "", Some(&two.root), &base)]);

        let first = one.import();
        let second = one.import();

        assert!(first.stored.is_empty() && second.stored.is_empty());
        assert!(second.marked.is_empty() && !second.moved);
        assert!(!marked("t"));
    }

    /// Fails by: a marker written for a push the forge did not take, or none
    /// written once it does.
    #[test]
    fn a_throttled_push_marks_nothing_and_the_next_applied_one_does() {
        let base = base("offbox-import-throttled");
        let stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        let a = base.join("a.jsonl");
        put(&a, &records(10..13, 4));
        one.history = listing(&[("a", "", None, &a)]);
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Receive,
            left: 1,
            status: 429,
            headers: vec![(String::from("retry-after"), String::from("120"))],
        });

        let throttled = one.import();

        assert!(matches!(outcome(&throttled), Pushed::Throttled(_)));
        assert!(throttled.marked.is_empty() && !marked("a"));

        let applied = one.import();
        assert_eq!(outcome(&applied), &Pushed::Applied);
        assert_eq!(applied.marked, [history_leaf("a")]);
        assert_eq!(imported(&one.remote(&stand), "a", "main"), text(&a));
    }

    /// Fails by: history another writer's snapshot left here uploaded again.
    #[test]
    fn history_absorbed_from_another_writer_is_marked_and_not_imported() {
        let base = base("offbox-import-absorbed");
        let _stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        let a = base.join("a.jsonl");
        put(&a, &records(10..13, 4));
        one.history = listing(&[("a", "", None, &a)]);
        let theirs = one
            .dir()
            .join("history")
            .join(history_leaf("a"))
            .join("transcript/main/0/000000.jsonl");
        put(&theirs, "{\"theirs\":1}\n");

        let done = one.import();

        assert_eq!(done.stored, [history_leaf("a")]);
        assert!(marked("a") && !one.imports());
        assert_eq!(text(&theirs), "{\"theirs\":1}\n");
    }

    /// Fails by: history read ahead of live data or past the cap, a session
    /// the cap never reached marked, or a session whose `meta.json` exists but
    /// whose import is unfinished taken for another writer's.
    ///
    /// The row's 250 MiB under a 100 MiB cap, at one part in 1024.
    #[test]
    fn history_is_imported_behind_live_data_inside_the_cap() {
        const KIB: usize = 1024;
        let base = base("offbox-import-cap");
        let stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        one.byte_cap = 100 * 1024;
        put(&one.transcript, &records(0..30, 1000));
        let (a, b, c) = (
            base.join("a.jsonl"),
            base.join("b.jsonl"),
            base.join("c.jsonl"),
        );
        put(&a, &records(1000..1118, 1000));
        put(&b, &records(2000..2118, 1000));
        put(&c, &records(3000..3010, 1000));
        let history = text(&a).len() + text(&b).len() + text(&c).len();
        assert!((245 * KIB..=250 * KIB).contains(&history), "{history}");
        one.history = listing(&[
            ("a", "", None, &a),
            ("b", "", None, &b),
            ("c", "", None, &c),
        ]);
        let live = text(&one.transcript);

        // The first push: all the live data, and history in what is left.
        assert_eq!(outcome(&one.import()), &Pushed::Applied);
        let tree = one.remote(&stand);
        assert_eq!(tree["transcript/main/0/000000.jsonl"], live.as_bytes());
        let got = imported(&tree, "a", "main");
        assert!(!got.is_empty() && text(&a).starts_with(&got));
        assert!(
            got.len() <= 100 * KIB - live.len() + 2 * KIB,
            "{}",
            got.len()
        );
        assert!(imported(&tree, "b", "main").is_empty());
        // A session the cap never reached has its entry and its meta already.
        let unreached = one.dir().join("history").join(history_leaf("c"));
        assert!(unreached.join("meta.json").is_file());

        assert_eq!(outcome(&one.import()), &Pushed::Applied);
        let tree = one.remote(&stand);
        assert_eq!(imported(&tree, "a", "main"), text(&a));
        assert!(imported(&tree, "c", "main").is_empty());
        assert!(!marked("a") && !marked("b") && !marked("c"));

        // The third push carries the last of it.
        assert_eq!(outcome(&one.import()), &Pushed::Applied);
        let tree = one.remote(&stand);
        for (id, file) in [("a", &a), ("b", &b), ("c", &c)] {
            assert_eq!(imported(&tree, id, "main"), text(file), "{id}");
        }
        assert!(marked("a"), "nothing new was found in it");
        assert!(!marked("b") && !marked("c"), "read to the end only now");

        // And the push after it finds nothing new anywhere, and sends nothing.
        assert_eq!(outcome(&one.import()), &Pushed::Unchanged);
        assert_eq!(receives(&stand), 3);
        assert!(marked("b") && marked("c"));
    }

    /// Fails by: a session another agent is still writing marked as finished,
    /// or one of its records stored twice.
    #[test]
    fn a_session_that_keeps_growing_is_never_marked() {
        let base = base("offbox-import-growing");
        let stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        let a = base.join("a.jsonl");
        put(&a, &records(10..12, 4));
        one.history = listing(&[("a", "", None, &a)]);

        for round in 0..4 {
            let done = one.import();
            assert!(done.marked.is_empty(), "round {round}");
            assert_eq!(imported(&one.remote(&stand), "a", "main"), text(&a));
            add(&a, &records(100 + round..101 + round, 4));
        }
        assert!(!marked("a"));
    }

    /// Fails by: a push rejected part-way through an import storing a record
    /// twice when it is tried again.
    #[test]
    fn a_push_rejected_mid_import_stores_no_record_twice() {
        let base = base("offbox-import-rejected");
        let stand = standing(&[], Vec::new());
        let first = Writer::new(&base, "first", "s");
        put(&first.transcript, &records(0..2, 4));
        assert_eq!(first.push().outcome, Pushed::Applied);
        let mut two = Writer::new(&base, "two", "s");
        put(&two.transcript, &records(5..6, 4));
        let a = base.join("a.jsonl");
        put(&a, &records(10..14, 4));
        two.history = listing(&[("a", "", None, &a)]);

        let done = two.import();

        assert_eq!(outcome(&done), &Pushed::Applied);
        assert_eq!(stand.borrow().uploads, 1, "the first try was rejected");
        assert_eq!(imported(&two.remote(&stand), "a", "main"), text(&a));
        two.import();
        assert_eq!(imported(&two.remote(&stand), "a", "main"), text(&a));
        assert!(marked("a"));
    }

    /// Fails by: two daemons on one machine both importing, or the one without
    /// the lock never importing once it is free.
    #[test]
    fn a_daemon_without_the_import_lock_imports_nothing_until_it_is_free() {
        let base = base("offbox-import-lock");
        let _stand = standing(&[], Vec::new());
        let mut one = Writer::new(&base, "one", "s");
        put(&one.transcript, &records(0..1, 4));
        let a = base.join("a.jsonl");
        put(&a, &records(10..12, 4));
        one.history = listing(&[("a", "", None, &a)]);
        std::fs::create_dir_all(machine()).unwrap();
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(machine().join(IMPORT_LOCK))
            .unwrap();
        fs4::FileExt::try_lock(&held).unwrap();

        let stopped = one.daemon(1000, 40, |_| {});

        let status = one.status();
        assert_eq!(status.history, "lock-held");
        assert_eq!(status.history_listed, 0);
        assert!(status.pushed != "-", "its own session is still pushed");
        assert!(!one.imports() && !marked("a"));

        drop(held);
        one.daemon(stopped, 40, |_| {});
        let status = one.status();
        assert_eq!(status.history, "ok");
        assert_eq!(
            (
                status.history_listed,
                status.history_imported,
                status.history_stored,
                status.history_remaining
            ),
            (1, 1, 0, 0)
        );
        assert!(marked("a"));
    }

    /// Fails by: a marker kept per session or per checkout, so every daemon on
    /// the machine uploads the same history.
    #[test]
    fn a_session_one_daemon_marked_is_not_imported_by_another_on_the_machine() {
        let base = base("offbox-import-once");
        let _stand = standing(&[], Vec::new());
        let a = base.join("a.jsonl");
        put(&a, &records(10..12, 4));
        let mut one = Writer::new(&base, "one", "s");
        one.history = listing(&[("a", "", None, &a)]);
        one.daemon(1000, 40, |_| {});
        assert!(marked("a"));
        assert!(one.imports());

        // Another session, in another checkout, on the same machine.
        let mut two = Writer::new(&base, "two", "t");
        two.history = listing(&[("a", "", None, &a)]);
        two.daemon(1000, 40, |_| {});

        let status = two.status();
        assert_eq!(
            (
                status.history_listed,
                status.history_imported,
                status.history_stored,
                status.history_remaining
            ),
            (1, 0, 1, 0)
        );
        assert!(!two.imports());
        assert!(two.local("history").is_empty());
    }

    /// Fails by: a daemon with no source to list sessions from saying its
    /// import is fine.
    #[test]
    fn a_harness_with_no_source_reads_not_surveyed() {
        let base = base("offbox-import-unsurveyed");
        let _stand = standing(&[], Vec::new());
        let one = Writer::new(&base, "one", "s");

        one.daemon(1000, 8, |_| {});

        let status = one.status();
        assert!(status.pushed != "-");
        assert_eq!(status.history, "not-surveyed");
        assert_eq!(crate::sessions::machine_sources("exit-code", None).len(), 0);
        let names: Vec<String> = crate::sessions::machine_sources("claude-code", None)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(names, ["claude-code"]);
    }

    // --- the rotation (CLOUD-2724) --------------------------------------------

    /// The rotation's scratch repository under `base`.
    fn rotating(base: &Path) -> PathBuf {
        base.join("rotate.git")
    }

    fn pass(base: &Path, quiet_runs: u64) -> Rotated {
        rotate_once(REMOTE, &rotating(base), quiet_runs, TIME).expect("the pass runs")
    }

    fn archive_tip(stand: &Shared) -> String {
        stand.borrow().head_of(ARCHIVE)
    }

    /// The archive's tree after an applied pass, path to text.
    fn archive_tree(stand: &Shared, base: &Path) -> BTreeMap<String, String> {
        let (repo, tip) = (rotating(base), archive_tip(stand));
        gitwrite::tree_index(&repo, &tip)
            .unwrap()
            .into_iter()
            .map(|(path, id)| {
                let bytes = gitwrite::read_blob(&repo, &id).unwrap();
                (path, String::from_utf8(bytes).unwrap())
            })
            .collect()
    }

    /// The parents of a commit the stand-in holds.
    fn parents_of(stand: &Shared, commit: &str) -> Vec<String> {
        let stand = stand.borrow();
        let held = stand.objects.iter().find(|held| held.id == commit).unwrap();
        String::from_utf8_lossy(&held.body)
            .lines()
            .filter_map(|line| line.strip_prefix("parent "))
            .map(str::to_owned)
            .collect()
    }

    /// A writer that has pushed one record of session `session`.
    fn session_pushed(base: &Path, name: &str, session: &str) -> Writer {
        let writer = Writer::new(base, name, session);
        put(&writer.transcript, &records(0..1, 4));
        assert_eq!(writer.push().outcome, Pushed::Applied);
        writer
    }

    /// Push one more record, so the session's ref moves.
    fn push_again(writer: &Writer, n: usize) {
        add(&writer.transcript, &records(n..n + 1, 4));
        assert_eq!(writer.push().outcome, Pushed::Applied);
    }

    fn observed(tree: &BTreeMap<String, String>, writer: &Writer) -> Option<String> {
        tree.get(&archive_path(OBSERVED, &reference(&writer.meta)))
            .cloned()
    }

    /// Fails by: a first pass that needs an archive to exist, that counts a ref
    /// it has only just seen as quiet, or that removes anything.
    #[test]
    fn a_first_pass_observes_every_ref_and_removes_none() {
        let base = base("offbox-rotate-first");
        let stand = standing(&[], Vec::new());
        let writers = [
            session_pushed(&base, "a", "a"),
            session_pushed(&base, "b", "b"),
            session_pushed(&base, "c", "c"),
        ];

        let rotated = pass(&base, 6);

        assert_eq!(rotated, Rotated::Done(0));
        assert_eq!(rotated.token(), "rotated 0");
        assert_eq!(rotated.code(), ExitCode::Success);
        assert!(parents_of(&stand, &archive_tip(&stand)).is_empty());
        let tree = archive_tree(&stand, &base);
        assert_eq!(tree.len(), 3, "{tree:?}");
        for writer in &writers {
            let tip = head(&stand, &writer.meta);
            assert_eq!(observed(&tree, writer), Some(format!("{tip}\n0\n")));
        }
        assert_eq!(
            stand.borrow().refs.len(),
            4,
            "three sessions and the archive"
        );

        // With no session ref there is nothing to observe and nothing is sent.
        let empty = standing(&[], Vec::new());
        assert_eq!(pass(&base.join("empty"), 6), Rotated::Done(0));
        assert_eq!(receives(&empty), 0);
    }

    /// Fails by: a ref removed whose commit the archive does not reach, a
    /// removal not tied to the tip that was archived, the previous archive left
    /// behind, a busy session rotated, or a pack that sends again what the
    /// remote already holds.
    #[test]
    fn a_quiet_session_is_archived_and_its_ref_removed() {
        let base = base("offbox-rotate-quiet");
        let stand = standing(&[], Vec::new());
        let quiet = session_pushed(&base, "a", "a");
        let busy = [
            session_pushed(&base, "b", "b"),
            session_pushed(&base, "c", "c"),
        ];
        let tip = head(&stand, &quiet.meta);
        let name = reference(&quiet.meta);
        for round in 1..=2 {
            assert_eq!(pass(&base, 2), Rotated::Done(0), "round {round}");
            for writer in &busy {
                push_again(writer, round);
            }
        }
        let before = archive_tip(&stand);

        let rotated = pass(&base, 2);

        assert_eq!(rotated, Rotated::Done(1));
        assert_eq!(rotated.token(), "rotated 1");
        let archive = archive_tip(&stand);
        assert_eq!(parents_of(&stand, &archive), [before, tip.clone()]);
        assert_eq!(head(&stand, &quiet.meta), lease::ZERO, "its ref is gone");
        let tree = archive_tree(&stand, &base);
        let index = archive_path(INDEX, &name);
        assert_eq!(tree[&index], format!("{name}\n{tip}\n"));
        assert_eq!(observed(&tree, &quiet), None);
        for writer in &busy {
            let theirs = head(&stand, &writer.meta);
            assert_ne!(theirs, lease::ZERO);
            assert_eq!(observed(&tree, writer), Some(format!("{theirs}\n0\n")));
        }
        // Every blob of the rotated snapshot is still held, under a commit the
        // archive names as a parent; and none of them was sent again.
        let sent = lease::testing::pack_ids(stand.borrow().sent.last().unwrap());
        let snapshot = gitwrite::tree_index(&quiet.repo(), &tip).unwrap();
        assert!(!snapshot.is_empty());
        for (path, blob) in &snapshot {
            let held = stand.borrow().objects.iter().any(|held| &held.id == blob);
            assert!(held, "{path}");
            assert!(!sent.contains(blob), "{path} was sent again");
        }
        assert!(!sent.contains(&tip));

        // The next pass carries the index file by id, and does not send it.
        let carried = gitwrite::tree_index(&rotating(&base), &archive)
            .unwrap()
            .into_iter()
            .find(|(path, _)| path == &index)
            .unwrap()
            .1;
        push_again(&busy[0], 9);
        assert_eq!(pass(&base, 2), Rotated::Done(0));
        let sent = lease::testing::pack_ids(stand.borrow().sent.last().unwrap());
        assert!(!sent.is_empty() && !sent.contains(&carried));
        assert_eq!(
            archive_tree(&stand, &base)[&index],
            format!("{name}\n{tip}\n")
        );
    }

    /// Fails by: a path a reader cannot compute from the ref's name.
    #[test]
    fn the_index_path_is_two_levels_and_its_first_line_is_the_ref() {
        // A ref whose key starts `0a1b`, found by trying names.
        let name = (0..10_000_000_u32)
            .map(|n| format!("refs/heads/session/acme/widgets/exit-code-{n:016x}"))
            .find(|name| archive_key(name).starts_with("0a1b"))
            .unwrap();
        let key = archive_key(&name);

        assert_eq!(key.len(), 16);
        assert_eq!(archive_path(INDEX, &name), format!("index/0a/1b/{key}"));
        assert_eq!(
            archive_path(OBSERVED, &name),
            format!("observed/0a/1b/{key}")
        );
    }

    /// Fails by: two projects' sessions sharing one index file.
    #[test]
    fn two_projects_with_one_session_name_have_two_keys() {
        let one = "refs/heads/session/acme/widgets/exit-code-0123456789abcdef";
        let other = "refs/heads/session/acme/gadgets/exit-code-0123456789abcdef";
        assert_ne!(archive_key(one), archive_key(other));
        assert_ne!(archive_path(INDEX, one), archive_path(INDEX, other));
    }

    /// Fails by: a ref skipped because its last segment is not a session leaf.
    #[test]
    fn a_ref_of_any_shape_under_the_session_prefix_is_rotated() {
        const PROBE: &str = "refs/heads/session/x/y/probe";
        let base = base("offbox-rotate-probe");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        let tip = head(&stand, &writer.meta);
        stand
            .borrow_mut()
            .refs
            .push((PROBE.to_owned(), tip.clone()));

        assert_eq!(pass(&base, 1), Rotated::Done(0));
        let tree = archive_tree(&stand, &base);
        assert_eq!(tree[&archive_path(OBSERVED, PROBE)], format!("{tip}\n0\n"));
        assert_eq!(pass(&base, 1), Rotated::Done(2));

        assert_eq!(stand.borrow().head_of(PROBE), lease::ZERO);
        let tree = archive_tree(&stand, &base);
        assert_eq!(
            tree[&archive_path(INDEX, PROBE)],
            format!("{PROBE}\n{tip}\n")
        );
    }

    /// Fails by: a session that pushed while the pass ran losing its branch, or
    /// the archive moving without the removal it was built for.
    #[test]
    fn a_session_that_pushes_during_the_pass_refuses_the_whole_push() {
        let base = base("offbox-rotate-moved");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        let name = reference(&writer.meta);
        assert_eq!(pass(&base, 1), Rotated::Done(0));
        let before = archive_tip(&stand);
        // The session's next push lands between the pass's read and its push.
        let pushed_meanwhile = before.clone();
        stand.borrow_mut().moved = Some(Moved {
            left: 1,
            name: name.clone(),
            id: pushed_meanwhile.clone(),
            then: Vec::new(),
        });

        let rotated = pass(&base, 1);

        assert_eq!(rotated, Rotated::Contended);
        assert_eq!(rotated.token(), "contended");
        assert_eq!(rotated.code(), ExitCode::Violation);
        assert_eq!(archive_tip(&stand), before, "the archive did not move");
        assert_eq!(stand.borrow().head_of(&name), pushed_meanwhile);
    }

    /// Fails by: a second rotation of one session losing the first snapshot's
    /// line, or its commit.
    #[test]
    fn a_session_rotated_twice_has_two_index_lines_oldest_first() {
        let base = base("offbox-rotate-twice");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        let name = reference(&writer.meta);
        let first = head(&stand, &writer.meta);
        assert_eq!(pass(&base, 1), Rotated::Done(0));
        assert_eq!(pass(&base, 1), Rotated::Done(1));

        // It was only idle: its daemon finds the ref absent and creates it.
        push_again(&writer, 1);
        let second = head(&stand, &writer.meta);
        assert_ne!(second, first);
        assert_eq!(pass(&base, 1), Rotated::Done(0));
        assert_eq!(pass(&base, 1), Rotated::Done(1));

        let tree = archive_tree(&stand, &base);
        assert_eq!(
            tree[&archive_path(INDEX, &name)],
            format!("{name}\n{first}\n{second}\n")
        );
        // Both snapshots are parents somewhere in the archive's history.
        let mut reached = BTreeSet::new();
        let mut pending = vec![archive_tip(&stand)];
        while let Some(commit) = pending.pop() {
            if commit != first && commit != second && reached.insert(commit.clone()) {
                pending.extend(parents_of(&stand, &commit));
            } else {
                reached.insert(commit);
            }
        }
        assert!(reached.contains(&first) && reached.contains(&second));
    }

    /// Fails by: a session that pushed keeping the quiet passes it had counted.
    #[test]
    fn a_ref_whose_tip_changed_starts_its_count_again() {
        assert_eq!(quiet_passes("abc\n2\n", "abc"), 3);
        assert_eq!(quiet_passes("abc\n2\n", "def"), 0);
        assert_eq!(quiet_passes("abc\n", "abc"), 1);

        let base = base("offbox-rotate-reset");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        for _ in 0..3 {
            assert_eq!(pass(&base, 5), Rotated::Done(0));
        }
        let tip = head(&stand, &writer.meta);
        let tree = archive_tree(&stand, &base);
        assert_eq!(observed(&tree, &writer), Some(format!("{tip}\n2\n")));

        push_again(&writer, 1);
        assert_eq!(pass(&base, 5), Rotated::Done(0));

        let tip = head(&stand, &writer.meta);
        let tree = archive_tree(&stand, &base);
        assert_eq!(observed(&tree, &writer), Some(format!("{tip}\n0\n")));
    }

    /// Fails by: a throttled pass removing a ref, moving the archive, or
    /// failing the job that runs it.
    #[test]
    fn a_throttled_pass_changes_nothing_and_exits_clean() {
        let base = base("offbox-rotate-throttled");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        let tip = head(&stand, &writer.meta);
        assert_eq!(pass(&base, 1), Rotated::Done(0));
        let before = archive_tip(&stand);
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Receive,
            left: 1,
            status: 429,
            headers: vec![(String::from("retry-after"), String::from("60"))],
        });

        let rotated = pass(&base, 1);

        assert_eq!(rotated, Rotated::Throttled);
        assert_eq!(rotated.token(), "throttled");
        assert_eq!(rotated.code(), ExitCode::Success);
        assert_eq!(archive_tip(&stand), before);
        assert_eq!(head(&stand, &writer.meta), tip, "no ref was removed");

        // A throttle at discovery is the same answer, and sends nothing.
        stand.borrow_mut().canned.push(Canned {
            kind: Kind::Discovery,
            left: 1,
            status: 429,
            headers: Vec::new(),
        });
        let posts = receives(&stand);
        assert_eq!(pass(&base, 1), Rotated::Throttled);
        assert_eq!(receives(&stand), posts);

        // And the next pass does what the throttled one could not.
        assert_eq!(pass(&base, 1), Rotated::Done(1));
        assert_eq!(head(&stand, &writer.meta), lease::ZERO);
    }

    /// Fails by: a command list sent to a remote that may apply part of it.
    #[test]
    fn a_remote_without_atomic_is_refused_and_nothing_is_sent() {
        let base = base("offbox-rotate-no-atomic");
        let stand = standing(&[], Vec::new());
        let writer = session_pushed(&base, "a", "a");
        stand.borrow_mut().no_atomic = true;
        let posts = receives(&stand);

        let refused = rotate_once(REMOTE, &rotating(&base), 1, TIME);

        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(receives(&stand), posts);
        assert_eq!(archive_tip(&stand), lease::ZERO);
        assert_ne!(head(&stand, &writer.meta), lease::ZERO);
    }
}
