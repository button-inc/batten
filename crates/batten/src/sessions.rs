//! The session-source contract: list every session an agent has stored on this
//! machine, and read each one's native records from a cursor (CLOUD-1010).
//!
//! # Why this is a contract and not a parser
//!
//! Agents keep sessions three ways — a directory of append-only files, a command
//! or HTTP API, a database — and the off-box daemon (CLOUD-2717) has to ship all
//! of them without knowing which it is holding. So the contract is the READING
//! half of a session store and nothing more: [`SessionSource::list`] names the
//! sessions, [`SessionSource::read`] hands back the next records after a cursor.
//!
//! # Records are verbatim
//!
//! [`Record::bytes`] is exactly what the agent wrote for that record. Nothing is
//! parsed out of it except, where the format has one, the record's own id — and
//! that only because identity is what makes a union of two logs a valid merge.
//! A source whose records carry no id returns `None`, and its sessions are kept
//! whole rather than merged by record.
//!
//! # Could-not-look is never empty
//!
//! A source that cannot be read answers [`Fidelity::Unavailable`], and one that
//! was replaced under its cursor answers [`Fidelity::Partial`]. Neither is ever
//! an empty [`Fidelity::Full`]: "there is nothing new" and "I could not look"
//! are different answers, and a snapshot built from the second would record a
//! session as shorter than it is.
//!
//! # A read is bounded
//!
//! [`SessionSource::read`] returns whole records until their bytes reach
//! `max_bytes`, and at least one when one is available. So a caller can stop
//! part-way through a 250 MiB transcript holding a valid cursor, and the whole
//! source is never in memory.
//!
//! # No clock, and no network in the trait
//!
//! A source that needs a network call makes it inside its own implementation,
//! and only the daemon may use such a source. `policy/module-layering.rego`
//! forbids the `hook -> sessions` edge, so no mediated call can come to wait on
//! one. The module is `sessions` because `source.rs` is already the Rust parser.

use std::io::{BufRead as _, Read as _, Seek as _};
use std::path::{Path, PathBuf};

use crate::Result;
use crate::hook::Harness;

/// One session an agent has stored, as its source names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionRef {
    /// The agent's own id for the session.
    pub id: String,
    /// The project directory the agent recorded for it, where it records one.
    pub project: Option<PathBuf>,
    /// Where the source finds it. Opaque to every caller: only the source that
    /// produced it reads it back.
    pub locator: String,
    /// Empty for the session's main record stream; a name for a secondary one,
    /// such as a subagent's file.
    pub sub: String,
}

/// How far into a session a reader has got: an opaque byte string a source
/// produced earlier, or empty for the start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor(pub Vec<u8>);

impl Cursor {
    /// The cursor before the first record.
    #[must_use]
    pub const fn start() -> Self {
        Cursor(Vec::new())
    }

    /// Whether this is the start.
    #[must_use]
    pub fn is_start(&self) -> bool {
        self.0.is_empty()
    }
}

/// One native record, verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's own id, where its format has one.
    pub id: Option<String>,
    /// Exactly what the agent wrote for it.
    pub bytes: Vec<u8>,
}

/// How much of the truth a [`Batch`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fidelity {
    /// Everything between the two cursors.
    Full,
    /// Something is known to be missing; the token says what.
    Partial(&'static str),
    /// The source could not be read at all; the token says why.
    Unavailable(&'static str),
}

/// The token for a source that is not there.
pub const MISSING: &str = "source-missing";

/// The token for a source that will not read.
pub const UNREADABLE: &str = "source-unreadable";

/// The token for a source that is not the one a cursor was taken over: shorter
/// than the cursor, or opening with a different record.
pub const REPLACED: &str = "source-replaced";

/// A source that cannot be enumerated at all, where there is no [`Batch`] to
/// carry the fidelity: [`SessionSource::list`]'s could-not-look.
///
/// An error a caller matches BY TYPE, so "there are no sessions" — an empty
/// list — never stands in for "the place sessions are kept could not be read".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable(pub &'static str);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "sessions: the source is unavailable ({})",
            self.0
        )
    }
}

impl std::error::Error for Unavailable {}

/// The records after a cursor, the cursor after them, and how whole they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    /// In the source's own order.
    pub records: Vec<Record>,
    /// Where the next read starts.
    pub cursor: Cursor,
    /// Whether this is everything.
    pub fidelity: Fidelity,
}

impl Batch {
    /// No records and a start cursor, with the fidelity that says why.
    #[must_use]
    pub const fn unavailable(fidelity: Fidelity) -> Self {
        Batch {
            records: Vec::new(),
            cursor: Cursor::start(),
            fidelity,
        }
    }

    /// Whether the source has no more complete records after this batch's
    /// cursor: a full batch that came back empty.
    #[must_use]
    pub fn is_ended(&self) -> bool {
        self.fidelity == Fidelity::Full && self.records.is_empty()
    }
}

/// The reading half of a session store.
pub trait SessionSource {
    /// Every session this source holds.
    ///
    /// # Errors
    ///
    /// A source that cannot be enumerated. A source that is simply absent is an
    /// empty list: there are no sessions to name.
    fn list(&self) -> Result<Vec<SessionRef>>;

    /// The records of `session` after `from`: whole records until their bytes
    /// reach `max_bytes`, and at least one when one is available.
    ///
    /// # Errors
    ///
    /// An internal failure of the source. A source that cannot be read is NOT
    /// an error: it is a [`Batch`] whose fidelity says so.
    fn read(&self, session: &SessionRef, from: &Cursor, max_bytes: u64) -> Result<Batch>;
}

/// How much of a file's start is hashed to tell it from another file.
const HEAD_PROBE: u64 = 64 * 1024;

/// A digest of `file`'s first line, or of its first [`HEAD_PROBE`] bytes where
/// the line is longer — what a file cursor carries to notice a replacement.
fn head_of(file: &mut std::fs::File) -> std::io::Result<String> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut first = Vec::new();
    file.by_ref().take(HEAD_PROBE).read_to_end(&mut first)?;
    let line = first
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    Ok(blake3::hash(line).to_hex().to_string())
}

/// A file cursor's two halves: the byte offset it stops at, and the head digest
/// of the file it was taken over.
fn parse_cursor(cursor: &Cursor) -> Option<(u64, String)> {
    let text = std::str::from_utf8(&cursor.0).ok()?;
    let (offset, head) = text.split_once(':')?;
    Some((offset.parse().ok()?, head.to_owned()))
}

/// The id a JSON-lines record carries: its top-level `uuid`, when the line is a
/// JSON object that has one as a string. Nothing else is read out of a record.
fn record_id(bytes: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Identified {
        uuid: Option<String>,
    }
    serde_json::from_slice::<Identified>(bytes).ok()?.uuid
}

/// Read a JSON-lines file as a session: one record per complete line, verbatim
/// (CLOUD-1010).
///
/// The file source every append-only agent format shares. The cursor is a byte
/// offset plus a digest of the file's first line, which is `transcript`'s own
/// test for "this is not the file I read before": a file shorter than the
/// offset, or opening with a different line, answers
/// [`Fidelity::Partial`]`(`[`REPLACED`]`)` and a start cursor.
///
/// **A partial trailing line is not returned.** A host mid-write leaves a line
/// with no terminator; the cursor stops before it, so a half-written line is
/// never stored as a record and is read whole once its newline lands.
///
/// An empty line is not a record. The terminator is not part of a record.
#[must_use]
//MUTANT-SUITE crates/batten/tests/it/source_claude_code.rs
//MUTANT unterminated-line-returned|s@^        if line.last() != Some(&b'\\n') {$@        if false {@|an_unterminated_line_is_withheld_until_it_ends
//MUTANT bounded-read-skips-a-line|s@^        if taken >= max_bytes {$@        if taken >= max_bytes { at += 1;@|a_bounded_read_returns_every_line_exactly_once
//MUTANT truncated-file-keeps-its-cursor|s@^    if replaced {$@    if false {@|a_truncated_file_is_partial
//MUTANT-SUITE crates/batten/tests/it/session_source.rs
//MUTANT partial-trailing-record-returned|s@^        if line.last() != Some(&b'\\n') {$@        if false {@|a_half_written_line_waits_for_its_newline
//MUTANT record-bytes-normalised|s@^        line.pop();$@        line.pop(); line.retain(\x7cbyte\x7c !byte.is_ascii_whitespace());@|records_are_the_files_lines_byte_for_byte
//MUTANT missing-source-reads-empty|s@^        return Batch::unavailable(Fidelity::Unavailable(MISSING));$@        return Batch::unavailable(Fidelity::Full);@|a_missing_source_is_unavailable_and_never_empty
//MUTANT replaced-source-keeps-its-cursor|s@^    if replaced {$@    if false {@|a_replaced_file_is_partial_and_starts_again
//MUTANT read-ignores-the-byte-bound|s@^        if taken >= max_bytes {$@        if false {@|a_read_stops_at_the_byte_bound_and_never_splits_a_record
pub fn read_jsonl(path: &Path, from: &Cursor, max_bytes: u64) -> Batch {
    let Ok(mut file) = std::fs::File::open(path) else {
        if path.exists() {
            return Batch::unavailable(Fidelity::Unavailable(UNREADABLE));
        }
        return Batch::unavailable(Fidelity::Unavailable(MISSING));
    };
    let unreadable = || Batch::unavailable(Fidelity::Unavailable(UNREADABLE));
    let Ok(length) = file.metadata().map(|meta| meta.len()) else {
        return unreadable();
    };
    let Ok(head) = head_of(&mut file) else {
        return unreadable();
    };
    let (offset, replaced) = match parse_cursor(from) {
        Some((offset, taken_over)) => (offset, taken_over != head || offset > length),
        // A cursor this source did not produce reads as the start only when it
        // IS the start; anything else is a cursor over some other source.
        None => (0, !from.is_start()),
    };
    if replaced {
        return Batch::unavailable(Fidelity::Partial(REPLACED));
    }
    if file.seek(std::io::SeekFrom::Start(offset)).is_err() {
        return unreadable();
    }
    let mut reader = std::io::BufReader::new(file);
    let mut records = Vec::new();
    let mut at = offset;
    let mut taken = 0_u64;
    loop {
        let mut line = Vec::new();
        let Ok(read) = reader.read_until(b'\n', &mut line) else {
            return unreadable();
        };
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            break;
        }
        at += u64::try_from(read).unwrap_or(u64::MAX);
        line.pop();
        if line.is_empty() {
            continue;
        }
        taken += u64::try_from(line.len()).unwrap_or(u64::MAX);
        records.push(Record {
            id: record_id(&line),
            bytes: line,
        });
        if taken >= max_bytes {
            break;
        }
    }
    // THE START STAYS THE START: a cursor is minted only once a first line
    // exists to take the head digest over, so a file read before its first
    // newline lands is not later mistaken for a replaced one.
    let cursor = if at == 0 {
        Cursor::start()
    } else {
        Cursor(format!("{at}:{head}").into_bytes())
    };
    Batch {
        records,
        cursor,
        fidelity: Fidelity::Full,
    }
}

/// The neutral source: one JSON-lines file the caller names, ids from a
/// top-level `uuid` where a line has one.
///
/// What [`Harness::ExitCode`] gets, and what the contract's own cases drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlFile {
    path: PathBuf,
}

impl JsonlFile {
    /// The source over the file at `path`.
    #[must_use]
    pub fn at(path: &Path) -> Self {
        JsonlFile {
            path: path.to_path_buf(),
        }
    }
}

impl SessionSource for JsonlFile {
    fn list(&self) -> Result<Vec<SessionRef>> {
        if !self.path.is_file() {
            return Ok(Vec::new());
        }
        Ok(vec![SessionRef {
            id: self
                .path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default(),
            project: None,
            locator: self.path.to_string_lossy().into_owned(),
            sub: String::new(),
        }])
    }

    fn read(&self, session: &SessionRef, from: &Cursor, max_bytes: u64) -> Result<Batch> {
        Ok(read_jsonl(Path::new(&session.locator), from, max_bytes))
    }
}

/// A harness's session source, or that nobody has written one.
///
/// [`crate::hook::TranscriptShape`]'s shape, for its reason: a harness with no
/// source is "not surveyed", carrying the row that owes it, and is never
/// reported as a harness that stores no sessions.
#[allow(missing_debug_implementations)]
pub enum Sourced {
    /// The source for this harness.
    Surveyed(Box<dyn SessionSource>),
    /// Nobody has written one; the row that owes it.
    Unsurveyed(&'static str),
}

/// The session source for `harness`, reading `transcript` where the harness's
/// source is a single file the caller names.
#[must_use]
pub fn source_for(harness: Harness, transcript: Option<&Path>) -> Sourced {
    match harness {
        Harness::ExitCode => match transcript {
            Some(path) => Sourced::Surveyed(Box::new(JsonlFile::at(path))),
            // The neutral contract has no place of its own to look: without a
            // file there is no source, and saying so is not a survey gap.
            None => Sourced::Surveyed(Box::new(JsonlFile::at(Path::new("")))),
        },
        Harness::ClaudeCode => Sourced::Surveyed(Box::new(claude_code::ClaudeCode::at(
            &claude_code::root_from(
                transcript,
                std::env::var(claude_code::ROOT_ENV).ok().as_deref(),
                etcetera::home_dir().ok().as_deref(),
            )
            .unwrap_or_default(),
        ))),
        Harness::CodexCli => Sourced::Unsurveyed("CLOUD-1012"),
        Harness::GeminiCli => Sourced::Unsurveyed("CLOUD-1013"),
        Harness::Cursor => Sourced::Unsurveyed("CLOUD-1014"),
        Harness::CopilotCli => Sourced::Unsurveyed("CLOUD-1015"),
    }
}

/// The session source for the harness NAMED `harness`, or `None` where the name
/// is no harness's or nobody has written its source.
///
/// For a caller that holds the name as text — a flag's value — and must not
/// reach the harness table to turn it into one.
#[must_use]
pub fn source_named(harness: &str, transcript: Option<&Path>) -> Option<Box<dyn SessionSource>> {
    let harness = Harness::ALL.iter().find(|each| each.as_str() == harness)?;
    match source_for(*harness, transcript) {
        Sourced::Surveyed(source) => Some(source),
        Sourced::Unsurveyed(_) => None,
    }
}

/// A harness's name and its source.
pub type Named = (String, Box<dyn SessionSource>);

/// Every source that lists the sessions kept on this machine, by harness name,
/// for the daemon of a session of `harness` (CLOUD-2735).
///
/// One per harness that has an implementation; a harness with none is left
/// out. `transcript` is read only by `harness`'s own source, which finds its
/// place from it.
///
/// **The neutral harness gets none.** Its source is one file the caller names:
/// it has no machine to list, so a daemon run for it imports nothing.
#[must_use]
pub fn machine_sources(harness: &str, transcript: Option<&Path>) -> Vec<Named> {
    let neutral = Harness::ExitCode.as_str();
    if harness == neutral {
        return Vec::new();
    }
    Harness::ALL
        .iter()
        .filter(|each| each.as_str() != neutral)
        .filter_map(|each| {
            let named = transcript.filter(|_| each.as_str() == harness);
            match source_for(*each, named) {
                Sourced::Surveyed(source) => Some((each.as_str().to_owned(), source)),
                Sourced::Unsurveyed(_) => None,
            }
        })
        .collect()
}

/// Claude Code's session source (CLOUD-1011): one append-only JSON-lines file
/// per session under a projects directory, with subagent transcripts in a
/// `subagents` directory beside the session they belong to.
///
/// An inline module rather than a file of its own under a `sessions/`
/// directory: every gate that scans this crate's sources reads `src/*.rs`, and
/// a nested file would sit outside all of them.
///
/// **Nothing waits for the agent to flush.** Its transcript "is written
/// asynchronously and may lag the in-memory conversation", so a record not yet
/// on disk is simply picked up by the next read.
///
/// No record's content is interpreted beyond `sessionId` and `cwd` — and
/// `uuid`, which [`read_jsonl`] reads — and none is ever printed.
//MUTANT-SUITE crates/batten/tests/it/source_claude_code.rs
//MUTANT session-without-an-author-listed|s@^                        (None, None) => continue,$@                        (None, None) => (String::from("unauthored"), String::new()),@|every_authored_session_is_listed_sorted_with_its_cwd
//MUTANT directory-link-followed|s@^                        let real_dir = entry.file_type().is_ok_and(\x7ckind\x7c kind.is_dir());$@                        let real_dir = entry.path().is_dir();@|a_directory_link_is_not_followed
//MUTANT subagent-file-listed-as-its-own-session|s@^                        (Some(sub), _) => (parent, sub),$@                        (Some(sub), _) => (sub, String::new()),@|a_subagent_file_is_listed_under_its_parent_session
pub mod claude_code {
    use std::io::BufRead as _;
    use std::path::{Path, PathBuf};

    use super::{Batch, Cursor, MISSING, SessionRef, SessionSource, Unavailable, read_jsonl};
    use crate::Result;

    /// The variable that names the projects directory outright.
    pub const ROOT_ENV: &str = "BATTEN_TRANSCRIPT_ROOT";

    /// The directory, under a session's own, that holds its subagents' files.
    const SUBAGENTS: &str = "subagents";

    /// The projects directory to read.
    ///
    /// Two levels above the envelope's transcript path when the caller has one
    /// — `<root>/<encoded working directory>/<session id>.jsonl` — otherwise
    /// the variable, otherwise the agent's default under `home`. The first is
    /// preferred because it is where THIS session's agent is actually writing,
    /// whatever relocated its config directory.
    #[must_use]
    pub fn root_from(
        transcript: Option<&Path>,
        named: Option<&str>,
        home: Option<&Path>,
    ) -> Option<PathBuf> {
        transcript
            .and_then(|path| path.parent()?.parent())
            .map(Path::to_path_buf)
            .or_else(|| named.filter(|root| !root.is_empty()).map(PathBuf::from))
            .or_else(|| home.map(|home| home.join(".claude").join("projects")))
    }

    /// The source over one projects directory.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ClaudeCode {
        root: PathBuf,
    }

    impl ClaudeCode {
        /// The source over the projects directory at `root`.
        #[must_use]
        pub fn at(root: &Path) -> Self {
            ClaudeCode {
                root: root.to_path_buf(),
            }
        }
    }

    /// What one transcript file says about whose it is.
    #[derive(Default)]
    struct Named {
        /// The first AUTHORED session id, which identifies a session's own file.
        authored: Option<String>,
        /// The first session id of any record, which a subagent's file carries
        /// for the session that started it.
        any: Option<String>,
        /// The working directory the identifying record carries.
        project: Option<PathBuf>,
    }

    /// Read `path` a line at a time until it has said whose it is.
    fn named(path: &Path) -> Named {
        #[derive(serde::Deserialize)]
        struct Fields {
            #[serde(rename = "sessionId")]
            session_id: Option<String>,
            cwd: Option<String>,
        }
        let mut found = Named::default();
        let Ok(file) = std::fs::File::open(path) else {
            return found;
        };
        let mut reader = std::io::BufReader::new(file);
        loop {
            let mut raw = Vec::new();
            if !reader
                .read_until(b'\n', &mut raw)
                .is_ok_and(|read| read > 0)
            {
                return found;
            }
            let Ok(line) = std::str::from_utf8(&raw) else {
                continue;
            };
            let fields = serde_json::from_str::<Fields>(line).ok();
            if found.any.is_none() {
                found.any = fields
                    .as_ref()
                    .and_then(|fields| fields.session_id.clone())
                    .filter(|id| !id.is_empty());
            }
            if let Some(id) = crate::transcript::authored_session_id(line) {
                found.authored = Some(id);
                found.project = fields.and_then(|fields| fields.cwd).map(PathBuf::from);
                return found;
            }
        }
    }

    impl SessionSource for ClaudeCode {
        /// Every session under the root: one per `.jsonl` file that has an
        /// authored `sessionId`, and one per file under a `subagents`
        /// directory, listed under its parent session's id with a sub-key.
        ///
        /// Sorted, and a directory link is never followed.
        ///
        /// # Errors
        ///
        /// [`Unavailable`] where the root is not a directory. One unreadable
        /// directory beneath it is not a failed listing of the rest.
        fn list(&self) -> Result<Vec<SessionRef>> {
            if !self.root.is_dir() {
                return Err(anyhow::Error::new(Unavailable(MISSING)));
            }
            let mut sessions = Vec::new();
            let mut pending = vec![self.root.clone()];
            while let Some(next) = pending.pop() {
                let Ok(entries) = std::fs::read_dir(&next) else {
                    continue;
                };
                // THE ENTRY'S OWN TYPE, WHICH DOES NOT FOLLOW A LINK: this walk
                // keeps no visited set, so a linked directory cycle under the
                // root would never end — `transcript::census`'s own reason.
                let mut names: Vec<(PathBuf, bool)> = entries
                    .flatten()
                    .map(|entry| {
                        let real_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
                        (entry.path(), real_dir)
                    })
                    .collect();
                names.sort();
                for (path, real_dir) in names {
                    if real_dir {
                        pending.push(path);
                        continue;
                    }
                    if path.extension().is_none_or(|ext| ext != "jsonl") {
                        continue;
                    }
                    let said = named(&path);
                    let holder = path.parent();
                    let subagent = holder
                        .filter(|dir| dir.file_name().is_some_and(|name| name == SUBAGENTS))
                        .and(path.file_stem())
                        .map(|stem| stem.to_string_lossy().into_owned());
                    // A subagent's parent is the session its records name, or
                    // the session directory its `subagents` directory sits in.
                    let parent = said.any.clone().unwrap_or_else(|| {
                        holder
                            .and_then(Path::parent)
                            .and_then(Path::file_name)
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    });
                    let (id, sub) = match (subagent, said.authored) {
                        (Some(sub), _) => (parent, sub),
                        (None, Some(id)) => (id, String::new()),
                        (None, None) => continue,
                    };
                    sessions.push(SessionRef {
                        id,
                        project: said.project,
                        locator: path.to_string_lossy().into_owned(),
                        sub,
                    });
                }
            }
            sessions.sort();
            Ok(sessions)
        }

        fn read(&self, session: &SessionRef, from: &Cursor, max_bytes: u64) -> Result<Batch> {
            Ok(read_jsonl(Path::new(&session.locator), from, max_bytes))
        }
    }
}
