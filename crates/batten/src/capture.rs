//! Captured child output, content-addressed in out-of-tree state (CLOUD-162).
//!
//! The shared substrate two capabilities need over the output of a single
//! `batten exec` run: an output predicate that scans it for a pattern meaning
//! "not actually done" (CLOUD-117), and a handle an agent can expand without
//! re-running the command (CLOUD-121). Built once, here, so neither consumer
//! grows its own copy — building the capture twice is the failure the issue
//! exists to prevent.
//!
//! ## What this module is, and is not
//!
//! It is the *storage and addressing* of bytes a child already wrote. It renders
//! no verdict, scans for nothing, and emits nothing: the predicate is CLOUD-117's
//! and the `show` verbs are CLOUD-121's. Keeping it inert is what lets both land
//! on top of it without renegotiating where captures live.
//!
//! ## Addressing reuses the one hashing discipline
//!
//! [`crate::identity::capture_fingerprint`] — a domain tag then each field,
//! length-prefixed, the same construction every finding identity and the config
//! epoch already go through. The digest **is** the key: a capture is stored at
//! `captures/<digest>`, so identical bytes are one record rather than two, and
//! re-running a command whose output did not change writes nothing new.
//!
//! That is also why the record carries no timestamp. A capture keyed by content
//! must be a pure function of that content, and a "captured at" field would make
//! two identical outputs two different records — the byte-stability §6 requires,
//! broken by a field nothing reads.
//!
//! ## Why it lives out of tree
//!
//! [`crate::state::repo_state_dir`] — the same root the receipt store uses, so a
//! checkout stays clean and no new path scheme is invented. A capture is a fact
//! about one run of one command; it is not source, and a repo that accumulated
//! them would have to gitignore its own bookkeeping.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::error::UsageError;
use crate::identity;
use crate::state;

/// Which of a child's two output streams a capture holds.
///
/// A named pair rather than a bare string, so the stored key and the hashed
/// field cannot drift apart, and so a caller cannot invent a third stream the
/// reader will not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stream {
    /// The child's standard output.
    Stdout,
    /// The child's standard error.
    Stderr,
}

impl Stream {
    /// Both streams, so anything ranging over them is derived rather than typed
    /// twice.
    pub const ALL: &'static [Stream] = &[Stream::Stdout, Stream::Stderr];

    /// The stable token used in the store key and in the hashed preimage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }
}

/// A pointer to captured bytes: which stream, how many bytes, and their digest.
///
/// Pointer-only by construction (non-negotiable rule 4) — the record names the
/// bytes and never carries them, which is what lets it be emitted or logged
/// without leaking a program's output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Capture {
    /// The stream these bytes came from.
    pub stream: &'static str,
    /// How many bytes were captured. Zero is a real answer, not an absence.
    pub bytes: u64,
    /// The content digest, lowercase hex — and the key the bytes are stored at.
    pub digest: String,
}

impl Capture {
    /// The handle a consumer addresses this capture by: `<stream>:<digest>`.
    ///
    /// One string rather than two fields at every call site, and the shape
    /// CLOUD-121's `show` and CLOUD-117's predicate both read. A byte range is
    /// appended by the consumer that needs one, never stored here.
    #[must_use]
    pub fn handle(&self) -> String {
        format!("{}:{}", self.stream, self.digest)
    }
}

/// The directory captures live in, under the repository's state root.
fn captures_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(state::repo_state_dir(repo_root)?.join("captures"))
}

/// Distinguishes one staging file from another within a process.
///
/// See [`store`]: the pid alone collides when two threads of one `batten` write
/// the same content-addressed record at the same moment.
static STAGING_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Store `bytes` as `stream`'s capture for the repository at `repo_root`.
///
/// Content-addressed and therefore idempotent: storing the same bytes twice
/// leaves one record, and the returned [`Capture`] is identical both times.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be written. **Never a silent skip** — this is the substrate a gate will read,
/// and a capture that quietly did not happen is indistinguishable from a command
/// nobody checked. That is the same posture the receipt store takes, and the
/// reason both are internal errors rather than fail-open allowances.
pub fn store(repo_root: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
    let digest = identity::capture_fingerprint(stream.as_str(), bytes).to_hex();
    let dir = captures_dir(repo_root)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the capture store {}", dir.display()))?;

    // The digest already carries the stream, so the filename does not need to —
    // but it is included so a human listing the directory can tell what they are
    // looking at without hashing anything.
    let path = dir.join(format!("{}-{digest}", stream.as_str()));
    // Write unconditionally rather than skipping an existing file: a truncated
    // record from an interrupted earlier run would otherwise persist forever
    // under a digest that promises different bytes.
    //
    // TEMP-AND-RENAME, pid-suffixed, the idiom `findings.rs` and `journal.rs`
    // already use (CLOUD-430). `File::create` + `write_all` is two observable
    // states, and the first of them is an EMPTY file under a digest that
    // promises bytes — so a concurrent reader, or a second `batten` storing the
    // same content-addressed record at the same moment, could read a record that
    // is real, addressable and torn. `rename` within one directory is atomic, so
    // the only states a reader can see are "absent" and "complete". CLOUD-412's
    // flake is a strong candidate for exactly this.
    //
    // Pid AND a per-process counter. The pid alone is not unique enough: two
    // threads of ONE `batten` storing the same content-addressed record — a
    // bundle whose commands printed the same thing, or two library callers at
    // once — would stage to one path, and the second `rename` would find nothing
    // there. Measured, as `No such file or directory` on the publish.
    let attempt = STAGING_ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = dir.join(format!(
        "{}-{digest}.{}.{attempt}.tmp",
        stream.as_str(),
        std::process::id()
    ));
    let mut file = std::fs::File::create(&staging)
        .with_context(|| format!("write the capture {}", staging.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write the capture {}", staging.display()))?;
    file.sync_all()
        .with_context(|| format!("sync the capture {}", staging.display()))?;
    drop(file);
    std::fs::rename(&staging, &path)
        .with_context(|| format!("publish the capture {}", path.display()))?;

    Ok(Capture {
        stream: stream.as_str(),
        bytes: bytes.len() as u64,
        digest,
    })
}

/// The directory a still-running capture spools into.
fn live_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(captures_dir(repo_root)?.join("live"))
}

/// The handle a **live** capture is addressed by: `<stream>@<key>`.
///
/// `@` rather than `:`, and that is the whole point: a sealed handle is
/// `<stream>:<digest>` and names bytes that will never change again, while this
/// names a file that is still growing. One separator for each promise means a
/// reader cannot be handed a live handle and treat it as a settled one.
///
/// The `key` is the writing process's pid and the command's index within its
/// bundle, both of which the caller already knows — it spawned the process. That
/// is deliberate: printing the handle would put a pid in Batten's output, and §6
/// byte-stability forbids a field that differs between two identical runs.
#[must_use]
pub fn live_handle(stream: Stream, key: &str) -> String {
    format!("{}@{key}", stream.as_str())
}

/// What a reader saw when it asked a live capture for bytes.
///
/// `Busy` is an outcome rather than an error, exactly as [`crate::journal`]'s
/// merge treats a lost lock race: losing to an honest writer says nothing about
/// the capture, and the next read gets it. Making it an error would turn a
/// scheduling detail into a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiveRead {
    /// The bytes between the requested offset and the watermark.
    Bytes(Vec<u8>),
    /// Another party held the lock; nothing was read.
    Busy,
    /// No spool by that handle — never opened, or already sealed.
    Absent,
}

/// A capture that is still being written, with a committed-length watermark.
///
/// **Forced by the existing design rather than chosen** (CLOUD-430). [`store`]
/// runs after the child is reaped and the digest hashes the *complete* output,
/// so the digest cannot be the key while the stream is open: a mid-run read
/// would either block until exit or return a prefix under a key that promises
/// different bytes. A spool with a watermark is the smallest thing that makes
/// "read what has arrived so far" a well-defined question.
///
/// ## The lock, and why it is `fs4` rather than an async runtime
///
/// hk's model as a **shape** — one writer, N readers — not as a library. hk
/// keys a `tokio::sync::RwLock` per path; `crates/batten` links no async runtime
/// and adding one for a lock primitive is a large change to the dependency
/// surface for a small need. `fs4` is already here for [`crate::journal`], and it
/// brings the property this substrate actually has to survive: **an OS advisory
/// lock is released by the kernel when its holder dies.** A supervisor `SIGKILL`ed
/// mid-write (CLOUD-427) leaves a tokio `RwLock` nowhere and a `flock` released,
/// with the watermark naming exactly how much of the spool is real.
///
/// ## What the lock protects, which is less than it looks
///
/// Not the data. The spool has **one** writer, appending, so the bytes need no
/// mutual exclusion; what needs it is the *watermark*, because a reader that saw
/// a torn length would read a range nobody promised. So the discipline is: append
/// the bytes and flush them, then take the lock, publish the new length, release.
/// A reader takes a shared lock, reads the length, and reads only that far — and
/// because the length is published strictly after the bytes it covers, every byte
/// under the watermark is already durable.
///
/// A writer that cannot take the lock **skips the publish** rather than waiting:
/// the watermark then lags by one chunk and the next publish carries both. That
/// is what keeps a reader's contention off the child's critical path.
#[derive(Debug)]
pub struct Spool {
    /// The append-only data file.
    data: std::fs::File,
    /// Where the data file lives, for removal at seal.
    data_path: PathBuf,
    /// The lock file guarding the watermark.
    lock_path: PathBuf,
    /// The published length.
    watermark_path: PathBuf,
    /// How many bytes have been appended, published or not.
    written: u64,
}

impl Spool {
    /// Open (or reopen) the spool for `stream` under `key`.
    ///
    /// # Errors
    ///
    /// Returns an error when the state root cannot be resolved or the spool
    /// cannot be created.
    pub fn open(repo_root: &Path, stream: Stream, key: &str) -> Result<Self> {
        Self::open_in(&live_dir(repo_root)?, stream, key)
    }

    /// [`Spool::open`] into a directory named outright.
    ///
    /// The seam a test needs and the one production caller does not: resolving
    /// the state root reads the OS data directory, which a unit test must not
    /// write into. Splitting it keeps that out of the type's contract rather than
    /// putting a test-only branch inside `open`.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be created.
    pub fn open_in(dir: &Path, stream: Stream, key: &str) -> Result<Self> {
        let dir = dir.to_path_buf();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create the live capture directory {}", dir.display()))?;
        let handle = live_handle(stream, key);
        let data_path = dir.join(&handle);
        // Truncating on open, not appending: a pid can be reused, and inheriting
        // a dead run's bytes under a live handle would be worse than losing them.
        let data = std::fs::File::create(&data_path)
            .with_context(|| format!("open the spool {}", data_path.display()))?;
        let watermark_path = dir.join(format!("{handle}.watermark"));
        std::fs::write(&watermark_path, "0\n")
            .with_context(|| format!("open the watermark {}", watermark_path.display()))?;
        Ok(Spool {
            data,
            data_path,
            lock_path: dir.join(format!("{handle}.lock")),
            watermark_path,
            written: 0,
        })
    }

    /// Append `bytes` and publish the new committed length.
    ///
    /// # Errors
    ///
    /// Returns an error when the append fails. A lock the writer could not take
    /// is **not** an error — see the type's docs.
    pub fn commit(&mut self, bytes: &[u8]) -> Result<()> {
        self.data
            .write_all(bytes)
            .with_context(|| format!("append to the spool {}", self.data_path.display()))?;
        self.data
            .flush()
            .with_context(|| format!("flush the spool {}", self.data_path.display()))?;
        self.written += bytes.len() as u64;

        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("open the spool lock {}", self.lock_path.display()))?;
        // Fully qualified for `journal.rs`'s reason: `std::fs::File::try_lock`
        // was stabilized under the same name, and an inherent method would
        // silently win over the trait once the MSRV moves.
        match fs4::FileExt::try_lock(&lock) {
            Ok(()) => {}
            // The watermark lags one chunk and the next publish carries both.
            // Waiting here would put a reader's contention on the child's path.
            Err(fs4::TryLockError::WouldBlock) => return Ok(()),
            Err(fs4::TryLockError::Error(err)) => {
                return Err(anyhow::Error::from(err))
                    .with_context(|| format!("take the spool lock {}", self.lock_path.display()));
            }
        }
        let published = std::fs::write(&self.watermark_path, format!("{}\n", self.written));
        drop(lock);
        published
            .with_context(|| format!("publish the watermark {}", self.watermark_path.display()))
    }

    /// A second handle on the same spool, without truncating it.
    ///
    /// For the one case that needs it: a drain that hit its deadline leaves the
    /// tee thread alive holding the shared `Spool`, so the caller cannot take it
    /// by value — and waiting for a thread parked on a pipe a grandchild holds
    /// open is the hang the deadline exists to prevent. Reopening is safe because
    /// a spool's identity is its handle rather than its file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be opened for append.
    pub fn reopen(&self) -> Result<Self> {
        let data = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.data_path)
            .with_context(|| format!("reopen the spool {}", self.data_path.display()))?;
        Ok(Spool {
            data,
            data_path: self.data_path.clone(),
            lock_path: self.lock_path.clone(),
            watermark_path: self.watermark_path.clone(),
            written: self.written,
        })
    }

    /// Seal the spool into its content-addressed record and remove it.
    ///
    /// The sealed record is [`store`]'s, unchanged — which is what makes a
    /// bundled command's capture byte-identical to the same command run alone.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be stored.
    pub fn seal(self, repo_root: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
        let capture = store(repo_root, stream, bytes)?;
        drop(self.data);
        // Best effort: a spool file left behind names a run that ended, and the
        // next run with the same key truncates it. Failing the command because
        // bookkeeping could not be tidied would be the tail wagging the dog.
        drop(std::fs::remove_file(&self.data_path));
        drop(std::fs::remove_file(&self.watermark_path));
        drop(std::fs::remove_file(&self.lock_path));
        Ok(capture)
    }
}

/// Read a live capture from `from`, up to its committed watermark.
///
/// `limit` bounds one read; a reader asking again from where it stopped is
/// idempotent, which is the whole point — "more context" must not require
/// parsing a stream or holding a redirect.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the spool cannot
/// be read. A lock another party holds is [`LiveRead::Busy`], and an unopened or
/// already-sealed handle is [`LiveRead::Absent`] — neither is an error.
pub fn read_live(
    repo_root: &Path,
    stream: Stream,
    key: &str,
    from: u64,
    limit: usize,
) -> Result<LiveRead> {
    read_live_in(&live_dir(repo_root)?, stream, key, from, limit)
}

/// [`read_live`] from a directory named outright — [`Spool::open_in`]'s seam.
///
/// # Errors
///
/// As [`read_live`].
pub fn read_live_in(
    dir: &Path,
    stream: Stream,
    key: &str,
    from: u64,
    limit: usize,
) -> Result<LiveRead> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let handle = live_handle(stream, key);
    let data_path = dir.join(&handle);
    let watermark_path = dir.join(format!("{handle}.watermark"));
    let lock_path = dir.join(format!("{handle}.lock"));
    if !data_path.exists() {
        return Ok(LiveRead::Absent);
    }

    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open the spool lock {}", lock_path.display()))?;
    match fs4::FileExt::try_lock_shared(&lock) {
        Ok(()) => {}
        Err(fs4::TryLockError::WouldBlock) => return Ok(LiveRead::Busy),
        Err(fs4::TryLockError::Error(err)) => {
            return Err(anyhow::Error::from(err))
                .with_context(|| format!("take the spool lock {}", lock_path.display()));
        }
    }
    let committed = std::fs::read_to_string(&watermark_path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    drop(lock);

    if from >= committed {
        return Ok(LiveRead::Bytes(Vec::new()));
    }
    let available = committed - from;
    let want = usize::try_from(available).unwrap_or(usize::MAX).min(limit);
    let mut file = std::fs::File::open(&data_path)
        .with_context(|| format!("open the spool {}", data_path.display()))?;
    file.seek(SeekFrom::Start(from))
        .with_context(|| format!("seek the spool {}", data_path.display()))?;
    let mut bytes = vec![0_u8; want];
    // `read_exact`, never `read_to_end`: the file may have grown past the
    // watermark since it was read, and a reader that took those bytes would be
    // reading output the writer has not committed to.
    file.read_exact(&mut bytes)
        .with_context(|| format!("read the spool {}", data_path.display()))?;
    Ok(LiveRead::Bytes(bytes))
}

/// The committed length of a live capture, or `None` if there is no spool.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved.
pub fn live_watermark(repo_root: &Path, stream: Stream, key: &str) -> Result<Option<u64>> {
    Ok(live_watermark_in(&live_dir(repo_root)?, stream, key))
}

/// [`live_watermark`] in a directory named outright — [`Spool::open_in`]'s seam.
#[must_use]
pub fn live_watermark_in(dir: &Path, stream: Stream, key: &str) -> Option<u64> {
    let path = dir.join(format!("{}.watermark", live_handle(stream, key)));
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// Read back the bytes a [`Capture`] points at.
///
/// The read half CLOUD-117's predicate and CLOUD-121's `show` both need. It is
/// here rather than in either of them for the same reason the write half is: two
/// readers deriving the path independently is two chances to disagree about it.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be read.
pub fn read(repo_root: &Path, capture: &Capture) -> Result<Vec<u8>> {
    let path = captures_dir(repo_root)?.join(format!("{}-{}", capture.stream, capture.digest));
    std::fs::read(&path).with_context(|| format!("read the capture {}", path.display()))
}

// --- navigation (CLOUD-121) --------------------------------------------------
//
// The half that deletes the re-run. `cmd | tail -N` re-executes a possibly
// non-idempotent command to widen a window the agent had to guess the size of;
// everything below selects against bytes that were captured once and are frozen,
// so widening costs a read and never a second run.

/// A parsed `<stream>:<digest>` handle.
///
/// A type rather than two strings threaded through every call, and parsed rather
/// than trusted: a handle arrives from an agent's argv, so an unknown stream or a
/// non-hex digest is a [`UsageError`] naming the shape it wanted, never a path
/// join that reaches for a file outside the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    /// Which stream the capture holds.
    pub stream: Stream,
    /// The content digest, lowercase hex.
    pub digest: String,
}

impl Handle {
    /// Parse `text` as `<stream>:<digest>`.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a missing separator, a stream
    /// token no [`Stream`] declares, or a digest that is not lowercase hex.
    ///
    /// The digest check is not cosmetic: the digest becomes a path component, so
    /// rejecting anything that is not hex is what stops `..` and a separator from
    /// travelling there. Validating the *shape* rather than sanitising the string
    /// keeps that a property of the parser instead of a habit at each call site.
    pub fn parse(text: &str) -> Result<Self> {
        let Some((stream, digest)) = text.split_once(':') else {
            return Err(UsageError::raise(format!(
                "capture: {text:?} is not a handle — write `<stream>:<digest>`, as `batten capture \
                 list` prints them"
            )));
        };
        let Some(stream) = Stream::ALL.iter().find(|known| known.as_str() == stream) else {
            return Err(UsageError::raise(format!(
                "capture: unknown stream {stream:?} — a capture is one of {}",
                Stream::ALL
                    .iter()
                    .map(|known| known.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        if digest.is_empty() || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(UsageError::raise(format!(
                "capture: {digest:?} is not a digest — it is the lowercase hex `batten capture \
                 list` prints"
            )));
        }
        Ok(Handle {
            stream: *stream,
            digest: digest.to_owned(),
        })
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.stream.as_str(), self.digest)
    }
}

/// What a caller asked to see of a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Selection {
    /// No selection: the pointer alone — stream, digest, byte and line counts.
    ///
    /// The default, and deliberately the cheap one. Content is something a caller
    /// names, so the shape that costs nothing is what an unqualified `show`
    /// returns.
    Summary,
    /// A 1-indexed, inclusive line range, clamped to the capture.
    ///
    /// Clamped rather than refused: widening a window is the whole point, and an
    /// agent that asks for `1:5000` of a 400-line log wants the log, not an error
    /// telling it to guess again. Guessing again is the behaviour this deletes.
    Lines { from: usize, to: usize },
    /// Every line containing a literal substring.
    ///
    /// Literal, not regex, for the reason [`crate::outputs`] states about its own
    /// predicate: a reader should see what would match without evaluating an
    /// expression. `forbid` took the regex decision narrowly (CLOUD-283) and this
    /// is one of the places it was deliberately not taken.
    Grep { needle: String },
}

/// A capture's lines, numbered, as selected.
///
/// Numbered because the number is what makes the next call possible: an agent
/// greps, reads `127`, and asks for `120:135` — navigation, rather than a second
/// guess at a window size.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Line {
    /// The 1-indexed line number within the capture.
    pub number: usize,
    /// The line's text, without its terminator.
    pub text: String,
}

/// The answer to one `capture show`.
///
/// Carries the pointer *and* whatever content was selected, so a `-J` consumer
/// gets the provenance of the bytes in the same document as the bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Selected {
    /// The handle these lines came from.
    pub handle: String,
    /// The capture's total size in bytes.
    pub bytes: u64,
    /// The capture's total line count.
    pub lines: usize,
    /// The selected lines. Empty for [`Selection::Summary`], and empty is also a
    /// real answer for a `--grep` that matched nothing.
    pub selected: Vec<Line>,
}

/// Apply `selection` to `bytes`.
///
/// Pure over the bytes, so the arithmetic that decides what a caller sees is
/// testable without a store, a repository, or a spawned child.
///
/// **Lines come from a lossy decode**, and that is the honest reading rather than
/// a shortcut: a capture holds whatever a program wrote, which is not guaranteed
/// to be UTF-8, and refusing an agent line 127 of a build log because byte 4000
/// was invalid would send it back to the re-run. The *bytes* stay exact in the
/// store and are what the digest addresses; only this view is decoded. A trailing
/// newline mints no empty last line — a 400-line log has 400 lines.
#[must_use]
pub fn select(handle: &Handle, bytes: &[u8], selection: &Selection) -> Selected {
    let decoded = String::from_utf8_lossy(bytes);
    let all: Vec<&str> = decoded.lines().collect();
    let numbered = |index: usize, text: &str| Line {
        number: index + 1,
        text: text.to_owned(),
    };
    let selected = match selection {
        Selection::Summary => Vec::new(),
        Selection::Lines { from, to } => {
            // Clamped at both ends, and an inverted range selects nothing rather
            // than panicking on the slice — `5:2` is a caller error that costs an
            // empty answer, never a crash on a reachable path.
            let start = from.saturating_sub(1).min(all.len());
            let end = (*to).min(all.len());
            all.get(start..end)
                .unwrap_or(&[])
                .iter()
                .enumerate()
                .map(|(offset, text)| numbered(start + offset, text))
                .collect()
        }
        Selection::Grep { needle } => all
            .iter()
            .enumerate()
            .filter(|(_, text)| text.contains(needle.as_str()))
            .map(|(index, text)| numbered(index, text))
            .collect(),
    };
    Selected {
        handle: handle.to_string(),
        bytes: bytes.len() as u64,
        lines: all.len(),
        selected,
    }
}

/// Every capture in the repository's store, in a fixed order.
///
/// Sorted by handle rather than by mtime, so a listing is byte-stable (§6) and
/// two runs over an unchanged store agree. An mtime order would make the answer a
/// function of when captures happened, which is exactly the kind of field
/// [`store`] refuses to record.
///
/// A store that does not exist yet is an **empty listing, not an error**: a
/// repository where `exec` has never run has honestly captured nothing.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved, or when the store
/// exists and cannot be read.
pub fn list(repo_root: &Path) -> Result<Vec<Capture>> {
    let dir = captures_dir(repo_root)?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .with_context(|| format!("read the capture store {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("read the capture store {}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // A file the store did not write is skipped rather than reported: the
        // directory is Batten's, but a stray file there is not evidence about any
        // command, and inventing a capture from one would be a fabricated pointer.
        let Some((stream, digest)) = name.split_once('-') else {
            continue;
        };
        if Handle::parse(&format!("{stream}:{digest}")).is_err() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Some(stream) = Stream::ALL.iter().find(|known| known.as_str() == stream) else {
            continue;
        };
        found.push(Capture {
            stream: stream.as_str(),
            bytes: meta.len(),
            digest: digest.to_owned(),
        });
    }
    found.sort_by_key(Capture::handle);
    Ok(found)
}

/// Remove every capture in the repository's store, returning how many went.
///
/// **The whole lifecycle, and that is the design.** A capture is content-addressed
/// and never expires on its own; this is the one removal path. A time-based
/// sweeper would put a property of the world inside a verb — the split
/// `.claude/rules/toolchain.md` draws between a gate and a schedule — and the
/// store is bounded by how many *distinct* outputs a repository produces, not by
/// how often it runs them, because identical bytes are one record.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or a record cannot be
/// removed. A store that does not exist removes nothing and is not an error.
pub fn prune(repo_root: &Path) -> Result<usize> {
    let dir = captures_dir(repo_root)?;
    let mut removed = 0;
    for capture in list(repo_root)? {
        let path = dir.join(format!("{}-{}", capture.stream, capture.digest));
        std::fs::remove_file(&path)
            .with_context(|| format!("remove the capture {}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_stream_round_trips_through_its_token() {
        for stream in Stream::ALL {
            let token = stream.as_str();
            assert!(!token.is_empty());
            assert_eq!(
                Stream::ALL
                    .iter()
                    .filter(|other| other.as_str() == token)
                    .count(),
                1,
                "{token} is declared twice"
            );
        }
    }

    /// A live-capture directory under this process's own scratch space.
    fn scratch_live(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-spool-{}-{name}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        dir
    }

    #[test]
    fn a_live_handle_cannot_be_mistaken_for_a_sealed_one() {
        // One separator per promise: `:` names bytes that will never change,
        // `@` names a file that is still growing. A reader handed the wrong one
        // must be unable to treat it as the other.
        assert_eq!(live_handle(Stream::Stdout, "42.0"), "stdout@42.0");
        assert!(!live_handle(Stream::Stdout, "42.0").contains(':'));
    }

    #[test]
    fn a_reader_never_sees_past_the_watermark() {
        // The property the whole spool exists for, exercised through the one way
        // the file can genuinely run ahead of the watermark: a commit whose
        // publish lost the lock. The bytes land, the length does not, and a
        // reader must see the old length rather than the new bytes.
        let dir = scratch_live("watermark");
        let mut spool = Spool::open_in(&dir, Stream::Stdout, "unit").unwrap();
        spool.commit(b"first").unwrap();

        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("stdout@unit.lock"))
            .unwrap();
        // A second open file description in this same process still conflicts:
        // `flock` locks the description, not the process.
        fs4::FileExt::try_lock(&held).unwrap();

        // A reader that cannot take the shared lock is BUSY, which is an outcome
        // rather than an error — losing a race to an honest writer says nothing
        // about the capture, and the next read gets it.
        assert_eq!(
            read_live_in(&dir, Stream::Stdout, "unit", 0, 4096).unwrap(),
            LiveRead::Busy
        );

        // The commit succeeds and the publish is skipped: waiting here would put
        // a reader's contention on the child's critical path.
        spool.commit(b"-second").unwrap();
        assert!(
            std::fs::metadata(dir.join("stdout@unit")).unwrap().len() > 5,
            "the bytes did land"
        );
        drop(held);

        let LiveRead::Bytes(seen) = read_live_in(&dir, Stream::Stdout, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(
            seen, b"first",
            "the watermark lagged, so the reader must lag with it"
        );
        // IDEMPOTENT: the same range re-read is the same bytes, which is what
        // makes "more context" a repeatable question rather than a stream to
        // parse.
        let LiveRead::Bytes(again) = read_live_in(&dir, Stream::Stdout, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(again, seen);

        // And the next publish carries both chunks, so nothing is lost by lagging.
        spool.commit(b"-third").unwrap();
        let LiveRead::Bytes(all) = read_live_in(&dir, Stream::Stdout, "unit", 0, 4096).unwrap()
        else {
            panic!("the lock is free again");
        };
        assert_eq!(all, b"first-second-third");
        assert_eq!(
            live_watermark_in(&dir, Stream::Stdout, "unit"),
            Some(all.len() as u64)
        );
    }

    #[test]
    fn a_handle_nobody_opened_is_absent_rather_than_an_error() {
        let dir = scratch_live("absent");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            read_live_in(&dir, Stream::Stdout, "never", 0, 16).unwrap(),
            LiveRead::Absent
        );
        assert_eq!(live_watermark_in(&dir, Stream::Stdout, "never"), None);
    }

    #[test]
    fn reopening_a_spool_keeps_what_is_already_in_it() {
        // The one case `reopen` exists for: a drain that hit its deadline leaves
        // the tee thread holding the spool, so the caller takes a second handle
        // instead of waiting. If that handle truncated, a timed-out drain would
        // seal an empty capture over a run that produced output.
        let dir = scratch_live("reopen");
        let mut spool = Spool::open_in(&dir, Stream::Stdout, "unit").unwrap();
        spool.commit(b"kept").unwrap();
        let mut second = spool.reopen().unwrap();
        second.commit(b"-more").unwrap();
        let LiveRead::Bytes(seen) = read_live_in(&dir, Stream::Stdout, "unit", 0, 4096).unwrap()
        else {
            panic!("nothing else holds this lock");
        };
        assert_eq!(seen, b"kept-more");
    }

    #[test]
    fn a_handle_names_the_stream_and_the_digest() {
        let capture = Capture {
            stream: "stdout",
            bytes: 3,
            digest: "abc".to_owned(),
        };
        assert_eq!(capture.handle(), "stdout:abc");
    }

    #[test]
    fn the_same_bytes_on_two_streams_are_two_identities() {
        // A program that wrote the same text to both streams must not collapse
        // into one record, or a predicate scoped to stderr would match stdout.
        let out = identity::capture_fingerprint(Stream::Stdout.as_str(), b"same");
        let err = identity::capture_fingerprint(Stream::Stderr.as_str(), b"same");
        assert_ne!(out.to_hex(), err.to_hex());
    }

    #[test]
    fn the_digest_is_a_pure_function_of_the_bytes() {
        let first = identity::capture_fingerprint("stdout", b"hello\n");
        let second = identity::capture_fingerprint("stdout", b"hello\n");
        assert_eq!(first.to_hex(), second.to_hex());
        assert_ne!(
            first.to_hex(),
            identity::capture_fingerprint("stdout", b"hello").to_hex(),
            "a trailing newline is a different output, so it is a different capture"
        );
    }

    // --- navigation (CLOUD-121) ---------------------------------------------

    fn handle() -> Handle {
        Handle {
            stream: Stream::Stdout,
            digest: "abc123".to_owned(),
        }
    }

    /// Four lines, so a clamp has something to clamp against.
    const LOG: &[u8] = b"first\nsecond warning[duplicate] here\nthird\nfourth\n";

    #[test]
    fn a_handle_round_trips_through_its_text() {
        for capture in [Stream::Stdout, Stream::Stderr] {
            let text = format!("{}:deadbeef", capture.as_str());
            let parsed = Handle::parse(&text).expect("a well-formed handle parses");
            assert_eq!(parsed.stream, capture);
            assert_eq!(parsed.to_string(), text);
        }
    }

    #[test]
    fn a_malformed_handle_is_a_usage_error_never_a_path() {
        // The digest becomes a path component, so the parser refusing anything
        // that is not hex is what stops a separator or a `..` travelling there.
        // Shape-checking here rather than sanitising at each call site is what
        // makes that a property instead of a habit.
        for bad in [
            "nocolon",
            "stdin:abc",
            "stdout:",
            "stdout:../../etc/passwd",
            "stdout:not hex",
            ":abc",
        ] {
            let err = Handle::parse(bad).expect_err("{bad} is not a handle");
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{bad} should be a usage error"
            );
        }
    }

    #[test]
    fn the_default_selection_is_the_pointer_not_the_payload() {
        // Content is something a caller names. An unqualified `show` answers with
        // the shape that costs nothing, which is what keeps the cheap path cheap.
        let answer = select(&handle(), LOG, &Selection::Summary);
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4);
        assert_eq!(answer.bytes, LOG.len() as u64);
        assert_eq!(answer.handle, "stdout:abc123");
    }

    #[test]
    fn a_line_range_is_one_indexed_and_inclusive() {
        let answer = select(&handle(), LOG, &Selection::Lines { from: 2, to: 3 });
        assert_eq!(
            answer
                .selected
                .iter()
                .map(|line| line.number)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(answer.selected[0].text, "second warning[duplicate] here");
    }

    #[test]
    fn a_range_past_the_end_is_clamped_rather_than_refused() {
        // Widening a window is the whole point of a handle. An agent asking for
        // 1:5000 of a 4-line log wants the log — refusing would send it back to
        // guessing, which is the behaviour this deletes.
        let answer = select(&handle(), LOG, &Selection::Lines { from: 1, to: 5000 });
        assert_eq!(answer.selected.len(), 4);
        assert_eq!(answer.selected[3].number, 4);
    }

    #[test]
    fn an_inverted_range_selects_nothing_rather_than_panicking() {
        // A reachable path, since the range comes from an agent's argv, and the
        // workspace lints forbid panicking on one.
        let answer = select(&handle(), LOG, &Selection::Lines { from: 5, to: 2 });
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4, "the capture is still described");
    }

    #[test]
    fn grep_numbers_the_lines_it_matched() {
        // The number is what makes the next call possible: grep, read 2, then ask
        // for a window around it — navigation rather than a second guess.
        let answer = select(
            &handle(),
            LOG,
            &Selection::Grep {
                needle: "warning[duplicate]".to_owned(),
            },
        );
        assert_eq!(answer.selected.len(), 1);
        assert_eq!(answer.selected[0].number, 2);
    }

    #[test]
    fn grep_matching_nothing_is_an_answer_not_an_error() {
        let answer = select(
            &handle(),
            LOG,
            &Selection::Grep {
                needle: "absent".to_owned(),
            },
        );
        assert!(answer.selected.is_empty());
        assert_eq!(answer.lines, 4);
    }

    #[test]
    fn a_trailing_newline_mints_no_empty_last_line() {
        assert_eq!(select(&handle(), b"a\nb\n", &Selection::Summary).lines, 2);
        assert_eq!(select(&handle(), b"a\nb", &Selection::Summary).lines, 2);
        assert_eq!(select(&handle(), b"", &Selection::Summary).lines, 0);
    }

    #[test]
    fn invalid_utf8_is_still_navigable() {
        // A capture holds whatever a program wrote. Refusing to show line 2
        // because byte 3 is invalid would send the caller back to re-running.
        let answer = select(&handle(), b"ok\n\xff\xfe bad\ntail\n", &Selection::Summary);
        assert_eq!(answer.lines, 3);
        assert_eq!(answer.bytes, 15);
    }

    #[test]
    fn an_empty_stream_still_has_an_identity() {
        // Zero bytes is a real answer — "the command said nothing" — and it must
        // be distinguishable from a run that was never captured.
        let empty = identity::capture_fingerprint("stdout", b"");
        assert_eq!(empty.to_hex().len(), 64);
        assert_ne!(
            empty.to_hex(),
            identity::capture_fingerprint("stderr", b"").to_hex()
        );
    }
}
