//! Crash-only file writes: the one place this crate mutates a file (CLOUD-1919).
//!
//! # The property
//!
//! A write interrupted at ANY point — a crash, a kill, a reboot, a second writer
//! arriving mid-record — leaves either the previous state or the new one, and
//! never a torn one. A reader that then refuses a torn record is doing its job,
//! so the defect is always the writer's, and this module is where writers stop
//! being able to commit it.
//!
//! Measured on 2026-09-27, in a host's session transcript: two of 21,179 lines
//! each held one record cut mid-string with a second record spliced into it —
//! two appenders interleaving between the `write(2)` calls of one line. The host
//! wrote that file, but this crate had the same shape in its own appenders.
//!
//! # The operations
//!
//! * [`append`] — the complete record in ONE `write(2)` on an `O_APPEND` handle,
//!   then `fsync`. On a local filesystem the kernel positions and writes a single
//!   append as one unit, so a concurrent appender lands before or after it, never
//!   inside. `writeln!` on an unbuffered [`std::fs::File`] is NOT that: it may
//!   issue one write per format piece.
//! * [`replace`] — write a sibling temp file, `fsync` it, `rename` it over the
//!   target, then `fsync` the directory so the rename itself survives a crash.
//!   `rename` within one directory is atomic, so a reader sees the old file or
//!   the new one. `fs::write` truncates first and is neither.
//!
//! Both are synced before returning: persist-before-emit, so a caller that reports
//! a record as written has it on disk rather than in a page cache a reboot drops.
//!
//! Beside them, two crate-private, unsynced ones: `create_empty` makes a zero-byte
//! mark whose time is its meaning, and `open_handle` opens a file or directory
//! for its lock or its times.
//!
//! # Enforced, not remembered
//!
//! `path write unsafe` (`policy/durable-write.rego`) refuses `fs::write(`,
//! `File::create(` and `.append(true)` anywhere in this crate's source outside
//! this file, unless the line is marked `// stream:` — a child process's output
//! sink, which is a stream being captured rather than state being committed.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Whether a write waits for the disk before returning (CLOUD-2315).
///
/// **BOTH TIERS ARE CRASH-ONLY AGAINST A PROCESS.** A temp file published by
/// `rename` or `link` is complete before it has a name, so a killed writer
/// leaves the old state or the new one whatever this says. `Synced` adds the one
/// thing `Atomic` lacks: the record survives the MACHINE going down, because
/// `fsync` put it on the disk rather than in a page cache.
///
/// **`Atomic` IS FOR A RECORD WHOSE LOSS ON POWER FAILURE COSTS NOTHING**, and
/// only on the per-call hook path, where `fsync` is a latency lottery: measured
/// 2026-10-15 on one container, the same capture's sync took 0.09 ms on one call
/// and 211 ms on the next, depending on what else the disk was flushing. A
/// sighting marker that is lost re-explains a class once; a hook's copy of a
/// tool response is lost only with the session whose transcript holds it.
/// Neither is reported to anyone as written, so persist-before-emit has nothing
/// to protect there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persist {
    /// `fsync` the file (and a published name's directory) before returning.
    Synced,
    /// Publish atomically and return without waiting for the disk.
    Atomic,
}

impl Persist {
    /// `fsync` `file` at the `Synced` tier; nothing at `Atomic`. The one
    /// spelling of the tier for a file, so a third tier changes one place.
    ///
    /// # Errors
    ///
    /// The I/O error a sync returns.
    pub fn sync(self, file: &std::fs::File) -> std::io::Result<()> {
        match self {
            Persist::Synced => {
                #[cfg(test)]
                synced::file();
                file.sync_all()
            }
            Persist::Atomic => Ok(()),
        }
    }

    /// `fsync` `directory` at the `Synced` tier, best-effort, as
    /// [`sync_directory`]; nothing at `Atomic`.
    fn sync_dir(self, directory: &Path) {
        if self == Persist::Synced {
            sync_directory(directory);
        }
    }
}

/// Append whole lines to `path` as ONE write, then sync.
///
/// `text` is one or more lines; a missing trailing newline is supplied, so a
/// caller cannot leave the next append glued to its last line. The file is
/// created if absent; its directory must exist.
///
/// # Errors
///
/// Returns the I/O error when the file cannot be opened, written, or synced.
pub fn append(path: &Path, text: &str) -> std::io::Result<()> {
    let mut buffer = String::with_capacity(text.len() + 1);
    buffer.push_str(text);
    if !buffer.ends_with('\n') {
        buffer.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(buffer.as_bytes())?;
    file.sync_all()
}

//MUTANT-SUITE crates/batten/src/durable.rs
//MUTANT torn-tail-kept|s@^        if last\[0\] != b'\\n' {$@        if false {@|a_torn_tail_is_dropped_before_the_next_append
/// [`append`] to a LINE store, first dropping a torn tail the file ends with.
///
/// **A torn tail survives only until the next append, unless something drops
/// it** (CLOUD-843, round-2 review). A process killed mid-`write` leaves a final
/// fragment with no newline, and a line reader drops it — but `O_APPEND` writes
/// the next record straight after it, so the two become ONE terminated line: a
/// torn `x … land-stopped` glued to the next container's `h …` reads back as a
/// whole `x` under the old boot, and swallows the new record too. Truncating to
/// the last newline first makes the disk agree with what every reader already
/// discards, so a fragment can never be promoted into a record.
///
/// Only a store with ONE writer per file may use it: the truncation and the
/// append are two operations, and a second writer landing between them would
/// lose its record. The tail is read only when the last byte is not a newline, so
/// the common case costs one one-byte read.
///
/// # Errors
///
/// Returns the I/O error when the file cannot be opened, read, truncated,
/// written, or synced.
pub fn append_whole_lines(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut buffer = String::with_capacity(text.len() + 1);
    buffer.push_str(text);
    if !buffer.ends_with('\n') {
        buffer.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    let len = file.metadata()?.len();
    if len > 0 {
        let mut last = [0_u8; 1];
        file.seek(SeekFrom::Start(len - 1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            let mut bytes = Vec::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut bytes)?;
            let whole = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |at| at + 1);
            // THROUGH A WRITE HANDLE OF ITS OWN: Windows grants an append-only
            // handle FILE_APPEND_DATA and not FILE_WRITE_DATA, so truncating
            // through `file` is access-denied there. The append itself stays on
            // `file`, so every write still lands at the end. `tests/it/truncate_handle.rs`
            // holds every `set_len` in the crates to this shape (CLOUD-2055).
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)?
                .set_len(u64::try_from(whole).unwrap_or(0))?;
        }
    }
    file.write_all(buffer.as_bytes())?;
    file.sync_all()
}

/// [`append`], creating the file with `mode` on unix when it does not exist.
///
/// For a ledger whose first byte must already be private: a file created at the
/// umask's default and narrowed afterwards is readable in between.
///
/// # Errors
///
/// Returns the I/O error when the file cannot be opened, written, or synced.
pub fn append_with_mode(path: &Path, text: &str, mode: u32) -> std::io::Result<()> {
    append_with_mode_as(path, text, mode, Persist::Synced)
}

/// [`append_with_mode`] at a chosen [`Persist`] tier. The record is still ONE
/// `write(2)` on an `O_APPEND` handle, so concurrent appenders never interleave;
/// `Atomic` only skips the wait for the disk.
///
/// # Errors
///
/// Returns the I/O error when the file cannot be opened, written, or synced.
pub fn append_with_mode_as(
    path: &Path,
    text: &str,
    mode: u32,
    persist: Persist,
) -> std::io::Result<()> {
    let mut buffer = String::with_capacity(text.len() + 1);
    buffer.push_str(text);
    if !buffer.ends_with('\n') {
        buffer.push('\n');
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(buffer.as_bytes())?;
    persist.sync(&file)
}

/// Replace `path`'s contents atomically: temp, sync, rename, sync the directory.
///
/// **A symlinked target is resolved first**, so the link survives and its target
/// is what changes — renaming over the link itself would silently replace a link
/// with a file. **An existing file's permission bits are kept**, so a `0600`
/// secret or an executable hook does not come back with the umask's defaults.
///
/// # Errors
///
/// Returns the I/O error when the temp file cannot be created, written, synced
/// or renamed into place. The temp file is removed on every failure path.
pub fn replace(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    replace_as(path, contents, Persist::Synced)
}

/// [`replace`] at a chosen [`Persist`] tier: a reader still sees the old file or
/// the new one, never a torn one; `Atomic` only skips the wait for the disk.
///
/// # Errors
///
/// As [`replace`].
pub fn replace_as(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    persist: Persist,
) -> std::io::Result<()> {
    let target = resolve(path.as_ref());
    let directory = directory_of(&target);
    let temp = temp_beside(&target);
    let written = write_temp_as(&temp, &target, contents.as_ref(), persist)
        .and_then(|()| std::fs::rename(&temp, &target));
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }
    persist.sync_dir(&directory);
    Ok(())
}

/// Create `path` holding `contents` only if nothing is there yet: `true` when
/// this call created it, `false` when it already existed (CLOUD-2145).
///
/// THE EXISTENCE TEST AND THE WRITE ARE ONE OPERATION, which is the whole point:
/// a check-then-write lets two concurrent callers both see "absent" and both
/// claim the first. The contents go to a synced temp beside the target, and a
/// hard link publishes it — `link(2)` fails with `AlreadyExists` when the name
/// is taken, so exactly one caller wins, and the winner's file is never torn
/// because it was complete before it had a name.
///
/// # Errors
///
/// Any I/O error other than the target already existing; the temp file is
/// removed on every path.
//MUTANT exclusive-create-overwrites|s@^        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),$@        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(true),@|exactly_one_of_many_concurrent_creators_wins
pub fn create_exclusive(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<bool> {
    create_exclusive_as(path, contents, Persist::Synced)
}

/// [`create_exclusive`] at a chosen [`Persist`] tier: exactly one concurrent
/// caller still wins, and the winner's file is still complete before it has a
/// name; `Atomic` only skips the wait for the disk.
///
/// # Errors
///
/// Any I/O error other than the target already existing; the temp file is
/// removed on every path.
pub fn create_exclusive_as(
    path: &Path,
    contents: impl AsRef<[u8]>,
    persist: Persist,
) -> std::io::Result<bool> {
    let directory = directory_of(path);
    let temp = temp_beside(path);
    let linked = write_temp_as(&temp, path, contents.as_ref(), persist)
        .and_then(|()| std::fs::hard_link(&temp, path));
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => {
            persist.sync_dir(&directory);
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

/// Create `path` empty, failing when anything already has the name.
///
/// For a zero-byte MARK whose time carries its meaning: with no contents there
/// is nothing to tear, so it needs neither [`create_exclusive`]'s temp nor its
/// hard link, and works on a filesystem without links.
///
/// # Errors
///
/// `AlreadyExists` when the name is taken, else any I/O error.
//MUTANT empty-mark-overwrites|s@^    std::fs::File::create_new(path).map(drop)$@    std::fs::File::create(path).map(drop)@|an_empty_mark_is_made_once
pub(crate) fn create_empty(path: &Path) -> std::io::Result<()> {
    std::fs::File::create_new(path).map(drop)
}

/// `path`, file or directory, opened for its lock or its times.
///
/// WINDOWS OPENS A DIRECTORY ONLY WITH BACKUP SEMANTICS and writes times only
/// through a handle opened for writing; measured on #1132's `windows` job, a
/// plain `File::open` locked no directory and set no time (the rule `perf.rs`'s
/// sibling stamp records). Elsewhere a read-only handle does both, and is the
/// only handle a directory takes.
pub(crate) fn open_handle(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path)
    }
}

/// The directory whose entry a write to `path` creates: its parent, or `.` for a
/// bare name, whose parent is the empty path no directory handle opens.
fn directory_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The file a write should land on: a symlink's target, else the path itself.
fn resolve(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// A temp name in the target's own directory, unique to this process and moment,
/// so a rename never crosses a filesystem and two writers never share a temp.
///
/// The per-process sequence is what makes it unique within a process. The clock
/// alone did not: macOS `SystemTime` ticks in microseconds, so two threads of one
/// process drew the same name, and one writer's `create_new` or cleanup hit the
/// other's temp — `exactly_one_of_many_concurrent_creators_wins` red on macOS CI.
fn temp_beside(target: &Path) -> PathBuf {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    temp_name(target, std::process::id(), nanos, sequence)
}

/// The temp name for one draw: process, instant and sequence, so a name repeats
/// only if all three do.
//MUTANT temp-name-ignores-sequence|s@^    target.with_file_name(format!(".{name}.{pid}.{nanos}.{sequence}.tmp"))$@    target.with_file_name(format!(".{name}.{pid}.{nanos}.tmp"))@|two_draws_in_one_instant_get_two_names
fn temp_name(target: &Path, pid: u32, nanos: u128, sequence: u64) -> PathBuf {
    let name = target
        .file_name()
        .map_or_else(|| "file".into(), |name| name.to_string_lossy().into_owned());
    target.with_file_name(format!(".{name}.{pid}.{nanos}.{sequence}.tmp"))
}

/// Whether a file name is one of [`temp_name`]'s: a write in flight, or one a
/// kill stranded between its sync and its rename, never the target itself. A
/// reader listing a directory these writes land in skips it. The leading dot is
/// the mark: `temp_name` always draws one, and a target named with one is not a
/// target these writes serve.
#[must_use]
pub(crate) fn is_temp(name: &str) -> bool {
    name.starts_with('.')
}

fn write_temp_as(
    temp: &Path,
    target: &Path,
    contents: &[u8],
    persist: Persist,
) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)?;
    if let Ok(existing) = std::fs::metadata(target) {
        file.set_permissions(existing.permissions())?;
    }
    file.write_all(contents)?;
    persist.sync(&file)
}

/// Sync the directory entry a rename created, so the rename survives a crash.
///
/// Best-effort and unix-only: Windows has no directory handle to sync, and a
/// failure here leaves a fully written file whose NAME may not yet be durable —
/// strictly better than the torn file this module exists to prevent.
fn sync_directory(directory: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(directory) {
        #[cfg(test)]
        synced::directory();
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = directory;
}

/// What this thread asked the disk to sync, for a case to read (CLOUD-2509).
///
/// THE SEAM FOR A CALL WHOSE EFFECT IS ONLY VISIBLE AFTER POWER LOSS. A sync
/// that was skipped leaves the same bytes in the page cache as one that ran, so
/// no read of the file can tell them apart; the call is the observable, and a
/// count of calls is what a case asserts. Test-only and per thread, so the
/// production path carries nothing and parallel cases never see each other's.
#[cfg(test)]
pub(crate) mod synced {
    use std::cell::Cell;

    thread_local! {
        static FILES: Cell<u64> = const { Cell::new(0) };
        static DIRECTORIES: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn file() {
        FILES.with(|count| count.set(count.get() + 1));
    }

    #[cfg(unix)]
    pub(super) fn directory() {
        DIRECTORIES.with(|count| count.set(count.get() + 1));
    }

    /// `(files, directories)` synced on this thread so far.
    pub(crate) fn counts() -> (u64, u64) {
        (FILES.with(Cell::get), DIRECTORIES.with(Cell::get))
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be written is a broken test, not a reachable path"
)]
mod tests {
    use super::*;

    /// A directory under the crate's shared scratch root, which a later run reaps
    /// once this process is gone, rather than one more loose `/tmp` entry per run.
    fn scratch(name: &str) -> PathBuf {
        let dir = crate::scratch::scratch(&format!("durable-{name}"));
        assert!(dir.is_dir(), "scratch");
        dir
    }

    /// CLOUD-2509: the tier decides which syncs are ASKED FOR, which is all a
    /// case can see of a sync — its effect shows only after power loss. Fails
    /// by: `Synced` skipping the file's or the directory's sync, or `Atomic`
    /// paying for either.
    #[test]
    fn only_the_synced_tier_asks_the_disk() {
        let dir = scratch("tiers");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("record"))
            .expect("the record opens");
        let before = synced::counts();
        Persist::Atomic
            .sync(&file)
            .expect("an atomic sync is nothing");
        Persist::Atomic.sync_dir(&dir);
        assert_eq!(synced::counts(), before, "Atomic waits for no disk");
        Persist::Synced.sync(&file).expect("the file syncs");
        Persist::Synced.sync_dir(&dir);
        // A directory has a handle to sync only on unix.
        let directories = u64::from(cfg!(unix));
        assert_eq!(
            synced::counts(),
            (before.0 + 1, before.1 + directories),
            "Synced syncs the file and its directory"
        );
    }

    /// THE GLUE CASE (CLOUD-843, round-2 review): a fragment a killed writer left
    /// must not become the head of the next record. Plain [`append`] glues them;
    /// this drops the fragment, keeps every whole line, and appends whole.
    #[test]
    fn a_torn_tail_is_dropped_before_the_next_append() {
        let dir = scratch("torn-tail");
        let path = dir.join("shard.jsonl");
        std::fs::write(&path, "h 1400 1500\nx 1600 1500 land-st").expect("plant a torn tail");
        append_whole_lines(&path, "h 2100 2000").expect("append");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "h 1400 1500\nh 2100 2000\n",
            "the fragment is gone and the new record stands alone"
        );
        // A tail that is all fragment leaves nothing before the new record, and a
        // whole file is appended to untouched.
        std::fs::write(&path, "x 16").expect("plant a lone fragment");
        append_whole_lines(&path, "h 1").expect("append");
        append_whole_lines(&path, "h 2").expect("append");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "h 1\nh 2\n");
    }

    /// Fails by: a first append to an empty store probing a tail it does not
    /// have, or the mode-taking append writing nothing.
    #[test]
    fn a_first_append_writes_one_whole_line() {
        let dir = scratch("first-append");
        let lines = dir.join("lines");
        std::fs::write(&lines, "").expect("an empty store");
        append_whole_lines(&lines, "h 1").expect("append");
        assert_eq!(std::fs::read_to_string(&lines).expect("read"), "h 1\n");
        let ledger = dir.join("ledger");
        append_with_mode(&ledger, "one", 0o600).expect("append");
        assert_eq!(std::fs::read_to_string(&ledger).expect("read"), "one\n");
    }

    /// Fails by: a creation that failed for any reason but the name being
    /// taken reported as "someone else created it".
    #[test]
    fn an_exclusive_create_that_cannot_write_is_an_error() {
        let dir = scratch("exclusive-missing");
        let refused = create_exclusive(&dir.join("absent").join("mark"), "x");
        assert!(refused.is_err(), "{refused:?}");
    }

    /// Fails by: a bare name synced through the empty path, which opens nothing.
    #[test]
    fn a_bare_name_lives_in_the_current_directory() {
        assert_eq!(directory_of(Path::new("file")), PathBuf::from("."));
        assert_eq!(directory_of(Path::new("dir/file")), PathBuf::from("dir"));
    }

    /// Fails by: a regular file resolved as a link would be, so a write lands
    /// on its canonical spelling rather than the path the caller named.
    #[test]
    fn only_a_symlink_is_resolved() {
        let dir = scratch("resolve");
        std::fs::create_dir_all(dir.join("sub")).expect("sub");
        std::fs::write(dir.join("file"), "x").expect("file");
        let named = dir.join("sub").join("..").join("file");
        assert_eq!(resolve(&named), named);
    }

    /// An empty mark is made once: a second creation is `AlreadyExists`, which a
    /// caller reads as "someone else marked it" (CLOUD-2361).
    #[test]
    fn an_empty_mark_is_made_once() {
        let dir = scratch("empty");
        let path = dir.join("used");
        create_empty(&path).expect("the first creation");
        assert_eq!(std::fs::metadata(&path).expect("made").len(), 0);
        let again = create_empty(&path).expect_err("the name is taken");
        assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
    }

    /// `#MUTANT exclusive-create-overwrites` reddens here: of many threads racing
    /// to create one name, exactly one is told it created it, and its contents
    /// are what the file holds.
    #[test]
    fn exactly_one_of_many_concurrent_creators_wins() {
        let dir = scratch("exclusive");
        let path = dir.join("mark");
        let winners: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|n| {
                    let path = &path;
                    scope.spawn(move || {
                        create_exclusive(path, format!("writer {n}")).expect("create")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().expect("join")))
                .sum()
        });
        assert_eq!(winners, 1, "one creator, however many raced");
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .starts_with("writer "),
            "the winner's contents, whole"
        );
        assert!(
            !create_exclusive(&path, "late").expect("create"),
            "a later caller sees it taken"
        );
        assert_eq!(
            std::fs::read_dir(&dir).expect("list").count(),
            1,
            "no temp file survives"
        );
    }

    /// THE UNSYNCED TIER KEEPS EVERY PROPERTY BUT THE WAIT (CLOUD-2315): one
    /// winner among racing creators, the winner's bytes whole, no temp left, and
    /// an append that lands as one line. Only the disk sync is dropped.
    #[test]
    fn the_atomic_tier_keeps_exclusivity_and_whole_records() {
        let dir = scratch("atomic-tier");
        let path = dir.join("mark");
        let winners: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|n| {
                    let path = &path;
                    scope.spawn(move || {
                        create_exclusive_as(path, format!("writer {n}"), Persist::Atomic)
                            .expect("create")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().expect("join")))
                .sum()
        });
        assert_eq!(winners, 1, "one creator, however many raced");
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .starts_with("writer "),
            "the winner's contents, whole"
        );
        assert_eq!(
            std::fs::read_dir(&dir).expect("list").count(),
            1,
            "no temp file survives"
        );
        let log = dir.join("log");
        append_with_mode_as(&log, "one", 0o600, Persist::Atomic).expect("append");
        append_with_mode_as(&log, "two\n", 0o600, Persist::Atomic).expect("append");
        assert_eq!(
            std::fs::read_to_string(&log).expect("read"),
            "one\ntwo\n",
            "each append is one terminated line"
        );
    }

    /// The macOS case, made deterministic: one process, one clock reading, two
    /// draws. Only the sequence can tell them apart.
    #[test]
    fn two_draws_in_one_instant_get_two_names() {
        let target = Path::new("dir/mark");
        assert_ne!(
            temp_name(target, 7, 1_000, 0),
            temp_name(target, 7, 1_000, 1),
            "same process, same instant, different draw"
        );
    }

    /// `is_temp` recognises every name `temp_name` draws, and not the target.
    #[test]
    fn a_drawn_temp_is_recognised_and_its_target_is_not() {
        let target = Path::new("dir/4242");
        let temp = temp_name(target, 7, 1_000, 0);
        let drawn = temp.file_name().and_then(std::ffi::OsStr::to_str);
        assert_eq!(drawn.map(is_temp), Some(true));
        assert!(!is_temp("4242"));
    }

    #[test]
    fn replace_leaves_no_temp_and_the_new_contents() {
        let dir = scratch("replace");
        let path = dir.join("state");
        replace(&path, "old\n").expect("first");
        replace(&path, "new\n").expect("second");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new\n");
        let leftovers = std::fs::read_dir(&dir).expect("list").count();
        assert_eq!(leftovers, 1, "no temp file survives a successful replace");
    }

    #[test]
    fn replace_keeps_the_permission_bits() {
        // Compiled everywhere; the mode assertion is unix's, since Windows has
        // no mode bits to keep.
        let dir = scratch("mode");
        let path = dir.join("secret");
        replace(&path, "a").expect("create");
        #[cfg(not(unix))]
        {
            replace(&path, "b").expect("replace");
            assert_eq!(std::fs::read_to_string(&path).expect("read"), "b");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            replace(&path, "b").expect("replace");
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn replace_through_a_symlink_writes_the_target_and_keeps_the_link() {
        // Compiled everywhere; creating a symlink needs privileges Windows does
        // not grant by default, so the link half runs where links are ordinary.
        let dir = scratch("link");
        let real = dir.join("real");
        replace(&real, "a").expect("create");
        #[cfg(not(unix))]
        assert_eq!(std::fs::read_to_string(&real).expect("read"), "a");
        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&real, &link).expect("symlink");
            replace(&link, "b").expect("replace");
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("lstat")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(std::fs::read_to_string(&real).expect("read"), "b");
        }
    }

    #[test]
    fn concurrent_appends_never_interleave_inside_a_line() {
        // THE DISCRIMINATING CASE. Long lines, many writers: a `writeln!` split
        // across writes tears here; one `write(2)` per record does not.
        let dir = scratch("append");
        let path = dir.join("log.jsonl");
        let line = |writer: usize, n: usize| {
            format!(
                "{{\"w\":{writer},\"n\":{n},\"pad\":\"{}\"}}",
                "x".repeat(2000)
            )
        };
        let handles: Vec<_> = (0..8)
            .map(|writer| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for n in 0..50 {
                        append(&path, &line(writer, n)).expect("append");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("writer");
        }
        let body = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 400);
        for record in lines {
            assert!(
                record.starts_with("{\"w\":")
                    && record.ends_with("\"}")
                    && record.matches("{\"w\":").count() == 1,
                "a torn line: {}",
                &record[..record.len().min(80)]
            );
        }
    }
}
