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
//! # The two operations
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
//! # Enforced, not remembered
//!
//! `path write unsafe` (`policy/durable-write.rego`) refuses `fs::write(`,
//! `File::create(` and `.append(true)` anywhere in this crate's source outside
//! this file, unless the line is marked `// stream:` — a child process's output
//! sink, which is a stream being captured rather than state being committed.

use std::io::Write as _;
use std::path::{Path, PathBuf};

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
            file.set_len(u64::try_from(whole).unwrap_or(0))?;
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
    file.sync_all()
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
    let target = resolve(path.as_ref());
    let directory = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let temp = temp_beside(&target);
    let written = write_temp(&temp, &target, contents.as_ref())
        .and_then(|()| std::fs::rename(&temp, &target));
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }
    sync_directory(&directory);
    Ok(())
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
fn temp_beside(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map_or_else(|| "file".into(), |name| name.to_string_lossy().into_owned());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    target.with_file_name(format!(".{name}.{}.{nanos}.tmp", std::process::id()))
}

fn write_temp(temp: &Path, target: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)?;
    if let Ok(existing) = std::fs::metadata(target) {
        file.set_permissions(existing.permissions())?;
    }
    file.write_all(contents)?;
    file.sync_all()
}

/// Sync the directory entry a rename created, so the rename survives a crash.
///
/// Best-effort and unix-only: Windows has no directory handle to sync, and a
/// failure here leaves a fully written file whose NAME may not yet be durable —
/// strictly better than the torn file this module exists to prevent.
fn sync_directory(directory: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(directory) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = directory;
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a fixture that cannot be written is a broken test, not a reachable path"
)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("batten-durable-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
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
