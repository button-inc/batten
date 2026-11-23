//! The one syscall tracer (CLOUD-2784): `strace` on Linux, shared by the
//! mutant schema's reach recorder and `batten step run`'s trace lint.
//!
//! Moved out of `schema.rs` so the two callers cannot drift into two tracers
//! with two argvs. What each KEEPS of a trace is its own rule: the reach
//! recorder gives up on any `.git` read and drops `target/`; the step lint
//! drops the git dir, paths outside the worktree and git-ignored paths. The
//! reading both share is [`touched`].

use std::path::{Path, PathBuf};

/// The syscall tracer a case's file reads are recorded with, where the host
/// has one: `strace` on Linux. Elsewhere no case is traced, and each keys on
/// every non-Rust file, which is the sound answer, not a cheaper one.
#[must_use]
pub fn tracer() -> Option<String> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let record = std::env::var_os(super::schema::RECORD).map(PathBuf::from);
    if refused(traced_already(), record.as_deref()) {
        return None;
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("strace"))
            .find(|candidate| candidate.is_file())
            .map(|found| found.to_string_lossy().into_owned())
    })
}

/// The file a case's reach record holds once a process in the case asked for
/// a tracer while the recorder's own held it ([`refused`]).
pub const REFUSED: &str = "tracer-refused";

/// Whether a tracer is refused to a process `traced` already; and when it is
/// and the process runs inside a case the reach recorder traces (`record`,
/// the case's record directory), say so there ([`REFUSED`]).
///
/// THE RECORDER'S TRACE MUST NOT CHANGE THE CASE (U3): a case that traces its
/// own work took its untraced branch under reach and its traced one when
/// judged, so the sites reach recorded for it were not the ones a judging run
/// executes. No second tracer can attach under `-f`, so the recorder runs such
/// a case again untraced, which is the branch judging takes.
pub(crate) fn refused(traced: bool, record: Option<&Path>) -> bool {
    if traced && let Some(record) = record {
        let _ = crate::durable::replace(record.join(REFUSED), "");
    }
    traced
}

/// Whether this process is itself under a tracer, which refuses a second one:
/// a sweep run inside another sweep's reach (the schema's own suite does this)
/// records untraced rather than spawning a tracer that cannot attach.
pub(crate) fn traced_already() -> bool {
    crate::fsio::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .is_some_and(|pid| pid.trim() != "0")
    })
}

/// The tracer's argv around one case: every syscall that names a path, in the
/// case and every process it spawns, with each descriptor printed as the path
/// it resolves to. `--seccomp-bpf` stops the case only at those syscalls.
///
/// `-DD` RUNS THE TRACER DETACHED, in its own process group: the case keeps the
/// pid the recorder spawned it with and leads its own group, as it does
/// untraced. Attached, strace led the group and the case was its child, so a
/// case signalling its own group signalled the tracer, and one asserting it
/// leads its group failed (seven baseline failures, #1276). `-q` rather than
/// `-qq` keeps the case's own exit line, which is how the reader knows the
/// detached tracer finished writing ([`trace_whole`]).
pub(crate) fn trace_args(trace: &Path, program: &str, rest: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-DD",
        "--seccomp-bpf",
        "-f",
        "-q",
        "-y",
        "-e",
        "trace=%file,openat2",
        "-o",
    ]
    .map(String::from)
    .to_vec();
    args.push(trace.to_string_lossy().into_owned());
    args.push(String::from("--"));
    args.push(program.to_owned());
    args.extend(rest.iter().cloned());
    args
}

/// Every path a whole trace shows touched, absolute and with `.`/`..` folded,
/// or `None` when the trace cannot be read whole: unfinished, a relative path
/// with no directory to resolve it against, or an escape this reader does not
/// decode. Both the path argument of each syscall and the descriptor it
/// returned (`-y`) count, so a probe that found nothing (`ENOENT`) is a touch.
/// What a caller keeps of them is its own rule.
///
/// A RELATIVE PATH WITH NO DIRECTORY ARGUMENT (`stat("c")`, a shell's `test -e
/// c`) resolves against `cwd`, the directory the traced command started in, but
/// only when no process in the trace changed directory: a `chdir` is in
/// `%file`, so one is seen and the trace then reads as unresolvable. `fchdir`
/// is outside `%file`, a stated gap. With `cwd` absent such a path is
/// unresolvable, the reach recorder's reading.
pub(crate) fn touched(trace: &str, cwd: Option<&Path>) -> Option<Vec<PathBuf>> {
    Some(
        walk(trace, cwd, false)?
            .into_iter()
            .map(|(path, _)| path)
            .collect(),
    )
}

/// How a traced syscall used a path (CLOUD-2786).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Looked at, opened read-only, executed: the bytes were judged, not moved.
    Read,
    /// Created, truncated, opened for writing, removed or renamed over.
    Write,
}

/// Every path a whole trace shows touched, as [`touched`] reads them, each with
/// how it was used — and, for the two-path syscalls ([`TWO_PATHS`]), the second
/// path too, which [`touched`] does not read: the source of a rename is
/// removed and its destination created, so both are writes.
///
/// A LINE IS A WRITE iff its syscall is in [`WRITES`], is in [`TWO_PATHS`], or
/// is an `open`/`openat`/`openat2` naming `O_WRONLY`, `O_RDWR`, `O_CREAT` or
/// `O_TRUNC`. A call strace split across two lines (`<unfinished ...>` and
/// `<... resumed>`) is read line by line: the half holding the flags marks the
/// path or descriptor that half holds, and an open whose flags sit only in the
/// resumed half wrote through the descriptor that half returns.
pub(crate) fn accesses(trace: &str, cwd: Option<&Path>) -> Option<Vec<(PathBuf, Access)>> {
    walk(trace, cwd, true)
}

/// The syscalls that write the one path they name.
const WRITES: [&str; 7] = [
    "creat", "truncate", "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir",
];

/// The syscalls that name two paths and write both.
const TWO_PATHS: [&str; 7] = [
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
];

/// The open flags that make an open a write.
const WRITE_FLAGS: [&str; 4] = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"];

/// The syscall a trace line reports: the word before its `(`, or the name a
/// `<... name resumed>` line carries.
fn syscall(line: &str) -> &str {
    let rest = line
        .split_once(' ')
        .map_or(line, |(_, rest)| rest.trim_start());
    rest.strip_prefix("<... ").map_or_else(
        || rest.split('(').next().unwrap_or_default(),
        |resumed| resumed.split(' ').next().unwrap_or_default(),
    )
}

/// How the syscall on `line` uses the paths it names.
fn access_of(line: &str) -> Access {
    let name = syscall(line);
    let opens = matches!(name, "open" | "openat" | "openat2")
        && WRITE_FLAGS.iter().any(|flag| line.contains(flag));
    if opens || WRITES.contains(&name) || TWO_PATHS.contains(&name) {
        Access::Write
    } else {
        Access::Read
    }
}

/// The walk [`touched`] and [`accesses`] share; `second` reads the second path
/// of a [`TWO_PATHS`] syscall.
fn walk(trace: &str, cwd: Option<&Path>, second: bool) -> Option<Vec<(PathBuf, Access)>> {
    if !trace_whole(trace) {
        return None;
    }
    let cwd = cwd.filter(|_| {
        !trace.lines().any(|line| {
            line.split_once(' ')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with("chdir("))
        })
    });
    let mut out = Vec::new();
    for line in trace.lines() {
        if trace_event(line).is_some() {
            continue;
        }
        let access = access_of(line);
        if let Some(resolved) = line
            .rsplit_once(") = ")
            .and_then(|(_, result)| result.split_once('<'))
            .and_then(|(_, rest)| rest.strip_suffix('>'))
        {
            out.push((lexical(Path::new(resolved)), access));
        }
        if let Some(open) = line.find('(')
            && !line[..open].contains("<...")
            && let Some(quote) = line[open..].find('"')
        {
            let (argument, after) = quoted_arg(&line[open + quote + 1..])?;
            out.push((
                resolve(&argument, &line[open + 1..open + quote], cwd)?,
                access,
            ));
            if second
                && TWO_PATHS.contains(&syscall(line))
                && let Some(next) = after.find('"')
            {
                let (argument, _) = quoted_arg(&after[next + 1..])?;
                out.push((resolve(&argument, &after[..next], cwd)?, Access::Write));
            }
        }
    }
    Some(out)
}

/// A traced path argument made absolute: as it is, against the directory
/// descriptor `-y` printed in `before` (the text between the previous argument
/// and this one), or against `cwd`. `None` where none answers.
fn resolve(argument: &str, before: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(argument);
    if path.is_absolute() {
        return Some(lexical(path));
    }
    let base = before
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(dir, _)| PathBuf::from(dir))
        .or_else(|| cwd.map(Path::to_path_buf))?;
    Some(lexical(&base.join(path)))
}

/// The pid a trace line is from and the event it reports, when the line is an
/// exit or signal report (`+++ ... +++`, `--- ... ---`) rather than a syscall.
///
/// THE PID COLUMN IS PADDED: strace prints a short pid left-aligned in a
/// five-wide field (`8638  execve`), so the event starts after however many
/// spaces follow it. Read as one space, no pid under five digits ever matched
/// its exit, every trace read as unfinished, and every case keyed on every file.
pub(crate) fn trace_event(line: &str) -> Option<(&str, &str)> {
    let (pid, rest) = line.split_once(' ')?;
    let rest = rest.trim_start();
    (rest.starts_with("+++ ") || rest.starts_with("--- ")).then_some((pid, rest))
}

/// Whether a trace is whole: its first line is the case's own `execve`, and
/// the same pid's exit is reported. The tracer runs detached ([`trace_args`]),
/// so the case can exit before the tracer has written its last line; and a
/// tracer that could not attach — under another trace, where ptrace is refused
/// — writes no such line while the case runs untraced. Either way the reader
/// has no whole picture, and the case keys on every file.
pub(crate) fn trace_whole(trace: &str) -> bool {
    let Some((root, _)) = trace.lines().next().and_then(|line| line.split_once(' ')) else {
        return false;
    };
    trace.lines().filter_map(trace_event).any(|(pid, event)| {
        pid == root
            && (event.starts_with("+++ exited with ") || event.starts_with("+++ killed by "))
    })
}

/// How long a recorder waits for the detached tracer to finish a case's trace
/// once the case exited. A trace still unfinished at this bound is read as no
/// trace, which keys the case on every file: slower, never unsound.
#[cfg(target_os = "linux")]
pub(crate) const TRACE_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// The trace at `path` once whole, or whatever it holds at [`TRACE_GRACE`].
///
/// WOKEN BY THE TRACER'S CLOSE, NEVER BY A POLL: the watch is placed before the
/// first read, so a close after that read is an event and one before it left a
/// whole trace to read. A wait that could not be set up reads once — a partial
/// trace keys the case on every file, slower and never unsound.
#[cfg(target_os = "linux")]
pub(crate) fn await_trace(path: &Path) -> Option<String> {
    use rustix::fs::inotify;
    let read = || crate::fsio::read_to_string(path).ok();
    let Ok(watch) = inotify::init(inotify::CreateFlags::CLOEXEC) else {
        return read();
    };
    if inotify::add_watch(&watch, path, inotify::WatchFlags::CLOSE_WRITE).is_err() {
        return read();
    }
    let (closed, woken) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut events = [0_u8; 1024];
        while rustix::io::read(&watch, &mut events).is_ok() && closed.send(()).is_ok() {}
    });
    let deadline = std::time::Instant::now() + TRACE_GRACE;
    loop {
        let text = read();
        if text.as_deref().is_some_and(trace_whole) {
            return text;
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || woken.recv_timeout(left).is_err() {
            return read();
        }
    }
}

/// No tracer off Linux, so nothing to wait for.
#[cfg(not(target_os = "linux"))]
pub(crate) fn await_trace(path: &Path) -> Option<String> {
    crate::fsio::read_to_string(path).ok()
}

/// A strace string argument up to its closing quote, with the text after it,
/// or `None` for an escape other than `\"` and `\\`, or a string strace cut
/// short.
fn quoted_arg(text: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let rest = chars.as_str();
                return (!rest.starts_with("...")).then_some((out, rest));
            }
            '\\' => match chars.next()? {
                escaped @ ('"' | '\\') => out.push(escaped),
                _ => return None,
            },
            other => out.push(other),
        }
    }
    None
}

/// `path` with `.` and `..` folded away, without touching the filesystem.
pub(crate) fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::{Path, PathBuf};

    /// A whole trace for pid 7: its `execve`, the given syscall lines, its exit.
    fn whole(lines: &[&str]) -> String {
        let mut out = String::from("7     execve(\"/bin/sh\", [\"sh\"], 0x0 /* 0 vars */) = 0\n");
        for line in lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("7     +++ exited with 0 +++\n");
        out
    }

    // A SHELL PROBE NAMES NO DIRECTORY (CLOUD-2784): `test -e c` is `stat("c")`.
    // With the step's directory it resolves; without one it is unresolvable,
    // the reach recorder's reading.
    #[test]
    fn a_bare_relative_path_resolves_against_the_start_directory() {
        let trace = whole(&["7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)"]);
        assert_eq!(
            super::touched(&trace, Some(Path::new("/repo"))),
            Some(vec![PathBuf::from("/bin/sh"), PathBuf::from("/repo/c")])
        );
        assert_eq!(super::touched(&trace, None), None);
    }

    // A `chdir` anywhere makes the start directory no longer the answer, so the
    // bare path is unresolvable rather than attributed to the wrong place.
    #[test]
    fn a_changed_directory_leaves_a_bare_path_unresolvable() {
        let trace = whole(&[
            "7     chdir(\"sub\") = 0",
            "7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
        ]);
        assert_eq!(super::touched(&trace, Some(Path::new("/repo"))), None);
    }

    /// The accesses of a whole trace of `lines`, run from `/repo`, without the
    /// shell's own `execve`.
    fn accessed(lines: &[&str]) -> Vec<(PathBuf, super::Access)> {
        let mut found = super::accesses(&whole(lines), Some(Path::new("/repo"))).unwrap();
        found.retain(|(path, _)| path != Path::new("/bin/sh"));
        found
    }

    // THE WRITE HAZARD (CLOUD-2786): an open's flags say whether it wrote, on
    // the path it named and on the descriptor it returned.
    #[test]
    fn an_open_for_write_is_a_write() {
        use super::Access::Write;
        for flags in ["O_WRONLY|O_CREAT|O_TRUNC", "O_RDWR", "O_WRONLY|O_APPEND"] {
            assert_eq!(
                accessed(&[&format!(
                    "7     openat(AT_FDCWD</repo>, \"a\", {flags}, 0666) = 3</repo/a>"
                )]),
                vec![
                    (PathBuf::from("/repo/a"), Write),
                    (PathBuf::from("/repo/a"), Write)
                ],
                "{flags}"
            );
        }
        // A call split by another thread's syscall: the flags in the resumed
        // half mark the descriptor that half returns.
        assert!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"b\" <unfinished ...>",
                "7     <... openat resumed>, O_CREAT|O_WRONLY, 0644) = 4</repo/b>",
            ])
            .contains(&(PathBuf::from("/repo/b"), Write))
        );
    }

    #[test]
    fn an_open_read_only_is_a_read() {
        use super::Access::Read;
        assert_eq!(
            accessed(&["7     openat(AT_FDCWD</repo>, \"a\", O_RDONLY|O_CLOEXEC) = 3</repo/a>"]),
            vec![
                (PathBuf::from("/repo/a"), Read),
                (PathBuf::from("/repo/a"), Read)
            ]
        );
        assert_eq!(
            accessed(&["7     newfstatat(AT_FDCWD</repo>, \"c\", 0x1, 0) = 0"]),
            vec![(PathBuf::from("/repo/c"), Read)],
            "a stat is a read"
        );
    }

    #[test]
    fn an_unlink_is_a_write() {
        use super::Access::Write;
        for line in [
            "7     unlink(\"a\") = 0",
            "7     unlinkat(AT_FDCWD</repo>, \"a\", 0) = 0",
            "7     truncate(\"/repo/a\", 0) = 0",
            "7     mkdir(\"a\", 0777) = 0",
            "7     rmdir(\"a\") = 0",
        ] {
            assert_eq!(
                accessed(&[line]),
                vec![(PathBuf::from("/repo/a"), Write)],
                "{line}"
            );
        }
    }

    // `touched` reads only the first path, so the second is `accesses`' own.
    #[test]
    fn both_paths_of_a_rename_are_writes() {
        use super::Access::Write;
        let rename = "7     renameat2(AT_FDCWD</repo>, \"g\", AT_FDCWD</repo/sub>, \"h\", \
                      RENAME_NOREPLACE) = 0";
        assert_eq!(
            accessed(&[rename]),
            vec![
                (PathBuf::from("/repo/g"), Write),
                (PathBuf::from("/repo/sub/h"), Write)
            ]
        );
        assert_eq!(
            accessed(&["7     rename(\"/repo/g\", \"h\") = 0"]),
            vec![
                (PathBuf::from("/repo/g"), Write),
                (PathBuf::from("/repo/h"), Write)
            ]
        );
        assert_eq!(
            super::touched(&whole(&[rename]), None).unwrap(),
            vec![PathBuf::from("/bin/sh"), PathBuf::from("/repo/g")],
            "the reach reader's reading is unchanged"
        );
    }
}
