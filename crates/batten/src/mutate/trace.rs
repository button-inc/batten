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
    if !cfg!(target_os = "linux") || traced_already() {
        return None;
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("strace"))
            .find(|candidate| candidate.is_file())
            .map(|found| found.to_string_lossy().into_owned())
    })
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
        if let Some(resolved) = line
            .rsplit_once(") = ")
            .and_then(|(_, result)| result.split_once('<'))
            .and_then(|(_, rest)| rest.strip_suffix('>'))
        {
            out.push(lexical(Path::new(resolved)));
        }
        if let Some(open) = line.find('(')
            && !line[..open].contains("<...")
            && let Some(quote) = line[open..].find('"')
        {
            let argument = unquote(&line[open + quote + 1..])?;
            let path = Path::new(&argument);
            if path.is_absolute() {
                out.push(lexical(path));
            } else {
                let base = line[open + 1..open + quote]
                    .split_once('<')
                    .and_then(|(_, rest)| rest.split_once('>'))
                    .map(|(dir, _)| PathBuf::from(dir))
                    .or_else(|| cwd.map(Path::to_path_buf))?;
                out.push(lexical(&base.join(path)));
            }
        }
    }
    Some(out)
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

/// A strace string argument up to its closing quote, or `None` for an escape
/// other than `\"` and `\\`, or a string strace cut short.
pub(crate) fn unquote(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return (!chars.as_str().starts_with("...")).then_some(out),
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
}
