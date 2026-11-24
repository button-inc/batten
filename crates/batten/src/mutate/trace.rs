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
    crate::fsio::read_to_string("/proc/self/status").is_ok_and(|status| traced_in(&status))
}

/// Whether a `/proc/<pid>/status` text names a tracer: its `TracerPid` is set
/// and is not `0`. Apart from the read so a case can hand it either answer,
/// whether or not the suite itself runs under one (CLOUD-2789).
fn traced_in(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .is_some_and(|pid| pid.trim() != "0")
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
///
/// THE PROCESS TREE AND `fchdir` ARE TRACED TOO (CLOUD-2789), so each pid's
/// working directory is known ([`Cwds`]): every process cargo starts runs
/// `chdir` to its package before it execs, and when one `chdir` anywhere
/// disabled the start directory for every pid, one relative probe
/// (`access("libgcc_s.so.1")`) left every cargo step's trace unreadable, so
/// `cross-check`, `darwin-link`, `semver` and `enforce-tree` never recorded.
pub(crate) fn trace_args(trace: &Path, program: &str, rest: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "-DD",
        "--seccomp-bpf",
        "-f",
        "-q",
        "-y",
        "-e",
        "trace=%file,openat2,fchdir,clone,clone3,fork,vfork",
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
/// c`) resolves against the working directory of the process that named it, as
/// [`Cwds`] reads it: `cwd` for the traced command, then each `chdir` and
/// `fchdir` a pid made, and a forked pid inheriting its parent's at the fork.
/// Where that cannot be known the path is unresolvable, and with `cwd` absent
/// the root's is, the reach recorder's reading.
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
    /// Opened read-only, executed, a link read: the bytes were judged, not
    /// moved.
    Read,
    /// Asked whether it is there, or a directory listed for its names
    /// ([`PROBES`], an `O_DIRECTORY` open): no file's bytes were read
    /// (CLOUD-2835).
    Probe,
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

/// The syscalls whose FIRST quoted argument is a link's content, not a path
/// (CLOUD-2789): `symlink(target, linkpath)` stores `target` as text and never
/// resolves it, so only `linkpath` is touched. Read as a path, gix's capability
/// probe, `symlink("dangling", "<git dir>/__file_link…")`, wrote `dangling`
/// against the prober's working directory, a file in no tree, and refused
/// `test-replay` and `perf-gate` (#1276).
const LINK_CONTENT: [&str; 2] = ["symlink", "symlinkat"];

/// The open flags that make an open a write.
const WRITE_FLAGS: [&str; 4] = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"];

/// The syscalls that ask whether a path is there, or what it is, and read none
/// of its bytes (CLOUD-2835).
const PROBES: [&str; 12] = [
    "stat",
    "stat64",
    "lstat",
    "lstat64",
    "newfstatat",
    "fstatat64",
    "statx",
    "statfs",
    "statfs64",
    "access",
    "faccessat",
    "faccessat2",
];

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
    } else if PROBES.contains(&name)
        || (matches!(name, "open" | "openat" | "openat2") && line.contains("O_DIRECTORY"))
    {
        Access::Probe
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
    let cwds = Cwds::read(trace, cwd);
    let resumed = resumptions(trace);
    let mut out = Vec::new();
    for (index, line) in trace.lines().enumerate() {
        if trace_event(line).is_some() {
            continue;
        }
        let outcome = resumed.get(&index).copied().unwrap_or(line);
        let pid = line.split(' ').next().unwrap_or_default();
        let cwd = cwds.at(pid, index);
        let cwd = cwd.as_deref();
        let access = access_of(line);
        if let Some(resolved) = result_of(line)
            .and_then(|result| result.split_once('<'))
            .and_then(|(_, rest)| rest.strip_suffix('>'))
        {
            out.push((lexical(Path::new(resolved)), access));
        }
        if let Some(open) = line.find('(')
            && !line[..open].contains("<...")
            && let Some(quote) = line[open..].find('"')
        {
            let (argument, after) = quoted_arg(&line[open + quote + 1..])?;
            if library_lookup(&argument, line, outcome) || url_lookup(&argument, line, outcome) {
                continue;
            }
            if !LINK_CONTENT.contains(&syscall(line)) {
                out.push((
                    resolve(&argument, &line[open + 1..open + quote], cwd)?,
                    access,
                ));
            }
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

/// Whether `line` is a linker or loader looking a shared library up by its
/// bare name (CLOUD-2870): a path argument with no `/` that is a soname
/// (`libgcc_s.so.1`, `libz.so`), named by a read-only `open`/`openat`/`openat2`,
/// or by a probe ([`PROBES`]) that found nothing (`= -1 ENOENT`).
///
/// MEASURED, a link through rustup's `gcc-ld/ld.lld` (`rust-lld`): asked for
/// the input `libgcc_s.so.1`, it first tries the name against its working
/// directory, `access("libgcc_s.so.1", F_OK) = -1 ENOENT`, and the walk read
/// that as a path in the step's tree. A build script links only when it
/// rebuilds, which is why the refusal was intermittent. The runtime loader
/// searches the same way when a search-path entry is the working directory.
///
/// The ARGUMENT names a search, not a file, so it is dropped, and only where
/// dropping it loses nothing: an open that found a file still yields the
/// descriptor `-y` printed for it, so a library really loaded from the tree
/// stays a read, and a probe is dropped only when it found nothing. Never an
/// absolute or slashed path, never a write, never a name that is no soname. A
/// probe strace split across two lines carries its result, and an open any flag
/// past the split, on the resumed half, `outcome` ([`resumptions`]): judged off
/// the first half alone, a cold `lint:clippy` refused on `libgcc_s.so.1`
/// (CLOUD-2789).
fn library_lookup(argument: &str, line: &str, outcome: &str) -> bool {
    let searched = match (access_of(line), access_of(outcome)) {
        (_, Access::Write) | (Access::Write, _) => false,
        (Access::Read, _) => matches!(syscall(line), "open" | "openat" | "openat2"),
        (Access::Probe, _) => {
            PROBES.contains(&syscall(line))
                && result_of(outcome).is_some_and(|result| result.starts_with("-1 ENOENT"))
        }
    };
    searched && !argument.contains('/') && soname(argument)
}

/// Whether `line` is a tool asking whether a URL is a local path, and finding
/// it is not (CLOUD-2789): a path argument spelled `scheme://…` (an RFC 3986
/// scheme, then `://` as written, before the walk folds the `//`), named by a
/// read-only open or a probe ([`PROBES`]) that returned `-1 ENOENT`.
///
/// MEASURED, `cargo deny check` on a cold advisory cache: gix, handed the
/// advisory database's URL to clone, first stats it as a path against the
/// working directory, `newfstatat(AT_FDCWD</repo>,
/// "https://github.com/RustSec/advisory-db.git", …) = -1 ENOENT`, with its
/// `/.git`, `.git/.git` and `.bundle` variants. The walk read those as five
/// files under `https:/` in the step's tree, and `deny` refused on every cold
/// container — CI's every run — and passed warm, where the clone is opened,
/// not looked up.
///
/// The ARGUMENT names a remote, not a file, so it is dropped, and only where
/// dropping it loses nothing: a lookup that found something is kept (a tree
/// really holding `https:/…` reads it), and a write is never dropped.
///
/// A CALL STRACE SPLIT ACROSS TWO LINES is judged on both: the argument sits on
/// the `<unfinished ...>` half and the result, and any flag past the split, on
/// the `<... resumed>` half, `outcome` ([`resumptions`]). Read off the first
/// half alone, three of the five probes of one cold `deny` run still refused.
fn url_lookup(argument: &str, line: &str, outcome: &str) -> bool {
    let missed = access_of(line) != Access::Write
        && access_of(outcome) != Access::Write
        && result_of(outcome).is_some_and(|result| result.starts_with("-1 ENOENT"));
    missed
        && argument.split_once("://").is_some_and(|(scheme, _)| {
            scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        })
}

/// Each `<unfinished ...>` line's index, mapped to the same pid's next
/// `<... resumed>` line: the half that carries the call's result.
fn resumptions(trace: &str) -> std::collections::HashMap<usize, &str> {
    let mut pending = std::collections::HashMap::new();
    let mut out = std::collections::HashMap::new();
    for (index, line) in trace.lines().enumerate() {
        let Some((pid, rest)) = line.split_once(' ') else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("<... ") {
            if let Some(began) = pending.remove(pid) {
                out.insert(began, line);
            }
        } else if rest.ends_with("<unfinished ...>") {
            pending.insert(pid, index);
        }
    }
    out
}

/// Whether `name` is a shared object's name: a nonempty stem, `.so`, then
/// nothing or a dotted numeric version.
fn soname(name: &str) -> bool {
    name.split_once(".so").is_some_and(|(stem, version)| {
        !stem.is_empty()
            && (version.is_empty()
                || version.strip_prefix('.').is_some_and(|digits| {
                    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
                }))
    })
}

/// Each traced pid's working directory over the trace (CLOUD-2789), read from
/// the lines the tracer writes: the root pid starts in `start`; a pid's own
/// successful `chdir` or `fchdir` moves it; a pid a `clone`, `clone3`, `fork`
/// or `vfork` returned starts where its parent was when that call began.
///
/// A pid none of those account for (a trace written before the process tree
/// was traced) inherits `start` only while no pid in the trace changed
/// directory, the earlier reading; otherwise its directory is unknown. A
/// thread sharing its parent's directory (`CLONE_FS`) and moving it later is
/// not followed, a stated gap: the processes a step starts move their own.
struct Cwds {
    /// The traced command's pid.
    root: String,
    start: Option<PathBuf>,
    /// Each forked pid's parent and the line its fork began on.
    parent: std::collections::HashMap<String, (String, usize)>,
    /// Each pid's directory changes, in order: the line and the target, a
    /// `chdir` argument as written or an `fchdir` descriptor's path.
    moves: std::collections::HashMap<String, Vec<(usize, String)>>,
}

impl Cwds {
    /// The working directories `trace` shows, the root starting in `start`.
    fn read(trace: &str, start: Option<&Path>) -> Self {
        let mut cwds = Cwds {
            root: trace
                .lines()
                .next()
                .and_then(|line| line.split(' ').next())
                .unwrap_or_default()
                .to_owned(),
            start: start.map(Path::to_path_buf),
            parent: std::collections::HashMap::new(),
            moves: std::collections::HashMap::new(),
        };
        // A CALL SPLIT ACROSS TWO LINES begins on the first: its argument (a
        // `chdir` target) or its start (a fork) is held until the resumed half
        // says it succeeded.
        let mut pending: std::collections::HashMap<&str, (usize, Option<String>)> =
            std::collections::HashMap::new();
        for (index, line) in trace.lines().enumerate() {
            let Some((pid, rest)) = line.split_once(' ') else {
                continue;
            };
            let rest = rest.trim_start();
            let name = syscall(line);
            let (began, target) = if rest.starts_with("<... ") {
                match pending.remove(pid) {
                    Some(held) => held,
                    None => continue,
                }
            } else {
                let target = match name {
                    "chdir" => rest
                        .split_once('"')
                        .and_then(|(_, arg)| quoted_arg(arg))
                        .map(|(arg, _)| arg),
                    "fchdir" => rest
                        .split_once('<')
                        .and_then(|(_, fd)| fd.split_once(">)"))
                        .map(|(path, _)| path.to_owned()),
                    _ => None,
                };
                if rest.ends_with("<unfinished ...>") {
                    if matches!(
                        name,
                        "chdir" | "fchdir" | "clone" | "clone3" | "fork" | "vfork"
                    ) {
                        pending.insert(pid, (index, target));
                    }
                    continue;
                }
                (index, target)
            };
            let Some(result) = result_of(line) else {
                continue;
            };
            let result = result.split_whitespace().next().unwrap_or_default();
            match name {
                "chdir" | "fchdir" if result == "0" => {
                    if let Some(target) = target {
                        cwds.moves
                            .entry(pid.to_owned())
                            .or_default()
                            .push((began, target));
                    }
                }
                "clone" | "clone3" | "fork" | "vfork"
                    if result.parse::<u32>().is_ok_and(|child| child > 0) =>
                {
                    cwds.parent
                        .insert(result.to_owned(), (pid.to_owned(), began));
                }
                _ => {}
            }
        }
        cwds
    }

    /// `pid`'s working directory as of line `index`, or `None` where unknown.
    fn at(&self, pid: &str, index: usize) -> Option<PathBuf> {
        self.walk_back(pid, index, 0)
    }

    fn walk_back(&self, pid: &str, index: usize, depth: usize) -> Option<PathBuf> {
        // A cycle needs a reused pid; a bound answers it as unknown.
        if depth > 256 {
            return None;
        }
        if let Some((at, target)) = self
            .moves
            .get(pid)
            .and_then(|moves| moves.iter().rev().find(|(at, _)| *at < index))
        {
            let target = Path::new(target);
            if target.is_absolute() {
                return Some(lexical(target));
            }
            return Some(lexical(&self.walk_back(pid, *at, depth + 1)?.join(target)));
        }
        if pid == self.root {
            return self.start.clone();
        }
        if let Some((parent, at)) = self.parent.get(pid) {
            return self.walk_back(parent, *at, depth + 1);
        }
        self.moves.is_empty().then(|| self.start.clone()).flatten()
    }
}

/// What a syscall line returned: the text after its closing `)` and `= `.
///
/// STRACE PADS THE RESULT COLUMN (CLOUD-2789): a short call is followed by
/// spaces up to a fixed column (`<... vfork resumed>)              = 6111`),
/// so the literal `") = "` this read before missed every padded line — a
/// fork's child pid, and the descriptor path `-y` printed for a padded open.
fn result_of(line: &str) -> Option<&str> {
    let (head, result) = line.rsplit_once(" = ")?;
    head.trim_end().ends_with(')').then_some(result)
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

#[cfg(not(target_os = "linux"))]
pub(crate) use off_linux::await_trace;

/// The off-Linux arm, in a module of its own so its compiled-out mutants are
/// named apart from the Linux arm's (`.cargo/mutants.toml`, CLOUD-2902), as
/// `batten_core::lease`'s `off_proc` is.
#[cfg(not(target_os = "linux"))]
mod off_linux {
    use std::path::Path;

    /// No tracer off Linux, so nothing to wait for.
    pub(crate) fn await_trace(path: &Path) -> Option<String> {
        crate::fsio::read_to_string(path).ok()
    }
}

/// A strace string argument up to its closing quote, with the text after it,
/// or `None` for a string strace cut short, an escape it never writes, or
/// bytes that are not UTF-8.
///
/// STRACE'S C ESCAPES DECODE (CLOUD-2835): `\"`, `\\`, the named controls
/// (`\n`, `\t`, `\r`, `\v`, `\f`, `\a`, `\b`), `\xHH` and up to three octal
/// digits. Refusing all but the first two left `darwin-link` unrecorded on
/// every lap: Python probes `python3.13\n._pth`, and one such line made the
/// whole trace unreadable.
fn quoted_arg(text: &str) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    let octal = |at: usize| {
        bytes
            .get(at)
            .is_some_and(|byte| (b'0'..b'8').contains(byte))
    };
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0;
    // BOUNDED BY THE TEXT'S LENGTH (CLOUD-2789), as `item_index::paths_in` is:
    // every pass moves `at` forward by at least one byte, so `bytes.len()`
    // passes reach the end. A change that stops it advancing, or steps it back
    // onto an escape's backslash, ends the walk unread rather than spinning.
    for _ in 0..bytes.len() {
        let &byte = bytes.get(at)?;
        at += 1;
        match byte {
            b'"' => {
                let rest = text.get(at..)?;
                if rest.starts_with("...") {
                    return None;
                }
                return String::from_utf8(out).ok().map(|out| (out, rest));
            }
            b'\\' => {
                let escaped = *bytes.get(at)?;
                at += 1;
                match escaped {
                    b'"' | b'\\' => out.push(escaped),
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'v' => out.push(0x0b),
                    b'f' => out.push(0x0c),
                    b'a' => out.push(0x07),
                    b'b' => out.push(0x08),
                    b'x' => {
                        out.push(u8::from_str_radix(text.get(at..at + 2)?, 16).ok()?);
                        at += 2;
                    }
                    b'0'..=b'7' => {
                        let start = at - 1;
                        // UP TO TWO DIGITS MORE, three in all, as a pass
                        // count rather than a cursor test (CLOUD-2789): a
                        // change that stops `at` advancing reads a shorter
                        // escape instead of spinning on the same digit.
                        for _ in 0..2 {
                            if !octal(at) {
                                break;
                            }
                            at += 1;
                        }
                        out.push(u8::from_str_radix(text.get(start..at)?, 8).ok()?);
                    }
                    _ => return None,
                }
            }
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

    // Fails by: a Linux host with `strace` on `PATH` answered no tracer (the
    // platform test inverted), or a host without one answered one. The answer
    // is computed from what this host has, never skipped, so a host with no
    // `strace` or a run already under a tracer still asserts it (CLOUD-2789).
    #[test]
    fn a_linux_host_untraced_with_strace_on_path_has_a_tracer() {
        let on_path = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("strace"))
                .find(|candidate| candidate.is_file())
                .map(|found| found.to_string_lossy().into_owned())
        });
        let expected = if cfg!(target_os = "linux") && !super::traced_already() {
            on_path
        } else {
            None
        };
        assert_eq!(super::tracer(), expected);
    }

    // Fails by: a zero `TracerPid` read as a tracer, a set one read as none,
    // or a status with no such line read as traced.
    #[test]
    fn a_tracer_is_one_whose_pid_is_set() {
        assert!(!super::traced_in("Name:\tcase\nTracerPid:\t0\n"));
        assert!(super::traced_in("Name:\tcase\nTracerPid:\t4242\n"));
        assert!(!super::traced_in("Name:\tcase\n"));
    }

    /// Fails by: no tracer offered to an untraced process on Linux whose
    /// `PATH` holds `strace`, which leaves every case untraced and keyed on
    /// every file (CLOUD-2789). Off Linux, or already traced, it is `None`.
    #[test]
    fn an_untraced_process_is_offered_the_strace_on_its_path() {
        let refused = super::traced_already();
        let on_path = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("strace"))
                .find(|candidate| candidate.is_file())
                .map(|found| found.to_string_lossy().into_owned())
        });
        let expected = if cfg!(target_os = "linux") && !refused {
            on_path
        } else {
            None
        };
        assert_eq!(super::tracer(), expected);
    }

    // Fails by: this process's own status not the one read (`traced_already`
    // answering a constant), so a run under no tracer reads as traced and
    // records every case untraced. Compared with `traced_in` over the same
    // file rather than with `false`, so it holds under a reach run's tracer
    // too (CLOUD-2789). Off Linux there is no `/proc`, so nothing reads as
    // traced: `cfg!` keeps both arms compiled on every target.
    #[test]
    fn traced_already_reads_this_process_status() {
        if cfg!(target_os = "linux") {
            let status = crate::fsio::read_to_string("/proc/self/status").unwrap();
            assert_eq!(super::traced_already(), super::traced_in(&status));
        } else {
            assert!(!super::traced_already());
        }
    }

    // Fails by: an escaped quote or backslash refused (the path cut short as
    // unreadable), or kept with its backslash.
    #[test]
    fn a_quoted_argument_unescapes_a_quote_and_a_backslash() {
        assert_eq!(
            super::quoted_arg(r#"a\"b\\c", rest"#),
            Some((String::from("a\"b\\c"), ", rest"))
        );
        assert_eq!(super::quoted_arg(r#"cut"..."#), None);
    }

    // Fails by: an escape's second byte not stepped past (`at += 1` read as
    // `at -= 1`), so the walk reads its backslash again. A hex escape then
    // reads `\x` as its digits and refuses at once, where a quote or a
    // backslash escape would spin; so this case alone can fail inside its
    // own run, beside the cases that hang (CLOUD-2789).
    #[test]
    fn a_hex_escape_is_stepped_past_whole() {
        assert_eq!(
            super::quoted_arg("a\\x41b\", 0"),
            Some((String::from("aAb"), ", 0"))
        );
    }

    // Fails by: an absent trace read as an empty one (every case keyed on
    // nothing rather than on every file), or a whole one not read back.
    #[test]
    fn an_absent_trace_is_none_and_a_whole_one_is_read() {
        let dir = crate::scratch::scratch("trace-await");
        assert_eq!(super::await_trace(&dir.join("absent")), None);
        let file = dir.join("whole");
        let text = whole(&[]);
        std::fs::write(&file, &text).unwrap();
        assert_eq!(super::await_trace(&file), Some(text));
    }

    // Fails by: the grace's deadline set before now (`+` read as `-`), so the
    // wait reads once more and answers the second partial text; or the close
    // watcher sending nothing once a read succeeds (`&&` read as `||`), so the
    // wait sleeps out its grace and answers that same second read. A FIFO
    // makes every read block until the writer's next round closes, so the
    // writer, not a clock, decides which text each read sees: two partial
    // traces, then the whole one (CLOUD-2789).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_trace_finished_after_a_partial_read_is_waited_for() {
        use rustix::fs::{CWD, FileType, Mode, mknodat};
        let dir = crate::scratch::scratch("trace-await-fifo");
        let fifo = dir.join("trace");
        mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
        let partial = String::from("7     execve(\"/bin/sh\", [\"sh\"], 0x0 /* 0 vars */) = 0\n");
        let text = whole(&[]);
        let rounds = [partial.clone(), partial, text.clone()];
        // EACH ROUND WAITS FOR THE READER'S CLOSE: a writer opening while the
        // last read is still open joins that read's stream, and the rounds run
        // together into one text.
        let closed = rustix::fs::inotify::init(rustix::fs::inotify::CreateFlags::CLOEXEC).unwrap();
        rustix::fs::inotify::add_watch(
            &closed,
            &fifo,
            rustix::fs::inotify::WatchFlags::CLOSE_NOWRITE,
        )
        .unwrap();
        let writer = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                let mut events = [0_u8; 1024];
                for round in rounds {
                    std::fs::write(&fifo, round).unwrap();
                    rustix::io::read(&closed, &mut events).unwrap();
                }
            })
        };
        assert_eq!(super::await_trace(&fifo), Some(text));
        writer.join().unwrap();
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

    // A `chdir` moves only the pid that made it (CLOUD-2789): the bare path after
    // it resolves in the new directory, never the start one.
    #[test]
    fn a_changed_directory_moves_its_own_pid() {
        let trace = whole(&[
            "7     chdir(\"sub\") = 0",
            "7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
        ]);
        assert_eq!(
            super::touched(&trace, Some(Path::new("/repo"))),
            Some(vec![
                PathBuf::from("/bin/sh"),
                PathBuf::from("/repo/sub"),
                PathBuf::from("/repo/sub/c"),
            ])
        );
    }

    // The walk back through relative moves is bounded (CLOUD-2789): a chain
    // deeper than the bound answers the directory as unknown, so a bare path
    // after it cannot resolve and the trace is unreadable. Fails by: the depth
    // never growing along the chain (`+` for `*`), so no bound is ever met.
    #[test]
    fn a_relative_move_chain_past_the_bound_is_unknown() {
        let chain = |moves: usize| {
            let mut lines = vec!["7     chdir(\"d\") = 0"; moves];
            lines.push("7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)");
            super::touched(&whole(&lines), Some(Path::new("/repo")))
        };
        assert!(chain(200).is_some(), "a chain under the bound resolves");
        assert_eq!(chain(300), None);
        // THE BOUND ITSELF (CLOUD-2789): 256 relative moves reach the start
        // directory at depth 256, which the bound admits; one more does not.
        // Fails by: the bound read as `>=`, refusing a chain it admits.
        assert!(chain(256).is_some(), "a chain at the bound resolves");
        assert_eq!(chain(257), None, "a chain one past the bound is unknown");
    }

    // THE CARGO SHAPE (CLOUD-2789): the root forks a child that `chdir`s to its
    // package before exec, and that child probes a bare name. Read as
    // one `chdir` anywhere disabling every pid's start directory, this trace
    // was unreadable, so no cargo step ever recorded. Now the child's probe
    // resolves in its package, the root's after it in the start directory,
    // and a grandchild inherits the child's directory at its fork.
    #[test]
    fn a_forked_child_keeps_its_own_directory_and_the_root_its_own() {
        let trace = whole(&[
            "7     clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88 <unfinished ...>",
            "8     chdir(\"/pkg\" <unfinished ...>",
            // strace pads a short call's result column, as it printed these.
            "7     <... clone3 resumed>)             = 8",
            "8     <... chdir resumed>)              = 0",
            "8     access(\"build.rs\", F_OK) = -1 ENOENT (No such file or directory)",
            "8     clone(child_stack=NULL, flags=SIGCHLD) = 9",
            "9     stat(\"out\", 0x1) = -1 ENOENT (No such file or directory)",
            "7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
            "8     +++ exited with 0 +++",
        ]);
        let touched = super::touched(&trace, Some(Path::new("/repo"))).expect("readable");
        for path in ["/pkg/build.rs", "/pkg/out", "/repo/c"] {
            assert!(
                touched.contains(&PathBuf::from(path)),
                "{path}: {touched:?}"
            );
        }
    }

    // A pid nothing accounts for, once some pid moved, is unknown: its bare path
    // stays unresolvable rather than attributed to the start directory.
    #[test]
    fn an_unaccounted_pid_after_a_move_is_unresolvable() {
        let trace = whole(&[
            "8     chdir(\"/pkg\") = 0",
            "9     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
        ]);
        assert_eq!(super::touched(&trace, Some(Path::new("/repo"))), None);
    }

    // A `chdir` the kernel refused moves nothing (CLOUD-2789): the bare path
    // after it still resolves in the start directory. Fails by: the result
    // guard dropped, so a failed `chdir` reads as a move.
    #[test]
    fn a_refused_chdir_moves_nothing() {
        let trace = whole(&[
            "7     chdir(\"gone\") = -1 ENOENT (No such file or directory)",
            "7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
        ]);
        let touched = super::touched(&trace, Some(Path::new("/repo"))).expect("readable");
        assert!(touched.contains(&PathBuf::from("/repo/c")), "{touched:?}");
        assert!(
            !touched.contains(&PathBuf::from("/repo/gone/c")),
            "{touched:?}"
        );
    }

    // `fchdir` moves its pid to the path `-y` printed for the descriptor.
    #[test]
    fn an_fchdir_moves_to_its_descriptors_path() {
        let trace = whole(&[
            "7     fchdir(3</pkg>) = 0",
            "7     stat(\"c\", 0x1) = -1 ENOENT (No such file or directory)",
        ]);
        let touched = super::touched(&trace, Some(Path::new("/repo"))).expect("readable");
        assert!(touched.contains(&PathBuf::from("/pkg/c")), "{touched:?}");
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
            accessed(&["7     readlink(\"c\", \"x\", 4095) = 1"]),
            vec![(PathBuf::from("/repo/c"), Read)],
            "a link's target is its bytes"
        );
    }

    /// A BARE-NAME LIBRARY LOOKUP IS NO TOUCH (CLOUD-2870): `rust-lld`, linking
    /// a build script, tried the input `libgcc_s.so.1` against its working
    /// directory (the first line below, as a link here traced it), and the walk
    /// read it as a file in the tree.
    ///
    /// Fails by: dropping the `library_lookup` skip (the bare name resolves to
    /// `/repo/libgcc_s.so.1`); dropping its no-`/`, soname, ENOENT or
    /// not-a-write clause (the slashed, the non-library, the found or the
    /// written path vanishes); dropping the descriptor read (a library found
    /// in the tree vanishes); reading a split probe's result off its first half
    /// (the split lookup stays); or judging write flags on the first half alone
    /// (the split create vanishes).
    #[test]
    fn a_bare_library_lookup_is_no_touch() {
        use super::Access::{Probe, Read, Write};
        let lookups = [
            String::from("7     access(\"libgcc_s.so.1\", F_OK)     = -1 ENOENT (No such file or directory)"),
            String::from("7     newfstatat(AT_FDCWD</repo>, \"libz.so\", 0x1, 0) = -1 ENOENT (No such file or directory)"),
        ]
        .into_iter()
        .chain(["libgcc_s.so.1", "libz.so", "libstdc++.so.6.0.33"].map(|name| {
            format!(
                "7     openat(AT_FDCWD</repo>, \"{name}\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No \
                 such file or directory)"
            )
        }));
        for line in lookups {
            assert_eq!(accessed(&[&line]), vec![], "{line}");
        }
        assert_eq!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"libgcc_s.so.1\", O_RDONLY|O_CLOEXEC) = \
                 3</repo/libgcc_s.so.1>"
            ]),
            vec![(PathBuf::from("/repo/libgcc_s.so.1"), Read)],
            "a library found in the tree is still read, through its descriptor"
        );
        for (line, want) in [
            (
                "7     openat(AT_FDCWD</repo>, \"lib/libz.so\", O_RDONLY) = -1 ENOENT (No such \
                 file or directory)",
                (PathBuf::from("/repo/lib/libz.so"), Read),
            ),
            (
                "7     openat(AT_FDCWD</repo>, \"notes.so.txt\", O_RDONLY) = -1 ENOENT (No such \
                 file or directory)",
                (PathBuf::from("/repo/notes.so.txt"), Read),
            ),
            (
                "7     openat(AT_FDCWD</repo>, \".so\", O_RDONLY) = -1 ENOENT (No such file or \
                 directory)",
                (PathBuf::from("/repo/.so"), Read),
            ),
            (
                "7     access(\"libgcc_s.so.1\", F_OK) = 0",
                (PathBuf::from("/repo/libgcc_s.so.1"), Probe),
            ),
            (
                "7     access(\"libgcc_s.so.1\", F_OK <unfinished ...>",
                (PathBuf::from("/repo/libgcc_s.so.1"), Probe),
            ),
            (
                "7     openat(AT_FDCWD</repo>, \"libz.so\", O_WRONLY|O_CREAT, 0644) = -1 EACCES \
                 (Permission denied)",
                (PathBuf::from("/repo/libz.so"), Write),
            ),
        ] {
            assert_eq!(accessed(&[line]), vec![want], "{line}");
        }
        // A split probe is judged on its resumed half (CLOUD-2789), and a split
        // open whose write flags sit past the split stays.
        assert_eq!(
            accessed(&[
                "7     access(\"libgcc_s.so.1\", F_OK <unfinished ...>",
                "7     <... access resumed>) = -1 ENOENT (No such file or directory)",
            ]),
            vec![],
            "a split lookup that found nothing"
        );
        assert_eq!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"libz.so\", <unfinished ...>",
                "7     <... openat resumed>O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission \
                 denied)",
            ]),
            vec![(PathBuf::from("/repo/libz.so"), Read)],
            "a split create is never dropped"
        );
    }

    // STRACE'S C ESCAPES DECODE (CLOUD-2835): `darwin-link`'s trace never read
    // whole because Python probes `python3.13\n._pth`, a path holding a
    // newline, and any escape but `\"` and `\\` refused the whole trace.
    #[test]
    fn a_path_spelled_with_a_c_escape_decodes() {
        use super::Access::Read;
        assert_eq!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"/bin/py3\\n._pth\", O_RDONLY) = -1 ENOENT (No such \
                 file or directory)"
            ]),
            vec![(PathBuf::from("/bin/py3\n._pth"), Read)]
        );
        for (spelled, meant) in [
            ("a\\tb", "a\tb"),
            ("a\\x41b", "aAb"),
            ("a\\101b", "aAb"),
            ("a\\0", "a\0"),
            ("a\\1011", "aA1"),
            ("a\\rb", "a\rb"),
            ("a\\vb", "a\u{b}b"),
            ("a\\fb", "a\u{c}b"),
            ("a\\ab", "a\u{7}b"),
            ("a\\bb", "a\u{8}b"),
            ("q\\\"\\\\", "q\"\\"),
        ] {
            assert_eq!(
                super::quoted_arg(&format!("{spelled}\", 0")).map(|(arg, _)| arg),
                Some(meant.to_owned()),
                "{spelled}"
            );
        }
        // NOT UTF-8 IS STILL UNREAD: a path that cannot be held as text is not
        // guessed at.
        assert_eq!(super::quoted_arg("\\377\", 0"), None);
        assert_eq!(
            super::quoted_arg("\\q\", 0"),
            None,
            "an escape strace never writes"
        );
    }

    // A PROBE (CLOUD-2835): a call that asks whether a path is there, or lists a
    // directory's names, and reads no file's bytes. Cargo's target discovery
    // probes every member's `src/lib.rs`, `build.rs` and the rest this way.
    #[test]
    fn a_stat_an_access_or_a_listing_is_a_probe() {
        use super::Access::Probe;
        for line in [
            "7     newfstatat(AT_FDCWD</repo>, \"c\", 0x1, 0) = 0",
            "7     statx(AT_FDCWD</repo>, \"c\", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x1) = 0",
            "7     stat(\"c\", 0x1) = 0",
            "7     lstat(\"c\", 0x1) = 0",
            "7     access(\"c\", F_OK) = -1 ENOENT (No such file or directory)",
            "7     faccessat2(AT_FDCWD</repo>, \"c\", R_OK, 0) = 0",
        ] {
            assert_eq!(
                accessed(&[line]),
                vec![(PathBuf::from("/repo/c"), Probe)],
                "{line}"
            );
        }
        assert_eq!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"d\", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = \
                 3</repo/d>"
            ]),
            vec![
                (PathBuf::from("/repo/d"), Probe),
                (PathBuf::from("/repo/d"), Probe)
            ],
            "a directory opened to list its names"
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

    /// A URL LOOKED UP AS A PATH IS NO TOUCH (CLOUD-2789): gix, cloning the
    /// advisory database on a cold `cargo deny`, stats the URL against its
    /// working directory first (the first line below, as that run traced it),
    /// and the walk read `/repo/https:/github.com/…` as a file in the tree.
    ///
    /// Fails by: dropping the `url_lookup` skip (the URL resolves under
    /// `/repo/https:`); dropping its ENOENT clause (the found lookup vanishes);
    /// dropping its not-a-write clause (the failed create vanishes); or
    /// loosening the scheme to any text before `://` (the digit-led, the
    /// slashed and the spaced paths vanish) or to `:/` (the single-slash path
    /// vanishes); reading a split call's result off its first half (the missed
    /// half stays); pairing halves across pids (the found half vanishes); or
    /// judging write flags on the first half alone (the split create vanishes).
    #[test]
    fn a_url_looked_up_as_a_path_is_no_touch() {
        use super::Access::{Probe, Read, Write};
        for line in [
            "7     newfstatat(AT_FDCWD</repo>, \"https://github.com/RustSec/advisory-db.git\", \
             0x1, 0) = -1 ENOENT (No such file or directory)",
            "7     stat(\"git+ssh://host/a.bundle\", 0x1) = -1 ENOENT (No such file or directory)",
            "7     openat(AT_FDCWD</repo>, \"file://x/y\", O_RDONLY) = -1 ENOENT (No such file or \
             directory)",
        ] {
            assert_eq!(accessed(&[line]), vec![], "{line}");
        }
        let kept = [
            (
                "7     newfstatat(AT_FDCWD</repo>, \"https://h/x\", 0x1, 0) = 0",
                "/repo/https:/h/x",
                Probe,
            ),
            (
                "7     openat(AT_FDCWD</repo>, \"https://h/x\", O_WRONLY|O_CREAT, 0644) = -1 \
                 ENOENT (No such file or directory)",
                "/repo/https:/h/x",
                Write,
            ),
            (
                "7     stat(\"1x://h\", 0x1) = -1 ENOENT (No such file or directory)",
                "/repo/1x:/h",
                Probe,
            ),
            (
                "7     stat(\"d/https://h\", 0x1) = -1 ENOENT (No such file or directory)",
                "/repo/d/https:/h",
                Probe,
            ),
            (
                "7     stat(\"a b://h\", 0x1) = -1 ENOENT (No such file or directory)",
                "/repo/a b:/h",
                Probe,
            ),
            (
                "7     openat(AT_FDCWD</repo>, \"https:/h\", O_RDONLY) = -1 ENOENT (No such file \
                 or directory)",
                "/repo/https:/h",
                Read,
            ),
        ];
        for (line, path, access) in kept {
            assert_eq!(
                accessed(&[line]),
                vec![(PathBuf::from(path), access)],
                "{line}"
            );
        }
        // Split calls, interleaved across two pids: each half pairs with its
        // own pid's resumed half, never the next line's.
        assert_eq!(
            accessed(&[
                "7     newfstatat(AT_FDCWD</repo>, \"https://h/a\", <unfinished ...>",
                "8     newfstatat(AT_FDCWD</repo>, \"https://h/b\", <unfinished ...>",
                "8     <... newfstatat resumed>0x1, 0) = 0",
                "7     <... newfstatat resumed>0x1, 0) = -1 ENOENT (No such file or directory)",
                "8     +++ exited with 0 +++",
            ]),
            vec![(PathBuf::from("/repo/https:/h/b"), Probe)],
            "the missed half drops, the found half stays"
        );
        assert_eq!(
            accessed(&[
                "7     openat(AT_FDCWD</repo>, \"https://h/c\", <unfinished ...>",
                "7     <... openat resumed>O_WRONLY|O_CREAT, 0644) = -1 ENOENT (No such file or \
                 directory)",
            ]),
            vec![(PathBuf::from("/repo/https:/h/c"), Read)],
            "a create whose flags sit past the split is never dropped"
        );
    }

    // Fails by: a symlink's target text read as a path (CLOUD-2789) — gix's
    // probe `symlink("dangling", …)` then writes `/repo/dangling`, which no
    // process touched — or its link path no longer read as the one write.
    #[test]
    fn a_symlinks_target_is_its_content_not_a_path() {
        use super::Access::Write;
        for line in [
            "7     symlink(\"dangling\", \"/repo/.git/__file_link1\") = 0",
            "7     symlinkat(\"dangling\", AT_FDCWD</repo>, \".git/__file_link1\") = 0",
        ] {
            assert_eq!(
                accessed(&[line]),
                vec![(PathBuf::from("/repo/.git/__file_link1"), Write)],
                "{line}"
            );
            assert_eq!(
                super::touched(&whole(&[line]), None).unwrap(),
                vec![PathBuf::from("/bin/sh")],
                "the target text is no path the reach reader keys on: {line}"
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
