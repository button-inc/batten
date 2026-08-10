//! `batten exec -- <cmd> …`: run a command and get out of the way (CLOUD-285).
//!
//! House style §2 has listed this verb since the surface was designed, and two
//! Phase 2 issues are built on it — [`crate::hook`]'s siblings CLOUD-162 (capture
//! its output) and CLOUD-117 (promote a lying exit `0` to a violation). Neither
//! could be built, because the verb did not exist.
//!
//! ## Transparent, which is a stronger claim than "thin"
//!
//! Three things pass through untouched, and each is load-bearing for a consumer:
//!
//! * **The child's argv.** Declared as [`crate::surface::ValueDecl::Trailing`],
//!   which sets `trailing_var_arg(true)` and `allow_hyphen_values(true)`. The
//!   second is not defensive tidying: without
//!   it a wrapped command's own `-v` is parsed as Batten's §3 verbosity rung, so
//!   `batten exec -- cargo test -v` would raise Batten's log level and drop the
//!   flag the caller meant for `cargo`.
//! * **The child's streams.** TEED, not merely captured (CLOUD-162): each stream
//!   is copied to the store *and* to Batten's corresponding stream, so the caller
//!   still sees exactly the bytes the child wrote. Replacing inheritance with a
//!   plain capture would have silently changed what every wrapped command's
//!   caller sees, which is why `exec_inherits_both_child_streams_unchanged` is the
//!   test that governs this design.
//!
//!   **The cost, stated rather than discovered:** stdout and stderr are separate
//!   pipes, so their *relative* interleaving is no longer guaranteed to match what
//!   a terminal would have shown. Each stream's own order is preserved. That is
//!   inherent to reading two pipes, and it is why a capture is keyed by stream
//!   rather than stored as one merged log.
//!
//!   Each pipe is drained on its own thread. Reading them in sequence would
//!   deadlock the moment a child filled the other pipe's buffer — a wrapped
//!   command that writes a lot to stderr before finishing stdout would hang
//!   forever, and it would hang only for large outputs, which is the worst
//!   possible way to find out.
//! * **The child's exit code.**
//!
//! ## The exit code is the child's, and that is an exception with a record
//!
//! Non-negotiable rule 5 and §7 declare the `0/1/2/3` table with no per-verb
//! exception, and [`crate::exit`] states that `1` and `3` are the only codes a
//! Batten *failure* produces. A passthrough cannot honour that, because the code
//! is not Batten's to choose: a child exiting `7` must be reported as `7` or the
//! wrapper has lied about what happened.
//!
//! What survives — and it is the property fail-open actually rests on — is that
//! **Batten never *invents* a `2` on this path.** A mediated call is adjudicated
//! by [`crate::hook`], never here, so nothing reads an `exec` code as a policy
//! verdict. A `2` from this verb is the child's `2`, and
//! `exec_passes_through_a_code_outside_the_table` pins the whole reading.
//!
//! Mechanically the code travels as [`Passthrough`] on the error channel, the same
//! route [`crate::Denial`] takes for the same reason — the library never exits a
//! process. That keeps [`ExitCode`] total over the four codes Batten *chooses*
//! rather than widening the table to hold one it does not.
//!
//! ## What is still Batten's answer
//!
//! Exactly one thing: whether the command could be *started*. An absent program
//! is a [`UsageError`] (exit `1`), the same reading
//! [`crate::rules`]'s configured-command runner gives it — the caller named
//! something that is not there, which is a statement about the invocation.
//! Reporting that as the child's code would be worse than useless, because there
//! is no child.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::capture::{self, Stream};
use crate::error::{Passthrough, UsageError};
use crate::exit::ExitCode;
use crate::outputs::{self, Hit, OutputPattern};

/// The exit code a POSIX shell reports for a process killed by a signal.
///
/// A child that died on `SIGTERM` has no exit status of its own, and
/// [`std::process::ExitStatus::code`] returns `None`. Inventing `0` there would
/// report a killed build as a success — the exact false-green this engine exists
/// to prevent — so the shell's own convention is used instead: `128 + signal`.
/// Unavailable signal numbers fall back to `128`, which is still non-zero.
#[cfg(unix)]
fn signal_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(128, |signal| 128 + signal)
}

#[cfg(not(unix))]
fn signal_code(_status: std::process::ExitStatus) -> i32 {
    128
}

/// Drain `pipe` into `sink`, returning everything that passed through.
///
/// The tee. Chunked rather than read-to-end-then-write so a long-running child's
/// output still appears as it is produced: buffering it all until exit would make
/// `batten exec -- cargo test` look hung.
fn tee<R: Read, W: Write>(mut pipe: R, mut sink: W) -> Result<Vec<u8>> {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = pipe.read(&mut chunk)?;
        if read == 0 {
            return Ok(seen);
        }
        let bytes = chunk.get(..read).unwrap_or(&[]);
        sink.write_all(bytes)?;
        sink.flush()?;
        seen.extend_from_slice(bytes);
    }
}

/// Run `command`, teeing its streams, and report its exit code unchanged.
///
/// Returns [`ExitCode::Success`] only for a child that exited `0`; every other
/// code travels as a [`Passthrough`] error, which the binary boundary turns into
/// that exact status.
///
/// # Errors
///
/// Returns a [`UsageError`] when `command` is empty or names a program that
/// cannot be started, and a [`Passthrough`] for any non-zero child code. A store
/// that cannot be written is an internal error, never a silent skip: this is the
/// substrate a gate reads, and a capture that quietly did not happen is
/// indistinguishable from a command nobody checked. Nothing here returns
/// [`ExitCode::Violation`] of its own accord; a `2` from this verb came from the
/// child.
pub fn run(command: &[String]) -> Result<ExitCode> {
    run_with(command, &[], &mut std::io::sink())
}

/// [`run`], with the output predicates to apply and where to report a hit.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    command: &[String],
    patterns: &[OutputPattern],
    report: &mut dyn Write,
) -> Result<ExitCode> {
    // The repository root, not the cwd: `state::derive_repo_name` needs a real
    // final path component, and `.` has none — measured, as
    // `cannot derive a repository name from .`. Resolving through `git::repo_root`
    // also means a capture taken from a subdirectory lands in the same store as one
    // taken from the top, which is what makes a handle portable within a checkout.
    let root = crate::git::repo_root(Path::new("."))?;
    run_in_with(&root, command, patterns, report)
}

/// [`run`], with the repository root the capture is stored under.
///
/// # Errors
///
/// As [`run`].
pub fn run_in(repo_root: &Path, command: &[String]) -> Result<ExitCode> {
    run_in_with(repo_root, command, &[], &mut std::io::sink())
}

/// [`run_in`], with the output predicates to apply and where to report a hit.
///
/// # Errors
///
/// As [`run`].
pub fn run_in_with(
    repo_root: &Path,
    command: &[String],
    patterns: &[OutputPattern],
    report: &mut dyn Write,
) -> Result<ExitCode> {
    let Some((program, args)) = command.split_first() else {
        // Unreachable through the CLI: `num_args(1..)` makes clap refuse an empty
        // tail. Kept total because the workspace lints forbid panicking on a
        // reachable path, and a library caller can construct one.
        return Err(UsageError::raise(
            "exec: no command given — write `batten exec -- <cmd> [args…]`",
        ));
    };

    let spawned = Command::new(OsString::from(program))
        .args(args.iter().map(OsString::from))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawned {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "exec: cannot run `{program}`: not found on PATH"
            )));
        }
        Err(err) => {
            return Err(UsageError::raise(format!(
                "exec: cannot run `{program}`: {err}"
            )));
        }
    };

    // A missing pipe is unreachable — both were just requested as `piped()` — but
    // the workspace lints forbid unwrapping on a path the compiler cannot rule
    // out, and an internal error here is honest: it means the spawn lied.
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(anyhow::anyhow!(
            "exec: the spawned child exposed no pipes to tee"
        ));
    };

    // One thread per pipe. See the module docs: draining them in sequence
    // deadlocks as soon as a child fills the one not being read.
    let out_worker = std::thread::spawn(move || tee(out_pipe, std::io::stdout()));
    let err_worker = std::thread::spawn(move || tee(err_pipe, std::io::stderr()));

    let status = child.wait().context("wait for the wrapped command")?;
    let out_bytes = out_worker
        .join()
        .map_err(|_| anyhow::anyhow!("exec: the stdout tee panicked"))?
        .context("tee the wrapped command's stdout")?;
    let err_bytes = err_worker
        .join()
        .map_err(|_| anyhow::anyhow!("exec: the stderr tee panicked"))?
        .context("tee the wrapped command's stderr")?;

    // Both streams are stored, including an empty one: zero bytes is the real
    // answer "the command said nothing", and it must be distinguishable from a run
    // that was never captured at all. The handles are addressable, never printed —
    // emitting them here would put Batten's bookkeeping on a channel this verb
    // promises is the child's (CLOUD-121 owns the verbs that read them).
    capture::store(repo_root, Stream::Stdout, &out_bytes)?;
    capture::store(repo_root, Stream::Stderr, &err_bytes)?;

    let code = status.code().unwrap_or_else(|| signal_code(status));
    if code != 0 {
        // Batten only ever ADDS failure (CLOUD-117). A child that already failed
        // needs no promotion, and re-deciding a failure Batten did not diagnose
        // would make the wrapper's verdict unreadable. Its code passes through.
        return Err(Passthrough::raise(code));
    }

    // Only `0` is promotable, and only a declared pattern promotes it.
    let mut found: Vec<Hit> = outputs::hits(patterns, Stream::Stdout, &out_bytes);
    found.extend(outputs::hits(patterns, Stream::Stderr, &err_bytes));
    if found.is_empty() {
        return Ok(ExitCode::Success);
    }

    // Pointer-only (non-negotiable rule 4): `stream:line <id>` per hit, then the
    // count, then each pattern's reason once. Never the matched line — a wrapped
    // command's output is the likeliest place in this whole engine for a secret to
    // appear, which is what makes pointer-only load-bearing here.
    for hit in &found {
        writeln!(report, "{}", hit.line_text())?;
    }
    writeln!(report, "exec: {} output match(es)", found.len())?;
    for reason in outputs::reasons(patterns, &found) {
        writeln!(report, "{reason}")?;
    }
    // Exit 1, not 2: this is a statement that the invocation's own report was
    // untrustworthy, not a rule finding over the repository. Stated on the issue as
    // a chosen asymmetry rather than an oversight.
    Err(UsageError::raise(format!(
        "exec: the wrapped command exited 0 but its output matched {} declared \
         pattern(s) meaning it is not actually done",
        outputs::reasons(patterns, &found).len()
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_command_is_a_usage_error_never_a_verdict() {
        let err = run(&[]).expect_err("an empty command cannot be run");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_absent_program_is_a_usage_error_never_a_verdict() {
        let err = run(&["batten-no-such-program-exists".to_owned()])
            .expect_err("an absent program cannot be run");
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a program that is not there is a statement about the invocation"
        );
    }

    /// The code `run` reports for a shell exiting `code`.
    #[cfg(unix)]
    fn exit_with(script: &str) -> Result<ExitCode> {
        run(&["sh".to_owned(), "-c".to_owned(), script.to_owned()])
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_child_is_success() {
        assert_eq!(exit_with("exit 0").expect("sh runs"), ExitCode::Success);
    }

    #[cfg(unix)]
    #[test]
    fn the_childs_code_is_reported_unchanged_including_outside_the_table() {
        // The exception, asserted at the unit boundary as well as end-to-end: a
        // code the §7 table does not contain must survive intact.
        for expected in [1, 2, 7, 42, 255] {
            let err =
                exit_with(&format!("exit {expected}")).expect_err("non-zero travels as an error");
            let carried = err
                .downcast_ref::<Passthrough>()
                .expect("a non-zero child code is a Passthrough");
            assert_eq!(carried.0, expected);
            assert_eq!(i32::from(carried.byte()), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_signalled_child_is_never_reported_as_success() {
        // `ExitStatus::code()` is `None` for a signalled child. Reporting `0`
        // there would call a killed build a pass.
        let err = exit_with("kill -TERM $$").expect_err("a signalled child is not success");
        let carried = err
            .downcast_ref::<Passthrough>()
            .expect("a signalled child is a Passthrough");
        assert_ne!(carried.0, 0, "a signalled child must not read as success");
        assert_eq!(
            carried.0,
            128 + 15,
            "the shell's own 128 + signal convention"
        );
    }

    #[test]
    fn a_code_outside_one_byte_saturates_rather_than_truncating() {
        // Truncation could turn a failure into a success: `0x100` would report
        // `0`. Only a non-POSIX child can produce one, but the direction matters.
        assert_eq!(Passthrough(0x100).byte(), u8::MAX);
        assert_eq!(Passthrough(-1).byte(), u8::MAX);
        assert_eq!(Passthrough(7).byte(), 7);
    }
}
