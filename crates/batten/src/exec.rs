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
//! * **The child's streams.** Inherited, not captured, so the caller sees exactly
//!   the bytes the child wrote, in the order it wrote them, with no buffering
//!   Batten introduced. Capturing is CLOUD-162's job and it belongs behind a
//!   pointer; doing it here would silently change what every existing consumer of
//!   a wrapped command sees.
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
use std::process::Command;

use anyhow::Result;

use crate::error::{Passthrough, UsageError};
use crate::exit::ExitCode;

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

/// Run `command`, inheriting its streams, and report its exit code unchanged.
///
/// Returns [`ExitCode::Success`] only for a child that exited `0`; every other
/// code travels as a [`Passthrough`] error, which the binary boundary turns into
/// that exact status.
///
/// # Errors
///
/// Returns a [`UsageError`] when `command` is empty or names a program that
/// cannot be started, and a [`Passthrough`] for any non-zero child code. Nothing
/// here returns [`ExitCode::Violation`] of its own accord; a `2` from this verb
/// came from the child.
pub fn run(command: &[String]) -> Result<ExitCode> {
    let Some((program, args)) = command.split_first() else {
        // Unreachable through the CLI: `num_args(1..)` makes clap refuse an empty
        // tail. Kept total because the workspace lints forbid panicking on a
        // reachable path, and a library caller can construct one.
        return Err(UsageError::raise(
            "exec: no command given — write `batten exec -- <cmd> [args…]`",
        ));
    };

    // No `.stdout()`/`.stderr()` call: inherit is the default, and saying so
    // explicitly here would read as a choice that could be changed, when in fact
    // capturing is a different verb's contract (CLOUD-162).
    let status = Command::new(OsString::from(program))
        .args(args.iter().map(OsString::from))
        .status();

    let status = match status {
        Ok(status) => status,
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

    let code = status.code().unwrap_or_else(|| signal_code(status));
    if code == 0 {
        return Ok(ExitCode::Success);
    }
    Err(Passthrough::raise(code))
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
