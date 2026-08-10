//! The `batten` binary: resolve the output mode, parse arguments, run, and
//! translate the outcome into a process exit status. All real logic lives in the
//! library crate.
//!
//! Stderr is written through [`batten::output`] rather than `eprintln!`, which is
//! what lets the §3 ladder exist at all: a `print`-shaped write has no mode to
//! consult, so `--quiet` could only ever be a promise. The lint that used to
//! permit `print_stderr` here is gone with it.

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Result;
use batten::output::{self, Mode};

fn main() -> ExitCode {
    // Resolved before parsing, and from the raw argument list, because a *usage*
    // error must still be reported — and at that point `clap` has refused to
    // produce any parsed value to read the mode from.
    let flags = output::Presentation::from_argv(std::env::args_os().skip(1));
    // NOT `.lock()`. A held `StderrLock` is not reentrant, and `batten exec` tees a
    // child's streams from worker threads — so holding either lock across the run
    // deadlocks the moment a wrapped command actually writes something. Measured:
    // `batten exec -- sh -c 'echo hi'` hung forever while `exit 0` passed, which is
    // the worst possible way to find out. `Stdout`/`Stderr` lock per write instead,
    // which costs a mutex acquire and removes the footgun.
    let mut err = io::stderr();
    // A bad `BATTEN_LOG_LEVEL` is itself a usage error, reported under the
    // default mode: loud and uncoloured, the reading that cannot hide a message.
    let (mode, resolution) = match output::resolve(&flags) {
        Ok(mode) => (mode, Ok(())),
        Err(failure) => (Mode::default(), Err(failure)),
    };
    if let Err(failure) = resolution {
        return report(&failure, mode, &mut err);
    }
    match real_main(mode, &mut err) {
        Ok(code) => code.into(),
        Err(failure) => report(&failure, mode, &mut err),
    }
}

/// Write a failure to stderr and pick its exit code.
///
/// Four destinations, distinguished by type rather than by message, and **none
/// of them gated by the ladder**:
///
/// * A wrapped command's own code is not Batten's answer at all: `batten exec` is
///   transparent, so the code is returned with **no output of Batten's own**.
///   Saying anything here would be Batten narrating a result it did not produce.
///
/// * A mediation deny is a *verdict*: it prints its reason unprefixed, because a
///   hook host hands stderr back to the model as the reason and `batten: ` there
///   reads as a tool crash.
/// * An expected bad-input error (§7) maps to Usage and prints as a clean
///   one-line message. Exit `1` is defined as *fail loud, do not block* — a
///   statement about the invocation, not chatter about it — so `--silent` must
///   not empty it.
/// * An internal failure to *complete* prints its full chain for diagnosis.
fn report(failure: &anyhow::Error, mode: Mode, err: &mut dyn Write) -> ExitCode {
    if let Some(passthrough) = failure.downcast_ref::<batten::Passthrough>() {
        return ExitCode::from(passthrough.byte());
    }
    if let Some(denial) = failure.downcast_ref::<batten::Denial>() {
        let _ = output::verdict(err, &denial.to_string());
        batten::ExitCode::Violation.into()
    } else if failure.downcast_ref::<batten::UsageError>().is_some() {
        let _ = output::error(mode, err, &failure.to_string());
        batten::ExitCode::Usage.into()
    } else {
        let _ = output::error(mode, err, &format!("{failure:?}"));
        batten::ExitCode::Internal.into()
    }
}

fn real_main(mode: Mode, err: &mut dyn Write) -> Result<batten::ExitCode> {
    // Not `parse()`: clap's own exit path uses code 2, which under this contract
    // is the policy verdict. Render the message clap already composed, then map
    // the outcome onto the one table — help and version are a successful answer
    // on stdout, everything else is a usage error.
    //
    // Clap's render is *not* ladder-gated, and cannot be: the flags may not have
    // parsed, so suppressing the usage message would leave a bare `1` explaining
    // nothing (`an_unknown_flag_is_a_usage_error_even_under_silent`).
    let cli = match batten::cli::try_parse() {
        Ok(cli) => cli,
        Err(failure) => {
            let _ = failure.print();
            return Ok(if failure.use_stderr() {
                batten::ExitCode::Usage
            } else {
                batten::ExitCode::Success
            });
        }
    };
    // Nothing emits at `Verbose` or above yet — the ladder is the mechanism, and
    // the messages that will use it belong to the verbs that grow them (G10).
    // This one line proves the gated channel is wired to the resolved mode.
    let _ = output::message(
        mode,
        batten::Verbosity::Verbose,
        err,
        "resolved the output mode; running",
    );
    // stdout is the answer channel. Deliberately unlocked, for the reason given on
    // the stderr handle above; flushed explicitly before exit so buffered output is
    // never dropped.
    let mut out = io::stdout();
    let code = batten::run(cli, &mut out)?;
    out.flush()?;
    Ok(code)
}
