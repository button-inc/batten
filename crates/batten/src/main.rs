//! The `batten` binary: parse arguments, run, and translate the outcome into a
//! process exit status. All real logic lives in the library crate.

// The binary boundary is the one sanctioned place to write to stderr; library
// code is held to pointer-only, byte-stable output and keeps the workspace lint.
#![allow(clippy::print_stderr)]

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code.into(),
        Err(err) => {
            // Three destinations, distinguished by type rather than by message.
            // A mediation deny is a *verdict*: it prints its reason unprefixed,
            // because a hook host hands stderr back to the model as the reason
            // and `batten: ` there reads as a tool crash. An expected bad-input
            // error (§7) maps to Usage and prints as a clean one-line message;
            // an internal failure to *complete* prints its full chain for
            // diagnosis.
            if let Some(denial) = err.downcast_ref::<batten::Denial>() {
                eprintln!("{denial}");
                batten::ExitCode::Violation.into()
            } else if err.downcast_ref::<batten::UsageError>().is_some() {
                eprintln!("batten: {err}");
                batten::ExitCode::Usage.into()
            } else {
                eprintln!("batten: {err:?}");
                batten::ExitCode::Internal.into()
            }
        }
    }
}

fn real_main() -> Result<batten::ExitCode> {
    // Not `parse()`: clap's own exit path uses code 2, which under this contract
    // is the policy verdict. Render the message clap already composed, then map
    // the outcome onto the one table — help and version are a successful answer
    // on stdout, everything else is a usage error.
    let cli = match batten::Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return Ok(if err.use_stderr() {
                batten::ExitCode::Usage
            } else {
                batten::ExitCode::Success
            });
        }
    };
    // stdout is the answer channel; hold the lock for the whole run and flush
    // before exit so buffered output is never dropped.
    let mut out = io::stdout().lock();
    let code = batten::run(cli, &mut out)?;
    out.flush()?;
    Ok(code)
}
