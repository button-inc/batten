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
            // Policy violations never travel this path. An expected bad-input
            // error (§7) maps to Usage and prints as a clean one-line message;
            // an internal failure to *complete* prints its full chain for
            // diagnosis.
            if err.downcast_ref::<batten::UsageError>().is_some() {
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
    let cli = batten::Cli::parse();
    // stdout is the answer channel; hold the lock for the whole run and flush
    // before exit so buffered output is never dropped.
    let mut out = io::stdout().lock();
    let code = batten::run(cli, &mut out)?;
    out.flush()?;
    Ok(code)
}
