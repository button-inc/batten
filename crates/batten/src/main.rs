//! The `batten` binary: parse arguments, run, and translate the outcome into a
//! process exit status. All real logic lives in the library crate.

// The binary boundary is the one sanctioned place to write to stderr; library
// code is held to pointer-only, byte-stable output and keeps the workspace lint.
#![allow(clippy::print_stderr)]

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code.into(),
        Err(err) => {
            // A failure to *complete* a check. Report the full chain to stderr;
            // policy violations never travel this path.
            eprintln!("batten: {err:?}");
            batten::ExitCode::Internal.into()
        }
    }
}

fn real_main() -> Result<batten::ExitCode> {
    let cli = batten::Cli::parse();
    batten::run(cli)
}
