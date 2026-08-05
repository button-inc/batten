//! Batten is a repo-agnostic policy engine.
//!
//! It gates what gets written, proves what was verified, and refuses to let
//! unlanded work appear finished — enforcing one repository's policy consistently
//! at the pre-commit layer, in CI, and at an agent's tool call.
//!
//! This crate exposes the library surface ([`run`]) that the `batten` binary is a
//! thin wrapper around. Keeping the logic in the library keeps it testable and
//! keeps the binary's `main` trivial.

pub mod cli;
pub mod exit;

use anyhow::Result;

pub use cli::{Cli, Command};
pub use exit::ExitCode;

/// Execute a parsed [`Cli`] and return the [`ExitCode`] to hand back to the OS.
///
/// # Errors
///
/// Returns an error when a command cannot complete because of an underlying
/// failure (I/O, a missing external tool, or an internal invariant violation).
/// Such errors map to [`ExitCode::Internal`] at the boundary; a *policy
/// violation*, by contrast, is a normal return of [`ExitCode::Violation`].
pub fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        // The command tree is empty at this scaffold stage; with no subcommand,
        // clap's default help has already been offered. Nothing to do yet.
        None => Ok(ExitCode::Success),
        // `Command` is an empty enum, so this arm is statically unreachable and
        // will start matching real variants as the surface is filled in.
        Some(command) => match command {},
    }
}
