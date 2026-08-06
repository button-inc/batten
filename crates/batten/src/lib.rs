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
pub mod config;
pub mod effect;
pub mod error;
pub mod exit;
pub mod rules;
pub mod spec;
pub mod state;

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use clap::CommandFactory;

pub use cli::{Cli, Command, ConfigCommand, SpecFormat};
pub use config::Config;
pub use effect::Effect;
pub use error::UsageError;
pub use exit::ExitCode;

/// The committed authority Batten reads: the repo `batten.toml` in the current
/// directory. No upward walk, no `conf.d` merge (§8).
const CONFIG_FILE: &str = "batten.toml";

/// Execute a parsed [`Cli`], writing any data output to `out`, and return the
/// [`ExitCode`] to hand back to the OS.
///
/// Data output goes to `out` (the binary passes stdout) rather than through a
/// `print!`, so the library stays byte-stable and testable and the
/// stdout-is-the-answer split of the output contract is honoured.
///
/// # Errors
///
/// Returns an error when a command cannot complete because of an underlying
/// failure (I/O, a missing external tool, or an internal invariant violation).
/// Such errors map to [`ExitCode::Internal`] at the boundary; a *policy
/// violation*, by contrast, is a normal return of [`ExitCode::Violation`].
pub fn run(cli: Cli, out: &mut dyn Write) -> Result<ExitCode> {
    let Cli { command } = cli;
    match command {
        // With no subcommand, clap's default help has already been offered.
        None => Ok(ExitCode::Success),
        Some(Command::Check) => run_check(out),
        Some(Command::Config { command }) => run_config(&command, out),
        Some(Command::Spec { format }) => run_spec(format, out),
    }
}

/// Run the configured rules against the current directory and report findings.
///
/// Output is pointer-only (non-negotiable rule 4): one `path:line rule-id` per
/// finding, byte-stable and never the matched bytes. A clean run exits
/// [`ExitCode::Success`]; any finding exits [`ExitCode::Violation`].
fn run_check(out: &mut dyn Write) -> Result<ExitCode> {
    let config = config::load(Path::new(CONFIG_FILE))?;
    let findings = rules::check(&config.rules, Path::new("."))?;
    for finding in &findings {
        // Pointer only: location and the rule that fired, never the line text.
        writeln!(out, "{}:{} {}", finding.path, finding.line, finding.rule)?;
    }
    if findings.is_empty() {
        Ok(ExitCode::Success)
    } else {
        Ok(ExitCode::Violation)
    }
}

fn run_config(command: &ConfigCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match command {
        ConfigCommand::Show => {
            let config = config::load(Path::new(CONFIG_FILE))?;
            // stdout is the answer: byte-stable JSON of the effective config.
            let json = serde_json::to_string_pretty(&config)?;
            writeln!(out, "{json}")?;
            Ok(ExitCode::Success)
        }
    }
}

fn run_spec(format: SpecFormat, out: &mut dyn Write) -> Result<ExitCode> {
    let described = spec::describe(&Cli::command());
    match format {
        SpecFormat::Json => {
            let json = spec::to_json(&described)?;
            writeln!(out, "{json}")?;
        }
    }
    Ok(ExitCode::Success)
}
