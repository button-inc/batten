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
pub mod hook;
pub mod identity;
pub mod resolve;
pub mod rules;
pub mod severity;
pub mod spec;
pub mod state;

use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;
use clap::CommandFactory;

pub use cli::{Cli, Command, ConfigCommand, SpecFormat};
pub use config::Config;
pub use effect::Effect;
pub use error::UsageError;
pub use exit::ExitCode;
pub use resolve::{Overrides, Resolved, Source};
pub use severity::{AdvisoryTier, Mapping, ReportLevel, RuleSeverity};

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
    let Cli {
        strictness,
        command,
    } = cli;
    // The flag layer of the §8 precedence chain; every config read in this run
    // resolves through it, so a flag can never apply to one verb and not another.
    let overrides = Overrides { strictness };
    match command {
        // Unreachable in practice: `arg_required_else_help` has clap offer the
        // subcommand listing (exit 2) before parse returns. Kept total — the
        // workspace lints forbid panicking on a reachable path.
        None => Ok(ExitCode::Success),
        Some(Command::Check) => run_rules(out, overrides, rules::run_static),
        Some(Command::Enforce) => run_rules(out, overrides, rules::run_all),
        Some(Command::Config { command }) => run_config(&command, overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::Hook { harness }) => run_hook(harness, out),
    }
}

/// Adjudicate one mediated call read from stdin (CLOUD-202).
///
/// Fail open at every boundary — unreadable stdin, an undecodable payload, an
/// envelope with no command all allow: a guard must never be the reason a
/// session cannot proceed. The bypass env var is the same hatch the shell
/// guards honour, resolved here at the boundary so the core stays pure.
///
/// The deny channel is per-harness: the Claude Code adapter answers in the
/// host's JSON decision object (exit 0); the neutral exit-code adapter is the
/// §7 inversion — exit 2 denies, with the reason on stderr via the usage-error
/// path, which is the one sanctioned stderr boundary.
fn run_hook(harness: hook::Harness, out: &mut dyn Write) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return Ok(ExitCode::Success);
    }
    let bypass = std::env::var_os("BATTEN_GH_GUARD_BYPASS").is_some_and(|v| !v.is_empty());
    let Some(envelope) = hook::decode(harness, &raw) else {
        return Ok(ExitCode::Success);
    };
    match hook::adjudicate(&envelope, bypass) {
        hook::Decision::Allow => Ok(ExitCode::Success),
        hook::Decision::Deny(reason) => match harness {
            hook::Harness::ClaudeCode => {
                writeln!(
                    out,
                    "{}",
                    hook::encode_claude_deny(&envelope.event, &reason)?
                )?;
                Ok(ExitCode::Success)
            }
            hook::Harness::ExitCode => Err(UsageError::raise(reason)),
        },
    }
}

/// Run the configured rules against the current directory and report findings.
///
/// `runner` selects which surface runs them — [`rules::run_static`] for the
/// `read`-effect `check`, [`rules::run_all`] for the unclassified `enforce`
/// (§5, CLOUD-170). Both report identically; only the admissible rule kinds
/// differ, so the two verbs can never drift in output shape.
///
/// Output is pointer-only (non-negotiable rule 4): one `path:line rule-id` per
/// finding, byte-stable and never the matched bytes. The exit code consumes
/// each finding's severity (CLOUD-61): a clean run exits [`ExitCode::Success`],
/// any `deny` finding exits [`ExitCode::Violation`], and a `warn` finding is
/// reported without failing the run — promoting it is `--fail-on-warning`'s
/// job (CLOUD-49). Which severity produced a finding is the committed rule's
/// declaration, looked up by the printed rule id.
fn run_rules(
    out: &mut dyn Write,
    overrides: Overrides,
    runner: fn(&[rules::Rule], &Path) -> Result<Vec<rules::Finding>>,
) -> Result<ExitCode> {
    // The *resolved* rule set, so a local override's added rules are gates a run
    // actually applies rather than config the tool merely prints.
    let config = resolve::resolve(Path::new("."), overrides)?;
    let findings = runner(&config.rules, Path::new("."))?;
    for finding in &findings {
        // Pointer only: location and the rule that fired, never the line text.
        // A rule-scoped finding (no line) prints its pointer without one rather
        // than inventing a line number it does not have.
        match finding.line {
            Some(line) => writeln!(out, "{}:{} {}", finding.path, line, finding.rule)?,
            None => writeln!(out, "{} {}", finding.path, finding.rule)?,
        }
    }
    // The severity axis reaches the exit contract exactly here: blocking is
    // derived through the taxonomy table, never name-matched (CLOUD-168).
    if rules::any_blocking(&findings) {
        Ok(ExitCode::Violation)
    } else {
        Ok(ExitCode::Success)
    }
}

fn run_config(
    command: &ConfigCommand,
    overrides: Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ConfigCommand::Show => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            // stdout is the answer: byte-stable JSON of the effective config,
            // with the layer that won each key alongside it (§8).
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
