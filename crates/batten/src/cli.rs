//! The command surface, defined with `clap`.
//!
//! The surface is defined once, here, as data: `clap` derives the parser, and
//! [`crate::spec`] introspects this same tree at runtime to emit the command
//! spec (house-style §11). Each command's `///` doc comment is its human
//! summary, and each command's effect is declared in the one table in
//! [`crate::effect`] (§5).
//!
//! The tree grows one verb at a time: a verb is added here together with its
//! effect-table entry and its behaviour, in the verb's own change. A completeness
//! test in [`crate::spec`] fails if a command is ever added without an effect.

use clap::{Parser, Subcommand, ValueEnum};

/// Repo-agnostic policy engine that keeps "done" aligned with landed-and-verified work.
#[derive(Debug, Parser)]
#[command(name = "batten", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The top-level subcommands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// Run the configured rules against the repository.
    Check,
    /// Inspect configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Print the tool's own command spec.
    Spec {
        /// The output format for the spec.
        #[arg(long, value_enum, default_value_t = SpecFormat::Json)]
        format: SpecFormat,
    },
}

/// Subcommands of `config`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ConfigCommand {
    /// Print the effective configuration.
    Show,
}

/// The formats `batten spec` can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum SpecFormat {
    /// Byte-stable JSON — the agent-facing contract (§6).
    Json,
}
