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

use crate::config::Strictness;

/// Repo-agnostic policy engine that keeps "done" aligned with landed-and-verified work.
#[derive(Debug, Parser)]
#[command(name = "batten", version, about, long_about = None)]
pub struct Cli {
    /// Raise how strictly gates apply (an override may only tighten policy).
    ///
    /// The highest-precedence config layer (§8: flag > env > local file > repo
    /// config > default), and still raise-only: it can tighten a gate for one
    /// run, never disable one for it.
    ///
    /// `BATTEN_STRICTNESS` is the env equivalent, resolved by
    /// [`crate::resolve`] as its own layer rather than by `clap`, so `config
    /// show` can attribute the value to `env` or `flag` and not conflate them.
    #[arg(long, global = true, value_enum)]
    pub strictness: Option<Strictness>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The top-level subcommands.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// Run the applicable read-only gates against the repository.
    Check,
    /// Run every configured rule, including kinds that execute a configured command.
    Enforce,
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
