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
use crate::hook::Harness;

/// Repo-agnostic policy engine that keeps "done" aligned with landed-and-verified work.
#[derive(Debug, Parser)]
// arg_required_else_help: a bare invocation lists the subcommands and never
// performs a default action (§2). clap renders the listing on its error path
// (stderr, exit 2), so stdout stays the answer channel.
#[command(name = "batten", version, about, long_about = None, arg_required_else_help = true)]
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
    /// Adjudicate a mediated tool call read from stdin (under this verb, exit 2 denies).
    Hook {
        /// The harness whose payload to decode and whose decision channel to answer in.
        #[arg(long, value_enum)]
        harness: Harness,
    },
    /// Verification receipts: SHA-keyed claims a named check passed, invalidated by git facts.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
}

/// Subcommands of `receipt`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ReceiptCommand {
    /// Record that the named check concluded pass against the current HEAD.
    Record {
        /// The check whose conclusion is being recorded.
        check: String,
    },
    /// Judge the named check's recorded receipt against HEAD and origin/main.
    Status {
        /// The check whose receipt is judged.
        check: String,
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
