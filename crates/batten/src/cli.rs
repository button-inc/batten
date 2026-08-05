//! The command surface, defined with `clap`.
//!
//! The command tree is intentionally empty at this scaffold stage: the shape of
//! the surface (`check`, `doctor`, `config`, `at-risk`, `test-guard`, `rgr`, the
//! `hook` mediator, and the append-only record operations) is a Phase-0 decision
//! that dependent work must follow rather than outrun. New subcommands are added
//! to [`Command`] as those decisions land.

use clap::{Parser, Subcommand};

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
pub enum Command {}
