//! The modules below Batten's module cycle (CLOUD-2789, phase 2).
//!
//! The second package `batten modules cycle` let the `batten` crate shed: the
//! dependency-closed set below its one large component, from the wall clock and
//! the exit contract up to the HTTP client, the forge readers and the codemod
//! substrate. Nothing here reaches back into `batten`, so it compiles, lints and
//! cross-checks without it. `batten` re-exports each module under its old name,
//! so `crate::exit::…` resolves there exactly as it did.
//!
//! # Effect
//!
//! What each module states; this root adds none.

pub use batten_facts::{durable, error, facts, identity, scratch, source};
pub use batten_fsio as fsio;

pub use error::{Passthrough, UsageError};
pub use exit::ExitCode;

use anyhow::Result;

pub mod arm;
pub mod background;
pub mod board;
pub mod brief;
pub mod cargo_graph;
pub mod carry;
pub mod checks_green;
pub mod ci;
pub mod clock;
pub mod codemod;
pub mod config_edit;
pub mod crate_cut;
pub mod deferral;
pub mod doc;
pub mod effect;
pub mod environment;
pub mod exit;
pub mod fast_forward;
pub mod fetch;
pub mod forge;
pub mod graph;
pub mod landed;
pub mod low_water;
pub mod module_graph;
pub mod outcome;
pub mod patch;
pub mod pattern;
pub mod preflight;
pub mod probe_verdict;
pub mod propose;
pub mod release_path;
pub mod remedy;
pub mod rest;
pub mod ripcord;
pub mod secret;
pub mod suites;
pub mod task;
pub mod testing;
pub mod tools;
pub mod traversal;
pub mod turn;
pub mod verbs;
pub mod version;
