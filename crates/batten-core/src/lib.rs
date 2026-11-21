//! The layer below Batten's module cycle that `git` anchors (CLOUD-2789).
//!
//! The third package `batten modules cycle` let the `batten` crate shed, once
//! the shell parse, the finding grammar and the glob selector came out of
//! `hook`, `refusal` and `rules`: the git reads and writes, the landing lease
//! and its fast-forward watchers, the shell parse, and the small vocabularies
//! they share. Nothing here reaches back into `batten`, so it compiles, lints
//! and cross-checks without it. `batten` re-exports each module under its old
//! name, so `crate::git::…` resolves there exactly as it did.
//!
//! # Effect
//!
//! What each module states; this root adds none.

pub use batten_base::{checks_green, exit, fetch, forge, patch, propose, rest};
pub use batten_facts::{cache, durable, error, facts, identity, scratch};
pub use batten_fsio as fsio;
pub use batten_stream as stream;

pub use error::{Passthrough, UsageError};
pub use exit::ExitCode;

use anyhow::Result;

pub mod git;
pub mod gitwrite;
pub mod grammar;
pub mod lease;
pub mod main_watch;
pub mod pr_watch;
pub mod selector;
pub mod severity;
pub mod shell;
pub mod signer_posture;
pub mod sink;
pub mod state;
pub mod step_table;
pub mod stream_input;
pub mod testing;
