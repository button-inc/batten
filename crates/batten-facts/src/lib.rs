//! Batten's fact model and what sits beneath it (CLOUD-2789, phase 2).
//!
//! The first package `batten modules cycle` let the `batten` crate shed: every
//! module here is below the crate's one large component, and nothing here
//! reaches back into `batten`. `batten` re-exports each module under its old
//! name, so `crate::facts::…` resolves there exactly as it did.
//!
//! # Effect
//!
//! What each module states; this root adds none.

pub use batten_fsio as fsio;

// FIRST, because `error` declares `Native` through it.
#[doc(hidden)]
pub mod token_enum;

pub mod cache;
pub mod digest;
pub mod dispatch;
pub mod durable;
pub mod error;
pub mod facts;
pub mod identity;
/// Rust call sites, parsed — where a token sits, not merely that it appears.
pub mod invocation;
pub mod kill;
pub mod minted;
pub mod register;
pub mod scratch;
pub mod source;
/// The `use` graph: which module reaches which, resolved through the root's own
/// re-export table.
pub mod uses;
