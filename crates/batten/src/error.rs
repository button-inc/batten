//! Typed errors that carry their intended process exit code: `batten-facts`'
//! `error`, re-exported (CLOUD-2789).
//!
//! A module rather than a bare `pub use` for the one item `batten-facts` cannot
//! hold: the test-only path to [`crate::refusal::Denial`].

pub use batten_facts::error::*;

/// `Denial` lives with `Refusal` now (CLOUD-2789). The old path resolves for
/// TESTS ONLY, so a base test the replay splices in (`crate::error::Denial`)
/// still builds, while the library never reaches back up to `refusal`: that
/// edge alone put 20 modules back into the crate's largest cycle (128 → 148).
///
/// AN ALIAS, NOT A `use`: `module_closure` draws the crate's graph from `use`
/// items, test modules included, and a test-only re-export there put `refusal`
/// and `verdict` into the closure of every module reaching `error` (exec, land
/// and four more left the plumbing). A test-only path is no crate boundary —
/// cargo allows a dev-dependency to point back — and once the replay's base is
/// a trunk carrying the new path, nothing spells the old one.
#[cfg(test)]
pub type Denial = crate::refusal::Denial;
