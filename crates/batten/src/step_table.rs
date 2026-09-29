//! The `[[step]]` row and its load-time validator (CLOUD-843).
//!
//! **A LEAF, split from [`crate::step`] so the loader can name the row without
//! reaching the cache.** `config` owns the table's field and refuses a bad row
//! at load; `step` reads the committed table back through `resolve`. With the
//! type in `step`, `config -> step -> resolve -> config` was a module cycle —
//! the `config -> resolve` edge the layering table forbids, routed around in
//! one hop. Here the row's OWN edges are `error` and `git`'s pathspec
//! predicate, and neither is a module that loads a config.
//!
//! **What that does not claim.** The layering table decides over direct edges,
//! and `git` reaches `rules` (for its tree walker and glob selector), which
//! reaches `config`. So this module reaches the loader transitively — through
//! the `config <-> rules` cycle that already exists and that this split neither
//! adds to nor removes. What the split removed is the edge that was the row's
//! own: `step -> resolve`, with the loader naming `step`.

use std::collections::BTreeSet;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// One declared step: what its verdict depends on.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The step's name, as its caller passes it to `batten step`.
    pub id: String,
    /// Git pathspecs (no `:` magic) whose INDEX entries are key material. `.`
    /// is the whole tracked tree.
    ///
    /// The index rather than the worktree, and the worktree must agree with it
    /// over the set: a diverged or untracked path under a spec is no key at all.
    pub inputs: Vec<String>,
    /// Programs, as argv, whose stdout is key material: a tool's version, or
    /// the declaration of the step's own command. Each must exit 0 and print
    /// something, or there is no key.
    pub tools: Vec<Vec<String>>,
}

/// Refuse a row the cache cannot act on, at LOAD rather than at the first run.
///
/// Each refusal is a row that would otherwise answer the wrong thing silently:
/// no inputs would key a receipt to no file at all, so it would answer for any
/// tree; no tools would let a receipt outlive the toolchain that earned it; a
/// `:`-magic pathspec would select nothing and read as a clean set.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row's id.
pub fn validate(rows: &[Step]) -> Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for row in rows {
        if row.id.trim().is_empty() {
            return Err(UsageError::raise(String::from(
                "[[step]]: `id` is empty, so no caller could name the row",
            )));
        }
        if row.inputs.is_empty() {
            return Err(UsageError::raise(format!(
                "[[step]] {}: `inputs` is empty, so a receipt would answer for any tree — \
                 declare `.` for the whole tracked tree",
                row.id
            )));
        }
        if let Some(spec) = row
            .inputs
            .iter()
            .find(|spec| !crate::git::pathspec_is_supported(spec))
        {
            return Err(UsageError::raise(format!(
                "[[step]] {}: `{spec}` is not a pathspec this build reads (empty, or `:` magic), \
                 so it would select nothing and read as a clean set",
                row.id
            )));
        }
        if row.tools.is_empty() {
            return Err(UsageError::raise(format!(
                "[[step]] {}: `tools` is empty, so a receipt would outlive the toolchain that \
                 earned it",
                row.id
            )));
        }
        if row.tools.iter().any(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "[[step]] {}: a `tools` entry is an empty argv, which runs nothing",
                row.id
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "[[step]] {}: declared twice — one id, one key",
                row.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(inputs: &[&str], tools: &[&[&str]]) -> Step {
        Step {
            id: String::from("a-step"),
            inputs: inputs.iter().map(|spec| (*spec).to_owned()).collect(),
            tools: tools
                .iter()
                .map(|argv| argv.iter().map(|word| (*word).to_owned()).collect())
                .collect(),
        }
    }

    #[test]
    fn a_well_formed_row_loads() {
        validate(&[row(&["crates", "."], &[&["rustc", "--version"]])]).unwrap();
    }

    #[test]
    fn a_row_that_would_answer_the_wrong_thing_is_refused_at_load() {
        // Each of these parses and would decide wrongly in silence: no inputs key
        // nothing, no tools outlive the toolchain, a magic spec selects nothing,
        // and an empty argv runs nothing.
        for (bad, why) in [
            (row(&[], &[&["t"]]), "inputs"),
            (row(&[":(exclude)x"], &[&["t"]]), "pathspec"),
            (row(&[""], &[&["t"]]), "pathspec"),
            (row(&["a"], &[]), "tools"),
            (row(&["a"], &[&[]]), "empty argv"),
        ] {
            let refused = validate(&[bad]).unwrap_err().to_string();
            assert!(refused.contains(why), "{why}: {refused}");
        }
    }

    #[test]
    fn a_step_declared_twice_is_refused() {
        let refused = validate(&[row(&["a"], &[&["t"]]), row(&["b"], &[&["t"]])])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("declared twice"), "{refused}");
    }
}
