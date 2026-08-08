//! The mutating-verb table (CLOUD-36): which shell programs change the world?
//!
//! A guard that wants to refuse `rm` against managed state needs two things it
//! cannot invent — the set of paths that are protected, and the set of programs
//! that mutate. This module owns the second. It is the table and the lookup and
//! nothing else: crossing it with a path set is the gate CLOUD-96 builds on top
//! (`{verb ∈ this table} × {path ∈ protected}`), and the path sets themselves
//! are CLOUD-37's. Keeping the three apart is what lets each have one authority.
//!
//! Load-bearing choices:
//!
//! * **The table is config, never crate constants** (non-negotiable rule 1).
//!   Which programs count as mutating is a property of the repository being
//!   guarded — one repo's `terraform apply` is another's irrelevance — so
//!   `crates/batten` names no verb, and a grep for one returns zero hits.
//!   Batten's own table lives in Batten's own `batten.toml`, as consumer #1.
//! * **The severity axis is [`Effect`]**, the house-style §5 vocabulary, not a
//!   second one invented here. A verb is `write` or `destructive` — the same
//!   words a command's own effect entry uses — so `-y --yes` and the raise-only
//!   `max_effect` rule keep meaning one thing across the tool.
//! * **A verb carries its redirect.** The refusal contract (CLOUD-122) is that
//!   every deny names the fix, and the sanctioned mutation for a path class is
//!   knowledge the config author has and the core does not. Declaring it beside
//!   the verb is what keeps CLOUD-96's deny message out of the crate.
//! * **Lookup is exact on the program name, never a substring.** Matching
//!   loosely is how a guard denies `remove_stale_cache` because it contains
//!   `rm`; the *effective* program is what the caller passes in, and extracting
//!   it from a command line — wrapper lookthrough, env prefixes, quoted spans —
//!   is [`crate::hook`]'s parser, not a second one here.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effect::Effect;
use crate::error::UsageError;

/// One mutating program declared in `batten.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutatingVerb {
    /// The program name as it appears on a command line, e.g. the basename of
    /// the executable. Matched exactly.
    pub verb: String,
    /// What running it does, in the one effect vocabulary: `write` for state
    /// the caller can recreate, `destructive` for state whose recovery means
    /// redoing work.
    pub effect: Effect,
    /// The sanctioned mutation to point at when this verb is refused — the
    /// "run this instead" half of the refusal contract. Optional, because not
    /// every verb has an alternative; a consumer with none falls back to
    /// naming the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

impl MutatingVerb {
    /// Reject an entry that would make the table dishonest.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `verb`, for a `verb`
    /// carrying whitespace (a command line, not a program), or for an `effect`
    /// that does not describe a mutation. The last is the load-bearing one: a
    /// verb declared `read` in the *mutating*-verb table would sit there
    /// matching nothing while reading as covered — a gate that is present and
    /// inert, which is worse than an absent one.
    fn validate(&self) -> Result<()> {
        if self.verb.is_empty() {
            return Err(UsageError::raise("verb: `verb` must not be empty"));
        }
        if self.verb.split_whitespace().count() != 1 {
            return Err(UsageError::raise(format!(
                "verb {:?}: `verb` names one program, not a command line",
                self.verb
            )));
        }
        if !matches!(self.effect, Effect::Write | Effect::Destructive) {
            return Err(UsageError::raise(format!(
                "verb {}: `effect` must be \"{}\" or \"{}\", got \"{}\" — a non-mutating entry in \
                 the mutating-verb table is an inert gate",
                self.verb,
                Effect::Write.as_str(),
                Effect::Destructive.as_str(),
                self.effect.as_str()
            )));
        }
        Ok(())
    }
}

/// Validate a whole table, and refuse a duplicate declaration.
///
/// Two rows for one verb is a policy question with two answers — which effect,
/// which redirect — and silently taking the first is how a tightening edit gets
/// lost behind a stale row.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated entry.
pub fn validate(table: &[MutatingVerb]) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        entry.validate()?;
        if table[..index].iter().any(|prior| prior.verb == entry.verb) {
            return Err(UsageError::raise(format!(
                "verb {}: declared twice; a verb has one effect and one redirect",
                entry.verb
            )));
        }
    }
    Ok(())
}

/// Look `program` up in the table.
///
/// `None` means "not declared mutating", which for this primitive is simply an
/// absence of information — the conservative reading of an unknown program
/// belongs to the consumer's own policy (house-style §5: absence means *ask*,
/// never *safe*), not to a lookup.
///
/// Exact match, deliberately: `program` is the effective program a caller has
/// already extracted, and substring matching is how a guard refuses
/// `rmdir_helper` for containing a shorter verb.
#[must_use]
pub fn classify<'table>(
    table: &'table [MutatingVerb],
    program: &str,
) -> Option<&'table MutatingVerb> {
    table.iter().find(|entry| entry.verb == program)
}

/// Every verb in the table declaring exactly `effect`, in declaration order.
///
/// Derived from the effect each verb declares rather than from a second
/// hand-kept list — the same posture that makes the read-only allowlist a
/// `filter` over the effect table (house-style §5).
#[must_use]
pub fn with_effect(table: &[MutatingVerb], effect: Effect) -> Vec<&MutatingVerb> {
    table
        .iter()
        .filter(|entry| entry.effect == effect)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn verb(name: &str, effect: Effect) -> MutatingVerb {
        MutatingVerb {
            verb: name.to_owned(),
            effect,
            redirect: None,
        }
    }

    #[test]
    fn a_non_mutating_entry_is_refused_rather_than_kept_inert() {
        // A `read` row in the mutating-verb table would match nothing while
        // reading as covered — present and inert, which is worse than absent.
        for effect in [Effect::Read, Effect::Unclassified, Effect::Ask] {
            let err = verb("x", effect).validate().unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{} is not a mutation",
                effect.as_str()
            );
        }
        assert!(verb("x", Effect::Write).validate().is_ok());
        assert!(verb("x", Effect::Destructive).validate().is_ok());
    }

    #[test]
    fn a_verb_names_one_program_not_a_command_line() {
        assert!(verb("", Effect::Write).validate().is_err());
        assert!(verb("a b", Effect::Write).validate().is_err());
    }

    #[test]
    fn a_verb_declared_twice_is_a_usage_error() {
        let table = [verb("x", Effect::Write), verb("x", Effect::Destructive)];
        let err = validate(&table).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn lookup_is_exact_never_a_substring() {
        let table = [verb("x", Effect::Destructive)];
        assert!(classify(&table, "x").is_some());
        // The bug this pins: a guard that refuses a longer program for
        // containing a shorter verb.
        assert!(classify(&table, "xy").is_none());
        assert!(classify(&table, "yx").is_none());
        assert!(classify(&table, "").is_none());
    }

    #[test]
    fn the_source_bakes_in_no_verb() {
        // Non-negotiable rule 1, as a grep over this module's own source: which
        // programs mutate is the consumer's policy, so no real verb may appear
        // here as a literal. The tokens are assembled so the prose above — which
        // must be free to *discuss* the failure mode — is not itself a match.
        let source = include_str!("verbs.rs");
        for baked in [
            ["\"", "rm\""].concat(),
            ["\"", "mv\""].concat(),
            ["\"", "dd\""].concat(),
            ["\"", "truncate\""].concat(),
            ["\"", "shred\""].concat(),
        ] {
            assert!(
                !source.contains(&baked),
                "verbs source hardcodes {baked}; the table comes from batten.toml"
            );
        }
    }
}
