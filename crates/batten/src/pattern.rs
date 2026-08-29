//! Named regular expressions, declared in the one committed authority
//! (CLOUD-885).
//!
//! # Why a pattern may not be written inline in a module
//!
//! Enabling `regorus`'s `regex` builtin gave a policy module the matching
//! vocabulary [`crate::rules::RuleKind::Forbid`] has carried since CLOUD-283.
//! It also handed 86 queued bash migrations the closest-looking thing to the
//! `grep -E`/`sed -E`/`awk` they are being translated from, and a translator
//! reaches for whatever is cheapest to write.
//!
//! **The lever is cost, not prohibition.** A rule saying "do not regex things
//! that are not regular" cannot be a gate: "is this pattern parsing something
//! non-regular" is a judgement, and non-negotiable rule 3 says a gate resolves
//! to a command and an exit code over an object it decides. What *is* decidable
//! is where a pattern lives. So a regex costs a declaration — an id and a row in
//! `batten.toml` — while asking the same question of a parsed document or a
//! resolved invocation costs a field access. One-off patterns get priced; shared
//! ones stay cheap after the first.
//!
//! # Three things fall out, and none of them is friction for its own sake
//!
//! **Non-negotiable rule 1.** A tracker key — `TEAM-[0-9]+`, whatever the
//! consumer's team prefix happens to be — is a *consumer* identifier. Written
//! into a module under `crates/batten` it is a repo-agnosticism violation of
//! exactly the kind rule 1 names; written here it is where consumer facts
//! belong. `no-tracker-key-in-core` is the mechanism, and this paragraph is
//! written with a NEUTRAL prefix for the reason that row exists: spelling the
//! gated repository's own key here would make the doc explaining the rule the
//! first thing the rule fires on. [`crate::verbs::MutatingVerb`] already states this argument for the
//! mutating-verb table — "consumer-specific by nature, so it lives here and
//! never in the crate" — and this is the same table shape for the same reason.
//!
//! **Duplication becomes unwritable rather than detectable.** Measured on the
//! tree this engine gates, 2026-08-22 with comments stripped: 82 of 140 shell
//! programs use `grep -E`/`sed -E`/`awk`/`=~` over 338 sites, and one concept —
//! a tracker key — carries **19 distinct spellings across 17 programs**. The
//! bare `<prefix>-[0-9]+` form alone sits at 15 sites in 9 of them, with a glob
//! spelling beside the regexes and one program holding two variants of its own
//! pattern 52 lines apart. Those are correct regexes over a genuinely regular
//! thing, duplicated until they drifted. A named declaration has one home, so
//! the second author finds the first one's work instead of re-deriving it.
//!
//! **The inventory becomes reviewable data** (house style §11). Every pattern
//! the policy set can apply is readable out of one file, which is not true of
//! any tree where they are written inline.
//!
//! # What a module sees
//!
//! The set is projected into the evaluator's `data` document, so a reference
//! reads `data.batten.patterns["tracker-key"]`. It is deliberately NOT on
//! `input`: `input` is the subject under adjudication and changes per call,
//! while this is configuration, fixed for the life of the load.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// One declared regular expression.
///
/// Mirrors [`crate::verbs::MutatingVerb`]'s shape deliberately: a consumer-owned
/// table in the one committed authority, keyed by an id the config author picks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedPattern {
    /// The name a module references it by — the key under
    /// `data.batten.patterns`.
    ///
    /// Unique across the table. A repeated id would make
    /// `data.batten.patterns["x"]` ambiguous, and "which declaration answered
    /// me" is not a question a reviewer should have to resolve — the same
    /// reasoning [`crate::policy`] applies to two rows registering one module.
    pub id: String,
    /// The expression itself.
    ///
    /// Compiled at load by [`validate`], so a malformed pattern is a config
    /// fault at exit `1` rather than an evaluation failure on the mediated path
    /// — house style §8's placement, and the same one `forbid`'s `regex` column
    /// already takes.
    pub regex: String,
}

/// Refuse a malformed pattern table, at load.
///
/// Two rules, and both are about the table rather than about any predicate that
/// might use it:
///
/// * an id is non-empty and unique;
/// * the expression compiles.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the offending id. The expression itself is
/// a **declaration** — a literal the config author wrote, the class `config
/// show` exists to echo — so naming it is inside non-negotiable rule 4, and
/// without it a refusal over a malformed pattern could not be acted on.
pub fn validate(patterns: &[NamedPattern]) -> anyhow::Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for pattern in patterns {
        if pattern.id.trim().is_empty() {
            return Err(UsageError::raise(String::from(
                "pattern: `id` cannot be blank — it is the name a module references, \
                 and an empty one names nothing",
            )));
        }
        if !seen.insert(pattern.id.as_str()) {
            return Err(UsageError::raise(format!(
                "pattern `{}` is declared twice; one concept, one spelling — \
                 `data.batten.patterns[\"{}\"]` cannot resolve to two expressions",
                pattern.id, pattern.id
            )));
        }
        regex::Regex::new(&pattern.regex).map_err(|err| {
            UsageError::raise(format!(
                "pattern `{}`: `{}` is not a valid expression: {err}",
                pattern.id, pattern.regex
            ))
        })?;
    }
    Ok(())
}

/// The table as the evaluator's `data` document carries it.
///
/// `{"batten": {"patterns": {"<id>": "<regex>"}}}` — a flat map, because a
/// module's whole use of it is one lookup by name.
#[must_use]
pub fn data_document(patterns: &[NamedPattern]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for pattern in patterns {
        map.insert(
            pattern.id.clone(),
            serde_json::Value::from(pattern.regex.as_str()),
        );
    }
    serde_json::json!({ "batten": { "patterns": serde_json::Value::Object(map) } })
}
