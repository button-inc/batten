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
    /// PARSED at load by [`validate`], so a malformed pattern is a config fault
    /// at exit `1` rather than an evaluation failure on the mediated path —
    /// house style §8's placement, and the same one `forbid`'s `regex` column
    /// already takes. Parsed rather than COMPILED, for the measured reason
    /// [`validate`] states.
    pub regex: String,
}

/// Refuse a malformed pattern table, at load.
///
/// Two rules, and both are about the table rather than about any predicate that
/// might use it:
///
/// * an id is non-empty and unique;
/// * the expression is a well-formed regular expression.
///
/// # The second rule PARSES; it does not compile
///
/// The registry is a table every config load walks, and a load happens on every
/// mediated call — the one path an agent waits on. So the cost of a row is paid
/// by every `batten hook`, whether or not any predicate on that call reads it,
/// and it is paid again for each row the campaign adds. `regex::Regex::new`
/// answers "is this well formed" and builds the matcher in one step, and the
/// second half is the expensive one: measured on this container, ten
/// `(?i)…[\s\S]*` rows cost **110 ms** through `Regex::new` and nothing
/// distinguishable from noise through the parser. Twenty-two rows of Ready
/// vocabulary took `wired` from 35.4 ms to 78.7 ms and `perf-compare` refused
/// the branch at 2.223x against a 1.30x threshold — the gate working, over a
/// cost the table's shape guarantees will keep growing.
///
/// **The answer is not weaker, it is the same answer asked at the layer that
/// holds it.** `regex-syntax` is `regex`'s own front end, at the version the
/// same lock already resolves, and it is what rejects a malformed expression
/// there too; `utf8(true)` is set explicitly rather than left to the default so
/// that a pattern able to match invalid UTF-8 — which `Regex` also refuses — is
/// refused here rather than at first use. What is no longer decided at load is
/// the compiled matcher's SIZE limit, which is a property of the built automaton
/// and not of the declaration; the site that builds it still names the id.
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
        regex_syntax::ParserBuilder::new()
            .utf8(true)
            .build()
            .parse(&pattern.regex)
            .map_err(|err| {
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

#[cfg(test)]
mod tests {
    use super::{NamedPattern, validate};

    fn row(id: &str, regex: &str) -> NamedPattern {
        NamedPattern {
            id: String::from(id),
            regex: String::from(regex),
        }
    }

    fn refusal(patterns: &[NamedPattern], why: &str) -> String {
        match validate(patterns) {
            Ok(()) => panic!("{why}"),
            Err(err) => format!("{err}"),
        }
    }

    /// The load-time refusal survived the move from compiling to parsing, which
    /// is the whole claim [`validate`]'s doc comment makes about it.
    #[test]
    fn a_malformed_expression_is_refused_at_load_and_names_its_id() {
        let text = refusal(
            &[row("tracker-key", "(unclosed")],
            "an unbalanced group is not a regular expression",
        );
        assert!(text.contains("tracker-key"), "{text}");
        assert!(text.contains("is not a valid expression"), "{text}");
    }

    /// The premise of the assertion above: this table is otherwise accepted, so
    /// the refusal is about the expression rather than about the shape.
    #[test]
    fn a_well_formed_expression_loads() {
        if let Err(err) = validate(&[row("tracker-key", r"(?i)[A-Z]+-[0-9]+")]) {
            panic!("a well-formed expression is not a config fault: {err}");
        }
    }

    /// `utf8(true)` is set explicitly, so the class `Regex::new` refuses is
    /// still refused here. Without that call the parser accepts this and the
    /// fault surfaces at first use instead — which is the one behaviour the
    /// cheaper validation could have quietly dropped.
    ///
    /// THE EXPRESSION IS ASSEMBLED RATHER THAN WRITTEN, and that is the premise
    /// confirming itself a second time: `clippy::invalid_regex` reads a literal
    /// argument and refuses this one at `-D warnings`, so the only way to hand a
    /// known-bad pattern to a run-time API is to keep it out of the literal.
    #[test]
    fn a_pattern_able_to_match_invalid_utf8_is_still_refused() {
        let raw = format!("{}{}", r"(?-u)", r"\xFF");
        assert!(
            regex::Regex::new(&raw).is_err(),
            "the premise: the compiler refuses this, so the parser must too"
        );
        let text = refusal(
            &[row("raw-byte", &raw)],
            "a pattern able to match invalid UTF-8 is a config fault",
        );
        assert!(text.contains("raw-byte"), "{text}");
    }

    /// One concept, one spelling — the rule that is about the table rather than
    /// about any one expression.
    #[test]
    fn an_id_declared_twice_is_refused() {
        let text = refusal(
            &[row("key", "a"), row("key", "b")],
            "two expressions cannot answer to one name",
        );
        assert!(text.contains("declared twice"), "{text}");
    }
}
