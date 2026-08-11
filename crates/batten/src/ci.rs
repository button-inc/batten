//! The merge contract, derived from the host ruleset (CLOUD-54).
//!
//! "Which checks must pass, and how may a branch land" is a fact every gate and
//! lifecycle task either reads from somewhere or hardcodes. The hardcode was
//! measured: required checks inlined, and `configured.unwrap_or("squash")` for
//! the merge method.
//!
//! # The host is the authority; `[ci]` is the projection
//!
//! The GitHub rules API exposes the merged contract, and it is the authority.
//! `[ci]` in `batten.toml` is a **derived** copy of it — never the reverse.
//!
//! A committed projection rather than a live fetch, deliberately: agents fetch,
//! gates decide. Deriving on every run would put a credentialed network call
//! inside a gate, and a gate that can fail because a token expired is not a gate.
//! The committed copy is offline, deterministic and `[epoch]`-observable; the
//! drift check is what keeps it from quietly becoming a second authority.
//!
//! # Why this cannot be a `[[rule]]` row
//!
//! No rule kind carries an external payload input, and the constraint is not a
//! pattern over the tree. It was tried both ways and both fail in opposite
//! directions: patterning `"--squash"` exits 0 against `unwrap_or("squash")` —
//! missing the hardcode — and patterning `"merge_method"` exits 2 against a
//! *correct* reader's own field. The computable form is "effective pair equals
//! host-derived pair", which is a set comparison, not a match.
//!
//! # Drift is symmetric
//!
//! Both directions are findings: a check the host requires and the config omits,
//! and a check the config claims and the host does not require. The second is
//! not harmless — a stale name in the projection is exactly what a downstream
//! reader would wait on forever.

use std::collections::BTreeSet;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::UsageError;

/// The `[ci]` table: this repository's committed copy of the host's contract.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ci {
    /// Exact check-run names the host requires, sorted and unique.
    ///
    /// Required when the table is present: a `[ci]` declaring no checks is the
    /// half-change rule 2 refuses — it looks like the contract is recorded when
    /// nothing is.
    pub required_checks: Vec<String>,
    /// The merge methods the host allows, sorted.
    ///
    /// Absent means **the host exposes no merge-method constraint**, which is a
    /// different claim from "no method is allowed". Legacy branch protection
    /// exposes none at all, so absence is the ordinary case rather than an
    /// omission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_merge_methods: Option<Vec<String>>,
}

/// The merge methods the host vocabulary admits.
///
/// Checked at parse so a typo is exit 1 rather than a set that silently never
/// matches the host's.
pub const MERGE_METHODS: &[&str] = &["merge", "rebase", "squash"];

impl Ci {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty or duplicated
    /// `required_checks`, or an unknown merge-method token.
    pub fn validate(&self) -> Result<()> {
        if self.required_checks.is_empty() {
            return Err(UsageError::raise(
                "ci.required_checks: declares no checks; a merge contract recording nothing is \
                 not a merge contract"
                    .to_owned(),
            ));
        }
        let unique: BTreeSet<&String> = self.required_checks.iter().collect();
        if unique.len() != self.required_checks.len() {
            return Err(UsageError::raise(
                "ci.required_checks: contains a duplicate; the host reports a set, and a repeated \
                 name means the projection was hand-edited"
                    .to_owned(),
            ));
        }
        if let Some(methods) = &self.allowed_merge_methods {
            for method in methods {
                if !MERGE_METHODS.contains(&method.as_str()) {
                    return Err(UsageError::raise(format!(
                        "ci.allowed_merge_methods: `{method}` is not one of {}",
                        MERGE_METHODS.join(", ")
                    )));
                }
            }
        }
        Ok(())
    }

    /// The contract as a comparable pair.
    fn pair(&self) -> Contract {
        Contract {
            required_checks: self.required_checks.iter().cloned().collect(),
            allowed_merge_methods: self
                .allowed_merge_methods
                .as_ref()
                .map(|methods| methods.iter().cloned().collect()),
        }
    }
}

/// A merge contract as sets, whichever side it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// Exact check-run names.
    pub required_checks: BTreeSet<String>,
    /// Allowed merge methods, or `None` for "the host constrains none".
    pub allowed_merge_methods: Option<BTreeSet<String>>,
}

/// Derive the contract from a rules-API response array.
///
/// A pure function of the payload — no network, no clock — which is what lets
/// the gate be a byte-stable comparison over caller-supplied data.
///
/// * required checks: the **union** of every `required_status_checks` rule's
///   contexts. Union because each rule adds an obligation, and a branch must
///   satisfy all of them.
/// * allowed merge methods: the **intersection** over `pull_request` rules that
///   carry the key. Intersection because each rule *narrows* what may be used,
///   and a method has to be permitted by every rule that speaks to it. No such
///   rule means no constraint, which is `None` rather than an empty set — the
///   two are opposite claims.
///
/// Unknown rule types are ignored: the host adds them over time, and a
/// derivation that failed on one would break the gate on a change nobody made.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the payload is not a JSON array.
/// A gate handed the wrong document must say so, not derive an empty contract
/// from it — an empty contract compared against a real `[ci]` would read as
/// drift, and compared against an absent one as agreement.
pub fn derive(payload: &str) -> Result<Contract> {
    let value: Value = serde_json::from_str(payload)
        .map_err(|err| UsageError::raise(format!("host rules payload is not JSON: {err}")))?;
    let Some(rules) = value.as_array() else {
        return Err(UsageError::raise(
            "host rules payload is not a rules-API array; expected the response of `GET \
             /repos/{owner}/{repo}/rules/branches/{branch}`"
                .to_owned(),
        ));
    };

    let mut required_checks = BTreeSet::new();
    let mut allowed_merge_methods: Option<BTreeSet<String>> = None;
    for rule in rules {
        match rule.get("type").and_then(Value::as_str) {
            Some("required_status_checks") => {
                let contexts = rule
                    .pointer("/parameters/required_status_checks")
                    .and_then(Value::as_array);
                for check in contexts.into_iter().flatten() {
                    if let Some(context) = check.get("context").and_then(Value::as_str) {
                        required_checks.insert(context.to_owned());
                    }
                }
            }
            Some("pull_request") => {
                let Some(methods) = rule
                    .pointer("/parameters/allowed_merge_methods")
                    .and_then(Value::as_array)
                else {
                    // A `pull_request` rule that does not speak to merge methods
                    // constrains none, so it narrows nothing.
                    continue;
                };
                let declared: BTreeSet<String> = methods
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect();
                allowed_merge_methods = Some(match allowed_merge_methods {
                    Some(existing) => existing.intersection(&declared).cloned().collect(),
                    None => declared,
                });
            }
            _ => {}
        }
    }

    Ok(Contract {
        required_checks,
        allowed_merge_methods,
    })
}

/// The smell ids this comparison can raise.
///
/// Named per half so a reader knows which key to edit without parsing prose.
pub const REQUIRED_CHECKS_DRIFT: &str = "ci-required-checks-drift";
/// The merge-method half's smell id.
pub const MERGE_METHODS_DRIFT: &str = "ci-allowed-merge-methods-drift";

/// One difference between the committed projection and the host's contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    /// The smell id.
    pub id: &'static str,
    /// The config key path this names.
    pub key: String,
    /// The differing tokens, sorted, each prefixed `+` (the host has it and the
    /// config does not) or `-` (the config claims it and the host does not).
    pub tokens: Vec<String>,
}

impl Drift {
    /// The token list as it renders in a pointer.
    #[must_use]
    pub fn rendered(&self) -> String {
        self.tokens.join(",")
    }
}

/// Compare the committed `[ci]` against the host-derived contract.
///
/// Empty when they agree. Both directions are reported: a token the host has and
/// the config lacks is `+`, one the config claims and the host does not is `-`.
#[must_use]
pub fn drift(committed: &Ci, host: &Contract) -> Vec<Drift> {
    let mine = committed.pair();
    let mut found = Vec::new();

    let checks = difference_tokens(&mine.required_checks, &host.required_checks);
    if !checks.is_empty() {
        found.push(Drift {
            id: REQUIRED_CHECKS_DRIFT,
            key: "ci.required_checks".to_owned(),
            tokens: checks,
        });
    }

    // `None` on either side is "no constraint", and it only agrees with `None`.
    // A host that constrains methods while the config omits the key is drift in
    // the dangerous direction — the projection silently claims freedom the host
    // does not grant.
    let methods = match (&mine.allowed_merge_methods, &host.allowed_merge_methods) {
        (None, None) => Vec::new(),
        (Some(mine), Some(host)) => difference_tokens(mine, host),
        (None, Some(host)) => host.iter().map(|token| format!("+{token}")).collect(),
        (Some(mine), None) => mine.iter().map(|token| format!("-{token}")).collect(),
    };
    if !methods.is_empty() {
        found.push(Drift {
            id: MERGE_METHODS_DRIFT,
            key: "ci.allowed_merge_methods".to_owned(),
            tokens: methods,
        });
    }
    found
}

/// The symmetric difference, sorted, signed by which side has each token.
fn difference_tokens(mine: &BTreeSet<String>, host: &BTreeSet<String>) -> Vec<String> {
    let mut tokens: Vec<String> = host
        .difference(mine)
        .map(|token| format!("+{token}"))
        .chain(mine.difference(host).map(|token| format!("-{token}")))
        .collect();
    tokens.sort();
    tokens
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The shape this repository's own host returns: one required check, and no
    /// `pull_request` rule at all.
    const RULES: &str = include_str!("../tests/fixtures/ci/rules-required-checks.json");
    /// A ruleset that also constrains merge methods.
    const RULES_WITH_METHODS: &str = include_str!("../tests/fixtures/ci/rules-merge-methods.json");
    /// Two `pull_request` rules whose method sets overlap.
    const RULES_TWO_PR_RULES: &str = include_str!("../tests/fixtures/ci/rules-two-pr-rules.json");
    /// A legacy branch-protection-shaped payload: no `pull_request` rule.
    const RULES_LEGACY: &str = include_str!("../tests/fixtures/ci/rules-legacy.json");

    fn ci(checks: &[&str], methods: Option<&[&str]>) -> Ci {
        Ci {
            required_checks: checks.iter().map(|check| (*check).to_owned()).collect(),
            allowed_merge_methods: methods
                .map(|methods| methods.iter().map(|m| (*m).to_owned()).collect()),
        }
    }

    #[test]
    fn required_checks_are_the_union_over_every_rule_that_declares_them() {
        let contract = derive(RULES).unwrap();
        assert_eq!(
            contract.required_checks,
            ["final".to_owned()].into_iter().collect()
        );
        assert_eq!(
            contract.allowed_merge_methods, None,
            "no `pull_request` rule means no constraint, which is not an empty set"
        );
    }

    #[test]
    fn merge_methods_are_the_intersection_because_each_rule_narrows() {
        // One rule: its own set.
        let one = derive(RULES_WITH_METHODS).unwrap();
        assert_eq!(
            one.allowed_merge_methods,
            Some(["squash".to_owned()].into_iter().collect())
        );

        // Two rules: only what both permit. Union would *widen* the contract
        // past what one of the rules allows, which is the dangerous direction.
        let two = derive(RULES_TWO_PR_RULES).unwrap();
        assert_eq!(
            two.allowed_merge_methods,
            Some(["squash".to_owned()].into_iter().collect()),
            "a method has to be permitted by every rule that speaks to it"
        );
    }

    #[test]
    fn a_legacy_payload_constrains_no_methods_and_still_yields_its_checks() {
        let contract = derive(RULES_LEGACY).unwrap();
        assert!(!contract.required_checks.is_empty());
        assert_eq!(contract.allowed_merge_methods, None);
    }

    #[test]
    fn an_unknown_rule_type_is_ignored_rather_than_fatal() {
        // The host adds rule types over time. Failing on one would break the
        // gate on a change nobody made.
        let payload = r#"[{"type":"some_future_rule","parameters":{"whatever":true}},
             {"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"final"}]}}]"#;
        let contract = derive(payload).unwrap();
        assert_eq!(
            contract.required_checks,
            ["final".to_owned()].into_iter().collect()
        );
    }

    #[test]
    fn a_payload_that_is_not_a_rules_array_is_a_usage_error() {
        // Never an empty contract: that would read as agreement against an
        // absent `[ci]` and as drift against a real one — two wrong answers from
        // one wrong document.
        for payload in ["{}", "\"a string\"", "17", "not json"] {
            let err = derive(payload).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{payload:?} must be a usage error"
            );
        }
        // An empty array IS a valid answer: a branch with no rules.
        let empty = derive("[]").unwrap();
        assert!(empty.required_checks.is_empty());
        assert_eq!(empty.allowed_merge_methods, None);
    }

    #[test]
    fn agreement_is_silence() {
        let host = derive(RULES).unwrap();
        assert!(drift(&ci(&["final"], None), &host).is_empty());
    }

    #[test]
    fn drift_is_reported_in_both_directions() {
        let host = derive(RULES).unwrap();

        // The host requires a check the config lacks.
        let missing = drift(&ci(&["other"], None), &host);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].id, REQUIRED_CHECKS_DRIFT);
        assert_eq!(missing[0].key, "ci.required_checks");
        assert_eq!(
            missing[0].rendered(),
            "+final,-other",
            "`+` is the host's, `-` is the config's — the sign says which to edit"
        );

        // The config claims a check the host does not require. Not harmless: a
        // stale name is what a downstream reader would wait on forever.
        let stale = drift(&ci(&["final", "ghost"], None), &host);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].rendered(), "-ghost");
    }

    #[test]
    fn a_host_constraint_the_config_omits_is_drift() {
        // The dangerous direction: the projection silently claims freedom the
        // host does not grant.
        let host = derive(RULES_WITH_METHODS).unwrap();
        let found = drift(&ci(&["final"], None), &host);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, MERGE_METHODS_DRIFT);
        assert_eq!(found[0].rendered(), "+squash");

        // And the reverse: the config constrains where the host does not.
        let unconstrained = derive(RULES).unwrap();
        let claimed = drift(&ci(&["final"], Some(&["squash"])), &unconstrained);
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].rendered(), "-squash");
    }

    #[test]
    fn a_table_that_records_nothing_is_refused() {
        assert!(ci(&[], None).validate().is_err());
        assert!(
            ci(&["final", "final"], None).validate().is_err(),
            "a duplicate means the projection was hand-edited"
        );
        assert!(ci(&["final"], Some(&["fast-forward"])).validate().is_err());
        assert!(ci(&["final"], Some(&["squash"])).validate().is_ok());
    }

    #[test]
    fn every_declared_method_token_validates() {
        // The vocabulary is a census, so a token added to `MERGE_METHODS`
        // without being accepted here would fail loudly.
        for method in MERGE_METHODS {
            assert!(ci(&["final"], Some(&[method])).validate().is_ok());
        }
    }
}
