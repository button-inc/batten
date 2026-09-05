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

/// The repository-object keys [`derive_host`] reads.
///
/// Named once so the recogniser and the reader cannot drift: a payload is the
/// repository response iff it carries one of these, and every one of them is a
/// setting [`Host`] projects.
const HOST_KEYS: &[&str] = &[
    "delete_branch_on_merge",
    "web_commit_signoff_required",
    "security_and_analysis",
];

/// The `[host]` half's smell id (CLOUD-380).
pub const HOST_SETTING_DRIFT: &str = "host-setting-drift";

/// Repository settings the host decides and the tree projects (CLOUD-380).
///
/// **A projection a gate polices, never a second place the fact is decided** —
/// the same wording `[ci]` already carries, and the reason both tables exist:
/// the host is the authority, and a value here is a claim about the host that
/// something checks.
///
/// **Membership is decidable rather than a matter of taste: a setting belongs
/// here iff changing it WEAKENS a control.** That is the test `protected`
/// already uses one table over. Description, topics, homepage and visibility are
/// excluded by it — none of them gates anything — and the exclusion is what
/// keeps this from becoming a mirror of the whole repository object, which would
/// report drift every time somebody edits a sentence.
///
/// Every field is optional and `None` means **unclaimed**, never "false". A
/// consumer projecting one setting must not be told it disagrees about three it
/// never mentioned.
///
/// Measured: `delete_branch_on_merge` was set on the repository and nothing in
/// the tree said so, so turning it off would have removed it with no diff, no
/// gate and no notification. `ci-drift` established the right pattern for
/// exactly one host fact — the branch ruleset — and the generalisation was never
/// made.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Whether the host deletes a branch when its pull request merges.
    ///
    /// Off, stale branches accumulate and `branch-hygiene`'s subject drifts from
    /// what actually landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_branch_on_merge: Option<bool>,
    /// Whether the host requires a sign-off on web commits.
    ///
    /// Off, a commit can enter `main` through the web UI carrying none of the
    /// attribution `commit-attribution` decides over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_commit_signoff_required: Option<bool>,
    /// Whether the host blocks a push carrying a detected secret.
    ///
    /// Off, the last barrier before a secret reaches the remote is gone, and
    /// `no-secrets` only ever sees what a local run reached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_scanning_push_protection: Option<bool>,
}

/// Whether a JSON object is the repository response rather than some other
/// document (CLOUD-380).
///
/// Exposed so the caller routes on the same recogniser [`derive_host`] enforces,
/// instead of a second reading that could disagree with it.
#[must_use]
pub fn is_host_payload(object: &serde_json::Map<String, Value>) -> bool {
    HOST_KEYS.iter().any(|key| object.contains_key(*key))
}

/// Read the host's own view of these settings out of a `GET /repos/{owner}/{repo}`
/// response (CLOUD-380).
///
/// **A key the payload omits stays `None`**, which is could-not-look rather than
/// `false`: a token with no `administration` scope gets a response missing
/// `security_and_analysis` entirely, and reading that as "push protection is
/// off" would report drift the host never claimed.
///
/// # Errors
///
/// [`UsageError`] when the payload is not a JSON object — the repository
/// endpoint returns one, and an array is the branch-rules payload handed to the
/// wrong comparison.
pub fn derive_host(payload: &str) -> Result<Host> {
    let value: Value = serde_json::from_str(payload)
        .map_err(|err| UsageError::raise(format!("host settings payload is not JSON: {err}")))?;
    let Some(object) = value.as_object() else {
        return Err(UsageError::raise(
            "host settings payload is not a repository object; expected the response of `GET \
             /repos/{owner}/{repo}`"
                .to_owned(),
        ));
    };
    // A PAYLOAD CARRYING NONE OF THESE KEYS IS COULD-NOT-LOOK, NEVER AGREEMENT.
    // `{"message": "Not Found"}` is a JSON object too, and deriving `None` for
    // every field from it would compare clean against any projection — a failed
    // fetch reading as "the host agrees", which is the one answer this comparison
    // must never give.
    if !HOST_KEYS.iter().any(|key| object.contains_key(*key)) {
        return Err(UsageError::raise(
            "host settings payload carries none of the repository keys this compares; expected \
             the response of `GET /repos/{owner}/{repo}`"
                .to_owned(),
        ));
    }
    let flag = |key: &str| object.get(key).and_then(Value::as_bool);
    Ok(Host {
        delete_branch_on_merge: flag("delete_branch_on_merge"),
        web_commit_signoff_required: flag("web_commit_signoff_required"),
        secret_scanning_push_protection: object
            .get("security_and_analysis")
            .and_then(Value::as_object)
            .and_then(|analysis| analysis.get("secret_scanning_push_protection"))
            .and_then(Value::as_object)
            .and_then(|setting| setting.get("status"))
            .and_then(Value::as_str)
            .map(|status| status == "enabled"),
    })
}

/// Compare the committed `[host]` against what the host reports (CLOUD-380).
///
/// One [`Drift`] per disagreeing key, so a refusal names the key an author has
/// to edit rather than reporting that "something" differs — which is what
/// separates a real comparison from a non-zero exit on any non-200.
///
/// A key the config leaves unclaimed is skipped: this polices what the tree
/// says, and says nothing about what it does not.
#[must_use]
pub fn host_drift(committed: &Host, host: &Host) -> Vec<Drift> {
    let mut found = Vec::new();
    let mut compare = |key: &str, mine: Option<bool>, theirs: Option<bool>| {
        let (Some(mine), Some(theirs)) = (mine, theirs) else {
            return;
        };
        if mine != theirs {
            found.push(Drift {
                id: HOST_SETTING_DRIFT,
                key: format!("host.{key}"),
                // POINTER, NEVER PAYLOAD: which side claims what, as two tokens,
                // and never a byte of the host's response.
                tokens: vec![format!("-{mine}"), format!("+{theirs}")],
            });
        }
    };
    compare(
        "delete_branch_on_merge",
        committed.delete_branch_on_merge,
        host.delete_branch_on_merge,
    );
    compare(
        "web_commit_signoff_required",
        committed.web_commit_signoff_required,
        host.web_commit_signoff_required,
    );
    compare(
        "secret_scanning_push_protection",
        committed.secret_scanning_push_protection,
        host.secret_scanning_push_protection,
    );
    found
}

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
