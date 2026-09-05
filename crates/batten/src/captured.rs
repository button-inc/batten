//! Declared reductions over responses the agent already captured (CLOUD-1188).
//!
//! # Ten board gates are CLI verbs because they have nowhere to read from
//!
//! `rules/toolchain.md` names the family outright: each is *"a pure
//! function of stdin"* — payloads piped in by the caller, because no tracker
//! credential exists. They are pure predicates, and every one of them would be a
//! policy module if a fact channel existed. This is that channel.
//!
//! # The store, never stdin, and three independent reasons refuse it
//!
//! * **The surface table drops it before projection.** A stdin-fed fact declared
//!   [`crate::facts::Surface::Check`] is not admitted, so the module silently
//!   sees nothing — the dead-gate class, arrived at through the axis rather than
//!   through a missing key.
//! * **A payload on stdin is a payload something read**, which is context re-sent
//!   every turn. `ready lint` and `claim check` were both moved off that channel
//!   for this reason; re-introducing it here would undo two migrations.
//! * **The step-receipt key does not include stdin.** Two runs with different
//!   piped payloads over one unchanged tree hit the same receipt and skip — a
//!   false green, which is the exact failure this repository exists to prevent.
//!
//! [`crate::capture::list`] is sorted by handle rather than by time, so a
//! reduction here is a pure function of the store's bytes. That is what
//! `Surface::Check` requires and what stdin structurally cannot offer.
//!
//! # The reduction is part of the fact
//!
//! A fact carrying whole payloads would put a tracker's prose on the policy input
//! where any module could lift it into a `subjects` pointer — non-negotiable rule
//! 4 violated by construction rather than by carelessness. So a row declares WHAT
//! and HOW, the closed set of reductions is bounded by construction, and a
//! `token` over a value that is not already a token is REFUSED rather than
//! truncated: a prefix of an issue body is still an issue body.
//!
//! # Three answers, kept apart
//!
//! * **no capture answers a declared key** — absent from the map. Nothing has
//!   been captured about it.
//! * **a capture answers and the reduction yields nothing** — also absent, and
//!   the cause is recorded rather than inferred: a `present` reduction always
//!   yields, so an absent id under one is a key nothing matched.
//! * **no store, or nobody declared a reduction** — the whole fact is `None`,
//!   projected as `null`.
//!
//! A board gate reporting green over a store nobody filled is the vacuous pass in
//! its purest form, which is why the first and last may never collapse.

use std::collections::BTreeMap;
use std::path::Path;

use crate::facts::{CaptureQuery, Format};

/// The stream a captured RESPONSE is filed under.
///
/// Responses only: a captured command line or its stdout is not a payload
/// anything here claims to read, and reducing one would be this family answering
/// a question nobody asked it.
const RESPONSES: &str = "response";

/// Reduce each DECLARED row against the capture store.
///
/// **First match in HANDLE order**, which is [`crate::capture::list`]'s own sort,
/// so two runs over an unchanged store return the same answer — the byte
/// stability `Surface::Check` requires and the property a time-ordered store
/// could not offer.
///
/// **An id whose key nothing matched is ABSENT** from the result, never present
/// with a falsy value: "nothing has been captured about this" and "the capture
/// says no" are different answers, and a board gate acts on the second.
///
/// **`None` is the store being unreadable, and returning an empty map for it was
/// a live defect in this function's first draft.** The store is addressed under a
/// per-checkout state directory that is derived from an ABSOLUTE root, so a
/// caller handing over a relative one gets an error — and swallowing that into an
/// empty map is precisely the collapse the module header calls the vacuous pass
/// in its purest form. Measured: every declared row resolved to nothing and the
/// module read a clean, empty object rather than could-not-look.
///
/// The root is resolved here rather than trusted, so the honest answer and the
/// unreadable one stay apart for a reason a caller cannot accidentally cause.
#[must_use]
pub fn reduce(
    root: &Path,
    declared: &[CaptureQuery],
) -> Option<BTreeMap<String, serde_json::Value>> {
    // ABSOLUTE, because `state::derive_repo_name` refuses a relative root and
    // `check` does not promise one. A failure here is a store that could not be
    // addressed, which is could-not-look and never an empty answer.
    let root = std::fs::canonicalize(root).ok()?;
    let root = root.as_path();
    let captures = crate::capture::list(root).ok()?;
    // Read once per capture rather than once per (capture, row): a store holding
    // hundreds of responses and a config declaring several rows would otherwise
    // re-read the same bytes per row, which is the acquisition cost CLOUD-851
    // measured a 2.103x bill for one family over.
    let mut parsed: Vec<(String, Option<crate::facts::Node>)> = Vec::new();
    for capture in &captures {
        if capture.stream != RESPONSES {
            continue;
        }
        let Ok(bytes) = crate::capture::read(root, capture) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        // THROUGH `rules::parse_node`, which is the one `Format::read` call in
        // the crate (CLOUD-849): a second call site is a second error mapping,
        // and two mappings over one grammar diverge.
        parsed.push((
            text.clone(),
            crate::rules::parse_node(Format::Json, &text).ok(),
        ));
    }

    let mut found = BTreeMap::new();
    for row in declared {
        // The KEY selects the capture, by containment in the response's own
        // bytes. Containment rather than a parsed field, because which member
        // carries a key is a tracker's schema and non-negotiable rule 1 keeps
        // that out of this crate — the row names the token, the engine matches
        // it.
        let Some(node) = parsed
            .iter()
            .find(|(text, node)| text.contains(&row.key) && node.is_some())
            .and_then(|(_, node)| node.as_ref())
        else {
            // NOTHING HAS BEEN CAPTURED about this key, or what was captured did
            // not parse. Absent, never a falsy answer.
            continue;
        };
        if let Some(value) = row.reduce.apply(&node.at(&row.node)) {
            found.insert(row.id.clone(), value);
        }
    }
    Some(found)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::facts::{Format, Look, Node, Reduction, TOKEN_MAX};

    fn node(text: &str) -> Node {
        match Format::Json.read(text) {
            Look::Is(node) => node,
            Look::IsNot | Look::CouldNotLook => panic!("the fixture must parse"),
        }
    }

    #[test]
    fn a_token_reduction_refuses_prose() {
        // THE RULE-4 GUARANTEE, decided here rather than at the report. A value
        // carrying whitespace is a sentence, and a sentence on the policy input
        // is one any module can lift into a pointer.
        let parsed = node(r#"{"status": "In Progress", "state": "todo"}"#);
        assert_eq!(
            Reduction::Token.apply(&parsed.at("status")),
            None,
            "a value carrying whitespace is prose, not a token"
        );
        assert_eq!(
            Reduction::Token.apply(&parsed.at("state")),
            Some(serde_json::json!("todo")),
            "a bounded whitespace-free value is a token"
        );
    }

    #[test]
    fn an_over_long_token_is_refused_rather_than_truncated() {
        // TRUNCATION IS THE TEMPTING BUG: a prefix of an issue body is still an
        // issue body, so the bound refuses rather than shortens.
        let long = "x".repeat(TOKEN_MAX + 1);
        let parsed = node(&format!(r#"{{"key": "{long}"}}"#));
        assert_eq!(Reduction::Token.apply(&parsed.at("key")), None);
    }

    #[test]
    fn present_and_count_answer_over_an_absent_node() {
        // The two reductions whose ANSWER is "it is not there" — collapsing them
        // into absence would make a real negative indistinguishable from a key
        // nothing matched.
        let parsed = node(r#"{"labels": ["a", "b"]}"#);
        assert_eq!(
            Reduction::Present.apply(&parsed.at("nothing")),
            Some(serde_json::json!(false))
        );
        assert_eq!(
            Reduction::Count.apply(&parsed.at("nothing")),
            Some(serde_json::json!(0))
        );
        assert_eq!(
            Reduction::Count.apply(&parsed.at("labels")),
            Some(serde_json::json!(2))
        );
        assert_eq!(
            Reduction::Present.apply(&parsed.at("labels")),
            Some(serde_json::json!(true))
        );
    }

    #[test]
    fn a_token_over_an_absent_node_is_absent_rather_than_empty() {
        // An empty string would let a predicate comparing against `""` succeed
        // over a node nobody read — a verdict from an absence.
        let parsed = node(r#"{"labels": []}"#);
        assert_eq!(Reduction::Token.apply(&parsed.at("nothing")), None);
    }
}
