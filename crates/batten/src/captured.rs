//! Declared reductions over responses the agent already captured (CLOUD-1188).
//!
//! # Ten board gates are CLI verbs because they have nowhere to read from
//!
//! `.claude/rules/toolchain.md` names the family outright: each is *"a pure
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

/// The most recent captured response whose scalar at `key_at` equals `key`.
///
/// [`crate::capture::find`]'s question with the tool filter removed, because a
/// `[[rule.captured]]` row names a key and a path and never a tool — see the
/// call site for why fabricating a tool list would be worse than omitting the
/// filter.
///
/// **Append order, taken from the end**, which is [`crate::capture::find_in`]'s
/// ordering and is chosen for its reason rather than copied: `order` is monotone
/// only WITHIN a session, so sorting by it lets a stale session outrank a live
/// one, while the log's append order is chronological across all of them and is
/// still a pure function of the log's bytes. So recency costs no clock and two
/// runs over an unchanged store agree.
///
/// Returns the response's text, so the caller parses it through the crate's one
/// [`crate::rules::parse_node`] call site rather than through a second mapping.
fn find_by_key_at(root: &Path, key: &str, key_at: &str) -> Option<String> {
    let selector = crate::capture::Selector {
        tools: &[],
        key,
        key_at,
    };
    let resolved = crate::capture::find_any_tool(root, &selector).ok()??;
    let bytes = crate::capture::read(root, &resolved.capture).ok()?;
    String::from_utf8(bytes).ok()
}

/// The stream a captured RESPONSE is filed under.
///
/// Responses only: a captured command line or its stdout is not a payload
/// anything here claims to read, and reducing one would be this family answering
/// a question nobody asked it.
const RESPONSES: &str = "response";

/// Reduce each DECLARED row against the capture store.
///
/// **How a row selects depends on whether it declared `key_at`**, and the two
/// arms answer different questions (CLOUD-1387).
///
/// With a path, the row resolves through [`crate::capture::find`]: the response
/// whose scalar at that path EQUALS the key, most recent first in the log's
/// append order. That is the record the key is the subject OF.
///
/// Without one, selection is byte containment and the **first match in HANDLE
/// order** answers — [`crate::capture::list`]'s own sort. That is every document
/// that MENTIONS the key, with a digest deciding between them, and it is why
/// `key_at` exists; it stays the default only so a landed row does not change
/// verdict underneath a consumer.
///
/// Both arms are byte-stable, which is what `Surface::Check` requires: handle
/// order is a sort, and append order is a pure function of the log's bytes. A
/// time-ordered store could offer neither.
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
        // A DECLARED PATH SELECTS THE RECORD THE KEY IS THE SUBJECT OF, through
        // the same resolver `capture find --key-at` uses. One authority on what
        // "the capture for this key" means, rather than two that can disagree.
        //
        // Rule 1 is intact either way: the path is the ROW's, so no tracker field
        // name reaches this crate — the engine reads what it was handed, exactly
        // as it does for `node`.
        let owned;
        let node = if let Some(key_at) = row.key_at.as_deref() {
            // No tool filter: a `[[rule.captured]]` row names a key and a path,
            // never a tool, and inventing a default here would silently exclude
            // whichever tool a consumer's response came from. `Selector`'s tools
            // are matched with `any`, so an empty slice is "no tool matches" —
            // hence the dedicated resolver below rather than a `find` call with
            // a fabricated list.
            let Some(text) = find_by_key_at(root, &row.key, key_at) else {
                // NOTHING CAPTURED CARRIES THIS KEY AT THIS PATH. Absent, never
                // a falsy answer — the could-not-look arm the module reads.
                continue;
            };
            let Ok(parsed) = crate::rules::parse_node(Format::Json, &text) else {
                continue;
            };
            owned = parsed;
            &owned
        } else {
            // THE LEGACY ARM: containment over the response's own bytes, first
            // match in handle order. Kept so a row that declared no path does
            // not change verdict, and no longer the recommended shape — see
            // `CaptureQuery::key_at` for what it costs (CLOUD-1387).
            let Some(node) = parsed
                .iter()
                .find(|(text, node)| text.contains(&row.key) && node.is_some())
                .and_then(|(_, node)| node.as_ref())
            else {
                // Nothing captured about this key, or what was captured did not
                // parse. Absent, never a falsy answer.
                continue;
            };
            node
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
