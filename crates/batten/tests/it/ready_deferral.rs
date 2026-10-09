//! Deferral claims held to the board, over the compiled binary (CLOUD-197),
//! ported off `tests/ready-lint-deferral.bats` under CLOUD-1221.
//!
//! An issue that says an obligation is someone else's — "deferred to <key>" — is
//! asserting a hand-off. Without a relation the board does not know about it, and
//! the obligation belongs to nobody. The hard half is NOT flagging the
//! cross-references that make issues readable: comparisons, provenance and "see
//! also" mention keys without handing anything off.
//!
//! The suite exercised `mise-tasks/ready-lint.sh`; its successor is
//! `batten ready lint` over `crate::ready`, which `tests/ready-lint.bats`'s
//! ledger in `crates/batten/tests/it/ready.rs` already names. The exit codes
//! moved as that ledger records, uniformly: a violation is `2` here where it was
//! `1`, and could-not-look is `1` where it was `2`.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: tests/ready-lint-deferral.bats crates/batten/src/ready.rs kind:verb crates/batten/tests/it/ready_deferral.rs
//!
//! # RETIREMENT LEDGER — `tests/ready-lint-deferral.bats`, 14 cases
//!
// carried: "a deferral with no relation is reported" crates/batten/tests/it/ready_deferral.rs
// carried: "the same deferral with a relation passes" crates/batten/tests/it/ready_deferral.rs
// carried: "ownership phrasing is a hand-off too" crates/batten/tests/it/ready_deferral.rs
// carried: "a deferral outside the Ready block still counts" crates/batten/tests/it/ready_deferral.rs
// carried: "Linear's stored mention markup is the same case as the rendered form" crates/batten/tests/it/ready_deferral.rs
// carried: "any relation direction satisfies it — a deferral is not always a blocker" crates/batten/tests/it/ready_deferral.rs
// carried: "a comparison is not a hand-off" crates/batten/tests/it/ready_deferral.rs
// carried: "provenance is not a hand-off" crates/batten/tests/it/ready_deferral.rs
// carried: "a bare cross-reference is not a hand-off" crates/batten/tests/it/ready_deferral.rs
// carried: "an id far from the verb is not what was deferred" crates/batten/tests/it/ready_deferral.rs
// carried: "an issue cannot defer to itself" crates/batten/tests/it/ready_deferral.rs
// carried: "output is a pointer — a line number and a rule id, never the prose" crates/batten/tests/it/ready_deferral.rs
// carried: "a payload with no relations key is a gap, not a parse failure and not a verdict" crates/batten/tests/it/ready_deferral.rs
// carried: "the same body with the key present and empty is still held to the board" crates/batten/tests/it/ready_deferral.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, declared_patterns, run_with_stdin, stderr};

/// A repository declaring this consumer's Ready grammar.
fn repo(name: &str) -> PathBuf {
    Fixture::new(&format!("ready-deferral-{name}"))
        .config(&format!("version = 1\n\n{}", declared_patterns()))
        .file("Cargo.toml", "[workspace.package]\nversion = \"0.0.125\"\n")
        .git()
        .base_commit()
        .build()
}

/// The suite's body: a minimal Ready block whose only clause is a §8 heading, a
/// Done section, and `prose` after it.
fn body(prose: &str) -> String {
    format!("## Ready\n\nA thing.\n\n### Blockers (§8)\n\nNone.\n\n## Done\n\n{prose}")
}

/// A payload whose relations carry `related` as `relatedTo` edges.
fn issue(prose: &str, related: &[&str]) -> String {
    serde_json::json!({
        "id": "CLOUD-1",
        "status": "Todo",
        "relations": {
            "blockedBy": [],
            "relatedTo": related
                .iter()
                .map(|id| serde_json::json!({ "id": id }))
                .collect::<Vec<_>>(),
        },
        "description": body(prose),
    })
    .to_string()
}

fn lint(dir: &Path, payload: &str) -> Output {
    run_with_stdin(dir, &["ready", "lint"], payload)
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

#[test]
fn a_deferral_with_no_relation_is_reported() {
    let dir = repo("unlinked");
    let output = lint(&dir, &issue("The wiring is deferred to CLOUD-61.", &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("deferral-cited-without-relation (CLOUD-61)"));
}

#[test]
fn the_same_deferral_with_a_relation_passes() {
    let dir = repo("linked");
    let output = lint(
        &dir,
        &issue("The wiring is deferred to CLOUD-61.", &["CLOUD-61"]),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn ownership_phrasing_is_a_hand_off_too() {
    let dir = repo("owned");
    let output = lint(&dir, &issue("That transition is owned by CLOUD-174.", &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
}

#[test]
fn a_deferral_outside_the_ready_block_still_counts() {
    // Deferrals live in Done, Open questions and out-of-scope notes — exactly
    // where an obligation is most likely to be quietly abandoned.
    let dir = repo("outside");
    let output = lint(
        &dir,
        &issue(
            "## Open questions\n\nThe general migration belongs to CLOUD-14.",
            &[],
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
}

#[test]
fn the_stored_mention_markup_is_the_same_case_as_the_rendered_form() {
    let dir = repo("markup");
    let output = lint(
        &dir,
        &issue(
            r#"Deferred to <issue id="x" href="y">CLOUD-61</issue>."#,
            &[],
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("CLOUD-61"));
}

#[test]
fn any_relation_direction_satisfies_it_since_a_deferral_is_not_always_a_blocker() {
    // Demanding blockedBy specifically would push authors to declare false
    // dependencies to pass the lint.
    let dir = repo("direction");
    let output = lint(&dir, &issue("Deferred to CLOUD-61.", &["CLOUD-61"]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_comparison_is_not_a_hand_off() {
    let dir = repo("comparison");
    let output = lint(
        &dir,
        &issue("This is the same failure shape as CLOUD-195.", &[]),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn provenance_is_not_a_hand_off() {
    let dir = repo("provenance");
    let output = lint(
        &dir,
        &issue(
            "Split out of CLOUD-177, which is Done on its own scope.",
            &[],
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_bare_cross_reference_is_not_a_hand_off() {
    let dir = repo("see-also");
    let output = lint(
        &dir,
        &issue(
            "See CLOUD-33 for the most refined example in the corpus.",
            &[],
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_id_far_from_the_verb_is_not_what_was_deferred() {
    // "<a> blocks this, deferred to <b>" hands off <b> only.
    let dir = repo("far");
    let output = lint(
        &dir,
        &issue(
            "CLOUD-9 describes the shape. Deferred to CLOUD-10.",
            &["CLOUD-10"],
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_issue_cannot_defer_to_itself() {
    let dir = repo("itself");
    let output = lint(&dir, &issue("Deferred to CLOUD-1.", &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn output_is_a_pointer_never_the_prose() {
    let dir = repo("pointer");
    let output = lint(
        &dir,
        &issue(
            "The confidential wiring detail is deferred to CLOUD-61.",
            &[],
        ),
    );
    let text = format!("{}{}", common::stdout(&output), stderr(&output));
    assert!(!text.contains("confidential wiring detail"), "{text}");
    assert!(text.contains("CLOUD-1:"), "{text}");
}

/// One body, two payloads, differing only in the relations key — so the §8
/// clause clears the floor and the gap is the SOLE reason the verdict is
/// incomplete.
fn defer_body() -> String {
    body("The wiring is deferred to CLOUD-61.")
}

#[test]
fn a_payload_with_no_relations_key_is_a_gap_not_a_parse_failure_and_not_a_verdict() {
    let dir = repo("gap");
    let payload = serde_json::json!({
        "id": "CLOUD-1",
        "status": "Todo",
        "description": defer_body(),
    })
    .to_string();
    let output = lint(&dir, &payload);
    // Could-not-look is this verb's usage exit, never the verdict's `2`.
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("issue grade partial"), "{text}");
    assert!(!text.contains("deferral-cited-without-relation"), "{text}");
    // Still parsed: the id resolved, so this is not the description refusal.
    assert!(text.contains("CLOUD-1:"), "{text}");
    assert!(!text.contains("not a get_issue payload"), "{text}");
}

#[test]
fn the_same_body_with_the_key_present_and_empty_is_still_held_to_the_board() {
    // "No edges" is an answer, so the hand-off is one this board does not know
    // about. Only the key differs from the case above.
    let dir = repo("present");
    let payload = serde_json::json!({
        "id": "CLOUD-1",
        "status": "Todo",
        "relations": { "blockedBy": [], "relatedTo": [] },
        "description": defer_body(),
    })
    .to_string();
    let output = lint(&dir, &payload);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("deferral-cited-without-relation (CLOUD-61)"));
}
