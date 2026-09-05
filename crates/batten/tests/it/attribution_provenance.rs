//! `sha -> {model, harness, session}` over the guard-decision log (CLOUD-275).
//!
//! # Why the join is owed at all
//!
//! CLOUD-268 moved model, harness and session identifiers out of durable public
//! commit text, and `batten attribution` enforces that suppression over produced
//! commits. Suppression alone would trade an unreliable public signal for
//! nothing, so the operational question — which harness, model and session
//! produced a change — has to stay answerable somewhere. The guard-decision
//! record already reserves all three fields (CLOUD-133) and already anchors
//! itself to a commit; what was missing is the query that reads them back.
//!
//! # The distinction every case here is oriented on
//!
//! **No rows and `unknown` rows are different answers.** No rows means the log
//! holds nothing anchored to this commit: the could-not-look case, and the
//! ordinary state of a commit made outside a mediated session. A row valued
//! `unknown` means a record exists and the host exposed no identity. Collapsing
//! them makes a gap read as a fact, which is CLOUD-251's trap arriving in this
//! surface — so the degraded case is the discriminating one, and it asserts the
//! fields are PRESENT rather than merely not wrong.
//!
//! # A grouping, never a merge
//!
//! A commit can carry many records, and they can disagree — two sessions, or a
//! tree that went dirty between two calls. Folding them into one row would
//! invent a fact no record carries, so the query groups and counts, and a
//! consumer that gets two rows knows the question had two answers.
//!
//! # The declared mutation, and why the row is in THIS file
//!
//! `obligations-bound` reads the declared file's own lines for a row beginning
//! `#MUTANT <slug>|`, and its `line_sources` covers `crates/batten/tests/**` and
//! not `crates/batten/src/**` — so the row lives here even though the expression
//! it applies belongs to `decision.rs`'s degradation. A block comment because
//! the match is on a line PREFIX and Rust has no line comment starting with `#`.
//!
//! The mutation is the row's own: stop rendering the degraded token, so a field
//! the host did not declare serializes empty and reads back as `Declared("")`
//! rather than `unknown`. It reddens the degraded case and leaves the other
//! three green — the axis, rather than the query.
//!
//! **The first spelling of it survived, which is why this one is written down.**
//! It mutated `Provenance::from_host`, on the reading that degradation happens
//! where a host value is normalized. `Caller::undeclared()` constructs
//! `Provenance::Unknown` directly and never calls `from_host`, so the case did
//! not touch the mutated conjunct at all: declared, survived, green. Choosing a
//! mutation over the path a case actually walks is the whole discipline, and
//! running it is the only thing that tells you which one you picked.

/*
#MUTANT-SUITE crates/batten/tests/it/attribution_provenance.rs
#MUTANT degraded-field-not-unknown|s@            Provenance::Unknown => UNKNOWN,@            Provenance::Unknown => "",@|the_degraded_host_answers_unknown_in_every_field
*/
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::Path;

use batten::decision::{
    Anchor, Caller, ContextPointer, DECISION_SCHEMA, DecisionRecord, Outcome, Provenance,
    RecordedAt, Subject, UNKNOWN, append, attribution_for,
};
use batten::identity::{FindingKind, SpanNormalization, StoredIdentity, code_fingerprint};
use batten::{identity, state};

use common::Fixture;

/// A commit sha that is not the one under test, so a case can prove the query
/// filters rather than returning the whole log.
const OTHER: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

/// The sha every case queries.
fn subject_commit() -> String {
    "a".repeat(40)
}

/// A record anchored to `commit`, carrying `caller`, with everything else fixed
/// so a case varies one thing.
///
/// `subject` and `context` carry real planted content, because one case below
/// asserts that none of it reaches the query's answer. A fixture that left them
/// empty would pass that case for the wrong reason.
fn record_for(commit: &str, dirty: bool, caller: Caller) -> DecisionRecord {
    DecisionRecord {
        schema: DECISION_SCHEMA,
        config_epoch: "epoch-1".to_owned(),
        repo: "fixture".to_owned(),
        anchor: Anchor {
            commit: commit.to_owned(),
            reference: Some("refs/heads/main".to_owned()),
            dirty,
        },
        recorded_at: RecordedAt::from_unix_seconds(1_700_000_000),
        gate_id: "protected-mutation".to_owned(),
        rule_version: "1".to_owned(),
        outcome: Outcome::Violation,
        subject: Subject::identified(StoredIdentity::new(
            FindingKind::Code,
            code_fingerprint(
                "r",
                "src/secret-path.rs",
                "let planted = \"payload\";",
                SpanNormalization::Collapsed,
            )
            .unwrap(),
        )),
        context: ContextPointer::digest(
            identity::context_fingerprint(b"planted context bytes"),
            21,
        ),
        caller,
    }
}

/// Drop this repository's state directory, so a case reads only what it wrote.
fn clear_state(repo_root: &Path) {
    if let Ok(dir) = state::repo_state_dir(repo_root) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// A fixture repository with the given records already in the log.
fn log_with(name: &str, records: &[DecisionRecord]) -> std::path::PathBuf {
    let dir = Fixture::new(name).config("version = 1\n").git().build();
    clear_state(&dir);
    for record in records {
        append(&dir, &dir, record).expect("append a decision record");
    }
    dir
}

#[test]
fn the_join_answers_a_mediated_commit_with_all_three_fields() {
    // The end-to-end case: a record taken during a mediated session, read back
    // by the sha the commit carries.
    let commit = subject_commit();
    let dir = log_with(
        "attribution-join",
        &[record_for(
            &commit,
            false,
            Caller::from_host(Some("some-model"), Some("claude-code"), Some("session-1")),
        )],
    );

    let found = attribution_for(&dir, &commit).expect("query the log");
    assert_eq!(
        found.len(),
        1,
        "one caller answered for this sha: {found:?}"
    );
    assert_eq!(found[0].commit, commit);
    assert_eq!(found[0].caller.model_id.as_str(), "some-model");
    assert_eq!(found[0].caller.harness.as_str(), "claude-code");
    assert_eq!(found[0].caller.session.as_str(), "session-1");
    assert_eq!(found[0].records, 1);
    assert!(!found[0].dirty);
}

#[test]
fn the_degraded_host_answers_unknown_in_every_field() {
    // THE DISCRIMINATING CASE, and the one the declared mutation reddens. A host
    // exposing no identity yields three fields PRESENT and valued `unknown` —
    // never a short record, because absent and unknown are different answers.
    let commit = subject_commit();
    let dir = log_with(
        "attribution-degraded",
        &[record_for(&commit, false, Caller::undeclared())],
    );

    let found = attribution_for(&dir, &commit).expect("query the log");
    assert_eq!(found.len(), 1, "a degraded record still answers: {found:?}");
    assert_eq!(found[0].caller.model_id.as_str(), UNKNOWN);
    assert_eq!(found[0].caller.harness.as_str(), UNKNOWN);
    assert_eq!(found[0].caller.session.as_str(), UNKNOWN);
    assert_eq!(
        found[0].caller.model_id,
        Provenance::Unknown,
        "degraded, not a host that literally declared the token"
    );

    // The other half of the distinction, in the same case so neither can drift:
    // a sha the log knows nothing about answers with NO rows, which is not the
    // same as a row full of `unknown`.
    let absent = attribution_for(&dir, OTHER).expect("query the log");
    assert!(
        absent.is_empty(),
        "an unrecorded sha is empty, never an unknown row: {absent:?}"
    );
}

#[test]
fn the_answer_is_byte_stable_across_runs() {
    // §6. Two queries over one log render identically, whatever order the shards
    // were read in — the property a consumer diffing two runs depends on, and
    // the one a `read_dir` order would quietly break.
    let commit = subject_commit();
    let dir = log_with(
        "attribution-stable",
        &[
            record_for(
                &commit,
                false,
                Caller::from_host(Some("model-b"), Some("cursor"), Some("s2")),
            ),
            record_for(
                &commit,
                false,
                Caller::from_host(Some("model-a"), Some("claude-code"), Some("s1")),
            ),
            record_for(&commit, true, Caller::undeclared()),
        ],
    );

    let first = attribution_for(&dir, &commit).expect("query the log");
    let second = attribution_for(&dir, &commit).expect("query the log again");
    assert_eq!(first, second, "two runs over one log agree");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap(),
        "and render the same bytes"
    );

    // A GROUPING, NEVER A MERGE: three records that disagree are three rows, so
    // a consumer sees that the question had three answers rather than one the
    // query picked.
    assert_eq!(
        first.len(),
        3,
        "disagreeing records stay distinct: {first:?}"
    );
    assert!(
        first.iter().any(|row| row.dirty),
        "the dirty record keeps its own row: {first:?}"
    );
}

#[test]
fn no_planted_subject_or_context_byte_reaches_the_answer() {
    // Non-negotiable rule 4, asserted over the rendered answer rather than over
    // the type: the record carries a real path and real context bytes, and the
    // query's output must carry neither. Structural rather than a rendering
    // choice — `subject` and `context` are not fields of the answer at all — and
    // this is what would catch a later author adding one "for context".
    let commit = subject_commit();
    let dir = log_with(
        "attribution-pointer-only",
        &[record_for(
            &commit,
            false,
            Caller::from_host(Some("some-model"), Some("claude-code"), Some("session-1")),
        )],
    );

    let rendered = serde_json::to_string(&attribution_for(&dir, &commit).expect("query the log"))
        .expect("render the answer");
    for planted in [
        "secret-path",
        "planted",
        "payload",
        "context bytes",
        "protected-mutation",
    ] {
        assert!(
            !rendered.contains(planted),
            "the answer leaked {planted}: {rendered}"
        );
    }
}
