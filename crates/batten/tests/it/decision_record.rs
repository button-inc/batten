//! The guard-decision telemetry record's acceptance pack (CLOUD-133).
//!
//! An integration target over the **library** surface, not the compiled binary:
//! the record mints no subcommand — surfacing it is CLOUD-275's — so
//! `mise run test` is its gate, the way it is for `tests/primitives.rs` and
//! `tests/identity_churn.rs`. It is here rather than inline in
//! `crates/batten/src/decision.rs` for the two reasons that pack states: the
//! fixture materializer is `tests/common` (CLOUD-63), and the claims below span
//! three modules — `epoch` computes the stamp, `identity` mints the pointers,
//! `decision` renders and stores the line.
//!
//! Each case is one clause of the issue's acceptance:
//!
//! * byte-stable bytes,
//! * `config_epoch` + caller provenance present on **every** record,
//! * the CLOUD-32 stamp-join round-trips (this issue's stated hand-off),
//! * no raw subject or context content reaches the line,
//! * schema round-trip through the store, and a rewritten line rejected.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::Path;

use batten::decision::{
    Anchor, Caller, ContextPointer, DECISION_SCHEMA, DecisionRecord, Outcome, RecordedAt, Subject,
    UNKNOWN, append, load_all, shard_path, verify_append_only,
};
use batten::identity::{FindingKind, SpanNormalization, StoredIdentity, code_fingerprint};
use batten::{epoch, identity, state};

use common::Fixture;

/// A record over `epoch`, with everything else fixed so a case varies one thing.
fn record_at(epoch_value: &str, caller: Caller) -> DecisionRecord {
    DecisionRecord {
        schema: DECISION_SCHEMA,
        config_epoch: epoch_value.to_owned(),
        repo: "fixture".to_owned(),
        anchor: Anchor {
            commit: "a".repeat(40),
            reference: Some("refs/heads/main".to_owned()),
            dirty: false,
        },
        recorded_at: RecordedAt::from_unix_seconds(1_700_000_000),
        gate_id: "protected-mutation".to_owned(),
        rule_version: "1".to_owned(),
        outcome: Outcome::Violation,
        subject: Subject::identified(StoredIdentity::new(
            FindingKind::Code,
            code_fingerprint("r", "src/a.rs", "let x = 1;", SpanNormalization::Collapsed).unwrap(),
        )),
        context: ContextPointer::digest(identity::context_fingerprint(b"context bytes"), 13),
        caller,
    }
}

/// The host-declared caller most cases use.
fn declared() -> Caller {
    Caller::from_host(Some("some-model"), Some("claude-code"), Some("session-1"))
}

/// Drop this repository's state directory, so a case that writes one leaves
/// nothing behind for the next run to read.
fn clear_state(repo_root: &Path) {
    if let Ok(dir) = state::repo_state_dir(repo_root) {
        let _ = fs::remove_dir_all(dir);
    }
}

#[test]
fn the_same_inputs_render_the_same_bytes() {
    // §6: byte-stable. The clock is an input (`RecordedAt`), which is what lets
    // a record carry a timestamp and still satisfy "same input, same bytes".
    let first = record_at(&"0".repeat(64), declared()).to_line().unwrap();
    let second = record_at(&"0".repeat(64), declared()).to_line().unwrap();
    assert_eq!(first, second);

    // Field order is the declaration order, not a map's iteration order, so the
    // line is stable across runs and across processes.
    assert_eq!(
        first,
        record_at(&"0".repeat(64), declared()).to_line().unwrap()
    );
    assert!(first.starts_with(r#"{"schema":1,"configEpoch":"#));
}

#[test]
fn every_record_carries_the_epoch_and_all_three_provenance_fields() {
    // The DoR predicate: `config_epoch`, `caller_model_id` and `caller_harness`
    // are present on EVERY record. A host that exposes no identity degrades the
    // VALUES, never the shape (CLOUD-275) — so a consumer can tell "this host
    // declares nothing" from "this record predates the field".
    for caller in [declared(), Caller::undeclared()] {
        let line = record_at(&"b".repeat(64), caller).to_line().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(parsed["configEpoch"].as_str().unwrap().len(), 64);
        let caller = &parsed["caller"];
        for field in ["modelId", "harness", "session"] {
            assert!(
                caller[field].is_string(),
                "{field} must be present on every record, got {caller}"
            );
        }
    }

    let undeclared = record_at(&"b".repeat(64), Caller::undeclared())
        .to_line()
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&undeclared).unwrap();
    for field in ["modelId", "harness", "session"] {
        assert_eq!(parsed["caller"][field].as_str(), Some(UNKNOWN));
    }
}

#[test]
fn the_epoch_stamp_join_round_trips_against_a_changed_config() {
    // The obligation CLOUD-32 handed over: every record carries the epoch
    // CLOUD-32 produces, and changing a tracked config file changes the stamped
    // epoch on subsequent records. Stamped from the real `epoch::compute`, not
    // from a literal — a test that typed its own hash would assert nothing about
    // the join.
    let fixture = Fixture::new("decision-epoch-join").config("version = 1\n");
    let before = epoch::compute(fixture.path(), None).unwrap();
    let first = record_at(&before, declared());
    assert_eq!(first.config_epoch, before);

    fs::write(
        fixture.path().join("batten.toml"),
        "version = 1\nstrictness = \"strict\"\n",
    )
    .unwrap();
    let after = epoch::compute(fixture.path(), None).unwrap();
    let second = record_at(&after, declared());

    assert_ne!(
        first.config_epoch, second.config_epoch,
        "a changed tracked file must change the stamped epoch"
    );
    assert_eq!(second.config_epoch, after);
    // Round-trippable in the direction a consumer reads it: the stamped value is
    // exactly what recomputing the surface yields.
    assert_eq!(
        epoch::compute(fixture.path(), None).unwrap(),
        second.config_epoch
    );
}

#[test]
fn no_raw_subject_or_context_content_reaches_the_line() {
    // Rule 4, as the issue's acceptance states it: pointer/hash only. The record
    // is structurally incapable of carrying either — it is handed fingerprints,
    // never bytes — and this asserts the consequence over content chosen to be
    // unmistakable if it leaked.
    let span = "let token = \"hunter2-CORRECT-horse-battery\";";
    let context = b"PROMPT: the quick brown fox jumps over SECRET-CONTEXT-MARKER";

    let subject_fingerprint =
        code_fingerprint("r", "src/a.rs", span, SpanNormalization::Collapsed).unwrap();
    let context_fingerprint = identity::context_fingerprint(context);

    let mut record = record_at(&"c".repeat(64), declared());
    record.subject =
        Subject::identified(StoredIdentity::new(FindingKind::Code, subject_fingerprint));
    record.context = ContextPointer::digest(context_fingerprint, context.len() as u64);

    let line = record.to_line().unwrap();
    for leaked in [
        span,
        "hunter2-CORRECT-horse-battery",
        "SECRET-CONTEXT-MARKER",
        "the quick brown fox",
    ] {
        assert!(
            !line.contains(leaked),
            "the record leaked {leaked:?}: {line}"
        );
    }
    // And it does carry the pointers, or it would be pointing at nothing.
    assert!(line.contains(&subject_fingerprint.to_hex()));
    assert!(line.contains(&context_fingerprint.to_hex()));
    // The byte count is a count, which rule 4 permits and which is what makes an
    // empty context distinguishable from an absent one.
    assert!(line.contains(&format!("\"bytes\":{}", context.len())));
}

#[test]
fn the_subject_pointer_is_the_finding_identity_and_carries_its_version() {
    // CLOUD-123's join: the record's subject IS the finding-identity
    // fingerprint, never a second hash of the same bytes, with the per-kind
    // identity_version beside it. Without the version, a bump would silently
    // break the join to CLOUD-78's dispositions across the transition window.
    let fingerprint =
        code_fingerprint("r", "src/a.rs", "let x = 1;", SpanNormalization::Collapsed).unwrap();
    let record = record_at(&"d".repeat(64), declared());
    let parsed: serde_json::Value = serde_json::from_str(&record.to_line().unwrap()).unwrap();

    assert_eq!(parsed["subject"]["kind"].as_str(), Some("identified"));
    assert_eq!(
        parsed["subject"]["identity"]["fingerprint"].as_str(),
        Some(fingerprint.to_hex().as_str())
    );
    assert_eq!(
        parsed["subject"]["identity"]["version"].as_str(),
        Some(FindingKind::Code.identity_version())
    );

    // A subject with no corresponding finding says so, rather than being given a
    // hash minted here.
    let mut unattributed = record;
    unattributed.subject = Subject::Unattributed;
    let parsed: serde_json::Value = serde_json::from_str(&unattributed.to_line().unwrap()).unwrap();
    assert_eq!(parsed["subject"]["kind"].as_str(), Some("unattributed"));
    assert!(parsed["subject"]["identity"].is_null());
}

#[test]
fn records_round_trip_through_the_out_of_tree_store() {
    let fixture = Fixture::new("decision-store-round-trip");
    clear_state(fixture.path());

    let written = [
        record_at(&"e".repeat(64), declared()),
        record_at(&"f".repeat(64), Caller::undeclared()),
    ];
    for record in &written {
        append(fixture.path(), fixture.path(), record).unwrap();
    }

    let read_back = load_all(fixture.path()).unwrap();
    assert_eq!(read_back, written.to_vec());

    // Out of tree, always: the checkout stays clean.
    assert!(!fixture.path().join("decisions").exists());
    clear_state(fixture.path());
}

#[test]
fn appending_holds_the_prefix_and_rewriting_an_existing_line_is_rejected() {
    // The append-only predicate, and it is a BYTE PREFIX rather than a growing
    // id set (CLOUD-52): a prefix also freezes past rows' bytes, so the quiet
    // revision an id-set check waves through is caught.
    let fixture = Fixture::new("decision-append-only");
    clear_state(fixture.path());
    let shard = shard_path(fixture.path(), fixture.path()).unwrap();

    append(
        fixture.path(),
        fixture.path(),
        &record_at(&"1".repeat(64), declared()),
    )
    .unwrap();
    append(
        fixture.path(),
        fixture.path(),
        &record_at(&"2".repeat(64), declared()),
    )
    .unwrap();
    let snapshot = fs::read_to_string(&shard).unwrap();
    assert_eq!(snapshot.lines().count(), 2);

    // A genuine append preserves the prefix.
    append(
        fixture.path(),
        fixture.path(),
        &record_at(&"3".repeat(64), declared()),
    )
    .unwrap();
    let grown = fs::read_to_string(&shard).unwrap();
    assert_eq!(verify_append_only(&snapshot, &grown), None);

    // Rewriting a landed row is refused, and named by line.
    let rewritten = grown.replacen(&"1".repeat(64), &"9".repeat(64), 1);
    assert_eq!(verify_append_only(&grown, &rewritten), Some(1));

    // So is a log that shrank: the row is simply gone.
    let truncated = grown.lines().take(1).collect::<Vec<_>>().join("\n");
    assert_eq!(verify_append_only(&grown, &truncated), Some(2));

    clear_state(fixture.path());
}
