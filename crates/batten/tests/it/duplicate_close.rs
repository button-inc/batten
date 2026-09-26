//! `[tasks.duplicate-close-check]` — a duplicate close decided in the same
//! operation as its target's close (CLOUD-829), over the producer, the module
//! and the adapter together (CLOUD-1752).
//!
//! The discriminating fixture is the MEASURED PAIR: CLOUD-777 marked Done and
//! CLOUD-817 closed as a Duplicate of it, both stamped
//! `2026-08-21T02:37:51.492Z`. Every other case differs from it in one way. The
//! adapter's exit table is the composers' — 0 clean, 1 a refusal, 2 could not
//! look — because `board-sweep` reads it.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/duplicate-close-check.sh policy/duplicate-close.rego crates/batten/tests/it/duplicate_close.rs
// carried: tests/duplicate-close-check.bats policy/duplicate-close.rego crates/batten/tests/it/duplicate_close.rs
// carried: "a duplicate close in the same operation as its target's close is refused" policy/duplicate-close.rego kind:mechanism
// carried: "the refusal demands a decision rather than judging who was right" mise.toml kind:mechanism
// carried: "a duplicate close whose target completed days earlier passes" policy/duplicate-close.rego kind:mechanism
// carried: "a duplicate close whose target is not completed at all passes" mise.toml kind:mechanism
// carried: "a set with no duplicates at all passes" mise.toml kind:mechanism
// carried: "a close one second outside the window passes, which is the stated bound" policy/duplicate-close.rego kind:mechanism
// changed: "a set with no duplicateOf key anywhere is could not look" mise.toml still exit 2 and never the clean line; the producer refuses and writes nothing, and names the re-fetch rather than a `graph unjudgeable-duplicateof` pseudo-row
// carried: "an explicit null duplicateOf is data, not an unjudgeable payload" mise.toml kind:mechanism
// changed: "a duplicate whose target was not piped is unjudgeable, never clean" mise.toml still exit 2, now the producer's refusal naming both keys, with nothing recorded
// changed: "a duplicate close carrying no canceledAt is unjudgeable, never clean" mise.toml still exit 2, now the producer's refusal naming the row, with nothing recorded
// carried: "could not look outranks a refusal, so a half-read set is never exit 1" mise.toml kind:mechanism
// carried: "empty stdin is exit 2, never a verdict" mise.toml kind:mechanism
// carried: "stdin that is not a payload set is exit 2" mise.toml kind:mechanism
// carried: "the report carries no line of either body" policy/duplicate-close.rego kind:mechanism
// carried: "the report is byte-stable across runs" policy/duplicate-close.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;
use std::process::Output;

const OP: &str = "2026-08-21T02:37:51.492Z";

/// A scratch repository carrying the committed config and modules, which is
/// where the producer records and the check reads.
fn repo(name: &str) -> PathBuf {
    common::committed_fixture_with_protected(&format!("duplicate-close-{name}"))
}

/// `row(id, canceledAt, completedAt, duplicateOf)`; `None` is JSON null.
fn row(id: &str, cancel: Option<&str>, complete: Option<&str>, dup: Option<&str>) -> String {
    let quote = |v: Option<&str>| v.map_or("null".to_owned(), |v| format!("\"{v}\""));
    let dup = dup.map_or("null".to_owned(), |d| format!("{{\"id\":\"{d}\"}}"));
    format!(
        r#"{{"id":"{id}","canceledAt":{},"completedAt":{},"relations":{{"blockedBy":[],"blocks":[],"relatedTo":[],"duplicateOf":{dup}}}}}"#,
        quote(cancel),
        quote(complete)
    )
}

fn check(dir: &PathBuf, stdin: &str) -> (Option<i32>, String) {
    let mut command = common::task_command(dir, "duplicate-close-check");
    command.env("MISE_CONFIG_FILE", common::at_root("mise.toml"));
    let out: Output = {
        use std::io::Write as _;
        use std::process::Stdio;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the gate");
        let _ = child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes());
        child.wait_with_output().expect("run the gate")
    };
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The producer alone, with no nested `mise run`: its refusals are asserted here,
/// where a mutation of its body is the body that runs.
fn produce(dir: &PathBuf, stdin: &str) -> (Option<i32>, String) {
    let out = common::produce(dir, "duplicate-close-record", stdin);
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn board(rows: &[String]) -> String {
    rows.join("\n")
}

fn pair() -> Vec<String> {
    vec![
        row("CLOUD-777", None, Some(OP), None),
        row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
    ]
}

#[test]
fn a_duplicate_close_in_its_targets_operation_is_refused() {
    let dir = repo("measured");
    let (code, text) = check(&dir, &board(&pair()));
    assert_eq!(code, Some(1), "{text}");
    // Both keys named: a reader must be able to find the decision taken alongside.
    assert!(text.contains("CLOUD-817>CLOUD-777"), "{text}");
    assert!(text.contains("does not know which row was right"), "{text}");
    assert!(text.contains("TWO decisions taken as one"), "{text}");
}

#[test]
fn closes_in_different_seconds_pass() {
    let dir = repo("seconds");
    for target_at in ["2026-08-14T09:00:00.000Z", "2026-08-21T02:37:52.000Z"] {
        let rows = [
            row("CLOUD-777", None, Some(target_at), None),
            row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
        ];
        let (code, text) = check(&dir, &board(&rows));
        assert_eq!(code, Some(0), "{target_at}: {text}");
    }
}

#[test]
fn an_uncompleted_target_and_a_set_without_duplicates_pass() {
    let dir = repo("clean");
    let uncompleted = [
        row("CLOUD-777", None, None, None),
        row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
    ];
    assert_eq!(check(&dir, &board(&uncompleted)).0, Some(0));
    let (code, text) = check(&dir, &board(&[row("CLOUD-1", None, None, None)]));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("no duplicate close shares an operation"),
        "{text}"
    );
    // An explicit null duplicateOf is data, never could-not-look.
    assert!(!text.contains("re-fetch"), "{text}");
}

#[test]
fn a_set_with_no_duplicateof_key_anywhere_is_could_not_look() {
    let dir = repo("unkeyed");
    let unkeyed =
        r#"{"id":"CLOUD-1","canceledAt":null,"completedAt":null,"relations":{"blockedBy":[]}}"#;
    let (code, text) = produce(&dir, unkeyed);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("includeRelations"), "{text}");
    assert!(!text.contains("no duplicate close shares"), "{text}");
}

#[test]
fn a_duplicate_whose_target_was_not_piped_is_unjudgeable() {
    let dir = repo("unpiped");
    let rows = [row("CLOUD-817", Some(OP), None, Some("CLOUD-777"))];
    let (code, text) = produce(&dir, &board(&rows));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-777, which was not piped"), "{text}");
}

#[test]
fn a_duplicate_close_with_no_stamp_is_unjudgeable() {
    let dir = repo("unstamped");
    let rows = [
        row("CLOUD-777", None, Some(OP), None),
        row("CLOUD-817", None, None, Some("CLOUD-777")),
    ];
    let (code, text) = produce(&dir, &board(&rows));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("carries no canceledAt"), "{text}");
}

/// A real same-operation pair beside a target nobody piped: the set was not
/// judged, so the answer is could-not-look, never exit 1.
#[test]
fn could_not_look_outranks_a_refusal() {
    let dir = repo("outranks");
    let mut rows = pair();
    rows.push(row("CLOUD-818", Some(OP), None, Some("CLOUD-999")));
    assert_eq!(check(&dir, &board(&rows)).0, Some(2));
}

/// A record with no closing census was torn mid-write, and is refused rather
/// than judged as a board with no duplicates.
#[test]
fn a_record_without_its_census_is_torn() {
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "duplicate-close"],
        "dup\tCLOUD-817\t2026-08-21T02:37:52\tCLOUD-777\t2026-08-21T02:37:51\n",
    );
    assert!(written.status.success(), "{}", common::stderr(&written));
    let judged = common::run(&dir, &["check", "--rule", "issue answer other"]);
    let text = common::stderr(&judged) + &String::from_utf8_lossy(&judged.stdout);
    assert_eq!(judged.status.code(), Some(2), "{text}");
    // The pointer is the census count the record carried: 0 lines of it.
    assert!(text.contains("0 issue answer other"), "{text}");
}

#[test]
fn unreadable_stdin_is_could_not_look() {
    let dir = repo("stdin");
    assert_eq!(check(&dir, "").0, Some(2));
    assert_eq!(check(&dir, "not json").0, Some(2));
}

#[test]
fn the_report_carries_no_body_and_is_byte_stable() {
    let dir = repo("pointer");
    let with_bodies = [
        format!(
            r#"{{"id":"CLOUD-777","canceledAt":null,"completedAt":"{OP}","description":"the acceptance is satisfied vacuously and nobody noticed","relations":{{"blockedBy":[],"duplicateOf":null}}}}"#
        ),
        format!(
            r#"{{"id":"CLOUD-817","canceledAt":"{OP}","completedAt":null,"description":"CLOUD-777 passes vacuously, which is the whole finding","relations":{{"blockedBy":[],"duplicateOf":{{"id":"CLOUD-777"}}}}}}"#
        ),
    ];
    let first = check(&dir, &board(&with_bodies));
    assert_eq!(first.0, Some(1), "{}", first.1);
    assert!(!first.1.contains("vacuously"), "{}", first.1);
    assert_eq!(first, check(&dir, &board(&with_bodies)));
}
