//! The tracker readings' records, read directly (CLOUD-2244).
//!
//! `tracker_hygiene.rs` drives each family through the gate; this suite pins
//! what a reading WRITES, where a token the module never refuses on would pass
//! every gate case unseen.

use std::collections::BTreeMap;
use std::path::Path;

/// The `done-pr` record for one issue carrying PR #7 in `pull`'s state.
fn done_pr_record(pull: &str) -> String {
    let stdin = format!(
        r#"[{{"id":"A-1","attachments":[{{"url":"https://f.example/o/r/pull/7"}}],"pulls":[{pull}]}}]"#
    );
    batten::tracker_reading::reading("done-pr", &BTreeMap::new(), &[], Path::new("."), &stdin)
        .expect("the reading accepts a well-formed set")
}

/// A pull request's token on the record.
fn token(record: &str) -> &str {
    record
        .lines()
        .find_map(|line| line.strip_prefix("pull\tA-1\t7\t"))
        .expect("the record carries the pull line")
}

#[test]
fn an_unknown_pull_state_never_records_closed() {
    // Each read as closed before: the hand-spelled reader matched `"open"`
    // exactly and called everything else finished.
    for pull in [
        r#"{"number":7,"state":"OPEN"}"#,
        r#"{"number":7}"#,
        r#"{"number":7,"state":"weird"}"#,
    ] {
        let record = done_pr_record(pull);
        assert_ne!(token(&record), "closed", "{pull} recorded closed: {record}");
    }
    assert_eq!(
        token(&done_pr_record(r#"{"number":7,"state":"OPEN"}"#)),
        "open"
    );
    assert_eq!(
        token(&done_pr_record(r#"{"number":7,"state":"weird"}"#)),
        "unknown"
    );
}

#[test]
fn a_finished_pull_request_records_closed() {
    // The control: merged and closed still read as finished.
    for pull in [
        r#"{"number":7,"state":"closed","merged":true}"#,
        r#"{"number":7,"state":"closed","merged":false}"#,
        r#"{"number":7,"state":"MERGED"}"#,
    ] {
        assert_eq!(token(&done_pr_record(pull)), "closed", "{pull}");
    }
    assert_eq!(
        token(&done_pr_record(
            r#"{"number":7,"state":"open","draft":true}"#
        )),
        "draft"
    );
}
