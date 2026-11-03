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
    batten::tracker_reading::reading(
        "done-pr",
        &BTreeMap::new(),
        &[],
        Path::new("."),
        &stdin,
        None,
    )
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

/// The `served` line of a `closing-key` record.
fn served(record: &str) -> &str {
    record
        .lines()
        .find(|line| line.starts_with("served\t"))
        .expect("the record carries the served line")
}

/// **THE BET REACHES AN IN-PROCESS `closing-key` READING** (CLOUD-2387,
/// CLOUD-1770).
///
/// A landing's body gates used to learn the bet from an exported
/// `BATTEN_SPEC_BASE`; derived in-process, they are handed it. A speculative
/// replay puts the lease holder's commit — and its `Refs:` key — under this
/// branch, and only the handed base keeps that key out of what this branch
/// served. The mirror reads the same tree with no bet and must see the borrowed
/// key, so a reading that ignored `spec_base` fails the first assertion.
#[test]
fn the_bet_reaches_an_in_process_closing_key_reading() {
    let dir = crate::common::scratch("tracker-reading-bet");
    crate::common::init_repo(&dir);
    let git = |args: &[&str]| crate::common::git_in(&dir, args);
    git(&["commit", "-q", "--allow-empty", "-m", "chore: init"]);
    git(&["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git(&["checkout", "-q", "-b", "work"]);
    git(&[
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "feat: the holder's\n\nRefs: CLOUD-9",
    ]);
    let borrowed = git(&["rev-parse", "HEAD"]).trim().to_owned();
    git(&[
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "feat: this branch's\n\nRefs: CLOUD-1",
    ]);

    let text = std::fs::read_to_string(crate::common::at_root("batten.toml")).expect("the config");
    let parsed: toml::Value = toml::from_str(&text).expect("batten.toml parses");
    let patterns: Vec<batten::pattern::NamedPattern> = parsed["pattern"]
        .clone()
        .try_into()
        .expect("the committed [[pattern]] rows");
    let inputs = BTreeMap::from([
        ("hold".to_owned(), "closing-hold-marker".to_owned()),
        ("base".to_owned(), "origin/main".to_owned()),
    ]);
    let read = |spec_base: Option<&str>| {
        batten::tracker_reading::reading(
            "closing-key",
            &inputs,
            &patterns,
            &dir,
            "Closes CLOUD-1",
            spec_base,
        )
        .expect("the reading accepts a body and a branch")
    };

    let with_bet = read(Some(&borrowed));
    assert!(served(&with_bet).contains("CLOUD-1"), "{with_bet}");
    assert!(!served(&with_bet).contains("CLOUD-9"), "{with_bet}");
    let without = read(None);
    assert!(served(&without).contains("CLOUD-9"), "{without}");
}
