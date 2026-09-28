//! `[tasks.record-verdicts]`'s forge filter, over the task's own committed body
//! (CLOUD-1965).
//!
//! The task body also runs every declared validator and `batten` itself, so it is
//! not driven whole here. What decides whether a check-run is recorded as a
//! GRADING is the one `--jq` program handed to `gh api`, and that program is
//! extracted from the committed body and run with `jq` over fixture check-runs —
//! so the case asserts the bytes mise hands bash, never a copy of them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::process::Stdio;

/// The `--jq` program of the check-runs read, exactly as committed.
fn forge_filter() -> String {
    let body = common::task_body("record-verdicts");
    let line = body
        .lines()
        .find(|line| line.contains("--jq '.check_runs"))
        .expect("record-verdicts reads the forge's check-runs through --jq");
    let start = line.find("--jq '").expect("a --jq program") + "--jq '".len();
    let rest = &line[start..];
    let end = rest.find("' 2>").expect("the program is single-quoted");
    rest[..end].to_owned()
}

/// The `name<TAB>conclusion` lines the committed filter keeps for `runs`.
#[expect(
    clippy::disallowed_types,
    reason = "stays: the subject is a jq program the task hands to a spawned gh, so running it is a spawn by definition"
)]
fn kept(runs: &str) -> Vec<String> {
    let mut child = std::process::Command::new("jq")
        .args(["-r", &forge_filter()])
        .env(
            "CI_ANSWERED_CONCLUSIONS",
            common::task_env("CI_ANSWERED_CONCLUSIONS"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("jq runs");
    child
        .stdin
        .take()
        .expect("a stdin")
        .write_all(runs.as_bytes())
        .expect("write the fixture");
    let out = child.wait_with_output().expect("jq finishes");
    assert!(out.status.success(), "the committed filter runs under jq");
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

fn one(name: &str, conclusion: Option<&str>) -> String {
    let conclusion = conclusion.map_or_else(|| "null".to_owned(), |value| format!("\"{value}\""));
    format!(
        "{{\"check_runs\":[{{\"name\":\"{name}\",\"conclusion\":{conclusion},\
         \"started_at\":\"2026-09-28T00:00:00Z\",\"id\":1}}]}}"
    )
}

/// **A `cancelled` fan-in judged nothing, so it is not recorded** (CLOUD-1965).
///
/// The filter excluded the literal `skipped` alone, so a cancelled `final` was
/// written as `final cancelled` and read by `head grade twice` and
/// `forge-verdict-required` as the forge having graded the commit. Membership in
/// the declared `CI_ANSWERED_CONCLUSIONS` is the one list `checks_green` also
/// reads, so the two cannot disagree about what counts as an answer again.
#[test]
fn an_unanswered_conclusion_is_not_recorded_as_a_grading() {
    assert!(kept(&one("final", Some("cancelled"))).is_empty());
    assert!(kept(&one("final", Some("skipped"))).is_empty());
    assert!(
        kept(&one("final", None)).is_empty(),
        "pending is not a grading"
    );
}

/// The anti-vacuity half: a real verdict of either colour is still recorded, or
/// the fix is satisfied by recording nothing at all.
#[test]
fn an_answered_conclusion_is_still_recorded() {
    assert_eq!(kept(&one("final", Some("success"))), vec!["final\tsuccess"]);
    assert_eq!(kept(&one("final", Some("failure"))), vec!["final\tfailure"]);
}
