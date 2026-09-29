//! `[tasks.record-verdicts]`' successors, over the compiled binary (CLOUD-1265,
//! CLOUD-1707, CLOUD-1965; the body retired under CLOUD-843).
//!
//! The task body ran every declared validator, reduced hk's two plans with `jq`,
//! and piped a `gh api --jq` reduction of HEAD's check-runs into `record forge`.
//! Each arm has a home now: the validators are `record validate` over the
//! `[[rule.tools]]` rows' own `run` argv (`tool_verdict_facts.rs` drives it),
//! the plan join is `policy/hook-profile.rego`'s over two acquired plans
//! (`hook_profile.rs`), and the forge arm is `record forge --fetch`, which this
//! file drives against the `BATTEN_REST_FIXTURE` forge.
//!
//! # What #1054 established, carried
//!
//! That open pull request pinned the forge filter by extracting the committed
//! `--jq` program and running it. The program is gone, and the two cases it added
//! are carried here against the verb: an UNANSWERED conclusion — cancelled,
//! skipped, pending — is not recorded as a grading, and an answered one of either
//! colour still is.
//!
// carried: "[tasks.record-verdicts]" crates/batten/src/record.rs kind:mechanism crates/batten/tests/it/record_verdicts.rs
// carried: "an unanswered conclusion is not recorded as a grading" crates/batten/src/record.rs kind:mechanism
// carried: "an answered conclusion is still recorded" crates/batten/src/record.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, init_repo, scratch, stderr, stdout, write};

/// The repository the fixture forge answers for.
const REPO: &str = "acme/widgets";

/// The answered set this repository declares in `CI_ANSWERED_CONCLUSIONS`.
const ANSWERED: &str = "success,neutral,failure,timed_out,action_required";

/// A committed repository, and its fixture forge.
fn consumer(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("record-verdicts-{name}"));
    init_repo(&dir);
    write(&dir, "batten.toml", "version = 1\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "a commit to grade"]);
    (dir, scratch(&format!("record-verdicts-{name}-forge")))
}

/// One check-run as the endpoint returns it.
fn run(name: &str, conclusion: Option<&str>, started: &str, id: u64) -> String {
    let conclusion =
        conclusion.map_or_else(|| String::from("null"), |value| format!("\"{value}\""));
    let status = if conclusion == "null" {
        "in_progress"
    } else {
        "completed"
    };
    format!(
        r#"{{"name": "{name}", "status": "{status}", "conclusion": {conclusion}, "started_at": "{started}", "id": {id}, "output": {{"summary": "a log nobody declared"}}}}"#
    )
}

/// The forge answers HEAD's check-runs with `runs`, on one page.
fn forge_answers(forge: &Path, runs: &[String]) {
    std::fs::write(
        forge.join("resp.1"),
        format!(
            "HTTP/2 200\ncontent-type: application/json\n\n{{\"total_count\": {}, \"check_runs\": [{}]}}\n",
            runs.len(),
            runs.join(", ")
        ),
    )
    .expect("write the canned answer");
}

/// `record forge HEAD --fetch` against the fixture forge.
fn fetch(dir: &Path, forge: &Path, fanin: Option<&str>) -> Output {
    let mut command = common::batten();
    command
        .args(["record", "forge", "HEAD", "--fetch", "--answered", ANSWERED])
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir);
    if let Some(fanin) = fanin {
        command.args(["--fanin", fanin]);
    }
    command.output().expect("the compiled binary runs")
}

/// The forge record for HEAD, or `None` where nothing was written.
fn recorded(dir: &Path) -> Option<String> {
    let sha = git_in(dir, &["rev-parse", "HEAD"]);
    std::fs::read_to_string(batten::forge::record_path(&dir.join(".git"), sha.trim())).ok()
}

fn said(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

/// **A `cancelled` fan-in judged nothing, so it is not recorded** (CLOUD-1965).
#[test]
fn an_unanswered_conclusion_is_not_recorded_as_a_grading() {
    for (name, conclusion) in [
        ("cancelled", Some("cancelled")),
        ("skipped", Some("skipped")),
        ("pending", None),
    ] {
        let (dir, forge) = consumer(name);
        forge_answers(
            &forge,
            &[run("final", conclusion, "2026-09-28T00:00:00Z", 1)],
        );
        let written = fetch(&dir, &forge, None);
        assert_eq!(written.status.code(), Some(0), "{}", said(&written));
        assert_eq!(
            recorded(&dir).as_deref(),
            Some(""),
            "a `{name}` fan-in is not a grading"
        );
    }
}

/// The anti-vacuity half: a real verdict of either colour is still recorded, or
/// the fix is satisfied by recording nothing at all.
#[test]
fn an_answered_conclusion_is_still_recorded() {
    for conclusion in ["success", "failure"] {
        let (dir, forge) = consumer(conclusion);
        forge_answers(
            &forge,
            &[run("final", Some(conclusion), "2026-09-28T00:00:00Z", 1)],
        );
        let written = fetch(&dir, &forge, Some("final"));
        assert_eq!(written.status.code(), Some(0), "{}", said(&written));
        assert_eq!(
            recorded(&dir).as_deref(),
            Some(format!("final {conclusion}\n").as_str())
        );
    }
}

#[test]
fn the_latest_run_per_name_wins_by_start_then_id() {
    // A re-run adds a second run under the same name, and the reader folds a
    // record into a map — so the producer must choose by recency, never by
    // listing order. The older success is listed LAST here.
    let (dir, forge) = consumer("latest");
    forge_answers(
        &forge,
        &[
            run("final", Some("failure"), "2026-09-28T02:00:00Z", 2),
            run("final", Some("success"), "2026-09-28T01:00:00Z", 9),
        ],
    );
    let written = fetch(&dir, &forge, Some("final"));
    assert_eq!(written.status.code(), Some(0), "{}", said(&written));
    assert_eq!(recorded(&dir).as_deref(), Some("final failure\n"));
}

#[test]
fn nothing_is_written_until_the_fan_in_has_answered() {
    // The fan-in gates writing AT ALL: a record present without it is what
    // `forge-verdict-required` refuses, on local `verify` and inside CI's own
    // run alike.
    let (dir, forge) = consumer("fanin-pending");
    forge_answers(
        &forge,
        &[
            run("lint", Some("success"), "2026-09-28T00:00:00Z", 1),
            run("final", None, "2026-09-28T00:00:00Z", 2),
        ],
    );
    let written = fetch(&dir, &forge, Some("final"));
    assert_eq!(written.status.code(), Some(0), "{}", said(&written));
    assert_eq!(recorded(&dir), None, "no record before the fan-in answers");
}

#[test]
fn a_name_with_whitespace_is_dropped_and_counted_never_mangled() {
    let (dir, forge) = consumer("spaced");
    forge_answers(
        &forge,
        &[
            run(
                "action (ubuntu-latest)",
                Some("success"),
                "2026-09-28T00:00:00Z",
                1,
            ),
            run("final", Some("success"), "2026-09-28T00:00:00Z", 2),
        ],
    );
    let written = fetch(&dir, &forge, Some("final"));
    assert_eq!(written.status.code(), Some(0), "{}", said(&written));
    assert_eq!(recorded(&dir).as_deref(), Some("final success\n"));
    assert!(
        stderr(&written).contains("1 check-run name"),
        "{}",
        said(&written)
    );
    assert!(
        !said(&written).contains("ubuntu-latest"),
        "rule 4: {}",
        said(&written)
    );
}

#[test]
fn a_forge_that_will_not_answer_is_could_not_look_and_writes_nothing() {
    let (dir, forge) = consumer("refused");
    std::fs::write(
        forge.join("resp.1"),
        "HTTP/2 403\ncontent-type: application/json\n\n{\"message\": \"no\"}\n",
    )
    .expect("write the refusal");
    let refused = fetch(&dir, &forge, Some("final"));
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    assert_eq!(recorded(&dir), None);
}

#[test]
fn a_qualifier_without_fetch_is_a_usage_error() {
    let (dir, _) = consumer("usage");
    let mut command = common::batten();
    command
        .args(["record", "forge", "HEAD", "--fanin", "final"])
        .current_dir(&dir);
    let refused = command.output().expect("the compiled binary runs");
    assert_eq!(refused.status.code(), Some(1), "{}", said(&refused));
}
