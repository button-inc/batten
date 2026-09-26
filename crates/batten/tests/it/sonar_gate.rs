//! `[tasks."sonar-gate"]` — the external analyzer's verdict on one SHA
//! (CLOUD-441), over the task's own body (CLOUD-1717).
//!
//! The decision is `batten checks green`'s over a roster of one name that may be
//! absent; what the task keeps is the fetch and its one distinction, a SHA the
//! remote has never seen. Every case runs offline: a reading is injected through
//! `SONAR_GATE_RUNS`, and the fetch cases through a stub `gh`.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/sonar-gate.sh mise.toml kind:mechanism crates/batten/tests/it/sonar_gate.rs
// carried: tests/sonar-gate.bats mise.toml kind:mechanism crates/batten/tests/it/sonar_gate.rs
// carried: "a green analysis passes" mise.toml kind:mechanism
// carried: "a failed analysis is red, and named" mise.toml kind:mechanism
// carried: "a neutral conclusion passes — the analyzer graded and did not object" mise.toml kind:mechanism
// carried: "timed_out is red like any other non-success conclusion" mise.toml kind:mechanism
// carried: "ABSENT IS NOT A VETO — an analyzer with no opinion cannot wedge a PR" mise.toml kind:mechanism
// carried: "an empty reading is absent, and takes no network to say so" mise.toml kind:mechanism
// carried: "a pending analysis is not an answer" mise.toml kind:mechanism
// carried: "a skipped analysis is not an answer either" mise.toml kind:mechanism
// carried: "a cancelled analysis is not an answer either — it judged nothing" mise.toml kind:mechanism
// carried: "another check's failure is none of this gate's business" mise.toml kind:mechanism
// carried: "a skip superseded by a success passes — the residue does not veto" mise.toml kind:mechanism
// carried: "a success superseded by a FAILURE is red" mise.toml kind:mechanism
// carried: "a success superseded by a re-run in flight is not an answer yet" mise.toml kind:mechanism
// carried: "the id breaks a tie between two runs started in the same second" mise.toml kind:mechanism
// carried: "a reading with no ordering key fails closed — the least conclusive wins" mise.toml kind:mechanism
// carried: "output is a pointer — a conclusion and a name, never the analysis" mise.toml kind:mechanism
// carried: "the verdict is byte-identical across two runs on identical input" mise.toml kind:mechanism
// carried: "a SHA the remote has never seen is NO ANSWER YET, not a failed reading" mise.toml kind:mechanism
// carried: "any other fetch failure is COULD NOT LOOK — a reading we cannot take is not a pass" mise.toml kind:mechanism
// carried: "an auth failure is could not look too, never a pass" mise.toml kind:mechanism
// carried: "a successful fetch returning nothing is absent — the SHA exists and has no analysis" mise.toml kind:mechanism
// carried: "an AUTHENTICATED unpushed SHA is no answer yet — 422, not 404" mise.toml kind:mechanism
// carried: "a 422 that is NOT a missing commit stays could-not-look" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

const NAME: &str = "SonarCloud Code Analysis";

fn gate(dir: &Path, runs: Option<&str>, gh: Option<&Path>) -> (Option<i32>, String) {
    let mut command = common::task_command(dir, "sonar-gate");
    command
        .env(
            "CI_ANSWERED_CONCLUSIONS",
            common::task_env("CI_ANSWERED_CONCLUSIONS"),
        )
        .env("SHA", "deadbeef")
        .env("REPO", "o/r")
        .env("SONAR_CHECK_NAME", NAME)
        .stdin(Stdio::null());
    match runs {
        Some(runs) => command.env("SONAR_GATE_RUNS", runs),
        None => command.env_remove("SONAR_GATE_RUNS"),
    };
    match gh {
        Some(gh) => command.env("SONAR_GATE_GH", gh),
        None => command.env_remove("SONAR_GATE_GH"),
    };
    let out: Output = command.output().expect("run the task body");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn reading(lines: &[&str]) -> String {
    lines.join("\n")
}

fn run(name: &str) -> PathBuf {
    common::scratch(&format!("sonar-gate-{name}"))
}

/// A stub `gh` exiting `code` with `stderr` on its error stream.
fn stub_gh(dir: &Path, code: i32, stderr: &str) -> PathBuf {
    let path = dir.join("gh");
    common::write(
        dir,
        "gh",
        &format!("#!/usr/bin/env bash\necho '{stderr}' >&2\nexit {code}\n"),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    path
}

fn single(conclusion: &str) -> String {
    format!("completed\t{conclusion}\t{NAME}")
}

#[test]
fn green_and_neutral_pass() {
    let dir = run("green");
    for conclusion in ["success", "neutral"] {
        let (code, text) = gate(&dir, Some(&single(conclusion)), None);
        assert_eq!(code, Some(0), "{conclusion}: {text}");
        assert!(text.contains("green"), "{text}");
    }
}

#[test]
fn a_failed_or_timed_out_analysis_is_red_and_names_only_a_pointer() {
    let dir = run("red");
    for conclusion in ["failure", "timed_out"] {
        let (code, text) = gate(&dir, Some(&single(conclusion)), None);
        assert_eq!(code, Some(1), "{conclusion}: {text}");
        assert!(text.contains(&format!("{conclusion}\t{NAME}")), "{text}");
    }
}

#[test]
fn absent_is_not_a_veto_and_an_empty_reading_takes_no_network() {
    let dir = run("absent");
    for runs in ["completed\tsuccess\tci".to_owned(), String::new()] {
        let (code, text) = gate(&dir, Some(&runs), None);
        assert_eq!(code, Some(0), "{runs:?}: {text}");
        assert!(text.contains("absent is not a verdict"), "{text}");
    }
}

#[test]
fn pending_skipped_and_cancelled_are_not_an_answer() {
    let dir = run("unanswered");
    for runs in [
        format!("in_progress\t-\t{NAME}"),
        single("skipped"),
        single("cancelled"),
    ] {
        let (code, text) = gate(&dir, Some(&runs), None);
        assert_eq!(code, Some(3), "{runs}: {text}");
        assert!(text.contains("not an answer yet"), "{text}");
        assert!(
            !text.contains("::error::"),
            "no verdict is not a refusal: {text}"
        );
    }
}

#[test]
fn another_checks_failure_is_none_of_this_gates_business() {
    let dir = run("other");
    let runs = reading(&["completed\tfailure\tci", &single("success")]);
    assert_eq!(gate(&dir, Some(&runs), None).0, Some(0));
}

#[test]
fn the_latest_run_decides() {
    let dir = run("latest");
    let at = |status: &str, conclusion: &str, time: &str, id: u32| {
        format!("{status}\t{conclusion}\t{NAME}\t2026-08-12T03:{time}Z\t{id}")
    };
    for (runs, want) in [
        (
            reading(&[
                &at("completed", "skipped", "18:10", 1),
                &at("completed", "success", "20:16", 2),
            ]),
            Some(0),
        ),
        (
            reading(&[
                &at("completed", "success", "00:00", 1),
                &at("completed", "failure", "05:00", 2),
            ]),
            Some(1),
        ),
        (
            reading(&[
                &at("completed", "success", "00:00", 1),
                &at("in_progress", "-", "05:00", 2),
            ]),
            Some(3),
        ),
        (
            reading(&[
                &at("completed", "success", "00:00", 10),
                &at("completed", "failure", "00:00", 11),
            ]),
            Some(1),
        ),
    ] {
        let (code, text) = gate(&dir, Some(&runs), None);
        assert_eq!(code, want, "{runs}: {text}");
    }
}

/// Two runs with no ordering key: the least conclusive wins, and the pointer
/// names the red conclusion rather than whichever line came last.
#[test]
fn an_unorderable_pair_fails_closed_and_points_at_the_red_one() {
    let dir = run("unorderable");
    let runs = reading(&[&single("failure"), &single("success")]);
    let (code, text) = gate(&dir, Some(&runs), None);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains(&format!("failure\t{NAME}")), "{text}");
    assert!(!text.contains(&format!("success\t{NAME}")), "{text}");
}

#[test]
fn the_verdict_is_byte_identical_across_two_runs() {
    let dir = run("stable");
    let first = gate(&dir, Some(&single("success")), None);
    assert_eq!(first, gate(&dir, Some(&single("success")), None));
}

#[test]
fn an_unpushed_sha_is_no_answer_yet_at_404_and_at_an_authenticated_422() {
    let dir = run("unpushed");
    for stderr in [
        "gh: Not Found (HTTP 404)",
        "gh: No commit found for SHA: f0f2b7b (HTTP 422)",
    ] {
        let gh = stub_gh(&dir, 1, stderr);
        let (code, text) = gate(&dir, None, Some(&gh));
        assert_eq!(code, Some(3), "{stderr}: {text}");
        assert!(text.contains("not pushed yet"), "{text}");
    }
}

#[test]
fn any_other_failed_read_is_could_not_look() {
    let dir = run("unreadable");
    for stderr in [
        "gh: connection refused",
        "gh: Bad credentials (HTTP 401)",
        "gh: Validation Failed (HTTP 422)",
    ] {
        let gh = stub_gh(&dir, 1, stderr);
        let (code, text) = gate(&dir, None, Some(&gh));
        assert_eq!(code, Some(2), "{stderr}: {text}");
    }
}

#[test]
fn a_successful_fetch_returning_nothing_is_absent() {
    let dir = run("fetched-nothing");
    let gh = stub_gh(&dir, 0, "");
    let (code, text) = gate(&dir, None, Some(&gh));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("absent is not a verdict"), "{text}");
}
