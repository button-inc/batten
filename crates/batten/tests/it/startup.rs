//! `batten startup` over the compiled binary (CLOUD-1324).
//!
//! # What this tier reaches that the unit cases cannot
//!
//! `src/startup.rs`'s own cases pin the decision — what a passing check, a
//! failing one, an unspawnable one and a repair that does not satisfy its own
//! check each produce. What they structurally cannot reach is everything
//! between the config file and that decision: that `[[startup]]` parses at all,
//! that `resolve` carries the rows to the verb, that the verb renders them in
//! §6's pointer shape, that its exit code stays inside the `0`/`1` pair, and
//! that a malformed row is refused at LOAD rather than at the first run.
//!
//! Each of those is a place the feature can be completely dead while every unit
//! case passes — the class `rules/policy-modules.md` records for a Rego
//! predicate reading a key the engine never builds.
//!
//! # Why the fixtures use `true`, `false` and `test -f`
//!
//! A row's check is a command, so a fixture that ran a REAL precondition would
//! be testing the container. These are the smallest commands whose exit code is
//! known, which leaves exactly the plumbing above under test.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;
use std::process::Output;

use common::{batten, git_in, scratch, stdout, write};

/// A repository whose `batten.toml` carries `rows`.
fn fixture(name: &str, rows: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));
    write(&dir, "a.txt", "x\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

fn startup(dir: &Path, args: &[&str]) -> Output {
    batten()
        .current_dir(dir)
        .arg("startup")
        .args(args)
        .output()
        .expect("the binary runs")
}

/// A row spelling `check` and optionally `repair`, as TOML.
fn row(id: &str, check: &str, repair: Option<&str>) -> String {
    let repair = repair.map_or_else(String::new, |argv| format!("repair = {argv}\n"));
    format!("[[startup]]\nid = \"{id}\"\ngloss = \"a fixture row\"\ncheck = {check}\n{repair}\n")
}

#[test]
fn a_provisioned_container_reports_every_row_and_exits_zero() {
    let dir = fixture("startup-clean", &row("clean", "[\"true\"]", None));
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(0));
    // EVERY row, not only the failing ones, and deliberately unlike `provision
    // status`: a reader running this is asking whether the container is right,
    // and silence cannot distinguish a row that passed from one never declared.
    assert_eq!(stdout(&out), "clean ok\nstartup: 1 row(s), 0 failed\n");
}

#[test]
fn a_row_with_no_repair_reports_the_class_a_reader_can_act_on() {
    let dir = fixture("startup-bare", &row("bare", "[\"false\"]", None));
    let out = startup(&dir, &[]);
    // `1`, never `2`: a container that does not match what the repository
    // declares is the config-or-usage class, and a mediating harness reads `2`
    // as a policy denial (§7). `doctor`'s reasoning, inherited.
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stdout(&out),
        "bare failed not-provisioned\nstartup: 1 row(s), 1 failed\n"
    );
}

/// THE VERB'S WHOLE POINT, in one pair: the same tree, the same row, and the
/// flag is the only difference.
///
/// The check is a file test and the repair creates the file, so the two runs
/// genuinely differ rather than rendering one answer twice.
#[test]
fn repair_fixes_and_says_so_while_the_bare_verb_changes_nothing() {
    let dir = scratch("startup-repair");
    let target = dir.join("marker");
    let path = target.to_str().unwrap().to_owned();
    let rows = row(
        "makes-it",
        &format!("[\"test\", \"-f\", {}]", json(&path)),
        Some(&format!("[\"touch\", {}]", json(&path))),
    );
    write(&dir, "batten.toml", &format!("version = 1\n\n{rows}"));
    git_in(&dir, &["init", "-q", "-b", "main", "."]);

    let bare = startup(&dir, &[]);
    assert_eq!(out_code(&bare), 1);
    assert!(
        !target.exists(),
        "the read path must not mutate — that is the whole of --repair"
    );

    let repaired = startup(&dir, &["--repair"]);
    assert_eq!(out_code(&repaired), 0);
    assert_eq!(
        stdout(&repaired),
        "makes-it ok repaired\nstartup: 1 row(s), 0 failed\n",
        "a reader who ran --repair should see which rows it moved"
    );
    assert!(target.exists());

    // Idempotent, and reported as ordinary rather than as repaired again: a
    // repair that runs every time is a repair whose check is wrong, and the two
    // renderings are what let a reader tell those apart.
    let again = startup(&dir, &["--repair"]);
    assert_eq!(stdout(&again), "makes-it ok\nstartup: 1 row(s), 0 failed\n");
}

/// A repository declaring nothing says so, rather than saying nothing.
///
/// The count line is what makes silence legible: without it, "no rows" and
/// "every row passed" are the same empty output.
#[test]
fn a_repository_with_no_rows_reports_the_count_rather_than_nothing() {
    let dir = fixture("startup-none", "");
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "startup: 0 row(s), 0 failed\n");
}

#[test]
fn the_data_channel_carries_every_row_with_its_verdict() {
    let dir = fixture(
        "startup-json",
        &(row("good", "[\"true\"]", None) + &row("bad", "[\"false\"]", None)),
    );
    let out = startup(&dir, &["-J"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("one JSON document");
    let rows = rows.as_array().expect("an array of outcomes");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["id"], "good");
    assert_eq!(rows[0]["ok"], true);
    // Omitted rather than nulled on a pass — a key whose only value is null is
    // a field every reader has to learn to ignore.
    assert!(rows[0].get("reason").is_none(), "{:?}", rows[0]);
    assert_eq!(rows[1]["reason"], "not-provisioned");
}

/// A ROW THAT COULD NEVER DECIDE IS REFUSED AT LOAD, not once per session.
///
/// The direction is what matters: an empty check answers could-not-look
/// forever, so the row would report a failure nobody can fix and its repair
/// would never run — a dead gate that reads as a broken container.
#[test]
fn a_malformed_row_is_refused_when_the_config_loads() {
    let dir = fixture("startup-malformed", &row("empty", "[]", None));
    let out = startup(&dir, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = common::stderr(&out);
    assert!(text.contains("startup"), "{text}");

    // The same refusal reaches every verb, because it is the CONFIG that is
    // refused rather than this one command — which is what makes it a load-time
    // rule instead of a check inside `startup`.
    let elsewhere = batten()
        .current_dir(&dir)
        .arg("check")
        .output()
        .expect("the binary runs");
    assert_eq!(elsewhere.status.code(), Some(1));
}

#[test]
fn two_rows_may_not_share_an_id() {
    let dir = fixture(
        "startup-duplicate",
        &(row("same", "[\"true\"]", None) + &row("same", "[\"false\"]", None)),
    );
    assert_eq!(startup(&dir, &[]).status.code(), Some(1));
}

fn json(value: &str) -> String {
    serde_json::to_string(value).expect("a path is encodable")
}

fn out_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}
