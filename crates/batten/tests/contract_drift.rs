//! Contract drift over the compiled binary (CLOUD-461, CLOUD-525).
//!
//! The unit tests in `src/contract.rs` pin the comparison and the rendering
//! against explicit maps. These pin the half a unit test structurally cannot
//! reach: that the predicate is wired to the **advisory channel** of the `hook`
//! surface, that it is silent by default and silent again the moment after it
//! speaks, and that every path through it exits `0`.
//!
//! This is `tests/contract-drift.bats` ported, and the exit numbers are
//! **translated rather than copied**: the shell tasks use `1 = violation`, where
//! batten's contract is the inverse (house-style §7). Carrying a bats
//! `assert_equal $status 1` across unchanged would assert "unreadable input"
//! while meaning "violation" — and it would pass, which is the false green that
//! hazard exists to name.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// The `[contract]` table this suite's fixtures declare.
const CONTRACT: &str = r#"
[contract]
tracked = ["AGENTS.md", ".claude/rules/**", ".claude/settings.json", "mise-tasks/**"]
wiring = [".claude/settings.json"]
"#;

/// A repository with a contract surface, in the shape a consumer declares one.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    std::fs::create_dir_all(dir.join(".claude/rules")).unwrap();
    std::fs::create_dir_all(dir.join("mise-tasks")).unwrap();
    std::fs::write(dir.join("batten.toml"), format!("version = 1\n{CONTRACT}")).unwrap();
    std::fs::write(dir.join("AGENTS.md"), "# the contract\n").unwrap();
    std::fs::write(dir.join(".claude/rules/rust.md"), "# rust\n").unwrap();
    std::fs::write(dir.join(".claude/settings.json"), "{\"hooks\":{}}\n").unwrap();
    std::fs::write(dir.join("mise-tasks/a-gate"), "#!/usr/bin/env bash\ntrue\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

/// One `PostToolBatch` through `batten hook --harness claude-code`.
fn drift(dir: &Path, session: &str) -> Output {
    let payload =
        format!(r#"{{"hook_event_name":"PostToolBatch","session_id":"{session}","cwd":"/w"}}"#);
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "a drift notice is never a refusal — house-style §7, and CLOUD-97/CLOUD-219 both"
    );
    output
}

/// The `additionalContext` the host would hand the model, if any.
fn notice(output: &Output) -> Option<String> {
    let raw = common::stdout(output);
    if raw.trim().is_empty() {
        return None;
    }
    let document: serde_json::Value = serde_json::from_str(&raw).expect("stdout is one document");
    assert!(
        document["hookSpecificOutput"]["permissionDecision"].is_null(),
        "an advisory carries no verdict field"
    );
    Some(
        document["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("an advisory carries additionalContext")
            .to_owned(),
    )
}

#[test]
fn the_first_batch_of_a_session_seeds_the_snapshot_silently() {
    // A session that started AFTER a change has already read the new files, so
    // nudging it about them is the noise that gets an advisory channel ignored.
    let dir = fixture("contract-seed");
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
    // And a surface that has not moved stays quiet on every later batch.
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

#[test]
fn a_moved_contract_file_is_reported_in_band() {
    let dir = fixture("contract-moved");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nmore\n").unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the surface moved");
    assert!(told.contains("AGENTS.md"), "{told}");
    assert!(told.contains("1 changed"), "{told}");
}

/// **The load-bearing bound.** A suite proving only that it fires would pass on
/// a hook that nags every batch, which is how an advisory channel becomes noise
/// and stops being read.
///
/// Fails by: moving `contract::record` after the emit's early return, or adding
/// a second piece of state that decides whether to speak. The write IS the rate
/// limit.
#[test]
fn a_change_set_is_reported_once_and_the_very_next_batch_is_silent() {
    let dir = fixture("contract-once");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nchange\n").unwrap();

    assert!(drift(&dir, "s1").pipe_notice().is_some(), "it fires");
    assert_eq!(
        drift(&dir, "s1").pipe_notice(),
        None,
        "and the very next batch is silent"
    );
}

#[test]
fn a_second_change_set_is_reported_again_and_quiet_is_not_permanent() {
    let dir = fixture("contract-second");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nfirst\n").unwrap();
    drift(&dir, "s1");
    std::fs::write(dir.join(".claude/rules/rust.md"), "# rust\nsecond\n").unwrap();

    let told = drift(&dir, "s1")
        .pipe_notice()
        .expect("a second change-set");
    assert!(told.contains(".claude/rules/rust.md"), "{told}");
    // The comparison is against what was last REPORTED, not against the
    // session's start, so an already-named file is not named twice.
    assert!(!told.contains("AGENTS.md"), "{told}");
}

#[test]
fn a_newly_added_contract_file_is_drift_and_a_deleted_one_is_too() {
    // The case `[epoch] tracked` structurally cannot express: a stated set of
    // literal paths cannot see a file that did not exist when it was written,
    // and here that file IS the drift.
    let dir = fixture("contract-added");
    drift(&dir, "s1");
    std::fs::write(dir.join("mise-tasks/brand-new-gate"), "#!/bin/sh\ntrue\n").unwrap();
    let added = drift(&dir, "s1")
        .pipe_notice()
        .expect("a new gate is drift");
    assert!(added.contains("mise-tasks/brand-new-gate"), "{added}");

    std::fs::remove_file(dir.join(".claude/rules/rust.md")).unwrap();
    let gone = drift(&dir, "s1").pipe_notice().expect("a removal is drift");
    assert!(gone.contains("no longer tracked"), "{gone}");
    assert!(gone.contains(".claude/rules/rust.md"), "{gone}");
}

#[test]
fn a_file_outside_the_declared_surface_is_not_drift() {
    let dir = fixture("contract-outside");
    drift(&dir, "s1");
    std::fs::write(dir.join("README.md"), "not the contract\n").unwrap();
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

#[test]
fn each_session_is_told_about_what_moved_under_it_and_not_about_the_rest() {
    // Keyed per session, so a session that started after a change is not nudged
    // about one it already has.
    let dir = fixture("contract-sessions");
    drift(&dir, "early");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nmid\n").unwrap();
    // A session whose first batch is now: it reads the CURRENT files at start,
    // so its snapshot is seeded with them and it is told nothing.
    assert_eq!(drift(&dir, "late").pipe_notice(), None);
    // The session that was already running is told.
    assert!(drift(&dir, "early").pipe_notice().is_some());
}

/// Pointer-only, carried over verbatim in meaning from the bats suite.
///
/// Fails by: rendering content beside the path. A reminder carrying the new text
/// is a mirror, and a mirror is cleared by reading the hook instead of the file.
#[test]
fn the_notice_names_paths_and_never_a_byte_of_one() {
    // Assembled rather than written, and the reason is this repo's own gate:
    // a credential-shaped literal in a tracked file is what `no-secrets`
    // exists to catch, and it caught this one. The planted value is still
    // secret-shaped where it matters — in the file the fixture writes and in
    // every string this case then searches — while the SOURCE carries no
    // token-shaped literal for a scanner to be right about.
    let planted = format!("{}_{}", "ghp", "thisIsTheSortOfThingAFileMustNeverEcho");
    let planted = planted.as_str();
    let dir = fixture("contract-pointer");
    drift(&dir, "s1");
    std::fs::write(
        dir.join(".claude/settings.json"),
        format!("{{\"hooks\":{{}},\"note\":\"{planted}\"}}\n"),
    )
    .unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the surface moved");
    assert!(told.contains(".claude/settings.json"));
    assert!(!told.contains(planted), "the payload must never travel");
    assert!(
        !told.contains("+++") && !told.contains("@@"),
        "and no diff of any kind"
    );
    // Nor may it reach anything under the state root.
    let snapshot = dir.join(".git/batten-contract");
    for entry in std::fs::read_dir(&snapshot).unwrap() {
        let body = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!body.contains(planted), "the snapshot stores hashes only");
    }
}

/// CLOUD-525: the settings.json clause is REPLACED, not deleted, and what
/// replaces it is derivable from the change-set the predicate already has.
///
/// Fails by: emitting the wiring line unconditionally, or restoring a clause
/// whose subject is the session's loaded hook set — an instruction no mechanism
/// can answer, which an agent following it can only guess at.
#[test]
fn a_moved_wiring_file_says_so_computably_and_claims_nothing_about_the_session() {
    let dir = fixture("contract-wiring");
    drift(&dir, "s1");
    std::fs::write(
        dir.join(".claude/settings.json"),
        "{\"hooks\":{\"Stop\":[]}}\n",
    )
    .unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the wiring moved");
    assert!(told.contains("The hook wiring is among them"), "{told}");
    assert!(told.contains("batten doctor hooks"), "{told}");
    assert!(
        !told.contains("self-enforced"),
        "the unactionable clause must not come back: {told}"
    );

    // And a change-set that did not touch the wiring says nothing about it.
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nelsewhere\n").unwrap();
    let other = drift(&dir, "s1").pipe_notice().expect("something moved");
    assert!(!other.contains("The hook wiring is among them"), "{other}");
}

#[test]
fn a_repository_that_declares_no_contract_surface_is_silent_rather_than_stable() {
    // Could-not-look, not "nothing moved". The two are different claims, and
    // collapsing them would report an unmeasured repository as stable forever.
    let dir = scratch("contract-undeclared");
    std::fs::write(dir.join("batten.toml"), "version = 1\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
    assert!(!dir.join(".git/batten-contract").exists());
}

#[test]
fn a_directory_that_is_not_a_repository_reports_nothing_and_still_allows() {
    // `scratch_outside_tree`, not `scratch`: this is the one fixture shape that
    // must not be inside ANY repository, and `target/tmp/` is inside this one —
    // so discovery would walk up, find the real authority, and the case would be
    // judging batten's own tree rather than an unrepository'd directory.
    let dir = common::scratch_outside_tree("batten-contract-drift", "contract-no-repo");
    std::fs::write(dir.join("batten.toml"), format!("version = 1\n{CONTRACT}")).unwrap();
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

/// A local convenience so the cases above read as one statement each.
trait PipeNotice {
    fn pipe_notice(&self) -> Option<String>;
}

impl PipeNotice for Output {
    fn pipe_notice(&self) -> Option<String> {
        notice(self)
    }
}
