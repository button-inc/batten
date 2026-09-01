//! The pinned-program fact and the practice built on it, over the compiled
//! engine (CLOUD-1028).
//!
//! # Why this tier
//!
//! The preset's own `test_` cases hand themselves a `programs` array and a
//! `pinned-programs` list. Both are shapes the ENGINE has to build, and a module
//! test cannot establish that it does: `.claude/rules/policy-modules.md` records
//! two measured instances of a module that passed its own suite while iterating
//! a key nothing filled. Three things here can only be proved against the real
//! boundary — that a command's argv reaches a module already parsed, that
//! `mediated` reads the pin's own wrapper forms, and that the record one function
//! writes is the record another reads.
//!
//! # The incident this is about
//!
//! Measured 2026-08-23: `./tests/bats/bin/bats --filter … tests/land.bats`, which
//! reaches the suite runner without the environment the pin composes. Sixty runs
//! died on an unset variable rather than on the assertion under test, and the
//! report that followed was published as three claims about the tree, all false.
//! `the_measured_argv_is_reported` pins that exact command line.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use batten::facts::Look;
use batten::pinned;
use common::{Fixture, run_with_stdin, stderr};

/// A checkout carrying this repository's own committed config, plus the manifest
/// the record is keyed to.
///
/// The config is `include_str!`'d rather than hand-written for the reason
/// `board_receipts.rs` states: a fixture spelling its own row would pass over a
/// committed row that says something else, and the row under test here is the
/// one this repository actually enables.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name)
        .config(include_str!("../../../../batten.toml"))
        .file("mise.toml", "[tools]\njq = \"1.7\"\n");
    // The in-repo modules that config registers, copied by ENUMERATION rather
    // than by name — `board_receipts.rs`'s reasoning, and naming them would put a
    // consumer's policy filenames in `crates/**` (non-negotiable rule 1).
    //
    // NOT OPTIONAL, AND THE OMISSION IS INSTRUCTIVE: without them the load fails
    // on the first unreadable module, every call gets that error instead of a
    // decision, and the three cases below that assert a SILENCE all pass over it.
    // Measured here, first run — one case failed honestly and three were green
    // for the wrong reason.
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let entry = entry.expect("a policy directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(entry.file_name())).expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// What the engine said about this call, on the channel a `warn` row speaks on.
fn advice(repo: &Path, command: &str) -> String {
    stderr(&run_with_stdin(
        repo,
        &["hook", "--harness", "exit-code"],
        &payload(command),
    ))
}

/// The pin configuration the fixture is keyed to.
///
/// A path the FIXTURE owns rather than one asked of a real pin: `configs` spawns,
/// and a test that had to install a toolchain to reach the record would be
/// asserting its own premise before its conclusion (`.claude/rules/rust.md`).
/// What these cases are about is the writer and the reader agreeing over the same
/// key, which does not depend on where the list came from.
fn configs(repo: &Path) -> Vec<PathBuf> {
    vec![repo.join("mise.toml")]
}

fn provided(repo: &Path, programs: &[&str]) {
    let set: BTreeSet<String> = programs.iter().map(|name| (*name).to_owned()).collect();
    assert!(
        pinned::record(repo, &configs(repo), &set),
        "the fixture's record should be writable"
    );
}

// ---------------------------------------------------------------------------
// The record: one writer, one reader.
// ---------------------------------------------------------------------------

#[test]
fn the_record_round_trips() {
    // Without this every case below could pass over a reader that answers from
    // something other than what the writer wrote.
    let repo = repo("pinned-round-trip");
    provided(&repo, &["bats", "jq"]);
    let Look::Is(read) = pinned::cached(&repo) else {
        panic!("a record just written should read back");
    };
    assert!(read.contains("bats") && read.contains("jq"));
}

#[test]
fn a_record_keyed_to_another_manifest_is_could_not_look() {
    // The whole of the caching claim: the key is what can invalidate the answer,
    // so a session that adds a tool must not be served the previous session's
    // set. Stale-as-could-not-look is also what makes the failure quiet rather
    // than wrong — the fact names every program in the project.
    let repo = repo("pinned-stale-key");
    provided(&repo, &["bats"]);
    std::fs::write(repo.join("mise.toml"), "[tools]\njq = \"1.8\"\n")
        .expect("the fixture manifest is writable");
    assert!(
        pinned::cached(&repo).could_not_look(),
        "a record under the previous manifest's key is not an answer about this one"
    );
}

#[test]
fn a_lockfile_appearing_beside_the_manifest_moves_the_key() {
    // The case the sibling expansion exists for, and the one a key over the
    // pin's REPORTED configs alone would miss: a pin does not list its lockfile
    // as configuration, and an install that resolves a floating version writes
    // the lockfile without touching the manifest. Recorded once, that set would
    // outlive the toolchain it describes.
    let repo = repo("pinned-lock-appears");
    provided(&repo, &["bats"]);
    assert!(
        !pinned::cached(&repo).could_not_look(),
        "the record just written is an answer about this tree"
    );
    std::fs::write(repo.join("mise.lock"), "[tools.jq]\nversion = \"1.8\"\n")
        .expect("the fixture lockfile is writable");
    assert!(
        pinned::cached(&repo).could_not_look(),
        "a lockfile that appeared after the record is a different toolchain"
    );
}

#[test]
fn a_checkout_with_no_record_is_could_not_look() {
    // The common case on a fresh clone, and the one that must never refuse.
    let repo = repo("pinned-no-record");
    assert!(pinned::cached(&repo).could_not_look());
}

// ---------------------------------------------------------------------------
// The practice, end to end.
// ---------------------------------------------------------------------------

#[test]
fn the_measured_argv_is_reported() {
    // The 2026-08-23 command, character for character in its shape: the runner
    // reached by path, with a filter, against a suite. What made it dangerous is
    // that nothing about the failure said "you invoked this wrong".
    let repo = repo("pinned-measured-argv");
    provided(&repo, &["bats"]);
    let said = advice(
        &repo,
        "./tests/bats/bin/bats --filter 'a case' tests/land.bats",
    );
    assert!(
        said.contains("bats"),
        "the program reached around the pin should be named: {said}"
    );
}

#[test]
fn the_same_program_through_the_pin_is_not_reported() {
    // The half that pays for the practice. `mise exec` is looked THROUGH by the
    // boundary, so the effective program is the same one — and the difference
    // this row exists for is entirely whether the pin selected it.
    let repo = repo("pinned-mediated");
    provided(&repo, &["bats"]);
    let said = advice(&repo, "mise exec -- bats tests/land.bats");
    assert!(
        !said.contains("V-PIN-BYPASSED"),
        "the mediated form is the sanctioned one: {said}"
    );
}

#[test]
fn a_program_the_pin_does_not_provide_is_not_reported() {
    // A gate that fired on every program would be a ban on the shell, and would
    // be switched off within a day.
    let repo = repo("pinned-unprovided");
    provided(&repo, &["bats"]);
    let said = advice(&repo, "ls -la tests");
    assert!(
        !said.contains("V-PIN-BYPASSED"),
        "an unpinned program is a genuine one-off: {said}"
    );
}

#[test]
fn a_checkout_with_no_record_reports_nothing() {
    // Could-not-look reaching all the way to the decision, which is the property
    // the module's own `null` case asserts one layer down and cannot assert here:
    // this is the engine choosing to project `null` rather than an empty list.
    let repo = repo("pinned-silent");
    let said = advice(
        &repo,
        "./tests/bats/bin/bats --filter 'a case' tests/land.bats",
    );
    assert!(
        !said.contains("V-PIN-BYPASSED"),
        "a project whose pin could not be read is not one to refuse: {said}"
    );
}
