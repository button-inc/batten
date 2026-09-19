//! `batten ci slow-needed` and the gate over its list — CLOUD-398/CLOUD-1716,
//! ported off `mise-tasks/ci-slow-needed.sh`.
//!
//! # The list moved, and that is what made the self-test a gate
//!
//! The retired program owned its inert list and probed it from inside itself,
//! arguing that a second program asserting things about the list would be the
//! second authority non-negotiable 6 condemns. It was right while the list lived
//! in the program. With the list in `[ci] slow_inert` the argument reverses:
//! `policy/ci-slow-inert.rego` READS declared data rather than owning a rival
//! copy, so there is exactly one authority and the probes are a gate.
//!
//! # What the verb owes that the pure decision cannot show
//!
//! `ci::first_live_path` is pure and its cases cover the prefix rule, the exact
//! rule and the empty list. They cannot show that the VERB resolves a base,
//! reads the declared list, reports could-not-look for an empty diff, or names
//! the deciding path rather than counting. Those are properties of the compiled
//! binary.
//
// carried: mise-tasks/ci-slow-needed.sh crates/batten/src/ci.rs kind:verb crates/batten/tests/it/ci_slow_needed.rs runs:mise+run+ci-slow-needed
// carried: tests/ci-slow-needed.bats crates/batten/src/ci.rs kind:verb crates/batten/tests/it/ci_slow_needed.rs
//
// carried: "a crates change still needs the slow tier" crates/batten/src/ci.rs
// carried: "a memories-only diff does not need the slow tier" crates/batten/src/ci.rs
// carried: "the bot config is inert too — the diff that bought an 18-minute run" crates/batten/src/ci.rs
// carried: "ONE non-inert path in a mostly-inert diff still needs the tier" crates/batten/src/ci.rs
// carried: "an empty diff is could-not-look, not a clean skip" crates/batten/src/ci.rs kind:verb crates/batten/tests/it/ci_slow_needed.rs runs:mise+run+ci-slow-needed
// carried: "no base revision refuses rather than guessing" crates/batten/src/ci.rs kind:verb crates/batten/tests/it/ci_slow_needed.rs runs:mise+run+ci-slow-needed
// carried: "output is a pointer — no file contents echoed" crates/batten/src/ci.rs kind:verb crates/batten/tests/it/ci_slow_needed.rs runs:mise+run+ci-slow-needed
// changed: "the probe mode holds the inert list to both directions" policy/ci-slow-inert.rego the probes are unchanged and both directions survive — a live path declared inert, and an inert path no longer covered — but they are a rule over declared config rather than a flag on the program that owns the list, which is what the move from program to `[ci] slow_inert` makes possible

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{self, Fixture, batten, git_in};

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// A repository with one commit to diff against, and a second the checkout sits
/// on. The config declares the inert list this tree's own does.
fn repo(name: &str, changed: &str) -> std::path::PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\n\n[ci]\nrequired_checks = [\"final\"]\nslow_inert = [\".serena/memories/\"]\n")
        .file("seed.txt", "seed\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["branch", "base"]);
    std::fs::create_dir_all(dir.join(changed).parent().unwrap()).unwrap();
    std::fs::write(dir.join(changed), "moved\n").unwrap();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "work"]);
    dir
}

#[test]
fn a_live_path_needs_the_tier_and_is_named() {
    let dir = repo("slow-needed-live", "crates/demo/src/lib.rs");
    let output = batten()
        .args(["ci", "slow-needed", "--base", "base"])
        .current_dir(&dir)
        .output()
        .expect("run batten ci slow-needed");

    assert_eq!(output.status.code(), Some(0), "the tier is needed");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("crates/demo/src/lib.rs"),
        "the deciding path is named, not counted: {said}"
    );
    // A POINTER, NEVER THE PAYLOAD: the file's contents are what must not travel.
    assert!(!said.contains("moved"), "no file contents echoed: {said}");
}

#[test]
fn an_all_inert_diff_does_not_need_the_tier() {
    let dir = repo("slow-needed-inert", ".serena/memories/core.md");
    let output = batten()
        .args(["ci", "slow-needed", "--base", "base"])
        .current_dir(&dir)
        .output()
        .expect("run batten ci slow-needed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "every changed path is inert, so the answer is no"
    );
}

#[test]
fn an_empty_diff_is_could_not_look_rather_than_a_clean_skip() {
    // THE FALSE-ABSENT THE RETIRED PROGRAM NAMES: an empty diff means the
    // comparison did not look — a wrong base, a shallow clone — and answering
    // "skip the tier" there is the failure this refuses.
    let dir = repo("slow-needed-empty", ".serena/memories/core.md");
    let output = batten()
        .args(["ci", "slow-needed", "--base", "HEAD"])
        .current_dir(&dir)
        .output()
        .expect("run batten ci slow-needed");

    assert_eq!(output.status.code(), Some(3), "could-not-look, not clean");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could-not-look"),
        "and it says so"
    );
}

#[test]
fn a_base_that_does_not_resolve_refuses_rather_than_guessing() {
    let dir = repo("slow-needed-unresolvable", "crates/demo/src/lib.rs");
    let output = batten()
        .args(["ci", "slow-needed", "--base", "no-such-rev"])
        .current_dir(&dir)
        .output()
        .expect("run batten ci slow-needed");

    assert_ne!(
        output.status.code(),
        Some(0),
        "an unresolvable base is not a yes"
    );
    assert_ne!(output.status.code(), Some(2), "and not a no either");
}

// --- The gate over the list itself -------------------------------------------
//
// The retired program's `--probe` mode, now a rule over declared config. These
// run the COMMITTED module through the real read surface, which is the only
// thing that shows the `[ci] slow_inert` key parses into
// `input.tree.documents["batten.toml"].ci.slow_inert` at all — the hazard
// `rules/policy-modules.md` names, where a module's own `test_` cases hand
// themselves a shape the engine never builds.

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "path list loose",
        "kind": "policy",
        "scope": "tree",
        "documents": ["batten.toml"],
        "module": "policy/ci-slow-inert.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a config and the committed module.
fn tree(name: &str, config: &str) -> PathBuf {
    let root = common::scratch(&format!("ci-slow-inert-{name}"));
    common::write(&root, "batten.toml", config);
    let source = common::at_root("policy/ci-slow-inert.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/ci-slow-inert.rego")).expect("install committed module");
    root
}

fn findings(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.path)
    .collect()
}

#[test]
fn a_list_admitting_a_path_that_moves_the_tier_is_refused() {
    // The direction that LOSES A VERDICT: `batten.toml` declared inert would let
    // a config change skip every slow step, green over a check nobody ran.
    let root = tree(
        "admits",
        "version = 1\n\n[ci]\nslow_inert = [\".serena/memories/\", \".coderabbit.yaml\", \"batten.toml\"]\n",
    );
    assert!(
        findings(&root).contains(&"batten.toml".to_owned()),
        "the admitted live path is reported"
    );
}

#[test]
fn a_list_that_stopped_covering_an_inert_path_is_reported_too() {
    // The direction that costs a BILL, whose only symptom is minutes.
    let root = tree(
        "dropped",
        "version = 1\n\n[ci]\nslow_inert = [\".serena/memories/\"]\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "dropping `.coderabbit.yaml` is a finding, not a quiet narrowing"
    );
}

#[test]
fn an_undeclared_list_is_could_not_look_rather_than_clean() {
    let root = tree("undeclared", "version = 1\n");
    assert!(
        !findings(&root).is_empty(),
        "a list nobody could read is not a list anybody reviewed"
    );
}

#[test]
fn a_sound_list_is_clean() {
    // The shape that has to keep PASSING — without it every case above is green
    // over a module that reports on everything.
    let root = tree(
        "sound",
        "version = 1\n\n[ci]\nslow_inert = [\".serena/memories/\", \".coderabbit.yaml\"]\n",
    );
    assert_eq!(findings(&root), Vec::<String>::new(), "no findings");
}
