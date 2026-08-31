//! The ENGINE tier for `suite-subject-retirable` (CLOUD-1156).
//!
//! The module's own `test_` rules pin the predicate. They cannot prove the engine
//! builds `input.tree.lines` for a `tests/*.bats` glob, and that key is the whole
//! of what this rule turns on: a module iterating a key nothing fills reports
//! green over a corpus it never read, and a dead gate and a clean tree are
//! byte-identical on the decision surface (CLOUD-845). A `with input as` case
//! fabricates exactly the shape that would be missing, so it cannot discriminate.

mod common;

use common::{at_root, batten, run, scratch, stdout};

/// A suite whose every declared subject is a path the campaign can retire.
const GOVERNED: &str = "#!/usr/bin/env bats\n# subject: mise-tasks/probe.sh\n@test 'a' { true; }\n";

/// A suite naming a subject no shell retirement deletes.
const IMMORTAL: &str = "#!/usr/bin/env bats\n# subject: mise.toml\n@test 'a' { true; }\n";

#[test]
fn the_engine_fills_lines_for_a_bats_glob_and_the_rule_fires() {
    // THE CASE THE LOAD-TIME TIER CANNOT MAKE. Everything below rests on the
    // engine actually populating `input.tree.lines` for `tests/*.bats`; if it
    // does not, `suites` is empty and every arm is vacuously satisfied.
    let dir = scratch("suite-subjects-positive");
    at_root(&dir, |root| {
        std::fs::create_dir_all(root.join("tests")).expect("tests dir");
        std::fs::write(root.join("tests/probe.bats"), IMMORTAL).expect("suite");
    });

    let out = run(batten(&dir).args(["check", "--rule", "suite-subject-retirable"]));
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("tests/probe.bats"),
        "the finding must point at the suite: {}",
        stdout(&out)
    );
}

#[test]
fn a_suite_subjecting_only_governed_programs_is_clean() {
    // THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by a rule
    // that reports every suite in the corpus, which would be a gate nobody could
    // leave switched on.
    let dir = scratch("suite-subjects-negative");
    at_root(&dir, |root| {
        std::fs::create_dir_all(root.join("tests")).expect("tests dir");
        std::fs::write(root.join("tests/probe.bats"), GOVERNED).expect("suite");
    });

    let out = run(batten(&dir).args(["check", "--rule", "suite-subject-retirable"]));
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

#[test]
fn a_suite_declaring_no_subject_is_not_a_clean_suite() {
    // Deleting the header would otherwise be the way OUT of this gate: the
    // immortal-subject arm quantifies over declared subjects, and a suite with
    // none satisfies it trivially.
    let dir = scratch("suite-subjects-headerless");
    at_root(&dir, |root| {
        std::fs::create_dir_all(root.join("tests")).expect("tests dir");
        std::fs::write(
            root.join("tests/probe.bats"),
            "#!/usr/bin/env bats\n@test 'a' { true; }\n",
        )
        .expect("suite");
    });

    let out = run(batten(&dir).args(["check", "--rule", "suite-subject-retirable"]));
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
}

#[test]
fn the_committed_tree_passes_its_own_rule() {
    // The exemption table is only honest if it actually covers this repository.
    // Run over the real tree: every immortal subject here is either declared or
    // this is a finding, and a stale exemption is a finding too — the table is
    // held in both directions.
    let out = run(
        batten(&std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).args([
            "check",
            "--rule",
            "suite-subject-retirable",
        ]),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the committed corpus must satisfy its own exemption table: {}",
        stdout(&out)
    );
}
