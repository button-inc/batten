//! `policy/privileged-lane.rego` decides over the compiled engine (CLOUD-931).
//!
//! # Where this came from
//!
//! The successor to `tests/privileged-lane.bats`, retired under CLOUD-1059. Its
//! subject was `policy/privileged-lane.rego`, which CLOUD-1050 rewrote: the
//! module's refusal stopped being prose and became a declared class, so the
//! suite's fixture — a `batten.toml` with no `[[verdict]]` row — stopped
//! loading. `shell-retirement` refuses editing a bats suite in place, so the
//! open door is the migration. Every case below carries a `// carried:` arm.
//!
//! # What it keeps
//!
//! `policy/privileged-lane.rego` is a live `deny` row over this repository's own
//! privileged CI lanes, and its nine `test_` rules are `with input as`
//! assertions — insufficient evidence on their own (CLOUD-845), because a module
//! can fabricate a shape the engine never produces, pass its own suite green,
//! and gate nothing. Every case here goes in through `batten check`, the same
//! door `verify` and the hk gate come through, and reads the verdict a caller
//! would read.
//!
//! The two tiers are complementary rather than redundant: the module's own rules
//! pin the PREDICATE, this file pins that the ENGINE builds the input the
//! predicate reads.

// THE FILE-GRANULARITY RETIREMENT ARM (CLOUD-1059). Its grammar is disjoint
// from CLOUD-908's case arms below by construction: a case arm's first field
// after the marker is a QUOTED case name, and a file arm's is a path. Neither
// reader can match the other's shape, which is what lets one marker carry two
// ledgers without a second convention.
//
// carried: tests/privileged-lane.bats policy/privileged-lane.rego crates/batten/tests/it/privileged_lane.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// A throwaway repository carrying the committed module, the row that enables
/// it, the class it raises, and one workflow.
fn fixture(name: &str, workflow: &str, body: &str) -> PathBuf {
    let root = common::scratch(&format!("privileged-lane-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::create_dir_all(root.join(".github/workflows")).expect("scratch workflows dir");
    let module = common::at_root("policy/privileged-lane.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::copy(module, root.join("policy/privileged-lane.rego")).expect("install committed module");
    fs::write(root.join(".github/workflows").join(workflow), body).expect("write the workflow");
    fs::write(
        root.join("batten.toml"),
        concat!(
            "version = 1\n\n",
            "[[rule]]\n",
            "id = \"privileged-lane-tests-origin\"\n",
            "kind = \"policy\"\n",
            "scope = \"tree\"\n",
            "sources = [\".github/workflows/*.yml\"]\n",
            "module = \"policy/privileged-lane.rego\"\n",
            "severity = \"deny\"\n\n",
            "[[verdict]]\n",
            "id = \"lane guard missing\"\n",
            "gloss = \"a job an outside author can reach holds contents:write and tests no head origin\"\n",
            "class = \"\"\"\n",
            "A trigger an outside author can fire, a token that can write, and no check that \\\n",
            "the head being built came from this repository.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"workflow read first\"\n",
            "kind = \"document\"\n",
            "target = \".github/workflows\"\n\n",
            // The split's second class (CLOUD-1317). Declaring it is not
            // optional here and the registry pushes both ways: the module can
            // raise it, so a fixture omitting the row fails to load with an
            // undeclared token — and a row nothing raises fails the load too, so
            // it cannot be declared anywhere the module does not emit it.
            "[[verdict]]\n",
            "id = \"lane resolve missing\"\n",
            "gloss = \"a job that looks up an outside head holds contents:write and tests no origin\"\n",
            "class = \"\"\"\n",
            "No trigger carries a head, so the job resolved one through the pulls API and the \\\n",
            "test belongs on what the lookup returned.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"workflow read first\"\n",
            "kind = \"document\"\n",
            "target = \".github/workflows\"\n\n",
            "[[verdict]]\n",
            "id = \"workflow parse broken\"\n",
            "gloss = \"a workflow could not be parsed, so its lanes were never judged\"\n",
            "class = \"\"\"\n",
            "Could-not-look, and deliberately not spelled the same way as a workflow whose \\\n",
            "lanes are all safe.\n",
            "\"\"\"\n\n",
            "[[verdict.route]]\n",
            "id = \"task run first\"\n",
            "kind = \"document\"\n",
            "target = \".github/workflows\"\n",
        ),
    )
    .expect("write the fixture authority");
    // No global or system config: a contributor's own git settings must not be
    // able to change a verdict here (CLOUD-282). `common::git_in` already fences
    // discovery; `init` is what makes the walk a repository walk.
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    root
}

/// The exit contract, asserted by NAME rather than by integer
/// (`.claude/rules/rust.md`): `2` is the policy verdict, `0` is clean. The shell
/// tasks' inverted convention must not be carried in — a case asserting `1` here
/// would be asserting "unreadable input" while meaning "violation", and it would
/// pass.
fn denied(root: &Path) {
    let output = common::run(root, &["check"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "expected the policy verdict: {text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("privileged-lane-tests-origin"),
        "the finding names the rule: {text}"
    );
}

fn clean(root: &Path) {
    let output = common::run(root, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "expected a clean tree: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

// carried: "a bot lane selecting by branch prefix is denied" crates/batten/tests/it/privileged_lane.rs
#[test]
fn a_bot_lane_selecting_by_branch_prefix_is_denied() {
    // The defect CLOUD-867 was filed for: the head is chosen by a string the PR
    // author picks. Driven through the engine rather than through `policy test`.
    let root = fixture(
        "branch-prefix",
        "auto-bot-land.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  land:\n    permissions:\n      \
         contents: write\n    if: startsWith(github.event.workflow_run.head_branch, 'renovate/')\n    \
         steps:\n      - run: echo land\n",
    );
    denied(&root);
}

// carried: "the same lane testing the head origin is clean" crates/batten/tests/it/privileged_lane.rs
#[test]
fn the_same_lane_testing_the_head_origin_is_clean() {
    // The discriminating half. Same trigger, same grant, same job — only the
    // origin test is added, so a gate that denied both would prove nothing.
    let root = fixture(
        "origin-tested",
        "auto-bot-land.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  land:\n    permissions:\n      \
         contents: write\n    if: github.event.workflow_run.head_repository.full_name == \
         github.repository\n    steps:\n      - run: echo land\n",
    );
    clean(&root);
}

// carried: "a scheduled writer that resolves no outside head is not a subject" crates/batten/tests/it/privileged_lane.rs
#[test]
fn a_scheduled_writer_that_resolves_no_outside_head_is_not_a_subject() {
    // THE FALSE POSITIVE THE THIRD CONJUNCT EXISTS FOR: `perf.yml` is scheduled,
    // holds contents:write to push its own series, and selects no outside head.
    // A gate whose first firing is a false positive gets an exception written
    // for it, and the exception is what rots.
    let root = fixture(
        "scheduled",
        "perf.yml",
        "on:\n  schedule:\n    - cron: \"0 0 * * *\"\n  workflow_dispatch:\njobs:\n  measure:\n    \
         permissions:\n      contents: write\n    steps:\n      - run: git push origin \
         refs/notes/perf\n",
    );
    clean(&root);
}

// carried: "an outsider-reachable writer that resolves no outside head is not a subject" crates/batten/tests/it/privileged_lane.rs
#[test]
fn an_outsider_reachable_writer_that_resolves_no_outside_head_is_not_a_subject() {
    // THE CASE THAT ACTUALLY DISCRIMINATES THE THIRD CONJUNCT. It exists because
    // the first declared mutation SURVIVED, and the survival identified a false
    // rationale rather than a false predicate.
    //
    // That rationale named `perf.yml` as what the third conjunct excludes.
    // Measured: the real `perf.yml` triggers are `schedule` and
    // `workflow_dispatch`, and NEITHER is in `outsider_reachable`'s list — so the
    // FIRST conjunct already excludes it and dropping the third changes nothing.
    // The module's own `test_a_scheduled_writer_with_no_outside_head_is_not_a_subject`
    // has the same hole. This comment records how it was found, because reading
    // could not have found it.
    //
    // A discriminating input is outsider-reachable (`issue_comment`), holds
    // `contents: write`, and resolves no outside head — no `pull_request` or
    // `workflow_run` trigger and no `/pulls` anywhere. Clean today; a finding the
    // moment the third conjunct stops being asked.
    let root = fixture(
        "outsider-reachable",
        "triage.yml",
        "on:\n  issue_comment:\n    types: [created]\njobs:\n  label:\n    permissions:\n      \
         contents: write\n    steps:\n      - run: echo \"labelling from a comment\"\n",
    );
    clean(&root);
}

// carried: "a read-only lane is not a subject" crates/batten/tests/it/privileged_lane.rs
#[test]
fn a_read_only_lane_is_not_a_subject() {
    let root = fixture(
        "read-only",
        "ci.yml",
        "on:\n  pull_request:\njobs:\n  gate:\n    permissions:\n      contents: read\n    \
         steps:\n      - run: echo test\n",
    );
    clean(&root);
}

// THE CASE THIS FILE DELIBERATELY DOES NOT CARRY, and the reason is a finding
// rather than an omission (CLOUD-1049).
//
// The module's first clause says an unparseable workflow lands in
// `input.tree.missing` and denies, so that "could not read it" never reads as
// "clean". Written as a case here, that is RED: a genuinely invalid workflow
// produces exit 0, no finding, and no cause, even under `--strictness strict`.
// The same fixture with a parseable workflow that fails the predicate denies at
// 2, so the row is live and selected; it is the unparseable path specifically
// that vanishes.
//
// It is not shipped red, and it is not shipped asserting the current behaviour
// either — that would bake the defect in as the contract and go green forever.
// CLOUD-1049 owns it and names this file as where the case belongs once the
// engine honours what the module already documents.
//
// This is also the clearest evidence for why this tier exists at all: the
// module's own `test_an_unparseable_workflow_denies_rather_than_passing` is
// GREEN, because `with input as` hands itself the populated `missing` the engine
// never builds (CLOUD-845).

// --- the class split, over the compiled binary (CLOUD-1317) -----------------
//
// THE OBVIOUS ASSERTION DOES NOT WORK, AND FINDING THAT OUT IS THE POINT OF THIS
// TIER. `check`'s line is `<path> <rule-id>` and its `--json` finding carries
// `rule`, `path`, `severity`, `report` and `identity` — the verdict class is on
// NEITHER. Two cases asserting the class appears in `check` output fail against a
// correctly split module, which is a test asserting its own premise rather than
// its conclusion (`.claude/rules/rust.md`, CLOUD-249). Measured, not reasoned:
// both were written that way first and both went red for that reason.
//
// What the engine DOES carry through is the registry, and its two directions are
// exactly a statement about how many classes the module raises. So the split is
// asserted where the engine actually decides it.

/// Both classes declared: the module loads and the lane is denied.
///
/// The anti-vacuity half. Without it the case below is satisfied by a fixture
/// that refuses every config, which would name the missing class every time and
/// prove nothing.
#[test]
fn a_resolver_lane_is_denied_where_both_classes_are_declared() {
    let root = fixture(
        "resolve-class",
        "auto-bot-land.yml",
        "on:\n  issue_comment:\n    types: [created]\njobs:\n  land:\n    permissions:\n      \
         contents: write\n    steps:\n      - run: gh api repos/$REPO/pulls?state=open\n",
    );
    denied(&root);
}

/// Dropping the resolve class refuses the LOAD, naming the token nothing declares.
///
/// This is the split, asserted over the compiled binary: an unsplit module raises
/// one token, so a config declaring only `lane guard missing` would load clean and
/// this case would go green for the wrong reason. It is red on a collapse and red
/// on a rename, which is what a class the reporting surface never prints needs.
///
/// Exit `1`, not `2`: a config that will not load is a statement about the
/// invocation, never a verdict about the repository.
#[test]
fn dropping_the_resolve_class_refuses_the_load_rather_than_reporting_one_class() {
    let root = fixture(
        "resolve-class-undeclared",
        "auto-bot-land.yml",
        "on:\n  issue_comment:\n    types: [created]\njobs:\n  land:\n    permissions:\n      \
         contents: write\n    steps:\n      - run: gh api repos/$REPO/pulls?state=open\n",
    );
    let config = root.join("batten.toml");
    let text = fs::read_to_string(&config).expect("the fixture authority is readable");
    let without = text
        .split("[[verdict]]\n")
        .filter(|block| !block.starts_with("id = \"lane resolve missing\""))
        .collect::<Vec<_>>()
        .join("[[verdict]]\n");
    assert_ne!(without, text, "the fixture must actually declare the class");
    fs::write(&config, without).expect("rewrite the fixture authority");

    let output = common::run(&root, &["check"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "an undeclared class is a config fault, not a verdict: {stderr}"
    );
    assert!(
        stderr.contains("lane resolve missing"),
        "the refusal names the token nothing declares: {stderr}"
    );
}
