//! Every workflow job's timeout carries a budget that justifies it, over the
//! compiled binary (CLOUD-266, ported from `mise-tasks/timeout-check.sh` under
//! CLOUD-843).
//!
//! **What is decidable only here.** `policy/timeout-budget.rego` carries
//! load-time cases pinning the walker, the two grammars and the arithmetic, and
//! every one supplies one workflow with `with input as`. That fabricates the very
//! shape the engine may be unable to produce (CLOUD-845), and this rule's declared
//! SCOPE is precisely what it fabricates: every workflow including the scheduled
//! and release ones, which is the hole the retiring gate was written to fill. A
//! resolution reaching only some of them would leave the most expensive job here
//! unbounded with nothing red — and a module whose suite only fabricated one file
//! cannot tell that state from a clean one.
//!
//! The self-consumption case is the one the retiring suite opened on: the real
//! workflows all carry a justified budget today.
//
// carried: mise-tasks/timeout-check.sh policy/timeout-budget.rego crates/batten/tests/it/timeout_budget.rs
// carried: tests/timeout-check.bats policy/timeout-budget.rego crates/batten/tests/it/timeout_budget.rs
//
// carried: "the repo's real workflows all carry a justified budget today" policy/timeout-budget.rego
// carried: "a grandfathered budget passes — dated debt is the day-one state" policy/timeout-budget.rego
// carried: "a measured budget whose arithmetic agrees passes" policy/timeout-budget.rego
// carried: "a job with no timeout-minutes is caught, and the pointer names the job" policy/timeout-budget.rego
// carried: "a timeout with no budget comment is caught" policy/timeout-budget.rego
// carried: "a malformed budget comment is caught" policy/timeout-budget.rego
// carried: "a budget comment missing its measured= date is malformed, not accepted" policy/timeout-budget.rego
// carried: "a measured budget whose declared minutes disagree with its own arithmetic is caught" policy/timeout-budget.rego
// carried: "a per-job multiplier is refused — the multiplier is one repo-wide constant" policy/timeout-budget.rego
// carried: "a step-level timeout does not satisfy the job's obligation" policy/timeout-budget.rego
// carried: "a matrix job passes with one budget covering every leg" policy/timeout-budget.rego
// carried: "prose that merely mentions a budget does not satisfy any job" policy/timeout-budget.rego
// carried: "every offender is reported in one pass, not just the first" policy/timeout-budget.rego
// carried: "a file with no jobs: block is exit 2, never a pass" policy/timeout-budget.rego
// carried: "a jobs: block with no job keys under it is exit 2, never a pass" policy/timeout-budget.rego
// changed: "a missing file is exit 2, never a pass" policy/timeout-budget.rego the shell took explicit paths and refused one it could not open; the successor declares a `line_sources` glob and the ENGINE decides this earlier — a rule whose glob matches nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). The two arms that carried the weight survive whole: a workflow that resolves and declares no jobs block, and one whose jobs block has no keys under it, are both `job list empty`
// changed: "the gate makes no network call" policy/timeout-budget.rego the property is carried by CONSTRUCTION rather than by a case: a `kind = "policy"` rule over `scope = "tree"` reads `input.tree` and has no spawn or socket surface at all, where the shell could in principle have reached the network and needed a case saying it did not

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn budget_repo(name: &str, workflows: &[(&str, &str)]) -> PathBuf {
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[pattern]]\n\
         id = \"workflow-job-key\"\n\
         regex = '^  [A-Za-z0-9_-]+:[[:space:]]*$'\n\n\
         [[pattern]]\n\
         id = \"workflow-top-level-key\"\n\
         regex = '^[a-z][A-Za-z0-9_-]*:'\n\n\
         [[pattern]]\n\
         id = \"job-timeout-line\"\n\
         regex = '^    timeout-minutes:[[:space:]]*[0-9]+'\n\n\
         [[pattern]]\n\
         id = \"timeout-budget-measured\"\n\
         regex = '^#[[:space:]]*budget:[[:space:]]*p95=([0-9]+)s[[:space:]]+x([0-9]+)[[:space:]]+measured=([0-9]{4}-[0-9]{2}-[0-9]{2})[[:space:]]*$'\n\n\
         [[pattern]]\n\
         id = \"timeout-budget-grandfathered\"\n\
         regex = '^#[[:space:]]*budget:[[:space:]]*grandfathered[[:space:]]+measured=[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]*$'\n\n\
         [[verdict]]\n\
         id = \"timer declare missing\"\n\
         gloss = \"a workflow job declares no timeout at all\"\n\
         class = \"An unbounded job burns a runner until the forge's own ceiling stops it.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"timer carry unnamed\"\n\
         gloss = \"a timeout carries no budget comment beside it\"\n\
         class = \"A limit with no justification is boilerplate and never reports that a job got slower.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"timer parse unclear\"\n\
         gloss = \"a budget comment does not match either accepted form\"\n\
         class = \"A budget a reader cannot parse is one a gate cannot check.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"timer count wrong\"\n\
         gloss = \"a measured budget's declared minutes disagree with its own stated p95\"\n\
         class = \"A justification for a different number than the one enforced.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"timer count other\"\n\
         gloss = \"a measured budget uses a multiplier other than the repository's\"\n\
         class = \"A per-job multiplier is a per-job argument.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"job list empty\"\n\
         gloss = \"a workflow declares no jobs this rule can read\"\n\
         class = \"A file that cannot be parsed as a workflow is not one with no jobs.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"timeout-budget\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\".github/workflows/*.yml\"]\n\
         module = \"policy/timeout-budget.rego\"\n\
         severity = \"deny\"\n",
    );
    fixture = fixture.file("AGENTS.md", "the consumer's own authority\n");
    for (path, body) in workflows {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/timeout-budget.rego",
        &std::fs::read_to_string(common::at_root("policy/timeout-budget.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "timeout-budget"])
}

/// One workflow whose `jobs:` block carries `jobs`.
fn flow(jobs: &str) -> String {
    format!("on: push\njobs:\n{jobs}")
}

const GRANDFATHERED: &str = "  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15 # budget: grandfathered measured=2026-08-01\n";

#[test]
fn a_grandfathered_budget_passes() {
    // Dated debt is the day-one state: honest, gateable, and visibly not a
    // justification.
    let dir = budget_repo(
        "budget-grandfathered",
        &[(".github/workflows/ci.yml", &flow(GRANDFATHERED))],
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_measured_budget_whose_arithmetic_agrees_passes() {
    let dir = budget_repo(
        "budget-measured",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 14 # budget: p95=267s x3 measured=2026-08-01\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_job_with_no_timeout_is_refused_and_the_pointer_names_the_job() {
    let dir = budget_repo(
        "budget-no-timeout",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    runs-on: ubuntu-latest\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("build"),
        "the pointer names the job: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_timeout_with_no_budget_comment_is_refused() {
    let dir = budget_repo(
        "budget-no-comment",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 15\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_malformed_budget_comment_is_refused() {
    let dir = budget_repo(
        "budget-malformed",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 15 # budget is generous here\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_budget_missing_its_measured_date_is_malformed() {
    // The grammars are matched WHOLE, so a nearly-right comment is not accepted.
    let dir = budget_repo(
        "budget-no-date",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 15 # budget: grandfathered\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn arithmetic_that_disagrees_with_its_own_p95_is_refused() {
    // The capability the retiring program said a `forbid` row did not have: a
    // numeric comparison over a parsed field.
    let dir = budget_repo(
        "budget-arithmetic",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 30 # budget: p95=267s x3 measured=2026-08-01\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_per_job_multiplier_is_refused() {
    // The point of a single number is that loosening it anywhere is visible as
    // loosening it everywhere.
    let dir = budget_repo(
        "budget-multiplier",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    timeout-minutes: 45 # budget: p95=267s x10 measured=2026-08-01\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_step_timeout_does_not_satisfy_the_jobs_obligation() {
    let dir = budget_repo(
        "budget-step-level",
        &[(
            ".github/workflows/ci.yml",
            &flow(
                "  build:\n    steps:\n      - run: make\n        timeout-minutes: 5 # budget: grandfathered measured=2026-08-01\n",
            ),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_matrix_job_passes_with_one_budget_covering_every_leg() {
    // The structural oddity a separate budget table would have needed a key
    // scheme to express.
    let dir = budget_repo(
        "budget-matrix",
        &[(
            ".github/workflows/release-artifacts.yml",
            &flow(
                "  dist:\n    strategy:\n      matrix:\n        target: [a, b, c]\n    timeout-minutes: 30 # budget: grandfathered measured=2026-08-01\n",
            ),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn prose_that_merely_mentions_a_budget_satisfies_no_job() {
    let dir = budget_repo(
        "budget-prose",
        &[(
            ".github/workflows/ci.yml",
            &format!(
                "# budget: grandfathered measured=2026-08-01\n{}",
                flow("  build:\n    timeout-minutes: 15\n")
            ),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn every_offender_is_reported_in_one_pass() {
    let dir = budget_repo(
        "budget-many-offenders",
        &[
            (
                ".github/workflows/ci.yml",
                &flow("  build:\n    timeout-minutes: 15\n"),
            ),
            (
                ".github/workflows/release.yml",
                &flow("  publish:\n    runs-on: ubuntu-latest\n"),
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("build") && text.contains("publish"),
        "one run reports both: {text:?}"
    );
}

#[test]
fn a_file_with_no_jobs_block_is_not_a_pass() {
    let dir = budget_repo(
        "budget-no-jobs-block",
        &[(".github/workflows/ci.yml", "on: push\nname: ci\n")],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_jobs_block_with_no_job_keys_is_not_a_pass() {
    let dir = budget_repo(
        "budget-empty-jobs-block",
        &[(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  # every job was removed\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = budget_repo(
        "budget-pointer-only",
        &[(
            ".github/workflows/ci.yml",
            &flow("  build:\n    runs-on: a-distinctive-runner\n    timeout-minutes: 15\n"),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("a-distinctive-runner"),
        "the workflow body is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_real_workflows_all_carry_a_justified_budget() {
    // The self-consumption case the retiring suite opened on.
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "timeout-budget"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a job here has no justified budget: {}",
        stdout(&output)
    );
}
