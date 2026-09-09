//! The review bot's config still carries the keys the lifecycle rests on, over
//! the compiled binary (CLOUD-860, the missing half of CLOUD-847, ported from
//! `mise-tasks/coderabbit-config-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/coderabbit-config.rego` carries
//! load-time cases pinning the predicate, and every one supplies the config's
//! lines with `with input as`. That fabricates the very shape the engine may be
//! unable to produce (CLOUD-845), and for this rule it fabricates the one claim
//! the retiring program made loudest: that there is NO FAIL-OPEN ARM. The input
//! is a tracked file in this checkout, so "could not look" means the file is
//! gone, which is itself the state the rule refuses — and a module whose suite
//! only fabricated the lines cannot tell an engine that resolved the file from
//! one that resolved nothing, because both hand the predicate a value it treats
//! the same way.
//!
//! The self-consumption case is the one the retiring suite opened on: this
//! repository's own config holds the three keys.
//
// carried: mise-tasks/coderabbit-config-check.sh policy/coderabbit-config.rego crates/batten/tests/it/coderabbit_config.rs
// carried: tests/coderabbit-config-check.bats policy/coderabbit-config.rego crates/batten/tests/it/coderabbit_config.rs
//
// carried: "coderabbit-config-check.bats::the repo as it stands passes" policy/coderabbit-config.rego
// carried: "a compliant fixture passes" policy/coderabbit-config.rego
// carried: "request_changes_workflow flipped off fails, and names the key" policy/coderabbit-config.rego
// carried: "drafts flipped off fails, and names the key" policy/coderabbit-config.rego
// carried: "gitleaks disabled fails: drafts would have no secret scanning at all" policy/coderabbit-config.rego
// carried: "the gitleaks arm is SCOPED to gitleaks, not to the first tool in the file" policy/coderabbit-config.rego
// carried: "gitleaks absent passes: its default is enabled, so only an explicit false is a violation" policy/coderabbit-config.rego
// carried: "a key deleted rather than flipped fails: absence leaves the default in force" policy/coderabbit-config.rego
// carried: "a comment-only file is a failure, not a vacuous pass" policy/coderabbit-config.rego
// carried: "a commented-out key does not satisfy the assertion" policy/coderabbit-config.rego
// carried: "output is pointer-only: it names keys and lines, never the file's contents" policy/coderabbit-config.rego
// changed: "coderabbit-config-check.bats::the gate is wired: hk.pkl declares a step that runs this task" policy/coderabbit-config.rego the task the step ran no longer exists, so the case has no subject to assert. Its property does not go unheld: a `[[rule]]` row IS the wiring on the engine, `batten check` runs every registered row, and `glob-containment` refuses the commit where the hook manifest's trigger stops selecting a path the config makes an input — which is the same claim reached by a mechanism rather than by a suite reading a manifest
// changed: "an absent file fails rather than passing for want of anything to read" policy/coderabbit-config.rego the shell opened a named file and refused when it was gone; the successor declares it as a `line_sources` path and the ENGINE decides this earlier — a rule whose declared path matches nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). What the case protected survives as the vacuity arm: a file that resolves and declares no keys is `config carry empty`, never a pass

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn review_repo(name: &str, config: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"config carry empty\"\n\
             gloss = \"the review config declares none of the keys the lifecycle rests on\"\n\
             class = \"A key nobody wrote and a key someone deleted both leave the default in force.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"config state wrong\"\n\
             gloss = \"a review-config key is set to the value that switches the lifecycle off\"\n\
             class = \"The symptom is silence, and the visible failure is the gate rather than the cause.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"coderabbit-config\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\".coderabbit.yaml\"]\n\
             module = \"policy/coderabbit-config.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file(".coderabbit.yaml", config)
        .git()
        .build();
    common::write(
        &dir,
        "policy/coderabbit-config.rego",
        &std::fs::read_to_string(common::at_root("policy/coderabbit-config.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "coderabbit-config"])
}

const COMPLIANT: &str = "reviews:\n  request_changes_workflow: true\n  auto_review:\n    drafts: true\n  tools:\n    gitleaks:\n      enabled: true\n    ruff:\n      enabled: false\n";

#[test]
fn a_compliant_config_passes() {
    let dir = review_repo("review-compliant", COMPLIANT);
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
fn the_changes_workflow_flipped_off_is_refused() {
    let dir = review_repo(
        "review-workflow-off",
        &COMPLIANT.replace(
            "request_changes_workflow: true",
            "request_changes_workflow: false",
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains(".coderabbit.yaml:"),
        "the finding points at the line: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_draft_key_flipped_off_is_refused() {
    // Its symptom is SILENCE: reviews stop happening, which looks exactly like
    // nobody having pushed.
    let dir = review_repo(
        "review-drafts-off",
        &COMPLIANT.replace("drafts: true", "drafts: false"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn the_scanner_denied_explicitly_is_refused() {
    // The only secret scanning a draft gets.
    let dir = review_repo(
        "review-scanner-off",
        "reviews:\n  request_changes_workflow: true\n  auto_review:\n    drafts: true\n  tools:\n    gitleaks:\n      enabled: false\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn the_scanner_arm_is_scoped_to_its_own_block() {
    // The enabling key appears once per tool, so an unscoped read answers about
    // whichever tool came first in the file.
    let dir = review_repo(
        "review-scanner-scoped",
        "reviews:\n  request_changes_workflow: true\n  auto_review:\n    drafts: true\n  tools:\n    ruff:\n      enabled: false\n    gitleaks:\n      enabled: true\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn an_absent_scanner_block_passes() {
    // Its default is enabled, so only an explicit denial is a violation.
    let dir = review_repo(
        "review-scanner-absent",
        "reviews:\n  request_changes_workflow: true\n  auto_review:\n    drafts: true\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_key_deleted_rather_than_flipped_is_refused() {
    // ABSENCE LEAVES THE DEFAULT IN FORCE, which is the value the rule refuses —
    // a key nobody wrote and a key someone deleted are the same file.
    let dir = review_repo(
        "review-key-deleted",
        "reviews:\n  request_changes_workflow: true\n  auto_review:\n    base_branches:\n      - main\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_comment_only_file_is_a_failure_not_a_vacuous_pass() {
    // Every assertion here is ABOUT a key, so a file carrying none of them
    // satisfies all of them by having nothing to judge.
    let dir = review_repo(
        "review-comment-only",
        "# every key was removed\n# and this still parses as a document\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_commented_out_key_does_not_satisfy_the_assertion() {
    let dir = review_repo(
        "review-commented-key",
        "reviews:\n  # request_changes_workflow: true\n  auto_review:\n    drafts: true\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    // A config can carry review instructions and paths, and a gate that echoed
    // them would put them in every CI log.
    let dir = review_repo(
        "review-pointer-only",
        "reviews:\n  request_changes_workflow: false\n  auto_review:\n    drafts: true\n  path_instructions:\n    - path: \"crates/**\"\n      instructions: \"a distinctive instruction\"\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("distinctive instruction"),
        "the config's instructions are payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn this_repositorys_own_config_holds_the_three_keys() {
    // The self-consumption case the retiring suite opened on.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "coderabbit-config"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a key the review lifecycle rests on is missing or flipped: {}",
        stdout(&output)
    );
}
