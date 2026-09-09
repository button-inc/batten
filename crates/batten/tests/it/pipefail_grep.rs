//! No producer is piped into an early-exiting grep under pipefail, over the
//! compiled binary (ported from `mise-tasks/pipefail-grep-check.sh` under
//! CLOUD-843).
//!
//! **What is decidable only here.** `policy/pipefail-grep.rego` carries
//! load-time cases pinning the flag reading and the `||` distinction, and each
//! fabricates `input.tree.lines`. Only a real repository shows the engine
//! handing this module the shell corpus — the anti-vacuity half, since a scan
//! that matched no file reports "no producer is piped into an early-exiting
//! grep" over nothing and reads as coverage (CLOUD-418).
//
// carried: mise-tasks/pipefail-grep-check.sh policy/pipefail-grep.rego crates/batten/tests/it/pipefail_grep.rs
// carried: tests/pipefail-grep-check.bats policy/pipefail-grep.rego crates/batten/tests/it/pipefail_grep.rs
//
// carried: "the exact shape that broke issue-guard is flagged" policy/pipefail-grep.rego
// carried: "the here-string fix passes" policy/pipefail-grep.rego
// carried: "a flag cluster is judged by its letters, not its spelling" policy/pipefail-grep.rego
// carried: "--quiet is the same hazard under its long name" policy/pipefail-grep.rego
// carried: "-l stops at the first matching file, so it is flagged too" policy/pipefail-grep.rego
// carried: "-m N stops after N matches" policy/pipefail-grep.rego
// carried: "a grep that consumes its whole input is not the hazard" policy/pipefail-grep.rego
// carried: "an || before grep is not a pipe" policy/pipefail-grep.rego
// carried: "a real pipe into an early-exiting grep is still caught alongside an ||" policy/pipefail-grep.rego
// carried: "a file that does not enable pipefail is out of scope" policy/pipefail-grep.rego
// carried: "a comment describing the hazard is not the hazard" policy/pipefail-grep.rego
// carried: "-q after -- is a pattern, not a flag" policy/pipefail-grep.rego
// carried: "output is a pointer — file:line and the fix, never the matched content" policy/pipefail-grep.rego
//
// changed: "an untracked file is not judged — the gate reads committed bytes" policy/pipefail-grep.rego the shell fed itself `git ls-files`, so the index was its subject. `input.tree.lines` resolves from a declared glob over the working-tree walk, which honours `.gitignore` and explicitly is not the index, and nothing available to a module expresses index membership for a glob. The successor judges an uncommitted program too — stricter, fail-closed, and the same difference `policy/module-map.rego` and `policy/awk-regex.rego` record for their own ports

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

fn pipefail_repo(name: &str, program: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[pattern]]\n\
             id = \"shell-enables-pipefail\"\n\
             regex = '^[[:space:]]*set[[:space:]]+-[a-z]*o?[a-z]*[[:space:]]*.*pipefail'\n\n\
             [[pattern]]\n\
             id = \"pipe-into-grep\"\n\
             regex = '(^|[^|])\\|[[:space:]]*grep([[:space:]]|$)'\n\n\
             [[verdict]]\n\
             id = \"spawn read broken\"\n\
             gloss = \"a command is spelled in a way whose behaviour is not defined\"\n\
             class = \"An early-exiting grep under pipefail promotes SIGPIPE to the pipeline's status, so a MATCH reports failure.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"pipefail-grep\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"mise-tasks/**\"]\n\
             module = \"policy/pipefail-grep.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("mise-tasks/demo.sh", program)
        .git()
        .build();
    common::write(
        &dir,
        "policy/pipefail-grep.rego",
        &std::fs::read_to_string(common::at_root("policy/pipefail-grep.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "pipefail-grep"])
}

const HEAD: &str = "#!/usr/bin/env bash\nset -euo pipefail\n";

#[test]
fn the_shape_that_broke_issue_guard_is_flagged_over_the_binary() {
    let dir = pipefail_repo(
        "pipefail-issue-guard",
        &format!("{HEAD}git log --format=%B main | grep -q \"$id\"\n"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("mise-tasks/demo.sh"),
        "the finding points at the line: {text:?}"
    );
    assert!(
        !text.contains("git log"),
        "the matched content is payload and never appears: {text:?}"
    );
}

#[test]
fn the_here_string_fix_passes() {
    let dir = pipefail_repo(
        "pipefail-here-string",
        &format!("{HEAD}x=$(git log)\ngrep -q \"$id\" <<<\"$x\"\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn a_flag_cluster_is_judged_by_its_letters_over_the_binary() {
    // `-qxF` is the same hazard as `-q`. The predecessor's own comment says the
    // enumeration of exact spellings is what would rot.
    let dir = pipefail_repo(
        "pipefail-cluster",
        &format!("{HEAD}producer | grep -qxF thing\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(2));
}

#[test]
fn an_or_before_grep_is_not_a_pipe() {
    // DISCRIMINATING, and the case the predecessor's own scan failed: it matched
    // the SECOND bar of `||` and reported a here-string — the remedy this gate
    // recommends — as the defect. Measured on `ready-lint.sh` (CLOUD-852).
    let dir = pipefail_repo(
        "pipefail-or",
        &format!("{HEAD}[[ -n \"$x\" ]] || grep -qE 'p' <<<\"$var\"\n"),
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the second bar of `||` was read as a pipe: {}",
        stdout(&output)
    );
}

#[test]
fn a_grep_that_consumes_its_whole_input_is_not_the_hazard() {
    let dir = pipefail_repo(
        "pipefail-full-consume",
        &format!("{HEAD}producer | grep thing\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn a_file_that_does_not_enable_pipefail_is_out_of_scope() {
    let dir = pipefail_repo(
        "pipefail-not-enabled",
        "#!/usr/bin/env bash\nproducer | grep -q thing\n",
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn q_after_the_separator_is_a_pattern_not_a_flag() {
    let dir = pipefail_repo(
        "pipefail-separator",
        &format!("{HEAD}producer | grep -- -q\n"),
    );
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn this_repos_own_programs_pass_today() {
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "pipefail-grep"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a producer is piped into an early-exiting grep in this tree: {}",
        stdout(&output)
    );
}
