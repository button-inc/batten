//! `review open twice`: one pull request per branch until it lands (CLOUD-1891).
//!
//! AGENTS.md's "one PR all of it" was prose, and a session split a bundle into a
//! second PR twice in two days. The mechanism is a branch-keyed marker minted from
//! `create_pull_request`'s own result and a row that refuses the next
//! `create_pull_request` while it exists. These cases run the committed config,
//! so they break if either half of the pair is edited away.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// Carries a `/`, because the marker's filename replaces it.
const BRANCH: &str = "claude/one-pr-probe";

const TOOL: &str = "mcp__github__create_pull_request";

/// This repository's own rows and modules, on [`BRANCH`].
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let path = entry.expect("a policy directory entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(path.file_name().expect("a file name")))
                .expect("copy a policy module");
        }
    }
    let dir = staged.git().base_commit().build();
    common::git_command(&dir, &["checkout", "-q", "-b", BRANCH])
        .status()
        .expect("checkout the probe branch");
    dir
}

fn marker(dir: &Path) -> PathBuf {
    let output = common::git_command(dir, &["rev-parse", "--absolute-git-dir"])
        .output()
        .expect("resolve the git dir");
    PathBuf::from(String::from_utf8(output.stdout).expect("utf-8").trim())
        .join("batten-receipts")
        .join(format!("pr-open.{}", BRANCH.replace('/', "-")))
}

fn envelope(event: &str, extra: &str) -> String {
    format!(
        "{{\"hook_event_name\":\"{event}\",\"tool_name\":\"{TOOL}\",\
         \"tool_input\":{{\"title\":\"t\",\"head\":\"{BRANCH}\",\"base\":\"main\"}}{extra}}}"
    )
}

fn open_a_pr(dir: &Path) -> std::process::Output {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &envelope("PreToolUse", ""),
    )
}

/// The result of a PR that really opened mints the marker, and the next
/// `create_pull_request` on the same branch is refused by `review open twice`.
///
/// MUTANT: dropping `while_marker = "pr-open"` from the row denies EVERY PR,
/// which `a_branch_with_no_open_pr_may_open_one` catches; dropping the `[[mint]]`
/// leaves the marker unwritten and this case goes red.
#[test]
fn a_second_pr_while_the_first_is_unlanded_is_refused() {
    let dir = repo("one-pr-second");
    let _ = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &envelope(
            "PostToolUse",
            ",\"tool_response\":{\"id\":\"1\",\"url\":\"https://github.com/o/r/pull/1\"}",
        ),
    );
    assert!(
        marker(&dir).exists(),
        "an opened PR mints the branch marker"
    );

    let refusal = open_a_pr(&dir);
    assert_eq!(refusal.status.code(), Some(2), "{}", stderr(&refusal));
    let text = stderr(&refusal);
    assert!(
        crate::common::refusing_rule(&text).as_deref() == Some("review open twice"),
        "refused by the one-PR row: {text}"
    );
}

/// ANTI-VACUITY: a branch with no open PR is not refused, so the row is not a
/// blanket ban on opening pull requests.
#[test]
fn a_branch_with_no_open_pr_may_open_one() {
    let dir = repo("one-pr-first");
    assert!(!marker(&dir).exists());
    let decided = open_a_pr(&dir);
    assert!(
        !stderr(&decided).contains("review open twice"),
        "the first PR on a branch is allowed: {}",
        stderr(&decided)
    );
}
