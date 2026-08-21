//! Which directory `batten hook` reads its authority from (CLOUD-824).
//!
//! `load_policy` reads `./batten.toml` with no upward walk, so whichever
//! directory answers "where is the repository" decides whether a mediated call
//! is adjudicated at all. Until CLOUD-824 that answer came from a launcher in
//! shell — `.claude/hooks/batten-hook.sh` — which asked git the wrong question:
//!
//! ```text
//! cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}"
//! ```
//!
//! `--show-toplevel` is the **worktree's** toplevel. [`batten::git::repo_root`]
//! uses the common dir, which in a linked worktree is the **main** repository
//! root — deliberately, because that "keeps per-repository config and state
//! stable across worktrees". Measured on a constructed pair, the two answers are
//! different directories.
//!
//! So from a linked worktree whose checkout carries no `batten.toml`, the
//! launcher landed on `Policy::declaring_nothing` and allowed every mediated
//! call, silently — no deny, no error, no stderr line, because from the
//! launcher's point of view everything worked. That is verbatim the state the
//! launcher's own comment called the `cd` "the whole defence" against.
//!
//! **The first case here is red on `main`** (CLOUD-418), which is the evidence
//! this is a defect rather than a preference. The rest are the mirrors that stop
//! the fix from being a change only worktrees exercise: the main root, and a
//! subdirectory of it — the case the launcher was actually written for.

mod common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, git_in};

/// A policy with exactly one deny, so the assertion is unambiguous.
///
/// Not this repository's own `batten.toml`: a test reading the committed file
/// would pass or fail with an edit to production policy.
const ONE_DENY: &str = r#"version = 1

[[rule]]
id = "no-gh-pr-merge"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr merge"
reason = "use `mise run land`"
"#;

/// A payload the policy above refuses.
fn banned_payload() -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "gh pr merge 42" }
    })
    .to_string()
}

fn hook_from(dir: &Path) -> Output {
    let mut command = common::batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .env_remove("CLAUDE_PROJECT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(banned_payload().as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

/// Whether this run refused the call, read through both channels a host reads.
///
/// Exit `2` is the one contract (§7); the JSON body is what Claude Code parses.
/// Asserting on both is what stops a change that satisfies one and not the other.
fn denied(output: &Output) -> bool {
    output.status.code() == Some(2) || String::from_utf8_lossy(&output.stdout).contains("\"deny\"")
}

/// A repository with `batten.toml` committed on `main`, plus a **linked
/// worktree** checked out to a branch that carries none.
///
/// The worktree's emptiness is the normal case rather than a contrivance: a
/// worktree sits at a different ref, and a ref that predates the authority — or
/// a sparse checkout that excludes it — has no `batten.toml` to find.
fn repo_with_bare_worktree(name: &str) -> (PathBuf, PathBuf) {
    let main = Fixture::new(name).file("README.md", "base\n").git().build();
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "base"]);
    // The branch the worktree will sit on, created BEFORE the authority lands,
    // so its tree genuinely lacks the file rather than having it deleted.
    git_in(&main, &["branch", "no-authority"]);
    common::write(&main, "batten.toml", ONE_DENY);
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "authority"]);

    // `scratch` wipes and creates; `git worktree add` wants to create the
    // directory itself, so it is removed again straight away. Going through the
    // one helper is what keeps the path under `target/tmp` with every other
    // fixture rather than inventing a second convention.
    let linked = common::scratch(&format!("{name}-linked"));
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            linked.to_str().unwrap_or_default(),
            "no-authority",
        ],
    );
    (main, linked)
}

#[test]
fn a_linked_worktree_adjudicates_against_the_repositorys_authority() {
    // THE REGRESSION. Red on `main`: the launcher `cd`'d to the worktree, found
    // no `batten.toml`, resolved `Policy::declaring_nothing`, and allowed.
    let (main, linked) = repo_with_bare_worktree("hook-root-linked");
    assert!(
        !linked.join("batten.toml").exists(),
        "the fixture is only a fixture if the worktree carries no authority"
    );
    assert!(
        main.join("batten.toml").exists(),
        "the repository must carry the authority the worktree is missing"
    );
    let output = hook_from(&linked);
    assert!(
        denied(&output),
        "a mediated call from a linked worktree must be judged by the \
         REPOSITORY's authority, not by the worktree's absence of one: {:?} {:?}",
        output.status.code(),
        common::stderr(&output)
    );
}

#[test]
fn the_two_git_questions_really_do_disagree_here() {
    // The premise of the case above, asserted rather than assumed (CLOUD-249):
    // if the fixture's worktree resolved the same directory under both questions
    // there would be nothing for the deny to prove, and the test would pass over
    // a condition it never created.
    let (main, linked) = repo_with_bare_worktree("hook-root-premise");
    let toplevel = git_in(&linked, &["rev-parse", "--show-toplevel"]);
    let common_root = batten::git::repo_root(&linked).expect("the worktree is inside a repository");
    assert_ne!(
        Path::new(toplevel.trim()).canonicalize().ok(),
        common_root.canonicalize().ok(),
        "the launcher's question and `repo_root`'s must differ here, or the \
         regression above is vacuous"
    );
    assert_eq!(
        common_root.canonicalize().ok(),
        main.canonicalize().ok(),
        "`repo_root` from a linked worktree is the main repository root"
    );
}

#[test]
fn the_main_root_is_unchanged() {
    // The mirror the row asks for: this must not become a change only worktrees
    // exercise.
    let (main, _linked) = repo_with_bare_worktree("hook-root-main");
    assert!(denied(&hook_from(&main)), "the main root still adjudicates");
}

#[test]
fn a_subdirectory_of_the_main_root_adjudicates_too() {
    // The case the launcher's `cd` was actually written for — "a hook fired
    // while the session's cwd is `crates/batten`" — and the reason deleting the
    // launcher is not a regression: the defence moved into the binary rather
    // than away.
    let (main, _linked) = repo_with_bare_worktree("hook-root-subdir");
    let nested = main.join("crates").join("batten");
    std::fs::create_dir_all(&nested).expect("create a nested directory");
    assert!(
        denied(&hook_from(&nested)),
        "a hook fired from a subdirectory must still find the repository's \
         authority — this is what the launcher's `cd` bought and what \
         `git::repo_root` buys now"
    );
}

#[test]
fn outside_a_repository_the_call_is_allowed_rather_than_refused() {
    // The fail-open half, unchanged and load-bearing. `batten hook` is
    // registered once and then mediates every call in whatever directory the
    // agent is in, most of them outside any repository. Refusing there would
    // make Batten the reason ordinary work stops (CLOUD-70) — the same posture
    // the launcher had at this point (`|| exit 0`).
    let dir = common::scratch_outside_tree("hook-root", "no-repository");
    let output = hook_from(&dir);
    assert!(
        !denied(&output),
        "a directory with no repository and no authority allows: {:?}",
        common::stderr(&output)
    );
}
