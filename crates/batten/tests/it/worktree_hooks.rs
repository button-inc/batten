//! Claude Code's `WorktreeCreate` and `WorktreeRemove`, answered natively
//! (CLOUD-2581).
//!
//! Both reached Batten as `Unrecognized` and answered an empty allow, and the
//! host reads `WorktreeCreate`'s stdout as the new worktree's path, so an empty
//! answer failed every `EnterWorktree` in a repository that registered Batten
//! there. The fixture-side `git` below only OBSERVES what Batten wrote: Batten
//! itself spawns no git.

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run_with_stdin};

/// A committed repository whose trunk is `main`, recorded at `origin/main`.
fn trunked(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\nmust_land_on = \"main\"\n")
        .file("notes.md", "ordinary\n")
        .git()
        .base_commit()
        .build();
    common::pin_origin_main(&dir);
    canonical(&dir)
}

fn canonical(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).expect("the fixture resolves")
}

fn hook(dir: &Path, payload: &serde_json::Value) -> std::process::Output {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload.to_string(),
    )
}

fn create(dir: &Path, name: &str) -> std::process::Output {
    hook(
        dir,
        &serde_json::json!({ "hook_event_name": "WorktreeCreate", "name": name, "cwd": dir }),
    )
}

fn remove(dir: &Path, worktree: &Path) -> std::process::Output {
    hook(
        dir,
        &serde_json::json!({ "hook_event_name": "WorktreeRemove", "worktree_path": worktree, "cwd": dir }),
    )
}

/// Whether `reference` resolves in `dir`, asked of fixture-side git.
fn resolves(dir: &Path, reference: &str) -> bool {
    common::git_command(dir, &["rev-parse", "--verify", "--quiet", reference])
        .output()
        .expect("run git")
        .status
        .success()
}

#[test]
fn a_created_worktree_answers_with_its_path_alone() {
    let dir = trunked("worktree-create-path");
    let output = create(&dir, "feat/x");
    let expected = dir.join(".claude/worktrees/feat/x");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\n", expected.display()),
        "stdout is the path and nothing else"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "",
        "no advice was owed, so no verdict line is written"
    );
    let listed = git_in(&dir, &["worktree", "list", "--porcelain"]);
    assert!(
        listed.contains(&format!("worktree {}", expected.display())),
        "git sees the worktree: {listed}"
    );
    assert!(
        listed.contains("branch refs/heads/worktree-feat+x"),
        "on its own branch: {listed}"
    );
    assert_eq!(
        git_in(&expected, &["status", "--porcelain"]).trim(),
        "",
        "the index carries real stat data, so nothing reads as modified"
    );
}

#[test]
fn a_removed_worktree_keeps_a_branch_trunk_does_not_carry() {
    let dir = trunked("worktree-remove-trunk");
    assert_eq!(create(&dir, "a").status.code(), Some(0));
    assert_eq!(create(&dir, "b").status.code(), Some(0));
    let a = dir.join(".claude/worktrees/a");
    let b = dir.join(".claude/worktrees/b");
    git_in(&a, &["commit", "-q", "--allow-empty", "-m", "unlanded"]);

    for worktree in [&a, &b] {
        let output = remove(&dir, worktree);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "remove answers nothing on stdout");
        assert!(!worktree.exists(), "{} is removed", worktree.display());
    }
    assert!(!dir.join(".git/worktrees/a").exists());
    assert!(!dir.join(".git/worktrees/b").exists());
    assert!(
        resolves(&dir, "refs/heads/worktree-a"),
        "a branch the trunk does not carry survives"
    );
    assert!(
        !resolves(&dir, "refs/heads/worktree-b"),
        "a branch the trunk carries goes with its worktree"
    );
}

#[test]
fn a_removed_worktree_keeps_its_branch_when_no_trunk_resolves() {
    // By hand rather than `base_commit`, which declares `origin/main`: no
    // `must_land_on`, no remote, so nothing resolves a trunk.
    let dir = common::scratch("worktree-remove-no-trunk").join("repo");
    std::fs::create_dir_all(&dir).expect("create the fixture");
    common::write(&dir, "batten.toml", "version = 1\n");
    common::write(&dir, "notes.md", "ordinary\n");
    common::init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    let dir = canonical(&dir);
    assert_eq!(create(&dir, "c").status.code(), Some(0));
    let c = dir.join(".claude/worktrees/c");
    assert_eq!(remove(&dir, &c).status.code(), Some(0));
    assert!(!c.exists());
    assert!(
        resolves(&dir, "refs/heads/worktree-c"),
        "with no trunk to judge against, the delete fails closed"
    );
}

#[test]
fn a_handler_deny_creates_no_worktree() {
    let dir = canonical(
        &Fixture::new("worktree-create-denied")
            .config(
                "version = 1\n\n\
                 [[hook.handler]]\n\
                 id = \"no-worktrees\"\n\
                 on = \"worktree-create\"\n\
                 run = [\"sh\", \"-c\", \"echo refused by fixture >&2; exit 2\"]\n\
                 timeout_ms = 5000\n\
                 owner = \"CLOUD-2581\"\n\
                 expires = \"2027-03-31\"\n",
            )
            .file("notes.md", "ordinary\n")
            .git()
            .base_commit()
            .build(),
    );
    let output = create(&dir, "d");
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(output.stdout.is_empty(), "a refusal answers no path");
    assert!(
        err.contains("hook.handler.no-worktrees"),
        "the refusal names its handler: {err}"
    );
    assert!(!dir.join(".claude/worktrees/d").exists());
    assert!(!resolves(&dir, "refs/heads/worktree-d"));
}
