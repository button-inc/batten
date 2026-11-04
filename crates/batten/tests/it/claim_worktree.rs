//! `claim check` run inside a linked worktree reads the trunk from the
//! WORKTREE's `batten.toml` (CLOUD-2532).
//!
//! Measured 2026-10-25: from a linked worktree, `claim check` refused with the
//! MAIN checkout's load error (`prose declare refused at rule[1].reason …`), and
//! `--config-in <worktree>` changed nothing. `claim_base` read `must_land_on`
//! through `worktree::declared_trunk(board_root())`, and `board_root` is
//! `git::repo_root` — the main checkout — with no overrides to consult.
//!
//! Where the receipt LANDS (the main checkout's `.git`, keyed by its branch) is
//! CLOUD-2112 / CLOUD-2464, and this suite does not assert it; it puts the
//! session stamp and read receipt where today's code reads them, so the one
//! variable is which `batten.toml` judges the claim.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common::{
    Fixture, declared_board, declared_patterns, git_in, run_with_stdin, stderr, stdout,
};

/// A main checkout whose `batten.toml` will not load, and a linked worktree on
/// `feature/claim` whose own `batten.toml` does and declares the trunk.
fn main_and_worktree(name: &str) -> (PathBuf, PathBuf) {
    let main = Fixture::new(name)
        .file("README.md", "base\n")
        // `claim check` reads the workspace version §6's arrows key on.
        .file("Cargo.toml", "[workspace.package]\nversion = \"0.0.125\"\n")
        .git()
        .build();
    git_in(&main, &["add", "-A"]);
    git_in(&main, &["commit", "-q", "-m", "base"]);
    git_in(&main, &["branch", "-q", "-m", "main", "trunk"]);
    git_in(
        &main,
        &["remote", "add", "origin", "http://127.0.0.1:9/nothing.git"],
    );
    git_in(&main, &["update-ref", "refs/remotes/origin/trunk", "HEAD"]);

    let linked = crate::common::scratch(&format!("{name}-linked"));
    let _ = std::fs::remove_dir_all(&linked);
    git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "feature/claim",
            linked.to_str().unwrap_or_default(),
        ],
    );
    crate::common::write(
        &linked,
        "batten.toml",
        &format!(
            "version = 1\nmust_land_on = \"trunk\"\n\n{}\n{}",
            declared_board(),
            declared_patterns()
        ),
    );
    git_in(&linked, &["add", "-A"]);
    git_in(
        &linked,
        &["commit", "-q", "-m", "the branch's own authority"],
    );

    // The main checkout's authority will not load at all — the shape of the
    // incident, where a newer engine refused the trunk's file outright.
    crate::common::write(&main, "batten.toml", "version = 1\nnot_a_key = true\n");
    (main, linked)
}

/// A body that passes the readiness rule, so nothing but the trunk decides.
fn refined_body() -> String {
    "**Refinement — Ready (a summary)**\n\n\
     * **Source of truth (§1).** One authoritative artifact.\n\
     * **Commit / bump (§6).** `ci` → **no bump**.\n"
        .to_owned()
}

/// `claim check` from `dir` with a pullable `Todo` row, its session stamp and
/// read receipt minted into `store`, the way `trunk_name.rs` mints them.
fn claim_check(dir: &Path, store: &Path) -> Output {
    std::fs::create_dir_all(store).expect("the receipt store");
    std::fs::write(store.join("session-start"), "").expect("the session stamp");
    let scratch = store.join("hash-input");
    std::fs::write(&scratch, refined_body()).expect("the hash input");
    let digest = git_in(dir, &["hash-object", scratch.to_str().expect("utf-8")]);
    std::fs::remove_file(&scratch).expect("clean up the hash input");
    std::fs::write(
        store.join("issue-read.CLOUD-1"),
        format!("issue-read CLOUD-1 - {}\n", digest.trim()),
    )
    .expect("the read receipt");
    let payload = serde_json::json!({
        "id": "CLOUD-1",
        "status": "Todo",
        "description": refined_body(),
        "updatedAt": "2026-08-01T00:00:00Z",
    });
    run_with_stdin(dir, &["claim", "check"], &payload.to_string())
}

#[test]
fn claim_check_in_a_worktree_reads_the_worktrees_trunk() {
    let (main, linked) = main_and_worktree("claim-worktree");
    let output = claim_check(&linked, &main.join(".git").join("batten-receipts"));
    let said = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !said.contains("not_a_key"),
        "a claim made in a worktree must be judged by the worktree's batten.toml, \
         never refused by the main checkout's load error: {said}"
    );
    assert!(
        output.status.success(),
        "the worktree's authority loads and declares the trunk, so the claim mints: \
         {:?} {said}",
        output.status.code()
    );
}
