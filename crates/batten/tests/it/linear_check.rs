//! `[tasks."linear-check"]` — is HEAD linear on the current `origin/main`?
//! Over `batten land linear` since CLOUD-1991, and over the task's own
//! declaration for the receipt it records.
//!
//! The body the task carried in shell (CLOUD-1717) fetched with an explicit
//! refspec, deepened a shallow clone, and compared the merge base in `bash`; a
//! stub `git` was how this tier reached its fail-closed arm. The question is the
//! engine's now, through the same in-process fetch a landing lap makes, so the
//! arms are driven over the compiled binary: a clone with no landing remote, a
//! remote the fetch cannot reach, and a shallow clone. The two arms that need a
//! smart-HTTP remote to answer — linear and behind — are the lap's own fetch and
//! `gitwrite::carries`, each pinned where it lives, and the integrator's replay
//! of the retired body against the verb over this repository's own remote.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/linear-check.sh subject:mise.toml crates/batten/tests/it/linear_check.rs
// ported: tests/linear-check.bats subject:mise.toml crates/batten/tests/it/linear_check.rs
// changed: "a failed fetch exits 1 instead of trusting the stale ref" crates/batten/src/lib.rs kind:verb the fetch that cannot complete is could-not-look on the engine's table (`3`), never a pass; `verify` branches on `2` alone, so a non-`2` failure still stops it rather than lapping
// carried: "a failed fetch writes no receipt" mise.toml kind:mechanism
// carried: "a successful fetch on a linear HEAD passes and records the receipt" mise.toml kind:mechanism
// carried: "a HEAD behind main is exit 2 — the input moved, not a broken branch" crates/batten/src/lib.rs kind:verb
// carried: "a failed receipt write fails the gate — set -e is what carries it" mise.toml kind:mechanism
// carried: "the naive fetch exits 0 while resolving nothing in a single-branch clone" crates/batten/tests/it/linear_check.rs
// changed: "the gate resolves main in a single-branch clone" crates/batten/src/land.rs the verb fetches the named reference into its tracking ref directly, so a single-branch clone's configured refspec is never consulted; the naive-fetch case above keeps the trap it avoids documented
// changed: "the gate resolves main in a shallow single-branch clone" crates/batten/src/lib.rs a shallow clone is REFUSED as could-not-look naming `git fetch --unshallow`, where the body deepened it in place: the in-process fetch cannot deepen, and ancestry over truncated history answers wrong in one direction

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

fn linear(dir: &Path) -> Output {
    common::batten()
        .args(["land", "linear", "main"])
        .current_dir(dir)
        .output()
        .expect("run batten land linear")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// An origin with `main` and a `feature` one commit ahead of it.
fn origin(dir: &Path) -> PathBuf {
    let origin = dir.join("origin");
    let seed = dir.join("seed");
    let git = |at: &Path, args: &[&str]| {
        common::git_in(at, args);
    };
    std::fs::create_dir_all(&origin).expect("origin dir");
    std::fs::create_dir_all(&seed).expect("seed dir");
    // Both from the shared template rather than a spawned `git init`. The
    // origin takes pushes to its unborn default branch as a bare one would.
    common::init_repo(&origin);
    git(&origin, &["config", "receive.denyCurrentBranch", "ignore"]);
    common::init_repo(&seed);
    git(&seed, &["config", "user.email", "t@example.com"]);
    git(&seed, &["config", "user.name", "t"]);
    git(&seed, &["config", "commit.gpgsign", "false"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "one"]);
    git(&seed, &["branch", "-M", "main"]);
    let url = format!("file://{}", origin.display());
    git(&seed, &["push", "-q", &url, "main"]);
    git(&seed, &["checkout", "-q", "-b", "feature"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "work"]);
    git(&seed, &["push", "-q", &url, "feature"]);
    origin
}

fn clone(dir: &Path, origin: &Path, name: &str, shallow: bool) -> PathBuf {
    let into = dir.join(name);
    let url = format!("file://{}", origin.display());
    let mut args = vec!["clone", "-q", "--branch", "feature", "--single-branch"];
    if shallow {
        args.extend(["--depth", "1"]);
    }
    let into_str = into.display().to_string();
    args.extend([url.as_str(), into_str.as_str()]);
    common::git_in(dir, &args);
    into
}

/// The trap the retired body's explicit refspec existed for, stated as a
/// property of git — and the reason the verb fetches the reference by name.
#[test]
fn the_naive_fetch_exits_0_while_resolving_nothing_in_a_single_branch_clone() {
    let dir = common::scratch("linear-check-naive");
    let origin = origin(&dir);
    let clone = clone(&dir, &origin, "naive", false);
    common::git_in(&clone, &["fetch", "-q", "origin", "main"]);
    let resolved = common::git_command(&clone, &["rev-parse", "origin/main"])
        .output()
        .expect("git rev-parse");
    assert!(
        !resolved.status.success(),
        "the naive fetch wrote origin/main"
    );
}

/// `#MUTANT linear-shallow-trusted` reddens here: a shallow clone's truncated
/// history is refused as could-not-look, never read as an ancestry answer.
#[test]
fn a_shallow_clone_is_could_not_look_and_names_the_remedy() {
    let dir = common::scratch("linear-check-shallow");
    let origin = origin(&dir);
    let clone = clone(&dir, &origin, "shallow", true);
    let out = linear(&clone);
    assert_eq!(
        out.status.code(),
        Some(batten::exit::ExitCode::Internal.code()),
        "{}",
        said(&out)
    );
    assert!(said(&out).contains("--unshallow"), "{}", said(&out));
}

/// `#MUTANT linear-fetch-failure-trusted` reddens here. The remote is an address
/// nothing listens on, so the fetch cannot complete without touching a network,
/// and the verb must not fall back to whatever tracking ref the clone holds —
/// the stale-main false green the retired body's `set -e` history records.
#[test]
fn a_fetch_that_cannot_complete_is_could_not_look_and_never_a_pass() {
    let dir = common::scratch("linear-check-unreachable");
    let origin = origin(&dir);
    let clone = clone(&dir, &origin, "unreachable", false);
    common::git_in(
        &clone,
        &[
            "remote",
            "set-url",
            "origin",
            "http://127.0.0.1:9/nothing.git",
        ],
    );
    let out = linear(&clone);
    assert_eq!(
        out.status.code(),
        Some(batten::exit::ExitCode::Internal.code()),
        "{}",
        said(&out)
    );
    assert!(
        said(&out).contains("could not fetch main"),
        "{}",
        said(&out)
    );
}

#[test]
fn a_clone_with_no_landing_remote_is_could_not_look() {
    let dir = common::scratch("linear-check-no-remote");
    common::init_repo(&dir);
    common::git_in(&dir, &["config", "user.email", "t@example.com"]);
    common::git_in(&dir, &["config", "user.name", "t"]);
    common::git_in(&dir, &["config", "commit.gpgsign", "false"]);
    common::git_in(&dir, &["commit", "-q", "--allow-empty", "-m", "one"]);
    let out = linear(&dir);
    assert_eq!(
        out.status.code(),
        Some(batten::exit::ExitCode::Internal.code()),
        "{}",
        said(&out)
    );
}

/// The receipt half, which stays the task's: minted only after the verb answered
/// `0`, and a receipt that will not write fails the task. Both are what an argv
/// sequence does — it stops at the first failing entry, with that entry's code —
/// so the property is the ORDER of the two entries.
#[test]
fn the_receipt_is_recorded_only_after_the_verb_answers() {
    let block = common::task_block("linear-check").expect("linear-check is a declared task");
    let run = common::task_value(&block, "run");
    let asked = run.find("land linear").expect("the task asks the verb");
    let recorded = run
        .find("receipt record linear-check")
        .expect("the task records the receipt");
    assert!(
        asked < recorded,
        "the receipt follows the verdict it attests: {run}"
    );
}
