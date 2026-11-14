//! Where `verify` belongs (CLOUD-2707), over the compiled binary.
//!
//! Measured on PR #1276: rows pushed with no full gate run, then a standalone
//! `mise run verify` before every `mise run land`. The second costs a second
//! gate only when the trunk moved — the lap answers a proved head from its
//! receipt (CLOUD-1891) — so `land placed` advises `land` as the next step and
//! never refuses; the `branch run missing` row is the push-time advice against
//! the first.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::common;

/// A repository whose `main` is committed and on `origin/main`.
fn pushed(name: &str) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);
    fs::write(root.join("a.txt"), "a\n").expect("seed a file");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    common::pin_origin_main(&root);
    root
}

fn placed(root: &Path, lap: bool) -> std::process::Output {
    let mut command = common::batten();
    command.args(["land", "placed"]).current_dir(root);
    if lap {
        command.env("BATTEN_LAND_GATE", "1");
    }
    command.output().expect("run batten land placed")
}

/// Advice on stderr, and never a refusal: verifying without landing is
/// legitimate, so every case exits 0 and only the stderr line differs.
fn advised(out: &std::process::Output) -> bool {
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(out));
    assert!(out.stdout.is_empty(), "advice is not data");
    common::stderr(out).contains("mise run land")
}

/// A committed, pushed head outside the lap runs, and is told `land` is next.
/// Fails by: the guard refusing the run, or saying nothing.
#[test]
fn a_clean_pushed_head_outside_the_lap_is_advised_toward_land() {
    let root = pushed("placement-before-land");
    assert!(advised(&placed(&root, false)));
}

/// The lap's own gate hears nothing. Fails by: the lap told to run the lap.
#[test]
fn the_laps_own_gate_is_not_advised() {
    let root = pushed("placement-lap");
    assert!(!advised(&placed(&root, true)));
}

/// A dirty tree or an unpushed commit is a draft being iterated, and hears
/// nothing. Fails by: either condition dropped from the predicate.
#[test]
fn an_iterated_draft_is_not_advised() {
    let dirty = pushed("placement-dirty");
    fs::write(dirty.join("a.txt"), "b\n").expect("dirty the tree");
    assert!(!advised(&placed(&dirty, false)), "dirty");

    let ahead = pushed("placement-ahead");
    fs::write(ahead.join("b.txt"), "b\n").expect("a second file");
    common::git_in(&ahead, &["add", "-A"]);
    common::git_in(&ahead, &["commit", "--quiet", "-m", "ahead"]);
    assert!(!advised(&placed(&ahead, false)), "unpushed");
}
