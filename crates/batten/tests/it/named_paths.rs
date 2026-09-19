//! `ready::named_paths` over the compiled binary — CLOUD-514/CLOUD-774, ported
//! off `mise-tasks/board-diff-overlap.sh --named` under CLOUD-1716.
//!
//! # Why a compiled tier and not only the unit cases
//!
//! The cases beside the function pin the RESOLUTION. They cannot show that the
//! recorder reaches the authority at all — that `authority = { ask =
//! "named-paths" }` resolves, that the column's `stdin` expression arrives as
//! something the body reader understands, or that a tree whose index will not
//! open records could-not-look rather than an empty answer. Those are properties
//! of the wiring, and the wiring is exactly what changed.
//!
//! # POINTER-ONLY IS STRUCTURAL, and one case exists to say so
//!
//! Only TRACKED paths can reach the output, so a body's prose, a customer name
//! or a pasted credential cannot. That is a property of the resolution rather
//! than of a scrubbing step, and `prose_in_the_body_cannot_reach_the_output`
//! asserts it over a body carrying all three.
//
// carried: mise-tasks/board-diff-overlap.sh crates/batten/src/ready.rs kind:authority crates/batten/tests/it/named_paths.rs
// carried: tests/board-diff-overlap.bats crates/batten/src/ready.rs kind:authority crates/batten/tests/it/named_paths.rs
//
// carried: "an AMBIGUOUS basename resolves to NOTHING rather than to a guess" crates/batten/src/ready.rs
// carried: "a short form resolves to the tracked path" crates/batten/src/ready.rs
// carried: "only paths TRACKED IN THIS REPOSITORY can reach the output" crates/batten/src/ready.rs
// carried: "a task is INVOKED as `mise run land` and written up as `land`, while the file is `land.sh`" crates/batten/src/ready.rs
// changed: "the default mode intersects with the diff" crates/batten/src/ready.rs the intersect mode is DROPPED rather than ported, because `[program.named-paths]` passed `--named` and nothing else ever called the program — an intersection is a fact about the diff at write time, and the recorder wants what the row is about, which does not decay
// changed: "exit 0 always — this is a sensor" crates/batten/src/ready.rs the exit code is gone with the process: an authority answers `(status, stdout)` to the recorder, and could-not-look is `None` rather than a printed `-`

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use crate::common::{Fixture, git_in};

/// A repository whose tracked set carries an unambiguous name, an ambiguous one,
/// and a task whose file has an extension its prose will not.
fn repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\n")
        .file("crates/batten/src/git.rs", "// git\n")
        .file("mise-tasks/land.sh", "#!/usr/bin/env bash\nexit 0\n")
        .file("crates/batten/src/dup.rs", "// one\n")
        .file("crates/other/src/dup.rs", "// two\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

/// What the authority answers for a body, as `(status, stdout)`.
fn named(dir: &PathBuf, body: &str) -> (i32, String) {
    let payload = serde_json::Value::String(body.to_owned());
    batten::ready::named_paths(&payload, dir).expect("the authority could look")
}

/// CARRIES: "bodies here write `git.rs:107`, not `crates/batten/src/git.rs`.
/// Exact path matching finds ZERO and basename resolution finds all three."
#[test]
fn a_short_form_resolves_to_the_tracked_path() {
    let dir = repo("named-short-form");
    let (status, said) = named(&dir, "the bug is in `git.rs` around line 107");
    assert_eq!(status, 0);
    assert!(
        said.contains("crates/batten/src/git.rs"),
        "the basename resolved to its tracked path: {said}"
    );
    assert!(said.starts_with('1'), "one path named: {said}");
}

/// CARRIES: "an AMBIGUOUS basename resolves to NOTHING rather than to a guess,
/// which is the 'could not look' reading this repo draws everywhere."
#[test]
fn an_ambiguous_basename_resolves_to_nothing() {
    let dir = repo("named-ambiguous");
    let (status, said) = named(&dir, "see `dup.rs` for the detail");
    assert_eq!(status, 0);
    assert_eq!(
        said.trim(),
        "0",
        "two tracked paths share the basename, so neither is guessed: {said}"
    );
}

/// CARRIES: "a task is INVOKED as `mise run land` and written up as `land`,
/// while the file it resolves to is `land.sh`. Prose does not carry the
/// extension and should not have to."
#[test]
fn a_bare_task_name_resolves_through_its_extension() {
    let dir = repo("named-task");
    let (_, said) = named(&dir, "the lap-cap message in `land` is wrong");
    assert!(
        said.contains("mise-tasks/land.sh"),
        "the bare task name resolved to the file: {said}"
    );
}

/// An exact tracked path wins without going near the basename map.
#[test]
fn an_exact_tracked_path_resolves_as_itself() {
    let dir = repo("named-exact");
    let (_, said) = named(&dir, "see crates/batten/src/git.rs for the detail");
    assert!(said.contains("crates/batten/src/git.rs"), "{said}");
}

/// POINTER-ONLY IS STRUCTURAL: only tracked paths can reach the output, so a
/// body's prose, a customer name and a pasted credential all cannot.
#[test]
fn prose_in_the_body_cannot_reach_the_output() {
    let dir = repo("named-prose");
    let (_, said) = named(
        &dir,
        "Acme Corporation reported this. token=ghp_notarealsecretvalue. \
         The fix is in `git.rs`.",
    );
    assert!(said.contains("crates/batten/src/git.rs"), "{said}");
    for leaked in ["Acme", "ghp_", "token="] {
        assert!(
            !said.contains(leaked),
            "only tracked paths reach the output, never {leaked}: {said}"
        );
    }
}

/// A body naming nothing tracked is the honest zero, not could-not-look.
#[test]
fn a_body_naming_nothing_tracked_is_zero_rather_than_absent() {
    let dir = repo("named-zero");
    let (status, said) = named(&dir, "this row is about a decision, not a file");
    assert_eq!(status, 0);
    assert_eq!(said.trim(), "0");
}

/// Two runs over one body agree byte for byte — the output is sorted, so a
/// column's value cannot move between records for no reason a reader can see.
#[test]
fn the_answer_is_byte_stable() {
    let dir = repo("named-stable");
    let body = "`git.rs` and `land` and crates/other/src/dup.rs";
    assert_eq!(named(&dir, body), named(&dir, body));
}

/// The retired program is gone, and no `[program]` row still resolves it.
#[test]
fn the_retired_program_is_not_tracked_and_no_row_names_it() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repository root");
    for path in [
        "mise-tasks/board-diff-overlap.sh",
        "tests/board-diff-overlap.bats",
    ] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let config = std::fs::read_to_string(root.join("batten.toml")).expect("batten.toml");
    assert!(
        !config.contains(r#"path = "mise-tasks/board-diff-overlap.sh""#),
        "no `[program]` row RESOLVES the retired file — a prose mention in the \
         note that records the retirement is not a call site"
    );
    assert!(
        config.contains(r#"authority = { ask = "named-paths""#),
        "the columns ask the compiled authority instead"
    );
}
