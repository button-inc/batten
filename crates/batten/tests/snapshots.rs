//! The machine contract, frozen as bytes (CLOUD-106).
//!
//! Rule 4 (output is a pointer, never the payload) and rule 5 (one exit-code
//! contract) are asserted elsewhere as *shape* checks — this output contains no
//! timestamp, that allowlist is sorted, this code is not the deny code. A
//! snapshot asserts something a shape check cannot: **the exact bytes**. Any
//! change to what a consumer parses then lands as a reviewed diff rather than as
//! a test that still passes because the new shape also satisfies the old
//! predicate.
//!
//! # What is derived, and what is authoritative
//!
//! The compiled binary's actual output is the authority (§1). Everything under
//! `tests/snapshots/` is DERIVED from it, regenerated only by
//! `mise run snapshots` (`cargo insta accept`), and **never hand-edited** — the
//! same standing as `completions/`, `man/` and `schema/`, which `mise run fix`
//! regenerates in the same step.
//!
//! # Redaction policy, which is narrower than insta's default habit
//!
//! Redaction is for genuinely host-dependent bytes — an absolute path, a
//! scratch-directory name — and for nothing else. In particular **a timestamp or
//! a duration is never redacted**, because §6 forbids those bytes existing in
//! this output at all: a redaction that hid one would convert a contract
//! violation into a passing snapshot, which is the failure this file exists to
//! catch. Nothing here currently needs a redaction, and that is the point.
//!
//! # The two golden manifests
//!
//! `golden_exit_code_table` and `golden_json_schema` freeze the two surfaces a
//! consumer branches on. They are regenerate-and-diff-to-zero: the test renders
//! the manifest from the binary and compares it to the committed copy, so a
//! stale copy fails and a deliberate change is a diff someone approved.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Output;

mod common;

use common::{Fixture, batten, scratch};

/// stdout as text, for a snapshot that freezes what a consumer parses.
fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A fixture whose one rule fires twice, in a fixed order.
///
/// Two files rather than one, because ordering is half of byte-stability and a
/// single finding cannot show it (§6).
fn two_findings(name: &str) -> std::path::PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
        )
        .files(&[("b.rs", "TODO\n"), ("a.rs", "TODO\n")])
        .build()
}

/// The pointer lines a consumer reads, frozen exactly.
///
/// The shape assertions beside this in `cli.rs` say the output names a path, a
/// line and a rule id and leaks no source text. This says which bytes, in which
/// order — so a reordering, an added column or a changed separator is a diff
/// rather than a still-passing shape check.
#[test]
fn pointer_output_is_frozen() {
    let dir = two_findings("snap-pointers");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2), "the fixture must find both");
    insta::assert_snapshot!(stdout_of(&output));
}

/// The `-J` view a machine consumer parses, frozen exactly.
#[test]
fn json_output_is_frozen() {
    let dir = two_findings("snap-json");
    let output = batten()
        .args(["check", "--json"])
        .current_dir(&dir)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2), "the fixture must find both");
    insta::assert_snapshot!(stdout_of(&output));
}

/// A clean run says nothing on stdout, and that is a contract rather than an
/// accident: a consumer that greps output for findings must not have to filter a
/// success banner out of it.
#[test]
fn a_clean_run_is_frozen_as_silent() {
    let dir = scratch("snap-clean");
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::write(dir.join("batten.toml"), "version = 1\n").expect("write config");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "nothing to report");
    insta::assert_snapshot!(stdout_of(&output), @"");
}

/// GOLDEN MANIFEST (a): the §7 exit-code table.
///
/// Rendered from `ExitCode::ALL` by the binary itself, so the committed copy and
/// the codes the process returns cannot disagree. `exit.rs`'s unit tests pin that
/// every variant appears; this pins **what it says**, which is the half a
/// consumer reads when deciding how to branch.
///
/// A renumbering (CLOUD-226 did one) or a reworded meaning is a machine-surface
/// change, and this is what makes it arrive as a reviewed diff.
#[test]
fn golden_exit_code_table() {
    // Rendered by the same function the binary documents the contract with, so
    // the committed manifest cannot describe one table while the process returns
    // another. Asked of the library rather than of a verb because there is no
    // `doctor exit-codes` verb and inventing one to make a test convenient would
    // be command surface nobody asked for.
    insta::assert_snapshot!(batten::exit::table());
}

/// GOLDEN MANIFEST (b): the command spec a consumer generates against.
///
/// `batten spec` is the emitted surface every derived artifact is built from —
/// the completions, the man pages and the published reference. Freezing it means
/// a flag added, renamed or re-defaulted shows up here even when the three
/// derived artifacts happen to render identically.
#[test]
fn golden_json_schema() {
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0), "the spec is an answer");
    insta::assert_snapshot!(stdout_of(&output));
}

/// A pending snapshot in the tree is a failure, not a diff to look at later.
///
/// `cargo insta` writes `.snap.new` beside a snapshot it could not confirm, and
/// a run that left one behind has an unreviewed machine-surface change sitting
/// in the working tree. CI would otherwise pass on the old bytes while the new
/// ones sit unexamined, which is the drift the whole file exists to prevent.
#[test]
fn no_pending_snapshot_is_left_in_the_tree() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    let pending: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".snap.new"))
        .collect();
    assert!(
        pending.is_empty(),
        "pending snapshot(s) left unreviewed: {pending:?} — run `mise run snapshots` and commit the diff"
    );
}
