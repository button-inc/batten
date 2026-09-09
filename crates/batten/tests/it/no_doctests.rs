//! No runnable doctest exists, over the compiled binary (CLOUD-813, ported from
//! `mise-tasks/no-doctests.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/no-doctests.rego` carries load-time
//! cases pinning the parity rule and the attribute list, and every one supplies
//! `input.tree.lines` with `with input as`. That fabricates the scan's SUBJECT —
//! which is precisely what the shell spent an explicit anti-vacuity arm on, and
//! what CLOUD-418 names: a scan that matched no file at all reports "no runnable
//! doctest" over nothing, and reads as coverage. Only a real repository can show
//! the engine actually handing this module a workspace.
//!
//! The self-consumption case is the one that made the runner swap safe in the
//! first place: the class is empty on this workspace, and it is asserted here
//! rather than assumed.
//
// carried: mise-tasks/no-doctests.sh policy/no-doctests.rego crates/batten/tests/it/no_doctests.rs
// carried: tests/no-doctests.bats policy/no-doctests.rego crates/batten/tests/it/no_doctests.rs
//
// carried: "the committed workspace carries no runnable doctest" policy/no-doctests.rego
// carried: "an unattributed fence in a doc comment is refused" policy/no-doctests.rego
// carried: "the refusal is a pointer, never the example" policy/no-doctests.rego
// carried: "a text fence is not a doctest" policy/no-doctests.rego
// carried: "ignore, compile_fail and no_run are all non-running" policy/no-doctests.rego
// carried: "a closing fence is not read as an unattributed opening one" policy/no-doctests.rego
// carried: "a fence outside a doc comment is not a doctest" policy/no-doctests.rego
//
// THE TWO COULD-NOT-LOOK CASES, which the successor answers structurally rather
// than by an arm of its own.
//
// changed: "a root with no tracked .rs file is could-not-look, not clean" policy/no-doctests.rego the shell took its scan root as an ARGUMENT and so could be pointed at an empty one, which is why it needed the arm. The successor's subject is a declared `line_sources` glob rather than argv: a glob matching nothing means the rule is not evaluated, and the declaration itself is gated by `batten-glob-check`. There is no caller left that can aim it at an empty root, so the case has no subject rather than no coverage
// changed: "a missing root is could-not-look, not clean" policy/no-doctests.rego same reason, one step further: a root that does not exist is not expressible when the root is a committed glob rather than a positional argument

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stdout};

/// A workspace declaring only this rule, so any finding is the one under test.
fn doctest_repo(name: &str, source: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"test place wrong\"\n\
             gloss = \"a test exists that nothing runs\"\n\
             class = \"An example nothing executes is dead code a reader trusts for being executable.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"no-doctests\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"crates/**/*.rs\"]\n\
             module = \"policy/no-doctests.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("crates/demo/src/lib.rs", source)
        .git()
        .build();
    common::write(
        &dir,
        "policy/no-doctests.rego",
        &std::fs::read_to_string(common::at_root("policy/no-doctests.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "no-doctests"])
}

#[test]
fn an_unattributed_fence_is_refused_over_the_binary() {
    let dir = doctest_repo(
        "doctests-unattributed",
        "/// ```\n/// let x = 1;\n/// ```\npub fn f() {}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("crates/demo/src/lib.rs"),
        "the finding points at the fence's file: {}",
        stdout(&output)
    );
}

#[test]
fn a_text_fence_is_not_a_doctest_over_the_binary() {
    let dir = doctest_repo(
        "doctests-text-fence",
        "/// ```text\n/// not rust\n/// ```\npub fn f() {}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_closing_fence_is_not_read_as_an_unattributed_opener() {
    // DISCRIMINATING. A closing fence carries no info string, so a scanner
    // without the parity rule counts it as a second unattributed opener and
    // refuses a file that is correctly marked. The shell toggled a flag; the
    // successor counts parity, and this is the case that tells them from a
    // scanner that does neither.
    let dir = doctest_repo(
        "doctests-closing-fence",
        "/// ```text\n/// safe\n/// ```\npub fn f() {}\n",
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the closing fence was read as an opener: {}",
        stdout(&output)
    );
}

#[test]
fn the_refusal_is_a_pointer_never_the_example() {
    let dir = doctest_repo(
        "doctests-pointer-only",
        "/// ```\n/// let secret_example = 1;\n/// ```\npub fn f() {}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("secret_example"),
        "the example is payload and never appears: {}",
        stdout(&output)
    );
}

#[test]
fn a_fence_outside_a_doc_comment_is_not_a_doctest() {
    let dir = doctest_repo(
        "doctests-plain-comment",
        "// ```\n// let x = 1;\n// ```\npub fn f() {}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn the_committed_workspace_carries_no_runnable_doctest() {
    // The self-consumption case, and the measurement the runner swap rested on:
    // `cargo nextest run` executes no doctest, so an example here would be run
    // nowhere. Asserted rather than assumed, because an empty class is not a
    // stable property.
    let output =
        common::run_at_real_root(&common::at_root(""), &["check", "--rule", "no-doctests"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a runnable doctest landed, and nextest runs none of them: {}",
        stdout(&output)
    );
}
