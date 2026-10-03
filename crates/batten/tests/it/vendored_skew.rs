//! A branch declaring a class the binary already ships (CLOUD-2089).
//!
//! The state is a SKEW rather than a redefinition: a trunk change moves a class
//! from `batten.toml` into the binary, the session updates the engine to its
//! release pin, and a branch cut before the move still declares the class. The
//! mediated boundary used to refuse the load, which made every call
//! unadjudicable — the rebuild, the fetch and the rebase that are the only ways
//! out included. Only the compiled binary answers what the boundary does with
//! that load, so the tier is here rather than in `policy.rs`.
//!
//! # The pair is the point
//!
//! The boundary must decide; the authoring surface must still refuse. Either
//! case alone is satisfied by a wrong fix — a hook that never refuses anything,
//! or a `check` that let the dead row land.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{Fixture, run, run_with_stdin};

/// A config re-declaring the first class this binary vendors.
///
/// Read off the binary rather than written as a literal, so the case follows
/// whatever the build ships instead of going vacuous the day one token moves.
fn declaring_a_vendored_class() -> String {
    let shipped = batten::verdict::vendored();
    let token = &shipped
        .first()
        .expect("the binary vendors at least one class")
        .id;
    format!(
        "version = 1\n\
         \n\
         [[verdict]]\n\
         id = \"{token}\"\n\
         gloss = \"a copy of a class the binary ships\"\n\
         class = \"the row a branch still carries after trunk moved it into the binary\"\n\
         \n\
         [[verdict.route]]\n\
         id = \"task run first\"\n\
         kind = \"command\"\n\
         target = \"run it\"\n"
    )
}

fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&declaring_a_vendored_class())
        .file("notes.md", "ordinary\n")
        .git()
        .base_commit()
        .build()
}

#[test]
fn a_branch_declaring_a_class_the_binary_ships_still_adjudicates() {
    // WAS `2` WITH `engine-cannot-adjudicate`: the registry refused the load, so
    // the boundary had no rules and denied an ordinary command (CLOUD-2089).
    let dir = fixture("skew-boundary");
    let payload = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
                   \"tool_input\":{\"command\":\"echo hello\"}}";
    let out = run_with_stdin(&dir, &["adjudicate", "--harness", "exit-code"], payload);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("engine-cannot-adjudicate"),
        "a stale declaration of a shipped class must not leave the boundary without rules: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "an ordinary command under a config that loads must be allowed: {stderr}"
    );
}

#[test]
fn a_class_the_binary_ships_is_still_refused_by_check() {
    // THE MIRROR. Without it the case above is satisfied by deleting the check
    // altogether, and a dead row lands reading as live.
    let dir = fixture("skew-check");
    let out = run(&dir, &["check"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "check must refuse the row: {stderr}"
    );
    assert!(
        stderr.contains("already ships"),
        "the refusal names the collision: {stderr}"
    );
}
