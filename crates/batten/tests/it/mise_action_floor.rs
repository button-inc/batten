//! No workflow pins a toolchain-install commit that predates its download
//! retry, over the compiled binary (CLOUD-404, ported from
//! `mise-tasks/mise-action-floor.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/mise-action-floor.rego` carries
//! load-time cases pinning the predicate, and every one of them supplies
//! `input.tree.lines` with `with input as`. That fabricates the very shape the
//! engine may be unable to produce (CLOUD-845) — and here it fabricates the
//! multi-path resolution of a declared `line_sources` GLOB, which is exactly what
//! the anti-vacuity arm turns on: a module whose suite only fabricated the map
//! would report "no pin found" as could-not-look while an engine that resolved
//! nothing at all reported the same thing, and the two would be
//! indistinguishable.
//!
//! The self-consumption case is the one the retiring suite ended on: this
//! repository's own workflows are judged, so the floor is a live claim rather
//! than an asserted one.
//
// carried: mise-tasks/mise-action-floor.sh policy/mise-action-floor.rego crates/batten/tests/it/mise_action_floor.rs
// carried: tests/mise-action-floor.bats policy/mise-action-floor.rego crates/batten/tests/it/mise_action_floor.rs
//
// carried: "a pin carrying the retry passes, and says what it judged" policy/mise-action-floor.rego
// carried: "THE ACCEPTANCE CASE: a pre-retry pin fails and is named with path:line" policy/mise-action-floor.rego
// carried: "THE BACKSLIDE: one reverted pin among many still fails" policy/mise-action-floor.rego
// carried: "SHOWN ABLE TO FAIL IN BOTH DIRECTIONS: every pin reverted fails with the full count" policy/mise-action-floor.rego
// carried: "the predicate is scoped to this action, so a lookalike coordinate does not fire" policy/mise-action-floor.rego
// carried: "the sha in prose or a comment is not a pin" policy/mise-action-floor.rego
// carried: "ANTI-VACUITY: a workflow with no mise-action pin is exit 2, never a pass" policy/mise-action-floor.rego
// carried: "an unversioned float is not a pin this gate can judge, so it is exit 2" policy/mise-action-floor.rego
// carried: "POINTER, NEVER PAYLOAD: the report carries no workflow content" policy/mise-action-floor.rego
// changed: "COULD NOT LOOK: a missing path is exit 2 rather than an empty pass" policy/mise-action-floor.rego the shell took explicit paths and refused one it could not open; the successor takes a declared `line_sources` glob and the ENGINE decides this earlier — a rule whose glob matches nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049). What the case protected is not lost: a tree with workflows but no pin of this action still reports could-not-look, which is `a_tree_with_no_pin_of_this_action_is_not_clean`

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// The pre-retry commit, split so the literal never reads as a live coordinate
/// in this file.
const PRE_RETRY: &str = "7e36c90d9ab29c415a2384db3006f3ec8a8cc654";

/// Any later commit. Its only property that matters is not being the one above.
const FORWARD: &str = "1111111111111111111111111111111111111111";

/// A repository declaring only this rule, so any finding is the one under test.
///
/// The `[[pattern]]` row is carried in beside the two `[[verdict]]` rows for the
/// same reason: a module referencing a pattern no row declares is refused AT
/// LOAD, which is a usage error rather than the verdict these cases are about.
fn floor_repo(name: &str, workflows: &[(&str, &str)]) -> PathBuf {
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[pattern]]\n\
         id = \"git-object-id\"\n\
         regex = '^[0-9a-f]{40}$'\n\n\
         [[verdict]]\n\
         id = \"version pin stale\"\n\
         gloss = \"a pin resolves behind a fix this repository depends on\"\n\
         class = \"A backslide auto-lands silently and the next occurrence reads as fresh.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"version pin unread\"\n\
         gloss = \"the pin under judgement could not be read\"\n\
         class = \"A gate whose subject can vanish and read as clean is not a gate.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"mise-action-floor\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\".github/workflows/*.yml\"]\n\
         module = \"policy/mise-action-floor.rego\"\n\
         severity = \"deny\"\n",
    );
    fixture = fixture.file("AGENTS.md", "the consumer's own authority\n");
    for (path, body) in workflows {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/mise-action-floor.rego",
        &std::fs::read_to_string(common::at_root("policy/mise-action-floor.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "mise-action-floor"])
}

/// A workflow whose install step pins the action at `reference`.
fn workflow(reference: &str) -> String {
    format!(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: jdx/mise-action@{reference}\n"
    )
}

#[test]
fn a_pin_carrying_the_retry_passes() {
    let dir = floor_repo(
        "floor-forward",
        &[(".github/workflows/ci.yml", &workflow(FORWARD))],
    );
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_pre_retry_pin_is_refused_and_named() {
    let dir = floor_repo(
        "floor-backslide",
        &[(".github/workflows/ci.yml", &workflow(PRE_RETRY))],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains(".github/workflows/ci.yml:"),
        "the finding points at the workflow line: {:?}",
        stdout(&output)
    );
}

#[test]
fn one_reverted_pin_among_many_still_fails() {
    // THE BACKSLIDE the gate exists for: the bot bumps one workflow and the
    // others stay forward, so a whole-tree "all pins agree" reading would miss
    // it.
    let dir = floor_repo(
        "floor-one-among-many",
        &[
            (".github/workflows/ci.yml", &workflow(FORWARD)),
            (".github/workflows/release.yml", &workflow(PRE_RETRY)),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("release.yml"),
        "the finding names the reverted workflow: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_lookalike_coordinate_does_not_fire() {
    // The same sha on a different action is not this defect. A gate firing on a
    // lookalike trains its readers to ignore it.
    let dir = floor_repo(
        "floor-lookalike",
        &[(
            ".github/workflows/ci.yml",
            &format!(
                "{}      - uses: some/other-action@{PRE_RETRY}\n",
                workflow(FORWARD)
            ),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_sha_in_prose_is_not_a_pin() {
    let dir = floor_repo(
        "floor-prose",
        &[(
            ".github/workflows/ci.yml",
            &format!(
                "{}      # was {PRE_RETRY} before the retry landed\n",
                workflow(FORWARD)
            ),
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_tree_with_no_pin_of_this_action_is_not_clean() {
    // ANTI-VACUITY: the thing under test must not be able to vanish and read as
    // clean.
    let dir = floor_repo(
        "floor-vacuous",
        &[(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_floating_ref_is_not_a_pin_this_gate_can_judge() {
    // `@v4` carries no sha, so the denylist cannot speak about it at all.
    // Reporting green over it would be a claim the gate cannot support.
    let dir = floor_repo(
        "floor-floating",
        &[(".github/workflows/ci.yml", &workflow("v4"))],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = floor_repo(
        "floor-pointer-only",
        &[(".github/workflows/ci.yml", &workflow(PRE_RETRY))],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        !text.contains("ubuntu-latest") && !text.contains("runs-on"),
        "the workflow's content is payload: {text:?}"
    );
}

#[test]
fn this_repositorys_own_workflows_hold_the_floor() {
    // The self-consumption case the retiring suite ended on: the floor is a live
    // claim about this repository, checked rather than asserted.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "mise-action-floor"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a workflow here pins behind the download retry: {}",
        stdout(&output)
    );
}
