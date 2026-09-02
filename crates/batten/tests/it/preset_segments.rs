//! The vendored presets, driven through `batten hook` over a real envelope
//! (CLOUD-857).
//!
//! **This file exists because a green `policy test` is not evidence.** CLOUD-845
//! established that a module can pass its own suite and gate nothing, and
//! CLOUD-857 is that class by a second road: the `trunk-based` preset anchored
//! `split(input.call.command, " ")[0] == "git"` over the whole command line, so
//! `git push --force origin main` denied while
//! `cd /tmp && git push --force origin main` was allowed — and its four `test_`
//! rules each passed a bare command, so the suite could not see it. Green tests,
//! silent gate, and neither safety net fired: the predicate WAS exercised and
//! the module WAS tested.
//!
//! So the acceptance is stated over the ENGINE. `.claude/rules/policy-modules.md`
//! is explicit that a `with input as` case cannot answer this — *"it fabricates
//! the very shape the engine may be unable to produce"* — and here the shape was
//! one the engine produces constantly and the tests never did.
//!
//! **Judged against the committed `batten.toml`**, which enables
//! `trunk-based-preset` like any other consumer would (CLOUD-836). A fixture-only
//! suite would stay green after someone disabled the row, which is exactly the
//! drift a corpus over the real config exists to catch.
//!
//! **The refusal's ATTRIBUTION is asserted, never just the exit code**, and that
//! is the lesson `crates/batten/tests/it/run_shape_guard_door.rs`'s header records: this
//! repository's own rows refuse commands in the same family, so an exit 2 alone
//! would let some other row's verdict stand in for the preset's — coverage that
//! has stopped testing the thing it names.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{run_with_stdin_at_real_root, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// The exit code and the refusal text together, because both are asserted.
fn adjudicate(command: &str) -> (Option<i32>, String) {
    let outcome = run_with_stdin_at_real_root(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload(command),
    );
    let code = outcome.status.code();
    (code, stderr(&outcome))
}

/// Denied, and denied by the PRESET rather than by a neighbour.
fn assert_preset_denies(command: &str) {
    let (code, cause) = adjudicate(command);
    assert_eq!(code, Some(2), "must refuse: {command}");
    assert!(
        cause.contains("no-force-push"),
        "the deny must be the preset's own, not a neighbouring row's: {command}\n{cause}"
    );
}

/// The PRESET did not fire. Weaker than [`assert_allowed`] and used only where a
/// consumer row legitimately refuses the same command.
///
/// The header above states this file's rule for the deny side — assert the
/// preset's attribution, never a bare exit code, "so an exit 2 alone would let
/// some other row's verdict stand in for the preset's". The allow side has the
/// mirror defect and it went unnoticed until it bit: exit 0 conflates "the preset
/// did not fire" with "nothing fired", so the assertion breaks the moment this
/// consumer declares its own row over the same command, while the property the
/// case is named for is untouched.
fn assert_preset_allows(command: &str) {
    let (_, cause) = adjudicate(command);
    assert!(
        !cause.contains("no-force-push"),
        "the preset must not refuse: {command}\n{cause}"
    );
}

fn assert_allowed(command: &str) {
    let (code, cause) = adjudicate(command);
    assert_eq!(code, Some(0), "must allow: {command}\n{cause}");
}

#[test]
fn a_force_push_alone_still_denies() {
    // The one case that worked before the projection. It is here so the fix is
    // shown to preserve what it already had, rather than to trade one anchoring
    // for another.
    assert_preset_denies("git push --force origin main");
    assert_preset_denies("git push -f origin main");
}

#[test]
fn a_force_push_inside_a_compound_command_denies() {
    // CLOUD-857's reproduction, measured 2026-08-21 as ALLOWED. Every one of
    // these puts the force push somewhere other than the first word of the line,
    // which is the only place the old predicate could see.
    assert_preset_denies("cd /tmp && git push --force origin main");
    assert_preset_denies("echo hi; git push --force origin main");
    assert_preset_denies("export FOO=1 && git push -f origin main");
    // Not only the second element: the anchor has to be per-segment, not
    // per-first-and-last.
    assert_preset_denies("cd /tmp && echo hi && git push --force origin main");
}

#[test]
fn force_with_lease_survives_segmentation() {
    // The distinction the preset exists to draw, and the half a deny-only suite
    // would not test. `--force-with-lease` refuses when the remote moved, which
    // is the whole difference between "I know what I am replacing" and "replace
    // whatever is there" — a preset banning both would push its consumers toward
    // the bypass rather than toward the safer flag.
    //
    // ASSERTED AS "THE PRESET DOES NOT FIRE" rather than as a clean exit, because
    // this consumer now declares `leased-push` over the BARE spelling and the two
    // statements are different. The preset's distinction is what this case
    // is named for and it is unchanged; whether THIS repository additionally
    // refuses the leased spelling is a consumer decision the preset has no view on.
    //
    // The consumer's reason, recorded here so the divergence is not read as an
    // accident: a bare `--force-with-lease` compares against the remote-tracking
    // ref this clone holds, so `git fetch` followed by a leased push compares
    // EQUAL and overwrites the sibling commit the fetch just brought in. That is
    // measured (2026-09-02, two sessions on one branch), and it is a fact about a
    // fleet of agents in separate containers rather than about trunk-based
    // development, which is why it is a consumer row and the preset stays as it is.
    assert_preset_allows("git push --force-with-lease origin main");
    assert_preset_allows("cd /tmp && git push --force-with-lease origin main");
}

#[test]
fn a_mention_inside_a_quoted_span_still_does_not_fire() {
    // What segmentation must not regress. `hook::segments` keeps a quoted span
    // as ONE word (CLOUD-269), so the program here is `echo` and `git` is an
    // operand — the same property that stops `git commit -m "gh pr merge"` from
    // reading as an invocation.
    assert_allowed("echo \"git push --force origin main\"");
    assert_allowed("cd /tmp && echo 'git push --force origin main'");
}

#[test]
fn another_tool_is_not_judged_wherever_it_sits() {
    // The preset carries a PRACTICE about git, so a different tool's identical
    // flag is not its business — in a list as much as alone.
    assert_allowed("hg push --force");
    assert_allowed("cd /tmp && hg push --force");
}
