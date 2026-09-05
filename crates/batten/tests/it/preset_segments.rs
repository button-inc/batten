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
        &["adjudicate", "--harness", "exit-code"],
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

#[test]
fn a_token_before_the_program_does_not_hide_it() {
    // CLOUD-1382's table, measured 2026-09-03 and re-measured 2026-09-05 against
    // the shipped binary: every one of these ran the force push at exit 0.
    // CLOUD-857 moved the anchor off the whole LINE and onto the segment, which
    // closed `cd /tmp && …`; it did not close a token before the PROGRAM, and
    // six of those are one keystroke.
    //
    // `!` inverts the exit status and still executes. `time` executes and
    // reports. `(` and `{` both group and both execute. `command` executes,
    // bypassing only function and alias lookup. `then` is the body of a
    // conditional that ran.
    //
    // SHOWN ABLE TO FAIL (CLOUD-418). Run against the preset as it stood, seven
    // of these eight were green when they should have been red — and the
    // load-time tier could not have shown it, because a `with input as` case
    // hands the predicate hand-written `words` and so fabricates the very
    // tokenization that is wrong.
    assert_preset_denies("(git push --force origin main)");
    assert_preset_denies("time git push --force origin main");
    assert_preset_denies("! git push --force origin main");
    assert_preset_denies("{ git push --force origin main; }");
    assert_preset_denies("command git push --force origin main");
    assert_preset_denies("if true; then git push --force origin main; fi");
    // The eighth, found while reproducing the row's seven: an environment
    // assignment occupies index 0 in its own right, and `effective_program` has
    // stepped past those since long before this row.
    assert_preset_denies("GIT_TRACE=1 git push --force origin main");
    // A grammar token in a COMPOUND command, which is the two holes at once —
    // neither anchor alone reaches it.
    assert_preset_denies("cd /tmp && time git push --force origin main");
}

#[test]
fn a_token_before_the_program_does_not_invent_a_deny_either() {
    // The anti-vacuity half, and it is the one that would catch a fix that
    // simply searched the whole segment for `git`. Each of these carries a
    // grammar prefix AND something that must stay allowed, so a predicate that
    // stopped correlating the flag with git's own argv fails here.
    assert_preset_allows("time git push --force-with-lease origin main");
    assert_allowed("(git push origin feature)");
    assert_allowed("time hg push --force");
    assert_allowed("! echo \"git push --force origin main\"");
    // git behind a grammar token, doing something the preset has no view on.
    // The prefix must make the program VISIBLE, never make it guilty.
    assert_allowed("time git status");
}

#[test]
fn a_groups_closing_paren_does_not_hide_the_last_argument() {
    // CodeRabbit's finding on #868, verified against the shipped binary before
    // it was fixed: `program_token` stripped the OPENING grouping punctuation
    // only, so the closing paren stayed glued to the last token — which is
    // exactly the token an exact-match predicate is decided on.
    //
    // Measured, and the word ORDER is the whole tell: with the flag written
    // early the group already denied, and with the flag written last it exited
    // 0, because `arguments` ended `--force)` and this preset compares for
    // equality.
    assert_preset_denies("(git push origin main --force)");
    assert_preset_denies("(git push origin main -f)");
    assert_preset_denies("{ git push origin main --force; }");
    // The flag early, which denied before the fix too — kept so the pair reads
    // as one measurement rather than two unrelated cases.
    assert_preset_denies("(git push --force origin main)");
}

#[test]
fn a_closing_paren_does_not_invent_a_deny_either() {
    // The mirror. Stripping a group's punctuation must not make an ordinary
    // grouped command guilty, and must not reach INSIDE a command substitution:
    // `binary=$(which gh)` is ONE word to `hook::segments`, and its `)` closes
    // the `$(` within it rather than a group around it.
    assert_allowed("(git push origin feature)");
    assert_allowed("(hg push --force)");
    assert_allowed("binary=$(which gh)");
}
