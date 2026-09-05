//! Switching an `hk` step off locally, over the compiled binary and the
//! committed table (CLOUD-1340).
//!
//! # The gap this covers
//!
//! Measured 2026-09-02 on this branch. `hooks-wiring-check` refused; the session
//! read the refusal as environmental and unfixable, set `HK_SKIP_STEPS` on three
//! commits, wrote that justification into two commit messages, and put a
//! four-option menu to a human. `batten wiring reclaim -y` cleared the condition
//! in one command. **Nothing in Batten fired at any point** — the variable is read
//! by `hk`, which batten never sees, so a switched-off gate and a satisfied one
//! were byte-identical from here.
//!
//! # Why the exemption case is the load-bearing one
//!
//! `ci-suite-lane` already governs this variable where CI sets it, so the
//! DECLARED use is gated and the ad-hoc one was free — a hole shaped exactly like
//! the repository's own legitimate use. That shape is what makes the exemption
//! assertion matter more than the deny: a row that refused the `ci` job's own line
//! would be a guard people switch off rather than satisfy, which is the failure
//! this whole family exists to avoid. So `HK_SKIP_STEPS=test:bats` must be
//! allowed, and `HK_SKIP_STEPS=test:bats,batten-check` must not — the second is
//! what an author reaches for after finding the first in a workflow file.
//!
//! # This is the tier that proves the key exists
//!
//! The module's own `test_` rules fabricate `input.call.segments` with
//! `with input as`, so they pass over a shape the engine may never build —
//! `.claude/rules/policy-modules.md`'s opening defect, and the reason both live
//! instances of it were found by adding a tier like this one. The specific risk
//! here is real rather than notional: `hook::is_env_assignment` is what the
//! boundary uses to look THROUGH an assignment when resolving the effective
//! program, so `input.call.programs` reports `git` and never the variable. These
//! cases are what prove the token survives in `words`.
//!
//! Judged against the committed `batten.toml` rather than a fixture, for
//! `forced_push.rs`'s reason: a fixture would assert the engine CAN express this,
//! which was never in doubt. What is in doubt is whether the table this
//! repository ships refuses the command.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

fn decision(command: &str) -> String {
    let root = common::at_root(".");
    common::stdout(&common::run_with_stdin(
        &root,
        &["adjudicate", "--harness", "claude-code"],
        &bash_payload(command),
    ))
}

/// Refused, and by THIS row — an assertion that would go green on some other
/// row's coverage proves nothing about this one.
fn denied_by_this_row(command: &str) {
    let out = decision(command);
    assert!(
        out.contains("\"deny\""),
        "the committed policy must refuse: {command}\n{out}"
    );
    assert!(
        out.contains("hook-skip-local"),
        "the refusal for `{command}` must come from this row\n{out}"
    );
}

fn allowed(command: &str) {
    let out = decision(command);
    assert!(
        !out.contains("\"deny\""),
        "the committed policy must allow: {command}\n{out}"
    );
}

#[test]
fn a_local_step_skip_is_refused() {
    // The measured command, as it was actually run on this branch.
    denied_by_this_row("HK_SKIP_STEPS=hooks-wiring-check git commit -m 'x'");
    denied_by_this_row("HK_SKIP_STEPS=batten-check,test:cargo git commit --amend --no-edit");
}

#[test]
fn a_step_skip_behind_a_compound_command_is_still_reached() {
    // `input.call.segments`, not the first word of the line (CLOUD-857). A real
    // agent command is compound most of the time, and `git add -A && <skip> git
    // commit` is the exact shape this session ran.
    denied_by_this_row("git add -A && HK_SKIP_STEPS=hooks-wiring-check git commit -m 'x'");
    denied_by_this_row("cd /home/user/batten && HK_SKIP_STEPS=batten-check git commit -m 'x'");
}

#[test]
fn the_declared_ci_carve_is_not_judged_here() {
    // THE CASE THAT KEEPS THIS FROM BEING SWITCHED OFF. `.github/workflows/ci.yml`
    // hands hk exactly this, and `ci-suite-lane` is the row that governs it. A
    // guard refusing the repository's own declared invocation gets disabled, and
    // then it enforces nothing at all.
    allowed("HK_SKIP_STEPS=test:bats mise run ci");
}

#[test]
fn the_carve_with_a_step_appended_is_refused() {
    // The arm a prefix test would lose, and the one an author actually reaches
    // for: find the line in a workflow, add "just one more" step to it.
    denied_by_this_row("HK_SKIP_STEPS=test:bats,batten-check mise run ci");
    denied_by_this_row("HK_SKIP_STEPS=test:bats,hooks-wiring-check mise run verify");
}

#[test]
fn an_ordinary_command_is_allowed() {
    // ANTI-VACUITY. Without these the denies above are satisfied by a build that
    // refuses every command, which would name this row every time.
    allowed("git commit -m 'an ordinary commit'");
    allowed("mise run ci");
    allowed("RUST_LOG=debug git commit -m 'another variable is not this one'");
}

#[test]
fn a_quoted_mention_is_not_an_invocation() {
    // The tokenizer's own quoting, reached through the engine rather than
    // re-derived: prose naming the variable is not a command setting it.
    allowed("echo 'set HK_SKIP_STEPS=x to skip a step'");
}
