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
//! # Why there is no exemption any more (CLOUD-843)
//!
//! `job select missing` already governs this variable where CI sets it, so the
//! DECLARED use is gated and the ad-hoc one was free — a hole shaped exactly like
//! the repository's own legitimate use. The module used to exempt the one
//! spelling the `ci` job handed hk, `HK_SKIP_STEPS=test:bats`. That step retired
//! with the shell suite, so the exemption admitted a skip of nothing, and it went
//! with the step. The `ci` job's carve is now `batten-check`, which CI sets in a
//! workflow `env:` this surface never sees; typed by an agent it is the incident
//! itself, so it is refused and not exempted in the old one's place.
//!
//! # This is the tier that proves the key exists
//!
//! The module's own `test_` rules fabricate `input.call.segments` with
//! `with input as`, so they pass over a shape the engine may never build —
//! `rules/policy-modules.md`'s opening defect, and the reason both live
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
        out.contains("hook skip unseen"),
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

/// [`allowed`], with the call's backgrounding STATED.
///
/// These cases adjudicate against the LIVE root, so every committed row reaches
/// them — `task run blocked` included, which refuses a foreground `mise` call with
/// no fast list. An anti-vacuity case has to survive on this row's own account
/// rather than by another row's silence, so the posture is stated and the
/// remaining question is whether THIS row fires.
fn allowed_backgrounded(command: &str) {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let payload = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped},\"run_in_background\":true}}}}"
    );
    let root = common::at_root(".");
    let out = common::stdout(&common::run_with_stdin(
        &root,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    ));
    assert!(
        !out.contains("\"deny\""),
        "the committed policy must allow a backgrounded: {command}\n{out}"
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
fn the_retired_carve_is_refused_like_any_other() {
    // The spelling the module once exempted names a step that no longer exists
    // (CLOUD-843), so an exemption for it would be dead policy surface. The
    // mutant `skip-pattern-unread` names this case: with the pattern unread,
    // nothing here is refused.
    denied_by_this_row("HK_SKIP_STEPS=test:bats mise run ci");
    // The `ci` job's current carve, typed by an agent rather than set in the
    // workflow's `env:`, is the incident this row was filed from.
    denied_by_this_row("HK_SKIP_STEPS=batten-check mise run ci");
}

#[test]
fn the_carve_with_a_step_appended_is_refused() {
    // Find the line in a workflow, add "just one more" step to it.
    denied_by_this_row("HK_SKIP_STEPS=test:bats,batten-check mise run ci");
    denied_by_this_row("HK_SKIP_STEPS=test:bats,hooks-wiring-check mise run verify");
}

#[test]
fn an_ordinary_command_is_allowed() {
    // ANTI-VACUITY. Without these the denies above are satisfied by a build that
    // refuses every command, which would name this row every time.
    allowed("git commit -m 'an ordinary commit'");
    allowed_backgrounded("mise run ci");
    allowed("RUST_LOG=debug git commit -m 'another variable is not this one'");
}

#[test]
fn a_quoted_mention_is_not_an_invocation() {
    // The tokenizer's own quoting, reached through the engine rather than
    // re-derived: prose naming the variable is not a command setting it.
    allowed("echo 'set HK_SKIP_STEPS=x to skip a step'");
}
