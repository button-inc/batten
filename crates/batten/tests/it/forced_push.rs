//! The leased push, over the compiled binary and the committed table.
//!
//! # The gap this covers, and the one it does not
//!
//! Measured 2026-09-02 on `claude/cloud-1295-retire-bot-issue`: two sessions in
//! different containers held one branch. One pushed; the other had already built
//! a commit and its push was rejected non-fast-forward. **Nothing in Batten fired
//! at any point** — the rejection came from git, after the work was written,
//! verified and committed.
//!
//! `claim-not-raced` asks about a KEY across open pull requests, and both
//! sessions served the same one, so it is correctly silent. The claim receipt —
//! the one artifact saying *this session is working this branch* — lives under
//! `$GIT_DIR`, is never committed, and dies with the container, so no clone can
//! read another's.
//!
//! # Why this row is only one flag
//!
//! `trunk-based/no-force-push` already denies `--force` and `-f`, per segment.
//! It excludes `--force-with-lease` on a stated argument: it "refuses when the
//! remote moved". That is true when the sibling's push arrived AFTER your last
//! fetch — the remote-tracking ref is stale, the comparison differs, the push is
//! refused. It is false for the sequence an agent actually runs: `git fetch`
//! moves that ref onto the sibling's commit, the lease then compares EQUAL, and
//! the push succeeds. The flag chosen for being careful is the one that destroys
//! the commit.
//!
//! So these cases are about the spelling the preset leaves out. The ones it owns
//! are asserted here too, but as *somebody* refusing rather than as this row's
//! work — a second rule over one object is what the narrowing avoids.
//!
//! Judged against the committed `batten.toml` rather than a fixture: a fixture
//! would assert that the ENGINE can express this, which was never in doubt. What
//! is in doubt is whether the table this repository ships refuses the command.

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
        &["hook", "--harness", "claude-code"],
        &bash_payload(command),
    ))
}

/// Refused, and by THIS row — the assertion that would go green on the preset's
/// coverage alone is the one that proves nothing.
fn denied_by_this_row(command: &str) {
    let out = decision(command);
    assert!(
        out.contains("\"deny\""),
        "the committed policy must refuse: {command}\n{out}"
    );
    assert!(
        out.contains("leased-push"),
        "the refusal for `{command}` must come from this row\n{out}"
    );
}

/// Refused by something. Used only where the preset legitimately owns the case.
fn denied(command: &str) {
    let out = decision(command);
    assert!(
        out.contains("\"deny\""),
        "the committed policy must refuse: {command}\n{out}"
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
fn a_bare_leased_push_is_refused() {
    denied_by_this_row("git push --force-with-lease origin main");
    denied_by_this_row("git push origin claude/some-branch --force-with-lease");
}

#[test]
fn a_leased_push_behind_a_compound_command_is_still_reached() {
    // `input.call.segments`, not the first word of the line. The preset this
    // extends carries the measured instance in its own header: anchored on
    // `command`, it denied the bare `git push --force origin main` and allowed
    // `cd /tmp && git push --force origin main` with a green suite over it
    // (CLOUD-857) — and a real agent command is compound most of the time.
    //
    // THE FETCH-THEN-PUSH PAIR IS THE MEASURED SEQUENCE, not an invented one: it
    // is what makes the lease compare equal, so a row that missed it would miss
    // exactly the case this exists for.
    denied_by_this_row("cd /tmp && git push --force-with-lease origin main");
    denied_by_this_row("git fetch origin && git push --force-with-lease origin main");
}

#[test]
fn the_preset_still_owns_the_bare_forced_spellings() {
    // Asserted as SOMEBODY refusing rather than as this row's work. If this ever
    // starts coming from `leased-push`, the narrowing has been undone and
    // there are two rules over one object again.
    denied("git push --force origin main");
    denied("git push -f origin main");
}

#[test]
fn an_ordinary_push_is_untouched() {
    // The cost of this row must be zero on the path every session takes. An
    // ordinary push is already refused by git when it would discard commits, so
    // there is nothing here for this row to add and a refusal would only teach
    // people to reach for the bypass.
    allowed("git push -u origin claude/some-branch");
    allowed("git push origin main");
    allowed("git fetch origin main");
}

/// THE EXPLICIT EXPECTED VALUE IS THE WHOLE DISTINCTION, and this is the case
/// that would have gone green over a guard that banned the flag outright.
///
/// `land-lock.sh` states it about its own CAS: "The expected value is passed
/// EXPLICITLY (`<ref>:<sha>`) and must stay that way… The two forms look
/// interchangeable and are not." Naming the sha IS the assertion — you cannot
/// name a value you never observed — and a stale one is refused by git rather
/// than by policy.
///
/// Measured within an hour of writing the first version, which banned the
/// spelling: correcting a missing `Refs:` trailer on three of this branch's own
/// commits needed exactly this form, over history no other clone had fetched.
/// A guard that refused it had no route out at all — a consumer `[[rule]]` row
/// raises no class, so nothing could admit it, and the only remaining way
/// through was the password shape CLOUD-1051 retired.
#[test]
fn the_explicit_expected_value_is_allowed() {
    allowed("git push --force-with-lease=refs/heads/main:abc123 origin main");
    allowed("git fetch origin && git push --force-with-lease=refs/heads/x:deadbeef origin x");
}

#[test]
fn the_flag_named_in_prose_is_not_a_push() {
    // ANTI-VACUITY IN THE OTHER DIRECTION. A row keyed on the substring alone
    // would fire on any command mentioning the flag — including the ones
    // documenting this rule, which is how `no-secrets` refused its own
    // explanatory comment. `pattern` requires the `git push` shape and `contains`
    // narrows within it, so a sentence about a leased push is not one.
    allowed("echo 'never reach for git push --force-with-lease here'");
    // A `git` command carrying the flag that is not a PUSH — which is what says
    // `pattern` is doing work rather than `contains` alone deciding.
    allowed("git log --oneline --grep force-with-lease");
}
