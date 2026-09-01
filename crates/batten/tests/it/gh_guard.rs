//! The `gh` lifecycle corpus, over the compiled binary and the committed policy
//! (CLOUD-1163, unit 8).
//!
//! This is the acceptance corpus `tests/gh-guard.bats` carried, translated into
//! the surface that now decides it. The retirement is unusual in the campaign
//! because **the successor landed first**: `batten.toml`'s four `gh` lifecycle
//! rows are, in that file's own words at `:274`, "the ported `gh-guard`", and
//! CLOUD-312 made `PreToolUse` a single entry — `batten hook`. Nothing has
//! invoked `mise-tasks/gh-guard.sh` since: it is absent from
//! `.claude/settings.json`, from `mise.toml`'s task graph, from `hk.pkl` and from
//! every workflow, and its only executions were its own suite and `mise run
//! mutant`.
//!
//! So without this file the deletion would take the corpus with it and nothing
//! would notice a shape that stopped being refused. That is the whole reason the
//! ledger demands a compiled tier rather than accepting "the engine already does
//! it".
//!
//! **Judged against the committed `batten.toml`, not a fixture**, on
//! `tests/mediated_verbs.rs`' precedent and for its reason: a fixture policy
//! tests the engine and says nothing about the TABLE, so deleting a `gh`
//! lifecycle row would break none of it.
//!
//! **The allows are the load-bearing half.** The dying suite says so in its own
//! header — its first live run denied a `git commit` whose MESSAGE quoted the
//! blocked verbs — and a guard with false positives is one people switch off.
//!
//! # One case asserts a rule id rather than a verdict, and that is not a weakening
//!
//! `gh pr ready` is ALLOWED by the predicate under test and DENIED by the engine
//! overall, because `ready-needs-receipts` legitimately refuses a ready with no
//! `verify` receipt for this head. The bats case drove `gh-guard-check.sh`
//! directly, so it only ever asked the narrower question. Reading the aggregate
//! exit code here would make one rule's correct arrival look like this rule's
//! regression — [`assert_no_gh_lifecycle_refusal`] asks the question the case
//! actually asked.
//!
//! # The ledger
//!
//! Three deleted paths, one arm each, and one arm per deleted `@test` case. The
//! successor is engine source rather than a `policy/*.rego` module, so each file
//! arm declares its kind: `kind:mechanism`, because `hook.rs` is the boundary a
//! `[[rule]]` row is read by and no new top-level verb is minted here.
//
// carried: mise-tasks/gh-guard.sh crates/batten/src/hook.rs kind:mechanism crates/batten/tests/gh_guard.rs
// carried: mise-tasks/gh-guard-check.sh crates/batten/src/hook.rs kind:mechanism crates/batten/tests/gh_guard.rs
// carried: tests/gh-guard.bats crates/batten/src/hook.rs kind:mechanism crates/batten/tests/gh_guard.rs
//
// carried: "blocks gh pr merge" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr merge behind a flag value" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr merge behind an env prefix" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr checks" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh run watch" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks a blocked verb hiding in a later chained segment" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks a hand-typed /fast-forward comment" crates/batten/src/hook.rs kind:mechanism
// carried: "allows gh pr ready" crates/batten/src/hook.rs kind:mechanism
// carried: "allows gh pr reads" crates/batten/src/hook.rs kind:mechanism
// carried: "allows a branch argument that merely contains a blocked verb" crates/batten/src/hook.rs kind:mechanism
// carried: "allows an ordinary gh pr comment" crates/batten/src/hook.rs kind:mechanism
// carried: "allows gh api and the unblocked run subcommands" crates/batten/src/hook.rs kind:mechanism
// carried: "allows a non-gh command that quotes a blocked verb" crates/batten/src/hook.rs kind:mechanism
// carried: "allows an empty command" crates/batten/src/hook.rs kind:mechanism
// carried: "hook emits a deny decision for a blocked command" crates/batten/src/hook.rs kind:mechanism
// carried: "hook stays silent for an allowed command" crates/batten/src/hook.rs kind:mechanism
// carried: "hook fails open on unparseable input" crates/batten/src/hook.rs kind:mechanism
// carried: "hook honours the bypass" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr merge behind mise exec" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr merge behind mise x with a tool pin" crates/batten/src/hook.rs kind:mechanism
// carried: "blocks gh pr checks behind env and timeout" crates/batten/src/hook.rs kind:mechanism
// carried: "allows mise run — a task name is not a wrapped program" crates/batten/src/hook.rs kind:mechanism
// carried: "allows a bare wrapper with nothing after it" crates/batten/src/hook.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{run_with_stdin, stdout};

/// The four rule ids that carry the `gh` lifecycle, as `batten.toml` declares
/// them.
///
/// Named rather than spelled per case, because the property under test is that
/// THESE rows decide — a refusal from any other row is a different question, and
/// the `gh pr ready` case below turns on exactly that distinction.
const LIFECYCLE: [&str; 4] = [
    "gh-pr-merge",
    "gh-pr-comment-fast-forward",
    "gh-pr-checks",
    "gh-run-watch",
];

/// The repository root, whose committed `batten.toml` is the policy under test.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

/// The decision document this harness emits, as text.
///
/// `claude-code` rather than `exit-code` here, because two of the dying suite's
/// cases are about the DOCUMENT — that a deny carries
/// `"permissionDecision": "deny"`, and that an allowed command produces no
/// document at all. The exit-code adapter collapses both into a status.
fn decision(command: &str) -> String {
    stdout(&run_with_stdin(
        &root(),
        &["hook", "--harness", "claude-code"],
        &bash_payload(command),
    ))
}

fn denied_by(command: &str, rule: &str) {
    let out = decision(command);
    assert!(
        out.contains("\"deny\""),
        "the committed policy must refuse: {command}\n{out}"
    );
    assert!(
        out.contains(rule),
        "the refusal for `{command}` must come from `{rule}`\n{out}"
    );
}

/// No `gh` lifecycle row refused this command.
///
/// Weaker than a full allow on purpose, and only for commands where a SECOND row
/// legitimately fires — see the module header on `gh pr ready`. The dying suite
/// drove the decision program directly, so this is the same question it asked.
fn assert_no_gh_lifecycle_refusal(command: &str) {
    let out = decision(command);
    for rule in LIFECYCLE {
        assert!(
            !out.contains(rule),
            "no gh lifecycle row may refuse `{command}`, and `{rule}` did\n{out}"
        );
    }
}

/// Nothing at all refused this command.
fn allowed(command: &str) {
    let out = decision(command);
    assert!(
        !out.contains("\"deny\""),
        "the committed policy must allow: {command}\n{out}"
    );
}

// --- blocked: shapes a task already encapsulates ------------------------------

#[test]
fn gh_pr_merge_is_refused_however_it_is_spelled() {
    denied_by("gh pr merge 42 --rebase", "gh-pr-merge");
    // Behind a flag VALUE, and behind an env prefix. The pairs are adjacent, so
    // an interposed flag never hides a real match.
    denied_by("gh -R example-org/example-repo pr merge 42", "gh-pr-merge");
    denied_by("GH_TOKEN=x gh pr merge 42", "gh-pr-merge");
}

#[test]
fn the_ci_watch_shapes_are_refused() {
    denied_by("gh pr checks 63 --watch", "gh-pr-checks");
    denied_by("gh run watch 12345", "gh-run-watch");
}

#[test]
fn a_blocked_verb_in_a_later_segment_is_still_refused() {
    // CLOUD-857's class: a real agent command is compound most of the time, and
    // anchoring on the first word of the LINE misses every one of these.
    denied_by("gh pr view 63 && gh run watch 1", "gh-run-watch");
    denied_by("echo hi; gh pr checks 63", "gh-pr-checks");
}

#[test]
fn a_hand_typed_fast_forward_comment_is_refused() {
    denied_by(
        "gh pr comment 63 --body \"/fast-forward\"",
        "gh-pr-comment-fast-forward",
    );
}

#[test]
fn a_wrapped_gh_call_is_judged_by_its_effective_program() {
    // `input.call.programs` is the argv ALREADY READ (CLOUD-1028): the boundary
    // looks through wrappers, so the wrapper token is never what is judged. In
    // the web sandbox the wrapper form is often the only working form, so a guard
    // stopping at the wrapper would see none of the calls that matter.
    denied_by("mise exec -- gh pr merge 42", "gh-pr-merge");
    denied_by("mise x node@22 gh pr merge 42", "gh-pr-merge");
    denied_by("env GH_TOKEN=x timeout 30 gh pr checks 42", "gh-pr-checks");
}

// --- allowed: reads, creates, and verbs with no task wrapper -------------------

#[test]
fn gh_pr_ready_is_not_a_lifecycle_refusal() {
    // The one case that asks about the ROW rather than the verdict. See the
    // module header: `ready-needs-receipts` refuses this correctly, and reading
    // the aggregate would report that as this rule's regression.
    assert_no_gh_lifecycle_refusal("gh pr ready 63");
}

#[test]
fn the_read_shaped_gh_calls_are_allowed() {
    allowed("gh pr view 63 --json state");
    allowed("gh pr list --state open");
    allowed("gh pr create --draft --fill");
    allowed("gh api repos/o/r/commits/abc/check-runs");
    allowed("gh run view 12345 --log");
    allowed("gh run rerun 12345");
    allowed("gh workflow run ci.yml");
}

#[test]
fn an_argument_that_merely_contains_a_blocked_verb_is_allowed() {
    // `gh pr view merge-fix` is not `gh pr merge`: the shapes match as an
    // ADJACENT verb pair, which is what keeps a branch name off the deny path.
    allowed("gh pr view merge-fix --json state");
}

#[test]
fn an_ordinary_gh_pr_comment_is_allowed() {
    // Only a comment carrying the landing directive is the lifecycle. This is the
    // one row with a second condition (`contains = "fast-forward"`).
    allowed("gh pr comment 63 --body \"CI is green\"");
}

#[test]
fn a_non_gh_command_quoting_a_blocked_verb_is_allowed() {
    // THE REGRESSION THE DYING SUITE WAS WRITTEN FOR. A commit message naming the
    // verbs is not a call, and the guard's first live run denied exactly this.
    allowed("git commit -m \"ci(guard): block gh pr merge and a typed /fast-forward comment\"");
    allowed("echo \"gh run watch\"");
}

#[test]
fn an_empty_command_is_allowed() {
    allowed("");
}

#[test]
fn a_task_name_is_not_a_wrapped_program() {
    // `mise run` names a TASK; only `mise exec`/`mise x` run another program. A
    // wrapper-looking-through that did not know the difference would refuse the
    // command every deny in this file recommends.
    allowed("mise run land");
    allowed("mise exec --");
}

// --- the hook's own document contract -----------------------------------------

#[test]
fn a_blocked_command_emits_a_deny_decision() {
    let out = decision("gh pr merge 63");
    assert!(
        out.contains("\"permissionDecision\":\"deny\"")
            || out.contains("\"permissionDecision\": \"deny\""),
        "a blocked command must emit a deny decision document\n{out}"
    );
}

#[test]
fn an_allowed_command_emits_no_decision() {
    // Silence is the contract: a document per allowed call would put a line in
    // front of the agent on every tool use.
    let out = decision("gh pr view 63 --json state");
    assert!(
        !out.contains("permissionDecision"),
        "an allowed command must emit no decision document\n{out}"
    );
}

#[test]
fn unparseable_input_fails_open() {
    let out = stdout(&run_with_stdin(
        &root(),
        &["hook", "--harness", "claude-code"],
        "not json",
    ));
    assert!(
        !out.contains("\"deny\""),
        "a payload the boundary cannot read is never a refusal\n{out}"
    );
}

/// Run one command with an environment variable set, and return the document.
fn decision_with_env(command: &str, key: &str, value: &str) -> String {
    stdout(
        &common::batten()
            .args(["hook", "--harness", "claude-code"])
            .current_dir(root())
            .env(key, value)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child
                    .stdin
                    .as_mut()
                    .expect("stdin is piped")
                    .write_all(bash_payload(command).as_bytes())?;
                child.wait_with_output()
            })
            .expect("the binary runs"),
    )
}

/// The hatch these four rows actually take, which is the ENGINE'S.
///
/// # The docs said otherwise and the docs were wrong (found by this port)
///
/// `.claude/rules/toolchain.md` claimed `BATTEN_GH_GUARD_BYPASS` was "the
/// `bypass_env` these rows DECLARE rather than the engine's global hatch". It is
/// not: `batten.toml:273` says in as many words that these four "WOULD DECLARE
/// `bypass_env = "BATTEN_GH_GUARD_BYPASS"` AND DO NOT YET", deferred to
/// CLOUD-1027 because adding the key reads to `config-lint` as
/// `rule-predicate-changed` and needs a groomed `Weakens:` clause first — so
/// "until that row is groomed, these four take the general `BATTEN_HOOK_BYPASS`
/// like every other row."
///
/// The tree's decision is deliberate and documented; the rules file had drifted
/// from it. That is corrected in the same change rather than carried forward, and
/// the drift is reported rather than folded in — `rules-drift` gates values
/// `.claude/rules/*.md` restates, and it did not catch this one.
///
/// **So the shell's own `BATTEN_GH_GUARD_BYPASS` arm is NOT conserved, and that
/// is not a loss this change causes.** `mise-tasks/gh-guard.sh:16` honoured the
/// variable, but nothing has invoked that program since CLOUD-312 made
/// `PreToolUse` one entry — so the variable has been inert for that whole span
/// and this deletion removes the dead code that still appeared to offer it.
#[test]
fn the_engines_hatch_suppresses_the_lifecycle() {
    let out = decision_with_env("gh pr merge 63", "BATTEN_HOOK_BYPASS", "1");
    assert!(
        !out.contains("\"deny\""),
        "the engine's hatch must suppress a mediated refusal\n{out}"
    );
}

/// And the row-specific variable does NOT, because no row declares it.
///
/// The anti-vacuity mirror for the case above: without it, a run where BOTH
/// variables were ignored would pass the first assertion for the wrong reason.
#[test]
fn the_undeclared_row_bypass_does_not_suppress() {
    let out = decision_with_env("gh pr merge 63", "BATTEN_GH_GUARD_BYPASS", "1");
    assert!(
        out.contains("gh-pr-merge"),
        "no row declares BATTEN_GH_GUARD_BYPASS, so it must not suppress this refusal \
         (batten.toml:273, deferred to CLOUD-1027)\n{out}"
    );
}
