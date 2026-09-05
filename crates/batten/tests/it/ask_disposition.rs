//! `severity = "ask"` is a third terminal state on the mediated boundary
//! (CLOUD-340).
//!
//! # What was actually missing
//!
//! `Decision::Ask`, `Capability::Ask` and `encode_ask` all shipped with
//! CLOUD-45. The degradation was decided, the capability table was consulted,
//! and the encoder had its own cases. What did not exist was a **producer**:
//! `Decision::Ask(` appeared only in `match` arms, never in a constructor, so a
//! consumer had no vocabulary to reach any of it with — and every exhaustive
//! match over the enum reported green throughout. That is the dead-vocabulary
//! shape `.claude/rules/policy-modules.md` records one layer up, reached by a
//! different route.
//!
//! So the load-bearing case here is
//! [`an_ask_row_renders_the_escalation_on_a_capable_host`], and it is
//! **shown able to fail** in the strongest available sense: against the
//! unmodified binary the config below did not parse at all, and with the
//! severity token alone it exited `2` with a deny body.
//!
//! # The two hosts are the whole degradation clause
//!
//! `claude-code` declares `ask` enforced on `PreToolUse`; `exit-code` declares
//! it nowhere. The pair is what pins CLOUD-45's asymmetry: an unreachable
//! escalation becomes the **refusal**, carrying the same text, and never an
//! allow. "Check with a human" degrading to "go ahead" is the one direction that
//! inverts the policy a consumer wrote.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr, stdout};

/// The command the row below selects.
const ASKED: &str = "gh pr merge 42";
/// The row's `reason`, which is the whole of what reaches the person asked.
const REASON: &str = "land through mise run land so main stays fast-forward";

/// A repository whose only mediated row carries `severity`.
///
/// `glob` is deliberately absent: a `shape` row reads the command line rather
/// than the tree, and declaring one is refused at load. A first draft carried it
/// and every case below failed on that refusal instead of on its own subject —
/// the premise-before-conclusion shape `.claude/rules/rust.md` names.
fn fixture(name: &str, severity: &str, reason: Option<&str>) -> PathBuf {
    let reason = reason.map_or_else(String::new, |it| format!("reason = \"{it}\"\n"));
    Fixture::new(name)
        .config(&format!(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"land-through-the-loop\"\n\
             kind = \"shape\"\n\
             scope = \"mediated_call\"\n\
             severity = \"{severity}\"\n\
             pattern = \"gh pr merge\"\n\
             {reason}"
        ))
        .git()
        .base_commit()
        .build()
}

/// The same severity on a genuinely TREE-scoped row, which is the other half of
/// the scope clause: `forbid` over a glob is what a repository walk decides, and
/// it is where `ask` has no caller to hand the decision to.
fn tree_fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"land-through-the-loop\"\n\
             kind = \"forbid\"\n\
             scope = \"tree\"\n\
             severity = \"ask\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n",
        )
        .git()
        .base_commit()
        .build()
}

/// The mediated fixture in its ordinary shape: `ask`, mediated, with a reason.
fn asking(name: &str) -> PathBuf {
    fixture(name, "ask", Some(REASON))
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

/// Adjudicate `command` in `dir` as `harness` sees it.
fn adjudicate(dir: &Path, harness: &str, command: &str) -> (Option<i32>, String, String) {
    let out = run_with_stdin(
        dir,
        &["adjudicate", "--harness", harness],
        &payload(command),
    );
    (out.status.code(), stdout(&out), stderr(&out))
}

/// THE HEADLINE. A capable host is handed the escalation, and the call is
/// neither allowed nor refused.
///
/// Exit `0` **with a body** is deliberately not the same thing as an allow, and
/// asserting the body is what tells them apart: §7's table has no third code, so
/// the exit status alone cannot carry this verdict and a case reading only the
/// status would pass over a plain allow.
#[test]
fn an_ask_row_renders_the_escalation_on_a_capable_host() {
    let dir = asking("ask-capable");
    let (code, body, cause) = adjudicate(&dir, "claude-code", ASKED);
    assert_eq!(
        code,
        Some(0),
        "an answered escalation is exit 0 with a body\n{cause}"
    );
    let json: serde_json::Value =
        serde_json::from_str(body.trim()).expect("the host's verdict envelope is JSON");
    let hook_output = &json["hookSpecificOutput"];
    assert_eq!(
        hook_output["permissionDecision"], "ask",
        "the verdict must be the escalation rather than a deny: {body}"
    );
    let rendered = hook_output["permissionDecisionReason"]
        .as_str()
        .expect("an escalation carries what is being asked");
    assert!(
        rendered.contains(REASON),
        "the row's reason is the whole of what a person reads: {rendered}"
    );
    assert!(
        rendered.contains("land-through-the-loop"),
        "…beside the row that raised it: {rendered}"
    );
}

/// THE DEGRADATION, and the direction it must fail in.
///
/// `exit-code` declares no reachable ask surface, so the same row on the same
/// command becomes a refusal carrying the same explanation. The `Some(2)` half
/// is CLOUD-45's contract; the "never 0" half is the one that matters, because
/// an escalation silently becoming an allow is a policy inversion nobody sees.
#[test]
fn an_incapable_host_gets_the_refusal_and_never_an_allow() {
    let dir = asking("ask-incapable");
    let (code, body, cause) = adjudicate(&dir, "exit-code", ASKED);
    assert_eq!(
        code,
        Some(2),
        "an unanswerable escalation is the policy verdict, not an allow\n{cause}"
    );
    assert!(
        cause.contains(REASON),
        "and it carries the same explanation the escalation would have\n{cause}"
    );
    assert_eq!(body, "", "the verdict channel is stderr on this harness");
}

/// THE ANTI-VACUITY HALF. Without it, "escalate every mediated call" passes both
/// cases above, and the row would hand a human every command a session runs.
#[test]
fn a_command_the_row_does_not_select_is_untouched() {
    let dir = asking("ask-unselected");
    for allowed in ["gh pr view 42", "git status", "mise run verify"] {
        let (code, body, cause) = adjudicate(&dir, "claude-code", allowed);
        assert_eq!(code, Some(0), "must proceed: {allowed}\n{cause}");
        assert!(
            !body.contains("\"ask\""),
            "…and with nothing to escalate: {allowed}\n{body}"
        );
    }
}

/// A `deny` row is unmoved by this change, which is what keeps the new variant
/// from being a rename of the old one.
///
/// **THE EXIT CODE DOES NOT DISCRIMINATE HERE, AND THAT IS THE POINT.** On a
/// host that takes its verdict from the body, a deny is exit `0` with
/// `"deny"` in it exactly as an escalation is exit `0` with `"ask"` — the
/// status says the hook ran, not what it decided. So the two dispositions are
/// told apart by the token, and a case reading the status alone would pass over
/// either one. `exit-code` is where the status carries the verdict, and
/// [`the_exit_code_table_gained_no_third_verdict`] is where that is pinned.
#[test]
fn a_deny_row_still_denies_on_the_capable_host() {
    let dir = fixture("ask-deny-unmoved", "deny", Some(REASON));
    let (code, body, cause) = adjudicate(&dir, "claude-code", ASKED);
    assert_eq!(
        code,
        Some(0),
        "the body carries this host's verdict\n{cause}"
    );
    let json: serde_json::Value =
        serde_json::from_str(body.trim()).expect("the host's verdict envelope is JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "deny",
        "a `deny` row must still refuse rather than escalate: {body}"
    );
    // And the same row on the host that answers in the status is the ordinary
    // policy verdict, unchanged by the new variant existing.
    assert_eq!(adjudicate(&dir, "exit-code", ASKED).0, Some(2));
}

/// `ask` OUTSIDE THE MEDIATED SCOPE IS A CONFIG FAULT, exit `1`.
///
/// A repository walk answers to whoever ran it: there is no caller to hand the
/// decision to and no call to hold open. Rendering it as a deny would be a
/// downgrade nobody wrote down, so it is refused at load with the reason.
#[test]
fn ask_on_a_tree_rule_is_a_usage_error() {
    let dir = tree_fixture("ask-tree-scope");
    let out = common::batten()
        .args(["check"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a config fault is exit 1, never a silent downgrade"
    );
    let cause = stderr(&out);
    assert!(
        cause.contains("land-through-the-loop") && cause.contains("ask"),
        "the refusal must name the row and the token: {cause}"
    );
}

/// AN ESCALATION WITH NO REASON IS UNANSWERABLE, so it is refused at load.
///
/// A deny that reads "denied by rule 7" is poor and the reader has `explain`,
/// the store and the surrounding output. An escalation reaches a person as the
/// entire explanation, with none of that around it.
#[test]
fn ask_without_a_reason_is_a_usage_error() {
    let dir = fixture("ask-no-reason", "ask", None);
    let out = common::batten()
        .args(["check"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1), "exit 1, at load");
    let cause = stderr(&out);
    assert!(
        cause.contains("reason"),
        "the refusal must name the missing column: {cause}"
    );
}

/// THE KIND AXIS, and it is here because review found the first draft wrong on it.
///
/// `severity` is a column on the ROW, so a `pipeline` row declaring `ask` means
/// exactly what a `shape` row declaring it means. The first version of
/// `hook::disposed` was called from the two shape sites only, so this row loaded
/// clean and hard-denied — the config saying ask while the runtime blocked with
/// no route, which is the same downgrade `validate_ask_disposition` refuses one
/// axis over.
///
/// SHOWN ABLE TO FAIL: measured against that version, this case saw
/// `permissionDecision` `"deny"`.
#[test]
fn the_disposition_is_the_rows_rather_than_the_kinds() {
    let dir = Fixture::new("ask-pipeline-kind")
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"read-the-verdict\"\n\
             kind = \"pipeline\"\n\
             scope = \"mediated_call\"\n\
             severity = \"ask\"\n\
             filters = [\"tail\"]\n\
             reason = \"read the status from the harness rather than a pager\"\n\
             verdict = [{ program = \"mise\", subcommands = [\"run\"] }]\n",
        )
        .git()
        .base_commit()
        .build();
    let (code, body, cause) = adjudicate(&dir, "claude-code", "mise run verify | tail -5");
    assert_eq!(
        code,
        Some(0),
        "the body carries this host's verdict\n{cause}"
    );
    let json: serde_json::Value =
        serde_json::from_str(body.trim()).expect("the host's verdict envelope is JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "ask",
        "a non-shape row's `ask` must escalate too: {body}"
    );
    // And the degradation still holds on the kind axis, so an incapable host gets
    // the refusal rather than the silent allow.
    assert_eq!(
        adjudicate(&dir, "exit-code", "mise run verify | tail -5").0,
        Some(2)
    );
}

/// §7's table is unchanged: the new disposition bought no third exit code, on
/// either host. Asserted rather than assumed, because a variant that reached the
/// boundary and invented a code there would satisfy every case above.
#[test]
fn the_exit_code_table_gained_no_third_verdict() {
    let dir = asking("ask-exit-table");
    for (harness, expected) in [("claude-code", 0), ("exit-code", 2)] {
        let (code, _, cause) = adjudicate(&dir, harness, ASKED);
        assert_eq!(
            code,
            Some(expected),
            "{harness} must answer within the table\n{cause}"
        );
    }
}
