//! The waiver surface end to end (CLOUD-208).
//!
//! The unit tests in `src/waiver.rs` pin the predicate; these pin the things only
//! the compiled binary can answer — which channel each half of the answer lands
//! on, and what the exit code is. Both matter, and for different reasons:
//!
//! * **The exit code is the whole interface an agent has.** A waiver that
//!   suppressed the report but left the run at `2` would suppress nothing an agent
//!   can perceive; one that flipped the code while still printing the finding
//!   would tell a human the opposite of what it told the harness.
//! * **The audit line must be un-hideable from the data channel.** A waiver is a
//!   suppression, so the record of it is the compensating control — and it is on
//!   stderr precisely so it cannot corrupt a `-J` document.
//!
//! Kept out of `tests/cli.rs` deliberately, following `fail_on_warning.rs`: that
//! file is the exit-code and output-contract suite for the surface as a whole, and
//! this one's subject is one feature's behaviour.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{Fixture, StateHome, batten, run_with_stdin, scratch, stderr};

/// A `forbid` rule at `deny` over the fixture's one Rust file.
const RULE: &str = "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
                    pattern = \"TODO\"\nseverity = \"deny\"\n";

/// A waiver of that rule, expiring on `expires`.
fn waiver(expires: &str) -> String {
    format!(
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"tracked in CLOUD-1\"\nexpires = \"{expires}\"\n"
    )
}

/// A date comfortably in the future, and one comfortably past. Written as
/// constants rather than derived from the clock: the point of the design is that
/// the date is an input, and a test that computed "today ± a year" would be
/// asserting against the same clock it is testing.
const LIVE: &str = "2099-12-31";
const LAPSED: &str = "2000-01-01";

/// A `shape` rule at `deny` over one mediated command (CLOUD-610).
///
/// The mediated channel's counterpart to [`RULE`]: it reads no `glob`, because it
/// matches a command line rather than a file, and it is the row the cases at the
/// end of this file waive.
const SHAPE_RULE: &str = "\n[[rule]]\nid = \"no-merge\"\nkind = \"shape\"\n\
                          scope = \"mediated_call\"\npattern = \"gh pr merge\"\n\
                          reason = \"land by fast-forward\"\nseverity = \"deny\"\n";

/// A waiver of that row, expiring on `expires`.
fn shape_waiver(expires: &str) -> String {
    format!(
        "\n[[waiver]]\nrule = \"no-merge\"\nreason = \"tracked in CLOUD-1\"\nexpires = \"{expires}\"\n"
    )
}

/// A Claude Code `PreToolUse` envelope carrying a shell command.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

/// Adjudicate one command in `repo`, on the adapter whose channel IS the code.
fn adjudicate(repo: &std::path::Path, command: &str) -> (i32, String) {
    let output = run_with_stdin(
        repo,
        &["hook", "--harness", "exit-code"],
        &bash_payload(command),
    );
    (output.status.code().expect("exit code"), stderr(&output))
}

/// A fixture repo whose `batten.toml` is `version = 1` plus `extra`, containing
/// one file that trips the rule.
fn repo(name: &str, extra: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(&format!("version = 1\n{extra}"))
        .file("lib.rs", "fine\nTODO fix this\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

fn run(repo: &std::path::Path, home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let output = batten()
        .state_home(home)
        .args(args)
        .current_dir(repo)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_LOG_LEVEL")
        .output()
        .expect("run batten");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_a_waiver_the_rule_denies() {
    // The baseline the rest of this file is a delta from. Without it, a bug that
    // stopped the rule firing at all would make every assertion below pass.
    let (repo, home) = repo("waiver-baseline", RULE);
    let (code, stdout, _) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "a deny finding is a policy verdict");
    assert!(stdout.contains("lib.rs:2 no-todo"), "got: {stdout}");
}

// subsumed: "an exempted entry passes only through a waiver carrying a reason" crates/batten/tests/it/waivers.rs that case was about the waiver SURFACE rather than about `no-source-built-tool` — a live waiver clears the verdict and leaves a pointer-only audit line on stderr — and this drives the compiled binary over a `forbid` row to assert exactly that (CLOUD-1137)
#[test]
fn a_live_waiver_clears_the_verdict_and_audits_on_stderr() {
    let (repo, home) = repo("waiver-live", &format!("{RULE}{}", waiver(LIVE)));
    let (code, stdout, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 0, "a waived finding does not block: {stderr}");
    assert!(
        !stdout.contains("no-todo"),
        "and is absent from the answer channel: {stdout}"
    );
    // The compensating control: the suppression is on the record.
    assert!(stderr.contains("waived lib.rs:2 no-todo"), "got: {stderr}");
    assert!(
        stderr.contains(&format!("expires {LIVE}")),
        "the audit line names the expiry it relied on: {stderr}"
    );
    assert!(
        !stderr.contains("TODO fix this"),
        "pointer-only: the audit line must never carry the matched line"
    );
    assert!(
        !stderr.contains("tracked in CLOUD-1"),
        "nor the justification, which is config content and not a pointer"
    );
}

// subsumed: "an exemption that has lapsed stops exempting, with nobody acting" crates/batten/tests/it/waivers.rs the property that makes a waiver an exemption rather than a deletion is generic over which row it names, and this asserts it on the same shape (CLOUD-1137)
#[test]
fn a_lapsed_waiver_leaves_the_finding_and_the_verdict_alone() {
    // The property the whole design rests on, at the surface a caller sees:
    // nobody had to act for this waiver to stop working.
    let (repo, home) = repo("waiver-lapsed", &format!("{RULE}{}", waiver(LAPSED)));
    let (code, stdout, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "the rule fires again");
    assert!(stdout.contains("lib.rs:2 no-todo"), "got: {stdout}");
    assert!(
        !stderr.contains("waived"),
        "and nothing is audited as waived: {stderr}"
    );
}

#[test]
fn the_data_channel_never_mentions_the_waived_finding_or_the_waiver() {
    // A waiver is not a fourth severity, so there is no severity token for it and
    // no waived entry to find. A consumer parsing `-J` sees the run it would have
    // seen had the finding never existed — plus the audit line, on the other
    // channel, where it cannot corrupt the document.
    let (repo, home) = repo("waiver-json", &format!("{RULE}{}", waiver(LIVE)));
    let (code, stdout, stderr) = run(&repo, &home, &["check", "-J"]);
    assert_eq!(code, 0);
    let document: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(
        document["findings"].as_array().map(Vec::len),
        Some(0),
        "got: {stdout}"
    );
    for token in ["waived", "waiver", "expires"] {
        assert!(
            !stdout.contains(token),
            "{token:?} must not appear on the data channel: {stdout}"
        );
    }
    assert!(stderr.contains("waived"), "it is on stderr instead");
}

#[test]
fn the_audit_line_is_ladder_gated_but_the_verdict_is_not() {
    // The audit line is chatter about a run, so `--silent` may drop it; that is
    // what makes it a §3 message rather than output. The exit code cannot be
    // silenced, which is why the code is where the meaning lives.
    let (repo, home) = repo("waiver-ladder", &format!("{RULE}{}", waiver(LIVE)));
    let (code, _, stderr) = run(&repo, &home, &["--silent", "check"]);
    assert_eq!(code, 0, "the verdict is unchanged by the rung");
    assert!(
        !stderr.contains("waived"),
        "a suppressed rung writes nothing: {stderr}"
    );
}

#[test]
fn both_verbs_pass_through_the_one_filter() {
    // `check` and `enforce` differ only in which rule kinds they admit, so a
    // waiver applied in one and not the other would be the drift the single funnel
    // exists to prevent.
    let (repo, home) = repo("waiver-enforce", &format!("{RULE}{}", waiver(LIVE)));
    let (code, stdout, _) = run(&repo, &home, &["enforce"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains("no-todo"), "got: {stdout}");
}

#[test]
fn two_runs_over_one_config_and_one_date_are_byte_identical() {
    // §6 with a clock in the design: the date is an input, so two runs on the
    // same day agree on every byte of both channels.
    let (repo, home) = repo("waiver-stable", &format!("{RULE}{}", waiver(LIVE)));
    let first = run(&repo, &home, &["check"]);
    let second = run(&repo, &home, &["check"]);
    assert_eq!(first, second);
}

// subsumed: "the exemption is scoped to what it names: a second violation still blocks" crates/batten/tests/it/waivers.rs the scoping half is here and the channel half — the waived finding absent from the ANSWER channel the exit code was computed from — is `the_data_channel_never_mentions_the_waived_finding_or_the_waiver` just above (CLOUD-1137)
#[test]
fn a_narrowed_waiver_leaves_the_rest_of_the_rule_gating() {
    let narrowed = format!(
        "\n[[waiver]]\nrule = \"no-todo\"\nreason = \"vendored\"\nexpires = \"{LIVE}\"\n\
         path = \"vendor/**\"\n"
    );
    let root = scratch("waiver-narrowed");
    let repo = Fixture::at(root.join("repo"))
        .config(&format!("version = 1\n{RULE}{narrowed}"))
        .file("vendor/dep.rs", "TODO upstream\n")
        .file("src/mine.rs", "TODO here\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    let (code, stdout, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "the un-waived finding still blocks");
    assert!(stdout.contains("src/mine.rs:1 no-todo"), "got: {stdout}");
    assert!(!stdout.contains("vendor/dep.rs"), "got: {stdout}");
    assert!(stderr.contains("waived vendor/dep.rs:1"), "got: {stderr}");
}

// subsumed: "an exemption with no reason is refused as bad input, not applied" crates/batten/tests/it/waivers.rs exit 1 is a statement about the invocation and never a policy verdict, which is what this asserts, generic over the row waived (CLOUD-1137)
#[test]
fn a_waiver_with_no_reason_is_a_usage_error_not_a_verdict() {
    // Refused at load, and as bad *input* — exit 1. Reporting it as 2 would tell
    // a mediating harness that policy denied something.
    let (repo, home) = repo(
        "waiver-no-reason",
        &format!("{RULE}\n[[waiver]]\nrule = \"no-todo\"\nreason = \"\"\nexpires = \"{LIVE}\"\n"),
    );
    let (code, _, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 1, "got: {stderr}");
    assert!(stderr.contains("reason is required"), "got: {stderr}");
}

#[test]
fn an_expiry_that_is_not_a_date_is_refused_rather_than_ignored() {
    let (repo, home) = repo(
        "waiver-bad-date",
        &format!(
            "{RULE}\n[[waiver]]\nrule = \"no-todo\"\nreason = \"r\"\nexpires = \"whenever\"\n"
        ),
    );
    let (code, _, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 1, "got: {stderr}");
    assert!(stderr.contains("expected YYYY-MM-DD"), "got: {stderr}");
}

#[test]
fn config_lint_names_the_two_dead_waiver_shapes() {
    let dead = format!("\n[[waiver]]\nrule = \"typo\"\nreason = \"r\"\nexpires = \"{LAPSED}\"\n");
    let (repo, home) = repo("waiver-lint", &format!("{RULE}{dead}"));
    let (code, stdout, _) = run(&repo, &home, &["config", "lint"]);
    assert_eq!(code, 2, "any smell is a policy verdict: {stdout}");
    assert!(stdout.contains("waiver-names-no-rule"), "got: {stdout}");
    assert!(stdout.contains("waiver-expired"), "got: {stdout}");
    assert!(
        !stdout.contains("\"r\""),
        "the pointer must not carry the justification: {stdout}"
    );
}

#[test]
fn config_show_attributes_the_waiver_table_to_its_layer() {
    // Every emitted key carries a source, and a new table that skipped
    // attribution would make `config show` fail rather than under-report.
    let (repo, home) = repo("waiver-show", &format!("{RULE}{}", waiver(LIVE)));
    let (code, stdout, stderr) = run(&repo, &home, &["config", "show", "-J"]);
    assert_eq!(code, 0, "got: {stderr}");
    let document: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(
        document["waiver"]["source"].as_str(),
        Some("repo-config"),
        "got: {stdout}"
    );
}

// --- the mediation channel's hatch (CLOUD-610) --------------------------------
//
// CLOUD-606 decided that a mediated call gets the same durable, lapsing exemption
// a finding does, with the expiry resolved at the boundary so `hook::adjudicate`
// stays clock-free. These four are that verdict at the surface a caller sees. The
// unit tests in `src/hook.rs` pin the predicate; only the compiled binary can
// answer which channel the audit lands on and what the exit code is.

#[test]
fn without_a_waiver_the_mediated_row_denies() {
    // The baseline the three below are a delta from, for the reason the tree
    // side has one: a bug that stopped the shape row firing would make every
    // suppression assertion pass for the wrong reason.
    let (repo, _home) = repo("waiver-hook-baseline", SHAPE_RULE);
    let (code, err) = adjudicate(&repo, "gh pr merge 42");
    assert_eq!(code, 2, "a mediated deny is the policy verdict: {err}");
    assert!(err.contains("no-merge"), "got: {err}");
}

#[test]
fn a_live_waiver_lets_the_mediated_call_through_and_audits_it() {
    let (repo, _home) = repo(
        "waiver-hook-live",
        &format!("{SHAPE_RULE}{}", shape_waiver(LIVE)),
    );
    let (code, err) = adjudicate(&repo, "gh pr merge 42");
    assert_eq!(code, 0, "the call proceeds: {err}");
    // The compensating control, in the tree side's shape minus the pointer a
    // mediated call does not have.
    assert!(
        err.contains(&format!("waived no-merge (expires {LIVE})")),
        "got: {err}"
    );
    // Pointer-only (non-negotiable 4): never the command, never the reason.
    assert!(!err.contains("gh pr merge 42"), "got: {err}");
    assert!(!err.contains("tracked in CLOUD-1"), "got: {err}");
}

#[test]
fn a_lapsed_waiver_leaves_the_mediated_deny_alone() {
    // THE PROPERTY THE WHOLE DESIGN RESTS ON, at the surface a caller sees:
    // nobody had to act for this waiver to stop working, and the boundary is
    // where the date was read.
    let (repo, _home) = repo(
        "waiver-hook-lapsed",
        &format!("{SHAPE_RULE}{}", shape_waiver(LAPSED)),
    );
    let (code, err) = adjudicate(&repo, "gh pr merge 42");
    assert_eq!(code, 2, "the row refuses again: {err}");
    assert!(!err.contains("waived"), "and nothing is audited: {err}");
}

#[test]
fn a_waived_row_does_not_waive_the_rest_of_the_policy() {
    // The half that keeps the hatch narrow, and the mediated counterpart of
    // `a_narrowed_waiver_leaves_the_rest_of_the_rule_gating`: suppression is by
    // rule id, so a second row still refuses.
    // A pattern of non-flag words only: a shape row matches the effective program
    // plus the adjacent words that are not flags, so `git push --force` would
    // never fire and this case would pass for the wrong reason.
    let second = "\n[[rule]]\nid = \"no-run-watch\"\nkind = \"shape\"\n\
                  scope = \"mediated_call\"\npattern = \"gh run watch\"\n\
                  reason = \"wait through ci-wait\"\nseverity = \"deny\"\n";
    let (repo, _home) = repo(
        "waiver-hook-narrow",
        &format!("{SHAPE_RULE}{second}{}", shape_waiver(LIVE)),
    );
    assert_eq!(adjudicate(&repo, "gh pr merge 42").0, 0);
    let (code, err) = adjudicate(&repo, "gh run watch 123");
    assert_eq!(code, 2, "the unwaived row still refuses: {err}");
    assert!(err.contains("no-run-watch"), "got: {err}");
}
