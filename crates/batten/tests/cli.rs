//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
}

/// Run `batten hook --harness <harness>` with `payload` piped to stdin.
///
/// The ambient bypass var is removed so a developer's shell can never flip a
/// deny case; the `bypass` flag sets it explicitly for the case that wants it.
fn run_hook(harness: &str, payload: &str, bypass: bool) -> Output {
    let mut command = batten();
    command
        .args(["hook", "--harness", harness])
        .env_remove("BATTEN_GH_GUARD_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if bypass {
        command.env("BATTEN_GH_GUARD_BYPASS", "1");
    }
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

/// A Claude Code `PreToolUse` payload wrapping one Bash command.
fn claude_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// Create a fresh temp directory under the test target dir containing a
/// `batten.toml` with `contents`, and return its path so a command can run there.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::create_dir_all(&dir).expect("create temp repo dir");
    fs::write(dir.join("batten.toml"), contents).expect("write batten.toml");
    dir
}

/// The exit-code contract (§7), asserted as one table over the compiled binary.
///
/// The contract is CLI-wide, so each command's invocations are pinned together
/// here rather than one assertion per test: a regression in any command's code
/// surfaces in this single place. Each case runs in its own fresh directory,
/// with a `batten.toml` written only when `config` is `Some`, so the missing-file
/// path is exercised without leaking config between cases.
///
/// Coverage spans the codes reachable today — `Success` (0) for well-formed runs
/// and `Usage` (1) for malformed input or bad config, including the two clap
/// renders `--help` (an answer, 0) and an unknown flag (1). `Violation` (2) is
/// reached by `check` when a rule fires; because that needs source files placed
/// beside the config, it is exercised in the dedicated `check_*` tests below
/// rather than this config-only table, and by `hook` in the `hook_*` tests —
/// the same code, since §7 has no per-verb exception. `Internal` (3) has no
/// command that reaches it at this stage: its numeric contract is pinned in the
/// `exit` unit tests.
#[test]
fn exit_code_contract() {
    struct Case {
        /// What the invocation exercises, surfaced on assertion failure.
        name: &'static str,
        /// Arguments passed to `batten`.
        args: &'static [&'static str],
        /// `batten.toml` contents to place in the run directory, if any.
        config: Option<&'static str>,
        /// The exit code the invocation must return.
        expected: i32,
    }

    let cases = [
        Case {
            name: "no subcommand → usage (subcommand listing offered)",
            args: &[],
            config: None,
            expected: 1,
        },
        Case {
            name: "--help → success (help is an answer, not clap's exit 2)",
            args: &["--help"],
            config: None,
            expected: 0,
        },
        Case {
            name: "--version → success",
            args: &["--version"],
            config: None,
            expected: 0,
        },
        Case {
            name: "spec → success",
            args: &["spec"],
            config: None,
            expected: 0,
        },
        Case {
            name: "config show, valid config → success",
            args: &["config", "show"],
            config: Some("version = 1\n"),
            expected: 0,
        },
        Case {
            name: "unknown flag → usage",
            args: &["--nope"],
            config: None,
            expected: 1,
        },
        Case {
            name: "config show, unsupported version → usage",
            args: &["config", "show"],
            config: Some("version = 2\n"),
            expected: 1,
        },
        Case {
            name: "config show, unknown key → usage",
            args: &["config", "show"],
            config: Some("version = 1\nbogus = true\n"),
            expected: 1,
        },
        Case {
            name: "config show, missing config → usage",
            args: &["config", "show"],
            config: None,
            expected: 1,
        },
        Case {
            name: "config show, rule omitting severity → usage (no implicit fallback)",
            args: &["config", "show"],
            config: Some(
                "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\n",
            ),
            expected: 1,
        },
        Case {
            name: "config show, severity token in the scope key → usage (scope ≠ severity)",
            args: &["config", "show"],
            config: Some(
                "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\nscope = \"deny\"\n",
            ),
            expected: 1,
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("exit-case-{index}"));
        fs::create_dir_all(&dir).expect("create case dir");
        let config_path = dir.join("batten.toml");
        match case.config {
            Some(contents) => fs::write(&config_path, contents).expect("write batten.toml"),
            // A stale file from a prior run would mask the missing-config path.
            None => {
                let _ = fs::remove_file(&config_path);
            }
        }
        let status = batten()
            .args(case.args)
            .current_dir(&dir)
            .status()
            .expect("run batten");
        assert_eq!(status.code(), Some(case.expected), "case: {}", case.name);
    }
}

#[test]
fn check_clean_repo_exits_success() {
    let dir = repo_with_config(
        "check-clean",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "all clear\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "clean run reports nothing");
}

#[test]
fn check_violation_exits_two_with_pointer_only_output() {
    let dir = repo_with_config(
        "check-violation",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "fine\nTODO fix this\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(2), "a finding is a violation");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Pointer only: the location and rule id, never the offending line text.
    assert_eq!(stdout, "lib.rs:2 no-todo\n");
    assert!(
        !stdout.contains("fix this"),
        "output must not leak the bytes"
    );
}

#[test]
fn check_output_is_byte_stable_across_runs() {
    let dir = repo_with_config(
        "check-stable",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("b.rs"), "TODO\n").expect("write b");
    fs::write(dir.join("a.rs"), "TODO\n").expect("write a");
    let first = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run 1");
    let second = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run 2");
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn enforce_runs_the_same_static_rules_as_check() {
    // The effect split (CLOUD-170) changes which kinds each verb admits, never
    // the reported result for an admissible kind.
    let dir = repo_with_config(
        "enforce-parity",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "fine\nTODO fix\n").expect("write source");
    let check = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run check");
    let enforce = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run enforce");
    assert_eq!(check.status.code(), Some(2));
    assert_eq!(enforce.status.code(), Some(2));
    assert_eq!(check.stdout, enforce.stdout);
}

#[test]
fn spec_marks_enforce_unclassified_and_check_read() {
    // The emitted spec is what a mediator reads (§11), so the split must be
    // visible there — not only in the internal table.
    let output = batten().arg("spec").output().expect("run batten spec");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("spec stdout is valid JSON");
    let subs = value["subcommands"].as_array().expect("subcommands array");
    let effect_of = |path: &str| -> String {
        subs.iter()
            .find(|node| node["path"] == path)
            .and_then(|node| node["effect"].as_str())
            .unwrap_or("<missing>")
            .to_owned()
    };
    assert_eq!(effect_of("check"), "read");
    assert_eq!(effect_of("enforce"), "unclassified");
}

/// A `batten.toml` carrying one command rule that always fails.
const COMMAND_RULE_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"false\"\nseverity = \"deny\"\nscope = \"tree\"\n";

#[test]
fn check_refuses_a_command_rule_rather_than_skipping_it() {
    // The CLOUD-170 split, end to end: the read-effect verb must refuse (exit
    // 1, a usage error) — never exit 0 having quietly skipped the gate.
    let dir = repo_with_config("cmd-check-refuses", COMMAND_RULE_CONFIG);
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(1),
        "check must refuse a spawning rule kind"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("batten enforce"),
        "the refusal must point at the verb that runs it, got: {stderr}"
    );
}

#[test]
fn enforce_runs_a_command_rule_and_maps_its_exit_code() {
    let dir = repo_with_config("cmd-enforce-runs", COMMAND_RULE_CONFIG);
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a non-zero command exit is a violation"
    );
    // Rule-scoped pointer: no invented line number, and never the command output.
    assert_eq!(String::from_utf8_lossy(&output.stdout), "**/*.rs dyn\n");
}

#[test]
fn enforce_passes_when_the_command_exits_zero() {
    let dir = repo_with_config(
        "cmd-enforce-pass",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"true\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn enforce_missing_binary_is_a_usage_error() {
    let dir = repo_with_config(
        "cmd-enforce-missing",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"definitely-not-a-real-binary-xyz\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a command that cannot run is a config error, never a silent pass"
    );
}

#[test]
fn command_rule_with_no_glob_match_is_skipped_without_spawning() {
    // The glob gates first (§4): the missing binary would be a usage error if
    // it were ever reached, so exit 0 proves nothing spawned.
    let dir = repo_with_config(
        "cmd-no-match",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"definitely-not-a-real-binary-xyz\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("notes.txt"), "x\n").expect("write source");
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn check_unknown_rule_key_is_a_usage_error() {
    let dir = repo_with_config(
        "check-bad-rule",
        "version = 1\n\n[[rule]]\nid = \"x\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"y\"\nseverity = \"deny\"\nbogus = true\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unknown rule key is usage"
    );
}

#[test]
fn version_flag_succeeds() {
    let output = batten()
        .arg("--version")
        .output()
        .expect("run batten --version");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("batten"));
}

#[test]
fn spec_emits_parseable_json_on_stdout() {
    let output = batten().arg("spec").output().expect("run batten spec");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("spec stdout is valid JSON");
    assert_eq!(value["path"], "batten");
    // The surface is data: `spec` describes itself, with its effect merged in.
    let subs = value["subcommands"].as_array().expect("subcommands array");
    let spec_node = subs
        .iter()
        .find(|node| node["path"] == "spec")
        .expect("spec appears in its own surface");
    assert_eq!(spec_node["effect"], "read");
}

#[test]
fn spec_json_is_byte_stable_across_runs() {
    // §6: identical input yields identical bytes — no timestamps or ordering drift.
    let first = batten().arg("spec").output().expect("run batten spec");
    let second = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn spec_default_format_matches_explicit_json() {
    let bare = batten().arg("spec").output().expect("run batten spec");
    let explicit = batten()
        .args(["spec", "--format", "json"])
        .output()
        .expect("run batten spec --format json");
    assert_eq!(bare.stdout, explicit.stdout);
}

#[test]
fn config_show_prints_the_effective_config() {
    let dir = repo_with_config(
        "config-show-ok",
        "version = 1\nmin_batten_version = \"0.0.0\"\n",
    );
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show stdout is JSON");
    assert_eq!(value["version"], 1);
    assert_eq!(value["min_batten_version"], "0.0.0");
}

/// Write a `batten.local.toml` beside an existing repo config.
fn with_local_config(dir: &std::path::Path, contents: &str) {
    fs::write(dir.join("batten.local.toml"), contents).expect("write batten.local.toml");
}

#[test]
fn config_show_reports_the_layer_that_won_each_key() {
    // §8: `config` prints the effective config *with sources*, so which layer
    // set a key is an answer the tool gives, not one a reader reconstructs.
    let dir = repo_with_config("config-sources", "version = 1\nstrictness = \"standard\"\n");
    with_local_config(&dir, "version = 1\nstrictness = \"strict\"\n");
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(value["strictness"], "strict");
    assert_eq!(value["sources"]["strictness"], "local-file");
}

#[test]
fn config_precedence_runs_flag_over_env_over_local_over_repo() {
    // The whole §8 chain in one invocation: each layer in turn tightens, and the
    // reported source is always the highest layer that set the value.
    let dir = repo_with_config("config-precedence", "version = 1\n");
    with_local_config(&dir, "version = 1\nstrictness = \"standard\"\n");

    let strictness_of = |args: &[&str], env: Option<&str>| -> (i32, serde_json::Value) {
        let mut command = batten();
        command.args(args).current_dir(&dir);
        match env {
            Some(value) => command.env("BATTEN_STRICTNESS", value),
            // Inherited from the test runner's environment otherwise.
            None => command.env_remove("BATTEN_STRICTNESS"),
        };
        let output = command.output().expect("run batten config show");
        let code = output.status.code().expect("exit code");
        let value = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
        (code, value)
    };

    let (code, local) = strictness_of(&["config", "show"], None);
    assert_eq!(code, 0);
    assert_eq!(local["strictness"], "standard");
    assert_eq!(local["sources"]["strictness"], "local-file");

    let (code, env) = strictness_of(&["config", "show"], Some("strict"));
    assert_eq!(code, 0);
    assert_eq!(env["strictness"], "strict");
    assert_eq!(env["sources"]["strictness"], "env");

    // A flag outranks the env var — here restating the same value, which the
    // clamp accepts and re-attributes to the higher layer.
    let (code, flag) = strictness_of(
        &["--strictness", "strict", "config", "show"],
        Some("strict"),
    );
    assert_eq!(code, 0);
    assert_eq!(flag["sources"]["strictness"], "flag");
}

#[test]
fn a_local_override_that_weakens_a_gate_is_rejected() {
    // The raise-only clamp (§8), end to end: an uncommitted file may tighten
    // policy, never lower it. Exit 1 — bad input, not a silently applied edit.
    let dir = repo_with_config(
        "config-weaken-local",
        "version = 1\nstrictness = \"strict\"\n",
    );
    with_local_config(&dir, "version = 1\nstrictness = \"permissive\"\n");
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("may only tighten"),
        "the refusal must name the rule it enforces, got: {stderr}"
    );
}

#[test]
fn an_env_or_flag_override_that_weakens_a_gate_is_rejected() {
    let dir = repo_with_config(
        "config-weaken-flag",
        "version = 1\nstrictness = \"strict\"\n",
    );
    for (label, args, env) in [
        ("env", vec!["config", "show"], Some("permissive")),
        (
            "flag",
            vec!["--strictness", "permissive", "config", "show"],
            None,
        ),
    ] {
        let mut command = batten();
        command.args(&args).current_dir(&dir);
        match env {
            Some(value) => command.env("BATTEN_STRICTNESS", value),
            None => command.env_remove("BATTEN_STRICTNESS"),
        };
        let output = command.output().expect("run batten config show");
        assert_eq!(
            output.status.code(),
            Some(1),
            "a weakening {label} override must be refused"
        );
    }
}

#[test]
fn a_local_override_may_add_a_rule_but_not_redefine_one() {
    let config = "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n";
    let dir = repo_with_config("config-local-rules", config);
    fs::write(dir.join("lib.rs"), "FIXME later\n").expect("write source");

    // Adding a rule tightens policy, and the added gate really runs.
    with_local_config(
        &dir,
        "version = 1\n\n[[rule]]\nid = \"no-fixme\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"FIXME\"\nseverity = \"deny\"\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(2), "the added rule must fire");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "lib.rs:1 no-fixme\n"
    );

    // Redefining a committed rule could weaken it, so it is refused outright.
    with_local_config(
        &dir,
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"nothing/**\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("may not redefine"),
        "the refusal must name the redefinition"
    );
}

#[test]
fn hook_denies_a_blocked_shape_in_the_harness_channel() {
    // The claude-code adapter answers in the host's JSON decision object with
    // exit 0 — the channel the production shell guards already use. The
    // wrapper form is the load-bearing case: judging the wrapper token instead
    // of the effective program is the bug class CLOUD-181 hardened against.
    let output = run_hook(
        "claude-code",
        &claude_payload("mise exec -- gh pr merge 42"),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "got: {stdout}"
    );
    assert!(
        stdout.contains("mise run land"),
        "the deny must name the redirect"
    );
}

#[test]
fn hook_allows_reads_and_quoted_lookalikes_silently() {
    for command in ["gh pr view 42", "git commit -m \"gh pr merge\""] {
        let output = run_hook("claude-code", &claude_payload(command), false);
        assert_eq!(output.status.code(), Some(0), "command: {command}");
        assert!(
            output.stdout.is_empty(),
            "an allow emits nothing: {command}"
        );
    }
}

#[test]
fn hook_fails_open_on_an_undecodable_payload() {
    // A guard must never be the reason a session cannot proceed: junk on stdin
    // is an allow, not an error.
    let output = run_hook("claude-code", "not json at all", false);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn hook_honours_the_bypass_hatch() {
    let output = run_hook("claude-code", &claude_payload("gh pr merge 42"), true);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn hook_exit_code_harness_denies_with_exit_2() {
    // The one contract, unmodified: 2 is the policy verdict, so a deny needs
    // no translation. The reason goes to stderr — the neutral channel for a
    // host whose only decision vocabulary is an exit status.
    let output = run_hook("exit-code", &claude_payload("gh pr merge 42"), false);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refused"), "got: {stderr}");
    // A verdict is an answer, not a crash. The host hands this text back to the
    // model as the deny reason, so it must not wear the binary's error prefix.
    assert!(
        !stderr.starts_with("batten:"),
        "a deny reason is unprefixed, got: {stderr}"
    );
}

#[test]
fn no_failure_path_can_deny_a_mediated_call() {
    // Fail-open, asserted at the exit code rather than trusted to `run_hook`'s
    // branches: the ways `hook` can fail must all produce a code every harness
    // reads as non-blocking. A `2` from any of these would silently convert a
    // broken guard into one that blocks every tool call it mediates.
    let cases = [
        ("undecodable payload", "not json at all"),
        ("empty stdin", ""),
        ("well-formed JSON, no command", "{}"),
        (
            "wrong-shaped tool_input",
            r#"{"tool_input":{"command":42}}"#,
        ),
    ];
    for harness in ["claude-code", "exit-code"] {
        for (name, payload) in cases {
            let output = run_hook(harness, payload, false);
            assert_ne!(
                output.status.code(),
                Some(2),
                "{harness}: {name} must never deny"
            );
        }
    }
}

#[test]
fn bare_invocation_lists_subcommands() {
    // §2: bare invocation lists subcommands and never performs a default
    // action. clap renders the listing on its error path — stderr, exit 1, a
    // usage error — so a script can never mistake the listing for a successful
    // run's answer, nor a bare invocation for a policy verdict.
    let output = batten().output().expect("run batten");
    assert_eq!(output.status.code(), Some(1));
    let listing = String::from_utf8_lossy(&output.stderr);
    for verb in ["check", "enforce", "config", "spec", "receipt"] {
        assert!(listing.contains(verb), "the listing must name `{verb}`");
    }
    assert!(
        output.stdout.is_empty(),
        "stdout is the answer channel; a bare invocation has no answer"
    );
}

// --- receipts (CLOUD-203) ----------------------------------------------------

/// Run `git` in `dir`, asserting success; returns trimmed stdout.
fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git stdout is UTF-8")
        .trim_end()
        .to_owned()
}

/// A repo fixture for the receipt tests, in the normal PR shape: a committed
/// `batten.toml` as the base commit, `origin/main` pinned to it, and one
/// commit of work on top. Returns `(repo, home)` where `home` isolates the
/// out-of-tree receipt store.
fn receipt_fixture(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    // A stale fixture from a prior run would mask state-dir behaviour.
    let _ = fs::remove_dir_all(&root);
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo).expect("create fixture repo");
    fs::create_dir_all(&home).expect("create fixture home");
    git_in(&repo, &["init", "-q"]);
    git_in(&repo, &["config", "user.email", "t@example.com"]);
    git_in(&repo, &["config", "user.name", "t"]);
    fs::write(repo.join("batten.toml"), "version = 1\n").expect("write policy");
    git_in(&repo, &["add", "batten.toml"]);
    git_in(&repo, &["commit", "-q", "-m", "policy"]);
    git_in(&repo, &["branch", "-M", "main"]);
    let base = git_in(&repo, &["rev-parse", "HEAD"]);
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", &base]);
    git_in(&repo, &["commit", "-q", "--allow-empty", "-m", "work"]);
    (repo, home)
}

/// Run `batten` in `dir` with the receipt store isolated under `home`, and
/// repository discovery fenced to the test tmpdir — so a fixture that forgot
/// `git init` fails loudly instead of resolving the real batten checkout and
/// forging a genuine receipt into its `.git/batten-receipts/`.
fn receipt_cmd(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    batten()
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten receipt")
}

/// `receipt status <check>` → (exit code, stdout).
fn receipt_status(dir: &std::path::Path, home: &std::path::Path, check: &str) -> (i32, String) {
    let output = receipt_cmd(dir, home, &["receipt", "status", check]);
    (
        output.status.code().expect("exit code"),
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
    )
}

#[test]
fn receipt_lifecycle_amend_rebase_and_moved_main_invalidate() {
    let (repo, home) = receipt_fixture("receipt-triple");
    let base = git_in(&repo, &["rev-parse", "origin/main"]);
    let head = git_in(&repo, &["rev-parse", "HEAD"]);

    // Never recorded → missing, and the gate fails (exit 2, a violation).
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 2);
    assert_eq!(line, format!("verify {head} missing\n"));

    // Record is silent on success (§6: a clean run prints nothing).
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(
        record.status.code(),
        Some(0),
        "record failed: {}",
        String::from_utf8_lossy(&record.stderr)
    );
    assert!(record.stdout.is_empty(), "a clean record prints nothing");

    // Valid, and byte-stable across runs (§6).
    let (code, first) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 0);
    assert_eq!(first, format!("verify {head} valid\n"));
    let (_, second) = receipt_status(&repo, &home, "verify");
    assert_eq!(first, second);

    // The grandfathered compat file is exactly what ready-guard parses:
    // `<check>.<head>` under the git dir, content = the recorded main SHA.
    let compat = repo
        .join(".git/batten-receipts")
        .join(format!("verify.{head}"));
    assert_eq!(fs::read_to_string(&compat).expect("compat receipt"), base);

    // Amend: a new HEAD the check never ran against → stale-head.
    git_in(
        &repo,
        &[
            "commit",
            "-q",
            "--amend",
            "--allow-empty",
            "-m",
            "work, amended",
        ],
    );
    let amended = git_in(&repo, &["rev-parse", "HEAD"]);
    assert_ne!(amended, head, "amend must move HEAD");
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 2);
    assert_eq!(line, format!("verify {amended} stale-head\n"));

    // Re-record, then a rebase-shaped move (a new commit) → stale-head again.
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));
    git_in(&repo, &["commit", "-q", "--allow-empty", "-m", "more work"]);
    let rebased = git_in(&repo, &["rev-parse", "HEAD"]);
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 2);
    assert_eq!(line, format!("verify {rebased} stale-head\n"));

    // Re-record at the new HEAD, then move origin/main out from under the
    // receipt: HEAD still matches, the recorded main no longer does.
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", &rebased]);
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 2);
    assert_eq!(line, format!("verify {rebased} stale-main\n"));

    // The canonical store is idempotent on identity: three records of one
    // check are one receipt file, updated in place.
    let store = home.join("data/batten/repo/receipts");
    let receipts: Vec<_> = fs::read_dir(&store).expect("receipt store").collect();
    assert_eq!(
        receipts.len(),
        1,
        "one check, one receipt, updated in place"
    );
}

#[test]
fn receipt_identity_is_per_check() {
    let (repo, home) = receipt_fixture("receipt-per-check");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));
    // A verify receipt says nothing about linear-check: identities are
    // content-keyed per check, never shared.
    let (code, line) = receipt_status(&repo, &home, "linear-check");
    assert_eq!(code, 2);
    assert_eq!(line, format!("linear-check {head} missing\n"));
}

#[test]
fn a_receipt_from_another_checkout_reads_as_missing() {
    let (repo, home) = receipt_fixture("receipt-foreign");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));

    // Clone to a different parent with the SAME directory basename, so the
    // two checkouts share a state directory — the sharpest aliasing shape.
    // The receipt records the git dir it was taken in, so here it must read
    // as missing (per-checkout facts), never as valid or merely stale.
    let elsewhere = repo.parent().expect("fixture parent").join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create clone parent");
    let repo_str = repo.to_str().expect("fixture path is UTF-8");
    git_in(&elsewhere, &["clone", "-q", repo_str, "repo"]);
    let clone = elsewhere.join("repo");
    let (code, line) = receipt_status(&clone, &home, "verify");
    assert_eq!(code, 2);
    assert_eq!(line, format!("verify {head} missing\n"));
}

#[test]
fn receipt_checkout_problems_are_usage_errors_never_verdicts() {
    // Not a repository (discovery fenced by GIT_CEILING_DIRECTORIES): exit 1,
    // and no verdict line — a checkout problem is not a verification answer.
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("receipt-no-repo");
    let _ = fs::remove_dir_all(&root);
    let plain = root.join("plain");
    let home = root.join("home");
    fs::create_dir_all(&plain).expect("create plain dir");
    fs::create_dir_all(&home).expect("create home dir");
    for verb in ["status", "record"] {
        let output = receipt_cmd(&plain, &home, &["receipt", verb, "verify"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "receipt {verb} outside a repo"
        );
        assert!(output.stdout.is_empty(), "no verdict outside a repo");
    }

    // An unresolvable origin/main is a checkout problem, not a stale receipt.
    let (repo, home) = receipt_fixture("receipt-no-main");
    git_in(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
    let output = receipt_cmd(&repo, &home, &["receipt", "status", "verify"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    // A check name that cannot be a filename component is refused outright.
    let (repo, home) = receipt_fixture("receipt-bad-name");
    let output = receipt_cmd(&repo, &home, &["receipt", "status", "../evil"]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn receipt_record_requires_the_policy_committed_at_head() {
    // The statement's subject is a commit digest, so the policy digest must
    // bind bytes from that commit: a batten.toml present only in the working
    // tree is refused, never silently hashed.
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("receipt-no-policy");
    let _ = fs::remove_dir_all(&root);
    let repo = root.join("repo");
    let home = root.join("home");
    fs::create_dir_all(&repo).expect("create fixture repo");
    fs::create_dir_all(&home).expect("create fixture home");
    git_in(&repo, &["init", "-q"]);
    git_in(&repo, &["config", "user.email", "t@example.com"]);
    git_in(&repo, &["config", "user.name", "t"]);
    fs::write(repo.join("README"), "no policy committed\n").expect("write file");
    git_in(&repo, &["add", "README"]);
    git_in(&repo, &["commit", "-q", "-m", "no policy"]);
    git_in(&repo, &["branch", "-M", "main"]);
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", &head]);
    fs::write(repo.join("batten.toml"), "version = 1\n").expect("write uncommitted policy");
    let output = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn the_receipt_statement_is_in_toto_shaped_and_never_printed() {
    let (repo, home) = receipt_fixture("receipt-shape");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let base = git_in(&repo, &["rev-parse", "origin/main"]);
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));

    // The stored statement uses the in-toto vocabulary: subject = digest.
    let store = home.join("data/batten/repo/receipts");
    let entry = fs::read_dir(&store)
        .expect("receipt store")
        .next()
        .expect("one receipt")
        .expect("readable entry");
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(entry.path()).expect("read receipt"))
            .expect("receipt is JSON");
    assert_eq!(value["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(value["subject"][0]["digest"]["gitCommit"], head.as_str());
    assert_eq!(value["predicate"]["check"], "verify");
    assert_eq!(value["predicate"]["recordedMain"], base.as_str());
    assert_eq!(value["predicate"]["conclusion"], "pass");
    let digest = value["predicate"]["policyDigest"]["sha256"]
        .as_str()
        .expect("policy digest");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));

    // The status output is a pointer, never the payload (rule 4).
    let (_, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(line, format!("verify {head} valid\n"));
}

#[test]
fn the_committed_repo_config_gates_a_repository() {
    // Consumer #1: the repo's own `batten.toml` must load, and its rule table
    // must detect what it claims to — asserted over the shipped file, so config
    // that drifts from the schema, or a rule that can never fire, fails here.
    // The gate side (`mise run batten-check`, wired into hk) runs the same
    // config against the real tree; this pins the config's behaviour.
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");

    let dir = repo_with_config("config-committed", &contents);
    // A file the committed no-conflict-markers rule must flag. The marker is
    // assembled at runtime so this source file never carries the banned shape
    // itself — the gate this test backs scans the whole tree, including here.
    let marker = format!("{} HEAD\n", "<".repeat(7));
    let src = dir.join("crates/x/src");
    fs::create_dir_all(&src).expect("create fixture source tree");
    fs::write(src.join("lib.rs"), marker).expect("write fixture source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the committed rule must fire on the shape it names"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "crates/x/src/lib.rs:1 no-conflict-markers\n",
        "pointer-only finding, byte-stable"
    );
}

#[test]
fn the_committed_example_config_loads_over_the_binary() {
    // DoD: `batten.example.toml` loads and round-trips — asserted against the
    // shipped file itself, so an example that drifts from the schema fails here.
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.example.toml");
    let contents = fs::read_to_string(&example).expect("read batten.example.toml");
    let dir = repo_with_config("config-example", &contents);
    let output = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten config show");
    assert_eq!(output.status.code(), Some(0), "the example must load");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(value["version"], 1);

    // A copied example must be able to produce a finding — a template whose
    // every rule can never fire teaches a new consumer that clean output means
    // nothing. Same runtime-assembled marker discipline as the repo-config test.
    let marker = format!("{} HEAD\n", "<".repeat(7));
    fs::write(dir.join("main.rs"), marker).expect("write fixture source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the example's shipped rule must fire on the shape it names"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "main.rs:1 no-conflict-markers\n"
    );
}

// --- The severity model (CLOUD-61): explicit defaults, scope ≠ severity, ---
// --- and the exit contract consuming the deny/warn/allow vocabulary.     ---

/// A one-rule config whose severity/scope lines are supplied by the test.
fn severity_fixture(severity_and_scope: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n{severity_and_scope}"
    )
}

#[test]
fn a_rule_omitting_severity_is_refused_with_a_named_key() {
    // The explicit-defaults discipline over the binary: no implicit fallback
    // exists, so the file simply does not parse — and the refusal names the
    // missing key so the fix is mechanical.
    let dir = repo_with_config("severity-omitted", &severity_fixture(""));
    fs::write(dir.join("lib.rs"), "clean\n").expect("write source");
    for args in [&["check"][..], &["config", "show"][..]] {
        let output = batten()
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("run batten");
        assert_eq!(
            output.status.code(),
            Some(1),
            "omitted severity must be a usage error under {args:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("severity"),
            "the refusal must name the missing key"
        );
    }
}

#[test]
fn conflating_scope_and_severity_is_refused_in_both_directions() {
    // Two independent keys, never conflated: each axis's vocabulary is rejected
    // by the other key at parse time (exit 1), not reinterpreted.
    for (name, lines) in [
        ("scope-token-in-severity", "severity = \"tree\"\n"),
        (
            "severity-token-in-scope",
            "severity = \"deny\"\nscope = \"deny\"\n",
        ),
        (
            "severity-token-warn-in-scope",
            "severity = \"deny\"\nscope = \"warn\"\n",
        ),
    ] {
        let dir = repo_with_config(&format!("conflate-{name}"), &severity_fixture(lines));
        let output = batten()
            .args(["config", "show"])
            .current_dir(&dir)
            .output()
            .expect("run batten config show");
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: a conflated key must be a usage error"
        );
    }
}

#[test]
fn warn_findings_report_without_failing_the_run() {
    // The middle rank of the exit contract: the finding is printed —
    // pointer-only, same shape as any other — but the run succeeds. Promoting
    // it to a failure is `--fail-on-warning`'s job (CLOUD-49), not the default's.
    let dir = repo_with_config("severity-warn", &severity_fixture("severity = \"warn\"\n"));
    fs::write(dir.join("lib.rs"), "TODO later\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a warn finding must not fail the run"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "lib.rs:1 no-todo\n",
        "the warn finding must still be reported"
    );
}

#[test]
fn an_allow_rule_is_configured_off() {
    // The weakest rank: a match is not a finding at all — nothing printed,
    // nothing failed. The rule stays committed and readable; only its effect is
    // switched off, explicitly.
    let dir = repo_with_config(
        "severity-allow",
        &severity_fixture("severity = \"allow\"\n"),
    );
    fs::write(dir.join("lib.rs"), "TODO later\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "an allow rule must report nothing"
    );
}

#[test]
fn severity_and_scope_serialize_byte_stably_over_the_binary() {
    // §6 over the emitted surface: the tokens `config show` prints are the
    // pinned vocabulary, byte-for-byte, and identical across runs. The scope
    // key is omitted in the input, so the emitted "tree" also proves the
    // per-field-pinned default resolves explicitly rather than vanishing.
    let dir = repo_with_config(
        "severity-byte-stable",
        &severity_fixture("severity = \"warn\"\n"),
    );
    let run = || {
        batten()
            .args(["config", "show"])
            .current_dir(&dir)
            .env_remove("BATTEN_STRICTNESS")
            .output()
            .expect("run batten config show")
    };
    let first = run();
    assert_eq!(first.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("config show stdout is JSON");
    assert_eq!(value["rule"][0]["severity"], "warn");
    assert_eq!(value["rule"][0]["scope"], "tree");
    assert_eq!(
        first.stdout,
        run().stdout,
        "identical input, identical bytes"
    );
}

#[test]
fn committed_rules_pin_severity_and_scope_explicitly() {
    // Schema conformance over the shipped configs (consumer #1 discipline):
    // every committed rule states both keys in the file itself — the explicit,
    // per-field-pinned defaults — and the compiled binary accepts each file and
    // re-emits only the pinned vocabulary.
    for (label, file) in [
        ("batten.toml", "../../batten.toml"),
        ("batten.example.toml", "../../batten.example.toml"),
    ] {
        let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file);
        let contents = fs::read_to_string(&committed).expect("read committed config");

        // The file text pins the keys — not merely the parsed result, which
        // would also be satisfied by a default the file never wrote down.
        let parsed: toml::Value = toml::from_str(&contents).expect("committed config is TOML");
        let rules = parsed
            .get("rule")
            .and_then(toml::Value::as_array)
            .expect("committed config declares rules");
        assert!(!rules.is_empty(), "{label}: consumer #1 ships a live rule");
        for rule in rules {
            let id = rule.get("id").and_then(toml::Value::as_str).unwrap_or("?");
            for key in ["severity", "scope"] {
                assert!(
                    rule.get(key).is_some(),
                    "{label}: rule {id} must pin `{key}` explicitly"
                );
            }
        }

        // And the binary agrees: the file loads, and the emitted tokens are the
        // byte-stable vocabulary — never a value outside it.
        let dir = repo_with_config(&format!("conformance-{label}"), &contents);
        let output = batten()
            .args(["config", "show"])
            .current_dir(&dir)
            .env_remove("BATTEN_STRICTNESS")
            .output()
            .expect("run batten config show");
        assert_eq!(output.status.code(), Some(0), "{label} must load");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("config show stdout is JSON");
        for rule in value["rule"].as_array().expect("rules in output") {
            let severity = rule["severity"].as_str().expect("severity token");
            assert!(
                ["allow", "warn", "deny"].contains(&severity),
                "{label}: severity {severity:?} outside the vocabulary"
            );
            assert_eq!(rule["scope"], "tree", "{label}: scope token");
        }
    }
}
