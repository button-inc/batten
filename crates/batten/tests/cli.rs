//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Output, Stdio};

use common::{Fixture, batten, git_in, scratch};

/// Run `batten hook --harness <harness>` with `payload` piped to stdin.
///
/// The ambient bypass var is removed so a developer's shell can never flip a
/// deny case; the `bypass` flag sets it explicitly for the case that wants it.
fn run_hook(harness: &str, payload: &str, bypass: bool) -> Output {
    run_hook_in(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        harness,
        payload,
        bypass,
    )
}

/// A fixture repo whose `batten.toml` carries the `gh` lifecycle shape rows.
///
/// Since CLOUD-48 the policy is config, not Rust, so a hook test that wants a
/// deny has to supply one. Deliberately *not* this repo's own `batten.toml`: a
/// test that read the committed file would pass or fail with an edit to
/// production policy, and the committed rows have their own gate
/// (`the_committed_shape_rules_fire_on_every_banned_shape`).
fn repo_with_gh_policy(name: &str) -> PathBuf {
    repo_with_config(
        name,
        r#"version = 1
[[rule]]
id = "gh-pr-merge"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr merge"
reason = "use `mise run land`"

[[rule]]
id = "gh-pr-comment-fast-forward"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr comment"
contains = "fast-forward"
reason = "use `mise run land`"

[[rule]]
id = "gh-pr-checks"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr checks"
reason = "use `mise run ci-wait`"

[[rule]]
id = "gh-run-watch"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh run watch"
reason = "use `mise run ci-wait`"
"#,
    )
}

/// [`run_hook`], with the directory the policy is resolved from.
///
/// The directory is now load-bearing: `hook` reads its authority from the cwd
/// (CLOUD-48), so a test that does not set one adjudicates against the empty
/// policy and allows everything. `run_hook` itself keeps the old signature and
/// points at `crates/batten/`, which has no `batten.toml` — that is the
/// no-authority case, which several tests want.
fn run_hook_in(dir: &std::path::Path, harness: &str, payload: &str, bypass: bool) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
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
    // Wiping first is `Fixture`'s unconditional behaviour (CLOUD-63). This copy
    // used not to wipe, which is why byte-exact assertions below had to clear
    // the directory by hand before calling it.
    Fixture::new(name).config(contents).build()
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
/// One row of the exit-code table: an invocation, its config, and its code.
struct Case {
    /// What the invocation exercises, surfaced on assertion failure.
    name: &'static str,
    /// Arguments passed to `batten`.
    args: &'static [&'static str],
    /// `batten.toml` contents to place in the run directory, if any.
    config: Option<&'static str>,
    /// Environment variables set for the invocation.
    env: &'static [(&'static str, &'static str)],
    /// The exit code the invocation must return.
    expected: i32,
}

/// Run every case in its own scratch directory and assert its code.
///
/// `label` names the table, so two tables can share the runner without their
/// scratch directories colliding.
fn assert_exit_codes(label: &str, cases: &[Case]) {
    for (index, case) in cases.iter().enumerate() {
        let dir = scratch(&format!("exit-{label}-{index}"));
        fs::create_dir_all(&dir).expect("create case dir");
        let config_path = dir.join("batten.toml");
        match case.config {
            Some(contents) => fs::write(&config_path, contents).expect("write batten.toml"),
            // A stale file from a prior run would mask the missing-config path.
            None => {
                let _ = fs::remove_file(&config_path);
            }
        }
        let mut command = batten();
        command.args(case.args).current_dir(&dir);
        for (key, value) in case.env {
            command.env(key, value);
        }
        let status = command.status().expect("run batten");
        assert_eq!(status.code(), Some(case.expected), "case: {}", case.name);
    }
}

#[test]
fn exit_code_contract() {
    let cases = [
        Case {
            name: "no subcommand → usage (subcommand listing offered)",
            args: &[],
            config: None,
            env: &[],
            expected: 1,
        },
        Case {
            name: "--help → success (help is an answer, not clap's exit 2)",
            args: &["--help"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "--version → success",
            args: &["--version"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "spec → success",
            args: &["spec"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "config show, valid config → success",
            args: &["config", "show"],
            config: Some("version = 1\n"),
            env: &[],
            expected: 0,
        },
        Case {
            name: "unknown flag → usage",
            args: &["--nope"],
            config: None,
            env: &[],
            expected: 1,
        },
        Case {
            name: "config show, unsupported version → usage",
            args: &["config", "show"],
            config: Some("version = 2\n"),
            env: &[],
            expected: 1,
        },
        Case {
            name: "config show, unknown key → usage",
            args: &["config", "show"],
            config: Some("version = 1\nbogus = true\n"),
            env: &[],
            expected: 1,
        },
        Case {
            name: "config show, missing config → usage",
            args: &["config", "show"],
            config: None,
            env: &[],
            expected: 1,
        },
        Case {
            name: "config show, rule omitting severity → usage (no implicit fallback)",
            args: &["config", "show"],
            config: Some(
                "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\n",
            ),
            env: &[],
            expected: 1,
        },
        Case {
            name: "config show, severity token in the scope key → usage (scope ≠ severity)",
            args: &["config", "show"],
            config: Some(
                "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\nscope = \"deny\"\n",
            ),
            env: &[],
            expected: 1,
        },
    ];
    assert_exit_codes("contract", &cases);
}

/// The §3 ladder and the §4 presentation booleans never change a verdict — they
/// change how much is said about one (CLOUD-42).
#[test]
fn the_ladder_never_changes_an_exit_code() {
    let cases = [
        // Each case carries a VERB deliberately:
        // `arg_required_else_help` makes a bare invocation exit 1, so
        // `["--silent"]` alone would assert 0 and be wrong for a reason that has
        // nothing to do with the ladder.
        Case {
            name: "--silent → the verb's own code, unchanged",
            args: &["--silent", "spec"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "-q -v → no conflict; last flag wins",
            args: &["-q", "-v", "spec"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "-vv → the next rung, not a second occurrence error",
            args: &["-vv", "spec"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            name: "--debug and --trace are hidden but real",
            args: &["--trace", "spec"],
            config: None,
            env: &[],
            expected: 0,
        },
        Case {
            // Carries a verb so the 1 can only come from the rung parse: with a
            // bare invocation clap errors first and the case would pass without
            // `output::resolve` ever reading the variable.
            name: "a bogus BATTEN_LOG_LEVEL → usage, never a rounded default",
            args: &["spec"],
            config: None,
            env: &[("BATTEN_LOG_LEVEL", "chatty")],
            expected: 1,
        },
        Case {
            name: "an empty BATTEN_LOG_LEVEL is unset, not invalid",
            args: &["spec"],
            config: None,
            env: &[("BATTEN_LOG_LEVEL", "")],
            expected: 0,
        },
    ];
    assert_exit_codes("ladder", &cases);
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
        .args(["config", "show", "--json"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("config show stdout is JSON");
    assert_eq!(value["version"]["value"], 1);
    assert_eq!(value["min_batten_version"]["value"], "0.0.0");
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
        .args(["config", "show", "--json"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(value["strictness"]["value"], "strict");
    assert_eq!(value["strictness"]["source"], "local-file");
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

    let (code, local) = strictness_of(&["config", "show", "--json"], None);
    assert_eq!(code, 0);
    assert_eq!(local["strictness"]["value"], "standard");
    assert_eq!(local["strictness"]["source"], "local-file");

    let (code, env) = strictness_of(&["config", "show", "--json"], Some("strict"));
    assert_eq!(code, 0);
    assert_eq!(env["strictness"]["value"], "strict");
    assert_eq!(env["strictness"]["source"], "env");

    // A flag outranks the env var — here restating the same value, which the
    // clamp accepts and re-attributes to the higher layer.
    let (code, flag) = strictness_of(
        &["--strictness", "strict", "config", "show", "--json"],
        Some("strict"),
    );
    assert_eq!(code, 0);
    assert_eq!(flag["strictness"]["source"], "flag");
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
        .args(["config", "show", "--json"])
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

/// Which channel a decision travels over (CLOUD-40).
///
/// The *number* is the same on every surface (§7); only the channel differs.
/// And a channel is observable only by spawning the binary — reading `hook.rs`
/// cannot tell you whether a deny actually reached the host — so this is the
/// one property that has to be pinned by a fixture rather than a type.
enum Channel {
    /// Nothing on stdout. A clean run is the cheapest possible signal (§6).
    Silent,
    /// The host reads an in-band decision document; the document *is* the deny.
    StdoutDenyJson,
    /// The host's only channel is process status, so the reason rides stderr.
    StderrReason,
}

/// One row of the per-harness decision matrix.
struct Row {
    harness: &'static str,
    case: &'static str,
    command: &'static str,
    expected: i32,
    channel: Channel,
}

/// Allow and deny, once per supported harness.
///
/// Kept beside the other `hook_*` tests rather than in a file of its own: the
/// rows pin exactly the behaviour those tests describe, and splitting them
/// would put the reasoning a screen away from the assertions it explains.
const MATRIX: &[Row] = &[
    Row {
        harness: "claude-code",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "claude-code",
        case: "deny",
        command: "gh pr merge 42",
        expected: 0,
        channel: Channel::StdoutDenyJson,
    },
    Row {
        harness: "exit-code",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "exit-code",
        case: "deny",
        command: "gh pr merge 42",
        expected: 2,
        channel: Channel::StderrReason,
    },
];

#[test]
fn the_decision_channel_matrix_holds_for_every_harness() {
    let dir = repo_with_gh_policy("matrix-policy");
    for row in MATRIX {
        let output = run_hook_in(&dir, row.harness, &claude_payload(row.command), false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let at = format!("{}/{}", row.harness, row.case);
        assert_eq!(output.status.code(), Some(row.expected), "{at}: exit code");
        match row.channel {
            Channel::Silent => assert!(
                stdout.is_empty(),
                "{at}: an allow answers nothing on stdout, got: {stdout}"
            ),
            Channel::StdoutDenyJson => assert!(
                stdout.contains("\"permissionDecision\":\"deny\""),
                "{at}: the decision document is the deny, got: {stdout}"
            ),
            Channel::StderrReason => {
                assert!(
                    stdout.is_empty(),
                    "{at}: the verdict rides stderr, not the answer channel, got: {stdout}"
                );
                assert!(!stderr.trim().is_empty(), "{at}: a deny carries its reason");
                // A verdict is an answer, not a crash. The host hands this text
                // back to the model, so it must not wear the binary's error
                // prefix — that belongs to 1 and 3.
                assert!(
                    !stderr.starts_with("batten:"),
                    "{at}: a deny reason is unprefixed, got: {stderr}"
                );
            }
        }
    }
}

#[test]
fn the_matrix_covers_every_supported_harness() {
    // The matrix is a contract only while it is total. A third adapter added to
    // `Harness::ALL` with no row here would ship with its channel unpinned, and
    // an unpinned channel is precisely the silently-converted refusal this
    // issue exists to prevent.
    let mut covered: Vec<&str> = MATRIX.iter().map(|row| row.harness).collect();
    covered.sort_unstable();
    covered.dedup();
    let mut declared: Vec<&str> = batten::hook::Harness::ALL
        .iter()
        .map(|harness| harness.as_str())
        .collect();
    declared.sort_unstable();
    assert_eq!(
        covered, declared,
        "every declared harness needs a decision-channel row"
    );
}

#[test]
fn a_quoted_invocation_denies_on_both_harness_channels() {
    // CLOUD-269's one intended tightening, asserted over the compiled binary
    // rather than only in-module: quoting the subcommand words is a real
    // `gh pr merge`, and the sentinel parser let it through because the span
    // never became tokens. Checked on both channels so the tightening is
    // pinned wherever a host reads its decision.
    let dir = repo_with_gh_policy("quoted-invocation");
    for harness in ["claude-code", "exit-code"] {
        let output = run_hook_in(&dir, harness, &claude_payload("gh \"pr\" \"merge\""), false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if harness == "claude-code" {
            assert_eq!(output.status.code(), Some(0), "{harness}");
            assert!(
                stdout.contains("\"permissionDecision\":\"deny\""),
                "{harness}: got {stdout}"
            );
        } else {
            assert_eq!(output.status.code(), Some(2), "{harness}");
            assert!(stderr.contains("Refused by"), "{harness}: got {stderr}");
        }
    }
}

#[test]
fn a_malformed_harness_token_fails_loud_without_denying() {
    // The forced-failure leg of the matrix, and the only one reachable today:
    // `hook` reads no config, so nothing else it does can fail. An unselectable
    // harness is a usage error — exit 1, loud on stderr, and emphatically not a
    // deny, because a guard that blocks when its own invocation is wrong is a
    // guard that blocks on a typo.
    //
    // Spawned without piping a payload, deliberately: clap rejects the token
    // before anything reads stdin, so `run_hook`'s write would race a closed
    // pipe. That it never reads the payload is itself the point.
    for token in ["claude_code", "", "exitcode"] {
        let output = batten()
            .args(["hook", "--harness", token])
            .env_remove("BATTEN_GH_GUARD_BYPASS")
            .stdin(Stdio::null())
            .output()
            .expect("run batten hook");
        let code = output.status.code();
        assert_eq!(code, Some(1), "harness {token:?}: usage error");
        assert_ne!(code, Some(2), "harness {token:?}: must never deny");
        assert!(output.stdout.is_empty(), "harness {token:?}: no answer");
        assert!(
            !output.stderr.is_empty(),
            "harness {token:?}: a failure is loud"
        );
    }
}

#[test]
fn hook_allows_when_no_authority_is_configured() {
    // This replaces CLOUD-40's `hook_reads_no_config_so_a_broken_one_cannot_block`
    // — the test written to be deleted here, marking the seam where config became
    // load-bearing.
    //
    // `hook` is registered once and then mediates every call in whatever
    // directory the agent is in, most of which are not Batten repositories. An
    // absent authority is therefore the empty policy, not an error: nothing
    // declared, nothing denied, silently.
    let dir = repo_with_config("hook-no-authority", "");
    fs::remove_file(dir.join("batten.toml")).expect("remove the authority");
    let output = run_hook_in(
        &dir,
        "claude-code",
        &claude_payload("gh pr merge 42"),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "no authority denies nothing");
}

#[test]
fn hook_fails_open_and_loud_on_an_unloadable_authority() {
    // The opposite case, and the one CLOUD-40 could not reach because `hook`
    // loaded no config: an authority that EXISTS and cannot be read means the
    // rules the operator wrote are not being applied. Allowing silently there
    // would be the false green the engine exists to catch, so it is a usage
    // error — loud on stderr, exit 1, and structurally not a deny, because §7
    // spends 2 on the verdict alone.
    let dir = repo_with_config("hook-broken-authority", "this is not toml at all\n");
    for harness in ["claude-code", "exit-code"] {
        let output = run_hook_in(&dir, harness, &claude_payload("gh pr view 42"), false);
        let code = output.status.code();
        assert_eq!(code, Some(1), "{harness}: an unreadable authority is usage");
        assert_ne!(code, Some(2), "{harness}: must never deny");
        assert!(output.stdout.is_empty(), "{harness}: no decision document");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("batten.toml"),
            "{harness}: the failure names the file, got: {stderr}"
        );
    }
}

#[test]
fn shape_scope_parses_independently_of_severity() {
    // Acceptance (d). The two keys are separate axes, and a shape row proves it
    // over the binary: `mediated_call` × each severity all load, and neither
    // key's vocabulary is accepted in the other's slot.
    for severity in ["deny", "warn", "allow"] {
        let dir = repo_with_config(
            &format!("shape-severity-{severity}"),
            &format!(
                "version = 1\n\n[[rule]]\nid = \"s\"\nkind = \"shape\"\n\
                 scope = \"mediated_call\"\nseverity = \"{severity}\"\n\
                 pattern = \"gh pr merge\"\nreason = \"use the landing path\"\n"
            ),
        );
        let output = batten()
            .args(["config", "show", "--json"])
            .current_dir(&dir)
            .output()
            .expect("run config show");
        assert_eq!(
            output.status.code(),
            Some(0),
            "severity {severity} must load"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is JSON");
        let rule = &value["rule"]["value"][0];
        assert_eq!(rule["severity"], severity);
        assert_eq!(rule["scope"], "mediated_call");
    }

    // And crossing them is inexpressible, not silently reinterpreted.
    for (key, value) in [("scope", "deny"), ("severity", "mediated_call")] {
        let dir = repo_with_config(
            &format!("shape-crossed-{key}"),
            &format!(
                "version = 1\n\n[[rule]]\nid = \"s\"\nkind = \"shape\"\n\
                 scope = \"mediated_call\"\nseverity = \"deny\"\n\
                 pattern = \"gh pr merge\"\nreason = \"r\"\n{key} = \"{value}\"\n"
            ),
        );
        assert_eq!(
            batten()
                .arg("check")
                .current_dir(&dir)
                .output()
                .expect("run batten check")
                .status
                .code(),
            Some(1),
            "{key} = {value:?} must be a usage error"
        );
    }
}

#[test]
fn hook_refuses_an_invalid_severity_without_denying() {
    // Acceptance (e), corrected: the ticket said exit 2, but 2 is the deny code,
    // so a config typo would refuse every mediated call. Every sibling
    // config error in the tree is exit 1, and non-negotiable rule 5 plus
    // `no_failure_code_can_deny_a_mediated_call` forbid the alternative.
    let dir = repo_with_config(
        "shape-bad-severity",
        "version = 1\n\n[[rule]]\nid = \"s\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"nope\"\n\
         pattern = \"gh pr merge\"\nreason = \"r\"\n",
    );
    for harness in ["claude-code", "exit-code"] {
        let output = run_hook_in(&dir, harness, &claude_payload("gh pr merge"), false);
        let code = output.status.code();
        assert_eq!(code, Some(1), "{harness}: a bad severity is a usage error");
        assert_ne!(code, Some(2), "{harness}: must never deny");
        assert!(output.stdout.is_empty(), "{harness}: no decision document");
    }
}

#[test]
fn hook_honours_a_shape_rule_a_local_override_added() {
    // Why the policy resolves through `resolve` rather than `config::load`: the
    // raise-only override model is worth nothing at a surface that ignores it.
    // A `batten.local.toml` may only tighten, and adding a shape row is a
    // tightening, so the hook must apply it.
    let dir = repo_with_config("shape-local-override", "version = 1\n");
    with_local_config(
        &dir,
        "version = 1\n\n[[rule]]\nid = \"local-shape\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"deny\"\n\
         pattern = \"npm publish\"\nreason = \"releases go through the release pipeline\"\n",
    );
    let output = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("npm publish --tag next"),
        false,
    );
    assert_eq!(output.status.code(), Some(2), "a local row must be applied");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("local-shape"), "got: {stderr}");
}

/// A fixture repo declaring the CLOUD-96 cross product: two verbs, one path.
fn repo_with_protected_policy(name: &str) -> PathBuf {
    repo_with_config(
        name,
        r#"version = 1
protected = ["guarded/**"]

[[verb]]
verb = "rm"
effect = "destructive"
redirect = "restore it with git"

[[verb]]
verb = ">"
effect = "destructive"
redirect = "append instead"
"#,
    )
}

#[test]
fn hook_denies_a_mutating_verb_against_a_protected_path_on_both_channels() {
    let dir = repo_with_protected_policy("protected-both-channels");
    for harness in ["claude-code", "exit-code"] {
        let output = run_hook_in(&dir, harness, &claude_payload("rm guarded/thing"), false);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if harness == "claude-code" {
            assert_eq!(output.status.code(), Some(0), "{harness}");
            assert!(
                stdout.contains("\"permissionDecision\":\"deny\""),
                "{harness}: got {stdout}"
            );
            assert!(stdout.contains("restore it with git"), "names the redirect");
        } else {
            assert_eq!(output.status.code(), Some(2), "{harness}");
            assert!(
                stderr.contains("restore it with git"),
                "{harness}: names the redirect, got {stderr}"
            );
        }
    }
}

#[test]
fn hook_allows_the_same_verb_against_an_unprotected_path() {
    let dir = repo_with_protected_policy("protected-elsewhere");
    let output = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("rm scratch/thing"),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn hook_denies_a_truncating_redirect_against_a_protected_path() {
    // A redirect has no mutating program to classify, so the operator is the
    // pseudo-verb the consumer declared.
    let dir = repo_with_protected_policy("protected-redirect");
    for command in ["cat x > guarded/thing", "cat x >guarded/thing"] {
        let output = run_hook_in(&dir, "exit-code", &claude_payload(command), false);
        assert_eq!(output.status.code(), Some(2), "must deny: {command}");
    }
}

#[test]
fn the_deny_is_a_function_of_config_and_argv_not_the_ambient_environment() {
    // Acceptance (c): "a repeat attempt with the sandbox disabled is still
    // denied" — i.e. the verdict is computed from config plus argv, so nothing
    // ambient can turn it off. Asserted by varying the environment around an
    // identical payload and config and requiring byte-identical answers.
    let dir = repo_with_protected_policy("protected-deterministic");
    let payload = claude_payload("rm guarded/thing");
    let baseline = run_hook_in(&dir, "exit-code", &payload, false);
    for (key, value) in [
        ("BATTEN_SANDBOX", "0"),
        ("CI", "1"),
        ("NO_COLOR", "1"),
        ("HOME", "/tmp"),
    ] {
        let mut command = batten();
        command
            .current_dir(&dir)
            .args(["hook", "--harness", "exit-code"])
            .env_remove("BATTEN_GH_GUARD_BYPASS")
            .env(key, value)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn batten hook");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(payload.as_bytes())
            .expect("write payload");
        let output = child.wait_with_output().expect("run batten hook");
        assert_eq!(
            output.status.code(),
            baseline.status.code(),
            "{key}={value} changed the verdict"
        );
        assert_eq!(
            output.stderr, baseline.stderr,
            "{key}={value} changed the reason"
        );
    }
}

#[test]
fn the_committed_protected_paths_fire_on_a_mutating_verb() {
    // The same obligation the shape rows carry: every other protected-path test
    // supplies its own fixture, so without this, deleting a `protected` entry or
    // a `[[verb]]` row from the real `batten.toml` would break nothing.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for command in [
        "rm .serena/memories/core.md",
        "mv batten.toml elsewhere.toml",
        "cat x > .github/workflows/ci.yml",
    ] {
        let output = run_hook_in(&root, "exit-code", &claude_payload(command), false);
        assert_eq!(
            output.status.code(),
            Some(2),
            "the committed policy must refuse {command:?}"
        );
    }
    // A mutating verb aimed somewhere ordinary is not this gate's business.
    let output = run_hook_in(
        &root,
        "exit-code",
        &claude_payload("rm target/debug/scratch"),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn hook_fails_open_and_loud_on_a_malformed_protected_list() {
    // `PathSet::includes` refuses a `!` entry — `protected` is an include-only
    // key. That is a usage error, never a deny.
    let dir = repo_with_config(
        "protected-malformed",
        "version = 1\nprotected = [\"!nope\"]\n\n[[verb]]\nverb = \"rm\"\n\
         effect = \"destructive\"\n",
    );
    let output = run_hook_in(&dir, "exit-code", &claude_payload("rm anything"), false);
    let code = output.status.code();
    assert_eq!(code, Some(1), "a malformed protected list is usage");
    assert_ne!(code, Some(2), "must never deny");
    assert!(!output.stderr.is_empty(), "a failure is loud");
}

#[test]
fn the_committed_shape_rules_fire_on_every_banned_shape() {
    // The obligation the fixture tests do not discharge. Every hook test above
    // supplies its own policy, so after CLOUD-48 deleting a row from this repo's
    // `batten.toml` would break none of them — and the guard chain in
    // `.claude/settings.json` would silently lose a rule. `tests/cli.rs` states
    // the standing rule: a rule is only pinned by a fixture that seeds the shape
    // it bans, and any rule landing later owes one of its own.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for command in [
        "gh pr merge 42",
        "gh pr checks --watch",
        "gh run watch 123",
        "gh pr comment 7 --body /fast-forward",
    ] {
        let output = run_hook_in(&root, "exit-code", &claude_payload(command), false);
        assert_eq!(
            output.status.code(),
            Some(2),
            "the committed policy must still refuse {command:?}"
        );
    }
    // And the reads it must not refuse, from the same committed rows.
    for command in ["gh pr view 42", "gh pr ready 42", "mise run land"] {
        let output = run_hook_in(&root, "exit-code", &claude_payload(command), false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "the committed policy must allow {command:?}"
        );
    }
}

#[test]
fn hook_denies_a_blocked_shape_in_the_harness_channel() {
    // The claude-code adapter answers in the host's JSON decision object with
    // exit 0 — the channel the production shell guards already use. The
    // wrapper form is the load-bearing case: judging the wrapper token instead
    // of the effective program is the bug class CLOUD-181 hardened against.
    let dir = repo_with_gh_policy("deny-claude-channel");
    let output = run_hook_in(
        &dir,
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
        "the deny must name the redirect the fixture policy declares"
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
    let dir = repo_with_gh_policy("deny-exit-code-channel");
    let output = run_hook_in(&dir, "exit-code", &claude_payload("gh pr merge 42"), false);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Refused by"), "got: {stderr}");
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

// --- the §3 ladder and the §4 attended layer (CLOUD-42) ----------------------

/// Run `batten` in `dir` with extra environment, capturing both streams.
fn batten_with(dir: &std::path::Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = batten();
    command.args(args).current_dir(dir);
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("run batten")
}

/// A scratch directory carrying this repository's own `batten.toml`, for the
/// verbs that need a real authority.
fn repo_with_committed_config(name: &str) -> PathBuf {
    let dir = scratch(name);
    fs::create_dir_all(&dir).expect("create dir");
    fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("batten.toml"),
        dir.join("batten.toml"),
    )
    .expect("copy the committed authority");
    dir
}

#[test]
fn stdout_bytes_are_identical_at_every_rung() {
    // The property that makes `-J` safe, asserted rather than promised: the
    // ladder shapes stderr, and stdout is the answer. If a rung could touch
    // stdout, a `--quiet` in a wrapper script would silently truncate a document
    // its caller is parsing.
    let dir = scratch("ladder-stdout");
    fs::create_dir_all(&dir).expect("create dir");
    let baseline = batten_with(&dir, &["spec"], &[]).stdout;
    assert!(!baseline.is_empty(), "spec emits its answer");
    for rung in [
        vec!["--silent", "spec"],
        vec!["-q", "spec"],
        vec!["-qq", "spec"],
        vec!["-v", "spec"],
        vec!["-vv", "spec"],
        vec!["--debug", "spec"],
        vec!["--trace", "spec"],
        vec!["--log-level", "trace", "spec"],
        vec!["--no-color", "spec"],
        vec!["--no-input", "spec"],
    ] {
        assert_eq!(
            batten_with(&dir, &rung, &[]).stdout,
            baseline,
            "{rung:?} changed the answer channel"
        );
    }
}

#[test]
fn json_output_is_identical_under_every_machine_signal() {
    // Acceptance (d). The §4 signals decide whether a human is watching, which
    // is a question about *stderr*. A data document that varied with `CI` or
    // `TERM` would be unparseable by exactly the callers that set them.
    let dir = repo_with_committed_config("machine-signal-json");
    let baseline = batten_with(&dir, &["config", "lint", "-J"], &[]).stdout;
    assert!(!baseline.is_empty());
    for signal in [
        ("CI", "1"),
        ("TERM", "dumb"),
        ("NO_COLOR", "1"),
        ("CLICOLOR_FORCE", "1"),
        ("CLICOLOR", "0"),
        ("BATTEN_NO_COLOR", "1"),
        ("BATTEN_NO_INPUT", "1"),
    ] {
        assert_eq!(
            batten_with(&dir, &["config", "lint", "-J"], &[signal]).stdout,
            baseline,
            "{signal:?} changed the data channel"
        );
    }
}

#[test]
fn an_unknown_flag_is_a_usage_error_even_under_silent() {
    // clap's own usage render cannot be ladder-gated: the flags may not have
    // parsed, so suppressing it would leave a bare `1` explaining nothing.
    let dir = scratch("silent-unknown-flag");
    fs::create_dir_all(&dir).expect("create dir");
    let output = batten_with(&dir, &["--silent", "--nope", "spec"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !output.stderr.is_empty(),
        "exit 1 is fail-loud; --silent must not empty it"
    );
}

#[test]
fn a_library_usage_error_is_loud_under_silent_too() {
    // The other half: a `UsageError` raised by the library and reported through
    // `output::error`, which *does* see the mode. Several gates in this repo read
    // this message rather than the code (CLOUD-40's DoD, CLOUD-48's fail-loud
    // test), so the invariant is bundle-wide, not local to clap.
    let dir = scratch("silent-missing-config");
    fs::create_dir_all(&dir).expect("create dir");
    let _ = fs::remove_file(dir.join("batten.toml"));
    let output = batten_with(&dir, &["--silent", "config", "show"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("batten:"),
        "a usage error names itself even at the quietest rung"
    );
}

#[test]
fn the_hidden_rungs_are_absent_from_help_but_still_parse() {
    let dir = scratch("hidden-rungs");
    fs::create_dir_all(&dir).expect("create dir");
    let help = String::from_utf8_lossy(&batten_with(&dir, &["--help"], &[]).stdout).into_owned();
    for shown in [
        "--silent",
        "--quiet",
        "--verbose",
        "--no-color",
        "--no-input",
    ] {
        assert!(help.contains(shown), "--help must list {shown}");
    }
    for hidden in ["--debug", "--trace", "--log-level"] {
        assert!(!help.contains(hidden), "--help must not list {hidden}");
    }
    // Hidden is a `--help` property, not an undeclared flag: each still parses.
    // `--log-level` is the one that names a rung, so it carries its value.
    for argv in [
        vec!["--debug", "spec"],
        vec!["--trace", "spec"],
        vec!["--log-level", "trace", "spec"],
    ] {
        assert_eq!(
            batten_with(&dir, &argv, &[]).status.code(),
            Some(0),
            "{argv:?} must still parse"
        );
    }
}

#[test]
fn the_ladder_is_emitted_in_the_spec_as_taking_no_value() {
    // `spec.rs` reported `takes_value: true` for every counted flag until
    // `ArgAction::Count` joined the boolean actions — a lie a completion script
    // acts on by eating the next word.
    let dir = scratch("spec-counted");
    fs::create_dir_all(&dir).expect("create dir");
    let document: serde_json::Value =
        serde_json::from_slice(&batten_with(&dir, &["spec"], &[]).stdout).expect("spec is JSON");
    let flags = document["flags"].as_array().expect("root flags");
    for id in ["silent", "quiet", "verbose", "debug", "trace"] {
        let flag = flags
            .iter()
            .find(|flag| flag["name"] == id)
            .unwrap_or_else(|| panic!("{id} is in the spec"));
        assert_eq!(flag["takes_value"], serde_json::json!(false), "{id}");
    }
    let named = flags
        .iter()
        .find(|flag| flag["name"] == "log_level")
        .expect("log_level is in the spec");
    assert_eq!(named["takes_value"], serde_json::json!(true));
}

// --- the data channel reaches three more verbs (CLOUD-42) --------------------

#[test]
fn config_epoch_emits_the_digest_and_the_surface_it_covers() {
    let dir = scratch("epoch-json");
    fs::create_dir_all(&dir).expect("create dir");
    // Its own authority rather than this repository's: the committed `[epoch]`
    // list names four files that do not exist in a scratch directory, and an
    // unreadable tracked path is exit 1 by design (never a silent skip).
    fs::write(
        dir.join("batten.toml"),
        "version = 1\n\n[epoch]\ntracked = [\"batten.toml\"]\n",
    )
    .expect("write config");
    let plain = batten_with(&dir, &["config", "epoch"], &[]);
    assert_eq!(plain.status.code(), Some(0));
    let value = String::from_utf8_lossy(&plain.stdout).trim().to_owned();

    let output = batten_with(&dir, &["config", "epoch", "-J"], &[]);
    assert_eq!(output.status.code(), Some(0));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("epoch -J is JSON");
    assert_eq!(document["epoch"], serde_json::json!(value));
    let tracked = document["tracked"].as_array().expect("tracked is a list");
    assert!(
        tracked.iter().any(|path| path == "batten.toml"),
        "the surface names the authority that governs it"
    );
    // Paths, never bytes: the digest attributes a surface, it does not carry it.
    assert!(!String::from_utf8_lossy(&output.stdout).contains("min_batten_version"));
}

#[test]
fn config_lint_emits_its_document_even_when_clean() {
    // A data channel emits unconditionally. JSON that is sometimes absent is
    // unparseable, which is why the empty case is the one worth pinning.
    let dir = repo_with_committed_config("lint-json-clean");
    let output = batten_with(&dir, &["config", "lint", "-J"], &[]);
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("lint -J is JSON");
    assert_eq!(document["smells"], serde_json::json!([]));
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn config_lint_json_carries_the_same_smells_the_pointer_lines_do() {
    let dir = scratch("lint-json-smelly");
    fs::create_dir_all(&dir).expect("create dir");
    // An empty declared set is a smell, and one that needs no rule to trigger.
    fs::write(
        dir.join("batten.toml"),
        "version = 1
protected = []
",
    )
    .expect("write config");
    let plain = batten_with(&dir, &["config", "lint"], &[]);
    assert_eq!(plain.status.code(), Some(2), "a smell is a policy verdict");
    let lines = String::from_utf8_lossy(&plain.stdout).into_owned();

    let output = batten_with(&dir, &["config", "lint", "-J"], &[]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the encoding never changes the verdict"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("lint -J is JSON");
    let smells = document["smells"].as_array().expect("smells is a list");
    assert!(!smells.is_empty());
    for smell in smells {
        let id = smell["id"].as_str().expect("an id");
        let at = smell["at"].as_str().expect("a location");
        assert!(lines.contains(id), "the human channel names {id} too");
        assert!(lines.contains(at), "the human channel points at {at} too");
    }
}

// --- receipts (CLOUD-203) ----------------------------------------------------

/// A repo fixture for the receipt tests, in the normal PR shape: a committed
/// `batten.toml` as the base commit, `origin/main` pinned to it, and one
/// commit of work on top. Returns `(repo, home)` where `home` isolates the
/// out-of-tree receipt store.
fn receipt_fixture(name: &str) -> (PathBuf, PathBuf) {
    // Wiping a stale fixture from a prior run is `Fixture`'s unconditional
    // behaviour; it would otherwise mask state-dir behaviour.
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
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
    let root = scratch("receipt-no-repo");
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
    let root = scratch("receipt-no-policy");
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
    // Consumer #1: the repo's own `batten.toml` must load, and the rule this
    // fixture seeds must fire — asserted over the shipped file, so config that
    // drifts from the schema fails here. The gate side (`mise run batten-check`,
    // wired into hk) runs the same config against the real tree; this pins the
    // config's behaviour.
    //
    // WHAT THIS CASE CANNOT SEE, stated because an earlier version of this
    // comment claimed it could ("a rule that can never fire fails here"): the
    // fixture writes one file carrying only a conflict marker, so the stdout
    // asserted below is byte-identical whether the *other* committed rules are
    // present, absent, misspelled, mis-globbed, or switched off at
    // `severity = "allow"`. A rule is only pinned by a fixture that seeds the
    // shape it bans. `the_committed_repo_agnosticism_rules_fire_on_every_banned_shape`
    // below is that fixture for the CLOUD-7 rules, and any rule landing later
    // owes one of its own.
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
fn the_committed_repo_agnosticism_rules_fire_on_every_banned_shape() {
    // Non-negotiable rule 1 — "no consumer-specific identifier anywhere in
    // crates/batten" — as a gate rather than a one-time grep (CLOUD-7). The
    // committed rule table is loaded from the shipped file, so this fails if a
    // rule is missing, renamed, mis-globbed, or set to `severity = "allow"`.
    //
    // Full stdout equality is the load-bearing part. Findings sort by the
    // `(path, line, rule)` pointer tuple, so the expected bytes are fixed, and
    // every way a rule can stop working changes them. A `contains` assertion
    // would pass with one of the two rules deleted.
    //
    // The banned shapes are assembled at runtime rather than written as source
    // text — the same dodge the conflict marker above uses. This file sits under
    // `crates/batten/tests/`, inside the very glob these rules scan, so spelling
    // one here would make `mise run batten-check` fire on the test that proves
    // the rule works.
    let account = format!("e{}bc", "tax");
    let entity_path = format!("entit{}/", "ies");
    let payload = format!("let id = \"{account}\";\nuse crate::{entity_path}mod;\n");

    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");

    // A stale fixture from a prior run would add findings and break the byte
    // equality below — `repo_with_config` does not clear the directory itself.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-agnostic-dirty"),
    );
    let dirty = repo_with_config("config-agnostic-dirty", &contents);

    // Both a Rust file and a non-Rust one, because that is what discriminates
    // the rules' `crates/**` glob from the `crates/**/*.rs` the marker rule uses:
    // rule 1 says *anywhere* under the crate, and a `*.rs` glob would wave the
    // second file straight through.
    let src = dirty.join("crates/demo/src");
    fs::create_dir_all(&src).expect("create fixture source tree");
    fs::write(src.join("lib.rs"), &payload).expect("write fixture source");
    fs::write(dirty.join("crates/demo/notes.txt"), &payload).expect("write fixture notes");

    let output = batten()
        .arg("check")
        .current_dir(&dirty)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a banned consumer shape under crates/ is a policy violation"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "crates/demo/notes.txt:1 no-consumer-account-literal\n\
         crates/demo/notes.txt:2 no-consumer-entity-path\n\
         crates/demo/src/lib.rs:1 no-consumer-account-literal\n\
         crates/demo/src/lib.rs:2 no-consumer-entity-path\n",
        "one sorted pointer per banned shape per file, and nothing else"
    );

    // The other half of the discriminator: the same rules must stay silent on a
    // tree that carries none of the shapes. A rule that fired on everything
    // would pass the case above and still be useless.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-agnostic-clean"),
    );
    let clean = repo_with_config("config-agnostic-clean", &contents);
    let ordinary = clean.join("crates/demo/src");
    fs::create_dir_all(&ordinary).expect("create clean source tree");
    fs::write(ordinary.join("lib.rs"), "pub fn ok() {}\n").expect("write clean source");

    let output = batten()
        .arg("check")
        .current_dir(&clean)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a clean tree is not a violation"
    );
    assert!(
        output.stdout.is_empty(),
        "a clean tree prints nothing, got: {}",
        String::from_utf8_lossy(&output.stdout)
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
        .args(["config", "show", "--json"])
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten config show");
    assert_eq!(output.status.code(), Some(0), "the example must load");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(value["version"]["value"], 1);

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
            .args(["config", "show", "--json"])
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
            .args(["config", "show", "--json"])
            .current_dir(&dir)
            .env_remove("BATTEN_STRICTNESS")
            .output()
            .expect("run batten config show")
    };
    let first = run();
    assert_eq!(first.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("config show stdout is JSON");
    assert_eq!(value["rule"]["value"][0]["severity"], "warn");
    assert_eq!(value["rule"]["value"][0]["scope"], "tree");
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
            .args(["config", "show", "--json"])
            .current_dir(&dir)
            .env_remove("BATTEN_STRICTNESS")
            .output()
            .expect("run batten config show");
        assert_eq!(output.status.code(), Some(0), "{label} must load");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("config show stdout is JSON");
        for rule in value["rule"]["value"].as_array().expect("rules in output") {
            let severity = rule["severity"].as_str().expect("severity token");
            assert!(
                ["allow", "warn", "deny"].contains(&severity),
                "{label}: severity {severity:?} outside the vocabulary"
            );
            // Derived from the vocabulary rather than pinned to `tree`: the
            // literal was correct while one scope existed, and would have had to
            // be edited by every change that adds one — which is the edit a
            // reviewer waves through. What matters is that the token is *in* the
            // vocabulary, never that it is one particular member.
            let scope = rule["scope"].as_str().expect("scope token");
            assert!(
                ["tree", "mediated_call"].contains(&scope),
                "{label}: scope {scope:?} outside the vocabulary"
            );
        }
    }
}
