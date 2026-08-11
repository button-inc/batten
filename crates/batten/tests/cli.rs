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

/// Every supported harness token, derived from `Harness::ALL`.
///
/// The five loops below used to hardcode `["claude-code", "exit-code"]`. That is
/// the same defect class the matrix's own totality test exists to prevent, one
/// level down: a third adapter would have landed with its fail-open leg, its
/// cross-channel leg and its malformed-payload leg all unexercised, while every
/// totality assertion still passed. Derived, so a new variant is covered the day
/// it is declared.
fn harnesses() -> Vec<&'static str> {
    batten::hook::Harness::ALL
        .iter()
        .map(|harness| harness.as_str())
        .collect()
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
    // Deduping the HARNESS column alone was not enough, and the gap was real: a
    // third adapter landing with a single `allow` row would have satisfied it
    // with its deny channel — the one thing this matrix exists to pin —
    // completely unexercised. So the assertion is over harness x case.
    let cases: Vec<&str> = {
        let mut seen: Vec<&str> = MATRIX.iter().map(|row| row.case).collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    };
    assert!(
        cases.contains(&"allow") && cases.contains(&"deny"),
        "the matrix must pin both an allow and a deny, or a channel goes unpinned"
    );

    let mut covered: Vec<(&str, &str)> = MATRIX.iter().map(|row| (row.harness, row.case)).collect();
    covered.sort_unstable();
    covered.dedup();
    let mut required: Vec<(&str, &str)> = harnesses()
        .into_iter()
        .flat_map(|harness| cases.iter().map(move |case| (harness, *case)))
        .collect();
    required.sort_unstable();
    assert_eq!(
        covered, required,
        "every declared harness needs a row for every case the matrix distinguishes"
    );
}

// --- the normalized event census (CLOUD-43) ---------------------------------
//
// The envelope carried an `event` field from CLOUD-202 and never dispatched on
// it: its one consumer echoed it into the deny document. So a `PostToolUse`
// payload carrying a banned command was adjudicated as though the call had not
// happened yet, and denied — a refusal of something already done, on an event no
// host offers a deny channel for.
//
// Golden rows per normalized event, and a census over `Event::ALL` so a new
// variant cannot land with its decision unexercised. That is the same defect
// class `the_matrix_covers_every_supported_harness` guards one level up.

/// One golden row: an event's host spelling, and what a banned command does at it.
struct EventRow {
    /// The normalized event this row pins.
    event: batten::hook::Event,
    /// The host's own spelling, as it appears in `hook_event_name`.
    spelling: &'static str,
    /// Whether policy adjudicates at this event at all.
    adjudicated: bool,
}

const EVENTS: &[EventRow] = &[
    EventRow {
        event: batten::hook::Event::PreTool,
        spelling: "PreToolUse",
        adjudicated: true,
    },
    EventRow {
        event: batten::hook::Event::PostTool,
        spelling: "PostToolUse",
        adjudicated: false,
    },
    EventRow {
        event: batten::hook::Event::Stop,
        spelling: "Stop",
        adjudicated: false,
    },
    EventRow {
        event: batten::hook::Event::SessionStart,
        spelling: "SessionStart",
        adjudicated: false,
    },
    EventRow {
        event: batten::hook::Event::Unrecognized,
        spelling: "SomethingThisBuildDoesNotKnow",
        adjudicated: false,
    },
];

/// A payload at a named event, carrying a command the committed policy bans.
fn payload_at(spelling: &str, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": spelling,
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

#[test]
fn every_normalized_event_resolves_to_its_golden_decision() {
    let dir = repo_with_gh_policy("event-census");
    for row in EVENTS {
        assert_eq!(
            batten::hook::Event::normalize(row.spelling),
            row.event,
            "{}: spelling does not normalize to the event it claims",
            row.spelling
        );
        for harness in harnesses() {
            let output = run_hook_in(
                &dir,
                harness,
                &payload_at(row.spelling, "gh pr merge 42"),
                false,
            );
            let at = format!("{harness}/{}", row.spelling);
            if row.adjudicated {
                // Pre-tool is the one event a deny can still prevent anything at.
                let denied = output.status.code() == Some(2)
                    || String::from_utf8_lossy(&output.stdout).contains("\"deny\"");
                assert!(
                    denied,
                    "{at}: a banned command must be denied before it runs"
                );
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{at}: a non-pre-tool event must not deny"
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).is_empty(),
                    "{at}: a non-pre-tool event emits no decision document"
                );
            }
        }
    }
}

#[test]
fn the_census_covers_every_normalized_event() {
    // Total, or the golden set is coverage rather than a contract: a variant
    // added to `Event::ALL` with no row would ship with its decision unpinned.
    let mut covered: Vec<&str> = EVENTS.iter().map(|row| row.event.as_str()).collect();
    covered.sort_unstable();
    covered.dedup();
    let mut required: Vec<&str> = batten::hook::Event::ALL
        .iter()
        .map(|event| event.as_str())
        .collect();
    required.sort_unstable();
    assert_eq!(
        covered, required,
        "every normalized event needs a golden row, or its decision is unexercised"
    );
    assert!(
        EVENTS.iter().any(|row| row.adjudicated),
        "a census where nothing is adjudicated would pass while policy did nothing"
    );
}

#[test]
fn the_deny_document_echoes_the_hosts_own_spelling_not_ours() {
    // The host reads its own vocabulary. Normalizing inward must not leak our
    // token back out, or the document names an event the host never emitted.
    let dir = repo_with_gh_policy("event-echo");
    let output = run_hook_in(
        &dir,
        "claude-code",
        &payload_at("PreToolUse", "gh pr merge 42"),
        false,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PreToolUse"), "got: {stdout}");
    assert!(
        !stdout.contains("pre-tool"),
        "the normalized token must not reach the host: {stdout}"
    );
}

#[test]
fn an_absent_session_degrades_to_per_invocation_without_panicking() {
    // The acceptance's second clause. A host that reports no session must be
    // adjudicated exactly as one that does — the deny is a function of the
    // command, and nothing here is keyed on a session yet.
    let dir = repo_with_gh_policy("session-absent");
    let with = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "abc123",
        "tool_name": "Bash",
        "tool_input": { "command": "gh pr merge 42" }
    })
    .to_string();
    let without = payload_at("PreToolUse", "gh pr merge 42");
    for harness in harnesses() {
        let a = run_hook_in(&dir, harness, &with, false);
        let b = run_hook_in(&dir, harness, &without, false);
        assert_eq!(
            a.status.code(),
            b.status.code(),
            "{harness}: an absent session must not change the verdict"
        );
        assert_eq!(a.stdout, b.stdout, "{harness}: nor the decision document");
    }
    // An empty string is absent, not a session: the two must not collapse, since
    // a consumer keyed on one hashes `Some("")` and `None` differently.
    let empty = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "",
        "tool_name": "Bash",
        "tool_input": { "command": "gh pr view 42" }
    })
    .to_string();
    assert_eq!(
        run_hook_in(&dir, "exit-code", &empty, false).status.code(),
        Some(0)
    );
}

#[test]
fn an_undecodable_payload_fails_open_loudly_and_never_denies() {
    // The acceptance's third clause. Failing open is right; failing open in
    // SILENCE is the false green — byte-identical to a clean allow, in the one
    // place nobody looks. Prefixed, because this is a statement about Batten
    // rather than a verdict.
    let dir = repo_with_gh_policy("undecodable");
    for harness in harnesses() {
        let output = run_hook_in(&dir, harness, "{not json at all", false);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{harness}: an undecodable payload must never deny"
        );
        assert!(
            stderr.contains("batten:") && stderr.contains("did not decode"),
            "{harness}: the fail-open must say so, got: {stderr}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).is_empty(),
            "{harness}: no decision document for a payload we could not read"
        );
    }
}

#[test]
fn a_quoted_invocation_denies_on_both_harness_channels() {
    // CLOUD-269's one intended tightening, asserted over the compiled binary
    // rather than only in-module: quoting the subcommand words is a real
    // `gh pr merge`, and the sentinel parser let it through because the span
    // never became tokens. Checked on both channels so the tightening is
    // pinned wherever a host reads its decision.
    let dir = repo_with_gh_policy("quoted-invocation");
    for harness in harnesses() {
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
    for harness in harnesses() {
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
    for harness in harnesses() {
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
    for harness in harnesses() {
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
    for harness in harnesses() {
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

// --- `batten exec`: the transparent passthrough (CLOUD-285) -------------------
//
// The verb house style §2 always listed and nothing built, which two Phase 2
// issues were waiting on. Three things pass through untouched — the child's argv,
// its streams, and its exit code — and the third is the one deliberate exception
// to the §7 table, so it is pinned rather than left to a reader's inference.

/// Run `batten exec` with the capture store isolated under a scratch HOME.
///
/// Without the isolation these tests write captures into the developer's real
/// state dir — harmless but untidy, and it would make one test's store visible to
/// another. The env keys are the receipt suite's, for the same reason.
fn exec_cmd(name: &str, args: &[&str]) -> (Output, PathBuf) {
    let home = scratch(name);
    fs::create_dir_all(&home).expect("create home");
    let output = batten()
        .args(args)
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .expect("run batten exec");
    (output, home)
}

/// Every file under a scratch home's capture store, sorted.
fn captures_in(home: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let root = home.join("data");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                found.push(name.to_owned());
            }
        }
    }
    found.sort();
    found
}

/// A `#!/bin/sh` fixture child, executable, that runs `body`.
///
/// The `tests/doctor.rs` idiom. Unix-only: `PermissionsExt` is the only portable
/// way to set the mode, so these cases skip on Windows rather than fail there
/// (CLOUD-113 owns the real matrix).
#[cfg(unix)]
fn child_script(name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch(name);
    fs::create_dir_all(&dir).expect("create dir");
    let script = dir.join("child.sh");
    fs::write(&script, format!("#!/bin/sh\n{body}\n")).expect("write child");
    let mut mode = fs::metadata(&script).expect("stat child").permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&script, mode).expect("chmod child");
    script
}

#[cfg(unix)]
#[test]
fn exec_passes_through_a_code_outside_the_table() {
    // The exception, stated as a test so it cannot be mistaken for a bug. §7's
    // table is 0/1/2/3; a wrapped command's code is not Batten's to choose, and
    // reporting `7` as anything else would make the wrapper lie.
    let script = child_script("exec-codes", "exit \"$1\"");
    for code in [0, 1, 2, 3, 7, 42, 255] {
        let output = batten()
            .args([
                "exec",
                "--",
                script.to_str().expect("utf-8"),
                &code.to_string(),
            ])
            .output()
            .expect("run batten exec");
        assert_eq!(
            output.status.code(),
            Some(code),
            "the child's code must survive unchanged"
        );
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "a transparent verb adds no output of its own"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_exec_two_is_the_childs_verdict_not_battens() {
    // `2` is the policy verdict everywhere Batten *renders* one. Here it came from
    // the child, and no mediation path can reach it: `hook` adjudicates a mediated
    // call, and `exec` is not reachable from `hook`. Pinned because a host reading
    // codes alone could otherwise take a wrapped command's `2` for a deny.
    let script = child_script("exec-two", "exit 2");
    let (output, _) = exec_cmd(
        "exec-two-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.is_empty(),
        "Batten renders no reason, because it rendered no verdict"
    );
}

#[cfg(unix)]
#[test]
fn exec_hands_the_child_its_own_argv_including_battens_own_flag_spellings() {
    // The hazard the §3 ladder created: without `allow_hyphen_values` a child's
    // `-v` is parsed as Batten's verbosity rung, so the flag the caller meant for
    // `cargo` vanishes and Batten gets louder for no reason anyone typed.
    let script = child_script("exec-argv", r#"printf '%s\n' "$@""#);
    let output = batten()
        .args([
            "exec",
            "--",
            script.to_str().expect("utf-8"),
            "-v",
            "--json",
            "--silent",
            "--strictness",
            "strict",
        ])
        .output()
        .expect("run batten exec");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "-v\n--json\n--silent\n--strictness\nstrict\n",
        "every token after `--` reaches the child verbatim"
    );
    assert!(
        output.stderr.is_empty(),
        "and none of them moved Batten's own verbosity rung"
    );
}

#[cfg(unix)]
#[test]
fn exec_inherits_both_child_streams_unchanged() {
    let script = child_script("exec-streams", "echo out; echo err >&2");
    let (output, _) = exec_cmd(
        "exec-streams-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "err\n");
}

#[test]
fn no_exec_failure_path_can_deny() {
    // The property fail-open actually rests on: Batten never MINTS a `2` here.
    // Whatever goes wrong with the invocation is a statement about the invocation,
    // so it is exit 1 — loud, and not a verdict a host can read as a refusal.
    let cases: [&[&str]; 2] = [
        // A program that is not there.
        &["exec", "--", "batten-no-such-program-exists"],
        // The separator omitted: `--` is mandatory precisely so the ladder scan
        // can tell Batten's argv from the child's.
        &["exec", "sh", "-c", "true"],
    ];
    for args in cases {
        let (output, _) = exec_cmd("exec-failopen-home", args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?} must be a usage error"
        );
        assert_ne!(
            output.status.code(),
            Some(2),
            "{args:?} must never be reported as a policy verdict"
        );
        assert!(!output.stderr.is_empty(), "{args:?}: exit 1 is fail-loud");
    }
}

#[test]
fn a_trailing_arg_takes_values_in_the_emitted_spec() {
    // `takes_value` is a hand-maintained expression over clap's actions, and it
    // has already been wrong once for a newly added action (`Count`, CLOUD-42).
    // A trailing variadic consumes every remaining token, so `true` is the honest
    // answer and a completion script depends on it.
    let dir = scratch("exec-spec");
    fs::create_dir_all(&dir).expect("create dir");
    let document: serde_json::Value =
        serde_json::from_slice(&batten_with(&dir, &["spec"], &[]).stdout).expect("spec is JSON");
    let exec = document["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "exec")
        .expect("exec is in the spec");
    let command = exec["flags"]
        .as_array()
        .expect("flags")
        .iter()
        .find(|flag| flag["name"] == "command")
        .expect("exec declares its trailing argument");
    assert_eq!(command["takes_value"], serde_json::json!(true));
    // A positional: no long, no short.
    assert_eq!(command["long"], serde_json::json!(null));
    assert_eq!(command["short"], serde_json::json!(null));
}

// --- the capture primitive (CLOUD-162) ---------------------------------------

#[cfg(unix)]
#[test]
fn a_captured_run_still_hands_the_caller_the_childs_own_bytes() {
    // The property that governs the whole design. Capture had to be a TEE: a plain
    // capture would replace inheritance with a pipe and silently change what every
    // wrapped command's caller sees. This is the same assertion
    // `exec_inherits_both_child_streams_unchanged` makes, restated here because it
    // is what the capture must not break.
    let script = child_script("capture-tee", "echo out; echo err >&2; exit 5");
    let (output, home) = exec_cmd(
        "capture-tee-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert_eq!(output.status.code(), Some(5), "the child's code survives");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out\n");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "err\n",
        "no handle, no pointer, no bookkeeping — stderr is the child's"
    );
    // And both streams were nonetheless stored.
    let stored = captures_in(&home);
    assert_eq!(stored.len(), 2, "one record per stream, got {stored:?}");
    assert!(stored.iter().any(|name| name.starts_with("stdout-")));
    assert!(stored.iter().any(|name| name.starts_with("stderr-")));
}

#[cfg(unix)]
#[test]
fn a_capture_is_content_addressed_so_an_identical_rerun_adds_nothing() {
    // Acceptance: "re-running over identical child output yields a byte-identical
    // capture and digest." Content addressing makes that structural rather than a
    // promise — the digest IS the key, so identical bytes are one record.
    let script = child_script("capture-stable", "echo same");
    let argv = ["exec", "--", script.to_str().expect("utf-8")];

    let home = scratch("capture-stable-home");
    fs::create_dir_all(&home).expect("create home");
    let run_once = || {
        batten()
            .args(argv)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("data"))
            .output()
            .expect("run batten exec")
    };

    run_once();
    let first = captures_in(&home);
    run_once();
    let second = captures_in(&home);
    assert_eq!(
        first, second,
        "identical output must not mint a second record"
    );
    assert_eq!(first.len(), 2);
}

#[cfg(unix)]
#[test]
fn different_output_is_a_different_capture() {
    // The other direction: content addressing is only useful if it discriminates.
    let home = scratch("capture-differs-home");
    fs::create_dir_all(&home).expect("create home");
    for body in ["echo one", "echo two"] {
        let script = child_script(&format!("capture-differs-{}", body.len()), body);
        batten()
            .args(["exec", "--", script.to_str().expect("utf-8")])
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("data"))
            .output()
            .expect("run batten exec");
    }
    let stored = captures_in(&home);
    let stdouts = stored
        .iter()
        .filter(|name| name.starts_with("stdout-"))
        .count();
    assert_eq!(
        stdouts, 2,
        "two different outputs are two records: {stored:?}"
    );
}

#[cfg(unix)]
#[test]
fn an_empty_stream_is_still_captured() {
    // "The command said nothing" is an answer, and it must be distinguishable
    // from a run nobody captured — otherwise a consumer cannot tell a silent
    // success from a missing record.
    let script = child_script("capture-empty", "true");
    let (output, home) = exec_cmd(
        "capture-empty-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert_eq!(output.status.code(), Some(0));
    let stored = captures_in(&home);
    assert_eq!(
        stored.len(),
        2,
        "both streams recorded even when empty: {stored:?}"
    );
}

#[test]
fn the_capture_digest_is_the_one_hashing_discipline() {
    // Asserted against a hand-computed preimage rather than a golden string, so
    // this fails if the construction changes rather than merely recording whatever
    // it currently produces. The framing is a domain tag then each field, every
    // part length-prefixed as u64 LE — the same one every finding identity and the
    // config epoch go through.
    use sha2::{Digest, Sha256};
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    field(&mut hasher, b"capture");
    field(&mut hasher, b"stdout");
    field(&mut hasher, b"hello\n");
    let expected = hasher
        .finalize()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            // `write!` into a String cannot fail; the result is consumed so clippy's
            // format-collect lint is satisfied without an allocation per byte.
            let _ = write!(hex, "{byte:02x}");
            hex
        });

    assert_eq!(
        batten::identity::capture_fingerprint("stdout", b"hello\n").to_hex(),
        expected,
        "a capture digest must be the one length-prefixed, tagged construction"
    );
}

#[test]
fn a_capture_handle_is_what_a_log_anchored_finding_joins_on() {
    // CLOUD-162's own words: "a log-anchored finding's evidence pointer is
    // `capture_handle:byte_range` into this capture". `log_fingerprint` was landed
    // and unused; the capture handle is the `source_key` that makes it real.
    let capture = batten::capture::Capture {
        stream: "stdout",
        bytes: 6,
        digest: batten::identity::capture_fingerprint("stdout", b"hello\n").to_hex(),
    };
    let handle = capture.handle();
    assert!(handle.starts_with("stdout:"));

    let joined = batten::identity::log_fingerprint("a-rule", &handle, "a-pattern");
    // The join is a function of the handle: a different capture is a different
    // finding identity, which is what stops two runs' findings deduplicating.
    let other = batten::identity::log_fingerprint("a-rule", "stdout:different", "a-pattern");
    assert_ne!(joined.to_hex(), other.to_hex());
}

// --- exec output predicates (CLOUD-117) ---------------------------------------
//
// A command can lie about completion: exit 0 while its own output says otherwise.
// A declared literal in that output promotes the lying 0 to a failure — always,
// with no severity tier, because a finding that exits 0 is invisible to the only
// surface an agent reads.

/// A repo with a committed authority carrying `patterns`, plus an isolated store.
#[cfg(unix)]
fn exec_pattern_repo(name: &str, patterns: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(&format!("version = 1\n{patterns}"))
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// One committed pattern over both streams.
#[cfg(unix)]
const ONE_PATTERN: &str = "\n[[exec_pattern]]\nid = \"lying-zero\"\n                           pattern = \"warning[duplicate]\"\nstream = \"both\"\n                           reason = \"configure the tool to fail instead\"\n";

#[cfg(unix)]
fn run_exec(repo: &std::path::Path, home: &std::path::Path, script: &str) -> Output {
    batten()
        .args(["exec", "--", "sh", "-c", script])
        .current_dir(repo)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten exec")
}

#[cfg(unix)]
#[test]
fn an_exit_zero_child_whose_output_matches_is_promoted_to_a_failure() {
    let (repo, home) = exec_pattern_repo("exec-pred-match", ONE_PATTERN);
    let output = run_exec(&repo, &home, "echo 'warning[duplicate] serde'");
    assert_eq!(output.status.code(), Some(1));
    let report = String::from_utf8_lossy(&output.stderr);
    // Pointer-only: stream, line, and the pattern id — the same `path:line rule-id`
    // shape `check` emits, so a caller needs no second parser.
    assert!(report.contains("stdout:1 lying-zero"), "got {report}");
    assert!(report.contains("1 output match(es)"));
    assert!(report.contains("configure the tool to fail instead"));
}

#[cfg(unix)]
#[test]
fn the_refusal_never_echoes_the_line_that_matched() {
    // A wrapped command's output is the likeliest place in this whole engine for a
    // secret to appear, which is what makes pointer-only load-bearing here rather
    // than stylistic. The child's own stdout still carries it — that is the
    // child's channel — but Batten's report must not repeat it.
    let (repo, home) = exec_pattern_repo("exec-pred-pointer", ONE_PATTERN);
    let output = run_exec(&repo, &home, "echo 'warning[duplicate] SUPERSECRET'");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("SUPERSECRET"),
        "the refusal echoed the matched line"
    );
}

#[cfg(unix)]
#[test]
fn an_exit_zero_child_with_no_match_is_still_clean() {
    let (repo, home) = exec_pattern_repo("exec-pred-clean", ONE_PATTERN);
    let output = run_exec(&repo, &home, "echo 'all good'");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "all good\n");
    assert!(output.stderr.is_empty(), "a clean run says nothing");
}

#[cfg(unix)]
#[test]
fn batten_only_adds_failure_so_a_non_zero_child_is_untouched() {
    // There is nothing to promote, and re-deciding a failure Batten did not
    // diagnose would make the wrapper's verdict unreadable. The child's own code
    // survives even though its output matches.
    let (repo, home) = exec_pattern_repo("exec-pred-nonzero", ONE_PATTERN);
    let output = run_exec(&repo, &home, "echo 'warning[duplicate] x'; exit 7");
    assert_eq!(
        output.status.code(),
        Some(7),
        "a child that already failed passes its code through"
    );
}

#[cfg(unix)]
#[test]
fn a_pattern_scoped_to_one_stream_does_not_fire_on_the_other() {
    let stderr_only = "\n[[exec_pattern]]\nid = \"err-only\"\npattern = \"boom\"\n                       stream = \"stderr\"\nreason = \"look at stderr\"\n";
    let (repo, home) = exec_pattern_repo("exec-pred-stream", stderr_only);
    assert_eq!(
        run_exec(&repo, &home, "echo boom").status.code(),
        Some(0),
        "a stderr-scoped pattern must ignore stdout"
    );
    assert_eq!(
        run_exec(&repo, &home, "echo boom >&2").status.code(),
        Some(1),
        "and must fire on stderr"
    );
}

#[cfg(unix)]
#[test]
fn every_match_is_reported_not_only_the_first() {
    let (repo, home) = exec_pattern_repo("exec-pred-all", ONE_PATTERN);
    let output = run_exec(
        &repo,
        &home,
        "echo 'warning[duplicate] a'; echo ok; echo 'warning[duplicate] b'",
    );
    assert_eq!(output.status.code(), Some(1));
    let report = String::from_utf8_lossy(&output.stderr);
    assert!(report.contains("stdout:1 lying-zero"), "got {report}");
    assert!(report.contains("stdout:3 lying-zero"), "got {report}");
    assert!(report.contains("2 output match(es)"));
}

#[cfg(unix)]
#[test]
fn exec_still_runs_where_no_authority_is_configured() {
    // `exec` is a wrapper a caller puts in front of arbitrary commands, most of
    // them outside a Batten repository. Refusing there would make the wrapper the
    // reason ordinary work stops — the same reading `hook` takes for its policy.
    let home = scratch("exec-pred-no-authority");
    fs::create_dir_all(&home).expect("create home");
    let elsewhere = scratch("exec-pred-elsewhere");
    fs::create_dir_all(&elsewhere).expect("create dir");
    let _ = fs::remove_file(elsewhere.join("batten.toml"));
    let output = batten()
        .args(["exec", "--", "sh", "-c", "echo fine"])
        .current_dir(&elsewhere)
        .env("HOME", &home)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .expect("run batten exec");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "fine\n");
}

#[cfg(unix)]
#[test]
fn an_unreadable_authority_stops_exec_rather_than_silently_ungating_it() {
    // The mirror of the case above, and the reason it is not fail-open: a pattern
    // table nobody could parse is a gate that silently did not run.
    let (repo, home) = exec_pattern_repo("exec-pred-broken", ONE_PATTERN);
    fs::write(repo.join("batten.toml"), "version = 1\nbogus = true\n").expect("break the config");
    let output = run_exec(&repo, &home, "echo fine");
    assert_eq!(output.status.code(), Some(1));
    assert_ne!(
        output.status.code(),
        Some(2),
        "an unreadable authority is a usage error, never a policy verdict"
    );
    assert!(!output.stderr.is_empty(), "exit 1 is fail-loud");
}

#[cfg(unix)]
#[test]
fn a_local_file_may_add_a_pattern_but_not_redefine_a_committed_one() {
    // Raise-only (§8): adding a pattern is one more way for a lying command to be
    // caught, so it is tightening. Redefining one could narrow its stream or alter
    // its literal, and Batten cannot tell that from a fix — so it is refused.
    let (repo, home) = exec_pattern_repo("exec-pred-local", ONE_PATTERN);
    fs::write(
        repo.join("batten.local.toml"),
        "version = 1\n\n[[exec_pattern]]\nid = \"local-extra\"\npattern = \"deprecated\"\n         stream = \"both\"\nreason = \"stop using it\"\n",
    )
    .expect("write local");
    assert_eq!(
        run_exec(&repo, &home, "echo 'deprecated api'")
            .status
            .code(),
        Some(1),
        "a locally added pattern is a gate the run applies"
    );

    fs::write(
        repo.join("batten.local.toml"),
        "version = 1\n\n[[exec_pattern]]\nid = \"lying-zero\"\npattern = \"never\"\n         stream = \"both\"\nreason = \"weaken it\"\n",
    )
    .expect("write local");
    let output = run_exec(&repo, &home, "echo fine");
    assert_eq!(output.status.code(), Some(1), "redefining is refused");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("may not redefine"),
        "the refusal says why"
    );
}

// --- the machine-output contract, as a derived census (CLOUD-41) -------------
//
// House-style §6-§7 says stdout is the answer and stderr is the messaging, that a
// data document is byte-stable, and that it is emitted whole or not at all. Those
// properties were already asserted sixteen times over — once per surface, by
// hand, in six different files. That is coverage, not a contract: the next `-J`
// verb inherits the flag census in `surface.rs` and none of the document
// properties, which is exactly how `receipt status -J` shipped in CLOUD-42 with a
// declared data channel and zero assertions about what it emits.
//
// So the suite is derived from the same `data_channel` column the flag census
// reads. A verb that declares the channel is held to the document contract the
// day its row lands, with no edit here.

/// A git repo with a committed authority, isolated state dir, and a work commit —
/// enough for every `data_channel` verb to have something real to answer about.
///
/// `config epoch` needs readable tracked paths, `receipt status` needs a repo with
/// `origin/main`, and `check`/`enforce`/`config *` need an authority. One fixture
/// satisfying all of them beats a per-verb table that would drift.
fn census_fixture(name: &str) -> (PathBuf, PathBuf) {
    // Shaped like `receipt_fixture`, but with a config every data-emitting verb
    // can actually answer from. `policy budget` is the reason it diverged: a
    // budget verb whose config declares no budget measured nothing, and it
    // refuses (exit 1) rather than reporting a `0` it did not earn — so a
    // fixture carrying `version = 1` alone would make the census assert about a
    // usage error instead of about a document. The census is about the output
    // contract; supplying each verb's minimum input is the fixture's job, the
    // same way `census_argv` supplies `receipt status` its positional.
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n[budget.instructions]\npaths = [\"AGENTS.md\"]\nmax_tokens = 1000\n")
        .file("AGENTS.md", "instructions\n")
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// The minimal argv that makes `decl` emit its document.
///
/// Derived from the declaration rather than listed: the path, then a placeholder
/// for each required positional, then `-J`. The placeholder is a valid check name
/// because the one positional across every data-emitting verb today is `receipt
/// status <check>`; the assertion below fails loudly if a second one ever appears,
/// rather than silently passing a nonsense value to it.
fn census_argv(decl: &batten::surface::CommandDecl) -> Vec<String> {
    let positionals: Vec<&batten::surface::FlagDecl> =
        decl.flags.iter().filter(|flag| flag.positional).collect();
    assert!(
        positionals.len() <= 1,
        "{}: more than one positional — the census placeholder needs revisiting",
        decl.path
    );
    let mut argv: Vec<String> = decl.path.split(' ').map(ToOwned::to_owned).collect();
    for _ in &positionals {
        argv.push("verify".to_owned());
    }
    argv.push("-J".to_owned());
    argv
}

/// Every verb that declares the `-J` data channel.
fn data_channel_verbs() -> Vec<&'static batten::surface::CommandDecl> {
    let verbs: Vec<&batten::surface::CommandDecl> = batten::surface::SURFACE
        .iter()
        .filter(|decl| decl.data_channel)
        .collect();
    assert!(
        !verbs.is_empty(),
        "the census is vacuous — no row declares a data channel"
    );
    verbs
}

#[test]
fn every_data_channel_verb_emits_one_pure_json_document() {
    // Acceptance: "JSON mode emits pure JSON on stdout for every subcommand."
    // Purity is the load-bearing half — a single line of messaging mixed into
    // stdout makes the document unparseable for the caller that asked for it.
    let (repo, home) = census_fixture("census-purity");
    for decl in data_channel_verbs() {
        let owned = census_argv(decl);
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        let output = receipt_cmd(&repo, &home, &argv);
        assert!(
            !output.stdout.is_empty(),
            "{}: a data channel emits its document unconditionally, including \
             when the answer is empty — JSON that is sometimes absent is unparseable",
            decl.path
        );
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&output.stdout);
        assert!(
            parsed.is_ok(),
            "{} -J stdout is not one JSON document: {}",
            decl.path,
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn every_data_channel_verb_is_byte_stable_across_runs() {
    // Acceptance: "re-running the same command with the same input under --json
    // yields byte-identical stdout." No timestamps, no durations, no ordering
    // nondeterminism — the property that makes a golden file possible at all
    // (CLOUD-106 mechanises it from here).
    let (repo, home) = census_fixture("census-stable");
    for decl in data_channel_verbs() {
        let owned = census_argv(decl);
        let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
        let first = receipt_cmd(&repo, &home, &argv).stdout;
        let second = receipt_cmd(&repo, &home, &argv).stdout;
        assert_eq!(
            first, second,
            "{} -J is not byte-stable across two identical runs",
            decl.path
        );
    }
}

#[test]
fn no_ladder_rung_can_change_a_data_document() {
    // The structural guarantee, asserted against real documents rather than only
    // against `spec`. `Mode` is consumed in `output` and in `main`; the
    // data-emitting functions take `out: &mut dyn Write` and have no `Mode` to
    // consult, so no rung can reach stdout. This is what makes `-J` safe to hand
    // to a parser regardless of what the wrapper script passed.
    let (repo, home) = census_fixture("census-ladder");
    for decl in data_channel_verbs() {
        let base: Vec<String> = census_argv(decl);
        let baseline = {
            let argv: Vec<&str> = base.iter().map(String::as_str).collect();
            receipt_cmd(&repo, &home, &argv).stdout
        };
        for rung in ["--silent", "-q", "-vv", "--trace", "--no-color"] {
            let mut argv: Vec<&str> = vec![rung];
            argv.extend(base.iter().map(String::as_str));
            assert_eq!(
                receipt_cmd(&repo, &home, &argv).stdout,
                baseline,
                "{}: {rung} changed the answer channel",
                decl.path
            );
        }
    }
}

#[test]
fn no_progress_reaches_stderr_when_it_is_not_a_terminal() {
    // Acceptance (d): "progress never appears when not on a TTY." A test's stderr
    // is a pipe, so §4 resolves to machine mode and the default rung admits no
    // progress — stderr stays empty for a clean run.
    //
    // The complement is what keeps this honest rather than vacuous: asking for a
    // rung explicitly DOES produce output, even piped, because the caller asked.
    // The property is that unrequested decoration never appears, not that stderr
    // is unreachable.
    let (repo, home) = census_fixture("census-progress");
    for decl in data_channel_verbs() {
        let base: Vec<String> = census_argv(decl);
        let argv: Vec<&str> = base.iter().map(String::as_str).collect();
        let quiet = receipt_cmd(&repo, &home, &argv);
        assert!(
            quiet.stderr.is_empty(),
            "{}: a clean piped run must print no progress, got {}",
            decl.path,
            String::from_utf8_lossy(&quiet.stderr)
        );
    }

    // Asked for, and therefore delivered — so the assertion above is a statement
    // about the default, not about an unreachable channel.
    let mut verbose: Vec<&str> = vec!["-v"];
    verbose.extend(["spec"]);
    let asked = receipt_cmd(&repo, &home, &verbose);
    assert!(
        !asked.stderr.is_empty(),
        "an explicitly requested rung must still reach a piped stderr"
    );
}

#[test]
fn receipt_status_json_names_the_pointer_lines_tokens() {
    // The specific gap this issue closes: `receipt status -J` landed in CLOUD-42
    // and every receipt test used the pointer form, so a declared data channel
    // shipped with nothing asserting its shape. The census above covers purity
    // and stability; this covers the field names a consumer actually reads.
    let (repo, home) = census_fixture("census-receipt");
    let output = receipt_cmd(&repo, &home, &["receipt", "status", "verify", "-J"]);
    // Missing receipt: a policy verdict, and the document is still emitted.
    assert_eq!(output.status.code(), Some(2));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("receipt status -J is JSON");
    assert_eq!(document["check"], serde_json::json!("verify"));
    assert_eq!(document["verdict"], serde_json::json!("missing"));
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    assert_eq!(document["head"], serde_json::json!(head));

    // The same three tokens the human channel concatenates, so the two renderings
    // cannot drift apart.
    let (_, pointer) = receipt_status(&repo, &home, "verify");
    assert_eq!(pointer.trim(), format!("verify {head} missing"));
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

// --- `policy budget` (CLOUD-50) -----------------------------------------------
//
// The gate over what every agent pays on every turn. The shell task this
// replaced counted lines and tokens the same way; what the engine adds is a
// refusal for a dead entry, a `<=` boundary, and silence on success.

/// A fixture whose instruction file loads to *exactly* `tokens` estimated
/// tokens: the estimator is bytes/4, so 4 bytes per token, and a trailing
/// newline is one of them.
fn instructions_of(tokens: usize) -> String {
    let mut body = "x".repeat(tokens * 4);
    body.pop();
    body.push('\n');
    body
}

fn budget_config(paths: &str, max_tokens: usize) -> String {
    format!("version = 1\n[budget.instructions]\npaths = {paths}\nmax_tokens = {max_tokens}\n")
}

#[test]
fn a_set_over_budget_exits_2_and_reports_the_files_the_total_and_the_budget() {
    let dir = repo_with_config("budget-over", &budget_config("[\"AGENTS.md\"]", 100));
    common::write(&dir, "AGENTS.md", &instructions_of(150));

    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "over budget is a policy verdict"
    );

    let text = common::stdout(&output);
    // Per-file pointer line, then the total and the budget it was judged
    // against. Counts and a path — never a byte of what was counted.
    assert!(
        text.contains("AGENTS.md ~150 tokens"),
        "the report must carry the per-file line: {text:?}"
    );
    assert!(
        text.contains("~150 tokens of 100"),
        "the report must carry the total and the budget: {text:?}"
    );
    assert!(
        !text.contains("xxxx"),
        "the report must never carry the measured content: {text:?}"
    );
}

#[test]
fn exactly_at_budget_exits_0_with_empty_stdout() {
    // The boundary is `<=`, and success is silent (§6): a clean run's cheapest
    // possible signal is no bytes at all.
    let dir = repo_with_config("budget-at", &budget_config("[\"AGENTS.md\"]", 100));
    common::write(&dir, "AGENTS.md", &instructions_of(100));

    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "exactly at budget is within it"
    );
    assert_eq!(common::stdout(&output), "", "success prints nothing");
}

#[test]
fn one_entry_matching_nothing_is_exit_1_even_when_its_siblings_match() {
    // CLOUD-298's defect class: a dead glob contributing nothing while the rest
    // counted, so the gate measured less than it claimed and still reported
    // green. Per entry, never per set.
    let dir = repo_with_config(
        "budget-dead-entry",
        &budget_config("[\"AGENTS.md\", \"memories/always/*.md\"]", 10_000),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(10));

    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a dead entry is a config error, not a verdict and never a pass"
    );
    assert!(
        common::stderr(&output).contains("memories/always/*.md"),
        "the refusal must name the entry that matched nothing"
    );
}

#[test]
fn two_runs_over_the_same_tree_emit_identical_bytes() {
    let dir = repo_with_config("budget-stable", &budget_config("[\"AGENTS.md\"]", 10));
    common::write(&dir, "AGENTS.md", &instructions_of(50));

    let first = common::run(&dir, &["policy", "budget", "--json"]);
    let second = common::run(&dir, &["policy", "budget", "--json"]);
    assert_eq!(first.stdout, second.stdout, "the document is byte-stable");
    assert_eq!(first.status.code(), second.status.code());
    // The data channel emits unconditionally, including for a run within
    // budget, so a caller parsing it never sees an absent document.
    let clean = repo_with_config(
        "budget-stable-clean",
        &budget_config("[\"AGENTS.md\"]", 500),
    );
    common::write(&clean, "AGENTS.md", &instructions_of(50));
    let json = common::run(&clean, &["policy", "budget", "--json"]);
    assert_eq!(json.status.code(), Some(0));
    assert!(
        common::stdout(&json).contains("\"tokens\": 50"),
        "a clean run still emits its document"
    );
}

#[test]
fn frontmatter_and_comment_bytes_alone_never_cross_the_budget() {
    // Stripped constructs cost nothing: the loader drops both before the file
    // reaches a context window, so a gate that charged for them could fail for
    // a construct no agent pays for.
    let dir = repo_with_config("budget-stripped", &budget_config("[\"AGENTS.md\"]", 10));
    let padding = "x".repeat(4_000);
    common::write(
        &dir,
        "AGENTS.md",
        &format!("---\ntitle: {padding}\n---\n<!--\n{padding}\n-->\nkept\n"),
    );

    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "frontmatter and block comments are free: {:?}",
        common::stdout(&output)
    );
}

#[test]
fn a_config_declaring_no_budget_is_a_usage_error_not_a_silent_pass() {
    // A budget verb that measured nothing must not report `0`. That is the
    // false green the whole engine exists to catch.
    let dir = repo_with_config("budget-undeclared", "version = 1\n");
    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(common::stderr(&output).contains("budget.instructions"));
}

#[test]
fn this_repos_own_budget_is_pinned_so_raising_it_is_a_visible_diff() {
    // The acceptance's "pinned deliberately". These numbers are the bar the
    // deleted `mise-tasks/context-budget` carried, restated for a `<=`
    // boundary — the shell gate failed AT 200 lines, so 199 is the same bar.
    // Changing either one means changing this test in the same diff, which is
    // what makes the change a decision rather than a drift.
    let committed = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("batten.toml"),
    )
    .expect("this repository's own config");
    let config: toml::Value = toml::from_str(&committed).expect("the authority parses");
    let instructions = &config["budget"]["instructions"];

    assert_eq!(instructions["max_tokens"].as_integer(), Some(3500));
    assert_eq!(instructions["max_lines"].as_integer(), Some(199));
    assert_eq!(
        instructions["paths"].as_array().map(Vec::len),
        Some(1),
        "the counted set is AGENTS.md alone; adding an always-load surface is a \
         decision that shows up here"
    );
}
