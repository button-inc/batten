//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
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
/// and `Usage` (2) for malformed input or bad config. `Violation` (1) is reached
/// by `check` when a rule fires; because that needs source files placed beside
/// the config, it is exercised in the dedicated `check_*` tests below rather than
/// this config-only table. `Internal` (3) has no command that reaches it at this
/// stage: its numeric contract is pinned in the `exit` unit tests (the `hook`
/// exit-2-denies inversion is CLOUD-40).
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
            expected: 2,
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
            expected: 2,
        },
        Case {
            name: "config show, unsupported version → usage",
            args: &["config", "show"],
            config: Some("version = 2\n"),
            expected: 2,
        },
        Case {
            name: "config show, unknown key → usage",
            args: &["config", "show"],
            config: Some("version = 1\nbogus = true\n"),
            expected: 2,
        },
        Case {
            name: "config show, missing config → usage",
            args: &["config", "show"],
            config: None,
            expected: 2,
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
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\n",
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
fn check_violation_exits_one_with_pointer_only_output() {
    let dir = repo_with_config(
        "check-violation",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\n",
    );
    fs::write(dir.join("lib.rs"), "fine\nTODO fix this\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(1), "a finding is a violation");
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
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\n",
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
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\n",
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
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(enforce.status.code(), Some(1));
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
const COMMAND_RULE_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"false\"\n";

#[test]
fn check_refuses_a_command_rule_rather_than_skipping_it() {
    // The CLOUD-170 split, end to end: the read-effect verb must refuse (exit
    // 2) — never exit 0 having quietly skipped the gate.
    let dir = repo_with_config("cmd-check-refuses", COMMAND_RULE_CONFIG);
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
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
        Some(1),
        "a non-zero command exit is a violation"
    );
    // Rule-scoped pointer: no invented line number, and never the command output.
    assert_eq!(String::from_utf8_lossy(&output.stdout), "**/*.rs dyn\n");
}

#[test]
fn enforce_passes_when_the_command_exits_zero() {
    let dir = repo_with_config(
        "cmd-enforce-pass",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"true\"\n",
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
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"definitely-not-a-real-binary-xyz\"\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a command that cannot run is a config error, never a silent pass"
    );
}

#[test]
fn command_rule_with_no_glob_match_is_skipped_without_spawning() {
    // The glob gates first (§4): the missing binary would be a usage error if
    // it were ever reached, so exit 0 proves nothing spawned.
    let dir = repo_with_config(
        "cmd-no-match",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"definitely-not-a-real-binary-xyz\"\n",
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
        "version = 1\n\n[[rule]]\nid = \"x\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"y\"\nbogus = true\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
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
    // policy, never lower it. Exit 2 — bad input, not a silently applied edit.
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
    assert_eq!(output.status.code(), Some(2));
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
            Some(2),
            "a weakening {label} override must be refused"
        );
    }
}

#[test]
fn a_local_override_may_add_a_rule_but_not_redefine_one() {
    let config = "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\n";
    let dir = repo_with_config("config-local-rules", config);
    fs::write(dir.join("lib.rs"), "FIXME later\n").expect("write source");

    // Adding a rule tightens policy, and the added gate really runs.
    with_local_config(
        &dir,
        "version = 1\n\n[[rule]]\nid = \"no-fixme\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"FIXME\"\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(1), "the added rule must fire");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "lib.rs:1 no-fixme\n"
    );

    // Redefining a committed rule could weaken it, so it is refused outright.
    with_local_config(
        &dir,
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"nothing/**\"\npattern = \"TODO\"\n",
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("may not redefine"),
        "the refusal must name the redefinition"
    );
}

#[test]
fn bare_invocation_lists_subcommands() {
    // §2: bare invocation lists subcommands and never performs a default
    // action. clap renders the listing on its error path — stderr, exit 2 —
    // so a script can never mistake the listing for a successful run's answer.
    let output = batten().output().expect("run batten");
    assert_eq!(output.status.code(), Some(2));
    let listing = String::from_utf8_lossy(&output.stderr);
    for verb in ["check", "enforce", "config", "spec"] {
        assert!(listing.contains(verb), "the listing must name `{verb}`");
    }
    assert!(
        output.stdout.is_empty(),
        "stdout is the answer channel; a bare invocation has no answer"
    );
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
        Some(1),
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
}
