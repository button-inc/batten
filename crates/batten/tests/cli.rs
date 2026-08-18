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
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, StateHome, batten, git_in, scratch, scratch_outside_tree, stderr, stdout};

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

/// The `gh` lifecycle shape rows a hook fixture adjudicates against.
///
/// A `const` rather than an inline literal so the refusal-contract census
/// (`every_hook_policy_table_deny_names_its_fix`) can count the rows it owes a
/// case for. A table whose coverage is asserted against a hand-written number is
/// the same defect the decision matrix's own totality test exists to prevent.
const GH_POLICY_CONFIG: &str = r#"version = 1
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
"#;

/// A fixture repo whose `batten.toml` carries the `gh` lifecycle shape rows.
///
/// Since CLOUD-48 the policy is config, not Rust, so a hook test that wants a
/// deny has to supply one. Deliberately *not* this repo's own `batten.toml`: a
/// test that read the committed file would pass or fail with an edit to
/// production policy, and the committed rows have their own gate
/// (`the_committed_shape_rules_fire_on_every_banned_shape`).
fn repo_with_gh_policy(name: &str) -> PathBuf {
    repo_with_config(name, GH_POLICY_CONFIG)
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

/// `batten -v hook`, for the ladder-gated notes a default run withholds.
fn run_hook_verbose(dir: &std::path::Path, harness: &str, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["-v", "hook", "--harness", harness])
        .env_remove("BATTEN_GH_GUARD_BYPASS")
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

/// Give a fixture that carries the *committed* `batten.toml` a git repository
/// with `origin/main` resolving.
///
/// The committed config's `ratchet` rows (CLOUD-55) count against that ref, and
/// an unresolvable base is exit 1 by design. Without this the fixture inherits
/// whatever repository encloses the scratch directory — which is how these two
/// tests passed locally, against the outer repo's `origin/main`, and failed on a
/// CI runner that has no such ref. A fixture that reads the repository it is
/// running inside is not a fixture.
/// Seed the surfaces the committed `[budget.instructions]` set declares.
///
/// A fixture standing in for a repository using the committed config owes it
/// every declared entry, because a dead one is exit 1 per entry (CLOUD-298's
/// refusal, reaching the main gate since CLOUD-50 wired budgets into `check`).
/// The embedded key is seeded EMPTY, which is the committed tree's own state:
/// it contributes nothing and prints no row, so these fixtures keep testing the
/// rule they are about rather than a budget.
fn committed_budget_surfaces(dir: &Path) {
    fs::write(dir.join("AGENTS.md"), "instructions\n").expect("write fixture instructions");
    fs::create_dir_all(dir.join(".serena")).expect("create fixture serena dir");
    fs::write(dir.join(".serena/project.yml"), "initial_prompt: ''\n")
        .expect("write fixture project config");
}

/// Also seeds the scanner the committed `no-secrets` row resolves, and returns
/// the `HOME` every invocation against this fixture must run under.
///
/// Same argument as the `origin/main` ref above, one precondition further out:
/// the committed config carries a `secrets` row (CLOUD-59) whose kind resolves a
/// PINNED binary from the provision cache, and an absent one is exit 1 naming
/// `batten provision apply`. Without this the cases fail on that refusal rather
/// than on the rule each is about — and worse, they would read whichever cache
/// the ambient `XDG_DATA_HOME` points at, which is the "fixture that reads the
/// environment it runs inside" defect this helper's own history is about.
///
/// The out-of-tree state root a fixture's runs write to, under its own `home`.
///
/// Derived through the library's own [`batten::state::derive_repo_name`] rather
/// than re-spelled here. It used to be re-spelled — `dir.file_name()`, a second
/// implementation of the segment rule — and CLOUD-296 is what that cost: the
/// segment gained a per-checkout digest, and every fixture holding a hand-rolled
/// copy of the old rule started reading a directory nothing writes. A test that
/// re-derives a production rule is a test that can disagree with it.
///
/// Canonicalized because the binary's own root comes from
/// `git rev-parse --path-format=absolute`, which resolves symlinks; deriving from
/// an unresolved path here would address a different segment than the child does.
fn fixture_state_dir(repo: &Path, home: &Path) -> PathBuf {
    let canonical = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let segment =
        batten::state::derive_repo_name(&canonical).expect("derive the fixture's state segment");
    home.join("data/batten").join(segment)
}

/// SEEDED, never fetched: `provision apply` would reach github for a real
/// artifact, and a suite about the exit-code contract must not depend on the
/// network. The adapter asks only whether the binary is there, so a stub answers
/// the same question offline — and it exits 0 with no output, which is what the
/// real scanner does on these fixtures anyway, since none carries a credential.
fn committed_config_fixture_git(dir: &std::path::Path) -> PathBuf {
    git_in(dir, &["init", "-q"]);
    git_in(dir, &["commit", "-q", "--allow-empty", "-m", "base"]);
    git_in(dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

    let home = dir.join(".batten-test-home");
    let bin = fixture_state_dir(dir, &home).join("provision/ripsecrets/0.1.11/bin");
    fs::create_dir_all(&bin).expect("create the fixture provision cache");
    let scanner = bin.join("ripsecrets");
    fs::write(&scanner, "#!/bin/sh\nexit 0\n").expect("write the stub scanner");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&scanner, fs::Permissions::from_mode(0o755))
            .expect("mark the stub scanner executable");
    }
    home
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
            // CLOUD-70 retired the usage error here, and the two cases above are
            // what keep that from being a blanket relaxation: absence resolves
            // to the compiled-in default layer, while a config that is *present*
            // and cannot be honoured is refused exactly as before.
            name: "config show, missing config → the default layer",
            args: &["config", "show"],
            config: None,
            env: &[],
            expected: 0,
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
        Case {
            // CLOUD-84/CLOUD-307. In the SHARED table on purpose: `lint brief`'s
            // unreadable-input case is the same `Usage` the config verbs above
            // return, and the Ready block that shipped this issue originally
            // numbered it `2`. One table, no per-verb exception (rule 5) — the
            // verdict half needs a fixture path and is asserted beside it.
            name: "lint brief, unreadable input → usage (never the deny code)",
            args: &["lint", "brief", "no-such-brief.md"],
            config: None,
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
const COMMAND_RULE_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"false\"\nseverity = \"deny\"\nscope = \"tree\"\n";

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
    // And in the one refusal shape (CLOUD-122), not a second one invented for
    // this surface: the id that refused, the cause, and the fix clause. Exit 1
    // rather than 2 is correct here — a rule `check` cannot honestly run is a
    // statement about the invocation, not a policy verdict (§7) — so this
    // refusal carries the `batten:` prefix that belongs to 1 and 3, and no
    // bypass hatch, because a read-only run has nothing to bypass.
    assert!(
        stderr.contains("Refused by dyn:") && stderr.contains("Fix: batten enforce."),
        "the refusal must adopt the one shape, got: {stderr}"
    );
    assert!(
        !stderr.contains("Bypass with"),
        "a check refusal has no mediation hatch, got: {stderr}"
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
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"true\"\nseverity = \"deny\"\n",
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
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"definitely-not-a-real-binary-xyz\"\nseverity = \"deny\"\n",
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
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"definitely-not-a-real-binary-xyz\"\nseverity = \"deny\"\n",
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
fn the_retired_run_key_is_refused_by_name_pointing_at_check() {
    // CLOUD-215. §2 declares no back-compatibility surface, so `run` is not an
    // alias that still works — it is a key that stopped. The refusal has to
    // carry the one fix (CLOUD-122), or an author whose config went dark learns
    // only that it did.
    let dir = repo_with_config(
        "rule-run-renamed",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\nrun = \"true\"\nseverity = \"deny\"\n",
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
        "a config naming a key this build does not have is the usage class (§7)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`check`"),
        "the refusal must name the replacement key, got: {stderr}"
    );
}

#[test]
fn a_reserved_fix_loads_and_is_refused_rather_than_silently_ignored() {
    // The other half of CLOUD-215: `fix` parses today — that is what reserves
    // the vocabulary before external configs exist — while the engine that
    // would execute it does not. Accepting the key and running only the check
    // side would report green over a repair nobody performed.
    let dir = repo_with_config(
        "rule-fix-reserved",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"true\"\nfix = \"true\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");

    // It loads: `config show` reads the same authority and does not refuse it.
    let shown = batten()
        .args(["config", "show"])
        .current_dir(&dir)
        .output()
        .expect("run batten config show");
    assert_eq!(
        shown.status.code(),
        Some(0),
        "`fix` must parse, or the vocabulary is not reserved at all"
    );

    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unbuilt capability is a config error, never a policy verdict"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`fix`"),
        "the refusal must name the key it is about, got: {stderr}"
    );
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
fn spec_emits_the_derived_read_only_allowlist() {
    // CLOUD-217 (39). The §5 allowlist is derived from the effect annotations,
    // and until now the derivation was reachable only from this crate's own
    // tests — so the agent expected to honour it had to re-derive it, which is
    // a second implementation of a filter whose failure mode is advertising a
    // write-bearing verb as agent-safe. Asserted over the binary's stdout
    // because that is the artifact the agent actually reads.
    let output = batten().arg("spec").output().expect("run batten spec");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("spec stdout is valid JSON");

    let allowlist: Vec<&str> = value["read_only_allowlist"]
        .as_array()
        .expect("the emitted document carries the derived allowlist")
        .iter()
        .map(|path| path.as_str().expect("an allowlist entry is a string"))
        .collect();

    assert!(allowlist.contains(&"check"), "{allowlist:?}");
    assert!(allowlist.contains(&"spec"), "{allowlist:?}");
    // The two verbs whose exclusion is the whole point: `enforce` may run
    // user-supplied commands, and `hook` adjudicates someone else's write.
    assert!(!allowlist.contains(&"enforce"), "{allowlist:?}");
    assert!(!allowlist.contains(&"hook"), "{allowlist:?}");

    let mut sorted = allowlist.clone();
    sorted.sort_unstable();
    assert_eq!(allowlist, sorted, "the emitted allowlist is sorted (§6)");
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
    /// Cursor's in-band body, a different shape for a different reason: it
    /// documents no meaning for stderr, so JSON is the only channel a reason has.
    StdoutCursorDenyJson,
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

/// Whether this host reads its deny reason from a JSON body rather than stderr.
///
/// Read off the enum rather than listing tokens here: a host added with the
/// in-band posture and forgotten in a test list would silently stop being
/// checked on the channel it actually uses.
fn reads_a_deny_body(harness: &str) -> bool {
    batten::hook::Harness::ALL
        .iter()
        .find(|candidate| candidate.as_str() == harness)
        .is_some_and(|candidate| candidate.reason_travels_in_band())
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
    // Cursor is the second in-band host, and for a different reason than Claude:
    // it documents no meaning for stderr at all, so a deny that explained itself
    // there would explain itself to nobody. Its body shape is its own.
    Row {
        harness: "cursor",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "cursor",
        case: "deny",
        command: "gh pr merge 42",
        expected: 0,
        channel: Channel::StdoutCursorDenyJson,
    },
    // The three hosts that read exit 2 and take their reason from stderr. They
    // differ on the way IN (event names, arg encodings) and not on the way out,
    // which is why they share the neutral channel here.
    Row {
        harness: "copilot-cli",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "copilot-cli",
        case: "deny",
        command: "gh pr merge 42",
        expected: 2,
        channel: Channel::StderrReason,
    },
    Row {
        harness: "gemini-cli",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "gemini-cli",
        case: "deny",
        command: "gh pr merge 42",
        expected: 2,
        channel: Channel::StderrReason,
    },
    Row {
        harness: "codex-cli",
        case: "allow",
        command: "gh pr view 42",
        expected: 0,
        channel: Channel::Silent,
    },
    Row {
        harness: "codex-cli",
        case: "deny",
        command: "gh pr merge 42",
        expected: 2,
        channel: Channel::StderrReason,
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
            Channel::StdoutCursorDenyJson => assert!(
                stdout.contains("\"permission\":\"deny\"") && stdout.contains("user_message"),
                "{at}: Cursor's own body shape is the deny, got: {stdout}"
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

// --- the refusal contract (CLOUD-122) ---------------------------------------
//
// Every deny points to the fix. The shape is one type in the crate and the
// constructor makes the fix disposition mandatory, so a deny with no disposition
// cannot compile — but "did the fix clause survive the projection onto the
// channel this host actually reads" is observable only by spawning the binary,
// which is what these cases are for. A refusal is a contract only where a host
// reads it.

/// One hook policy-table row, and the sanctioned command its deny must name.
struct FixCase {
    /// A mediated command the row refuses.
    command: &'static str,
    /// The remedy that row declares, which the refusal must carry.
    fix: &'static str,
}

const FIX_CASES: &[FixCase] = &[
    FixCase {
        command: "gh pr merge 42",
        fix: "use `mise run land`",
    },
    FixCase {
        command: "gh pr comment 7 --body /fast-forward",
        fix: "use `mise run land`",
    },
    FixCase {
        command: "gh pr checks --watch",
        fix: "use `mise run ci-wait`",
    },
    FixCase {
        command: "gh run watch 123",
        fix: "use `mise run ci-wait`",
    },
];

#[test]
fn every_hook_policy_table_deny_names_its_fix() {
    // One case per row of the policy table, and the count is *derived* from the
    // fixture config rather than written down: a fifth row added with no case
    // would otherwise ship its deny unexercised, which is the same defect class
    // the decision matrix's totality test guards one level up.
    let rows = GH_POLICY_CONFIG
        .matches("scope = \"mediated_call\"")
        .count();
    assert_eq!(
        FIX_CASES.len(),
        rows,
        "every mediated_call row in the fixture policy owes a refusal case"
    );

    let dir = repo_with_gh_policy("refusal-fix-pointer");
    for case in FIX_CASES {
        let output = run_hook_in(&dir, "exit-code", &claude_payload(case.command), false);
        assert_eq!(output.status.code(), Some(2), "{}: deny", case.command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("Fix: {}", case.fix)),
            "{}: the refusal must name the sanctioned command, got: {stderr}",
            case.command
        );
    }
}

#[test]
fn the_in_band_hosts_carry_the_fix_in_their_decision_document() {
    // The contract is not stderr-only. Claude discards stdout on exit 2 and
    // Cursor assigns stderr no meaning at all, so on those two hosts the decision
    // document is the ONLY place a fix pointer can travel — the case that would
    // silently regress to a bare "deny" if the projection happened per channel
    // instead of once.
    let dir = repo_with_gh_policy("refusal-in-band");
    for (harness, pointer) in [
        (
            "claude-code",
            "/hookSpecificOutput/permissionDecisionReason",
        ),
        ("cursor", "/agent_message"),
    ] {
        let output = run_hook_in(&dir, harness, &claude_payload("gh pr merge 42"), false);
        assert_eq!(output.status.code(), Some(0), "{harness}: in-band deny");
        let body: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|err| panic!("{harness}: the deny document must parse: {err}"));
        let reason = body
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{harness}: no reason at {pointer}: {body}"));
        assert!(
            reason.contains("Fix: use `mise run land`"),
            "{harness}: the document must carry the fix, got: {reason}"
        );
    }
}

/// A protected-path gate whose verb declares **no** sanctioned alternative.
const NO_REMEDY_CONFIG: &str = r#"version = 1
protected = ["guarded/**"]

[[verb]]
verb = "mv"
effect = "destructive"
"#;

#[test]
fn a_deny_with_no_safe_remedy_declares_it_rather_than_omitting_the_clause() {
    // The half of the contract that is easy to get wrong: where nothing is
    // declared, the refusal says so. An omitted fix clause is indistinguishable
    // from a producer that forgot one, which is exactly the bare "no" the
    // contract exists to prevent — so the absence is a value, not a silence.
    // (CLOUD-280 is what gives this case a per-path-class answer to give.)
    let dir = repo_with_config("refusal-no-remedy", NO_REMEDY_CONFIG);
    let output = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("mv notes.md guarded/thing"),
        false,
    );
    assert_eq!(output.status.code(), Some(2), "the protected gate denies");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Refused by protected-mutation:"),
        "names the gate, got: {stderr}"
    );
    assert!(
        stderr.contains("Fix: none declared"),
        "the absence is stated, not omitted, got: {stderr}"
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
    /// Whether the **mediated-call** policy adjudicates at this event.
    ///
    /// Narrower than "does anything decide here" since CLOUD-85: the stop event
    /// is now adjudicated too, by the end-of-turn gate, whose inputs are the
    /// checkout's state rather than the call's. This column stays about the
    /// command matcher, so the row below keeps pinning what it always pinned —
    /// a banned command is refused before it runs, and only there.
    adjudicated: bool,
    /// Whether a decision at this event is a function of repository state
    /// rather than of the payload.
    ///
    /// Only the stop event (CLOUD-85). Its verdict depends on whether the tree
    /// is clean and the store empty, so a fixture cannot pin it to one answer
    /// the way a command can — what is pinned instead is that the answer is a
    /// legal one, and the gate's own cases assert which.
    state_decided: bool,
}

const EVENTS: &[EventRow] = &[
    EventRow {
        event: batten::hook::Event::PreTool,
        spelling: "PreToolUse",
        adjudicated: true,
        state_decided: false,
    },
    EventRow {
        event: batten::hook::Event::PostTool,
        spelling: "PostToolUse",
        adjudicated: false,
        state_decided: false,
    },
    EventRow {
        event: batten::hook::Event::Stop,
        spelling: "Stop",
        adjudicated: false,
        state_decided: true,
    },
    EventRow {
        event: batten::hook::Event::SessionStart,
        spelling: "SessionStart",
        adjudicated: false,
        state_decided: false,
    },
    // Claude-only (CLOUD-45). Every host is fed every row below, and the four
    // that do not declare these two allow through the capability path instead of
    // the adjudication path — which is the same observable answer, deliberately:
    // an absent capability must be indistinguishable from a declared event
    // nobody keyed policy on. `an_event_a_host_does_not_declare_degrades_cleanly`
    // is what tells the two apart, through the ladder.
    EventRow {
        event: batten::hook::Event::TaskCompleted,
        spelling: "TaskCompleted",
        adjudicated: false,
        state_decided: false,
    },
    EventRow {
        event: batten::hook::Event::ConfigChange,
        spelling: "ConfigChange",
        adjudicated: false,
        state_decided: false,
    },
    // Claude-only too, and added by CLOUD-389 because this census is TOTAL over
    // `Event::ALL` — a variant with no row here ships with its decision
    // unexercised, which is the whole point of the assertion below. The advisory
    // drain rides this boundary; the command matcher does not adjudicate at it,
    // and no host offers a deny channel there.
    EventRow {
        event: batten::hook::Event::PostToolBatch,
        spelling: "PostToolBatch",
        adjudicated: false,
        state_decided: false,
    },
    EventRow {
        event: batten::hook::Event::Unrecognized,
        spelling: "SomethingThisBuildDoesNotKnow",
        adjudicated: false,
        state_decided: false,
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
            } else if row.state_decided {
                // The end-of-turn gate (CLOUD-85). Its verdict is a function of
                // the checkout, not of the banned command in the payload — so
                // what is pinned here is that the answer stays inside the §7
                // table and never leaks the command matcher's reasoning. Which
                // way it goes for a given tree is the gate's own fixtures.
                let code = output.status.code();
                assert!(
                    code == Some(0) || code == Some(2),
                    "{at}: a stop verdict is allow or deny, never a failure code"
                );
                assert!(
                    !common::stderr(&output).contains("gh pr merge"),
                    "{at}: the stop gate answers about the turn, never about the payload's command"
                );
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{at}: an unadjudicated event must not deny"
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).is_empty(),
                    "{at}: an unadjudicated event emits no decision document"
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
        if reads_a_deny_body(harness) {
            assert_eq!(output.status.code(), Some(0), "{harness}");
            assert!(stdout.contains("\"deny\""), "{harness}: got {stdout}");
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
        if reads_a_deny_body(harness) {
            assert_eq!(output.status.code(), Some(0), "{harness}");
            assert!(stdout.contains("\"deny\""), "{harness}: got {stdout}");
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
    //
    // `gh pr ready` has left this list and did not simply become a deny: since
    // CLOUD-312 it is gated by the `ready-needs-receipts` row, so its verdict
    // depends on whether THIS checkout carries valid receipts — a property of
    // the world, not of the commit. Asserting either verdict here would make
    // the suite pass or fail on the runner's git state. The case below pins
    // what is actually a property of the commit: nothing bans it outright.
    for command in ["gh pr view 42", "mise run land"] {
        let output = run_hook_in(&root, "exit-code", &claude_payload(command), false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "the committed policy must allow {command:?}"
        );
    }
}

/// `gh pr ready` is gated by a precondition, never banned outright.
///
/// The distinction is the whole point of the `receipt` kind: a shape row refuses
/// a command permanently, a receipt row refuses it *until the work is proved*,
/// and confusing the two would leave the branch with no way to ready a PR at
/// all. Asserted through the refusal's identity rather than its verdict, so the
/// case is a statement about the committed policy and not about whether this
/// checkout happens to have run `verify`.
///
/// TWO ROWS CAN REFUSE, AND BOTH ARE PRECONDITIONS — which is the assertion,
/// rather than a widening of it. `ready-needs-receipts` refuses until `verify`
/// has run; `ready-names-an-issue` is a `shape` row carrying `requires_key`,
/// which the rules file describes as narrowing the deny "from *this command is
/// banned* to *this command is banned unless the work is keyed*". Neither is the
/// outright ban this case exists to refuse, and which one fires first is a
/// property of the checkout.
///
/// Naming only the receipt row made that a hidden dependency on the branch
/// NAME. A branch carrying no `CLOUD-*` key trips the key row before the receipt
/// row is ever reached — and a keyless branch is not an oddity here, it is what
/// `mem:workflow/board-states` REQUIRES of a PR closing several keys, because
/// branch-name precedence otherwise moves one issue and strands the rest. So the
/// committed shape of a multi-key bundle reddened this case, on a branch that
/// was correct (CLOUD-661). The fix is to assert what the case means.
#[test]
fn the_committed_policy_gates_ready_on_receipts_rather_than_banning_it() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = run_hook_in(&root, "exit-code", &claude_payload("gh pr ready 42"), false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    match output.status.code() {
        // Preconditions satisfied in this checkout: allowed, which is the point.
        Some(0) => {}
        // Refused — and it must be a PRECONDITION row that did it, never one of
        // the `gh` lifecycle bans, which refuse the command outright.
        Some(2) => assert!(
            stderr.contains("ready-needs-receipts") || stderr.contains("ready-names-an-issue"),
            "a refused `gh pr ready` must come from a precondition row, got: {stderr}"
        ),
        other => panic!("unexpected exit {other:?}: {stderr}"),
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

/// A checked-in host fixture, by file stem.
fn host_fixture(stem: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/hooks")
        .join(format!("{stem}.json"));
    fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()))
}

#[test]
fn every_host_denies_the_same_call_through_its_own_channel() {
    // CLOUD-44's acceptance over the compiled binary: five hosts, five wire
    // formats, one policy, one verdict — and each answer shaped the way that
    // host reads it. The fixtures all carry `gh pr merge 1`, which the fixture
    // policy denies.
    let dir = repo_with_gh_policy("host-matrix");

    // Hosts whose reason travels in a JSON body, with the key that proves the
    // body is that host's own shape rather than a shared one.
    for (harness, stem, marker) in [
        (
            "claude-code",
            "claude-code",
            "\"permissionDecision\":\"deny\"",
        ),
        ("cursor", "cursor", "\"permission\":\"deny\""),
    ] {
        let output = run_hook_in(&dir, harness, &host_fixture(stem), false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{harness}: an in-band deny exits 0 — the body is the verdict"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(marker),
            "{harness}: wrong deny shape, got: {stdout}"
        );
        assert!(
            stdout.contains("mise run land"),
            "{harness}: the deny must name the redirect"
        );
    }

    // Hosts whose channel is the exit code, with the reason on stderr.
    for (harness, stem) in [
        ("copilot-cli", "copilot-cli"),
        ("gemini-cli", "gemini-cli"),
        ("codex-cli", "codex-cli"),
    ] {
        let output = run_hook_in(&dir, harness, &host_fixture(stem), false);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{harness}: exit 2 is the deny on every surveyed host"
        );
        assert!(
            output.stdout.is_empty(),
            "{harness}: stray stdout on these hosts risks being read as an allow"
        );
        assert!(
            common::stderr(&output).contains("mise run land"),
            "{harness}: the reason travels on stderr here"
        );
    }
}

#[test]
fn a_cursor_payload_with_a_windows_bom_still_denies() {
    // The measured failure this guards: a UTF-8 BOM on Cursor's stdin breaks a
    // strict JSON parser, and fail-open turns that into allow-all. Through the
    // binary, because that is where the bytes actually arrive.
    let dir = repo_with_gh_policy("host-bom");
    let output = run_hook_in(&dir, "cursor", &host_fixture("cursor-bom"), false);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"permission\":\"deny\""),
        "a BOM must not degrade the guard to an allow"
    );
}

#[test]
fn an_event_a_host_does_not_declare_degrades_cleanly() {
    // CLOUD-45's acceptance over the binary: the same `TaskCompleted` payload
    // under a host that declares it and one that does not. Both allow — an
    // absent capability is a statement about the host, never a reason to refuse
    // the call — and only the host that lacks it says so.
    let dir = repo_with_gh_policy("capability-degrade");
    let payload = serde_json::json!({
        "hook_event_name": "TaskCompleted",
        "session_id": "sess-1",
        "cwd": "/repo",
        "tool_name": "Bash",
        // A command the fixture policy denies, so an accidental adjudication of
        // an undeclared event would show up as a deny rather than passing
        // silently.
        "tool_input": { "command": "gh pr merge 1" }
    })
    .to_string();

    // Declared: no capability note, and the event is simply not adjudicated
    // (only pre-tool is), so it allows quietly.
    let declared = run_hook_in(&dir, "claude-code", &payload, false);
    assert_eq!(declared.status.code(), Some(0));
    assert!(declared.stdout.is_empty());
    assert!(
        !common::stderr(&declared).contains("does not emit"),
        "the host that has the capability says nothing about lacking it"
    );

    // Undeclared: still an allow, still nothing on the answer channel.
    for harness in ["cursor", "copilot-cli", "gemini-cli", "codex-cli"] {
        let output = run_hook_in(&dir, harness, &payload, false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{harness}: an absent capability is never an error and never a deny"
        );
        assert!(
            output.stdout.is_empty(),
            "{harness}: nothing keyed on the event fired"
        );
        assert!(
            output.stderr.is_empty(),
            "{harness}: the note is ladder-gated — a default run stays quiet"
        );

        // Asking for detail produces it, and names the fallback the survey
        // assigns: a policy keyed on completion watches the Stop family here.
        let loud = run_hook_verbose(&dir, harness, &payload);
        let stderr = common::stderr(&loud);
        assert!(
            stderr.contains("does not emit task-completed"),
            "{harness}: the degradation is reportable, got: {stderr}"
        );
        assert!(
            stderr.contains("stop"),
            "{harness}: and names what stands in for it, got: {stderr}"
        );
    }
}

#[test]
fn a_payload_that_fits_no_host_fails_open_on_every_host() {
    // §7(c): a payload no adapter can read is an allow, never an error and never
    // a deny — a guard must not be the reason a session cannot proceed.
    let dir = repo_with_gh_policy("host-junk");
    for harness in [
        "claude-code",
        "cursor",
        "copilot-cli",
        "gemini-cli",
        "codex-cli",
        "exit-code",
    ] {
        let output = run_hook_in(&dir, harness, "not json at all", false);
        assert_eq!(output.status.code(), Some(0), "{harness} must fail open");
        assert!(output.stdout.is_empty(), "{harness} emits no verdict");
    }
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
    //
    // The vehicle is an *unsupported version* rather than a missing config,
    // which is what it used to be: CLOUD-70 made absence resolve to the default
    // layer, so it no longer raises anything. The invariant under test is
    // unchanged — a library-raised `UsageError` is loud at the quietest rung —
    // and a present-but-unhonourable config is still exactly that error.
    let dir = scratch("silent-invalid-config");
    fs::create_dir_all(&dir).expect("create dir");
    fs::write(dir.join("batten.toml"), "version = 2\n").expect("write batten.toml");
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
        .state_home(&home)
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
            .state_home(&home)
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
            .state_home(&home)
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
        .state_home(home)
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
        .state_home(&home)
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
        .config(concat!(
            "version = 1\n",
            "must_land_on = \"main\"\n",
            "[budget.instructions]\n",
            "files = [\"AGENTS.md\"]\n",
            "max_tokens = 1000\n",
            // `defects query` is the second verb with a minimum input, for the
            // same reason: a ledger nobody declared is a usage error, never an
            // empty answer. The file itself stays absent — that is the ledger's
            // legitimate bootstrap state, and `-J` still emits `[]`.
            "[defects]\n",
            "path = \"defects.jsonl\"\n",
            "classes = [\"example\"]\n",
            // `attribution check`'s minimum input, for the same reason: a
            // repository declaring no attribution policy is a usage error, never
            // a clean pass over commits nobody judged.
            "[attribution]\n",
            "identity_deny = [\"^Nobody <\"]\n",
            "trailer_deny = [\"^Nobody-Session:\"]\n",
            "body_deny = [\"^Nobody generated\"]\n",
            "[attribution.identity]\n",
            "name = \"Census Human\"\n",
            "email = \"census@example.test\"\n",
        ))
        .file("AGENTS.md", "instructions\n")
        // `lint brief`'s minimum input, the third verb to need one. Named by
        // `CENSUS_POSITIONALS` rather than by this call site, so the argv and the
        // file it points at cannot drift apart.
        .file("census-brief.md", &census_brief())
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// The positional value each data-emitting verb needs to reach its document.
///
/// A table rather than one shared placeholder. It used to be the literal
/// `"verify"` for every positional, on the stated grounds that `receipt status
/// <check>` was the only one — and when `lint brief <path>` landed (CLOUD-84) that
/// constant became a path to a file nobody wrote, so the census ran the verb's
/// unreadable-input arm and asserted about a usage error. The guard that was meant
/// to catch this only counted positionals *per verb*, so a SECOND verb with a
/// positional slipped through silently, which is the failure mode a census exists
/// to prevent.
///
/// Every value is relative to the census fixture's repo directory, and
/// [`census_fixture`] writes whatever a row names.
const CENSUS_POSITIONALS: &[(&str, &str)] = &[
    // An empty but resolvable range: the clean answer is `[]`, which is a
    // document like any other, and it needs no commit the fixture did not make.
    ("attribution check", "HEAD..HEAD"),
    // A valid check name; `receipt status` answers `missing` for it, which is a
    // document like any other.
    ("receipt status", "verify"),
    // A brief that satisfies the schema, so the census asserts about a CLEAN run
    // — which is what `no_progress_reaches_stderr_when_it_is_not_a_terminal`
    // needs, and what makes the empty `-J` document the interesting case.
    ("lint brief", "census-brief.md"),
];

/// A brief satisfying every row of `brief::SCHEMA`, for the census fixture.
///
/// Built from the schema rather than hand-typed, so a new required section cannot
/// leave this fixture quietly failing the verb it is meant to exercise cleanly.
fn census_brief() -> String {
    let mut text = String::new();
    for section in batten::brief::SCHEMA {
        text.push_str(&format!("## {}\n\ncensus fixture\n\n", section.labels[0]));
        if section.runnable {
            text.push_str("```\nmise run verify\n```\n\n");
        }
    }
    text
}

/// The minimal argv that makes `decl` emit its document.
///
/// Derived from the declaration rather than listed: the path, then the positional
/// [`CENSUS_POSITIONALS`] names for it, then `-J`. A verb with a positional and no
/// row fails loudly here rather than being handed a value that means nothing to it.
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
        let found = CENSUS_POSITIONALS
            .iter()
            .find(|(path, _)| *path == decl.path)
            .map(|(_, value)| *value);
        let Some(value) = found else {
            panic!(
                "{}: takes a positional but CENSUS_POSITIONALS names no value for it — \
                 add a row (and whatever file it needs to census_fixture)",
                decl.path
            )
        };
        argv.push(value.to_owned());
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
        .state_home(home)
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
    let store = fixture_state_dir(&repo, &home).join("receipts");
    let receipts: Vec<_> = fs::read_dir(&store).expect("receipt store").collect();
    assert_eq!(
        receipts.len(),
        1,
        "one check, one receipt, updated in place"
    );
}

/// CLOUD-581's three acceptance bullets, over the real binary.
///
/// The receipt records the config epoch at its subject commit, so it can answer
/// "under which governing surface" — and for a check that delegates its clause
/// list to an external verifier, that surface is where the tool's pin, and
/// therefore the standard's edition, lives.
#[test]
fn receipt_records_the_config_epoch_at_its_subject_commit() {
    let root = scratch("receipt-epoch");
    let _ = fs::remove_dir_all(&root);
    // A tracked surface wider than batten.toml, so the test can move a
    // governing file that is NOT the policy — the toolchain-pin shape.
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n[epoch]\ntracked = [\"batten.toml\", \"pinned.lock\"]\n")
        .file("pinned.lock", "tool = \"1.0.0\"\n")
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let epoch_of = |dir: &std::path::Path, home: &std::path::Path| -> String {
        let out = receipt_cmd(dir, home, &["receipt", "record", "verify"]);
        assert_eq!(out.status.code(), Some(0), "record must succeed");
        let store = fixture_state_dir(dir, home).join("receipts");
        let file = fs::read_dir(&store)
            .expect("receipt store")
            .next()
            .expect("one receipt")
            .expect("readable entry")
            .path();
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(file).expect("read receipt"))
                .expect("receipt is JSON");
        doc["predicate"]["configEpoch"]
            .as_str()
            .expect("configEpoch is a string")
            .to_owned()
    };

    // 1. The field is recorded, and it is a real epoch rather than a placeholder.
    let first = epoch_of(&repo, &home);
    assert!(!first.is_empty(), "an epoch is recorded");

    // 3. A WORKING-TREE edit to a governing file does not move it: the subject
    //    is a commit, so every byte the statement binds comes from that commit.
    fs::write(repo.join("pinned.lock"), "tool = \"2.0.0\"\n").expect("edit the pin");
    let uncommitted = epoch_of(&repo, &home);
    assert_eq!(
        uncommitted, first,
        "an uncommitted pin bump must not move the recorded epoch"
    );

    // 2. Committing that same bump does move it: the two are distinguishable,
    //    which is what lets a reader tell which toolchain decided the check.
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "bump the pin"]);
    let committed = epoch_of(&repo, &home);
    assert_ne!(
        committed, first,
        "a committed pin bump must move the recorded epoch"
    );
}

/// CLOUD-579's three acceptance bullets, over the real binary.
///
/// The distinctive string in the fixture is the load-bearing part: a transcript
/// is the richest source of secrets the engine can be pointed at, so the test
/// that matters is not "the record has fields" but "the record has NO free
/// text" (non-negotiable rule 4).
#[test]
fn the_agent_context_statement_is_bounded_and_never_carries_free_text() {
    const SECRET: &str = "SUPERSECRETPROMPTBODY";
    let root = scratch("receipt-agent-context");
    let _ = fs::remove_dir_all(&root);
    let transcript = format!(
        concat!(
            r#"{{"type":"assistant","sessionId":"s-9","version":"9.9.9","entrypoint":"remote","#,
            r#""cwd":"/w","gitBranch":"topic","attributionMcpServer":"srv-a","#,
            r#""message":{{"role":"assistant","model":"a-model","#,
            r#""content":[{{"type":"text","text":"{secret}"}}]}}}}"#,
            "\n",
            r#"{{"type":"user","sessionId":"s-9","message":{{"role":"user","#,
            r#""content":"{secret}"}}}}"#,
        ),
        secret = SECRET
    );
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n[transcript]\npath = \"session.jsonl\"\n")
        .file("session.jsonl", &transcript)
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0), "record must succeed");

    let store = fixture_state_dir(&repo, &home).join("receipts");
    let agent_file = fs::read_dir(&store)
        .expect("receipt store")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.to_string_lossy().ends_with(".agent-context.json"))
        .expect("an agent-context statement beside the receipt");
    let raw = fs::read_to_string(&agent_file).expect("read the statement");

    // 3. NO FREE TEXT. The fixture's prompt body appears twice in the
    //    transcript and must appear nowhere in the emitted bytes.
    assert!(
        !raw.contains(SECRET),
        "the statement must carry no transcript free text"
    );

    let doc: serde_json::Value = serde_json::from_str(&raw).expect("statement is JSON");

    // 1. ROUND-TRIP AGAINST THE SIBLING. Same envelope, same subject digest,
    //    different predicate — which is what makes the pair joinable.
    assert_eq!(
        doc["predicateType"], "https://batten.dev/agent-context/v1",
        "the predicate is ours; the envelope is in-toto's"
    );
    assert_eq!(doc["subject"][0]["digest"]["gitCommit"], head);
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 0, "the sibling receipt still reads back valid");
    assert_eq!(line, format!("verify {head} valid\n"));

    // 2. THE BOUND IS PRESENT. A statement without it would read as a complete
    //    agent bill of materials, which CLOUD-279 measured it is not.
    let coverage = doc["predicate"]["coverage"]
        .as_array()
        .expect("coverage is an array");
    assert!(!coverage.is_empty(), "the bound is never empty");

    // The typed facts, as sets rather than a picked occurrence.
    assert_eq!(doc["predicate"]["models"][0], "a-model");
    assert_eq!(doc["predicate"]["exercisedMcpServers"][0], "srv-a");
    assert_eq!(doc["predicate"]["sessionId"], "s-9");
    assert!(
        doc["predicate"]["configEpoch"]
            .as_str()
            .is_some_and(|epoch| !epoch.is_empty()),
        "the governing surface is bound here too"
    );
}

/// A configured transcript that is not there is reported, never papered over
/// with an empty statement — "nothing was stated" and "nothing was in effect"
/// are different claims and only one of them is true.
#[test]
fn a_configured_but_absent_transcript_refuses_rather_than_recording_an_empty_context() {
    let root = scratch("receipt-agent-absent");
    let _ = fs::remove_dir_all(&root);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n[transcript]\npath = \"session.jsonl\"\n")
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(
        record.status.code(),
        Some(1),
        "a usage error, not a verdict"
    );
    let store = fixture_state_dir(&repo, &home).join("receipts");
    let agent = fs::read_dir(&store)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .to_string_lossy()
                .ends_with(".agent-context.json")
        });
    assert!(
        !agent,
        "no statement is written when there is nothing to state"
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
    let store = fixture_state_dir(&repo, &home).join("receipts");
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
    let home = committed_config_fixture_git(&dir);
    committed_budget_surfaces(&dir);
    // A file the committed no-conflict-markers rule must flag. The marker is
    // still assembled at runtime, but for a narrower reason than before
    // (CLOUD-229): the rule now delegates to `hk util check-merge-conflict`,
    // which only fires on a marker at the START of a line, so the seven
    // characters appearing mid-line in this source file no longer trip the gate
    // this test backs. Writing it out would be safe and would also stop proving
    // that the fixture's marker is the line-initial shape hk actually judges.
    let marker = format!("{} HEAD\n", "<".repeat(7));
    let src = dir.join("crates/x/src");
    fs::create_dir_all(&src).expect("create fixture source tree");
    fs::write(src.join("lib.rs"), marker).expect("write fixture source");
    // `enforce`, not `check`: a `command` rule spawns a process, so the
    // read-effect verb refuses the whole ruleset (exit 1, naming this verb).
    // That refusal is asserted on its own below.
    //
    // This spawns `hk`, so it needs hk on PATH — true under `mise run
    // test:cargo` and false under a bare `cargo test`, where it fails loudly
    // with "cannot run `hk`: not found on PATH" rather than passing silently.
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the committed rule must fire on the shape it names: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "crates/** no-conflict-markers\n",
        "a command condemns a batch, so the pointer is the glob and carries no line"
    );
}

#[test]
fn the_committed_delegating_rule_is_refused_by_the_read_only_verb() {
    // The visible consequence of delegation, pinned rather than left implicit:
    // `batten check` cannot run this repository's own committed config any more,
    // because a `command` rule reaches user-supplied code and `check` promises
    // it never does (§5, CLOUD-170). The refusal must name the verb that does
    // run it — that is what `mise run batten-check` was pointed at.
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");
    let dir = repo_with_config("config-committed-read-refusal", &contents);
    let home = committed_config_fixture_git(&dir);
    committed_budget_surfaces(&dir);

    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a spawning kind is refused loudly by the read-effect verb, never skipped"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("batten enforce"),
        "the refusal must name the verb that runs it, got: {stderr}"
    );
}

#[test]
fn the_committed_delegating_rule_spawns_nothing_when_its_glob_misses() {
    // "The glob is a gate before it is an argv source", asserted for the SHIPPED
    // rule rather than only in unit fixtures (CLOUD-229's acceptance).
    //
    // The discriminator is that this tree carries a conflict marker hk would
    // certainly fail on — at the start of a line, in a file the delegate would
    // read happily — placed OUTSIDE `crates/`. Exit 0 is therefore only
    // reachable if the glob selected nothing and no process was spawned at all.
    // A version of this test with an empty tree would pass just as well against
    // an engine that spawned the delegate over zero files.
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");
    let dir = repo_with_config("config-committed-glob-miss", &contents);
    let home = committed_config_fixture_git(&dir);
    committed_budget_surfaces(&dir);
    let marker = format!("{} HEAD\n", "<".repeat(7));
    fs::write(dir.join("notes.txt"), marker).expect("write out-of-glob source");

    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(0),
        "a marker outside the declared glob is not this rule's business"
    );
    assert!(
        output.stdout.is_empty(),
        "a glob miss reports nothing, got: {}",
        String::from_utf8_lossy(&output.stdout)
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
    // would pass with one of the rules deleted.
    //
    // The banned shapes are assembled at runtime rather than written as source
    // text — the same dodge the conflict marker above uses. This file sits under
    // `crates/batten/tests/`, inside the very glob these rules scan, so spelling
    // one here would make `mise run batten-check` fire on the test that proves
    // the rule works.
    let account = format!("e{}bc", "tax");
    let entity_path = format!("entit{}/", "ies");
    // CLOUD-73's row, and the only one of the three whose predicate is a `regex`
    // rather than a literal. Spelled here with a CAPITAL, which is the half a
    // case-sensitive literal could not have caught and the reason the row waited
    // for `regex` to exist.
    let repo_name = format!("C{}ce", "omplian");
    let payload = format!(
        "let id = \"{account}\";\nuse crate::{entity_path}mod;\n// ported from {repo_name}\n"
    );

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
    // Same reason as the sibling test above: the committed budget names
    // `AGENTS.md`, and `check` now refuses a budget entry that matches nothing.
    committed_budget_surfaces(&dirty);
    let home = committed_config_fixture_git(&dirty);
    let src = dirty.join("crates/demo/src");
    fs::create_dir_all(&src).expect("create fixture source tree");
    fs::write(src.join("lib.rs"), &payload).expect("write fixture source");
    fs::write(dirty.join("crates/demo/notes.txt"), &payload).expect("write fixture notes");

    // `enforce` since CLOUD-229: the committed table now carries a `command`
    // rule, so the read-effect verb refuses the whole ruleset. The expected
    // bytes below are unchanged, and that is the point — these fixtures carry no
    // line-initial conflict marker, so the delegating rule spawns hk over them
    // and contributes nothing, leaving the CLOUD-7 findings alone on stdout.
    let output = batten()
        .arg("enforce")
        .current_dir(&dirty)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a banned consumer shape under crates/ is a policy violation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "crates/demo/notes.txt:1 no-consumer-account-literal\n\
         crates/demo/notes.txt:2 no-consumer-entity-path\n\
         crates/demo/notes.txt:3 no-consumer-repo-name\n\
         crates/demo/src/lib.rs:1 no-consumer-account-literal\n\
         crates/demo/src/lib.rs:2 no-consumer-entity-path\n\
         crates/demo/src/lib.rs:3 no-consumer-repo-name\n",
        "one sorted pointer per banned shape per file, and nothing else"
    );

    // The other half of the discriminator: the same rules must stay silent on a
    // tree that carries none of the shapes. A rule that fired on everything
    // would pass the case above and still be useless.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-agnostic-clean"),
    );
    let clean = repo_with_config("config-agnostic-clean", &contents);
    committed_budget_surfaces(&clean);
    let home = committed_config_fixture_git(&clean);
    let ordinary = clean.join("crates/demo/src");
    fs::create_dir_all(&ordinary).expect("create clean source tree");
    fs::write(ordinary.join("lib.rs"), "pub fn ok() {}\n").expect("write clean source");

    let output = batten()
        .arg("enforce")
        .current_dir(&clean)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
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
fn the_committed_portability_rules_fire_on_every_banned_shape() {
    // CLOUD-282. `mise run verify` is the authorization the workflow contract
    // rests on, and on macOS it could not pass: two gates used sed's GNU-only
    // NUL-separated mode, two used bash 4's `mapfile` against a 3.2 /bin/bash,
    // one used xargs' short --no-run-if-empty, and three fixture repos
    // force-created a checked-out branch. CI runs ubuntu, so CI is structurally
    // blind to every one of them — which is exactly why the standing gate is a
    // property of the COMMITTED TREE rather than a job.
    //
    // Same shape as `the_committed_repo_agnosticism_rules_fire_on_every_banned_
    // shape` above, and full stdout equality is the load-bearing part for the
    // same reason: findings sort by the `(path, line, rule)` pointer tuple, so
    // the expected bytes are fixed, and a rule that is deleted, renamed,
    // mis-globbed or set to `severity = "allow"` changes them. A `contains`
    // assertion would pass with five of the six rules gone.
    //
    // Unlike that test, the banned literals CAN be written as source text here:
    // both globs are anchored at a first segment (`mise-tasks/`, `tests/`) that
    // this file, at `crates/batten/tests/cli.rs`, does not sit under.
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");

    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-portability-dirty"),
    );
    let dirty = repo_with_config("config-portability-dirty", &contents);
    committed_budget_surfaces(&dirty);
    let home = committed_config_fixture_git(&dirty);

    // One file per glob, each carrying every literal its rules ban, so a rule
    // scoped to the wrong directory shows up as a missing line rather than as a
    // silent pass. The task file's five are written in the order they sort by
    // line, and the sed rows are on separate lines because a single line can
    // only ever produce one finding per rule.
    fs::create_dir_all(dirty.join("mise-tasks")).expect("create fixture task dir");
    fs::write(
        dirty.join("mise-tasks/seed"),
        "printf x | sed -zE 's/a/b/'\n\
         sed -i 's/a/b/' file\n\
         mapfile -t lines < <(printf 'x')\n\
         git ls-files | xargs -r grep x\n\
         flock /tmp/lock true\n",
    )
    .expect("write fixture task");
    fs::create_dir_all(dirty.join("tests")).expect("create fixture test dir");
    fs::write(dirty.join("tests/seed.bats"), "\tgit branch -f main\n")
        .expect("write fixture suite");

    // `enforce`, not `check`: the committed ruleset carries `no-conflict-markers`,
    // a kind that runs a configured command, and the read-effect verb refuses the
    // whole config rather than silently skipping that one row (exit 1, pinned by
    // `the_committed_config_refuses_to_run_a_spawning_kind_under_check`). Every
    // sibling test over the committed bytes takes the same verb for the same
    // reason.
    let output = batten()
        .arg("enforce")
        .current_dir(&dirty)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a construct that cannot run on macOS is a policy violation"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "mise-tasks/seed:1 no-gnu-sed-z\n\
         mise-tasks/seed:2 no-gnu-sed-in-place\n\
         mise-tasks/seed:3 no-bash4-mapfile\n\
         mise-tasks/seed:4 no-gnu-xargs-r\n\
         mise-tasks/seed:5 no-util-linux-flock\n\
         tests/seed.bats:1 no-branch-f-main\n",
        "one sorted pointer per banned construct, and nothing else"
    );

    // The discriminator: the portable spellings this change adopted must be
    // SILENT, or the rows would forbid their own replacements. `-i.bak` is the
    // one in-place form BSD accepts, a `read` loop replaces `mapfile`, bare
    // `xargs` replaces the short flag, and a plain `branch main` off an explicitly
    // named branch replaces the force.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("config-portability-clean"),
    );
    let clean = repo_with_config("config-portability-clean", &contents);
    committed_budget_surfaces(&clean);
    let home = committed_config_fixture_git(&clean);
    fs::create_dir_all(clean.join("mise-tasks")).expect("create clean task dir");
    fs::write(
        clean.join("mise-tasks/seed"),
        "printf x | perl -0777 -pe 's/a/b/'\n\
         sed -i.bak 's/a/b/' file\n\
         while IFS= read -r l; do :; done < <(printf 'x\\n')\n\
         git ls-files | xargs grep x\n",
    )
    .expect("write clean task");
    fs::create_dir_all(clean.join("tests")).expect("create clean test dir");
    fs::write(clean.join("tests/seed.bats"), "\tgit branch main\n").expect("write clean suite");

    let output = batten()
        .arg("enforce")
        .current_dir(&clean)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the portable spellings are not violations"
    );
    assert!(
        output.stdout.is_empty(),
        "a portable tree prints nothing, got: {}",
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
    // `enforce`: the example's shipped rule delegates too, so the template
    // teaches the same verb the repo's own config needs (CLOUD-229).
    let output = batten()
        .arg("enforce")
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the example's shipped rule must fire on the shape it names: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "**/*.rs no-conflict-markers\n",
        "a command condemns a batch, so the pointer is the glob and carries no line"
    );
}

#[test]
fn the_shipped_starter_config_loads_over_the_binary() {
    // The same DoD obligation over the artifact `batten init` actually writes.
    // Held alongside the example above rather than instead of it: that file is a
    // teaching document a reader copies by hand, this is the file the binary
    // authors, and retiring the first is CLOUD-206's follow-up.
    let dir = repo_with_config("config-starter", batten::init::STARTER);
    let output = batten()
        .args(["config", "show", "--json"])
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten config show");
    assert_eq!(output.status.code(), Some(0), "the starter must load");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON on stdout");
    assert_eq!(value["version"]["value"], 1);

    // A scaffolded config must be able to produce a finding — a template whose
    // every rule can never fire teaches a new consumer that clean output means
    // nothing.
    //
    // Written a directory down, not at the root: the starter's glob deliberately
    // excludes root-level files, because a `forbid` pattern is a literal and a
    // repo-wide glob would report the config that declares it.
    let marker = format!("{} HEAD\n", "<".repeat(7));
    fs::create_dir_all(dir.join("src")).expect("create fixture source dir");
    fs::write(dir.join("src/main.rs"), marker).expect("write fixture source");
    // `check`, not `enforce`, and that is the starter diverging from the example
    // on purpose. CLOUD-229 moved the example's rule to `kind = "command"`
    // delegating to `hk`, which teaches the verb this repository's own config
    // needs — but a scaffold is read by someone who has just installed `batten`
    // and nothing else. `check` REFUSES a command rule (exit 1, the §5 split) and
    // `hk` is not on a fresh consumer's PATH, so that rule would make the first
    // command after `init` an error. The starter ships a self-contained `forbid`
    // instead: it runs under the read-effect verb, needs no second tool, and
    // still gates something real on day one.
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the starter's shipped rule must fire on the shape it names"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "src/main.rs:1 no-conflict-markers\n",
        "a forbid rule points at the line, not at the batch a command condemns"
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
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let own = fs::read_to_string(root.join("batten.toml")).expect("read batten.toml");
    let example =
        fs::read_to_string(root.join("batten.example.toml")).expect("read batten.example.toml");
    for (label, contents) in [
        ("batten.toml", own.as_str()),
        ("batten.example.toml", example.as_str()),
        ("the starter", batten::init::STARTER),
    ] {
        // The file text pins the keys — not merely the parsed result, which
        // would also be satisfied by a default the file never wrote down.
        let parsed: toml::Value = toml::from_str(contents).expect("committed config is TOML");
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
        let dir = repo_with_config(
            &format!("conformance-{}", label.replace(' ', "-")),
            contents,
        );
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

fn budget_config(files: &str, max_tokens: usize) -> String {
    format!("version = 1\n[budget.instructions]\nfiles = {files}\nmax_tokens = {max_tokens}\n")
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
fn an_over_budget_set_denies_through_check_not_only_policy_budget() {
    // The clause this issue was demoted from Done for. `policy budget` is the
    // introspection surface; a budget that only reported when somebody thought
    // to ask is a gate nobody runs. Enforcement is a finding on `check`.
    let dir = repo_with_config("budget-check-deny", &budget_config("[\"AGENTS.md\"]", 100));
    common::write(&dir, "AGENTS.md", &instructions_of(150));

    let output = common::run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "over budget is a policy verdict on the main gate"
    );
    let text = common::stdout(&output);
    assert!(
        text.contains("budget.instructions"),
        "the finding names which budget was exceeded: {text:?}"
    );
    assert!(
        !text.contains("xxxx"),
        "pointer-only: never a byte of what was counted: {text:?}"
    );

    // And it is an ordinary finding, so it appears in the machine channel with
    // the same shape every other finding has.
    let json = common::run(&dir, &["check", "-J"]);
    let parsed: serde_json::Value =
        serde_json::from_str(&common::stdout(&json)).expect("check -J is JSON");
    let findings = parsed["findings"].as_array().expect("findings array");
    assert!(
        findings
            .iter()
            .any(|finding| finding["rule"] == "budget.instructions"),
        "the budget finding rides the normal findings channel: {findings:?}"
    );
}

#[test]
fn a_set_within_budget_leaves_check_silent() {
    // The other half: the gate must not fire on a repository that is inside its
    // declared budget, or every consumer would carry a permanent violation.
    let dir = repo_with_config("budget-check-clean", &budget_config("[\"AGENTS.md\"]", 100));
    common::write(&dir, "AGENTS.md", &instructions_of(50));

    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "a set within budget says nothing");
}

#[test]
fn several_named_sets_are_each_measured_and_each_named() {
    // Rule 1, end to end: the set name is the consumer's, so a repository may
    // declare any number of budgets under names the engine has never heard of.
    let dir = repo_with_config(
        "budget-many",
        "version = 1\n\
         [budget.instructions]\n\
         files = [\"AGENTS.md\"]\n\
         max_tokens = 100\n\
         [budget.prompts]\n\
         files = [\"PROMPTS.md\"]\n\
         max_tokens = 100\n",
    );
    common::write(&dir, "AGENTS.md", &instructions_of(50));
    common::write(&dir, "PROMPTS.md", &instructions_of(150));

    let output = common::run(&dir, &["check"]);
    assert_eq!(output.status.code(), Some(2));
    let text = common::stdout(&output);
    assert!(
        text.contains("budget.prompts"),
        "the over-budget set is named: {text:?}"
    );
    assert!(
        !text.contains("budget.instructions"),
        "the set within budget raises nothing: {text:?}"
    );

    // `policy budget` reports every declared set as an array, so the shape does
    // not change as a consumer adds a second budget.
    let json = common::run(&dir, &["policy", "budget", "-J"]);
    let parsed: serde_json::Value =
        serde_json::from_str(&common::stdout(&json)).expect("policy budget -J is JSON");
    let sets = parsed.as_array().expect("an array of reports");
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0]["name"], "instructions", "reported in name order");
    assert_eq!(sets[1]["name"], "prompts");
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

// --- embedded always-loaded strings (CLOUD-298) -------------------------------
//
// A host that injects a key from its own config on every session is an
// always-loaded surface `files` cannot reach: the cost is a string inside a
// document, not a document. Left unmeasured it is the budget's own false green —
// a gate reporting green over content it never looked at.

/// A config counting `AGENTS.md` and one embedded key, with a token ceiling.
fn embedded_config(path: &str, key: &str, max_tokens: usize) -> String {
    format!(
        "version = 1\n[budget.instructions]\nfiles = [\"AGENTS.md\"]\nmax_tokens = \
         {max_tokens}\n\n[[budget.instructions.embedded]]\npath = '{path}'\nkey = \"{key}\"\n"
    )
}

/// A YAML document whose `prompt` key holds exactly `tokens` estimated tokens.
fn prompt_of(tokens: usize) -> String {
    format!("prompt: '{}'\nunrelated: 1\n", "x".repeat(tokens * 4))
}

#[test]
fn a_non_empty_embedded_value_is_counted_and_names_itself_in_the_report() {
    // Acceptance one and three together: the characters reach the total under
    // the same convention a file gets, and the surface appears as its own row —
    // so a counted surface names itself and an uncounted one cannot hide behind
    // a total.
    let dir = repo_with_config(
        "budget-embedded-counted",
        &embedded_config("host.yml", "prompt", 100),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(10));
    common::write(&dir, "host.yml", &prompt_of(25));

    let output = common::run(&dir, &["policy", "budget", "-J"]);
    assert_eq!(output.status.code(), Some(0), "35 of 100 is within budget");
    let parsed: serde_json::Value =
        serde_json::from_str(&common::stdout(&output)).expect("policy budget -J is JSON");
    assert_eq!(
        parsed[0]["tokens"], 35,
        "the embedded value's tokens join the total: {parsed}"
    );
    let rows = parsed[0]["files"].as_array().expect("per-file rows");
    assert!(
        rows.iter()
            .any(|row| row["path"] == "host.yml#prompt" && row["tokens"] == 25),
        "the embedded surface carries its own row, keyed path#key: {rows:?}"
    );
}

#[test]
fn an_embedded_value_can_cross_the_bound_on_its_own() {
    // The anti-vacuity partner of the test above, and the one that proves the
    // characters reach the *total* rather than only the report: the file half is
    // exactly at budget, so only the embedded half can carry it over.
    let dir = repo_with_config(
        "budget-embedded-over",
        &embedded_config("host.yml", "prompt", 100),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(100));
    common::write(&dir, "host.yml", &prompt_of(1));

    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "over budget is a policy verdict: {:?}",
        common::stdout(&output)
    );
    assert!(
        common::stdout(&output).contains("host.yml#prompt"),
        "the report names the surface that carried it over"
    );
}

#[test]
fn an_empty_absent_or_null_embedded_value_contributes_nothing_and_adds_no_row() {
    // The tree's current state, and why this is a gate rather than a fix in
    // passing: the key exists and is empty, so the gate must stay completely
    // quiet — a zero row would claim a surface was measured and free.
    for (case, document) in [
        ("empty", "prompt: ''\n"),
        ("absent", "unrelated: 1\n"),
        ("null", "prompt:\n"),
        ("empty-document", "\n"),
    ] {
        let dir = repo_with_config(
            &format!("budget-embedded-{case}"),
            &embedded_config("host.yml", "prompt", 100),
        );
        common::write(&dir, "AGENTS.md", &instructions_of(10));
        common::write(&dir, "host.yml", document);

        let output = common::run(&dir, &["policy", "budget", "-J"]);
        assert_eq!(output.status.code(), Some(0), "{case} contributes nothing");
        let parsed: serde_json::Value =
            serde_json::from_str(&common::stdout(&output)).expect("policy budget -J is JSON");
        assert_eq!(parsed[0]["tokens"], 10, "{case} adds no tokens: {parsed}");
        let rows = parsed[0]["files"].as_array().expect("per-file rows");
        assert!(
            rows.iter().all(|row| row["path"] != "host.yml#prompt"),
            "{case} adds no row: {rows:?}"
        );
    }
}

#[test]
fn an_unparseable_or_unreadable_embedded_source_is_exit_1_never_a_zero() {
    // The defect restated: an uncountable surface must not read as an empty one.
    // A silent zero here is indistinguishable from a genuinely empty key, which
    // is exactly the reading that made the dead glob pass as measured.
    for (case, file, document) in [
        ("malformed", "host.yml", "prompt: 'unterminated\n"),
        ("unknown-extension", "host.conf", "prompt = 1\n"),
    ] {
        let dir = repo_with_config(
            &format!("budget-embedded-{case}"),
            &embedded_config(file, "prompt", 10_000),
        );
        common::write(&dir, "AGENTS.md", &instructions_of(10));
        common::write(&dir, file, document);

        let output = common::run(&dir, &["policy", "budget"]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{case} is a config error, not a verdict and never a pass"
        );
        assert!(
            common::stderr(&output).contains(file),
            "{case}: the refusal must name the path it could not read"
        );
    }

    // A declared source that is not there at all is the same dead-entry refusal
    // `files` already gives, for the same reason.
    let dir = repo_with_config(
        "budget-embedded-missing",
        &embedded_config("host.yml", "prompt", 10_000),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(10));
    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(common::stderr(&output).contains("host.yml"));
}

#[test]
fn an_embedded_key_is_read_from_toml_and_json_by_the_same_rule() {
    // The dispatch is by extension, which is what makes the rule total: a path
    // either names a format the engine reads or is refused. TOML and JSON are
    // vendored already, so covering them costs nothing and keeps "YAML only"
    // from reading as a rule about one consumer's host.
    for (file, document) in [
        ("host.toml", "prompt = 'xxxxxxxx'\n"),
        ("host.json", "{\"prompt\": \"xxxxxxxx\"}\n"),
    ] {
        let dir = repo_with_config(
            &format!("budget-embedded-{file}"),
            &embedded_config(file, "prompt", 100),
        );
        common::write(&dir, "AGENTS.md", &instructions_of(10));
        common::write(&dir, file, document);

        let output = common::run(&dir, &["policy", "budget", "-J"]);
        assert_eq!(output.status.code(), Some(0));
        let parsed: serde_json::Value =
            serde_json::from_str(&common::stdout(&output)).expect("policy budget -J is JSON");
        assert_eq!(parsed[0]["tokens"], 12, "{file}: 10 + 2 = 12: {parsed}");
    }
}

#[test]
fn a_dotted_embedded_key_walks_maps_and_a_non_string_leaf_is_a_miss() {
    // Dotted for a nested key; maps only, so a leaf that is not a string is
    // absent rather than guessed at — a number's decimal spelling is not the
    // content a host injects.
    let dir = repo_with_config(
        "budget-embedded-nested",
        &embedded_config("host.yml", "a.b", 100),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(10));
    common::write(&dir, "host.yml", "a:\n  b: 'xxxxxxxx'\n");
    let output = common::run(&dir, &["policy", "budget", "-J"]);
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_str(&common::stdout(&output)).expect("policy budget -J is JSON");
    assert_eq!(parsed[0]["tokens"], 12, "the nested key is read: {parsed}");

    let dir = repo_with_config(
        "budget-embedded-nonstring",
        &embedded_config("host.yml", "a.b", 100),
    );
    common::write(&dir, "AGENTS.md", &instructions_of(10));
    common::write(&dir, "host.yml", "a:\n  b: 42\n");
    let output = common::run(&dir, &["policy", "budget", "-J"]);
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_str(&common::stdout(&output)).expect("policy budget -J is JSON");
    assert_eq!(parsed[0]["tokens"], 10, "a non-string leaf is a miss");
}

#[test]
fn a_config_declaring_no_budget_is_a_usage_error_not_a_silent_pass() {
    // A budget verb that measured nothing must not report `0`. That is the
    // false green the whole engine exists to catch.
    let dir = repo_with_config("budget-undeclared", "version = 1\n");
    let output = common::run(&dir, &["policy", "budget"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(common::stderr(&output).contains("budget"));

    // `check` reads the same absence the other way, and both are right: a
    // repository that declares no budget has no budget to fail, so the gate is
    // silent rather than refusing. Two callers asking different questions.
    let checked = common::run(&dir, &["check"]);
    assert_eq!(checked.status.code(), Some(0));
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
        instructions["files"].as_array().map(Vec::len),
        Some(1),
        "the counted set is AGENTS.md alone; adding an always-load surface is a \
         decision that shows up here"
    );
}

// --- `worktree status` (CLOUD-51) ---------------------------------------------
//
// The three at-risk categories as one read gate. The load-bearing property is
// that merged-ness is content, never ancestry: these consumers land by rebase
// and fast-forward, so a branch that landed perfectly is never an ancestor of
// the trunk, and every ancestry test reports finished work as outstanding.

/// A repository with one base commit, `origin/main` pinned to it, and a
/// `must_land_on` naming `target`.
fn worktree_repo(name: &str, target: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(&format!("version = 1\nmust_land_on = \"{target}\"\n"))
        .file("README.md", "base\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// Commit `body` at `path`, returning the new HEAD sha.
fn commit_file(dir: &std::path::Path, path: &str, body: &str, message: &str) -> String {
    common::write(dir, path, body);
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", message]);
    git_in(dir, &["rev-parse", "HEAD"])
}

/// Point `branch` at the pinned `origin/main` as its upstream, without a real
/// remote: the tracking ref already exists, so the branch config plus a fetch
/// refspec is the whole of what `@{upstream}` resolves through.
fn track_origin_main(dir: &std::path::Path, branch: &str) {
    git_in(dir, &["config", "remote.origin.url", "."]);
    git_in(
        dir,
        &[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
    );
    git_in(
        dir,
        &["config", &format!("branch.{branch}.remote"), "origin"],
    );
    git_in(
        dir,
        &[
            "config",
            &format!("branch.{branch}.merge"),
            "refs/heads/main",
        ],
    );
}

fn worktree_status(dir: &std::path::Path) -> Output {
    common::run(dir, &["worktree", "status"])
}

#[test]
fn a_dirty_tree_is_at_risk_and_names_the_count_not_the_paths() {
    let dir = worktree_repo("worktree-dirty", "main");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(2), "at-risk work is a verdict");
    let text = common::stdout(&output);
    assert!(
        text.contains("uncommitted: 1 paths"),
        "the report states the count: {text:?}"
    );
    // A count, never a path and never a diff (non-negotiable rule 4). The
    // primitive cannot return a path at all, so this is structural.
    assert!(!text.contains("scratch.txt"), "pointer-only: {text:?}");
    assert!(
        !text.contains("work in progress"),
        "never content: {text:?}"
    );
}

#[test]
fn a_committed_but_unpushed_branch_is_at_risk() {
    let dir = worktree_repo("worktree-unpushed", "origin/main");
    track_origin_main(&dir, "main");
    commit_file(&dir, "feature.txt", "shipped locally\n", "feat: local only");

    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        common::stdout(&output).contains("unpushed:"),
        "work the upstream does not carry is at risk: {:?}",
        common::stdout(&output)
    );
}

#[test]
fn a_rebased_and_landed_branch_reads_landed_though_ancestry_says_otherwise() {
    // The keystone, at the verb layer. The branch's commit was replayed onto the
    // target under a new SHA, so `main` is not an ancestor of the branch and no
    // reachability test can see the landing. Content can.
    let dir = worktree_repo("worktree-rebased", "main");
    git_in(&dir, &["checkout", "-q", "-b", "feature"]);
    let original = commit_file(&dir, "work.txt", "the work\n", "feat: the work");

    // The target moves first. That is why a rebase happens at all, and it is
    // also what makes the replay a genuinely different commit: cherry-picking
    // onto the *same* parent reproduces the original object exactly, so a test
    // that skipped this would assert nothing about new SHAs.
    git_in(&dir, &["checkout", "-q", "main"]);
    commit_file(
        &dir,
        "other.txt",
        "landed meanwhile\n",
        "feat: someone else",
    );
    git_in(&dir, &["cherry-pick", &original]);
    let landed_as = git_in(&dir, &["rev-parse", "HEAD"]);
    assert_ne!(original, landed_as, "the replay must mint a new SHA");
    git_in(&dir, &["checkout", "-q", "feature"]);

    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a rebased landing is landed: {:?}",
        common::stdout(&output)
    );
    assert_eq!(common::stdout(&output), "", "clean prints nothing");
}

#[test]
fn a_squash_merged_multi_commit_branch_reads_landed() {
    // The case per-commit patch identity alone under-detects: no individual
    // commit survived the merge, so only the branch's cumulative content matches.
    let dir = worktree_repo("worktree-squashed", "main");
    git_in(&dir, &["checkout", "-q", "-b", "feature"]);
    commit_file(&dir, "one.txt", "first\n", "feat: one");
    commit_file(&dir, "two.txt", "second\n", "feat: two");

    git_in(&dir, &["checkout", "-q", "main"]);
    git_in(&dir, &["merge", "--squash", "feature"]);
    git_in(
        &dir,
        &["commit", "-q", "-m", "feat: the whole branch, squashed"],
    );
    git_in(&dir, &["checkout", "-q", "feature"]);

    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a squash merge is landed: {:?}",
        common::stdout(&output)
    );
}

#[test]
fn a_clean_landed_checkout_prints_nothing_and_exits_0() {
    let dir = worktree_repo("worktree-clean", "main");
    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(common::stdout(&output), "", "success is silent");
}

#[test]
fn a_target_that_resolves_to_no_commit_is_exit_1_never_a_vacuous_pass() {
    let dir = worktree_repo("worktree-bad-target", "refs/heads/no-such-branch");
    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unresolvable target is a config error, not `nothing is at risk`"
    );
    assert!(common::stderr(&output).contains("does not resolve to a commit"));
}

#[test]
fn a_local_only_branch_raises_no_upstream_as_its_own_fact() {
    // Absence of an upstream is not safety. This is the branch that disappears
    // with the container it lived in, and the one an upstream-only check misses
    // entirely.
    //
    // §5 names the line `no-upstream <branch>` — its own category, not a
    // flavour of `unpushed`. The two have different fixes: `unpushed` says push,
    // `no-upstream` says set a tracking branch first, and a reader told only
    // "unpushed" runs `git push` and gets an error rather than a fix.
    let dir = worktree_repo("worktree-local-only", "main");
    git_in(&dir, &["checkout", "-q", "-b", "orphan"]);
    commit_file(&dir, "orphan.txt", "never pushed\n", "feat: orphan work");

    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = common::stdout(&output);
    assert!(
        text.contains("no-upstream: orphan"),
        "a branch tracking nothing raises its own fact: {text:?}"
    );
    assert!(
        text.contains("unlanded:") && text.contains("orphan@"),
        "and it is still unlanded, with a pointer naming the branch: {text:?}"
    );
    assert!(
        !text.contains("unpushed:"),
        "there is nowhere to have pushed it to, so that fact does not fire: {text:?}"
    );
}

#[test]
fn an_absent_target_key_falls_back_to_the_remotes_default_branch() {
    // The DoD's fallback: work lands on the trunk unless told otherwise, so an
    // absent `must_land_on` resolves `refs/remotes/<remote>/HEAD` rather than
    // refusing the invocation.
    let dir = Fixture::new("worktree-default-branch")
        .config("version = 1\n")
        .file("README.md", "base\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    git_in(&dir, &["config", "remote.origin.url", "."]);
    git_in(
        &dir,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
        ],
    );

    // Landed against the resolved default: silent 0, no config line required.
    let clean = worktree_status(&dir);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "the fallback resolves, and the branch is landed on it: {:?}",
        common::stdout(&clean)
    );
    assert!(clean.stdout.is_empty());

    // Work the default does not carry is unlanded against it, named as such.
    git_in(&dir, &["checkout", "-q", "-b", "feature"]);
    commit_file(&dir, "work.txt", "the work\n", "feat: the work");
    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = common::stdout(&output);
    assert!(
        text.contains("unlanded:") && text.contains("origin/main"),
        "the fallback target is named in the verdict: {text:?}"
    );
}

#[test]
fn no_resolvable_target_reports_not_computable_and_never_suppresses_the_rest() {
    // The clause this issue was demoted from Done for. A repository with no
    // `must_land_on` AND no remote default used to be a usage error, which meant
    // the verb reported *nothing at all* — not the dirty tree, not the branch
    // tracking nothing. The one configuration most likely to be a fresh, at-risk
    // checkout was the one the gate stayed silent about.
    //
    // Not-computable must never read as clean, and it must never suppress the
    // facts beside it.
    let dir = Fixture::new("worktree-no-target")
        .config("version = 1\n")
        .file("README.md", "base\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    common::write(&dir, "scratch.txt", "dirty\n");

    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown landedness is at-risk work, not a pass and not a usage error"
    );
    let text = common::stdout(&output);
    assert!(
        text.contains("unlanded: not-computable"),
        "the unknown says it is unknown: {text:?}"
    );
    assert!(
        text.contains("must_land_on"),
        "and names what would make it computable: {text:?}"
    );
    assert!(
        text.contains("uncommitted: 1 paths"),
        "the facts that COULD be computed still report — the whole point: {text:?}"
    );
    assert!(
        text.contains("no-upstream:"),
        "including the branch tracking nothing: {text:?}"
    );
}

#[test]
fn a_target_the_author_named_and_got_wrong_is_still_a_usage_error() {
    // Naming no target and naming a broken one are different mistakes. The
    // fallback covers the first; the second stays exit 1, because a target the
    // author wrote down and misspelled is a config error they need told about.
    let dir = worktree_repo("worktree-bad-target-still", "refs/heads/no-such-branch");
    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(1));
    assert!(common::stderr(&output).contains("does not resolve to a commit"));
}

#[test]
fn the_at_risk_report_is_byte_stable_across_runs() {
    let dir = worktree_repo("worktree-stable", "main");
    git_in(&dir, &["checkout", "-q", "-b", "feature"]);
    commit_file(&dir, "work.txt", "the work\n", "feat: the work");
    common::write(&dir, "scratch.txt", "dirty\n");

    let first = common::run(&dir, &["worktree", "status", "--json"]);
    let second = common::run(&dir, &["worktree", "status", "--json"]);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.status.code(), Some(2));
}

// --- the worktree pileup gate (CLOUD-46) --------------------------------------
//
// The counted predicate over the *machine* rather than this checkout, plus the
// snapshot-then-abandon path out of it. The load-bearing property is ordering:
// a worktree is only ever removed after its snapshot ref has been shown to
// resolve, so "the abandoned work is recoverable" is a property of the code
// path and not of the test that checks it.

/// A repository declaring `pileup_threshold`, with `count` linked worktrees.
///
/// Each linked worktree is left **clean**; the tests dirty exactly the ones they
/// mean to, so the predicate's conjunction is exercised rather than assumed.
fn pileup_repo(name: &str, threshold: usize, count: usize) -> (PathBuf, Vec<PathBuf>) {
    let dir = Fixture::new(name)
        .config(&format!(
            "version = 1\nmust_land_on = \"main\"\n\n[worktree]\npileup_threshold = {threshold}\n"
        ))
        .file("README.md", "base\n")
        // The linked worktrees live under `wt/`, inside the fixture so the
        // builder cleans them between runs — and ignored, so the main
        // checkout's own porcelain status stays empty. Without the ignore every
        // linked worktree would read as an untracked path in the main tree and
        // the `uncommitted` category would fire in tests that are about the
        // pileup category alone. This mirrors the real layout, where agent
        // worktrees sit in an ignored directory of the repository they came from.
        .file(".gitignore", "wt/\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

    let linked = (0..count)
        .map(|index| {
            let path = dir.join("wt").join(format!("wt{index}"));
            git_in(
                &dir,
                &[
                    "worktree",
                    "add",
                    "-q",
                    "-b",
                    &format!("wt{index}"),
                    path.to_str().expect("fixture path is UTF-8"),
                ],
            );
            path
        })
        .collect();
    (dir, linked)
}

/// Dirty `worktree` with a tracked edit, which is what `git stash create` can
/// capture. Untracked-only dirt is its own case and has its own test.
fn dirty(worktree: &std::path::Path) {
    common::write(worktree, "README.md", "edited in the worktree\n");
}

#[test]
fn a_pileup_at_the_threshold_is_a_verdict_naming_the_count_and_each_path() {
    let (dir, linked) = pileup_repo("pileup-over", 2, 2);
    for worktree in &linked {
        dirty(worktree);
    }

    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a pileup at the threshold is a policy verdict"
    );
    let text = common::stdout(&output);
    assert!(
        text.contains("pileup: 2 worktree(s) dirty and unreapable (threshold 2)"),
        "the report states the count and the bar it crossed: {text:?}"
    );
    // Each offending worktree, by path — the Ready block asks for the count and
    // the paths, and a path is a pointer, never the work in it.
    for worktree in &linked {
        let name = worktree
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture worktree name is UTF-8");
        assert!(
            text.contains(name),
            "the report names {name}, the worktree to go look at: {text:?}"
        );
    }
    assert!(
        !text.contains("edited in the worktree"),
        "the report is a pointer, never the content (rule 4): {text:?}"
    );
}

#[test]
fn a_clean_set_of_worktrees_exits_zero_and_says_nothing() {
    // Acceptance (b). The worktrees exist and are counted — they are simply not
    // dirty, so the conjunction is false and there is nothing to report.
    let (dir, _linked) = pileup_repo("pileup-clean", 1, 3);
    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        common::stdout(&output),
        "",
        "a clean run prints nothing (§6)"
    );
}

#[test]
fn a_count_below_the_threshold_is_not_a_pileup() {
    // The predicate is `>=`, so one dirty worktree under a threshold of two is
    // silent — and silent rather than reported-but-passing, because a report
    // nobody has to act on is noise a caller pays for every run.
    let (dir, linked) = pileup_repo("pileup-under", 2, 2);
    dirty(&linked[0]);

    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(!common::stdout(&output).contains("pileup"));
}

#[test]
fn a_locked_worktree_is_kept_deliberately_and_never_counted() {
    // A lock is an explicit "I am keeping this", which is the opposite of an
    // unreaped pileup — and `reclaim` must never remove one, so counting it
    // would be a verdict with no escape.
    let (dir, linked) = pileup_repo("pileup-locked", 1, 1);
    dirty(&linked[0]);
    git_in(
        &dir,
        &[
            "worktree",
            "lock",
            linked[0].to_str().expect("fixture path is UTF-8"),
        ],
    );

    let output = worktree_status(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(!common::stdout(&output).contains("pileup"));
}

#[test]
fn an_absent_threshold_still_reports_the_other_three_categories() {
    // The bug this module was demoted for once already (CLOUD-51's DoD audit),
    // in its second possible location: an absent key must not silence the
    // report, and must not become exit 1 either.
    let dir = worktree_repo("pileup-unconfigured", "main");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = worktree_status(&dir);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the dirty tree is still a verdict; the absent threshold is not an error"
    );
    let text = common::stdout(&output);
    assert!(text.contains("uncommitted: 1 paths"), "{text:?}");
    assert!(
        !text.contains("pileup"),
        "a threshold nobody declared reports nothing: {text:?}"
    );
}

#[test]
fn reclaim_previews_under_dry_run_and_mutates_nothing() {
    // Acceptance (c). The preview is structurally incapable of the mutation it
    // previews: `reclaim` returns before reaching a single git write.
    let (dir, linked) = pileup_repo("pileup-preview", 1, 1);
    dirty(&linked[0]);

    let output = common::run(&dir, &["worktree", "reclaim", "--dry-run"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        common::stderr(&output).contains("would reclaim:"),
        "the preview says what it would do: {:?}",
        common::stderr(&output)
    );
    assert!(linked[0].exists(), "the worktree is still there");
    assert_eq!(
        git_in(
            &dir,
            &["for-each-ref", "--format=%(refname)", "refs/batten"]
        ),
        "",
        "a preview writes no snapshot ref"
    );
}

#[test]
fn reclaim_snapshots_then_abandons_and_the_work_is_recoverable() {
    // Acceptance (d), and the whole safety argument: the worktree is gone, and
    // the ref the report named still holds the work that was in it.
    let (dir, linked) = pileup_repo("pileup-reclaim", 1, 1);
    dirty(&linked[0]);

    let output = common::run(&dir, &["worktree", "reclaim", "--yes"]);
    assert_eq!(output.status.code(), Some(0));
    let text = common::stderr(&output);
    assert!(text.contains("reclaimed:"), "{text:?}");
    assert!(!linked[0].exists(), "the worktree was abandoned");

    // The snapshot ref exists, and it carries the abandoned edit — recoverable
    // is the claim, so the test reads the content back rather than trusting the
    // ref's existence to imply it.
    let refs = git_in(
        &dir,
        &["for-each-ref", "--format=%(refname)", "refs/batten"],
    );
    let snapshot = refs.lines().next().expect("a snapshot ref was written");
    assert!(snapshot.starts_with("refs/batten/snapshot/"), "{refs:?}");
    let recovered = git_in(&dir, &["show", &format!("{snapshot}:README.md")]);
    assert_eq!(
        recovered, "edited in the worktree",
        "the abandoned work is readable from the snapshot"
    );

    // And the count it existed to bring down has come down.
    assert_eq!(worktree_status(&dir).status.code(), Some(0));
}

#[test]
fn reclaim_without_confirmation_refuses_with_instructions_and_removes_nothing() {
    // §4: destructive plus no `-y` refuses with the exact flag needed. Exit 1,
    // not 2 — "you did not pass the flag" is a usage error, and §7 keeps the
    // verdict code for verdicts.
    let (dir, linked) = pileup_repo("pileup-unconfirmed", 1, 1);
    dirty(&linked[0]);

    let output = common::run(&dir, &["worktree", "reclaim"]);
    assert_eq!(output.status.code(), Some(1));
    let text = common::stderr(&output);
    assert!(
        text.contains("--yes"),
        "the refusal names the flag that answers it: {text:?}"
    );
    assert!(linked[0].exists(), "nothing was removed");
}

#[test]
fn a_worktree_nothing_can_snapshot_is_left_in_place() {
    // The fail-closed edge, and the reason `stash_create` returns an Option:
    // git captures no commit for a tree dirty only with untracked files, and
    // removing on that answer would destroy exactly the work this verb exists
    // to preserve.
    let (dir, linked) = pileup_repo("pileup-untracked", 1, 1);
    common::write(&linked[0], "only-untracked.txt", "never committed\n");

    let output = common::run(&dir, &["worktree", "reclaim", "--yes"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "work that cannot be made recoverable is a verdict about this machine"
    );
    let text = common::stderr(&output);
    assert!(text.contains("refused:"), "{text:?}");
    assert!(
        linked[0].exists(),
        "the worktree holding unrecoverable work was not touched"
    );
}

#[test]
fn reclaim_without_a_declared_threshold_is_a_usage_error() {
    // Unlike `status`, this verb has nothing else to answer: reclaiming against
    // a threshold nobody declared would mean choosing the threshold itself.
    let dir = worktree_repo("pileup-no-threshold", "main");
    let output = common::run(&dir, &["worktree", "reclaim", "--yes"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        common::stderr(&output).contains("pileup_threshold"),
        "the refusal names the missing key: {:?}",
        common::stderr(&output)
    );
}

// --- the findings store's identity (CLOUD-164) --------------------------------

/// A repo fixture for the store tests, plus the `home` that isolates the
/// out-of-tree store. Separate from [`receipt_fixture`] in one respect that
/// matters: it takes the directory name, because *basename collision* is one of
/// the behaviours under test and cannot be exercised through a fixed layout.
/// `distinct` seeds a file so the repository gets its own root commit. The
/// harness pins author and committer dates for determinism, so two fixtures with
/// byte-identical history would share a commit SHA — and a shared root commit
/// means "the same repository" to this module, quite correctly. Real unrelated
/// repositories never collide there; fixtures have to be told not to.
fn store_fixture(group: &str, parent: &str, name: &str, distinct: &str) -> (PathBuf, PathBuf) {
    let root = scratch(group);
    let repo = Fixture::at(root.join(parent).join(name))
        .config("version = 1\n")
        .file("seed.txt", distinct)
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// Run `batten` in `dir` with the store isolated under `home`, and repository
/// discovery fenced to the test tmpdir — so a fixture that forgot `git init`
/// fails loudly rather than resolving the real batten checkout and writing a
/// store marker into its `.git/`.
fn store_cmd(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    batten()
        .args(args)
        .current_dir(dir)
        .state_home(home)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten state")
}

/// The store id bound to `dir`, read from the marker the repository carries.
///
/// Read through the marker rather than by scanning the state dir, because the
/// marker is the repository→store direction the design depends on: a test that
/// scanned instead would pass even if the marker were never written.
fn bound_store_id(dir: &std::path::Path) -> String {
    fs::read_to_string(dir.join(".git").join("batten-store"))
        .expect("the repository carries a store marker")
        .trim()
        .to_owned()
}

#[test]
fn adopting_mints_one_store_and_is_idempotent() {
    let (repo, home) = store_fixture("store-mint", "parent", "proj", "mint");

    let first = store_cmd(&repo, &home, &["state", "adopt"]);
    assert_eq!(first.status.code(), Some(0));
    let minted = bound_store_id(&repo);
    assert_eq!(minted.len(), 64, "a store id is 64 hex characters");
    assert!(minted.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        String::from_utf8_lossy(&first.stderr).contains("minted"),
        "minting a store is announced, never silent"
    );

    // Re-running binds the same store: resolution asks every criterion before
    // it mints, so a second run cannot mint a second one.
    let again = store_cmd(&repo, &home, &["state", "adopt"]);
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(
        bound_store_id(&repo),
        minted,
        "a second run re-mints nothing"
    );
}

#[test]
fn two_repos_sharing_a_directory_name_do_not_share_a_store() {
    // Acceptance (b). Basename keying is disqualified precisely because it
    // merges same-named strangers; both repos here are called `proj` and share
    // one state root, and they must still hold two distinct stores.
    let (one, home) = store_fixture("store-strangers", "a", "proj", "repo-a");
    let two = Fixture::at(
        one.parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("b")
            .join("proj"),
    )
    .config("version = 1\n")
    .file("seed.txt", "repo-b")
    .git()
    .base_commit()
    .build();

    assert_eq!(
        store_cmd(&one, &home, &["state", "adopt"]).status.code(),
        Some(0)
    );
    assert_eq!(
        store_cmd(&two, &home, &["state", "adopt"]).status.code(),
        Some(0)
    );

    assert_ne!(
        bound_store_id(&one),
        bound_store_id(&two),
        "same-named strangers must not merge onto one store"
    );
}

#[test]
fn a_moved_no_remote_repo_keeps_its_store() {
    // Acceptance (c). A move changes the common dir AND the basename at once,
    // which is why neither can be the key: with no remote to fall back on, the
    // marker and the minted id are all that carry continuity across it.
    let (repo, home) = store_fixture("store-moved", "before", "proj", "moved");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "adopt"]).status.code(),
        Some(0)
    );
    let minted = bound_store_id(&repo);

    // Move it, and rename it while we are at it: the basename hint is now wrong
    // as well as the path.
    let moved = repo.parent().unwrap().join("renamed");
    fs::rename(&repo, &moved).expect("move the repository");

    let after = store_cmd(&moved, &home, &["state", "adopt"]);
    assert_eq!(after.status.code(), Some(0));
    assert_eq!(
        bound_store_id(&moved),
        minted,
        "a moved repository is adopted by its store, never orphaned onto a fresh one"
    );
    assert!(
        String::from_utf8_lossy(&after.stderr).contains("migrated"),
        "a key-material change is reported, never silent"
    );
}

#[test]
fn a_linked_worktree_resolves_to_the_main_repositorys_store() {
    // The store half of acceptance (a): worktree siblings must not split. The
    // root resolver answers with the *common* dir's parent, so a call from
    // inside a linked worktree names the main repository — which is what makes
    // one defect seen from two worktrees one finding rather than two.
    let (repo, home) = store_fixture("store-worktree", "parent", "proj", "worktree");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "adopt"]).status.code(),
        Some(0)
    );
    let minted = bound_store_id(&repo);

    let tree = repo.parent().unwrap().join("wt");
    git_in(
        &repo,
        &["worktree", "add", "-b", "topic", tree.to_str().unwrap()],
    );

    let from_worktree = store_cmd(&tree, &home, &["state", "adopt"]);
    assert_eq!(from_worktree.status.code(), Some(0));
    assert_eq!(
        bound_store_id(&repo),
        minted,
        "a linked worktree binds the main repository's store, never a second one"
    );
}

#[test]
fn adopting_outside_a_repository_is_a_usage_error() {
    // Not a repository: exit 1, never a mint. A store minted against whatever
    // repository happened to be up the tree would bind the wrong one.
    //
    // **Outside the tree, not under `target/`, and `GIT_CEILING_DIRECTORIES` is
    // not what saves this.** `git::repo_root` scrubs the discovery *fences* on
    // purpose — its answer must be a function of the path and the filesystem
    // alone — so a fixture under `target/` walks straight up into this
    // repository's own `.git`. Measured: the first version of this test adopted
    // a store for the real batten checkout and wrote a marker into it.
    let loose = scratch_outside_tree("store-no-repo", "loose");
    let home = scratch_outside_tree("store-no-repo", "home");

    let output = store_cmd(&loose, &home, &["state", "adopt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!loose.join(".git").exists());
}

#[test]
fn adopting_a_store_id_that_does_not_exist_is_refused() {
    // A typo must not silently bind the wrong store, and must not mint one
    // either — the named form is an override of resolution, not a create.
    let (repo, home) = store_fixture("store-bad-id", "parent", "proj", "bad-id");
    let output = store_cmd(&repo, &home, &["state", "adopt", &"f".repeat(64)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no store with id"),
        "the refusal names what was not found"
    );
}

// --- the `[judge]` loader surface (CLOUD-135) ---------------------------------

#[test]
fn an_unknown_judge_key_is_a_hard_schema_error() {
    // The config surface stays narrow: a typo inside `[judge]` must never
    // silently widen — or silently fail to widen — the payload boundary.
    let dir = repo_with_config(
        "judge-unknown-key",
        "version = 1\n\n[judge]\nbogus = true\n",
    );
    let output = common::run(&dir, &["config", "lint"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an unknown key is a usage error"
    );
    assert!(common::stderr(&output).contains("bogus"));
}

#[test]
fn an_unknown_payload_class_is_refused_rather_than_ignored() {
    // A class the engine does not know is not a class it may quietly drop: the
    // author asked for something, and silently admitting nothing would read in
    // the file as an opt-in that is not one.
    let dir = repo_with_config(
        "judge-unknown-class",
        "version = 1\n\n[judge]\nraw = [\"everything\"]\n",
    );
    let output = common::run(&dir, &["config", "lint"]);
    assert_eq!(output.status.code(), Some(1));
}

// --- the findings ledger (CLOUD-164) ------------------------------------------

/// One stored finding as `state list -J` reports it.
#[derive(Debug, PartialEq, Eq)]
struct StoredFinding {
    fingerprint: String,
    rule: String,
    /// `(context, observed count)` per instance, in the order the store emits.
    instances: Vec<(String, i64)>,
}

/// `state list -J`, parsed.
///
/// Read through the machine channel rather than the pointer lines, so these
/// assert the contract a consumer depends on rather than a rendering.
fn stored_findings(dir: &std::path::Path, home: &std::path::Path) -> Vec<StoredFinding> {
    let output = store_cmd(dir, home, &["state", "list", "-J"]);
    assert_eq!(output.status.code(), Some(0), "state list always succeeds");
    let text = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("state list -J is JSON");
    parsed
        .as_array()
        .expect("a JSON array")
        .iter()
        .map(|record| {
            let instances = record["instances"]
                .as_array()
                .expect("instances")
                .iter()
                .map(|instance| {
                    (
                        instance["context"].as_str().expect("context").to_owned(),
                        instance["occurrences"]["Observed"]
                            .as_i64()
                            .expect("an observed count"),
                    )
                })
                .collect();
            StoredFinding {
                fingerprint: record["identity"]["fingerprint"]
                    .as_str()
                    .expect("fingerprint")
                    .to_owned(),
                rule: record["rule"].as_str().expect("rule").to_owned(),
                instances,
            }
        })
        .collect()
}

/// A repo whose config forbids `TODO`, with one offending file.
///
/// It carries `no_fix_reason` because these fixtures record to the store, and a
/// stored finding is one something later has to close (CLOUD-81). A rule with
/// neither remediation column still gates — see
/// [`state_record_refuses_a_finding_with_no_remediation`] for that half.
fn ledger_fixture(name: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nseverity = \"deny\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nno_fix_reason = \"delete the marker by hand\"\n")
        .file("src/a.rs", "fn main() {}\n// TODO fix me\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

#[test]
fn check_and_state_list_name_the_same_finding_by_the_same_key() {
    // CLOUD-322's whole point: a key that does not join the two documents is not
    // a key. `check -J` reports what it just found, `state list -J` reports what
    // the store holds, and until now they described the same defect with nothing
    // in common. Run both against ONE store and assert the fingerprints are
    // equal — not merely well-formed, which a second derivation would also be.
    let (repo, home) = ledger_fixture("identity-join");

    let recorded = store_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(recorded.status.code(), Some(0));

    let checked = store_cmd(&repo, &home, &["check", "-J"]);
    assert_eq!(
        checked.status.code(),
        Some(2),
        "a deny-severity match is a policy verdict"
    );
    let report: serde_json::Value =
        serde_json::from_str(&String::from_utf8(checked.stdout).expect("stdout is UTF-8"))
            .expect("check -J is JSON");

    let stored = stored_findings(&repo, &home);
    assert_eq!(stored.len(), 1, "one defect, one finding");
    assert_eq!(
        report["findings"][0]["identity"]["fingerprint"]
            .as_str()
            .expect("check -J carries the identity"),
        stored[0].fingerprint,
        "the same span mints the same fingerprint on both surfaces"
    );
    assert_eq!(report["findings"][0]["rule"], "no-todo");

    // Pointer, never payload (rule 4): the identity is a digest, so the matched
    // line must not appear anywhere in the document that now carries it.
    let text = serde_json::to_string(&report).expect("re-serialize");
    assert!(!text.contains("TODO fix me"), "pointer-only: {text}");
}

#[test]
fn state_record_refuses_a_finding_with_no_remediation() {
    // CLOUD-81 acceptance (c)/(d), over the compiled binary — the exit code a
    // consumer actually sees. A rule with neither `fix` nor `no_fix_reason`
    // still loads and still gates, because refusing at load would turn a
    // store-shaped requirement into a gate outage; what it cannot do is put a
    // finding in the store that nothing can close.
    let root = scratch("ledger-no-remediation");
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nseverity = \"deny\"\n\
             glob = \"**/*.rs\"\npattern = \"TODO\"\n",
        )
        .file("src/a.rs", "fn main() {}\n// TODO fix me\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    // The gate still renders its verdict: exit 2, the policy code.
    assert_eq!(
        store_cmd(&repo, &home, &["check"]).status.code(),
        Some(2),
        "an un-remediated rule still gates"
    );

    // Storing it does not. Exit 1 — the config-error code, never the 2 that is
    // the deny channel (house style §7): a malformed rule must not be able to
    // deny a call.
    let recorded = store_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(1),
        "no remediation is a config error, not a policy verdict"
    );
    let stderr = String::from_utf8(recorded.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("no_fix_reason"), "it names the remedy");
    assert!(
        !stderr.contains("TODO fix me"),
        "pointer-only, never the flagged content: {stderr}"
    );
}

#[test]
fn a_defect_seen_from_two_worktrees_is_one_finding_with_two_instances() {
    // Acceptance (a), end to end. The same defect observed from two worktrees
    // must be ONE finding — and fixing it in one must not disturb the other's
    // count, or the pair would flap as scans interleave.
    let (repo, home) = ledger_fixture("ledger-worktree");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "record"]).status.code(),
        Some(0)
    );

    let tree = repo.parent().unwrap().join("wt");
    git_in(
        &repo,
        &["worktree", "add", "-b", "topic", tree.to_str().unwrap()],
    );
    assert_eq!(
        store_cmd(&tree, &home, &["state", "record"]).status.code(),
        Some(0)
    );

    let stored = stored_findings(&repo, &home);
    assert_eq!(
        stored.len(),
        1,
        "one defect is one finding, not one per worktree"
    );
    assert_eq!(stored[0].rule, "no-todo");
    assert_eq!(
        stored[0].instances,
        vec![
            ("refs/heads/main".to_owned(), 1),
            ("refs/heads/topic".to_owned(), 1),
        ],
        "one instance per ref, sorted, each counting for itself"
    );

    // Fix it on `topic` only. The finding survives, `topic` goes to zero, and
    // `main`'s count is untouched — a scan that never ran there re-evaluates
    // nothing there.
    common::write(&tree, "src/a.rs", "fn main() {}\n");
    assert_eq!(
        store_cmd(&tree, &home, &["state", "record"]).status.code(),
        Some(0)
    );

    let after = stored_findings(&repo, &home);
    assert_eq!(after.len(), 1, "the finding survives a fix in one context");
    assert_eq!(
        after[0].instances,
        vec![
            ("refs/heads/main".to_owned(), 1),
            ("refs/heads/topic".to_owned(), 0),
        ],
        "no count-thrash: only the context that was scanned moved"
    );

    // Re-recording with nothing changed is byte-identical — no flap.
    assert_eq!(
        store_cmd(&tree, &home, &["state", "record"]).status.code(),
        Some(0)
    );
    assert_eq!(
        stored_findings(&repo, &home),
        after,
        "a repeat scan changes nothing"
    );
}

#[test]
fn deleting_a_ref_gcs_its_instances_and_keeps_the_finding() {
    // Acceptance (d). Liveness is ref EXISTENCE: these repos land by
    // fast-forward, so a reachability test would collect work that landed fine.
    let (repo, home) = ledger_fixture("ledger-gc");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "record"]).status.code(),
        Some(0)
    );

    let tree = repo.parent().unwrap().join("wt");
    git_in(
        &repo,
        &["worktree", "add", "-b", "doomed", tree.to_str().unwrap()],
    );
    assert_eq!(
        store_cmd(&tree, &home, &["state", "record"]).status.code(),
        Some(0)
    );
    assert_eq!(stored_findings(&repo, &home)[0].instances.len(), 2);

    // Remove the worktree and its branch, then re-record from the survivor.
    git_in(
        &repo,
        &["worktree", "remove", "--force", tree.to_str().unwrap()],
    );
    git_in(&repo, &["branch", "-D", "doomed"]);
    assert_eq!(
        store_cmd(&repo, &home, &["state", "record"]).status.code(),
        Some(0)
    );

    let after = stored_findings(&repo, &home);
    assert_eq!(
        after.len(),
        1,
        "the finding survives on its remaining instance"
    );
    assert_eq!(
        after[0].instances,
        vec![("refs/heads/main".to_owned(), 1)],
        "the dead ref's instance is collected, the live one is not"
    );
}

#[test]
fn recording_on_a_detached_head_is_refused_rather_than_keyed_to_nothing() {
    // An instance is keyed by ref, and a detached HEAD has none. Inventing a
    // synthetic key would mint an instance ref-death GC could never collect,
    // because the ref it names never existed to die.
    let (repo, home) = ledger_fixture("ledger-detached");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    git_in(&repo, &["checkout", "--detach", head.trim()]);

    let output = store_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("detached"),
        "the refusal names why"
    );
}

#[test]
fn listing_an_unbound_repository_succeeds_and_says_nothing_by_default() {
    // A stored finding is a record, never a fresh verdict: `check` already spent
    // the 2. `state list` must not put the store on the deny channel.
    let (repo, home) = ledger_fixture("ledger-unbound");
    let output = store_cmd(&repo, &home, &["state", "list"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "no findings, no pointer lines");
    assert!(
        output.stderr.is_empty(),
        "an unbound store is an ordinary first-run state, not progress to announce"
    );

    // The note is on the ladder, not deleted: asking for detail produces it.
    let loud = store_cmd(&repo, &home, &["state", "list", "-v"]);
    assert!(String::from_utf8_lossy(&loud.stderr).contains("no store is bound"));
}

// --- store format versioning (CLOUD-78) ---------------------------------------
//
// No implicit upgrades. A binary writes the store's version and reads a window
// around it; the only thing that moves a store forward is `state migrate`. The
// alternative — upgrading on a read path — turns a routine `check` in one
// worktree into an outage for an older binary reading the same store from
// another.

/// The store directory bound to `repo`, located through the marker.
fn bound_store_dir(repo: &std::path::Path, home: &std::path::Path) -> PathBuf {
    let id = bound_store_id(repo);
    let mut found = None;
    for entry in walk_dirs(&home.join("data")) {
        if entry.join("store.json").is_file()
            && fs::read_to_string(entry.join("store.json")).is_ok_and(|text| text.contains(&id))
        {
            found = Some(entry);
            break;
        }
    }
    found.expect("the bound store directory exists under the state dir")
}

/// Every directory under `root`, breadth-first. Test-local; the crate has no
/// recursive-walk helper exposed for tests.
fn walk_dirs(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut queue = vec![root.to_path_buf()];
    while let Some(dir) = queue.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            if path.is_dir() {
                queue.push(path.clone());
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn migrate_upgrades_an_older_store_and_nothing_else_does() {
    // The keystone of the versioning rule, end to end over the binary: a store
    // pinned to the oldest record version stays there across ordinary verbs, and
    // moves only when `state migrate` is run.
    let (repo, home) = ledger_fixture("ledger-migrate");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "record"]).status.code(),
        Some(0)
    );
    let store_dir = bound_store_dir(&repo, &home);
    let format_path = store_dir.join("journal").join("format.json");

    // Pin it back to the oldest version, as an older binary would have left it.
    let format = fs::read_to_string(&format_path).expect("a format record");
    let mut parsed: serde_json::Value = serde_json::from_str(&format).expect("format is JSON");
    let current = parsed["findingsSchema"].as_u64().expect("a version");
    parsed["findingsSchema"] = serde_json::json!(1);
    fs::write(&format_path, parsed.to_string()).expect("pin the format");

    // An ordinary read verb must NOT upgrade it.
    assert_eq!(
        store_cmd(&repo, &home, &["state", "list"]).status.code(),
        Some(0)
    );
    let after_read: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&format_path).unwrap()).unwrap();
    assert_eq!(
        after_read["findingsSchema"].as_u64(),
        Some(1),
        "a read path must never upgrade the store"
    );

    // `state migrate` is the one thing that does.
    let migrated = store_cmd(&repo, &home, &["state", "migrate"]);
    assert_eq!(migrated.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&migrated.stderr).contains("state migrate"),
        "the migration reports what it did"
    );
    let after_migrate: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&format_path).unwrap()).unwrap();
    assert_eq!(after_migrate["findingsSchema"].as_u64(), Some(current));

    // Idempotent: running it again is a no-op that still exits 0.
    assert_eq!(
        store_cmd(&repo, &home, &["state", "migrate"]).status.code(),
        Some(0)
    );
}

#[test]
fn a_store_newer_than_the_binary_is_read_only_and_still_allows() {
    // Degraded read-only: an out-of-date binary is an operator problem, and
    // refusing the agent's work is not how it gets fixed. So this path exits 0,
    // says `persisted:false`, and never reaches the deny channel.
    let (repo, home) = ledger_fixture("ledger-degraded");
    assert_eq!(
        store_cmd(&repo, &home, &["state", "record"]).status.code(),
        Some(0)
    );
    let store_dir = bound_store_dir(&repo, &home);
    let format_path = store_dir.join("journal").join("format.json");
    let mut parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&format_path).unwrap()).unwrap();
    let current = parsed["findingsSchema"].as_u64().expect("a version");
    parsed["findingsSchema"] = serde_json::json!(current + 1);
    fs::write(&format_path, parsed.to_string()).expect("advance the format");

    let output = store_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a store it cannot write is never a deny and never an internal error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("degraded read-only"),
        "the degradation is announced, not silent: {stderr}"
    );
    assert!(
        stderr.contains("persisted:false"),
        "the emission says it was not persisted: {stderr}"
    );

    // Reads still work — dedupe keeps functioning in degraded mode.
    assert_eq!(
        store_cmd(&repo, &home, &["state", "list"]).status.code(),
        Some(0)
    );

    // And migrating DOWN is refused rather than silently truncating fields.
    let refused = store_cmd(&repo, &home, &["state", "migrate"]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a binary older than the store cannot migrate it"
    );
}

// --- warm-fork restart (CLOUD-83) ---------------------------------------------
//
// A warm fork abandons the trajectory and keeps the working state. Almost
// everything survives because it was never in the forked process; what does not
// is the reader's position and the session key an open sequence-kind finding was
// minted under. Every `batten` invocation below is a separate process, so each
// pair of runs IS a restart — there is no in-process state for one to leak to
// the next.

/// `store_cmd`, plus the session environment a fork inherits.
///
/// A warm fork inherits its parent's environment, which is exactly why the parent
/// is declared there rather than inferred from the store — so these tests set it
/// the same way a forking host would.
fn session_cmd(
    dir: &std::path::Path,
    home: &std::path::Path,
    session: &str,
    parent: Option<&str>,
    args: &[&str],
) -> Output {
    let mut command = batten();
    command
        .args(args)
        .current_dir(dir)
        .state_home(home)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env("BATTEN_SESSION", session);
    match parent {
        Some(parent) => command.env("BATTEN_SESSION_PARENT", parent),
        // Explicitly cleared rather than merely unset, so a test cannot inherit a
        // parent from whatever environment the suite happens to run in.
        None => command.env_remove("BATTEN_SESSION_PARENT"),
    };
    command.output().expect("run batten with a session")
}

/// The session records the store holds, as `(parent, holder -> seqno)` per file.
///
/// Read off disk rather than through a verb: no verb reports them, deliberately —
/// CLOUD-83 adds no command — so the store is the only place to assert the
/// durable half.
fn session_records(store_dir: &std::path::Path) -> Vec<serde_json::Value> {
    let dir = store_dir.join("sessions");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            serde_json::from_str(&fs::read_to_string(path).expect("read a session record"))
                .expect("a session record is JSON")
        })
        .collect()
}

/// The one record whose `session` is `key`.
fn session_record(store_dir: &std::path::Path, key: &str) -> serde_json::Value {
    session_records(store_dir)
        .into_iter()
        .find(|record| record["session"] == key)
        .unwrap_or_else(|| panic!("the store holds a record for session {key}"))
}

#[test]
fn a_fork_resumes_at_its_parents_cursor_with_every_finding_intact() {
    // Acceptance (a) and (c) together, because one mechanism serves both: the
    // cursor is stored on the LINEAGE ROOT, so the fork finds its parent's
    // position without knowing it was forked, and a position it can honour is a
    // delta rather than the full resync that would re-emit an unchanged set.
    let (repo, home) = ledger_fixture("fork-resume");

    let first = session_cmd(&repo, &home, "alpha", None, &["state", "record", "-v"]);
    assert_eq!(first.status.code(), Some(0));
    let before = stored_findings(&repo, &home);
    assert_eq!(before.len(), 1, "the scan found the planted defect");
    // The whole document, not the parsed subset: §2's predicate is that a
    // kill-and-restart preserves the store BYTE-FOR-BYTE, which covers the
    // fields `stored_findings` drops — the tier, the presentation and the
    // disposition among them.
    let before_bytes = store_cmd(&repo, &home, &["state", "list", "-J"]).stdout;

    let store_dir = bound_store_dir(&repo, &home);
    let parent = session_record(&store_dir, "alpha");
    assert!(
        parent["parent"].is_null(),
        "the first session is nobody's fork: {parent}"
    );
    let held = parent["cursors"]["record"].clone();
    assert!(
        held["generation"].is_string() && held["seqno"].is_number(),
        "the parent left a resume point: {parent}"
    );

    // A separate process, declaring itself a fork of the first.
    let forked = session_cmd(
        &repo,
        &home,
        "beta",
        Some("alpha"),
        &["state", "record", "-v"],
    );
    assert_eq!(forked.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&forked.stderr);
    assert!(
        stderr.contains("resumed"),
        "the fork resumed from a cursor: {stderr}"
    );
    assert!(
        !stderr.contains("full resync"),
        "a fork with its parent's position must never re-hand itself the whole set: {stderr}"
    );

    // The edge is recorded on the fork, and the cursor stays on the root: two
    // records, one position.
    assert_eq!(session_record(&store_dir, "beta")["parent"], "alpha");
    assert!(
        session_record(&store_dir, "beta")["cursors"]
            .as_object()
            .is_none_or(serde_json::Map::is_empty),
        "the position belongs to the lineage root, not to each descendant"
    );
    assert_eq!(
        session_record(&store_dir, "alpha")["cursors"]["record"],
        held,
        "an unchanged journal leaves the root's position where it was"
    );

    // And the findings themselves are untouched by any of it.
    assert_eq!(
        stored_findings(&repo, &home),
        before,
        "a restart preserves the store, findings and instances alike"
    );
    assert_eq!(
        store_cmd(&repo, &home, &["state", "list", "-J"]).stdout,
        before_bytes,
        "byte-for-byte: every field survives, including the ones no verb can \
         vary yet — a disposition set by a future caller must survive too, and \
         a comparison over a parsed subset would not notice if it stopped"
    );
}

#[test]
fn a_rotated_generation_still_forces_the_resync_it_exists_to_force() {
    // The resume point must not become a way to honour a cursor that is no longer
    // honourable. GC rotates the generation, which invalidates every outstanding
    // position by construction — the stored one included, since it is read back
    // through the same `since` every other reader uses.
    let (repo, home) = ledger_fixture("fork-rotate");
    assert_eq!(
        session_cmd(&repo, &home, "alpha", None, &["state", "record"])
            .status
            .code(),
        Some(0)
    );

    // A second ref, then its death, is what makes GC drop instances and rotate.
    let tree = repo.parent().unwrap().join("wt");
    git_in(
        &repo,
        &["worktree", "add", "-b", "doomed", tree.to_str().unwrap()],
    );
    assert_eq!(
        session_cmd(&tree, &home, "alpha", None, &["state", "record"])
            .status
            .code(),
        Some(0)
    );
    git_in(
        &repo,
        &["worktree", "remove", "--force", tree.to_str().unwrap()],
    );
    git_in(&repo, &["branch", "-D", "doomed"]);

    let store_dir = bound_store_dir(&repo, &home);
    let before = session_record(&store_dir, "alpha")["cursors"]["record"]["generation"].clone();

    let collected = session_cmd(
        &repo,
        &home,
        "beta",
        Some("alpha"),
        &["state", "record", "-v"],
    );
    assert_eq!(collected.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&collected.stderr);
    assert!(
        stderr.contains("full resync"),
        "a cursor from a retired generation must resync, never delta: {stderr}"
    );
    assert_ne!(
        session_record(&store_dir, "alpha")["cursors"]["record"]["generation"],
        before,
        "the stored position moves to the live generation"
    );
}

#[test]
fn an_undeclared_session_leaves_the_store_and_the_report_untouched() {
    // Absent is not empty (`transcript.rs`'s law). A host that supplies no
    // session is a repository not using this, so nothing is written and the
    // byte-stable one-line report is exactly what it was before any of this.
    let (repo, home) = ledger_fixture("fork-unconfigured");
    let plain = store_cmd(&repo, &home, &["state", "record", "-v"]);
    assert_eq!(plain.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(
        !stderr.contains("session"),
        "an unconfigured repository is told nothing about sessions: {stderr}"
    );
    assert!(
        stderr.contains("state record refs/heads/main: 1 minted"),
        "the existing report is unchanged: {stderr}"
    );
    assert!(
        !bound_store_dir(&repo, &home).join("sessions").exists(),
        "nothing declared, nothing written"
    );

    // An empty value is how a CI file clears one, and reads the same way.
    let cleared = session_cmd(&repo, &home, "", None, &["state", "record", "-v"]);
    assert_eq!(cleared.status.code(), Some(0));
    assert!(
        !bound_store_dir(&repo, &home).join("sessions").exists(),
        "an empty session is no session, never a session named the empty string"
    );
}

#[test]
fn a_declared_parent_never_relinks_a_lineage_that_is_already_recorded() {
    // Ancestry is a fact about a fork that happened. A second, different parent
    // would move every already-resolved sequence identity and the cursor with
    // them, under readers holding the old root — so the recorded edge stands and
    // the disagreement is reported rather than resolved silently.
    let (repo, home) = ledger_fixture("fork-relink");
    for (session, parent) in [("alpha", None), ("beta", Some("alpha"))] {
        assert_eq!(
            session_cmd(&repo, &home, session, parent, &["state", "record"])
                .status
                .code(),
            Some(0)
        );
    }
    let store_dir = bound_store_dir(&repo, &home);
    assert_eq!(session_record(&store_dir, "beta")["parent"], "alpha");

    let conflicting = session_cmd(
        &repo,
        &home,
        "beta",
        Some("gamma"),
        &["state", "record", "-v"],
    );
    assert_eq!(
        conflicting.status.code(),
        Some(0),
        "a contradicted declaration is reported, never an error and never a deny"
    );
    assert!(
        String::from_utf8_lossy(&conflicting.stderr).contains("differs from the recorded one"),
        "the disagreement is visible: {}",
        String::from_utf8_lossy(&conflicting.stderr)
    );
    assert_eq!(
        session_record(&store_dir, "beta")["parent"],
        "alpha",
        "the recorded ancestry is what stands"
    );
}

// --- the transcript capability (CLOUD-95) -----------------------------------
//
// A completed session transcript is an optional `check` input. Three states,
// and the distinction between the first two is the whole design: a repository
// that never configured one is not missing anything, while one that pointed at
// a file that is not there has rules that did not run — and that must be said
// out loud, or a skipped gate exits 0 and reads as clean.
//
// The fixture carries deliberate sentinels in every free-text position the host
// records — thinking, a hook's stderr, a tool result's body. Nothing may render
// them, which is what `no_transcript_text_reaches_any_output_stream` proves.

/// The captured sample, materialized from its inert `.in` copy.
///
/// `.in` for the house reason: a fixture must be able to hold shapes this
/// repository's own gates would refuse, and a tracked `.jsonl` full of sentinel
/// strings is exactly that.
fn repo_with_transcript(name: &str, transcript: Option<&str>) -> PathBuf {
    let dir = repo_with_config(
        name,
        "version = 1\n\n[transcript]\npath = \"session.jsonl\"\n",
    );
    if let Some(body) = transcript {
        fs::write(dir.join("session.jsonl"), body).expect("write transcript");
    }
    dir
}

fn captured_sample() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transcripts/session.jsonl.in");
    fs::read_to_string(path).expect("read the captured fixture")
}

#[test]
fn a_configured_transcript_parses_to_pointer_only_counts() {
    let dir = repo_with_transcript("transcript-present", Some(&captured_sample()));
    let output = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one pure JSON document");
    let transcript = &document["transcript"];
    assert_eq!(transcript["capability"], "present");
    // Two user turns and two assistant turns; the `attachment` and
    // `queue-operation` lines are neither, which is the point of counting the
    // role rather than the line.
    assert_eq!(transcript["counts"]["turns"], 4);
    assert_eq!(transcript["counts"]["tool_calls"], 2);
    assert_eq!(transcript["counts"]["tool_errors"], 1);
    assert_eq!(transcript["counts"]["hook_decisions"], 2);
    // Read from the host's recorded `exitCode`, not from its stderr prose: one
    // hook returned the §7 verdict code and the other returned 0.
    assert_eq!(transcript["counts"]["hook_denials"], 1);
}

#[test]
fn the_transcript_report_is_byte_identical_across_two_runs() {
    let dir = repo_with_transcript("transcript-stable", Some(&captured_sample()));
    let once = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run once");
    let twice = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run twice");
    assert_eq!(
        once.stdout, twice.stdout,
        "a transcript read must be a pure function of its bytes"
    );
}

#[test]
fn an_absent_transcript_is_reported_and_exits_zero() {
    // Configured, nothing there. The run continues — a missing optional input is
    // not a violation — but it must not continue in silence.
    let dir = repo_with_transcript("transcript-absent", None);
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(batten::transcript::ABSENT_NOTICE),
        "the skip must be stated, got: {stderr}"
    );
}

#[test]
fn the_absent_report_survives_silent_because_it_rides_the_data_channel() {
    // THE PROPERTY THAT MAKES THE SKIP HONEST. `output::message` is ladder-gated,
    // so `--silent` erases the stderr half; if that were the only channel, a
    // skipped gate would exit 0 with nothing said — the false green this engine
    // exists to catch. `-J` has no `Mode` to consult, so it cannot be silenced.
    let dir = repo_with_transcript("transcript-silent", None);
    let output = batten()
        .args(["--silent", "check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "--silent empties the human channel"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one pure JSON document");
    assert_eq!(document["transcript"]["capability"], "absent");
}

#[test]
fn an_unconfigured_transcript_reports_nothing_at_all() {
    // Absent is not empty (`lint.rs`'s principle): a repository that never named
    // a transcript is not missing one, and reporting on it would fire on every
    // minimal config — which is how a report teaches people to ignore it.
    let dir = repo_with_config("transcript-unconfigured", "version = 1\n");
    let output = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).is_empty());
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one pure JSON document");
    assert!(
        document
            .get("transcript")
            .is_none_or(serde_json::Value::is_null),
        "an unconfigured capability emits no key"
    );
}

#[test]
fn an_undecodable_transcript_is_a_usage_error_never_a_verdict() {
    // Exit 1, not 2. The operator pointed at something Batten cannot read, so the
    // rules keyed on it did not run — loud, and structurally not a deny: §7
    // spends 2 on the policy verdict alone, and a parse failure reaching a
    // mediating harness as a deny would be the inversion this contract forbids.
    let dir = repo_with_transcript(
        "transcript-undecodable",
        Some("{\"type\":\"user\"}\nnot json\n"),
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("session.jsonl:2"),
        "a pointer, got: {stderr}"
    );
    assert!(
        !stderr.contains("not json"),
        "never the line itself: {stderr}"
    );
}

#[test]
fn no_transcript_text_reaches_any_output_stream() {
    // The reason this module exists in the shape it does. A transcript holds
    // every command, every file body and every prompt of a session, so it is the
    // richest source of secrets the engine can be pointed at. The fixture plants
    // a sentinel in each free-text position the host records; none may appear.
    let dir = repo_with_transcript("transcript-opaque", Some(&captured_sample()));
    for args in [vec!["check"], vec!["check", "-J"]] {
        let output = batten()
            .args(&args)
            .current_dir(&dir)
            .output()
            .expect("run batten check");
        let both = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for sentinel in [
            "PRIVATE-THINKING-SENTINEL",
            "DENY-REASON-SENTINEL",
            "TOOL-ERROR-BODY-SENTINEL",
            "IGNORED-SENTINEL",
            "gh pr merge 42",
            "dangerouslyDisableSandbox",
        ] {
            assert!(
                !both.contains(sentinel),
                "{args:?} leaked {sentinel}: {both}"
            );
        }
    }
}

// --- unprompted self-persistence (CLOUD-267) --------------------------------
//
// A memory write in a turn no user message opened. The intent question ("was
// this authorized?") is not computable and is permanently out of scope; the
// structure is, and that is what these assert.
//
// The fixture carries a sentinel in every position that would be a disclosure —
// the memory key, the written body, the target path, the injected message — so
// the leak test below is total rather than illustrative.

fn unprompted_pack() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transcripts/unprompted-memory-write.jsonl.in");
    fs::read_to_string(path).expect("read the unprompted fixture")
}

/// The `-J` view of the scan, or `None` when the run reported no writes.
fn self_write_view(dir: &std::path::Path) -> Option<serde_json::Value> {
    let output = batten()
        .args(["check", "-J"])
        .current_dir(dir)
        .output()
        .expect("run batten check");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("-J is a JSON document");
    document
        .get("transcript")?
        .get("unprompted_memory_writes")
        .cloned()
}

#[test]
fn a_memory_write_in_a_turn_no_user_message_opened_is_raised() {
    let dir = repo_with_transcript("selfwrite-raises", Some(&unprompted_pack()));
    let view = self_write_view(&dir).expect("the scan reports");
    // Three raised: the unprompted `edit_memory`, the generic `Write` under the
    // memory root, and the one following a host-marked injected message.
    assert_eq!(view["raised"], 3, "{view}");
    // One unresolved: the turn whose authorship cannot be reconstructed.
    assert_eq!(view["unresolved"], 1, "{view}");
}

#[test]
fn a_turn_a_person_opened_does_not_raise_however_many_calls_follow() {
    // The fixture's FIRST write is a `write_memory` inside a turn a real user
    // message opened. If authorization were read per-call rather than per
    // exchange, this would be a fourth raise.
    let dir = repo_with_transcript("selfwrite-authorized", Some(&unprompted_pack()));
    let view = self_write_view(&dir).expect("the scan reports");
    let lines: Vec<u64> = view["lines"]
        .as_array()
        .expect("lines is an array")
        .iter()
        .map(|line| line.as_u64().expect("a line number"))
        .collect();
    assert!(
        !lines.contains(&2),
        "the authorized write on line 2 must not be reported: {lines:?}"
    );
}

#[test]
fn a_non_memory_write_in_an_unprompted_turn_does_not_raise() {
    // Line 6 writes `/w/src/main.rs` with no user message in sight. It is a
    // write, it is unprompted, and it is none of this rule's business.
    let dir = repo_with_transcript("selfwrite-non-memory", Some(&unprompted_pack()));
    let view = self_write_view(&dir).expect("the scan reports");
    let lines: Vec<u64> = view["lines"]
        .as_array()
        .expect("lines is an array")
        .iter()
        .map(|line| line.as_u64().expect("a line number"))
        .collect();
    assert!(!lines.contains(&6), "an ordinary source write: {lines:?}");
}

#[test]
fn an_unreconstructable_turn_registers_unresolved_rather_than_nothing() {
    // House style §10: the third value is a real answer. Silence here would be
    // the false green, and raising would manufacture a finding.
    let dir = repo_with_transcript("selfwrite-unresolved", Some(&unprompted_pack()));
    let view = self_write_view(&dir).expect("the scan reports");
    assert_eq!(view["unresolved"], 1, "{view}");
}

#[test]
fn the_scan_never_blocks_the_run() {
    // Advisory means structurally unable to block (§0.3) — including under
    // `--fail-on-warning`, which is a promotion path for findings and must have
    // nothing to promote here.
    let dir = repo_with_transcript("selfwrite-advisory", Some(&unprompted_pack()));
    for args in [
        vec!["check"],
        vec!["check", "-J"],
        vec!["--fail-on-warning", "check"],
    ] {
        let output = batten()
            .args(&args)
            .current_dir(&dir)
            .output()
            .expect("run batten check");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?} must not block on an advisory"
        );
    }
}

#[test]
fn the_scan_is_byte_identical_across_two_runs() {
    let dir = repo_with_transcript("selfwrite-stable", Some(&unprompted_pack()));
    let once = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run once");
    let twice = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run twice");
    assert_eq!(once.stdout, twice.stdout, "the scan is a pure function");
}

#[test]
fn no_memory_key_path_or_content_reaches_any_output_stream() {
    // The disclosure test. What the agent persisted is payload, not a pointer:
    // reporting the key or the target would leak exactly what the rule is
    // watching being written.
    let dir = repo_with_transcript("selfwrite-no-leak", Some(&unprompted_pack()));
    for args in [
        vec!["check"],
        vec!["check", "-J"],
        vec!["--verbose", "check"],
    ] {
        let output = batten()
            .args(&args)
            .current_dir(&dir)
            .output()
            .expect("run batten check");
        let both = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for sentinel in [
            "AUTHORIZED-KEY-SENTINEL",
            "AUTHORIZED-BODY-SENTINEL",
            "UNPROMPTED-KEY-SENTINEL",
            "UNPROMPTED-BODY-SENTINEL",
            "PATH-SENTINEL",
            "PATH-BODY-SENTINEL",
            "INJECTED-SENTINEL",
            "INJECTED-WRITE-SENTINEL",
            "UNRESOLVED-SENTINEL",
            ".serena/memories",
        ] {
            assert!(
                !both.contains(sentinel),
                "{args:?} leaked {sentinel}: {both}"
            );
        }
    }
}

// --- `lint brief`: the delegation-brief handoff schema (CLOUD-84) -------------

/// A committed brief fixture, by name.
///
/// Committed rather than composed inline, for the reason `tests/fixtures/hooks/`
/// records: a fixture written from memory pins what its author believed the shape
/// was, and this schema's whole subject is a shape people get wrong.
fn brief_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/briefs")
        .join(name)
}

/// `batten lint brief <fixture>`, run from a directory with no `batten.toml`.
///
/// Run outside any config on purpose: the schema is engine structure, not repo
/// policy, so the verdict must not depend on a config being present — and a
/// caller linting a brief has no reason to be standing in a configured repo.
fn run_lint_brief(name: &str, extra: &[&str]) -> Output {
    let dir = scratch(&format!("lint-brief-{name}"));
    let mut command = batten();
    command.arg("lint").arg("brief");
    command.args(extra);
    command
        .arg(brief_fixture(name))
        .current_dir(&dir)
        .output()
        .expect("run batten lint brief")
}

#[test]
fn a_complete_brief_exits_zero_and_says_nothing() {
    // CLOUD-84 §7(a). Silence is the contract, not an omission: `lint brief` is
    // meant to sit inline on a dispatch path, where a line per successful handoff
    // is noise a reader learns to skip.
    let output = run_lint_brief("complete.md", &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout(&output));
}

#[test]
fn a_brief_missing_the_check_section_is_a_policy_verdict_naming_it() {
    // CLOUD-84 §7(b), with the exit number CLOUD-307 corrected: a missing section
    // is a VIOLATION (2), not a usage error. Shipping 1 here would make every
    // mediating harness read the verdict as "Batten is misconfigured".
    let output = run_lint_brief("missing-check.md", &[]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing section is the policy verdict, not a usage error"
    );
    assert_eq!(stdout(&output), "missing: check (1)\n");
}

#[test]
fn a_check_section_with_no_runnable_command_is_reported_separately() {
    // CLOUD-84 §7(d): the structural assertion that retires a separate reply
    // scanner. Its own class, not `missing`, because the repair is different —
    // put a command in the section that already exists.
    let output = run_lint_brief("unrunnable-check.md", &[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "unrunnable: check (1)\n");
}

#[test]
fn the_brief_report_is_byte_stable_across_runs() {
    // CLOUD-84 §7(c). The report is a pure function of the bytes: no clock, no
    // filesystem, no config, and an order that comes from the schema rather than
    // from how the author arranged the document.
    for name in ["complete.md", "missing-check.md", "unrunnable-check.md"] {
        let first = run_lint_brief(name, &[]);
        let second = run_lint_brief(name, &[]);
        assert_eq!(first.stdout, second.stdout, "{name} stdout drifted");
        assert_eq!(first.status.code(), second.status.code());
    }
}

#[test]
fn an_unreadable_brief_is_a_usage_error_and_never_a_deny() {
    // The other half of CLOUD-307's correction. `1`, not `2`: "I could not read
    // the input" must never travel to a harness as a policy decision, or a
    // mistyped path becomes a block.
    let dir = scratch("lint-brief-unreadable");
    let output = batten()
        .args(["lint", "brief", "no-such-brief.md"])
        .current_dir(&dir)
        .output()
        .expect("run batten lint brief");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn a_brief_arrives_on_stdin_when_no_path_is_given() {
    // A brief is composed in memory by whatever is dispatching; requiring a
    // temporary file would put a write on the path of a `read` verb's caller.
    let dir = scratch("lint-brief-stdin");
    let brief = fs::read_to_string(brief_fixture("complete.md")).expect("read fixture");
    let mut child = batten()
        .args(["lint", "brief"])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn batten lint brief");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(brief.as_bytes())
        .expect("write the brief");
    let output = child.wait_with_output().expect("wait for batten");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn the_json_channel_answers_even_on_a_clean_brief() {
    // JSON that is sometimes absent is unparseable — the same reasoning
    // `config lint -J` records. The human channel stays silent; this one does not.
    let output = run_lint_brief("complete.md", &["-J"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report is JSON");
    assert_eq!(report["missing"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["unrunnable"].as_array().map(Vec::len), Some(0));

    let dirty = run_lint_brief("missing-check.md", &["-J"]);
    assert_eq!(dirty.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&dirty.stdout).expect("report is JSON");
    assert_eq!(report["missing"][0], "check");
}

#[test]
fn no_byte_of_the_brief_reaches_any_output_stream() {
    // Non-negotiable rule 4, and the reason it is load-bearing here rather than
    // formal: a delegation brief is the likeliest document in this system to
    // carry a consumer's name, an entity path, or a credential pasted "for
    // context". The report is section ids and counts.
    let dir = scratch("lint-brief-no-leak");
    let sentinel = "ACCOUNT-SENTINEL-01189998819991197253";
    let path = dir.join("brief.md");
    fs::write(
        &path,
        format!("## Identifiers\n\n{sentinel}\n\n## Check\n\nno command here\n"),
    )
    .expect("write brief");
    for extra in [vec![], vec!["-J"]] {
        let output = batten()
            .arg("lint")
            .arg("brief")
            .args(&extra)
            .arg(&path)
            .current_dir(&dir)
            .output()
            .expect("run batten lint brief");
        let both = format!("{}{}", stdout(&output), stderr(&output));
        assert!(
            !both.contains(sentinel),
            "{extra:?} leaked the brief: {both}"
        );
    }
}

#[test]
fn lint_brief_declares_itself_read_in_the_spec() {
    // The derived read-only allowlist is built from this classification, so a
    // misdeclared row would put a text-reading verb in the wrong effect class —
    // or keep an honest one out of the allowlist a mediating harness consults.
    let output = batten().arg("spec").output().expect("run batten spec");
    assert_eq!(output.status.code(), Some(0));
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let lint = spec["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "lint")
        .expect("lint is in the spec");
    assert_eq!(lint["effect"], "read");
    let brief = lint["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "lint brief")
        .expect("lint brief is in the spec");
    assert_eq!(brief["effect"], "read");
}

// --- `[[hook.action]]`: declared side effects on hook events (CLOUD-91) -------
//
// House style §9's extension surface. The load-bearing property is that an
// action cannot reach the decision — `action::fire` returns nothing — so every
// case below asserts the hook's own answer is untouched alongside whatever the
// action did.

/// A repo whose config declares one action, firing `run` on `on`.
fn action_repo(name: &str, on: &str, run: &str) -> PathBuf {
    repo_with_config(
        name,
        &format!("version = 1\n\n[[hook.action]]\nid = \"probe\"\non = \"{on}\"\nrun = {run}\n"),
    )
}

/// A Claude Code payload for an arbitrary event, carrying no tool input.
fn claude_event_payload(event: &str) -> String {
    serde_json::json!({ "hook_event_name": event, "session_id": "s-1" }).to_string()
}

#[test]
fn a_declared_action_fires_on_its_event_with_the_substituted_argv() {
    // Acceptance (a). Observed through the command's own side effect in a temp
    // dir, because `fire` returns nothing there is no return value to inspect —
    // which is the design, not a limitation of the test.
    let dir = action_repo(
        "action-fires",
        "task-completed",
        r#"["sh", "-c", "printf %s \"$1\" > fired.txt", "sh", "{event}"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &claude_event_payload("Stop"), false);

    // Claude's `Stop` normalizes to the stop event, so the task-completed row
    // must NOT fire: an action runs at the moment it named, never a stand-in.
    assert!(!dir.join("fired.txt").exists(), "no action fires on stop");
    assert_eq!(output.status.code(), Some(0));

    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted", "session_id": "s-1" }).to_string(),
        false,
    );
    assert_eq!(output.status.code(), Some(0), "the answer is unchanged");
    assert_eq!(
        std::fs::read_to_string(dir.join("fired.txt")).expect("the action ran"),
        "task-completed",
        "the child saw the expanded placeholder"
    );
}

#[test]
fn a_host_without_the_capability_fires_nothing_and_still_answers() {
    // Acceptance (b). `task-completed` is Claude-only, so the neutral exit-code
    // adapter must spawn nothing — and must still answer its contract, because
    // an absent capability is a fact about the host, never an error.
    let dir = action_repo(
        "action-uncapable",
        "task-completed",
        r#"["sh", "-c", "touch fired.txt"]"#,
    );
    let output = run_hook_in(
        &dir,
        "exit-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        false,
    );
    assert_eq!(output.status.code(), Some(0), "allow, never an error");
    assert!(
        !dir.join("fired.txt").exists(),
        "a host that does not emit the event fires nothing"
    );
}

#[test]
fn a_failing_action_leaves_the_hooks_answer_alone_and_reports_a_pointer() {
    // Acceptance (c). The whole safety argument: an action is user-supplied
    // code, and no exit code it produces may become Batten's.
    let dir = action_repo("action-fails", "task-completed", r#"["false"]"#);
    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        false,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the hook contract is untouched by the action's failure"
    );
    let text = common::stderr(&output);
    assert!(
        text.contains("hook.action probe: exit 1"),
        "the failure is a pointer naming the row: {text:?}"
    );
}

#[test]
fn an_actions_output_never_reaches_either_channel() {
    // Rule 4, at the surface most likely to breach it: the command's streams are
    // discarded rather than forwarded — to stdout because two hosts parse a
    // decision document there, and to stderr because two others read a deny
    // reason from it.
    let dir = action_repo(
        "action-quiet",
        "task-completed",
        r#"["sh", "-c", "echo SECRET-ON-STDOUT; echo SECRET-ON-STDERR >&2"]"#,
    );
    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    let both = format!("{}{}", common::stdout(&output), common::stderr(&output));
    assert!(
        !both.contains("SECRET-ON"),
        "an action's own output is never forwarded: {both:?}"
    );
}

#[test]
fn an_action_on_the_adjudicated_event_is_a_config_error() {
    // Acceptance (d)'s shape, and the surface's one real restriction: a side
    // effect at pre-tool would run before a deny that may be about to refuse
    // the very call. Exit 1, the config-error code — never 2, which would read
    // to a host as a policy verdict about the mediated call.
    let dir = action_repo("action-pre-tool", "pre-tool", r#"["true"]"#);
    let output = run_hook_in(&dir, "claude-code", &claude_payload("echo hi"), false);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        common::stderr(&output).contains("before a possible deny"),
        "the refusal says why: {:?}",
        common::stderr(&output)
    );
}

#[test]
fn an_unknown_key_in_an_action_row_stays_a_hard_config_error() {
    // Acceptance (d). `deny_unknown_fields` on the row, so a mistyped key is
    // refused rather than silently dropped — an action nobody notices is
    // half-declared is a side effect that never fires.
    let dir = repo_with_config(
        "action-unknown-key",
        "version = 1\n\n[[hook.action]]\nid = \"probe\"\non = \"stop\"\nrun = [\"true\"]\nwhen = \"always\"\n",
    );
    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "Stop" }).to_string(),
        false,
    );
    assert_eq!(output.status.code(), Some(1), "a usage error, never a deny");
}

#[test]
fn a_bypassed_call_fires_no_action() {
    // The bypass says "do not mediate this call"; spawning the operator's
    // command while claiming not to mediate would be the surprising reading.
    let dir = action_repo(
        "action-bypassed",
        "task-completed",
        r#"["sh", "-c", "touch fired.txt"]"#,
    );
    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        true,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !dir.join("fired.txt").exists(),
        "a bypassed run fires nothing"
    );
}

#[test]
fn a_repository_declaring_no_actions_spawns_nothing_and_is_unaffected() {
    // Absent is not empty, and it is certainly not an error: the overwhelming
    // majority of directories a registered hook runs in declare no actions.
    let dir = repo_with_config("action-absent", "version = 1\n");
    let output = run_hook_in(
        &dir,
        "claude-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(common::stderr(&output), "");
}

// --- the end-of-turn gate (CLOUD-85) ------------------------------------------
//
// `deny-stop ⇔ at-risk work ∨ an undischarged denial`. Both inputs are consumed
// rather than re-derived, so these cases exercise the composition and the
// channel; what each input means is pinned by its own module's tests.

/// A repository whose tree is clean and whose store is empty.
fn stop_repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\nmust_land_on = \"main\"\n")
        .file("README.md", "base\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// A Claude Code `Stop` payload — the end-of-turn event.
fn stop_payload() -> String {
    serde_json::json!({ "hook_event_name": "Stop", "session_id": "s-1" }).to_string()
}

#[test]
fn a_clean_tree_and_an_empty_store_let_the_turn_end() {
    // Acceptance (b). Allow prints nothing: a turn that may end is the ordinary
    // case, and saying so on every one would spend context to report a non-event.
    let dir = stop_repo("stop-clean");
    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(common::stdout(&output), "");
    assert_eq!(common::stderr(&output), "");
}

#[test]
fn at_risk_work_blocks_the_turn_and_names_the_fact() {
    // Acceptance (a), the at-risk half. The uncommitted file is work that would
    // not survive the container, which is precisely what end-of-turn is for.
    let dir = stop_repo("stop-at-risk");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    // Claude reads an in-band decision document on exit 0; the deny is the
    // document, not the code (CLOUD-40).
    assert_eq!(output.status.code(), Some(0));
    let document = common::stdout(&output);
    assert!(
        document.contains("\"deny\""),
        "the turn is refused through the host's own channel: {document:?}"
    );
    assert!(
        document.contains("uncommitted: 1 paths"),
        "the refusal names the blocking fact as a pointer: {document:?}"
    );
    assert!(
        !document.contains("work in progress"),
        "a pointer, never the content (rule 4): {document:?}"
    );
}

#[test]
fn the_stop_refusal_names_something_to_run() {
    // §5, and `Refusal`'s own contract: a block that says only "no" cannot be
    // acted on in one hop. The at-risk half has no per-finding command, so this
    // is the case where the fallback remedy has to carry it.
    let dir = stop_repo("stop-remedy");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    let document = common::stdout(&output);
    assert!(
        document.contains("Fix:"),
        "every refusal carries a remedy clause: {document:?}"
    );
}

#[test]
fn the_same_state_on_a_pre_tool_event_does_not_deny() {
    // Acceptance (c). The gate fires on the stop event only — it is distinct
    // from a pre-tool deny by EVENT, and an unfinished turn must not start
    // refusing the tool calls that would finish it.
    let dir = stop_repo("stop-pre-tool");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "claude-code", &claude_payload("echo hi"), false);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !common::stdout(&output).contains("\"deny\""),
        "at-risk work does not refuse an ordinary tool call"
    );
}

#[test]
fn a_host_that_does_not_emit_stop_ends_its_turn_unmediated() {
    // Acceptance (d). Every surveyed host emits Stop, so the degradation is
    // exercised through an event the neutral adapter genuinely lacks — the
    // capability path answers before the gate is reached, and the answer is
    // allow rather than an error.
    let dir = stop_repo("stop-uncapable");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(
        &dir,
        "exit-code",
        &serde_json::json!({ "hook_event_name": "TaskCompleted" }).to_string(),
        false,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "an absent capability is a fact about the host, never a refusal"
    );
}

#[test]
fn outside_a_repository_the_turn_ends_unmediated() {
    // `batten hook` is registered once and mediates every turn in whatever
    // directory the agent is in. Answering "at risk" for a directory Batten does
    // not govern would make the guard the reason a turn cannot end.
    // Genuinely outside the tree: `scratch` lives under `target/`, which is
    // inside this repository, so a gate that reads the checkout would answer
    // about Batten's own working tree rather than about nothing.
    let dir = common::scratch_outside_tree("batten-stop", "outside");
    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(common::stdout(&output), "");
}

#[test]
fn a_stop_deny_is_the_same_exit_code_as_a_pre_tool_deny() {
    // §7 has no per-verb exception, so the two denies are one code on a host
    // whose only channel is the exit status. What distinguishes them is the
    // event, which is the whole design.
    let dir = stop_repo("stop-exit-code");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "exit-code", &stop_payload(), false);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the policy verdict, on the channel a neutral host reads"
    );
    assert!(
        common::stderr(&output).contains("uncommitted: 1 paths"),
        "the reason travels on stderr: {:?}",
        common::stderr(&output)
    );
}

// --- `generate hooks`: the wiring is derived, not hand-kept (CLOUD-62) -------

/// The registrations the binary emits for `harness`.
fn generated_wiring(harness: &str) -> Output {
    batten()
        .args(["generate", "hooks", "--harness", harness])
        .output()
        .expect("run batten generate hooks")
}

/// The checked-in golden for `harness`.
fn wiring_golden(harness: &str) -> String {
    let path = common::at_root(&format!(
        "crates/batten/tests/fixtures/hooks/wiring/{harness}.json"
    ));
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// Every harness that declares a wiring row — derived from the binary's own
/// harness list rather than re-typed, so a new host cannot land uncovered here.
const INSTALLABLE_HARNESSES: &[&str] = &[
    "claude-code",
    "cursor",
    "copilot-cli",
    "gemini-cli",
    "codex-cli",
];

#[test]
fn generated_hook_wiring_matches_its_golden_for_every_installable_harness() {
    // DoR §4's shape: an artifact derived from the spec is regenerated by its
    // generator and diffed against the committed copy. The goldens are what make
    // a wiring-row edit reviewable — the rows are terse Rust data and their
    // consequence is a document a host acts on.
    for harness in INSTALLABLE_HARNESSES {
        let output = generated_wiring(harness);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{harness} is installable, so it emits: {:?}",
            common::stderr(&output)
        );
        assert_eq!(
            common::stdout(&output),
            wiring_golden(harness),
            "{harness}'s emitted wiring drifted from its golden — re-run the emitter, \
             never edit the golden by hand"
        );
    }
}

#[test]
fn generated_hook_wiring_is_byte_stable_across_runs() {
    // §6's determinism law over this artifact. Key order here is the code's, not
    // a map's, precisely so two runs cannot disagree; this is what asserts it.
    for harness in INSTALLABLE_HARNESSES {
        assert_eq!(
            common::stdout(&generated_wiring(harness)),
            common::stdout(&generated_wiring(harness)),
            "{harness} emitted two different documents for one question"
        );
    }
}

#[test]
fn every_generated_wiring_is_parseable_json_naming_the_harness_it_is_for() {
    // A golden that is byte-stable and unparseable would pass every other check
    // in this file. And each must name its OWN harness: a copy-pasted row that
    // registers the wrong `--harness` is exactly the drift the goldens exist to
    // make visible, and it survives a byte comparison against a golden generated
    // from the same mistake.
    for harness in INSTALLABLE_HARNESSES {
        let emitted = common::stdout(&generated_wiring(harness));
        let parsed: serde_json::Value =
            serde_json::from_str(&emitted).unwrap_or_else(|err| panic!("{harness}: {err}"));
        assert!(parsed.is_object(), "{harness} emitted a non-object");
        assert!(
            emitted.contains(&format!("batten hook --harness {harness}")),
            "{harness}'s registrations must invoke the engine for {harness}"
        );
    }
}

#[test]
fn generate_hooks_refuses_the_contract_only_harness() {
    // `exit-code` is the neutral contract — envelope in, decision as exit status
    // out — not a host. Emitting `{}` would answer "this host registers
    // nothing", a different claim from "there is nothing to register with", so
    // it refuses. Exit 1: the caller named something that cannot be asked for,
    // which is a statement about the invocation, and `generate` renders no
    // policy verdict so 2 is structurally unreachable here.
    let output = generated_wiring("exit-code");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        common::stdout(&output),
        "",
        "a refusal writes nothing to the artifact channel"
    );
    let stderr = common::stderr(&output);
    assert!(
        stderr.contains("exit-code") && stderr.contains("not a host"),
        "the refusal names the harness and why: {stderr:?}"
    );
}

// --- per-host attribution adapters (CLOUD-276) -------------------------------
//
// The invariant these pin is an asymmetry, and it is the issue's whole point:
// **capture fidelity varies by host; enforcement never does.** Enforcement seams
// are git-native — a commit hook and CI over the produced object — and a commit
// carries no record of which host made it, so a `--harness` that changed a
// verdict would be a bug rather than a feature.
//
// `--message` rather than `--range` on purpose: the finding then comes from the
// message file this fixture writes, so it is deterministic. A range case would
// judge the identity the sandbox's git happens to resolve, which is asserting a
// premise the fixture never created (`.claude/rules/rust.md`, CLOUD-249).

/// The six harness tokens, as the binary accepts them.
///
/// Spelled here rather than read off `Harness::ALL` at runtime **and** checked
/// against it below, so a new host cannot join the enum without joining this
/// matrix — the failure a hand-kept list otherwise hides.
const ATTRIBUTION_HOSTS: &[&str] = &[
    "claude-code",
    "cursor",
    "copilot-cli",
    "gemini-cli",
    "codex-cli",
    "exit-code",
];

/// A repo whose attribution policy refuses one thing the fixture message says.
///
/// The **repo-local git identity is written**, and that is load-bearing rather
/// than tidy (CLOUD-513). Message mode reads the identity git is about to stamp
/// through `git var GIT_AUTHOR_IDENT`, and `common::git_command` supplies the
/// fixture's identity transiently with `-c` — so it never reaches the repo
/// config, and the `batten` child process resolves whatever the ambient global
/// config carries. A developer's container has one and a CI runner does not, so
/// without this the gate answers exit 1 ("could not look") there and exit 2 here:
/// green locally, red in CI, which is the exact shape this repository has already
/// been bitten by.
fn attribution_fixture(name: &str) -> PathBuf {
    let dir = Fixture::at(scratch(name))
        .config(concat!(
            "version = 1\n",
            "[attribution]\n",
            "identity_deny = [\"^Nobody <\"]\n",
            "trailer_deny = [\"^Nobody-Session:\"]\n",
            // The one the fixture message trips, deterministically.
            "body_deny = [\"^Generated with\"]\n",
            "[attribution.identity]\n",
            "name = \"Accountable Human\"\n",
            "email = \"human@example.test\"\n",
        ))
        .file("pending-message", "Generated with SomeTool\n")
        .git()
        .base_commit()
        .build();
    // Written into the repo, where the binary's own `git var` will find it.
    git_in(&dir, &["config", "user.name", "Accountable Human"]);
    git_in(&dir, &["config", "user.email", "human@example.test"]);
    dir
}

/// `attribution check -J` over the fixture message, optionally naming a host.
///
/// The ambient global and system git config are fenced off, so the fixture's own
/// identity is the only one in play. Belt to the repo-local identity's suspenders,
/// and the half that makes the case assert its own premise: without it a
/// developer's ambient identity could satisfy the run for a reason CI does not
/// share — which is how a suite comes to pass `verify` and fail CI.
fn attribution_document(dir: &Path, harness: Option<&str>) -> Output {
    let mut args = vec!["attribution", "check", "--message", "pending-message", "-J"];
    if let Some(harness) = harness {
        args.extend(["--harness", harness]);
    }
    batten_with(
        dir,
        &args,
        &[
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ],
    )
}

#[test]
fn every_harness_the_enum_declares_is_in_the_attribution_matrix() {
    // The guard on the list above. `Harness::ALL` is the authority; this asserts
    // the matrix ranges over all of it, so a seventh host fails here rather than
    // silently going uncovered by every case below.
    let declared: Vec<&str> = batten::hook::Harness::ALL
        .iter()
        .map(|harness| harness.as_str())
        .collect();
    assert_eq!(declared, ATTRIBUTION_HOSTS);
}

#[test]
fn enforcement_is_identical_across_every_host() {
    // §7(a) and the enforcement half of §7(c). One fixture, six hosts, plus the
    // run that names no host at all: the findings and the exit code are the same
    // every time. A `--harness` that could move a verdict would make the gate's
    // answer depend on which agent happened to be running, which is the opposite
    // of what a git-native seam means.
    let dir = attribution_fixture("attribution-host-enforcement");

    let unnamed = attribution_document(&dir, None);
    assert_eq!(
        unnamed.status.code(),
        Some(2),
        "the fixture message trips `body_deny`, so this is the policy verdict"
    );
    let baseline: serde_json::Value = serde_json::from_slice(&unnamed.stdout).expect("-J is JSON");
    assert_eq!(
        baseline["findings"],
        serde_json::json!([{ "label": "pending", "field": "body" }]),
    );

    for harness in ATTRIBUTION_HOSTS {
        let output = attribution_document(&dir, Some(harness));
        assert_eq!(
            output.status.code(),
            Some(2),
            "{harness}: naming a host must not move the verdict"
        );
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("-J is JSON");
        assert_eq!(
            document["findings"], baseline["findings"],
            "{harness}: the findings are the gate's, and the gate is host-blind"
        );
    }
}

#[test]
fn the_document_reports_exactly_the_rows_the_named_host_declares() {
    // §7(b). The declarations are what varies, and they are observable rather
    // than merely typed: one host measured on this repository, four the survey
    // does not answer for, and the neutral contract that can honestly say `no`.
    let dir = attribution_fixture("attribution-host-rows");

    let claude = attribution_document(&dir, Some("claude-code"));
    let document: serde_json::Value = serde_json::from_slice(&claude.stdout).expect("-J is JSON");
    let rows = document["expects"].as_array().expect("expects is an array");
    assert_eq!(
        rows.len(),
        batten::hook::Capability::ATTRIBUTION.len(),
        "the document is derived from the table, so every attribution row appears"
    );
    let declared = |capability: &str| -> String {
        rows.iter()
            .find(|row| row["capability"] == capability)
            .unwrap_or_else(|| panic!("{capability} is missing from the document"))["declares"]
            .as_str()
            .expect("a declaration token")
            .to_owned()
    };
    assert_eq!(declared("injects-coauthorship-trailer"), "yes");
    assert_eq!(declared("exposes-session-id"), "yes");
    // Neither `yes` nor `no`: a setting exists and does not govern every path.
    assert_eq!(declared("attribution-config-surface"), "partial");
    // Measured as environment-injected, which cannot separate host from
    // container — so the host is not credited with it.
    assert_eq!(declared("sets-git-identity"), "unknown");

    // The distinction CLOUD-276's stated assumption turns on, visible in the
    // document a consumer reads and not only in the type: `no` is measured
    // absence, `unknown` is evidence that does not answer.
    let exit_code = attribution_document(&dir, Some("exit-code"));
    let neutral: serde_json::Value = serde_json::from_slice(&exit_code.stdout).expect("-J is JSON");
    let row = |document: &serde_json::Value, capability: &str| -> String {
        document["expects"]
            .as_array()
            .expect("expects is an array")
            .iter()
            .find(|row| row["capability"] == capability)
            .expect("the row")["declares"]
            .as_str()
            .expect("a declaration token")
            .to_owned()
    };
    assert_eq!(row(&neutral, "exposes-model-id"), "no");
    assert_eq!(declared("exposes-model-id"), "unknown");
}

#[test]
fn a_row_the_host_does_not_declare_captures_unknown() {
    // §7(c), over the binary. No surveyed host puts a model id on the payload
    // Batten reads, so the captured value is the token and not an empty string, a
    // missing key, or a guess. The enforcement half is asserted above.
    let dir = attribution_fixture("attribution-host-capture");
    for harness in ATTRIBUTION_HOSTS {
        let output = attribution_document(&dir, Some(harness));
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("-J is JSON");
        assert_eq!(
            document["caller"]["modelId"], "unknown",
            "{harness}: an undeclared row degrades to the token"
        );
        // The harness is known by construction — the caller named it.
        assert_eq!(document["caller"]["harness"], *harness);
        // Present on every record whatever the value, which is the shape
        // contract `decision::Caller` keeps (CLOUD-275).
        for field in ["modelId", "harness", "session"] {
            assert!(
                document["caller"][field].is_string(),
                "{harness}: {field} must be present, got {}",
                document["caller"]
            );
        }
    }
}

#[test]
fn naming_no_host_declares_nothing_rather_than_borrowing_a_default() {
    // The flag has no default, and this is why: an absent `--harness` is its own
    // answer. Three degraded provenance values and no declarations — never some
    // host's rows attributed to a caller who named none.
    let dir = attribution_fixture("attribution-no-host");
    let document: serde_json::Value =
        serde_json::from_slice(&attribution_document(&dir, None).stdout).expect("-J is JSON");
    assert_eq!(document["caller"]["harness"], "unknown");
    assert_eq!(document["caller"]["modelId"], "unknown");
    assert_eq!(document["caller"]["session"], "unknown");
    assert_eq!(
        document["expects"],
        serde_json::json!([]),
        "no host was named, so there are no declarations to report"
    );
}

#[test]
fn the_document_is_byte_identical_across_two_runs() {
    // §7(d), and §6 generally. The keys are struct order and the rows are
    // `Capability::ATTRIBUTION` order, so neither a map's hashing nor a set's
    // iteration can reorder them between runs.
    let dir = attribution_fixture("attribution-host-stable");
    for harness in ATTRIBUTION_HOSTS {
        let first = attribution_document(&dir, Some(harness));
        let second = attribution_document(&dir, Some(harness));
        assert_eq!(
            first.stdout, second.stdout,
            "{harness}: the document is not byte-stable"
        );
    }
}
