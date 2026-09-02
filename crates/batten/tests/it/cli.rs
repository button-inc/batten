//! End-to-end tests over the compiled `batten` binary.
//!
//! These assert the parts of the interface that consumers depend on — the
//! exit-code contract and that `--version`/`--help` resolve — so that filling in
//! the command tree cannot silently break them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use batten::decision::Outcome;
use batten::rules::{Decidability, RuleKind};
use batten::{ExitCode, ReportLevel, RuleSeverity, severity};
use common::{
    Fixture, StateHome, batten, declared_patterns, git_in, run, scratch, scratch_outside_tree,
    stderr, stdout, write,
};

/// Run `batten hook --harness <harness>` with `payload` piped to stdin, against
/// an authority that declares no rules.
///
/// The ambient bypass var is removed so a developer's shell can never flip a
/// deny case; the `bypass` flag sets it explicitly for the case that wants it.
///
/// **THE FIXTURE IS THE POINT, AND IT USED TO BE `crates/batten/` (CLOUD-1135).**
/// The comment here said that directory "has no `batten.toml` — that is the
/// no-authority case". It has none, and `hook` resolves its authority upward to
/// the git root anyway, so every case below adjudicated against THIS
/// repository's own committed policy. Measured 2026-08-29: driven from
/// `crates/batten/`, `gh pr checks 714` came back refused by `gh-pr-checks`, a
/// row that exists only in the repository-root `batten.toml`.
///
/// What that cost is the failure this file already names one helper down — "a
/// fixture that reads the repository it is running inside is not a fixture" —
/// in its live form rather than its historical one:
/// `hook_allows_reads_and_quoted_lookalikes_silently` began failing on `gh pr
/// view 42` the moment a checkout's own `SessionStart` wrote
/// `.git/batten-facts/pinned-programs`, because the live config's
/// `pinned-toolchain` preset then fires on `gh`. Local red, CI green — a runner
/// never writes that record — over a diff touching none of it.
///
/// `version = 1` and nothing else IS the no-authority case, stated rather than
/// inherited: an authority that loads and declares no rule. `name` is per
/// caller because [`Fixture::new`] wipes, and these cases run in parallel.
fn run_hook(name: &str, harness: &str, payload: &str, bypass: bool) -> Output {
    let dir = repo_with_config(name, "version = 1\n");
    run_hook_in(&dir, harness, payload, bypass)
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
    let mut command = common::batten_at_real_root();
    command
        .current_dir(dir)
        .args(["hook", "--harness", harness])
        .env_remove("BATTEN_HOOK_BYPASS")
        .env_remove("BATTEN_GH_GUARD_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if bypass {
        command.env("BATTEN_HOOK_BYPASS", "1");
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

/// `batten hook` with named environment variables set, for the per-row hatches
/// (CLOUD-437).
///
/// [`run_hook_in`]'s `bypass` flag sets the GENERAL hatch and nothing else, which
/// cannot express "this row's hatch is set and no other's" — the distinction the
/// whole column exists to make. Both names are scrubbed first for the same reason
/// every other harness here scrubs them: `BATTEN_GH_GUARD_BYPASS` is a live row
/// hatch now, so a leaked one would disarm the four `gh` rows and their
/// assertions would pass for the wrong reason.
fn run_hook_with_env(
    dir: &std::path::Path,
    harness: &str,
    payload: &str,
    env: &[(&str, &str)],
) -> Output {
    let mut command = common::batten_at_real_root();
    command
        .current_dir(dir)
        .args(["hook", "--harness", harness])
        .env_remove("BATTEN_HOOK_BYPASS")
        .env_remove("BATTEN_GH_GUARD_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
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
        .env_remove("BATTEN_HOOK_BYPASS")
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

/// A Claude Code `PreToolUse` payload wrapping one bare tool call.
///
/// Empty input, deliberately: a row keyed on the tool name alone reads no field
/// of it, so supplying one would assert over something the row never consults.
fn claude_verb_payload(tool: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {}
    })
    .to_string()
}

/// A Claude Code `PreToolUse` payload wrapping one subagent spawn.
///
/// The spawn's sibling of [`claude_payload`], for a row keyed on the tool a call
/// names rather than on a command line (CLOUD-924): a `Task` call carries no
/// command, so the census's command shape cannot reach it at all.
fn claude_spawn_payload(tool: &str, prompt: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": { "prompt": prompt }
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
/// Seed the surfaces the committed config declares.
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
    // The committed `perf-assert` row declares `README.md` as a LITERAL `lines`
    // entry (CLOUD-1321), so it is acquired whether or not this fixture has one
    // and an absent file reaches the module through `input.tree.missing`. That is
    // deliberate there — a glob would match nothing in a treeless fixture and the
    // could-not-look clause would be unreachable — and it means a fixture running
    // the committed config owes this surface exactly as it owes `AGENTS.md`.
    //
    // The table AGREES with the module's `budgets`, so a case about some other
    // rule is not also a case about the published budget.
    fs::write(
        dir.join("README.md"),
        "| path | what it does | p50 | p95 | budget |\n\
         | ---- | ------------ | --- | --- | ------ |\n\
         | `noop` | process start | 2.1 ms | 2.4 ms | \u{2264} 100 ms |\n\
         | `check` | one-rule tree | 2.3 ms | 2.7 ms | \u{2264} 100 ms |\n\
         | `hook` | adjudication | 2.8 ms | 3.0 ms | \u{2264} 100 ms |\n\
         | `passthrough` | a call no rule selects | \u{2014} | \u{2014} | \u{2264} 100 ms |\n\
         | `posttool` | a PostToolUse call | \u{2014} | \u{2014} | \u{2264} 100 ms |\n\
         | `wired` | as settings.json invokes it | 8.0 ms | 8.4 ms | \u{2264} 100 ms |\n",
    )
    .expect("write fixture README");
    committed_policy_modules(dir);
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
/// Coverage spans all four codes. `Success` (0) for well-formed runs and `Usage`
/// (1) for malformed input or bad config, including the two clap renders `--help`
/// (an answer, 0) and an unknown flag (1). `Violation` (2) is reached by `check`
/// when a rule fires; because that needs source files placed beside the config, it
/// is exercised in the dedicated `check_*` tests below rather than this
/// config-only table, and by `hook` in the `hook_*` tests — the same code, since
/// §7 has no per-verb exception. `Internal` (3) is reached here, by the
/// could-not-look row below.
///
/// **That last sentence used to say the opposite** (CLOUD-421): "`Internal` (3)
/// has no command that reaches it at this stage". It was the stated coverage of
/// this table, and it was false — `run` returns `Internal` for any error that is
/// neither a passthrough, a denial nor a usage error, and several commands
/// produce one.
///
/// **The row is a could-not-look rather than an unreadable file, deliberately.**
/// CLOUD-110 measured `Internal` through `rules::forbid_in_file` surfacing an
/// `EACCES` from a file inside a rule's glob, and that is the shape this issue
/// set out to pin here. It cannot be pinned *here*: the precondition is a file
/// the running user cannot read, this suite runs as root, and a test resting on a
/// permission drop that never bit is exactly what
/// `primitives.rs::every_permission_drop_asserts_its_own_premise` refuses. That
/// arm stays where its precondition can be created and is proven — the
/// `action-internal` job in `.github/workflows/test.yml`, which fails loudly on a
/// runner that defeats the `chmod`. What belongs in this table is a route to `3`
/// that needs no precondition at all, and `config deprecations` against a ref
/// carrying no published schema is it.
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
        Case {
            // CLOUD-421, and the fourth code's only row. `config deprecations`
            // needs a published baseline to compare against; a ref carrying none
            // is COULD NOT LOOK, which is `Internal` and never `Success`. The
            // distinction from the row above is the whole of §7's 1-versus-3
            // split: omitting the baseline argument is a malformed invocation
            // (`Usage`), while naming one that resolves to no schema is a
            // well-formed invocation Batten could not answer.
            //
            // It is here rather than only in the dedicated `config deprecations`
            // test for the reason this table exists at all: a regression in any
            // command's code has to surface in one place, and for `3` there was
            // no such place.
            name: "config deprecations, no published schema at the ref → internal",
            args: &["config", "deprecations", "refs/tags/nope-not-a-tag"],
            config: Some("version = 1\n"),
            env: &[],
            expected: 3,
        },
    ];
    assert_exit_codes("contract", &cases);
}

/// CLOUD-330: the disposition -> exit mapping is TOTAL, asserted by enumeration.
///
/// Measured on Danger (`danger-js`, `source/runner/Executor.ts`), the closest
/// prior art for a graduated severity model over git state: its default run with
/// failing rules **exits 0**, because the blocking is delivered as a commit
/// status posted to the forge and the exit code is set only behind an opt-in
/// flag. That is a false green for every caller Batten has — `hk`, a pre-commit
/// hook, a CI step, a `PreToolUse` guard all read the code and nothing else.
///
/// The §7 contract says what each code MEANS. It does not say every blocking
/// disposition must REACH one, and nothing here would have caught a disposition
/// that reports richly and exits `0`.
///
/// **By enumeration, never by sampling.** A test naming dispositions one at a
/// time regrows the gap the moment a disposition is added, which is the failure
/// mode this exists to close. So both halves below range over a declared set:
/// the first over [`Outcome`] through an exhaustive `match`, the second over
/// `RuleSeverity::ALL` crossed with the `--fail-on-warning` setting.
///
/// The row's stated blocker was CLOUD-12, "the engine has no enumerable
/// disposition set to iterate". It has one: `decision::Outcome` carries four
/// variants, an `ALL`, and `exit_code()`. The gate enumerates rather than
/// samples today.
#[test]
fn every_disposition_maps_to_a_declared_exit_code() {
    // (a) TOTALITY, and it is the `match` that carries it rather than the loop.
    //
    // A new `Outcome` variant fails to COMPILE here — which is the acceptance
    // clause, stated as "a disposition added without an exit mapping fails the
    // suite". Iterating `Outcome::ALL` alone would not: a variant added to the
    // enum, to `exit_code()` and to `ALL` would pass over silently, and one
    // added to the enum but not to `ALL` would never be visited at all.
    fn declared_exit_of(outcome: Outcome) -> Option<ExitCode> {
        match outcome {
            Outcome::Pass => Some(ExitCode::Success),
            Outcome::Violation => Some(ExitCode::Violation),
            // NOT `Success`. A gate that did not run reported nothing, and
            // reading that silence as a pass is precisely how fail-closed
            // becomes fail-open.
            Outcome::Skipped => None,
            Outcome::Internal => Some(ExitCode::Internal),
        }
    }

    for outcome in Outcome::ALL {
        assert_eq!(
            outcome.exit_code(),
            declared_exit_of(*outcome),
            "{outcome:?} disagrees with the mapping this test declares"
        );
    }

    // And `ALL` itself is the set the loop above ranges over, so it has to BE
    // the set. Exhaustive again, so a variant missing from `ALL` is caught here
    // rather than by never being tested.
    for outcome in [
        Outcome::Pass,
        Outcome::Violation,
        Outcome::Skipped,
        Outcome::Internal,
    ] {
        assert!(
            Outcome::ALL.contains(&outcome),
            "{outcome:?} is not in Outcome::ALL, so nothing ranges over it"
        );
    }

    // (b) THE PARTITION: every outcome that blocks reaches a NON-ZERO code, and
    // every one that does not reaches `Success` or abstains. This is the Danger
    // claim in one assertion — no disposition both blocks and exits 0.
    for outcome in Outcome::ALL {
        match outcome.exit_code() {
            Some(ExitCode::Success) => assert_eq!(
                *outcome,
                Outcome::Pass,
                "only a passing gate may reach exit 0"
            ),
            Some(code) => assert_ne!(
                code.code(),
                ExitCode::Success.code(),
                "{outcome:?} is blocking, so it must not reach exit 0"
            ),
            // Abstention is not a pass; it contributes no code at all.
            None => assert_eq!(*outcome, Outcome::Skipped),
        }
    }
}

/// The other half of CLOUD-330, over the COMPILED BINARY: the severity table's
/// blocking partition is what the process actually exits with.
///
/// Part (b) above is a statement about a table. This is the one that would have
/// caught Danger: it drives the real config -> `severity::promote` ->
/// `rules::any_blocking` -> `ExitCode::verdict` path and reads the process's own
/// status, so a verdict delivered anywhere OTHER than the exit code shows up as
/// a `0` here.
///
/// Enumerated from `RuleSeverity::ALL` crossed with the `--fail-on-warning`
/// setting rather than written out, so a new severity is covered by this loop on
/// the day it is declared, and a change to `TABLE` that moves which levels block
/// makes the binary and the table disagree.
#[test]
fn every_severity_reaches_the_exit_the_table_declares() {
    for severity in RuleSeverity::ALL {
        for fail_on_warning in [false, true] {
            // The expectation comes from the declared table, never from a
            // literal: this asserts the binary AGREES with `severity::TABLE`,
            // which is the property, rather than re-stating the table here as a
            // second authority (non-negotiable rule 6).
            let report =
                severity::promote(severity::row_for_rule(*severity).report, fail_on_warning);
            let expected = ExitCode::verdict(report == ReportLevel::Fail);

            let label = format!("{}-{fail_on_warning}", severity.as_str());
            let dir = repo_with_config(
                &format!("disposition-{label}"),
                &format!(
                    "version = 1\n\n[[rule]]\nid = \"banned\"\nkind = \"forbid\"\nglob = \"src/**/*.rs\"\npattern = \"BANNED\"\nseverity = \"{}\"\n",
                    severity.as_str()
                ),
            );
            fs::create_dir_all(dir.join("src")).expect("create fixture src");
            fs::write(dir.join("src/a.rs"), "// BANNED\n").expect("write the matching file");

            let mut command = batten();
            command.arg("check").current_dir(&dir);
            if fail_on_warning {
                command.arg("--fail-on-warning");
            }
            let status = command.status().expect("run batten check");

            assert_eq!(
                status.code(),
                Some(expected.code()),
                "severity {} with fail_on_warning={fail_on_warning} renders {} and must exit {}",
                severity.as_str(),
                report.as_str(),
                expected.code()
            );

            // The Danger assertion, stated separately because it is the one that
            // fails if a verdict ever moves to a side channel: a finding the
            // table calls blocking must never leave the process at 0.
            if report == ReportLevel::Fail {
                assert_ne!(
                    status.code(),
                    Some(ExitCode::Success.code()),
                    "a blocking finding reached exit 0 — the verdict is not on the exit code"
                );
            }
        }
    }
}

// --- `check` scoping: `--staged` and `--since <rev>` (CLOUD-519) ------------

/// A repository with a banned shape in TWO files, one of them changed.
///
/// The planted shape in the unchanged file is the discriminator: a narrowed run
/// that reported it would have narrowed nothing, and one that reported neither
/// would pass for the wrong reason. Both directions are asserted below.
fn scoped_fixture(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"src/**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
        )
        .files(&[
            ("src/untouched.rs", "// TODO: planted, and never in a change-set\n"),
            ("src/changed.rs", "fn clean() {}\n"),
        ])
        .git()
        .base_commit()
        .build();
    // The change comes AFTER the base commit, so `--since HEAD` and `--staged`
    // both have exactly one path to find.
    write(
        &dir,
        "src/changed.rs",
        "// TODO: the caller just wrote this\n",
    );
    dir
}

#[test]
fn a_narrowed_check_judges_the_changed_file_and_not_the_others() {
    let dir = scoped_fixture("scope-narrows");

    // The control: unnarrowed, both files are reported. Without this the
    // assertions below would hold over a fixture whose rule never fired.
    let whole = run(&dir, &["check"]);
    let plain = stdout(&whole);
    assert_eq!(whole.status.code(), Some(2), "the planted shapes are found");
    assert!(plain.contains("src/untouched.rs"), "control: {plain}");
    assert!(plain.contains("src/changed.rs"), "control: {plain}");

    // `--staged` sees nothing until the change is staged: an unstaged edit is
    // explicitly not what a pre-commit hook is about to commit.
    let unstaged = run(&dir, &["check", "--staged"]);
    assert_eq!(
        unstaged.status.code(),
        Some(0),
        "an unstaged edit is not staged: {}",
        stdout(&unstaged)
    );

    git_in(&dir, &["add", "src/changed.rs"]);
    for narrowing in [vec!["check", "--staged"], vec!["check", "--since", "HEAD"]] {
        let narrowed = run(&dir, &narrowing);
        let said = stdout(&narrowed);
        assert_eq!(narrowed.status.code(), Some(2), "{narrowing:?}: {said}");
        assert!(
            said.contains("src/changed.rs"),
            "{narrowing:?} must judge the changed file: {said}"
        );
        assert!(
            !said.contains("src/untouched.rs"),
            "{narrowing:?} must not judge the unchanged file: {said}"
        );
    }
}

/// §5: narrowing changes WHICH files are judged, never WHAT is said about one.
#[test]
fn a_narrowed_findings_pointer_is_byte_identical_to_an_unnarrowed_one() {
    let dir = scoped_fixture("scope-pointers");
    git_in(&dir, &["add", "src/changed.rs"]);

    let whole = stdout(&run(&dir, &["check"]));
    let narrowed = stdout(&run(&dir, &["check", "--staged"]));

    let line = |text: &str| -> String {
        text.lines()
            .find(|line| line.contains("src/changed.rs"))
            .unwrap_or_default()
            .to_owned()
    };
    assert!(!line(&whole).is_empty(), "the control found nothing");
    assert_eq!(
        line(&narrowed),
        line(&whole),
        "the narrowed run must say the same bytes about the file it did judge"
    );
}

/// A ratchet counts its whole glob under either flag (CLOUD-519, CLOUD-328).
///
/// **`non_decreasing` is the direction that can detect this, and choosing it is
/// the whole test.** A ratchet's two halves compare aggregates over one glob, so
/// a narrowed working-tree side counts fewer matches than the base — a FALL.
/// Under `non_increasing` a fall is permitted, so the same fixture would pass
/// whether or not the exemption existed; under `non_decreasing` a fall is
/// exactly the violation, which is the manufactured deletion CLOUD-328 measured
/// from a different cause.
///
/// The changed file sits OUTSIDE the ratchet's glob on purpose: that is what
/// makes a narrowed count `0` against a base of `2`, rather than merely smaller.
#[test]
fn a_ratchet_is_not_narrowed_by_a_scoping_flag() {
    let dir = Fixture::new("scope-ratchet")
        .config(
            "version = 1\n\n[[rule]]\nid = \"keep-the-cases\"\nkind = \"ratchet\"\nglob = \"src/**/*.rs\"\npattern = \"#[test]\"\ndirection = \"non_decreasing\"\nbase = \"origin/main\"\nseverity = \"deny\"\n",
        )
        .files(&[
            ("src/a.rs", "#[test]\nfn one() {}\n"),
            ("src/b.rs", "#[test]\nfn two() {}\n"),
        ])
        .git()
        .base_commit()
        .build();
    // A change the ratchet's glob does not select, so a narrowed scope contains
    // none of the files it counts.
    write(&dir, "notes.md", "unrelated\n");
    git_in(&dir, &["add", "-A"]);

    // The control, and it must be CLEAN: the cases are all still there, so the
    // ratchet holds. Without this the assertions below could pass over a rule
    // that was refusing for some other reason — which an earlier draft of this
    // test did, comparing two identical usage errors from an invalid `direction`
    // token and establishing nothing.
    let plain = run(&dir, &["check"]);
    assert_eq!(
        plain.status.code(),
        Some(0),
        "the ratchet holds when nothing was deleted: {}",
        stdout(&plain)
    );

    for narrowing in [
        vec!["check", "--staged"],
        vec!["check", "--since", "origin/main"],
    ] {
        let scoped = run(&dir, &narrowing);
        assert_eq!(
            scoped.status.code(),
            Some(0),
            "{narrowing:?} narrowed the ratchet and manufactured a deletion: {}",
            stdout(&scoped)
        );
        assert_eq!(
            stdout(&scoped),
            stdout(&plain),
            "{narrowing:?} moved what the ratchet said"
        );
    }
}

/// The two flags name two different change-sets, so passing both is a usage
/// error rather than one of them silently winning.
#[test]
fn staged_and_since_together_are_a_usage_error() {
    let dir = scoped_fixture("scope-conflict");
    let both = run(&dir, &["check", "--staged", "--since", "HEAD"]);
    assert_eq!(
        both.status.code(),
        Some(1),
        "two change-sets is a malformed invocation, never a verdict: {}",
        stderr(&both)
    );
    assert!(
        stdout(&both).is_empty(),
        "a refused invocation emits no findings"
    );
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

/// CLOUD-222's load-bearing assertion, and it is a NEGATIVE one: the agent path
/// keeps the silence it has today.
///
/// A first-contact notice on stderr is only defensible if it cannot reach the
/// caller §6's silence rule exists for — an agent in a loop, reading an exit code
/// and paying for every byte. A spawned process has both channels piped, so §4
/// resolves it unattended and the notice is unreachable **by construction**
/// rather than by a reviewer's promise. This is what proves it, and it fails the
/// moment the notice is emitted unconditionally.
///
/// Both channels, not just stdout: the notice rides stderr, so asserting only
/// stdout would pass over exactly the regression this guards.
#[test]
fn a_clean_check_says_nothing_at_all_when_its_channels_are_piped() {
    let dir = repo_with_config(
        "check-clean-piped",
        "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
    );
    fs::write(dir.join("lib.rs"), "all clear\n").expect("write source");

    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stdout.is_empty(),
        "stdout is the answer channel and a clean run has no answer, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "a piped run is the agent path — it must keep today's silence, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

    // An entry is `{id, path}` since CLOUD-969, and reading BOTH halves here is
    // the point of the reconciliation: a consumer that pinned paths alone loses
    // its allowlist to a rename, in the direction where a path it still trusts
    // no longer means what it did.
    let entries = value["read_only_allowlist"]
        .as_array()
        .expect("the emitted document carries the derived allowlist");
    let ids: Vec<&str> = entries
        .iter()
        .map(|entry| entry["id"].as_str().expect("every entry carries its id"))
        .collect();
    let allowlist: Vec<&str> = entries
        .iter()
        .map(|entry| {
            entry["path"]
                .as_str()
                .expect("every entry carries its path")
        })
        .collect();

    assert!(allowlist.contains(&"check"), "{allowlist:?}");
    assert!(allowlist.contains(&"spec"), "{allowlist:?}");
    // The two verbs whose exclusion is the whole point: `enforce` may run
    // user-supplied commands, and `hook` adjudicates someone else's write.
    assert!(!allowlist.contains(&"enforce"), "{allowlist:?}");
    assert!(!allowlist.contains(&"hook"), "{allowlist:?}");

    // Sorted by the STABLE half (§6). Asserting the path order instead would
    // pin an order the document does not have, and would move under a rename
    // that changed nothing about which commands are read-only.
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "the emitted allowlist is sorted by id (§6)");
    assert_eq!(
        ids.len(),
        allowlist.len(),
        "every entry carries both halves: {ids:?} {allowlist:?}"
    );
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
        // CLOUD-1286: the sanctioned command is ONE HOP away rather than
        // inline, and this case is what proves the hop actually lands. The
        // emitted line carries the rule id; `batten policy explain <rule>`
        // resolves that id to the row's own remedy. Asserting only the absence
        // would pass over a refusal that points nowhere, which is worse than
        // the repetition it replaced.
        let row = stderr
            .split_whitespace()
            .next_back()
            .expect("a deny names the rule that fired");
        let explained = batten_with(&dir, &["policy", "explain", row], &[]);
        assert_eq!(
            explained.status.code(),
            Some(0),
            "{}: the rule on the line must resolve, got: {stderr}",
            case.command
        );
        let text = String::from_utf8_lossy(&explained.stdout);
        assert!(
            text.contains(case.fix),
            "{}: the hop must reach the sanctioned command, got: {text}",
            case.command
        );
    }
}

#[test]
fn the_in_band_hosts_carry_the_decision_in_their_document() {
    // The contract is not stderr-only. Claude discards stdout on exit 2 and
    // Cursor assigns stderr no meaning at all, so on those two hosts the decision
    // document is the ONLY place the refusal can travel — the case that would
    // silently regress to a bare "deny" if the projection happened per channel
    // instead of once.
    //
    // CLOUD-1286 shortened WHAT travels, not WHERE: the class, the pointers and
    // the rule id, with the fix one `batten policy explain <rule>` away. That
    // this file's projection is still one function rather than one per host is
    // exactly what this case pins, and it pins it on the shorter line just as
    // well.
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
            reason.contains("call name refused"),
            "{harness}: the document must carry the class, got: {reason}"
        );
        assert!(
            reason.contains("gh-pr-merge"),
            "{harness}: and the rule the hop takes, got: {reason}"
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
fn a_deny_with_no_consumer_remedy_falls_back_to_the_declared_class() {
    // WHAT CLOUD-1050 CHANGED, over the compiled binary — the tier that used to
    // be a generic apology.
    //
    // The contract was: where nothing is declared, the refusal says so, because
    // an omitted fix clause is indistinguishable from a producer that forgot one.
    // That is still the contract; what changed is that a NATIVE refusal now names
    // a declared class, so the floor under the consumer's two tiers is that
    // class's own `command` route rather than a sentence naming no verb.
    // `verdict::validate` refuses a class with no route and refuses one whose only
    // route is an override, so this floor cannot be empty by construction.
    //
    // The explicit-absence half is still asserted, on the path where it is still
    // reachable: `refusal::tests::a_refusal_from_consumer_prose_still_declares_an_
    // absent_fix_rather_than_omitting_it`.
    let dir = repo_with_config("refusal-no-remedy", NO_REMEDY_CONFIG);
    let output = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("mv notes.md guarded/thing"),
        false,
    );
    assert_eq!(output.status.code(), Some(2), "the protected gate denies");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // CLOUD-1286: the emitted line is the class, the pointers, and the rule id.
    // The FLOOR itself — that a native refusal falls back to its class's own
    // `command` route rather than to a generic apology — is asserted on the
    // typed field by `hook::tests::a_verb_with_no_redirect_falls_back_to_the_
    // classs_own_route`, which is the stronger read: a substring here could be
    // satisfied by the same words appearing anywhere in the line.
    assert!(
        stderr.contains("protected-mutation"),
        "names the gate, got: {stderr}"
    );
    assert!(
        stderr.contains("path write refused"),
        "the hot path leads with the token, got: {stderr}"
    );
    assert!(
        !stderr.contains("path write refused ("),
        "and does not inline the class's own definition, got: {stderr}"
    );
    assert!(
        !stderr.contains("Fix: "),
        "nor the remedy, which `batten policy explain` prints, got: {stderr}"
    );
}

/// A gate whose protected class carries its own redirect, and a verb whose
/// general remedy is the wrong answer for it (CLOUD-280).
const PER_CLASS_REDIRECT_CONFIG: &str = r#"version = 1
protected = ["guarded/**", "vendor/**"]

[[redirect]]
glob = "guarded/**"
mutation = "change it in a pull request"

[[verb]]
verb = "rm"
effect = "destructive"
redirect = "restore it with git"
"#;

/// **The remedy channel survives a config that will not load** (CLOUD-1313).
///
/// Measured before the fix, on a repository whose `batten.toml` carries one
/// malformed table:
///
/// ```text
/// $ batten policy explain "path write refused"
/// batten: invalid config ./batten.toml: TOML parse error at line 3
/// ```
///
/// `explain` opened with `resolve::resolve(..)?`, so a load failure killed it
/// before any registry was consulted — including for a VENDORED class that needs
/// no consumer config at all. `path write refused` is what the mediated boundary
/// raises dozens of times a session, and its remedy was unreachable in exactly
/// the repository state where a reader is most likely to be stuck.
///
/// This is a precondition of CLOUD-1313 rather than a nicety beside it: twelve
/// config-fault classes shipped onto a surface that goes dark when a config
/// breaks would be twelve dead remedies, which is the shape that row is about.
#[test]
fn a_class_still_explains_when_the_config_cannot_be_read() {
    let dir = scratch("explain-over-a-broken-config");
    write(
        &dir,
        "batten.toml",
        // Well-formed enough to be found and malformed enough to refuse: `verb`
        // is a table array whose row omits every required key.
        "version = 1\n\n[[verb]]\nverb = \"x\"\n",
    );

    let explained = batten_with(&dir, &["policy", "explain", "path write refused"], &[]);
    assert_eq!(
        explained.status.code(),
        Some(0),
        "a vendored class needs no consumer config: {}",
        String::from_utf8_lossy(&explained.stderr)
    );
    let out = String::from_utf8_lossy(&explained.stdout);
    assert!(out.contains("path write refused"), "the class: {out}");
    assert!(
        out.contains("config read first"),
        "AND ITS ROUTES — the one that says to read `batten.toml` is exactly the \
         advice a reader with a broken config needs: {out}"
    );

    // THE CONSUMER'S OWN TABLES STILL SAY SO rather than answering emptily. A
    // rule id cannot resolve from a config nobody could read, and an empty
    // redirect table would read as "nothing to do instead".
    let missing = batten_with(&dir, &["policy", "explain", "some-rule-id"], &[]);
    assert_eq!(missing.status.code(), Some(1), "no config, no rule table");
    let said = String::from_utf8_lossy(&missing.stderr);
    assert!(
        said.contains("could not be read"),
        "and it names WHY rather than reporting zero rows: {said}"
    );
}

#[test]
fn a_deny_names_the_path_classs_own_mutation_over_the_verbs() {
    // The three tiers over the compiled binary, because a refusal is a contract
    // only where a host reads it. Same command, same verb, two paths: the class
    // that declares a remedy gets it, and the class that does not falls back to
    // the verb's — which is CLOUD-96's behaviour, asserted here so the floor is
    // proven rather than assumed.
    let dir = repo_with_config("refusal-per-class", PER_CLASS_REDIRECT_CONFIG);

    let claimed = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("rm guarded/thing.md"),
        false,
    );
    assert_eq!(claimed.status.code(), Some(2), "the protected gate denies");
    let stderr = String::from_utf8_lossy(&claimed.stderr);
    // CLOUD-1286 took the remedy off the emitted line, so what this case can
    // still assert over the compiled binary is that the two paths are told
    // apart AT ALL and that neither remedy is inlined. WHICH remedy wins — the
    // path class's over the verb's, CLOUD-280's tiering — is asserted on the
    // typed `Refusal::fix()` by `hook::tests::the_deny_names_the_sanctioned_
    // mutation_declared_beside_the_verb`.
    //
    // The hop for THIS remedy is the derived gate's own id rather than a class
    // or a rule, because the answer is per path glob: `batten policy explain
    // protected-mutation` prints the `[[redirect]]` table and the `[[verb]]`
    // fallback under it, in the order the boundary applies them.
    let explained = batten_with(&dir, &["policy", "explain", "protected-mutation"], &[]);
    assert_eq!(explained.status.code(), Some(0), "the gate resolves");
    let routes = String::from_utf8_lossy(&explained.stdout);
    assert!(
        routes.contains("change it in a pull request"),
        "the path class's remedy is reachable, got: {routes}"
    );
    assert!(
        routes.contains("restore it with git"),
        "and so is the verb's fallback, got: {routes}"
    );
    assert!(
        stderr.contains("guarded/thing.md"),
        "the path class that matched is the pointer, got: {stderr}"
    );
    assert!(
        !stderr.contains("change it in a pull request"),
        "the remedy is dereferenced rather than inlined, got: {stderr}"
    );
    assert!(
        !stderr.contains("restore it with git"),
        "the verb's general remedy must not appear either, got: {stderr}"
    );

    let unclaimed = run_hook_in(
        &dir,
        "exit-code",
        &claude_payload("rm vendor/thing.md"),
        false,
    );
    assert_eq!(unclaimed.status.code(), Some(2), "still denied");
    let stderr = String::from_utf8_lossy(&unclaimed.stderr);
    assert!(
        stderr.contains("vendor/thing.md"),
        "an unclaimed class still points at what it refused, got: {stderr}"
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
    // Claude-only, and the one row whose `adjudicated: false` is a GAP rather
    // than a design no-op (CLOUD-777). The host honours a deny at this moment —
    // the two bash guards registered here exit 2 — so the column records that no
    // rule KIND selects for it yet, not that nothing could. When one does, this
    // row flips and `payload_at` is already able to prove it.
    EventRow {
        event: batten::hook::Event::UserPromptSubmit,
        spelling: "UserPromptSubmit",
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
                // NO DECISION, WHICH IS NOT THE SAME AS NO OUTPUT — and the
                // difference is the advisory channel, which `SessionStart`
                // legitimately carries (CLOUD-1324). This read `is_empty()`,
                // which passed only because no fixture here had ever tripped an
                // advisory; the drift reporter could already emit one on this
                // very event. So an unadjudicated event is held to what the
                // message claims: it may say things, and it may not decide.
                let raw = String::from_utf8_lossy(&output.stdout).into_owned();
                if !raw.trim().is_empty() {
                    let document: serde_json::Value =
                        serde_json::from_str(&raw).unwrap_or_else(|_| {
                            panic!("{at}: anything on stdout is one JSON document: {raw}")
                        });
                    assert!(
                        document["hookSpecificOutput"]["permissionDecision"].is_null(),
                        "{at}: an unadjudicated event emits no decision document: {raw}"
                    );
                }
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
            // The row's id on the line is what says a deny reached this channel
            // — CLOUD-1286 took the `Refused by` prefix off it, and this case
            // is about the CHANNEL rather than about the wording.
            assert!(stderr.contains("gh-pr-merge"), "{harness}: got {stderr}");
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
            .env_remove("BATTEN_HOOK_BYPASS")
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
    //
    // OUTSIDE ANY REPOSITORY SINCE CLOUD-824, and the move is the point rather
    // than a workaround. This used to delete `batten.toml` from a fixture under
    // `target/tmp` — inside THIS repository — and read the result as "no
    // authority". It is not: the hook now resolves the repository when the cwd
    // carries no authority of its own, which is exactly the subdirectory case the
    // deleted launcher's `cd` existed to cover, so the old fixture was asserting
    // fail-open over a directory that has an authority one level up. The claim
    // this case actually makes needs a directory no repository encloses, which is
    // what `scratch_outside_tree` is for.
    let dir = common::scratch_outside_tree("hook-no-authority", "not-a-repository");
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
            // CLOUD-1286: the redirect is dereferenced; what every channel
            // carries is the class and the path it refused.
            assert!(
                stdout.contains("path write refused"),
                "{harness}: names the class, got {stdout}"
            );
            assert!(
                stdout.contains("guarded/thing"),
                "{harness}: and the pointer, got {stdout}"
            );
        } else {
            assert_eq!(output.status.code(), Some(2), "{harness}");
            assert!(
                stderr.contains("path write refused"),
                "{harness}: names the class, got {stderr}"
            );
            assert!(
                stderr.contains("guarded/thing"),
                "{harness}: and the pointer, got {stderr}"
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
            .env_remove("BATTEN_HOOK_BYPASS")
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

/// Where a census case's verdict is a property of the **commit** rather than of
/// the world.
///
/// The obligation this column serves used to be a comment: every hook test above
/// supplies its own policy, so after CLOUD-48 deleting a row from this repo's
/// `batten.toml` would break none of them — and the guard chain in
/// `.claude/settings.json` would silently lose a rule. The standing rule it
/// stated is that a rule is only pinned by a case that seeds the shape it bans,
/// and any rule landing later owes one of its own. Nothing decided it, and two
/// of the six committed rows had no case at all (CLOUD-652).
///
/// **The reason they had none is this column, and it is not an exemption.** A
/// row carrying `requires_key` resolves the key against the branch name and the
/// commit subjects on `origin/main..HEAD`, so its verdict *against the ambient
/// checkout* is whatever the runner's git state happens to be — measured: a
/// branch naming its issue allows `gh pr create` here, a keyless one denies it.
/// What that makes unavailable is the census's ambient shape, never the row
/// itself: supplying the git state a `requires_key` row reads puts the verdict
/// back inside the commit, and `batten.toml`'s own bytes are what the fixture
/// then carries. So the debt was simply unpaid, and the site a row owes is
/// DECIDED from the row (see [`census_gaps`]) rather than chosen per case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CensusSite {
    /// This checkout. The row bans the shape outright, so no fact about the
    /// working tree can move the answer.
    Checkout,
    /// A fixture carrying the **committed** config bytes, on a branch and a
    /// commit range naming no tracker key.
    Keyless,
    /// A fixture carrying the **committed** config bytes and a known set of
    /// tracked artifacts (CLOUD-312 row 6).
    ///
    /// The third site, and it exists for the same reason `Keyless` does rather
    /// than as an exemption. A `tracked_artifacts` ceiling counts the paths a
    /// prompt names INTERSECTED with the tracked set, so its verdict against the
    /// ambient checkout is whatever this repository happens to track today — a
    /// case naming four files here would pass or fail on an unrelated rename.
    /// Supplying the tracked set puts the verdict back inside the commit, exactly
    /// as supplying the git state does for a `requires_key` row.
    Manifest,
}

/// What a census case hands the adjudicator.
///
/// Two shapes, because a `shape` row's keying column is one of three and only one
/// of them is a command line (CLOUD-924): a row selecting on `tool` with a
/// `prompt` projection has no command to seed, so a command-only case could not
/// exercise it at all. The enum is what keeps the census TOTAL over the kind
/// rather than over the rows that happen to be command-shaped.
enum CensusCall {
    /// A shell command line, for a row keyed on `pattern`.
    Command(&'static str),
    /// A bare tool call, for a row keyed on `tool` with no projection to measure
    /// (CLOUD-312 row 4).
    ///
    /// The connector verbs are decided by the name alone, so the input is empty:
    /// a case supplying one would be asserting over a field the row never reads.
    Verb(&'static str),
    /// A subagent spawn, for a row keyed on `tool` and measuring `prompt`.
    Spawn {
        /// The tool the call names, as the host spells it.
        tool: &'static str,
        /// The prompt the ceiling measures, repeated `repeat` times.
        prompt: &'static str,
        /// How many copies of `prompt` the case hands over.
        ///
        /// A token ceiling needs a prompt longer than any literal worth reading in
        /// a case table, and `str::repeat` is not const — so the length is a
        /// number here rather than 6100 characters of filler.
        repeat: usize,
    },
}

impl CensusCall {
    /// The case's own description, for an assertion message.
    ///
    /// Pointer-shaped: a spawn reports its TOOL, never its prompt, because a
    /// prompt is the projection this row exists to keep out of output (rule 4).
    fn describe(&self) -> &'static str {
        match self {
            CensusCall::Command(command) => command,
            CensusCall::Verb(tool) | CensusCall::Spawn { tool, .. } => tool,
        }
    }
}

/// One census case: a mediated call, the committed row that must refuse it, and
/// the site where that refusal is a property of the commit.
struct ShapeCase {
    /// The call handed to the adjudicator.
    call: CensusCall,
    /// The `batten.toml` row id whose refusal must name this case.
    ///
    /// Asserted rather than the exit code alone: a case denied by some *other*
    /// row reads as coverage while the row it was written for is already dead,
    /// which is the failure one level in from the one this census is about.
    rule: &'static str,
    /// Where the case runs.
    site: CensusSite,
}

/// One case per committed `shape` row — and the pairing is decided rather than
/// remembered by [`every_committed_shape_row_is_exercised_by_the_census`], which
/// reads the rows out of `batten.toml` through the real loader.
const SHAPE_CENSUS: &[ShapeCase] = &[
    ShapeCase {
        call: CensusCall::Command("gh pr merge 42"),
        rule: "gh-pr-merge",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("gh pr comment 7 --body /fast-forward"),
        rule: "gh-pr-comment-fast-forward",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("gh pr checks --watch"),
        rule: "gh-pr-checks",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("gh run watch 123"),
        rule: "gh-run-watch",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("cargo test -p batten"),
        rule: "no-bare-cargo",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        // The wrapper does not launder it: `effective_program` steps past `env`
        // to reach `cargo`, and the mediator is read from what it stepped over.
        call: CensusCall::Command("env RUSTFLAGS=-Awarnings cargo build"),
        rule: "no-bare-cargo",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("gh pr create --title 'no key here'"),
        rule: "pr-names-an-issue",
        site: CensusSite::Keyless,
    },
    ShapeCase {
        call: CensusCall::Command("gh pr ready 42"),
        rule: "ready-names-an-issue",
        site: CensusSite::Keyless,
    },
    // CLOUD-312 row 4. Decided by the tool name alone, under the readable server
    // spelling — the UUID and bare-name spellings are `connector_verbs.rs`'s.
    ShapeCase {
        call: CensusCall::Verb("mcp__Claude_Code_Remote__subscribe_pr_activity"),
        rule: "no-pr-activity-subscription",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Verb("mcp__Claude_Code_Remote__send_later"),
        rule: "no-scheduled-self-wakeup",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Verb("mcp__Claude_Code_Remote__create_trigger"),
        rule: "no-scheduled-trigger",
        site: CensusSite::Checkout,
    },
    // CLOUD-1264. The raw tracker read, under the readable server spelling — the
    // UUID and bare-name spellings, and every negative control, are
    // `raw_tracker_read.rs`'s.
    ShapeCase {
        call: CensusCall::Verb("mcp__Linear__get_issue"),
        rule: "no-raw-issue-read",
        site: CensusSite::Checkout,
    },
    // CLOUD-312 row 6. Four named artifacts against a ceiling of three, over the
    // tracked set the `Manifest` fixture supplies.
    ShapeCase {
        call: CensusCall::Spawn {
            tool: "Task",
            prompt: "read one.txt two.txt three.txt four.txt then act",
            repeat: 1,
        },
        rule: "a-spawn-names-few-artifacts",
        site: CensusSite::Manifest,
    },
    // The token ceiling reads only the envelope, so no fact about the tree can
    // move its answer and it owes the ambient site. 6100 characters over four is
    // 1525, past the committed 1500.
    ShapeCase {
        call: CensusCall::Spawn {
            tool: "Task",
            // 6100 characters over four is 1525, past the committed 1500.
            prompt: "x",
            repeat: 6100,
        },
        rule: "a-spawn-prompt-stays-in-budget",
        site: CensusSite::Checkout,
    },
];

/// A gap in the census: pointer-only, an id and what is wrong with it.
///
/// Never the row's `pattern`, which is the policy's own text (non-negotiable
/// rule 4). The renderer adds the `batten.toml` line and nothing else.
#[derive(Debug, PartialEq, Eq)]
struct CensusGap {
    /// A `batten.toml` row id, or the row id a case declares.
    id: String,
    /// A stable token naming the class of gap.
    class: &'static str,
}

/// Decide the census obligation over a config's `shape` rows.
///
/// Pure over the config text so the falsification below can create the failing
/// conditions the committed config must never have — `rust.md`'s rule that a
/// test must be shown able to fail, rather than asserting a conclusion over a
/// precondition nothing established.
///
/// Three classes, and the third is what keeps the site column from becoming an
/// exemption channel: the site a row owes is a function of the row, so a
/// `requires_key` row censused against the ambient checkout is a gap even though
/// it would pass on this branch, and a row carrying no `requires_key` cannot
/// claim the keyless site to avoid saying what it bans here.
fn census_gaps(config: &str, cases: &[ShapeCase]) -> Vec<CensusGap> {
    let parsed = batten::config::parse(config, "batten.toml").expect("parse the config");
    let rows: Vec<&batten::rules::Rule> = parsed
        .rules
        .iter()
        .filter(|rule| {
            rule.kind == batten::rules::RuleKind::Shape
                && rule.scope == batten::rules::RuleScope::MediatedCall
        })
        .collect();

    let mut gaps = Vec::new();
    for row in &rows {
        let Some(case) = cases.iter().find(|case| case.rule == row.id) else {
            gaps.push(CensusGap {
                id: row.id.clone(),
                class: "unexercised",
            });
            continue;
        };
        // DECIDED FROM THE ROW, never chosen per case. A ceiling counting tracked
        // artifacts reads the tracked set, and a keyed row reads the branch and
        // the commit range; both are facts a fixture has to supply for the verdict
        // to be about the commit. Everything else is banned outright and no fact
        // about the working tree can move its answer.
        let owed = if row.counts == Some(batten::rules::CeilingUnit::TrackedArtifacts) {
            CensusSite::Manifest
        } else if row.requires_key.is_some() {
            CensusSite::Keyless
        } else {
            CensusSite::Checkout
        };
        if case.site != owed {
            gaps.push(CensusGap {
                id: row.id.clone(),
                class: "wrong-site",
            });
        }
    }
    for case in cases {
        if !rows.iter().any(|row| row.id == case.rule) {
            gaps.push(CensusGap {
                id: case.rule.to_owned(),
                class: "names-no-row",
            });
        }
    }
    gaps
}

/// The `batten.toml` line a row id is declared on, for the pointer.
fn row_line(config: &str, id: &str) -> Option<usize> {
    let needle = format!("id = \"{id}\"");
    config
        .lines()
        .position(|line| line.trim() == needle)
        .map(|index| index + 1)
}

/// `<row id> batten.toml:<line> <class>` per gap, and nothing else.
fn render_gaps(config: &str, gaps: &[CensusGap]) -> String {
    let mut report = String::new();
    for gap in gaps {
        let line = row_line(config, &gap.id).map_or_else(|| "-".to_owned(), |at| at.to_string());
        let _ = writeln!(report, "{} batten.toml:{line} {}", gap.id, gap.class);
    }
    report
}

/// Copy every registered policy module into a fixture carrying the committed
/// authority (CLOUD-843).
///
/// A `policy` row naming a module the tree does not carry is refused at LOAD,
/// before any rule runs — correctly, since a silently absent module is a gate
/// that decides nothing. So a fixture missing them fails on that refusal rather
/// than on the rule it is about, which is the same precondition the budget
/// surfaces and the `no-secrets` scanner already owe.
///
/// The DIRECTORY is mirrored rather than a list named here. The retirement
/// campaign adds a module per migrated gate, and a hand-kept list would make
/// every one of them a second edit somewhere else — whose omission surfaces as
/// whichever rule the fixture was actually about appearing to fail.
fn committed_policy_modules(dir: &Path) {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy");
    let Ok(entries) = fs::read_dir(&source) else {
        return;
    };
    fs::create_dir_all(dir.join("policy")).expect("create fixture policy dir");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "rego") {
            fs::copy(&path, dir.join("policy").join(entry.file_name()))
                .expect("copy the committed policy module");
        }
    }
}

/// The committed authority, read once per case that needs its bytes.
fn committed_config() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    fs::read_to_string(&path).expect("read the committed batten.toml")
}

/// A fixture carrying the **committed** `batten.toml`, naming no tracker key.
///
/// The config is copied rather than re-typed, which is the whole point: deleting
/// a row from the authority deletes it here too, so the case fails. `Fixture`'s
/// `git`/`base_commit` pair pins the branch to `main` and `origin/main` to the
/// base commit, leaving `origin/main..HEAD` empty — so none of the three key
/// sources answers, and the branch name is set rather than inherited from
/// whatever `init.defaultBranch` the runner carries.
fn keyless_committed_config_fixture(name: &str) -> PathBuf {
    let dir = Fixture::new(&format!("shape-census-{name}"))
        .config(&committed_config())
        .git()
        .base_commit()
        .build();
    committed_policy_modules(&dir);
    dir
}

/// A fixture carrying the **committed** `batten.toml` and four tracked artifacts.
///
/// Four because the committed manifest ceiling is three: the fixture has to be
/// able to cross it, and a case that could not is the "wrong site" the column
/// exists to refuse. The names are this suite's own and mean nothing to the row —
/// what the ceiling counts is that the tracked set contains them.
fn manifest_committed_config_fixture(name: &str) -> PathBuf {
    let dir = Fixture::new(&format!("shape-census-{name}"))
        .config(&committed_config())
        .git()
        .base_commit()
        .build();
    committed_policy_modules(&dir);
    for artifact in MANIFEST_ARTIFACTS {
        fs::write(dir.join(artifact), "x\n").expect("write a census artifact");
    }
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "census artifacts"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// The artifacts a `Manifest` case names, tracked by the fixture above.
const MANIFEST_ARTIFACTS: &[&str] = &["one.txt", "two.txt", "three.txt", "four.txt"];

#[test]
fn the_committed_shape_rules_fire_on_every_banned_shape() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for case in SHAPE_CENSUS {
        let dir = match case.site {
            CensusSite::Checkout => root.clone(),
            CensusSite::Keyless => keyless_committed_config_fixture(case.rule),
            CensusSite::Manifest => manifest_committed_config_fixture(case.rule),
        };
        let payload = match &case.call {
            CensusCall::Command(command) => claude_payload(command),
            CensusCall::Verb(tool) => claude_verb_payload(tool),
            CensusCall::Spawn {
                tool,
                prompt,
                repeat,
            } => claude_spawn_payload(tool, &prompt.repeat(*repeat)),
        };
        let output = run_hook_in(&dir, "exit-code", &payload, false);
        assert_eq!(
            output.status.code(),
            Some(2),
            "the committed policy must still refuse {:?}",
            case.call.describe()
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The rule id is still the engine's own attribution and is still what
        // this census reads; CLOUD-1286 took the `Refused by` framing off it,
        // and the id now ENDS the line, which is why this is an `ends_with`
        // rather than a bare `contains` — the stricter read, and the one that
        // still tells a row that spoke from a row it merely mentioned.
        assert!(
            stderr.trim().ends_with(&case.rule),
            "{:?} must be refused by {}, got: {stderr}",
            case.call.describe(),
            case.rule
        );
    }
    // And the reads it must not refuse, from the same committed rows.
    //
    // `gh pr ready` is absent from this list and did not simply become a deny:
    // since CLOUD-312 it is *also* gated by the `ready-needs-receipts` row, so
    // against this checkout its verdict depends on whether the tree carries
    // valid receipts — a property of the world, not of the commit. Its shape row
    // is censused at the keyless site above, where the shape rows are evaluated
    // first and the refusal therefore names `ready-names-an-issue`; the receipt
    // row's own case is the one below this.
    // `mise exec -- cargo test` and `mise run test:cargo` are here because
    // `no-bare-cargo` is not a ban on the program (CLOUD-271): the row refuses
    // the ROUTE, and a row that closed the sanctioned route too would ban the
    // toolchain outright. `mise exec` is looked through, so this pair is the
    // only thing standing between `require_via` and exactly that.
    for command in [
        "gh pr view 42",
        "mise run land",
        "mise exec -- cargo test -p batten",
        "mise run test:cargo",
    ] {
        let output = run_hook_in(&root, "exit-code", &claude_payload(command), false);
        assert_eq!(
            output.status.code(),
            Some(0),
            "the committed policy must allow {command:?}"
        );
    }
}

#[test]
fn the_bare_cargo_refusal_names_the_sanctioned_route() {
    // A deny reaches the model as the entire explanation (CLOUD-122), and this
    // row's whole point is that the program is fine and the route is not — so a
    // refusal that did not name the route would read as "cargo is banned" and
    // send its reader looking for a way around rather than through.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = run_hook_in(
        &root,
        "exit-code",
        &claude_payload("cargo test -p batten"),
        false,
    );
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    // CLOUD-1286: the route is one hop from the row id on the line. The claim
    // this case makes is unchanged and still asserted end to end — a reader must
    // be able to reach "the program is fine, the route is not" rather than
    // reading the deny as "cargo is banned".
    assert!(stderr.contains("no-bare-cargo"), "got: {stderr}");
    let explained = batten_with(&root, &["policy", "explain", "no-bare-cargo"], &[]);
    assert_eq!(explained.status.code(), Some(0), "the row resolves");
    let text = String::from_utf8_lossy(&explained.stdout);
    assert!(text.contains("mise exec -- cargo"), "got: {text}");
    assert!(text.contains("mise run"), "got: {text}");
}

#[test]
fn every_committed_shape_row_is_exercised_by_the_census() {
    // The obligation, decided. The rows come from the authority through the real
    // loader — never from this file — so a row landing with no case fails here
    // rather than waiting for someone to remember the comment that used to state
    // it. The load-bearing mutation runs the other way: delete a case from
    // `SHAPE_CENSUS` and its row reads `unexercised`, which is what stops this
    // becoming a permanent green.
    let config = committed_config();
    let gaps = census_gaps(&config, SHAPE_CENSUS);
    assert!(
        gaps.is_empty(),
        "every committed shape row owes a census case:\n{}",
        render_gaps(&config, &gaps)
    );
}

/// The three ways the census can be wrong, over a config this repository's own
/// authority must never be.
///
/// A fixture rather than the committed config for the reason `rust.md` gives: the
/// failing condition cannot be created in the tree under test, so the decision is
/// extracted and exercised directly instead of asserting a conclusion over a
/// precondition nothing established.
const CENSUS_FIXTURE: &str = r#"version = 1

[[rule]]
id = "banned-outright"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "banned command"
reason = "do not"

[[rule]]
id = "banned-unless-keyed"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "keyed command"
requires_key = 'KEY-[0-9]+'
base = "origin/main"
reason = "name the issue"
"#;

/// One case per fixture row, at the site each row decides.
const FIXTURE_CENSUS: &[ShapeCase] = &[
    ShapeCase {
        call: CensusCall::Command("banned command now"),
        rule: "banned-outright",
        site: CensusSite::Checkout,
    },
    ShapeCase {
        call: CensusCall::Command("keyed command now"),
        rule: "banned-unless-keyed",
        site: CensusSite::Keyless,
    },
];

#[test]
fn the_census_check_refuses_a_row_with_no_case() {
    // A row with no case at all — the shape the committed config was in.
    assert_eq!(
        census_gaps(CENSUS_FIXTURE, &[]),
        vec![
            CensusGap {
                id: "banned-outright".to_owned(),
                class: "unexercised",
            },
            CensusGap {
                id: "banned-unless-keyed".to_owned(),
                class: "unexercised",
            },
        ]
    );

    // Both rows censused at the site the row itself decides: clean.
    assert_eq!(census_gaps(CENSUS_FIXTURE, FIXTURE_CENSUS), vec![]);
}

#[test]
fn the_census_check_refuses_a_keyed_row_censused_against_the_ambient_checkout() {
    // It would pass on a keyless branch and fail on a keyed one, which is the
    // verdict a census must never depend on — and the reading under which these
    // two rows looked uncensusable rather than uncensused.
    assert_eq!(
        census_gaps(
            CENSUS_FIXTURE,
            &[
                ShapeCase {
                    call: CensusCall::Command("banned command now"),
                    rule: "banned-outright",
                    site: CensusSite::Checkout,
                },
                ShapeCase {
                    call: CensusCall::Command("keyed command now"),
                    rule: "banned-unless-keyed",
                    site: CensusSite::Checkout,
                },
            ]
        ),
        vec![CensusGap {
            id: "banned-unless-keyed".to_owned(),
            class: "wrong-site",
        }]
    );
}

#[test]
fn the_census_check_refuses_a_case_naming_no_row() {
    // How deleting a row is caught even where its case would still pass on its
    // own: an id is all a case carries, so the case outlives the row visibly.
    let gaps = census_gaps(
        CENSUS_FIXTURE,
        &[
            ShapeCase {
                call: CensusCall::Command("banned command now"),
                rule: "banned-outright",
                site: CensusSite::Checkout,
            },
            ShapeCase {
                call: CensusCall::Command("keyed command now"),
                rule: "banned-unless-keyed",
                site: CensusSite::Keyless,
            },
            ShapeCase {
                call: CensusCall::Command("retired command now"),
                rule: "retired-row",
                site: CensusSite::Checkout,
            },
        ],
    );
    assert_eq!(
        gaps,
        vec![CensusGap {
            id: "retired-row".to_owned(),
            class: "names-no-row",
        }]
    );
    // Pointer-only: an id, a line the config does not declare, and a class.
    assert_eq!(
        render_gaps(CENSUS_FIXTURE, &gaps),
        "retired-row batten.toml:- names-no-row\n"
    );
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
/// SEVEN ROWS CAN REFUSE, AND ALL SEVEN ARE PRECONDITIONS — which is the
/// assertion, rather than a widening of it. `ready-needs-receipts` refuses until
/// `verify` has run; `ready-names-an-issue` is a `shape` row carrying
/// `requires_key`, which the rules file describes as narrowing the deny "from
/// *this command is banned* to *this command is banned unless the work is
/// keyed*"; `ready-needs-an-answered-review` (CLOUD-859) refuses until the
/// declared review command has been run for this head. None is the outright ban
/// this case exists to refuse, and which one fires first is a property of the
/// checkout.
///
/// The third row arrived after this case was written and reddened it here, on a
/// checkout whose first two preconditions were satisfied — the same class of
/// hidden dependency the paragraph below records for the branch NAME, one row
/// later. A precondition row added to the committed table belongs in this list
/// the day it lands.
///
/// Naming only the receipt row made that a hidden dependency on the branch
/// NAME. A branch carrying no `CLOUD-*` key trips the key row before the receipt
/// row is ever reached — and a keyless branch is not an oddity here, it is what
/// `mem:workflow/board-states` REQUIRES of a PR closing several keys, because
/// branch-name precedence otherwise moves one issue and strands the rest. So the
/// committed shape of a multi-key bundle reddened this case, on a branch that
/// was correct (CLOUD-661). The fix is to assert what the case means.
///
/// AND THE SAME OMISSION RECURRED, which is why the list is the fragile part
/// rather than the wording. `ready-needs-an-answered-review` landed as a third
/// precondition row and was not added here, so this case stayed green only while
/// one of the older two ALSO refused. It goes red the moment a branch satisfies
/// both — a `verify` receipt present and a key on the commits — which is the
/// state every branch reaches just before it readies, and precisely the state
/// this case is about. CI never saw it: a fresh checkout has no verify receipt,
/// so `ready-needs-receipts` fires first and masks the gap. Measured 2026-08-26.
/// A fourth precondition row will do this again; the durable form is to select
/// the rows by KIND rather than to name them, which needs a surface this test
/// does not have today.
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
            [
                "ready-needs-receipts",
                "ready-names-an-issue",
                "ready-needs-an-answered-review",
                // CLOUD-690's two tool-sourced siblings, each a receipt row over
                // one check, and the two module predicates that read what those
                // records found. The module rows belong here for the same reason
                // the receipt rows do: `review-unanswered` refuses until the
                // threads are answered and `review-absent` until a review exists,
                // so both are preconditions on the WORK and neither is a ban on
                // the command. Which one fires first is a property of the
                // checkout — measured, a head with a record carrying unresolved
                // threads reaches the module rather than any receipt row.
                "ready-needs-the-threads-answered",
                "ready-needs-a-review-to-exist",
                "review-unanswered",
                "review-absent",
            ]
            .iter()
            .any(|row| stderr.contains(row)),
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
    // CLOUD-1286: the redirect is one hop off the line, so what the channel must
    // carry is the row that refused — the handle that hop takes.
    assert!(
        stdout.contains("gh-pr-merge"),
        "the deny must name the row the fixture policy declares, got: {stdout}"
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
        // CLOUD-1286: the redirect is one hop away, so what every channel must
        // carry is the ROW that refused — the handle the hop takes. This case is
        // about the channel, and the hop itself is proven by
        // `every_hook_policy_table_deny_names_its_fix`.
        assert!(
            stdout.contains("gh-pr-merge"),
            "{harness}: the deny must name the row that refused, got: {stdout}"
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
            common::stderr(&output).contains("gh-pr-merge"),
            "{harness}: the decision travels on stderr here"
        );
    }
}

/// A policy declaring one protected path and **Claude Code's** write vocabulary.
///
/// The table a consumer actually writes, and the one CLOUD-779 measured: four
/// tool names, all of them one host's. Every other harness spells a write
/// differently, which is the whole defect — so this config is deliberately not
/// widened to name the others.
const PROTECTED_WRITE_CONFIG: &str = r#"version = 1
protected = ["guarded.txt"]

[[redirect]]
glob = "guarded.txt"
mutation = "change it through the surface that owns it"

[[verb]]
verb = "rm"
effect = "destructive"
redirect = "restore it with `git checkout --`"

[[verb]]
verb = "Write"
effect = "write"
redirect = "write through the surface that owns the file"

[[verb]]
verb = "Edit"
effect = "write"
redirect = "write through the surface that owns the file"

[[verb]]
verb = "MultiEdit"
effect = "write"
redirect = "write through the surface that owns the file"

[[verb]]
verb = "NotebookEdit"
effect = "write"
redirect = "write through the surface that owns the file"
"#;

/// Whether this host's deny travels in a JSON body or on the exit code.
///
/// The channel matrix CLOUD-40 owns, restated here as data so the write matrix
/// below asserts one verdict per harness rather than one per channel.
fn denied(harness: &str, output: &Output) -> bool {
    match harness {
        "claude-code" => {
            String::from_utf8_lossy(&output.stdout).contains("\"permissionDecision\":\"deny\"")
        }
        "cursor" => String::from_utf8_lossy(&output.stdout).contains("\"permission\":\"deny\""),
        _ => output.status.code() == Some(2),
    }
}

/// THE PINNED REGRESSION (CLOUD-779), over the compiled binary.
///
/// One protected path, one policy, and a write-shaped call from every harness in
/// `Harness::ALL` **in that host's own vocabulary**. Measured on `main`
/// 2026-08-20: Cursor's `write`, Gemini's `WriteFile` and Copilot's
/// `StrReplaceEditor` all reached `guarded.txt` and were **allowed**, because the
/// gate asked a consumer's `[[verb]]` table — Claude Code's names — to recognise
/// spellings it had never been given. Not degraded: absent, and silent, because a
/// rule that matches nothing is indistinguishable from a rule with nothing to
/// match.
#[test]
fn a_protected_write_is_refused_on_every_harness_in_its_own_vocabulary() {
    let dir = repo_with_config("protected-write-matrix", PROTECTED_WRITE_CONFIG);
    for (harness, stem) in [
        ("claude-code", "claude-code-write"),
        ("cursor", "cursor-write"),
        ("copilot-cli", "copilot-cli-write"),
        ("gemini-cli", "gemini-cli-write"),
        ("codex-cli", "codex-cli-write"),
    ] {
        let output = run_hook_in(&dir, harness, &host_fixture(stem), false);
        assert!(
            denied(harness, &output),
            "{harness}: a write to a protected path was not refused — \
             stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            common::stderr(&output)
        );
    }
    // `exit-code` is a contract rather than a host, so it has no checked-in
    // fixture: a caller composing the envelope by hand states the normalized
    // shape, and that shape is what it is asserted against.
    let neutral = run_hook_in(
        &dir,
        "exit-code",
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"guarded.txt"}}"#,
        false,
    );
    assert_eq!(
        neutral.status.code(),
        Some(2),
        "the neutral contract denies through the exit code alone"
    );
}

#[test]
fn a_cursor_shell_call_reaches_the_same_protected_gate() {
    // The other half of CLOUD-779's routing: `beforeShellExecution` carries the
    // operand at top level and no `tool_name`, so it names no write target
    // through the tool and every target it has lives in the command text. It is
    // `Operation::Execute`, and the SAME gate judges it — which is what stops the
    // shell path and the tool path from being two implementations that drift.
    let dir = repo_with_config("protected-write-cursor-shell", PROTECTED_WRITE_CONFIG);
    let output = run_hook_in(&dir, "cursor", &host_fixture("cursor-shell-write"), false);
    assert!(
        denied("cursor", &output),
        "got stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("guarded.txt"),
        "the refusal names the path it refused"
    );
}

#[test]
fn a_read_of_a_protected_path_is_not_refused_on_any_harness() {
    // The false positive that would get the gate switched off, asserted across
    // the matrix rather than on one host: `Read` and `Write` both carry
    // `file_path`, and what keeps them apart is each host's own `write_tools`
    // table. A gate keyed on "the payload names a protected path" would refuse
    // reading the policy file everywhere at once.
    let dir = repo_with_config("protected-read-matrix", PROTECTED_WRITE_CONFIG);
    for harness in ["claude-code", "cursor", "gemini-cli", "codex-cli"] {
        let output = run_hook_in(
            &dir,
            harness,
            r#"{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"guarded.txt"}}"#,
            false,
        );
        assert!(
            !denied(harness, &output),
            "{harness}: reading a protected path must not be refused"
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
        let output = run_hook(
            "hook-allows-reads",
            "claude-code",
            &claude_payload(command),
            false,
        );
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
    let output = run_hook(
        "hook-undecodable-payload",
        "claude-code",
        "not json at all",
        false,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}

#[test]
fn hook_honours_the_bypass_hatch() {
    // THE AUTHORITY HAS TO REFUSE THIS CALL, or the case says nothing (CLOUD-1135).
    // It used to drive `run_hook`, which now loads an authority declaring no
    // rules — an allow the bypass could not have caused. `gh-pr-merge` is a row
    // in the same fixture `hook_exit_code_harness_denies_with_exit_2` uses to
    // assert the deny this suppresses, so the two are the same call twice.
    let dir = repo_with_gh_policy("bypass-over-a-real-deny");
    let output = run_hook_in(&dir, "claude-code", &claude_payload("gh pr merge 42"), true);
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
    assert!(stderr.contains("gh-pr-merge"), "got: {stderr}");
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
    // One fixture for the whole matrix: `Fixture::new` wipes, so building it
    // inside the loops would be 24 rebuilds of the same two bytes.
    let dir = repo_with_config("no-failure-path-denies", "version = 1\n");
    for harness in harnesses() {
        for (name, payload) in cases {
            let output = run_hook_in(&dir, harness, payload, false);
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
///
/// `cfg(unix)` because every caller is, and an ungated helper whose callers all
/// vanish is dead code on the other target — invisible on Linux, and the first
/// thing `cross-check` reports for the Windows triple (CLOUD-397).
#[cfg(unix)]
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
                // `quiet` is mise's "the tool says nothing of its own", which is
                // exactly the claim below. The record CLOUD-429 made the default
                // is Batten's output, so asserting "no output of its own" against
                // it would be asserting that the default does not exist.
                "--style",
                "quiet",
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
        &[
            "exec",
            "--style",
            "quiet",
            "--",
            script.to_str().expect("utf-8"),
        ],
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
            "--tee",
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
    // Batten's own record is on stderr now (CLOUD-429), so "nothing moved the
    // verbosity rung" is asserted as the ABSENCE of a rung's effect rather than
    // as an empty stream: the record is there, and nothing else is.
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.lines().all(|line| line.starts_with("exec: ")),
        "none of the child's flags may move Batten's own verbosity rung: {said}"
    );
}

#[cfg(unix)]
#[test]
fn exec_inherits_both_child_streams_unchanged() {
    // RE-POINTED AT `--tee`, NOT DELETED (CLOUD-429). The property — asking for
    // the child's bytes gets exactly the child's bytes, on both streams, with
    // nothing of Batten's interleaved — is the one the module docs call the test
    // that governs this design. What changed is that it must now be asked for;
    // deleting the case would have retired the property along with the default.
    let script = child_script("exec-streams", "echo out; echo err >&2");
    let (output, _) = exec_cmd(
        "exec-streams-home",
        &[
            "exec",
            "--tee",
            "--style",
            "quiet",
            "--",
            script.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "err\n");
}

#[cfg(unix)]
#[test]
fn the_default_charges_the_caller_a_record_rather_than_the_childs_bytes() {
    // CLOUD-429's headline. The child says something distinctive on each stream;
    // neither utterance may appear anywhere in what Batten emitted, and the
    // record that replaces them must name the bytes without carrying them.
    let script = child_script(
        "exec-tokenkind",
        "echo Q7v-stdout-x9nK; echo Q7v-stderr-x9nK >&2",
    );
    let (output, home) = exec_cmd(
        "exec-tokenkind-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert!(output.status.success());
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !said.contains("Q7v-stdout-x9nK") && !said.contains("Q7v-stderr-x9nK"),
        "the default emitted the child's own bytes: {said}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout belongs to the wrapped command, and the record is not the child's"
    );
    assert!(
        said.contains("exec: exit 0") && said.contains("exec: stdout 16 byte(s) stdout:"),
        "the record must name the bytes it did not print: {said}"
    );
    // And the bytes are still there to be read, which is what makes the record a
    // pointer rather than a loss.
    assert_eq!(captures_in(&home).len(), 2);
}

#[cfg(unix)]
#[test]
fn silent_suppresses_both_speakers_and_quiet_only_battens() {
    // mise's `style_only()` distinction, which the issue is explicit must not be
    // collapsed into one key: suppressing the TOOL's metadata is a different
    // question from choosing a stream style, and `silent` answers both.
    let script = child_script("exec-suppression", "echo Q7v-said-x9nK");

    let (quiet, _) = exec_cmd(
        "exec-quiet-home",
        &[
            "exec",
            "--tee",
            "--style",
            "quiet",
            "--",
            script.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(String::from_utf8_lossy(&quiet.stdout), "Q7v-said-x9nK\n");
    assert!(
        quiet.stderr.is_empty(),
        "quiet silences Batten, not the child"
    );

    let (silent, _) = exec_cmd(
        "exec-silent-home",
        &[
            "exec",
            "--tee",
            "--style",
            "silent",
            "--",
            script.to_str().expect("utf-8"),
        ],
    );
    assert!(
        silent.stdout.is_empty() && silent.stderr.is_empty(),
        "silent silences everyone"
    );
}

#[cfg(unix)]
#[test]
fn the_prefixed_styles_dress_every_line_including_across_chunks() {
    // A pipe splits wherever it likes, so the prefix has to be a function of
    // where the last byte left the line rather than of where a read happened to
    // end. Two lines is the smallest case that can tell those apart.
    let script = child_script("exec-prefix", "printf 'one\ntwo\n'");
    let program = script.to_str().expect("utf-8").to_owned();
    for style in ["prefix", "replacing", "timed"] {
        let (output, _) = exec_cmd(
            &format!("exec-prefix-{style}-home"),
            &["exec", "--tee", "--style", style, "--", &program],
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("{program}| one\n{program}| two\n"),
            "`{style}` must prefix every line"
        );
    }
}

#[cfg(unix)]
#[test]
fn keep_order_lays_each_stream_down_whole() {
    // The one style that cannot render as the bytes arrive: its claim is that a
    // stream appears WHOLE, so an interleaving is the thing it exists to refuse.
    let script = child_script(
        "exec-keep-order",
        "echo out-1; echo err-1 >&2; echo out-2; echo err-2 >&2",
    );
    let (output, _) = exec_cmd(
        "exec-keep-order-home",
        &[
            "exec",
            "--tee",
            "--style",
            "keep-order",
            "--",
            script.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out-1\nout-2\n");
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with("err-1\nerr-2\n"),
        "stderr whole and first, before Batten's own record"
    );
}

#[cfg(unix)]
#[test]
fn every_format_is_byte_stable_over_the_same_run() {
    // §6, asserted as REPETITION rather than as a shape: a record carrying a
    // clock or a duration would pass any assertion about its fields and still
    // print differently twice. `timed` is in the sweep on purpose — it is the
    // style whose name promises the thing byte-stability forbids.
    let script = child_script("exec-stable", "echo Q7v-out-x9nK; echo Q7v-err-x9nK >&2");
    let program = script.to_str().expect("utf-8").to_owned();
    for format in ["human", "json", "jsonl"] {
        for style in ["interleave", "timed", "keep-order"] {
            let mut seen = Vec::new();
            for run in 0..2 {
                let (output, _) = exec_cmd(
                    &format!("exec-stable-{format}-{style}-{run}-home"),
                    &["exec", "--format", format, "--style", style, "--", &program],
                );
                seen.push(String::from_utf8_lossy(&output.stderr).into_owned());
            }
            assert_eq!(
                seen[0], seen[1],
                "`--format {format} --style {style}` is not byte-stable"
            );
            assert!(
                !seen[0].contains("Q7v-out-x9nK") && !seen[0].contains("Q7v-err-x9nK"),
                "and it must still carry no child bytes: {}",
                seen[0]
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn the_record_survives_a_child_that_failed() {
    // The passthrough returns early on a non-zero code, so the record has to be
    // emitted before it — a caller debugging a failure is exactly the caller who
    // needs the handle, and losing it there would make the default useless in
    // the one case it matters most.
    let script = child_script("exec-record-fail", "echo nope >&2; exit 7");
    let (output, _) = exec_cmd(
        "exec-record-fail-home",
        &["exec", "--", script.to_str().expect("utf-8")],
    );
    assert_eq!(output.status.code(), Some(7));
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("exec: exit 7"), "got {said}");
    assert!(!said.contains("nope"), "and still no child bytes: {said}");
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
        &[
            "exec",
            "--tee",
            "--style",
            "quiet",
            "--",
            script.to_str().expect("utf-8"),
        ],
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
    // Named by INDEX, not by `body.len()`: "echo one" and "echo two" are both
    // eight bytes, so the old name put both scripts in one fixture directory
    // that `child_script` wipes on entry. Sequentially it happened to work; it is
    // a latent collision of exactly the kind CLOUD-412 was chasing.
    for (index, body) in ["echo one", "echo two"].iter().enumerate() {
        let script = child_script(&format!("capture-differs-{index}"), body);
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
    // `--tee --style quiet` keeps these cases about the OUTPUT PREDICATE: the
    // child's bytes on the caller's streams, and nothing of Batten's except the
    // refusal a match produces. CLOUD-429's record would otherwise be the only
    // thing on stderr in the clean case and a second thing in the matched one.
    batten()
        .args([
            "exec", "--tee", "--style", "quiet", "--", "sh", "-c", script,
        ])
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
        .args(["exec", "--tee", "--", "sh", "-c", "echo fine"])
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

/// The census fixture's repository, built alone.
///
/// `config epoch` needs readable tracked paths, `receipt status` needs a repo with
/// `origin/main`, and `check`/`enforce`/`config *` need an authority. One fixture
/// satisfying all of them beats a per-verb table that would drift.
/// The committed config the purity census judges against.
///
/// Lifted out of [`census_fixture`] rather than inlined: the fixture's job is
/// to supply each data-emitting verb its MINIMUM INPUT, and that list grows by
/// a table every time a verb with one is added — which pushed the function past
/// the line ceiling. The reasoning for each table stays here, beside the table.
const CENSUS_CONFIG: &str = concat!(
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
    // `commit check`'s minimum input: a repository declaring no
    // convention is a usage error, never an empty answer.
    "[commit]\n",
    "subject_pattern = \"^(feat|fix|chore): .+\"\n",
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
    // `policy hooks`' minimum input, and the fifth verb to need one
    // (CLOUD-417): a repository pointing at no session has nothing to
    // measure, so it is a usage error rather than a `0` it did not earn.
    // The file itself is written below — a declared path with nothing
    // behind it is could-not-look, which is that same error.
    "[transcript]\n",
    "path = \".session.jsonl\"\n",
);

/// The session the census points `policy hooks` at.
///
/// One assistant turn and nothing else: the census is about the OUTPUT CONTRACT,
/// so the reading this produces is the empty one — zero producers, zero repeats
/// — and a document is still emitted, which is exactly the "including when the
/// answer is empty" half the purity assertion names.
const CENSUS_SESSION: &str = "{\"type\":\"assistant\",\"sessionId\":\"s-1\",\
                              \"message\":{\"role\":\"assistant\",\"content\":[]}}\n";

/// The repository half of [`census_fixture`], extracted for length and nothing
/// else: every verb with a minimum input adds a file or a table to this chain,
/// and it reached the function ceiling. The shape is unchanged.
///
/// It composes with [`CENSUS_CONFIG`] rather than replacing it: the const holds
/// the config TEXT each verb needs declared, and this holds the tracked FILES and
/// the two commits a diff-shaped verb needs. Two extractions because they came
/// out for two different reasons, and folding them would put a `[defects]` table
/// beside a `base_commit()`.
fn census_repo(root: &Path) -> PathBuf {
    Fixture::at(root.join("repo"))
        .config(CENSUS_CONFIG)
        // `ready lint` and `claim check`'s minimum input, and the fourth verb
        // family to need one (CLOUD-1100). The Ready grammar is the CONSUMER's
        // vocabulary, so a repository that declares no `[[pattern]]` rows has no
        // grammar and both verbs say so by id — the right answer, and not the one
        // this census is about. Read from the committed table rather than re-typed
        // here, so a fixture cannot drift from the expressions it exercises.
        .config_append(&declared_patterns())
        .file("AGENTS.md", "instructions\n")
        // `lint brief`'s minimum input, the third verb to need one. Named by
        // `CENSUS_POSITIONALS` rather than by this call site, so the argv and the
        // file it points at cannot drift apart.
        .file("census-brief.md", &census_brief())
        // The session `policy hooks` measures (CLOUD-417).
        .file(".session.jsonl", CENSUS_SESSION)
        // A published schema for `config deprecations` to use as its baseline.
        // Deliberately a SUBSET of the real surface — every key here still
        // exists — so the census exercises the CLEAN arm, which is what
        // `no_progress_reaches_stderr_when_it_is_not_a_terminal` needs and what
        // makes the `-J` document the interesting case (`lint brief`'s reason).
        .file(
            "schema/batten.schema.json",
            "{\n  \"properties\": {\n    \"version\": {}\n  }\n}\n",
        )
        // `claim carry`'s minimum input, and the first that is a property of the
        // DIFF rather than of a file: the verb judges this branch against its merge
        // base, so the fixture has to give it both sides. The base maps one repo;
        // the work commit below appends a row for that same repo with only the sha
        // changed, which is the whole of what a carry may be. A fixture writing
        // only the base would make the census assert about `nothing-carried`, and
        // one writing only the head about `no-prior-row` — both refusals, and both
        // the wrong thing for a census about the output contract.
        .file(CENSUS_CARRY_TABLE, CENSUS_CARRY_BASE)
        .git()
        .base_commit()
        .file(
            CENSUS_CARRY_TABLE,
            &format!("{CENSUS_CARRY_BASE}census/action@bbb\tMIT\tCopyright (c) 2026 Census\n"),
        )
        .work_commit()
        .build()
}

/// A git repo with a committed authority, isolated state dir, and a work commit —
/// enough for every `data_channel` verb to have something real to answer about.
///
/// `config epoch` needs readable tracked paths, `receipt status` needs a repo with
/// `origin/main`, and `check`/`enforce`/`config *` need an authority. One fixture
/// satisfying all of them beats a per-verb table that would drift.
fn census_fixture(name: &str) -> (PathBuf, PathBuf, String) {
    // Shaped like `receipt_fixture`, but with a config every data-emitting verb
    // can actually answer from. `policy budget` is the reason it diverged: a
    // budget verb whose config declares no budget measured nothing, and it
    // refuses (exit 1) rather than reporting a `0` it did not earn — so a
    // fixture carrying `version = 1` alone would make the census assert about a
    // usage error instead of about a document. The census is about the output
    // contract; supplying each verb's minimum input is the fixture's job, the
    // same way `census_argv` supplies `receipt status` its positional.
    let root = scratch(name);
    let repo = census_repo(&root);
    let home = Fixture::at(root.join("home")).build();
    // `capture show` is the fourth verb with a minimum input, and the first whose
    // input cannot be a literal: a handle carries a content digest, so the fixture
    // has to MAKE one rather than name one. Seeded through `exec --capture-only`
    // — the same path a caller uses — so the census asserts about a real capture
    // and not about a file this test hand-placed in the store.
    let seeded = batten()
        .args([
            "exec",
            "--capture-only",
            "--",
            "sh",
            "-c",
            "printf 'census\n'",
        ])
        .current_dir(&repo)
        .state_home(&home)
        .output()
        .expect("seed a capture");
    assert_eq!(
        seeded.status.code(),
        Some(0),
        "the census capture was not made"
    );
    let listed = batten()
        .args(["capture", "list", "--stream", "stdout"])
        .current_dir(&repo)
        .state_home(&home)
        .output()
        .expect("list the census capture");
    let handle = stdout(&listed)
        .split_whitespace()
        .next()
        .expect("the seeded capture is listed")
        .to_owned();

    // A RESPONSE capture, which `exec` cannot make and `capture find`'s clean run
    // needs. Seeded by driving the post-tool event, so the ENGINE writes it —
    // placing a blob and a log line here by hand would build the fixture to the
    // shape the reader expects and prove nothing about what the writer emits,
    // which is the defect CLOUD-1121 measured twice while landing this verb.
    //
    // The MCP content-block shape is the one a host actually hands over, and it
    // is the only one `decode_response` reads for a tool call: a bare result
    // object is recorded as `response-shape-unreadable` with no digest, and the
    // capture then silently does not exist.
    // `status` joins `id` and `description` for `claim check`, whose entry
    // contract is the two fields EVERY issue carries (CLOUD-526) — a payload
    // without it is a usage error rather than an empty answer, which would make
    // the census assert about a refusal instead of about a document.
    // A body that PASSES `ready lint`, not merely one it can parse. The census
    // asserts a clean piped run prints nothing on stderr, and a fixture whose
    // block is refused would make that case assert about a finding instead of
    // about the channel. The minimum a refined leaf needs is the canonical
    // opener plus one clause label — the gate document forbids restating all
    // eight, so "only what is present" plus a floor is the whole predicate.
    let document = serde_json::json!({
        "id": CENSUS_ISSUE_KEY,
        "status": "Todo",
        "description": "**Refinement — Ready**\n\n* **Source of truth (§1).** the census fixture\n",
    });
    let envelope = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "census",
        "tool_name": "mcp__census__get_issue",
        "tool_input": {},
        "tool_response": [{ "type": "text", "text": document.to_string() }],
    })
    .to_string();
    let mut hook = batten();
    let spawned = hook
        .args(["hook", "--harness", "claude-code"])
        .current_dir(&repo)
        .state_home(&home)
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawned.spawn().expect("spawn the census post-tool hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(envelope.as_bytes())
        .expect("write the census response");
    let recorded = child
        .wait_with_output()
        .expect("record the census response");
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "the census response capture was not recorded"
    );

    (repo, home, handle)
}

/// The stand-in `CENSUS_POSITIONALS` uses for a value only the fixture can know.
///
/// A sentinel rather than a second table: exactly one verb takes an input that is
/// computed rather than named, and giving the table two shapes for one column
/// would cost more than the single substitution below.
const CENSUS_SEEDED_HANDLE: &str = "<seeded-capture-handle>";

/// The licence table `claim carry` judges, read from the engine rather than
/// re-typed — a census that named its own path would pass over a verb reading a
/// different one.
const CENSUS_CARRY_TABLE: &str = batten::carry::TABLE;

/// The base side of the census fixture's carry: one mapped repo, so the head's
/// appended row has a prior verdict to carry forward.
const CENSUS_CARRY_BASE: &str = "census/action@aaa\tMIT\tCopyright (c) 2026 Census\n";

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
const CENSUS_POSITIONALS: &[(&str, &[&str])] = &[
    // An empty but resolvable range: the clean answer is `[]`, which is a
    // document like any other, and it needs no commit the fixture did not make.
    ("attribution check", &["HEAD..HEAD"]),
    // The same empty-but-resolvable range, for the same reason (CLOUD-701).
    ("commit check", &["HEAD..HEAD"]),
    // A valid check name; `receipt status` answers `missing` for it, which is a
    // document like any other.
    ("receipt status", &["verify"]),
    // `HEAD`, where the fixture commits a published schema whose keys all still
    // exist — so the census asserts about a CLEAN run. The could-not-look arm
    // emits an ::error:: line by design, which is the one thing a data-channel
    // verb's stderr may not carry unprompted; that arm is covered by
    // `the_removal_gate_reports_a_verdict_or_refuses_to_guess` instead.
    ("config deprecations", &["HEAD"]),
    // A brief that satisfies the schema, so the census asserts about a CLEAN run
    // — which is what `no_progress_reaches_stderr_when_it_is_not_a_terminal`
    // needs, and what makes the empty `-J` document the interesting case.
    ("lint brief", &["census-brief.md"]),
    // Substituted at argv time — see `CENSUS_SEEDED_HANDLE`.
    ("capture show", &[CENSUS_SEEDED_HANDLE]),
    // A class this BINARY vendors (CLOUD-1050), so the census resolves it in a
    // fixture that declares no `[[verdict]]` row of its own — which is the same
    // reason the vendored half exists at all. A consumer token here would make
    // this census depend on the fixture's authority carrying a row, and the
    // fixture's authority is `batten init`'s output.
    ("policy explain", &["path write refused"]),
    // The key the fixture's seeded RESPONSE capture carries. `capture find` is
    // the first verb whose clean run needs a capture of a kind `exec` cannot
    // make: a `Stream::Response`, which only the post-tool event writes.
    ("capture find", &[CENSUS_ISSUE_KEY]),
];

/// The required flags each data-emitting verb needs to reach its document.
///
/// A second table rather than a wider first one, and the split is the same one
/// `CENSUS_POSITIONALS` already documents: a positional is a VALUE the verb
/// consumes, a required flag is a SELECTOR it will not act without. `capture
/// find` is the first data-channel verb to carry one, in the progression this
/// census keeps recording — `receipt status` was the first with a positional at
/// all, `lint brief` the first whose positional is a path the fixture must
/// write, `capture show` the first whose value cannot be a literal.
///
/// **The flag stays required rather than being defaulted so this table could
/// stay empty.** The default that suggests itself for `--tool` is "any tool",
/// which is precisely the reading that resolves an issue key out of whatever
/// response happened to carry it — a search result, a comment, an unrelated tool
/// echoing the id. Naming the tool is what makes the answer a statement about a
/// read rather than about a coincidence, so the census grows a column instead.
const CENSUS_FLAGS: &[(&str, &[&str])] = &[
    // The tool whose response the census fixture seeds — see `census_fixture`,
    // which drives the post-tool event so the capture is written by the ENGINE
    // rather than placed in the store by this test.
    ("capture find", &["--tool", "get_issue"]),
    // The two board verbs read a payload, and `--issue` is how they read one
    // WITHOUT it entering context — the whole of CLOUD-1121. Naming the key here
    // rather than piping the document is also what exercises the resolve path in
    // the census: a verb handed its bytes on stdin would prove nothing about the
    // store the row exists to spend.
    ("ready lint", &["--issue", CENSUS_ISSUE_KEY]),
    // The roster `checks green` decides against (CLOUD-1143). Both stay required
    // rather than defaulted, for the reason this table's header gives: the
    // default that suggests itself for either is the EMPTY set, and an empty
    // roster makes every check unrequired while an empty answered-set makes every
    // conclusion an answer. Both are the false green the verb exists to stop, so
    // the census grows a row instead of the verb growing a dangerous default.
    //
    // The census supplies a reading of nothing on stdin, so the document it emits
    // is the not-yet-answered one — which is the point: the contract is that a
    // data channel emits unconditionally, including when the answer is empty.
    (
        "checks green",
        &["--required", "ci", "--answered", "success"],
    ),
    // `--bypass-sequence` because the census is about the OUTPUT CONTRACT, not
    // about the refinement-sequence predicate: those rules read this clone's own
    // receipt store, which a scratch fixture has no honest way to populate — a
    // hand-written baseline would be the fixture agreeing with the reader while
    // neither agrees with the writer, which is the class CLOUD-1121 measured.
    // `crates/batten/tests/it/claim.rs` is where that predicate is exercised, over
    // a store the engine itself minted.
    (
        "claim check",
        &["--issue", CENSUS_ISSUE_KEY, "--bypass-sequence"],
    ),
];

/// The issue key the census fixture's seeded response carries.
///
/// A literal here and in `CENSUS_POSITIONALS`, deliberately: unlike a capture
/// HANDLE, which is a content digest the fixture can only compute, a key is
/// something the fixture chooses — so naming it twice is a pair a reader can
/// check rather than a value only the code knows.
const CENSUS_ISSUE_KEY: &str = "CLOUD-CENSUS";

/// A brief satisfying every row of `brief::SCHEMA`, for the census fixture.
///
/// Built from the schema rather than hand-typed, so a new required section cannot
/// leave this fixture quietly failing the verb it is meant to exercise cleanly.
fn census_brief() -> String {
    let mut text = String::new();
    for section in batten::brief::SCHEMA {
        // Infallible into a String; discarded like `render.rs` does.
        let _ = write!(text, "## {}\n\ncensus fixture\n\n", section.labels[0]);
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
fn census_argv(decl: &batten::surface::CommandDecl, seeded: &str) -> Vec<String> {
    let positionals: Vec<&batten::surface::FlagDecl> =
        decl.flags.iter().filter(|flag| flag.positional).collect();
    let mut argv: Vec<String> = decl.path.split(' ').map(ToOwned::to_owned).collect();
    let found = CENSUS_POSITIONALS
        .iter()
        .find(|(path, _)| *path == decl.path)
        .map(|(_, values)| *values);
    let values = match (positionals.is_empty(), found) {
        (true, None) => &[][..],
        (false, Some(values)) => values,
        (false, None) => panic!(
            "{}: takes {} positional(s) but CENSUS_POSITIONALS names none — add a row (and \
             whatever file it needs to census_fixture)",
            decl.path,
            positionals.len()
        ),
        (true, Some(_)) => panic!(
            "{}: CENSUS_POSITIONALS names values for a verb that takes no positional — drop \
             the stale row",
            decl.path
        ),
    };
    // ARITY IS CHECKED, which is what the predecessor's "at most one positional"
    // guard was standing in for (CLOUD-1260). That assertion did not generalise:
    // it refused a THIRD verb shape outright rather than describing what a row
    // owes, so the first multi-positional verb failed the census instead of being
    // served by it. Comparing the two counts says the same thing and keeps
    // working — a row short of a value is as loud as no row at all, where a
    // silently short argv would have run the verb's usage-error arm and the
    // census would have asserted about a refusal.
    assert_eq!(
        positionals.len(),
        values.len(),
        "{}: takes {} positional(s) and CENSUS_POSITIONALS names {} value(s)",
        decl.path,
        positionals.len(),
        values.len()
    );
    for value in values {
        argv.push(if *value == CENSUS_SEEDED_HANDLE {
            seeded.to_owned()
        } else {
            (*value).to_owned()
        });
    }
    if let Some((_, flags)) = CENSUS_FLAGS.iter().find(|(path, _)| *path == decl.path) {
        argv.extend(flags.iter().map(|flag| (*flag).to_owned()));
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
    let (repo, home, seeded) = census_fixture("census-purity");
    for decl in data_channel_verbs() {
        let owned = census_argv(decl, &seeded);
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
    let (repo, home, seeded) = census_fixture("census-stable");
    for decl in data_channel_verbs() {
        let owned = census_argv(decl, &seeded);
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
    let (repo, home, seeded) = census_fixture("census-ladder");
    for decl in data_channel_verbs() {
        let base: Vec<String> = census_argv(decl, &seeded);
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
    let (repo, home, seeded) = census_fixture("census-progress");
    for decl in data_channel_verbs() {
        let base: Vec<String> = census_argv(decl, &seeded);
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
    let (repo, home, _seeded) = census_fixture("census-receipt");
    let output = receipt_cmd(&repo, &home, &["receipt", "status", "verify", "-J"]);
    // Missing receipt: a policy verdict, and the document is still emitted.
    assert_eq!(output.status.code(), Some(2));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("receipt status -J is JSON");
    assert_eq!(document["check"], serde_json::json!("verify"));
    assert_eq!(document["verdict"], serde_json::json!("missing"));
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    // `subject` carries the git fact judged, and `key` names which fact that is
    // (CLOUD-741). It was `head`, which stopped being true the moment
    // `--key branch` existed: under that keying the same field holds a branch
    // name. A field whose meaning changes with a flag is unparseable in exactly
    // the way this document exists to prevent, so the keying is named beside it
    // rather than left for a consumer to infer from the value's shape.
    assert_eq!(document["key"], serde_json::json!("head"));
    assert_eq!(document["subject"], serde_json::json!(head));
    assert!(
        document.get("head").is_none(),
        "the ambiguous field is gone, not merely joined by a clearer one: {document}"
    );

    // The same tokens the human channel concatenates, so the two renderings
    // cannot drift apart.
    let (_, pointer) = receipt_status(&repo, &home, "verify");
    assert_eq!(pointer.trim(), format!("verify {head} missing"));
}

#[test]
fn receipt_status_json_names_the_branch_it_judged_under_branch_keying() {
    // The other half of the same contract: `subject` earns its name only if it
    // actually changes with the keying. Without this row the rename would be
    // cosmetic and a reader could still assume the field is always a SHA.
    let (repo, home, _seeded) = census_fixture("census-receipt-branch");
    let output = receipt_cmd(
        &repo,
        &home,
        &["receipt", "status", "claim", "--key", "branch", "-J"],
    );
    assert_eq!(output.status.code(), Some(2));
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("receipt status -J is JSON");
    assert_eq!(document["key"], serde_json::json!("branch"));
    assert_eq!(document["verdict"], serde_json::json!("missing"));
    let branch = git_in(&repo, &["symbolic-ref", "--quiet", "--short", "HEAD"]);
    assert_eq!(
        document["subject"],
        serde_json::json!(branch),
        "the subject is the branch under branch keying, never a commit"
    );
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

/// Whether the receipt store holds an agent-context statement.
fn has_agent_statement(store: &std::path::Path) -> bool {
    fs::read_dir(store)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .path()
                .to_string_lossy()
                .ends_with(".agent-context.json")
        })
}

/// A repository with `[transcript]` configured and no file at that path.
fn transcript_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = scratch(name);
    let _ = fs::remove_dir_all(&root);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n[transcript]\npath = \"session.jsonl\"\n")
        .git()
        .base_commit()
        .work_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// A configured transcript that is not there is REPORTED, and the receipt is
/// still recorded (CLOUD-819).
///
/// changed: this case asserted the opposite — exit 1, "a usage error, not a
/// verdict" — and it was a deliberate assertion, so it is rewritten here rather
/// than deleted. What it was right about is kept: no statement is written, since
/// "nothing was stated" and "nothing was in effect" are different claims. What
/// it was wrong about is the exit code. `mise-tasks/linear-check.sh` ends with
/// this command under `set -e`, so the refusal stopped `verify` — and therefore
/// `land` — on a gate that had already measured linearity correctly, in exactly
/// the three states `batten.toml` calls ordinary: a fresh checkout, a non-Claude
/// host, and a gate run by hand outside a turn.
#[test]
fn a_configured_but_absent_transcript_records_the_receipt_and_reports() {
    let (repo, home) = transcript_fixture("receipt-agent-absent");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);

    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(
        record.status.code(),
        Some(0),
        "could-not-look about the environment is not a refusal about this commit"
    );

    // The notice reaches stderr. This is the row that stops the change becoming
    // a silent pass: an exit 0 with no report would make a missing seam
    // invisible, which is the state that took a session to diagnose.
    let stderr = String::from_utf8_lossy(&record.stderr);
    assert!(
        stderr.contains(batten::transcript::ABSENT_NOTICE),
        "the absent notice is emitted, got: {stderr}"
    );

    // The receipt this verb exists to write is on disk and reads back valid —
    // the half the old refusal already performed before exiting 1.
    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 0, "the receipt was recorded, not merely attempted");
    assert_eq!(line, format!("verify {head} valid\n"));

    let store = fixture_state_dir(&repo, &home).join("receipts");
    assert!(
        !has_agent_statement(&store),
        "no statement is written when there is nothing to state"
    );
}

/// A transcript whose line does not decode is could-not-look too, and it says
/// WHICH line (CLOUD-819's 2026-08-24 pressure-test amendment).
///
/// Absent is a missing file; this is `transcript::parse` refusing the stream.
/// Both are properties of the environment rather than of the commit, so both
/// report and record — but this one carries a `<label>:<line>` pointer, because
/// a decode failure is a seam somebody can repair and a missing file is not.
#[test]
fn a_malformed_transcript_records_the_receipt_and_points_at_the_line() {
    let (repo, home) = transcript_fixture("receipt-agent-malformed");
    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    // Line 1 decodes, line 2 does not: a torn append, which is the shape
    // measured in the field rather than an invented one.
    fs::write(
        repo.join("session.jsonl"),
        "{\"type\":\"user\"}\n{\"type\":\"assist\
         ",
    )
    .expect("write the malformed transcript");

    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(
        record.status.code(),
        Some(0),
        "a transcript that cannot be decoded is not a verdict about this commit"
    );

    let stderr = String::from_utf8_lossy(&record.stderr);
    assert!(
        stderr.contains(batten::transcript::UNREADABLE_NOTICE),
        "the unreadable notice is emitted, got: {stderr}"
    );
    assert!(
        stderr.contains("session.jsonl:2"),
        "the notice points at the line that did not decode, got: {stderr}"
    );
    // Pointer-only (rule 4): the bytes of the line never leave the file. A
    // transcript is the richest secret surface this engine can be pointed at.
    assert!(
        !stderr.contains("assist"),
        "the failing line's content is never emitted, got: {stderr}"
    );

    let (code, line) = receipt_status(&repo, &home, "verify");
    assert_eq!(code, 0, "the receipt was recorded");
    assert_eq!(line, format!("verify {head} valid\n"));

    let store = fixture_state_dir(&repo, &home).join("receipts");
    assert!(
        !has_agent_statement(&store),
        "an undecodable transcript is never read as an empty one"
    );
}

/// The anti-vacuity half: a change that merely stopped writing statements would
/// pass every row above. A readable transcript still mints one, still bounded.
#[test]
fn a_present_transcript_still_writes_a_bounded_statement() {
    let (repo, home) = transcript_fixture("receipt-agent-present");
    fs::write(
        repo.join("session.jsonl"),
        "{\"type\":\"user\",\"sessionId\":\"s-1\"}\n",
    )
    .expect("write the transcript");

    let record = receipt_cmd(&repo, &home, &["receipt", "record", "verify"]);
    assert_eq!(record.status.code(), Some(0));

    let store = fixture_state_dir(&repo, &home).join("receipts");
    assert!(
        has_agent_statement(&store),
        "a readable transcript still states its context"
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

    // `enforce --rule`, not a bare `enforce`. The property is about ONE row —
    // `no-conflict-markers`, `kind = "command"`, `glob = "crates/**"` — and the
    // narrowing is what makes the assertion say so. Unnarrowed, exit 0 and an
    // empty stdout also claimed that none of the other 103 rows fires on this
    // fixture, which is incidental to the property and cost 206s of a 1482s
    // suite on the Windows runner.
    //
    // The discriminator above is untouched by the narrowing: exit 0 is still
    // reachable only if this row's glob selected nothing and no process was
    // spawned. `check --rule` is not available here and that is the point — the
    // SUBJECT is a spawning kind, so the read-effect verb must refuse it.
    let output = batten()
        .arg("enforce")
        .arg("--rule")
        .arg("no-conflict-markers")
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

/// The rule ids each of the two committed-ruleset cases below asserts.
///
/// Named once rather than spelled at each of the four call sites: the arms are a
/// banned-shape run and its clean-fixture discriminator, and a narrowing that
/// drifted between them would leave the discriminator proving nothing about the
/// set the other arm ran.
const AGNOSTICISM_RULES: [&str; 4] = [
    "no-consumer-account-literal",
    "no-consumer-entity-path",
    "no-consumer-repo-name",
    "no-tracker-key-in-core",
];

/// See [`AGNOSTICISM_RULES`].
const PORTABILITY_RULES: [&str; 6] = [
    "no-gnu-sed-z",
    "no-gnu-sed-in-place",
    "no-bash4-mapfile",
    "no-gnu-xargs-r",
    "no-branch-f-main",
    "no-util-linux-flock",
];

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
    // CLOUD-1100's row, the fourth and the one whose absence let a whole grammar
    // into the core. The discriminator is the character CLASS: a grammar constant
    // is a regex over keys where a provenance citation is a literal key, and the
    // crate is full of the latter. Assembled like its siblings, and here the dodge
    // is load-bearing twice over — the row would otherwise fire on this line.
    let tracker_key = format!("CL{}-[0-9]+", "OUD");
    let payload = format!(
        "let id = \"{account}\";\nuse crate::{entity_path}mod;\n// ported from {repo_name}\n\
         const KEY: &str = r\"{tracker_key}\";\n"
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
        .args(AGNOSTICISM_RULES.iter().flat_map(|id| ["--rule", id]))
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
         crates/demo/notes.txt:4 no-tracker-key-in-core\n\
         crates/demo/src/lib.rs:1 no-consumer-account-literal\n\
         crates/demo/src/lib.rs:2 no-consumer-entity-path\n\
         crates/demo/src/lib.rs:3 no-consumer-repo-name\n\
         crates/demo/src/lib.rs:4 no-tracker-key-in-core\n",
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
        .args(AGNOSTICISM_RULES.iter().flat_map(|id| ["--rule", id]))
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
    // this file, at `crates/batten/tests/it/cli.rs`, does not sit under.
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
        dirty.join("mise-tasks/seed.sh"),
        "printf x | sed -zE 's/a/b/'\n\
         sed -i 's/a/b/' file\n\
         mapfile -t lines < <(printf 'x')\n\
         git ls-files | xargs -r grep x\n\
         flock /tmp/lock true\n",
    )
    .expect("write fixture task");
    fs::create_dir_all(dirty.join("tests")).expect("create fixture test dir");
    // The `# subject:` header every suite owes since CLOUD-807: the committed
    // `bats-tests-not-deleted` row carries `retires_with`, so a suite declaring
    // no subject is itself a finding. Declared here — pointing at the task seed
    // this fixture already writes — so this test keeps asserting the PORTABILITY
    // rules and nothing else, rather than growing a second rule's pointer. It
    // takes line 1, which is where a real suite puts it, so the banned line
    // below is line 2.
    fs::write(
        dirty.join("tests/seed.bats"),
        "# subject: mise-tasks/seed.sh\n\tgit branch -f main\n",
    )
    .expect("write fixture suite");

    // THE SEEDS ARE COMMITTED INTO THE BASE, for the reason the `# subject:`
    // header above already records one rule earlier (CLOUD-1059). The committed
    // `shell-retirement` row decides over the delta against `origin/main`, and
    // `committed_config_fixture_git` pins that ref at an EMPTY commit — so a seed
    // written afterwards is an authored shell rule this fixture ADDS, which that
    // row refuses, and the refusal would grow a second rule's pointer into an
    // assertion about portability. Committing them and re-pointing the ref makes
    // the two files unchanged rather than added, so the delta is empty and this
    // test keeps asserting the PORTABILITY rules and nothing else.
    // The two seeds by name rather than `-A`: this fixture also carries an
    // untracked `batten.toml` and a provision cache, and sweeping those into the
    // index would move `Fact::Tracked` under every other committed rule — a
    // wider blast radius than the one path this needs to change.
    git_in(&dirty, &["add", "mise-tasks/seed.sh", "tests/seed.bats"]);
    git_in(&dirty, &["commit", "-q", "-m", "seed"]);
    git_in(&dirty, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

    // `enforce`, not `check`: the committed ruleset carries `no-conflict-markers`,
    // a kind that runs a configured command, and the read-effect verb refuses the
    // whole config rather than silently skipping that one row (exit 1, pinned by
    // `the_committed_config_refuses_to_run_a_spawning_kind_under_check`). Every
    // sibling test over the committed bytes takes the same verb for the same
    // reason.
    let output = batten()
        .arg("enforce")
        .args(PORTABILITY_RULES.iter().flat_map(|id| ["--rule", id]))
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
        "mise-tasks/seed.sh:1 no-gnu-sed-z\n\
         mise-tasks/seed.sh:2 no-gnu-sed-in-place\n\
         mise-tasks/seed.sh:3 no-bash4-mapfile\n\
         mise-tasks/seed.sh:4 no-gnu-xargs-r\n\
         mise-tasks/seed.sh:5 no-util-linux-flock\n\
         tests/seed.bats:2 no-branch-f-main\n",
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
        clean.join("mise-tasks/seed.sh"),
        "printf x | perl -0777 -pe 's/a/b/'\n\
         sed -i.bak 's/a/b/' file\n\
         while IFS= read -r l; do :; done < <(printf 'x\\n')\n\
         git ls-files | xargs grep x\n",
    )
    .expect("write clean task");
    fs::create_dir_all(clean.join("tests")).expect("create clean test dir");
    fs::write(
        clean.join("tests/seed.bats"),
        "# subject: mise-tasks/seed.sh\n\tgit branch main\n",
    )
    .expect("write clean suite");

    // Committed into the base for the reason the dirty fixture above records
    // (CLOUD-1059): otherwise these two seeds are files this fixture ADDS, and
    // `shell-retirement` refuses an added authored shell rule — which would make
    // a tree that is portable by construction exit 2 for a reason that has
    // nothing to do with portability.
    git_in(&clean, &["add", "mise-tasks/seed.sh", "tests/seed.bats"]);
    git_in(&clean, &["commit", "-q", "-m", "seed"]);
    git_in(&clean, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

    let output = batten()
        .arg("enforce")
        .args(PORTABILITY_RULES.iter().flat_map(|id| ["--rule", id]))
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
    // deleted `mise-tasks/context-budget.sh` carried, restated for a `<=`
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

/// changed: an undecodable transcript is REPORTED by `check`, not a usage error
/// (CLOUD-819). This case asserted exit 1 and a comment arguing "loud, and
/// structurally not a deny". The §7 half of that argument still holds and is
/// untouched — this never was and still is not a `2`. What was wrong is that
/// loudness was implemented as a VETO: the only rule consuming this capability is
/// declared structurally unable to block (§0.3), so a parse failure stopped
/// `check` entirely, every unrelated tree rule with it, from one line written by
/// a host this repository does not control.
///
/// Both properties this case really guarded — the pointer, and that the line's
/// bytes never escape — are kept verbatim below, which is what makes this a
/// narrowing rather than a deletion.
#[test]
fn an_undecodable_transcript_is_reported_and_does_not_veto_the_verb() {
    let dir = repo_with_transcript(
        "transcript-undecodable",
        Some("{\"type\":\"user\"}\nnot json\n"),
    );
    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(0),
        "an advisory surface that could not be read is not the verb's verdict"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(batten::transcript::UNREADABLE_NOTICE),
        "the report is not silent, got: {stderr}"
    );
    assert!(
        stderr.contains("session.jsonl:2"),
        "a pointer, got: {stderr}"
    );
    assert!(
        !stderr.contains("not json"),
        "never the line itself: {stderr}"
    );
}

/// THE ANTI-SILENCE ARM. A repair that merely stopped erroring would report the
/// capability as `absent` and lose the one fact an operator needs — that data was
/// damaged rather than never wired. `-J` is the half that cannot be silenced, so
/// the distinction has to live there and not only in a stderr line.
#[test]
fn an_undecodable_transcript_is_named_unreadable_rather_than_absent() {
    let dir = repo_with_transcript(
        "transcript-undecodable-json",
        Some("{\"type\":\"user\"}\nnot json\n"),
    );
    let output = batten()
        .args(["check", "-J"])
        .current_dir(&dir)
        .output()
        .expect("run batten check -J");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one pure JSON document");
    assert_eq!(
        document["transcript"]["capability"], "unreadable",
        "damaged is its own state, never folded into absent"
    );
    // Rule 4 holds on the data channel too, and this is where a leak would be
    // easiest: the document is machine-read and less likely to be eyeballed.
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("not json"),
        "the failing line never reaches the document"
    );
}

/// THE ANTI-WIDENING ARM. Freeing the advisory surface must free ONLY it: a tree
/// rule with a real finding still reports it and still sets the exit code, with
/// the torn transcript present. Without this, "stop blocking on the transcript"
/// and "stop blocking" are indistinguishable.
#[test]
fn a_torn_transcript_does_not_suppress_an_unrelated_finding() {
    let dir = repo_with_transcript(
        "transcript-undecodable-finding",
        Some("{\"type\":\"user\"}\nnot json\n"),
    );
    // A tree rule with nothing to do with the transcript, in the shape
    // `fixtures/repos/forbid-deny` already uses.
    fs::write(
        dir.join("batten.toml"),
        "version = 1\n\n\
         [transcript]\npath = \"session.jsonl\"\n\n\
         [[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\n\
         glob = \"**/*.txt\"\npattern = \"TODO\"\nseverity = \"deny\"\nscope = \"tree\"\n",
    )
    .expect("write config");
    fs::write(dir.join("flagged.txt"), "TODO: this must still be found\n").expect("write subject");

    let output = batten()
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run batten check");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the tree rule's verdict survives an unreadable transcript"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no-todo"),
        "the finding is reported: {stdout}"
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

/// CLOUD-437's fixture: two rows, one declaring its own hatch and one not.
///
/// The pair is the point. A suite with only a hatched row could not tell "the
/// hatch worked" from "the deny never fired", and a suite with only an unhatched
/// one could not tell the general name from a row's own.
const HATCH_POLICY_CONFIG: &str = r#"version = 1
[[rule]]
id = "owns-its-hatch"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr merge"
bypass_env = "BATTEN_GH_GUARD_BYPASS"
reason = "use `mise run land`"

[[rule]]
id = "takes-the-general-hatch"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "danger-zone"
reason = "do not"
"#;

fn hatch_call(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string()
}

#[test]
fn no_deny_advertises_a_hatch_on_the_hot_path() {
    // CLOUD-437 CLOSED RATHER THAN NARROWED (CLOUD-1286). That row's defect was
    // a deny pointing at another subsystem's variable, and the fix at the time
    // was to advertise the RIGHT one. The fix now is to advertise none: the
    // sentence was byte-identical on every firing of every row, so it was pure
    // per-firing cost carrying no per-firing information, and naming the wrong
    // variable was only the most visible symptom of printing it at all.
    //
    // The hatch is not removed and this is not a weakening — `the_hatch_a_deny_
    // advertises_actually_suppresses_that_deny` below still proves each row's
    // own variable suppresses its own deny, which was always the load-bearing
    // half. What is gone is the advertisement.
    let dir = repo_with_config("hatch-named", HATCH_POLICY_CONFIG);

    let owned = run_hook_with_env(&dir, "claude-code", &hatch_call("gh pr merge 42"), &[]);
    let owned_text = String::from_utf8_lossy(&owned.stdout).into_owned();
    assert!(
        owned_text.contains("owns-its-hatch"),
        "the row that refused is still named: {owned_text}"
    );
    assert!(
        !owned_text.contains("BATTEN_GH_GUARD_BYPASS"),
        "but it does not advertise its hatch: {owned_text}"
    );

    let general = run_hook_with_env(&dir, "claude-code", &hatch_call("danger-zone --now"), &[]);
    let general_text = String::from_utf8_lossy(&general.stdout).into_owned();
    assert!(
        !general_text.contains("BATTEN_HOOK_BYPASS"),
        "and neither does a row taking the general hatch: {general_text}"
    );
    assert!(
        !general_text.contains("GH_GUARD"),
        "no deny names a hatch belonging to a subsystem it did not come from: {general_text}"
    );
}

#[test]
fn the_hatch_a_deny_advertises_actually_suppresses_that_deny() {
    // THE LOAD-BEARING HALF (CLOUD-437 §7). A suite asserting only the string
    // would pass on a hatch nothing reads, and a refusal pointing at a variable
    // the boundary ignores is worse than one pointing nowhere.
    let dir = repo_with_config("hatch-works", HATCH_POLICY_CONFIG);
    let call = hatch_call("gh pr merge 42");

    let denied = run_hook_with_env(&dir, "claude-code", &call, &[]);
    assert!(
        String::from_utf8_lossy(&denied.stdout).contains("owns-its-hatch"),
        "the row denies when its hatch is unset"
    );

    let hatched = run_hook_with_env(
        &dir,
        "claude-code",
        &call,
        &[("BATTEN_GH_GUARD_BYPASS", "1")],
    );
    assert!(
        !String::from_utf8_lossy(&hatched.stdout).contains("owns-its-hatch"),
        "setting the advertised hatch suppresses that deny: {:?}",
        String::from_utf8_lossy(&hatched.stdout)
    );
}

#[test]
fn one_rows_hatch_leaves_every_other_row_live() {
    // The fidelity bar this column exists for. The bash guards were separate
    // programs, so suppressing `memory-guard` left `ready-guard` live; one global
    // hatch silently widens the blast radius of every bypass, invisibly, because
    // the deny text cannot say what else it just switched off.
    //
    // Fails by: suppressing the REFUSAL post-hoc instead of removing the row —
    // adjudication would stop at the hatched row and every row behind it would
    // go unevaluated.
    let dir = repo_with_config("hatch-narrow", HATCH_POLICY_CONFIG);
    let output = run_hook_with_env(
        &dir,
        "claude-code",
        &hatch_call("danger-zone --now"),
        &[("BATTEN_GH_GUARD_BYPASS", "1")],
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("takes-the-general-hatch"),
        "another row's hatch must not disarm this one: {text}"
    );
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
fn at_risk_work_does_not_block_the_turn() {
    // THE CONTRACT THAT CHANGED (CLOUD-889). This asserted that at-risk work
    // produced a `"deny"` document. It did — and `adjudicate` never read
    // `stop_active`, so the deny repeated on the continuation it caused, over a
    // predicate (`unlanded` against the landing target) that holds for a feature
    // branch's entire life. Forced continuation with no bound is the runaway.
    //
    // CLOUD-97 and CLOUD-219 each independently ruled a hard deny out here, and
    // `completion.rs` already implements that decision; this arm was the outlier.
    // The property asserted now is the permanent one: **no Stop input produces a
    // refusal**, whatever the worktree holds.
    let dir = stop_repo("stop-at-risk");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    assert_eq!(output.status.code(), Some(0));
    let document = common::stdout(&output);
    assert!(
        !document.contains("\"deny\""),
        "a turn may always end; the end-of-turn gate reports, never refuses: {document:?}"
    );
    assert!(
        !document.contains("work in progress"),
        "a pointer, never the content (rule 4): {document:?}"
    );
}

#[test]
fn the_at_risk_fact_is_still_computed_and_still_a_pointer() {
    // COVERAGE THAT MUST NOT EVAPORATE WITH THE DENY (CLOUD-843's trap). The
    // refusal is gone; the FACT is not, and `worktree status` is the verb that
    // prints exactly the lines the gate read. Asserting it here keeps "at-risk
    // work is detected, and named as a count rather than a content" under test
    // while the reporting channel moves.
    let dir = stop_repo("stop-remedy");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = batten()
        .args(["worktree", "status"])
        .current_dir(&dir)
        .output()
        .expect("run batten worktree status");
    let report = format!("{}{}", common::stdout(&output), common::stderr(&output));
    assert!(
        report.contains("uncommitted: 1 paths"),
        "the fact is still computed and still a pointer: {report:?}"
    );
    assert!(
        !report.contains("work in progress"),
        "a pointer, never the content (rule 4): {report:?}"
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
fn a_stop_event_never_reaches_the_deny_exit_code() {
    // THE DISCRIMINATOR FOR CLOUD-889, on the host whose only channel IS the
    // exit status. This asserted `Some(2)` — the verdict code — which on a Stop
    // event forces the host to continue the turn. With no recursion bound in
    // `adjudicate` and a predicate true for a branch's whole life, that is an
    // unbounded loop terminating only at the host's continuation cap.
    //
    // Exit 2 is unreachable from this event now, and the property is structural
    // rather than observed: the arm returns `Decision::Allow` outright, so there
    // is no `Deny` for a caller to construct. Fails by restoring the match on
    // `stop.refusal()`.
    let dir = stop_repo("stop-exit-code");
    common::write(&dir, "scratch.txt", "work in progress\n");

    let output = run_hook_in(&dir, "exit-code", &stop_payload(), false);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the end-of-turn gate cannot refuse on any channel: {:?}",
        common::stderr(&output)
    );
}

// --- `[[hook.handler]]`: the door, end to end (CLOUD-898) --------------------

/// A repository whose only policy is one handler, with `run` given verbatim.
///
/// The caller supplies the whole TOML array so each case owns its own quoting.
/// That is not fussiness: the first version of this helper interpolated a shell
/// string into a basic TOML string, and a case whose command contained double
/// quotes silently produced an unparseable config — which `batten` correctly
/// refused with exit 1, and which read as "the handler misbehaved".
fn handler_repo(name: &str, event: &str, run: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\n\n[[hook.handler]]\nid = \"probe\"\non = \"{event}\"\nrun = {run}\ntimeout_ms = 4000\n"
        ))
        .build()
}

/// A Claude Code `UserPromptSubmit` payload.
fn prompt_payload() -> String {
    serde_json::json!({ "hook_event_name": "UserPromptSubmit", "session_id": "h-1" }).to_string()
}

/// A Claude Code `PostToolBatch` payload — the batch boundary, and the one event
/// where this host delivers an advisory to the MODEL.
fn batch_payload() -> String {
    serde_json::json!({ "hook_event_name": "PostToolBatch", "session_id": "h-1" }).to_string()
}

/// A repository whose one handler is narrowed by `matcher` (CLOUD-312 row 5).
fn narrowed_handler_repo(name: &str, matcher: &str, run: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\n\n[[hook.handler]]\nid = \"probe\"\non = \"pre-tool\"\nrun = {run}\nmatcher = \"{matcher}\"\ntimeout_ms = 4000\n"
        ))
        .build()
}

/// A Claude Code `PreToolUse` payload naming `tool`.
fn pre_tool_payload(tool: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "h-1",
        "tool_name": tool,
        "tool_input": { "command": "echo hi" }
    })
    .to_string()
}

#[test]
fn a_matcher_keeps_a_pre_tool_handler_off_the_calls_it_does_not_name() {
    // THE SPAWN IS THE SUBJECT, not the verdict, and that distinction is the whole
    // test. `selects` narrows by EVENT alone, which is enough for a handler that
    // fires once a turn and not for `pre-tool`, which fires on every tool call:
    // measured 2026-08-25, an unnarrowed row cost 41.5ms p50 on a `Bash` call
    // against 21.4ms narrowed — the spawn, on calls it has nothing to say about.
    //
    // A verdict assertion could not discriminate this at all: the guard this stands
    // in for is SILENT on a call it does not decide, so allow-versus-allow says
    // nothing about whether a process ran. The handler therefore refuses, which
    // makes the dispatch observable — the same reason `graph-check`'s deleted clause
    // was untestable and this one is not.
    let dir = narrowed_handler_repo(
        "handler-matcher",
        "^mcp__",
        r#"["sh", "-c", "echo dispatched >&2; exit 2"]"#,
    );

    let named = run_hook_in(
        &dir,
        "claude-code",
        &pre_tool_payload("mcp__x__get_session"),
        false,
    );
    let document = common::stdout(&named);
    assert!(
        document.contains("dispatched"),
        "the calls the matcher names still reach the handler: {document:?}"
    );

    for tool in ["Bash", "Read", "Edit"] {
        let other = run_hook_in(&dir, "claude-code", &pre_tool_payload(tool), false);
        let document = common::stdout(&other);
        assert!(
            !document.contains("dispatched"),
            "{tool} is not named by the matcher, so no process runs for it: {document:?}"
        );
    }
}

#[test]
fn a_handler_with_no_matcher_still_runs_for_every_call_at_its_event() {
    // The column's ABSENCE is the behaviour every landed row had before it existed,
    // so its arrival changes nothing for `mcp-attach-check` and its neighbours. This
    // is the anti-vacuity half of the case above: without it, a narrowing that
    // matched nothing at all would pass.
    let dir = handler_repo(
        "handler-unnarrowed",
        "pre-tool",
        r#"["sh", "-c", "echo dispatched >&2; exit 2"]"#,
    );
    for tool in ["Bash", "mcp__x__get_session"] {
        let output = run_hook_in(&dir, "claude-code", &pre_tool_payload(tool), false);
        let document = common::stdout(&output);
        assert!(
            document.contains("dispatched"),
            "an unnarrowed handler runs for {tool}: {document:?}"
        );
    }
}

#[test]
fn a_handler_that_refuses_reaches_the_host_channel_the_engine_uses() {
    // The door's whole claim: a dispatched program's refusal is rendered by
    // Batten, on whichever channel this host reads, rather than by the program
    // writing bytes the host happens to parse.
    let dir = handler_repo(
        "handler-deny",
        "user-prompt-submit",
        r#"["sh", "-c", "echo refused-by-handler >&2; exit 2"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &prompt_payload(), false);
    let document = common::stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        document.contains("\"deny\""),
        "the refusal is the host's own decision document: {document:?}"
    );
    assert!(
        document.contains("hook.handler.probe"),
        "and it names the handler that refused: {document:?}"
    );
    assert!(
        document.contains("refused-by-handler"),
        "carrying the handler's own reason: {document:?}"
    );
}

#[test]
fn a_handler_that_refuses_and_says_nothing_allows_rather_than_denying() {
    // The sibling of the case above, raised in review on #632: exit 2 with BOTH
    // streams empty produced `Deny("")` — a host-facing refusal naming nothing,
    // which is the un-actionable shape §5 forbids and CLOUD-122 exists to
    // prevent, with `Fix::None` so there was nothing to act on either.
    //
    // Reported rather than given a fabricated reason, and the direction is the
    // point: Batten cannot invent a remedy for a predicate it does not know, and
    // a handler broken this way must not be able to block a call. So this asserts
    // the ALLOW as hard as it asserts the report — fail-open is the property, and
    // a test that only checked the pointer line would pass on a silent deny too.
    // ON A BATCH BOUNDARY RATHER THAN A PROMPT, and the first version of this
    // case got it wrong: `user-prompt-submit` has no model-facing advisory
    // channel on this host, so the pointer went to the operator's stream and the
    // stdout assertion read `""`. That would have made the case about which
    // channel carries a notice, when what it is for is the demotion itself.
    // `post-tool-batch` delivers advice AND carries a verdict, so a silent deny
    // there is a deny the engine would otherwise have honoured.
    let dir = handler_repo(
        "handler-silent-deny",
        "post-tool-batch",
        r#"["sh", "-c", "exit 2"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &batch_payload(), false);
    let document = common::stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !document.contains("\"deny\""),
        "a handler that refused without saying why must not reach the host as a \
         refusal: {document:?}"
    );
    assert!(
        document.contains("no reason on stdout or stderr"),
        "and the author is told what their handler did: {document:?}"
    );
}

#[test]
fn a_handler_that_exits_zero_with_stdout_advises_rather_than_deciding() {
    let dir = handler_repo(
        "handler-advise",
        "post-tool-batch",
        r#"["sh", "-c", "echo a-pointer-line"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &batch_payload(), false);
    let document = common::stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        document.contains("a-pointer-line"),
        "stdout on a passing exit is advisory text: {document:?}"
    );
    assert!(
        !document.contains("permissionDecision"),
        "and an advisory is never a verdict: {document:?}"
    );
}

#[test]
fn an_advisory_at_an_event_with_no_channel_reaches_the_operator_not_the_model() {
    // MEASURED WHILE WRITING THESE CASES, and worth a case of its own rather
    // than a footnote: this host delivers `additionalContext` at the batch
    // boundary and offers no such field on `UserPromptSubmit`. So the same
    // handler that advises the model above degrades to the OPERATOR's stream
    // here. Silence toward the model, never an invented verdict.
    //
    // It also bounds what a migration through this door can promise: a hook
    // moved from `UserPromptSubmit` keeps its exit-code verdict and loses its
    // model-facing advisory, which is a fact about the host rather than about
    // the door.
    let dir = handler_repo(
        "handler-no-channel",
        "user-prompt-submit",
        r#"["sh", "-c", "echo a-pointer-line"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &prompt_payload(), false);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        common::stdout(&output).is_empty(),
        "nothing reaches the model: {:?}",
        common::stdout(&output)
    );
    assert!(
        common::stderr(&output).contains("a-pointer-line"),
        "and the text is the operator's: {:?}",
        common::stderr(&output)
    );
}

#[test]
fn a_handler_writing_a_host_document_is_reported_and_not_forwarded() {
    // THE PORTABILITY PROPERTY, and the one a well-meaning author is most likely
    // to break. Registered directly, this script's bytes would have been obeyed
    // by the host. Through the door nothing forwards them, so the author is told
    // rather than left believing they decided something.
    //
    // `printf` RATHER THAN `echo`, and the difference is the whole test. `sh`
    // strips the inner quotes from `echo {"hookSpecificOutput":1}`, so the
    // fixture emitted `{hookSpecificOutput:1}` — detected, because
    // `impersonates_host` matches a leading brace plus a bare key substring, but
    // it meant the NEGATIVE assertion below named a quoted string the handler
    // could never produce, and an assertion that cannot fail is not one
    // (CLOUD-251, raised in review on #632).
    //
    // So the handler now emits a document the host would really obey, and the
    // absence check names the bytes it actually wrote. Registered directly, these
    // bytes decide the call; through the door nothing forwards them.
    let dir = handler_repo(
        "handler-impersonates",
        "post-tool-batch",
        r#"["sh", "-c", 'printf %s "{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}"']"#,
    );
    let output = run_hook_in(&dir, "claude-code", &batch_payload(), false);
    let document = common::stdout(&output);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        document.contains("wrote a host decision document"),
        "the violation is named: {document:?}"
    );
    assert!(
        !document.contains(r#""permissionDecision":"deny""#),
        "and the handler's own decision is not passed along: {document:?}"
    );
}

#[test]
fn a_handler_that_hangs_is_killed_at_its_bound_and_the_turn_still_ends() {
    // The property no dispatched program can give itself. `stop-guard`
    // hand-rolled `timeout 1s cat` for exactly this; the parent owns it now.
    let dir = Fixture::new("handler-hangs")
        .config(
            "version = 1\n\n[[hook.handler]]\nid = \"slow\"\non = \"post-tool-batch\"\nrun = [\"sleep\", \"30\"]\ntimeout_ms = 300\n",
        )
        .build();
    let started = std::time::Instant::now();
    let output = run_hook_in(&dir, "claude-code", &batch_payload(), false);
    assert_eq!(output.status.code(), Some(0), "a bound is not a refusal");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the bound was imposed rather than waited out"
    );
    assert!(
        common::stdout(&output).contains("exceeded 300ms"),
        "and the author is told which handler and by how much: {:?}",
        common::stdout(&output)
    );
}

#[test]
fn an_event_no_handler_selects_for_dispatches_nothing() {
    // CLOUD-460's narrowing, which is what makes admitting `pre-tool` affordable
    // at all: the handler is keyed on `user-prompt-submit`, so a Stop payload
    // must not reach a spawn.
    let dir = handler_repo(
        "handler-narrowed",
        "user-prompt-submit",
        r#"["sh", "-c", "echo should-not-run"]"#,
    );
    let output = run_hook_in(&dir, "claude-code", &stop_payload(), false);
    assert_eq!(output.status.code(), Some(0));
    let seen = format!("{}{}", common::stdout(&output), common::stderr(&output));
    assert!(
        !seen.contains("should-not-run"),
        "no handler selects for this event: {seen:?}"
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

// --- handles: capture once, expand without re-running (CLOUD-121) ------------
//
// The pain is `cmd | tail -N`: the agent guesses a window, misses the line, and
// re-runs a possibly non-idempotent command to widen it. Everything below reads a
// capture that was taken once and is frozen, so widening costs a read.
//
// A COUNTER IS THE LOAD-BEARING FIXTURE. The wrapped command appends to a file
// every time it runs, so "no second run" is asserted against evidence the child
// itself leaves rather than against the absence of output — which would pass just
// as happily if the command ran twice and printed nothing the second time.

/// A repo with a counter script, plus an isolated store.
#[cfg(unix)]
fn capture_repo(name: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

/// Run the counter child, appending a tick per execution.
#[cfg(unix)]
fn run_counted(repo: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    let script = format!(
        "printf 'x' >>{}/runs; printf 'alpha\\nbravo warning here\\ncharlie\\ndelta\\n'",
        repo.display()
    );
    batten()
        .args(args)
        .args(["--", "sh", "-c", &script])
        .current_dir(repo)
        .state_home(home)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten exec")
}

/// How many times the counter child has run.
#[cfg(unix)]
fn runs(repo: &std::path::Path) -> usize {
    std::fs::read_to_string(repo.join("runs")).map_or(0, |text| text.len())
}

/// `batten capture …` against the same isolated store.
#[cfg(unix)]
fn run_capture(repo: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    batten()
        .arg("capture")
        .args(args)
        .current_dir(repo)
        .state_home(home)
        .output()
        .expect("run batten capture")
}

/// The stdout handle of the one capture in the store.
#[cfg(unix)]
fn stdout_handle(repo: &std::path::Path, home: &std::path::Path) -> String {
    let listed = run_capture(repo, home, &["list", "--stream", "stdout"]);
    assert_eq!(listed.status.code(), Some(0));
    stdout(&listed)
        .split_whitespace()
        .next()
        .expect("a listed handle")
        .to_owned()
}

#[cfg(unix)]
#[test]
fn capture_only_reports_handles_instead_of_the_childs_bytes() {
    // The economics of the whole capability. Teeing is the default and stays it;
    // this is the caller asking to be handed pointers, which is what makes a
    // handle worth having — one obtainable only after paying for the full output
    // saves nothing (measured at 1.47x in bench/tokens/RESULTS.md).
    let (repo, home) = capture_repo("handle-only");
    let output = run_counted(&repo, &home, &["exec", "--capture-only"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        stdout(&output).is_empty(),
        "the child's bytes must not reach stdout: {}",
        stdout(&output)
    );
    let report = stderr(&output);
    assert!(report.contains("stdout:"), "got {report}");
    assert!(report.contains("stderr:"), "got {report}");
    assert!(
        !report.contains("bravo warning here"),
        "the handle report echoed the payload: {report}"
    );
}

#[cfg(unix)]
#[test]
fn tee_still_passes_the_childs_streams_through() {
    // The other half of the same property, RE-POINTED at `--tee` (CLOUD-429).
    // It used to read "the default", and the default is now the handle report —
    // that inversion is the whole of CLOUD-429. What must never regress is the
    // property itself: asking for the bytes gets exactly the bytes, and `--style
    // quiet` is how a caller asks for them with nothing of Batten's alongside.
    let (repo, home) = capture_repo("handle-default-tees");
    let output = run_counted(&repo, &home, &["exec", "--tee", "--style", "quiet"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("bravo warning here"));
    assert!(stderr(&output).is_empty(), "a clean run says nothing");
}

#[cfg(unix)]
#[test]
fn widening_the_window_costs_no_second_run_of_the_command() {
    // THE acceptance criterion. The counter is what makes it evidence: an
    // assertion that output was absent would pass even if the child ran again.
    let (repo, home) = capture_repo("handle-no-rerun");
    run_counted(&repo, &home, &["exec", "--capture-only"]);
    assert_eq!(runs(&repo), 1);

    let handle = stdout_handle(&repo, &home);
    let found = run_capture(&repo, &home, &["show", &handle, "--grep", "warning"]);
    assert_eq!(found.status.code(), Some(0));
    assert_eq!(stdout(&found), "stdout:2 bravo warning here\n");

    let widened = run_capture(&repo, &home, &["show", &handle, "--lines", "1:4"]);
    assert_eq!(widened.status.code(), Some(0));
    assert_eq!(stdout(&widened).lines().count(), 4);

    assert_eq!(
        runs(&repo),
        1,
        "the command ran again — the handle bought nothing"
    );
}

#[cfg(unix)]
#[test]
fn an_unqualified_show_is_the_pointer_not_the_payload() {
    let (repo, home) = capture_repo("handle-summary");
    run_counted(&repo, &home, &["exec", "--capture-only"]);
    let handle = stdout_handle(&repo, &home);
    let output = run_capture(&repo, &home, &["show", &handle]);
    assert_eq!(output.status.code(), Some(0));
    let answer = stdout(&output);
    assert!(answer.contains("4 lines"), "got {answer}");
    assert!(
        !answer.contains("bravo"),
        "content must be asked for by name: {answer}"
    );
}

#[cfg(unix)]
#[test]
fn a_line_range_past_the_end_is_clamped_rather_than_refused() {
    // Widening is the point. Refusing an over-wide range would send the caller
    // back to guessing a window size, which is the behaviour this deletes.
    let (repo, home) = capture_repo("handle-clamp");
    run_counted(&repo, &home, &["exec", "--capture-only"]);
    let handle = stdout_handle(&repo, &home);
    let output = run_capture(&repo, &home, &["show", &handle, "--lines", "1:9999"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output).lines().count(), 4);
}

#[cfg(unix)]
#[test]
fn two_selectors_are_refused_rather_than_silently_composed() {
    // Two readings — intersection or union — and picking one silently would make
    // the answer depend on a choice the caller never saw.
    let (repo, home) = capture_repo("handle-two-selectors");
    run_counted(&repo, &home, &["exec", "--capture-only"]);
    let handle = stdout_handle(&repo, &home);
    let output = run_capture(
        &repo,
        &home,
        &["show", &handle, "--lines", "1:2", "--grep", "alpha"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("grep first"),
        "{}",
        stderr(&output)
    );
}

#[cfg(unix)]
#[test]
fn a_handle_naming_nothing_is_a_usage_error_never_a_verdict() {
    // Exit 1, not 2: the caller asked about a capture that is not there, which is
    // a statement about the invocation rather than a finding about the repo.
    let (repo, home) = capture_repo("handle-absent");
    let output = run_capture(&repo, &home, &["show", "stdout:abc123"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("capture list"),
        "{}",
        stderr(&output)
    );
}

#[cfg(unix)]
#[test]
fn a_malformed_handle_never_reaches_the_filesystem() {
    // The digest is a path component, so the parser refusing anything but hex is
    // what stops a traversal travelling there.
    let (repo, home) = capture_repo("handle-traversal");
    for bad in ["stdout:../../../etc/passwd", "stdin:abc", "nocolon"] {
        let output = run_capture(&repo, &home, &["show", bad]);
        assert_eq!(output.status.code(), Some(1), "{bad} should be refused");
        assert!(
            !stderr(&output).contains("root:"),
            "{bad} reached a file: {}",
            stderr(&output)
        );
    }
}

#[cfg(unix)]
#[test]
fn prune_refuses_without_confirmation_and_removes_with_it() {
    // The first destructive verb in the surface. It never prompts — §4's own
    // reasoning is that a policy engine blocking a loop on a Y/N is a dead gate —
    // so the refusal names the flag and is one hop from done.
    let (repo, home) = capture_repo("handle-prune");
    run_counted(&repo, &home, &["exec", "--capture-only"]);

    let refused = run_capture(&repo, &home, &["prune"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("-y"), "{}", stderr(&refused));

    let preview = run_capture(&repo, &home, &["prune", "-n"]);
    assert_eq!(preview.status.code(), Some(0));
    assert!(
        stderr(&preview).contains("would remove 2"),
        "{}",
        stderr(&preview)
    );
    assert_eq!(
        run_capture(&repo, &home, &["list"]).stdout.len(),
        run_capture(&repo, &home, &["list"]).stdout.len(),
    );
    assert!(!stdout(&run_capture(&repo, &home, &["list"])).is_empty());

    let pruned = run_capture(&repo, &home, &["prune", "-y"]);
    assert_eq!(pruned.status.code(), Some(0));
    assert!(stdout(&run_capture(&repo, &home, &["list"])).is_empty());
}

#[cfg(unix)]
#[test]
fn a_capture_listing_is_byte_stable_across_runs() {
    // §6: the same bytes for the same input. Sorted by handle rather than mtime,
    // so a listing is a statement about the store and not about when it happened.
    let (repo, home) = capture_repo("handle-stable");
    run_counted(&repo, &home, &["exec", "--capture-only"]);
    let first = run_capture(&repo, &home, &["list"]);
    let second = run_capture(&repo, &home, &["list"]);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(
        run_capture(&repo, &home, &["list", "-J"]).stdout,
        run_capture(&repo, &home, &["list", "-J"]).stdout
    );
}

#[cfg(unix)]
#[test]
fn the_navigation_verbs_declare_themselves_read_in_the_spec() {
    // The derived allowlist is built from this classification: `show` and `list`
    // must be on it, and the `capture` noun must not — its subtree removes.
    let output = batten().arg("spec").output().expect("run batten spec");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let capture = spec["subcommands"]
        .as_array()
        .expect("subcommands is an array")
        .iter()
        .find(|node| node["path"] == "capture")
        .expect("capture is in the spec");
    assert_eq!(capture["effect"], "unclassified");
    let subs = capture["subcommands"]
        .as_array()
        .expect("subcommands is an array");
    let effect = |path: &str| {
        subs.iter()
            .find(|node| node["path"] == path)
            .unwrap_or_else(|| panic!("{path} is in the spec"))["effect"]
            .clone()
    };
    assert_eq!(effect("capture show"), "read");
    assert_eq!(effect("capture list"), "read");
    assert_eq!(effect("capture prune"), "destructive");
}

// --- the byte-exact route (CLOUD-918) ----------------------------------------
//
// Every test above reads a capture through the LINE view, which is an explicitly
// lossy projection: `select` decodes with `from_utf8_lossy` and the module doc
// says so. That made the module's own promise — "the bytes stay exact in the
// store" — unfalsifiable, because no operation returned them.
//
// THE ASSERTION IS ON BYTES, and that choice is what gives these tests teeth. A
// line count or a rendered string would survive a `--raw` path that decoded
// somewhere along the way; comparing the raw stdout to the bytes the child wrote
// does not. Routing `--raw` through `from_utf8_lossy` reds the first two
// immediately, which is this row's CLOUD-418 obligation.

/// Run a child that writes `printf`-escaped `bytes`, capturing them.
#[cfg(unix)]
fn run_raw_bytes(repo: &std::path::Path, home: &std::path::Path, escaped: &str) -> Output {
    batten()
        .args(["exec", "--capture-only"])
        .args(["--", "sh", "-c", &format!("printf '{escaped}'")])
        .current_dir(repo)
        .state_home(home)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten exec")
}

#[cfg(unix)]
#[test]
fn an_invalid_utf8_byte_round_trips_through_raw_unchanged() {
    // A lone continuation byte: valid nowhere in UTF-8, so a decode replaces it
    // with U+FFFD and the bytes that come back are not the bytes that went in.
    let (repo, home) = capture_repo("raw-invalid-utf8");
    assert_eq!(
        run_raw_bytes(&repo, &home, "before\\377after")
            .status
            .code(),
        Some(0)
    );
    let handle = stdout_handle(&repo, &home);
    let read = run_capture(&repo, &home, &["show", &handle, "--raw"]);
    assert_eq!(read.status.code(), Some(0));
    assert_eq!(
        read.stdout,
        b"before\xffafter".to_vec(),
        "the raw read decoded the bytes instead of returning them"
    );
}

#[cfg(unix)]
#[test]
fn a_nul_byte_round_trips_through_raw_unchanged() {
    // A NUL survives a UTF-8 decode, so this catches a different defect from the
    // case above: a path that treats the capture as a C string, or that trims.
    let (repo, home) = capture_repo("raw-nul");
    assert_eq!(
        run_raw_bytes(&repo, &home, "a\\000b").status.code(),
        Some(0)
    );
    let handle = stdout_handle(&repo, &home);
    let read = run_capture(&repo, &home, &["show", &handle, "--raw"]);
    assert_eq!(read.status.code(), Some(0));
    assert_eq!(read.stdout, b"a\0b".to_vec());
}

#[cfg(unix)]
#[test]
fn a_raw_read_adds_no_trailing_newline() {
    // The one thing every other arm of this verb does. A caller reassembling a
    // capture from ranges would otherwise get a byte per range it never stored.
    let (repo, home) = capture_repo("raw-no-newline");
    assert_eq!(run_raw_bytes(&repo, &home, "tight").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    let read = run_capture(&repo, &home, &["show", &handle, "--raw"]);
    assert_eq!(read.stdout, b"tight".to_vec());
}

#[cfg(unix)]
#[test]
fn a_raw_byte_range_returns_exactly_that_range_and_tiles() {
    // Half-open is what makes ranges composable: `0:3` then `3:6` must reassemble
    // the record with nothing doubled and nothing dropped. An inclusive
    // convention would repeat a byte at every seam.
    let (repo, home) = capture_repo("raw-range");
    assert_eq!(run_raw_bytes(&repo, &home, "abcdef").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    let head = run_capture(&repo, &home, &["show", &handle, "--raw", "--bytes", "0:3"]);
    let tail = run_capture(&repo, &home, &["show", &handle, "--raw", "--bytes", "3:6"]);
    assert_eq!(head.stdout, b"abc".to_vec());
    assert_eq!(tail.stdout, b"def".to_vec());
    let mut tiled = head.stdout.clone();
    tiled.extend_from_slice(&tail.stdout);
    assert_eq!(tiled, b"abcdef".to_vec());
    // An omitted bound means the end, which is the only way to say so without
    // first learning the length.
    let rest = run_capture(&repo, &home, &["show", &handle, "--raw", "--bytes", "3:"]);
    assert_eq!(rest.stdout, b"def".to_vec());
}

#[cfg(unix)]
#[test]
fn a_byte_range_past_the_end_is_clamped_rather_than_refused() {
    // `Selection::Lines`'s posture, on the byte axis: widening a window is the
    // point, so an out-of-range but well-formed bound answers.
    let (repo, home) = capture_repo("raw-clamp");
    assert_eq!(run_raw_bytes(&repo, &home, "short").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    let wide = run_capture(
        &repo,
        &home,
        &["show", &handle, "--raw", "--bytes", "0:5000"],
    );
    assert_eq!(wide.status.code(), Some(0));
    assert_eq!(wide.stdout, b"short".to_vec());
    // Entirely past the end is an empty answer, not a failure.
    let past = run_capture(
        &repo,
        &home,
        &["show", &handle, "--raw", "--bytes", "1000:2000"],
    );
    assert_eq!(past.status.code(), Some(0));
    assert!(past.stdout.is_empty());
    // And an inverted range selects nothing rather than panicking.
    let inverted = run_capture(&repo, &home, &["show", &handle, "--raw", "--bytes", "4:1"]);
    assert_eq!(inverted.status.code(), Some(0));
    assert!(inverted.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn a_malformed_byte_bound_is_a_usage_error_rather_than_a_clamp() {
    // The split that makes clamping safe to offer: a caller who guessed a window
    // gets an answer, and a caller who wrote nonsense gets told. Exit 1, never a
    // policy verdict.
    let (repo, home) = capture_repo("raw-malformed");
    assert_eq!(run_raw_bytes(&repo, &home, "body").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    for range in ["notanumber:4", "0:nope", "nocolon"] {
        let refused = run_capture(&repo, &home, &["show", &handle, "--raw", "--bytes", range]);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{range:?} was not refused as a usage error"
        );
    }
}

#[cfg(unix)]
#[test]
fn raw_and_json_name_two_encodings_and_are_refused_together() {
    // Two encodings of one selection. Resolving it silently is how a caller ends
    // up with base64 where it wanted bytes, so the combination is refused.
    let (repo, home) = capture_repo("raw-vs-json");
    assert_eq!(run_raw_bytes(&repo, &home, "body").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    let refused = run_capture(&repo, &home, &["show", &handle, "--raw", "-J"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty(), "a refusal emitted a document");
}

#[cfg(unix)]
#[test]
fn raw_and_a_line_selection_are_refused_together() {
    // A byte stream is not a line view. `--bytes` is how a raw read narrows.
    let (repo, home) = capture_repo("raw-vs-lines");
    assert_eq!(
        run_raw_bytes(&repo, &home, "one\\ntwo\\n").status.code(),
        Some(0)
    );
    let handle = stdout_handle(&repo, &home);
    for selector in [["--lines", "1:2"], ["--grep", "one"]] {
        let refused = run_capture(
            &repo,
            &home,
            &["show", &handle, "--raw", selector[0], selector[1]],
        );
        assert_eq!(
            refused.status.code(),
            Some(1),
            "--raw {} was not refused",
            selector[0]
        );
    }
}

#[cfg(unix)]
#[test]
fn a_byte_selection_under_json_is_base64_and_names_its_encoding() {
    // `--raw` and `--json` are refused together, so this is the OTHER encoding of
    // a byte range: base64 rather than an escaped string, because §6 requires the
    // document to be a function of the bytes and a lossy decode is not one.
    let (repo, home) = capture_repo("raw-json-doc");
    assert_eq!(
        run_raw_bytes(&repo, &home, "before\\377after")
            .status
            .code(),
        Some(0)
    );
    let handle = stdout_handle(&repo, &home);
    let read = run_capture(&repo, &home, &["show", &handle, "--bytes", "0:12", "-J"]);
    assert_eq!(read.status.code(), Some(0));
    let document: serde_json::Value =
        serde_json::from_slice(&read.stdout).expect("a JSON document");
    assert_eq!(document["encoding"], "base64");
    assert_eq!(document["from"], 0);
    assert_eq!(document["to"], 12);
    // The document CARRIED the invalid byte, which is the property under test: a
    // JSON string could not have, and `serde_json` would have refused to emit
    // one. Twelve bytes encode to sixteen characters of the base64 alphabet, and
    // asserting the shape here rather than a literal keeps this test from
    // re-implementing the encoder it is checking — the exact-value case is below.
    let data = document["data"].as_str().expect("data is a string");
    assert_eq!(data.len(), 16, "12 bytes should encode to 16 characters");
    assert!(
        data.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')),
        "the payload is not base64: {data}"
    );
}

#[cfg(unix)]
#[test]
fn the_base64_payload_is_the_standard_encoding_of_the_selected_bytes() {
    // The exact-value half, on a body whose encoding is unambiguous, so the
    // encoder is pinned against RFC 4648 rather than against itself. `abcdef` is
    // 6 bytes — two whole 3-byte groups, so no padding is involved either.
    let (repo, home) = capture_repo("raw-json-exact");
    assert_eq!(run_raw_bytes(&repo, &home, "abcdef").status.code(), Some(0));
    let handle = stdout_handle(&repo, &home);
    let read = run_capture(&repo, &home, &["show", &handle, "--bytes", "0:6", "-J"]);
    let document: serde_json::Value =
        serde_json::from_slice(&read.stdout).expect("a JSON document");
    assert_eq!(document["data"], "YWJjZGVm");
    // And a length that is not a multiple of three pads, which is where a
    // hand-rolled encoder usually goes wrong.
    let one = run_capture(&repo, &home, &["show", &handle, "--bytes", "0:1", "-J"]);
    let document: serde_json::Value = serde_json::from_slice(&one.stdout).expect("a JSON document");
    assert_eq!(document["data"], "YQ==");
    let two = run_capture(&repo, &home, &["show", &handle, "--bytes", "0:2", "-J"]);
    let document: serde_json::Value = serde_json::from_slice(&two.stdout).expect("a JSON document");
    assert_eq!(document["data"], "YWI=");
}

#[cfg(unix)]
#[test]
fn a_byte_range_without_an_encoding_is_a_pointer_rather_than_the_payload() {
    // Rule 4 holds on this path too: naming a window with neither encoding
    // reports what it WOULD return. Content stays something a caller asks for.
    let (repo, home) = capture_repo("raw-pointer");
    assert_eq!(
        run_raw_bytes(&repo, &home, "secretish").status.code(),
        Some(0)
    );
    let handle = stdout_handle(&repo, &home);
    let pointed = run_capture(&repo, &home, &["show", &handle, "--bytes", "0:9"]);
    assert_eq!(pointed.status.code(), Some(0));
    let text = stdout(&pointed);
    assert!(text.contains("0..9"), "the pointer names no window: {text}");
    assert!(
        !text.contains("secretish"),
        "the pointer carried the payload: {text}"
    );
}

/// Run `batten payload field --harness <harness> --name <name>` over `payload`.
fn run_payload_field(name: &str, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .args([
            "payload",
            "field",
            "--harness",
            "claude-code",
            "--name",
            name,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten payload field");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten payload field")
}

/// A `Task` spawn envelope, the shape `fanout-guard` is wired to (CLOUD-287).
fn spawn_payload(prompt: &serde_json::Value) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {"description": "d", "prompt": prompt},
    })
    .to_string()
}

/// A spawn is not shell-shaped, so its prompt is reachable only through the
/// allowlist's own member — `Command` is empty for exactly this payload, which
/// is why `Field::Prompt` had to exist at all (CLOUD-287).
#[test]
fn a_spawn_prompt_is_readable_and_its_command_is_not() {
    let payload = spawn_payload(&serde_json::json!("read AGENTS.md then stop"));

    let out = run_payload_field("prompt", &payload);
    assert!(out.status.success(), "status: {:?}", out.status);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        "read AGENTS.md then stop"
    );

    let command = run_payload_field("command", &payload);
    assert!(command.status.success());
    assert!(
        String::from_utf8_lossy(&command.stdout).trim().is_empty(),
        "a spawn carries no shell command"
    );
}

/// A non-string `prompt` reads as ABSENT, never as its debug rendering: a caller
/// counting characters must never be handed `{"a":1}` and told it is a prompt.
#[test]
fn a_non_string_prompt_reads_as_absent() {
    let out = run_payload_field("prompt", &spawn_payload(&serde_json::json!({"a": 1})));
    assert!(out.status.success(), "absent is not an error");
    assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty());
}

// --- the agent-sourced fact loop (CLOUD-776) ---------------------------------
//
// The channel that removes a choice rather than making it. A gate that needs a
// fact the engine cannot reach used to mean *the engine spawns a process* or *we
// implement less*; here it denies with `Fix::Run`, the AGENT's own tool runs the
// command, the harness hands the bytes back on the post-tool event, and the
// retry decides. Batten executes nothing at any point in that loop.
//
// These run it over the compiled binary, because the halves live in different
// processes and a unit test of either one would prove a loop that does not close.

/// A policy whose `gh pr create` needs one agent-sourced fact.
///
/// `claim-not-raced` is the worked instance CLOUD-776 names: `issue-guard`'s
/// duplicate-claim half could not port to the mediated path because "the
/// claimed-key lookup needs a network call the mediated path is barred from"
/// (CLOUD-446), so it became a `tree`-scoped row run under `verify` — catching
/// the race at `verify` where the guard caught it at `gh pr create`. The engine
/// still makes no network call; the agent's own `gh` does.
const AGENT_FACT_CONFIG: &str = r#"version = 1

[[fact]]
name = "claimed-key"
command = "gh pr list --state open --json headRefName"
returns = "json-array"

[[rule]]
id = "claim-not-raced"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr create"
checks = ["claimed-key"]
key = "branch"
reason = "unused: an agent-sourced check builds its fix from the declared command"
"#;

/// The post-tool payload a harness sends after the agent ran `command`.
fn post_tool(command: &str, rows: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-agent-fact",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_response": [{ "type": "text", "text": rows }],
    })
    .to_string()
}

/// The mediated call the fact gates.
const PR_CREATE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --draft"}}"#;

#[test]
fn the_agent_sourced_fact_loop_closes_end_to_end() {
    let dir = common::Fixture::new("agent-fact-loop")
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();

    // 1. The gate has no fact, so it denies — and the deny carries the COMMAND to
    //    run, built from the declared fact rather than from the row's prose.
    let denied = run_hook_in(&dir, "exit-code", PR_CREATE, false);
    assert_eq!(denied.status.code(), Some(2), "a missing fact must deny");
    let reason = common::stderr(&denied);
    // CLOUD-1286 moved the command one hop out, and this case is what proves the
    // hop lands: the loop's whole content is that the agent runs the EXACT
    // string the record is verified against, so a dereference that lost it would
    // be a broken loop rather than a shorter line.
    assert!(
        reason.contains("claim-not-raced"),
        "the deny names the row that refused; got: {reason}"
    );
    let explained = batten_with(&dir, &["policy", "explain", "claim-not-raced"], &[]);
    assert_eq!(explained.status.code(), Some(0), "the row resolves");
    assert!(
        String::from_utf8_lossy(&explained.stdout)
            .contains("gh pr list --state open --json headRefName"),
        "the hop must reach the command whose output will be accepted; got: {}",
        String::from_utf8_lossy(&explained.stdout)
    );

    // 2. The agent runs it. The harness hands the buffer back.
    let recorded = run_hook_in(
        &dir,
        "exit-code",
        &post_tool("gh pr list --state open --json headRefName", "[]"),
        false,
    );
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "a post-tool event is never a deny channel"
    );

    // 3. The retry decides from the fact. `[]` is "it ran and there are none" —
    //    an ANSWER, and the one a never-ran must never collapse into.
    let allowed = run_hook_in(&dir, "exit-code", PR_CREATE, false);
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "the recorded fact must satisfy the check; stderr: {}",
        common::stderr(&allowed)
    );
}

#[test]
fn a_buffer_from_another_command_never_becomes_the_fact() {
    // THE residual attack this channel carries, over the binary. The agent picks
    // WHICH command runs — it does not author what the output says — so a fact
    // keyed to a `Fix::Run` nobody verifies is CLOUD-526's forgery gradient
    // rebuilt on a new surface. `echo '[]'` is the convenient answer.
    let dir = common::Fixture::new("agent-fact-forged")
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();

    run_hook_in(&dir, "exit-code", &post_tool("echo '[]'", "[]"), false);

    let still_denied = run_hook_in(&dir, "exit-code", PR_CREATE, false);
    assert_eq!(
        still_denied.status.code(),
        Some(2),
        "a buffer from a command nobody asked for must not satisfy the check"
    );
}

/// The DECLARATION is checked at the recording site, not merely offered in config
/// (CLOUD-993).
///
/// This is the case that catches the field being dead. `rows_declared` existed and
/// `record_agent_fact` still called `rows_in`, so a row could declare
/// `json-array`, its command could emit prose, and the boundary would record one
/// opaque row — satisfying the check and making a `rows == 0` predicate silently
/// unsatisfiable. Every case in `tests/facts.rs` passed, because every one of them
/// calls `rows_declared` directly and the function was never the thing at risk:
/// the WIRING was, exactly as `.claude/rules/policy-modules.md` records for a
/// module reading a key the engine never builds.
///
/// So it goes through the binary, and it discriminates: under `rows_in` the prose
/// records `Is(1)` and the retry is ALLOWED, which is the observed red this case
/// was written against.
#[test]
fn a_buffer_that_breaks_the_declared_shape_records_nothing() {
    let dir = common::Fixture::new("agent-fact-shape")
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();

    // The declared command, run by the agent, answering with prose rather than the
    // `json-array` the row promises — a `gh` that printed an auth error, a wrapper
    // that annotated its own output, a tool that changed its default format.
    run_hook_in(
        &dir,
        "exit-code",
        &post_tool(
            "gh pr list --state open --json headRefName",
            "gh: could not determine the current repository",
        ),
        false,
    );

    let still_denied = run_hook_in(&dir, "exit-code", PR_CREATE, false);
    assert_eq!(
        still_denied.status.code(),
        Some(2),
        "prose under a `json-array` declaration must record nothing, not one opaque row"
    );
}

/// The post-tool payload from a tool that carries NO command.
///
/// Every structured tool is this shape — `Write`, `Edit`, `Read`, every MCP call.
/// `tool_input` names no `command`, so `Envelope::command` is empty while the
/// response is present and non-empty, which is exactly the pair CLOUD-919's guard
/// had to stop conflating.
#[cfg(unix)]
fn post_tool_commandless(response: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-commandless",
        "cwd": "/repo",
        "tool_name": "Write",
        "tool_input": { "file_path": "/repo/notes.md" },
        "tool_response": response,
    })
    .to_string()
}

/// [`run_hook_in`] with the state root pinned.
///
/// Load-bearing since CLOUD-919, and its absence is what let the predecessor of
/// the test below stay green over a build that stored the bytes: with no state
/// root pinned, a capture lands under the AMBIENT root while the assertion
/// searches the fixture, so the message named a place it never looked.
#[cfg(unix)]
fn run_hook_state(
    dir: &std::path::Path,
    home: &std::path::Path,
    harness: &str,
    payload: &str,
) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", harness])
        .env_remove("BATTEN_HOOK_BYPASS")
        .env_remove("BATTEN_GH_GUARD_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    common::state_home(&mut command, home);
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait_with_output().expect("run batten hook")
}

/// Every file under `root`, recursively, whose contents carry `needle`.
///
/// Recursive on purpose: `read_dir` is one level deep, and a subdirectory entry
/// read as a file yields nothing, so a single level of nesting would silently
/// empty the assertion this feeds.
#[cfg(unix)]
fn files_carrying(root: &std::path::Path, needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // The ONE place the bytes may live, excluded by name rather than by a
        // computed path: the store's location is `state`'s to decide, and a test
        // recomputing it would assert its own copy of that decision.
        if dir.file_name().is_some_and(|name| name == "captures") {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if fs::read(&path)
                .is_ok_and(|body| String::from_utf8_lossy(&body).contains(needle))
            {
                found.push(path.display().to_string());
            }
        }
    }
    found.sort_unstable();
    found
}

/// The one response handle in the store.
#[cfg(unix)]
fn response_handle(repo: &std::path::Path, home: &std::path::Path) -> String {
    let listed = run_capture(repo, home, &["list", "--stream", "response"]);
    assert_eq!(
        listed.status.code(),
        Some(0),
        "listing the response captures"
    );
    stdout(&listed)
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("a listed response handle; got: {}", stdout(&listed)))
        .to_owned()
}

/// CLOUD-776's assertion, re-scoped by CLOUD-919 rather than deleted.
///
/// The predecessor was named `no_byte_of_the_result_buffer_is_emitted_or_stored`,
/// and its second half became FALSE the moment CLOUD-919 landed: the bytes are
/// stored, deliberately, because a response that cannot be re-read has to be
/// obtained by re-running a command that may not be idempotent. What survives is
/// the half rule 4 has always been about — EMISSION — and it survives on four
/// channels rather than the two the predecessor checked.
///
/// The capture store is excluded BY NAME and everything else under the pinned
/// state root is asserted clean, which is the negative-space half: a later change
/// spraying the bytes into the calls log, a receipt or a lock file reds this.
///
/// `cfg(unix)` where the predecessor was not, because the assertion now reaches
/// the suite's capture helpers and those are unix-gated. The Windows triple is
/// type-checked rather than run (CLOUD-397), so what it loses is a run it never
/// had; what it must not gain is a helper nothing calls, which `cross-check`
/// reports as denied dead code.
#[cfg(unix)]
#[test]
fn no_byte_of_the_result_buffer_reaches_stdout_stderr_a_json_document_or_a_receipt() {
    // Rule 4 end to end, and load-bearing rather than formal here: a command's
    // stdout can carry anything, which makes the result buffer the likeliest
    // thing in the envelope to hold a secret.
    let root = scratch("agent-fact-secret");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    let secret = "ghp_PLANTEDSECRETVALUE";
    let rows = format!("[{{\"headRefName\":\"{secret}\"}}]");
    let recorded = run_hook_state(
        &dir,
        &home,
        "exit-code",
        &post_tool("gh pr list --state open --json headRefName", &rows),
    );

    // Not on either channel of the call that carried it...
    assert!(!String::from_utf8_lossy(&recorded.stdout).contains(secret));
    assert!(!common::stderr(&recorded).contains(secret));

    // ...nor in any `-J` document, which the predecessor never checked at all.
    // A pointer surface that renders the payload under `--json` would be rule 4's
    // violation on the one channel a machine reader consumes.
    for args in [
        vec!["list", "-J"],
        vec!["list", "--calls", "-J"],
        vec!["show", "-J"],
    ] {
        let rendered = run_capture(&dir, &home, &args);
        assert!(
            !String::from_utf8_lossy(&rendered.stdout).contains(secret),
            "the buffer reached `capture {}` on stdout",
            args.join(" ")
        );
    }
    // The PINNED root, not the process default: `doctor` reading a different
    // state root than the capture wrote to would pass this over a real leak.
    let mut doctor = batten();
    doctor.args(["doctor", "-J"]).current_dir(&dir);
    common::state_home(&mut doctor, &home);
    let doctored = doctor.output().expect("run batten doctor");
    assert!(!String::from_utf8_lossy(&doctored.stdout).contains(secret));

    // ...and nowhere the recording wrote. The fact record carries a COUNT, and the
    // ONE place the bytes may live is the capture store, excluded by name.
    let receipts = files_carrying(&dir.join(".git/batten-receipts"), secret);
    assert!(
        receipts.is_empty(),
        "the buffer reached a receipt under {}: {receipts:?}",
        dir.join(".git/batten-receipts").display()
    );
    let elsewhere = files_carrying(&home, secret);
    assert!(
        elsewhere.is_empty(),
        "the buffer reached the state root outside the capture store: {elsewhere:?}"
    );
}

/// THE POSITIVE TWIN, and it is what makes the absence half a contract.
///
/// A build that captured nothing passes every assertion above. This one fails on
/// it, and fails just as loudly on a build that captured the bytes and mangled
/// them — the comparison is over `Vec<u8>`, never over a `String` obtained by a
/// lossy conversion, which would pass over exactly the corruption `--raw` exists
/// to rule out.
#[cfg(unix)]
#[test]
fn the_captured_response_replays_byte_identical_to_the_bytes_the_host_sent() {
    let root = scratch("agent-fact-replay");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    // The same planted secret as the absence half, from one place, so the two
    // cannot drift about what was planted where.
    let secret = "ghp_PLANTEDSECRETVALUE";
    let rows = format!("[{{\"headRefName\":\"{secret}\"}}]");
    run_hook_state(
        &dir,
        &home,
        "exit-code",
        &post_tool("gh pr list --state open --json headRefName", &rows),
    );

    let handle = response_handle(&dir, &home);
    let replayed = run_capture(&dir, &home, &["show", &handle, "--raw"]);
    assert_eq!(replayed.status.code(), Some(0), "replaying {handle}");
    assert_eq!(
        replayed.stdout,
        rows.as_bytes(),
        "the replay is not byte-identical to what the host sent"
    );
}

/// CLOUD-919's guard, and the reason it is the response member rather than the
/// command.
///
/// `!command.is_empty()` is CLOUD-776's guard and it is correct THERE — a fact is
/// keyed to a command. Carried onto the capture it silently drops every
/// structured tool, which is most of the hot path. Restoring the conjunct makes
/// the capture vanish entirely and reds this.
#[cfg(unix)]
#[test]
fn a_response_from_a_tool_that_carries_no_command_is_still_captured() {
    let root = scratch("capture-commandless");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    let written = "wrote 3 lines to notes.md";
    let recorded = run_hook_state(&dir, &home, "exit-code", &post_tool_commandless(written));
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "a post-tool call is never a verdict"
    );

    let handle = response_handle(&dir, &home);
    let replayed = run_capture(&dir, &home, &["show", &handle, "--raw"]);
    assert_eq!(replayed.stdout, written.as_bytes());
}

/// A post-tool payload whose response arrives under `alias`.
///
/// The three spellings are `decode`'s alias walk, and a capture that reads only
/// one of them is a capture that works on one host.
#[cfg(unix)]
fn post_tool_aliased(alias: &str, response: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-aliased",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": { "command": "true" },
        alias: response,
    })
    .to_string()
}

/// All three aliases reach the capture, and identical content is ONE blob.
///
/// Both halves in one case on purpose: the alias walk and the content addressing
/// are the two things that could make three calls look like fewer or more than
/// they are, and they fail in opposite directions — a missed alias loses a row, a
/// broken digest mints a blob per call.
#[cfg(unix)]
#[test]
fn all_three_response_aliases_reach_the_capture() {
    let root = scratch("capture-aliases");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    let body = "the same bytes by three names";
    for alias in ["tool_response", "toolResponse", "tool_result"] {
        let recorded = run_hook_state(&dir, &home, "exit-code", &post_tool_aliased(alias, body));
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "a post-tool call is never a verdict ({alias})"
        );
    }

    let listed = run_capture(&dir, &home, &["list", "--stream", "response"]);
    assert_eq!(
        stdout(&listed).lines().count(),
        1,
        "identical content under three aliases must be one blob; got: {}",
        stdout(&listed)
    );
    let calls = run_capture(&dir, &home, &["list", "--calls", "-J"]);
    let rows: serde_json::Value =
        serde_json::from_slice(&calls.stdout).expect("the call view is JSON");
    let rows = rows.as_array().expect("a calls array");
    assert_eq!(
        rows.len(),
        3,
        "three calls must be three rows — one alias never reached the capture"
    );

    let handle = response_handle(&dir, &home);
    let replayed = run_capture(&dir, &home, &["show", &handle, "--raw"]);
    assert_eq!(replayed.stdout, body.as_bytes());
}

/// An MCP content-block response: the CONTENT is the capture, the FRAMING is the
/// row.
///
/// That split is what makes byte-identical replay possible at all — interleaving
/// the block count or the per-block type into the bytes would make the replay a
/// document the host never sent. Fidelity is `decoded-content` rather than
/// `lexical-bytes`, and the assertion is on the token: CLOUD-917 reserves
/// "byte-perfect" for a fidelity this call site cannot reach, because `decode`
/// hands `run_hook` an already-parsed value.
#[cfg(unix)]
#[test]
fn an_mcp_content_block_response_is_captured_at_the_fidelity_it_declares() {
    let root = scratch("capture-content-blocks");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-mcp",
        "cwd": "/repo",
        "tool_name": "mcp__linear__get_issue",
        "tool_input": { "id": "CLOUD-919" },
        "tool_response": [
            { "type": "text", "text": "first block" },
            { "type": "text", "text": " and second" },
        ],
    })
    .to_string();
    run_hook_state(&dir, &home, "exit-code", &payload);

    let handle = response_handle(&dir, &home);
    let replayed = run_capture(&dir, &home, &["show", &handle, "--raw"]);
    assert_eq!(
        replayed.stdout, b"first block and second",
        "the blocks must concatenate in host order, with no framing interleaved"
    );

    let calls = run_capture(&dir, &home, &["list", "--calls", "-J"]);
    let rows: serde_json::Value =
        serde_json::from_slice(&calls.stdout).expect("the call view is JSON");
    // SELECTED BY TOOL, NEVER BY INDEX (CLOUD-1260). The `--raw` replay above is
    // itself a recorded escape now, so the log holds two rows — and the listing
    // sorts by `(session, order)`, which `capture::find_in`'s own doc says is not
    // chronological ACROSS sessions. The escape carries no host session, so it
    // sorts ahead of this one's `sess-mcp` and `rows[0]` silently became the
    // wrong row. The index was always an assumption the log never promised; this
    // asks for the row the case is about.
    let row = rows
        .as_array()
        .expect("a calls array")
        .iter()
        .find(|row| row["tool"] == "mcp__linear__get_issue")
        .expect("the recorded response is in the call log");
    assert_eq!(row["fidelity"], "decoded-content");

    // THE ESCAPE IS RECORDED WHEN SPENT (CLOUD-1260), and this is where that is
    // asserted rather than described. `capture show --raw` is the deliberate
    // route to an unreduced payload and it STAYS open — a single-purpose,
    // visible retrieval is not the failure mode, 973 reflexive full-body reads
    // are. What makes the invariant measurable rather than notional is that
    // spending it leaves a row, so a later count can say "every retrieval
    // appears as a recorded escape" instead of asserting an absence.
    let escape = rows
        .as_array()
        .expect("a calls array")
        .iter()
        .find(|row| row["source"] == "raw-escape")
        .expect("a spent `--raw` leaves a record");
    assert_eq!(
        escape["tool"], "22",
        "the row carries the byte COUNT that left the store, never a byte of it"
    );
}

/// A shape the decoder cannot read is COULD-NOT-LOOK, never zero bytes.
///
/// `facts::rows_in`'s own distinction, on the capture surface: recording an
/// unreadable shape as an empty response would make "the tool said nothing" and
/// "we could not read what it said" one record — and the empty case is a real
/// record of zero bytes, so the collapse would be silent.
#[cfg(unix)]
#[test]
fn a_response_shape_the_decoder_cannot_read_is_recorded_as_such() {
    let root = scratch("capture-unreadable-shape");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    // A number: none of the three shapes the decoder declares.
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-shape",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": { "command": "true" },
        "tool_response": 42,
    })
    .to_string();
    let recorded = run_hook_state(&dir, &home, "exit-code", &payload);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "an unreadable shape is not a verdict"
    );

    let calls = run_capture(&dir, &home, &["list", "--calls", "-J"]);
    let rows: serde_json::Value =
        serde_json::from_slice(&calls.stdout).expect("the call view is JSON");
    let row = &rows.as_array().expect("a calls array")[0];
    assert_eq!(row["fidelity"], "unavailable");
    assert_eq!(row["absent"], "capture-response-shape-unreadable");
    assert!(
        row.get("digest").is_none(),
        "an unread shape must not claim a capture"
    );
    // And no blob was minted, which is what "never zero bytes" means here.
    assert!(stdout(&run_capture(&dir, &home, &["list", "--stream", "response"])).is_empty());
}

/// A store that cannot be written leaves the hook at exit 0 with a reason id.
///
/// Driven through the state-root seam rather than through permission bits: this
/// sandbox runs as root, so a mode-based fixture asserts its own premise before
/// its conclusion (`.claude/rules/rust.md`, CLOUD-249). A state root that is a
/// REGULAR FILE fails `create_dir_all` with `ENOTDIR` for root too.
#[cfg(unix)]
#[test]
fn a_store_that_cannot_be_written_leaves_exit_zero_and_a_reason_id() {
    let root = scratch("capture-unwritable");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();
    // `state_home` resolves `<home>/data`; make that a file rather than a dir.
    fs::write(home.join("data"), b"not a directory").expect("plant a regular file");

    let recorded = run_hook_state(
        &dir,
        &home,
        "exit-code",
        &post_tool_commandless("bytes nobody can store"),
    );
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "NO Batten failure may block a tool call — a storage failure least of all"
    );
    let reported = common::stderr(&recorded);
    assert!(
        reported.contains("capture-"),
        "the failure must reach the advisory channel as a reason id; got: {reported}"
    );
    // Pointer-only: the reason id, never the bytes it could not store.
    assert!(!reported.contains("bytes nobody can store"));
}

/// CLOUD-251's shape on a new surface: "the tool returned nothing" and "nobody
/// looked" must not become one record.
///
/// Compared as the two `-J` rows rather than as a count, because a count is
/// exactly what cannot tell them apart. The empty capture carries a digest and
/// the absence carries a reason id, so they differ in WHICH KEYS EXIST — and
/// collapsing them, dropping either row, or giving the absence a digest all red
/// this.
#[cfg(unix)]
#[test]
fn an_empty_response_and_an_absent_one_never_produce_the_same_record() {
    let root = scratch("capture-empty-vs-absent");
    let dir = common::Fixture::at(root.join("repo"))
        .config(AGENT_FACT_CONFIG)
        .git()
        .base_commit()
        .build();
    let home = common::Fixture::at(root.join("home")).build();

    // Present and empty: a real capture of zero bytes.
    run_hook_state(&dir, &home, "exit-code", &post_tool_commandless(""));
    // Absent: the member is not there at all.
    let absent = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-commandless",
        "cwd": "/repo",
        "tool_name": "Write",
        "tool_input": { "file_path": "/repo/notes.md" },
    })
    .to_string();
    run_hook_state(&dir, &home, "exit-code", &absent);

    let listed = run_capture(&dir, &home, &["list", "--calls", "-J"]);
    assert_eq!(listed.status.code(), Some(0), "listing the call log");
    let listing: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("the call view is JSON");
    let rows = listing
        .as_array()
        .unwrap_or_else(|| panic!("a calls array; got: {listing}"));
    assert_eq!(rows.len(), 2, "two calls became {} row(s)", rows.len());
    let with_digest = rows
        .iter()
        .filter(|row| row.get("digest").is_some())
        .count();
    assert_eq!(with_digest, 1, "the empty capture must carry a digest");
    // The VALUES, not merely the keys: a row carrying a storage-failure reason
    // satisfies a presence check while recording the wrong fact about the call,
    // and a reason id exists to send a reader to ONE remedy.
    let absence = rows
        .iter()
        .find(|row| row.get("absent").is_some())
        .unwrap_or_else(|| panic!("an absence row; got: {rows:?}"));
    assert_eq!(absence["absent"], "capture-response-absent");
    assert_eq!(absence["fidelity"], "unavailable");
    assert!(
        absence.get("digest").is_none(),
        "an absence must not claim a capture"
    );
    assert_ne!(rows[0], rows[1], "the two records collapsed into one shape");
}

/// CLOUD-402: `--help` leads with the crate manifest's description, and there is
/// no second copy of it in the source.
///
/// `ROOT.about` was a literal restating `Cargo.toml`'s `description`, and one of
/// the two moved on while the other kept the retired category claim. The fix is
/// derivation rather than a second copy, so the unit-level equality this row's
/// §7 asks for would now be a tautology. What can still fail is the wiring: that
/// clap actually renders the manifest string as the lead of `--help`, which is
/// the surface a consumer's agent reads first. Reintroducing any literal there
/// fails this — and it failed against the literal that was there.
#[test]
fn help_leads_with_the_crate_description() {
    let dir = common::scratch("help-lead");
    let out = common::run(&dir, &["--help"]);
    assert_eq!(out.status.code(), Some(0), "--help is an answer");

    let description = env!("CARGO_PKG_DESCRIPTION");
    let rendered = common::stdout(&out);
    let lead = rendered.lines().next().unwrap_or_default();
    assert_eq!(
        lead, description,
        "the first line of --help is the manifest description, not a copy of it"
    );
}

/// CLOUD-605: a tracked instruction prescribing the denied commit identity is a
/// violation, and the same tree without it is clean.
///
/// `[attribution] identity_deny` refuses what a COMMIT carries and has never
/// failed to. `no-denied-identity-prescribed` refuses what a tracked FILE
/// prescribes — the user-level hook's remedy, copied into the tree, where it
/// would become a standing second authority telling the next reader to do the
/// thing this repository denies.
///
/// The banned literal can be written as source text here for the same reason the
/// portability case can: the row's glob is `**/*.md`, and this file is `.rs`.
#[test]
fn a_tracked_instruction_may_not_prescribe_the_denied_commit_identity() {
    let committed = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml");
    let contents = fs::read_to_string(&committed).expect("read batten.toml");

    // The prescription, spelled the way the hook spells it. Line 2, so the
    // pointer proves the finding is anchored rather than reported file-wide.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("denied-identity-dirty"),
    );
    let dirty = repo_with_config("denied-identity-dirty", &contents);
    committed_budget_surfaces(&dirty);
    let home = committed_config_fixture_git(&dirty);
    fs::write(
        dirty.join("HOWTO.md"),
        "# how to commit\n\
         run `git config user.email noreply@anthropic.com` then amend\n",
    )
    .expect("write fixture instruction");

    // `check --rule`, not `enforce`. The unnarrowed read-effect verb does refuse
    // this config outright — it carries a spawning kind — but `--rule` selects
    // the row BEFORE that refusal is reached, and `no-denied-identity-prescribed`
    // is not one of the three `kind = "command"` rows. `mise.toml` already relies
    // on this against these same committed bytes: `check --rule prose-only`,
    // `--rule filed-here`, `--rule memory-graph`.
    //
    // This comment used to say `enforce`, "and every sibling test over the
    // committed bytes takes the same verb for the same reason". True of an
    // unnarrowed `check` and over-general as written: it sent the whole family
    // through the 103-rule ruleset to assert one row. Measured on Windows CI,
    // this case alone was 305s of a 1482s suite.
    //
    // The narrowing is not a weakening. Both arms survive, the clean one
    // included, and the asserted stdout is now the output of the rule under test
    // rather than of all 103 happening to produce that line.
    let output = batten()
        .arg("check")
        .arg("--rule")
        .arg("no-denied-identity-prescribed")
        .current_dir(&dirty)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(2),
        "an instruction prescribing the denied identity is a policy violation"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "HOWTO.md:2 no-denied-identity-prescribed\n",
        "one pointer, and the matched line is never echoed"
    );

    // The discriminator. Stating the precedence rather than the command is what
    // the rule leaves room for — otherwise the row would forbid the very prose
    // AGENTS.md rule 8 and `.claude/rules/commits.md` are made of.
    let _ = fs::remove_dir_all(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("denied-identity-clean"),
    );
    let clean = repo_with_config("denied-identity-clean", &contents);
    committed_budget_surfaces(&clean);
    let home = committed_config_fixture_git(&clean);
    fs::write(
        clean.join("HOWTO.md"),
        "# how to commit\n\
         a harness asking for a vendor no-reply committer is refused; the\n\
         authority is `[attribution] identity_deny`.\n",
    )
    .expect("write fixture instruction");

    let output = batten()
        .arg("check")
        .arg("--rule")
        .arg("no-denied-identity-prescribed")
        .current_dir(&clean)
        .state_home(&home)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten enforce");
    assert_eq!(
        output.status.code(),
        Some(0),
        "naming the authority is not prescribing the identity"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "",
        "a clean tree renders nothing"
    );
}

// --- the config deprecation grammar (CLOUD-360) -----------------------------

/// §7(d) over the COMPILED BINARY: the removal gate answers, and its three exit
/// codes are the contract §5 states.
///
/// The unannounced-removal arm cannot be built here — it needs a schema key to
/// vanish, which is a change to the config TYPES rather than to a fixture — so it
/// was observed against the real gate instead: renaming `capture` to
/// `capture_v2` in the config surface (a change that compiles and passes every
/// test) made `mise run config-deprecations` exit 2 naming `capture`, and
/// declaring a `DEPRECATED_KEYS` row for it returned the gate to 0. Both arms,
/// so the gate requires the ANNOUNCEMENT rather than the absence of change.
///
/// What this case holds is the half a fixture can: the clean verdict against a
/// real published baseline, and the could-not-look refusal.
#[test]
fn the_removal_gate_reports_a_verdict_or_refuses_to_guess() {
    let dir = repo_with_committed_config("deprecations-verdict");

    // A ref that carries no schema is COULD NOT LOOK — exit 3, never 0.
    // Reporting "no key was removed" having compared nothing is the vacuous pass
    // CLOUD-251 names, and it is the one outcome this gate must never produce.
    let absent = batten_with(
        &dir,
        &["config", "deprecations", "refs/tags/nope-not-a-tag"],
        &[],
    );
    assert_eq!(
        absent.status.code(),
        Some(3),
        "an unreadable baseline is exit 3: {}",
        String::from_utf8_lossy(&absent.stderr)
    );
    assert!(
        absent.stdout.is_empty(),
        "no verdict is emitted when nothing could be compared"
    );

    // And the baseline is REQUIRED: a gate that picked its own could quietly
    // choose one that makes it pass.
    let unbaselined = batten_with(&dir, &["config", "deprecations"], &[]);
    assert_eq!(
        unbaselined.status.code(),
        Some(1),
        "omitting the baseline is a usage error, not a default"
    );
}

/// §7(a)-(c) over the compiled binary: the three config-side outcomes, and the
/// one that matters is that they are TOLD APART.
///
/// The window itself is exercised by `config::tests`, which supply a table —
/// `DEPRECATED_KEYS` ships empty on purpose, and inventing a row so a fixture had
/// something to find would put a key in the published schema no consumer should
/// write. What the binary can be held to is the boundary those cases cannot see:
/// that an unknown key is still refused, and refused with a diagnostic that does
/// not borrow the deprecation vocabulary.
#[test]
fn an_unknown_key_is_refused_without_borrowing_the_deprecation_vocabulary() {
    let dir = scratch("deprecations-unknown");
    fs::create_dir_all(&dir).expect("create dir");
    fs::write(
        dir.join("batten.toml"),
        "version = 1\n[not_a_batten_key]\nvalue = 1\n",
    )
    .expect("write the fixture config");

    let output = batten_with(&dir, &["config", "show"], &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "strictness is unchanged: an unknown key is still a hard error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("deprecated") && !stderr.contains("expires"),
        "an unknown key must not read as a deprecated one — the two remedies \
         differ, and collapsing them makes the window invisible: {stderr}"
    );
}

/// The same config with the `returns` field removed (CLOUD-993).
///
/// A separate constant rather than a `replace` on the good one, so the refusal is
/// asserted against a literal a reader can see is missing the field.
const AGENT_FACT_CONFIG_NO_RETURNS: &str = r#"version = 1

[[fact]]
name = "claimed-key"
command = "gh pr list --state open --json headRefName"

[[rule]]
id = "claim-not-raced"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr create"
checks = ["claimed-key"]
key = "branch"
reason = "unused: an agent-sourced check builds its fix from the declared command"
"#;

#[test]
fn a_fact_row_that_states_no_returns_is_refused_at_load_over_the_binary() {
    // CLOUD-993's load-time half, asserted where a consumer meets it rather than
    // over the struct. The field is required with no default precisely so this is
    // a refusal and not an inherited contract — and the refusal has to be exit 1,
    // a usage error, never the policy verdict 2: a malformed config is a fact
    // about the config and must not read as a decision about the call.
    //
    // Found the honest way: this constant is the OLD fixture, and it began
    // failing `a_buffer_from_another_command_never_becomes_the_fact` with
    // Some(1) where Some(2) was expected the moment `returns` became required.
    // That is the mechanism working, so it is pinned rather than only repaired.
    let dir = common::Fixture::new("agent-fact-no-returns")
        .config(AGENT_FACT_CONFIG_NO_RETURNS)
        .git()
        .base_commit()
        .build();

    let refused = run_hook_in(&dir, "exit-code", PR_CREATE, false);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a `[[fact]]` row with no `returns` is a usage error, not a policy verdict; stderr: {}",
        common::stderr(&refused)
    );
    // Pointer-only, and this is the clause worth asserting rather than trusting:
    // the message names the missing FIELD, and carries no command. A consumer's
    // argv may hold anything, so a config error that echoed it would leak.
    let reason = common::stderr(&refused);
    assert!(
        reason.contains("returns"),
        "the refusal must name the field the row omitted; got: {reason}"
    );
    assert!(
        !reason.contains("gh pr list"),
        "a config error must not echo the declared command; got: {reason}"
    );
}

// --- resolving a capture by key (CLOUD-1121) ---------------------------------
//
// The store is seeded by driving `batten hook` at the post-tool event, never by
// writing the blob and the log line by hand. That is the whole point of these
// cases: a fixture built to the shape the READER expects proves nothing about
// whether the WRITER emits it, and this repository has already shipped one gate
// whose suite agreed with its own bug for exactly that reason (`claim-check`'s
// baseline, repaired in this same change). So every case below asks the engine
// to record the capture and then asks the resolver to find it.

/// A `PostToolUse` envelope carrying a tool result, which is what makes the
/// engine write a `Stream::Response` capture and a `CallRow` for it.
///
/// The document is wrapped in the **MCP content-block shape** — an array of
/// `{"type":"text","text":…}` — because that is what a host actually hands over
/// for an MCP tool call, and `capture::decode_response` reads exactly three
/// shapes of which a bare result object is not one. Getting this wrong is not a
/// cosmetic fixture detail: the first draft of these cases passed a bare object,
/// the engine recorded `response-shape-unreadable` with no digest, and the three
/// NEGATIVE cases still went green — because a resolver that can never resolve
/// satisfies every assertion about what it must not resolve. That is the false
/// green this suite exists to refuse, so the positive cases are what hold it.
#[cfg(unix)]
fn post_tool_result(tool: &str, document: &serde_json::Value) -> String {
    serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "find-session",
        "tool_name": tool,
        "tool_input": {},
        "tool_response": [{ "type": "text", "text": document.to_string() }],
    })
    .to_string()
}

/// Drive one post-tool event against an isolated state home, so the capture the
/// engine writes lands in this test's store and nowhere else.
#[cfg(unix)]
fn record_response(dir: &Path, home: &Path, tool: &str, document: &serde_json::Value) {
    let mut command = batten();
    let output = command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .env_remove("BATTEN_HOOK_BYPASS")
        .state_home(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = output.spawn().expect("spawn batten hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(post_tool_result(tool, document).as_bytes())
        .expect("write payload");
    let done = child.wait_with_output().expect("run batten hook");
    assert!(
        done.status.success(),
        "recording a post-tool response must not fail: {}",
        String::from_utf8_lossy(&done.stderr)
    );
}

/// `batten capture find` in a fixture, against an isolated state home.
#[cfg(unix)]
fn find_in_repo(dir: &Path, home: &Path, args: &[&str]) -> Output {
    batten()
        .current_dir(dir)
        .args(["capture", "find"])
        .args(args)
        .state_home(home)
        .output()
        .expect("run batten capture find")
}

#[cfg(unix)]
#[test]
fn a_stored_response_is_resolved_by_the_key_it_carries() {
    // The premise of the whole row: the bytes were written when the read
    // happened, so a consumer can have them again without a second fetch AND
    // without a handle to look up first.
    let dir = repo_with_gh_policy("find-by-key");
    let home = scratch("find-by-key-home");
    fs::create_dir_all(&home).expect("create home");
    record_response(
        &dir,
        &home,
        "mcp__tracker__get_issue",
        &serde_json::json!({ "id": "KEY-1", "description": "a body" }),
    );

    let output = find_in_repo(&dir, &home, &["KEY-1", "--tool", "get_issue"]);
    assert!(output.status.success(), "a stored response must resolve");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("response:"),
        "the pointer must name the capture: {stdout}"
    );

    // The property the row is worth landing for, asserted rather than hoped: the
    // pointer carries no byte of the body it points at.
    assert!(
        !stdout.contains("a body"),
        "the pointer must never carry the payload: {stdout}"
    );

    // And `--raw` is the one route by which the bytes leave, into a program's
    // stdin — which is what a board gate consumes.
    let raw = find_in_repo(&dir, &home, &["KEY-1", "--tool", "get_issue", "--raw"]);
    assert!(raw.status.success());
    let body: serde_json::Value =
        serde_json::from_slice(&raw.stdout).expect("--raw writes the stored document");
    assert_eq!(body["id"], "KEY-1");
}

#[cfg(unix)]
#[test]
fn an_empty_store_could_not_look_rather_than_reporting_a_clean_answer() {
    // THE ANTI-VACUITY CASE. Finding nothing is the reading that looks harmless
    // and is not: every caller is a gate about to decide over the payload, and a
    // gate handed nothing that exits 0 reports a clean row it never read.
    let dir = repo_with_gh_policy("find-empty-store");
    let home = scratch("find-empty-store-home");
    fs::create_dir_all(&home).expect("create home");

    let output = find_in_repo(&dir, &home, &["KEY-1", "--tool", "get_issue"]);
    assert_eq!(
        output.status.code(),
        Some(batten::ExitCode::Usage.code()),
        "an empty store must refuse, never resolve to nothing"
    );
    assert!(output.stdout.is_empty(), "a refusal emits no pointer");
}

#[cfg(unix)]
#[test]
fn a_response_from_a_tool_nobody_named_is_not_resolved() {
    // `--tool` is required precisely so a key is never resolved out of whatever
    // response happened to carry it. A comment mentioning the issue, a search
    // result, an unrelated tool echoing the id — none of those are the read.
    let dir = repo_with_gh_policy("find-wrong-tool");
    let home = scratch("find-wrong-tool-home");
    fs::create_dir_all(&home).expect("create home");
    record_response(
        &dir,
        &home,
        "mcp__tracker__list_issues",
        &serde_json::json!({ "id": "KEY-1" }),
    );

    let output = find_in_repo(&dir, &home, &["KEY-1", "--tool", "get_issue"]);
    assert_eq!(
        output.status.code(),
        Some(batten::ExitCode::Usage.code()),
        "a response from an unnamed tool must not satisfy the selector"
    );
}

#[cfg(unix)]
#[test]
fn the_newest_matching_response_wins_so_a_lint_after_a_write_sees_the_stored_body() {
    // CLOUD-1118's defect, in the route that supersedes the transcript one: a
    // lint run straight after a write must judge the body the tracker STORED,
    // and the write's own response is where that body appears. Recency is the
    // log's append order, so this is a fact about which call came last rather
    // than about a clock.
    let dir = repo_with_gh_policy("find-newest");
    let home = scratch("find-newest-home");
    fs::create_dir_all(&home).expect("create home");
    record_response(
        &dir,
        &home,
        "mcp__tracker__get_issue",
        &serde_json::json!({ "id": "KEY-1", "description": "before" }),
    );
    record_response(
        &dir,
        &home,
        "mcp__tracker__save_issue",
        &serde_json::json!({ "id": "KEY-1", "description": "after" }),
    );

    let raw = find_in_repo(
        &dir,
        &home,
        &[
            "KEY-1",
            "--tool",
            "get_issue",
            "--tool",
            "save_issue",
            "--raw",
        ],
    );
    assert!(raw.status.success());
    let body: serde_json::Value = serde_json::from_slice(&raw.stdout).expect("a stored document");
    assert_eq!(
        body["description"], "after",
        "the newest matching response must win"
    );

    // And the narrower selector still reaches the read, so `--tool` genuinely
    // discriminates rather than every row collapsing to the last one recorded.
    let narrowed = find_in_repo(&dir, &home, &["KEY-1", "--tool", "get_issue", "--raw"]);
    assert!(narrowed.status.success());
    let body: serde_json::Value =
        serde_json::from_slice(&narrowed.stdout).expect("a stored document");
    assert_eq!(body["description"], "before");
}

#[cfg(unix)]
#[test]
fn raw_and_json_are_refused_together_rather_than_one_winning() {
    // `capture show`'s rule, and for its reason: a raw byte stream and a
    // byte-stable JSON document are different contracts over one selection, and
    // resolving the pair silently is how a caller gets base64 where it wanted
    // bytes.
    let dir = repo_with_gh_policy("find-raw-json");
    let home = scratch("find-raw-json-home");
    fs::create_dir_all(&home).expect("create home");

    let output = find_in_repo(
        &dir,
        &home,
        &["KEY-1", "--tool", "get_issue", "--raw", "--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(batten::ExitCode::Usage.code()),
        "the two encodings must be refused together"
    );
}

#[cfg(unix)]
#[test]
fn resolving_never_returns_the_policy_verdict() {
    // §7 has no per-verb exception, and this verb renders no verdict at all. A
    // harness that read "no capture here" as a deny would be reading a fact
    // about a local store as a fact about the repository.
    let dir = repo_with_gh_policy("find-never-two");
    let home = scratch("find-never-two-home");
    fs::create_dir_all(&home).expect("create home");
    for args in [
        vec!["KEY-1", "--tool", "get_issue"],
        vec!["KEY-1", "--tool", "get_issue", "--raw", "--json"],
    ] {
        let output = find_in_repo(&dir, &home, &args);
        assert_ne!(
            output.status.code(),
            Some(batten::ExitCode::Violation.code()),
            "capture find must never mint the policy verdict: {args:?}"
        );
    }
}

// --- fail-closed isolation and the declared input-precondition ---------------
// CLOUD-126 and CLOUD-125. One mechanism seen from two sides: a gate that could
// not complete and a gate that declined to start both report, and neither is
// ever rendered as a pass.

/// A `forbid` row whose id and pattern the caller picks, so a fixture can carry
/// several rows that are identical but for which files they select.
fn forbid_row(id: &str, glob: &str) -> String {
    format!(
        "\n[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"{glob}\"\npattern = \"TODO\"\nseverity = \"deny\"\nscope = \"tree\"\n"
    )
}

/// A config error is **not** a gate fault, and isolation must not swallow it
/// into `3`.
///
/// The boundary this pins is the one that keeps the exit contract whole: every
/// sibling config error in this tree is exit `1`, and reporting one as `3` would
/// tell a caller "Batten could not answer" about a file they can fix. Asserted
/// here rather than left to `enforce_missing_binary_is_a_usage_error` alone
/// because that test would still pass if the code moved for the wrong reason.
#[test]
fn a_configuration_error_is_still_exit_one_under_isolation() {
    let dir = repo_with_config(
        "isolate-keeps-usage",
        "version = 1\n\n[[rule]]\nid = \"dyn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"batten-no-such-program-anywhere\"\nseverity = \"deny\"\nscope = \"tree\"\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");
    let output = run(&dir, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a program the config names and PATH lacks is a usage error: {}",
        stderr(&output)
    );
    assert_ne!(
        output.status.code(),
        Some(3),
        "containing a config error would move a landed contract from 1 to 3"
    );
}

/// A gate held back by a declared `requires_path` is **skipped** — not failed,
/// not errored — and says so.
#[test]
fn an_unmet_precondition_is_skipped_rather_than_failed_or_errored() {
    let dir = repo_with_config(
        "precondition-unmet",
        &format!(
            "version = 1\n{}requires_path = [\"vendor/generated.json\"]\n",
            forbid_row("needs-the-vendor-tree", "**/*.rs")
        ),
    );
    // A file the rule WOULD have fired on, so the skip is the only reason it
    // does not: without the precondition this fixture exits 2.
    fs::write(dir.join("lib.rs"), "TODO fix\n").expect("write source");

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a skip does not by itself change the exit code: {}",
        stderr(&output)
    );
    assert!(
        stdout(&output).is_empty(),
        "a skipped gate emits no finding: {}",
        stdout(&output)
    );
    let stderr = stderr(&output);
    assert!(
        stderr.contains("needs-the-vendor-tree") && stderr.contains("vendor/generated.json"),
        "the skip names its identifier and its unmet requirement: {stderr}"
    );
}

/// The clause that makes the skip honest rather than a quieter pass: a run of
/// only skipped gates is **byte-distinguishable** from a run of only passing
/// ones.
///
/// Both exit `0` and both print nothing on stdout, which is exactly why this
/// cannot be asserted there. The two fixtures are identical but for the one
/// declared column, so the difference measured is the disposition and nothing
/// else.
#[test]
fn a_skip_only_run_is_byte_distinguishable_from_a_pass_only_run() {
    let row = forbid_row("the-same-rule", "**/*.rs");
    let skipped = repo_with_config(
        "precondition-skip-only",
        &format!("version = 1\n{row}requires_path = [\"absent/input.json\"]\n"),
    );
    let passing = repo_with_config("precondition-pass-only", &format!("version = 1\n{row}"));
    for dir in [&skipped, &passing] {
        // Clean under the rule, so both runs are exit 0 with empty stdout and
        // the only channel left to tell them apart is the one under test.
        fs::write(dir.join("lib.rs"), "nothing here\n").expect("write source");
    }

    let skip_run = run(&skipped, &["check"]);
    let pass_run = run(&passing, &["check"]);
    assert_eq!(skip_run.status.code(), Some(0));
    assert_eq!(pass_run.status.code(), Some(0));
    assert_eq!(skip_run.stdout, pass_run.stdout, "both are clean on stdout");
    assert_ne!(
        skip_run.stderr, pass_run.stderr,
        "a run whose gates all skipped must not be byte-identical to one whose gates all passed"
    );

    // And on the data channel, for the consumer that reads neither stderr nor a
    // human line.
    let skip_json = run(&skipped, &["check", "--json"]);
    let pass_json = run(&passing, &["check", "--json"]);
    assert_ne!(
        skip_json.stdout, pass_json.stdout,
        "the -J document must distinguish them too"
    );
    let document: serde_json::Value =
        serde_json::from_slice(&skip_json.stdout).expect("-J stdout is JSON");
    assert_eq!(document["skipped"][0]["rule"], "the-same-rule");
    assert_eq!(document["skipped"][0]["requires"], "absent/input.json");
    assert!(
        pass_json.stdout.windows(7).all(|w| w != b"skipped"),
        "a run with nothing skipped emits no skipped key at all"
    );
}

/// The precondition is decided **before** the body, proven by a body that would
/// fail loudly if it were entered.
///
/// The `command` kind is the fixture because its body is the one that spawns: a
/// row naming a program `PATH` does not have is exit `1` the moment it runs, so
/// a clean `0` here is evidence the spawn never happened rather than evidence it
/// happened and found nothing.
#[test]
fn an_unmet_precondition_never_enters_the_body() {
    let dir = repo_with_config(
        "precondition-short-circuits",
        "version = 1\n\n[[rule]]\nid = \"would-spawn\"\nkind = \"command\"\nglob = \"**/*.rs\"\ncheck = \"batten-no-such-program-anywhere\"\nseverity = \"deny\"\nscope = \"tree\"\nrequires_path = [\"absent/input.json\"]\n",
    );
    fs::write(dir.join("lib.rs"), "x\n").expect("write source");

    let output = run(&dir, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the body must not run: the same row without the precondition is exit 1: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("would-spawn"),
        "the skip is still reported: {}",
        stderr(&output)
    );
}

/// A declared precondition that is **met** changes nothing.
///
/// The compatibility half, and the reason this column is additive: a row whose
/// inputs are present behaves exactly as it did before the column existed.
#[test]
fn a_met_precondition_lets_the_rule_run_normally() {
    let dir = repo_with_config(
        "precondition-met",
        &format!(
            "version = 1\n{}requires_path = [\"vendor/generated.json\"]\n",
            forbid_row("needs-the-vendor-tree", "**/*.rs")
        ),
    );
    fs::create_dir_all(dir.join("vendor")).expect("create vendor");
    fs::write(dir.join("vendor/generated.json"), "{}\n").expect("write input");
    fs::write(dir.join("lib.rs"), "TODO fix\n").expect("write source");

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a met precondition is not a filter: {}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "lib.rs:1 needs-the-vendor-tree\n");
}

/// A ratchet still fires on an empty match set, which the new skip must not
/// regress.
///
/// The engine deliberately evaluates a ratchet **before** the empty-match skip,
/// because for that one kind an empty match set means the working tree now
/// carries none of the files the base did — the maximal deletion the kind exists
/// to catch. The precondition gate sits above that ordering, so this pins that
/// it did not quietly become a second way to silence it.
#[test]
fn a_ratchet_declaring_no_precondition_is_untouched_by_the_new_gate() {
    let dir = Fixture::new("precondition-ratchet")
        .config(
            "version = 1\n\n[[rule]]\nid = \"tests-not-deleted\"\nkind = \"ratchet\"\nglob = \"**/*.rs\"\npattern = \"#[test]\"\ndirection = \"non_decreasing\"\nbase = \"HEAD\"\nseverity = \"deny\"\nscope = \"tree\"\nno_fix_reason = \"restore the tests, or waive the reduction deliberately\"\n",
        )
        .files(&[("lib.rs", "#[test]\nfn a() {}\n")])
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "base"]);
    // Delete every file the glob named: the ratchet's worst case, and the one it
    // must not read as "nothing to inspect".
    fs::remove_file(dir.join("lib.rs")).expect("delete the counted file");

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an empty match set is the maximal deletion, not a skip: {}",
        stderr(&output)
    );
}

// --- decidability is the bar to block (CLOUD-331) -----------------------------
// A rule may reach a blocking exit code only if its predicate DECIDES the
// question it claims to answer. A kind that approximates an open-ended question
// is advisory, and no flag promotes it — which is the half a severity axis
// cannot express, since `severity = "deny"` is exactly what such a row would
// carry today.

/// A `forbid` row over the same tree: a deciding kind, and the control that
/// proves the fixture would otherwise block.
const FORBID_CONFIG: &str = "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\nscope = \"tree\"\n";

/// A **deciding** kind blocks, end to end.
///
/// The other half — that an approximating kind cannot — is not reachable from a
/// config, and that is a property of the one approximating kind rather than a
/// gap in the test. `judge` carries ambient authority, so `check` refuses the
/// whole run before any classification happens, and under `enforce` a judge
/// outcome never becomes a `Finding` at all (`judge.rs` constructs none), so
/// nothing reaches `any_blocking` to be classified. The bound is exercised
/// where it can be: `rules::tests::an_approximating_row_cannot_block_through_any_flag`
/// composes
/// `decidability_of` with the fold directly.
#[test]
fn a_deciding_kind_over_the_same_tree_does_block() {
    let dir = repo_with_config("decidability-deciding", FORBID_CONFIG);
    fs::write(dir.join("lib.rs"), "TODO fix\n").expect("write source");

    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the control must block, or the approximating case proves nothing: {}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "lib.rs:1 no-todo\n");
}

/// Every kind carries a classification, and the vocabulary is total.
///
/// CLOUD-331's second acceptance clause. Asserted over `RuleKind::ALL` so a kind
/// added later cannot be silently unclassified — the `match` in `decidability`
/// stops compiling first, which is the stronger half, and this pins that the
/// answer is one of the two declared values rather than merely that it compiles.
#[test]
fn every_rule_kind_is_classified_and_only_one_approximates() {
    let approximating: Vec<&str> = RuleKind::ALL
        .iter()
        .filter(|kind| kind.decidability() == Decidability::Approximating)
        .map(|kind| kind.as_str())
        .collect();
    assert_eq!(
        approximating,
        vec!["judge"],
        "the authored classification moved; that is a decision, so change it here deliberately"
    );
    for kind in RuleKind::ALL {
        assert!(
            Decidability::ALL.contains(&kind.decidability()),
            "{} carries no classification",
            kind.as_str()
        );
    }
    // Only the deciding class may block, and that is what the fold consults.
    assert!(Decidability::Deciding.may_block());
    assert!(!Decidability::Approximating.may_block());
}
