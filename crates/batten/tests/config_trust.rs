//! End-to-end tests over the compiled binary for `--config-from <ref>`
//! (CLOUD-31).
//!
//! The property under test is the one that makes the flag load-bearing: a
//! branch that edits `batten.toml` to relax policy is **still judged by the base
//! ref**, so the change under review cannot lower the bar it is reviewed
//! against. Alongside it, the working-tree-vs-base delta names the weakening
//! pointer-only, so a human sees what was attempted.
//!
//! Every fixture is a real git repository with a base commit on `origin/main`
//! and a working tree edited on top — the shape of an actual pull request,
//! because the flag's whole subject is the difference between the two.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, git_in, scratch, stdout};

/// A pull-request-shaped fixture: `base` committed and pinned as `origin/main`,
/// then `working` written into the tree on top (committed, so the tree is clean
/// and only the *ref* differs).
///
/// Returns the repo path. `files` are extra files written into the working tree,
/// so a rule has something to fire on.
fn pr_fixture(name: &str, base: &str, working: &str, files: &[(&str, &str)]) -> PathBuf {
    Fixture::new(name)
        .config(base)
        .git()
        // Pin origin/main to the base commit: the trusted ref a PR is judged
        // against.
        .base_commit()
        .config(working)
        .files(files)
        .work_commit()
        .build()
}

fn run(repo: &Path, args: &[&str]) -> Output {
    common::run(repo, args)
}

/// A `forbid` rule at the given severity, banning `TODO` in `.rs` files.
fn rule(id: &str, severity: &str) -> String {
    format!(
        "\n[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"{severity}\"\n"
    )
}

// --- the acceptance: base policy judges the working tree ---------------------

#[test]
fn a_working_tree_that_deletes_a_rule_is_still_judged_by_base_policy() {
    // CLOUD-31's headline acceptance, in its most direct form: the branch
    // removes the rule that would catch it. Without `--config-from` that is a
    // clean run; with it, base policy still fires.
    let repo = pr_fixture(
        "trust-rule-deleted",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        "version = 1\n",
        &[("lib.rs", "fine\nTODO fix this\n")],
    );

    let unguarded = run(&repo, &["check"]);
    assert_eq!(
        unguarded.status.code(),
        Some(0),
        "the working-tree config has no rule, so an unguarded check is clean — \
         which is exactly the hole --config-from closes"
    );

    let guarded = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(
        guarded.status.code(),
        Some(2),
        "base policy must still fire: a violation is exit 2"
    );
    assert!(
        stdout(&guarded).contains("lib.rs:2 no-todo"),
        "the base rule's finding must be reported, got: {}",
        stdout(&guarded)
    );
}

#[test]
fn a_working_tree_that_weakens_protected_paths_is_judged_by_base_policy() {
    // The acceptance as the issue words it — the protected set, which CLOUD-37
    // defines and this mechanism defends.
    let repo = pr_fixture(
        "trust-protected-weakened",
        &format!(
            "version = 1\nprotected = [\"crates/**\", \"policy.toml\"]\n{}",
            rule("no-todo", "deny")
        ),
        "version = 1\nprotected = []\n",
        &[("lib.rs", "TODO\n")],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    // The delta names exactly the weakened keys, and nothing it did not weaken.
    assert!(
        text.contains("batten.toml:protected[crates/**] present→absent"),
        "got: {text}"
    );
    assert!(
        text.contains("batten.toml:protected[policy.toml] present→absent"),
        "got: {text}"
    );
    assert!(
        text.contains("batten.toml:rule[no-todo] present→absent"),
        "got: {text}"
    );
    assert!(
        text.contains("config-from origin/main: 3 weakened"),
        "got: {text}"
    );
}

#[test]
fn lowering_a_rules_severity_is_reported_and_still_judged_at_the_base_rank() {
    // The subtler weakening: the rule survives, rated down to `warn` so it
    // reports without failing. Base policy still rates it `deny`.
    let repo = pr_fixture(
        "trust-severity-lowered",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        &format!("version = 1\n{}", rule("no-todo", "warn")),
        &[("lib.rs", "TODO\n")],
    );
    assert_eq!(
        run(&repo, &["check"]).status.code(),
        Some(0),
        "a warn finding does not fail by itself — the bar the branch lowered to"
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("batten.toml:rule[no-todo].severity deny→warn"),
        "got: {}",
        stdout(&output)
    );
}

// --- the delta is pointer-only, byte-stable, and honest ----------------------

#[test]
fn a_clean_branch_reports_zero_weakened_and_no_entries() {
    // The delta always states its count, including zero: silence would be
    // indistinguishable from "the comparison did not run".
    let repo = pr_fixture(
        "trust-no-weakening",
        "version = 1\nprotected = [\"a\"]\n",
        "version = 1\nprotected = [\"a\"]\n",
        &[],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-from origin/main: 0 weakened\n");
}

#[test]
fn tightening_the_config_is_not_reported_as_weakening() {
    // The monotonicity §8 is defined over. Adding a protected path, raising
    // strictness and adding a rule are all tightening; none is a weakening.
    let repo = pr_fixture(
        "trust-tightened",
        "version = 1\nprotected = [\"a\"]\nstrictness = \"permissive\"\n",
        &format!(
            "version = 1\nprotected = [\"a\", \"b\"]\nstrictness = \"strict\"\n{}",
            rule("no-todo", "deny")
        ),
        &[],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-from origin/main: 0 weakened\n");
}

#[test]
fn the_delta_is_byte_stable_across_runs() {
    // §6. Without a sort the entry order would be authoring order, so two runs
    // over the same pair of configs could disagree.
    let repo = pr_fixture(
        "trust-byte-stable",
        "version = 1\nprotected = [\"z\", \"a\", \"m\"]\nstrictness = \"strict\"\n",
        "version = 1\n",
        &[],
    );
    let first = run(&repo, &["check", "--config-from", "origin/main"]);
    let second = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(
        stdout(&first),
        "batten.toml:protected[a] present→absent\n\
         batten.toml:protected[m] present→absent\n\
         batten.toml:protected[z] present→absent\n\
         batten.toml:strictness strict→standard\n\
         config-from origin/main: 4 weakened\n"
    );
}

#[test]
fn the_delta_never_emits_the_config_bytes() {
    // Non-negotiable rule 4: a count, a key path and two verdict tokens — never
    // the config that produced them. A protected glob is a path pattern, so the
    // key names it; the *values* around it must not leak.
    let repo = pr_fixture(
        "trust-pointer-only",
        "version = 1\nprotected = [\"a\"]\n# a very distinctive comment\nstrictness = \"strict\"\n",
        "version = 1\n",
        &[],
    );
    let text = stdout(&run(&repo, &["check", "--config-from", "origin/main"]));
    assert!(!text.contains("very distinctive comment"), "got: {text}");
    assert!(!text.contains("version = 1"), "got: {text}");
}

#[test]
fn without_the_flag_stdout_is_exactly_the_findings() {
    // The delta must not leak into an ordinary run: `check`'s stdout has always
    // been the findings and nothing else, and a consumer parses it that way.
    let repo = pr_fixture(
        "trust-absent-flag",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        &[("lib.rs", "TODO\n")],
    );
    let output = run(&repo, &["check"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(stdout(&output), "lib.rs:1 no-todo\n");
}

// --- a ref this binary cannot read is a usage error, never a verdict ---------

#[test]
fn an_unknown_ref_is_a_usage_error() {
    // Exit 1, not 2. "I cannot read that ref" is a statement about the
    // invocation; a harness reading 2 would report a policy denial that never
    // happened (§7).
    let repo = pr_fixture("trust-unknown-ref", "version = 1\n", "version = 1\n", &[]);
    let output = run(&repo, &["check", "--config-from", "origin/nonexistent"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("origin/nonexistent"),
        "the refusal must name the ref"
    );
}

#[test]
fn a_ref_with_no_config_is_a_usage_error() {
    // The ref exists but carries no `batten.toml` — the shape of pointing at a
    // branch from before the config landed. Refused, never treated as an empty
    // policy, which would silently pass everything.
    let repo = scratch("trust-ref-no-config");
    let _ = fs::remove_dir_all(&repo);
    fs::create_dir_all(&repo).expect("create fixture");
    git_in(&repo, &["init", "-q"]);
    git_in(&repo, &["config", "user.email", "t@example.com"]);
    git_in(&repo, &["config", "user.name", "t"]);
    fs::write(repo.join("README"), "no config here\n").expect("write file");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "before batten"]);
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    fs::write(repo.join("batten.toml"), "version = 1\n").expect("write config");

    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("batten.toml"),
        "the refusal must name the path it could not read"
    );
}

#[test]
fn a_malformed_config_at_the_ref_is_a_usage_error() {
    let repo = pr_fixture(
        "trust-malformed-ref",
        "version = 1\nthis is not toml\n",
        "version = 1\n",
        &[],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(1));
}

// --- precedence is unchanged (§8) --------------------------------------------

#[test]
fn raise_only_overrides_still_stack_on_the_base_ref_config() {
    // No second config surface: the ref-loaded file is simply the committed
    // authority, and env/flag overrides layer on top under the same clamp.
    let repo = pr_fixture(
        "trust-overrides-stack",
        "version = 1\nstrictness = \"permissive\"\n",
        "version = 1\nstrictness = \"permissive\"\n",
        &[],
    );
    let raised = run(
        &repo,
        &[
            "--strictness",
            "strict",
            "config",
            "show",
            "--config-from",
            "origin/main",
        ],
    );
    assert_eq!(raised.status.code(), Some(0));
    // The pointer form is `<key> <value> <source>` (CLOUD-30), so the raised
    // value and the layer that raised it are one line.
    let shown = stdout(&raised);
    assert!(shown.contains("strictness strict flag"), "got: {shown}");
}

#[test]
fn an_override_may_not_weaken_the_base_refs_policy() {
    // The clamp is what makes the base ref a floor rather than a suggestion.
    let repo = pr_fixture(
        "trust-override-weaken",
        "version = 1\nstrictness = \"strict\"\n",
        "version = 1\nstrictness = \"permissive\"\n",
        &[],
    );
    let output = run(
        &repo,
        &[
            "--strictness",
            "permissive",
            "check",
            "--config-from",
            "origin/main",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "weakening below the base authority is refused, not applied"
    );
}

#[test]
fn the_env_form_selects_the_same_ref_as_the_flag() {
    // §3: every flag has a `BATTEN_`-prefixed env equivalent, declared as data
    // on the flag itself.
    let repo = pr_fixture(
        "trust-env-form",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        "version = 1\n",
        &[("lib.rs", "TODO\n")],
    );
    let output = batten()
        .args(["check"])
        .current_dir(&repo)
        .env("BATTEN_CONFIG_FROM", "origin/main")
        .output()
        .expect("run batten");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the env form must judge by the ref too"
    );
}

// --- the JSON channel carries the same answer --------------------------------

#[test]
fn json_carries_the_delta_and_is_byte_stable() {
    let repo = pr_fixture(
        "trust-json",
        "version = 1\nprotected = [\"a\"]\n",
        "version = 1\n",
        &[],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert_eq!(report["config_delta"][0]["key"], "protected[a]");
    assert_eq!(report["config_delta"][0]["base"], "present");
    assert_eq!(report["config_delta"][0]["working"], "absent");

    let again = run(&repo, &["check", "--config-from", "origin/main", "--json"]);
    assert_eq!(
        output.stdout, again.stdout,
        "the data channel must be byte-stable"
    );
}

#[test]
fn json_omits_the_delta_when_no_base_ref_was_named() {
    // The field's presence says "a base ref was compared", so an absent one must
    // not render as an empty list — that would read as "nothing was weakened".
    let repo = pr_fixture("trust-json-no-ref", "version = 1\n", "version = 1\n", &[]);
    let output = run(&repo, &["check", "--json"]);
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the report is JSON");
    assert!(report.get("config_delta").is_none(), "got: {report}");
}

// --- an unreadable working authority is the maximal weakening, not an abort ---
//
// CLOUD-243. `resolve` takes its policy from the base ref under `--config-from`,
// so the verdict is computable whatever the working tree did to its own config.
// The working copy is loaded only to build the delta, and letting that load abort
// turned "delete `batten.toml`" — the most complete weakening available — into
// exit 1, which every mediating harness reads as "do not block".

/// `pr_fixture`, then the working `batten.toml` removed and the removal committed.
fn pr_fixture_without_working_config(name: &str, base: &str, files: &[(&str, &str)]) -> PathBuf {
    let repo = pr_fixture(name, base, base, files);
    fs::remove_file(repo.join("batten.toml")).expect("remove the working config");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "delete the policy"]);
    repo
}

#[test]
fn a_deleted_working_config_still_gets_the_base_rule_verdict() {
    let repo = pr_fixture_without_working_config(
        "trust-deleted-config-violation",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &[("a.rs", "// TODO\n")],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "the base rule found a violation, so the verdict is 2 — not 1, which a \
         harness reads as do-not-block. stdout: {}, stderr: {}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout(&output).contains("a.rs:1 no-todo"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_deleted_working_config_reports_every_base_key_as_removed() {
    let repo = pr_fixture_without_working_config(
        "trust-deleted-config-delta",
        &format!(
            "version = 1\nprotected = [\"crates/**\"]\nstrictness = \"strict\"{}",
            rule("no-todo", "deny")
        ),
        &[],
    );
    let text = stdout(&run(&repo, &["check", "--config-from", "origin/main"]));
    // Each key named under its own pointer: granting nothing is what an absent
    // authority grants, so every key the base declared reads as removed.
    for pointer in [
        "batten.toml:protected[crates/**] present→absent",
        "batten.toml:rule[no-todo] present→absent",
        "batten.toml:strictness strict→standard",
    ] {
        assert!(text.contains(pointer), "missing {pointer} in: {text}");
    }
    assert!(
        text.contains("config-from origin/main: 3 weakened"),
        "got: {text}"
    );
}

#[test]
fn an_unparseable_working_config_still_gets_the_base_rule_verdict() {
    let repo = pr_fixture(
        "trust-corrupt-config",
        &format!("version = 1{}", rule("no-todo", "deny")),
        "this is not = = toml\n",
        &[("a.rs", "// TODO\n")],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a corrupt working config grants no policy either. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_deleted_working_config_does_not_manufacture_a_verdict() {
    // The fallback must not invent findings: with no rule to fire, the base
    // policy's verdict over a clean tree is still 0.
    let repo = pr_fixture_without_working_config(
        "trust-deleted-config-clean",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &[("a.rs", "fn main() {}\n")],
    );
    let output = run(&repo, &["check", "--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(0), "stdout: {}", stdout(&output));
}

#[test]
fn without_a_base_ref_a_missing_config_is_still_a_usage_error() {
    // The asymmetry is the point, and pinning it is what stops a later change
    // from quietly making an unreadable config fall back everywhere. A trusted
    // base is exactly what makes the fallback safe; with no base there is no
    // policy to fall back to, so refusing is correct.
    let repo = pr_fixture_without_working_config(
        "trust-no-config-no-base",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &[("a.rs", "// TODO\n")],
    );
    let output = run(&repo, &["check"]);
    assert_eq!(output.status.code(), Some(1), "stdout: {}", stdout(&output));
}
