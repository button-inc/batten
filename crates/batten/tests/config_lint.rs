//! End-to-end tests over the compiled binary for `batten config lint`
//! (CLOUD-87).
//!
//! The lint answers a question neither schema validation nor `--config-from`
//! does: this config parses fine and is judged against a trusted base — but does
//! it *gate anything*? A set declared and empty, a rule switched off, a severity
//! quietly rated down all survive both of those checks.
//!
//! Kept out of `tests/cli.rs` deliberately — that file is the exit-code and
//! output-contract suite, and other work appends to it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn batten() -> Command {
    Command::new(env!("CARGO_BIN_EXE_batten"))
}

/// Create a temp repo containing a `batten.toml` with `contents`.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp repo dir");
    fs::write(dir.join("batten.toml"), contents).expect("write batten.toml");
    dir
}

/// Run `git` in `dir`, asserting success.
fn git_in(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(output.status.success(), "git {args:?} failed");
}

/// A pull-request-shaped fixture: `base` pinned as `origin/main`, `working` in
/// the tree on top.
fn pr_fixture(name: &str, base: &str, working: &str) -> PathBuf {
    let repo = repo_with_config(name, base);
    git_in(&repo, &["init", "-q"]);
    git_in(&repo, &["config", "user.email", "t@example.com"]);
    git_in(&repo, &["config", "user.name", "t"]);
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "base policy"]);
    git_in(&repo, &["branch", "-M", "main"]);
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    fs::write(repo.join("batten.toml"), working).expect("write working config");
    git_in(&repo, &["add", "-A"]);
    git_in(
        &repo,
        &["commit", "-q", "--allow-empty", "-m", "the pull request"],
    );
    repo
}

fn lint(dir: &Path, extra: &[&str]) -> Output {
    let mut command = batten();
    command.args(["config", "lint"]);
    command.args(extra);
    command
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config lint")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A `forbid` rule at the given severity.
fn rule(id: &str, severity: &str) -> String {
    format!(
        "\n[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"{severity}\"\n"
    )
}

// --- single-tree smells ------------------------------------------------------

#[test]
fn a_clean_config_exits_zero_and_still_states_its_count() {
    // Stating zero matters: silence would be indistinguishable from "the lint
    // did not run", which is how a skipped gate reads as a passing one.
    let dir = repo_with_config(
        "lint-clean",
        &format!("version = 1\nprotected = [\"a\"]\n{}", rule("r", "deny")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn an_empty_protected_set_is_a_violation_with_a_pointer() {
    // CLOUD-87's headline acceptance. Exit 2 — a smell is a verdict about the
    // config, the same class as a rule finding.
    let dir = repo_with_config("lint-empty-protected", "version = 1\nprotected = []\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:2 empty-protected-set\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn the_pointer_names_the_line_the_key_is_written_on() {
    let dir = repo_with_config(
        "lint-line-number",
        "version = 1\n\n# a comment\n\nprotected = []\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).starts_with("batten.toml:5 empty-protected-set\n"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn an_absent_set_is_not_a_smell() {
    // Absent means "this repository does not use the feature"; flagging it would
    // fire on every minimal config, which is how a lint teaches people to
    // ignore it. Deletion of a populated set is caught by the base-ref class.
    let dir = repo_with_config("lint-absent-set", "version = 1\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn a_rule_switched_off_is_a_smell() {
    // `severity = "allow"` reads as a gate in the file and is not one.
    let dir = repo_with_config(
        "lint-rule-disabled",
        &format!("version = 1\n{}", rule("no-todo", "allow")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("rule-disabled"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn every_empty_set_is_reported_and_the_output_is_byte_stable() {
    let dir = repo_with_config(
        "lint-all-empty",
        "version = 1\nunlanded = []\nscope = []\nprotected = []\n",
    );
    let first = lint(&dir, &[]);
    assert_eq!(first.status.code(), Some(2));
    assert_eq!(
        stdout(&first),
        "batten.toml:2 empty-unlanded-set\n\
         batten.toml:3 empty-scope-set\n\
         batten.toml:4 empty-protected-set\n\
         config-lint: 3 smell(s)\n"
    );
    let second = lint(&dir, &[]);
    assert_eq!(
        first.stdout, second.stdout,
        "the report must be byte-stable"
    );
}

#[test]
fn the_output_never_carries_the_config_bytes() {
    // Non-negotiable rule 4: a location and a stable id, never the content.
    let dir = repo_with_config(
        "lint-pointer-only",
        "version = 1\n# a very distinctive comment\nprotected = []\n",
    );
    let text = stdout(&lint(&dir, &[]));
    assert!(!text.contains("very distinctive comment"), "got: {text}");
    assert!(!text.contains("version = 1"), "got: {text}");
}

// --- base-ref comparison smells ----------------------------------------------

#[test]
fn a_severity_lowered_against_the_base_ref_is_a_smell() {
    // CLOUD-87's second acceptance, and the one that needs CLOUD-31's loader.
    // Without a base ref this config is entirely clean — a `warn` rule is legal.
    let repo = pr_fixture(
        "lint-severity-lowered",
        &format!("version = 1\n{}", rule("no-todo", "deny")),
        &format!("version = 1\n{}", rule("no-todo", "warn")),
    );
    assert_eq!(
        lint(&repo, &[]).status.code(),
        Some(0),
        "the single-tree view cannot see the lowering"
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        // The key path, not `:0`. `trust` located this weakening precisely and
        // the conversion now keeps that location, so the pointer names the key
        // that was lowered and matches what `check --config-from` prints for the
        // same finding (CLOUD-233).
        "batten.toml:rule[no-todo].severity severity-lowered\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn a_deleted_protected_entry_is_a_smell_against_the_base_ref() {
    // The deletion the single-tree class deliberately does not flag: absent is
    // not empty, but absent-having-been-present is a weakening.
    let repo = pr_fixture(
        "lint-protected-deleted",
        "version = 1\nprotected = [\"crates/**\"]\n",
        "version = 1\n",
    );
    assert_eq!(lint(&repo, &[]).status.code(), Some(0));
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout(&output).contains("protected-removed"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn tightening_against_the_base_ref_is_not_a_smell() {
    let repo = pr_fixture(
        "lint-tightened",
        "version = 1\nprotected = [\"a\"]\n",
        "version = 1\nprotected = [\"a\", \"b\"]\nstrictness = \"strict\"\n",
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn the_smell_ids_are_the_same_names_the_check_delta_uses() {
    // One definition of "weakened", shared: the lint's base-ref ids come off the
    // same `WeakeningKind` the `check` delta is built from, so the two can never
    // disagree about what happened.
    let repo = pr_fixture(
        "lint-shared-vocabulary",
        "version = 1\nprotected = [\"a\"]\nstrictness = \"strict\"\n",
        "version = 1\n",
    );
    let linted = stdout(&lint(&repo, &["--config-from", "origin/main"]));
    assert!(linted.contains("protected-removed"), "got: {linted}");
    assert!(linted.contains("strictness-lowered"), "got: {linted}");

    // The same run through `check` names the same two keys.
    let checked = batten()
        .args(["check", "--config-from", "origin/main"])
        .current_dir(&repo)
        .output()
        .expect("run batten check");
    let checked = String::from_utf8_lossy(&checked.stdout);
    assert!(
        checked.contains("batten.toml:protected[a]"),
        "got: {checked}"
    );
    assert!(checked.contains("batten.toml:strictness"), "got: {checked}");
}

// --- errors are usage errors, never verdicts ---------------------------------

#[test]
fn a_malformed_config_is_a_usage_error() {
    // Exit 1, not 2: "I cannot read this" is a statement about the invocation.
    // A harness reading 2 would report a policy denial that never happened (§7).
    let dir = repo_with_config("lint-malformed", "version = 1\nthis is not toml\n");
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
}

#[test]
fn a_missing_config_is_a_usage_error() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lint-missing-config");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create dir");
    assert_eq!(lint(&dir, &[]).status.code(), Some(1));
}

#[test]
fn an_unknown_base_ref_is_a_usage_error() {
    let repo = pr_fixture("lint-unknown-ref", "version = 1\n", "version = 1\n");
    let output = lint(&repo, &["--config-from", "origin/nonexistent"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

// --- the surface ------------------------------------------------------------

#[test]
fn config_lint_is_declared_read_in_the_spec() {
    // §5: the derived agent allowlist is `filter(effect == read)`, so a lint that
    // only inspects must say so or it is needlessly excluded.
    let output = batten().arg("spec").output().expect("run batten spec");
    let spec: serde_json::Value = serde_json::from_slice(&output.stdout).expect("spec is JSON");
    let config = spec["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config")
        .expect("config is in the spec");
    let lint = config["subcommands"]
        .as_array()
        .expect("subcommands")
        .iter()
        .find(|node| node["path"] == "config lint")
        .expect("config lint is in the spec");
    assert_eq!(lint["effect"], "read");
}

#[test]
fn this_repositorys_own_config_is_clean() {
    // Consumer #1: the lint Batten ships runs against the config Batten is
    // gated by, which is also what `mise run config-lint` asserts in the gate.
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = batten()
        .args(["config", "lint"])
        .current_dir(&repo)
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten config lint");
    assert_eq!(
        output.status.code(),
        Some(0),
        "this repository's batten.toml has a smell: {}",
        stdout(&output)
    );
}

// --- one weakening, one pointer, whichever verb reports it --------------------
//
// CLOUD-233. `config lint` and `check --config-from` reuse one comparison, so
// they must agree on where a weakening *is*. They did not: this verb substituted
// `:0` for the key `trust` had already computed, which pointed nowhere and — since
// a smell's identity was `(line, id)` — made two weakenings of one kind compare
// equal, so `dedup` silently dropped all but the first.

#[test]
fn two_rules_lowered_in_one_edit_are_both_reported() {
    // The count is the sharp end: under-reporting a weakening is worse than
    // mislocating it, and no test asserted cardinality before this one.
    let repo = pr_fixture(
        "lint-two-lowerings",
        &format!("version = 1{}{}", rule("one", "deny"), rule("two", "deny")),
        &format!("version = 1{}{}", rule("one", "warn"), rule("two", "warn")),
    );
    let output = lint(&repo, &["--config-from", "origin/main"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:rule[one].severity severity-lowered\n\
         batten.toml:rule[two].severity severity-lowered\n\
         config-lint: 2 smell(s)\n",
        "both lowerings, each under its own key"
    );
}

#[test]
fn the_two_verbs_agree_on_where_a_weakening_is() {
    // The assertion that would have caught this, and which neither verb's own
    // suite can express alone: the pointer half of each line must match, so a
    // caller can join a smell to the weakening it came from.
    let repo = pr_fixture(
        "lint-pointer-joinable",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &format!("version = 1{}", rule("no-todo", "warn")),
    );
    let lint_out = stdout(&lint(&repo, &["--config-from", "origin/main"]));

    let check = batten()
        .args(["check", "--config-from", "origin/main"])
        .current_dir(&repo)
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten check");
    let check_out = String::from_utf8_lossy(&check.stdout).into_owned();

    // The pointer is everything up to the first space; the trailing token differs
    // by verb on purpose — one names the smell, the other the verdict transition.
    let pointer = |text: &str| -> String {
        text.lines()
            .find(|line| line.starts_with("batten.toml:"))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(
        pointer(&lint_out),
        pointer(&check_out),
        "lint: {lint_out}check: {check_out}"
    );
    assert_eq!(pointer(&lint_out), "batten.toml:rule[no-todo].severity");
}
