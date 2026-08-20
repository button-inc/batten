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

use common::{Fixture, StateHome, batten, git_in, scratch, stdout};

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
    //
    // Updated by CLOUD-718 rather than added to: this and the case below used to
    // pin BOTH states against one hedged refusal ("no such ref, or the path is
    // absent there"), so neither could assert what it was actually about. Each
    // now takes its own half.
    let repo = pr_fixture("trust-unknown-ref", "version = 1\n", "version = 1\n", &[]);
    let output = run(&repo, &["check", "--config-from", "origin/nonexistent"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("origin/nonexistent"),
        "the refusal must name the ref"
    );
    assert!(
        !stderr.contains("batten.toml"),
        "the ref is what failed; naming the config hedges about a file that was \
         never looked for: {stderr}"
    );
}

#[test]
fn a_reference_that_spells_an_option_is_refused_and_writes_nothing() {
    // CLOUD-718 end to end. `--config-from` is `global: true`, so this string
    // reaches every verb — including `check`, which declares `Effect::Read` and
    // therefore sits in the derived read-only allowlist a mediated agent may
    // call with no permission prompt. As a shell-out the value below made `git
    // show` exit 0, print nothing, and create a file, which is a `read` verb
    // writing a caller-chosen path.
    let repo = pr_fixture("trust-option-ref", "version = 1\n", "version = 1\n", &[]);
    let before = listing(&repo);
    let reference = format!("--output={}", repo.join("pwned.toml").display());

    // Through the ENV form, which is the channel that matters. Clap refuses a
    // `--`-prefixed value for `--config-from` on the command line, so the flag
    // form never reached the loader — but `BATTEN_CONFIG_FROM` is applied by
    // clap as a value and skips that check entirely, which is the issue's "it
    // can be set without a command line at all". Testing only the flag would
    // have asserted clap's argument parsing and called it a trust boundary.
    let output = batten()
        .args(["check"])
        .current_dir(&repo)
        .env("BATTEN_CONFIG_FROM", &reference)
        .output()
        .expect("run batten");
    assert_eq!(output.status.code(), Some(1), "bad input, never a verdict");
    assert!(output.stdout.is_empty(), "stdout stays the answer channel");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pwned.toml"),
        "the refusal must name the ref it could not honour"
    );

    // The whole listing, not a probe for one name: the old shell-out formatted
    // `{reference}:{path}` into a single token, so the file it created was
    // `pwned.toml:batten.toml` and a probe for `pwned.toml` would have passed
    // against the defect.
    assert_eq!(
        listing(&repo),
        before,
        "a read-effect verb must leave the tree byte-identical"
    );
}

/// Every entry in `dir`, sorted — the filesystem's own answer to "did anything
/// appear", with no guess about what it would have been called.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read the fixture directory")
        .map(|entry| entry.expect("a directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("batten.toml"),
        "the refusal must name the path it could not read"
    );
    // The other half of the split (CLOUD-718): this ref resolves perfectly well,
    // so a refusal that also offers "no such ref" leaves the operator guessing
    // between a mistyped branch and a branch from before the config landed —
    // two different repairs. CLOUD-720 builds last-known-good on the difference.
    assert!(
        !stderr.contains("no such ref"),
        "the ref resolved; only the path was missing: {stderr}"
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
fn without_a_base_ref_a_missing_config_falls_back_to_the_defaults_and_not_to_the_base() {
    // The asymmetry is still the point, and CLOUD-70 moved which asymmetry it
    // is. A missing working config used to be a usage error here; it now
    // resolves to the compiled-in default layer. What must NOT happen is the
    // thing this case has always been about: the base ref's policy reaching a
    // run that did not ask for it. `--config-from` is what makes the trusted
    // fallback safe, and without it the base's rules are simply not in play.
    //
    // `no-todo` is declared only in the base, so a `// TODO` line firing here
    // would be exactly that leak — which is why the assertion is on the verdict
    // and not merely on the exit code being reachable.
    let repo = pr_fixture_without_working_config(
        "trust-no-config-no-base",
        &format!("version = 1{}", rule("no-todo", "deny")),
        &[("a.rs", "// TODO\n")],
    );
    let output = run(&repo, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the defaults gate this tree, and they declare no `no-todo`. stdout: {}",
        stdout(&output)
    );
    assert_eq!(stdout(&output), "", "the base's rule must not have fired");
}

// --- the flag is consulted before the file, on every surface that takes it ----
//
// CLOUD-719. CLOUD-243 landed its rule in `run_rules` only, so `check` was the
// one verb that survived the maximal weakening. Three others tested the working
// file's existence BEFORE `resolve` was reached, and `--config-from` is
// `global: true`, so all three accepted the flag and then ignored it.
//
// Every case below is paired with its no-flag control, because the early return
// each fix guards is CORRECT on its own: `batten hook` and `batten exec` run in
// directories that are not Batten repositories, and refusing there would make
// the tool the reason ordinary work stops (CLOUD-70). The fix is to ask the flag
// first, never to delete the short-circuit.

/// The `[[rule]]` a `mediated_call` policy denies a `Write` with.
fn protected_policy() -> String {
    "\nprotected = [\"secrets.txt\"]\n\n[[verb]]\nverb = \"mv\"\neffect = \"destructive\"\n"
        .to_owned()
}

/// A `PreToolUse` envelope carrying a shell command, in the neutral dialect.
///
/// The protected-path gate is the intersection of two config tables — a
/// mutating `[[verb]]` and a `protected` path — so a shell command is what
/// exercises it, which is also the shape `tests/mediated_verbs.rs` uses.
fn bash_payload(command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped}}}}}"
    )
}

#[test]
fn hook_adjudicates_against_the_base_ref_when_the_working_config_is_gone() {
    // The surface where this matters most, and the reason the issue is High: the
    // pre-tool adjudicator is the one place a policy verdict actually stops an
    // agent's tool call. On the other three surfaces CLOUD-243's failure is a
    // report that under-states; here it is an un-gated write.
    let repo = pr_fixture_without_working_config(
        "trust-hook-deleted-config",
        &format!("version = 1{}", protected_policy()),
        &[],
    );
    let output = common::run_with_stdin(
        &repo,
        &[
            "hook",
            "--harness",
            "exit-code",
            "--config-from",
            "origin/main",
        ],
        &bash_payload("mv secrets.txt elsewhere.txt"),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "the base ref protects secrets.txt, so the write is denied whatever the \
         working tree did to its own config. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hook_without_the_flag_still_allows_everything_in_a_config_less_tree() {
    // The control, and the whole reason the short-circuit exists. A tree with no
    // authority declares no policy, and `hook` must not become the reason a
    // non-Batten directory stops working (CLOUD-70).
    let repo = pr_fixture_without_working_config(
        "trust-hook-no-flag",
        &format!("version = 1{}", protected_policy()),
        &[],
    );
    let output = common::run_with_stdin(
        &repo,
        &["hook", "--harness", "exit-code"],
        &bash_payload("mv secrets.txt elsewhere.txt"),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "absent authority is the empty policy, not a deny"
    );
}

#[test]
fn config_lint_reports_the_deleted_config_as_a_verdict_not_a_usage_error() {
    // Exit 2, not 1. §7 reserves 2 for the policy verdict on every surface
    // (CLOUD-226), and the most complete weakening available — delete the file —
    // answered 1, "bad config". A consumer that is not this repo's own workflow
    // reads that as its own mistake.
    let repo = pr_fixture_without_working_config(
        "trust-lint-deleted-config",
        &format!(
            "version = 1\nprotected = [\"crates/**\"]{}",
            rule("no-todo", "deny")
        ),
        &[],
    );
    let output = run(&repo, &["config", "lint", "--config-from", "origin/main"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout: {}, stderr: {}",
        stdout(&output),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = stdout(&output);
    // Every base key named as removed, each under its own key path — the same
    // report `check --config-from` already prints for this tree.
    assert!(
        text.contains("protected[crates/**]"),
        "the removed protected entry is named: {text}"
    );
    assert!(
        text.contains("rule[no-todo]"),
        "the removed rule is named: {text}"
    );
}

#[test]
fn config_lint_without_the_flag_still_refuses_a_missing_config_as_usage() {
    // The control. With no ref named there is nothing to judge the tree against,
    // so "no config found" is the honest answer and stays exit 1 — a statement
    // about the invocation, not a policy verdict.
    let repo = pr_fixture_without_working_config("trust-lint-no-flag", "version = 1\n", &[]);
    let output = run(&repo, &["config", "lint"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no config found"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_unreadable_ref_still_outranks_a_missing_working_config_in_lint() {
    // Ordering, pinned: the base ref is loaded BEFORE the working file's absence
    // can route anywhere, so a ref this binary cannot read stays exit 1 and names
    // the ref — never exit 2 against a base that was never loaded.
    let repo = pr_fixture_without_working_config("trust-lint-bad-ref", "version = 1\n", &[]);
    let output = run(
        &repo,
        &["config", "lint", "--config-from", "origin/nonexistent"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("origin/nonexistent"),
        "the refusal names the ref: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn exec_applies_the_base_refs_output_predicates_when_the_working_config_is_gone() {
    // The quietest of the three and still real: `[[exec_pattern]]` promotes a
    // wrapped command that lies with exit `0` (CLOUD-117), and deleting
    // `batten.toml` dropped the whole table. A gate that silently did not run is
    // the false green that predicate exists to prevent.
    let repo = pr_fixture_without_working_config(
        "trust-exec-deleted-config",
        "version = 1\n\n[[exec_pattern]]\nid = \"lying-zero\"\n\
         pattern = \"warning[duplicate]\"\nstream = \"both\"\n\
         reason = \"configure the tool to fail instead\"\n",
        &[],
    );
    let home = scratch("trust-exec-deleted-config-home");
    let output = batten()
        .args([
            "exec",
            "--config-from",
            "origin/main",
            "--tee",
            "--style",
            "quiet",
            "--",
            "sh",
            "-c",
            "echo 'warning[duplicate] serde'",
        ])
        .current_dir(&repo)
        .state_home(&home)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten exec");
    assert_eq!(
        output.status.code(),
        Some(1),
        "the base ref's pattern still promotes the lying zero. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Pointer-only, as the predicate always is: the id and the position, never
    // the line that matched.
    let report = String::from_utf8_lossy(&output.stderr);
    assert!(report.contains("stdout:1 lying-zero"), "got {report}");
    assert!(
        !report.contains("serde"),
        "no matched text echoed: {report}"
    );
}

#[cfg(unix)]
#[test]
fn exec_without_the_flag_declares_no_patterns_in_a_config_less_tree() {
    // The control. `batten exec` is a wrapper a caller puts in front of arbitrary
    // commands, most of them outside Batten repositories; an absent authority
    // declares no patterns and passes the child's own exit code through.
    let repo = pr_fixture_without_working_config(
        "trust-exec-no-flag",
        "version = 1\n\n[[exec_pattern]]\nid = \"lying-zero\"\n\
         pattern = \"warning[duplicate]\"\nstream = \"both\"\n\
         reason = \"configure the tool to fail instead\"\n",
        &[],
    );
    let home = scratch("trust-exec-no-flag-home");
    let output = batten()
        .args([
            "exec",
            "--tee",
            "--style",
            "quiet",
            "--",
            "sh",
            "-c",
            "echo 'warning[duplicate] serde'",
        ])
        .current_dir(&repo)
        .state_home(&home)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten exec");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the child's own exit code passes through untouched"
    );
}
