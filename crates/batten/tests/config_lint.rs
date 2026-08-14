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

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, scratch, stderr, stdout};

/// Create a temp repo containing a `batten.toml` with `contents`.
fn repo_with_config(name: &str, contents: &str) -> PathBuf {
    Fixture::new(name).config(contents).build()
}

/// A pull-request-shaped fixture: `base` pinned as `origin/main`, `working` in
/// the tree on top.
fn pr_fixture(name: &str, base: &str, working: &str) -> PathBuf {
    Fixture::new(name)
        .config(base)
        .git()
        .base_commit()
        .config(working)
        .work_commit()
        .build()
}

fn lint(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["config", "lint"];
    args.extend_from_slice(extra);
    common::run(dir, &args)
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

// --- a waiver that cannot reach its rule (CLOUD-293) -------------------------

/// A config with one `shape` rule — the mediated-call kind, which reads no
/// `glob` — plus whatever waiver rows the case needs.
fn shape_config(waivers: &str) -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"no-merge\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\npattern = \"gh pr merge\"\n\
         reason = \"land by fast-forward\"\nseverity = \"deny\"\n{waivers}"
    )
}

fn waiver_row(rule: &str) -> String {
    format!(
        "\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked in CLOUD-1\"\nexpires = \"2099-01-01\"\n"
    )
}

#[test]
fn a_waiver_over_an_unreachable_kind_is_a_violation_naming_the_kind() {
    // CLOUD-293's headline acceptance, over the compiled binary. The rule
    // exists and the expiry is live, so neither sibling waiver smell fires —
    // and `waiver::apply` filters findings, which a shape row never mints.
    let dir = repo_with_config("lint-waiver-shape", &shape_config(&waiver_row("no-merge")));
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "batten.toml:waiver[no-merge] shape waiver-unreachable-kind\nconfig-lint: 1 smell(s)\n"
    );
}

#[test]
fn a_waiver_over_a_reachable_kind_exits_zero() {
    // The half that keeps the smell worth reading: it must not fire on every
    // waiver in the file. `forbid` mints findings, so its waiver is live.
    let dir = repo_with_config(
        "lint-waiver-forbid",
        &format!("version = 1\n{}{}", rule("r", "deny"), waiver_row("r")),
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(stdout(&output), "config-lint: 0 smell(s)\n");
}

#[test]
fn the_unreachable_smell_reaches_the_machine_channel_unchanged() {
    // No new field: the pointer splits into the same `at`/`id` pair every other
    // smell uses, so a consumer needs no second convention for this one.
    let dir = repo_with_config("lint-waiver-json", &shape_config(&waiver_row("no-merge")));
    let output = lint(&dir, &["-J"]);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        text.contains("\"at\": \"waiver[no-merge] shape\""),
        "got: {text}"
    );
    assert!(
        text.contains("\"id\": \"waiver-unreachable-kind\""),
        "got: {text}"
    );
    // Pointer-only: never the justification, never the shape the rule bans.
    assert!(!text.contains("tracked in CLOUD-1"), "got: {text}");
    assert!(!text.contains("gh pr merge"), "got: {text}");
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
    let dir = scratch("lint-missing-config");
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

// --- the judge payload boundary (CLOUD-135) ----------------------------------

/// A config with a protected set and a `[judge]` table, with `extra` appended
/// inside that table.
fn judge_config(extra: &str) -> String {
    format!("version = 1\nprotected = [\"secrets/**\"]\n\n[judge]\nraw = [\"span_text\"]\n{extra}")
}

#[test]
fn a_judge_over_a_protected_set_needs_no_answer_because_the_engine_gives_one() {
    // `judge-over-protected-unstated` used to fire here. It is gone with the key
    // it asked about: protected content now refuses the whole invocation, so
    // there is no question for a config to leave unanswered, and a smell over a
    // decision the engine makes structurally could never fire.
    let dir = repo_with_config("judge-unstated", &judge_config(""));
    let output = lint(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an unanswerable question is not a smell: {}",
        stdout(&output)
    );
}

#[test]
fn the_removed_protected_egress_key_is_refused_rather_than_ignored() {
    // The key was the issue's own rejected alternative — "a committed opt-in key
    // for protected egress … not a latent key". A config still carrying it must
    // hear that it no longer does anything, rather than parsing green and
    // leaving its author believing protected content still crosses.
    for answer in ["pointer", "raw"] {
        let dir = repo_with_config(
            &format!("judge-removed-{answer}"),
            &judge_config(&format!("over_protected = \"{answer}\"\n")),
        );
        let output = lint(&dir, &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "an unknown key is a usage error, never a silent ignore"
        );
        assert!(
            stderr(&output).contains("over_protected"),
            "the refusal names the key that is gone"
        );
    }
}

#[test]
fn a_judge_with_no_protected_set_owes_no_answer() {
    // Absent is not empty, the rule this whole module runs on: a config with
    // nothing marked protected has no protected content to decide about, and
    // firing there would make the smell noise on every minimal config.
    let dir = repo_with_config(
        "judge-no-protected",
        "version = 1\n\n[judge]\nraw = [\"span_text\"]\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_protected_set_with_no_judge_owes_no_answer_either() {
    let dir = repo_with_config(
        "judge-absent",
        "version = 1\nprotected = [\"secrets/**\"]\n",
    );
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

// --- the merge-contract drift gate (CLOUD-54) --------------------------------
//
// The host ruleset is the authority; `[ci]` is a projection a gate polices. The
// payload arrives from the caller — agents fetch, gates decide — so every case
// below is a pure comparison over bytes on disk or stdin, with no network.

/// A config declaring `[ci]`, with `extra` appended inside the table.
fn ci_config(extra: &str) -> String {
    format!("version = 1\n\n[ci]\nrequired_checks = [\"final\"]\n{extra}")
}

/// One of the committed rules-API fixtures, by file stem.
fn rules_fixture(stem: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ci")
        .join(format!("{stem}.json"))
}

/// `config lint --host-rules <fixture>` in `dir`.
fn lint_against(dir: &Path, stem: &str) -> Output {
    lint(
        dir,
        &[
            "--host-rules",
            rules_fixture(stem).to_str().expect("fixture path is UTF-8"),
        ],
    )
}

#[test]
fn a_projection_matching_the_host_is_silent_and_clean() {
    let dir = repo_with_config("ci-agrees", &ci_config(""));
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("0 smell(s)"),
        "agreement is the count stated at zero, never silence that could be a \
         lint which did not run"
    );
}

#[test]
fn a_check_the_host_requires_and_the_config_lacks_is_drift() {
    let dir = repo_with_config(
        "ci-missing-check",
        "version = 1\n\n[ci]\nrequired_checks = [\"other\"]\n",
    );
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(2), "drift is a policy verdict");
    let text = stdout(&output);
    assert!(
        text.contains("ci-required-checks-drift"),
        "the smell names itself: {text:?}"
    );
    assert!(
        text.contains("ci.required_checks"),
        "and the key to edit: {text:?}"
    );
    assert!(
        text.contains("+final") && text.contains("-other"),
        "signed by which side has each token — `+` host, `-` config: {text:?}"
    );
}

#[test]
fn a_check_the_config_claims_and_the_host_does_not_require_is_drift_too() {
    // Not harmless: a stale name in the projection is exactly what a downstream
    // reader would wait on forever.
    let dir = repo_with_config(
        "ci-stale-check",
        "version = 1\n\n[ci]\nrequired_checks = [\"final\", \"ghost\"]\n",
    );
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("-ghost"));
}

#[test]
fn a_host_that_constrains_merge_methods_while_the_config_omits_them_is_drift() {
    // The dangerous direction: the projection silently claims freedom the host
    // does not grant.
    let dir = repo_with_config("ci-omits-methods", &ci_config(""));
    let output = lint_against(&dir, "rules-merge-methods");
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(text.contains("ci-allowed-merge-methods-drift"), "{text:?}");
    assert!(text.contains("+squash"), "{text:?}");
}

#[test]
fn a_config_claiming_a_method_the_host_does_not_allow_is_drift() {
    let dir = repo_with_config(
        "ci-extra-method",
        &ci_config("allowed_merge_methods = [\"merge\", \"squash\"]\n"),
    );
    let output = lint_against(&dir, "rules-merge-methods");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("-merge"));
}

#[test]
fn a_legacy_payload_is_clean_on_the_method_half_and_still_compares_checks() {
    // No `pull_request` rule at all — the shape legacy branch protection
    // produces. A config that omits the key agrees with it.
    let dir = repo_with_config(
        "ci-legacy",
        "version = 1\n\n[ci]\nrequired_checks = [\"build\", \"test\"]\n",
    );
    assert_eq!(
        lint_against(&dir, "rules-legacy").status.code(),
        Some(0),
        "omitting the key agrees with a host that constrains no method"
    );

    // The check half is still compared, so a legacy payload is not a free pass.
    let wrong = repo_with_config(
        "ci-legacy-wrong",
        "version = 1\n\n[ci]\nrequired_checks = [\"build\"]\n",
    );
    let output = lint_against(&wrong, "rules-legacy");
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("+test"));
}

#[test]
fn a_payload_that_is_not_a_rules_array_is_a_usage_error() {
    let dir = repo_with_config("ci-bad-payload", &ci_config(""));
    let path = dir.join("not-rules.json");
    fs::write(&path, "{\"message\":\"Not Found\"}").expect("write payload");
    let output = lint(&dir, &["--host-rules", path.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a gate handed the wrong document says so rather than deriving an empty \
         contract from it"
    );
    assert!(stderr(&output).contains("rules-API array"));
}

#[test]
fn asking_for_a_comparison_the_config_cannot_join_is_a_usage_error() {
    // `--host-rules` with no committed `[ci]`: the caller asked for a comparison
    // one side cannot participate in, and answering "no drift" would be a pass
    // over nothing.
    let dir = repo_with_config("ci-absent", "version = 1\n");
    let output = lint_against(&dir, "rules-required-checks");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("[ci]"));
}

#[test]
fn a_malformed_ci_table_is_refused_at_parse() {
    for (name, table) in [
        (
            "ci-unknown-key",
            "[ci]\nrequired_checks = [\"a\"]\nbogus = 1\n",
        ),
        ("ci-empty", "[ci]\nrequired_checks = []\n"),
        ("ci-duplicate", "[ci]\nrequired_checks = [\"a\", \"a\"]\n"),
        (
            "ci-bad-method",
            "[ci]\nrequired_checks = [\"a\"]\nallowed_merge_methods = [\"fast-forward\"]\n",
        ),
    ] {
        let dir = repo_with_config(name, &format!("version = 1\n\n{table}"));
        let output = lint(&dir, &[]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name}: a malformed table is refused, never ignored"
        );
    }
}

#[test]
fn the_drift_report_is_byte_stable_and_reads_stdin() {
    let dir = repo_with_config(
        "ci-stable",
        "version = 1\n\n[ci]\nrequired_checks = [\"other\"]\n",
    );
    let payload = fs::read_to_string(rules_fixture("rules-required-checks")).expect("fixture");

    // `-` is stdin, which is how the CI task pipes a live fetch in.
    let piped = |args: &[&str]| -> Output {
        let mut command = batten();
        command
            .current_dir(&dir)
            .args(["config", "lint", "--host-rules", "-"])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("spawn batten");
        std::io::Write::write_all(
            &mut child.stdin.take().expect("piped stdin"),
            payload.as_bytes(),
        )
        .expect("write payload");
        child.wait_with_output().expect("run batten")
    };

    let first = piped(&["-J"]);
    let second = piped(&["-J"]);
    assert_eq!(first.status.code(), Some(2));
    assert_eq!(
        first.stdout, second.stdout,
        "identical input must produce identical bytes"
    );
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("ci-required-checks-drift"),
        "the machine channel carries the smell too"
    );
}

#[test]
fn lint_without_the_flag_is_unchanged() {
    // The drift half is additive: a run that does not ask for it must behave
    // exactly as it did before this landed.
    let dir = repo_with_config("ci-no-flag", &ci_config(""));
    let output = lint(&dir, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!stdout(&output).contains("ci-"), "no drift smell appears");
}
