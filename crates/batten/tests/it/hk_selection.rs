//! Which steps a change SELECTS, asserted as data over hk's own plan (CLOUD-224,
//! CLOUD-509), ported from `tests/hk-selection.bats` under CLOUD-843.
//!
//! # Why the plan and never a timing
//!
//! `batten-check` and `macos-link-check` carried no glob, so they ran on every
//! commit whatever it touched. Giving them a glob is the fix; the risk a glob
//! introduces is the opposite failure, a step that silently stops running for a
//! change it should judge. `hk check --plan` prints the plan WITHOUT running a
//! step, so selection is readable as JSON rather than inferred from a timing —
//! which is the only form the negative case can be asserted in at all. A step can
//! be fast because it was skipped or because its inputs were cached, and those
//! are the two cases that must not be confused.
//!
//! These run against the repository's own `hk.pkl`, which is the artifact under
//! test. Nothing here executes a gate.
//!
//! # Why the ambient `HK_*` environment is scrubbed
//!
//! The retired suite ran in its own CI job, whose environment named no hk
//! setting. This tier runs under `test:cargo`, which the `ci` job reaches through
//! `hk check --all` with `HK_SKIP_STEPS` exported — so an inherited value would
//! make `batten-check` read as skipped for a reason that has nothing to do with
//! `hk.pkl`. The subject is the committed config, so the plan is taken under a
//! scrubbed environment every time.
//!
//! # Where hk is not installed
//!
//! Resolved through `mise which hk`, the pinned tool, exactly as the retired suite
//! resolved it through its runner's PATH. A host with no hk has learned nothing
//! about the plan, so each case returns rather than failing — the shape
//! `hk_fix_selection.rs` already uses for the same tool.

// CLOUD-1268's fifth arm. `hk.pkl` is this repository's gate definition: it does
// not die, so what is spelled here is a port WITHOUT a retirement, and every arm
// names the survivor it still accounts for.
//
// ported: tests/hk-selection.bats subject:hk.pkl crates/batten/tests/it/hk_selection.rs
// ported: "hk-selection.bats::every path selects batten-check once a rule globs the whole tree" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::AGENTS.md DOES select batten-check — a budget file is an input" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::the engine selects batten-check" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::the config authority selects batten-check" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::a dependency change selects batten-check" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::every non-crates path a batten.toml rule globs selects batten-check" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::the embedded budget path selects batten-check" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::a manifest change selects macos-link-check, a doc change does not" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// changed: "hk-selection.bats::every slow-tier step is skipped when the profile is off" crates/batten/tests/it/hk_selection.rs the roster loses `test:bats`, which this same change retires with its step; every other slow-tier step the suite named is still asserted skipped at `!slow`
// changed: "hk-selection.bats::every slow-tier step still runs under check, which is what CI drives" crates/batten/tests/it/hk_selection.rs the roster loses `test:bats`, which this same change retires with its step; every other slow-tier step the suite named is still asserted included under `check`
// changed: "hk-selection.bats::an unprofiled step is selected in both tiers" crates/batten/tests/it/hk_selection.rs the control is `taplo` rather than `no-docs-tree`, because CLOUD-1991 moves `no-docs-tree` into the slow tier; the property is strengthened besides — every step `!slow` includes must also be included under `check`
// changed: "hk-selection.bats::the profile skip is reported as profile_exclude, not as a filter miss" crates/batten/tests/it/hk_selection.rs the step observed is `batten-check`, still slow-tier, because `test:bats` retires with this change; the reason kind asserted is unchanged
// ported: "hk-selection.bats::no-docs-tree keeps no glob, so it runs on a change it does not read" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::deno-fmt selects the harness JSON that had no syntax gate" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::deno-fmt leaves Markdown to prettier" crates/batten/tests/it/hk_selection.rs subject:hk.pkl
// ported: "hk-selection.bats::the deno-fmt TRIGGER is wider than the lint:deno COVERAGE, deliberately" crates/batten/tests/it/hk_selection.rs subject:hk.pkl

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

/// The slow-tier steps whose tier this file pins, in both directions.
///
/// `test:bats` was the pole of this list and retires with this change; the rest
/// are the retired suite's own roster, unchanged.
const SLOW_TIER: &[&str] = &[
    "cargo-clippy",
    "test",
    "batten-check",
    "token-bench-check",
    "sbom-check",
];

/// The hk this clone pins, or `None` where it is not installed.
fn hk_binary() -> Option<PathBuf> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: resolving the pinned tool is what the retired `tests/hk-selection.bats` did through its runner's PATH, and the plan is hk's to print"
    )]
    let output = std::process::Command::new("mise")
        .args(["which", "hk"])
        .current_dir(common::at_root("."))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

/// `hk check --plan --json <args>` at the repository root, parsed.
///
/// `--plan` runs nothing, so this is free and has no side effect on the tree. The
/// working directory is what pins which config is under test: hk has no `--cd`
/// and resolves `hk.pkl` from where it stands.
fn plan(hk: &Path, args: &[&str]) -> serde_json::Value {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: the subject IS hk's selection over `hk.pkl`, so reading it means asking hk for its plan, as the retired suite did"
    )]
    let mut command = std::process::Command::new(hk);
    command
        .args(["check", "--plan", "--json"])
        .args(args)
        .current_dir(common::at_root("."));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("HK_") {
            command.env_remove(name);
        }
    }
    let output = command.output().expect("hk prints a plan");
    assert!(
        output.status.success(),
        "hk check --plan {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("`--json` prints one JSON document")
}

/// The step named `step` in `plan`, if the plan carries one.
fn step<'a>(plan: &'a serde_json::Value, step: &str) -> Option<&'a serde_json::Value> {
    plan.get("steps")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(step))
}

/// The status hk assigns `name` in `plan`, or `""` where the step is absent — an
/// absent step equals no status a case asserts, so it fails the case.
fn status_in(plan: &serde_json::Value, name: &str) -> String {
    step(plan, name)
        .and_then(|entry| entry.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The status of one step for a change touching exactly `files`.
fn status_of(hk: &Path, name: &str, files: &[&str]) -> String {
    status_in(&plan(hk, files), name)
}

/// The whole-tree plan at a profile, the profile axis where [`status_of`] is the
/// changed-files axis: a step can be selected by its glob and still excluded by
/// its profile, and the split is only correct if both are asserted.
fn plan_at_profile(hk: &Path, profile: &str) -> serde_json::Value {
    plan(hk, &["--all", "--profile", profile])
}

/// The whole-tree plan as `check` resolves it, which is what CI drives.
fn plan_default(hk: &Path) -> serde_json::Value {
    plan(hk, &["--all"])
}

// --- batten-check: the expensive one -----------------------------------------

#[test]
fn every_path_selects_batten_check_once_a_rule_globs_the_whole_tree() {
    // CLOUD-59's `no-secrets` row globs `**`, so a credential can be in README.md
    // and narrowing the rule would be choosing which files may carry one. The
    // question is whether the glob is still TOTAL; a narrowing that reintroduced
    // a skip fails here. The economy moved to the TIER — `batten-check` is `slow`.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "batten-check", &["README.md"]), "included");
}

#[test]
fn agents_md_does_select_batten_check_a_budget_file_is_an_input() {
    // `[budget.instructions] files = ["AGENTS.md"]`, and a declared budget is a
    // gate under `check` (CLOUD-50). Globbing this step on non-Markdown alone
    // would switch the gate off for the most-edited Markdown file in the repo.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "batten-check", &["AGENTS.md"]), "included");
}

#[test]
fn the_engine_selects_batten_check() {
    let Some(hk) = hk_binary() else { return };
    assert_eq!(
        status_of(&hk, "batten-check", &["crates/batten/src/lib.rs"]),
        "included"
    );
}

#[test]
fn the_config_authority_selects_batten_check() {
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "batten-check", &["batten.toml"]), "included");
}

#[test]
fn a_dependency_change_selects_batten_check() {
    // The gate runs the working tree's engine, so a change to what that engine is
    // built from must run it.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "batten-check", &["Cargo.lock"]), "included");
    assert_eq!(status_of(&hk, "batten-check", &["Cargo.toml"]), "included");
}

#[test]
fn every_non_crates_path_a_rule_globs_selects_batten_check() {
    // mise.toml, the workflows, and a bats suite path — the ones the issue's
    // proposed glob would have dropped. A suite path still matters after this
    // change: the ratchet row over `tests/**/*.bats` stays in `batten.toml`.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "batten-check", &["mise.toml"]), "included");
    assert_eq!(
        status_of(&hk, "batten-check", &[".github/workflows/ci.yml"]),
        "included"
    );
    assert_eq!(
        status_of(&hk, "batten-check", &["tests/lock-complete.bats"]),
        "included"
    );
}

#[test]
fn the_embedded_budget_path_selects_batten_check() {
    let Some(hk) = hk_binary() else { return };
    assert_eq!(
        status_of(&hk, "batten-check", &[".serena/project.yml"]),
        "included"
    );
}

// --- macos-link-check: globbed on the manifests ------------------------------

#[test]
fn a_manifest_change_selects_macos_link_check_a_doc_change_does_not() {
    // Its predicate is `cargo metadata --filter-platform` over the resolved graph,
    // so the manifests are exactly its inputs.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(
        status_of(&hk, "macos-link-check", &["Cargo.lock"]),
        "included"
    );
    assert_eq!(
        status_of(&hk, "macos-link-check", &["README.md"]),
        "skipped"
    );
}

// --- the two tiers: profile-based selection (CLOUD-509) ----------------------

#[test]
fn every_slow_tier_step_is_skipped_when_the_profile_is_off() {
    // The pre-commit economy. `.claude/hooks/git-hook.sh` passes exactly this
    // flag, so this is the selection a commit actually gets.
    let Some(hk) = hk_binary() else { return };
    let plan = plan_at_profile(&hk, "!slow");
    for name in SLOW_TIER {
        assert_eq!(status_in(&plan, name), "skipped", "{name} at !slow");
    }
}

#[test]
fn every_slow_tier_step_still_runs_under_check_which_is_what_ci_drives() {
    // THE ONE THAT MATTERS. `mise run ci` -> `hk check --all` uses this mapping,
    // so a step missing here is a step CI has silently stopped running.
    let Some(hk) = hk_binary() else { return };
    let plan = plan_default(&hk);
    for name in SLOW_TIER {
        assert_eq!(status_in(&plan, name), "included", "{name} under check");
    }
}

#[test]
fn an_unprofiled_step_is_selected_in_both_tiers() {
    // The control. Without it, a run that excluded EVERYTHING would satisfy the
    // skipped-assertion above and look like a working split.
    let Some(hk) = hk_binary() else { return };
    let fast = plan_at_profile(&hk, "!slow");
    let full = plan_default(&hk);
    assert_eq!(status_in(&fast, "taplo"), "included");
    assert_eq!(status_in(&full, "taplo"), "included");
    // And the whole fast tier, not one named step: a step `!slow` still runs is a
    // step `check` must run too, or the split dropped it from CI.
    let included: Vec<&str> = fast
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("status").and_then(serde_json::Value::as_str) == Some("included"))
        .filter_map(|entry| entry.get("name").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        !included.is_empty(),
        "the fast tier selected nothing at all"
    );
    for name in included {
        assert_eq!(status_in(&full, name), "included", "{name} under check");
    }
}

#[test]
fn the_profile_skip_is_reported_as_profile_exclude_not_as_a_filter_miss() {
    // `filter_match` would mean the step's glob stopped matching, which is a
    // selection bug wearing the same status. The JSON kind is snake_case
    // `profile_exclude` — NOT the kebab-case `profile-not-enabled` that names the
    // same condition in hk's `display_skip_reasons` setting.
    let Some(hk) = hk_binary() else { return };
    let plan = plan_at_profile(&hk, "!slow");
    let kinds: Vec<&str> = step(&plan, "batten-check")
        .and_then(|entry| entry.get("reasons"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|reason| reason.get("kind").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        kinds.contains(&"profile_exclude"),
        "batten-check at !slow gave {kinds:?}"
    );
}

#[test]
fn no_docs_tree_keeps_no_glob_so_it_runs_on_a_change_it_does_not_read() {
    // Its input is the whole INDEX — any tracked docs/ path, including one an
    // earlier commit left behind — so a glob would let a violation persist
    // unreported on every commit that did not touch it.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "no-docs-tree", &["README.md"]), "included");
}

// --- deno-fmt: a selector this repo owns, so its reach is measured -----------

#[test]
fn deno_fmt_selects_the_harness_json_that_had_no_syntax_gate() {
    // CLOUD-104: a malformed `.mcp.json` used to reach the gate only by accident
    // of which content check happened to parse it first.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "deno-fmt", &[".mcp.json"]), "included");
    assert_eq!(
        status_of(&hk, "deno-fmt", &[".serena/project.yml"]),
        "included"
    );
}

#[test]
fn deno_fmt_leaves_markdown_to_prettier() {
    // `deno fmt` rewrites documentation whose whitespace is load-bearing, so
    // widening this glob to `**/*.md` would corrupt it.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(status_of(&hk, "deno-fmt", &["AGENTS.md"]), "skipped");
    assert_eq!(status_of(&hk, "prettier", &["AGENTS.md"]), "included");
}

#[test]
fn the_deno_fmt_trigger_is_wider_than_the_lint_deno_coverage_deliberately() {
    // These two report `included` and the task then excludes both. Pinned so that
    // if either side moves, the divergence is a failing case rather than
    // something a reader has to re-derive with `hk check --plan`.
    let Some(hk) = hk_binary() else { return };
    assert_eq!(
        status_of(&hk, "deno-fmt", &[".github/workflows/ci.yml"]),
        "included"
    );
    assert_eq!(
        status_of(
            &hk,
            "deno-fmt",
            &["crates/batten/tests/fixtures/hooks/cursor.json"]
        ),
        "included"
    );
}
