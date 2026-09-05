//! `policy/ci-parity.rego` decides over the compiled engine (CLOUD-1161).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading.
//!
//! This row reads FOUR document formats at once — YAML workflows, the TOML
//! manifest, a TOML release config and a JSON5 bot config — plus the `lines`
//! fact over two shell programs and `tracked` for a file that must be ABSENT.
//! Whether every one of those resolves, and resolves to the shape the predicates
//! expect, is exactly what a `with input as` case cannot answer, because it
//! fabricates the very structure in question.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the roster still names exactly the
//! pull-request jobs, the release PR still opens as a draft, the retired second
//! bot has not come back, the surviving one still carries its five bounds, and
//! the fan-in is still wired end to end.
//!
//! # What this row does NOT decide
//!
//! What a run COSTS — the draft guard, superseding, the concurrency group, the
//! ready subscription — is the `ci-hygiene` preset's, because it is true of the
//! practice rather than of this repository. `crates/batten/tests/it/ci_hygiene.rs`
//! is that half's tier.
//!
//! Whether the foreign-runner cargo invocation still matches the task's own is
//! this row's, as `foreign-cargo-is-the-declared-spelling`. It reads
//! `test:cargo`'s body out of the manifest rather than out of `mise tasks info`,
//! which no policy module can spawn for — and the two are the same bytes only
//! while that task carries no template. `task read unread` is the arm
//! that surfaces the day they stop being.

//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! CLOUD-1161. `ci-local-parity` was 54.6s and 1093 lines holding 40 predicates.
//! The generic half is the `ci-hygiene` preset, the consumer half is
//! `policy/ci-parity.rego`. The predicate that reads `test:cargo`'s own cargo
//! invocation is there too, reading the manifest directly, with the bound on
//! that reading stated above.

// carried: mise-tasks/ci-local-parity.sh policy/ci-parity.rego crates/batten/tests/it/ci_parity.rs crates/batten/tests/it/ci_hygiene.rs
// carried: tests/ci-local-parity.bats policy/ci-parity.rego crates/batten/tests/it/ci_parity.rs crates/batten/tests/it/ci_hygiene.rs

//! # RETIREMENT LEDGER — `tests/ci-local-parity.bats`, 101 cases
//!
//! CARRIED — the same assertion, in a new home.

// carried: "a draft-gated, self-superseding workflow running a verify task passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "a job with no draft guard is refused, and named" crates/batten/tests/it/ci_hygiene.rs
// carried: "a workflow that does not supersede its own runs is refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "a task CI runs that verify does not is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a workflow not triggered by pull_request is out of scope for the landing-path properties" crates/batten/tests/it/ci_parity.rs
// carried: "a pull_request job missing from CI_REQUIRED_CHECKS is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a required name matching no job is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a matrix leg matches on its base name" crates/batten/tests/it/ci_parity.rs
// carried: "a manifest with no required set at all is a failure, not a pass" crates/batten/tests/it/ci_parity.rs
// carried: "a release config that does not open the release PR as a draft is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a release config set to something other than true is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a fan-in that enumerates only some of its needs is refused, and the omission named" crates/batten/tests/it/ci_hygiene.rs
// carried: "a fan-in asserting over needs.* passes, and stays passing when a leg is added" crates/batten/tests/it/ci_hygiene.rs
// carried: "an unquoted # that swallows an interpolation is refused, and named" crates/batten/tests/it/ci_hygiene.rs
// carried: "the same value quoted passes — the repair must not be refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "a whole-line comment mentioning an interpolation passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "a trailing comment with no interpolation after it passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "a foreign-runner job that runs nothing is not a second spelling" crates/batten/tests/it/ci_parity.rs
// carried: "a cache-warm compile with no cache-hit guard is refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "a guard naming a step id that does not exist is refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "a guarded cache-warm compile passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "the no-run exemption cannot be used to escape the property" crates/batten/tests/it/ci_parity.rs
// carried: "this repository's real workflows pass" crates/batten/tests/it/ci_hygiene.rs
// carried: "a job that starts without asking the landing lease is refused, and named" crates/batten/tests/it/ci_parity.rs
// carried: "the precondition must be FIRST — a job that asks after installing has already spent" crates/batten/tests/it/ci_parity.rs
// carried: "a fan-in is exempt, because it cannot start before its dependencies" crates/batten/tests/it/ci_parity.rs
// carried: "a scheduled workflow with no concurrency group is refused, and named" crates/batten/tests/it/ci_hygiene.rs
// carried: "a scheduled workflow that declares one passes, with cancel-in-progress false" crates/batten/tests/it/ci_hygiene.rs
// carried: "two workflows sharing a cron expression are refused, and both named" crates/batten/tests/it/ci_hygiene.rs
// carried: "a staggered pair passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "an every-30-minutes schedule beside a weekly slot is not a collision" crates/batten/tests/it/ci_hygiene.rs
// carried: "a workflow_run job filtering on head_branch with no trigger filter is refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "the same workflow with a trigger-level branches filter passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "a workflow_run workflow with no branch condition at all is not asked for a filter" crates/batten/tests/it/ci_hygiene.rs
// carried: "no dependabot config is the passing state — the bot is retired (CLOUD-660)" crates/batten/tests/it/ci_parity.rs
// carried: "a dependabot config that comes back is refused, and named" crates/batten/tests/it/ci_parity.rs
// carried: "an empty dependabot config is still a config — presence is the predicate" crates/batten/tests/it/ci_parity.rs
// carried: "a renovate config carrying all five keys passes" crates/batten/tests/it/ci_parity.rs
// carried: "each of the five keys missing is refused, and named" crates/batten/tests/it/ci_parity.rs
// carried: "REVERTING rebaseWhen TO never IS REFUSED, because that is the regression (CLOUD-692)" crates/batten/tests/it/ci_parity.rs
// carried: "a key present with a value that is not the fix is the same defect" crates/batten/tests/it/ci_parity.rs
// carried: "all three ecosystems named in the one config passes" crates/batten/tests/it/ci_parity.rs
// carried: "an ecosystem missing from enabledManagers is refused, and named" crates/batten/tests/it/ci_parity.rs
// carried: "mise IS judged now — the one bot can read that file, so its absence is a drift" crates/batten/tests/it/ci_parity.rs
// carried: "a bot prefix with no workflow scoped to it is refused, and named" crates/batten/tests/it/ci_parity.rs
// carried: "a trigger-level branches filter is what satisfies it" crates/batten/tests/it/ci_parity.rs
// carried: "A JOB CONDITION IS NOT A SCOPE, which is property 10's finding reused" crates/batten/tests/it/ci_parity.rs
// carried: "the prefix is read from the config that owns it, not assumed" crates/batten/tests/it/ci_parity.rs
// carried: "a lane whose config is absent is not asked for a watcher" crates/batten/tests/it/ci_parity.rs
// carried: "a trigger no job condition admits is refused, and named" crates/batten/tests/it/ci_hygiene.rs
// carried: "the same workflow admitting both triggers passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "workflow_run is admitted by reading its payload, not only by naming the event" crates/batten/tests/it/ci_hygiene.rs
// carried: "a job condition that mentions no event admits everything, so nothing is judged" crates/batten/tests/it/ci_hygiene.rs
// carried: "a workflow reading check-runs without checks-green is refused" crates/batten/tests/it/ci_parity.rs
// carried: "the same workflow deciding through checks-green passes" crates/batten/tests/it/ci_parity.rs
// carried: "a workflow that never reads check status is not asked for the predicate" crates/batten/tests/it/ci_parity.rs
// carried: "a Windows job may run a task verify does not — there is no local Windows to have caught it" crates/batten/tests/it/ci_parity.rs
// carried: "a macOS job is exempt on the same reasoning" crates/batten/tests/it/ci_parity.rs
// carried: "the identical step on a Linux runner is still refused" crates/batten/tests/it/ci_parity.rs
// carried: "a job declaring no runs-on is judged, not exempted" crates/batten/tests/it/ci_parity.rs
// carried: "an unclassified runner label is judged — the exemption is foreign labels, not non-Linux ones" crates/batten/tests/it/ci_parity.rs
// carried: "a Windows job running a task verify DOES run is still fine" crates/batten/tests/it/ci_parity.rs
// carried: "the exemption is per job, so a Linux job beside a Windows one is still judged" crates/batten/tests/it/ci_parity.rs
// carried: "a commit type inside packageRules passes" crates/batten/tests/it/ci_parity.rs
// carried: "no commit type anywhere is refused" crates/batten/tests/it/ci_parity.rs
// carried: "THE MEASURED DEFECT: a top-level commit type is refused, because a preset outranks it" crates/batten/tests/it/ci_parity.rs
// carried: "a config with no packageRules at all is refused, and says why" crates/batten/tests/it/ci_parity.rs
// carried: "a foreign-runner command matching the task passes" crates/batten/tests/it/ci_parity.rs
// carried: "a task that gained a flag the foreign runner did not is refused, and names both" crates/batten/tests/it/ci_parity.rs
// carried: "a foreign runner whose command drifted from the task is refused the same way" crates/batten/tests/it/ci_parity.rs
// carried: "a tree with no foreign-runner cargo job is refused, not passed" crates/batten/tests/it/ci_parity.rs
// carried: "a task yielding no cargo invocation is refused, not passed" crates/batten/tests/it/ci_parity.rs
// carried: "an anchored comment trigger that also reads draft state passes" crates/batten/tests/it/ci_hygiene.rs
// carried: "CLOUD-853: an UNANCHORED comment trigger is refused, because prose naming the token fires it" crates/batten/tests/it/ci_hygiene.rs
// carried: "CLOUD-853: a comment-triggered merge that never reads draft state is refused" crates/batten/tests/it/ci_hygiene.rs
// carried: "a comment-triggered workflow that does NOT merge is not asked the draft question" crates/batten/tests/it/ci_hygiene.rs
// carried: "a manifest with no CI_FANIN_CHECK is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a manifest with no CI_FANIN_WORKFLOW is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a fan-in that is not in the required roster is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a fan-in workflow that is not a file is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a fan-in workflow that declares no job of that name is refused" crates/batten/tests/it/ci_parity.rs
// carried: "an abandon task that restates the path instead of reading it is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a missing abandon task is refused rather than passed" crates/batten/tests/it/ci_parity.rs
// carried: "THE ANTI-VACUITY TERM: a lander that never calls the abandon is refused" crates/batten/tests/it/ci_parity.rs
// carried: "a missing lander is refused rather than passed" crates/batten/tests/it/ci_parity.rs

//!
//! SUBSUMED — a more general property covers it now. Every one of these is
//! the PARSE doing the work: a comment does not survive into a parsed document,
//! and a parsed value is one shape whatever its source formatting, so a class the
//! shell had to exclude by hand cannot arise here at all.

// subsumed: "a task named only in a comment is not read as spend" crates/batten/tests/it/ci_parity.rs the reading is bounded to `run:` scalars and a YAML comment does not survive the parse, so prose cannot be read as spend by construction rather than by exclusion
// subsumed: "a multi-line run block is read too" crates/batten/tests/it/ci_parity.rs a parsed `run:` scalar carries its whole body whatever the block style, so the folded and literal forms are one shape rather than two
// subsumed: "a cron named only in a comment is not read as a schedule" crates/batten/tests/it/ci_hygiene.rs a YAML comment does not survive the parse at all, so the false-positive class this excluded by hand cannot arise over a parsed document
// subsumed: "a key named only in a comment does not satisfy the property" crates/batten/tests/it/ci_parity.rs a JSON5 comment does not survive the parse, so a key named in prose cannot answer for one that is set
// subsumed: "a manager list broken across lines reads the same as one on a single line" crates/batten/tests/it/ci_parity.rs a parsed array is one value whatever the source formatting, so a formatter's line choice cannot change the verdict by construction
// subsumed: "the endpoint named only in a comment does not demand the predicate" crates/batten/tests/it/ci_parity.rs comments do not survive the parse, so the endpoint named in prose cannot demand the predicate

//!
//! CHANGED — behaviour that diverges deliberately, each with its reason.

// changed: "the concurrency property judges every workflow, not only the pull_request ones" crates/batten/tests/it/ci_hygiene.rs it judges every workflow whose runs answer about ONE SUBJECT — pull_request, issue_comment, workflow_run and schedule — and no longer a push-only workflow, whose runs are each keyed to a different commit and are therefore two subjects rather than two answers. Every measured instance of the original defect is inside the narrowed set; what it gives up is a preset that refuses an ordinary minimal repository, which this tree's own shipped-config canary in tests/prebuilt-lint.bats is what surfaced
// changed: "a required check whose workflow cannot see ready_for_review is refused" crates/batten/tests/it/ci_hygiene.rs the preset scopes it to a workflow that DRAFT-GATES rather than to one producing a required check: a roster is a consumer fact and cannot live in a vendored preset (rule 1). Same condition read from the workflow itself, since a job that skips on a draft is one whose verdict can only arrive on the ready event
// changed: "a workflow producing no required check may omit ready_for_review" crates/batten/tests/it/ci_hygiene.rs the exemption is now 'does not draft-gate' rather than 'produces no required check', for the same rule-1 reason; a workflow whose jobs run on drafts has no skipped run to supersede
// changed: "finding no pull_request workflow at all is a failure, not a pass" crates/batten/tests/it/ci_parity.rs the engine distinguishes could-not-look from not-applicable through `input.tree.missing`, so an unreadable workflow raises workflow read unread while a tree that genuinely runs no such workflow is not-applicable. The shell had one channel for both and had to refuse the empty case to avoid a vacuous pass
// changed: "a missing release config is a failure, not a pass" crates/batten/tests/it/ci_parity.rs a consumer with no release automation is not-applicable rather than refused; the row's `sources` declares the file, so a declared-but-unparseable one raises the could-not-look verdict instead
// changed: "an empty workflow directory is refused rather than silently green" crates/batten/tests/it/ci_parity.rs the anti-vacuity term moved from the gate's own counter to the rule guards: each rule stands down on a tree carrying no workflow, and the compiled-binary tier's `this_repository_is_clean_today` is what proves the rules are not vacuous over the real tree
// changed: "a missing renovate config is a failure, not a pass" crates/batten/tests/it/ci_parity.rs same as the release config: absent is not-applicable and unparseable is loud, which is the distinction the shell could not draw

//!
//! WITHDRAWN — nothing replaced these, because nothing should. All three assert
//! the retired program's own success-line output. A policy module emits findings
//! and says nothing on success (house style §6), so there is no summary line for
//! a successor to carry.

// withdrawn: "the success line reports the lease gate, so a silent skip is visible" the property is about the retired program's own stdout summary line. A policy module emits findings and says nothing on success (house style §6), so there is no summary line to assert and nothing replaced it. The visibility it bought is now the rule's own `governed` guard plus the compiled-binary tier, which fail loudly rather than reporting a count
// withdrawn: "the success line reports how many workflows were judged for concurrency" same: a count in a success line is the shell gate's shape, and a module that says nothing on success has none. Anti-vacuity is carried by `this_repository_is_clean_today` over the real workflow set instead of by a printed number
// withdrawn: "the success line reports the fan-in pairing, so a silent skip is visible" same: the fan-in clauses now fail loudly per clause rather than reporting a pairing on success, and the anti-vacuity term is the lander-never-calls-abandon refusal rather than a line of output

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "ci-parity",
        "kind": "policy",
        "scope": "tree",
        "sources": [
            ".github/workflows/*.yml",
            "mise.toml",
            "release-plz.toml",
            "renovate.json5",
        ],
        "line_sources": [
            ".github/workflows/*.yml",
            "crates/batten/src/lib.rs",
        ],
        "module": "policy/ci-parity.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/ci-parity.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/ci-parity.rego")).expect("install committed module");
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    findings_declared_by(root, root)
}

fn findings_declared_by(root: &Path, vocabulary_root: &Path) -> Vec<(String, Option<usize>)> {
    // A fixture holds this module and no other, so its own tree is the honest
    // vocabulary. The real checkout is not: `verdicts_in` would collect every
    // module's tokens while only this row is loaded, and registry equality runs
    // in BOTH directions — the load is refused for the tokens nothing here emits.
    let verdicts = common::verdicts_in(vocabulary_root);
    // The one `[[pattern]]` row this module reads, declared here as the config
    // declares it. An inline regex in the module is refused at LOAD, so the row
    // has to exist for the bundle to compile at all — which is the registry
    // doing its job rather than a fixture detail.
    let patterns = [batten::pattern::NamedPattern {
        id: "mise-run-task".to_owned(),
        regex: "mise run [a-z][a-z0-9:_-]*".to_owned(),
    }];
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| (finding.path, finding.line))
    .collect()
}

/// The VERDICT TOKENS a run raises, which `findings` above cannot carry.
///
/// `Violation` holds the token and a `Finding` does not — by the time one exists
/// it is gone (CLOUD-1120) — so the class arrives on `Scan::classes`, keyed by
/// fingerprint. Asserting on paths instead would not discriminate here: every
/// case below is a different token over the SAME file, and `--no-run` in
/// particular has to show one token firing while another does not. A test that
/// only asked "is anything refused" would pass on any unrelated finding a
/// fixture edit introduced.
fn verdicts_raised(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    let patterns = [batten::pattern::NamedPattern {
        id: "mise-run-task".to_owned(),
        regex: "mise run [a-z][a-z0-9:_-]*".to_owned(),
    }];
    let mut raised: Vec<String> = rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .classes
    .into_values()
    .collect();
    raised.sort();
    raised
}

// ---------------------------------------------------------------------------
// A sound fixture tree, assembled from the shipped shapes rather than copied.
// ---------------------------------------------------------------------------

const WORKFLOW: &str = r#"
name: CI
on:
  pull_request:
    types: [opened, ready_for_review]
jobs:
  ci:
    name: ci
    runs-on: ubuntu-latest
    steps:
      - name: Landing lease precondition
        run: |
          "$RUNNER_TEMP/batten-bin/batten" lease guard \
            "$LEASE_HEAD_SHA" "$LEASE_HEAD_REF" "$LEASE_RUN_ID" || exit 0
      - run: mise run lint
      - run: mise exec -- cargo nextest run --workspace
  final:
    name: final
    runs-on: ubuntu-latest
    needs: [ci]
    steps:
      - run: echo done
"#;

/// The watcher every live bot lane owes, scoped at the trigger.
const LANDER: &str = r"
name: Land
on:
  workflow_run:
    workflows: [CI]
    branches: ['renovate/**', 'release-plz-**']
concurrency:
  group: land
jobs:
  land:
    runs-on: ubuntu-latest
    steps:
      - run: mise run land
";

const MANIFEST: &str = r#"
[env]
CI_REQUIRED_CHECKS = "ci,final"
CI_FANIN_CHECK = "final"
CI_FANIN_WORKFLOW = ".github/workflows/ci.yml"

[tasks.verify]
run = "mise run verify:gated"

[tasks."verify:gated"]
run = "mise run lint"

[tasks."test:cargo"]
run = """
if ! cargo nextest run --workspace; then exit 1; fi
"""

# `deny` BY NAME, AND IT IS THE REGRESSION TERM RATHER THAN A FILLER TASK
# (measured 2026-09-04). This module was silent over the real tree for as long as
# it bound the manifest to a top-level rule: a top-level rule whose value carries
# a `deny` key at any depth silences the whole module under the engine's
# evaluator, and `mise.toml` declares `[tasks.deny]` for cargo-deny. This fixture
# declared no such task, so every case below was green over a shape that cannot
# trigger it — the suite agreed with the module and neither agreed with the tree.
# Removing this block makes the suite blind again.
[tasks.deny]
run = "cargo deny check"
"#;

const RENOVATE: &str = r#"{
  draftPR: true,
  rebaseWhen: "behind-base-branch",
  prConcurrentLimit: 1,
  minimumReleaseAge: "3 days",
  vulnerabilityAlerts: { enabled: true },
  enabledManagers: ["cargo", "github-actions", "mise"],
  packageRules: [{ semanticCommitType: "ci" }],
}
"#;

fn sound(name: &str) -> PathBuf {
    let root = common::scratch(&format!("ci-parity-{name}"));
    common::write(&root, ".github/workflows/ci.yml", WORKFLOW);
    common::write(&root, ".github/workflows/land.yml", LANDER);
    common::write(&root, "mise.toml", MANIFEST);
    common::write(&root, "renovate.json5", RENOVATE);
    common::write(&root, "release-plz.toml", "[pr]\npr_draft = true\n");
    // THE COMPENSATION'S OWN SITE, since CLOUD-1148 retired the two shell
    // programs this used to stand in for. Both fan-in clauses read one file
    // now — the site that resolves the declaration and the site that reaches
    // `land::abandon` are the same lines — so the sound fixture carries both.
    //
    // THE DECLARATION SITS AT THE CONSTRUCTOR, which is the binding review of
    // #848 added: `abandon_reads_declaration` no longer accepts the read
    // anywhere in the file, so this fixture is written the way rustfmt renders
    // the real call rather than as one line.
    common::write(
        &root,
        "crates/batten/src/lib.rs",
        "let fanin = land::FanIn::from_workflow_path(\n\
        \x20   std::env::var(\"CI_FANIN_WORKFLOW\").unwrap_or_default(),\n\
         );\n\
         let report = land::abandon(&repo, &sha, &fanin);\n",
    );
    install_module(&root);
    root
}

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings_declared_by` states; the scratch name is this case's own,
    // because nextest runs each case in its own process and a shared name is a
    // wipe under another process's read.
    let only = common::scratch("ci-parity-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed wiring should satisfy its own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = sound("sound");
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The defects, each shown able to fail (CLOUD-418).
// ---------------------------------------------------------------------------

#[test]
fn a_ci_task_verify_does_not_run_is_refused() {
    let root = sound("task-parity");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace("- run: mise run lint", "- run: mise run smoke"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a task CI runs that verify does not should be refused"
    );
}

#[test]
fn a_foreign_runner_may_run_a_task_verify_does_not() {
    // There is no local Windows, so the premise "a free local run would have
    // caught it" is false there and the property becomes a prohibition on
    // cross-OS jobs rather than a parity check.
    let root = sound("foreign-runner");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW
            .replace("- run: mise run lint", "- run: mise run smoke")
            .replace(
                "  ci:\n    name: ci\n    runs-on: ubuntu-latest",
                "  ci:\n    name: ci\n    runs-on: windows-latest",
            ),
    );
    assert!(
        findings(&root).is_empty(),
        "a foreign runner is exempt from task parity: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The foreign runner's cargo spelling (CLOUD-662).
//
// THIS TIER IS WHAT PROVES THE ENGINE BUILDS THE INPUT. The predicate reads the
// workflow through `input.tree.lines` and the task through
// `input.tree.documents["mise.toml"]`, and a `with input as` case cannot show
// that either is populated — it fabricates the shape the engine may be unable to
// produce. `line_sources` not declaring the workflows is exactly the defect this
// catches, and it is one that leaves every deny case passing green.
// ---------------------------------------------------------------------------

#[test]
fn a_foreign_leg_running_a_different_cargo_is_refused() {
    let root = sound("foreign-cargo-drift");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "mise exec -- cargo nextest run --workspace",
            "mise exec -- cargo nextest run --workspace --all-features",
        ),
    );
    let found = verdicts_raised(&root);
    assert!(
        found.iter().any(|v| v == "cargo spelling other"),
        "a foreign leg running a cargo the task does not declare should be refused: {found:?}"
    );
}

#[test]
fn a_tree_with_no_foreign_cargo_leg_is_refused() {
    // The anti-vacuity term: every other clause judges a foreign leg, so a tree
    // that lost the leg entirely reports clean for the reason it should refuse.
    let root = sound("foreign-cargo-absent");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "      - run: mise exec -- cargo nextest run --workspace\n",
            "",
        ),
    );
    let found = verdicts_raised(&root);
    assert!(
        found.iter().any(|v| v == "cargo reach absent"),
        "a tree with no foreign cargo leg should be refused, not passed: {found:?}"
    );
}

#[test]
fn a_no_run_build_is_exempt_and_does_not_satisfy_the_term() {
    // A `--no-run` build compiles and executes nothing, so it covers nothing and
    // cannot drift onto work it no longer covers. Exempt from the comparison AND
    // outside the term, so a leg that gains `--no-run` refuses here rather than
    // silently ceasing to test.
    let root = sound("foreign-cargo-no-run");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "mise exec -- cargo nextest run --workspace",
            "mise exec -- cargo nextest run --no-run --workspace",
        ),
    );
    let found = verdicts_raised(&root);
    assert!(
        found.iter().any(|v| v == "cargo reach absent"),
        "a --no-run leg is not a subject and must not satisfy the term: {found:?}"
    );
    assert!(
        !found.iter().any(|v| v == "cargo spelling other"),
        "a --no-run leg is exempt from the comparison itself: {found:?}"
    );
}

#[test]
fn a_task_yielding_no_cargo_invocation_is_refused() {
    // Could-not-look, never a pass: the comparison has lost its right-hand side.
    // This is also the arm that surfaces the bound on reading the manifest rather
    // than `mise tasks info` — a body whose cargo line stops being literal.
    let root = sound("task-cargo-unreadable");
    common::write(
        &root,
        "mise.toml",
        &MANIFEST.replace(
            "if ! cargo nextest run --workspace; then exit 1; fi",
            "./mise-tasks/step-receipt.sh check test:cargo",
        ),
    );
    let found = verdicts_raised(&root);
    assert!(
        found.iter().any(|v| v == "task read unread"),
        "a task yielding no cargo invocation should be refused, not passed: {found:?}"
    );
}

#[test]
fn a_pull_request_job_missing_from_the_roster_is_refused() {
    // CLOUD-327's false green arriving through the roster: the job is not waited
    // on, so a commit reports green without its verdict.
    let root = sound("job-unrequired");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "  final:",
            "  extra:\n    name: extra\n    runs-on: ubuntu-latest\n    steps:\n      - run: mise run lint\n  final:",
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a pull_request job missing from the roster should be refused"
    );
}

#[test]
fn a_roster_name_matching_no_job_is_refused() {
    let root = sound("roster-ghost");
    common::write(
        &root,
        "mise.toml",
        &MANIFEST.replace(r#""ci,final""#, r#""ci,final,ghost""#),
    );
    assert!(
        !findings(&root).is_empty(),
        "a required name no job creates should be refused"
    );
}

#[test]
fn a_release_config_that_does_not_open_a_draft_is_refused() {
    let root = sound("release-ready");
    common::write(&root, "release-plz.toml", "[pr]\npr_draft = false\n");
    assert!(
        !findings(&root).is_empty(),
        "a release PR that opens ready should be refused"
    );
}

#[test]
fn a_returned_dependabot_config_is_refused() {
    // The property INVERTED rather than being deleted: from the commit that
    // removed the file it asserts the file is not there, so a second updater
    // cannot quietly come back on ecosystems the survivor already owns.
    let root = sound("dependabot");
    common::write(&root, ".github/dependabot.yml", "version: 2\n");
    // `tracked` is a git fact, so the fixture has to be a repository for the
    // file to be visible to the predicate at all.
    common::git_in(&root, &["init", "-q"]);
    common::git_in(&root, &["add", "-A"]);
    assert!(
        !findings(&root).is_empty(),
        "a returned dependabot config should be refused"
    );
}

#[test]
fn each_renovate_bound_dropped_is_refused() {
    // All five, because each is the mechanism rather than a preference and
    // dropping any one changes what the lane spends or what it covers.
    for key in [
        "draftPR: true,",
        r#"rebaseWhen: "behind-base-branch","#,
        "prConcurrentLimit: 1,",
        r#"minimumReleaseAge: "3 days","#,
        "vulnerabilityAlerts: { enabled: true },",
    ] {
        let root = sound("renovate-bound");
        common::write(&root, "renovate.json5", &RENOVATE.replace(key, ""));
        assert!(
            !findings(&root).is_empty(),
            "dropping `{key}` should be refused"
        );
    }
}

#[test]
fn a_zero_concurrent_limit_is_not_a_bound() {
    // Renovate reads 0 as UNLIMITED, so the bound and its own negation differ by
    // a single character. Matching the key without its value would pass here.
    let root = sound("renovate-zero");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace("prConcurrentLimit: 1,", "prConcurrentLimit: 0,"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a zero concurrency limit is unlimited, not a bound"
    );
}

#[test]
fn a_top_level_commit_type_does_not_satisfy_the_scoped_one() {
    // THE MEASURED DEFECT: a top-level key is silently outranked by the
    // recommended preset's catch-all package rule, so the config asserts an
    // intent the tool overrode.
    let root = sound("commit-type");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace(
            r#"packageRules: [{ semanticCommitType: "ci" }],"#,
            r#"semanticCommitType: "ci","#,
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a top-level commit type should not satisfy the scoped property"
    );
}

#[test]
fn an_unserved_ecosystem_is_refused() {
    let root = sound("ecosystem");
    common::write(
        &root,
        "renovate.json5",
        &RENOVATE.replace(r#"["cargo", "github-actions", "mise"]"#, r#"["cargo"]"#),
    );
    assert!(
        !findings(&root).is_empty(),
        "an ecosystem nothing proposes updates for should be refused"
    );
}

#[test]
fn a_fanin_outside_the_required_roster_is_refused() {
    let root = sound("fanin-unrequired");
    common::write(
        &root,
        "mise.toml",
        &MANIFEST.replace(
            r#"CI_FANIN_CHECK = "final""#,
            r#"CI_FANIN_CHECK = "nowhere""#,
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a fan-in the landing path does not wait for should be refused"
    );
}

#[test]
fn a_fanin_workflow_declaring_no_such_job_is_refused() {
    let root = sound("fanin-homeless");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace("    name: final", "    name: closing"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a fan-in whose declared home does not carry it should be refused"
    );
}

#[test]
fn an_abandon_that_restates_the_path_is_refused() {
    let root = sound("abandon-literal");
    // A LITERAL WHERE THE DECLARATION BELONGS. This also covers the
    // sibling-variable defect CLOUD-1148 measured: reading `CI_FANIN_CHECK`
    // here compiles, runs, and cancels the fan-in's own run, because that value
    // is a check NAME and `land::worthless` compares against a workflow PATH.
    common::write(
        &root,
        "crates/batten/src/lib.rs",
        "let fanin = land::FanIn::from_workflow_path(\".github/workflows/ci.yml\");\n\
         let report = land::abandon(&repo, &sha, &fanin);\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "an abandon that restates the path rather than reading the declaration \
         should be refused"
    );
}

#[test]
fn a_lander_that_never_abandons_is_refused() {
    // THE ANTI-VACUITY TERM. Every other fan-in clause makes the abandon SAFE;
    // none of them notices it is never called.
    let root = sound("abandon-uncalled");
    // The declaration is read and the abandon is never reached — which is what a
    // compensation arm deleted, renamed, or left behind a `match` that no longer
    // dispatches it looks like from here.
    common::write(
        &root,
        "crates/batten/src/lib.rs",
        "let fanin = land::FanIn::from_workflow_path(\n\
        \x20   std::env::var(\"CI_FANIN_WORKFLOW\").unwrap_or_default(),\n\
         );\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "a lander that never calls the abandon should be refused"
    );
}

#[test]
fn a_declaration_read_far_from_the_constructor_does_not_satisfy_the_clause() {
    // **THE CLASS REVIEW OF #848 NAMED, AND THE ONE THE ROW COULD NOT SEE.**
    // `abandon_reads_declaration` and `lander_calls_abandon` were two
    // INDEPENDENT line questions over one file, so a read of the declaration
    // anywhere — a comment, a doc block, an unrelated helper six thousand lines
    // away — plus a call handed the WRONG value satisfied both, and the module
    // reported clean.
    //
    // That is not a hypothetical shape: the row's own header records the engine
    // reading `CI_FANIN_CHECK` where it needed `CI_FANIN_WORKFLOW` for the whole
    // of the branch that wrote it, which is exactly this, so the rule could not
    // catch its own subject.
    //
    // The fixture is written to pass the OLD spelling and fail the new one:
    // `land::abandon` is reached, `CI_FANIN_WORKFLOW` appears, and the value the
    // constructor is handed is a different variable entirely.
    let root = sound("declaration-far-from-the-call");
    common::write(
        &root,
        "crates/batten/src/lib.rs",
        "// the fan-in is declared as CI_FANIN_WORKFLOW in the manifest\n\
         fn unrelated() -> String {\n\
        \x20   std::env::var(\"CI_FANIN_WORKFLOW\").unwrap_or_default()\n\
         }\n\
         \n\
         let fanin = land::FanIn::from_workflow_path(\n\
        \x20   std::env::var(\"CI_FANIN_CHECK\").unwrap_or_default(),\n\
         );\n\
         let report = land::abandon(&repo, &sha, &fanin);\n",
    );
    assert!(
        !findings(&root).is_empty(),
        "a declaration read that is not the constructor's own argument should \
         be refused: the call is handed a check name and the module cannot see it"
    );
}

#[test]
fn the_constructor_and_its_declaration_may_sit_on_one_line() {
    // The window is THREE lines rather than one, deliberately: pinning rustfmt's
    // current rendering would make a reflow silence the gate, which is strictly
    // worse than the duplication the binding exists to stop. So the collapsed
    // spelling has to pass too, and this is the case that says so.
    let root = sound("constructor-one-line");
    common::write(
        &root,
        "crates/batten/src/lib.rs",
        "let fanin = land::FanIn::from_workflow_path(std::env::var(\"CI_FANIN_WORKFLOW\").unwrap_or_default());\n\
         let report = land::abandon(&repo, &sha, &fanin);\n",
    );
    assert!(
        findings(&root).is_empty(),
        "one line carrying both halves is still the binding: {:?}",
        findings(&root)
    );
}

#[test]
fn a_job_that_starts_without_asking_the_lease_is_refused() {
    // The lease serialises landing, but enforcing it only inside the lander means
    // anything else pushing to a ready pull request buys a full matrix without
    // ever touching the lock. Measured: four concurrent matrices while the lease
    // changed hands three times, every holder honouring it.
    let root = sound("lease-absent");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "      - name: Landing lease precondition\n        run: |\n          \"$RUNNER_TEMP/batten-bin/batten\" lease guard \\\n            \"$LEASE_HEAD_SHA\" \"$LEASE_HEAD_REF\" \"$LEASE_RUN_ID\" || exit 0\n",
            "",
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a job that can start immediately without asking the lease should be refused"
    );
}

#[test]
fn a_precondition_invoked_without_the_tolerant_suffix_is_refused() {
    // The presence clause matches the step's NAME, so a copy that reds its own
    // job reads as present and correct. Counted rather than searched for absence,
    // because the two forms differ only by the suffix.
    let root = sound("lease-fatal");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace("\"$LEASE_RUN_ID\" || exit 0", "\"$LEASE_RUN_ID\""),
    );
    assert!(
        !findings(&root).is_empty(),
        "a precondition body that can red the first step of every job should be refused"
    );
}

#[test]
fn a_cached_path_carrying_an_expression_is_refused() {
    // The landed defect (CLOUD-1342). `actions/cache` identifies an entry by key
    // AND version, and version is derived from the `path` — so a path carrying an
    // expression moves the entry out of reach of the next run whatever the key
    // says. Measured before the fix: 4 runs across 2 pull requests, 0 hits,
    // ~190 MB written and discarded each time, and the job log said only
    // `Cache not found`.
    let root = sound("cache-path-varies");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "      - run: mise run lint\n",
            "      - uses: actions/cache@v6.1.0\n        with:\n          path: \
             target/perf/base-${{ steps.base.outputs.sha }}\n          key: perf-base\n      \
             - run: mise run lint\n",
        ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a cached path that differs between runs of the same job should be refused"
    );
}

#[test]
fn an_expression_in_the_cache_key_alone_is_clean() {
    // The other direction, and it is the one that keeps the rule from refusing
    // its own fix: an expression BELONGS in a key. A key that never moves never
    // saves, because "if the provided `key` matches an existing cache, a new
    // cache is not created" — so the moved-base MISS is what buys the save, and a
    // predicate reading both halves would forbid the only shape that works.
    let root = sound("cache-key-varies");
    common::write(
        &root,
        ".github/workflows/ci.yml",
        &WORKFLOW.replace(
            "      - run: mise run lint\n",
            "      - uses: actions/cache@v6.1.0\n        with:\n          path: \
             target/perf/base-seed\n          key: perf-base-${{ steps.base.outputs.sha }}\n      \
             - run: mise run lint\n",
        ),
    );
    assert!(
        findings(&root).is_empty(),
        "an expression in the key is the working shape and must not be refused: {:?}",
        findings(&root)
    );
}

#[test]
fn a_workflow_reading_check_runs_without_the_one_predicate_is_refused() {
    // Every hand-rolled copy of the green predicate so far has counted a wholly
    // skipped set as zero outstanding, which is green — and a wholly skipped set
    // is exactly what a draft-era refresh looks like.
    let root = sound("checks-rerolled");
    common::write(
        &root,
        ".github/workflows/land.yml",
        &LANDER.replace("- run: mise run land", "- run: gh api /check-runs | jq ."),
    );
    assert!(
        !findings(&root).is_empty(),
        "a workflow deciding green from its own copy of the predicate should be refused"
    );
}

#[test]
fn a_bot_prefix_with_no_watcher_is_refused() {
    // Nothing runs on a bot's behalf unless a workflow is watching its heads, so
    // handing a lane to a bot without a lander is a complete, silent failure.
    let root = sound("prefix-unwatched");
    common::write(
        &root,
        ".github/workflows/land.yml",
        &LANDER.replace("'renovate/**', 'release-plz-**'", "'release-plz-**'"),
    );
    assert!(
        !findings(&root).is_empty(),
        "a live bot lane with no workflow watching its prefix should be refused"
    );
}

#[test]
fn a_prefix_named_only_in_a_job_condition_is_not_a_scope() {
    // The `workflow_run` finding reused rather than restated: a job condition is
    // evaluated after the run exists, so a lander scoped only there is not
    // scoped. Without this the rule would accept the exact shape that produced
    // 1131 inserted-and-skipped runs in 25 hours.
    let root = sound("prefix-in-condition");
    common::write(
        &root,
        ".github/workflows/land.yml",
        &LANDER
            .replace("    branches: ['renovate/**', 'release-plz-**']\n", "")
            .replace(
                "  land:\n    runs-on: ubuntu-latest",
                "  land:\n    runs-on: ubuntu-latest\n    if: startsWith(github.event.workflow_run.head_branch, 'renovate/')",
            ),
    );
    assert!(
        !findings(&root).is_empty(),
        "a prefix named only in a job condition is not a trigger-level scope"
    );
}

// ---------------------------------------------------------------------------
// Not-applicable, never a vacuous pass pretending to be a verdict.
// ---------------------------------------------------------------------------

#[test]
fn a_tree_with_no_verify_task_is_not_this_rows_business() {
    let root = common::scratch("ci-parity-absent");
    install_module(&root);
    assert!(
        findings(&root).is_empty(),
        "absent is not-applicable, never a finding: {:?}",
        findings(&root)
    );
}
