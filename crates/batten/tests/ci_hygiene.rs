//! The `ci-hygiene` preset decides over the compiled engine (CLOUD-1161).
//!
//! # Why this tier
//!
//! The preset's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading.
//!
//! This row reads deeper into a parsed workflow than any of its neighbours, and
//! one of those reads is the whole risk the retired program's issue flagged:
//! **YAML 1.1 resolves a bare `on` to a boolean**, which would key the trigger
//! block as `true` and turn every trigger predicate into a dead gate — passing
//! its own suite green while deciding nothing. `privileged-lane` already reads
//! `doc.on[...]` over this repository's real workflows, so the answer was
//! already in the tree; `the_engine_keys_the_trigger_block_as_on` is this row's
//! own proof of it, over real YAML text rather than a fabricated document.
//!
//! The second shape question is the same class: `cancel-in-progress: true`
//! parses to a BOOLEAN, not the string `"true"`. The retired program matched it
//! as text. A module comparing against `"true"` would be green in its own suite
//! and dead in the field, so `a_quoted_cancel_flag_does_not_satisfy_the_boolean`
//! drives that distinction through the parser.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the preset over this checkout. Every
//! other fixture is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says all 24 committed workflows are still
//! draft-gated, superseding, concurrency-grouped and subscribed to the ready
//! event. Without it, a preset that refused everything would look identical to
//! one that discriminates.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, deserialized rather than
/// struct-literalled: `Rule` carries `deny_unknown_fields`, so this goes through
/// the same column census a consumer's config does.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "ci-hygiene",
        "kind": "policy",
        "scope": "tree",
        "preset": "ci-hygiene",
        "sources": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying one workflow.
///
/// No module is installed: a preset ships INSIDE the binary, so unlike an
/// in-repo module there is nothing to copy into the fixture. That is also what
/// makes this tier the only place the vendored bytes are exercised at all.
fn tree(name: &str, workflow: &str) -> PathBuf {
    let root = common::scratch(&format!("ci-hygiene-{name}"));
    common::write(&root, ".github/workflows/ci.yml", workflow);
    root
}

fn findings(root: &Path) -> Vec<(String, Option<usize>)> {
    // A preset's verdicts are the binary's own vendored table rather than the
    // consumer's `[[verdict]]` rows, so the fixture needs no vocabulary of its
    // own — which is exactly the property that makes a preset loadable by a
    // consumer who wrote no rows at all.
    //
    // PATTERNS ARE NOT LIKE VERDICTS, and this tier is what proved it. A
    // `[[pattern]]` row IS the consumer's, so a fixture passing an empty table
    // leaves `data.batten.patterns[...]` undefined — the rule reading it then
    // never fires, and both its deny case and its clean case pass. That is
    // CLOUD-845's dead-gate class arriving inside the test harness rather than
    // in the module, and the load-time tier cannot see it because it fabricates
    // the whole document including the pattern data.
    let patterns = [batten::pattern::NamedPattern {
        id: "cache-hit-step-id".to_owned(),
        regex: r"steps\.[A-Za-z0-9_-]+\.outputs\.cache-hit".to_owned(),
    }];
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &[],
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

/// The shape this repository ships, reduced to what the four rules are about.
///
/// Assembled from the real workflow's own markers rather than copied wholesale:
/// a fixture that pasted a shipped 600-line `ci.yml` would be re-asserting the
/// file under test, and every edit to it would be a fixture edit too.
const SOUND: &str = r"
name: CI
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  build:
    name: build
    runs-on: ubuntu-latest
    if: ${{ github.event.pull_request.draft == false }}
    steps:
      - run: mise run ci
";

// ---------------------------------------------------------------------------
// The tree this preset actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "the committed workflows should satisfy the preset they enable: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the rules
    // simply cannot read — a preset that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("sound", SOUND);
    assert!(
        findings(&root).is_empty(),
        "the sound fixture should be clean: {:?}",
        findings(&root)
    );
}

// ---------------------------------------------------------------------------
// The two parse questions, which a `with input as` case cannot answer.
// ---------------------------------------------------------------------------

#[test]
fn the_engine_keys_the_trigger_block_as_on() {
    // THE DEAD-GATE CLASS THIS ROW WAS WARNED ABOUT. YAML 1.1 resolves a bare
    // `on` to a boolean; if this engine's parser did that, the trigger block
    // would key as `true`, `on_pull_request` would never hold, and every
    // pull-request-scoped rule would be silently absent — green over a workflow
    // it never judged.
    //
    // Proved by DISCRIMINATION rather than by inspection: this workflow is
    // pull-request-triggered and omits `ready_for_review`, so a refusal can only
    // arrive if the trigger block was read as `on`. A parser that keyed it `true`
    // returns clean here, and this case fails.
    let no_ready = SOUND.replace(
        "    types: [opened, synchronize, reopened, ready_for_review]",
        "    types: [opened, synchronize]",
    );
    let root = tree("trigger-key", &no_ready);
    assert!(
        !findings(&root).is_empty(),
        "the `on:` block must survive the parse as the string key, or every \
         trigger predicate is a dead gate"
    );
}

#[test]
fn a_quoted_cancel_flag_does_not_satisfy_the_boolean() {
    // The retired program matched `cancel-in-progress: true` as TEXT, where the
    // quoted and bare spellings are identical. Through a parser they are a string
    // and a boolean, and only the boolean is the flag GitHub honours.
    let quoted = SOUND.replace("cancel-in-progress: true", "cancel-in-progress: 'true'");
    let root = tree("quoted-cancel", &quoted);
    assert!(
        !findings(&root).is_empty(),
        "a quoted `cancel-in-progress` is a string, not the flag"
    );
}

// ---------------------------------------------------------------------------
// The four defects, each shown able to fail (CLOUD-418).
// ---------------------------------------------------------------------------

#[test]
fn a_job_that_runs_on_a_draft_is_refused_and_named() {
    let ungated = SOUND.replace(
        "    if: ${{ github.event.pull_request.draft == false }}\n",
        "",
    );
    let root = tree("draft", &ungated);
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".github/workflows/ci.yml"),
        "the workflow should be named as the place to fix it: {found:?}"
    );
}

#[test]
fn a_step_level_draft_guard_is_read_too() {
    // A reading that reached only the job level would refuse a workflow that is
    // correctly gated, and a gate that refuses its own remedy gets switched off.
    // It is also a second, deeper path through the parsed document — a mapping
    // inside a sequence inside a mapping — so it says the boundary builds
    // `jobs.<name>.steps[].if` and not merely the job's own keys.
    let step_level = SOUND
        .replace(
            "    if: ${{ github.event.pull_request.draft == false }}\n",
            "",
        )
        .replace(
            "      - run: mise run ci",
            "      - run: mise run ci\n        if: ${{ github.event.pull_request.draft == false }}",
        );
    let root = tree("step-guard", &step_level);
    assert!(
        findings(&root).is_empty(),
        "a step-level guard should satisfy the rule: {:?}",
        findings(&root)
    );
}

#[test]
fn a_workflow_that_never_supersedes_itself_is_refused() {
    let no_cancel = SOUND.replace("  cancel-in-progress: true\n", "");
    let root = tree("no-cancel", &no_cancel);
    assert!(
        !findings(&root).is_empty(),
        "a pull-request workflow that cannot supersede its own runs should be refused"
    );
}

#[test]
fn a_workflow_with_no_concurrency_group_is_refused() {
    let none = SOUND.replace(
        "concurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\n",
        "",
    );
    let root = tree("no-group", &none);
    assert!(
        !findings(&root).is_empty(),
        "a workflow that can race itself should be refused"
    );
}

#[test]
fn a_draft_gated_workflow_that_cannot_be_superseded_is_refused() {
    // CLOUD-503's deadlock: draft-gated, so the `opened` run is a skip, and with
    // no `ready_for_review` there is no later event that could replace it.
    let no_ready = SOUND.replace(
        "    types: [opened, synchronize, reopened, ready_for_review]",
        "    types: [opened, synchronize, reopened]",
    );
    let root = tree("no-ready", &no_ready);
    assert!(
        !findings(&root).is_empty(),
        "a draft-gated workflow with no ready_for_review should be refused"
    );
}

// ---------------------------------------------------------------------------
// The shapes that must NOT be refused.
// ---------------------------------------------------------------------------

#[test]
fn a_scheduled_workflow_may_decline_to_supersede_itself() {
    // The two concurrency rules are separate for exactly this: a scheduled
    // workflow must not be killed by its own next tick, so `false` is correct
    // there and refusing it would make the preset unusable off the landing path.
    let scheduled = r"
name: Nightly
on:
  schedule:
    - cron: '0 3 * * *'
concurrency:
  group: nightly
  cancel-in-progress: false
jobs:
  sweep:
    runs-on: ubuntu-latest
    steps:
      - run: mise run sweep
";
    let root = tree("scheduled", scheduled);
    assert!(
        findings(&root).is_empty(),
        "a scheduled workflow should not be asked to cancel itself: {:?}",
        findings(&root)
    );
}

#[test]
fn a_workflow_that_does_not_draft_gate_is_not_asked_for_ready() {
    // Demanding the subscription of a workflow whose jobs run on drafts anyway
    // would assert more than the failure needs: there is no skipped run to
    // supersede.
    let ungated = SOUND
        .replace(
            "    if: ${{ github.event.pull_request.draft == false }}\n",
            "",
        )
        .replace(
            "    types: [opened, synchronize, reopened, ready_for_review]",
            "    types: [opened, synchronize, reopened]",
        );
    let root = tree("no-gate-no-ready", &ungated);
    let found = findings(&root);
    // The draft rule still fires; what must NOT appear is a second finding about
    // the ready event.
    assert_eq!(
        found.len(),
        1,
        "only the draft guard should be missing here: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// The wiring half, over the compiled binary. Each of these reads a shape a
// `with input as` case fabricates: a cron SEQUENCE, a `needs` ARRAY, the trigger
// map iterated by key, and a step id nested in a sequence.
// ---------------------------------------------------------------------------

#[test]
fn a_workflow_run_scoped_only_in_a_job_condition_is_refused() {
    let unscoped = r"
name: Land
on:
  workflow_run:
    workflows: [CI]
concurrency:
  group: land
jobs:
  land:
    runs-on: ubuntu-latest
    if: startsWith(github.event.workflow_run.head_branch, 'bot/')
    steps:
      - run: land
";
    let root = tree("wfrun-unscoped", unscoped);
    assert!(
        !findings(&root).is_empty(),
        "a branch scope written only in a job condition should be refused"
    );
}

#[test]
fn an_unanchored_comment_predicate_is_refused() {
    let unanchored = r"
name: Comment
on:
  issue_comment:
    types: [created]
concurrency:
  group: comment
jobs:
  go:
    runs-on: ubuntu-latest
    if: contains(github.event.comment.body, '/land')
    steps:
      - run: go
";
    let root = tree("comment-unanchored", unanchored);
    assert!(
        !findings(&root).is_empty(),
        "an unanchored comment predicate should be refused"
    );
}

#[test]
fn a_declared_trigger_no_job_admits_is_refused() {
    // The trigger MAP iterated by key, which is the shape this proves: a
    // workflow declaring two triggers and admitting one.
    let unreachable = r"
name: Sweep
on:
  schedule:
    - cron: '0 1 * * *'
  workflow_dispatch:
concurrency:
  group: sweep
jobs:
  go:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule'
    steps:
      - run: go
";
    let root = tree("trigger-unreachable", unreachable);
    assert!(
        !findings(&root).is_empty(),
        "a declared trigger no job condition admits should be refused"
    );
}

#[test]
fn two_workflows_sharing_a_cron_are_refused() {
    // A cron SEQUENCE under `schedule:`, across TWO documents — the only case
    // here whose predicate spans files, so it also says the engine hands the
    // module every declared document at once rather than one at a time.
    let root = common::scratch("ci-hygiene-cron");
    for (name, group) in [("a", "alpha"), ("b", "beta")] {
        common::write(
            &root,
            &format!(".github/workflows/{name}.yml"),
            &format!(
                "name: {group}
on:
  schedule:
    - cron: '0 3 * * *'
concurrency:
                   group: {group}
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
                       - run: go
"
            ),
        );
    }
    assert!(
        !findings(&root).is_empty(),
        "two workflows on one cron expression should be refused"
    );
}

#[test]
fn a_staggered_pair_is_clean() {
    // The discriminating half: without it, a rule that flagged every schedule
    // would pass the case above and look identical to one that compares.
    let root = common::scratch("ci-hygiene-cron-ok");
    for (name, group, cron) in [("a", "alpha", "0 3 * * *"), ("b", "beta", "30 3 * * *")] {
        common::write(
            &root,
            &format!(".github/workflows/{name}.yml"),
            &format!(
                "name: {group}
on:
  schedule:
    - cron: '{cron}'
concurrency:
                   group: {group}
jobs:
  go:
    runs-on: ubuntu-latest
    steps:
                       - run: go
"
            ),
        );
    }
    assert!(
        findings(&root).is_empty(),
        "a staggered pair should be clean: {:?}",
        findings(&root)
    );
}

#[test]
fn a_fan_in_that_enumerates_only_some_of_its_needs_is_refused() {
    // The `needs` ARRAY, and the defect that made this property exist: a fan-in
    // asserting three of four dependencies leaves a red fourth green on the one
    // check branch protection requires.
    let partial = r"
name: CI
on:
  pull_request:
    types: [opened, ready_for_review]
concurrency:
  group: ci
  cancel-in-progress: true
jobs:
  final:
    runs-on: ubuntu-latest
    needs: [alpha, beta]
    if: ${{ github.event.pull_request.draft == false }}
    steps:
      - run: test needs.alpha.result = success
";
    let root = tree("fanin-partial", partial);
    assert!(
        !findings(&root).is_empty(),
        "a fan-in asserting only some of its needs should be refused"
    );
}

#[test]
fn a_cache_warm_guard_naming_a_missing_step_id_is_refused() {
    // The step id lives in a mapping inside a sequence, and the guard that reads
    // it is a string in a sibling mapping — so this is the deepest read in the
    // preset and the one most likely to be a dead gate if the boundary flattened
    // anything.
    let missing_id = r"
name: Warm
on:
  push:
concurrency:
  group: warm
jobs:
  warm:
    runs-on: ubuntu-latest
    steps:
      - uses: Swatinem/rust-cache@v2
        id: restore
      - run: cargo test --no-run
        if: steps.cache.outputs.cache-hit != 'true'
";
    let root = tree("warm-missing-id", missing_id);
    assert!(
        !findings(&root).is_empty(),
        "a cache guard naming a step id nothing declares should be refused"
    );
}

#[test]
fn a_guarded_cache_warm_compile_is_clean() {
    let guarded = r"
name: Warm
on:
  push:
concurrency:
  group: warm
jobs:
  warm:
    runs-on: ubuntu-latest
    steps:
      - uses: Swatinem/rust-cache@v2
        id: cache
      - run: cargo test --no-run
        if: steps.cache.outputs.cache-hit != 'true'
";
    let root = tree("warm-guarded", guarded);
    assert!(
        findings(&root).is_empty(),
        "a guarded cache-warm compile should be clean: {:?}",
        findings(&root)
    );
}

#[test]
fn a_tree_with_no_workflow_is_not_this_presets_business() {
    let root = common::scratch("ci-hygiene-absent");
    assert!(
        findings(&root).is_empty(),
        "absent is not-applicable, never a finding: {:?}",
        findings(&root)
    );
}
