//! `release wire other` over the compiled engine (CLOUD-618, CLOUD-1026,
//! CLOUD-1717).
//!
//! `policy/release-tracking.rego` walks both release workflows' lines, and this
//! tier drives the committed module through `rules::run_static` over synthetic
//! workflows plus the two committed ones. Each shape leaves a job GREEN while a
//! shipped tag fails to reach Linear, so each case below is one the program's
//! suite held, now asked of the module. The pointer is `<workflow>#<token>` plus
//! the line, where the program printed `<workflow>:<line> release-tracking-<token>`.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-tracking-check.sh policy/release-tracking.rego kind:mechanism crates/batten/tests/it/release_tracking.rs
// ported: tests/release-tracking-check.bats crates/batten/tests/it/release_tracking.rs subject:.github/workflows/release-plz.yml
// carried: "the workflow this change ships passes" policy/release-tracking.rego kind:mechanism
// carried: "the backfill workflow this change ships passes" policy/release-tracking.rego kind:mechanism
// carried: "the clean fixture passes" policy/release-tracking.rego kind:mechanism
// ported: "the summary names both subjects" crates/batten/tests/it/release_tracking.rs subject:.github/workflows/linear-release-backfill.yml — that both are judged is `an_absent_workflow_is_unread_never_clean`
// changed: "the committed workflow is judged from any directory in the tree" policy/release-tracking.rego the engine resolves `line_sources` from the repository root by construction, so there is no working directory for the reading to depend on; the committed-workflow cases are that reading
// carried: "a dropped sync invocation is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped complete invocation is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped sync invocation on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped complete invocation on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "the floating @v0 ref upstream publishes is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a SHA pin without its version comment is a violation" policy/release-tracking.rego kind:mechanism
// carried: "an unpinned ref on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped credential precondition is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped credential precondition on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "an absent fetch-depth is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a non-zero fetch-depth is a violation" policy/release-tracking.rego kind:mechanism
// carried: "fetch-depth 0 on a job that does not invoke the action is not enough" policy/release-tracking.rego kind:mechanism
// carried: "an absent fetch-depth on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a literal version instead of the resolved tag output is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a version bound to an undeclared step is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a step-output version on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a literal version on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a version bound to an undeclared input is a violation" policy/release-tracking.rego kind:mechanism
// carried: "an input declared nowhere but passed as a step key is not a declaration" policy/release-tracking.rego kind:mechanism
// carried: "a deeper but valid input indentation still declares the input" policy/release-tracking.rego kind:mechanism
// carried: "a dropped tag-resolution step is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a dropped tag-resolution step does not also report the refresh" policy/release-tracking.rego kind:mechanism
// carried: "a dropped tag refresh is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a tag refresh after the resolver is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a fetch without --tags is not a refresh" policy/release-tracking.rego kind:mechanism
// carried: "a comment quoting the resolver is not the resolver" policy/release-tracking.rego kind:mechanism
// carried: "a comment quoting the refresh does not satisfy the refresh rule" policy/release-tracking.rego kind:mechanism
// carried: "a dropped tag-exists probe on the backfill path is a violation" policy/release-tracking.rego kind:mechanism
// carried: "the release path is not asked for a tag-exists probe" policy/release-tracking.rego kind:mechanism
// carried: "a backfill checkout with no ref is a violation" policy/release-tracking.rego kind:mechanism
// carried: "fetch-depth 0 does not stand in for a bound ref" policy/release-tracking.rego kind:mechanism
// carried: "a backfill checkout pinned to a branch is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a backfill checkout bound to an undeclared input is a violation" policy/release-tracking.rego kind:mechanism
// carried: "the release path is not asked for a bound ref" policy/release-tracking.rego kind:mechanism
// carried: "a backfill sync with no base_ref is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a bound ref does not stand in for a range base" policy/release-tracking.rego kind:mechanism
// carried: "a literal base_ref is a violation" policy/release-tracking.rego kind:mechanism
// carried: "a base_ref bound to an undeclared step is a violation" policy/release-tracking.rego kind:mechanism
// carried: "the release path is not asked for a range base" policy/release-tracking.rego kind:mechanism
// changed: "an absent workflow is could-not-look, not a violation" policy/release-tracking.rego an absent workflow is `release wire unread`, a deny finding through `check`, where the program exited 2; the class stays could-not-look and still never a pass
// changed: "a directory where the workflow should be is could-not-look" policy/release-tracking.rego the same move: a directory is no readable line source, so the workflow reads as absent and is `release wire unread`
// changed: "an absent backfill workflow is could-not-look, not a violation" policy/release-tracking.rego the same move, on the backfill subject
// changed: "an unreadable backfill workflow is not a clean release path" policy/release-tracking.rego the same move: the finding names the backfill path, and no finding or sentence certifies the release path on the strength of it
// carried: "findings are pointers, never workflow text" policy/release-tracking.rego kind:mechanism
// carried: "output is sorted and stable across runs" policy/release-tracking.rego kind:mechanism
// carried: "findings from both subjects sort into one list" policy/release-tracking.rego kind:mechanism
// ported: "a failing run prints no success summary" crates/batten/tests/it/release_tracking.rs subject:.github/workflows/release-plz.yml — a failing `check` prints findings only, `findings_are_pointers_never_workflow_text`

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

const RELEASE: &str = ".github/workflows/release-plz.yml";
const BACKFILL: &str = ".github/workflows/linear-release-backfill.yml";

/// The `[[pattern]]` rows the module reads, taken from the committed config so
/// the fixture cannot drift from what a consumer declares.
const PATTERNS: &[&str] = &[
    "yaml-comment",
    "yaml-key-line",
    "linear-release-uses",
    "action-sha-pin",
    "gha-step-output",
    "gha-dispatch-input",
    "linear-key-guard",
    "gha-output-write",
    "checkout-uses",
    "git-tag-refresh",
    "tag-exists-probe",
];

/// The release path, reduced to the nodes the module judges. TWO JOBS, and the
/// first one is not decoration: a cache-warm job whose checkout comes FIRST and
/// carries no `fetch-depth` is what made a file-global depth probe pass for the
/// wrong reason.
const CLEAN_RELEASE: &str = r#"name: release-plz
on:
  push:
    branches: [main]
jobs:
  cache-warm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false
  release-plz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          fetch-depth: 0
      - run: mise run release
      - name: Refresh tags after release-plz pushed one
        run: git fetch --force --tags origin
      - name: Resolve the release tag this push shipped
        id: release-tag
        run: echo "tag=$(git tag --points-at HEAD | grep -E '^v[0-9]' | head -n1)" >>"$GITHUB_OUTPUT"
      - name: Release tracking requires its credential
        if: steps.release-tag.outputs.tag != ''
        env:
          LINEAR_ACCESS_KEY: ${{ secrets.LINEAR_ACCESS_KEY }}
        run: |
          if [ -z "$LINEAR_ACCESS_KEY" ]; then
            echo "::error:: LINEAR_ACCESS_KEY is empty" >&2
            exit 1
          fi
      - name: Record the release in Linear
        if: steps.release-tag.outputs.tag != ''
        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
        with:
          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
          command: sync
          version: ${{ steps.release-tag.outputs.tag }}
      - name: Complete the Linear release
        if: steps.release-tag.outputs.tag != ''
        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
        with:
          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
          command: complete
          version: ${{ steps.release-tag.outputs.tag }}
"#;

/// The backfill path: the version is a declared `workflow_dispatch` input, and
/// the tag-exists probe stands in for the resolver a dispatch does not have.
const CLEAN_BACKFILL: &str = r#"name: linear-release-backfill
on:
  workflow_dispatch:
    inputs:
      tag:
        description: Release tag to record in Linear
        required: true
        type: string
jobs:
  linear-release-backfill:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          ref: ${{ inputs.tag }}
          fetch-depth: 0
          persist-credentials: false
      - name: The tag must exist in this checkout
        env:
          TAG: ${{ inputs.tag }}
        run: |
          if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
            echo "::error:: no such tag" >&2
            exit 1
          fi
      - name: Resolve the tag this one follows
        id: base
        env:
          TAG: ${{ inputs.tag }}
        run: echo "ref=$(git describe --abbrev=0 --tags "$TAG^" 2>/dev/null || true)" >>"$GITHUB_OUTPUT"
      - name: Release tracking requires its credential
        env:
          LINEAR_ACCESS_KEY: ${{ secrets.LINEAR_ACCESS_KEY }}
        run: |
          if [ -z "$LINEAR_ACCESS_KEY" ]; then
            echo "::error:: LINEAR_ACCESS_KEY is empty" >&2
            exit 1
          fi
      - name: Record the release in Linear
        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
        with:
          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
          command: sync
          version: ${{ inputs.tag }}
          base_ref: ${{ steps.base.outputs.ref }}
      - name: Complete the Linear release
        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
        with:
          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
          command: complete
          version: ${{ inputs.tag }}
"#;

// --- fixture edits, one per shape of diff ----------------------------------

/// Delete one step by its `- name:`, through the line before the next step.
fn drop_step(body: &str, name: &str) -> String {
    let want = format!("      - name: {name}");
    let mut dropping = false;
    let mut out = Vec::new();
    for line in body.lines() {
        if line == want {
            dropping = true;
            continue;
        }
        if dropping && line.starts_with("      - ") {
            dropping = false;
        }
        if !dropping {
            out.push(line);
        }
    }
    out.join("\n") + "\n"
}

/// Replace every line containing `needle` with `with`.
fn replace_line(body: &str, needle: &str, with: &str) -> String {
    body.lines()
        .map(|line| if line.contains(needle) { with } else { line })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn drop_lines(body: &str, keep: impl Fn(&str) -> bool) -> String {
    body.lines()
        .filter(|line| keep(line))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Insert `lines` after the first line satisfying `at` (before it when `before`).
fn insert(body: &str, at: impl Fn(&str) -> bool, lines: &[&str], before: bool) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut done = false;
    for line in body.lines() {
        let hit = !done && at(line);
        if hit && before {
            out.extend_from_slice(lines);
        }
        out.push(line);
        if hit && !before {
            out.extend_from_slice(lines);
        }
        done |= hit;
    }
    out.join("\n") + "\n"
}

// --- the engine ---------------------------------------------------------------

fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "release wire other",
        "kind": "policy",
        "scope": "tree",
        "line_sources": [".github/workflows/*.yml"],
        "module": "policy/release-tracking.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn patterns() -> Vec<batten::pattern::NamedPattern> {
    let config = fs::read_to_string(common::at_root("batten.toml")).expect("the committed config");
    let parsed: toml::Value = toml::from_str(&config).expect("batten.toml parses");
    let rows = parsed["pattern"].as_array().expect("`[[pattern]]` rows");
    let found: Vec<_> = rows
        .iter()
        .filter(|row| PATTERNS.contains(&row["id"].as_str().unwrap_or_default()))
        .map(|row| batten::pattern::NamedPattern {
            id: row["id"].as_str().unwrap().to_owned(),
            regex: row["regex"].as_str().unwrap().to_owned(),
        })
        .collect();
    assert_eq!(
        found.len(),
        PATTERNS.len(),
        "every pattern the module reads is declared"
    );
    found
}

/// A tree carrying the two workflows (either may be absent) and the committed
/// module. A sibling workflow is always present so the glob always matches.
fn tree(name: &str, release: Option<&str>, backfill: Option<&str>) -> PathBuf {
    let root = common::scratch(&format!("release-tracking-{name}"));
    common::write(&root, ".github/workflows/ci.yml", "jobs:\n  ci:\n");
    if let Some(body) = release {
        common::write(&root, RELEASE, body);
    }
    if let Some(body) = backfill {
        common::write(&root, BACKFILL, body);
    }
    let source = common::at_root("policy/release-tracking.rego");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/release-tracking.rego")).expect("install committed module");
    root
}

/// Every pointer, rendered as `check` prints it minus the rule id.
fn pointers(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    let patterns = patterns();
    let scan = rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            records: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row");
    // A SKIPPED row reports no findings too, so an empty list proves nothing until
    // the row is shown to have evaluated.
    assert!(scan.not_evaluated.is_empty(), "{:?}", scan.not_evaluated);
    scan.findings
        .into_iter()
        .map(|finding| match finding.line {
            Some(line) => format!("{}:{line}", finding.path),
            None => finding.path,
        })
        .collect()
}

fn judge(name: &str, release: &str, backfill: &str) -> Vec<String> {
    pointers(&tree(name, Some(release), Some(backfill)))
}

/// Does any pointer name this workflow and this shape?
fn has(found: &[String], workflow: &str, token: &str) -> bool {
    let prefix = format!("{workflow}#{token}");
    found
        .iter()
        .any(|pointer| pointer == &prefix || pointer.starts_with(&format!("{prefix}:")))
}

fn any_token(found: &[String], token: &str) -> bool {
    has(found, RELEASE, token) || has(found, BACKFILL, token)
}

fn release_with(name: &str, release: &str) -> Vec<String> {
    judge(name, release, CLEAN_BACKFILL)
}

fn backfill_with(name: &str, backfill: &str) -> Vec<String> {
    judge(name, CLEAN_RELEASE, backfill)
}

// --- the ties to reality ------------------------------------------------------

#[test]
fn the_committed_workflows_pass() {
    let release = fs::read_to_string(common::at_root(RELEASE)).expect("the release workflow");
    let backfill = fs::read_to_string(common::at_root(BACKFILL)).expect("the backfill workflow");
    let found = judge("committed", &release, &backfill);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn the_clean_fixture_passes() {
    let found = judge("clean", CLEAN_RELEASE, CLEAN_BACKFILL);
    assert!(found.is_empty(), "{found:?}");
}

// --- shapes both profiles hold ------------------------------------------------

#[test]
fn a_dropped_sync_invocation_is_a_violation() {
    let found = release_with(
        "drop-sync",
        &drop_step(CLEAN_RELEASE, "Record the release in Linear"),
    );
    assert!(has(&found, RELEASE, "sync-missing"), "{found:?}");
    assert!(!any_token(&found, "complete-missing"), "{found:?}");
}

#[test]
fn a_dropped_complete_invocation_is_a_violation() {
    let found = release_with(
        "drop-complete",
        &drop_step(CLEAN_RELEASE, "Complete the Linear release"),
    );
    assert!(has(&found, RELEASE, "complete-missing"), "{found:?}");
    assert!(!any_token(&found, "sync-missing"), "{found:?}");
}

#[test]
fn a_dropped_invocation_on_the_backfill_path_is_a_violation() {
    let found = backfill_with(
        "bf-drop-sync",
        &drop_step(CLEAN_BACKFILL, "Record the release in Linear"),
    );
    assert!(
        found.contains(&format!("{BACKFILL}#sync-missing")),
        "{found:?}"
    );
    assert!(!has(&found, RELEASE, "sync-missing"), "{found:?}");
    let found = backfill_with(
        "bf-drop-complete",
        &drop_step(CLEAN_BACKFILL, "Complete the Linear release"),
    );
    assert!(
        found.contains(&format!("{BACKFILL}#complete-missing")),
        "{found:?}"
    );
}

#[test]
fn the_floating_ref_upstream_publishes_is_a_violation() {
    let floating = "        uses: linear/linear-release-action@v0";
    let found = release_with(
        "floating",
        &replace_line(CLEAN_RELEASE, "uses: linear/", floating),
    );
    assert!(has(&found, RELEASE, "unpinned"), "{found:?}");
    let found = backfill_with(
        "bf-floating",
        &replace_line(CLEAN_BACKFILL, "uses: linear/", floating),
    );
    assert!(has(&found, BACKFILL, "unpinned"), "{found:?}");
}

/// A SHA with no trailing version comment is invisible to the update bot.
/// `#MUTANT unpinned-sha-passes` reddens exactly here.
#[test]
fn a_sha_pin_without_its_version_comment_is_a_violation() {
    let bare =
        "        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac";
    let found = release_with(
        "bare-sha",
        &replace_line(CLEAN_RELEASE, "uses: linear/", bare),
    );
    assert!(has(&found, RELEASE, "unpinned"), "{found:?}");
}

#[test]
fn a_dropped_credential_precondition_is_a_violation() {
    let step = "Release tracking requires its credential";
    let found = release_with("drop-guard", &drop_step(CLEAN_RELEASE, step));
    assert!(has(&found, RELEASE, "precondition-missing"), "{found:?}");
    let found = backfill_with("bf-drop-guard", &drop_step(CLEAN_BACKFILL, step));
    assert!(
        found.contains(&format!("{BACKFILL}#precondition-missing")),
        "{found:?}"
    );
}

// --- the checkout, judged per job ---------------------------------------------

#[test]
fn an_absent_or_bounded_fetch_depth_is_a_violation() {
    let found = release_with(
        "no-depth",
        &drop_lines(CLEAN_RELEASE, |l| !l.contains("fetch-depth:")),
    );
    assert!(has(&found, RELEASE, "shallow-checkout"), "{found:?}");
    let found = release_with(
        "depth-one",
        &replace_line(CLEAN_RELEASE, "fetch-depth:", "          fetch-depth: 1"),
    );
    assert!(has(&found, RELEASE, "shallow-checkout"), "{found:?}");
    let found = backfill_with(
        "bf-no-depth",
        &drop_lines(CLEAN_BACKFILL, |l| !l.contains("fetch-depth:")),
    );
    assert!(has(&found, BACKFILL, "shallow-checkout"), "{found:?}");
}

/// The file-global probe passed this: depth on the cache-warm job, which never
/// reads a commit range, and none on the job that invokes the action. The
/// pointer names the INVOKING job's checkout, not the first one in the file.
#[test]
fn fetch_depth_0_on_a_job_that_does_not_invoke_the_action_is_not_enough() {
    let moved = insert(
        &drop_lines(CLEAN_RELEASE, |l| !l.contains("fetch-depth:")),
        |l| l.contains("persist-credentials: false"),
        &["          fetch-depth: 0"],
        true,
    );
    let found = release_with("depth-elsewhere", &moved);
    assert!(
        found.contains(&format!("{RELEASE}#shallow-checkout:16")),
        "{found:?}"
    );
}

// --- the version binding, per profile -----------------------------------------

#[test]
fn a_version_not_bound_to_the_resolved_tag_is_a_violation() {
    for (name, version) in [
        ("literal", "          version: v0.0.77"),
        (
            "undeclared-step",
            "          version: ${{ steps.nonesuch.outputs.tag }}",
        ),
    ] {
        let found = release_with(name, &replace_line(CLEAN_RELEASE, "version: ", version));
        assert!(has(&found, RELEASE, "version-unbound"), "{name}: {found:?}");
    }
}

#[test]
fn a_version_not_bound_to_a_declared_input_is_a_violation() {
    for (name, version) in [
        (
            "bf-step-output",
            "          version: ${{ steps.release-tag.outputs.tag }}",
        ),
        ("bf-literal", "          version: v0.0.78"),
        ("bf-undeclared", "          version: ${{ inputs.nonesuch }}"),
    ] {
        let found = backfill_with(name, &replace_line(CLEAN_BACKFILL, "version: ", version));
        assert!(
            has(&found, BACKFILL, "version-unbound"),
            "{name}: {found:?}"
        );
    }
}

/// A step's `with: tag:` is not an input declaration.
#[test]
fn an_input_declared_nowhere_but_passed_as_a_step_key_is_not_a_declaration() {
    let with_key = insert(
        &drop_lines(CLEAN_BACKFILL, |l| l != "      tag:"),
        |l| l.contains("fetch-depth: 0"),
        &["          tag: ${{ inputs.tag }}"],
        false,
    );
    let found = backfill_with("bf-step-key", &with_key);
    assert!(has(&found, BACKFILL, "version-unbound"), "{found:?}");
}

/// Indent is measured, not assumed.
#[test]
fn a_deeper_but_valid_input_indentation_still_declares_the_input() {
    let deeper = CLEAN_BACKFILL.replace(
        "  workflow_dispatch:\n    inputs:\n      tag:\n        description: Release tag to record in Linear\n        required: true\n        type: string\n",
        "    workflow_dispatch:\n      inputs:\n        tag:\n          required: true\n",
    );
    assert_ne!(deeper, CLEAN_BACKFILL, "the fixture edit applied");
    let found = backfill_with("bf-deeper", &deeper);
    assert!(found.is_empty(), "{found:?}");
}

// --- the release path's tag source and its refresh ----------------------------

#[test]
fn a_dropped_tag_resolution_step_is_one_finding() {
    let found = release_with(
        "drop-resolver",
        &drop_step(CLEAN_RELEASE, "Resolve the release tag this push shipped"),
    );
    assert!(has(&found, RELEASE, "tag-source-missing"), "{found:?}");
    assert!(
        !any_token(&found, "tag-refresh-missing"),
        "one cause, one finding: {found:?}"
    );
}

#[test]
fn a_dropped_tag_refresh_is_a_violation() {
    let found = release_with(
        "drop-refresh",
        &drop_step(CLEAN_RELEASE, "Refresh tags after release-plz pushed one"),
    );
    assert!(has(&found, RELEASE, "tag-refresh-missing"), "{found:?}");
}

/// THE DEFECT THE PROGRAM EXISTED FOR: a refresh after the resolver updates a ref
/// set nothing reads again. `#MUTANT refresh-order-ignored` reddens exactly here.
#[test]
fn a_tag_refresh_after_the_resolver_is_a_violation() {
    let late = insert(
        &drop_step(CLEAN_RELEASE, "Refresh tags after release-plz pushed one"),
        |l| l.contains("git tag --points-at HEAD"),
        &[
            "      - name: Refresh tags too late",
            "        run: git fetch --force --tags origin",
        ],
        false,
    );
    let found = release_with("late-refresh", &late);
    assert!(has(&found, RELEASE, "tag-refresh-missing"), "{found:?}");
}

#[test]
fn a_fetch_without_tags_is_not_a_refresh() {
    let found = release_with(
        "no-tags",
        &replace_line(
            CLEAN_RELEASE,
            "run: git fetch --force",
            "        run: git fetch origin main",
        ),
    );
    assert!(has(&found, RELEASE, "tag-refresh-missing"), "{found:?}");
}

/// A comment quoting the resolver above the refresh must not become the resolver.
#[test]
fn a_comment_quoting_the_resolver_is_not_the_resolver() {
    let quoted = insert(
        CLEAN_RELEASE,
        |l| l == "      - run: mise run release",
        &["      # `git tag --points-at HEAD` is what the resolver below runs."],
        true,
    );
    let found = release_with("quoted-resolver", &quoted);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_comment_quoting_the_refresh_does_not_satisfy_the_refresh_rule() {
    let quoted = insert(
        &drop_step(CLEAN_RELEASE, "Refresh tags after release-plz pushed one"),
        |l| l == "      - run: mise run release",
        &["      # run: git fetch --force --tags origin"],
        true,
    );
    let found = release_with("quoted-refresh", &quoted);
    assert!(has(&found, RELEASE, "tag-refresh-missing"), "{found:?}");
}

// --- the dispatch profile's own shapes ----------------------------------------

#[test]
fn a_dropped_tag_exists_probe_on_the_backfill_path_is_a_violation() {
    let found = backfill_with(
        "bf-drop-probe",
        &drop_step(CLEAN_BACKFILL, "The tag must exist in this checkout"),
    );
    assert!(
        found.contains(&format!("{BACKFILL}#tag-unverified")),
        "{found:?}"
    );
}

/// The release path is asked for none of the dispatch profile's three shapes.
#[test]
fn the_release_path_is_not_asked_for_the_dispatch_shapes() {
    let found = judge("release-only", CLEAN_RELEASE, CLEAN_BACKFILL);
    for token in ["tag-unverified", "ref-unbound", "range-unbased"] {
        assert!(!has(&found, RELEASE, token), "{token}: {found:?}");
    }
}

#[test]
fn a_backfill_checkout_not_on_the_tag_is_a_violation() {
    for (name, body) in [
        (
            "bf-no-ref",
            drop_lines(CLEAN_BACKFILL, |l| !l.trim_start().starts_with("ref: ")),
        ),
        (
            "bf-branch",
            replace_line(CLEAN_BACKFILL, "          ref: ", "          ref: main"),
        ),
        (
            "bf-ref-undeclared",
            replace_line(
                CLEAN_BACKFILL,
                "          ref: ",
                "          ref: ${{ inputs.nonesuch }}",
            ),
        ),
    ] {
        let found = backfill_with(name, &body);
        assert!(has(&found, BACKFILL, "ref-unbound"), "{name}: {found:?}");
    }
}

/// Depth is not the same assertion: losing only `ref:` is `ref-unbound` alone.
#[test]
fn fetch_depth_0_does_not_stand_in_for_a_bound_ref() {
    let found = backfill_with(
        "bf-depth-not-ref",
        &drop_lines(CLEAN_BACKFILL, |l| !l.trim_start().starts_with("ref: ")),
    );
    assert!(!has(&found, BACKFILL, "shallow-checkout"), "{found:?}");
    assert!(
        found.contains(&format!("{BACKFILL}#ref-unbound:13")),
        "{found:?}"
    );
}

#[test]
fn a_backfill_sync_with_no_real_base_is_a_violation() {
    for (name, body) in [
        (
            "bf-no-base",
            drop_lines(CLEAN_BACKFILL, |l| !l.contains("base_ref: ")),
        ),
        (
            "bf-literal-base",
            replace_line(CLEAN_BACKFILL, "base_ref: ", "          base_ref: v0.0.77"),
        ),
        (
            "bf-base-undeclared",
            replace_line(
                CLEAN_BACKFILL,
                "base_ref: ",
                "          base_ref: ${{ steps.nonesuch.outputs.ref }}",
            ),
        ),
    ] {
        let found = backfill_with(name, &body);
        assert!(
            found.contains(&format!("{BACKFILL}#range-unbased")),
            "{name}: {found:?}"
        );
        assert!(
            !has(&found, BACKFILL, "ref-unbound"),
            "a bound ref is not a base: {found:?}"
        );
    }
}

// --- could-not-look -----------------------------------------------------------

/// EITHER subject absent is `release wire unread`, never a pass earned on the
/// other; a directory where the file should be reads the same.
#[test]
fn an_absent_workflow_is_unread_never_clean() {
    let found = pointers(&tree("no-release", None, Some(CLEAN_BACKFILL)));
    assert_eq!(found, vec![RELEASE.to_owned()]);
    let found = pointers(&tree("no-backfill", Some(CLEAN_RELEASE), None));
    assert_eq!(found, vec![BACKFILL.to_owned()]);
    let root = tree("dir-release", None, Some(CLEAN_BACKFILL));
    fs::create_dir_all(root.join(RELEASE)).expect("a directory where the workflow should be");
    assert_eq!(pointers(&root), vec![RELEASE.to_owned()]);
}

// --- the output contract ------------------------------------------------------

/// Rule 4: the workflows carry a secret reference on every invocation.
#[test]
fn findings_are_pointers_never_workflow_text() {
    let found = release_with(
        "pointers",
        &drop_step(CLEAN_RELEASE, "Record the release in Linear"),
    );
    assert_eq!(found, vec![format!("{RELEASE}#sync-missing")]);
    for pointer in &found {
        for secret in ["access_key", "LINEAR_ACCESS_KEY", "secrets."] {
            assert!(!pointer.contains(secret), "{pointer}");
        }
    }
}

#[test]
fn output_is_sorted_stable_and_one_list_across_subjects() {
    let release = drop_step(
        &drop_step(CLEAN_RELEASE, "Record the release in Linear"),
        "Complete the Linear release",
    );
    let first = release_with("stable-a", &release);
    let second = release_with("stable-b", &release);
    assert_eq!(first, second);
    assert_eq!(
        first,
        vec![
            format!("{RELEASE}#complete-missing"),
            format!("{RELEASE}#sync-missing"),
        ]
    );
    let found = judge(
        "both-subjects",
        &drop_step(CLEAN_RELEASE, "Complete the Linear release"),
        &drop_step(CLEAN_BACKFILL, "Complete the Linear release"),
    );
    assert_eq!(
        found,
        vec![
            format!("{BACKFILL}#complete-missing"),
            format!("{RELEASE}#complete-missing"),
        ]
    );
}
