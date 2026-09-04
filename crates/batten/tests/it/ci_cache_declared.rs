//! `policy/ci-cache-declared.rego` decides over the compiled engine
//! (CLOUD-1410, CLOUD-1408).
//!
//! # Why this tier
//!
//! The module's own `test_` cases hand themselves a `documents` object, so they
//! are green over a shape the engine may never build — the hazard
//! `.claude/rules/policy-modules.md` names, and the reason both of its measured
//! instances were found by adding this tier rather than by reading.
//!
//! This row reads deeper than any of its neighbours and reads TWO documents of
//! different formats to reach one verdict. Predicate 2's whole question is
//! whether a workflow job's `mise run <task>` resolves, through `mise.toml`'s
//! own `depends`, to something that forks `cargo` — so it needs
//! `jobs.<name>.steps[].run` out of parsed YAML and `tasks.<name>.depends` out
//! of parsed TOML in the same evaluation. Whether the boundary builds both, at
//! that depth, from one rule's `sources` glob is exactly the class a `with
//! input as` case cannot answer, because it fabricates the very structures in
//! question.
//!
//! The `save-if` reading is the second thing only this tier can settle. YAML
//! spells `false` as a boolean and `"false"` as a string, and which one arrives
//! is the boundary's decision rather than the author's — a module compared
//! against only one of them would read a read-only step as a writer, or worse,
//! read every step in the tree as read-only.
//!
//! # The case that carries the most
//!
//! `this_repository_is_clean_today` runs the row over this checkout. Every
//! fixture below is a shape somebody wrote to fail; that one is the shape that
//! has to keep passing, and it is what says the twelve live `shared-key` values,
//! the `commit-lint` cache step and the four read-only consumers of the `ci-`
//! family are still in the arrangement this row exists to hold — the live
//! property, not a fixture of it.
//!
//! # The measurements behind the row
//!
//! `commit-lint`, job 100806281473: `commit-attribution` 341.89s and
//! `commit-check` 341.98s, both blocked on one cold debug build, against a lint
//! body of 758.6ms — 5m42s of a 5m43s step. The `ci` job's own cache API
//! reading, 2026-08-21: six live copies of one key, every one on a
//! `refs/pull/N/merge` ref and none on `refs/heads/main`, with a miss run
//! spending 1021s in `mise run ci` against 741s for the one hit.

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
        "id": "ci-cache-declared",
        "kind": "policy",
        "scope": "tree",
        "sources": [".github/workflows/*.yml", "mise.toml"],
        "line_sources": [".github/workflows/*.yml"],
        "module": "policy/ci-cache-declared.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares")
}

/// A scratch tree carrying a manifest, some workflows and the committed module.
fn tree(name: &str, manifest: &str, workflows: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(&format!("ci-cache-declared-{name}"));
    common::write(&root, "mise.toml", manifest);
    for (file, body) in workflows {
        common::write(&root, &format!(".github/workflows/{file}"), body);
    }
    install_module(&root);
    root
}

/// The COMMITTED module, copied in rather than restated: an inline copy would
/// drift from the shipped one and pass while the real gate was broken.
fn install_module(root: &Path) {
    let source = common::at_root("policy/ci-cache-declared.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/ci-cache-declared.rego")).expect("install committed module");
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
    // THE ONE `[[pattern]]` ROW THIS MODULE READS, declared here as the config
    // declares it. An inline regex is refused at LOAD, so the row has to exist
    // for the bundle to compile at all — the registry doing its job rather than
    // a fixture detail. Supplied rather than left empty because this is an
    // in-repo module and a consumer really does declare it: the preset exemption
    // `.claude/rules/policy-modules.md` records does not apply, and an empty
    // vocabulary would make predicate 2 read undefined and abstain, so every
    // deny case below would pass for the wrong reason.
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

// ---------------------------------------------------------------------------
// The fixtures, assembled from the real files' own markers rather than copied
// wholesale: a fixture pasting the shipped 900-line `ci.yml` would be
// re-asserting the file under test, and every edit to it would be a fixture edit.
// ---------------------------------------------------------------------------

/// `depends` reaching cargo at one hop, which is the depth `commit-lint` and
/// `ci` actually sit at in this repository.
const MANIFEST: &str = r#"
[tasks.build]
run = "cargo run --quiet -p batten -- enforce"

[tasks.lint]
depends = ["build"]

[tasks.inert]
run = "echo nothing"
"#;

/// The trunk-side writer, which is what makes a family warm at all.
const WARM: &str = r"
name: warm
on:
  push:
    branches: [main]
jobs:
  cache-warm-linux:
    name: cache-warm-linux
    runs-on: ubuntu-24.04-arm
    steps:
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6
        with:
          shared-key: ci-
";

/// A pull-request consumer in the arrangement this row exists to hold: a
/// readable key, a declared cache, read-only against a warmed family.
const READER: &str = r"
name: pr
on:
  pull_request:
    types: [opened]
jobs:
  reader:
    name: reader
    runs-on: ubuntu-24.04-arm
    steps:
      - run: mise run lint
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6
        with:
          shared-key: ci-
          save-if: false
";

// ---------------------------------------------------------------------------
// The tree this row actually defends.
// ---------------------------------------------------------------------------

#[test]
fn this_repository_is_clean_today() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    // The vocabulary comes from a directory holding only this module, for the
    // reason `findings` states; the scratch name is this case's own, because
    // nextest runs each case in its own process and a shared name is a wipe
    // under another process's read.
    let only = common::scratch("ci-cache-declared-vocabulary-real-tree");
    install_module(&only);
    let found = findings_declared_by(&root, &only);
    assert!(
        found.is_empty(),
        "the committed workflows should satisfy their own row: {found:?}"
    );
}

#[test]
fn the_fixture_shape_is_clean_too() {
    // Without this, every refusal below could be produced by a fixture the row
    // simply cannot read — a module that fires on everything looks identical to
    // one that discriminates, until something is supposed to pass.
    let root = tree("clean", MANIFEST, &[("warm.yml", WARM), ("pr.yml", READER)]);
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "the paired fixture should be clean: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 1. a key carrying a content hash cannot be read.
// ---------------------------------------------------------------------------

#[test]
fn a_shared_key_carrying_a_content_hash_is_refused() {
    // THE DEFECT THAT SHIPPED TWELVE TIMES. `shared-key` lands at
    // `config.ts:77`, inside the prefix assigned to `restoreKey` at `:133`, so
    // this does not merely miss the exact key — it moves the fallback and
    // nothing in the store matches.
    let hashed = READER.replace(
        "shared-key: ci-",
        "shared-key: ci-${{ hashFiles('Cargo.toml') }}",
    );
    let root = tree(
        "hashed",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &hashed)],
    );
    let found = findings(&root);
    assert!(
        found
            .iter()
            .any(|(path, _)| path == ".github/workflows/pr.yml"),
        "the workflow should be named as the place to fix it: {found:?}"
    );
}

#[test]
fn the_offending_key_is_pointed_at_by_line() {
    // RULE 4's SHAPE, ASSERTED OVER THE ENGINE. The finding carries a
    // `{path, line}` and never the key's VALUE, and the line has to come from
    // `input.tree.lines` — which only this tier can say the boundary populates
    // for a `line_sources` glob rather than a literal path.
    let hashed = READER.replace(
        "shared-key: ci-",
        "shared-key: ci-${{ hashFiles('Cargo.toml') }}",
    );
    let root = tree(
        "pointed",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &hashed)],
    );
    let found = findings(&root);
    assert!(
        found.iter().any(|(_, line)| line.is_some()),
        "a placed key should carry its line: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. a pull-request job reaching cargo declares a cache.
// ---------------------------------------------------------------------------

#[test]
fn a_cargo_job_with_no_cache_step_is_refused() {
    // `commit-lint.yml`'s shape before CLOUD-1408: `mise run <task>` whose
    // transitive `depends` fork cargo, and no `Swatinem/rust-cache` anywhere in
    // the workflow.
    let uncached = READER
        .split_once("      - uses: Swatinem/rust-cache")
        .expect("the fixture carries a cache step")
        .0;
    let root = tree(
        "uncached",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", uncached)],
    );
    let found = findings(&root);
    assert!(
        !found.is_empty(),
        "a pull-request job forking cargo with no cache should be refused"
    );
}

#[test]
fn the_engine_resolves_cargo_through_the_manifests_depends() {
    // THE CASE THIS TIER EXISTS FOR. The fixture's job runs `mise run lint`,
    // whose own body forks nothing — the cargo call is one `depends` hop away,
    // in a DIFFERENT document and a different format. If the boundary does not
    // build `mise.toml`'s task table alongside the workflow YAML, this reads as
    // "reaches no cargo" and the predicate abstains at exit 0, which is
    // byte-identical to a clean tree on the decision surface.
    let uncached = READER
        .split_once("      - uses: Swatinem/rust-cache")
        .expect("the fixture carries a cache step")
        .0;
    let root = tree(
        "indirect",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", uncached)],
    );
    assert!(
        !findings(&root).is_empty(),
        "a cargo reach through `depends` must be seen, or the predicate is dead"
    );
}

#[test]
fn a_job_reaching_no_cargo_needs_no_cache() {
    // ANTI-VACUITY. A job that forks no cargo has nothing to answer for, and
    // refusing it would make this a prohibition on uncached jobs rather than a
    // rule about builds.
    let inert = READER
        .split_once("      - uses: Swatinem/rust-cache")
        .expect("the fixture carries a cache step")
        .0
        .replace("mise run lint", "mise run inert");
    let root = tree("inert", MANIFEST, &[("warm.yml", WARM), ("pr.yml", &inert)]);
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "a job that never forks cargo should be clean: {found:?}"
    );
}

#[test]
fn a_push_triggered_job_is_not_asked_for_a_cache() {
    // The predicate is stated over `pull_request` deliberately: a trunk-side job
    // reads an entry nobody has written yet by definition, and the warm job is
    // the one that pays for the first build.
    let warm_uncached = WARM
        .split_once("      - uses: Swatinem/rust-cache")
        .expect("the fixture carries a cache step")
        .0
        .to_owned()
        + "      - run: mise run lint\n";
    let root = tree(
        "push-uncached",
        MANIFEST,
        &[("warm.yml", &warm_uncached), ("pr.yml", READER)],
    );
    // `pr.yml` still reads `ci-`, which nothing warms in this fixture, so the
    // only thing that could fire here is predicate 2 over the push job.
    let found = findings(&root);
    assert!(
        found
            .iter()
            .all(|(path, _)| path != ".github/workflows/warm.yml"),
        "a push-triggered job is not this predicate's business: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. a pull-request reader of a warmed family does not write to it.
// ---------------------------------------------------------------------------

#[test]
fn a_pull_request_writer_of_a_warmed_family_is_refused() {
    // A cache entry is immutable once written, so on a fresh key the first job
    // to finish becomes the entry every later reader inherits — and a
    // pull-request write is unreadable by every other pull request regardless.
    let writes = READER.replace("          save-if: false\n", "");
    let root = tree(
        "writer",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &writes)],
    );
    let found = findings(&root);
    assert!(
        !found.is_empty(),
        "a pull-request writer of a warmed family should be refused"
    );
}

#[test]
fn an_unwarmed_family_may_still_be_written() {
    // ANTI-VACUITY, AND IT IS WHAT DISCRIMINATES THIS PREDICATE FROM A BLANKET
    // REFUSAL OF PR-SIDE WRITES. `cross-`, `semver-` and `${{ matrix.target }}`
    // have no trunk writer, so read-only would leave them with nothing at all —
    // which is why this change deliberately left them writing. Without this case
    // the clause would pass for the wrong reason.
    let writes = READER
        .replace("          save-if: false\n", "")
        .replace("shared-key: ci-", "shared-key: cross-");
    let root = tree(
        "unwarmed",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &writes)],
    );
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "a family nothing warms is not this predicate's business: {found:?}"
    );
}

#[test]
fn the_same_key_on_another_architecture_is_not_the_same_family() {
    // THE PAIR THE PREDICATE USED TO CONFUSE, asserted over the engine because
    // the discriminator is a `runs-on` label the boundary has to project out of
    // the parsed job — the module's own case supplies that mapping itself.
    //
    // rust-cache composes `runnerOS-runnerArch` into the key at `config.ts:93`,
    // so `ci-` written by an arm64 job and `ci-` written by an x64 one are
    // different entries: no contention, no overwrite, no reader handed the
    // other's tree. Comparing the `shared-key` string alone refused exactly this
    // shape, measured against this repository's own tree the first time one job
    // of a family stayed on x64 while the rest moved.
    // `WARM` writes `ci-` on `ubuntu-24.04-arm`; this reader writes the same key
    // on x64, which is a different composed key.
    let writes = READER
        .replace("          save-if: false\n", "")
        .replace("runs-on: ubuntu-24.04-arm", "runs-on: ubuntu-latest");
    let root = tree(
        "cross-arch",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &writes)],
    );
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "the same key on another architecture is another entry: {found:?}"
    );
}

#[test]
fn the_same_key_on_the_same_architecture_is_still_refused() {
    // The other direction, so the widened key cannot pass by never matching.
    // Both sides are `ubuntu-24.04-arm`, which is one family.
    let writes = READER.replace("          save-if: false\n", "");
    let root = tree(
        "same-arch",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &writes)],
    );
    assert!(
        !findings(&root).is_empty(),
        "same key and same architecture is one family, and a PR-side write of it is refused"
    );
}

#[test]
fn the_engine_reads_a_quoted_save_if_as_read_only() {
    // YAML SPELLS `false` TWO WAYS AND THE BOUNDARY DECIDES WHICH ARRIVES. A
    // bare `false` is a boolean and a quoted one is a string; a module comparing
    // against only one would refuse a step that is in fact read-only. Only this
    // tier can settle which the engine hands over, because a `with input as`
    // case picks the type itself.
    let quoted = READER.replace("save-if: false", "save-if: 'false'");
    let root = tree(
        "quoted",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", &quoted)],
    );
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "a quoted `save-if` is still read-only: {found:?}"
    );
}

// ---------------------------------------------------------------------------
// Could not look, and it must not be spelled like a clean tree.
// ---------------------------------------------------------------------------

#[test]
fn an_unparsed_workflow_is_could_not_look() {
    // A DECLARED SOURCE THAT WILL NOT PARSE IS NOT AN ABSENT ONE. Asserted over
    // the engine rather than with `with input as` because that fabricates
    // `input.tree.missing` — the exact channel CLOUD-1049 found dead while every
    // module's own suite was green over it.
    let root = tree(
        "unparsed",
        MANIFEST,
        &[("warm.yml", WARM), ("pr.yml", READER)],
    );
    common::write(
        &root,
        ".github/workflows/broken.yml",
        "jobs: [this is not a mapping\n  - and this will not parse\n",
    );
    let found = findings(&root);
    assert!(
        !found.is_empty(),
        "an unparsed declared source is a finding, never a pass"
    );
}

#[test]
fn a_tree_with_no_workflow_is_not_this_rows_business() {
    let root = common::scratch("ci-cache-declared-absent");
    common::write(&root, "mise.toml", MANIFEST);
    install_module(&root);
    let found = findings(&root);
    assert!(
        found.is_empty(),
        "absent is not-applicable, never a finding: {found:?}"
    );
}
