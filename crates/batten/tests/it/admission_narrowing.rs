//! `policy::publishers_of` — the narrowing a mint's anchor selects with
//! (CLOUD-1571).
//!
//! # What went wrong, because it decides what these cases have to pin
//!
//! `admission_anchor` re-runs the rule a refusal named so it can recover that
//! finding's fingerprint and bind the admission to it. `--rule` carries a
//! PREDICATE id — `issue file other` publishes `filed-over-own-diff` — so filtering
//! `declared.id == rule` selected nothing, the scan produced no finding, and the
//! mint silently took the `head()` fallback: an admission answered, spent, and
//! queried by nothing (CLOUD-1087, CLOUD-1125).
//!
//! Widening an empty exact match to every `policy` row fixed that and cost
//! **2m22.121s per mint**, measured on `main` at `6eb08e14` against **0.123s**
//! for a full adjudication of the same tree. The bound "widens to those rows and
//! no further" is a statement about which KIND of row, and the regression is that
//! this is not the same as which ROW: `protected-mutation` is an engine-side rule
//! name with zero hits under `policy/`, so **no bundle could ever publish it**,
//! and 58 modules were evaluated over the whole tree to produce a finding set
//! discarded one line later. One test case paying that was 24% of the entire
//! suite.
//!
//! # Why the pure function is the subject
//!
//! The narrowing is the decision; the early return that skips the scan is one
//! line downstream of it. `admission_anchor` reads stdin and is reachable only
//! through `override request`, so the decision is extracted where it can be
//! driven directly rather than asserted through a verb that also parses answers,
//! resolves an epoch and reads a git identity.
//!
//! **The last case is the one that matters, and it is not a fixture.** It asks
//! the REAL committed bundles the real question, so a module later publishing
//! `protected-mutation` — which would silently restore the full scan — reddens
//! here. A fixture-only suite would pass over exactly that.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::policy::{self, Bundle};
use batten::rules::Rule;

/// A module publishing one predicate whose id is not its enabling row's — the
/// shape that defeated the `declared.id == rule` filter in the first place.
const PUBLISHES: &str = r#"
package batten

import rego.v1

rules contains "PREDICATE"

violation contains {"rule": "PREDICATE", "verdict": "stray key probe"} if {
	input.tree.documents["config.toml"].stray
}
"#;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-narrow-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// One bundle folder per row, each publishing a predicate the row is not named
/// after. Distinct packages and distinct predicate ids, because `load` refuses a
/// shared source and a shared id alike.
fn write_bundle(root: &Path, row_id: &str, predicate: &str) {
    let dir = root.join(format!("policy-{row_id}"));
    fs::create_dir_all(&dir).expect("bundle folder");
    let module = PUBLISHES
        .replace("package batten", &format!("package batten.b{row_id}"))
        .replace("PREDICATE", predicate);
    fs::write(dir.join("gate.rego"), module).expect("module");
}

fn row(id: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "tree",
        "bundle": format!("policy-{id}/"),
        "documents": ["config.toml"],
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row the loader accepts")
}

/// The vocabulary derived from what the fixture's modules actually raise —
/// registry equality runs both ways, so a table naming an unraised token is dead
/// vocabulary and `load` refuses it.
fn load_fixture(root: &Path, rows: &[Rule]) -> Vec<Bundle> {
    let verdicts = common::verdicts_in(root);
    policy::load(
        root,
        rows,
        policy::Vocabulary {
            // NO PATTERN ROWS, and that is a statement rather than an omission:
            // these modules resolve none, so supplying any would be input no
            // consumer supplies.
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        policy::ModuleChecks::RunOverSelection,
        None,
    )
    .expect("the fixture bundles load")
}

/// THE REGRESSION, in one assertion. A predicate no bundle publishes selects no
/// bundle, so the caller has nothing to scan for and skips the scan entirely.
///
/// Fails by: restoring the widen-to-every-policy-row filter, which selects both
/// rows here and, on the real tree, all 58.
#[test]
fn a_predicate_no_bundle_publishes_selects_nothing() {
    let root = scratch("unpublished");
    write_bundle(&root, "alpha", "alpha-violated");
    write_bundle(&root, "beta", "beta-violated");
    let bundles = load_fixture(&root, &[row("alpha"), row("beta")]);

    assert!(
        policy::publishers_of(&bundles, "protected-mutation").is_empty(),
        "an engine-side rule name is published by nothing, so nothing is selected \
         and no module is evaluated (CLOUD-1571)"
    );
}

/// THE PROPERTY CLOUD-1087 AND CLOUD-1125 BOUGHT, which this must not spend. A
/// predicate a bundle DOES publish still selects that bundle — so the mint still
/// reaches its finding and still anchors on it rather than falling back.
///
/// Fails by: narrowing back to `declared.id == rule`, which selects nothing here
/// because no row is named after the predicate it publishes.
#[test]
fn a_published_predicate_selects_its_own_bundle_and_only_that_one() {
    let root = scratch("published");
    write_bundle(&root, "alpha", "alpha-violated");
    write_bundle(&root, "beta", "beta-violated");
    let bundles = load_fixture(&root, &[row("alpha"), row("beta")]);

    let selected = policy::publishers_of(&bundles, "beta-violated");
    assert_eq!(
        selected.into_iter().collect::<Vec<_>>(),
        vec!["beta"],
        "exactly the publishing bundle, so the scan is one module rather than every one"
    );
}

/// ANTI-VACUITY ON THE FIXTURE ITSELF. Both cases above would pass over a bundle
/// set that failed to publish anything at all — an empty `declared` set makes
/// every query empty, and the first case would then be green for the wrong
/// reason.
#[test]
fn the_fixture_bundles_actually_publish_their_predicates() {
    let root = scratch("anti-vacuity");
    write_bundle(&root, "alpha", "alpha-violated");
    let bundles = load_fixture(&root, &[row("alpha")]);

    assert_eq!(bundles.len(), 1, "one row, one bundle");
    assert!(
        bundles[0].declared().contains("alpha-violated"),
        "the module publishes the predicate the cases above query for; without \
         this, an empty declared set would make every query vacuously empty"
    );
    assert!(
        !policy::publishers_of(&bundles, "alpha-violated").is_empty(),
        "and the query reaches it"
    );
}

/// THE FIDELITY CASE, over the REAL committed bundles rather than a fixture.
///
/// `protected-mutation` is the measured instance: it is the rule every protected
/// path write mints against, it is engine-side (`decision.rs`, `refusal.rs`,
/// `hook.rs`, `rules.rs`, `admission.rs`), and it has **zero hits under
/// `policy/`**. If some later module publishes it, the scan silently goes wide
/// again and the 2m22s comes back with nothing to announce it. That is what this
/// case refuses, and no fixture can.
///
/// The committed `filed-over-own-diff` is asserted beside it in the same
/// function, because a repository whose bundles failed to load would give an
/// empty set for the first assertion and pass it for exactly the wrong reason.
#[test]
fn the_committed_bundles_publish_no_engine_side_rule_name() {
    let root = common::at_root("batten.toml");
    let root = root.parent().expect("the committed config has a parent");
    let config = batten::resolve::resolve(root, &batten::resolve::Overrides::default())
        .expect("the committed config resolves");
    let policy_rows: Vec<_> = config
        .rules
        .iter()
        .filter(|declared| declared.kind == batten::rules::RuleKind::Policy)
        .cloned()
        .collect();
    let bundles = policy::load(
        root,
        &policy_rows,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        policy::ModuleChecks::RunOverSelection,
        None,
    )
    .expect("the committed bundles load");

    // ANTI-VACUITY FIRST, so the refusal below cannot pass over an empty set.
    assert!(
        policy::publishers_of(&bundles, "filed-over-own-diff")
            .into_iter()
            .eq(["issue file other"]),
        "the committed tree still publishes a predicate under a differently-named \
         row — the shape the whole narrowing exists to handle"
    );

    assert!(
        policy::publishers_of(&bundles, "protected-mutation").is_empty(),
        "`protected-mutation` is engine-side and no module may publish it; if one \
         does, every mint against it goes back to evaluating {} bundles over the \
         whole tree (CLOUD-1571)",
        bundles.len()
    );
}
