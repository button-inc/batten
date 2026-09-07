//! `policy/landing-roster-guarded.rego` over the COMPILED engine (CLOUD-1570).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads: `with input as` fabricates
//! the very shape the engine may be unable to produce, so a module reading a key
//! nothing fills passes its own suite green and enforces nothing.
//!
//! This module reads two things the engine has to resolve rather than a harness
//! hand over — `input.tree.lines` for one declared path, and
//! `input.tree.missing` when that path cannot be read. The second is the one
//! that has gone dead before: `.claude/rules/policy-modules.md` records that
//! `missing` was silently unfillable for its whole early life, that two
//! measurements reported it as an unfilled channel, and that the only thing
//! which distinguishes a live channel from a dead one is an arm that does not
//! itself read the channel.
//!
//! # The case that matters most drives the REAL committed workflow
//!
//! `the_committed_landing_workflow_is_guarded` scans this repository's own tree.
//! A fixture-only suite would pass over a `fast-forward.yml` that had lost the
//! guard, which is the exact regression this module exists to refuse.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares.
const UNGUARDED: &str = "landing-roster-unguarded";

/// The one path the module is anchored on.
const LANDING: &str = ".github/workflows/fast-forward.yml";

/// A landing workflow that consults the roster, in the spelling the real one
/// uses.
const GUARDED: &str = r#"
jobs:
  fast-forward:
    steps:
      - name: refuse a head whose required checks have not all answered
        run: |
          SHA="$head_sha" mise run checks-green
"#;

/// And one that does not: it goes straight to the push.
const UNGUARDED_BODY: &str = r#"
jobs:
  fast-forward:
    steps:
      - uses: sequoia-pgp/fast-forward@ea7628b # v1.0.0
        with:
          merge: true
"#;

/// A fixture tree carrying a landing workflow with `body`, or none at all when
/// `body` is `None` — which is what puts the declared path in `missing` rather
/// than in `lines`.
fn repo(name: &str, body: Option<&str>) -> PathBuf {
    let root = common::scratch(name);
    if let Some(body) = body {
        let full = root.join(LANDING);
        fs::create_dir_all(full.parent().expect("the landing path has a parent"))
            .expect("scratch workflow dir");
        fs::write(full, body).expect("write the landing workflow");
    }
    install_module(&root);
    root
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/landing-roster-guarded.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/landing-roster-guarded.rego"))
        .expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "landing-roster-guarded",
        "kind": "policy",
        "scope": "tree",
        "line_sources": [".github/workflows/fast-forward.yml"],
        "module": "policy/landing-roster-guarded.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    // NO PATTERN ROWS, and that is a statement rather than an omission: this
    // module resolves none, so supplying any would be input no consumer supplies
    // and the cases would pass for the wrong reason.
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn rules_fired(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

/// THE FIDELITY CASE. This repository's own tree, scanned by the engine, against
/// the workflow that actually lands every PR here. `#MUTANT guard-unread`
/// reddens exactly here, and a fixture-only suite could not see the regression
/// this refuses.
#[test]
fn the_committed_landing_workflow_is_guarded() {
    let root = common::at_root("batten.toml");
    let root = root.parent().expect("the committed config has a parent");
    assert!(
        !rules_fired(root).contains(&UNGUARDED.to_owned()),
        "the committed {LANDING} must consult the roster; \
         if this fails the landing path has lost its guard (CLOUD-1570)"
    );
}

/// THE REFUSAL. Without this the case above is satisfied by a module that
/// refuses nothing.
#[test]
fn a_landing_workflow_that_does_not_consult_the_roster_is_refused() {
    let root = repo("landing-roster-unguarded", Some(UNGUARDED_BODY));
    assert_eq!(rules_fired(&root), vec![UNGUARDED.to_owned()]);
}

/// AND THE PASS SIDE OVER A FIXTURE, so the refusal above is shown to turn on
/// the guard's presence rather than on the fixture being a fixture.
#[test]
fn a_fixture_landing_workflow_that_consults_the_roster_is_clean() {
    let root = repo("landing-roster-guarded", Some(GUARDED));
    assert!(rules_fired(&root).is_empty());
}

/// THE COULD-NOT-LOOK CHANNEL, DRIVEN BY THE ENGINE. A declared `line_sources`
/// path that is not there must reach `input.tree.missing` and be reported —
/// never read as a clean tree. Asserted here rather than with `with input as`
/// for the reason `.claude/rules/policy-modules.md` gives: fabricating the
/// shape is exactly how a dead `missing` channel survived two measurements.
#[test]
fn an_absent_landing_workflow_is_reported_rather_than_read_as_clean() {
    let root = repo("landing-roster-absent", None);
    assert_eq!(
        rules_fired(&root),
        vec![UNGUARDED.to_owned()],
        "an absent declared source is could-not-look, and could-not-look is a finding"
    );
}
