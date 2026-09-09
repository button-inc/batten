//! `policy/landing-roster-guarded.rego` over the COMPILED engine (CLOUD-1570).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads: `with input as` fabricates
//! the very shape the engine may be unable to produce, so a module reading a key
//! nothing fills passes its own suite green and enforces nothing.
//!
//! What the engine has to resolve here is `input.tree.lines` for one declared
//! path — and, decisively, what it does NOT resolve when that path is absent.
//! The first draft assumed a missing declared source lands in
//! `input.tree.missing`; `an_absent_landing_workflow_is_refused` measured that it
//! does not, because `line_sources` is a glob list and a glob matching nothing is
//! no source rather than an unreadable one. That arm was dead, and a branch
//! deleting the landing workflow passed the gate.
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
const UNGUARDED: &str = "check read never";

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
const UNGUARDED_BODY: &str = r"
jobs:
  fast-forward:
    steps:
      - uses: sequoia-pgp/fast-forward@ea7628b # v1.0.0
        with:
          merge: true
";

/// A fixture tree carrying a landing workflow with `body`, or none at all when
/// `body` is `None` — which is what makes the declared glob match nothing, so
/// the path reaches neither `lines` nor `missing`.
fn repo(name: &str, body: Option<&str>) -> PathBuf {
    let root = common::scratch(name);
    let dir = root.join(".github/workflows");
    fs::create_dir_all(&dir).expect("scratch workflow dir");
    // A SIBLING WORKFLOW IS ALWAYS PRESENT, because the real tree always has 27
    // of them and because the declared glob must match something for the rule to
    // run at all. A fixture with no workflows would exercise the skipped path
    // rather than the predicate.
    fs::write(dir.join("ci.yml"), "jobs:\n  ci:\n").expect("write the sibling");
    if let Some(body) = body {
        fs::write(dir.join("fast-forward.yml"), body).expect("write the landing workflow");
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
        "id": "check read never",
        "kind": "policy",
        "scope": "tree",
        "line_sources": [".github/workflows/*.yml"],
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
            words: None,
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

/// THE FIDELITY CASE. The COMMITTED bytes of the workflow that actually lands
/// every PR here, scanned by the engine in a fixture — the repo root itself
/// cannot be scanned with a one-rule subset, because `check_registry_is_exhausted`
/// then reports every class the other rules would have raised. `#MUTANT guard-unread`
/// reddens exactly here, and a fixture-only suite could not see the regression
/// this refuses.
#[test]
fn the_committed_landing_workflow_is_guarded() {
    let committed = fs::read_to_string(common::at_root(LANDING))
        .expect("the committed landing workflow is where the row says it is");
    let root = repo("landing-roster-committed", Some(&committed));
    assert!(
        rules_fired(&root).is_empty(),
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

/// THE DEFECT A CODE REVIEW FOUND, and it is the sharpest of the three because
/// the module's own DOCUMENTATION was what defeated it.
///
/// `guarded` first matched any line containing `checks-green`. The committed
/// `fast-forward.yml` carries that substring on FOUR comment lines — the block
/// explaining why the predicate is the engine's and reused whole — against ONE
/// real invocation. So deleting the step while leaving its comment block, which
/// is the ordinary shape of a "this step was flaky, dropping it" edit, left the
/// gate green over a landing path that no longer consults the roster.
///
/// The more the guard was explained, the deader it got. Anchoring on
/// `mise run checks-green` and excluding comment lines is what discriminates the
/// invocation from every mention of it.
///
/// The module's other anti-vacuity case rules out another FILE satisfying the
/// rule; this one rules out another LINE in the same file.
#[test]
fn a_comment_naming_the_roster_check_does_not_satisfy_the_guard() {
    let commentary = "\
jobs:
  fast-forward:
    steps:
      # THE PREDICATE IS THE ENGINE'S, REUSED WHOLE. `mise run checks-green` is
      # the adapter `land` itself decides on, and re-deriving it here would be a
      # second authority — `checks-green` read `cancelled` as red (CLOUD-363).
      - uses: sequoia-pgp/fast-forward@ea7628b # v1.0.0
";
    let root = repo("landing-roster-comment-only", Some(commentary));
    assert_eq!(
        rules_fired(&root),
        vec![UNGUARDED.to_owned()],
        "a comment that NAMES the roster check is not an invocation of it; \
         the step was deleted and only its rationale remains"
    );
}

/// AND THE PASS SIDE OVER A FIXTURE, so the refusal above is shown to turn on
/// the guard's presence rather than on the fixture being a fixture.
#[test]
fn a_fixture_landing_workflow_that_consults_the_roster_is_clean() {
    let root = repo("landing-roster-guarded", Some(GUARDED));
    assert!(rules_fired(&root).is_empty());
}

/// THE CASE THAT CORRECTED THE PREDICATE, kept with its history because the
/// history is the point.
///
/// The first draft guarded the refusal on the file being present and carried a
/// second arm over `input.tree.missing` for absence. This case returned `[]`
/// where a finding was owed: `line_sources` is a GLOB LIST, and a glob matching
/// zero files is not an unreadable source but no source at all, so nothing
/// enters `documents`, `lines` or `missing`. A branch DELETING the landing
/// workflow passed the gate silently.
///
/// The unconditional-arm probe `.claude/rules/policy-modules.md` prescribes had
/// already been run and had spoken — it confirms the MODULE evaluates, and says
/// nothing about whether a particular arm is reachable. Only driving the engine
/// over a tree with the file removed can tell.
#[test]
fn an_absent_landing_workflow_is_refused() {
    let root = repo("landing-roster-absent", None);
    assert_eq!(
        rules_fired(&root),
        vec![UNGUARDED.to_owned()],
        "deleting the landing workflow removes the guard, and must refuse rather than read clean"
    );
}

/// ANTI-VACUITY ON THE ANCHOR, over the engine's own projection. Another
/// workflow carrying the guard's text must not satisfy this rule — the failure
/// mode of an anchored rule whose walk quietly reads every path.
#[test]
fn the_guard_is_not_satisfied_from_another_workflow() {
    let root = repo("landing-roster-other-file", Some(UNGUARDED_BODY));
    // The decoy carries the guard's own text, in a workflow that is not the
    // landing one.
    fs::write(root.join(".github/workflows/ci.yml"), GUARDED).expect("write the decoy");
    assert_eq!(rules_fired(&root), vec![UNGUARDED.to_owned()]);
}
