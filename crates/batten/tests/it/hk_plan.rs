//! The effective plan as a pre-admission fact, over the compiled engine
//! (CLOUD-949).
//!
//! # Why this tier
//!
//! `policy/hk-plan-required.rego`'s own cases hand themselves an
//! `input.tree.plan` object, so they are green over a key the engine may never
//! build — the class `.claude/rules/policy-modules.md` records, whose two
//! measured instances were both found by adding this tier rather than by
//! reading. What can only be proved here is that the boundary ACQUIRES the plan
//! and projects it under the key the module reads.
//!
//! # The discriminator that matters most
//!
//! [`a_dirty_edit_with_head_unchanged_moves_the_fingerprint`]. An
//! implementation keyed on HEAD passes every other case in this file and fails
//! only that one, which is exactly what CLOUD-949 says to test for. It is
//! asserted directly on the decision rather than through the gate, per
//! `.claude/rules/rust.md`: the failing condition is a WORKING TREE state, and a
//! test that reached it through a policy verdict would be asserting its own
//! premise on the way.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use batten::facts::Look;
use batten::hk;

/// The row `batten.toml` declares, deserialized rather than struct-literalled:
/// `Rule` carries `deny_unknown_fields`, so this goes through the same column
/// census a consumer's config does.
fn row() -> batten::rules::Rule {
    serde_json::from_value(serde_json::json!({
        "id": "hk-plan-required",
        "kind": "policy",
        "scope": "tree",
        "module": "policy/hk-plan-required.rego",
        "severity": "deny",
        "plan": [{"id": "gate", "hook": "check", "required": ["batten-check"]}],
    }))
    .expect("the row batten.toml declares")
}

/// The row declares the fact, which is what makes the engine acquire it.
///
/// A row that declared nothing would leave `input.tree.plan` unbuilt and the
/// module green over a key nothing fills — the dead-gate shape, which is silent
/// by construction. Asserted against the census rather than by reading the
/// column, so a renamed column fails here rather than going quiet.
#[test]
fn the_row_declares_the_plan_fact() {
    let row = row();
    assert!(
        batten::rules::COLUMN_CENSUS.iter().any(|column| {
            column.field == "plan"
                && matches!(
                    column.declares,
                    batten::rules::Declares::Fact(batten::facts::Fact::Plan, declared)
                        if declared(&row)
                )
        }),
        "a row carrying a `plan` column declares the plan fact"
    );
}

/// The fact is `Cost::Effect` on `Surface::Check`, so the mediated path cannot
/// resolve it.
///
/// The structural half of the row's effect claim: acquiring the plan runs the
/// runner, and `run_static` already refuses a spawning kind on the mediated
/// path. A fact resolvable there would weaken that guarantee into a convention.
#[test]
fn the_plan_is_never_resolvable_on_the_mediated_path() {
    let class = batten::facts::Fact::Plan.class();
    assert_eq!(class.cost, batten::facts::Cost::Effect);
    assert!(!class.resolvable_on(batten::facts::Surface::Hook));
    assert!(class.resolvable_on(batten::facts::Surface::Check));
}

/// The boundary really acquires a plan from the pinned runner, over this
/// checkout.
///
/// The case a `with input as` fixture cannot reach: it proves the engine builds
/// the shape the module reads, rather than that a fabricated one would satisfy
/// it. Every binding field is asserted non-empty, because a field the boundary
/// silently left blank is a binding nothing would ever compare.
#[test]
fn the_boundary_acquires_a_plan_the_module_can_read() {
    let root = common::at_root(".");
    let query: hk::PlanQuery = serde_json::from_value(
        serde_json::json!({"id": "gate", "hook": "check", "required": ["batten-check"]}),
    )
    .expect("the query a row declares");
    let Look::Is(planned) = hk::acquire(&root, &query) else {
        panic!("the pinned runner plans this checkout")
    };
    assert_eq!(planned.hook, "check");
    assert!(!planned.run_type.is_empty());
    assert!(!planned.tool_version.is_empty());
    assert!(!planned.input_fingerprint.is_empty());
    assert!(!planned.invocation.is_empty());
    assert!(!planned.steps.is_empty(), "an empty plan is never acquired");
    assert_eq!(planned.required, vec!["batten-check".to_owned()]);
    assert!(
        planned
            .steps
            .iter()
            .any(|step| step.name == "batten-check" && step.status == "included"),
        "this repository's gate still runs the step the row requires"
    );
}

/// A step the plan carries a reason for keeps the KIND and nothing else.
///
/// Rule 4 asserted over the real projection rather than over a fixture: the
/// runner's own `detail` sentence ("970 files matched") is what a copy would
/// have carried through, and the type has no field it could occupy.
#[test]
fn a_projected_step_carries_no_prose() {
    let value = serde_json::json!({"steps": [{
        "name": "one",
        "status": "skipped",
        "orderIndex": 0,
        "parallelGroupId": "group_0",
        "fileCount": 970,
        "reasons": [{"kind": "profile_exclude", "detail": "970 files matched"}],
    }]});
    let Look::Is(steps) = hk::planned_steps(&value) else {
        panic!("the fixture projects")
    };
    let rendered = serde_json::to_string(&steps).expect("the steps serialise");
    assert!(rendered.contains("profile_exclude"), "the kind survives");
    assert!(
        !rendered.contains("files matched"),
        "the runner's prose reaches no module"
    );
}

/// An empty plan is could-not-look, never a clean fact.
///
/// A plan that selected nothing looks exactly like a gate that passed, and the
/// two must not be one value.
#[test]
fn an_empty_plan_is_never_a_fact() {
    assert_eq!(
        hk::planned_steps(&serde_json::json!({"steps": []})),
        Look::CouldNotLook
    );
    assert_eq!(
        hk::planned_steps(&serde_json::json!({})),
        Look::CouldNotLook
    );
}

/// **The discriminator.** Dirty state moves the fingerprint with HEAD unmoved.
///
/// Three readings over one commit: clean, dirty, and dirty-differently. An
/// implementation keyed on HEAD gives three identical values and passes every
/// other case in this file; one keyed on the changed-path SET gives two, which
/// is why the third reading edits a file that is ALREADY dirty rather than
/// adding another.
#[test]
fn a_dirty_edit_with_head_unchanged_moves_the_fingerprint() {
    let dir = common::scratch("hk-plan-fingerprint");
    common::init_repo(&dir);
    common::write(&dir, "tracked.txt", "one\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-m", "seed", "--no-verify"]);

    let head = common::git_in(&dir, &["rev-parse", "HEAD"]);
    let Look::Is(clean) = hk::fingerprint(&dir) else {
        panic!("a committed tree fingerprints")
    };

    fs::write(dir.join("tracked.txt"), "two\n").expect("dirty the tree");
    let Look::Is(dirty) = hk::fingerprint(&dir) else {
        panic!("a dirty tree fingerprints")
    };

    fs::write(dir.join("tracked.txt"), "three\n").expect("dirty it differently");
    let Look::Is(dirtier) = hk::fingerprint(&dir) else {
        panic!("a differently dirty tree fingerprints")
    };

    assert_eq!(
        head,
        common::git_in(&dir, &["rev-parse", "HEAD"]),
        "HEAD did not move, which is the whole premise"
    );
    assert_ne!(clean, dirty, "going dirty moves the fingerprint");
    assert_ne!(
        dirty, dirtier,
        "editing an ALREADY dirty file moves it too; a changed-path set alone would not"
    );
}

/// An untracked file moves it as well, because the runner would select over it.
#[test]
fn an_untracked_file_moves_the_fingerprint() {
    let dir = common::scratch("hk-plan-fingerprint-untracked");
    common::init_repo(&dir);
    common::write(&dir, "tracked.txt", "one\n");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-m", "seed", "--no-verify"]);

    let Look::Is(before) = hk::fingerprint(&dir) else {
        panic!("a committed tree fingerprints")
    };
    fs::write(dir.join("new.txt"), "new\n").expect("add an untracked file");
    let Look::Is(after) = hk::fingerprint(&dir) else {
        panic!("a tree with an untracked file fingerprints")
    };
    assert_ne!(before, after);
}

/// A row naming a surface the contract does not cover is refused at load rather
/// than resolving to could-not-look forever.
#[test]
fn a_row_naming_an_unplannable_surface_is_refused() {
    let known: hk::PlanQuery =
        serde_json::from_value(serde_json::json!({"id": "gate", "hook": "check"}))
            .expect("a query naming a planned surface");
    let unknown: hk::PlanQuery =
        serde_json::from_value(serde_json::json!({"id": "gate", "hook": "post-merge"}))
            .expect("a query naming an unplannable surface");
    assert!(!known.unknown_hook());
    assert!(unknown.unknown_hook());
}

/// This repository's own row is clean over this checkout, through the compiled
/// binary and the spawning verb.
///
/// The case that has to keep passing. `enforce` rather than `check`, because the
/// fact is `Cost::Effect` and the read verb structurally refuses a rule set that
/// spawns — which is itself the row's effect claim, asserted by the exit code.
#[test]
fn this_repositorys_plan_row_is_clean_today() {
    let root = common::at_root(".");
    let output = common::run_at_real_root(&root, &["enforce", "--rule", "hk-plan-required"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the committed plan row refuses this checkout.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
