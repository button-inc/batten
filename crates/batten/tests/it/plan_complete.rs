//! `plan-complete`, over the engine that builds its input (CLOUD-472).
//!
//! # The seam this tier owns, and why the module's own suite cannot reach it
//!
//! `policy/plan-complete.rego`'s `test_` rules pin the predicate against a
//! fabricated document. They cannot answer the question that actually decides
//! whether this gate is alive: does the ENGINE put `batten record plan`'s output
//! at `input.tree.records.plan` at all?
//!
//! That question has a specific reason to be asked here rather than assumed.
//! Every other record on that surface is minted by a `[[recorder]]` row, and
//! `recorder_records` used to read **only** the declared ones — so a store
//! written by a verb was invisible no matter what any module asked for. A
//! `with input as` case would have passed over that for the same reason it
//! passes over any key nothing fills, which is `rules/policy-modules.md`'s
//! whole warning about the two tiers.
//!
//! So these cases drive the real writer where they can, and `run_static` over a
//! real fixture repository otherwise.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule, RuleKind, RuleScope};

/// A fixture repository whose base is one commit back, with the plan record on
/// disk exactly where `batten record plan` writes it.
///
/// `origin/main` is a local ref at the base commit: `base_delta` resolves a rev,
/// and a fetch would make every case below depend on the network for a question
/// that is entirely local.
fn repo(name: &str, changed: &[&str], plan: Option<&[&str]>) -> PathBuf {
    claimed_repo(name, changed, plan, true)
}

/// The same fixture, with the claim receipt under the caller's control.
///
/// `claimed` is the population `plan-unrecorded` asks about — a branch that
/// pulled a row — so a case about an UNCLAIMED tree needs to build one, and that
/// case is what keeps the committed config usable over a scratch repository.
fn claimed_repo(name: &str, changed: &[&str], plan: Option<&[&str]>, claimed: bool) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", &base]);

    for path in changed {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, "changed\n").expect("write changed file");
    }

    install_module(&root);
    if claimed {
        write_record(&root, "claim", &["CLOUD-1"]);
    }
    if let Some(lines) = plan {
        write_record(&root, "plan", lines);
    }
    root
}

/// Write the record the way the verb does — through the engine's own
/// `record_path`, so a change to the naming breaks this tier rather than
/// silently pointing the reader and the writer at different files.
fn write_record(root: &Path, record: &str, lines: &[&str]) {
    let git_dir = common::git_in(root, &["rev-parse", "--absolute-git-dir"]);
    let git_dir = Path::new(git_dir.trim());
    // PARTITIONED EXACTLY AS THE READER PARTITIONS (CLOUD-1300), and the comment
    // above is what caught this: writing the unpartitioned name while
    // `recorder_records` resolved the claim pointed the two at different files,
    // and the `plan-unrecorded` arm went red because the reader found nothing
    // where the writer had put something.
    //
    // The `claim` receipt itself is never partitioned, and cannot be: it is the
    // file the partition is DERIVED from, so keying it by its own token would be
    // circular.
    let claim = if record == "claim" {
        None
    } else {
        batten::claim::claimed_token(&git_dir.join("batten-receipts"), "work")
    };
    let path = batten::recorder::record_path(git_dir, record, "work", claim.as_deref());
    fs::create_dir_all(path.parent().unwrap()).expect("receipts dir");
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    fs::write(path, body).expect("write the plan record");
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/plan-complete.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/plan-complete.rego")).expect("install committed module");
}

fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "plan-complete",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "module": "policy/plan-complete.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
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

fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

fn pointers(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.path)
        .collect()
}

const UNFINISHED: &str = "plan-unfinished";
const UNRECORDED: &str = "plan-unrecorded";

// ---------------------------------------------------------------------------
// THE READ SEAM. Without these two the whole module is a `with input as` suite
// over a key nothing fills — the shape a dead gate and a clean tree share.
// ---------------------------------------------------------------------------

/// The engine reads a store NO `[[recorder]]` declares. This is the assertion
/// that would have failed before `recorder_records` learned to read the
/// verb-written names, with every module test still green.
#[test]
fn the_engine_reads_a_verb_written_plan_store() {
    let root = repo("plan-read-seam", &["src/a.rs"], Some(&["1 pending"]));
    assert_eq!(
        verdicts(&root),
        vec![UNFINISHED.to_owned()],
        "the record the verb writes must reach the predicate"
    );
}

/// And the empty store is DISTINGUISHABLE from an absent one across the engine
/// boundary, not just inside the module. Absent refuses on the vacuity arm;
/// empty is an answer and is clean. If the projection collapsed the two, the
/// remedy for a trivial branch would be unreachable.
#[test]
fn an_empty_store_and_an_absent_one_reach_different_arms() {
    let empty = repo("plan-empty", &["src/a.rs"], Some(&[]));
    assert!(
        verdicts(&empty).is_empty(),
        "an empty record is the branch saying there is nothing to track: {:?}",
        verdicts(&empty)
    );

    let absent = repo("plan-absent", &["src/a.rs"], None);
    assert_eq!(
        verdicts(&absent),
        vec![UNRECORDED.to_owned()],
        "no record at all is the vacuity the other arm cannot see"
    );
}

// ---------------------------------------------------------------------------
// `plan-unfinished`.
// ---------------------------------------------------------------------------

#[test]
fn an_unfinished_entry_stops_the_lap() {
    let root = repo(
        "plan-unfinished",
        &["src/a.rs"],
        Some(&["1 completed", "2 in_progress"]),
    );
    assert_eq!(verdicts(&root), vec![UNFINISHED.to_owned()]);
    assert!(
        pointers(&root).iter().any(|line| line.contains('2')),
        "the refusal names the entry: {:?}",
        pointers(&root)
    );
}

#[test]
fn a_wholly_completed_plan_is_clean() {
    let root = repo(
        "plan-done",
        &["src/a.rs"],
        Some(&["1 completed", "2 deleted"]),
    );
    assert!(
        verdicts(&root).is_empty(),
        "finished and withdrawn are both terminal: {:?}",
        verdicts(&root)
    );
}

/// ONE FINDING PER ENTRY, so finishing one does not clear another and a reviewer
/// sees which item rather than a count to reconstruct.
#[test]
fn every_unfinished_entry_is_reported() {
    let root = repo(
        "plan-many",
        &["src/a.rs"],
        Some(&["1 pending", "2 completed", "3 pending"]),
    );
    assert_eq!(
        verdicts(&root),
        vec![UNFINISHED.to_owned(), UNFINISHED.to_owned()]
    );
}

/// POINTER, NEVER PAYLOAD (rule 4). The store holds an id and a status token and
/// no description, so there is no prose here to leak — and this is the assertion
/// that keeps a later edit from adding one.
#[test]
fn the_refusal_carries_no_entry_prose() {
    let root = repo("plan-pointer", &["src/a.rs"], Some(&["1 pending"]));
    let rendered = pointers(&root).join("\n");
    assert!(rendered.contains('1'), "the id is the pointer: {rendered}");
    assert!(
        !rendered.contains("pending"),
        "a status token is not a pointer: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// `plan-unrecorded` — the anti-vacuity arm.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_that_recorded_no_plan_is_refused() {
    let root = repo("plan-none", &["src/a.rs"], None);
    assert_eq!(verdicts(&root), vec![UNRECORDED.to_owned()]);
}

/// A branch holding nothing open has nothing to have planned. Without that the
/// arm fires on every fresh checkout, which is how a gate gets switched off.
///
/// The fixture always writes the module into the tree, so `changed` is never
/// truly empty here — the case that needs a genuinely empty delta lives in the
/// module's own suite, and this one records why it cannot live here. Same split,
/// and same reason, as `filed_here.rs`'s empty-delta note.
#[test]
fn the_engine_tier_cannot_build_an_empty_delta() {
    let root = repo("plan-fresh", &[], None);
    assert_eq!(
        verdicts(&root),
        vec![UNRECORDED.to_owned()],
        "installing the module is itself a change, so this tier always has a diff"
    );
}

/// AN UNCLAIMED BRANCH OWES NO PLAN, and this is the case that keeps the
/// committed config usable over a scratch repository. The first draft of the
/// vacuity arm keyed only on a non-empty diff, which is true of every fixture —
/// measured, it reddened four `cli.rs` cases whose only business was exercising
/// unrelated rules. Asserted at THIS tier and not only in the module, because
/// the population it selects is a record the engine has to actually read.
#[test]
fn an_unclaimed_branch_is_not_this_gates_business() {
    let root = claimed_repo("plan-unclaimed", &["src/a.rs"], None, false);
    assert!(
        verdicts(&root).is_empty(),
        "a branch that pulled no row owes no plan: {:?}",
        verdicts(&root)
    );
}

/// ANTI-VACUITY over the whole file: the row this suite exercises is the one the
/// committed config declares, so a rename or a scope change reddens here rather
/// than leaving every case above passing over a module nothing runs.
#[test]
fn the_committed_row_is_the_one_these_cases_exercise() {
    let committed: Vec<Rule> = batten::config::load(&common::at_root("batten.toml"))
        .expect("the committed config loads")
        .rules;
    let declared = committed
        .iter()
        .find(|rule| rule.id == "plan-complete")
        .expect("the committed config declares the row this suite exercises");
    assert_eq!(declared.kind, RuleKind::Policy);
    assert_eq!(declared.scope, RuleScope::Tree);
    assert_eq!(
        declared.module.as_deref(),
        Some("policy/plan-complete.rego")
    );
}

/// The verb and the reader must agree on the store's name and keying. Asserted
/// against `record::VERB_WRITTEN` rather than a literal, so adding a store
/// without teaching the engine to read it cannot pass.
#[test]
fn the_plan_store_is_declared_as_verb_written() {
    assert!(
        batten::record::VERB_WRITTEN.contains(&"plan"),
        "the engine must read the store the verb writes: {:?}",
        batten::record::VERB_WRITTEN
    );
}
