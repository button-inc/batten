//! `filed-here`, over the engine that builds its input (CLOUD-1051).
//!
//! # The tier this is, and why the retired suite could not be it
//!
//! `tests/filed-here-check.bats` drove a shell program that read the record and
//! shelled out for the diff itself. This drives `rules::run_static` over a real
//! fixture repository with a real `origin/main` and a real record on disk, so it
//! proves the ENGINE builds the shape the predicate reads — the seam
//! `.claude/rules/policy-modules.md` names as the one a `with input as` case
//! cannot reach. The module's own `test_` rules are the other tier and pin the
//! predicate; neither replaces the other.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! Two ledgers, two keys, and neither substitutes for the other. CLOUD-908's
//! `[rule.conserves]` ledger below is keyed on a quoted CASE TITLE and asks what
//! happened to each assertion. `shell-retirement` is keyed on the RETIRED PATH
//! and asks what now holds the predicate at all — so it demands one arm per file
//! naming both a policy surface and a compiled-binary test, because either alone
//! is satisfiable by a port that does nothing.
//!
// carried: mise-tasks/filed-here-check.sh policy/filed-here.rego crates/batten/tests/it/filed_here.rs
// carried: tests/filed-here-check.bats policy/filed-here.rego crates/batten/tests/it/filed_here.rs
//!
//! # RETIREMENT LEDGER — `tests/filed-here-check.bats`, 47 cases
//!
//! CARRIED — the property survives, proved here or in the module's own suite.
//!
// carried: "a create recorded with an unready verdict stops the lap, and the refusal names the id" crates/batten/tests/it/filed_here.rs
// carried: "the same row passes once its recorded verdict is green" policy/filed-here.rego
// carried: "a groom recorded after the create supersedes it" policy/filed-here.rego
// carried: "a later unready supersedes an earlier ready" policy/filed-here.rego
// carried: "superseding is per id: one row groomed leaves another's refusal standing" crates/batten/tests/it/filed_here.rs
// carried: "a recorded comment is never gated, whatever its verdict column says" policy/filed-here.rego
// carried: "a create the recorder could not lint is not a refusal" policy/filed-here.rego
// carried: "one unrefined row among refined ones is reported, and only that one" crates/batten/tests/it/filed_here.rs
// carried: "a branch that filed nothing passes untouched" crates/batten/tests/it/filed_here.rs
// carried: "an empty record passes" crates/batten/tests/it/filed_here.rs
// carried: "a record belonging to another branch is not read" crates/batten/tests/it/filed_here.rs
// carried: "a branch name with a slash finds its record, matching the recorder's spelling" crates/batten/tests/it/filed_here.rs
// carried: "the refusal carries the id and no prose from the row" crates/batten/tests/it/filed_here.rs
// carried: "a malformed line is skipped rather than judged" policy/filed-here.rego
// carried: "a row naming a file this branch is changing stops the lap" crates/batten/tests/it/filed_here.rs
// carried: "a row naming only untouched files passes" policy/filed-here.rego
// carried: "a row the recorder could not measure passes" policy/filed-here.rego
// carried: "a four-field line predating the column is not refused" crates/batten/tests/it/filed_here.rs
// carried: "A ROW RECORDED BEFORE THIS BRANCH'S BASE IS NOT A PUNT OVER ITS DIFF" crates/batten/tests/it/filed_here.rs
// carried: "a row recorded after the base, whose §1 names the diff, still refuses" crates/batten/tests/it/filed_here.rs
// carried: "A PATH CITED AS EVIDENCE IS NOT A CLAIM ON IT — §1 decides the subject" policy/filed-here.rego
// carried: "a row whose §1 names the diff is refused even when it cites other paths too" policy/filed-here.rego
// carried: "a six-field record with no §1 column is judged exactly as before" crates/batten/tests/it/filed_here.rs
// carried: "every overlapping path is named, one pointer per line" crates/batten/tests/it/filed_here.rs
// carried: "a row that is both unrefined and over the diff reports both" policy/filed-here.rego
// carried: "a later reading with no overlap supersedes an earlier one" policy/filed-here.rego
// carried: "and a later reading WITH an overlap supersedes a clean one" policy/filed-here.rego
// carried: "a comment is never gated on the diff either" policy/filed-here.rego
// carried: "A ROW RECORDED BEFORE THE FILE WAS TOUCHED IS STILL CAUGHT" crates/batten/tests/it/filed_here.rs
// carried: "a recorded path the branch does not change is not reported" crates/batten/tests/it/filed_here.rs
// carried: "a row naming only files this branch leaves alone passes" policy/filed-here.rego
// carried: "A ROW THE PR CLOSES IS EXEMPT — filing then fixing is the point, not the punt" crates/batten/tests/it/filed_here.rs
// carried: "closing a different row does not exempt this one" crates/batten/tests/it/filed_here.rs
// carried: "the diff refusal carries the id and one path and nothing else" crates/batten/tests/it/filed_here.rs policy/filed-here.rego
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce. Each names the general property that now covers it.
//!
// subsumed: "an AMBIENT bypass does not silence the gate — setup owns the environment" crates/batten/src/rules.rs kind:mechanism
// subsumed: "a re-lint of one row does not inflate the filed count" policy/filed-here.rego
// subsumed: "outside a git repository the gate fails open rather than stopping every lap" crates/batten/src/rules.rs kind:mechanism
// subsumed: "a detached HEAD has no branch to key on, and fails open" crates/batten/src/rules.rs kind:mechanism
// subsumed: "the pass line counts creates and comments separately" crates/batten/src/outputs.rs kind:mechanism
// subsumed: "the refusal names the three sinks and the local check" crates/batten/src/verdict.rs kind:mechanism
// subsumed: "the diff refusal names four remedies and none of them is writing more prose" crates/batten/src/verdict.rs kind:mechanism
// subsumed: "a body that only refs the row does not exempt it" mise-tasks/closing-key-check.sh
//!
//! CHANGED — behaviour that diverges deliberately, each with its reason.
//!
// changed: "filed-here-check.bats::the bypass is honoured" crates/batten/src/rules.rs kind:mechanism BATTEN_FILED_HERE_BYPASS is gone: this is a `[[rule]]` row now, so the engine's own hatch is the one switch, and a per-gate variable would be a second one nobody can find
// changed: "filed-here-check.bats::the override lets the diff refusal through" crates/batten/tests/it/admission.rs the override is an ISSUED admission rather than a variable somebody knows (CLOUD-1051), so the case moves to the suite that drives `batten override request` end to end
// changed: "filed-here-check.bats::the override records which rows it overrode" crates/batten/tests/it/admission.rs same cause: what an admission records is the store's property, asserted where the store is
// changed: "filed-here-check.bats::the override does not excuse an unrefined row" crates/batten/tests/it/admission.rs same cause, and the narrowing is structural now: an admission is keyed to one subject, so it cannot reach a second predicate at all
// changed: "filed-here-check.bats::the override records nothing when there was nothing to override" crates/batten/tests/it/admission.rs same cause: an unspent admission leaves the store untouched, which is the store's own case
//!
//! `BATTEN_FILED_HERE_BYPASS` and `BATTEN_FILED_HERE_OVERLAP` are **gone rather
//! than ported**, which is the whole of CLOUD-1051's first half: a knowable
//! environment variable is an override anyone can spend without articulating
//! anything, and the four `override` cases above are now the admission
//! mechanism's — requested, answered, content-addressed, and spent exactly once.
//! The engine's own `BATTEN_HOOK_BYPASS` never reached this gate and still does
//! not; `batten check` is a tree verb.
//!
//! The three-remedy and four-remedy prose is `[[verdict]]`'s now, once, where a
//! gate can read it — which is what makes a refusal naming a task that does not
//! exist a load error rather than a sentence nobody checked (CLOUD-1050).
//!
//! # Two rows this file does NOT carry, stated rather than left to inference
//!
//! `--advisory` and `--checklist` were `stop-guard`'s two callers and had no
//! case of their own in the retired suite — that suite drove the decision mode
//! only. They move with `stop-guard` rather than here, over this same module, so
//! there is still exactly one implementation of the intersection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule, RuleKind, RuleScope};

/// A fixture repository whose base is one commit back and whose record is on
/// disk exactly where the recorder would have written it.
///
/// `origin/main` is a local ref pointed at the base commit. No remote is
/// configured: `base_delta` resolves a rev, and a fetch would make every case
/// below depend on the network for a question that is entirely local.
fn repo(name: &str, branch: &str, changed: &[&str], record: &[&str], closes: &[&str]) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", branch]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    // The base commit, dated fixed and in the past so a record's timestamp can be
    // placed on either side of it deliberately rather than by racing the clock.
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    commit(&root, "base", BASE_DATE);
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
    write_record(&root, branch, "board-writes", record);
    if !closes.is_empty() {
        write_record(&root, branch, "pr-closes", closes);
    }
    root
}

/// The base commit's own timestamp, fixed so the timestamp arm is testable.
const BASE_DATE: &str = "2026-02-01T00:00:00+0000";
/// A record written after the base — the punt window.
const AFTER: &str = "2026-02-02T00:00:00Z";
/// A record written before it — a row that cannot be a deferral of this diff.
const BEFORE: &str = "2026-01-01T00:00:00Z";

/// A commit whose COMMITTER date is fixed.
///
/// `--date` sets the AUTHOR date and `base_delta` reads the committer one, so
/// the environment variable is the half that matters here; both are set so the
/// fixture carries one timestamp rather than two.
fn commit(root: &Path, message: &str, date: &str) {
    let output = common::git_command(root, &["commit", "--quiet", "-m", message, "--date", date])
        .env("GIT_COMMITTER_DATE", date)
        .output()
        .expect("run git");
    assert!(output.status.success(), "commit the fixture base");
}

fn write_record(root: &Path, branch: &str, record: &str, lines: &[&str]) {
    let dir = root.join(".git/batten-receipts");
    fs::create_dir_all(&dir).expect("receipts dir");
    let path = dir.join(format!("{record}.{}", branch.replace('/', "-")));
    fs::write(path, format!("{}\n", lines.join("\n"))).expect("write record");
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/filed-here.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/filed-here.rego")).expect("install committed module");
}

fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "filed-here",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "module": "policy/filed-here.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

/// The recorder rows the engine needs in order to KNOW which records to read.
///
/// Minimal on purpose: `recorder_records` reads `record` and nothing else, so a
/// full transcription of `batten.toml`'s columns here would be a second copy of
/// a declaration this test does not exercise.
fn recorders() -> Vec<batten::recorder::Declared> {
    ["board-writes", "pr-closes"]
        .into_iter()
        .map(|record| batten::recorder::Declared {
            name: record.to_owned(),
            record: record.to_owned(),
            tool: "save_issue".to_owned(),
            key: batten::recorder::RecordKey::Branch,
            requires: Vec::new(),
            refused_when_input: Vec::new(),
            requires_input_matching: std::collections::BTreeMap::new(),
            requires_recorded: None,
            columns: vec![batten::recorder::Column {
                name: "kind".to_owned(),
                value: batten::recorder::Value::Literal("issue".to_owned()),
                minus: None,
                without: None,
                counted_with: None,
                zero_is_a_count: false,
            }],
        })
        .collect()
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    let patterns = vec![batten::pattern::NamedPattern {
        id: "positive-count".to_owned(),
        regex: "^[1-9][0-9]*$".to_owned(),
    }];
    let declared = recorders();
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            recorders: &declared,
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

/// Every finding's predicate id, in the order the engine emitted them.
fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

/// Every finding's pointer — the path the first path-bearing subject named.
fn pointers(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.path)
        .collect()
}

const UNREFINED: &str = "filed-unrefined";
const OVER_DIFF: &str = "filed-over-own-diff";
const LEFT_OPEN: &str = "filed-and-left-open";

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_that_filed_nothing_passes_untouched() {
    let root = repo("filed-nothing", "work", &["src/a.rs"], &[], &[]);
    fs::remove_file(root.join(".git/batten-receipts/board-writes.work")).expect("no record");
    assert!(verdicts(&root).is_empty(), "no record is no answer");
}

#[test]
fn an_empty_record_passes() {
    let root = repo("empty-record", "work", &["src/a.rs"], &[""], &[]);
    assert!(verdicts(&root).is_empty(), "an empty record judges nothing");
}

#[test]
fn a_record_belonging_to_another_branch_is_not_read() {
    let root = repo("other-branch", "work", &["src/a.rs"], &[], &[]);
    write_record(
        &root,
        "somebody-else",
        "board-writes",
        &[&format!("issue CLOUD-1 {AFTER} unready - - -")],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the record is keyed by branch, and this branch has none"
    );
}

/// The recorder replaces `/` with `-` in the filename; a reader spelling it any
/// other way opens a file the recorder never wrote and passes everything.
#[test]
fn a_branch_name_with_a_slash_finds_its_record() {
    let root = repo(
        "slashed",
        "feat/thing",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} unready - - -")],
        &[],
    );
    assert_eq!(verdicts(&root), vec![UNREFINED.to_owned()]);
}

// ---------------------------------------------------------------------------
// `filed-unrefined`.
// ---------------------------------------------------------------------------

#[test]
fn an_unready_create_stops_the_lap() {
    let root = repo(
        "unready",
        "work",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} unready - - -")],
        &[],
    );
    assert_eq!(verdicts(&root), vec![UNREFINED.to_owned()]);
}

#[test]
fn one_unrefined_row_among_refined_ones_is_reported_and_only_that_one() {
    let root = repo(
        "one-of-many",
        "work",
        &["src/a.rs"],
        &[
            &format!("issue CLOUD-1 {AFTER} ready - - -"),
            &format!("issue CLOUD-2 {AFTER} unready - - -"),
            &format!("issue CLOUD-3 {AFTER} ready - - -"),
        ],
        &[],
    );
    assert_eq!(verdicts(&root), vec![UNREFINED.to_owned()]);
    assert!(
        pointers(&root).iter().any(|line| line.contains("CLOUD-2")),
        "the refusal names the row: {:?}",
        pointers(&root)
    );
}

/// Superseding is PER ID, which is what a single accumulator got wrong: grooming
/// one row must not clear another's refusal.
#[test]
fn superseding_is_per_id() {
    let root = repo(
        "per-id",
        "work",
        &["src/a.rs"],
        &[
            &format!("issue CLOUD-1 {AFTER} unready - - -"),
            &format!("issue CLOUD-2 {AFTER} unready - - -"),
            &format!("issue CLOUD-1 {AFTER} ready - - -"),
        ],
        &[],
    );
    assert_eq!(verdicts(&root), vec![UNREFINED.to_owned()]);
    assert!(
        pointers(&root).iter().any(|line| line.contains("CLOUD-2")),
        "the ungroomed row's refusal stands: {:?}",
        pointers(&root)
    );
}

/// POINTER, NEVER PAYLOAD (rule 4). The recorder never wrote a title or a body,
/// so there is none here to leak — and this is the assertion that keeps a later
/// edit from putting one in.
#[test]
fn the_refusal_carries_the_id_and_no_prose_from_the_row() {
    let root = repo(
        "pointer-only",
        "work",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} unready - - -")],
        &[],
    );
    let rendered = pointers(&root).join("\n");
    assert!(rendered.contains("CLOUD-1"), "the id is the pointer");
    assert!(
        !rendered.contains("unready"),
        "a column value is not a pointer: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// `filed-over-own-diff`.
// ---------------------------------------------------------------------------

#[test]
fn a_row_naming_a_file_this_branch_is_changing_stops_the_lap() {
    let root = repo(
        "over-diff",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(verdicts(&root), vec![OVER_DIFF.to_owned()]);
}

/// A path outside the diff is not a punt against it — for the PROXIMITY refusal,
/// which is the only one this case was ever about. `filed-and-left-open` takes it
/// instead, and asserting the exact verdict rather than "not empty" is what makes
/// the partition falsifiable from this tier.
#[test]
fn a_recorded_path_the_branch_does_not_change_is_not_a_proximity_refusal() {
    let root = repo(
        "elsewhere",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/z.rs - 1,src/z.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(verdicts(&root), vec![LEFT_OPEN.to_owned()]);
}

/// ONE POINTER PER PATH, as the shell emitted, so a reviewer sees which file
/// rather than a count they have to go and reconstruct.
#[test]
fn every_overlapping_path_is_named() {
    let root = repo(
        "many-paths",
        "work",
        &["src/a.rs", "src/b.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 2,src/a.rs,src/b.rs - 2,src/a.rs,src/b.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(
        verdicts(&root),
        vec![OVER_DIFF.to_owned(), OVER_DIFF.to_owned()]
    );
}

/// THE PATH IS THE FINDING'S OWN POINTER, which is the ordering statement the
/// module makes: `subjects` leads with the tracked path a reader should open,
/// and the row's id follows it. `first_pointer` takes the first PATH-BEARING
/// subject, so the id travels as an ordered subject rather than as the pointer —
/// and both reach a reader, which is what the module's own suite asserts on the
/// subject list.
#[test]
fn the_diff_refusal_points_at_the_tracked_path() {
    let root = repo(
        "diff-pointer",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(pointers(&root), vec!["src/a.rs".to_owned()]);
}

/// THE EXEMPTION THAT KEEPS THE GATE FROM INVERTING. Without it, every honest
/// file-then-fix needs the override, and a routinely overridden gate is bypassed
/// rather than satisfied.
#[test]
fn a_row_the_pr_closes_is_exempt() {
    let root = repo(
        "closed",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 1:CLOUD-1"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "filing then fixing is the work landing"
    );
}

#[test]
fn closing_a_different_row_does_not_exempt_this_one() {
    let root = repo(
        "closed-other",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 1:CLOUD-9"],
    );
    assert_eq!(verdicts(&root), vec![OVER_DIFF.to_owned()]);
}

/// A punt is a deferral of work in the diff you are holding open; a row recorded
/// before the branch's base cannot be one, by construction. Measured: 3 of 3
/// refusals on one PR were rows already In Review, landed before the branch was
/// cut, and the override had to be spent on all three.
#[test]
fn a_row_recorded_before_the_branch_s_base_is_not_a_punt() {
    let root = repo(
        "predates",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {BEFORE} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 0"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the diff did not exist when the row was written"
    );
}

#[test]
fn a_row_recorded_after_the_base_whose_sec1_names_the_diff_still_refuses() {
    let root = repo(
        "after-base",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(verdicts(&root), vec![OVER_DIFF.to_owned()]);
}

/// A ROW RECORDED BEFORE THE FILE WAS TOUCHED IS STILL CAUGHT, which is the
/// whole reason the intersection moved to read time. Rows are filed BEFORE any
/// file is touched — AGENTS.md says claim before writing code — so a fact frozen
/// at write time recorded zero every time and this refusal could never see the
/// punt it exists for.
#[test]
fn a_row_recorded_before_the_file_was_touched_is_still_caught() {
    let root = repo(
        "before-touch",
        "work",
        &[],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/a.rs"
        )],
        &["closes 0"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "nothing is in the diff yet, so nothing intersects"
    );
    fs::create_dir_all(root.join("src")).expect("src");
    fs::write(root.join("src/a.rs"), "now\n").expect("touch the file");
    assert_eq!(
        verdicts(&root),
        vec![OVER_DIFF.to_owned()],
        "the same record refuses once the file is open"
    );
}

// ---------------------------------------------------------------------------
// A RECORD FROM AN OLDER RECORDER. A branch is never refused for a question its
// recorder could not ask, and never silently exempted either.
// ---------------------------------------------------------------------------

#[test]
fn a_four_field_line_predating_the_overlap_column_is_not_refused() {
    let root = repo(
        "four-field",
        "work",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} ready")],
        &["closes 0"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "no overlap column is could-not-look, not a measured zero"
    );
}

#[test]
fn a_six_field_record_with_no_sec1_column_is_judged_exactly_as_before() {
    let root = repo(
        "six-field",
        "work",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} ready 1,src/a.rs -")],
        &["closes 0"],
    );
    assert_eq!(
        verdicts(&root),
        vec![OVER_DIFF.to_owned()],
        "an absent §1 leaves the row judged as it was before that column existed"
    );
}

// ---------------------------------------------------------------------------
// `filed-and-left-open` (CLOUD-1311). The set refusal: a row this branch put on
// the board that it is not landing.
//
// Its whole reason for existing is the class the two arms above cannot see — a
// row filed while the branch was open whose §1 points somewhere else, which
// `cites_only` exempts from the proximity refusal by design. Three of the four
// deferrals that motivated this issue sat exactly there.
// ---------------------------------------------------------------------------

#[test]
fn a_row_the_branch_filed_and_does_not_close_stops_the_lap() {
    let root = repo(
        "left-open",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"
        )],
        &["closes 0"],
    );
    assert_eq!(verdicts(&root), vec![LEFT_OPEN.to_owned()]);
}

/// NO PR YET IS COULD-NOT-LOOK. `verify` runs before the PR exists on most laps,
/// and refusing there would name a remedy — "close it in the body" — with no body
/// to write it in. The absent record is the signal; there is nothing to tune.
#[test]
fn an_unread_pr_body_leaves_the_set_unjudged() {
    let root = repo(
        "no-body",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"
        )],
        &[],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the forge's answer has not been captured, so the set is not judged"
    );
}

/// AND A FETCH WHOSE KEY READER COULD NOT RUN IS THE SAME ANSWER, which is the
/// distinction `zero-is-a-count` exists to preserve: `closes 0` is a measurement
/// and `closes -` is not.
#[test]
fn an_unreadable_closing_key_column_leaves_the_set_unjudged() {
    let root = repo(
        "unreadable-body",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"
        )],
        &["closes -"],
    );
    assert!(verdicts(&root).is_empty(), "`-` is could-not-look");
}

/// ANTI-VACUITY ON THE EXEMPTION: one closing key must not buy the whole set.
/// Without this, an author closes the cheapest row they filed and the gate goes
/// quiet about every other one — which is the arm switched off by its own remedy.
#[test]
fn closing_one_row_does_not_close_the_set() {
    let root = repo(
        "close-one",
        "work",
        &["src/a.rs"],
        &[
            &format!("issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"),
            &format!("issue CLOUD-2 {AFTER} ready 1,src/a.rs - 1,src/b.rs"),
        ],
        &["closes 1:CLOUD-1"],
    );
    assert_eq!(verdicts(&root), vec![LEFT_OPEN.to_owned()]);
    assert!(
        pointers(&root).iter().any(|line| line.contains("CLOUD-2")),
        "the row still open is the one reported: {:?}",
        pointers(&root)
    );
}

/// POINTER, NEVER PAYLOAD (rule 4) for this arm too. The recorder wrote no title
/// and no body, and this is the assertion that keeps a later edit from adding
/// one — an articulation's prose especially, which is the one thing this class
/// collects that a finding must never carry.
#[test]
fn the_set_refusal_carries_the_id_and_nothing_else() {
    let root = repo(
        "left-open-pointer",
        "work",
        &["src/a.rs"],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"
        )],
        &["closes 0"],
    );
    let rendered = pointers(&root).join("\n");
    assert!(rendered.contains("CLOUD-1"), "the id is the pointer");
    assert!(
        !rendered.contains("src/b.rs"),
        "a §1 path is not this arm's subject: {rendered}"
    );
}

/// A BRANCH HOLDING NOTHING OPEN DEFERRED NOTHING, so there is no diff for the
/// row to have been filed instead of. Not a dodge: an empty branch cannot land.
#[test]
fn a_branch_with_no_diff_judges_no_row() {
    let root = repo(
        "left-open-empty",
        "work",
        &[],
        &[&format!(
            "issue CLOUD-1 {AFTER} ready 1,src/a.rs - 1,src/b.rs"
        )],
        &["closes 0"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "nothing is open, so nothing was deferred"
    );
}

/// A record from an older recorder has no §1 column, so the partition cannot be
/// evaluated and the row stays judged exactly as it was before this arm existed.
#[test]
fn a_record_with_no_sec1_column_is_outside_this_arm() {
    let root = repo(
        "left-open-six-field",
        "work",
        &["src/a.rs"],
        &[&format!("issue CLOUD-1 {AFTER} ready 0 -")],
        &["closes 0"],
    );
    assert!(
        verdicts(&root).is_empty(),
        "could-not-look on §1 is not a refusal"
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
        .find(|rule| rule.id == "filed-here")
        .expect("the committed config declares the row this suite exercises");
    assert_eq!(declared.kind, RuleKind::Policy);
    assert_eq!(declared.scope, RuleScope::Tree);
    assert_eq!(declared.module.as_deref(), Some("policy/filed-here.rego"));
}
