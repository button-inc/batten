//! `batten ready graph` over the compiled binary (CLOUD-175, CLOUD-1221).
//!
//! The board's decision table — the two board-state predicates as exit codes,
//! graph coherence, the milestone claims, the status-claim scan and the frontier
//! as a by-product — ported from `tests/graph-check.bats` when the program and
//! the second Ready grammar it spawned retired together.
//!
//! # EVERY CASE RUNS IN A THROWAWAY REPOSITORY, AND NOW IT CARRIES A GRAMMAR
//!
//! The bats suite `cd`'d into a scratch repo so the `board-move` receipts the
//! gate mints landed there rather than in the real checkout (CLOUD-512). That
//! sandbox is also what sank the first retirement (PR #778): the compiled
//! successor reads its grammar from a consumer's `[[pattern]]` rows, and a bare
//! scratch repo has none. So each fixture here declares this repository's own
//! board and patterns, read from the committed table rather than re-typed, and a
//! workspace version for the §6 arrows — the consumer the verb is judged by.
//!
//! # THE EXIT CODES MOVED, ALL OF THEM, AND IT IS ONE DECISION RATHER THAN 84
//!
//! The shell answered `1` for a violation and `2` for could-not-look. This verb
//! answers the crate's one table: `2` is the policy verdict and `1` is
//! could-not-look. The `[tasks.graph-check]` adapter translates back for the two
//! shell readers; the cases here assert the verb's own codes, and the pair at the
//! bottom asserts the adapter's. The arms stay CARRIED because the predicate is
//! identical in every one.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/graph-check.sh crates/batten/src/graph_check.rs kind:verb crates/batten/tests/it/graph_check.rs
// carried: tests/graph-check.bats crates/batten/src/graph_check.rs kind:verb crates/batten/tests/it/graph_check.rs
//!
//! # RETIREMENT LEDGER — `tests/graph-check.bats`, 86 cases
//!
//! CARRIED — the property survives, proved here against the engine.
//!
// carried: "a coherent board exits 0" crates/batten/tests/it/graph_check.rs
// carried: "an unassigned In Progress issue is reported" crates/batten/tests/it/graph_check.rs
// carried: "an assigned In Progress issue is not" crates/batten/tests/it/graph_check.rs
// carried: "an In Review issue with no PR attachment is reported" crates/batten/tests/it/graph_check.rs
// carried: "an In Review issue with a linked PR is not" crates/batten/tests/it/graph_check.rs
// carried: "AN IN REVIEW ROW DECLARING NO COMMIT IS EXEMPT FROM in-review-no-pr" crates/batten/tests/it/graph_check.rs
// carried: "a row declaring no commit that carries a PR is refused for the contradiction" crates/batten/tests/it/graph_check.rs
// carried: "an In Review row that declares nothing is still refused with no PR" crates/batten/tests/it/graph_check.rs
// carried: "a declaration of no commit does not change how any other column is judged" crates/batten/tests/it/graph_check.rs
// carried: "a blockedBy cycle is reported with its members" crates/batten/tests/it/graph_check.rs
// carried: "a dangling blocker is reported" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue whose only blocker is Done and piped reaches the frontier" crates/batten/tests/it/graph_check.rs
// carried: "a blocker outside the piped set is unjudgeable, not resolved" crates/batten/tests/it/graph_check.rs
// carried: "a piped, genuinely open blocker still excludes at exit 0" crates/batten/tests/it/graph_check.rs
// carried: "a Todo row whose only blocker is Canceled reaches the frontier" crates/batten/tests/it/graph_check.rs
// carried: "a Todo row whose only blocker is Duplicate reaches the frontier" crates/batten/tests/it/graph_check.rs
// carried: "a blocker In Review still resolves, since its type is started" crates/batten/tests/it/graph_check.rs
// carried: "an In Progress blocker still excludes, with its attribution unchanged" crates/batten/tests/it/graph_check.rs
// carried: "a Backlog blocker still excludes" crates/batten/tests/it/graph_check.rs
// carried: "a frontier row over a retired blocker says so" crates/batten/tests/it/graph_check.rs
// carried: "a frontier row over a COMPLETED blocker says nothing extra" crates/batten/tests/it/graph_check.rs
// carried: "a set with no edges at all is unchanged by the three-way branch" crates/batten/tests/it/graph_check.rs
// carried: "one row short of its closure does not withhold the rest of the frontier" crates/batten/tests/it/graph_check.rs
// carried: "the frontier is unblocked lint-passing Todo issues" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue blocked by unfinished work is off the frontier" crates/batten/tests/it/graph_check.rs
// carried: "a blocker landed to In Review unblocks its dependents" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue with no Ready block is refused" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue whose Ready block satisfies the clauses is not" crates/batten/tests/it/graph_check.rs
// carried: "a Backlog issue with no Ready block is not refused" crates/batten/tests/it/graph_check.rs
// carried: "wip counts In Progress only" crates/batten/tests/it/graph_check.rs
// carried: "output ordering is byte-stable and numeric" crates/batten/tests/it/graph_check.rs
// carried: "an array input works the same as a stream" crates/batten/tests/it/graph_check.rs
// carried: "graph-check.bats::unparseable stdin exits 2, not 1" crates/batten/tests/it/graph_check.rs
// carried: "an unjudgeable payload and a failing Ready block do not produce the same output" crates/batten/tests/it/graph_check.rs
// carried: "a payload ready-lint cannot read is reported and exits 2" crates/batten/tests/it/graph_check.rs
// carried: "a genuinely failing Ready block is attributed and refused" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue held off the frontier by a blocker says which one" crates/batten/tests/it/graph_check.rs
// carried: "a set carrying no blockedBy data claims nothing about the graph" crates/batten/tests/it/graph_check.rs
// carried: "the missing-blockedBy report is keyed to the set, not to each issue" crates/batten/tests/it/graph_check.rs
// carried: "an explicit empty blockedBy is data, not an unjudgeable payload" crates/batten/tests/it/graph_check.rs
// carried: "a payload it could not read outranks a board it could" crates/batten/tests/it/graph_check.rs
// carried: "a judgeable, passing board emits no exclusion and no unjudgeable report" crates/batten/tests/it/graph_check.rs
// carried: "a coherent set's stdout bytes are unchanged" crates/batten/tests/it/graph_check.rs
// carried: "violations are pointer-only — no issue prose echoed" crates/batten/tests/it/graph_check.rs
// carried: "a body claiming a column the board contradicts is reported" crates/batten/tests/it/graph_check.rs
// carried: "the same claim, agreeing with the board, is clean" crates/batten/tests/it/graph_check.rs
// carried: "a mention asserting no column is not a claim" crates/batten/tests/it/graph_check.rs
// carried: "Linear's stored mention markup is caught identically to the rendered form" crates/batten/tests/it/graph_check.rs
// carried: "a claim about an id outside the piped set is unjudgeable, never guessed" crates/batten/tests/it/graph_check.rs
// carried: "a quoted or backticked citation of a claim is not a claim" crates/batten/tests/it/graph_check.rs
// carried: "narration about an issue is not a claim about its column" crates/batten/tests/it/graph_check.rs
// carried: "a gloss with no verb at all is a claim, in every shape the corpus uses" crates/batten/tests/it/graph_check.rs
// carried: "a set with no descriptions cannot be scanned for claims, and says so" crates/batten/tests/it/graph_check.rs
// carried: "a set carrying only the declared field set is accepted" crates/batten/tests/it/graph_check.rs
// carried: "a status claim report is pointer-only — no surrounding prose echoed" crates/batten/tests/it/graph_check.rs
// carried: "a column no piped issue occupies is not in the vocabulary" crates/batten/tests/it/graph_check.rs
// carried: "a claim naming a column no piped issue occupies is refused, not ignored" crates/batten/tests/it/graph_check.rs
// carried: "the same claim, over a set that DOES occupy the column, is judged as before" crates/batten/tests/it/graph_check.rs
// carried: "a body carrying a stale claim AND its own correction reports the stale one" crates/batten/tests/it/graph_check.rs
// carried: "ordinary prose is not a claim, however capitalized" crates/batten/tests/it/graph_check.rs
// carried: "an unscannable report is pointer-only — no surrounding prose echoed" crates/batten/tests/it/graph_check.rs
// carried: "a multi-word column is named whole, never its first word" crates/batten/tests/it/graph_check.rs
// carried: "ANTI-VACUITY: a set with no status claims anywhere still exits 0" crates/batten/tests/it/graph_check.rs
// carried: "a coherent board records one receipt per id it judged" crates/batten/tests/it/graph_check.rs
// carried: "a value that is not an issue key mints nothing, so it cannot become a path" crates/batten/tests/it/graph_check.rs
// carried: "a board signalling falsely records nothing" crates/batten/tests/it/graph_check.rs
// carried: "a board it could not read records nothing" crates/batten/tests/it/graph_check.rs
// carried: "an earlier closure stays judged, because each id has its own receipt" crates/batten/tests/it/graph_check.rs
// carried: "the receipt is pointer-only — an id and an epoch, never issue prose" crates/batten/tests/it/graph_check.rs
// carried: "an unwritable receipt store does not change the verdict" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue carrying a milestone is clean, and still reaches the frontier" crates/batten/tests/it/graph_check.rs
// carried: "a Todo issue with no milestone, in a set where others carry one, is refused" crates/batten/tests/it/graph_check.rs
// carried: "a set with the field absent everywhere is unjudgeable, not a wall of violations" crates/batten/tests/it/graph_check.rs
// carried: "an unparented In Progress row with no milestone is refused" crates/batten/tests/it/graph_check.rs
// carried: "an unparented In Review row with no milestone is refused" crates/batten/tests/it/graph_check.rs
// carried: "a started row carrying a milestone passes, and its frontier place is unchanged" crates/batten/tests/it/graph_check.rs
// carried: "a parented row is reported ONCE, by CLOUD-599's clause and not CLOUD-771's" crates/batten/tests/it/graph_check.rs
// carried: "a Done row with no milestone is clean — a closed row's phase changes nothing" crates/batten/tests/it/graph_check.rs
// carried: "the anti-vacuity arm widened with the clause" crates/batten/tests/it/graph_check.rs
// carried: "a child with no milestone under a milestoned parent is refused" crates/batten/tests/it/graph_check.rs
// carried: "a child carrying a DIFFERENT milestone is the declared re-phase and passes" crates/batten/tests/it/graph_check.rs
// carried: "a child whose parent carries no milestone is clean — no pair can diverge" crates/batten/tests/it/graph_check.rs
// carried: "a parent outside the piped set is unjudgeable, not a violation" crates/batten/tests/it/graph_check.rs
// carried: "a Backlog issue with no milestone is clean — filing stays free" crates/batten/tests/it/graph_check.rs
//!
//! CHANGED — two cases bounded the PROCESS count of a shell program's joins
//! (CLOUD-634): the number of `jq` and `grep` forks did not grow with the edge
//! count. One compiled process forks nothing, so the bound holds by
//! construction and a count of zero against zero would discriminate nothing.
//! The property they protected — lookups indexed once rather than rescanned per
//! edge — is `graph_check::Board`'s map.
//!
// changed: "the jq count does not grow with the edge count" crates/batten/src/graph_check.rs the verb spawns no jq at all, so the fork count it bounded is zero on both arms by construction
// changed: "the grep count does not grow with the edge count" crates/batten/src/graph_check.rs the verb spawns no grep at all, so the fork count it bounded is zero on both arms by construction

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, declared_board, declared_patterns, run_with_stdin, stderr, stdout};

/// A passing Ready block, shared by every row: since CLOUD-375 a Todo issue
/// whose block fails is a violation, so a fixture body is never neutral.
const READY: &str = "**Refinement — Ready (t)**\n\n* **Source of truth (§1).** One artifact.";

/// A repository that declares this consumer's grammar and board, as the
/// committed table spells them, and a workspace version for the §6 arrows.
fn repo(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&format!(
            "version = 1\n{}\n{}",
            declared_board(),
            declared_patterns()
        ))
        .file("Cargo.toml", "[workspace.package]\nversion = \"0.0.125\"\n")
        .git()
        .build()
}

fn receipts(dir: &Path) -> PathBuf {
    dir.join(".git").join("batten-receipts")
}

/// The payload set, built the way the bats suite's `issue` helper built it.
#[derive(Default)]
struct Board {
    rows: Vec<serde_json::Value>,
}

impl Board {
    /// One payload. `statusType` is DERIVED from the column, because the tracker
    /// returns both on every payload (CLOUD-477) — `Canceled` is `canceled` and
    /// `Duplicate` is `duplicate`, two distinct values.
    fn issue(&mut self, id: &str, status: &str, assignee: &str, pr: &str, blockers: &[&str]) {
        let kind = match status {
            "Todo" => "unstarted",
            "Backlog" => "backlog",
            "In Progress" | "In Review" => "started",
            "Done" => "completed",
            "Canceled" => "canceled",
            "Duplicate" => "duplicate",
            _ => "",
        };
        let attachments: Vec<serde_json::Value> = if pr.is_empty() {
            Vec::new()
        } else {
            vec![serde_json::json!({ "url": pr })]
        };
        let relations: Vec<serde_json::Value> = blockers
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect();
        let mut row = serde_json::json!({
            "id": id,
            "status": status,
            "attachments": attachments,
            "relations": { "blockedBy": relations },
            "description": format!("**Why**\nx.\n\n{READY}"),
            "projectMilestone": { "id": "m-1", "name": "Phase 3" },
        });
        if !assignee.is_empty() {
            row["assigneeId"] = serde_json::json!(assignee);
        }
        if !kind.is_empty() {
            row["statusType"] = serde_json::json!(kind);
        }
        self.rows.push(row);
    }

    /// The same payload with `projectMilestone` omitted — how the tracker renders
    /// a row that has none, since it drops the key rather than nulling it.
    fn no_milestone(&mut self, id: &str, status: &str, assignee: &str, pr: &str) {
        self.issue(id, status, assignee, pr, &[]);
        self.row(id)
            .as_object_mut()
            .unwrap()
            .remove("projectMilestone");
    }

    /// Declare that this row lands no commit, in its §6.
    fn declares_none(&mut self, id: &str, status: &str, pr: &str) {
        self.issue(id, status, "someone", pr, &[]);
        let row = self.row(id);
        let body = row["description"].as_str().unwrap().to_owned();
        row["description"] = serde_json::json!(format!(
            "{body}\n* **Commit / bump (§6).** **none** — this row lands no commit."
        ));
    }

    /// Give one row a body to be judged on, the Ready block riding along.
    fn describe(&mut self, id: &str, text: &str) {
        self.row(id)["description"] = serde_json::json!(format!("{text}\n\n{READY}"));
    }

    fn set(&mut self, id: &str, key: &str, value: serde_json::Value) {
        self.row(id)[key] = value;
    }

    /// Drop a key from EVERY payload — a caller that projected it away.
    fn drop_key(&mut self, key: &str) {
        for row in &mut self.rows {
            row.as_object_mut().unwrap().remove(key);
        }
    }

    fn row(&mut self, id: &str) -> &mut serde_json::Value {
        self.rows
            .iter_mut()
            .find(|row| row["id"] == id)
            .expect("the row is on the board")
    }

    /// A concatenated stream of objects, which is what a caller pipes.
    fn stream(&self) -> String {
        self.rows
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn check(dir: &Path, board: &Board) -> Output {
    run_with_stdin(dir, &["ready", "graph"], &board.stream())
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

/// Both streams, which is what the bats suite's `$output` held.
fn all(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

const COHERENT: i32 = 0;
const VIOLATION: i32 = 2;
const COULD_NOT_LOOK: i32 = 1;

#[test]
fn a_coherent_board_exits_0() {
    let dir = repo("graph-coherent");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("board coherent (2 issues)"),
        "{}",
        all(&out)
    );
}

#[test]
fn an_unassigned_in_progress_issue_is_reported() {
    let dir = repo("graph-unassigned");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 in-progress-unassigned"),
        "{}",
        all(&out)
    );
}

#[test]
fn an_assigned_in_progress_issue_is_not() {
    let dir = repo("graph-assigned");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
    assert_eq!(code(&check(&dir, &board)), COHERENT);
}

#[test]
fn an_in_review_issue_with_no_pr_attachment_is_reported() {
    let dir = repo("graph-review-no-pr");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Review", "someone", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 in-review-no-pr"),
        "{}",
        all(&out)
    );
}

#[test]
fn an_in_review_issue_with_a_linked_pr_is_not() {
    let dir = repo("graph-review-pr");
    let mut board = Board::default();
    board.issue(
        "CLOUD-1",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
        &[],
    );
    assert_eq!(code(&check(&dir, &board)), COHERENT);
}

#[test]
fn an_in_review_row_declaring_no_commit_is_exempt_from_in_review_no_pr() {
    let dir = repo("graph-none-exempt");
    let mut board = Board::default();
    board.declares_none("CLOUD-1", "In Review", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("in-review-no-pr"), "{}", all(&out));
}

// THE ANTI-CHEAT: without it `none` is the cheapest way past this gate.
#[test]
fn a_row_declaring_no_commit_that_carries_a_pr_is_refused_for_the_contradiction() {
    let dir = repo("graph-none-with-pr");
    let mut board = Board::default();
    board.declares_none("CLOUD-1", "In Review", "https://github.com/o/r/pull/9");
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 declares-no-commit-with-pr"),
        "{}",
        all(&out)
    );
}

#[test]
fn an_in_review_row_that_declares_nothing_is_still_refused_with_no_pr() {
    let dir = repo("graph-none-silent");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Review", "someone", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 in-review-no-pr"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_declaration_of_no_commit_does_not_change_how_any_other_column_is_judged() {
    let dir = repo("graph-none-todo");
    let mut board = Board::default();
    board.declares_none("CLOUD-1", "Todo", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        !all(&out).contains("declares-no-commit-with-pr"),
        "{}",
        all(&out)
    );
}

// CLOUD-1092's acceptance, finally reaching its consumer (CLOUD-1221): a typed
// row that releases nothing declares `no bump`, and the one grammar emits
// `bump no-release` for it — which is NOT "lands no commit", so a PR beside it
// is no contradiction. The retired program emitted `none` here and refused it.
#[test]
fn a_typed_row_releasing_nothing_is_not_refused_for_carrying_its_pr() {
    let dir = repo("graph-no-release");
    let mut board = Board::default();
    board.issue(
        "CLOUD-1",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
        &[],
    );
    let row = board.row("CLOUD-1");
    let body = row["description"].as_str().unwrap().to_owned();
    row["description"] = serde_json::json!(format!(
        "{body}\n* **Commit / bump (§6).** `test` — **no bump**."
    ));
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        !all(&out).contains("declares-no-commit-with-pr"),
        "{}",
        all(&out)
    );
}

// A COMMIT TYPE NAMED AFTER THE ANSWER IS PROSE, not the declaration. The parity
// run found two live rows (CLOUD-1055, CLOUD-368) whose §6 answers `none` and
// then explains the correction "from `docs`" — the type pattern took that later
// token, emitted `no-release`, and refused both `in-review-no-pr`, which the
// retired program had exempted.
#[test]
fn a_type_named_after_a_none_answer_does_not_make_the_row_land_a_commit() {
    let dir = repo("graph-none-then-prose");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Review", "someone", "", &[]);
    let row = board.row("CLOUD-1");
    let body = row["description"].as_str().unwrap().to_owned();
    row["description"] = serde_json::json!(format!(
        "{body}\n* **Commit / bump (§6).** `none` — **no bump**. No commit lands \
         (corrected from `docs`: a type is a claim about a commit)."
    ));
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("in-review-no-pr"), "{}", all(&out));
}

#[test]
fn a_blockedby_cycle_is_reported_with_its_members() {
    let dir = repo("graph-cycle");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &["CLOUD-2"]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("graph blockedby-cycle (CLOUD-1 CLOUD-2)"),
        "{}",
        all(&out)
    );
}

// CLOUD-678 moved this from a violation to could-not-look, set-keyed.
#[test]
fn a_dangling_blocker_is_reported() {
    let dir = repo("graph-dangling");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &["CLOUD-99"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph dangling-blocker (CLOUD-99)"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("CLOUD-1 dangling-blocker"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_todo_issue_whose_only_blocker_is_done_and_piped_reaches_the_frontier() {
    let dir = repo("graph-done-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn a_blocker_outside_the_piped_set_is_unjudgeable_not_resolved() {
    let dir = repo("graph-unknown-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 excluded (unjudgeable-blocker CLOUD-1)"),
        "{}",
        all(&out)
    );
    assert!(!stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
    assert!(
        !all(&out).contains("CLOUD-2 excluded (blocked-by"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_piped_genuinely_open_blocker_still_excludes_at_exit_0() {
    let dir = repo("graph-open-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("unjudgeable-blocker"), "{}", all(&out));
}

#[test]
fn a_todo_row_whose_only_blocker_is_canceled_reaches_the_frontier() {
    let dir = repo("graph-canceled-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Canceled", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
    assert!(
        !all(&out).contains("CLOUD-2 excluded (blocked-by"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_todo_row_whose_only_blocker_is_duplicate_reaches_the_frontier() {
    let dir = repo("graph-duplicate-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Duplicate", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

// THE GUARD AGAINST A TYPE-ONLY REWRITE: the landed column's type is `started`.
#[test]
fn a_blocker_in_review_still_resolves_since_its_type_is_started() {
    let dir = repo("graph-review-blocker");
    let mut board = Board::default();
    board.issue(
        "CLOUD-1",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/1",
        &[],
    );
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn an_in_progress_blocker_still_excludes_with_its_attribution_unchanged() {
    let dir = repo("graph-progress-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"),
        "{}",
        all(&out)
    );
    assert!(!stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn a_backlog_blocker_still_excludes() {
    let dir = repo("graph-backlog-blocker");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Backlog", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_frontier_row_over_a_retired_blocker_says_so() {
    let dir = repo("graph-retired-note");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Canceled", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 frontier-over-retired-blocker CLOUD-1"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_frontier_row_over_a_completed_blocker_says_nothing_extra() {
    let dir = repo("graph-completed-note");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
    assert!(!all(&out).contains("retired-blocker"), "{}", all(&out));
}

#[test]
fn a_set_with_no_edges_at_all_is_unchanged_by_the_three_way_branch() {
    let dir = repo("graph-no-edges");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
    assert!(!all(&out).contains("unjudgeable-blocker"), "{}", all(&out));
    assert!(!all(&out).contains("dangling-blocker"), "{}", all(&out));
}

#[test]
fn one_row_short_of_its_closure_does_not_withhold_the_rest_of_the_frontier() {
    let dir = repo("graph-short-closure");
    let mut board = Board::default();
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    board.issue("CLOUD-3", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-3"), "{}", all(&out));
    assert!(!stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn the_frontier_is_unblocked_lint_passing_todo_issues() {
    let dir = repo("graph-frontier");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    board.issue("CLOUD-3", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-3"), "{}", all(&out));
}

#[test]
fn a_todo_issue_blocked_by_unfinished_work_is_off_the_frontier() {
    let dir = repo("graph-blocked-off");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn a_blocker_landed_to_in_review_unblocks_its_dependents() {
    let dir = repo("graph-landed-unblocks");
    let mut board = Board::default();
    board.issue(
        "CLOUD-1",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
        &[],
    );
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-2"), "{}", all(&out));
}

#[test]
fn a_todo_issue_with_no_ready_block_is_refused() {
    let dir = repo("graph-todo-unready");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.set("CLOUD-1", "description", serde_json::json!("just prose"));
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 todo-not-ready"),
        "{}",
        all(&out)
    );
    assert!(!stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
}

#[test]
fn a_todo_issue_whose_ready_block_satisfies_the_clauses_is_not() {
    let dir = repo("graph-todo-ready");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
    assert!(!all(&out).contains("todo-not-ready"), "{}", all(&out));
}

#[test]
fn a_backlog_issue_with_no_ready_block_is_not_refused() {
    let dir = repo("graph-backlog-unready");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Backlog", "", "", &[]);
    board.set("CLOUD-1", "description", serde_json::json!("just prose"));
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("todo-not-ready"), "{}", all(&out));
    assert!(all(&out).contains("board coherent"), "{}", all(&out));
}

#[test]
fn wip_counts_in_progress_only() {
    let dir = repo("graph-wip");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "a", "", &[]);
    board.issue(
        "CLOUD-2",
        "In Review",
        "b",
        "https://github.com/o/r/pull/1",
        &[],
    );
    board.issue("CLOUD-3", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(stdout(&out).contains("wip 1"), "{}", all(&out));
}

#[test]
fn output_ordering_is_byte_stable_and_numeric() {
    let dir = repo("graph-ordering");
    let mut board = Board::default();
    board.issue("CLOUD-10", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    let text = stdout(&out);
    let first = text
        .find("frontier CLOUD-2\n")
        .expect("CLOUD-2 is on the frontier");
    let second = text
        .find("frontier CLOUD-10\n")
        .expect("CLOUD-10 is on the frontier");
    assert!(first < second, "{text}");
}

#[test]
fn an_array_input_works_the_same_as_a_stream() {
    let dir = repo("graph-array");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    let array = serde_json::Value::Array(board.rows.clone()).to_string();
    let out = run_with_stdin(&dir, &["ready", "graph"], &array);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
}

#[test]
fn unparseable_stdin_exits_2_not_1() {
    // The shell's `2` is could-not-look, which is the verb's `1`.
    let dir = repo("graph-unparseable");
    let out = run_with_stdin(&dir, &["ready", "graph"], "not json");
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
}

#[test]
fn an_unjudgeable_payload_and_a_failing_ready_block_do_not_produce_the_same_output() {
    let dir = repo("graph-unjudgeable-vs-failing");
    let mut base = Board::default();
    base.issue("CLOUD-1", "Todo", "", "", &[]);
    base.issue("CLOUD-2", "Todo", "", "", &[]);
    let mut unreadable = Board {
        rows: base.rows.clone(),
    };
    unreadable
        .row("CLOUD-2")
        .as_object_mut()
        .unwrap()
        .remove("description");
    let mut failing = Board {
        rows: base.rows.clone(),
    };
    failing.set("CLOUD-2", "description", serde_json::json!("just prose"));
    let unreadable = all(&check(&dir, &unreadable));
    let failing = all(&check(&dir, &failing));
    assert_ne!(unreadable, failing);
    assert!(!unreadable.contains("frontier CLOUD-2"), "{unreadable}");
    assert!(!failing.contains("frontier CLOUD-2"), "{failing}");
}

#[test]
fn a_payload_ready_lint_cannot_read_is_reported_and_exits_2() {
    let dir = repo("graph-unreadable-block");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.drop_key("description");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 excluded (unjudgeable-ready-block)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("board coherent"), "{}", all(&out));
    assert!(!all(&out).contains("todo-not-ready"), "{}", all(&out));
}

#[test]
fn a_genuinely_failing_ready_block_is_attributed_and_refused() {
    let secret = "ACME Corp escalation";
    let dir = repo("graph-failing-block");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.set("CLOUD-1", "description", serde_json::json!(secret));
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 todo-not-ready"),
        "{}",
        all(&out)
    );
    // The grammar's own rule id, forwarded rather than re-derived.
    assert!(
        all(&out).contains("CLOUD-1:0 no-ready-block"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains(secret), "{}", all(&out));
    // One verdict, one summary: the grammar's own is not repeated.
    assert!(!all(&out).contains("not Ready"), "{}", all(&out));
}

#[test]
fn a_todo_issue_held_off_the_frontier_by_a_blocker_says_which_one() {
    let dir = repo("graph-held-off");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_set_carrying_no_blockedby_data_claims_nothing_about_the_graph() {
    let dir = repo("graph-no-relations");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.drop_key("relations");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph unjudgeable-blockedby (CLOUD-1 CLOUD-2)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("board coherent"), "{}", all(&out));
}

#[test]
fn the_missing_blockedby_report_is_keyed_to_the_set_not_to_each_issue() {
    let dir = repo("graph-no-relations-set");
    let mut board = Board::default();
    board.issue(
        "CLOUD-1",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
        &[],
    );
    board.drop_key("relations");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph unjudgeable-blockedby (CLOUD-1)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("CLOUD-1 unjudgeable"), "{}", all(&out));
}

#[test]
fn an_explicit_empty_blockedby_is_data_not_an_unjudgeable_payload() {
    let dir = repo("graph-empty-relations");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("unjudgeable"), "{}", all(&out));
}

#[test]
fn a_payload_it_could_not_read_outranks_a_board_it_could() {
    let dir = repo("graph-outranks");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board
        .row("CLOUD-2")
        .as_object_mut()
        .unwrap()
        .remove("description");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-1 in-progress-unassigned"),
        "{}",
        all(&out)
    );
    assert!(
        all(&out).contains("CLOUD-2 excluded (unjudgeable-ready-block)"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_judgeable_passing_board_emits_no_exclusion_and_no_unjudgeable_report() {
    let dir = repo("graph-anti-vacuity");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("excluded"), "{}", all(&out));
    assert!(!all(&out).contains("unjudgeable"), "{}", all(&out));
    assert!(all(&out).contains("board coherent"), "{}", all(&out));
}

#[test]
fn a_coherent_sets_stdout_bytes_are_unchanged() {
    let dir = repo("graph-stdout-bytes");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert_eq!(
        stdout(&out),
        "wip 0\nfrontier CLOUD-2\ngraph-check: board coherent (2 issues)\n"
    );
}

#[test]
fn violations_are_pointer_only_no_issue_prose_echoed() {
    let secret = "ACME Corp escalation";
    let dir = repo("graph-pointer-only");
    let mut board = Board::default();
    board.issue("CLOUD-1", "In Progress", "", "", &[]);
    board.set("CLOUD-1", "description", serde_json::json!(secret));
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(!all(&out).contains(secret), "{}", all(&out));
}

#[test]
fn a_body_claiming_a_column_the_board_contradicts_is_reported() {
    let dir = repo("graph-claim-contradicted");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
    board.describe(
        "CLOUD-1",
        "Children:\n* CLOUD-2 — **In Progress** (PR #157)",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains(
            "CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"
        ),
        "{}",
        all(&out)
    );
}

#[test]
fn the_same_claim_agreeing_with_the_board_is_clean() {
    let dir = repo("graph-claim-agrees");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.describe("CLOUD-1", "* CLOUD-2 — **Done**");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn a_mention_asserting_no_column_is_not_a_claim() {
    let dir = repo("graph-claim-mention");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.describe(
        "CLOUD-1",
        "Splits the representation CLOUD-2 introduced; see it for the rationale.",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn linears_stored_mention_markup_is_caught_identically_to_the_rendered_form() {
    let dir = repo("graph-claim-markup");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
    board.describe(
        "CLOUD-1",
        "* <issue id=\"x\" href=\"https://linear.app/i/CLOUD-2\">CLOUD-2</issue> — **In Progress**",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains(
            "CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"
        ),
        "{}",
        all(&out)
    );
}

#[test]
fn a_claim_about_an_id_outside_the_piped_set_is_unjudgeable_never_guessed() {
    let dir = repo("graph-claim-outside");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.describe("CLOUD-1", "* CLOUD-99 — **Done**");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains(
            "graph status-claim-unjudgeable (CLOUD-1 claims CLOUD-99, not in the piped set)"
        ),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("CLOUD-1 status-claim-unjudgeable"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_quoted_or_backticked_citation_of_a_claim_is_not_a_claim() {
    let dir = repo("graph-claim-quoted");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
    board.describe(
        "CLOUD-1",
        "The inventory said \"CLOUD-2 — **In Progress** (PR #157)\" after it merged,\nand the same defect in a span reads `CLOUD-2 — In Progress` too.",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn narration_about_an_issue_is_not_a_claim_about_its_column() {
    let dir = repo("graph-claim-narration");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.issue("CLOUD-3", "Done", "", "", &[]);
    board.issue("CLOUD-4", "In Progress", "someone", "", &[]);
    board.describe(
        "CLOUD-1",
        "CLOUD-2 went In Progress at 04:29 and CLOUD-3 still read In Progress.\nCLOUD-2 was Done when this was written, then reopened.",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn a_gloss_with_no_verb_at_all_is_a_claim_in_every_shape_the_corpus_uses() {
    let dir = repo("graph-claim-gloss");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "Done", "", "", &[]);
    board.issue("CLOUD-4", "Done", "", "", &[]);
    board.issue("CLOUD-5", "In Progress", "someone", "", &[]);
    board.describe(
        "CLOUD-1",
        "| CLOUD-2 | In Progress |\nCLOUD-3 is In Progress\nCLOUD-4 (now In Progress)",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    for id in ["CLOUD-2", "CLOUD-3", "CLOUD-4"] {
        assert!(
            all(&out).contains(&format!("{id} claimed In Progress, board says Done")),
            "{}",
            all(&out)
        );
    }
}

#[test]
fn a_set_with_no_descriptions_cannot_be_scanned_for_claims_and_says_so() {
    let dir = repo("graph-no-descriptions");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.drop_key("description");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph unjudgeable-description (CLOUD-1 CLOUD-2)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("board coherent"), "{}", all(&out));
}

#[test]
fn a_set_carrying_only_the_declared_field_set_is_accepted() {
    let dir = repo("graph-declared-fields");
    let board = Board {
        rows: vec![
            serde_json::json!({
                "id": "CLOUD-1", "status": "Todo",
                "attachments": [], "relations": { "blockedBy": [] },
                "description": format!("**Why**\nx.\n\n{READY}"),
                "projectMilestone": { "id": "m-1", "name": "Phase 3" },
            }),
            serde_json::json!({
                "id": "CLOUD-2", "status": "In Progress", "assigneeId": "someone",
                "attachments": [], "relations": { "blockedBy": [] },
                "description": "nothing to claim here",
                "projectMilestone": { "id": "m-1", "name": "Phase 3" },
            }),
        ],
    };
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(all(&out).contains("board coherent"), "{}", all(&out));
    assert!(!all(&out).contains("unjudgeable"), "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
}

#[test]
fn a_status_claim_report_is_pointer_only_no_surrounding_prose_echoed() {
    let secret = "ACME Corp escalation";
    let dir = repo("graph-claim-pointer-only");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
    board.describe("CLOUD-1", &format!("{secret}: CLOUD-2 — **In Progress**"));
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("status-claim-disagrees"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains(secret), "{}", all(&out));
}

// Stated rather than worked around: with no vocabulary to lean on, the gloss
// form of an unspellable column is the same bytes as a capitalised mention.
#[test]
fn a_column_no_piped_issue_occupies_is_not_in_the_vocabulary() {
    let dir = repo("graph-claim-unoccupied-gloss");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.describe("CLOUD-1", "* CLOUD-2 — **In Review**");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
}

#[test]
fn a_claim_naming_a_column_no_piped_issue_occupies_is_refused_not_ignored() {
    let dir = repo("graph-claim-unscannable");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.describe("CLOUD-1", "CLOUD-2 is now Canceled, on a measurement.");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("CLOUD-1 status-claim-unscannable"),
        "{}",
        all(&out)
    );
}

#[test]
fn the_same_claim_over_a_set_that_does_occupy_the_column_is_judged_as_before() {
    let dir = repo("graph-claim-occupied");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "Canceled", "", "", &[]);
    board.describe("CLOUD-1", "CLOUD-2 is now Canceled, on a measurement.");
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out)
            .contains("CLOUD-1 status-claim-disagrees (CLOUD-2 claimed Canceled, board says Done)"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("status-claim-unscannable"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_body_carrying_a_stale_claim_and_its_own_correction_reports_the_stale_one() {
    let dir = repo("graph-claim-correction");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.describe(
        "CLOUD-1",
        "CLOUD-2 is now Canceled, on a measurement.\n\nNote also that CLOUD-2 is Todo, not Canceled.",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("status-claim-disagrees"),
        "{}",
        all(&out)
    );
}

#[test]
fn ordinary_prose_is_not_a_claim_however_capitalized() {
    let dir = repo("graph-claim-prose");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.describe(
        "CLOUD-1",
        "CLOUD-2 Batten's engine, per the note above.\nCLOUD-2 is the durable artifact this campaign rests on.\nSplits the representation CLOUD-2 introduced; see Regorus for the rationale.",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn an_unscannable_report_is_pointer_only_no_surrounding_prose_echoed() {
    let secret = "ACME Corp escalation";
    let dir = repo("graph-unscannable-pointer-only");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.describe("CLOUD-1", &format!("{secret}: CLOUD-2 is now Canceled."));
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("status-claim-unscannable"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains(secret), "{}", all(&out));
}

#[test]
fn a_multi_word_column_is_named_whole_never_its_first_word() {
    let dir = repo("graph-claim-multiword");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.describe("CLOUD-1", "CLOUD-2 is now In Review.");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("claims CLOUD-2 is In Review"),
        "{}",
        all(&out)
    );
}

#[test]
fn anti_vacuity_a_set_with_no_status_claims_anywhere_still_exits_0() {
    let dir = repo("graph-claim-none");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
    assert!(all(&out).contains("board coherent"), "{}", all(&out));
}

#[test]
fn a_coherent_board_records_one_receipt_per_id_it_judged() {
    let dir = repo("graph-receipt-per-id");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Done", "", "", &[]);
    board.issue(
        "CLOUD-2",
        "In Review",
        "",
        "https://github.com/o/r/pull/1",
        &[],
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    let store = receipts(&dir);
    assert!(store.join("board-move.CLOUD-1").is_file());
    assert!(store.join("board-move.CLOUD-2").is_file());
    let body = std::fs::read_to_string(store.join("board-move.CLOUD-1")).unwrap();
    let epoch = body.split_whitespace().next().unwrap_or_default();
    assert!(
        !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()),
        "{body}"
    );
    assert!(!store.join("board-move").exists());
}

#[test]
fn a_value_that_is_not_an_issue_key_mints_nothing_so_it_cannot_become_a_path() {
    let dir = repo("graph-receipt-not-a-key");
    let mut board = Board::default();
    board.issue("notakey", "Done", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    let minted = std::fs::read_dir(receipts(&dir)).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("board-move")
            })
            .count()
    });
    assert_eq!(minted, 0);
}

#[test]
fn a_board_signalling_falsely_records_nothing() {
    let dir = repo("graph-receipt-refused");
    let mut board = Board::default();
    board.issue("CLOUD-3", "In Review", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(!receipts(&dir).join("board-move.CLOUD-3").exists());
}

#[test]
fn a_board_it_could_not_read_records_nothing() {
    let dir = repo("graph-receipt-unread");
    let mut board = Board::default();
    board.issue("CLOUD-4", "Done", "", "", &[]);
    board.drop_key("relations");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(!receipts(&dir).join("board-move.CLOUD-4").exists());
}

#[test]
fn an_earlier_closure_stays_judged_because_each_id_has_its_own_receipt() {
    let dir = repo("graph-receipt-accumulates");
    let mut first = Board::default();
    first.issue("CLOUD-5", "Done", "", "", &[]);
    assert_eq!(code(&check(&dir, &first)), COHERENT);
    let mut second = Board::default();
    second.issue("CLOUD-6", "Done", "", "", &[]);
    assert_eq!(code(&check(&dir, &second)), COHERENT);
    let store = receipts(&dir);
    assert!(store.join("board-move.CLOUD-5").is_file());
    let sixth = std::fs::read_to_string(store.join("board-move.CLOUD-6")).unwrap();
    assert_eq!(sixth.lines().count(), 1, "{sixth}");
}

#[test]
fn the_receipt_is_pointer_only_an_id_and_an_epoch_never_issue_prose() {
    let dir = repo("graph-receipt-pointer-only");
    let mut board = Board::default();
    board.issue("CLOUD-7", "Done", "", "", &[]);
    assert_eq!(code(&check(&dir, &board)), COHERENT);
    let body = std::fs::read_to_string(receipts(&dir).join("board-move.CLOUD-7")).unwrap();
    assert!(!body.contains("Source of truth"), "{body}");
    assert!(!body.contains("Refinement"), "{body}");
}

// FAIL-SOFT, extracted so the premise is created rather than assumed: this
// sandbox runs as root, where permission bits never bite (CLOUD-249), so the
// unwritable store is a FILE standing where the directory would go.
#[test]
fn an_unwritable_receipt_store_does_not_change_the_verdict() {
    let dir = repo("graph-receipt-unwritable");
    std::fs::write(receipts(&dir), "not a directory").unwrap();
    assert!(
        receipts(&dir).is_file(),
        "the premise: the store cannot be a directory"
    );
    let mut board = Board::default();
    board.issue("CLOUD-8", "Done", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
}

#[test]
fn a_todo_issue_carrying_a_milestone_is_clean_and_still_reaches_the_frontier() {
    let dir = repo("graph-milestone-clean");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Done", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("unmilestoned"), "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
}

#[test]
fn a_todo_issue_with_no_milestone_in_a_set_where_others_carry_one_is_refused() {
    let dir = repo("graph-milestone-refused");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone("CLOUD-2", "Todo", "", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 unmilestoned (Todo)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("CLOUD-1 unmilestoned"), "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
    assert!(!all(&out).contains("**Why**"), "{}", all(&out));
}

#[test]
fn a_set_with_the_field_absent_everywhere_is_unjudgeable_not_a_wall_of_violations() {
    let dir = repo("graph-milestone-projected");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.issue("CLOUD-3", "Done", "", "", &[]);
    board.drop_key("projectMilestone");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("graph unjudgeable-milestone (CLOUD-1 CLOUD-2)"),
        "{}",
        all(&out)
    );
    assert!(!all(&out).contains("unmilestoned ("), "{}", all(&out));
    assert!(!all(&out).contains("CLOUD-3"), "{}", all(&out));
}

#[test]
fn an_unparented_in_progress_row_with_no_milestone_is_refused() {
    let dir = repo("graph-milestone-progress");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone("CLOUD-2", "In Progress", "someone", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 unmilestoned (In Progress)"),
        "{}",
        all(&out)
    );
}

#[test]
fn an_unparented_in_review_row_with_no_milestone_is_refused() {
    let dir = repo("graph-milestone-review");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone(
        "CLOUD-2",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 unmilestoned (In Review)"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_started_row_carrying_a_milestone_passes_and_its_frontier_place_is_unchanged() {
    let dir = repo("graph-milestone-started");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "In Progress", "someone", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("unmilestoned"), "{}", all(&out));
    assert!(stdout(&out).contains("frontier CLOUD-1"), "{}", all(&out));
}

#[test]
fn a_parented_row_is_reported_once_by_cloud_599s_clause_and_not_cloud_771s() {
    let dir = repo("graph-milestone-once");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone("CLOUD-2", "In Progress", "someone", "");
    board.set("CLOUD-2", "parentId", serde_json::json!("CLOUD-1"));
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 child-unmilestoned (parent CLOUD-1)"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("CLOUD-2 unmilestoned ("),
        "{}",
        all(&out)
    );
}

#[test]
fn a_done_row_with_no_milestone_is_clean_a_closed_rows_phase_changes_nothing() {
    let dir = repo("graph-milestone-done");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone("CLOUD-2", "Done", "", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("unmilestoned"), "{}", all(&out));
}

#[test]
fn the_anti_vacuity_arm_widened_with_the_clause() {
    let dir = repo("graph-milestone-widened");
    let mut board = Board::default();
    board.no_milestone("CLOUD-1", "In Progress", "someone", "");
    board.no_milestone(
        "CLOUD-2",
        "In Review",
        "someone",
        "https://github.com/o/r/pull/9",
    );
    board.drop_key("projectMilestone");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(all(&out).contains("unjudgeable-milestone"), "{}", all(&out));
    assert!(!all(&out).contains("CLOUD-1 unmilestoned"), "{}", all(&out));
}

/// A child of `parent` carrying no milestone of its own.
fn child_no_milestone(board: &mut Board, child: &str, parent: &str) {
    board.no_milestone(child, "Todo", "someone", "");
    board.set(child, "parentId", serde_json::json!(parent));
}

#[test]
fn a_child_with_no_milestone_under_a_milestoned_parent_is_refused() {
    let dir = repo("graph-child-refused");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    child_no_milestone(&mut board, "CLOUD-2", "CLOUD-1");
    let out = check(&dir, &board);
    assert_eq!(code(&out), VIOLATION, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 child-unmilestoned (parent CLOUD-1)"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_child_carrying_a_different_milestone_is_the_declared_re_phase_and_passes() {
    let dir = repo("graph-child-rephase");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.issue("CLOUD-2", "Todo", "", "", &[]);
    board.set("CLOUD-2", "parentId", serde_json::json!("CLOUD-1"));
    board.set(
        "CLOUD-2",
        "projectMilestone",
        serde_json::json!({ "id": "phase-4", "name": "phase-4" }),
    );
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("child-unmilestoned"), "{}", all(&out));
}

#[test]
fn a_child_whose_parent_carries_no_milestone_is_clean_no_pair_can_diverge() {
    // THE SET MUST BE JUDGEABLE, or this passes for the wrong reason: with no
    // row carrying `projectMilestone` the whole milestone arm abstains as
    // `unjudgeable-milestone` and never looks at the child. CLOUD-3 carries the
    // key so the arm runs; the parent sits in Backlog so it is not itself
    // `unmilestoned`, leaving the pair as the only thing under judgement.
    let dir = repo("graph-child-unphased-parent");
    let mut board = Board::default();
    board.no_milestone("CLOUD-1", "Backlog", "", "");
    child_no_milestone(&mut board, "CLOUD-2", "CLOUD-1");
    board.issue("CLOUD-3", "Backlog", "", "", &[]);
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("child-unmilestoned"), "{}", all(&out));
}

// A SET WHOSE EVERY STATUS IS EMPTY HAS NO COLUMN TO CLAIM. Composed anyway, the
// alphabet is `(?:)` and every key mention reads as a claim of the column "".
#[test]
fn an_empty_status_alphabet_scans_no_claim() {
    let dir = repo("graph-empty-alphabet");
    let mut board = Board::default();
    board.issue("CLOUD-1", "", "", "", &[]);
    board.issue("CLOUD-2", "", "", "", &[]);
    // A key OUTSIDE the set: the empty "claim" of it reads as
    // `status-claim-unjudgeable`, where a key in the set would agree with "".
    board.describe("CLOUD-1", "Follows CLOUD-9 closely.");
    let out = check(&dir, &board);
    assert!(!all(&out).contains("status-claim"), "{}", all(&out));
}

#[test]
fn a_parent_outside_the_piped_set_is_unjudgeable_not_a_violation() {
    let dir = repo("graph-child-parent-outside");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    child_no_milestone(&mut board, "CLOUD-2", "CLOUD-999");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COULD_NOT_LOOK, "{}", all(&out));
    assert!(
        all(&out).contains("CLOUD-2 child-milestone-unjudgeable"),
        "{}",
        all(&out)
    );
    assert!(
        !all(&out).contains("CLOUD-2 child-unmilestoned"),
        "{}",
        all(&out)
    );
}

#[test]
fn a_backlog_issue_with_no_milestone_is_clean_filing_stays_free() {
    let dir = repo("graph-milestone-backlog");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.no_milestone("CLOUD-2", "Backlog", "", "");
    let out = check(&dir, &board);
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(!all(&out).contains("unmilestoned"), "{}", all(&out));
    assert!(
        !all(&out).contains("unjudgeable-milestone"),
        "{}",
        all(&out)
    );
}

// ---------------------------------------------------------------------------
// The grammar is the consumer's, and a sandbox is judged by it (CLOUD-1228).
// ---------------------------------------------------------------------------

/// A bare scratch repository declaring nothing — the sandbox that sank PR #778.
fn bare(name: &str) -> PathBuf {
    Fixture::new(name).git().build()
}

// THE DISCRIMINATING PAIR for `--config-in`. Told where the consumer lives, a
// sandboxed run answers exactly as a run inside the consumer does; untold, it is
// could-not-look rather than a board judged by no grammar. The second is what
// stops the adapter shipping as a silent fallback.
#[test]
fn a_sandbox_told_where_the_consumer_lives_is_judged_by_its_grammar() {
    let consumer = repo("graph-config-in-consumer");
    let sandbox = bare("graph-config-in-sandbox");
    let mut board = Board::default();
    board.issue("CLOUD-1", "Todo", "", "", &[]);
    board.set("CLOUD-1", "description", serde_json::json!("just prose"));
    let told = run_with_stdin(
        &sandbox,
        &["--config-in", consumer.to_str().unwrap(), "ready", "graph"],
        &board.stream(),
    );
    assert_eq!(code(&told), VIOLATION, "{}", all(&told));
    assert!(
        all(&told).contains("CLOUD-1 todo-not-ready"),
        "{}",
        all(&told)
    );
    let untold = check(&sandbox, &board);
    assert_eq!(code(&untold), COULD_NOT_LOOK, "{}", all(&untold));
    assert!(!all(&untold).contains("board coherent"), "{}", all(&untold));
}

// And the receipts land in the SANDBOX's store, the clone whose moves they
// authorise, never in the consumer the grammar came from (CLOUD-512).
#[test]
fn receipts_land_in_the_callers_clone_not_the_consumers() {
    let consumer = repo("graph-receipts-consumer");
    let sandbox = bare("graph-receipts-sandbox");
    let mut board = Board::default();
    board.issue("CLOUD-9", "Done", "", "", &[]);
    let out = run_with_stdin(
        &sandbox,
        &["--config-in", consumer.to_str().unwrap(), "ready", "graph"],
        &board.stream(),
    );
    assert_eq!(code(&out), COHERENT, "{}", all(&out));
    assert!(receipts(&sandbox).join("board-move.CLOUD-9").is_file());
    assert!(!receipts(&consumer).join("board-move.CLOUD-9").exists());
}
