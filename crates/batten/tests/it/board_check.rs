//! `batten board check` over the compiled binary (CLOUD-1221): the board graph,
//! the Ready blocks' citations against the tree, and the tree's clause citations
//! against the payloads — ported off `tests/graph-check.bats`,
//! `tests/ready-cites-check.bats` and `tests/spec-ref-check.bats`, whose
//! programs retired in the same delta: their DECISIONS into the
//! `tracker-hygiene` preset's `board-*` modules, their reading into
//! `crates/batten/src/board_check.rs`, which evaluates that preset in process.
//!
//! **This is the tier that proves the engine builds the reading the modules
//! decide over.** The modules' own `test_` rules pin each predicate over a
//! fabricated reading; only a case here shows the verb writes the lines those
//! predicates parse, so every `#MUTANT` row in a `board-*` module names a case
//! in this file, beside the rows `board_check.rs` keeps for its reading.
//!
//! **One suite, three inner modules, because `batten mutate` reads the FIRST
//! `MUTANT-SUITE` line of a source**. The modules are named for the gates they
//! carry, so a filter of `graph_check`, `ready_cites` or `spec_ref` selects one
//! gate's cases.
//!
//! # THE EXIT CODES MOVED, UNIFORMLY, AND IT IS ONE DECISION
//!
//! The shell programs answered `1` for a refusal and `2` for could-not-look. The
//! verb answers the crate's one table: `2` is the policy verdict everywhere and
//! `3` is could-not-look. The PREDICATE is identical in every carried case — the
//! same boards are refused, the same gaps are gaps — so they are CARRIED, and the
//! one numeric mapping is stated here once rather than eighty times.
//!
//! # THE VOCABULARY IS THE COMMITTED ONE
//!
//! Every fixture reads this repository's own `[board]` table and `[[pattern]]`
//! rows through `common::declared_board` and `common::declared_patterns`, so a
//! column renamed or a row dropped in `batten.toml` is a red case here rather than
//! a fixture quietly carrying the old words. The config lives in a directory of
//! its own, reached through `--config-in`, so the tracked tree the citation gates
//! scan is the fixture's alone.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/graph-check.sh crates/batten/src/policy/presets/tracker-hygiene/board-columns-tell-the-truth.rego crates/batten/tests/it/board_check.rs
// carried: tests/graph-check.bats crates/batten/src/policy/presets/tracker-hygiene/board-frontier-is-ready.rego crates/batten/tests/it/board_check.rs
// carried: mise-tasks/ready-cites-check.sh crates/batten/src/policy/presets/tracker-hygiene/board-citations-resolve.rego crates/batten/tests/it/board_check.rs
// carried: tests/ready-cites-check.bats crates/batten/src/policy/presets/tracker-hygiene/board-citations-resolve.rego crates/batten/tests/it/board_check.rs
// carried: mise-tasks/spec-ref-check.sh crates/batten/src/policy/presets/tracker-hygiene/board-citations-resolve.rego crates/batten/tests/it/board_check.rs
// carried: tests/spec-ref-check.bats crates/batten/src/policy/presets/tracker-hygiene/board-citations-resolve.rego crates/batten/tests/it/board_check.rs
//!
//! # RETIREMENT LEDGER — `tests/graph-check.bats`
//!
// carried: "a coherent board exits 0" crates/batten/tests/it/board_check.rs
// carried: "an unassigned In Progress issue is reported" crates/batten/tests/it/board_check.rs
// carried: "an assigned In Progress issue is not" crates/batten/tests/it/board_check.rs
// carried: "an In Review issue with no PR attachment is reported" crates/batten/tests/it/board_check.rs
// carried: "an In Review issue with a linked PR is not" crates/batten/tests/it/board_check.rs
// carried: "AN IN REVIEW ROW DECLARING NO COMMIT IS EXEMPT FROM in-review-no-pr" crates/batten/tests/it/board_check.rs
// carried: "a row declaring no commit that carries a PR is refused for the contradiction" crates/batten/tests/it/board_check.rs
// carried: "an In Review row that declares nothing is still refused with no PR" crates/batten/tests/it/board_check.rs
// carried: "a declaration of no commit does not change how any other column is judged" crates/batten/tests/it/board_check.rs
// changed: "a blockedBy cycle is reported with its members" crates/batten/tests/it/board_check.rs every member of every cycle is named in numeric order, where `tsort` named the loop it happened to break first in lexical order
// carried: "a dangling blocker is reported" crates/batten/tests/it/board_check.rs
// changed: "the jq count does not grow with the edge count" crates/batten/tests/it/board_check.rs one process indexes the set once and forks nothing, so the bound is structural and the case asserts the verdict over the many-edge fixture instead
// changed: "the grep count does not grow with the edge count" crates/batten/tests/it/board_check.rs one process indexes the set once and forks nothing, so the bound is structural and the case asserts the verdict over the many-edge fixture instead
// carried: "a Todo issue whose only blocker is Done and piped reaches the frontier" crates/batten/tests/it/board_check.rs
// carried: "a blocker outside the piped set is unjudgeable, not resolved" crates/batten/tests/it/board_check.rs
// carried: "a piped, genuinely open blocker still excludes at exit 0" crates/batten/tests/it/board_check.rs
// carried: "a Todo row whose only blocker is Canceled reaches the frontier" crates/batten/tests/it/board_check.rs
// carried: "a Todo row whose only blocker is Duplicate reaches the frontier" crates/batten/tests/it/board_check.rs
// carried: "a blocker In Review still resolves, since its type is started" crates/batten/tests/it/board_check.rs
// carried: "an In Progress blocker still excludes, with its attribution unchanged" crates/batten/tests/it/board_check.rs
// carried: "a Backlog blocker still excludes" crates/batten/tests/it/board_check.rs
// carried: "a frontier row over a retired blocker says so" crates/batten/tests/it/board_check.rs
// carried: "a frontier row over a COMPLETED blocker says nothing extra" crates/batten/tests/it/board_check.rs
// carried: "a set with no edges at all is unchanged by the three-way branch" crates/batten/tests/it/board_check.rs
// carried: "one row short of its closure does not withhold the rest of the frontier" crates/batten/tests/it/board_check.rs
// carried: "the frontier is unblocked lint-passing Todo issues" crates/batten/tests/it/board_check.rs
// carried: "a Todo issue blocked by unfinished work is off the frontier" crates/batten/tests/it/board_check.rs
// carried: "a blocker landed to In Review unblocks its dependents" crates/batten/tests/it/board_check.rs
// carried: "a Todo issue with no Ready block is refused" crates/batten/tests/it/board_check.rs
// carried: "a Todo issue whose Ready block satisfies the clauses is not" crates/batten/tests/it/board_check.rs
// carried: "a Backlog issue with no Ready block is not refused" crates/batten/tests/it/board_check.rs
// carried: "wip counts In Progress only" crates/batten/tests/it/board_check.rs
// carried: "output ordering is byte-stable and numeric" crates/batten/tests/it/board_check.rs
// carried: "an array input works the same as a stream" crates/batten/tests/it/board_check.rs
// carried: "unparseable stdin exits 2, not 1" crates/batten/tests/it/board_check.rs
// carried: "an unjudgeable payload and a failing Ready block do not produce the same output" crates/batten/tests/it/board_check.rs
// carried: "a payload ready-lint cannot read is reported and exits 2" crates/batten/tests/it/board_check.rs
// changed: "a genuinely failing Ready block is attributed and refused" crates/batten/tests/it/board_check.rs the refinement gate is asked in process, so there is no child `::error::` summary left to drop and the case asserts the forwarded rule id alone
// carried: "a Todo issue held off the frontier by a blocker says which one" crates/batten/tests/it/board_check.rs
// carried: "a set carrying no blockedBy data claims nothing about the graph" crates/batten/tests/it/board_check.rs
// carried: "the missing-blockedBy report is keyed to the set, not to each issue" crates/batten/tests/it/board_check.rs
// carried: "an explicit empty blockedBy is data, not an unjudgeable payload" crates/batten/tests/it/board_check.rs
// carried: "a payload it could not read outranks a board it could" crates/batten/tests/it/board_check.rs
// carried: "a judgeable, passing board emits no exclusion and no unjudgeable report" crates/batten/tests/it/board_check.rs
// changed: "a coherent set's stdout bytes are unchanged" crates/batten/tests/it/board_check.rs the closing line names the verb that produced it, `board check:` where it was `graph-check:`
// carried: "violations are pointer-only — no issue prose echoed" crates/batten/tests/it/board_check.rs
// carried: "a body claiming a column the board contradicts is reported" crates/batten/tests/it/board_check.rs
// carried: "the same claim, agreeing with the board, is clean" crates/batten/tests/it/board_check.rs
// carried: "a mention asserting no column is not a claim" crates/batten/tests/it/board_check.rs
// carried: "Linear's stored mention markup is caught identically to the rendered form" crates/batten/tests/it/board_check.rs
// carried: "a claim about an id outside the piped set is unjudgeable, never guessed" crates/batten/tests/it/board_check.rs
// carried: "a quoted or backticked citation of a claim is not a claim" crates/batten/tests/it/board_check.rs
// carried: "narration about an issue is not a claim about its column" crates/batten/tests/it/board_check.rs
// carried: "a gloss with no verb at all is a claim, in every shape the corpus uses" crates/batten/tests/it/board_check.rs
// carried: "a set with no descriptions cannot be scanned for claims, and says so" crates/batten/tests/it/board_check.rs
// carried: "a set carrying only the declared field set is accepted" crates/batten/tests/it/board_check.rs
// carried: "a status claim report is pointer-only — no surrounding prose echoed" crates/batten/tests/it/board_check.rs
// carried: "a column no piped issue occupies is not in the vocabulary" crates/batten/tests/it/board_check.rs
// carried: "a claim naming a column no piped issue occupies is refused, not ignored" crates/batten/tests/it/board_check.rs
// carried: "the same claim, over a set that DOES occupy the column, is judged as before" crates/batten/tests/it/board_check.rs
// carried: "a body carrying a stale claim AND its own correction reports the stale one" crates/batten/tests/it/board_check.rs
// carried: "ordinary prose is not a claim, however capitalized" crates/batten/tests/it/board_check.rs
// carried: "an unscannable report is pointer-only — no surrounding prose echoed" crates/batten/tests/it/board_check.rs
// carried: "a multi-word column is named whole, never its first word" crates/batten/tests/it/board_check.rs
// carried: "ANTI-VACUITY: a set with no status claims anywhere still exits 0" crates/batten/tests/it/board_check.rs
// carried: "a coherent board records one receipt per id it judged" crates/batten/tests/it/board_check.rs
// carried: "a value that is not an issue key mints nothing, so it cannot become a path" crates/batten/tests/it/board_check.rs
// carried: "a board signalling falsely records nothing" crates/batten/tests/it/board_check.rs
// carried: "a board it could not read records nothing" crates/batten/tests/it/board_check.rs
// carried: "an earlier closure stays judged, because each id has its own receipt" crates/batten/tests/it/board_check.rs
// carried: "the receipt is pointer-only — an id and an epoch, never issue prose" crates/batten/tests/it/board_check.rs
// changed: "an unwritable receipt store does not change the verdict" crates/batten/tests/it/board_check.rs the store is made unwritable by a FILE where its directory belongs, because permission bits never bite a root sandbox and the case must be shown able to fail
// carried: "a Todo issue carrying a milestone is clean, and still reaches the frontier" crates/batten/tests/it/board_check.rs
// carried: "a Todo issue with no milestone, in a set where others carry one, is refused" crates/batten/tests/it/board_check.rs
// carried: "a set with the field absent everywhere is unjudgeable, not a wall of violations" crates/batten/tests/it/board_check.rs
// carried: "an unparented In Progress row with no milestone is refused" crates/batten/tests/it/board_check.rs
// carried: "an unparented In Review row with no milestone is refused" crates/batten/tests/it/board_check.rs
// carried: "a started row carrying a milestone passes, and its frontier place is unchanged" crates/batten/tests/it/board_check.rs
// carried: "a parented row is reported ONCE, by CLOUD-599's clause and not CLOUD-771's" crates/batten/tests/it/board_check.rs
// carried: "a Done row with no milestone is clean — a closed row's phase changes nothing" crates/batten/tests/it/board_check.rs
// carried: "the anti-vacuity arm widened with the clause" crates/batten/tests/it/board_check.rs
// carried: "a child with no milestone under a milestoned parent is refused" crates/batten/tests/it/board_check.rs
// carried: "a child carrying a DIFFERENT milestone is the declared re-phase and passes" crates/batten/tests/it/board_check.rs
// carried: "a child whose parent carries no milestone is clean — no pair can diverge" crates/batten/tests/it/board_check.rs
// carried: "a parent outside the piped set is unjudgeable, not a violation" crates/batten/tests/it/board_check.rs
// carried: "a Backlog issue with no milestone is clean — filing stays free" crates/batten/tests/it/board_check.rs
//!
//! # RETIREMENT LEDGER — `tests/ready-cites-check.bats`
//!
// carried: "CLOUD-740's superseded §7 names two tests the tree does not carry" crates/batten/tests/it/board_check.rs
// carried: "a citation resolving only under tests/fixtures is refused" crates/batten/tests/it/board_check.rs
// carried: "a body with a superseded block and a live one is judged on the live one" crates/batten/tests/it/board_check.rs
// carried: "a citation that resolves only in a fixture and nowhere else is refused" crates/batten/tests/it/board_check.rs
// carried: "the last opener is the live block and an earlier one is history" crates/batten/tests/it/board_check.rs
// carried: "a §7 citing a test that exists passes" crates/batten/tests/it/board_check.rs
// carried: "a §7 citing no candidate passes and reports zero resolved" crates/batten/tests/it/board_check.rs
// carried: "a one-underscore API name is not a citation" crates/batten/tests/it/board_check.rs
// carried: "a cited path that does not exist is refused" crates/batten/tests/it/board_check.rs
// carried: "a §7 citation the block marks (new) is prospective, not fatal" crates/batten/tests/it/board_check.rs
// carried: "an unmarked absent path is still refused" crates/batten/tests/it/board_check.rs
// carried: "the two absent cases are distinguishable in output" crates/batten/tests/it/board_check.rs
// carried: "a marker on a deleted path is refused, not believed" crates/batten/tests/it/board_check.rs
// carried: "a (new) marker elsewhere in the block does not excuse an unrelated citation" crates/batten/tests/it/board_check.rs
// carried: "a cited path that exists passes" crates/batten/tests/it/board_check.rs
// carried: "a test name cited outside §7 is not judged" crates/batten/tests/it/board_check.rs
// changed: "the report carries no line of the block and no line of a source file" crates/batten/tests/it/board_check.rs the pointer names the key, the token and the rule, no longer a clause number the engine would have had to hard-code
// carried: "the report is byte-stable across runs" crates/batten/tests/it/board_check.rs
// carried: "empty stdin is exit 2, never a verdict" crates/batten/tests/it/board_check.rs
// carried: "stdin that is not a payload is exit 2" crates/batten/tests/it/board_check.rs
// carried: "a root that is not a repository is exit 2, never a pass" crates/batten/tests/it/board_check.rs
// carried: "a body with no Ready block is not this gate's business" crates/batten/tests/it/board_check.rs
//!
//! # RETIREMENT LEDGER — `tests/spec-ref-check.bats`
//!
// carried: "a citation naming a clause the issue does not carry is reported with its pointer" crates/batten/tests/it/board_check.rs
// carried: "a citation naming a clause the issue does carry passes" crates/batten/tests/it/board_check.rs
// carried: "a sub-numbered citation resolves to its parent clause" crates/batten/tests/it/board_check.rs
// carried: "the possessive form is read as a citation" crates/batten/tests/it/board_check.rs
// carried: "a clause label naming two numbers declares both" crates/batten/tests/it/board_check.rs
// carried: "a cited issue absent from the payload set is exit 2, never a silent pass" crates/batten/tests/it/board_check.rs
// carried: "a proven finding outranks an unfetched issue" crates/batten/tests/it/board_check.rs
// carried: "empty stdin is exit 2" crates/batten/tests/it/board_check.rs
// carried: "stdin that is not a get_issue payload set is exit 2" crates/batten/tests/it/board_check.rs
// carried: "a tree with no citations at all passes" crates/batten/tests/it/board_check.rs
// carried: "the emitted bytes carry no substring of any issue body" crates/batten/tests/it/board_check.rs
// changed: "the gate does not report its own header or suite" crates/batten/tests/it/board_check.rs the gate is compiled and its suite spells no citation whole, so the exclusion is a declared `[board] refs_exclude` glob and the case asserts that a file carrying a known-bad witness is skipped when excluded

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{declared_board, declared_patterns, run_with_stdin, stderr, stdout};

/// A directory holding only the committed vocabulary, reached by `--config-in`.
fn vocabulary(name: &str, extra: &str) -> PathBuf {
    let dir = common::scratch(&format!("board-check-config-{name}"));
    common::write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n{}\n{extra}\n{}",
            declared_board(),
            declared_patterns()
        ),
    );
    dir
}

/// `batten --config-in <config> board check <args>` in `dir`, `input` on stdin.
fn board_check(dir: &Path, config: &Path, args: &[&str], input: &str) -> Output {
    let config = config.display().to_string();
    let mut command = vec!["--config-in", config.as_str(), "board", "check"];
    command.extend_from_slice(args);
    run_with_stdin(dir, &command, input)
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

/// Both channels, for the substring assertions the suites made over `$output`.
fn text(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

/// The key a fixture names, spelled from parts where a case needs a citation
/// that must not appear whole in this tracked file.
fn key(n: u32) -> String {
    format!("{}-{n}", "CL".to_owned() + "OUD")
}

mod graph_check {
    use super::{board_check, code, text, vocabulary};
    use crate::common;
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use std::process::Output;

    /// ONE PASSING READY BLOCK, shared by every row: a Todo row whose block fails
    /// the refinement gate is a violation, so a fixture body is never neutral.
    const READY: &str = "**Refinement — Ready (t)**\n\n* **Source of truth (§1).** One artifact.";

    /// A throwaway repository — the gate mints the board-move receipt, and a
    /// suite run here must not write adjudications into the real store — with a
    /// workspace version for the §6 arrows.
    fn repo(name: &str) -> (PathBuf, PathBuf) {
        let dir = common::Fixture::new(&format!("board-check-graph-{name}"))
            .file("Cargo.toml", "[workspace.package]\nversion = \"0.0.125\"\n")
            .git()
            .base_commit()
            .build();
        (dir, vocabulary(&format!("graph-{name}"), ""))
    }

    /// `statusType` is derived from the column, as the live board carries both —
    /// and `Canceled` is `canceled` while `Duplicate` is `duplicate`.
    fn status_type(status: &str) -> Option<&'static str> {
        match status {
            "Todo" => Some("unstarted"),
            "Backlog" => Some("backlog"),
            "In Progress" | "In Review" => Some("started"),
            "Done" => Some("completed"),
            "Canceled" => Some("canceled"),
            "Duplicate" => Some("duplicate"),
            _ => None,
        }
    }

    /// A payload set, built the way the suite's `issue` helper built one.
    #[derive(Default)]
    struct Board {
        rows: Vec<Value>,
    }

    impl Board {
        /// `issue <id> <status> [assignee] [pr-url] [blocker...]`.
        fn issue(&mut self, id: &str, status: &str, assignee: &str, pr: &str, blockers: &[&str]) {
            let attachments = if pr.is_empty() {
                json!([])
            } else {
                json!([{ "url": pr }])
            };
            let mut row = json!({
                "id": id,
                "status": status,
                "attachments": attachments,
                "relations": {
                    "blockedBy": blockers.iter().map(|b| json!({ "id": b })).collect::<Vec<_>>(),
                },
                "description": format!("**Why**\nx.\n\n{READY}"),
                "projectMilestone": { "id": "m-1", "name": "Phase 3" },
            });
            if !assignee.is_empty() {
                row["assigneeId"] = json!(assignee);
            }
            if let Some(kind) = status_type(status) {
                row["statusType"] = json!(kind);
            }
            self.rows.push(row);
        }

        /// The same payload with `projectMilestone` omitted — how the tracker
        /// renders a row with none, dropping the key rather than nulling it.
        fn no_milestone(&mut self, id: &str, status: &str, assignee: &str, pr: &str) {
            self.issue(id, status, assignee, pr, &[]);
            self.row(id)
                .as_object_mut()
                .expect("an object")
                .remove("projectMilestone");
        }

        fn row(&mut self, id: &str) -> &mut Value {
            self.rows
                .iter_mut()
                .find(|row| row["id"] == id)
                .expect("the row was added")
        }

        /// Give one row a body to be judged on, the Ready block riding along.
        fn describe(&mut self, id: &str, prose: &str) {
            self.row(id)["description"] = json!(format!("{prose}\n\n{READY}"));
        }

        /// Drop a key from every payload — the projection a caller makes.
        fn drop_key(&mut self, key: &str) {
            for row in &mut self.rows {
                row.as_object_mut().expect("an object").remove(key);
            }
        }

        /// The set as a concatenated stream, one object per line.
        fn stream(&self) -> String {
            self.rows
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        }

        /// A row declaring in its §6 that it lands no commit.
        fn declares_none(&mut self, id: &str, status: &str, pr: &str) {
            self.issue(id, status, "someone", pr, &[]);
            let row = self.row(id);
            let body = row["description"].as_str().unwrap_or_default().to_owned();
            row["description"] = json!(format!(
                "{body}\n* **Commit / bump (§6).** **none** — this row lands no commit."
            ));
        }
    }

    fn check(dir: &Path, config: &Path, board: &Board) -> Output {
        board_check(dir, config, &[], &board.stream())
    }

    fn receipt(dir: &Path, id: &str) -> PathBuf {
        dir.join(".git/batten-receipts")
            .join(format!("board-move.{id}"))
    }

    #[test]
    fn a_coherent_board_exits_0() {
        let (dir, config) = repo("coherent");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("board coherent (2 issues)"));
    }

    #[test]
    fn an_unassigned_in_progress_issue_is_reported() {
        let (dir, config) = repo("unassigned");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 in-progress-unassigned"));
    }

    #[test]
    fn an_assigned_in_progress_issue_is_not() {
        let (dir, config) = repo("assigned");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn an_in_review_issue_with_no_pr_attachment_is_reported() {
        let (dir, config) = repo("no-pr");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Review", "someone", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 in-review-no-pr"));
    }

    #[test]
    fn an_in_review_issue_with_a_linked_pr_is_not() {
        let (dir, config) = repo("pr");
        let mut board = Board::default();
        board.issue(
            "CLOUD-1",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/9",
            &[],
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn an_in_review_row_declaring_no_commit_is_exempt_from_in_review_no_pr() {
        let (dir, config) = repo("none-exempt");
        let mut board = Board::default();
        board.declares_none("CLOUD-1", "In Review", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("in-review-no-pr"));
    }

    #[test]
    fn a_row_declaring_no_commit_that_carries_a_pr_is_refused_for_the_contradiction() {
        // THE ANTI-CHEAT: without it `none` is the cheapest way past this gate.
        let (dir, config) = repo("none-with-pr");
        let mut board = Board::default();
        board.declares_none("CLOUD-1", "In Review", "https://github.com/o/r/pull/9");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 declares-no-commit-with-pr"));
    }

    #[test]
    fn an_in_review_row_that_declares_nothing_is_still_refused_with_no_pr() {
        let (dir, config) = repo("declares-nothing");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Review", "someone", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 in-review-no-pr"));
    }

    #[test]
    fn a_declaration_of_no_commit_does_not_change_how_any_other_column_is_judged() {
        let (dir, config) = repo("none-todo");
        let mut board = Board::default();
        board.declares_none("CLOUD-1", "Todo", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("declares-no-commit-with-pr"));
    }

    #[test]
    fn a_blocked_by_cycle_is_reported_with_its_members() {
        let (dir, config) = repo("cycle");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &["CLOUD-2"]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(
            text(&output).contains("graph blockedby-cycle (CLOUD-1 CLOUD-2)"),
            "{}",
            text(&output)
        );
    }

    #[test]
    fn a_dangling_blocker_is_reported() {
        // A blocker outside the piped closure is a question the closure cannot
        // answer (CLOUD-678), keyed to the set.
        let (dir, config) = repo("dangling");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &["CLOUD-99"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("graph dangling-blocker (CLOUD-99)"));
        assert!(!text(&output).contains("CLOUD-1 dangling-blocker"));
    }

    #[test]
    fn many_edges_over_one_indexed_set_are_judged_as_few() {
        // The two fork-count cases bound a shell's per-edge rescans; one process
        // indexes once and forks nothing, so what is left to assert is that the
        // verdict over the many-edge fixture is the few-edge one.
        let (dir, config) = repo("edges");
        let mut few = Board::default();
        few.issue("CLOUD-1", "Done", "", "", &[]);
        few.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        few.issue("CLOUD-3", "Todo", "", "", &[]);
        few.issue("CLOUD-4", "Todo", "", "", &[]);
        let mut many = Board::default();
        many.issue("CLOUD-1", "Done", "", "", &[]);
        many.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        many.issue("CLOUD-3", "Todo", "", "", &["CLOUD-1", "CLOUD-2"]);
        many.issue(
            "CLOUD-4",
            "Todo",
            "",
            "",
            &["CLOUD-1", "CLOUD-2", "CLOUD-3"],
        );
        let (sparse, dense) = (check(&dir, &config, &few), check(&dir, &config, &many));
        assert_eq!(code(&sparse), 0, "{}", text(&sparse));
        assert_eq!(code(&dense), 0, "{}", text(&dense));
        assert!(common::stdout(&dense).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_todo_issue_whose_only_blocker_is_done_and_piped_reaches_the_frontier() {
        let (dir, config) = repo("done-blocker");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_blocker_outside_the_piped_set_is_unjudgeable_not_resolved() {
        let (dir, config) = repo("outside");
        let mut board = Board::default();
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("CLOUD-2 excluded (unjudgeable-blocker CLOUD-1)"),
            "{all}"
        );
        assert!(!all.contains("frontier CLOUD-2"), "{all}");
        assert!(!all.contains("CLOUD-2 excluded (blocked-by"), "{all}");
    }

    #[test]
    fn a_piped_genuinely_open_blocker_still_excludes_at_exit_0() {
        let (dir, config) = repo("open-blocker");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"));
        assert!(!text(&output).contains("unjudgeable-blocker"));
    }

    #[test]
    fn a_todo_row_whose_only_blocker_is_canceled_reaches_the_frontier() {
        let (dir, config) = repo("canceled");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Canceled", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
        assert!(!text(&output).contains("CLOUD-2 excluded (blocked-by"));
    }

    #[test]
    fn a_todo_row_whose_only_blocker_is_duplicate_reaches_the_frontier() {
        // `Duplicate` is its own type, not a shared canceled one: a rule keyed on
        // one of them alone fixes half the defect.
        let (dir, config) = repo("duplicate");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Duplicate", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_blocker_in_review_still_resolves_since_its_type_is_started() {
        // THE GUARD AGAINST A TYPE-ONLY REWRITE: `In Review` shares `started` with
        // `In Progress`, so the name arm has to stay.
        let (dir, config) = repo("review-blocker");
        let mut board = Board::default();
        board.issue(
            "CLOUD-1",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/1",
            &[],
        );
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn an_in_progress_blocker_still_excludes_with_its_attribution_unchanged() {
        let (dir, config) = repo("progress-blocker");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"));
        assert!(!text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_backlog_blocker_still_excludes() {
        let (dir, config) = repo("backlog-blocker");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Backlog", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"));
    }

    #[test]
    fn a_frontier_row_over_a_retired_blocker_says_so() {
        let (dir, config) = repo("retired");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Canceled", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 frontier-over-retired-blocker CLOUD-1"));
    }

    #[test]
    fn a_frontier_row_over_a_completed_blocker_says_nothing_extra() {
        let (dir, config) = repo("completed");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
        assert!(!text(&output).contains("retired-blocker"));
    }

    #[test]
    fn a_set_with_no_edges_at_all_is_unchanged_by_the_three_way_branch() {
        let (dir, config) = repo("no-edges");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-1"));
        assert!(!text(&output).contains("unjudgeable-blocker"));
        assert!(!text(&output).contains("dangling-blocker"));
    }

    #[test]
    fn one_row_short_of_its_closure_does_not_withhold_the_rest_of_the_frontier() {
        let (dir, config) = repo("short");
        let mut board = Board::default();
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        board.issue("CLOUD-3", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-3"));
        assert!(!text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn the_frontier_is_unblocked_lint_passing_todo_issues() {
        let (dir, config) = repo("frontier");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        board.issue("CLOUD-3", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
        assert!(text(&output).contains("frontier CLOUD-3"));
    }

    #[test]
    fn a_todo_issue_blocked_by_unfinished_work_is_off_the_frontier() {
        let (dir, config) = repo("unfinished");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_blocker_landed_to_in_review_unblocks_its_dependents() {
        let (dir, config) = repo("landed");
        let mut board = Board::default();
        board.issue(
            "CLOUD-1",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/9",
            &[],
        );
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_todo_issue_with_no_ready_block_is_refused() {
        let (dir, config) = repo("no-block");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.row("CLOUD-1")["description"] = json!("just prose");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 todo-not-ready"));
        assert!(!text(&output).contains("frontier CLOUD-1"));
    }

    #[test]
    fn a_todo_issue_whose_ready_block_satisfies_the_clauses_is_not() {
        let (dir, config) = repo("ready");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("frontier CLOUD-1"));
        assert!(!text(&output).contains("todo-not-ready"));
    }

    #[test]
    fn a_backlog_issue_with_no_ready_block_is_not_refused() {
        let (dir, config) = repo("backlog");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Backlog", "", "", &[]);
        board.row("CLOUD-1")["description"] = json!("just prose");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("todo-not-ready"));
        assert!(text(&output).contains("board coherent"));
    }

    #[test]
    fn wip_counts_in_progress_only() {
        let (dir, config) = repo("wip");
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
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(common::stdout(&output).contains("wip 1"));
    }

    #[test]
    fn output_ordering_is_byte_stable_and_numeric() {
        let (dir, config) = repo("ordering");
        let mut board = Board::default();
        board.issue("CLOUD-10", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        let out = common::stdout(&output);
        let first = out
            .find("frontier CLOUD-2\n")
            .expect("CLOUD-2 is on the frontier");
        let second = out
            .find("frontier CLOUD-10\n")
            .expect("CLOUD-10 is on the frontier");
        assert!(first < second, "{out}");
    }

    #[test]
    fn an_array_input_works_the_same_as_a_stream() {
        let (dir, config) = repo("array");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        let array = Value::Array(board.rows.clone()).to_string();
        let output = board_check(&dir, &config, &[], &array);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn unparseable_stdin_is_could_not_look_not_a_verdict() {
        let (dir, config) = repo("unparseable");
        let output = board_check(&dir, &config, &[], "not json");
        assert_eq!(code(&output), 3, "{}", text(&output));
    }

    #[test]
    fn an_unjudgeable_payload_and_a_failing_ready_block_do_not_produce_the_same_output() {
        let (dir, config) = repo("two-answers");
        let mut unreadable = Board::default();
        unreadable.issue("CLOUD-1", "Todo", "", "", &[]);
        unreadable.issue("CLOUD-2", "Todo", "", "", &[]);
        let mut failing = Board::default();
        failing.rows.clone_from(&unreadable.rows);
        unreadable
            .row("CLOUD-2")
            .as_object_mut()
            .expect("an object")
            .remove("description");
        failing.row("CLOUD-2")["description"] = json!("just prose");
        let (gap, refusal) = (
            check(&dir, &config, &unreadable),
            check(&dir, &config, &failing),
        );
        assert_ne!(text(&gap), text(&refusal));
        assert!(!text(&gap).contains("frontier CLOUD-2"));
        assert!(!text(&refusal).contains("frontier CLOUD-2"));
    }

    #[test]
    fn a_payload_the_ready_gate_cannot_read_is_reported_and_could_not_look() {
        let (dir, config) = repo("unreadable");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.drop_key("description");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("CLOUD-1 excluded (unjudgeable-ready-block)"),
            "{all}"
        );
        assert!(!all.contains("board coherent"), "{all}");
        assert!(!all.contains("todo-not-ready"), "{all}");
    }

    #[test]
    fn a_genuinely_failing_ready_block_is_attributed_and_refused() {
        let secret = "ACME Corp escalation";
        let (dir, config) = repo("failing");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.row("CLOUD-1")["description"] = json!(secret);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(all.contains("CLOUD-1 todo-not-ready"), "{all}");
        // The refinement gate's own rule id, forwarded rather than re-derived.
        assert!(all.contains("CLOUD-1:0 no-ready-block"), "{all}");
        assert!(!all.contains(secret), "{all}");
    }

    #[test]
    fn a_todo_issue_held_off_the_frontier_by_a_blocker_says_which_one() {
        let (dir, config) = repo("says-which");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "someone", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 excluded (blocked-by CLOUD-1)"));
    }

    #[test]
    fn a_set_carrying_no_blocked_by_data_claims_nothing_about_the_graph() {
        let (dir, config) = repo("no-relations");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.drop_key("relations");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("graph unjudgeable-blockedby (CLOUD-1 CLOUD-2)"));
        assert!(!text(&output).contains("board coherent"));
    }

    #[test]
    fn the_missing_blocked_by_report_is_keyed_to_the_set_not_to_each_issue() {
        let (dir, config) = repo("set-keyed");
        let mut board = Board::default();
        board.issue(
            "CLOUD-1",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/9",
            &[],
        );
        board.drop_key("relations");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("graph unjudgeable-blockedby (CLOUD-1)"));
        assert!(!text(&output).contains("CLOUD-1 unjudgeable"));
    }

    #[test]
    fn an_explicit_empty_blocked_by_is_data_not_an_unjudgeable_payload() {
        let (dir, config) = repo("empty-edges");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("unjudgeable"));
    }

    #[test]
    fn a_payload_it_could_not_read_outranks_a_board_it_could() {
        let (dir, config) = repo("outranks");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board
            .row("CLOUD-2")
            .as_object_mut()
            .expect("an object")
            .remove("description");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-1 in-progress-unassigned"));
        assert!(text(&output).contains("CLOUD-2 excluded (unjudgeable-ready-block)"));
    }

    #[test]
    fn a_judgeable_passing_board_emits_no_exclusion_and_no_unjudgeable_report() {
        let (dir, config) = repo("clean");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &["CLOUD-1"]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("excluded"));
        assert!(!text(&output).contains("unjudgeable"));
        assert!(text(&output).contains("board coherent"));
    }

    #[test]
    fn a_coherent_sets_stdout_bytes_are_stable() {
        let (dir, config) = repo("stdout");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert_eq!(
            common::stdout(&output),
            "wip 0\nfrontier CLOUD-2\nboard check: board coherent (2 issues)\n"
        );
    }

    #[test]
    fn violations_are_pointer_only_no_issue_prose_echoed() {
        let secret = "ACME Corp escalation";
        let (dir, config) = repo("pointer");
        let mut board = Board::default();
        board.issue("CLOUD-1", "In Progress", "", "", &[]);
        board.row("CLOUD-1")["description"] = json!(secret);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(!text(&output).contains(secret));
    }

    #[test]
    fn a_body_claiming_a_column_the_board_contradicts_is_reported() {
        let (dir, config) = repo("claim-disagrees");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
        board.describe(
            "CLOUD-1",
            "Children:\n* CLOUD-2 — **In Progress** (PR #157)",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains(
            "CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"
        ));
    }

    #[test]
    fn the_same_claim_agreeing_with_the_board_is_clean() {
        let (dir, config) = repo("claim-agrees");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.describe("CLOUD-1", "* CLOUD-2 — **Done**");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
    }

    #[test]
    fn a_mention_asserting_no_column_is_not_a_claim() {
        let (dir, config) = repo("mention");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.describe(
            "CLOUD-1",
            "Splits the representation CLOUD-2 introduced; see it for the rationale.",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
    }

    #[test]
    fn the_stored_mention_markup_is_caught_identically_to_the_rendered_form() {
        let (dir, config) = repo("markup");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
        board.describe(
            "CLOUD-1",
            r#"* <issue id="x" href="https://linear.app/i/CLOUD-2">CLOUD-2</issue> — **In Progress**"#,
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains(
            "CLOUD-1 status-claim-disagrees (CLOUD-2 claimed In Progress, board says Done)"
        ));
    }

    #[test]
    fn a_claim_about_an_id_outside_the_piped_set_is_unjudgeable_never_guessed() {
        let (dir, config) = repo("claim-outside");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.describe("CLOUD-1", "* CLOUD-99 — **Done**");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains(
                "graph status-claim-unjudgeable (CLOUD-1 claims CLOUD-99, not in the piped set)"
            ),
            "{all}"
        );
        assert!(!all.contains("CLOUD-1 status-claim-unjudgeable"), "{all}");
    }

    #[test]
    fn a_quoted_or_backticked_citation_of_a_claim_is_not_a_claim() {
        let (dir, config) = repo("quoted");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
        board.describe(
            "CLOUD-1",
            "The inventory said \"CLOUD-2 — **In Progress** (PR #157)\" after it merged,\n\
             and the same defect in a span reads `CLOUD-2 — In Progress` too.",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
    }

    #[test]
    fn narration_about_an_issue_is_not_a_claim_about_its_column() {
        let (dir, config) = repo("narration");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.issue("CLOUD-3", "Done", "", "", &[]);
        board.issue("CLOUD-4", "In Progress", "someone", "", &[]);
        board.describe(
            "CLOUD-1",
            "CLOUD-2 went In Progress at 04:29 and CLOUD-3 still read In Progress.\n\
             CLOUD-2 was Done when this was written, then reopened.",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
    }

    #[test]
    fn a_gloss_with_no_verb_at_all_is_a_claim_in_every_shape_the_corpus_uses() {
        let (dir, config) = repo("gloss");
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
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        for cited in ["CLOUD-2", "CLOUD-3", "CLOUD-4"] {
            assert!(
                all.contains(&format!("{cited} claimed In Progress, board says Done")),
                "{all}"
            );
        }
    }

    #[test]
    fn a_set_with_no_descriptions_cannot_be_scanned_for_claims_and_says_so() {
        let (dir, config) = repo("no-descriptions");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.drop_key("description");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("graph unjudgeable-description (CLOUD-1 CLOUD-2)"));
        assert!(!text(&output).contains("board coherent"));
    }

    #[test]
    fn a_set_carrying_only_the_declared_field_set_is_accepted() {
        let (dir, config) = repo("declared-fields");
        let rows = [
            json!({
                "id": "CLOUD-1", "status": "Todo",
                "attachments": [], "relations": { "blockedBy": [] },
                "description": format!("**Why**\nx.\n\n{READY}"),
                "projectMilestone": { "id": "m-1", "name": "Phase 3" },
            }),
            json!({
                "id": "CLOUD-2", "status": "In Progress", "assigneeId": "someone",
                "attachments": [], "relations": { "blockedBy": [] },
                "description": "nothing to claim here",
                "projectMilestone": { "id": "m-1", "name": "Phase 3" },
            }),
        ];
        let stream = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let output = board_check(&dir, &config, &[], &stream);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("board coherent"));
        assert!(!text(&output).contains("unjudgeable"));
        assert!(text(&output).contains("frontier CLOUD-1"));
    }

    #[test]
    fn a_status_claim_report_is_pointer_only() {
        let secret = "ACME Corp escalation";
        let (dir, config) = repo("claim-pointer");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
        board.describe("CLOUD-1", &format!("{secret}: CLOUD-2 — **In Progress**"));
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("status-claim-disagrees"));
        assert!(!text(&output).contains(secret));
    }

    #[test]
    fn a_column_no_piped_issue_occupies_is_not_in_the_vocabulary() {
        // The gloss form of an unspellable column stays exit 0: telling
        // `— **In Review**` from `— **Batten**` needs a second copy of the
        // status list, which this gate must not hold.
        let (dir, config) = repo("vocabulary");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.describe("CLOUD-1", "* CLOUD-2 — **In Review**");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn a_claim_naming_a_column_no_piped_issue_occupies_is_refused_not_ignored() {
        let (dir, config) = repo("unscannable");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.describe("CLOUD-1", "CLOUD-2 is now Canceled, on a measurement.");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"),
            "{all}"
        );
        assert!(!all.contains("CLOUD-1 status-claim-unscannable"), "{all}");
    }

    #[test]
    fn the_same_claim_over_a_set_that_does_occupy_the_column_is_judged_as_before() {
        let (dir, config) = repo("occupied");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "Canceled", "", "", &[]);
        board.describe("CLOUD-1", "CLOUD-2 is now Canceled, on a measurement.");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains(
                "CLOUD-1 status-claim-disagrees (CLOUD-2 claimed Canceled, board says Done)"
            ),
            "{all}"
        );
        assert!(!all.contains("status-claim-unscannable"), "{all}");
    }

    #[test]
    fn a_body_carrying_a_stale_claim_and_its_own_correction_reports_the_stale_one() {
        let (dir, config) = repo("correction");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.describe(
            "CLOUD-1",
            "CLOUD-2 is now Canceled, on a measurement.\n\nNote also that CLOUD-2 is Todo, not Canceled.",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("graph status-claim-unscannable (CLOUD-1 claims CLOUD-2 is Canceled"),
            "{all}"
        );
        assert!(!all.contains("status-claim-disagrees"), "{all}");
    }

    #[test]
    fn ordinary_prose_is_not_a_claim_however_capitalized() {
        let (dir, config) = repo("prose");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.describe(
            "CLOUD-1",
            "CLOUD-2 Batten's engine, per the note above.\n\
             CLOUD-2 is the durable artifact this campaign rests on.\n\
             Splits the representation CLOUD-2 introduced; see Regorus for the rationale.",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
    }

    #[test]
    fn an_unscannable_report_is_pointer_only() {
        let secret = "ACME Corp escalation";
        let (dir, config) = repo("unscannable-pointer");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.describe("CLOUD-1", &format!("{secret}: CLOUD-2 is now Canceled."));
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("status-claim-unscannable"));
        assert!(!text(&output).contains(secret));
    }

    #[test]
    fn a_multi_word_column_is_named_whole_never_its_first_word() {
        let (dir, config) = repo("multi-word");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.describe("CLOUD-1", "CLOUD-2 is now In Review.");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("claims CLOUD-2 is In Review"));
    }

    #[test]
    fn anti_vacuity_a_set_with_no_status_claims_anywhere_still_exits_0() {
        let (dir, config) = repo("no-claims");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        board.issue("CLOUD-3", "In Progress", "someone", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("status-claim"));
        assert!(text(&output).contains("board coherent"));
    }

    #[test]
    fn a_coherent_board_records_one_receipt_per_id_it_judged() {
        let (dir, config) = repo("receipts");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Done", "", "", &[]);
        board.issue(
            "CLOUD-2",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/1",
            &[],
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        for id in ["CLOUD-1", "CLOUD-2"] {
            let body = std::fs::read_to_string(receipt(&dir, id)).expect("one receipt per id");
            let epoch = body.split_whitespace().next().unwrap_or_default();
            assert!(
                !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()),
                "{body}"
            );
        }
        // No aggregate is left behind, or two shapes would describe one fact.
        assert!(!dir.join(".git/batten-receipts/board-move").exists());
    }

    #[test]
    fn a_value_that_is_not_an_issue_key_mints_nothing_so_it_cannot_become_a_path() {
        let (dir, config) = repo("not-a-key");
        let mut board = Board::default();
        board.issue("notakey", "Done", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        let store = dir.join(".git/batten-receipts");
        let minted = std::fs::read_dir(&store).map_or(0, |entries| {
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
        let (dir, config) = repo("false");
        let mut board = Board::default();
        board.issue("CLOUD-3", "In Review", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(!receipt(&dir, "CLOUD-3").exists());
    }

    #[test]
    fn a_board_it_could_not_read_records_nothing() {
        let (dir, config) = repo("unread");
        let mut board = Board::default();
        board.issue("CLOUD-4", "Done", "", "", &[]);
        board.drop_key("relations");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(!receipt(&dir, "CLOUD-4").exists());
    }

    #[test]
    fn an_earlier_closure_stays_judged_because_each_id_has_its_own_receipt() {
        let (dir, config) = repo("accumulate");
        let mut first = Board::default();
        first.issue("CLOUD-5", "Done", "", "", &[]);
        assert_eq!(code(&check(&dir, &config, &first)), 0);
        let mut second = Board::default();
        second.issue("CLOUD-6", "Done", "", "", &[]);
        assert_eq!(code(&check(&dir, &config, &second)), 0);
        assert!(receipt(&dir, "CLOUD-5").exists());
        let body = std::fs::read_to_string(receipt(&dir, "CLOUD-6")).expect("the receipt");
        assert_eq!(body.lines().count(), 1, "{body}");
    }

    #[test]
    fn the_receipt_is_pointer_only_an_id_and_an_epoch() {
        let (dir, config) = repo("receipt-pointer");
        let mut board = Board::default();
        board.issue("CLOUD-7", "Done", "", "", &[]);
        assert_eq!(code(&check(&dir, &config, &board)), 0);
        let body = std::fs::read_to_string(receipt(&dir, "CLOUD-7")).expect("the receipt");
        assert!(!body.contains("Source of truth"), "{body}");
        assert!(!body.contains("Refinement"), "{body}");
    }

    #[test]
    fn an_unwritable_receipt_store_does_not_change_the_verdict() {
        // A FILE where the store's directory belongs: permission bits never bite a
        // root sandbox, and this makes the write fail on every host.
        let (dir, config) = repo("unwritable");
        std::fs::write(dir.join(".git/batten-receipts"), "not a directory").expect("plant a file");
        let mut board = Board::default();
        board.issue("CLOUD-8", "Done", "", "", &[]);
        let output = check(&dir, &config, &board);
        // The premise, asserted before the conclusion: the store really is unusable.
        assert!(dir.join(".git/batten-receipts").is_file());
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn a_todo_issue_carrying_a_milestone_is_clean_and_still_reaches_the_frontier() {
        let (dir, config) = repo("milestoned");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Done", "", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("unmilestoned"));
        assert!(text(&output).contains("frontier CLOUD-1"));
    }

    #[test]
    fn a_todo_issue_with_no_milestone_in_a_set_where_others_carry_one_is_refused() {
        let (dir, config) = repo("unmilestoned");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone("CLOUD-2", "Todo", "", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(all.contains("CLOUD-2 unmilestoned (Todo)"), "{all}");
        assert!(!all.contains("CLOUD-1 unmilestoned"), "{all}");
        assert!(all.contains("frontier CLOUD-1"), "{all}");
        assert!(!all.contains("**Why**"), "{all}");
    }

    #[test]
    fn a_set_with_the_field_absent_everywhere_is_unjudgeable_not_a_wall_of_violations() {
        let (dir, config) = repo("milestone-absent");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        board.issue("CLOUD-3", "Done", "", "", &[]);
        board.drop_key("projectMilestone");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("graph unjudgeable-milestone (CLOUD-1 CLOUD-2)"),
            "{all}"
        );
        assert!(!all.contains("unmilestoned"), "{all}");
    }

    #[test]
    fn an_unparented_in_progress_row_with_no_milestone_is_refused() {
        let (dir, config) = repo("progress-unphased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone("CLOUD-2", "In Progress", "someone", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 unmilestoned (In Progress)"));
    }

    #[test]
    fn an_unparented_in_review_row_with_no_milestone_is_refused() {
        let (dir, config) = repo("review-unphased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone(
            "CLOUD-2",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/9",
        );
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 unmilestoned (In Review)"));
    }

    #[test]
    fn a_started_row_carrying_a_milestone_passes_and_its_frontier_place_is_unchanged() {
        let (dir, config) = repo("started-phased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "In Progress", "someone", "", &[]);
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("unmilestoned"));
        assert!(text(&output).contains("frontier CLOUD-1"));
    }

    #[test]
    fn a_parented_row_is_reported_once_by_the_child_clause() {
        let (dir, config) = repo("parented-once");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone("CLOUD-2", "In Progress", "someone", "");
        board.row("CLOUD-2")["parentId"] = json!("CLOUD-1");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("CLOUD-2 child-unmilestoned (parent CLOUD-1)"),
            "{all}"
        );
        assert!(!all.contains("CLOUD-2 unmilestoned ("), "{all}");
    }

    #[test]
    fn a_done_row_with_no_milestone_is_clean() {
        let (dir, config) = repo("done-unphased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone("CLOUD-2", "Done", "", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("unmilestoned"));
    }

    #[test]
    fn the_anti_vacuity_arm_widened_with_the_clause() {
        let (dir, config) = repo("widened");
        let mut board = Board::default();
        board.no_milestone("CLOUD-1", "In Progress", "someone", "");
        board.no_milestone(
            "CLOUD-2",
            "In Review",
            "someone",
            "https://github.com/o/r/pull/9",
        );
        board.drop_key("projectMilestone");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("unjudgeable-milestone"));
        assert!(!text(&output).contains("CLOUD-1 unmilestoned"));
    }

    /// A child of `parent` carrying no milestone of its own.
    fn child_no_milestone(board: &mut Board, child: &str, parent: &str) {
        board.no_milestone(child, "Todo", "someone", "");
        board.row(child)["parentId"] = json!(parent);
    }

    #[test]
    fn a_child_with_no_milestone_under_a_milestoned_parent_is_refused() {
        let (dir, config) = repo("child-unphased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        child_no_milestone(&mut board, "CLOUD-2", "CLOUD-1");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 child-unmilestoned (parent CLOUD-1)"));
    }

    #[test]
    fn a_child_carrying_a_different_milestone_is_the_declared_rephase_and_passes() {
        let (dir, config) = repo("rephase");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.issue("CLOUD-2", "Todo", "", "", &[]);
        let child = board.row("CLOUD-2");
        child["parentId"] = json!("CLOUD-1");
        child["projectMilestone"] = json!({ "id": "phase-4", "name": "phase-4" });
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("child-unmilestoned"));
    }

    #[test]
    fn a_child_whose_parent_carries_no_milestone_is_clean() {
        let (dir, config) = repo("parent-unphased");
        let mut board = Board::default();
        board.no_milestone("CLOUD-1", "Todo", "someone", "");
        child_no_milestone(&mut board, "CLOUD-2", "CLOUD-1");
        let output = check(&dir, &config, &board);
        assert!(
            !text(&output).contains("child-unmilestoned"),
            "{}",
            text(&output)
        );
    }

    #[test]
    fn a_parent_outside_the_piped_set_is_unjudgeable_not_a_violation() {
        let (dir, config) = repo("parent-outside");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        child_no_milestone(&mut board, "CLOUD-2", "CLOUD-999");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("CLOUD-2 child-milestone-unjudgeable"));
        assert!(!text(&output).contains("CLOUD-2 child-unmilestoned"));
    }

    #[test]
    fn a_backlog_issue_with_no_milestone_is_clean_and_filing_stays_free() {
        let (dir, config) = repo("backlog-unphased");
        let mut board = Board::default();
        board.issue("CLOUD-1", "Todo", "", "", &[]);
        board.no_milestone("CLOUD-2", "Backlog", "", "");
        let output = check(&dir, &config, &board);
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(!text(&output).contains("unmilestoned"));
        assert!(!text(&output).contains("unjudgeable-milestone"));
    }
}

mod ready_cites {
    use super::{board_check, code, key, text, vocabulary};
    use crate::common;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::process::Output;

    /// A synthetic corpus: a real repository so the tracked paths answer, and
    /// nothing of this repository's own text can satisfy a citation.
    fn synthetic(name: &str) -> (PathBuf, PathBuf) {
        let dir = common::Fixture::new(&format!("board-check-cites-{name}"))
            .file(
                "crates/batten/src/git.rs",
                "fn a_real_test_that_exists_here() {}\n",
            )
            .file(
                "tests/fixtures/quoted/QUOTE.md",
                "a note quoting `only_in_a_fixture_and_nowhere_else` and nothing more\n",
            )
            .git()
            .base_commit()
            .build();
        (dir, vocabulary(&format!("cites-{name}"), ""))
    }

    /// A payload whose live Ready block carries `obligation` as its §7 body.
    fn block7(obligation: &str) -> String {
        json!({
            "id": key(999),
            "description": format!(
                "**Why**\nSomething needs doing.\n\n**Refinement — Ready**\n\n\
                 * **Source of truth (§1).** One artifact.\n\
                 * **Test obligation (§7).** {obligation}\n\
                 * **Blockers (§8).** None.\n"
            ),
        })
        .to_string()
    }

    fn cites(dir: &Path, config: &Path, payload: &str) -> Output {
        board_check(dir, config, &["--cites"], payload)
    }

    #[test]
    fn a_superseded_obligation_naming_two_deleted_tests_is_refused_over_the_real_tree() {
        // The FETCHED fixture, over this repository's own tree and config. The
        // two tokens are assembled from halves so this tracked file cannot
        // satisfy the citation it says does not resolve.
        let snapshot = format!(
            "{}{}",
            "a_snapshot_captures_a_dirty_tree", "_and_nothing_else"
        );
        let worktree = format!("{}{}", "the_worktree_listing_reads", "_gits_own_attributes");
        let payload = std::fs::read_to_string(common::at_root(
            "tests/fixtures/ready-cites-check/CLOUD-740-superseded.json",
        ))
        .expect("the fetched fixture");
        let output = common::run_with_stdin_at_real_root(
            &common::at_root(""),
            &["board", "check", "--cites"],
            &payload,
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains(&format!("{worktree} absent-cited-test")),
            "{all}"
        );
        assert!(
            all.contains(&format!("{snapshot} absent-cited-test")),
            "{all}"
        );
    }

    #[test]
    fn a_citation_resolving_only_in_the_excluded_fixtures_is_refused_over_the_real_tree() {
        // The vacuity guard over the real tree: the snapshot citation resolves
        // only in a fixture QUOTING it, and that fixture is excluded.
        let snapshot = format!(
            "{}{}",
            "a_snapshot_captures_a_dirty_tree", "_and_nothing_else"
        );
        let payload = std::fs::read_to_string(common::at_root(
            "tests/fixtures/ready-cites-check/CLOUD-740-superseded.json",
        ))
        .expect("the fetched fixture");
        let output = common::run_with_stdin_at_real_root(
            &common::at_root(""),
            &["board", "check", "--cites"],
            &payload,
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains(&snapshot));
    }

    #[test]
    fn a_body_with_a_superseded_block_and_a_live_one_is_judged_on_the_live_one() {
        let payload = std::fs::read_to_string(common::at_root(
            "tests/fixtures/ready-cites-check/CLOUD-740-live.json",
        ))
        .expect("the fetched fixture");
        let output = common::run_with_stdin_at_real_root(
            &common::at_root(""),
            &["board", "check", "--cites"],
            &payload,
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn a_citation_that_resolves_only_in_a_fixture_and_nowhere_else_is_refused() {
        let (dir, config) = synthetic("fixture-only");
        let output = cites(
            &dir,
            &config,
            &block7("The case `only_in_a_fixture_and_nowhere_else` holds."),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("only_in_a_fixture_and_nowhere_else absent-cited-test"));
    }

    #[test]
    fn the_last_opener_is_the_live_block_and_an_earlier_one_is_history() {
        let (dir, config) = synthetic("last-opener");
        let payload = json!({
            "id": key(999),
            "description": "**Refinement — Ready (SUPERSEDED)**\n\n\
                * **Test obligation (§7).** The case `a_name_that_is_absent_entirely` holds.\n\n\
                **Refinement — Ready (2026-08-21)**\n\n\
                * **Test obligation (§7).** The case `a_real_test_that_exists_here` holds.\n",
        })
        .to_string();
        let output = cites(&dir, &config, &payload);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn an_obligation_citing_a_test_that_exists_passes() {
        let (dir, config) = synthetic("exists");
        let output = cites(
            &dir,
            &config,
            &block7("The case `a_real_test_that_exists_here` still holds."),
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("1 of 1 citation(s) resolve"));
    }

    #[test]
    fn an_obligation_citing_no_candidate_passes_and_reports_zero_resolved() {
        let (dir, config) = synthetic("none-cited");
        let output = cites(
            &dir,
            &config,
            &block7("End-to-end over the compiled binary, shown able to fail."),
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("0 of 0 citation(s) resolve"));
    }

    #[test]
    fn a_one_underscore_api_name_is_not_a_citation() {
        let (dir, config) = synthetic("api-name");
        let output = cites(
            &dir,
            &config,
            &block7("The `check_ignore` and `update_ref` paths keep their behaviour."),
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("0 of 0 citation(s) resolve"));
    }

    #[test]
    fn a_cited_path_that_does_not_exist_is_refused() {
        let (dir, config) = synthetic("absent-path");
        let output = cites(
            &dir,
            &config,
            &block7("Cases live in `tests/no_such_suite.bats`."),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("tests/no_such_suite.bats absent-cited-path"));
    }

    #[test]
    fn a_citation_the_block_marks_new_is_prospective_not_fatal() {
        let (dir, config) = synthetic("prospective");
        let output = cites(
            &dir,
            &config,
            &block7(
                "Cases live in `tests/layer-check.bats` (new): a fixture with a back-edge exits non-zero.",
            ),
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("tests/layer-check.bats prospective-cited-path"));
        assert!(text(&output).contains("1 prospective"));
    }

    #[test]
    fn an_unmarked_absent_path_is_still_refused() {
        let (dir, config) = synthetic("unmarked");
        let output = cites(
            &dir,
            &config,
            &block7(
                "Cases live in `tests/layer-check.bats`: a fixture with a back-edge exits non-zero.",
            ),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("tests/layer-check.bats absent-cited-path"));
        assert!(!text(&output).contains("prospective"));
    }

    #[test]
    fn the_two_absent_cases_are_distinguishable_in_output() {
        let (dir, config) = synthetic("distinguishable");
        let output = cites(
            &dir,
            &config,
            &block7(
                "Present: `crates/batten/src/git.rs`. Planned: `tests/layer-check.bats` (new). Stale: `tests/gone.bats`.",
            ),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(
            all.contains("tests/layer-check.bats prospective-cited-path"),
            "{all}"
        );
        assert!(all.contains("tests/gone.bats absent-cited-path"), "{all}");
        assert!(
            !all.contains("tests/layer-check.bats absent-cited-path"),
            "{all}"
        );
    }

    #[test]
    fn a_marker_on_a_deleted_path_is_refused_not_believed() {
        let (dir, config) = synthetic("deleted");
        common::write(&dir, "tests/was_here.bats", "old cases\n");
        common::git_in(&dir, &["add", "-A"]);
        common::git_in(&dir, &["commit", "-q", "-m", "add"]);
        common::git_in(&dir, &["rm", "-q", "tests/was_here.bats"]);
        common::git_in(&dir, &["commit", "-q", "-m", "delete"]);
        let output = cites(
            &dir,
            &config,
            &block7("Cases live in `tests/was_here.bats` (new)."),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("tests/was_here.bats stale-cited-path"));
        assert!(!text(&output).contains("prospective"));
    }

    #[test]
    fn a_new_marker_elsewhere_in_the_block_does_not_excuse_an_unrelated_citation() {
        let (dir, config) = synthetic("unrelated");
        let output = cites(
            &dir,
            &config,
            &block7(
                "Planned: `tests/layer-check.bats` (new). Also cites `tests/unrelated.bats` for context.",
            ),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("tests/unrelated.bats absent-cited-path"));
        assert!(text(&output).contains("tests/layer-check.bats prospective-cited-path"));
    }

    #[test]
    fn a_cited_path_that_exists_passes() {
        let (dir, config) = synthetic("path-exists");
        let output = cites(
            &dir,
            &config,
            &block7("The subject is `crates/batten/src/git.rs`."),
        );
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("1 of 1 citation(s) resolve"));
    }

    #[test]
    fn a_test_name_cited_outside_the_obligations_clause_is_not_judged() {
        let (dir, config) = synthetic("outside-span");
        let payload = json!({
            "id": key(999),
            "description": "**Refinement — Ready**\n\n\
                * **Source of truth (§1).** One artifact.\n\
                * **Test obligation (§7).** Nothing named.\n\
                * **Blockers (§8).** None. See `a_name_that_is_absent_entirely` for context.\n",
        })
        .to_string();
        let output = cites(&dir, &config, &payload);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn the_report_carries_no_line_of_the_block_and_no_line_of_a_source_file() {
        let (dir, config) = synthetic("pointer");
        let output = cites(
            &dir,
            &config,
            &block7("ACME-12345 is the account. The case `a_name_that_is_absent_entirely` holds."),
        );
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        assert!(!all.contains("ACME-12345"), "{all}");
        assert!(!all.contains("is the account"), "{all}");
        assert!(!all.contains("fn a_real_test_that_exists_here"), "{all}");
    }

    #[test]
    fn the_report_is_byte_stable_across_runs() {
        let (dir, config) = synthetic("stable");
        let payload = block7(
            "The cases `a_name_that_is_absent_entirely` and `another_name_absent_as_well` hold.",
        );
        let first = text(&cites(&dir, &config, &payload));
        let second = text(&cites(&dir, &config, &payload));
        assert_eq!(first, second);
    }

    #[test]
    fn empty_stdin_is_could_not_look_never_a_verdict() {
        let (dir, config) = synthetic("empty");
        let output = cites(&dir, &config, "");
        assert_eq!(code(&output), 3, "{}", text(&output));
    }

    #[test]
    fn stdin_that_is_not_a_payload_is_could_not_look() {
        let (dir, config) = synthetic("junk");
        let output = cites(&dir, &config, "not json");
        assert_eq!(code(&output), 3, "{}", text(&output));
    }

    #[test]
    fn a_root_that_is_not_a_repository_is_could_not_look_never_a_pass() {
        let bare = common::scratch_outside_tree("board-check", "bare-root");
        let config = vocabulary("cites-bare", "");
        let output = cites(
            &bare,
            &config,
            &block7("The case `a_real_test_that_exists_here` still holds."),
        );
        assert_eq!(code(&output), 3, "{}", text(&output));
    }

    #[test]
    fn a_body_with_no_ready_block_is_not_this_gates_business() {
        let (dir, config) = synthetic("no-block");
        let payload = json!({ "id": key(999), "description": "Just a description." }).to_string();
        let output = cites(&dir, &config, &payload);
        assert_eq!(code(&output), 0, "{}", text(&output));
    }
}

mod spec_ref {
    use super::{board_check, code, key, text, vocabulary};
    use crate::common;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::process::Output;

    /// The witness issue's real clause set: §1, §2, §3, §6, §8 and no §4, with
    /// the label that names two numbers kept verbatim.
    fn payload() -> String {
        json!([
            {
                "id": key(420),
                "description": "**Refinement — Ready**\n\n\
                    * **Source of truth (§1).** The lease ref.\n\
                    * **Mechanism (§3).** land-lock gains a read-only verb.\n\
                    * **THE HAZARD — a stop is a third answer (§2).** Cancelled is the one that works.\n\
                    * **Below it, for free (§3).** Extend ready-guard.\n\
                    * **Engine gap, per §2 (§3).** Extends ci-local-parity.\n\
                    * **Commit / bump (§6):** `feat(ci)`.\n\
                    * **Blockers (§8):** blockedBy CLOUD-363.\n",
            },
            {
                "id": key(326),
                "description": "**Refinement — Ready**\n\n\
                    * **Source of truth (§1).** The transcript corpus.\n\
                    * **Blockers (§8).** N independent sessions.\n",
            },
        ])
        .to_string()
    }

    /// A throwaway tree carrying one tracked file of `lines`.
    fn tree(name: &str, lines: &[String]) -> (PathBuf, PathBuf) {
        let dir = common::Fixture::new(&format!("board-check-refs-{name}"))
            .file("mise-tasks/subject.sh", &format!("{}\n", lines.join("\n")))
            .git()
            .base_commit()
            .build();
        (dir, vocabulary(&format!("refs-{name}"), ""))
    }

    fn refs(dir: &Path, config: &Path, input: &str) -> Output {
        board_check(dir, config, &["--refs"], input)
    }

    /// A citation line, spelled from parts so this tracked file carries none.
    fn cite(n: u32, rest: &str) -> String {
        format!("# {}{rest}", key(n))
    }

    #[test]
    fn a_citation_naming_a_clause_the_issue_does_not_carry_is_reported_with_its_pointer() {
        let (dir, config) = tree("absent", &[cite(420, " §4 the offline half")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains(&format!(
            "mise-tasks/subject.sh:1 {} §4 absent-issue-clause",
            key(420)
        )));
    }

    #[test]
    fn a_citation_naming_a_clause_the_issue_does_carry_passes() {
        let (dir, config) = tree("present", &[cite(420, " §3 the receipt ready-guard reads")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 0, "{}", text(&output));
        assert!(text(&output).contains("every clause citation in the tree resolves"));
    }

    #[test]
    fn a_sub_numbered_citation_resolves_to_its_parent_clause() {
        let (dir, config) = tree("sub-numbered", &[cite(326, " §8.1 the unblock condition")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn the_possessive_form_is_read_as_a_citation() {
        let (dir, config) = tree("possessive", &[cite(420, "'s §4 says so")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains(&format!("{} §4 absent-issue-clause", key(420))));
    }

    #[test]
    fn a_clause_label_naming_two_numbers_declares_both() {
        let (dir, config) = tree("two-numbers", &[cite(420, " §2 per the engine gap")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn a_cited_issue_absent_from_the_payload_set_is_could_not_look_never_a_silent_pass() {
        let (dir, config) = tree("unfetched", &[cite(999, " §1 see it")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains(&format!("{} unjudgeable-issue", key(999))));
    }

    #[test]
    fn a_proven_finding_outranks_an_unfetched_issue() {
        let (dir, config) = tree(
            "outranks",
            &[cite(420, " §4 the offline half"), cite(999, " §1 see it")],
        );
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 2, "{}", text(&output));
    }

    #[test]
    fn empty_stdin_is_could_not_look() {
        let (dir, config) = tree("empty", &["# nothing to see".to_owned()]);
        let output = refs(&dir, &config, "");
        assert_eq!(code(&output), 3, "{}", text(&output));
    }

    #[test]
    fn stdin_that_is_not_a_payload_set_is_could_not_look() {
        let (dir, config) = tree("not-payloads", &["# nothing to see".to_owned()]);
        let output = refs(&dir, &config, &json!([{ "id": key(1) }]).to_string());
        assert_eq!(code(&output), 3, "{}", text(&output));
        assert!(text(&output).contains("need id and description"));
    }

    #[test]
    fn a_tree_with_no_citations_at_all_passes() {
        let (dir, config) = tree("none", &["# no section references here".to_owned()]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 0, "{}", text(&output));
    }

    #[test]
    fn the_emitted_bytes_carry_no_substring_of_any_issue_body() {
        let (dir, config) = tree("pointer", &[cite(420, " §4 the offline half")]);
        let output = refs(&dir, &config, &payload());
        assert_eq!(code(&output), 2, "{}", text(&output));
        let all = text(&output);
        for body in [
            "lease ref",
            "read-only verb",
            "Cancelled is the one",
            "blockedBy",
        ] {
            assert!(!all.contains(body), "{all}");
        }
    }

    #[test]
    fn an_excluded_file_carrying_a_known_bad_witness_is_not_reported() {
        // The witness a suite carries as its fixture would otherwise report
        // itself forever; a declared exclusion is how a consumer skips it.
        let dir = common::Fixture::new("board-check-refs-excluded")
            .file(
                "mise-tasks/witness.sh",
                &format!("{}\n", cite(420, " §4 the witness")),
            )
            .file("mise-tasks/subject.sh", "# no section references here\n")
            .git()
            .base_commit()
            .build();
        let config = vocabulary("refs-excluded", "");
        let seen = refs(&dir, &config, &payload());
        assert_eq!(code(&seen), 2, "{}", text(&seen));
        // The same tree with the witness excluded by a declared glob. The
        // committed `[board]` table is the only one a config may carry, so the
        // exclusion is written into a copy of it.
        let excluding = common::scratch("board-check-config-refs-excluding");
        let board = common::declared_board().replacen(
            "[board]\n",
            "[board]\nrefs_exclude = [\"mise-tasks/witness.sh\"]\n",
            1,
        );
        common::write(
            &excluding,
            "batten.toml",
            &format!("version = 1\n{board}\n{}", common::declared_patterns()),
        );
        let skipped = refs(&dir, &excluding, &payload());
        assert_eq!(code(&skipped), 0, "{}", text(&skipped));
    }
}
