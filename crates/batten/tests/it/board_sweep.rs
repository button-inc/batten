//! `[tasks.board-sweep]`'s successor — every board gate over one payload set,
//! reported as a SET (CLOUD-825) — over the compiled `batten board sweep`
//! (CLOUD-843).
//!
//! About the COMPOSER and nothing else: each case asserts a gate was REACHED
//! with the payload set and its exit read on its row's own table, never that a
//! gate's predicate is right — that is each gate's own tier. The gates here are
//! this binary's own verbs (`verdict` for a chosen exit, `landed abandoned` for a
//! gate that reads stdin and decides), declared in a fixture `[board] sweep`
//! table: the sweep's gates are the consumer's facts, so no case leans on this
//! repository's own rows.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/board-sweep.sh subject:mise.toml crates/batten/tests/it/board_sweep.rs
// ported: tests/board-sweep.bats subject:mise.toml crates/batten/tests/it/board_sweep.rs
// carried: [tasks.board-sweep] crates/batten/src/sweep.rs kind:verb crates/batten/tests/it/board_sweep.rs runs:batten+board+sweep
// carried: "a set with no dissonance exits 0 and says every gate ran" crates/batten/tests/it/board_sweep.rs
// carried: "every gate is reached, and the report names each one" crates/batten/tests/it/board_sweep.rs
// carried: "a landed-but-In-Progress row is named by in-progress-drain" crates/batten/tests/it/board_sweep.rs
// changed: "a payload set reaches graph-check behind released" crates/batten/src/sweep.rs the sweep hands every declared gate the same payload set on stdin, which `the_payload_set_reaches_every_gate_on_stdin` asserts; `released` rejoins the consumer's table when its successor reads the set
// changed: "an empty payload set is COULD NOT LOOK, not a clean board" crates/batten/src/sweep.rs could-not-look about the INPUT is `Usage` (1) on the engine's table, where the corpus answered 2
// changed: "a gate exiting 2 is not laundered into the refusal lane" crates/batten/src/sweep.rs each row carries its own exit table, so the laundering case is an exit OUTSIDE the row's table, which reads as could-not-look
// carried: "a board-scoped could-not-look outranks a refusal, so a half-run sweep is never exit 1" crates/batten/tests/it/board_sweep.rs
// changed: "a duplicate close sharing its target's operation is named by the sweep" crates/batten/src/sweep.rs `duplicate-close-check` is a consumer row read on the corpus table (`refuses = [1]`); a corpus gate's refusal reaching the report is `a_corpus_gate_is_read_on_its_own_table`, and the predicate is `duplicate_close.rs`'s tier
// changed: "a tag-less clone still gets a graph-check verdict, and the sweep says so" crates/batten/src/sweep.rs which tag a release gate judges is that gate's to resolve; a gate that cannot answer on this clone declares the exit under `abstains`, which `an_abstaining_gate_is_not_a_clean_board` asserts
// changed: "an abstention and a not-judged sweep are different exit codes" crates/batten/src/sweep.rs the engine has four codes and no fifth, so both unanswered lanes are `Internal` (3) and the REPORT tells them apart
// carried: "a refusal outranks a clone-scoped abstention, so reachability buys no weaker verdict" crates/batten/tests/it/board_sweep.rs
// changed: "a tag-less clone reaches ready-lint, which is graph-check's own leaf" crates/batten/src/sweep.rs `ready-lint` retires into `board check`, which is a consumer row like any other
// carried: "the report carries no issue body" crates/batten/tests/it/board_sweep.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;
use std::process::Output;

/// This binary, as a gate's argv spells it — a TOML literal string, so a path
/// carrying a backslash reads as written.
fn bin() -> String {
    format!("'{}'", env!("CARGO_BIN_EXE_batten"))
}

/// A gate answering with `findings` and `unjudgeable`: `0/0` is exit 0, a
/// finding exit 2, a blind spot exit 3 — `ExitCode::combine`'s own table.
fn verdict_gate(name: &str, findings: u8, unjudgeable: u8, extra: &str) -> String {
    format!(
        "[[board.sweep]]\nname = \"{name}\"\nrun = [{}, 'verdict', '--findings', '{findings}', '--unjudgeable', '{unjudgeable}']\n{extra}\n",
        bin()
    )
}

/// The drain as a gate: it READS the payload set on stdin and decides, so a row
/// it refuses proves the set reached it.
fn drain_gate() -> String {
    format!(
        "[[board.sweep]]\nname = \"in-progress-drain\"\nrun = [{}, 'landed', 'abandoned', '--merged-prs', 'merged.tsv', '--refs', 'refs.txt', '--instant', '2026-08-20']\n",
        bin()
    )
}

/// A fixture repository declaring a board and the given sweep rows.
struct Board {
    dir: PathBuf,
}

impl Board {
    fn new(name: &str, gates: &str) -> Self {
        Self::with_board(name, &common::declared_board(), gates)
    }

    fn with_board(name: &str, board: &str, gates: &str) -> Self {
        let dir = common::scratch(&format!("board-sweep-{name}"));
        common::init_repo(&dir);
        common::write(
            &dir,
            "batten.toml",
            &format!("version = 1\n{board}\n{gates}"),
        );
        common::write(&dir, "merged.tsv", "");
        common::write(&dir, "refs.txt", "");
        Self { dir }
    }

    fn sweep(&self, payloads: &str) -> Output {
        common::run_with_stdin(&self.dir, &["board", "sweep"], payloads)
    }
}

/// A row that the drain passes: In Progress, touched today, a PR attached.
fn row(id: &str, status: &str, updated: &str, attachments: &str) -> String {
    format!(
        r#"{{"id":"{id}","status":"{status}","updatedAt":"{updated}","gitBranchName":"x/{id}","description":"a body","attachments":{attachments}}}"#
    )
}

const PR: &str = r#"[{"url":"https://github.com/o/r/pull/1"}]"#;
const TODAY: &str = "2026-08-20T00:00:00.000Z";

fn clean(id: &str) -> String {
    row(id, "In Progress", TODAY, PR)
}

fn set_of(rows: &[String]) -> String {
    format!("[{}]", rows.join(","))
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_clean_board_exits_0_and_every_gate_is_reached_and_named() {
    let board = Board::new(
        "clean",
        &format!("{}{}", verdict_gate("first", 0, 0, ""), drain_gate()),
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("every gate ran"), "{text}");
    assert!(text.contains("first ok"), "{text}");
    assert!(text.contains("in-progress-drain ok"), "{text}");
}

#[test]
fn a_landed_but_in_progress_row_is_named_by_in_progress_drain() {
    let board = Board::new("drain", &drain_gate());
    common::write(&board.dir, "merged.tsv", "CLOUD-1\t1\n");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("in-progress-drain REFUSED"), "{text}");
    assert!(text.contains("landed-unswept"), "{text}");
}

/// THE SET REACHES THE GATE. The same table over two payload sets answers two
/// ways, and the only thing that differs is what arrived on the gate's stdin.
#[test]
fn the_payload_set_reaches_every_gate_on_stdin() {
    let board = Board::new("stdin", &drain_gate());
    let live = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert_eq!(live.status.code(), Some(0), "{}", said(&live));
    let dead = board.sweep(&set_of(&[row(
        "CLOUD-1",
        "In Progress",
        "2026-01-01T00:00:00.000Z",
        "[]",
    )]));
    assert_eq!(dead.status.code(), Some(2), "{}", said(&dead));
    assert!(said(&dead).contains("claimed-abandoned"), "{}", said(&dead));
}

#[test]
fn an_empty_payload_set_is_could_not_look() {
    let board = Board::new("empty", &verdict_gate("first", 0, 0, ""));
    for payloads in ["", "[]"] {
        let out = board.sweep(payloads);
        let text = said(&out);
        assert_eq!(out.status.code(), Some(1), "{text}");
        assert!(!text.contains("every gate ran"), "{text}");
        assert!(!text.contains("first ok"), "no gate may run: {text}");
        assert!(text.contains("the payload set is empty"), "{text}");
    }
    let out = board.sweep("not json");
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("not JSON"), "{}", said(&out));
}

/// A row reads its exit on ITS table, and an exit it does not name is
/// could-not-look — never laundered into the refusal lane.
#[test]
fn a_gate_exiting_outside_its_table_is_not_laundered_into_the_refusal_lane() {
    let board = Board::new("laundered", &verdict_gate("blind", 0, 1, ""));
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("blind COULD NOT LOOK"), "{text}");
    assert!(!text.contains("blind REFUSED"), "{text}");
    assert!(text.contains("could not look"), "{text}");
}

#[test]
fn a_gate_that_cannot_be_run_is_could_not_look() {
    let board = Board::new(
        "unrunnable",
        "[[board.sweep]]\nname = \"ghost\"\nrun = [\"no-such-program-for-the-board-sweep\"]\n",
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert_eq!(out.status.code(), Some(3), "{}", said(&out));
    assert!(
        said(&out).contains("ghost COULD NOT LOOK"),
        "{}",
        said(&out)
    );
}

#[test]
fn a_board_scoped_could_not_look_outranks_a_refusal() {
    let board = Board::new(
        "outranks",
        &format!(
            "{}{}",
            verdict_gate("refuses", 1, 0, ""),
            verdict_gate("blind", 0, 1, "")
        ),
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    // Both are still reported: the set, never a first failure.
    assert!(text.contains("refuses REFUSED"), "{text}");
    assert!(text.contains("blind COULD NOT LOOK"), "{text}");
}

#[test]
fn a_refusal_outranks_a_clone_scoped_abstention() {
    let board = Board::new(
        "refusal-wins",
        &format!(
            "{}{}",
            verdict_gate("clone", 0, 1, "abstains = [3]"),
            verdict_gate("refuses", 1, 0, "")
        ),
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("clone ABSTAINED"), "{text}");
    assert!(text.contains("refuses REFUSED"), "{text}");
}

/// An abstention alone is not a clean board, and the report says which lane
/// held — the one thing the shared exit code cannot.
#[test]
fn an_abstaining_gate_is_not_a_clean_board() {
    let board = Board::new(
        "abstains",
        &format!(
            "{}{}",
            verdict_gate("first", 0, 0, ""),
            verdict_gate("clone", 0, 1, "abstains = [3]")
        ),
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    let text = said(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("clone ABSTAINED"), "{text}");
    assert!(
        text.contains("abstained on a property of this clone"),
        "{text}"
    );
    assert!(!text.contains("gate(s) could not look"), "{text}");
    assert!(!text.contains("every gate ran"), "{text}");
}

/// A gate on the corpus's table refuses at 1, and the sweep reads it so.
#[cfg(unix)]
#[test]
fn a_corpus_gate_is_read_on_its_own_table() {
    let board = Board::new(
        "corpus",
        "[[board.sweep]]\nname = \"corpus\"\nrun = [\"false\"]\nrefuses = [1]\n",
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(said(&out).contains("corpus REFUSED"), "{}", said(&out));
}

#[test]
fn an_undeclared_or_malformed_sweep_is_refused_rather_than_clean() {
    let board = Board::new("undeclared", "");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("board.sweep"), "{}", said(&out));
    let board = Board::new(
        "malformed",
        "[[board.sweep]]\nname = \"zero\"\nrun = [\"x\"]\nrefuses = [0]\n",
    );
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
}

/// A CONSUMER THAT IS NOT THIS REPOSITORY: another board's column vocabulary,
/// and the drain gate still decides over it — the sweep and its gates carry no
/// word of this repository's (non-negotiable rule 1).
#[test]
fn a_consumer_with_another_board_vocabulary_is_swept() {
    let board = Board::with_board(
        "another-vocabulary",
        "[board]\nready = \"To Do\"\nin_progress = \"In Development\"\nreview = \"Under Review\"\nstarted = [\"In Development\", \"Shipped\"]\n",
        &drain_gate(),
    );
    let dead = board.sweep(&set_of(&[row(
        "ACME-7",
        "In Development",
        "2026-01-01T00:00:00.000Z",
        "[]",
    )]));
    assert_eq!(dead.status.code(), Some(2), "{}", said(&dead));
    assert!(said(&dead).contains("ACME-7"), "{}", said(&dead));
    let live = board.sweep(&set_of(&[row("ACME-7", "In Development", TODAY, PR)]));
    assert_eq!(live.status.code(), Some(0), "{}", said(&live));
}

/// THIS REPOSITORY'S TABLE IS DECLARED AND WELL-FORMED — the analogue of the
/// retired composer's `drain-not-invoked` and `graph-check-not-a-leaf` mutants.
/// An undeclared table makes `board sweep` refuse on every run, so a sweep this
/// repository could not run would otherwise read as a gate it has.
#[test]
fn this_repositorys_sweep_declares_the_board_check_and_the_drain() {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).expect("the config");
    let config: toml::Value = toml::from_str(&text).expect("the config parses");
    let rows = config
        .get("board")
        .and_then(|board| board.get("sweep"))
        .and_then(toml::Value::as_array)
        .expect("`[[board.sweep]]` is declared");
    let runs: Vec<Vec<&str>> = rows
        .iter()
        .map(|row| {
            row.get("run")
                .and_then(toml::Value::as_array)
                .expect("every row has a run")
                .iter()
                .filter_map(toml::Value::as_str)
                .collect()
        })
        .collect();
    for want in [
        vec!["batten", "board", "check"],
        vec!["batten", "landed", "abandoned", "--gather"],
    ] {
        assert!(
            runs.contains(&want),
            "{want:?} is not a sweep row: {runs:?}"
        );
    }
}

#[test]
fn the_report_carries_no_issue_body() {
    let board = Board::new("pointer", &drain_gate());
    common::write(&board.dir, "merged.tsv", "CLOUD-1\t1\n");
    let out = board.sweep(&set_of(&[clean("CLOUD-1")]));
    assert!(!said(&out).contains("a body"), "{}", said(&out));
}
