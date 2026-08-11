//! End-to-end tests for the append-only defect ledger (CLOUD-52).
//!
//! Two surfaces, deliberately kept apart. `defects add`/`defects query` are the
//! **verbs** a human or an agent drives; the ledger gate is engine-side and runs
//! inside `check` whenever `[defects]` is declared, so a consumer cannot lower
//! it by editing a rule table.
//!
//! Every fixture carries real git history, because the append-only half compares
//! the working tree against `git show <rev>:<path>` and a fake would prove
//! nothing about the plumbing. Exit assertions use **2** for a policy verdict
//! and **1** for a usage error, per the one exit table.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, batten, git_in, run, stderr, stdout};

/// The declared table every fixture below uses.
const CONFIG: &str = "version = 1\n\n[defects]\npath = \"defects.jsonl\"\nclasses = [\"false-green\", \"silent-skip\"]\n";

/// One well-formed record line.
fn row(id: &str, class: &str, evidence: &str) -> String {
    format!(
        "{{\"id\":\"{id}\",\"class\":\"{class}\",\"observed\":\"2026-08-11\",\"evidence\":\"{evidence}\"}}"
    )
}

/// A repo whose base commit carries `ledger` (when `Some`) beside [`CONFIG`].
fn ledger_repo(name: &str, ledger: Option<&str>) -> PathBuf {
    let mut fixture = Fixture::new(name).config(CONFIG).git();
    if let Some(text) = ledger {
        fixture = fixture.file("defects.jsonl", text);
    }
    let dir = fixture.build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check"])
}

/// Run `batten` with `stdin` piped in — `defects add` reads its records there.
fn run_with_stdin(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = batten()
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for batten")
}

fn ledger_text(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("defects.jsonl")).unwrap_or_default()
}

// --- the gate ------------------------------------------------------------

#[test]
fn rewriting_a_committed_row_is_a_violation_at_that_line() {
    // The headline case, and the one an id-set check would miss: every id
    // survives and history still changed.
    let base = format!("{}\n{}\n", row("d-1", "false-green", "a.rs:1"), row("d-2", "silent-skip", "b.rs:2"));
    let dir = ledger_repo("defects-rewritten", Some(&base));
    common::write(
        &dir,
        "defects.jsonl",
        &format!("{}\n{}\n", row("d-1", "false-green", "a.rs:1"), row("d-2", "silent-skip", "SOMEWHERE-ELSE:9")),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "a rewrite is a policy verdict");
    let text = stdout(&output);
    assert!(
        text.contains("defect-not-append-only"),
        "the finding names the rule: {text:?}"
    );
    assert!(
        text.contains("defects.jsonl:2"),
        "and points at the row that changed: {text:?}"
    );
    assert!(
        !text.contains("SOMEWHERE-ELSE"),
        "pointer-only: no byte of either version of the row appears (rule 4): {text:?}"
    );
}

#[test]
fn appending_is_the_permitted_move_and_says_nothing() {
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-appended", Some(&base));
    common::write(
        &dir,
        "defects.jsonl",
        &format!("{base}{}\n", row("d-2", "silent-skip", "b.rs:2")),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "a ledger that only grew is silent");
}

#[test]
fn deleting_a_committed_row_is_caught_at_the_row_that_went_missing() {
    let base = format!("{}\n{}\n", row("d-1", "false-green", "a.rs:1"), row("d-2", "silent-skip", "b.rs:2"));
    let dir = ledger_repo("defects-shrunk", Some(&base));
    common::write(&dir, "defects.jsonl", &format!("{}\n", row("d-1", "false-green", "a.rs:1")));

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("defects.jsonl:2"));
}

#[test]
fn an_absent_ledger_under_a_declared_table_is_the_bootstrap_state() {
    // `[defects]` declared before the first record: nothing there to be wrong
    // about. The one absence in this module that is legitimately silent.
    let dir = ledger_repo("defects-absent", None);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty(), "got: {}", stdout(&output));
}

#[test]
fn a_class_outside_the_taxonomy_and_a_repeated_id_are_both_findings() {
    let dir = ledger_repo("defects-invalid", None);
    common::write(
        &dir,
        "defects.jsonl",
        &format!(
            "{}\n{}\n{}\n",
            row("d-1", "false-green", "a.rs:1"),
            row("d-2", "invented-locally", "b.rs:2"),
            row("d-1", "silent-skip", "c.rs:3"),
        ),
    );

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(text.contains("defect-unknown-class"), "got: {text:?}");
    assert!(text.contains("defect-duplicate-id"), "got: {text:?}");
    assert!(
        !text.contains("invented-locally"),
        "the offending token is content, and content never rides the report: {text:?}"
    );
}

#[test]
fn a_malformed_row_is_a_finding_rather_than_an_aborted_run() {
    // Exit 1 here would be the wrong reading: one bad row must not stop `check`
    // reporting everything else it found.
    let dir = ledger_repo("defects-malformed", None);
    common::write(&dir, "defects.jsonl", "not json at all\n");

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "a verdict, not a usage error");
    let text = stdout(&output);
    assert!(text.contains("defect-malformed-line"), "got: {text:?}");
    assert!(
        text.contains("defects.jsonl:1"),
        "and names the line: {text:?}"
    );
    assert!(
        !text.contains("not json at all"),
        "the unparseable bytes are payload: {text:?}"
    );
}

#[test]
fn a_rewrite_and_a_malformed_row_are_both_reported() {
    // The reason the byte comparison does not sit behind the parse: a rewrite
    // that also broke the JSON must not be hidden by the breakage.
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-both", Some(&base));
    common::write(&dir, "defects.jsonl", "not json at all\n");

    let text = stdout(&check(&dir));
    assert!(text.contains("defect-malformed-line"), "got: {text:?}");
    assert!(text.contains("defect-not-append-only"), "got: {text:?}");
}

#[test]
fn every_ledger_problem_is_reachable_through_the_compiled_binary() {
    // The census: a problem id nobody can provoke is a taxonomy member that
    // documents a check the engine does not perform.
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-census", Some(&base));

    let mut seen: Vec<&str> = Vec::new();
    for text in [
        // malformed + not-append-only
        "not json\n".to_owned(),
        // unknown class + duplicate id, both appended so history holds
        format!(
            "{base}{}\n{}\n",
            row("d-2", "invented-locally", "b.rs:2"),
            row("d-1", "false-green", "a.rs:1"),
        ),
    ] {
        common::write(&dir, "defects.jsonl", &text);
        let reported = stdout(&check(&dir));
        for id in batten::defects::PROBLEMS {
            if reported.contains(id) {
                seen.push(id);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    let mut expected: Vec<&str> = batten::defects::PROBLEMS.to_vec();
    expected.sort_unstable();
    assert_eq!(seen, expected, "every declared problem must be provocable");
}

#[test]
fn with_no_remote_the_comparison_degrades_to_head_only_never_to_a_pass() {
    // The absence reading that matters. A repository with no remote has no
    // recorded default branch, so one of the two bases simply is not there —
    // and the ledger is still guarded, by `HEAD`. Answering "append-only held"
    // because a base was missing is the false green this engine exists to catch.
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-no-remote", Some(&base));
    assert!(
        git_in(&dir, &["remote"]).is_empty(),
        "the fixture must genuinely have no remote for this to prove anything"
    );
    common::write(&dir, "defects.jsonl", &format!("{}\n", row("d-1", "false-green", "z.rs:9")));

    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).contains("defect-not-append-only"));
}

#[test]
fn a_resolvable_remote_default_is_a_second_base_and_one_rewrite_is_one_finding() {
    // Both bases resolving to the same commit find the same divergence twice.
    // The gate reports one, because a reader counting findings is counting
    // problems, not comparisons.
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-remote", Some(&base));

    // A real remote with a recorded HEAD: `remote_default_branch` reads
    // `refs/remotes/<remote>/HEAD`, which is what a clone maintains.
    let upstream = common::scratch("defects-remote-upstream");
    git_in(&upstream, &["init", "-q", "--bare", "--initial-branch=main"]);
    git_in(&dir, &["remote", "add", "origin", &upstream.to_string_lossy()]);
    git_in(&dir, &["push", "-q", "origin", "main"]);
    git_in(&dir, &["remote", "set-head", "origin", "main"]);

    common::write(&dir, "defects.jsonl", &format!("{}\n", row("d-1", "false-green", "z.rs:9")));
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output)
            .lines()
            .filter(|line| line.contains("defect-not-append-only"))
            .count(),
        1,
        "one rewrite is one finding, not one per base: {}",
        stdout(&output)
    );
}

#[test]
fn the_gate_is_silent_when_no_table_is_declared() {
    // Config keys plus engine: no `[defects]`, no gate — and specifically not a
    // default path the engine invents.
    let dir = Fixture::new("defects-undeclared")
        .config("version = 1\n")
        .file("defects.jsonl", "not json at all\n")
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    assert_eq!(check(&dir).status.code(), Some(0));
}

#[test]
fn the_report_is_byte_stable_across_runs_in_both_channels() {
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-stable", Some(&base));
    common::write(&dir, "defects.jsonl", &format!("{}\n", row("d-1", "false-green", "z.rs:9")));

    for args in [&["check"][..], &["check", "-J"][..]] {
        let first = run(&dir, args);
        let second = run(&dir, args);
        assert_eq!(
            first.stdout, second.stdout,
            "identical state must produce identical bytes"
        );
        assert_eq!(first.status.code(), Some(2));
    }
}

#[test]
fn a_waiver_suppresses_a_ledger_finding_like_any_other() {
    // The proof that the gate joins the one funnel rather than growing a second
    // verdict path: waivers reach it for free.
    let base = format!("{}\n", row("d-1", "false-green", "a.rs:1"));
    let dir = ledger_repo("defects-waived", Some(&base));
    common::write(
        &dir,
        "batten.toml",
        &format!(
            "{CONFIG}\n[[waiver]]\nrule = \"defect-not-append-only\"\nreason = \"tracked in CLOUD-1; the ledger is being migrated\"\nexpires = \"2999-01-01\"\n"
        ),
    );
    common::write(&dir, "defects.jsonl", &format!("{}\n", row("d-1", "false-green", "z.rs:9")));
    assert_eq!(check(&dir).status.code(), Some(0));
}

// --- the verbs -----------------------------------------------------------

#[test]
fn add_appends_and_is_idempotent_on_a_byte_identical_row() {
    let dir = ledger_repo("defects-add", None);
    let line = format!("{}\n", row("d-1", "false-green", "a.rs:1"));

    let first = run_with_stdin(&dir, &["defects", "add"], &line);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(
        first.stderr.is_empty(),
        "§5: `add` prints nothing on success: {}",
        stderr(&first)
    );
    assert_eq!(ledger_text(&dir).lines().count(), 1);

    // Re-running a half-finished import is safe — that is what idempotence buys.
    // Asked for on the ladder, the counts are there.
    let again = run_with_stdin(&dir, &["-v", "defects", "add"], &line);
    assert_eq!(again.status.code(), Some(0));
    assert!(stderr(&again).contains("already present 1"), "{}", stderr(&again));
    assert_eq!(
        ledger_text(&dir).lines().count(),
        1,
        "the row is not written twice"
    );
}

#[test]
fn add_refuses_a_revision_and_names_the_sanctioned_correction() {
    let dir = ledger_repo("defects-revise", Some(&format!("{}\n", row("d-1", "false-green", "a.rs:1"))));
    let output = run_with_stdin(
        &dir,
        &["defects", "add"],
        &format!("{}\n", row("d-1", "false-green", "elsewhere.rs:9")),
    );
    assert_eq!(output.status.code(), Some(1), "a usage error, not a verdict");
    assert!(
        stderr(&output).contains("supersedes"),
        "got: {}",
        stderr(&output)
    );
}

#[test]
fn add_refuses_a_class_outside_the_taxonomy_before_writing_it() {
    // A ledger is append-only, so a bad row admitted once cannot be taken back:
    // the taxonomy is enforced at the write, not only by the gate afterwards.
    let dir = ledger_repo("defects-add-class", None);
    let output = run_with_stdin(
        &dir,
        &["defects", "add"],
        &format!("{}\n", row("d-1", "invented-locally", "a.rs:1")),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        ledger_text(&dir).is_empty(),
        "nothing was written: {:?}",
        ledger_text(&dir)
    );
}

#[test]
fn add_dry_run_reports_the_counts_and_writes_nothing() {
    let dir = ledger_repo("defects-dry", None);
    let output = run_with_stdin(
        &dir,
        &["defects", "add", "-n"],
        &format!("{}\n", row("d-1", "false-green", "a.rs:1")),
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(stderr(&output).contains("would append 1"), "{}", stderr(&output));
    assert!(ledger_text(&dir).is_empty(), "a dry run writes nothing");
}

#[test]
fn add_refuses_an_empty_stream() {
    // An add that adds nothing is a mistake — a truncated pipe, most likely —
    // and reporting success would make it invisible.
    let dir = ledger_repo("defects-empty", None);
    let output = run_with_stdin(&dir, &["defects", "add"], "");
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn query_is_pointer_only_sorted_by_id_and_filterable() {
    let mut gated = row("d-2", "false-green", "b.rs:2");
    gated = format!("{},\"enforcement\":\"no-todo\"}}", gated.trim_end_matches('}'));
    let dir = ledger_repo(
        "defects-query",
        Some(&format!(
            "{}\n{gated}\n{}\n",
            row("d-3", "silent-skip", "c.rs:3"),
            row("d-1", "false-green", "a.rs:1"),
        )),
    );

    let all = run(&dir, &["defects", "query"]);
    assert_eq!(all.status.code(), Some(0), "{}", stderr(&all));
    assert_eq!(
        stdout(&all),
        "defects.jsonl:3 d-1 ungated\ndefects.jsonl:2 d-2 no-todo\ndefects.jsonl:1 d-3 ungated\n3 record(s)\n",
        "sorted by id, located by line, then the count"
    );
    assert!(
        !stdout(&all).contains("2026-08-11"),
        "the default channel carries no record body"
    );

    // The filter rule 2 wants somebody looking at: which lessons are still prose.
    assert_eq!(
        stdout(&run(&dir, &["defects", "query", "--ungated"])).lines().count(),
        3,
        "the pointers plus the trailing count"
    );
    assert_eq!(
        stdout(&run(&dir, &["defects", "query", "--class", "silent-skip"])).lines().count(),
        2,
        "the pointers plus the trailing count"
    );
    assert_eq!(
        stdout(&run(&dir, &["defects", "query", "--id", "d-2"])).lines().count(),
        2,
        "the pointers plus the trailing count"
    );
}

#[test]
fn query_refuses_two_filters_rather_than_picking_a_winner() {
    let dir = ledger_repo("defects-two-filters", Some(&format!("{}\n", row("d-1", "false-green", "a.rs:1"))));
    let output = run(&dir, &["defects", "query", "--ungated", "--class", "false-green"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("name one"), "{}", stderr(&output));
}

#[test]
fn query_json_is_emitted_even_when_it_is_empty() {
    // JSON that is sometimes absent is unparseable — the caller cannot tell an
    // empty answer from a crashed one.
    let dir = ledger_repo("defects-empty-json", None);
    let output = run(&dir, &["defects", "query", "-J"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("parses as JSON");
    assert_eq!(parsed.as_array().map(Vec::len), Some(0));
}

#[test]
fn a_verb_over_an_undeclared_ledger_is_a_usage_error_not_an_empty_answer() {
    // Answering "no records" for a ledger nobody declared would be the false
    // green the engine exists to catch — `policy budget`'s reading, applied here.
    let dir = Fixture::new("defects-no-table").config("version = 1\n").git().build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);

    let output = run(&dir, &["defects", "query"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("[defects]"), "{}", stderr(&output));
}

#[test]
fn a_table_that_cannot_be_used_is_refused_at_load() {
    let dir = Fixture::new("defects-bad-table")
        .config("version = 1\n\n[defects]\npath = \"defects.jsonl\"\nclasses = []\n")
        .git()
        .build();
    let output = run(&dir, &["defects", "query"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("classes"), "{}", stderr(&output));
}
