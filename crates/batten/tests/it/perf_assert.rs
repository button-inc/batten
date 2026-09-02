//! `policy/perf-assert.rego` over the compiled binary (CLOUD-207, retired under
//! CLOUD-1321).
//!
//! **This is the tier the module's own `test_` rules cannot be.** A `with input
//! as` block writes the shape it then reads, so it is green over a key the engine
//! never fills — CLOUD-845's defect, and the one
//! `.claude/rules/policy-modules.md` records both live instances of. Two claims
//! here are exactly of that kind and are asserted nowhere else: that the engine
//! fills `input.tree.lines["README.md"]` from a row declaring it, and that
//! `input.tree.missing` reaches the module when it cannot.
//!
//! **The row declares `lines`, not `line_sources`, and the difference is a dead
//! gate.** `line_sources` is the GLOB field: its entries are matched against the
//! walked file list, so an absent `README.md` matches nothing, is never declared,
//! is never acquired, and never reaches `input.tree.missing` — the could-not-look
//! clause simply cannot fire. `lines` is the literal field and is unioned into the
//! declared set unconditionally, so an absent path is acquired, fails, and is
//! named with its cause. The first spelling here was `line_sources` and
//! `an_unreadable_readme_is_reported` is what caught it; every other case in this
//! file passed over it, which is the shape the second tier exists for.
//!
//! **The producer is RUN, never planted.** `batten record tool` writes the record
//! and `batten check` reads it back, so these cases prove the writer and the
//! reader compose the SAME key. A hand-written record agrees with the reader by
//! construction, which is how `validator-verdict-clean` shipped resolving `null`
//! on every real checkout — the only writer in the tree was a test helper.
//!
//! The module read here is the COMMITTED one, copied into each scratch tree, and
//! the pattern row is derived from the committed table rather than restated: an
//! inline copy of either would drift and pass while the real gate was broken.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! `perf-assert.sh` was a pure function of stdin that adjudicated two questions
//! over data something else measured. Both move: the measurement verdict onto the
//! `perf-p95` `[[rule.tools]]` row, and the README-agreement clause onto the
//! module. The MEASUREMENT itself never lived in the program and does not move —
//! `mise run perf` still spawns hyperfine, and `.github/workflows/perf.yml` still
//! runs it. What changes is that the records now reach a gate through a key
//! naming the tool, its pin and the digest of the binary measured, so a record
//! taken over bytes that have since changed is absent rather than stale. The
//! predecessor's stdin pipe could not state that at all.

// carried: mise-tasks/perf-assert.sh policy/perf-assert.rego crates/batten/tests/it/perf_assert.rs
// carried: tests/perf-assert.bats policy/perf-assert.rego crates/batten/tests/it/perf_assert.rs

//! # RETIREMENT LEDGER — `tests/perf-assert.bats`, 16 cases
//!
//! CARRIED — the budget verdict, the presence gate and the README clause, which
//! are the whole of what the gate decided.

// carried: "records inside budget pass" crates/batten/tests/it/perf_assert.rs
// carried: "a path over budget is named, and a sibling inside budget is not reported" crates/batten/tests/it/perf_assert.rs
// carried: "a budgeted path missing from the records is could-not-look" crates/batten/tests/it/perf_assert.rs
// carried: "wired over budget is a violation" crates/batten/tests/it/perf_assert.rs
// carried: "wired missing from the records is could-not-look" crates/batten/tests/it/perf_assert.rs
// carried: "posttool missing from the records is could-not-look" crates/batten/tests/it/perf_assert.rs
// carried: "posttool over budget is a violation" crates/batten/tests/it/perf_assert.rs
// carried: "a README publishing a different budget is a violation" crates/batten/tests/it/perf_assert.rs
// carried: "a README with no row for a budgeted path is a violation" crates/batten/tests/it/perf_assert.rs
// carried: "a README with no wired row is a violation" crates/batten/tests/it/perf_assert.rs
// carried: "the real README publishes the budgets this gate enforces" crates/batten/tests/it/perf_assert.rs
// carried: "a missing README is could-not-look" crates/batten/tests/it/perf_assert.rs

//! CHANGED — the four stdin-parsing cases. Their subject was the program's own
//! record parser, and there is no parser left to test: the record reaches the
//! module as a projected map the engine composed, so "a line that is not a
//! record" is refused by `batten record tool` at the WRITE (it demands
//! `<name> <token>`) rather than adjudicated at the read. The could-not-look
//! meaning is conserved and its exit code moves from the program's `2` to the
//! engine's contract.

// changed: "empty stdin is could-not-look" crates/batten/tests/it/perf_assert.rs the record store is read by key rather than piped, so an empty stream is an absent record and the module abstains
// changed: "whitespace-only stdin is could-not-look" crates/batten/tests/it/perf_assert.rs the record store is read by key rather than piped, so an empty stream is an absent record and the module abstains
// changed: "a line that is not a record is could-not-look, naming the line" crates/batten/tests/it/perf_assert.rs `batten record tool` refuses a malformed line at the write, so the reader never sees one
// changed: "a record with a non-numeric p95 is could-not-look" crates/batten/tests/it/perf_assert.rs the comparison is numeric in the module and a non-numeric token cannot satisfy it, so such a path is not judged rather than crashing the gate

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, run_with_stdin, scratch, stdout, write};

/// The pin the fixture row declares. Any value works — what matters is that the
/// producer and the reader compose the key from the SAME one.
const DECLARED_VERSION: &str = "1.20.0";

/// The bytes standing in for the measured binary. Small, because the digest is
/// the point and the size is not.
const SUBJECT: &str = "the release binary hyperfine measured\n";

/// The committed pattern row this module resolves, rendered back as TOML.
///
/// DERIVED, never restated: an inline regex here would drift from `batten.toml`
/// and let this tier pass over a module whose reference the real config could not
/// satisfy.
fn pattern_rows() -> String {
    let committed = common::committed_patterns();
    let row = committed
        .iter()
        .find(|pattern| pattern.id == "published-budget-value")
        .expect("the committed table declares the row the module resolves");
    format!(
        "[[pattern]]\nid = \"{}\"\nregex = '{}'\n",
        row.id, row.regex
    )
}

/// The committed verdict rows this module raises, rendered back as TOML.
///
/// Derived for `pattern_rows`' reason, and because a module raising a token no
/// row declares fails to LOAD — so a restated table that fell behind would redden
/// every case here over a module that is fine.
fn verdict_rows() -> String {
    let mut rows = String::new();
    for verdict in common::verdicts_in(&common::at_root(".")) {
        if !verdict.id.starts_with("path measure")
            && !verdict.id.starts_with("prose state")
            && !verdict.id.starts_with("source read")
        {
            continue;
        }
        rows.push_str(&format!(
            "[[verdict]]\nid = \"{}\"\ngloss = \"a fixture gloss\"\nclass = \"A fixture class.\"\n\n\
             [[verdict.route]]\nid = \"module read first\"\nkind = \"document\"\ntarget = \"policy/perf-assert.rego\"\n\n",
            verdict.id
        ));
    }
    rows
}

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "perf-assert"
kind = "policy"
scope = "tree"
lines = ["README.md"]
module = "policy/perf-assert.rego"
severity = "deny"

[[rule.tools]]
id = "perf-p95"
tool = "hyperfine"
version = "{DECLARED_VERSION}"
input = "subject.bin"

{}
{}"#,
        pattern_rows(),
        verdict_rows()
    )
}

/// A README table publishing `budget` for every path the module gates.
fn agreeing_readme() -> String {
    "| path | what it does | p50 | p95 | budget |\n\
     | ---- | ------------ | --- | --- | ------ |\n\
     | `noop` | process start | 2.1 ms | 2.4 ms | ≤ 100 ms |\n\
     | `check` | one-rule tree | 2.3 ms | 2.7 ms | ≤ 100 ms |\n\
     | `hook` | adjudication | 2.8 ms | 3.0 ms | ≤ 100 ms |\n\
     | `passthrough` | a call no rule selects | — | — | ≤ 100 ms |\n\
     | `posttool` | a PostToolUse call | — | — | ≤ 100 ms |\n\
     | `wired` | as settings.json invokes it | 8.0 ms | 8.4 ms | ≤ 100 ms |\n"
        .to_owned()
}

/// Every budgeted path measured comfortably inside its ceiling, as the producer
/// takes them: `<name> <token>` per line.
fn clean_record() -> String {
    "noop 2.4\ncheck 2.7\nhook 3.0\npassthrough 2.2\nposttool 2.3\nwired 8.4\n".to_owned()
}

/// A scratch repository carrying the fixture config, the COMMITTED module, and
/// `readme` as its README.
fn repo(name: &str, readme: Option<&str>) -> PathBuf {
    let dir = scratch(&format!("perf-assert-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "subject.bin", SUBJECT);
    if let Some(body) = readme {
        write(&dir, "README.md", body);
    }
    let module = common::at_root("policy/perf-assert.rego");
    std::fs::create_dir_all(dir.join("policy")).expect("scratch policy dir");
    std::fs::copy(module, dir.join("policy/perf-assert.rego")).expect("install committed module");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

/// Run the producer, handing it the records on stdin — the real writer, so the
/// key under test is the one the engine will look for.
fn record(dir: &Path, records: &str) {
    let outcome = run_with_stdin(dir, &["record", "tool", "perf-p95"], records);
    assert!(
        outcome.status.success(),
        "the producer must accept a well-formed record: {}",
        common::stderr(&outcome)
    );
}

fn findings(dir: &Path) -> String {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    let outcome = command.output().expect("run batten check");
    stdout(&outcome)
}

#[test]
fn a_measurement_inside_every_budget_is_silent() {
    let dir = repo("clean", Some(&agreeing_readme()));
    record(&dir, &clean_record());
    let answer = findings(&dir);
    assert!(
        answer.trim().is_empty(),
        "a clean measurement against an agreeing README decides nothing:\n{answer}"
    );
}

#[test]
fn an_over_budget_path_is_refused() {
    let dir = repo("over", Some(&agreeing_readme()));
    record(
        &dir,
        "noop 150\ncheck 2.7\nhook 3.0\npassthrough 2.2\nposttool 2.3\nwired 8.4\n",
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("perf-over-budget"),
        "a p95 over its ceiling is a finding:\n{answer}"
    );
}

#[test]
fn a_budgeted_path_absent_from_a_present_record_is_refused() {
    // PARTIAL COVERAGE IS NOT A SMALLER PASS. A run that measured five of six and
    // reported green over the five is the false green this repository keeps
    // re-meeting.
    let dir = repo("partial", Some(&agreeing_readme()));
    record(
        &dir,
        "noop 2.4\ncheck 2.7\nhook 3.0\npassthrough 2.2\nposttool 2.3\n",
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("perf-record-incomplete"),
        "a budgeted path missing from a present record is a finding:\n{answer}"
    );
}

#[test]
fn no_record_at_all_is_silent() {
    // ABSENT IS NOT INCOMPLETE, and this is the case that keeps every checkout
    // that has never run `perf` from reddening.
    let dir = repo("absent", Some(&agreeing_readme()));
    let answer = findings(&dir);
    assert!(
        answer.trim().is_empty(),
        "a tree with no record decides nothing about the measurement:\n{answer}"
    );
}

#[test]
fn a_record_does_not_survive_its_subject() {
    // THE KEYING, AND IT IS WHY THIS FAMILY WAS CHOSEN. The record is written over
    // one binary and the subject is then rebuilt; the key no longer resolves, so
    // the module abstains rather than answering from a measurement of other bytes.
    // A file of records on stdin could not state this.
    let dir = repo("rebuilt", Some(&agreeing_readme()));
    record(
        &dir,
        "noop 150\ncheck 2.7\nhook 3.0\npassthrough 2.2\nposttool 2.3\nwired 8.4\n",
    );
    write(&dir, "subject.bin", "a rebuilt binary\n");
    let answer = findings(&dir);
    assert!(
        !answer.contains("perf-over-budget"),
        "a record taken over bytes that have since changed must not answer:\n{answer}"
    );
}

#[test]
fn a_readme_publishing_a_different_budget_is_refused() {
    let dir = repo(
        "readme-disagrees",
        Some(&agreeing_readme().replace(
            "| `noop` | process start | 2.1 ms | 2.4 ms | ≤ 100 ms |",
            "| `noop` | process start | 2.1 ms | 2.4 ms | ≤ 50 ms |",
        )),
    );
    record(&dir, &clean_record());
    let answer = findings(&dir);
    assert!(
        answer.contains("perf-budget-unpublished"),
        "the published budget and the enforced one must agree:\n{answer}"
    );
}

#[test]
fn a_readme_with_no_row_for_a_budgeted_path_is_refused() {
    let dir = repo(
        "readme-short",
        Some(&agreeing_readme().replace(
            "| `wired` | as settings.json invokes it | 8.0 ms | 8.4 ms | ≤ 100 ms |\n",
            "",
        )),
    );
    record(&dir, &clean_record());
    let answer = findings(&dir);
    assert!(
        answer.contains("perf-budget-unpublished"),
        "a budgeted path README does not publish is a disagreement:\n{answer}"
    );
}

#[test]
fn an_unreadable_readme_is_reported() {
    // THE `missing` CLAUSE, over the compiled binary and never with `with input
    // as` — the whole question is whether the ENGINE routes an unacquirable
    // declared path into `input.tree.missing`, and a fabricated input would answer
    // it by construction.
    let dir = repo("no-readme", None);
    record(&dir, &clean_record());
    let answer = findings(&dir);
    assert!(
        answer.contains("perf-budget-unreadable"),
        "a declared source that could not be read is reported, never assumed clean:\n{answer}"
    );
}

#[test]
fn the_committed_readme_publishes_the_budgets_this_module_enforces() {
    // THE REAL PER-COMMIT GATE, and the case `tests/perf-assert.bats` ran on every
    // commit. It is the one assertion here whose subject is this repository rather
    // than a fixture: the committed README, the committed module, and no record at
    // all — so the measurement half abstains and only the published column is
    // judged.
    let committed =
        std::fs::read_to_string(common::at_root("README.md")).expect("README.md is committed");
    let dir = repo("committed-readme", Some(&committed));
    let answer = findings(&dir);
    assert!(
        !answer.contains("perf-budget-unpublished"),
        "README's Performance table must publish the budget `policy/perf-assert.rego` \
         enforces — move both together:\n{answer}"
    );
}
