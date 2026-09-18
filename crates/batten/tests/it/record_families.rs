//! `record keyed` / `record journal`, over the compiled binary (CLOUD-1713).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! Nothing is retired by this tier yet: this row builds the two doors and the
//! three retirements that walk through them are separate rows. The arms land
//! with them.
//!
//! # Why these three cases
//!
//! They are the ones the hand-rolled stores got RIGHT and a naive store gets
//! wrong. A store that merely reads back what it wrote passes a happy path and
//! still loses every distinction that made the shell versions correct:
//! `reclaim-census` reached for `sync -d` because a half-written append is not a
//! record, and `task::Reading` already separates "nothing" from "unreadable"
//! because a store that conflates them reports clean over one it could not open.
//!
//! Over the compiled binary rather than the library, because the exit contract is
//! half the claim: a MISS must be exit 0 with the discrimination on stdout, since
//! the engine's exit 2 means VIOLATION and a cache miss is not one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;

use common::{git_in, init_repo, run, run_with_stdin, scratch, stdout, write};

/// A repository with a git directory for the stores to live under.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("record-families-{name}"));
    write(&dir, "seed.txt", "seed\n");
    // The TEMPLATE, never a fork (CLOUD-1419). `init_repo` copies a repository
    // the harness publishes once per filesystem; a hand-rolled `git init` here
    // pays a process for what the copy already has, and the trace that motivated
    // the ratchet counted 1,819 of them in one run.
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

fn shard_dir(dir: &Path, family: &str) -> std::path::PathBuf {
    dir.join(".git")
        .join("batten-journals")
        .join(family)
        .join("journal")
        .join("shards")
}

#[test]
fn a_hit_returns_the_stored_value_and_a_miss_says_miss() {
    // THE DISCRIMINATING PAIR. A store that answered an empty string for both
    // would pass any assertion about the hit alone, and `step-receipt`'s whole
    // decision is "run the step or skip it" — so a miss that reads as an empty
    // hit skips a step nothing has verified.
    let dir = repo("hit-miss");

    let miss = run(&dir, &["record", "show", "steps", "some-key"]);
    assert_eq!(miss.status.code(), Some(0), "a miss is not a violation");
    assert_eq!(
        stdout(&miss).trim(),
        "miss",
        "an absent record must SAY miss rather than return empty"
    );

    let put = run_with_stdin(
        &dir,
        &["record", "keyed", "steps", "some-key"],
        "verdict-token\n",
    );
    assert_eq!(put.status.code(), Some(0), "the put succeeds");

    let hit = run(&dir, &["record", "show", "steps", "some-key"]);
    assert_eq!(hit.status.code(), Some(0));
    let answer = stdout(&hit);
    assert!(
        answer.starts_with("hit"),
        "a present record reads as a hit\n{answer}"
    );
    assert!(
        answer.contains("verdict-token"),
        "and carries the stored value back\n{answer}"
    );
}

#[test]
fn a_record_under_another_key_does_not_answer() {
    // THE ANTI-STALENESS CASE, and it is why the store is KEYED rather than
    // compared: a record from other inputs lives under a name nothing opens, so
    // staleness cannot be a comparison a caller forgets to make.
    let dir = repo("keying");
    // Asserted rather than discarded: a setup write that failed would leave the
    // store empty, and `miss` below would then pass for the wrong reason.
    let written = run_with_stdin(&dir, &["record", "keyed", "steps", "key-a"], "answer-a\n");
    assert!(written.status.success(), "the setup write lands");

    let other = run(&dir, &["record", "show", "steps", "key-b"]);
    assert_eq!(
        stdout(&other).trim(),
        "miss",
        "a record under another key must not answer"
    );
}

#[test]
fn a_half_written_append_is_not_a_record() {
    // THE DISCRIMINATING CASE (CLOUD-1032). A process killed mid-`write` leaves a
    // line with no terminator. `str::lines` yields it identically to a whole one,
    // so a fold built on `lines()` counts a torn record as a record — and
    // `reclaim-census` classifies a boot from the KIND of the last record under
    // it, which is precisely the value a torn tail corrupts.
    let dir = repo("torn");
    // Same reason: the torn tail below is appended to THIS record, so a failed
    // write would leave nothing for the fold to be wrong about.
    let written = run_with_stdin(&dir, &["record", "journal", "census"], "h 1000 boot-a\n");
    assert!(written.status.success(), "the setup write lands");

    // Append a torn tail the way a crash would: no trailing newline.
    let shards = shard_dir(&dir, "census");
    let shard = std::fs::read_dir(&shards)
        .expect("the shard directory exists once something was appended")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("one shard");
    let mut text = std::fs::read_to_string(&shard).expect("readable shard");
    text.push_str("x 1001 boot-a");
    std::fs::write(&shard, &text).expect("writable shard");

    let folded = run(&dir, &["record", "fold", "census"]);
    assert_eq!(folded.status.code(), Some(0));
    let answer = stdout(&folded);
    assert!(
        answer.contains("h 1000 boot-a"),
        "the terminated record still folds\n{answer}"
    );
    assert!(
        !answer.contains("x 1001"),
        "an unterminated tail is NOT a record\n{answer}"
    );
}

#[test]
fn a_fold_over_zero_records_is_nothing_rather_than_unreadable() {
    // `task::Reading`'s distinction, which is the stated precedent. A store
    // nobody has appended to has no shards, and that is a real answer — reporting
    // it as unreadable would make every fresh checkout look like a broken one,
    // and reporting an unreadable store as "no records" reads clean over a store
    // that could not be opened.
    let dir = repo("empty");
    let folded = run(&dir, &["record", "fold", "census"]);
    assert_eq!(
        folded.status.code(),
        Some(0),
        "an empty fold is not a failure"
    );
    assert_eq!(
        stdout(&folded).trim(),
        "nothing",
        "zero records is `nothing`, never `unreadable`"
    );
}

#[test]
fn every_appended_record_folds_back_in_order() {
    // THE ANTI-VACUITY MIRROR for the torn case: a fold that dropped every line
    // would also pass `a_half_written_append_is_not_a_record`.
    let dir = repo("fold-all");
    for record in ["h 1000 boot-a", "h 1001 boot-a", "x 1002 boot-a"] {
        let appended = run_with_stdin(
            &dir,
            &["record", "journal", "census"],
            &format!("{record}\n"),
        );
        assert_eq!(appended.status.code(), Some(0), "{record}");
    }
    let answer = stdout(&run(&dir, &["record", "fold", "census"]));
    let folded: Vec<&str> = answer.lines().collect();
    assert_eq!(
        folded,
        vec!["h 1000 boot-a", "h 1001 boot-a", "x 1002 boot-a"],
        "append order is the fold order within a shard"
    );
}

#[test]
fn an_empty_append_is_refused_as_usage() {
    // An empty append would put a record in the log that no fold can tell from a
    // torn one, so the writer refuses rather than the reader guessing. USAGE (1),
    // not violation (2): the caller made a mistake, this is not a policy verdict.
    let dir = repo("empty-append");
    let refused = run_with_stdin(&dir, &["record", "journal", "census"], "");
    assert_eq!(
        refused.status.code(),
        Some(1),
        "an empty append is a usage error, never a violation"
    );
}

#[test]
fn a_family_that_would_escape_its_store_is_refused() {
    // Not a security boundary so much as a silent miss: a `..` family writes
    // outside the store the reader looks in, so the write succeeds, the read finds
    // nothing, and the gate reads clean.
    let dir = repo("escape");
    let refused = run_with_stdin(&dir, &["record", "keyed", "../escape", "k"], "v\n");
    assert_eq!(refused.status.code(), Some(1));
}

// ---------------------------------------------------------------------------
// The projection: a declared family reaches a module (CLOUD-1810).
// ---------------------------------------------------------------------------

/// A module that decides from one record and nothing else.
///
/// Deliberately the thinnest thing that can tell the three states apart: it
/// reports when the record holds a `hit` line, and is undefined when the family
/// is not projected at all. A richer module would let a case pass for a reason
/// that has nothing to do with the projection.
const READS_A_FAMILY: &str = r#"# METADATA
# description: reads one verb-written record family.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.reads_a_family

import rego.v1

rules contains "record read other"

recorded := input.tree.records["measured"]

violation contains {
	"rule": "record read other",
	"verdict": "record read other",
} if {
	some line in recorded
	line == "hit"
}
"#;

/// Config registering that module, with `declares` deciding whether the family
/// is declared at all.
fn family_config(declares: bool) -> String {
    let table = if declares {
        "\n[[record]]\nrecord = \"measured\"\nwriter = \"mise run measure\"\n"
    } else {
        ""
    };
    format!(
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "record read other"
gloss = "the record this rule reads says so"
class = "A test fixture's class."

[[verdict.route]]
id = "record read first"
kind = "document"
target = "the record this rule reads"

[[rule]]
id = "record read other"
kind = "policy"
scope = "tree"
module = "policy/reads-a-family.rego"
severity = "deny"
{table}"#
    )
}

/// The tree both cases below run over, differing only in the declaration.
fn family_repo(name: &str, declares: bool) -> std::path::PathBuf {
    let dir = repo(name);
    write(&dir, "batten.toml", &family_config(declares));
    write(&dir, "policy/reads-a-family.rego", READS_A_FAMILY);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

#[test]
fn a_declared_family_reaches_the_module_that_reads_it() {
    // THE DEFECT THIS ROW EXISTS FOR (CLOUD-1810). Before the declaration table,
    // `record named` wrote a store no module could read: the key never reached
    // `input.tree.records`, every rule beneath it was undefined, and the row
    // reported clean over a record that said otherwise. Measured over
    // `branch-age`: a 36-day branch against a two-day threshold, exit 0.
    let dir = family_repo("projected", true);
    let written = run_with_stdin(
        &dir,
        &["record", "named", "measured"],
        "hit
",
    );
    assert!(written.status.success(), "the setup write lands");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a declared family's record must reach the module and decide\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn an_absent_record_under_a_declared_family_says_nothing() {
    // THE OTHER HALF OF THE PAIR, and the half a weaker tier skips. Asserting
    // only the case above passes on a projection that reads the DECLARATION
    // rather than the store — it would report the finding with nothing written.
    // Absent is could-not-look, never a pass and never a violation.
    let dir = family_repo("absent", true);

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look, so the module says nothing\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn an_undeclared_family_is_not_projected_whatever_the_store_holds() {
    // DECLARED RATHER THAN SWEPT, as an exit code. If the projection read the
    // store directory instead of the table, this record would decide — and a
    // leftover file from a retired producer would answer as a live measurement
    // with nothing naming what should be there.
    let dir = family_repo("undeclared", false);
    let written = run_with_stdin(&dir, &["record", "named", "measured"], "hit\n");
    assert!(written.status.success(), "the setup write lands");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an undeclared family is not a family, whatever sits in its store\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}
