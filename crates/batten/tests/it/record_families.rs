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

use common::{git_in, run, run_with_stdin, scratch, stdout, write};

/// A repository with a git directory for the stores to live under.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("record-families-{name}"));
    write(&dir, "seed.txt", "seed\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
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
    run_with_stdin(&dir, &["record", "keyed", "steps", "key-a"], "answer-a\n");

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
    run_with_stdin(&dir, &["record", "journal", "census"], "h 1000 boot-a\n");

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
