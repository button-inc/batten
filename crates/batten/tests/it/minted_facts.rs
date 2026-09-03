//! `input.tree.minted`, over the compiled binary (CLOUD-1310).
//!
//! **A declared FIELD of a receipt the mediated boundary already wrote, bounded by
//! how old the reading is.** The engine fetches nothing: something else read the
//! subject, `[[mint]]` wrote a receipt, and a `[[rule.minted]]` row names which
//! field of it a module may see and how stale a reading is allowed to be.
//!
//! **This suite exists because the module that used to carry it does not any
//! more.** `policy/harness-wiring.rego`'s `spent` direction was the fact's first
//! and only consumer — a declared hook exemption whose owning issue had CLOSED —
//! and CLOUD-1383 deleted the exemption table with all three of its directions.
//! The four cases below came from `crates/batten/tests/it/harness_wiring.rs` and
//! are unchanged in what they assert; only the module they drive is different.
//! Deleting them with the predicate would have been coverage loss dressed as
//! cleanup, on the engine half of a row that landed the day before.
//!
//! **A `with input as` case cannot answer any of this.** It fabricates
//! `input.tree.minted` and so passes over an engine that never builds it
//! (CLOUD-845, CLOUD-857) — and the age bound is worse, because a fabricated
//! projection has already had the bound applied to it by the author. Every case
//! here writes a real receipt into a real store and asks the shipped `check`.
//!
//! **The age bound is why this family is not `captured`.** That store is keyed by
//! CONTENT and carries no clock, so a question about a MUTABLE field answers from
//! whichever read sorts first in digest order — a status read eight days ago would
//! go on saying `done` forever. Staleness has to be keyed into the projection, and
//! `a_reading_older_than_the_declared_bound_does_not_answer` is where that is
//! decided rather than argued.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The subject every case reads about.
///
/// GENERIC, NEVER THIS CONSUMER'S TRACKER PREFIX. A key shape naming a specific
/// tracker inside `crates/` is non-negotiable rule 1, which `no-tracker-key-in-core`
/// refuses — and it refuses a comment quoting one just as readily as an expression.
const SUBJECT: &str = "ROW-1";

/// How old a reading may be, in days, as the fixture row declares it.
const MAX_AGE_DAYS: u64 = 7;

fn config() -> String {
    r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[rule.minted]]
id = "subject-status"
mint = "subject-read"
field = 4
recency = 2
max_age_days = 7

# NO `[[mint]]` ROW, AND THE ABSENCE IS PART OF WHAT THIS ASSERTS. Minting is the
# MEDIATED boundary's job and happens in another process entirely; the reading
# side names the mint and the field, and nothing more. A fixture declaring a mint
# would be declaring the producer it is deliberately not running.

[[verdict]]
id = "probe closed probe"
gloss = "the declared field of the declared receipt reads as a closed subject"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe read first"
kind = "document"
target = "probe.rego"
"#
    .to_owned()
}

/// One predicate over one field, and it discriminates on the VALUE.
///
/// A rule asking only "did I read anything" would be green whether the engine
/// handed back the status field or the digest one, and could not tell a closed
/// subject from an open one — which is the entire question the fact answers.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-closed"

violation contains {
	"rule": "probe-closed",
	"verdict": "probe closed probe",
} if {
	some _, status in input.tree.minted["subject-status"]
	status in {"done", "canceled", "duplicate"}
}

test_a_closed_status_fires if {
	some v in violation with input as {"tree": {"minted": {"subject-status": {"ROW-1": "done"}}}}
	v.rule == "probe-closed"
}

test_an_open_status_does_not if {
	count(violation) == 0 with input as {"tree": {"minted": {"subject-status": {"ROW-1": "in-progress"}}}}
}

test_an_empty_map_fires_nothing if {
	count(violation) == 0 with input as {"tree": {"minted": {"subject-status": {}}}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"minted": null}}
}
"#;

/// A repository declaring the row, with no receipt store at all.
fn fixture(name: &str) -> PathBuf {
    let dir = scratch(&format!("minted-facts-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["add", "-A"]);
    dir
}

/// Write one receipt into the fixture's own receipt store.
///
/// The store is under the GIT DIRECTORY, never in the tree, which is what makes
/// this fact per-checkout and empty on any runner. The body is the `[[mint]]`
/// row's: `{id} {updatedAt} {now} {digest} {status} {ready}`, so field 4 is the
/// status and field 2 is when the reading was taken.
///
/// WRITTEN HERE RATHER THAN MINTED, which is the shape of the family: the engine
/// reads a receipt the mediated boundary wrote, so `check` spawns nothing and the
/// producer's half is somebody else's process.
fn receipt(repo: &Path, key: &str, status: &str, taken: u64) {
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("receipt store");
    std::fs::write(
        store.join(format!("subject-read.{key}")),
        format!("{key} 2026-01-01 {taken} abcd1234 {status} ready\n"),
    )
    .expect("write receipt");
}

/// Seconds since the epoch, for a receipt written "just now".
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn the_engine_reads_a_declared_field_off_a_minted_receipt() {
    // THE POSITIVE, and it is only decidable here: a `with input as` case builds
    // `input.tree.minted` itself and so passes over an engine that never does.
    // This writes a real receipt into a real store and asks the shipped `check` to
    // find it.
    let dir = fixture("closed");
    receipt(&dir, SUBJECT, "done", now());
    let outcome = check(&dir);
    assert!(
        !outcome.status.success(),
        "a closed subject was allowed: {}",
        stdout(&outcome)
    );
    assert!(
        stdout(&outcome).contains("probe"),
        "wrong finding: {}",
        stdout(&outcome)
    );
}

#[test]
fn a_different_value_in_the_same_field_does_not_fire() {
    // The other direction, and without it the case above passes over a module —
    // or an engine — that answers with any reading at all rather than with the
    // declared field's value.
    let dir = fixture("open");
    receipt(&dir, SUBJECT, "in-progress", now());
    let outcome = check(&dir);
    assert!(
        outcome.status.success(),
        "an open subject was reported closed: {}",
        stdout(&outcome)
    );
}

#[test]
fn a_reading_older_than_the_declared_bound_does_not_answer() {
    // THE AGE BOUND, and the one thing a module's own tier structurally cannot
    // reach: it fabricates the projection, so it cannot show that the ENGINE
    // dropped a stale reading before any module saw it.
    //
    // This is why the fact is not a `captured` reduction. That store is keyed by
    // content and carries no clock, so a mutable field answers from whichever read
    // sorts first by digest — here, a status read eight days ago would still say
    // `done` forever.
    let dir = fixture("stale");
    receipt(&dir, SUBJECT, "done", now() - (MAX_AGE_DAYS + 1) * 86_400);
    let outcome = check(&dir);
    assert!(
        outcome.status.success(),
        "a reading past the declared bound still answered: {}",
        stdout(&outcome)
    );
}

#[test]
fn no_receipt_store_at_all_is_could_not_look() {
    // COULD-NOT-LOOK, and it is the ORDINARY state: the store is per-checkout, so
    // every CI runner and every fresh clone has none. A module reading that absence
    // as an answer would redden everywhere for a state nobody can fix — and an
    // engine returning something other than an empty map would make that the
    // module's problem to guard rather than the fact's.
    let dir = fixture("unread");
    let outcome = check(&dir);
    assert!(
        outcome.status.success(),
        "a tree whose receipt store does not exist reported: {}",
        stderr(&outcome)
    );
}
