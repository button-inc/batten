//! Cancelling the runs a red verdict made worthless, over the library the
//! retirement moved them into (CLOUD-1148).
//!
//! # The one safety property, and everything else is secondary to it
//!
//! `final` is the context branch protection requires. It is `always()` over a
//! `needs:` assertion, so **cancelling its run leaves that context `cancelled`,
//! which is not an answer** — the branch then carries a required check that will
//! never conclude and cannot land at all. Every case here exists to make the
//! sparing arm impossible to lose quietly; the counts are what a reader sees, and
//! the spare is what keeps the branch alive.
//!
//! # What this tier reaches
//!
//! `land::worthless` is a pure function over a run list, so the whole
//! doomed/spared partition runs with no forge. `land::spending` and
//! `land::abandon` reach the REST tier and are exercised through the driver's own
//! arm rather than here; what those add over this file is one `GET` and one
//! `POST` per run, and `crates/batten/tests/it/checks_green.rs` is where the
//! request seam is driven.
//!
//! Said plainly rather than implied: a reader must not take this file as evidence
//! that the cancel endpoint is called correctly. It is evidence that the right
//! runs are chosen.

// carried: mise-tasks/abandon-matrix.sh crates/batten/src/land.rs kind:mechanism crates/batten/tests/it/abandon_matrix.rs
// carried: tests/abandon-matrix.bats crates/batten/src/land.rs kind:mechanism crates/batten/tests/it/abandon_matrix.rs
//
// The ten cases, one row each, keyed by TITLE — a row whose first field is the
// suite path is indexed as another arm for it and the deletion reads as
// `shell retire unclear`.
//
// carried: "the siblings are cancelled and the fan-in's run is spared — the acceptance case" crates/batten/src/land.rs kind:mechanism
// carried: "THE ROW THAT MATTERS: the run carrying the fan-in is never cancelled" crates/batten/src/land.rs kind:mechanism
// carried: "a fan-in declared for a file no run carries spares nothing — and still cancels the rest" crates/batten/src/land.rs kind:mechanism
// carried: "an unset fan-in declaration cancels NOTHING rather than guessing" crates/batten/src/land.rs kind:mechanism
// carried: "a refused cancellation is a pointer, not a stop — and the rest still go" crates/batten/src/land.rs kind:mechanism
// carried: "a list that will not answer stops without cancelling and without failing" crates/batten/src/land.rs kind:mechanism
// carried: "nothing in flight is a clean no-op" crates/batten/src/land.rs kind:mechanism
// carried: "a run that has already completed is not asked to cancel" crates/batten/src/land.rs kind:mechanism
// changed: "the reason is carried into the pointer, and the SHA is abbreviated" crates/batten/src/lib.rs kind:mechanism
// changed: "no SHA anywhere is a give-up rather than a guess at HEAD's neighbours" crates/batten/src/lib.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::land::{Abandoned, Spending, worthless};

const FANIN: &str = ".github/workflows/ci.yml";

fn run(id: &str, path: &str) -> Spending {
    Spending {
        id: id.to_owned(),
        path: path.to_owned(),
    }
}

/// **THE ROW THAT MATTERS: the run carrying the fan-in is never cancelled.**
///
/// The acceptance case and the safety property in one body, because they are the
/// same reading: the siblings go and the fan-in stays. Splitting them would let a
/// partition that spares everything satisfy the second alone.
#[test]
fn the_siblings_are_doomed_and_the_fan_ins_own_run_is_spared() {
    let in_flight = [
        run("1", ".github/workflows/rust.yml"),
        run("2", FANIN),
        run("3", ".github/workflows/test.yml"),
    ];
    let (doomed, spared) = worthless(&in_flight, FANIN);

    assert_eq!(spared, 1, "exactly the fan-in's run is spared");
    assert_eq!(doomed.len(), 2, "both siblings are doomed");
    assert!(
        !doomed.iter().any(|run| run.path == FANIN),
        "the fan-in's run reached the doomed list, which wedges the branch: {doomed:?}"
    );
    // The ids travel, because the cancel endpoint is addressed by id and a
    // partition that carried only paths could not act on either half.
    assert_eq!(
        doomed.iter().map(|run| run.id.as_str()).collect::<Vec<_>>(),
        vec!["1", "3"]
    );
}

/// **A fan-in declared for a file no run carries spares nothing — and still
/// cancels the rest.**
///
/// The anti-vacuity half of the case above. A partition that spared on any
/// mismatch would pass the acceptance case and quietly stop cancelling anything
/// the day a workflow was renamed, which is a leak with no symptom.
#[test]
fn a_declaration_matching_no_run_spares_nothing_and_still_dooms_the_others() {
    let in_flight = [
        run("1", ".github/workflows/rust.yml"),
        run("2", ".github/workflows/test.yml"),
    ];
    let (doomed, spared) = worthless(&in_flight, ".github/workflows/renamed.yml");

    assert_eq!(spared, 0, "no run carries the declared path");
    assert_eq!(doomed.len(), 2, "the rest are still worthless and still go");
}

/// **An unset fan-in declaration cancels NOTHING rather than guessing.**
///
/// The guard whose absence would have been worst, and the first port of this
/// dropped it: with no name to spare, EVERY run is doomed — including the one
/// carrying the fan-in, whose cancelled context is not an answer.
///
/// The refusal lives in `land::abandon` rather than in the partition, so this
/// case asserts the shape that makes it necessary: `worthless` with an empty
/// declaration spares nothing and dooms everything. The two together are the
/// whole argument, and asserting only the partition would read as approval of it.
#[test]
fn an_empty_declaration_would_doom_the_fan_in_which_is_why_abandon_refuses_first() {
    let in_flight = [run("1", ".github/workflows/rust.yml"), run("2", FANIN)];
    let (doomed, spared) = worthless(&in_flight, "");

    assert_eq!(spared, 0);
    assert_eq!(
        doomed.len(),
        2,
        "an empty declaration matches nothing, so the partition dooms the fan-in too"
    );

    // AND THE CALLER IS WHAT STOPS IT. `abandon` returns an empty report without
    // reading the forge at all when the declaration is unset — no request, no
    // cancellation, no guess. A default report is three zeroes, which is what a
    // reader sees on the lap's own line.
    assert_eq!(
        Abandoned::default(),
        Abandoned {
            cancelled: 0,
            spared: 0,
            refused: 0
        },
        "an unset declaration reports a measured nothing rather than a silence"
    );
}

/// **Nothing in flight is a clean no-op.**
///
/// Not an error and not a refusal: a head with no runs on it is the ordinary
/// state after a lap that stopped before readying, and reporting it as a failure
/// would make the compensation itself a reason to stop.
#[test]
fn an_empty_flight_list_dooms_nothing_and_spares_nothing() {
    let (doomed, spared) = worthless(&[], FANIN);
    assert!(doomed.is_empty());
    assert_eq!(spared, 0);
}

/// **Every run carrying the fan-in's path is spared, not merely the first.**
///
/// A re-run leaves two runs on one workflow file, and a partition that stopped
/// at the first match would cancel the live one. Not a case the predecessor's
/// suite carried — found by reading its titles and asking what "the run carrying
/// the fan-in" means when there are two.
#[test]
fn a_re_run_leaves_two_fan_in_runs_and_both_are_spared() {
    let in_flight = [
        run("1", FANIN),
        run("2", ".github/workflows/rust.yml"),
        run("3", FANIN),
    ];
    let (doomed, spared) = worthless(&in_flight, FANIN);

    assert_eq!(spared, 2, "both fan-in runs are spared");
    assert_eq!(doomed.len(), 1);
    assert_eq!(doomed[0].id, "2");
}
