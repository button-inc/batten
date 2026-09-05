//! The runner's step-0 guard, over the library the retirement moved it into
//! (CLOUD-420, CLOUD-1148).
//!
//! # THIS GATE IS THE OPPOSITE OF EVERY OTHER REFUSAL HERE
//!
//! Everything else in this repository fails CLOSED. This one fails open, on an
//! asymmetry that is the whole justification: a reading it could not take would
//! stop **every job in the fleet**, where waving one matrix through costs one
//! matrix. So the majority of the cases below are fail-open arms, and they are
//! the load-bearing ones — the two that stop are easy to keep and the ten that
//! run are what a well-meaning "tighten this up" would break.
//!
//! # What this tier reaches
//!
//! `lease::guard` composes two readings the caller already took, so the entire
//! decision table runs with no forge and no clock. `lease::authorises` and
//! `lease::carries` resolve those readings and are exercised where they are
//! resolved; `crates/batten/tests/it/lease_health.rs` is the sibling tier over
//! `lease check`'s own reading.
//!
//! What it does NOT reach is the workflow step: the exit code, the `::error::`
//! annotation at column 0, and the cancellation of the run the guard is standing
//! in are `run_lease_guard`'s and `report_guard`'s. Stated rather than implied.

// carried: mise-tasks/ci-lease-precondition.sh crates/batten/src/lease.rs kind:mechanism crates/batten/tests/it/lease_precondition.rs runs:batten+lease+guard
// carried: tests/ci-lease-precondition.bats crates/batten/src/lease.rs kind:mechanism crates/batten/tests/it/lease_precondition.rs
//
// The twenty-two cases, one row each, keyed by TITLE — a row whose first field
// is the suite path is indexed as another arm for it and the deletion reads as
// `shell retire unclear`.
//
// carried: "a current head with a free lease runs, and cancels nothing" crates/batten/src/lease.rs kind:mechanism
// carried: "a lease that authorises another branch STOPS this run — the acceptance case" crates/batten/src/lease.rs kind:mechanism
// carried: "THE STALENESS ROW: a head whose land does not take the lease is stopped" crates/batten/src/lease.rs kind:mechanism
// carried: "the staleness refusal names the remedy, not merely the refusal" crates/batten/src/lease.rs kind:mechanism
// carried: "a stale head is stopped WITHOUT consulting the lease — it cannot be judged by it" crates/batten/src/lease.rs kind:mechanism
// changed: "the head sha is read from LEASE_HEAD_SHA, and its absence is said out loud" crates/batten/src/lib.rs kind:mechanism
// carried: "FAIL OPEN: an unreadable head land is not judged" crates/batten/src/lease.rs kind:mechanism
// carried: "FAIL OPEN: an unreadable land-lock runs rather than stopping the fleet" crates/batten/src/lease.rs kind:mechanism
// changed: "FAIL OPEN: an answer that is neither run nor stop runs" crates/batten/src/lease.rs kind:mechanism
// withdrawn: "CLOUD-420: A WORKSPACE THAT CANNOT BE BUILT STILL EXITS 0" mise-tasks/ci-lease-precondition.sh
// withdrawn: "CLOUD-420: a broken workspace is not reported as land-lock's answer" mise-tasks/ci-lease-precondition.sh
// changed: "FAIL OPEN: a refused cancellation runs rather than reddening" crates/batten/src/lib.rs kind:mechanism
// changed: "FAIL OPEN: no run id means there is nothing to cancel" crates/batten/src/lib.rs kind:mechanism
// changed: "FAIL OPEN: no repository and no head ref each run" crates/batten/src/lib.rs kind:mechanism
// carried: "the branch under judgement is the one passed to land-lock" crates/batten/src/lease.rs kind:mechanism
// carried: "the token never reaches the log, on any path" crates/batten/src/rest.rs kind:mechanism
// carried: "a branch that lands through /fast-forward is not judged, in either row" crates/batten/src/lease.rs kind:mechanism
// carried: "the retired bot's prefix is judged like any other branch (CLOUD-660)" crates/batten/src/lease.rs kind:mechanism
// carried: "the exemption is a prefix on the landing path, not a substring anywhere in the ref" crates/batten/src/lease.rs kind:mechanism
// changed: "the ambient Actions run id is the fallback, and it is the run this is standing in" crates/batten/src/lib.rs kind:mechanism
// changed: "the lease refusal is a real annotation, not a log line the runner ignores" crates/batten/src/lib.rs kind:mechanism
// changed: "the staleness remedy is a real annotation too — it is the actionable one" crates/batten/src/lib.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::lease::{Authority, Carries, Guarded, guard, lands_by_fast_forward};

fn stale() -> Carries {
    Carries::Stale {
        wanted: String::from("abc1234"),
    }
}

fn unknown(because: &str) -> Carries {
    Carries::Unknown {
        because: because.to_owned(),
    }
}

/// **A current head with a free lease runs**, and **a lease naming somebody else
/// stops it.** The acceptance pair, in one body because either alone passes over
/// a guard that answers one way always.
#[test]
fn a_free_lease_runs_and_one_naming_another_branch_stops() {
    let free = Authority::Run(String::from("the lease is free"));
    assert!(matches!(
        guard(&Carries::Current, Some(&free)),
        Guarded::Run { .. }
    ));

    let held = Authority::Stop(String::from("the lease authorises other/branch"));
    let Guarded::Stop { why } = guard(&Carries::Current, Some(&held)) else {
        panic!("a lease naming another branch must stop this run");
    };
    assert!(
        why.contains("other/branch"),
        "the refusal names the holder a reader can go and look at: {why}"
    );
}

/// **THE STALENESS ROW, and the lease is not consulted when it stops.**
///
/// A head that does not carry trunk's landing mechanism cannot be serialised
/// against the fleet — so it is not something the lease can judge, and asking
/// would be one forge read on a head that is doomed either way. The predecessor
/// set `stop` from the staleness row and entered the lease table only
/// `if [[ -z "$stop" ]]`; `None` here is that ordering, and it is not a third
/// verdict.
#[test]
fn a_stale_head_stops_without_the_lease_being_consulted_at_all() {
    let Guarded::Stop { why } = guard(&stale(), None) else {
        panic!("a stale head must stop");
    };
    assert!(why.contains("abc1234"), "the refusal names what is missing");

    // AND THE REMEDY, WHICH IS THE HALF THAT MATTERS. A stopped run is a
    // CANCELLED run with no failed step of its own, so a reader who is not told
    // sees a red check and no cause at all.
    assert!(
        why.contains("Rebase"),
        "the refusal must carry the remedy, not merely the refusal: {why}"
    );

    // The lease cannot rescue it either — staleness is decided first, so an
    // authority that says run does not reach the answer.
    let free = Authority::Run(String::from("the lease is free"));
    assert!(matches!(guard(&stale(), Some(&free)), Guarded::Stop { .. }));
}

/// **FAIL OPEN, on every could-not-look.**
///
/// The load-bearing family. An unreadable head, an unreadable lease, and an
/// absent authority all RUN — because a reading this gate could not take would
/// stop every job in the fleet.
#[test]
fn every_reading_that_could_not_be_taken_runs_rather_than_stopping_the_fleet() {
    // The head's age could not be judged.
    let Guarded::Run { why } = guard(&unknown("no trunk ref to compare against"), None) else {
        panic!("an unreadable head must run");
    };
    assert!(
        why.contains("not judging"),
        "a green step says why it did not judge: {why}"
    );

    // The lease could not be read at all.
    let Guarded::Run { why } = guard(&Carries::Current, None) else {
        panic!("an unreadable lease must run");
    };
    assert!(
        why.contains("could not be read"),
        "and says which reading was missing: {why}"
    );

    // THE MIRROR. Without it this case passes over a guard that runs
    // unconditionally, which is the shape a well-meaning simplification produces
    // and which no other assertion here would notice.
    let held = Authority::Stop(String::from("the lease authorises other/branch"));
    assert!(matches!(
        guard(&Carries::Current, Some(&held)),
        Guarded::Stop { .. }
    ));
}

/// **A branch that lands through the fast-forward lane is not judged**, and the
/// exemption is a PREFIX on the landing path rather than a substring anywhere in
/// the ref.
///
/// A substring test would exempt `feature/renovate-notes` — a branch nobody
/// declared — from the serialisation the whole guard exists to impose.
#[test]
fn the_carve_out_is_a_prefix_and_never_a_substring() {
    let lanes = [String::from("renovate/"), String::from("release-plz-")];

    assert!(lands_by_fast_forward("renovate/cargo-deps", &lanes));
    assert!(lands_by_fast_forward("release-plz-2026-09-05", &lanes));

    // THE SUBSTRING ESCAPE, which is the case the title names.
    assert!(
        !lands_by_fast_forward("feature/renovate-notes", &lanes),
        "a declared lane appearing mid-ref is not the lane"
    );
    // An ordinary branch, and the retired bot's own prefix — judged like any
    // other, because nothing declares it (CLOUD-660).
    assert!(!lands_by_fast_forward("claude/some-work", &lanes));
    assert!(!lands_by_fast_forward("bot/bump-thing", &lanes));

    // AN EMPTY DECLARATION EXEMPTS NOTHING rather than everything. The opposite
    // reading would switch the guard off for the whole fleet on a config typo,
    // silently and in the permissive direction.
    assert!(!lands_by_fast_forward("renovate/cargo-deps", &[]));
}
