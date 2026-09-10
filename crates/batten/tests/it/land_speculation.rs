//! A live bet never reaches the publish (CLOUD-1681).
//!
//! # What this tier is for
//!
//! `mise-tasks/land.sh`'s invariant, quoted verbatim in `pipeline.rs`:
//!
//! > there is no path from a losing bet to a push, which is what makes
//! > speculating safe rather than merely fast.
//!
//! `Settle::Lost` has no such path — `Precheck::BetSettled` unwinds it at the top
//! of the lap. `Settle::Pending` had one, because that precheck deliberately
//! KEEPS a pending bet and the `Step::Push` row carried `precheck: None`.
//! Measured twice: four commits of another branch published under this one on
//! 2026-09-08, eight on 2026-09-10 — the second costing a full CI matrix on a
//! head that could not merge when it was graded.
//!
//! # Why a pending bet is exactly as unpublishable as a lost one
//!
//! A bet names the holder's SHAS, and the holder lands by rebase, which mints new
//! ones for the same patches. So a published pending head is not merely at risk
//! of going stale — the moment the holder lands it is DIVERGENT, and the
//! fast-forward is impossible by construction rather than by race.
//!
//! # The composition is the subject, not a lap
//!
//! Every case here decides over `Pipeline::default()` and `speculation::Bet`,
//! both of which are pure. Driving a real lap would need a remote, a lease and a
//! matrix to answer a question the step table already answers — and the defect
//! was never in the lap's execution, it was in a row that declared no question.

// Panicking on a failed assertion is how a test fails loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::land::Step;
use batten::pipeline::{Pipeline, Precheck};
use batten::speculation::Bet;

/// The row that publishes, and the question it now asks.
fn precheck_of(step: Step) -> Option<Precheck> {
    Pipeline::default()
        .steps
        .iter()
        .find(|row| row.step == step)
        .and_then(|row| row.precheck)
}

/// A bet that is outstanding, as `place_the_bet` leaves one.
fn placed() -> Bet {
    Bet {
        base: Some(String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
        undo: Some(String::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
        main_at_bet: Some(String::from("cccccccccccccccccccccccccccccccccccccccc")),
        ..Bet::default()
    }
}

/// **A LAP HOLDING A LIVE BET DOES NOT REACH THE PUSH.**
///
/// The two halves of the reading are asserted together because either alone is
/// satisfiable by the defect: the row could declare the precheck while the bet
/// answers `false`, or the bet could be live over a row that asks nothing. The
/// pair is what the lap actually evaluates.
#[test]
fn a_live_bet_is_refused_by_the_row_that_would_publish_it() {
    assert_eq!(
        precheck_of(Step::Push),
        Some(Precheck::BetLive),
        "the row that publishes must ask whether this head is publishable"
    );
    assert!(
        placed().live(),
        "a placed bet is outstanding, which is the state the precheck refuses"
    );
}

/// **THE MIRROR — A SETTLED BET STILL PUSHES.**
///
/// Without this the case above is satisfied by a pipeline that never publishes
/// at all, which is an outage rather than a fix. A holder that lands during
/// `verify` settles `Landed`, `drop_the_bet` forgets it, and the lap publishes
/// the pre-linearized head exactly as before — which is the whole value of
/// speculating and the reason this refuses `live()` rather than "a bet was ever
/// placed".
#[test]
fn a_settled_bet_still_reaches_the_push() {
    let mut settled = placed();
    settled.forget();
    assert!(
        !settled.live(),
        "a settled bet is not outstanding, so the precheck admits the push"
    );
}

/// **AND THE GATE DOES NOT SPREAD TO THE ROW THAT SPENDS THE GATE.**
///
/// `Verify` must stay unguarded on the bet, or a speculating lap could never
/// verify the tree it speculated — which is the point of speculating. Asserting
/// only that `Push` carries a precheck would pass over a table that gated every
/// row, so this is where the arm's boundary is written down.
#[test]
fn the_verify_row_is_not_gated_on_the_bet() {
    assert_eq!(
        precheck_of(Step::Verify),
        None,
        "gating the gate on the bet would stop a speculating lap verifying at all"
    );
    assert_eq!(
        precheck_of(Step::Replay),
        Some(Precheck::BetSettled),
        "and the settle stays on Replay — the two rows ask different questions"
    );
}

/// **THE TERMINATION PROPERTY, which the row's own §3 does not state.**
///
/// The precheck answers `Lap`, and no `Compensation` drops a bet — `Nothing`,
/// `Redraft`, `Abandon`, `ReleaseLease`. `place_the_bet`'s own guards are about
/// the HOLDER (already landed; trunk has passed it), so without a memory of the
/// decision the next lap re-bets the same holder, arrives back at this row, and
/// unwinds again until the lap budget is spent — rather than the one extra local
/// verify and zero CI the design promises.
///
/// `declined` is that memory, and it survives `forget` because `forget` is what
/// the unwind calls.
#[test]
fn a_declined_landing_does_not_speculate_again() {
    let mut bet = placed();
    bet.declined = true;
    bet.forget();
    assert!(
        bet.declined,
        "the decision must outlive the unwind that made it, or the lap spins"
    );
    assert!(
        !bet.live(),
        "and the borrowed range is gone, which is what the next lap replays without"
    );
}
