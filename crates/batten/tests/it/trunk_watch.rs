//! The staleness poll, over the library the retirement moved it into
//! (CLOUD-1148).
//!
//! # What this tier is for
//!
//! `mise-tasks/main-watch.sh` blocked until `origin/main` advanced past a given
//! sha, polling the ref endpoint conditionally so a quiet trunk cost no rate
//! limit. `tests/main-watch.bats` pinned eight properties of that loop. Both are
//! retired here, and this file is where those eight are answered — the ledger
//! arms below name it, and `shell-retirement`'s `test port missing` arm is what
//! refuses a retirement that names no compiled tier at all.
//!
//! # What it reaches, and what it deliberately does not
//!
//! Everything the eight cases pinned is a property of the POLL'S STATE MACHINE —
//! which validator goes out next, what a `304` does and does not overwrite, when
//! a reading counts as movement, and how a server-sent floor composes with the
//! configured interval. All of that is `main_watch::Poll` plus `rest::Answer`,
//! both public and both constructible without a forge, so these cases drive the
//! real decision rather than a fixture of it.
//!
//! What they do NOT drive is the request itself. `main_watch::read` goes through
//! `rest::get`, whose seam is `$BATTEN_REST_FIXTURE` and whose caller in a lap is
//! `land::stale` — reachable only from `land lap`, which fetches from a remote
//! before it gets there. Stated rather than left implied: a reader should not
//! take this file as evidence that the endpoint path or the header spelling is
//! covered. `crates/batten/tests/it/pr_watch.rs` is where the fixture seam is
//! exercised.
//!
//! # The loop is gone on purpose, and that is the one behavioural change
//!
//! The predecessor blocked. `land::stale` asks ONCE per lap and answers `None`
//! for both *unmoved* and *could not look*. The blocking is the lap's now
//! (`land::wait`), because a module holding its own unbounded loop cannot be
//! raced without becoming a second authority over when to stop asking. The
//! disposition rows below record that against the case it changes.

// carried: mise-tasks/main-watch.sh crates/batten/src/main_watch.rs kind:mechanism crates/batten/tests/it/trunk_watch.rs
// carried: tests/main-watch.bats crates/batten/src/main_watch.rs kind:mechanism crates/batten/tests/it/trunk_watch.rs
//
// The eight cases, one row each, keyed by the TITLE rather than by the suite —
// a row whose first field were the path would be indexed as a ninth arm for it
// and the deletion would read as `shell retire unclear`. `changed` carries the
// difference rather than hiding it; a title with no row here is a behavioural
// claim nobody decided on.
//
// carried: "main having moved exits 0 and points at both ends" crates/batten/src/main_watch.rs kind:mechanism
// changed: "main standing still blocks, because losing the race is the normal case" crates/batten/src/land.rs kind:mechanism
// carried: "the second request is conditional on the first response's ETag" crates/batten/src/main_watch.rs kind:mechanism
// carried: "a 304 is not read as a change, however many arrive" crates/batten/src/main_watch.rs kind:mechanism
// carried: "movement after a run of 304s is still caught" crates/batten/src/main_watch.rs kind:mechanism
// carried: "a server-sent poll interval is honoured as a floor" crates/batten/src/main_watch.rs kind:mechanism
// carried: "a transient gh failure costs one poll, not the landing" crates/batten/src/main_watch.rs kind:mechanism
// carried: "no base to compare against is a refusal, not a silent block" crates/batten/src/main_watch.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::main_watch::Poll;
use batten::rest::Answer;

const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MOVED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// A `200` carrying a ref object, and optionally a validator.
fn ref_object(sha: &str, etag: Option<&str>) -> Answer {
    Answer {
        status: 200,
        etag: etag.map(ToOwned::to_owned),
        poll_floor: None,
        backoff: None,
        body: format!("{{\"object\":{{\"sha\":\"{sha}\"}}}}"),
    }
}

/// A `304`: no body, and the validator the server echoes back.
fn unchanged(etag: Option<&str>) -> Answer {
    Answer {
        status: 304,
        etag: etag.map(ToOwned::to_owned),
        poll_floor: None,
        backoff: None,
        body: String::new(),
    }
}

/// **`main` having moved is reported WITH the sha it moved to.**
///
/// The predecessor printed both ends — `main moved <base> -> <head>` — and the
/// pointer is the half that matters: three counts with no subject cannot be told
/// from another head's reading. `moved` returns the new sha rather than a bool
/// for exactly that reason, and the lap's own line prints both.
#[test]
fn movement_reports_where_the_trunk_went_and_not_merely_that_it_went() {
    let mut poll = Poll::default();
    poll.absorb(Some(&ref_object(MOVED, None)), 5);
    assert_eq!(poll.moved(BASE), Some(MOVED));

    // THE MIRROR, and it is not hygiene: without it this case passes over a
    // `moved` that reports every reading as movement, which is the shape that
    // costs one CI run per poll.
    assert_eq!(
        poll.moved(MOVED),
        None,
        "a reading equal to the base is not movement"
    );
}

/// **The second request carries the first response's validator.**
///
/// This IS the economy the whole design rests on: a `304` costs no rate limit,
/// which is what makes a second poller affordable beside the CI wait at all. An
/// unconditional second request would be silently correct and silently
/// expensive.
#[test]
fn the_validator_from_one_answer_is_what_the_next_request_sends() {
    let mut poll = Poll::default();
    assert_eq!(poll.etag(), None, "the first ask carries no validator");

    poll.absorb(Some(&ref_object(BASE, Some("W/\"first\""))), 5);
    assert_eq!(poll.etag(), Some("W/\"first\""));

    // A LATER ANSWER CARRYING NONE MUST NOT CLEAR IT. Without this arm one
    // validator-less response turns every request after it unconditional, and
    // nothing about the poll's behaviour would look wrong.
    poll.absorb(Some(&ref_object(BASE, None)), 5);
    assert_eq!(
        poll.etag(),
        Some("W/\"first\""),
        "an answer with no validator leaves the standing one alone"
    );
}

/// **A `304` is not a change, however many arrive — and movement after a run of
/// them is still caught.**
///
/// Two of the predecessor's cases, in one body because the second is the first's
/// anti-vacuity half: a poll that simply ignored every answer would satisfy the
/// `304` arm perfectly and never report anything at all.
#[test]
fn a_run_of_unchanged_answers_hides_nothing_from_the_reading_that_follows() {
    let mut poll = Poll::default();
    poll.absorb(Some(&ref_object(BASE, Some("W/\"one\""))), 5);
    assert_eq!(poll.moved(BASE), None);

    for _ in 0..5 {
        poll.absorb(Some(&unchanged(Some("W/\"one\""))), 5);
        assert_eq!(
            poll.moved(BASE),
            None,
            "a 304 leaves the last reading standing rather than clearing it"
        );
    }
    assert_eq!(poll.polls(), 6, "every answer is counted, 304s included");

    poll.absorb(Some(&ref_object(MOVED, Some("W/\"two\""))), 5);
    assert_eq!(
        poll.moved(BASE),
        Some(MOVED),
        "movement after a run of 304s is still caught"
    );
}

/// **A server-sent poll interval is honoured as a FLOOR, never as the pace.**
///
/// `f64` throughout, which is CLOUD-390's defect: the predecessor compared with
/// `-gt`, so a fractional value read as *the server asked for no floor* —
/// byte-identical to an absent header, and silently faster than the endpoint
/// allows.
#[test]
fn a_server_floor_raises_the_interval_and_never_lowers_it() {
    let mut poll = Poll::default();

    let mut asked = ref_object(BASE, None);
    asked.poll_floor = Some(11.0);
    assert!(
        poll.absorb(Some(&asked), 5) >= 11.0,
        "a floor above the configured interval is honoured"
    );

    // AND THE OTHER DIRECTION, which is what makes it a floor rather than an
    // override: an endpoint asking to be polled FASTER than configured does not
    // get to set the pace.
    let mut lower = ref_object(BASE, None);
    lower.poll_floor = Some(1.0);
    assert!(
        poll.absorb(Some(&lower), 30) >= 30.0,
        "a floor below the configured interval leaves it alone"
    );

    // A FRACTIONAL FLOOR IS A FLOOR. This is the exact reading the integer
    // comparison dropped, so it is asserted rather than assumed.
    let mut fractional = ref_object(BASE, None);
    fractional.poll_floor = Some(0.5);
    let paced = poll.absorb(Some(&fractional), 0);
    assert!(
        paced >= 0.5,
        "a sub-second floor is still read as one, got {paced}"
    );
}

/// **A read that did not answer costs one poll, not the landing.**
///
/// `None` is could-not-look. It is FOLDED rather than skipped — the count
/// advances and the previous reading stands — because dropping it would let an
/// unreachable forge make a bounded loop unbounded, and treating it as movement
/// would decide about the network rather than about the work.
#[test]
fn a_read_that_did_not_answer_advances_the_count_and_changes_no_reading() {
    let mut poll = Poll::default();
    poll.absorb(Some(&ref_object(BASE, Some("W/\"held\""))), 5);

    poll.absorb(None, 5);
    assert_eq!(poll.polls(), 2, "a failed read is still a poll");
    assert_eq!(
        poll.etag(),
        Some("W/\"held\""),
        "a failed read does not discard the validator"
    );
    assert_eq!(
        poll.moved(BASE),
        None,
        "a forge that did not answer is not the trunk moving"
    );
    assert_eq!(poll.head(), Some(BASE), "the previous reading still stands");
}

/// **An empty base is not a base**, and this is the arm the first port dropped.
///
/// `main-watch.bats` refuses one outright — *"no base to compare against is a
/// refusal, not a silent block"* — because an empty base compares unequal to
/// every sha, so the first poll reports movement and the lap laps forever.
/// `None` here is that refusal in the shape this type has: there is nothing to
/// have moved FROM, so nothing has moved.
///
/// Found by reading the predecessor's titles rather than by any gate, which is
/// the whole reason the dispositions above exist as rows.
#[test]
fn an_empty_base_is_not_movement_however_the_reading_came_back() {
    let mut poll = Poll::default();
    poll.absorb(Some(&ref_object(MOVED, None)), 5);
    assert_eq!(
        poll.moved(""),
        None,
        "an empty base compares unequal to every sha and must not read as movement"
    );

    // And with no reading at all, which is the state a first lap is in.
    assert_eq!(Poll::default().moved(""), None);
    assert_eq!(Poll::default().moved(BASE), None);
}
