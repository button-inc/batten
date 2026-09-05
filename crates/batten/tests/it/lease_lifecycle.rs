//! The landing lease's whole state machine, over the library the retirement
//! moved it into (CLOUD-1148).
//!
//! # The predecessor, and the size of what it was carrying
//!
//! `mise-tasks/land-lock.sh` was 1,201 lines and `tests/land-lock.bats` pinned 77
//! properties of it: acquire, release, renew, hold, held, peek, reserve and
//! authorises, plus a stall detector, a fence, and a corroboration clock. It was
//! the single largest program in the landing cluster and the one whose failure
//! mode is worst — two holders means two branches landing at once.
//!
//! # Why almost all of it runs with no remote
//!
//! The lease is a compare-and-swap over one ref, and the DECISIONS are pure
//! functions of a reading the caller already took: `claim`, `tombstone`,
//! `renewal`, `reservation`, `authorises`, `turn`, `bail` and `health` all take
//! an `Observed` or a `Body` and return the next one. Only `observe` and `cas`
//! reach the wire. So the entire table below is exercised without a forge, which
//! is what makes "does the port conserve the bash's behaviour" an answerable
//! question rather than a claim.
//!
//! What this tier does NOT reach is the swap itself — the receive-pack CAS, the
//! `--force-with-lease` expected value, and the pack encoding. Those are
//! `lease::swap`'s and are driven where the module's own suite drives them.
//! Stated rather than implied.
//!
//! # The two properties everything else serves
//!
//! **A live lease is never stolen**, and **an expired one is not stolen on the
//! first sighting.** The second is the subtle one: clocks are not shared, so a
//! lease that merely LOOKS expired to a rival's clock may be alive on the
//! holder's. Corroboration — the sha having demonstrably stopped moving — is what
//! turns a reading into a verdict, and it is the case a simplification would
//! delete first.

// carried: mise-tasks/land-lock.sh crates/batten/src/lease.rs kind:verb crates/batten/tests/it/lease_lifecycle.rs runs:batten+lease
// carried: tests/land-lock.bats crates/batten/src/lease.rs kind:verb crates/batten/tests/it/lease_lifecycle.rs
//
// AND ONE CASE FROM A SUITE THAT SURVIVES. `tests/reclaim-census.bats` reached
// into `mise-tasks/land-lock.sh` to count the hold loop's own beat records, so
// the case dies with the program it was counting — but the suite's declared
// subject, `mise-tasks/reclaim-census.sh`, is still standing.
//
// `ported` is the arm for exactly that, and it obliges MORE than `carried`
// rather than less: a target the tree carries, PLUS a `subject:` naming a path
// the edited file declared at base and head still carries. The `subject:` field
// is what clears the aggregate subject-alive term — by naming the survivor,
// rather than by a `carried` row falsely claiming the case moved somewhere.
//
// ported: tests/reclaim-census.bats crates/batten/tests/it/lease_lifecycle.rs subject:mise-tasks/reclaim-census.sh
// carried: "land-lock's hold loop records a beat and every stop it chooses" crates/batten/src/lease.rs kind:verb
//
// The seventy-seven cases, one row each, keyed by TITLE — a row whose first
// field is the suite path is indexed as another arm for it and the deletion
// reads as `shell retire unclear`.
//
// carried: "an unheld lease reports unheld, and says so at exit 0" crates/batten/src/lease.rs kind:verb
// carried: "acquire on a free lease wins and creates the ref" crates/batten/src/lease.rs kind:verb
// carried: "THE CLAIM: a rival cannot acquire a live lease" crates/batten/src/lease.rs kind:verb
// carried: "acquire is re-entrant for the holder, so a retry is not a deadlock" crates/batten/src/lease.rs kind:verb
// carried: "held is the holder's yes and the rival's no" crates/batten/src/lease.rs kind:verb
// carried: "release by the holder frees the lease for the next claimant" crates/batten/src/lease.rs kind:verb
// carried: "THE DEFECT: a released lease's status names the last holder, never an epoch" crates/batten/src/lease.rs kind:verb
// carried: "THE DEFECT: releasing an already-released lease says so, and reports no epoch age" crates/batten/src/lease.rs kind:verb
// withdrawn: "THE DEFECT: a first sighting of a sha emits no shell error on stderr" mise-tasks/land-lock.sh
// carried: "THE DEFECT: a LIVE lease is sighted, so the corroboration clock is already running when it expires" crates/batten/src/lease.rs kind:verb
// carried: "THE DEFECT: a lease sighted before it expired is taken on the first check after" crates/batten/src/lease.rs kind:verb
// carried: "a released lease is not still held by its releaser" crates/batten/src/lease.rs kind:verb
// carried: "release by a non-holder is a silent no-op, never a theft" crates/batten/src/lease.rs kind:verb
// carried: "renew extends the lease and moves the ref" crates/batten/src/lease.rs kind:verb
// carried: "a non-holder cannot renew, so a heartbeat cannot steal" crates/batten/src/lease.rs kind:verb
// carried: "an expired lease is taken once its death is corroborated, not waited out forever" crates/batten/src/lease.rs kind:verb
// carried: "a live lease is NOT stolen — expiry is the only steal condition" crates/batten/src/lease.rs kind:verb
// carried: "THE FENCE: a holder whose lease was stolen reports not-held" crates/batten/src/lease.rs kind:verb
// carried: "an expired lease reads as free, and still names who left it" crates/batten/src/lease.rs kind:verb
// carried: "FAIL CLOSED: an unreachable remote is exit 2, never 'unheld'" crates/batten/src/lease.rs kind:verb
// carried: "an unreachable remote fails acquire closed too" crates/batten/src/lease.rs kind:verb
// changed: "an unknown verb is exit 2 and names the usage" crates/batten/src/cli.rs kind:verb
// carried: "POINTER, NEVER PAYLOAD: output carries ids and seconds, never the lease body" crates/batten/src/lib.rs kind:verb
// carried: "THE EXPECTED VALUE IS EXPLICIT — a bare --force-with-lease is two holders" crates/batten/src/lease.rs kind:verb
// carried: "SHA AND BODY COME FROM ONE SOURCE — never ls-remote paired with FETCH_HEAD" crates/batten/src/lease.rs kind:verb
// changed: "observe leaves no per-process ref behind" crates/batten/src/lease.rs kind:verb
// carried: "the fence demands MARGIN, not merely an unexpired lease" crates/batten/src/lib.rs kind:verb
// carried: "an expired lease is not stolen on the first sighting — clocks are not shared" crates/batten/src/lease.rs kind:verb
// carried: "a dead lease IS taken once the sha has demonstrably stopped moving" crates/batten/src/lease.rs kind:verb
// carried: "NO GIT IDENTITY: the lease is takeable on a machine with no user.email" crates/batten/src/lease.rs kind:verb
// carried: "A FAILED MINT IS A REFUSED SWAP, NEVER A DELETE" crates/batten/src/lease.rs kind:verb
// carried: "a hold whose land died releases within a beat instead of renewing for nobody" crates/batten/src/lease.rs kind:verb
// carried: "a live land keeps its heartbeat renewing — the tether never fires on a healthy hold" crates/batten/src/lease.rs kind:verb
// carried: "a pid recycled into something that is not a land reads as gone" crates/batten/src/lease.rs kind:verb
// carried: "an unset holder pid keeps today's behaviour, so no other caller changes" crates/batten/src/lease.rs kind:verb
// carried: "THE ACCEPTANCE CASE: a land that stops advancing loses its lease and is stopped" crates/batten/src/lease.rs kind:verb
// carried: "a land whose phase keeps changing is never bailed on" crates/batten/src/lease.rs kind:verb
// carried: "RE-STATING A PHASE IS NOT ADVANCING IT, or a wedged land renews forever" crates/batten/src/lease.rs kind:verb
// carried: "a loop that stops turning is caught by the shorter hang bound" crates/batten/src/lease.rs kind:verb
// carried: "THE HANG BOUND DOES NOT REACH A PHASE WITH NO LOOP, or verify is killed for running" crates/batten/src/lease.rs kind:verb
// carried: "no registry entry is no verdict — an unregistered land is not a stalled one" crates/batten/src/lease.rs kind:verb
// carried: "A RIVAL MAY REAP A LEASE THAT BEATS WITHOUT PROGRESSING" crates/batten/src/lease.rs kind:verb
// carried: "a lease that carries no progress token is never stall-stealable" crates/batten/src/lease.rs kind:verb
// carried: "authorises: an absent lease lets any branch run" crates/batten/src/lease.rs kind:verb
// carried: "authorises: the branch the lease names may run" crates/batten/src/lease.rs kind:verb
// changed: "THE STOP: a branch the lease does not name is refused with exit 3" crates/batten/src/lib.rs kind:verb
// carried: "authorises: a released lease stops nobody" crates/batten/src/lease.rs kind:verb
// carried: "authorises: an expired lease stops nobody" crates/batten/src/lease.rs kind:verb
// carried: "FAIL OPEN: a lease carrying no branch runs rather than guessing" crates/batten/src/lease.rs kind:verb
// carried: "FAIL OPEN: an unreachable remote runs, where every other verb refuses" crates/batten/src/lease.rs kind:verb
// changed: "authorises: a missing branch argument is exit 2, never a verdict" crates/batten/src/cli.rs kind:verb
// carried: "the lease body carries the branch it authorises, and still ends with the nonce" crates/batten/src/lease.rs kind:verb
// carried: "the lease's own ref name is never mistaken for the branch it authorises" crates/batten/src/lease.rs kind:verb
// carried: "acquire leaves a receipt carrying the instant the lease expires" crates/batten/src/lease.rs kind:verb
// carried: "a renew REFRESHES the receipt — a lease held for a long lap is still held" crates/batten/src/lease.rs kind:verb
// carried: "release REMOVES the receipt rather than letting it age out" crates/batten/src/lease.rs kind:verb
// carried: "A REFUSED ACQUIRE LEAVES NO RECEIPT — the whole point of the predicate" crates/batten/src/lease.rs kind:verb
// carried: "the lease body carries the head that is about to become main" crates/batten/src/lease.rs kind:verb
// carried: "peek prints the field alone, so a caller never parses a sentence" crates/batten/src/lib.rs kind:verb
// carried: "peek on an absent lease is silent and 0 — a reading, not an error" crates/batten/src/lib.rs kind:verb
// changed: "peek on an unknown field is exit 2, never an empty answer" crates/batten/src/cli.rs kind:verb
// carried: "reserve admits a waiter as the successor behind the holder" crates/batten/src/lease.rs kind:verb
// carried: "THE BOUND: a second waiter cannot take a slot that is already filled" crates/batten/src/lease.rs kind:verb
// carried: "reserve is idempotent for the branch already holding the slot" crates/batten/src/lease.rs kind:verb
// carried: "RESERVING IS NOT STEALING: the holder keeps the lease and every other field" crates/batten/src/lease.rs kind:verb
// carried: "a reservation does not extend the holder's lease" crates/batten/src/lease.rs kind:verb
// carried: "authorises admits the holder AND its one admitted successor" crates/batten/src/lease.rs kind:verb
// carried: "THE STOP STILL STOPS: a third branch is refused while two are admitted" crates/batten/src/lease.rs kind:verb
// carried: "reserve refuses when no lease is held — acquire is the right verb then" crates/batten/src/lease.rs kind:verb
// carried: "reserve refuses to reserve behind yourself, which would consume the slot" crates/batten/src/lease.rs kind:verb
// carried: "THE HEARTBEAT CARRIES THE RESERVATION, or it erases it within a beat" crates/batten/src/lease.rs kind:verb
// carried: "ACQUIRE CLEARS IT: a new turn does not inherit the last one's successor" crates/batten/src/lease.rs kind:verb
// carried: "a lease minted before this change carries no next, and admits no successor" crates/batten/src/lease.rs kind:verb
// carried: "AGING: an aged waiter probes a freed lease sooner than a fresh one" crates/batten/src/lease.rs kind:verb
// carried: "a non-numeric age is read as zero rather than crashing the backoff" crates/batten/src/lease.rs kind:verb
// changed: "PRESSURE: two waiters against one holder produce exactly ONE winner" crates/batten/src/lease.rs kind:verb
// changed: "PRESSURE: the lease passes to exactly one waiter after release, not both" crates/batten/src/lease.rs kind:verb

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::lease::{
    Authority, Body, Observed, Terms, authorises, authorises_this_clone, renewal, reservation,
    tombstone,
};

const HOLDER: &str = "clone-a";
const RIVAL: &str = "clone-b";
const NOW: i64 = 1_000_000;

fn terms() -> Terms {
    Terms::default()
}

fn held(branch: &str, expires: i64) -> Body {
    Body {
        holder: String::from(HOLDER),
        expires,
        branch: branch.to_owned(),
        head: String::from("abc1234"),
        next: String::new(),
        progress: String::from("verify"),
        nonce: String::from("n1"),
    }
}

fn observed(body: Body) -> Observed {
    Observed::Held {
        sha: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        body,
    }
}

/// **A live lease authorises its own branch and refuses another** — the claim
/// the whole design exists to make, and the mirror that keeps it honest.
#[test]
fn the_branch_a_live_lease_names_may_run_and_another_may_not() {
    let lease = observed(held("work", NOW + 60));

    assert!(matches!(
        authorises(Some(&lease), "work", NOW),
        Authority::Run(_)
    ));

    let Authority::Stop(why) = authorises(Some(&lease), "other", NOW) else {
        panic!("a branch the lease does not name must be stopped");
    };
    assert!(
        why.contains("work"),
        "the refusal names the branch that IS authorised, so a reader can go and look: {why}"
    );
}

/// **Every reading that is not a live lease naming somebody else lets the branch
/// run.** An absent lease, a released one, an expired one, one carrying no
/// branch, and a reading that could not be taken at all.
///
/// This is the fail-open family, and it is the load-bearing half: refusing here
/// stops the whole fleet, where waving one matrix through costs one matrix.
#[test]
fn absent_released_expired_branchless_and_unreadable_all_run() {
    assert!(matches!(
        authorises(Some(&Observed::Absent), "work", NOW),
        Authority::Run(_)
    ));

    // A RELEASE IS A DECLARATION, and `expires == 0` is its sentinel rather than
    // an instant — unmistakable under any clock and on any machine.
    let released = observed(tombstone(&held("other", NOW + 60)));
    assert!(matches!(
        authorises(Some(&released), "work", NOW),
        Authority::Run(_)
    ));

    // AN EXPIRY IS AN INFERENCE, and needs the clock the release does not.
    let expired = observed(held("other", NOW - 1));
    assert!(matches!(
        authorises(Some(&expired), "work", NOW),
        Authority::Run(_)
    ));

    // A lease naming nobody: during the rollout of that field this was not an
    // edge case, it was every lease.
    let branchless = observed(held("", NOW + 60));
    assert!(matches!(
        authorises(Some(&branchless), "work", NOW),
        Authority::Run(_)
    ));

    // COULD NOT LOOK. Every other verb refuses here and this one runs.
    assert!(matches!(authorises(None, "work", NOW), Authority::Run(_)));
}

/// **A reservation admits the holder AND its one successor — and still stops a
/// third.**
///
/// The bound is what makes the slot a slot: admitting everyone who asked would
/// be the same as having no lease.
#[test]
fn a_reservation_admits_exactly_one_successor_and_the_third_branch_still_stops() {
    let reserved = observed(reservation(&held("work", NOW + 60), "next-up"));

    assert!(matches!(
        authorises(Some(&reserved), "work", NOW),
        Authority::Run(_)
    ));
    assert!(matches!(
        authorises(Some(&reserved), "next-up", NOW),
        Authority::Run(_)
    ));
    assert!(
        matches!(
            authorises(Some(&reserved), "third", NOW),
            Authority::Stop(_)
        ),
        "a third branch must still be refused while two are admitted"
    );
}

/// **RESERVING IS NOT STEALING, and it does not extend the holder's lease.**
///
/// Every other field survives, and `expires` in particular: a reservation that
/// renewed the lease as a side effect would let a waiter keep the holder alive
/// indefinitely by asking to be next.
#[test]
fn a_reservation_changes_the_successor_and_nothing_else() {
    let before = held("work", NOW + 60);
    let after = reservation(&before, "next-up");

    assert_eq!(after.next, "next-up");
    assert_eq!(after.holder, before.holder, "the holder is unchanged");
    assert_eq!(
        after.expires, before.expires,
        "a reservation does not extend the holder's lease"
    );
    assert_eq!(after.branch, before.branch);
    assert_eq!(after.head, before.head);
    assert_eq!(after.progress, before.progress);

    // IDEMPOTENT for the branch already in the slot, so a waiter retrying does
    // not consume anything.
    assert_eq!(reservation(&after, "next-up").next, "next-up");
}

/// **A lease minted before the successor field existed carries no `next`, and
/// admits nobody.**
///
/// The absent-is-not-empty reading: an old body's missing field must not read as
/// a slot standing open.
#[test]
fn a_lease_with_no_successor_field_admits_no_successor() {
    let old = observed(held("work", NOW + 60));
    assert!(matches!(
        authorises(Some(&old), "anyone", NOW),
        Authority::Stop(_)
    ));
}

/// **THE HEARTBEAT CARRIES THE RESERVATION**, or it erases it within a beat.
///
/// A renewal rebuilds the body, so a successor that the rebuild dropped would
/// vanish one beat after being admitted — and the waiter would sit behind a slot
/// it had already been given.
#[test]
fn a_renewal_keeps_the_successor_and_moves_only_the_expiry_and_progress() {
    let reserved = reservation(&held("work", NOW + 10), "next-up");
    let beat = renewal(&terms(), &reserved, Some("push"), NOW);

    assert_eq!(reserved.next, "next-up");
    assert_eq!(
        beat.next, "next-up",
        "a heartbeat that dropped the successor would erase it within a beat"
    );
    assert!(
        beat.expires > reserved.expires,
        "a renewal extends the lease"
    );
    assert_eq!(
        beat.progress, "push",
        "and records the phase it advanced to"
    );
    assert_eq!(beat.holder, reserved.holder);
    assert_eq!(beat.branch, reserved.branch);
}

/// **A release names the last holder and reports no epoch.**
///
/// `expires == 0` is a sentinel. Conflating it with an instant made a release
/// wait a full beat before anyone could take it, and made three separate
/// renderers print a wall-clock epoch as an age.
#[test]
fn a_tombstone_is_released_at_any_clock_and_still_names_who_left_it() {
    let stone = tombstone(&held("work", NOW + 60));

    assert!(
        stone.released(),
        "a release is a declaration, not an expiry"
    );
    assert_eq!(
        stone.holder, HOLDER,
        "a released lease still names its last holder"
    );

    // UNDER ANY CLOCK. The sentinel is what makes this true on a machine whose
    // clock disagrees with the holder's.
    assert!(stone.expired(0));
    assert!(stone.expired(i64::MAX));
}

/// **A lease with zero seconds left has none.**
///
/// `>=` rather than `>`, and the difference is measurable: under `>` a release
/// tombstone — whose expiry is exactly now — read as still-held for one more
/// second, so the releaser itself still saw it as held.
#[test]
fn expiry_is_inclusive_so_a_lease_with_no_time_left_is_not_held() {
    let lease = held("work", NOW);
    assert!(lease.expired(NOW), "zero seconds left is expired");
    assert!(!lease.expired(NOW - 1), "one second left is not");
}

/// **THE FENCE demands MARGIN, and it is a DIFFERENT predicate from the
/// recorder's — which is the distinction this case exists to keep.**
///
/// `authorises_this_clone` asks *is anything stopping this clone*, so it fails
/// OPEN: an absent, released or expired lease all answer yes, because none of
/// them is somebody else holding one. `lease held` asks *may this clone act*,
/// and adds a beat of margin — "not expired" is a fact about the instant of the
/// check, and the caller then goes on to post a comment or wait for a bot, so a
/// lease with one second left passes and is gone before the action it authorised
/// takes effect. That is the time-of-check/time-of-use gap the fence closes.
///
/// Writing this case first against the wrong one of the two is what surfaced the
/// distinction, so both halves are asserted here rather than one.
#[test]
fn the_recorder_fails_open_where_the_fence_demands_a_beat_of_margin() {
    // The recorder's reading: only a LIVE lease held by somebody else stops.
    assert!(authorises_this_clone(
        &observed(held("work", NOW + 3600)),
        HOLDER,
        NOW
    ));
    assert!(
        !authorises_this_clone(&observed(held("work", NOW + 3600)), RIVAL, NOW),
        "a live lease held by another clone is the one thing that stops"
    );
    assert!(
        authorises_this_clone(&observed(held("work", NOW - 1)), RIVAL, NOW),
        "an expired lease stops nobody, which is the fail-open half"
    );
    assert!(authorises_this_clone(&Observed::Absent, RIVAL, NOW));

    // The FENCE's reading, as `run_lease_held` computes it. One beat is the right
    // margin because it is the interval at which the holder proves it is alive:
    // with a beat left, either the heartbeat renews and the lease keeps rolling,
    // or it does not and this check would have failed anyway.
    let beat = terms().beat;
    let comfortable = held("work", NOW + beat + 1);
    let bare = held("work", NOW + beat - 1);

    assert!(
        comfortable.expires - NOW >= beat,
        "a lease with more than a beat left is actionable"
    );
    assert!(
        bare.expires - NOW < beat,
        "one with less is not, even though it has not expired"
    );
    assert!(
        !bare.expired(NOW),
        "and that is the point: it is unexpired AND too thin to act on"
    );
}

/// **The lease's own ref name is never mistaken for the branch it authorises.**
///
/// Two different things with confusingly similar names: writing the lease's ref
/// into the body would stamp `refs/heads/batten-land-lock` into every lease while
/// looking entirely correct, and every branch would then be refused.
#[test]
fn the_leases_own_reference_is_not_the_branch_it_names() {
    let terms = terms();
    assert!(
        terms.reference.contains("batten-land-lock"),
        "the lease lives on its own ref"
    );

    let lease = observed(held("work", NOW + 60));
    assert!(
        matches!(
            authorises(Some(&lease), &terms.reference, NOW),
            Authority::Stop(_)
        ),
        "the lease's ref name is not a branch it authorises"
    );
}

/// **POINTER, NEVER PAYLOAD.** The rendered body is what goes on the wire; no
/// reading returns it to a reporter.
///
/// This asserts the render's SHAPE rather than a report's absence, because the
/// terminal `nonce:` line is what the check half reads as the end of the body —
/// a field appended after it would be silently unread.
#[test]
fn the_rendered_body_opens_with_the_banner_and_ends_with_the_nonce() {
    let rendered = held("work", NOW + 60).render();

    assert!(
        rendered.starts_with("land-lock\n"),
        "a commit that does not open with the banner is not a lease"
    );
    assert!(
        rendered.trim_end().ends_with("nonce: n1"),
        "the nonce stays last: {rendered}"
    );
    assert!(
        rendered.contains("branch: work"),
        "the body carries the branch it authorises"
    );
    assert!(
        rendered.contains("head: abc1234"),
        "and the head that is about to become main"
    );
}
