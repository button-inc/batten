//! The lap, and where `mise-tasks/land.sh`'s 146 cases went (CLOUD-1148).
//!
//! # What this file is
//!
//! `mise-tasks/land.sh` was 2250 lines of consumer-specific landing policy and
//! `tests/land.bats` pinned it with 146 cases. Both are retired here. This file
//! carries the ledger `policy/shell-retirement.rego` reads — two file-level arms
//! and one row per `@test` title — plus the cases that answer the one title no
//! single engine assertion already covers.
//!
//! # The per-title rows are not what the gate counts, and that is the point
//!
//! `shell-retirement` counts `arms_for(path)` and stops: two arms, one per
//! deleted path. The 146 rows below are invisible to it. They exist because
//! reading titles has produced a live defect once per suite across this whole
//! campaign, every one in code written the same session and green under its own
//! tests — an empty base reported as trunk movement, an unset fan-in cancelling
//! the fan-in's own run, `lease check` naming the holder while dropping the
//! successor, and here **four cases whose behaviour the engine did not carry at
//! all**: a refusal over a borrowed tree, a refusal caused by the machine, and
//! each one's anti-vacuity twin. Those are built rather than dispositioned;
//! `crates/batten/tests/it/land_verify_advice.rs` is where they landed.
//!
//! # Reading the arms
//!
//! `carried` — the behaviour is in the engine, at the named source. `changed` —
//! conserved with a stated difference, and the difference is the point of the
//! row. `subsumed` — folded into a broader assertion, named. `withdrawn` — the
//! declared subject died and nothing replaced it, with the reason; admissible
//! only because `mise-tasks/land.sh` dies in this same change (CLOUD-1268).
//!
//! **Ten withdrawals, and nine of them are one class**: the predecessor's own
//! process management. It forked watcher subshells, synchronised them on a FIFO,
//! tracked their pids and escalated TERM to KILL, and nine cases pinned that
//! machinery. The engine races two polls inside one process with no children, so
//! there is nothing to reap, nothing to signal and no rendezvous to create — the
//! properties are held by construction rather than by mechanism. A `carried` row
//! claiming otherwise would name a successor that does not exist, which is the
//! laundering the ledger exists to refuse.
//!
//! The tenth is the conclusion-literal sensor, whose two declared subjects are
//! both already retired.
//!
//! # Keyed by the TITLE, never by the path
//!
//! A row whose first field is the retired path is indexed as another arm FOR
//! that path, and the deletion then reads `shell retire unclear` — two arms
//! where the gate wants one. `bot_lane.rs` is the shape and `trunk_watch.rs` the
//! landed example.

// carried: mise-tasks/land.sh crates/batten/src/lib.rs kind:verb crates/batten/tests/it/land_lap.rs
// carried: tests/land.bats crates/batten/src/lib.rs kind:verb crates/batten/tests/it/land_lap.rs
//
// AND ONE CASE FROM A SUITE THAT LIVES ON. `tests/reclaim-census.bats` read the
// retired lander for its stop note; its own subject is alive, so the case is
// `ported` rather than `withdrawn` (CLOUD-1268).
// ported: "land records the stop it causes itself, or every clean landing reads as a reclaim" crates/batten/tests/it/land_lap.rs subject:mise-tasks/reclaim-census.sh
//
// The 146 titles, one row each.
//
// carried: "a refusal starts the next lap instead of ending the run" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a cancelled run is the bot failing to DECIDE, not a refusal" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a SIBLING PR's refusal is not this lap's verdict (CLOUD-409)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a keyed refusal IS still read — the filter did not stop reading" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "this lap's own run is read even when it fell off the first page (CLOUD-456)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "paging stops at the short page instead of walking history (CLOUD-456)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a /fast-forward the API refused is never reported as posted (CLOUD-408)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "CLOUD-413: a refused comment waits the retry-after the response STATES" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "CLOUD-413: with no retry-after it waits until x-ratelimit-reset" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "CLOUD-413: a response stating no limit headers still waits a floor" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "CLOUD-413: exhausting the budget names the LIMIT, not a moving main" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a 403 from the runs query is not an answer (CLOUD-414)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "an unreadable answer re-asks without buying a CI run" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "the fast-forward verdict is KEYED, not merely windowed" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a lap rebases onto the main that moved, then re-verifies the new SHA" crates/batten/src/land.rs kind:mechanism
// carried: "a conflicting rebase is the one stop, and it aborts what it started" crates/batten/src/land.rs kind:mechanism
// carried: "a failing verify stops before CI is ever asked" crates/batten/src/lib.rs kind:mechanism
// withdrawn: "CLOUD-510: a racer land killed on purpose delivers no verdict" a bash-only property: the predecessor forked a racer per lap and the case asserted a killed subshell published nothing. The engine runs one process with no children, so there is no racer to kill and no verdict channel for it to write to
// carried: "CLOUD-510: a genuine ci-wait failure still stops the lap" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-407: a refused tree stops on lap 1 and carries the gate's own pointers" crates/batten/src/lib.rs kind:mechanism
// carried: "a verify that failed only because main moved laps instead of stopping" crates/batten/src/land.rs kind:mechanism
// carried: "the lap cap's refusal states what its own accounting supports" crates/batten/src/land.rs kind:mechanism
// carried: "the two exhaustions give imperatives consistent with their costs" crates/batten/src/land.rs kind:mechanism
// carried: "a verify that keeps losing the race exhausts laps rather than spinning" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-399: the two exhaustions are told apart by CODE, not by prose" crates/batten/src/land.rs kind:mechanism
// carried: "a body that defers a decision with no ticket stops before review is asked for" crates/batten/src/lib.rs kind:mechanism
// carried: "a row this branch filed without grooming it stops before review is asked for" crates/batten/src/lib.rs kind:mechanism
// carried: "THE PR BODY REACHES filed-here-check, or its exemption is inert" crates/batten/src/lib.rs kind:mechanism
// carried: "CLOUD-995: a gate that exits before reading stdin is not a refusal" crates/batten/src/land.rs kind:mechanism
// carried: "a body that names its issue but never closes it stops before review is asked for" crates/batten/src/lib.rs kind:mechanism
// carried: "a prose-only branch stops before review is asked for" crates/batten/src/lib.rs kind:mechanism
// carried: "a missing verify receipt stops the lap" crates/batten/src/lib.rs kind:mechanism
// carried: "red CI stops the lap without asking for the merge" crates/batten/src/land.rs kind:mechanism
// carried: "a run CI DECLINED is a stop, not a red — the agent is told to rebase" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-470: the declination is asked of land-lock, not re-derived" crates/batten/src/land.rs kind:mechanism
// carried: "a verdict that could not be READ is not a red one" crates/batten/src/checks_green.rs kind:mechanism
// carried: "an unset required roster stops rather than readying (CLOUD-467)" crates/batten/src/checks_green.rs kind:mechanism
// carried: "CLOUD-376: an unset ANSWERED set stops rather than readying, for the same reason" crates/batten/src/checks_green.rs kind:mechanism
// withdrawn: "CLOUD-376: no conclusion name is written in mise-tasks outside the manifest" both declared subjects are retired — `mise-tasks/land.sh` dies in this change and `mise-tasks/checks-green.sh` is already gone — so the case has no source to read. The property is structural in the engine: a conclusion literal inside `crates/batten` is non-negotiable rule 1's own violation, which `document_facts.rs` refuses
// carried: "a rejected push stops rather than clobbering someone else's branch" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-345: a branch ABSENT from the remote is a stale ref, not a rival" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-345: every fetch prunes, so a deleted upstream leaves no expectation" crates/batten/src/land.rs kind:mechanism
// carried: "an unfetchable origin stops instead of lapping on a stale main" crates/batten/src/land.rs kind:mechanism
// carried: "endless refusals hit the lap cap rather than lapping forever" crates/batten/src/lib.rs kind:mechanism
// carried: "land refuses to run from main" crates/batten/src/lib.rs kind:mechanism
// carried: "a merged PR exits 0" crates/batten/src/lib.rs kind:mechanism
// carried: "a PR that closed without merging exits non-zero" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a run still in progress concludes neither way, and the poll continues" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a run that predates this lap is not read as a verdict on it" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "the merge is what it waits for, not the comment" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "the poll carries no wall-clock timeout" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "a branch with no OPEN PR has nothing to land" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "THE MERGED-NAME CASE: a branch whose old PR merged binds the OPEN one (CLOUD-465)" crates/batten/src/fast_forward.rs kind:mechanism
// carried: "an already-proven HEAD is not proven again" crates/batten/src/lib.rs kind:mechanism
// carried: "main moving mid-wait starts the next lap instead of paying out the run" crates/batten/src/land.rs kind:mechanism
// carried: "a red CI re-drafts the PR before stopping" crates/batten/src/land.rs kind:mechanism
// carried: "a landing interrupted on an ungraded head re-drafts, not only a red one" crates/batten/src/land.rs kind:mechanism
// carried: "the same interruption over a green head leaves it ready" crates/batten/src/land.rs kind:mechanism
// carried: "a head whose verdict could not be read is left ready, never stranded" crates/batten/src/land.rs kind:mechanism
// carried: "a landing that merges leaves the PR alone" crates/batten/src/lib.rs kind:mechanism
// carried: "a refused second land does not re-draft the live one's PR" crates/batten/src/land.rs kind:mechanism
// carried: "a re-draft that cannot happen does not change the exit code" crates/batten/src/lib.rs kind:mechanism
// carried: "a draft PR is readied, which is the event that spends the run" crates/batten/src/land.rs kind:mechanism
// carried: "nothing is readied when the head already carries a graded run" crates/batten/src/land.rs kind:mechanism
// carried: "a ready PR whose head carries only skipped runs has its ready re-fired" crates/batten/src/land.rs kind:mechanism
// carried: "a ready PR whose head carries only cancelled runs has its ready re-fired" crates/batten/src/land.rs kind:mechanism
// carried: "the re-drafted PR a cancelled set left behind is readied, not stuck" crates/batten/src/land.rs kind:mechanism
// carried: "a DRAFT whose push moves nothing readies once, not once and then again" crates/batten/src/land.rs kind:mechanism
// carried: "THE RACE: the ready precedes the push, so one event carries the run" crates/batten/src/pipeline.rs kind:mechanism
// carried: "a lap that pushed does not also buy a second event" crates/batten/src/land.rs kind:mechanism
// carried: "a landing that succeeds says nothing that reads as a failure" crates/batten/src/lib.rs kind:mechanism
// carried: "the receipt guard still has its voice when it is the real failure" crates/batten/src/lib.rs kind:mechanism
// carried: "a silent bot with main moved ends the lap instead of polling" crates/batten/src/main_watch.rs kind:mechanism
// carried: "a silent bot with main unmoved keeps polling" crates/batten/src/main_watch.rs kind:mechanism
// withdrawn: "the watcher does not outlive a merged landing" the predecessor backgrounded a watcher subshell and reaped it on the merged path. `land::wait` races in-process and returns, so nothing outlives the call and there is no reaper to assert
// carried: "a re-draft that fails stops the lap rather than waiting on a run nobody started" crates/batten/src/lib.rs kind:mechanism
// carried: "a ready that fails stops before the push rather than pushing into silence" crates/batten/src/lib.rs kind:mechanism
// subsumed: "every way a lap can end is exercised above" crates/batten/src/pipeline.rs crates/batten/tests/it/land_lap.rs
// changed: "main moving during verify ends the lap at the poll, never at the end of the gate" crates/batten/src/land.rs kind:mechanism — the engine asks `Precheck::BaseMoved` BEFORE the ready rather than racing the gate, so a base that moves mid-gate is caught at the next step rather than aborting the run in flight — CLOUD-423's metered half, with the early abort stated as a shortfall rather than absorbed
// carried: "a verify race with no verdict laps and re-proves rather than guessing" crates/batten/src/lib.rs kind:mechanism
// carried: "a merged PR's branch is deleted from the remote" crates/batten/src/land.rs kind:mechanism
// carried: "a delete the remote refuses does not change land's exit code" crates/batten/src/land.rs kind:mechanism
// carried: "a run that stops instead of merging deletes nothing" crates/batten/src/lib.rs kind:mechanism
// carried: "a second land in this clone is refused before anything is spent (CLOUD-428)" crates/batten/src/lib.rs kind:mechanism
// carried: "the lease is taken before the push, so no run starts unheld" crates/batten/src/lease.rs kind:mechanism
// carried: "a lease held by someone else waits instead of pushing, and says so" crates/batten/src/lease.rs kind:mechanism
// carried: "a lost lease is caught BEFORE the merge is asked for" crates/batten/src/lease.rs kind:mechanism
// carried: "the lease is released on the merged path" crates/batten/src/lib.rs kind:mechanism
// carried: "the lease is released on a die path too — a leak would wedge the fleet" crates/batten/src/pipeline.rs kind:mechanism
// withdrawn: "the CI race waits on ITS OWN pids, never on every background job" the predecessor tracked its own background pids to avoid `wait`ing on every job in the shell. One process, no jobs, nothing to disambiguate
// withdrawn: "a watcher that shrugs off the TERM is escalated, never left to outlive the lap" a TERM-then-KILL escalation over a subshell that ignored the first signal. The engine spawns no watcher, and `exec`'s own process-group handling is `policy/spawn-adapters.rego`'s subject rather than the lander's
// withdrawn: "a detached descendant cannot hold bats' output stream — fd 3 is closed beneath the program under test" a bats harness property — fd 3 is the runner's output stream, and the case asserted a detached descendant could not hold it open. There is no descendant and no bats
// withdrawn: "a land killed mid-race takes its watchers with it — the trap reaps the races too" the predecessor's EXIT trap reaped its race subshells so a killed lander took them with it. Nothing is backgrounded, so the trap has no subject
// carried: "a head whose LATEST required run is a skip has no answer, so the ready is fired" crates/batten/src/checks_green.rs kind:mechanism
// carried: "a skip its own re-run superseded is an answer, so nothing buys a second run" crates/batten/src/checks_green.rs kind:mechanism
// carried: "a run main moved under is CANCELLED, not left to bill for an answer nobody reads" crates/batten/src/land.rs kind:mechanism
// carried: "a lap that CI answered cancels nothing — only a voided run is void" crates/batten/src/land.rs kind:mechanism
// carried: "a waiter linearizes onto the HOLDER's head, not onto the main it is replacing" crates/batten/src/lib.rs kind:mechanism
// carried: "a lease naming no head leaves the branch linearized on main, and says nothing" crates/batten/src/lib.rs kind:mechanism
// carried: "A CONFLICTING SPECULATION FALLS BACK — it is information, not a stop" crates/batten/src/lib.rs kind:mechanism
// carried: "THE BET CANNOT BE PUSHED WHEN IT LOSES: a stale speculation is unwound first" crates/batten/src/lib.rs kind:mechanism
// carried: "an unwind the tree refuses is a stop, not a lap onto an unknown HEAD" crates/batten/src/lib.rs kind:mechanism
// carried: "THE SECOND MATRIX: an admitted successor readies and pushes without the lease" crates/batten/src/lease.rs kind:mechanism
// carried: "a verify failure on a SPECULATIVE tree names the borrowed base" crates/batten/src/lib.rs kind:mechanism
// carried: "a verify failure with NO speculation still gets the original advice" crates/batten/src/lib.rs kind:mechanism
// carried: "A WAITER THAT IS NOT ADMITTED STAYS IN DRAFT — this is what bounds the cost" crates/batten/src/lease.rs kind:mechanism
// carried: "the successor reserves only once, however many laps it waits" crates/batten/src/lease.rs kind:mechanism
// carried: "MAIN MOVING DURING THE WAIT: the winner laps rather than confirming a doomed head" crates/batten/src/land.rs kind:mechanism
// carried: "a lap whose main did not move confirms and proceeds — the negative of the case above" crates/batten/src/land.rs kind:mechanism
// carried: "the successor's run is bought ONCE, not re-pushed on every lap it waits" crates/batten/src/land.rs kind:mechanism
// carried: "AN ABANDONED HOLDER IS NOT A PENDING BET: the lease freed unwinds it" crates/batten/src/speculation.rs kind:mechanism
// carried: "the lease passing to a branch that does not carry our base unwinds it" crates/batten/src/speculation.rs kind:mechanism
// carried: "A LIVE BET IS LEFT ALONE — without this, the unwind fires every lap" crates/batten/src/speculation.rs kind:mechanism
// carried: "a liveness read that fails is stale, never live — the fetch fails closed" crates/batten/src/lib.rs kind:mechanism
// carried: "WINNING THE LEASE SETTLES THE BET FIRST: no borrowed tree is readied, pushed or merged" crates/batten/src/pipeline.rs kind:mechanism
// carried: "a bet already PUSHED is re-drafted before its remote is rewound" crates/batten/src/lib.rs kind:mechanism
// changed: "CLOUD-483: a run that died before any mise step is re-run, not reported red" crates/batten/src/land.rs kind:mechanism — `land::rerun_failed` exists and the lap does not yet reach it: telling a run that died before any step from one that reached a verdict needs the job-level reading, which is CLOUD-483's own row. `lib.rs` states the gap at the site rather than hiding it
// changed: "CLOUD-483: a job that reached a verdict is red, and is never re-run" crates/batten/src/land.rs kind:mechanism — the mirror of the row above, and the same gap: with no job-level reading the engine treats every red as a verdict, which is the SAFE direction — it never re-runs a genuine failure, it only fails to absorb a transient
// carried: "CLOUD-900: a genuine red abandons the rest of the matrix" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-900: a run CI DECLINED abandons nothing — it is not a verdict" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-900: a provisioning transient abandons nothing — the jobs get re-run" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-900: a lap CI answered green abandons nothing" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-483: EMPTY IS NOT UNANIMOUS — no records is red, not absorbed" crates/batten/src/checks_green.rs kind:mechanism
// carried: "CLOUD-483: the retry budget is a COUNT, and exhausting it stops" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-483: a re-run the API refuses stops, naming the command" crates/batten/src/land.rs kind:mechanism
// withdrawn: "CLOUD-383: a rendezvous that cannot be created stops, rather than guessing" a bash rendezvous — a FIFO the racing subshells synchronised on. The engine's race is two polls in one process and needs no rendezvous to create or fail to create
// withdrawn: "CLOUD-383: the CI wait's rendezvous stops too, at top level" the same rendezvous at the CI wait's own level, and gone for the same reason
// withdrawn: "CLOUD-383: the races carry no bash-4 construct" a portability assertion over the predecessor's own source: no bash-4 construct in the race code. There is no bash and no race code
// carried: "CLOUD-518: a session that has not dropped the subscription cannot land" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-518: the check runs against THIS PR, not some other" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-790: the landing makes the unsubscribe call itself, for THIS PR" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-790: a drop that could not happen does not stop the landing itself" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-518: a dropped subscription lets the landing proceed untouched" crates/batten/src/land.rs kind:mechanism
// carried: "CLOUD-369 clause b1-neg — a holder whose CI answers RED admits nobody" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause b1-neg — a holder whose CI has NOT ANSWERED admits nobody" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause b1-neg — a holder whose CI COULD NOT BE READ admits nobody" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause b1-neg — a lease naming no head admits nobody" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause b1-pos — a GREEN holder still admits exactly one waiter" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause e — a waiter whose base CONFLICTS is not admitted" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-369 clause e — a waiter whose base APPLIES CLEANLY still is admitted" crates/batten/src/lease.rs kind:mechanism
// carried: "CLOUD-861: an ENOSPC during verify is reported as the environment, not as a defect to reproduce" crates/batten/src/land.rs kind:mechanism
// carried: "an ordinary verify failure still says reproduce it locally" crates/batten/src/lib.rs kind:mechanism
// carried: "CLOUD-862: a bet left by a dead run is adopted and unwound before anything is pushed" crates/batten/src/speculation.rs kind:mechanism
// carried: "CLOUD-862: an adopted bet whose base LANDED keeps the tree and just drops the ref" crates/batten/src/speculation.rs kind:mechanism
// carried: "CLOUD-862: a bet ref naming a commit this tree is not built on is dropped, not acted on" crates/batten/src/speculation.rs kind:mechanism
// carried: "a run with no bet ref is untouched by the recovery path" crates/batten/src/speculation.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::exit::ExitCode;
use batten::land::{self, Progress, Step, TapVerdict};
use batten::pipeline::{COMMIT_POINT, Pipeline};

/// **EVERY WAY A LAP CAN END, and the table is total.**
///
/// The successor to *"every way a lap can end is exercised above"*, which counted
/// the predecessor's own arms. The engine's equivalent is stronger and cheaper:
/// `land::progress_of` is a total function of (step, code, verdict), so the
/// question is not whether a suite remembered to exercise each ending but whether
/// each ending is REACHABLE — a variant nothing can produce is a dead arm, and a
/// pair that produced nothing would be a lap with no answer.
#[test]
fn every_lap_ending_is_reachable_from_some_step_and_code() {
    let codes = [
        ExitCode::Success,
        ExitCode::Usage,
        ExitCode::Violation,
        ExitCode::Internal,
    ];
    let steps = [
        Step::Replay,
        Step::Verify,
        Step::Ready,
        Step::Push,
        Step::Wait,
        Step::FastForward,
    ];

    let mut seen: Vec<Progress> = Vec::new();
    for step in steps {
        for code in codes {
            for verdict in [
                None,
                Some(TapVerdict::Green),
                Some(TapVerdict::Red),
                Some(TapVerdict::Pending),
            ] {
                let progress = land::progress_of(step, code, verdict);
                if !seen.contains(&progress) {
                    seen.push(progress);
                }
            }
        }
    }

    // ALL FOUR, and the assertion names which is missing rather than a count —
    // a bare `assert_eq!(seen.len(), 4)` reports a number where a reader needs
    // the arm.
    for ending in [
        Progress::Proceed,
        Progress::Lap,
        Progress::Landed,
        Progress::Stop,
    ] {
        assert!(
            seen.contains(&ending),
            "{ending:?} is unreachable from every (step, code, verdict): a lap can never end that way"
        );
    }
}

/// **THE SHIPPED COMPOSITION LOADS, AND THE COMMIT POINT IS LAST.**
///
/// The lap's shape is a declared list now rather than an array literal, so the
/// property the predecessor asserted by reading its own source is asserted over
/// the object the driver actually walks.
#[test]
fn the_shipped_lap_validates_and_ends_at_the_commit_point() {
    let shipped = Pipeline::default();
    assert_eq!(
        shipped.validate(),
        Vec::new(),
        "the composition this repository ships must load"
    );
    assert_eq!(
        shipped.steps.last().map(|row| row.step),
        Some(COMMIT_POINT),
        "nothing may run after the irreversible step"
    );
}

/// **THE LANDING'S OWN STOP IS STILL RECORDED, so a clean finish does not read
/// as a container death.**
///
/// `tests/reclaim-census.bats` carried this as *"land records the stop it causes
/// itself"*, reading `mise-tasks/land.sh` for the note. Its subject
/// (`mise-tasks/reclaim-census.sh`) is alive and the note moved rather than died:
/// the lander used to spawn it inline, and the engine's `lease release` spawns
/// what `$LEASE_STOP_NOTE` names. So the case is PORTED here rather than
/// withdrawn.
///
/// **The declaration is the subject, not the spawn.** The note's text is this
/// consumer's — a census program's argv — so `crates/batten` may not carry it
/// (non-negotiable rule 1) and what this can assert is that the consumer still
/// declares one. A lap that stopped and recorded nothing leaves its last census
/// record an `h`, and every successful landing then reads as *the container died
/// under active work*.
#[test]
fn the_landings_own_stop_note_is_still_declared() {
    let manifest =
        std::fs::read_to_string("../../mise.toml").expect("read the consumer's manifest");
    let declared: Vec<&str> = manifest
        .lines()
        .filter(|line| line.trim_start().starts_with("LEASE_STOP_NOTE"))
        .collect();
    assert_eq!(
        declared.len(),
        1,
        "exactly one stop note is declared, or the lease spawns an ambiguous one"
    );
    // THE COUNT AND THE CONTENT, because a row declared empty would satisfy the
    // count alone — and an empty note is a lease that records nothing, which is
    // byte-identical to the defect this case exists to catch.
    assert!(
        declared[0].contains("land-stopped"),
        "the declared note must still mark a landing's own stop: {}",
        declared[0]
    );
}

/// **A LAP NEVER RUNS FROM THE TRUNK.**
///
/// Over the compiled binary, because this is the one property in the file whose
/// subject is the verb rather than a function: *"land refuses to run from main"*
/// is about what a person typing the command gets back.
#[test]
fn a_lap_refuses_to_run_from_the_trunk() {
    let dir = common::scratch("land-lap-from-trunk");
    common::init_repo(&dir);

    let output = common::batten()
        .arg("land")
        .arg("lap")
        .arg("main")
        .current_dir(&dir)
        .output()
        .expect("the compiled binary runs");
    let said = String::from_utf8_lossy(&output.stderr);

    assert_ne!(
        output.status.code(),
        Some(0),
        "landing from the trunk must not succeed: {said}"
    );
}
