//! Betting on the base that is about to exist (CLOUD-748, CLOUD-862, CLOUD-369).
//!
//! # What a speculation is
//!
//! The landing lease names one branch as the next thing to land. A waiter behind
//! it can either sit on today's `main` — and rebase onto the holder's work the
//! moment it lands, spending a lap — or linearize onto the holder's head NOW and
//! be already correct when it lands. The second is the bet, and the whole of the
//! machinery below exists because a bet can be wrong.
//!
//! # A BET CAN BE LOST, AND IT CAN ALSO BE POISONED
//!
//! `settle` has FOUR outcomes: the holder landed, the bet is still open, the bet
//! lost — and the base is **poisoned**, meaning its tree will not pass `verify`.
//! The port that created this module conserved the bash's three and carried the
//! fourth as a declared gap so the retirement stayed reviewable as a port;
//! CLOUD-1306 is that gap and this is its close.
//!
//! What it cost while it was open, recorded because the shape recurs: a waiter
//! linearizes onto a head that cannot go green, `settle` reads the bet as still
//! open every lap — the holder is still there and `main` has not moved, which is
//! exactly what "pending" looks like — and [`Bet::would_rebet`] bets on the same
//! holder again. Every waiter behind that holder stalls together. Measured over
//! three consecutive invocations on PR #815, all three exited identically.
//!
//! **The discriminator is the re-verify off the borrowed base**, and it is the
//! one the error message already told a human to run by hand: red on the
//! borrowed tree and green on our own means the failure is the holder's, so the
//! bet is poisoned rather than merely open. Red on both is OURS and stops the
//! lap exactly as before — [`Settle::Poisoned`] is an arm, never a hatch.
//!
//! **A poisoned base is REMEMBERED on a ref** ([`REFUSED_REF`]), not merely in
//! this process. The measured stall was three separate `land` invocations, so a
//! memory that died with the process would have unwound the first lap and
//! re-bet on the same refused head at the start of the next one.
//!
//! # Every failure is a FALLBACK, never a stop
//!
//! The holder may never land, so a conflict against its head is information
//! about a base that may not happen — not the `die`-worthy conflict a rebase
//! onto `origin/main` reports. Reading an unreachable remote, an unresolvable ref
//! or an unknown ancestry all mean "do not bet" or "the bet is stale", never
//! "stop the landing".
//!
//! **Except in one direction, and the asymmetry is the correctness property.**
//! [`Live::decide`] fails CLOSED: an unreadable lease, an unfetchable branch and
//! an unknown ancestry are all *stale*, because failing open there would make a
//! network blip the thing that lands somebody else's work.

// CLOUD-1306's own Ready block names both of these, and they are the two
// directions the arm can fail in: forgetting the judgement (the stall returns)
// and applying it to everything (a waiter with its own defect never stops).
//MUTANT-SUITE crates/batten/src/speculation.rs
//MUTANT poisoned-bet-rebet|s@        if self.refused.as_deref() == Some(candidate) {@        if false {@|forgetting_a_bet_keeps_the_base_that_would_not_go_green
//MUTANT own-red-tree-unwinds|s@    if bet.refused.as_deref() == Some(base) {@    if true {@|a_waiter_whose_own_tree_is_red_still_settles_pending

use std::path::Path;

use anyhow::Result;

/// The ref a live bet's BASE is recorded under.
///
/// A ref rather than a process variable because a bet outlives the process that
/// placed it: a `land` that was killed mid-lap leaves the tree linearized on
/// somebody else's commits, and the next one has to be able to find that out.
/// CLOUD-862 is that reading — measured, a stopped `land` left seven of another
/// branch's commits in the tree and the next run took them all the way to a push.
pub const BASE_REF: &str = "refs/batten-spec/base";

/// The ref the holder's CURRENT head is fetched into when re-confirming a bet.
///
/// A SECOND ref, deliberately. The bet's base and the tip it is checked against
/// are two different commits, and reusing [`BASE_REF`] would overwrite the base
/// while answering a question about it.
pub const LIVE_REF: &str = "refs/batten-spec/live";

/// The ref a base KNOWN to fail `verify` is remembered under.
///
/// A THIRD ref, and it outlives the bet it refused. [`BASE_REF`] records a bet
/// that exists and is deleted the moment one settles; this records a judgement
/// about a commit, which stays true after the bet built on it is gone. Reusing
/// either of the other two would delete the memory at exactly the point it
/// starts being useful.
///
/// A ref rather than a field alone because the measured stall (CLOUD-1306, PR
/// #815) was three separate `land` invocations. [`Bet::refused`] is this
/// process's copy; without the ref, lap one unwinds and the next invocation bets
/// on the same refused head again — which is the stall, one process later.
pub const REFUSED_REF: &str = "refs/batten-spec/refused";

/// The variable a bet is published to the child process under.
///
/// `verify` runs `claim-race-check`, which reads `claimed-keys`, which cannot
/// otherwise tell a commit this branch authored from one this speculation
/// adopted — so it reported the waiter as racing the very PR the bet was placed
/// on, twice in one session (CLOUD-748). The name is the CONSUMER's and reaches
/// the child through the environment; nothing in this crate reads it.
pub const PUBLISHED_AS: &str = "BATTEN_SPEC_BASE";

/// What a settle decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    /// No bet is outstanding, so there is nothing to settle.
    Nothing,
    /// The base is an ancestor of `origin/main`: the holder landed, and this
    /// branch is already linearized on it. Nothing to undo.
    Landed,
    /// Undecided. The holder is still landing and this branch is already behind
    /// it, so the tree is kept.
    ///
    /// **A base that will never go green USED TO HIDE HERE**, indistinguishable
    /// from one that simply has not landed yet. It no longer does — but only
    /// because something took the discriminating reading and recorded it. With
    /// no such reading this arm is still the honest answer, which is why a
    /// re-verify that cannot run settles `Pending` rather than [`Self::Poisoned`].
    Pending,
    /// The bet cannot come true: the holder is gone, or `main` moved and took
    /// something else. The borrowed range is dropped.
    Lost,
    /// The bet is still live and its base is KNOWN not to go green (CLOUD-1306).
    ///
    /// **APPENDED, NEVER INSERTED.** This enum carries no `repr` and its
    /// discriminants are compared across builds by anything that stores one, so
    /// a variant placed mid-enum silently renumbers every variant after it —
    /// `verdict::Native` paid for that lesson in this same branch.
    ///
    /// Distinct from [`Self::Lost`] because the action differs in one way that
    /// matters: a lost bet's base may be bet on again the moment the holder is
    /// back, and a poisoned one must not be until the tree that refused it
    /// moves. Both unwind; only this one is remembered ([`REFUSED_REF`]).
    Poisoned,
}

/// Whether the bet is still on the branch that is about to land.
///
/// A three-valued reading rather than a bool, because "could not look" and "no"
/// take the same action here and must still be distinguishable to a reader —
/// the bash collapsed them into one non-zero exit and the collapse is what made
/// the fail-closed posture invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Live {
    /// Somebody else holds the lease and the base is still on their branch.
    Yes,
    /// The lease is free, held by US, or the base is no longer on the holder's
    /// branch.
    No,
    /// The lease would not read, the branch would not fetch, or the ancestry is
    /// unknown. **Decides as [`Live::No`]** — see [`Live::decide`].
    Unreadable,
}

impl Live {
    /// The fail-CLOSED reading: anything but a confirmed yes is stale.
    ///
    /// Failing open here would make a network blip the thing that lands somebody
    /// else's work, which is the one place in this module where a could-not-look
    /// must not be permissive.
    #[must_use]
    pub const fn decide(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// One outstanding bet.
///
/// **AT MOST ONE.** A waiter laps repeatedly while the same holder lands, and
/// re-betting each lap would overwrite [`Bet::undo`] with a HEAD that is itself
/// speculative — so unwinding would restore a tree that still carried somebody
/// else's commits, which is the exact hazard the undo exists to remove. It would
/// also mint a new sha every lap and throw away a `verify` receipt for no gain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bet {
    /// The holder's head this branch was replayed onto.
    pub base: Option<String>,
    /// This branch's own last NON-speculative HEAD, and the exact unwind point.
    ///
    /// `None` on a bet this process ADOPTED rather than placed: the undo point
    /// died with the process that recorded it, and such a bet unwinds by
    /// replaying onto `origin/main` from the base instead (CLOUD-862).
    pub undo: Option<String>,
    /// The `origin/main` this bet was placed against.
    ///
    /// Without it, "not landed yet" and "landed something else" are the same
    /// reading and the bet would be unwound every lap while the holder was
    /// perfectly on course.
    pub main_at_bet: Option<String>,
    /// Set when this process adopted a bet it did not place.
    pub recovered: bool,
    /// Set once the bet has been PUSHED. An unwind then owes the remote a
    /// correction too: without one, a stop or a spent lap budget leaves origin
    /// holding another branch's commits under an open PR — the measured
    /// two-PRs-at-one-sha state.
    pub pushed: bool,
    /// The holder's base that is KNOWN to conflict with this branch.
    ///
    /// Kept rather than discarded (CLOUD-369): a successor whose base is known
    /// to conflict is guaranteed to be voided, so its run grades a head the
    /// fast-forward will refuse and the rebase that follows still has to resolve
    /// the same conflict. Measured for one such admission: a full CI run burned,
    /// a ~200s `verify` discarded, a hand-resolved conflict, and a second run.
    ///
    /// **IT CARRIED NO SUBJECT AND NOTHING READ IT** (review of #848). As a bare
    /// `bool` it was set on a conflicting replay and never consulted, so
    /// [`Bet::would_rebet`] — which compares `base`, and `base` is deliberately
    /// NOT set when the replay conflicted — answered `true` on the next lap and
    /// the same conflicting rebase was attempted again, every lap, to reach the
    /// same answer. CLOUD-369's mechanism was written and then unreachable.
    ///
    /// An `Option<String>` because refusing to re-bet needs to know WHICH base:
    /// a flag cannot tell the holder that conflicted from the one that replaced
    /// it, and reading it as "no more bets at all" would give up speculating for
    /// the rest of the landing over one bad candidate.
    pub conflicts: Option<String>,
    /// The holder's base that is KNOWN to fail `verify` (CLOUD-1306).
    ///
    /// **`conflicts`'s sibling, and the pair is not one field.** A base that
    /// conflicts cannot be replayed onto at all; a base that is poisoned replays
    /// perfectly and then refuses the gate. They are learned at different
    /// moments — the replay and the verify — and a branch can hit either without
    /// the other, so collapsing them would make each answer the other's question.
    ///
    /// Survives [`Bet::forget`] for `conflicts`' own stated reason: it records a
    /// judgement about a COMMIT, which stays true of that commit after the bet
    /// built on it settles. Forgetting it is what made CLOUD-369's refusal
    /// unreachable, and the same forgetting here would re-bet on the refused
    /// head on the very next lap.
    ///
    /// An `Option<String>` rather than a `bool` for the same reason `conflicts`
    /// is: refusing to re-bet needs to know WHICH base. A flag cannot tell the
    /// poisoned holder from the one that replaced it, and reading it as "no more
    /// bets at all" would abandon speculation for the rest of the landing over
    /// one bad candidate.
    pub refused: Option<String>,
    /// A base the gate refused ON THE BORROWED TREE, not yet discriminated.
    ///
    /// **THE THIRD CONJUNCT OF CLOUD-1306's PREDICATE, AND IT COSTS NO EXTRA
    /// GATE RUN.** The row states the reading as "replay onto `origin/main` and
    /// re-run"; run literally that would buy a second full gate inside a lap
    /// that has just spent one — measured at ~25 minutes on this container.
    ///
    /// The NEXT LAP'S verify is that same re-run. So a refusal on a speculative
    /// tree records the base here and unwinds, and the lap that follows decides
    /// it: green off our own base means the failure was the holder's and this is
    /// promoted to [`Bet::refused`]; red again means it was ours all along and
    /// this is dropped without ever becoming a judgement.
    ///
    /// **[`Bet::would_rebet`] refuses a suspect as firmly as a refused base**,
    /// and it must: re-borrowing the head under suspicion on the very next lap
    /// would re-poison the tree and destroy the reading that was about to
    /// discriminate it.
    pub suspect: Option<String>,
}

impl Bet {
    /// Is a bet outstanding?
    #[must_use]
    pub const fn live(&self) -> bool {
        self.base.is_some()
    }

    /// The value [`PUBLISHED_AS`] should carry, or `None` to unset it.
    ///
    /// A function rather than a side effect so the two states cannot disagree:
    /// the bash called `publish_speculation` at every point the bet was placed or
    /// cleared precisely because they could.
    #[must_use]
    pub fn published(&self) -> Option<&str> {
        self.base.as_deref()
    }

    /// **Would `speculate` place a bet on this candidate?**
    ///
    /// `false` for the same candidate twice — the one-outstanding-bet rule above.
    ///
    /// **A base known to CONFLICT is a different question and this answers it**
    /// (review of #848). That one is not about a tree that will not go green —
    /// it is a replay this clone already attempted and watched fail, so
    /// re-attempting it is guaranteed waste rather than a gamble whose odds
    /// changed. [`Bet::conflicts`] records which base.
    ///
    /// **AND A BASE KNOWN TO BE POISONED IS A THIRD** (CLOUD-1306). Once the bet
    /// on it is unwound, `base` no longer names it, so without
    /// [`Bet::refused`] this would answer `true` on the very next lap and
    /// re-borrow the tree that just refused the gate. That is the stall the whole
    /// arm exists to end, and it reappears the moment this stops consulting it.
    ///
    /// Both memories survive the bet not being placed, which is what makes them
    /// useful here rather than merely recorded.
    #[must_use]
    pub fn would_rebet(&self, candidate: &str) -> bool {
        if self.conflicts.as_deref() == Some(candidate) {
            return false;
        }
        if self.refused.as_deref() == Some(candidate) {
            return false;
        }
        // A SUSPECT IS REFUSED AS FIRMLY AS A JUDGEMENT, and for a sharper
        // reason: re-borrowing the head that is currently under suspicion would
        // put the borrowed range back into the tree and destroy the very reading
        // — the next lap's own verify — that was about to discriminate it.
        if self.suspect.as_deref() == Some(candidate) {
            return false;
        }
        self.base.as_deref() != Some(candidate)
    }

    /// The borrowed tree was refused: hold this base pending discrimination.
    ///
    /// Records nothing if some other base is already under suspicion — one
    /// outstanding question at a time, for [`Bet`]'s own one-bet reason.
    pub fn suspect(&mut self, base: &str) {
        if self.suspect.is_none() {
            self.suspect = Some(base.to_owned());
        }
    }

    /// The next lap went GREEN off our own base: the suspicion was the holder's.
    ///
    /// Returns the base to remember, so the caller writes [`REFUSED_REF`] only
    /// where a judgement was actually reached.
    pub fn confirm_refusal(&mut self) -> Option<String> {
        let confirmed = self.suspect.take()?;
        self.refused = Some(confirmed.clone());
        Some(confirmed)
    }

    /// The next lap was red off our own base too: the failure is OURS.
    ///
    /// **The anti-vacuity half, and dropping it is what would make every stop
    /// look like a poisoning.** A branch with a genuine defect refuses the gate
    /// on every base, so without this it would accumulate a refusal against each
    /// holder it ever waited behind and stop speculating altogether.
    pub fn clear_suspicion(&mut self) {
        self.suspect = None;
    }

    /// Drop the bet's own bookkeeping. The REF is the caller's to delete.
    ///
    /// **`pushed` IS CLEARED AND `conflicts` IS NOT, and the asymmetry is the
    /// whole of this doc** (review of #848). `pushed` is a fact about THIS bet's
    /// range reaching the remote, so leaving it set leaks a settled bet's state
    /// into the next one — and the reader is `unwind_the_bet`, which force-writes
    /// the branch under a CAS that always applies, so a bet that never reached
    /// the remote would have the remote "corrected" to a head it already had.
    ///
    /// `conflicts` survives deliberately, and its own doc says why: it records a
    /// base KNOWN to conflict, which stays true of that base after the bet built
    /// on some other one is settled. Forgetting it is what made CLOUD-369's
    /// mechanism unreachable.
    ///
    /// **`refused` survives for the identical reason** (CLOUD-1306), and it is
    /// the field with the most to lose by not doing so: a poisoned bet is
    /// settled by UNWINDING it, so this runs on the exact path that would
    /// otherwise erase the judgement one line before the next lap re-bets on it.
    ///
    /// **`suspect` survives too, and its case is sharper still.** Suspicion is
    /// RAISED on the unwind path — this function's own caller — so clearing it
    /// here would delete the question in the same breath as asking it, and the
    /// next lap would have nothing to discriminate.
    pub fn forget(&mut self) {
        self.base = None;
        self.undo = None;
        self.main_at_bet = None;
        self.recovered = false;
        self.pushed = false;
    }

    #[cfg(test)]
    /// A settled bet carries nothing forward but the bases it will not re-bet on.
    ///
    /// Both memories are excluded here rather than asserted absent: `conflicts`
    /// and `refused` are judgements about commits, and the cases beside this one
    /// assert each SURVIVES. A spelling that required them cleared would make the
    /// two suites contradict each other.
    fn is_forgotten(&self) -> bool {
        self.base.is_none()
            && self.undo.is_none()
            && self.main_at_bet.is_none()
            && !self.recovered
            && !self.pushed
    }
}

/// **The settle table, and it is a pure function on purpose.**
///
/// Every input is a reading the caller already took, so the decision can be
/// exercised over all of its arms without a remote, a clock or a fixture — which
/// is what makes "does the port conserve the bash's behaviour" an answerable
/// question rather than a claim.
///
/// The argument order follows the bash's own arms, and the FIRST arm is load-
/// bearing: `settle_speculation` used to open on "did this process place a bet",
/// so a `land` that had merely inherited one returned on its first line while the
/// ref holding the answer sat on disk beside it (CLOUD-862). Ask git before
/// asking the process — the caller does that by handing an adopted bet in here
/// exactly as it would one of its own.
///
/// # `main_now` IS THREE-VALUED, AND THE THIRD VALUE IS NOT AN EMPTY STRING
///
/// `None` is the tracking ref that would not read — a fetch that lost the
/// network, a clone with no remote-tracking ref yet, a ref file being rewritten
/// under the read. It is a COULD-NOT-LOOK, and it must not reach the last arm.
///
/// Taking a `&str` is what made it: the caller spelled the failed read
/// `unwrap_or_default()`, so an unreadable ref arrived as `""`, compared unequal
/// to every `main_at_bet`, and fell through to "`main` moved and took something
/// else" — settling a perfectly live bet as [`Settle::Lost`] and unwinding the
/// tree on a transient read. That is the one direction [`settle_the_bet`]'s own
/// header forbids: an unresolvable ref means the bet is STALE, never that the
/// trunk moved.
///
/// [`settle_the_bet`]: crate::settle_the_bet
///
/// The could-not-look arm is the ADOPTED arm's, not a fourth answer: without a
/// trunk reading, "has `main` moved" is unanswerable for exactly the reason an
/// adopted bet's is — there is no comparison to make — and the lease answers the
/// question either way. So a readable lease still holding for this branch settles
/// [`Settle::Pending`] and the waiter laps, and [`Live::Unreadable`] still
/// decides as `No`, which keeps the fail-CLOSED posture where both readings are
/// gone.
#[must_use]
pub fn settle(bet: &Bet, main_now: Option<&str>, base_on_main: bool, live: Live) -> Settle {
    let Some(base) = bet.base.as_deref() else {
        return Settle::Nothing;
    };

    // WON. Checked first and unconditionally, because it is true whoever placed
    // the bet and because the two arms below would both misread it: an adopted
    // bet has no `main_at_bet` to compare, and a placed one would see `main`
    // moved and call it lost.
    if base_on_main {
        return Settle::Landed;
    }

    // POISONED (CLOUD-1306), and its position between `Landed` and the liveness
    // arms is the whole of its correctness.
    //
    // AFTER `Landed`, because a base the trunk has already taken is not poisoned
    // whatever a stale judgement says — the tree that refused it is now `main`'s
    // problem and unwinding off it would drop commits we are already correctly
    // linearized on.
    //
    // BEFORE the liveness arms, because every one of them reads a live holder
    // that has not moved `main` as [`Settle::Pending`] — which is exactly what a
    // poisoned holder looks like, and precisely the arm this used to hide in.
    //
    // The judgement is the CALLER's reading, taken by re-verifying off the
    // borrowed base and recorded on [`REFUSED_REF`]. This function only asks
    // whether the bet outstanding is the one that was refused; a re-verify that
    // could not run records nothing and falls through to `Pending`, which is the
    // could-not-look direction the module header requires.
    if bet.refused.as_deref() == Some(base) {
        return Settle::Poisoned;
    }

    // An ADOPTED bet has no `main_at_bet` — the process that recorded it is gone
    // — so the "has main moved" arm cannot judge it. The lease can: it reads who
    // holds it NOW and whether the base is still on the branch about to land,
    // which is the question either way.
    //
    // A trunk reading that would not take is the same position by a different
    // route: `None` is a could-not-look, so there is nothing to compare
    // `main_at_bet` AGAINST, and the arm below would read the missing reading as
    // a moved trunk. Both defer to the lease.
    let Some(main_now) = main_now else {
        return if live.decide() {
            Settle::Pending
        } else {
            Settle::Lost
        };
    };
    if bet.recovered {
        return if live.decide() {
            Settle::Pending
        } else {
            Settle::Lost
        };
    }

    // `main` has not moved, which USED TO END THE QUESTION. It does not: the
    // holder can go away without `main` moving at all, and that reading is
    // indistinguishable from "still landing" unless the lease is re-read.
    //
    // The measured incident: a holder whose CI died in a provider incident held
    // the lease going nowhere, a sibling linearized onto its published head, and
    // the two branches ended at the identical sha with neither able to land.
    // A PLACED BET WITH NO `main_at_bet` IS THE SAME POSITION AS AN ADOPTED ONE,
    // and reading it as a moved trunk was this arm's own defect (review of #848).
    // The field is a reading that may not have taken when the bet was placed, and
    // `Some(main_now) != None` is true, so the comparison below fell through to
    // `Lost` — unwinding a speculation that is very much alive, on the strength
    // of a reading nobody ever got. It is could-not-look on the SAME side of the
    // comparison the `main_now` arm above already defers for, so it defers the
    // same way.
    let Some(main_at_bet) = bet.main_at_bet.as_deref() else {
        return if live.decide() {
            Settle::Pending
        } else {
            Settle::Lost
        };
    };
    if main_at_bet == main_now {
        return if live.decide() {
            Settle::Pending
        } else {
            Settle::Lost
        };
    }

    // `main` moved and took something else.
    Settle::Lost
}

/// Is `candidate` an ancestor of `tip`?
///
/// **[`crate::gitwrite::carries`]'s, not this module's, and the delegation is a
/// gate's finding rather than taste.** `gix_is_confined_to_the_git_modules`
/// refuses a fourth module reaching the backend directly, and it caught the
/// first draft of this file doing exactly that. Widening that list for a
/// predicate `gitwrite::rebase` already asks inline would have bought a second
/// place to get ancestry wrong; delegating buys none.
#[must_use]
pub fn carries(dir: &Path, candidate: &str, tip: &str) -> bool {
    crate::gitwrite::carries(dir, candidate, tip)
}

/// Load the refused-base judgement this clone recorded in an earlier process.
///
/// **Separate from [`recover`], and not folded into it, because the two answer
/// different questions.** `recover` asks whether a BET is outstanding and
/// returns early when one is; a judgement about a poisoned base is worth reading
/// whether or not this process is speculating, and is most worth reading when it
/// is not — that is the moment [`Bet::would_rebet`] is about to be asked.
///
/// Fail-open and silent, like every other reading in this module: a ref store
/// that will not answer leaves the memory empty, which costs a wasted lap rather
/// than a wrong verdict.
pub fn recall_refusal(dir: &Path, bet: &mut Bet) {
    if bet.refused.is_some() {
        return;
    }
    bet.refused = crate::git::resolve_ref(dir, REFUSED_REF).ok().flatten();
}

/// Adopt a bet this process did not place.
///
/// Runs BEFORE the ordinary settle, so the settle that follows is the ordinary
/// one — there is no second settle path to keep in agreement with the first.
///
/// **The ancestry pair is the whole predicate** and both halves are load-bearing:
/// the base must be an ancestor of HEAD (this tree really is linearized on it,
/// rather than the ref being left over from a clone that reset). It deliberately
/// does NOT decide "did it land" — [`settle`]'s first arm already answers that,
/// and answers it out loud; an arm here would be a second place deciding one
/// thing, and the one that stayed silent is how this whole class went unnoticed.
///
/// # Errors
///
/// Only a ref store that will not answer at all. A ref that is simply absent is
/// `Ok(false)` — no bet to adopt is the ordinary state.
pub fn recover(dir: &Path, bet: &mut Bet) -> Result<bool> {
    if bet.live() {
        return Ok(false);
    }
    let Some(recorded) = crate::git::resolve_ref(dir, BASE_REF)? else {
        return Ok(false);
    };
    if !carries(dir, &recorded, "HEAD") {
        // The ref names a commit this tree is not built on, so whatever it was
        // recording is not true of this HEAD.
        bet.forget();
        return Ok(false);
    }
    bet.base = Some(recorded);
    bet.recovered = true;
    Ok(true)
}

#[cfg(test)]
// Panicking on a failed assertion is how a test fails loudly; these are the
// module's own cases, not a reachable path.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// **A SETTLED BET LEAKS NOTHING INTO THE NEXT ONE**, which `pushed` did.
    ///
    /// It is a fact about THIS bet's range reaching the remote, and its reader
    /// force-writes the branch under a CAS that always applies — so carrying it
    /// forward would "correct" the remote for a range that never got there.
    #[test]
    fn forgetting_a_bet_clears_every_field_the_next_one_would_inherit() {
        let mut bet = Bet {
            base: Some(String::from("abc1234")),
            undo: Some(String::from("def5678")),
            main_at_bet: Some(String::from("0badc0de")),
            recovered: true,
            pushed: true,
            conflicts: Some(String::from("feedface")),
            refused: Some(String::from("baddecaf")),
            suspect: Some(String::from("d15ea5e0")),
        };
        bet.forget();
        assert!(bet.is_forgotten(), "a settled bet carried state forward");
    }

    /// AND THE ONE FIELD THAT MUST SURVIVE STILL DOES. Without this the case
    /// above is satisfied by a `forget` that clears everything, which is what
    /// made CLOUD-369's refusal unreachable in the first place.
    #[test]
    fn forgetting_a_bet_keeps_the_base_it_will_not_re_bet_on() {
        let mut bet = Bet {
            conflicts: Some(String::from("feedface")),
            ..Bet::default()
        };
        bet.forget();
        assert_eq!(bet.conflicts.as_deref(), Some("feedface"));
        assert!(
            !bet.would_rebet("feedface"),
            "a base known to conflict is still known to conflict after the bet settles"
        );
    }

    /// **AND SO DOES THE POISONED ONE, WHICH IS THE FIELD WITH THE MOST TO LOSE**
    /// (CLOUD-1306). A poisoned bet is settled BY unwinding it, so `forget` runs
    /// on the exact path that would otherwise erase the judgement one line before
    /// the next lap re-bets on the same refused head — the measured stall,
    /// reproduced one process later.
    #[test]
    fn forgetting_a_bet_keeps_the_base_that_would_not_go_green() {
        let mut bet = Bet {
            base: Some(String::from(HOLDER)),
            refused: Some(String::from(HOLDER)),
            ..Bet::default()
        };
        bet.forget();
        assert_eq!(bet.refused.as_deref(), Some(HOLDER));
        assert!(
            !bet.would_rebet(HOLDER),
            "a base that would not go green is still refused after the bet unwinds"
        );
        assert!(
            bet.would_rebet(MOVED),
            "one poisoned candidate must not abandon speculation altogether"
        );
    }

    const HOLDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MAIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const MOVED: &str = "cccccccccccccccccccccccccccccccccccccccc";

    fn placed() -> Bet {
        Bet {
            base: Some(String::from(HOLDER)),
            undo: Some(String::from("dddddddddddddddddddddddddddddddddddddddd")),
            main_at_bet: Some(String::from(MAIN)),
            ..Bet::default()
        }
    }

    /// No bet is not a lost bet, and the distinction is the first arm.
    #[test]
    fn a_tree_with_no_bet_settles_to_nothing() {
        assert_eq!(
            settle(&Bet::default(), Some(MAIN), false, Live::No),
            Settle::Nothing
        );
    }

    /// **WON is checked first, and unconditionally.**
    ///
    /// Both arms below would misread it: an adopted bet has no `main_at_bet` to
    /// compare against, and a placed one would see `main` moved and call it lost
    /// — unwinding a linearization that is already correct.
    #[test]
    fn a_base_that_reached_main_is_landed_however_the_bet_arrived() {
        assert_eq!(
            settle(&placed(), Some(MOVED), true, Live::No),
            Settle::Landed
        );

        let adopted = Bet {
            recovered: true,
            main_at_bet: None,
            undo: None,
            ..placed()
        };
        assert_eq!(
            settle(&adopted, Some(MOVED), true, Live::No),
            Settle::Landed
        );
    }

    /// **THE THREE OUTCOMES, and the middle one is the whole reason there are
    /// three.**
    ///
    /// A bet is usually still PENDING at the next lap — the holder takes minutes
    /// to land, so "not on main yet" is the normal reading. Unwinding on it would
    /// undo the linearization every single lap and leave the mechanism running
    /// while achieving nothing: warm, then cold, then warm again.
    #[test]
    fn an_unmoved_main_with_a_live_holder_is_pending_and_a_dead_one_is_lost() {
        assert_eq!(
            settle(&placed(), Some(MAIN), false, Live::Yes),
            Settle::Pending
        );
        assert_eq!(settle(&placed(), Some(MAIN), false, Live::No), Settle::Lost);
    }

    /// An unmoved `main` used to END the question, and that was the defect.
    ///
    /// A holder can go away without `main` moving at all, and that reading is
    /// indistinguishable from "still landing" unless the lease is re-read.
    /// Measured: a holder whose CI died in a provider incident held the lease
    /// going nowhere, a sibling linearized onto its published head, and the two
    /// branches ended at the identical sha with neither able to land.
    #[test]
    fn a_could_not_look_on_the_lease_is_stale_rather_than_still_landing() {
        assert_eq!(
            settle(&placed(), Some(MAIN), false, Live::Unreadable),
            Settle::Lost,
            "failing open here would make a network blip land somebody else's work"
        );
        assert!(!Live::Unreadable.decide());
        assert!(!Live::No.decide());
        assert!(Live::Yes.decide());
    }

    /// **A TRUNK READING THAT WOULD NOT TAKE IS NOT A MOVED TRUNK.**
    ///
    /// The caller spelled the failed `resolve_ref` as `unwrap_or_default()`, so
    /// an unreadable `refs/remotes/origin/<ref>` arrived here as `""`. That
    /// compares unequal to every `main_at_bet`, so a placed bet fell past the
    /// unmoved-`main` arm and into "`main` moved and took something else" —
    /// [`Settle::Lost`], and the caller unwinds the tree. A fetch that lost the
    /// network, a clone with no tracking ref yet, or a ref file being rewritten
    /// under the read would each have thrown away a live linearization, which is
    /// the opposite of the fail-open direction `settle_the_bet`'s own header
    /// states.
    ///
    /// The `None` arm defers to the lease, exactly as the adopted arm does and
    /// for the same reason: with no trunk reading there is no comparison to make.
    /// So a live holder is `Pending` — and both non-`Yes` readings stay `Lost`,
    /// which is what keeps the fail-CLOSED posture where the lease is gone too.
    #[test]
    fn an_unreadable_trunk_defers_to_the_lease_rather_than_reading_as_a_moved_main() {
        assert_eq!(
            settle(&placed(), None, false, Live::Yes),
            Settle::Pending,
            "an unresolvable tracking ref is a could-not-look, and unwinding on \
             one discards a linearization that is still correct"
        );
        assert_eq!(settle(&placed(), None, false, Live::No), Settle::Lost);
        assert_eq!(
            settle(&placed(), None, false, Live::Unreadable),
            Settle::Lost
        );

        // WON still outranks it: an ancestry that resolved is an answer whether
        // or not the tip did.
        assert_eq!(settle(&placed(), None, true, Live::No), Settle::Landed);
    }

    /// THE OTHER SIDE OF THE SAME COMPARISON, and it read as a moved trunk.
    ///
    /// `main_at_bet` is a reading that may not have taken when the bet was
    /// placed. `Some(main_now) != None` is true, so the comparison fell straight
    /// through to `Lost` and unwound a speculation that was very much alive —
    /// the same defect the test above records, on the operand nobody checked.
    #[test]
    fn a_placed_bet_with_no_main_at_bet_defers_to_the_lease_too() {
        let unread = Bet {
            main_at_bet: None,
            ..placed()
        };
        assert_eq!(
            settle(&unread, Some(MAIN), false, Live::Yes),
            Settle::Pending,
            "a reading that never took is a could-not-look on this side of the \
             comparison exactly as it is on the other"
        );
        assert_eq!(settle(&unread, Some(MAIN), false, Live::No), Settle::Lost);
        assert_eq!(
            settle(&unread, Some(MAIN), false, Live::Unreadable),
            Settle::Lost
        );

        // ANTI-VACUITY: a bet whose reading DID take is still judged by it, so a
        // moved trunk with a dead holder is still lost.
        assert_eq!(
            settle(&placed(), Some(MOVED), false, Live::No),
            Settle::Lost
        );
    }

    /// A `main` that moved without taking the base is a lost bet, whoever placed
    /// it.
    #[test]
    fn a_moved_main_that_did_not_take_the_base_is_lost() {
        assert_eq!(
            settle(&placed(), Some(MOVED), false, Live::Yes),
            Settle::Lost
        );
    }

    /// An adopted bet is judged by the LEASE, because it has no `main_at_bet`.
    #[test]
    fn an_adopted_bet_is_judged_by_the_lease_rather_than_by_a_main_it_never_saw() {
        let adopted = Bet {
            recovered: true,
            main_at_bet: None,
            undo: None,
            ..placed()
        };
        assert_eq!(
            settle(&adopted, Some(MOVED), false, Live::Yes),
            Settle::Pending
        );
        assert_eq!(settle(&adopted, Some(MOVED), false, Live::No), Settle::Lost);
    }

    /// **CLOUD-1306, PORTED AS-IS AND PINNED SO IT CANNOT BE FIXED BY ACCIDENT.**
    ///
    /// A poisoned base — one whose tree will never pass `verify` — is
    /// byte-identical here to a holder that is simply slow: the lease is held,
    /// `main` has not moved, so `settle` says pending and the waiter sits. This
    /// case asserts that reading rather than the one a fixed version would give,
    /// because a port that quietly improved behaviour could not be shown to
    /// conserve it.
    ///
    /// When CLOUD-1306 lands, this case is the one that must change, and its
    /// changing is the review's cue that behaviour moved.
    #[test]
    fn a_poisoned_base_is_conserved_as_pending_because_cloud_1306_owns_the_fix() {
        assert_eq!(
            settle(&placed(), Some(MAIN), false, Live::Yes),
            Settle::Pending,
            "the holder is there and main has not moved — which is what a poisoned \
             base looks like from here, and there is no fourth arm"
        );
    }

    /// One outstanding bet at a time.
    #[test]
    fn the_same_candidate_is_not_bet_on_twice() {
        let bet = placed();
        assert!(!bet.would_rebet(HOLDER), "already the outstanding bet");
        assert!(bet.would_rebet(MOVED), "a different candidate is a new bet");
        assert!(
            Bet::default().would_rebet(HOLDER),
            "and a forgotten bet re-bets on the same holder — CLOUD-1306's other half"
        );
    }

    /// **A BASE THIS CLONE ALREADY WATCHED CONFLICT IS NOT BET ON AGAIN.**
    ///
    /// `place_the_bet` records the conflict and deliberately does NOT set
    /// `base` — the replay failed, so there is no borrowed range — which left
    /// `would_rebet` comparing against `None` and answering `true` on the next
    /// lap. The same conflicting rebase was then attempted every lap to reach
    /// the same answer, with CLOUD-369's mechanism written and unreachable.
    ///
    /// The third assertion is what keeps the fix from over-reaching: one bad
    /// candidate must not end speculation for the rest of the landing, which is
    /// what reading a bare flag would have done.
    #[test]
    fn a_base_known_to_conflict_is_not_bet_on_again() {
        let refused = Bet {
            conflicts: Some(String::from(HOLDER)),
            ..Bet::default()
        };
        assert!(
            !refused.would_rebet(HOLDER),
            "this clone already replayed onto it and watched the rebase conflict"
        );
        assert!(
            refused.would_rebet(MOVED),
            "a DIFFERENT holder is a fresh question — the flag form could not say this"
        );
        assert!(
            Bet::default().would_rebet(HOLDER),
            "and with nothing recorded the candidate is open, as before"
        );
    }

    /// Forgetting clears the bookkeeping AND what the child would read.
    #[test]
    fn forgetting_a_bet_unpublishes_it() {
        let mut bet = placed();
        assert_eq!(bet.published(), Some(HOLDER));
        bet.forget();
        assert_eq!(
            bet.published(),
            None,
            "a child that still read a base would report this branch as racing the \
             PR the bet was placed on"
        );
        assert!(!bet.live());
    }

    /// A bet whose base was recorded as refused settles POISONED.
    ///
    /// The inputs are deliberately the ones that spell a healthy `Pending`: the
    /// holder is live, `main` has not moved, and the base is not on the trunk.
    /// That is the whole defect — a poisoned holder is indistinguishable from a
    /// winning one on every reading EXCEPT the recorded judgement, so a case
    /// that varied anything else would pass against the old code too.
    #[test]
    fn a_base_recorded_as_refused_settles_poisoned() {
        let bet = Bet {
            refused: Some(String::from(HOLDER)),
            ..placed()
        };
        assert_eq!(
            settle(&bet, Some(MAIN), false, Live::Yes),
            Settle::Poisoned,
            "a live holder whose tree will not go green is not merely pending"
        );
    }

    /// **THE ANTI-VACUITY MIRROR, and without it the arm above is satisfied by a
    /// `settle` that answers `Poisoned` to everything.**
    ///
    /// The waiter's OWN tree being red records nothing — the re-verify off the
    /// borrowed base reproduces the failure, so the judgement is never written —
    /// and the identical inputs must still settle `Pending` and stop the lap
    /// exactly as before. CLOUD-1306's acceptance names this case in as many
    /// words: *a waiter whose own tree is red still stops.*
    #[test]
    fn a_waiter_whose_own_tree_is_red_still_settles_pending() {
        assert_eq!(
            settle(&placed(), Some(MAIN), false, Live::Yes),
            Settle::Pending,
            "nothing was recorded against this base, so the failure is the waiter's"
        );
    }

    /// A judgement about a DIFFERENT base does not poison this bet.
    ///
    /// The memory outlives the bet it refused, so a stale entry naming a holder
    /// that has since been replaced would unwind a perfectly good speculation
    /// every lap — the `Option<String>` earning its keep over a `bool`.
    #[test]
    fn a_refusal_recorded_against_another_base_leaves_this_bet_alone() {
        let bet = Bet {
            refused: Some(String::from(MOVED)),
            ..placed()
        };
        assert_eq!(
            settle(&bet, Some(MAIN), false, Live::Yes),
            Settle::Pending,
            "the refused base is not the one this bet is on"
        );
    }

    /// **A POISONED BASE THAT LANDED ANYWAY IS `Landed`, NOT `Poisoned`.**
    ///
    /// The trunk taking the base settles the question whatever a stale judgement
    /// says, and this is why the arm sits AFTER `Landed` rather than before it.
    /// Reversed, this would unwind a branch off commits it is already correctly
    /// linearized on — dropping landed work to honour an obsolete opinion.
    #[test]
    fn a_refused_base_that_reached_the_trunk_still_settles_landed() {
        let bet = Bet {
            refused: Some(String::from(HOLDER)),
            ..placed()
        };
        assert_eq!(
            settle(&bet, Some(MAIN), true, Live::Yes),
            Settle::Landed,
            "the trunk took it, so the judgement is history rather than a reason to unwind"
        );
    }

    /// With no bet outstanding a recorded refusal decides nothing.
    ///
    /// `refused` survives `forget`, so it is routinely populated while `base` is
    /// `None`. Reading it before the `Nothing` guard would have this answer
    /// `Poisoned` for a branch that is not speculating at all.
    #[test]
    fn a_recorded_refusal_with_no_bet_is_still_nothing() {
        let bet = Bet {
            refused: Some(String::from(HOLDER)),
            ..Bet::default()
        };
        assert_eq!(settle(&bet, Some(MAIN), false, Live::Yes), Settle::Nothing);
    }
}
