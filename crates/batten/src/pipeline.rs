//! The landing pipeline as a DECLARED list, with a compensation per step
//! (CLOUD-1338, PR #848's review).
//!
//! # What this replaces, and why a list rather than an array literal
//!
//! The driver was an array literal of [`crate::land::Step`] with a compile-time
//! step→function `match`. A consumer could not add, remove, reorder or
//! re-implement a step, nor supply a fast-forward for a forge without this
//! repository's bot — so the successor still described *"Button-specific landing
//! policy a consumer inherits and cannot tailor"*, which is the sentence the
//! whole retirement exists to falsify. A shell script can at least be forked
//! where a `match` arm needs a release.
//!
//! # Compensation is per STEP, which is what forced the list
//!
//! Readying is undone by re-drafting; a held lease by a tombstone; a speculative
//! bet by an abandon. `Progress` is one global table, so there was nowhere to say
//! *what unwinds*. Giving each step its own undo IS a declared list — the two
//! changes are one change, which is why they land together.
//!
//! The shortage was already visible before anyone asked for this: a
//! `Progress::Proceed if step == Step::Verify` staleness probe sat in the driver
//! sixteen lines below a comment promising that policy *"cannot land in four
//! `if`s out of five"*. `(step, code) → progress` had no per-step room, so the
//! first thing that needed it leaked into the loop. [`StepRow::precheck`] is
//! where it goes instead.
//!
//! # A COMPENSATION IS A DURABLE EXTERNAL WRITE, NEVER AN IN-PROCESS UNWIND
//!
//! This is the part that had to be settled before the code existed, because the
//! obvious implementation is wrong here. A saga-style compensation stack unwound
//! in the same process does not run when the container is killed —
//! `mise-tasks/land.sh:353` records exactly that: *"a trap runs on the container
//! kill too."* The compensations that survive are the ones landing OUTSIDE the
//! process: a pull request re-drafted on the forge, a lease tombstone, a
//! cancelled run.
//!
//! The lease's own `expires` is the same idea already done right — a
//! compensation that needs no live process to perform it, because the passage of
//! time performs it. Every arm of [`Compensation`] is held to that standard, and
//! [`Compensation::is_durable`] is where a future arm gets asked.
//!
//! # The invariant the schema carries
//!
//! **An effectful step positioned before the commit point must declare a
//! compensation**, and [`crate::land::Step::FastForward`] is the commit point —
//! irreversible by definition, which is exactly why everything before it needs
//! one. [`Pipeline::validate`] refuses a composition that spends and then
//! abandons, so it fails to LOAD rather than failing in production.
//!
//! That is raise-only in the same spirit as the deny-only Rego surface: a
//! consumer may compose any pipeline, but not one that leaks spend.

use crate::land::Step;

/// A step's declared undo, run when a lap leaves without landing.
///
/// **Every arm names a write that outlives this process.** An arm that named an
/// in-process rollback would be unable to run in the one case compensation is
/// for — see this module's header, and `land.sh:353`'s measured note that a trap
/// runs on the container kill too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compensation {
    /// Nothing this step did outlives the process, so there is nothing to undo.
    ///
    /// **Declared rather than defaulted.** A step reaching this arm has said so;
    /// a step that simply omitted the field would be indistinguishable from one
    /// nobody thought about, which is the whole failure [`Pipeline::validate`]
    /// exists to refuse.
    Nothing,
    /// Put the pull request back to draft.
    ///
    /// CI skips drafts, so this is what stops the NEXT push — from any source —
    /// spending another runner on a failure nobody has fixed yet.
    Redraft,
    /// Cancel the runs still spending on this head, sparing the fan-in's.
    Abandon,
    /// Hand the landing lease back, so the next branch does not wait out a TTL.
    ReleaseLease,
}

impl Compensation {
    /// Whether this undo lands outside the process that performs it.
    ///
    /// **The question a new arm must answer**, and the reason it is a method
    /// rather than a comment: an arm added later gets asked by the compiler
    /// rather than by a reviewer who remembers this file's header.
    #[must_use]
    pub const fn is_durable(self) -> bool {
        // EVERY VARIANT NAMED, never a wildcard, and that is the mechanism this
        // method is: `Compensation` is `#[non_exhaustive]`, so an arm added later
        // fails to compile HERE and its author is asked the question by the
        // compiler rather than by a reviewer who remembers this file's header.
        //
        // `Nothing` answers yes vacuously — there is no effect, so nothing could
        // fail to survive — and the other three are writes to somebody else's
        // server or ref. One arm rather than two because clippy is right that the
        // bodies are identical today; the discrimination this buys is over the
        // arm nobody has written yet, which is exactly what
        // `Invalid::NotDurable` is the slot for.
        match self {
            Self::Nothing | Self::Redraft | Self::Abandon | Self::ReleaseLease => true,
        }
    }

    /// Whether this step actually undoes something.
    #[must_use]
    pub const fn undoes_something(self) -> bool {
        !matches!(self, Self::Nothing)
    }

    /// Whether this undo is owed as soon as its step is ATTEMPTED, rather than
    /// once the step has succeeded.
    ///
    /// # A step's SUCCESS is not always what creates the effect
    ///
    /// The driver records an effectful row as entered on [`ExitCode::Success`]
    /// alone, and for `Ready` that is exactly right: a refused ready bought no
    /// matrix, so re-drafting over it would draft a pull request the lap never
    /// made ready. Applied to the step that WAITS, the same rule inverts the arm
    /// it exists for (PR #848's review). A wait comes back `Success` only when it
    /// is GREEN; red, stale and unanswered are the three outcomes where runs are
    /// still billing against a head nothing will land — and those were the three
    /// that recorded nothing. [`Self::Abandon`] therefore ran only after a green
    /// wait whose fast-forward then lapped, which is CLOUD-900's *"runs on a
    /// superseded head keep spending"* backwards: it cancelled a green head's
    /// runs and never a red one's.
    ///
    /// # Why it hangs off the COMPENSATION rather than off the step
    ///
    /// A `step == Wait` arm in the driver is the `step == Verify` exception this
    /// module exists to have removed, reintroduced one field later. And the
    /// discrimination is not really the step's: what makes this undo attempt-owed
    /// is that it cancels runs the steps BEFORE it bought, so it is owed from the
    /// moment those runs can exist. A consumer who hangs `Abandon` off a
    /// different step inherits the same reading without declaring anything.
    ///
    /// A `match` rather than a comparison, for [`Self::is_durable`]'s reason: an
    /// arm nobody has written yet is a compile error rather than a default.
    #[must_use]
    pub const fn owed_on_attempt(self) -> bool {
        match self {
            Self::Abandon => true,
            Self::Nothing | Self::Redraft | Self::ReleaseLease => false,
        }
    }
}

/// One step of a declared pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StepRow {
    /// Which primitive this row dispatches.
    pub step: Step,
    /// Whether reaching this step leaves something behind that a later stop
    /// would have to undo.
    ///
    /// **Not derivable from the step's name**, which is why it is declared: the
    /// same primitive is effectful for a consumer whose gate posts a comment and
    /// free for one whose gate only reads.
    pub effectful: bool,
    /// What undoes this step, where a lap leaves without landing.
    pub compensate: Compensation,
    /// Whether this row asks a question of its own before dispatching.
    ///
    /// This is where the driver's `step == Verify` exception goes: a per-step
    /// slot rather than an `if` in the loop.
    pub precheck: Option<Precheck>,
}

impl StepRow {
    /// Whether this row owes its undo, given how its primitive finished.
    ///
    /// **THE DRIVER'S RULE, HERE RATHER THAN IN THE LOOP**, for the reason
    /// [`StepRow::precheck`] exists: a `step == Wait` arm in `run_land_lap` is
    /// the `step == Verify` exception this module was written to remove,
    /// reintroduced one conjunction later. It is also what makes the rule
    /// testable without driving a whole lap against a forge.
    ///
    /// `succeeded` is the primitive's own answer, which is right for `Ready` and
    /// wrong on its own for `Wait` — see [`Compensation::owed_on_attempt`], which
    /// carries the measurement.
    #[must_use]
    pub const fn entered(&self, succeeded: bool) -> bool {
        self.effectful && (succeeded || self.compensate.owed_on_attempt())
    }
}

/// A question a row asks before its primitive runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Precheck {
    /// Has the base moved while the previous step ran?
    ///
    /// **The last free moment**, which is the whole reason this is a precheck
    /// rather than a step: everything after `verify` is metered, so a base that
    /// moved while the gate ran makes the push a matrix spent to learn what one
    /// ref read already knows. Fails open.
    BaseMoved,
    /// Is an outstanding speculation still worth carrying?
    ///
    /// **AT THE TOP OF THE LAP, BEFORE ANYTHING CAN PUSH**, which is the property
    /// `mise-tasks/land.sh` states in as many words: *"there is no path from a
    /// losing bet to a push, which is what makes speculating safe rather than
    /// merely fast."* A lost bet leaves this branch carrying another branch's
    /// commits, and the lap's own replay runs immediately after — so the unwind
    /// has nothing to re-linearize by hand.
    ///
    /// A precheck rather than a `Step` because it spends nothing and cannot land:
    /// it reads refs and the lease, and either keeps the tree or rewinds it.
    BetSettled,
}

/// A declared landing pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    /// The steps, in the order a lap walks them.
    pub steps: Vec<StepRow>,
}

/// Why a composition will not load.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invalid {
    /// An effectful step before the commit point declares no undo.
    ///
    /// The finding a consumer sees when their composition would spend and then
    /// abandon. Pointer-only: the step, never a rendering of the whole list.
    Uncompensated(Step),
    /// A compensation that would not survive the process performing it.
    NotDurable(Step),
    /// The commit point is missing, so nothing can ever land.
    NoCommitPoint,
    /// The commit point is not last, so a step would run after the irreversible
    /// one.
    CommitPointNotLast(Step),
    /// One step declared twice. Which of the two an undo belongs to is then
    /// unanswerable.
    Duplicate(Step),
}

/// The step that commits, after which nothing is reversible.
///
/// Named once rather than compared inline: [`Pipeline::validate`] asks three
/// separate questions about it, and three spellings of "which one is the commit
/// point" is three places for them to disagree.
pub const COMMIT_POINT: Step = Step::FastForward;

impl Pipeline {
    /// Refuse a composition that would spend and then abandon.
    ///
    /// # The invariant, and why it is checked at LOAD
    ///
    /// An effectful step positioned before [`COMMIT_POINT`] must declare a
    /// compensation. A composition that violates it does not fail here and
    /// succeed in production — it never loads, which is the difference between a
    /// schema and a convention.
    ///
    /// # Errors
    ///
    /// Every way the list is unwalkable, as [`Invalid`]. All of them are
    /// returned, not just the first: an author fixing one at a time pays a load
    /// cycle each.
    #[must_use]
    pub fn validate(&self) -> Vec<Invalid> {
        let mut found = Vec::new();

        let mut seen: Vec<Step> = Vec::new();
        for row in &self.steps {
            if seen.contains(&row.step) {
                found.push(Invalid::Duplicate(row.step));
            }
            seen.push(row.step);
        }

        let Some(commit_at) = self.steps.iter().position(|row| row.step == COMMIT_POINT) else {
            found.push(Invalid::NoCommitPoint);
            return found;
        };
        if commit_at + 1 != self.steps.len() {
            // NAMES THE STEP THAT FOLLOWS IT, not the commit point: the commit
            // point is where it belongs and the trailing row is the mistake.
            if let Some(row) = self.steps.get(commit_at + 1) {
                found.push(Invalid::CommitPointNotLast(row.step));
            }
        }

        for row in &self.steps[..commit_at] {
            if row.effectful && !row.compensate.undoes_something() {
                found.push(Invalid::Uncompensated(row.step));
            }
            if !row.compensate.is_durable() {
                found.push(Invalid::NotDurable(row.step));
            }
        }
        found
    }

    /// The undos a lap owes, for the steps it actually entered, newest first.
    ///
    /// **REVERSE ORDER, and it is the same reason a stack unwinds that way**: a
    /// later step's effect sits on top of an earlier one's, so undoing the
    /// earlier one first can leave the later effect pointing at something that no
    /// longer exists.
    ///
    /// Takes what was ENTERED rather than reading the whole list: a lap that
    /// stopped at `Verify` never readied, so it owes no re-draft, and computing
    /// the owed set from the composition alone would compensate effects nobody
    /// caused.
    #[must_use]
    pub fn unwind(&self, entered: &[Step]) -> Vec<Compensation> {
        entered
            .iter()
            .rev()
            .filter_map(|step| {
                self.steps
                    .iter()
                    .find(|row| row.step == *step)
                    .map(|row| row.compensate)
            })
            .filter(|compensation| compensation.undoes_something())
            .collect()
    }
}

impl Default for Pipeline {
    /// This repository's own composition — the default an adopter amends.
    ///
    /// **`Ready` is the one that buys the matrix**, which its own primitive's
    /// header says: *"readying is what starts CI, so it is the one site that buys
    /// a matrix."* That makes it the effectful step whose compensation the whole
    /// invariant exists for, and [`Compensation::Redraft`] is it.
    ///
    /// `Push` is effectful too and its undo is the lease: a push that landed on a
    /// remote ref cannot be un-pushed, but the lease it holds can be handed back
    /// so the next branch does not wait out a TTL.
    fn default() -> Self {
        Self {
            steps: vec![
                StepRow {
                    step: Step::Replay,
                    effectful: false,
                    compensate: Compensation::Nothing,
                    // SETTLED BEFORE THE REPLAY, never after: the replay is what
                    // re-linearizes this branch, so a bet unwound here needs no
                    // second rebase — and a bet left un-settled would have the
                    // replay build on top of somebody else's commits.
                    precheck: Some(Precheck::BetSettled),
                },
                StepRow {
                    step: Step::Verify,
                    effectful: false,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: Step::Ready,
                    effectful: true,
                    compensate: Compensation::Redraft,
                    // THE DRIVER'S OLD EXCEPTION, as a row column. It ran after
                    // `Verify` answered and before `Ready` dispatched, which is
                    // exactly this slot.
                    precheck: Some(Precheck::BaseMoved),
                },
                StepRow {
                    step: Step::Push,
                    effectful: true,
                    compensate: Compensation::ReleaseLease,
                    precheck: None,
                },
                StepRow {
                    step: Step::Wait,
                    effectful: true,
                    compensate: Compensation::Abandon,
                    precheck: None,
                },
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A WAIT THAT DID NOT SUCCEED STILL OWES ITS ABANDON, AND A READY THAT
    /// DID NOT SUCCEED OWES NOTHING.**
    ///
    /// The driver's rule was `effectful && succeeded`, which is right for the
    /// second half and inverts the first: `land wait` answers success only when
    /// the head is GREEN, so red, stale and unanswered — the three outcomes where
    /// runs are billing against a head nothing will land — recorded no entry and
    /// `Compensation::Abandon` never ran for them.
    ///
    /// Four assertions rather than one, because each half of the conjunction can
    /// be got wrong on its own: a rule that always returned `true` passes the
    /// wait cases, a rule that kept `&& succeeded` passes the ready cases, and a
    /// rule ignoring `effectful` passes both.
    #[test]
    fn a_wait_owes_its_undo_on_the_attempt_and_a_ready_owes_its_undo_on_success() {
        let shipped = Pipeline::default();
        // `is_some_and` rather than an unwrap: the crate's lints refuse a panic
        // on a reachable path even here, and a step the composition does not
        // declare should read as *did not enter* rather than end the run.
        let entered = |step: Step, succeeded: bool| {
            shipped
                .steps
                .iter()
                .find(|row| row.step == step)
                .is_some_and(|row| row.entered(succeeded))
        };

        assert!(
            entered(Step::Wait, false),
            "a red, stale or unanswered wait leaves runs live and owes the abandon"
        );
        assert!(entered(Step::Wait, true), "a green wait owes it too");
        assert!(
            !entered(Step::Ready, false),
            "a refused ready bought no matrix, so there is no draft to undo"
        );
        assert!(entered(Step::Ready, true));
        assert!(
            !entered(Step::Verify, true),
            "a step that is not effectful never owes an undo, however it ended"
        );
    }

    /// **`Abandon` IS THE ONLY ATTEMPT-OWED UNDO, and the mirror is what makes
    /// this case discriminate.** Without the second half, a predicate returning
    /// `true` for everything would satisfy the first — and that predicate would
    /// re-draft over a ready that never fired.
    #[test]
    fn only_the_undo_that_cancels_runs_is_owed_before_its_step_succeeds() {
        assert!(Compensation::Abandon.owed_on_attempt());
        for compensation in [
            Compensation::Nothing,
            Compensation::Redraft,
            Compensation::ReleaseLease,
        ] {
            assert!(
                !compensation.owed_on_attempt(),
                "{compensation:?} undoes an effect its own step's success creates"
            );
        }
    }

    /// **THE INVARIANT, AND THE PAIR THAT SHOWS IT DISCRIMINATES.**
    ///
    /// An effectful step before the commit point with no undo fails to load; the
    /// same step with one loads. Without the second half, a validator that
    /// refused everything would satisfy the first.
    #[test]
    fn an_effectful_step_before_the_commit_point_must_declare_an_undo() {
        let leaks = Pipeline {
            steps: vec![
                StepRow {
                    step: Step::Ready,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
            ],
        };
        assert_eq!(
            leaks.validate(),
            vec![Invalid::Uncompensated(Step::Ready)],
            "a composition that spends and then abandons must not load"
        );

        let compensated = Pipeline {
            steps: vec![
                StepRow {
                    step: Step::Ready,
                    effectful: true,
                    compensate: Compensation::Redraft,
                    precheck: None,
                },
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
            ],
        };
        assert!(
            compensated.validate().is_empty(),
            "and one that declares its undo loads: {:?}",
            compensated.validate()
        );
    }

    /// **THE COMMIT POINT ITSELF NEEDS NO UNDO, which is not an oversight.**
    ///
    /// It is irreversible by definition — that is what makes it the commit point,
    /// and what makes everything before it need one. A validator demanding a
    /// compensation for it would be demanding the impossible and would refuse
    /// every honest composition.
    #[test]
    fn the_commit_point_needs_no_compensation() {
        assert!(Pipeline::default().validate().is_empty());
    }

    /// **THE BET IS SETTLED BEFORE ANYTHING IS SPENT**, and the position is the
    /// property rather than the presence.
    ///
    /// `mise-tasks/land.sh` states the invariant in as many words: *"there is no
    /// path from a losing bet to a push."* A [`Precheck::BetSettled`] positioned
    /// after any effectful row would give it one — the lap would spend a matrix,
    /// or push, on a tree still carrying another branch's commits, and only then
    /// discover the bet was lost. So this asserts the ORDER, which a row-presence
    /// case would not: moving the declaration one row down leaves it present and
    /// leaves the invariant broken.
    #[test]
    fn the_bet_settles_before_the_first_effectful_step() {
        let shipped = Pipeline::default();
        let settles = shipped
            .steps
            .iter()
            .position(|row| row.precheck == Some(Precheck::BetSettled));
        assert!(
            settles.is_some(),
            "the shipped composition settles an outstanding bet"
        );
        let first_spend = shipped.steps.iter().position(|row| row.effectful);
        assert!(
            settles.is_some_and(|at| first_spend.is_none_or(|spend| at <= spend)),
            "the settle is at row {settles:?} and the first spend at {first_spend:?}"
        );
    }

    /// A step after the commit point is refused: it would run after the
    /// irreversible one, so its own undo could never help.
    #[test]
    fn nothing_may_be_positioned_after_the_commit_point() {
        let trailing = Pipeline {
            steps: vec![
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: Step::Push,
                    effectful: true,
                    compensate: Compensation::ReleaseLease,
                    precheck: None,
                },
            ],
        };
        assert_eq!(
            trailing.validate(),
            vec![Invalid::CommitPointNotLast(Step::Push)],
            "and the finding names the trailing row rather than the commit point"
        );
    }

    /// **A COMPOSITION WITH NO COMMIT POINT CAN NEVER LAND**, which is a
    /// different failure from an uncompensated one and must not be reported as a
    /// clean list.
    #[test]
    fn a_composition_that_can_never_land_is_refused() {
        let never = Pipeline {
            steps: vec![StepRow {
                step: Step::Verify,
                effectful: false,
                compensate: Compensation::Nothing,
                precheck: None,
            }],
        };
        assert_eq!(never.validate(), vec![Invalid::NoCommitPoint]);
    }

    /// One step declared twice makes "which row's undo is this" unanswerable.
    #[test]
    fn a_step_declared_twice_is_refused() {
        let twice = Pipeline {
            steps: vec![
                StepRow {
                    step: Step::Verify,
                    effectful: false,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: Step::Verify,
                    effectful: false,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
            ],
        };
        assert!(twice.validate().contains(&Invalid::Duplicate(Step::Verify)));
    }

    /// **EVERY FINDING IS RETURNED, not just the first**, because an author
    /// fixing one at a time pays a load cycle each.
    #[test]
    fn a_composition_with_two_faults_reports_both() {
        let two = Pipeline {
            steps: vec![
                StepRow {
                    step: Step::Ready,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: Step::Push,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
                StepRow {
                    step: COMMIT_POINT,
                    effectful: true,
                    compensate: Compensation::Nothing,
                    precheck: None,
                },
            ],
        };
        assert_eq!(two.validate().len(), 2, "{:?}", two.validate());
    }

    /// **THE UNWIND IS OVER WHAT WAS ENTERED, never over the whole list.**
    ///
    /// A lap that stopped at `Verify` never readied, so it owes no re-draft.
    /// Computing the owed set from the composition alone would compensate
    /// effects nobody caused — which on this pipeline means re-drafting a pull
    /// request that was never made ready.
    #[test]
    fn a_lap_owes_undos_only_for_the_steps_it_entered() {
        let pipeline = Pipeline::default();
        assert!(
            pipeline.unwind(&[Step::Replay, Step::Verify]).is_empty(),
            "nothing effectful was entered"
        );
        assert_eq!(
            pipeline.unwind(&[Step::Replay, Step::Verify, Step::Ready]),
            vec![Compensation::Redraft],
            "readying bought the matrix, so the tap is what closes"
        );
    }

    /// **NEWEST FIRST, because a later effect sits on top of an earlier one.**
    ///
    /// Releasing the lease before re-drafting would hand the next branch a
    /// landing slot while this one's pull request is still ready and still
    /// spending.
    #[test]
    fn the_unwind_runs_newest_first() {
        let pipeline = Pipeline::default();
        assert_eq!(
            pipeline.unwind(&[Step::Ready, Step::Push, Step::Wait]),
            vec![
                Compensation::Abandon,
                Compensation::ReleaseLease,
                Compensation::Redraft,
            ],
            "the reverse of the order they took effect in"
        );
    }

    /// A step the composition does not declare contributes no undo rather than
    /// panicking — an entered set naming one is a driver bug, and a compensation
    /// pass is the wrong place to discover it loudly.
    #[test]
    fn an_entered_step_the_pipeline_does_not_declare_is_skipped() {
        let pipeline = Pipeline {
            steps: vec![StepRow {
                step: COMMIT_POINT,
                effectful: true,
                compensate: Compensation::Nothing,
                precheck: None,
            }],
        };
        assert!(pipeline.unwind(&[Step::Ready]).is_empty());
    }

    /// Every compensation this crate ships lands outside the process performing
    /// it, which is the property the whole design rests on.
    #[test]
    fn every_shipped_compensation_is_durable() {
        for compensation in [
            Compensation::Nothing,
            Compensation::Redraft,
            Compensation::Abandon,
            Compensation::ReleaseLease,
        ] {
            assert!(
                compensation.is_durable(),
                "{compensation:?} would not survive the container being killed, \
                 which is the one case compensation exists for"
            );
        }
    }
}
