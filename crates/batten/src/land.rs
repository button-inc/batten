//! The landing lap, in-process (CLOUD-1335).
//!
//! # What this owns and what it deliberately does not
//!
//! A lap is fetch → replay → verify → push → wait → fast-forward, and a refusal
//! starts the next one by itself. This module owns the **git and record** work:
//! bring the base forward, replay the branch onto it, and write down what the
//! replay and the wait did. It stands beside the consumer's lander rather than
//! replacing it — the same shape `batten lease` took beside `land-lock`.
//!
//! # It DECIDES nothing, and that separation is the whole design
//!
//! Two policy questions arise in a lap and neither is answered here. *May a lap
//! continue past a conflicted replay?* is `rebase-conflict-stops-the-lap`'s.
//! *Which answer may a lap act on when its wait raced two questions?* is
//! `lap-waits-on-one-answer`'s. Both are `landing-loop` preset predicates over
//! the records this module writes, which is CLOUD-1148's thesis read forwards:
//! the mechanics move to the engine and the decisions become Rego. So nothing
//! here branches on "should we stop" — it does the work, writes down what it
//! did, and reports. A consumer wanting different rules writes different modules
//! and this code does not change.
//!
//! **That is also why the wait's LOSER is recorded.** The obvious shape writes
//! only the arm that won, and then a lap that raced properly and a lap that read
//! both answers produce identical records — so the module has nothing to decide
//! over. Writing the loser as an explicit could-not-look is what keeps the
//! property visible to something outside this file.
//!
//! The one thing it will not do is **resolve** a conflict.
//! [`crate::gitwrite::rebase`] refuses with `Rebase::Conflicted` rather than
//! taking a strategy, and this module carries that refusal outward unchanged.
//! `mem:workflow/landing-loop` gives the loop exactly one human stop and this is
//! it.
//!
//! # No `git` binary, which is the property the whole campaign exists to keep
//!
//! Every write below goes through [`crate::gitwrite`] and [`crate::lease`], which
//! speak to the odb and to the remote in process. `git.rs`'s
//! `no_second_git_invoker_exists` scans this file like every other, and it stays
//! green over a module that performs every write CLOUD-1148 §D recorded as
//! unreachable.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::gitwrite::{self, Rebase};

/// What one replay did.
///
/// Three outcomes rather than a `Result`, because none of them is an error: a
/// conflict is the mechanism working, and an already-current branch is the
/// ordinary state of a lap that has nothing to catch up on. An error here means
/// the replay could not be attempted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replay {
    /// Two sides changed the same lines. **The one human stop.** Nothing moved:
    /// the branch and the worktree are exactly as they were.
    Conflicted {
        /// The original commit that would not replay.
        commit: String,
        /// The paths that would not merge, in the order the merge reported them.
        paths: Vec<String>,
    },
    /// The branch already descended from the base, so nothing was replayed and
    /// no sha was minted — which is what keeps a still-good `verify` receipt
    /// alive for another lap.
    Current,
    /// The branch was replayed onto the moved base.
    Replayed {
        /// The sha the branch now points at.
        head: String,
        /// How many commits were replayed.
        commits: usize,
    },
}

impl Replay {
    /// The record line this outcome writes.
    ///
    /// Four columns, `rebase <verdict> <commit> <path>`, which is the layout
    /// `rebase-conflict-stops-the-lap` reads and the reason it is stated in both
    /// places rather than derived: the module is vendored into every consumer's
    /// binary and this writer is one consumer of it, so neither can be the
    /// other's authority. `crates/batten/tests/it/land.rs` holds them together.
    ///
    /// `-` IS THE COULD-NOT-LOOK SPELLING and is what an absent column carries,
    /// never an empty string — a column that collapsed to nothing would shift
    /// every column after it and be read through the wrong lens.
    ///
    /// POINTER-ONLY (non-negotiable rule 4): a sha and a path, never a hunk and
    /// never a conflict marker, which is the whole of what a conflict consists
    /// of and exactly what a reader must not be handed here.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Self::Conflicted { commit, paths } => {
                // THE FIRST PATH, because the record has one column for it and a
                // list would need a separator this format does not have. The
                // count is not lost: the caller reports it, and the module's job
                // is to say WHERE to look first rather than to enumerate.
                let path = paths.first().map_or("-", String::as_str);
                format!("rebase conflicted {commit} {path}")
            }
            Self::Current => String::from("rebase current - -"),
            Self::Replayed { head, .. } => format!("rebase replayed {head} -"),
        }
    }
}

/// Bring `reference` forward from `remote` into this clone, and answer where it
/// now points.
///
/// Three steps that have to stay in this order and are easy to get wrong as two:
/// the objects are fetched, then WRITTEN to the odb, and only then does the ref
/// move. A ref moved before its objects landed names a commit this clone cannot
/// read, which is a corrupt clone rather than a failed fetch.
///
/// # Errors
///
/// A transport failure, a reference the remote does not advertise, or an odb that
/// will not take the objects.
fn advance(root: &Path, remote: &str, reference: &str, tracking: &str) -> Result<String> {
    let fetched = crate::lease::fetch(remote, root, reference)
        .with_context(|| format!("land: fetch {reference} from the remote"))?;
    // EMPTY IS NOT A FAILURE — `Fetched::objects` is empty when the odb already
    // had the commit, which is the common case on a quiet base. Writing an empty
    // slice is a no-op and the ref still has to move, so there is no early
    // return here.
    gitwrite::write_objects(root, &fetched.objects)
        .with_context(|| format!("land: write the objects {reference} brought"))?;
    gitwrite::set_ref(root, tracking, &fetched.head)
        .with_context(|| format!("land: move {tracking} to the fetched head"))?;
    Ok(fetched.head)
}

/// One lap's replay: advance the base, replay the branch onto it, record it.
///
/// # Errors
///
/// A fetch that will not complete, an odb that will not take what it brought, or
/// a replay that could not be attempted. **A conflict is not an error** — it is
/// [`Replay::Conflicted`], and reporting it as a failure is what would let a
/// caller's `?` turn the loop's one human stop into a stack trace.
pub fn replay(root: &Path, remote: &str, reference: &str, branch: &str) -> Result<Replay> {
    let tracking = tracking_ref(reference);
    advance(root, remote, reference, &tracking)?;

    let outcome = gitwrite::rebase(root, &format!("refs/heads/{branch}"), &tracking)
        .with_context(|| format!("land: replay {branch} onto {tracking}"))?;
    let replayed = match outcome {
        Rebase::Conflicted { commit, paths } => Replay::Conflicted { commit, paths },
        Rebase::Current => Replay::Current,
        Rebase::Replayed { head, commits } => Replay::Replayed { head, commits },
    };

    // RECORDED WHATEVER HAPPENED, INCLUDING THE CLEAN CASE. A store written only
    // on conflict cannot tell "this lap replayed cleanly" from "no lap has run",
    // and the module reads the LAST line precisely so a resolved conflict stops
    // refusing — which only works if the resolution writes a line of its own.
    record(root, branch, &replayed)?;
    Ok(replayed)
}

/// Where a remote reference is tracked locally.
///
/// `refs/heads/main` on the remote is `refs/remotes/origin/main` here. Written as
/// a function rather than formatted at the call site so the one place that
/// decides this is greppable, and so a caller cannot pass a tracking ref where a
/// remote one belongs.
fn tracking_ref(reference: &str) -> String {
    let leaf = reference.rsplit('/').next().unwrap_or(reference);
    format!("refs/remotes/origin/{leaf}")
}

/// Append this lap's outcome to the branch's record.
///
/// PUBLIC BECAUSE THE SECOND TIER HAS TO DRIVE IT. `replay` needs a real remote,
/// so a compiled-binary case cannot reach this writer through it — and a case
/// that fabricated the store instead would assert the very shape the engine may
/// be unable to produce, which is the failure `.claude/rules/policy-modules.md`
/// records for exactly this pair. `crates/batten/tests/it/land.rs` writes through
/// here and reads back through `batten check`, so the writer and the vendored
/// module meet over the engine rather than over a fixture somebody typed.
///
/// APPEND, NEVER REPLACE, because the store is a HISTORY and the predicate over
/// it reads the last line: a lap that conflicted and a later lap that resolved
/// the conflict are two facts, and a store keeping only the newer one cannot say
/// that the older was ever true. `record::store` replaces, which is right for the
/// stores that answer "what is the current state" and wrong for this one.
///
/// # Errors
///
/// A store directory or file that will not open or append.
pub fn record(root: &Path, branch: &str, outcome: &Replay) -> Result<()> {
    append(root, branch, std::slice::from_ref(&outcome.line()))
}

/// Append `lines` to this branch's lap record.
///
/// ONE WRITER FOR BOTH FAMILIES, because the store is shared: a replay outcome
/// and a wait outcome go to the same file and are told apart by their KIND
/// column, so two writers computing the path separately would be two authorities
/// over one location.
///
/// A DETACHED HEAD HAS NOTHING TO KEY ON, exactly as the claim receipt does not,
/// so the write is skipped rather than failing the lap. The work itself happened
/// either way, and turning "nowhere to write this down" into "the lap failed"
/// would report a verdict about the clone as a verdict about the branch.
///
/// ONE OPEN FOR THE WHOLE BATCH, which is what makes `record_wait`'s both-arms
/// signature mean something: a race's two lines land together or not at all,
/// rather than leaving a record with a winner and no loser — the exact shape a
/// lap reading both sides would also produce.
fn append(root: &Path, branch: &str, lines: &[String]) -> Result<()> {
    let Ok(git_dir) = crate::git::git_dir(root) else {
        return Ok(());
    };
    let claim = crate::claim::claimed_token(&git_dir.join("batten-receipts"), branch);
    let path = crate::recorder::record_path(&git_dir, LAP_RECORD, branch, claim.as_deref());
    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)
        .with_context(|| format!("land: create the record store {}", directory.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("land: open the lap record {}", path.display()))?;
    for line in lines {
        writeln!(file, "{line}")
            .with_context(|| format!("land: append to the lap record {}", path.display()))?;
    }
    Ok(())
}

/// The record this module writes, and the one `record::VERB_WRITTEN` names so a
/// module can read it back.
pub const LAP_RECORD: &str = "lap";

/// Which arm of the lap's raced wait an answer came from (CLOUD-1338).
///
/// # The race, and why it is two arms rather than one wait
///
/// A lap asks two questions at once — *is this commit green?* and *is this
/// commit still landable?* — and whichever answers first decides. The loser's
/// answer is **voided**: the moment the base advances, the run in flight is
/// spend for a verdict nobody will read, and the next lap's push supersedes it
/// through the forge's own cancel-in-progress, which is why nothing here cancels
/// a run by hand.
///
/// The arms are named rather than numbered because the record is what
/// `lap-waits-on-one-answer` reads, and a reviewer chasing a refusal needs to
/// know WHICH question answered, not that some arm did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Is the commit green? — the check-run roster's verdict.
    Green,
    /// Has the base moved out from under it? — the staleness question.
    Stale,
}

impl Arm {
    /// The token this arm writes into the record's second column.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Stale => "stale",
        }
    }
}

/// One arm's answer, or its silence.
///
/// **A LOSER IS RECORDED, AND RECORDING IT IS THE POINT.** The obvious shape is
/// to write down only the arm that won — and then a lap that read both is
/// indistinguishable from a lap that raced properly, because the record looks
/// the same either way. Writing the loser as an explicit could-not-look is what
/// makes the difference legible to a module: two answers is a defect, one answer
/// beside one silence is the design working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    /// Which question this is.
    pub arm: Arm,
    /// What it answered, or `None` where it was abandoned unread — the loser of
    /// the race, or a poller that could not reach the forge.
    pub verdict: Option<String>,
    /// The commit the question was about.
    pub sha: String,
}

impl Answered {
    /// The record line this answer writes.
    ///
    /// Four columns, `wait <arm> <verdict> <sha>`, which is the layout
    /// `lap-waits-on-one-answer` reads. Stated in both places rather than derived
    /// for the reason its sibling gives: the module is vendored into every
    /// consumer's binary and this writer is one consumer of it, so neither can be
    /// the other's authority.
    ///
    /// POINTER-ONLY (rule 4): an arm token, a verdict token and a sha. Never a
    /// check's log body, and never the forge's payload.
    #[must_use]
    pub fn line(&self) -> String {
        let verdict = self.verdict.as_deref().unwrap_or("-");
        format!("wait {} {verdict} {}", self.arm.token(), self.sha)
    }
}

/// Append this wait's outcomes to the branch's record.
///
/// BOTH ARMS IN ONE CALL, so a caller cannot write the winner and forget the
/// loser — which would produce exactly the record a lap reading both sides
/// produces, and make the module unable to tell them apart. The signature is the
/// mechanism: there is no way to record half a race.
///
/// # Errors
///
/// A store directory or file that will not open or append.
pub fn record_wait(root: &Path, branch: &str, answers: &[Answered]) -> Result<()> {
    append(
        root,
        branch,
        &answers.iter().map(Answered::line).collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four columns the vendored module reads, pinned on this side too.
    ///
    /// The writer and the reader are deliberately not each other's authority —
    /// the module ships into every consumer's binary and this is one consumer —
    /// so the layout is asserted at both ends rather than derived at one.
    #[test]
    fn every_outcome_writes_four_columns_led_by_the_kind() {
        for outcome in [
            Replay::Conflicted {
                commit: String::from("abc1234"),
                paths: vec![String::from("shared.txt")],
            },
            Replay::Current,
            Replay::Replayed {
                head: String::from("def5678"),
                commits: 1,
            },
        ] {
            let line = outcome.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "rebase", "the kind column leads: {line:?}");
        }
    }

    /// A conflict names the commit and the first path, and nothing else.
    #[test]
    fn a_conflict_records_a_pointer_and_never_a_hunk() {
        let line = Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: vec![String::from("shared.txt"), String::from("other.txt")],
        }
        .line();
        assert_eq!(line, "rebase conflicted abc1234 shared.txt");
    }

    /// A CONFLICT WITH NO PATH still writes four columns, with `-` where the
    /// pointer would be. An empty column would shift every column after it, and
    /// the reader's own length check would then skip the line entirely — turning
    /// the loop's one human stop into silence.
    #[test]
    fn a_conflict_with_no_path_keeps_the_column_count() {
        let line = Replay::Conflicted {
            commit: String::from("abc1234"),
            paths: Vec::new(),
        }
        .line();
        assert_eq!(line, "rebase conflicted abc1234 -");
    }

    /// The two clean outcomes are distinguishable from each other and from a
    /// conflict — a replay that minted a sha, and one that had nothing to mint.
    #[test]
    fn the_clean_outcomes_are_told_apart() {
        assert_eq!(Replay::Current.line(), "rebase current - -");
        assert_eq!(
            Replay::Replayed {
                head: String::from("def5678"),
                commits: 3,
            }
            .line(),
            "rebase replayed def5678 -"
        );
    }

    #[test]
    fn a_remote_reference_resolves_to_its_tracking_ref() {
        assert_eq!(tracking_ref("refs/heads/main"), "refs/remotes/origin/main");
        assert_eq!(tracking_ref("main"), "refs/remotes/origin/main");
    }

    /// A wait line carries four columns led by its kind, like a replay line.
    #[test]
    fn every_wait_answer_writes_four_columns_led_by_the_kind() {
        for answer in [
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            },
            Answered {
                arm: Arm::Stale,
                verdict: None,
                sha: String::from("abc1234"),
            },
        ] {
            let line = answer.line();
            let columns: Vec<&str> = line.split(' ').collect();
            assert_eq!(columns.len(), 4, "four columns exactly, got {line:?}");
            assert_eq!(columns[0], "wait", "the kind column leads: {line:?}");
        }
    }

    /// **THE LOSER IS WRITTEN AS COULD-NOT-LOOK, and that is what makes the race
    /// legible.** An arm abandoned unread records `-` rather than being omitted:
    /// omitting it would make a lap that raced properly and a lap that read both
    /// sides produce records nothing can tell apart.
    #[test]
    fn a_voided_loser_records_could_not_look_rather_than_vanishing() {
        assert_eq!(
            Answered {
                arm: Arm::Stale,
                verdict: None,
                sha: String::from("abc1234"),
            }
            .line(),
            "wait stale - abc1234"
        );
        assert_eq!(
            Answered {
                arm: Arm::Green,
                verdict: Some(String::from("success")),
                sha: String::from("abc1234"),
            }
            .line(),
            "wait green success abc1234"
        );
    }

    /// The two arms are distinguishable, which is what lets a module count
    /// ANSWERING ARMS rather than recorded lines.
    #[test]
    fn the_two_arms_carry_different_tokens() {
        assert_ne!(Arm::Green.token(), Arm::Stale.token());
    }
}
