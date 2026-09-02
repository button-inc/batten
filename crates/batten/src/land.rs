//! The landing lap, in-process (CLOUD-1335).
//!
//! # What this owns and what it deliberately does not
//!
//! A lap is fetch → replay → verify → push → wait → fast-forward, and a refusal
//! starts the next one by itself. This module owns the **replay** half: bring the
//! base forward, replay the branch onto it, and record what happened. The
//! remaining phases stay in the consumer's lander until they land here too, so
//! this is a parallel capability rather than a cut-over — the same shape
//! `batten lease` took beside `land-lock`.
//!
//! # It DECIDES nothing, and that separation is the whole design
//!
//! Whether a lap may continue after a conflicted replay is a policy question, and
//! it is answered by `rebase-conflict-stops-the-lap` in the `landing-loop` preset
//! over the record this module writes. That is CLOUD-1148's thesis read forwards:
//! the mechanics move to the engine and the decisions become Rego. So nothing
//! here branches on "should we stop" — it performs the replay, writes down what
//! the replay did, and reports. A consumer that wants a different rule about
//! conflicts writes a different module and this code does not change.
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
/// A DETACHED HEAD HAS NOTHING TO KEY ON, exactly as the claim receipt does not,
/// so the write is skipped rather than failing the replay. The replay itself
/// happened either way, and turning "nowhere to write this down" into "the lap
/// failed" would report a verdict about the clone as a verdict about the branch.
/// # Errors
///
/// A store directory or file that will not open or append.
pub fn record(root: &Path, branch: &str, outcome: &Replay) -> Result<()> {
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
    writeln!(file, "{}", outcome.line())
        .with_context(|| format!("land: append to the lap record {}", path.display()))?;
    Ok(())
}

/// The record this module writes, and the one `record::VERB_WRITTEN` names so a
/// module can read it back.
pub const LAP_RECORD: &str = "lap";

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
}
