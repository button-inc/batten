//! Test scratch space outside the tree, owned in one place and reaped by
//! liveness.
//!
//! # The defect this closes, measured rather than argued
//!
//! 269 leaked `batten-*` directories in `/tmp` after two suite runs, and the
//! count only ever grows. The cause is one line repeated across ~76 call sites:
//!
//! ```text
//! std::env::temp_dir().join(format!("batten-branch-receipt-{pid}-{name}"))
//! ```
//!
//! **The pid is in the NAME.** `cargo nextest` runs every case in its own
//! process, so each case in each run mints a directory whose name no successor
//! will ever compute again — and the `remove_dir_all` those sites open with is
//! therefore a wipe of a path that was already empty. Nothing removes it.
//!
//! The sites that leave the pid OUT do not leak, which is what makes this the
//! cause rather than a correlate: `batten-startup-{name}` and
//! `batten-doctor-tests/{name}` are a fixed working set of 12 and 2, because a
//! stable path means the next run's `remove_dir_all` collects the last run's.
//!
//! # Why the pid stays, and moves one level up
//!
//! Two concurrent runs covering one binary DO collide on a stable path, which is
//! what the pid was defending against. So it is kept and made a path SEGMENT
//! rather than part of a leaf name:
//!
//! ```text
//! /tmp/batten-scratch/<pid>/<name>
//! ```
//!
//! That is the whole fix. A segment is something a reaper can decide about — it
//! parses as a pid or it does not — where a pid spliced into `batten-<x>-<pid>-<y>`
//! can only be recovered by guessing at 76 different name shapes, which is the
//! second-authority class `[[pattern]]` exists to make unwritable.
//!
//! It also matches the discipline this repository already chose one directory
//! over. `tests/it/common`'s `in_lane` adds the pid only under
//! `BATTEN_TEST_SCRATCH_LANE`, because CLOUD-1252 measured that a per-run path on
//! every scratch moved the journal's fingerprint ordering and silently switched
//! off an emission budget. Nothing here reaches the journal — these are fixtures
//! outside the tree — so the pid may ride every path, and the reaper is what pays
//! for it.
//!
//! # Crash-only, because that is the only state this container is ever in
//!
//! A run here is killed constantly: a lap stops, a container is reclaimed, an
//! operator interrupts. Cleanup on the happy path is therefore not a mechanism,
//! and a `Drop` would be tidiness rather than the answer. This reaps on
//! **acquire** — a caller asking for scratch first sweeps every sibling whose pid
//! is gone. Recovery is the only path, which is the reasoning
//! [`crate::task::singleton_acquire`] already uses to reclaim a lock from a dead
//! holder.
//!
//! **Liveness, never age.** An mtime bound would reap a long-running suite's own
//! corpora out from under it, which is the direction that breaks a passing run.
//! A pid that does not exist cannot be using anything.

use std::path::{Path, PathBuf};

/// The one directory every out-of-tree scratch lives under.
///
/// A single parent rather than 39 prefixes loose in `/tmp`, so the reaper has one
/// place to look and an operator has one path to delete.
const SCRATCH_ROOT: &str = "batten-scratch";

/// This process's scratch root, with dead processes' subtrees reaped first.
///
/// Test-support rather than product surface, and `#[doc(hidden)]` says so. It is
/// `pub` because the leaking call sites live in three scopes that cannot share a
/// `#[cfg(test)]` helper: this crate's own unit tests, the `it` integration
/// binary, and the standalone `tests/*.rs` binaries.
#[doc(hidden)]
#[must_use]
pub fn root() -> PathBuf {
    let root = std::env::temp_dir().join(SCRATCH_ROOT);
    reap_the_dead(&root);
    root.join(std::process::id().to_string())
}

/// An EMPTY scratch directory named `name`, under this process's root.
///
/// The wipe is kept because callers relied on it: every site this replaces opened
/// with `remove_dir_all`, and a case that finds a previous case's bytes is a
/// different test from the one that was written.
#[doc(hidden)]
#[must_use]
pub fn scratch(name: &str) -> PathBuf {
    let dir = root().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Remove every subtree whose owning process is gone.
///
/// Best effort in every direction, and each arm is the could-not-look side on
/// purpose: an unreadable root reaps nothing rather than guessing, a name that is
/// not a pid is left alone rather than parsed loosely, and a directory that will
/// not remove is left for the next caller. This deletes what it can prove is
/// dead and nothing else.
fn reap_the_dead(root: &Path) {
    let Ok(listing) = std::fs::read_dir(root) else {
        return;
    };
    for entry in listing.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if !pid_is_live(pid) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Is a process with this pid running?
///
/// `kill(pid, 0)`: **EPERM means it exists** and this uid may not signal it,
/// which is LIFE — reading it as death is what would delete a live sibling's
/// corpora mid-run. Only ESRCH is death. The same asymmetry
/// [`crate::task`]'s own probe argues for, and for the same reason.
#[cfg(unix)]
fn pid_is_live(pid: i32) -> bool {
    let Some(target) = rustix::process::Pid::from_raw(pid) else {
        return true;
    };
    !matches!(
        rustix::process::test_kill_process(target),
        Err(rustix::io::Errno::SRCH)
    )
}

/// Off unix there is no `kill -0` in this closure at all — `rustix` is declared
/// under `[target.'cfg(unix)'.dependencies]` — so nothing is reaped. That is the
/// could-not-look direction, which never deletes a live run's scratch.
#[cfg(not(unix))]
fn pid_is_live(_pid: i32) -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The whole point, asserted over the mechanism rather than over a name: a
    /// subtree owned by a pid that cannot exist is collected, and this process's
    /// own is not.
    ///
    /// **A CORPSE IS UNREACHABLE OFF UNIX, AND BOTH ARMS ARE ASSERTED**
    /// (CLOUD-1148). `pid_is_live` is two functions, not one: `rustix` is
    /// declared under `[target.'cfg(unix)'.dependencies]`, so off unix there is
    /// no `kill -0` in this closure at all and the module abstains by
    /// construction — which is the safe direction, since a platform that cannot
    /// tell life from death must not delete a live run's corpora. This case
    /// asserted collection unconditionally and so demanded, on Windows,
    /// behaviour the module deliberately does not have; the `windows` job found
    /// it while every other leg was green.
    ///
    /// `cfg!` RATHER THAN AN ATTRIBUTE, for the reason
    /// `crates/batten/tests/it/task_registry.rs` records beside the same
    /// asymmetry: it keeps BOTH arms compiled on every target, so `cross-check`
    /// type-checks the off-unix branch instead of skipping over it unparsed.
    /// A `#[cfg(unix)]` over the whole case — which this fix first used — leaves
    /// the Windows contract unstated and one arm never compiled locally, which is
    /// how the class stayed invisible.
    ///
    /// The second assertion is the one both arms share: whatever the platform
    /// decides about corpses, this process's own scratch survives its own reap,
    /// so neither arm can pass by reaping everything.
    ///
    /// Fails by: dropping the `pid_is_live` guard in [`reap_the_dead`], which
    /// takes the live directory with it.
    #[test]
    fn a_dead_processes_scratch_is_collected_and_a_live_ones_is_not() {
        let mine = scratch("still-here");
        std::fs::write(mine.join("corpus"), "bytes").expect("seed the live subtree");

        // A pid nothing can own. `i32::MAX` is above every `pid_max` this runs
        // on, so the probe answers ESRCH rather than depending on a pid that
        // happens to be free right now.
        let parent = std::env::temp_dir().join(SCRATCH_ROOT);
        let dead = parent.join(i32::MAX.to_string());
        std::fs::create_dir_all(dead.join("left-behind")).expect("seed the dead subtree");

        let _ = root();

        if cfg!(unix) {
            assert!(
                !dead.exists(),
                "a subtree whose pid is gone must be collected"
            );
        } else {
            assert!(
                dead.exists(),
                "with no liveness probe the reaper must abstain, never guess"
            );
        }
        assert!(
            mine.join("corpus").exists(),
            "this process's own scratch must survive its own reap"
        );
        let _ = std::fs::remove_dir_all(&dead);
    }

    /// A name that is not a pid is not a corpse. Deleting one would make this
    /// reaper a `rm -rf` over whatever else ends up under the root.
    ///
    /// Fails by: replacing the `parse::<i32>()` guard with an unconditional
    /// remove.
    #[test]
    fn a_subtree_that_is_not_a_pid_is_left_alone() {
        let root = std::env::temp_dir().join(SCRATCH_ROOT);
        let stray = root.join("not-a-pid");
        std::fs::create_dir_all(&stray).expect("seed a stray");

        reap_the_dead(&root);

        assert!(stray.exists(), "a name that is not a pid is not decidable");
        let _ = std::fs::remove_dir_all(&stray);
    }

    /// COULD NOT LOOK IS NOT AN EMPTY ANSWER. An unreadable root reaps nothing
    /// and says nothing, rather than reporting a clean sweep it never performed.
    ///
    /// Fails by: `expect`ing the `read_dir`, which panics instead of abstaining.
    #[test]
    fn an_unreadable_root_reaps_nothing() {
        reap_the_dead(&std::env::temp_dir().join("batten-scratch-absent-entirely"));
    }
}
