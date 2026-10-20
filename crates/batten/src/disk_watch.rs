//! The disk watcher a long-running batten process hosts (CLOUD-1937, CLOUD-2197).
//!
//! # Reaction, not prediction
//!
//! Below `[prune] min_free_mb` the watcher collects — unreachable, then
//! least-recently-used cargo units ([`crate::collect`]) — until `max_free_mb` is
//! free. Nothing is projected and nothing is learned: bursts between two samples
//! are absorbed by the headroom `min_free_mb` declares, as Nix's `min-free` and
//! kubelet's image GC band absorb them. The arm this replaces projected a burn
//! over a horizon against a floor it learned, and reacted by deleting
//! `incremental` first — the most valuable cache of an edit loop.
//!
//! # It spans the whole run
//!
//! `land` starts it once, around every lap: replay, verify, push and the CI wait.
//! The arm it replaces lived only while a gate ran, so replay, push and the
//! lap-close prune were unwatched. `mutate sweep` hosts the same watcher around
//! its builds. It ends on its stop flag, never when one step returns.
//!
//! # Sampling never pauses
//!
//! The watcher thread only samples, every [`TICK`]. A collection runs on its own
//! short-lived scoped thread, so a pass over a large tree never stops the clock;
//! one collection runs at a time, and a sample that finds one running does
//! nothing. Its first act is to re-arm `relatime` ([`crate::collect::rearm`]),
//! which is what "at lap open" means.
//!
//! # One sanctioned pause
//!
//! The tick is [`crate::pr_watch::pause_until`], the crate's one delay, bounded
//! by the stop flag, so this arm grows no timer of its own.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// How often the watcher samples, in seconds.
///
/// A property of the mechanism rather than of any repository (rule 1): one
/// `statvfs` per tick is free, and five seconds is short against a lap's
/// twenty-five minutes and long against the syscall.
pub const TICK: f64 = 5.0;

/// How long the hook may collect before admitting (CLOUD-2197): a sixth of the
/// harness's 60 s default command-hook timeout, so a killed hook is never the
/// bound. Checked at unit boundaries; the next pressed call resumes.
pub const HOOK_COLLECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A free-space reader both the watcher and its collection thread take turns on.
type Reader<'a> = Arc<Mutex<Box<dyn FnMut() -> anyhow::Result<u64> + Send + 'a>>>;

/// What a watcher needs: the repository whose trees it collects, the committed
/// `[prune]` rules, how free space is read, and what is never collected.
///
/// The reading is INJECTED — the volume in production ([`crate::prune::sampler`]),
/// a series in a test — so the trigger and the stop are decidable without
/// filling a disk.
pub struct DiskWatch<'a> {
    /// The repository: its `[prune] root` and each linked worktree's are the trees.
    pub repo: PathBuf,
    /// The committed `[prune]` rules; nothing outside them is touched.
    pub config: &'a crate::prune::Prune,
    /// Free space on the trees' volume, in MiB.
    pub free_mb: Box<dyn FnMut() -> anyhow::Result<u64> + Send + 'a>,
    /// Files no collection removes ([`crate::collect::kept`]).
    pub kept: Vec<crate::collect::Kept>,
}

impl std::fmt::Debug for DiskWatch<'_> {
    /// The reader is a closure, so it is named rather than printed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiskWatch")
            .field("repo", &self.repo)
            .field("config", &self.config)
            .field("free_mb", &"<reader>")
            .finish_non_exhaustive()
    }
}

/// Start the watcher in `scope`; it runs until `stop` is set, then returns the
/// record lines its collections produced (`disk-collected …`, `disk-unlink-ms …`).
///
/// A repository with no declared band returns at once with no lines: the arm is
/// off, as it is for a consumer with no `[prune]`.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT arm-ends-with-the-gate|s@^        while !stop.load(Ordering::Relaxed) {$@        for _ in 0..1 {@|the_arm_watches_past_the_gate
pub fn watch<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    watch: DiskWatch<'scope>,
    stop: &'scope AtomicBool,
) -> std::thread::ScopedJoinHandle<'scope, Vec<String>> {
    scope.spawn(move || {
        let DiskWatch {
            repo,
            config,
            free_mb,
            kept,
        } = watch;
        let Some((min, _)) = config.free_band() else {
            return Vec::new();
        };
        // THE LAP OPENS RE-ARMED: every fingerprint's atime is set to its mtime,
        // so the next read by cargo records a fresh one and the LRU order is
        // this run's use rather than the first read of the day.
        for tree in crate::collect::trees(&repo, config) {
            crate::collect::rearm(&tree);
        }
        let reader: Reader<'scope> = Arc::new(Mutex::new(free_mb));
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let collecting = Arc::new(AtomicBool::new(false));
        let trace = crate::collect::tracing();
        let started = std::time::Instant::now();
        let mut pending: Option<std::thread::ScopedJoinHandle<'scope, ()>> = None;
        while !stop.load(Ordering::Relaxed) {
            let reading = reader.lock().ok().and_then(|mut read| read().ok());
            if let Some(free) = reading {
                if trace {
                    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let _ = std::io::Write::write_all(
                        &mut std::io::stderr(),
                        format!(
                            "{}\n",
                            crate::collect::trace_line("disk-sample", &[ms, free])
                        )
                        .as_bytes(),
                    );
                }
                // ONE COLLECTION AT A TIME: a sample that finds one running
                // does nothing, and the next sample judges what it left.
                if free < min && !collecting.swap(true, Ordering::AcqRel) {
                    if let Some(done) = pending.take() {
                        let _ = done.join();
                    }
                    let (repo, kept) = (repo.clone(), kept.clone());
                    let (reader, lines, collecting) = (
                        Arc::clone(&reader),
                        Arc::clone(&lines),
                        Arc::clone(&collecting),
                    );
                    pending = Some(scope.spawn(move || {
                        let mut read = || {
                            reader
                                .lock()
                                .map_err(|_| anyhow::anyhow!("the free-space reader was poisoned"))
                                .and_then(|mut read| read())
                        };
                        if let Some(done) = crate::collect::collect_toward_max(
                            &repo, config, &kept, free, &mut read, None, false,
                        ) && let Ok(mut lines) = lines.lock()
                        {
                            lines.extend(done.lines());
                        }
                        collecting.store(false, Ordering::Release);
                    }));
                }
            }
            crate::pr_watch::pause_until(TICK, stop);
        }
        if let Some(done) = pending.take() {
            let _ = done.join();
        }
        lines.lock().map(|lines| lines.clone()).unwrap_or_default()
    })
}

/// Run `body` with a watcher over `repo` alive for its whole duration, and
/// return what it returned together with the watcher's record lines.
///
/// `None` for `watch` runs `body` unwatched: no band, or no readable volume.
pub fn around<T>(watch: Option<DiskWatch<'_>>, body: impl FnOnce() -> T) -> (T, Vec<String>) {
    let Some(watch) = watch else {
        return (body(), Vec::new());
    };
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let handle = self::watch(scope, watch, &stop);
        // THE FLAG IS SET HOWEVER THE BODY LEAVES, RETURNING OR UNWINDING.
        let answer = {
            let _stop = Stop(&stop);
            body()
        };
        let lines = handle.join().unwrap_or_default();
        (answer, lines)
    })
}

/// Sets the stop flag when it drops, so the watcher ends on a panic too.
///
/// **A BARE `stop.store` AFTER `body()` IS SKIPPED BY A PANIC (CLOUD-2376),**
/// and [`std::thread::scope`]'s join at unwind then waits on a thread looping
/// `while !stop` — which no longer has any way to become true. The process hangs
/// instead of propagating the panic, and nothing says why.
///
/// Measured on `prune_watch::the_arm_watches_past_the_gate` with the collection
/// mutated away: its own `wait_for` reached its bound and panicked on schedule,
/// and the case then ran past 100s without ever reporting the failure it had
/// already found. `cargo-mutants` killed it and reported `suite-timed-out` —
/// could-not-look (CLOUD-1267) — over a mutant 27 cases in that file do catch.
/// So the bound was never the defect; the un-stoppable watcher was.
///
/// In production the same shape swallows any panic raised inside a watched step.
struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails by: a watcher printing nothing of what it watches, or printing its
    /// reader rather than naming it.
    #[test]
    fn a_watcher_debugs_its_repository_and_names_its_reader() {
        let config: crate::prune::Prune = match serde_json::from_str("{}") {
            Ok(config) => config,
            Err(why) => panic!("an empty table: {why}"),
        };
        let watch = DiskWatch {
            repo: PathBuf::from("/repo"),
            config: &config,
            free_mb: Box::new(|| Ok(0)),
            kept: Vec::new(),
        };
        let printed = format!("{watch:?}");
        assert!(printed.starts_with("DiskWatch {"), "{printed}");
        assert!(printed.contains("\"/repo\""), "{printed}");
        assert!(printed.contains("\"<reader>\""), "{printed}");
    }

    /// [`Stop`] sets the flag when it drops, which is what makes a panicking
    /// body end the watcher instead of hanging the join (CLOUD-2376).
    ///
    /// **ASSERTED ON THE GUARD, NOT THROUGH [`around`], AND THAT IS THE POINT.**
    /// A case that panics inside a watched body is the honest end-to-end shape,
    /// and it is unrunnable as a gate: without the guard it does not fail, it
    /// HANGS, so a runner reports could-not-look over the one mutation that
    /// matters. Measured — `drop` replaced with `()` timed the suite out at 42s
    /// rather than failing. The contract is one flag and one drop, so it is
    /// asserted where it can fail fast.
    ///
    /// The end-to-end half is covered by what the fix changed:
    /// `prune_watch::the_arm_watches_past_the_gate` under a mutated collection
    /// went from past 100s and killed, to 21.1s and failed.
    ///
    /// Fails by: a `drop` that does not store, or stores `false`.
    #[test]
    fn the_watcher_is_stopped_however_the_body_leaves() {
        let stop = AtomicBool::new(false);
        drop(Stop(&stop));
        assert!(
            stop.load(Ordering::Relaxed),
            "the guard's drop is what ends the watcher on an unwind"
        );
    }
}
