//! The disk arm of `land`'s gate race (CLOUD-1937).
//!
//! # Why the lap watches the disk rather than measuring it once
//!
//! A lap is admitted against a floor once, at its open, and then runs a gate for
//! twenty-five minutes on a volume nothing else is watching. `prune`'s own report
//! names what follows a crossing — a rustc IO error inside a test run, which reads
//! as a suite regression — and the session this row was filed from filled its
//! volume mid-work hard enough to tear the host's own transcript. Admission cannot
//! see that: the phase in between consumes what admission certified. So the lap
//! samples free space for as long as its gate runs, and reclaims through the
//! committed `[prune]` rules before the floor is crossed rather than after the
//! build has died of it.
//!
//! # IN THE LAP'S OWN PROCESS, ON ITS EXISTING CLOCK
//!
//! No daemon, no second thread and no second timer. `land::verify_raced` already
//! runs the gate beside a watcher arm that serves the crate's one sanctioned pause
//! ([`crate::pr_watch::pause_until`], stop-flag bounded); the disk check rides that
//! arm's loop. Converting the race to an async `select!` would mean an async
//! `exec`, and which runtime is CLOUD-1945's decision rather than this row's.
//!
//! # The quantity is free space, and it is PROJECTED
//!
//! A linker writes gigabytes between two samples, so a check that reacts only at
//! the floor reacts after the write that crossed it. [`Pressure`] keeps the last
//! sample and extrapolates the burn over [`HORIZON`], which covers one tick plus
//! the reclaim itself.
//!
//! # Pure, so the projection is decidable without a disk
//!
//! [`Pressure::observe`] takes the instant and the reading as arguments. The loop
//! supplies the clock and the volume; a test supplies a series.

//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT projection-unread|s@^        let projected = free_mb.saturating_sub(burn);$@        let projected = free_mb;@|a_falling_series_reclaims_before_the_floor_is_crossed
//MUTANT reclaim-unlink-unmeasured|s@^        lines.push(format!("disk-unlink-ms {}", self.wall_ms));$@@|an_exhausted_volume_never_starts_the_gate_and_records_the_reclaim
//MUTANT admission-floor-judged-mid-lap|s@^    floor.mb.saturating_sub(floor.worst_mb)$@    floor.mb@|a_lap_below_the_admission_floor_but_within_its_budget_runs

/// The free space below which a RUNNING lap is off its measured model, in MB.
///
/// **NOT THE ADMISSION FLOOR, and the difference was measured.** The warm floor
/// certifies, once, at a lap's open, that the worst lap on record fits with the
/// multiplier's margin. A healthy lap then SPENDS that headroom — that is what
/// it was certified for — so judging mid-gate readings against the admission
/// floor stops laps for being ordinary. #1036's first lap consumed 6368MB, read
/// 15375MB free against a 15384MB floor, and this arm stopped a gate that had
/// just printed `fast-forward-green`.
///
/// The lap is off-model only once it has eaten past its worst measured
/// consumption into the multiplier's margin: `mb − worst_mb`. That is where
/// reclaiming earns its cost, and where "nothing left to reclaim" means the
/// volume, not the tree, is about to decide the verdict.
#[must_use]
pub const fn reserve_mb(floor: &crate::prune::Floor) -> u64 {
    floor.mb.saturating_sub(floor.worst_mb)
}

/// How often the watcher samples, in seconds.
///
/// A property of the mechanism rather than of any repository (rule 1): one
/// `statvfs` per tick is free, and five seconds is short against a lap's
/// twenty-five minutes and long against the syscall.
pub const TICK: f64 = 5.0;

/// How far ahead the burn is projected, in milliseconds: one tick, plus the
/// reclaim's own wall time with room — a superseded pass over a warm tree was
/// measured in seconds, and a projection shorter than the reaction is a floor
/// crossed while reacting.
pub const HORIZON: u64 = 30_000;

/// What the projection says about the next [`HORIZON`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// Free space stays above the floor over the horizon.
    Clear,
    /// It will not: reclaim now, while there is still room to.
    Reclaim,
}

/// The last sample and the floor it is judged against.
#[derive(Debug, Clone)]
pub struct Pressure {
    floor_mb: u64,
    horizon_ms: u64,
    last: Option<(u64, u64)>,
}

impl Pressure {
    /// A watcher judging against `floor_mb`, projecting over `horizon_ms`.
    #[must_use]
    pub const fn new(floor_mb: u64, horizon_ms: u64) -> Self {
        Self {
            floor_mb,
            horizon_ms,
            last: None,
        }
    }

    /// Take one sample: `free_mb` read at `at_ms` on a monotonic clock.
    ///
    /// The burn is the fall since the previous sample over the time between
    /// them; a rise burns nothing, so a reclaim never projects as growth. The
    /// first sample has no burn and is judged as it stands.
    pub fn observe(&mut self, at_ms: u64, free_mb: u64) -> Reading {
        let burn = match self.last {
            Some((then, before)) if at_ms > then => {
                let fallen = u128::from(before.saturating_sub(free_mb));
                let elapsed = u128::from(at_ms - then);
                let projected = fallen * u128::from(self.horizon_ms) / elapsed;
                u64::try_from(projected).unwrap_or(u64::MAX)
            }
            _ => 0,
        };
        self.last = Some((at_ms, free_mb));
        let projected = free_mb.saturating_sub(burn);
        if projected < self.floor_mb {
            Reading::Reclaim
        } else {
            Reading::Clear
        }
    }
}

/// What one reclaim left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reclaimed {
    /// Free space after the reclaim, in megabytes.
    pub free_mb: u64,
    /// The running lap's reserve it was judged against ([`reserve_mb`]).
    pub floor_mb: u64,
    /// Megabytes the reclaim freed, superseded and escalated together.
    pub freed_mb: u64,
    /// Whether it dropped a regrowable root — a cache a running gate may be
    /// reading, which is what makes a later failure the environment's.
    pub escalated: bool,
    /// Wall time the reclaim spent, in milliseconds (CLOUD-1945's figure: what
    /// the unlinks cost on this runtime).
    pub wall_ms: u64,
}

impl Reclaimed {
    /// Whether the floor still is not cleared: nothing left that would help.
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.free_mb < self.floor_mb
    }

    /// The lap-record lines, pointer-only: numbers, never paths.
    ///
    /// The wall time is a line of its own because it answers a different
    /// question: the reclaim line says what the volume did, and this one is the
    /// cost CLOUD-1945 decides the runtime on — what unlinking took here.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "disk-reclaimed {} {} {} {}",
            self.freed_mb, self.free_mb, self.floor_mb, self.escalated
        )];
        lines.push(format!("disk-unlink-ms {}", self.wall_ms));
        lines
    }
}

/// Reclaim `tree` under the committed `[prune]` rules, and time it.
///
/// No lap journal (`store` is `None`): the lap that opened the journal closes it,
/// and a watcher writing it mid-gate would be the second actor CLOUD-1913
/// measured racing the builds. Every removal goes through `prune`'s own build-lock
/// claim, so a profile a build holds is skipped rather than pulled from under it.
///
/// Judged against `reserve_mb`, the running lap's reserve, never `prune`'s own
/// admission floor — see [`reserve_mb`] for why the two differ.
///
/// # Errors
///
/// `prune`'s could-not-look: an absent tree, or free space that cannot be read.
pub fn reclaim(
    tree: &std::path::Path,
    config: &crate::prune::Prune,
    reserve_mb: u64,
) -> anyhow::Result<Reclaimed> {
    let started = std::time::Instant::now();
    let outcome = crate::prune::prune(tree, config, false, None)?;
    let wall_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(Reclaimed {
        free_mb: outcome.free_mb,
        floor_mb: reserve_mb,
        freed_mb: outcome.reclaimed_mb + outcome.escalated_mb.unwrap_or(0),
        escalated: outcome.escalated_mb.is_some(),
        wall_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_steady_volume_above_the_floor_is_clear() {
        let mut pressure = Pressure::new(1000, HORIZON);
        assert_eq!(pressure.observe(0, 5000), Reading::Clear);
        assert_eq!(pressure.observe(5000, 5000), Reading::Clear);
    }

    #[test]
    fn a_reading_below_the_floor_reclaims_with_no_history() {
        let mut pressure = Pressure::new(1000, HORIZON);
        assert_eq!(pressure.observe(0, 900), Reading::Reclaim);
    }

    #[test]
    fn a_rise_projects_no_growth() {
        let mut pressure = Pressure::new(1000, HORIZON);
        assert_eq!(pressure.observe(0, 1100), Reading::Clear);
        assert_eq!(pressure.observe(5000, 4000), Reading::Clear);
    }
}
