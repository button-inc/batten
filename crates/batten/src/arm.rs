//! The declared-arm harness: run N declared things, reduce each to a named
//! observable, and hand back one record per arm (CLOUD-1714).
//!
//! # Why this exists
//!
//! The engine shipped **two** instances of "run N declared things, reduce to an
//! observable, record, adjudicate" and neither was generic, so two more lived in
//! bash. [`crate::perf`] spawns a benchmarking tool and reduces wall-clock to
//! percentiles; [`crate::mutate`] stages a repository copy, runs a declared
//! command and reduces a test stream to pass/fail counts. The bash pair reduce a
//! multi-path sweep to percentiles and a merged output stream to a byte count.
//! Four copies of a percentile function existed between them.
//!
//! This is the primitive all four are instances of: a table of
//! `(id, cwd, argv, stdin, env)` arms, a run count, and a pluggable
//! [`Observable`]. **It generalises the two shipped instances rather than adding
//! a third** — [`percentile`] is the one this module owns, and both consumers
//! call it here.
//!
//! # The percentile reduction is owned HERE
//!
//! Decided on CLOUD-1714 and recorded so CLOUD-1712 can consume it: the
//! `forge::window` cluster needs percentiles over durations it FETCHED rather
//! than ran, which is the same reduction over a different series. A fifth copy
//! there would be the drift this module exists to end, so [`percentile`] takes a
//! bare series and knows nothing about where it came from.
//!
//! # A FAILED ARM IS COULD-NOT-LOOK, NEVER A ZERO
//!
//! [`Outcome`] is the whole reason this is not a `Vec<f64>`. A zero measurement
//! and an absent one are different verdicts, and conflating them is how a broken
//! arm reads as **fast**: an arm that failed to start, or whose output could not
//! be parsed, contributes nothing to a comparison rather than contributing the
//! best number in it. This is [`crate::findings::Observation`]'s distinction
//! applied to measurement.
//!
//! # BYTE-STABILITY IS AN OBSERVABLE, NOT AN ASSERTION
//!
//! The bash token benchmark asserts that arms produce identical bytes across
//! runs *before* it counts them, and a harness that only reported the last run
//! could not see instability at all. So [`Observable::Stability`] is a
//! first-class reduction: an arm whose runs disagree is reported
//! [`Reading::Unstable`], never averaged into a number that describes none of
//! them.
//!
//! # Isolation is BEHAVIOUR, not setup
//!
//! Arms run with a state root of their own because a contributor's ambient state
//! must not move a measurement — and because an arm that WRITES would otherwise
//! leave the store in a condition depending on which arm ran first, making the
//! result a fact about ordering. [`Isolation`] carries that explicitly rather
//! than leaving it to each caller to remember (CLOUD-1559: a port carries the
//! decisions, not the steps).
//!
//! # Output is a pointer
//!
//! [`Reading::line`] renders `arm=<id> observable=<name> …` and never a byte of
//! a captured stream (non-negotiable rule 4). The streams these arms produce are
//! exactly the payload that must not reach a log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One declared thing to run.
///
/// `id` is the arm's name in every record and refusal it produces; the rest is
/// what it takes to run it once. Declared as data so a caller states its table
/// and this module owns the loop.
#[derive(Debug, Clone)]
pub struct Arm {
    /// The name this arm carries in every record and refusal.
    pub id: String,
    /// Where the arm runs.
    pub cwd: PathBuf,
    /// The program and its arguments. The first element is the program.
    pub argv: Vec<String>,
    /// What to write to the arm's standard input, if anything.
    pub stdin: Option<String>,
    /// Environment entries set for this arm, over and above [`Isolation`].
    pub env: BTreeMap<String, String>,
}

impl Arm {
    /// A new arm with no stdin and no extra environment.
    #[must_use]
    pub fn new(id: impl Into<String>, cwd: impl Into<PathBuf>, argv: Vec<String>) -> Self {
        Self {
            id: id.into(),
            cwd: cwd.into(),
            argv,
            stdin: None,
            env: BTreeMap::new(),
        }
    }
}

/// The state root an arm runs under, so ambient state cannot move a measurement.
///
/// Not a convenience: the perf pair's post-tool arm WRITES, and two arms sharing
/// a store would each read rows the other created. That is an order dependency,
/// and it does not divide out of a ratio — which is the only thing the comparison
/// reads.
#[derive(Debug, Clone)]
pub struct Isolation {
    root: PathBuf,
}

impl Isolation {
    /// A state root at `root`.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The environment entries that point every state-writing path at this root.
    ///
    /// All four names are set together and always: a caller that set only the
    /// one its own platform reads would leave the others ambient, which is the
    /// leak this type exists to close.
    #[must_use]
    pub fn env(&self) -> BTreeMap<String, String> {
        let root = self.root.to_string_lossy().into_owned();
        let mut env = BTreeMap::new();
        for name in ["HOME", "XDG_DATA_HOME", "APPDATA", "LOCALAPPDATA"] {
            env.insert(String::from(name), root.clone());
        }
        env
    }

    /// The root itself, for a caller that must create or empty it.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// What an arm's runs are reduced to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observable {
    /// A percentile of the wall-clock series, in the caller's own units.
    WallClock,
    /// The byte count of the arm's merged output stream.
    Bytes,
    /// Whether every run produced identical bytes.
    Stability,
    /// The arm's exit status.
    ExitStatus,
}

impl Observable {
    /// The stable name this observable carries in a record line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Observable::WallClock => "wall-clock",
            Observable::Bytes => "bytes",
            Observable::Stability => "stability",
            Observable::ExitStatus => "exit",
        }
    }
}

/// What an arm's runs reduced to, or why they did not.
#[derive(Debug, Clone, PartialEq)]
pub enum Reading {
    /// A percentile pair over the wall-clock series, with the sample count.
    WallClock {
        /// The median.
        p50: f64,
        /// The 95th percentile.
        p95: f64,
        /// How many runs the series holds.
        runs: usize,
    },
    /// A byte count every run agreed on.
    Bytes(usize),
    /// Every run produced identical bytes.
    Stable,
    /// The runs disagreed, and this is reported rather than averaged away.
    Unstable {
        /// How many distinct outputs the runs produced.
        distinct: usize,
        /// How many runs there were.
        runs: usize,
    },
    /// The arm's exit status.
    ExitStatus(i32),
}

/// One arm's result: observed, or not.
///
/// The two arms are the point. A zero measurement and an absent one are
/// different verdicts, and a harness that returned `0.0` for an arm that failed
/// to start would report the broken arm as the fastest one.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The arm ran and reduced.
    Observed(Reading),
    /// The arm could not be measured, and this is why.
    NotObserved(String),
}

impl Outcome {
    /// Whether this arm produced a reading at all.
    #[must_use]
    pub const fn observed(&self) -> bool {
        matches!(self, Outcome::Observed(_))
    }

    /// The pointer line this outcome renders as.
    ///
    /// Pointer-only per non-negotiable rule 4: an arm's id, the observable's
    /// name and the reduction. Never a byte of the stream that produced it —
    /// which for these arms is exactly the payload that must not reach a log.
    #[must_use]
    pub fn line(&self, id: &str, observable: Observable) -> String {
        let value = match self {
            Outcome::Observed(Reading::WallClock { p50, p95, runs }) => {
                format!("p50={p50} p95={p95} runs={runs}")
            }
            Outcome::Observed(Reading::Bytes(count)) => format!("count={count}"),
            Outcome::Observed(Reading::Stable) => String::from("stable"),
            Outcome::Observed(Reading::Unstable { distinct, runs }) => {
                format!("UNSTABLE distinct={distinct} runs={runs}")
            }
            Outcome::Observed(Reading::ExitStatus(code)) => format!("code={code}"),
            // The reason is the caller's own text, not captured content: every
            // construction site below writes it, and none of them reads a stream.
            Outcome::NotObserved(why) => format!("not-observed {why}"),
        };
        format!("arm={id} observable={} {value}", observable.name())
    }
}

/// A percentile over a series, by the nearest-rank convention this repository
/// already used.
///
/// **The one copy.** Four existed across the two shipped instances and the two
/// bash programs; CLOUD-1714 decides this module owns it, and CLOUD-1712's
/// fetched-duration series consume it here rather than growing a fifth.
///
/// The series is taken by value and sorted, because a percentile over an
/// unsorted series is the bug this signature makes unrepresentable. `quantile`
/// is clamped to `[0, 1]`, and an empty series has no percentile — which is a
/// [`Outcome::NotObserved`] at the call site, never a zero.
#[must_use]
pub fn percentile(mut series: Vec<f64>, quantile: f64) -> Option<f64> {
    if series.is_empty() {
        return None;
    }
    series.sort_by(f64::total_cmp);
    let n = series.len();
    #[expect(
        clippy::cast_precision_loss,
        reason = "a run count is a small integer and this is an index computation, not a measurement"
    )]
    let last = (n - 1) as f64;
    let position = last * quantile.clamp(0.0, 1.0);
    // CEIL rather than round: the 95th percentile of a short series must not
    // round DOWN into the body of the distribution, which is how a tail that a
    // budget exists to bound stops being represented at all.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the product is within [0, n-1] by construction, so the cast cannot truncate meaningfully or go negative"
    )]
    let index = position.ceil() as usize;
    series.get(index.min(n - 1)).copied()
}

/// Reduce a wall-clock series to a reading, or say why it could not be.
#[must_use]
pub fn wall_clock(series: Vec<f64>) -> Outcome {
    let runs = series.len();
    let (Some(p50), Some(p95)) = (percentile(series.clone(), 0.5), percentile(series, 0.95)) else {
        return Outcome::NotObserved(String::from("the arm produced no timing series"));
    };
    Outcome::Observed(Reading::WallClock { p50, p95, runs })
}

/// Reduce a set of per-run outputs to a byte count, refusing to count an
/// unstable arm.
///
/// The order is the decision: stability is checked BEFORE the count, because a
/// count over runs that disagree describes none of them. The bash program this
/// generalises asserted the same thing and in the same order.
#[must_use]
pub fn bytes(runs: &[Vec<u8>]) -> Outcome {
    match stability(runs) {
        Outcome::Observed(Reading::Stable) => runs.first().map_or_else(
            || Outcome::NotObserved(String::from("the arm produced no runs")),
            |first| Outcome::Observed(Reading::Bytes(first.len())),
        ),
        other => other,
    }
}

/// Whether every run produced identical bytes.
#[must_use]
pub fn stability(runs: &[Vec<u8>]) -> Outcome {
    let Some(first) = runs.first() else {
        return Outcome::NotObserved(String::from("the arm produced no runs"));
    };
    let distinct = runs.iter().collect::<std::collections::BTreeSet<_>>().len();
    if runs.iter().all(|run| run == first) {
        Outcome::Observed(Reading::Stable)
    } else {
        Outcome::Observed(Reading::Unstable {
            distinct,
            runs: runs.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_percentile_over_a_known_series_matches_a_hand_computation() {
        // Ten values, so the indices are checkable by eye: p50 takes index
        // ceil(9 * 0.5) = 5, and p95 takes ceil(9 * 0.95) = 9.
        let series: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(percentile(series.clone(), 0.5), Some(6.0));
        assert_eq!(percentile(series.clone(), 0.95), Some(10.0));
        // And it does not depend on the order it was handed.
        let mut shuffled = series;
        shuffled.reverse();
        assert_eq!(percentile(shuffled, 0.95), Some(10.0));
    }

    #[test]
    fn a_percentile_of_an_empty_series_is_absent_rather_than_zero() {
        // The whole `Outcome` distinction, at its source: an empty series has no
        // percentile, and returning `0.0` would make an arm that produced
        // nothing the fastest one in the comparison.
        assert_eq!(percentile(Vec::new(), 0.5), None);
        assert!(matches!(wall_clock(Vec::new()), Outcome::NotObserved(_)));
    }

    #[test]
    fn an_unstable_arm_is_reported_unstable_rather_than_averaged_away() {
        // THE CASE A NAIVE HARNESS GETS WRONG. Reporting the last run, or the
        // mean of the counts, would describe none of the runs — and would hide
        // exactly the instability the observable exists to surface.
        let runs = vec![b"aaa".to_vec(), b"aaaa".to_vec(), b"aaa".to_vec()];
        let outcome = stability(&runs);
        assert_eq!(
            outcome,
            Outcome::Observed(Reading::Unstable {
                distinct: 2,
                runs: 3
            })
        );
        // And the byte count refuses to be taken over it, in that order.
        assert_eq!(bytes(&runs), outcome);
    }

    #[test]
    fn a_stable_arm_counts_its_bytes() {
        let runs = vec![b"hello".to_vec(), b"hello".to_vec()];
        assert_eq!(stability(&runs), Outcome::Observed(Reading::Stable));
        assert_eq!(bytes(&runs), Outcome::Observed(Reading::Bytes(5)));
    }

    #[test]
    fn an_arm_with_no_runs_is_could_not_look() {
        assert!(matches!(stability(&[]), Outcome::NotObserved(_)));
        assert!(matches!(bytes(&[]), Outcome::NotObserved(_)));
    }

    #[test]
    fn a_record_line_is_a_pointer_and_never_a_stream() {
        // Rule 4, at the one place a reading becomes text. The arms these
        // observables run produce exactly the payload that must not reach a log.
        let secret = b"a-distinctive-token".to_vec();
        let line = bytes(&[secret.clone(), secret]).line("baseline", Observable::Bytes);
        assert_eq!(line, "arm=baseline observable=bytes count=19");
        assert!(!line.contains("distinctive"));
    }

    #[test]
    fn isolation_sets_every_state_root_together() {
        // A caller that set only the name its own platform reads would leave the
        // others ambient, which is the leak this type closes.
        let env = Isolation::at("/tmp/state").env();
        for name in ["HOME", "XDG_DATA_HOME", "APPDATA", "LOCALAPPDATA"] {
            assert_eq!(env.get(name).map(String::as_str), Some("/tmp/state"));
        }
    }
}
