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
///
/// `Eq` AS WELL AS `PartialEq`, WHICH THE FLOAT USED TO FORBID. `WallClock`
/// carried `f64` percentiles until the reduction stopped converting: a duration
/// is a count, `percentile` selects an element rather than averaging, and
/// nothing here ever did float arithmetic. Recovering total equality is the
/// second thing that conversion was costing, after the lint escape it needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// A percentile pair over the wall-clock series, with the sample count.
    WallClock {
        /// The median.
        p50: u128,
        /// The 95th percentile.
        p95: u128,
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

/// One completed run of one arm — what a caller's runner hands back.
///
/// Three fields because the four observables need exactly three facts between
/// them, and a runner that returned only the one its caller happened to reduce
/// would make the table's `Observable` a lie: every arm is run the same way, and
/// which fact is READ is the table's decision rather than the runner's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The arm's own wall clock for this run, in the caller's units.
    ///
    /// `u128` nanoseconds rather than `f64` seconds: a duration is a count, the
    /// conversion to a float belongs at the reduction where the unit is chosen,
    /// and a runner that rounded first would hand this module a series it could
    /// not have reproduced.
    pub nanos: u128,
    /// Everything the arm wrote, the streams already merged by the runner.
    pub output: Vec<u8>,
    /// The status the arm exited with.
    pub exit: i32,
}

/// Run every arm `runs` times and reduce each to `observable`.
///
/// # The spawn is INJECTED, and that is a placement rather than a convenience
///
/// `policy/spawn-adapters.rego` decides which modules may hold a child-process
/// boundary, by name resolution over the compiled crate. `perf` is on that table
/// and this module is not — and it should not be, because the two own different
/// subjects. A declared-arm harness owns *the loop, the reduction, and the rule
/// that a failed arm is could-not-look*; **what it costs to start a process is
/// somebody else's fact.** Taking `once` as a parameter is what lets both stay
/// true: the placed adapter supplies the spawn, this module never names
/// `Command`, and the table above needs no new row to admit a module that spawns
/// nothing.
///
/// It also makes the harness testable without a process at all, which is how the
/// cases below drive an arm that fails on its third run.
///
/// # A FAILING ARM DOES NOT ABORT THE TABLE
///
/// `once` returning `Err` retires THAT arm to [`Outcome::NotObserved`] carrying
/// the runner's own reason, and the loop moves to the next one. The alternative —
/// a `Result` over the whole table — would throw away every arm that worked
/// because one did not, which is the shape that makes a comparison unavailable
/// exactly when it is most wanted. A partial table with one honest
/// `not-observed` row is more use than no table.
///
/// Arms are reduced in the order declared, and each arm's runs are consecutive,
/// so a caller reading the records back gets the table it wrote.
pub fn run(
    arms: &[Arm],
    runs: usize,
    observable: Observable,
    mut once: impl FnMut(&Arm) -> Result<Run, String>,
) -> Vec<(String, Outcome)> {
    arms.iter()
        .map(|arm| (arm.id.clone(), run_one(arm, runs, observable, &mut once)))
        .collect()
}

/// One arm's `runs` runs, reduced — the body of [`run`]'s loop.
fn run_one(
    arm: &Arm,
    runs: usize,
    observable: Observable,
    once: &mut impl FnMut(&Arm) -> Result<Run, String>,
) -> Outcome {
    // ZERO RUNS IS COULD-NOT-LOOK, not an empty series. Every reduction below
    // would otherwise answer from nothing: `wall_clock` already says so, but
    // `stability` over no runs would have to invent an answer, and "no runs were
    // asked for" is a different fault from "the arm produced none".
    if runs == 0 {
        return Outcome::NotObserved(String::from("no runs were asked for"));
    }
    let mut series = Vec::with_capacity(runs);
    let mut outputs = Vec::with_capacity(runs);
    let mut exits = Vec::with_capacity(runs);
    for _ in 0..runs {
        match once(arm) {
            Ok(run) => {
                series.push(run.nanos);
                outputs.push(run.output);
                exits.push(run.exit);
            }
            Err(why) => return Outcome::NotObserved(why),
        }
    }
    match observable {
        Observable::WallClock => wall_clock(series),
        Observable::Bytes => bytes(&outputs),
        Observable::Stability => stability(&outputs),
        Observable::ExitStatus => exit_status(&exits),
    }
}

/// The status every run agreed on, or a refusal to name one.
///
/// **Disagreement is could-not-look rather than a pick.** An arm that exits `0`
/// twice and `1` once has no exit status, and reporting either of them would be
/// reporting a run rather than the arm. This is [`stability`]'s rule over the
/// status instead of over the bytes, and it exists for the same reason: the
/// reduction that hides a disagreement is the one that makes a flaky arm look
/// decided.
fn exit_status(exits: &[i32]) -> Outcome {
    let Some(first) = exits.first() else {
        return Outcome::NotObserved(String::from("the arm produced no runs"));
    };
    let distinct = exits
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if distinct == 1 {
        Outcome::Observed(Reading::ExitStatus(*first))
    } else {
        Outcome::NotObserved(format!(
            "the arm's exit status varied across {} run(s): {distinct} distinct",
            exits.len()
        ))
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
/// unsorted series is the bug this signature makes unrepresentable. An empty
/// series has no percentile — which is an [`Outcome::NotObserved`] at the call
/// site, never a zero.
///
/// # The quantile is a RATIO OF INTEGERS, not a float, and that is the whole
/// reason the rank arithmetic carries no lint escape
///
/// The obvious signature takes `f64` and pays for it three times: `(n - 1) as
/// f64` is a precision loss, and `position.ceil() as usize` is a possible
/// truncation and a sign loss. Each is provably harmless here and each still
/// needs an `#[expect]` to say so — three escapes in engine source, which
/// `spawn-widening` counts as inventory growth whether or not the reasoning
/// behind them is sound.
///
/// A rank is an index, and an index is an integer. `numerator / denominator`
/// says the same thing the float said and computes the ceiling exactly, so
/// nothing is rounded, nothing is cast, and there is no lint to waive. A zero
/// denominator is [`None`] rather than a panic, for the reason an empty series
/// is: this is a reduction, and a reduction that cannot answer says so.
///
/// # The ELEMENT type is the caller's too, and for the same reason
///
/// A nearest-rank percentile SELECTS an element; it never averages, so it needs
/// an order over the series and nothing else. This used to fix the element as
/// `f64`, which made `arm` convert `Run::nanos` — a `u128` count, as its own doc
/// insists — and buy a `cast_precision_loss` escape to do it. The float was the
/// type the sort wanted, never the type the answer needed.
///
/// Taking `compare` moves the order to the caller and lets each series keep the
/// type it measured: `u128` nanoseconds here, and `f64` seconds in
/// [`crate::perf`], whose times come from an external tool and whose mean is a
/// real float division. `f64::total_cmp` is the total order floats do have, so
/// the float caller is served without this function knowing about floats — and
/// `Reading` recovered `Eq`, which the `f64` field had forbidden.
#[must_use]
pub fn percentile<T>(
    mut series: Vec<T>,
    numerator: usize,
    denominator: usize,
    compare: impl FnMut(&T, &T) -> core::cmp::Ordering,
) -> Option<T> {
    if series.is_empty() || denominator == 0 {
        return None;
    }
    series.sort_by(compare);
    let last = series.len() - 1;
    // CLAMPED RATHER THAN REFUSED, because the clamp is what a percentile above
    // the top of the series means: the last element. The float form clamped the
    // quantile to `[0, 1]` and this clamps the rank to `[0, last]`, which is the
    // same bound expressed where it can be checked.
    let scaled = last.saturating_mul(numerator.min(denominator));
    // CEIL rather than round: the 95th percentile of a short series must not
    // round DOWN into the body of the distribution, which is how a tail that a
    // budget exists to bound stops being represented at all. Integer ceiling
    // division, so the rounding is exact rather than a float's best effort.
    //
    // **THE SAME RANK SERVES p50, and that is a stated convention rather than a
    // side effect** (review of #928). On an EVEN series the ceiling rank selects
    // the upper of the two middle elements, so `[1.0, 2.0]` has a p50 of 2.0
    // where a floor rank would answer 1.0. Nearest-rank defines no
    // interpolation, both are legitimate, and ONE convention across every
    // percentile this crate reports is worth more than a split that has to be
    // remembered per call site.
    //
    // It moves a published number, which is why it is written down: `perf
    // measure` prints `p50=` in its record line. Nothing GATES on it —
    // `policy/perf-assert.rego` reads `perf-p95` and only that — so the change
    // reaches a reader's eye and no ratchet. A p50 that ever does gate owes its
    // own basis at that point, not this comment.
    let index = scaled.div_ceil(denominator);
    series.into_iter().nth(index.min(last))
}

/// Reduce a wall-clock series to a reading, or say why it could not be.
#[must_use]
pub fn wall_clock(series: Vec<u128>) -> Outcome {
    let runs = series.len();
    let (Some(p50), Some(p95)) = (
        percentile(series.clone(), 50, 100, u128::cmp),
        percentile(series, 95, 100, u128::cmp),
    ) else {
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

    /// An arm, ready to hand to [`run`].
    fn arm(id: &str) -> Arm {
        Arm::new(id, ".", vec![String::from("true")])
    }

    /// A run with a chosen duration and output, which is every fact [`run`] reads.
    fn run_of(nanos: u128, output: &str, exit: i32) -> Run {
        Run {
            nanos,
            output: output.as_bytes().to_vec(),
            exit,
        }
    }

    #[test]
    fn every_arm_is_run_the_asked_number_of_times_and_reduced_in_order() {
        let arms = [arm("first"), arm("second")];
        let mut seen: Vec<String> = Vec::new();
        let out = run(&arms, 3, Observable::WallClock, |arm| {
            seen.push(arm.id.clone());
            Ok(run_of(1_000, "same", 0))
        });

        // CONSECUTIVE, and asserted as the whole sequence rather than as a
        // count: a harness that interleaved arms would pass a count check and
        // still make each arm's series a measurement of both.
        assert_eq!(
            seen,
            ["first", "first", "first", "second", "second", "second"]
        );
        assert_eq!(
            out.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(out.iter().all(|(_, outcome)| outcome.observed()));
    }

    #[test]
    fn a_failing_arm_is_not_observed_and_the_others_still_reduce() {
        // THE CASE THE MODULE EXISTS FOR. The failing arm must not become a
        // zero, and it must not take the working arm down with it.
        let arms = [arm("broken"), arm("fine")];
        let out = run(&arms, 2, Observable::WallClock, |arm| {
            if arm.id == "broken" {
                Err(String::from("could not start"))
            } else {
                Ok(run_of(2_000, "out", 0))
            }
        });

        assert_eq!(
            out[0].1,
            Outcome::NotObserved(String::from("could not start"))
        );
        assert!(out[1].1.observed(), "a sibling's failure is not this arm's");
        // And the reason travels, so a reader learns what happened rather than
        // that something did.
        assert!(
            out[0]
                .1
                .line("broken", Observable::WallClock)
                .contains("could not start")
        );
    }

    #[test]
    fn a_failure_on_a_later_run_retires_the_whole_arm_rather_than_reducing_a_short_series() {
        // A series of one, from an arm that was asked for three, describes an
        // arm that did not finish. Reducing it would report the one run that
        // worked as though it were the measurement.
        let arms = [arm("flaky")];
        let mut calls = 0;
        let out = run(&arms, 3, Observable::WallClock, |_| {
            calls += 1;
            if calls < 3 {
                Ok(run_of(10, "x", 0))
            } else {
                Err(String::from("died on the third run"))
            }
        });

        assert_eq!(calls, 3, "the arm is not abandoned before the failing run");
        assert_eq!(
            out[0].1,
            Outcome::NotObserved(String::from("died on the third run"))
        );
    }

    #[test]
    fn zero_runs_is_could_not_look_rather_than_an_empty_reduction() {
        let arms = [arm("unrun")];
        let mut called = false;
        let out = run(&arms, 0, Observable::Stability, |_| {
            called = true;
            Ok(run_of(1, "", 0))
        });

        assert!(!called, "an arm asked for no runs is not run");
        assert_eq!(
            out[0].1,
            Outcome::NotObserved(String::from("no runs were asked for"))
        );
    }

    #[test]
    fn an_arm_whose_runs_disagree_is_unstable_rather_than_counted() {
        let arms = [arm("noisy")];
        let mut calls = 0;
        let out = run(&arms, 2, Observable::Bytes, |_| {
            calls += 1;
            Ok(run_of(1, if calls == 1 { "short" } else { "longer" }, 0))
        });

        // BYTES, not stability, and still UNSTABLE: `bytes` checks agreement
        // first, because a count over runs that disagree describes none of them.
        assert_eq!(
            out[0].1,
            Outcome::Observed(Reading::Unstable {
                distinct: 2,
                runs: 2
            })
        );
    }

    #[test]
    fn an_exit_status_is_read_only_when_every_run_agreed() {
        let arms = [arm("steady"), arm("varying")];
        let mut calls = 0;
        let out = run(&arms, 2, Observable::ExitStatus, |arm| {
            calls += 1;
            let exit = if arm.id == "steady" { 3 } else { calls % 2 };
            Ok(run_of(1, "", exit))
        });

        assert_eq!(out[0].1, Outcome::Observed(Reading::ExitStatus(3)));
        assert!(
            !out[1].1.observed(),
            "a status that varied names no run: {:?}",
            out[1].1
        );
    }

    #[test]
    fn a_percentile_over_a_known_series_matches_a_hand_computation() {
        // Ten values, so the indices are checkable by eye: p50 takes index
        // ceil(9 * 0.5) = 5, and p95 takes ceil(9 * 0.95) = 9.
        let series: Vec<u128> = (1..=10).collect();
        assert_eq!(percentile(series.clone(), 50, 100, u128::cmp), Some(6));
        assert_eq!(percentile(series.clone(), 95, 100, u128::cmp), Some(10));
        // And it does not depend on the order it was handed.
        let mut shuffled = series;
        shuffled.reverse();
        assert_eq!(percentile(shuffled, 95, 100, u128::cmp), Some(10));
    }

    /// **THE EVEN SERIES, which is where the convention is visible** (review of
    /// #928).
    ///
    /// Nearest-rank defines no interpolation, so a two-element series has to
    /// pick one of the middle pair. The ceiling rank picks the UPPER, and the
    /// review is right that this moves a published p50 — `[1.0, 2.0]` answers
    /// 2.0 where a floor rank answers 1.0.
    ///
    /// It is pinned rather than left implicit because the number reaches a
    /// reader: `perf measure` prints `p50=` in its record line. Nothing gates on
    /// it — `perf-assert` reads `perf-p95` alone — so the cost is a figure that
    /// shifted once, against one convention serving every percentile this crate
    /// reports instead of a split remembered per call site.
    #[test]
    fn an_even_series_takes_the_upper_of_the_middle_pair() {
        assert_eq!(
            percentile(vec![1.0_f64, 2.0], 50, 100, f64::total_cmp),
            Some(2.0)
        );
        // And the same rank over an integer series, so the convention is the
        // function's rather than the float caller's.
        assert_eq!(percentile(vec![10_u128, 20], 50, 100, u128::cmp), Some(20));
    }

    #[test]
    fn the_order_is_the_callers_so_a_float_series_is_served_too() {
        // `perf` measures seconds as `f64` from an external tool, and this is
        // the property that lets one selection serve both without this module
        // knowing about floats. `total_cmp` is the total order floats have.
        let series = vec![3.5_f64, 1.25, 2.0];
        assert_eq!(percentile(series, 50, 100, f64::total_cmp), Some(2.0));
    }

    #[test]
    fn a_percentile_of_an_empty_series_is_absent_rather_than_zero() {
        // The whole `Outcome` distinction, at its source: an empty series has no
        // percentile, and returning `0.0` would make an arm that produced
        // nothing the fastest one in the comparison.
        assert_eq!(percentile(Vec::<u128>::new(), 50, 100, u128::cmp), None);
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
