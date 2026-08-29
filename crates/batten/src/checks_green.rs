//! Is this SHA green over the required check set? (CLOUD-1143)
//!
//! The one definition of that question, ported off `mise-tasks/checks-green.sh`.
//! It decides over a **reading** the caller already holds — never over the
//! network — so the fetch stays with `ci-wait`, which polls conditionally and
//! hands over the body it got. That is the agents-fetch-gates-decide split the
//! board gates already use, and it is what lets every case here run offline.
//!
//! # The four states, and why the exit table is not the shell's
//!
//! The predecessor used `0` green / `1` red / `2` could-not-look / `3` not-yet.
//! Three of those numbers mean something else under [`crate::exit::ExitCode`],
//! which is total with no per-verb exception, so the mapping had to change:
//!
//! | state | code |
//! | --- | --- |
//! | [`Verdict::Green`] | `Success` |
//! | [`Verdict::Red`] and [`Verdict::Pending`] | `Violation` — this head is not landable |
//! | a roster that will not resolve | `Usage` |
//! | a reading that could not be taken | `Internal` |
//!
//! **Red and pending collapse onto one code deliberately.** They differ only in
//! whether the caller should ask again, never in whether the head may land, and
//! that distinction travels on stdout. Collapsing them makes the fail-safe
//! direction structural: a reader that branches on the code alone and ignores
//! stdout treats "not yet" as "do not land". Any mapping that gave pending a `0`
//! would let that same reader fast-forward a head nothing had judged, which is
//! CLOUD-337's defect re-introduced by the port meant to preserve it.
//!
//! # The three rules this conserves, none of them re-decided here
//!
//! * **Latest run per name** (CLOUD-436). A SHA accumulates a check-run per
//!   event, so a PR created as a draft carries its `opened`-event skip set
//!   forever. Judged as a union that residue vetoes a verdict that already
//!   exists — measured three times in one evening, twice as an unbounded poll
//!   over a green head and once as a poll blind to a completed failure.
//!   `started_at` orders them (ISO-8601 sorts lexicographically) with the run id
//!   breaking a same-second tie.
//! * **Absent is not skipped, and absent is not an answer** (CLOUD-337). A
//!   path-filtered workflow produces no check-run at all, so absence is
//!   legitimate for exactly the names the caller declares tolerated; every other
//!   roster name must be present. An unset tolerated set is the STRICT
//!   direction, because the two failures are not symmetric — a name this waits
//!   for that never arrives is a visible stall, while a name it forgives that
//!   had merely not registered yet is a landing nobody judged.
//! * **The fan-in split** (CLOUD-900, over CLOUD-363). "No answer" outranks red,
//!   because a cancelled sibling can MANUFACTURE a fan-in failure — `final`
//!   declares `needs:` over the others. That is true of the fan-in and of
//!   nothing else, so a non-fan-in failure is a verdict on the tree whatever
//!   else has not answered. With no fan-in named every failure is treated as
//!   manufacturable, which is CLOUD-363's ordering intact and the safe default.

use std::collections::BTreeMap;

/// What a reading says about one SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every required check terminal and green.
    Green,
    /// A required check failed, and no cancellation could have manufactured it.
    Red(Vec<Finding>),
    /// Not an answer yet: still running, no verdict, or never registered.
    Pending(Pending),
}

/// Why a reading is not yet an answer. Carried rather than collapsed, because
/// "no verdict" has several spellings and a stall you cannot spell is a stall
/// you cannot diagnose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    /// Required checks that are registered but not `completed`.
    Running { pending: usize, graded: usize },
    /// Required checks whose latest run carries a conclusion that is not an
    /// answer — a draft-era `skipped`, a `cancelled`, or one GitHub adds
    /// tomorrow that nobody has seen.
    NoVerdict(Vec<Finding>),
    /// Required names with no run at all, which is a fresh SHA.
    Unregistered(Vec<String>),
}

/// A pointer, never a payload: the check's name and the conclusion it carries.
/// Non-negotiable rule 4 — this type cannot hold a run's log because it has
/// nowhere to put one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: String,
    pub conclusion: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.check, self.conclusion)
    }
}

/// One row of a reading, as the check-runs endpoint projects it.
#[derive(Debug, Clone)]
pub struct Run {
    pub status: String,
    pub conclusion: String,
    pub name: String,
    /// The ordering key's first field. Empty where the caller's reading predates
    /// CLOUD-436 and carries none.
    pub started_at: String,
    /// The ordering key's tie-break. Zero where the reading carries none.
    pub id: u64,
}

/// The roster and its two qualifiers, all of them the consumer's.
///
/// None of these is a literal in this crate: a tracker's or a forge's vocabulary
/// under `crates/batten` is non-negotiable rule 1's violation, so the caller
/// declares them and this decides over what it is handed.
#[derive(Debug, Clone)]
pub struct Roster {
    /// Every check that carries a verdict about this repository.
    pub required: Vec<String>,
    /// The names for which having no run at all is a legitimate reading.
    pub absent_ok: Vec<String>,
    /// The conclusions that constitute an answer.
    pub answered: Vec<String>,
    /// The one check whose failure a cancelled sibling can manufacture.
    pub fanin: Option<String>,
}

/// A roster that cannot decide anything, kept distinct from a reading that says
/// nothing: the first is a malformed invocation and the second is a real state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterError {
    /// An empty required set makes every check unrequired, which is the false
    /// green this whole module exists to stop.
    NoRequiredChecks,
    /// An empty answered set makes every conclusion an answer, which is the same
    /// false green in a new spelling.
    NoAnsweredConclusions,
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRequiredChecks => {
                f.write_str("the required check set is empty, so every check would be unrequired")
            }
            Self::NoAnsweredConclusions => f.write_str(
                "the answered-conclusion set is empty, so every conclusion would be an answer",
            ),
        }
    }
}

/// How conclusive a row is, for choosing between two runs of one name that share
/// an ordering key.
///
/// The precedence is what makes an UNORDERABLE pair fail closed: a reading
/// carrying no `started_at` or id leaves every key equal, and then the LEAST
/// conclusive row wins — which is the union answer this replaces, so an
/// unorderable pair can never read greener than it did before ordering existed.
/// `cancelled` ranks with `skipped` rather than with a failure (CLOUD-363): a
/// cancelled run judged nothing, so an unorderable pair holding one falls to "no
/// answer" rather than to red.
fn rank(run: &Run, answered: &[String]) -> u8 {
    if run.status != "completed" {
        return 4;
    }
    if !answered.iter().any(|c| c == &run.conclusion) {
        return 3;
    }
    if run.conclusion == "success" || run.conclusion == "neutral" {
        1
    } else {
        2
    }
}

/// The ordering key for one run. ISO-8601 sorts lexicographically, so a string
/// compare is chronological; the zero-padded id breaks a tie inside one second.
fn key(run: &Run) -> (String, u64) {
    (run.started_at.clone(), run.id)
}

/// Decide a reading. Pure: no clock, no network, no filesystem.
///
/// # Errors
///
/// Returns [`RosterError`] when the roster cannot decide anything. That is a
/// statement about the invocation, not about the repository, which is why it is
/// an error here and [`crate::exit::ExitCode::Usage`] at the boundary.
pub fn decide(runs: &[Run], roster: &Roster) -> Result<Verdict, RosterError> {
    if roster.required.is_empty() {
        return Err(RosterError::NoRequiredChecks);
    }
    if roster.answered.is_empty() {
        return Err(RosterError::NoAnsweredConclusions);
    }

    // Latest run per name (CLOUD-436), over the required subset only. An
    // unrelated check gets neither a vote nor a veto — the same scoping that
    // stops a third party vetoing a landing.
    let mut best: BTreeMap<&str, &Run> = BTreeMap::new();
    for run in runs {
        if !roster.required.iter().any(|name| name == &run.name) {
            continue;
        }
        match best.get(run.name.as_str()) {
            None => {
                best.insert(&run.name, run);
            }
            Some(held) => {
                let (hk, hr) = (key(held), rank(held, &roster.answered));
                let (nk, nr) = (key(run), rank(run, &roster.answered));
                if nk > hk || (nk == hk && nr > hr) {
                    best.insert(&run.name, run);
                }
            }
        }
    }

    // Iterated in ROSTER order rather than the map's, because this output is a
    // contract (house style §6) and a set's iteration order is not one.
    let mut graded = 0usize;
    let mut pending = 0usize;
    let mut no_verdict: Vec<Finding> = Vec::new();
    let mut failed: Vec<Finding> = Vec::new();
    let mut real_failed: Vec<Finding> = Vec::new();
    let mut unregistered: Vec<String> = Vec::new();

    for name in &roster.required {
        let Some(run) = best.get(name.as_str()) else {
            // Tolerated only for the names the caller declared absent-ok; every
            // other absence is a name that has not registered yet, which is a
            // fresh SHA and not an answer (CLOUD-337).
            if !roster.absent_ok.iter().any(|ok| ok == name) {
                unregistered.push(name.clone());
            }
            continue;
        };
        if run.status != "completed" {
            pending += 1;
            continue;
        }
        // MEMBERSHIP, NOT A LITERAL PAIR (CLOUD-376). Naming `skipped` and
        // `cancelled` and letting everything else fall through to red would
        // report a conclusion GitHub adds tomorrow as a verdict against a head it
        // never judged.
        if !roster.answered.iter().any(|c| c == &run.conclusion) {
            no_verdict.push(Finding {
                check: name.clone(),
                conclusion: run.conclusion.clone(),
            });
            continue;
        }
        graded += 1;
        if run.conclusion != "success" && run.conclusion != "neutral" {
            let finding = Finding {
                check: name.clone(),
                conclusion: run.conclusion.clone(),
            };
            // THE SPLIT (CLOUD-900). Only the fan-in is excluded, and only
            // because its `needs:` assertion turns a cancelled sibling into its
            // own red. `fanin.is_some()` is what makes the unset direction the
            // safe one: with none named, every failure stays manufacturable,
            // which is CLOUD-363's ordering intact.
            if roster.fanin.as_deref().is_some_and(|f| f != name) {
                real_failed.push(finding.clone());
            }
            failed.push(finding);
        }
    }

    // A failure no cancellation could have manufactured is a verdict, and it is
    // tested FIRST (CLOUD-900). After an `abandon-matrix` run a head carries one
    // real failure beside several deliberately cancelled siblings; under the
    // ordering alone that reads as "not an answer yet", so the saving would buy a
    // wedge.
    if !real_failed.is_empty() {
        return Ok(Verdict::Red(real_failed));
    }

    // "No answer" is tested BEFORE "red", and the order is load-bearing
    // (CLOUD-363): `final` fans in over the others, so its failure over five
    // cancelled siblings was a CONSEQUENCE of the cancellations rather than an
    // independent verdict. Promoting red here would put the branch back in that
    // wedge. A genuine failure leaves this bucket empty and falls through.
    if !no_verdict.is_empty() {
        return Ok(Verdict::Pending(Pending::NoVerdict(no_verdict)));
    }
    if graded == 0 || pending > 0 {
        return Ok(Verdict::Pending(Pending::Running { pending, graded }));
    }

    // A required name with no run at all is not an answer either — and unlike
    // the bucket above it YIELDS to a failure rather than outranking one. An
    // absent name manufactures nothing, so a completed failure beside it is an
    // independent verdict and must still be reported; holding the poll open
    // would leave a PR ready over a tree already known to be red.
    if !unregistered.is_empty() && failed.is_empty() {
        return Ok(Verdict::Pending(Pending::Unregistered(unregistered)));
    }

    if !failed.is_empty() {
        return Ok(Verdict::Red(failed));
    }
    Ok(Verdict::Green)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roster() -> Roster {
        Roster {
            required: ["ci", "perf", "final"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            absent_ok: vec!["zizmor".to_string()],
            answered: [
                "success",
                "neutral",
                "failure",
                "timed_out",
                "action_required",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            fanin: Some("final".to_string()),
        }
    }

    fn run(status: &str, conclusion: &str, name: &str, started_at: &str, id: u64) -> Run {
        Run {
            status: status.to_string(),
            conclusion: conclusion.to_string(),
            name: name.to_string(),
            started_at: started_at.to_string(),
            id,
        }
    }

    fn green_set() -> Vec<Run> {
        ["ci", "perf", "final"]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                run(
                    "completed",
                    "success",
                    n,
                    "2026-08-12T00:00:00Z",
                    i as u64 + 1,
                )
            })
            .collect()
    }

    #[test]
    fn a_graded_all_success_required_set_is_green() {
        assert_eq!(decide(&green_set(), &roster()), Ok(Verdict::Green));
    }

    #[test]
    fn a_partial_set_on_a_fresh_sha_is_not_an_answer() {
        // THE DISCRIMINATING ROW (CLOUD-337): one graded check is the ORDINARY
        // state of a freshly pushed SHA, and reading the roster from it answered
        // green over a set of one.
        let reading = vec![run("completed", "success", "ci", "", 0)];
        let Ok(Verdict::Pending(Pending::Unregistered(missing))) = decide(&reading, &roster())
        else {
            panic!("a partial set must be unregistered-pending");
        };
        assert_eq!(missing, vec!["perf".to_string(), "final".to_string()]);
    }

    #[test]
    fn a_tolerated_name_with_no_run_is_elided() {
        // `zizmor` is absent-ok, so its absence is legitimate and must not join
        // the unregistered list — requiring it would hang the poll.
        assert_eq!(decide(&green_set(), &roster()), Ok(Verdict::Green));
    }

    #[test]
    fn a_failure_outranks_a_name_that_has_not_registered() {
        // An absent name manufactures nothing, so a completed failure beside it
        // is an independent verdict and must still be red.
        let reading = vec![run("completed", "failure", "ci", "", 0)];
        let Ok(Verdict::Red(findings)) = decide(&reading, &roster()) else {
            panic!("a real failure outranks an absent name");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].to_string(), "ci failure");
    }

    #[test]
    fn an_all_skipped_required_set_is_not_an_answer() {
        let reading = vec![run("completed", "skipped", "ci", "", 0)];
        let Ok(Verdict::Pending(Pending::NoVerdict(findings))) = decide(&reading, &roster()) else {
            panic!("a skipped set is not an answer");
        };
        assert_eq!(findings[0].to_string(), "ci skipped");
    }

    #[test]
    fn a_cancelled_required_check_is_not_an_answer_either() {
        // CLOUD-363: a cancelled run is the ABSENCE of a verdict, not a bad one.
        let reading = vec![run("completed", "cancelled", "ci", "", 0)];
        let Ok(Verdict::Pending(Pending::NoVerdict(findings))) = decide(&reading, &roster()) else {
            panic!("a cancelled check is not an answer");
        };
        assert_eq!(findings[0].to_string(), "ci cancelled");
    }

    #[test]
    fn a_fanin_failure_over_cancelled_siblings_is_no_verdict() {
        // CLOUD-363's measured set on #293: `final failure` plus cancelled
        // siblings. `final` fans in over them, so its failure was manufactured.
        let reading = vec![
            run("completed", "cancelled", "ci", "", 0),
            run("completed", "cancelled", "perf", "", 0),
            run("completed", "failure", "final", "", 0),
        ];
        let Ok(Verdict::Pending(Pending::NoVerdict(_))) = decide(&reading, &roster()) else {
            panic!("a manufactured fan-in failure is not a verdict");
        };
    }

    #[test]
    fn a_non_fanin_failure_over_cancelled_siblings_is_the_verdict() {
        // CLOUD-900: `ci` failing judges the tree directly, and no cancellation
        // can produce it. This is the case `abandon-matrix` deliberately creates.
        let reading = vec![
            run("completed", "failure", "ci", "", 0),
            run("completed", "cancelled", "perf", "", 0),
            run("completed", "cancelled", "final", "", 0),
        ];
        let Ok(Verdict::Red(findings)) = decide(&reading, &roster()) else {
            panic!("a non-fan-in failure is the verdict");
        };
        assert_eq!(findings[0].to_string(), "ci failure");
    }

    #[test]
    fn with_no_fanin_named_every_failure_stays_manufacturable() {
        // The unset direction is CLOUD-363's ordering intact, and it is the safe
        // one: forgetting the name costs a poll that holds too long, where the
        // opposite default would report a manufactured failure as a verdict.
        let mut r = roster();
        r.fanin = None;
        let reading = vec![
            run("completed", "failure", "ci", "", 0),
            run("completed", "cancelled", "perf", "", 0),
            run("completed", "cancelled", "final", "", 0),
        ];
        let Ok(Verdict::Pending(Pending::NoVerdict(_))) = decide(&reading, &r) else {
            panic!("with no fan-in named, no failure is promoted");
        };
    }

    #[test]
    fn a_later_run_supersedes_a_drafts_skip_residue() {
        // CLOUD-436, measured on #345: the skip at 03:18:10Z against the success
        // at 03:20:16Z. Judged as a union the residue vetoes a verdict that
        // already exists.
        let mut reading = green_set();
        for name in ["ci", "perf", "final"] {
            reading.push(run("completed", "skipped", name, "2026-08-11T00:00:00Z", 1));
        }
        assert_eq!(decide(&reading, &roster()), Ok(Verdict::Green));
    }

    #[test]
    fn an_unorderable_pair_falls_to_the_least_conclusive() {
        // The precedence that makes a reading with no ordering key fail CLOSED:
        // it answers exactly as the union did, so it can never read greener.
        let reading = vec![
            run("completed", "success", "ci", "", 0),
            run("completed", "skipped", "ci", "", 0),
        ];
        let Ok(Verdict::Pending(Pending::NoVerdict(findings))) = decide(&reading, &roster()) else {
            panic!("an unorderable pair falls to the least conclusive row");
        };
        assert_eq!(findings[0].to_string(), "ci skipped");
    }

    #[test]
    fn a_still_running_check_holds_the_poll_open() {
        let mut reading = green_set();
        reading.push(run("in_progress", "-", "ci", "2026-08-13T00:00:00Z", 99));
        let Ok(Verdict::Pending(Pending::Running { pending, .. })) = decide(&reading, &roster())
        else {
            panic!("a running check holds the poll open");
        };
        assert_eq!(pending, 1);
    }

    #[test]
    fn an_unknown_conclusion_holds_the_poll_open() {
        // CLOUD-376: not in the answered set means "no answer", so a conclusion
        // GitHub adds tomorrow is never reported as a verdict.
        let reading = vec![run("completed", "invented_tomorrow", "ci", "", 0)];
        let Ok(Verdict::Pending(Pending::NoVerdict(findings))) = decide(&reading, &roster()) else {
            panic!("an unknown conclusion is not an answer");
        };
        assert_eq!(findings[0].to_string(), "ci invented_tomorrow");
    }

    #[test]
    fn an_unrelated_check_gets_neither_a_vote_nor_a_veto() {
        let mut reading = green_set();
        reading.push(run("completed", "failure", "SomeAnalyzer", "", 0));
        assert_eq!(decide(&reading, &roster()), Ok(Verdict::Green));
    }

    #[test]
    fn an_empty_roster_is_a_usage_error_and_never_green() {
        let mut r = roster();
        r.required.clear();
        assert_eq!(decide(&green_set(), &r), Err(RosterError::NoRequiredChecks));
    }

    #[test]
    fn an_empty_answered_set_is_a_usage_error_and_never_green() {
        let mut r = roster();
        r.answered.clear();
        assert_eq!(
            decide(&green_set(), &r),
            Err(RosterError::NoAnsweredConclusions)
        );
    }

    #[test]
    fn an_empty_reading_is_not_an_answer() {
        // An explicitly empty reading is a real state — a SHA with no check-runs
        // yet — and must answer "not yet" rather than green.
        let Ok(Verdict::Pending(Pending::Unregistered(missing))) = decide(&[], &roster()) else {
            panic!("an empty reading is not an answer");
        };
        assert_eq!(missing.len(), 3);
    }

    #[test]
    fn an_unset_tolerated_set_is_the_strict_direction() {
        // CLOUD-337's asymmetry: forgetting the tolerated set makes this wait for
        // a name that may never come, which is loud; the opposite would forgive a
        // name that had merely not registered, which is a landing nobody judged.
        let mut r = roster();
        r.absent_ok.clear();
        let reading = vec![run("completed", "success", "ci", "", 0)];
        let Ok(Verdict::Pending(Pending::Unregistered(missing))) = decide(&reading, &r) else {
            panic!("an unset tolerated set requires every roster name");
        };
        assert!(missing.contains(&"perf".to_string()));
    }
}
