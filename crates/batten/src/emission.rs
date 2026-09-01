//! Emission policy: hysteresis and a re-emit cap on the notification channel,
//! and nothing on the state plane (CLOUD-165).
//!
//! A nondeterministic gate — a network-dependent check, a timing-sensitive test, a
//! scan over a generated file — drives the self-clear and recurrence-after-clear
//! loop into permanent raise/clear oscillation. Every phantom clear-then-raise
//! defeats repeat suppression, mints fresh dispositions into false-positive
//! accounting, and spends the drain's token budget on news that is not news.
//! Alerting settled this decades ago; Nagios computes a state-change rate and
//! Alertmanager separates the alert from its `repeat_interval`, and both halves
//! are adopted here rather than reinvented.
//!
//! # The plane split is load-bearing
//!
//! Hysteresis applied to finding **state** would contradict CLOUD-81's law: a
//! finding self-clears when its own check no longer holds, so an open finding
//! whose check exits `0` is a broken invariant, not a debounced one. This module
//! therefore governs one thing — whether the drain says something — and is
//! structurally unable to govern anything else: it takes the journal by reference,
//! returns values, and has no store handle to write through. Disposition and
//! occurrence state clear on exactly the schedule they did before it existed, and
//! clearing latency is asserted identical with the policy on and off.
//!
//! Flapping is an **annotation**, feeding per-rule health telemetry. It is never a
//! gate on clearing, and it is never a verdict: nothing here reaches an exit code.
//!
//! # Counted in evaluation boundaries, never a clock
//!
//! The window is the last N entries the journal carries **for one subject**, which
//! is why the ratio is a rate rather than a frequency. A wall-clock window would
//! make the same oscillation read as flapping on a busy machine and steady on an
//! idle one, and would make the policy unreproducible from the log — where
//! [`crate::drain`]'s coalescing interval genuinely is a clock, because pacing a
//! wake is a question about time.
//!
//! # Per (identity × context), which is what keeps two worktrees apart
//!
//! Two worktrees scanning at two refs interleave their entries in one merged log.
//! Read per identity alone, `raised at A, cleared at B, raised at A` is
//! indistinguishable from one identity oscillating — so the subject is the pair,
//! and each ref's own sequence stays monotone. This is [`crate::findings`]'s
//! comparison law ("every comparison is per (identity × context)") applied to the
//! journal, and it is the reason [`Entry::context`] exists.
//!
//! An entry that names no context is **not** folded into some default ref. It is
//! its own subject, because a writer that did not say is not a writer that said
//! `refs/heads/main` — the same "cannot classify, do not default" reading
//! [`crate::identity::StoredIdentity::kind`] forces on a kind it cannot name, and
//! it is how a secret-class record (whose kind answers `None`) travels through
//! here unclassified rather than guessed into a bucket.
//!
//! # A pure function of the journal, deliberately
//!
//! Flap state is derived from the store's own journal and this module keeps no
//! history of its own. Two consequences worth stating: identical journals yield
//! identical emissions, so the drain payload stays byte-stable; and a suppression
//! is recomputable after the fact from bytes the store already has, rather than
//! being a decision that lived only in the process that made it.
//!
//! [`Entry::context`]: crate::journal::Entry::context

use std::collections::BTreeMap;

use crate::findings::{NotShown, Observation};
use crate::journal::{Entry, Origin};

/// The coordinate a flap ratio is computed per: one identity at one context.
///
/// `context` is `Option` for the reason the module doc gives — an entry naming no
/// ref is its own subject rather than a member of some default one. Ordered so a
/// caller can hold these in a `BTreeMap` and get a byte-stable walk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subject {
    /// The finding identity, as hex.
    pub identity: String,
    /// The ref the evaluations belong to, or `None` for an entry that named none.
    pub context: Option<String>,
}

/// Whether an identity's signal is worth believing, and the counts behind the
/// answer.
///
/// The counts travel with the verdict because the annotation is telemetry: a
/// consumer reporting "flapping" with no ratio has published a label nobody can
/// check, and rule health is read as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Not flapping — either the ratio is under the threshold, or the window holds
    /// too few evaluations to have a ratio at all.
    ///
    /// **Too few is `Steady`, not `Flapping`**, and the direction is deliberate:
    /// the cost of believing a steady identity is one emission, and the cost of
    /// disbelieving a real one is a finding the agent never sees.
    Steady,
    /// Flapping: the state-change rate over the window is at or over the
    /// threshold.
    Flapping {
        /// State changes between consecutive evaluations in the window.
        transitions: usize,
        /// Evaluations in the window that actually looked.
        evaluations: usize,
    },
}

impl Health {
    /// Whether this is the flapping answer.
    #[must_use]
    pub const fn is_flapping(self) -> bool {
        matches!(self, Health::Flapping { .. })
    }
}

/// What the policy decided about one identity's emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emission {
    /// Emit it.
    Emit,
    /// Withhold it, under the reason the journal will record.
    Withhold(NotShown),
}

/// The journal folded into the two things a policy decision needs.
///
/// One fold rather than two passes at the call site: the emission count and the
/// evaluation history are read off the same ordered log, and a caller free to
/// window them differently could count emissions from outside the window whose
/// ratio it is testing.
#[derive(Debug, Default)]
pub struct Assessment {
    /// Per identity, the strongest health verdict any of its subjects reported.
    health: BTreeMap<String, Health>,
    /// Per identity, emissions inside the window its subjects define.
    emissions: BTreeMap<String, usize>,
}

impl Assessment {
    /// This identity's health, `Steady` for one the journal has never seen.
    #[must_use]
    pub fn health(&self, identity: &str) -> Health {
        self.health.get(identity).copied().unwrap_or(Health::Steady)
    }

    /// Every flapping identity and its counts, for the rule-health annotation.
    pub fn flapping(&self) -> impl Iterator<Item = (&String, Health)> {
        self.health
            .iter()
            .filter(|(_, health)| health.is_flapping())
            .map(|(identity, health)| (identity, *health))
    }

    /// Whether the drain may say this identity this boundary.
    ///
    /// **The cap only bites a flapping identity, and that conjunction IS the
    /// hysteresis.** A steady finding re-raised many times is a signal repeating
    /// itself for a reason the agent has not addressed, and capping it would hide
    /// working output; a flapping one has already told the agent everything its
    /// oscillation contains, and the N+1st repeat carries no information. Reading
    /// the cap alone would make this a rate limiter on the drain, which is a
    /// different feature with a different failure mode.
    #[must_use]
    pub fn decide(&self, identity: &str, cap: usize) -> Emission {
        let emitted = self.emissions.get(identity).copied().unwrap_or(0);
        if self.health(identity).is_flapping() && emitted >= cap {
            return Emission::Withhold(NotShown::FlapSuppressed);
        }
        Emission::Emit
    }
}

/// Fold the merged log into per-identity health and emission counts.
///
/// `window` is counted in **entries for one subject**, so a subject with fewer
/// than that many evaluations is judged on what it has. A `window` of `0` or `1`
/// yields no ratio anywhere — a single evaluation cannot contain a transition —
/// which is the honest bottom of the range rather than a disabled feature.
///
/// `percent` is the threshold as state-changes per hundred evaluations, an integer
/// so the comparison behind a suppression is exact. A float threshold would put a
/// rounding question inside a decision the journal is supposed to make
/// reproducible.
#[must_use]
pub fn assess(log: &[Entry], window: usize, percent: u32) -> Assessment {
    let mut evaluations: BTreeMap<Subject, Vec<(usize, Observation)>> = BTreeMap::new();
    // Emissions are per IDENTITY, not per subject: the drain emits one line per
    // identity and its entries carry no ref, so keying them by subject would
    // silently count every emission as belonging to a context that never claimed
    // it.
    let mut emitted: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for (at, entry) in log.iter().enumerate() {
        match entry.origin {
            Origin::Scan => {
                let Some(observation) = entry.observation else {
                    // A scan entry from a binary that predates the field says
                    // nothing about what was seen. Counting it as an evaluation
                    // would put an unknown in the denominator.
                    continue;
                };
                evaluations
                    .entry(Subject {
                        identity: entry.identity.clone(),
                        context: entry.context.clone(),
                    })
                    .or_default()
                    .push((at, observation));
            }
            Origin::Drain => {
                if entry.presentation.is_shown() {
                    emitted.entry(entry.identity.clone()).or_default().push(at);
                }
            }
            // A SETTLE IS NEITHER AN EVALUATION NOR AN EMISSION (CLOUD-587), so
            // it enters neither side of the ratio. Counting it as an evaluation
            // would put an agent's answer in the denominator of a flap rate that
            // measures what the ENGINE saw; counting it as an emission would say
            // the drain showed something it never did. The disposition it
            // carries is folded by `journal::merge`, which is where it belongs.
            Origin::Settle => {}
        }
    }

    let mut assessment = Assessment::default();
    for (subject, seen) in evaluations {
        let start = seen.len().saturating_sub(window);
        let recent = &seen[start..];
        let health = health_of(recent, percent);
        // The window's own start position in the log, which is what scopes the
        // emission count to the same span the ratio was computed over.
        let from = recent.first().map_or(usize::MAX, |(at, _)| *at);
        let count = emitted
            .get(&subject.identity)
            .map_or(0, |ats| ats.iter().filter(|at| **at >= from).count());

        // The strongest answer any of an identity's contexts gave. An identity
        // oscillating at one ref is flapping even while another ref is calm — the
        // pair is what keeps two calm refs from reading as one oscillation, not a
        // reason to need every ref to agree.
        let entry = assessment
            .health
            .entry(subject.identity.clone())
            .or_insert(Health::Steady);
        if health.is_flapping() && !entry.is_flapping() {
            *entry = health;
        }
        let seats = assessment.emissions.entry(subject.identity).or_insert(0);
        *seats = (*seats).max(count);
    }
    assessment
}

fn health_of(window: &[(usize, Observation)], percent: u32) -> Health {
    let raised: Vec<bool> = window
        .iter()
        .filter_map(|(_, observation)| observation.count())
        .map(|count| count > 0)
        .collect();
    let evaluations = raised.len();
    if evaluations < 2 {
        return Health::Steady;
    }
    let transitions = raised.windows(2).filter(|pair| pair[0] != pair[1]).count();
    // Per hundred, in integers: `transitions * 100 >= percent * (evaluations - 1)`.
    // The denominator is the number of ADJACENT PAIRS, not of evaluations, because
    // that is how many transitions could have occurred — dividing by evaluations
    // would make a perfectly alternating window score under 100% and never reach a
    // threshold set at it.
    let pairs = evaluations - 1;
    if transitions as u64 * 100 >= u64::from(percent) * pairs as u64 {
        return Health::Flapping {
            transitions,
            evaluations,
        };
    }
    Health::Steady
}

/// The ratio over one subject's window, and the threshold test.
///
/// Only evaluations that **looked** are counted, on both sides. A rule that was
/// skipped or errored reports [`Observation::NotObserved`], and reading that
/// silence as a state — either one — is the fail-open that type exists to prevent:
/// as a clear it would manufacture a transition out of a rule that never ran, and
/// in the denominator it would dilute a real oscillation toward steadiness.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::findings::{NotObserved, Presentation};
    use crate::journal::Origin;

    /// One evaluation of `identity` at `context`, raised or cleared.
    fn seen(identity: &str, context: Option<&str>, raised: bool) -> Entry {
        Entry {
            identity: identity.to_owned(),
            rule: "r".to_owned(),
            origin: Origin::Scan,
            context: context.map(ToOwned::to_owned),
            observation: Some(Observation::Observed(u64::from(raised))),
            disposition: None,
            presentation: Presentation::Shown,
        }
    }

    /// One evaluation that did not look.
    fn skipped(identity: &str, context: Option<&str>) -> Entry {
        Entry {
            observation: Some(Observation::NotObserved(NotObserved::RuleSkipped)),
            ..seen(identity, context, true)
        }
    }

    /// One drain emission of `identity`.
    fn shown(identity: &str) -> Entry {
        Entry {
            identity: identity.to_owned(),
            rule: "r".to_owned(),
            origin: Origin::Drain,
            context: None,
            observation: None,
            disposition: None,
            presentation: Presentation::Shown,
        }
    }

    /// An alternating run of evaluations at one context.
    fn alternating(identity: &str, context: Option<&str>, count: usize) -> Vec<Entry> {
        (0..count)
            .map(|at| seen(identity, context, at % 2 == 0))
            .collect()
    }

    // The acceptance's first bullet, on the arithmetic half: a rule that alternates
    // every evaluation is the maximal flap, and it must reach a threshold set at
    // 100 rather than falling just under it — which is what dividing by evaluations
    // instead of by adjacent pairs would have done.
    #[test]
    fn a_rule_alternating_every_evaluation_is_the_maximal_flap() {
        let log = alternating("a", Some("refs/heads/main"), 8);
        let assessment = assess(&log, 8, 100);
        assert_eq!(
            assessment.health("a"),
            Health::Flapping {
                transitions: 7,
                evaluations: 8,
            }
        );
    }

    // A raise that gets fixed is one transition, which is what the threshold has to
    // stay clear of: if an ordinary fix read as flapping, the policy would suppress
    // exactly the findings the drain exists to deliver.
    #[test]
    fn a_raise_and_a_fix_is_not_flapping() {
        let context = Some("refs/heads/main");
        let log = vec![
            seen("a", context, true),
            seen("a", context, true),
            seen("a", context, true),
            seen("a", context, false),
        ];
        assert_eq!(assess(&log, 8, DEFAULT_PERCENT).health("a"), Health::Steady);
    }

    /// The shipped threshold, so these cases are pinned against the default a
    /// consumer actually gets rather than a number chosen to make them pass.
    const DEFAULT_PERCENT: u32 = crate::drain::DEFAULT_FLAP_PERCENT;

    // Acceptance (b). The load-bearing case: two worktrees at two refs, each
    // perfectly monotone, interleaved in one log. Read per identity alone this is
    // `raised, raised, cleared, cleared` in an order that depends on scheduling;
    // read per (identity × context) each ref never changes state at all.
    #[test]
    fn a_worktree_pair_at_different_refs_is_not_flapping() {
        let a = Some("refs/heads/a");
        let b = Some("refs/heads/b");
        let log = vec![
            seen("x", a, true),
            seen("x", b, false),
            seen("x", a, true),
            seen("x", b, false),
            seen("x", a, true),
            seen("x", b, false),
        ];
        assert_eq!(
            assess(&log, 8, 100).health("x"),
            Health::Steady,
            "each ref's own sequence is monotone; only the interleaving alternates"
        );
        // And the same six observations at ONE ref are the flap, which is what makes
        // the assertion above about the context rather than about the counts.
        let merged: Vec<Entry> = log
            .iter()
            .map(|entry| Entry {
                context: a.map(ToOwned::to_owned),
                ..entry.clone()
            })
            .collect();
        assert!(assess(&merged, 8, 100).health("x").is_flapping());
    }

    // One flapping ref is enough. The pair keeps two calm refs from reading as one
    // oscillation; it is not a rule that every ref must agree before an identity is
    // annotated, which would let one quiet worktree mask a genuinely broken check.
    #[test]
    fn one_flapping_context_annotates_the_identity_even_beside_a_calm_one() {
        let mut log = alternating("x", Some("refs/heads/noisy"), 6);
        log.extend((0..6).map(|_| seen("x", Some("refs/heads/calm"), true)));
        assert!(assess(&log, 8, 100).health("x").is_flapping());
    }

    // Fewer than two evaluations has no rate, and the answer is `Steady` rather
    // than a guess in either direction — `FpRate::rate`'s "no rate rather than a
    // perfect one", resolved toward showing the finding.
    #[test]
    fn one_evaluation_has_no_rate_and_is_not_flapping() {
        let log = vec![seen("a", Some("refs/heads/main"), true)];
        assert_eq!(assess(&log, 8, 0).health("a"), Health::Steady);
    }

    // A rule that was skipped or errored said nothing about state. Counting it as a
    // clear would manufacture a transition out of a rule that never ran, which is
    // the fail-open `Observation::NotObserved` exists to prevent, one layer up.
    #[test]
    fn a_rule_that_did_not_look_neither_transitions_nor_dilutes() {
        let context = Some("refs/heads/main");
        let raised_around_a_skip = vec![
            seen("a", context, true),
            skipped("a", context),
            seen("a", context, true),
        ];
        assert_eq!(
            assess(&raised_around_a_skip, 8, 100).health("a"),
            Health::Steady,
            "two raises with a skip between them are one state, not two changes"
        );
        // Nor is the skip in the denominator: an alternating pair with a skip
        // between them is still 1 transition over 2 evaluations, so a threshold of
        // 100 is met rather than diluted to 50 by counting the skip.
        let alternating_around_a_skip = vec![
            seen("a", context, true),
            skipped("a", context),
            seen("a", context, false),
        ];
        assert!(
            assess(&alternating_around_a_skip, 8, 100)
                .health("a")
                .is_flapping()
        );
    }

    // The window is counted in evaluation boundaries, so an identity that HAS
    // stopped oscillating is believed again once the flapping evaluations fall out
    // of it. A wall-clock window could not express this at all.
    #[test]
    fn a_settled_identity_leaves_the_window_and_is_believed_again() {
        let context = Some("refs/heads/main");
        let mut log = alternating("a", context, 4);
        assert!(assess(&log, 4, 100).health("a").is_flapping());
        log.extend((0..4).map(|_| seen("a", context, true)));
        assert_eq!(
            assess(&log, 4, 100).health("a"),
            Health::Steady,
            "the last four evaluations hold no transition, whatever came before"
        );
    }

    // The cap and the annotation are read as a CONJUNCTION, and this is the half
    // that makes the policy hysteresis rather than a rate limiter: a steady
    // identity emitted far past the cap is still emitted.
    #[test]
    fn the_cap_never_bites_a_steady_identity() {
        let context = Some("refs/heads/main");
        let mut log: Vec<Entry> = (0..4).map(|_| seen("a", context, true)).collect();
        log.extend((0..9).map(|_| shown("a")));
        let assessment = assess(&log, 8, DEFAULT_PERCENT);
        assert_eq!(assessment.health("a"), Health::Steady);
        assert_eq!(assessment.decide("a", 3), Emission::Emit);
    }

    // And the other half: a flapping identity emits up to the cap and then stops.
    #[test]
    fn a_flapping_identity_emits_up_to_the_cap_and_then_stops() {
        let context = Some("refs/heads/main");
        let mut log = alternating("a", context, 6);
        assert_eq!(
            assess(&log, 8, 100).decide("a", 3),
            Emission::Emit,
            "nothing has been emitted yet, so the budget is unspent"
        );
        log.extend((0..3).map(|_| shown("a")));
        assert_eq!(
            assess(&log, 8, 100).decide("a", 3),
            Emission::Withhold(NotShown::FlapSuppressed)
        );
    }

    // Emissions are counted inside the window whose ratio was computed, not over
    // the whole log: an identity that flapped, was capped, then settled and later
    // flapped again must get its budget back, or one bad afternoon silences a
    // finding forever.
    #[test]
    fn emissions_outside_the_window_do_not_spend_this_windows_budget() {
        let context = Some("refs/heads/main");
        let mut log: Vec<Entry> = Vec::new();
        log.extend((0..3).map(|_| shown("a")));
        log.extend(alternating("a", context, 4));
        let assessment = assess(&log, 4, 100);
        assert!(assessment.health("a").is_flapping());
        assert_eq!(
            assessment.decide("a", 3),
            Emission::Emit,
            "the three emissions predate every evaluation in the window"
        );
    }

    // An identity the journal has never mentioned is emitted. The policy is a
    // filter on a history, so no history means no reason to withhold — and reading
    // absence as suppression would make the first drain after a GC silent.
    #[test]
    fn an_unknown_identity_is_steady_and_emitted() {
        let assessment = assess(&[], 8, 0);
        assert_eq!(assessment.health("nobody"), Health::Steady);
        assert_eq!(assessment.decide("nobody", 0), Emission::Emit);
    }

    // A window of 0 or 1 is how a consumer turns the policy off, and it must be off
    // for BOTH halves: nothing annotated, and therefore nothing suppressed however
    // much has been emitted.
    #[test]
    fn a_window_under_two_disables_the_policy_outright() {
        let context = Some("refs/heads/main");
        let mut log = alternating("a", context, 8);
        log.extend((0..9).map(|_| shown("a")));
        for window in [0, 1] {
            let assessment = assess(&log, window, 0);
            assert_eq!(assessment.health("a"), Health::Steady, "window {window}");
            assert_eq!(assessment.decide("a", 0), Emission::Emit, "window {window}");
        }
    }

    // An entry written before `observation` existed says nothing about what was
    // seen, and must not enter the denominator as an unknown. Write-old/read-both
    // at the field level: the fold has to survive meeting one.
    #[test]
    fn an_entry_that_names_no_observation_is_not_an_evaluation() {
        let context = Some("refs/heads/main");
        let mut log = alternating("a", context, 2);
        log.push(Entry {
            observation: None,
            ..seen("a", context, false)
        });
        assert_eq!(
            assess(&log, 8, 100).health("a"),
            Health::Flapping {
                transitions: 1,
                evaluations: 2,
            },
            "the silent entry changes neither count"
        );
    }

    // A secret-class record carries no `FindingKind`, so nothing about it can be
    // classified — and the emission plane must handle that without defaulting,
    // exactly as the changed-scope filter does (CLOUD-529 §7(e)). Here that means
    // its evaluations are folded on their context like any other subject's.
    #[test]
    fn an_identity_with_no_context_is_its_own_subject_never_a_default_ref() {
        let mut log = alternating("secret", None, 6);
        assert!(
            assess(&log, 8, 100).health("secret").is_flapping(),
            "a subject with no ref still has a history of its own"
        );
        // And it is not folded together with a named ref: adding a monotone run at
        // a real ref cannot make the unattributed subject's flap disappear, nor
        // does the unattributed run make the named one flap.
        log.extend((0..6).map(|_| seen("named", Some("refs/heads/main"), true)));
        let assessment = assess(&log, 8, 100);
        assert!(assessment.health("secret").is_flapping());
        assert_eq!(assessment.health("named"), Health::Steady);
    }

    // The annotation is telemetry, so it has to be enumerable with its counts —
    // "flapping" with no ratio is a label nobody can check.
    #[test]
    fn the_annotation_enumerates_only_flapping_identities_with_their_counts() {
        let context = Some("refs/heads/main");
        let mut log = alternating("noisy", context, 6);
        log.extend((0..6).map(|_| seen("calm", context, true)));
        let assessment = assess(&log, 8, 100);
        let annotated: Vec<(&String, Health)> = assessment.flapping().collect();
        assert_eq!(annotated.len(), 1);
        assert_eq!(annotated[0].0, "noisy");
        assert_eq!(
            annotated[0].1,
            Health::Flapping {
                transitions: 5,
                evaluations: 6,
            }
        );
    }

    // Byte-stability's precondition: the fold is a function of the log's contents
    // and its order, and holds no map whose iteration could vary.
    #[test]
    fn two_folds_of_one_log_agree() {
        let context = Some("refs/heads/main");
        let mut log = alternating("a", context, 5);
        log.extend(alternating("b", Some("refs/heads/other"), 5));
        log.extend((0..2).map(|_| shown("a")));
        let first = assess(&log, 8, 50);
        let second = assess(&log, 8, 50);
        assert_eq!(first.health("a"), second.health("a"));
        assert_eq!(first.health("b"), second.health("b"));
        assert_eq!(first.decide("a", 1), second.decide("a", 1));
    }
}
