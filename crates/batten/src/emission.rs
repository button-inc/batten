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

/// The ratio over one subject's window, and the threshold test.
///
/// Only evaluations that **looked** are counted, on both sides. A rule that was
/// skipped or errored reports [`Observation::NotObserved`], and reading that
/// silence as a state — either one — is the fail-open that type exists to prevent:
/// as a clear it would manufacture a transition out of a rule that never ran, and
/// in the denominator it would dilute a real oscillation toward steadiness.
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
