//! The advisory CHANNEL and what it may cost (CLOUD-896).
//!
//! CLOUD-461 put the drain and the drift notice on one
//! `hookSpecificOutput.additionalContext` document, and CLOUD-1051 moved the Stop
//! surface onto the same one. That solved FRAMING — one JSON object per call —
//! and solved nothing about VOLUME: the producers share no rate budget, so
//! nothing bounds how much any of them says or how much the set says together.
//!
//! CLOUD-82 already holds a token budget for the drain ALONE. Extending it to
//! the channel rather than to the producer is the difference between one
//! well-behaved reporter and three reporters that are each individually
//! reasonable, and it is the same trajectory `stop-guard` took: one rule, then
//! five, each defensible in isolation, with the aggregate never costed.
//!
//! The failure mode is CLOUD-417's, measured: hook output at 20% of a long
//! session's context. Setting the ceiling before the third producer arrives is
//! cheaper than rationalising it after — and the third producer has since
//! arrived, which is the row being right rather than lucky.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::refusal::{Arm, Refusal};
use crate::severity::AdvisoryTier;

/// One producer's contribution, with the latency its content demands.
///
/// The tier is carried from the PUSH SITE rather than inferred at the boundary,
/// because "how soon must this be answered" is a property of what is being said
/// and the boundary has only the string. CLOUD-80's reading of severity as
/// required response latency is what makes the ordering meaningful: when the
/// channel is over budget, what survives is what has to be answered soonest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advice {
    /// How soon this must be answered.
    pub tier: AdvisoryTier,
    /// The pointer text, already composed by its producer. Empty on a classed
    /// entry until `sight_advice` renders its `finding` at emission.
    pub text: String,
    /// The finding this entry projects, rendered only when it is emitted, so
    /// advice dropped beside a verdict is never marked seen (CLOUD-2075).
    pub finding: Option<Box<Refusal>>,
    /// Whether the text is a classed finding, rendered or still to render. The
    /// ceiling holds every entry alike (CLOUD-2175); this says what kind of
    /// line it is, never whether it may be shed.
    pub classed: bool,
    /// Said on its FULL arm only (CLOUD-2145): an entry whose address another
    /// line beside it already carries, so its repeat would say nothing new.
    pub full_only: bool,
}

impl Advice {
    /// One unclassed entry.
    #[must_use]
    pub fn new(tier: AdvisoryTier, text: impl Into<String>) -> Advice {
        Advice {
            tier,
            text: text.into(),
            finding: None,
            classed: false,
            full_only: false,
        }
    }

    /// Text that is ALREADY labelled finding lines, rendered by its producer —
    /// the drain's payload, whose every line is `rule '<id>' …` (CLOUD-2078).
    #[must_use]
    pub fn rendered(tier: AdvisoryTier, text: impl Into<String>) -> Advice {
        Advice {
            tier,
            text: text.into(),
            finding: None,
            classed: true,
            full_only: false,
        }
    }

    /// One classed entry, rendered through the finding projection at emission.
    #[must_use]
    pub fn finding(tier: AdvisoryTier, refusal: Refusal) -> Advice {
        Advice {
            tier,
            text: String::new(),
            finding: Some(Box::new(refusal)),
            classed: true,
            full_only: false,
        }
    }

    /// A classed entry said only where its reader has not yet had it in full —
    /// a drained rule's remedy, whose address the drain's own line already is.
    #[must_use]
    pub fn first_sighting(tier: AdvisoryTier, refusal: Refusal) -> Advice {
        Advice {
            full_only: true,
            ..Advice::finding(tier, refusal)
        }
    }
}

/// The `[advisory]` table: what ONE emission of the whole channel may cost.
///
/// **The channel, not the producer**, which is the whole of this row. Absent
/// means unenforced, on `[budget]`'s reading — a threshold nobody declared is
/// not a threshold of zero — so a consumer that has not adopted it emits exactly
/// what it emitted before.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// The ceiling on estimated tokens for one emission, across every producer.
    /// The boundary is `<=`, matching `[budget]` and `[refusal]` so the three
    /// thresholds in this tree do not disagree about their own edge.
    pub max_tokens: usize,
}

/// Refuse a ceiling nothing could satisfy.
///
/// # Errors
///
/// When the declared ceiling is zero: it would suppress every advisory including
/// the shortest, which is a channel switched off wearing a budget's clothes.
pub fn validate(channel: Option<&Channel>) -> Result<(), String> {
    match channel {
        Some(declared) if declared.max_tokens == 0 => Err(
            "`[advisory] max_tokens = 0` suppresses every advisory the channel could carry — \
             remove the table to leave the channel unbounded, or name a ceiling something can \
             fit inside"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}

/// What one emission carries, and what it left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emission {
    /// The admitted text, tier-ordered and joined.
    pub text: String,
    /// How many entries did not fit.
    pub suppressed: usize,
    /// The entries that did not fit, full and joined — what the caller stores so
    /// the closing line can name a handle that returns exactly them.
    pub overflow: String,
}

/// How an emission learns which arm each finding gets (CLOUD-2175): `peek`
/// answers without marking, so the ceiling can decide; `mark` answers as the
/// finding is delivered, so only what is admitted is ever marked seen.
pub trait Sighter {
    /// The arm `refusal` would get, marking nothing.
    fn peek(&self, refusal: &Refusal) -> Arm;
    /// The arm `refusal` gets as it is delivered, marking it seen.
    fn mark(&mut self, refusal: &Refusal) -> Arm;
}

/// A channel with no window: every finding is full and nothing is marked.
#[derive(Debug, Clone, Copy)]
pub struct Unsighted;

impl Sighter for Unsighted {
    fn peek(&self, _: &Refusal) -> Arm {
        Arm::Full
    }

    fn mark(&mut self, _: &Refusal) -> Arm {
        Arm::Full
    }
}

/// The widest handle a closing line can name, reserved while admitting so the
/// line itself never pushes an emission past its ceiling.
const WIDEST_HANDLE: &str =
    "advisory:0000000000000000000000000000000000000000000000000000000000000000";

/// The line closing an emission the ceiling cut, so a partial report cannot
/// read as a complete one: how many entries were withheld, the ceiling, and the
/// handle returning exactly them — or that they could not be stored.
///
/// **A truncated report that reads as complete is the false green in advisory
/// form**, and a count with no way to the rest is a truncation that calls
/// itself a summary (CLOUD-2175).
#[must_use]
pub fn suppressed_line(suppressed: usize, ceiling: usize, handle: Option<&str>) -> String {
    match handle {
        Some(handle) => format!(
            "advisory: {suppressed} further finding(s) past the declared channel ceiling of \
             {ceiling} token(s); run batten capture show {handle}"
        ),
        None => format!(
            "advisory: {suppressed} further finding(s) past the declared channel ceiling of \
             {ceiling} token(s), and they could not be stored"
        ),
    }
}

/// Merge entries whose findings differ only in their subjects (CLOUD-2175):
/// one class over several subjects is one line, keeping the first's position
/// and the stronger tier.
fn merged(entries: Vec<Advice>) -> Vec<Advice> {
    let mut out: Vec<Advice> = Vec::new();
    'entries: for entry in entries {
        if let Some(refusal) = entry.finding.as_deref() {
            for held in &mut out {
                if held
                    .finding
                    .as_deref_mut()
                    .is_some_and(|other| other.absorb(refusal))
                {
                    held.tier = held.tier.max(entry.tier);
                    continue 'entries;
                }
            }
        }
        out.push(entry);
    }
    out
}

/// Admit this call's advice to one emission, under the channel's ceiling.
///
/// # The ordering is the whole design
///
/// Under a ceiling, sorted by tier, strongest first, and STABLE within a tier so
/// two producers at one latency keep the order the boundary produced them in —
/// byte-stable under §6. With no ceiling nothing can be cut, so nothing is
/// reordered either: an undeclared table leaves the channel as it was.
///
/// # What fits is decided before anything is marked (CLOUD-2175)
///
/// Each finding is measured at the arm it WOULD get ([`Sighter::peek`]), and
/// marked ([`Sighter::mark`]) only once admitted. With no ceiling, or with
/// everything fitting, the whole set is admitted untouched — the ordinary case
/// pays nothing. Otherwise entries are admitted while they fit with the closing
/// line reserved, and the first that does not ends the emission: never skipping
/// to a smaller later entry, which would put a less urgent line ahead of a more
/// urgent one withheld. Every class is held to the ceiling; CLOUD-2075's
/// exemption for classed entries made it bound almost nothing once every
/// emitter was classed.
///
/// # The FIRST entry is always admitted
///
/// Even where it alone exceeds the ceiling: a channel that could emit nothing
/// would turn a budget into a mute switch.
//MUTANT-SUITE crates/batten/src/advisory.rs
//MUTANT first-sighting-repeated|s@^            !held$@            true@|a_drained_rules_remedy_is_said_once_per_window
//MUTANT unceilinged-reordered|s@^    let ranked = ceiling.is_some();$@    let ranked = true;@|an_undeclared_ceiling_leaves_the_channel_exactly_as_it_was
//MUTANT advisory-ceiling-unread|s@^    let whole = within(\&probes);$@    let whole = true;@|what_does_not_fit_is_counted_and_returned_rather_than_dropped
//MUTANT cut-entry-marked|s@^            overflow.push(match entry.finding {$@            overflow.push(match entry.finding.map(|refusal| { let _ = sighter.mark(\&refusal); refusal }) {@|a_cut_finding_is_never_marked_seen
#[must_use]
pub fn admit(
    entries: Vec<Advice>,
    ceiling: Option<&Channel>,
    sighter: &mut dyn Sighter,
) -> Emission {
    // An entry said on its full arm only is dropped where the reader already has
    // that arm, before anything is measured, so it costs a full channel nothing.
    let entries: Vec<Advice> = entries
        .into_iter()
        .filter(|entry| {
            let held = entry.full_only
                && entry
                    .finding
                    .as_deref()
                    .is_some_and(|refusal| sighter.peek(refusal) == Arm::Pointer);
            !held
        })
        .collect();
    let mut ordered = merged(entries);
    // `Reverse` because `AdvisoryTier` derives `Ord` weakest-first, and what must
    // survive a full channel is what has to be answered soonest. With no ceiling
    // nothing can be cut, so the boundary's own order stands untouched.
    let ranked = ceiling.is_some();
    if ranked {
        ordered.sort_by_key(|entry| std::cmp::Reverse(entry.tier));
    }
    let probes: Vec<String> = ordered
        .iter()
        .map(|entry| match entry.finding.as_deref() {
            Some(refusal) => refusal.render_finding(sighter.peek(refusal)),
            None => entry.text.clone(),
        })
        .collect();
    let within = |texts: &[String]| {
        ceiling.is_none_or(|held| {
            crate::budget::estimate_tokens(&joined_text(texts)) <= held.max_tokens
        })
    };
    let whole = within(&probes);
    let reserve =
        ceiling.map(|held| suppressed_line(ordered.len(), held.max_tokens, Some(WIDEST_HANDLE)));

    let mut admitted: Vec<String> = Vec::new();
    let mut overflow: Vec<String> = Vec::new();
    for (entry, probe) in ordered.into_iter().zip(probes) {
        let fits = overflow.is_empty()
            && (whole || admitted.is_empty() || {
                let mut candidate = admitted.clone();
                candidate.push(probe.clone());
                candidate.extend(reserve.clone());
                within(&candidate)
            });
        if !fits {
            overflow.push(match entry.finding {
                Some(refusal) => refusal.render_finding(Arm::Full),
                None => entry.text,
            });
            continue;
        }
        admitted.push(match entry.finding {
            Some(refusal) => refusal.render_finding(sighter.mark(&refusal)),
            None => entry.text,
        });
    }
    Emission {
        text: joined_text(&admitted),
        suppressed: overflow.len(),
        overflow: joined_text(&overflow),
    }
}

/// The channel's one separator, over rendered texts.
fn joined_text(texts: &[String]) -> String {
    texts.join("\n\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(tier: AdvisoryTier, text: &str) -> Advice {
        Advice::new(tier, text)
    }

    fn emit(entries: Vec<Advice>, ceiling: Option<&Channel>) -> Emission {
        admit(entries, ceiling, &mut Unsighted)
    }

    /// A sighter recording what it was asked to mark.
    #[derive(Default)]
    struct Recording {
        marked: Vec<String>,
    }

    impl Sighter for Recording {
        fn peek(&self, _: &Refusal) -> Arm {
            Arm::Pointer
        }

        fn mark(&mut self, refusal: &Refusal) -> Arm {
            self.marked.push(refusal.subjects_text().to_owned());
            Arm::Pointer
        }
    }

    fn finding(tier: AdvisoryTier, subject: &str) -> Advice {
        classed(tier, crate::verdict::Native::RunBroken, subject)
    }

    /// A drained rule's remedy is said in full once per window, and never as a
    /// second address beside the drain line that already is one (CLOUD-2145).
    #[test]
    fn a_drained_rules_remedy_is_said_once_per_window() {
        let remedy = || {
            Advice::first_sighting(
                AdvisoryTier::Advisory,
                Refusal::engine(
                    crate::verdict::Native::CheckRunRed,
                    &[crate::verdict::artifact("remedy-subject")],
                    crate::refusal::Fix::None,
                ),
            )
        };
        let seen = admit(
            vec![finding(AdvisoryTier::Advisory, "kept"), remedy()],
            None,
            &mut Recording::default(),
        );
        assert!(seen.text.contains("kept"), "{}", seen.text);
        assert!(!seen.text.contains("remedy-subject"), "{}", seen.text);
        let fresh = admit(vec![remedy()], None, &mut Unsighted);
        assert!(fresh.text.contains("remedy-subject"), "{}", fresh.text);
    }

    fn classed(tier: AdvisoryTier, class: crate::verdict::Native, subject: &str) -> Advice {
        Advice::finding(
            tier,
            Refusal::engine(
                class,
                &[crate::verdict::artifact(subject)],
                crate::refusal::Fix::None,
            ),
        )
    }

    #[test]
    fn three_producers_emit_one_document_ordered_by_tier() {
        // THE ROW'S OWN CASE. Three producers on one boundary, admitted in
        // `AdvisoryTier` order — what must be answered soonest leads.
        let emission = emit(
            vec![
                entry(AdvisoryTier::Advisory, "drain says a thing"),
                entry(AdvisoryTier::Warning, "the contract moved"),
                entry(AdvisoryTier::Caution, "the turn ended oddly"),
            ],
            Some(&Channel { max_tokens: 500 }),
        );
        assert_eq!(emission.suppressed, 0);
        assert_eq!(
            emission.text,
            "the contract moved\n\nthe turn ended oddly\n\ndrain says a thing"
        );
    }

    #[test]
    fn what_does_not_fit_is_counted_and_returned_rather_than_dropped() {
        // THE MUTATION CASE (CLOUD-418): remove the ceiling and this goes red,
        // because everything fits and nothing is counted. What did not fit is
        // returned whole, so the caller can store it and name where it went
        // (CLOUD-2175) — a count with no way to the rest is a truncation.
        let emission = emit(
            vec![
                entry(AdvisoryTier::Warning, &"w".repeat(80)),
                entry(AdvisoryTier::Caution, &"c".repeat(80)),
                entry(AdvisoryTier::Advisory, &"a".repeat(80)),
            ],
            Some(&Channel { max_tokens: 30 }),
        );
        assert_eq!(emission.suppressed, 2, "two did not fit: {}", emission.text);
        assert_eq!(
            emission.text,
            "w".repeat(80),
            "the one due soonest survives"
        );
        assert_eq!(
            emission.overflow,
            format!("{}\n\n{}", "c".repeat(80), "a".repeat(80)),
            "and the rest is handed back whole, in order"
        );
    }

    #[test]
    fn an_undeclared_ceiling_leaves_the_channel_exactly_as_it_was() {
        // ANTI-VACUITY. A consumer that has not adopted the table emits what it
        // emitted before, in the order the boundary produced — no reordering, no
        // count line, nothing paid on a call that was never the problem.
        let emission = emit(
            vec![
                entry(AdvisoryTier::Advisory, "first"),
                entry(AdvisoryTier::Warning, "second"),
            ],
            None,
        );
        assert_eq!(emission.suppressed, 0);
        assert_eq!(emission.text, "first\n\nsecond");
    }

    #[test]
    fn the_first_entry_is_admitted_even_when_it_alone_is_over() {
        // A channel that could emit nothing would make the count line the only
        // thing said — a report about a report. The overflow is still counted, so
        // the reader learns the ceiling is too small rather than hearing silence.
        let emission = emit(
            vec![
                entry(AdvisoryTier::Warning, &"w".repeat(400)),
                entry(AdvisoryTier::Advisory, "short"),
            ],
            Some(&Channel { max_tokens: 1 }),
        );
        assert_eq!(emission.suppressed, 1);
        assert!(emission.text.starts_with(&"w".repeat(400)));
    }

    #[test]
    fn a_zero_ceiling_is_refused_at_load() {
        assert!(validate(Some(&Channel { max_tokens: 0 })).is_err());
        assert!(validate(Some(&Channel { max_tokens: 1 })).is_ok());
        assert!(validate(None).is_ok());
    }

    #[test]
    fn one_tier_keeps_the_boundarys_own_order() {
        // Stable within a tier, so two producers at one latency stay byte-stable
        // under §6 rather than depending on a sort nobody declared.
        let emission = emit(
            vec![
                entry(AdvisoryTier::Caution, "alpha"),
                entry(AdvisoryTier::Caution, "beta"),
            ],
            Some(&Channel { max_tokens: 500 }),
        );
        assert_eq!(emission.text, "alpha\n\nbeta");
    }

    /// THE CEILING HOLDS CLASSED ENTRIES TOO, and a cut one is never marked
    /// seen (CLOUD-2175): marked and cut, it would read as delivered and its
    /// next firing would carry the pointer alone.
    #[test]
    fn a_cut_finding_is_never_marked_seen() {
        let mut sighter = Recording::default();
        let emission = admit(
            vec![
                finding(AdvisoryTier::Warning, &"w".repeat(120)),
                entry(AdvisoryTier::Caution, &"c".repeat(80)),
                classed(
                    AdvisoryTier::Advisory,
                    crate::verdict::Native::CheckRunRed,
                    "a-subject",
                ),
            ],
            Some(&Channel { max_tokens: 40 }),
            &mut sighter,
        );
        assert_eq!(emission.suppressed, 2, "{}", emission.text);
        assert_eq!(
            sighter.marked,
            ["w".repeat(120)],
            "only the admitted one is marked"
        );
        assert!(
            emission.overflow.contains("a-subject"),
            "{}",
            emission.overflow
        );
    }

    /// ONE CLASS, ONE LINE (CLOUD-2175): findings of a class that differ only
    /// in their subjects merge, so the label and routes are paid once.
    #[test]
    fn findings_of_one_class_merge_into_one_line() {
        let emission = emit(
            vec![
                finding(AdvisoryTier::Advisory, "first"),
                finding(AdvisoryTier::Warning, "second"),
            ],
            None,
        );
        assert_eq!(emission.text.lines().count(), 1, "{}", emission.text);
        assert!(
            emission.text.contains("at first, second"),
            "both subjects on the one line: {}",
            emission.text
        );
    }
}
