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
    /// The pointer text, already composed by its producer.
    pub text: String,
}

impl Advice {
    /// One entry.
    #[must_use]
    pub fn new(tier: AdvisoryTier, text: impl Into<String>) -> Advice {
        Advice {
            tier,
            text: text.into(),
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
}

/// The line a truncated emission ends with, so a partial report cannot read as a
/// complete one.
///
/// **A truncated report that reads as complete is the false green in advisory
/// form**, which is the row's own words and the reason the count is not
/// optional. `drain.rs`'s `budget_summary` is the shape reused: a count and a
/// ceiling, never the text that was dropped — the suppressed entries are
/// pointers somebody else's producer composed, and reprinting them here would
/// spend the budget this exists to hold.
#[must_use]
pub fn suppressed_line(suppressed: usize, ceiling: usize) -> String {
    format!(
        "advisory: {suppressed} further finding(s) suppressed at the declared channel ceiling of {ceiling} token(s)"
    )
}

/// Admit producers to one emission in tier order until the ceiling is spent.
///
/// # The ordering is the whole design
///
/// Sorted by tier, strongest first, and STABLE within a tier so two producers at
/// one latency keep the order the boundary produced them in — which is the same
/// declaration-order tie-break every other table here uses, and the one that
/// keeps output byte-stable under §6.
///
/// # Under-budget is untouched
///
/// With no ceiling declared, or with everything fitting, this joins and returns
/// exactly what it was handed and suppresses nothing. That is the anti-vacuity
/// half: a budget that reordered or trimmed the ordinary case would be paid for
/// on every call that was never the problem.
///
/// # The FIRST entry is always admitted
///
/// Even where it alone exceeds the ceiling. A channel that could emit nothing at
/// all would turn a budget into a mute switch, and the count line would then be
/// the only thing said — a report about a report. The overflow is still counted,
/// so the reader learns the ceiling is too small for its own content rather than
/// hearing silence.
#[must_use]
pub fn admit(entries: Vec<Advice>, ceiling: Option<&Channel>) -> Emission {
    let Some(ceiling) = ceiling else {
        return Emission {
            text: joined(&entries),
            suppressed: 0,
        };
    };
    let mut ordered = entries;
    // `Reverse` because `AdvisoryTier` derives `Ord` weakest-first, and what must
    // survive a full channel is what has to be answered soonest.
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.tier));

    let mut admitted: Vec<Advice> = Vec::new();
    let mut suppressed = 0;
    for entry in ordered {
        let candidate = joined_with(&admitted, &entry);
        if admitted.is_empty() || crate::budget::estimate_tokens(&candidate) <= ceiling.max_tokens {
            admitted.push(entry);
        } else {
            suppressed += 1;
        }
    }
    let mut text = joined(&admitted);
    if suppressed > 0 {
        text.push_str("\n\n");
        text.push_str(&suppressed_line(suppressed, ceiling.max_tokens));
    }
    Emission { text, suppressed }
}

/// The channel's one separator, in one place so the measurement and the emission
/// cannot disagree about what a joined document costs.
fn joined(entries: &[Advice]) -> String {
    entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect::<Vec<&str>>()
        .join("\n\n")
}

/// What `admitted` would cost with `next` added — measured on the JOINED form,
/// because the separator is part of what the channel carries.
fn joined_with(admitted: &[Advice], next: &Advice) -> String {
    let mut all: Vec<&str> = admitted.iter().map(|entry| entry.text.as_str()).collect();
    all.push(next.text.as_str());
    all.join("\n\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(tier: AdvisoryTier, text: &str) -> Advice {
        Advice::new(tier, text)
    }

    #[test]
    fn three_producers_emit_one_document_ordered_by_tier() {
        // THE ROW'S OWN CASE. Three producers on one boundary, admitted in
        // `AdvisoryTier` order — what must be answered soonest leads.
        let emission = admit(
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
    fn what_does_not_fit_is_counted_rather_than_dropped_silently() {
        // THE MUTATION CASE (CLOUD-418): remove the comparison in `admit` and
        // this goes red, because everything fits and nothing is counted. A
        // truncated report that reads as complete is the false green in advisory
        // form, which is why the count is not optional.
        let emission = admit(
            vec![
                entry(AdvisoryTier::Warning, &"w".repeat(80)),
                entry(AdvisoryTier::Caution, &"c".repeat(80)),
                entry(AdvisoryTier::Advisory, &"a".repeat(80)),
            ],
            Some(&Channel { max_tokens: 30 }),
        );
        assert_eq!(emission.suppressed, 2, "two did not fit: {}", emission.text);
        assert!(
            emission.text.starts_with(&"w".repeat(80)),
            "and the one that survives is the one due soonest: {}",
            emission.text
        );
        assert!(
            emission.text.contains("2 further finding(s) suppressed"),
            "the drop is counted: {}",
            emission.text
        );
    }

    #[test]
    fn an_undeclared_ceiling_leaves_the_channel_exactly_as_it_was() {
        // ANTI-VACUITY. A consumer that has not adopted the table emits what it
        // emitted before, in the order the boundary produced — no reordering, no
        // count line, nothing paid on a call that was never the problem.
        let emission = admit(
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
        let emission = admit(
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
        let emission = admit(
            vec![
                entry(AdvisoryTier::Caution, "alpha"),
                entry(AdvisoryTier::Caution, "beta"),
            ],
            Some(&Channel { max_tokens: 500 }),
        );
        assert_eq!(emission.text, "alpha\n\nbeta");
    }
}
