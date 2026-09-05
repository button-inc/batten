//! What this repository's own hooks cost the session that runs them (CLOUD-417).
//!
//! # The finding this exists for
//!
//! Non-negotiable rule 4 holds every check to "a count, `path:line`, or boolean —
//! never the content itself", and each hook obeys it individually. Nobody had
//! measured them **in aggregate**, over a session, where one line that obeys the
//! rule is emitted hundreds of times and every copy stays in context forever.
//!
//! Measured on one captured transcript (758 turns, 5.83 MB): `hook_success` at
//! 1181 KB and `hook_additional_context` at 42 KB against 95 KB of edited files
//! and 88 KB of delivered memories — **hook output alone is 20% of the
//! transcript**. The single largest contributor said one true, correctly
//! pointer-shaped, identical thing on essentially every turn.
//!
//! # Why the rule was unstatable before
//!
//! The output rule is stated per-CHECK and enforced per-CHECK. There is no rule
//! about a check's output over a SESSION, so a hook that is silent by default
//! (correct) and one that confirms success every turn (also individually
//! defensible) are indistinguishable to every gate that exists. That is the same
//! shape CLOUD-896 found one layer down, where three producers each within their
//! own budget shared a channel with none — and the answer is the same: put the
//! ceiling on the aggregate, because the aggregate is what is actually spent.
//!
//! # Two predicates, and the second is most of the win
//!
//! [`Ceiling::max_tokens`] is the blunt one: hook output over a whole session has
//! a ceiling. [`Ceiling::max_repeats`] is the sharp one, and it is what makes
//! "silence on success is the default" and "a repeat is a pointer to the first,
//! not a copy" **decidable** rather than prose. A hook that says the same thing
//! every turn is byte-identical every turn, so it is exactly a digest repeated —
//! and prose asking hooks to be quiet is the feedforward this repository refuses
//! (non-negotiable rule 2).
//!
//! # Pointer-only, structurally
//!
//! Everything here is a count, a digest prefix, or a host-supplied producer name.
//! The emitted text never reaches this module: [`crate::transcript`] hashes it and
//! drops it at the parse. A measurement of an over-wide channel that itself
//! carried what the channel said would be the joke writing itself.
//!
//! # It applies to itself
//!
//! [`Reading::line`] is ONE line. The row's acceptance says so, and it is not
//! decoration: a gate about hook volume whose own report is a paragraph would be
//! the defect wearing the sensor's clothes.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::{FindingKind, StoredIdentity};
use crate::rules::Finding;
use crate::severity::RuleSeverity;
use crate::transcript::{Event, Stream};

/// The `[hook_output]` table: what this repository's hooks may cost one session.
///
/// **Absent means unenforced**, on `[budget]`'s reading — a threshold nobody
/// declared is not a threshold of zero — so a consumer that has not adopted the
/// table measures exactly as it did before and refuses nothing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    /// The ceiling on estimated tokens of hook output across the whole session.
    /// The boundary is `<=`, matching `[budget]`, `[refusal]` and `[advisory]`
    /// so the four thresholds in this tree do not disagree about their own edge.
    pub max_tokens: usize,
    /// How many times one hook may emit byte-identical text in one session.
    ///
    /// **The floor is 1, not 0.** Saying a thing once is the report; saying it
    /// again is the copy. A ceiling of 0 would refuse the first emission, which
    /// is a hook switched off rather than a hook made quiet — and this row puts
    /// "removing any hook, or weakening what it detects" explicitly out of scope.
    pub max_repeats: usize,
}

/// Refuse a ceiling nothing could satisfy.
///
/// # Errors
///
/// When `max_tokens` is zero — no hook could speak at all — or when
/// `max_repeats` is zero, which refuses a hook's FIRST emission and so silences
/// the finding rather than its restatement.
pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
    let Some(declared) = ceiling else {
        return Ok(());
    };
    if declared.max_tokens == 0 {
        return Err(
            "`[hook_output] max_tokens = 0` refuses every hook that speaks at all — remove the \
             table to leave hook output unbounded, or name a ceiling a session can fit inside"
                .to_owned(),
        );
    }
    if declared.max_repeats == 0 {
        return Err(
            "`[hook_output] max_repeats = 0` refuses a hook's FIRST emission, which silences the \
             finding rather than its restatement; 1 is the floor — say it once"
                .to_owned(),
        );
    }
    Ok(())
}

/// One producer's cost over the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Cost {
    /// Estimated tokens this producer spent in total.
    pub tokens: usize,
    /// How many times it emitted anything at all.
    pub emissions: usize,
}

/// One thing said more than once.
///
/// Pointer-only: the producer's host-given name, a digest PREFIX, a count, and
/// the line the first copy landed on. Never the text, and never the full digest —
/// eight hex characters name the repeat in a report and cannot reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Repeat {
    /// The producer, as the host named it.
    pub hook: String,
    /// The first eight hex characters of the emission's digest.
    pub digest: String,
    /// How many copies the session carried.
    pub count: usize,
    /// The transcript line the FIRST copy landed on — the pointer a repeat is
    /// supposed to be, which is the row's own remedy stated as an output field.
    pub first_line: usize,
}

/// What [`measure`] found.
///
/// Byte-stable for identical input: producers are reported in name order,
/// repeats in (producer, digest) order, and no field derives from the clock, the
/// environment, or where the repository lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Reading {
    /// Estimated tokens of hook output over the whole session.
    pub tokens: usize,
    /// Estimated tokens of the whole transcript, the denominator that turns the
    /// number above into the row's headline share.
    pub session_tokens: usize,
    /// Per-producer costs, in producer-name order.
    pub per_hook: BTreeMap<String, Cost>,
    /// Every emission the session carried more than once, whatever the declared
    /// ceiling — the measurement is separate from the judgement, so a reading
    /// taken with no table declared still reports what a table would refuse.
    pub repeats: Vec<Repeat>,
}

impl Reading {
    /// Hook output as a percentage of the session, rounded down.
    ///
    /// **Zero when the session measured nothing**, rather than a division that
    /// cannot be performed: an empty transcript has no share, and reporting one
    /// would be an answer where there is no reading.
    #[must_use]
    pub fn share(&self) -> usize {
        if self.session_tokens == 0 {
            return 0;
        }
        self.tokens * 100 / self.session_tokens
    }

    /// The whole report, as ONE line.
    ///
    /// The row's acceptance clause, and this module's self-application: a gate
    /// about hook volume answers in the shape it demands. Counts and a share,
    /// never a producer's text — and the producers themselves are named in the
    /// findings, which is where a reader who needs one goes.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "hook output {} token(s), {}% of {} session token(s), {} producer(s), {} repeat(s)",
            self.tokens,
            self.share(),
            self.session_tokens,
            self.per_hook.len(),
            self.repeats.len()
        )
    }
}

/// `policy hooks`' one summary line. ONE line always, which is the self-applying
/// property: a gate about hook volume whose own report grew with what it found
/// would be the defect wearing the sensor's clothes.
///
/// Forwards to [`Reading::line`] rather than restating it: CLOUD-371 unifies
/// which types may reach the data channel, never what any of them renders, so
/// the bytes here are the bytes this type already emitted.
impl crate::output::Line for Reading {
    fn line(&self) -> String {
        Reading::line(self)
    }
}

/// The rule id a session-budget finding carries.
pub const BUDGET_RULE: &str = "hook-output-budget";

/// The rule id a repeated-emission finding carries.
pub const REPEAT_RULE: &str = "hook-repeat-pointer";

/// Count what the hooks spent, from the parsed stream alone.
///
/// **No I/O and no clock**, which is what lets the second test tier run this over
/// a fixture transcript and get the same answer the live path would.
#[must_use]
pub fn measure(stream: &Stream) -> Reading {
    let mut per_hook: BTreeMap<String, Cost> = BTreeMap::new();
    // Keyed on (producer, digest) so one hook saying two different things is two
    // entries and two hooks saying one thing is two entries. Collapsing either
    // way would report a repeat that nobody made.
    let mut seen: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    let mut tokens = 0;
    for record in &stream.records {
        let Event::HookOutput {
            hook,
            tokens: cost,
            digest,
        } = &record.event
        else {
            continue;
        };
        tokens += cost;
        let entry = per_hook.entry(hook.clone()).or_insert(Cost {
            tokens: 0,
            emissions: 0,
        });
        entry.tokens += cost;
        entry.emissions += 1;
        let slot = seen
            .entry((hook.clone(), digest.clone()))
            .or_insert((0, record.line));
        slot.0 += 1;
    }
    let repeats = seen
        .into_iter()
        .filter(|(_, (count, _))| *count > 1)
        .map(|((hook, digest), (count, first_line))| Repeat {
            hook,
            // A PREFIX. Eight characters name the thing in a report; the whole
            // digest would let a reader who already holds a candidate text
            // confirm it, which is a payload channel opened by arithmetic.
            digest: digest.chars().take(8).collect(),
            count,
            first_line,
        })
        .collect();
    Reading {
        tokens,
        session_tokens: crate::budget::estimate_tokens_over(stream.bytes),
        per_hook,
        repeats,
    }
}

/// Judge a reading against the declared ceiling.
///
/// **An undeclared ceiling judges nothing and is not an error.** That is the
/// anti-vacuity direction stated as behaviour: `measure` still reports, so a
/// consumer can read its own number before choosing one, and adopting the table
/// is a separate act from being measured by it.
#[must_use]
pub fn judge(reading: &Reading, ceiling: Option<&Ceiling>) -> Vec<Finding> {
    let Some(ceiling) = ceiling else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if reading.tokens > ceiling.max_tokens {
        found.push(finding(
            BUDGET_RULE,
            // The SUBJECT is the session, named as a count rather than as a
            // path: there is no file to point at, and pointing at the transcript
            // would name a document rule 4 keeps every byte of off this channel.
            format!("session:{}", reading.tokens),
            None,
            "cut what the hooks restate until the session is under its budget",
        ));
    }
    for repeat in &reading.repeats {
        if repeat.count > ceiling.max_repeats {
            found.push(finding(
                REPEAT_RULE,
                format!("{}:{}x{}", repeat.hook, repeat.digest, repeat.count),
                Some(repeat.first_line),
                "emit it once and make the later turns point at the first, the way \
                 `contract-drift` already reports a change-set once",
            ));
        }
    }
    found
}

/// One engine-produced finding, in `budget.rs`'s shape.
///
/// Engine-produced rather than a `[[rule]]` row, for that module's reason
/// exactly: re-measuring the session IS the check, and the fix is cutting what a
/// hook restates — prose no command can write, so [`Remediation::NoFix`] states
/// it rather than a `Fix::Run` naming a command that would not help.
fn finding(rule: &str, subject: String, line: Option<usize>, remedy: &str) -> Finding {
    Finding {
        owner: None,
        rule: rule.to_owned(),
        severity: RuleSeverity::Deny,
        identity: StoredIdentity::new(
            FindingKind::Scope,
            crate::identity::scope_fingerprint(rule, &subject),
        ),
        path: subject,
        line,
        check: crate::findings::Check::Reevaluate,
        remediation: Some(crate::findings::Remediation::NoFix(remedy.to_owned())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::transcript::Record;

    fn emitted(line: usize, hook: &str, digest: &str, tokens: usize) -> Record {
        Record {
            line,
            event: Event::HookOutput {
                hook: hook.to_owned(),
                tokens,
                digest: digest.to_owned(),
            },
        }
    }

    fn session(records: Vec<Record>, bytes: usize) -> Stream {
        Stream {
            session: Some("s-1".to_owned()),
            records,
            agent: crate::transcript::AgentContext::default(),
            bytes,
            // Unkeyed: this suite is about hook OUTPUT cost, and a fixture that
            // claimed a key it never used would say the stream had been
            // fingerprinted when nothing was.
            keyed: false,
        }
    }

    #[test]
    fn a_hook_saying_one_thing_n_times_is_a_violation() {
        // THE ROW'S OWN CASE, and the mutation case with it: drop the `count > 1`
        // filter in `measure` and every single emission becomes a repeat, so the
        // clean case below goes red.
        let reading = measure(&session(
            vec![
                emitted(3, "SessionStart:mcp", "aaaaaaaabbbb", 40),
                emitted(9, "SessionStart:mcp", "aaaaaaaabbbb", 40),
                emitted(14, "SessionStart:mcp", "aaaaaaaabbbb", 40),
            ],
            4_000,
        ));
        assert_eq!(reading.repeats.len(), 1);
        assert_eq!(reading.repeats[0].count, 3);
        assert_eq!(
            reading.repeats[0].first_line, 3,
            "the pointer is the FIRST copy"
        );
        assert_eq!(
            reading.repeats[0].digest, "aaaaaaaa",
            "a prefix, not the key"
        );

        let refused = judge(&reading, Some(&Ceiling::once()));
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].rule, REPEAT_RULE);
    }

    #[test]
    fn a_hook_reporting_one_change_set_once_is_clean() {
        // The discriminating half. Without it a rule that refused every emission
        // would satisfy the case above and gate nothing.
        let reading = measure(&session(
            vec![
                emitted(3, "PostToolBatch:drift", "cccccccc1111", 30),
                emitted(9, "PostToolBatch:drift", "dddddddd2222", 30),
            ],
            4_000,
        ));
        assert!(
            reading.repeats.is_empty(),
            "two different things are not one"
        );
        assert!(judge(&reading, Some(&Ceiling::once())).is_empty());
    }

    #[test]
    fn a_hook_silent_on_success_is_clean_and_costs_nothing() {
        // Silence is the default, and it has to be spellable as a reading rather
        // than only as a posture: no records, no cost, no share, no findings.
        let reading = measure(&session(Vec::new(), 4_000));
        assert_eq!(reading.tokens, 0);
        assert_eq!(reading.share(), 0);
        assert!(reading.per_hook.is_empty());
        assert!(judge(&reading, Some(&Ceiling::once())).is_empty());
    }

    #[test]
    fn two_hooks_saying_the_same_thing_are_two_producers_not_one_repeat() {
        // The key is (producer, digest). Collapsing to the digest alone would
        // report a repeat neither hook made, and blame it on whichever name
        // sorted first.
        let reading = measure(&session(
            vec![
                emitted(3, "one", "eeeeeeee3333", 10),
                emitted(4, "two", "eeeeeeee3333", 10),
            ],
            4_000,
        ));
        assert!(reading.repeats.is_empty());
        assert_eq!(reading.per_hook.len(), 2);
    }

    #[test]
    fn the_session_share_is_the_headline_figure_recomputed() {
        // The row's acceptance: the 20% figure is re-runnable rather than
        // believed. 1000 tokens of hook output against a 4000-byte transcript,
        // which the estimator reads as 1000 session tokens... so the share is
        // over the denominator the estimator gives, not over a byte count.
        let reading = measure(&session(vec![emitted(3, "loud", "ffff4444", 200)], 4_000));
        assert_eq!(reading.session_tokens, 1_000);
        assert_eq!(reading.tokens, 200);
        assert_eq!(reading.share(), 20);
    }

    #[test]
    fn an_undeclared_ceiling_measures_and_refuses_nothing() {
        // ANTI-VACUITY. The reading still reports the repeat; only the judgement
        // is withheld, so a consumer can read its own number before adopting one.
        let reading = measure(&session(
            vec![
                emitted(3, "loud", "aaaaaaaa", 9_000),
                emitted(4, "loud", "aaaaaaaa", 9_000),
            ],
            10,
        ));
        assert_eq!(reading.repeats.len(), 1, "measured");
        assert!(judge(&reading, None).is_empty(), "and not judged");
    }

    #[test]
    fn the_budget_arm_fires_on_the_total_and_the_boundary_is_inclusive() {
        let reading = measure(&session(vec![emitted(3, "loud", "aaaaaaaa", 100)], 4_000));
        assert!(
            judge(
                &reading,
                Some(&Ceiling {
                    max_tokens: 100,
                    max_repeats: 1
                })
            )
            .is_empty(),
            "exactly at budget passes, as `[budget]` does"
        );
        let over = judge(
            &reading,
            Some(&Ceiling {
                max_tokens: 99,
                max_repeats: 1,
            }),
        );
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].rule, BUDGET_RULE);
    }

    #[test]
    fn a_ceiling_nothing_can_satisfy_is_refused_at_load() {
        assert!(validate(None).is_ok());
        assert!(validate(Some(&Ceiling::once())).is_ok());
        assert!(
            validate(Some(&Ceiling {
                max_tokens: 0,
                max_repeats: 1
            }))
            .is_err()
        );
        assert!(
            validate(Some(&Ceiling {
                max_tokens: 10,
                max_repeats: 0
            }))
            .is_err(),
            "zero repeats refuses the finding rather than its restatement"
        );
    }

    #[test]
    fn the_reports_own_output_is_one_line() {
        // THE SELF-APPLYING PROPERTY, asserted rather than intended.
        let reading = measure(&session(
            vec![
                emitted(3, "a", "1111", 5),
                emitted(4, "b", "2222", 5),
                emitted(5, "b", "2222", 5),
            ],
            400,
        ));
        assert_eq!(reading.line().lines().count(), 1);
    }

    impl Ceiling {
        /// A ceiling that refuses only a repeat, so a case can vary one predicate.
        fn once() -> Ceiling {
            Ceiling {
                max_tokens: usize::MAX,
                max_repeats: 1,
            }
        }
    }
}
