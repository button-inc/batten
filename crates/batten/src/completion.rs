//! Declared done with work not landed, as a structural predicate (CLOUD-97).
//!
//! Batten's threat model names *the wrong completion signal*, and until this
//! module nothing in the engine compared a declared stopping point to repo
//! state. The predicate is a conjunction of two facts, each read from a typed
//! field and neither inferred from prose:
//!
//! * **`completion-signaled`** — the session's stream carries a completion
//!   marker with no tool call after it. Two producers, both exact membership
//!   over a token set: a turn that ended because the model finished
//!   ([`crate::transcript::StopReason`]), and a hook run at a Stop-family event
//!   ([`crate::hook::Event`]).
//! * **`¬landed`** — [`crate::git::landing`] finds no patch-id-equivalent
//!   commit on the landing target. **Content, never ancestry**, which is the
//!   whole reason acceptance's rebased-and-landed case needs no code here: it
//!   is a property of the primitive.
//!
//! # Why this detects rather than prevents
//!
//! A hard deny at "done" was ruled out on the issue and the reasoning is worth
//! keeping where the code is: pausing or handing off mid-task is legitimate, so
//! blocking a completion signal punishes correct behaviour. What is registered
//! is **self-clearing** — the next evaluation over the same session, once the
//! work has landed, resolves it with no acknowledgement from anybody. That is
//! also why the finding is registered through the advisory door and never
//! becomes a [`crate::rules::Finding`]: an advisory surface must be
//! *structurally* unable to block (house style §0.3), not merely observed not
//! to.
//!
//! # Facts in, verdict out
//!
//! [`stop`](crate::stop)'s split, for the same reason: [`signal`] reads a
//! parsed stream and [`assess`] is pure over values, so every branch of the
//! four-valued outcome is testable without a repository, a clock, or a store.
//! The caller owns both boundaries — resolving the transcript and asking git —
//! and this module owns neither.
//!
//! # Output is a pointer
//!
//! A transcript line number, a marker token, and a count of unaccounted
//! commits. Never a commit message, never a SHA's content, never a line of the
//! transcript (non-negotiable rule 4) — and never the raw session id, which is
//! a host-chosen string that reaches the store only through
//! [`crate::identity::sequence_fingerprint`].

use serde::Serialize;

use crate::findings::{NotObserved, Observation};
use crate::git::Landing;
use crate::transcript::{Event, StopReason, Stream};

/// The rule id this detector's findings are stored under.
///
/// Engine-side, like `budget.<name>` and the defect ledger's gate ids: there is
/// no `[[rule]]` row to take an id from, because the predicate needs the
/// transcript input and the findings store — neither of which a `batten.toml`
/// rule can name.
pub const RULE_ID: &str = "completion.unlanded";

/// The identity's pattern key, fixed for the life of the rule.
///
/// The *session* is what separates one incident from another
/// ([`crate::identity::sequence_fingerprint`] puts it in the tuple by default),
/// and the *context* — the ref — is what separates one branch's instance from
/// another's. So the pattern key names the pattern and nothing else; folding
/// the branch in here would re-mint the identity on a rename, which is exactly
/// the churn CLOUD-123 exists to prevent.
const PATTERN_KEY: &str = "completion-signaled-unlanded";

/// Which typed field carried the completion signal.
///
/// Recorded because the two producers degrade differently — a host that runs no
/// Stop hook still ends turns — so a reader diagnosing a quiet detector needs
/// to know which one answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Marker {
    /// A turn the model ended of its own accord.
    ///
    /// The only marker, since CLOUD-887 removed `StopHook`: a hook run is
    /// machinery observing a moment and never the model asserting anything, so
    /// there is one record in the stream that is the model speaking and this is
    /// it. The enum stays an enum rather than collapsing to a unit, because the
    /// question "what kind of claim was this" is the right shape even with one
    /// answer today — and a second honest producer (a host that spells an
    /// explicit completion event the model emits) would be a variant here.
    TurnEnd,
}

impl Marker {
    /// The stable token a report names this marker by.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Marker::TurnEnd => "turn-end",
        }
    }
}

/// A completion signal, as a pointer.
///
/// Carries a line number and a token — never the record that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Signal {
    /// 1-based transcript line.
    pub line: usize,
    /// Which typed field said so.
    pub marker: Marker,
}

/// What the conjunction resolved to.
///
/// Four values, and the fourth is the point. `NotComputable` is not a pass:
/// where no landing target resolves, the engine did not look, and reading that
/// silence as "landed" is the fail-open [`Observation::NotObserved`] exists to
/// prevent (`findings.rs`'s "observed zero is not the same as not observed").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Signalled done, and the work is not accounted for on the target.
    Raised {
        /// Where the signal was, as a pointer.
        signal: Signal,
        /// How many head-side commits have no patch-id equivalent. A count,
        /// never the SHAs.
        unaccounted: usize,
    },
    /// Signalled done, and every commit is accounted for. The self-clearing
    /// half: this is what a raised finding resolves to once the work lands.
    Cleared,
    /// No completion signal — the session declared no stopping point, so the
    /// conjunction is false for a reason that says nothing about landedness.
    NotSignaled,
    /// Landedness could not be established.
    NotComputable {
        /// Why, as a fixed token — never a path and never an error string.
        reason: &'static str,
    },
}

/// The token a landing target that does not resolve is reported under.
///
/// A fixed string rather than a formatted one: it reaches a report, and §6's
/// byte-stability is easier to hold when there is nothing in it to vary.
pub const NO_TARGET: &str = "no landing target resolved";

impl Outcome {
    /// The stable token a report names this outcome by.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Outcome::Raised { .. } => "raised",
            Outcome::Cleared => "cleared",
            Outcome::NotSignaled => "not-signaled",
            Outcome::NotComputable { .. } => "not-computable",
        }
    }

    /// What this outcome writes to the store, or `None` for "write nothing".
    ///
    /// The mapping is the whole self-clearing contract, so it lives here beside
    /// the type rather than in the caller:
    ///
    /// | Outcome | Observation |
    /// | --- | --- |
    /// | `Raised` | `Observed(1)` |
    /// | `Cleared` | `Observed(0)` — resolves an open finding |
    /// | `NotSignaled` | nothing |
    /// | `NotComputable` | `NotObserved(RuleSkipped)` — **holds**, never clears |
    ///
    /// `NotSignaled` writes nothing rather than clearing, and the distinction
    /// is load-bearing: a session that is still running has declared no
    /// stopping point, and resolving an open finding on that silence would let
    /// a mid-flight scan clear an incident nobody addressed.
    #[must_use]
    pub const fn observation(&self) -> Option<Observation> {
        match self {
            Outcome::Raised { .. } => Some(Observation::Observed(1)),
            Outcome::Cleared => Some(Observation::Observed(0)),
            Outcome::NotSignaled => None,
            Outcome::NotComputable { .. } => {
                Some(Observation::NotObserved(NotObserved::RuleSkipped))
            }
        }
    }

    /// The signal's pointer, where the outcome has one.
    #[must_use]
    pub const fn signal(&self) -> Option<Signal> {
        match self {
            Outcome::Raised { signal, .. } => Some(*signal),
            _ => None,
        }
    }
}

/// Whether a turn-end reason is a completion.
///
/// The token set, declared once and here rather than in
/// [`crate::transcript`]: that module owns the *vocabulary*, this one owns
/// which members of it mean "done". `ToolUse` is the model continuing and
/// `Other` covers truncation and anything a later host ships — neither is a
/// turn the model chose to end.
const fn is_completion(reason: StopReason) -> bool {
    matches!(reason, StopReason::EndTurn | StopReason::StopSequence)
}

/// The session's completion signal, if it declared one.
///
/// **The last marker with no tool call after it.** Both halves matter. "Last",
/// because a session that signalled done and then kept working has not stopped
/// there. "No tool call after it", because that is what separates a completed
/// session from a transcript captured mid-turn — and without it the predicate
/// would fire on every session that ever paused, which is the false-positive
/// rate that gets a detector switched off.
#[must_use]
pub fn signal(stream: &Stream) -> Option<Signal> {
    let mut latest = None;
    for record in &stream.records {
        match &record.event {
            Event::TurnEnd(reason) if is_completion(*reason) => {
                latest = Some(Signal {
                    line: record.line,
                    marker: Marker::TurnEnd,
                });
            }
            // Work after the marker retracts it. A turn that ended to make a
            // tool call retracts it too: the model said it was continuing. A
            // USER TURN retracts as well (CLOUD-887): the claim belonged to the
            // episode the user has now continued past, and holding it across the
            // boundary is what let one turn's marker answer for every turn after
            // it.
            Event::ToolCall { .. } | Event::TurnEnd(_) | Event::Turn(..) => latest = None,
            // A HOOK RUN IS NEVER A CLAIM (CLOUD-887), and this arm is where that
            // is decided.
            //
            // It used to mint `Marker::StopHook` from any Stop-family hook
            // record. `transcript.rs` builds one of those from ANY host-recorded
            // hook run carrying an event and an exit code — whoever registered
            // it, whatever it returned — and this repository registers a hook on
            // the Stop event that ran on every single turn. So the conjunct
            // CLOUD-97 specified as "the model declared done" was satisfied by
            // Batten's own bookkeeping, on 100% of turns, and
            // `completion.unlanded` collapsed to `¬landed` — true for a feature
            // branch's entire life. The detector's own firing was its input.
            //
            // THE NARROWING IS BROADER THAN "EXCLUDE OUR OWN", deliberately.
            // Identifying Batten's registration by name would leave a
            // third-party Stop hook minting claims, and would break the moment
            // the name changed. The honest predicate is the general one: a hook
            // run is machinery observing a moment, never the model asserting
            // anything about it. The claim now comes from `StopReason` alone —
            // the model speaking — which is the only record in the stream that
            // is the model speaking.
            //
            // The cost is stated rather than buried: a host that records no stop
            // reason now yields NO claim rather than a claim per hook run. That
            // is the correct three-valued answer — "could not look", not
            // "declared done" — and it is strictly better than a constant, which
            // is what the old arm produced.
            Event::HookDecision { .. } | Event::ToolResult { .. } => {}
        }
    }
    latest
}

/// Join the signal to the landing verdict.
///
/// Pure over values: `landing` is `None` for "nobody could ask", which is the
/// [`Outcome::NotComputable`] arm rather than a pass. The order of the two
/// tests is deliberate — an unsignalled session is [`Outcome::NotSignaled`]
/// **even when landedness is unknown**, because the conjunction is already
/// false and reporting "could not look" about a rule that had nothing to look
/// for would hold a finding on a session that never declared anything.
#[must_use]
pub fn assess(signal: Option<Signal>, landing: Option<&Landing>) -> Outcome {
    let Some(signal) = signal else {
        return Outcome::NotSignaled;
    };
    let Some(landing) = landing else {
        return Outcome::NotComputable { reason: NO_TARGET };
    };
    if landing.is_landed() {
        return Outcome::Cleared;
    }
    Outcome::Raised {
        signal,
        unaccounted: landing.unlanded().len(),
    }
}

/// The identity this detector's findings are keyed by.
///
/// [`crate::identity::FindingKind::Sequence`], which is the kind reserved for
/// exactly this class — a pattern over a session's event order rather than a
/// span in a file — and which the drain's scope filter bypasses
/// unconditionally, because a done-but-not-landed finding attaches to no
/// changed file by construction.
#[must_use]
pub fn identity(session: Option<&str>) -> crate::identity::StoredIdentity {
    crate::identity::StoredIdentity::new(
        crate::identity::FindingKind::Sequence,
        crate::identity::sequence_fingerprint(RULE_ID, PATTERN_KEY, session),
    )
}

/// Why no argv the engine may name fixes this.
///
/// The fix is "land the work", and the command that does it is a consumer's
/// (`rule 1`: no consumer-specific identifier may appear in the crate). So the
/// remediation is a **stated** reason naming the target ref — a pointer the
/// config or the remote already declares — rather than an invented command or
/// an absent field, which `findings::FindingRecord::is_emittable` refuses.
#[must_use]
pub fn no_fix_reason(target: &str) -> String {
    format!(
        "the session signalled done with commits that have no patch-id equivalent on {target}; \
         landing them clears this finding on the next evaluation, and no command this engine \
         can name lands work for a consumer"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::transcript::parse;

    const USER: &str = r#"{"message":{"role":"user","content":"do it"}}"#;
    const DONE: &str = r#"{"message":{"role":"assistant","content":[],"stop_reason":"end_turn"}}"#;
    const CALLING: &str = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{}}],"stop_reason":"tool_use"}}"#;
    const STOP_HOOK: &str =
        r#"{"attachment":{"type":"hook_success","hookEvent":"Stop","exitCode":0}}"#;

    fn signal_of(body: &str) -> Option<Signal> {
        signal(&parse(body, "fixture").expect("fixture parses"))
    }

    #[test]
    fn a_turn_the_model_ended_is_a_completion_signal() {
        let found = signal_of(&format!("{USER}\n{CALLING}\n{DONE}")).expect("signalled");
        assert_eq!(found.marker, Marker::TurnEnd);
        assert_eq!(found.line, 3);
    }

    #[test]
    fn a_stop_hook_record_is_not_a_completion_signal() {
        // THE DECISIVE CASE (CLOUD-887). This asserted the opposite, and that
        // assertion was the tautology: `transcript.rs` mints a `HookDecision`
        // from ANY host-recorded hook run, this repository registers a hook on
        // the Stop event, and it ran on every single turn — so the conjunct
        // CLOUD-97 specified as "the model declared done" was satisfied by
        // Batten's own bookkeeping and `completion.unlanded` collapsed to
        // `¬landed`.
        //
        // A hook run is machinery observing a moment. Only the model can claim.
        // Fails by restoring the `HookDecision` arm in `signal`.
        assert!(signal_of(&format!("{USER}\n{STOP_HOOK}")).is_none());
    }

    #[test]
    fn no_hook_record_at_any_event_is_a_completion_signal() {
        // The narrowing is general rather than "exclude our own": a third-party
        // Stop hook is no more the model speaking than Batten's is, and matching
        // on a registration's name would break the moment the name changed.
        for event in ["Stop", "TaskCompleted", "PreToolUse", "SessionStart"] {
            let record = format!(
                r#"{{"attachment":{{"type":"hook_success","hookEvent":"{event}","exitCode":0}}}}"#
            );
            assert!(
                signal_of(&record).is_none(),
                "a {event} hook run is bookkeeping, not a claim"
            );
        }
    }

    #[test]
    fn a_user_turn_retracts_a_claim_the_previous_episode_made() {
        // CLOUD-887's open sub-decision, taken: the claim belonged to the
        // episode the user has now continued past. Holding it across the
        // boundary is what let one turn's marker answer for every turn after it.
        assert!(signal_of(&format!("{DONE}\n{USER}")).is_none());
        // And the claim still stands when nothing followed it.
        assert!(signal_of(&format!("{USER}\n{DONE}")).is_some());
    }

    #[test]
    fn a_transcript_captured_mid_turn_has_not_signalled() {
        // The conjunct that stops this firing on every session that paused: the
        // marker is retracted by work that followed it.
        assert!(signal_of(&format!("{USER}\n{DONE}\n{CALLING}")).is_none());
    }

    #[test]
    fn a_turn_that_ended_to_call_a_tool_is_not_a_signal() {
        assert!(signal_of(&format!("{USER}\n{CALLING}")).is_none());
    }

    #[test]
    fn truncation_is_not_a_completion() {
        let truncated =
            r#"{"message":{"role":"assistant","content":[],"stop_reason":"max_tokens"}}"#;
        assert!(signal_of(truncated).is_none());
    }

    #[test]
    fn the_last_marker_wins_and_a_later_one_moves_the_pointer() {
        let body = format!("{DONE}\n{CALLING}\n{DONE}");
        let found = signal_of(&body).expect("signalled");
        assert_eq!(found.line, 3, "the pointer names the marker that stands");
    }

    #[test]
    fn assess_is_total_over_the_four_outcomes() {
        let signal = Signal {
            line: 7,
            marker: Marker::TurnEnd,
        };
        assert_eq!(assess(None, None), Outcome::NotSignaled);
        assert_eq!(
            assess(Some(signal), None),
            Outcome::NotComputable { reason: NO_TARGET }
        );
        // The two landed arms need a `Landing`, which only a repository can
        // build, so they are asserted end to end in
        // `tests/done_not_landed.rs` rather than mocked here.
    }

    #[test]
    fn an_unsignalled_session_is_not_signalled_even_when_landedness_is_unknown() {
        // Order of the two tests: the conjunction is already false, so
        // reporting "could not look" would hold a finding on a session that
        // declared nothing.
        assert_eq!(assess(None, None), Outcome::NotSignaled);
    }

    #[test]
    fn the_observation_mapping_never_clears_on_a_silence() {
        assert_eq!(
            Outcome::Raised {
                signal: Signal {
                    line: 1,
                    marker: Marker::TurnEnd
                },
                unaccounted: 2,
            }
            .observation(),
            Some(Observation::Observed(1))
        );
        assert_eq!(
            Outcome::Cleared.observation(),
            Some(Observation::Observed(0))
        );
        assert_eq!(Outcome::NotSignaled.observation(), None);
        assert_eq!(
            Outcome::NotComputable { reason: NO_TARGET }.observation(),
            Some(Observation::NotObserved(NotObserved::RuleSkipped)),
            "not-computable must hold, never resolve"
        );
    }

    #[test]
    fn the_identity_separates_sessions_and_survives_a_second_read() {
        let one = identity(Some("s-1"));
        let two = identity(Some("s-2"));
        assert_ne!(one.fingerprint, two.fingerprint);
        assert_eq!(one.fingerprint, identity(Some("s-1")).fingerprint);
        assert_eq!(
            one.kind(),
            Some(crate::identity::FindingKind::Sequence),
            "the drain's scope filter reads the kind off the stored version"
        );
    }

    #[test]
    fn the_no_fix_reason_names_the_target_and_no_consumer_command() {
        let reason = no_fix_reason("refs/remotes/origin/main");
        assert!(reason.contains("refs/remotes/origin/main"), "{reason}");
        assert!(
            !reason.contains("mise") && !reason.contains("git push"),
            "a consumer's command must not appear in the crate: {reason}"
        );
    }
}
