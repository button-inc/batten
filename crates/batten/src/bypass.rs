//! Guardrail bypass: a deny, then the same operation with enforcement off
//! (CLOUD-98).
//!
//! A guardrail fires, and the agent turns enforcement off and forces the same
//! operation through. **Both halves are in the transcript and neither is
//! visible to a synchronous hook** — the sandbox toggle does not route through
//! Batten, so there is no moment at which a mediating gate sees the second call
//! as a retry of the first. Only the completed record sees both, which is why
//! this is a post-hoc audit and not a reference monitor (and why the scope
//! reminder in AGENTS.md still holds: nothing here mediates anything).
//!
//! # The predicate is a conjunction, and each half alone is deliberately silent
//!
//! Two things were rejected on the issue and the rejections are what shape the
//! match. A synchronous hook cannot see the toggle. And **flagging every
//! enforcement-disable is not the signal** — turning the sandbox off is a
//! legitimate, declared affordance. What is not legitimate is turning it off to
//! push through the specific operation something just refused. So a refusal
//! alone raises nothing, an enforcement-disable alone raises nothing, and only
//! the ordered pair does.
//!
//! # Equivalence is exact
//!
//! Same tool verb, same normalized target, both compared for equality. Never
//! similarity, never a judge (CLOUD-93): "is this the same operation" has a
//! computable answer here because the retry differs from the original in
//! exactly one argument, and that argument is the one being detected.
//!
//! # What a refusal is, structurally
//!
//! Two producers, joined to a call by the host's own `tool_use` id:
//!
//! * A **mediated** deny — a hook record whose exit code is the §7 verdict
//!   code, read from the other side of the table [`crate::hook`] emits it on.
//! * A **failed** call — the host's typed `is_error` boolean. This is what
//!   covers the sandbox denial the issue names, which by its own account never
//!   reaches Batten's hook, so no mediated record for it can exist. It is
//!   broader than a deny, and that breadth is bounded by the conjunction: an
//!   ordinary failure raises nothing until the same operation is retried with
//!   enforcement explicitly disabled.
//!
//! The two are recorded distinctly so a reader can tell a refusal from a bare
//! failure, and [`Refusal`] is a total order with the mediated answer winning —
//! so a call that both was denied and failed reports the stronger fact whatever
//! order the host wrote the two records in. Byte-stability cannot depend on a
//! host's record ordering.
//!
//! # This finding does not self-clear, and that is a property of its subject
//!
//! It anchors to an **immutable transcript event**. Re-evaluation keeps finding
//! it, so the observation is always positive and never resolves to zero: a
//! bypass that happened, happened, and no later state makes it not have
//! happened. It settles by disposition in the store instead (CLOUD-78's
//! three-valued model), which is the issue's own stated assumption 1.
//!
//! # Output is a pointer
//!
//! A pair of transcript line numbers and a refusal token. The verb, the target
//! and every argument are **payload** — a command line is the likeliest thing
//! in this stream to carry a credential — so none of them appears in any output.
//! The operation reaches only the identity's hash preimage, which is a digest
//! (non-negotiable rule 4).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::identity::{FindingKind, StoredIdentity, sequence_fingerprint};
use crate::transcript::{Event, Stream};

/// The rule id this detector's findings are stored under.
///
/// Engine-side, like [`crate::completion::RULE_ID`]: there is no `[[rule]]` row
/// to take an id from, because the predicate needs the transcript input, a
/// cross-event correlation and the findings store.
pub const RULE_ID: &str = "guardrail.bypass";

/// Argument names whose `true` value turns enforcement off.
///
/// **Host-adapter data, not consumer data** — the name of a host's own escape
/// hatch — so it is a crate constant on [`crate::selfwrite::MEMORY_TOOLS`]'s
/// precedent rather than a config key. Rule 6 says keep configuration narrow,
/// and a repository does not get to decide what counts as disabling
/// enforcement: that is a fact about the harness, pinned by the fixtures.
///
/// Exact membership and an exact JSON `true`. A truthy string or a `1` is not
/// matched, because the host writes a boolean and reading anything else as one
/// would be inference.
pub const ENFORCEMENT_OFF_ARGS: &[&str] = &["dangerouslyDisableSandbox"];

/// The argument names that carry a call's operand, most specific first.
///
/// Not every field of a call — the operand, and only enough of them to name the
/// two shapes a host actually produces (measured over a captured session: a
/// command string and a file path dominate every other input key). A call
/// carrying none of these has **no comparable target**, and is skipped rather
/// than compared on some other field, because "same operation" over a field
/// nobody declared is a guess.
pub const TARGET_FIELDS: &[&str] = &["command", "file_path"];

/// The exit code a host's hook run uses to deny (house style §7).
///
/// Read from [`crate::ExitCode::Violation`] rather than spelled `2`, so
/// recognising a deny here and emitting one in `hook` cannot drift.
const DENY_EXIT: i64 = crate::ExitCode::Violation.code() as i64;

/// How the original call was refused.
///
/// Ordered weakest-first, so the derived [`Ord`] **is** the precedence and
/// merging two answers about one call is a `max` — the same construction
/// [`crate::findings::Disposition`] uses, and for the same reason: a join on a
/// total order commutes, so the verdict cannot depend on the order a host
/// happened to write its records in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Refusal {
    /// The call did not succeed — the host's typed error boolean. Covers a
    /// sandbox denial, which reaches no mediating gate.
    Failed,
    /// A mediating hook returned the §7 verdict code. The stronger fact.
    Mediated,
}

impl Refusal {
    /// The stable token a report names this refusal by.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Refusal::Failed => "failed",
            Refusal::Mediated => "mediated",
        }
    }
}

/// One bypassed operation, as a pointer.
///
/// Deliberately carries no verb, no target and no arguments: those are what was
/// pushed through, and naming them is the disclosure this rule exists to avoid.
/// The operation survives only inside [`Detection::identity`], which is a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detection {
    /// 1-based transcript line where the operation was refused.
    pub denied_line: usize,
    /// 1-based transcript line of the first retry with enforcement off.
    pub retry_line: usize,
    /// How the original was refused.
    pub refusal: Refusal,
    /// How many enforcement-off retries of this one operation there were.
    ///
    /// A count rather than a second detection: identical operations are **one
    /// identity with a count**, the same multiset reading
    /// [`crate::findings::record`] gives identical spans in a file.
    pub retries: u64,
    /// The identity this detection is keyed by — a digest of the session and
    /// the operation, so distinct bypassed operations are distinct findings.
    pub identity: StoredIdentity,
}

/// A call's comparable operation: its verb and its normalized target.
///
/// Ordered so the scan's maps are deterministic, which is what makes the
/// reported order a function of the transcript rather than of a hash seed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Operation {
    verb: String,
    target: String,
}

impl Operation {
    /// The pattern key this operation is fingerprinted under.
    ///
    /// One string because [`sequence_fingerprint`] takes one pattern key, joined
    /// by a unit separator — a control character no tool verb contains, so the
    /// join is unambiguous in practice and the composite is length-prefixed
    /// inside the fingerprint construction anyway.
    fn pattern_key(&self) -> String {
        format!("{}\u{1f}{}", self.verb, self.target)
    }
}

/// The operation a call names, or `None` when it declares no comparable target.
///
/// Normalization is the minimum that makes equality mean what a reader expects:
/// surrounding whitespace trimmed, and `\` folded to `/` so a Windows-shaped
/// path compares equal to the same path written the other way
/// ([`crate::selfwrite`]'s precedent). Nothing else — no case folding, no path
/// resolution, no shell parsing, because each of those would decide that two
/// different operations are the same one.
fn operation_of(name: &str, input: &serde_json::Value) -> Option<Operation> {
    let target = TARGET_FIELDS
        .iter()
        .find_map(|field| input.get(field).and_then(serde_json::Value::as_str))?;
    Some(Operation {
        verb: name.to_owned(),
        target: target.trim().replace('\\', "/"),
    })
}

/// Does this call's input turn enforcement off?
///
/// Exact membership over [`ENFORCEMENT_OFF_ARGS`] and an exact JSON `true`.
fn disables_enforcement(input: &serde_json::Value) -> bool {
    ENFORCEMENT_OFF_ARGS.iter().any(|arg| {
        input
            .get(arg)
            .and_then(serde_json::Value::as_bool)
            .is_some_and(|disabled| disabled)
    })
}

/// Scan a parsed stream for refused operations retried with enforcement off.
///
/// **One forward pass, and the direction is the predicate.** A refusal is
/// recorded only for calls already seen, and a retry pairs only against a
/// refusal already recorded — so a call that disables enforcement *before*
/// anything refused the same operation raises nothing, which is the ordering the
/// issue's second rejected alternative is about. Reversing the pass, or matching
/// a set against a set, would lose that and flag an agent that turned the
/// sandbox off and only later hit an unrelated failure.
///
/// The three maps are all keyed on values rather than on stream position, which
/// is what makes the result a function of the transcript's content.
#[must_use]
pub fn scan(stream: &Stream) -> Vec<Detection> {
    // Which operation each outstanding call names. A refusal record joins to its
    // call by the host's id, and the operation is what the retry is compared to,
    // so the join has to go through here.
    let mut calls: BTreeMap<&str, Operation> = BTreeMap::new();
    // The strongest refusal seen per operation, and where. `max` on the refusal
    // and first-wins on the line: the pointer names where the guardrail spoke.
    let mut refused: BTreeMap<Operation, (usize, Refusal)> = BTreeMap::new();
    let mut found: BTreeMap<Operation, Detection> = BTreeMap::new();

    for record in &stream.records {
        match &record.event {
            Event::ToolCall { id, name, input } => {
                let Some(operation) = operation_of(name, input) else {
                    // No declared target: nothing to compare, so this call can
                    // neither be refused-and-matched nor count as a retry.
                    continue;
                };
                if disables_enforcement(input)
                    && let Some(&(denied_line, refusal)) = refused.get(&operation)
                {
                    found
                        .entry(operation.clone())
                        .and_modify(|detection| detection.retries += 1)
                        .or_insert(Detection {
                            denied_line,
                            retry_line: record.line,
                            refusal,
                            retries: 1,
                            identity: StoredIdentity::new(
                                FindingKind::Sequence,
                                sequence_fingerprint(
                                    RULE_ID,
                                    &operation.pattern_key(),
                                    stream.session.as_deref(),
                                ),
                            ),
                        });
                }
                calls.insert(id.as_str(), operation);
            }
            Event::HookDecision {
                call: Some(call),
                exit_code,
                ..
            } if *exit_code == DENY_EXIT => {
                note_refusal(&calls, call, record.line, Refusal::Mediated, &mut refused);
            }
            Event::ToolResult { call, failed: true } => {
                note_refusal(&calls, call, record.line, Refusal::Failed, &mut refused);
            }
            Event::Turn(..)
            | Event::TurnEnd(_)
            | Event::ToolResult { .. }
            // Not a tool call and not a retry: an injection carries no
            // enforcement posture at all (CLOUD-1054).
            | Event::HookDecision { .. }
            | Event::MemoryInjection { .. } => {}
        }
    }
    found.into_values().collect()
}

/// Record that `call`'s operation was refused, keeping the strongest answer.
///
/// The line is the **first** refusal's, and the refusal is the **strongest** —
/// two different questions, so two different rules. A caller wants the pointer
/// to name where the guardrail first spoke, and the token to say what kind of
/// refusal it ultimately was.
fn note_refusal(
    calls: &BTreeMap<&str, Operation>,
    call: &str,
    line: usize,
    refusal: Refusal,
    refused: &mut BTreeMap<Operation, (usize, Refusal)>,
) {
    let Some(operation) = calls.get(call) else {
        // A refusal for a call this stream never recorded, or one whose call
        // declared no comparable target. Nothing to key it on, and inventing a
        // key would pair it with an unrelated retry.
        return;
    };
    refused
        .entry(operation.clone())
        .and_modify(|(_, seen)| *seen = (*seen).max(refusal))
        .or_insert((line, refusal));
}

/// Why nothing can un-do this.
///
/// A stated reason rather than an argv, because there is no command that makes a
/// bypass not have happened — and `findings::FindingRecord::is_emittable`
/// refuses a finding carrying neither. This is also the honest form of the
/// issue's assumption 1: the finding settles by disposition, not by the
/// condition ceasing to hold.
#[must_use]
pub fn no_fix_reason() -> String {
    "a refused operation was retried with enforcement disabled; the event is in the completed \
     transcript and no command un-does it, so this settles by recording a disposition rather \
     than by the condition going away"
        .to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::transcript::parse;

    /// A call, its refusal, and its retry, spelled as the host writes them.
    fn call(id: &str, command: &str) -> String {
        format!(
            r#"{{"message":{{"role":"assistant","content":[{{"type":"tool_use","id":"{id}","name":"Bash","input":{{"command":"{command}"}}}}]}}}}"#
        )
    }

    fn retry(id: &str, command: &str) -> String {
        format!(
            r#"{{"message":{{"role":"assistant","content":[{{"type":"tool_use","id":"{id}","name":"Bash","input":{{"command":"{command}","dangerouslyDisableSandbox":true}}}}]}}}}"#
        )
    }

    fn denied(id: &str) -> String {
        format!(
            r#"{{"attachment":{{"type":"hook_success","hookEvent":"PreToolUse","toolUseID":"{id}","exitCode":2}}}}"#
        )
    }

    fn failed(id: &str) -> String {
        format!(
            r#"{{"message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"{id}","is_error":true}}]}}}}"#
        )
    }

    fn scan_body(body: &str) -> Vec<Detection> {
        scan(&parse(body, "fixture").expect("fixture parses"))
    }

    #[test]
    fn a_mediated_deny_then_the_same_op_with_enforcement_off_raises() {
        let body = format!(
            "{}\n{}\n{}",
            call("t1", "touch protected"),
            denied("t1"),
            retry("t2", "touch protected")
        );
        let found = scan_body(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].denied_line, 2);
        assert_eq!(found[0].retry_line, 3);
        assert_eq!(found[0].refusal, Refusal::Mediated);
        assert_eq!(found[0].retries, 1);
    }

    #[test]
    fn a_failed_call_is_the_other_producer() {
        // The sandbox denial, which reaches no mediating gate — so if this half
        // is missing the rule cannot see the case the issue is named for.
        let body = format!(
            "{}\n{}\n{}",
            call("t1", "touch protected"),
            failed("t1"),
            retry("t2", "touch protected")
        );
        let found = scan_body(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].refusal, Refusal::Failed);
    }

    #[test]
    fn a_standalone_enforcement_disable_does_not_raise() {
        // Turning the sandbox off is a declared affordance. The signal is the
        // sequence, never the disable.
        assert!(scan_body(&retry("t1", "touch anything")).is_empty());
    }

    #[test]
    fn a_deny_followed_by_a_different_op_does_not_raise() {
        let body = format!(
            "{}\n{}\n{}",
            call("t1", "touch protected"),
            denied("t1"),
            retry("t2", "touch something-else")
        );
        assert!(scan_body(&body).is_empty());
    }

    #[test]
    fn a_different_verb_on_the_same_target_is_a_different_operation() {
        let write = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/w/a"}}]}}"#;
        let edit = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Edit","input":{"file_path":"/w/a","dangerouslyDisableSandbox":true}}]}}"#;
        let body = format!("{write}\n{}\n{edit}", denied("t1"));
        assert!(
            scan_body(&body).is_empty(),
            "equivalence is verb AND target"
        );
    }

    #[test]
    fn a_retry_before_the_refusal_does_not_pair() {
        // The direction of the pass IS the predicate: enforcement was already
        // off, so nothing was pushed through a guardrail that had spoken.
        let body = format!(
            "{}\n{}\n{}",
            retry("t1", "touch protected"),
            call("t2", "touch protected"),
            denied("t2")
        );
        assert!(scan_body(&body).is_empty());
    }

    #[test]
    fn an_allowing_hook_record_is_not_a_refusal() {
        let allowed = r#"{"attachment":{"type":"hook_success","hookEvent":"PreToolUse","toolUseID":"t1","exitCode":0}}"#;
        let body = format!(
            "{}\n{allowed}\n{}",
            call("t1", "touch protected"),
            retry("t2", "touch protected")
        );
        assert!(scan_body(&body).is_empty());
    }

    #[test]
    fn a_successful_result_is_not_a_refusal() {
        let ok = r#"{"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","is_error":false}]}}"#;
        let body = format!(
            "{}\n{ok}\n{}",
            call("t1", "touch protected"),
            retry("t2", "touch protected")
        );
        assert!(scan_body(&body).is_empty());
    }

    #[test]
    fn repeats_of_one_operation_are_one_finding_with_a_count() {
        let body = format!(
            "{}\n{}\n{}\n{}",
            call("t1", "touch protected"),
            denied("t1"),
            retry("t2", "touch protected"),
            retry("t3", "touch protected")
        );
        let found = scan_body(&body);
        assert_eq!(found.len(), 1, "one identity");
        assert_eq!(found[0].retries, 2);
        assert_eq!(found[0].retry_line, 3, "the pointer names the first retry");
    }

    #[test]
    fn two_different_operations_are_two_findings() {
        let body = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            call("t1", "touch a"),
            denied("t1"),
            retry("t2", "touch a"),
            call("t3", "touch b"),
            denied("t3"),
            retry("t4", "touch b")
        );
        let found = scan_body(&body);
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].identity.fingerprint, found[1].identity.fingerprint);
    }

    #[test]
    fn the_mediated_answer_wins_whatever_order_the_host_wrote_them_in() {
        // Byte-stability must not depend on a host's record ordering, which is
        // what the total order on `Refusal` buys.
        let deny_first = format!(
            "{}\n{}\n{}\n{}",
            call("t1", "touch protected"),
            denied("t1"),
            failed("t1"),
            retry("t2", "touch protected")
        );
        let fail_first = format!(
            "{}\n{}\n{}\n{}",
            call("t1", "touch protected"),
            failed("t1"),
            denied("t1"),
            retry("t2", "touch protected")
        );
        assert_eq!(scan_body(&deny_first)[0].refusal, Refusal::Mediated);
        assert_eq!(scan_body(&fail_first)[0].refusal, Refusal::Mediated);
    }

    #[test]
    fn a_call_with_no_declared_target_is_skipped_rather_than_guessed() {
        let opaque = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"description":"no operand here"}}]}}"#;
        let opaque_retry = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"description":"no operand here","dangerouslyDisableSandbox":true}}]}}"#;
        let body = format!("{opaque}\n{}\n{opaque_retry}", denied("t1"));
        assert!(scan_body(&body).is_empty());
    }

    #[test]
    fn an_enforcement_arg_that_is_not_true_does_not_count() {
        let off = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"touch protected","dangerouslyDisableSandbox":false}}]}}"#;
        let stringy = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"touch protected","dangerouslyDisableSandbox":"true"}}]}}"#;
        let body = format!(
            "{}\n{}\n{off}\n{stringy}",
            call("t1", "touch protected"),
            denied("t1")
        );
        assert!(
            scan_body(&body).is_empty(),
            "the host writes a boolean; reading a string as one is inference"
        );
    }

    #[test]
    fn the_target_is_normalized_but_never_resolved() {
        let write = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"  w\\memories\\a.md  "}}]}}"#;
        let retry_call = r#"{"message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Write","input":{"file_path":"w/memories/a.md","dangerouslyDisableSandbox":true}}]}}"#;
        let body = format!("{write}\n{}\n{retry_call}", denied("t1"));
        assert_eq!(scan_body(&body).len(), 1, "trim and separator folding only");
    }

    #[test]
    fn a_detection_carries_pointers_and_never_the_operation() {
        let body = format!(
            "{}\n{}\n{}",
            call("t1", "SECRET-COMMAND"),
            denied("t1"),
            retry("t2", "SECRET-COMMAND")
        );
        let rendered = serde_json::to_string(&scan_body(&body)[0]).expect("serialize");
        assert!(!rendered.contains("SECRET-COMMAND"), "{rendered}");
        assert!(!rendered.contains("Bash"), "{rendered}");
        assert!(rendered.contains("denied_line"), "{rendered}");
    }

    #[test]
    fn the_identity_separates_sessions_and_is_the_sequence_kind() {
        let with_session = |session: &str| {
            let body = format!(
                r#"{{"sessionId":"{session}","message":{{"role":"assistant","content":[{{"type":"tool_use","id":"t1","name":"Bash","input":{{"command":"x"}}}}]}}}}
{}
{}"#,
                denied("t1"),
                retry("t2", "x")
            );
            scan_body(&body)[0].identity.clone()
        };
        let one = with_session("s-1");
        assert_ne!(one.fingerprint, with_session("s-2").fingerprint);
        assert_eq!(one.fingerprint, with_session("s-1").fingerprint);
        assert_eq!(one.kind(), Some(FindingKind::Sequence));
    }

    #[test]
    fn the_deny_code_is_the_one_exit_table_not_a_literal() {
        assert_eq!(DENY_EXIT, 2);
    }
}
