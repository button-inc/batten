//! Whether an issue is pullable, and the receipt that records the pull
//! (CLOUD-272, CLOUD-431; ported from `mise-tasks/claim-check.sh` by CLOUD-1121).
//!
//! The tracker's automation fires on the PR event — the END of the work — so
//! nothing reserves an issue at the moment somebody starts it. What that costs,
//! measured rather than hypothesised: CLOUD-49 went In Progress at 04:29:34, a
//! second session started writing it six minutes later, and the result was
//! thrown away. The board carried the claim the whole time; nothing made that
//! session read it.
//!
//! This is that read, given an exit code and a receipt.
//!
//! ## Agents fetch, gates decide
//!
//! No tracker credential exists here, so this is a pure function of the payloads
//! its caller supplies — no network, and therefore nothing that can hang,
//! rate-limit, or fail differently in a sandbox than in CI. Since CLOUD-1121 the
//! caller can resolve those payloads from the capture store by key
//! ([`crate::capture::find`]) instead of piping them, so the bytes never have to
//! enter an agent's context at all.
//!
//! ## Two questions, and conflating them is how the hole shipped
//!
//! [`Competitor`] rules detect **somebody else**: already In Progress, already
//! assigned, already carrying a live pull request. Every one reads "clear" when
//! nobody else is involved, so all three are blind by construction to a SOLE
//! agent moving too fast.
//!
//! [`Sequence`] rules answer the other question — **was this story refined
//! before the session implementing it** (CLOUD-431). Measured on CLOUD-427: an
//! agent asked to discuss a design instead filed the issue, wrote its own Ready
//! block, moved it Todo, piped a hand-written payload to this gate, took the
//! receipt, and implemented ~600 lines. Every guard that fired gated the SHAPE
//! of an action; none gated the SEQUENCE, and against a self-minted receipt "the
//! gates are your authorization" resolves to "I authorized myself".
//!
//! **The takeover clears the first set and never the second** (CLOUD-816). They
//! shared a counter once, so `--takeover` — documented for "the competitor is
//! this branch" — also cleared `refined-this-session`, which is the whole of
//! CLOUD-431. Measured on a payload with no competitor at all: without the flag
//! the gate refused on the sequence rule; with it the gate exited 0 and minted a
//! receipt.

use std::path::Path;

use crate::Result;
use crate::error::UsageError;

/// A refusal: which issue, and which rule.
///
/// **Pointer-only** (rule 4): the issue key, the rule id, and a PR number where
/// there is one. Never a body and never a title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The issue this is about.
    pub id: String,
    /// The rule id plus its parenthesised detail.
    pub rule: String,
    /// Whether a takeover clears it. [`Sequence`] rules do not.
    pub kind: Kind,
}

/// Which question a refusal answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Somebody else is on it. Cleared by a deliberate takeover.
    Competitor,
    /// The story was not refined before the session implementing it. **Never**
    /// cleared by a takeover — that flag answers a different question.
    Sequence,
}

/// One issue, as much of it as this gate reads.
///
/// **The entry contract is what EVERY issue needs: `id` and `status`**
/// (CLOUD-526). `description` is demanded by the one rule that reads it, at its
/// own site, by name — three of the four rules decide from `status`, `assignee`
/// and `attachments` and never look at the body, and demanding the largest field
/// on the row for all of them is what made the common refusals cost a full
/// re-typed description to reach.
///
/// `assignee` is deliberately not required, and that is a fact about the tracker
/// rather than a softening: it omits the key entirely for an unassigned issue,
/// so requiring it would refuse the very payloads the `assigned` rule exists to
/// pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// The issue key.
    pub id: String,
    /// The column it sits in.
    pub status: String,
    /// Whether anyone's name is on it.
    ///
    /// Deliberately NOT "assigned to someone else", because in this workspace it
    /// cannot be: every agent authenticates as the same tracker user, so self and
    /// other are indistinguishable in the payload. Reporting a name comparison
    /// would be a check that looks like it discriminates and does not.
    pub assigned: bool,
    /// A **live** pull request attached to it, if any — the URL's number.
    pub live_pr: Option<String>,
    /// The body, when the caller supplied one.
    pub description: Option<String>,
}

impl Issue {
    /// Parse one payload.
    ///
    /// # Errors
    ///
    /// [`UsageError`] when `id` or `status` is missing — the entry contract.
    pub fn parse(value: &serde_json::Value) -> Result<Self> {
        let field = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        let id = field("id")
            .ok_or_else(|| {
                UsageError::raise(
                    "claim: not a set of get_issue payloads (need id and status per issue)"
                        .to_owned(),
                )
            })?
            .to_owned();
        let status = value
            .get("status")
            .and_then(|s| {
                s.as_str().map(str::to_owned).or_else(|| {
                    s.get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
            })
            .ok_or_else(|| {
                UsageError::raise(format!(
                    "claim: {id} carries no status — the entry contract is id and status"
                ))
            })?;
        Ok(Self {
            id,
            status,
            assigned: value.get("assignee").is_some_and(|value| !value.is_null()),
            live_pr: live_pull_request(value),
            description: value
                .get("description")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        })
    }
}

/// The first attachment that is a **live** GitHub pull request.
///
/// LIVE, NOT MERELY PRESENT (CLOUD-520). This rule catches somebody who
/// published before the column moved, which is a claim about an OPEN pull
/// request. A MERGED one is the opposite signal — evidence that work finished —
/// and refusing on it makes an issue released back to Todo permanently
/// unpullable. Measured on CLOUD-479: Todo, unassigned, its own body inviting
/// the next taker, refused on a PR that had merged the day before.
///
/// **The state comes from the CALLER**, and that is forced rather than chosen:
/// the tracker's attachment objects carry `id`, `title`, `subtitle` and `url`
/// and no state at all (measured 2026-08-19), and this gate has no credential to
/// look one up. **Absent refuses**, so a caller supplying nothing gets exactly
/// the old behaviour — this narrowing can only ever turn a false refusal into a
/// pull, never a real competitor into a silent pass. Malformed refuses too: a
/// parse failure must not become a pass.
fn live_pull_request(value: &serde_json::Value) -> Option<String> {
    let attachments = value.get("attachments")?.as_array()?;
    attachments.iter().find_map(|attachment| {
        let url = attachment.get("url").and_then(serde_json::Value::as_str)?;
        if !is_pull_request_url(url) {
            return None;
        }
        let state = attachment
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let merged = attachment.get("merged") == Some(&serde_json::Value::Bool(true));
        if state == "merged" || state == "closed" || merged {
            return None;
        }
        Some(url.rsplit('/').next().unwrap_or(url).to_owned())
    })
}

/// Whether a URL is a GitHub pull request.
///
/// Matched on the URL SHAPE rather than the attachment title, which is free text
/// a human wrote.
fn is_pull_request_url(url: &str) -> bool {
    let Some(rest) = url.split_once("github.com/").map(|(_, rest)| rest) else {
        return false;
    };
    let Some((_, tail)) = rest.split_once("/pull/") else {
        return false;
    };
    let number: String = tail.chars().take_while(char::is_ascii_digit).collect();
    !number.is_empty()
}

/// What the caller asked for, beyond the payloads.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// The deliberate takeover: claim over the competitor refusals and record
    /// what was overridden.
    pub takeover: bool,
    /// "I refined this story in my own session, on purpose" — the one way a
    /// human clears the sequence rules, and it says so in the receipt.
    pub bypass_sequence: bool,
}

/// What the gate decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Every refusal, in the order the issues were judged.
    pub refusals: Vec<Refusal>,
    /// What a takeover overrode, for the receipt to name rather than merely
    /// admit that something was overridden.
    pub overridden: Vec<String>,
}

impl Verdict {
    /// Whether a receipt may be minted.
    ///
    /// A [`Kind::Sequence`] refusal survives a takeover, which is the arm that
    /// makes this module's header true rather than merely stated.
    #[must_use]
    pub fn pullable(&self, request: &Request) -> bool {
        self.refusals
            .iter()
            .all(|refusal| request.takeover && matches!(refusal.kind, Kind::Competitor))
    }
}

/// Judge a set of issues.
///
/// The competitor rules run first and their answer is final for that issue: if
/// any refused, no reading of the body can make it pullable, so the body is
/// never demanded (CLOUD-526). That also keeps them REACHABLE — without the
/// short-circuit an assigned issue sent without a body would fall through to the
/// readiness rule, be reported as unreadable, and lose the `assigned` refusal it
/// had already earned behind "could not look".
///
/// # Errors
///
/// [`UsageError`] when an issue reaches the readiness rule carrying no body.
/// Refused by name rather than by the readiness predicate's own message, which
/// would send the reader to the wrong question.
pub fn judge(issues: &[Issue], request: &Request, root: &Path) -> Result<Verdict> {
    let mut verdict = Verdict::default();
    for issue in issues {
        let before = verdict.refusals.len();

        if issue.status != "Todo" {
            verdict.refusals.push(Refusal {
                id: issue.id.clone(),
                rule: format!("not-todo (in {})", issue.status),
                kind: Kind::Competitor,
            });
            continue;
        }
        if issue.assigned {
            verdict.refusals.push(Refusal {
                id: issue.id.clone(),
                rule: "assigned".to_owned(),
                kind: Kind::Competitor,
            });
        }
        if let Some(number) = &issue.live_pr {
            verdict.refusals.push(Refusal {
                id: issue.id.clone(),
                rule: format!(
                    "has-pr ({number}) — if it is merged or closed, say so on the attachment \
                     (\"state\": \"merged\") and re-run"
                ),
                kind: Kind::Competitor,
            });
        }

        // Skipped wholesale under the bypass: both rules below are about the
        // SEQUENCE of refinement, and the bypass is the one way a human says "I
        // refined it just now, on purpose".
        if request.bypass_sequence {
            continue;
        }
        // The cheap rules have had their say. If any refused, this issue is not
        // pullable and the body cannot change that.
        if verdict.refusals.len() != before {
            continue;
        }

        let Some(description) = &issue.description else {
            return Err(UsageError::raise(format!(
                "claim: {} carries no description, and nothing else has refused it — the \
                 not-ready rule decides on the body. Re-fetch this one issue and try again.",
                issue.id
            )));
        };
        if !is_ready(issue, description, root)? {
            verdict.refusals.push(Refusal {
                id: issue.id.clone(),
                rule: "not-ready".to_owned(),
                kind: Kind::Sequence,
            });
        }
    }
    verdict.overridden = if request.takeover {
        verdict
            .refusals
            .iter()
            .filter(|refusal| matches!(refusal.kind, Kind::Competitor))
            .map(|refusal| format!("{} {}", refusal.id, refusal.rule))
            .collect()
    } else {
        Vec::new()
    };
    Ok(verdict)
}

/// Whether the issue's Ready block satisfies the checkable clauses.
///
/// Delegates to [`crate::ready`] rather than re-reading the grammar: that module
/// is the single authority the shell program was, and a second reading of it is
/// a copy that drifts silently — the grammar is subtle enough that CLOUD-290's
/// whole-code-span anchor was found only by experiment.
///
/// # Errors
///
/// Propagates the readiness predicate's own could-not-read.
fn is_ready(issue: &Issue, description: &str, root: &Path) -> Result<bool> {
    let payload = crate::ready::Payload {
        id: issue.id.clone(),
        description: description.to_owned(),
        // The readiness predicate's own cross-checks need the relations, which
        // this gate does not carry. It reports them as could-not-look rather than
        // as violations, so a claim is never refused for a gap in what the caller
        // fetched — CLOUD-679's split, honoured across the module boundary.
        relations_present: false,
        blocked_by: Vec::new(),
        all_relations: Vec::new(),
    };
    let report = crate::ready::lint(&payload, root)?;
    Ok(report.findings.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(id: &str, status: &str) -> Issue {
        Issue {
            id: id.to_owned(),
            status: status.to_owned(),
            assigned: false,
            live_pr: None,
            description: None,
        }
    }

    #[test]
    fn a_merged_pull_request_is_a_predecessor_rather_than_a_competitor() {
        // CLOUD-520, measured on CLOUD-479: Todo, unassigned, its own body
        // inviting the next taker, refused on a PR that had merged the day
        // before. A merged PR is evidence the work finished, not that it is in
        // flight, and refusing on it makes a released issue permanently
        // unpullable.
        let merged = serde_json::json!({
            "id": "CLOUD-1", "status": "Todo",
            "attachments": [{ "url": "https://github.com/o/r/pull/376", "state": "merged" }]
        });
        let Ok(parsed) = Issue::parse(&merged) else {
            panic!("a well-formed payload must parse")
        };
        assert_eq!(parsed.live_pr, None);
    }

    #[test]
    fn an_open_pull_request_still_refuses_and_an_absent_state_refuses_too() {
        // The narrowing must only ever turn a false refusal into a pull, never a
        // real competitor into a silent pass — so absent refuses.
        for attachment in [
            serde_json::json!({ "url": "https://github.com/o/r/pull/9", "state": "open" }),
            serde_json::json!({ "url": "https://github.com/o/r/pull/9" }),
            serde_json::json!({ "url": "https://github.com/o/r/pull/9", "state": "nonsense" }),
        ] {
            let value = serde_json::json!({
                "id": "CLOUD-1", "status": "Todo", "attachments": [attachment]
            });
            let Ok(parsed) = Issue::parse(&value) else {
                panic!("a well-formed payload must parse")
            };
            assert_eq!(
                parsed.live_pr.as_deref(),
                Some("9"),
                "only an explicit merged/closed reading may stand down"
            );
        }
    }

    #[test]
    fn a_takeover_clears_a_competitor_and_never_a_sequence_refusal() {
        // CLOUD-816. The two shared a counter once, so `--takeover` cleared
        // `refined-this-session` — the whole of CLOUD-431 — on a payload with no
        // competitor at all.
        let verdict = Verdict {
            refusals: vec![
                Refusal {
                    id: "CLOUD-1".to_owned(),
                    rule: "assigned".to_owned(),
                    kind: Kind::Competitor,
                },
                Refusal {
                    id: "CLOUD-1".to_owned(),
                    rule: "not-ready".to_owned(),
                    kind: Kind::Sequence,
                },
            ],
            overridden: Vec::new(),
        };
        let takeover = Request {
            takeover: true,
            bypass_sequence: false,
        };
        assert!(
            !verdict.pullable(&takeover),
            "a takeover must not clear a sequence refusal"
        );

        let competitor_only = Verdict {
            refusals: vec![Refusal {
                id: "CLOUD-1".to_owned(),
                rule: "assigned".to_owned(),
                kind: Kind::Competitor,
            }],
            overridden: Vec::new(),
        };
        assert!(competitor_only.pullable(&takeover));
        assert!(!competitor_only.pullable(&Request::default()));
    }

    #[test]
    fn a_status_that_is_not_todo_short_circuits_the_rest() {
        // The body is never demanded once a competitor rule has answered, which
        // is CLOUD-526's projection: three of the four rules never look at it.
        let issues = [issue("CLOUD-1", "In Progress")];
        let Ok(verdict) = judge(&issues, &Request::default(), Path::new(".")) else {
            panic!("a non-Todo issue needs no body")
        };
        assert_eq!(verdict.refusals.len(), 1);
        assert!(verdict.refusals[0].rule.starts_with("not-todo"));
    }

    #[test]
    fn an_unrefusable_issue_with_no_body_is_a_usage_error_rather_than_a_pass() {
        // Reaching the readiness rule with nothing to read is could-not-look, and
        // it is refused BY NAME so the reader is sent to the right question.
        let issues = [issue("CLOUD-1", "Todo")];
        let answer = judge(&issues, &Request::default(), Path::new("."));
        assert!(
            answer.is_err(),
            "a bodyless payload must not read as pullable"
        );
    }
}
