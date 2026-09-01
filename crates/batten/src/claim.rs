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

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

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
pub fn judge(
    grammar: &crate::ready::Grammar,
    issues: &[Issue],
    request: &Request,
    root: &Path,
    receipts: Option<&Path>,
) -> Result<Verdict> {
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
        if !is_ready(grammar, issue, description, root)? {
            verdict.refusals.push(Refusal {
                id: issue.id.clone(),
                rule: "not-ready (the Ready block is refused — run `batten ready lint` on it)"
                    .to_owned(),
                kind: Kind::Sequence,
            });
            continue;
        }

        // OUTSIDE A CHECKOUT the question is not applicable rather than
        // unanswerable, and skipping it there closes no hole: the receipt is a
        // side effect of being in a clone, so a run from anywhere else mints
        // nothing for any reader to honour. Refusing would only break the
        // composability this gate and the board sweep share.
        let Some(receipts) = receipts else {
            continue;
        };
        if let Some(refusal) = sequence_refusal(issue, description, receipts)? {
            verdict.refusals.push(refusal);
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

/// The refinement-sequence verdict for one issue, read out of this clone's own
/// receipt store.
///
/// **This is the forgery-resistant half.** The payload is agent-supplied, so any
/// CONTENT claim in it can be authored by the thing being checked — the readiness
/// rule alone is a gate an agent satisfies by writing better prose. The baseline
/// is different in kind: a hash this clone wrote down BEFORE the body could be
/// rewritten, living under `$GIT_DIR`, so a restart cannot reset it. A
/// hand-edited payload defeats it, and that is fabrication rather than honest
/// error — outside the threat model, and recorded in the row's own history on the
/// tracker regardless.
///
/// # Errors
///
/// [`UsageError`] — could-not-look — when the receipt or its store EXISTS and
/// cannot be read. That is not a missing receipt: the file may be there and say
/// the body is unchanged, and collapsing the two is CLOUD-251's error one more
/// time.
fn sequence_refusal(issue: &Issue, description: &str, receipts: &Path) -> Result<Option<Refusal>> {
    // INSIDE a clone, a MISSING stamp is a REFUSAL rather than a pass. The
    // sequence question is answerable here and we simply cannot see the answer,
    // and a gate that silently clears everything it cannot see is the false green
    // this repository keeps re-meeting. The remedy is local and cheap — the
    // SessionStart hook writes it before it does anything else.
    if !receipts.join(SESSION_STAMP).exists() {
        return Ok(Some(Refusal {
            id: issue.id.clone(),
            rule: "no-session-stamp (run .claude/hooks/session-start.sh, or pass \
                   --bypass-sequence)"
                .to_owned(),
            kind: Kind::Sequence,
        }));
    }

    let receipt = receipts.join(format!("{READ_RECEIPT_PREFIX}{}", issue.id));
    let baseline = match read_baseline(&receipt, receipts)? {
        // A hollow receipt (`-`, CLOUD-691's class) certifies nothing, so it is
        // absence rather than a weaker yes — the distinction that made this rule
        // opt-out in the first place.
        Some(baseline) if baseline != "-" => baseline,
        _ => {
            // ABSENCE IS NOT AN ANSWER (CLOUD-820). The baseline cannot be reset;
            // it can be DELETED, by an agent's own clone, with no bypass and no
            // record — and it used to fall through to a clock comparison that
            // CLOUD-597 and CLOUD-615 each proved wrong in one direction. So the
            // strong half was opt-out. It is a refusal now.
            return Ok(Some(Refusal {
                id: issue.id.clone(),
                rule: format!(
                    "no-read-receipt (no body baseline for {} under $GIT_DIR/batten-receipts — \
                     read the row over the tracker and the receipt mints itself, or pass \
                     --bypass-sequence)",
                    issue.id
                ),
                kind: Kind::Sequence,
            }));
        }
    };

    // THE DESCRIPTION EXACTLY AS THE TRACKER RETURNED IT, with no trailing
    // newline, because that is what the engine hashed when it minted the baseline
    // (CLOUD-1121). The shell hashed `jq -r`'s output, which appends one, so the
    // two could never agree for any body not already ending in a newline: the rule
    // refused every claim in every clone, unconditionally, and the only way past
    // it was the bypass it reserves for a human's visible decision. It stayed
    // invisible because the suite fabricated the baseline the same wrong way, so
    // reader and fixture agreed with each other and neither agreed with the
    // writer. Sharing `git::blob_id` with the minting side is what makes a second
    // spelling unwritable rather than merely wrong.
    let Some(now) = crate::git::blob_id(description) else {
        return Err(UsageError::raise(format!(
            "claim: could not hash {}'s body to compare against the read this clone recorded",
            issue.id
        )));
    };
    if now == baseline {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: issue.id.clone(),
        rule: "refined-this-session (body baseline: the body changed since this clone read it)"
            .to_owned(),
        kind: Kind::Sequence,
    }))
}

/// The recorded baseline digest, or `None` where no receipt was written.
///
/// # Errors
///
/// [`UsageError`] when the receipt or the store exists and will not read.
fn read_baseline(receipt: &Path, store: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(receipt) {
        Ok(text) => Ok(text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(3))
            .map(str::to_owned)),
        // A path that EXISTS and will not read is could-not-look, and it is the
        // one a suite can exercise without depending on whether the runner is
        // root — where a permission fixture would assert nothing.
        Err(_) if receipt.exists() => Err(UsageError::raise(format!(
            "claim: a read receipt exists at {} and cannot be read, so the body baseline could \
             not be looked at — this is not the same as having none",
            receipt.display()
        ))),
        Err(_) if store.exists() && !store.is_dir() => Err(UsageError::raise(format!(
            "claim: the receipt store at {} is not a readable directory, so no baseline could be \
             looked at",
            store.display()
        ))),
        Err(_) => Ok(None),
    }
}

/// The session boundary, written by the `SessionStart` hook before it does
/// anything else, so its presence means a session began in this clone.
const SESSION_STAMP: &str = "session-start";

/// The prefix `[[mint]] issue-read` writes one file per issue key under.
const READ_RECEIPT_PREFIX: &str = "issue-read.";

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
fn is_ready(
    grammar: &crate::ready::Grammar,
    issue: &Issue,
    description: &str,
    root: &Path,
) -> Result<bool> {
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
    let report = crate::ready::lint(grammar, &payload, root)?;
    Ok(report.findings.is_empty())
}

// ---------------------------------------------------------------------------
// The claim receipt, and the recovery that re-keys a stranded one.
// ---------------------------------------------------------------------------

/// The weakenings a groomed body ADMITS, as `<smell> <key>` pairs.
///
/// # Why this lives here and not in the gate that reads it
///
/// `config lint`'s admission arm needs two sources that must AGREE: a
/// `Weakens: <smell> <key>` commit trailer, and the groomed body that named the
/// same pair BEFORE the work started. This is the second one, and the moment it
/// is computable is exactly this one — a claim holds the groomed body in hand and
/// the work has not begun. Reading it later is not the same question, because a
/// body edited after the claim would answer it too.
///
/// # The port dropped this, and its own consumer never noticed
///
/// `mise-tasks/claim-check.sh` extracted these lines; the migration to this verb
/// did not carry them, so every receipt since has been silent and
/// `config-lint`'s groomed half has been unreachable — a trailer alone admitted
/// anything, which is precisely the "asserted in the change that performs it"
/// shape house style §8 refuses. CLOUD-841 filed the *lenient-fallback* half of
/// that defect in 2026-08; this is the half underneath it, and it is why 841's
/// own note that "`claim-check` must keep minting a receipt … it already does"
/// read as satisfied while nothing was written.
///
/// # The tracker normalises the spelling, so the grammar must not be exact
///
/// An author types `**Weakens:** ` and the tracker stores `**Weakens: **` —
/// the trailing space moves inside the emphasis. The shell anchored on
/// `\*\*Weakens:\*\*[[:space:]]` and therefore could not have matched a body the
/// tracker returned, only one typed into a local file. Both spellings are
/// accepted here for that measured reason rather than for tolerance's sake.
///
/// **Pointer-only** (rule 4): the smell id and the config key, never the clause's
/// prose or the reason it gives.
fn admitted_weakenings(description: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in description.lines() {
        // A list marker is optional because a Ready block writes the clause as a
        // bullet and a plain paragraph is equally valid; the label is what
        // anchors, and it must be at the start of the line's content so a clause
        // QUOTED mid-sentence cannot pose as one.
        let text = line.trim_start();
        let text = text
            .strip_prefix("* ")
            .or_else(|| text.strip_prefix("- "))
            .unwrap_or(text)
            .trim_start();
        let Some(rest) = text
            .strip_prefix("**Weakens:** ")
            .or_else(|| text.strip_prefix("**Weakens: **"))
        else {
            continue;
        };
        // `` `smell` at `key` ``. Split on the backticks rather than a regex: the
        // key path carries `[` and `]`, which a character class reads as a set,
        // and this file carries no pattern registry to declare one in.
        let mut spans = rest.split('`');
        let (Some(_), Some(smell), Some(joiner), Some(key)) =
            (spans.next(), spans.next(), spans.next(), spans.next())
        else {
            continue;
        };
        if joiner.trim() != "at" {
            continue;
        }
        if smell.is_empty() || key.is_empty() {
            continue;
        }
        found.push(format!("{smell} {key}"));
    }
    found
}

/// The filename a claim receipt takes for `branch`.
///
/// A slash is the one character a filename cannot carry and a branch name
/// routinely does. The spelling must match `receipt`'s own — the mediated
/// `claim-needs-receipt` row reads what this writes, and two spellings of one
/// filename mean the gate reports a missing receipt for one that exists.
#[must_use]
pub fn receipt_name(branch: &str) -> String {
    format!("claim.{}", branch.replace('/', "-"))
}

/// Write the claim receipt.
///
/// **Only on the pullable path**, which is what makes it a claim rather than a
/// record of an attempt: a refused issue mints nothing.
///
/// Keyed by BRANCH rather than by the commit SHA a verification receipt uses. A
/// verification attests to a property of exact bytes and should expire on an
/// amend; a claim attests to a decision about an *issue*, which every commit on
/// the branch continues to serve, and a SHA-keyed one would demand a re-claim per
/// commit — the false-positive rate that gets a guard bypassed.
///
/// **Pointer-only** (rule 4): keys, a verdict word, timestamps and a base commit.
/// Never a line of the body that was linted.
///
/// # Errors
///
/// [`UsageError`] when the receipt cannot be written.
pub fn mint(
    receipts: &Path,
    branch: &str,
    issues: &[Issue],
    verdict: &Verdict,
    request: &Request,
    base: Option<&str>,
    claimed_at: &str,
) -> Result<PathBuf> {
    let dest = receipts.join(receipt_name(branch));

    // WHAT THIS BRANCH ALREADY CLAIMED, CARRIED FORWARD (CLOUD-1231). `mint` has
    // always written line 1 as an id LIST, so a receipt holding several keys is
    // the shape this file was built for — but every invocation wrote a fresh one,
    // so claiming a second row on one branch silently discarded the first row's
    // record. Measured on CLOUD-1295's branch: re-claiming would have dropped the
    // `weakens` lines `config lint`'s groomed half reads, which is the difference
    // between a landable branch and an unexplainable refusal, and the reason that
    // work had to move to a branch of its own.
    //
    // A branch legitimately serves several rows — `closing-key-check` expects a
    // body to close several — so the union is the honest record rather than a
    // convenience.
    //
    // ONLY WHEN THE BASE AGREES. CLOUD-516's restart case is exactly a receipt
    // that outlived the branch it described: `git checkout -B <name> origin/main`
    // discards the commits and keeps the filename. Carrying ids across that would
    // let a restarted branch inherit claims for work it no longer holds, which is
    // the defect that row exists to close. A differing or unreadable base
    // therefore REPLACES rather than merges — the direction that forgets rather
    // than the one that over-claims.
    let carried = carried_claim(&dest, base);

    let mut body = String::new();
    // LINE 1 IS THE ID LIST, exactly where it has always been, so any reader that
    // did parse it still finds it. Everything below is read BY KEY for the same
    // reason: a line added here must not move one somebody else counts on.
    let mut ids: Vec<String> = carried.ids.clone();
    for issue in issues {
        if !ids.iter().any(|id| id == &issue.id) {
            ids.push(issue.id.clone());
        }
    }
    body.push_str(&ids.join(" "));
    body.push('\n');
    if request.bypass_sequence {
        body.push_str("ready-lint bypassed (--bypass-sequence)\n");
    } else {
        body.push_str("ready-lint pass\n");
    }
    // A takeover is recorded with WHAT it overrode, never as a bare flag: the
    // reason to allow one is that a resumed branch looks identical to a collision,
    // and the only thing that tells them apart afterwards is which rules fired for
    // which ids.
    if !verdict.overridden.is_empty() {
        writeln!(
            body,
            "takeover {} refusal(s) overridden: {}",
            verdict.overridden.len(),
            verdict.overridden.join("; ")
        )?;
    }
    // WHAT THE GROOM ADMITTED, one line per pair, keyed by the issue that named
    // it. `config lint` strips the key back off before matching — which story
    // groomed a weakening does not change whether THIS one was groomed — and
    // keeps it because a reader of a refusal needs to know where to look.
    //
    // ABSENT IS NOT EMPTY, and the distinction is the whole of CLOUD-841: a
    // receipt that EXISTS and names nothing is "the groom looked and admitted
    // nothing", which must refuse; only a receipt that does not exist at all is
    // "could not look", which falls back to the trailer. That is decided by the
    // file's existence rather than by this loop writing zero lines, so nothing
    // here needs a placeholder.
    let mut weakens: Vec<String> = carried.weakens.clone();
    for issue in issues {
        for pair in issue
            .description
            .as_deref()
            .map(admitted_weakenings)
            .unwrap_or_default()
        {
            let line = format!("weakens {} {pair}", issue.id);
            if !weakens.contains(&line) {
                weakens.push(line);
            }
        }
    }
    for line in &weakens {
        writeln!(body, "{line}")?;
    }
    writeln!(body, "claimed-at {claimed_at}")?;
    // THE BASE THIS CLAIM WAS MADE AGAINST (CLOUD-516). A branch NAME outlives the
    // branch it described — `git checkout -B <name> origin/main` discards the
    // commits that were the branch while this file, keyed by the name, survives —
    // so a receipt recording nothing cannot notice, and one claim sat on a
    // restarted branch through four unrelated stories reporting nothing. Recorded
    // rather than derived later: no amount of looking afterwards recovers what was
    // true at claim time. `-` where the base did not resolve, which a reader treats
    // as void rather than as agreement.
    writeln!(body, "base {}", base.unwrap_or("-"))?;
    // THE BRANCH THIS WAS MINTED FOR (CLOUD-733), which the FILENAME already
    // encodes — until the branch is renamed, at which point the filename is the
    // only record and it names something that no longer exists.
    writeln!(body, "branch {branch}")?;

    std::fs::create_dir_all(receipts)
        .and_then(|()| std::fs::write(&dest, body))
        .map_err(|_| {
            UsageError::raise(format!(
                "claim: could not write the claim receipt at {}",
                dest.display()
            ))
        })?;
    Ok(dest)
}

/// What a prior claim on this branch still says, when it is still about this
/// branch (CLOUD-1231).
#[derive(Default)]
struct Carried {
    /// The ids line 1 already named.
    ids: Vec<String>,
    /// The `weakens` lines already recorded, verbatim.
    weakens: Vec<String>,
}

/// Read the receipt already at `dest`, if its recorded base matches `base`.
///
/// **Every could-not-look answers with nothing carried**, which is the direction
/// that forgets: an unreadable file, an empty one, a receipt whose `base` line is
/// absent or differs, or a run whose own base did not resolve. Carrying on a
/// doubtful match would let a restarted branch inherit a claim for work it no
/// longer holds, and that is CLOUD-516's defect rather than this one's fix.
fn carried_claim(dest: &Path, base: Option<&str>) -> Carried {
    let Some(base) = base else {
        return Carried::default();
    };
    let Ok(text) = std::fs::read_to_string(dest) else {
        return Carried::default();
    };
    let recorded = text
        .lines()
        .find_map(|line| line.strip_prefix("base "))
        .map(str::trim);
    if recorded != Some(base) {
        return Carried::default();
    }
    Carried {
        ids: text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        weakens: text
            .lines()
            .filter(|line| line.starts_with("weakens "))
            .map(str::to_owned)
            .collect(),
    }
}

/// A stranded receipt this branch may adopt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The file it lives in.
    pub path: PathBuf,
    /// The branch it records — one that no longer resolves as a ref.
    pub recorded: String,
}

/// Re-key a stranded claim receipt onto `branch` (CLOUD-733).
///
/// A branch NAME outlives nothing, but the receipt keyed by it does: `git branch
/// -m` destroys the old ref and leaves the receipt on disk, describing this exact
/// work and unreachable by every reader. Measured on CLOUD-730, where it cost a
/// closed pull request to recover by hand.
///
/// **This is on the MINT side, and that is the whole design.** The obvious fix is
/// a reader that notices the stray and adopts it, and it cannot work: the mediated
/// claim row fires on the FIRST WRITE, before the branch carries a commit, so the
/// only thing that could corroborate the claim — the issue keys the branch's own
/// commits name — does not exist yet. A reader left to infer from the receipt
/// alone would adopt a stray from a DELETED branch as readily as one from a
/// rename, which is a gate weakening itself on a guess. So the author asserts it,
/// once, and the assertion is recorded.
///
/// ORPHAN, not "any other receipt": one whose recorded branch no longer resolves.
/// A rename destroys exactly one ref, so it produces exactly one orphan, and a
/// receipt belonging to a branch that still exists is that branch's, not a stray.
///
/// # Errors
///
/// [`UsageError`] when this branch already carries a receipt, when nothing is
/// adoptable, or when more than one candidate is and `from` did not pick one.
pub fn adopt(
    receipts: &Path,
    branch: &str,
    from: Option<&str>,
    lives: &dyn Fn(&str) -> bool,
) -> Result<Orphan> {
    let dest = receipts.join(receipt_name(branch));
    if dest.exists() {
        return Err(UsageError::raise(format!(
            "claim: branch {branch} already carries a claim receipt; adopting over it would \
             discard the claim it records"
        )));
    }
    let mut candidates: Vec<Orphan> = Vec::new();
    let Ok(entries) = std::fs::read_dir(receipts) else {
        return Err(UsageError::raise(
            "claim: no receipt store to adopt from".to_owned(),
        ));
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("claim.") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Read by KEY, never by line number: line 1 is the id list every existing
        // reader parses, and `branch` is emitted with the others.
        let Some(recorded) = text
            .lines()
            .find_map(|line| line.strip_prefix("branch "))
            .map(str::trim)
            .filter(|recorded| !recorded.is_empty())
        else {
            // A receipt predating this record is NOT adoptable. Reading "no branch
            // line" as "adopt me" would grandfather in every receipt ever written,
            // which is the direction that turns a recovery into a bypass.
            continue;
        };
        // Still a live branch: this receipt is that branch's, not a stray.
        if lives(recorded) {
            continue;
        }
        if from.is_some_and(|wanted| wanted != recorded) {
            continue;
        }
        candidates.push(Orphan {
            path,
            recorded: recorded.to_owned(),
        });
    }
    candidates.sort_by(|left, right| left.recorded.cmp(&right.recorded));
    let mut found = candidates.into_iter();
    let Some(orphan) = found.next() else {
        return Err(UsageError::raise(
            "claim: no orphaned claim receipt to adopt — every receipt here names a branch that \
             still exists, or records no branch at all"
                .to_owned(),
        ));
    };
    if found.next().is_some() {
        return Err(UsageError::raise(
            "claim: more than one orphaned receipt; name the one this branch continues with \
             --adopt-from"
                .to_owned(),
        ));
    }

    // RECORDED, never silent. A recovery indistinguishable from a clean pull is a
    // bypass wearing a better name — the same reason the takeover names the
    // refusals it overrode. `branch` is rewritten so the receipt keeps describing
    // where it lives, and `adopted-from` keeps where it came from.
    let Ok(text) = std::fs::read_to_string(&orphan.path) else {
        return Err(UsageError::raise(
            "claim: the orphaned receipt could not be re-read to adopt it".to_owned(),
        ));
    };
    let mut body = String::new();
    for line in text.lines().filter(|line| !line.starts_with("branch ")) {
        writeln!(body, "{line}")?;
    }
    writeln!(body, "branch {branch}")?;
    writeln!(body, "adopted-from {}", orphan.recorded)?;
    std::fs::write(&dest, body)
        .and_then(|()| std::fs::remove_file(&orphan.path))
        .map_err(|_| {
            UsageError::raise(
                "claim: could not move the orphaned receipt onto this branch".to_owned(),
            )
        })?;
    Ok(orphan)
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
    fn the_trackers_own_spelling_is_extracted_and_the_authors_is_too() {
        // BOTH, and the first is the one that decides whether this ships dead.
        // An author types `**Weakens:** x`; the tracker stores `**Weakens: **x`,
        // moving the space inside the emphasis. The shell this replaces anchored
        // on the author's spelling only, so it could not have matched a body the
        // tracker returned — measured on CLOUD-1265, twice, and visible on every
        // other bold label in that body.
        let tracker = "* **Weakens: **`waiver-added` at `waiver[inline-task-bodies-not-growing]`";
        assert_eq!(
            admitted_weakenings(tracker),
            vec!["waiver-added waiver[inline-task-bodies-not-growing]".to_owned()],
        );
        let authored = "  **Weakens:** `rule-predicate-changed` at `rule[x].tools`";
        assert_eq!(
            admitted_weakenings(authored),
            vec!["rule-predicate-changed rule[x].tools".to_owned()],
        );
    }

    #[test]
    fn a_body_naming_no_weakening_extracts_nothing() {
        // The anti-vacuity mirror, and it carries more weight here than usual:
        // this function's whole job is to make "the groom admitted nothing"
        // distinguishable from "no groom happened", and an extractor that
        // returned a row for any body would collapse them the other way.
        assert!(admitted_weakenings("**Weakens** is discussed here in prose.").is_empty());
        assert!(admitted_weakenings("Weakens: no-backticks at all").is_empty());
        assert!(admitted_weakenings("").is_empty());
    }

    #[test]
    fn a_clause_quoted_mid_sentence_is_not_a_declaration() {
        // The label anchors at the start of the line's content, so a body
        // EXPLAINING the grammar — this repository's own rules files do — cannot
        // mint an admission by describing one.
        let quoted = "the clause reads **Weakens:** `x` at `y`, which the gate parses";
        assert!(admitted_weakenings(quoted).is_empty());
    }

    #[test]
    fn the_joiner_is_load_bearing_so_two_code_spans_are_not_a_pair() {
        // `smell` at `key` is the grammar. Two adjacent spans with anything else
        // between them is a sentence that happens to carry backticks, and reading
        // it as a declaration would admit a weakening nobody named.
        let wrong = "**Weakens:** `smell` and `key`";
        assert!(admitted_weakenings(wrong).is_empty());
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
        let grammar = crate::ready::Grammar::committed();
        let Ok(verdict) = judge(&grammar, &issues, &Request::default(), Path::new("."), None)
        else {
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
        let grammar = crate::ready::Grammar::committed();
        let answer = judge(&grammar, &issues, &Request::default(), Path::new("."), None);
        assert!(
            answer.is_err(),
            "a bodyless payload must not read as pullable"
        );
    }
}

/// CLOUD-1231: a branch serves several rows, so its receipt records several.
#[cfg(test)]
mod carried_claim_tests {
    use super::{Carried, carried_claim};

    fn write(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let dest = dir.join("claim.branch");
        std::fs::write(&dest, body).expect("write the fixture receipt");
        dest
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-carried-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the fixture root");
        dir
    }

    #[test]
    fn a_prior_claim_on_the_same_base_is_carried() {
        // The positive arm, and the defect this closes: claiming a second row on
        // one branch used to discard the first row's record entirely, including
        // the `weakens` lines `config lint`'s groomed half reads.
        let dir = scratch("same-base");
        let dest = write(
            &dir,
            "AAA-1 AAA-2\nready-lint pass\nweakens AAA-1 smell key\nbase deadbeef\nbranch b\n",
        );
        let carried = carried_claim(&dest, Some("deadbeef"));
        assert_eq!(carried.ids, vec!["AAA-1".to_owned(), "AAA-2".to_owned()]);
        assert_eq!(carried.weakens, vec!["weakens AAA-1 smell key".to_owned()]);
    }

    #[test]
    fn a_prior_claim_on_a_different_base_is_forgotten() {
        // CLOUD-516's restart case, and the reason this merges conditionally
        // rather than always. `git checkout -B <name> origin/main` discards the
        // commits and keeps the filename, so carrying ids across it would let a
        // restarted branch inherit claims for work it no longer holds.
        let dir = scratch("moved-base");
        let dest = write(&dir, "AAA-1\nbase deadbeef\nbranch b\n");
        assert!(carried_claim(&dest, Some("cafe")).ids.is_empty());
    }

    #[test]
    fn every_could_not_look_carries_nothing() {
        // The direction that forgets. An absent file, a receipt with no `base`
        // line, and a run whose own base did not resolve are all doubtful
        // matches, and over-claiming on a doubt is the failure CLOUD-516 records.
        let dir = scratch("could-not-look");
        assert!(
            carried_claim(&dir.join("claim.absent"), Some("deadbeef"))
                .ids
                .is_empty()
        );
        let no_base = write(&dir, "AAA-1\nready-lint pass\nbranch b\n");
        assert!(carried_claim(&no_base, Some("deadbeef")).ids.is_empty());
        assert!(carried_claim(&no_base, None).ids.is_empty());
    }

    #[test]
    fn the_default_carries_nothing() {
        // The anti-vacuity mirror: a `Carried` that arrived populated by default
        // would make every case above pass without reading a file at all.
        assert!(Carried::default().ids.is_empty());
        assert!(Carried::default().weakens.is_empty());
    }
}
