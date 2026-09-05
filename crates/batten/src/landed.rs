//! Whether a board column is honest about what git and the forge already did
//! (CLOUD-186 and CLOUD-1127, ported from `mise-tasks/landed-check.sh`).
//!
//! The tracker's automation moves a column on a MENTION, which is not the same
//! event as the work landing. That produces two dishonest columns, in opposite
//! directions, and until CLOUD-1127 only one of them was swept:
//!
//! * **behind git** — a row sits In Progress while its work is on `main`. The
//!   open-side automation fires on "a commit mentions this issue", and a commit
//!   can continue, document, cite or defer, so it only ever moves forward into
//!   In Progress and never past it (CLOUD-186).
//! * **ahead of nothing** — a row the PR body explicitly DECLINED is advanced by
//!   the same merge that declined it. `DO-NOT-CLOSE` is honoured by
//!   `closing-key-check`, which is this repository's, and ignored by whatever
//!   writes the transition, which is not (CLOUD-1127).
//!
//! The second is the worse one and the reason this row exists. A stranded row
//! sits a column behind its work and something sweeps for it; an over-advanced
//! row leaves the ready queue, stops being pullable, and reads to every other
//! session as work already done and merely awaiting review.
//!
//! ## Why this is Rust and not Rego
//!
//! The same reason [`crate::ready`] gives, and it is worth restating because the
//! first two revisions of CLOUD-1127's §1 got it wrong in two different ways.
//! The predicate reads a tracker PAYLOAD and `main`'s commit MESSAGES. A Rego
//! module reads `input.tree.*` and can spawn nothing, and there is no
//! commit-message fact for it to read — `input.tree["commit-meta"]` is a range's
//! identity fields and carries no message body (CLOUD-1187). A module written
//! against it would load clean, read undefined, and decide nothing, which is the
//! dead-gate shape `rules/policy-modules.md` opens with.
//! `policy/shell-retirement.rego` admits `crates/batten/src/*.rs` as a policy
//! surface for exactly this case, and `rules/toolchain.md` requires the
//! ledger arm to declare which disposition it is: this one is `kind:verb`.
//!
//! ## What this deliberately does not decide
//!
//! **Whether a started row was advanced without a served key.** CLOUD-1127 §2
//! names that arm, and implementing it surfaced two defects recorded on the row.
//! Its first conjunct — "whose most recent transition was written by the merge
//! automation" — is not computable from a `get_issue` payload, which carries a
//! status and an `updatedAt` and never says who wrote the transition. Its second
//! — "no commit in the merged range names it as its first `Refs:` key" —
//! contradicts this repository's own measurement, which
//! `mise-tasks/landed-check.sh` carried in its refusal text: only 3% of commits
//! here carry a closing keyword, because fast-forward landing puts it in the PR
//! body. A row closed properly through `Closes <key>` and no trailer satisfies
//! that refusal, which is the gate-whose-first-firing-is-a-false-positive shape
//! `batten.toml` refuses to write.
//!
//! So this carries the behind-git direction unchanged and the `DO-NOT-CLOSE`
//! arm, which depends on neither: an explicit decline plus a started column is
//! dishonest whoever wrote the transition, and CLOUD-1127 calls that arm the
//! load-bearing one for the same reason — "an explicit human statement, so a
//! transition contradicting it is wrong with no inference at all".
//!
//! ## Pointer-only, and could-not-look is never a clean board
//!
//! A finding is an issue key, the column it holds, the column it should hold,
//! and a reason class. Never a line of any body: a PR body and an issue body
//! both carry consumer detail, and a sweep that echoed them would leak it
//! through CI logs (non-negotiable rule 4).
//!
//! Every input this cannot read is a [`UsageError`] at exit 2 rather than an
//! empty set at exit 0. That direction is the whole reliability of the gate:
//! this repository has twice shipped a check that reported a clean board it
//! never looked at, and both times the silence was byte-identical to a pass.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::error::UsageError;

/// Which way a column is wrong, and therefore which remedy applies.
///
/// The two are separated rather than collapsed into "dishonest" because they
/// have different remedies and different evidence. Behind-git is derived from
/// what landed; declined-but-advanced is an explicit human statement the
/// transition contradicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// The row is In Progress and its work is on `main`.
    BehindGit,
    /// The PR body carried `DO-NOT-CLOSE` for this key and the row is in a
    /// started column anyway.
    DeclinedButAdvanced,
}

impl Reason {
    /// The token a reader sees. Stable, because the sweep's output is compared.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::BehindGit => "behind-git",
            Self::DeclinedButAdvanced => "declined-but-advanced",
        }
    }

    /// Where the row should sit instead.
    #[must_use]
    pub const fn wants(self) -> &'static str {
        match self {
            // Landed is In Review, per the Definition of Ready & Done.
            Self::BehindGit => "In Review",
            // A declined row was never this PR's to advance, so it belongs back
            // in the queue it was pulled from rather than at some later column.
            Self::DeclinedButAdvanced => "Todo",
        }
    }
}

/// One dishonest column. Pointer-only by construction: there is no field a body
/// could occupy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The issue key.
    pub id: String,
    /// The column the board currently holds.
    pub holds: String,
    /// Why it is wrong.
    pub reason: Reason,
    /// Where an ASSERTED landing came from, when the caller's word is what
    /// drained the row rather than derived evidence.
    ///
    /// A derived landing is evidence; an asserted one is the caller's word, and
    /// a reader who cannot tell them apart has to trust the union.
    pub asserted_by: Option<String>,
}

/// A board row, reduced to the two fields the sweep decides over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The issue key.
    pub id: String,
    /// The column it holds.
    pub status: String,
}

impl Row {
    /// The columns that mean "somebody has this, or it has landed, or it has
    /// shipped".
    ///
    /// Named as a set rather than tested inline so the two directions below
    /// cannot drift about what "advanced" means.
    ///
    /// **`Done` is in the set, and leaving it out was a measured defect**
    /// (CLOUD-1458). The set read `["In Progress", "In Review"]`, so a declined
    /// key that reached Done escaped the sweep entirely — and Done is
    /// RELEASED, which is where the claim is strongest and the lie therefore
    /// costs most. Measured on this gate's own two rows: CLOUD-186 and
    /// CLOUD-1127 were declined with `DO-NOT-CLOSE` in the body of the pull
    /// request that landed this module, advanced to In Review by the merge,
    /// moved back by hand, and advanced to Done by a release
    /// 2026-09-05T02:52:56Z — past the far edge of a predicate written the day
    /// before.
    ///
    /// `Backlog` and `Todo` stay out, because they are the ready queue: a
    /// declined key sitting there is `DO-NOT-CLOSE` working, and refusing it
    /// would make the marker unwritable.
    const STARTED: [&'static str; 3] = ["In Progress", "In Review", "Done"];

    fn is_in_progress(&self) -> bool {
        self.status == "In Progress"
    }

    fn is_started(&self) -> bool {
        Self::STARTED.contains(&self.status.as_str())
    }
}

/// Everything the sweep knows besides the board itself.
///
/// Assembled by the caller, and the reason is one authority rather than one
/// substrate — an earlier revision of this comment said "none of it is tree
/// state" and then named `main`'s log in the next clause, which is tree state
/// (CLOUD-1458). The closing keys come from `main`'s log through
/// `claimed-keys`, which is this repository's ONE authority on
/// claim-versus-mention and is CONSULTED rather than copied; the merged set
/// comes from the forge; the declined set from the PR body. The verb reads all
/// three from files the caller names; the predicate below decides over them and
/// touches nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// Keys `main`'s history CLOSES — claiming, never merely mentioning.
    pub claimed: BTreeSet<String>,
    /// Keys a merged pull request closed.
    pub merged: BTreeSet<String>,
    /// Keys the caller ASSERTS landed, and the ref each assertion names.
    pub asserted: BTreeMap<String, String>,
    /// Keys a PR body explicitly declined with `DO-NOT-CLOSE`.
    pub declined: BTreeSet<String>,
}

impl Evidence {
    /// Whether anything says this key's work is on `main`.
    ///
    /// A union of three key SETS, so membership is whole-value equality and
    /// never a substring — which is how `CLOUD-17` would otherwise match
    /// `CLOUD-179`. The bash predecessor spelled that as `grep -qxF` and the
    /// comparison is the same one.
    fn landed(&self, id: &str) -> bool {
        self.claimed.contains(id) || self.merged.contains(id) || self.asserted.contains_key(id)
    }

    /// Whether the caller's word is the ONLY thing draining this key.
    fn asserted_only(&self, id: &str) -> bool {
        self.asserted.contains_key(id) && !self.claimed.contains(id) && !self.merged.contains(id)
    }
}

/// What the sweep decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The dishonest columns, ordered by key so the output is byte-stable.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Whether anything is wrong.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Decide both directions over a board and the evidence about it.
///
/// Pure: no clock, no filesystem, no process. That is what makes the predicate
/// testable without a tracker or a forge, which is the split
/// `crate::speculation` makes for the same reason — "does this do what the bash
/// did" has to be answerable without a network.
#[must_use]
pub fn decide(rows: &[Row], evidence: &Evidence) -> Report {
    let mut findings = Vec::new();

    for row in rows {
        // DIRECTION ONE: the board is behind git. Only In Progress is swept,
        // because a Backlog or Todo row whose key appears on `main` is the
        // ordinary case — a commit may cite a row it does not implement, which
        // is the whole reason `claimed-keys` distinguishes closing from naming.
        if row.is_in_progress() && evidence.landed(&row.id) {
            findings.push(Finding {
                id: row.id.clone(),
                holds: row.status.clone(),
                reason: Reason::BehindGit,
                asserted_by: if evidence.asserted_only(&row.id) {
                    Some(
                        evidence
                            .asserted
                            .get(&row.id)
                            .cloned()
                            .unwrap_or_else(|| "no ref given".to_owned()),
                    )
                } else {
                    None
                },
            });
            continue;
        }

        // DIRECTION TWO: the board is ahead of nothing. A key the body DECLINED
        // sitting in a started column is dishonest whoever wrote the
        // transition — which is what makes this arm decidable where the
        // served-key arm is not (see the module doc).
        //
        // A declined row still in Todo passes, so this is not a blanket refusal
        // of the marker: `DO-NOT-CLOSE` on a row nothing advanced is the marker
        // working.
        if row.is_started() && evidence.declined.contains(&row.id) {
            findings.push(Finding {
                id: row.id.clone(),
                holds: row.status.clone(),
                reason: Reason::DeclinedButAdvanced,
                asserted_by: None,
            });
        }
    }

    findings.sort();
    Report { findings }
}

/// Whether a token is a tracker key this sweep can decide over.
///
/// **The shape is the CONSUMER's and lives in `[[pattern]]`, not here** — rule 1
/// keeps a tracker's vocabulary out of `crates/batten`. What this decides is the
/// weaker, generic property the evidence readers actually need: a non-empty
/// token carrying no whitespace, so a stray header line or a blank field in a
/// caller-assembled TSV is skipped rather than read as a key.
///
/// Skipping rather than refusing is deliberate. These files are assembled from
/// forge output by whatever fetched it, and a gate that refused a run because
/// somebody's export carried a header would be unrunnable for a reason that has
/// nothing to do with the board.
#[must_use]
pub fn is_key(token: &str) -> bool {
    !token.is_empty() && !token.chars().any(char::is_whitespace)
}

/// Parse the board out of a `get_issue` payload set.
///
/// # Errors
///
/// [`UsageError`] when the value is not a set of payloads carrying `id` and
/// `status`. That is exit 2 — "I could not read the input" — and is distinct
/// from a dishonest board at exit 1, so a caller piping the wrong thing never
/// looks like a clean sweep.
pub fn rows_from(value: &serde_json::Value) -> Result<Vec<Row>> {
    // One payload, a bare array, or an array wrapping one — the three shapes a
    // caller actually produces. The predecessor did this with a `jq -s` slurp
    // and the same unwrap of a single-element array.
    let items: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(items) => match items.as_slice() {
            [serde_json::Value::Array(inner)] => inner.iter().collect(),
            _ => items.iter().collect(),
        },
        other => vec![other],
    };

    let mut rows = Vec::with_capacity(items.len());
    for item in items {
        let (Some(id), Some(status)) = (
            item.get("id").and_then(serde_json::Value::as_str),
            item.get("status").and_then(serde_json::Value::as_str),
        ) else {
            return Err(UsageError::raise(
                "landed: not a set of get_issue payloads (need id and status per issue)".to_owned(),
            ));
        };
        rows.push(Row {
            id: id.to_owned(),
            status: status.to_owned(),
        });
    }
    Ok(rows)
}

/// A board row carrying the fields the ABANDONMENT sweep reads.
///
/// Separate from [`Row`] rather than widening it, because the two arms demand
/// different keys of different subsets and collapsing them would make the
/// narrowing below unexpressible: `landed check` needs `id` and `status` of
/// every row, and this needs three more keys of a subset it has not identified
/// yet.
///
/// **Every added field is `Option`, and the distinction is presence rather than
/// truthiness.** `None` is the key being ABSENT from the payload, which is
/// could-not-look; `Some` holding an empty value is the tracker saying there is
/// no branch or no attachment, which is an answer. The predecessor spelled this
/// as `has($k)` against a value read, and conflating the two would turn a row
/// with no PR into a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The issue key.
    pub id: String,
    /// The column it holds.
    pub status: String,
    /// When the row was last written, as the tracker stamped it.
    pub updated_at: Option<String>,
    /// The URLs the row's attachments name.
    pub attachments: Option<Vec<String>>,
    /// The branch name the tracker minted for the row.
    pub branch: Option<String>,
}

impl Claim {
    fn is_in_progress(&self) -> bool {
        self.status == "In Progress"
    }

    /// Whether any attachment is a pull request.
    ///
    /// A PR rescues a claim; **any other attachment does not**, which is the
    /// conjunct's whole content — it is "no PR", never "no attachments". A row
    /// carrying a design document is still an abandoned claim.
    fn has_pull_request(&self) -> bool {
        self.attachments
            .as_ref()
            .is_some_and(|urls| urls.iter().any(|url| is_pull_request_url(url)))
    }

    /// Whether the row's branch is one the caller's refs list carries.
    ///
    /// The empty name short-circuits false rather than being looked up, so a row
    /// the tracker gave no branch can never match a stray blank line in the
    /// evidence.
    fn has_live_branch(&self, refs: &BTreeSet<String>) -> bool {
        self.branch
            .as_deref()
            .is_some_and(|name| !name.is_empty() && refs.contains(name))
    }
}

/// Whether a URL names a pull request.
///
/// `/pull/` followed by at least one digit, anywhere in the URL. Deliberately
/// not a `[[pattern]]` row: a preset cannot read one (see
/// `.claude/rules/policy-modules.md`), and this is a forge's URL shape rather
/// than a consumer's vocabulary, so rule 1 is not in play.
fn is_pull_request_url(url: &str) -> bool {
    url.match_indices("/pull/").any(|(at, marker)| {
        url.get(at + marker.len()..)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|first| first.is_ascii_digit())
    })
}

/// Days since the epoch for an ISO-8601 instant, or `None` when it cannot be
/// read as a date at all.
///
/// **The shape is checked before the arithmetic, and that ordering is the
/// point.** `not-a-date` splits into three hyphen-separated parts exactly like a
/// real date, so a parser that split first and added second would answer a
/// number instead of admitting it could not read one — and an unreadable stamp
/// would silently become a row that is not stale.
///
/// Whole days only, from the first ten characters: the bound is a day count, so
/// a time of day never participates and two instants on one date are one answer.
#[must_use]
pub fn day_of(instant: &str) -> Option<i64> {
    let bytes = instant.get(..10)?.as_bytes();
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let digit = |index: usize| -> Option<i64> {
        let byte = *bytes.get(index)?;
        byte.is_ascii_digit().then(|| i64::from(byte - b'0'))
    };
    let mut year = 0_i64;
    for index in 0..4 {
        year = year * 10 + digit(index)?;
    }
    let month = digit(5)? * 10 + digit(6)?;
    let day = digit(8)? * 10 + digit(9)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // days_from_civil, the standard civil-calendar conversion. Integer only, so
    // it needs no date library and cannot disagree with the predecessor's awk.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// How long a claim may sit untouched, and the instant it is measured against.
///
/// **The instant is supplied rather than read**, which is the same split
/// `.claude/rules/policy-modules.md` states for every other clock here: the
/// boundary owns the clock and the decision is handed the answer. Two reasons,
/// both load-bearing — §6 requires byte-stable output, which a value that
/// differs per invocation cannot give; and without it every fixture date drifts
/// out of the bound as the calendar moves, so the suite rots on a date nobody
/// changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// Days a claim may be idle and still be live.
    pub max_idle_days: i64,
    /// The day the bound is measured against, from [`day_of`].
    ///
    /// A NUMBER rather than a string, so the parse and its refusal happen once
    /// at the boundary and this predicate stays pure. The boundary is also where
    /// the clock legitimately lives when no instant was supplied.
    pub today: i64,
}

/// What the abandonment sweep decided.
///
/// Three buckets, and they are disjoint. A landed row is never also reported as
/// abandoned — its work is on `main`, so the claim is discharged rather than
/// dead — and a row whose stamp will not parse is neither, because staleness is
/// unknown rather than false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drain {
    /// How many rows hold the In Progress column at all.
    pub in_progress: usize,
    /// In Progress while the work is on `main`.
    pub landed_unswept: Vec<String>,
    /// In Progress with no landing, no PR, no branch, and idle past the bound.
    pub abandoned: Vec<String>,
    /// In Progress with a stamp that cannot be read as a date.
    pub unreadable: Vec<String>,
}

impl Drain {
    /// Whether the column is honest.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.landed_unswept.is_empty() && self.abandoned.is_empty() && self.unreadable.is_empty()
    }
}

/// Sweep a board for claims nobody is serving.
///
/// # The narrowing is behaviour, not an optimisation
///
/// A projected-away key must be a NAMED refusal rather than a rule that
/// silently scans nothing — but demanded of the rows whose verdict depends on
/// it, never of the column. `updatedAt` is demanded of the CANDIDATES (In
/// Progress and not landed); `attachments` and `gitBranchName` are demanded only
/// of the STALE ones. So a fresh row is never demanded of `attachments` — which
/// matters because a tracker's list projection cannot carry it, making
/// `get_issue` the only source — a landed row is never demanded of anything, and
/// a row in another column is never demanded at all. An unresolved row in a
/// mixed payload still refuses, which is what keeps the narrowing from being a
/// hole.
///
/// # Errors
///
/// [`UsageError`] when the instant will not parse, or when a row whose verdict
/// needs a key does not carry it. Both are exit 2: a sweep that cannot read its
/// inputs must never render as a clean column.
pub fn drain(
    claims: &[Claim],
    evidence: &Evidence,
    refs: &BTreeSet<String>,
    bound: &Bound,
) -> Result<Drain> {
    let today = bound.today;

    let mut in_progress = 0_usize;
    let mut landed_unswept = Vec::new();
    let mut candidates = Vec::new();
    for claim in claims {
        if !claim.is_in_progress() {
            continue;
        }
        in_progress += 1;
        if evidence.landed(&claim.id) {
            landed_unswept.push(claim.id.clone());
            continue;
        }
        candidates.push(claim);
    }

    demand("updatedAt", &candidates, |claim| claim.updated_at.is_none())?;

    let mut unreadable = Vec::new();
    let mut stale = Vec::new();
    for claim in candidates {
        let Some(stamp) = claim.updated_at.as_deref() else {
            continue;
        };
        let Some(day) = day_of(stamp) else {
            unreadable.push(claim.id.clone());
            continue;
        };
        // STRICTLY greater. A claim idle for exactly the bound is still live,
        // and the boundary case is the one a reader checks.
        if today - day > bound.max_idle_days {
            stale.push(claim);
        }
    }

    // `attachments` first, matching the order the predecessor reports them in:
    // a row missing both names the one a tracker's list projection cannot
    // supply, which is the one whose remedy is a different fetch.
    demand("attachments", &stale, |claim| claim.attachments.is_none())?;
    demand("gitBranchName", &stale, |claim| claim.branch.is_none())?;

    let mut abandoned = Vec::new();
    for claim in stale {
        if claim.has_pull_request() || claim.has_live_branch(refs) {
            continue;
        }
        abandoned.push(claim.id.clone());
    }

    // Sorted and deduplicated so the report is byte-stable whatever order the
    // payload arrived in. Asserted rather than inherited: the predecessor bought
    // this with `sort -u` and a port that merely happened to preserve order
    // would pass today and drift the first time the loop changed.
    for bucket in [&mut landed_unswept, &mut abandoned, &mut unreadable] {
        bucket.sort();
        bucket.dedup();
    }

    Ok(Drain {
        in_progress,
        landed_unswept,
        abandoned,
        unreadable,
    })
}

/// Refuse when a row whose verdict needs `key` does not carry it.
fn demand(key: &str, claims: &[&Claim], absent: impl Fn(&Claim) -> bool) -> Result<()> {
    let missing: Vec<&str> = claims
        .iter()
        .filter(|claim| absent(claim))
        .map(|claim| claim.id.as_str())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(UsageError::raise(format!(
        "landed: no `{key}` on unresolved In Progress issue(s): {}. \
         The abandonment verdict reads that key, so a payload without it cannot \
         answer — re-fetch those rows individually.",
        missing.join(" ")
    )))
}

/// Parse the richer board the abandonment sweep reads.
///
/// # Errors
///
/// [`UsageError`] when the value is not a set of payloads carrying `id` and
/// `status`. The three added keys are OPTIONAL here and refused later by
/// [`drain`], because whether a row owes them depends on where it falls in the
/// narrowing — which is not knowable while parsing.
pub fn claims_from(value: &serde_json::Value) -> Result<Vec<Claim>> {
    let items: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(items) => match items.as_slice() {
            [serde_json::Value::Array(inner)] => inner.iter().collect(),
            _ => items.iter().collect(),
        },
        other => vec![other],
    };

    let mut claims = Vec::with_capacity(items.len());
    for item in items {
        let (Some(id), Some(status)) = (
            item.get("id").and_then(serde_json::Value::as_str),
            item.get("status").and_then(serde_json::Value::as_str),
        ) else {
            return Err(UsageError::raise(
                "landed: not a set of get_issue payloads (need id and status per issue)".to_owned(),
            ));
        };
        claims.push(Claim {
            id: id.to_owned(),
            status: status.to_owned(),
            updated_at: item
                .get("updatedAt")
                .map(|value| value.as_str().unwrap_or_default().to_owned()),
            // A present-but-not-an-array `attachments` reads as present and
            // empty rather than absent: the key IS there, so the payload is not
            // the could-not-look case the demand exists to catch.
            attachments: item.get("attachments").map(|value| {
                value
                    .as_array()
                    .map(|entries| {
                        entries
                            .iter()
                            .filter_map(|entry| {
                                entry
                                    .get("url")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned)
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }),
            branch: item
                .get("gitBranchName")
                .map(|value| value.as_str().unwrap_or_default().to_owned()),
        });
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, status: &str) -> Row {
        Row {
            id: id.to_owned(),
            status: status.to_owned(),
        }
    }

    fn keys(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn an_in_progress_row_whose_work_is_on_main_is_behind_git() {
        let report = decide(
            &[row("CLOUD-1", "In Progress")],
            &Evidence {
                claimed: keys(&["CLOUD-1"]),
                ..Evidence::default()
            },
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].reason, Reason::BehindGit);
        assert_eq!(report.findings[0].reason.wants(), "In Review");
    }

    /// THE SUBSTRING TRAP, asserted rather than assumed. `CLOUD-17` must not be
    /// drained by `CLOUD-179` being on `main`; the predecessor spelled the same
    /// comparison as `grep -qxF`.
    #[test]
    fn a_key_is_not_drained_by_a_longer_key_that_starts_with_it() {
        let report = decide(
            &[row("CLOUD-17", "In Progress")],
            &Evidence {
                claimed: keys(&["CLOUD-179"]),
                ..Evidence::default()
            },
        );
        assert!(report.is_clean());
    }

    #[test]
    fn a_declined_key_in_a_started_column_is_refused() {
        let report = decide(
            &[row("CLOUD-1", "In Review")],
            &Evidence {
                declined: keys(&["CLOUD-1"]),
                ..Evidence::default()
            },
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].reason, Reason::DeclinedButAdvanced);
        assert_eq!(report.findings[0].reason.wants(), "Todo");
    }

    /// DONE IS THE FAR EDGE, AND IT WAS OUTSIDE THE SET (CLOUD-1458).
    ///
    /// Done means RELEASED, so a key the body declined sitting there is the
    /// strongest form of the claim and the one that misleads furthest. The
    /// original `STARTED` stopped at In Review, and this gate's own two rows
    /// walked straight past it within a day of the module landing.
    #[test]
    fn a_declined_key_that_reached_done_is_refused() {
        let report = decide(
            &[row("CLOUD-1", "Done")],
            &Evidence {
                declined: keys(&["CLOUD-1"]),
                ..Evidence::default()
            },
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].reason, Reason::DeclinedButAdvanced);
    }

    /// THE ARM THAT KEEPS THIS FROM BEING A BLANKET REFUSAL OF THE MARKER. A
    /// declined row nothing advanced is the marker working, and a gate refusing
    /// it would make `DO-NOT-CLOSE` unusable.
    #[test]
    fn a_declined_key_still_in_the_queue_passes() {
        let report = decide(
            &[row("CLOUD-1", "Todo")],
            &Evidence {
                declined: keys(&["CLOUD-1"]),
                ..Evidence::default()
            },
        );
        assert!(report.is_clean());
    }

    /// WHICH ARM DRAINED IT IS PART OF THE FINDING. A derived landing is
    /// evidence; an asserted one is the caller's word, and the ref travels so
    /// the assertion can be checked rather than taken.
    #[test]
    fn an_asserted_landing_is_reported_as_asserted_and_names_its_ref() {
        let report = decide(
            &[row("CLOUD-1", "In Progress")],
            &Evidence {
                asserted: [("CLOUD-1".to_owned(), "abc1234".to_owned())]
                    .into_iter()
                    .collect(),
                ..Evidence::default()
            },
        );
        assert_eq!(report.findings[0].asserted_by.as_deref(), Some("abc1234"));
    }

    #[test]
    fn a_derived_landing_is_not_reported_as_asserted() {
        let report = decide(
            &[row("CLOUD-1", "In Progress")],
            &Evidence {
                claimed: keys(&["CLOUD-1"]),
                asserted: [("CLOUD-1".to_owned(), "abc1234".to_owned())]
                    .into_iter()
                    .collect(),
                ..Evidence::default()
            },
        );
        assert_eq!(report.findings[0].asserted_by, None);
    }

    #[test]
    fn a_payload_missing_status_is_could_not_look_rather_than_a_clean_board() {
        let value = serde_json::json!([{ "id": "CLOUD-1" }]);
        assert!(rows_from(&value).is_err());
    }

    #[test]
    fn a_single_payload_and_a_wrapped_array_read_alike() {
        let bare = serde_json::json!({ "id": "CLOUD-1", "status": "Todo" });
        let wrapped = serde_json::json!([[{ "id": "CLOUD-1", "status": "Todo" }]]);
        // Compared through `ok()` rather than unwrapped: the workspace denies
        // `unwrap`/`expect` on every reachable path, this one included.
        //
        // THE SECOND ASSERTION IS THE ANTI-VACUITY GUARD. Two `Err`s both map to
        // `None`, so the equality alone would pass over a verb that rejected
        // both shapes — agreement about nothing, which is the class this
        // repository's own `neither_reading_is_empty` cases exist to refuse.
        assert!(
            rows_from(&bare).is_ok(),
            "the equality below is only meaningful if the payload parsed at all"
        );
        assert_eq!(rows_from(&bare).ok(), rows_from(&wrapped).ok());
    }

    // --- the abandonment sweep -------------------------------------------

    /// A claim with every key present. The defaults are the ABANDONED shape, so
    /// each case below reads as "this one thing rescues it".
    fn claim(id: &str, since: &str) -> Claim {
        Claim {
            id: id.to_owned(),
            status: "In Progress".to_owned(),
            updated_at: Some(since.to_owned()),
            attachments: Some(Vec::new()),
            branch: Some(String::new()),
        }
    }

    fn bound() -> Bound {
        Bound {
            max_idle_days: 2,
            today: day_of("2026-08-20").unwrap_or_default(),
        }
    }

    fn swept(claims: &[Claim]) -> Drain {
        drain(claims, &Evidence::default(), &BTreeSet::new(), &bound()).unwrap_or_default()
    }

    #[test]
    fn every_conjunct_satisfied_is_claimed_abandoned() {
        let report = swept(&[claim("CLOUD-1", "2026-08-01")]);
        assert_eq!(report.abandoned, vec!["CLOUD-1".to_owned()]);
        assert_eq!(report.in_progress, 1);
        assert!(!report.is_clean());
    }

    /// THE VERDICTS ARE EXCLUSIVE. A row satisfying every abandonment conjunct
    /// whose work is nonetheless on `main` is landed, not dead — its claim was
    /// discharged. Reporting both would price one row twice and tell a reader to
    /// do two contradictory things with it.
    #[test]
    fn a_landed_row_is_not_also_reported_as_abandoned() {
        let report = drain(
            &[claim("CLOUD-1", "2026-08-01")],
            &Evidence {
                claimed: keys(&["CLOUD-1"]),
                ..Evidence::default()
            },
            &BTreeSet::new(),
            &bound(),
        )
        .unwrap_or_default();
        assert_eq!(report.landed_unswept, vec!["CLOUD-1".to_owned()]);
        assert!(report.abandoned.is_empty());
    }

    /// THE BOUND IS EXCLUSIVE AT THE THRESHOLD, and this is the case that pins
    /// it. Both arms are asserted because either alone passes over a predicate
    /// that never fires.
    ///
    /// SHOWN ABLE TO FAIL: `#MUTANT abandoned-ignores-bound` neuters the
    /// comparison, and the second arm below is what goes red.
    #[test]
    fn the_idle_bound_is_exclusive_at_exactly_the_threshold() {
        assert!(
            swept(&[claim("CLOUD-1", "2026-08-18")])
                .abandoned
                .is_empty(),
            "exactly the bound is still live"
        );
        assert_eq!(
            swept(&[claim("CLOUD-1", "2026-08-17")]).abandoned,
            vec!["CLOUD-1".to_owned()],
            "one day past it is not"
        );
    }

    /// A PR rescues; ANY OTHER ATTACHMENT DOES NOT. The conjunct is "no pull
    /// request", never "no attachments", so a row carrying a design document is
    /// still an abandoned claim.
    ///
    /// SHOWN ABLE TO FAIL: `#MUTANT abandoned-ignores-pr` drops the rescue, and
    /// the first arm goes red.
    #[test]
    fn only_a_pull_request_attachment_rescues_a_claim() {
        let mut with_pr = claim("CLOUD-1", "2026-08-01");
        with_pr.attachments = Some(vec!["https://github.com/o/r/pull/12".to_owned()]);
        assert!(swept(&[with_pr]).abandoned.is_empty());

        let mut with_doc = claim("CLOUD-2", "2026-08-01");
        with_doc.attachments = Some(vec!["https://tracker.example/document/abc".to_owned()]);
        assert_eq!(swept(&[with_doc]).abandoned, vec!["CLOUD-2".to_owned()]);
    }

    #[test]
    fn a_claim_with_a_live_remote_branch_is_not_abandoned() {
        let mut live = claim("CLOUD-1", "2026-08-01");
        live.branch = Some("feat/live".to_owned());
        let report = drain(
            &[live],
            &Evidence::default(),
            &keys(&["feat/live"]),
            &bound(),
        )
        .unwrap_or_default();
        assert!(report.abandoned.is_empty());
    }

    /// PRESENCE, NOT TRUTHINESS. An empty branch name and an empty attachment
    /// list are the tracker SAYING there is no branch and no PR — data, not
    /// absence — so the row is judged rather than refused, and the blank name
    /// must not match a blank line in the caller's refs.
    #[test]
    fn an_empty_value_is_an_answer_and_never_a_refusal() {
        let report = drain(
            &[claim("CLOUD-1", "2026-08-01")],
            &Evidence::default(),
            &keys(&[""]),
            &bound(),
        )
        .unwrap_or_default();
        assert_eq!(report.abandoned, vec!["CLOUD-1".to_owned()]);
    }

    /// An unreadable stamp is its own bucket: staleness is UNKNOWN, which is
    /// neither live nor dead. Reading it as fresh would hide the row; reading it
    /// as stale would invent a finding.
    #[test]
    fn an_unreadable_stamp_is_reported_rather_than_read_as_fresh() {
        let mut undated = claim("CLOUD-1", "2026-08-01");
        undated.updated_at = Some("not-a-date".to_owned());
        let report = swept(&[undated]);
        assert_eq!(report.unreadable, vec!["CLOUD-1".to_owned()]);
        assert!(report.abandoned.is_empty());
    }

    /// THE NARROWING, BOTH DIRECTIONS IN ONE CASE. The fresh row owes no
    /// `attachments` — a tracker's list projection cannot carry that key, so
    /// demanding it of the whole column forces a per-row fetch nobody needs —
    /// while the stale one in the same payload still refuses.
    #[test]
    fn a_key_is_demanded_of_the_rows_whose_verdict_needs_it_and_no_others() {
        let mut fresh = claim("CLOUD-1", "2026-08-20");
        fresh.attachments = None;
        assert!(
            drain(
                &[fresh.clone()],
                &Evidence::default(),
                &BTreeSet::new(),
                &bound()
            )
            .is_ok(),
            "a fresh row is already resolved by the bound, so it owes no attachments"
        );

        let mut stale = claim("CLOUD-2", "2026-08-01");
        stale.attachments = None;
        assert!(
            drain(
                &[fresh, stale],
                &Evidence::default(),
                &BTreeSet::new(),
                &bound()
            )
            .is_err(),
            "the narrowing must not become a hole: a stale row still owes the key"
        );
    }

    /// A row in another column is judged by neither verdict and owes no key.
    /// Over-refusal is as much a defect as the silent scan.
    #[test]
    fn a_row_in_another_column_is_neither_swept_nor_demanded() {
        let mut done = claim("CLOUD-1", "2026-08-01");
        done.status = "Done".to_owned();
        done.attachments = None;
        done.updated_at = None;
        let report =
            drain(&[done], &Evidence::default(), &BTreeSet::new(), &bound()).unwrap_or_default();
        assert!(report.is_clean());
        assert_eq!(report.in_progress, 0);
    }

    /// Byte-stable regardless of input order — asserted rather than inherited,
    /// because a port that merely happened to preserve order would pass today
    /// and drift the first time the loop changed.
    #[test]
    fn the_id_list_is_byte_stable_whatever_order_the_payload_arrived_in() {
        let one = claim("CLOUD-1", "2026-08-01");
        let two = claim("CLOUD-2", "2026-08-01");
        let forwards = swept(&[one.clone(), two.clone()]);
        let backwards = swept(&[two, one]);
        assert_eq!(forwards.abandoned, backwards.abandoned);
        assert_eq!(forwards.abandoned.len(), 2, "and neither reading is empty");
    }

    /// THE SHAPE IS CHECKED BEFORE THE ARITHMETIC. `not-a-date` splits into
    /// three hyphen-separated parts exactly like a real date, so a parser that
    /// split first would answer a number instead of admitting it could not read.
    #[test]
    fn a_stamp_shaped_like_a_date_but_not_one_is_unreadable() {
        assert!(day_of("not-a-date").is_none());
        assert!(day_of("2026-13-01").is_none());
        assert!(day_of("2026-08-99").is_none());
        assert!(day_of("2026-08-20T11:22:33Z").is_some());
        // A known offset, so the arithmetic is pinned and not merely non-None.
        let (earlier, later) = (day_of("2026-08-18"), day_of("2026-08-20"));
        assert_eq!(later.zip(earlier).map(|(a, b)| a - b), Some(2));
    }

    #[test]
    fn a_pull_request_url_needs_a_number_after_the_marker() {
        assert!(is_pull_request_url("https://github.com/o/r/pull/12"));
        assert!(!is_pull_request_url("https://github.com/o/r/pull/"));
        assert!(!is_pull_request_url("https://example.test/pulled/12"));
    }

    /// An absent key and a present-but-empty one must not read alike, because
    /// the whole demand rests on telling them apart.
    #[test]
    fn parsing_keeps_an_absent_key_distinct_from_an_empty_one() {
        let absent = serde_json::json!({ "id": "CLOUD-1", "status": "In Progress" });
        let empty = serde_json::json!({
            "id": "CLOUD-1", "status": "In Progress",
            "attachments": [], "gitBranchName": ""
        });
        let absent = claims_from(&absent).unwrap_or_default();
        let empty = claims_from(&empty).unwrap_or_default();
        assert_eq!(
            absent.first().map(|claim| claim.attachments.clone()),
            Some(None)
        );
        assert_eq!(
            empty.first().map(|claim| claim.attachments.clone()),
            Some(Some(Vec::new()))
        );
        assert_eq!(
            empty.first().and_then(|claim| claim.branch.clone()),
            Some(String::new())
        );
    }
}

/*
The mutations CLOUD-1513's Ready block declares. Each removes one conjunct, and
the named case is the one that stops discriminating.

THE SUITE IS DECLARED, because the default cannot exist here. `mutate` resolves
an undeclared gate's suite as a `.bats` file named for it, and this module has
none — `V-SHELL-RULE-ADDED` refuses adding one. The named cases are this file's
own unit tier, so the declared path is this file (CLOUD-1267).

#MUTANT-SUITE crates/batten/src/landed.rs
#MUTANT abandoned-ignores-bound|s@today - day > bound.max_idle_days@true@|the_idle_bound_is_exclusive_at_exactly_the_threshold
A ROW'S SCRIPT MAY CARRY NO `|` OF ITS OWN, because the three fields are
`|`-separated and `rows_in` splits on every one. The first draft of the row
below mutated both rescues at once — `has_pull_request() || has_live_branch()` —
and the two pipes made it a five-field row the sweep refused to read. Mutating
the single conjunct the case is about is both well-formed AND the sharper
declaration: it discriminates the pull-request arm rather than the disjunction.

#MUTANT abandoned-ignores-pr|s@claim.has_pull_request()@false@|only_a_pull_request_attachment_rescues_a_claim
*/
