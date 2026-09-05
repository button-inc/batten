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
//! dead-gate shape `.claude/rules/policy-modules.md` opens with.
//! `policy/shell-retirement.rego` admits `crates/batten/src/*.rs` as a policy
//! surface for exactly this case, and `.claude/rules/toolchain.md` requires the
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
}
