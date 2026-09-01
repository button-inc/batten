//! Whether a carry branch's diff is DERIVABLE, and the receipt that records it
//! (CLOUD-1295).
//!
//! # What this exists for
//!
//! `sbom-actions-currency` (CLOUD-1213) opens its licence-carry pull requests on
//! `sbom-actions/carry-<timestamp>`. `verify` refuses a branch carrying no claim
//! receipt, and neither receipt it accepts fits: the agent claim attests that a
//! human or agent read a refined issue and checked it for a competitor, which no
//! workflow performed; and `bot.<branch>` refused the branch outright for not
//! being a bot head. So the first such PR was landed with a `--takeover` claim
//! against CLOUD-1213 — a receipt asserting a refinement nobody did.
//!
//! # The receipt attests DERIVABILITY, and that is the whole design
//!
//! A branch-name exemption would be a password wearing a branch name: anything
//! that could name itself `sbom-actions/…` would pass, and the receipt would
//! attest nothing about the change. So nothing here reads the branch name.
//!
//! What is attested is checkable offline, against the merge base:
//!
//! * exactly one tracked path differs, and it is the licence table;
//! * every added line parses as `<repo>@<sha>\t<licence>\t<holder>`;
//! * for each, another row for the SAME repo carries an identical licence and
//!   holder — so only the sha differs;
//! * no line is removed or rewritten.
//!
//! Together those bound a carry branch to exactly what the workflow may produce.
//! It cannot introduce a new licence claim, edit an existing row, delete one, or
//! touch a second file — and each of those is a case the tier below drives.
//!
//! **Byte-identity of the upstream licence files is NOT attested here**, and
//! saying so matters. The workflow confirms it at carry time by fetching both
//! shas; this is the offline half, which bounds what the diff may *say* rather
//! than re-verifying what upstream *holds*. A reader wanting the second reads the
//! workflow run. Claiming otherwise would be a receipt asserting a check nobody
//! performed, which is the defect this module exists to end.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::UsageError;

/// The one path a carry branch may touch.
///
/// A constant rather than config: the receipt's whole meaning is "this is a
/// licence carry", and a configurable subject would let a consumer point the
/// admission at a file whose diffs are not derivable at all.
pub const TABLE: &str = "mise-tasks/sbom-actions.tsv";

/// Why a branch is not a carry.
///
/// **Pointer-only** (rule 4): a path, a repo name, a count. Never a licence
/// string and never a holder — those are the bytes the table exists to record,
/// and a refusal that echoed them would republish the thing being guarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A tracked path other than [`TABLE`] differs from the base.
    TouchedAnotherPath(String),
    /// The diff removes or rewrites a line rather than only appending.
    NotAppendOnly,
    /// An added line is not three tab-separated fields with a `repo@sha` key.
    Unparseable(usize),
    /// An added row names a repo the base table has no row for, so there is no
    /// recorded judgement to carry forward.
    NoPriorRow(String),
    /// An added row names a repo the base HAS, with a different licence or
    /// holder — a new claim rather than a carry.
    VerdictChanged(String),
    /// Nothing was added, so there is nothing to attest.
    NothingCarried,
}

impl Refusal {
    /// The pointer line, house style §6.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Refusal::TouchedAnotherPath(path) => format!("{path} not-the-licence-table"),
            Refusal::NotAppendOnly => format!("{TABLE} not-append-only"),
            Refusal::Unparseable(line) => format!("{TABLE}:{line} unparseable-row"),
            Refusal::NoPriorRow(repo) => format!("{TABLE} no-prior-row {repo}"),
            Refusal::VerdictChanged(repo) => format!("{TABLE} verdict-changed {repo}"),
            Refusal::NothingCarried => format!("{TABLE} nothing-carried"),
        }
    }
}

/// One row of the licence table: the repo, and the verdict recorded for it.
///
/// The sha is deliberately NOT part of the value — carrying a row forward is
/// exactly the act of changing the sha and nothing else, so the comparison has to
/// be over what must stay equal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    repo: String,
    licence: String,
    holder: String,
}

/// Parse one table line, or `None` for a comment, a blank, or a malformed row.
fn row(line: &str) -> Option<Row> {
    if line.trim_start().starts_with('#') || line.trim().is_empty() {
        return None;
    }
    let mut fields = line.split('\t');
    let key = fields.next()?;
    let licence = fields.next()?;
    let holder = fields.next()?;
    // A key with no `@` is not a pin, and a fourth field means the shape moved.
    let (repo, sha) = key.split_once('@')?;
    if repo.is_empty() || sha.is_empty() || fields.next().is_some() {
        return None;
    }
    Some(Row {
        repo: repo.to_owned(),
        licence: licence.to_owned(),
        holder: holder.to_owned(),
    })
}

/// Judge a carry: `base` and `head` are the table's lines on each side, and
/// `other` names every OTHER tracked path that differs.
///
/// Pure, so the tier below can drive every refusal without a git tree — and so
/// the predicate the receipt attests is the same one the tests assert.
///
/// # Errors
///
/// Never: a refusal is a value, not an error. The signature returns the count of
/// rows carried so a caller can record it.
pub fn judge(base: &str, head: &str, other: &[String]) -> std::result::Result<usize, Refusal> {
    if let Some(path) = other.first() {
        return Err(Refusal::TouchedAnotherPath(path.clone()));
    }

    // APPEND-ONLY, checked as a prefix rather than as a line-set difference. A
    // set comparison would read a rewritten line as one removal plus one
    // addition, which is precisely the edit this must refuse.
    let base_lines: Vec<&str> = base.lines().collect();
    let head_lines: Vec<&str> = head.lines().collect();
    if head_lines.len() < base_lines.len() || !head_lines.starts_with(&base_lines) {
        return Err(Refusal::NotAppendOnly);
    }

    // The verdict already recorded for each repo, from the BASE side only. A row
    // added by this same diff cannot vouch for another: two unmapped repos would
    // otherwise vouch for each other and the branch would carry nothing real.
    let mut known: BTreeMap<String, Row> = BTreeMap::new();
    for line in &base_lines {
        if let Some(parsed) = row(line) {
            known.insert(parsed.repo.clone(), parsed);
        }
    }

    let mut carried = 0;
    for (offset, line) in head_lines[base_lines.len()..].iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = base_lines.len() + offset + 1;
        let Some(added) = row(line) else {
            return Err(Refusal::Unparseable(number));
        };
        let Some(prior) = known.get(&added.repo) else {
            return Err(Refusal::NoPriorRow(added.repo));
        };
        if prior.licence != added.licence || prior.holder != added.holder {
            return Err(Refusal::VerdictChanged(added.repo));
        }
        carried += 1;
    }

    if carried == 0 {
        return Err(Refusal::NothingCarried);
    }
    Ok(carried)
}

/// The filename a carry receipt takes for `branch`.
///
/// `<check>.<branch>` with slashes replaced, matching `receipt`'s own spelling —
/// the same reason `claim::receipt_name` gives, and the same failure if the two
/// drift: `verify` reports a missing receipt for one that exists.
#[must_use]
pub fn receipt_name(branch: &str) -> String {
    format!("carry.{}", branch.replace('/', "-"))
}

/// Write the carry receipt.
///
/// **Pointer-only**: a count, a path, a timestamp and the base commit. The rows
/// themselves stay in the table.
///
/// The `base` line is not decoration — it is what gives this receipt CLOUD-516's
/// staleness rule for free, exactly as `bot.<branch>` gets it: a branch restarted
/// out from under its receipt is void rather than silently trusted.
///
/// # Errors
///
/// [`UsageError`] when the receipt cannot be written.
pub fn mint(
    receipts: &Path,
    branch: &str,
    carried: usize,
    base: Option<&str>,
    at: &str,
) -> Result<PathBuf> {
    let mut body = String::new();
    writeln!(body, "carry {carried} row(s)")?;
    writeln!(body, "table {TABLE}")?;
    writeln!(body, "derived-at {at}")?;
    writeln!(body, "base {}", base.unwrap_or("-"))?;

    std::fs::create_dir_all(receipts).map_err(|err| {
        UsageError::raise(format!(
            "claim carry: cannot create {}: {err}",
            receipts.display()
        ))
    })?;
    let path = receipts.join(receipt_name(branch));
    std::fs::write(&path, body).map_err(|err| {
        UsageError::raise(format!(
            "claim carry: cannot write {}: {err}",
            path.display()
        ))
    })?;
    Ok(path)
}

#[cfg(test)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The committed table's shape, minus the header prose.
    const BASE: &str = "# a comment the parser skips\n\
jdx/mise-action@aaa\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n\
taiki-e/install-action@bbb\tApache-2.0 OR MIT\tNONE\n";

    fn carried(head: &str) -> std::result::Result<usize, Refusal> {
        judge(BASE, head, &[])
    }

    #[test]
    fn a_row_carried_forward_to_a_new_sha_is_admitted() {
        let head = format!(
            "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
        );
        assert_eq!(carried(&head), Ok(1));
    }

    /// THE PREMISE CASE. Without it every refusal below could pass over a judge
    /// that refuses everything, which is the vacuity CLOUD-418 records.
    #[test]
    fn two_rows_for_two_mapped_repos_both_carry() {
        let head = format!(
            "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n\
             taiki-e/install-action@ddd\tApache-2.0 OR MIT\tNONE\n"
        );
        assert_eq!(carried(&head), Ok(2));
    }

    #[test]
    fn a_second_changed_path_is_refused_and_named() {
        let head = format!(
            "{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
        );
        assert_eq!(
            judge(BASE, &head, &["Cargo.toml".to_owned()]),
            Err(Refusal::TouchedAnotherPath("Cargo.toml".to_owned()))
        );
    }

    /// The row that makes this more than a diff-size check: a repo with no
    /// recorded verdict has nothing to carry, so a licence would be ASSERTED
    /// rather than carried — CLOUD-629's class, which the table's own header
    /// records four instances of.
    #[test]
    fn a_repo_with_no_prior_row_is_refused() {
        let head = format!("{BASE}brand/new-action@eee\tMIT\tCopyright (c) 2026 Somebody\n");
        assert_eq!(
            carried(&head),
            Err(Refusal::NoPriorRow("brand/new-action".to_owned()))
        );
    }

    /// A carry changes the sha and NOTHING else. A row whose licence or holder
    /// moved is a new claim, and admitting it would let the receipt launder one.
    #[test]
    fn a_changed_licence_is_refused_even_for_a_mapped_repo() {
        let head = format!(
            "{BASE}jdx/mise-action@ccc\tGPL-3.0\tCopyright (c) 2018 GitHub, Inc. and contributors\n"
        );
        assert_eq!(
            carried(&head),
            Err(Refusal::VerdictChanged("jdx/mise-action".to_owned()))
        );
    }

    #[test]
    fn a_changed_holder_is_refused_too() {
        let head = format!("{BASE}jdx/mise-action@ccc\tMIT\tCopyright (c) 2026 Somebody Else\n");
        assert_eq!(
            carried(&head),
            Err(Refusal::VerdictChanged("jdx/mise-action".to_owned()))
        );
    }

    /// APPEND-ONLY, and the prefix comparison is why. A line-set difference would
    /// read this as one removal plus one addition and could admit the addition.
    #[test]
    fn rewriting_an_existing_row_is_refused_rather_than_read_as_an_addition() {
        let head = "# a comment the parser skips\n\
jdx/mise-action@aaa\tGPL-3.0\tCopyright (c) 2018 GitHub, Inc. and contributors\n\
taiki-e/install-action@bbb\tApache-2.0 OR MIT\tNONE\n";
        assert_eq!(carried(head), Err(Refusal::NotAppendOnly));
    }

    #[test]
    fn deleting_a_row_is_refused() {
        let head = "# a comment the parser skips\n\
jdx/mise-action@aaa\tMIT\tCopyright (c) 2018 GitHub, Inc. and contributors\n";
        assert_eq!(carried(head), Err(Refusal::NotAppendOnly));
    }

    #[test]
    fn a_malformed_added_row_is_refused_with_its_line() {
        let head = format!("{BASE}not a table row at all\n");
        assert_eq!(carried(&head), Err(Refusal::Unparseable(4)));
    }

    /// A branch that changed nothing has nothing to attest, so it must not mint a
    /// receipt — otherwise any branch touching no tracked file would earn one.
    #[test]
    fn an_unchanged_table_carries_nothing() {
        assert_eq!(carried(BASE), Err(Refusal::NothingCarried));
    }

    /// A row added by THIS diff may not vouch for another one: two unmapped repos
    /// would otherwise vouch for each other and the branch would carry nothing
    /// that was ever judged.
    #[test]
    fn an_added_row_cannot_vouch_for_another_added_row() {
        let head = format!(
            "{BASE}brand/new-action@eee\tMIT\tCopyright (c) 2026 Somebody\n\
             brand/new-action@fff\tMIT\tCopyright (c) 2026 Somebody\n"
        );
        assert_eq!(
            carried(&head),
            Err(Refusal::NoPriorRow("brand/new-action".to_owned()))
        );
    }

    /// Pointer-only (rule 4): a refusal names the repo and the path, never the
    /// licence text or the holder it was comparing.
    #[test]
    fn no_refusal_line_echoes_a_licence_or_a_holder() {
        let head =
            format!("{BASE}jdx/mise-action@ccc\tGPL-3.0\tCopyright (c) 2026 Somebody Else\n");
        let line = carried(&head).unwrap_err().line();
        assert!(!line.contains("GPL-3.0"), "no licence: {line}");
        assert!(!line.contains("Somebody Else"), "no holder: {line}");
        assert!(line.contains("jdx/mise-action"), "names the repo: {line}");
    }

    #[test]
    fn the_receipt_filename_replaces_every_slash() {
        assert_eq!(
            receipt_name("sbom-actions/carry-20260901T110320Z"),
            "carry.sbom-actions-carry-20260901T110320Z"
        );
    }
}
