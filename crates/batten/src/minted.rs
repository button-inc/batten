//! A declared field of an already-minted receipt, on the tree surface
//! (CLOUD-1310).
//!
//! # What this is for
//!
//! A `declared` exemption table keyed to an issue can grow a row whose owner has
//! CLOSED — the licence outliving the row that was supposed to deliver it, which
//! is the permanent-exemption shape such a table exists to refuse. A shell
//! program used to decide that from payloads a caller piped in. A tree-scoped
//! policy module has no stdin, and no tree fact carried a subject's status, so
//! the predicate had no home at all after that program retired.
//!
//! The material was already on disk. `[[mint]]` writes a receipt at the mediated
//! boundary whenever an agent reads a subject, in a session that had whatever
//! credential the read needed; this projects one declared FIELD of that receipt
//! onto the tree surface. The engine fetches nothing and opens no socket — it
//! reads a line and compares a clock.
//!
//! # Why the age bound is the design rather than a refinement
//!
//! [`crate::captured`] is the neighbouring store and it is refused for this, on a
//! measurement rather than a preference: captures are keyed by CONTENT and carry
//! no clock — which is what makes a reduction byte-stable — so a question about a
//! MUTABLE field answers from whichever read sorts first in digest order. On any
//! branch that read a subject before working it, that is the state BEFORE the
//! work. `batten.toml`'s `claim-before-code` row records asking exactly that and
//! being refused from a pre-claim capture: the fact was right and the question
//! was wrong.
//!
//! So staleness is keyed IN, which is [`crate::tools`]' property rather than the
//! capture store's. A reading older than the row declares does not answer — the
//! subject is ABSENT, never present with a stale token.
//!
//! # Could-not-look is the ORDINARY answer here
//!
//! The receipt store lives under the git directory, is never committed, and dies
//! with its container. On a fresh clone and on every CI runner it is empty, so
//! the common case is that nobody has read this subject. That must stay
//! distinguishable from a subject whose reading says something, because reading
//! absence as agreement is the false green this whole family exists to refuse —
//! and it is why a module over this fact refuses narrowly and abstains widely.
//!
//! # What never leaves here
//!
//! One whitespace-separated TOKEN per subject. Never the receipt line, never a
//! neighbouring field, and never a byte of the prose the reading was taken from
//! (non-negotiable rule 4). The consumer's `[[mint]]` body already decided what
//! is projectable by rendering a `{slug:…}` or a `{digest:…}` rather than the
//! value itself; this reads one column of what that produced.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::facts::MintedQuery;

/// Where the mediated boundary leaves its receipts, under the git directory.
///
/// The same store `crate::claim` reads its baseline from — named here rather
/// than imported so this module states the one directory it opens, and beside
/// [`crate::tools`]' own for that module's reason: per-checkout state that must
/// never be committed.
const DIRECTORY: &str = "batten-receipts";

/// What separates a mint's name from its subject in a receipt's filename.
///
/// `[[mint]]` writes `<name>.<subject>`, so the FIRST separator ends the name
/// and everything after it is the subject — a subject carrying a dot is
/// therefore read whole rather than truncated.
const SUBJECT_SEPARATOR: char = '.';

/// The receipt directory for a checkout.
#[must_use]
pub fn store_path(git_dir: &Path) -> PathBuf {
    git_dir.join(DIRECTORY)
}

/// The subject a receipt filename names, for one declared mint.
///
/// `None` where the file belongs to a different mint. Matching on the prefix
/// plus the separator rather than on the prefix alone is what keeps a mint named
/// `issue` from claiming `issue-read`'s receipts.
#[must_use]
fn subject_of(filename: &str, mint: &str) -> Option<String> {
    let rest = filename.strip_prefix(mint)?;
    let subject = rest.strip_prefix(SUBJECT_SEPARATOR)?;
    (!subject.is_empty()).then(|| subject.to_owned())
}

/// The declared field of one receipt, if the reading is recent enough.
///
/// `None` for every could-not-look condition, and they are deliberately not
/// distinguished from each other here: a line too short to carry the field, a
/// recency column that will not parse, and a reading older than the bound are
/// all "this receipt is not an answer about that subject". What matters
/// downstream is only that the subject is absent rather than present with a
/// token nobody should trust.
#[must_use]
fn field_of(text: &str, row: &MintedQuery, now: u64) -> Option<String> {
    let line = text.lines().next()?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let taken: u64 = fields.get(row.recency)?.parse().ok()?;
    // A reading from the FUTURE is not refused: a clock that disagrees with the
    // one that wrote the receipt is could-not-look about the clock, not evidence
    // the reading is stale, and refusing it would make the fact depend on which
    // machine ran the mint.
    let age = now.saturating_sub(taken);
    let bound = u64::from(row.max_age_days).saturating_mul(86_400);
    if age > bound {
        return None;
    }
    fields.get(row.field).map(|value| (*value).to_owned())
}

/// Read the declared field for every subject each `[[rule.minted]]` row names.
///
/// **An id whose store cannot be listed is ABSENT from the result**, never
/// present with an empty map: "there is no receipt store here" is the ordinary
/// state on a fresh clone, and a gate that read it as "every subject is fine"
/// would pass on ignorance. A store that IS readable and holds no receipt for
/// this mint is present with an EMPTY map — the engine looked and there was
/// nothing, which is a different answer.
#[must_use]
pub fn fields(
    git_dir: &Path,
    declared: &[MintedQuery],
    now: u64,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    for row in declared {
        let Ok(entries) = std::fs::read_dir(store_path(git_dir)) else {
            // COULD NOT LIST. Not an empty map: see the doc above.
            continue;
        };
        let mut subjects = BTreeMap::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(filename) = name.to_str() else {
                continue;
            };
            let Some(subject) = subject_of(filename, &row.mint) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                // A receipt that exists and will not read says nothing about its
                // subject, so the subject stays absent.
                continue;
            };
            if let Some(value) = field_of(&text, row, now) {
                subjects.insert(subject, value);
            }
        }
        found.insert(row.id.clone(), subjects);
    }
    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row() -> MintedQuery {
        MintedQuery {
            id: String::from("issue-status"),
            mint: String::from("issue-read"),
            field: 4,
            recency: 2,
            max_age_days: 7,
        }
    }

    /// The separator is what keeps one mint from claiming another's receipts.
    ///
    /// Fails by: matching on the bare prefix. `issue` would then read every
    /// `issue-read.*` receipt and report its subject as `-read.CLOUD-1`.
    #[test]
    fn a_mint_name_that_is_a_prefix_of_another_claims_nothing_of_its() {
        assert_eq!(
            subject_of("issue-read.CLOUD-1", "issue-read"),
            Some(String::from("CLOUD-1"))
        );
        assert_eq!(subject_of("issue-read.CLOUD-1", "issue"), None);
    }

    /// A subject carrying the separator is read whole.
    #[test]
    fn only_the_first_separator_ends_the_mint_name() {
        assert_eq!(
            subject_of("issue-read.a.b", "issue-read"),
            Some(String::from("a.b"))
        );
    }

    /// The bound is what this family is for, so it gets both directions.
    ///
    /// Fails by: dropping the age comparison. The stale arm would then answer
    /// with a token taken eight days ago, which is the pre-claim reading
    /// `claim-before-code` measured.
    #[test]
    fn a_reading_older_than_the_bound_does_not_answer() {
        let now = 1_000_000_000;
        let fresh = format!("CLOUD-1 2026-01-01 {} d in-progress ready", now - 86_400);
        let stale = format!(
            "CLOUD-1 2026-01-01 {} d in-progress ready",
            now - 8 * 86_400
        );
        assert_eq!(
            field_of(&fresh, &row(), now),
            Some(String::from("in-progress")),
            "a reading inside the bound answers with the DECLARED field"
        );
        assert_eq!(
            field_of(&stale, &row(), now),
            None,
            "and one outside it is absent rather than present with a stale token"
        );
    }

    /// A line too short to carry the field is could-not-look, not an empty token.
    #[test]
    fn a_receipt_missing_the_declared_field_is_absent() {
        let now = 1_000_000_000;
        let short = format!("CLOUD-1 2026-01-01 {now}");
        assert_eq!(field_of(&short, &row(), now), None);
    }

    /// A recency column that will not parse cannot be read as recent.
    ///
    /// Fails by: defaulting an unparseable timestamp to zero, which reads as the
    /// epoch and is caught by the bound, or to `now`, which is the dangerous
    /// direction — a receipt whose clock field is `-` would answer forever.
    #[test]
    fn an_unparseable_recency_column_does_not_answer() {
        let now = 1_000_000_000;
        assert_eq!(
            field_of("CLOUD-1 2026-01-01 - d in-progress ready", &row(), now),
            None
        );
    }

    /// A store that cannot be listed is ABSENT, and one that can is present.
    ///
    /// The pair is the point: without the second arm, "absent" would be
    /// satisfied by a projection that never returns anything at all.
    #[test]
    fn an_unlistable_store_is_absent_and_a_listable_one_is_present() {
        let dir = std::env::temp_dir().join(format!("batten-minted-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            fields(&dir, &[row()], 0).is_empty(),
            "no store at all: the id must not appear, or a gate reads it as `looked, found nothing`"
        );
        std::fs::create_dir_all(store_path(&dir)).unwrap();
        let found = fields(&dir, &[row()], 0);
        assert_eq!(
            found.get("issue-status").map(BTreeMap::len),
            Some(0),
            "a store that IS readable and holds no receipt for this mint is present and EMPTY"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
