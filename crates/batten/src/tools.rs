//! A third-party tool's verdict, read back from a record keyed to the tool, its
//! pinned version and the digest of what it read (CLOUD-1171).
//!
//! # The engine runs no validator, and never could
//!
//! House style §5 makes `check` `read` and *structurally incapable* of spawning,
//! so ~five governed programs that run a validator and then adjudicate what it
//! said had no expressible successor: a tree-scoped module asking about a
//! validator's answer read undefined, Rego took undefined as *does not hold*, and
//! the gate was byte-identical to a clean tree on the decision surface.
//!
//! The answer is [`crate::forge`]'s, with a different key. The producer runs the
//! tool once, outside — a `mise` task, a CI step — and writes a keyed record this
//! reads back. CLOUD-1171 is that mechanism's second producer rather than a new
//! design, which is also why the record's line shape has ONE parser: two would be
//! two authorities over the same bytes, and they can disagree.
//!
//! # The key is a triple, and each component refuses a different lie
//!
//! * **the tool** — a record `pkl` wrote is not evidence about what `renovate`
//!   found.
//! * **the pinned version** — one validator's answer at v1.1 is not its answer at
//!   v1.2. That is CLOUD-646's shape (*a pinned tool invoked bare resolves to
//!   whatever is ambient*), closed for this path by putting the pin IN THE KEY
//!   rather than in a field a module has to remember to compare.
//! * **the input digest** — a verdict over bytes that have since changed is a
//!   verdict about a file nobody is asking about. This is what makes a record go
//!   stale by construction: edit the subject and the key moves, so the old
//!   verdict is not found rather than found and wrong.
//!
//! A record whose key differs in any component lives under a different filename
//! and is invisible. The negative half is the safety property, and it is
//! mechanical rather than a comparison anyone can skip.
//!
//! # Three answers, kept apart
//!
//! * **no record for a declared id** — absent from the map. Nothing has judged
//!   these bytes with this tool at this version.
//! * **a record holding no findings** — present, empty. The tool ran and found
//!   nothing.
//! * **no store at all, or nobody declared a tool** — the whole fact is `None`,
//!   projected as `null`.
//!
//! Collapsing any pair reports clean over a validator that never ran, which is
//! CLOUD-845's dead gate on the surface that decides whether work lands.
//!
//! # Pointer-only, at the boundary
//!
//! A finding's NAME and a pointer — a `path:line`, a count, a status token. Never
//! a tool's report, its diagnostic prose, or the span it quoted: a validator's
//! output is the likeliest place in this family for a secret to appear, so
//! non-negotiable rule 4 is decided here rather than at the report.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::Digest as _;

use crate::facts::{KEY_SEPARATOR, ToolQuery};

/// Where a producer leaves its records, under the git directory.
///
/// Beside [`crate::forge`]'s own store and for its reason: it is per-checkout
/// state that must never be committed, and the git directory is the one place
/// this crate already treats that way.
const DIRECTORY: &str = "batten-tools";

/// The digest of one input's bytes, as the key's third component.
///
/// Truncated to 32 hex characters, which is a filename rather than a security
/// boundary: the record is written by a local producer under the git directory,
/// so this distinguishes revisions of a file and is not asked to resist anyone.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    let full = sha2::Sha256::digest(bytes);
    let mut hex = String::with_capacity(32);
    for byte in full.iter().take(16) {
        use std::fmt::Write as _;
        // `write!` to a `String` is infallible; the result is discarded rather
        // than unwrapped because the library lints forbid an unwrap here.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The record name for one declared query over a known input digest.
///
/// Composed here and nowhere else, so the separator [`ToolQuery::malformed`]
/// refuses at load is the same one this joins with.
#[must_use]
pub fn record_key(row: &ToolQuery, input_digest: &str) -> String {
    format!(
        "{}{KEY_SEPARATOR}{}{KEY_SEPARATOR}{input_digest}",
        row.tool, row.version
    )
}

/// The record file for one composed key.
#[must_use]
pub fn record_path(git_dir: &Path, key: &str) -> PathBuf {
    git_dir.join(DIRECTORY).join(key)
}

/// Read the verdict for each DECLARED tool row.
///
/// The input is read from `root` and digested here, because the digest is what
/// makes the record stale-by-construction and a caller that supplied one could
/// supply the wrong one.
///
/// **An id whose input cannot be read is ABSENT from the result**, never present
/// with an empty verdict: "I could not look at what the tool looked at" is not
/// "the tool found nothing", and a gate that confused them would pass on
/// ignorance. Same for a key with no record.
#[must_use]
pub fn verdicts(
    git_dir: &Path,
    root: &Path,
    declared: &[ToolQuery],
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    for row in declared {
        let Ok(bytes) = std::fs::read(root.join(&row.input)) else {
            // COULD NOT LOOK at the subject, so no key can be composed for it.
            continue;
        };
        let key = record_key(row, &digest(&bytes));
        let Ok(text) = std::fs::read_to_string(record_path(git_dir, &key)) else {
            // ABSENT, not empty. This is the arm the whole family turns on: a
            // record under a DIFFERENT key — another version, another revision of
            // the input — is not read here, it is not seen at all.
            continue;
        };
        found.insert(row.id.clone(), crate::forge::parse(&text));
    }
    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(version: &str, input: &str) -> ToolQuery {
        ToolQuery {
            id: String::from("probe"),
            tool: String::from("validator"),
            version: String::from(version),
            input: String::from(input),
        }
    }

    #[test]
    fn a_record_from_another_version_does_not_answer() {
        // THE ANTI-STALENESS CASE the row's acceptance names. The record exists,
        // is readable, and says the tree is clean — it was simply taken by a
        // differently-pinned tool, whose answer is not this one's. Mechanical
        // rather than compared: the key differs, so the file is never opened.
        let dir = std::env::temp_dir().join("batten-tools-version");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(dir.join("subject.txt"), "bytes\n").unwrap();
        let old = row("1.1.0", "subject.txt");
        std::fs::write(
            record_path(&dir, &record_key(&old, &digest(b"bytes\n"))),
            "status clean\n",
        )
        .unwrap();

        assert!(
            !verdicts(&dir, &dir, &[row("1.2.0", "subject.txt")]).contains_key("probe"),
            "a record from another version must not answer"
        );
        assert!(
            verdicts(&dir, &dir, &[old]).contains_key("probe"),
            "the row's own version must answer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_over_other_bytes_does_not_answer() {
        // THE DIGEST HALF, and the one a version key alone cannot give: the tool
        // and the pin are identical, and only the subject moved. Without it a
        // verdict outlives the file it was taken over — clean forever, over bytes
        // nobody validated.
        let dir = std::env::temp_dir().join("batten-tools-digest");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        std::fs::write(dir.join("subject.txt"), "before\n").unwrap();
        let only = row("1.1.0", "subject.txt");
        std::fs::write(
            record_path(&dir, &record_key(&only, &digest(b"before\n"))),
            "status clean\n",
        )
        .unwrap();
        assert!(
            verdicts(&dir, &dir, std::slice::from_ref(&only)).contains_key("probe"),
            "the record must answer over the bytes it was taken on"
        );

        std::fs::write(dir.join("subject.txt"), "after\n").unwrap();
        assert!(
            !verdicts(&dir, &dir, &[only]).contains_key("probe"),
            "a verdict must not survive the bytes it was taken over"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_input_is_not_an_empty_verdict() {
        // COULD NOT LOOK at the subject. Reporting it as a verdict would let a
        // gate pass because the file it judges is missing, which is the failure
        // direction that matters.
        let dir = std::env::temp_dir().join("batten-tools-absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(DIRECTORY)).unwrap();
        assert!(
            verdicts(&dir, &dir, &[row("1.1.0", "nothing-here.txt")]).is_empty(),
            "an unreadable input must leave the id absent"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
