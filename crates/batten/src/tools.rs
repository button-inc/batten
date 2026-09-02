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
        let path = record_path(git_dir, &key);
        // RUN IT ON A MISS, so the record is minted by the run that reads it
        // rather than by a call somebody has to remember (CLOUD-1265).
        //
        // This family had a reader and no writer: `batten record tool` mints
        // these and nothing calls it, so the key resolved to nothing on every
        // real checkout and the deny rows over it refused nothing. That is the
        // same dead gate as a store nobody reads, and the fix is the same shape —
        // the engine takes the verdict itself, keyed exactly as before so a
        // differently-pinned tool or changed input still does not answer.
        if !path.is_file() {
            produce(root, row, &path);
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            // ABSENT, not empty. This is the arm the whole family turns on: a
            // record under a DIFFERENT key — another version, another revision of
            // the input — is not read here, it is not seen at all.
            continue;
        };
        found.insert(row.id.clone(), crate::forge::parse(&text));
    }
    found
}

/// Run a declared validator and store what it concluded.
///
/// # Exit status is the verdict, and stdout is not read at all
///
/// A validator's business is whether the input is acceptable, and that is its
/// exit code. Parsing its stdout would make this a second authority over a format
/// every tool spells differently — and `review.rs` has the measurement for what
/// that costs: demanding one shape from a third-party program turns every tool
/// that speaks its own into a failure, and refuses the subject for somebody
/// else's output.
///
/// So: zero writes an EMPTY record, which is "it ran and objected to nothing";
/// non-zero writes ONE pointer naming the input, which is "it ran and objected".
/// Both are records, because both are verdicts. Every other outcome — no runner,
/// a probe that says not-ready, a spawn that fails — leaves NO record, so the id
/// is absent from the map and the module reads could-not-look rather than clean.
fn produce(root: &Path, row: &ToolQuery, path: &Path) {
    let Some(program) = row.run.as_deref() else {
        return;
    };
    if !row.probe.is_empty() {
        let ready = crate::exec::piped(root, Path::new(program), &row.probe, "")
            .is_some_and(|(code, _)| code == 0);
        if !ready {
            return;
        }
    }
    let Some((code, _)) = crate::exec::piped(root, Path::new(program), &row.args, "") else {
        return;
    };
    // THE RESERVED `status` LINE, which is this family's own vocabulary rather
    // than anything the tool said. `validator-verdict-clean` defines it: `clean`
    // is the sentinel, and any other value — or any other key — counts as a
    // finding. So the exit code maps into a record shape the readers already
    // understand, and no reader has to learn a per-tool dialect.
    //
    // A POSITIVE ASSERTION rather than an empty file. Both read as clean to the
    // consumer, but an empty file is indistinguishable from a write that created
    // it and then failed, and this family's whole discipline is that could-not-
    // look and clean must never share a spelling.
    //
    // Pointer-only either way (rule 4): two closed tokens, and never a byte of
    // what the validator printed — which is the one thing a validator's output
    // reliably contains.
    let body = if code == 0 {
        "status clean\n".to_owned()
    } else {
        "status error\n".to_owned()
    };
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let _ = std::fs::write(path, body);
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
            // The existing cases pin the KEYING, which is what this family turns
            // on and what a producer does not change: a record from another
            // version or over other bytes still lives under a different name.
            run: None,
            args: Vec::new(),
            probe: Vec::new(),
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
