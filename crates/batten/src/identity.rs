//! Finding-identity fingerprints: when are two findings the same finding?
//!
//! The advisory subsystem's primary key (CLOUD-123). A finding's identity is a
//! fingerprint over a **normalized tuple, polymorphic by kind**, never a raw
//! `file:line` — inserting a line above a finding must not re-mint it as new.
//!
//! Load-bearing choices, each with the failure it prevents:
//!
//! * **The kind discriminator is hashed first** in the preimage, so a scope
//!   tuple and a sequence tuple with coincident bytes cannot collide.
//! * **Code-anchored identity hashes the matched content, not its position**,
//!   with whitespace fully collapsed (the `git patch-id` model) so a
//!   whitespace-only formatter reflow does not re-fire every finding. A
//!   formatter edit that *inserts bytes* (rustfmt's trailing comma on a
//!   multiline reflow) is a content change and correctly re-mints identity —
//!   a repo-agnostic tool does not parse language punctuation, so the accepted
//!   churn is one delta event per formatter pass. A rule whose *subject* is
//!   literal content narrows its span and opts into
//!   [`SpanNormalization::Verbatim`].
//! * **Identical spans in one file are one identity with an occurrence count**
//!   ([`count_occurrences`]), and count comparisons are direction-aware
//!   ([`compare_to_anchor`]): an increase re-raises, a decrease ratchets, zero
//!   resolves. Re-raising on a decrease would punish incremental fixing.
//! * **Canonicalization is part of identity**: NFC, `CRLF -> LF`, and
//!   repo-relative `/`-separated paths ([`canonical_repo_path`]), so the same
//!   defect fingerprints identically on macOS (NFD, case-insensitive), Linux,
//!   and Windows checkouts.
//! * **The identity version lives beside the hash, never inside it** (per-kind
//!   [`identity_version`]): two extractor versions must be able to produce
//!   comparable hashes for the migration equality-join, which a version salt
//!   baked into the preimage would forbid.
//!
//! Fields deliberately **excluded** from every tuple: severity, taxonomy tags,
//! check commands, and alias lists — severity re-rating or a re-tagging must
//! never re-mint an identity.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::error::UsageError;

/// The four finding kinds, each with its own identity tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A matched span in a source file: `(kind, rule, path, content_hash)`.
    Code,
    /// A line in captured command output, keyed by the rule's own declared
    /// template — never a mined one: `(kind, rule, source, template)`.
    Log,
    /// A whole-file or whole-repo condition: `(kind, rule, scope)`.
    Scope,
    /// A pattern over session events: `(kind, rule, pattern[, session])`.
    Sequence,
}

impl FindingKind {
    /// The stable lowercase tag hashed as the preimage's first field.
    #[must_use]
    pub const fn as_tag(self) -> &'static str {
        match self {
            FindingKind::Code => "code",
            FindingKind::Log => "log",
            FindingKind::Scope => "scope",
            FindingKind::Sequence => "sequence",
        }
    }

    /// The identity-function version for this kind, recorded *beside* every
    /// stored fingerprint (never inside the hash). Versions are per kind —
    /// the four tuples evolve independently — and date-styled so a bump reads
    /// as an event, not a counter.
    #[must_use]
    pub const fn identity_version(self) -> &'static str {
        match self {
            FindingKind::Code => "code:2026-08-06",
            FindingKind::Log => "log:2026-08-06",
            FindingKind::Scope => "scope:2026-08-06",
            FindingKind::Sequence => "sequence:2026-08-06",
        }
    }
}

/// How a code span's bytes are normalized before hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpanNormalization {
    /// Remove **all** whitespace (the `git patch-id` model): identity survives
    /// a formatter reflow. The default.
    #[default]
    Collapsed,
    /// Keep whitespace (still NFC + `LF`). For rules whose subject *is* the
    /// literal content — such a rule narrows its span to the literal so the
    /// span is reflow-stable *and* whitespace-sensitive.
    Verbatim,
}

/// A finding's identity: a SHA-256 over the kind-tagged, length-prefixed,
/// normalized tuple. Ordered and hex-rendered so stores and `--json` output
/// sort byte-stably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The lowercase hex form used in machine output and store keys.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            // `write!` into a String cannot fail; push the two nibbles directly
            // to keep this infallible without an unwrap.
            hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        hex
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

/// Canonicalize a repo-relative path for use in an identity tuple: `\` becomes
/// `/`, a leading `./` is stripped, and the result is NFC-normalized so macOS
/// NFD checkouts fingerprint identically to Linux NFC ones.
///
/// # Errors
///
/// Returns a [`UsageError`] for an absolute path (POSIX or Windows-drive), a
/// `..` component, or an empty path — an identity must never depend on where
/// the repository happens to be checked out.
pub fn canonical_repo_path(path: &str) -> anyhow::Result<String> {
    let slashed = path.replace('\\', "/");
    let trimmed = slashed.strip_prefix("./").unwrap_or(&slashed);
    if trimmed.is_empty() {
        return Err(UsageError::raise("identity path is empty"));
    }
    if trimmed.starts_with('/') {
        return Err(UsageError::raise(format!(
            "identity path must be repo-relative, got absolute path {path:?}"
        )));
    }
    let mut chars = trimmed.chars();
    let drive_absolute = matches!(
        (chars.next(), chars.next()),
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic()
    );
    if drive_absolute {
        return Err(UsageError::raise(format!(
            "identity path must be repo-relative, got drive-absolute path {path:?}"
        )));
    }
    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == "..")
    {
        return Err(UsageError::raise(format!(
            "identity path must not contain empty or `..` components, got {path:?}"
        )));
    }
    Ok(trimmed.nfc().collect())
}

/// Normalize span text for hashing: NFC, `CRLF -> LF`, and — under
/// [`SpanNormalization::Collapsed`] — all whitespace removed.
#[must_use]
pub fn normalize_span(span: &str, mode: SpanNormalization) -> String {
    let canonical: String = span.replace("\r\n", "\n").nfc().collect();
    match mode {
        SpanNormalization::Collapsed => canonical.chars().filter(|c| !c.is_whitespace()).collect(),
        SpanNormalization::Verbatim => canonical,
    }
}

/// Hash the kind tag plus each field, every part length-prefixed (u64 LE), so
/// field boundaries are injective: `("ab","c")` can never collide with
/// `("a","bc")`.
fn fingerprint_of(kind: FindingKind, fields: &[&str]) -> Fingerprint {
    let mut hasher = Sha256::new();
    let tag = kind.as_tag().as_bytes();
    hasher.update(u64::try_from(tag.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(tag);
    for field in fields {
        let bytes = field.as_bytes();
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(bytes);
    }
    Fingerprint(hasher.finalize().into())
}

/// The identity of a code-anchored finding:
/// `(code, rule_id, canonical_path, normalized_span)`.
///
/// Position never participates: the same span reflowed, or moved within the
/// file, keeps its identity; editing the span's content changes it — which is
/// correct, the finding is then about different bytes.
///
/// # Errors
///
/// Returns a [`UsageError`] when `repo_path` is not a clean repo-relative path
/// (see [`canonical_repo_path`]).
pub fn code_fingerprint(
    rule_id: &str,
    repo_path: &str,
    span: &str,
    mode: SpanNormalization,
) -> anyhow::Result<Fingerprint> {
    let path = canonical_repo_path(repo_path)?;
    let content = normalize_span(span, mode);
    Ok(fingerprint_of(
        FindingKind::Code,
        &[rule_id, &path, &content],
    ))
}

/// The identity of a log/output-anchored finding:
/// `(log, rule_id, source_key, template_key)`.
///
/// `template_key` is the rule's **own declared pattern** — never a mined
/// template: mined templates mutate retroactively as more lines arrive, so no
/// surveyed system uses one as a durable key.
#[must_use]
pub fn log_fingerprint(rule_id: &str, source_key: &str, template_key: &str) -> Fingerprint {
    fingerprint_of(FindingKind::Log, &[rule_id, source_key, template_key])
}

/// The identity of a file- or repo-scoped finding: `(scope, rule_id, scope_key)`.
#[must_use]
pub fn scope_fingerprint(rule_id: &str, scope_key: &str) -> Fingerprint {
    fingerprint_of(FindingKind::Scope, &[rule_id, scope_key])
}

/// The identity of a sequence/transcript finding:
/// `(sequence, rule_id, pattern_key, session)`.
///
/// The session is **in the tuple by default** — a session-less key would fold a
/// second session's incident of the same pattern into a duplicate increment on
/// an open finding, deduplicating away exactly the class of alert (for example
/// deny-then-bypass) the sequence kind exists to raise. A rule opts out by
/// passing `None`, which hashes distinctly from `Some("")`.
#[must_use]
pub fn sequence_fingerprint(
    rule_id: &str,
    pattern_key: &str,
    session: Option<&str>,
) -> Fingerprint {
    match session {
        Some(session) => fingerprint_of(
            FindingKind::Sequence,
            &[rule_id, pattern_key, "session", session],
        ),
        None => fingerprint_of(FindingKind::Sequence, &[rule_id, pattern_key]),
    }
}

/// Fold per-occurrence fingerprints into the multiset the store keys on:
/// identical spans in one file are **one identity with a count**, so a
/// duplicated line is a count of 2, never two findings.
#[must_use]
pub fn count_occurrences(
    fingerprints: impl IntoIterator<Item = Fingerprint>,
) -> BTreeMap<Fingerprint, u64> {
    let mut counts = BTreeMap::new();
    for fingerprint in fingerprints {
        *counts.entry(fingerprint).or_insert(0) += 1;
    }
    counts
}

/// The direction-aware verdict of comparing an identity's current occurrence
/// count against its disposition anchor. See [`compare_to_anchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountChange {
    /// Count equals the anchor: nothing to report.
    Unchanged,
    /// Count rose above the anchor: re-raise the group for **delta-only**
    /// review — a new occurrence is new evidence, even against a
    /// `rejected-by-design` disposition.
    ReRaise,
    /// Count fell but is not zero: keep the disposition, ratchet the anchor
    /// down, surface only as prune staleness. Never a re-raise — that would
    /// punish incremental fixing.
    Ratchet,
    /// Count reached zero in the evaluated context: the finding resolves.
    Resolved,
}

/// Compare an identity's `current` occurrence count against the `anchor`
/// recorded when its disposition was made.
///
/// Comparisons are only meaningful **within one context** (the same ref /
/// authoritative baseline): comparing counts observed from different worktrees
/// at different refs manufactures thrash the agent never authored.
#[must_use]
pub const fn compare_to_anchor(anchor: u64, current: u64) -> CountChange {
    if current == 0 {
        CountChange::Resolved
    } else if current == anchor {
        CountChange::Unchanged
    } else if current > anchor {
        CountChange::ReRaise
    } else {
        CountChange::Ratchet
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -- S12 fixture: formatter reflow must preserve collapsed identity. --
    #[test]
    fn whitespace_reflow_preserves_collapsed_identity() {
        let one_line =
            code_fingerprint("r", "src/lib.rs", "foo(a, b)", SpanNormalization::Collapsed).unwrap();
        let reflowed = code_fingerprint(
            "r",
            "src/lib.rs",
            "foo(\n    a,\n    b\n)",
            SpanNormalization::Collapsed,
        )
        .unwrap();
        assert_eq!(one_line, reflowed);
    }

    // -- S12 fixture (documented limitation): a formatter edit that INSERTS
    //    bytes — rustfmt's trailing comma on a multiline reflow — is a content
    //    change, and identity follows content. Repo-agnostic collapse cannot
    //    absorb language punctuation without an AST, which Batten forbids
    //    itself; the accepted churn is one delta event per formatter pass.
    #[test]
    fn byte_inserting_reflow_is_a_content_change() {
        let one_line =
            code_fingerprint("r", "src/lib.rs", "foo(a, b)", SpanNormalization::Collapsed).unwrap();
        let trailing_comma = code_fingerprint(
            "r",
            "src/lib.rs",
            "foo(\n    a,\n    b,\n)",
            SpanNormalization::Collapsed,
        )
        .unwrap();
        assert_ne!(one_line, trailing_comma);
    }

    // -- S12 fixture: whitespace inside a literal — collapse merges (the
    //    git patch-id precedent), and the narrowed verbatim span discriminates.
    #[test]
    fn literal_whitespace_needs_the_verbatim_narrowed_span() {
        let spaced = r#"println!("a b")"#;
        let fused = r#"println!("ab")"#;
        assert_eq!(
            code_fingerprint("r", "src/lib.rs", spaced, SpanNormalization::Collapsed).unwrap(),
            code_fingerprint("r", "src/lib.rs", fused, SpanNormalization::Collapsed).unwrap(),
            "collapse deliberately merges — this is why literal-subject rules narrow"
        );
        assert_ne!(
            code_fingerprint("r", "src/lib.rs", "a b", SpanNormalization::Verbatim).unwrap(),
            code_fingerprint("r", "src/lib.rs", "ab", SpanNormalization::Verbatim).unwrap(),
            "the narrowed verbatim span keeps the distinction"
        );
    }

    // -- S12 fixture: cross-platform byte pairs fingerprint identically. --
    #[test]
    fn crlf_and_nfd_pairs_fingerprint_identically() {
        // "café" as NFC vs NFD (e + combining acute), CRLF vs LF.
        let nfc_lf = code_fingerprint(
            "r",
            "src/lib.rs",
            "caf\u{e9}\n",
            SpanNormalization::Verbatim,
        )
        .unwrap();
        let nfd_crlf = code_fingerprint(
            "r",
            "src/lib.rs",
            "cafe\u{301}\r\n",
            SpanNormalization::Verbatim,
        )
        .unwrap();
        assert_eq!(nfc_lf, nfd_crlf);
    }

    #[test]
    fn nfd_paths_canonicalize_to_nfc() {
        assert_eq!(
            canonical_repo_path("docs/cafe\u{301}.md").unwrap(),
            canonical_repo_path("docs/caf\u{e9}.md").unwrap()
        );
    }

    #[test]
    fn paths_canonicalize_separators_and_reject_escapes() {
        assert_eq!(canonical_repo_path("./src/lib.rs").unwrap(), "src/lib.rs");
        assert_eq!(canonical_repo_path("src\\exit.rs").unwrap(), "src/exit.rs");
        assert!(canonical_repo_path("/etc/passwd").is_err());
        assert!(canonical_repo_path("C:\\repo\\src").is_err());
        assert!(canonical_repo_path("a/../b").is_err());
        assert!(canonical_repo_path("").is_err());
    }

    // -- The kind discriminator prevents cross-kind collisions. --
    #[test]
    fn kind_tag_prevents_cross_kind_collision() {
        let scope = scope_fingerprint("r", "x");
        let sequence = sequence_fingerprint("r", "x", None);
        assert_ne!(scope, sequence, "same field bytes, different kinds");
    }

    // -- Length prefixes make field boundaries injective. --
    #[test]
    fn field_boundaries_are_injective() {
        assert_ne!(
            log_fingerprint("r", "ab", "c"),
            log_fingerprint("r", "a", "bc")
        );
    }

    #[test]
    fn session_opt_out_differs_from_empty_session() {
        assert_ne!(
            sequence_fingerprint("r", "p", None),
            sequence_fingerprint("r", "p", Some(""))
        );
    }

    #[test]
    fn same_span_in_different_files_is_a_different_identity() {
        let a = code_fingerprint("r", "src/a.rs", "x", SpanNormalization::Collapsed).unwrap();
        let b = code_fingerprint("r", "src/b.rs", "x", SpanNormalization::Collapsed).unwrap();
        assert_ne!(a, b);
    }

    // -- S12 fixture: duplicated spans are one identity with a count. --
    #[test]
    fn duplicate_spans_group_into_one_identity_with_count() {
        let dup =
            code_fingerprint("r", "f.rs", "x.unwrap()", SpanNormalization::Collapsed).unwrap();
        let other =
            code_fingerprint("r", "f.rs", "y.unwrap()", SpanNormalization::Collapsed).unwrap();
        let counts = count_occurrences([dup, other, dup]);
        assert_eq!(counts.get(&dup), Some(&2));
        assert_eq!(counts.get(&other), Some(&1));
    }

    // -- S12 fixture: direction-aware count semantics, all four branches. --
    #[test]
    fn count_comparison_is_direction_aware() {
        assert_eq!(compare_to_anchor(5, 5), CountChange::Unchanged);
        assert_eq!(compare_to_anchor(5, 6), CountChange::ReRaise);
        assert_eq!(compare_to_anchor(5, 4), CountChange::Ratchet);
        assert_eq!(compare_to_anchor(5, 0), CountChange::Resolved);
        // A fresh identity (anchor 0) with occurrences is a raise, not a ratchet.
        assert_eq!(compare_to_anchor(0, 1), CountChange::ReRaise);
    }

    // -- Byte-stability: identical input, identical hex, stable ordering. --
    #[test]
    fn fingerprints_are_deterministic_and_hex_stable() {
        let a = log_fingerprint("r", "stdout", "warning: <count> issues");
        let b = log_fingerprint("r", "stdout", "warning: <count> issues");
        assert_eq!(a, b);
        assert_eq!(a.to_hex(), b.to_hex());
        assert_eq!(a.to_hex().len(), 64);
        assert!(a.to_hex().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn identity_versions_are_per_kind_and_dated() {
        for kind in [
            FindingKind::Code,
            FindingKind::Log,
            FindingKind::Scope,
            FindingKind::Sequence,
        ] {
            let version = kind.identity_version();
            assert!(version.starts_with(kind.as_tag()));
            assert!(version.contains(':'), "date-styled event id, not a counter");
        }
    }
}
