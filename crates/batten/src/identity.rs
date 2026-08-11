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
//!
//! # The four tuples
//!
//! | Kind | Tuple |
//! | -- | -- |
//! | [`FindingKind::Code`] | `(kind, rule_id, repo_relative_path, content_hash)` |
//! | [`FindingKind::Log`] | `(kind, rule_id, source_key, rule_declared_template_key)` |
//! | [`FindingKind::Scope`] | `(kind, rule_id, scope_key)` |
//! | [`FindingKind::Sequence`] | `(kind, rule_id, pattern_key[, session])` |
//!
//! The path is *in* the code tuple, so a rename re-mints and the old identity
//! goes to count 0 — which resolves it. That is a deliberate choice over
//! following content across a rename: a disposition carried silently onto a path
//! no reviewer looked at is worse than a re-raise.
//!
//! A log tuple's template is the rule's **own declared pattern**, never a mined
//! one. Mined templates mutate retroactively as more lines arrive, so no
//! surveyed system uses one as a durable key. A sequence tuple carries the
//! session by default, because a session-less key would fold a second session's
//! deny-then-bypass into a duplicate increment on an open finding — dedup'ing
//! away the alert the kind exists to raise.
//!
//! # Secret-class identity is keyed
//!
//! [`secret_code_fingerprint`] replaces the hashed span with an HMAC of it. An
//! unkeyed digest of a matched secret is an offline-guessing oracle — secrets are
//! often low-entropy, so a plain hash journaled into an append-only store is
//! recoverable by anyone who reads the store, and cannot be expunged from it.
//! The key is supplied by the caller: this module mints and stores nothing, and
//! custody (minting at store init, rotation, the loud orphan event on key loss)
//! belongs to the store and to the scanner adapter that classifies a span as
//! secret-bearing.
//!
//! # Per-rule overrides are split-only, by construction
//!
//! [`override_fingerprint`] hashes the default identity *as a field*, so two
//! spans with different default identities cannot collide under any
//! discriminator. An override can fragment a group and is mathematically unable
//! to merge two — the property a rule author must be held to, made a property of
//! the function rather than of a config check.
//!
//! # Migration
//!
//! An [`identity_version`](FindingKind::identity_version) bump is a per-kind
//! event, and the kinds split by whether a scan can be replayed. **Replayable**
//! kinds (code, scope) migrate by re-scanning the authoritative context and
//! pairing old to new with a dual-extractor equality join: run both versions over
//! one scan, and where the old version reproduces a stored hash, the new hash
//! joins that finding's alias set. **Non-replayable** kinds (sequence, and log
//! over an ephemeral capture) are grandfathered at the version they were minted
//! under and dual-hashed forward only — a version bump alone must never close,
//! GC, or re-mint one, because there is nothing left to re-derive it from.
//!
//! # Interaction laws
//!
//! Identity and dedup govern **advisory reporting only**; they never touch an
//! exit path. And a finding **holds** rather than self-clearing while its rule is
//! skipped (a precondition was unmet) or internal (the gate errored): a rule that
//! did not run observes zero occurrences, and treating that as
//! [`CountChange::Resolved`] would turn fail-closed into fail-open at the store
//! layer. Distinguishing "observed zero" from "not observed" is therefore the
//! store's obligation, not this module's — [`compare_to_anchor`] answers only the
//! first question, and answers it for a count the caller vouches for.

use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, Mac};
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
    let bytes: Vec<&[u8]> = fields.iter().map(|field| field.as_bytes()).collect();
    tagged_fingerprint(kind.as_tag(), &bytes)
}

/// The one framing: a domain tag then each field, every one length-prefixed.
///
/// The prefix is load-bearing. Without it `["ab", "c"]` and `["a", "bc"]` hash
/// identically, so a rename could be made invisible by choosing the right
/// names. Every identity in this crate — findings and the config-surface epoch
/// alike — goes through here, so there is one construction rather than two that
/// can drift.
fn tagged_fingerprint(tag: &str, fields: &[&[u8]]) -> Fingerprint {
    let mut hasher = Sha256::new();
    write_field(&mut hasher, tag.as_bytes());
    for field in fields {
        write_field(&mut hasher, field);
    }
    Fingerprint(hasher.finalize().into())
}

fn write_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

/// The domain tag for a config-surface identity, distinct from every
/// [`FindingKind`] tag so a surface hash can never collide with a finding's.
const SURFACE_TAG: &str = "surface";

/// The domain tag for a captured output stream, distinct from every
/// [`FindingKind`] tag and from [`SURFACE_TAG`] for the same reason: three
/// domains under one tag could collide across kinds of thing.
const CAPTURE_TAG: &str = "capture";

/// The domain tag for a **secret-class** identity, distinct from every
/// [`FindingKind`] tag and from [`SURFACE_TAG`]/[`CAPTURE_TAG`] for the same
/// reason those two are distinct from each other: a keyed identity and an
/// unkeyed one must not collide even when every other field agrees.
const SECRET_TAG: &str = "secret";

/// The domain tag for a per-rule identity **override**.
const OVERRIDE_TAG: &str = "override";

/// The domain tag for a **minted store identity**, distinct from every other tag
/// for the reason they are all distinct: a store id and a finding identity are
/// different kinds of thing and must not collide.
const STORE_TAG: &str = "store";

/// Mint an opaque identity from caller-supplied seed material.
///
/// The one place a store's identity is derived, and it is a *mint*, not a
/// derivation of anything the caller could reproduce: [`crate::store`] seeds it
/// with a clock and a process id alongside the repository facts, precisely so
/// the value cannot be recomputed from a path. That is what makes a store
/// identity survive the repository moving, which is the whole point of minting
/// one (CLOUD-164).
///
/// It lives here rather than in the store because the length-prefixed framing in
/// [`tagged_fingerprint`] is the one hashing construction this crate has, and a
/// second one would be a second authority on how bytes become an identity.
#[must_use]
pub fn store_fingerprint(seed: &[&str]) -> Fingerprint {
    let fields: Vec<&[u8]> = seed.iter().map(|field| field.as_bytes()).collect();
    tagged_fingerprint(STORE_TAG, &fields)
}

/// The domain tag for a **judge payload** entry (CLOUD-135), distinct from every
/// other tag here for the same reason they are distinct from each other.
///
/// It matters more than usual for this one: the hash stands in for content that
/// was deliberately *not* sent to a model, so a collision with a finding or a
/// capture identity would let a payload digest be mistaken for one of those and
/// joined against it.
const JUDGE_TAG: &str = "judge";

/// An HMAC key for secret-class identity inputs.
///
/// Opaque on purpose: the bytes have no accessor and no [`Debug`] rendering.
/// Output is a pointer, never the payload, and key material in a log line is the
/// payload. Only the key **id** is readable, because that is what a store records
/// beside a fingerprint.
///
/// This type mints, loads, and stores nothing — the caller supplies the bytes.
/// Custody (minting at store init, rotation, the loud orphan event on key loss)
/// belongs to the store and to the adapter that classifies a span as
/// secret-bearing. Wave one is the hashing path alone, which is exactly what lets
/// a store refuse to journal a secret-class kind before a keyed identity exists.
pub struct IdentityKey {
    id: String,
    bytes: [u8; 32],
}

impl IdentityKey {
    /// A key from supplied bytes, plus the id a store records beside every
    /// fingerprint minted under it.
    #[must_use]
    pub fn new(id: impl Into<String>, bytes: [u8; 32]) -> Self {
        IdentityKey {
            id: id.into(),
            bytes,
        }
    }

    /// The key id — a coordinate, not a secret. Rotation needs it readable to
    /// know which key a stored identity was minted under.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for IdentityKey {
    /// Renders the id and never the bytes: a derived `Debug` would put key
    /// material into any error or trace that formatted a value containing one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKey")
            .field("id", &self.id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// The identity of a **secret-class** code-anchored finding:
/// `(secret, rule_id, canonical_path, key_id, hmac(key, normalized_span))`.
///
/// The span is replaced by its HMAC rather than hashed directly — see the module
/// doc on why an unkeyed digest of a secret is an oracle. Keying costs nothing in
/// stability: the same secret at the same place fingerprints identically under
/// the same key.
///
/// **The key id is inside the preimage, and that does not contradict the
/// version-beside-the-hash rule above.** The two exist for opposite reasons. An
/// extractor version stays *out* so two versions can produce comparable hashes
/// for the migration equality-join. A key rotation is *meant* to re-mint, and its
/// join is dual-HMAC — computing the identity under both keys while both are
/// held — so the key id belongs in the tuple. A store records the id beside the
/// fingerprint as well, because a hash is one-way and rotation has to know what
/// it is rotating from.
///
/// Because an [`IdentityKey`] is required by the signature, a secret-class
/// identity cannot be minted without one. The refusal is structural, not a
/// runtime check that could be forgotten at a call site.
///
/// # Errors
///
/// Returns a [`UsageError`] when `repo_path` is not a clean repo-relative path
/// (see [`canonical_repo_path`]).
pub fn secret_code_fingerprint(
    key: &IdentityKey,
    rule_id: &str,
    repo_path: &str,
    span: &str,
    mode: SpanNormalization,
) -> anyhow::Result<Fingerprint> {
    let path = canonical_repo_path(repo_path)?;
    let content = normalize_span(span, mode);
    let keyed = keyed_span(key, &content)?;
    Ok(tagged_fingerprint(
        SECRET_TAG,
        &[
            rule_id.as_bytes(),
            path.as_bytes(),
            key.id.as_bytes(),
            &keyed,
        ],
    ))
}

/// HMAC-SHA256 over a normalized span.
///
/// # Errors
///
/// HMAC accepts a key of any length, so the length error cannot occur for a
/// fixed 32-byte key. It is mapped rather than unwrapped because library code
/// carries no panic path, not because the branch is reachable.
fn keyed_span(key: &IdentityKey, content: &str) -> anyhow::Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.bytes)
        .map_err(|_| UsageError::raise("identity key is not a usable HMAC key"))?;
    mac.update(content.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Apply a per-rule identity override to a default identity.
///
/// **Split-only by construction, not by validation.** The default fingerprint is
/// itself a field of the preimage, so two spans with different default identities
/// cannot produce the same override identity under any discriminator: an override
/// can fragment a group and is unable to merge two. Making that a property of the
/// function means no config check has to enforce it, and none can be bypassed.
///
/// A constant discriminator is therefore a relabel rather than a merge — it
/// preserves the default partition exactly. Splitting needs a discriminator that
/// varies *within* one default identity, which in turn needs a rule kind able to
/// supply one; the `batten.toml` key that binds this waits on findings carrying
/// their identity, since a rule field nothing reads is a decorative key.
#[must_use]
pub fn override_fingerprint(default: Fingerprint, discriminator: &str) -> Fingerprint {
    tagged_fingerprint(OVERRIDE_TAG, &[&default.0, discriminator.as_bytes()])
}

/// The identity of a **captured output stream**: `(capture, stream, bytes)`.
///
/// Not a finding, so it carries its own domain tag rather than a
/// [`FindingKind`] — the [`surface_fingerprint`] precedent below. It reuses the
/// one framing rather than minting a second hash of the same bytes, which is
/// what CLOUD-162 means by "the advisory subsystem must not contain two
/// divergent ways of content-addressing the same bytes".
///
/// Bytes are hashed **verbatim**, unlike [`surface_fingerprint`], which
/// NFC/LF-normalizes its text. A capture identifies the exact bytes a program
/// wrote: normalizing would give two genuinely different outputs one identity,
/// and there is no cross-platform checkout to reconcile here — the bytes came
/// from a process, not from a working tree.
///
/// The stream name is in the tuple, so one run's stdout and stderr are distinct
/// identities even when a program wrote the same text to both.
#[must_use]
pub fn capture_fingerprint(stream: &str, bytes: &[u8]) -> Fingerprint {
    tagged_fingerprint(CAPTURE_TAG, &[stream.as_bytes(), bytes])
}

/// The identity of a **judge payload** entry: its class and the bytes it stands
/// for (CLOUD-135).
///
/// Bytes are hashed **verbatim**, like a capture and unlike a span: the digest
/// exists so a model call can reference content it was not given, and
/// normalizing would make two genuinely different contents share one reference.
///
/// The class is in the tuple, so the same bytes seen as a matched span and as a
/// whole file are distinct identities — they are different claims about what was
/// withheld.
#[must_use]
pub fn judge_fingerprint(class: &str, bytes: &[u8]) -> Fingerprint {
    tagged_fingerprint(JUDGE_TAG, &[class.as_bytes(), bytes])
}

/// The identity of a **file surface**: an ordered set of `(path, contents)`
/// pairs — the `config_epoch`'s construction (CLOUD-32).
///
/// Not a finding, so it carries its own domain tag rather than a
/// [`FindingKind`]; it reuses the framing above rather than minting a second
/// hash of the same bytes.
///
/// Text content is canonicalized like a span — NFC, `LF` line endings, no
/// trailing-whitespace collapse — so the same policy checked out on Windows or
/// macOS attributes identically. Content that is not valid UTF-8 is hashed
/// verbatim: there is nothing to normalize, and refusing it would make the
/// tracked set silently text-only.
///
/// The path is hashed as well as the bytes, so the *set* is part of the
/// identity: adding an empty file still moves the value.
#[must_use]
pub fn surface_fingerprint(entries: &[(String, Vec<u8>)]) -> Fingerprint {
    let normalized: Vec<(Vec<u8>, Vec<u8>)> = entries
        .iter()
        .map(|(path, contents)| {
            let content = match std::str::from_utf8(contents) {
                Ok(text) => normalize_span(text, SpanNormalization::Verbatim).into_bytes(),
                Err(_) => contents.clone(),
            };
            (path.as_bytes().to_vec(), content)
        })
        .collect();
    let fields: Vec<&[u8]> = normalized
        .iter()
        .flat_map(|(path, content)| [path.as_slice(), content.as_slice()])
        .collect();
    tagged_fingerprint(SURFACE_TAG, &fields)
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

    // -- secret-class keying and the split-only override (CLOUD-123). ---------

    /// A length-prefixed field, restated here rather than reused from the module
    /// so the preimage assertion below fails when the *construction* changes,
    /// instead of recording whatever it currently emits.
    fn field(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn key(id: &str, seed: u8) -> IdentityKey {
        IdentityKey::new(id, [seed; 32])
    }

    const SECRET_SPAN: &str = "token = \"hunter2\"";

    #[test]
    fn the_same_span_under_two_keys_is_two_identities() {
        // The point of keying: someone holding a stored digest must not be able
        // to confirm a guess at the secret it came from, and a second holder of
        // the same secret must not produce the same digest.
        let one = secret_code_fingerprint(
            &key("k1", 1),
            "r",
            "src/a.rs",
            SECRET_SPAN,
            SpanNormalization::Verbatim,
        )
        .unwrap();
        let two = secret_code_fingerprint(
            &key("k2", 2),
            "r",
            "src/a.rs",
            SECRET_SPAN,
            SpanNormalization::Verbatim,
        )
        .unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn a_keyed_identity_never_collides_with_an_unkeyed_one() {
        // Distinct domain tags, so total agreement on every other field still
        // cannot make a secret-class identity equal a plain code one.
        let keyed = secret_code_fingerprint(
            &key("k1", 1),
            "r",
            "src/a.rs",
            SECRET_SPAN,
            SpanNormalization::Verbatim,
        )
        .unwrap();
        let plain =
            code_fingerprint("r", "src/a.rs", SECRET_SPAN, SpanNormalization::Verbatim).unwrap();
        assert_ne!(keyed, plain);
    }

    #[test]
    fn the_same_key_and_span_is_one_stable_identity() {
        // Keying must not cost stability: a re-observation of the same secret in
        // the same place is the same finding, or every scan would re-raise it.
        let mint = || {
            secret_code_fingerprint(
                &key("k1", 1),
                "r",
                "src/a.rs",
                SECRET_SPAN,
                SpanNormalization::Verbatim,
            )
            .unwrap()
        };
        assert_eq!(mint(), mint());
    }

    #[test]
    fn the_keyed_preimage_is_the_one_construction() {
        // Hand-built preimage rather than a golden hex string, so this fails if
        // the construction changes rather than recording what it emits today.
        let content = normalize_span(SECRET_SPAN, SpanNormalization::Verbatim);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[1u8; 32]).unwrap();
        mac.update(content.as_bytes());
        let inner: [u8; 32] = mac.finalize().into_bytes().into();

        let mut hasher = Sha256::new();
        for part in [
            field(b"secret"),
            field(b"r"),
            field(b"src/a.rs"),
            field(b"k1"),
            field(&inner),
        ] {
            hasher.update(&part);
        }
        let expected: [u8; 32] = hasher.finalize().into();

        let got = secret_code_fingerprint(
            &key("k1", 1),
            "r",
            "src/a.rs",
            SECRET_SPAN,
            SpanNormalization::Verbatim,
        )
        .unwrap();
        assert_eq!(got.to_hex(), Fingerprint(expected).to_hex());
    }

    #[test]
    fn an_identity_key_does_not_render_its_bytes() {
        // A derived Debug prints a [u8; 32] as decimals, so key material would
        // reach any error or trace that formatted a value carrying a key.
        let rendered = format!("{:?}", key("k1", 0xAB));
        assert!(
            rendered.contains("k1"),
            "the id is a coordinate and stays readable"
        );
        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains("171"),
            "no key byte in any rendering: {rendered}"
        );
    }

    #[test]
    fn an_override_cannot_merge_two_default_identities() {
        // The split-only law. A force-merge is not a rejected configuration, it
        // is unconstructable: the default is a field of the override's preimage.
        let a = code_fingerprint("r", "src/a.rs", "x", SpanNormalization::Collapsed).unwrap();
        let b = code_fingerprint("r", "src/b.rs", "x", SpanNormalization::Collapsed).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            override_fingerprint(a, "same"),
            override_fingerprint(b, "same"),
            "one discriminator over two defaults stays two identities"
        );
    }

    #[test]
    fn an_override_fragments_a_group_and_is_never_the_default() {
        let default = code_fingerprint("r", "src/a.rs", "x", SpanNormalization::Collapsed).unwrap();
        assert_ne!(
            override_fingerprint(default, "one"),
            override_fingerprint(default, "two"),
            "two discriminators fragment one default"
        );
        // An overridden identity is distinguishable from a default one, so a
        // store cannot silently adopt the override as the group it replaced.
        assert_ne!(override_fingerprint(default, ""), default);
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
