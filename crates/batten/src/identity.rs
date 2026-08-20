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
//! HMAC carries no work factor, so this buys separation and not difficulty: it
//! holds only while the key is unreachable from the journal it protects.
//! The key is supplied by the caller: this module mints and stores nothing, and
//! custody (minting on first need, rotation, the loud orphan event on key loss)
//! belongs to [`crate::secrets`] and to the store. Wave one is mint plus keyed
//! emission (CLOUD-59); rotation and orphan custody are CLOUD-529's.
//!
//! **Which span is keyed is settled by a type, not by recall.**
//! [`secret_code_fingerprint`] takes a [`SecretSpan`] — an opaque wrapper minted
//! at a scanner adapter's parse boundary with no route back to `&str` — so
//! handing a secret span to the unkeyed [`code_fingerprint`] does not compile.
//! An earlier reading here said recall was "the control keying does not supply";
//! that was true while both functions took `&str`, and it is what CLOUD-59
//! replaced. Recall still decides whether a secret is **reported**; it no longer
//! decides whether a reported one is **keyed**.
//!
//! # Per-rule overrides are split-only, by construction
//!
//! [`override_fingerprint`] hashes the default identity *as a field*, so for two
//! spans with different default identities no colliding preimage exists under any
//! discriminator. An override can fragment a group, and merging two would take a
//! SHA-256 collision rather than a chosen discriminator — the property a rule
//! author must be held to, made a property of the function rather than of a
//! config check that could be bypassed.
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

// `KeyInit` through `hmac::digest` rather than `hmac` itself: `hmac` re-exports
// the `digest` crate and `Mac`, but not the constructor trait (CLOUD-767). The
// path is the same in both major lines of the hashing substrate, which is what
// lets this file compile against either.
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
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
    /// Every kind, so anything ranging over them is derived rather than
    /// re-typed — the vocabulary idiom [`crate::hook::Event`],
    /// [`crate::hook::Harness`] and [`crate::findings::Disposition`] already
    /// use. [`FindingKind::from_tag`] reads it, so a fifth kind cannot land
    /// with a parse that silently does not know it.
    pub const ALL: &'static [FindingKind] = &[
        FindingKind::Code,
        FindingKind::Log,
        FindingKind::Scope,
        FindingKind::Sequence,
    ];

    /// The kind named by `tag`, or `None` if it names none.
    ///
    /// Derived from [`FindingKind::ALL`] and [`FindingKind::as_tag`], so the
    /// accepted spellings are exactly the emitted ones by construction.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<FindingKind> {
        FindingKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_tag() == tag)
    }

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

impl Fingerprint {
    /// Parse the 64-character lowercase hex form back into a fingerprint.
    ///
    /// The inverse of [`Fingerprint::to_hex`], and it exists because a store has
    /// to read its own keys back. Strict on purpose — exactly 64 characters, and
    /// lowercase only: uppercase hex would round-trip to the same bytes but a
    /// *different string*, and the store's on-disk keys and its sort order are
    /// both the string. Accepting both spellings would let one identity occupy
    /// two filenames.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] when `hex` is not 64 lowercase hex characters.
    pub fn from_hex(hex: &str) -> anyhow::Result<Fingerprint> {
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(UsageError::raise(format!(
                "not a fingerprint: expected 64 lowercase hex characters, got {:?}",
                hex.chars().take(72).collect::<String>()
            )));
        }
        let mut bytes = [0u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            // Each nibble is already known to be a hex digit by the guard above,
            // so the fold cannot fail; `?` keeps the path total regardless.
            let high = char::from(pair[0]).to_digit(16).unwrap_or(0);
            let low = char::from(pair[1]).to_digit(16).unwrap_or(0);
            // Both nibbles are < 16, so the assembled byte cannot exceed 0xff.
            bytes[index] = u8::try_from(high * 16 + low).unwrap_or(0);
        }
        Ok(Fingerprint(bytes))
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Fingerprint, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Fingerprint::from_hex(&hex).map_err(de::Error::custom)
    }
}

/// A minted identity as it travels and as it is stored: the fingerprint, plus
/// the per-kind version that produced it.
///
/// **The version rides beside the hash, never inside it.** That asymmetry is
/// what makes a migration possible at all: an equality-join needs two extractor
/// versions to produce comparable hashes for the same span, which a version
/// hashed into the preimage would make impossible by construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StoredIdentity {
    /// The fingerprint itself.
    pub fingerprint: Fingerprint,
    /// The [`FindingKind::identity_version`] of the function that minted it.
    pub version: String,
}

impl StoredIdentity {
    /// Pair a freshly minted fingerprint with its kind's current version.
    #[must_use]
    pub fn new(kind: FindingKind, fingerprint: Fingerprint) -> Self {
        StoredIdentity {
            fingerprint,
            version: kind.identity_version().to_owned(),
        }
    }

    /// Pair a freshly minted **secret-class** fingerprint with its version.
    ///
    /// Separate from [`StoredIdentity::new`] because the secret class has no
    /// [`FindingKind`] to read a version off — see [`SECRET_IDENTITY_VERSION`]
    /// for why that absence is the design and not a gap. Taking the fingerprint
    /// by value keeps this a pairing rather than a mint: the only thing that can
    /// produce the fingerprint is [`secret_code_fingerprint`], which cannot run
    /// without a key.
    #[must_use]
    pub fn secret(fingerprint: Fingerprint) -> Self {
        StoredIdentity {
            fingerprint,
            version: SECRET_IDENTITY_VERSION.to_owned(),
        }
    }

    /// The kind that minted this identity, recovered from the version's tag.
    ///
    /// [`FindingKind::identity_version`] is `<tag>:<date>`, so the tag is
    /// recoverable without a second stored field — and it must be, because the
    /// changed-scope filter is a **per-kind** rule (code-anchored kinds are
    /// filtered, sequence/log/scope kinds bypass it unconditionally) and the
    /// store persists a record's version rather than its kind.
    ///
    /// `None` for a version whose tag names no kind this binary knows: a record
    /// written by a future binary carrying a fifth kind. Callers must read that
    /// as "cannot classify", never as a default kind — guessing `Code` there
    /// would scope-filter away a finding whose kind is meant to bypass.
    #[must_use]
    pub fn kind(&self) -> Option<FindingKind> {
        let tag = self.version.split(':').next()?;
        FindingKind::from_tag(tag)
    }

    /// Whether this identity was minted under a **key** — the secret class.
    ///
    /// [`StoredIdentity::kind`] answers `None` here, and deliberately keeps
    /// answering `None`: the question that method exists for is the changed-scope
    /// filter's, and "cannot classify" is the honest answer to it (see
    /// [`SECRET_IDENTITY_VERSION`]). But key custody asks a *different* question —
    /// is this record replayable only while a key is held — and `None` cannot
    /// answer it, because a future fifth kind would answer `None` too and is
    /// replayable by re-scanning like any other unkeyed identity. Reading the two
    /// off one method would put a custody decision on a value that means "I do not
    /// know", which is how a key-loss orphan would either be missed or be
    /// manufactured out of a version this binary simply has not met (CLOUD-529).
    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.version == SECRET_IDENTITY_VERSION
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

/// Fingerprint a repository **checkout** by its canonical absolute root
/// (CLOUD-296), so two checkouts sharing a directory name address different
/// out-of-tree state.
///
/// The mirror image of [`canonical_repo_path`], and deliberately not a reuse of
/// it: that function normalizes a path *inside* a repository and refuses an
/// absolute one, because a finding's identity must not depend on where the
/// checkout lives. This one asks the opposite question — *which checkout is
/// this* — for which the location is the only answer that separates two clones
/// of one repository. Two functions stating opposite halves of one rule, in the
/// module that owns normalization, rather than a third scheme somewhere else.
///
/// Normalization matches its sibling's where the questions overlap: `\` becomes
/// `/` and the result is NFC, so a macOS NFD path and a Linux NFC one agree. A
/// trailing separator is dropped, because `/a/repo` and `/a/repo/` are one
/// checkout.
///
/// **No filesystem access.** Resolving symlinks would make this impure, fail for
/// a path that does not exist, and answer differently depending on when it ran —
/// none of which a state path may do (§6).
///
/// # Errors
///
/// Returns a [`UsageError`] for a relative or empty root — the exact refusal
/// [`canonical_repo_path`] makes for an absolute one.
pub fn checkout_fingerprint(repo_root: &std::path::Path) -> anyhow::Result<Fingerprint> {
    let raw = repo_root.to_str().ok_or_else(|| {
        UsageError::raise(format!(
            "checkout root is not UTF-8: {}",
            repo_root.display()
        ))
    })?;
    let slashed = raw.replace('\\', "/");
    // Windows' extended-length prefix is a SPELLING of a path, not a different
    // path, and dropping it belongs to the same rule as dropping a trailing
    // separator below: one checkout, one fingerprint. `fs::canonicalize` returns
    // `\\?\C:\x` where git and the shell both say `C:\x`, and `\\?\UNC\srv\share`
    // for `\\srv\share`. CLOUD-113's Windows job measured the consequence — a
    // caller that canonicalized and one that did not addressed two different
    // state roots for one repository, and four cases failed reading a directory
    // nothing had created. Still no filesystem access: this is string
    // normalization, exactly like the NFC pass.
    let slashed = match slashed.strip_prefix("//?/") {
        Some(rest) => match rest.strip_prefix("UNC/") {
            Some(share) => format!("//{share}"),
            None => rest.to_owned(),
        },
        None => slashed,
    };
    let trimmed = slashed.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(UsageError::raise("checkout root is empty"));
    }
    let mut chars = slashed.chars();
    let drive_absolute = matches!(
        (chars.next(), chars.next()),
        (Some(drive), Some(':')) if drive.is_ascii_alphabetic()
    );
    if !slashed.starts_with('/') && !drive_absolute {
        return Err(UsageError::raise(format!(
            "checkout root must be absolute, got {raw:?}"
        )));
    }
    let canonical: String = trimmed.nfc().collect();
    Ok(tagged_fingerprint(CHECKOUT_TAG, &[canonical.as_bytes()]))
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

/// The domain tag for a repository **checkout's location** (CLOUD-296), distinct
/// from [`CAPTURE_TAG`] above all: those two answer adjacent questions — "which
/// bytes are these" and "which checkout produced them" — and a shared tag would
/// let one be mistaken for the other in exactly the place the distinction is
/// load-bearing.
const CHECKOUT_TAG: &str = "checkout";

/// The domain tag for the **context** a guard decision was taken in (CLOUD-133),
/// distinct from every other tag here for the reason they are all distinct.
///
/// It matters for the same reason [`JUDGE_TAG`] does: the hash stands in for
/// content the record deliberately does **not** carry, so a collision with a
/// capture or a finding identity would let a context digest be mistaken for one
/// of those and joined against it.
const CONTEXT_TAG: &str = "context";

/// The domain tag for a **secret-class** identity, distinct from every
/// [`FindingKind`] tag and from [`SURFACE_TAG`]/[`CAPTURE_TAG`] for the same
/// reason those two are distinct from each other: a keyed identity and an
/// unkeyed one must not collide even when every other field agrees.
const SECRET_TAG: &str = "secret";

/// The identity-function version recorded beside a **secret-class** fingerprint
/// (CLOUD-59), date-styled for the reason [`FindingKind::identity_version`]'s
/// arms are: a bump reads as an event rather than a counter.
///
/// **It is a version, not a [`FindingKind`] variant**, and the distinction is
/// deliberate rather than incidental. A fifth kind would be an assertion about
/// the *changed-scope filter* — [`StoredIdentity::kind`] exists to answer that
/// one question — and the honest answer for a secret-class record is that this
/// binary cannot classify it: the filter is a control over code-anchored
/// findings, and a secret-class identity is a code anchor whose replayability
/// depends on key custody rather than on the tree (see
/// [`secret_code_fingerprint`]). `kind()` therefore answers `None` here, which
/// its own contract already defines as "cannot classify, do not default" — the
/// fail-open-in-reporting direction [`crate::drain`] documents. The kind
/// variant lands with the store journaling that gives it something to decide
/// (CLOUD-529).
const SECRET_IDENTITY_VERSION: &str = "secret:2026-08-13";

/// The domain tag for a per-rule identity **override**.
const OVERRIDE_TAG: &str = "override";

/// The domain tag for an advisory **drain result** (CLOUD-79/166), distinct from
/// every other tag for the reason they are all distinct from each other: a
/// result id summarizes a whole finding-set, and a collision with any single
/// finding's identity would let a set be mistaken for a member of itself.
const DRAIN_TAG: &str = "drain";

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

/// The identity of a whole **drain result**: the ordered set of pointer lines a
/// drain cycle would emit (CLOUD-79's `resultId` short-circuit, CLOUD-166).
///
/// Not a finding, so it carries its own domain tag rather than a
/// [`FindingKind`]; it reuses the length-prefixed framing above rather than
/// minting a second hash of the same bytes.
///
/// **Over the rendered pointers, deliberately, and not over the store.** The
/// question the short-circuit asks is "would this drain say anything the last
/// one did not", so the digest has to be a function of exactly what would be
/// emitted. A digest over the store's whole contents would move on a change the
/// scope filter drops, re-emitting an identical payload; one over identities
/// alone would miss a count that changed, which is the re-raise the drain exists
/// to surface.
///
/// Order participates, because the emission is ordered: two payloads differing
/// only in line order are different bytes, and the caller sorts before hashing
/// precisely so that never happens by accident.
#[must_use]
pub fn drain_result_fingerprint(lines: &[String]) -> Fingerprint {
    let fields: Vec<&[u8]> = lines.iter().map(std::string::String::as_bytes).collect();
    tagged_fingerprint(DRAIN_TAG, &fields)
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

/// The opaque span type, in its own module so its field has exactly one reader.
///
/// Rust has no friend declaration, so "only the keyed path may see these bytes"
/// is expressed as a visibility boundary: the tuple field is private to this
/// module, and the one accessor is `pub(super)` — visible to [`crate::identity`]
/// and to nothing else in the crate, let alone outside it. A module rather than
/// a bare newtype beside the rest is what buys that; declared alongside its
/// siblings the field would be readable by every function in this file,
/// including the unkeyed one it exists to keep away from.
mod secret_span {
    /// A span a classifier has judged secret-bearing.
    ///
    /// **This type is the routing control** (CLOUD-59). The hazard it closes is
    /// not a mistyped argument list but a call to the wrong function: a secret
    /// span reaching [`super::code_fingerprint`] becomes an unkeyed digest of
    /// low-entropy content in a journal that cannot be expunged. That function
    /// takes `&str`, this type is not a `&str` and offers no route to one, so
    /// the mis-route is a type error rather than a recall obligation.
    ///
    /// What it deliberately does **not** have, each absence load-bearing:
    ///
    /// - no `Debug`, `Display`, or `Serialize` — a rendering is how the bytes
    ///   reach a log line, an error, or a `-J` document;
    /// - no `Deref`, `AsRef<str>`, `Into<String>`, or public accessor — any of
    ///   them would hand the span back as a `&str` and re-open the mis-route the
    ///   type exists to close;
    /// - no `Clone` — nothing needs a second copy, and each one is a byte of
    ///   secret material with a longer life.
    ///
    /// `missing_debug_implementations` is allowed here for exactly that reason:
    /// the lint asks for a rendering, and the refusal to have one is the point.
    #[allow(missing_debug_implementations)]
    pub struct SecretSpan(String);

    impl SecretSpan {
        /// Wrap a span at the parse boundary.
        ///
        /// **Public, and it has to be**: [`super::secret_code_fingerprint`] is
        /// public and takes one of these, so a crate-private mint would leave
        /// that function uncallable by any consumer — an API taking a type
        /// nobody outside can construct is not an API. An earlier draft made it
        /// `pub(crate)` on the intuition that minting should belong to the
        /// adapter; the compiler disagreed twice over (the function became
        /// unreachable, and `mint` itself read as dead code).
        ///
        /// Nothing is lost by opening it, because **the guarantee this type
        /// carries is about routing, not about minting**. Whoever wraps a span
        /// still cannot unwrap it, and still cannot spend it anywhere but the
        /// keyed path. Restricting who may mint one would protect nothing that
        /// the absent conversions do not already protect.
        #[must_use]
        pub fn mint(span: &str) -> SecretSpan {
            SecretSpan(span.to_owned())
        }

        /// The bytes, for the one function permitted to read them.
        ///
        /// `pub(super)` is the whole enforcement: [`super::secret_code_fingerprint`]
        /// can call this and no other module can. `tests/primitives.rs` pins that
        /// the unkeyed path does not, since a same-file caller is the one thing
        /// visibility cannot rule out.
        pub(super) fn keying_input(&self) -> &str {
            &self.0
        }
    }
}

pub use secret_span::SecretSpan;

/// The identity of a **secret-class** code-anchored finding:
/// `(secret, rule_id, canonical_path, key_id, hmac(key, normalized_span))`.
///
/// The span is replaced by its HMAC rather than hashed directly — see the module
/// doc on why an unkeyed digest of a secret is an oracle. Keying costs nothing in
/// stability: the same secret at the same place fingerprints identically under
/// the same key.
///
/// **Keying is worth nothing if the key lives where the digests live.** HMAC
/// carries no work factor, so the protection is all-or-nothing: whoever can read
/// both the journal and the key can run the same full-speed offline guess the
/// unkeyed digest would have allowed. The invariant the custody contract owes this
/// function is that the key is *not* reachable from the store it protects.
///
/// **The key id is inside the preimage.** Not because it does work the HMAC does
/// not — a rotation re-mints through the HMAC alone — but because it makes the
/// identity self-describing about which key generation minted it, and that is the
/// decided custody contract (CLOUD-59): a store holding identities from two
/// generations can separate them in the tuple rather than only in metadata, and
/// dual-HMAC rotation has something to name the pair by. The id is a
/// caller-chosen label, so two keys sharing one id would be conflated in the
/// preimage; keeping ids unique per key generation is the custody contract's job,
/// not this function's.
///
/// This does not contradict the version-beside-the-hash rule above, which is about
/// an *extractor* version: that stays out of the preimage so two versions can
/// produce comparable hashes for the migration equality-join, whereas a key
/// rotation is meant to re-mint.
///
/// **The version coordinate a store records beside this is
/// [`SECRET_IDENTITY_VERSION`]**, paired by [`StoredIdentity::secret`]. An
/// earlier reading here said it was [`FindingKind::Code`]'s, on the ground that a
/// secret-class finding is the code kind with its span keyed; that is right about
/// the *tuple* and wrong about the *version*, because the two evolve
/// independently — a change to the keying construction must be able to bump this
/// without re-versioning every unkeyed code identity, and the paragraph below on
/// replayability is precisely a law that holds for one and not the other.
/// [`override_fingerprint`] still inherits the version of whichever kind produced
/// the default it wraps. Neither mints a version of its own, and a store must not
/// invent one.
///
/// **But the version does not settle replayability, and for this kind that is a
/// separate question.** The migration law above partitions on whether a scan can
/// be replayed, and it puts the code kind in the replayable half — re-scan the
/// authoritative context, equality-join old hash to new. A secret-class identity
/// is replayable **only while the key that minted it is still held**: the span
/// comes back from the re-scan, the old HMAC does not come back without the old
/// key. So an orphaned key moves those identities into the non-replayable half,
/// where a version bump must never close, GC, or re-mint them — the loud orphan
/// event, not a silent migration. A store reading [`SECRET_IDENTITY_VERSION`] off
/// a record must therefore check key custody before treating a bump as
/// replayable.
///
/// **The routing is structural now, and that is what changed here (CLOUD-59).**
/// A secret-tagged identity could never be minted without a key — that much the
/// signature always bought — but a span was keyed only if a classifier chose to
/// send it here, while [`code_fingerprint`] sat public and hashed the same
/// `(rule_id, repo_path, span)` unkeyed. The hazard was never a mistyped argument
/// list; it was a call to the wrong function, which no signature could catch
/// while both took `&str`. [`SecretSpan`] catches it: the span this takes is a
/// type with no route back to `&str`, so handing it to the unkeyed function does
/// not compile, and the adapter holds no raw span after its parse. Classifier
/// recall is still what decides whether a secret is *reported*, but a recall miss
/// is now a missed finding rather than an unkeyed digest of a secret in a journal
/// — which is the whole point of moving the control from discipline to the type
/// system.
///
/// # Errors
///
/// Returns a [`UsageError`] (exit `1`) when `repo_path` is not a clean
/// repo-relative path (see [`canonical_repo_path`]). The unreachable HMAC
/// key-length branch in [`keyed_span`] surfaces instead as a plain internal error
/// (exit `3`) — both classes reach a caller of this function, and they are not the
/// same answer.
pub fn secret_code_fingerprint(
    key: &IdentityKey,
    rule_id: &str,
    repo_path: &str,
    span: &SecretSpan,
) -> anyhow::Result<Fingerprint> {
    let path = canonical_repo_path(repo_path)?;
    // Verbatim, and not the caller's choice: a secret *is* literal content, so
    // this is exactly the narrowed-literal case the canonicalization law already
    // assigns to [`SpanNormalization::Verbatim`]. Collapsing would fold two
    // secrets differing only in whitespace into one identity, and for this kind a
    // false merge hides the second secret behind the first — strictly worse than
    // the false split a collapse is meant to avoid.
    let content = normalize_span(span.keying_input(), SpanNormalization::Verbatim);
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
/// HMAC accepts a key of any length, so the length error cannot occur for a fixed
/// 32-byte key. It is mapped rather than unwrapped because library code carries no
/// panic path — and mapped to a plain internal error (exit `3`) rather than a
/// [`UsageError`] (exit `1`), because an unreachable invariant breaking is Batten's
/// fault, never the caller's malformed input.
fn keyed_span(key: &IdentityKey, content: &str) -> anyhow::Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key.bytes).map_err(|_| {
        anyhow::anyhow!("identity: a 32-byte HMAC key was rejected as a key length")
    })?;
    mac.update(content.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Apply a per-rule identity override to a default identity.
///
/// **Split-only by construction, not by validation.** The default fingerprint is
/// itself a field of the preimage, so for two spans with different default
/// identities **no colliding preimage exists** under any discriminator — an
/// override can fragment a group, and merging two would take a SHA-256 collision
/// rather than a chosen discriminator. That is a stronger guarantee than a config
/// check, which could be bypassed, and a weaker one than "impossible": it inherits
/// the hash's collision resistance and claims nothing beyond it.
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

/// The identity of the **context a guard decision was taken in** (CLOUD-133).
///
/// The one sanctioned way for a caller to point at context, and the reason it
/// lives here rather than in [`crate::decision`]: a record that accepted context
/// *bytes* would have to hash them itself, which is the second, divergent
/// construction over the same bytes that CLOUD-123 forbids. Handing the caller a
/// fingerprint instead keeps [`crate::decision`] structurally incapable of
/// holding a payload — it is never given one.
///
/// Bytes are hashed **verbatim**, like a capture and a judge payload and unlike
/// a span: the digest exists so a consumer can reference context it was not
/// given, and normalizing would make two genuinely different contexts share one
/// reference.
///
/// There is no class field, unlike [`judge_fingerprint`]: a decision record has
/// exactly one context, so a discriminator would have nothing to discriminate.
#[must_use]
pub fn context_fingerprint(bytes: &[u8]) -> Fingerprint {
    tagged_fingerprint(CONTEXT_TAG, &[bytes])
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

    #[test]
    fn a_checkout_is_fingerprinted_by_where_it_is_and_refuses_a_relative_root() {
        use std::path::Path;

        // The mirror image of the case above, asserted together with it on
        // purpose: `canonical_repo_path` refuses an ABSOLUTE path because a
        // finding's identity must not depend on where the checkout lives, and
        // `checkout_fingerprint` refuses a RELATIVE one because a checkout's
        // identity is precisely where it lives (CLOUD-296). Two halves of one
        // rule; a reader who finds only one of them will reach for the wrong
        // function.
        let here = checkout_fingerprint(Path::new("/work/batten")).unwrap();
        let there = checkout_fingerprint(Path::new("/scratch/batten")).unwrap();
        assert_ne!(
            here, there,
            "the same directory name in two places is two checkouts"
        );

        // Deterministic, and insensitive to the spellings that name one tree.
        assert_eq!(
            here,
            checkout_fingerprint(Path::new("/work/batten")).unwrap()
        );
        assert_eq!(
            here,
            checkout_fingerprint(Path::new("/work/batten/")).unwrap(),
            "a trailing separator names the same checkout"
        );
        assert_eq!(
            checkout_fingerprint(Path::new("/repo/caf\u{e9}")).unwrap(),
            checkout_fingerprint(Path::new("/repo/cafe\u{301}")).unwrap(),
            "an NFD checkout path and its NFC form are one checkout, as they are \
             for a repo-relative path"
        );

        for relative in ["batten", "./batten", "some/repo", ""] {
            assert!(
                checkout_fingerprint(Path::new(relative)).is_err(),
                "{relative:?} names a different tree from each directory it is read \
                 in, so it cannot identify a checkout"
            );
        }
        // A Windows drive-absolute root is absolute, so it is accepted.
        assert!(checkout_fingerprint(Path::new("C:\\repo\\batten")).is_ok());

        // ...and the extended-length prefix is one more spelling, not one more
        // tree (CLOUD-113). `fs::canonicalize` returns it on Windows where git
        // and the shell do not, so a caller that canonicalized and one that did
        // not must still address one state root. Measured as four cases reading
        // a directory nothing had created.
        assert_eq!(
            checkout_fingerprint(Path::new("C:\\repo\\batten")).unwrap(),
            checkout_fingerprint(Path::new("\\\\?\\C:\\repo\\batten")).unwrap(),
            "the extended-length prefix names the same checkout"
        );
        assert_eq!(
            checkout_fingerprint(Path::new("\\\\srv\\share\\batten")).unwrap(),
            checkout_fingerprint(Path::new("\\\\?\\UNC\\srv\\share\\batten")).unwrap(),
            "and so does its UNC form"
        );
    }

    // -- The kind discriminator prevents cross-kind collisions. --
    #[test]
    fn kind_tag_prevents_cross_kind_collision() {
        let scope = scope_fingerprint("r", "x");
        let sequence = sequence_fingerprint("r", "x", None);
        assert_ne!(scope, sequence, "same field bytes, different kinds");
    }

    #[test]
    fn a_context_digest_cannot_collide_with_another_domain_over_the_same_bytes() {
        // CLOUD-133: the digest stands in for content the decision record
        // deliberately does not carry, so it must not be mistakable for a
        // capture, a judge payload, or a surface over the same bytes and be
        // joined against one.
        let bytes = b"the same bytes seen four ways";
        let context = context_fingerprint(bytes);
        assert_ne!(context, capture_fingerprint("", bytes));
        assert_ne!(context, judge_fingerprint("", bytes));
        assert_ne!(
            context,
            surface_fingerprint(&[(String::new(), bytes.to_vec())])
        );
        // And it is a pure function of those bytes, verbatim: whitespace is
        // context, not noise.
        assert_eq!(context, context_fingerprint(bytes));
        assert_ne!(context, context_fingerprint(b"the same bytes seenfourways"));
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

    /// The span as the keyed path now takes it. A helper rather than a constant
    /// because [`SecretSpan`] is deliberately not `Clone` — each call mints its
    /// own, which is also what a real parse does per match.
    fn span() -> SecretSpan {
        SecretSpan::mint(SECRET_SPAN)
    }

    #[test]
    fn the_same_span_under_two_keys_is_two_identities() {
        // Two holders of the same secret mint different identities, so a digest
        // taken from one store confirms nothing about a guess made against
        // another.
        let one = secret_code_fingerprint(&key("k1", 1), "r", "src/a.rs", &span()).unwrap();
        let two = secret_code_fingerprint(&key("k2", 2), "r", "src/a.rs", &span()).unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn a_keyed_identity_never_collides_with_an_unkeyed_one() {
        // Distinct domain tags, so total agreement on every other field still
        // cannot make a secret-class identity equal a plain code one.
        //
        // The unkeyed side is spelled with the raw `&str` on purpose: that call
        // is the mis-route this module now makes unrepresentable for a
        // `SecretSpan`, and writing it out is what shows the two paths are
        // distinguishable at all. Passing `&span()` there is a compile error, and
        // `a_secret_span_offers_no_route_back_to_a_str` below is that claim's gate.
        let keyed = secret_code_fingerprint(&key("k1", 1), "r", "src/a.rs", &span()).unwrap();
        let plain =
            code_fingerprint("r", "src/a.rs", SECRET_SPAN, SpanNormalization::Verbatim).unwrap();
        assert_ne!(keyed, plain);
    }

    #[test]
    fn the_same_key_and_span_is_one_stable_identity() {
        // Keying must not cost stability: a re-observation of the same secret in
        // the same place is the same finding, or every scan would re-raise it.
        let mint = || secret_code_fingerprint(&key("k1", 1), "r", "src/a.rs", &span()).unwrap();
        assert_eq!(mint(), mint());
    }

    #[test]
    fn a_secret_class_identity_carries_its_own_version_and_no_kind() {
        // Two claims in one, because they are the same decision: the secret class
        // versions independently of the code kind, and it deliberately answers
        // `None` to `kind()` rather than impersonating `Code` — which the
        // changed-scope filter reads as "cannot classify" and bypasses, the
        // fail-open-in-reporting direction.
        let stored = StoredIdentity::secret(
            secret_code_fingerprint(&key("k1", 1), "r", "src/a.rs", &span()).unwrap(),
        );
        assert_eq!(stored.version, SECRET_IDENTITY_VERSION);
        assert_ne!(stored.version, FindingKind::Code.identity_version());
        assert_eq!(stored.kind(), None);
    }

    #[test]
    fn a_secret_span_offers_no_route_back_to_a_str() {
        // The routing control, asserted over the source rather than the value:
        // the guarantee is the ABSENCE of a conversion, and an absence has no
        // runtime witness. `keying_input` is `pub(super)`, so the compiler already
        // refuses every module but this one; what it cannot refuse is a
        // same-file caller, and the unkeyed function is in this file.
        //
        // Same idiom as `tests/primitives.rs`'s body greps. `\n}\n` is the
        // column-zero close, so the slice is exactly one function body — but
        // only once the source is read in one line-ending shape, and only if a
        // missing terminator is an error rather than an answer. Both halves are
        // CLOUD-612, and both are load-bearing:
        //
        //   * `include_str!` embeds the WORKING TREE's bytes, and a Windows
        //     checkout takes `core.autocrlf=true`. Measured on the first Windows
        //     run this repository ever did: the `code_fingerprint` slice went
        //     from 309 characters to 18302 — the rest of the file — and this
        //     gate reported `SecretSpan` in a function that does not name it.
        //   * `split(…).next()` cannot tell "found the terminator" from "no
        //     terminator, here is everything", so it reports the second as a
        //     body. `split_once` makes that state unrepresentable. The failure
        //     is loud here only because these assertions are negative; the same
        //     widening passes any "must CONTAIN x" gate vacuously.
        //
        // Normalizing is a no-op on an LF checkout, so no verdict here moves.
        //
        // Comments are stripped first, and that is not tidiness: the wrapper's
        // own doc comment *lists* the conversions it refuses, so a scan over raw
        // source matches the prose describing the absence and reports it as the
        // presence. Measured — this test failed on its own documentation before
        // the strip went in. A gate that reads its own prose is measuring the
        // wrong text.
        let code = |text: &str| -> String {
            text.lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let source = include_str!("identity.rs").replace("\r\n", "\n");
        for name in [
            "pub fn code_fingerprint",
            "pub fn log_fingerprint",
            "pub fn scope_fingerprint",
        ] {
            let Some((declared, _)) = source
                .split_once(name)
                .and_then(|(_, rest)| rest.split_once("\n}\n"))
            else {
                panic!("{name} is declared in this module, and its body ends at a column-zero `}}`")
            };
            let body = code(declared);
            assert!(
                !body.contains("keying_input"),
                "{name} reads a secret span's bytes; only the keyed path may"
            );
            assert!(
                !body.contains("SecretSpan"),
                "{name} names the secret span type; the unkeyed path must not"
            );
        }

        // And the escapes a derive would have added, checked where they would be
        // written rather than inferred from their absence in the impl block.
        let Some((wrapper_body, _)) = source
            .split_once("mod secret_span {")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
        else {
            panic!("mod secret_span is in this file, and its body ends at a column-zero `}}`")
        };
        let wrapper = code(wrapper_body);
        for escape in [
            "impl Deref",
            "AsRef<str>",
            "derive(",
            "fn as_str",
            "Display",
        ] {
            assert!(
                !wrapper.contains(escape),
                "a secret span must offer no `{escape}` route back to its bytes"
            );
        }
    }

    #[test]
    fn the_keyed_preimage_is_the_one_construction() {
        // Hand-built preimage rather than a golden hex string, so this fails if
        // the construction changes rather than recording what it emits today.
        let content = normalize_span(SECRET_SPAN, SpanNormalization::Verbatim);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[1u8; 32]).unwrap();
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

        let got = secret_code_fingerprint(&key("k1", 1), "r", "src/a.rs", &span()).unwrap();
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
    fn an_override_has_no_colliding_preimage_for_two_defaults() {
        // The split-only law, in the strength the construction actually gives: the
        // default is a field of the override's preimage, so no colliding preimage
        // exists and merging two would take a SHA-256 collision. Not
        // "unconstructable" — that overstates it, and the assertion below is a
        // preimage-inequality check rather than a proof of impossibility.
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
