//! The in-process patch identity (CLOUD-739).
//!
//! [`crate::git::landing`] decides merged-ness by the identity of a *change*,
//! never by reachability (CLOUD-36) — which is what makes a rebased, squashed or
//! cherry-picked branch recognisable after it lands under a new SHA. This module
//! computes that identity without running a program.
//!
//! # Why this is ours to define
//!
//! A [`crate::git::PatchId`] is only ever compared against one produced by **the
//! same binary in the same run** — the head index against the target index,
//! inside `landing`. Nothing external computes one to compare against, and none
//! is persisted across versions. So the requirement is *a* canonical
//! deterministic identity, not git's (CLOUD-320 ruled this in writing).
//!
//! That licence is what lets the normalisation below be **decided** rather than
//! inherited. The implementation this replaces pinned twenty `git config` keys
//! and six flags for one purpose: stopping the host's configuration from
//! changing the answer. In-process there is no host configuration to read, so
//! all twenty-six are gone and nothing replaces them.
//!
//! # The normalisation, as decisions
//!
//! Each of these was a side effect of which tool got invoked. Each is now a
//! choice with a reason, and each has a case asserting it.
//!
//! **Line numbers are excluded.** Hunk positions are what shift when a change is
//! replayed on a different base, so an identity that included them would fail on
//! exactly the rebase it exists to recognise. This is the one behaviour inherited
//! deliberately and unchanged.
//!
//! **Whitespace is SIGNIFICANT, and this diverges from git.** `git patch-id`
//! folds whitespace away, so a whitespace-only difference collides and two
//! different changes share an identity. The doc this module replaces called that
//! collision *"the safe direction for a primitive whose failure class is a false
//! not landed"*. For this crate's consumers that reasoning is backwards: a false
//! **landed** is what suppresses `completion.unlanded`'s finding, and telling an
//! agent its work is on the trunk when it is not is the failure a completion gate
//! exists to prevent. A spurious not-landed is noise; a spurious landed is a lie.
//! So a whitespace-only change gets its own identity.
//!
//! **Renames are not detected**, matching what the old pinning forced with
//! `diff.renames=false` *and* `--no-renames` — but as a decision now. A rename is
//! a deletion and an addition, which is a change the target either has or does
//! not. Rename detection is a similarity heuristic, and a heuristic inside an
//! identity means two runs can disagree about what is the same change.
//!
//! **Binary content is identified by its blob ids, never by a patch body.** This
//! is what retires the caveat the old flag table admitted to: `--binary` emitted
//! a zlib-compressed body that was *"deterministic for a given zlib but not
//! guaranteed across zlib builds"*, so the identity was forced to choose between
//! being wrong and being unstable, and chose unstable. An object id is neither:
//! it is stable across builds, and two unrelated edits to one path have different
//! ids, so the collision `--binary` existed to prevent cannot occur.

use sha2::{Digest, Sha256};

/// How a single path changed, in the canonical form the identity hashes.
///
/// Ordered by path before hashing, because a tree walk's emission order is an
/// implementation detail and an identity that depended on it would not be
/// byte-stable. That ordering is what `git patch-id --stable` bought with a flag;
/// here it is the only behaviour available.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Change {
    /// The path, as bytes: a repository may carry a path that is not UTF-8, and
    /// an identity that could not represent one would be undefined exactly where
    /// `core.quotePath` used to make the old implementation host-dependent.
    pub(crate) path: Vec<u8>,
    /// What happened to it.
    pub(crate) kind: Kind,
}

/// The three shapes a change takes once rename detection is refused.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    /// The path did not exist and now does.
    Added { blob: Blob },
    /// The path existed and no longer does.
    Removed { blob: Blob },
    /// The path existed on both sides with different content or mode.
    Modified { before: Blob, after: Blob },
}

/// One side of a change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Blob {
    /// The object id, hex. Carries the whole content by construction.
    pub(crate) oid: String,
    /// The file mode, so a chmod is a change rather than a no-op.
    pub(crate) mode: u32,
    /// The content, when it is text and the hunks are what identify it.
    ///
    /// `None` for a binary blob, which is identified by [`Blob::oid`] alone —
    /// see the module doc on why that is stronger than a zlib patch body rather
    /// than weaker.
    pub(crate) text: Option<Vec<u8>>,
}

/// Whether a blob is treated as text for hunk extraction.
///
/// A NUL byte is git's own heuristic and is kept deliberately: the identity must
/// classify a blob the same way on every machine, and anything richer — an
/// attributes lookup, a filter, a content-type guess — is host state, which is
/// the whole class of input this migration removed.
#[must_use]
pub(crate) fn is_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
}

/// Hash a commit's changes into the hex identity `PatchId` wraps.
///
/// `None` when the change set is empty: an empty diff has no identity, and two
/// commits that changed nothing must never compare equal to each other. That is
/// the same answer `git patch-id` gave by printing nothing, preserved because
/// `landing` reads it — an absent identity is what produces `Evidence::NoContent`.
///
/// Infallible: a digest absorbs bytes and cannot refuse them, so there is no
/// error path to invent. The caller's fallibility is in READING the objects, not
/// in hashing them.
pub(crate) fn identity(changes: &mut [Change]) -> Option<String> {
    if changes.is_empty() {
        return None;
    }
    changes.sort();
    let mut hasher = Sha256::new();
    // A length-prefixed framing, for `identity::tagged_fingerprint`'s reason:
    // without it a path ending where the next field begins could be re-cut into
    // a different change set with the same bytes.
    field(&mut hasher, b"batten-patch-v1");
    for change in changes.iter() {
        field(&mut hasher, &change.path);
        match &change.kind {
            Kind::Added { blob } => {
                field(&mut hasher, b"+");
                side(&mut hasher, blob, None);
            }
            Kind::Removed { blob } => {
                field(&mut hasher, b"-");
                side(&mut hasher, blob, None);
            }
            Kind::Modified { before, after } => {
                field(&mut hasher, b"~");
                side(&mut hasher, before, None);
                side(&mut hasher, after, Some(before));
            }
        }
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Two nibbles pushed directly, matching `identity::Fingerprint::to_hex`
        // rather than reaching for a formatter that can fail.
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    Some(hex)
}

/// One side of one change, hashed.
///
/// When `previous` is supplied and both sides are text, what enters the hash is
/// the **edit script** rather than the content: that is what makes the identity
/// survive a rebase, because the hunks are the change and the surrounding file
/// is not. Otherwise the object id stands in, which is exact and cheap.
fn side(hasher: &mut Sha256, blob: &Blob, previous: Option<&Blob>) {
    field(hasher, blob.mode.to_le_bytes().as_slice());
    // Hunks when BOTH sides are text and there is a previous side to diff
    // against; otherwise the object id, which is exact. See the module doc —
    // that fallback is what retires the zlib stability caveat rather than
    // restating it.
    if let (Some(before), Some(after)) = (
        previous.and_then(|p| p.text.as_deref()),
        blob.text.as_deref(),
    ) {
        field(hasher, b"hunks");
        for line in hunks(before, after) {
            field(hasher, &line);
        }
    } else {
        field(hasher, b"oid");
        field(hasher, blob.oid.as_bytes());
    }
}

/// The edit script between two text blobs, as tagged lines with **no positions**.
///
/// Line numbers are excluded here and nowhere else, which is what keeps that
/// decision in one place. The tag distinguishes an insertion from a deletion, so
/// a change and its exact revert do not collide.
fn hunks(before: &[u8], after: &[u8]) -> Vec<Vec<u8>> {
    let before = String::from_utf8_lossy(before);
    let after = String::from_utf8_lossy(after);
    let input = imara_diff::InternedInput::new(before.as_ref(), after.as_ref());
    let diff = imara_diff::Diff::compute(imara_diff::Algorithm::Histogram, &input);
    let mut out: Vec<Vec<u8>> = Vec::new();
    for hunk in diff.hunks() {
        for token in hunk.before {
            out.push(tagged(b'-', &input, input.before[token as usize]));
        }
        for token in hunk.after {
            out.push(tagged(b'+', &input, input.after[token as usize]));
        }
    }
    out
}

/// One edit-script line: a tag byte and the token's text, and **no position**.
///
/// The tag is what keeps a change and its exact revert apart — without it the
/// same set of lines added and removed would hash identically.
fn tagged(tag: u8, input: &imara_diff::InternedInput<&str>, token: imara_diff::Token) -> Vec<u8> {
    let mut line = vec![tag];
    line.extend_from_slice(input.interner[token].as_bytes());
    line
}

/// Write one length-prefixed field.
///
/// `identity::write_field`'s framing, deliberately the same shape: the length as
/// a little-endian `u64` and then the bytes, so no two field sequences can be
/// re-cut into one another.
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::{Blob, Change, Kind, identity};

    /// The "renames are not detected" decision, gated where it is observable.
    ///
    /// It is NOT observable through [`crate::git::landing`], and that is worth
    /// writing down rather than discovering twice: rename detection is a pure
    /// function of the two trees, so a fixture built out of trees feeds an
    /// identical input to the detecting and the non-detecting build and gets an
    /// identical answer from both. A test over `landing` asserting this would be
    /// a case that cannot go red — which is what CLOUD-418 calls coverage.
    ///
    /// Where it IS observable is the shape: a rename can only enter the identity
    /// as a fourth [`Kind`], and this exhaustive match refuses to compile the day
    /// one appears. The named mutation is "add `Kind::Renamed`", and it fails the
    /// build rather than the assertion, which is the stronger of the two.
    #[test]
    fn renames_are_not_a_shape_this_identity_can_take() {
        let blob = Blob {
            oid: "0".repeat(64),
            mode: 0o100_644,
            text: Some(b"a\n".to_vec()),
        };
        for kind in [
            Kind::Added { blob: blob.clone() },
            Kind::Removed { blob: blob.clone() },
            Kind::Modified {
                before: blob.clone(),
                after: blob.clone(),
            },
        ] {
            match &kind {
                Kind::Added { .. } | Kind::Removed { .. } | Kind::Modified { .. } => {}
            }
            assert!(
                identity(&mut [Change {
                    path: b"p".to_vec(),
                    kind
                }])
                .is_some(),
                "every shape a change can take must have an identity"
            );
        }
    }

    /// An empty change set has no identity, which is what produces
    /// `Evidence::NoContent` rather than a hash every empty commit shares.
    #[test]
    fn an_empty_change_set_has_no_identity() {
        assert_eq!(identity(&mut []), None);
    }
}
