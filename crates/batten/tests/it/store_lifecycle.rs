//! Lifecycle outcomes and the chunk binding (CLOUD-1368).
//!
//! §7's declared mutation is `evicted-reported-as-missing`: collapsing
//! `Lifecycle::Evicted` into the resolver's `Missing` must redden
//! `an_eviction_is_refetchable_where_a_prune_is_not`, while
//! `a_prune_is_not_refetchable` stays green. That asymmetry is the anti-vacuity
//! property, and it is the whole reason the two are separate variants: a store
//! that reports both as "gone" lets a retry loop quietly reverse somebody's
//! retention decision.

use batten::identity::{AddressDomain, ContentAddress};
use batten::store::{ChunkBinding, Lifecycle, Resolution, StorageId};

const DOMAIN: AddressDomain = AddressDomain::Capture;

#[test]
fn a_prune_is_not_refetchable() {
    // An explicit decision. Re-fetching would undo it, so the outcome has to be
    // distinguishable from one where re-fetching is correct.
    assert!(!Lifecycle::Pruned.refetchable());
}

#[test]
fn an_eviction_is_refetchable_where_a_prune_is_not() {
    // THE DECLARED MUTATION'S TARGET. Collapse eviction into "gone" and this is
    // the case that reddens: the store ran out of budget, nobody decided the
    // content should disappear, and re-fetching is exactly right.
    assert!(Lifecycle::Evicted.refetchable());
    assert_ne!(
        Lifecycle::Evicted.refetchable(),
        Lifecycle::Pruned.refetchable(),
        "the two removals differ in the one way a caller acts on"
    );
}

#[test]
fn unavailable_is_not_refetchable_because_it_is_not_evidence_of_absence() {
    // Could-not-look. A retry against the STORE may be right; re-fetching the
    // CONTENT is not, because nothing here says the content is gone.
    assert!(!Lifecycle::Unavailable.refetchable());
}

#[test]
fn every_lifecycle_outcome_has_its_own_token() {
    // Five outcomes, five names. A shared token would make two different
    // situations one word in every log and every diagnostic.
    let tokens = [
        Lifecycle::Pruned.as_str(),
        Lifecycle::Evicted.as_str(),
        Lifecycle::Incomplete.as_str(),
        Lifecycle::Corrupt.as_str(),
        Lifecycle::Unavailable.as_str(),
    ];
    let unique: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
    assert_eq!(unique.len(), tokens.len(), "no two outcomes share a token");
}

#[test]
fn an_incomplete_entry_is_never_the_document() {
    // §2 states it as a rule: a range is never represented as the complete
    // document, nor used as proof of full-document freshness. `Incomplete` is
    // how that becomes a variant rather than something a reader remembers.
    assert_eq!(Lifecycle::Incomplete.as_str(), "incomplete");
    assert!(
        Lifecycle::Incomplete.refetchable(),
        "a partial write is worth completing, unlike a prune"
    );
}

#[test]
fn lifecycle_and_resolution_stay_separate_vocabularies() {
    // The lifecycle extends the resolver's answers without replacing them. The
    // resolver says whether bytes can be trusted; this says what happened to
    // them, and a caller resolving an address must not be made to handle
    // retention arms it cannot act on.
    //
    // `corrupt` and `unavailable` deliberately appear in BOTH, because they are
    // the same fact asked at two moments — and `pruned`, `evicted` and
    // `incomplete` appear only here, which is what makes this an extension.
    let lifecycle: std::collections::BTreeSet<&str> = [
        Lifecycle::Pruned.as_str(),
        Lifecycle::Evicted.as_str(),
        Lifecycle::Incomplete.as_str(),
    ]
    .into_iter()
    .collect();
    let resolution: std::collections::BTreeSet<&str> = [
        Resolution::Missing.as_str(),
        Resolution::Unavailable.as_str(),
        Resolution::Corrupt.as_str(),
        Resolution::Mismatch.as_str(),
    ]
    .into_iter()
    .collect();

    assert!(
        lifecycle.is_disjoint(&resolution),
        "the retention outcomes are the resolver's blind spot, not a rename of its own"
    );
}

// --- storage-internal identities stay internal ----------------------------

#[test]
fn no_storage_id_parses_as_a_content_address() {
    // §2's first clause, held by the boundary rather than by review. A chunk id,
    // a cursor, a generation and an internal checksum all change when the store
    // reorganises; a content address never does, so none of these may be
    // renderable as one.
    for id in [
        StorageId::Chunk("c-1".to_owned()),
        StorageId::Cursor("42".to_owned()),
        StorageId::Generation("g-7".to_owned()),
        // The one most likely to be confused: an internal checksum is 64 hex
        // characters and looks exactly like a legacy digest.
        StorageId::Checksum("a".repeat(64)),
    ] {
        assert!(
            ContentAddress::parse(&id.render()).is_err(),
            "a storage id is not an address: {}",
            id.render()
        );
    }
}

#[test]
fn a_storage_diagnostic_can_name_a_kind_without_naming_the_id() {
    let chunk = StorageId::Chunk("internal-layout-detail".to_owned());
    assert_eq!(chunk.kind(), "chunk");
    assert!(!chunk.kind().contains("internal-layout-detail"));
}

// --- the chunk binding ----------------------------------------------------

#[test]
fn a_chunked_payload_binds_to_the_whole_document_address() {
    // No chunk protocol is designed here — the row forbids designing one before
    // a measured range-read need. What is fixed is the BINDING: if parts ever
    // exist, they carry the canonical address of the whole.
    let whole = b"the document, whole and entire".to_vec();
    let binding = ChunkBinding {
        whole: ContentAddress::of(DOMAIN, &whole),
        parts: vec![
            StorageId::Chunk("0".to_owned()),
            StorageId::Chunk("1".to_owned()),
        ],
    };

    assert!(binding.verifies(DOMAIN, &whole));
}

#[test]
fn a_reassembly_that_is_not_byte_identical_does_not_verify() {
    // The chunked path is held to the same standard as the unchunked one: the
    // same rehash, so reassembly cannot reach a weaker notion of "the same
    // content" than a direct read.
    let whole = b"the document, whole and entire".to_vec();
    let binding = ChunkBinding {
        whole: ContentAddress::of(DOMAIN, &whole),
        parts: vec![StorageId::Chunk("0".to_owned())],
    };

    assert!(!binding.verifies(DOMAIN, b"the document, whole and entir"));
    assert!(
        !binding.verifies(AddressDomain::Payload, &whole),
        "and the domain is part of what it verifies against"
    );
}

#[test]
fn the_binding_names_no_second_canonical_identity() {
    // The row's last acceptance clause. A manifest naming only its own pieces
    // would be a second addressing scheme; this one's authoritative field is the
    // whole-document address, and its parts are storage ids that cannot be
    // rendered as addresses at all.
    let whole = b"x".to_vec();
    let binding = ChunkBinding {
        whole: ContentAddress::of(DOMAIN, &whole),
        parts: vec![StorageId::Chunk("0".to_owned())],
    };

    assert!(binding.whole.render().starts_with("b3-"));
    for part in &binding.parts {
        assert!(ContentAddress::parse(&part.render()).is_err());
    }
}
