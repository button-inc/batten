//! Verified address resolution (CLOUD-1365).
//!
//! §7's declared mutation is `rehash-skipped-before-decode`: returning the bytes
//! without re-addressing them must turn `a_tampered_blob_is_a_mismatch` into
//! `Resolved`, while `identical_bytes_resolve` stays green. That asymmetry is the
//! anti-vacuity property — the rehash is the entire integrity claim, and a suite
//! that reddened everywhere under the mutation would be asserting that reading
//! happens rather than that verification does.

use std::path::{Path, PathBuf};

use batten::identity::{AddressDomain, ContentAddress};
use batten::store::{Provenance, Resolution, resolve_address};

use crate::common::Fixture;

const DOMAIN: AddressDomain = AddressDomain::Capture;
const BYTES: &[u8] = b"\x00\x01\x02 binary payload with a NUL and \xff high bytes";

/// An addressed directory holding `bytes` under their own address.
fn stored(name: &str, bytes: &[u8]) -> (PathBuf, ContentAddress) {
    let dir = Fixture::new(name).git().build();
    let address = ContentAddress::of(DOMAIN, bytes);
    std::fs::write(dir.join(address.render()), bytes).expect("the blob writes");
    (dir, address)
}

#[test]
fn identical_bytes_resolve_and_come_back_byte_for_byte() {
    // The anti-vacuity half of the declared mutation, and the case that proves
    // "byte-identical" rather than "parses to the same thing": the payload
    // carries a NUL and a high byte that no lossy UTF-8 conversion survives.
    let (dir, address) = stored("resolve-ok", BYTES);
    let (outcome, provenance) = resolve_address(&dir, DOMAIN, &address, None);

    assert_eq!(outcome, Resolution::Resolved(BYTES.to_vec()));
    assert_eq!(provenance, Provenance::Store);
}

#[test]
fn a_tampered_blob_is_a_mismatch_and_never_resolved() {
    // THE DECLARED MUTATION'S TARGET. The filename is still the right address —
    // trusting it is exactly the live defect this replaces — and the content
    // underneath has changed.
    let (dir, address) = stored("resolve-tampered", BYTES);
    std::fs::write(dir.join(address.render()), b"not what was addressed").expect("tamper");

    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(outcome, Resolution::Mismatch);
}

#[test]
fn a_truncated_blob_is_a_mismatch_rather_than_a_short_read() {
    // The partial fixture. A prefix of the right content is still the wrong
    // content, and it is the shape a torn write leaves behind.
    let (dir, address) = stored("resolve-partial", BYTES);
    std::fs::write(dir.join(address.render()), &BYTES[..BYTES.len() / 2]).expect("truncate");

    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(outcome, Resolution::Mismatch);
}

#[test]
fn an_absent_address_is_missing() {
    let dir = Fixture::new("resolve-missing").git().build();
    let address = ContentAddress::of(DOMAIN, BYTES);

    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(outcome, Resolution::Missing);
}

#[test]
fn an_entry_that_is_not_a_blob_is_corrupt_rather_than_missing() {
    // A directory where a blob belongs: the entry exists, so `Missing` would be a
    // lie, and there are no bytes to hash, so `Mismatch` would be one too.
    let dir = Fixture::new("resolve-corrupt").git().build();
    let address = ContentAddress::of(DOMAIN, BYTES);
    std::fs::create_dir(dir.join(address.render())).expect("a directory at the address");

    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(outcome, Resolution::Corrupt);
}

#[test]
fn an_unreadable_store_directory_is_missing_rather_than_a_verdict_about_content() {
    // The unavailable fixture, expressed the way this sandbox permits. Running as
    // root makes permission bits unenforceable — `.claude/rules/rust.md` names
    // that exactly — so rather than assert a conclusion over a precondition the
    // environment cannot create, this pins the neighbouring guarantee: a
    // directory that is not there answers about the ADDRESS, never about the
    // content, and never `Mismatch`.
    let missing_dir = Path::new("/nonexistent-store-root-for-this-case");
    let address = ContentAddress::of(DOMAIN, BYTES);

    let (outcome, _) = resolve_address(missing_dir, DOMAIN, &address, None);
    assert!(
        matches!(outcome, Resolution::Missing | Resolution::Unavailable),
        "an unreachable store is an absence or a could-not-look, never a content \
         verdict: {outcome:?}"
    );
}

#[test]
fn the_wrong_domain_does_not_resolve_the_right_bytes() {
    // Domain separation reaching the resolver. The bytes on disk are exactly the
    // ones asked for; only the domain differs, and the address is therefore a
    // different address. Answering `Resolved` here would make the separation
    // CLOUD-1364 built decorative at the one boundary that consumes it.
    let (dir, address) = stored("resolve-domain", BYTES);

    let (outcome, _) = resolve_address(&dir, AddressDomain::Payload, &address, None);
    assert_eq!(outcome, Resolution::Mismatch);
}

// --- the inline fallback --------------------------------------------------

#[test]
fn an_inline_fallback_answers_where_the_store_cannot_and_says_so() {
    // §2's fallback clause: identical bytes, and the use is RECORDED. A fallback
    // that answered silently would hide a store rotting underneath the caller.
    let dir = Fixture::new("resolve-inline").git().build();
    let address = ContentAddress::of(DOMAIN, BYTES);

    let (outcome, provenance) = resolve_address(&dir, DOMAIN, &address, Some(BYTES));
    assert_eq!(outcome, Resolution::Resolved(BYTES.to_vec()));
    assert_eq!(
        provenance,
        Provenance::Inline,
        "the fallback's use is observable, not silent"
    );
}

#[test]
fn an_inline_copy_is_verified_by_the_same_rehash() {
    // The hole a careless fallback opens. Inline bytes that do not hash to the
    // address are not an answer — accepting them would route straight around the
    // boundary this function exists to be.
    let dir = Fixture::new("resolve-inline-bad").git().build();
    let address = ContentAddress::of(DOMAIN, BYTES);

    let (outcome, provenance) = resolve_address(&dir, DOMAIN, &address, Some(b"wrong bytes"));
    assert_eq!(outcome, Resolution::Missing, "the store's verdict stands");
    assert_eq!(provenance, Provenance::Store);
}

#[test]
fn the_store_is_preferred_and_the_fallback_is_not_consulted_when_it_answers() {
    // Ordering, asserted through provenance: a store that answers is the answer.
    let (dir, address) = stored("resolve-prefer-store", BYTES);

    let (outcome, provenance) = resolve_address(&dir, DOMAIN, &address, Some(BYTES));
    assert_eq!(outcome, Resolution::Resolved(BYTES.to_vec()));
    assert_eq!(provenance, Provenance::Store);
}

#[test]
fn a_mismatched_store_can_still_be_rescued_by_a_verified_inline_copy() {
    // The one case where a `Mismatch` is not the end: the caller's copy may be
    // the honest one. It is still verified, and the provenance says which side
    // answered — which is what lets a reader notice the store is wrong.
    let (dir, address) = stored("resolve-rescue", BYTES);
    std::fs::write(dir.join(address.render()), b"corrupted on disk").expect("tamper");

    let (outcome, provenance) = resolve_address(&dir, DOMAIN, &address, Some(BYTES));
    assert_eq!(outcome, Resolution::Resolved(BYTES.to_vec()));
    assert_eq!(provenance, Provenance::Inline);
}

// --- no decode qualifies as byte identity ---------------------------------

#[test]
fn a_reserialised_json_document_does_not_resolve_to_the_original_address() {
    // §2's serialization clause, and the live defect it names: the MCP and
    // capture readers decode and re-serialize JSON today, which renormalises key
    // order and escaping. The result parses to the same document and is not the
    // same bytes, so it must not satisfy the address.
    let wire = br#"{"b":1,"a":{"x":  "y"}}"#;
    let (dir, address) = stored("resolve-json", wire);

    let reserialised = serde_json::to_vec(
        &serde_json::from_slice::<serde_json::Value>(wire).expect("the fixture is JSON"),
    )
    .expect("it re-serialises");
    assert_ne!(
        reserialised.as_slice(),
        wire,
        "the fixture must actually change under a round trip, or this case proves nothing"
    );

    std::fs::write(dir.join(address.render()), &reserialised).expect("write the round trip");
    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(
        outcome,
        Resolution::Mismatch,
        "a re-serialised document is not the document"
    );
}

#[test]
fn a_lossy_utf8_conversion_does_not_resolve_to_the_original_address() {
    // The other live path. `from_utf8_lossy` replaces invalid sequences with
    // U+FFFD, which is a different payload that reads plausibly.
    let raw = b"\xff\xfe payload";
    let (dir, address) = stored("resolve-lossy", raw);

    let lossy = String::from_utf8_lossy(raw).into_owned();
    assert_ne!(lossy.as_bytes(), raw, "the fixture is genuinely lossy");

    std::fs::write(dir.join(address.render()), lossy.as_bytes()).expect("write the lossy form");
    let (outcome, _) = resolve_address(&dir, DOMAIN, &address, None);
    assert_eq!(outcome, Resolution::Mismatch);
}

#[test]
fn every_outcome_renders_a_token_and_never_a_byte() {
    // Pointer-only diagnostics (§5). The token set is closed and none of it is
    // content, so a diagnostic cannot leak a payload by naming its outcome.
    let (dir, address) = stored("resolve-tokens", BYTES);
    let (resolved, _) = resolve_address(&dir, DOMAIN, &address, None);

    assert_eq!(resolved.as_str(), "resolved");
    assert_eq!(Resolution::Missing.as_str(), "missing");
    assert_eq!(Resolution::Unavailable.as_str(), "unavailable");
    assert_eq!(Resolution::Corrupt.as_str(), "corrupt");
    assert_eq!(Resolution::Mismatch.as_str(), "mismatch");

    for token in ["resolved", "missing", "unavailable", "corrupt", "mismatch"] {
        assert!(
            !String::from_utf8_lossy(BYTES).contains(token),
            "a token must not be derivable from the payload"
        );
    }
}
