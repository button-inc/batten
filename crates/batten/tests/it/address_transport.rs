//! Inline versus addressed transport selection (CLOUD-1367).
//!
//! §7's declared mutation is an off-by-one in the threshold comparison: turning
//! `len <= threshold` into `len < threshold` must flip
//! `a_payload_at_the_threshold_renders_inline` to addressed, while
//! `a_payload_one_byte_over_the_threshold_is_addressed` and the parity case stay
//! green. The fixtures sit one byte either side of the boundary because that is
//! the only place the error is visible — every other payload size answers the
//! same under both spellings.

use batten::capture::{CaptureConfig, DEFAULT_INLINE_MAX_BYTES, Transport, transport_for};
use batten::identity::{ADDRESS_RENDERED_LEN, AddressDomain, ContentAddress};

/// A config declaring `bytes` as the inline threshold.
fn declaring(bytes: u64) -> CaptureConfig {
    CaptureConfig {
        max_bytes: None,
        max_records: None,
        inline_max_bytes: Some(bytes),
    }
}

#[test]
fn a_payload_at_the_threshold_renders_inline() {
    // THE DECLARED MUTATION'S TARGET. The boundary is inclusive: a payload
    // exactly at the declared size still carries its bytes. `len < threshold`
    // flips this one and nothing else.
    let config = declaring(1024);
    assert_eq!(transport_for(Some(&config), 1024), Transport::Inline);
}

#[test]
fn a_payload_one_byte_over_the_threshold_is_addressed() {
    // The other side of the same byte. Together these two are the whole of the
    // boundary's behaviour, and either alone would pass under a shifted
    // comparison.
    let config = declaring(1024);
    assert_eq!(transport_for(Some(&config), 1025), Transport::Addressed);
}

#[test]
fn the_threshold_is_the_declared_value_and_not_the_default() {
    // A config that declares one must be read, or the committed value is
    // decoration and every consumer silently gets the default.
    let tight = declaring(16);
    assert_eq!(transport_for(Some(&tight), 17), Transport::Addressed);
    assert_eq!(
        transport_for(None, 17),
        Transport::Inline,
        "the same payload is inline under the default, so the declaration is what moved it"
    );
}

#[test]
fn an_absent_declaration_takes_the_documented_default() {
    assert_eq!(
        transport_for(None, DEFAULT_INLINE_MAX_BYTES),
        Transport::Inline
    );
    assert_eq!(
        transport_for(None, DEFAULT_INLINE_MAX_BYTES + 1),
        Transport::Addressed
    );
}

#[test]
fn an_empty_payload_is_inline_under_every_declaration() {
    // Zero is the degenerate case a comparison flip can also disturb, and an
    // empty payload sent as an address would cost 69 characters to say nothing.
    assert_eq!(transport_for(Some(&declaring(0)), 0), Transport::Inline);
    assert_eq!(transport_for(None, 0), Transport::Inline);
}

#[test]
fn a_zero_threshold_addresses_everything_except_the_empty_payload() {
    // The declaration a consumer would write to force addressing. It must not
    // silently mean "use the default", which is what an `Option` collapsing zero
    // to absent would produce.
    let config = declaring(0);
    assert_eq!(transport_for(Some(&config), 1), Transport::Addressed);
}

#[test]
fn both_routes_carry_the_same_semantic_result() {
    // §2's parity clause, and the anti-vacuity half of the declared mutation:
    // green whichever way the comparison is spelled. Whatever the transport, the
    // bytes a caller ends up with are the same bytes — the address is a
    // representation of the payload, never a summary of it.
    let payload = b"a payload that outlives its own representation".to_vec();
    let address = ContentAddress::of(AddressDomain::Capture, &payload);

    // The addressed route hands back an address that re-addresses to itself; the
    // inline route hands back the bytes. Resolving one yields the other.
    assert_eq!(
        ContentAddress::of(AddressDomain::Capture, &payload),
        address,
        "the address is a function of the very bytes the inline route would send"
    );
}

#[test]
fn the_priced_grammar_is_the_rendered_address_and_not_a_hash_length() {
    // §2 rules out "a generic hash length or a bytes-over-four approximation".
    // The rendered address is longer than its digest — the tag, the version and
    // both separators are part of what an address costs — so a bench pricing 64
    // characters would understate every addressed row.
    let address = ContentAddress::of(AddressDomain::Capture, b"x");
    assert_eq!(address.render().len(), ADDRESS_RENDERED_LEN);
    assert!(
        ADDRESS_RENDERED_LEN > 64,
        "the grammar costs more than a bare digest, and that difference is what must be priced"
    );
}

#[test]
fn an_address_is_only_cheaper_once_the_payload_exceeds_it() {
    // The economic claim the default threshold rests on, asserted rather than
    // assumed: below the rendered length an address is strictly more expensive
    // than the payload it points at, so a threshold under it would cost tokens to
    // save none.
    let tiny = ADDRESS_RENDERED_LEN as u64 - 1;
    assert_eq!(
        transport_for(None, tiny),
        Transport::Inline,
        "a payload shorter than its own address must never be addressed"
    );
    assert!(
        DEFAULT_INLINE_MAX_BYTES > ADDRESS_RENDERED_LEN as u64,
        "the default threshold sits above the address's own cost"
    );
}

#[test]
fn every_transport_renders_a_token_and_never_a_payload() {
    assert_eq!(Transport::Inline.as_str(), "inline");
    assert_eq!(Transport::Addressed.as_str(), "addressed");
}

#[test]
fn the_economic_threshold_is_not_a_privacy_cap() {
    // Stated as a case because the two are easy to conflate and expensive to
    // merge. This threshold only ever changes the REPRESENTATION — a payload
    // over it is still emitted, as an address — where a privacy cap refuses to
    // emit content at all. A caller cannot use `inline_max_bytes` to stop a
    // payload leaving the process, and nothing here should let them think so.
    let config = declaring(8);
    assert_eq!(transport_for(Some(&config), 1 << 20), Transport::Addressed);
    assert_ne!(
        transport_for(Some(&config), 1 << 20),
        Transport::Inline,
        "a payload over the threshold is represented differently, never withheld"
    );
}
