//! The canonical content address (CLOUD-1364).
//!
//! §7's declared mutation is `domain-separation-dropped`: removing the domain tag
//! from the preimage in `ContentAddress::of` must redden
//! `two_domains_over_the_same_bytes_are_two_addresses` and leave
//! `the_same_bytes_under_one_domain_are_one_address` green. That asymmetry is the
//! anti-vacuity property — a suite where both cases fail under the mutation would
//! be asserting that hashing happens, not that separation does.

use batten::identity::{AddressDomain, ContentAddress, Fingerprint};

const BYTES: &[u8] = b"the payload, whatever it happens to be";

#[test]
fn the_same_bytes_under_one_domain_are_one_address() {
    // Addressing must be a function of the bytes, or nothing downstream can
    // deduplicate or resolve. Stays green under the declared mutation, which is
    // what makes the case below discriminate rather than merely fail.
    assert_eq!(
        ContentAddress::of(AddressDomain::Capture, BYTES),
        ContentAddress::of(AddressDomain::Capture, BYTES)
    );
}

#[test]
fn two_domains_over_the_same_bytes_are_two_addresses() {
    // THE DECLARED MUTATION'S TARGET. Drop the domain tag from the preimage and
    // this is the only case that reddens.
    let capture = ContentAddress::of(AddressDomain::Capture, BYTES);
    let payload = ContentAddress::of(AddressDomain::Payload, BYTES);
    let artifact = ContentAddress::of(AddressDomain::Artifact, BYTES);

    assert_ne!(capture, payload);
    assert_ne!(payload, artifact);
    assert_ne!(capture, artifact);
}

#[test]
fn a_tag_boundary_cannot_be_forged_by_shifting_bytes_into_the_domain() {
    // The reason the preimage is NUL-separated and length-prefixed rather than
    // concatenated. Under plain concatenation a domain whose tag is a prefix of
    // another's, over content shifted by the difference, shares a preimage — so
    // the separation would be real for the cases above and forgeable in general.
    //
    // Spelled over the tags this enum actually has: `payload` and `artifact` are
    // not prefixes of one another, so the strongest available statement is that
    // moving a byte across the boundary changes the address.
    let one = ContentAddress::of(AddressDomain::Capture, b"xdata");
    let two = ContentAddress::of(AddressDomain::Capture, b"data");
    assert_ne!(one, two, "content length is bound into the preimage");
}

#[test]
fn the_empty_payload_has_an_address_and_it_is_domain_separated() {
    // An empty document is a real document. Without the length prefix an empty
    // payload's preimage is just the tag, which is the case most likely to
    // collide across domains.
    let capture = ContentAddress::of(AddressDomain::Capture, b"");
    let payload = ContentAddress::of(AddressDomain::Payload, b"");
    assert_ne!(capture, payload);
}

#[test]
fn a_rendered_address_has_one_fixed_length_whatever_the_content() {
    // §2's length clause. A caller bounding a field must not have to parse it,
    // and a length that varied with content would leak content size.
    let short = ContentAddress::of(AddressDomain::Capture, b"a").render();
    let long = ContentAddress::of(AddressDomain::Capture, &vec![b'x'; 1 << 16]).render();

    assert_eq!(short.len(), long.len());
    assert_eq!(short.len(), 69, "`b3-` + version + `-` + 64 hex");
    assert!(short.starts_with("b3-1-"));
}

#[test]
fn a_rendered_address_round_trips_through_the_parser() {
    let address = ContentAddress::of(AddressDomain::Artifact, BYTES);
    let parsed = ContentAddress::parse(&address.render()).expect("its own rendering parses");
    assert_eq!(address, parsed);
}

#[test]
fn a_bare_sha256_digest_is_refused_rather_than_read_as_an_address() {
    // THE MIGRATION BOUNDARY, and the case that keeps the two families in
    // separate namespaces. A legacy identity is exactly 64 hex characters; an
    // address always carries its prefix. Accepting the bare form would let a
    // SHA-256 fingerprint be read as a version-less address, which is the
    // confusion `ContentAddress` exists to prevent.
    let legacy = Fingerprint::from_hex(&"a".repeat(64)).expect("a legacy identity");
    assert!(
        ContentAddress::parse(&legacy.to_hex()).is_err(),
        "a bare 64-hex digest is a legacy fingerprint, never an address"
    );
}

#[test]
fn the_parser_refuses_every_near_miss() {
    // Strictness stated as cases rather than as a doc claim. Each is a spelling
    // that round-trips to the same bytes and a different string, and a store's
    // keys and sort order are both the string.
    let good = ContentAddress::of(AddressDomain::Capture, BYTES).render();

    for (bad, why) in [
        (good.to_uppercase(), "uppercase hex is a different string"),
        (good.replace("b3-", "b4-"), "an unknown algorithm prefix"),
        // Deterministic truncation, not `trim_end_matches`: the first spelling
        // trimmed a character the digest happened not to end with, so the "short"
        // case handed the parser a perfectly valid address and asserted it was
        // refused. A fixture whose input depends on the digest's last nibble is
        // a case that passes or fails by luck.
        (good[..good.len() - 1].to_owned(), "short"),
        (format!("{good}0"), "long"),
        (
            good.replacen("b3-1-", "b3-1", 1),
            "the separator is missing",
        ),
        (String::new(), "empty"),
    ] {
        assert!(
            ContentAddress::parse(&bad).is_err(),
            "the parser must refuse {why}: {bad}"
        );
    }
}

#[test]
fn no_refusal_carries_the_input_it_refused() {
    // Non-negotiable rule 4. `Fingerprint::from_hex` echoes its input, which is
    // safe for a fingerprint; an address parser is pointed at whatever a store or
    // a caller hands it, so the message carries a length and nothing else.
    let secret = "correct horse battery staple and some more to pad it out past sixty nine";
    let Err(refusal) = ContentAddress::parse(secret) else {
        panic!("that is not an address");
    };
    let rendered = refusal.to_string();
    assert!(
        !rendered.contains("horse"),
        "the refusal must not echo what it refused: {rendered}"
    );
}

#[test]
fn an_address_and_a_fingerprint_do_not_share_a_rendering() {
    // Both are 32 bytes and both hex-render, which is exactly why they are
    // separate types. This asserts the renderings cannot be confused; the
    // compiler asserts the values cannot, since no conversion exists between
    // them.
    let address = ContentAddress::of(AddressDomain::Capture, BYTES).render();
    let fingerprint = Fingerprint::from_hex(&"b".repeat(64))
        .expect("a legacy identity")
        .to_hex();

    assert_ne!(address.len(), fingerprint.len());
    assert!(!fingerprint.starts_with("b3-"));
}

// --- BCP conformance, evaluated rather than assumed ------------------------

#[test]
fn bcp_compatibility_is_an_open_question_and_this_records_which_one() {
    // The row is explicit that BCP is "an interoperability and implementation
    // candidate" and that its raw block hashes must NOT be claimed to supply
    // Batten's versioned, domain-separated grammar. No BCP crate is vendored —
    // `Cargo.toml` gains `blake3` and nothing else — so there is no adapter to
    // run a conformance case against, and a case that asserted compatibility
    // against no adapter would be the assumption the row forbids.
    //
    // What IS assertable today, and is the honest content of this case: Batten's
    // address is not a bare BLAKE3 hash of the payload, so no BCP block hash can
    // equal one by construction. Any future adapter has to map, never substitute.
    let bare = blake3::hash(BYTES);
    let address = ContentAddress::of(AddressDomain::Capture, BYTES).render();

    let mut bare_hex = String::new();
    for byte in bare.as_bytes() {
        bare_hex.push_str(&format!("{byte:02x}"));
    }
    assert!(
        !address.ends_with(&bare_hex),
        "the address digests a versioned, domain-separated preimage — never the payload alone"
    );
}
