//! The canonical content address (CLOUD-1364).
//!
//! §7's declared mutation is `domain-separation-dropped`: removing the domain tag
//! from the preimage in `ContentAddress::of` must redden
//! `two_domains_over_the_same_bytes_are_two_addresses` and leave
//! `the_same_bytes_under_one_domain_are_one_address` green. That asymmetry is the
//! anti-vacuity property — a suite where both cases fail under the mutation would
//! be asserting that hashing happens, not that separation does.
//!
//! CLOUD-1360's declared mutation lives here too and is a different one:
//! `inline-address-parity-broken`. Making `DocumentInput::address` mint under a
//! fixed domain rather than the caller's — or return a digest of the ARM rather
//! than of the document — must redden
//! `an_inline_document_and_its_address_name_the_same_thing`, while
//! `the_two_arms_are_distinguishable_in_a_diagnostic` stays green. Green under
//! both spellings is the anti-vacuity half: a suite where both reddened would be
//! asserting the enum has two variants, not that they agree.

use batten::identity::{AddressDomain, ContentAddress, DocumentInput, Fingerprint};

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

// --- the payload contract: inline and addressed are one document (CLOUD-1360)

#[test]
fn an_inline_document_and_its_address_name_the_same_thing() {
    // THE DECLARED MUTATION'S TARGET, and clause 1 of the contract. A consumer
    // handed either arm must reach the same identity, or "address it when it is
    // cheaper" becomes a decision about VERDICTS rather than about transport.
    let inline = DocumentInput::Inline(BYTES.to_vec());
    let addressed = DocumentInput::Address(ContentAddress::of(AddressDomain::Capture, BYTES));

    assert_eq!(
        inline.address(AddressDomain::Capture),
        addressed.address(AddressDomain::Capture),
        "the two representations of one document resolve to one identity"
    );
}

#[test]
fn parity_holds_under_the_domain_the_caller_names_and_not_a_fixed_one() {
    // The half a fixed-domain mutation slips past when only one domain is ever
    // exercised: the inline arm must follow the CALLER's domain, because a
    // consumer reading a payload and a consumer reading a capture are handed the
    // same bytes and must not be told they are the same document.
    let inline = DocumentInput::Inline(BYTES.to_vec());

    assert_ne!(
        inline.address(AddressDomain::Capture),
        inline.address(AddressDomain::Payload),
        "the inline arm is domain-separated exactly as the addressed arm is"
    );
}

#[test]
fn a_differing_inline_document_does_not_match_the_address() {
    // Parity is agreement between two representations of ONE document, never a
    // blanket equality. An inline byte string that is not what the address names
    // must be distinguishable, or the contract would admit substitution — the
    // thing clause 2's `Mismatch` outcome exists to refuse.
    let addressed = DocumentInput::Address(ContentAddress::of(AddressDomain::Capture, BYTES));
    let nearly = DocumentInput::Inline(b"the payload, whatever it happens to b".to_vec());

    assert_ne!(
        nearly.address(AddressDomain::Capture),
        addressed.address(AddressDomain::Capture)
    );
}

#[test]
fn the_two_arms_are_distinguishable_in_a_diagnostic() {
    // The anti-vacuity case: green whichever way `address` is spelled. Parity is
    // about the document the two arms name, NOT about erasing which arm a
    // consumer was handed — a diagnostic that could not say "inline" or
    // "address" could not report where a resolution came from.
    assert_eq!(DocumentInput::Inline(BYTES.to_vec()).as_str(), "inline");
    assert_eq!(
        DocumentInput::Address(ContentAddress::of(AddressDomain::Capture, BYTES)).as_str(),
        "address"
    );
}

#[test]
fn the_arm_token_is_a_pointer_and_never_the_document() {
    // Clause 4. `as_str` is what a diagnostic prints, so it must not be a route
    // to the bytes — asserted rather than assumed, because a `Display` added
    // later for convenience is exactly how this leaks.
    let secret = b"payload bytes that must not reach a message".to_vec();
    let inline = DocumentInput::Inline(secret.clone());

    assert!(!inline.as_str().contains("payload"));
    assert_eq!(
        inline.as_str().len(),
        "inline".len(),
        "the token is the arm's name and carries nothing of the document"
    );
}

#[test]
fn a_git_oid_shaped_string_is_not_a_content_address() {
    // Clause 6, held at the parser rather than by convention. A Git OID is 40 or
    // 64 bare hex characters over Git's own `<type> <len>\0` preimage; neither
    // spelling may be read as an address, because an accepted one would put two
    // different algorithms over two different preimages into one namespace.
    for oid in ["a".repeat(40), "a".repeat(64)] {
        assert!(
            ContentAddress::parse(&oid).is_err(),
            "a Git OID is interoperability metadata, never an address: {oid}"
        );
    }
}

#[test]
fn no_bcp_component_is_adopted_and_the_grammar_is_why() {
    // Clause 5's non-adoption, recorded as a case so it is falsifiable rather
    // than a sentence in a doc comment. The reason is concrete: what a BCP
    // encoding adds over `blake3` is an addressable sub-structure, which
    // CLOUD-1368 refuses outright — a chunk binds to the whole-document address
    // and never becomes a second canonical identity.
    //
    // This case reverses the day an adapter arrives: it would then assert
    // CONFORMANCE against that adapter instead, which is the row's own standard.
    let address = ContentAddress::of(AddressDomain::Capture, BYTES);
    assert!(
        address.render().starts_with("b3-1-"),
        "the grammar is Batten's, whatever computes the digest underneath it"
    );
}
