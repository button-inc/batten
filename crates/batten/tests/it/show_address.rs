//! `show address` over the compiled binary (CLOUD-1717).
//!
//! # Why the verb exists
//!
//! `mise-tasks/checksums.sh` shelled `sha256sum` to build a release manifest,
//! and three things followed from that which this verb removes.
//!
//! The digest was BARE. A manifest entry and any other sha256 in the tree were
//! the same 64 characters, so nothing could say which was which, and nothing
//! stopped a digest computed for one purpose being compared against one computed
//! for another. [`identity::ContentAddress`] is domain-separated and versioned,
//! which is what makes the comparison `policy/release-assets.rego` performs a
//! comparison of like with like.
//!
//! The SPELLING differed per platform — `sha256sum` on GNU, `shasum -a 256` on
//! macOS — which is a second authority over one answer, and the class
//! `rules/policy-modules.md` refuses for parsers.
//!
//! And the FORMAT was one only that program wrote and only that program read.
//! The tree already had one answer to "what is this content", used by the
//! capture store and by `DocumentInput`; the release manifest joins it rather
//! than keeping a fourth spelling.
//!
//! # What these cases are for
//!
//! The address's SHAPE and the failure DIRECTION, because those are the two a
//! caller depends on and neither is visible from the happy path alone. A verb
//! that emitted a bare digest would pass any case that only checked two files
//! differ, and one that skipped an unreadable path would pass any case that only
//! checked a good one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{run_with_stdin, scratch, write};

#[test]
fn the_address_is_domain_separated_and_versioned_rather_than_a_bare_digest() {
    // THE WHOLE REASON THE VERB EXISTS, as an assertion rather than as a header
    // paragraph. `sha256sum` emitted 64 hex characters that named no domain and
    // no version, so a manifest entry was indistinguishable from any other
    // digest in the tree and a future change of domain could not be detected.
    let dir = scratch("show-address-shape");
    write(&dir, "asset.tar.gz", "payload");

    let reported = run_with_stdin(&dir, &["show", "address"], "asset.tar.gz\n");
    assert!(
        reported.status.success(),
        "a readable path is reported\n{}",
        String::from_utf8_lossy(&reported.stderr)
    );
    let said = String::from_utf8_lossy(&reported.stdout);
    let (path, address) = said
        .trim_end()
        .split_once('\t')
        .expect("one `<path>\\t<address>` line");
    assert_eq!(path, "asset.tar.gz", "the path is echoed verbatim\n{said}");
    assert!(
        address.starts_with("b3-1-"),
        "the address carries its domain and version\n{said}"
    );
    assert_eq!(
        address.len(),
        "b3-1-".len() + 64,
        "and the digest behind the prefix is a full blake3\n{said}"
    );
}

#[test]
fn identical_content_at_two_paths_gets_one_address() {
    // CONTENT-ADDRESSED, NOT PATH-ADDRESSED, which is what lets the module
    // compare an uploaded asset against the manifest entry that claims it: the
    // two are read at different names and must still compare equal.
    let dir = scratch("show-address-identical");
    write(&dir, "left.txt", "the same bytes");
    write(&dir, "right.txt", "the same bytes");
    write(&dir, "other.txt", "different bytes");

    let reported = run_with_stdin(
        &dir,
        &["show", "address"],
        "left.txt\nright.txt\nother.txt\n",
    );
    let said = String::from_utf8_lossy(&reported.stdout);
    let addresses: Vec<&str> = said
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(_, address)| address)
        .collect();
    assert_eq!(addresses.len(), 3, "one line per path\n{said}");
    assert_eq!(
        addresses[0], addresses[1],
        "identical content gets one address\n{said}"
    );
    assert_ne!(
        addresses[0], addresses[2],
        "and differing content does not\n{said}"
    );
}

#[test]
fn a_path_it_cannot_read_refuses_rather_than_writing_a_short_manifest() {
    // THE DIRECTION A MISS MUST FAIL IN. Skipping the line would produce a
    // manifest that is SHORT rather than absent, and a short manifest compares
    // equal to a release that is genuinely missing that asset — a silent pass on
    // exactly the question the manifest exists to answer.
    //
    // Exit 1 rather than 2: §7 spends `2` on the policy verdict, and "this path
    // is not there" is a claim about the invocation rather than about the tree.
    let dir = scratch("show-address-unreadable");
    write(&dir, "present.txt", "here");

    let refused = run_with_stdin(&dir, &["show", "address"], "present.txt\nabsent.txt\n");
    assert_eq!(
        refused.status.code(),
        Some(1),
        "an unreadable path refuses\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        String::from_utf8_lossy(&refused.stdout).is_empty(),
        "and writes no partial manifest\n{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("absent.txt"),
        "naming the path it could not read\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn the_json_channel_is_parseable_even_when_stdin_named_nothing() {
    // JSON THAT IS SOMETIMES ABSENT IS UNPARSEABLE, which is `show agent`'s own
    // rule at the same boundary. An empty reading is an empty array, never no
    // output, because a caller piping this into a parser must not have to
    // special-case the empty run.
    let dir = scratch("show-address-json-empty");

    let reported = run_with_stdin(&dir, &["show", "address", "--json"], "\n  \n");
    assert!(
        reported.status.success(),
        "naming no path is not a failure\n{}",
        String::from_utf8_lossy(&reported.stderr)
    );
    let said = String::from_utf8_lossy(&reported.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(said.trim()).expect("the json channel parses");
    assert_eq!(
        parsed,
        serde_json::json!([]),
        "an empty reading is an empty array\n{said}"
    );
}

#[test]
fn the_json_channel_carries_the_same_pairs_as_the_line_channel() {
    // ONE READING, TWO PROJECTIONS. A channel that disagreed with the other
    // would make the manifest depend on which flag the caller passed, which is
    // the drift a single source of truth exists to prevent.
    let dir = scratch("show-address-json");
    write(&dir, "asset.tar.gz", "payload");

    let lines = run_with_stdin(&dir, &["show", "address"], "asset.tar.gz\n");
    let json = run_with_stdin(&dir, &["show", "address", "--json"], "asset.tar.gz\n");

    let said = String::from_utf8_lossy(&lines.stdout);
    let (_, address) = said.trim_end().split_once('\t').expect("one pair");
    let parsed: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&json.stdout).trim())
            .expect("the json channel parses");
    assert_eq!(
        parsed,
        serde_json::json!([{"path": "asset.tar.gz", "address": address}]),
        "both channels carry one reading\n{said}"
    );
}
