//! Locators, the current-selection index, and no-read freshness (CLOUD-1366).
//!
//! # §7's declared mutation, and the one adaptation it needed
//!
//! The row specifies `compare-reads-payload-bytes`, asserted "with a store whose
//! payload files are unreadable". **This sandbox runs as root, so permission bits
//! never bite** — a chmod-0 fixture is readable here and the case would pass over
//! a comparison that opened every payload. `.claude/rules/rust.md` names that
//! exactly: do not assert a conclusion over a precondition the environment cannot
//! create.
//!
//! So the fixture makes the payloads **absent** rather than unreadable, which
//! discriminates on this host: a comparison that opened the payload cannot answer
//! `Unchanged` about a file that is not there, while one reading the index alone
//! answers from the index. `a_comparison_answers_with_no_payload_on_disk_at_all`
//! is that case; `an_unchanged_comparison_is_unchanged` is the anti-vacuity half.

use batten::capture::{Freshness, Index, Locator, OpaqueIdentity};
use batten::identity::{AddressDomain, ContentAddress};

use crate::common::Fixture;

const DOMAIN: AddressDomain = AddressDomain::Capture;

fn address(bytes: &[u8]) -> ContentAddress {
    ContentAddress::of(DOMAIN, bytes)
}

/// An index in a scratch repository, and the path it lives at.
///
/// The path is RETURNED rather than recomputed, because `Fixture::build` is not
/// idempotent: calling it twice with one name makes a second, empty directory. A
/// case that re-derived the path got a fresh fixture and read no file at all —
/// which is how the first spelling of the byte comparison below failed.
fn index_with_path(name: &str) -> (Index, std::path::PathBuf) {
    let at = Fixture::new(name).git().build().join("locator-index");
    (Index::at(at.clone()), at)
}

/// An index in a scratch repository, with no payloads written anywhere.
fn index(name: &str) -> Index {
    index_with_path(name).0
}

#[test]
fn an_unchanged_comparison_is_unchanged() {
    // The anti-vacuity half of the declared mutation: stays green whether or not
    // the comparison reads payloads, which is what makes the case below the one
    // that discriminates.
    let idx = index("locator-unchanged");
    let locator = Locator::IssueKey("CLOUD-1".to_owned());
    let current = address(b"the payload");
    idx.record(&locator, &current).expect("the index writes");

    assert_eq!(idx.compare(&locator, &current), Freshness::Unchanged);
}

#[test]
fn a_comparison_answers_with_no_payload_on_disk_at_all() {
    // THE DECLARED MUTATION'S TARGET, adapted to a precondition this host can
    // actually create. Nothing but the index exists — no payload file was ever
    // written — and the comparison still answers. A `compare` that opened the
    // payload could not.
    let idx = index("locator-no-payload");
    let locator = Locator::Handle("h-1".to_owned());
    let recorded = address(b"bytes that were never stored");
    idx.record(&locator, &recorded).expect("the index writes");

    assert_eq!(idx.compare(&locator, &recorded), Freshness::Unchanged);
    assert_eq!(
        idx.compare(&locator, &address(b"something else")),
        Freshness::Stale,
        "both verdicts come from the index alone"
    );
}

#[test]
fn a_moved_payload_is_stale_rather_than_absent() {
    // The content moved; the locator still resolves. Reporting `Absent` would
    // send a caller to re-discover a locator that is working fine.
    let idx = index("locator-stale");
    let locator = Locator::IssueKey("CLOUD-2".to_owned());
    idx.record(&locator, &address(b"v1")).expect("write");
    idx.record(&locator, &address(b"v2")).expect("rewrite");

    assert_eq!(idx.compare(&locator, &address(b"v1")), Freshness::Stale);
    assert_eq!(idx.compare(&locator, &address(b"v2")), Freshness::Unchanged);
}

#[test]
fn a_locator_the_index_never_saw_is_absent() {
    let idx = index("locator-absent");
    assert_eq!(
        idx.compare(&Locator::SpillPath("/tmp/x".to_owned()), &address(b"x")),
        Freshness::Absent
    );
}

#[test]
fn an_unreadable_index_is_unavailable_and_never_absent() {
    // Could-not-look, kept apart from `Absent`. A directory where the index file
    // belongs is unreadable-as-a-file on any host, so this precondition IS
    // creatable here — unlike the permission bits above.
    let dir = Fixture::new("locator-unavailable").git().build();
    let at = dir.join("locator-index");
    std::fs::create_dir(&at).expect("a directory where the index belongs");
    let idx = Index::at(at);

    assert_eq!(
        idx.compare(&Locator::Handle("h".to_owned()), &address(b"x")),
        Freshness::Unavailable,
        "an index that could not be read says nothing about whether an entry exists"
    );
}

#[test]
fn an_index_that_has_recorded_nothing_is_absent_rather_than_unavailable() {
    // The other side of the case above, and the one that keeps it discriminating:
    // a repository that has recorded nothing has an EMPTY index, not a broken
    // one. Calling that unreadable would make every first comparison
    // `Unavailable`.
    let idx = index("locator-empty");
    assert_eq!(
        idx.compare(&Locator::Handle("h".to_owned()), &address(b"x")),
        Freshness::Absent
    );
}

#[test]
fn recording_the_same_locator_twice_replaces_rather_than_appends() {
    // An append would leave two current addresses for one locator, and whichever
    // sorted first would win — a silent second authority over "what is current".
    let idx = index("locator-replace");
    let locator = Locator::IssueKey("CLOUD-3".to_owned());
    idx.record(&locator, &address(b"a")).expect("write");
    idx.record(&locator, &address(b"b")).expect("rewrite");

    assert_eq!(idx.current(&locator), Some(address(b"b")));
}

#[test]
fn the_index_is_byte_stable_whatever_order_entries_arrive_in() {
    // §6. Two runs recording the same set in different orders must produce
    // identical bytes, or a diff of this file is unreadable.
    let (one, one_at) = index_with_path("locator-order-a");
    one.record(&Locator::Handle("b".to_owned()), &address(b"2"))
        .expect("write");
    one.record(&Locator::Handle("a".to_owned()), &address(b"1"))
        .expect("write");

    let (two, two_at) = index_with_path("locator-order-b");
    two.record(&Locator::Handle("a".to_owned()), &address(b"1"))
        .expect("write");
    two.record(&Locator::Handle("b".to_owned()), &address(b"2"))
        .expect("write");

    // THE BYTES, not the lookups (CodeRabbit on #879). `current` scans for a
    // `<locator>\t` prefix, so it answers the same whatever order the lines sit
    // in — both assertions below stay green with `kept.sort()` deleted, which
    // means they were testing that recording works, not that it is byte-stable.
    // The claim is about the FILE, so the file is what gets compared.
    let one_bytes = std::fs::read(&one_at).expect("the first index");
    let two_bytes = std::fs::read(&two_at).expect("the second index");
    assert_eq!(
        one_bytes, two_bytes,
        "the same set recorded in two orders is the same bytes"
    );

    assert_eq!(
        one.current(&Locator::Handle("a".to_owned())),
        two.current(&Locator::Handle("a".to_owned()))
    );
    assert_eq!(
        one.current(&Locator::Handle("b".to_owned())),
        two.current(&Locator::Handle("b".to_owned()))
    );
}

// --- the four types stay four ---------------------------------------------

#[test]
fn no_locator_spelling_parses_as_a_content_address() {
    // Discovery-only, enforced at the boundary rather than by convention. An
    // issue key or a spill path that reached a field expecting an address is
    // refused there, so it can never be emitted AS an authoritative address.
    for locator in [
        Locator::IssueKey("CLOUD-1".to_owned()),
        Locator::Handle("h-1".to_owned()),
        Locator::SpillPath("/tmp/mcp-spill.json".to_owned()),
    ] {
        assert!(
            ContentAddress::parse(&locator.render()).is_err(),
            "a locator is not an address: {}",
            locator.render()
        );
    }
}

#[test]
fn a_non_resolvable_identity_cannot_enter_a_resolvable_path() {
    // The privacy exemption. `OpaqueIdentity` has no route into
    // `ContentAddress` — there is no `From`, no constructor taking one, and its
    // rendering is refused by the parser — so a payload nobody agreed to store
    // cannot acquire a resolvable identity by passing through a string.
    let opaque = OpaqueIdentity::new("deadbeef");
    assert!(ContentAddress::parse(&opaque.render()).is_err());
    assert!(opaque.render().starts_with("opaque:"));
}

#[test]
fn a_locator_diagnostic_can_name_a_kind_without_naming_the_locator() {
    // Pointer-only (§5). A spill path is a path on somebody's machine and an
    // issue key is a consumer's vocabulary, so a diagnostic that must carry
    // neither still has something true to say.
    let spill = Locator::SpillPath("/home/someone/private/spill.json".to_owned());
    assert_eq!(spill.kind(), "spill");
    assert!(!spill.kind().contains("someone"));
}

#[test]
fn every_freshness_outcome_renders_a_token_and_never_a_payload() {
    assert_eq!(Freshness::Unchanged.as_str(), "unchanged");
    assert_eq!(Freshness::Stale.as_str(), "stale");
    assert_eq!(Freshness::Absent.as_str(), "absent");
    assert_eq!(Freshness::Unavailable.as_str(), "unavailable");
}

#[test]
fn freshness_and_resolution_are_separate_vocabularies() {
    // They align without duplicating. `Stale` has no resolver counterpart — the
    // resolver cannot know the content moved — and `Mismatch` has no freshness
    // counterpart, because a corrupt payload is not a moved one. Collapsing them
    // would make those two situations one word.
    let freshness = [
        Freshness::Unchanged.as_str(),
        Freshness::Stale.as_str(),
        Freshness::Absent.as_str(),
        Freshness::Unavailable.as_str(),
    ];
    assert!(
        !freshness.contains(&"mismatch") && !freshness.contains(&"corrupt"),
        "freshness must not borrow the resolver's content verdicts"
    );
    assert!(
        freshness.contains(&"stale"),
        "and it carries the one the resolver cannot express"
    );
}

// --- the writer honours the reader's could-not-look (review of this bundle) ---

#[test]
fn an_unreadable_index_refuses_the_write_rather_than_discarding_what_it_cannot_see() {
    // FOUND IN REVIEW OF THIS BUNDLE, and it is a data-loss class rather than a
    // wrong answer. `record` rewrites the whole file from what it read, so a
    // could-not-look folded into "empty" does not degrade one comparison — it
    // deletes every mapping the index held.
    //
    // `compare` already reports this case as `Unavailable` rather than `Absent`.
    // A writer collapsing the same distinction would make that care pointless:
    // afterwards every prior locator answers `Absent`, correctly, about a mapping
    // the writer had just destroyed.
    let dir = Fixture::new("locator-index-unreadable").git().build();

    // A DIRECTORY where the index file goes: `read_to_string` fails with
    // something that is neither `Ok` nor `NotFound`, which is the shape an
    // unreadable index has. Spelled this way because this sandbox runs as root,
    // so a permission bit would never bite — the premise has to be created by
    // something other than access control (`.claude/rules/rust.md`).
    let at = dir.join("index");
    std::fs::create_dir(&at).expect("a directory standing where the file goes");

    let index = Index::at(at);
    let address = ContentAddress::of(AddressDomain::Capture, b"x");

    assert_eq!(
        index.compare(&Locator::IssueKey("CLOUD-1".to_owned()), &address),
        Freshness::Unavailable,
        "the reader's premise: this index cannot be looked at"
    );
    assert!(
        index
            .record(&Locator::IssueKey("CLOUD-1".to_owned()), &address)
            .is_err(),
        "so the writer must refuse rather than rewrite the file from an empty set"
    );
}

#[test]
fn an_absent_index_still_records_because_absent_is_not_unreadable() {
    // The anti-vacuity half. A repository that has recorded nothing has an empty
    // index, and a fix that refused on `None` AND on absent would make the first
    // record of every repository fail — turning a data-loss bug into a
    // never-works bug. The two causes stay distinct in the writer exactly as they
    // do in the reader.
    let dir = Fixture::new("locator-index-absent").git().build();
    let index = Index::at(dir.join("nested").join("index"));
    let address = ContentAddress::of(AddressDomain::Capture, b"x");
    let locator = Locator::IssueKey("CLOUD-1".to_owned());

    index.record(&locator, &address).expect("a first record");
    assert_eq!(index.compare(&locator, &address), Freshness::Unchanged);
}

#[test]
fn a_record_preserves_every_entry_it_did_not_replace() {
    // The property the bug broke, asserted directly rather than through the
    // failure that revealed it: recording one locator must not disturb another.
    let dir = Fixture::new("locator-index-preserves").git().build();
    let index = Index::at(dir.join("index"));
    let first = Locator::IssueKey("CLOUD-1".to_owned());
    let second = Locator::Handle("h-2".to_owned());
    let one = ContentAddress::of(AddressDomain::Capture, b"one");
    let two = ContentAddress::of(AddressDomain::Capture, b"two");

    index.record(&first, &one).expect("the first record");
    index.record(&second, &two).expect("the second record");

    assert_eq!(index.compare(&first, &one), Freshness::Unchanged);
    assert_eq!(index.compare(&second, &two), Freshness::Unchanged);
}

#[test]
fn a_reader_never_sees_a_truncated_index_mid_record() {
    // CodeRabbit on #879, and the half a lock does NOT fix. `std::fs::write`
    // truncates before it writes, so a `compare` landing in that window read an
    // empty file and answered `Absent` for every locator that was in fact
    // recorded — a could-not-look presented as a fact, from the writer this time.
    //
    // Asserted through the property the staging buys rather than by racing a
    // thread, which would be timing-dependent and would pass on a fast machine
    // whatever the code did: after a record, no intermediate file is left behind
    // and the index reads whole.
    let (idx, at) = index_with_path("locator-atomic");
    let locator = Locator::Handle("h".to_owned());

    idx.record(&locator, &address(b"1")).expect("first");
    idx.record(&locator, &address(b"2")).expect("second");

    assert_eq!(idx.current(&locator), Some(address(b"2")));
    assert!(
        !at.with_extension("staged").exists(),
        "the staging file is renamed into place, never left beside the index"
    );
    let bytes = std::fs::read(&at).expect("the index reads whole");
    assert!(
        bytes.ends_with(b"\n") && !bytes.is_empty(),
        "a published index is a complete file, never a truncation"
    );
}
