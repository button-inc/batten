//! The boundary an ingested reading may not cross (CLOUD-332).
//!
//! **This tier is deliberately over the library rather than the compiled
//! binary**, and the reason is `.claude/rules/rust.md`'s, gated by
//! `tests/primitives.rs::every_permission_drop_asserts_its_own_premise`
//! (CLOUD-249): where the environment cannot produce the failing condition, the
//! decision is extracted and tested directly rather than asserted over a
//! precondition that was never created. No adapter emits `Origin::Ingested` in
//! this tree — CLOUD-128 is the producer — so a fixture repository claiming to
//! carry an ingested contributor would be asserting the fixture, not the engine.
//!
//! What IS over the compiled binary is everything the environment can build:
//! `config_provenance.rs` carries the accepted-tightening/refused-loosening pair
//! and the token assertions, and `config_base_ref_reading.rs` carries CLOUD-722's.
//!
//! Every assertion here is red against a build where `Contributors` is a set of
//! bare layers: the pairs cannot be spelled, so the predicate cannot be written.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use batten::resolve::{Contributors, Origin, Source, authority_refusal, authority_violations};

/// One key's contributor set, from the layers and classes that set it.
fn key(pairs: &[(Source, Origin)]) -> Contributors {
    let mut contributors = Contributors::unset();
    for (layer, provenance) in pairs {
        contributors.also_from(*layer, *provenance);
    }
    contributors
}

/// A one-key `sources` map, in the shape `Resolved::sources` holds.
fn sources(name: &'static str, pairs: &[(Source, Origin)]) -> BTreeMap<&'static str, Contributors> {
    BTreeMap::from([(name, key(pairs))])
}

#[test]
fn an_ingested_winner_over_a_committed_contributor_is_a_violation() {
    // The headline. `Origin::Ingested` is the greatest class, so an ingested
    // reading seated at the same layer a committed file also set wins the key —
    // and that is exactly the state the boundary refuses.
    let map = sources(
        "strictness",
        &[
            (Source::RepoConfig, Origin::Committed),
            (Source::RepoConfig, Origin::Ingested),
        ],
    );
    let violations = authority_violations(&map);
    assert_eq!(violations.len(), 1, "the boundary did not fire");
    assert_eq!(violations[0].key, "strictness");
    assert_eq!(violations[0].effective, Origin::Ingested);
}

#[test]
fn a_committed_winner_over_an_ingested_contributor_is_not() {
    // The boundary HOLDING, which is a different answer from it never firing. An
    // implementation that simply banned ingestion outright passes the case above
    // and fails this one.
    let map = sources(
        "strictness",
        &[
            (Source::RepoConfig, Origin::Ingested),
            (Source::LocalFile, Origin::Committed),
        ],
    );
    assert!(
        authority_violations(&map).is_empty(),
        "a committed reading winning is the boundary working, not a violation"
    );
}

#[test]
fn an_ingested_contributor_with_no_committed_one_is_not() {
    // Ingestion doing its job on a repository that authored no answer. This is
    // what separates "ingested may not outrank committed" from "ingested is
    // banned" — and CLOUD-128's whole value proposition is this row passing.
    let map = sources("strictness", &[(Source::RepoConfig, Origin::Ingested)]);
    assert!(
        authority_violations(&map).is_empty(),
        "an ingested value is admissible where nothing committed spoke"
    );
}

#[test]
fn a_base_ref_reading_counts_as_committed_and_never_trips_the_boundary() {
    // CLOUD-722's token is a place the committed authority was READ, not a
    // different authority. Reading it as uncommitted would make an out-of-band
    // load — the trusted one — refuse where the working-tree load allows, which
    // is two rows disagreeing about one fact.
    let map = sources(
        "strictness",
        &[
            (Source::RepoConfig, Origin::BaseRef),
            (Source::RepoConfig, Origin::Ingested),
        ],
    );
    assert_eq!(
        authority_violations(&map).len(),
        1,
        "a base-ref contributor is a committed one, so the boundary still fires"
    );
}

#[test]
fn every_key_is_judged_and_the_refusal_names_the_first() {
    // Total over the document rather than over one key: a resolver that checked
    // only the keys `SETTINGS` declares would pass a one-key fixture and miss
    // every authority-only table.
    let mut map = sources("strictness", &[(Source::RepoConfig, Origin::Committed)]);
    map.insert(
        "protected",
        key(&[
            (Source::RepoConfig, Origin::Committed),
            (Source::RepoConfig, Origin::Ingested),
        ]),
    );
    map.insert(
        "rule",
        key(&[
            (Source::RepoConfig, Origin::Committed),
            (Source::RepoConfig, Origin::Ingested),
        ]),
    );
    let violations = authority_violations(&map);
    assert_eq!(violations.len(), 2, "both offending keys are reported");
    let refusal = authority_refusal(&violations).expect("two violations earn a refusal");
    let text = refusal.to_string();
    assert!(text.contains("protected"), "names the first key: {text}");
    assert!(text.contains('2'), "names how many keys: {text}");
}

#[test]
fn the_authority_violation_is_a_policy_verdict_and_never_a_usage_error() {
    // The exit code, asserted as the type the boundary returns rather than as a
    // number a reader has to trace. Wired to `UsageError::raise` this is red,
    // and a resolver that refused an authority violation at exit `1` would be
    // reporting a statement about the repository as a statement about the
    // invocation.
    let violations = authority_violations(&sources(
        "strictness",
        &[
            (Source::RepoConfig, Origin::Committed),
            (Source::RepoConfig, Origin::Ingested),
        ],
    ));
    let refusal = authority_refusal(&violations).expect("a violation earns a refusal");
    assert!(
        refusal.downcast_ref::<batten::Denial>().is_some(),
        "an authority violation is exit 2: {refusal}"
    );
    assert!(
        refusal.downcast_ref::<batten::UsageError>().is_none(),
        "exit 1 is for an invalid invocation, not for what the repository resolved to"
    );
}

#[test]
fn a_holding_boundary_earns_no_refusal_at_all() {
    // The direction that makes the pair above discriminate: a predicate that
    // always returned a refusal would satisfy every assertion up to here.
    assert!(
        authority_refusal(&[]).is_none(),
        "no violation must produce no error, or every resolve refuses"
    );
}

#[test]
fn the_refusal_names_the_key_and_the_class_and_never_a_value() {
    // Non-negotiable rule 4 at the one new refusal: a config value is exactly
    // the kind of payload that carries a secret, so the pointer is the key and
    // the class it resolved from.
    let violations = authority_violations(&sources(
        "must_land_on",
        &[
            (Source::RepoConfig, Origin::Committed),
            (Source::RepoConfig, Origin::Ingested),
        ],
    ));
    let text = authority_refusal(&violations)
        .expect("a violation earns a refusal")
        .to_string();
    assert!(text.contains("must_land_on"), "names the key: {text}");
    assert!(text.contains("ingested"), "names the class: {text}");
    for leaked in ["origin/main", "/home/", "batten.local.toml"] {
        assert!(
            !text.contains(leaked),
            "the refusal carries {leaked}, which is payload or a path: {text}"
        );
    }
}
