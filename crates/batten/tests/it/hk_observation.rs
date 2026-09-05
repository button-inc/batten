//! The bounded runtime-observation receipt (CLOUD-948).
//!
//! # What this receipt is for
//!
//! CLOUD-947's committed contract says what this repository INTENDS the gate to
//! run. It says nothing about what a session actually resolved — a different
//! runner on PATH, a stale contract, or a plan that will not resolve at all are
//! all invisible to a statement of intent. This records the observation
//! separately, so a later reader can tell an environment fault from a repository
//! one.
//!
//! # The discriminator
//!
//! [`the_three_states_are_distinct_and_unknown_is_not_drifted`]. An
//! implementation that collapsed `unknown` into `drifted` passes every other
//! case in this file and fails only that one — because it would turn a verdict
//! about the environment into a verdict about the repository, which is the
//! confusion a three-valued read exists to prevent.
//!
//! # And one case a fixture cannot reach
//!
//! [`this_session_can_observe_the_pinned_runner`] runs against the real binary
//! and the committed contract. A fixture cannot prove the recorder reads what
//! the runner actually emits, which is the same tier argument every other hk
//! suite here makes.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::Path;

use batten::facts::Look;
use batten::hk::{self, Capability};

/// A contract with one step, at a stated tool version.
fn contract(tool_version: &str, step: &str) -> hk::Contract {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "toolVersion": tool_version,
        "surfaces": [{
            "hook": "check",
            "runType": "check",
            "profiles": [],
            "groups": [{"id": "group_0", "stepIds": [step]}],
            "steps": [{
                "name": step,
                "status": "included",
                "orderIndex": 0,
                "parallelGroupId": "group_0",
            }],
        }],
    }))
    .expect("a contract fixture")
}

/// **The discriminator.** Three states, three distinct answers.
///
/// The third arm is what an implementation collapsing could-not-look into
/// disagreement gets wrong, and it is the only case that separates them: a
/// missing runner and a differing one are not the same finding.
#[test]
fn the_three_states_are_distinct_and_unknown_is_not_drifted() {
    let committed = contract("hk 1.56.1", "one");
    let same = contract("hk 1.56.1", "one");
    let other_version = contract("hk 1.57.0", "one");
    let other_step = contract("hk 1.56.1", "two");

    assert_eq!(
        hk::capability(Some(&committed), Some(&same)),
        Capability::Available
    );
    assert_eq!(
        hk::capability(Some(&committed), Some(&other_version)),
        Capability::Drifted,
        "a different runner is readable disagreement"
    );
    assert_eq!(
        hk::capability(Some(&committed), Some(&other_step)),
        Capability::Drifted,
        "a different plan is readable disagreement"
    );
    assert_eq!(
        hk::capability(Some(&committed), None),
        Capability::Unknown,
        "an unresolvable runner is could-not-look, NEVER drift: drift would be a \
         claim about the repository made on the strength of an environment fault"
    );
    assert_eq!(
        hk::capability(None, Some(&same)),
        Capability::Unknown,
        "an absent contract is could-not-look for the same reason, the other way round"
    );
    assert_eq!(hk::capability(None, None), Capability::Unknown);

    // Anti-vacuity: the three tokens are three tokens. A collapse that made two
    // of them equal would satisfy every assertion above that used only one.
    let tokens = [
        Capability::Available.as_str(),
        Capability::Drifted.as_str(),
        Capability::Unknown.as_str(),
    ];
    let unique: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
    assert_eq!(unique.len(), 3, "each state has its own recorded token");
}

/// A host that names no session gets no receipt at all.
///
/// `IsNot` rather than a failure: it is an answer. Writing one under a shared
/// key would let two sessions answer for each other, which is exactly what a
/// per-session receipt exists to prevent.
#[test]
fn a_host_with_no_session_writes_nothing() {
    let dir = common::scratch("hk-observation-no-session");
    common::init_repo(&dir);
    let git_dir = dir.join(".git");

    assert_eq!(
        hk::observe(&dir, &git_dir, None).expect("the verb runs"),
        Look::IsNot
    );
    assert_eq!(
        hk::observe(&dir, &git_dir, Some("")).expect("the verb runs"),
        Look::IsNot,
        "an empty token names no session either"
    );
    assert!(
        !git_dir.join("batten-hk-observations").exists(),
        "no session, no store"
    );
}

/// A second event in the same session and digest returns the record and does not
/// probe again.
///
/// Shown by SEEDING a record the probe would never produce: if the second call
/// re-probed, the seeded state would be overwritten. A timing assertion would
/// discriminate nothing here.
#[test]
fn a_second_event_in_one_session_does_not_reprobe() {
    let dir = common::scratch("hk-observation-once");
    common::init_repo(&dir);
    let git_dir = dir.join(".git");

    let Ok(Look::Is(first)) = hk::observe(&dir, &git_dir, Some("sess")) else {
        panic!("the first observation records")
    };
    let path = hk::observation_path(&git_dir, "sess", &first.contract_digest);

    let mut seeded = first.clone();
    seeded.tool_version = Some("a version no probe would report".to_owned());
    fs::write(
        &path,
        serde_json::to_string(&seeded).expect("the seed serialises"),
    )
    .expect("seed the record");

    let Ok(Look::Is(second)) = hk::observe(&dir, &git_dir, Some("sess")) else {
        panic!("the second observation reads back")
    };
    assert_eq!(
        second, seeded,
        "the second event returned the record rather than probing over it"
    );
}

/// A changed contract digest is a new observation rather than an overwrite.
#[test]
fn a_changed_digest_is_observed_afresh() {
    let dir = common::scratch("hk-observation-digest");
    common::init_repo(&dir);
    let git_dir = dir.join(".git");

    let Ok(Look::Is(first)) = hk::observe(&dir, &git_dir, Some("sess")) else {
        panic!("the first observation records")
    };

    fs::create_dir_all(dir.join("contracts")).expect("a contracts directory");
    fs::write(
        dir.join(batten::hk::ARTIFACT),
        contract("hk 1.56.1", "one")
            .render()
            .expect("the contract renders"),
    )
    .expect("commit a contract");

    let Ok(Look::Is(second)) = hk::observe(&dir, &git_dir, Some("sess")) else {
        panic!("the second observation records")
    };
    assert_ne!(
        first.contract_digest, second.contract_digest,
        "a committed contract changes the digest"
    );
    assert!(
        hk::observation_path(&git_dir, "sess", &first.contract_digest).exists(),
        "the earlier observation is not overwritten"
    );
    assert!(hk::observation_path(&git_dir, "sess", &second.contract_digest).exists());
}

/// The raw session identifier never reaches the disk (§5's exclusion list).
///
/// Asserted over the bytes rather than over the type, because the exclusion is
/// what the receipt is FOR: a host's session token may itself be sensitive, and
/// a field that quietly carried it would be indistinguishable from one that did
/// not until somebody read a record.
#[test]
fn no_record_carries_the_raw_session_or_a_path() {
    let dir = common::scratch("hk-observation-pointer-only");
    common::init_repo(&dir);
    let git_dir = dir.join(".git");
    let raw = "session-token-7f3a-not-for-disk";

    let Ok(Look::Is(record)) = hk::observe(&dir, &git_dir, Some(raw)) else {
        panic!("the observation records")
    };
    let path = hk::observation_path(&git_dir, raw, &record.contract_digest);
    let bytes = fs::read_to_string(&path).expect("the record reads back");

    assert!(!bytes.contains(raw), "the raw session token is not stored");
    assert!(
        !bytes.contains(&dir.display().to_string()),
        "no filesystem path is stored"
    );
    assert!(
        bytes.contains(hk::OBSERVATION_PREDICATE),
        "the record names its own predicate, so a reader matches on shape"
    );
    assert_ne!(record.session, raw);
    assert!(!record.session.is_empty());
}

/// A record whose predicate type is not this one does not answer this question.
///
/// Could-not-look rather than a value to reinterpret: a future `v2` must not be
/// read as a `v1` by a build that only knows the older shape.
#[test]
fn a_record_of_another_predicate_is_could_not_look() {
    let dir = common::scratch("hk-observation-predicate");
    common::init_repo(&dir);
    let git_dir = dir.join(".git");

    let path = hk::observation_path(&git_dir, "sess", "digest");
    fs::create_dir_all(path.parent().expect("the store has a parent"))
        .expect("the store directory");
    fs::write(
        &path,
        serde_json::json!({
            "predicateType": "hk-session-capability/v2",
            "session": "abc",
            "contractDigest": "digest",
            "configEpoch": "epoch",
            "toolVersion": null,
            "state": "available",
        })
        .to_string(),
    )
    .expect("seed another predicate");

    assert_eq!(
        hk::observed(&git_dir, "sess", "digest"),
        Look::CouldNotLook,
        "a record of another predicate answers no question this build asks"
    );
}

/// The end-to-end case a fixture cannot reach: the real runner, the committed
/// contract, and a record that reads back.
#[test]
fn this_session_can_observe_the_pinned_runner() {
    let root = common::at_root(".");
    let output = common::run_at_real_root(
        &root,
        &["hk", "observe", "--session", "hk-observation-suite"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "an observation is always exit 0 — failing to observe is an answer it carries.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let emitted = String::from_utf8_lossy(&output.stdout);
    let state = emitted.trim();
    assert!(
        [
            Capability::Available.as_str(),
            Capability::Drifted.as_str(),
            Capability::Unknown.as_str(),
        ]
        .contains(&state),
        "the verb emits one of the three state tokens, got {state:?}"
    );
    assert!(
        !emitted.contains("hk-observation-suite"),
        "the raw session token reaches no channel"
    );
}

/// The record's own store is under the git directory, never the working tree.
#[test]
fn the_store_is_per_checkout_and_never_committed() {
    let git_dir = Path::new("/tmp/example/.git");
    let path = hk::observation_path(git_dir, "sess", "digest");
    assert!(
        path.starts_with(git_dir),
        "the store is the git directory's"
    );
    assert!(
        path.to_string_lossy().ends_with(".digest.json"),
        "both cache components are in the name, which is what makes the once-per rule structural"
    );
}
