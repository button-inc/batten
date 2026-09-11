//! The lease's ref-namespace premise is measured, not remembered (CLOUD-416).
//!
//! `lease::Terms` explains why the lease lives on `refs/heads`. For two years the
//! explanation carried two claims and only one was true:
//!
//! 1. *"this sandbox proxies git and its write policy refuses any push outside
//!    `refs/heads`"* — **false**. Measured 2026-09-11 as a controlled pair, one
//!    variable: the same parentless orphan pushed to the same `refs/sessions/<sha>`
//!    exits `0` with `github.com` fenced and the PAT supplied through a credential
//!    helper, and returns `HTTP 403` unfenced with the harness-injected token.
//!    `refs/batten-probe/<nonce>` behaved identically. The 403 is a credential that
//!    is unscoped for the write; the namespace never came into it.
//! 2. *"GitHub also does not enforce the fast-forward rule off `refs/heads`"* —
//!    **true**, and the same run confirmed it: the parentless orphan was accepted.
//!
//! # Why this is a test and not a comment
//!
//! Because it was a comment, and the comment was wrong, and the tree believed it.
//! CLOUD-416 records the lease being implemented four times with "two of those
//! passes existed only because the environment lied and nothing said so". A
//! premise that expensive earns an assertion; `rules/scanning.md`'s own rule is
//! that a claim worth designing around is worth something executable, and the
//! absence of one is itself the finding.
//!
//! # WHAT THIS ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
//!
//! It asserts **presence and absence in the prose**: the refuted namespace claim
//! is gone, the surviving fast-forward reason is stated, and the measurement is
//! named so the next reader can re-run it rather than re-derive it. That is the
//! same shape as `scanner_taxonomy.rs` and `spawn_census.rs` — the prose carries
//! the position and the test keeps it from evaporating.
//!
//! It does **not** re-run the probe. A test that pushed to a real remote would
//! need a credential, would write to a shared forge from `cargo test`, and would
//! fail on every host that is not this one — which is the homogeneity fallacy
//! compiled into a test target. The probe is an operator procedure; this is the
//! ratchet that stops its answer being forgotten.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The module whose doc comment carries the premise.
const LEASE: &str = "crates/batten/src/lease.rs";

fn lease_source() -> String {
    fs::read_to_string(at_root(LEASE)).expect("the lease module is readable")
}

#[test]
fn the_refuted_namespace_claim_is_not_stated_anywhere_in_the_lease() {
    // THE PREMISE CASE. The sentence below is what sent four implementations down
    // the wrong path; if it returns in any spelling, this file is the thing that
    // says so.
    let source = lease_source();
    for refuted in [
        "refuses any push outside",
        "write policy refuses",
        "the day the proxy allows it",
    ] {
        assert!(
            !source.contains(refuted),
            "{LEASE} states the refuted namespace claim again ({refuted:?}); \
             the 403 is a credential, not a namespace — see CLOUD-416"
        );
    }
}

#[test]
fn the_surviving_reason_is_the_fast_forward_rule() {
    // Deleting the false half must not take the true half with it. The lease is on
    // `refs/heads` because the forge does not enforce fast-forward off it — and a
    // reader who finds no reason at all will move the lease and lose that.
    let source = lease_source();
    assert!(
        source.contains("fast-forward"),
        "{LEASE} must still state the fast-forward rule as the reason the lease \
         lives on refs/heads"
    );
    assert!(
        source.contains("parentless orphan"),
        "{LEASE} must still name the orphan acceptance that measures it"
    );
}

#[test]
fn the_measurement_is_named_so_it_can_be_rerun() {
    // A correction that says only "this was wrong" leaves the next reader with a
    // bare assertion to trust, which is the failure one layer over. Both arms of
    // the controlled pair have to be legible.
    let source = lease_source();
    assert!(
        source.contains("403"),
        "{LEASE} must record the unfenced arm's status"
    );
    assert!(
        source.contains("CLOUD-416"),
        "{LEASE} must point at the row that owns the misdiagnosis"
    );
}

#[test]
fn the_correction_does_not_generalise_the_fast_forward_loss_into_a_ban() {
    // The old text concluded "which is the whole safety property gone", and that
    // conclusion — drawn once about the lease — is what would refuse the log branch
    // and the transcript refs if it were reused. One property, opposite signs,
    // decided per structure.
    let source = lease_source();
    assert!(
        !source.contains("the whole safety property gone"),
        "{LEASE} must not restate the over-general conclusion: a missing \
         fast-forward rule is a loss for a branch-shaped ref and the enabling \
         property for a content-addressed one"
    );
}
