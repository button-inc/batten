//! The commit-identity precedence record is present on the surface that is
//! actually loaded when it is needed (CLOUD-605).
//!
//! A user-level stop hook outside this repository prescribes reconfiguring the
//! committer to a vendor no-reply identity and amending. Complying produces a
//! commit `[attribution] identity_deny` refuses. The gate has never failed —
//! what was missing was the record, so three refusals in one session were each
//! argued from first principles against `batten.toml`, and six more in a later
//! session across two container restarts.
//!
//! WHY AGENTS.md AND NOT `rules/commits.md`. That was the original
//! placement and it is falsified: `commits.md` is path-scoped by its frontmatter
//! to `CHANGELOG.md`, `release-plz.toml` and `Cargo.toml`, while the hook fires
//! on every commit in every session, most of which touch none of those three. A
//! record absent at the moment it is needed is indistinguishable from one that
//! was never written. AGENTS.md is the only always-loaded instruction surface,
//! so the record lives there and `commits.md` keeps the detail.
//!
//! WHAT THIS ASSERTS, AND WHAT IT CANNOT. Presence: the always-loaded file still
//! names `identity_deny` as the authority over a harness identity request, still
//! points the signature half at its own issue rather than absorbing it, and
//! still routes to the detail. That catches deletion and drift — the failure
//! mode for a rule whose whole value is being readable at Stop time.
//!
//! It does not catch a session that reads the line and complies anyway. The
//! runnable half of that is `no-denied-identity-prescribed`, which refuses the
//! prescription in the tree, and `identity_deny` itself, which refuses the
//! commit. Same shape as `scanner_taxonomy.rs`: the prose carries the position,
//! and the test keeps the prose from evaporating.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use common::at_root;

/// The always-loaded instruction surface the record has to live on.
const INSTRUCTIONS: &str = "AGENTS.md";

/// The path-scoped file that carries the detail behind the record.
const DETAIL: &str = "rules/commits.md";

fn read(path: &str) -> String {
    fs::read_to_string(at_root(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

#[test]
fn the_always_loaded_surface_records_which_authority_governs_commit_identity() {
    let instructions = read(INSTRUCTIONS);

    // The authority, named rather than restated. `identity_deny`'s patterns stay
    // in `batten.toml`; a copy here would be the second-authority defect the row
    // itself warns against.
    assert!(
        instructions.contains("identity_deny"),
        "{INSTRUCTIONS} must name `identity_deny` as the authority over commit identity"
    );

    // That it OUTRANKS the request is the whole content. Naming the gate without
    // saying which side wins leaves the reader exactly where the three refusals
    // found them.
    assert!(
        instructions.contains("outranks any harness identity request"),
        "{INSTRUCTIONS} must state that the repository's deny-set outranks a harness request"
    );

    // The signature half stays somebody else's, because the remedies differ:
    // resetting the author signs nothing.
    assert!(
        instructions.contains("CLOUD-591"),
        "{INSTRUCTIONS} must point the signature half at its own issue rather than absorbing it"
    );

    // And the reader has to be able to reach the detail from here.
    assert!(
        instructions.contains(DETAIL),
        "{INSTRUCTIONS} must route to {DETAIL} for the detail"
    );
}

#[test]
fn the_detail_states_why_the_hooks_predicate_cannot_be_satisfied() {
    let detail = read(DETAIL);

    // The three measured facts, each of which someone otherwise re-derives. The
    // first is the one that makes the clash irreducible rather than a setting
    // nobody has tuned.
    // "Deleting the FILE" rather than the "Deleting it" this pinned until
    // CLOUD-1356, and the change of one word is the reason the case moved.
    //
    // The finding is unchanged and still measured: a delete does not survive the
    // launcher's re-provision. What the old wording left open is WHAT does not
    // survive — and that ambiguity was load-bearing in the wrong direction. From
    // "it" a reader inferred that the REGISTRATION was equally beyond reach, and
    // wrote that the only remedy is an owner action outside this repository. It
    // is not: `batten wiring reclaim` removes the registration without touching
    // the file, and a `session-start` handler runs it every session (CLOUD-1079,
    // measured 2 -> 0 on this container).
    //
    // So the assertion was pinning the sentence rather than the finding, which
    // is CLOUD-1152's own diagnosis of this file's class: a core-crate test over
    // one vendor folder's prose owns the wording, not the rule.
    for phrase in [
        "unsatisfiable here",
        "Deleting the FILE does not survive",
        "unknown_key",
        "rejected on noise",
    ] {
        assert!(
            detail.contains(phrase),
            "{DETAIL} must still carry the measured finding \"{phrase}\""
        );
    }

    // The standing mechanism is named where the detail lives, so a reader who
    // arrives here knows the prose is not the only thing holding the line.
    assert!(
        detail.contains("no-denied-identity-prescribed"),
        "{DETAIL} must name the row that refuses the prescription in the tree"
    );
}
