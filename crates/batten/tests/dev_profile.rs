//! `[profile.dev]` declares what CLOUD-1211's adopted arm set.
//!
//! # Why a case rather than a comment
//!
//! CLOUD-1211's §7 asks for "a case asserting that whatever the adopted arms set
//! is what the committed profile declares — the shape `msrv-pin-agreement` uses
//! to hold two authorities together — so a later edit that drops a setting is a
//! finding rather than a silent regression."
//!
//! The regression this catches is silent by construction. Restoring `debug = 1`
//! (or letting it fall back to cargo's dev default of `2`) costs nothing a test
//! run can observe: the suite still passes, every gate still exits 0, and the
//! only symptom is `target/debug` growing back by an order of magnitude until a
//! session runs out of disk — which arrives as an unrelated rustc IO error
//! inside somebody else's test run, the misattribution CLOUD-766 records.
//!
//! # The measurement this pins
//!
//! Same `mise run test:cargo` both ways on one container, 2026-08-30, counting
//! `target/debug/deps`' extension-less linked binaries — the population
//! `crates/batten/src/prune.rs:262-269` reads:
//!
//! | `debug` | artifacts | linked bytes | `target/debug` |
//! | ------- | --------- | ------------ | -------------- |
//! | `1`     | 122       | 15.11 GB     | 19.18 GB       |
//! | `0`     | 123       | 1.60 GB      | 4.14 GB        |
//!
//! 9.4x off the linked artifacts, suite green both ways.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

/// What the adopted arm sets. Spelled as an integer because that is how cargo
/// reads it; `debug = true` is `2` and `debug = false` is `0`, so a later edit
/// spelling it as a bool is still judged on the value rather than the syntax.
const ADOPTED_DEBUG: i64 = 0;

fn dev_profile() -> toml::Value {
    let manifest = std::fs::read_to_string(common::at_root("Cargo.toml"))
        .expect("the workspace manifest is where the profiles are declared");
    let parsed: toml::Value = toml::from_str(&manifest).expect("Cargo.toml parses as TOML");
    parsed
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .cloned()
        .expect("[profile.dev] is declared")
}

/// `debug` normalised across the two spellings cargo accepts.
fn declared_debug(profile: &toml::Value) -> i64 {
    let value = profile
        .get("debug")
        .expect("[profile.dev] declares `debug` — an absent key is cargo's default of 2, which is the regression this asserts against");
    match value {
        toml::Value::Integer(level) => *level,
        toml::Value::Boolean(true) => 2,
        toml::Value::Boolean(false) => 0,
        other => panic!("[profile.dev] debug is neither an integer nor a bool: {other:?}"),
    }
}

#[test]
fn the_dev_profile_declares_the_adopted_debug_level() {
    let debug = declared_debug(&dev_profile());
    assert_eq!(
        debug, ADOPTED_DEBUG,
        "[profile.dev] debug is {debug}, not the adopted {ADOPTED_DEBUG}. Measured \
         2026-08-30, `debug = 1` put 15.11 GB into 122 linked test artifacts \
         against 1.60 GB at `debug = 0` — a 9.4x difference whose only symptom is \
         a full disk arriving as somebody else's rustc IO error (CLOUD-766, \
         CLOUD-1211). If this is a deliberate revert, move this constant and say \
         why in the same commit."
    );
}

/// ANTI-VACUITY, and it is the case that would actually have caught the drift.
/// The assertion above passes over a manifest that declares `[profile.dev]` and
/// nothing else only because `declared_debug` panics on the absent key — this
/// pins that reading, so loosening it to a defaulting lookup fails here rather
/// than passing silently over cargo's `2`.
#[test]
fn an_absent_debug_key_is_not_read_as_the_adopted_value() {
    let manifest: toml::Value =
        toml::from_str("[profile.dev]\nincremental = true\n").expect("fixture parses");
    let profile = manifest
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .expect("the fixture declares [profile.dev]");

    assert!(
        profile.get("debug").is_none(),
        "the fixture is the absent-key case this asserts over"
    );
    let caught = std::panic::catch_unwind(|| declared_debug(profile));
    assert!(
        caught.is_err(),
        "an absent `debug` is cargo's default of 2, not the adopted 0 — reading it \
         as satisfied is exactly the silent regression this file exists to refuse"
    );
}

/// `[profile.dist]` and `[profile.release]` are out of CLOUD-1211's scope: they
/// build the shipped artifact, and a test-loop change must not reach them. This
/// pins that boundary rather than trusting the commit that drew it.
#[test]
fn the_shipped_profiles_are_untouched_by_the_test_loop_arm() {
    let manifest = std::fs::read_to_string(common::at_root("Cargo.toml"))
        .expect("the workspace manifest is where the profiles are declared");
    let parsed: toml::Value = toml::from_str(&manifest).expect("Cargo.toml parses as TOML");
    let profiles = parsed.get("profile").expect("[profile] is declared");

    for shipped in ["release", "dist"] {
        let profile = profiles
            .get(shipped)
            .unwrap_or_else(|| panic!("[profile.{shipped}] is declared"));
        assert!(
            profile.get("debug").is_none(),
            "[profile.{shipped}] gained a `debug` key — CLOUD-1211 is a test-loop \
             change and the shipped artifact's profile is explicitly out of its scope"
        );
    }
}
