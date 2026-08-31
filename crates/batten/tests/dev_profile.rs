//! `[profile.dev]` declares what CLOUD-1211's adopted arm set.
//!
//! # Why a case rather than a comment
//!
//! CLOUD-1211's §7 asks for "a case asserting that whatever the adopted arms set
//! is what the committed profile declares — the shape `msrv-pin-agreement` uses
//! to hold two authorities together — so a later edit that drops a setting is a
//! finding rather than a silent regression."
//!
//! The regression this catches is silent by construction. Dropping the
//! dependency override, or letting `debug` fall back to cargo's dev default of
//! `2`, costs nothing a test run can observe: the suite still passes, every gate
//! still exits 0, and the only symptom is `target/debug` growing back until a
//! session runs out of disk — which arrives as an unrelated rustc IO error inside
//! somebody else's test run, the misattribution CLOUD-766 records.
//!
//! # The three arms, and why the biggest number is the rejected one
//!
//! Each a cold `mise run test:cargo` over a cleared `target/debug`, this
//! container, 2026-08-30, counting `target/debug/deps`' extension-less linked
//! binaries — the population `crates/batten/src/prune.rs:262-269` reads:
//!
//! | arm                              | artifacts | linked bytes | mean     |
//! | -------------------------------- | --------- | ------------ | -------- |
//! | `debug = 1` (baseline)           | 125       | 15.53 GB     | 124.3 MB |
//! | `debug = 0` whole profile        | 123       | 1.60 GB      | 13.0 MB  |
//! | `debug = 1` + deps `0` (adopted) | 125       | 6.82 GB      | 54.5 MB  |
//!
//! **The middle arm is 9.7x and is refused anyway.** It drops debuginfo from the
//! entire dev profile, `batten`'s own code included, so a panicking test reports
//! a backtrace with no line numbers — the diagnostic a reader needs at exactly
//! the moment it is gone. It was briefly committed and reverted; this file is
//! what makes that reversal hold.
//!
//! The adopted arm takes 2.3x off the bytes by stripping the dependency closure,
//! which is where they were, while every `batten` frame keeps its file and line.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

/// What the adopted arm sets for WORKSPACE code. Spelled as an integer because
/// that is how cargo reads it; `debug = true` is `2` and `debug = false` is `0`,
/// so a later edit spelling it as a bool is judged on the value, not the syntax.
const ADOPTED_DEBUG: i64 = 1;

/// What the adopted arm sets for the DEPENDENCY closure, which is where the
/// bytes actually were — 124.3 MB to 54.5 MB per linked binary.
const ADOPTED_DEPENDENCY_DEBUG: i64 = 0;

/// The glob cargo spells "every dependency, but not workspace members".
const DEPENDENCY_GLOB: &str = "*";

fn manifest() -> toml::Value {
    let text = std::fs::read_to_string(common::at_root("Cargo.toml"))
        .expect("the workspace manifest is where the profiles are declared");
    toml::from_str(&text).expect("Cargo.toml parses as TOML")
}

fn dev_profile() -> toml::Value {
    manifest()
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .cloned()
        .expect("[profile.dev] is declared")
}

/// `debug` normalised across the two spellings cargo accepts. Panics on an
/// absent key rather than defaulting, which is the reading
/// `an_absent_debug_key_is_not_read_as_the_adopted_value` pins.
fn declared_debug(profile: &toml::Value) -> i64 {
    let value = profile.get("debug").expect(
        "this profile declares `debug` — an absent key is cargo's own default, \
         which is the regression this asserts against",
    );
    match value {
        toml::Value::Integer(level) => *level,
        toml::Value::Boolean(true) => 2,
        toml::Value::Boolean(false) => 0,
        other => panic!("`debug` is neither an integer nor a bool: {other:?}"),
    }
}

#[test]
fn workspace_code_keeps_its_line_tables() {
    let debug = declared_debug(&dev_profile());
    assert_eq!(
        debug, ADOPTED_DEBUG,
        "[profile.dev] debug is {debug}, not the adopted {ADOPTED_DEBUG}. This is \
         the half that must NOT be traded for bytes: at `debug = 0` the whole dev \
         profile loses debuginfo and a panicking test reports a backtrace with no \
         line numbers. That arm was measured at 9.7x off the artifacts, committed, \
         and reverted for exactly this reason (CLOUD-1211). If this is a deliberate \
         change, move the constant and say why in the same commit."
    );
}

#[test]
fn the_dependency_closure_carries_no_debuginfo() {
    let debug = manifest()
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .and_then(|dev| dev.get("package"))
        .and_then(|package| package.get(DEPENDENCY_GLOB))
        .map(declared_debug)
        .expect(
            "[profile.dev.package.\"*\"] is declared — without it every dependency \
             carries debuginfo again and the linked binaries go back to ~124 MB",
        );
    assert_eq!(
        debug, ADOPTED_DEPENDENCY_DEBUG,
        "[profile.dev.package.\"*\"] debug is {debug}, not the adopted \
         {ADOPTED_DEPENDENCY_DEBUG}. This override is where the byte saving comes \
         from — 15.53 GB to 6.82 GB across 125 linked artifacts — and dropping it \
         is silent until a session runs out of disk (CLOUD-766)."
    );
}

/// ANTI-VACUITY, and it is the case that would actually have caught the drift.
/// Both assertions above pass over a profile that declares the key at the right
/// value; neither would notice a `declared_debug` loosened to a defaulting
/// lookup, which would read an ABSENT key as cargo's default and report it as
/// satisfied. This pins the panicking read.
#[test]
fn an_absent_debug_key_is_not_read_as_the_adopted_value() {
    let fixture: toml::Value =
        toml::from_str("[profile.dev]\nincremental = true\n").expect("fixture parses");
    let profile = fixture
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
        "an absent `debug` is cargo's own default, not the adopted value — reading \
         it as satisfied is exactly the silent regression this file refuses"
    );
}

/// `[profile.dist]` and `[profile.release]` are out of CLOUD-1211's scope: they
/// build the shipped artifact, and a test-loop change must not reach them. This
/// pins that boundary rather than trusting the commit that drew it.
#[test]
fn the_shipped_profiles_are_untouched_by_the_test_loop_arm() {
    let parsed = manifest();
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
