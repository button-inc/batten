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
//!
//! # `opt-level` is the larger half, and it was unpinned until CLOUD-1289
//!
//! The three arms above are all about `debug`, and so were all four of this
//! file's cases — it contained zero occurrences of `opt-level`. But the same
//! `[profile.dev.package."*"]` block carries `opt-level = 2`, and CLOUD-1211
//! measured that as its **biggest single win**: `mise run test:cargo` warm
//! 100.189s to 48.581s, **2.06x on the whole suite**, because `batten hook`
//! against this repository's own ruleset is dominated by dependency code
//! evaluating Rego and unoptimised that work is 6.8x what the shipped binary
//! does.
//!
//! Dropping that key today reds nothing and exits 0. It simply doubles every
//! suite run, for every developer, until somebody thinks to time it — the same
//! silent shape as the byte regression above, one dial over.

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

/// What CLOUD-1289's adopted arm sets. A STRING, because cargo spells this one
/// as an enum rather than a number, and `"packed"` and `"off"` are the other two
/// values a later edit could land here without noticing.
const ADOPTED_SPLIT_DEBUGINFO: &str = "unpacked";

/// What the adopted arm sets for the DEPENDENCY closure's optimisation, which is
/// where the SUITE'S WALL CLOCK was — 100.189s to 48.581s warm, 2.06x.
const ADOPTED_DEPENDENCY_OPT_LEVEL: i64 = 2;

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

/// `[profile.dev.package."*"]` — the override both adopted values live on.
///
/// Panics rather than returning an option, because an absent block is itself the
/// regression: without it every dependency carries debuginfo again AND compiles
/// unoptimised, which is both halves of CLOUD-1211 undone at once.
fn dependency_override() -> toml::Value {
    dev_profile()
        .get("package")
        .and_then(|package| package.get(DEPENDENCY_GLOB))
        .cloned()
        .expect(
            "[profile.dev.package.\"*\"] is declared — without it every dependency \
             carries debuginfo again and the linked binaries go back to ~124 MB",
        )
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

/// `opt-level` read the same panicking way `declared_debug` is, and for the same
/// reason: an absent key is cargo's own default (`0` for the dev profile), so a
/// defaulting lookup would report the regression as satisfied.
///
/// Cargo also accepts `"s"` and `"z"` here. Neither is the adopted value, and
/// both panic naming what they found rather than being silently coerced to a
/// number they are not.
fn declared_opt_level(profile: &toml::Value) -> i64 {
    let value = profile.get("opt-level").expect(
        "this profile declares `opt-level` — an absent key is cargo's own default \
         of 0, which is the regression this asserts against",
    );
    match value {
        toml::Value::Integer(level) => *level,
        other => panic!("`opt-level` is not an integer: {other:?}"),
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
    let debug = declared_debug(&dependency_override());
    assert_eq!(
        debug, ADOPTED_DEPENDENCY_DEBUG,
        "[profile.dev.package.\"*\"] debug is {debug}, not the adopted \
         {ADOPTED_DEPENDENCY_DEBUG}. This override is where the byte saving comes \
         from — 15.53 GB to 6.82 GB across 125 linked artifacts — and dropping it \
         is silent until a session runs out of disk (CLOUD-766)."
    );
}

/// The wall-clock half of the same override, and the one nothing asserted until
/// CLOUD-1289. `debug` above is about `target/debug`'s bytes; this is about how
/// long every suite run takes, and it is the larger of the two numbers.
#[test]
fn the_dependency_closure_is_optimised() {
    let level = declared_opt_level(&dependency_override());
    assert_eq!(
        level, ADOPTED_DEPENDENCY_OPT_LEVEL,
        "[profile.dev.package.\"*\"] opt-level is {level}, not the adopted \
         {ADOPTED_DEPENDENCY_OPT_LEVEL}. This is CLOUD-1211's biggest single win — \
         `mise run test:cargo` warm 100.189s to 48.581s, 2.06x — and dropping it \
         reds nothing, exits 0, and doubles every suite run for everybody \
         (CLOUD-1289). If this is a deliberate change, move the constant and say \
         why in the same commit."
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

/// CLOUD-1289's arm, and the assertion is over the byte finding rather than the
/// time one: `unpacked` was 2.04x off the linked binaries against a null of zero
/// width, and inside the null on wall clock. Dropping it is silent for exactly
/// the reason the `debug` keys are — `target/debug` grows back by 5.2 GB and
/// nothing reds until a session runs out of disk.
#[test]
fn debuginfo_stays_out_of_the_linked_binaries() {
    let profile = dev_profile();
    let declared = profile
        .get("split-debuginfo")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .expect(
            "[profile.dev] declares `split-debuginfo` — an absent key is cargo's own \
             default, which on this host triple is the packed form CLOUD-1289 measured \
             at 2.04x more linked bytes",
        );
    assert_eq!(
        declared, ADOPTED_SPLIT_DEBUGINFO,
        "[profile.dev] split-debuginfo is {declared:?}, not the adopted \
         {ADOPTED_SPLIT_DEBUGINFO:?}. Measured 2026-09-01 as a paired A/B on one \
         machine: 10.19 GB of linked binaries to 4.99 GB, and `target/debug` 13.03 GB \
         to 7.76 GB, with the two identical baselines byte-identical to each other \
         (CLOUD-1289). If this is a deliberate change, move the constant and say why \
         in the same commit."
    );
}

/// ANTI-VACUITY for the case above, and it is not the same assertion twice: the
/// dev profile's `opt-level` default is `0` rather than an absent key, so a
/// defaulting lookup here would read the UNOPTIMISED build — the exact 2x
/// regression — as the adopted value. This pins the panicking read.
#[test]
fn an_absent_opt_level_key_is_not_read_as_the_adopted_value() {
    let fixture: toml::Value =
        toml::from_str("[profile.dev.package.\"*\"]\ndebug = 0\n").expect("fixture parses");
    let profile = fixture
        .get("profile")
        .and_then(|profile| profile.get("dev"))
        .and_then(|dev| dev.get("package"))
        .and_then(|package| package.get(DEPENDENCY_GLOB))
        .expect("the fixture declares the dependency override");

    assert!(
        profile.get("opt-level").is_none(),
        "the fixture is the absent-key case this asserts over"
    );
    let caught = std::panic::catch_unwind(|| declared_opt_level(profile));
    assert!(
        caught.is_err(),
        "an absent `opt-level` is cargo's own dev default of 0, not the adopted 2 — \
         reading it as satisfied is exactly the silent regression this file refuses"
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
