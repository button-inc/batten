//! The per-rule cost reading is on the `-vv` rung and the answer channel does not
//! carry it (CLOUD-1321).
//!
//! # Why this is a separate case from `rule_cost_census.rs`
//!
//! That file asserts the census is CORRECT — one row per rule, counts tracking
//! what was opened, cleared per run — through `run_static`, in process. It never
//! runs the binary, so nothing in it can tell which verbosity rung the reading is
//! rendered at, or whether rendering it disturbed stdout. Those are the two
//! properties a CONSUMER depends on, and they were unheld: CLOUD-1217 landed the
//! instrument and argued the rung at `lib.rs:9872-9896`, and the argument was
//! prose with no mechanism under it, which non-negotiable rule 2 refuses.
//!
//! # The rung is the load-bearing assertion, not the presence
//!
//! `-vv` carrying `rule cost:` is the easy half and a build that emitted it at
//! every rung would satisfy it. The case that decides something is **`-v` staying
//! silent**: it pins the boundary, so a later promotion of the reading to `-v` is
//! a red case here rather than ~84 lines of non-byte-stable stderr appearing
//! under every `-v` consumer without anyone choosing it. CLOUD-1321 proposed
//! exactly that promotion, on the premise that the instrument did not yet exist;
//! it did, and this is what makes the rung a decision somebody has to reverse
//! deliberately.
//!
//! # And stdout is compared byte for byte
//!
//! A duration is not byte-stable, so house-style §6 puts it on stderr or nowhere.
//! Asserting that `check` and `check -vv` agree on stdout EXACTLY is what proves
//! the reading never leaked into the answer, and it is the assertion that would
//! catch the obvious wrong fix — rendering the census through the same writer the
//! findings use.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::Fixture;

/// The marker `report_rule_costs` renders each row with.
const MARKER: &str = "rule cost:";

/// A one-rule fixture that finds nothing.
///
/// **A CLEAN tree on purpose.** The subject here is the census, which is emitted
/// for every rule whether or not it reported — so a fixture with a finding would
/// put a refusal on stdout and make the byte-for-byte comparison below a
/// comparison of two refusals instead of two clean answers.
fn fixture(name: &str) -> std::path::PathBuf {
    Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"reads-the-md\"\n\
             kind = \"forbid\"\n\
             scope = \"tree\"\n\
             glob = \"*.md\"\n\
             pattern = \"a-literal-no-fixture-carries\"\n\
             severity = \"deny\"\n",
        )
        .file("README.md", "# a fixture\n\nnothing this rule looks for.\n")
        .build()
}

#[test]
fn the_cost_reading_is_on_the_debug_rung_and_never_below_it() {
    let root = fixture("cost-rung");

    let quiet = common::run(&root, &["check"]);
    let verbose = common::run(&root, &["check", "-v"]);
    let debug = common::run(&root, &["check", "-vv"]);

    // Every arm is the same clean answer, or the comparison below is between two
    // different questions.
    for (label, output) in [
        ("check", &quiet),
        ("check -v", &verbose),
        ("check -vv", &debug),
    ] {
        assert_eq!(
            output.status.code(),
            Some(0),
            "{label} must be clean over this fixture, or the arms are not comparable: {}",
            common::stderr(output)
        );
    }

    // THE RUNG. Silent at the default and at `-v`; present at `-vv`.
    //
    // Fails by: moving the `report_rule_costs` call in `lib.rs` from the
    // `Verbosity::Debug` arm to the `Verbose` one, which is precisely the change
    // CLOUD-1321 asked for and this case exists to make deliberate.
    assert!(
        !common::stderr(&quiet).contains(MARKER),
        "the default rung carries no cost reading: {}",
        common::stderr(&quiet)
    );
    assert!(
        !common::stderr(&verbose).contains(MARKER),
        "`-v` carries no cost reading — promoting it here widens every `-v` \
         consumer's stderr by a row per rule, none of it byte-stable: {}",
        common::stderr(&verbose)
    );
    assert!(
        common::stderr(&debug).contains(MARKER),
        "`-vv` is the rung the reading is rendered at, and it is missing: {}",
        common::stderr(&debug)
    );
}

#[test]
fn reading_the_cost_leaves_the_answer_channel_byte_identical() {
    let root = fixture("cost-answer-channel");

    let quiet = common::run(&root, &["check"]);
    let debug = common::run(&root, &["check", "-vv"]);

    // THE §6 PROPERTY. A duration is not byte-stable, so it belongs on stderr or
    // nowhere — and the way that goes wrong is rendering the census through the
    // writer the findings use, which this compares exactly rather than by
    // substring.
    //
    // Fails by: rendering `report_rule_costs` to stdout.
    assert_eq!(
        common::stdout(&quiet),
        common::stdout(&debug),
        "raising verbosity to the cost rung must not move a byte of the answer"
    );
    assert_eq!(
        quiet.status.code(),
        debug.status.code(),
        "nor the exit code"
    );

    // ANTI-VACUITY. Both stdouts being empty would satisfy the equality above
    // however the census behaved, so assert the debug arm actually took the
    // branch this case is about.
    assert!(
        common::stderr(&debug).contains(MARKER),
        "the `-vv` arm must have rendered the census, or the equality above \
         compares two runs that never reached it: {}",
        common::stderr(&debug)
    );
}
