//! One assertion, in its own binary: **a bundle of N modules constructs one
//! engine** (CLOUD-837).
//!
//! # Why this is not in `policy_modules.rs`
//!
//! `policy::engines_constructed()` is a process-global counter, and cargo runs
//! the tests inside one binary concurrently. A delta measured beside seventeen
//! other cases that each compile a bundle would race every one of them — it
//! would pass or fail on scheduling, which is the least useful shape a gate can
//! have. Cargo runs each integration test FILE as its own process, so a file
//! containing this case alone measures exactly what it intends to.
//!
//! # Why a counter and not a clock
//!
//! CLOUD-837 §7 is explicit, and the reason is measurable: engine construction
//! is cheap enough that a per-module implementation and a per-bundle one are
//! indistinguishable on a wall clock. That is how the N-linear cost went
//! unmeasured — the published `wired` figure of 8.4ms was taken at N = 1, and a
//! 79-predicate bundle had never been priced at all. A count discriminates where
//! a timing assertion cannot.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::policy;

/// A trivial module in its own sub-package, so N of them compose rather than
/// conflict.
fn module(name: &str) -> (String, String) {
    (
        format!("{name}.rego"),
        format!("package batten.{name}\nimport rego.v1\nrules contains \"{name}\"\n"),
    )
}

#[test]
fn a_bundle_of_n_modules_constructs_exactly_one_engine() {
    let sources: Vec<(String, String)> = ["alpha", "beta", "gamma", "delta", "epsilon"]
        .into_iter()
        .map(module)
        .collect();

    let before = policy::engines_constructed();
    let bundle = policy::compile("policy-many", &sources).expect("five modules, one bundle");
    let after = policy::engines_constructed();

    assert_eq!(
        bundle.modules().len(),
        5,
        "all five are in the bundle, so the count below is over five modules"
    );
    assert_eq!(
        after - before,
        1,
        "five modules must construct ONE engine. Restoring `Engine::new()` to \
         the per-module loop makes this five, which is the shape CLOUD-837 \
         found: N isolated engines that cannot share a helper and do not form a \
         set to analyse."
    );
}
