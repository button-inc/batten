//! The landing-path/clock split for zizmor (CLOUD-410), asserted over the task
//! definitions themselves — ported from `tests/zizmor-split.bats` under
//! CLOUD-843.
//!
//! There is no program here to test — zizmor is a pinned tool and the whole
//! change is WHICH INVOCATION runs WHERE. That is exactly the part that reverts
//! silently: dropping `--offline` restores a green-looking gate whose verdict
//! depends on api.github.com, and nothing else in the tree would notice until a
//! rate limit stopped a landing again. So the split is pinned as text.
//!
//! The measurement behind it: two laps of one `land` run over an unchanged tree —
//! `No findings to report`, then `403 Forbidden` on the advisories endpoint,
//! reported to the operator as "verify failed … reproduce and fix locally".
//!
//! # The INVOCATION, never the body
//!
//! Both readers extract the `zizmor` invocation from the task's commands, so a
//! change to whatever wraps it — a receipt, a step cache, an argv list in place
//! of a body — cannot break these cases and cannot hide the flag they watch.

// CLOUD-1268's fifth arm: `mise.toml` does not die, so every arm names it.
//
// ported: tests/zizmor-split.bats subject:mise.toml crates/batten/tests/it/zizmor_split.rs
// ported: "zizmor-split.bats::the landing-path invocation is offline" crates/batten/tests/it/zizmor_split.rs subject:mise.toml
// ported: "zizmor-split.bats::the scheduled invocation is not offline, or it would check nothing" crates/batten/tests/it/zizmor_split.rs subject:mise.toml
// ported: "zizmor-split.bats::the two audit the same targets at the same severity" crates/batten/tests/it/zizmor_split.rs subject:mise.toml
// ported: "zizmor-split.bats::verify depends on the offline one and never on the scheduled one" crates/batten/tests/it/zizmor_split.rs subject:mise.toml

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The `zizmor` invocation inside a named task, from the tool's name to the end
/// of its own command.
///
/// Anchored on `zizmor` followed by a FLAG — `--offline`, `--min-severity` —
/// rather than on the bare word, so a wrapper naming the step (`… step run zizmor
/// -- zizmor --offline …`) is read past rather than mistaken for the call. A
/// shell body's `if ! … ; then` framing ends at the first `;`, and quotes are
/// dropped so a quoted argument compares equal to a bare one.
fn invocation(task: &str) -> String {
    let call = regex::Regex::new(r"\bzizmor\s+--[A-Za-z]").expect("a valid expression");
    let found = common::task_commands(task)
        .into_iter()
        .find_map(|command| {
            let start = call.find(&command)?.start();
            let tail = &command[start..];
            let end = tail.find(';').unwrap_or(tail.len());
            Some(tail[..end].replace(['"', '\''], "").trim_end().to_owned())
        })
        .unwrap_or_default();
    assert!(
        found.starts_with("zizmor "),
        "[tasks.{task}] invokes no zizmor with a flag: {found:?}"
    );
    found
}

#[test]
fn the_landing_path_invocation_is_offline() {
    // The property. A gate on the landing path decides a question about THIS
    // COMMIT, and whether an action has an advisory today is not one.
    assert!(invocation("zizmor").contains("--offline"));
}

#[test]
fn the_scheduled_invocation_is_not_offline_or_it_would_check_nothing() {
    // The mirror. An advisory sweep that cannot reach the network answers
    // nothing while reporting success.
    assert!(!invocation("zizmor-advisories").contains("--offline"));
}

#[test]
fn the_two_audit_the_same_targets_at_the_same_severity() {
    // Only the network reach may differ. A split that also narrowed the target
    // set or relaxed the severity would be a coverage cut wearing a bug fix's
    // clothes.
    let landing = invocation("zizmor");
    let scheduled = invocation("zizmor-advisories");
    assert_eq!(landing.replacen("--offline ", "", 1), scheduled);
}

#[test]
fn verify_depends_on_the_offline_one_and_never_on_the_scheduled_one() {
    // `ci-local-parity` requires every task CI runs to be one `verify` runs, so
    // adding the online audit to `verify` would drag it back onto the landing
    // path through CI. `verify:gated` is the link that carries the gate set since
    // CLOUD-407 made `verify` a dependency-free sequence.
    let depends = common::task_depends("verify:gated");
    assert!(
        depends.iter().any(|task| task == "zizmor"),
        "verify:gated no longer depends on the offline audit: {depends:?}"
    );
    assert!(
        !depends
            .iter()
            .any(|task| task.contains("zizmor-advisories")),
        "verify:gated drags the online audit onto the landing path: {depends:?}"
    );
}
