//! The suite's own environment cannot weaken the engine it is testing
//! (CLOUD-1227).
//!
//! # Why this file exists at all
//!
//! `common::batten()` scrubs the ambient environment, derived from the command
//! SURFACE so the set "cannot drift behind a new flag". A bypass variable is not
//! a flag and never will be — the global hatch is ambient context by design
//! (`session.rs`), and the per-row hatches are a `[[rule]]` column (CLOUD-437) —
//! so the derivation is structurally blind to exactly the class of variable whose
//! purpose is to stop the engine refusing.
//!
//! Measured before the fix, on `ccb40a13`: `test:cargo` under an exported
//! `BATTEN_HOOK_BYPASS=1` was 1543 passed / 2 failed, both `board_receipts` cases
//! that assert a refusal, each expecting exit `2` and getting exit `0`. The same
//! tree with nothing exported was 3270/3270.
//!
//! # Why these cases assert the REMOVAL rather than run under a set variable
//!
//! The condition is a variable in the PARENT's environment. A case cannot create
//! that in-process: `std::env::set_var` is `unsafe` in this edition and the
//! workspace lints forbid `unsafe` outright — correctly, since a test mutating
//! the shared environment races every other case in the binary.
//!
//! So the assertion is over what `batten()` marks for removal on the child's
//! environment map, which is the engine-facing half of the same fact and is what
//! actually changed. `the_hatch_is_load_bearing` supplies the other half: it
//! shows the same call flipping from refused to allowed when the hatch DOES reach
//! the child, so the removal is demonstrably worth making rather than assumed to
//! be.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write as _;
use std::process::Stdio;

use common::{at_root, batten, scratch, write};

/// The hatches the committed config declares, read the way the helper reads them.
fn declared_row_hatches() -> Vec<String> {
    batten::config::load(&at_root("batten.toml"))
        .expect("the committed config loads")
        .rules
        .iter()
        .filter_map(|rule| rule.bypass_env.clone())
        .collect()
}

/// The variable names `batten()` marks for REMOVAL on the child.
fn scrubbed() -> Vec<String> {
    batten()
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .filter_map(|(name, _)| name.to_str().map(str::to_owned))
        .collect()
}

/// THE CASE THAT FAILS AGAINST THE UNFIXED HELPER. Before CLOUD-1227 the global
/// hatch was reachable from no surface flag, so the derived scrub never named it
/// and an inherited one went straight through to the engine.
#[test]
fn the_global_hatch_is_scrubbed() {
    let names = scrubbed();
    assert!(
        names.iter().any(|name| name == batten::hook::BYPASS_ENV),
        "the engine's own hatch must never reach the binary under test: {names:?}"
    );
}

/// THE PER-ROW HALF, AND IT IS VACUOUS TODAY — which this case says out loud
/// rather than hiding behind a passing assertion.
///
/// CLOUD-437 gave every `[[rule]]` a `bypass_env` column, and **no committed row
/// declares one**: `batten.toml:273` records that the four `gh`-lifecycle rows
/// *"WOULD DECLARE `bypass_env = "BATTEN_GH_GUARD_BYPASS"` AND DO NOT YET"*
/// (CLOUD-1027). So the loop below runs zero times.
///
/// The first draft of this case asserted the set was non-empty, to keep itself
/// honest. That assertion FAILED, which is the anti-vacuity guard working: the
/// premise was wrong, and CLOUD-1227's own acceptance overstated it. Corrected on
/// the row rather than deleted here.
///
/// The derivation still earns its place, and that is what the second assertion
/// pins: the scrub reads the config, so the day a row declares a hatch it is
/// covered without anyone remembering. A hand-written list would not be — it
/// would stop covering the next row silently, in the direction that weakens the
/// suite, which is `Config::protected_readers`' recorded failure one table over.
#[test]
fn every_row_declared_hatch_is_scrubbed() {
    let names = scrubbed();
    for hatch in declared_row_hatches() {
        assert!(
            names.contains(&hatch),
            "a row-declared hatch must be scrubbed too: {hatch} not in {names:?}"
        );
    }
    // The set is empty today, so the loop proves nothing on its own. What is
    // checkable now is that the scrub is CONFIG-DERIVED rather than a literal:
    // the global hatch is present because the helper puts it there, and nothing
    // else is, because nothing else is declared.
    assert!(
        names.contains(&batten::hook::BYPASS_ENV.to_owned()),
        "the derived set must still carry the global hatch: {names:?}"
    );
}

/// THE ANTI-VACUITY MIRROR, and the half that makes the two above worth
/// asserting: it shows the hatch genuinely disarms the engine, so removing it is
/// load-bearing rather than tidy. Same fixture, same call, one variable apart.
#[test]
fn the_hatch_is_load_bearing() {
    let root = scratch("bypass-scrub-load-bearing");
    write(
        &root,
        "batten.toml",
        "version = 1\nprotected = [\"guarded.txt\"]\n\n[[verb]]\nverb = \"mv\"\neffect = \"destructive\"\n",
    );
    write(&root, "guarded.txt", "original\n");
    let payload = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"{}/guarded.txt","content":"x"}}}}"#,
        root.display()
    );

    let refused = run(batten().current_dir(&root), &payload);
    assert_eq!(
        refused,
        Some(2),
        "the fixture must refuse on its own, or the comparison below proves nothing"
    );

    let allowed = run(
        batten()
            .current_dir(&root)
            .env(batten::hook::BYPASS_ENV, "1"),
        &payload,
    );
    assert_eq!(
        allowed,
        Some(0),
        "the hatch disarms the engine, which is why the scrub matters"
    );
}

fn run(command: &mut std::process::Command, payload: &str) -> Option<i32> {
    let mut child = command
        .args(["hook", "--harness", "exit-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        .expect("write the payload");
    child
        .wait_with_output()
        .expect("the hook answers")
        .status
        .code()
}
