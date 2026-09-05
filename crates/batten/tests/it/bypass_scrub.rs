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

use crate::common;

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
        // A `shape` ROW RATHER THAN THE PROTECTED GATE, and the swap is the point
        // rather than a convenience.
        //
        // This case used to observe the hatch through a protected-path refusal,
        // which was the obvious choice while the hatch reached every row. It no
        // longer reaches `path write refused`: that class declares an override
        // route and the boundary honours a spent admission for it, so the variable
        // stopped being its way out. Observing the hatch through the one gate it
        // deliberately cannot open would assert the opposite of the contract.
        //
        // The subject here is CLOUD-1227's scrub — that an exported hatch in the
        // SUITE's environment can weaken the engine under test — and any refusable
        // row demonstrates it. A `shape` row is the rest of the mediated surface
        // and is what the hatch still answers for.
        "version = 1\n\n[[rule]]\nid = \"no-touching\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"deny\"\npattern = \"touch guarded.txt\"\n\
         reason = \"the fixture refuses this on its own\"\n",
    );
    write(&root, "guarded.txt", "original\n");
    // BUILT BY THE SERIALIZER, NOT BY INTERPOLATION. A path is being embedded in
    // a JSON string, and on Windows `Path::display` renders backslashes — which
    // JSON reads as escapes, so `D:\a\_temp\...` arrives as a mangled `\a` and
    // `\_`. The engine then matches nothing and the fixture ALLOWS, which fails
    // the precondition below rather than the assertion it guards.
    //
    // Measured on the Windows job: exit 0 where every other platform gave 2.
    // Same class as `mediated_verbs::absolute`, one escape context over — there a
    // shell command, here a JSON document. Letting `serde_json` render the path
    // removes the class rather than the instance.
    // A COMMAND RATHER THAN A WRITE TOOL, following the row above. The path-in-JSON
    // hazard the comment above records belonged to the `file_path` field; a shape
    // row matches the command line, which carries no absolute path at all.
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "touch guarded.txt"},
    })
    .to_string();

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

/// THE THIRD CHANNEL, AND THE ONE THIS FILE ALREADY KNEW ABOUT.
///
/// `the_hatch_is_load_bearing` above had to stop observing the hatch through a
/// protected-path refusal, and its comment says why in as many words: *"that
/// class declares an override route and the boundary honours a spent admission
/// for it, so the variable stopped being its way out."* So this suite recorded
/// that an ADMISSION had replaced the variable for that class — and then left the
/// admission store ambient, which is the half nobody closed.
///
/// The two scrubs this file asserts are walks over ENVIRONMENT VARIABLES, and an
/// admission is a signed record in the state store rather than a knowable string.
/// CLOUD-1051 made it that way on purpose. So the channel that replaced the
/// scrubbed ones is unreachable from either walk by construction, and the state
/// root has to be redirected explicitly instead.
///
/// A FIXTURE HOME CANNOT ESCAPE THIS, which is why the redirect belongs in
/// `common::batten()` rather than in each case. The state segment is derived from
/// the repository root, so a suite whose subject is the COMMITTED config — this
/// one, `mediated_verbs.rs`, `gh_guard.rs`, `pipeline_shapes.rs`,
/// `refusal_ceiling.rs` — runs against the real root and therefore reads the real
/// repository's own segment. `mediated_admission.rs` is unaffected for exactly
/// the same reason, in the other direction: its fixture is a scratch repo, so it
/// has always had a segment of its own.
#[test]
fn the_ambient_state_root_never_reaches_the_binary_under_test() {
    // READ THROUGH `common`, NEVER BY NAMING THE VARIABLES HERE. That module is
    // the one place they may be spelled, which
    // `primitives::no_suite_sets_the_state_dir_variables_itself` enforces — a
    // case that re-typed them to assert the redirect would become the copy that
    // audit exists to refuse, while claiming there are none.
    let redirected = common::state_roots(&common::batten_at_real_root());
    assert_eq!(
        redirected.len(),
        2,
        "both state roots must be redirected, on every platform: {redirected:?}"
    );
    let scratch_root = common::scratch_state_root();
    for (name, value) in &redirected {
        assert_eq!(
            value.as_path(),
            scratch_root,
            "{name} must point at the suite's own state root, never the developer's"
        );
    }
}

/// THE ANTI-VACUITY MIRROR for the case above, and the same shape
/// `the_hatch_is_load_bearing` uses one screen up: it shows an admission
/// genuinely disarming the committed policy, so redirecting the store it lives in
/// is load-bearing rather than tidy.
///
/// Over the REAL repository root, deliberately — a scratch fixture would prove
/// the mechanism and miss the defect, because the defect IS that these suites
/// share the real repository's segment. Contained only because the case above now
/// holds: every spawn here writes into the suite's own state root, so issuing and
/// spending a real admission cannot touch the developer's store.
///
/// MEASURED 2026-09-02, before the redirect landed. A spent admission for
/// `batten.toml` — taken by hand, for unrelated work, hours earlier in the same
/// session — turned
/// `cli.rs::the_committed_protected_paths_fire_on_a_mutating_verb` green-side:
/// `mv batten.toml elsewhere.toml` answered exit `0` where that case demands `2`.
/// The suite reported that the committed protected-path policy refuses a write
/// while a record on the machine was admitting it.
#[test]
fn an_admission_in_the_store_disarms_the_committed_protected_gate() {
    let root = at_root("batten.toml");
    let root = root.parent().expect("the committed config has a parent");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "mv batten.toml elsewhere.toml"},
    })
    .to_string();

    let refused = run(common::batten_at_real_root().current_dir(root), &payload);
    assert_eq!(
        refused,
        Some(2),
        "the committed policy must refuse on its own, or the comparison below proves nothing"
    );

    let answers = "precondition=the suite is demonstrating that this channel admits, which is \
                   the property the redirect above exists to contain\n\
                   lost=nothing: this admission is spent inside the suite's own state root and \
                   is unreachable from any other process\n\
                   rejected-route=every declared route is a real remedy for a real write; this \
                   case is not making one, it is proving the channel is load-bearing\n";
    let issued = common::run_with_stdin_at_real_root(
        root,
        &[
            "override",
            "request",
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            "batten.toml",
        ],
        answers,
    );
    assert!(
        issued.status.success(),
        "the request must issue: {}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let admission = String::from_utf8_lossy(&issued.stdout)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned();
    assert!(!admission.is_empty(), "the request must name an address");

    let spent = common::run_at_real_root(
        root,
        &[
            "override",
            "spend",
            "--admission",
            &admission,
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            "batten.toml",
        ],
    );
    assert!(
        spent.status.success(),
        "the admission must spend: {}",
        String::from_utf8_lossy(&spent.stderr)
    );

    let admitted = run(common::batten_at_real_root().current_dir(root), &payload);
    assert_eq!(
        admitted,
        Some(0),
        "a spent admission admits the write — which is why the store must never be the \
         developer's"
    );
}

#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject of `the_hatch_is_load_bearing` is what \
              the CHILD's environment carries, so the fixture has to be a real process \
              and the helper has to name the type `common::batten()` hands it. There is \
              no in-process form of \"the engine ran without the hatch\"."
)]
fn run(command: &mut std::process::Command, payload: &str) -> Option<i32> {
    let mut child = command
        .args(["adjudicate", "--harness", "exit-code"])
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
