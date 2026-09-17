//! `verify` over a tree whose toolchain was never provisioned (CLOUD-1683).
//!
//! # The defect, measured rather than reasoned
//!
//! Three times in one container, `mise install` wrote `mise ERROR` as its last
//! line and exited **0** — twice on a credential failure the fetch could not
//! recover from. `session:install`'s `|| { …; exit 1; }` arm cannot fire on a
//! zero, so provisioning reported success over a tree with no toolchain. With
//! the toolchain absent, `mise run verify` ALSO returned 0 and did not run, so a
//! branch carrying no claim receipt at all was reported green and the gate that
//! would have refused it never executed.
//!
//! That is non-negotiable rule 5 defeated at the one place it cannot be
//! observed: a green that cannot be falsified.
//!
//! # What this suite proves, and what it does NOT
//!
//! The row's §7 asks for one case — "a tree with the toolchain deliberately
//! unprovisioned must make `verify` exit non-zero". What ships proves that as a
//! **composition of two halves**, and saying so here is the point rather than a
//! hedge:
//!
//! 1. the PREDICATE exits non-zero on a deliberately unprovisioned tree, driven
//!    over the compiled binary against a probe reading the case supplies; and
//! 2. `verify` ROUTES through that predicate, in a guard that stops before any
//!    receipt is written — read off the committed manifest as text.
//!
//! What no case here runs is an end-to-end `mise run verify` on an unprovisioned
//! container. That pulls the reclaim, the fetch and the whole gate set, and is
//! environment-dependent by construction, so it does not belong in this lane.
//! **The gap that leaves**: a change to the tool runner's own task resolution, or
//! to `verify`'s shell semantics, could break the composition while both halves
//! stay green. The row's acceptance is discharged by an OBSERVED run recorded on
//! it, not by this suite — do not read these cases as proving more than the two
//! propositions above.
//!
//! # Why the failing condition is supplied rather than produced
//!
//! `rules/rust.md`: where the environment cannot produce the failing condition,
//! extract the decision and test it directly. A genuinely unprovisioned container
//! cannot be created inside a test that needs a toolchain to run at all — so the
//! probe reading is handed in, which is possible precisely BECAUSE the verb
//! decides over stdin instead of fetching. The caller-fetches-gate-decides split
//! buys the read-only allowlist row and the hermetic test with one decision. The
//! pure halves — which tools the manifest declares, which the probe reports, and
//! the difference — are unit-tested beside the code in `crates/batten/src/doctor.rs`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use crate::common;

/// A manifest declaring two tools, in the three spellings the table really uses:
/// a plain string pin, an inline table, and a backend-prefixed quoted key.
const MANIFEST: &str = r#"[tools]
rust = { version = "1.98.0", components = "rustfmt,clippy" }
hk = "1.56.1"
"aqua:cli/cli" = "2.98.0"

[env]
UNRELATED = "1"
"#;

/// A probe reporting every tool the manifest above declares as installed.
const ALL_INSTALLED: &str = r#"{
  "rust": [{"version": "1.98.0", "installed": true}],
  "hk": [{"version": "1.56.1", "installed": true}],
  "aqua:cli/cli": [{"version": "2.98.0", "installed": true}]
}"#;

/// The same probe with one tool requested and never fetched — the state a failed
/// install leaves, and the one nothing in this tree could previously see.
const ONE_MISSING: &str = r#"{
  "rust": [{"version": "1.98.0", "installed": true}],
  "hk": [{"version": "1.56.1", "installed": false}],
  "aqua:cli/cli": [{"version": "2.98.0", "installed": true}]
}"#;

/// A scratch directory carrying `manifest`.
///
/// **No git repository, and that is a property of the verb rather than a
/// shortcut.** `doctor toolchain` opens the path it was handed and parses the
/// document on its stdin; it resolves no repository root, reads no committed
/// authority and spawns nothing, so a fixture forking one would be asserting
/// about machinery this verb does not touch. It also keeps these cases off
/// `fixture-forks`, which is right to refuse a hand-rolled `git init` — the gate
/// named this file twice while the fork was here, and the fork was the defect.
fn bench(name: &str, manifest: &str) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "mise.toml", manifest);
    dir
}

/// Ask the compiled binary, handing it `probe` on stdin the way the task does.
fn toolchain(dir: &Path, manifest: &str, probe: &str) -> (i32, String) {
    use std::io::Write as _;

    let mut child = common::batten()
        .args(["doctor", "toolchain", manifest])
        .current_dir(dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run batten doctor toolchain");
    child
        .stdin
        .take()
        .expect("the probe channel is open")
        .write_all(probe.as_bytes())
        .expect("hand the probe over");
    let output = child.wait_with_output().expect("the verb exited");
    (
        output.status.code().expect("the verb exited"),
        common::stdout(&output),
    )
}

// ─── The engine's half: what the predicate answers ──────────────────────────

/// CLOUD-1683. THE DISCRIMINATING CASE, and the row's §7 is explicit that it has
/// to be the real one: a test asserting only that a provisioned tree passes
/// cannot tell this defect from its absence, which is precisely the sensor that
/// was missing.
#[test]
fn a_declared_tool_that_is_not_installed_makes_the_toolchain_check_exit_non_zero() {
    let dir = bench("toolchain-missing", MANIFEST);
    let (code, said) = toolchain(&dir, "mise.toml", ONE_MISSING);
    assert_ne!(
        code, 0,
        "an unprovisioned tree must not report success: {said}"
    );
    assert!(
        said.contains("toolchain-unprovisioned"),
        "the refusal names its reason: {said}"
    );
}

/// CLOUD-1683. The anti-vacuity partner. Without it the case above passes over a
/// check that refuses everything, which would be a gate that decides nothing.
#[test]
fn a_tree_whose_every_declared_tool_resolves_is_silent() {
    let dir = bench("toolchain-provisioned", MANIFEST);
    let (code, said) = toolchain(&dir, "mise.toml", ALL_INSTALLED);
    assert_eq!(code, 0, "a provisioned tree passes: {said}");
    assert!(said.contains("toolchain ok"), "and says so: {said}");
}

/// CLOUD-1683, and CLOUD-1317's rule: a diagnosis nobody can act on is a sensor,
/// not a check. A reader who learns only that something is missing has to
/// re-derive which.
#[test]
fn the_refusal_names_which_declared_tool_is_missing_and_not_merely_that_one_is() {
    let dir = bench("toolchain-names", MANIFEST);
    let (_, said) = toolchain(&dir, "mise.toml", ONE_MISSING);
    assert!(said.contains("hk"), "the missing tool is named: {said}");
    assert!(
        !said.contains("aqua:cli/cli"),
        "and an installed one is not: {said}"
    );
}

/// CLOUD-1683. FAIL CLOSED, and this is the arm that inverts every other
/// could-not-look in `doctor`. Elsewhere an unreadable answer is not evidence of
/// a defect; here the probe being unrunnable is produced BY the state being
/// checked for, so reading it as a pass would restore the property the row exists
/// to remove — the broken path and the working path answering identically.
#[test]
fn a_probe_that_answered_nothing_is_unprovisioned_rather_than_a_pass() {
    let dir = bench("toolchain-no-runner", MANIFEST);
    // What the task's pipe delivers when the runner could not run at all: the
    // probe writes nothing and its exit status is lost to the pipe. That is the
    // state being checked for, so it must not read as health.
    let (code, said) = toolchain(&dir, "mise.toml", "");
    assert_ne!(
        code, 0,
        "a container with no runner is not provisioned: {said}"
    );
    assert!(
        said.contains("toolchain-unreadable"),
        "and says which reading it took: {said}"
    );
}

/// CLOUD-1683. A manifest that cannot be read is the same reading, reached by a
/// different route — and it must not be confused with a manifest declaring
/// nothing, which is a legitimate pass.
#[test]
fn a_manifest_that_cannot_be_read_is_unprovisioned_rather_than_a_pass() {
    let dir = bench("toolchain-no-manifest", MANIFEST);
    let (code, said) = toolchain(&dir, "absent.toml", ALL_INSTALLED);
    assert_ne!(code, 0, "an unreadable manifest is not a pass: {said}");
    assert!(
        said.contains("toolchain-unreadable"),
        "and says which reading it took: {said}"
    );
}

/// CLOUD-1683. `doctor` never mints a policy verdict — a mediating harness reads
/// `2` as a deny, and "this checkout was never provisioned" is not "policy says
/// no". The sub-verb inherits the parent's promise rather than re-deciding it.
#[test]
fn an_unprovisioned_toolchain_is_never_reported_as_a_policy_verdict() {
    let dir = bench("toolchain-code", MANIFEST);
    let (code, said) = toolchain(&dir, "mise.toml", ONE_MISSING);
    assert_eq!(code, 1, "usage, never the policy verdict 2: {said}");
}

/// CLOUD-1683. The three key spellings the real table uses are read identically,
/// because the difference between them is entirely on the right-hand side. A
/// parse that handled only the plain-string form would silently ignore most of
/// this repository's own tools.
#[test]
fn a_backend_prefixed_and_an_inline_table_key_are_both_read() {
    let probe = r#"{"hk": [{"version": "1.56.1", "installed": true}]}"#;
    let dir = bench("toolchain-key-shapes", MANIFEST);
    let (code, said) = toolchain(&dir, "mise.toml", probe);
    assert_ne!(code, 0, "two of the three are missing: {said}");
    assert!(
        said.contains("rust"),
        "the inline-table key is read: {said}"
    );
    assert!(
        said.contains("aqua:cli/cli"),
        "the backend-prefixed key is read: {said}"
    );
}

/// CLOUD-1683. THE REFUSING ARM'S `-J` DOCUMENT, pinned because it was broken
/// and the healthy arm hid it. `Toolchain` is internally tagged, and an internal
/// tag cannot be written into a sequence — so the first draft, whose refusing
/// variant was a newtype holding a `Vec`, serialized fine when everything was
/// installed and failed at exactly the moment it had something to report. A
/// case that only asked the clean arm for JSON would have passed over it.
#[test]
fn the_refusing_arm_emits_a_json_document_and_not_an_internal_failure() {
    let dir = bench("toolchain-json", MANIFEST);
    let (code, said) = {
        use std::io::Write as _;
        let mut child = common::batten()
            .args(["doctor", "toolchain", "mise.toml", "-J"])
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("run batten doctor toolchain -J");
        child
            .stdin
            .take()
            .expect("the probe channel is open")
            .write_all(ONE_MISSING.as_bytes())
            .expect("hand the probe over");
        let output = child.wait_with_output().expect("the verb exited");
        (
            output.status.code().expect("the verb exited"),
            common::stdout(&output),
        )
    };
    assert_eq!(code, 1, "still the usage answer: {said}");
    let parsed: serde_json::Value = serde_json::from_str(&said)
        .unwrap_or_else(|error| panic!("`-J` is parseable: {error}: {said}"));
    assert_eq!(parsed["state"], "unprovisioned", "the tag survives: {said}");
    assert_eq!(
        parsed["missing"][0], "hk",
        "and so does the subject: {said}"
    );
}

/// CLOUD-1683. Output is a pointer (rule 4): the declared keys are identifiers
/// out of the consumer's own manifest, and an install path is per-machine content
/// that would defeat §6 byte-stability besides.
#[test]
fn the_refusal_carries_no_install_path() {
    let probe = r#"{
      "hk": [{"version": "1.56.1", "installed": false,
              "install_path": "/root/.local/share/mise/installs/hk/1.56.1"}]
    }"#;
    let dir = bench("toolchain-pointer", MANIFEST);
    let (_, said) = toolchain(&dir, "mise.toml", probe);
    assert!(
        !said.contains("/root/.local"),
        "no install path reaches the report: {said}"
    );
}

// ─── The declaration's half: what the committed manifest actually says ──────

/// The body of one task in the committed manifest.
///
/// Text rather than a TOML parse, and only the executable surface: the committed
/// manifest does not round-trip through the `toml` crate in scope, and a task's
/// prose discusses tasks it deliberately does not run.
fn task_body(name: &str) -> String {
    let manifest = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("the task manifest is readable");
    // BOTH HEADER SPELLINGS, AND BOTH ANCHORED TO THEIR OWN LINE — which is
    // `session_provisioning.rs`'s shape, arrived at here the hard way.
    //
    // The manifest writes `[tasks.verify]` bare and `[tasks."session:install"]`
    // quoted, so a reader handling one spelling panics on the other. And a
    // reader matching the header as a bare SUBSTRING finds the manifest's own
    // PROSE first: `[tasks.verify]` appears in two comments (mise.toml:1064 and
    // :1107) hundreds of lines above the real table at :3909, so the extraction
    // silently returned a neighbouring task's body instead.
    //
    // Both were caught by `the_extracted_verify_body_is_the_task_and_not_the_whole_file`,
    // which is the whole reason that case exists: every other assertion in this
    // tier is a `contains` over this string, and all of them would have passed
    // just as well over the wrong region.
    [
        format!("\n[tasks.\"{name}\"]\n"),
        format!("\n[tasks.{name}]\n"),
    ]
    .iter()
    .find_map(|header| manifest.split(header.as_str()).nth(1))
    .unwrap_or_else(|| panic!("{name} is a declared task"))
    .split("\n[tasks")
    .next()
    .expect("the task body ends at the next table")
    .to_owned()
}

/// CLOUD-1683. THE ANTI-VACUITY CASE for this whole tier, and the one the
/// declared mutation must redden: every assertion below is a `contains` over an
/// extracted body, so an extraction that silently went empty would pass them all.
#[test]
fn the_extracted_verify_body_is_the_task_and_not_the_whole_file() {
    let body = task_body("verify");
    assert!(!body.is_empty(), "the body was found");
    assert!(
        body.contains("verify:gated"),
        "and it is the mapper, not a neighbouring table"
    );
    assert!(
        !body.contains("[tasks.\"verify:gated\"]"),
        "and it stops at the next table rather than running on"
    );
}

/// CLOUD-1683. The load-bearing ordering. An unprovisioned tree has to stop
/// BEFORE the receipt question, because that question is asked through a compile
/// entry point: on a tree with no toolchain it fails for the wrong reason and is
/// reported as "no VALID claim receipt", which is the misattribution one layer up
/// from the one this row closes.
#[test]
fn the_verify_mapper_refuses_an_unprovisioned_toolchain_before_it_reads_any_receipt() {
    let body = task_body("verify");
    let guard = body
        .find("mise run toolchain-check")
        .expect("verify asks the toolchain question");
    let receipt = body
        .find("receipt status claim")
        .expect("verify asks the receipt question");
    let gated = body
        .find("mise run verify:gated")
        .expect("verify runs the gate set");
    assert!(guard < receipt, "the toolchain precedes the receipt");
    assert!(guard < gated, "and precedes the gate set that writes one");
}

/// CLOUD-1683. Exit 1, never 2. `land` reads 2 as "main moved, lap", and nothing
/// about an unprovisioned container improves by rebasing — so a second way to
/// mint a 2 here is `land` lapping to its backstop over a real refusal.
#[test]
fn the_toolchain_precondition_is_a_stop_and_not_a_rebase_lap() {
    let body = task_body("verify");
    let guard = body
        .find("mise run toolchain-check")
        .expect("verify asks the toolchain question");
    let arm = &body[guard..];
    let fi = arm.find("\nfi").expect("the guard is a block");
    assert!(
        arm[..fi].contains("exit 1"),
        "the toolchain guard stops rather than lapping"
    );
}

/// CLOUD-1683. The constraint that is invisible from this file and unfixable if
/// broken: `tests/verify.bats` stubs the task runner and nothing else, answering
/// 0 for any task it was not told about. A direct `batten doctor` or `cargo run`
/// here has no stub, would escape to the real PATH inside that sandbox, and would
/// redden a suite `shell edit refused` forbids editing — retire it whole or leave
/// it alone, and there is no third shape. Stated as an assertion so a later
/// simplification cannot quietly take the unfixable route.
#[test]
fn the_toolchain_precondition_is_invoked_through_the_task_runner() {
    let body = task_body("verify");
    let guard = body
        .find("if ! mise run toolchain-check")
        .expect("the guard goes through the task runner");
    let arm = &body[guard..];
    let fi = arm.find("\nfi").expect("the guard is a block");
    assert!(
        !arm[..fi].contains("batten doctor"),
        "the mapper does not reach the verb directly"
    );
}

/// CLOUD-1683. The install half. The wrapper is what turns the lying zero into a
/// non-zero; the existing guard is KEPT rather than replaced, because it is still
/// the right answer for a genuine non-zero and it is now reachable.
#[test]
fn the_install_step_cannot_report_success_over_a_sub_invocation_that_failed() {
    let body = task_body("session:install");
    assert!(body.contains("exit 1"), "the non-zero arm is kept");
    assert!(
        body.contains("mise run toolchain-check"),
        "and the zero-exit failure this row exists for is caught after it"
    );
}

/// CLOUD-1683. The manifest is an operand rather than a constant in the engine,
/// which is what keeps the consumer artifact's name out of `crates/batten/src`.
/// A default would put it back.
#[test]
fn the_task_supplies_the_manifest_path_rather_than_the_engine_defaulting_it() {
    let body = task_body("toolchain-check");
    assert!(
        body.contains("batten doctor toolchain mise.toml"),
        "the consumer's own fact travels in the consumer's own task body"
    );
}
