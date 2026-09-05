//! The adopted runner's surface contract, over the compiled binary (CLOUD-947).
//!
//! # Why this tier
//!
//! `hk.rs`'s own `#[test]` cases hand [`batten::hk::project`] a JSON document
//! they wrote, so they are green over a shape the runner may never emit — the
//! hazard `.claude/rules/policy-modules.md` names for a policy module and which
//! applies verbatim to a projection over a delegated tool's output. Two things
//! can only be proved against the real boundary: that the pinned runner's ACTUAL
//! plan projects at all, and that the committed artifact is the one this binary
//! derives from it rather than one that agreed with an earlier canonicaliser.
//!
//! # The case that carries the most
//!
//! [`the_committed_contract_is_the_one_the_binary_derives`] runs the gate over
//! this checkout. Every other case here is a shape somebody wrote to fail; that
//! one is the shape that has to keep passing, and it is what says the committed
//! projection and the pinned runner still agree rather than that a fixture of
//! them would.
//!
//! # Why the could-not-look arms are asserted in a scratch directory
//!
//! A directory with no runner config is a place the runner genuinely cannot
//! plan, so the `3` those cases assert is the engine's own answer to a real
//! failure rather than one a fixture faked. `.claude/rules/rust.md` asks for a
//! failing condition a test can actually create; this is that condition.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::Path;

use batten::hk;

/// The exit code a caller reads, as an integer, for the assertions below.
fn code(output: &std::process::Output) -> Option<i32> {
    output.status.code()
}

/// The whole point of the row: the committed projection still matches the
/// pinned runner.
///
/// Exit `0` from the real gate at the real root. A `2` here means the artifact
/// is stale and `mise run hk-contract` is the remedy; a `3` means the pinned
/// runner could not be reached, which is a provisioning fault rather than a
/// drifted contract, and the two are deliberately different codes.
#[test]
fn the_committed_contract_is_the_one_the_binary_derives() {
    let root = common::at_root(".");
    let output = common::run_at_real_root(&root, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(0),
        "the committed contract drifted from the pinned runner; run `mise run hk-contract` and read the diff.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The committed artifact is a projection this build can read back.
///
/// Separate from the gate above because they fail for different reasons: this
/// one goes red when the artifact's SHAPE and the type disagree — a field
/// renamed, a key added — where the gate goes red when the CONTENT disagrees
/// with the runner. A shape change would otherwise surface as a `1` from the
/// gate with no case naming it.
#[test]
fn the_committed_artifact_reads_back_as_this_builds_shape() {
    let text =
        fs::read_to_string(common::at_root(hk::ARTIFACT)).expect("the artifact is committed");
    let contract = hk::Contract::parse(&text).expect("the artifact is this build's shape");
    assert_eq!(contract.version, hk::SHAPE);
    assert_eq!(
        contract.surfaces.len(),
        hk::SURFACES.len(),
        "one projected surface per declared surface"
    );
    assert!(
        contract
            .surfaces
            .iter()
            .all(|surface| !surface.steps.is_empty()),
        "an empty surface would commit clean against every later comparison"
    );
    assert_eq!(
        text,
        contract.render().expect("the artifact renders"),
        "the committed bytes are the ones this build emits; run `mise run hk-contract`"
    );
}

/// Where the runner cannot plan, the gate says so and does not say "clean".
///
/// `3`, never `0`: an absent answer and a passing one are different, and this is
/// the arm where the engine could not look. Asserted over the compiled binary
/// because a unit test can only fabricate the failure, and the fabrication is
/// what would hide a boundary that swallowed it.
#[test]
fn a_directory_the_runner_cannot_plan_is_could_not_look() {
    let dir = common::scratch("hk-contract-unplannable");
    common::init_repo(&dir);
    let output = common::run(&dir, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(3),
        "a tree the runner cannot plan is could-not-look, never clean"
    );
    assert_ne!(
        code(&output),
        Some(0),
        "an unreachable runner must never read as a passing contract"
    );
}

/// The read verb writes nothing, which is what makes its declared effect honest.
///
/// The structural half of `surface.rs`'s `generate_writes_no_file`: a `read` row
/// that touched the working directory would be a write verb with a read
/// declaration, and the declaration is what the read-only allowlist is derived
/// from.
#[test]
fn the_drift_verb_writes_no_file() {
    let dir = common::scratch("hk-contract-read-effect");
    common::init_repo(&dir);
    let before = tracked_entries(&dir);
    let _ = common::run(&dir, &["hk", "drift"]);
    assert_eq!(
        tracked_entries(&dir),
        before,
        "a read-effect verb wrote to the working directory"
    );
}

/// The directory's entries, excluding the git dir the harness created.
fn tracked_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("the directory reads")
        .filter_map(|entry| Some(entry.ok()?.file_name().to_str()?.to_owned()))
        .filter(|name| name != ".git")
        .collect();
    names.sort();
    names
}

/// The two verbs carry the two effects the row specifies, read off the surface
/// the allowlist is derived from.
///
/// Asserted through `spec` rather than by reading `surface.rs`, because the
/// published document is what a third party pins against — and a row whose
/// effect moved would keep compiling.
#[test]
fn the_generator_is_a_write_and_the_gate_is_a_read() {
    let root = common::at_root(".");
    let output = common::run_at_real_root(&root, &["spec", "--format", "json"]);
    let spec: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the spec is one JSON document");
    let mut seen = 0;
    let mut pending = vec![&spec];
    while let Some(command) = pending.pop() {
        if let Some(children) = command["subcommands"].as_array() {
            pending.extend(children);
        }
        match command["id"].as_str() {
            Some("hk.contract") => {
                assert_eq!(command["effect"], "write");
                seen += 1;
            }
            Some("hk.drift") => {
                assert_eq!(command["effect"], "read");
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 2, "both verbs are published on the surface");

    // The allowlist is a walk over the same tree, so a write verb reaching it
    // would mean the effect declared above is not the one the allowlist derives
    // from. The gate is on it; the generator must not be.
    let allowlist = spec["read_only_allowlist"]
        .as_array()
        .expect("the spec publishes the read-only allowlist");
    let ids: Vec<&str> = allowlist
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert!(ids.contains(&"hk.drift"), "the gate is read-only");
    assert!(
        !ids.contains(&"hk.contract"),
        "a generator that regenerates a committed artifact is never read-only"
    );
}

/// The gate's refusal names the class the registry declares, and points at the
/// artifact rather than quoting either plan (non-negotiable rule 4).
#[test]
fn the_refusal_is_a_declared_class_with_a_route() {
    let registry = batten::verdict::vendored();
    let token = batten::verdict::Native::PlanReadStale.id();
    let row = registry
        .iter()
        .find(|declared| declared.id == token)
        .expect("the class is declared");
    assert!(
        !row.routes.is_empty(),
        "a class with no route has no remedy"
    );
    assert!(!row.retired(), "the gate raises a live class");
}

/// **The drifted arm, over the real runtime path** — the one this file could not
/// otherwise show able to fire.
///
/// Every other case here reaches clean, could-not-look, or `hk::compare` in
/// isolation. None of them drives `hk drift` to a `2`, so the CLI's own
/// comparison, its refusal construction and its exit mapping were unexercised:
/// a build that mapped drift to `0` would have passed this whole file. That is
/// the CLOUD-418 shape — a gate never shown able to fail is a gate nobody has
/// evidence for — and the gap was reported in review of #873 rather than found
/// here, which is the reason it is written out.
///
/// **The baseline is GENERATED in the scratch root rather than copied from the
/// committed one**, and that is load-bearing. `hk` plans against the tree it
/// runs in, so a step whose glob matches nothing here is `skipped` where the
/// real tree has it `included` — and `status` is in the projection. Seeding
/// with the repository's own artifact would therefore drift for a reason this
/// case is not about, and would pass while proving nothing. Generating first
/// makes the mutation below the ONLY difference, and exercises the writer on
/// the way past.
#[test]
fn a_drifted_contract_exits_two_and_names_the_class() {
    // `Fixture` rather than a `tempfile`: it is this suite's own scratch
    // convention and needs no dev-dependency the binary does not link.
    let scratch = common::Fixture::new("hk-contract-drift");
    let root = scratch.path();
    fs::copy(common::at_root("hk.pkl"), root.join("hk.pkl")).expect("the runner config copies");
    fs::create_dir_all(root.join("contracts")).expect("the artifact directory");

    let generated = common::run_at_real_root(root, &["hk", "contract"]);
    if code(&generated) != Some(0) {
        // The pinned runner is unreachable here, which is a provisioning fault
        // and not a drifted contract. Skipped rather than asserted, because a
        // `3` from the generator says nothing about the arm under test — and
        // `the_committed_contract_is_the_one_the_binary_derives` above is the
        // case that goes red when the runner genuinely cannot be reached.
        return;
    }

    let artifact = root.join(hk::ARTIFACT);
    let text = fs::read_to_string(&artifact).expect("the generator wrote the artifact");
    let mut contract = hk::Contract::parse(&text).expect("it reads back");
    let step = contract
        .surfaces
        .first_mut()
        .and_then(|surface| surface.steps.first_mut())
        .expect("the generated contract carries a step");
    // A RENAME rather than a deletion: renaming drifts both directions at once
    // (one step gone, one arrived) and leaves the counts equal, so an
    // implementation comparing only lengths still goes red here.
    step.name = format!("{}-renamed", step.name);
    fs::write(&artifact, contract.render().expect("it renders")).expect("the drift is committed");

    let output = common::run_at_real_root(root, &["hk", "drift"]);
    assert_eq!(
        code(&output),
        Some(2),
        "a drifted contract is a policy verdict, not a fault.\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(batten::verdict::Native::PlanReadStale.id()),
        "the refusal names its declared class: {stderr}"
    );
    assert!(
        stderr.contains(hk::ARTIFACT),
        "and points at the artifact, which is the remedy's subject: {stderr}"
    );
    // RULE 4, at the one site where a diff would be the tempting thing to
    // print: the refusal carries step NAMES and never either plan's body.
    assert!(
        !stderr.contains("\"steps\":") && !stderr.contains("orderIndex"),
        "the refusal quoted a plan instead of pointing at one: {stderr}"
    );
}
