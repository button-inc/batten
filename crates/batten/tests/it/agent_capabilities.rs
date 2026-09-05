//! `show agent` over the compiled binary (CLOUD-1180).
//!
//! The in-module tests in `agent.rs` pin the projection. These are the tier that
//! proves the BINARY builds and emits it — the same split
//! `.claude/rules/policy-modules.md` states for policy modules, and for the same
//! reason: a unit test over a value the engine may be unable to produce passes
//! over a verb nobody can invoke.
//!
//! CLOUD-1180's §7 names four observed cases and each has one below, plus the
//! negative half the row calls "the point".

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use batten::surface::SURFACE;
use common::{Fixture, batten};

/// A fixture declaring one gate, so the gate list is non-empty and the
/// pointer-only assertion has something real to be pointer-only ABOUT.
fn configured(name: &str) -> Fixture {
    Fixture::new(name).config(
        r#"
version = 1

[[rule]]
id = "no-fixture-secrets"
kind = "forbid"
glob = "**/*.txt"
pattern = "hunter2"
severity = "deny"
scope = "tree"
"#,
    )
}

#[test]
fn the_verb_reports_this_repositorys_gates_as_pointers() {
    let fixture = configured("agent-configured");
    let output = batten()
        .args(["show", "agent", "-J"])
        .current_dir(fixture.path())
        .output()
        .expect("run show agent");
    assert!(output.status.success(), "show agent exits 0");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON document");

    assert_eq!(document["configured"], serde_json::json!(true));
    let gates = document["gates"].as_array().expect("gates is an array");
    assert!(
        gates.iter().any(|gate| gate["id"] == "no-fixture-secrets"),
        "the declared gate is reported"
    );

    // RULE 4, and this is the assertion the row calls load-bearing. The gate's
    // own pattern is a literal in the fixture config; it must not appear
    // anywhere in the emitted document, and neither must its glob.
    let whole = String::from_utf8_lossy(&output.stdout);
    assert!(
        !whole.contains("hunter2"),
        "the gate's pattern reached the data channel"
    );
    assert!(
        !whole.contains("**/*.txt"),
        "the gate's glob reached the data channel"
    );
}

#[test]
fn an_unconfigured_repository_answers_rather_than_failing() {
    // CLOUD-1180 §7(d): a deterministic unavailable state, never an error.
    let fixture = Fixture::new("agent-unconfigured");
    let output = batten()
        .args(["show", "agent", "-J"])
        .current_dir(fixture.path())
        .output()
        .expect("run show agent");
    assert!(
        output.status.success(),
        "an unconfigured repository is a state, not a usage error; got {:?}",
        output.status.code()
    );
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON document even here");
    assert_eq!(document["configured"], serde_json::json!(false));

    // AND THE GATE LIST IS NOT EMPTY, which is the whole point of this case.
    // `resolve` succeeds with the built-in defaults where no authority exists,
    // and those defaults really do gate the tree. Reporting `gates: []` here
    // would tell an agent it may do anything — the one direction this verb must
    // never be wrong in. This assertion is what caught a draft that said exactly
    // that, in the summary line an agent reads first.
    assert!(
        !document["gates"].as_array().unwrap().is_empty(),
        "an unconfigured repository is still gated by the built-in defaults; \
         an empty list here reads as `nothing is enforced`"
    );

    // The allowlist is a property of the BINARY, so it is still populated. An
    // implementation returning a wholly empty document would satisfy the
    // `configured` assertion above and be wrong.
    assert!(
        !document["read_only"].as_array().unwrap().is_empty(),
        "the read-only allowlist does not depend on repository config"
    );
}

#[test]
fn the_document_is_byte_stable_across_two_runs() {
    // CLOUD-1180 §7(a), and §6's general requirement.
    let fixture = configured("agent-stable");
    let run = || {
        batten()
            .args(["show", "agent", "-J"])
            .current_dir(fixture.path())
            .output()
            .expect("run show agent")
            .stdout
    };
    assert_eq!(run(), run(), "show agent -J is not byte-stable");
}

/// Every file under `dir`, with its bytes, sorted by path.
///
/// A local helper rather than a shared one: this is the only caller, and a
/// whole-tree snapshot is the wrong instrument for the targeted read-backs the
/// other suites do (`config_schema` reads back the one artifact it doctored).
fn snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).expect("read the fixture") {
            let path = entry.expect("read the entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let name = path
                    .strip_prefix(dir)
                    .expect("under the fixture")
                    .to_string_lossy()
                    .into_owned();
                found.push((name, std::fs::read(&path).expect("read the file")));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn the_verb_writes_no_file_and_leaves_the_tree_alone() {
    // CLOUD-1180 §7(b): the read leaf is shown unable to write, by OBSERVING the
    // tree rather than by inspecting the code. `read` is the claim the derived
    // agent allowlist rests on, so it is asserted rather than trusted — the
    // hazard CLOUD-244 caught on `hook`.
    let fixture = configured("agent-readonly");
    let before = snapshot(fixture.path());
    assert!(
        !before.is_empty(),
        "the fixture is empty, so an unchanged tree would prove nothing"
    );
    let output = batten()
        .args(["show", "agent"])
        .current_dir(fixture.path())
        .output()
        .expect("run show agent");
    assert!(output.status.success());
    assert_eq!(
        before,
        snapshot(fixture.path()),
        "show agent changed the tree it read"
    );
}

#[test]
fn the_leaf_is_on_the_derived_read_only_allowlist() {
    // CLOUD-1180 §7(c). The row demands the mirror as well as the claim: it is
    // not enough that a writer is absent, since an EMPTY allowlist satisfies
    // that too. So `show agent` must be present.
    let fixture = configured("agent-allowlist");
    let output = batten()
        .args(["spec", "--format", "json"])
        .current_dir(fixture.path())
        .output()
        .expect("run spec");
    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("one JSON document");
    let allowlist = document["read_only_allowlist"]
        .as_array()
        .expect("the allowlist is emitted");
    assert!(
        allowlist.iter().any(|entry| entry["path"] == "show agent"),
        "show agent is missing from the derived read-only allowlist"
    );
    assert!(
        allowlist.iter().any(|entry| entry["id"] == "show.agent"),
        "the allowlist entry carries the stable id, not only the spelling"
    );
}

#[test]
fn the_surface_declares_the_subtree_the_row_asked_for() {
    // The directive's own requirement: every `agent` path is in `SURFACE` with
    // an explicit effect. Read off the table rather than off the help text, so
    // this fails when the declaration moves rather than when the prose does.
    let show = SURFACE
        .iter()
        .find(|decl| decl.path == "show")
        .expect("the `show` noun is declared");
    let agent = SURFACE
        .iter()
        .find(|decl| decl.path == "show agent")
        .expect("the `show agent` leaf is declared");
    assert_eq!(show.id, "show");
    assert_eq!(agent.id, "show.agent");
    assert!(
        agent.data_channel,
        "the leaf answers through -J, so it declares the data channel"
    );
}
