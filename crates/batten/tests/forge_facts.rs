//! `input.tree.forge`, over the compiled binary (CLOUD-1154).
//!
//! **The anti-forgery case is what this family lives or dies on.** A verdict
//! taken against a different commit is not evidence about this one, so
//! `a_record_keyed_to_another_sha_does_not_answer` is the case the row's
//! acceptance names — without it a gate could inherit a green reading from a
//! commit nobody asked about, reporting a judgement that was never made.
//!
//! The engine reads a record something else wrote and **opens no socket**;
//! `evaluator-io-check` is the gate on that and this suite does not duplicate it.
//! What it does assert is that the read reaches a module at all, which a
//! `with input as` case cannot (CLOUD-845, CLOUD-857).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// The sha the row declares, and the one a record must be keyed to.
const DECLARED_SHA: &str = "1111111111111111111111111111111111111111";
/// A different commit entirely — the forgery the keying refuses.
const OTHER_SHA: &str = "2222222222222222222222222222222222222222";

fn config(sha: &str) -> String {
    format!(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
forge = ["{sha}"]

[[verdict]]
id = "V-FORGE-GREEN"
gloss = "the declared sha's record says the required check passed"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-GREEN"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-FORGE-RED"
gloss = "the declared sha's record says the required check failed"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-RED"
kind = "document"
target = "probe.rego"
"#
    )
}

/// Two predicates over one key, and the pair is what discriminates.
///
/// A single "did I read a verdict" rule would be green whether the engine handed
/// back this sha's record or another's, which is the forgery the keying exists to
/// refuse.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-green"

rules contains "probe-red"

violation contains {
	"rule": "probe-green",
	"verdict": "V-FORGE-GREEN",
} if {
	is_object(input.tree.forge)
	some checks in input.tree.forge
	checks.final == "success"
}

violation contains {
	"rule": "probe-red",
	"verdict": "V-FORGE-RED",
} if {
	is_object(input.tree.forge)
	some checks in input.tree.forge
	checks.final == "failure"
}

test_a_green_record_fires if {
	some v in violation with input as {"tree": {"forge": {"abc": {"final": "success"}}}}
	v.rule == "probe-green"
}

test_a_red_record_fires_the_other_class if {
	some v in violation with input as {"tree": {"forge": {"abc": {"final": "failure"}}}}
	v.rule == "probe-red"
}

test_no_record_fires_neither if {
	count(violation) == 0 with input as {"tree": {"forge": {}}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"forge": null}}
}
"#;

/// A repository whose row declares `DECLARED_SHA`, plus a record written under
/// `record_sha` — which the cases vary to make the keying observable.
fn fixture(name: &str, record_sha: Option<&str>, conclusion: &str) -> PathBuf {
    let dir = scratch(&format!("forge-facts-{name}"));
    write(&dir, "batten.toml", &config(DECLARED_SHA));
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    if let Some(sha) = record_sha {
        // The producer's half, written here rather than fetched: the engine
        // reads a record something else wrote, which is the entire shape of the
        // family and why it needs no socket.
        let store = dir.join(".git").join("batten-forge");
        std::fs::create_dir_all(&store).expect("record store");
        std::fs::write(store.join(sha), format!("final {conclusion}\n")).expect("write record");
    }
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_declared_sha_reads_its_own_record() {
    // THE POSITIVE. Before this family a tree-scoped module asking about a
    // check-run read undefined, Rego took that as *does not hold*, and the gate
    // was byte-identical to a clean tree on the decision surface.
    let dir = fixture("green", Some(DECLARED_SHA), "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-green"),
        "the declared sha's record must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_projection_carries_the_recorded_conclusion() {
    // THE POSITIVE CONTROL (CLOUD-418). Without it the case above passes over a
    // projection that emitted `success` unconditionally — and telling `success`
    // from `failure` is the entire question a landing gate asks.
    let dir = fixture("red", Some(DECLARED_SHA), "failure");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-red"),
        "the record's own conclusion must decide\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-green"),
        "the projection must carry the recorded value, not a constant\n{answer}{cause}"
    );
}

#[test]
fn a_record_keyed_to_another_sha_does_not_answer() {
    // THE ANTI-FORGERY CASE, and the one the row's acceptance names. The record
    // exists, is readable, and says `success` — it is simply keyed to a different
    // commit. A gate that answered from it would inherit a green verdict from a
    // commit nobody asked about, which is a judgement that was never made
    // reported as one that was.
    let dir = fixture("other-sha", Some(OTHER_SHA), "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a record keyed to another sha must not answer\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-green"), "{answer}{cause}");
    assert!(!answer.contains("probe-red"), "{answer}{cause}");
}

#[test]
fn no_record_at_all_is_could_not_look() {
    // COULD-NOT-LOOK, told apart from a clean verdict by the only means that
    // discriminates: the control above fires `probe-red` on a record that says
    // `failure`, and this fires nothing, because nothing was read.
    //
    // Collapsing them would report green on a commit nothing ever judged — the
    // dead gate, on the surface that decides whether work lands.
    let dir = fixture("no-record", None, "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an absent record must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-green"), "{answer}{cause}");
    assert!(!answer.contains("probe-red"), "{answer}{cause}");
}
