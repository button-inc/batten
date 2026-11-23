//! A tree-scope policy rule whose module cannot look is an error, never a pass
//! (CLOUD-2789), over the compiled binary.
//!
//! `policy_rule` used to answer a module fault with `RuleSkipped`, which folds
//! to no exit code and prints nothing: a module faulting on every input read as
//! a clean tree, and three of this repository's gates were dead that way for
//! weeks. The pair below is the point: the same module over an input it can
//! read must still pass, or a gate refusing everything would satisfy the fault
//! case alone.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, scratch, write};

/// The module: when the declared document's `s` is `fault` it reaches a call
/// this evaluator cannot make (`base64.decode`, outside its builtin set), and
/// any other `s` decides cleanly. The empty document `load` probes with
/// reaches no call, so it loads — which is the dead-gate shape exactly.
///
/// MEASURED, the shapes that do NOT fault in this evaluator: division by zero,
/// `count` of a number, `to_number` of a word, `object.get` on a number, a
/// complete rule with two values, `json.unmarshal` of a fragment — each is
/// undefined, so the module decides "no denial", which is not could-not-look.
const MODULE: &str = r#"package batten.fault

import rego.v1

deny contains "rule fault probe" if {
	s := input.tree.documents["a.json"].s
	s == "fault"
	base64.decode(s) == "never"
}
"#;

/// A repository registering [`MODULE`] over `a.json` carrying `s`.
fn repo(name: &str, s: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("could-not-look-tree-{name}"));
    write(&dir, "policy/fault.rego", MODULE);
    write(&dir, "a.json", &format!("{{\"s\": \"{s}\"}}\n"));
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "rule fault probe"
gloss = "a fixture verdict the module never reaches"
class = "A fixture class."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/fault.rego"

[[rule]]
id = "fault probe"
kind = "policy"
scope = "tree"
module = "policy/fault.rego"
documents = ["a.json"]
severity = "deny"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Fails by: a module fault folding to a skip (exit 0, nothing said), the
/// CLOUD-2789 dead-gate shape.
#[test]
fn a_faulting_module_is_named_and_the_run_is_non_zero() {
    let dir = repo("faults", "fault");
    for argv in [
        &["check", "--rule", "fault probe"][..],
        &["check"][..],
        &["enforce", "--half", "tree"][..],
    ] {
        let out = run(&dir, argv);
        let stderr = common::stderr(&out);
        assert_eq!(out.status.code(), Some(3), "{argv:?}: {stderr}");
        assert!(
            stderr.contains("errored fault probe") && stderr.contains("could not look"),
            "{argv:?} names the rule and why: {stderr}"
        );
    }
}

/// Fails by: the fault arm catching a module that decided — the guard that
/// rules out a fix refusing every policy row.
#[test]
fn the_same_module_over_a_readable_input_passes() {
    let dir = repo("reads", "fine");
    let out = run(&dir, &["check", "--rule", "fault probe"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
}
