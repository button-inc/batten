//! A module's rule VALUES are not packages (CLOUD-1969), over the compiled
//! binary.
//!
//! The engine reads `deny`, `violation`, `rules` and `preapprove` out of the
//! `data.batten` result. It used to find them by walking every object in that
//! result, so a helper rule whose value is a parsed document — a settings file,
//! a CI config — handed the engine that document's own keys of those names.
//! Measured: a settings file's six-entry `permissions.deny` came back as six
//! unattributed findings from a module that judged the tree clean.
//!
//! **Only this tier can see it.** A module's own `test_` rules read `violation`
//! directly and never pass through the engine's walk, so `policy test` was green
//! over the defect.
//!
//! Three observations:
//!
//! * `a_bound_document_leaks_nothing` — the defect: a helper rule bound to a
//!   document carrying `deny` and `violation` keys raises nothing of its own.
//! * `the_module_s_own_violation_still_raises` — the anti-vacuity mirror, in the
//!   same module over the same document: the real predicate still speaks, so the
//!   case above is not green because the module stopped being read.
//! * `a_sub_package_is_still_reached` — the reason the walk existed: a module in
//!   `package batten.<a>.<b>` is read at any depth.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, init_repo, scratch, stdout, write};

/// A module that binds the whole input document as a helper rule, and raises
/// one real violation when the document says `raise`.
///
/// `document` is the shape that leaked: an object-valued rule. Its value is the
/// fixture's own JSON, which carries `deny`, `violation` and `preapprove` keys
/// of its own — none of them a rule of this package.
const MODULE: &str = r#"package batten.walk.nested

import rego.v1

rules contains "walk probe real"

document := input.tree.documents["settings.json"]

violation contains {
	"rule": "walk probe real",
	"verdict": "walk probe real",
	"subjects": [{"path": "settings.json"}],
} if {
	document.raise == true
}
"#;

const CONFIG: &str = r#"version = 1

[[rule]]
id = "walk probe real"
kind = "policy"
scope = "tree"
documents = ["settings.json"]
module = "walk.rego"
severity = "deny"

[[verdict]]
id = "walk probe real"
gloss = "the module's own predicate"
class = "A fixture class raised only by the module's real violation."

[[verdict.route]]
id = "task run first"
kind = "document"
target = "walk.rego"
"#;

/// The document the helper rule binds. Every key a leaking walk would collect
/// is present, each carrying a token no registry row declares, so a leak shows
/// up as a finding the fixture never wrote.
fn settings(raise: bool) -> String {
    format!(
        r#"{{"raise": {raise}, "permissions": {{"deny": ["leaked deny one", "leaked deny two"]}}, "violation": ["leaked violation"], "preapprove": ["leaked grant"], "rules": ["leaked rule"]}}"#
    )
}

fn fixture(name: &str, raise: bool) -> PathBuf {
    let repo = scratch(&format!("policy-walk-{name}"));
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "walk.rego", MODULE);
    write(&repo, "settings.json", &settings(raise));
    init_repo(&repo);
    git_in(&repo, &["add", "-A"]);
    repo
}

fn check(repo: &Path) -> Output {
    let mut command = batten();
    command.current_dir(repo).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_bound_document_leaks_nothing() {
    // THE DEFECT. The document carries `deny`, `violation`, `preapprove` and
    // `rules` keys, and the module's predicate does not hold. A walk that
    // descends into rule values reports the leaked tokens; this one must report
    // nothing at all.
    let repo = fixture("leak", false);
    let outcome = check(&repo);
    let answer = stdout(&outcome);
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a bound document's own keys must not become findings\n{answer}"
    );
    assert!(!answer.contains("leaked"), "{answer}");
}

#[test]
fn the_module_s_own_violation_still_raises() {
    // THE MIRROR. Same module, same document, predicate true: exactly the real
    // finding, and still none of the leaked tokens beside it.
    let repo = fixture("real", true);
    let outcome = check(&repo);
    let answer = stdout(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{answer}");
    assert!(answer.contains("walk probe real"), "{answer}");
    assert!(!answer.contains("leaked"), "{answer}");
}

#[test]
fn a_sub_package_is_still_reached() {
    // WHY THE WALK EXISTED. The module lives in `package batten.walk.nested`,
    // two levels below the query root; recording packages rather than walking
    // must not lose it. This is the positive case above read for its depth.
    let repo = fixture("nested", true);
    let outcome = check(&repo);
    let answer = stdout(&outcome);
    assert!(
        answer.contains("settings.json"),
        "a nested package's finding must carry its pointer\n{answer}"
    );
}

/// A module may rewrite `timeout` and nothing else (CLOUD-2157): a rewrite that
/// could address `command` would replace the call the gate was asked to judge.
#[test]
fn a_rewrite_outside_the_allowlist_is_refused() {
    assert!(batten::policy::rewritable("timeout"));
    for key in ["command", "run_in_background", "file_path", ""] {
        assert!(!batten::policy::rewritable(key), "{key} is not rewritable");
    }
}
