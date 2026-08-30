//! `input.tree.staged` and `input.tree.state`, over the compiled binary
//! (CLOUD-1203).
//!
//! **The discriminating case is `the_index_answers_not_the_worktree`**, and the
//! row says why: without it the suite is satisfied by a fact that reads the
//! checkout, which is the exact trap `Fact::Tracked`'s own doc names — *"this is
//! how a module author writes a predicate about the index and gets an answer
//! about the checkout."* So the fixture stages one value, leaves a DIFFERENT
//! value in the working tree, and asserts the module sees the staged one.
//!
//! That matters beyond tidiness. `lock-complete` is the pure "committed bytes
//! only" gate — it judges THE COMMIT, not the developer's working copy — so a
//! successor reading the worktree would answer a different question and pass
//! over a staged-but-unsaved edit. A silent wrong answer, not a missing feature.
//!
//! `tracked_still_means_the_working_tree` is the other half of that pair: the
//! row refuses widening `tracked` to mean the index, because that would change
//! every existing consumer's answer without any of them asking.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// Reads the staged value of a declared path, and reports which one it saw.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
staged = ["pinned.toml"]

[[verdict]]
id = "V-STAGED-IS-INDEX"
gloss = "the probe read the value that was staged"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-INDEX"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-STAGED-IS-WORKTREE"
gloss = "the probe read the value left in the working tree"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-WORKTREE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-TRACKED-SEES-THE-PATH"
gloss = "the working-tree walk still yields the path, unchanged by the staged read"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-TRACKED"
kind = "document"
target = "probe.rego"
"#;

/// The same probe declaring NO staged path — the acquires-nothing arm.
const UNDECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["batten.toml"]

[[verdict]]
id = "V-STAGED-IS-INDEX"
gloss = "the probe read the value that was staged"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-INDEX"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-STAGED-IS-WORKTREE"
gloss = "the probe read the value left in the working tree"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-WORKTREE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-TRACKED-SEES-THE-PATH"
gloss = "the working-tree walk still yields the path, unchanged by the staged read"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-TRACKED"
kind = "document"
target = "probe.rego"
"#;

/// Two predicates over one key, plus one over `tracked`.
///
/// The pair is what discriminates: a single "did I read something" rule would be
/// green whether the engine handed back the index or the checkout, which is the
/// whole failure this family exists to prevent.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "staged-is-index"

rules contains "staged-is-worktree"

rules contains "tracked-sees-the-path"

violation contains {
	"rule": "staged-is-index",
	"verdict": "V-STAGED-IS-INDEX",
} if {
	input.tree.staged["pinned.toml"].pin == "staged"
}

violation contains {
	"rule": "staged-is-worktree",
	"verdict": "V-STAGED-IS-WORKTREE",
} if {
	input.tree.staged["pinned.toml"].pin == "worktree"
}

violation contains {
	"rule": "tracked-sees-the-path",
	"verdict": "V-TRACKED-SEES-THE-PATH",
} if {
	some path in input.tree.tracked
	path == "pinned.toml"
}

test_a_staged_value_fires_the_index_class if {
	some v in violation with input as {"tree": {"staged": {"pinned.toml": {"pin": "staged"}}, "tracked": []}}
	v.rule == "staged-is-index"
}

test_a_worktree_value_fires_the_other_class if {
	some v in violation with input as {"tree": {"staged": {"pinned.toml": {"pin": "worktree"}}, "tracked": []}}
	v.rule == "staged-is-worktree"
}

test_an_absent_key_fires_neither if {
	count({v | some v in violation; startswith(v.rule, "staged-")}) == 0 with input as {"tree": {"staged": {}, "tracked": []}}
}
"#;

/// A repository whose index and working tree DISAGREE about one path.
///
/// That disagreement is the whole fixture: `pinned.toml` is committed saying
/// `staged`, and then overwritten in the checkout saying `worktree` without
/// being re-staged.
fn fixture(name: &str, config: &str, diverge: bool) -> PathBuf {
    let dir = scratch(&format!("staged-facts-{name}"));
    write(&dir, "batten.toml", config);
    write(&dir, "probe.rego", PROBE);
    write(&dir, "pinned.toml", "pin = \"staged\"\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    if diverge {
        // THE DIVERGENCE, and it is left unstaged on purpose: the index still
        // says `staged` and the checkout now says `worktree`, so the two facts
        // give different answers and the suite can tell which one was read.
        write(&dir, "pinned.toml", "pin = \"worktree\"\n");
    }
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn the_index_answers_not_the_worktree() {
    // THE CASE THE ROW SAYS MATTERS. Stage one value, leave a different one in
    // the working tree, assert the fact returns the STAGED one. Without it the
    // suite is satisfied by a fact that reads the checkout — the exact trap
    // `Fact::Tracked`'s doc names.
    let dir = fixture("index", CONFIG, true);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("staged-is-index"),
        "the fact must return the STAGED bytes\n{answer}{cause}"
    );
    assert!(
        !answer.contains("staged-is-worktree"),
        "reading the working tree here is the defect this family exists to prevent\n{answer}{cause}"
    );
}

#[test]
fn tracked_still_means_the_working_tree() {
    // `tracked` IS NOT WIDENED, asserted rather than assumed. The row refuses it
    // outright, because widening would change every existing consumer's answer
    // without any of them asking — and this suite is the one place both facts
    // are read over the same tree, so it is the place that can tell.
    let dir = fixture("tracked", CONFIG, true);
    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert!(
        answer.contains("tracked-sees-the-path"),
        "the working-tree walk must be unchanged by the staged read\n{answer}"
    );
}

#[test]
fn an_undeclared_path_is_not_staged_read() {
    // THE BOUND. Same repository, same divergence, and the row declares no
    // staged path: the key resolves nothing and both predicates are silent.
    // Without it the family reads whatever the index holds rather than what a
    // row asked for, and `Cost::Read` stops being an honest classification.
    let dir = fixture("undeclared", UNDECLARED, true);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(!answer.contains("staged-is-index"), "{answer}{cause}");
    assert!(!answer.contains("staged-is-worktree"), "{answer}{cause}");
}

#[test]
fn an_unstaged_path_is_could_not_look_never_an_empty_node() {
    // COULD-NOT-LOOK. The declared path is not in the index at all, so the row
    // is skipped rather than run against an empty node — a module handed one
    // would decide over a file that is not there, which is CLOUD-845's dead gate
    // arriving as a clean tree.
    let dir = scratch("staged-facts-unstaged");
    write(&dir, "batten.toml", CONFIG);
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    // `pinned.toml` is never written and never staged.
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an unstaged path must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("staged-is-index"), "{answer}{cause}");
    assert!(!answer.contains("staged-is-worktree"), "{answer}{cause}");
}
