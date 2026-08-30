//! `input.tree["git-history"]`, over the compiled binary (CLOUD-1200).
//!
//! **The shallow case is not hypothetical, and this repository is the proof.**
//! CLOUD-1200 says so — `linear-check` already deepens a shallow clone before it
//! can answer — and measured while implementing the family, `batten`'s own
//! working copy carries `.git/shallow`. So the could-not-look arm is the one a
//! consumer meets first, and `a_shallow_clone_is_could_not_look` is here because
//! a truncated walk reported as a result is a gate deciding over history it
//! could not see.
//!
//! The other three are CLOUD-418's: a declared tag glob resolves its matching
//! set; a declared per-path delete filter resolves its own; and an UNDECLARED
//! pattern resolves nothing, which is the anti-scanner case — without it the
//! family is a git shell that reads whatever history is there.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch_outside_tree, stderr, stdout, write};

/// Declares one tag glob and one per-path delete filter.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[rule.history]]
id = "shipped"
tags = "v*"

[[rule.history]]
id = "retired"
path = "gone.txt"
filter = "D"

[[verdict]]
id = "V-HISTORY-TAG"
gloss = "the declared tag glob resolved a tag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-TAG"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-HISTORY-DELETED"
gloss = "the declared path filter resolved a deleting commit"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-DELETED"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-HISTORY-BODY"
gloss = "a commit body reached the policy input, which rule 4 refuses"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-BODY"
kind = "document"
target = "probe.rego"
"#;

/// The same probe declaring NO pattern — the anti-scanner arm.
const UNDECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["batten.toml"]

[[verdict]]
id = "V-HISTORY-TAG"
gloss = "the declared tag glob resolved a tag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-TAG"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-HISTORY-DELETED"
gloss = "the declared path filter resolved a deleting commit"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-DELETED"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-HISTORY-BODY"
gloss = "a commit body reached the policy input, which rule 4 refuses"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-BODY"
kind = "document"
target = "probe.rego"
"#;

/// One predicate per declared query, plus a body probe that must never fire.
///
/// `probe-body` is the rule-4 guarantee asserted rather than promised: it reaches
/// for a `body` key on every entry, so a widened struct or a changed serializer
/// turns this red.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-tag"

rules contains "probe-deleted"

rules contains "probe-body"

violation contains {
	"rule": "probe-tag",
	"verdict": "V-HISTORY-TAG",
} if {
	is_object(input.tree["git-history"])
	some entry in input.tree["git-history"].shipped
	entry.tag != ""
}

violation contains {
	"rule": "probe-deleted",
	"verdict": "V-HISTORY-DELETED",
} if {
	is_object(input.tree["git-history"])
	some entry in input.tree["git-history"].retired
	entry.commit != ""
}

violation contains {
	"rule": "probe-body",
	"verdict": "V-HISTORY-BODY",
} if {
	# GUARDED, and the guard is the lesson: `some .. in null` is a hard
	# evaluation FAULT in Rego, not a silent miss, so a module that iterates a
	# nullable fact without checking takes the whole bundle down with it. This
	# family is `null` on a shallow clone, which is the common case.
	is_object(input.tree["git-history"])
	some queries in input.tree["git-history"]
	some entry in queries
	entry.body
}

test_a_matched_tag_fires if {
	some v in violation with input as {"tree": {"git-history": {"shipped": [{"commit": "abc", "subject": "s", "tag": "v1.0.0"}], "retired": []}}}
	v.rule == "probe-tag"
}

test_a_deleting_commit_fires_the_other_class if {
	some v in violation with input as {"tree": {"git-history": {"shipped": [], "retired": [{"commit": "abc", "subject": "s"}]}}}
	v.rule == "probe-deleted"
}

test_an_empty_match_fires_neither if {
	count(violation) == 0 with input as {"tree": {"git-history": {"shipped": [], "retired": []}}}
}

test_could_not_look_fires_neither if {
	count(violation) == 0 with input as {"tree": {"git-history": null}}
}
"#;

/// A repository with a tag and a deleted path.
fn fixture(name: &str, config: &str) -> PathBuf {
    // OUTSIDE the tree, deliberately: `target/` is inside this repository,
    // which is itself SHALLOW, and this family answers could-not-look for a
    // shallow clone. A fixture there would inherit that answer and the suite
    // would prove nothing.
    let dir = scratch_outside_tree("history-facts", name);
    write(&dir, "batten.toml", config);
    write(&dir, "probe.rego", PROBE);
    write(&dir, "gone.txt", "here for now\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    // A body distinctive enough that finding it anywhere is unambiguous — the
    // thing rule 4 refuses to carry.
    git_in(
        &dir,
        &[
            "commit",
            "-q",
            "-m",
            "chore: base\n\nBODY-THAT-MUST-NOT-REACH-THE-POLICY-INPUT\n",
        ],
    );
    git_in(&dir, &["tag", "v1.0.0"]);

    std::fs::remove_file(dir.join("gone.txt")).expect("delete the path");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: retire the path"]);
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_declared_tag_glob_resolves_its_matching_set() {
    // THE POSITIVE, and the half `git-refs` structurally cannot reach: the row
    // names a PATTERN, and which tags exist is not knowable when it is written.
    let dir = fixture("tags", CONFIG);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-tag"),
        "a declared tag glob must resolve its matching set\nexit={:?}\nSTDOUT[{answer}]\nSTDERR[{cause}]",
        outcome.status.code()
    );
}

#[test]
fn a_declared_path_filter_resolves_its_deleting_commit() {
    // THE SECOND SHAPE, and a genuine positive control for the first: a
    // projection that emitted one hard-coded entry could satisfy the tag case and
    // not this one, because they resolve through different walks.
    let dir = fixture("paths", CONFIG);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-deleted"),
        "a declared add/delete filter must resolve its commit\n{answer}{cause}"
    );
}

#[test]
fn no_commit_body_reaches_the_policy_input() {
    // NON-NEGOTIABLE RULE 4. A history fact widens WHICH commits are visible,
    // never WHAT one carries — asserted two ways, because they fail differently:
    // the probe fires on any `body` key, and the body's own text is searched for
    // on both channels in case it arrives under another name.
    let dir = fixture("no-body", CONFIG);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        !answer.contains("probe-body"),
        "no `body` key may exist on a projected commit\n{answer}{cause}"
    );
    for channel in [&answer, &cause] {
        assert!(
            !channel.contains("BODY-THAT-MUST-NOT-REACH-THE-POLICY-INPUT"),
            "a commit body must not reach any output channel\n{channel}"
        );
    }
}

#[test]
fn an_undeclared_pattern_resolves_nothing() {
    // THE ANTI-SCANNER CASE. The repository is identical — same tag, same
    // deletion — and the row declares no pattern. Without this the family reads
    // whatever history is there rather than what a row asked for, which is the
    // difference between a fact and a git shell.
    let dir = fixture("undeclared", UNDECLARED);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "an undeclared pattern must resolve nothing\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-tag"), "{answer}{cause}");
    assert!(!answer.contains("probe-deleted"), "{answer}{cause}");
}

#[test]
fn a_shallow_clone_is_could_not_look() {
    // THE LIVE CASE, not a hypothetical: `batten`'s own working copy carries
    // `.git/shallow`, measured while implementing this family, and `linear-check`
    // deepens one before it can answer.
    //
    // A shallow clone cannot see the history a path query walks and may not carry
    // the tags a glob would match, so the WHOLE family is could-not-look rather
    // than a partial answer. Distinguishable from an empty match by the only
    // means that discriminates: the two cases above fire on this same repository
    // when it is fully cloned, and neither fires here.
    let origin = fixture("shallow-origin", CONFIG);
    let shallow = scratch_outside_tree("history-facts", "shallow");
    let _ = std::fs::remove_dir_all(&shallow);
    let cloned = git_in(
        Path::new("."),
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &format!("file://{}", origin.display()),
            &shallow.display().to_string(),
        ],
    );
    assert!(
        shallow.join(".git").join("shallow").exists(),
        "the fixture must actually be shallow for this case to mean anything: {cloned}"
    );

    let outcome = check(&shallow);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "a shallow clone must never be a policy verdict\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-tag"),
        "a shallow clone must not answer a tag glob\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-deleted"),
        "a shallow clone must not answer a path filter\n{answer}{cause}"
    );
}
