//! `input.tree["commit-meta"]`, over the compiled binary (CLOUD-1187).
//!
//! **The rule-4 case is the one this file exists for.** `git::CommitRecord`
//! already carries `%B`, because `attribution.rs` judges the message itself;
//! this family reaches Rego, where a message body would put tracked content on
//! the policy input. `git::CommitMeta` has no body field at all, so the
//! guarantee is structural — and `no_message_body_reaches_the_policy_input`
//! asserts it directly rather than inferring it from the absence of a
//! serializer line, which is what a comment would have done.
//!
//! The other three observations are CLOUD-418's: a declared range is read and
//! decided over; an UNDECLARED range acquires nothing; and a positive control,
//! without which the first passes over a projection that denied unconditionally.
//!
//! A `with input as` case answers none of them — it fabricates the very shape
//! the engine may be unable to produce (CLOUD-845, CLOUD-857).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, stdout, write};

/// A body distinctive enough that finding it anywhere is unambiguous.
///
/// It is the thing rule 4 refuses, so the assertion is that this string reaches
/// neither the projected input nor any output channel.
const BODY: &str = "BODY-THAT-MUST-NOT-REACH-THE-POLICY-INPUT";

/// Declares the range whose identity fields the probe reads.
const DECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
commits = ["HEAD~1..HEAD"]

[[verdict]]
id = "V-COMMIT-META-TRAILER"
gloss = "a commit in the declared range carries the trailer the probe looks for"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-COMMIT-META-BODY"
gloss = "a message body reached the policy input, which rule 4 refuses"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-BODY"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-COMMIT-META-AUTHOR"
gloss = "a commit in the declared range carries an author identity"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-AUTHOR"
kind = "document"
target = "probe.rego"
"#;

/// The same probe declaring NO range — the acquires-nothing arm.
const UNDECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["batten.toml"]

[[verdict]]
id = "V-COMMIT-META-TRAILER"
gloss = "a commit in the declared range carries the trailer the probe looks for"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-COMMIT-META-BODY"
gloss = "a message body reached the policy input, which rule 4 refuses"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-BODY"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-COMMIT-META-AUTHOR"
gloss = "a commit in the declared range carries an author identity"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-AUTHOR"
kind = "document"
target = "probe.rego"
"#;

/// Three predicates: the trailer, the author, and a body probe that must never
/// fire.
///
/// `probe-body` is the load-bearing one. It reaches for a `body` key on every
/// entry, so if the projection ever grew one — by a widened struct, a changed
/// serializer, a future author folding `CommitRecord` in — this fires and the
/// suite goes red. A test that only asserted the trailer is readable would be
/// silent on exactly that regression.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-trailer"

rules contains "probe-author"

rules contains "probe-body"

violation contains {
	"rule": "probe-trailer",
	"verdict": "V-COMMIT-META-TRAILER",
} if {
	some commits in input.tree["commit-meta"]
	some entry in commits
	some trailer in entry.trailers
	startswith(trailer, "Weakens:")
}

violation contains {
	"rule": "probe-author",
	"verdict": "V-COMMIT-META-AUTHOR",
} if {
	some commits in input.tree["commit-meta"]
	some entry in commits
	entry.author != ""
}

violation contains {
	"rule": "probe-body",
	"verdict": "V-COMMIT-META-BODY",
} if {
	some commits in input.tree["commit-meta"]
	some entry in commits
	entry.body
}

test_a_declared_trailer_is_readable if {
	some v in violation with input as {"tree": {"commit-meta": {"a..b": [{
		"commit": "abc",
		"author": "A <a@example.com>",
		"committer": "A <a@example.com>",
		"trailers": ["Weakens: protected"],
	}]}}}
	v.rule == "probe-trailer"
}

test_a_range_with_no_such_trailer_does_not_fire_it if {
	count({v | some v in violation; v.rule == "probe-trailer"}) == 0 with input as {"tree": {"commit-meta": {"a..b": [{
		"commit": "abc",
		"author": "A <a@example.com>",
		"committer": "A <a@example.com>",
		"trailers": [],
	}]}}}
}

test_the_body_probe_is_silent_on_the_shape_the_engine_emits if {
	count({v | some v in violation; v.rule == "probe-body"}) == 0 with input as {"tree": {"commit-meta": {"a..b": [{
		"commit": "abc",
		"author": "A <a@example.com>",
		"committer": "A <a@example.com>",
		"trailers": [],
	}]}}}
}
"#;

/// A repository with two commits: a base, then one carrying the trailer and the
/// body the assertions are about.
fn fixture(name: &str, config: &str) -> PathBuf {
    let dir = scratch(&format!("commit-meta-{name}"));
    write(&dir, "batten.toml", config);
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    // An identity on the repository rather than the ambient one, so the fixture
    // does not depend on whatever this machine configured.
    git_in(&dir, &["config", "user.name", "Fixture Author"]);
    git_in(&dir, &["config", "user.email", "fixture@example.com"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);

    write(&dir, "second.txt", "second\n");
    git_in(&dir, &["add", "-A"]);
    // The trailer the range must expose, and the body it must not.
    let message = format!("chore: second\n\n{BODY}\n\nWeakens: protected\n");
    git_in(&dir, &["commit", "-q", "-m", &message]);
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_declared_range_exposes_its_commits_trailers() {
    // THE POSITIVE, and the one the row's acceptance names: `config-lint.sh:174`
    // reads `Weakens:` trailers over `origin/main..HEAD` today, which is why
    // CLOUD-1162's unit could not land. This is that read, expressible.
    let dir = fixture("trailer", DECLARED);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a declared range's trailers must reach the module\n{answer}{cause}"
    );
    assert!(answer.contains("probe-trailer"), "{answer}{cause}");
}

#[test]
fn the_projection_carries_the_author_identity() {
    // THE POSITIVE CONTROL (CLOUD-418). A second field, read independently, so
    // the case above cannot pass over a projection that emitted one hard-coded
    // entry — and so `attribution check`'s own question (who authored this) is
    // shown answerable, which is the other half of what this family unblocks.
    let dir = fixture("author", DECLARED);
    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert!(
        answer.contains("probe-author"),
        "the author identity must reach the module\n{answer}"
    );
}

#[test]
fn no_message_body_reaches_the_policy_input() {
    // NON-NEGOTIABLE RULE 4, asserted rather than promised, and in two ways
    // because they fail differently.
    //
    // The probe fires on ANY `body` key, so a widened struct or a changed
    // serializer turns this red — which a test that only read the trailer would
    // sleep through. And the body's text is searched for on both channels, which
    // catches it arriving under some other name.
    let dir = fixture("no-body", DECLARED);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        !answer.contains("probe-body"),
        "no `body` key may exist on a projected commit\n{answer}{cause}"
    );
    for channel in [&answer, &cause] {
        assert!(
            !channel.contains(BODY),
            "a message body must not reach any output channel\n{channel}"
        );
    }
}

#[test]
fn an_undeclared_range_acquires_nothing() {
    // THE BOUND. The repository is identical — same commits, same trailer, same
    // author — and the row declares no range. Acquisition is guarded on the
    // declaration, so the key resolves nothing and every predicate is silent.
    //
    // Without this the family is a git shell: it would read whatever history is
    // there rather than what a row asked for, and `Cost::Read` would stop being
    // an honest classification.
    let dir = fixture("undeclared", UNDECLARED);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "an undeclared range must acquire nothing\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-trailer"), "{answer}{cause}");
    assert!(!answer.contains("probe-author"), "{answer}{cause}");
}
