//! `input.tree.captured`, over the compiled binary (CLOUD-1188).
//!
//! **The reduction is the family, and two of these cases are the only proof it is
//! real.** A fact carrying whole payloads would put a tracker's prose on the
//! policy input where any module could lift it into a `subjects` pointer, so
//! `no_payload_prose_reaches_the_policy_input` asserts non-negotiable rule 4
//! rather than promising it. One of this suite's declared rows reduces a `token`
//! over the payload's own prose, so what has to hold is the FAMILY's refusal and
//! not a module's discipline — and the refusal is a refusal rather than a
//! truncation, because a prefix of an issue body is still an issue body.
//! `captured.rs`'s own unit tier pins that bound directly.
//!
//! **The store, never stdin.** `two_runs_over_an_unchanged_store_agree` is what a
//! `Surface::Check` fact owes and what stdin structurally cannot offer: the
//! capture listing is sorted by handle rather than by time, so the answer is a
//! pure function of the store's bytes. A stdin channel would also be dropped by
//! the surface table before projection, would be context re-sent every turn, and
//! is invisible to the step-receipt key — three refusals, any one sufficient.
//!
//! A `with input as` case can do none of this: it fabricates the very shape the
//! engine may be unable to produce (CLOUD-845, CLOUD-857), and here it would
//! fabricate the reduction itself.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{StateHome as _, batten, git_in, scratch, stderr, stdout, write};

/// The key a row declares, and the token that selects a capture.
const DECLARED_KEY: &str = "PROBE-1";
/// A key no capture carries — the nothing-was-captured arm.
const ABSENT_KEY: &str = "PROBE-9";
/// Prose distinctive enough that finding it anywhere is unambiguous. This is the
/// thing rule 4 refuses to carry, and the `token` reduction over it must refuse.
const PROSE: &str = "PAYLOAD-PROSE-THAT-MUST-NOT-REACH-THE-POLICY-INPUT and more words";

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[rule.captured]]
id = "state"
key = "{DECLARED_KEY}"
node = "status"
reduce = "token"

[[rule.captured]]
id = "body"
key = "{DECLARED_KEY}"
node = "description"
reduce = "token"

[[rule.captured]]
id = "labels"
key = "{DECLARED_KEY}"
node = "labels"
reduce = "count"

[[rule.captured]]
id = "missing"
key = "{ABSENT_KEY}"
node = "status"
reduce = "present"

[[verdict]]
id = "V-CAPTURED-STATE"
gloss = "the declared reduction produced the expected state token"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-STATE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-CAPTURED-COUNT"
gloss = "the declared count reduction produced the expected number"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-COUNT"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-CAPTURED-PROSE"
gloss = "a payload's prose reached the policy input, which rule 4 refuses"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-PROSE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-CAPTURED-ABSENT"
gloss = "a key nothing captured answered anyway"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-ABSENT"
kind = "document"
target = "probe.rego"
"#
    )
}

/// Four predicates over one key, and the set is what discriminates.
///
/// `probe-prose` and `probe-absent` must never fire; `probe-state` and
/// `probe-count` must, and they read different reductions, so a projection that
/// emitted one constant could not satisfy both.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-state"

rules contains "probe-count"

rules contains "probe-prose"

rules contains "probe-absent"

violation contains {
	"rule": "probe-state",
	"verdict": "V-CAPTURED-STATE",
} if {
	is_object(input.tree.captured)
	input.tree.captured.state == "unstarted"
}

violation contains {
	"rule": "probe-count",
	"verdict": "V-CAPTURED-COUNT",
} if {
	is_object(input.tree.captured)
	input.tree.captured.labels == 2
}

# THE RULE-4 PROBE. It fires on any value long enough or spaced enough to be
# prose, so a widened projection or a relaxed reduction turns this red.
violation contains {
	"rule": "probe-prose",
	"verdict": "V-CAPTURED-PROSE",
} if {
	is_object(input.tree.captured)
	some value in input.tree.captured
	is_string(value)
	contains(value, " ")
}

# A key nothing captured must be ABSENT, never present with a falsy answer.
violation contains {
	"rule": "probe-absent",
	"verdict": "V-CAPTURED-ABSENT",
} if {
	is_object(input.tree.captured)
	input.tree.captured.missing == false
}

test_a_token_reduction_fires if {
	count(violation) > 0 with input as {"tree": {"captured": {"state": "unstarted"}}}
}

test_a_count_reduction_fires_the_other_class if {
	some v in violation with input as {"tree": {"captured": {"labels": 2}}}
	v.rule == "probe-count"
}

test_prose_fires_the_rule_four_probe if {
	some v in violation with input as {"tree": {"captured": {"state": "two words"}}}
	v.rule == "probe-prose"
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"captured": null}}
}
"#;

/// The captured response the store holds — the shape a tracker returns.
fn payload() -> String {
    serde_json::json!({
        "id": DECLARED_KEY,
        "status": "unstarted",
        "labels": ["one", "two"],
        "description": PROSE,
    })
    .to_string()
}

/// A repository whose rows declare four reductions, with one response captured.
///
/// The store path is DERIVED rather than guessed: `state::derive_repo_name`
/// keys it to this checkout, which is the same function the child resolves it
/// through, so the fixture and the binary cannot disagree about where the store
/// is. `capture::store_in` then writes the blob exactly as `exec` would — the
/// whole argument for this channel is that it reads what an agent already
/// populated, so a fixture writing the bytes some other way would test a path no
/// consumer takes.
fn fixture(name: &str, capture: bool) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("captured-{name}"));
    let home = scratch(&format!("captured-home-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    if capture {
        let store = home
            .join("data")
            .join(env!("CARGO_PKG_NAME"))
            .join(batten::state::derive_repo_name(&dir).expect("derive the repo state segment"))
            .join("captures");
        std::fs::create_dir_all(&store).expect("create the capture store");
        batten::capture::store_in(
            &store,
            batten::capture::Stream::Response,
            payload().as_bytes(),
        )
        .expect("store the response");
    }
    (dir, home)
}

fn check(dir: &Path, home: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).state_home(home).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_declared_reduction_reaches_the_module() {
    // THE POSITIVE. Before this family a tree-scoped board predicate read
    // undefined, Rego took undefined as *does not hold*, and every one of the ten
    // gates was a CLI verb because it had nowhere to read from.
    let (dir, home) = fixture("state", true);
    let outcome = check(&dir, &home);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-state"),
        "a declared token reduction must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_projection_carries_each_declared_reduction() {
    // THE POSITIVE CONTROL (CLOUD-418). Two reductions of different KINDS over
    // one captured response: a projection emitting a single constant could
    // satisfy the case above and not this one, because a count and a token
    // resolve through different arms.
    let (dir, home) = fixture("count", true);
    let outcome = check(&dir, &home);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-count"),
        "a `count` reduction must resolve its own answer\n{answer}{cause}"
    );
}

#[test]
fn no_payload_prose_reaches_the_policy_input() {
    // NON-NEGOTIABLE RULE 4, asserted two ways because they fail differently: the
    // probe fires on any value carrying a space, and the payload's own text is
    // searched for on both channels in case it arrives under another name.
    //
    // The `description` row declares a `token` reduction over prose, so the
    // family's own refusal is what has to hold — not the module's discipline.
    let (dir, home) = fixture("prose", true);
    let outcome = check(&dir, &home);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        !answer.contains("probe-prose"),
        "no value on this document may be prose\n{answer}{cause}"
    );
    for channel in [&answer, &cause] {
        assert!(
            !channel.contains("PAYLOAD-PROSE-THAT-MUST-NOT-REACH-THE-POLICY-INPUT"),
            "a payload's prose must not reach any output channel\n{channel}"
        );
    }
}

#[test]
fn a_key_nothing_captured_is_absent_rather_than_false() {
    // COULD-NOT-LOOK at the key, told apart from a real negative by the only
    // means that discriminates: the `missing` row declares a `present` reduction,
    // which always yields an answer when a capture matches — so its ABSENCE from
    // the map is the engine saying nothing was captured, and the probe that fires
    // on `false` must stay silent.
    //
    // Collapsing them reports on a row nothing ever looked at, which is the
    // vacuous pass in its purest form.
    let (dir, home) = fixture("absent-key", true);
    let outcome = check(&dir, &home);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        !answer.contains("probe-absent"),
        "a key nothing captured must be absent, never a negative\n{answer}{cause}"
    );
}

#[test]
fn an_unpopulated_store_is_could_not_look() {
    // The whole fact is `null` and nothing fires — distinguishable from the
    // positive above, which fires on the same configuration once a response has
    // been captured. A board gate reporting green over a store nobody filled is
    // exactly what this keeps impossible.
    let (dir, home) = fixture("no-store", false);
    let outcome = check(&dir, &home);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an unpopulated store must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-state"), "{answer}{cause}");
    assert!(!answer.contains("probe-count"), "{answer}{cause}");
}

#[test]
fn two_runs_over_an_unchanged_store_agree() {
    // BYTE STABILITY (§6), and the property that makes this a `Surface::Check`
    // fact at all: `capture::list` sorts by handle rather than by time, so the
    // answer is a pure function of the store's bytes. A time-ordered store would
    // make the reduction a function of when captures happened — and asserted with
    // a repeat comparison rather than a clock, which discriminates nothing.
    let (dir, home) = fixture("stable", true);
    let first = stdout(&check(&dir, &home));
    let second = stdout(&check(&dir, &home));
    assert_eq!(
        first, second,
        "two runs over an unchanged store must be byte-identical"
    );
}
