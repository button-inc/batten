//! `batten doctor session` over the session-start facts a registered rule reads
//! (CLOUD-1760), run against the compiled binary.
//!
//! # The defect this tier exists to keep closed
//!
//! Three registered mediated-call rules guard against reaching around the pin.
//! For one whole session all three were silent, and every one of them was
//! behaving correctly: the facts they read — `input.facts.tasks` and
//! `input.facts["pinned-programs"]` — are minted by the session-start chain, that
//! chain never ran, so each read `null`, treated it as could-not-look, and
//! refused nothing. *"A refusal on a failure to look would refuse the project"* is
//! the right per-module posture and it is not what failed.
//!
//! What failed is that **nothing asked whether the facts were produced at all**.
//! The composition fails open with every part correct, and the only report was one
//! `contract-drift` line whose consequence was a subordinate clause. A session in
//! that state is indistinguishable, to every gate, from a healthy one.
//!
//! # Why the mirror is half this file
//!
//! `an_unminted_fact_is_could_not_look` alone is satisfied by a verb that reports
//! could-not-look unconditionally — CLOUD-418's vacuous pass. `a_minted_fact_is_clean`
//! is what makes the pair discriminate, and it mints through the same writer the
//! session-start chain uses rather than spelling the record's bytes, so a fixture
//! cannot pass while the real writer and the real reader disagree (CLOUD-1093).
//!
//! `a_rule_reading_no_session_start_fact_is_not_judged` is the third axis and a
//! different kind of mirror: without it the gate could drift into "every mediated
//! rule must read a session-start fact", which would refuse most repositories.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, stdout};

/// A mediated module that DEREFERENCES a session-start fact.
///
/// The body is as small as a body can be and still read the fact: what is under
/// test is the engine's reading of the dependency edge off the AST, not this
/// predicate's own subject. The bracket spelling is deliberate — it is how the
/// committed `pinned-toolchain` module reads it, and a reader that handled only
/// the dotted form would see this module as depending on nothing.
const READS_A_FACT: &str = r#"package batten.fixture_fact_dep

import rego.v1

rules contains "fixture-fact-dep"

violation contains {
	"rule": "fixture-fact-dep",
	"verdict": "fixture fact probe",
	"subjects": [{"path": "fixture"}],
} if {
	names := input.facts["pinned-programs"]
	some segment in input.call.segments
	segment.words[0] in names
}
"#;

/// A mediated module that reads only the call, which most of them do.
///
/// The negative case: a rule depending on no session-start fact must contribute
/// to neither arm, so the gate cannot become "every rule must read a fact".
const READS_NO_FACT: &str = r#"package batten.fixture_callonly

import rego.v1

rules contains "fixture-callonly"

violation contains {
	"rule": "fixture-callonly",
	"verdict": "fixture fact probe",
	"subjects": [{"path": "fixture"}],
} if {
	some segment in input.call.segments
	segment.words[0] == "forbidden"
}
"#;

/// The transcript declaration and task-store template `session_drain` uses, so
/// the task half of the verb answers a real reading and this file's arms turn on
/// the fact half alone.
fn config(rule: &str, module: &str) -> String {
    format!(
        r#"version = 1

[transcript]
path = ".claude/.transcript.jsonl"
harness = "claude-code"
tasks = "/nonexistent/{{session}}"

[[verdict]]
id = "fixture fact probe"
gloss = "the fixture predicate matched"
class = """
A fixture class, carrying one route so the registry's own shape rules are met.
"""

[[verdict.route]]
id = "fixture probe probe"
kind = "command"
target = "stop running the fixture command"

[[rule]]
id = "{rule}"
kind = "policy"
scope = "mediated_call"
module = "{module}"
severity = "warn"
"#
    )
}

fn scratch(name: &str, rule: &str, module_path: &str, module: &str) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-doctor-session", name);
    // `init_repo` rather than a `git init` spelled here (CLOUD-1419): it is the
    // one helper for this, and a hand-rolled fork inside a fixture is what
    // `policy/fixture-forks.rego` refuses. Under the system temp dir it takes the
    // fork arm anyway, so the local spelling bought nothing and was a second
    // authority over what makes a fixture a repository.
    common::init_repo(&dir);
    common::write(&dir, "batten.toml", &config(rule, module_path));
    common::write(&dir, module_path, module);
    // The pin's manifest. Present because `pinned::key` derives the record's key
    // from the configs it is given and answers `None` for an empty set — so a
    // fixture with no manifest could not mint the fact even in the arm that must.
    common::write(&dir, "mise.toml", "[tools]\n");
    dir
}

/// Park one completed task, so the task half reads `0 of 1` rather than
/// could-not-look and cannot supply the exit code this file is asserting.
fn completed_task(dir: &Path) {
    common::write(
        dir,
        ".claude/.tasks/1.json",
        "{\n  \"id\": \"1\",\n  \"subject\": \"a declared unit of work\",\n  \"status\": \"completed\"\n}\n",
    );
}

/// Mint the session-start fact THROUGH THE CHAIN'S OWN WRITER.
///
/// `pinned::record` is what `pinned::refresh` calls at session start. Using it
/// here rather than writing the record's bytes is the CLOUD-1093 discipline: a
/// fixture that spells the format itself passes while the real writer and the
/// real reader disagree, and this file's whole subject is whether the reader can
/// tell a produced fact from an absent one.
fn mint(dir: &Path) {
    let programs: BTreeSet<String> = ["jq".to_owned()].into_iter().collect();
    assert!(
        batten::pinned::record(dir, &[dir.join("mise.toml")], &programs),
        "the fixture must be able to mint the fact it then asserts is minted"
    );
}

fn session(dir: &Path) -> Output {
    batten()
        .args(["doctor", "session"])
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_CONFIG_FROM")
        .output()
        .expect("run batten doctor session")
}

#[test]
fn a_session_whose_start_chain_did_not_run_is_could_not_look() {
    // THE STATE THE ROW WAS FOUND IN: rules registered, config valid, tree clean,
    // session-start facts absent. Before this row that combination exited 0.
    let dir = scratch(
        "unminted",
        "fixture-fact-dep",
        "policy/fixture-fact-dep.rego",
        READS_A_FACT,
    );
    completed_task(&dir);

    let output = session(&dir);
    assert_eq!(
        output.status.code(),
        Some(3),
        "an unminted fact is could-not-look, never a clean: {}",
        stdout(&output)
    );
    // A POINTER PAIR (rule 4): the rule that went silent, and what it wanted.
    assert!(
        stdout(&output).contains("fixture-fact-dep"),
        "the report names the rule that went silent: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("pinned-programs"),
        "the report names the fact nothing minted: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("could-not-look"),
        "got: {}",
        stdout(&output)
    );
    // The fact's VALUE never reaches the channel — the fixture mints `jq` in the
    // sibling case, and no arm of this verb may hand a program name back.
    assert!(
        !stdout(&output).contains("jq"),
        "the fact's contents must not reach the channel: {}",
        stdout(&output)
    );
}

#[test]
fn a_session_with_every_fact_minted_is_clean() {
    // THE ANTI-VACUITY MIRROR (CLOUD-418). Without this, a verb that reported
    // could-not-look unconditionally satisfies the case above and discriminates
    // nothing.
    let dir = scratch(
        "minted",
        "fixture-fact-dep",
        "policy/fixture-fact-dep.rego",
        READS_A_FACT,
    );
    completed_task(&dir);
    mint(&dir);

    let output = session(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a minted fact is clean: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("nothing minted it"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn a_rule_reading_no_session_start_fact_is_not_judged() {
    // The third axis: the gate must not become "every mediated rule must read a
    // session-start fact", which would refuse almost every repository. This rule
    // depends on nothing the chain mints, so an unrun chain says nothing about it.
    let dir = scratch(
        "callonly",
        "fixture-callonly",
        "policy/fixture-callonly.rego",
        READS_NO_FACT,
    );
    completed_task(&dir);

    let output = session(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a rule reading no session-start fact is not judged: {}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("fixture-callonly"),
        "got: {}",
        stdout(&output)
    );
}

#[test]
fn every_session_start_fact_has_a_reader() {
    // THE PAIRING IS THE THING THAT DRIFTS. `Fact::minted_at_session_start` says
    // which facts the chain produces; `doctor`'s `minted` says how to ask whether
    // one was. A fact admitted by the first with no arm in the second is reported
    // as unminted forever — safe, and useless. This holds the two in step.
    //
    // Fails by: adding a variant to `minted_at_session_start`'s `true` arm without
    // giving `doctor::minted` a reader for it.
    //
    // NO FIXTURE, AND THAT IS THE POINT: `has_session_start_reader` probes a path
    // that cannot exist, so this asserts the READER's presence and never any
    // record's. A fixture here would let a minted record stand in for an arm that
    // was never written.
    for fact in batten::facts::Fact::ALL {
        if !fact.minted_at_session_start() {
            continue;
        }
        assert!(
            batten::doctor::has_session_start_reader(*fact),
            "{} is minted at session start and `doctor::minted` has no reader for it",
            fact.as_str()
        );
    }
}
