//! `input.tree.external`, over the compiled binary (CLOUD-1167).
//!
//! **A `with input as` case cannot answer the question this file asks.**
//! CLOUD-845 measured a module fabricating an input KEY the engine cannot
//! produce and CLOUD-857 the same thing with an input SHAPE; both were green
//! over a gate that decided nothing. What is asked here is whether the ENGINE
//! can reach a file outside the repository at all — which is this family's whole
//! risk, since every other fact in the model is repo-rooted by construction.
//!
//! Four observations, per CLOUD-418, and each is here because dropping it makes
//! one of the others pass over a fact that resolves nothing:
//!
//! * `a_declared_out_of_root_file_is_read_and_decided_over` — the positive.
//! * `an_undeclared_file_is_unreadable` — **the anti-scanner case**, and the one
//!   a careless implementation passes by accident. The file is on disk, at a
//!   readable path, and no row declares it; a module must still see nothing.
//! * `an_unset_root_is_not_a_file_that_said_nothing` — could-not-look, told
//!   apart from a real negative by the only means that discriminates: the
//!   control below fires on a file whose flag is `false`, and this case must
//!   NOT, because nothing was read.
//! * `the_projection_carries_the_declared_value` — the positive control.
//!   Without it the first case passes over a projection that denied
//!   unconditionally, and the third passes over one that resolved nothing ever.
//!
//! The cause distinction one level down — `root-unset` against `absent` against
//! `unparsed` — is not observable through the binary today, because
//! `tree_document`'s causes are the caller's and `check` reports a skipped rule
//! without them. It is asserted in `rules.rs`'s own unit tier instead, and this
//! comment is here so the gap is stated rather than discovered.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, scratch_outside_tree, stderr, stdout, write};

/// The environment variable the fixture rows resolve their root beneath.
///
/// Deliberately not a `BATTEN_*` name: `common::batten()` scrubs every variable
/// the command surface declares, so a fixture using one would be testing the
/// scrubber. It is also the point of the family — the engine expands whatever
/// variable a row NAMES and has no opinion about which variables exist.
const ROOT_VAR: &str = "BATTEN_FIXTURE_EXTERNAL_ROOT";

/// Declares the out-of-root file and registers the probe over it.
const DECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[rule.external]]
id = "wiring"
root = "BATTEN_FIXTURE_EXTERNAL_ROOT"
path = "wiring.json"

[[verdict]]
id = "V-EXTERNAL-FLAG-SET"
gloss = "the declared out-of-root file carries a set flag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-EXTERNAL-FLAG-CLEAR"
gloss = "the declared out-of-root file carries a clear flag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-CLEAR"
kind = "document"
target = "probe.rego"
"#;

/// The same probe with NO `[[rule.external]]` row — the anti-scanner arm.
///
/// The file still exists, at the same readable path, and the module still asks
/// for it by the same id. Nothing declares it, so nothing may read it.
const UNDECLARED: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[verdict]]
id = "V-EXTERNAL-FLAG-SET"
gloss = "the declared out-of-root file carries a set flag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-EXTERNAL-FLAG-CLEAR"
gloss = "the declared out-of-root file carries a clear flag"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-CLEAR"
kind = "document"
target = "probe.rego"
"#;

/// Two predicates over one key, and the pair is what makes the suite
/// discriminate.
///
/// A single "the flag is set" rule would be silent on a clear flag AND silent on
/// a fact that resolved nothing, so could-not-look and a real negative would be
/// byte-identical on the decision surface — CLOUD-845's dead gate. Reading BOTH
/// values means the engine's silence is only ever could-not-look.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-set"

rules contains "probe-clear"

violation contains {
	"rule": "probe-set",
	"verdict": "V-EXTERNAL-FLAG-SET",
} if {
	input.tree.external.wiring.flag == true
}

violation contains {
	"rule": "probe-clear",
	"verdict": "V-EXTERNAL-FLAG-CLEAR",
} if {
	input.tree.external.wiring.flag == false
}

test_a_set_flag_fires if {
	some v in violation with input as {"tree": {"external": {"wiring": {"flag": true}}}}
	v.rule == "probe-set"
}

test_a_clear_flag_fires_the_other_class if {
	some v in violation with input as {"tree": {"external": {"wiring": {"flag": false}}}}
	v.rule == "probe-clear"
}

test_an_absent_key_fires_neither if {
	count(violation) == 0 with input as {"tree": {"external": {}}}
}
"#;

/// A repository fixture plus the out-of-root directory its row points at.
///
/// One of each per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the
/// projection.
fn fixture(name: &str, config: &str, wiring: Option<&str>) -> (PathBuf, PathBuf) {
    let repo = scratch(&format!("external-facts-{name}"));
    write(&repo, "batten.toml", config);
    write(&repo, "probe.rego", PROBE);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);

    // OUTSIDE the repository, which is the whole point: a path under the
    // checkout would be reachable through `documents` and would prove nothing
    // about this family.
    let outside = scratch_outside_tree("external-root", name);
    if let Some(body) = wiring {
        std::fs::create_dir_all(&outside).expect("out-of-root dir");
        std::fs::write(outside.join("wiring.json"), body).expect("write wiring");
    }
    (repo, outside)
}

/// `batten check` in `repo`, with the root variable set to `root` or removed.
fn check(repo: &Path, root: Option<&Path>) -> Output {
    let mut command = batten();
    command.current_dir(repo).arg("check");
    match root {
        Some(dir) => command.env(ROOT_VAR, dir),
        // REMOVED, not set to empty: this is the case where the host simply does
        // not have the root, and the engine must tell it apart from a file that
        // said nothing.
        None => command.env_remove(ROOT_VAR),
    };
    command.output().expect("run batten check")
}

#[test]
fn a_declared_out_of_root_file_is_read_and_decided_over() {
    // THE POSITIVE. Before this family the key was undefined, Rego read that as
    // *does not hold*, and the probe was silent on every tree — a dead gate and
    // a clean repository being byte-identical on the decision surface.
    let (repo, outside) = fixture("positive", DECLARED, Some(r#"{"flag": true}"#));
    let outcome = check(&repo, Some(&outside));
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a declared out-of-root file must reach the module\n{answer}{cause}"
    );
    assert!(answer.contains("probe-set"), "{answer}{cause}");
}

#[test]
fn the_projection_carries_the_declared_value() {
    // THE POSITIVE CONTROL (CLOUD-418). Without it the case above is satisfied
    // by a projection that emitted `true` unconditionally, and the case below is
    // satisfied by one that never resolves anything at all. The file is read and
    // its VALUE decides which class fires.
    let (repo, outside) = fixture("control", DECLARED, Some(r#"{"flag": false}"#));
    let outcome = check(&repo, Some(&outside));
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "the file's own value must decide the predicate\n{answer}{cause}"
    );
    assert!(answer.contains("probe-clear"), "{answer}{cause}");
    assert!(
        !answer.contains("probe-set"),
        "the projection must carry the file's value, not a constant\n{answer}{cause}"
    );
}

#[test]
fn an_undeclared_file_is_unreadable() {
    // THE ANTI-SCANNER CASE, and the one this row fails its own review without.
    // The file is on disk, at exactly the path the declared arm reads, and the
    // root variable is set — the ONLY difference is that no row declares it. A
    // module must see nothing, or this family is a filesystem scanner with a
    // configuration file in front of it.
    let (repo, outside) = fixture("undeclared", UNDECLARED, Some(r#"{"flag": true}"#));
    let outcome = check(&repo, Some(&outside));
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a path no row declares must be unreadable\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-set"), "{answer}{cause}");
    assert!(!answer.contains("probe-clear"), "{answer}{cause}");
}

#[test]
fn an_unset_root_is_not_a_file_that_said_nothing() {
    // COULD-NOT-LOOK, told apart from a real negative — and the pair of
    // predicates is what makes that observable. `the_projection_carries_the_
    // declared_value` fires `V-EXTERNAL-FLAG-CLEAR` on a file whose flag is
    // `false`; this case must fire NEITHER class, because nothing was read.
    //
    // Collapsing the two would ship a gate that reports the same answer on a
    // host that has the root and on one that has never heard of it, which is
    // CLOUD-845's class arriving as a clean tree.
    let (repo, outside) = fixture("unset-root", DECLARED, Some(r#"{"flag": false}"#));
    let outcome = check(&repo, None);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an unset root must never be a policy verdict\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-clear"),
        "an unset root must not read as the file saying `false`\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-set"), "{answer}{cause}");
    let _ = outside;
}

#[test]
fn no_byte_of_the_declared_file_reaches_the_output() {
    // NON-NEGOTIABLE RULE 4, asserted rather than promised. These paths hold a
    // consumer's permissions, connector rosters and credentials, so this is the
    // family where the rule is load-bearing rather than tidy — and the resolved
    // path is itself a machine's home directory, which is why the projection is
    // keyed by the declared id and `missing` carries the id too.
    let secret = r#"{"flag": true, "token": "fixture-secret-must-not-appear"}"#;
    let (repo, outside) = fixture("pointer-only", DECLARED, Some(secret));
    let outcome = check(&repo, Some(&outside));
    let cause = stderr(&outcome);
    let answer = String::from_utf8_lossy(&outcome.stdout);
    for channel in [&cause, &answer.to_string()] {
        assert!(
            !channel.contains("fixture-secret-must-not-appear"),
            "no byte of the file may reach an output channel\n{channel}"
        );
        assert!(
            !channel.contains(outside.to_string_lossy().as_ref()),
            "the resolved path is a machine's home directory and must not be reported\n{channel}"
        );
    }
}
