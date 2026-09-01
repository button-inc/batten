//! `input.call["run-in-background"]`, over the compiled binary (CLOUD-1094).
//!
//! **A `with input as` case cannot answer this**, which is why the tier is here
//! rather than in a module's own suite. CLOUD-845 measured a module fabricating
//! an input KEY the engine cannot produce, and CLOUD-857 the same thing with an
//! input SHAPE; both were green over a gate that decided nothing. The question
//! this file asks is precisely the one those cannot: does the ENGINE put the key
//! in the document it hands a module.
//!
//! The fixture module is deliberately trivial — it fires on the flag and on
//! nothing else — so a failure here is about the projection and never about a
//! predicate. Two arms, because one proves nothing: a module that denied every
//! call would satisfy the positive and be useless (CLOUD-418).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{git_in, run_with_stdin, scratch, stderr, write};

const CONFIG: &str = r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "mediated_call"
module = "probe.rego"
severity = "deny"

[[verdict]]
id = "probe backgrounded probe"
gloss = "the probe saw a backgrounded call"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe probe probe"
kind = "document"
target = "probe.rego"
"#;

/// Fires on the projected flag and on nothing else.
///
/// `== true` rather than a truthiness test, deliberately: the key is
/// three-valued, and a predicate that fired on `null` would be reading
/// "the host said nothing" as "the host said no".
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe"

violation contains {
	"rule": "probe",
	"verdict": "probe backgrounded probe",
} if {
	input.call["run-in-background"] == true
}

test_a_backgrounded_call_fires if {
	some v in violation with input as {"call": {"run-in-background": true, "command": "cd /tmp && sleep 1"}}
	v.rule == "probe"
}

test_a_foreground_call_does_not if {
	count(violation) == 0 with input as {"call": {"run-in-background": false, "command": "cd /tmp && sleep 1"}}
}

test_an_absent_flag_is_not_a_false_one if {
	count(violation) == 0 with input as {"call": {"run-in-background": null, "command": "cd /tmp && sleep 1"}}
}
"#;

/// A fixture per case: these run in parallel and `git init` races on a shared
/// directory, which is a fact about the harness rather than about the projection.
fn fixture(name: &str) -> PathBuf {
    let dir = scratch(&format!("call-background-flag-{name}"));
    write(&dir, "batten.toml", CONFIG);
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

/// The exit status the `exit-code` harness renders: `2` is the policy verdict.
fn verdict(dir: &Path, payload: &str) -> (Option<i32>, String) {
    let outcome = run_with_stdin(dir, &["hook", "--harness", "exit-code"], payload);
    (outcome.status.code(), stderr(&outcome))
}

fn envelope(flag: Option<bool>) -> String {
    let extra = match flag {
        Some(true) => r#","run_in_background":true"#,
        Some(false) => r#","run_in_background":false"#,
        None => "",
    };
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":\"sleep 90\"{extra}}}}}"
    )
}

#[test]
fn a_backgrounded_call_reaches_the_module() {
    // The positive. Before the projection this key was undefined, Rego read that
    // as *does not hold*, and the probe was silent on every call — a dead gate
    // and a clean tree being byte-identical on the decision surface.
    let dir = fixture("backgrounded");
    let (code, cause) = verdict(&dir, &envelope(Some(true)));
    assert_eq!(code, Some(2), "the flag must reach the module\n{cause}");
    assert!(cause.contains("probe backgrounded probe"), "{cause}");
}

#[test]
fn a_foreground_call_does_not() {
    // The discrimination. Without it the case above passes over a projection
    // that emitted `true` unconditionally.
    let dir = fixture("foreground");
    let (code, cause) = verdict(&dir, &envelope(Some(false)));
    assert_eq!(code, Some(0), "an explicit false must not fire\n{cause}");
}

#[test]
fn a_host_that_said_nothing_is_not_a_false_one() {
    // THREE-VALUED, and this is the case that holds it. Most hosts send no such
    // key at all, so collapsing absent into `false` would be a claim about every
    // one of them — and a predicate wanting "definitely foreground" would then
    // fire on a host that never spoke.
    let dir = fixture("absent");
    let (code, cause) = verdict(&dir, &envelope(None));
    assert_eq!(code, Some(0), "an absent flag must not fire\n{cause}");
}

#[test]
fn the_other_host_spelling_resolves_to_the_same_answer() {
    // `Field::RunInBackground` reads `run_in_background` or `runInBackground`
    // because the hosts disagree the same way they do over
    // `tool_response`/`toolResponse`. The projection carries THAT answer rather
    // than a raw key, so a module never has to know which host it is behind —
    // and this is what pins that, since a projection reading the key directly
    // would pass every case above and fail only here.
    let dir = fixture("camel-case");
    let payload = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
                   \"tool_input\":{\"command\":\"sleep 90\",\"runInBackground\":true}}";
    let (code, cause) = verdict(&dir, payload);
    assert_eq!(
        code,
        Some(2),
        "the camelCase spelling must resolve\n{cause}"
    );
}
