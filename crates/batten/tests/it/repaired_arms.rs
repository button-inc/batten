//! The repaired arms, end to end over the compiled binary (CLOUD-1639).
//!
//! `Rule::fix` existed since CLOUD-81 and was executed by nothing. These are the
//! cases that say it runs, which arm the boundary takes when it does, and — the
//! one that matters most — that a repair which did NOT happen is never reported
//! as one.
//!
//! # A LOCAL REPAIR, NEVER A NETWORK ONE
//!
//! The issue named `batten mcp call Linear get_issue` as its first candidate.
//! That was retired before it shipped: no network call can be guaranteed inside
//! `perf-assert`'s 100 ms hook ceiling, and every other rule at this boundary
//! adjudicates CACHED state — receipts, claims, captures — never a live read.
//! `policy/module-layering.rego` now forbids `repair` the network modules so the
//! bound is a gate rather than a sentence, and these fixtures repair by creating
//! a file, which is what a local repair looks like.
//!
//! # WHY EVERY ROW HERE IS `kind = "policy"`
//!
//! A repair is admissible only where the row's CLASS declares `applicability`,
//! and a `policy` row's module is the one thing that raises a class the CONSUMER
//! declared. A `shape` or `receipt` row raises its KIND's native class — every
//! `shape` row raises `call name refused` — so `applicability` there would flip
//! every row of the kind at once. The first draft of these fixtures was written
//! against a `shape` row and could not be made to load, which is what narrowed
//! `RuleKind::repairs_at_the_boundary` to `policy` alone.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// The module every fixture here binds: it refuses one command spelling and
/// raises a class the fixture's own config declares.
const MODULE: &str = r#"# METADATA
# description: |
#   The fixture module CLOUD-1639's repaired arms are exercised through.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.repair_fixture

import rego.v1

rules contains "repair-fixture"

violation contains {
	"rule": "repair-fixture",
	"verdict": "call fix pending",
	"subjects": [{"count": 1}],
} if {
	some segment in input.call.segments
	some word in segment.words
	word == "needs-repair"
}
"#;

/// The consumer class the module raises, with `applicability` left to the caller.
///
/// `call fix pending` rather than either vendored name: `call retry now` and
/// `call fix silent` are what the boundary RAISES after a repair, and a consumer
/// redeclaring a vendored token is refused at load. This is the class being
/// repaired FROM.
fn config(applicability: &str, fix: &str, extra: &str) -> String {
    format!(
        r#"version = 1

[[verdict]]
id = "call fix pending"
gloss = "the fixture class a declared repair is attached to"
applicability = "{applicability}"
class = """
A fixture class. It exists so a `policy` row can declare a repair against a
class the consumer owns, which is the only shape `applicability` can take.
"""

[[verdict.route]]
id = "config read first"
kind = "document"
target = "batten.toml"

[[rule]]
id = "repair-fixture"
kind = "policy"
scope = "mediated_call"
module = "policy/repair-fixture.rego"
severity = "deny"
fix = "{fix}"
{extra}
"#
    )
}

/// A fixture carrying the module and a config the caller shaped.
fn repo(name: &str, contents: &str) -> PathBuf {
    let staged = Fixture::new(name).config(contents);
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    std::fs::write(modules.join("repair-fixture.rego"), MODULE).expect("write the module");
    staged.git().base_commit().build()
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

fn fire(repo: &Path) -> (Option<i32>, String) {
    let run = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload("needs-repair now"),
    );
    (run.status.code(), stderr(&run).trim().to_owned())
}

/// THE HEADLINE: a `retry` repair runs, and the boundary refuses with the class
/// whose token IS the instruction to re-issue.
#[test]
fn a_retry_repair_refuses_and_never_allows() {
    let dir = repo("repair-retry", &config("retry", "touch repaired.txt", ""));
    let (code, text) = fire(&dir);
    assert_eq!(
        code,
        Some(2),
        "a repaired-and-retry call is still a refusal — the call as made did not happen: {text}"
    );
    assert!(
        text.contains("call retry now"),
        "the retry class is what travels: {text}"
    );
    assert!(
        dir.join("repaired.txt").exists(),
        "and the repair actually ran"
    );
}

/// THE OTHER POSTURE: `silent` allows, and writes the record it owes.
#[test]
fn a_silent_repair_allows_and_records() {
    let dir = repo(
        "repair-silent",
        &config(
            "silent",
            "touch repaired.txt",
            "no_retry_reason = \"the repair is idempotent and the caller has nothing to re-issue\"",
        ),
    );
    let (code, text) = fire(&dir);
    assert_eq!(code, Some(0), "a repaired-and-silent call proceeds: {text}");
    assert!(
        text.contains("call fix silent"),
        "the record names the class: {text}"
    );
    assert!(
        text.contains("repair-fixture"),
        "and the row that repaired: {text}"
    );
    assert!(
        dir.join("repaired.txt").exists(),
        "and the repair actually ran"
    );
}

/// THE ONE THAT MATTERS MOST: a repair that FAILED is never reported as one.
///
/// Without it the two cases above are satisfied by a boundary that claims
/// success unconditionally — a caller told the tree was fixed when it was not,
/// which is the worst shape this feature could take.
#[test]
fn a_failed_repair_falls_back_to_the_ordinary_refusal() {
    let dir = repo("repair-failing", &config("retry", "false", ""));
    let (code, text) = fire(&dir);
    assert_eq!(
        code,
        Some(2),
        "a failed repair is the original refusal, not an allow: {text}"
    );
    assert!(
        text.contains("call fix pending"),
        "the ORIGINAL class is what refused: {text}"
    );
    for claimed in ["call retry now", "call fix silent"] {
        assert!(
            !text.contains(claimed),
            "and no repaired arm is claimed: {text}"
        );
    }
}

/// ANTI-VACUITY: an `advice` class runs no repair, however the row is spelled.
///
/// Without it every case above passes over a boundary that repairs on every
/// refusal, which would make `applicability` decorative.
#[test]
fn an_advice_class_leaves_the_refusal_alone() {
    let dir = repo("repair-advice", &config("advice", "touch repaired.txt", ""));
    let (code, text) = fire(&dir);
    assert_eq!(code, Some(2), "the ordinary refusal still refuses: {text}");
    assert!(
        !dir.join("repaired.txt").exists(),
        "an advice class runs no repair: {text}"
    );
    assert!(
        !text.contains("call retry now"),
        "and claims no repaired arm: {text}"
    );
}
