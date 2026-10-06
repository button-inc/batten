//! A `[[traversal]]` over document edges, read by a module through
//! `input.tree.traversals`, through the compiled binary (CLOUD-1868).
//!
//! The chain is 04 entry --slug--> 02 record --capture--> 01 capture file
//! --id--> the `caps` register. ANTI-VACUITY IS THE POINT: the closing case
//! exits 0, and the same rule refuses a break at EACH of the four hops, with a
//! rule id per hop so the case asserts WHERE it broke, not merely that it did.

use crate::common;

use common::{Fixture, run, stdout};

const CONFIG: &str = r#"version = 1

[[register]]
id = "caps"
paths = ["SOURCES.md"]
source = "table"
key = 1
width = 2

[[traversal]]
id = "warrant"
seeds = "db/*.md"
until_register = "caps"
max_visits = 32
max_depth = MAX_DEPTH
reduce = "path"

[[traversal.edge]]
label = "slug"
field = "slug"
to = { same-stem = "extract/*.md" }

[[traversal.edge]]
label = "capture"
field = "capture"
to = { template = "captures/{value}.md" }

[[traversal.edge]]
label = "id"
field = "id"
to = { register = "caps" }

[[rule]]
id = "chain"
kind = "policy"
scope = "tree"
module = "policy/chain.rego"
severity = "deny"

[[verdict]]
id = "chain open"
gloss = "a warrant chain does not reach a registered capture"
class = "A stage-04 entry whose chain breaks before a registered stage-01 capture."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/chain.rego"
"#;

/// One rule id per place a chain can break, so a case names the hop.
const MODULE: &str = r#"package batten.chain
import rego.v1
rules contains id if some id in {"broke-at-entry", "broke-at-record", "broke-at-capture", "broke-at-register", "chain-bound", "chain-unread"}

violation contains {"rule": rule, "verdict": "chain open", "subjects": [{"path": seed}]} if {
	some seed, answer in input.tree.traversals.warrant
	answer.outcome == "exhausted"
	rule := hop(seed, answer.broke_at)
}

violation contains {"rule": "chain-bound", "verdict": "chain open", "subjects": [{"path": seed}]} if {
	some seed, answer in input.tree.traversals.warrant
	answer.outcome == "bound-exceeded"
}

violation contains {"rule": "chain-unread", "verdict": "chain open", "subjects": [{"path": seed}]} if {
	some seed, answer in input.tree.traversals.warrant
	answer.outcome == "could-not-look"
}

hop(seed, at) := "broke-at-entry" if at == seed
hop(_, at) := "broke-at-record" if startswith(at, "extract/")
hop(_, at) := "broke-at-capture" if startswith(at, "captures/")
hop(_, at) := "broke-at-register" if startswith(at, "register:")
"#;

const SOURCES: &str = "| id | file |\n| - | - |\n| cap-a | a.md |\n";

/// Build, commit and `check` a chain fixture; return the exit code and stdout.
fn check(name: &str, max_depth: usize, files: &[(&str, &str)]) -> (Option<i32>, String) {
    let config = CONFIG.replace("MAX_DEPTH", &max_depth.to_string());
    let mut all: Vec<(&str, &str)> = vec![("policy/chain.rego", MODULE), ("SOURCES.md", SOURCES)];
    all.extend_from_slice(files);
    let dir = Fixture::new(name)
        .config(&config)
        .files(&all)
        .base_commit()
        .build();
    let out = run(&dir, &["check"]);
    (out.status.code(), stdout(&out))
}

const ENTRY: &str = "---\nslug: e\n---\n";
const RECORD: &str = "---\ncapture: [a]\n---\n";
const CAPTURE: &str = "---\nid: cap-a\n---\n";

#[test]
fn a_closing_chain_exits_zero() {
    let (code, out) = check(
        "chain-closes",
        8,
        &[
            ("db/e.md", ENTRY),
            ("extract/e.md", RECORD),
            ("captures/a.md", CAPTURE),
        ],
    );
    assert_eq!(code, Some(0), "{out}");
}

#[test]
fn no_record_for_the_slug_breaks_at_the_entry() {
    let (code, out) = check("chain-no-record", 8, &[("db/e.md", ENTRY)]);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md broke-at-entry"), "{out}");
}

#[test]
fn a_record_citing_no_capture_breaks_at_the_record() {
    let (code, out) = check(
        "chain-no-capture",
        8,
        &[("db/e.md", ENTRY), ("extract/e.md", "---\nother: x\n---\n")],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md broke-at-record"), "{out}");
}

#[test]
fn a_missing_capture_file_breaks_at_the_capture() {
    let (code, out) = check(
        "chain-capture-missing",
        8,
        &[("db/e.md", ENTRY), ("extract/e.md", RECORD)],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md broke-at-capture"), "{out}");
}

#[test]
fn a_capture_present_but_unregistered_breaks_at_the_register() {
    let (code, out) = check(
        "chain-unregistered",
        8,
        &[
            ("db/e.md", ENTRY),
            ("extract/e.md", RECORD),
            ("captures/a.md", "---\nid: cap-z\n---\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md broke-at-register"), "{out}");
}

#[test]
fn a_cycle_terminates() {
    // The capture file names the record's own slug back, so the walk revisits
    // `extract/e.md`. The visited set ends it; the answer is a break, not a hang.
    let (code, out) = check(
        "chain-cycle",
        8,
        &[
            ("db/e.md", ENTRY),
            ("extract/e.md", RECORD),
            ("captures/a.md", "---\nslug: e\n---\n"),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md broke-at-"), "{out}");
}

#[test]
fn a_bound_is_reported_as_bound_exceeded_never_as_a_break() {
    // Depth 1 reaches the record and stops with a frontier still to expand.
    let (code, out) = check(
        "chain-bound",
        1,
        &[
            ("db/e.md", ENTRY),
            ("extract/e.md", RECORD),
            ("captures/a.md", CAPTURE),
        ],
    );
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains("db/e.md chain-bound"), "{out}");
    assert!(
        !out.contains("broke-at"),
        "a bound says nothing about the chain: {out}"
    );
}
