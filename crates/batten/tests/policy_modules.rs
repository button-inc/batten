//! The policy evaluator (CLOUD-647, CLOUD-689): a registered module decides over
//! the resolved fact set, and the four ways that must fail at LOAD rather than at
//! the gate.
//!
//! The load-time half is the point of these, not a precaution. Regorus reports a
//! rule conflict and a recursion at **evaluation**, never at `add_policy` —
//! measured on 0.11.0 across five cases. Left alone, the first thing to discover
//! a cyclic module would be a denied tool call: the worst possible moment and the
//! wrong exit class, where house style §8 wants a config fault refused by
//! `config lint`. `load` drives a throwaway query for exactly that reason, and
//! `a_cyclic_module_is_refused_at_load` is what stops someone deleting it as
//! dead code.
//!
//! The other axis is CLOUD-251's vacuous pass. A module that cannot answer is
//! `CouldNotLook` and the call is allowed; it must never be silently read as an
//! empty deny set, and it must never be read as a deny either — a gate that
//! refuses where it could not look becomes the reason work cannot proceed.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use batten::facts::Look;
use batten::policy;
use batten::rules::Rule;

/// A policy row registering `module`, built the way a real config builds one.
///
/// Deserialized rather than struct-literalled: `Rule` carries
/// `deny_unknown_fields`, so this exercises the column census a consumer's
/// `batten.toml` goes through and a row that the loader would refuse cannot be
/// smuggled into a test by hand.
fn row(id: &str, module: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "mediated_call",
        "module": module,
        "severity": "deny",
    }))
    .expect("a policy row the loader accepts")
}

/// Write `source` to `<root>/<name>` and return the relative path.
fn module_file(root: &Path, name: &str, source: &str) -> String {
    fs::write(root.join(name), source).expect("write module");
    name.to_owned()
}

/// A module denying every call whose operation is a write.
const DENIES_WRITES: &str = r#"
package batten

import rego.v1

deny contains "a write, refused by the module" if {
    input.call.operation == "write"
}
"#;

/// Direct recursion. Accepted by `add_policy`, refused when queried — which is
/// the whole reason `load` queries.
const CYCLIC: &str = r"
package batten

import rego.v1

deny contains msg if {
    deny[msg]
}
";

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-policy-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

#[test]
fn a_module_denies_on_a_fact_and_is_silent_otherwise() {
    let root = scratch("denies");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let modules = policy::load(&root, &[row("policy-writes", &path)], None).expect("load");
    assert_eq!(modules.len(), 1);

    let denied = policy::deny(&modules[0], r#"{"call":{"operation":"write"}}"#);
    assert_eq!(
        denied,
        Look::Is(vec!["a write, refused by the module".to_owned()]),
        "the module decided over the fact it was handed"
    );

    // The same module, a fact it does not match: an answer, and the answer is
    // "no denials". Distinct from could-not-look, which the next test pins.
    let allowed = policy::deny(&modules[0], r#"{"call":{"operation":"read"}}"#);
    assert_eq!(allowed, Look::Is(Vec::new()));
    assert!(
        !allowed.could_not_look(),
        "an empty deny set IS an answer, and collapsing it into could-not-look \
         is CLOUD-251's vacuous pass wearing the other face"
    );
}

#[test]
fn an_unparseable_input_is_could_not_look_and_never_an_empty_deny_set() {
    let root = scratch("couldnotlook");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let modules = policy::load(&root, &[row("policy-writes", &path)], None).expect("load");

    let answer = policy::deny(&modules[0], "{not json");
    assert!(
        answer.could_not_look(),
        "a document the evaluator cannot take is not evidence that nothing denies"
    );
    assert_ne!(answer, Look::Is(Vec::new()), "the collapse, refused");
}

#[test]
fn a_cyclic_module_is_refused_at_load() {
    // The case the smoke query exists for. `add_policy` ACCEPTS this — regorus
    // reports recursion when a query reaches it — so without the throwaway query
    // in `load`, this module compiles clean here and faults at the gate.
    let root = scratch("cyclic");
    let path = module_file(&root, "cyclic.rego", CYCLIC);
    let err = policy::load(&root, &[row("policy-cyclic", &path)], None)
        .expect_err("a cycle is a config error, not a runtime surprise");
    let text = format!("{err}");
    assert!(
        text.contains("cyclic.rego"),
        "the refusal points at the module: {text}"
    );
    // The discriminating half (CLOUD-418). Both `add_policy` and the smoke query
    // would name the file, so a test asserting only that would pass on a `load`
    // with the query deleted — and the query is the entire reason this function
    // does more than compile. Assert the message came from the EVALUATION arm,
    // which is the only one a cycle can reach.
    assert!(
        text.contains("faults when evaluated"),
        "regorus accepts a cycle at `add_policy` and reports it on query, so this \
         must be the smoke query talking; if it is the compile arm, the query has \
         become dead code: {text}"
    );
}

#[test]
fn a_module_that_cannot_be_read_is_refused_at_load() {
    let root = scratch("absent");
    let err = policy::load(&root, &[row("policy-absent", "nowhere.rego")], None)
        .expect_err("a registration naming no file decides nothing and must not load");
    assert!(format!("{err}").contains("nowhere.rego"));
}

#[test]
fn two_rows_registering_one_module_are_refused_at_load() {
    // Dead config: the second registration decides nothing the first did not,
    // and "which one denied me" is not a question a reviewer should have to
    // answer. Same reasoning as the duplicate derived-value name (CLOUD-773).
    let root = scratch("duplicate");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let err = policy::load(&root, &[row("first", &path), row("second", &path)], None)
        .expect_err("one module, two registrations");
    assert!(format!("{err}").contains("already registers"));
}

#[test]
fn a_module_holds_no_source_and_cannot_leak_one_through_debug() {
    // Rule 4 is structural here rather than careful: `Module` has no `source`
    // field, so there is nothing for a derived `Debug` to render even if someone
    // re-derived it. This asserts the rendering, which is the reachable half.
    let root = scratch("pointer");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let modules = policy::load(&root, &[row("policy-writes", &path)], None).expect("load");
    let rendered = format!("{:?}", modules[0]);
    assert!(rendered.contains("policy-writes"), "the pointer is present");
    assert!(
        !rendered.contains("deny contains"),
        "no byte of the policy body reaches a log: {rendered}"
    );
}
