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

/// A module reaching for the network, and the whole of CLOUD-831's behavioural
/// half.
///
/// `http.send` is a real OPA builtin that regorus gates behind its own `http`
/// feature. The workspace manifest pins `default-features = false` precisely so
/// that feature never enters the closure, and this is what asks the question the
/// pin exists to answer — *can a module reach the network* — rather than
/// asserting a string in a manifest.
const REACHES_THE_NETWORK: &str = r#"
package batten

import rego.v1

deny contains "the module reached the network" if {
    http.send({"method": "get", "url": "http://example.invalid/"})
}
"#;

/// The same shape over the `jsonschema` builtin, which the same feature line
/// keeps out. Two builtins rather than one because the manifest names two, and a
/// test covering half the pin would report the pin held while half of it drifted.
const REACHES_JSONSCHEMA: &str = r#"
package batten

import rego.v1

deny contains "the module validated a schema" if {
    json.verify_schema({"type": "object"})
}
"#;

/// The discriminator's control: a builtin that IS in the closure.
///
/// Without this, `no_evaluator_feature_admits_io` cannot tell "the builtin is
/// absent" from "this test cannot make a module deny at all" — it would assert
/// its own premise before its conclusion, which is what `.claude/rules/rust.md`
/// and CLOUD-249 refuse. `count` ships with the evaluator under any feature set,
/// so this module MUST deny for the assertions below to mean anything.
const REACHES_AN_INCLUDED_BUILTIN: &str = r#"
package batten

import rego.v1

deny contains "the module called a builtin that is in the closure" if {
    count([1, 2, 3]) == 3
}
"#;

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

/// The pin `policy.rs`'s module doc has cited since CLOUD-689 and nothing has
/// ever enforced (CLOUD-831).
///
/// # What this asserts, and why it is behavioural rather than textual
///
/// `policy.rs` admits consumer-authored code to the mediated call on one claim:
/// a module "cannot open a file, start a process, or reach the network". The
/// workspace manifest closes that with `default-features = false`, keeping
/// regorus's `http` and `jsonschema` features out of the closure — and the doc
/// comment names *this test* as what keeps it from drifting. Until CLOUD-831 the
/// name resolved to nothing (CLOUD-589's class, on the highest-consequence claim
/// in the crate).
///
/// A test over the manifest TEXT would not do: **Cargo unifies features across
/// the graph**, so a second workspace crate or any dependency taking regorus with
/// default features unions `http` back on with no edit to the line that states
/// the pin. This asks the evaluator instead, which stays true under unification.
///
/// # Shown able to fail (CLOUD-418)
///
/// `--features probe-evaluator-io` turns regorus's `http` feature on and the
/// `http.send` assertion below goes red. That is the whole point of the test and
/// it is in the diff rather than asserted: `tests/evaluator-io.bats` builds it
/// both ways and refuses a build that stays green with the feature on. Under the
/// shipped feature set the probe is off and costs the closure nothing —
/// `regorus`'s `http` feature is `[]`, gating only the builtin's registration,
/// so `Cargo.lock` is byte-identical either way.
///
/// The `jsonschema` half below gets no feature-flipped twin, and the manifest
/// records why: `regorus/jsonschema` admits a second copy of a crate this
/// workspace already resolves at a different major, which is not free. One
/// exercised discriminator is what CLOUD-418 asks for; the jsonschema assertion
/// still pins the shipped set.
///
/// The `count` control is the other half of discriminating: it proves the
/// harness can make a module deny at all, so a `CouldNotLook` above is the
/// builtin's absence rather than a broken fixture.
#[test]
#[cfg_attr(
    feature = "probe-evaluator-io",
    ignore = "the probe build turns the IO features ON; tests/evaluator-io.bats \
              runs this case there and requires it to FAIL"
)]
fn no_evaluator_feature_admits_io() {
    let root = scratch("evaluator-io");

    // The control first. If this does not deny, nothing below discriminates.
    let included = module_file(&root, "included.rego", REACHES_AN_INCLUDED_BUILTIN);
    let modules = policy::load(&root, &[row("policy-included", &included)], None)
        .expect("a module over an in-closure builtin loads");
    assert_eq!(
        policy::deny(&modules[0], "{}"),
        Look::Is(vec![
            "the module called a builtin that is in the closure".to_owned()
        ]),
        "the control must deny, or an absent-builtin verdict below is unattributable"
    );

    // `http.send` — the network. Whether regorus refuses this at compile or at
    // the smoke query, `load` turns it into a config error (exit 1) and the
    // module never decides a call. Either way it DOES NOT ANSWER, which is the
    // property the doc claims; both arms are accepted here and the assertion is
    // over the outcome that matters.
    let network = module_file(&root, "network.rego", REACHES_THE_NETWORK);
    match policy::load(&root, &[row("policy-network", &network)], None) {
        Err(refused) => {
            let text = format!("{refused}");
            assert!(
                text.contains("network.rego"),
                "the refusal points at the module: {text}"
            );
        }
        Ok(loaded) => {
            let answer = policy::deny(&loaded[0], "{}");
            assert!(
                answer.could_not_look(),
                "a module invoking `http.send` must not produce a deny — it must \
                 not be able to run at all. `http` has entered the evaluator's \
                 closure, which is the drift `Cargo.toml`'s feature list exists \
                 to prevent and `evaluator-closure-check` is the other half of."
            );
        }
    }

    // `json.verify_schema` — the `jsonschema` builtin, the second name the
    // manifest pins out. Same shape: a test covering one of the two would report
    // the pin held while half of it drifted.
    let schema = module_file(&root, "schema.rego", REACHES_JSONSCHEMA);
    match policy::load(&root, &[row("policy-schema", &schema)], None) {
        Err(refused) => {
            let text = format!("{refused}");
            assert!(
                text.contains("schema.rego"),
                "the refusal points at the module: {text}"
            );
        }
        Ok(loaded) => {
            let answer = policy::deny(&loaded[0], "{}");
            assert!(
                answer.could_not_look(),
                "a module invoking the `jsonschema` builtin must not answer; \
                 `jsonschema` has entered the evaluator's closure"
            );
        }
    }
}
