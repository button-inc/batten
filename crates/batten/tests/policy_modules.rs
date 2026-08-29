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

mod common;

use std::fs;
use std::path::Path;

use batten::facts::Look;
use batten::policy::{self, Violation};
use batten::rules::Rule;
use batten::severity::RuleSeverity;

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

/// The denial an unattributed bare-string `deny` produces.
///
/// `rule: None` is the whole of CLOUD-832's back-compatibility claim: a module
/// written before the `violation` shape existed yields exactly this, and is
/// attributed to the registering row as it always was. Spelled once here so the
/// cases below read as assertions about behaviour rather than about a struct.
fn unattributed(verdict: &str) -> Violation {
    Violation {
        rule: None,
        verdict: verdict.to_owned(),
        subjects: Vec::new(),
    }
}

/// The denial an attributed `violation` produces.
fn attributed(rule: &str, verdict: &str) -> Violation {
    Violation {
        rule: Some(rule.to_owned()),
        verdict: verdict.to_owned(),
        subjects: Vec::new(),
    }
}

/// The vocabulary the modules under `root` need, derived from the modules.
///
/// **Derived rather than listed, because registry equality runs in both
/// directions.** A shared table naming every token this file's fixtures use is
/// dead vocabulary for all but one of them, and `load` refuses that — correctly.
/// Reading the tokens off the modules the fixture just wrote declares exactly
/// what it raises, which is what a consumer's own `batten.toml` does.
///
/// Leaked, and stated: [`policy::Vocabulary`] borrows — that is what keeps it a
/// parameter rather than a clone on the mediated path — and the alternative is
/// naming a `Vec` at every one of this file's twenty load sites. A test binary
/// is a short-lived process and the table is tens of entries.
fn fixtures(root: &Path) -> policy::Vocabulary<'static> {
    let table: &'static [batten::verdict::DeclaredVerdict] =
        Box::leak(common::verdicts_in(root).into_boxed_slice());
    policy::Vocabulary {
        patterns: &[],
        verdicts: table,
        recorders: &[],
    }
}

/// The same table, plus the pattern rows a fixture declares.
fn fixtures_with(
    root: &Path,
    patterns: &'static [batten::pattern::NamedPattern],
) -> policy::Vocabulary<'static> {
    policy::Vocabulary {
        patterns,
        verdicts: fixtures(root).verdicts,
        recorders: &[],
    }
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

deny contains "V-WRITE-REFUSED" if {
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

deny contains "V-REACHED-THE-NETWORK" if {
    http.send({"method": "get", "url": "http://example.invalid/"})
}
"#;

/// The same shape over the `jsonschema` builtin, which the same feature line
/// keeps out. Two builtins rather than one because the manifest names two, and a
/// test covering half the pin would report the pin held while half of it drifted.
const REACHES_JSONSCHEMA: &str = r#"
package batten

import rego.v1

deny contains "V-VALIDATED-A-SCHEMA" if {
    json.verify_schema({"type": "object"})
}
"#;

/// Two predicates in one module, denying under distinct ids (CLOUD-832).
///
/// This is the shape the retirement campaign needs and the shape the engine
/// could not express: before the `violation` set existed, both of these would
/// have reported under the REGISTERING ROW's id, so a finding named the bundle
/// rather than the gate — and `mise run mutant` would have had one id and no
/// per-gate mutation to declare.
const TWO_PREDICATES: &str = r#"
package batten

import rego.v1

rules contains "no-stray-artifact"
rules contains "no-empty-fixture"

violation contains {"rule": "no-stray-artifact", "verdict": "V-STRAY-ARTIFACT"} if {
    input.call.operation == "write"
}

violation contains {"rule": "no-empty-fixture", "verdict": "V-EMPTY-FIXTURE"} if {
    input.call.operation == "write"
}
"#;

/// A module raising an id it never published.
///
/// Refused at load rather than at the gate: a denial this engine cannot
/// attribute is one it cannot honestly report, and both alternatives are wrong —
/// reporting it under the row id silently re-flattens the attribution CLOUD-832
/// exists to add, and dropping it turns a real refusal into a pass.
const UNDECLARED_ID: &str = r#"
package batten

import rego.v1

rules contains "declared-and-unused"

violation contains {"rule": "never-declared", "verdict": "V-NEVER-DECLARED"} if {
    true
}
"#;

/// Two modules that both publish `shared-id`.
///
/// The collision refusal is what keeps a FOLDER from becoming a merge: there is
/// no precedence to resolve, because a collision is refused outright rather than
/// silently won by whichever module loaded last.
const DECLARES_SHARED_ID_A: &str = r#"
package batten

import rego.v1

rules contains "shared-id"

violation contains {"rule": "shared-id", "verdict": "V-FROM-MODULE-A"} if {
    input.call.operation == "write"
}
"#;

const DECLARES_SHARED_ID_B: &str = r#"
package batten

import rego.v1

rules contains "shared-id"

violation contains {"rule": "shared-id", "verdict": "V-FROM-MODULE-B"} if {
    input.call.operation == "read"
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

deny contains "V-BUILTIN-IN-THE-CLOSURE" if {
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
    let bundles = policy::load(
        &root,
        &[row("policy-writes", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");
    assert_eq!(bundles.len(), 1);

    let denied = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#);
    assert_eq!(
        denied,
        Look::Is(vec![unattributed("V-WRITE-REFUSED")]),
        "the module decided over the fact it was handed"
    );

    // The same module, a fact it does not match: an answer, and the answer is
    // "no denials". Distinct from could-not-look, which the next test pins.
    let allowed = policy::deny(&bundles[0], r#"{"call":{"operation":"read"}}"#);
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
    let bundles = policy::load(
        &root,
        &[row("policy-writes", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");

    let answer = policy::deny(&bundles[0], "{not json");
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
    let err = policy::load(
        &root,
        &[row("policy-cyclic", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
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
    let err = policy::load(
        &root,
        &[row("policy-absent", "nowhere.rego")],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
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
    let err = policy::load(
        &root,
        &[row("first", &path), row("second", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("one module, two registrations");
    assert!(format!("{err}").contains("already registers"));
}

/// A pattern written inline, which is what a bash translation reaches for.
const INLINE_REGEX: &str = r#"
package batten

import rego.v1

deny contains "V-NAMES-A-TRACKER-KEY" if {
	regex.match(`TEAM-[0-9]+`, input.call.command)
}
"#;

/// The same predicate against a declared pattern — the sanctioned form.
const DECLARED_REGEX: &str = r#"
package batten

import rego.v1

deny contains "V-NAMES-A-TRACKER-KEY" if {
	regex.match(data.batten.patterns["tracker-key"], input.call.command)
}
"#;

/// A literal smuggled past a direct-parameter check by building it up.
const SMUGGLED_REGEX: &str = r#"
package batten

import rego.v1

deny contains "V-NAMES-A-TRACKER-KEY" if {
	regex.match(concat("", ["CLOUD", "-[0-9]+"]), input.call.command)
}
"#;

fn tracker_key() -> batten::pattern::NamedPattern {
    batten::pattern::NamedPattern {
        id: String::from("tracker-key"),
        regex: String::from("TEAM-[0-9]+"),
    }
}

#[test]
fn a_regex_written_inline_is_refused_and_a_declared_one_decides() {
    // THE LEVER IS COST, NOT PROHIBITION. "Do not regex things that are not
    // regular" cannot be a gate — that is a judgement, and non-negotiable rule 3
    // says a gate resolves to a command and an exit code over an object it
    // decides. Where a pattern LIVES is decidable, so a regex costs an id and a
    // config row while the same question over a parsed document costs a field
    // access. The cheap path becomes the correct one without anyone reasoning
    // about regularity.
    let root = scratch("inline-regex");
    let inline = module_file(&root, "inline.rego", INLINE_REGEX);
    let err = policy::load(
        &root,
        &[row("keys", &inline)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("a regex written inline must not load");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("TEAM-[0-9]+"),
        "the refusal names the expression, a declaration and not content: {rendered}"
    );
    assert!(
        rendered.contains("[[pattern]]"),
        "the refusal names its remedy (CLOUD-437): {rendered}"
    );

    // THE DISCRIMINATING HALF, and it is two claims rather than one. A check
    // that refused every `regex.*` call would satisfy the assertions above and
    // be useless, so the declared form must LOAD — and it must also DECIDE,
    // because a module whose pattern resolved to undefined would load clean and
    // gate nothing, which is CLOUD-251's vacuous pass with a regex in it. So
    // this asserts the deny, not merely the load.
    let declared = module_file(&root, "declared.rego", DECLARED_REGEX);
    let bundles = policy::load(
        &root,
        &[row("keys", &declared)],
        fixtures_with(&root, Box::leak(Box::new([tracker_key()]))),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("a declared pattern is the sanctioned form");
    let doc = r#"{"call":{"command":"git commit -m TEAM-885"}}"#;
    let Look::Is(violations) = policy::deny(&bundles[0], doc) else {
        panic!("the declared pattern must reach the module through `data`");
    };
    assert_eq!(
        violations,
        vec![unattributed("V-NAMES-A-TRACKER-KEY")],
        "the projected table decides, rather than resolving to undefined"
    );

    // THE SMUGGLE. A check reading only direct parameters would wave this
    // through; recursing into each parameter is what closes it.
    let smuggled = module_file(&root, "smuggled.rego", SMUGGLED_REGEX);
    let err = policy::load(
        &root,
        &[row("keys", &smuggled)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("a literal assembled inside the call is still a literal");
    assert!(
        format!("{err}").contains("[[pattern]]"),
        "the smuggled form gets the same refusal: {err}"
    );
}

#[test]
fn a_module_holds_no_source_and_cannot_leak_one_through_debug() {
    // Rule 4 is structural here rather than careful: `Module` has no `source`
    // field, so there is nothing for a derived `Debug` to render even if someone
    // re-derived it. This asserts the rendering, which is the reachable half.
    let root = scratch("pointer");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let bundles = policy::load(
        &root,
        &[row("policy-writes", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");
    let rendered = format!("{:?}", bundles[0]);
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
    let bundles = policy::load(
        &root,
        &[row("policy-included", &included)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("a module over an in-closure builtin loads");
    assert_eq!(
        policy::deny(&bundles[0], "{}"),
        Look::Is(vec![unattributed("V-BUILTIN-IN-THE-CLOSURE")]),
        "the control must deny, or an absent-builtin verdict below is unattributable"
    );

    // `http.send` — the network. Whether regorus refuses this at compile or at
    // the smoke query, `load` turns it into a config error (exit 1) and the
    // module never decides a call. Either way it DOES NOT ANSWER, which is the
    // property the doc claims; both arms are accepted here and the assertion is
    // over the outcome that matters.
    let network = module_file(&root, "network.rego", REACHES_THE_NETWORK);
    match policy::load(
        &root,
        &[row("policy-network", &network)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    ) {
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
    match policy::load(
        &root,
        &[row("policy-schema", &schema)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    ) {
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

/// One module, two predicates, two ids — the capability CLOUD-832 exists to add.
///
/// **Shown able to fail**: a single-id implementation reds this, because both
/// denials would carry the registering row's `policy-two` rather than their own.
/// That is not a hypothetical — it is exactly what `policy_rules` did before this
/// row, and the reason a 79-predicate bundle would have reported every finding
/// under one pointer.
#[test]
fn one_module_carries_two_predicates_that_deny_under_their_own_ids() {
    let root = scratch("two-predicates");
    let path = module_file(&root, "two.rego", TWO_PREDICATES);
    let bundles = policy::load(
        &root,
        &[row("policy-two", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");

    let denied = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#);
    let Look::Is(violations) = denied else {
        panic!("the module answered, so this must not be could-not-look");
    };

    // Both fired, and each is reported under ITS OWN id. Sorted before
    // comparison because a Rego set has no declaration order to preserve —
    // asserting a sequence here would pin an implementation detail of the
    // evaluator rather than the property.
    let mut pointers: Vec<&str> = violations
        .iter()
        .map(|violation| bundles[0].attribute(violation))
        .collect();
    pointers.sort_unstable();
    assert_eq!(
        pointers,
        vec!["no-empty-fixture", "no-stray-artifact"],
        "each predicate names itself; a single-id implementation reports \
         `policy-two` twice here"
    );

    // And neither is the row id, stated separately because the assertion above
    // would also pass on an implementation that invented ids from the messages.
    assert!(
        !pointers.contains(&"policy-two"),
        "the registering row is not the pointer when a predicate named itself"
    );

    // The whole value, not just the resolved id: an implementation that carried
    // the id but dropped the module's own message would pass everything above,
    // and a refusal with no text tells its reader nothing.
    let mut whole = violations.clone();
    whole.sort_by(|a, b| a.rule.cmp(&b.rule));
    assert_eq!(
        whole,
        vec![
            attributed("no-empty-fixture", "V-EMPTY-FIXTURE"),
            attributed("no-stray-artifact", "V-STRAY-ARTIFACT"),
        ]
    );
}

/// The bare-string path, unchanged — CLOUD-832's back-compatibility claim.
///
/// A module using only `deny` publishes no ids, produces `rule: None`, and is
/// attributed to the registering row exactly as it was before this change. This
/// is what makes the row additive rather than a break.
#[test]
fn a_bare_string_deny_still_reports_under_the_registering_row() {
    let root = scratch("bare-string");
    let path = module_file(&root, "writes.rego", DENIES_WRITES);
    let bundles = policy::load(
        &root,
        &[row("policy-writes", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");

    assert!(
        bundles[0].declared().is_empty(),
        "a module with no `rules` rule publishes nothing, and that is not an error"
    );

    let Look::Is(violations) = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#)
    else {
        panic!("the module answered");
    };
    assert_eq!(violations, vec![unattributed("V-WRITE-REFUSED")]);
    assert_eq!(
        bundles[0].attribute(&violations[0]),
        "policy-writes",
        "an unattributed denial falls back to the row, which is the pre-CLOUD-832 behaviour"
    );
}

/// A `violation` naming an id the module never published is a CONFIG error.
///
/// At load, with exit `1` — never a surprise at the gate. Same posture as the
/// smoke query the loader already drives: a fault belongs where `config lint`
/// can see it, not at the moment a tool call is adjudicated.
#[test]
fn an_undeclared_violation_id_is_refused_at_load() {
    let root = scratch("undeclared");
    let path = module_file(&root, "undeclared.rego", UNDECLARED_ID);
    let err = policy::load(
        &root,
        &[row("policy-undeclared", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("an id the module does not publish cannot be attributed");
    let text = format!("{err}");
    assert!(
        text.contains("never-declared"),
        "the refusal names the offending id: {text}"
    );
    assert!(
        text.contains("undeclared.rego"),
        "and the module it came from: {text}"
    );
    // Pointer-only (rule 4): the ids and the path, never the predicate body.
    assert!(
        !text.contains("raised without being published"),
        "no byte of the module's own text reaches the refusal: {text}"
    );
}

/// Two modules declaring one id are refused at load, across the whole set.
///
/// **This is the clause that makes enumerating modules inside an enabled bundle
/// safe.** Nothing merges: a collision has no precedence to resolve, so it is
/// refused rather than silently won by whichever loaded last. The same check
/// reaches across the vendored/in-repo boundary for free, because a preset is
/// just another module with a declared id set.
#[test]
fn two_modules_declaring_one_id_are_refused_at_load() {
    let root = scratch("collision");
    let first = module_file(&root, "collide-a.rego", DECLARES_SHARED_ID_A);
    let second = module_file(&root, "collide-b.rego", DECLARES_SHARED_ID_B);
    let err = policy::load(
        &root,
        &[row("policy-a", &first), row("policy-b", &second)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("one id, two publishers");
    let text = format!("{err}");
    assert!(
        text.contains("shared-id"),
        "the refusal names the id: {text}"
    );
    // BOTH sides, which is the difference between a pointer and a complaint: a
    // reader has to open two files, and a message naming one of them sends them
    // to whichever the loader happened to reach second.
    assert!(
        text.contains("collide-a.rego") && text.contains("collide-b.rego"),
        "and both modules that publish it: {text}"
    );
}

/// A waiver keys off the predicate, not the registering row (CLOUD-832 §7 (b)).
///
/// **The load-bearing case**, and the one a row-keyed implementation passes only
/// by accident. `waiver::apply` matches on a finding's `rule` field, so this
/// asserts over the value `Module::attribute` resolves — the same value that
/// reaches `Refusal::new` on the mediated path and a `Finding` on the tree.
/// Suppressing one predicate must leave its sibling standing; an implementation
/// keying on the row id suppresses both or neither.
#[test]
fn a_waiver_over_one_predicate_does_not_suppress_its_sibling() {
    let root = scratch("waiver-sibling");
    let path = module_file(&root, "two.rego", TWO_PREDICATES);
    let bundles = policy::load(
        &root,
        &[row("policy-two", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");

    let Look::Is(violations) = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#)
    else {
        panic!("the module answered");
    };
    let ids: Vec<&str> = violations
        .iter()
        .map(|violation| bundles[0].attribute(violation))
        .collect();

    // A waiver names ONE predicate. The other must be untouched.
    let waived = "no-stray-artifact";
    let suppressed: Vec<&&str> = ids.iter().filter(|id| **id == waived).collect();
    let surviving: Vec<&&str> = ids.iter().filter(|id| **id != waived).collect();
    assert_eq!(
        suppressed.len(),
        1,
        "exactly one predicate is named by the waiver"
    );
    assert_eq!(
        surviving,
        vec![&"no-empty-fixture"],
        "its sibling is a different id and survives; a row-keyed implementation \
         would have both reading `policy-two` and would suppress the pair"
    );
}

/// A denial this engine cannot attribute is could-not-look, never a pass.
///
/// `load` refuses an undeclared id for every violation the empty document
/// reaches. This is the residue: an id raised only on an input load could not
/// exercise. Reporting it under the row would re-flatten attribution; dropping it
/// would turn a real refusal into a pass. Neither, so: could-not-look.
#[test]
fn an_undeclared_id_met_at_evaluation_is_could_not_look() {
    let root = scratch("undeclared-late");
    // Declared at load-time silence — the violation's body is false on `{}`, so
    // `load` cannot see it — and undeclared when the fact arrives.
    let source = r#"
package batten

import rego.v1

rules contains "declared-and-unused"

violation contains {"rule": "only-on-a-write", "verdict": "V-REACHED-LATER"} if {
    input.call.operation == "write"
}
"#;
    let path = module_file(&root, "late.rego", source);
    let bundles = policy::load(
        &root,
        &[row("policy-late", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load cannot reach this violation, so it loads");

    let answer = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#);
    assert!(
        answer.could_not_look(),
        "an unattributable denial is not an answer this gate can read"
    );
    assert_ne!(
        answer,
        Look::Is(Vec::new()),
        "and it is certainly not a pass"
    );
}

/// A `predicate_severity` key naming nothing is refused at load.
///
/// The dead-waiver shape (CLOUD-208) applied to severity: a key that parses and
/// does nothing leaves a reader believing a predicate is tuned when it is not.
/// This is the only place that sees both the row and the module's declared set —
/// `Rule::validate` has the row and not the module — so it is the only place the
/// check can live.
#[test]
fn a_predicate_severity_naming_an_unpublished_id_is_refused_at_load() {
    let root = scratch("severity-dead-key");
    let path = module_file(&root, "two.rego", TWO_PREDICATES);
    let mut rule = row("policy-two", &path);
    rule.predicate_severity = Some(
        [("no-such-predicate".to_owned(), RuleSeverity::Warn)]
            .into_iter()
            .collect(),
    );
    let err = policy::load(
        &root,
        &[rule],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect_err("a severity aimed at an id nothing publishes decides nothing");
    let text = format!("{err}");
    assert!(text.contains("no-such-predicate"), "names the key: {text}");
    assert!(text.contains("two.rego"), "and the module: {text}");
}

/// Severity is resolved per predicate, falling back to the row (CLOUD-832).
///
/// **The discriminating pair.** `no-stray-artifact` is tuned down while its
/// sibling keeps the row's `deny`, so an implementation that read only
/// `Rule::severity` returns `deny` for both and reds the first assertion; one
/// that read only the table returns nothing for the sibling and reds the second.
/// Neither half alone proves the fallback works.
#[test]
fn severity_resolves_per_predicate_and_falls_back_to_the_row() {
    let root = scratch("severity-per-predicate");
    let path = module_file(&root, "two.rego", TWO_PREDICATES);
    let mut rule = row("policy-two", &path);
    rule.predicate_severity = Some(
        [("no-stray-artifact".to_owned(), RuleSeverity::Warn)]
            .into_iter()
            .collect(),
    );
    let bundles = policy::load(
        &root,
        &[rule.clone()],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("load");

    assert_eq!(
        rule.severity_for(Some("no-stray-artifact")),
        RuleSeverity::Warn,
        "the predicate the table names carries its own severity"
    );
    assert_eq!(
        rule.severity_for(Some("no-empty-fixture")),
        RuleSeverity::Deny,
        "its sibling, unnamed, inherits the row — one row could not carry both \
         before this, which is the `severity flattens` half of CLOUD-832"
    );
    assert_eq!(
        rule.severity_for(None),
        RuleSeverity::Deny,
        "and an unattributed denial answers the row, which is the pre-CLOUD-832 \
         behaviour reached without a special case"
    );

    // The module still loads and still denies: tuning a severity changes how
    // loudly a predicate refuses, never whether it does. §8's raise-only
    // invariant is untouched because a module has no spelling for an allow.
    let Look::Is(violations) = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#)
    else {
        panic!("the module answered");
    };
    assert_eq!(violations.len(), 2);
}

/// A module in a SUB-PACKAGE is reached, and denies (CLOUD-837).
///
/// **Red on `main` before this row**, and in the worst possible way: the query
/// was pinned at `data.batten.deny`, so `package batten.git` loaded clean,
/// smoke-queried clean, and was then silently never reached. A bundle of 79
/// predicates had one flat namespace available to it and no diagnostic saying so.
///
/// Asserts it **denies**, not merely that it loads — a test asserting the latter
/// passes on a module that answers nothing, which is exactly the state being
/// fixed.
#[test]
fn a_sub_package_module_is_reached_and_denies() {
    let root = scratch("sub-package");
    let source = r#"
package batten.git

import rego.v1

rules contains "no-force-push"

violation contains {"rule": "no-force-push", "verdict": "V-FORCE-PUSH-AT-TRUNK"} if {
    input.call.operation == "write"
}
"#;
    let path = module_file(&root, "git.rego", source);
    let bundles = policy::load(
        &root,
        &[row("policy-git", &path)],
        fixtures(&root),
        policy::ModuleChecks::Run,
        None,
    )
    .expect("a sub-package module loads");

    assert!(
        bundles[0].declared().contains("no-force-push"),
        "the ids a sub-package publishes are reached too, not just its denials"
    );

    let Look::Is(violations) = policy::deny(&bundles[0], r#"{"call":{"operation":"write"}}"#)
    else {
        panic!("the module answered");
    };
    assert_eq!(
        violations,
        vec![attributed("no-force-push", "V-FORCE-PUSH-AT-TRUNK")],
        "the package prefix is `batten` and the RULE NAMES are what is fixed; \
         pinning the whole path leaves this module silently unreachable"
    );
}

/// A helper defined in one module of a bundle is callable from another.
///
/// **The discriminator, and the reason CLOUD-837 exists.** Under per-module
/// isolation this cannot even evaluate — module B's engine has never seen module
/// A — so two predicates needing the same path normalisation had to define it
/// twice. At 79 predicates that is verbatim the defect `policy.rs`'s own doc
/// opens by decrying, rebuilt in a second language. Measured on this branch
/// before the split: `error: could not find function shared.is_protected`.
///
/// Drives `policy::compile` rather than `policy::load` deliberately. The
/// property is about the ENGINE — N modules, one evaluator — and a row cannot
/// name a folder until CLOUD-833 widens the column. Testing through `load` would
/// therefore assert the config surface's current shape rather than the
/// composition this row lands, and would have to be rewritten the moment it
/// widens.
#[test]
fn a_helper_in_one_module_is_callable_from_another_in_the_same_bundle() {
    let helper = r#"
package batten.shared

import rego.v1

is_protected(path) if {
    startswith(path, "policy/")
}
"#;
    let consumer = r#"
package batten

import rego.v1

import data.batten.shared

rules contains "no-protected-write"

violation contains {"rule": "no-protected-write", "verdict": "V-PROTECTED-MUTATION"} if {
    shared.is_protected(input.call.path)
}
"#;
    let bundle = policy::compile(
        "policy-repo",
        &[
            ("shared.rego".to_owned(), helper.to_owned()),
            ("consumer.rego".to_owned(), consumer.to_owned()),
        ],
        &serde_json::json!({}),
    )
    .expect("two modules compose into one rule set");

    assert_eq!(bundle.modules().len(), 2, "both modules are in the bundle");

    // The helper actually RUNS from the other module — asserting it merely
    // compiled would pass on a bundle whose consumer never reaches it.
    let Look::Is(violations) = policy::deny(&bundle, r#"{"call":{"path":"policy/git.rego"}}"#)
    else {
        panic!("the bundle answered");
    };
    assert_eq!(
        violations,
        vec![attributed("no-protected-write", "V-PROTECTED-MUTATION")],
        "module B called module A's helper; under per-module isolation this \
         evaluates to `could not find function shared.is_protected`"
    );

    // And the negative, so the case discriminates rather than asserting that
    // something — anything — denied: a path the helper does not match is silent.
    assert_eq!(
        policy::deny(&bundle, r#"{"call":{"path":"crates/batten/src/lib.rs"}}"#),
        Look::Is(Vec::new()),
        "the helper decides, and it decides both ways"
    );
}

/// A bundle of N modules builds ONE engine, asserted by count (CLOUD-837).
///
/// A **counter, not a clock**: engine construction is cheap enough that a
/// per-module implementation and a per-bundle one are indistinguishable on a
/// wall clock, which is how the N-linear cost went unmeasured for as long as it
/// did. Restoring `Engine::new()` to the per-module loop turns this red.
///
/// This case lives in its own test binary, `tests/policy_engine_count.rs`: the
/// counter is process-global, and cargo runs the tests inside one binary
/// concurrently, so a delta measured here would race every other case that
/// compiles a bundle.
#[test]
fn a_bundle_of_n_modules_is_one_engine_by_construction() {
    // The type-level half of the same claim, which is the part that cannot
    // regress silently: `Bundle` holds one engine, not a collection of them, so
    // a per-module implementation could not be written without changing the
    // struct. The count in `policy_engine_count.rs` is what catches an engine
    // built somewhere else and thrown away.
    let bundle = policy::compile(
        "policy-many",
        &[
            (
                "a.rego".to_owned(),
                "package batten.a\nimport rego.v1\nrules contains \"a\"\n".to_owned(),
            ),
            (
                "b.rego".to_owned(),
                "package batten.b\nimport rego.v1\nrules contains \"b\"\n".to_owned(),
            ),
            (
                "c.rego".to_owned(),
                "package batten.c\nimport rego.v1\nrules contains \"c\"\n".to_owned(),
            ),
        ],
        &serde_json::json!({}),
    )
    .expect("three modules, one bundle");

    assert_eq!(bundle.modules().len(), 3);
    assert_eq!(
        bundle
            .declared()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["a", "b", "c"],
        "and every sub-package's published ids are reached, not just the first"
    );
}
