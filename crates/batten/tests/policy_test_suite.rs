//! `batten policy test` — the module test surface (CLOUD-835).
//!
//! `policy_modules.rs` next door exercises the **evaluator**. These exercise a
//! **module**: a consumer writes a predicate and a `test_` rule beside it, and
//! this is what says whether the predicate decides correctly.
//!
//! # Every case here is a discriminator, not a demonstration
//!
//! CLOUD-418's obligation: a test that cannot go red is coverage theatre, and a
//! test surface that ships without its own discriminators would be that failure
//! at one remove. So each property is asserted in **both directions** — the
//! wrong module turns the verb red and the right one does not, the unexercised
//! predicate is reported and exercising it clears the report — because only the
//! pair establishes that the term is deciding anything.
//!
//! # The two traps these pin
//!
//! **An undefined test is a failure, not an absence.** An unsatisfied Rego body
//! evaluates to *undefined*, which is how a test ordinarily fails. Enumerating a
//! suite from the `data` document therefore cannot see a failing test at all —
//! it is simply missing, indistinguishable from a test nobody wrote. That is
//! CLOUD-251's vacuous pass wearing a test harness, and
//! `an_undefined_test_fails_rather_than_vanishing` is what stops the discovery
//! walk being "simplified" back into a document read.
//!
//! **A predicate is exercised by being ENTERED, never by being named.** The
//! tempting shortcut is a convention — `test_<id>` covers `<id>` — which is
//! satisfied by a test that never touches the predicate. `the_declaration_rule_
//! does_not_count_as_exercising_a_predicate` is the case that would pass under
//! any naming scheme and fails here.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::Path;

use batten::facts::Look;
use batten::policy::{self, Suite};
use batten::rules::Rule;

mod common;

use common::{Fixture, run, stdout};

/// A policy row registering `module`, built the way a real config builds one.
///
/// Deserialized rather than struct-literalled, for `policy_modules.rs`'s reason:
/// `Rule` carries `deny_unknown_fields`, so a row the loader would refuse cannot
/// be smuggled into a test by hand.
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

/// Compile `source` as a single-module bundle and run its suite.
fn suite_of(source: &str) -> Suite {
    let bundle = policy::compile(
        "fixture",
        &[("fixture.rego".to_owned(), source.to_owned())],
        &serde_json::json!({}),
    )
    .expect("the fixture compiles");
    match policy::test(&bundle, "{}").expect("the suite runs") {
        Look::Is(suite) => suite,
        Look::IsNot | Look::CouldNotLook => panic!("the suite did not run"),
    }
}

/// The test names a suite reports under one heading, for readable assertions.
fn names(ids: &[policy::TestId]) -> Vec<&str> {
    ids.iter().map(|id| id.name.as_str()).collect()
}

/// A module whose predicate is CORRECT: it fires on `--force` and not on
/// `--force-with-lease`, and its test asserts exactly that.
const CORRECT: &str = r#"
package batten.probe

import rego.v1

rules contains "no-force-push"

violation contains {
	"rule": "no-force-push",
	"msg": "a force push rewrites a shared branch",
} if {
	words := split(input.call.command, " ")
	"--force" in words
}

test_no_force_push if {
	some v in violation with input as {"call": {"command": "git push --force"}}
	v.rule == "no-force-push"
	count(violation) == 0 with input as {"call": {"command": "git push --force-with-lease"}}
}
"#;

/// The same module with the predicate DELIBERATELY WRONG — it matches the
/// sanctioned `--force-with-lease` too, which is the mistake the preset's own
/// comment says a consumer must not make. The test is unchanged.
const WRONG: &str = r#"
package batten.probe

import rego.v1

rules contains "no-force-push"

violation contains {
	"rule": "no-force-push",
	"msg": "a force push rewrites a shared branch",
} if {
	contains(input.call.command, "--force")
}

test_no_force_push if {
	some v in violation with input as {"call": {"command": "git push --force"}}
	v.rule == "no-force-push"
	count(violation) == 0 with input as {"call": {"command": "git push --force-with-lease"}}
}
"#;

// ─── (a) a wrong predicate turns the verb red, a right one does not ──────────

#[test]
fn a_correct_predicate_passes_its_own_test() {
    let suite = suite_of(CORRECT);
    assert_eq!(names(&suite.passed), ["test_no_force_push"]);
    assert!(suite.failed.is_empty(), "{:?}", suite.failed);
    assert!(!suite.is_violation());
}

#[test]
fn a_deliberately_wrong_predicate_turns_it_red() {
    // THE DISCRIMINATOR for the case above. Same test rule, same fixtures, one
    // changed predicate — so a green run over `CORRECT` is evidence the suite
    // decides rather than evidence it ran.
    let suite = suite_of(WRONG);
    assert_eq!(names(&suite.failed), ["test_no_force_push"]);
    assert!(suite.passed.is_empty(), "{:?}", suite.passed);
    assert!(suite.is_violation());
}

// ─── an undefined test is a failure with a name attached ─────────────────────

#[test]
fn an_undefined_test_fails_rather_than_vanishing() {
    // The case the AST discovery exists for. `test_never_holds`'s body is
    // unsatisfiable, so the rule evaluates to UNDEFINED and is absent from the
    // `data` document entirely — a suite enumerated by reading that document
    // would report one passing test and nothing else, which is exactly backwards.
    let suite = suite_of(
        r#"
package batten.probe

import rego.v1

rules contains "always"

violation contains {"rule": "always", "msg": "m"} if {
	input.call.command == "x"
}

test_holds if {
	some v in violation with input as {"call": {"command": "x"}}
	v.rule == "always"
}

test_never_holds if {
	false
}
"#,
    );
    assert_eq!(names(&suite.passed), ["test_holds"]);
    assert_eq!(names(&suite.failed), ["test_never_holds"]);
    assert!(suite.is_violation());
}

// ─── (b) an unexercised predicate is reported, not green ─────────────────────

/// Two predicates, one test. `unswept` is exercised; `never-tested` is declared,
/// raised by a real rule, and nothing enters it.
const HALF_TESTED: &str = r#"
package batten.probe

import rego.v1

rules contains "tested"

rules contains "never-tested"

violation contains {"rule": "tested", "msg": "m"} if {
	input.call.command == "a"
}

violation contains {"rule": "never-tested", "msg": "m"} if {
	input.call.command == "b"
}

test_tested if {
	some v in violation with input as {"call": {"command": "a"}}
	v.rule == "tested"
}
"#;

#[test]
fn a_predicate_no_test_exercises_is_reported_though_every_test_passes() {
    // THIS IS THE CASE THAT CHOSE THE MEASUREMENT. Referencing `violation`
    // evaluates every rule contributing to it, so `never-tested`'s BODY is
    // covered here exactly as `tested`'s is — an implementation reading
    // coverage over the whole rule reports this module fully exercised, which
    // is a false green in the term whose entire job is refusing false greens.
    // Reading the HEAD line instead separates them; see
    // `policy::DescribedRule::head_line`.
    let suite = suite_of(HALF_TESTED);
    assert!(suite.failed.is_empty(), "{:?}", suite.failed);
    assert_eq!(suite.unexercised, ["never-tested"]);
    // REPORTED, NOT GREEN (§7(b)). This is the assertion that makes the coverage
    // term load-bearing: without it the term is a line in a report nobody's
    // exit code depends on.
    assert!(suite.is_violation());
}

#[test]
fn exercising_the_second_predicate_clears_the_report() {
    // THE DISCRIMINATOR. Same module plus one test that actually makes
    // `never-tested` fire, so the term is shown to distinguish rather than to
    // fire always.
    let suite = suite_of(&format!(
        "{HALF_TESTED}
test_never_tested if {{
	some v in violation with input as {{\"call\": {{\"command\": \"b\"}}}}
	v.rule == \"never-tested\"
}}
"
    ));
    assert!(suite.unexercised.is_empty(), "{:?}", suite.unexercised);
    assert_eq!(suite.failed.len(), 0);
    assert!(!suite.is_violation());
}

#[test]
fn the_declaration_rule_does_not_count_as_exercising_a_predicate() {
    // THE CASE A NAMING CONVENTION CANNOT CATCH, and the reason `RULES_RULE` is
    // excluded from the literal search. `rules contains "never-tested"` carries
    // the id, and every sweep enters that rule — so counting it would report a
    // predicate as exercised on the strength of its own declaration.
    //
    // The test here is named `test_never_tested`, which is precisely the name a
    // `test_<id>` convention would accept. It touches nothing.
    let suite = suite_of(
        r#"
package batten.probe

import rego.v1

rules contains "never-tested"

violation contains {"rule": "never-tested", "msg": "m"} if {
	input.call.command == "b"
}

test_never_tested if {
	1 == 1
}
"#,
    );
    assert!(suite.failed.is_empty(), "{:?}", suite.failed);
    assert_eq!(
        suite.unexercised,
        ["never-tested"],
        "a test that names a predicate but never enters it must not count as exercising it"
    );
}

// ─── a module with no `test_` rules at all ───────────────────────────────────

#[test]
fn a_module_carrying_no_test_rule_is_reported() {
    let suite = suite_of(
        r#"
package batten.probe

import rego.v1

rules contains "untested"

violation contains {"rule": "untested", "msg": "m"} if {
	input.call.command == "x"
}
"#,
    );
    assert_eq!(suite.untested_modules, ["fixture.rego"]);
    // It does not decide on its own — its predicates already fall out as
    // unexercised, and counting the module again would report one fault twice.
    assert_eq!(suite.unexercised, ["untested"]);
}

#[test]
fn a_module_with_tests_is_not_reported_as_untested() {
    // The discriminator for the term above.
    let suite = suite_of(CORRECT);
    assert!(
        suite.untested_modules.is_empty(),
        "{:?}",
        suite.untested_modules
    );
}

// ─── end to end, over the compiled binary ────────────────────────────────────

/// A fixture repository registering one module.
fn fixture(name: &str, module: &str, scope: &str, documents: &str) -> std::path::PathBuf {
    Fixture::new(name)
        .config(&format!(
            r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "{scope}"
module = "probe.rego"
severity = "deny"
{documents}
"#
        ))
        .file("probe.rego", module)
        .build()
}

/// A `mediated_call` row, which declares no documents.
///
/// The loader REFUSES a tree-scoped policy row carrying no `documents` — "a row
/// declaring none is handed an empty tree and reads as a gate that decides
/// nothing" — which is why the cases below that are about the suite rather than
/// about fixtures use this scope. Their tests supply their own input with
/// `with input as`, OPA and Conftest's own shape.
const CALL: &str = "mediated_call";

/// A `tree` row, which must declare its documents.
const TREE: &str = "tree";

#[test]
fn a_clean_suite_is_exit_zero() {
    let dir = fixture("policy-test-clean", CORRECT, CALL, "");
    let output = run(&dir, &["policy", "test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_failing_test_is_exit_two_naming_the_rule() {
    // §7(c), first half. Asserted SEPARATELY from the fixture fault below, so
    // CLOUD-202's inversion — the shell tasks' `1 = violation` against this
    // contract's `2` — cannot be reintroduced by the port itself.
    let dir = fixture("policy-test-red", WRONG, CALL, "");
    let output = run(&dir, &["policy", "test"]);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("probe test-failed probe.rego test_no_force_push"),
        "{text}"
    );
}

#[test]
fn a_declared_fixture_the_tree_does_not_carry_is_exit_one() {
    // §7(c), second half, and the reason it is a different NUMBER: a suite that
    // could not run has established nothing, and reporting it in the verdict
    // class would say the module was judged and found clean.
    let dir = fixture(
        "policy-test-missing-fixture",
        CORRECT,
        TREE,
        "documents = [\"absent.json\"]",
    );
    let output = run(&dir, &["policy", "test"]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("probe fixture-missing absent.json"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_declared_fixture_the_tree_carries_runs_the_suite() {
    // The discriminator for the case above: the same row with the document
    // present runs to a verdict rather than to the config class.
    let dir = Fixture::new("policy-test-present-fixture")
        .config(
            r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
documents = ["present.json"]
"#,
        )
        .file("present.json", r#"{"ok": true}"#)
        .file("probe.rego", CORRECT)
        .build();
    let output = run(&dir, &["policy", "test"]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn the_json_document_is_byte_stable_and_carries_no_policy_body() {
    let dir = fixture("policy-test-json", CORRECT, CALL, "");
    let first = run(&dir, &["policy", "test", "-J"]);
    let second = run(&dir, &["policy", "test", "-J"]);
    assert_eq!(stdout(&first), stdout(&second), "§6: byte-stable under -J");

    let text = stdout(&first);
    // RULE 4. The AST document this verb parses carries the whole module source
    // in its `source.contents`, and the coverage report carries it again in
    // `File::code`. Neither may reach the emission — a pointer names the module,
    // it never republishes it.
    for payload in [
        "violation contains",
        "import rego.v1",
        "package batten.probe",
    ] {
        assert!(
            !text.contains(payload),
            "the emitted document carries policy source: {payload}"
        );
    }
    assert!(text.contains("\"bundle\": \"probe\""), "{text}");
}

#[test]
fn every_key_is_present_even_when_the_suite_did_not_run() {
    // One shape, always: a document whose keys come and go is unparseable, so
    // the could-not-look path degrades the VALUES and keeps the shape.
    let dir = fixture(
        "policy-test-json-not-run",
        CORRECT,
        TREE,
        "documents = [\"absent.json\"]",
    );
    let output = run(&dir, &["policy", "test", "-J"]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("the document parses");
    let report = parsed.get(0).expect("one report");
    for key in [
        "bundle",
        "looked",
        "missing",
        "passed",
        "failed",
        "unexercised",
        "untested_modules",
    ] {
        assert!(report.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(report.get("looked"), Some(&serde_json::Value::Bool(false)));
}

// ─── the loader still sees these rows the way it always did ──────────────────

#[test]
fn a_registered_module_with_tests_still_loads_and_denies() {
    // `test_` rules are ordinary rules in an ordinary module, so nothing about
    // registration changes. Pinned because the discovery walk reads the same
    // engine `load` built, and a change there that broke `deny` would otherwise
    // only surface at a mediated call.
    let dir = Fixture::new("policy-test-still-denies").build();
    fs::write(dir.join("probe.rego"), CORRECT).expect("write module");
    let bundles = policy::load(Path::new(&dir), &[row("probe", "probe.rego")], &[], None)
        .expect("the bundle loads");
    let bundle = bundles.first().expect("one bundle");
    let Look::Is(violations) = policy::deny(bundle, r#"{"call": {"command": "git push --force"}}"#)
    else {
        panic!("the module answered nothing");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].rule.as_deref(), Some("no-force-push"));
}
