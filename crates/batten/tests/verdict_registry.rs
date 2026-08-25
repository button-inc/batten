//! The typed refusal ABI, over the engine rather than over a fabricated input
//! (CLOUD-1050).
//!
//! # What is under test, and why it cannot be a `with input as` case
//!
//! Registry equality is a property of **loading**: the engine reads a module's
//! AST, compares the tokens it raises against the declared table, and refuses in
//! both directions. A module's own `test_` rules cannot reach any of that — they
//! run inside a bundle that has already loaded, so a suite made of them is green
//! over exactly the modules the loader would have refused.
//!
//! `.claude/rules/policy-modules.md` records both live instances of that class
//! being found by adding this tier rather than by reading, which is why it is
//! this file and not a fixture module that carries the assertions.
//!
//! # Every case here reddens exactly one predicate
//!
//! Each fixture differs from the conforming one by a single edit — the retired
//! key, a composed token, a missing row, an unraised row, a tombstone still
//! raised, a collision with a vendored class. The conforming case is asserted
//! too, because a loader that refused everything would satisfy every negative
//! case above it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::facts::Look;
use batten::policy::{self, Vocabulary};
use batten::rules::Rule;
use batten::verdict::{self, DeclaredVerdict, Subject};

/// A mediated-call policy row naming `module`.
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

/// Write `source` as a module in a fresh scratch tree and return both.
fn tree(name: &str, source: &str) -> (PathBuf, String) {
    let root = common::scratch(&format!("verdict-registry-{name}"));
    fs::write(root.join("gate.rego"), source).expect("write module");
    (root, "gate.rego".to_owned())
}

/// Load `source` against `verdicts`, returning whatever the loader answered.
fn load(
    name: &str,
    source: &str,
    verdicts: &[DeclaredVerdict],
) -> anyhow::Result<Vec<policy::Bundle>> {
    let (root, module) = tree(name, source);
    policy::load(
        &root,
        &[row("gate", &module)],
        Vocabulary {
            patterns: &[],
            verdicts,
        },
        policy::ModuleChecks::Run,
        None,
    )
}

/// The conforming module: a token, and a tagged pointer.
const CONFORMING: &str = r#"
package batten

import rego.v1

rules contains "a-gate"

violation contains {
	"rule": "a-gate",
	"verdict": "V-FIXTURE-CLASS",
	"subjects": [{"path": "a.rs", "line": 7}],
} if {
	input.call.operation == "write"
}
"#;

/// The registry the conforming module needs.
fn declared() -> Vec<DeclaredVerdict> {
    common::verdicts(&["V-FIXTURE-CLASS"])
}

// ---------------------------------------------------------------------------
// The positive arm. Without it every refusal below is satisfied by a loader
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_conforming_module_loads_and_denies_with_its_token_and_pointer() {
    let bundles = load("conforming", CONFORMING, &declared()).expect("a conforming module loads");
    let input = r#"{"call": {"operation": "write"}}"#;
    let Look::Is(denials) = policy::deny(&bundles[0], input) else {
        panic!("the bundle answered could-not-look over a document it can read");
    };
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].verdict, "V-FIXTURE-CLASS");
    assert_eq!(
        denials[0].subjects,
        vec![Subject::Line {
            path: "a.rs".to_owned(),
            line: 7
        }],
        "the tagged pointer survives the decoder with its line intact"
    );
}

// ---------------------------------------------------------------------------
// The retired key.
// ---------------------------------------------------------------------------

/// **The migration's own gate.** A module still speaking the old ABI would
/// otherwise load clean, evaluate clean and report nothing, because the decoder
/// no longer reads `msg` — a dead gate and a clean tree being byte-identical is
/// the defect `.claude/rules/policy-modules.md` opens on.
#[test]
fn a_module_still_binding_msg_is_refused_and_the_refusal_names_the_key() {
    let source = CONFORMING.replace(
        r#""verdict": "V-FIXTURE-CLASS","#,
        r#""msg": "some prose the engine cannot check","#,
    );
    let err =
        load("retired-key", &source, &declared()).expect_err("the retired key is refused at load");
    let text = format!("{err}");
    assert!(text.contains("msg"), "the refusal names the key: {text}");
    assert!(
        text.contains("gate.rego"),
        "and points at the module: {text}"
    );
}

// ---------------------------------------------------------------------------
// Registry equality, both directions.
// ---------------------------------------------------------------------------

#[test]
fn a_token_no_row_declares_is_refused() {
    let err = load("undeclared", CONFORMING, &[])
        .expect_err("a class with no declaration carries no gloss and no route");
    assert!(format!("{err}").contains("V-FIXTURE-CLASS"));
}

/// The other direction, and the one a reviewer would not think to ask for: a
/// class no gate reaches reads as coverage in `explain` while its routes have
/// never been walked by anybody.
#[test]
fn a_declared_row_nothing_raises_is_refused() {
    let mut table = declared();
    table.extend(common::verdicts(&["V-NOBODY-RAISES-THIS"]));
    let err = load("unemitted", CONFORMING, &table).expect_err("dead vocabulary is refused");
    assert!(format!("{err}").contains("V-NOBODY-RAISES-THIS"));
}

// ---------------------------------------------------------------------------
// A token has to be a NAME.
// ---------------------------------------------------------------------------

#[test]
fn a_composed_verdict_is_refused() {
    let source = CONFORMING.replace(
        r#""verdict": "V-FIXTURE-CLASS","#,
        r#""verdict": sprintf("V-%s", ["FIXTURE-CLASS"]),"#,
    );
    let err = load("composed", &source, &declared())
        .expect_err("a token a reader cannot look up is not a token");
    assert!(format!("{err}").contains("gate.rego"));
}

// ---------------------------------------------------------------------------
// Tombstones.
// ---------------------------------------------------------------------------

#[test]
fn a_tombstoned_token_that_is_still_raised_is_refused() {
    let mut table = declared();
    table[0].successor = Some("V-THE-LIVE-ONE".to_owned());
    table.extend(common::verdicts(&["V-THE-LIVE-ONE"]));
    let err = load("tombstoned", CONFORMING, &table)
        .expect_err("a tombstone exists so a historical token stays explainable");
    let text = format!("{err}");
    assert!(text.contains("V-FIXTURE-CLASS"), "{text}");
    assert!(text.contains("RETIRED"), "{text}");
}

/// A tombstone whose successor is live resolves, and the token the reader asked
/// for is reported as retired rather than silently swapped.
#[test]
fn a_tombstone_resolves_through_its_chain() {
    let mut table = common::verdicts(&["V-OLD", "V-NEW"]);
    table[0].successor = Some("V-NEW".to_owned());
    verdict::validate(&table).expect("a terminating chain is well formed");
    let (resolved, retired) = verdict::resolve(&table, "V-OLD").expect("the token resolves");
    assert_eq!(resolved.id, "V-NEW");
    assert!(retired);
}

// ---------------------------------------------------------------------------
// The vendored half.
// ---------------------------------------------------------------------------

/// A consumer redefining a class the binary ships would render a preset's
/// refusal under words its author never wrote.
#[test]
fn a_consumer_row_colliding_with_a_vendored_class_is_refused() {
    let mut table = declared();
    table.extend(common::verdicts(&["V-EMPTY-COMMIT"]));
    let err = load("collision", CONFORMING, &table)
        .expect_err("a class with two definitions is refused rather than resolved");
    assert!(format!("{err}").contains("V-EMPTY-COMMIT"));
}

/// **A preset loads against a registry the consumer never wrote.** Holding it to
/// their table would make an enabled preset unloadable with no fix available,
/// which is the wrongly-refusing gate AGENTS.md calls a defect.
#[test]
fn a_vendored_preset_loads_with_no_consumer_rows_at_all() {
    let root = common::scratch("verdict-registry-preset");
    let preset: Rule = serde_json::from_value(serde_json::json!({
        "id": "hygiene",
        "kind": "policy",
        "scope": "mediated_call",
        "preset": "commit-hygiene",
        "severity": "deny",
    }))
    .expect("a preset row the loader accepts");
    let bundles = policy::load(
        &root,
        &[preset],
        Vocabulary::EMPTY,
        policy::ModuleChecks::Run,
        None,
    )
    .expect("a vendored preset ships its own vocabulary");
    let Look::Is(denials) = policy::deny(
        &bundles[0],
        r#"{"call": {"command": "git commit --allow-empty -m x"}}"#,
    ) else {
        panic!("the preset answered could-not-look");
    };
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].verdict, "V-EMPTY-COMMIT");
}

// ---------------------------------------------------------------------------
// The bare-string channel is held to the same registry.
// ---------------------------------------------------------------------------

const BARE_DENY: &str = r#"
package batten

import rego.v1

deny contains "V-FIXTURE-CLASS" if {
	input.call.operation == "write"
}
"#;

#[test]
fn a_bare_deny_member_is_a_token_and_is_declared() {
    let bundles = load("bare-deny", BARE_DENY, &declared()).expect("a declared token loads");
    let Look::Is(denials) = policy::deny(&bundles[0], r#"{"call": {"operation": "write"}}"#) else {
        panic!("could-not-look");
    };
    assert_eq!(denials[0].verdict, "V-FIXTURE-CLASS");
    assert_eq!(denials[0].rule, None, "a bare member names no predicate");
}

#[test]
fn a_bare_deny_member_no_row_declares_is_refused() {
    let err = load("bare-deny-undeclared", BARE_DENY, &[])
        .expect_err("the string channel does not reopen the free-string hole");
    assert!(format!("{err}").contains("V-FIXTURE-CLASS"));
}

// ---------------------------------------------------------------------------
// Route resolution, over the tree surface.
// ---------------------------------------------------------------------------

/// The committed module, copied into the fixture rather than restated: an
/// inline copy would drift from the shipped one and pass while the real gate
/// was broken.
fn install_routes_module(root: &Path) {
    let source = common::at_root("policy/verdict-routes-resolve.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/verdict-routes-resolve.rego"))
        .expect("install committed module");
}

/// Run the committed route-resolution row over a scratch tree carrying
/// `authority` as its `batten.toml` and `manifest` as its `mise.toml`.
fn route_findings(name: &str, authority: &str, manifest: &str) -> Vec<String> {
    let root = common::scratch(&format!("verdict-routes-{name}"));
    install_routes_module(&root);
    fs::write(root.join("batten.toml"), authority).expect("write authority");
    fs::write(root.join("mise.toml"), manifest).expect("write manifest");
    common::git_in(&root, &["init", "--initial-branch=main"]);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-q", "-m", "fixture"]);
    let routes_row: Rule = serde_json::from_value(serde_json::json!({
        "id": "verdict-routes-resolve",
        "kind": "policy",
        "scope": "tree",
        "sources": ["batten.toml", "mise.toml"],
        "module": "policy/verdict-routes-resolve.rego",
        "severity": "deny",
    }))
    .expect("the row batten.toml declares");
    // The vocabulary the committed module needs, read off the module itself.
    // Derived rather than listed: this fixture copies the COMMITTED module in so
    // it cannot drift, and a hand-written table beside it would.
    let verdicts = common::verdicts_in(&root);
    batten::rules::run_static(
        &[routes_row],
        &[],
        Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
        },
        &root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

/// The authority a route fixture declares, with one route of `kind` at `target`.
fn authority_with(kind: &str, target: &str) -> String {
    format!(
        "version = 1\n\n\
         [[verdict]]\n\
         id = \"V-X\"\n\
         gloss = \"a class\"\n\
         class = \"what it means\"\n\n\
         [[verdict.route]]\n\
         id = \"R-X\"\n\
         kind = \"{kind}\"\n\
         target = \"{target}\"\n"
    )
}

const MANIFEST: &str = "[tasks.present]\nrun = \"true\"\n";

#[test]
fn a_command_route_naming_an_undefined_task_is_refused_over_the_engine() {
    assert_eq!(
        route_findings(
            "undefined",
            &authority_with("command", "mise run absent"),
            MANIFEST
        ),
        vec!["verdict-routes-resolve".to_owned()]
    );
}

#[test]
fn a_command_route_naming_a_defined_task_is_clean_over_the_engine() {
    assert!(
        route_findings(
            "defined",
            &authority_with("command", "mise run present"),
            MANIFEST
        )
        .is_empty()
    );
}
