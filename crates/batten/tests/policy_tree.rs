//! A `policy` row on the TREE surface (CLOUD-833): the four cases §7 names, and
//! the protected-path property that is the sharpest consequence of a bundle
//! being a folder.
//!
//! Why this surface exists at all: 79 of 133 `mise-tasks` programs are
//! gate-described, and nearly every one is a predicate over files and repo state
//! with no mediated call in sight. `RuleKind::Policy` paired with
//! `RuleScope::MediatedCall` alone, so the retirement campaign had nowhere to
//! migrate them to.
//!
//! Why it is safe here and a `command` row is not: `run_static` backs `check`
//! and refuses any kind that spawns, because a `command` row runs a process with
//! the calling user's authority. A policy module is `Authority::Supplied` — a
//! pure function over an input document — so admitting it makes `check` MORE
//! capable without making it less honest. `check_still_refuses_a_spawning_kind`
//! is what keeps that from quietly becoming "check runs anything".

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// A tree-scoped policy row enabling `bundle` over `documents`.
///
/// Deserialized rather than struct-literalled: `Rule` carries
/// `deny_unknown_fields`, so this exercises the column census a consumer's
/// `batten.toml` goes through and a row the loader would refuse cannot be
/// smuggled into a test by hand.
fn tree_row(id: &str, bundle: &str, documents: &[&str]) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "tree",
        "bundle": bundle,
        "documents": documents,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row the loader accepts")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-tree-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("policy")).expect("scratch");
    dir
}

/// A bundle that refuses a tracked path under `docs/` — deliberately generic in
/// shape, and expressed over a declared document rather than an ambient walk.
const NO_STRAY: &str = r#"
package batten

import rego.v1

rules contains "no-stray-key"

violation contains {"rule": "no-stray-key", "msg": "the manifest declares a stray key"} if {
    input.tree.documents["config.toml"].stray
}
"#;

fn write_bundle(root: &Path, source: &str) {
    fs::write(root.join("policy").join("gate.rego"), source).expect("write module");
}

fn scan(root: &Path, rules: &[Rule]) -> rules::Scan {
    rules::run_static(rules, &[], root).expect("the read surface runs a policy row")
}

/// (a) A tree-scoped bundle denies on a fixture that violates.
#[test]
fn a_tree_scoped_bundle_denies_by_predicate_id() {
    let root = scratch("denies");
    write_bundle(&root, NO_STRAY);
    fs::write(root.join("config.toml"), "stray = true\n").expect("fixture");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert_eq!(scan.findings.len(), 1, "the predicate fired");
    assert_eq!(
        scan.findings[0].rule, "no-stray-key",
        "THE PREDICATE'S id, not the row's — a finding names the gate rather \
         than the bundle that happens to hold it (CLOUD-832)"
    );
    assert!(
        !scan.findings[0].path.contains("stray = true"),
        "pointer-only: never a byte of the document's value (rule 4)"
    );
}

/// (a), the other half. Without this the case above passes on a bundle that
/// denies unconditionally, which is not a gate.
#[test]
fn the_same_bundle_is_green_on_a_fixture_that_does_not_violate() {
    let root = scratch("clean");
    write_bundle(&root, NO_STRAY);
    fs::write(root.join("config.toml"), "tidy = true\n").expect("fixture");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert!(
        scan.findings.is_empty(),
        "the predicate decides both ways: {:?}",
        scan.findings
    );
    assert!(
        !scan.not_evaluated.contains_key("repo-policy"),
        "and it EVALUATED — a rule reported as skipped here would make the case \
         above pass for the wrong reason"
    );
}

/// (b) **Load-bearing.** A declared document the tree does not carry is
/// could-not-look, never an empty deny set.
///
/// This is CLOUD-251's vacuous pass in the place it would be least visible: the
/// module would be handed an input whose key is simply absent, every Rego
/// predicate over it would be silently undefined, and the row would report clean
/// having established nothing.
#[test]
fn a_declared_document_the_tree_lacks_is_could_not_look_and_never_a_pass() {
    let root = scratch("missing");
    write_bundle(&root, NO_STRAY);
    // `config.toml` is declared and deliberately absent.

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert!(
        scan.findings.is_empty(),
        "a rule that could not look reports no finding"
    );
    assert!(
        scan.not_evaluated.contains_key("repo-policy"),
        "but it must be recorded as NOT EVALUATED, so the store holds rather \
         than resolves — silence here is the vacuous pass"
    );
}

/// The same arm for a document that exists and will not parse.
///
/// A file that cannot be read says nothing about what it contains, which is
/// `Format::read`'s own three-valued contract carried through to this surface.
#[test]
fn a_declared_document_that_will_not_parse_is_could_not_look() {
    let root = scratch("unparseable");
    write_bundle(&root, NO_STRAY);
    fs::write(root.join("config.toml"), "this = = not toml\n").expect("fixture");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert!(scan.findings.is_empty());
    assert!(
        scan.not_evaluated.contains_key("repo-policy"),
        "an unparseable declared input is could-not-look, not agreement"
    );
}

/// (c) **Load-bearing.** Admitting policy to the read surface did not open it
/// generally.
///
/// `check` still refuses every kind that runs a configured command, naming the
/// verb that would. This is the case that keeps CLOUD-833 from reading as "the
/// read-effect verb now runs anything".
#[test]
fn check_still_refuses_a_spawning_kind() {
    let root = scratch("spawning");
    write_bundle(&root, NO_STRAY);
    let command: Rule = serde_json::from_value(serde_json::json!({
        "id": "runs-a-program",
        "kind": "command",
        "scope": "tree",
        "glob": "**",
        "check": "true",
        "severity": "deny",
    }))
    .expect("a command row");

    let err = rules::run_static(&[command], &[], &root)
        .expect_err("a read-effect verb will not run a configured command");
    let text = format!("{err}");
    assert!(
        text.contains(rules::SPAWNING_VERB),
        "the refusal names the verb that WOULD run it: {text}"
    );
}

/// (d) A row whose declared inputs are unchanged does no work it does not need
/// to — house style §4's "cheap when irrelevant".
///
/// Asserted over the INPUTS rather than by timing: the bound is that only
/// declared paths are read, so a document the row does not name must not reach
/// the module even when it sits beside one that does. A rule that walked the
/// tree would see it, and would make the `read` classification a lie by degrees.
#[test]
fn only_the_declared_documents_reach_the_bundle() {
    let root = scratch("bounded");
    let source = r#"
package batten

import rego.v1

rules contains "saw-undeclared"

violation contains {"rule": "saw-undeclared", "msg": "an undeclared document reached the module"} if {
    input.tree.documents["undeclared.toml"]
}
"#;
    write_bundle(&root, source);
    fs::write(root.join("config.toml"), "tidy = true\n").expect("declared");
    fs::write(root.join("undeclared.toml"), "stray = true\n").expect("undeclared");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert!(
        scan.findings.is_empty(),
        "a file the row does not declare is not in the input document, even \
         though it sits beside one that is: {:?}",
        scan.findings
    );
}

/// A bundle root with no `.rego` module at all is refused at load.
///
/// An empty bundle enables nothing while reading in the config as a configured
/// gate — the shape house style §8 refuses everywhere else.
#[test]
fn an_empty_bundle_root_is_refused_at_load() {
    let root = scratch("empty-bundle");
    let err = rules::run_static(
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
        &[],
        &root,
    )
    .expect_err("a folder with no modules enables nothing");
    assert!(format!("{err}").contains("no `.rego` module"));
}

/// Every module in an enabled bundle is loaded, not just the first.
///
/// The property that makes a folder worth having, and the one whose absence
/// would be invisible: a second module that silently never ran would look
/// exactly like a second module that found nothing.
#[test]
fn every_module_under_the_bundle_root_is_enabled() {
    let root = scratch("many-modules");
    fs::write(
        root.join("policy").join("a.rego"),
        "package batten.a\nimport rego.v1\nrules contains \"from-a\"\nviolation contains {\"rule\": \"from-a\", \"msg\": \"a\"} if { input.tree.documents[\"config.toml\"].stray }\n",
    )
    .expect("module a");
    fs::write(
        root.join("policy").join("b.rego"),
        "package batten.b\nimport rego.v1\nrules contains \"from-b\"\nviolation contains {\"rule\": \"from-b\", \"msg\": \"b\"} if { input.tree.documents[\"config.toml\"].stray }\n",
    )
    .expect("module b");
    fs::write(root.join("config.toml"), "stray = true\n").expect("fixture");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    let mut fired: Vec<&str> = scan.findings.iter().map(|f| f.rule.as_str()).collect();
    fired.sort_unstable();
    assert_eq!(
        fired,
        vec!["from-a", "from-b"],
        "both modules in the folder decided, each under its own id"
    );
}

// --- the tree document corresponds to the fact model (CLOUD-845) -------------
/// The module `policy.rs`'s own doc example is shaped like — a predicate over
/// `input.tree.tracked` alone.
///
/// Shared by the deny case and its discriminator deliberately: the second case
/// discriminates only while the two modules are IDENTICAL, and two copies of a
/// literal can drift apart with nothing turning red.
const READS_TRACKED: &str = r#"
package batten

import rego.v1

rules contains "no-stray-artifact"

violation contains {"rule": "no-stray-artifact", "msg": "a tracked build product"} if {
  some p in input.tree.tracked
  endswith(p, ".o")
}
"#;

/// (b) from the row: the field is real, and a module written against the doc's
/// own example DENIES over a tracked build product.
///
/// This is CLOUD-845's reproduction, inverted. Before the fix this module
/// reported nothing with `stray.o` tracked on a `deny` row, and `policy test`
/// said `2 passed`.
#[test]
fn the_doc_shaped_module_denies_over_a_tracked_artifact() {
    let root = scratch("tracked-denies");
    write_bundle(&root, READS_TRACKED);
    fs::write(root.join("stray.o"), "ELF-ish\n").expect("the tracked artifact");

    let scan = scan(&root, &[tree_row("repo-policy", "policy/", &[])]);
    assert_eq!(
        scan.findings.len(),
        1,
        "the predicate fired over `tracked`: {:?}",
        scan.findings
    );
    assert_eq!(scan.findings[0].rule, "no-stray-artifact");
    // RULE 4 OVER THE WHOLE FINDING, not over one field that structurally
    // cannot hold content. `Finding::path` is set from the row's `bundle`, so
    // asserting the fixture's bytes are absent from IT holds for every possible
    // outcome — a check that cannot fail, which is the vacuity this suite
    // refuses everywhere else.
    let rendered = format!("{:?}", scan.findings[0]);
    assert!(
        !rendered.contains("ELF-ish"),
        "pointer-only: `tracked` carries paths, and no field of a finding \
         carries a byte of any file's content (rule 4): {rendered}"
    );
}

/// The discriminator for the case above. Without it that test passes on a
/// predicate that denies unconditionally, which is not a gate.
#[test]
fn the_same_module_is_green_when_no_artifact_is_tracked() {
    let root = scratch("tracked-clean");
    write_bundle(&root, READS_TRACKED);
    fs::write(root.join("kept.txt"), "not an object file\n").expect("fixture");

    let scan = scan(&root, &[tree_row("repo-policy", "policy/", &[])]);
    assert!(
        scan.findings.is_empty(),
        "the predicate decides both ways: {:?}",
        scan.findings
    );
    assert!(
        !scan.not_evaluated.contains_key("repo-policy"),
        "and it EVALUATED — a skip here would make the case above pass for the \
         wrong reason, which is the failure mode of the whole row"
    );
}

/// (c) from the row: a module reading a key the engine cannot produce is
/// REFUSED, and the refusal names the key.
///
/// This is the half that closes the class rather than the instance. Building
/// `tracked` fixed one dead gate; this makes the next one impossible to author,
/// because the shape that hid it — Rego reading an undefined path as silently
/// undefined — is now a config fault at load.
#[test]
fn a_module_reading_an_unemittable_tree_key_is_refused_naming_the_key() {
    let root = scratch("unemittable");
    write_bundle(
        &root,
        r#"
package batten

import rego.v1

rules contains "reads-a-ghost"

violation contains {"rule": "reads-a-ghost", "msg": "x"} if {
  some p in input.tree.nonesuch
  endswith(p, ".o")
}
"#,
    );

    let err = batten::policy::load(&root, &[tree_row("repo-policy", "policy/", &[])], None)
        .expect_err("a module reading a key the engine cannot emit is refused at load");
    let message = format!("{err}");
    assert!(
        message.contains("nonesuch"),
        "the refusal names the offending key: {message}"
    );
    assert!(
        message.contains("policy/gate.rego"),
        "and the module it is in, so the pointer is actionable: {message}"
    );
    // Rule 4: a pointer, never the module body.
    assert!(
        !message.contains("endswith"),
        "pointer-only — no line of the module reaches the message: {message}"
    );
}

/// The discriminator. Without it the case above passes on a `load` that refuses
/// every tree module, which would be a gate nobody could satisfy.
#[test]
fn a_module_reading_only_emittable_tree_keys_loads() {
    let root = scratch("emittable");
    write_bundle(
        &root,
        r#"
package batten

import rego.v1

rules contains "reads-real-keys"

violation contains {"rule": "reads-real-keys", "msg": "x"} if {
  some p in input.tree.tracked
  endswith(p, ".o")
}

violation contains {"rule": "reads-real-keys", "msg": "y"} if {
  input.tree.documents["config.toml"].stray
}

violation contains {"rule": "reads-real-keys", "msg": "z"} if {
  count(input.tree.missing) > 0
}
"#,
    );

    batten::policy::load(&root, &[tree_row("repo-policy", "policy/", &[])], None)
        .expect("every key this module reads is one the engine emits");
}

/// The third of `missing`'s three causes, split out as a CONFIG FAULT
/// (CLOUD-845).
///
/// An extension this build has no parser for was checked before any I/O and
/// dropped into `missing`, so the rule skipped silently — a migrated gate could
/// go dead by declaring `CLAUDE.md` or a `.bats` suite, with the file never
/// opened. No state of the filesystem fixes that, which is what makes it a
/// config error rather than a could-not-look.
///
/// Asserted through `run_static`, the surface a consumer actually reaches, so
/// the case covers the refusal REACHING them rather than a private helper
/// returning the right value.
#[test]
fn a_document_with_no_parser_is_refused_rather_than_skipped() {
    let root = scratch("no-parser");
    write_bundle(&root, NO_STRAY);
    // The file EXISTS, which is half the point: the cause is the DECLARATION,
    // not the tree, so this cannot pass by accident as an absent-file report.
    // The absent half is asserted by its own case below, because the two are
    // different claims and only together do they pin the precedence.
    fs::write(root.join("CLAUDE.md"), "# prose\n").expect("fixture");

    let err = rules::run_static(
        &[tree_row("repo-policy", "policy/", &["CLAUDE.md"])],
        &[],
        &root,
    )
    .expect_err("a declared document this build cannot parse is a config fault");
    let message = format!("{err}");
    assert!(
        message.contains("CLAUDE.md"),
        "the refusal names the path: {message}"
    );
    assert!(
        message.contains("parser"),
        "and says what is wrong with it — reporting it as a missing file would \
         be the silent skip this splits apart: {message}"
    );
    assert!(
        !message.contains("# prose"),
        "pointer-only: the file is not even opened, let alone quoted: {message}"
    );
}

/// The discriminator: a parseable extension still evaluates. Without it the case
/// above passes on a `run_static` that refuses every declared document.
#[test]
fn a_document_with_a_parser_still_evaluates() {
    let root = scratch("has-parser");
    write_bundle(&root, NO_STRAY);
    fs::write(root.join("config.toml"), "stray = true\n").expect("fixture");

    let scan = scan(
        &root,
        &[tree_row("repo-policy", "policy/", &["config.toml"])],
    );
    assert_eq!(
        scan.findings.len(),
        1,
        "TOML is one of the four formats this build parses: {:?}",
        scan.findings
    );
}

/// The other half of the precedence, and the one a fixture that creates the file
/// cannot make: an ABSENT unsupported path is still a parser fault, not
/// `missing`.
///
/// Without this, a regression that reordered the checks — testing the tree
/// before the extension — would classify a declared `.md` the tree lacks as a
/// could-not-look, which is the silent skip the split exists to remove, wearing
/// the other cause's name.
#[test]
fn an_absent_unsupported_document_is_still_a_parser_fault() {
    let root = scratch("no-parser-absent");
    write_bundle(&root, NO_STRAY);
    // `CLAUDE.md` is deliberately NOT created.

    let err = rules::run_static(
        &[tree_row("repo-policy", "policy/", &["CLAUDE.md"])],
        &[],
        &root,
    )
    .expect_err("the extension is decided before the tree is consulted");
    let message = format!("{err}");
    assert!(
        message.contains("CLAUDE.md"),
        "the refusal names the path: {message}"
    );
    assert!(
        message.contains("parser"),
        "and blames the parser rather than the absence — the extension is \
         checked before any I/O, so absence never gets a chance to explain it: \
         {message}"
    );
}

/// A bracket reference is the same reference, and the gate must not be
/// bypassable by a spelling.
///
/// `input.tree["nonesuch"]` is a `RefBrack` around `input.tree`; Rego treats it
/// as identical to `input.tree.nonesuch`. Reading only the dotted half recorded
/// the path as `tree`, so the key came out empty and
/// `check_tree_paths_are_emittable` skipped it — the refusal defeated by
/// quoting.
#[test]
fn a_bracket_reference_to_an_unemittable_key_is_refused_too() {
    let root = scratch("bracket");
    write_bundle(
        &root,
        r#"
package batten

import rego.v1

rules contains "reads-a-ghost"

violation contains {"rule": "reads-a-ghost", "msg": "x"} if {
  count(input.tree["nonesuch"]) > 0
}
"#,
    );

    let err = batten::policy::load(&root, &[tree_row("repo-policy", "policy/", &[])], None)
        .expect_err("a bracket reference is a reference");
    assert!(
        format!("{err}").contains("nonesuch"),
        "the refusal names the bracketed key: {err}"
    );
}

/// The discriminator: a bracket reference to a key the engine DOES emit still
/// loads. Without it the case above passes on a `load` that refuses every
/// bracket reference — which would break `input.tree.documents["path"]`, the
/// spelling every existing module uses.
#[test]
fn a_bracket_reference_to_an_emittable_key_still_loads() {
    let root = scratch("bracket-ok");
    write_bundle(
        &root,
        r#"
package batten

import rego.v1

rules contains "reads-real-keys"

violation contains {"rule": "reads-real-keys", "msg": "x"} if {
  input.tree["documents"]["config.toml"].stray
}
"#,
    );

    batten::policy::load(&root, &[tree_row("repo-policy", "policy/", &[])], None)
        .expect("`documents` is emitted, however it is spelled");
}
