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

use crate::common;

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
            recorders: &[],
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
	"verdict": "fixture class probe",
	"subjects": [{"path": "a.rs", "line": 7}],
} if {
	input.call.operation == "write"
}
"#;

/// The registry the conforming module needs.
fn declared() -> Vec<DeclaredVerdict> {
    common::verdicts(&["fixture class probe"])
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
    assert_eq!(denials[0].verdict, "fixture class probe");
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
        r#""verdict": "fixture class probe","#,
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
    assert!(format!("{err}").contains("fixture class probe"));
}

/// The other direction, and the one a reviewer would not think to ask for: a
/// class no gate reaches reads as coverage in `explain` while its routes have
/// never been walked by anybody.
#[test]
fn a_declared_row_nothing_raises_is_refused() {
    let mut table = declared();
    table.extend(common::verdicts(&["nobody raises this"]));
    let err = load("unemitted", CONFORMING, &table).expect_err("dead vocabulary is refused");
    assert!(format!("{err}").contains("nobody raises this"));
}

// ---------------------------------------------------------------------------
// A token has to be a NAME.
// ---------------------------------------------------------------------------

#[test]
fn a_composed_verdict_is_refused() {
    let source = CONFORMING.replace(
        r#""verdict": "fixture class probe","#,
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
    table[0].successor = Some("the live one".to_owned());
    table.extend(common::verdicts(&["the live one"]));
    let err = load("tombstoned", CONFORMING, &table)
        .expect_err("a tombstone exists so a historical token stays explainable");
    let text = format!("{err}");
    assert!(text.contains("fixture class probe"), "{text}");
    assert!(text.contains("RETIRED"), "{text}");
}

/// A tombstone whose successor is live resolves, and the token the reader asked
/// for is reported as retired rather than silently swapped.
#[test]
fn a_tombstone_resolves_through_its_chain() {
    let mut table = common::verdicts(&["old probe probe", "new probe probe"]);
    table[0].successor = Some("new probe probe".to_owned());
    verdict::validate(&table, &batten::verdict::Vocabulary::default())
        .expect("a terminating chain is well formed");
    let (resolved, retired) =
        verdict::resolve(&table, "old probe probe").expect("the token resolves");
    assert_eq!(resolved.id, "new probe probe");
    assert!(retired);
}

// ---------------------------------------------------------------------------
// The withdrawal arm (CLOUD-1114): a tombstone may name a reason instead of a
// successor.
//
// Every case here is red against a build where `retired()` is
// `successor.is_some()` — the arm cannot be spelled at all, so the field does not
// deserialize and the load refuses under `deny_unknown_fields`.
// ---------------------------------------------------------------------------

/// The positive arm, and the one the row exists for: a class that was withdrawn
/// rather than replaced retires on its own reason.
#[test]
fn a_row_naming_only_a_withdrawal_loads_and_reports_retired() {
    let mut table = common::verdicts(&["gone probe probe"]);
    table[0].withdrawn = Some("the thing it refused is no longer refused by anything".to_owned());
    verdict::validate(&table, &batten::verdict::Vocabulary::default())
        .expect("a withdrawal is a well-formed retirement");
    assert!(
        table[0].retired(),
        "a withdrawn class is as retired as a replaced one"
    );

    // It ends its own chain rather than resolving elsewhere — there is nowhere
    // to send the reader, which is exactly what a withdrawal says.
    let (resolved, retired) =
        verdict::resolve(&table, "gone probe probe").expect("the token resolves");
    assert_eq!(resolved.id, "gone probe probe");
    assert!(retired);
}

/// The tombstone exemption covers both arms, so a withdrawn token is still wrong
/// to emit. Without this the arm would be a way to keep dead vocabulary live.
#[test]
fn a_withdrawn_token_that_is_still_raised_is_refused() {
    let mut table = declared();
    table[0].withdrawn = Some("nothing refuses this any more".to_owned());
    let err = load("withdrawn-raised", CONFORMING, &table)
        .expect_err("a withdrawn class is retired, and a retired one must not be emitted");
    let text = format!("{err}");
    assert!(text.contains("fixture class probe"), "{text}");
    assert!(text.contains("RETIRED"), "{text}");
}

#[test]
fn an_empty_withdrawal_reason_is_refused() {
    // The arm's whole job is to carry the reason a successor cannot. A blank one
    // retires the token while explaining nothing, which is the deleted row again
    // at a tombstone's price.
    for blank in ["", "   ", "\n"] {
        let mut table = common::verdicts(&["gone probe probe"]);
        table[0].withdrawn = Some(blank.to_owned());
        let err = verdict::validate(&table, &batten::verdict::Vocabulary::default())
            .expect_err("an empty withdrawal explains nothing");
        let text = format!("{err}");
        assert!(
            text.contains("gone probe probe"),
            "the refusal names the id: {text}"
        );
        assert!(
            text.contains("withdrawn"),
            "and names the arm at fault: {text}"
        );
    }
}

#[test]
fn a_row_naming_both_arms_is_refused() {
    // Two different accounts of where the class went is neither. A reader
    // following the successor would never learn it was withdrawn.
    let mut table = common::verdicts(&["old probe probe", "new probe probe"]);
    table[0].successor = Some("new probe probe".to_owned());
    table[0].withdrawn = Some("and also nobody refuses it".to_owned());
    let err = verdict::validate(&table, &batten::verdict::Vocabulary::default())
        .expect_err("a row cannot be both replaced and withdrawn");
    let text = format!("{err}");
    assert!(
        text.contains("old probe probe"),
        "the refusal names the id: {text}"
    );
    assert!(text.contains("successor"), "{text}");
    assert!(text.contains("withdrawn"), "{text}");
}

/// The direction a careless arm breaks: the successor half must be untouched.
/// Both refusals below stood before this change and have to stand after it.
#[test]
fn the_withdrawal_arm_weakens_neither_successor_refusal() {
    let mut dangling = common::verdicts(&["old probe probe"]);
    dangling[0].successor = Some("never declared probe".to_owned());
    let err = verdict::validate(&dangling, &batten::verdict::Vocabulary::default())
        .expect_err("a successor nothing declares is refused");
    assert!(format!("{err}").contains("never declared probe"));

    let mut cycle = common::verdicts(&["a probe probe", "b probe probe"]);
    cycle[0].successor = Some("b probe probe".to_owned());
    cycle[1].successor = Some("a probe probe".to_owned());
    let err = verdict::validate(&cycle, &batten::verdict::Vocabulary::default())
        .expect_err("a chain that cycles terminates nowhere");
    assert!(format!("{err}").contains("cycles"));
}

/// A withdrawn entry is not walked as a chain, so it cannot dangle. Asserted
/// rather than assumed: reading the arm as a successor would refuse every
/// withdrawal as naming an undeclared token, which is the arm failing to exist.
#[test]
fn a_withdrawal_is_not_read_as_a_successor() {
    let mut table = common::verdicts(&["gone probe probe"]);
    table[0].withdrawn = Some("something that isnotatoken".to_owned());
    verdict::validate(&table, &batten::verdict::Vocabulary::default())
        .expect("a withdrawal reason is prose, never a token the registry must declare");
}

// ---------------------------------------------------------------------------
// The vendored half.
// ---------------------------------------------------------------------------

/// A consumer redefining a class the binary ships would render a preset's
/// refusal under words its author never wrote.
#[test]
fn a_consumer_row_colliding_with_a_vendored_class_is_refused() {
    let mut table = declared();
    table.extend(common::verdicts(&["commit ship empty"]));
    let err = load("collision", CONFORMING, &table)
        .expect_err("a class with two definitions is refused rather than resolved");
    assert!(format!("{err}").contains("commit ship empty"));
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
        // `segments` AND `programs`, because the ENGINE always emits both and
        // this preset reads the second (CLOUD-857, CLOUD-1382): a fixture
        // carrying only `command` — or only `segments`, once the preset moved
        // its anchor off `words[0]` onto the program — hands the predicate a
        // shape `hook::call_document` never produces, and the deny this case
        // asserts would vanish for a reason that has nothing to do with the
        // registry. That is not hypothetical here: it is what this line did on
        // the commit that moved the anchor.
        r#"{"call": {"command": "git commit --allow-empty -m x", "segments": [{"words": ["git", "commit", "--allow-empty", "-m", "x"], "raw": "git commit --allow-empty -m x", "terminator": null}], "programs": [{"program": "git", "name": "git", "arguments": ["commit", "--allow-empty", "-m", "x"], "mediated": false}]}}"#,
    ) else {
        panic!("the preset answered could-not-look");
    };
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].verdict, "commit ship empty");
}

// ---------------------------------------------------------------------------
// The bare-string channel is held to the same registry.
// ---------------------------------------------------------------------------

const BARE_DENY: &str = r#"
package batten

import rego.v1

deny contains "fixture class probe" if {
	input.call.operation == "write"
}
"#;

#[test]
fn a_bare_deny_member_is_a_token_and_is_declared() {
    let bundles = load("bare-deny", BARE_DENY, &declared()).expect("a declared token loads");
    let Look::Is(denials) = policy::deny(&bundles[0], r#"{"call": {"operation": "write"}}"#) else {
        panic!("could-not-look");
    };
    assert_eq!(denials[0].verdict, "fixture class probe");
    assert_eq!(denials[0].rule, None, "a bare member names no predicate");
}

#[test]
fn a_bare_deny_member_no_row_declares_is_refused() {
    let err = load("bare-deny-undeclared", BARE_DENY, &[])
        .expect_err("the string channel does not reopen the free-string hole");
    assert!(format!("{err}").contains("fixture class probe"));
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
            recorders: &[],
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
         id = \"x probe probex\"\n\
         gloss = \"a class\"\n\
         class = \"what it means\"\n\n\
         [[verdict.route]]\n\
         id = \"x probe probe\"\n\
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

/// **Every `Native` class is actually RAISED somewhere in production code**
/// (CLOUD-1313).
///
/// # The hole this closes
///
/// The registry's two directions make it honest for MODULE classes:
/// `check_verdicts_are_declared` refuses a raised token no row declares, and
/// `check_registry_is_exhausted` refuses a declared row nothing raises. But the
/// second one *exempts* `native_tokens()` rather than proving them —
/// deliberately, since a native class is raised from Rust and there is no AST to
/// read. So a `Native` variant could be declared, carry a `VENDORED` row with a
/// gloss and routes, resolve through `policy explain`, and be raised by nothing
/// at all. Every one of those signals says the class is live; none of them
/// checks it.
///
/// `every_native_class_is_listed` does not close this. It matches without a
/// wildcard, so a new variant fails to compile until it is LISTED — which is a
/// statement about the table, not about any call site.
///
/// # Measured before writing this: the existing twenty are clean
///
/// All 20 variants declared at the time were raised in production code, so this
/// is a ratchet over the classes CLOUD-1313 adds rather than a repair of
/// something already broken. Saying which it is matters: a gate introduced
/// alongside a finding reads as having caught one.
///
/// # Why a source scan rather than name resolution
///
/// `.claude/rules/scanning.md` routes "which type does this name resolve to" to
/// rust-analyzer, and `Native::Foo` is not that question — it is "does this
/// token appear in a raising position", which is a text question about a closed,
/// unambiguous spelling. There is exactly one `Native` type in this crate and no
/// import can alias a variant path, which is what makes the scan sound here where
/// `spawn_census`'s `Command::new` scan was not.
#[test]
fn every_native_class_is_raised_by_production_code() {
    let verdict_rs = common::at_root("crates/batten/src/verdict.rs");
    let declared = declared_native_variants(&verdict_rs);
    assert!(
        declared.len() >= 20,
        "the scan found {} variants, too few to be the enum",
        declared.len()
    );

    let mut raised: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for path in common::rust_sources() {
        // `verdict.rs` DECLARES them; naming a variant there is not raising it,
        // and counting the enum and `id()` as call sites is what would make this
        // gate vacuous.
        if path.ends_with("verdict.rs") || !path.starts_with(common::at_root("crates/batten/src")) {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("a source file");
        // A `#[cfg(test)]` module is not production code. A class raised only by
        // its own unit test is exactly the dead class this asserts against.
        let production = body
            .find("#[cfg(test)]")
            .map_or(&body[..], |at| &body[..at]);
        for found in production.match_indices("Native::") {
            let rest = &production[found.0 + "Native::".len()..];
            let name: String = rest
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
                .collect();
            if !name.is_empty() {
                raised.insert(name);
            }
        }
    }

    let dead: Vec<&String> = declared
        .iter()
        .filter(|name| !raised.contains(*name))
        .collect();
    assert!(
        dead.is_empty(),
        "these classes are declared and raised by nothing outside tests, so they \
         resolve through `policy explain` and can never fire: {dead:?}"
    );
}

/// The variants `Native::ALL` lists, read off the const rather than re-typed.
///
/// Re-typing the list here would be a second authority on it, and the two would
/// drift in exactly the direction that makes the assertion above pass
/// vacuously — a name missing from this copy is a class the gate stops checking.
fn declared_native_variants(verdict_rs: &std::path::Path) -> Vec<String> {
    let src = std::fs::read_to_string(verdict_rs).expect("verdict.rs is committed");
    let at = src
        .find("pub const ALL")
        .expect("`Native::ALL` is declared");
    let body = &src[at..src[at..].find("];").expect("the const terminates") + at];
    let mut found = Vec::new();
    for hit in body.match_indices("Native::") {
        let rest = &body[hit.0 + "Native::".len()..];
        let name: String = rest
            .chars()
            .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
            .collect();
        if !name.is_empty() {
            found.push(name);
        }
    }
    found
}
