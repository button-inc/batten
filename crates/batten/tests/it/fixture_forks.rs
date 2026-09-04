//! `policy/fixture-forks.rego` over the COMPILED engine (CLOUD-1419).
//!
//! # Why this file exists when the module already has `test_` rules
//!
//! Those are the load-time tier and they pin the PREDICATE. They cannot pin that
//! the engine BUILDS the input the predicate reads: `with input as` fabricates
//! the very shape the engine may be unable to produce, so a module reading a key
//! nothing fills passes its own suite green and enforces nothing.
//!
//! This module reads three things the engine has to resolve rather than a
//! harness hand over — `input.tree["base-delta"]`'s `added`/`edited` sets, its
//! `base-lines` map, and `input.tree.lines` — plus a `[[pattern]]` row it
//! resolves through `data.batten.patterns`. Every one of those is a way for the
//! gate to be dead while its own suite is green, and only a run over the
//! compiled binary against a real base ref can tell.
//!
//! # The pattern registry is passed, and that is the opposite of a preset's rule
//!
//! `.claude/rules/policy-modules.md` tells a PRESET's tier to supply
//! `patterns: &[]`, because a preset ships to consumers who wrote no rows and a
//! harness declaring the ids would supply input no consumer supplies. An in-repo
//! module is the other case: this repository DOES declare
//! `[[pattern]] fixture-git-init`, so the fidelity requirement runs the other
//! way — the fixture resolves the COMMITTED row through
//! `common::committed_patterns`, and a hand-written table beside it would pass
//! here while the real gate was broken.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares.
const FORK_ADDED: &str = "fixture-fork-added";

/// A line that forks `git init`, in the short spelling.
const FORKING: &str = r#"    git_in(&dir, &["init", "-q"]);"#;

/// And in the long one. Two spellings of one concept, which is why the pattern
/// is a registry row rather than a literal in the module.
const FORKING_LONG: &str = r#"    git_in(&dir, &["init", "--quiet"]);"#;

/// A fixture repository whose base is one commit back, so the engine's own
/// `base-delta` resolution is what produces the fact under test.
///
/// `base` carries the files as the base rev had them; `head` is written after
/// the commit and left uncommitted, which is what puts a path in `added` or
/// `edited` rather than in neither.
///
/// `origin/main` is a local ref pointed at the base commit: `base_delta`
/// resolves a rev, and configuring a remote would make every case here depend on
/// the network for an entirely local question. Same shape as `test_targets.rs`.
// needs-real-fixture: CLOUD-1419 these fixtures need a real base ref for the
// engine to resolve `base-delta` against, so `repo` builds history with real
// git. A template copy carries no commits and this tier's whole point is driving
// the engine over a branch that has some.
fn repo(name: &str, base: &[(&str, &str)], head: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet"]);
    write_all(&root, base);
    // A seed so the base commit is never empty even when `base` is.
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let at = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", &at]);

    write_all(&root, head);
    install_module(&root);
    root
}

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("scratch parent");
        }
        fs::write(full, body).expect("write fixture file");
    }
}

/// The COMMITTED module, copied rather than re-typed. A fixture carrying its own
/// copy of the predicate would pass while the shipped one was broken, which is
/// the fidelity failure this tier exists to catch.
fn install_module(root: &Path) {
    let source = common::at_root("policy/fixture-forks.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/fixture-forks.rego")).expect("install committed module");
}

/// The committed row's shape, so a registration the loader would reject cannot
/// pass here.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "fixture-forks",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["crates/batten/tests/it/**/*.rs"],
        "line_sources": ["crates/batten/tests/it/**/*.rs"],
        "module": "policy/fixture-forks.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn scan(root: &Path) -> rules::Scan {
    let verdicts = common::verdicts_in(root);
    let patterns = common::committed_patterns();
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
}

fn verdicts(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| finding.rule)
        .collect()
}

fn pointers(root: &Path) -> Vec<String> {
    scan(root)
        .findings
        .into_iter()
        .map(|finding| match finding.line {
            // A pointer with no line is reported as the path alone rather than
            // as `path:0`: this rule's subjects carry a line, so a missing one
            // is the projection failing and must be visible as a different
            // string rather than as a plausible-looking zero.
            Some(line) => format!("{}:{line}", finding.path),
            None => finding.path,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by a module
// that refuses everything.
// ---------------------------------------------------------------------------

#[test]
fn a_branch_adding_no_fixture_fork_passes_untouched() {
    let root = repo(
        "fixture-forks-clean",
        &[],
        &[(
            "crates/batten/tests/it/new_gate.rs",
            "let dir = Fixture::new(\"x\").git().build();\n",
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a fixture that builds its repository from the template forks nothing"
    );
}

/// THE ROW `#MUTANT added-init-unread` MUST REDDEN, and the mutation empties the
/// line walk rather than negating the match — negating it would also be excluded
/// by the scope conjunct on every fixture path and would survive.
#[test]
fn an_added_fixture_that_forks_git_init_is_refused() {
    let root = repo(
        "fixture-forks-added",
        &[],
        &[(
            "crates/batten/tests/it/new_gate.rs",
            &format!("fn one() {{\n{FORKING}\n}}\n"),
        )],
    );
    assert_eq!(
        verdicts(&root),
        vec![FORK_ADDED.to_owned()],
        "a fixture forking `git init` for itself is refused, and the engine's \
         own base-delta plus line projection is what has to surface it"
    );
    assert_eq!(
        pointers(&root),
        vec!["crates/batten/tests/it/new_gate.rs:2".to_owned()],
        "the finding points at the line that forks, not merely at the file"
    );
}

/// THE SECOND SPELLING REACHES THE SAME ROW, which is the whole argument for the
/// `[[pattern]]` registry over a literal in the module — and, over the compiled
/// engine, it is also what proves the row RESOLVES. A module whose pattern id
/// resolved to nothing would read undefined, hold nothing, and pass this suite
/// green while enforcing nothing anywhere.
#[test]
fn the_long_init_spelling_reaches_the_same_row() {
    let root = repo(
        "fixture-forks-long",
        &[],
        &[(
            "crates/batten/tests/it/new_gate.rs",
            &format!("{FORKING_LONG}\n"),
        )],
    );
    assert_eq!(
        verdicts(&root),
        vec![FORK_ADDED.to_owned()],
        "`--quiet` is the same concept as `-q` and the registry row covers both"
    );
}

/// THE CASE THAT KEEPS THE GATE FROM REFUSING ITS OWN MECHANISM.
/// `common/mod.rs` is where the surviving `git init` builds the template every
/// other fixture copies, so a rule refusing it would refuse the thing it exists
/// to protect — the shape a gate does not survive. `#MUTANT
/// harness-exemption-may-widen` reddens exactly here.
#[test]
fn the_harness_module_may_still_build_the_template() {
    let root = repo(
        "fixture-forks-harness",
        &[],
        &[(
            "crates/batten/tests/it/common/mod.rs",
            &format!("{FORKING}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the harness owns the one surviving fork; refusing it would refuse the \
         template every other fixture copies"
    );
}

/// AN EDITED FILE IS A COMPARISON, NOT A SNAPSHOT. This is the arm that reads
/// `base-lines`, and it is the one a `with input as` case cannot prove: the map
/// is built by the engine from the base rev, and a module reading a key the
/// engine never fills would pass its own suite over a hand-written fixture.
#[test]
fn an_edited_fixture_that_moved_its_fork_is_clean() {
    let body = format!("fn a() {{\n{FORKING}\n}}\n");
    let moved = format!("{FORKING}\nfn a() {{\n}}\n");
    let root = repo(
        "fixture-forks-moved",
        &[("crates/batten/tests/it/walker.rs", &body)],
        &[("crates/batten/tests/it/walker.rs", &moved)],
    );
    assert!(
        verdicts(&root).is_empty(),
        "moving an existing fork is ordinary editing; only the total growing is \
         the reversal this refuses"
    );
}

#[test]
fn an_edited_fixture_that_grew_a_fork_is_refused() {
    let before = format!("{FORKING}\n");
    let after = format!("{FORKING}\n{FORKING_LONG}\n");
    let root = repo(
        "fixture-forks-grew",
        &[("crates/batten/tests/it/walker.rs", &before)],
        &[("crates/batten/tests/it/walker.rs", &after)],
    );
    assert_eq!(
        verdicts(&root),
        vec![FORK_ADDED.to_owned()],
        "a file that ends the change with more forks than it started with is \
         the aggregate sliding back up, one file at a time"
    );
}

/// THE ADMISSION, and it is read from the WORKING tree because an added file has
/// no base side to read it from. Structurally weaker than `retires_with` and the
/// module's own header says so; what it buys is a visible, attributed increase.
#[test]
fn a_declared_fixture_owns_its_fork() {
    let root = repo(
        "fixture-forks-declared",
        &[],
        &[(
            "crates/batten/tests/it/new_gate.rs",
            &format!("// needs-real-fixture: CLOUD-1 the subject is init itself\n{FORKING}\n"),
        )],
    );
    assert!(
        verdicts(&root).is_empty(),
        "a fixture whose subject IS initialisation declares it and owns it"
    );
}

/// ANTI-VACUITY ON THE SCOPE. The engine's own source has the same content and
/// is not this rule's business — without the anchor the rule would refuse
/// `git.rs`, and with a wrong anchor it would refuse nothing at all while still
/// passing every case above.
#[test]
fn a_path_outside_the_suite_is_not_this_rules_business() {
    let root = repo(
        "fixture-forks-outside",
        &[],
        &[("crates/batten/src/git.rs", &format!("{FORKING}\n"))],
    );
    assert!(
        verdicts(&root).is_empty(),
        "the rule is about the integration suite's fixtures"
    );
}
