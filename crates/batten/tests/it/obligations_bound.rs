//! `obligations-bound`, over the engine that builds its input (CLOUD-472).
//!
//! # The seam, and why the module's own suite cannot reach it
//!
//! `policy/obligations-bound.rego`'s `test_` rules pin the predicate against a
//! fabricated document. The question that decides whether this gate is alive is
//! a different one: does the ENGINE put the recorded obligation column at
//! `input.tree.records`, and does it put the named file's lines at
//! `input.tree.lines` under a key the predicate spells the same way?
//!
//! Both have a specific way to fail silently. The column is the eighth field of
//! a record line, so an off-by-one reads a neighbouring column and finds no
//! `:` — which looks exactly like "this row declared no obligations". And
//! `input.tree.lines` is keyed by declared path, so an obligation naming a file
//! outside the row's `line_sources` resolves to nothing and the slug can never
//! be found, which reads exactly like "the case has no mutation". A `with input
//! as` case cannot distinguish either, because it fabricates the shape it wants.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule, RuleKind, RuleScope};

/// A fixture repository carrying a board record and, optionally, the case file
/// an obligation names.
fn repo(name: &str, record: &[&str], case: Option<(&str, &str)>) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let base = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", &base]);

    if let Some((path, body)) = case {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).expect("case parent");
        fs::write(full, body).expect("write the case file");
    }

    install_module(&root);
    write_record(&root, record);
    root
}

fn write_record(root: &Path, lines: &[&str]) {
    let git_dir = common::git_in(root, &["rev-parse", "--absolute-git-dir"]);
    let path =
        batten::recorder::record_path(Path::new(git_dir.trim()), "board-writes", "work", None);
    fs::create_dir_all(path.parent().unwrap()).expect("receipts dir");
    fs::write(path, format!("{}\n", lines.join("\n"))).expect("write the record");
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/obligations-bound.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/obligations-bound.rego")).expect("install committed module");
}

/// The committed row's shape, including `line_sources` — the field this suite
/// exists to keep honest, since a glob that misses the named file makes every
/// obligation unbindable for a reason no message would name.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "obligations-bound",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "line_sources": ["crates/batten/tests/**/*.rs", "policy/*.rego"],
        "module": "policy/obligations-bound.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn recorders() -> Vec<batten::recorder::Declared> {
    vec![batten::recorder::Declared {
        name: "board-writes".to_owned(),
        record: "board-writes".to_owned(),
        tool: "save_issue".to_owned(),
        key: batten::recorder::RecordKey::Branch,
        requires: Vec::new(),
        refused_when_input: Vec::new(),
        requires_input_matching: std::collections::BTreeMap::new(),
        requires_recorded: None,
        columns: vec![batten::recorder::Column {
            name: "kind".to_owned(),
            value: batten::recorder::Value::Literal("issue".to_owned()),
            minus: None,
            without: None,
            counted_with: None,
            zero_is_a_count: false,
        }],
    }]
}

fn verdicts(root: &Path) -> Vec<String> {
    let declared = recorders();
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &declared,
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

const UNBOUND: &str = "obligation-unbound";

/// The record line the recorder writes: eight fields, with the obligation set
/// last. Built here rather than inlined so an off-by-one in the module's column
/// index is a failure in every case at once rather than a silent pass in each.
fn line(obligations: &str) -> String {
    format!("issue CLOUD-1 2026-01-01T00:00:00Z ready - - - {obligations}")
}

// ---------------------------------------------------------------------------
// THE READ SEAM.
// ---------------------------------------------------------------------------

/// A bound obligation is clean, and this is the case that proves the ENGINE
/// reaches both inputs: the record's eighth column AND the named file's lines.
/// If either resolved to nothing, this would pass for the wrong reason — so the
/// refusal cases below are what give it meaning, and it is what gives them
/// theirs.
#[test]
fn a_bound_obligation_reaches_the_predicate_and_is_clean() {
    let root = repo(
        "obligations-bound-clean",
        &[&line("1,crates/batten/tests/it/x.rs:slug-one")],
        Some((
            "crates/batten/tests/it/x.rs",
            "#MUTANT slug-one|s@a@b@|the_case\n",
        )),
    );
    assert!(
        verdicts(&root).is_empty(),
        "the obligation names a tracked file whose lines declare the slug: {:?}",
        verdicts(&root)
    );
}

#[test]
fn an_obligation_naming_no_tracked_file_is_refused() {
    let root = repo(
        "obligations-no-file",
        &[&line("1,crates/batten/tests/it/missing.rs:slug-one")],
        None,
    );
    assert_eq!(verdicts(&root), vec![UNBOUND.to_owned()]);
}

/// THE FILE EXISTS AND THE PROMISE IS STILL UNKEPT. A case with no mutation is a
/// case nothing has shown can fail, which is CLOUD-418's whole finding — and it
/// is a different remedy from a missing file, which is why the module carries
/// two arms rather than one.
#[test]
fn an_obligation_whose_slug_no_row_declares_is_refused() {
    let root = repo(
        "obligations-no-slug",
        &[&line("1,crates/batten/tests/it/x.rs:slug-one")],
        Some((
            "crates/batten/tests/it/x.rs",
            "#MUTANT other-slug|s@a@b@|the_case\n",
        )),
    );
    assert_eq!(verdicts(&root), vec![UNBOUND.to_owned()]);
}

/// COULD-NOT-LOOK PASSES. A prose-dialect Ready block emits no obligations line,
/// so the column records `-`, and reading that as "declares none" would exempt
/// exactly the rows this gate exists for.
#[test]
fn a_row_with_no_obligations_column_is_not_judged() {
    let root = repo("obligations-absent", &[&line("-")], None);
    assert!(
        verdicts(&root).is_empty(),
        "`-` is could-not-look: {:?}",
        verdicts(&root)
    );
}

/// A MEASURED ZERO IS AN ANSWER. The object was read and declares no
/// obligations, which is a legitimate Ready block and must not be refused.
#[test]
fn a_row_declaring_no_obligations_passes() {
    let root = repo("obligations-zero", &[&line("0")], None);
    assert!(verdicts(&root).is_empty(), "{:?}", verdicts(&root));
}

/// ANTI-VACUITY over the whole file: the row this suite exercises is the one the
/// committed config declares, so a rename or a scope change reddens here rather
/// than leaving every case above passing over a module nothing runs.
#[test]
fn the_committed_row_is_the_one_these_cases_exercise() {
    let committed: Vec<Rule> = batten::config::load(&common::at_root("batten.toml"))
        .expect("the committed config loads")
        .rules;
    let declared = committed
        .iter()
        .find(|rule| rule.id == "obligations-bound")
        .expect("the committed config declares the row this suite exercises");
    assert_eq!(declared.kind, RuleKind::Policy);
    assert_eq!(declared.scope, RuleScope::Tree);
    assert!(
        declared
            .line_sources
            .iter()
            .any(|glob| glob.contains("crates/batten/tests")),
        "an obligation naming a case file must be resolvable, or the slug can \
         never be found and the gate refuses for a reason no message names: {:?}",
        declared.line_sources
    );
}
