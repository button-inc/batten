//! `policy/raw-output-ratchet.rego` over the COMPILED engine (CLOUD-2488).
//!
//! The module's own `test_` cases pin the predicate. This tier pins what they
//! cannot: that the engine builds `base-lines` for the committed side, and that
//! the three `[[pattern]]` rows the module reads compile and match the shapes
//! rustfmt actually writes — `cfg_gated_test.rs` records why a module reading a
//! key the engine never filled reports clean over every branch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares, not the `[[rule]]` id.
const LOOSE: &str = "output write loose";

/// A fixture repository whose base commit carries `before` and whose working
/// tree carries `after`, at one Rust path. Shape as `cfg_gated_test.rs`'s.
fn repo(name: &str, before: &[&str], after: &[&str]) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);

    let subject = root.join("crates/batten/src/subject.rs");
    fs::create_dir_all(subject.parent().expect("a parent")).expect("scratch parent");
    fs::write(&subject, join(before)).expect("seed the committed side");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    common::pin_origin_main(&root);

    fs::write(&subject, join(after)).expect("write the working side");

    let source = common::at_root("policy/raw-output-ratchet.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/raw-output-ratchet.rego"))
        .expect("install committed module");
    root
}

fn join(lines: &[&str]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "output write unseen",
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": ["**"],
        "line_sources": ["crates/**/*.rs"],
        "module": "policy/raw-output-ratchet.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

/// The three rows as the COMMITTED config declares them, read from it rather
/// than re-typed, so a regex edited there is the regex tested here.
fn patterns() -> Vec<batten::pattern::NamedPattern> {
    let config: toml::Value = toml::from_str(
        &fs::read_to_string(common::at_root("batten.toml")).expect("the committed config"),
    )
    .expect("the committed config parses");
    let wanted = ["raw-writeln-inline", "raw-writeln-open", "raw-literal-text"];
    let found: Vec<batten::pattern::NamedPattern> = config["pattern"]
        .as_array()
        .expect("[[pattern]] rows")
        .iter()
        .filter(|row| wanted.contains(&row["id"].as_str().unwrap_or("")))
        .map(|row| batten::pattern::NamedPattern {
            id: row["id"].as_str().unwrap().to_owned(),
            regex: row["regex"].as_str().unwrap().to_owned(),
        })
        .collect();
    assert_eq!(
        found.len(),
        wanted.len(),
        "every row the module reads is declared"
    );
    found
}

fn classes(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    let patterns = patterns();
    let scanned = rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            registers: &[],
            traversals: &[],
            records: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row");
    scanned
        .findings
        .iter()
        .filter_map(|finding| {
            scanned
                .classes
                .get(&finding.identity.fingerprint.to_hex())
                .cloned()
        })
        .collect()
}

/// THE REFUSAL. `#MUTANT direction-may-invert` reddens here.
#[test]
fn a_branch_that_adds_a_raw_writeln_is_refused() {
    let root = repo(
        "raw-output-added",
        &["fn a() {}"],
        &["fn a() {", "    writeln!(out, \"land: lap {n}\")?;", "}"],
    );
    assert_eq!(classes(&root), vec![LOOSE.to_owned()]);
}

/// rustfmt's three-line form is the MAJORITY of the class, so a one-line
/// pattern alone would miss it. `#MUTANT reach-may-be-empty` reddens here.
#[test]
fn a_multiline_raw_writeln_is_counted() {
    let root = repo(
        "raw-output-multiline",
        &["fn a() {}"],
        &[
            "fn a() {",
            "    writeln!(",
            "        err,",
            "        \"land: stopped after {laps} lap(s)\",",
            "    )?;",
            "}",
        ],
    );
    assert_eq!(classes(&root), vec![LOOSE.to_owned()]);
}

/// THE CASE THAT MAKES A RATCHET SURVIVABLE: ~385 sites exist, and an edit to a
/// file carrying one must pass. `#MUTANT base-may-read-as-empty` reddens here.
#[test]
fn a_pre_existing_raw_writeln_survives_an_edit() {
    let root = repo(
        "raw-output-preexisting",
        &["fn a() {", "    writeln!(out, \"land: lap\")?;", "}"],
        &[
            "fn a() {",
            "    writeln!(out, \"land: lap\")?;",
            "}",
            "",
            "// an unrelated edit",
        ],
    );
    assert!(classes(&root).is_empty(), "the count did not go up");
}

/// The typed emitter's own call shape is the remedy, so it has to pass.
/// `#MUTANT text-test-dropped` reddens here.
#[test]
fn a_placeholder_only_writeln_is_not_counted() {
    let root = repo(
        "raw-output-placeholder",
        &["fn a() {}"],
        &[
            "fn a() {",
            "    writeln!(out, \"{}\", progress.line())?;",
            "    writeln!(",
            "        err,",
            "        \"{} {}\",",
            "        a, b,",
            "    )?;",
            "}",
        ],
    );
    assert!(classes(&root).is_empty(), "no letter outside a placeholder");
}

/// COULD NOT LOOK IS REPORTED, NEVER PASSED. `#MUTANT could-not-look-passes`
/// reddens here.
#[test]
fn a_missing_delta_is_reported_not_passed() {
    let root = repo(
        "raw-output-no-base",
        &["fn a() {}"],
        &["fn a() {", "    writeln!(out, \"land: lap\")?;", "}"],
    );
    fs::remove_file(root.join(".git/refs/remotes/origin/main")).expect("unpin the base ref");
    assert_eq!(classes(&root), vec!["diff read absent".to_owned()]);
}
