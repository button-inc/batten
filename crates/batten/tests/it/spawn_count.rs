//! `spawn count ahead` (#1276): the spawn census as a ratchet. Engine source's
//! `clippy::disallowed_types` escapes, counted off the parsed syntax tree
//! (`counts = "lint_escapes"`), may only fall against `origin/main`. Whatever
//! `main` carries is the baseline, so no site needs approving one by one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::common;
use batten::rules::{self, Rule};

/// The row as `batten.toml` declares it, through the same column census.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "spawn count ahead",
        "kind": "ratchet",
        "glob": "crates/batten/src/**/*.rs",
        "counts": "lint_escapes",
        "pattern": "clippy::disallowed_types",
        "direction": "non_increasing",
        "base": "origin/main",
        "severity": "deny",
        "scope": "tree",
        "no_fix_reason": "a fixture row",
    }))
    .expect("the row batten.toml declares")
}

/// A repository whose `origin/main` carries `base`, with `head` written over it.
fn repo(name: &str, base: &[(&str, &str)], head: &[(&str, &str)]) -> PathBuf {
    let root = common::scratch(&format!("spawn-count-{name}"));
    common::git_in(&root, &["init", "--initial-branch=main"]);
    write_all(&root, base);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-m", "base"]);
    let base_sha = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", &base_sha],
    );
    write_all(&root, head);
    root
}

fn write_all(root: &Path, files: &[(&str, &str)]) {
    for (path, body) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, body).unwrap();
    }
}

fn verdicts(root: &Path) -> Vec<String> {
    let patterns = common::committed_patterns();
    let declared = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &patterns,
            verdicts: &declared,
            words: None,
            recorders: &[],
            registers: &[],
            traversals: &[],
            records: &[],
        },
        root,
    )
    .expect("the ratchet runs")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

const ONE: &str =
    "#[expect(\n    clippy::disallowed_types,\n    reason = \"stays: one\"\n)]\nfn one() {}\n";

const TWO: &str = "#[expect(\n    clippy::disallowed_types,\n    reason = \"stays: one\"\n)]\nfn one() {}\n#[expect(\n    clippy::disallowed_types,\n    reason = \"stays: two\"\n)]\nfn two() {}\n";

/// Fails by: an added escape not counted, including one whose text repeats an
/// escape the base already carried byte for byte (the set comparison
/// `spawn-widening` used could not see it, measured on #1276).
#[test]
fn an_added_escape_is_refused_even_when_its_text_repeats_one() {
    let root = repo(
        "added",
        &[("crates/batten/src/thing.rs", ONE)],
        &[("crates/batten/src/thing.rs", TWO)],
    );
    assert_eq!(verdicts(&root), vec![String::from("spawn count ahead")]);
}

/// Fails by: a site `main` already carries treated as needing approval, or an
/// escape moved between files read as an addition. The baseline is `main`.
#[test]
fn the_sites_main_carries_and_a_moved_escape_are_clean() {
    let root = repo(
        "moved",
        &[
            ("crates/batten/src/a.rs", TWO),
            ("crates/batten/src/b.rs", "fn b() {}\n"),
        ],
        &[
            ("crates/batten/src/a.rs", ONE),
            ("crates/batten/src/b.rs", ONE),
        ],
    );
    assert!(verdicts(&root).is_empty(), "two on main, two at head");
}

/// Fails by: an escape added beside one retired read as growth. A branch that
/// adds a site pays for it by retiring another.
#[test]
fn an_escape_added_while_one_is_retired_is_clean() {
    let root = repo(
        "traded",
        &[
            ("crates/batten/src/a.rs", ONE),
            ("crates/batten/src/b.rs", "fn b() {}\n"),
        ],
        &[
            ("crates/batten/src/a.rs", "fn one() {}\n"),
            ("crates/batten/src/b.rs", ONE),
        ],
    );
    assert!(verdicts(&root).is_empty());
}

/// Fails by: prose naming the lint counted as an escape. Only an attribute's
/// own list is read.
#[test]
fn a_doc_line_naming_the_lint_is_not_an_escape() {
    let root = repo(
        "prose",
        &[("crates/batten/src/thing.rs", ONE)],
        &[(
            "crates/batten/src/thing.rs",
            &format!(
                "{ONE}/// `#[expect(clippy::disallowed_types)]` is the spawn census.\nfn documented() {{}}\n"
            ),
        )],
    );
    assert!(verdicts(&root).is_empty());
}
