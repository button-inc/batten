//! CLOUD-850 §2(b): N rows declaring one path read and parse it **once**.
//!
//! **Its own test binary, for the same reason `policy_input_narrowing.rs` is
//! one**: `rules::documents_acquired` is a process-global counter, so a sibling
//! case acquiring a document in the same process would race the delta below
//! under a harness that threads rather than forks.
//!
//! **A counter rather than a clock**, per `.claude/rules/rust.md`: a single
//! small read is well inside the noise of a process start, so a timing
//! assertion here discriminates nothing. That is exactly how CLOUD-460's four
//! subprocesses per call went unmeasured.
//!
//! Asserted through `run_static` — the public surface a consumer reaches —
//! rather than by widening the acquisition helpers to `pub` for a test's
//! convenience.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// A bundle that decides over a declared document, so a row actually evaluates.
const READS_A_KEY: &str = r#"
package batten

import rego.v1

rules contains "no-stray-key"

violation contains {"rule": "no-stray-key", "msg": "a stray key"} if {
    input.tree.documents["config.toml"].stray
}
"#;

/// A row with its OWN bundle folder: `load` refuses two rows registering one
/// source ("two rows naming one source is dead config"), so the shared-read
/// property has to be shown across DISTINCT bundles — which is also the shape
/// the retirement produces, one migrated gate per bundle.
fn row(id: &str, documents: &[&str]) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "tree",
        "bundle": format!("policy-{id}/"),
        "documents": documents,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row the loader accepts")
}

/// Write one bundle folder per row, each holding the same predicate.
fn write_bundles(root: &Path, ids: &[&str]) {
    for id in ids {
        let dir = root.join(format!("policy-{id}"));
        fs::create_dir_all(&dir).expect("bundle folder");
        // A distinct PACKAGE and a distinct predicate id per bundle: `load`
        // refuses both a shared source and a shared id, because a finding names
        // one predicate and there is no precedence to resolve.
        let module = READS_A_KEY
            .replace("package batten", &format!("package batten.b{id}"))
            .replace("no-stray-key", &format!("no-stray-key-{id}"));
        fs::write(dir.join("gate.rego"), module).expect("module");
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-reads-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("policy")).expect("scratch");
    dir
}

#[test]
fn rows_declaring_one_path_read_it_once() {
    // THE DEFECT THIS ASSERTS AWAY. `run`'s `for rule in rules` wrapped
    // `tree_document`'s `for path in documents` with no dedup and no cache, so
    // two rows declaring one path read and parsed it twice — 79 rules x N
    // documents is 79N reads plus 79N parses, on the one surface `perf-assert`
    // deliberately budgets no ceiling for.
    //
    // Fails by: removing the cache lookup in `acquire_declared`, which makes
    // this delta 3 rather than 1.
    let root = scratch("shared");
    fs::write(root.join("config.toml"), "stray = true\n").expect("fixture");
    write_bundles(&root, &["first", "second", "third"]);

    let before = rules::documents_acquired();
    let scan = rules::run_static(
        &[
            row("first", &["config.toml"]),
            row("second", &["config.toml"]),
            row("third", &["config.toml"]),
        ],
        &[],
        &root,
    )
    .expect("the read surface runs the rows");
    let delta = rules::documents_acquired() - before;

    assert_eq!(
        delta, 1,
        "three rows over one path is ONE acquisition; the shared read is what \
         makes porting 82 bash gates into one engine affordable at all"
    );
    // And the rows still DECIDED — a cache that returned nothing would give a
    // delta of 1 for the wrong reason.
    assert!(
        !scan.findings.is_empty(),
        "the cached document reached the predicate"
    );

    // ANTI-VACUITY, in the same function: a counter that never moves would make
    // the assertion above pass however the cache behaved.
    let before = rules::documents_acquired();
    fs::write(root.join("other.toml"), "stray = true\n").expect("fixture");
    write_bundles(&root, &["fourth"]);
    let _ = rules::run_static(&[row("fourth", &["other.toml"])], &[], &root);
    assert!(
        rules::documents_acquired() > before,
        "the counter moves for a path not already cached, so the delta above \
         asserts something"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_glob_source_resolves_against_the_walk_rather_than_being_read_literally() {
    // CLOUD-850's headline: `documents = ["mise-tasks/*"]` was read as a file
    // with a `*` in its name, failed, landed in `missing`, and skipped the whole
    // rule — silently, green. A policy row was the ONE kind excluded from the
    // glob machinery every other kind uses, and it is the kind the retirement
    // migrates onto.
    let root = scratch("glob");
    fs::write(root.join("config.toml"), "stray = true\n").expect("fixture");
    write_bundles(&root, &["globbed"]);

    let globbed: Rule = serde_json::from_value(serde_json::json!({
        "id": "globbed",
        "kind": "policy",
        "scope": "tree",
        "bundle": "policy-globbed/",
        "sources": ["*.toml"],
        "severity": "deny",
    }))
    .expect("a row declaring a selector");

    let scan = rules::run_static(&[globbed], &[], &root).expect("the selector resolves");
    assert_eq!(
        scan.findings.len(),
        1,
        "the glob selected `config.toml` out of the walk and the predicate \
         decided over it: {:?}",
        scan.findings
    );

    let _ = fs::remove_dir_all(&root);
}
