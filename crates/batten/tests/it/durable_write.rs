//! `policy/durable-write.rego` over the COMPILED engine (CLOUD-1919).
//!
//! The module's `test_` rules pin the predicate over fabricated input; this tier
//! pins that the engine BUILDS `input.tree.lines` for the row's `line_sources`
//! glob, since a module reading a key the engine never filled reports clean over
//! every tree while its own load-time cases stay green.
//!
//! The live half — the committed rule over this crate's own tree — is
//! `batten-check` itself, which runs every `[[rule]]` on every commit.
//!
//! The four cases are the four arms a sweep mutates: each kind of raw write is
//! refused above a file's `#[cfg(test)]`, nothing below it is, and a line marked
//! `// stream:` is not.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::config_model::Rule;
use batten::rules;

/// The module's own rule id, which is what a finding carries.
const RAW: &str = "path write unsafe";

fn repo(name: &str, source: &[&str]) -> PathBuf {
    repo_at(name, "crates/batten/src/subject.rs", source)
}

fn repo_at(name: &str, path: &str, source: &[&str]) -> PathBuf {
    let root = common::scratch_repo(name);
    let subject = root.join(path);
    fs::create_dir_all(subject.parent().expect("a parent")).expect("scratch parent");
    let mut text = source.join("\n");
    text.push('\n');
    fs::write(&subject, text).expect("write the subject");
    let module = common::at_root("policy/durable-write.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(module, root.join("policy/durable-write.rego")).expect("install committed module");
    root
}

/// The committed row's shape, including the `line_sources` glob without which
/// the module reads no lines and refuses nothing — READ from `batten.toml`, not
/// restated: the hard-coded `crates/batten/src` copy outlived the row's widening
/// to every crate (CLOUD-2789).
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "path write unsafe",
        "kind": "policy",
        "scope": "tree",
        "line_sources": crate::source_scope::committed_rule_sources(RAW, "line_sources"),
        "module": "policy/durable-write.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn findings(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
            registers: &[],
            traversals: &[],
            records: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

#[test]
fn a_raw_fs_write_in_production_is_refused() {
    let root = repo(
        "durable-fs-write",
        &["fn f(p: &str) { let _ = std::fs::write(p, \"x\"); }"],
    );
    assert_eq!(findings(&root), [RAW]);
}

#[test]
fn a_raw_append_open_in_production_is_refused() {
    let root = repo(
        "durable-append",
        &["fn f(p: &str) { let _ = std::fs::OpenOptions::new().append(true).open(p); }"],
    );
    assert_eq!(findings(&root), [RAW]);
}

#[test]
fn a_write_inside_a_test_module_is_not_refused() {
    let root = repo(
        "durable-test-module",
        &[
            "pub fn f() {}",
            "#[cfg(test)]",
            "mod tests { fn g(p: &str) { let _ = std::fs::write(p, \"x\"); } }",
        ],
    );
    assert!(findings(&root).is_empty());
}

/// A test module ENDS: production after its closing brace is judged. The first
/// boundary was the file's first `#[cfg(test)]`, which let `forge.rs` write raw
/// below its test module, green (review of #962).
#[test]
fn production_after_a_closed_test_module_is_refused() {
    let root = repo(
        "durable-after-tests",
        &[
            "#[cfg(test)]",
            "mod tests {",
            "    fn g(p: &str) { let _ = std::fs::write(p, \"x\"); }",
            "}",
            "fn f(p: &str) { let _ = std::fs::write(p, \"x\"); }",
        ],
    );
    assert_eq!(findings(&root), [RAW]);
}

#[test]
fn a_line_marked_as_a_stream_is_not_refused() {
    let root = repo(
        "durable-stream",
        &["fn f(p: &str) { let _ = std::fs::File::create(p); } // stream: a child's stdout sink"],
    );
    assert!(findings(&root).is_empty());
}

/// CLOUD-2789: the crate split moved production code into `batten-base`,
/// `batten-core` and the rest, and a raw write there is the same torn file. The
/// fixture row is the committed one, so a row narrowed back to
/// `crates/batten/src` — or a module whose `production` reads one crate — goes
/// red here.
#[test]
fn a_raw_write_in_another_crate_is_refused() {
    let root = repo_at(
        "durable-other-crate",
        "crates/batten-base/src/subject.rs",
        &["fn f(p: &str) { let _ = std::fs::write(p, \"x\"); }"],
    );
    assert_eq!(findings(&root), [RAW]);
}
