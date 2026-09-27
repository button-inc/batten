//! `policy/spawn-factory.rego` over the COMPILED engine (CLOUD-1924).
//!
//! The module's `test_` rules pin the predicate over fabricated input; this tier
//! pins that the engine BUILDS `input.tree.lines` for the row's `line_sources`
//! glob, since a module reading a key the engine never filled reports clean over
//! every tree while its own load-time cases stay green.
//!
//! The live half — the committed rule over this crate's own tree — is
//! `batten-check` itself, which runs every `[[rule]]` on every commit.
//!
//! One case per arm a sweep mutates: both spellings of the return type are
//! refused, a named factory is not, and a `clap::Command` builder is not a spawn.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The module's own rule id, which is what a finding carries.
const LOOSE: &str = "spawn bind loose";

fn repo(name: &str, path: &str, source: &[&str]) -> PathBuf {
    let root = common::scratch(name);
    let subject = root.join(path);
    fs::create_dir_all(subject.parent().expect("a parent")).expect("scratch parent");
    let mut text = source.join("\n");
    text.push('\n');
    fs::write(&subject, text).expect("write the subject");
    let module = common::at_root("policy/spawn-factory.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(module, root.join("policy/spawn-factory.rego")).expect("install committed module");
    root
}

/// The committed row's shape, including the `line_sources` glob without which
/// the module reads no lines and refuses nothing.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "spawn bind loose",
        "kind": "policy",
        "scope": "tree",
        "line_sources": ["crates/**/*.rs"],
        "module": "policy/spawn-factory.rego",
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
fn a_factory_returning_the_qualified_command_is_refused() {
    let root = repo(
        "spawn-factory-qualified",
        "crates/batten/src/subject.rs",
        // Assembled, so this tier's own source never carries the return type the
        // live rule reads over `crates/**` (the same shape as `git.rs`'s needle).
        &[
            &["pub fn program(name: &str) -> std::process::", "Command {"].concat(),
            "    todo!()",
            "}",
        ],
    );
    assert_eq!(findings(&root), [LOOSE]);
}

#[test]
fn a_factory_returning_the_imported_command_is_refused() {
    let root = repo(
        "spawn-factory-imported",
        "crates/batten/tests/it/common/mod.rs",
        &[
            "use std::process::{Command, Output};",
            "pub(crate) fn program(name: &str) -> Command {",
            "    Command::new(name)",
            "}",
        ],
    );
    assert_eq!(findings(&root), [LOOSE]);
}

#[test]
fn a_named_factory_is_not_refused() {
    let root = repo(
        "spawn-factory-named",
        "crates/batten/tests/it/common/mod.rs",
        &[
            "use std::process::{Command, Output};",
            "pub(crate) fn git_command(dir: &Path, args: &[&str]) -> Command {",
            "    todo!()",
            "}",
        ],
    );
    assert!(findings(&root).is_empty());
}

#[test]
fn a_clap_command_builder_is_not_a_spawn() {
    let root = repo(
        "spawn-factory-clap",
        "crates/batten/src/surface.rs",
        &[
            "use clap::{Arg, ArgAction, Command};",
            "pub fn command() -> Command {",
            "    todo!()",
            "}",
        ],
    );
    assert!(findings(&root).is_empty());
}
