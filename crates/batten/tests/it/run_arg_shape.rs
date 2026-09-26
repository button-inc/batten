//! `policy/run-arg-shape.rego` over the COMPILED engine (CLOUD-1916).
//!
//! The module's `test_` rules pin the predicate over a fabricated
//! `input.tree.lines`; this tier pins that the engine actually reads
//! `mise.toml` into that key under the committed row's `line_sources`, and that
//! the committed `mise.toml` itself is clean. A module reading a key the engine
//! never fills reports clean over every tree while its own suite stays green.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// The predicate id the module declares, not the `[[rule]]` id.
const DROPPED: &str = "task read unseen";

/// The pre-fix `darwin-link` body, verbatim in shape: the x86_64 required check
/// ran this and linked aarch64.
const PRE_FIX_DARWIN_LINK: &str =
    r#"run = "t=\"${1:-${DARWIN_TARGET:-aarch64-apple-darwin}}\"; echo \"darwin-link: $t\"""#;

/// The pre-fix `ci-slow-needed` shape: arguments read as `$1`/`$2` in a bare body.
const PRE_FIX_CI_SLOW_NEEDED: &str =
    r#"run = "base=\"$1\"; head=\"$2\"; git diff --quiet \"$base\" \"$head\"""#;

/// The fix, for both.
const FUNCTION_SHAPED: &str =
    r#"run = "darwin_link() { t=\"${1:-aarch64-apple-darwin}\"; echo \"$t\"; }; darwin_link""#;

fn repo(name: &str, mise_toml: &str) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);
    fs::write(root.join("mise.toml"), format!("[tasks.x]\n{mise_toml}\n"))
        .expect("write mise.toml");
    let source = common::at_root("policy/run-arg-shape.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/run-arg-shape.rego")).expect("install committed module");
    commit(&root);
    root
}

/// `line_sources` reads TRACKED paths, so an uncommitted `mise.toml` is invisible
/// to the engine and every refusal case would pass vacuously.
fn commit(root: &Path) {
    common::git_in(root, &["add", "-A"]);
    common::git_in(root, &["commit", "--quiet", "-m", "fixture"]);
}

/// The committed row's shape, `line_sources` included: without it the module
/// reads no lines and refuses nothing.
fn row() -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": "task read dropped",
        "kind": "policy",
        "scope": "tree",
        "line_sources": ["mise.toml"],
        "module": "policy/run-arg-shape.rego",
        "severity": "deny",
    }))
    .expect("the loader accepts the committed row's shape")
}

fn verdicts(root: &Path) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row()],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            words: None,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

/// `#MUTANT bare-body-arg-admitted` reddens here.
#[test]
fn a_bare_body_reading_its_first_argument_is_refused() {
    let root = repo("run-arg-darwin", PRE_FIX_DARWIN_LINK);
    assert_eq!(verdicts(&root), vec![DROPPED.to_owned()]);
}

#[test]
fn the_pre_fix_ci_slow_needed_body_is_refused() {
    let root = repo("run-arg-slow", PRE_FIX_CI_SLOW_NEEDED);
    assert_eq!(verdicts(&root), vec![DROPPED.to_owned()]);
}

/// The pass side: without it the refusals above are satisfied by a module that
/// refuses every body.
#[test]
fn the_function_shaped_body_passes() {
    let root = repo("run-arg-fn", FUNCTION_SHAPED);
    assert!(verdicts(&root).is_empty());
}

/// The committed `mise.toml` is clean, which is what makes this a state rule
/// rather than a ratchet.
#[test]
fn the_committed_task_table_reads_no_dropped_argument() {
    let root = repo("run-arg-committed", "");
    fs::copy(common::at_root("mise.toml"), root.join("mise.toml"))
        .expect("copy committed mise.toml");
    commit(&root);
    assert!(verdicts(&root).is_empty());
}
