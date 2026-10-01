//! Three task-body gates retired onto policy modules over the compiled engine
//! (CLOUD-1991): `hk-version` onto `policy/hk-pin-agreement.rego`, `no-docs-tree`
//! onto `policy/docs-tree-absent.rego`, and `no-armed-ripcord` onto
//! `policy/ripcord-untracked.rego`.
//!
//! # Why this tier and not only the modules' own `test_` rules
//!
//! A `with input as` case writes the shape it then reads, so it is green over a
//! key the engine never fills (CLOUD-845). Every case here goes in through
//! `batten check` over a fixture repository, so what it pins is that the engine
//! FILLS `input.tree.documents["mise.toml"]`, `input.tree.lines["hk.pkl"]` and
//! `input.tree["git-index"][<spec>]` for the rows as `batten.toml` declares them,
//! and that `data.batten.patterns` reaches the module from a `[[pattern]]` row.
//!
//! # RETIREMENT LEDGER — the three `mise.toml` bodies
//!
//! The bodies were inline task shell, not governed paths, so they owe no
//! file-granularity arm; the properties each asserted are carried case by case.
//!
// carried: "hk-version: mise.toml and hk.pkl agree on the hk version" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// carried: "hk-version: a drift between the two pins is refused" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// carried: "hk-version: a pin neither file names refuses rather than passes (`:?`)" policy/hk-pin-agreement.rego crates/batten/tests/it/tracked_absent.rs
// changed: "hk-version: only the first `hk@` in hk.pkl is compared" policy/hk-pin-agreement.rego the module compares every `hk@<version>` the file names, so a second amends line naming another version is refused rather than shadowed by `head -n1`
// carried: "no-docs-tree: a tracked path under docs/ is refused, naming one" policy/docs-tree-absent.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-docs-tree: a tree with no docs/ passes" policy/docs-tree-absent.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-armed-ripcord: a tracked sentinel is refused" policy/ripcord-untracked.rego crates/batten/tests/it/tracked_absent.rs
// carried: "no-armed-ripcord: an armed but untracked sentinel passes" policy/ripcord-untracked.rego crates/batten/tests/it/tracked_absent.rs
// changed: "the three gates run in the pre-commit tier" hk.pkl their hk steps are `slow` now, because the task is `batten check` over a module and a commit may not pay a compile (CLOUD-1397); `batten-check`'s `enforce` also judges all three rows at `verify` and in CI, so what moves is WHEN a violation is caught, from the commit to the landing path

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The rows and classes a fixture carries, hand-built rather than copied from
/// the committed authority for `mise_pin_agreement.rs`'s reason: the whole
/// authority drags every other row's module into a tree that does not have one.
const AUTHORITY: &str = r#"version = 1

[[pattern]]
id = "hk-amends-version"
regex = 'hk@([0-9]+\.[0-9]+\.[0-9]+)'

[[rule]]
id = "tool pin other"
kind = "policy"
scope = "tree"
documents = ["mise.toml"]
line_sources = ["hk.pkl"]
module = "policy/hk-pin-agreement.rego"
severity = "deny"
reason = "set both pins to one version."

[[rule]]
id = "prose place refused"
kind = "policy"
scope = "tree"
index = ["docs"]
module = "policy/docs-tree-absent.rego"
severity = "deny"
reason = "research belongs on the tracker row."

[[rule]]
id = "path ship refused"
kind = "policy"
scope = "tree"
index = [".batten-ripcord"]
module = "policy/ripcord-untracked.rego"
severity = "deny"
reason = "remove the sentinel from the index."

[[verdict]]
id = "tool pin other"
gloss = "hk.pkl names a different hk than mise.toml pins"
class = """
Set both to one version.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/hk-pin-agreement.rego"

[[verdict]]
id = "prose place refused"
gloss = "a path under docs/ is tracked"
class = """
Move it onto the tracker row.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/docs-tree-absent.rego"

[[verdict]]
id = "path ship refused"
gloss = "the break-glass sentinel is tracked"
class = """
Remove it from the index.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/ripcord-untracked.rego"
"#;

const MODULES: [&str; 3] = [
    "policy/hk-pin-agreement.rego",
    "policy/docs-tree-absent.rego",
    "policy/ripcord-untracked.rego",
];

/// An `amends` line in the shape `hk.pkl` really spells it.
fn amends(version: &str) -> String {
    format!(
        "amends \"package://github.com/jdx/hk/releases/download/v{version}/hk@{version}#/Config.pkl\"\n"
    )
}

/// A committed fixture repository carrying the three committed modules, the
/// authority above, agreeing hk pins, and whatever else the case adds.
///
/// COMMITTED, because `line_sources` and the index projection read tracked
/// paths: an uncommitted fixture would be invisible and every refusal below
/// would pass vacuously.
fn fixture(name: &str, files: &[(&str, &str)], force_add: &[&str]) -> PathBuf {
    let root = common::scratch(&format!("tracked-absent-{name}"));
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    for module in MODULES {
        let source = common::at_root(module)
            .canonicalize()
            .expect("the committed module is where the row says it is");
        fs::copy(source, root.join(module)).expect("install committed module");
    }
    fs::write(root.join("batten.toml"), AUTHORITY).expect("write the fixture authority");
    fs::write(root.join("mise.toml"), "[tools]\nhk = \"1.56.1\"\n").expect("mise.toml");
    fs::write(root.join("hk.pkl"), amends("1.56.1")).expect("hk.pkl");
    for (path, body) in files {
        if let Some(parent) = root.join(path).parent() {
            fs::create_dir_all(parent).expect("fixture parent");
        }
        fs::write(root.join(path), body).expect("write a fixture file");
    }
    common::init_repo(&root);
    common::git_in(&root, &["add", "-A"]);
    for path in force_add {
        common::git_in(&root, &["add", "-f", path]);
    }
    common::git_in(&root, &["commit", "-q", "-m", "fixture"]);
    root
}

/// `batten check` over the fixture: its exit code and everything it said.
fn check(root: &Path) -> (Option<i32>, String) {
    let output = common::run(root, &["check"]);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code(), said)
}

fn denied(root: &Path, rule: &str, pointer: &str) {
    let (code, said) = check(root);
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Violation.code()),
        "expected the policy verdict: {said}"
    );
    assert!(said.contains(rule), "the finding names `{rule}`: {said}");
    assert!(
        said.contains(pointer),
        "the finding points at `{pointer}`: {said}"
    );
}

fn clean(root: &Path) {
    let (code, said) = check(root);
    assert_eq!(
        code,
        Some(batten::exit::ExitCode::Success.code()),
        "expected a clean tree: {said}"
    );
}

// ---------------------------------------------------------------------------
// The pass side first: without it every refusal below is satisfied by modules
// that refuse everything.
// ---------------------------------------------------------------------------

#[test]
fn agreeing_pins_no_docs_and_no_sentinel_are_clean() {
    let root = fixture("clean", &[], &[]);
    clean(&root);
}

// ---------------------------------------------------------------------------
// hk-version.
// ---------------------------------------------------------------------------

/// `#MUTANT hk-pin-disagreement-passes` reddens here.
#[test]
fn a_version_the_amends_url_names_differently_is_refused() {
    let root = fixture(
        "hk-drift",
        &[("mise.toml", "[tools]\nhk = \"1.57.0\"\n")],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

/// `#MUTANT hk-amends-unnamed-passes` reddens here: the shell's `:?` on an
/// `hk.pkl` whose `amends` names no version.
#[test]
fn an_hk_pkl_naming_no_version_is_refused() {
    let root = fixture(
        "hk-unnamed",
        &[(
            "hk.pkl",
            "amends \"package://example.invalid/Config.pkl\"\n",
        )],
        &[],
    );
    denied(&root, "tool pin other", "hk.pkl");
}

// ---------------------------------------------------------------------------
// no-docs-tree.
// ---------------------------------------------------------------------------

/// `#MUTANT docs-tree-admitted` reddens here.
#[test]
fn a_tracked_docs_file_is_refused() {
    let root = fixture("docs", &[("docs/notes.md", "# notes\n")], &[]);
    denied(&root, "prose place refused", "docs/notes.md");
}

/// A path that merely STARTS with `docs` is not under the tree.
#[test]
fn a_sibling_named_like_docs_is_not_the_docs_tree() {
    let root = fixture("docs-sibling", &[("docsite/index.md", "# site\n")], &[]);
    clean(&root);
}

// ---------------------------------------------------------------------------
// no-armed-ripcord.
// ---------------------------------------------------------------------------

/// `#MUTANT ripcord-admitted` reddens here. The sentinel is ignored by name, as
/// it is in this repository, so reaching the index takes `git add -f` — the
/// case the gate exists for.
#[test]
fn a_force_added_sentinel_is_refused() {
    let root = fixture(
        "ripcord-tracked",
        &[(".gitignore", ".batten-ripcord\n"), (".batten-ripcord", "")],
        &[".batten-ripcord"],
    );
    denied(&root, "path ship refused", ".batten-ripcord");
}

/// ARMED is not SHIPPED: an ignored sentinel in the working tree is one
/// operator's break-glass and reaches no clone.
#[test]
fn an_armed_but_ignored_sentinel_is_clean() {
    let root = fixture(
        "ripcord-armed",
        &[(".gitignore", ".batten-ripcord\n"), (".batten-ripcord", "")],
        &[],
    );
    clean(&root);
}
