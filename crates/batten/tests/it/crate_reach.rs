//! `crate reach unsafe` (CLOUD-2798): the module's own cases, run through the
//! compiled binary's `policy test`, so its `#MUTANT` row reaches the shipped
//! file, and the record writer (`batten record derive crate-reach`) driven
//! over a fixture `cargo metadata` document on stdin. The reading's unit case
//! is `record::tests::the_crate_reach_reading_lists_each_members_reached_members_sorted`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

const CONFIG: &str = r#"version = 1

[[rule]]
id = "crate reach wrong"
kind = "policy"
scope = "tree"
module = "policy/crate-reach.rego"
severity = "deny"

[[verdict]]
id = "crate reach unsafe"
gloss = "a workspace crate reaches one its allow pattern does not admit"
class = """
A fixture verdict for the crate-reach module's own cases.
"""
[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/crate-reach.rego"

[[verdict]]
id = "crate declare absent"
gloss = "a workspace crate has no allow pattern"
class = """
A fixture verdict for the crate-reach module's own cases.
"""
[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/crate-reach.rego"
"#;

/// Fails by: the unlisted arm or the undeclared arm unread, which reddens one
/// of the module's three cases (`#MUTANT unlisted-admitted`).
#[test]
fn the_crate_reach_module_suite_passes() {
    let dir = common::scratch("crate-reach-suite");
    common::write(&dir, "batten.toml", CONFIG);
    common::write(
        &dir,
        "policy/crate-reach.rego",
        &std::fs::read_to_string(common::at_root("policy/crate-reach.rego")).unwrap(),
    );
    common::init_repo(&dir);
    let tested = common::batten()
        .current_dir(&dir)
        .args(["policy", "test"])
        .streamed_output()
        .expect("run policy test");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&tested.stdout),
        String::from_utf8_lossy(&tested.stderr)
    );
    assert!(said.contains("3 passed, 0 failed"), "{said}");
}

/// A `cargo metadata` document: `top` reaches `mid` directly and `low` through
/// it, and `ext` is no member. Packages and nodes are listed out of name order,
/// so a writer that echoed the document's order is not sorted.
const METADATA: &str = r#"{
  "packages": [
    {"id": "top 1.0.0", "name": "top", "dependencies": [{"name": "mid"}, {"name": "ext"}]},
    {"id": "low 1.0.0", "name": "low", "dependencies": []},
    {"id": "ext 1.0.0", "name": "ext", "dependencies": []},
    {"id": "mid 1.0.0", "name": "mid", "dependencies": [{"name": "low"}]}
  ],
  "resolve": {"nodes": [
    {"id": "top 1.0.0", "features": [], "deps": [{"pkg": "mid 1.0.0"}, {"pkg": "ext 1.0.0"}]},
    {"id": "low 1.0.0", "features": [], "deps": []},
    {"id": "ext 1.0.0", "features": [], "deps": []},
    {"id": "mid 1.0.0", "features": [], "deps": [{"pkg": "low 1.0.0"}]}
  ]},
  "workspace_members": ["top 1.0.0", "mid 1.0.0", "low 1.0.0"]
}"#;

/// THE WRITER, THROUGH THE VERB (CLOUD-2798 §7): over a fixture metadata
/// document, `record derive crate-reach` emits one `reach` line per member,
/// members and reached names sorted, and the same bytes on a second run.
/// Fails by: a member's own name in its reach, the external package listed, a
/// transitive member missed, or the lines in document order.
#[test]
fn the_record_writer_emits_sorted_stable_reach_lines() {
    let dir = common::scratch("crate-reach-writer");
    common::write(&dir, "batten.toml", "version = 1\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    let derive = || {
        let written = common::run_with_stdin(&dir, &["record", "derive", "crate-reach"], METADATA);
        assert!(
            written.status.success(),
            "the writer reads its graph: {}",
            String::from_utf8_lossy(&written.stderr)
        );
        String::from_utf8_lossy(&written.stdout).into_owned()
    };
    let first = derive();
    assert_eq!(first, "reach low\nreach mid low\nreach top low,mid\n");
    assert_eq!(derive(), first, "byte-stable across runs");
}
