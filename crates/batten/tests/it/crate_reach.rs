//! `crate reach unsafe` (CLOUD-2798): the module's own cases, run through the
//! compiled binary's `policy test`, so its `#MUTANT` row reaches the shipped
//! file. The record writer's reading is pinned by
//! `record::tests::the_crate_reach_reading_lists_each_members_reached_members_sorted`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::StreamedChild as _;

const CONFIG: &str = r#"version = 1

[[rule]]
id = "crate reach unsafe"
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
