//! The epoch an admission binds is its own rule's (CLOUD-2779).
//!
//! It used to be the whole config surface's, so any `batten.toml` edit unbound
//! every outstanding admission: on #1276 narrowing one `[[pattern]]` unbound
//! four, and the `filed-row-settled` handler then refused every edit. Each case
//! holds one side of the property: an edit to what does not decide the rule
//! leaves its epoch alone, and an edit to what does moves it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common::Fixture;

/// A mediated shape rule, the module rule's row and module, and one pattern.
const CONFIG: &str = r#"version = 1

[[rule]]
id = "shape-refuses"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "never-matches-anything"
reason = "the fixture's shape row; it exists to be bound, never to fire"

[[rule]]
id = "module-refuses"
no_fix_reason = "class 3 (a call rewrite): the fixture's module row"
kind = "policy"
scope = "mediated_call"
module = "policy/fixture.rego"
severity = "deny"

[[pattern]]
id = "unrelated"
regex = 'one'
"#;

const MODULE: &str = "package fixture\n";

fn repo(name: &str, config: &str, module: &str) -> PathBuf {
    Fixture::at(std::env::temp_dir().join("batten-epoch-rule").join(name))
        .config(config)
        .files(&[("policy/fixture.rego", module)])
        .build()
}

fn epoch(dir: &Path, rule: &str) -> String {
    batten::epoch::for_rule(dir, None, rule, rule).expect("the rule's epoch resolves")
}

/// Fails by: a row no part of `shape-refuses` reads moving its epoch, which is
/// the defect — a pattern edit unbinding an admission it cannot affect.
#[test]
fn an_unrelated_pattern_leaves_a_rules_epoch_unchanged() {
    let before = repo("unrelated-before", CONFIG, MODULE);
    let edited = CONFIG.replace("regex = 'one'", "regex = 'two'");
    let after = repo("unrelated-after", &edited, MODULE);
    assert_eq!(
        epoch(&before, "shape-refuses"),
        epoch(&after, "shape-refuses")
    );
    // ...while the whole surface's epoch, the one admissions used to bind, moves.
    assert_ne!(
        batten::epoch::compute(&before, None).unwrap(),
        batten::epoch::compute(&after, None).unwrap()
    );
    // A comment is no rule's either.
    let commented = repo("unrelated-comment", &format!("# a note\n{CONFIG}"), MODULE);
    assert_eq!(
        epoch(&before, "shape-refuses"),
        epoch(&commented, "shape-refuses")
    );
}

/// Fails by: an edit to the rule's own row leaving its admissions bound.
#[test]
fn a_rules_own_row_moves_its_epoch() {
    let before = repo("own-row-before", CONFIG, MODULE);
    let edited = CONFIG.replace(
        "pattern = \"never-matches-anything\"",
        "pattern = \"matches-something-else\"",
    );
    let after = repo("own-row-after", &edited, MODULE);
    assert_ne!(
        epoch(&before, "shape-refuses"),
        epoch(&after, "shape-refuses")
    );
    // The other rule's epoch does not move with it.
    assert_eq!(
        epoch(&before, "module-refuses"),
        epoch(&after, "module-refuses")
    );
}

/// Fails by: a module edit leaving the module rule's admissions bound, or a
/// pattern the module may read by id not counting for it.
#[test]
fn a_rules_own_module_moves_its_epoch() {
    let before = repo("module-before", CONFIG, MODULE);
    let after = repo("module-after", CONFIG, "package fixture\n\nx := 1\n");
    assert_ne!(
        epoch(&before, "module-refuses"),
        epoch(&after, "module-refuses")
    );
    assert_eq!(
        epoch(&before, "shape-refuses"),
        epoch(&after, "shape-refuses")
    );
    let pattern = CONFIG.replace("regex = 'one'", "regex = 'two'");
    let repatterned = repo("module-pattern", &pattern, MODULE);
    assert_ne!(
        epoch(&before, "module-refuses"),
        epoch(&repatterned, "module-refuses")
    );
}
