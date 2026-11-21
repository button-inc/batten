use std::collections::BTreeMap;

use super::*;

fn tree(files: &[(&str, &str)]) -> BTreeMap<String, String> {
    files
        .iter()
        .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
        .collect()
}

/// A body spelled through each tree, mapped through the moves between them.
fn same(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    base_body: &str,
    head_body: &str,
) -> bool {
    let (base, head) = (Index::new(before), Index::new(after));
    let moves = moved_items(&base, &head);
    canonical(base_body, "batten", &base, &moves)
        == canonical(head_body, "batten", &head, &BTreeMap::new())
}

/// Fails by: a respelling at a moved item's new home compared as a modified
/// assertion, which is what made every move cost an admission.
#[test]
fn a_path_respelled_at_a_moved_items_home_names_the_same_item() {
    let before = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        ("crates/batten/src/rules.rs", "pub struct Rule;\n"),
        ("crates/batten/src/model.rs", ""),
    ]);
    let after = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        ("crates/batten/src/rules.rs", ""),
        ("crates/batten/src/model.rs", "pub struct Rule;\n"),
    ]);
    assert!(same(
        &before,
        &after,
        "{ let r = crate::rules::Rule; }",
        "{ let r = crate::model::Rule; }",
    ));
}

/// Fails by: a re-export not followed, so a body spelled through a shim at base
/// and at the defining module at head looked modified.
#[test]
fn a_re_export_names_the_item_it_re_exports() {
    let files = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        (
            "crates/batten/src/rules.rs",
            "pub use crate::model::Rule;\n",
        ),
        ("crates/batten/src/model.rs", "pub struct Rule;\n"),
    ]);
    assert!(same(
        &files,
        &files,
        "{ crate::rules::Rule::check(); }",
        "{ crate::model::Rule::check(); }",
    ));
}

/// Fails by: a module re-exported from a sibling crate not followed, so a
/// helper moved into `batten-core` looked like a different item.
#[test]
fn a_module_re_exported_from_a_sibling_crate_resolves_there() {
    let before = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub use batten_core::selector;\npub mod rules;\n",
        ),
        ("crates/batten/src/rules.rs", "pub fn glob_match() {}\n"),
        ("crates/batten-core/src/lib.rs", "pub mod selector;\n"),
        ("crates/batten-core/src/selector.rs", ""),
    ]);
    let after = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub use batten_core::selector;\npub mod rules;\n",
        ),
        ("crates/batten/src/rules.rs", ""),
        ("crates/batten-core/src/lib.rs", "pub mod selector;\n"),
        (
            "crates/batten-core/src/selector.rs",
            "pub fn glob_match() {}\n",
        ),
    ]);
    assert!(same(
        &before,
        &after,
        "{ assert!(crate::rules::glob_match()); }",
        "{ assert!(crate::selector::glob_match()); }",
    ));
}

/// Fails by: resolution by name alone. Two items of one name are two items, so
/// switching a test from one to the other is a modification.
#[test]
fn a_different_item_of_the_same_name_is_a_different_item() {
    let files = tree(&[
        ("crates/batten/src/lib.rs", "pub mod a;\npub mod b;\n"),
        ("crates/batten/src/a.rs", "pub fn parse() {}\n"),
        ("crates/batten/src/b.rs", "pub fn parse() {}\n"),
    ]);
    assert!(!same(
        &files,
        &files,
        "{ crate::a::parse(); }",
        "{ crate::b::parse(); }"
    ));
    // And a name declared twice at head is not paired as a move.
    let before = tree(&[
        ("crates/batten/src/lib.rs", "pub mod a;\npub mod b;\n"),
        ("crates/batten/src/a.rs", "pub fn parse() {}\n"),
        ("crates/batten/src/b.rs", ""),
    ]);
    assert!(!same(
        &before,
        &files,
        "{ crate::a::parse(); }",
        "{ crate::b::parse(); }"
    ));
}

/// Fails by: a changed assertion hidden behind a path. Only the path is
/// canonical; every other token still has to match.
#[test]
fn an_assertion_that_changed_still_differs() {
    let before = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        ("crates/batten/src/rules.rs", "pub struct Rule;\n"),
        ("crates/batten/src/model.rs", ""),
    ]);
    let after = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        ("crates/batten/src/rules.rs", ""),
        ("crates/batten/src/model.rs", "pub struct Rule;\n"),
    ]);
    assert!(!same(
        &before,
        &after,
        "{ assert_eq!(crate::rules::Rule::count(), 2); }",
        "{ assert_eq!(crate::model::Rule::count(), 3); }",
    ));
}

/// Fails by: a path inside a string literal rewritten. A string is data the
/// test asserts on, so its text must still match exactly.
#[test]
fn a_path_inside_a_string_is_data() {
    let files = tree(&[
        (
            "crates/batten/src/lib.rs",
            "pub mod rules;\npub mod model;\n",
        ),
        (
            "crates/batten/src/rules.rs",
            "pub use crate::model::Rule;\n",
        ),
        ("crates/batten/src/model.rs", "pub struct Rule;\n"),
    ]);
    assert!(!same(
        &files,
        &files,
        r#"{ assert_eq!(name(), "crate::rules::Rule"); }"#,
        r#"{ assert_eq!(name(), "crate::model::Rule"); }"#,
    ));
}

/// Fails by: an unresolvable path changed or dropped. What the index cannot
/// resolve stays exactly as written.
#[test]
fn an_unresolvable_path_is_left_as_written() {
    let files = tree(&[("crates/batten/src/lib.rs", "")]);
    let index = Index::new(&files);
    let body = "{ std::fs::read(p); super::helper(); 'a: loop {} }";
    assert_eq!(canonical(body, "batten", &index, &BTreeMap::new()), body);
}

/// Fails by: a file's crate or module misread, which every other answer rests on.
#[test]
fn a_files_crate_and_module_come_from_its_path() {
    assert_eq!(
        module_of("crates/batten-core/src/selector.rs"),
        Some((String::from("batten_core"), vec![String::from("selector")]))
    );
    assert_eq!(
        module_of("crates/batten/src/lib.rs"),
        Some((String::from("batten"), vec![]))
    );
    assert_eq!(
        module_of("crates/batten/src/mutate/mod.rs"),
        Some((String::from("batten"), vec![String::from("mutate")]))
    );
    assert_eq!(module_of("crates/batten/tests/it/main.rs"), None);
    assert_eq!(module_of("crates/batten/build.rs"), None);
    assert_eq!(
        crate_of("crates/batten-core/src/x.rs").as_deref(),
        Some("batten_core")
    );
}
