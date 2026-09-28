//! `config_edit`'s contract: an edit changes the edited key and nothing else
//! (CLOUD-1575).
//!
//! # The predicate, and why the naive assertion is not it
//!
//! [`only_changed_lines`] is the one rule every case here judges by: the output
//! has the input's line count, and every line but the named ones is
//! byte-identical. `the_edited_key_carries_the_new_value` asserts only that the
//! new value landed. It is kept on purpose, because it passes on a `toml::Value`
//! round-trip too, and the declared mutation below shows that directly: the
//! preservation case goes red while the naive one stays green. That is what makes
//! the preservation case bind preservation rather than assignment (CLOUD-418).
//!
//! # The negative control
//!
//! `a_value_round_trip_is_the_negative_control` pushes the same fixture and the
//! same edit through `toml::Value` and requires the SAME predicate to refuse it.
//! If that case ever passes, the fixture has stopped carrying anything a
//! serde round-trip would lose, and every other case here reads green over
//! nothing.
//
// The obligation CLOUD-1575's Ready block binds. The row itself is swept from
// `crates/batten/src/config_edit.rs`, the file it mutates:
// MUTANT config-edit-toml-roundtrip|see `config_edit::render`|an_edit_changes_only_the_edited_key

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::config_edit::{self, Edit, Format, Scalar};

use crate::common;

/// Comments, a blank line between sections, hand-aligned `=` signs and keys in
/// neither alphabetical nor any other order: everything a serde round-trip
/// throws away.
const FIXTURE: &str = "\
# A consumer's manifest, formatted by hand.

[package]
name    = \"demo\"   # aligned on purpose
version = \"0.1.0\"

# Lint levels, deliberately not alphabetical.
[lints.rust]
unsafe_code = \"deny\"  # a fix raises this
dead_code   = \"warn\"

[dependencies]
zeta  = \"1\"
alpha = \"2\"
";

/// The fixture line the canonical edit rewrites, and what it must become.
const EDITED_LINE: usize = 8;
const EDITED_TO: &str = "unsafe_code = \"forbid\"  # a fix raises this";

fn path(keys: &[&str]) -> Vec<String> {
    keys.iter().map(|key| (*key).to_owned()).collect()
}

fn raise_unsafe_code() -> Edit {
    Edit::Set {
        path: path(&["lints", "rust", "unsafe_code"]),
        value: Scalar::String(String::from("forbid")),
    }
}

/// The indices of the lines that differ, or `None` when the line count
/// changed. A changed count is never "only the edited key".
fn only_changed_lines(before: &str, after: &str) -> Option<Vec<usize>> {
    let before: Vec<&str> = before.lines().collect();
    let after: Vec<&str> = after.lines().collect();
    (before.len() == after.len()).then(|| {
        before
            .iter()
            .zip(&after)
            .enumerate()
            .filter(|(_, (was, now))| was != now)
            .map(|(at, _)| at)
            .collect()
    })
}

fn lookup(text: &str, keys: &[&str]) -> Option<toml::Value> {
    let mut value = toml::Value::Table(text.parse::<toml::Table>().ok()?);
    for key in keys {
        value = value.get(key)?.clone();
    }
    Some(value)
}

#[test]
fn the_fixture_line_is_the_one_the_edit_names() {
    // The cases below index the fixture by line. This pins that index to the
    // text, so a fixture edit that moves the line fails here with a reason
    // rather than turning the preservation case red for an unrelated one.
    assert_eq!(
        FIXTURE.lines().nth(EDITED_LINE),
        Some("unsafe_code = \"deny\"  # a fix raises this")
    );
}

#[test]
fn an_edit_changes_only_the_edited_key() {
    let edited = config_edit::apply(Format::Toml, FIXTURE, &[raise_unsafe_code()]).unwrap();
    assert_eq!(
        only_changed_lines(FIXTURE, &edited),
        Some(vec![EDITED_LINE]),
        "an edit through the seam must leave every other line byte-identical",
    );
    assert_eq!(edited.lines().nth(EDITED_LINE), Some(EDITED_TO));
    assert_eq!(edited.ends_with('\n'), FIXTURE.ends_with('\n'));
}

#[test]
fn the_edited_key_carries_the_new_value() {
    let edited = config_edit::apply(Format::Toml, FIXTURE, &[raise_unsafe_code()]).unwrap();
    assert_eq!(
        lookup(&edited, &["lints", "rust", "unsafe_code"]),
        Some(toml::Value::String(String::from("forbid"))),
    );
}

#[test]
fn a_value_round_trip_is_the_negative_control() {
    let mut table: toml::Table = FIXTURE.parse().unwrap();
    table["lints"]["rust"].as_table_mut().unwrap().insert(
        String::from("unsafe_code"),
        toml::Value::String(String::from("forbid")),
    );
    let round_tripped = toml::to_string(&table).unwrap();
    // The control assigns the value correctly...
    assert_eq!(
        lookup(&round_tripped, &["lints", "rust", "unsafe_code"]),
        Some(toml::Value::String(String::from("forbid"))),
    );
    // ...and the preservation predicate still refuses it.
    assert_ne!(
        only_changed_lines(FIXTURE, &round_tripped),
        Some(vec![EDITED_LINE]),
        "a serde round-trip passed the preservation predicate, so the fixture \
         no longer carries anything a round-trip loses",
    );
}

#[test]
fn an_edit_that_changes_nothing_returns_the_input_byte_for_byte() {
    let same = Edit::Set {
        path: path(&["lints", "rust", "unsafe_code"]),
        value: Scalar::String(String::from("deny")),
    };
    assert_eq!(
        config_edit::apply(Format::Toml, FIXTURE, &[same]).unwrap(),
        FIXTURE
    );
}

#[test]
fn a_missing_table_is_created_after_the_existing_text() {
    let source = "[package]\nname = \"demo\"  # kept\n";
    let edit = Edit::Set {
        path: path(&["lints", "workspace"]),
        value: Scalar::Bool(true),
    };
    let edited = config_edit::apply(Format::Toml, source, &[edit]).unwrap();
    assert!(
        edited.starts_with(source),
        "the existing text is a prefix of the edit"
    );
    assert_eq!(
        lookup(&edited, &["lints", "workspace"]),
        Some(toml::Value::Boolean(true))
    );
}

#[test]
fn a_remove_drops_only_that_key() {
    let edit = Edit::Remove {
        path: path(&["dependencies", "zeta"]),
    };
    let edited = config_edit::apply(Format::Toml, FIXTURE, &[edit]).unwrap();
    let mut expected = String::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with("zeta")) {
        expected.push_str(line);
        expected.push('\n');
    }
    assert_eq!(edited, expected);
}

#[test]
fn removing_an_absent_key_changes_nothing() {
    for keys in [
        &["dependencies", "omega"][..],
        &["no_such_table", "key"][..],
    ] {
        let edit = Edit::Remove { path: path(keys) };
        assert_eq!(
            config_edit::apply(Format::Toml, FIXTURE, &[edit]).unwrap(),
            FIXTURE
        );
    }
}

#[test]
fn a_path_through_a_scalar_is_refused() {
    let edit = Edit::Set {
        path: path(&["package", "name", "inner"]),
        value: Scalar::Integer(1),
    };
    assert!(config_edit::apply(Format::Toml, FIXTURE, &[edit]).is_err());
}

#[test]
fn a_set_over_a_table_is_refused() {
    let edit = Edit::Set {
        path: path(&["lints", "rust"]),
        value: Scalar::Bool(true),
    };
    assert!(config_edit::apply(Format::Toml, FIXTURE, &[edit]).is_err());
}

#[test]
fn an_empty_path_is_refused() {
    let edit = Edit::Remove { path: Vec::new() };
    assert!(config_edit::apply(Format::Toml, FIXTURE, &[edit]).is_err());
}

#[test]
fn apply_file_writes_only_a_change_and_nothing_on_a_refusal() {
    let dir = common::scratch("config-edit-apply-file");
    let file = dir.join("Cargo.toml");
    std::fs::write(&file, FIXTURE).unwrap();

    let noop = Edit::Remove {
        path: path(&["dependencies", "omega"]),
    };
    assert!(!config_edit::apply_file(Format::Toml, &file, &[noop]).unwrap());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), FIXTURE);

    assert!(config_edit::apply_file(Format::Toml, &file, &[raise_unsafe_code()]).unwrap());
    let written = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        only_changed_lines(FIXTURE, &written),
        Some(vec![EDITED_LINE])
    );

    let broken = "not = [toml\n";
    std::fs::write(&file, broken).unwrap();
    assert!(config_edit::apply_file(Format::Toml, &file, &[raise_unsafe_code()]).is_err());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), broken);
}
