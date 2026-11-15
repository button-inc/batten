//! Rust prose never points at a mutation row that cannot exist.
//!
//! Rust mutation is cargo-mutants' alone: this repository's `.rs` files carry no
//! `//MUTANT` row (`main` held 1,179 before the migration). A sentence naming one
//! (`` `#MUTANT x` reddens here ``) is then a pointer to nothing, and its reader
//! goes looking for a mechanism that is gone. Two shapes are refused, outside the
//! row harness itself, which parses rows for every language:
//!
//! - any `//MUTANT` in a `.rs` file: the Rust row's own spelling, live nowhere;
//! - any `MUTANT <slug>` whose slug no tracked non-Rust row (`.rego`, `.bats`,
//!   toml, workflow) declares as `MUTANT <slug>|`.
//!
//! A mention of a row that still exists in another language stays: it is live.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The row harness parses and tests rows for every language, so its own text
/// names the Rust spelling on purpose.
const HARNESS: &[&str] = &[
    "crates/batten/src/mutate.rs",
    "crates/batten/src/mutate/",
    "crates/batten/src/mutation_markers.rs",
    "crates/batten/tests/it/mutate.rs",
    "crates/batten/tests/it/rust_row_references.rs",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tracked() -> Vec<String> {
    crate::common::git_in(&root(), &["ls-files", "-z"])
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every slug a `MUTANT` mention in `text` names, with the byte offset of its
/// `MUTANT`: the next word when it is one — lowercase, hyphenated, optionally in
/// backticks, and possibly wrapped onto the next comment line. `MUTANT-SUITE`,
/// `MUTANT-OWNER` and `MUTANT-EXEMPT` are directives, not slugs, and `MUTANT:`
/// is prose.
fn slugs(text: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    for (at, _) in text.match_indices("MUTANT") {
        let after = &text[at + "MUTANT".len()..];
        if !after.starts_with([' ', '\n']) {
            continue;
        }
        let word = after
            .trim_start_matches(|c: char| c.is_whitespace() || c == '/' || c == '!')
            .trim_start_matches('`');
        let end = word
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
            .unwrap_or(word.len());
        let slug = &word[..end];
        if slug.contains('-') && !slug.starts_with('-') && !slug.ends_with('-') {
            found.push((at, slug));
        }
    }
    found
}

/// The 1-based line `offset` falls on in `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

#[test]
fn rust_prose_names_no_row_that_does_not_exist() {
    let files = tracked();
    let root = root();
    let mut declared = BTreeSet::new();
    for path in files.iter().filter(|path| {
        !Path::new(path)
            .extension()
            .is_some_and(|ext| ext == "rs" || ext == "md" || ext == "jsonl")
    }) {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        for line in text.lines() {
            if let Some(at) = line.find("MUTANT ") {
                let row = &line[at + "MUTANT ".len()..];
                if let Some((slug, _)) = row.split_once('|') {
                    declared.insert(slug.trim().to_owned());
                }
            }
        }
    }
    let mut dead = Vec::new();
    for path in files.iter().filter(|path| {
        Path::new(path).extension().is_some_and(|ext| ext == "rs")
            && !HARNESS.iter().any(|skip| path.starts_with(skip))
    }) {
        let text = std::fs::read_to_string(root.join(path)).expect("read a tracked file");
        let mut lines = BTreeSet::new();
        for (at, _) in text.match_indices("//MUTANT") {
            lines.insert(line_of(&text, at));
        }
        for (at, slug) in slugs(&text) {
            if !declared.contains(slug) {
                lines.insert(line_of(&text, at));
            }
        }
        dead.extend(lines.into_iter().map(|line| format!("{path}:{line}")));
    }
    assert!(
        dead.is_empty(),
        "{} line(s) name a mutation row that does not exist:\n{}",
        dead.len(),
        dead.join("\n")
    );
}

#[test]
fn a_slug_is_read_from_every_spelling_and_a_directive_is_not_one() {
    let names = |text| {
        slugs(text)
            .into_iter()
            .map(|(_, slug)| slug)
            .collect::<Vec<_>>()
    };
    assert_eq!(names("/// `#MUTANT a-b` reddens here"), ["a-b"]);
    assert_eq!(names("// MUTANT `lease-loss` counts"), ["lease-loss"]);
    assert_eq!(
        names("x MUTANT-SUITE crates/a.rs, #MUTANT-OWNER CLOUD-1"),
        Vec::<&str>::new()
    );
    assert_eq!(
        names("/// MUTANT: dropping the guard reds this"),
        Vec::<&str>::new()
    );
    assert_eq!(
        names("/// `#MUTANT one-x` and `#MUTANT\n/// two-y` redden"),
        ["one-x", "two-y"]
    );
    assert_eq!(line_of("a\nb\nc", 4), 3);
}
