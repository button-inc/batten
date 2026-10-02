//! Every shell stub the test suite writes is held to the portability rows
//! (CLOUD-2055).
//!
//! # Why this tier exists
//!
//! The `shell * unsafe` rows in `batten.toml` ban the GNU-only spellings that
//! break on a Mac — `sed -i` with no suffix, `sed -zE`, `mapfile`, `xargs -r`,
//! `flock`, `wait -n`, a padded `wc -l` count. Their glob is `mise-tasks/**`,
//! and the bash retirement (CLOUD-843) emptied that directory: the shell it
//! governed now lives as shebang string literals in these tests, where no rule
//! looked. Measured on #1056: a `syft` stub here ran `sed -i "s/…/…/"`, BSD sed
//! took the script as the backup suffix, and only CI's macOS runner noticed.
//!
//! # What is a stub
//!
//! A string literal whose VALUE begins `#!`. A hook payload such as
//! `assert_denied("sed -i s/old/new/ …")` carries no shebang, so it is data and
//! never judged — which is the whole reason a plain substring rule over
//! `tests/**` could not do this job. Scanned fixtures carry shebangs too and are
//! judged alike; one whose purpose is to CARRY a banned spelling says so with a
//! `# portability: fixture` line.
//!
//! Literals inside macro invocations are read as well: `syn::visit` never enters
//! `Macro.tokens`, and most stubs are `format!` strings.
//!
//! **The bound, stated rather than discovered:** only literal text is readable.
//! The `{body}` a `format!` interpolates, and lines pushed onto a stub after its
//! shebang literal, are not checked.
//!
//! # The mutations, and why they are declared in this file
//!
//! The predicate lives here rather than in the engine, so `mutate`'s file arm
//! seds the right target when this path is a gate name in `MUTANT_GATES`.

/*
#MUTANT-SUITE crates/batten/tests/it/stub_portability.rs
#MUTANT shebang-gate-dropped|s@    if !value.starts_with("#!") {@    if false {@|a_payload_string_is_not_a_stub
#MUTANT rows-unread|s@    id.starts_with("shell ") \&\& id.ends_with(" unsafe")@    id.is_empty()@|a_gnu_only_spelling_in_a_stub_is_named
#MUTANT macro-tokens-skipped|s@        self.tokens(\&mac.tokens);@        let _ = \&mac.tokens;@|a_stub_inside_format_is_seen
*/

use crate::common;

use std::path::{Path, PathBuf};

use syn::visit::Visit;

/// The portability rows this tier holds stubs to, by id. The gate case asserts
/// exactly these loaded, so a renamed row cannot pass vacuously.
const ROWS: [&str; 7] = [
    "shell parse unsafe",
    "shell edit unsafe",
    "shell read unsafe",
    "shell list unsafe",
    "shell guard unsafe",
    "shell run unsafe",
    "shell count unsafe",
];

/// The line a fixture writes to carry a banned spelling on purpose.
const FIXTURE_MARK: &str = "# portability: fixture";

fn is_portability_row(id: &str) -> bool {
    id.starts_with("shell ") && id.ends_with(" unsafe")
}

/// One row's matcher.
struct Row {
    id: String,
    matches: Box<dyn Fn(&str) -> bool>,
}

/// The `shell * unsafe` rows, read from the committed config — one authority for
/// the patterns, never a second spelling of them here.
fn rows() -> Vec<Row> {
    let config =
        batten::config::load(&common::at_root("batten.toml")).expect("the committed config loads");
    config
        .rules
        .iter()
        .filter(|rule| is_portability_row(&rule.id))
        .filter_map(|rule| {
            let id = rule.id.clone();
            if let Some(pattern) = rule.pattern.clone() {
                return Some(Row {
                    id,
                    matches: Box::new(move |line: &str| line.contains(&pattern)),
                });
            }
            let regex = regex::Regex::new(rule.regex.as_deref()?).expect("a row's regex compiles");
            Some(Row {
                id,
                matches: Box::new(move |line: &str| regex.is_match(line)),
            })
        })
        .collect()
}

/// Every string literal in a file: its value and the line it starts on.
#[derive(Default)]
struct Literals {
    found: Vec<(String, usize)>,
}

impl Literals {
    fn literal(&mut self, lit: &syn::Lit) {
        let value = match lit {
            syn::Lit::Str(text) => text.value(),
            syn::Lit::ByteStr(bytes) => String::from_utf8_lossy(&bytes.value()).into_owned(),
            _ => return,
        };
        self.found.push((value, lit.span().start().line));
    }

    /// Literals inside a macro's token stream, which `syn::visit` never enters.
    fn tokens(&mut self, stream: &proc_macro2::TokenStream) {
        for tree in stream.clone() {
            match tree {
                proc_macro2::TokenTree::Literal(literal) => {
                    if let Ok(lit) = syn::parse_str::<syn::Lit>(&literal.to_string()) {
                        let line = literal.span().start().line;
                        let value = match &lit {
                            syn::Lit::Str(text) => text.value(),
                            syn::Lit::ByteStr(bytes) => {
                                String::from_utf8_lossy(&bytes.value()).into_owned()
                            }
                            _ => continue,
                        };
                        self.found.push((value, line));
                    }
                }
                proc_macro2::TokenTree::Group(group) => self.tokens(&group.stream()),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Literals {
    fn visit_lit(&mut self, lit: &'ast syn::Lit) {
        self.literal(lit);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(&mac.tokens);
        syn::visit::visit_macro(self, mac);
    }
}

/// The findings for one source, as `<label>:<line> <rule id>` pointers.
fn findings(label: &str, source: &str, rows: &[Row]) -> (usize, Vec<String>) {
    let file = syn::parse_file(source).expect("every test source parses");
    let mut literals = Literals::default();
    literals.visit_file(&file);
    let mut stubs = 0;
    let mut found = Vec::new();
    for (value, start) in literals.found {
        if !value.starts_with("#!") {
            continue;
        }
        stubs += 1;
        if value.lines().any(|line| line.trim() == FIXTURE_MARK) {
            continue;
        }
        for (offset, line) in value.lines().enumerate() {
            for row in rows {
                if (row.matches)(line) {
                    found.push(format!("{label}:{} {}", start + offset, row.id));
                }
            }
        }
    }
    (stubs, found)
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read a test directory") {
        let path = entry.expect("a test directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// THE GATE: no stub this suite writes carries a GNU-only spelling.
#[test]
fn every_executed_test_stub_is_portable() {
    let rows = rows();
    let mut loaded: Vec<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    loaded.sort_unstable();
    let mut expected = ROWS.to_vec();
    expected.sort_unstable();
    assert_eq!(loaded, expected, "the portability rows this tier reads");

    let root = common::at_root("crates/batten/tests");
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    sources.sort();
    let mut stubs = 0;
    let mut found = Vec::new();
    for path in &sources {
        let source = std::fs::read_to_string(path).expect("read a test source");
        let label = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let (count, mut hits) = findings(&label, &source, &rows);
        stubs += count;
        found.append(&mut hits);
    }
    assert!(stubs > 0, "a gate that found no stub judged nothing");
    assert!(
        found.is_empty(),
        "{stubs} stub(s) judged; GNU-only spellings: {found:#?}"
    );
}

#[test]
fn a_gnu_only_spelling_in_a_stub_is_named() {
    let source = "const S: &str = \"#!/usr/bin/env bash\\nsed -i \\\"s/a/b/\\\" f\\n\";\n";
    let (stubs, found) = findings("fixture.rs", source, &rows());
    assert_eq!(stubs, 1);
    assert_eq!(found, vec!["fixture.rs:2 shell edit unsafe".to_owned()]);
}

#[test]
fn a_padded_count_in_a_stub_is_named() {
    let source = "const S: &str = \"#!/bin/sh\\nn=$(wc -l < f)\\n\";\n";
    let (stubs, found) = findings("fixture.rs", source, &rows());
    assert_eq!(stubs, 1);
    assert_eq!(found, vec!["fixture.rs:2 shell count unsafe".to_owned()]);
}

#[test]
fn a_payload_string_is_not_a_stub() {
    let source = "const S: &str = \"sed -i \\\"s/a/b/\\\" f\\n\";\n";
    let (stubs, found) = findings("fixture.rs", source, &rows());
    assert_eq!(stubs, 0);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_stub_inside_format_is_seen() {
    let source =
        "fn f(y: &str) -> String { format!(\"#!/bin/sh\\nsed -i \\\"x\\\" f\\n{}\", y) }\n";
    let (stubs, found) = findings("fixture.rs", source, &rows());
    assert_eq!(stubs, 1);
    assert_eq!(found, vec!["fixture.rs:2 shell edit unsafe".to_owned()]);
}

#[test]
fn a_declared_fixture_carries_its_spelling() {
    let source =
        "const S: &str = \"#!/bin/sh\\n# portability: fixture\\nsed -i \\\"x\\\" f\\n\";\n";
    let (stubs, found) = findings("fixture.rs", source, &rows());
    assert_eq!(stubs, 1);
    assert!(found.is_empty(), "{found:?}");
}
