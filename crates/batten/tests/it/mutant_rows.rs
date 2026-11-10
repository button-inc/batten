//! Rust carries no hand-rolled `//MUTANT` row (CLOUD-2253).
//!
//! `MUTANT_RUNNERS` gives every Rust source to cargo-mutants, and
//! `mutate::Registry::declares` leaves a registered runner's rows unswept, so a
//! row in a `.rs` file is never run. 868 of them accumulated on `main` while
//! reading as coverage. A Rust obligation names the runner instead
//! (`"mutation": "cargo-mutants"`, `policy/obligations-bound.rego`).
//!
//! `//MUTANT-SUITE` stays: cargo-mutants reads it to scope each mutant's tests.
//! A `#MUTANT` row is another language's, carried here as fixture text.

use std::path::Path;

use crate::common;

const ROW: &str = "//MUTANT ";

/// Every tracked `.rs` line under `root` carrying a Rust mutation row, at any
/// indent, as `path:line`.
//MUTANT-SUITE crates/batten/tests/it/mutant_rows.rs
fn rust_rows(root: &Path) -> Vec<String> {
    let tracked = batten::git::tracked_paths(root).expect("the tracked set");
    let mut found = Vec::new();
    // Exactly `rs`, as rustc reads it: a `.RS` file is no source of rows.
    let sources = tracked
        .iter()
        .filter(|path| Path::new(path).extension().is_some_and(|ext| ext == "rs"));
    for path in sources {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        for (at, line) in text.lines().enumerate() {
            if line.trim_start().starts_with(ROW) {
                found.push(format!("{path}:{}", at + 1));
            }
        }
    }
    found
}

/// No tracked Rust source declares a hand-rolled mutation row.
#[test]
fn no_rust_source_declares_a_hand_rolled_mutation_row() {
    let found = rust_rows(&common::at_root("."));
    assert!(
        found.is_empty(),
        "cargo-mutants owns every Rust source (`MUTANT_RUNNERS`), so a \
         `//MUTANT` row there is never run; delete it, and bind a Ready \
         obligation to `cargo-mutants`: {}",
        found.join(", ")
    );
}

/// THE ANTI-VACUITY HALF. A reader that found nothing would pass the case above
/// over a tree full of rows, so the predicate is shown finding one at column 0
/// and one indented, and passing a suite line and another language's marker.
#[test]
fn a_rust_row_at_any_indent_is_found() {
    let repo = common::scratch_repo("mutant-rows-rust");
    let source = [
        "//MUTANT-SUITE tests/a.rs",
        "//MUTANT top|s/a/b/|case",
        "fn f() {",
        "    //MUTANT nested|s/a/b/|case",
        "    let fixture = \"",
        "    #MUTANT rego|s/a/b/|case",
        "\";",
        "}",
        "",
    ]
    .join("\n");
    common::write(&repo, "src/a.rs", &source);
    common::git_in(&repo, &["add", "-A"]);
    assert_eq!(
        rust_rows(&repo),
        vec!["src/a.rs:2".to_owned(), "src/a.rs:4".to_owned()]
    );
}
