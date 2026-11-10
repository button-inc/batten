//! Rust carries no hand-written mutation marker (CLOUD-2253).
//!
//! cargo-mutants generates and judges every Rust mutant itself (`mutant:rust`),
//! and reads no marker in the source: a row, a `MUTANT-SUITE`, `-OWNER` or
//! `-EXEMPT` line in a `.rs` file is never run and only reads as coverage. 868
//! rows and 408 suite lines accumulated that way. A Rust obligation names the
//! runner instead (`"mutation": "cargo-mutants"`).
//!
//! A marker is either a `//MUTANT…` line, or a `#MUTANT…` / `MUTANT…` line
//! inside a `/* */` block, the two shapes rows were carried in. A `#MUTANT` row
//! in a string literal is another language's fixture text and passes.

use std::path::Path;

use crate::common;

/// Whether `line`, inside a `/* */` block or not, is a mutation marker.
fn is_marker(line: &str, in_block: bool) -> bool {
    let line = line.trim_start();
    line.starts_with("//MUTANT")
        || (in_block && (line.starts_with("#MUTANT") || line.starts_with("MUTANT")))
}

/// Every tracked `.rs` line under `root` carrying a mutation marker, as
/// `path:line`.
fn rust_markers(root: &Path) -> Vec<String> {
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
        let mut in_block = false;
        for (at, line) in text.lines().enumerate() {
            match line.trim() {
                "/*" => in_block = true,
                "*/" => in_block = false,
                _ if is_marker(line, in_block) => found.push(format!("{path}:{}", at + 1)),
                _ => {}
            }
        }
    }
    found
}

/// No tracked Rust source declares a hand-written mutation marker.
#[test]
fn no_rust_source_declares_a_hand_written_mutation_marker() {
    let found = rust_markers(&common::at_root("."));
    assert!(
        found.is_empty(),
        "cargo-mutants owns every Rust source and reads no marker, so one here \
         is never run; delete it, and bind a Ready obligation to \
         `cargo-mutants`: {}",
        found.join(", ")
    );
}

/// THE ANTI-VACUITY HALF. A reader that found nothing would pass the case above
/// over a tree full of markers, so the predicate is shown finding each shape at
/// any indent, and passing another language's row in a string literal.
#[test]
fn every_marker_shape_is_found_at_any_indent() {
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
        "/*",
        "#MUTANT-SUITE tests/a.rs",
        "MUTANT bare|s/a/b/|case",
        "*/",
        "",
    ]
    .join("\n");
    common::write(&repo, "src/a.rs", &source);
    common::git_in(&repo, &["add", "-A"]);
    assert_eq!(
        rust_markers(&repo),
        [
            "src/a.rs:1",
            "src/a.rs:2",
            "src/a.rs:4",
            "src/a.rs:10",
            "src/a.rs:11"
        ]
    );
}
