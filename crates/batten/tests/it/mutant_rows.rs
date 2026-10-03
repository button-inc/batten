//! A Rust `//MUTANT` row sits at column 0, or it is not a row (CLOUD-2067).
//!
//! `mutate`'s marker reader matches at the START of a line, deliberately: a
//! declaration is a statement about the whole file, and an indented marker could
//! be fixture text inside a nested block. But `rustfmt` re-indents a comment
//! inside a function body to the block's level, so a row written beside the line
//! it mutates was silently no row at all. There were 36 of them on `main`, each a
//! gate whose red-proof had never run, and nothing said so. The reader's rule
//! stands; what changes is that breaking it is refused here rather than read as
//! nothing.
//!
//! RUST'S OWN OPENER ONLY. A `#MUTANT` inside a `.rs` file is another language's
//! row carried as fixture text, such as `mutate.rs`'s own cases, and indenting
//! one is how a string literal holds it.

use std::path::Path;

use crate::common;

const OPENER: &str = "//MUTANT";

/// Every tracked `.rs` line under `root` carrying an indented Rust mutation
/// marker, as `path:line`.
//MUTANT-SUITE crates/batten/tests/it/mutant_rows.rs
//MUTANT indented-row-unread|s@^            let indented = indent > 0 \&\& line\[indent..\].starts_with(OPENER);$@            let indented = false;@|an_indented_row_in_a_tracked_source_is_found
fn indented_rows(root: &Path) -> Vec<String> {
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
            let indent = line.len() - line.trim_start().len();
            let indented = indent > 0 && line[indent..].starts_with(OPENER);
            if indented {
                found.push(format!("{path}:{}", at + 1));
            }
        }
    }
    found
}

/// Every tracked `//MUTANT` row sits at column 0, where `mutate` reads it.
#[test]
fn no_rust_mutation_row_is_indented() {
    let found = indented_rows(&common::at_root("."));
    assert!(
        found.is_empty(),
        "`mutate` reads a row only at column 0, and rustfmt indents a comment \
         inside a block, so these are not rows: move each above its item, at \
         column 0: {}",
        found.join(", ")
    );
}

/// THE ANTI-VACUITY HALF. A reader that found nothing would pass the case above
/// over a tree full of dead rows, so the predicate is shown finding one, and
/// passing the column-0 row and the other language's indented marker beside it.
#[test]
fn an_indented_row_in_a_tracked_source_is_found() {
    let repo = common::scratch_repo("mutant-rows-indented");
    common::write(
        &repo,
        "src/a.rs",
        "//MUTANT top|s/a/b/|case\nfn f() {\n    //MUTANT nested|s/a/b/|case\n    \
         let fixture = \"\n    #MUTANT rego|s/a/b/|case\n\";\n}\n",
    );
    common::git_in(&repo, &["add", "-A"]);
    assert_eq!(indented_rows(&repo), vec!["src/a.rs:3".to_owned()]);
}
