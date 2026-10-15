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

/// Every tracked column-0 Rust mutation row under `root` whose body does not
/// split into `mutate`'s three `|` fields, as `path:line`.
//MUTANT row-field-count-unread|s@^            if fields.len() != 3 {$@            if false {@|a_row_carrying_a_bare_pipe_is_found
fn malformed_rows(root: &Path) -> Vec<String> {
    let tracked = batten::git::tracked_paths(root).expect("the tracked set");
    let mut found = Vec::new();
    let sources = tracked
        .iter()
        .filter(|path| Path::new(path).extension().is_some_and(|ext| ext == "rs"));
    for path in sources {
        let Ok(text) = std::fs::read_to_string(root.join(path)) else {
            continue;
        };
        for (at, line) in text.lines().enumerate() {
            let Some(body) = line.strip_prefix("//MUTANT ") else {
                continue;
            };
            let fields: Vec<&str> = body.split('|').collect();
            if fields.len() != 3 {
                found.push(format!("{path}:{}", at + 1));
                continue;
            }
            // A row that reads but changes nothing in its own file is inert —
            // the sweep would compile the unchanged source and call it covered.
            // An address script (`/re/{…}`) is the sweep's own to apply; only a
            // bare `s` script is checked here.
            let Some(script) = fields.get(1).filter(|script| script.starts_with('s')) else {
                continue;
            };
            let applied = batten::mutate::substitute(&text, script);
            // Marker lines excluded, as the sweep excludes them: a pattern that
            // matches only its own declaration changes no source.
            let source_changed = applied.as_deref().is_some_and(|mutated| {
                text.lines()
                    .zip(mutated.lines())
                    .any(|(before, after)| !before.starts_with("//MUTANT") && before != after)
            });
            if !source_changed {
                found.push(format!("{path}:{} (inert)", at + 1));
            }
        }
    }
    found
}

/// A row is `slug|script|test`, split on EVERY `|` (CLOUD-2315). A script
/// carrying a pipe — `\|` included, which a sed basic regex also reads as
/// alternation — is not three fields, so the sweep cannot read the row at all.
/// Six rows carried one and nothing said so; a literal pipe is spelled `\x7c`.
#[test]
fn every_rust_mutation_row_is_three_fields() {
    let found = malformed_rows(&common::at_root("."));
    assert!(
        found.is_empty(),
        "a row is `slug|script|test` split on every `|`, so a pipe inside the \
         script (`\\|` included) breaks it; spell a literal pipe `\\x7c`: {}",
        found.join(", ")
    );
}

/// The anti-vacuity half of the case above.
#[test]
fn a_row_carrying_a_bare_pipe_is_found() {
    let repo = common::scratch_repo("mutant-rows-pipe");
    common::write(
        &repo,
        "src/a.rs",
        "//MUTANT ok|s/a\\x7cb/c/|case\n//MUTANT piped|s/a\\|b/c/|case\n//MUTANT inert|s/nowhere/c/|case\nfn f() -> &'static str {\n    \"a|b\"\n}\n",
    );
    common::git_in(&repo, &["add", "-A"]);
    assert_eq!(
        malformed_rows(&repo),
        vec!["src/a.rs:2".to_owned(), "src/a.rs:3 (inert)".to_owned()]
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
