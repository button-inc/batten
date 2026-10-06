//! Replay each modified test's BASE form against HEAD (CLOUD-2090).
//!
//! # Why config lint is not enough
//!
//! `config lint --config-from <base>` sees a weakening only where it is
//! configuration. A test whose expectation was loosened is code: measured in
//! #1056, `this_repository_is_healthy` came to exclude a check while GAINING
//! assertions, so a count of asserts reads it as a strengthening. The base test
//! run against HEAD's code does not: it asserts what the base asserted, and a
//! HEAD that no longer satisfies it has changed what "passing" means.
//!
//! # What this decides, and what it does not
//!
//! - A `#[test]` fn present at both revisions whose body changed (whitespace
//!   aside) is **modified**; its base body is spliced into HEAD's tree and run.
//!   A base body that fails, or a spliced tree that will not build, is
//!   `test-expectation-changed`.
//! - A `#[test]` fn present at base and gone at HEAD is `test-removed`, with no
//!   replay: there is nothing at HEAD to run it beside.
//! - An ADDED test is never replayed — it has no base expectation to hold HEAD to.
//!
//! **The bound, stated:** only `#[test]` bodies are compared. A helper whose body
//! changed under an unchanged test is not replayed; the test's own run at HEAD
//! is what covers it.
//!
//! Each finding is a pointer (rule 4): the test's key and a token. It is admitted
//! only through the `asked` ledger, the one route `config lint` uses, so one
//! landing puts every changed expectation to the owner in one recorded question.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use crate::exit::ExitCode;

/// A base test that HEAD's code no longer satisfies, or that will not build there.
pub const TEST_EXPECTATION_CHANGED: &str = "test-expectation-changed";

/// A base test that HEAD deleted.
pub const TEST_REMOVED: &str = "test-removed";

/// One `#[test]` fn: where it is, and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestFn {
    /// `<module path inside the file>::<name>`, e.g. `tests::a_case`.
    pub inner: String,
    /// The 1-based line of the fn's name.
    pub line: usize,
    /// The body's byte range in its file, braces included.
    pub body: (usize, usize),
}

/// One modified test: its base body, and where its head body sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modified {
    /// `<module path inside the file>::<name>`.
    pub inner: String,
    /// The base revision's body text, braces included.
    pub base_body: String,
    /// The head body's byte range in the head file.
    pub head_body: (usize, usize),
    /// The 1-based line of the fn's name at head.
    pub line: usize,
}

/// What a diff did to the tests of one file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Changed {
    /// Present at both revisions with a different body.
    pub modified: Vec<Modified>,
    /// Present at base, absent at head: `(inner, base line)`.
    pub removed: Vec<(String, usize)>,
}

/// Every `#[test]` fn in `source`, or `None` when it is not Rust.
#[must_use]
pub fn tests_in(source: &str) -> Option<Vec<TestFn>> {
    let file = crate::source::rust(source).ok()?;
    let starts = line_starts(source);
    let mut found = Vec::new();
    collect(&file.items, &mut Vec::new(), source, &starts, &mut found);
    Some(found)
}

fn collect(
    items: &[syn::Item],
    path: &mut Vec<String>,
    source: &str,
    starts: &[usize],
    found: &mut Vec<TestFn>,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) if is_test(&function.attrs) => {
                let open = function.block.brace_token.span.open().start();
                let close = function.block.brace_token.span.close().end();
                if let (Some(from), Some(to)) =
                    (offset(source, starts, open), offset(source, starts, close))
                {
                    let mut inner = path.clone();
                    inner.push(function.sig.ident.to_string());
                    found.push(TestFn {
                        inner: inner.join("::"),
                        line: function.sig.ident.span().start().line,
                        body: (from, to),
                    });
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    path.push(module.ident.to_string());
                    collect(nested, path, source, starts, found);
                    path.pop();
                }
            }
            _ => {}
        }
    }
}

/// `#[test]`, or a test macro spelled with a path ending in `test`
/// (`#[tokio::test]`).
fn is_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

/// The byte offset of each line's first byte.
fn line_starts(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(source.match_indices('\n').map(|(at, _)| at + 1))
        .collect()
}

/// A `proc-macro2` position (1-based line, 0-based char column) as a byte offset.
fn offset(source: &str, starts: &[usize], at: proc_macro2::LineColumn) -> Option<usize> {
    let start = *starts.get(at.line.checked_sub(1)?)?;
    let rest = source.get(start..)?;
    Some(
        start
            + rest
                .char_indices()
                .nth(at.column)
                .map_or(rest.len(), |(byte, _)| byte),
    )
}

/// The body text with every whitespace character removed, so a reformat is not a
/// modification.
fn shape(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether a body changed beyond its whitespace.
fn differs(base: &str, head: &str) -> bool {
    shape(base) != shape(head)
}

/// What changed between a file's base and head text.
#[must_use]
//MUTANT-SUITE crates/batten/src/replay.rs
//MUTANT modified-unseen|s@^    shape(base) != shape(head)$@    false@|a_changed_body_is_modified_and_formatting_is_not
pub fn compare(base: &str, head: &str) -> Changed {
    let index = |source: &str| -> BTreeMap<String, TestFn> {
        tests_in(source)
            .unwrap_or_default()
            .into_iter()
            .map(|test| (test.inner.clone(), test))
            .collect()
    };
    let (before, after) = (index(base), index(head));
    let mut changed = Changed::default();
    for (inner, old) in &before {
        let base_body = &base[old.body.0..old.body.1];
        match after.get(inner) {
            Some(new) if differs(base_body, &head[new.body.0..new.body.1]) => {
                changed.modified.push(Modified {
                    inner: inner.clone(),
                    base_body: base_body.to_owned(),
                    head_body: new.body,
                    line: new.line,
                });
            }
            Some(_) => {}
            None => changed.removed.push((inner.clone(), old.line)),
        }
    }
    changed
}

/// `head` with each modified test's base body spliced in, applied from the last
/// range back so earlier offsets stay valid.
#[must_use]
pub fn splice(head: &str, modified: &[Modified]) -> String {
    let mut edits: Vec<&Modified> = modified.iter().collect();
    edits.sort_by_key(|edit| std::cmp::Reverse(edit.head_body.0));
    let mut out = head.to_owned();
    for edit in edits {
        out.replace_range(edit.head_body.0..edit.head_body.1, &edit.base_body);
    }
    out
}

/// Every `.rs` blob at `rev`, by path.
fn rust_files(root: &Path, rev: &str) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    crate::git::for_each_blob_at_rev(root, rev, "**/*.rs", |path, text| {
        files.insert(path.to_owned(), text.to_owned());
    })?;
    Ok(files)
}

/// One finding: the test's `<path>::<inner>` key, its line, and the token.
struct Finding {
    key: String,
    path: String,
    line: usize,
    id: &'static str,
}

/// `batten test replay --base <ref>`: run each modified test's base form against
/// HEAD, and admit what changed only through the `asked` ledger.
///
/// Exit 0 when every finding is admitted (or there is none), 2 when one is not.
///
/// # Errors
///
/// A base that does not resolve, a tree that cannot be materialised, or a
/// ledger that cannot be read — each could-not-look rather than a pass.
pub fn run(root: &Path, base: &str, out: &mut dyn Write) -> Result<ExitCode> {
    let fork = crate::git::merge_base(root, base)?.unwrap_or_else(|| base.to_owned());
    let before = rust_files(root, &fork)?;
    let after = rust_files(root, "HEAD")?;

    let mut findings = Vec::new();
    // The head text each modified file is spliced from, by path.
    let mut splices: BTreeMap<String, (String, Vec<Modified>)> = BTreeMap::new();
    for (path, base_text) in &before {
        let Some(head_text) = after.get(path) else {
            continue;
        };
        if head_text == base_text {
            continue;
        }
        let changed = compare(base_text, head_text);
        for (inner, line) in changed.removed {
            findings.push(Finding {
                key: format!("{path}::{inner}"),
                path: path.clone(),
                line,
                id: TEST_REMOVED,
            });
        }
        if !changed.modified.is_empty() {
            splices.insert(path.clone(), (head_text.clone(), changed.modified));
        }
    }

    if !splices.is_empty() {
        findings.extend(replay(root, &splices)?);
    }

    let smells: Vec<crate::lint::Smell> = findings
        .iter()
        .map(|finding| crate::lint::Smell {
            at: crate::lint::Where::Key(finding.key.clone()),
            id: finding.id,
        })
        .collect();
    let ledger = crate::asked::added_since(root, base)?;
    let admitted = crate::lint::admissions(&smells, &ledger);
    let mut refused = 0_usize;
    for (finding, (_, admission)) in findings.iter().zip(&admitted) {
        writeln!(
            out,
            "{}:{} {} {} ({})",
            finding.path,
            finding.line,
            finding.id,
            finding.key,
            admission.as_str()
        )?;
        if *admission == crate::lint::Admission::Refused {
            refused += 1;
        }
    }
    Ok(if refused == 0 {
        ExitCode::Success
    } else {
        ExitCode::Violation
    })
}

/// Materialise HEAD under the repository's state directory, splice each base
/// body in, and run each modified test there. A test that fails, or a tree that
/// will not build, is `test-expectation-changed`.
///
/// **Outside the checkout**, CLOUD-2096's lesson: a tree or a build cache inside
/// the repository is walked by its own scans. The target directory persists, so a
/// later lap builds warm.
fn replay(
    root: &Path,
    splices: &BTreeMap<String, (String, Vec<Modified>)>,
) -> Result<Vec<Finding>> {
    let state = crate::state::repo_state_dir(root)?.join("replay");
    let tree = state.join("tree");
    if tree.exists() {
        std::fs::remove_dir_all(&tree)
            .with_context(|| format!("test replay: clear {}", tree.display()))?;
    }
    crate::git::materialize_rev(root, "HEAD", &tree)?;
    for (path, (head_text, modified)) in splices {
        crate::durable::replace(tree.join(path), splice(head_text, modified))
            .with_context(|| format!("test replay: splice {path}"))?;
    }
    let published = [(
        String::from("CARGO_TARGET_DIR"),
        Some(state.join("target").to_string_lossy().into_owned()),
    )];
    let mut findings = Vec::new();
    for (path, (_, modified)) in splices {
        for test in modified {
            let filter = format!("test(/(^|::){}$/)", test.inner);
            let argv: Vec<String> = [
                "cargo",
                "nextest",
                "run",
                "--workspace",
                "--no-tests=fail",
                "-E",
                &filter,
            ]
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
            // `piped_argv` because it runs the child IN `tree`: `run_in_env`'s
            // root names only where a capture is stored, and the child inherits
            // this process's directory — the checkout, whose HEAD test passes.
            let outcome = crate::exec::piped_argv(
                &tree,
                &argv,
                "",
                crate::exec::Diagnostics::Drop,
                &published,
            );
            if !passes(outcome.as_ref()) {
                findings.push(Finding {
                    key: format!("{path}::{}", test.inner),
                    path: path.clone(),
                    line: test.line,
                    id: TEST_EXPECTATION_CHANGED,
                });
            }
        }
    }
    Ok(findings)
}

/// Whether a replay passed: the child ran and exited 0. A non-zero exit, and a
/// child that could not be run at all, are a base expectation HEAD did not meet.
//MUTANT-SUITE crates/batten/tests/it/test_replay.rs
//MUTANT expectation-unchecked|s@^    matches!(outcome, Some((0, _)))$@    true@|a_narrowed_expectation_is_refused_by_name
fn passes(outcome: Option<&(i32, String)>) -> bool {
    matches!(outcome, Some((0, _)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const BASE: &str = "\
fn helper() -> u8 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn kept() {
        assert_eq!(1, 1);
    }

    #[test]
    fn narrowed() {
        assert_eq!(super::helper(), 1);
    }

    #[test]
    fn dropped() {
        assert!(true);
    }
}
";

    #[test]
    fn a_changed_body_is_modified_and_formatting_is_not() {
        let head = BASE
            .replace("assert_eq!(1, 1);", "assert_eq!( 1,1 );")
            .replace(
                "assert_eq!(super::helper(), 1);",
                "let _ = super::helper();",
            );
        let changed = compare(BASE, &head);
        let names: Vec<&str> = changed.modified.iter().map(|m| m.inner.as_str()).collect();
        assert_eq!(
            names,
            ["tests::narrowed"],
            "a reformat is not a modification"
        );
        assert!(
            changed.modified[0]
                .base_body
                .contains("assert_eq!(super::helper(), 1);")
        );
    }

    #[test]
    fn a_base_test_gone_at_head_is_removed() {
        let head = BASE.replace(
            "    #[test]\n    fn dropped() {\n        assert!(true);\n    }\n",
            "",
        );
        let changed = compare(BASE, &head);
        assert_eq!(changed.removed, vec![(String::from("tests::dropped"), 16)]);
        assert!(changed.modified.is_empty());
    }

    #[test]
    fn an_added_test_is_never_replayed() {
        let head = BASE.replace(
            "mod tests {\n",
            "mod tests {\n    #[test]\n    fn added() { assert!(false); }\n",
        );
        assert_eq!(compare(BASE, &head), Changed::default());
    }

    #[test]
    fn a_base_body_is_spliced_into_exactly_its_fn() {
        let head = BASE.replace(
            "assert_eq!(super::helper(), 1);",
            "let _ = super::helper();",
        );
        let changed = compare(BASE, &head);
        assert_eq!(splice(&head, &changed.modified), BASE);
    }
}
