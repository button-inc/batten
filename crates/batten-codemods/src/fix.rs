//! Apply the compiler's own machine-applicable suggestions, deciding imports
//! per build (CLOUD-2803).
//!
//! # Prior art
//!
//! `rustfix`, the engine behind `cargo fix`: rustc emits each suggestion with
//! its span and an applicability, and a `MachineApplicable` one can be applied
//! without reading it. This module adds the one decision `cargo fix` does not
//! make, which CLOUD-2793 made by hand with a classifier over JSON diagnostics:
//! an import is judged in TWO builds.
//!
//! | `unused_imports` reported in | the import is              | so it is |
//! | ---------------------------- | -------------------------- | -------- |
//! | the non-test build only      | used by test code          | gated `#[cfg(test)]` |
//! | the test build only          | inside test-only code      | deleted  |
//! | both                         | used nowhere               | deleted  |
//!
//! `cargo fix` would delete the first row and break the test build; that is
//! the failure the hand classifier existed to avoid. A partial removal (one
//! leaf of a `use` group) used only by tests cannot be gated without splitting
//! the group, so it is left and counted, never guessed.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;

use rustfix::{CodeFix, Filter, Suggestion};

/// What one pass decided.
#[derive(Debug, Default)]
pub struct Plan {
    /// Every suggestion to apply, by the file it edits.
    pub edits: BTreeMap<String, Vec<Suggestion>>,
    /// Imports gated `#[cfg(test)]` rather than deleted.
    pub gated: usize,
    /// Partial removals used only by tests: left for a person.
    pub left: usize,
    /// Error-level diagnostics in either build.
    pub errors: usize,
}

/// One diagnostic out of cargo's `--message-format json` stream.
struct Diagnostic {
    /// The rustc diagnostic object, re-serialised for `rustfix`.
    json: String,
    /// Its lint code, if any.
    code: Option<String>,
    /// Whether it is an error.
    error: bool,
}

fn diagnostics(stream: &str) -> Vec<Diagnostic> {
    stream
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value["reason"] == "compiler-message")
        .map(|value| {
            let message = &value["message"];
            Diagnostic {
                json: message.to_string(),
                code: message["code"]["code"].as_str().map(str::to_owned),
                error: message["level"] == "error",
            }
        })
        .collect()
}

fn suggestions(diagnostic: &Diagnostic) -> Vec<Suggestion> {
    rustfix::get_suggestions_from_json(
        &diagnostic.json,
        &HashSet::new(),
        Filter::MachineApplicableOnly,
    )
    .unwrap_or_default()
}

/// Where a suggestion edits, as one comparable key across the two builds.
fn site(suggestion: &Suggestion) -> Option<(String, Range<usize>)> {
    let replacement = suggestion.solutions.first()?.replacements.first()?;
    Some((
        replacement.snippet.file_name.clone(),
        replacement.snippet.range.clone(),
    ))
}

/// Plan one pass from the non-test build's stream and the test build's.
/// `read` returns a file's current text, by the path rustc reports.
#[must_use]
pub fn plan(non_test: &str, test: &str, read: &dyn Fn(&str) -> Option<String>) -> Plan {
    let (lib, tests) = (diagnostics(non_test), diagnostics(test));
    let unused_sites = |stream: &[Diagnostic]| -> BTreeSet<(String, usize, usize)> {
        stream
            .iter()
            .filter(|diagnostic| diagnostic.code.as_deref() == Some("unused_imports"))
            .flat_map(suggestions)
            .filter_map(|suggestion| site(&suggestion))
            .map(|(file, range)| (file, range.start, range.end))
            .collect()
    };
    let in_tests = unused_sites(&tests);
    let mut plan = Plan {
        errors: lib.iter().chain(&tests).filter(|d| d.error).count(),
        ..Plan::default()
    };
    let mut seen: BTreeSet<(String, usize, usize, String)> = BTreeSet::new();
    let from_lib = lib.iter().map(|d| (d, true));
    let from_tests = tests.iter().map(|d| (d, false));
    for (diagnostic, non_test_build) in from_lib.chain(from_tests) {
        for mut suggestion in suggestions(diagnostic) {
            let Some((file, range)) = site(&suggestion) else {
                continue;
            };
            let unused = diagnostic.code.as_deref() == Some("unused_imports");
            if unused
                && non_test_build
                && !in_tests.contains(&(file.clone(), range.start, range.end))
            {
                // Unused only where tests are not compiled: tests use it.
                match gate(&mut suggestion, read) {
                    Some(()) => plan.gated += 1,
                    None => {
                        plan.left += 1;
                        continue;
                    }
                }
            }
            let replacement = suggestion.solutions[0].replacements[0].replacement.clone();
            if seen.insert((file.clone(), range.start, range.end, replacement)) {
                plan.edits.entry(file).or_default().push(suggestion);
            }
        }
    }
    plan
}

/// Turn a whole-item removal into the same item gated `#[cfg(test)]`. `None`
/// when the removal is not a whole `use` item (one leaf of a group), which
/// cannot be gated without splitting the group.
fn gate(suggestion: &mut Suggestion, read: &dyn Fn(&str) -> Option<String>) -> Option<()> {
    let replacement = suggestion.solutions.first_mut()?.replacements.first_mut()?;
    let text = read(&replacement.snippet.file_name)?;
    let covered = text.get(replacement.snippet.range.clone())?;
    let item = covered.trim();
    let whole_use = replacement.replacement.is_empty()
        && item.ends_with(';')
        && (item.starts_with("use ") || item.starts_with("pub use ") || item.starts_with("pub("));
    if !whole_use {
        return None;
    }
    let indent: String = covered
        .chars()
        .skip_while(|c| *c == '\n')
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();
    let leading = &covered[..covered.len() - covered.trim_start().len()];
    replacement.replacement = format!("{leading}#[cfg(test)]\n{indent}{}", covered.trim_start());
    Some(())
}

/// Apply a plan's edits to `text`, the current contents of one file.
///
/// # Errors
///
/// When `rustfix` refuses an edit (overlapping, non-identical replacements).
pub fn apply(text: &str, suggestions: &[Suggestion]) -> Result<String, rustfix::Error> {
    let mut fix = CodeFix::new(text);
    for suggestion in suggestions {
        fix.apply(suggestion)?;
    }
    fix.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One cargo `compiler-message` line: an `unused_imports` warning whose
    /// machine-applicable fix removes `[start, end)` of `file`.
    fn unused(file: &str, start: usize, end: usize, line: usize) -> String {
        let span = |replacement: Option<&str>, applicability: Option<&str>| {
            serde_json::json!({
                "file_name": file, "byte_start": start, "byte_end": end,
                "line_start": line, "line_end": line + 1, "column_start": 1, "column_end": 1,
                "is_primary": true, "text": [], "label": null,
                "suggested_replacement": replacement, "suggestion_applicability": applicability,
                "expansion": null
            })
        };
        let message = serde_json::json!({
            "message": "unused import", "code": {"code": "unused_imports", "explanation": null},
            "level": "warning", "spans": [span(None, None)],
            "children": [{
                "message": "remove the whole `use` item", "code": null, "level": "help",
                "spans": [span(Some(""), Some("MachineApplicable"))], "children": [], "rendered": null
            }],
            "rendered": "unused import"
        });
        serde_json::json!({"reason": "compiler-message", "message": message}).to_string()
    }

    const SRC: &str = "use std::fmt;\nuse std::io;\nfn f() {}\n";

    fn read(_: &str) -> Option<String> {
        Some(SRC.to_owned())
    }

    /// Fails by: an import unused only in the non-test build deleted (which
    /// breaks the test build), or one unused in both builds kept.
    #[test]
    fn an_import_only_tests_use_is_gated_and_a_dead_one_is_deleted() {
        let non_test = format!(
            "{}\n{}\n",
            unused("src/a.rs", 0, 14, 1),
            unused("src/a.rs", 14, 27, 2)
        );
        let test = format!("{}\n", unused("src/a.rs", 14, 27, 2));
        let plan = plan(&non_test, &test, &read);
        assert_eq!((plan.gated, plan.left, plan.errors), (1, 0, 0));
        let fixed = apply(SRC, &plan.edits["src/a.rs"]).expect("the edits apply");
        assert_eq!(fixed, "#[cfg(test)]\nuse std::fmt;\nfn f() {}\n");
    }

    /// Fails by: a removal reported by both builds applied twice and refused
    /// as overlapping, or not applied at all.
    #[test]
    fn a_removal_both_builds_report_is_applied_once() {
        let line = unused("src/a.rs", 14, 27, 2);
        let plan = plan(&line, &line, &read);
        assert_eq!(plan.edits["src/a.rs"].len(), 1);
        assert_eq!(
            apply(SRC, &plan.edits["src/a.rs"]).expect("applies"),
            "use std::fmt;\nfn f() {}\n"
        );
    }
}
