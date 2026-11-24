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

/// Which build a diagnostic came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    NonTest,
    UnitTest,
    Other,
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

/// The three diagnostic streams a pass reads.
#[derive(Debug, Clone, Copy)]
pub struct Streams<'a> {
    /// `--lib --bins`: the non-test build.
    pub non_test: &'a str,
    /// `cargo test --no-run --lib --bins`: the same sources compiled as their
    /// own test units, with `cfg(test)`; the only stream that decides whether
    /// tests use an import (`check --profile test` does not set it).
    pub unit_test: &'a str,
    /// `--tests --examples --benches`: the other targets. Cargo builds the
    /// library NON-test as their dependency, so its warnings repeat here;
    /// read as "unused in a test build" they turned a gate into a deletion
    /// on the applier's first real run (`verdict.rs`, `VocabularyWord`).
    pub other: &'a str,
}

/// Only the lines of a cargo JSON stream whose `package_id` names `package`.
///
/// A build of one package's test unit also builds its workspace dependencies
/// non-test, and their warnings share the stream: measured, a
/// `test --no-run --lib --workspace` stream held 8 `unused_imports` against
/// the non-test stream's 5, because `batten-codemods` builds `batten` as a
/// dependency. Filtered to `package`, a `test --no-run --lib -p package`
/// stream holds that package's library test unit and nothing else. A
/// `package_id` is `path+file:///…/<dir>#<version>` or `…#<name>@<version>`.
#[must_use]
pub fn only_package(stream: &str, package: &str) -> String {
    let (by_dir, by_name) = (format!("/{package}#"), format!("#{package}@"));
    stream
        .lines()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|value| {
                value["package_id"]
                    .as_str()
                    .is_some_and(|id| id.contains(&by_dir) || id.contains(&by_name))
            })
        })
        .fold(String::new(), |mut kept, line| {
            kept.push_str(line);
            kept.push('\n');
            kept
        })
}

/// Plan one pass from the three streams. `read` returns a file's current
/// text, by the path rustc reports.
#[must_use]
pub fn plan(streams: Streams<'_>, read: &dyn Fn(&str) -> Option<String>) -> Plan {
    let lib = diagnostics(streams.non_test);
    let unit = diagnostics(streams.unit_test);
    let other = diagnostics(streams.other);
    let unused_sites = |stream: &[Diagnostic]| -> BTreeSet<(String, usize, usize)> {
        stream
            .iter()
            .filter(|diagnostic| diagnostic.code.as_deref() == Some("unused_imports"))
            .flat_map(suggestions)
            .filter_map(|suggestion| site(&suggestion))
            .map(|(file, range)| (file, range.start, range.end))
            .collect()
    };
    let (in_lib, in_tests) = (unused_sites(&lib), unused_sites(&unit));
    let mut plan = Plan {
        errors: lib
            .iter()
            .chain(&unit)
            .chain(&other)
            .filter(|d| d.error)
            .count(),
        ..Plan::default()
    };
    let mut seen: BTreeSet<(String, usize, usize, String)> = BTreeSet::new();
    let from_lib = lib.iter().map(|d| (d, Stream::NonTest));
    let from_unit = unit.iter().map(|d| (d, Stream::UnitTest));
    let from_other = other.iter().map(|d| (d, Stream::Other));
    for (diagnostic, stream) in from_lib.chain(from_unit).chain(from_other) {
        for mut suggestion in suggestions(diagnostic) {
            let Some((file, range)) = site(&suggestion) else {
                continue;
            };
            let unused = diagnostic.code.as_deref() == Some("unused_imports");
            let key = (file.clone(), range.start, range.end);
            // The library's own warning, repeated by a dependent target's
            // build: already decided from the first two streams.
            if unused && stream == Stream::Other && in_lib.contains(&key) {
                continue;
            }
            if unused && stream == Stream::NonTest && !in_tests.contains(&key) {
                // Unused only where tests are not compiled: tests use it.
                if let Some(()) = gate(&mut suggestion, read) {
                    plan.gated += 1;
                } else {
                    plan.left += 1;
                    continue;
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

/// Whether a pass may write anything: never over a build that does not compile.
///
/// Suggestions computed over code the compiler rejected are not trustworthy, and
/// the unused-import judgement in particular reads "unused" off a build that may
/// have stopped early. So one error anywhere refuses every edit in the pass.
#[must_use]
pub fn may_apply(plan: &Plan) -> bool {
    plan.errors == 0
}

/// Whether a cargo run read nothing: it failed AND emitted no compiler message.
///
/// A bad `-p`, a broken manifest or a missing toolchain fails before any unit is
/// compiled, so its JSON stream is empty, and an empty stream otherwise reads as
/// "nothing to fix". A failed build that did emit messages is the ordinary case:
/// its errors are counted by [`plan`] and refused by [`may_apply`].
#[must_use]
pub fn read_nothing(succeeded: bool, stream: &str) -> bool {
    !succeeded && !stream.contains("\"reason\":\"compiler-message\"")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_over_a_build_with_an_error_applies_nothing() {
        let clean = Plan::default();
        assert!(may_apply(&clean));
        let broken = Plan {
            errors: 1,
            ..Plan::default()
        };
        assert!(
            !may_apply(&broken),
            "one compile error must refuse every edit"
        );
    }

    #[test]
    fn a_failed_cargo_with_no_compiler_message_read_nothing() {
        // `cargo check -p nonexistent`: non-zero, empty stream.
        assert!(read_nothing(false, ""));
        // A non-zero exit that still compiled something: errors to count, not a void.
        let compiled = r#"{"reason":"compiler-message","message":{}}"#;
        assert!(!read_nothing(false, compiled));
        // A clean run with nothing to say is a judgement, not a void.
        assert!(!read_nothing(true, ""));
    }

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

    /// `plan`'s reader, which reads every file as [`SRC`]. A closure, because
    /// the `Option` is `plan`'s signature (a file it cannot read is `None`) and
    /// a `fn` that always answers `Some` is the wrap clippy refuses.
    fn reader() -> impl Fn(&str) -> Option<String> {
        |_| Some(SRC.to_owned())
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
        let plan = plan(
            Streams {
                non_test: &non_test,
                unit_test: &test,
                other: "",
            },
            &reader(),
        );
        assert_eq!((plan.gated, plan.left, plan.errors), (1, 0, 0));
        let fixed = apply(SRC, &plan.edits["src/a.rs"]).expect("the edits apply");
        assert_eq!(fixed, "#[cfg(test)]\nuse std::fmt;\nfn f() {}\n");
    }

    /// Fails by: a line from another package's unit kept, which put a
    /// dependency's non-test warnings in the test stream.
    #[test]
    fn only_the_named_packages_messages_are_kept() {
        let mine = r#"{"reason":"compiler-message","package_id":"path+file:///w/crates/batten#0.1.0","message":{}}"#;
        let theirs = r#"{"reason":"compiler-message","package_id":"path+file:///w/crates/batten-codemods#0.1.0","message":{}}"#;
        let kept = only_package(&format!("{mine}\n{theirs}\n"), "batten");
        assert_eq!(kept, format!("{mine}\n"));
    }

    /// Fails by: a removal reported by both builds applied twice and refused
    /// as overlapping, or not applied at all.
    #[test]
    fn a_removal_both_builds_report_is_applied_once() {
        let line = unused("src/a.rs", 14, 27, 2);
        let plan = plan(
            Streams {
                non_test: &line,
                unit_test: &line,
                other: &line,
            },
            &reader(),
        );
        assert_eq!(plan.edits["src/a.rs"].len(), 1);
        assert_eq!(
            apply(SRC, &plan.edits["src/a.rs"]).expect("applies"),
            "use std::fmt;\nfn f() {}\n"
        );
    }

    /// Fails by: the library's non-test warning, repeated by an integration
    /// test's build of it, read as "unused in tests" and deleted. Measured on
    /// the applier's first real run: `VocabularyWord` in `verdict.rs`.
    #[test]
    fn a_library_warning_another_target_repeats_is_still_gated() {
        let lib = unused("src/a.rs", 0, 14, 1);
        let plan = plan(
            Streams {
                non_test: &lib,
                unit_test: "",
                other: &lib,
            },
            &reader(),
        );
        assert_eq!((plan.gated, plan.edits["src/a.rs"].len()), (1, 1));
        assert!(
            apply(SRC, &plan.edits["src/a.rs"])
                .expect("applies")
                .starts_with("#[cfg(test)]\nuse std::fmt;\n")
        );
    }

    /// Fails by: an import the TEST build alone reports gated as if tests used
    /// it. Unused only where tests are compiled means test-only code imports
    /// it for nothing, so it is deleted.
    #[test]
    fn an_import_only_the_test_build_reports_is_deleted() {
        let test = unused("src/a.rs", 0, 14, 1);
        let plan = plan(
            Streams {
                non_test: "",
                unit_test: &test,
                other: "",
            },
            &reader(),
        );
        assert_eq!((plan.gated, plan.left, plan.errors), (0, 0, 0));
        assert_eq!(
            apply(SRC, &plan.edits["src/a.rs"]).expect("applies"),
            "use std::io;\nfn f() {}\n"
        );
    }
}
