//! The per-suite cost corpus: derive what each bats suite costs from the report
//! the runner already wrote (CLOUD-352), ported off `mise-tasks/suite-bench.sh`
//! under CLOUD-1753.
//!
//! # What this is for
//!
//! `test:bats` is thousands of cases over dozens of suites and the distribution
//! is extremely uneven — measured 2026-08-21, `land-lock.bats` at 175.8s against
//! a median under 5s. Nothing told an author which side of that a suite they were
//! editing sits on, and the timeout budgets that would eventually notice fire
//! minutes after a push, against an agent whose context is gone.
//!
//! # IT RUNS NOTHING, and that is the load-bearing property
//!
//! The corpus is derived from the report `test:bats` leaves behind. Re-executing
//! a multi-thousand-case suite to measure it would cost more than the waste it
//! reports, and would be a SECOND AUTHORITY over a run that already happened.
//! This module opens one file and writes one file; it spawns nothing, which is
//! also what keeps it out of `policy/spawn-adapters.rego` entirely.
//!
//! # A MISSING REPORT IS COULD-NOT-LOOK, never an empty corpus
//!
//! `test:bats` is receipt-gated, so a tree whose receipt is valid skips the run
//! entirely and an absent report is the ORDINARY state after a no-op lap.
//! Writing that out as "every suite costs nothing" is the CLOUD-251 collapse, and
//! it would be published rather than merely computed.
//!
//! # A REPORT OLDER THAN THE TREE IS ALSO COULD-NOT-LOOK
//!
//! This is faithful to the report, which is what makes it trustworthy and also
//! what made `--write` useless in one measured case: a suite retired, the report
//! still named it, so the regenerated corpus carried a cost attached to nothing
//! and the gate refused the very file its own remedy had just produced. A remedy
//! that cannot reach the state it prescribes is worse than no remedy — the author
//! reads the gate as broken rather than the report as stale. So a report naming a
//! suite this tree does not track is refused BY NAME, with the count and the
//! paths, before anything is written.
//!
//! # Durations are a CLOCK, not a gate
//!
//! Nothing here fails on a number moving. `rules/toolchain.md` puts a clock in a
//! drift job rather than in a gate, and what the companion rule decides is
//! MEMBERSHIP — which is deterministic — never a duration.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::UsageError;

/// Where the runner leaves its report, relative to the repository root.
///
/// Under `target/`, which is gitignored, so producing it cannot dirty the tree
/// and `receipt clean` stays green.
pub const REPORT: &str = "target/bats-report/report.xml";

/// The corpus this derives, relative to the repository root.
///
/// **A committed path, and the companion rule reads it by name.** The gate that
/// decides membership is a `[[rule]]` over these bytes, so the location is a
/// contract between the two halves rather than an implementation detail.
pub const CORPUS: &str = "bench/suites/RESULTS.md";

/// One suite's own wall clock, as the runner measured it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// The suite path, as the corpus spells it (`tests/<name>`).
    pub suite: String,
    /// Seconds, at the precision the report carries.
    pub seconds: f64,
}

/// Read `<testsuite>` elements out of a JUnit report.
///
/// **Text rather than a parser, for `ci-tools`' reason**: the shape is fixed by
/// the formatter the runner ships, and an XML parser is a dependency this
/// judgement does not otherwise need. The retired program said the same and read
/// the same two attributes.
///
/// Order is by cost, descending, because the corpus is read by an author asking
/// "is the file I am editing expensive" and the answer is at the top.
#[must_use]
pub fn rows_in(report: &str) -> Vec<Row> {
    let mut rows: Vec<Row> = report
        .lines()
        .filter_map(|line| {
            let element = line.split_once("<testsuite")?.1;
            let name = attribute(element, "name")?;
            let time = attribute(element, "time")?;
            let seconds = time.parse::<f64>().ok()?;
            Some(Row {
                suite: format!("tests/{name}"),
                seconds,
            })
        })
        .collect();
    // `total_cmp` rather than `partial_cmp`: a `NaN` time would otherwise make
    // the ordering inconsistent and the sort's output unspecified, which is a
    // corpus whose rows move between runs for no reason a reader can see.
    rows.sort_by(|left, right| right.seconds.total_cmp(&left.seconds));
    rows
}

/// One attribute's value out of an element's text.
fn attribute<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let after = element.split_once(needle.as_str())?.1;
    let (value, _) = after.split_once('"')?;
    (!value.is_empty()).then_some(value)
}

/// Render the corpus.
///
/// The share column is computed at FULL PRECISION and rounded only where it is
/// printed. Rounding first and dividing second reported a single-suite corpus as
/// 105% of itself.
#[must_use]
pub fn render(rows: &[Row]) -> String {
    let total: f64 = rows.iter().map(|row| row.seconds).sum();
    let mut out = String::new();
    out.push_str("# Per-suite cost of `test:bats`\n\n");
    out.push_str("Generated by `batten record suites` from the report `test:bats` writes.\n");
    out.push_str("Do not hand-edit. Durations are wall clock for the suite alone, as the\n");
    out.push_str("runner measured it; the suite runs `--no-parallelize-within-files`, so a\n");
    out.push_str("file's number is its own serial cost and is what an author adding a case\n");
    out.push_str("to it pays.\n\n");
    out.push_str(&format!("- suites: {}\n", rows.len()));
    out.push_str(&format!("- serial total: {total:.1}s\n\n"));
    out.push_str("| seconds | share | suite |\n| ---: | ---: | --- |\n");
    for row in rows {
        let share = if total > 0.0 {
            (row.seconds / total) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "| {:.1} | {share:.1}% | `{}` |\n",
            row.seconds, row.suite
        ));
    }
    out
}

/// Which of `rows` name a suite `tracked` does not carry.
///
/// Pointer-only (rule 4): the caller reports the count and the paths, which is
/// what a reader acts on, and never a duration — a number here would be a second
/// authority over the corpus.
#[must_use]
pub fn stale(rows: &[Row], tracked: &BTreeSet<String>) -> Vec<String> {
    rows.iter()
        .map(|row| row.suite.clone())
        .filter(|suite| !tracked.contains(suite))
        .collect()
}

/// Derive the corpus, or say why it could not be.
///
/// # Errors
///
/// An internal error (exit `3`) when the report is absent, carries no readable
/// `<testsuite>` element, or names a suite this tree does not track. All three
/// are could-not-look, and none of them is an empty corpus.
pub fn derive(root: &Path, tracked: &BTreeSet<String>) -> Result<(Vec<Row>, String)> {
    let path = root.join(REPORT);
    let Ok(report) = std::fs::read_to_string(&path) else {
        return Err(UsageError::raise(format!(
            "record suites: no report at {REPORT} — `test:bats` has not run in this tree, or its \
             receipt let it skip. Run `mise run test:bats` first; this reads a report and measures \
             nothing itself."
        )));
    };
    let rows = rows_in(&report);
    if rows.is_empty() {
        return Err(UsageError::raise(format!(
            "record suites: {REPORT} carries no <testsuite> element with a name and a time, so \
             there is nothing to derive. This is could-not-look, not an empty corpus."
        )));
    }
    let orphans = stale(&rows, tracked);
    if !orphans.is_empty() {
        return Err(UsageError::raise(format!(
            "record suites: {REPORT} names {} suite(s) this tree does not track — the report \
             predates the tree, so deriving from it would publish a cost for a suite that is gone. \
             Run `mise run test:bats` to produce a report over the suites that exist, then re-run.",
            orphans.len()
        )));
    }
    let text = render(&rows);
    Ok((rows, text))
}

/// Where the corpus is written.
#[must_use]
pub fn corpus_path(root: &Path) -> PathBuf {
    root.join(CORPUS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::expect_used)]
    fn tracked(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_report_yields_one_row_per_suite_ordered_by_cost() {
        let report = concat!(
            "<testsuites>\n",
            "<testsuite name=\"quick.bats\" tests=\"2\" time=\"1.5\">\n",
            "<testsuite name=\"slow.bats\" tests=\"9\" time=\"42.25\">\n",
            "</testsuites>\n",
        );
        let rows = rows_in(report);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].suite, "tests/slow.bats");
        assert_eq!(rows[1].suite, "tests/quick.bats");
    }

    #[test]
    fn an_element_missing_either_attribute_yields_no_row() {
        // Not a zero. A suite whose time the report does not carry is a suite
        // this cannot answer about, and a `0.0` there would publish it as the
        // cheapest file in the tree.
        let report = "<testsuite name=\"nameless.bats\">\n<testsuite time=\"3.0\">\n";
        assert!(rows_in(report).is_empty());
    }

    #[test]
    fn the_share_column_is_computed_before_rounding() {
        // Rounding first and dividing second reported a single-suite corpus as
        // 105% of itself.
        let rows = vec![Row {
            suite: "tests/only.bats".to_owned(),
            seconds: 0.04,
        }];
        let text = render(&rows);
        assert!(text.contains("100.0%"), "{text}");
    }

    #[test]
    fn a_row_naming_an_untracked_suite_is_stale() {
        let rows = vec![
            Row {
                suite: "tests/live.bats".to_owned(),
                seconds: 1.0,
            },
            Row {
                suite: "tests/retired.bats".to_owned(),
                seconds: 2.0,
            },
        ];
        let orphans = stale(&rows, &tracked(&["tests/live.bats"]));
        assert_eq!(orphans, vec!["tests/retired.bats".to_owned()]);
    }

    #[test]
    fn a_corpus_over_no_rows_has_no_share_to_divide_by() {
        // Zero total, and the guard is what stops a division by zero becoming a
        // `NaN%` column in a published file.
        let text = render(&[]);
        assert!(text.contains("- suites: 0"), "{text}");
    }
}
