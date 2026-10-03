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

use std::collections::{BTreeMap, BTreeSet};
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

/// Read `<testsuite>` elements out of a `JUnit` report.
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
    table(rows, BATS_PREAMBLE, "suites", "serial total", "suite")
}

/// The nextest table: one row per MODULE, which is what a row names there — a
/// bats row is a file, a nextest row is a module path inside one test binary.
//MUTANT-SUITE crates/batten/src/suites.rs
//MUTANT nextest-rows-labelled-suites|s@^        "module",$@        "suite",@|a_nextest_table_says_its_figures_are_summed_case_durations
fn nextest_table(rows: &[Row]) -> String {
    table(
        rows,
        NEXTEST_PREAMBLE,
        "modules",
        "sum of case durations",
        "module",
    )
}

/// What the bats corpus's numbers mean: each suite ran alone and serially.
const BATS_PREAMBLE: &[&str] = &[
    "# Per-suite cost of `test:bats`",
    "",
    "Generated by `batten record suites` from the report `test:bats` writes.",
    "Do not hand-edit. Durations are wall clock for the suite alone, as the",
    "runner measured it; the suite runs `--no-parallelize-within-files`, so a",
    "file's number is its own serial cost and is what an author adding a case",
    "to it pays.",
];

/// What a nextest table's numbers mean, which is NOT the bats corpus's: nextest
/// runs cases concurrently, so a module's figure is the sum of its cases' own
/// durations rather than a share of the run's wall clock.
const NEXTEST_PREAMBLE: &[&str] = &[
    "# Per-module cost of the nextest run",
    "",
    "Generated by `batten record suites` from the JUnit report nextest writes.",
    "Each figure is the sum of the module's case durations. nextest runs cases",
    "concurrently, so a figure is what the module's cases cost, not the share",
    "of the run's wall clock they occupied.",
];

/// The table under `preamble`, its count, total and row column labelled for what
/// they are.
fn table(rows: &[Row], preamble: &[&str], counted: &str, summed: &str, column: &str) -> String {
    let total: f64 = rows.iter().map(|row| row.seconds).sum();
    // ONE OWNED STRING PER LINE, joined once. `push_str(&format!(..))` is what
    // this said first and `format_push_string` refuses it: every call allocates a
    // String only to copy it into another. `write!` into a `String` is the lint's
    // own suggestion and costs a `fmt::Result` at every line that cannot fail,
    // which is a discarded verdict on eleven lines to avoid one allocation in a
    // function that runs once per `record suites`.
    // EVERY ELEMENT IS ONE LINE with no embedded newline, and the blank lines are
    // empty elements, so the join below reproduces the previous bytes exactly --
    // which matters, because the membership gate reads this file.
    let mut lines: Vec<String> = preamble.iter().map(|line| (*line).to_owned()).collect();
    lines.extend([
        String::new(),
        format!("- {counted}: {}", rows.len()),
        format!("- {summed}: {total:.1}s"),
        String::new(),
        format!("| seconds | share | {column} |"),
        "| ---: | ---: | --- |".to_owned(),
    ]);
    for row in rows {
        let share = if total > 0.0 {
            (row.seconds / total) * 100.0
        } else {
            0.0
        };
        lines.push(format!(
            "| {:.1} | {share:.1}% | `{}` |",
            row.seconds, row.suite
        ));
    }
    lines.push(String::new());
    lines.join("\n")
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
            "record suites: no report at {REPORT} — the suite runner has not written one in this \
             tree, or a receipt let it skip. Run the suite first; this reads a report and measures \
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
             Run the suite again to produce a report over the suites that exist, then re-run.",
            orphans.len()
        )));
    }
    let text = render(&rows);
    Ok((rows, text))
}

/// Whether `path` is one of the shared inputs the consumer declared.
///
/// **DECLARED, NOT ENUMERATED HERE** (review of #928). This was a constant
/// listing this repository's task runner, gate config, lockfile and harness
/// settings, which non-negotiable rule 1 refuses: the core knows the
/// RELATIONSHIP — a path every suite depends on widens the run — and `[ci]
/// suite_shared` is where a consumer names its own. The engine's half is the
/// spelling, which is `slow_inert`'s: an entry ending `/` covers a directory,
/// anything else must match exactly — so an entry cannot quietly cover a
/// neighbour whose name merely starts with it.
///
/// The example that would make that concrete is a consumer path, and naming one
/// here is what `no_artifact_name_reaches_the_core` refuses, doc comment
/// included. It is in `batten.toml` beside the declaration instead.
fn is_shared(path: &str, shared: &[String]) -> bool {
    shared.iter().any(|entry| {
        entry.strip_suffix('/').map_or(entry == path, |directory| {
            path.starts_with(&format!("{directory}/"))
        })
    })
}

/// Which suites a diff can move, or every suite and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The suites to run, sorted.
    pub suites: Vec<String>,
    /// Why the selection widened to everything, or `None` where it narrowed.
    ///
    /// Pointer-only (rule 4): the path that forced the widening and the reason,
    /// never a line of anybody's diff.
    pub widened: Option<String>,
}

/// Decide which bats suites a changed set can move.
///
/// # THE ASYMMETRY DECIDES THE WHOLE DESIGN
///
/// A selection that is too WIDE costs money and is obvious in the bill. One that
/// is too NARROW does not fail: the suites simply do not run, the count matches
/// whatever was selected, and a regression lands green. There is no symptom. So
/// this is a DENY-LIST, never an allow-list — selection applies only when every
/// changed path is provably inert with respect to every other suite, and
/// anything else runs everything.
///
/// Pure over its inputs, which is what lets the decision be exercised without
/// paying for the run it gates. The caller resolves `changed`, `suites` and each
/// suite's declared subjects; nothing here reads the filesystem.
///
/// An EMPTY changed set widens. It is not "nothing to run": it is a question
/// this could not answer, because a caller running the task by hand on a clean
/// tree still wants the suite.
#[must_use]
pub fn select(
    changed: &BTreeSet<String>,
    suites: &BTreeSet<String>,
    subjects: &BTreeMap<String, BTreeSet<String>>,
    shared: &[String],
) -> Selection {
    let everything = || Vec::from_iter(suites.iter().cloned());
    if changed.is_empty() {
        return Selection {
            suites: everything(),
            widened: Some(String::from("no changed paths could be computed")),
        };
    }
    // AN UNDECLARED SHARED SET WIDENS, which is the opposite of what an empty
    // `slow_inert` does and is the asymmetry this function's header states: a
    // selection that is too narrow has no symptom, so "this tree has not said
    // what its shared inputs are" must answer with every suite rather than with
    // a confident subset.
    if shared.is_empty() {
        return Selection {
            suites: everything(),
            widened: Some(String::from(
                "`[ci] suite_shared` declares no shared input, so no diff can be judged narrow",
            )),
        };
    }

    let mut selected: BTreeSet<String> = BTreeSet::new();
    for path in changed {
        if is_shared(path, shared) {
            return Selection {
                suites: everything(),
                widened: Some(format!(
                    "{path} is an input to suites whose subject does not name it"
                )),
            };
        }
        // A suite selects itself; a `mise-tasks/` program resolves through the
        // declared headers. Nothing is inferred from the FILENAME: CLOUD-807
        // measured 19 of 142 suites with no same-named program and every one
        // legitimate, so a name heuristic would both skip real work and select
        // the wrong thing.
        if path.starts_with("tests/")
            && Path::new(path).extension().is_some_and(|ext| ext == "bats")
        {
            // A DELETED SUITE HAS NOTHING TO RUN. The changed set reports a
            // removed path, and handing bats a file it cannot open is a failure
            // rather than coverage — reachable in this very campaign, which
            // retires suites.
            if suites.contains(path) {
                selected.insert(path.clone());
            }
            continue;
        }
        if !path.starts_with("mise-tasks/") {
            return Selection {
                suites: everything(),
                widened: Some(format!(
                    "{path} is outside the set selection can reason about"
                )),
            };
        }
        // The header is `# subject:` followed by whitespace-separated paths, so
        // the match is on a WHOLE FIELD rather than a substring: `mise-tasks/land`
        // must not select a suite whose subject is `mise-tasks/land-lock`.
        let hits: Vec<&String> = subjects
            .iter()
            .filter(|(_, declared)| declared.contains(path))
            .map(|(suite, _)| suite)
            .collect();
        // A path under `mise-tasks/` that no suite declares as its subject is a
        // program nothing covers, or a header that has rotted. Either way this
        // cannot say which suites it moves, and could-not-look widens.
        if hits.is_empty() {
            return Selection {
                suites: everything(),
                widened: Some(format!("no suite declares {path} as its subject")),
            };
        }
        selected.extend(hits.into_iter().cloned());
    }

    Selection {
        suites: selected.into_iter().collect(),
        widened: None,
    }
}

/// Where the corpus is written.
#[must_use]
pub fn corpus_path(root: &Path) -> PathBuf {
    root.join(CORPUS)
}

/// Where cargo-nextest writes a profile's `JUnit` report, relative to the
/// repository root (CLOUD-2059).
///
/// nextest's own layout — `target/nextest/<profile>/` plus the file name the
/// profile's `[profile.<name>.junit] path` declares — so the engine names the
/// runner's convention and no consumer's (non-negotiable rule 1). The file name is
/// the consumer's, read from its own nextest config by the caller's reader of
/// choice; this is the conventional one.
pub const NEXTEST_REPORT_DIR: &str = "target/nextest";

/// The report file name a nextest profile writes when it declares `junit.xml`.
pub const NEXTEST_REPORT_FILE: &str = "junit.xml";

/// Read `<testcase>` elements out of a nextest `JUnit` report, one row per
/// MODULE: the binary's suite name, then the test name's first path segment.
///
/// **Per module rather than per case**, for the bats corpus's reason: the reader
/// is an author asking whether the file they are about to add a case to is
/// expensive, and a module is that file. A case is `path::to::module::name` and
/// its module is everything before the LAST `::`, so `outer::fast::a` and
/// `outer::slow::b` stay two rows; a case with no `::` is its own module, so
/// nothing is dropped.
///
/// Text rather than a parser, as [`rows_in`] reads: the element shape is fixed
/// by the runner's formatter.
#[must_use]
pub fn nextest_rows(report: &str) -> Vec<Row> {
    /// The classname prefix nextest gives a setup script's `<testcase>`.
    const SETUP_SCRIPT_CLASS: &str = "@setup-script:";

    let mut totals: BTreeMap<String, f64> = BTreeMap::new();
    for chunk in report.split("<testcase").skip(1) {
        let element = chunk.split_once('>').map_or(chunk, |(head, _)| head);
        let (Some(name), Some(binary), Some(time)) = (
            attribute(element, "name"),
            attribute(element, "classname"),
            attribute(element, "time"),
        ) else {
            continue;
        };
        let Ok(seconds) = time.parse::<f64>() else {
            continue;
        };
        // A SETUP SCRIPT IS NOT A MODULE. nextest reports each one it ran as a
        // `<testcase>` whose classname is `@setup-script:<name>`, and this
        // repository's `clear-scratch` runs on every invocation — so it would be
        // a row an author could never add a case to.
        if binary.starts_with(SETUP_SCRIPT_CLASS) {
            continue;
        }
        let module = name.rsplit_once("::").map_or(name, |(module, _)| module);
        *totals.entry(format!("{binary}::{module}")).or_default() += seconds;
    }
    let mut rows: Vec<Row> = totals
        .into_iter()
        .map(|(suite, seconds)| Row { suite, seconds })
        .collect();
    rows.sort_by(|left, right| right.seconds.total_cmp(&left.seconds));
    rows
}

/// Derive the per-module table from a nextest profile's report, or say why it
/// could not be.
///
/// # Errors
///
/// A usage error when the report is absent or carries no readable case: both are
/// could-not-look, never an empty suite.
pub fn derive_nextest(root: &Path, profile: &str) -> Result<(Vec<Row>, String)> {
    let relative = format!("{NEXTEST_REPORT_DIR}/{profile}/{NEXTEST_REPORT_FILE}");
    let Ok(report) = std::fs::read_to_string(root.join(&relative)) else {
        return Err(UsageError::raise(format!(
            "record suites: no report at {relative} — nextest has not written one for profile \
             `{profile}` in this tree. Run the suite first; this reads a report and measures \
             nothing itself."
        )));
    };
    let rows = nextest_rows(&report);
    if rows.is_empty() {
        return Err(UsageError::raise(format!(
            "record suites: {relative} carries no <testcase> element with a name, a classname \
             and a time, so there is nothing to derive. This is could-not-look, not an empty \
             suite."
        )));
    }
    let text = nextest_table(&rows);
    Ok((rows, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::expect_used)]
    fn tracked(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Fails by: keying on the first `::` segment (a nested module folds into its
    /// parent), counting a setup script as a module, or dropping the cost order.
    #[test]
    fn a_nextest_report_yields_one_row_per_module_ordered_by_cost() {
        let report = concat!(
            "<testsuites>\n",
            "<testsuite name=\"batten::it\" tests=\"3\">\n",
            "<testcase name=\"cli::a\" classname=\"batten::it\" time=\"1.5\">\n</testcase>\n",
            "<testcase name=\"cli::b\" classname=\"batten::it\" time=\"2.0\"/>\n",
            "<testcase name=\"board::c\" classname=\"batten::it\" time=\"9.25\"/>\n",
            "<testcase name=\"cli::nested::d\" classname=\"batten::it\" time=\"0.75\"/>\n",
            "<testcase name=\"lonely\" classname=\"batten\" time=\"0.5\"/>\n",
            "</testsuite>\n",
            "<testsuite name=\"@setup-script:clear-scratch\" tests=\"1\">\n",
            "<testcase name=\"clear-scratch\" classname=\"@setup-script:clear-scratch\" time=\"40\"/>\n",
            "</testsuite>\n</testsuites>\n",
        );
        let rows = nextest_rows(report);
        let named: Vec<String> = rows
            .iter()
            .map(|row| format!("{} {:.2}", row.suite, row.seconds))
            .collect();
        assert_eq!(
            named,
            vec![
                "batten::it::board 9.25",
                "batten::it::cli 3.50",
                "batten::it::cli::nested 0.75",
                "batten::lonely 0.50",
            ],
            "a nested module is its own row, never folded into its parent, and a setup \
             script is no row at all"
        );
    }

    /// Fails by: rendering the nextest table with the bats corpus's serial-total
    /// wording, which a concurrent run's summed case durations are not.
    #[test]
    fn a_nextest_table_says_its_figures_are_summed_case_durations() {
        let rows = vec![Row {
            suite: "batten::it::cli".to_owned(),
            seconds: 2.0,
        }];
        let text = nextest_table(&rows);
        assert!(text.contains("- sum of case durations: 2.0s"), "{text}");
        assert!(
            text.contains("| seconds | share | module |"),
            "a nextest row is a module, not a suite: {text}"
        );
        assert!(
            !text.contains("serial") && !text.contains("--no-parallelize-within-files"),
            "a concurrent run's sum is not a serial cost: {text}"
        );
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
