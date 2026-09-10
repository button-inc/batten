//! `suite-cost-corpus` and `batten record suites` over the compiled binary —
//! CLOUD-352, ported off `mise-tasks/suite-bench.sh` and
//! `mise-tasks/suite-bench-check.sh` under CLOUD-1753.
//!
//! # The pair, and why the split is the design
//!
//! The producer derives what each suite costs from the report the runner already
//! wrote; the gate decides MEMBERSHIP over the corpus it writes. That division is
//! the whole point and the retired programs argued it in their own words: wall
//! clock is a CLOCK — the same suite varies with load, and a gate demanding byte
//! equality on a duration would be red on every second run and switched off
//! within a day. Membership is deterministic and costs nothing, and it is what
//! rots: a suite added and never recorded is invisible to everything that reads
//! the corpus, and a row naming a deleted suite is a figure attached to nothing.
//!
//! # WHAT THIS TIER REACHES THAT THE MODULE'S OWN CASES CANNOT
//!
//! Two things, and the first was measured the hard way while writing this port.
//!
//! **That the ENGINE resolves the declared `lines` path to the committed bytes,
//! and `input.tree.tracked` to the index.** A `with input as` fixture fabricates
//! exactly the shape the boundary may be unable to produce (CLOUD-845) — and
//! here the fixture was wrong for several runs: it keyed its `lines` object with
//! a rule reference, so `corpus_lines` resolved against nothing. **Every "clean"
//! case still passed**, because a fixture that resolves to nothing produces no
//! findings and reads exactly like a clean tree. That is the load-time tier
//! failing in the direction this tier exists to cover.
//!
//! **That the producer and the gate agree on the corpus.** They are two halves of
//! one contract — `suites::CORPUS` and the rule's `lines` row — and nothing in
//! either half can see the other. A port that let them pick their own locations
//! would have disconnected them silently, which is the same class of failure one
//! level up.
//
// carried: mise-tasks/suite-bench.sh crates/batten/src/suites.rs kind:verb crates/batten/tests/it/suite_cost_corpus.rs runs:batten+record+suites
// carried: mise-tasks/suite-bench-check.sh policy/suite-cost-corpus.rego crates/batten/tests/it/suite_cost_corpus.rs
// carried: tests/suite-bench-check.bats policy/suite-cost-corpus.rego crates/batten/tests/it/suite_cost_corpus.rs
//
// carried: "a corpus naming exactly the tracked suites passes" policy/suite-cost-corpus.rego
// carried: "a suite absent from the corpus is refused" policy/suite-cost-corpus.rego
// carried: "a corpus row naming no real suite is refused" policy/suite-cost-corpus.rego
// carried: "an untracked suite is not demanded — the corpus describes the tree git carries" policy/suite-cost-corpus.rego
// carried: "a missing corpus is could-not-look, not a clean tree" policy/suite-cost-corpus.rego
// carried: "a corpus with no rows is could-not-look, not an empty suite set" policy/suite-cost-corpus.rego
// carried: "no tracked suite at all is could-not-look" policy/suite-cost-corpus.rego
// carried: "output is a pointer — no duration is echoed" policy/suite-cost-corpus.rego
// carried: "a report naming a suite the tree does not track is could-not-look" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/suite_cost_corpus.rs runs:batten+record+suites
// carried: "a report naming only tracked suites derives a corpus" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/suite_cost_corpus.rs runs:batten+record+suites

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::batten;

/// A repository carrying suites, a report, and optionally a corpus.
fn bench(name: &str, suites: &[&str], corpus: Option<&str>) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-suite-corpus", name);
    common::init_repo(&dir);
    common::write(&dir, "batten.toml", &config());
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    for suite in suites {
        common::write(&dir.join("tests"), suite, "#!/usr/bin/env bats\n");
    }
    if let Some(text) = corpus {
        std::fs::create_dir_all(dir.join("bench").join("suites")).unwrap();
        common::write(&dir.join("bench").join("suites"), "RESULTS.md", text);
    }
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

/// The one rule under test, registered against the module in this repository.
///
/// **The four verdicts are declared here too, and that is the ABI rather than
/// boilerplate.** A module raising a verdict no `[[verdict]]` row declares is
/// refused at load — the refusal would carry no gloss, no class and no route,
/// which is the bare no the vocabulary exists to make unwritable. So a fixture
/// registering the module and not its verdicts does not test the module, it
/// tests the loader; this suite met that on its first run.
fn config() -> String {
    let module = common::at_root("policy/suite-cost-corpus.rego")
        .to_string_lossy()
        .into_owned();
    let mut out = format!(
        "version = 1\n\n[[rule]]\nid = \"suite-cost-corpus\"\nkind = \"policy\"\nscope = \"tree\"\n\
         lines = [\"bench/suites/RESULTS.md\"]\nmodule = {module:?}\nseverity = \"deny\"\n"
    );
    for (id, gloss) in [
        (
            "suite count unread",
            "the cost corpus is absent or carries no row",
        ),
        ("suite list empty", "no tracked bats suite exists"),
        (
            "suite count absent",
            "a tracked suite has no row in the cost corpus",
        ),
        (
            "suite count dead",
            "the cost corpus records a suite this tree does not track",
        ),
    ] {
        out.push_str(&format!(
            "\n[[verdict]]\nid = {id:?}\ngloss = {gloss:?}\nclass = \"\"\"\n{gloss}\n\"\"\"\n\n\
             [[verdict.route]]\nid = \"suite measure now\"\nkind = \"command\"\n\
             target = \"batten record suites --write\"\n"
        ));
    }
    out
}

/// A corpus body in the shape the producer emits.
fn corpus(rows: &[(&str, &str)]) -> String {
    let mut out = String::from(
        "# Per-suite cost of `test:bats`\n\n| seconds | share | suite |\n| ---: | ---: | --- |\n",
    );
    for (seconds, suite) in rows {
        out.push_str(&format!("| {seconds} | 50.0% | `{suite}` |\n"));
    }
    out
}

fn check(dir: &Path) -> Output {
    batten()
        .arg("check")
        .arg("--rule")
        .arg("suite-cost-corpus")
        .current_dir(dir)
        .env_remove("BATTEN_STRICTNESS")
        .output()
        .expect("run batten check")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_corpus_covering_every_tracked_suite_passes() {
    let dir = bench(
        "clean",
        &["a.bats", "b.bats"],
        Some(&corpus(&[("4.5", "tests/a.bats"), ("0.5", "tests/b.bats")])),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
}

#[test]
fn a_tracked_suite_missing_from_the_corpus_is_refused() {
    let dir = bench(
        "unrecorded",
        &["a.bats", "unrecorded.bats"],
        Some(&corpus(&[("4.5", "tests/a.bats")])),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    // POINTER, NEVER PAYLOAD, and the pointer is what tells the two directions
    // apart: `check` renders `<pointer> <rule>`, so the SUBJECT is the assertion.
    // The verdict tokens are pinned by the module's own load-time cases; what
    // this tier owns is that the engine reached the right one.
    assert!(
        said(&output).contains("tests/unrecorded.bats"),
        "{}",
        said(&output)
    );
    assert!(!said(&output).contains("4.5"), "{}", said(&output));
}

#[test]
fn a_corpus_row_naming_no_tracked_suite_is_refused() {
    let dir = bench(
        "phantom",
        &["a.bats"],
        Some(&corpus(&[
            ("4.5", "tests/a.bats"),
            ("1.0", "tests/retired.bats"),
        ])),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    // The pointer is the corpus ROW, where the missing-suite direction points at
    // the tracked path — which is how a reader tells them apart at a glance.
    assert!(
        said(&output).contains("tests/retired.bats"),
        "{}",
        said(&output)
    );
}

#[test]
fn both_directions_are_reported_in_one_run() {
    // A corpus can rot in both directions at once, and reporting only the first
    // makes the second a second trip.
    let dir = bench(
        "both",
        &["a.bats", "unrecorded.bats"],
        Some(&corpus(&[
            ("4.5", "tests/a.bats"),
            ("1.0", "tests/retired.bats"),
        ])),
    );
    let text = said(&check(&dir));
    assert!(text.contains("tests/unrecorded.bats"), "{text}");
    assert!(text.contains("tests/retired.bats"), "{text}");
}

#[test]
fn a_missing_corpus_is_could_not_look_rather_than_a_clean_corpus() {
    // THE ARM THAT MATTERS MOST, and the one a fixture cannot honestly reach:
    // the engine still acquires a declared literal `lines` path that no file
    // satisfies, so the module evaluates and reports rather than being SKIPPED.
    let dir = bench("no-corpus", &["a.bats"], None);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("bench/suites/RESULTS.md"),
        "{}",
        said(&output)
    );
}

#[test]
fn an_empty_corpus_is_could_not_look_rather_than_a_clean_corpus() {
    let dir = bench("empty-corpus", &["a.bats"], Some(&corpus(&[])));
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("bench/suites/RESULTS.md"),
        "{}",
        said(&output)
    );
}

#[test]
fn no_tracked_suites_is_could_not_look_rather_than_a_clean_corpus() {
    // The corpus would have no subject. Reporting green over that is the
    // collapse this repository keeps meeting in new disguises.
    let dir = bench(
        "no-suites",
        &[],
        Some(&corpus(&[("1.0", "tests/gone.bats")])),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("suite-cost-corpus"),
        "{}",
        said(&output)
    );
}

#[test]
fn the_formatters_padding_does_not_defeat_the_row_match() {
    // MEASURED ON THE RETIRED PROGRAM: `prettier` owns Markdown here and aligns
    // table columns, and its first pattern required exactly one space before the
    // closing pipe. Against a formatted corpus it matched no row at all and
    // reported every tracked suite missing — 150 findings, all false, from a gate
    // that looked like it was working.
    let dir = bench("padded", &["a.bats"], None);
    std::fs::create_dir_all(dir.join("bench").join("suites")).unwrap();
    common::write(
        &dir.join("bench").join("suites"),
        "RESULTS.md",
        "| seconds | share | suite |\n| ---: | ---: | --- |\n|   4.5 |  100.0% | `tests/a.bats`   |\n",
    );
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "padded"]);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
}

// --- the producer -------------------------------------------------------------

fn record(dir: &Path, write: bool) -> Output {
    let mut command = batten();
    command.arg("record").arg("suites");
    if write {
        command.arg("--write");
    }
    command
        .current_dir(dir)
        .output()
        .expect("run batten record suites")
}

fn report(dir: &Path, suites: &[(&str, &str)]) {
    std::fs::create_dir_all(dir.join("target").join("bats-report")).unwrap();
    let mut xml = String::from("<testsuites>\n");
    for (name, time) in suites {
        xml.push_str(&format!(
            "<testsuite name=\"{name}\" tests=\"1\" time=\"{time}\">\n</testsuite>\n"
        ));
    }
    xml.push_str("</testsuites>\n");
    common::write(&dir.join("target").join("bats-report"), "report.xml", &xml);
}

#[test]
fn a_report_naming_a_suite_the_tree_does_not_track_is_could_not_look() {
    // THE REMEDY MUST REACH THE STATE IT PRESCRIBES. A suite retired while the
    // report still named it made the regenerated corpus carry a cost attached to
    // nothing — so the gate refused the very file its own remedy had just
    // produced, and the author reads the gate as broken rather than the report as
    // stale.
    let dir = bench("stale-report", &["a.bats"], None);
    report(&dir, &[("a.bats", "1.0"), ("retired.bats", "2.0")]);
    let output = record(&dir, false);
    assert_ne!(output.status.code(), Some(0), "{}", said(&output));
    assert!(
        said(&output).contains("does not track"),
        "{}",
        said(&output)
    );
}

#[test]
fn a_report_naming_only_tracked_suites_derives_a_corpus() {
    let dir = bench("derive", &["a.bats", "b.bats"], None);
    report(&dir, &[("a.bats", "3.0"), ("b.bats", "1.0")]);
    let output = record(&dir, false);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let text = said(&output);
    // Ordered by cost, descending: the corpus is read by an author asking which
    // side of the distribution a file sits on, and the answer is at the top.
    let slow = text.find("tests/a.bats").expect("the slow suite");
    let quick = text.find("tests/b.bats").expect("the quick suite");
    assert!(slow < quick, "{text}");
    assert!(text.contains("75.0%"), "{text}");
}

#[test]
fn an_absent_report_is_could_not_look_rather_than_an_empty_corpus() {
    // `test:bats` is receipt-gated, so a tree whose receipt is valid skips the
    // run and an absent report is the ORDINARY state after a no-op lap. Writing
    // that out as "every suite costs nothing" would publish the collapse rather
    // than merely compute it.
    let dir = bench("no-report", &["a.bats"], None);
    let output = record(&dir, false);
    assert_ne!(output.status.code(), Some(0), "{}", said(&output));
    assert!(said(&output).contains("has not run"), "{}", said(&output));
}

#[test]
fn the_producer_writes_a_corpus_the_gate_accepts() {
    // THE TWO HALVES OF ONE CONTRACT, and neither can see the other: the producer
    // spells the path as `suites::CORPUS` and the rule spells it in its `lines`
    // row. A port that let them pick their own locations would have disconnected
    // them with nothing red.
    let dir = bench("round-trip", &["a.bats", "b.bats"], None);
    report(&dir, &[("a.bats", "3.0"), ("b.bats", "1.0")]);
    let written = record(&dir, true);
    assert_eq!(written.status.code(), Some(0), "{}", said(&written));
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "corpus"]);
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
}
