//! `batten record suites` over the compiled binary — CLOUD-352, ported off
//! `mise-tasks/suite-bench.sh` under CLOUD-1753.
//!
//! # The producer, without the gate it used to feed
//!
//! The producer derives what each suite costs from the report the runner already
//! wrote. Wall clock is a CLOCK — the same suite varies with load — so what it
//! writes is a corpus an author reads, never a verdict.
//!
//! Its consumer in this repository was `suite measure stale`, a membership gate
//! over `bench/suites/RESULTS.md` (`policy/suite-cost-corpus.rego`). That gate
//! RETIRED UNDER CLOUD-843 together with `test:bats`, the one task whose report
//! the corpus was derived from: with the shell suite gone nothing can regenerate
//! the corpus, so a membership gate over it would have been a refusal whose own
//! remedy (`batten record suites --write`) could no longer run. The producer stays
//! as mechanism — a consumer with a bats lane still has a report to read — and
//! this tier keeps holding it to the report it reads and the path it writes.
//
// carried: mise-tasks/suite-bench.sh crates/batten/src/suites.rs kind:verb crates/batten/tests/it/suite_cost_corpus.rs runs:batten+record+suites
//
// THE HISTORICAL LEDGER, KEPT AS WRITTEN. The rows below record where the retired
// shell gate's cases went under CLOUD-1753; the module they name retired under
// CLOUD-843 with the task that fed it, and no case of theirs is dropped by that
// change — it drops the module the cases had already moved into.
//
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

use std::fmt::Write as _;

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::batten;

/// A repository carrying suites and a config that declares no rule — the
/// producer reads the tree and the report, never a row.
fn bench(name: &str, suites: &[&str]) -> PathBuf {
    let dir = common::scratch_outside_tree("batten-suite-corpus", name);
    common::init_repo(&dir);
    common::write(&dir, "batten.toml", "version = 1\n");
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    for suite in suites {
        common::write(&dir.join("tests"), suite, "#!/usr/bin/env bats\n");
    }
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

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
        write!(
            xml,
            "<testsuite name=\"{name}\" tests=\"1\" time=\"{time}\">\n</testsuite>\n"
        )
        .unwrap();
    }
    xml.push_str("</testsuites>\n");
    common::write(&dir.join("target").join("bats-report"), "report.xml", &xml);
}

#[test]
fn a_report_naming_a_suite_the_tree_does_not_track_is_could_not_look() {
    // THE REMEDY MUST REACH THE STATE IT PRESCRIBES. A suite retired while the
    // report still named it would make the regenerated corpus carry a cost
    // attached to nothing.
    let dir = bench("stale-report", &["a.bats"]);
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
    let dir = bench("derive", &["a.bats", "b.bats"]);
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
    // An absent report is the ORDINARY state of a tree whose runner has not run.
    // Writing that out as "every suite costs nothing" would publish the collapse
    // rather than merely compute it.
    let dir = bench("no-report", &["a.bats"]);
    let output = record(&dir, false);
    assert_ne!(output.status.code(), Some(0), "{}", said(&output));
    assert!(said(&output).contains("has not run"), "{}", said(&output));
}

#[test]
fn the_producer_writes_the_corpus_at_the_path_it_declares() {
    // The one half of the retired contract that is still the producer's own: it
    // writes where it says it writes, so a reader who opens that path reads what
    // the report measured rather than a file nothing regenerates.
    let dir = bench("write", &["a.bats", "b.bats"]);
    report(&dir, &[("a.bats", "3.0"), ("b.bats", "1.0")]);
    let written = record(&dir, true);
    assert_eq!(written.status.code(), Some(0), "{}", said(&written));
    let corpus = std::fs::read_to_string(dir.join(batten::suites::CORPUS))
        .expect("the corpus is written where the producer declares it");
    assert!(corpus.contains("`tests/a.bats`"), "{corpus}");
    assert!(corpus.contains("`tests/b.bats`"), "{corpus}");
}
