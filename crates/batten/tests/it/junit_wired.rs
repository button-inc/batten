//! Every nextest run leaves its per-case times behind, and `batten record suites`
//! reads them (CLOUD-2059, P0).
//!
//! # Why this is a gate and not a convenience
//!
//! Before it, the only per-case figures were whatever scrolled past in a
//! terminal: "which module is slow" was answered by grepping task logs that a
//! container reclaim deletes, and a regression in one module was invisible until
//! the whole suite crossed a timeout. The junit stanza in `.config/nextest.toml`
//! is what turns every run into a measurement, so deleting it is the regression
//! this file exists to refuse — and `junit-unwired`, declared beside the stanza,
//! is the mutation `batten mutate` uses to show that this case notices.

use std::path::Path;
use std::process::Output;

use crate::common;

/// `profile.<name>.junit.path` in the committed nextest config, if declared.
fn junit_path(config: &toml::Table, profile: &str) -> Option<String> {
    config
        .get("profile")?
        .get(profile)?
        .get("junit")?
        .get("path")?
        .as_str()
        .map(str::to_owned)
}

/// The committed nextest config, parsed.
fn nextest_config() -> toml::Table {
    std::fs::read_to_string(common::at_root(".config/nextest.toml"))
        .expect("read the committed nextest config")
        .parse()
        .expect("the nextest config is TOML")
}

/// The default profile writes the report, under the reader's own file name.
#[test]
fn the_default_profile_writes_a_junit_report() {
    let config = nextest_config();
    // THE READER'S OWN NAME, not merely a non-empty one: `derive_nextest` reads
    // `NEXTEST_REPORT_FILE`, so a stanza writing any other file leaves a report
    // nothing reads.
    let reader = batten::suites::NEXTEST_REPORT_FILE;
    assert_eq!(
        junit_path(&config, "default").as_deref(),
        Some(reader),
        ".config/nextest.toml must write `[profile.default.junit] path = '{reader}'`, or a run \
         leaves no per-case times `record suites` can read"
    );
}

/// EVERY REPORT LANDS WHERE `record suites` READS IT (review of #1089). The reader
/// opens `NEXTEST_REPORT_DIR/<profile>/NEXTEST_REPORT_FILE`, so two edits to this
/// config would move a report out from under it while the case above stayed
/// green: a `[store] dir`, which relocates every profile's directory, and a
/// profile that names its own junit file. EVERY declared profile is judged, not
/// a list of the ones that exist today, so a profile added later is covered by
/// construction.
#[test]
fn every_report_lands_where_record_suites_reads_it() {
    let config = nextest_config();
    let store = config
        .get("store")
        .and_then(|store| store.get("dir"))
        .map(|dir| dir.as_str().unwrap_or_default().trim_end_matches('/'));
    assert!(
        store.is_none_or(|dir| dir == batten::suites::NEXTEST_REPORT_DIR),
        "`[store] dir = {store:?}` moves every report out of `{}`, where `record suites` reads it",
        batten::suites::NEXTEST_REPORT_DIR
    );
    let profiles = config
        .get("profile")
        .and_then(toml::Value::as_table)
        .expect("the nextest config declares profiles");
    for name in profiles.keys() {
        let path = junit_path(&config, name);
        assert!(
            path.as_deref()
                .is_none_or(|path| path == batten::suites::NEXTEST_REPORT_FILE),
            "profile `{name}` writes its report to {path:?}, a file `record suites` never reads"
        );
    }
}

/// A SUBSET GATE NEVER OVERWRITES THE FULL SUITE'S REPORT. nextest writes the junit
/// file under the selected profile's store, and `verify` runs one-module gates
/// beside the full suite: measured, the 7,497-case report was replaced by a 12-case
/// one from whichever subset finished last. So every manifest task that runs a
/// filtered nextest selects a declared profile of its own, never the one the full
/// suite reports into.
#[test]
fn a_subset_gate_never_overwrites_the_full_suites_report() {
    let nextest = nextest_config();
    let manifest: toml::Table = std::fs::read_to_string(common::at_root("mise.toml"))
        .expect("read the manifest")
        .parse()
        .expect("the manifest is TOML");
    let tasks = manifest
        .get("tasks")
        .and_then(toml::Value::as_table)
        .expect("the manifest declares tasks");
    let mut subsets = 0;
    for (name, task) in tasks {
        let runs: Vec<&str> = match task.get("run") {
            Some(toml::Value::String(run)) => vec![run.as_str()],
            Some(toml::Value::Array(runs)) => runs.iter().filter_map(toml::Value::as_str).collect(),
            _ => Vec::new(),
        };
        let filtered = runs
            .iter()
            .any(|run| run.contains("nextest run") && !run.contains("--workspace"));
        if !filtered {
            continue;
        }
        subsets += 1;
        let profile = task
            .get("env")
            .and_then(|env| env.get("NEXTEST_PROFILE"))
            .and_then(toml::Value::as_str)
            .unwrap_or("default");
        assert!(
            !matches!(profile, "default" | "ci"),
            "task `{name}` runs a filtered nextest under `{profile}`, the profile the full suite \
             reports into, so its report replaces the full one"
        );
        assert!(
            nextest
                .get("profile")
                .and_then(|profiles| profiles.get(profile))
                .is_some(),
            "task `{name}` selects nextest profile `{profile}`, which .config/nextest.toml does \
             not declare"
        );
    }
    assert!(
        subsets > 0,
        "the manifest runs no filtered nextest task, so this case asserts nothing"
    );
}

/// A repository whose last nextest run left `report` as its junit file.
fn run_left(name: &str, report: Option<&str>) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::init_repo(&dir);
    common::write(&dir, "batten.toml", "version = 1\n");
    if let Some(report) = report {
        common::write(&dir, "target/nextest/default/junit.xml", report);
    }
    dir
}

/// `batten record suites` in `dir`, reading the default profile's report.
fn record(dir: &Path) -> Output {
    common::batten()
        .args(["record", "suites"])
        .env("NEXTEST_PROFILE", "default")
        .current_dir(dir)
        .output()
        .expect("run batten record suites")
}

/// The verb reads a nextest report into one row per module, summed and ordered
/// by cost.
#[test]
fn record_suites_reads_a_nextest_report_per_module() {
    let dir = run_left(
        "junit-wired-reads",
        Some(concat!(
            "<testsuites>\n<testsuite name=\"pkg::it\" tests=\"3\">\n",
            "<testcase name=\"quick::a\" classname=\"pkg::it\" time=\"0.25\"/>\n",
            "<testcase name=\"slow::a\" classname=\"pkg::it\" time=\"3.0\"/>\n",
            "<testcase name=\"slow::b\" classname=\"pkg::it\" time=\"1.0\"/>\n",
            "</testsuite>\n</testsuites>\n",
        )),
    );
    let output = record(&dir);
    let said = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{said}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let slow = said
        .find("`pkg::it::slow`")
        .expect("the slow module has a row");
    let quick = said
        .find("`pkg::it::quick`")
        .expect("the quick module has a row");
    assert!(slow < quick, "ordered by cost, descending: {said}");
    assert!(
        said.contains("| 4.0 |"),
        "a module's cases are summed: {said}"
    );
}

/// A RETIRED LANE'S LAST REPORT IS NOT A LANE. The bats report outlives the bats
/// suites in `target/` indefinitely; measured on this repository, it shadowed
/// every nextest reading behind a "stale report" refusal. The lane is decided by
/// whether the tree still tracks a bats suite, never by a file existing.
#[test]
fn a_retired_bats_report_does_not_shadow_the_nextest_one() {
    let dir = run_left(
        "junit-wired-retired-bats",
        Some(concat!(
            "<testsuites>\n<testsuite name=\"pkg::it\" tests=\"1\">\n",
            "<testcase name=\"only::a\" classname=\"pkg::it\" time=\"2.0\"/>\n",
            "</testsuite>\n</testsuites>\n",
        )),
    );
    common::write(
        &dir,
        "target/bats-report/report.xml",
        "<testsuite name=\"tests/retired.bats\" time=\"9.0\">\n",
    );
    let output = record(&dir);
    let said = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{said}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(said.contains("`pkg::it::only`"), "{said}");
}

/// No report is could-not-look, never an empty table that reads as a fast suite.
#[test]
fn an_absent_nextest_report_is_could_not_look() {
    let dir = run_left("junit-wired-absent", None);
    let output = record(&dir);
    assert_ne!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no report at"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
