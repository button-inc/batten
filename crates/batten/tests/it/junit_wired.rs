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

#[test]
fn the_default_profile_writes_a_junit_report() {
    let text = std::fs::read_to_string(common::at_root(".config/nextest.toml"))
        .expect("read the committed nextest config");
    let config: toml::Table = text.parse().expect("the nextest config is TOML");
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
    // `ci` inherits `default`'s; a ci profile that set its own path to anything
    // else would silently move the CI legs' report out from under the reader.
    assert!(
        junit_path(&config, "ci").is_none_or(|path| path == reader),
        "the ci profile overrides the junit path the reader expects"
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

fn record(dir: &Path) -> Output {
    common::batten()
        .args(["record", "suites"])
        .env("NEXTEST_PROFILE", "default")
        .current_dir(dir)
        .output()
        .expect("run batten record suites")
}

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
