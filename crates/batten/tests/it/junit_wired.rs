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
    let path = junit_path(&config, "default");
    assert!(
        path.as_deref().is_some_and(|path| !path.is_empty()),
        ".config/nextest.toml declares no `[profile.default.junit] path`, so a run leaves no \
         per-case times behind"
    );
    // `ci` inherits `default`'s; a ci profile that set its own empty path would
    // silently switch the CI legs' report off.
    assert!(
        junit_path(&config, "ci").is_none_or(|path| !path.is_empty()),
        "the ci profile blanks the junit path it would otherwise inherit"
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
