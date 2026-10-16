//! The release gate's `--on` table maps the verb's own not-green exit
//! (CLOUD-2392).
//!
//! `release settings --last-run` answers not-green with `Violation`, which is 2.
//! Both callers wrapped it in `ci step --on 0=true --on 1=false`, copied from a
//! doc comment that said 1, so the answer was unmapped: `ci step` failed the job
//! instead of writing `green=false`, and the `if:` written to skip the release PR
//! never ran. Every `release-plz` run on `main` went red on a guard that was
//! working as designed, and the engine-pin steps after it never ran.
//!
//! Exit 3 stays unmapped on purpose: could-not-look must still fail the job.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// The two workflows that gate on the release guard's last `settings` run.
const CALLERS: [&str; 2] = [
    ".github/workflows/release-plz.yml",
    ".github/workflows/auto-release-land.yml",
];

/// Every `--on` pair on the `ci step` lines that wrap `release settings --last-run`.
fn tables(path: &str) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(common::at_root(path)).expect("the workflow is readable");
    text.lines()
        .filter(|line| line.contains("ci step") && line.contains("release settings --last-run"))
        .map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            words
                .windows(2)
                .filter(|pair| pair[0] == "--on")
                .map(|pair| pair[1].to_owned())
                .collect()
        })
        .collect()
}

#[test]
fn the_release_settings_gate_maps_its_violation_exit() {
    for path in CALLERS {
        let found = tables(path);
        assert!(
            !found.is_empty(),
            "{path} no longer wraps `release settings --last-run` in `ci step`; this case reads nothing"
        );
        for table in found {
            assert!(
                table.iter().any(|pair| pair == "2=false"),
                "{path}: not-green is exit 2 (`Violation`) and must map to `green=false`: {table:?}"
            );
            assert!(
                !table.iter().any(|pair| pair.starts_with("1=")),
                "{path}: exit 1 is `Usage`, a malformed call, and must fail the job: {table:?}"
            );
            assert!(
                !table.iter().any(|pair| pair.starts_with("3=")),
                "{path}: exit 3 is could-not-look and must fail the job: {table:?}"
            );
        }
    }
}
