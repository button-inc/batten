//! Every `ci step --on` table over a `batten release` verb maps the verb's own
//! refusal (CLOUD-2392).
//!
//! The release verbs answer a refusal with `Violation`, which is exit 2.
//! `release settings --last-run`, `release in-flight` and `release verify` were
//! each wrapped in `ci step --on 0=… --on 1=…`, copied from doc comments that
//! said 1, so the refusal was unmapped: `ci step` failed the job instead of
//! writing the captured answer. The `if:` written to skip the release PR, hold
//! the ready, or discard a refused draft never ran.
//!
//! Exit 1 is `Usage`, a malformed call, and exit 3 is could-not-look: both must
//! stay unmapped so they still fail the job.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// Every `(workflow, verb, --on pairs)` for a `ci step` wrapping `batten release`.
fn tables() -> Vec<(String, String, Vec<String>)> {
    let dir = common::at_root(".github/workflows");
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the workflows directory is readable") {
        let path = entry.expect("a workflow entry is readable").path();
        let text = std::fs::read_to_string(&path).expect("the workflow is readable");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        for line in text.lines().filter(|line| line.contains("ci step")) {
            let words: Vec<&str> = line.split_whitespace().collect();
            // `batten -- release <verb>` through mise, or `batten release <verb>`.
            let Some(at) = words.iter().enumerate().position(|(i, word)| {
                *word == "release"
                    && (words.get(i.wrapping_sub(1)) == Some(&"batten")
                        || (words.get(i.wrapping_sub(1)) == Some(&"--")
                            && words.get(i.wrapping_sub(2)) == Some(&"batten")))
            }) else {
                continue;
            };
            let verb = words.get(at + 1).copied().unwrap_or_default().to_owned();
            let pairs = words
                .windows(2)
                .filter(|pair| pair[0] == "--on")
                .map(|pair| pair[1].to_owned())
                .collect::<Vec<_>>();
            if !pairs.is_empty() {
                found.push((name.clone(), verb, pairs));
            }
        }
    }
    found
}

#[test]
fn the_release_settings_gate_maps_its_violation_exit() {
    let found = tables();
    for verb in ["settings", "in-flight", "verify"] {
        assert!(
            found.iter().any(|(_, seen, _)| seen == verb),
            "no workflow wraps `release {verb}` in `ci step --on` any more; this case reads nothing for it"
        );
    }
    for (workflow, verb, table) in found {
        assert!(
            table.iter().any(|pair| pair.starts_with("2=")),
            "{workflow}: `release {verb}` refuses with exit 2 (`Violation`), which must be mapped: {table:?}"
        );
        assert!(
            !table.iter().any(|pair| pair.starts_with("1=")),
            "{workflow}: `release {verb}` exit 1 is `Usage`, a malformed call, and must fail the job: {table:?}"
        );
        assert!(
            !table.iter().any(|pair| pair.starts_with("3=")),
            "{workflow}: `release {verb}` exit 3 is could-not-look and must fail the job: {table:?}"
        );
    }
}
