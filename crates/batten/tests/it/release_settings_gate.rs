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

/// Every committed workflow as `(file name, text)`.
fn workflows() -> Vec<(String, String)> {
    let dir = common::at_root(".github/workflows");
    std::fs::read_dir(&dir)
        .expect("the workflows directory is readable")
        .map(|entry| {
            let path = entry.expect("a workflow entry is readable").path();
            let text = std::fs::read_to_string(&path).expect("the workflow is readable");
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, text)
        })
        .collect()
}

/// Every `(workflow, verb, --on pairs)` for a `ci step` wrapping `batten release`.
fn tables() -> Vec<(String, String, Vec<String>)> {
    let mut found = Vec::new();
    for (name, text) in workflows() {
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

/// `release-land` moves the draft onto its bake BEFORE it verifies it
/// (CLOUD-2574).
///
/// `release verify --draft` reads `install.lock` at the draft's target. The cut
/// created the draft at the pre-bake head, which carries the previous cut's
/// lock, so every v0.0.217 draft was refused and discarded and re-cut six
/// times. A `gh release edit --target` carrying the bake must come first.
#[test]
fn the_draft_is_moved_onto_its_bake_before_it_is_verified() {
    let (_, text) = workflows()
        .into_iter()
        .find(|(name, _)| name == "release-land.yml")
        .expect("release-land.yml is committed");
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    let verify = lines
        .iter()
        .position(|line| line.contains("release verify --draft"))
        .expect("release-land verifies the draft");
    let moved = lines
        .iter()
        .position(|line| line.contains("--arg-env TARGET -- gh release edit"))
        .expect("release-land moves the release onto its bake with `gh release edit`");
    assert!(
        moved < verify,
        "release-land.yml verifies the draft at its cut, before it is moved onto the bake that carries its install.lock"
    );
}

/// No workflow finds a pull request through the SEARCH INDEX (CLOUD-2566).
///
/// `gh pr list --search` reads GitHub's search index, which lags a PR's
/// creation by seconds. release-plz opened #1245 at 02:19:35 and its own pin
/// step searched for it at 02:19:39, read nothing, and skipped the pin move, so
/// the release PR refused its own config on every leg. The pull-request list
/// without `--search` is read from the repository and is consistent on creation.
#[test]
fn no_workflow_finds_a_pull_request_through_the_search_index() {
    let mut release_branch_lookups = 0;
    for (name, text) in workflows() {
        for line in text
            .lines()
            .filter(|line| line.contains("gh pr list") && !line.trim_start().starts_with('#'))
        {
            assert!(
                !line.contains("--search"),
                "{name}: `gh pr list --search` reads the search index, which misses a PR opened seconds ago"
            );
            if name == "release-plz.yml" && line.contains("release-plz-") {
                release_branch_lookups += 1;
            }
        }
    }
    assert_eq!(
        release_branch_lookups, 1,
        "release-plz.yml names the release PR's branch with one `gh pr list`; this case reads nothing without it"
    );
}
