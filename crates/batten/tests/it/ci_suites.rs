//! `batten ci suites` over the compiled binary — CLOUD-886/CLOUD-1716, ported
//! off `mise-tasks/suite-select.sh`.
//!
//! # THE ASYMMETRY IS WHAT EVERY CASE HERE IS ABOUT
//!
//! A selection that is too WIDE costs money and is obvious in the bill. One that
//! is too NARROW does not fail: the suites simply do not run, the count matches
//! whatever was selected, and a regression lands green. There is no symptom. So
//! the cases that carry the most weight are the ones asserting a wide answer,
//! and each names the path that forced it.
//!
//! # What the verb owes that the pure decision cannot show
//!
//! `suites::select` is pure and its own cases cover the deny-list, the whole-
//! field subject match and the empty changed set. They cannot show that the VERB
//! resolves a base, reads each suite's `# subject:` header off disk, widens on a
//! base that does not resolve, or keeps the reason off the channel a caller
//! parses. Those are properties of the compiled binary.
//
// carried: mise-tasks/suite-select.sh crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// carried: tests/suite-select.bats crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs
//
// carried: "A WIDE RUN SEES AN UNTRACKED SUITE, since the narrow path already does" crates/batten/tests/it/ci_suites.rs
// carried: "A DELETED SUITE IS NOT HANDED TO BATS as a path that does not exist" crates/batten/tests/it/ci_suites.rs
// carried: "THE PROBE: a change to one program selects that program's suite and no others" crates/batten/tests/it/ci_suites.rs
// carried: "a subject match is a whole field, not a substring" crates/batten/tests/it/ci_suites.rs
// carried: "a changed suite selects itself" crates/batten/tests/it/ci_suites.rs
// carried: "two changed programs select both suites, sorted" crates/batten/tests/it/ci_suites.rs
// carried: "a shared input runs everything" crates/batten/tests/it/ci_suites.rs
// carried: "the helpers file runs everything, because it is sourced widely" crates/batten/tests/it/ci_suites.rs
// carried: "a path outside the reasonable set runs everything" crates/batten/tests/it/ci_suites.rs
// carried: "a program no suite declares runs everything" crates/batten/tests/it/ci_suites.rs
// carried: "an unresolvable base runs everything rather than guessing" crates/batten/tests/it/ci_suites.rs
// carried: "every wide run says why, as a pointer" crates/batten/tests/it/ci_suites.rs
// changed: "the case count of a narrow selection is the selected suites' own" crates/batten/src/suites.rs the verb emits the SELECTED PATHS and nothing else; how many cases they hold is the runner's own count, and a selector that also reported it would be a second authority over a number bats already prints
//
// carried: "a deny-list, never an allow-list" crates/batten/src/suites.rs
// carried: "a shared input is one that can move a suite whose subject does not name it" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// carried: "the match is on a whole field rather than a substring" crates/batten/src/suites.rs
// carried: "a deleted suite has nothing to run" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// carried: "an empty changed set is not nothing to run" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// carried: "fail open toward cost: a selector that cannot answer falls back to every suite" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// carried: "a path under mise-tasks that no suite declares is could-not-look" crates/batten/src/suites.rs kind:verb crates/batten/tests/it/ci_suites.rs runs:mise+run+test:bats
// changed: "the reason goes to stderr as a pointer" crates/batten/src/suites.rs the reason is unchanged and still stderr-only, but it is now one sentence built by the engine rather than the program's own `wide()` echo, so the case asserts the channel split rather than the exact bytes

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{Fixture, batten, git_in};

use std::path::{Path, PathBuf};

/// A repository with two programs, two suites, and a declared subject each.
fn repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config("version = 1\n")
        .file("mise-tasks/alpha.sh", "#!/usr/bin/env bash\nexit 0\n")
        .file("mise-tasks/beta.sh", "#!/usr/bin/env bash\nexit 0\n")
        .file(
            "tests/alpha.bats",
            "# subject: mise-tasks/alpha.sh\n@test \"a\" { true; }\n",
        )
        .file(
            "tests/beta.bats",
            "# subject: mise-tasks/beta.sh\n@test \"b\" { true; }\n",
        )
        .git()
        .build();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    git_in(&dir, &["branch", "base"]);
    dir
}

/// Write a path and commit it, so the changed set has something in it.
fn change(dir: &Path, path: &str, body: &str) {
    if let Some(parent) = dir.join(path).parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(dir.join(path), body).unwrap();
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "work"]);
}

/// Run the verb and hand back `(code, stdout, stderr)`.
fn select(dir: &Path, base: &str) -> (Option<i32>, String, String) {
    let output = batten()
        .args(["ci", "suites", "--base", base])
        .current_dir(dir)
        .output()
        .expect("run batten ci suites");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The suite paths a run named.
fn named(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|line| line.starts_with("tests/"))
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn a_program_selects_only_the_suite_that_declares_it() {
    let dir = repo("suites-narrow");
    change(&dir, "mise-tasks/alpha.sh", "#!/usr/bin/env bash\nexit 1\n");
    let (code, stdout, _) = select(&dir, "base");
    assert_eq!(code, Some(0), "a selection was computed");
    assert_eq!(
        named(&stdout),
        vec!["tests/alpha.bats"],
        "beta's subject does not name the changed program"
    );
}

/// CARRIES: "`mise-tasks/land` must not select a suite whose subject is
/// `mise-tasks/land-lock`" — the match is a whole field, never a prefix.
#[test]
fn a_subject_is_matched_as_a_whole_field_never_a_prefix() {
    let dir = repo("suites-whole-field");
    std::fs::write(
        dir.join("mise-tasks/alpha-lock.sh"),
        "#!/usr/bin/env bash\nexit 0\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/alpha-lock.bats"),
        "# subject: mise-tasks/alpha-lock.sh\n@test \"c\" { true; }\n",
    )
    .unwrap();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "longer name"]);
    git_in(&dir, &["branch", "-f", "base"]);
    change(&dir, "mise-tasks/alpha.sh", "#!/usr/bin/env bash\nexit 1\n");
    let (_, stdout, _) = select(&dir, "base");
    assert_eq!(
        named(&stdout),
        vec!["tests/alpha.bats"],
        "the suite whose subject merely starts with this name is not selected"
    );
}

#[test]
fn a_shared_input_runs_every_suite_and_names_itself() {
    let dir = repo("suites-shared");
    change(&dir, "mise.toml", "[tasks.noop]\nrun = \"true\"\n");
    let (code, stdout, stderr) = select(&dir, "base");
    assert_eq!(code, Some(0), "widening is an answer, never a refusal");
    assert_eq!(named(&stdout).len(), 2, "every suite runs");
    assert!(
        stderr.contains("mise.toml is an input to suites"),
        "the widening names the path that forced it: {stderr}"
    );
}

#[test]
fn a_path_selection_cannot_reason_about_runs_every_suite() {
    let dir = repo("suites-outside");
    change(&dir, "src/main.rs", "fn main() {}\n");
    let (_, stdout, stderr) = select(&dir, "base");
    assert_eq!(named(&stdout).len(), 2, "every suite runs");
    assert!(
        stderr.contains("outside the set selection can reason about"),
        "the reason is stated: {stderr}"
    );
}

/// CARRIES: "a path under `mise-tasks/` that no suite declares as its subject is
/// a program nothing covers, or a header that has rotted. Either way this cannot
/// say which suites it moves, and could-not-look widens."
#[test]
fn a_program_no_suite_declares_runs_every_suite() {
    let dir = repo("suites-undeclared");
    change(&dir, "mise-tasks/gamma.sh", "#!/usr/bin/env bash\nexit 0\n");
    let (_, stdout, stderr) = select(&dir, "base");
    assert_eq!(named(&stdout).len(), 2, "every suite runs");
    assert!(
        stderr.contains("no suite declares mise-tasks/gamma.sh as its subject"),
        "the uncovered program is named: {stderr}"
    );
}

/// CARRIES: "a deleted suite has nothing to run" — the changed set reports a
/// removed path, and handing bats a file it cannot open is a failure rather than
/// coverage. Reachable in this very campaign, which retires suites.
#[test]
fn a_deleted_suite_is_not_handed_to_the_runner() {
    let dir = repo("suites-deleted");
    std::fs::remove_file(dir.join("tests/beta.bats")).unwrap();
    std::fs::remove_file(dir.join("mise-tasks/beta.sh")).unwrap();
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "retire beta"]);
    let (_, stdout, _) = select(&dir, "base");
    let said = named(&stdout);
    assert!(
        !said.iter().any(|suite| suite == "tests/beta.bats"),
        "the deleted suite is never named: {said:?}"
    );
}

/// CARRIES: "an empty changed set is not 'nothing to run': it is a question this
/// could not answer, because a caller running the task by hand on a clean tree
/// still wants the suite."
#[test]
fn a_clean_tree_runs_every_suite_rather_than_none() {
    let dir = repo("suites-clean");
    let (code, stdout, _) = select(&dir, "HEAD");
    assert_eq!(code, Some(0));
    assert_eq!(
        named(&stdout).len(),
        2,
        "a clean tree is could-not-look, and could-not-look widens"
    );
}

/// CARRIES: "fail open toward cost: a selector that cannot answer at all falls
/// back to every suite." An unresolvable base is the plainest instance, and it
/// is the one direction a refusal would be worst in — a wedged selector would
/// otherwise run nothing at all.
#[test]
fn an_unresolvable_base_runs_every_suite() {
    let dir = repo("suites-no-base");
    let (code, stdout, stderr) = select(&dir, "refs/heads/nothing");
    assert_eq!(code, Some(0), "this widens rather than refusing");
    assert_eq!(named(&stdout).len(), 2);
    assert!(
        stderr.contains("to compare against"),
        "the unresolvable base is named: {stderr}"
    );
}

/// The reason is a pointer on stderr and never reaches the channel a caller
/// parses — the retired program's own split, and the reason `test:bats` can pipe
/// stdout straight into the runner.
#[test]
fn the_reason_stays_off_the_channel_a_caller_parses() {
    let dir = repo("suites-channels");
    change(&dir, "mise.toml", "[tasks.noop]\nrun = \"true\"\n");
    let (_, stdout, stderr) = select(&dir, "base");
    assert!(
        stdout
            .lines()
            .filter(|line| !line.is_empty())
            .all(|line| line.starts_with("tests/")),
        "stdout carries suite paths and nothing else: {stdout}"
    );
    assert!(
        !stdout.contains("running every suite"),
        "the widening reason never reaches stdout"
    );
    assert!(
        stderr.contains("running every suite"),
        "it is on stderr instead: {stderr}"
    );
}

/// The retired program is gone, and the caller that resolved it by path now
/// names the successor instead.
#[test]
fn the_retired_program_is_not_tracked_and_its_caller_moved() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    for path in ["mise-tasks/suite-select.sh", "tests/suite-select.bats"] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    assert!(
        !tasks.contains("suite-select.sh"),
        "no caller resolves the retired program by path"
    );
    assert!(
        tasks.contains("ci suites"),
        "the successor is what `test:bats` selects with"
    );
}
