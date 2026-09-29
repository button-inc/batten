//! `lint:rego` and `fmt:rego` (CLOUD-930), ported from `tests/lint-rego.bats`
//! under CLOUD-843.
//!
//! `.rego` was the one config format with no formatter, and the campaign CLOUD-843
//! owns migrates its gates onto it — so this gate's value scales with the
//! campaign. What is pinned is not "opa fmt works". It is the properties that
//! were WRONG on the first attempt and would fail silently if they regressed:
//!
//!   1. the file list is git's index, and never a command substitution over
//!      `git ls-files -z` — bash strips the NUL bytes `-z` emits, so every path
//!      arrives as one argument and the gate presents a "no such file" red rather
//!      than a gate that selected nothing;
//!   2. the check lists every unformatted file rather than short-circuiting on
//!      the first, which `--fail` alone does;
//!   3. a deliberately broken fixture outside the index is never judged — a gate
//!      that fails on its own test data is a gate someone switches off.
//!
//! # Read as commands, whichever way the task is spelled
//!
//! CLOUD-1991 moves both tasks off their shell bodies onto `batten exec
//! --tracked`, which selects git's index by construction. The selection
//! predicate below admits that spelling beside the piped one, and refuses the
//! substitution shape either way.
//!
//! # opa, where installed
//!
//! The two behavioural cases run the pinned `opa` through `mise which opa`, the
//! way the retired suite ran it through `mise run`. A host without it has learned
//! nothing about the corpus and returns rather than failing.

// CLOUD-1268's fifth arm: `mise.toml` does not die, so every `ported` arm names
// it. Three cases are `changed`, each for the reason on its row.
//
// ported: tests/lint-rego.bats subject:mise.toml crates/batten/tests/it/lint_rego.rs
// ported: "lint-rego.bats::both task bodies were found at all — this suite is not passing vacuously" crates/batten/tests/it/lint_rego.rs subject:mise.toml
// changed: "lint-rego.bats::THE FIXTURE HAZARD: an unparseable .rego outside git's index is never judged" crates/batten/tests/it/lint_rego.rs the broken fixture is written where the suite wrote it and shown absent from git's index and unjudged by the pinned `opa` over that index, and both tasks are shown to select that index — rather than by running `mise run lint:rego`, which since CLOUD-1991 builds the engine inside a test
// changed: "lint-rego.bats::the selection is git's index, piped — never a command substitution over -z" crates/batten/tests/it/lint_rego.rs `batten exec --tracked` is admitted as a spelling of the index beside the `xargs -0` pipe, and the refused shape is narrowed to what strips the NULs — a substitution that closes over `git ls-files` itself — because a substitution wrapping the WHOLE pipe keeps the NULs inside it and was refused by the suite's pattern while being correct
// ported: "lint-rego.bats::the check reports every unformatted file, so it does not pass --fail" crates/batten/tests/it/lint_rego.rs subject:mise.toml
// ported: "lint-rego.bats::the fixer writes in place and the checker never does" crates/batten/tests/it/lint_rego.rs subject:mise.toml
// changed: "lint-rego.bats::a clean corpus passes, and says so rather than passing silently" crates/batten/tests/it/lint_rego.rs the corpus is judged by the pinned `opa fmt -l` over git's index directly, with an empty listing as the pass; the task's own success line is not asserted, because an argv task prints none

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

/// The commands of `lint:rego` (the checker) and `fmt:rego` (the fixer).
fn check_and_fix() -> (Vec<String>, Vec<String>) {
    (
        common::task_commands("lint:rego"),
        common::task_commands("fmt:rego"),
    )
}

/// The commands in `commands` that RUN `opa fmt` — the verb followed by a flag.
///
/// Anchored on the flag because a shell body's error message names the tool in
/// prose (`… would change under opa fmt. Run …`), and holding a sentence to the
/// selection predicate would fail the case on its own documentation.
fn formatting(commands: &[String]) -> Vec<&String> {
    let runs = regex::Regex::new(r"\bopa fmt\s+-[A-Za-z]").expect("a valid expression");
    commands
        .iter()
        .filter(|command| runs.is_match(command))
        .collect()
}

/// Whether `command` selects git's index: the `-z` listing piped into `xargs
/// -0`, or the engine's own tracked-set selector.
fn selects_the_index(command: &str) -> bool {
    let piped = command.contains("git ls-files -z '*.rego'") && command.contains("| xargs -0 -r");
    let tracked = command.contains("--tracked '*.rego'");
    piped || tracked
}

/// The tracked `.rego` corpus, as git's index lists it.
fn tracked_modules() -> Vec<String> {
    let root = common::at_root(".");
    common::git_in(&root, &["ls-files", "--", "*.rego"])
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The `opa` this clone pins, or `None` where it is not installed.
fn opa_binary() -> Option<PathBuf> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: resolving the pinned tool is what the retired `tests/lint-rego.bats` did through `mise run`, and the formatter is opa's"
    )]
    let output = std::process::Command::new("mise")
        .args(["which", "opa"])
        .current_dir(common::at_root("."))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    path.is_file().then_some(path)
}

/// `opa fmt -l` over git's index at the repository root: its status and listing.
fn list_unformatted(opa: &Path) -> (bool, String) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — CLOUD-843: the subject is the formatter's verdict over the tracked corpus, which only opa can give; the retired suite made the same spawn through `mise run lint:rego`"
    )]
    let output = std::process::Command::new(opa)
        .args(["fmt", "-l"])
        .args(tracked_modules())
        .current_dir(common::at_root("."))
        .output()
        .expect("opa runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn both_task_bodies_were_found_at_all() {
    let (check, fix) = check_and_fix();
    assert!(!formatting(&check).is_empty(), "lint:rego runs no opa fmt");
    assert!(!formatting(&fix).is_empty(), "fmt:rego runs no opa fmt");
}

#[test]
fn the_fixture_hazard_an_unparseable_rego_outside_the_index_is_never_judged() {
    // `lint:toml`'s reason, on this format: the suites write deliberately broken
    // fixtures under `target/`. Unparseable rather than merely misformatted,
    // because that is the case a tree walk could not survive quietly.
    let (check, fix) = check_and_fix();
    for command in formatting(&check).into_iter().chain(formatting(&fix)) {
        assert!(
            selects_the_index(command),
            "a formatter step that does not select git's index: {command}"
        );
    }
    let fixture = common::at_root(&format!(
        "target/tmp/lint-rego-fixture-{}",
        std::process::id()
    ));
    fs::create_dir_all(&fixture).expect("create the fixture directory");
    fs::write(fixture.join("broken.rego"), "this is not = = rego\n").expect("write the fixture");
    let listed = tracked_modules();
    let judged = opa_binary().map(|opa| list_unformatted(&opa));
    let _ = fs::remove_dir_all(&fixture);
    assert!(
        !listed.iter().any(|path| path.ends_with("broken.rego")),
        "git's index lists the untracked fixture: {listed:?}"
    );
    if let Some((clean, listing)) = judged {
        assert!(clean, "opa failed over the tracked corpus: {listing}");
        assert!(!listing.contains("broken.rego"), "the fixture was judged");
    }
}

#[test]
fn the_selection_is_the_index_never_a_substitution_over_the_listing() {
    // The NUL-stripping bug is a substitution that CLOSES over `git ls-files`, so
    // its output — NULs and all — becomes a shell word. Asserted over both tasks,
    // since the fixer selecting a wider set than the checker would repair a
    // fixture the suite wrote to be broken.
    let stripped = regex::Regex::new(r"\$\(\s*git ls-files[^|)]*\)").expect("a valid expression");
    let (check, fix) = check_and_fix();
    for command in formatting(&check).into_iter().chain(formatting(&fix)) {
        assert!(selects_the_index(command), "not the index: {command}");
        assert!(
            !stripped.is_match(command),
            "a substitution over the -z listing: {command}"
        );
    }
}

#[test]
fn the_check_reports_every_unformatted_file_so_it_does_not_only_pass_fail() {
    // `--fail` short-circuits on the first differing file, so a corpus with two
    // unformatted modules reported one. A listing without it must run.
    let (check, _) = check_and_fix();
    assert!(
        check
            .iter()
            .any(|command| command.contains("opa fmt -l") && !command.contains("--fail")),
        "lint:rego never lists the unformatted files: {check:?}"
    );
}

#[test]
fn the_fixer_writes_in_place_and_the_checker_never_does() {
    let (check, fix) = check_and_fix();
    assert!(
        fix.iter().any(|command| command.contains("opa fmt -w")),
        "fmt:rego does not write: {fix:?}"
    );
    for command in &check {
        assert!(!command.contains("-w"), "the checker writes: {command}");
    }
}

#[test]
fn a_clean_corpus_passes() {
    let Some(opa) = opa_binary() else { return };
    let (clean, listing) = list_unformatted(&opa);
    assert!(clean, "opa failed over the tracked corpus: {listing}");
    assert!(
        listing.trim().is_empty(),
        "tracked modules opa would reformat:\n{listing}"
    );
}
