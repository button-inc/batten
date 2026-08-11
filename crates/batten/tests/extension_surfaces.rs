//! The README's extension-surfaces section, executed (CLOUD-88).
//!
//! "Rules ship with their mechanism" applies to documentation too. A worked
//! example is a claim about what the binary does, and prose is feedforward only —
//! so every example in the README's *Extending Batten* section is run here against
//! the compiled binary and asserted to produce the exit code it advertises.
//!
//! Two directions, and both matter:
//!
//! * **The binary still does what the doc says.** A behaviour change that
//!   invalidates an example fails here rather than being discovered by whoever
//!   trusted the example.
//! * **The doc still says what is being tested.** Each case also asserts its own
//!   config and command text appears in the README, so deleting a documented
//!   surface cannot leave a passing test behind — the failure mode where coverage
//!   outlives the thing it covered.
//!
//! Kept out of `tests/cli.rs` deliberately: that file is the exit-code and
//! output-contract suite, and this one's subject is the README.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::PathBuf;

use common::{Fixture, at_root, batten, scratch};

/// The README section these examples are drawn from.
const SECTION: &str = "## Extending Batten: three surfaces, and which to reach for";

fn readme() -> String {
    fs::read_to_string(at_root("README.md")).expect("read README.md")
}

/// The README's table row containing `needle`, with its column padding collapsed.
///
/// Prettier owns the alignment of a Markdown table, and it re-pads on every run —
/// so an assertion on the exact line breaks whenever a neighbouring row changes
/// width, for a reason that has nothing to do with the contract. The CODES are the
/// contract; the spaces between them are not.
fn table_row(needle: &str) -> String {
    readme()
        .lines()
        .find(|line| line.starts_with('|') && line.contains(needle))
        .map_or_else(
            || panic!("no README table row contains {needle:?}"),
            |line| line.split_whitespace().collect::<Vec<_>>().join(" "),
        )
}

/// The README with every run of whitespace collapsed to one space.
///
/// Prose in this file is hard-wrapped, so a phrase a reader sees as one sentence
/// is split by a newline in the bytes. Asserting on the raw text made a correct
/// doc fail — measured, on "passes its code through untouched". Table rows are
/// still matched against the raw text, where the exact line IS the contract.
fn readme_prose() -> String {
    readme().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A fixture repo with `config` as its committed authority and one Rust file that
/// trips a `TODO` rule, plus an isolated state dir for `exec`'s capture store.
fn repo_with(name: &str, config: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(config)
        .file("lib.rs", "fine\nTODO fix this\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

fn run(repo: &std::path::Path, home: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let output = batten()
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn the_section_exists_so_the_cases_below_are_not_vacuous() {
    // Without this, deleting the whole section would leave every test here
    // passing — coverage outliving the thing it covers.
    assert!(
        readme().contains(SECTION),
        "the README no longer carries the extension-surfaces section this suite documents"
    );
}

#[test]
fn the_decision_table_names_all_three_surfaces_and_where_each_is_configured() {
    // The table is the point of the doc: the failure mode is a consumer reaching
    // for the wrong surface, not misusing the one they picked.
    let readme = readme();
    for surface in ["`command` rule", "`[[exec_pattern]]`", "`fail_on_warning`"] {
        assert!(readme.contains(surface), "the table must name {surface}");
    }
    let prose = readme_prose();
    for boundary in ["Don't reach for this", "raise-only"] {
        assert!(prose.contains(boundary), "the doc must carry {boundary:?}");
    }
}

#[test]
fn the_command_rule_example_is_refused_by_check_and_run_by_enforce() {
    // The documented claim: a `command` rule runs under `enforce` only, and
    // `check` refuses it with a usage error rather than running it — which is what
    // keeps `check`'s read-only effect honest.
    let config = "version = 1\n\n[[rule]]\nid = \"single-entrypoint\"\nkind = \"command\"\n\
                  glob = \"**/*.rs\"\ncheck = \"true\"\nseverity = \"deny\"\n";
    let (repo, home) = repo_with("ext-command-rule", config);

    let (code, _, stderr) = run(&repo, &home, &["check"]);
    assert_eq!(code, 1, "check refuses a process-spawning rule: {stderr}");
    assert_ne!(code, 2, "a refusal to run is not a policy verdict");

    let (code, _, _) = run(&repo, &home, &["enforce"]);
    assert_eq!(code, 0, "enforce runs it, and `true` passes");

    let readme = readme();
    assert!(readme.contains("kind = \"command\""));
    assert!(
        readme_prose().contains("`batten check` **refuses** it"),
        "the doc must state the refusal the test just asserted"
    );
}

#[test]
fn a_failing_command_rule_is_a_policy_verdict() {
    let config = "version = 1\n\n[[rule]]\nid = \"single-entrypoint\"\nkind = \"command\"\n\
                  glob = \"**/*.rs\"\ncheck = \"false\"\nseverity = \"deny\"\n";
    let (repo, home) = repo_with("ext-command-fails", config);
    let (code, _, _) = run(&repo, &home, &["enforce"]);
    assert_eq!(
        code, 2,
        "a non-zero exit from the configured command is a violation"
    );
}

#[cfg(unix)]
#[test]
fn the_exec_predicate_example_promotes_a_lying_exit_zero() {
    // The README's own pattern, verbatim.
    let config = "version = 1\n\n[[exec_pattern]]\nid = \"no-unfailed-duplicate\"\n\
                  pattern = \"warning[duplicate]\"\nstream = \"both\"\n\
                  reason = \"set the tool's own severity to deny; do not let a warning ride an exit 0\"\n";
    let (repo, home) = repo_with("ext-exec-pred", config);

    let (code, _, stderr) = run(
        &repo,
        &home,
        &["exec", "--", "sh", "-c", "echo 'warning[duplicate] serde'"],
    );
    assert_eq!(code, 1, "the documented exit code for an output match");
    assert!(stderr.contains("no-unfailed-duplicate"), "got {stderr}");
    assert!(stderr.contains("output match(es)"), "got {stderr}");
    // Pointer-only, as the doc's sample output shows.
    assert!(
        !stderr.contains("warning[duplicate] serde"),
        "the sample output is a pointer, so the real one must be too"
    );

    let readme = readme();
    assert!(readme.contains("no-unfailed-duplicate"));
    assert!(
        readme_prose().contains("A match **always fails**"),
        "the doc must state the unconditional-failure rule"
    );
}

#[cfg(unix)]
#[test]
fn batten_only_adds_failure_as_the_doc_claims() {
    let config = "version = 1\n\n[[exec_pattern]]\nid = \"lying\"\npattern = \"warning\"\n\
                  stream = \"both\"\nreason = \"fix the tool\"\n";
    let (repo, home) = repo_with("ext-exec-adds", config);
    let (code, _, _) = run(
        &repo,
        &home,
        &["exec", "--", "sh", "-c", "echo warning; exit 7"],
    );
    assert_eq!(code, 7, "a child that already failed keeps its own code");
    assert!(
        readme_prose().contains("passes its code through untouched"),
        "the doc must state the only-adds-failure rule"
    );
}

#[test]
fn the_two_promotion_paths_produce_exactly_the_codes_the_table_claims() {
    // The row the Ready block got wrong: it said a promoted checks-pipeline warn
    // exits 1. It exits 2 — the policy verdict, on every surface that renders one.
    // Measured here rather than restated, which is the whole reason this suite
    // exists.
    let warn_rule = "\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
                     pattern = \"TODO\"\nseverity = \"warn\"\n";

    let (unpromoted, home) = repo_with("ext-warn-off", &format!("version = 1\n{warn_rule}"));
    let (code, stdout, _) = run(&unpromoted, &home, &["check"]);
    assert_eq!(code, 0, "a warn finding reports without failing");
    assert!(stdout.contains("no-todo"), "and still reports: {stdout}");

    let (promoted, home) = repo_with(
        "ext-warn-on",
        &format!("version = 1\nfail_on_warning = true\n{warn_rule}"),
    );
    let (code, _, _) = run(&promoted, &home, &["check"]);
    assert_eq!(code, 2, "a promoted warn is a policy verdict, which is 2");

    // And the doc's table must carry those codes rather than any others.
    assert_eq!(
        table_row("a `warn` finding"),
        "| a `warn` finding from `check`/`enforce` | exit `0` | exit `2` |",
        "the promotion table must state exit 0 → exit 2 for the checks pipeline"
    );
    assert_eq!(
        table_row("an `exec` output match"),
        "| an `exec` output match | — | exit `1` |",
        "the promotion table must state exit 1 for an exec match"
    );
}

#[test]
fn the_doc_records_the_asymmetry_as_a_rough_edge_rather_than_a_design() {
    // The honest half. Two things both called policy violations use different
    // codes, and §7 says 2 is *the* policy verdict with no per-verb exception. The
    // doc must not present that as settled, because it is not.
    assert!(
        readme_prose().contains("known rough edge"),
        "the doc must name the exit-code asymmetry as a rough edge, not a decision"
    );
}
