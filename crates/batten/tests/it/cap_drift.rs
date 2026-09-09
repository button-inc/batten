//! A cap and its bot-side withholding rule exist together or not at all, over
//! the compiled binary (CLOUD-593, ported from `mise-tasks/cap-drift.sh` under
//! CLOUD-843).
//!
//! **What is decidable only here.** `policy/cap-drift.rego` carries load-time
//! cases pinning the predicate, and every one hands the module a ready-made map
//! of both files with `with input as`. That fabricates the very shape the engine
//! may be unable to produce (CLOUD-845), and here it fabricates the pairing
//! itself: this rule is set equality ACROSS two `line_sources` paths resolved in
//! one evaluation, and a module whose suite only fabricated the map would stay
//! green over an engine that resolved one of them. Resolving only the manifest
//! empties the withheld set and reports every cap as unmirrored; resolving only
//! the bot config empties the capped set and reports the half-lift everywhere.
//! Both are loud. What is silent, and what this tier is for, is the arm each
//! guard makes conditional: with a file absent the rule is not evaluated at all,
//! and the pairing goes unchecked with nothing red.
//!
//! The self-consumption case is the one the retiring suite ended on: the real
//! tree's two sets agree, checked rather than asserted.
//
// carried: mise-tasks/cap-drift.sh policy/cap-drift.rego crates/batten/tests/it/cap_drift.rs
// carried: tests/cap-drift.bats policy/cap-drift.rego crates/batten/tests/it/cap_drift.rs
//
// carried: "both sets empty passes — the state CLOUD-593 leaves, and the ratchet still runs" policy/cap-drift.rego
// carried: "a cap mirrored by an allowedVersions rule passes" policy/cap-drift.rego
// carried: "THE HALF-LIFT: an allowedVersions rule with no cap is refused, and named" policy/cap-drift.rego
// carried: "a cap with no allowedVersions rule is refused, and named" policy/cap-drift.rego
// carried: "both directions are reported in one pass, not one per run" policy/cap-drift.rego
// carried: "a caret requirement is not a cap — it bounds the major, not the compiler" policy/cap-drift.rego
// carried: "a bare-string upper bound is a cap too, not only the inline-table form" policy/cap-drift.rego
// carried: "a less-than outside the workspace dependencies table mints no phantom cap" policy/cap-drift.rego
// carried: "a matchPackageNames used for grouping is not read as a cap mirror" policy/cap-drift.rego
// carried: "an allowedVersions named only in a comment mirrors nothing" policy/cap-drift.rego
// carried: "a rule written inline reads the same as one spread over lines" policy/cap-drift.rego
// carried: "the real tree agrees" policy/cap-drift.rego
// changed: "an unreadable file is exit 2 — never a silent agreement" policy/cap-drift.rego the shell opened two named files and refused one it could not read; the successor declares them as `line_sources` and the ENGINE decides this earlier — a rule whose declared paths match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). What the case protected is kept in the shape the engine does allow: each direction guards on the OTHER file having resolved, so a present-but-empty file still reports the pairing rather than reading as agreement

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn cap_repo(name: &str, manifest: &str, bot: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[pattern]]\n\
             id = \"md-quoted-span\"\n\
             regex = '\"[^\"]*\"'\n\n\
             [[verdict]]\n\
             id = \"bound carry missing\"\n\
             gloss = \"an upper bound exists in one of its two files and not the other\"\n\
             class = \"A rule with no cap withholds a version the manifest admits, and nothing goes red.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"cap-drift\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"Cargo.toml\", \"renovate.json5\"]\n\
             module = \"policy/cap-drift.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("Cargo.toml", manifest)
        .file("renovate.json5", bot)
        .git()
        .build();
    common::write(
        &dir,
        "policy/cap-drift.rego",
        &std::fs::read_to_string(common::at_root("policy/cap-drift.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "cap-drift"])
}

fn deps(entries: &[&str]) -> String {
    let mut manifest = String::from("[workspace.dependencies]\n");
    for entry in entries {
        writeln!(manifest, "{entry}").unwrap();
    }
    manifest.push_str("\n[workspace.lints]\nrust = {}\n");
    manifest
}

fn bot(rules: &[&str]) -> String {
    let mut config = String::from(
        "{\n  \"$schema\": \"https://docs.renovatebot.com/renovate-schema.json\",\n  packageRules: [\n",
    );
    for rule in rules {
        writeln!(config, "{rule}").unwrap();
    }
    config.push_str("  ],\n}\n");
    config
}

const MIRRORED: &str = "    { matchPackageNames: [\"ignore\"], allowedVersions: \"<0.4.30\" },";

#[test]
fn both_sets_empty_passes_and_the_ratchet_still_runs() {
    // The state CLOUD-593 leaves them in. A gate that only functioned while a
    // list was non-empty would have been deleted with the list.
    let dir = cap_repo("cap-empty", &deps(&["serde = \"1\""]), &bot(&[]));
    let output = check(&dir);
    assert_eq!(
        output.status.code(),
        Some(0),
        "out={} err={}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_mirrored_cap_passes() {
    let dir = cap_repo(
        "cap-mirrored",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&[MIRRORED]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn the_half_lift_is_refused() {
    // The manifest side lifted, the bot side left withholding: the crate
    // silently never advances and nothing anywhere is red. This is the direction
    // with no symptom, and the reason the gate exists.
    let dir = cap_repo(
        "cap-half-lift",
        &deps(&["ignore = \"0.4\""]),
        &bot(&[MIRRORED]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("ignore"),
        "the finding names the crate: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_cap_with_no_withholding_rule_is_refused() {
    let dir = cap_repo(
        "cap-unmirrored",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&[]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn both_directions_are_reported_in_one_pass() {
    let dir = cap_repo(
        "cap-both-directions",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&["    { matchPackageNames: [\"globset\"], allowedVersions: \"<0.4.20\" },"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("ignore") && text.contains("globset"),
        "one run reports both directions: {text:?}"
    );
}

#[test]
fn a_caret_requirement_is_not_a_cap() {
    // It bounds the MAJOR. Treating it as a cap would demand a withholding rule
    // for every dependency in the file, and the gate would be switched off
    // within a day.
    let dir = cap_repo("cap-caret", &deps(&["serde = \"1.0\""]), &bot(&[]));
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_bare_string_upper_bound_is_a_cap_too() {
    let dir = cap_repo(
        "cap-bare-string",
        &deps(&["ignore = \"<0.4.30\""]),
        &bot(&[]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_less_than_outside_the_table_mints_no_phantom_cap() {
    let dir = cap_repo(
        "cap-outside-table",
        "[workspace.dependencies]\nserde = \"1.0\"\n\n[workspace.metadata]\nnote = \"was <2 once\"\n",
        &bot(&[]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_grouping_matcher_is_not_a_cap_mirror() {
    // A matcher used for grouping withholds nothing, so reading it as a mirror
    // would let the half-lift through under a rule that never held anything
    // back.
    let dir = cap_repo(
        "cap-grouping-matcher",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&["    { matchPackageNames: [\"ignore\"], groupName: \"rust\" },"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_commented_rule_mirrors_nothing() {
    // A gate a comment can satisfy is a gate satisfied by deleting the key the
    // comment explains.
    let dir = cap_repo(
        "cap-commented-rule",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&["    // { matchPackageNames: [\"ignore\"], allowedVersions: \"<0.4.30\" },"]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_multiline_rule_reads_the_same_as_an_inline_one() {
    // A formatter's choice must not change a verdict.
    let dir = cap_repo(
        "cap-multiline-rule",
        &deps(&["ignore = \">=0.4, <0.4.30\""]),
        &bot(&[
            "    {",
            "      matchPackageNames: [\"ignore\"],",
            "      allowedVersions: \"<0.4.30\",",
            "    },",
        ]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = cap_repo(
        "cap-pointer-only",
        &deps(&["ignore = \">=0.4, <0.4.30\" # a distinctive justification"]),
        &bot(&[]),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        !text.contains("distinctive justification") && !text.contains("0.4.30"),
        "the range and the manifest's prose are payload: {text:?}"
    );
}

#[test]
fn the_real_trees_two_sets_agree() {
    // The self-consumption case the retiring suite ended on.
    let output = common::run_at_real_root(&common::at_root(""), &["check", "--rule", "cap-drift"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a cap here has no counterpart: {}",
        stdout(&output)
    );
}
