//! The floor, the toolchain pin and the bot's constraint name one compiler
//! line, over the compiled binary (CLOUD-593 and CLOUD-658, ported from
//! `mise-tasks/msrv-pin-agreement.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/msrv-pin-agreement.rego` carries
//! load-time cases pinning the predicate, and every one of them hands the module
//! a ready-made map of all three files with `with input as`. That fabricates the
//! very shape the engine may be unable to produce (CLOUD-845), and here it
//! fabricates the whole judgement: the agreement IS the join across three
//! separate `line_sources` paths resolved in one evaluation. A module whose suite
//! only fabricated the map would stay green over an engine that resolved two of
//! the three, which is the state in which the third copy silently stops being
//! gated — exactly what CLOUD-658 argues is safe only because this gate covers
//! it.
//!
//! The self-consumption case is the one the retiring suite ended on: the real
//! tree's three numbers agree, checked rather than asserted.
//
// carried: mise-tasks/msrv-pin-agreement.sh policy/msrv-pin-agreement.rego crates/batten/tests/it/msrv_pin_agreement.rs
// carried: tests/msrv-pin-agreement.bats policy/msrv-pin-agreement.rego crates/batten/tests/it/msrv_pin_agreement.rs
//
// carried: "the floor and the pin agreeing passes" policy/msrv-pin-agreement.rego
// carried: "the floor behind the pin is refused, and both values are named" policy/msrv-pin-agreement.rego
// carried: "the floor ahead of the pin is refused too — the check is equality, not a bound" policy/msrv-pin-agreement.rego
// carried: "a patch-only difference is agreement, not drift" policy/msrv-pin-agreement.rego
// carried: "a bare string pin is read, not only the inline-table form" policy/msrv-pin-agreement.rego
// carried: "a rust-version inside another table cannot answer for the workspace" policy/msrv-pin-agreement.rego
// carried: "a manifest with no rust-version is exit 2, never a silent pass" policy/msrv-pin-agreement.rego
// carried: "a tools file with no rust pin is exit 2, never a silent pass" policy/msrv-pin-agreement.rego
// carried: "all three agreeing passes" policy/msrv-pin-agreement.rego
// carried: "a Renovate constraint naming a different compiler is refused" policy/msrv-pin-agreement.rego
// carried: "a constraint ahead of the pin is refused too — equality, not a bound" policy/msrv-pin-agreement.rego
// carried: "a patch component in the constraint is agreement, not drift" policy/msrv-pin-agreement.rego
// carried: "a rust key outside the constraints block cannot answer for it" policy/msrv-pin-agreement.rego
// carried: "a missing constraints.rust is exit 2, never a silent pass" policy/msrv-pin-agreement.rego
// carried: "msrv-pin-agreement.bats::the real tree agrees" policy/msrv-pin-agreement.rego
// changed: "an unreadable file is exit 2 — a gate that cannot look must not report agreement" policy/msrv-pin-agreement.rego the shell opened three named files and refused one it could not read; the successor declares them as `line_sources` and the ENGINE decides this earlier — a rule whose declared paths match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). What the case protected survives as the three PRESENT-BUT-SILENT arms: a file that resolves and carries no number is still a refusal, never agreement
// changed: "an unreadable renovate config is exit 2 on the same terms as the other two" policy/msrv-pin-agreement.rego same engine-side decision as the row above, and the arm that matters is kept: a config that resolves with no `constraints.rust` is `version declare missing`, because an absent constraint is MSRV-aware resolution switched off rather than a neutral omission

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn msrv_repo(name: &str, manifest: &str, tools: &str, bot: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[pattern]]\n\
             id = \"md-quoted-span\"\n\
             regex = '\"[^\"]*\"'\n\n\
             [[verdict]]\n\
             id = \"version declare other\"\n\
             gloss = \"a derived copy names a different compiler than the pin\"\n\
             class = \"The pin is the authority; a copy that drifts switches off what it was written for.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"version declare missing\"\n\
             gloss = \"a file that must carry the number carries none\"\n\
             class = \"Silence on any one of the three would read as agreement.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"msrv-pin-agreement\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"Cargo.toml\", \"mise.toml\", \"renovate.json5\"]\n\
             module = \"policy/msrv-pin-agreement.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("Cargo.toml", manifest)
        .file("mise.toml", tools)
        .file("renovate.json5", bot)
        .git()
        .build();
    common::write(
        &dir,
        "policy/msrv-pin-agreement.rego",
        &std::fs::read_to_string(common::at_root("policy/msrv-pin-agreement.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "msrv-pin-agreement"])
}

fn cargo(version: &str) -> String {
    format!("[workspace.package]\nedition = \"2024\"\nrust-version = \"{version}\"\n")
}

fn tools(version: &str) -> String {
    format!("[tools]\nrust = {{ version = \"{version}\", profile = \"minimal\" }}\n")
}

fn bot(version: &str) -> String {
    format!(
        "{{\n  \"$schema\": \"https://docs.renovatebot.com/renovate-schema.json\",\n  // the pin is the authority; this is its derived copy\n  constraints: {{\n    rust: \"{version}\",\n  }},\n}}\n"
    )
}

/// The three files, each at its own version.
fn three(name: &str, floor: &str, pin: &str, constraint: &str) -> PathBuf {
    msrv_repo(name, &cargo(floor), &tools(pin), &bot(constraint))
}

#[test]
fn all_three_naming_one_compiler_line_pass() {
    let dir = three("msrv-agree", "1.97", "1.97.1", "1.97");
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
fn a_patch_only_difference_is_agreement_not_drift() {
    // The field is a MINIMUM; a patch component there says nothing extra, and
    // reddening on every patch bump of the pin is the noise that gets a gate
    // switched off.
    let dir = three("msrv-patch-only", "1.97", "1.97.4", "1.97");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_floor_behind_the_pin_is_refused_and_both_are_named() {
    // The whole defect: both numbers were `1.x` throughout the twelve releases
    // they were apart, so a major-only comparison passes it.
    let dir = three("msrv-floor-behind", "1.85", "1.97.1", "1.97");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("1.85"),
        "the finding names the divergent value: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_floor_ahead_of_the_pin_is_refused_too() {
    // Equality, not a bound.
    let dir = three("msrv-floor-ahead", "1.99", "1.97.1", "1.97");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_bot_constraint_naming_another_compiler_is_refused() {
    let dir = three("msrv-bot-behind", "1.97", "1.97.1", "1.85");
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("renovate.json5"),
        "the finding names the file the copy came from: {:?}",
        stdout(&output)
    );
}

#[test]
fn a_bare_string_pin_is_read_too() {
    // A gate that understood only one spelling would fail OPEN on the other.
    let dir = msrv_repo(
        "msrv-bare-pin",
        &cargo("1.97"),
        "[tools]\nrust = \"1.97.1\"\n",
        &bot("1.97"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_nested_floor_cannot_answer_for_the_workspace() {
    let dir = msrv_repo(
        "msrv-nested-floor",
        "[workspace.dependencies.demo]\nversion = \"1\"\n  rust-version = \"1.97\"\n",
        &tools("1.97.1"),
        &bot("1.97"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_manifest_with_no_floor_is_refused() {
    let dir = msrv_repo(
        "msrv-no-floor",
        "[workspace.package]\nedition = \"2024\"\n",
        &tools("1.97.1"),
        &bot("1.97"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_tools_file_with_no_pin_is_refused() {
    let dir = msrv_repo(
        "msrv-no-pin",
        &cargo("1.97"),
        "[env]\nX = \"1\"\n",
        &bot("1.97"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_missing_bot_constraint_is_refused() {
    // An absent constraint is MSRV-aware resolution silently switched off, not a
    // neutral omission.
    let dir = msrv_repo(
        "msrv-no-constraint",
        &cargo("1.97"),
        &tools("1.97.1"),
        "{\n  \"$schema\": \"https://docs.renovatebot.com/renovate-schema.json\",\n}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_commented_constraint_does_not_answer_for_the_real_one() {
    // A gate a COMMENT could answer is a gate satisfied by deleting the value it
    // explains.
    let dir = msrv_repo(
        "msrv-commented-constraint",
        &cargo("1.97"),
        &tools("1.97.1"),
        "{\n  // constraints: { rust: \"1.97\" } used to be declared here\n}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_rust_key_outside_the_constraints_block_does_not_answer_for_it() {
    let dir = msrv_repo(
        "msrv-key-outside-block",
        &cargo("1.97"),
        &tools("1.97.1"),
        "{\n  packageRules: [{ rust: \"1.97\" }],\n}\n",
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = msrv_repo(
        "msrv-pointer-only",
        &format!("{}# a distinctive phrase\n", cargo("1.85")),
        &tools("1.97.1"),
        &bot("1.97"),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("distinctive phrase"),
        "the manifest's prose is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_real_trees_three_numbers_agree() {
    // The self-consumption case the retiring suite ended on.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "msrv-pin-agreement"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "the floor, the pin and the bot's constraint do not agree here: {}",
        stdout(&output)
    );
}
