//! The workspace's own crypto crates resolve one `digest` major, over the
//! compiled binary (CLOUD-767, ported from `mise-tasks/digest-major-agreement.sh`
//! under CLOUD-843).
//!
//! **What is decidable only here.** `policy/digest-major-agreement.rego` carries
//! load-time cases pinning the predicate, and every one hands the module a
//! ready-made map of both files with `with input as`. That fabricates the very
//! shape the engine may be unable to produce (CLOUD-845), and here it fabricates
//! the whole judgement: the rule is a JOIN in which the manifest answers which
//! crates are OURS and the lock answers what they resolved, and neither file can
//! answer the other's question. A module whose suite only fabricated the map would
//! stay green over an engine that resolved the lock and not the manifest — the
//! state in which every transitive hasher enrols and the gate is red forever, or
//! resolved the manifest and not the lock, where it decides nothing at all.
//!
//! The self-consumption case is this repository's own two files, which is what
//! makes the claim the old manifest comment got wrong checkable rather than
//! asserted.
//
// carried: mise-tasks/digest-major-agreement.sh policy/digest-major-agreement.rego crates/batten/tests/it/digest_major_agreement.rs
// carried: tests/digest-major-agreement.bats policy/digest-major-agreement.rego crates/batten/tests/it/digest_major_agreement.rs
//
// carried: "the pair agreeing is the ordinary pass, and the verdict names the major" policy/digest-major-agreement.rego
// carried: "THE HALF-BUMP IS REFUSED — one crate moved and the other left behind" policy/digest-major-agreement.rego
// carried: "the coordinated bump passes — moving BOTH is what the manifest asks for" policy/digest-major-agreement.rego
// carried: "A CRATE GIX OWNS IS NOT OURS: a transitive hasher on the other major is ignored" policy/digest-major-agreement.rego
// carried: "one declared crate cannot disagree with itself, and the gate says so" policy/digest-major-agreement.rego
// carried: "a bare digest reference resolves against the one major vendored" policy/digest-major-agreement.rego
// carried: "COULD NOT LOOK, NEVER AGREEMENT: a declared crate absent from the lock is exit 2" policy/digest-major-agreement.rego
// carried: "a name outside [workspace.dependencies] does not enrol the crate" policy/digest-major-agreement.rego
// carried: "POINTER, NEVER PAYLOAD: the refusal carries no version requirement and no manifest line" policy/digest-major-agreement.rego
// changed: "an unreadable lockfile is exit 2, not a pass" policy/digest-major-agreement.rego the shell opened two named files and refused one it could not read; the successor declares them as `line_sources` and the ENGINE decides this earlier — a rule whose declared paths match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). What the case protected survives as the PRESENT-BUT-SILENT arm: a lock that resolves and answers nothing for a declared crate is still `lock read unclear`, never agreement
// changed: "an unreadable manifest is exit 2, not a pass" policy/digest-major-agreement.rego same engine-side decision as the row above. The manifest's own silence is not a separate refusal here because it is not a separate failure: a manifest declaring neither crate leaves fewer than two under judgement, which the retiring suite itself calls a legitimate state rather than a vacuous pass
// changed: "the gate writes nothing — it decides over two committed files" policy/digest-major-agreement.rego the property is carried by CONSTRUCTION rather than by a case: a `kind = "policy"` rule over `scope = "tree"` reaches the filesystem through `input.tree` and has no write surface at all, where the shell could in principle have opened a file for writing and needed a case saying it did not

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn digest_repo(name: &str, manifest: &str, lock: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[verdict]]\n\
             id = \"version resolve other\"\n\
             gloss = \"the workspace's own crypto crates resolved different majors\"\n\
             class = \"They compose in one expression, so a split is a type that does not exist.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[verdict]]\n\
             id = \"lock read unclear\"\n\
             gloss = \"the lockfile does not answer what a declared crate resolved\"\n\
             class = \"A lock that does not describe the manifest decides nothing.\"\n\n\
             [[verdict.route]]\n\
             id = \"prose read first\"\n\
             kind = \"document\"\n\
             target = \"AGENTS.md\"\n\n\
             [[rule]]\n\
             id = \"digest-major-agreement\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             line_sources = [\"Cargo.toml\", \"Cargo.lock\"]\n\
             module = \"policy/digest-major-agreement.rego\"\n\
             severity = \"deny\"\n",
        )
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("Cargo.toml", manifest)
        .file("Cargo.lock", lock)
        .git()
        .build();
    common::write(
        &dir,
        "policy/digest-major-agreement.rego",
        &std::fs::read_to_string(common::at_root("policy/digest-major-agreement.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "digest-major-agreement"])
}

/// A `[workspace.dependencies]` table declaring `names`.
fn workspace(names: &[&str]) -> String {
    let mut manifest = String::from("[workspace.dependencies]\n");
    for name in names {
        writeln!(manifest, "{name} = \"1\"").unwrap();
    }
    manifest.push_str("\n[workspace.lints]\nrust = {}\n");
    manifest
}

/// One lockfile stanza.
fn pkg(name: &str, version: &str, deps: &[&str]) -> String {
    let mut stanza = format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n");
    if !deps.is_empty() {
        stanza.push_str("dependencies = [\n");
        for dep in deps {
            writeln!(stanza, " \"{dep}\",").unwrap();
        }
        stanza.push_str("]\n");
    }
    stanza.push('\n');
    stanza
}

#[test]
fn the_pair_agreeing_is_the_ordinary_pass() {
    let dir = digest_repo(
        "digest-agree",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("hmac", "0.12.1", &["digest"]),
            pkg("sha2", "0.10.8", &["digest"])
        ),
    );
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
fn the_half_bump_is_refused() {
    // One crate moved and the other left behind: the composed type stops
    // existing, and the whole point of the gate is saying so before a runner is
    // spent.
    let dir = digest_repo(
        "digest-half-bump",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("digest", "0.11.3", &[]),
            pkg("hmac", "0.12.1", &["digest 0.10.7"]),
            pkg("sha2", "0.11.0", &["digest 0.11.3"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(
        text.contains("hmac") && text.contains("sha2"),
        "the finding names both crates and their majors: {text:?}"
    );
}

#[test]
fn the_coordinated_bump_passes() {
    // Moving BOTH is what the manifest asks for, so the gate must not stand in
    // the way of the bump it exists to keep honest.
    let dir = digest_repo(
        "digest-coordinated",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}",
            pkg("digest", "0.11.3", &[]),
            pkg("hmac", "0.13.0", &["digest"]),
            pkg("sha2", "0.11.0", &["digest"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_transitive_crate_on_another_major_is_not_ours() {
    // The workspace has no say in what a transitive dependency vendors, and a
    // gate asserting otherwise is red on the commit that introduced it and every
    // commit after — which is a gate switched off within a day.
    let dir = digest_repo(
        "digest-transitive",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("digest", "0.11.3", &[]),
            pkg("hmac", "0.12.1", &["digest 0.10.7"]),
            pkg("sha2", "0.10.8", &["digest 0.10.7"]),
            pkg("sha1-checked", "0.11.0", &["digest 0.11.3"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn one_declared_crate_cannot_disagree_with_itself() {
    let dir = digest_repo(
        "digest-single",
        &workspace(&["hmac"]),
        &format!(
            "{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("hmac", "0.12.1", &["digest"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_bare_reference_resolves_against_the_one_major_vendored() {
    // Cargo writes a bare entry when one major is in the tree; with nothing to
    // disambiguate, the lock's own package is the answer.
    let dir = digest_repo(
        "digest-bare",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("hmac", "0.12.1", &["digest"]),
            pkg("sha2", "0.10.8", &["digest 0.10.7"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn a_declared_crate_the_lock_answers_nothing_for_is_not_agreement() {
    let dir = digest_repo(
        "digest-absent",
        &workspace(&["hmac", "sha2"]),
        &format!(
            "{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("hmac", "0.12.1", &["digest"]),
            pkg("sha2", "0.10.8", &["cpufeatures"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_name_outside_the_workspace_table_does_not_enrol_the_crate() {
    // Conflating our direct dependency with a transitive one is exactly the
    // mistake the old manifest comment made.
    let dir = digest_repo(
        "digest-name-outside",
        "[workspace.dependencies]\nhmac = \"0.12\"\n\n[workspace.lints]\n# sha2 is discussed here and declared nowhere\nrust = {}\n",
        &format!(
            "{}{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("digest", "0.11.3", &[]),
            pkg("hmac", "0.12.1", &["digest 0.10.7"]),
            pkg("sha2", "0.11.0", &["digest 0.11.3"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn output_is_pointer_only() {
    let dir = digest_repo(
        "digest-pointer-only",
        "[workspace.dependencies]\nhmac = \"0.12\" # a distinctive justification\nsha2 = \"0.10\"\n",
        &format!(
            "{}{}{}{}",
            pkg("digest", "0.10.7", &[]),
            pkg("digest", "0.11.3", &[]),
            pkg("hmac", "0.12.1", &["digest 0.10.7"]),
            pkg("sha2", "0.11.0", &["digest 0.11.3"])
        ),
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    let text = stdout(&output);
    assert!(
        !text.contains("distinctive justification") && !text.contains("0.12.1"),
        "the manifest's prose and the lock's versions are payload: {text:?}"
    );
}

#[test]
fn this_workspaces_own_crypto_crates_agree() {
    // The claim the old manifest comment got wrong, checked rather than
    // asserted.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "digest-major-agreement"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "this workspace's own crypto crates split across digest majors: {}",
        stdout(&output)
    );
}
