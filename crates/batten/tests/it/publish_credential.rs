//! No long-lived registry credential can reach the release path, and publishing
//! implies OIDC, over the compiled binary (CLOUD-109, ported from
//! `mise-tasks/publish-credential-check.sh` under CLOUD-843).
//!
//! **What is decidable only here.** `policy/publish-credential.rego` carries
//! load-time cases pinning the predicate, and every one hands the module a
//! ready-made map of workflows with `with input as`. That fabricates the very
//! shape the engine may be unable to produce (CLOUD-845), and the first half of
//! this rule rests on it entirely: a credential can appear in ANY workflow, so a
//! declared `line_sources` glob that resolved only the release workflow — or
//! resolved a workflow directory to nothing — would leave the rest unscanned
//! with nothing red. That is the vacuous pass the retiring suite spent a case on,
//! and no `with input as` block can distinguish it from a scan that found
//! nothing.
//!
//! The self-consumption case is the one the retiring suite opened on: the tree as
//! it stands carries no registry credential.
//
// carried: mise-tasks/publish-credential-check.sh policy/publish-credential.rego crates/batten/tests/it/publish_credential.rs
// carried: tests/publish-credential-check.bats policy/publish-credential.rego crates/batten/tests/it/publish_credential.rs
//
// carried: "the tree as it stands passes: no registry credential, publishing off" policy/publish-credential.rego
// carried: "THE DEFECT: a workflow gaining CARGO_REGISTRY_TOKEN fails" policy/publish-credential.rego
// carried: "an alternate-registry token is caught too, whatever the registry is named" policy/publish-credential.rego
// carried: "a hand-rolled cargo login is the same defect spelled differently" policy/publish-credential.rego
// carried: "the finding is a pointer — a path and a rule id, never the matched line" policy/publish-credential.rego
// carried: "THE POINT: turning publishing on without id-token: write fails" policy/publish-credential.rego
// carried: "turning publishing on WITH id-token: write passes" policy/publish-credential.rego
// carried: "the permission is not satisfied by the phrase appearing in a comment" policy/publish-credential.rego
// carried: "publishing off does NOT require the permission — a dead grant is not the ask" policy/publish-credential.rego
// carried: "THE SILENT CASE: no publish key reads as publishing, because that is the default" policy/publish-credential.rego
// carried: "publishing on with no release workflow at all is exit 2" policy/publish-credential.rego
// changed: "an unreadable config is exit 2 — could not look, never a clean tree" policy/publish-credential.rego the shell opened a named file and refused when it was gone; the successor declares it as a `line_sources` path and the ENGINE decides this earlier — a rule whose declared paths match nothing is not evaluated at all, and `input.tree.missing` is never populated on the tree surface (CLOUD-1049, measured identically for `policy/mise-pin-agreement.rego`'s own could-not-look clause). The direction that mattered survives and is stronger for it: a config that resolves and says nothing reads as PUBLISHING, so silence is never the quiet arm
// changed: "a workflow directory with no workflows is exit 2, not a vacuous pass" policy/publish-credential.rego the shell listed a directory itself and refused an empty one; the successor is handed whatever the declared glob resolved, and cannot tell "no workflows exist" from "the glob resolved none" — both arrive as an empty map. The vacuity is not left unheld: it is the ENGINE's to answer, which is why this tier drives the compiled binary over trees that really do carry several workflows

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, git_in, run, stderr, stdout};

/// A repository declaring only this rule, so any finding is the one under test.
fn publish_repo(name: &str, config: &str, workflows: &[(&str, &str)]) -> PathBuf {
    let mut fixture = Fixture::new(name).config(
        "version = 1\n\n\
         [[pattern]]\n\
         id = \"cargo-registry-token\"\n\
         regex = 'CARGO_REGISTRY_TOKEN|CARGO_REGISTRIES_[A-Z0-9_]*_TOKEN'\n\n\
         [[pattern]]\n\
         id = \"cargo-login-call\"\n\
         regex = '(^|[^A-Za-z0-9_-])cargo login([^A-Za-z0-9_-]|$)'\n\n\
         [[pattern]]\n\
         id = \"oidc-token-permission\"\n\
         regex = '^[[:space:]]+id-token:[[:space:]]*write[[:space:]]*(#.*)?$'\n\n\
         [[verdict]]\n\
         id = \"grant carry unsafe\"\n\
         gloss = \"a workflow can reach a long-lived registry credential\"\n\
         class = \"A stored credential is the thing trusted publishing exists to retire.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[verdict]]\n\
         id = \"lane grant missing\"\n\
         gloss = \"publishing is on without the credential-free way to do it\"\n\
         class = \"Publishing cannot be switched on except through OIDC, in the same commit.\"\n\n\
         [[verdict.route]]\n\
         id = \"prose read first\"\n\
         kind = \"document\"\n\
         target = \"AGENTS.md\"\n\n\
         [[rule]]\n\
         id = \"publish-credential\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         line_sources = [\"release-plz.toml\", \".github/workflows/*.yml\"]\n\
         module = \"policy/publish-credential.rego\"\n\
         severity = \"deny\"\n",
    );
    fixture = fixture
        .file("AGENTS.md", "the consumer's own authority\n")
        .file("release-plz.toml", config);
    for (path, body) in workflows {
        fixture = fixture.file(path, body);
    }
    let dir = fixture.git().build();
    common::write(
        &dir,
        "policy/publish-credential.rego",
        &std::fs::read_to_string(common::at_root("policy/publish-credential.rego")).unwrap(),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn check(dir: &Path) -> Output {
    run(dir, &["check", "--rule", "publish-credential"])
}

const PLAIN: &str = "on: push\njobs:\n  release-plz:\n    permissions:\n      contents: write\n    steps:\n      - run: release-plz release\n";

const WITH_OIDC: &str = "on: push\njobs:\n  release-plz:\n    permissions:\n      contents: write\n      id-token: write\n    steps:\n      - run: release-plz release\n";

#[test]
fn no_credential_and_publishing_off_passes() {
    let dir = publish_repo(
        "publish-clean",
        "[workspace]\npublish = false\n",
        &[(".github/workflows/release-plz.yml", PLAIN)],
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
fn a_registry_token_in_any_workflow_is_refused() {
    // THE DEFECT: a credential reaches every job that can read the secret, not
    // the one step that needs it.
    let dir = publish_repo(
        "publish-token",
        "[workspace]\npublish = false\n",
        &[
            (".github/workflows/release-plz.yml", PLAIN),
            (
                ".github/workflows/other.yml",
                "on: push\njobs:\n  x:\n    env:\n      CARGO_REGISTRY_TOKEN: ${{ secrets.X }}\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("other.yml"),
        "the finding names the workflow: {:?}",
        stdout(&output)
    );
}

#[test]
fn the_alternate_registry_form_is_refused_too() {
    // Its middle segment is the registry's own name and cannot be enumerated, so
    // the pattern matches the shape.
    let dir = publish_repo(
        "publish-alt-registry",
        "[workspace]\npublish = false\n",
        &[
            (".github/workflows/release-plz.yml", PLAIN),
            (
                ".github/workflows/other.yml",
                "on: push\njobs:\n  x:\n    env:\n      CARGO_REGISTRIES_MYREG_TOKEN: ${{ secrets.X }}\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn a_hand_rolled_login_is_the_same_defect() {
    let dir = publish_repo(
        "publish-login",
        "[workspace]\npublish = false\n",
        &[
            (".github/workflows/release-plz.yml", PLAIN),
            (
                ".github/workflows/other.yml",
                "on: push\njobs:\n  x:\n    steps:\n      - run: cargo login \"$TOKEN\"\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn the_finding_never_carries_the_matched_line() {
    // Load-bearing rather than stylistic: the class of thing being looked for is
    // the class that must not reach a log, so a gate that echoed the line would
    // be the leak it exists to prevent.
    let dir = publish_repo(
        "publish-pointer-only",
        "[workspace]\npublish = false\n",
        &[
            (".github/workflows/release-plz.yml", PLAIN),
            (
                ".github/workflows/other.yml",
                "on: push\njobs:\n  x:\n    env:\n      CARGO_REGISTRY_TOKEN: a-distinctive-literal\n",
            ),
        ],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !stdout(&output).contains("a-distinctive-literal"),
        "the matched line is payload: {:?}",
        stdout(&output)
    );
}

#[test]
fn publishing_on_without_oidc_is_refused() {
    // THE POINT: publishing cannot be switched on except through OIDC, in the
    // same commit that switches it.
    let dir = publish_repo(
        "publish-on-no-oidc",
        "[workspace]\npublish = true\n",
        &[(".github/workflows/release-plz.yml", PLAIN)],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn publishing_on_with_oidc_passes() {
    let dir = publish_repo(
        "publish-on-with-oidc",
        "[workspace]\npublish = true\n",
        &[(".github/workflows/release-plz.yml", WITH_OIDC)],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn the_permission_named_in_a_comment_does_not_satisfy_it() {
    let dir = publish_repo(
        "publish-comment-permission",
        "[workspace]\npublish = true\n",
        &[(
            ".github/workflows/release-plz.yml",
            "on: push\njobs:\n  release-plz:\n    permissions:\n      contents: write\n      # id-token: write goes here when publishing turns on\n",
        )],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn publishing_off_does_not_require_the_permission() {
    // A dead grant is not the ask: granting a capability no step uses is a
    // finding of its own to an excessive-permissions audit.
    let dir = publish_repo(
        "publish-off-no-permission",
        "[workspace]\npublish = false\n",
        &[(".github/workflows/release-plz.yml", PLAIN)],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
}

#[test]
fn an_absent_publish_key_reads_as_publishing() {
    // THE SILENT CASE: the release tool's own default is to publish, so reading
    // silence as `false` would make the gate quiet in exactly the case it exists
    // for.
    let dir = publish_repo(
        "publish-absent-key",
        "[workspace]\nallow_dirty = false\n",
        &[(".github/workflows/release-plz.yml", PLAIN)],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn publishing_on_with_no_release_workflow_is_not_a_pass() {
    let dir = publish_repo(
        "publish-no-release-workflow",
        "[workspace]\npublish = true\n",
        &[(".github/workflows/ci.yml", PLAIN)],
    );
    let output = check(&dir);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
}

#[test]
fn the_tree_as_it_stands_carries_no_registry_credential() {
    // The self-consumption case the retiring suite opened on.
    let output = common::run_at_real_root(
        &common::at_root(""),
        &["check", "--rule", "publish-credential"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a long-lived registry credential can reach this release path: {}",
        stdout(&output)
    );
}
