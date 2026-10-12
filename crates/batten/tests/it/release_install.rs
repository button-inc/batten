//! `batten release install` over the compiled binary — CLOUD-65, ported off
//! `mise-tasks/install-check.sh` under CLOUD-1716.
//!
//! # What the pure decisions cannot show
//!
//! `install::{matrix_targets, binstall_in, parametric, is_executable}` are pure
//! and their own cases cover the anchored matrix form, the override table, the
//! placeholder set and the magic bytes. None of them can show that the VERB
//! resolves a repository root, asks the generated bootstrap's target table and
//! `dist`'s naming rule in process (`install::TARGETS` since CLOUD-2203,
//! `dist::archive_stem` since `mise-tasks/dist.sh` retired onto `batten dist`
//! under CLOUD-843), derives the installable set from the archive suffix rather
//! than from a triple list, or reports could-not-look for a workflow that
//! declares no matrix. Those are properties of the compiled binary.
//!
//! # THE COULD-NOT-LOOK CASES ARE THE ONES THAT MATTER
//!
//! Every way this gate can fail to look is a way it can report a contract it
//! never checked, and that is a 404 on a user's machine rather than a red build.
//! A workflow with no matrix and a `pkg-fmt` with no suffix rule are each
//! `Internal` rather than a pass.
//
// carried: mise-tasks/install-check.sh crates/batten/src/install.rs kind:verb crates/batten/tests/it/release_install.rs runs:mise+run+install-check
// carried: tests/install-check.bats crates/batten/src/install.rs kind:verb crates/batten/tests/it/release_install.rs
//
// carried: "the tree as it stands agrees across dist, install.sh and binstall" crates/batten/tests/it/release_install.rs
// carried: "THE DEFECT: a matrix target install.sh does not serve fails, naming it" crates/batten/tests/it/release_install.rs
// carried: "a target install.sh claims that no matrix leg builds fails the other way" crates/batten/tests/it/release_install.rs
// carried: "THE DEFECT: renaming the archive in dist breaks the install path" crates/batten/tests/it/release_install.rs
// carried: "THE DEFECT: a binstall pkg-url that resolves elsewhere fails" crates/batten/tests/it/release_install.rs
// carried: "THE DEFECT: a committed executable fails, naming the path and nothing else" crates/batten/tests/it/release_install.rs
// carried: "a text file that happens to start MZ is not an executable" crates/batten/tests/it/release_install.rs
// changed: "an empty matrix is exit 2 — a gate that checks nothing must not report green" crates/batten/src/install.rs the corpus INVERTS the engine's exit table: this was exit 2 in the shell and is `Internal` (3) on the engine, because the engine could not look rather than the caller asking for something wrong
// changed: "a missing install.sh is exit 2, not a passing contract" crates/batten/src/install.rs the corpus INVERTS the engine's exit table: this was exit 2 in the shell and is `Internal` (3) on the engine, because the engine could not look rather than the caller asking for something wrong
// changed: "a manifest with no binstall metadata is exit 2 — that half is unimplemented" crates/batten/src/install.rs the corpus INVERTS the engine's exit table: this was exit 2 in the shell and is `Internal` (3) on the engine, because the engine could not look rather than the caller asking for something wrong
// changed: "a pkg-fmt with no suffix rule is exit 2, never a guessed extension" crates/batten/src/install.rs the corpus INVERTS the engine's exit table: this was exit 2 in the shell and is `Internal` (3) on the engine, because the engine could not look rather than the caller asking for something wrong
//
// carried: "a matrix target install.sh does not serve fails" crates/batten/src/install.rs kind:verb crates/batten/tests/it/release_install.rs runs:mise+run+install-check
// carried: "the target LIST has one authority and it is the workflow's" crates/batten/src/install.rs
// carried: "the Windows exclusion is derived, never restated" crates/batten/src/install.rs
// carried: "an unrecognised pkg-fmt is exit 2 rather than a guessed suffix" crates/batten/src/install.rs kind:verb crates/batten/tests/it/release_install.rs runs:mise+run+install-check
// carried: "no binary is committed, judged on executable magic rather than a path convention" crates/batten/src/install.rs
// carried: "reports the path only — never a byte of the file" crates/batten/src/install.rs
// changed: "a SAMPLE_VERSION of 9.9.9 so a hardcoded version cannot pass" crates/batten/src/install.rs `dist --stem` reads the crate version from the workspace manifest and takes no version argument — deliberately, so an archive's name cannot lie about its contents — so the sample is unavailable; `install::parametric` asks install.sh for one target under TWO versions and requires the answers to differ and each to carry its own, which catches the hardcoded template directly and also catches one that varies while dropping the version, a case the sample could not see
// changed: "exit 0 pass / 1 fail / 2 could-not-look" crates/batten/src/install.rs the shell corpus INVERTS the engine's table, so the port lands on `0` Success, `2` Violation and `3` Internal

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{batten, git_in, scratch, stderr, stdout, write};

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

/// A workflow building `targets`, one matrix leg each.
fn workflow(targets: &[&str]) -> String {
    let legs = targets.iter().fold(String::new(), |mut legs, target| {
        let _ = writeln!(legs, "          - target: {target}");
        legs
    });
    format!("jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n{legs}")
}

/// A workflow building every target the generated bootstrap serves, plus the
/// Windows zip leg it never does — the shape of the real release matrix.
fn agreeing_workflow() -> String {
    let mut targets: Vec<&str> = batten::install::TARGETS.to_vec();
    targets.push("x86_64-pc-windows-msvc");
    workflow(&targets)
}

/// A manifest whose template resolves to what `dist` names: `name-vVERSION-TARGET`.
const MANIFEST: &str = r#"[package]
name = "batten"

[package.metadata.binstall]
pkg-url = "{ repo }/releases/download/v{ version }/{ name }-v{ version }-{ target }{ archive-suffix }"
pkg-fmt = "tgz"

[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]
pkg-fmt = "zip"
"#;

const WORKSPACE: &str =
    "[workspace.package]\nversion = \"1.2.3\"\nrepository = \"https://example/r\"\n";

/// A repository fixture carrying the files the contract is written in. No `dist`
/// or `install.sh` stand-in: the naming rule and the bootstrap's target table
/// are engine code (CLOUD-2203) and are asked in process.
fn fixture(name: &str, workflow: &str) -> PathBuf {
    let repo = scratch(&format!("release-install-{name}"));
    // THE WORKFLOW IS DECLARED, not guessed (rule 1). `[ci] release_workflow`
    // is what tells the verb which file carries the build matrix; without it the
    // verb answers could-not-look rather than reaching for a path this engine
    // has no business knowing.
    write(
        &repo,
        "batten.toml",
        "version = 1\n[ci]\nrequired_checks = [\"final\"]\n\
         release_workflow = \".github/workflows/release-artifacts.yml\"\n",
    );
    write(&repo, ".github/workflows/release-artifacts.yml", workflow);
    write(&repo, "crates/batten/Cargo.toml", MANIFEST);
    write(&repo, "Cargo.toml", WORKSPACE);
    // THE TEMPLATE, NOT A FORK. `common/mod.rs` owns the one `git init` this
    // suite pays and every other fixture copies it; `policy/fixture-forks.rego`
    // is what refuses a second one.
    crate::common::init_repo(&repo);
    git_in(&repo, &["add", "-A"]);
    repo
}

fn run(repo: &Path) -> Output {
    let mut command = batten();
    command.current_dir(repo).args(["release", "install"]);
    command.output().expect("run batten release install")
}

#[test]
fn a_contract_every_authority_agrees_on_passes() {
    let repo = fixture("agreeing", &agreeing_workflow());
    let outcome = run(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "three authorities agreeing must pass\n{answer}{cause}"
    );
    assert!(answer.contains("name-agree"), "{answer}{cause}");
}

/// THE CLASS THIS ROW EXISTS FOR: a tarball leg the bootstrap will not serve,
/// so `curl … | sh` on that platform finds no asset.
#[test]
fn a_matrix_target_install_does_not_serve_is_refused() {
    let mut targets: Vec<&str> = batten::install::TARGETS.to_vec();
    targets.push("riscv64gc-unknown-linux-gnu");
    let repo = fixture("unserved", &workflow(&targets));
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains("riscv64gc-unknown-linux-gnu"), "{cause}");
}

/// The other direction: a target the bootstrap serves that no matrix leg
/// builds, so the script asks for an asset no release carries.
#[test]
fn a_target_the_bootstrap_serves_that_no_leg_builds_is_refused() {
    let unbuilt = batten::install::TARGETS[0];
    let targets: Vec<&str> = batten::install::TARGETS[1..].to_vec();
    let repo = fixture("unbuilt", &workflow(&targets));
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains(unbuilt), "{cause}");
}

/// A WORKFLOW DECLARING NO MATRIX IS COULD-NOT-LOOK. A gate that checks nothing
/// must not report green.
/// AND A TREE THAT DECLARES NO WORKFLOW IS COULD-NOT-LOOK, never a guess. A
/// guessed path that does not exist reads as "no matrix", and this verb's own
/// refusal for that case says a gate which checks nothing must not report green
/// — so the two would be indistinguishable.
#[test]
fn a_tree_that_declares_no_release_workflow_is_could_not_look() {
    let repo = fixture("undeclared-workflow", &agreeing_workflow());
    write(&repo, "batten.toml", "version = 1\n");
    let output = run(&repo);
    assert_eq!(
        output.status.code(),
        Some(3),
        "could not look, not a verdict"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("release_workflow"),
        "the refusal names the key that would answer it"
    );
}

#[test]
fn a_workflow_with_no_matrix_is_could_not_look() {
    let repo = fixture("no-matrix", "jobs:\n  build:\n    steps: []\n");
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(3), "{cause}");
    assert!(cause.contains("no matrix targets"), "{cause}");
}

/// AN UNRECOGNISED `pkg-fmt` IS COULD-NOT-LOOK, never a guessed suffix. Guessing
/// would make the comparison pass over a template nobody has checked.
#[test]
fn an_unknown_package_format_is_could_not_look() {
    let repo = fixture("unknown-format", &agreeing_workflow());
    let manifest = MANIFEST.replace("pkg-fmt = \"tgz\"", "pkg-fmt = \"7z\"");
    write(&repo, "crates/batten/Cargo.toml", &manifest);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(3), "{cause}");
    assert!(cause.contains("no suffix rule"), "{cause}");
}

/// NO BINARY IS COMMITTED, judged on magic rather than on a path convention —
/// and reported as a PATH, never as a byte of the file, which for a committed
/// binary is exactly the payload rule 4 keeps out of a log.
#[test]
fn a_committed_binary_is_refused_and_only_its_path_is_named() {
    let repo = fixture("committed-binary", &agreeing_workflow());
    std::fs::write(
        repo.join("vendor.bin"),
        [0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01],
    )
    .unwrap();
    git_in(&repo, &["add", "-A"]);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains("vendor.bin"), "{cause}");
    assert!(
        !cause.contains("ELF"),
        "the path is named and the bytes are not: {cause}"
    );
}

/// A SHELL SCRIPT IS NOT A BINARY, and neither is prose that happens to open
/// with two printable characters a PE header also uses.
#[test]
fn a_script_and_prose_are_not_committed_binaries() {
    let repo = fixture("not-binaries", &agreeing_workflow());
    std::fs::write(repo.join("tool.sh"), "#!/usr/bin/env bash\nexit 0\n").unwrap();
    std::fs::write(repo.join("NOTES.md"), "MZ is how a sentence might start\n").unwrap();
    git_in(&repo, &["add", "-A"]);
    let outcome = run(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(outcome.status.code(), Some(0), "{answer}{cause}");
}

/// The retired program is gone, and the NAME its four callers use still answers.
#[test]
fn the_retired_program_is_gone_and_its_task_name_survives() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    for path in ["mise-tasks/install-check.sh", "tests/install-check.bats"] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    assert!(
        tasks.contains(r#"[tasks."install-check"]"#),
        "the task name four callers depend on is declared rather than auto-discovered"
    );
    assert!(
        tasks.contains("release install"),
        "and it calls the successor"
    );
    let gate = std::fs::read_to_string(root.join("hk.pkl")).expect("hk.pkl");
    assert!(
        gate.contains("mise run install-check"),
        "hk's gate still names a task that exists"
    );
}
