//! `batten release install` over the compiled binary — CLOUD-65, ported off
//! `mise-tasks/install-check.sh` under CLOUD-1716.
//!
//! # What the pure decisions cannot show
//!
//! `install::{matrix_targets, binstall_in, parametric, is_executable}` are pure
//! and their own cases cover the anchored matrix form, the override table, the
//! placeholder set and the magic bytes. None of them can show that the VERB
//! resolves a repository root, asks the two programs through the flags they
//! publish, derives the installable set from the archive suffix rather than from
//! a triple list, or reports could-not-look for a workflow that declares no
//! matrix. Those are properties of the compiled binary.
//!
//! # THE COULD-NOT-LOOK CASES ARE THE ONES THAT MATTER
//!
//! Every way this gate can fail to look is a way it can report a contract it
//! never checked, and that is a 404 on a user's machine rather than a red build.
//! A workflow with no matrix, an `install.sh --targets` that prints nothing, and
//! a `pkg-fmt` with no suffix rule are each `Internal` rather than a pass.
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

use std::path::{Path, PathBuf};
use std::process::Output;

/// A workflow declaring one Linux and one Windows leg.
const WORKFLOW: &str = "jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          \
                        - target: x86_64-unknown-linux-gnu\n          - target: x86_64-pc-windows-msvc\n";

/// A manifest whose template resolves to what `dist` names.
const MANIFEST: &str = r#"[package]
name = "batten"

[package.metadata.binstall]
pkg-url = "{ repo }/releases/download/v{ version }/{ name }-{ version }-{ target }{ archive-suffix }"
pkg-fmt = "tgz"

[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]
pkg-fmt = "zip"
"#;

const WORKSPACE: &str =
    "[workspace.package]\nversion = \"1.2.3\"\nrepository = \"https://example/r\"\n";

/// A `dist` stand-in answering only the query flag this gate uses.
const DIST: &str = "#!/usr/bin/env bash\nset -u\n\
                    if [[ \"${1:-}\" == \"--stem\" ]]; then printf 'batten-1.2.3-%s\\n' \"$2\"; fi\n";

/// An `install.sh` stand-in that agrees with `DIST`.
const INSTALL_AGREEING: &str = "#!/usr/bin/env bash\nset -u\n\
    case \"${1:-}\" in\n\
    --targets) printf 'x86_64-unknown-linux-gnu\\n' ;;\n\
    --asset-name)\n\
      case \"$3\" in\n\
      *windows*) printf 'batten-%s-%s.zip\\n' \"$2\" \"$3\" ;;\n\
      *) printf 'batten-%s-%s.tar.gz\\n' \"$2\" \"$3\" ;;\n\
      esac ;;\n\
    esac\n";

/// An `install.sh` stand-in whose template has the version BAKED IN, so it
/// resolves one name whatever version it is asked for.
///
/// A dedicated fixture rather than surgery on [`INSTALL_AGREEING`]: the
/// replacement had to match an escape sequence inside a Rust literal, and when
/// it silently did not, this case ran the agreeing script and passed for the
/// wrong reason. A fixture that fails to become what a case is named for is
/// indistinguishable from a gate that does not fire.
const INSTALL_HARDCODED: &str = "#!/usr/bin/env bash\nset -u\n\
    case \"${1:-}\" in\n\
    --targets) printf 'x86_64-unknown-linux-gnu\\n' ;;\n\
    --asset-name)\n\
      case \"$3\" in\n\
      *windows*) printf 'batten-1.2.3-%s.zip\\n' \"$3\" ;;\n\
      *) printf 'batten-1.2.3-%s.tar.gz\\n' \"$3\" ;;\n\
      esac ;;\n\
    esac\n";

/// A repository fixture carrying the four files the contract is written in.
fn fixture(name: &str, install: &str, workflow: &str) -> PathBuf {
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
    write(&repo, "mise-tasks/dist.sh", DIST);
    write(&repo, "install.sh", install);
    // `cfg(unix)` because `cross-check` TYPE-CHECKS this crate for
    // `x86_64-pc-windows-gnu`, where `std::os::unix` does not exist at all --
    // an unconditional path is an E0433 there rather than a runtime
    // difference. The executable bit is what makes `install.sh` askable, and a
    // target with no such bit needs nothing set.
    #[cfg(unix)]
    for program in ["mise-tasks/dist.sh", "install.sh"] {
        let path = repo.join(program);
        let mut mode = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        std::fs::set_permissions(&path, mode).unwrap();
    }
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
    // UNIX ONLY: the fixture's authorities are read through `bash`, which a
    // Windows runner resolves to WSL; its UTF-16 banner then reads as 13
    // disagreements about assets nobody changed.
    if !cfg!(unix) {
        return;
    }
    let repo = fixture("agreeing", INSTALL_AGREEING, WORKFLOW);
    let outcome = run(&repo);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "three authorities agreeing must pass\n{answer}{cause}"
    );
    assert!(answer.contains("name-agree"), "{answer}{cause}");
}

/// THE CLASS THIS ROW EXISTS FOR: a matrix leg `install.sh` will not serve.
#[test]
fn a_matrix_target_install_does_not_serve_is_refused() {
    // UNIX ONLY: the fixture's authorities are read through `bash`, which a
    // Windows runner resolves to WSL; its UTF-16 banner then reads as 13
    // disagreements about assets nobody changed.
    if !cfg!(unix) {
        return;
    }
    let serves_nothing = INSTALL_AGREEING.replace("printf 'x86_64-unknown-linux-gnu\\n'", "true");
    let repo = fixture("unserved", &serves_nothing, WORKFLOW);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    // An `install.sh --targets` printing nothing is could-not-look rather than a
    // refusal: the flag is how this reads the script's own list, and without it
    // nothing has been compared.
    assert_eq!(
        outcome.status.code(),
        Some(3),
        "a --targets that answers nothing is could-not-look\n{cause}"
    );
}

/// THE WINDOWS EXCLUSION IS DERIVED. `install.sh` listing the zip target is a
/// disagreement, because nothing builds a POSIX installer for it.
#[test]
fn a_target_install_lists_that_ships_a_zip_is_refused() {
    let lists_windows = INSTALL_AGREEING.replace(
        "printf 'x86_64-unknown-linux-gnu\\n'",
        "printf 'x86_64-unknown-linux-gnu\\nx86_64-pc-windows-msvc\\n'",
    );
    let repo = fixture("unbuilt", &lists_windows, WORKFLOW);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains("x86_64-pc-windows-msvc"), "{cause}");
}

/// A NAME `dist` DOES NOT WRITE. The 404 this whole gate exists to prevent.
#[test]
fn an_asset_name_dist_does_not_write_is_refused() {
    let renamed = INSTALL_AGREEING.replace("batten-%s-%s.tar.gz", "batten_%s_%s.tar.gz");
    let repo = fixture("renamed", &renamed, WORKFLOW);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains("dist writes"), "{cause}");
}

/// THE DEFECT THE SAMPLE VERSION EXISTED TO CATCH, caught directly.
///
/// A template with the version baked in resolves one name whatever it is asked,
/// so the asset for every release but one is a 404.
#[test]
fn a_hardcoded_version_is_refused() {
    let repo = fixture("hardcoded", INSTALL_HARDCODED, WORKFLOW);
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a template that does not carry the version must refuse\n{cause}"
    );
    assert!(cause.contains("does not carry the version"), "{cause}");
}

/// A WORKFLOW DECLARING NO MATRIX IS COULD-NOT-LOOK. A gate that checks nothing
/// must not report green.
/// AND A TREE THAT DECLARES NO WORKFLOW IS COULD-NOT-LOOK, never a guess. A
/// guessed path that does not exist reads as "no matrix", and this verb's own
/// refusal for that case says a gate which checks nothing must not report green
/// — so the two would be indistinguishable.
#[test]
fn a_tree_that_declares_no_release_workflow_is_could_not_look() {
    let repo = fixture("undeclared-workflow", INSTALL_AGREEING, WORKFLOW);
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
    let repo = fixture(
        "no-matrix",
        INSTALL_AGREEING,
        "jobs:\n  build:\n    steps: []\n",
    );
    let outcome = run(&repo);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(3), "{cause}");
    assert!(cause.contains("no matrix targets"), "{cause}");
}

/// AN UNRECOGNISED `pkg-fmt` IS COULD-NOT-LOOK, never a guessed suffix. Guessing
/// would make the comparison pass over a template nobody has checked.
#[test]
fn an_unknown_package_format_is_could_not_look() {
    let repo = fixture("unknown-format", INSTALL_AGREEING, WORKFLOW);
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
    let repo = fixture("committed-binary", INSTALL_AGREEING, WORKFLOW);
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
    // UNIX ONLY: the fixture's authorities are read through `bash`, which a
    // Windows runner resolves to WSL; its UTF-16 banner then reads as 13
    // disagreements about assets nobody changed.
    if !cfg!(unix) {
        return;
    }
    let repo = fixture("not-binaries", INSTALL_AGREEING, WORKFLOW);
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
