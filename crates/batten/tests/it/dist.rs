//! `batten dist` over the compiled binary — the release build and archive,
//! ported off `mise-tasks/dist.sh` under CLOUD-843.
//!
//! # What the module's own cases cannot show
//!
//! `dist::{archive_stem, archive_ext, is_windows_target, BuildTool, package}` are
//! pure and their unit cases pin the naming contract, the wrapper choice and the
//! one-binary rule. None of them can show that the VERB asks `cargo metadata`
//! from where it stands, refuses an unknown builder before anything runs, runs the
//! build the tool names, finds the binary under the target directory the
//! workspace declares, archives it, and prints two pointers and nothing else.
//! Those are properties of the compiled binary, and they are asserted here over
//! a STUB `cargo` (and `cross`) first on `PATH`: a real cross-build needs the
//! target toolchain and minutes, and the first release is its end-to-end proof,
//! exactly as the retiring suite said of itself.
//!
//! # A consumer that is not this repository
//!
//! The stub workspace is `widget`, not `batten`. The shell carried `BIN=batten`;
//! the verb reads the package, its binary and its version out of the workspace,
//! and a fixture spelling this repository's own crate could not show that.
//
// carried: mise-tasks/dist.sh crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs runs:batten+dist
// carried: tests/dist.bats crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
//
// carried: "windows targets are detected by triple, not by host" crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
// carried: "unix targets are not windows targets" crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
// carried: "archive stem is name-vversion-target" crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
// carried: "archive extension is keyed off the target, not the host" crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
// carried: "archive stem carries the target, so two targets never collide" crates/batten/src/dist.rs kind:verb crates/batten/tests/it/dist.rs
// changed: "the version comes from Cargo.toml, never from an argument" crates/batten/src/dist.rs kind:verb the version is still read and never passed, but from `cargo metadata`'s package version rather than the first `version = "…"` line of the root manifest: that line was the workspace's, and the package cargo builds is the authority the archive must not lie about; asserted by `the_stem_is_named_from_the_workspace_and_nothing_is_built`
// changed: "a missing version in Cargo.toml is an error, not an empty name" crates/batten/src/dist.rs kind:verb still refused rather than named empty, now as could-not-look (exit 3) over `cargo metadata`'s package rather than exit 1 over a scraped line; asserted by `a_package_with_no_version_is_refused_and_nothing_is_built`
// carried: "no target argument is a usage error" crates/batten/tests/it/dist.rs
// carried: "--help succeeds and does not build" crates/batten/tests/it/dist.rs
// carried: "an unknown build tool is refused before anything is compiled" crates/batten/tests/it/dist.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{at_root, batten, scratch, scratch_outside_tree, stderr, stdout, write};

use std::path::{Path, PathBuf};
use std::process::Output;

use batten::exit::ExitCode;

/// A stand-in for `cargo` and `cross`, first on `PATH`.
///
/// It logs every invocation, answers `metadata` from a file, and for a build
/// writes the binary where the declared target directory says the builder
/// would — unless told to fail, or to write nothing.
const STUB: &str = r#"#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >>"$STUB_LOG"
if [ "${1:-}" = metadata ]; then cat "$STUB_METADATA"; exit 0; fi
if [ -n "${STUB_FAIL:-}" ]; then echo "error: the stub build failed" >&2; exit 101; fi
[ -n "${STUB_NOBIN:-}" ] && exit 0
t=""; b=""
while [ $# -gt 0 ]; do
  case "$1" in
  --target) t="$2"; shift ;;
  --bin) b="$2"; shift ;;
  esac
  shift
done
case "$t" in *-windows-*) b="$b.exe" ;; esac
mkdir -p "$STUB_TARGET/$t/dist"
printf 'not really a binary\n' >"$STUB_TARGET/$t/dist/$b"
"#;

/// One scratch workspace: its root, its stub directory and the stub's log.
struct Bench {
    root: PathBuf,
    stubs: PathBuf,
    log: PathBuf,
}

/// A workspace whose one member `widget` declares the given version and binaries.
fn bench(name: &str, version: &str, bins: &[&str]) -> Bench {
    let root = scratch(&format!("dist-{name}"));
    let stubs = root.join(".stubs");
    for program in ["cargo", "cross"] {
        write(&stubs, program, STUB);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(stubs.join(program), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
    }
    let mut targets: Vec<serde_json::Value> = bins
        .iter()
        .map(|bin| serde_json::json!({"kind": ["bin"], "name": bin}))
        .collect();
    targets.push(serde_json::json!({"kind": ["lib"], "name": "widget"}));
    let id = "widget 0.0.0 (path+file:///widget)";
    let metadata = serde_json::json!({
        "packages": [{"id": id, "name": "widget", "version": version, "targets": targets}],
        "workspace_members": [id],
        "workspace_root": root.to_string_lossy(),
        "target_directory": root.join("target").to_string_lossy(),
    });
    write(&root, ".stubs/metadata.json", &metadata.to_string());
    let log = root.join(".stubs/log");
    Bench { root, stubs, log }
}

/// Run `batten dist <args>` in the bench with the stubs first on `PATH`.
fn dist(bench: &Bench, args: &[&str], env: &[(&str, &str)]) -> Output {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bench.stubs.clone()];
    paths.extend(std::env::split_paths(&path));
    let mut command = batten();
    command
        .current_dir(&bench.root)
        .arg("dist")
        .args(args)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("STUB_LOG", &bench.log)
        .env("STUB_METADATA", bench.stubs.join("metadata.json"))
        .env("STUB_TARGET", bench.root.join("target"))
        // An ambient builder (a release leg's own) must not pick the case's.
        .env_remove("DIST_BUILD_TOOL");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("run batten dist")
}

/// Every stub invocation, in order.
fn calls(bench: &Bench) -> Vec<String> {
    std::fs::read_to_string(&bench.log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn opens_with(path: &Path, magic: &[u8]) -> bool {
    std::fs::read(path).is_ok_and(|bytes| bytes.starts_with(magic))
}

#[test]
fn the_stem_is_named_from_the_workspace_and_nothing_is_built() {
    // UNIX ONLY: the stub builders are `bash` scripts, which a Windows runner
    // cannot put first on `PATH` as `cargo`.
    if !cfg!(unix) {
        return;
    }
    let bench = bench("stem", "1.2.3", &["widget"]);
    let output = dist(&bench, &["x86_64-unknown-linux-gnu", "--stem"], &[]);
    assert_eq!(
        output.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "widget-v1.2.3-x86_64-unknown-linux-gnu\n");
    // The version and the name are the workspace's, read — nothing was passed.
    assert_eq!(
        calls(&bench),
        vec!["cargo metadata --no-deps --format-version 1".to_owned()],
        "--stem reads the workspace and builds nothing"
    );
}

#[test]
fn a_build_stages_a_tar_gz_and_prints_two_pointers_and_nothing_else() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("tar", "1.2.3", &["widget"]);
    let output = dist(&bench, &["x86_64-unknown-linux-gnu"], &[]);
    assert_eq!(
        output.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&output)
    );
    // KEY=VALUE and nothing else, so a workflow can append it to
    // `$GITHUB_OUTPUT` unchanged — a stray line there is a failed step.
    assert_eq!(
        stdout(&output),
        "archive=dist/widget-v1.2.3-x86_64-unknown-linux-gnu.tar.gz\n\
         binary=target/x86_64-unknown-linux-gnu/dist/widget\n"
    );
    assert!(
        opens_with(
            &bench
                .root
                .join("dist/widget-v1.2.3-x86_64-unknown-linux-gnu.tar.gz"),
            &[0x1f, 0x8b]
        ),
        "the archive is a gzip stream"
    );
    assert!(
        calls(&bench).contains(
            &"cargo auditable build --locked --profile dist --target x86_64-unknown-linux-gnu \
              --bin widget"
                .to_owned()
        ),
        "the host build is locked, auditable and on the dist profile: {:?}",
        calls(&bench)
    );
}

#[test]
fn a_windows_target_ships_a_zip_of_the_exe() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("zip", "1.2.3", &["widget"]);
    let output = dist(
        &bench,
        &["x86_64-pc-windows-gnu", "--build-tool", "zigbuild"],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        stdout(&output),
        "archive=dist/widget-v1.2.3-x86_64-pc-windows-gnu.zip\n\
         binary=target/x86_64-pc-windows-gnu/dist/widget.exe\n"
    );
    assert!(
        opens_with(
            &bench
                .root
                .join("dist/widget-v1.2.3-x86_64-pc-windows-gnu.zip"),
            b"PK"
        ),
        "the archive is a zip"
    );
    assert!(
        calls(&bench)
            .iter()
            .any(|call| call.starts_with("cargo auditable zigbuild --locked")),
        "{:?}",
        calls(&bench)
    );
}

#[test]
fn a_cross_build_is_not_wrapped_in_auditable() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("cross", "1.2.3", &["widget"]);
    let output = dist(
        &bench,
        &["aarch64-unknown-linux-musl", "--build-tool", "cross"],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&output)
    );
    let calls = calls(&bench);
    assert!(
        calls.contains(
            &"cross build --locked --profile dist --target aarch64-unknown-linux-musl --bin widget"
                .to_owned()
        ),
        "{calls:?}"
    );
    assert!(
        !calls.iter().any(|call| call.contains("auditable")),
        "composition inside the container is unmeasured (CLOUD-263): {calls:?}"
    );
}

#[test]
fn an_unknown_build_tool_is_refused_before_anything_runs() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("bogus-tool", "1.2.3", &["widget"]);
    let output = dist(
        &bench,
        &["x86_64-unknown-linux-gnu", "--build-tool", "bogus"],
        &[],
    );
    assert_eq!(output.status.code(), Some(ExitCode::Usage.code()));
    assert!(
        stderr(&output).contains("must be cargo, cross, or zigbuild"),
        "{}",
        stderr(&output)
    );
    assert!(calls(&bench).is_empty(), "nothing ran: {:?}", calls(&bench));
}

/// The retired program read its builder ONLY from `DIST_BUILD_TOOL`, and the
/// suite exercised exactly that spelling; the verb still honours it when no flag
/// names one, and refuses an unknown one before anything runs.
#[test]
fn the_environment_names_the_builder_when_no_flag_does() {
    if !cfg!(unix) {
        return;
    }
    let refused_bench = bench("env-bogus", "1.2.3", &["widget"]);
    let refused = dist(
        &refused_bench,
        &["x86_64-unknown-linux-gnu"],
        &[("DIST_BUILD_TOOL", "bogus")],
    );
    assert_eq!(refused.status.code(), Some(ExitCode::Usage.code()));
    assert!(
        stderr(&refused).contains("must be cargo, cross, or zigbuild"),
        "{}",
        stderr(&refused)
    );
    assert!(
        calls(&refused_bench).is_empty(),
        "nothing ran: {:?}",
        calls(&refused_bench)
    );

    let honoured_bench = bench("env-cross", "1.2.3", &["widget"]);
    let honoured = dist(
        &honoured_bench,
        &["aarch64-unknown-linux-musl"],
        &[("DIST_BUILD_TOOL", "cross")],
    );
    assert_eq!(
        honoured.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&honoured)
    );
    assert!(
        calls(&honoured_bench)
            .iter()
            .any(|call| call.starts_with("cross build --locked")),
        "the environment's builder ran: {:?}",
        calls(&honoured_bench)
    );

    let flagged_bench = bench("env-flag", "1.2.3", &["widget"]);
    let flagged = dist(
        &flagged_bench,
        &["x86_64-unknown-linux-gnu", "--build-tool", "cargo"],
        &[("DIST_BUILD_TOOL", "cross")],
    );
    assert_eq!(
        flagged.status.code(),
        Some(ExitCode::Success.code()),
        "{}",
        stderr(&flagged)
    );
    assert!(
        !calls(&flagged_bench)
            .iter()
            .any(|call| call.starts_with("cross ")),
        "the flag outranks the environment: {:?}",
        calls(&flagged_bench)
    );
}

#[test]
fn no_target_is_a_usage_error_and_help_builds_nothing() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("usage", "1.2.3", &["widget"]);
    let bare = dist(&bench, &[], &[]);
    assert_eq!(bare.status.code(), Some(ExitCode::Usage.code()));
    let help = dist(&bench, &["--help"], &[]);
    assert_eq!(help.status.code(), Some(ExitCode::Success.code()));
    assert!(stdout(&help).contains("dist"), "{}", stdout(&help));
    assert!(calls(&bench).is_empty(), "{:?}", calls(&bench));
}

#[test]
fn a_package_with_no_version_is_refused_and_nothing_is_built() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("no-version", "", &["widget"]);
    let output = dist(&bench, &["x86_64-unknown-linux-gnu"], &[]);
    assert_eq!(output.status.code(), Some(ExitCode::Internal.code()));
    assert!(
        stderr(&output).contains("declares no version"),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty(), "no partial answer");
    assert_eq!(calls(&bench).len(), 1, "metadata only: {:?}", calls(&bench));
}

#[test]
fn a_workspace_with_two_binaries_is_refused_rather_than_guessed() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("two-bins", "1.2.3", &["widget", "helper"]);
    let output = dist(&bench, &["x86_64-unknown-linux-gnu", "--stem"], &[]);
    assert_eq!(output.status.code(), Some(ExitCode::Internal.code()));
    assert!(
        stderr(&output).contains("2 binary targets"),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty(), "no stem for a guess");
}

#[test]
fn a_failed_build_is_could_not_look_and_names_the_compilers_reason() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("fails", "1.2.3", &["widget"]);
    let output = dist(&bench, &["x86_64-unknown-linux-gnu"], &[("STUB_FAIL", "1")]);
    assert_eq!(output.status.code(), Some(ExitCode::Internal.code()));
    let cause = stderr(&output);
    assert!(cause.contains("the stub build failed"), "{cause}");
    assert!(cause.contains("exited 101"), "{cause}");
    assert!(
        stdout(&output).is_empty(),
        "no pointer to an archive that is not there"
    );
}

#[test]
fn a_build_that_writes_no_binary_is_refused() {
    if !cfg!(unix) {
        return;
    }
    let bench = bench("no-binary", "1.2.3", &["widget"]);
    let output = dist(
        &bench,
        &["x86_64-unknown-linux-gnu"],
        &[("STUB_NOBIN", "1")],
    );
    assert_eq!(output.status.code(), Some(ExitCode::Internal.code()));
    assert!(
        stderr(&output)
            .contains("expected a binary at target/x86_64-unknown-linux-gnu/dist/widget"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn outside_a_workspace_is_could_not_look() {
    // No stub: a directory `cargo metadata` cannot read as a workspace is
    // could-not-look, never a stem invented from nothing.
    // OUTSIDE THE TREE: under `target/` cargo would walk up and find this
    // repository's own workspace, and the case would read batten's stem.
    let dir = scratch_outside_tree("batten-dist", "no-workspace");
    let output = batten()
        .current_dir(&dir)
        .args(["dist", "x86_64-unknown-linux-gnu", "--stem"])
        .output()
        .expect("run batten dist");
    assert_eq!(output.status.code(), Some(ExitCode::Internal.code()));
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
}

/// The retired program and suite are gone, and the task name the release
/// workflow calls still answers, through the verb.
#[test]
fn the_retired_program_is_gone_and_its_task_name_survives() {
    for path in ["mise-tasks/dist.sh", "tests/dist.bats"] {
        assert!(
            !at_root(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(at_root("mise.toml")).expect("mise.toml");
    assert!(
        tasks.contains("[tasks.dist]"),
        "the task name the release workflow calls is declared rather than auto-discovered"
    );
    assert!(
        tasks.contains(r#"run = "cargo run --quiet --locked -p batten -- dist""#),
        "and it calls the successor verb"
    );
}
