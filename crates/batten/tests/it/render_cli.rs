//! `[tasks."render:cli"]` — CLOUD-171's publish-time CLI reference, over the
//! task's own body (CLOUD-1752).
//!
//! The program moved whole into `mise.toml`: it is an effect with no decision a
//! module could take — it renders, refuses to publish an empty or failed render,
//! and names the asset. This tier runs the body the manifest declares, as mise
//! does (`usage_names` in the environment, the `{% raw %}` fence stripped),
//! against a stub `cargo` for the failure arms and the real engine for the render.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/render/cli.sh mise.toml kind:mechanism crates/batten/tests/it/render_cli.rs
// carried: tests/render-cli.bats mise.toml kind:mechanism crates/batten/tests/it/render_cli.rs
// carried: "--names answers the asset path" mise.toml kind:mechanism
// carried: "--names builds nothing and creates nothing" mise.toml kind:mechanism
// changed: "an unrecognised argument is a usage error, not a silent render" mise.toml the task's `usage` spec declares only `--names`, so mise refuses an undeclared argument before the body runs; the body no longer re-parses `$@`, which is the template-appended text `[tasks.checksums]` measured running as a command
// carried: "the render writes the reference and names it on stdout" mise.toml kind:mechanism
// carried: "the KEY=VALUE line is the only thing on stdout" mise.toml kind:mechanism
// carried: "a render that emits nothing is a failure, not an empty artifact" mise.toml kind:mechanism
// carried: "a failed render leaves no artifact behind" mise.toml kind:mechanism
// carried: "the reference is git-ignored, so it cannot be committed by accident" mise.toml kind:mechanism
// carried: "this repo's surface renders — the task on the real tree" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, program, scratch, task_bash, task_body, task_env, write};

/// Run the body in `dir`, with `--names` as the `usage` spec delivers it.
fn render(dir: &Path, names: bool) -> Output {
    let mut command = task_bash(dir, &task_body("render:cli"));
    command
        .env("RENDER_CLI_OUT_DIR", dir.join("out"))
        .env("BATTEN_CLI_REFERENCE", task_env("BATTEN_CLI_REFERENCE"))
        .env("usage_names", if names { "true" } else { "false" })
        // The real render must not rebuild into a scratch target.
        .env("CARGO_TARGET_DIR", at_root("target"))
        .stdin(Stdio::null());
    command.output().expect("run the task body")
}

/// A scratch directory whose `bin/cargo` runs `script` and records the call.
fn with_cargo(name: &str, script: &str) -> PathBuf {
    let dir = scratch(&format!("render-cli-{name}"));
    let marker = dir.join("cargo-was-called");
    write(
        &dir,
        "bin/cargo",
        &format!(
            "#!/usr/bin/env bash\ntouch '{}'\n{script}\n",
            marker.display()
        ),
    );
    executable(&dir.join("bin/cargo"));
    dir
}

fn executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(path).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("chmod");
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn reference(dir: &Path) -> PathBuf {
    dir.join("out").join(task_env("BATTEN_CLI_REFERENCE"))
}

#[test]
fn names_answers_the_asset_path_and_builds_nothing() {
    let dir = with_cargo("names", "exit 0");
    let out = render(&dir, true);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        stdout(&out),
        format!("reference={}\n", reference(&dir).display())
    );
    // The property that makes asking cheap: an answer behind a compile is one
    // its callers would stop asking for.
    assert!(!dir.join("cargo-was-called").exists(), "--names built");
    assert!(
        !dir.join("out").exists(),
        "--names created the output directory"
    );
}

#[test]
fn an_empty_render_is_a_failure_not_an_empty_artifact() {
    let dir = with_cargo("empty", "exit 0");
    let out = render(&dir, false);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(said(&out).contains("rendered empty"), "{}", said(&out));
    assert!(!reference(&dir).exists(), "an empty file was published");
}

#[test]
fn a_failed_render_leaves_the_previous_artifact_untouched() {
    let dir = with_cargo("failed", "exit 3");
    write(
        &dir,
        &format!("out/{}", task_env("BATTEN_CLI_REFERENCE")),
        "a previous good render\n",
    );
    let out = render(&dir, false);
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(reference(&dir)).expect("the previous render"),
        "a previous good render\n",
        "a failed render truncated the artifact"
    );
}

/// The real engine over this repository's surface: it renders, writes a
/// non-empty file, and says exactly one KEY=VALUE line.
#[test]
fn this_repos_surface_renders_to_one_named_file_and_one_line() {
    let dir = scratch("render-cli-real");
    let out = render(&dir, false);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        stdout(&out),
        format!("reference={}\n", reference(&dir).display()),
        "the KEY=VALUE line is the only thing on stdout"
    );
    let bytes = std::fs::metadata(reference(&dir))
        .expect("the reference")
        .len();
    assert!(bytes > 0, "the reference is empty");
}

/// "Never committed" as a property of `.gitignore`, not of anyone's discipline.
#[test]
fn the_default_reference_path_is_git_ignored() {
    let path = format!("reference/{}", task_env("BATTEN_CLI_REFERENCE"));
    let out = program("git")
        .args(["check-ignore", "-q", &path])
        .current_dir(at_root("."))
        .output()
        .expect("git check-ignore");
    assert!(out.status.success(), "{path} is not git-ignored");
}
