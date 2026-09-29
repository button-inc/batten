//! `[tasks."render:cli"]` — CLOUD-171's publish-time CLI reference (CLOUD-1752,
//! CLOUD-1991).
//!
//! The program moved whole into `mise.toml` under CLOUD-1752 as a shell body; the
//! render, the empty-refusal and the atomic move retired onto `batten artifacts
//! write --reference` under CLOUD-1991, which `artifacts_write.rs` drives over
//! the compiled binary. What the task still owns is ARGV ASSEMBLY — the asset
//! path's default and the `--names` short cut — spelled in mise's template, so
//! this tier asserts the declaration rather than running a body mise renders.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/render/cli.sh subject:mise.toml crates/batten/tests/it/render_cli.rs
// ported: tests/render-cli.bats subject:mise.toml crates/batten/tests/it/render_cli.rs
// carried: "--names answers the asset path" mise.toml kind:mechanism
// carried: "--names builds nothing and creates nothing" mise.toml kind:mechanism
// changed: "an unrecognised argument is a usage error, not a silent render" mise.toml the task's `usage` spec declares only `--names`, so mise refuses an undeclared argument before the body runs; the body no longer re-parses `$@`, which is the template-appended text `[tasks.checksums]` measured running as a command
// carried: "the render writes the reference and names it on stdout" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// carried: "the KEY=VALUE line is the only thing on stdout" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs
// changed: "a render that emits nothing is a failure, not an empty artifact" crates/batten/src/lib.rs the refusal moved into `artifacts write` with the render, and it can no longer be DRIVEN: the shell body rendered through a `cargo` a stub could replace, and the verb renders the surface in-process, which is never empty. The refusal is kept in the verb for the publish step's sake; what is withdrawn is the stub-cargo route to it
// changed: "a failed render leaves no artifact behind" crates/batten/src/durable.rs the scratch-then-`mv` the body spelled is `durable::replace`'s temp-fsync-rename, whose own tier pins that an interrupted write leaves the old bytes or the new ones; the stub-cargo route that failed the render on purpose is withdrawn with the shell it stubbed
// carried: "the reference is git-ignored, so it cannot be committed by accident" crates/batten/tests/it/render_cli.rs
// carried: "this repo's surface renders — the task on the real tree" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/artifacts_write.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{at_root, task_body, task_env};

/// The two arms the template selects between: the `--names` echo, and the render.
fn arms() -> (String, String) {
    let body = task_body("render:cli");
    let names = body
        .strip_prefix("{% if usage.names %}")
        .expect("the body selects on the `--names` flag first");
    let split = names
        .rfind("{% else %}cargo")
        .expect("the render is the other arm");
    (names[..split].to_owned(), names[split..].to_owned())
}

#[test]
fn names_answers_the_asset_path_and_builds_nothing() {
    let (names, _) = arms();
    assert!(
        names.starts_with("echo reference="),
        "the names arm answers the KEY=VALUE line: {names}"
    );
    assert!(
        names.contains("{{env.BATTEN_CLI_REFERENCE}}"),
        "and names the asset from [env], its one declaration: {names}"
    );
    // The property that makes asking cheap: an answer behind a compile is one
    // its callers would stop asking for.
    assert!(!names.contains("cargo"), "--names builds nothing: {names}");
}

#[test]
fn the_render_is_the_writer_verb_at_the_same_path() {
    let (names, render) = arms();
    assert!(
        render.contains("artifacts write --reference"),
        "the render is `artifacts write`, not a redirect: {render}"
    );
    let path = |arm: &str| -> String {
        arm.split_once("{% if env.RENDER_CLI_OUT_DIR %}")
            .map(|(_, rest)| rest.to_owned())
            .expect("each arm defaults the output directory")
    };
    assert_eq!(
        path(&names).trim_end_matches("{% endif %}"),
        path(&render).trim_end_matches("{% endif %}"),
        "--names answers the path the render writes"
    );
    assert!(
        !task_env("BATTEN_CLI_REFERENCE").is_empty(),
        "the asset name is declared"
    );
}

/// "Never committed" as a property of `.gitignore`, not of anyone's discipline.
#[test]
fn the_default_reference_path_is_git_ignored() {
    let path = format!("reference/{}", task_env("BATTEN_CLI_REFERENCE"));
    let out = common::git_command(&at_root("."), &["check-ignore", "-q", &path])
        .output()
        .expect("git check-ignore");
    assert!(out.status.success(), "{path} is not git-ignored");
}
