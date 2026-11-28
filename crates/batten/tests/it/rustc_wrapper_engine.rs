//! `mise.toml`'s `RUSTC_WRAPPER` names the engine `BATTEN_BIN` names, where one
//! is set and answers the probe (CLOUD-2789).
//!
//! THE DEFECT THIS REFUSES. `verify:gated` builds the tree's engine and exports it
//! as `BATTEN_BIN`; every step it runs is that engine. The wrapper cargo hands each
//! compile to was resolved elsewhere: `target/release/batten`, else the `batten`
//! on `PATH`. Both can predate the tree. A wrapper older than CLOUD-2925's
//! `BATTEN_DISK_WATCHED` skip collects under disk pressure INSIDE the traced
//! command of the step that started the build, so its reads of `batten.toml` and
//! `.gitignore` were charged to that step: `darwin-link`, `lint:clippy` and
//! `cross-check` each refused their record for a read their command never made,
//! and only when the disk was low.
//!
//! EVALUATED, NOT PATTERN-MATCHED, for `release_token_precedence`'s reason: the
//! case runs `mise env --json`, the resolver every task runs under, against a
//! stub engine that answers the probe with its own path.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;

/// `RUSTC_WRAPPER` as `mise env` resolves it at the repository root with
/// `BATTEN_BIN` set to `engine`.
fn resolved(engine: &std::path::Path) -> String {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — the subject IS mise's own template resolution, so the gate has to run the resolver; `release_token_precedence` resolves its template the same way"
    )]
    let mut command = std::process::Command::new("mise");
    command
        .args(["env", "--json"])
        .current_dir(common::at_root("."))
        .env("BATTEN_BIN", engine)
        .env_remove("RUSTC_WRAPPER");
    let output = command
        .streamed_output()
        .expect("mise resolves the environment");
    assert!(
        output.status.success(),
        "mise env exits 0: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resolved: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("mise env --json is json");
    resolved
        .get("RUSTC_WRAPPER")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Fails by: `RUSTC_WRAPPER` resolving to `target/release/batten` or the `PATH`
/// engine while `BATTEN_BIN` names one that answers the probe. ONE CASE ON EVERY
/// TARGET: `mise.toml` sets no wrapper on Windows, whose probe shell is not `sh`,
/// so there the same resolution answers empty.
#[test]
fn the_wrapper_is_the_engine_the_gate_set_built() {
    let dir = common::scratch("rustc-wrapper-engine");
    let engine = dir.join("engine");
    common::write(
        &dir,
        "engine",
        "#!/bin/sh\n[ \"$1 $2\" = \"rustc --batten-wrapper-probe\" ] && echo \"$0\"\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let expected = if cfg!(windows) {
        String::new()
    } else {
        engine.display().to_string()
    };
    assert_eq!(
        resolved(&engine),
        expected,
        "cargo wraps each compile in the engine the gate set built"
    );
}
