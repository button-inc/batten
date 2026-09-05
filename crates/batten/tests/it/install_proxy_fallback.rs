//! `install.sh` respects a proxy, and goes around it only when it is the thing
//! refusing (CLOUD-1457).
//!
//! # Why this is a Rust tier and not a `.bats` case
//!
//! `tests/install.bats` is where this obviously belongs and `shell-retirement`
//! refuses the edit: a `tests/**/*.bats` change has two landable shapes, retire
//! whole or leave alone, and there is no override. So the tier lives here, which
//! is also where `.claude/rules/policy-modules.md` says a new second tier goes.
//!
//! # The condition CI cannot produce, and what is asserted instead
//!
//! The real failure needs an INTERCEPTING proxy answering for GitHub with a
//! credential of its own — a container-build host, where no session exists for
//! the proxy to scope one to. CI has no such proxy, so a case driving the real
//! network there would pass without ever reaching the arm. Following
//! `.claude/rules/rust.md`, the decision is extracted instead: a stub `curl` on
//! `PATH` answers `403` and records the config it was handed, so the assertion is
//! over WHAT THE SCRIPT DECIDED TO SEND rather than over a network that cannot be
//! made to misbehave here.
//!
//! That is the same stub-on-PATH shape `install.bats` already uses for the CA
//! bundle cases, so the technique is the suite's own rather than invented here.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::scratch;

/// The installer under test, read from the tree rather than copied.
fn installer() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../install.sh")
}

/// A `curl` that records every config it is handed, reports `403`, and fails.
///
/// `403` is the discriminator: it is a refusal — something answered and declined
/// — where a network fault is a connect failure. The script may only bypass the
/// proxy on the former, so a stub reporting a timeout must NOT provoke a bypass,
/// which the second case below asserts.
fn stub_curl(dir: &Path, code: &str) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).expect("the stub directory exists");
    let seen = dir.join("configs");
    std::fs::write(
        bin.join("curl"),
        format!(
            "#!/bin/sh\ncat >>{seen}\necho '--- call ---' >>{seen}\nprintf '{code}'\nexit 22\n",
            seen = seen.display(),
        ),
    )
    .expect("the stub is written");
    let mut perms = std::fs::metadata(bin.join("curl"))
        .expect("the stub exists")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(bin.join("curl"), perms).expect("the stub is executable");
    seen
}

/// Run the installer with the stub ahead of the real `curl`.
fn run(dir: &Path, code: &str, token: &str) -> String {
    let seen = stub_curl(dir, code);
    let path = format!(
        "{}:{}",
        dir.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let _ = std::process::Command::new("sh")
        .arg(installer())
        .env("PATH", path)
        .env("BATTEN_INSTALL_DIR", dir.join("dest"))
        .env("BATTEN_ALLOW_OFF_PATH", "1")
        .env("BATTEN_RETRIES", "1")
        .env("BATTEN_TARGET", "x86_64-unknown-linux-musl")
        .env("GH_TOKEN", "proxy-placeholder")
        .env("GITHUB_PERSONAL_ACCESS_TOKEN", token)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("BATTEN_GITHUB_TOKEN")
        .output()
        .expect("the installer runs");
    std::fs::read_to_string(&seen).unwrap_or_default()
}

#[test]
fn a_refusal_is_retried_around_the_proxy_with_the_operators_own_credential() {
    // THE ARM THE OUTAGE NEEDED. A build host's proxy answers 403 for GitHub with
    // a credential of its own, and no amount of retrying moves it — so the second
    // attempt has to leave the proxy, and has to carry a token that GitHub will
    // actually accept rather than the placeholder the proxy exported.
    let dir = scratch("install-proxy-refused");
    let configs = run(&dir, "403", "operator-pat");
    assert!(
        configs.contains("noproxy ="),
        "a 403 is the proxy refusing, so the retry must go around it: {configs}"
    );
    assert!(
        configs.contains("operator-pat"),
        "the direct attempt must carry the operator's credential — `GH_TOKEN` is \
         the proxy's placeholder and is what was just refused: {configs}"
    );
}

#[test]
fn an_ordinary_failure_never_leaves_the_proxy() {
    // THE ANTI-VACUITY HALF, and the one that keeps this honest. Without it the
    // case above is satisfied by a script that bypasses the proxy on every
    // failure — which would route around an operator's legitimate proxy on a
    // flaky network, the opposite of what a proxy is for.
    let dir = scratch("install-proxy-timeout");
    let configs = run(&dir, "000", "operator-pat");
    assert!(
        !configs.contains("noproxy ="),
        "a connect failure is not a refusal, so the proxy is respected: {configs}"
    );
}

#[test]
fn the_placeholder_is_still_preferred_on_an_ordinary_host() {
    // The precedence stays as it was, and that is deliberate rather than
    // incidental: on a machine with no intercepting proxy, `GH_TOKEN` IS the
    // operator's credential and must win. The PAT is a FALLBACK tried once the
    // first has been refused, never a replacement for it.
    let dir = scratch("install-first-attempt");
    let configs = run(&dir, "403", "operator-pat");
    let first = configs.split("--- call ---").next().unwrap_or_default();
    assert!(
        first.contains("proxy-placeholder"),
        "the FIRST attempt uses the ordinary order: {first}"
    );
}
