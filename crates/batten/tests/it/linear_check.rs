//! `[tasks."linear-check"]` — is HEAD linear on the current `origin/main`?
//! Over the task's own body (CLOUD-1717).
//!
//! Two halves, as the retired suite had them. A stub `git` makes the fetch fail
//! on demand, which is the only way to reach the fail-closed arm without
//! unplugging a network; and real repositories in the shapes CI produces —
//! single-branch and shallow single-branch clones — prove the refspec fetch
//! resolves `origin/main` where a naive one exits 0 and resolves nothing. The
//! receipt writer is a stub recording its calls, so "no receipt" is "never
//! invoked".
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/linear-check.sh mise.toml kind:mechanism crates/batten/tests/it/linear_check.rs
// carried: tests/linear-check.bats mise.toml kind:mechanism crates/batten/tests/it/linear_check.rs
// carried: "a failed fetch exits 1 instead of trusting the stale ref" mise.toml kind:mechanism
// carried: "a failed fetch writes no receipt" mise.toml kind:mechanism
// carried: "a successful fetch on a linear HEAD passes and records the receipt" mise.toml kind:mechanism
// carried: "a HEAD behind main is exit 2 — the input moved, not a broken branch" mise.toml kind:mechanism
// carried: "a failed receipt write fails the gate — set -e is what carries it" mise.toml kind:mechanism
// carried: "the naive fetch exits 0 while resolving nothing in a single-branch clone" mise.toml kind:mechanism
// carried: "the gate resolves main in a single-branch clone" mise.toml kind:mechanism
// carried: "the gate resolves main in a shallow single-branch clone" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    common::write(dir, name, body);
    let path = dir.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&path).expect("stat").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }
    path
}

/// A receipt writer that records each call to `calls`, or fails when `fails`.
fn writer(dir: &Path, fails: bool) -> PathBuf {
    let calls = dir.join("batten-calls");
    let body = if fails {
        "#!/usr/bin/env bash\nexit 1\n".to_owned()
    } else {
        format!("#!/usr/bin/env bash\necho \"$@\" >>'{}'\n", calls.display())
    };
    executable(dir, "batten-stub", &body)
}

/// A `bin/git` whose fetch exits `fetch`, `origin/main` is `main` and the merge
/// base is `base`: a fetch failure or a moved main is the only variable.
fn stub_git(dir: &Path, fetch: i32, main: &str, base: &str) {
    executable(
        dir,
        "bin/git",
        &format!(
            "#!/usr/bin/env bash\ncase \"$1\" in\n  fetch) exit {fetch} ;;\n  rev-parse)\n    case \"$2\" in\n      origin/main) echo {main} ;;\n      HEAD) echo headsha ;;\n    esac ;;\n  merge-base) echo {base} ;;\nesac\n"
        ),
    );
}

fn gate(dir: &Path, writer: &Path) -> Output {
    let mut command = common::task_bash(dir, &common::task_body("linear-check"));
    command
        .env("BATTEN_BIN", writer)
        .stdin(Stdio::null())
        .output()
        .expect("run the task body")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_failed_fetch_exits_1_and_writes_no_receipt() {
    let dir = common::scratch("linear-check-fetch-fails");
    stub_git(&dir, 1, "aaaa111", "aaaa111");
    let out = gate(&dir, &writer(&dir, false));
    // Exit 1, not 2: a caller laps on "behind" and must never lap on "offline".
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(
        said(&out).contains("could not fetch origin/main"),
        "{}",
        said(&out)
    );
    assert!(!dir.join("batten-calls").exists(), "a receipt was minted");
}

#[test]
fn a_linear_head_passes_and_records_the_receipt() {
    let dir = common::scratch("linear-check-linear");
    stub_git(&dir, 0, "aaaa111", "aaaa111");
    let out = gate(&dir, &writer(&dir, false));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        said(&out).contains("linear on origin/main"),
        "{}",
        said(&out)
    );
    let calls = std::fs::read_to_string(dir.join("batten-calls")).expect("the receipt call");
    assert!(calls.contains("receipt record linear-check"), "{calls}");
}

#[test]
fn a_head_behind_main_is_exit_2_and_writes_no_receipt() {
    let dir = common::scratch("linear-check-behind");
    stub_git(&dir, 0, "aaaa111", "bbbb222");
    let out = gate(&dir, &writer(&dir, false));
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    assert!(
        said(&out).contains("not rebased on latest main"),
        "{}",
        said(&out)
    );
    assert!(!dir.join("batten-calls").exists(), "a receipt was minted");
}

#[test]
fn a_failed_receipt_write_fails_the_gate() {
    let dir = common::scratch("linear-check-writer-fails");
    stub_git(&dir, 0, "aaaa111", "aaaa111");
    let out = gate(&dir, &writer(&dir, true));
    assert_ne!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        !said(&out).contains("linear on origin/main"),
        "{}",
        said(&out)
    );
}

/// An origin with `main` and a `feature` one commit ahead of it.
fn origin(dir: &Path) -> PathBuf {
    let origin = dir.join("origin");
    let seed = dir.join("seed");
    let git = |at: &Path, args: &[&str]| {
        let out = common::program("git")
            .args(args)
            .current_dir(at)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}: {}", said(&out));
    };
    std::fs::create_dir_all(&origin).expect("origin dir");
    std::fs::create_dir_all(&seed).expect("seed dir");
    // Both from the shared template rather than a spawned `git init`. The
    // origin takes pushes to its unborn default branch as a bare one would.
    common::init_repo(&origin);
    git(&origin, &["config", "receive.denyCurrentBranch", "ignore"]);
    common::init_repo(&seed);
    git(&seed, &["config", "user.email", "t@example.com"]);
    git(&seed, &["config", "user.name", "t"]);
    git(&seed, &["config", "commit.gpgsign", "false"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "one"]);
    git(&seed, &["branch", "-M", "main"]);
    let url = format!("file://{}", origin.display());
    git(&seed, &["push", "-q", &url, "main"]);
    git(&seed, &["checkout", "-q", "-b", "feature"]);
    git(&seed, &["commit", "-q", "--allow-empty", "-m", "work"]);
    git(&seed, &["push", "-q", &url, "feature"]);
    origin
}

fn clone(dir: &Path, origin: &Path, name: &str, shallow: bool) -> PathBuf {
    let into = dir.join(name);
    let url = format!("file://{}", origin.display());
    let mut args = vec!["clone", "-q", "--branch", "feature", "--single-branch"];
    if shallow {
        args.extend(["--depth", "1"]);
    }
    let into_str = into.display().to_string();
    args.extend([url.as_str(), into_str.as_str()]);
    let out = common::program("git")
        .args(&args)
        .output()
        .expect("git clone");
    assert!(out.status.success(), "clone: {}", said(&out));
    into
}

/// The trap the explicit refspec exists for, stated as a property of git.
#[test]
fn the_naive_fetch_exits_0_while_resolving_nothing_in_a_single_branch_clone() {
    let dir = common::scratch("linear-check-naive");
    let origin = origin(&dir);
    let clone = clone(&dir, &origin, "naive", false);
    let fetch = common::program("git")
        .args(["fetch", "-q", "origin", "main"])
        .current_dir(&clone)
        .output()
        .expect("git fetch");
    assert!(fetch.status.success(), "{}", said(&fetch));
    let resolved = common::program("git")
        .args(["rev-parse", "origin/main"])
        .current_dir(&clone)
        .output()
        .expect("git rev-parse");
    assert!(
        !resolved.status.success(),
        "the naive fetch wrote origin/main"
    );
}

#[test]
fn the_gate_resolves_main_in_single_branch_and_shallow_clones() {
    let dir = common::scratch("linear-check-clones");
    let origin = origin(&dir);
    for (name, shallow) in [("single", false), ("shallow", true)] {
        let clone = clone(&dir, &origin, name, shallow);
        let out = gate(&clone, &writer(&dir, false));
        assert_eq!(out.status.code(), Some(0), "{name}: {}", said(&out));
        assert!(
            said(&out).contains("linear on origin/main"),
            "{name}: {}",
            said(&out)
        );
    }
}
