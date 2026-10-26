//! The mediated verb's latency gate, on every event it answers (CLOUD-1480).
//!
//! A Stop cost ~110 s while every `perf` arm read a `PreToolUse` or
//! `PostToolUse` payload, so the 100 ms ceiling never saw the event that broke
//! it. Two cases hold that shut, and they need each other: a wall-clock ceiling
//! alone passes on any consumer whose tree happens to be cheap to analyse, which
//! is the false green this row is about, so the second case counts spawns.
//!
//! **The budget case** feeds `perf-assert` the record the `perf` arm writes —
//! the arm's own measurement, never a clock taken here — and asserts a Stop over
//! its ceiling is refused. **The no-spawn case** runs the mediated verb on each
//! event against a tree that declares a `Cost::Effect` fact, with the analyser
//! replaced by a shim that records its parent, and asserts the verb itself
//! spawned it on none of them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use crate::perf_assert;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;

/// A Stop measured over its ceiling is refused, inside an otherwise clean
/// record.
///
/// Fails by: the `stop` path dropped from `perf-assert`'s budgets, which leaves
/// the arm measured and never gated — the shape the 100 ms ceiling had for
/// every Stop before this row.
#[test]
fn a_stop_over_its_budget_is_refused() {
    let dir = perf_assert::repo("stop-over", Some(&perf_assert::agreeing_readme()));
    let record = perf_assert::clean_record().replace("stop 2.6", "stop 150");
    assert_ne!(
        record,
        perf_assert::clean_record(),
        "the clean record carries the stop arm this case overrides"
    );
    perf_assert::record(&dir, &record);
    let answer = perf_assert::findings(&dir);
    assert!(
        answer.contains("path measure late"),
        "a Stop over its ceiling is a finding:\n{answer}"
    );
}

/// The committed module the fixture's `symbols` row evaluates. Any tree module
/// serves: the row exists to DECLARE the fact, and what decides is whether
/// resolving it spawns.
#[cfg(unix)]
const MODULE: &str = "policy/docs-tree-absent.rego";

#[cfg(unix)]
const CONFIG: &str = r#"version = 1

[[rule]]
id = "prose place refused"
kind = "policy"
scope = "tree"
index = ["docs"]
symbols = true
module = "policy/docs-tree-absent.rego"
severity = "deny"
reason = "research belongs on the tracker row."

[[verdict]]
id = "prose place refused"
gloss = "a path under docs/ is tracked"
class = """
Move it onto the tracker row.
"""

[[verdict.route]]
id = "module read first"
kind = "document"
target = "policy/docs-tree-absent.rego"
"#;

/// A committed repository declaring the `symbols` fact, a shim directory whose
/// `cargo` appends its parent's pid to `spawns.log`, and a state home.
///
/// The fixture declares no toolchain pin, so the analyser is the bare `cargo`
/// on `PATH` (`rules::symbols_launcher`) — which is the shim. Unix only: the
/// shim is a shell script.
#[cfg(unix)]
fn fixture(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = common::scratch(name);
    let repo = root.join("repo");
    fs::create_dir_all(repo.join("policy")).expect("policy dir");
    fs::write(repo.join("batten.toml"), CONFIG).expect("write config");
    fs::copy(common::at_root(MODULE), repo.join(MODULE)).expect("install committed module");
    common::write(&repo, "src/a.rs", "fn main() {}\n");
    common::git_in(&repo, &["init", "-q", "-b", "main", "."]);
    common::git_in(&repo, &["config", "user.name", "Fixture Author"]);
    common::git_in(&repo, &["config", "user.email", "fixture@example.com"]);
    common::git_in(&repo, &["add", "-A"]);
    common::git_in(&repo, &["commit", "-q", "-m", "chore: base"]);
    let shims = root.join("shims");
    fs::create_dir_all(&shims).expect("shim dir");
    let log = root.join("spawns.log");
    let cargo = shims.join("cargo");
    fs::write(
        &cargo,
        format!("#!/bin/sh\necho \"$PPID\" >> '{}'\nexit 1\n", log.display()),
    )
    .expect("write shim");
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).expect("shim mode");
    }
    let home = root.join("home");
    fs::create_dir_all(&home).expect("home dir");
    (repo, shims, home)
}

/// `args` run in `repo` with the shims first on `PATH`, `payload` on stdin;
/// returns the pid it ran as.
#[cfg(unix)]
fn run(repo: &Path, shims: &Path, home: &Path, args: &[&str], payload: &str) -> u32 {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![shims.to_path_buf()];
    dirs.extend(std::env::split_paths(&path));
    let mut command = common::batten();
    common::state_home(&mut command, home);
    command
        .current_dir(repo)
        .args(args)
        .env("PATH", std::env::join_paths(dirs).expect("a joinable PATH"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn batten");
    let pid = child.id();
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    child.wait().expect("run batten");
    pid
}

/// `batten state record` in `repo` as a detached drain runs it, or as the verb
/// when `drain` is false; returns the pid it ran as.
#[cfg(unix)]
fn record(repo: &Path, shims: &Path, home: &Path, drain: bool) -> u32 {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = vec![shims.to_path_buf()];
    dirs.extend(std::env::split_paths(&path));
    let mut command = common::batten();
    common::state_home(&mut command, home);
    command
        .current_dir(repo)
        .args(["state", "record"])
        .env("PATH", std::env::join_paths(dirs).expect("a joinable PATH"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if drain {
        command.env("BATTEN_STATE_DRAIN", "1");
    } else {
        command.env_remove("BATTEN_STATE_DRAIN");
    }
    let mut child = command.spawn().expect("spawn batten state record");
    let pid = child.id();
    child.wait().expect("run batten state record");
    pid
}

/// A drain that finds another drain scanning exits without resolving the
/// analyser fact, while the verb under the same lock and a drain with the lock
/// free both resolve it.
///
/// Fails by: drains scanning concurrently, which is how three ends of turn
/// left three workspace compiler runs holding the build lock (CLOUD-2536).
#[cfg(unix)]
#[test]
fn a_drain_finding_another_scanning_does_not_scan() {
    let (repo, shims, home) = fixture("hook-latency-drain");
    let held = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(repo.join(".git/batten-state-scan.lock"))
        .expect("open the scan lock");
    held.try_lock().expect("take the scan lock");
    let drain = record(&repo, &shims, &home, true);
    assert!(
        !spawners(&repo).contains(&drain),
        "a drain scanned while another drain held the scan lock"
    );
    let verb = record(&repo, &shims, &home, false);
    assert!(
        spawners(&repo).contains(&verb),
        "the verb a human ran waits for no drain and scans"
    );
    held.unlock().expect("release the scan lock");
    let free = record(&repo, &shims, &home, true);
    assert!(
        spawners(&repo).contains(&free),
        "the control: a drain with the lock free resolves the fact"
    );
}

/// The parent pids the shim recorded.
#[cfg(unix)]
fn spawners(repo: &Path) -> Vec<u32> {
    let log = repo.parent().expect("fixture root").join("spawns.log");
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// The mediated verb spawns the analyser on no event, while `check` over the
/// same tree does — so the shim is reachable and its silence is a measurement.
///
/// Fails by: the surface gate on the two `Cost::Effect` facts removed, which
/// put a compiler run inside every mediated call (23 execve where 1 belongs).
#[cfg(unix)]
#[test]
fn the_mediated_verb_spawns_nothing_on_any_event() {
    let (repo, shims, home) = fixture("hook-latency-spawn");
    let hooks = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks");
    for event in [
        "claude-code.json",
        "claude-code-posttool.json",
        "claude-code-stop.json",
    ] {
        let payload = fs::read_to_string(hooks.join(event)).expect("read payload");
        let pid = run(
            &repo,
            &shims,
            &home,
            &["adjudicate", "--harness", "claude-code"],
            &payload,
        );
        assert!(
            !spawners(&repo).contains(&pid),
            "the mediated verb spawned the analyser on {event}"
        );
    }
    let pid = run(&repo, &shims, &home, &["check"], "");
    assert!(
        spawners(&repo).contains(&pid),
        "the control: `check` resolves the declared fact through the shim, so \
         the mediated verb's silence above is not an unreachable shim"
    );
}
