//! The per-turn cross-triple check keeps the properties that make it an alarm
//! rather than a log (CLOUD-1731), over `batten singleton detach` since
//! CLOUD-1991.
//!
//! **Why a test and not a careful author.** Every property below was got wrong
//! once while the row was being written, and each wrong version still *worked*:
//! the failure was written, the marker was cleared, the task exited 0. What
//! differed was only whether a human ever saw it. A regression here is therefore
//! invisible by construction — the handler goes on running, silently, and the
//! first anyone learns of a broken triple is CI, which is the exact failure the
//! row exists to move earlier.
//!
//! **Behaviour now, where it was text.** `[tasks."cross-turn"]` was a shell
//! one-liner, so these cases read its `run` string and asserted it carried
//! `cat $f`, `rm -f $f`, `head -3`, `) &` and the lock call. The body is one argv
//! into the engine now, so the same properties are driven over the compiled
//! binary in a scratch repository: the announcing invocation, and the attached
//! copy it starts, run synchronously here so no case waits on a background
//! process.
//!
//! # RETIREMENT LEDGER — the text cases, per property
//!
//! Each case below names the property it carries; the ledger rows are the
//! `changed:` arms because the SUBJECT moved from a string to a verb.
// changed: "the failure is announced on stdout and not into a log" crates/batten/src/lib.rs kind:verb `the_failure_is_announced_on_stdout_and_then_cleared` asserts the announcement IS the invocation's stdout
// changed: "the marker is cleared once it has been announced" crates/batten/src/lib.rs kind:verb the same case asserts the marker is gone after the announcement
// changed: "the pointers are capped so a build log cannot reach the window" crates/batten/src/lib.rs kind:verb `the_pointers_are_capped_and_name_the_full_log` feeds five pointer lines and asserts three, plus the log's path
// changed: "the pointer pattern survives a coloured log" batten.toml the pattern is the `compiler-error-pointer` `[[pattern]]` row; the capped-pointers case feeds lines carrying colour escapes between `: ` and `error`
// changed: "the check is detached so the handler cannot tax the turn" crates/batten/src/lib.rs kind:verb the announcing invocation hands the command to the placed `exec::detached` adapter, which keeps no handle to wait on, and returns; a case timing the return would be a clock standing in for an exit condition (CLOUD-1177), so the cases here run the attached copy synchronously instead
// changed: "the second copy is refused by the lock rather than a process probe" crates/batten/src/lib.rs kind:verb `a_copy_already_holding_the_lock_leaves_the_run_to_it` holds the lock and asserts the copy runs nothing
// carried: "the cross-check asks the compiler for one line per diagnostic" mise.toml kind:mechanism

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common;

/// One task's `run` value from the committed manifest, whatever its quoting —
/// an array arrives in its TOML spelling.
fn run_body(name: &str) -> String {
    let block = common::task_block(name).unwrap_or_else(|| panic!("`{name}` is declared"));
    common::task_value(&block, "run")
}

/// The compiler does the reduction, rather than a grep guessing at it.
///
/// `--message-format=short` emits one `path:line:col: error: …` per diagnostic.
/// The draft this replaced scraped `-->` spans, which belong to notes and helps
/// as much as to errors — so it could report a note's location as the failure.
///
/// Fails by: dropping the flag, which restores the span art this cannot parse.
#[test]
fn the_cross_check_asks_the_compiler_for_one_line_per_diagnostic() {
    let body = run_body("cross-check");
    assert!(
        body.contains("--message-format=short"),
        "cross-check emits span art, which the per-turn extractor cannot reduce: {body}"
    );
}

/// The handler is the verb, named with the committed pattern row it reads.
#[test]
fn the_turn_handler_detaches_the_cross_check_under_its_lock() {
    let body = run_body("cross-turn");
    assert!(
        body.starts_with("batten singleton detach cross-turn ")
            && body.contains("--pattern compiler-error-pointer")
            && body.ends_with("-- mise run cross-check"),
        "the per-turn check is the detach verb over cross-check: {body}"
    );
    for probe in ["pgrep", "pkill", "ps -", "jobs", "&"] {
        assert!(
            !body.contains(probe),
            "`{probe}` is shell the verb replaced: {body}"
        );
    }
}

// --- the verb, over a scratch repository -------------------------------------

const TASK: &str = "turn-check";

/// A repository declaring the pointer pattern the committed row declares.
fn repo(name: &str) -> PathBuf {
    let dir = common::scratch(&format!("turn-cross-check-{name}"));
    common::write(
        &dir,
        "batten.toml",
        "version = 1\n\n[[pattern]]\nid = \"compiler-error-pointer\"\nregex = '^[^ :]+:[0-9]+:[0-9]+: .*error'\n",
    );
    common::init_repo(&dir);
    dir
}

/// An executable at `dir/name` running `body`.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    common::write(dir, name, body);
    let path = dir.join(name);
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Five pointer lines, two carrying colour escapes, among noise, then a failure.
fn failing(dir: &Path) -> PathBuf {
    script(
        dir,
        "failing.sh",
        "#!/bin/sh\n\
         echo 'Checking batten'\n\
         printf 'src/a.rs:1:1: \\033[31merror\\033[0m: one\\n'\n\
         printf 'src/b.rs:2:1: \\033[31merror\\033[0m: two\\n' >&2\n\
         echo 'src/c.rs:3:1: error: three' >&2\n\
         echo 'src/d.rs:4:1: error: four' >&2\n\
         echo 'src/e.rs:5:1: error: five' >&2\n\
         echo 'note: noise'\n\
         exit 1\n",
    )
}

/// `singleton detach` over `command`, with `extra` flags before the `--`.
fn detach(dir: &Path, extra: &[&str], command: &[&str]) -> Output {
    let mut args = vec![
        "singleton",
        "detach",
        TASK,
        "--marker",
        "marker.txt",
        "--log",
        "run.log",
        "--pattern",
        "compiler-error-pointer",
    ];
    args.extend_from_slice(extra);
    args.push("--");
    args.extend_from_slice(command);
    common::batten()
        .args(&args)
        .current_dir(dir)
        .output()
        .expect("run batten singleton detach")
}

/// One failure is announced once, on STDOUT, then cleared.
///
/// `handler.rs` states the contract a handler is read under: "Exit `0` with
/// stdout: advisory text". stderr goes to a log nobody opens — the first draft
/// `cat`-ed the marker to stderr, which printed the failure, cleared it, and
/// showed it to no one. And a marker never cleared re-announces one failure every
/// turn, which is what keeps the row under `[hook_output] max_repeats = 1`.
#[test]
fn the_failure_is_announced_on_stdout_and_then_cleared() {
    let dir = repo("announce");
    common::write(&dir, "marker.txt", "::error:: turn-check: it broke\n");
    let out = detach(&dir, &[], &["true"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(common::stdout(&out), "::error:: turn-check: it broke\n");
    assert!(
        !dir.join("marker.txt").exists(),
        "an announced failure is cleared, or it is re-announced every turn"
    );
}

/// The window cost of a failing run is bounded, and the rest is findable.
///
/// Pointer-only is non-negotiable rule 4, and here the payload is a compiler's
/// whole output. The pattern must span colour escapes: three drafts died
/// anchoring on a literal `: error`, which the escapes split.
#[test]
fn the_pointers_are_capped_and_name_the_full_log() {
    let dir = repo("capped");
    let command = failing(&dir);
    let out = detach(&dir, &["--attached"], &[command.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    let marker = std::fs::read_to_string(dir.join("marker.txt")).expect("a failure is recorded");
    let pointers: Vec<&str> = marker
        .lines()
        .filter(|line| line.starts_with("  src/"))
        .collect();
    assert_eq!(pointers.len(), 3, "at most three pointers:\n{marker}");
    assert!(
        pointers.iter().any(|line| line.contains("src/a.rs:1:1")),
        "a coloured pointer is still a pointer:\n{marker}"
    );
    assert!(
        marker.contains("(full output: run.log)"),
        "the cap costs the reader nothing, because the log is named:\n{marker}"
    );
    let log = std::fs::read_to_string(dir.join("run.log")).expect("the whole output is kept");
    assert!(log.contains("src/e.rs:5:1") && log.contains("note: noise"));
}

/// A passing run says nothing and gives the lock back.
#[test]
fn a_passing_run_leaves_no_marker_and_releases_the_lock() {
    let dir = repo("passing");
    let out = detach(&dir, &["--attached"], &["true"]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(!dir.join("marker.txt").exists(), "success is silence");
    let pid = std::process::id().to_string();
    let taken = common::run(&dir, &["singleton", "acquire", TASK, &pid]);
    assert_eq!(
        taken.status.code(),
        Some(0),
        "the copy released its lock: {}",
        common::stderr(&taken)
    );
    common::run(&dir, &["singleton", "release", TASK]);
}

/// A second copy is refused by the declared lock, never by a process probe.
///
/// `polls-a-local-process` refuses reading the process table to answer "is one
/// already running", and the singleton lock is the mechanism that answers it.
#[test]
fn a_copy_already_holding_the_lock_leaves_the_run_to_it() {
    let dir = repo("held");
    let pid = std::process::id().to_string();
    let held = common::run(&dir, &["singleton", "acquire", TASK, &pid]);
    assert_eq!(held.status.code(), Some(0), "{}", common::stderr(&held));
    let command = failing(&dir);
    let out = detach(&dir, &["--attached"], &[command.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert!(
        !dir.join("run.log").exists() && !dir.join("marker.txt").exists(),
        "a copy that could not take the lock ran nothing"
    );
    common::run(&dir, &["singleton", "release", TASK]);
}

/// A pattern no row declares is this invocation's usage error, reported before
/// anything starts — never a background copy failing where no one reads it.
#[test]
fn a_pattern_no_row_declares_is_refused_before_anything_starts() {
    let dir = repo("undeclared");
    common::write(&dir, "marker.txt", "::error:: turn-check: kept\n");
    let out = common::batten()
        .args([
            "singleton",
            "detach",
            TASK,
            "--marker",
            "marker.txt",
            "--log",
            "run.log",
            "--pattern",
            "no-such-row",
            "--",
            "true",
        ])
        .current_dir(&dir)
        .output()
        .expect("run batten singleton detach");
    assert_eq!(out.status.code(), Some(1), "{}", common::stderr(&out));
    assert!(
        dir.join("marker.txt").exists(),
        "a refused invocation announces and clears nothing"
    );
}
