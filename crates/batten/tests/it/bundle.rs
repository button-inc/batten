//! CLOUD-430: `:::` bundles, and reading a capture that is still being written.
//!
//! Unix-only per CLOUD-113: the live-capture cases signal a pid with `kill(1)`,
//! and two of them reach for `flock(1)` to be a genuinely independent reader.
//! Every child is a real program or the test stand-in, never authored shell
//! (CLOUD-2336).
//!
//! The concurrency cases use **real second processes**, never two threads, and
//! that is the acceptance clause rather than a preference: the property is about
//! parallel `batten` invocations, and a thread-based test would pass against an
//! in-process lock that cannot survive a `SIGKILL`ed writer — which is the exact
//! case the `fs4` decision was made for.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: `exec --jobs` is a bundle of real children, so this suite's subject is a process tree and its fixtures are processes"
)]
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{StateHome as _, scratch};

/// How long a case waits for a condition before giving up.
const PATIENCE: Duration = Duration::from_secs(20);

/// The test stand-in, installed as a fixture child that runs `steps`.
fn stand_in(name: &str, steps: &serde_json::Value) -> PathBuf {
    let path = scratch(name).join("child");
    common::stub_at(&path, &serde_json::json!([{ "steps": steps }]));
    path
}

/// A fixture child that exits `code` and says nothing.
fn exits(name: &str, code: i32) -> String {
    stand_in(name, &serde_json::json!([{ "exit": code }]))
        .to_str()
        .expect("utf-8")
        .to_owned()
}

/// Run `batten exec` with the capture store isolated under a scratch home.
fn exec(name: &str, args: &[&str]) -> (Output, PathBuf) {
    let home = scratch(name);
    fs::create_dir_all(&home).expect("create home");
    let output = common::batten()
        .args(args)
        .state_home(&home)
        .output()
        .expect("run batten exec");
    (output, home)
}

/// Everything `batten` said on stderr — the record's channel.
fn said(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every file under a scratch home's capture store, sorted.
fn captures_in(home: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![home.join("data")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                found.push(name.to_owned());
            }
        }
    }
    found.sort();
    found
}

// --- bundling -----------------------------------------------------------------

#[test]
fn a_bundle_runs_every_command_and_addresses_each_one() {
    // The token argument for bundling at all: N commands cost one tool call, and
    // each one is still separately addressable afterwards — a bundle's Nth
    // capture must be reachable without re-running the bundle.
    let (output, home) = exec(
        "bundle-two",
        &[
            "exec", "--", "printf", "%s\n", "first", ":::", "printf", "%s\n", "second",
        ],
    );
    assert!(output.status.success(), "{}", said(&output));
    let record = said(&output);
    assert!(record.contains("exec: [0] exit 0"), "{record}");
    assert!(record.contains("exec: [1] exit 0"), "{record}");
    assert!(record.contains("exec: exit 0"), "{record}");

    // Two commands, two streams each, and the two empty stderrs share one
    // content-addressed record — so three files, not four.
    let stored = captures_in(&home);
    let stdouts = stored
        .iter()
        .filter(|name| name.starts_with("stdout-"))
        .count();
    assert_eq!(
        stdouts, 2,
        "each command's stdout is its own record: {stored:?}"
    );
    assert!(
        stored.iter().any(|name| name.starts_with("stderr-")),
        "and the silent stderrs are still stored: {stored:?}"
    );
}

#[test]
fn a_single_command_renders_exactly_as_it_did_before_bundling() {
    // Byte-stability, and the reason the index is conditional: every reader and
    // every receipt keyed to these lines predates bundling.
    let (output, _) = exec("bundle-single", &["exec", "--", "printf", "%s\n", "alone"]);
    let record = said(&output);
    assert!(
        !record.contains("[0]"),
        "a bare command carries no index: {record}"
    );
    assert!(record.starts_with("exec: stdout "), "{record}");
    assert!(record.contains("exec: exit 0"), "{record}");
}

#[test]
fn a_bundle_reports_the_first_failure_never_the_last_child() {
    // The §5 clause, spelled out: a bundle where command 2 of 3 failed must not
    // report command 3's zero. Reading the FIRST failure rather than the last
    // also keeps the answer a property of the bundle rather than of the
    // scheduler, which `--jobs` would otherwise make non-deterministic.
    let three = exits("bundle-first-failure-child", 3);
    let (output, _) = exec(
        "bundle-first-failure",
        &[
            "exec",
            "--continue-on-error",
            "--",
            "true",
            ":::",
            &three,
            ":::",
            "true",
        ],
    );
    assert_eq!(output.status.code(), Some(3), "{}", said(&output));
    let record = said(&output);
    assert!(record.contains("exec: [1] exit 3"), "{record}");
    assert!(record.contains("exec: exit 3"), "{record}");
}

#[test]
fn a_bundle_stops_at_the_first_failure_unless_told_to_continue() {
    // mise's `--continue-on-error`, with mise's meaning. The marker file is what
    // makes "did not run" observable — a record that merely omitted the command
    // could be omitting it for any reason.
    let marker = scratch("bundle-stop").join("third-ran");
    let args: Vec<String> = vec![
        "exec".into(),
        "--".into(),
        exits("bundle-stop-child", 4),
        ":::".into(),
        "touch".into(),
        marker.to_str().expect("utf-8").to_owned(),
    ];
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let (output, _) = exec("bundle-stop-home", &borrowed);
    assert_eq!(output.status.code(), Some(4));
    assert!(!marker.exists(), "the second command must not have run");
    let record = said(&output);
    assert!(
        record.contains("exec: 1 of 2 command(s) ran"),
        "a bundle that stopped early must say so: {record}"
    );

    let mut with_flag = borrowed.clone();
    with_flag.insert(1, "--continue-on-error");
    let (output, _) = exec("bundle-continue-home", &with_flag);
    assert_eq!(
        output.status.code(),
        Some(4),
        "the code is still the failure's"
    );
    assert!(marker.exists(), "with the flag, the second command runs");
}

#[test]
fn bundling_does_not_change_a_captures_identity() {
    // The clause that protects every receipt keyed to a handle: the sealed record
    // for a bundled command is byte-identical to what the same command run alone
    // would have stored. Asserted on the DIGEST, which is the identity.
    let (alone, _) = exec(
        "bundle-identity-alone",
        &["exec", "--", "printf", "%s\n", "same"],
    );
    let (bundled, _) = exec(
        "bundle-identity-bundled",
        &[
            "exec", "--", "printf", "%s\n", "other", ":::", "printf", "%s\n", "same",
        ],
    );
    let digest = |text: &str, want: &str| -> String {
        text.lines()
            .find(|line| line.contains(want) && line.contains("stdout:"))
            .and_then(|line| line.split("stdout:").nth(1))
            .map_or_else(|| panic!("no stdout handle in {text}"), str::to_owned)
    };
    assert_eq!(
        digest(&said(&alone), "exec: stdout"),
        digest(&said(&bundled), "exec: [1] stdout"),
        "bundling must not change what a capture is called"
    );
}

#[test]
fn an_empty_segment_is_a_usage_error_rather_than_a_silent_narrowing() {
    // `a ::: ::: b` is a typo. Running two commands where three were written is
    // exactly the quiet narrowing a gate must never do.
    let (output, _) = exec(
        "bundle-empty-segment",
        &["exec", "--", "true", ":::", ":::", "true"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(said(&output).contains("is empty"), "{}", said(&output));
}

#[test]
fn a_bad_jobs_value_names_what_was_wrong_with_it() {
    // Parsed by Batten rather than by clap so the refusal can say so. Zero is a
    // width nobody can mean, and reading it as one would answer a question the
    // caller did not ask.
    for value in ["0", "many"] {
        let (output, _) = exec(
            &format!("bundle-jobs-{value}"),
            &["exec", "--jobs", value, "--", "true"],
        );
        assert_eq!(output.status.code(), Some(1), "--jobs {value} must refuse");
        assert!(said(&output).contains("--jobs"), "{}", said(&output));
    }
}

#[test]
fn the_record_is_in_declaration_order_whatever_order_they_finish_in() {
    // What `--jobs` would otherwise cost: with two children in flight the order
    // things FINISH in is a property of the machine, and Batten's output has to
    // be a property of the bundle. Command 0 sleeps so it reliably finishes last.
    let slow = stand_in(
        "bundle-jobs-order-child",
        &serde_json::json!([{ "sleep": 1000 }, { "stdout": "slow\n" }]),
    );
    let (output, _) = exec(
        "bundle-jobs-order",
        &[
            "exec",
            "--jobs",
            "2",
            "--",
            slow.to_str().expect("utf-8"),
            ":::",
            "printf",
            "%s\n",
            "fast",
        ],
    );
    assert!(output.status.success(), "{}", said(&output));
    let record = said(&output);
    let zero = record.find("[0]").expect("command 0 is recorded");
    let one = record.find("[1]").expect("command 1 is recorded");
    assert!(
        zero < one,
        "declaration order, not completion order: {record}"
    );
}

// --- the live capture ----------------------------------------------------------

/// Whether `flock(1)` is installed, so a shell can be a real reader.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: probing for `flock(1)` is asking the host a question about itself, which has no in-process form"
)]
fn has_flock() -> bool {
    Command::new("flock")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Copy a spool's watermark and data into `snapshot` while holding its lock
/// (`flock -s` shared, `flock -n` without waiting), then answer the lock's exit
/// status and the committed bytes from `from` up to the watermark — what the
/// `dd`/`head -c` a shell once ran under the lock printed.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the reader is a REAL second process holding the same OS advisory lock Batten takes"
)]
fn snapshot_under_lock(
    mode: &str,
    lock: &Path,
    watermark: &Path,
    data: &Path,
    snapshot: &Path,
    from: u64,
) -> (bool, String) {
    fs::create_dir_all(snapshot).expect("create the snapshot directory");
    let status = Command::new("flock")
        .arg(mode)
        .arg(lock)
        .arg("cp")
        .arg(watermark)
        .arg(data)
        .arg(snapshot)
        .stdin(Stdio::null())
        .status()
        .expect("read the spool");
    let name = |path: &Path| snapshot.join(path.file_name().expect("a file name"));
    let committed: u64 = fs::read_to_string(name(watermark))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0);
    let bytes = fs::read(name(data)).unwrap_or_default();
    let end = usize::try_from(committed)
        .expect("a length fits")
        .min(bytes.len());
    let start = usize::try_from(from).expect("an offset fits");
    let seen = bytes.get(start..end).unwrap_or_default();
    (status.success(), String::from_utf8_lossy(seen).into_owned())
}

/// The live spool's three paths for one stream of one command.
fn spool_paths(home: &Path, stream: &str, pid: u32, index: usize) -> (PathBuf, PathBuf, PathBuf) {
    let dir = home.join("data").join("batten");
    // The repo-name segment is derived at runtime, so the directory is found
    // rather than spelled: one `live` directory exists under the scratch home.
    let mut live = None;
    let mut stack = vec![dir];
    while let Some(next) = stack.pop() {
        let Ok(entries) = fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some("live") {
                    live = Some(path.clone());
                }
                stack.push(path);
            }
        }
    }
    let live = live.expect("the live capture directory exists while a command runs");
    // `<pid>.<dispatch>.<index>`, and the dispatch is always `0` through the
    // CLI — one `exec` per process. Derived here rather than read out of Batten's
    // output, because printing it would break §6 byte-stability.
    let handle = format!("{stream}@{pid}.0.{index}");
    (
        live.join(&handle),
        live.join(format!("{handle}.watermark")),
        live.join(format!("{handle}.lock")),
    )
}

/// Read the committed span of a live spool from `from`, through a **real second
/// process** holding the same OS advisory lock Batten takes.
///
/// A free function rather than the closure it used to be, because the closure's
/// body sat inside the case and put it over `too_many_lines` the moment its poll
/// grew a delay verdict (CLOUD-1177). The extraction changes nothing about what
/// is asserted: the second process is the whole point, since an in-process
/// reader would say nothing about a lock the kernel releases when its holder
/// dies.
fn read_spool(lock: &Path, watermark: &Path, data: &Path, snapshot: &Path, from: u64) -> String {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let (_, seen) = snapshot_under_lock("-s", lock, watermark, data, snapshot, from);
        if !seen.is_empty() || Instant::now() >= deadline {
            return seen;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll whose exit condition is the `flock`ed reader \
                      returning bytes, bounded by `PATIENCE` — the `deadline` comparison one line \
                      up is what ends it either way (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Block until `path` exists, or fail.
fn await_path(path: &Path) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll whose exit condition is `path.exists`, bounded by \
                      `PATIENCE` — past that this panics rather than waiting longer (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} never appeared", path.display());
}

/// Poll `probe` until it answers, bounded by [`PATIENCE`], or `None` once the
/// patience is spent — so the CALLER asserts on the state it found, and no
/// assertion reads the clock (CLOUD-2059).
fn poll_until<T>(mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if let Some(found) = probe() {
            return Some(found);
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll whose exit condition is the caller's probe answering, \
                      bounded by `PATIENCE` — past that this answers `None` (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// A child that says `line`, records its own pid, and then holds its capture
/// live — for far longer than any case waits, so the live window is the case's
/// to close rather than a race against a short `sleep` (CLOUD-2059). Returns the
/// child and the note its pid lands in.
fn live_child(name: &str, line: &str) -> (PathBuf, PathBuf) {
    let note = scratch(&format!("{name}-pid")).join("pid");
    fs::create_dir_all(note.parent().expect("a parent")).expect("create the note's directory");
    let child = stand_in(
        name,
        &serde_json::json!([
            { "stdout": format!("{line}\n") },
            { "write": [note.to_str().expect("utf-8"), "{pid}"] },
            { "sleep": 300_000 },
        ]),
    );
    (child, note)
}

/// End the child [`live_child`] recorded, so the `sleep` it became does not
/// outlive the case that killed its writer.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the live child is a real process the case left running, and ending it is a signal to its pid"
)]
fn end_live_child(note: &Path) {
    if let Ok(pid) = fs::read_to_string(note) {
        let _ = Command::new("kill").args(["-KILL", pid.trim()]).status();
    }
}

#[test]
fn a_second_process_reads_a_live_capture_and_never_passes_the_watermark() {
    // `flock(1)` is util-linux: on every Linux leg and on no macOS one. So the
    // platform is a `cfg!` arm, and a Linux host without it FAILS rather than
    // passing over a reader it never ran (CLOUD-2059).
    if !cfg!(target_os = "linux") {
        return;
    }
    assert!(
        has_flock(),
        "`flock(1)` is util-linux, installed on every Linux leg"
    );
    let home = scratch("live-read-home");
    fs::create_dir_all(&home).expect("create home");
    // Speaks, then holds the stream open. The capture is live for as long as the
    // case keeps the child alive, which is the window this case reads in.
    let (child, child_pid) = live_child("live-read-child", "committed");
    let mut batten = common::batten()
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .state_home(&home)
        .spawn()
        .expect("spawn batten exec");

    let pid = batten.id();
    // The live handle is derived from the pid and the command's index, both of
    // which this test knows because it spawned the process — printing it would
    // put a pid in Batten's output and break §6 byte-stability.
    let (data, watermark, lock) = poll_until(|| {
        std::panic::catch_unwind(|| spool_paths(&home, "stdout", pid, 0))
            .ok()
            .filter(|paths| paths.0.exists())
    })
    .expect("the spool never appeared");
    await_path(&watermark);

    // A REAL SECOND PROCESS, holding the same OS advisory lock Batten takes.
    let snapshot = scratch("live-read-snapshot");
    let read = |from: u64| read_spool(&lock, &watermark, &data, &snapshot, from);

    let first = read(0);
    assert_eq!(
        first, "committed\n",
        "a reader sees what has been committed and no more"
    );
    // IDEMPOTENT: the same range re-read is the same bytes. That is the whole
    // point — "more context" must not mean parsing a stream or holding a
    // redirect.
    assert_eq!(read(0), first, "the same range must re-read identically");

    let committed: u64 = fs::read_to_string(&watermark)
        .expect("read the watermark")
        .trim()
        .parse()
        .expect("the watermark is a length");
    assert_eq!(
        committed,
        first.len() as u64,
        "the watermark names exactly what a reader may see"
    );
    let on_disk = fs::metadata(&data).expect("stat the spool").len();
    assert!(
        on_disk >= committed,
        "the spool may run ahead of the watermark, never behind: {on_disk} < {committed}"
    );

    // Killed rather than waited on: this case is about the live window.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the live-window case needs the writer killed rather than reaped, which is a signal to a pid"
    )]
    drop(
        Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status(),
    );
    let _ = batten.wait();
    end_live_child(&child_pid);
}

#[test]
fn a_killed_writer_leaves_a_reader_a_defined_answer_rather_than_a_hang() {
    // The clause the `fs4` decision was made for: what a reader sees when the
    // writer was `SIGKILL`ed. The answer must be a defined prefix and a takeable
    // lock, never a hang — an OS advisory lock is released by the kernel when its
    // holder dies, where an in-process `RwLock` would simply have vanished with
    // its holder and left nothing releasable.
    //
    // Scope, stated rather than implied: the writer holds the lock only across a
    // watermark publish, so this does not manufacture a death mid-publish. What
    // it asserts is the property that matters to a reader — after an uncatchable
    // kill, the lock is free and the watermark still names exactly how much of
    // the spool is real.
    // `flock(1)` is util-linux: on every Linux leg and on no macOS one. So the
    // platform is a `cfg!` arm, and a Linux host without it FAILS rather than
    // passing over a reader it never ran (CLOUD-2059).
    if !cfg!(target_os = "linux") {
        return;
    }
    assert!(
        has_flock(),
        "`flock(1)` is util-linux, installed on every Linux leg"
    );
    let home = scratch("live-killed-home");
    fs::create_dir_all(&home).expect("create home");
    let (child, child_pid) = live_child("live-killed-child", "durable");
    let mut batten = common::batten()
        .args(["exec", "--", child.to_str().expect("utf-8")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .state_home(&home)
        .spawn()
        .expect("spawn batten exec");
    let pid = batten.id();

    let (data, watermark, lock) = poll_until(|| {
        std::panic::catch_unwind(|| spool_paths(&home, "stdout", pid, 0))
            .ok()
            .filter(|paths| fs::read_to_string(&paths.1).is_ok_and(|text| text.trim() != "0"))
    })
    .expect("the spool never committed anything");

    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: auto-release on death is the property under test, so the holder has to actually die"
    )]
    let killed = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .expect("kill batten");
    assert!(killed.success());
    let _ = batten.wait();
    end_live_child(&child_pid);

    // The lock is takeable — immediately, and without `-w`, which is what makes
    // this an assertion about auto-release rather than about patience.
    // Taking the lock from outside the process is what makes this an assertion
    // about auto-release rather than about patience.
    let (taken, prefix) = snapshot_under_lock(
        "-n",
        &lock,
        &watermark,
        &data,
        &scratch("live-killed-snapshot"),
        0,
    );
    assert!(taken, "a dead writer's advisory lock must not outlive it");
    assert_eq!(
        prefix, "durable\n",
        "and the watermark still names a defined prefix"
    );
}

#[test]
fn two_concurrent_batten_processes_store_the_same_record_without_tearing() {
    // CLOUD-412's re-check, with real second processes. `capture::store` was a
    // `File::create` + `write_all`, which is two observable states — and the
    // first of them is an EMPTY file under a digest that promises bytes. Two
    // `batten` runs writing the same content-addressed record at the same moment
    // is exactly the window; temp-and-rename closes it, because `rename` within a
    // directory is atomic and the only states a reader can see are absent and
    // complete.
    let home = scratch("live-concurrent-home");
    fs::create_dir_all(&home).expect("create home");
    let mut running = Vec::new();
    for _ in 0..6 {
        running.push(
            common::batten()
                .args(["exec", "--", "printf", "%s\n", "identical"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .state_home(&home)
                .spawn()
                .expect("spawn batten exec"),
        );
    }
    for mut one in running {
        assert!(
            one.wait().expect("batten exits").success(),
            "a concurrent run must not fail"
        );
    }

    let stored = captures_in(&home);
    assert!(
        stored
            .iter()
            .all(|name| Path::new(name).extension() != Some("tmp".as_ref())),
        "no staging file may survive: {stored:?}"
    );
    let stdouts: Vec<&String> = stored
        .iter()
        .filter(|name| name.starts_with("stdout-"))
        .collect();
    assert_eq!(
        stdouts.len(),
        1,
        "identical output is one content-addressed record: {stored:?}"
    );
}
