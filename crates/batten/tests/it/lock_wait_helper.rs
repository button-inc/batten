//! The off-Linux lock wait, driven on Linux through the real binary
//! (CLOUD-2789).
//!
//! Off Linux `lock_wait` waits through a helper process: `batten __lock-wait
//! <mode> <path>` blocks on the lock and exits once it holds it, and the waiter
//! ends it by closing its stdin. That path is the production wait on macOS and
//! Windows, so it is proven HERE, where every case can watch the helper by pid:
//! each case waits on an event (the helper parking, a holder's line), never a
//! clock, and asserts the helper is gone when the wait returns.
//!
//! `/proc` is how a case sees a pid, so off Linux each case returns at once;
//! `cfg!` rather than `#[cfg]` keeps every case compiled on every target.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs::File;
use std::path::{Path, PathBuf};

use batten::lock_wait::{Mode, Stop, wait_with_helper};

/// The helper spawner, run as the real batten binary: `exec`'s placed spawn,
/// the one the binary itself installs.
fn helper(path: &Path, mode: Mode) -> std::io::Result<std::process::Child> {
    batten::exec::spawn_lock_helper_as(Path::new(env!("CARGO_BIN_EXE_batten")), path, mode)
}

/// A fresh lock file under a case's own scratch directory, and a handle on it.
fn lock_file(name: &str) -> (PathBuf, File) {
    let dir = common::scratch(name);
    let path = dir.join("lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .expect("create the lock file");
    (path, file)
}

/// A second handle on `path`: a second lock, as another process's would be.
fn reopen(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("reopen the lock file")
}

/// Whether `pid` is still a process (a zombie included) on this machine.
fn exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Fails by: a holder's release never ending the helper's wait, or the waiter
/// not taking the lock once its helper exits holding it.
#[test]
fn a_release_by_the_holder_ends_the_helper_and_hands_over_the_lock() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (path, file) = lock_file("lock-helper-release");
    let mut holder = Some(reopen(&path));
    holder
        .as_ref()
        .unwrap()
        .try_lock()
        .expect("free in a fresh fixture");
    let mut helpers = Vec::new();
    let taken = wait_with_helper(&file, &path, Mode::Exclusive, None, &helper, &mut |pid| {
        helpers.push(pid);
        drop(holder.take());
    })
    .expect("the wait ends");
    assert!(taken, "the lock is the waiter's once its helper let go");
    assert_eq!(helpers.len(), 1, "one helper, woken by one release");
    assert!(
        !exists(helpers[0]),
        "the helper was reaped before the wait returned"
    );
}

/// Fails by: a stop raised mid-wait leaving the helper blocked, or the wait.
#[test]
fn a_stop_mid_wait_ends_the_helper_and_returns_stopped() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (path, file) = lock_file("lock-helper-stop");
    let holder = reopen(&path);
    holder.try_lock().expect("free in a fresh fixture");
    let stop = Stop::new().expect("a stop");
    let mut helpers = Vec::new();
    let taken = wait_with_helper(
        &file,
        &path,
        Mode::Exclusive,
        Some(&stop),
        &helper,
        &mut |pid| {
            helpers.push(pid);
            stop.raise();
        },
    )
    .expect("the wait ends");
    assert!(!taken, "the stop ended the wait, the holder still holds");
    assert!(!exists(helpers[0]), "the stopped helper was reaped");
    drop(holder);
}

/// Fails by: a holder that DIES (rather than releasing) leaving the waiter
/// parked. The holder is another process, killed on the helper's park event.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: a holder that dies is a property of another process, so only \
              a real spawn can be one"
)]
fn a_holder_that_dies_hands_the_lock_over() {
    use std::io::BufRead as _;

    if !cfg!(target_os = "linux") {
        return;
    }
    let (path, file) = lock_file("lock-helper-dies");
    // `--no-fork`: the shell REPLACES flock, so the one process holding the
    // descriptor is the one killed — a forked child would hold it on.
    let mut holder = std::process::Command::new("flock")
        .args(["--no-fork", "-x"])
        .arg(&path)
        .args(["sh", "-c", "echo held; read _"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn a holder");
    let mut line = String::new();
    std::io::BufReader::new(holder.stdout.take().expect("piped"))
        .read_line(&mut line)
        .expect("the holder says it holds");
    assert_eq!(line.trim(), "held");
    let taken = wait_with_helper(&file, &path, Mode::Exclusive, None, &helper, &mut |_| {
        holder.kill().expect("kill the holder");
        holder.wait().expect("reap the holder");
    })
    .expect("the wait ends");
    assert!(taken, "a dead holder's lock is the waiter's");
}

/// Fails by: the helper blocking in a mode other than the waiter's — a shared
/// waiter's helper asking for the lock exclusively would wait on other
/// readers it never had to.
#[test]
fn the_helper_waits_in_the_waiters_own_mode() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (path, file) = lock_file("lock-helper-mode");
    let mut holder = Some(reopen(&path));
    holder
        .as_ref()
        .unwrap()
        .try_lock()
        .expect("free in a fresh fixture");
    let mut argv = String::new();
    let taken = wait_with_helper(&file, &path, Mode::Shared, None, &helper, &mut |pid| {
        argv = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).expect("read its argv");
        drop(holder.take());
    })
    .expect("the wait ends");
    assert!(taken);
    let words: Vec<&str> = argv.split('\0').collect();
    assert!(
        words
            .windows(2)
            .any(|pair| pair == ["__lock-wait", "shared"]),
        "the helper was asked for the waiter's mode: {words:?}"
    );
}

/// Fails by: a helper outliving a waiter that UNWOUND — the panic path, where
/// no return value reaps anything and only the guard can.
#[test]
fn no_helper_outlives_a_waiter_that_panics() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let (path, file) = lock_file("lock-helper-unwind");
    let holder = reopen(&path);
    holder.try_lock().expect("free in a fresh fixture");
    let seen = std::sync::Mutex::new(None);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wait_with_helper(&file, &path, Mode::Exclusive, None, &helper, &mut |pid| {
            *seen.lock().unwrap() = Some(pid);
            panic!("the waiter fails while its helper is parked");
        })
    }));
    assert!(unwound.is_err(), "the panic propagated");
    let pid = seen.lock().unwrap().expect("a helper was parked on");
    assert!(!exists(pid), "the unwinding guard reaped helper {pid}");
    drop(holder);
}
