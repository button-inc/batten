//! `batten exec --lock` holds a named singleton lock across a child, over the
//! compiled binary (CLOUD-1710, ported from `mise-tasks/with-lock.sh`).
//!
//! **The two cases that discriminate are the last two**, and they are why this
//! tier exists rather than a pair of acquire/release assertions. A lock that
//! never blocks, never releases, or swallows the verdict of what it guards all
//! look identical from the outside on a quiet machine — the retiring suite says
//! so in its own header — and so does a lock that reclaims a holder it should
//! not. `an_empty_holder_file_is_held_not_free` and
//! `a_dead_holder_is_reclaimed_rather_than_waited_out` are the pair a naive
//! successor fails, and each has a `#MUTANT` row in `crates/batten/src/exec.rs`
//! that makes the discrimination an exit code rather than a claim.
//!
//! **Over the compiled binary rather than a unit test on `task::singleton_queue`
//! (CLOUD-418).** The queue is testable in isolation and that is not the
//! obligation: what retired is a WRAPPER, so the property is that the lock is
//! taken before the child and dropped after it whatever the child did, and only
//! the binary runs both halves.
//!
//! **The retirement this was built for is NOT in this delta, and the reason is a
//! measured coupling rather than a deferral.** `batten exec` resolves a
//! repository root for its capture store, and `mise-tasks/with-lock.sh` needed
//! none — so a caller running outside a real clone works under the shell and
//! refuses under the successor. `tests/doctor-race.bats` is exactly that caller:
//! its fixture is a `.git` DIRECTORY rather than a repository, so every port of
//! `with-lock` onto an `exec` flag reddens it, and that suite is governed and
//! cannot be edited. Its declared subject is `mise-tasks/doctor.sh`, which
//! retires under CLOUD-1753 — so `with-lock` retires in the same delta as the
//! `doctor` / `target-ensure` / `doctor-check` closed set, or not at all. The
//! capability lands here; the ledger arms land with the deletion.

use std::path::Path;

use crate::common;

/// Where the engine keeps one clone's singleton locks.
fn lock_dir(repo: &Path, key: &str) -> std::path::PathBuf {
    repo.join(".git").join("batten-singleton").join(key)
}

/// A pid that is certainly not running.
///
/// Reaped rather than invented: a number picked out of the air can collide with
/// a live process and turn a reclaim case green for the wrong reason.
fn dead_pid() -> u32 {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: reaping a real process is the only way to name a pid that is certainly dead, and the reclaim case turns on that — a number picked out of the air can collide with a live process and go green for the wrong reason"
    )]
    let child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a process that exits immediately");
    let pid = child.id();
    let mut child = child;
    child.wait().expect("reap it");
    pid
}

fn repo(name: &str) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::init_repo(&dir);
    dir
}

#[test]
fn the_wrapped_exit_code_survives_the_lock() {
    // The whole product of a wrapper. The shell names losing it as the defect
    // that would "destroy the verdict of everything it guards".
    let dir = repo("exec-lock-verdict");
    let output = common::run(&dir, &["exec", "--lock", "k", "--", "bash", "-c", "exit 7"]);
    assert_eq!(output.status.code(), Some(7), "{}", common::stderr(&output));
}

#[test]
fn a_signal_survives_the_lock() {
    // A child that died on a signal has no exit status of its own, and the
    // shell's `128 + signal` convention is what the wrapper reports. The lock
    // must not replace it with a success of its own.
    let dir = repo("exec-lock-signal");
    let output = common::run(
        &dir,
        &["exec", "--lock", "k", "--", "bash", "-c", "kill -TERM $$"],
    );
    assert_eq!(
        output.status.code(),
        Some(143),
        "{}",
        common::stderr(&output)
    );
}

#[test]
fn the_lock_is_released_when_the_child_fails() {
    // The half that matters: a failure leaving the lock held wedges every later
    // caller for the whole queue, turning one red run into a stuck repo.
    let dir = repo("exec-lock-release-on-failure");
    let output = common::run(&dir, &["exec", "--lock", "k", "--", "false"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        !lock_dir(&dir, "k").exists(),
        "the lock survived a failing child"
    );
}

#[test]
fn an_empty_holder_file_is_held_not_free() {
    // DISCRIMINATING. A holder caught between its create and its write has an
    // empty pid file, and absence of evidence is "held", never "free" —
    // reclaiming there robs a live process of a lock it is about to stamp.
    // `--lock-attempts 1` is what makes this one ask rather than the full queue.
    let dir = repo("exec-lock-empty-holder");
    let lock = lock_dir(&dir, "k");
    std::fs::create_dir_all(&lock).expect("stage a holder mid-write");
    std::fs::write(lock.join("pid"), "").expect("an empty pid file");

    let output = common::run(
        &dir,
        &["exec", "--lock", "k", "--lock-attempts", "1", "--", "true"],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an empty holder file was read as free: {}",
        common::stderr(&output)
    );
}

#[test]
fn a_dead_holder_is_reclaimed_rather_than_waited_out() {
    // DISCRIMINATING, and the opposite direction from the case above. A
    // directory lock's release comes from the guard, which a SIGKILLed holder
    // never runs; reclaim is what keeps that a delay of one ask instead of the
    // whole queue. A refusal here means it regressed.
    let dir = repo("exec-lock-dead-holder");
    let lock = lock_dir(&dir, "k");
    std::fs::create_dir_all(&lock).expect("stage an abandoned lock");
    std::fs::write(lock.join("pid"), format!("{}\n", dead_pid())).expect("a corpse");

    let output = common::run(
        &dir,
        &["exec", "--lock", "k", "--lock-attempts", "2", "--", "true"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a dead holder was waited out rather than reclaimed: {}",
        common::stderr(&output)
    );
}

#[test]
fn a_live_holder_is_refused_and_the_caller_names_the_wait() {
    // Two properties in one case because they share a setup and neither is
    // meaningful without the other: the refusal happens, and it points at the
    // concept rather than at a directory. "the toolchain lock (some-triple)" is
    // a pointer a reader can reason about; a bare key is a pointer to a path.
    let dir = repo("exec-lock-live-holder");
    let lock = lock_dir(&dir, "k");
    std::fs::create_dir_all(&lock).expect("stage a live holder");
    std::fs::write(lock.join("pid"), format!("{}\n", std::process::id())).expect("a live pid");

    let output = common::run(
        &dir,
        &[
            "exec",
            "--lock",
            "k",
            "--lock-attempts",
            "1",
            "--lock-label",
            "the toolchain lock (some-triple)",
            "--",
            "true",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(
        common::stderr(&output).contains("the toolchain lock (some-triple)"),
        "the refusal must name what the wait was for: {}",
        common::stderr(&output)
    );
}

#[test]
fn an_unlocked_run_is_untouched() {
    // Anti-vacuity: every case above asserts something about `--lock`, and a
    // build in which the flag did nothing at all would still pass several of
    // them. This pins that the lock is opt-in and takes nothing when unasked.
    let dir = repo("exec-lock-absent");
    let output = common::run(&dir, &["exec", "--", "true"]);
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
    assert!(
        !dir.join(".git").join("batten-singleton").exists(),
        "an unlocked run took a lock"
    );
}

#[test]
fn a_malformed_attempt_count_is_named_rather_than_defaulted() {
    // `--jobs`' reading, and for `--jobs`' reason: reading a bad value as the
    // default would queue for a length nobody asked for, and the refusal has to
    // say which value was wrong.
    let dir = repo("exec-lock-bad-attempts");
    let output = common::run(
        &dir,
        &[
            "exec",
            "--lock",
            "k",
            "--lock-attempts",
            "nought",
            "--",
            "true",
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", common::stderr(&output));
    assert!(
        common::stderr(&output).contains("nought"),
        "the refusal must name the value: {}",
        common::stderr(&output)
    );
}
