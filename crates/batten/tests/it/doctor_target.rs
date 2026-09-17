//! `batten doctor target` over the compiled binary — CLOUD-1753, retiring five
//! programs that were one capability.
//!
//! # Five files, one decision
//!
//! `rustup target add` is documented as idempotent and is not, in two separate
//! ways, and the shell grew a file for each of them. A toolchain can carry a
//! target's FILES while `rustup target list --installed` omits it, so `add`
//! downloads, reports `detected conflict` and rolls back (`doctor-check.sh`
//! classified that state, `target-ensure.sh` repaired it). And rustup has no
//! cross-process lock, so two concurrent `add` calls each see the other's
//! half-written component tree and BOTH roll back, leaving the target absent on
//! a clean tree (`with-lock.sh` serialised them, `doctor.sh` needed the same lock
//! for its own writers, `darwin-link.sh` routed through the pair).
//!
//! That is one capability — *make this target present, once, safely* — split
//! across five files by the shell's own limits rather than by the problem.
//!
//! # What this tier reaches that the unit cases cannot
//!
//! `doctor::rustup_target` is pure and its cases drive every residue combination
//! against a fixture directory; they cannot see whether the VERB wired to it
//! resolves a sysroot, takes the lock before it classifies, or reports a rustup
//! failure as a pointer rather than as the download spew. Those are properties of
//! the compiled binary, which is what this file drives.
//!
//! # The lock is CLOUD-1710's, not a second one
//!
//! `exec::hold` already shipped with `tests/it/exec_lock.rs` covering the
//! acquire, the queue, the dead-holder reclaim and the empty-pid-file reading.
//! This verb takes that lock rather than growing another, which is why the
//! retired concurrency cases below carry to that file: a second implementation of
//! a lock is two copies of its edge cases, and the edges are where the defects
//! are.
//
// carried: mise-tasks/doctor-check.sh crates/batten/src/doctor.rs kind:verb crates/batten/tests/it/doctor_target.rs runs:batten+doctor+target
// carried: mise-tasks/target-ensure.sh crates/batten/src/doctor.rs kind:verb crates/batten/tests/it/doctor_target.rs runs:batten+doctor+target
// carried: mise-tasks/with-lock.sh crates/batten/src/exec.rs kind:verb crates/batten/tests/it/exec_lock.rs runs:batten+exec
// carried: mise-tasks/doctor.sh crates/batten/src/startup.rs batten.toml kind:mechanism crates/batten/tests/it/doctor_target.rs
// carried: mise-tasks/darwin-link.sh crates/batten/src/doctor.rs mise.toml kind:mechanism crates/batten/tests/it/doctor_target.rs
//
// carried: tests/darwin-link.bats crates/batten/src/doctor.rs mise.toml kind:mechanism crates/batten/tests/it/doctor_target.rs
// carried: tests/doctor.bats crates/batten/src/startup.rs batten.toml kind:mechanism crates/batten/tests/it/doctor_target.rs
// carried: tests/doctor-race.bats crates/batten/src/exec.rs kind:mechanism crates/batten/tests/it/exec_lock.rs
// carried: tests/target-ensure.bats crates/batten/src/doctor.rs kind:verb crates/batten/tests/it/doctor_target.rs
// carried: tests/with-lock.bats crates/batten/src/exec.rs kind:verb crates/batten/tests/it/exec_lock.rs
// carried: tests/target-race.bats crates/batten/src/exec.rs kind:mechanism crates/batten/tests/it/exec_lock.rs
//
// The classification, which is `doctor::rustup_target` and its own cases.
// carried: "missing target: installs, reports the triple, exit 0" crates/batten/src/doctor.rs
// carried: "already-installed target: no-op, no add call" crates/batten/src/doctor.rs
// carried: "stale residue: purged, then installed" crates/batten/src/doctor.rs
// carried: "a failing add is one ::error:: pointer line, not the rustup spew" crates/batten/src/doctor.rs kind:verb crates/batten/tests/it/doctor_target.rs runs:batten+doctor+target
//
// The lock, every case of which CLOUD-1710 already landed on `exec --lock`.
// carried: "a queued caller waits for the lock holder, then proceeds" crates/batten/src/exec.rs
// carried: "a held lock past the timeout is a loud failure, not a hang" crates/batten/src/exec.rs
// carried: "the lock is released on a normal exit" crates/batten/src/exec.rs
// carried: "a lock whose holder is dead is reclaimed, not waited out" crates/batten/src/exec.rs
// carried: "AN EMPTY PID FILE IS HELD, NEVER FREE — absence of evidence is not evidence" crates/batten/src/exec.rs
// carried: "the pre-CLOUD-286 lock FILE does not wedge the directory lock" crates/batten/src/exec.rs
// carried: "with no flock on PATH: acquires, serializes and releases" crates/batten/src/exec.rs
// carried: "the wrapped command runs, and its stdout is untouched by the lock" crates/batten/src/exec.rs
// carried: "THE VERDICT SURVIVES: a failing command's exit status is the task's" crates/batten/src/exec.rs
// carried: "the lock is released on success" crates/batten/src/exec.rs
// carried: "the lock is released when the wrapped command FAILS" crates/batten/src/exec.rs
// carried: "a second caller waits for the holder rather than running concurrently" crates/batten/src/exec.rs
// carried: "the caller names what the wait was for, so the pointer is the concept" crates/batten/src/exec.rs
// carried: "an EMPTY pid file is a holder mid-write, never a corpse" crates/batten/src/exec.rs
// carried: "a missing parent directory is created rather than refused" crates/batten/src/exec.rs
// carried: "a malformed invocation refuses instead of running something unlocked" crates/batten/src/exec.rs
// carried: "no command after the separator is a refusal, not a silent lock-and-exit" crates/batten/src/exec.rs
//
// The concurrency the race suites drove, now one lock rather than three callers.
// carried: "two concurrent doctors run the submodule repair exactly once" crates/batten/src/exec.rs
// carried: "the doctor that queued still reports the submodule as checked out" crates/batten/src/exec.rs
// carried: "two concurrent doctors run the torn-install repair exactly once" crates/batten/src/exec.rs
// carried: "an intact installs tree takes the lock never — the healthy path is free" crates/batten/src/doctor.rs
// carried: "the lock never lands in the working tree, where tree-clean would see it" crates/batten/src/doctor.rs
// carried: "doctor and darwin-link converge when concurrent: both succeed, target installed" crates/batten/src/exec.rs
// carried: "doctor is idempotent under concurrency: two doctors, one real install" crates/batten/src/exec.rs
// carried: "stale residue is purged inside the critical section, then installed" crates/batten/src/doctor.rs
//
// The provisioning, which is now four declared `[[startup]]` rows.
// carried: "a healthy installs tree passes untouched" batten.toml
// carried: "a broken bin symlink is torn: version dir removed, mise install re-run" batten.toml
// carried: "a working symlink is not torn" batten.toml
// carried: "a repair that leaves the tree broken exits non-zero" batten.toml
// carried: "an installed, probe-honouring hook is reported runnable" batten.toml
// carried: "a missing hook fails and names the remedy" batten.toml
// carried: "a present but non-executable hook is not counted as installed" batten.toml
// carried: "a hook that does not honour the probe is REPORTED, never executed" batten.toml
// carried: "a hook that cannot resolve its runner fails distinguishably from an absent one" batten.toml
// carried: "harness self-test: the fixture really does need the submodule repair" batten.toml
//
// The Darwin link, whose steps are now the inline task body.
// carried: "it links rather than type-checks" mise.toml
// carried: "it does not build the optimized profile" mise.toml
// carried: "it mutates the toolchain only through the target-ensure lock" crates/batten/src/doctor.rs
// changed: "a non-darwin target is refused" mise.toml the guard survives as the task body's own precondition and now exits 2 rather than 1, folding onto the engine's table (CLOUD-1718). What does NOT survive is its declared mutation: the `#MUTANT non-darwin-target-passes` row retired with the file, so the guard is no longer shown able to fail. It has no engine home — `doctor target` installs any triple legitimately — and the cost is stated here rather than hidden
//
// Seven cases assert properties their own subject removed.
// withdrawn: "--no-targets is the CLI spelling of an empty DOCTOR_TARGETS: rustup untouched" the flag existed to keep one program's target half off a caller's path; a declared table has no half to exclude, because the rows that touch the toolchain ARE separate rows
// withdrawn: "doctor inside a probe says nothing about hooks — the other half of the recursion" the recursion was the program probing hooks that invoked the program; `batten startup` is registered as no hook, so the shape is unrepresentable
// withdrawn: "CI has no commit path, so the hook check does not run there" the commit-path reading is `doctor gate`'s and carried its own row before this retirement
// withdrawn: "the task layer names no util-linux flock" a ratchet over a task layer this campaign is emptying; `shell-retirement` counts the same tree and is the gate that survives it
// withdrawn: "target-ensure is the only live rustup-target-add in the task layer" the same ratchet, and its subject is the file this row retires
// withdrawn: "harness self-test: two raw concurrent adds both roll back (the model can represent the bug)" a self-test of the retired suite's own fixture, which does not outlive the fixture
// withdrawn: "harness self-test: skewed writers still both roll back (CI spawn-skew shape)" the same self-test at a different spawn skew
//
// One case of a SURVIVING suite, deleted because it names a dying path.
// changed: "CLOUD-498: every receipt-gated call site invokes the task BY PATH" mise.toml the case greps `mise-tasks/darwin-link.sh` for `mise run step-receipt`, so it dies with that file while `tests/step-receipt.bats` lives on. Its surviving half — that `mise.toml` carries no `mise run step-receipt` and that at least eight call sites invoke the program by path — is a property of the committed `mise.toml`, and the count rises rather than falls when darwin-link's body lands there

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{Fixture, batten};

/// A triple no toolchain ships, so `rustup target add` fails for a reason about
/// the argument rather than about the network.
const UNREAL: &str = "nonexistent-unknown-none";

#[test]
fn the_verb_is_declared_and_takes_a_triple() {
    // The surface half, asserted over the BINARY rather than over `surface.rs`:
    // a row declared and not wired reads identically to one that is, until
    // somebody runs it.
    let dir = Fixture::new("doctor-target-declared").git().build();
    let output = batten()
        .args(["doctor", "target", "--help"])
        .current_dir(&dir)
        .output()
        .expect("run batten doctor target --help");

    assert!(output.status.success(), "the sub-verb resolves");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("target triple"),
        "the positional is documented: {said}"
    );
}

#[test]
fn a_triple_rustup_cannot_install_is_one_pointer_line_and_never_the_spew() {
    // THE RETIRED CASE THIS FILE OWES: "a failing add is one ::error:: pointer
    // line, not the rustup spew". rustup's failure output runs to many lines
    // including a backtrace, and a verb that forwarded it would put a payload
    // where non-negotiable rule 4 asks for a pointer.
    let dir = Fixture::new("doctor-target-unreal").git().build();
    let output = batten()
        .args(["doctor", "target", UNREAL])
        .current_dir(&dir)
        .output()
        .expect("run batten doctor target");

    // Could-not-look is a legitimate answer here: a host with no rustup at all
    // cannot say whether the target is installed, and reporting that as "the
    // target is absent" is the reading this verb refuses. Either way it must not
    // succeed, and it must not spill.
    assert!(
        !output.status.success(),
        "a triple that cannot be installed is not a success"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        said.lines()
            .filter(|line| line.contains("::error::"))
            .count(),
        1,
        "exactly one pointer line, got: {said}"
    );
    assert!(
        !said.contains("stack backtrace"),
        "rustup's spew does not travel: {said}"
    );
}
