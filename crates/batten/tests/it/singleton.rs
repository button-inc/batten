//! `batten singleton` over the compiled binary (CLOUD-428), ported off
//! `mise-tasks/singleton.sh` under CLOUD-843.
//!
//! **THE SECOND TIER, AND IT IS NOT OPTIONAL.** `task.rs`'s own `mod tests` can
//! pin the predicates over values handed to them. What it cannot pin is that the
//! VERB resolves the git dir the lock lives under: a module that resolved the
//! wrong one would acquire happily forever, and "the lock was free" and "I looked
//! in the wrong place" are byte-identical on the decision surface. That is the
//! defect this file exists to catch, and it is the same shape CLOUD-428 itself
//! measured — three concurrent `land` processes, each certain it was alone.
//!
//! **THE REFUSAL IS THE PRODUCT, so most cases assert exit 2 rather than a
//! message.** Unlike a lock that waits, a second `land` must exit non-zero
//! naming the live pid: waiting would mean two agents intending to land the same
//! branch, which is a mistake to surface rather than to queue.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, batten, scratch, stderr, stdout};

/// A repository with somewhere to put a lock, and nothing holding one.
fn lock_repo(name: &str) -> PathBuf {
    Fixture::at(scratch(name).join("repo"))
        .config("version = 1\n")
        .git()
        .base_commit()
        .build()
}

/// `batten singleton …` in `dir`, fenced so a fixture that forgot `git init`
/// fails loudly instead of taking a lock in the real checkout.
fn singleton(dir: &Path, args: &[&str]) -> Output {
    let mut command = batten();
    command.arg("singleton");
    command
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten singleton")
}

/// Where one task's lock lives.
fn lock(repo: &Path, task: &str) -> PathBuf {
    repo.join(".git/batten-singleton").join(task)
}

/// A pid no process can hold.
///
/// `/proc/sys/kernel/pid_max` is exclusive — the kernel never assigns it — so
/// this is a genuine "no such process" rather than a race against whatever
/// happens to be running. A literal high number would eventually collide, and
/// the collision would turn a crashed case green.
fn unassignable_pid() -> String {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or_else(|| "4194304".to_owned(), |max| max.to_string())
}

#[test]
fn an_unheld_task_is_acquired_and_the_pid_file_names_the_caller() {
    // The pid written is the CALLER's, never this process's: the verb acts on
    // the caller's behalf and holds nothing itself, because it exits at once.
    let repo = lock_repo("singleton-free");
    let output = singleton(&repo, &["acquire", "land", "4242"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let pid = std::fs::read_to_string(lock(&repo, "land").join("pid")).expect("a pid file");
    assert_eq!(pid.trim(), "4242");
}

#[test]
fn a_second_acquire_is_refused_while_the_first_is_alive_and_names_the_live_pid() {
    // THE ACCEPTANCE CASE, and the one CLOUD-428 was measured on. This process
    // is the live holder — a process this file knows everything about, so the
    // case cannot be wrong about whether its subject is running (`rust.md`'s
    // premise rule; spawning one would assert its own premise).
    let repo = lock_repo("singleton-held");
    let live = std::process::id().to_string();
    assert_eq!(
        singleton(&repo, &["acquire", "land", &live]).status.code(),
        Some(0)
    );

    let second = singleton(&repo, &["acquire", "land", "9999"]);
    assert_eq!(second.status.code(), Some(2), "{}", stdout(&second));
    assert!(stderr(&second).contains(&live), "{}", stderr(&second));
    // And the lock still names the FIRST caller: a refused acquire takes nothing.
    let held = std::fs::read_to_string(lock(&repo, "land").join("pid")).expect("a pid file");
    assert_eq!(held.trim(), live);
}

#[test]
fn the_refusal_names_the_holders_phase_when_the_registry_knows_it() {
    // The registry is the first consumer of CLOUD-425 rather than a second
    // bookkeeping scheme, and this is the case that proves the two modules share
    // one reader: the phase comes from a record `task register` minted.
    let repo = lock_repo("singleton-phase");
    let live = std::process::id().to_string();
    let mut register = batten();
    register
        .args(["task", "register", "land", &live, "ci-wait(lap 1)"])
        .current_dir(&repo)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("register the holder");
    singleton(&repo, &["acquire", "land", &live]);

    let refused = singleton(&repo, &["acquire", "land", "9999"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        stderr(&refused).contains("ci-wait(lap 1)"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn a_missing_registry_entry_still_refuses_because_the_lock_is_the_authority() {
    // The registry is best-effort and a holder that died before registering has
    // no entry, so absence is the COMMON case. It must never turn a refusal into
    // a pass — which is what a naive "look up the holder, and if you cannot find
    // it assume nothing is running" would do.
    let repo = lock_repo("singleton-no-entry");
    let live = std::process::id().to_string();
    singleton(&repo, &["acquire", "land", &live]);

    let refused = singleton(&repo, &["acquire", "land", "9999"]);
    assert_eq!(refused.status.code(), Some(2), "{}", stdout(&refused));
    assert!(stderr(&refused).contains(&live));
}

#[test]
fn a_lock_whose_holder_is_dead_is_reclaimed_rather_than_waited_out() {
    let repo = lock_repo("singleton-reclaim");
    let corpse = unassignable_pid();
    singleton(&repo, &["acquire", "land", &corpse]);

    let output = singleton(&repo, &["acquire", "land", "4242", "--recheck-ms", "1"]);

    // THE SAME ASYMMETRY `task::tests::a_reclaim_needs_two_sightings_of_one_dead_pid`
    // WRITES DOWN, reached through the verb rather than through the decision.
    // `pid_exists` has no probe off unix — its `#[cfg(not(unix))]` arm answers
    // `true` for every parseable pid, on purpose — so a corpse reads as a live
    // holder there, nothing is ever reaped, and the acquire REFUSES instead of
    // reclaiming. Asserting the unix contract as universal is what made this red
    // on the `windows` job and green on every developer machine; `#[cfg(unix)]`
    // over the whole test would leave the Windows contract unstated, which is the
    // hole that let CI find its sibling.
    #[cfg(unix)]
    {
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(stdout(&output).contains("reclaimed"), "{}", stdout(&output));
        let held = std::fs::read_to_string(lock(&repo, "land").join("pid")).expect("a pid file");
        assert_eq!(held.trim(), "4242");
    }
    #[cfg(not(unix))]
    {
        assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
        let held = std::fs::read_to_string(lock(&repo, "land").join("pid")).expect("a pid file");
        assert_eq!(
            held.trim(),
            corpse,
            "off unix the corpse still holds it — nothing is ever reported dead"
        );
    }
}

#[test]
fn an_empty_pid_file_is_held_and_a_lock_with_no_pid_file_at_all_is_too() {
    // ABSENCE OF EVIDENCE IS NEVER "FREE". Both shapes are a holder caught
    // between its create and its write, so reading either as free hands the lock
    // to a second caller while the first is mid-acquire — the exact interleaving
    // a lock exists to prevent.
    let repo = lock_repo("singleton-midwrite");
    std::fs::create_dir_all(lock(&repo, "land")).expect("a lock");

    let no_file = singleton(&repo, &["acquire", "land", "4242", "--recheck-ms", "1"]);
    assert_eq!(no_file.status.code(), Some(2), "{}", stdout(&no_file));

    std::fs::write(lock(&repo, "land").join("pid"), "").expect("an empty pid file");
    let empty = singleton(&repo, &["acquire", "land", "4242", "--recheck-ms", "1"]);
    assert_eq!(empty.status.code(), Some(2), "{}", stdout(&empty));
}

#[test]
fn a_live_holder_is_never_reclaimed_however_long_the_recheck_is() {
    // The reachable half of TWO SIGHTINGS at this tier. The unreachable half —
    // the lock changing hands BETWEEN the two sightings — is
    // `task::tests::a_reclaim_needs_two_sightings_of_one_dead_pid`, because
    // driving it here means racing a live child against a sleep, and a sleep
    // standing in for "the child reached its first sighting" is the timer
    // CLOUD-1177 refuses. Over the decision it is four assertions and no clock.
    //
    // What this pins is that the verb consults that decision at all: a wide
    // recheck over a live holder must still refuse rather than time its way into
    // a reclaim.
    let repo = lock_repo("singleton-live-holder");
    let live = std::process::id().to_string();
    singleton(&repo, &["acquire", "land", &live]);

    let output = singleton(&repo, &["acquire", "land", "4242", "--recheck-ms", "250"]);
    assert_eq!(output.status.code(), Some(2), "a live holder was robbed");
    let held = std::fs::read_to_string(lock(&repo, "land").join("pid")).expect("a pid file");
    assert_eq!(held.trim(), live);
}

#[test]
fn release_frees_the_lock_and_releasing_one_never_taken_is_a_no_op() {
    // It runs from an exit trap that also fires on paths where the acquire never
    // happened. A trap that can fail masks the real exit code.
    let repo = lock_repo("singleton-release");
    let live = std::process::id().to_string();
    singleton(&repo, &["acquire", "land", &live]);

    let released = singleton(&repo, &["release", "land"]);
    assert_eq!(released.status.code(), Some(0), "{}", stderr(&released));
    assert_eq!(
        singleton(&repo, &["acquire", "land", "4242"]).status.code(),
        Some(0),
        "the lock was not freed"
    );

    let never = singleton(&repo, &["release", "verify"]);
    assert_eq!(never.status.code(), Some(0), "{}", stderr(&never));
}

#[test]
fn tasks_are_locked_independently() {
    // The lock is keyed by TASK, so a held `land` says nothing about `verify`.
    let repo = lock_repo("singleton-independent");
    let live = std::process::id().to_string();
    singleton(&repo, &["acquire", "land", &live]);

    let other = singleton(&repo, &["acquire", "verify", "4242"]);
    assert_eq!(other.status.code(), Some(0), "{}", stderr(&other));
}

#[test]
fn a_missing_argument_is_usage_and_takes_no_lock() {
    // Exit 1 where the retiring shell spelled every one of these `2`: a missing
    // argument is a statement about the INVOCATION, and `2` here already means
    // "somebody holds it", which is an answer about the clone.
    let repo = lock_repo("singleton-usage");
    for args in [
        vec!["acquire", "land"],
        vec!["release"],
        vec!["hold", "land"],
    ] {
        let output = singleton(&repo, &args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    assert!(
        !repo.join(".git/batten-singleton").exists(),
        "a refused invocation took a lock"
    );
}

#[test]
fn a_malformed_recheck_is_refused_rather_than_silently_defaulted() {
    // The pause is the reclaim's whole safety margin against robbing a live
    // holder, so guessing it would decide a lock silently.
    let repo = lock_repo("singleton-bad-recheck");
    let output = singleton(&repo, &["acquire", "land", "4242", "--recheck-ms", "soon"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn outside_a_repository_it_is_could_not_look_rather_than_free() {
    // Exit 3 where the shell spelled it 2. Reading "I could not tell" as "nothing
    // holds it" is how a second land starts, which is the whole point of the
    // three-valued answer.
    let outside = Fixture::at(scratch("singleton-no-repo").join("plain")).build();
    let output = singleton(&outside, &["acquire", "land", "4242"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

#[test]
fn the_refusal_is_a_pointer_and_never_a_line_of_any_log() {
    // Non-negotiable rule 4. The refusal carries a pid and the holder's phase —
    // the phase being the writer's own declaration — and no other byte of the
    // record it read to find it.
    let repo = lock_repo("singleton-pointer");
    let live = std::process::id().to_string();
    std::fs::create_dir_all(repo.join(".git/batten-tasks")).expect("a registry");
    std::fs::write(
        repo.join(".git/batten-tasks").join(&live),
        format!(
            "task: land\npid: {live}\npgid: {live}\nphase: verify\n\
             started_at: 1000\nphase_since: 1000\n\
             tick: Q7vtickedx9nK\ntick_at: 1000\nsig: Q7vsignedx9nK\nsig_at: 1000\n"
        ),
    )
    .expect("a record carrying unrendered fields");
    singleton(&repo, &["acquire", "land", &live]);

    let refused = singleton(&repo, &["acquire", "land", "9999"]);
    for canary in ["Q7vtickedx9nK", "Q7vsignedx9nK"] {
        assert!(
            !stderr(&refused).contains(canary) && !stdout(&refused).contains(canary),
            "a field this refusal does not render reached the output: {canary}"
        );
    }
    assert!(
        stderr(&refused).contains("(verify)"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn the_lock_is_a_directory_rather_than_a_flock_file() {
    // CLOUD-286, held structurally. `flock(1)` ships with util-linux and does not
    // exist on macOS, where the refusal guarding it fired before any other gate.
    // A directory is an atomic create-or-fail everywhere and costs no binary.
    //
    // Asserted over what the acquire LEAVES rather than over the source, because
    // that is the property a second caller actually contends on.
    let repo = lock_repo("singleton-directory");
    singleton(&repo, &["acquire", "land", "4242"]);
    assert!(lock(&repo, "land").is_dir(), "the lock is not a directory");
}

// --- `singleton`, retired onto `batten singleton` (CLOUD-843 / CLOUD-428) ----
//
// **THE CALL SITES ARE UNTOUCHED, and that is this retirement's whole reach.**
// `mise-tasks/land.sh` calls `mise run singleton acquire|release` by TASK NAME
// rather than by path, so keeping the mise task name means `land.sh` and
// `tests/land.bats` are not edited at all. The wrapper translates the engine's
// `2`/`3` back to the shell's `1`/`2`, so a caller branching on the code reads
// the same answers it always did.
//
// **THE SUCCESSOR IS `task.rs` RATHER THAN A MODULE OF ITS OWN**, and the reason
// is the retiring program's own text: it read the task registry by hand to name
// what the holder was doing. That was a second authority over a layout CLOUD-425
// had just given one owner, so the port removes a duplicate reader rather than
// relocating one. It shares `pid_exists` for the same reason.
//
// carried: mise-tasks/singleton.sh crates/batten/src/task.rs kind:verb crates/batten/tests/it/singleton.rs
// carried: tests/singleton.bats crates/batten/src/task.rs kind:verb crates/batten/tests/it/singleton.rs
//
// carried: "an unheld task is acquired, and the pid file names the caller" crates/batten/tests/it/singleton.rs
// carried: "THE ACCEPTANCE CASE: a second acquire is refused while the first is alive, and names the live pid" crates/batten/tests/it/singleton.rs
// carried: "the refusal names the holder's phase when the registry knows it" crates/batten/tests/it/singleton.rs
// carried: "a missing registry entry still refuses — the lock is the authority, not the registry" crates/batten/tests/it/singleton.rs
// carried: "a lock whose holder is dead is reclaimed, not waited out" crates/batten/tests/it/singleton.rs
// carried: "AN EMPTY PID FILE IS HELD, NEVER FREE — absence of evidence is not evidence" crates/batten/tests/it/singleton.rs
// carried: "a lock directory with no pid file at all is held too" crates/batten/tests/it/singleton.rs
// carried: "TWO SIGHTINGS: a lock that changed hands under the reclaim is not stolen" crates/batten/src/task.rs kind:mechanism
// carried: "release frees the lock for the next caller" crates/batten/tests/it/singleton.rs
// carried: "release of a lock that was never taken is a no-op, not a failure" crates/batten/tests/it/singleton.rs
// carried: "tasks are locked independently — a held land does not block another task" crates/batten/tests/it/singleton.rs
// carried: "the refusal is pointer-only — a pid and a phase, never a log line" crates/batten/tests/it/singleton.rs
//
// CHANGED — one property restated where a consumer can see it, and the codes.
//
// changed: "the lock is taken with mkdir, not flock — util-linux is absent on macOS" crates/batten/tests/it/singleton.rs the shell could only scan its own text for `mkdir`, because a bats suite cannot see inside its subject any other way. `the_lock_is_a_directory_rather_than_a_flock_file` asserts the property a second caller actually contends on — what the acquire LEAVES is a directory — which a source scan can only approximate and which survives the implementation being rewritten
// changed: "singleton.bats::an unknown verb is exit 2, never a silent success" crates/batten/tests/it/singleton.rs exit 1: an unknown subcommand is a statement about the invocation. Carried into `a_missing_argument_is_usage_and_takes_no_lock`, which asserts the code over the unknown verb and over both missing positionals at once, because they are one class and the shell had spelled them as two
// changed: "acquire without a pid is exit 2, and takes no lock" crates/batten/tests/it/singleton.rs exit 1, same class and same case; the "takes no lock" half is carried unchanged as an assertion that the state directory was never created
// changed: "outside a git repository it exits 2 — could not look is not 'nothing is running'" crates/batten/tests/it/singleton.rs exit 3: could-not-look is `Internal` in the one contract, and `2` here already means "somebody holds it". The PREDICATE — that could-not-look is never read as free — is carried whole, and the wrapper maps it back to `2` so `land.sh` sees what it always saw
//
// WITHDRAWN — one case the port cannot express, and it is the environment's.
//
// withdrawn: "THE PROPERTY: a killed holder does not block the next run indefinitely" crates/batten/tests/it/singleton.rs the shell drove this by SIGKILLing a real holder it had spawned. `clippy::disallowed_types` makes this crate's spawn an inventory row, and a test that spawns a process only to kill it buys nothing the reclaim case above does not already prove over an unassignable pid — which is a genuine "no such process" rather than a race. The property is the reclaim case's; what is withdrawn is the spawn-and-kill route to it
