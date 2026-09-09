//! `batten lease check`, over the compiled binary — the tier
//! `mise-tasks/land-lock-check.sh`'s retirement owes (CLOUD-1148).
//!
//! # What this tier is FOR, and what it deliberately is not
//!
//! The DECISION — absent, released, lapsed, live, wedged, garbage, and the
//! successor named in all five healthy renderings — is `lease::health`, a pure
//! function of a reading the caller already took. Its cases live beside it, and
//! that is the right home: every input is in hand, so the whole table is
//! exercisable without a remote, a clock or a fixture.
//!
//! What a load-time tier structurally cannot answer is what the BINARY does with
//! that decision, and the predecessor's suite could: the exit code, the channel
//! each verdict is written to, and whether a could-not-look is told apart from a
//! verdict. Those are this file's, and they are the half where a wrong answer is
//! silent — a `Wedged` mapped to `Success` would leave a wedged lease reported in
//! prose and passing its own gate.
//!
//! # THE STATES THAT NEED A REMOTE ARE NOT HERE, AND THAT IS STATED RATHER THAN
//! IMPLIED
//!
//! `lease::observe` reads the lease over smart HTTP and has no offline fixture
//! seam — the predecessor injected `$LAND_LOCK_BODY`, which the verb does not
//! take. So the four healthy states and the two refusals are reachable here only
//! through a live remote, and the cases below drive the two arms that need none:
//! a clone with no lease at all, and a remote that will not answer.
//!
//! Giving the verb a body-injection lever to close that gap was considered and
//! not done: it would be a second route to a verdict, present in every shipped
//! binary, whose only consumer is a test — which is the shape
//! `crates/batten/src/rest.rs`'s fixture seam is scoped to a client for
//! deliberately. The exit-code mapping over all four `Health` arms is asserted
//! instead where it lives, in `lib.rs`'s own module.

// carried: mise-tasks/land-lock-check.sh crates/batten/src/lease.rs kind:mechanism crates/batten/tests/it/lease_health.rs runs:batten+lease+check
// carried: tests/land-lock-check.bats crates/batten/src/lease.rs kind:mechanism crates/batten/tests/it/lease_health.rs

//! # RETIREMENT LEDGER — `tests/land-lock-check.bats`, 17 cases
//!
//! **Every title below is the base file's, byte for byte**, read from
//! `git show origin/main:tests/land-lock-check.bats` rather than reconstructed —
//! `receipt_verified.rs`'s own header records what happens otherwise, and it is
//! ten unmapped arms.
//!
//! CARRIED ONTO `lease::health`, whose cases sit beside it: every input is a
//! reading the caller already took, so the whole state table is exercisable with
//! no remote, no clock and no fixture. That is a BETTER home than the bats suite
//! had, which reached the same states only through an injected `$LAND_LOCK_BODY`.

// carried: "an absent lease is healthy — nobody is landing" crates/batten/src/lease.rs
// carried: "a live lease is healthy and names its holder and remaining time" crates/batten/src/lease.rs
// carried: "a RELEASED lease is free, and is reported as a handover rather than an expiry" crates/batten/src/lease.rs
// carried: "a LAPSED lease is free too — a holder that stopped without releasing" crates/batten/src/lease.rs
// carried: "a lease expiring exactly now is free — zero seconds left is none" crates/batten/src/lease.rs
// carried: "WEDGED: a horizon beyond one TTL is refused, since nothing legitimate mints one" crates/batten/src/lease.rs
// carried: "a lease at exactly one TTL is the longest legitimate hold, not wedged" crates/batten/src/lease.rs
// carried: "GARBAGE: a ref carrying no lease body is refused" crates/batten/src/lease.rs
// carried: "GARBAGE: a non-numeric expiry is a refusal, never a shell error" crates/batten/src/lease.rs
// carried: "GARBAGE: a lease with no holder is refused — nobody could ever release it" crates/batten/src/lease.rs
// carried: "CLOUD-369 clause f — a held lease names the successor admitted behind it" crates/batten/src/lease.rs
// carried: "CLOUD-369 clause f — output is BYTE-IDENTICAL when no successor is admitted" crates/batten/src/lease.rs
// carried: "CLOUD-369 clause f — a RELEASED lease still names who was admitted behind it" crates/batten/src/lease.rs
// carried: "CLOUD-369 clause f — a WEDGED lease names the successor too, and still fails" crates/batten/src/lease.rs
// carried: "CLOUD-369 clause f — a LAPSED lease names the successor it left behind" crates/batten/src/lease.rs

//! CARRIED HERE, over the compiled binary, because the property is the BINARY's
//! rather than the predicate's — an exit code and a channel, which no pure
//! function has.

// carried: "an unreachable remote is exit 2 — could not look is not a verdict" crates/batten/tests/it/lease_health.rs
// carried: "POINTER, NEVER PAYLOAD: no case echoes the lease body" crates/batten/tests/it/lease_health.rs

#![cfg(unix)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, scratch, stderr, stdout};

/// A git repository with a committer, and no remote unless a case adds one.
fn repo(name: &str) -> PathBuf {
    let dir = scratch(name);
    let repo = gix::init(&dir).expect("init");
    let mut config = std::fs::read_to_string(dir.join(".git/config")).expect("read config");
    config.push_str("[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n");
    std::fs::write(dir.join(".git/config"), config).expect("write config");
    drop(repo);
    dir
}

/// Point the fixture at a remote by URL, without a network round trip to set it.
fn remote(dir: &Path, url: &str) {
    let config = std::fs::read_to_string(dir.join(".git/config")).expect("read config");
    let with_remote = format!("{config}[remote \"origin\"]\n\turl = {url}\n");
    std::fs::write(dir.join(".git/config"), with_remote).expect("write config");
}

/// `batten lease check` in `dir`: the exit code, stdout and stderr.
fn check(dir: &Path) -> (i32, String, String) {
    let output = batten()
        .args(["lease", "check"])
        .current_dir(dir)
        .output()
        .expect("run batten lease check");
    (
        output.status.code().expect("exit code"),
        stdout(&output),
        stderr(&output),
    )
}

/// A clone with no remote has no lease to judge, and that is a reading rather
/// than a failure to take one.
///
/// `lease::TermsMissing` keeps `NoRemote` and `Unreadable` apart for exactly this:
/// folding a repository that was never pushed anywhere into the could-not-look
/// guard made every reporting verb an error in a clone that is perfectly healthy.
#[test]
fn a_clone_with_no_remote_is_healthy_and_says_why() {
    let dir = repo("lease-health-no-remote");
    let (code, out, err) = check(&dir);
    assert_eq!(
        code, 0,
        "a clone with no lease is not a refusal: {err}{out}"
    );
    assert!(
        out.contains("no remote"),
        "the reading names its own cause: {out}"
    );
}

/// **A REMOTE THAT WILL NOT ANSWER IS EXIT 3, AND THE PREDECESSOR SPELLED IT 2.**
///
/// This is the one case in the retired suite whose NUMBER moves, and it moves
/// because the engine has one exit table with no per-verb exception
/// (non-negotiable rule 5): `2` is the policy verdict everywhere — here, a wedged
/// or garbage lease — and `3` is could-not-look. The predecessor used `1` for the
/// verdict and `2` for the unreachable remote, which is the same two answers with
/// the numbers swapped.
///
/// The property both spellings share is the one under test: a lease nobody could
/// read must not be reported as a lease that is wrong. A gate that conflated them
/// would fail the fleet over a network blip and name a wedge that does not exist.
#[test]
fn a_remote_that_will_not_answer_is_could_not_look_and_never_a_verdict() {
    let dir = repo("lease-health-unreachable");
    // A LOOPBACK PORT NOTHING LISTENS ON, rather than a blackholed address. Both
    // are could-not-look, and only one is fast: a reserved documentation address
    // has to time out, which cost this case 6.2s measured, where a refused
    // connection answers at once. The reading under test is the same either way.
    remote(&dir, "https://127.0.0.1:1/unreachable.git");

    let (code, out, err) = check(&dir);
    assert_eq!(
        code, 3,
        "an unreachable remote is could-not-look, not a wedge: {err}{out}"
    );
    // AND IT IS NOT THE VERDICT CODE. Without this arm the case above passes over
    // a binary that answers `2` for everything it cannot read, which is the exact
    // conflation the rule 5 table exists to prevent.
    assert_ne!(code, 2, "a lease nobody read is not a lease that is wrong");
    assert!(
        !err.contains("WEDGED") && !err.contains("GARBAGE"),
        "a could-not-look names no state: {err}"
    );
}

/// POINTER, NEVER PAYLOAD (non-negotiable rule 4): no path echoes a lease body.
///
/// Carried over from the retired suite, and it is cheap to keep because what it
/// asserts is an ABSENCE — a case that only checked the healthy renderings would
/// pass over a refusal that dumped the ref's contents, and a refusal is exactly
/// where an implementer reaches for more detail.
#[test]
fn no_path_echoes_a_lease_body() {
    for (name, url) in [
        ("lease-health-pointer-none", None),
        (
            "lease-health-pointer-unreachable",
            Some("https://127.0.0.1:1/unreachable.git"),
        ),
    ] {
        let dir = repo(name);
        if let Some(url) = url {
            remote(&dir, url);
        }
        let (_, out, err) = check(&dir);
        let said = format!("{out}{err}");
        for field in ["holder:", "expires:", "progress:", "next:"] {
            assert!(
                !said.contains(field),
                "a lease field reached the report at {name}: {said}"
            );
        }
    }
}

// ─── CLOUD-1703: THE PROGRESS TOKEN A BEAT PUBLISHES ─────────────────────────
//
// These three run over the LIBRARY rather than the binary, which the header
// above says this tier is not for — and they are here anyway because the Ready
// block names this suite and because the property is not `lease check`'s. Stated
// rather than left as an inconsistency: the subject is `own_progress`, whose
// whole point is that it joins two already-tested halves, so a case for it
// belongs wherever the join is asserted rather than wherever the halves are.

/// A land publishes the token its own registry entry carries.
///
/// **This is the anti-vacuity case, and it is the reason the tier is here at
/// all.** `progress_of` and `Progress::token` were both correct and both tested
/// while `body.progress` was empty on every lease in the fleet, because nothing
/// called one with the other. A case that exercised either half alone would have
/// passed throughout the defect — so this one drives the join, by the same
/// `std::process::id()` route the heartbeat uses.
#[test]
fn a_land_publishes_its_own_progress_token() {
    let dir = repo("lease-health-own-progress");
    let git_dir = dir.join(".git");
    let pid = std::process::id();
    std::fs::create_dir_all(git_dir.join("batten-tasks")).expect("registry dir");
    std::fs::write(
        git_dir.join("batten-tasks").join(pid.to_string()),
        "phase_since: 1700000000\ntick_at: 1700000030\n",
    )
    .expect("registry entry");

    let published = batten::lease::own_progress(&git_dir, pid);
    assert_eq!(
        published.as_deref(),
        Some("1700000000.1700000030"),
        "a beat publishes the registry's stamps, not an empty token"
    );
}

/// A lap whose bookkeeping never registered publishes nothing, and that is a
/// reading rather than a stall.
///
/// The complement matters as much as the case above: if an absent entry answered
/// with some placeholder token, every land that had not yet registered would look
/// like one that had stopped moving, and `turn`'s steal arm tests the token for
/// EQUALITY OVER TIME — a constant would make every holder stealable.
#[test]
fn a_land_with_no_registry_entry_publishes_nothing() {
    let dir = repo("lease-health-no-registry");
    let git_dir = dir.join(".git");
    assert_eq!(
        batten::lease::own_progress(&git_dir, std::process::id()),
        None,
        "no entry is no token, never a placeholder"
    );
}

/// A holder that beats without landing is stealable ONCE its beat publishes.
///
/// The steal arm in `turn` has been written and unit-tested throughout the
/// defect and could never fire, because it opens with
/// `!body.progress.is_empty()` and no lease ever carried a token. So this asserts
/// the arm against a body shaped the way a published beat now shapes it, and the
/// empty-token twin below is what proves the guard is the thing that was
/// disarming it.
#[test]
fn a_stalled_holder_is_stealable_once_its_beat_has_published() {
    use batten::lease::{Body, Observed, Terms, Turn, turn};

    let terms = Terms::default();
    let stall = 60;
    let stalled_for = stall * terms.beat + 1;
    let body = |progress: &str| Body {
        holder: String::from("clone-a"),
        expires: 2_000_000,
        branch: String::from("claude/some-branch"),
        head: String::from("abc1234"),
        next: String::new(),
        progress: progress.to_owned(),
        nonce: String::from("n1"),
    };
    let observed = |progress: &str| Observed::Held {
        sha: "f".repeat(40),
        body: body(progress),
    };

    let took = turn(
        &terms,
        &observed("1700000000.1700000030"),
        "clone-b",
        stalled_for,
        stalled_for,
        stall,
        1_999_999,
    );
    assert!(
        matches!(took, Turn::Take(_)),
        "a live-but-stalled holder is stealable: {took:?}"
    );

    // THE DISARMED SHAPE, which is what every lease in the fleet looked like.
    let waited = turn(
        &terms,
        &observed(""),
        "clone-b",
        stalled_for,
        stalled_for,
        stall,
        1_999_999,
    );
    assert_eq!(
        waited,
        Turn::Wait,
        "an empty token is what made a stalled holder unstealable"
    );
}

/// A wait whose checks keep moving keeps publishing a NEW token.
///
/// The regression case for the hazard the first version of this change
/// introduced (CLOUD-1703). `guard.phase` pushes once per step, so nothing inside
/// `Step::Wait` moved `phase_since` — a lap watching CI for longer than the stall
/// bound published one unchanging token, and a rival could take its lease. The
/// wait now pushes the poll's signature as `Signal::Sig`, and `stamp_for` moves
/// the stamp only when the value changes, so a matrix that is completing checks
/// keeps advancing.
#[test]
fn a_wait_whose_checks_move_keeps_advancing() {
    let dir = repo("lease-health-wait-advances");
    let git_dir = dir.join(".git");
    let pid = std::process::id();
    let pid_text = pid.to_string();
    std::fs::create_dir_all(git_dir.join("batten-tasks")).expect("registry dir");
    std::fs::write(
        git_dir.join("batten-tasks").join(&pid_text),
        format!("task: land\npid: {pid_text}\nphase: wait\nphase_since: 1700000000\ntick_at: 0\nsig_at: 0\n"),
    )
    .expect("registry entry");

    batten::task::push(
        &git_dir,
        &pid_text,
        batten::task::Signal::Sig,
        "7",
        1_700_001_000,
    );
    let first =
        batten::lease::own_progress(&git_dir, pid).expect("a token after the first reading");

    batten::task::push(
        &git_dir,
        &pid_text,
        batten::task::Signal::Sig,
        "9",
        1_700_002_000,
    );
    let moved = batten::lease::own_progress(&git_dir, pid).expect("a token after the world moved");

    assert_ne!(
        first, moved,
        "a check run completing must advance the published token, or a healthy wait reads as a stall"
    );
}

/// A wait where nothing moves keeps publishing the SAME token, and that is the
/// half that must not be traded away to fix the case above.
///
/// `Signal::Tick` would satisfy the previous case and break this one: the token
/// is `{advance}.{tick_at}`, so a tick pushed every poll moves it every poll and
/// a holder that beats without landing becomes unstealable again — the exact
/// defect this row exists to close. Only a signal that moves when the WORLD moves
/// answers both, which is what `Sig` is for.
#[test]
fn a_wait_where_nothing_moves_republishes_the_same_token() {
    let dir = repo("lease-health-wait-frozen");
    let git_dir = dir.join(".git");
    let pid = std::process::id();
    let pid_text = pid.to_string();
    std::fs::create_dir_all(git_dir.join("batten-tasks")).expect("registry dir");
    std::fs::write(
        git_dir.join("batten-tasks").join(&pid_text),
        format!("task: land\npid: {pid_text}\nphase: wait\nphase_since: 1700000000\ntick_at: 0\nsig_at: 0\n"),
    )
    .expect("registry entry");

    batten::task::push(
        &git_dir,
        &pid_text,
        batten::task::Signal::Sig,
        "7",
        1_700_001_000,
    );
    let first =
        batten::lease::own_progress(&git_dir, pid).expect("a token after the first reading");

    // The same reading, an hour later: the poll went round and learned nothing.
    batten::task::push(
        &git_dir,
        &pid_text,
        batten::task::Signal::Sig,
        "7",
        1_700_005_000,
    );
    let still = batten::lease::own_progress(&git_dir, pid).expect("a token after a quiet hour");

    assert_eq!(
        first, still,
        "a poll that learns nothing must not advance the token, or nothing is ever stealable"
    );
}
