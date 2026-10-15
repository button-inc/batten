//! A signal does not strand a speculation (CLOUD-1747).
//!
//! # What was measured
//!
//! On #1178 a `land` was stopped mid-verify while it held a bet. The harness's
//! stop sends SIGTERM and hard-kills within three seconds, nothing ran on the way
//! out, and the branch was left carrying another session's commits under this
//! PR's name, with only the next push between them and the remote.
//!
//! # Why the child is this binary
//!
//! A bet is reachable over the compiled `batten` only through a live lease, and
//! `lease::observe` reads one over smart HTTP with no offline seam
//! (`lease_health.rs` records why none is added). So the cases drive the seam a
//! bet arms — `speculation::arm` — in a child process that is this test binary
//! re-run on one ignored case, and deliver a real SIGTERM to it. The process dies
//! of the signal either way; what the parent reads is the repository it left.
//!
//! # The two kills, and which half answers each
//!
//! A catchable signal is `arm`'s: the unwind runs at the signal. A SIGKILL cannot
//! be caught, so the next lap answers it: `speculation::recover` adopts the
//! stranded ref, and that case is here too, because nothing else covered it.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::{BufRead as _, Write as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use batten::speculation::{self, BASE_REF, Bet};

/// The repository the child arms over.
const CHILD: &str = "BATTEN_LAND_SIGNAL_CHILD";
/// The head the child's unwind restores.
const UNDO: &str = "BATTEN_LAND_SIGNAL_UNDO";
/// Present when the child settles its bet before the signal.
const SETTLED: &str = "BATTEN_LAND_SIGNAL_SETTLED";
/// What the child prints once armed; spelled so no case name contains it.
const ARMED: &str = "BATTEN-UNWIND-ARMED";

/// A branch `work` whose own head is `own`, then carrying one borrowed commit,
/// with the bet recorded under [`BASE_REF`] — the tree `place_the_bet` leaves.
fn speculating(name: &str) -> (PathBuf, String, String) {
    let dir = common::Fixture::at(common::scratch(name).join("repo"))
        .config("version = 1\n")
        .file("own.txt", "this branch\n")
        .git()
        .base_commit()
        .build();
    common::git_in(&dir, &["checkout", "-q", "-b", "work"]);
    let own = common::git_in(&dir, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    std::fs::write(dir.join("borrowed.txt"), "another session\n").expect("write");
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-q", "-m", "borrowed"]);
    let borrowed = common::git_in(&dir, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    common::git_in(&dir, &["update-ref", BASE_REF, &borrowed]);
    (dir, own, borrowed)
}

/// Run the armed child over `dir`, SIGTERM it once it is armed, and return the
/// signal it died of.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is a process dying of a signal, so the child is spawned and signalled as the process it is"
)]
fn terminated(dir: &Path, undo: &str, settled: bool) -> Option<i32> {
    let mut child = std::process::Command::new(std::env::current_exe().expect("this test binary"));
    child
        .args([
            "land_signal::armed_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, dir)
        .env(UNDO, undo)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if settled {
        child.env(SETTLED, "1");
    }
    let mut child = child.spawn().expect("spawn the child");
    let stdout = child.stdout.take().expect("piped stdout");
    let armed = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        // AT THE END of a line, not the whole of one: libtest prints the case's
        // name with no newline before the case runs, so the marker shares it.
        .any(|line| line.ends_with(ARMED));
    assert!(
        armed,
        "the child reports it is armed before it is signalled"
    );
    let sent = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success(), "the signal is delivered");
    child.wait().expect("reap the child").signal()
}

/// The child half: arm the unwind, say so, and wait to be signalled.
///
/// Ignored, because it is not a case: a run that is not spawned by one of the
/// cases below has no repository to arm over, and fails rather than passing
/// over nothing.
#[test]
#[ignore = "the child the cases below spawn; it arms over the repository they name"]
fn armed_child() {
    let dir = std::env::var(CHILD).expect("spawned by a case below, which names the repository");
    let undo = std::env::var(UNDO).expect("the head to unwind to");
    speculation::arm(Path::new(&dir), "work", &undo);
    if std::env::var_os(SETTLED).is_some() {
        speculation::disarm();
    }
    // The parent's pipe, unbuffered by libtest under `--nocapture`.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{ARMED}").expect("tell the parent");
    stdout.flush().expect("tell the parent now");
    loop {
        std::thread::park();
    }
}

/// **A SIGTERM MID-SPECULATION LEAVES THE BRANCH ON ITS OWN HEAD.**
///
/// Both halves of the unwind are asserted: the branch back on its own head, and
/// the bet's ref gone, so the next `land` does not adopt a bet already undone.
/// The process still dies of the signal: the unwind is a step on the way out,
/// never a reason to stay.
#[test]
fn a_sigterm_mid_speculation_leaves_the_branch_on_its_own_head() {
    let (dir, own, _) = speculating("land-signal-unwinds");
    let died = terminated(&dir, &own, false);
    assert_eq!(died, Some(15), "the child still dies of SIGTERM");
    assert_eq!(
        common::git_in(&dir, &["rev-parse", "refs/heads/work"]).trim(),
        own,
        "the borrowed commit is unwound off the branch"
    );
    assert!(
        !dir.join(".git").join(BASE_REF).exists()
            && common::git_in(&dir, &["for-each-ref", BASE_REF])
                .trim()
                .is_empty(),
        "the bet's ref goes with the unwind"
    );
}

/// **THE MIRROR — A SETTLED BET IS NOT UNWOUND BY A LATER SIGNAL.**
///
/// Without this the case above is satisfied by an unwind that fires on every
/// SIGTERM, which would reset a branch whose bet already WON to a head from
/// before it — discarding the linearization the landing is built on.
#[test]
fn a_sigterm_after_the_bet_settled_leaves_the_branch_alone() {
    let (dir, own, borrowed) = speculating("land-signal-settled");
    let died = terminated(&dir, &own, true);
    assert_eq!(
        died,
        Some(15),
        "an unarmed process takes the default action"
    );
    assert_eq!(
        common::git_in(&dir, &["rev-parse", "refs/heads/work"]).trim(),
        borrowed,
        "a settled bet's tree is left as it is"
    );
}

/// **A SIGKILL CANNOT BE CAUGHT, SO THE NEXT LAP ADOPTS WHAT IT STRANDED.**
///
/// `recover` is the predicate the next lap's settle opens with: a recorded base
/// this HEAD is built on is adopted, and a ref naming a commit this tree is not
/// built on is a leftover, not a bet.
#[test]
fn a_stranded_speculation_is_adopted_by_the_next_lap() {
    let (dir, own, borrowed) = speculating("land-signal-stranded");
    let mut bet = Bet::default();
    assert!(
        speculation::recover(&dir, &mut bet).expect("the ref store answers"),
        "a base the branch carries is adopted"
    );
    assert_eq!(bet.base.as_deref(), Some(borrowed.as_str()));
    assert!(bet.recovered && bet.live(), "and settled as a live bet");

    common::git_in(&dir, &["reset", "-q", "--hard", &own]);
    let mut leftover = Bet::default();
    assert!(
        !speculation::recover(&dir, &mut leftover).expect("the ref store answers"),
        "a base this HEAD is not built on is not adopted"
    );
    assert!(!leftover.live());
}
