//! `batten offbox run` over the compiled binary (CLOUD-2721).
//!
//! Each case starts the daemon as a child, which is what an agent does, and
//! kills it. The fixture's origin is a local path, so no push is ever tried:
//! what is under test is the process — its lock, its status file, its inbox —
//! and the backoff and the loop are exercised beside the code over a simulated
//! clock.

use std::path::{Path, PathBuf};
use std::process::Child;

use batten::offbox::{self, StatusFile};
use batten::session::STATE_REPO_ENV;

use crate::common::{StateHome as _, batten, git_in, scratch, scratch_repo, stdout};

/// How many 50 ms looks a wait takes before it is a failure: fifteen seconds,
/// which is three of the daemon's five-second wakes.
const LOOKS: u32 = 300;

/// A checkout with a local-path origin and its own state home.
struct Checkout {
    repo: PathBuf,
    home: PathBuf,
}

impl Checkout {
    fn new(name: &str) -> Self {
        let repo = scratch_repo(name);
        git_in(&repo, &["remote", "add", "origin", "/srv/git/widgets.git"]);
        Checkout {
            repo,
            home: scratch(&format!("{name}-home")),
        }
    }

    fn launch(&self, harness: &str, session: &str) -> Child {
        batten()
            .args(["offbox", "run", "--session", session, "--harness", harness])
            .current_dir(&self.repo)
            .env(STATE_REPO_ENV, "example/state")
            .state_home(&self.home)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the daemon")
    }

    /// The checkout's off-box directory, once something has made it.
    fn offbox(&self) -> Option<PathBuf> {
        let root = self.home.join("data").join("batten");
        std::fs::read_dir(root)
            .ok()?
            .flatten()
            .map(|entry| entry.path().join(offbox::DIR))
            .find(|dir| dir.is_dir())
    }

    fn status(&self) -> Option<StatusFile> {
        let text = std::fs::read_to_string(self.offbox()?.join(offbox::STATUS)).ok()?;
        Some(StatusFile::parse(&text))
    }

    /// The status file once `ready` holds of it.
    fn status_when(&self, what: &str, ready: impl Fn(&StatusFile) -> bool) -> StatusFile {
        eventually(what, || self.status().filter(|status| ready(status)))
    }
}

/// Look every 50 ms until `look` answers, and fail naming `what` if it never does.
fn eventually<T>(what: &str, look: impl Fn() -> Option<T>) -> T {
    for _ in 0..LOOKS {
        if let Some(found) = look() {
            return found;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a bounded poll: it exits when `look` answers, and `LOOKS` turns a daemon that never got there into a failed assertion rather than a hang"
        )]
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("never saw: {what}");
}

fn kill(mut child: Child) {
    child.kill().expect("kill the daemon");
    child.wait().expect("reap the daemon");
}

fn running(child: &mut Child) -> bool {
    child.try_wait().expect("look at the daemon").is_none()
}

/// Fails by: an unset variable starting a daemon or leaving a directory.
#[test]
fn unset_is_off_and_leaves_no_directory() {
    let checkout = Checkout::new("offbox-daemon-unset");
    let output = batten()
        .args(["offbox", "run", "--session", "s", "--harness", "exit-code"])
        .current_dir(&checkout.repo)
        .state_home(&checkout.home)
        .output()
        .expect("run batten offbox run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "off\n");
    assert!(checkout.offbox().is_none(), "off must leave no trace");
}

/// Fails by: a status file that does not say which process and which session.
#[test]
fn the_status_file_names_the_daemons_pid_and_session() {
    let checkout = Checkout::new("offbox-daemon-status");
    let mut child = checkout.launch("exit-code", "a ../ session");

    let status = checkout.status_when("a status file", |status| status.pid != 0);

    assert_eq!(status.pid, child.id());
    assert_eq!(status.session, offbox::leaf("exit-code", "a ../ session"));
    assert_eq!(status.attached, "no-origin");
    assert_eq!(status.source, "ok");
    assert_eq!(status.restored, "none");
    assert_eq!(status.pushed, "-");
    assert!(running(&mut child));
    kill(child);
}

/// Fails by: two daemons in one checkout, or the second taking the first down.
#[test]
fn a_second_daemon_in_one_checkout_says_running_and_exits() {
    let checkout = Checkout::new("offbox-daemon-second");
    let mut first = checkout.launch("exit-code", "s");
    checkout.status_when("the first daemon's status", |status| {
        status.pid == first.id()
    });

    let second = checkout
        .launch("exit-code", "s")
        .wait_with_output()
        .expect("the second daemon returns");

    assert_eq!(second.status.code(), Some(0));
    assert_eq!(stdout(&second), "running\n");
    assert!(running(&mut first), "the first is still running");
    assert_eq!(checkout.status().unwrap().pid, first.id());
    kill(first);
}

/// Fails by: the hook's instant on the lock reading as another daemon.
#[test]
fn a_lock_probed_at_start_does_not_stop_the_daemon() {
    let checkout = Checkout::new("offbox-daemon-probed");
    // Find where the lock will be by letting one daemon make the directory.
    let scout = checkout.launch("exit-code", "s");
    let dir = eventually("the off-box directory", || checkout.offbox());
    checkout.status_when("the scout's status", |status| status.pid != 0);
    kill(scout);

    let lock = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join(offbox::LOCK))
        .expect("open the lock");
    // HELD, so the daemon's first try certainly fails; then taken and released
    // every 10 ms, as a run of tool calls would.
    fs4::FileExt::lock(&lock).expect("take the lock");
    let mut child = checkout.launch("exit-code", "s");
    let prober = std::thread::spawn(move || {
        pause(300);
        for _ in 0..40 {
            fs4::FileExt::unlock(&lock).expect("release");
            pause(9);
            if fs4::FileExt::try_lock(&lock).is_ok() {
                pause(1);
            }
        }
        let _ = fs4::FileExt::unlock(&lock);
    });

    let status = checkout.status_when("the probed daemon's status", |status| {
        status.pid == child.id()
    });
    prober.join().expect("the prober finishes");

    assert_eq!(status.pid, child.id());
    assert!(running(&mut child), "it took the lock and runs");
    kill(child);
}

fn pause(millis: u64) {
    #[expect(
        clippy::disallowed_methods,
        reason = "the hold and the gap of a lock taken and released on a beat: the loop that calls this runs a fixed `40` rounds and ends"
    )]
    std::thread::sleep(std::time::Duration::from_millis(millis));
}

/// Fails by: a kill leaving a status file that will not parse, or a daemon
/// that will not start again.
#[test]
fn a_killed_daemon_leaves_a_status_file_and_starts_again() {
    let checkout = Checkout::new("offbox-daemon-killed");
    // Three moments: as soon as the status names it, a little after, and after
    // the inbox has been written to.
    for round in 0..3_u32 {
        let child = checkout.launch("exit-code", "s");
        let id = child.id();
        checkout.status_when("the daemon's own status", |status| status.pid == id);
        if round == 1 {
            pause(120);
        }
        if round == 2 {
            append(&checkout.offbox().unwrap().join(offbox::INBOX), "x\n");
        }
        kill(child);

        let left = checkout.status().expect("the status file parses");
        assert_eq!(left.pid, id, "round {round}");
        assert_eq!(left.session, offbox::leaf("exit-code", "s"));
    }
    let mut last = checkout.launch("exit-code", "s");
    checkout.status_when("a daemon after three kills", |status| {
        status.pid == last.id()
    });
    assert!(running(&mut last));
    kill(last);
}

fn append(path: &Path, text: &str) {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open the inbox")
        .write_all(text.as_bytes())
        .expect("append to the inbox");
}

/// Fails by: the daemon not seeing what the hook appended.
#[test]
fn the_daemon_reads_the_inboxs_length_within_two_wakes() {
    let checkout = Checkout::new("offbox-daemon-inbox");
    let child = checkout.launch("exit-code", "s");
    checkout.status_when("the daemon's status", |status| status.pid == child.id());
    let inbox = checkout.offbox().unwrap().join(offbox::INBOX);
    eventually("an emptied inbox", || inbox.is_file().then_some(()));

    for line in 0..10 {
        append(&inbox, &format!("{line}\n"));
    }

    let status = checkout.status_when("the inbox's length in the status", |status| {
        status.inbox_read == 20
    });
    assert_eq!(status.inbox_read, std::fs::metadata(&inbox).unwrap().len());
    kill(child);
}

/// Fails by: a harness with no session source stopping the daemon.
#[test]
fn a_harness_with_no_source_is_not_surveyed_and_the_daemon_runs() {
    let checkout = Checkout::new("offbox-daemon-unsurveyed");
    let mut child = checkout.launch("cursor", "s");

    let status = checkout.status_when("the daemon's status", |status| status.pid != 0);

    assert_eq!(status.source, "not-surveyed");
    assert!(running(&mut child));
    kill(child);
}
