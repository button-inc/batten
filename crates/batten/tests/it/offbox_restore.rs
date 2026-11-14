//! `batten offbox restore` and the session stamp it holds back (CLOUD-2723),
//! over the compiled binary.
//!
//! The restore itself is exercised beside the code, over the transport
//! stand-in. Here: the verb's answers before any transport, and the hook's
//! half — a session start that owes its stamp until the restore has an
//! answer. The test plays the daemon by writing the files it would.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use batten::offbox_watch;
use batten::session::STATE_REPO_ENV;

use crate::common::{self, StateHome as _, batten, git_in, scratch, scratch_repo, stdout};

const SESSION: &str = "sess-restore-1";

struct Rig {
    repo: PathBuf,
    home: PathBuf,
    harness: &'static str,
    set: bool,
}

impl Rig {
    fn new(name: &str) -> Self {
        Rig {
            repo: common::adjudicable_with(name, ""),
            home: scratch(&format!("{name}-home")),
            harness: "claude-code",
            set: true,
        }
    }

    fn hook(&self, event: &str, rest: &str) {
        let mut command = batten();
        command.state_home(&self.home);
        if self.set {
            command.env(STATE_REPO_ENV, "example/state");
        }
        let payload = format!(
            "{{\"hook_event_name\":\"{event}\",\"session_id\":\"{SESSION}\",\"cwd\":{}{rest}}}",
            serde_json::to_string(&self.repo.to_string_lossy()).unwrap()
        );
        let _ = common::stdin_run(
            &mut command,
            &self.repo,
            &["adjudicate", "--harness", self.harness],
            &payload,
        );
    }

    fn start(&self) {
        self.hook("SessionStart", ",\"source\":\"startup\"");
    }

    fn pre(&self) {
        self.hook(
            "PreToolUse",
            ",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"true\"}",
        );
    }

    fn offbox(&self) -> PathBuf {
        batten::state::repo_state_dir_under(
            &self.home.join("data"),
            &self.repo.canonicalize().unwrap(),
        )
        .unwrap()
        .join(offbox_watch::DIR)
    }

    fn stamp(&self) -> PathBuf {
        self.repo.join(".git/batten-receipts/session-start")
    }

    fn owed(&self) -> PathBuf {
        self.offbox().join(offbox_watch::STAMP_OWED)
    }

    fn record_restore(&self) {
        let path =
            offbox_watch::restored_path(&self.offbox(), &offbox_watch::leaf(self.harness, SESSION));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "none\n").unwrap();
    }

    fn status(&self, restored: &str) {
        std::fs::create_dir_all(self.offbox()).unwrap();
        std::fs::write(
            self.offbox().join(offbox_watch::STATUS),
            format!("pid 1\nrestored {restored}\n"),
        )
        .unwrap();
    }

    /// Date the owed file in the past, so "the stamp carries the session's
    /// start" is told apart from "the stamp carries the moment it was paid".
    fn backdate_owed(&self) -> SystemTime {
        let began = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(self.owed())
            .unwrap()
            .set_modified(began)
            .unwrap();
        began
    }
}

fn modified(path: &Path) -> SystemTime {
    std::fs::metadata(path).unwrap().modified().unwrap()
}

/// Fails by: the stamp written before the restore, which would send the
/// restored receipts aside instead of back in place.
#[test]
fn a_session_start_with_no_restore_record_owes_its_stamp() {
    let rig = Rig::new("offbox-restore-deferred");
    rig.start();
    assert!(!rig.stamp().exists(), "the stamp is held back");
    assert!(rig.owed().exists(), "and recorded as owed");
}

/// Fails by: an owed stamp never paid, or paid dated at the payment.
#[test]
fn an_owed_stamp_is_paid_once_the_restore_is_recorded() {
    let rig = Rig::new("offbox-restore-paid");
    rig.start();
    let began = rig.backdate_owed();
    rig.record_restore();

    rig.pre();

    assert!(rig.stamp().exists(), "paid");
    assert!(!rig.owed().exists(), "and no longer owed");
    assert_eq!(
        modified(&rig.stamp()),
        began,
        "dated at the session's start"
    );
}

/// Fails by: a daemon that cannot restore leaving the session unable to claim.
#[test]
fn an_owed_stamp_is_paid_when_the_restore_is_unavailable() {
    let rig = Rig::new("offbox-restore-unavailable");
    rig.start();
    let began = rig.backdate_owed();
    rig.status("unavailable");

    rig.pre();

    assert!(rig.stamp().exists());
    assert!(!rig.owed().exists());
    assert_eq!(modified(&rig.stamp()), began);
}

/// Fails by: the stamp written while the restore may still put receipts back.
/// With no stamp, `claim check` refuses `no-session-stamp`; `claim.rs` holds
/// that half.
#[test]
fn an_owed_stamp_is_not_paid_while_the_restore_is_pending() {
    let rig = Rig::new("offbox-restore-pending");
    rig.start();
    rig.status("pending");
    for _ in 0..10 {
        rig.pre();
    }
    assert!(!rig.stamp().exists());
    assert!(rig.owed().exists());
}

/// Fails by: a container that already ran this session being made to wait.
#[test]
fn a_session_already_restored_is_stamped_at_its_start() {
    let rig = Rig::new("offbox-restore-already");
    rig.record_restore();
    rig.start();
    assert!(rig.stamp().exists());
    assert!(!rig.owed().exists());
}

/// Fails by: a host nothing will ever make run the daemon owing a stamp
/// nothing will ever pay.
#[test]
fn a_host_with_no_background_facility_is_stamped_at_once() {
    let mut rig = Rig::new("offbox-restore-neutral");
    rig.harness = "exit-code";
    rig.start();
    assert!(rig.stamp().exists());
    assert!(!rig.owed().exists());
}

/// Fails by: the feature being off changing when a session is stamped.
#[test]
fn unset_stamps_at_session_start_as_before() {
    let mut rig = Rig::new("offbox-restore-unset");
    rig.set = false;
    rig.start();
    assert!(rig.stamp().exists());
    assert!(!rig.offbox().exists(), "off leaves no directory");
}

const RESTORE: [&str; 6] = [
    "offbox",
    "restore",
    "--session",
    "s",
    "--harness",
    "exit-code",
];

/// Fails by: an unset variable touching anything.
#[test]
fn the_verb_is_off_with_the_variable_unset() {
    let repo = scratch_repo("offbox-restore-verb-unset");
    let home = scratch("offbox-restore-verb-unset-home");
    let output = batten()
        .args(RESTORE)
        .current_dir(&repo)
        .state_home(&home)
        .output()
        .expect("run batten offbox restore");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "off\n");
    assert!(
        !home
            .join("data")
            .join("batten")
            .join(offbox_watch::DIR)
            .exists()
    );
}

/// Fails by: a project with no http(s) origin being read from.
#[test]
fn the_verb_refuses_a_local_path_origin() {
    let repo = scratch_repo("offbox-restore-verb-local");
    git_in(&repo, &["remote", "add", "origin", "/srv/git/widgets.git"]);
    let output = batten()
        .args(RESTORE)
        .current_dir(&repo)
        .env(STATE_REPO_ENV, "example/state")
        .output()
        .expect("run batten offbox restore");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "no-http-origin\n");
}
