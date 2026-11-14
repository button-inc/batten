//! What the hook does about the off-box daemon (CLOUD-2736), over the compiled
//! binary.
//!
//! The test plays the daemon: it holds or frees the lock and writes `status`
//! and `note` itself. No daemon is ever started — and the last cases here are
//! that the hook starts none either. Payloads are Claude Code's unless a case
//! says otherwise.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Output;

use batten::offbox_watch::{self, Seen};
use batten::session::STATE_REPO_ENV;

use crate::common::{self, StateHome as _, batten, scratch, stderr, stdout};

const SESSION: &str = "sess-offbox-1";
const TRANSCRIPT: &str = "/transcripts/projects/-repo/sess-offbox-1.jsonl";
const DOWN: &str = "spawn run missing";
const FOREGROUND: &str = "spawn run blocked";

/// A checkout, its state home, and the off-box directory the hook will use.
struct Rig {
    repo: PathBuf,
    home: PathBuf,
    harness: &'static str,
    /// Whether the variable is set for the hook.
    set: bool,
}

/// What one hook call answered.
struct Said {
    code: Option<i32>,
    text: String,
}

impl Said {
    /// Whether the call was refused under `class`, on either decision channel:
    /// Claude Code refuses in band, the neutral contract by exit 2.
    fn denied(&self, class: &str) -> bool {
        let in_band = self.text.contains("permissionDecision") && self.text.contains("\"deny\"");
        (in_band || self.code == Some(2)) && self.text.contains(class)
    }

    fn refused_at_all(&self) -> bool {
        (self.text.contains("permissionDecision") && self.text.contains("\"deny\""))
            || self.code == Some(2)
    }
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

    fn hook(&self, payload: &str) -> Said {
        let mut command = batten();
        command.state_home(&self.home);
        if self.set {
            command.env(STATE_REPO_ENV, "example/state");
        }
        let out: Output = common::stdin_run(
            &mut command,
            &self.repo,
            &["adjudicate", "--harness", self.harness],
            payload,
        );
        Said {
            code: out.status.code(),
            text: format!("{}\n{}", stdout(&out), stderr(&out)),
        }
    }

    fn cwd(&self) -> String {
        serde_json::to_string(&self.repo.to_string_lossy()).unwrap()
    }

    fn post(&self) -> Said {
        self.hook(&format!(
            "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Bash\",\"session_id\":\"{SESSION}\",\
             \"transcript_path\":\"{TRANSCRIPT}\",\"cwd\":{},\
             \"tool_input\":{{\"command\":\"true\"}},\"tool_response\":{{\"stdout\":\"\"}}}}",
            self.cwd()
        ))
    }

    fn pre_with(&self, command: &str, background: bool, transcript: bool) -> Said {
        let transcript = if transcript {
            format!("\"transcript_path\":\"{TRANSCRIPT}\",")
        } else {
            String::new()
        };
        self.hook(&format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"session_id\":\"{SESSION}\",\
             {transcript}\"cwd\":{},\"tool_input\":{{\"command\":{},\"run_in_background\":{background}}}}}",
            self.cwd(),
            serde_json::to_string(command).unwrap()
        ))
    }

    fn pre(&self) -> Said {
        self.pre_with("true", false, true)
    }

    fn start(&self) -> Said {
        self.hook(&format!(
            "{{\"hook_event_name\":\"SessionStart\",\"session_id\":\"{SESSION}\",\
             \"transcript_path\":\"{TRANSCRIPT}\",\"cwd\":{},\"source\":\"startup\"}}",
            self.cwd()
        ))
    }

    /// The off-box directory, wherever under the state home it is.
    fn dir(&self) -> Option<PathBuf> {
        std::fs::read_dir(self.home.join("data").join("batten"))
            .ok()?
            .flatten()
            .map(|entry| entry.path().join(offbox_watch::DIR))
            .find(|dir| dir.is_dir())
    }

    /// The off-box directory, made by one post-tool call where it is not there.
    fn made(&self) -> PathBuf {
        if self.dir().is_none() {
            self.post();
            let dir = self.dir().expect("a post-tool call makes the directory");
            Seen::default().write(&dir).unwrap();
            std::fs::write(dir.join(offbox_watch::INBOX), "").unwrap();
        }
        self.dir().unwrap()
    }

    fn seen(&self) -> Seen {
        Seen::read(&self.dir().expect("the off-box directory"))
    }

    /// Hold the daemon's lock, as a running daemon does.
    fn hold(&self) -> File {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.made().join(offbox_watch::LOCK))
            .unwrap();
        fs4::FileExt::try_lock(&lock).expect("take the daemon's lock");
        lock
    }

    /// Write a status file as a daemon for `session` at `pid` would.
    fn status(&self, session: &str, inbox_read: Option<u64>, attached: &str) {
        let read = inbox_read.map_or_else(String::new, |read| format!("inbox_read {read}\n"));
        let text = format!(
            "pid 4242\nsession {}\n{read}attached {attached}\n",
            offbox_watch::leaf(self.harness, session)
        );
        std::fs::write(self.made().join(offbox_watch::STATUS), text).unwrap();
    }

    fn inbox_len(&self) -> u64 {
        std::fs::metadata(self.made().join(offbox_watch::INBOX)).map_or(0, |meta| meta.len())
    }

    fn relaunch(&self, transcript: bool) -> String {
        offbox_watch::relaunch(SESSION, self.harness, transcript.then_some(TRANSCRIPT))
    }
}

/// Fails by: a tool call the daemon never hears of.
#[test]
fn a_post_tool_call_appends_one_line_naming_the_session() {
    let rig = Rig::new("offbox-hook-message");
    rig.post();
    let inbox = std::fs::read_to_string(rig.dir().unwrap().join(offbox_watch::INBOX)).unwrap();
    assert_eq!(inbox, format!("{SESSION}\n"));
    rig.post();
    assert_eq!(rig.inbox_len(), 2 * (SESSION.len() as u64 + 1));
}

/// Fails by: a dead daemon going unreported, or the report naming no remedy.
#[test]
fn a_dead_daemon_is_advised_on_the_next_reply_that_carries_advice() {
    let rig = Rig::new("offbox-hook-advised");
    rig.post();
    assert_eq!(rig.seen().misses, 1);

    let said = rig.pre();

    assert!(said.text.contains(DOWN), "{}", said.text);
    assert!(
        said.text.contains("offbox daemon not running"),
        "{}",
        said.text
    );
    assert!(said.text.contains(&rig.relaunch(true)), "{}", said.text);
    assert!(
        !said.refused_at_all(),
        "advice, inside the grace: {}",
        said.text
    );
    // Told once per miss, not on every call after it.
    let again = rig.pre();
    assert!(!again.text.contains(DOWN), "{}", again.text);
}

/// Fails by: a session that starts with no daemon not being told so, or the
/// telling counting as a miss.
#[test]
fn a_session_start_with_no_daemon_is_advised_and_counts_nothing() {
    let rig = Rig::new("offbox-hook-start");
    let said = rig.start();
    assert!(said.text.contains(DOWN), "{}", said.text);
    assert!(said.text.contains(&rig.relaunch(true)), "{}", said.text);
    // The start may leave the owed-stamp file (CLOUD-2723); it counts no miss.
    assert_eq!(rig.dir().map_or(0, |dir| Seen::read(&dir).misses), 0);
}

/// Fails by: a refusal before the agent has had its five calls.
#[test]
fn a_dead_daemon_is_allowed_inside_the_grace() {
    let rig = Rig::new("offbox-hook-grace");
    for _ in 0..4 {
        rig.post();
    }
    assert_eq!(rig.seen().misses, 4);
    assert!(!rig.pre().refused_at_all());
}

/// Fails by: a dead daemon never refused, or a remedy that is not the command
/// to run, byte for byte.
#[test]
fn a_dead_daemon_is_denied_after_the_grace_with_the_relaunch_command() {
    let rig = Rig::new("offbox-hook-denied");
    for _ in 0..5 {
        rig.post();
    }
    assert_eq!(rig.seen().misses, 5);

    let with = rig.pre();
    assert!(with.denied(DOWN), "{}", with.text);
    let command = format!("batten offbox run --session {SESSION} --harness claude-code");
    assert!(
        with.text
            .contains(&format!("{command} --transcript {TRANSCRIPT}")),
        "{}",
        with.text
    );

    let without = rig.pre_with("true", false, false);
    assert!(without.denied(DOWN), "{}", without.text);
    assert!(without.text.contains(&command), "{}", without.text);
    assert!(!without.text.contains("--transcript"), "{}", without.text);
}

/// Fails by: the one command that fixes it being refused, or being let run in
/// the foreground where it would hold the turn.
#[test]
fn the_relaunch_command_is_admitted_only_in_the_background() {
    let rig = Rig::new("offbox-hook-relaunch");
    for _ in 0..5 {
        rig.post();
    }
    let command = rig.relaunch(true);

    let background = rig.pre_with(&command, true, true);
    assert!(!background.refused_at_all(), "{}", background.text);

    let foreground = rig.pre_with(&command, false, true);
    assert!(foreground.denied(FOREGROUND), "{}", foreground.text);
    assert!(
        foreground.text.contains("background"),
        "{}",
        foreground.text
    );
}

/// Fails by: a count left over from before the relaunch denying a live daemon.
#[test]
fn a_relaunched_daemon_is_seen_at_once_whatever_the_count() {
    let rig = Rig::new("offbox-hook-race");
    for _ in 0..5 {
        rig.post();
    }
    assert!(rig.pre().refused_at_all(), "the premise: denied");
    let _lock = rig.hold();
    rig.status(SESSION, Some(rig.inbox_len()), "yes");

    // No post-tool call in between: the count still reads 5.
    assert_eq!(rig.seen().misses, 5);
    let said = rig.pre();
    assert!(!said.refused_at_all(), "{}", said.text);

    // And the next post-tool call that finds it alive clears the count.
    rig.status(
        SESSION,
        Some(rig.inbox_len() + SESSION.len() as u64 + 1),
        "yes",
    );
    rig.post();
    assert_eq!(rig.seen().misses, 0);
    assert!(!rig.pre().refused_at_all());
}

/// Fails by: a daemon that holds the lock and reads nothing passing as alive.
#[test]
fn a_daemon_far_behind_its_inbox_is_stuck_and_the_remedy_kills_it() {
    let rig = Rig::new("offbox-hook-stuck");
    let _lock = rig.hold();
    let dir = rig.made();
    // EXACTLY 16 KiB past what it read, after this call's own line: alive.
    let line = SESSION.len() as u64 + 1;
    std::fs::write(
        dir.join(offbox_watch::INBOX),
        "x".repeat(usize::try_from(offbox_watch::BEHIND - line).unwrap()),
    )
    .unwrap();
    rig.status(SESSION, Some(0), "yes");
    rig.post();
    assert_eq!(rig.seen().misses, 0, "at the boundary it is alive");
    // A status file with no `inbox_read` line is a daemon at its start: alive.
    rig.status(SESSION, None, "yes");
    rig.post();
    assert_eq!(rig.seen().misses, 0);

    // One line further and it is stuck.
    rig.status(SESSION, Some(0), "yes");
    for _ in 0..5 {
        rig.post();
    }
    assert_eq!(rig.seen().misses, 5);
    let said = rig.pre();
    assert!(said.denied(DOWN), "{}", said.text);
    assert!(said.text.contains("offbox daemon stuck"), "{}", said.text);
    assert!(said.text.contains("kill 4242"), "{}", said.text);
    let kill = rig.pre_with("kill 4242", false, true);
    assert!(!kill.refused_at_all(), "{}", kill.text);
}

/// Fails by: a daemon serving another session passing as this one's.
#[test]
fn a_daemon_serving_another_session_is_reported_and_then_denied() {
    let rig = Rig::new("offbox-hook-other");
    let _lock = rig.hold();
    rig.status("some-other-session", Some(u64::MAX / 2), "yes");
    rig.post();
    assert_eq!(rig.seen().misses, 1);
    let advised = rig.pre();
    assert!(
        advised
            .text
            .contains("offbox daemon serving another session"),
        "{}",
        advised.text
    );
    assert!(advised.text.contains("kill 4242"), "{}", advised.text);
    for _ in 0..4 {
        rig.post();
    }
    let said = rig.pre();
    assert!(said.denied(DOWN), "{}", said.text);
    assert!(said.text.contains("kill 4242"), "{}", said.text);
}

/// Fails by: another hook's instant on the lock reading as a daemon.
#[test]
fn a_shared_hold_on_the_lock_is_not_a_daemon() {
    let rig = Rig::new("offbox-hook-shared");
    let lock = File::open({
        let path = rig.made().join(offbox_watch::LOCK);
        std::fs::write(&path, "").unwrap();
        path
    })
    .unwrap();
    fs4::FileExt::try_lock_shared(&lock).expect("a shared hold, as a parallel hook takes");

    rig.post();

    assert_eq!(rig.seen().misses, 1, "still dead");
}

/// Fails by: a host that may have no way to run a daemon being refused for
/// not running one.
#[test]
fn a_host_with_no_known_background_facility_is_advised_and_never_denied() {
    let mut rig = Rig::new("offbox-hook-neutral");
    rig.harness = "exit-code";
    for _ in 0..7 {
        rig.post();
    }
    assert_eq!(rig.seen().misses, 7, "the count still runs");
    let said = rig.pre();
    assert!(!said.refused_at_all(), "{:?} {}", said.code, said.text);
}

/// Fails by: the attach note being repeated on every call, never delivered, or
/// an unreachable state repository denying anything.
#[test]
fn the_attach_note_is_relayed_once_and_denies_nothing() {
    let rig = Rig::new("offbox-hook-note");
    let _lock = rig.hold();
    let note = "offbox: the state repository example/state cannot be written from here.";
    std::fs::write(rig.made().join(offbox_watch::NOTE), format!("{note}\n")).unwrap();
    rig.status(SESSION, Some(u64::MAX / 2), "no");

    let first = rig.pre();
    assert!(first.text.contains(note), "{}", first.text);
    assert!(!first.refused_at_all());
    let second = rig.pre();
    assert!(!second.text.contains(note), "{}", second.text);

    rig.status(SESSION, Some(u64::MAX / 2), "yes");
    rig.pre();
    rig.status(SESSION, Some(u64::MAX / 2), "no");
    let again = rig.pre();
    assert!(again.text.contains(note), "{}", again.text);
    assert!(!again.refused_at_all());
}

/// Fails by: the hook opening a file for a feature that is switched off.
#[test]
fn unset_opens_no_file_and_denies_nothing() {
    let mut rig = Rig::new("offbox-hook-unset");
    rig.set = false;
    for _ in 0..25 {
        rig.post();
    }
    assert!(rig.dir().is_none(), "off leaves no directory");
    assert!(!rig.pre().refused_at_all());
    assert!(!rig.start().text.contains(DOWN));
}

/// Fails by: the hook starting the daemon, or any process, for the agent.
#[test]
fn the_hook_starts_no_process() {
    let rig = Rig::new("offbox-hook-spawns");
    // A `batten` first on PATH that records being started: the hook must never
    // reach for it.
    let shims = scratch("offbox-hook-spawns-shims");
    let log = shims.join("started.log");
    write_shim(&shims.join("batten"), &log);
    let path = std::env::join_paths(std::iter::once(shims.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let call = |payload: String| {
        let mut command = batten();
        command
            .state_home(&rig.home)
            .env(STATE_REPO_ENV, "example/state")
            .env("PATH", &path);
        common::stdin_run(
            &mut command,
            &rig.repo,
            &["adjudicate", "--harness", "claude-code"],
            &payload,
        )
    };
    let cwd = rig.cwd();
    for _ in 0..6 {
        call(format!(
            "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Bash\",\"session_id\":\"{SESSION}\",\
             \"cwd\":{cwd},\"tool_input\":{{\"command\":\"true\"}},\"tool_response\":{{\"stdout\":\"\"}}}}"
        ));
        call(format!(
            "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\"session_id\":\"{SESSION}\",\
             \"cwd\":{cwd},\"tool_input\":{{\"command\":\"true\"}}}}"
        ));
    }
    call(format!(
        "{{\"hook_event_name\":\"SessionStart\",\"session_id\":\"{SESSION}\",\"cwd\":{cwd},\"source\":\"startup\"}}"
    ));

    assert!(!log.exists(), "the hook started `batten`");
    let dir = rig.dir().unwrap();
    assert!(
        !dir.join(offbox_watch::STATUS).exists(),
        "no daemon wrote a status"
    );
    // Nothing holds the lock: it does not even exist, since only a daemon makes it.
    assert_eq!(
        offbox_watch::probe(&dir, None),
        offbox_watch::Liveness::Dead
    );
    assert!(!dir.join(offbox_watch::LOCK).exists());
}

fn write_shim(path: &Path, log: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(
        path,
        format!("#!/bin/sh\necho started >> '{}'\nexit 0\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Fails by: a call this repository's own rows pre-approve walking past the
/// gate. Found live: under the committed config an ordinary command is granted,
/// not merely allowed, and the first build of this gate read only a plain allow.
#[test]
fn a_call_the_repository_grants_is_still_denied_after_the_grace() {
    let mut rig = Rig::new("offbox-hook-granted");
    rig.repo = common::committed_fixture_with_protected("offbox-hook-granted-committed");
    for _ in 0..5 {
        rig.post();
    }
    assert_eq!(rig.seen().misses, 5);
    let said = rig.pre();
    assert!(said.denied(DOWN), "{}", said.text);
    assert!(said.text.contains(&rig.relaunch(true)), "{}", said.text);
}

/// Fails by: this repository's own rules refusing the command the gate tells
/// the agent to run.
#[test]
fn the_remedies_pass_this_repositorys_own_rules() {
    let mut rig = Rig::new("offbox-hook-own-rules");
    rig.repo = common::committed_fixture_with_protected("offbox-hook-own-rules-committed");
    for (command, background) in [
        (rig.relaunch(true), true),
        (rig.relaunch(false), true),
        (offbox_watch::kill("4242"), false),
    ] {
        let said = rig.pre_with(&command, background, command.contains("--transcript"));
        assert!(!said.refused_at_all(), "{command}: {}", said.text);
    }
}
