//! Whether this checkout's off-box daemon is alive, read from four small files
//! (CLOUD-2736).
//!
//! The daemon (`offbox::run`, CLOUD-2721) is started by the agent and can be
//! killed at any time. This module is what notices: the hook calls it on every
//! tool call, and `doctor session` calls the same function, so the two cannot
//! come to disagree about what "alive" means.
//!
//! # It does file operations and nothing else
//!
//! The hook path may not reach `offbox`, `lease`, `fetch` or `gitwrite` — it
//! must never be able to start a process or open a connection — so everything
//! the hook needs to know about the daemon lives here, apart from them: the
//! file names, the session's leaf name, the probe, the hook's own two-line
//! file, and the two remedy commands. `offbox` reads its names from here.
//!
//! # No clock
//!
//! "Stuck" is a count of bytes the daemon has not read, and the grace before a
//! gate is a count of calls. Neither is a duration.

use std::path::Path;

/// The directory, under a checkout's state directory, that holds every file
/// below.
pub const DIR: &str = "offbox";

/// The lock one daemon holds exclusively for its life.
pub const LOCK: &str = "lock";

/// The daemon's status file: one `key value` per line.
pub const STATUS: &str = "status";

/// The file the hook appends one line to per tool call.
pub const INBOX: &str = "inbox";

/// The one line telling an agent how to attach the state repository.
pub const NOTE: &str = "note";

/// The hook's own file: `misses <n>`, `noted <0|1>` and `owed <0|1>`.
pub const HOOK: &str = "hook";

/// The directory, under [`DIR`], holding one directory per session.
pub const SESSIONS: &str = "sessions";

/// A session's restore record, in its own directory: the commit id restored,
/// or `none`. A plain file, so the hook can see it without opening a repository.
pub const RESTORED: &str = "restored";

/// The empty file saying a session's start stamp was held back for a restore.
/// Its modification time is the session's start.
pub const STAMP_OWED: &str = "stamp-owed";

/// Where, under the off-box directory `dir`, the session with this [`leaf`]
/// keeps its restore record.
#[must_use]
pub fn restored_path(dir: &Path, leaf: &str) -> std::path::PathBuf {
    dir.join(SESSIONS).join(leaf).join(RESTORED)
}

/// How far behind the inbox a daemon may be before it is stuck. It reads the
/// inbox every five seconds, so a healthy one is never this far behind.
pub const BEHIND: u64 = 16 * 1024;

/// How many tool calls may find the daemon not alive before a gate may deny.
pub const GRACE: u32 = 5;

/// What a probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// A daemon holds the lock, keeps up with the inbox, and serves this
    /// session.
    Alive,
    /// Nothing holds the lock.
    Dead,
    /// A daemon holds the lock and has not read the inbox for a long way.
    Stuck,
    /// A daemon holds the lock and serves a different session.
    OtherSession,
}

impl Liveness {
    /// The state as an advisory says it; `None` for a daemon that is fine.
    #[must_use]
    pub const fn says(self) -> Option<&'static str> {
        match self {
            Liveness::Alive => None,
            Liveness::Dead => Some("offbox daemon not running"),
            Liveness::Stuck => Some("offbox daemon stuck"),
            Liveness::OtherSession => Some("offbox daemon serving another session"),
        }
    }
}

/// `<harness>-<hash>`: the last segment of a session's ref, the name of its
/// local directory, and what the daemon's status file calls the session it
/// serves. The hash is the first sixteen hex digits of the BLAKE3 of the
/// session id, which is harness-defined and may not be valid in a ref name.
#[must_use]
pub fn leaf(harness: &str, session: &str) -> String {
    let digest = blake3::hash(session.as_bytes()).to_hex();
    format!("{harness}-{}", &digest[..16])
}

/// One key's value in a status file's text, where it has that key.
#[must_use]
pub fn field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (held, value) = line.split_once(' ')?;
        (held == key).then_some(value)
    })
}

/// Whether the daemon for the checkout whose off-box directory is `dir` is
/// alive, and for `session` — a [`leaf`] — where one is given.
///
/// **It creates nothing.** With no directory, or no lock file, it answers
/// [`Liveness::Dead`] and leaves them absent.
///
/// The lock is tried **shared** and released at once: hooks running in
/// parallel never make each other's attempt fail, and only the daemon's
/// exclusive lock does.
///
/// A status file with no `inbox_read` line — which a daemon has for an instant
/// at start — is not stuck, and one with no `session` line serves this session.
/// [`Liveness::OtherSession`] is never returned without a `session` to compare.
//MUTANT-SUITE crates/batten/tests/it/offbox_hook.rs
//MUTANT held-lock-far-behind-reads-alive|s@^    if behind > BEHIND {$@    if false {@|a_daemon_far_behind_its_inbox_is_stuck_and_the_remedy_kills_it
//MUTANT other-session-daemon-reads-alive|s@^        \&\& serving != session$@        \&\& false@|a_daemon_serving_another_session_is_reported_and_then_denied
//MUTANT-SUITE crates/batten/tests/it/doctor_session.rs
//MUTANT stuck-threshold-off-by-one|s@^    if behind > BEHIND {$@    if behind >= BEHIND {@|a_daemon_is_stuck_one_byte_past_sixteen_kibibytes
//MUTANT-SUITE crates/batten/tests/it/offbox_hook.rs
//MUTANT probe-takes-the-lock-exclusively|s@^    if fs4::FileExt::try_lock_shared(\&lock).is_ok() {$@    if fs4::FileExt::try_lock(\&lock).is_ok() {@|a_shared_hold_on_the_lock_is_not_a_daemon
#[must_use]
pub fn probe(dir: &Path, session: Option<&str>) -> Liveness {
    let Ok(lock) = std::fs::File::open(dir.join(LOCK)) else {
        return Liveness::Dead;
    };
    if fs4::FileExt::try_lock_shared(&lock).is_ok() {
        let _ = fs4::FileExt::unlock(&lock);
        return Liveness::Dead;
    }
    let status = std::fs::read_to_string(dir.join(STATUS)).unwrap_or_default();
    if let (Some(session), Some(serving)) = (session, field(&status, "session"))
        && serving != session
    {
        return Liveness::OtherSession;
    }
    let Some(read) = field(&status, "inbox_read").and_then(|value| value.parse::<u64>().ok())
    else {
        return Liveness::Alive;
    };
    let inbox = std::fs::metadata(dir.join(INBOX)).map_or(0, |meta| meta.len());
    let behind = inbox.saturating_sub(read);
    if behind > BEHIND {
        return Liveness::Stuck;
    }
    Liveness::Alive
}

/// Append one line to the daemon's inbox: the word that a tool call happened.
///
/// The daemon reads only the file's length, so the line is the session id for
/// a reader's sake. This is the one call here that creates the directory.
///
/// # Errors
///
/// The directory or the file will not open or write.
pub fn message(dir: &Path, session: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    std::fs::create_dir_all(dir)?;
    let mut inbox = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(INBOX))?;
    let mut line = session.replace(['\n', '\r'], " ");
    line.push('\n');
    inbox.write_all(line.as_bytes())
}

/// The hook's own two lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Seen {
    /// Consecutive tool calls that found the daemon not alive.
    pub misses: u32,
    /// Whether the daemon's attach note has been handed to the agent.
    pub noted: bool,
    /// Whether a miss was counted that no advisory has yet told the agent of.
    /// A post-tool reply carries no advice on every host, so the word waits
    /// here for the next event that does.
    pub owed: bool,
}

impl Seen {
    /// Read the hook's file; absent or unparseable reads as nothing seen.
    #[must_use]
    pub fn read(dir: &Path) -> Self {
        let text = std::fs::read_to_string(dir.join(HOOK)).unwrap_or_default();
        Seen {
            misses: field(&text, "misses")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            noted: field(&text, "noted") == Some("1"),
            owed: field(&text, "owed") == Some("1"),
        }
    }

    /// Replace the hook's file. **Without a lock**: parallel calls can lose an
    /// increment, which only lengthens the grace by a call.
    ///
    /// # Errors
    ///
    /// The file will not write.
    pub fn write(self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        crate::durable::replace(
            dir.join(HOOK),
            format!(
                "misses {}\nnoted {}\nowed {}\n",
                self.misses,
                u8::from(self.noted),
                u8::from(self.owed)
            ),
        )
    }
}

/// The command that starts the daemon for a session: the remedy for a dead one.
///
/// Byte-stable, because a gate admits exactly this text and nothing near it.
//MUTANT-SUITE crates/batten/tests/it/offbox_hook.rs
//MUTANT remedy-omits-the-transcript-path|s@^    if let Some(transcript) = transcript {$@    if let Some(transcript) = transcript.filter(\x7c_\x7c false) {@|a_dead_daemon_is_denied_after_the_grace_with_the_relaunch_command
#[must_use]
pub fn relaunch(session: &str, harness: &str, transcript: Option<&str>) -> String {
    let mut command = format!("batten offbox run --session {session} --harness {harness}");
    if let Some(transcript) = transcript {
        command.push_str(" --transcript ");
        command.push_str(transcript);
    }
    command
}

/// The command that ends a daemon that is stuck or serving another session.
/// Once it is killed the daemon is dead, and [`relaunch`] applies.
#[must_use]
pub fn kill(pid: &str) -> String {
    format!("kill {pid}")
}

/// The remedy for what a probe found, read from the status file where it needs
/// the daemon's pid; `None` for a daemon that is fine.
#[must_use]
pub fn remedy(
    dir: &Path,
    found: Liveness,
    session: &str,
    harness: &str,
    transcript: Option<&str>,
) -> Option<String> {
    match found {
        Liveness::Alive => None,
        Liveness::Dead => Some(relaunch(session, harness, transcript)),
        Liveness::Stuck | Liveness::OtherSession => {
            let status = std::fs::read_to_string(dir.join(STATUS)).unwrap_or_default();
            Some(kill(field(&status, "pid").unwrap_or("<pid>")))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Fails by: a probe that leaves a directory behind it.
    #[test]
    fn a_probe_of_nothing_is_dead_and_creates_nothing() {
        let dir = crate::scratch::scratch("offbox-watch-absent").join(DIR);
        assert_eq!(probe(&dir, None), Liveness::Dead);
        assert_eq!(probe(&dir, Some("claude-code-0123")), Liveness::Dead);
        assert!(!dir.exists());
    }

    /// Fails by: the leaf depending on anything but the two names.
    #[test]
    fn the_leaf_is_the_harness_and_sixteen_hex_digits() {
        let name = leaf("claude-code", "a ../ b");
        let hash = name.strip_prefix("claude-code-").unwrap();
        assert_eq!(hash.len(), 16);
        assert!(hash.chars().all(|each| each.is_ascii_hexdigit()));
        assert_eq!(name, leaf("claude-code", "a ../ b"));
        assert_ne!(name, leaf("claude-code", "a ../ c"));
    }

    /// Fails by: the hook's file not reading back what it wrote.
    #[test]
    fn the_hooks_file_round_trips() {
        let dir = crate::scratch::scratch("offbox-watch-seen").join(DIR);
        assert_eq!(Seen::read(&dir), Seen::default());
        let seen = Seen {
            misses: 4,
            noted: true,
            owed: false,
        };
        seen.write(&dir).unwrap();
        assert_eq!(Seen::read(&dir), seen);
        assert_eq!(
            std::fs::read_to_string(dir.join(HOOK)).unwrap(),
            "misses 4\nnoted 1\nowed 0\n"
        );
    }

    /// Fails by: a remedy an agent cannot run as written.
    #[test]
    fn the_remedies_are_byte_stable() {
        assert_eq!(
            relaunch("s-1", "claude-code", Some("/t/s-1.jsonl")),
            "batten offbox run --session s-1 --harness claude-code --transcript /t/s-1.jsonl"
        );
        assert_eq!(
            relaunch("s-1", "claude-code", None),
            "batten offbox run --session s-1 --harness claude-code"
        );
        assert_eq!(kill("4242"), "kill 4242");
    }
}
