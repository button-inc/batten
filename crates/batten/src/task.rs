//! What long-running tasks are running right now, and what phase each is in.
//!
//! CLOUD-425's READER half, ported off `mise-tasks/alive.sh` under CLOUD-843's
//! retirement campaign.
//!
//! **The writer half is deliberately absent, and CLOUD-1283 is why.** The two
//! were built together — the registry is one mechanism read from both ends — and
//! only this half could land: `mise-tasks/land-lock.sh` binds the writer to a
//! variable and spends it with arguments, and `shell-retirement` admits a
//! repointing at the BINDING and has none for the SPEND, so the writer cannot
//! retire and its program is still the one that writes here. Shipping engine
//! writers beside it would put two implementations of the stamp rule over one
//! file format, which is the second-authority class CLOUD-857 measured; shipping
//! them unconsumed would be dead surface. So this module READS a format another
//! program owns, and says so.
//!
//! **State is pushed, never polled, and this module sends no signal at all.**
//! That is forced by `signal(7)` rather than chosen: `SIGUSR1`'s default
//! disposition is `Term`, so a broadcast meant to inspect a task would kill it,
//! and a shell trap does not run while a foreground child does — precisely when
//! an answer is wanted. `rustix::process::test_kill_process` is the one probe
//! used here and it delivers nothing; `tests/task_registry.rs` pins that no
//! signal-sending call reaches this file.
//!
//! **Three answers stay distinct, and conflating any two is the defect this
//! exists to fix** (measured 2026-08-12: a dead `land` was reported to a human
//! as "still in verify" twice, seventeen minutes apart, because `pgrep -f`
//! matched the asking subshell):
//!
//! * *running* — registered, and the process is still that task
//! * *crashed* — registered, and the process is gone. A STATE, not an absence
//! * *nothing registered* — which is not the same as could-not-look
//!
//! **Pointer-only** (non-negotiable rule 4): a task name, a phase word, a pid
//! and a count of seconds. Never a line of any log — being forced to read logs
//! is the defect this removes, so emitting log content would reintroduce it
//! through the front door.
//!
//! **The program root is the CONSUMER'S** (non-negotiable rule 1). Corroborating
//! that a live pid is still the task that registered it means matching the task's
//! own name inside the process's `cmdline`, and *where a consumer keeps its
//! programs* is a fact about that consumer, not about the engine. It arrives as
//! [`Alive::program_root`] rather than as a literal here — the same reason
//! `document_facts::no_artifact_name_reaches_the_core` refuses a manifest name in
//! this crate.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Result;

/// The directory the registry lives in, under the git dir.
///
/// The `batten-<noun>` convention `batten-receipts/` and `batten-land-lock/`
/// already use. Byte-identical to what the writer this reads after produces —
/// which is a constraint rather than a coincidence while that writer is still a
/// separate program (CLOUD-1283).
const STATE_DIR: &str = "batten-tasks";

/// One registered task, as the writer left it.
///
/// Every field is a `String`, and that is deliberate rather than lazy: the record
/// is written by another program, a field may be absent on an entry written
/// before it existed, and a reader's job is to render what is there rather than
/// to insist the record parse. An entry missing a stamp renders without it — the
/// byte-stability obligation for readers that predate the field — which a typed
/// `u64` would have turned into an error.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// The task name as the caller registered it.
    pub task: String,
    /// The registering process.
    pub pid: String,
    /// What it is doing.
    pub phase: String,
    /// When it registered.
    pub started_at: String,
    /// When it entered this phase.
    pub phase_since: String,
}

impl Entry {
    /// The first `<name>: ` line's value, or the empty string.
    ///
    /// First rather than last, matching the retiring `sed -n "s/^$2: //p" | head
    /// -n 1`: the writer rewrites the whole record, so a second line for one key
    /// cannot occur — and where it somehow does, taking the first is what the
    /// previous reader did, and a reader may not move a verdict silently.
    fn field(body: &str, name: &str) -> String {
        let prefix = format!("{name}: ");
        body.lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_default()
            .to_owned()
    }

    /// Read a record out of its own bytes.
    ///
    /// The fields this reader does not render — `pgid`, `tick`, `tick_at`,
    /// `sig`, `sig_at` — are deliberately not parsed. They belong to the
    /// heartbeat that consumes them, and a reader carrying them would be
    /// asserting a layout it has no use for.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        Self {
            task: Self::field(body, "task"),
            pid: Self::field(body, "pid"),
            phase: Self::field(body, "phase"),
            started_at: Self::field(body, "started_at"),
            phase_since: Self::field(body, "phase_since"),
        }
    }

    /// Whether this record is renderable at all.
    ///
    /// A half-written entry is SKIPPED rather than rendered as a line of blanks:
    /// a partial record is not a task, and inventing one would be a claim.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.task.is_empty() && !self.pid.is_empty()
    }
}

/// Where the registry lives for this repository.
fn state_dir(git_dir: &Path) -> PathBuf {
    git_dir.join(STATE_DIR)
}

/// What [`alive`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// Nothing has ever registered, or every entry was half-written. A real
    /// answer, and NOT the same as being unable to read the registry.
    Nothing,
    /// One line per renderable entry, in lexical order.
    Lines(Vec<String>),
    /// The registry is there and cannot be read. Could-not-look, never
    /// "nothing runs".
    Unreadable(PathBuf),
}

/// How [`alive`] decides whether a live pid is still the task that registered it.
#[derive(Clone, Copy, Debug)]
pub struct Alive<'a> {
    /// The directory a consumer keeps its task programs in, matched inside a
    /// live process's own `cmdline`. The consumer's fact, never a literal in
    /// this crate (non-negotiable rule 1).
    pub program_root: &'a str,
    /// The instant ages are measured against, supplied rather than read, so two
    /// calls over one registry state produce identical bytes (house-style §6).
    pub now: u64,
}

/// Is the process behind this entry still the task that registered it?
///
/// Two parts, because existence alone is not enough: pids recycle, and this
/// clone measurably wrapped its pid space inside 20 minutes (CLOUD-432).
///
/// **The asymmetry runs the opposite way here than in a lease heartbeat.** There
/// an unevaluable probe reads as gone, because a wrongly renewed lease wedges
/// the fleet. Here a wrongly CRASHED verdict is the expensive direction: a
/// successor session reads this to learn what was in flight, and a duplicate-run
/// refusal consumes it, so a live task misreported as dead licenses exactly the
/// duplicate-landing incident the registry exists to prevent. So an unevaluable
/// corroboration reads as ALIVE — which also keeps the reader honest off Linux,
/// where `/proc/<pid>/cmdline` does not exist at all.
fn task_alive(program_root: &str, pid: &str, task: &str) -> bool {
    if !pid_exists(pid) {
        return false;
    }
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return true;
    };
    let cmdline: String = raw
        .iter()
        .map(|byte| if *byte == 0 { ' ' } else { char::from(*byte) })
        .collect();
    if cmdline.trim().is_empty() {
        return true;
    }
    matches_cmdline(program_root, task, &cmdline)
}

/// The corroboration predicate alone, over a `cmdline` already in hand.
///
/// Split out so it is testable without a process in a known state: `rust.md`
/// requires a test be shown able to fail, and a case that spawned one would
/// assert its own premise before its conclusion.
///
/// TWO SPELLINGS, BOTH WRITTEN OUT — never a `<task>*` prefix (CLOUD-901). A
/// consumer's task NAME and its task FILE can differ by an extension, so both
/// are accepted; the trailing space is what stops `land` matching a running
/// `land-lock`, which is the pid-recycling defence above. A prefix glob would fix
/// the first case and destroy the second.
fn matches_cmdline(program_root: &str, task: &str, cmdline: &str) -> bool {
    let base = format!("/{program_root}/{task}");
    cmdline.contains(&format!("{base} ")) || cmdline.contains(&format!("{base}.sh "))
}

/// `kill -0`: existence and permission, and no signal delivered.
///
/// A pid that will not parse is not a process, which is the one direction this
/// may answer `false` in without asking the kernel: an unparseable field is a
/// malformed record rather than a dead task.
#[cfg(unix)]
fn pid_exists(pid: &str) -> bool {
    let Ok(raw) = pid.parse::<i32>() else {
        return false;
    };
    rustix::process::Pid::from_raw(raw)
        .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
}

/// Off unix there is no probe, so nothing is ever reported dead — and nothing is
/// ever REAPED.
///
/// The same asymmetry [`task_alive`] argues for, applied to the only other place
/// that can act on it. `rustix` is a `cfg(unix)` dependency (`Cargo.toml`
/// declares it under `[target.'cfg(unix)'.dependencies]` precisely so a Windows
/// build links neither it nor `signal-hook`), so there is no `kill -0` here at
/// all — and a wrongly CRASHED verdict is the expensive direction, because a
/// successor session reads this to learn what was in flight. Answering "alive"
/// makes the reader useless on Windows rather than wrong there, which is the
/// side to be on.
///
/// The parse still decides, for the reason above: a malformed record is not a
/// process on any platform.
#[cfg(not(unix))]
fn pid_exists(pid: &str) -> bool {
    pid.parse::<i32>().is_ok()
}

/// Render one entry's line.
///
/// `in-phase` is APPENDED rather than substituted, and omitted entirely on an
/// entry written before that field existed, so the line stays byte-stable for
/// every reader that predates it.
fn render_line(entry: &Entry, running: bool, now: u64) -> String {
    let age = elapsed(&entry.started_at, now).map_or_else(|| "?".to_owned(), |age| age.to_string());
    let in_phase = elapsed(&entry.phase_since, now)
        .map_or_else(String::new, |since| format!(" in-phase {since}s"));
    let phase = if entry.phase.is_empty() {
        "unknown"
    } else {
        entry.phase.as_str()
    };
    if running {
        format!("{} {phase} {} {age}s{in_phase}", entry.task, entry.pid)
    } else {
        format!(
            "{} crashed({phase}) {} {age}s{in_phase}",
            entry.task, entry.pid
        )
    }
}

/// Seconds since a recorded stamp, or `None` where none was recorded.
fn elapsed(stamp: &str, now: u64) -> Option<u64> {
    stamp
        .parse::<u64>()
        .ok()
        .map(|then| now.saturating_sub(then))
}

/// Read the registry, reaping the entries whose process is genuinely gone.
///
/// **Reaping is licensed by `kill -0` alone, never by a failed corroboration**
/// (CLOUD-901). Reaping a corpse is right — a headstone read once is a
/// diagnosis, read forever it is a registry that fills up and stops being read.
/// Reaping on an unmatched corroboration is not, because [`task_alive`]
/// collapses "the process is gone" and "the process is not this task" into one
/// `false`: measured, one call reported a live `land` as crashed AND erased its
/// entry, so the follow-up call reported nothing registered — a different lie,
/// caused by the first. A future corroboration bug then costs a wrong word,
/// never the evidence.
#[must_use]
pub fn alive(git_dir: &Path, options: Alive<'_>) -> Reading {
    let dir = state_dir(git_dir);
    // Genuine ABSENCE is a real answer — "nothing is running" — and only genuine
    // absence may take this branch. Present-but-unreadable is the other one.
    if !dir.exists() {
        return Reading::Nothing;
    }
    let Ok(listing) = std::fs::read_dir(&dir) else {
        return Reading::Unreadable(dir);
    };
    let mut files: Vec<PathBuf> = listing
        .filter_map(|found| found.ok().map(|found| found.path()))
        .filter(|path| path.is_file())
        .collect();
    // Sorted, so the output is byte-stable across runs for one registry state
    // (non-negotiable rule 5) rather than dependent on readdir order.
    files.sort();

    let mut lines = Vec::new();
    for file in files {
        let Ok(body) = std::fs::read_to_string(&file) else {
            continue;
        };
        let entry = Entry::parse(&body);
        if !entry.is_complete() {
            continue;
        }
        let running = task_alive(options.program_root, &entry.pid, &entry.task);
        lines.push(render_line(&entry, running, options.now));
        if !running && !pid_exists(&entry.pid) {
            let _ = std::fs::remove_file(&file);
        }
    }
    if lines.is_empty() {
        Reading::Nothing
    } else {
        Reading::Lines(lines)
    }
}

/// Write a reading out, as the reader's caller expects to read it.
///
/// # Errors
///
/// Propagates a write failure on either channel.
pub fn report(
    reading: &Reading,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<crate::ExitCode> {
    match reading {
        Reading::Nothing => {
            writeln!(out, "alive: nothing registered")?;
            Ok(crate::ExitCode::Success)
        }
        Reading::Lines(lines) => {
            for line in lines {
                writeln!(out, "{line}")?;
            }
            Ok(crate::ExitCode::Success)
        }
        // Could-not-look is exit 3 in the one contract, where the retiring shell
        // spelled it 2. The remap is deliberate and is `checks green`'s: this
        // table has one meaning per code and no per-verb exception, so a caller
        // branching on the code alone cannot read "I could not tell" as a
        // verdict about the repository.
        Reading::Unreadable(path) => {
            writeln!(
                err,
                "::error:: task alive: the registry at {} cannot be read — that is not 'nothing runs'",
                path.display()
            )?;
            Ok(crate::ExitCode::Internal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_half_written_entry_is_not_renderable() {
        assert!(!Entry::parse("task: land\n").is_complete());
        assert!(!Entry::parse("pid: 42\n").is_complete());
        assert!(Entry::parse("task: land\npid: 42\n").is_complete());
    }

    #[test]
    fn an_entry_predating_the_phase_stamp_renders_without_the_suffix() {
        let entry = Entry::parse("task: land\npid: 42\nphase: verify\nstarted_at: 100\n");
        assert_eq!(render_line(&entry, true, 160), "land verify 42 60s");
    }

    #[test]
    fn a_missing_start_time_renders_a_question_mark_rather_than_a_number() {
        let entry = Entry::parse("task: land\npid: 42\nphase: verify\n");
        assert_eq!(render_line(&entry, true, 160), "land verify 42 ?s");
    }

    #[test]
    fn an_absent_phase_reads_as_unknown_rather_than_as_a_blank() {
        let entry = Entry::parse("task: land\npid: 42\nstarted_at: 100\n");
        assert_eq!(
            render_line(&entry, false, 160),
            "land crashed(unknown) 42 60s"
        );
    }

    #[test]
    fn a_crashed_line_carries_the_phase_it_died_in() {
        let entry =
            Entry::parse("task: land\npid: 42\nphase: verify\nstarted_at: 100\nphase_since: 140\n");
        assert_eq!(
            render_line(&entry, false, 160),
            "land crashed(verify) 42 60s in-phase 20s"
        );
    }

    #[test]
    fn the_first_line_wins_for_a_repeated_key() {
        // The retiring reader's `head -n 1`, kept: a reader may not move a
        // verdict silently, even for a shape the writer cannot produce.
        assert_eq!(Entry::field("phase: one\nphase: two\n", "phase"), "one");
    }

    #[test]
    fn a_value_carrying_a_colon_is_one_field() {
        assert_eq!(Entry::field("phase: lap: 3\n", "phase"), "lap: 3");
    }

    #[test]
    fn corroboration_accepts_both_spellings_and_refuses_a_longer_sibling() {
        // CLOUD-901's three mutations as one property. The extensionless and
        // `.sh` forms both corroborate; the sibling whose name EXTENDS this one
        // does not, which is the pid-recycling defence and the thing a `$task*`
        // glob would destroy.
        let root = "mise-tasks";
        assert!(matches_cmdline(
            root,
            "land",
            "/bin/bash /repo/mise-tasks/land "
        ));
        assert!(matches_cmdline(
            root,
            "land",
            "/bin/bash /repo/mise-tasks/land.sh "
        ));
        assert!(!matches_cmdline(
            root,
            "land",
            "/bin/bash /repo/mise-tasks/land-lock.sh "
        ));
    }

    #[test]
    fn the_program_root_is_a_parameter_rather_than_a_literal() {
        // Non-negotiable rule 1 as a property: a different consumer's layout
        // corroborates under its own root and not under somebody else's.
        assert!(matches_cmdline("scripts", "land", "/repo/scripts/land.sh "));
        assert!(!matches_cmdline(
            "mise-tasks",
            "land",
            "/repo/scripts/land.sh "
        ));
    }
}
