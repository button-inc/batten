//! The session's setup: ONE install task the agent dispatches, never the hook
//! (CLOUD-2840).
//!
//! **The hook budget is 10 ms with a 100 ms ceiling, and setup is minutes.** So
//! `SessionStart` does in-process work only: it spools the host's payload where
//! the task can read it and says, on the advisory channel every hook's advice
//! uses, exactly what to dispatch ([`instruction`]). It SPAWNS NOTHING. The
//! owner's ruling (2026-11-25): "implement install as a 10/100ms hook just like
//! every other hook with instructions to agent on how to install as background
//! task and gating until agent dispatches the damn install task".
//!
//! **The task is [`DISPATCH`], run by the agent with its harness's own
//! background facility.** It takes the singleton, registers itself (pid plus
//! process start tick), then runs the environment manager's install (a
//! `[[startup]]` row naming a `preset`), the declared handlers (each under its
//! own `timeout_ms`), the pin record, the other `[[startup]]` repairs, and the
//! health report re-decided after them. What any of them would have said is
//! RECORDED here as JSON lines, and the next `PreToolUse` or `UserPromptSubmit`
//! surfaces it once ([`surface`]), through the same constructors the inline
//! path used, so a finding reads the same whichever call carries it.
//!
//! **The task's last phase is its verdict** ([`crate::task::OK`] or
//! [`crate::task::FAILED`]): the install gate reads the registry, never this
//! record, so it can answer without parsing findings. Before any record exists
//! the gate holds every call but a read and the dispatch itself.

use std::path::{Path, PathBuf};

use crate::refusal::Refusal;
use crate::task;

/// Whether `event`'s declared rows run in the setup task rather than inline:
/// `SessionStart`'s, and no other event's. The hook asks this ONE predicate,
/// and `session_start::a_blocking_handler_holds_nothing_and_is_said_once` is
/// the case that reddens when it answers `false` (CLOUD-2840).
#[must_use]
pub fn detaches(event: crate::config_model::Event) -> bool {
    event == crate::config_model::Event::SessionStart
}

/// The registry name the task registers under and holds its singleton by.
pub const TASK: &str = "session-setup";

/// Where the task's inputs and outputs live, under the git dir.
const DIR: &str = "batten-session-setup";

/// The host's `SessionStart` payload, as the handlers read it on stdin.
const PAYLOAD: &str = "payload";

/// What the task found, one JSON object per finding.
const OUTCOME: &str = "outcome";

/// The outcome once a call has carried it: renamed, so it is said once.
const SURFACED: &str = "outcome.surfaced";

/// The one install task, as the agent dispatches it (CLOUD-2840).
pub const DISPATCH: &str = "batten startup --session";

/// What the agent is told to do, at `SessionStart` and in the install gate's
/// refusal: THE ONE SPELLING of the instruction, so the two never drift.
///
/// Claude Code's own facility is named because it is the measured host; every
/// other harness reads the same sentence with its own background facility.
#[must_use]
pub fn instruction() -> String {
    format!(
        "session setup not dispatched: run `{DISPATCH}` once, as a background task \
         with your harness's own facility (Claude Code: the Bash tool with \
         run_in_background and an explicit timeout of 3600000 ms), never inline, \
         never with `&`, `nohup` or a redirect; until it is dispatched every call \
         but a read is held, and until it records `ok` a program it installs is held"
    )
}

fn dir(git_dir: &Path) -> PathBuf {
    git_dir.join(DIR)
}

/// The git dir the setup task lives under for the authority at `root`, or
/// `None` where `root` holds no repository of its own.
///
/// ONE STAT ON THE HOT PATH (CLOUD-2840's perf-gate). Every mediated call asks
/// this, and `git::git_dir` opens the repository: from a directory that is not a
/// repository root it walks up and opens the enclosing one, on every call of the
/// `hook` and `passthrough` arms. Setup is prepared only where the
/// authority is a repository root, so a `.git` directory answers here, a `.git`
/// file (a linked worktree) is the one case that opens, and no `.git` at all is
/// no setup to read.
#[must_use]
pub fn git_dir_of(root: &Path) -> Option<PathBuf> {
    let dot = root.join(".git");
    if dot.is_dir() {
        return Some(dot);
    }
    if dot.is_file() {
        return crate::git::git_dir(root).ok();
    }
    None
}

/// Whether `SessionStart` ever prepared setup under `git_dir`: one stat, so a
/// reader with nothing to read opens no registry. Prepared is not dispatched:
/// [`record`] answers that.
#[must_use]
pub fn started(git_dir: &Path) -> bool {
    dir(git_dir).exists()
}

/// The spooled payload the task's handlers read.
#[must_use]
pub fn payload_path(git_dir: &Path) -> PathBuf {
    dir(git_dir).join(PAYLOAD)
}

/// Whether `command` is the dispatch itself: [`DISPATCH`], its program reached
/// by any path, and nothing else on the line. The install gate admits it in
/// every phase, so the one call that ends the hold is never held.
#[must_use]
pub fn is_dispatch(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let mut wanted = DISPATCH.split_whitespace();
    words
        .next()
        .zip(wanted.next())
        .is_some_and(|(program, name)| program.rsplit('/').next() == Some(name))
        && words.eq(wanted)
}

/// Spool the host's `SessionStart` payload for the task, in process, and
/// answer whether setup is still owed: no record of the task exists, so the
/// agent must be told to dispatch it.
///
/// SPAWNS NOTHING (CLOUD-2840): two file writes and one registry read, inside
/// the hook budget. A record the task already left (a resume or a compaction in
/// the same container) stands, and its outcome is not erased: a finished
/// install is not this session's to redo, and an unsaid finding is still owed.
/// Silent on failure, as every side effect at this boundary is.
#[must_use]
pub fn prepare(git_dir: &Path, raw: &str) -> bool {
    let here = dir(git_dir);
    if std::fs::create_dir_all(&here).is_err() {
        return false;
    }
    let _ = crate::durable::replace(here.join(PAYLOAD), raw);
    record(git_dir).is_none()
}

/// The setup task's registry record, live or ended, or `None` where it was
/// never dispatched.
#[must_use]
pub fn record(git_dir: &Path) -> Option<task::Entry> {
    let (running, gone) = task::partition(git_dir);
    running.into_iter().chain(gone).find(|entry| entry.task == TASK)
}

/// What one finding is, recorded as the inputs its refusal is built from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Finding {
    /// A handler spoke: `hook report now` over its row and its words.
    Report { id: String, text: String },
    /// A handler broke the contract: `hook answer broken` over its token.
    Broken { id: String, token: String },
    /// A doctor check or `[[startup]]` row failed: `workspace state broken`.
    Workspace {
        name: String,
        reason: String,
        subjects: Vec<String>,
    },
}

impl Finding {
    fn refusal(&self) -> Refusal {
        match self {
            Finding::Report { id, text } => crate::handler::report_refusal(id, text),
            Finding::Broken { id, token } => crate::handler::broken_refusal(id, token),
            Finding::Workspace {
                name,
                reason,
                subjects,
            } => crate::doctor::workspace_finding(name, reason, subjects),
        }
    }
}

/// Run the session's setup: what `SessionStart` used to run inline.
///
/// Returns whether every step passed — the phase the task leaves behind.
#[must_use]
pub fn run(
    root: &Path,
    git_dir: &Path,
    handlers: &[crate::config_model::Handler],
    rows: &[crate::config_model::Startup],
) -> bool {
    let pid = std::process::id().to_string();
    // THE SINGLETON BEFORE THE RECORD: a second dispatch while one runs leaves
    // no record of its own, so the gate reads the one task that is installing.
    if !matches!(
        task::singleton_acquire(git_dir, TASK, &pid, std::time::Duration::ZERO),
        task::Claim::Taken | task::Claim::Reclaimed(_)
    ) {
        return true;
    }
    let _ = std::fs::create_dir_all(dir(git_dir));
    // A NEW RUN'S OUTCOME REPLACES THE LAST ONE'S, surfaced or not.
    let _ = std::fs::remove_file(dir(git_dir).join(OUTCOME));
    let _ = std::fs::remove_file(dir(git_dir).join(SURFACED));
    task::register(git_dir, TASK, &pid, "start", crate::clock::now_unix());
    let mut findings = Vec::new();

    // THE ENVIRONMENT MANAGER'S INSTALL FIRST (CLOUD-2840). A `[[startup]]` row
    // naming a `preset` runs that preset's declared install, and every later
    // step — a handler running a pinned tool, a repair needing one — runs on
    // what it installed, so it goes before them, whatever line declares it.
    let (installs, rest): (Vec<_>, Vec<_>) =
        rows.iter().cloned().partition(|row| row.preset.is_some());
    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        "install",
        crate::clock::now_unix(),
    );
    let _ = crate::startup::repair(root, &installs);

    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        "handlers",
        crate::clock::now_unix(),
    );
    let payload = crate::handler::Payload::Spooled(payload_path(git_dir));
    let dispatched = crate::handler::dispatch(
        root,
        handlers,
        crate::config_model::Event::SessionStart,
        "",
        None,
        &payload,
    );
    findings.extend(handler_findings(&dispatched));
    let handlers_passed = findings.is_empty();

    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        "repair",
        crate::clock::now_unix(),
    );
    let _ = crate::pinned::refresh(root);
    let _ = crate::startup::repair(root, &rest);

    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        "health",
        crate::clock::now_unix(),
    );
    let rows_passed = health_findings(root, rows, &mut findings);

    let body: String = findings
        .iter()
        .filter_map(|finding| serde_json::to_string(finding).ok())
        .map(|line| line + "\n")
        .collect();
    let _ = crate::durable::replace(dir(git_dir).join(OUTCOME), body);
    let passed = handlers_passed && rows_passed;
    let last = if passed { task::OK } else { task::FAILED };
    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        last,
        crate::clock::now_unix(),
    );
    task::singleton_release(git_dir, TASK);
    passed
}

/// What the handlers said, as the findings the inline dispatch reported.
fn handler_findings(dispatched: &crate::handler::Dispatched) -> Vec<Finding> {
    dispatched
        .ran
        .iter()
        .filter_map(|ran| match &ran.outcome {
            // A REFUSAL AT `SessionStart` WAS ALWAYS ADVICE (`dispatch_handlers`):
            // the moment carries no verdict, so a deny is recorded as a report.
            crate::handler::Outcome::Advise(text)
            | crate::handler::Outcome::Reported(text)
            | crate::handler::Outcome::Deny(text) => Some(Finding::Report {
                id: ran.id.clone(),
                text: text.trim_end().to_owned(),
            }),
            crate::handler::Outcome::Broke(violation) => Some(Finding::Broken {
                id: ran.id.clone(),
                token: violation.token(),
            }),
            _ => None,
        })
        .collect()
}

/// The health report re-decided after the repairs: every failing doctor check
/// and `[[startup]]` row, pushed onto `findings`. Returns whether every row
/// passed, which is what the task's phase answers for.
fn health_findings(
    root: &Path,
    rows: &[crate::config_model::Startup],
    findings: &mut Vec<Finding>,
) -> bool {
    let report = crate::doctor::diagnose(root);
    for check in report.checks.iter().filter(|check| !check.ok) {
        findings.push(Finding::Workspace {
            name: check.name.to_owned(),
            reason: check.reason.unwrap_or("failed").to_owned(),
            subjects: check.subjects.clone(),
        });
    }
    let mut rows_passed = true;
    for outcome in crate::startup::evaluate(root, rows) {
        if !outcome.ok {
            rows_passed = false;
            findings.push(Finding::Workspace {
                name: outcome.id,
                reason: outcome.reason.unwrap_or("failed").to_owned(),
                subjects: Vec::new(),
            });
        }
    }
    rows_passed
}

/// The task's findings, ONCE, for the call that carries them.
///
/// Empty while the task runs (its findings are not yet a state), once they have
/// been surfaced, and where nothing was recorded. A task that died without
/// recording is itself a finding, said once too.
#[must_use]
pub fn surface(git_dir: &Path) -> Vec<Refusal> {
    let here = dir(git_dir);
    let outcome = here.join(OUTCOME);
    let surfaced = here.join(SURFACED);
    // THE STEADY STATE, AND IT IS EVERY CALL OF A SESSION BUT ONE: already said,
    // or never started. Two stats, before the registry is read at all.
    if !outcome.exists() && (surfaced.exists() || !here.exists()) {
        return Vec::new();
    }
    let (running, gone) = task::partition(git_dir);
    let state = running
        .into_iter()
        .chain(gone)
        .find(|entry| entry.task == TASK)
        .map(|entry| task::state(&entry));
    let Some(state @ (task::State::Ok | task::State::Failed | task::State::Crashed)) = state else {
        // Running, or never started: nothing is a state yet.
        return Vec::new();
    };
    if state == task::State::Crashed && !outcome.exists() {
        // A CRASH IS A STATE (task.rs's header): a task gone with no outcome and
        // no terminal phase is said once, keyed by the surfaced marker.
        if !surfaced.exists() && crate::durable::replace(&surfaced, "").is_ok() {
            return vec![crate::doctor::workspace_finding(TASK, "crashed", &[])];
        }
        return Vec::new();
    }
    // THE RENAME IS THE ONCE: two calls racing here, one wins it.
    if std::fs::rename(&outcome, &surfaced).is_err() {
        return Vec::new();
    }
    crate::fsio::read_to_string(&surfaced)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Finding>(line).ok())
        .map(|finding| finding.refusal())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A setup task that exited and was never reaped reads as crashed, not
    /// running (CLOUD-2789). `detached_in` never waits, so its child stays a
    /// zombie of this test process until the process ends, on any Linux.
    ///
    /// Fails by: `task_alive`'s exit test dropped, so a zombie's empty cmdline
    /// reads as unevaluable and the task as running forever, which is how
    /// `session_start`'s `settle` waited out its bound on `run -> true`.
    #[test]
    fn an_unreaped_setup_task_reads_as_crashed() {
        if !cfg!(target_os = "linux") {
            return;
        }
        let git_dir = crate::scratch::scratch("session-setup-zombie");
        let Some(pid) = crate::exec::detached_in(Path::new("true"), &[], &[], &git_dir) else {
            panic!("premise: `true` spawns");
        };
        let pid = pid.to_string();
        let exited = || {
            crate::fsio::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next())
                    == Some("Z")
            })
        };
        // BOUNDED BY A PASS COUNT, never the clock: `true` exits at once.
        let mut zombie = false;
        for _ in 0..1_000_000 {
            if exited() {
                zombie = true;
                break;
            }
            std::thread::yield_now();
        }
        assert!(zombie, "premise: the child exited unreaped");
        task::register(&git_dir, TASK, &pid, "start", 100);
        let task::Reading::Lines(lines) = task::alive(&git_dir, task::Alive { now: 160 }) else {
            panic!("one whole record");
        };
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(&format!("{TASK} crashed(start) "))),
            "{lines:?}"
        );
    }

    /// Fails by: the spooled payload's path answered as an empty path, so the
    /// handlers read nothing where `start` wrote the host's payload.
    #[test]
    fn the_spooled_payload_is_the_file_start_writes() {
        let git_dir = Path::new("/repo/.git");
        assert_eq!(
            payload_path(git_dir),
            git_dir.join("batten-session-setup").join("payload")
        );
        assert_eq!(payload_path(git_dir), dir(git_dir).join(PAYLOAD));
    }

    /// Fails by: a recorded finding that does not come back as the refusal the
    /// inline path built from the same inputs.
    #[test]
    fn a_recorded_finding_rebuilds_the_inline_refusal() {
        let report = Finding::Report {
            id: "step".to_owned(),
            text: "said".to_owned(),
        };
        let line = serde_json::to_string(&report).unwrap_or_default();
        let back: Option<Finding> = serde_json::from_str(&line).ok();
        assert_eq!(back.as_ref(), Some(&report));
        assert_eq!(
            report.refusal(),
            crate::handler::report_refusal("step", "said")
        );
        let broken = Finding::Broken {
            id: "step".to_owned(),
            token: crate::handler::Violation::Signalled.token(),
        };
        assert_eq!(
            broken.refusal(),
            crate::handler::violation_refusal("step", &crate::handler::Violation::Signalled)
        );
        let workspace = Finding::Workspace {
            name: "row".to_owned(),
            reason: "repair-failed".to_owned(),
            subjects: Vec::new(),
        };
        let inline = crate::startup::Outcome {
            id: "row".to_owned(),
            ok: false,
            reason: Some(crate::startup::REPAIR_FAILED),
        };
        assert_eq!(Some(workspace.refusal()), inline.finding());
    }

    /// Fails by: a registered setup task not found as the setup task's record,
    /// so the gate reads "never dispatched" while it installs (CLOUD-2840).
    #[test]
    fn a_registered_task_is_the_setup_record() {
        let git_dir = crate::scratch::scratch("session-setup-registered");
        assert!(record(&git_dir).is_none());
        task::register(&git_dir, "another-task", "4194304", "start", 100);
        assert!(record(&git_dir).is_none(), "another task is not setup");
        task::register(&git_dir, TASK, "4194305", "start", 100);
        assert_eq!(
            record(&git_dir).map(|entry| entry.pid).as_deref(),
            Some("4194305")
        );
    }

    /// Fails by: a dispatch read as any other call, so the gate holds the one
    /// call that ends the hold; or a longer line read as the dispatch, so a
    /// mutating call rides past the gate behind it.
    #[test]
    fn the_dispatch_is_exactly_the_one_command() {
        assert!(is_dispatch("batten startup --session"));
        assert!(is_dispatch("  /root/.local/bin/batten  startup --session "));
        assert!(!is_dispatch("batten startup"));
        assert!(!is_dispatch("batten startup --session && cargo build"));
        assert!(!is_dispatch("mise exec -- batten startup --session"));
        assert!(!is_dispatch("notbatten startup --session"));
        assert!(!is_dispatch(""));
    }

    /// Fails by: `started` answering true where setup was never prepared.
    #[test]
    fn a_task_is_started_only_once_its_directory_exists() -> std::io::Result<()> {
        let git_dir = crate::scratch::scratch("session-setup-started");
        assert!(!started(&git_dir));
        std::fs::create_dir_all(dir(&git_dir))?;
        assert!(started(&git_dir));
        Ok(())
    }

    /// Fails by: `prepare` answering "setup owed" where the task already left
    /// a record, so a resume or a compaction asks for a second install; or
    /// answering "nothing owed" before any dispatch, so the agent is never told.
    /// `prepare` spawns nothing: the registry it leaves holds no record of its own.
    #[test]
    fn prepare_owes_a_dispatch_only_where_no_record_exists() {
        let git_dir = crate::scratch::scratch("session-setup-prepare");
        assert!(prepare(&git_dir, "{}"), "never dispatched: owed");
        assert_eq!(
            crate::fsio::read_to_string(payload_path(&git_dir)).ok().as_deref(),
            Some("{}"),
            "the payload is spooled for the task"
        );
        assert!(record(&git_dir).is_none(), "prepare registers nothing");
        task::register(&git_dir, TASK, "4194305", task::OK, 100);
        assert!(!prepare(&git_dir, "{}"), "a recorded task is not owed again");
    }

    /// Fails by: a crash read as said only once it HAS an outcome, so a task
    /// that died before writing one is never surfaced.
    #[test]
    fn a_task_gone_without_an_outcome_is_surfaced_once_as_a_crash() -> std::io::Result<()> {
        let git_dir = crate::scratch::scratch("session-setup-crashed");
        std::fs::create_dir_all(dir(&git_dir))?;
        task::register(&git_dir, TASK, "999999999", "start", 100);
        if cfg!(unix) {
            assert_eq!(
                surface(&git_dir),
                vec![crate::doctor::workspace_finding(TASK, "crashed", &[])]
            );
            assert!(surface(&git_dir).is_empty(), "said once");
        }
        Ok(())
    }

    /// Fails by: a task that ENDED, ok or failed, with no outcome on disk
    /// reported as a crash (and its marker spent).
    #[test]
    fn a_finished_task_with_no_outcome_says_nothing() {
        for phase in [task::OK, task::FAILED] {
            let git_dir = crate::scratch::scratch(&format!("session-setup-ended-{phase}"));
            std::fs::create_dir_all(dir(&git_dir)).unwrap_or_default();
            task::register(&git_dir, TASK, "4194305", phase, 100);
            assert!(surface(&git_dir).is_empty(), "{phase}");
            assert!(!dir(&git_dir).join(SURFACED).exists(), "{phase}");
        }
        let git_dir = crate::scratch::scratch("session-setup-crashed");
        std::fs::create_dir_all(dir(&git_dir)).unwrap_or_default();
        task::register(&git_dir, TASK, "4194305", "start", 100);
        assert_eq!(surface(&git_dir).len(), 1);
        assert!(surface(&git_dir).is_empty(), "said once");
    }

    /// Fails by: an outcome on disk skipped because a crash marker is already
    /// there, so a finding the task recorded after its crash was said is never
    /// surfaced (the early return read as `outcome.exists() && …`, CLOUD-2789).
    #[test]
    fn an_outcome_beside_a_spent_crash_marker_is_still_surfaced() -> std::io::Result<()> {
        let git_dir = crate::scratch::scratch("session-setup-outcome-after-crash");
        std::fs::create_dir_all(dir(&git_dir))?;
        task::register(&git_dir, TASK, "4194305", task::FAILED, 100);
        let report = Finding::Report {
            id: "step".to_owned(),
            text: "said".to_owned(),
        };
        let line = serde_json::to_string(&report).unwrap_or_default();
        std::fs::write(dir(&git_dir).join(OUTCOME), format!("{line}\n"))?;
        std::fs::write(dir(&git_dir).join(SURFACED), "")?;
        assert_eq!(surface(&git_dir), vec![report.refusal()]);
        assert!(surface(&git_dir).is_empty(), "said once");
        Ok(())
    }

    /// Fails by: a passing `[[startup]]` row reported as a finding, or the
    /// rows read as failed when every one passed.
    #[test]
    fn a_passing_startup_row_is_no_finding() {
        let root = crate::scratch::scratch("session-setup-health");
        let row = |id: &str, check: &str| crate::config_model::Startup {
            id: id.to_owned(),
            gloss: "a fixture row".to_owned(),
            check: vec![check.to_owned()],
            decided_by: crate::config_model::Decided::ExitStatus,
            repair: None,
            preset: None,
        };
        let named = |findings: &[Finding], id: &str| {
            findings
                .iter()
                .any(|f| matches!(f, Finding::Workspace { name, .. } if name == id))
        };
        let mut findings = Vec::new();
        assert!(health_findings(
            &root,
            &[row("passes", "true")],
            &mut findings
        ));
        assert!(!named(&findings, "passes"));
        let mut findings = Vec::new();
        assert!(!health_findings(
            &root,
            &[row("fails", "false")],
            &mut findings
        ));
        assert!(named(&findings, "fails"));
    }
}
