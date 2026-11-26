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

/// Where the task's inputs and outputs live, under the repository's state
/// directory ([`dir_of`]).
const DIR: &str = "batten-session-setup";

/// The host's `SessionStart` payload, as the handlers read it on stdin.
const PAYLOAD: &str = "payload";

/// What the task found, one JSON object per finding.
const OUTCOME: &str = "outcome";

/// The outcome once a call has carried it: renamed, so it is said once.
const SURFACED: &str = "outcome.surfaced";

/// The session `SessionStart` last prepared setup for: the one that owes a
/// dispatch until a task records it is done.
const SESSION: &str = "session";

/// `<session>\t<pid>`: the session a task began for, and its pid.
const BEGAN: &str = "began";

/// `<session>\t<ok|failed>\t<pid>`: the session a task finished for.
///
/// OUTSIDE THE REGISTRY ON PURPOSE (CLOUD-2840): `land`'s reap unregisters
/// every record whose pid is gone, the finished setup's included, and a gate
/// that read only the registry then read a finished install as never
/// dispatched and held the session again. The registry answers only "is it
/// running"; these files answer "did it finish, for this session".
const DONE: &str = "done";

/// `<session>\t<ok|failed>`: how the INSTALL phase ended for a session, apart
/// from the task's overall outcome.
///
/// THE GATE HOLDS ON THIS, NEVER ON `DONE` (CLOUD-2840, #1276): the install
/// gate's phase (b) holds a program that may still be installing, and once the
/// preset's install has ended `ok` nothing is. A handler, repair or health row
/// failing AFTER it (the container preflight's `doctor egress`, measured) is a
/// finding said once, and read through `DONE` it held `mise`, `cargo` and every
/// installed tool for the rest of the session.
const INSTALLED: &str = "installed";

/// The one install task, as the agent dispatches it (CLOUD-2840).
pub const DISPATCH: &str = "batten startup --session";

/// What the agent is told to do at `SessionStart`: THE ONE SPELLING of the
/// instruction for each kind of host, so it never drifts from what the install
/// gate admits (CLOUD-2840).
///
/// `backgrounds` is the host's answer to `HarnessExt::backgrounds`, asked by
/// the caller so this module stays harness-blind. A host with a background
/// facility is told to use it and never to run the dispatch inline, which the
/// gate holds there. A host without one is told to run it inline: that is the
/// dispatch it can make, and the gate admits it there. Neither is told to
/// detach it with `&`, `nohup` or a redirect, whose end the host cannot see.
#[must_use]
pub fn instruction(backgrounds: bool) -> String {
    let how = if backgrounds {
        "as a background task with your harness's own facility (Claude Code: the \
         Bash tool with run_in_background and an explicit timeout of 3600000 ms), \
         never inline"
    } else {
        "inline: this harness has no background facility, so the call holds the \
         turn until setup ends"
    };
    format!(
        "session setup not dispatched: run `{DISPATCH}` once, {how}, never with `&`, \
         `nohup` or a redirect; until it is dispatched every call but a read is held, \
         and until it records `ok` a program it installs is held"
    )
}

fn dir(git_dir: &Path) -> PathBuf {
    dir_of(git_dir)
}

/// The setup record for the repository whose git dir is `git_dir`: under the
/// STATE ROOT, in that repository's state directory, never beside the
/// repository itself (CLOUD-2789).
///
/// THE RECORD IS THE SESSION'S, AND A SESSION'S STATE IS THE STATE ROOT'S. It
/// lived under the git dir, so every process judging a checkout read one
/// record whatever state root it ran under: a test case adjudicating the
/// committed policy at the checkout read the HOST's session, held on
/// `session-setup undispatched` wherever the host had only prepared setup and
/// admitted wherever it had dispatched it. Land lap 10 failed 25 cases so. The
/// state root is what a harness contains per process, so under it a case reads
/// its own record and the host its own, for the same repository.
///
/// Keyed on the WORKING TREE where `git_dir` is its `.git`, so the record sits
/// beside the repository's other state; a linked worktree's git dir keys its
/// own. Where no state root resolves, the git dir is the one place left.
#[must_use]
pub fn dir_of(git_dir: &Path) -> PathBuf {
    let anchor = match git_dir.parent() {
        Some(tree) if git_dir.file_name() == Some(std::ffi::OsStr::new(".git")) => tree,
        _ => git_dir,
    };
    crate::state::repo_state_dir(anchor).map_or_else(|_| git_dir.join(DIR), |state| state.join(DIR))
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

/// Whether `SessionStart` ever prepared setup for `git_dir`: one stat, so a
/// reader with nothing to read opens no registry. Prepared is not dispatched:
/// [`state`] answers that.
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
///
/// THE PROGRAM WORD IS A PATH AND NOTHING ELSE (CLOUD-2840 review of r3): its
/// last `/`-separated part was the whole test, so a shell prefix glued to it,
/// `{touch,PWN};/usr/bin/batten startup --session`, read as the dispatch and
/// ran `touch PWN` past the gate. A word made only of path characters cannot
/// carry a separator, an expansion or a quote, so what the shell runs is the
/// one program this names.
#[must_use]
pub fn is_dispatch(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let mut wanted = DISPATCH.split_whitespace();
    words
        .next()
        .zip(wanted.next())
        .is_some_and(|(program, name)| {
            program
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+'))
                && program.rsplit('/').next() == Some(name)
        })
        && words.eq(wanted)
}

/// Spool the host's `SessionStart` payload for the task and name the session
/// it is for, in process, and answer whether a dispatch is owed: this session
/// has no running, finished or failed task.
///
/// SPAWNS NOTHING (CLOUD-2840): file writes and one registry read, inside the
/// hook budget. KEYED PER SESSION: a new session in the same clone owes its own
/// dispatch (its handlers, repairs, pin record and health report), while a
/// resume or a compaction of a session whose task finished owes nothing. A
/// crashed task owes a re-dispatch. Silent on failure, as every side effect at
/// this boundary is.
#[must_use]
pub fn prepare(git_dir: &Path, raw: &str, session: &str) -> bool {
    let here = dir(git_dir);
    if std::fs::create_dir_all(&here).is_err() {
        return false;
    }
    let _ = crate::durable::replace(here.join(PAYLOAD), raw);
    let _ = crate::durable::replace(here.join(SESSION), session);
    matches!(state(git_dir), State::Undispatched | State::Crashed(_))
}

/// Where this session's setup stands, as the install gate reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Prepared, and no task ran for this session.
    Undispatched,
    /// A task is running, under this pid.
    Running(String),
    /// This session's task finished `ok`.
    Ok(String),
    /// This session's task finished `failed`.
    Failed(String),
    /// This session's task began and is gone without finishing.
    Crashed(String),
}

impl State {
    /// The token a policy module reads.
    #[must_use]
    pub const fn token(&self) -> &'static str {
        match self {
            State::Undispatched => "undispatched",
            State::Running(_) => "running",
            State::Ok(_) => "ok",
            State::Failed(_) => "failed",
            State::Crashed(_) => "crashed",
        }
    }

    /// The task's pid, or `None` before any task ran.
    #[must_use]
    pub fn pid(&self) -> Option<&str> {
        match self {
            State::Undispatched => None,
            State::Running(pid) | State::Ok(pid) | State::Failed(pid) | State::Crashed(pid) => {
                Some(pid)
            }
        }
    }
}

/// One tab-separated record file under the setup directory, split.
fn fields(git_dir: &Path, name: &str) -> Option<Vec<String>> {
    let body = crate::fsio::read_to_string(dir(git_dir).join(name)).ok()?;
    Some(
        body.trim_end_matches('\n')
            .split('\t')
            .map(str::to_owned)
            .collect(),
    )
}

/// This session's setup state: a running task first (whichever session
/// dispatched it), then this session's finished or begun task, else none.
#[must_use]
pub fn state(git_dir: &Path) -> State {
    let session = crate::fsio::read_to_string(dir(git_dir).join(SESSION)).unwrap_or_default();
    let (running, _) = task::partition(git_dir);
    if let Some(live) = running
        .into_iter()
        .find(|entry| entry.task == TASK && task::state(entry) == task::State::Running)
    {
        return State::Running(live.pid);
    }
    if let Some([ran_for, phase, pid]) = fields(git_dir, DONE).as_deref()
        && *ran_for == session
    {
        return if phase == task::OK {
            State::Ok(pid.clone())
        } else {
            State::Failed(pid.clone())
        };
    }
    if let Some([ran_for, pid]) = fields(git_dir, BEGAN).as_deref()
        && *ran_for == session
    {
        return State::Crashed(pid.clone());
    }
    State::Undispatched
}

/// Whether this session's setup task finished its INSTALL phase `ok`, whatever
/// came after it: the one reading the install gate's hold keys on.
#[must_use]
pub fn installed(git_dir: &Path) -> bool {
    let session = crate::fsio::read_to_string(dir(git_dir).join(SESSION)).unwrap_or_default();
    matches!(
        fields(git_dir, INSTALLED).as_deref(),
        Some([ran_for, outcome]) if *ran_for == session && outcome == task::OK
    )
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
/// `fire_actions` fires the session-start actions for the session it is
/// handed. THE CALLER FIRES THEM, NOT THIS MODULE (CLOUD-2789): the caller
/// already reaches `action`, and a reach from here was the one edge that put
/// `crates/batten/src`'s propagation over its `modules.lock` record.
///
/// Returns whether every step passed — the phase the task leaves behind.
#[must_use]
pub fn run(
    root: &Path,
    git_dir: &Path,
    handlers: &[crate::config_model::Handler],
    fire_actions: &mut dyn FnMut(&str),
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
    // THE SESSION THIS TASK RUNS FOR: the one `SessionStart` last prepared.
    let session = crate::fsio::read_to_string(dir(git_dir).join(SESSION)).unwrap_or_default();
    let _ = std::fs::remove_file(dir(git_dir).join(DONE));
    let _ = std::fs::remove_file(dir(git_dir).join(INSTALLED));
    let _ = crate::durable::replace(dir(git_dir).join(BEGAN), format!("{session}\t{pid}"));
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
    install(root, git_dir, &installs, &session);

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
    let handlers_passed = !failed_any(&dispatched);
    // THE SESSION-START ACTIONS, which the hook used to fire inline: fire and
    // forget, as they always were, but from this task (CLOUD-2840).
    fire_actions(&session);

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
    let _ = crate::durable::replace(dir(git_dir).join(DONE), format!("{session}\t{last}\t{pid}"));
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

/// Run the install rows and record how the install phase ended for `session`
/// ([`INSTALLED`]): the one outcome the install gate's hold keys on.
fn install(root: &Path, git_dir: &Path, installs: &[crate::config_model::Startup], session: &str) {
    let outcome = if crate::startup::repair(root, installs)
        .iter()
        .all(|row| row.ok)
    {
        task::OK
    } else {
        task::FAILED
    };
    let _ = crate::durable::replace(
        dir(git_dir).join(INSTALLED),
        format!("{session}\t{outcome}"),
    );
}

/// Whether a handler FAILED: reported a violation, refused, or broke the
/// contract. ADVICE IS NOT FAILURE (CLOUD-2840): a handler that exits `0` and
/// speaks is said once on the next call, and the task still ends `ok`, so the
/// install gate does not hold the session over a sentence.
fn failed_any(dispatched: &crate::handler::Dispatched) -> bool {
    dispatched.ran.iter().any(|ran| {
        matches!(
            ran.outcome,
            crate::handler::Outcome::Reported(_)
                | crate::handler::Outcome::Deny(_)
                | crate::handler::Outcome::Broke(_)
        )
    })
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
    // THIS SESSION'S STATE, the gate's own reading: a record `land`'s reap
    // removed cannot hide an outcome nobody has said yet.
    let crashed = match state(git_dir) {
        State::Ok(_) | State::Failed(_) => false,
        State::Crashed(_) => true,
        // Running, or never dispatched: nothing is a state yet.
        State::Undispatched | State::Running(_) => return Vec::new(),
    };
    if crashed && !outcome.exists() {
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
    /// handlers read nothing where `start` wrote the host's payload; or the
    /// record kept under the git dir again (CLOUD-2789), where every process
    /// judging the checkout reads one session's setup whatever state root it
    /// runs under.
    #[test]
    fn the_spooled_payload_is_the_file_start_writes() {
        let git_dir = Path::new("/repo/.git");
        let Ok(state) = crate::state::repo_state_dir(Path::new("/repo")) else {
            panic!("a state root resolves here");
        };
        assert_eq!(
            payload_path(git_dir),
            state.join("batten-session-setup").join("payload")
        );
        assert_eq!(payload_path(git_dir), dir(git_dir).join(PAYLOAD));
        assert!(
            !payload_path(git_dir).starts_with(git_dir),
            "the record is the state root's, never the repository's"
        );
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

    /// Write what a task leaves for `session` under `git_dir`: the session
    /// prepared, the task's start, and its finish when `phase` is given.
    fn left(git_dir: &Path, session: &str, pid: &str, phase: Option<&str>) {
        std::fs::create_dir_all(dir(git_dir)).unwrap_or_default();
        std::fs::write(dir(git_dir).join(SESSION), session).unwrap_or_default();
        std::fs::write(dir(git_dir).join(BEGAN), format!("{session}\t{pid}")).unwrap_or_default();
        let _ = std::fs::remove_file(dir(git_dir).join(DONE));
        if let Some(phase) = phase {
            std::fs::write(
                dir(git_dir).join(DONE),
                format!("{session}\t{phase}\t{pid}"),
            )
            .unwrap_or_default();
        }
    }

    /// Fails by: the install outcome read from another session's record, a
    /// `failed` install read as installed, or its absence read as installed —
    /// each makes the gate admit a program the install has not provided.
    #[test]
    fn the_install_outcome_is_this_sessions() {
        let git_dir = crate::scratch::scratch("session-setup-installed");
        left(&git_dir, "s1", "1", Some("failed"));
        assert!(!installed(&git_dir), "no install recorded");
        std::fs::write(dir(&git_dir).join(INSTALLED), "s1\tok").unwrap_or_default();
        assert!(installed(&git_dir), "this session's install ended ok");
        std::fs::write(dir(&git_dir).join(SESSION), "s2").unwrap_or_default();
        assert!(!installed(&git_dir), "another session's install");
        std::fs::write(dir(&git_dir).join(INSTALLED), "s2\tfailed").unwrap_or_default();
        assert!(!installed(&git_dir), "a failed install");
    }

    /// Fails by: a finished task read from the registry alone, so `land`'s reap
    /// of its dead record reads as "never dispatched" and the gate holds the
    /// session after `ok` (review of 076a19082); or a task for ANOTHER session
    /// read as this one's, so a new session is never told to install; or a task
    /// that began and vanished read as anything but a crash.
    #[test]
    fn the_state_is_this_sessions_and_survives_the_reap() {
        let git_dir = crate::scratch::scratch("session-setup-state");
        assert_eq!(state(&git_dir), State::Undispatched);
        // FINISHED, AND NO REGISTRY RECORD AT ALL: what a reap leaves.
        left(&git_dir, "s1", "4194305", Some(task::OK));
        assert_eq!(state(&git_dir), State::Ok("4194305".to_owned()));
        left(&git_dir, "s1", "4194305", Some(task::FAILED));
        assert_eq!(state(&git_dir), State::Failed("4194305".to_owned()));
        left(&git_dir, "s1", "4194305", None);
        assert_eq!(state(&git_dir), State::Crashed("4194305".to_owned()));
        // A NEW SESSION IN THE SAME CLONE owes its own dispatch.
        left(&git_dir, "s1", "4194305", Some(task::OK));
        std::fs::write(dir(&git_dir).join(SESSION), "s2").unwrap_or_default();
        assert_eq!(state(&git_dir), State::Undispatched);
        assert_eq!(State::Undispatched.pid(), None);
        assert_eq!(State::Ok("7".to_owned()).pid(), Some("7"));
    }

    /// Fails by: a running task read as anything but running, whichever
    /// session dispatched it, so a second dispatch is asked for over it.
    #[test]
    fn a_live_task_is_running() {
        let git_dir = crate::scratch::scratch("session-setup-live");
        let own = std::process::id().to_string();
        task::register(&git_dir, TASK, &own, "handlers", 100);
        if cfg!(unix) {
            assert_eq!(state(&git_dir), State::Running(own));
        }
        let other = crate::scratch::scratch("session-setup-live-other");
        task::register(
            &other,
            "another-task",
            &std::process::id().to_string(),
            "x",
            100,
        );
        assert_eq!(
            state(&other),
            State::Undispatched,
            "another task is not setup"
        );
    }

    /// Fails by: a dispatch read as any other call, so the gate holds the one
    /// call that ends the hold; or a longer line read as the dispatch, so a
    /// mutating call rides past the gate behind it.
    #[test]
    fn the_dispatch_is_exactly_the_one_command() {
        assert!(is_dispatch("batten startup --session"));
        assert!(is_dispatch("  /root/.local/bin/batten  startup --session "));
        // A SHELL PREFIX GLUED TO THE PROGRAM WORD is no path: the shell runs
        // the prefix first (CLOUD-2840 review of r3).
        for glued in [
            "{touch,PWN};/usr/bin/batten startup --session",
            "x;batten startup --session",
            "$(touch PWN)/batten startup --session",
            "`touch PWN`/batten startup --session",
            "'batten' startup --session",
            "a&&/usr/bin/batten startup --session",
        ] {
            assert!(!is_dispatch(glued), "{glued}");
        }
        assert!(!is_dispatch("batten startup"));
        assert!(!is_dispatch("batten startup --session && cargo build"));
        assert!(!is_dispatch("mise exec -- batten startup --session"));
        assert!(!is_dispatch("notbatten startup --session"));
        assert!(!is_dispatch(""));
    }

    /// Fails by: a host with no background facility told to dispatch in the
    /// background, which it cannot, so it is never told the dispatch the gate
    /// admits there; or a host that has one told to run it inline, which the
    /// gate holds there (CLOUD-2840 r5).
    #[test]
    fn the_instruction_asks_each_host_for_the_dispatch_it_can_make() {
        let background = instruction(true);
        assert!(
            background.contains("run_in_background") && background.contains("never inline"),
            "{background}"
        );
        let inline = instruction(false);
        assert!(
            inline.contains(&format!("`{DISPATCH}` once, inline"))
                && !inline.contains("run_in_background")
                && !inline.contains("never inline"),
            "{inline}"
        );
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

    /// Fails by: `prepare` answering "setup owed" where this session's task
    /// finished, so a resume or a compaction asks for a second install; or
    /// "nothing owed" before any dispatch, or for a new session, or after a
    /// crash, so the agent is never told. `prepare` spawns nothing: the
    /// registry it leaves holds no record.
    #[test]
    fn prepare_owes_a_dispatch_per_session() {
        let git_dir = crate::scratch::scratch("session-setup-prepare");
        assert!(prepare(&git_dir, "{}", "s1"), "never dispatched: owed");
        assert_eq!(
            crate::fsio::read_to_string(payload_path(&git_dir))
                .ok()
                .as_deref(),
            Some("{}"),
            "the payload is spooled for the task"
        );
        assert!(
            task::partition(&git_dir).0.is_empty(),
            "prepare registers nothing"
        );
        left(&git_dir, "s1", "4194305", Some(task::OK));
        assert!(
            !prepare(&git_dir, "{}", "s1"),
            "a finished session owes nothing"
        );
        assert!(prepare(&git_dir, "{}", "s2"), "a new session owes its own");
        left(&git_dir, "s3", "4194305", None);
        assert!(prepare(&git_dir, "{}", "s3"), "a crash owes a re-dispatch");
    }

    /// Fails by: a crash read as said only once it HAS an outcome, so a task
    /// that died before writing one is never surfaced.
    #[test]
    fn a_task_gone_without_an_outcome_is_surfaced_once_as_a_crash() -> std::io::Result<()> {
        let git_dir = crate::scratch::scratch("session-setup-crashed");
        std::fs::create_dir_all(dir(&git_dir))?;
        left(&git_dir, "s1", "999999999", None);
        assert_eq!(
            surface(&git_dir),
            vec![crate::doctor::workspace_finding(TASK, "crashed", &[])]
        );
        assert!(surface(&git_dir).is_empty(), "said once");
        Ok(())
    }

    /// Fails by: a task that ENDED, ok or failed, with no outcome on disk
    /// reported as a crash (and its marker spent).
    #[test]
    fn a_finished_task_with_no_outcome_says_nothing() {
        for phase in [task::OK, task::FAILED] {
            let git_dir = crate::scratch::scratch(&format!("session-setup-ended-{phase}"));
            left(&git_dir, "s1", "4194305", Some(phase));
            assert!(surface(&git_dir).is_empty(), "{phase}");
            assert!(!dir(&git_dir).join(SURFACED).exists(), "{phase}");
        }
        let git_dir = crate::scratch::scratch("session-setup-ended-crashed");
        left(&git_dir, "s1", "4194305", None);
        assert_eq!(surface(&git_dir).len(), 1);
        assert!(surface(&git_dir).is_empty(), "said once");
    }

    /// Fails by: an outcome on disk skipped because a crash marker is already
    /// there, so a finding the task recorded after its crash was said is never
    /// surfaced (the early return read as `outcome.exists() && …`, CLOUD-2789).
    #[test]
    fn an_outcome_beside_a_spent_crash_marker_is_still_surfaced() -> std::io::Result<()> {
        let git_dir = crate::scratch::scratch("session-setup-outcome-after-crash");
        left(&git_dir, "s1", "4194305", Some(task::FAILED));
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

    /// A failing `[[startup]]` row fails the run even when every handler
    /// passed: the task's verdict is the conjunction of both phases.
    ///
    /// Fails by: `handlers_passed && rows_passed` read as `||`, so a session
    /// with no handlers reported setup passed over a failing row.
    #[test]
    fn a_failing_row_fails_the_run_though_no_handler_failed() {
        let row = |id: &str, check: &str| crate::config_model::Startup {
            id: id.to_owned(),
            gloss: "a fixture row".to_owned(),
            check: vec![check.to_owned()],
            decided_by: crate::config_model::Decided::ExitStatus,
            repair: None,
            preset: None,
        };
        let root = crate::scratch::scratch("session-setup-run-passes");
        let git_dir = root.join(".git");
        let mut no_actions = |_: &str| {};
        assert!(run(
            &root,
            &git_dir,
            &[],
            &mut no_actions,
            &[row("passes", "true")]
        ));
        let root = crate::scratch::scratch("session-setup-run-fails");
        let git_dir = root.join(".git");
        assert!(!run(
            &root,
            &git_dir,
            &[],
            &mut no_actions,
            &[row("fails", "false")]
        ));
    }
}
