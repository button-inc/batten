//! The session's setup, run as ONE detached task rather than inside the hook
//! (CLOUD-2840).
//!
//! **The hook budget is 10 ms with a 100 ms ceiling, and setup is minutes.** A
//! `SessionStart` that ran every declared `session-start` handler and every
//! `[[startup]]` repair in-process held the agent's first response for as long
//! as the slowest of them, bounded only by the host's 600 s kill. So the hook
//! starts this task and returns: it writes the host's payload where the task can
//! read it, spawns `batten startup --session` in its own process group, and
//! registers that pid in the task registry before the dispatch returns.
//!
//! **The task runs what the hook used to, in the order it used to**, with one
//! step moved ahead: the environment manager's install (a `[[startup]]` row
//! naming a `preset`), then the declared handlers (each under its own
//! `timeout_ms`), the pin record, the other `[[startup]]` repairs, the
//! checkout's engine put under the hooks where they run a release download
//! (CLOUD-2871), then the health report re-decided after them. What any
//! of them would have said is RECORDED here as JSON lines, and the next
//! `PreToolUse` or `UserPromptSubmit` surfaces it once ([`surface`]), through the
//! same constructors the inline path used, so a finding reads the same whichever
//! call carries it.
//!
//! **The task's last phase is its verdict** ([`crate::task::OK`] or
//! [`crate::task::FAILED`]): a gate that holds a tool while it installs reads the
//! registry, never this record, so it can answer without parsing findings.

use std::path::{Path, PathBuf};

use crate::refusal::Refusal;
use crate::task;

/// Whether `event`'s declared rows run in the setup task rather than inline:
/// `SessionStart`'s, and no other event's. The hook asks this ONE predicate,
/// and `session_start::a_session_start_registers_its_task_before_it_returns`
/// is the case that reddens when it answers `false` (CLOUD-2840).
#[must_use]
pub fn detaches(event: crate::config_model::Event) -> bool {
    event == crate::config_model::Event::SessionStart
}

/// The registry name the task registers under and holds its singleton by.
pub const TASK: &str = "session-setup";

/// The phase the task is in while it builds the checkout's engine
/// (CLOUD-2871): the gate holds [`BUILD_PROGRAM`] for exactly this phase.
pub const ENGINE: &str = "engine";

/// The program the engine phase builds with, and the one a call is held on
/// while it does: a second build in the same target directory would race it.
pub const BUILD_PROGRAM: &str = "cargo";

/// The name a failed engine phase is reported under.
const ENGINE_ROW: &str = "hook-engine-is-the-checkout-build";

/// Where the task's inputs and outputs live, under the git dir.
const DIR: &str = "batten-session-setup";

/// The host's `SessionStart` payload, as the handlers read it on stdin.
const PAYLOAD: &str = "payload";

/// What the task found, one JSON object per finding.
const OUTCOME: &str = "outcome";

/// The outcome once a call has carried it: renamed, so it is said once.
const SURFACED: &str = "outcome.surfaced";

/// Register `pid` as the setup task unless a record for it already exists.
///
/// BOTH SIDES CALL THIS, AND NEITHER WAITS (CLOUD-2840). The hook registers the
/// pid its spawn returned, so the registry names the task before the hook
/// returns; the task registers itself before its first push, because a push to
/// a pid with no record is a no-op ([`task::push`]) and its last phase is the
/// one the gate reads. Whichever runs second finds the record and leaves it, so
/// a phase the task already pushed is never reset to `start`.
fn register_once(git_dir: &Path, pid: &str, now: u64) {
    if task::read_field(git_dir, pid, "task").is_none() {
        task::register(git_dir, TASK, pid, "start", now);
    }
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
/// `hook` and `passthrough` arms. A setup task is started only where the
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

/// Whether a setup task was ever started under `git_dir`: one stat, so a
/// reader with nothing to read opens no registry.
#[must_use]
pub fn started(git_dir: &Path) -> bool {
    dir(git_dir).exists()
}

/// The spooled payload the task's handlers read.
#[must_use]
pub fn payload_path(git_dir: &Path) -> PathBuf {
    dir(git_dir).join(PAYLOAD)
}

/// Start the task for this session, unless one is already running.
///
/// Returns the registered pid, or `None` where nothing was started: one is
/// already running (a resume or a second `SessionStart` must not start a
/// second install over the first), or the spawn failed — which is silent, as
/// every side effect at this boundary is, and leaves the gates with no record
/// to hold on.
#[must_use]
pub fn start(root: &Path, git_dir: &Path, raw: &str, now: u64) -> Option<String> {
    let (running, _) = task::partition(git_dir);
    if running.iter().any(|entry| entry.task == TASK) {
        return None;
    }
    let here = dir(git_dir);
    std::fs::create_dir_all(&here).ok()?;
    crate::durable::replace(here.join(PAYLOAD), raw).ok()?;
    // A NEW SESSION'S OUTCOME REPLACES THE LAST ONE'S, surfaced or not: what a
    // previous container found is not this one's state.
    let _ = std::fs::remove_file(here.join(OUTCOME));
    let _ = std::fs::remove_file(here.join(SURFACED));
    let exe = std::env::current_exe().ok()?;
    let pid = crate::exec::detached_in(
        &exe,
        &["startup".to_owned(), "--session".to_owned()],
        &[],
        root,
    )?
    .to_string();
    register_once(git_dir, &pid, now);
    Some(pid)
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
    presets: &[&str],
) -> bool {
    let pid = std::process::id().to_string();
    register_once(git_dir, &pid, crate::clock::now_unix());
    if !matches!(
        task::singleton_acquire(git_dir, TASK, &pid, std::time::Duration::ZERO),
        task::Claim::Taken | task::Claim::Reclaimed(_)
    ) {
        return true;
    }
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

    // THE CHECKOUT'S ENGINE UNDER THE HOOKS (CLOUD-2871), after every repair,
    // so the toolchain it builds with is already installed.
    task::push(
        git_dir,
        &pid,
        task::Signal::Phase,
        ENGINE,
        crate::clock::now_unix(),
    );
    let engine_passed = match adopt_checkout_build(root, presets) {
        Some(finding) => {
            findings.push(finding);
            false
        }
        None => true,
    };

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
    let passed = handlers_passed && engine_passed && rows_passed;
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

/// Put this checkout's engine under the hooks, where they run a release
/// download (CLOUD-2871). `None` where that holds or was made to hold.
///
/// **A RELEASE PIN NEVER BRINGS THE BRANCH'S ENGINE.** Every hook names a bare
/// `batten`, which in a fresh container is the release `install.sh` placed, and
/// a release pin is satisfied by any engine of its version. So a session on a
/// branch was judged by the last release: the gates the branch adds judged
/// nothing for it, its dispatched children included. In a tree carrying the
/// engine's own source, this phase builds it and installs it, stamped, over the
/// `batten` the hooks resolve. The branch's build carries the version the pin
/// names, so the pin accepts it and no follow is added to the hook path.
///
/// **NEVER ON THE HOOK PATH, NEVER TWICE.** It runs only in this detached task,
/// and only over an UNSTAMPED hook engine ([`crate::engine::unbuilt_hook_engine`]):
/// a resume or a compaction finds the stamp and builds nothing, so the 714 s
/// mid-lap rebuild CLOUD-2840 removed cannot come back through here. Whether a
/// stamped build is current is `doctor mediator`'s question.
///
/// The build runs on the toolchain the environment manager pins, through its
/// declared `exec`, where any enabled preset (`presets`, every name a
/// `[[rule]]` or `[[startup]]` row enables) declares an install; else on the
/// host's. Not the `[[startup]]` rows alone: a consumer can enable the manager
/// without placing its install row, and then the host's compiler, older than
/// the floor the manager pins, failed the build.
fn adopt_checkout_build(root: &Path, presets: &[&str]) -> Option<Finding> {
    if !crate::engine::builds_itself(root) {
        return None;
    }
    let target = crate::engine::unbuilt_hook_engine(std::env::var_os("PATH").as_deref(), root)?;
    let failed = |reason: &str| Finding::Workspace {
        name: ENGINE_ROW.to_owned(),
        reason: reason.to_owned(),
        subjects: vec![target.display().to_string()],
    };
    let mut argv: Vec<String> = presets
        .iter()
        .copied()
        .find_map(crate::config_model::install_of)
        .map(|install| {
            std::iter::once(install.program)
                .chain(install.exec.iter().copied())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    argv.extend(
        [
            BUILD_PROGRAM,
            "build",
            "--release",
            "-p",
            crate::surface::BINARY,
        ]
        .iter()
        .map(|word| (*word).to_owned()),
    );
    if crate::exec::run_in(root, &argv).is_err() {
        return Some(failed("build-failed"));
    }
    let Ok(digest) = crate::engine::digest(root) else {
        return Some(failed("digest-unreadable"));
    };
    let Ok(bytes) = crate::fsio::read(crate::engine::release_build(root)) else {
        return Some(failed("build-missing"));
    };
    // `replace` keeps the target's own permission bits and renames into place,
    // so a hook starting mid-install runs the old engine or the new one, never
    // a torn or unexecutable file.
    if crate::durable::replace(&target, &bytes).is_err()
        || crate::engine::stamp(&target, &digest).is_err()
    {
        return Some(failed("install-failed"));
    }
    None
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
}
