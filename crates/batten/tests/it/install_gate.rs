//! The install gate (CLOUD-2840), over the compiled binary: while the session's
//! setup task runs, a call naming a program it may still be installing is held
//! as could-not-look, pointing at the task; it runs once the task says `ok`; and
//! a failed or dead task is refused naming what happened.
//!
//! The setup task is a record in the fixture's registry, written the way
//! `batten task register` writes one. A RUNNING task is this test process itself,
//! keyed on its own pid and start tick, which is what makes the registry read it
//! live; a FINISHED one is a pid the kernel never assigns, carrying its last
//! phase.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use std::path::{Path, PathBuf};

/// A program no `PATH` on any machine resolves.
const ABSENT: &str = "batten-install-gate-no-such-tool";

/// A pid above every assignable number (`/proc/sys/kernel/pid_max` <= 2^22).
const NO_SUCH_PID: &str = "4194305";

/// A bench registering ONLY `tool install held`, from its committed bytes.
fn bench(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let module = std::fs::read_to_string(root.join("policy/install-gate.rego"))
        .expect("the module is readable");
    common::Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\nid = \"tool install held\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/install-gate.rego\"\n\
             severity = \"deny\"\n\n\
             [[verdict]]\nid = \"tool install pending\"\n\
             gloss = \"a program this call runs may still be installing\"\n\
             class = \"held while the session's setup task installs\"\n\n\
             [[verdict.route]]\nid = \"task watch first\"\nkind = \"command\"\n\
             target = \"batten task alive\"\n\n\
             [[verdict]]\nid = \"tool install absent\"\n\
             gloss = \"the session's setup ended without installing a program\"\n\
             class = \"refused after the session's setup task failed or died\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"batten startup --session\"\n",
        )
        .file("policy/install-gate.rego", &module)
        .git()
        .base_commit()
        .build()
}

/// Record the setup task under `pid` in `phase`, keyed as the registry keys it.
fn setup(dir: &Path, pid: &str, phase: &str) {
    let git_dir = batten::git::git_dir(dir).expect("the bench has a git dir");
    // THE SETUP DIRECTORY `session_setup::start` WRITES BEFORE IT REGISTERS:
    // the gate reads no registry where no setup was ever started.
    std::fs::create_dir_all(git_dir.join("batten-session-setup")).expect("the setup dir");
    let registry = git_dir.join("batten-tasks");
    std::fs::create_dir_all(&registry).expect("a registry");
    for stale in std::fs::read_dir(&registry).expect("the registry lists") {
        std::fs::remove_file(stale.expect("an entry").path()).expect("cleared");
    }
    record(dir, pid, phase, 1000);
}

/// Add a setup record under `pid`, registered at `started_at`, beside any
/// already there: a re-run registers next to the record it answers.
fn record(dir: &Path, pid: &str, phase: &str, started_at: u64) {
    let git_dir = batten::git::git_dir(dir).expect("the bench has a git dir");
    let registry = git_dir.join("batten-tasks");
    let tick = batten::task::process_start(pid).unwrap_or_default();
    std::fs::write(
        registry.join(pid),
        format!(
            "task: session-setup\npid: {pid}\npgid: {pid}\nphase: {phase}\n\
             started_at: {started_at}\nphase_since: {started_at}\ntick: \ntick_at: \n\
             sig: \nsig_at: \ncmdline_sha256: \nproc_start: {tick}\n"
        ),
    )
    .expect("a record");
}

/// A `PreToolUse` Bash call running `command` in `dir`: what the door said.
fn call(dir: &Path, command: &str) -> String {
    call_with(dir, command, &[])
}

/// [`call`] with extra environment on the adjudicating process.
fn call_with(dir: &Path, command: &str, env: &[(&str, &Path)]) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": dir,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let mut door = common::batten();
    for (key, value) in env {
        door.env(key, value);
    }
    let answer = common::stdin_run(
        &mut door,
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    format!("{}{}", common::stdout(&answer), common::stderr(&answer))
}

/// Held as still installing: the task runs. Read at the verdict's position,
/// since the refusal also names the rule after it.
fn held(said: &str) -> bool {
    said.contains("deny tool install pending")
}

/// Refused as missing after the setup ended without `ok` (CLOUD-2921).
fn absent(said: &str) -> bool {
    said.contains("deny tool install absent")
}

/// Fails by: the gate left open while the setup task runs — mutant
/// `install-gate-open` — so a program it has not installed yet runs and fails
/// as if the work were wrong.
#[test]
fn a_pending_program_is_held_while_the_setup_task_runs() {
    let dir = bench("install-gate-running");
    assert!(
        !held(&call(&dir, &format!("{ABSENT} --version"))),
        "no setup task is recorded, so nothing is held"
    );
    setup(&dir, &std::process::id().to_string(), "repair");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(held(&said), "a program nothing resolves is held: {said}");
    assert!(
        said.contains("session-setup running") && said.contains("batten task alive"),
        "the hold names the task, says it is still running, and points at it: {said}"
    );
}

/// Fails by: a program that resolves outside every install root held as
/// though the install owned it.
#[test]
fn a_resolved_program_runs_while_the_setup_task_runs() {
    let dir = bench("install-gate-resolved");
    setup(&dir, &std::process::id().to_string(), "handlers");
    let said = call(&dir, "sh -c true");
    assert!(
        !held(&said),
        "`sh` resolves on PATH, outside the install root: {said}"
    );
}

/// Fails by: a shell builtin held because no file on `PATH` carries its name,
/// so `cd <dir> && <anything>` is refused for as long as the task is unsettled
/// — measured, on a session whose setup task had failed. Mutation: drop the
/// builtin filter in `install_pending_for`, and `cd` becomes pending.
#[test]
fn a_shell_builtin_is_never_pending() {
    let dir = bench("install-gate-builtin");
    setup(&dir, NO_SUCH_PID, "failed");
    let said = call(&dir, "cd /tmp && sh -c true");
    assert!(
        !held(&said) && !absent(&said),
        "`cd` is the shell's own: {said}"
    );
    let said = call(&dir, "T=/bin/sh; $T -c true");
    assert!(
        !held(&said) && !absent(&said),
        "an expanded word is the shell's to resolve: {said}"
    );
    let said = call(&dir, &format!("cd /tmp && {ABSENT} --version"));
    assert!(
        absent(&said) && said.contains(ABSENT),
        "refused on the absent program alone: {said}"
    );
}

/// Fails by: `git status` held, the one read a session takes to learn where it
/// is.
#[test]
fn git_status_runs_throughout() {
    let dir = bench("install-gate-git-status");
    setup(&dir, &std::process::id().to_string(), "handlers");
    let said = call(&dir, "git status");
    assert!(!held(&said), "{said}");
}

/// Fails by: a finished install still holding, so the session waits on a task
/// that already answered.
#[test]
fn an_ok_task_admits_the_program() {
    let dir = bench("install-gate-ok");
    setup(&dir, NO_SUCH_PID, "ok");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(!held(&said), "{said}");
}

/// Fails by: a failed or dead install admitted, so its absent program runs and
/// fails as if the work were wrong; or refused without saying which.
#[test]
fn a_failed_or_dead_task_is_refused_naming_it() {
    let dir = bench("install-gate-failed");
    setup(&dir, NO_SUCH_PID, "failed");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        absent(&said) && said.contains("session-setup failed"),
        "a failed install is named: {said}"
    );
    setup(&dir, NO_SUCH_PID, "repair");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        absent(&said) && said.contains("session-setup crashed"),
        "a task gone without a last word is a crash: {said}"
    );
}

/// Fails by: a setup that ended without `ok` read as still installing —
/// mutant `install-failed-reads-pending` — so the reader waits on a task that
/// is gone; refused under no verdict at all — mutant `install-failed-open`; or
/// an INSTALLED program refused because it sits under the install root, the
/// measured `opa` held ~20 hours after a failed setup (CLOUD-2921).
#[test]
fn a_failed_install_is_refused_as_failed_never_pending() {
    let dir = bench("install-gate-ended");
    setup(&dir, NO_SUCH_PID, "failed");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        absent(&said) && !held(&said),
        "a missing program after a failed setup is absent, never pending: {said}"
    );
    assert!(
        said.contains("batten startup --session"),
        "the refusal routes to re-running the setup: {said}"
    );
    let root = common::scratch("install-gate-root");
    let installed = root.join("installs").join("tool");
    std::fs::create_dir_all(installed.parent().expect("a parent")).expect("the install dir");
    // Empty, not a script: the engine reads a script's shebang as the program
    // it runs, and this case is about the installed file itself.
    std::fs::write(&installed, "").expect("an installed program");
    let program = installed.to_str().expect("a UTF-8 path");
    let said = call_with(
        &dir,
        &format!("{program} --version"),
        &[("MISE_DATA_DIR", root.as_path())],
    );
    assert!(
        !held(&said) && !absent(&said),
        "an installed program runs once the setup has ended: {said}"
    );
}

/// Fails by: a stale `failed` record read in place of the `ok` re-run that
/// superseded it, so the refusal outlives its own remedy (CLOUD-2921). The
/// failed pid sorts first, which is the order the gone records are read in.
#[test]
fn a_rerun_setup_supersedes_its_failed_record() {
    let dir = bench("install-gate-rerun");
    setup(&dir, "4194305", "failed");
    record(&dir, "4194306", "ok", 2000);
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        !held(&said) && !absent(&said),
        "the newer `ok` is the setup's state: {said}"
    );
}
