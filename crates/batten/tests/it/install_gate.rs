//! The install gate (CLOUD-2840), over the compiled binary. Before the agent
//! dispatches the session's install task, every call but a read and the
//! dispatch is held, and the refusal names the dispatch. While the task runs, a
//! call naming a program it may still be installing is held as could-not-look,
//! pointing at the task; it runs once the task says `ok`; and a failed or dead
//! task is refused naming what happened.
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

/// A bench registering ONLY `tool install pending`, from its committed bytes.
fn bench(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let module = std::fs::read_to_string(root.join("policy/install-gate.rego"))
        .expect("the module is readable");
    common::Fixture::new(name)
        .config(
            "version = 1\n\n\
             [[rule]]\nid = \"tool install pending\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"policy/install-gate.rego\"\n\
             severity = \"deny\"\n\n\
             [[verdict]]\nid = \"tool install pending\"\n\
             gloss = \"a program this call runs may still be installing\"\n\
             class = \"held while the session's setup task installs\"\n\n\
             [[verdict.route]]\nid = \"task watch first\"\nkind = \"command\"\n\
             target = \"batten task alive\"\n\n\
             [[hook.handler]]\nid = \"setup\"\non = \"session-start\"\nrun = [\"true\"]\n\
             timeout_ms = 5000\n",
        )
        .file("policy/install-gate.rego", &module)
        .git()
        .base_commit()
        .build()
}

/// Record the setup task under `pid` in `phase`, keyed as the registry keys it.
fn setup(dir: &Path, pid: &str, phase: &str) {
    let git_dir = batten::git::git_dir(dir).expect("the bench has a git dir");
    // THE SETUP DIRECTORY `SessionStart` PREPARES, with what a task leaves in
    // it for the session it ran for: its start, and its finish once its phase
    // is terminal. The gate reads no registry where no setup was prepared.
    let setup = git_dir.join("batten-session-setup");
    std::fs::create_dir_all(&setup).expect("the setup dir");
    std::fs::write(setup.join("session"), "").expect("the session");
    std::fs::write(setup.join("began"), format!("\t{pid}")).expect("the start");
    let _ = std::fs::remove_file(setup.join("done"));
    if phase == "ok" || phase == "failed" {
        std::fs::write(setup.join("done"), format!("\t{phase}\t{pid}")).expect("the finish");
    }
    let registry = git_dir.join("batten-tasks");
    std::fs::create_dir_all(&registry).expect("a registry");
    for stale in std::fs::read_dir(&registry).expect("the registry lists") {
        std::fs::remove_file(stale.expect("an entry").path()).expect("cleared");
    }
    let tick = batten::task::process_start(pid).unwrap_or_default();
    std::fs::write(
        registry.join(pid),
        format!(
            "task: session-setup\npid: {pid}\npgid: {pid}\nphase: {phase}\n\
             started_at: 1000\nphase_since: 1000\ntick: \ntick_at: \nsig: \nsig_at: \n\
             cmdline_sha256: \nproc_start: {tick}\n"
        ),
    )
    .expect("a record");
}

/// A `PreToolUse` Bash call running `command` in `dir`: what the door said.
fn call(dir: &Path, command: &str) -> String {
    call_with(dir, command, &[])
}

/// [`call`], backgrounded as the dispatch instruction asks, with `envs` set.
fn call_with(dir: &Path, command: &str, envs: &[(&str, &std::ffi::OsStr)]) -> String {
    tool_call(
        dir,
        "Bash",
        &serde_json::json!({"command": command, "run_in_background": true}),
        envs,
    )
}

/// A `PreToolUse` call to `tool` with `input`: what the door said.
fn tool_call(
    dir: &Path,
    tool: &str,
    input: &serde_json::Value,
    envs: &[(&str, &std::ffi::OsStr)],
) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "cwd": dir,
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string();
    let mut command = common::batten();
    for (key, value) in envs {
        command.env(key, value);
    }
    let answer = common::stdin_run(
        &mut command,
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    format!("{}{}", common::stdout(&answer), common::stderr(&answer))
}

/// The session's `SessionStart` through the door: what it said.
fn session_start(dir: &Path) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": dir,
    })
    .to_string();
    let answer = common::stdin_run(
        &mut common::batten(),
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    format!("{}{}", common::stdout(&answer), common::stderr(&answer))
}

/// A `cargo` under a fixture environment manager's install root, first on
/// `PATH`: the shim an install may not have filled yet. Answers the
/// environment a call needs to see it so.
fn shimmed(dir: &Path) -> Vec<(&'static str, std::ffi::OsString)> {
    use std::os::unix::fs::PermissionsExt as _;
    let data = dir.join("mise-data");
    let bin = data.join("installs/rust/1.0/bin");
    std::fs::create_dir_all(&bin).expect("the install root");
    let cargo = bin.join("cargo");
    std::fs::write(&cargo, "#!/bin/sh\n").expect("the shim");
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755))
        .expect("the shim is runnable");
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&common::ambient_path())),
    )
    .expect("a joinable PATH");
    vec![("MISE_DATA_DIR", data.into_os_string()), ("PATH", path)]
}

/// The policy input `adjudicate --show-input` stored for this Bash call at
/// `event`: the view its pointer names, one `## /path` heading per field.
fn input_at(dir: &Path, event: &str, command: &str) -> String {
    let payload = serde_json::json!({
        "hook_event_name": event,
        "cwd": dir,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": "", "stderr": "", "interrupted": false},
    })
    .to_string();
    let answer = common::stdin_run(
        &mut common::batten(),
        dir,
        &["adjudicate", "--harness", "claude-code", "--show-input"],
        &payload,
    );
    let said = common::stderr(&answer);
    let view = said
        .split("; read ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no pointer: {said}"));
    std::fs::read_to_string(view).expect("the view reads")
}

fn held(said: &str) -> bool {
    said.contains("tool install pending")
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
    let env = shimmed(&dir);
    let env: Vec<(&str, &std::ffi::OsStr)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_os_str()))
        .collect();
    let said = call_with(&dir, "cargo build", &env);
    assert!(
        held(&said) && said.contains("session-setup running"),
        "a program under the install root is held: {said}"
    );
    let said = call_with(&dir, "mise run x", &env);
    assert!(
        held(&said) && said.contains("mise"),
        "the manager itself is held, wherever it resolves: {said}"
    );
    assert!(
        !held(&call_with(&dir, "git status", &env)),
        "git is admitted"
    );
}

/// Fails by: a call made before the install task is dispatched admitted —
/// mutant `dispatch-gate-open` — so the session runs on a container nothing
/// set up; a read refused, so the session cannot even look; the dispatch
/// itself refused, so the hold can never end; or a refusal that does not say
/// what to dispatch.
#[test]
fn a_call_before_the_dispatch_is_held_and_a_read_is_not() {
    let dir = bench("install-gate-undispatched");
    let said = call(&dir, "cargo build");
    assert!(!held(&said), "no session prepared setup yet: {said}");
    let started = session_start(&dir);
    assert!(
        started.contains("batten startup --session"),
        "the door names the dispatch: {started}"
    );
    let said = call(&dir, "cargo build");
    assert!(
        held(&said)
            && said.contains("session-setup undispatched")
            && said.contains("batten startup --session"),
        "a mutating call is held with the dispatch as its remedy: {said}"
    );
    let target = dir.join("x").display().to_string();
    let said = tool_call(
        &dir,
        "Write",
        &serde_json::json!({"file_path": target, "content": "x"}),
        &[],
    );
    assert!(held(&said), "a write tool is held: {said}");
    let source = dir.join("README").display().to_string();
    let said = tool_call(&dir, "Read", &serde_json::json!({"file_path": source}), &[]);
    assert!(!held(&said), "a read is admitted: {said}");
    assert!(!held(&call(&dir, "git status")), "git status is a read");
    assert!(!held(&call(&dir, "cat README")), "a reader is a read");
    assert!(
        held(&call(&dir, "cat README > copy")),
        "a reader that writes a file is not"
    );
    assert!(
        !held(&call(&dir, "batten startup --session")),
        "the dispatch is admitted"
    );
    let foreground = tool_call(
        &dir,
        "Bash",
        &serde_json::json!({"command": "batten startup --session", "run_in_background": false}),
        &[],
    );
    assert!(
        held(&foreground),
        "but never in the foreground: {foreground}"
    );
}

/// Only a call about to run can be held, so only one is asked about the
/// install: a call reported after it ran (`PostToolUse`) carries no
/// `install-pending` fact, which is what `--show-input` stores for it.
///
/// Fails by: `install_pending_for`'s event guard joined with `&&`, so a
/// post-tool call whose row reads pinned facts resolves the setup task's
/// state and every program on `PATH` for nothing (CLOUD-2789).
#[test]
fn a_call_reported_after_it_ran_is_never_asked_about_the_install() {
    let dir = bench("install-gate-post-tool");
    setup(&dir, &std::process::id().to_string(), "repair");
    let command = format!("{ABSENT} --version");
    // ANTI-VACUITY: the same call, about to run, carries the running task.
    let before = input_at(&dir, "PreToolUse", &command);
    assert!(
        before.contains("## /facts/install-pending/state\nrunning"),
        "{before}"
    );
    let after = input_at(&dir, "PostToolUse", &command);
    assert!(
        !after.contains("## /facts/install-pending/"),
        "a post-tool call resolves no install state: {after}"
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
    assert!(!held(&said), "`cd` is the shell's own: {said}");
    let said = call(&dir, "T=/bin/sh; $T -c true");
    assert!(
        !held(&said),
        "an expanded word is the shell's to resolve: {said}"
    );
    let said = call(&dir, &format!("cd /tmp && {ABSENT} --version"));
    assert!(
        held(&said) && said.contains(ABSENT),
        "held on the absent program alone: {said}"
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

/// Fails by: a finished setup read from the registry alone, so `land`'s reap
/// of its dead record reads as never dispatched and holds every call again
/// after `ok` (review of 076a19082); or the manager held after `ok`.
#[test]
fn a_finished_setup_survives_the_reap() {
    let dir = bench("install-gate-reaped");
    setup(&dir, NO_SUCH_PID, "ok");
    // WHAT THE REAP LEAVES: no registry record at all.
    let git_dir = batten::git::git_dir(&dir).expect("the bench has a git dir");
    std::fs::remove_dir_all(git_dir.join("batten-tasks")).expect("reaped");
    let env = shimmed(&dir);
    let env: Vec<(&str, &std::ffi::OsStr)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_os_str()))
        .collect();
    let said = call_with(&dir, "cargo build", &env);
    assert!(
        !held(&said),
        "an `ok` install admits after the reap: {said}"
    );
    let said = call_with(&dir, "mise run x", &env);
    assert!(!held(&said), "and the manager with it: {said}");
}

/// Record how the install phase ended for the session `setup` left (#1276).
fn installed(dir: &Path, outcome: &str) {
    let git_dir = batten::git::git_dir(dir).expect("the bench has a git dir");
    let setup = git_dir.join("batten-session-setup");
    std::fs::write(setup.join("installed"), format!("\t{outcome}")).expect("the install outcome");
}

/// Fails by: a failure AFTER a clean install — the container preflight's
/// `doctor egress`, measured on #1276 — holding `mise` and `cargo` for the
/// whole session with every tool installed, or its finding said on every call
/// or never; or a failed install admitted.
#[test]
fn a_handler_failure_after_a_clean_install_holds_nothing() {
    let dir = bench("install-gate-handler-failed");
    setup(&dir, NO_SUCH_PID, "failed");
    installed(&dir, "ok");
    let git_dir = batten::git::git_dir(&dir).expect("the bench has a git dir");
    std::fs::write(
        git_dir.join("batten-session-setup/outcome"),
        "{\"report\":{\"id\":\"session-container-preflight\",\"text\":\"egress failed\"}}\n",
    )
    .expect("the outcome");
    let env = shimmed(&dir);
    let env: Vec<(&str, &std::ffi::OsStr)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_os_str()))
        .collect();
    let said = call_with(&dir, "cargo build", &env);
    assert!(!held(&said), "cargo is installed: {said}");
    assert!(
        said.contains("session-container-preflight"),
        "the handler's failure is said: {said}"
    );
    let said = call_with(&dir, "mise run x", &env);
    assert!(!held(&said), "and the manager with it: {said}");
    assert!(
        !said.contains("session-container-preflight"),
        "once: {said}"
    );
    installed(&dir, "failed");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(held(&said), "a failed install still holds: {said}");
}

/// Fails by: a failed or dead install admitted, so its absent program runs and
/// fails as if the work were wrong; or refused without saying which.
#[test]
fn a_failed_or_dead_task_is_refused_naming_it() {
    let dir = bench("install-gate-failed");
    setup(&dir, NO_SUCH_PID, "failed");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        held(&said) && said.contains("session-setup failed"),
        "a failed install is named: {said}"
    );
    setup(&dir, NO_SUCH_PID, "repair");
    let said = call(&dir, &format!("{ABSENT} --version"));
    assert!(
        held(&said) && said.contains("session-setup crashed"),
        "a task gone without a last word is a crash: {said}"
    );
}
