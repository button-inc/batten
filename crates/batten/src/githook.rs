//! Batten as every git hook (CLOUD-2339).
//!
//! `batten wiring gate` links each githooks(5) name to the running binary, so
//! when git runs a hook it runs batten. [`dispatched`] recognises that from
//! argv[0] before the parser sees anything, loads the committed `[hook.git]`
//! table, and passes git's arguments and streams through to the argv declared
//! for that name. [`validate`] holds the table at config load.
//!
//! This retires the authored hook body's four jobs: resolving the runner
//! (`mise exec --` is the row's own argv), the per-commit `--profile '!slow'`
//! (also the row's argv), and the re-entry guard on a live `BATTEN_GATE_PID`,
//! which lives here in the entry point. The fourth, a probe for `doctor`, is
//! `doctor gate`'s stat of the link.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::{exec, git, hook, resolve};

/// Run as a git hook: argv[0] is a githooks(5) name (CLOUD-2339).
///
/// Every git hook links to this binary, so the hook IS batten: it loads the
/// committed `[hook.git]` table from the work tree git runs the hook in, and
/// passes git's own arguments and streams through to the argv declared for
/// that name. A name with no row, or a clone with no config, exits 0.
///
/// Before the output mode and the parser, as [`crate::provision::launched`] and
/// [`crate::rustc_wrapped`] are: everything after argv[0] is git's.
///
/// Exit codes stay inside the 0/1/2/3 contract: the child's `0` is `0`, any
/// other child exit is `2` (`hook-command-failed`), a config that will not
/// load is `1`, a child that could not start is `3`. A live `BATTEN_GATE_PID`
/// marker is `2` (`hook-reentry-refused`): the gate re-entered itself, which
/// once hung a commit, and the declared command is not run.
///
/// `None` when argv[0] names no git hook: the binary parses its own arguments.
#[must_use]
pub fn dispatched(mut args: impl Iterator<Item = std::ffi::OsString>) -> Option<ExitCode> {
    let invoked = PathBuf::from(args.next()?);
    let name = invoked.file_name()?.to_str()?.to_owned();
    if !hook::is_git_hook(&name) {
        return None;
    }
    let rest: Vec<String> = args.map(|arg| arg.to_string_lossy().into_owned()).collect();
    Some(run(&name, &rest, &mut std::io::stderr()))
}

/// [`dispatched`]'s body, over git's arguments.
//MUTANT-SUITE crates/batten/tests/it/git_hook.rs
//MUTANT hook-reentry-unguarded|s@^    if marker.as_deref().is_some_and(crate::task::pid_exists) {$@    if false {@|a_live_gate_marker_is_refused_as_hook_reentry
//MUTANT dead-pid-refuses|s@^    if marker.as_deref().is_some_and(crate::task::pid_exists) {$@    if marker.is_some() {@|a_dead_gate_marker_does_not_refuse_the_binary
//MUTANT argv0-dispatch-ignored|s@^    let Some(argv) = declared.get(name) else {$@    let Some(argv) = declared.get("pre-commit") else {@|the_link_invoked_as_commit_msg_runs_the_commit_msg_row
//MUTANT passthrough-args-dropped|s@^    command.extend(rest.iter().cloned());$@@|a_declared_pre_push_receives_gits_arguments_and_stdin
fn run(name: &str, rest: &[String], err: &mut dyn Write) -> ExitCode {
    // Not a repository: nothing can be declared for it, so nothing is owed.
    let Ok(root) = git::repo_root(Path::new(".")) else {
        return ExitCode::Success;
    };
    let config = match resolve::resolve(&root, &resolve::Overrides::default()) {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(err, "batten deny hook-config-unloadable at {name}: {error}");
            return ExitCode::Usage;
        }
    };
    let declared = config
        .hook
        .as_ref()
        .map(|hook| hook.git.clone())
        .unwrap_or_default();
    let Some(argv) = declared.get(name) else {
        return ExitCode::Success;
    };
    let marker = std::env::var(GATE_PID).ok();
    if marker.as_deref().is_some_and(crate::task::pid_exists) {
        let _ = writeln!(
            err,
            "batten deny hook-reentry-refused at {name} pid {}",
            marker.as_deref().unwrap_or_default()
        );
        return ExitCode::Violation;
    }
    let mut command = argv.clone();
    command.extend(rest.iter().cloned());
    let published = [(GATE_PID.to_owned(), std::process::id().to_string())];
    match exec::classify_in_env(&root, &command, &[], &exec::ExecConfig::DEFAULT, &published) {
        Ok((0, ..)) => ExitCode::Success,
        Ok(_) => {
            let _ = writeln!(err, "batten deny hook-command-failed at {name}");
            ExitCode::Violation
        }
        Err(error) => {
            let _ = writeln!(
                err,
                "batten: the {name} hook's command could not run: {error}"
            );
            ExitCode::Internal
        }
    }
}

/// The re-entry marker a git hook publishes to the command it runs.
const GATE_PID: &str = "BATTEN_GATE_PID";

/// Reject a `[hook.git]` row whose name is no git hook, or whose argv is empty
/// (CLOUD-2339): either would load clean and run nothing at the moment the
/// operator believes it guards.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) naming the row.
//MUTANT-SUITE crates/batten/tests/it/git_hook.rs
//MUTANT hook-git-key-unchecked|s@^        if !crate::hook::is_git_hook(name) {$@        if false {@|an_unknown_hook_git_key_refuses_the_config
pub fn validate(rows: &std::collections::BTreeMap<String, Vec<String>>) -> anyhow::Result<()> {
    for (name, argv) in rows {
        if !crate::hook::is_git_hook(name) {
            return Err(UsageError::raise(format!(
                "hook.git {name}: not a githooks(5) name, so git never runs it"
            )));
        }
        if argv.first().is_none_or(String::is_empty) {
            return Err(UsageError::raise(format!(
                "hook.git {name}: an empty argv runs nothing"
            )));
        }
    }
    Ok(())
}
