//! `batten mcp spawn`, over the compiled binary — CLOUD-714's ledger, ported off
//! `mise-tasks/serena-mcp.sh` under CLOUD-1753.
//!
//! # What the shim was for, and why the port changes none of it
//!
//! Serena failed to attach three times on 2026-08-19, each burning ~28,300 ms of
//! a 30,000 ms budget and leaving NO trace: no server log, no `Server stderr:`
//! record in the client's own log, nothing. Two very different failures produce
//! that exact signature — the client never executed the configured command, or it
//! executed it and the child died before the server opened its log file, which is
//! ~1.2 s of import into the process. Nothing could tell those apart, and a day
//! went into archaeology that still could not answer it.
//!
//! The answer is a file read: the FIRST thing that happens is a line saying the
//! launch ran, and the LAST is becoming the launch line. A connect timeout WITH a
//! matching record means spawned-and-unresponsive; one WITHOUT means never
//! spawned. `mcp-attach-check` makes that comparison, and it opens the ledger BY
//! PATH — so the location and the tab-separated layout are a contract with a
//! reader this port does not own, preserved exactly.
//!
//! # THIS TIER EXISTS FOR ONE PROPERTY THE MODULE'S OWN CASES CANNOT REACH
//!
//! `exec` versus fork is observable only from OUTSIDE the process, and only over
//! a real binary: the recorded pid and the launched program's own pid are the
//! same number if and only if this process was replaced. A unit case calling
//! `record_spawn` sees neither. That is the property CLOUD-714 forbids losing —
//! after an exec there is no process left that could become the retry loop or the
//! supervisor the issue rules out — so it is asserted here, against the compiled
//! binary, exactly as the retiring suite asserted it against the shim.
//!
//! # What the port improves, and it is the one thing the shell could not do
//!
//! The shell derived the server name from its own basename, so a second server
//! meant a second COPY of the script — `serena-mcp.sh`, then `foo-mcp.sh`, each
//! with its own basename-stripping and its own ledger logic. The verb takes the
//! name as an argument, so a second server is an argument.
//
// THE RETIREMENT ARMS ARE BACK, AND WHAT WAS MISSING LAST TIME IS NOW TRUE
// (CLOUD-1326, then CLOUD-843).
//
// This tier once carried these arms while the shim's only caller, `.mcp.json`,
// still named the shim — and the client resolves `batten` on `PATH`, a RELEASE,
// which did not ship `mcp spawn` then. The arms were withdrawn as a false claim
// about callers. Both halves have moved since: the release on `PATH` ships the
// verb, and `.mcp.json` now names `batten mcp spawn serena -- mise exec …`, so
// the shim has no caller left and retires with its suite.
//
// carried: mise-tasks/serena-mcp.sh crates/batten/src/mcp.rs kind:verb crates/batten/tests/it/mcp_spawn.rs runs:batten+mcp+spawn
// carried: tests/serena-mcp.bats crates/batten/src/mcp.rs kind:verb crates/batten/tests/it/mcp_spawn.rs
//
// carried: "a launch appends one record naming the server, and execs the launch line" crates/batten/tests/it/mcp_spawn.rs
// carried: "THE SERVER'S PID IS THE SHIM'S — it execs rather than forks" crates/batten/tests/it/mcp_spawn.rs
// carried: "the record carries five fields: epoch, server, pid, load, siblings" crates/batten/tests/it/mcp_spawn.rs
// carried: "a launch inside the window counts the earlier one as a sibling" crates/batten/tests/it/mcp_spawn.rs
// carried: "a launch outside the window counts no sibling" crates/batten/tests/it/mcp_spawn.rs
// carried: "STDOUT CARRIES ONLY THE SERVER'S BYTES — stdout is the MCP transport" crates/batten/tests/it/mcp_spawn.rs
// carried: "an unwritable ledger never stops the server from starting" crates/batten/tests/it/mcp_spawn.rs
// changed: "the server name comes from the shim's own basename, so a second server is a second name" crates/batten/src/mcp.rs kind:verb the name is an ARGUMENT of the verb rather than the program's basename, so a second server is a second argument and never a second copy of a script; asserted by `a_second_server_is_an_argument_rather_than_a_second_script`
// changed: "the shim is what .mcp.json launches, so the ledger is populated in real sessions" crates/batten/src/mcp.rs kind:verb `.mcp.json` launches `batten mcp spawn serena -- …` rather than the shim; asserted over the committed bytes by `the_committed_config_launches_serena_through_the_verb`
// carried: "the launch args stay in .mcp.json, so the pin gate still reads them" crates/batten/tests/it/mcp_spawn.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{at_root, batten};

/// A launcher standing in for the real server command.
///
/// **It prints its own pid**, which is the only thing that can distinguish exec
/// from fork from outside the process — the retiring suite's device, kept because
/// it is the right one.
fn launcher(dir: &Path) -> PathBuf {
    let path = dir.join("launcher");
    common::write(
        dir,
        "launcher",
        "#!/usr/bin/env bash\nprintf 'pid=%s args=%s\\n' \"$$\" \"$*\"\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

/// A git repository with a launcher in it, and the ledger path a reader would
/// open.
fn bench(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = common::scratch_outside_tree("batten-mcp-spawn", name);
    // `init_repo` rather than a `git init` of this suite's own, which is what
    // `fixture-forks` refuses and caught here on the first run: the harness
    // publishes a template once per filesystem and copies it, so a fixture that
    // forked for itself would put back the processes that mechanism removed.
    common::init_repo(&dir);
    let launcher = launcher(&dir);
    let ledger = dir.join(".git").join("batten-mcp-spawns");
    (dir, launcher, ledger)
}

/// Run `mcp spawn <server> -- <launcher> <args...>`.
///
/// **The `--` is required rather than decorative.** The trailing list is declared
/// `last(true)`, so clap will not take a free token as the start of the launch
/// line — which is the right refusal for this verb: a launch line that began
/// wherever the parser guessed could silently drop its first word, and the ledger
/// would record a launch of something else.
fn spawn(dir: &Path, server: &str, launcher: &Path, args: &[&str]) -> std::process::Output {
    let mut command = batten();
    command.arg("mcp").arg("spawn").arg(server).arg("--");
    command.arg(launcher);
    command.args(args);
    command
        .current_dir(dir)
        .output()
        .expect("run batten mcp spawn")
}

fn ledger_lines(ledger: &Path) -> Vec<Vec<String>> {
    let Ok(text) = std::fs::read_to_string(ledger) else {
        return Vec::new();
    };
    text.lines()
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect()
}

#[test]
fn a_launch_appends_one_record_naming_the_server_and_becomes_the_launch_line() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    let (dir, launcher, ledger) = bench("one-record");
    let output = spawn(
        &dir,
        "serena",
        &launcher,
        &["exec", "pipx:serena-agent@1.6.1"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("args=exec pipx:serena-agent@1.6.1"),
        "the launch line runs verbatim: {text}"
    );
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0][1], "serena");
}

#[test]
fn the_servers_pid_is_this_processs_it_execs_rather_than_forks() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    // NON-NEGOTIABLE FOR THIS DESIGN, and the one property only a compiled-binary
    // tier can see. After `exec` there is no process left, so the verb
    // structurally cannot become the supervisor or retry loop CLOUD-714 forbids.
    // A fork would also leave the recorded pid pointing at a process that is not
    // the server, which is a wrong answer to the question being asked.
    let (dir, launcher, ledger) = bench("exec-not-fork");
    let output = spawn(&dir, "serena", &launcher, &["x"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let lines = ledger_lines(&ledger);
    let recorded = &lines[0][2];
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains(&format!("pid={recorded}")),
        "the recorded pid must BE the server's: recorded {recorded}, said {text}"
    );
}

#[test]
fn the_record_carries_five_fields() {
    let (dir, launcher, ledger) = bench("five-fields");
    spawn(&dir, "serena", &launcher, &["x"]);
    let lines = ledger_lines(&ledger);
    assert_eq!(lines[0].len(), 5, "{lines:?}");
    assert!(lines[0][0].parse::<u64>().is_ok(), "{lines:?}");
    assert!(lines[0][4].parse::<u64>().is_ok(), "{lines:?}");
}

#[test]
fn a_launch_inside_the_window_counts_the_earlier_one_as_a_sibling() {
    // The hypothesis field. All three CLOUD-714 failures happened during a
    // multi-server startup burst and every successful isolated replication was a
    // lone launch, which is n=3 with no mechanism attached — so this count is
    // what lets the NEXT occurrence decide it.
    let (dir, launcher, ledger) = bench("sibling-inside");
    spawn(&dir, "serena", &launcher, &["x"]);
    spawn(&dir, "other", &launcher, &["x"]);
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 2, "{lines:?}");
    // Counted BEFORE the append, so a launch never counts itself.
    assert_eq!(lines[0][4], "0", "{lines:?}");
    assert_eq!(lines[1][4], "1", "{lines:?}");
}

#[test]
fn a_launch_outside_the_window_counts_no_sibling() {
    let (dir, launcher, ledger) = bench("sibling-outside");
    // An entry old enough to be outside the ten-second window, written directly:
    // the alternative is sleeping for the window, which buys the same assertion
    // at ten seconds a run.
    common::write(
        &dir.join(".git"),
        "batten-mcp-spawns",
        "1000000000\tancient\t1\t0.0\t0\n",
    );
    spawn(&dir, "serena", &launcher, &["x"]);
    let lines = ledger_lines(&ledger);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[1][4], "0", "{lines:?}");
}

#[test]
fn stdout_carries_only_the_servers_bytes() {
    // STDOUT IS THE MCP TRANSPORT. One stray byte corrupts the JSON-RPC stream
    // and takes the server down in a way that looks exactly like the bug this
    // records, so Batten writes nothing there — not a pointer, not a
    // confirmation, not a diagnostic.
    let (dir, launcher, _) = bench("stdout-clean");
    let output = spawn(&dir, "serena", &launcher, &["x"]);
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    for line in text.lines() {
        assert!(
            line.starts_with("pid="),
            "only the launched program may write to stdout: {line}"
        );
    }
}

#[test]
fn an_unwritable_ledger_never_stops_the_server_from_starting() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    // A ledger that cannot be written must never be the reason a server does not
    // start. The launch is the product; the record is the diagnosis.
    let (dir, launcher, ledger) = bench("ledger-unwritable");
    // A DIRECTORY where the ledger goes: opening it for append fails on every
    // platform, without needing a permission bit that a root-running container
    // ignores.
    std::fs::create_dir_all(&ledger).unwrap();
    let output = spawn(&dir, "serena", &launcher, &["x"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(text.contains("pid="), "the server still started: {text}");
}

#[test]
fn a_launch_outside_a_checkout_still_starts_the_server() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    // Outside a repository there is nowhere per-clone to keep the ledger, and
    // inventing a path under the temp directory would put it where no gate reads.
    // So this records nothing and launches anyway, which is the same priority the
    // unwritable case states.
    let dir = common::scratch_outside_tree("batten-mcp-spawn", "no-repo");
    let launcher = launcher(&dir);
    let output = spawn(&dir, "serena", &launcher, &["x"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("pid="),
        "{output:?}"
    );
}

#[test]
fn a_second_server_is_an_argument_rather_than_a_second_script() {
    // What the retired basename case protected, without the basename loop. The
    // shell read the server out of its own file name, so a second server meant a
    // second COPY of the script — and the stripping order was load-bearing
    // (`.sh` off before `-mcp`, or the suffix never matches, CLOUD-865).
    let (dir, launcher, ledger) = bench("second-server");
    spawn(&dir, "serena", &launcher, &["x"]);
    spawn(&dir, "context7", &launcher, &["x"]);
    let lines = ledger_lines(&ledger);
    assert_eq!(lines[0][1], "serena", "{lines:?}");
    assert_eq!(lines[1][1], "context7", "{lines:?}");
}

#[test]
fn a_launch_line_that_will_not_start_is_a_refusal_and_not_a_silent_success() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    // `exec` returns only on failure, so reaching the line after it IS the error.
    // A verb that reported success here would tell a reader the server was
    // launched when nothing was — which is the false half of exactly the
    // distinction the ledger exists to draw.
    let (dir, _, _) = bench("launch-fails");
    let missing = dir.join("not-a-program");
    let output = spawn(&dir, "serena", &missing, &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(text.contains("could not become"), "{text}");
}

// THE COMMITTED CLIENT CONFIG IS THIS VERB'S CALLER NOW (CLOUD-843).
//
// A case here once asserted `.mcp.json` names `batten mcp spawn` while no release
// shipped the verb, so the server died at startup with no report and `mem:*` was
// unreachable for a whole session (CLOUD-1326) — green throughout, because it
// read the committed bytes and found what the commit wrote. The repoint belonged
// to the release that shipped the verb; that release is the one on `PATH` now, so
// the repoint landed and this case pins it.
#[test]
fn the_committed_config_launches_serena_through_the_verb() {
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(at_root(".mcp.json")).unwrap()).unwrap();
    let serena = &config["mcpServers"]["serena"];
    assert_eq!(serena["command"], "batten", "{serena}");
    let args: Vec<&str> = serena["args"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        args.get(..4),
        Some(&["mcp", "spawn", "serena", "--"][..]),
        "the verb, the server's name, then the launch line: {args:?}"
    );
    assert_eq!(
        args.get(4..6),
        Some(&["mise", "exec"][..]),
        "the launch line is the scoped exec it always was: {args:?}"
    );
}

#[test]
fn a_launch_line_carrying_its_own_double_dash_runs_verbatim() {
    // UNIX ONLY: `mcp spawn` REPLACES this process (`exec`), and a host that
    // cannot do that is refused by design rather than served by a child; see
    // `a_host_that_cannot_replace_a_process_refuses_the_launch` for that arm.
    if !cfg!(unix) {
        return;
    }
    // THE COMMITTED SHAPE. `mise exec <tool> -- serena …` carries a `--` of its
    // own after the verb's. The trailing list must take it as a word of the
    // launch line, or the server would start without the argv that scopes it.
    let (dir, launcher, _) = bench("inner-double-dash");
    let output = spawn(
        &dir,
        "serena",
        &launcher,
        &[
            "exec",
            "pipx:serena-agent@1.7.0",
            "--",
            "serena",
            "start-mcp-server",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("args=exec pipx:serena-agent@1.7.0 -- serena start-mcp-server"),
        "the launch line runs verbatim, its own `--` included: {text}"
    );
}

#[test]
fn the_pinned_launch_args_are_still_in_the_committed_config() {
    // `mise-pin-agreement` reads the pin out of `.mcp.json`, so the args have to
    // stay there. Asserted here rather than only in the pin gate's own cases
    // because this tier is the one that runs over the committed file.
    let config = std::fs::read_to_string(at_root(".mcp.json")).unwrap();
    assert!(config.contains("pipx:serena-agent@"), "{config}");
    assert!(config.contains("start-mcp-server"), "{config}");
}

/// THE WINDOWS ARM, pinned rather than skipped. A host that cannot replace a
/// process refuses the launch with a usage-class exit and says why, instead of
/// running the server as a child: a supervisor that survives would break the
/// guarantee `mcp spawn` exists to give. Measured on #928's `windows` leg.
#[test]
fn a_host_that_cannot_replace_a_process_refuses_the_launch() {
    if cfg!(unix) {
        return;
    }
    let output = batten()
        .args(["mcp", "spawn", "fixture", "--", "cmd", "/c", "exit", "0"])
        .output()
        .expect("run batten mcp spawn");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot replace a process"),
        "{output:?}"
    );
}
