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
// carried: mise-tasks/serena-mcp.sh crates/batten/src/mcp.rs kind:verb crates/batten/tests/it/mcp_spawn.rs runs:batten+mcp+spawn
// carried: tests/serena-mcp.bats crates/batten/src/mcp.rs kind:verb crates/batten/tests/it/mcp_spawn.rs runs:batten+mcp+spawn
//
// carried: "a launch appends one record naming the server, and execs the launch line" crates/batten/src/mcp.rs
// carried: "THE SERVER'S PID IS THE SHIM'S — it execs rather than forks" crates/batten/src/mcp.rs
// carried: "the record carries five fields: epoch, server, pid, load, siblings" crates/batten/src/mcp.rs
// carried: "a launch inside the window counts the earlier one as a sibling" crates/batten/src/mcp.rs
// carried: "a launch outside the window counts no sibling" crates/batten/src/mcp.rs
// carried: "STDOUT CARRIES ONLY THE SERVER'S BYTES — stdout is the MCP transport" crates/batten/src/mcp.rs
// carried: "an unwritable ledger never stops the server from starting" crates/batten/src/mcp.rs
// changed: "the server name comes from the shim's own basename, so a second server is a second name" crates/batten/src/mcp.rs from `tests/serena-mcp.bats`. The property it protected — one name per server, never one script per server — is now structural: the name is a positional argument, so a second server cannot get the first one's name without somebody typing it. What the case actually asserted was a basename-stripping loop (`.sh` off before `-mcp`, in that order, or the suffix never matches) and that loop does not exist any more. `a_second_server_is_an_argument_rather_than_a_second_script` is the property without the loop
// changed: "the shim is what .mcp.json launches, so the ledger is populated in real sessions" crates/batten/src/mcp.rs from `tests/serena-mcp.bats`. Same claim, new spelling: the case grepped `.mcp.json` for the script path, and `the_committed_client_config_launches_this_verb` reads the same file for the verb's argv. It is CHANGED rather than CARRIED because the committed spelling moved from a path to a command line
// changed: "the launch args stay in .mcp.json, so the pin gate still reads them" crates/batten/src/mcp.rs from `tests/serena-mcp.bats`. The args are still in `.mcp.json` and `mise-pin-agreement` still reads the pin out of them, but they now sit BEHIND the verb's trailing separator rather than at the head of the array. The case asserted their position as well as their presence, and only the presence survives — which is the half the pin gate needs

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

#[test]
fn the_committed_client_config_launches_this_verb() {
    // The retired case grepped `.mcp.json` for the script path; this reads the
    // same file for the verb's argv. Without it the ledger is empty in every real
    // session and the whole mechanism is inert — which is the property, and it
    // cannot be asserted about a fixture.
    let config = std::fs::read_to_string(at_root(".mcp.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&config).unwrap();
    let serena = &parsed["mcpServers"]["serena"];
    assert_eq!(serena["command"], "batten", "{parsed}");
    let args: Vec<String> = serena["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(args[0], "mcp", "{args:?}");
    assert_eq!(args[1], "spawn", "{args:?}");
    assert_eq!(args[2], "serena", "{args:?}");
    // THE SEPARATOR IS PART OF THE CONTRACT. Without it clap refuses the argv
    // outright, so a config that dropped it would fail every launch — and the
    // failure would look like the client never spawning the server, which is the
    // exact reading this ledger exists to disambiguate.
    assert_eq!(args[3], "--", "{args:?}");
}

#[test]
fn the_pinned_launch_args_are_still_in_the_committed_config() {
    // `mise-pin-agreement` reads the pin out of `.mcp.json`, so the args have to
    // stay there. They moved BEHIND the verb rather than leading the array, and
    // the pin gate reads presence rather than position — which is why the arm for
    // this one is `// changed:` and not a carry.
    let config = std::fs::read_to_string(at_root(".mcp.json")).unwrap();
    assert!(config.contains("pipx:serena-agent@"), "{config}");
    assert!(config.contains("start-mcp-server"), "{config}");
}
