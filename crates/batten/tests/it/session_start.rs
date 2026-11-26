//! `SessionStart` spawns nothing and names the one install task the agent
//! dispatches (CLOUD-2840), over the compiled binary.
//!
//! The owner's design: the hook is a 10/100 ms hook like every other, and it
//! tells the agent how to install as a background task. A handler that blocks
//! until the case releases it, declared with a ten-minute bound, is the worst a
//! consumer can write; the door must answer without running it or starting
//! anything that would, and once the agent dispatches the task, what the
//! handler said must reach the session exactly once after it finishes.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;
use batten::capture::StreamedChild as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{stderr, stdout, write};

/// How long a case polls for the handler to open its gate before it gives up.
/// An INPUT, never an assertion (`wall_clock.rs`): the loop ends the moment the
/// handler reads, and giving up is the failure.
const SETTLE: Duration = Duration::from_secs(120);

/// One hook call through the door: `event`, with `extra` merged into the payload.
pub(crate) fn door(repo: &Path, event: &str, extra: &serde_json::Value) -> (String, String) {
    use std::io::Write as _;
    // THE REPOSITORY'S OWN SESSION (CLOUD-2840): a session's home is recorded
    // in the suite's shared state root by its id, so one fixed id judged every
    // fixture's call in the first fixture's repository under `cargo test`.
    let mut payload = serde_json::json!({
        "hook_event_name": event,
        "session_id": format!("session-start-fixture@{}", repo.display()),
        "source": "startup",
        "cwd": repo,
    });
    if let (Some(into), Some(from)) = (payload.as_object_mut(), extra.as_object()) {
        into.extend(from.clone());
    }
    let mut child = common::batten()
        .current_dir(repo)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(payload.to_string().as_bytes())
        .expect("write stdin");
    let outcome = child.streamed_wait().expect("wait for batten");
    assert_eq!(outcome.status.code(), Some(0), "{}", stderr(&outcome));
    (stdout(&outcome), stderr(&outcome))
}

/// A `PreToolUse` for a read: the first call after setup, which carries it.
pub(crate) fn pre_tool(repo: &Path) -> String {
    let (out, err) = door(
        repo,
        "PreToolUse",
        &serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": "batten.toml"}}),
    );
    format!("{out}{err}")
}

/// The dispatch the door names, as the agent runs it: `batten startup
/// --session` in `repo`, through `command` (so a case's `PATH`, `HOME` or
/// environment kind reaches the task exactly as it would reach the agent's).
fn dispatch(repo: &Path, mut command: common::Batten) -> common::Batten {
    command.current_dir(repo).args(["startup", "--session"]);
    command
}

/// Dispatch the setup task through `command`, run it to its end, and answer
/// its last phase: what the agent's background task leaves behind.
pub(crate) fn settle_with(repo: &Path, command: common::Batten) -> String {
    let mut command = dispatch(repo, command);
    let ran = command.streamed_output().expect("the task runs");
    assert!(
        matches!(ran.status.code(), Some(0 | 1)),
        "the task answers 0 or 1: {}",
        stderr(&ran)
    );
    setup_phase(repo).expect("the dispatched task registered itself")
}

/// [`settle_with`] under the suite's own engine invocation.
pub(crate) fn settle(repo: &Path) -> String {
    settle_with(repo, common::batten())
}

/// The FIFO at `gate`, opened for write once the handler has opened it to
/// read, GIVING UP AS SOON AS NOTHING EVER WILL (CLOUD-2789). A blocking open
/// waits for a reader forever: a setup task that returned before its handlers
/// ran hung this case to nextest's timeout rather than turning it red. The open
/// is non-blocking, so with no reader it fails at once, and `task` — the
/// dispatched process itself, this case's own child — decides whether to try
/// again: once it has exited, nothing will ever read. The handler blocks until
/// the descriptor is written or dropped.
fn reader(task: &mut std::process::Child, repo: &Path, gate: &Path) -> rustix::fd::OwnedFd {
    use rustix::fs::{Mode, OFlags};
    let began = Instant::now();
    while began.elapsed() < SETTLE {
        match rustix::fs::open(
            gate,
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => return fd,
            Err(rustix::io::Errno::NXIO) => {}
            Err(other) => panic!("the gate cannot be opened: {other}"),
        }
        if let Ok(Some(status)) = task.try_wait() {
            panic!(
                "the setup task exited ({status}) before its handler read the gate: {:?}",
                setup_phase(repo)
            );
        }
        std::thread::yield_now();
    }
    panic!("the handler never opened the gate: {:?}", setup_phase(repo));
}

/// Write `line` to the handler through `fd`, then close it.
fn write_gate(fd: rustix::fd::OwnedFd, line: &str) {
    let wrote = rustix::io::write(&fd, line.as_bytes()).expect("write the gate");
    assert_eq!(wrote, line.len(), "the whole line reaches the handler");
    // CLOSED HERE, which is the handler's end of file.
    drop(fd);
}

/// The setup task's current phase, or `None` where nothing registered it.
pub(crate) fn setup_phase(repo: &Path) -> Option<String> {
    setup_field(repo, "phase")
}

/// One field of the setup task's registry record, or `None` where nothing
/// registered it.
fn setup_field(repo: &Path, field: &str) -> Option<String> {
    let dir = repo.join(".git/batten-tasks");
    let prefix = format!("{field}: ");
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .find(|body| body.lines().any(|line| line == "task: session-setup"))
        .and_then(|body| {
            body.lines()
                .find_map(|line| line.strip_prefix(prefix.as_str()))
                .map(str::to_owned)
        })
}

/// A fixture repository declaring one `session-start` row running `body`.
fn bench(name: &str, body: &str, timeout_ms: u64) -> PathBuf {
    let repo = common::Fixture::new(name).build();
    std::fs::create_dir_all(repo.join("steps")).expect("the fixture repo");
    write(
        &repo,
        "batten.toml",
        &format!(
            "version = 1\n\n[[hook.handler]]\nid = \"step\"\non = \"session-start\"\nrun = [\"steps/step\"]\ntimeout_ms = {timeout_ms}\n"
        ),
    );
    write(&repo, "steps/step", &format!("#!/bin/sh\n{body}\n"));
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = repo.join("steps/step");
        let mut mode = std::fs::metadata(&path).expect("the stub").permissions();
        mode.set_mode(0o755);
        std::fs::set_permissions(&path, mode).expect("the stub is runnable");
    }
    let wired = common::batten()
        .current_dir(&repo)
        .args(["wiring", "register", "--all"])
        .streamed_output()
        .expect("the binary runs");
    assert_eq!(wired.status.code(), Some(0), "{}", stderr(&wired));
    repo
}

/// Whether a process other than this one runs `batten startup --session`
/// with `repo` as its directory: the spawn the door must never make.
fn setup_process_in(repo: &Path) -> bool {
    let own = std::process::id().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if pid == own || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let words: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
        let dispatched = words
            .windows(2)
            .any(|pair| pair == [&b"startup"[..], &b"--session"[..]]);
        dispatched && std::fs::read_link(entry.path().join("cwd")).is_ok_and(|cwd| cwd == repo)
    })
}

/// Whether anything holds `gate` open to read: a non-blocking open for write
/// fails with `ENXIO` exactly when no reader exists.
fn read_by_anyone(gate: &Path) -> bool {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(
        gate,
        OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .is_ok()
}

/// A FIFO at `repo/gate` the fixture's handler blocks on.
fn fifo(repo: &Path) -> PathBuf {
    let gate = repo.join("gate");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, test-only: a FIFO is made by `mkfifo`, and no door in `common` makes one"
    )]
    let made = std::process::Command::new("mkfifo")
        .arg(&gate)
        .streamed_output()
        .expect("mkfifo runs");
    assert!(made.status.success(), "{}", stderr(&made));
    gate
}

/// The blocking fixture: a handler that waits on the FIFO, bounded at ten
/// minutes, which an inline dispatch would have waited out.
fn blocking_bench(name: &str) -> (PathBuf, PathBuf) {
    let repo = bench(
        name,
        "read line < \"$(dirname \"$0\")/../gate\"\necho \"step finished: $line\"",
        600_000,
    );
    let gate = fifo(&repo);
    (repo, gate)
}

/// Fails by: a `SessionStart` that runs a declared handler or spawns the task
/// that would (mutant `session-start-spawns`, 70d075762's design); or one
/// that tells the agent nothing, so the session never dispatches the install.
///
/// THE FIFO IS THE BOUND, NOT A CLOCK (`wall_clock.rs`): a door that ran the
/// handler inline would hold this case until nextest's timeout, and a door that
/// spawned it leaves a reader on the gate and a record in the registry, both
/// read here. The 100 ms the hook owes is the `session-start` perf arm's.
#[test]
fn a_session_start_spawns_nothing_and_names_the_dispatch() {
    let (repo, gate) = blocking_bench("session-start-spawns-nothing");
    let (out, _) = door(&repo, "SessionStart", &serde_json::json!({}));
    // ON THE ADVISORY CHANNEL every hook's advice uses: Claude Code's
    // `additionalContext`, the document the model reads at session start.
    let document: serde_json::Value = serde_json::from_str(&out).expect("one JSON document");
    let advised = document["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default();
    assert!(
        advised.contains("batten startup --session") && advised.contains("run_in_background"),
        "the door names the dispatch and how to run it: {out}"
    );
    assert_eq!(setup_phase(&repo), None, "the registry names no task");
    assert!(!setup_process_in(&repo), "no setup process runs");
    assert!(!read_by_anyone(&gate), "no handler waits on the gate");
    // ANTI-VACUITY: the same probes see the task once the agent dispatches it.
    let mut child = dispatch(&repo, common::batten())
        .spawn()
        .expect("the task starts");
    let held = reader(&mut child, &repo, &gate);
    // ANTI-VACUITY: the probe sees the task once it holds the gate.
    assert!(setup_process_in(&repo), "the probe sees a running task");
    write_gate(held, "released\n");
    let ended = child.streamed_wait().expect("the task ends");
    assert_eq!(ended.status.code(), Some(0), "advice is not failure");
    assert_eq!(setup_phase(&repo).as_deref(), Some("ok"));
}

/// Fails by: a dispatched task the registry cannot name while it runs; a
/// second dispatch that stacks a second record; or an outcome that never
/// reaches the session, or reaches it twice.
#[test]
fn a_blocking_handler_holds_nothing_and_is_said_once() {
    let (repo, gate) = blocking_bench("session-start-dispatched");
    let (out, _) = door(&repo, "SessionStart", &serde_json::json!({}));
    assert!(!out.contains("step finished"), "{out}");

    let mut child = dispatch(&repo, common::batten())
        .spawn()
        .expect("the task starts");
    // The task registers itself before its handler runs: once the handler
    // holds the gate, the registry names the task.
    let held = reader(&mut child, &repo, &gate);
    let alive = common::batten()
        .current_dir(&repo)
        .args(["task", "alive"])
        .streamed_output()
        .expect("the binary runs");
    assert!(
        stdout(&alive).contains("session-setup"),
        "the running task is in the registry: {}",
        stdout(&alive)
    );
    let first_pid = setup_field(&repo, "pid");
    // A SECOND DISPATCH WHILE ONE RUNS STACKS NOTHING: the singleton refuses
    // it before it records, so the gate still reads the one task installing.
    let second = dispatch(&repo, common::batten())
        .streamed_output()
        .expect("the second dispatch runs");
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    assert_eq!(
        setup_field(&repo, "pid"),
        first_pid,
        "one record, the first's"
    );
    assert!(
        !pre_tool(&repo).contains("step finished"),
        "nothing is said while the task runs"
    );

    write_gate(held, "released\n");
    let ended = child.streamed_wait().expect("the task ends");
    // ADVICE IS NOT FAILURE (review of 076a19082): the handler exits `0` and
    // speaks, so the task ends `ok` and its words are said once, below.
    assert_eq!(ended.status.code(), Some(0), "advice is not failure");
    assert_eq!(setup_phase(&repo).as_deref(), Some("ok"));
    let first = pre_tool(&repo);
    assert!(
        first.contains("step finished: released"),
        "the first call after the task carries what it said: {first}"
    );
    let second = pre_tool(&repo);
    assert!(
        !second.contains("step finished"),
        "and only the first: {second}"
    );
}

/// Fails by: the dispatch owed once per CLONE, so a new session in it is never
/// told to install and an old `ok` opens the gate for a session that never
/// dispatched (review of 076a19082); or owed again on a resume of a session
/// whose task finished.
#[test]
fn the_dispatch_is_owed_once_per_session() {
    let repo = bench("session-start-per-session", "exit 0", 5000);
    let advised = |session: &str, source: &str| {
        let (out, _) = door(
            &repo,
            "SessionStart",
            &serde_json::json!({"session_id": session, "source": source}),
        );
        out.contains("batten startup --session")
    };
    assert!(advised("one", "startup"), "a new session owes a dispatch");
    assert_eq!(settle(&repo), "ok");
    assert!(!advised("one", "resume"), "its resume owes nothing");
    assert!(!advised("one", "compact"), "nor its compaction");
    assert!(
        advised("two", "startup"),
        "a new session in the clone owes its own"
    );
}

/// Fails by: any compile on session start in a tree that pins no source — the
/// 224.87 s cold `cargo build --release` the engine rows' repair used to run
/// whenever `target/` was empty (CLOUD-2840). The two rows are the committed
/// ones, copied verbatim, in a Cargo workspace with no `target/` at all, and a
/// `cargo` and a `mise` that record any call stand first on `PATH`.
#[test]
fn no_compile_runs_without_a_source_pin() {
    use std::os::unix::fs::PermissionsExt as _;
    let repo = common::Fixture::new("session-start-no-compile").build();
    std::fs::create_dir_all(repo.join("crates/batten")).expect("the fixture repo");
    write(
        &repo,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/batten\"]\n",
    );
    write(
        &repo,
        "crates/batten/Cargo.toml",
        "[package]\nname = \"batten\"\nversion = \"0.0.0\"\n",
    );
    let committed: toml::Table = std::fs::read_to_string(common::at_root("batten.toml"))
        .expect("the committed authority")
        .parse()
        .expect("the committed authority parses");
    let rows: Vec<toml::Value> = committed["startup"]
        .as_array()
        .expect("[[startup]] rows")
        .iter()
        .filter(|row| {
            matches!(
                row["id"].as_str(),
                // `mediator-matches-the-tree` is withheld until step 14.
                Some("engine-resolves-every-row")
            )
        })
        .cloned()
        .collect();
    assert_eq!(rows.len(), 1, "the engine row is committed");
    let mut config = toml::Table::new();
    config.insert("version".to_owned(), toml::Value::Integer(1));
    config.insert("startup".to_owned(), toml::Value::Array(rows));
    write(
        &repo,
        "batten.toml",
        &toml::to_string(&config).expect("the fixture config renders"),
    );

    let bin = repo.join("stub-bin");
    std::fs::create_dir_all(&bin).expect("the stub directory");
    let log = repo.join("compiled.log");
    for program in ["cargo", "mise"] {
        let path = bin.join(program);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' {program} \"$*\" >> '{}'\n",
                log.display()
            ),
        )
        .expect("the stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the stub is runnable");
    }
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_batten"), bin.join("batten"))
        .expect("the engine under test is the `batten` on PATH");
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&common::ambient_path())),
    )
    .expect("a joinable PATH");

    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "session_id": "session-start-no-compile",
        "source": "startup",
        "cwd": repo,
    })
    .to_string();
    let mut command = common::batten();
    command.env("PATH", &path);
    let _ = common::stdin_run(
        &mut command,
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    // THE AGENT'S DISPATCH, under the same `PATH` the session has.
    let mut task = common::batten();
    task.env("PATH", &path);
    let _ = settle_with(&repo, task);
    let called = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !called.contains("cargo") && !called.contains("install:local"),
        "a session in a tree pinning no source compiled: {called}"
    );
    assert!(!repo.join("target").exists(), "nothing built into target/");
}

/// Fails by: the environment manager's install running after the declared
/// handlers, or not at all (CLOUD-2840). Every later step runs a pinned tool,
/// so the preset's install is the setup task's first step. A `mise` stub that
/// reports a missing tool and records each call stands first on `PATH`.
#[test]
fn the_preset_install_runs_before_any_handler() {
    use std::os::unix::fs::PermissionsExt as _;
    let repo = common::Fixture::new("session-start-install-first").build();
    std::fs::create_dir_all(repo.join("steps")).expect("the fixture repo");
    let log = repo.join("order.log");
    write(
        &repo,
        "batten.toml",
        "version = 1\n\n[[rule]]\nid = \"task reach loose\"\nkind = \"policy\"\n\
         scope = \"mediated_call\"\npreset = \"mise\"\nseverity = \"warn\"\n\
         environments = [\"agent\"]\n\n\
         [[hook.handler]]\nid = \"step\"\non = \"session-start\"\nrun = [\"steps/step\"]\n\
         timeout_ms = 5000\n\n\
         [[startup]]\nid = \"toolchain\"\ngloss = \"the listed environments are installed\"\n\
         preset = \"mise\"\n",
    );
    write(&repo, "mise.agent.toml", "");
    let script = |path: &Path, body: &str| {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("the stub");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("the stub is runnable");
    };
    script(
        &repo.join("steps/step"),
        &format!("printf 'handler\\n' >> '{}'", log.display()),
    );
    let bin = repo.join("stub-bin");
    std::fs::create_dir_all(&bin).expect("the stub directory");
    script(
        &bin.join("mise"),
        &format!(
            "printf 'mise %s\\n' \"$*\" >> '{}'\ncase \"$1\" in ls) echo 'tool 1.0 (missing)' ;; esac",
            log.display()
        ),
    );
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&common::ambient_path())),
    )
    .expect("a joinable PATH");
    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "session_id": "session-start-install-first",
        "source": "startup",
        "cwd": repo,
    })
    .to_string();
    let mut command = common::batten();
    command.env("PATH", &path);
    let _ = common::stdin_run(
        &mut command,
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    // THE AGENT'S DISPATCH, under the same `PATH` the session has.
    let mut task = common::batten();
    task.env("PATH", &path);
    let _ = settle_with(&repo, task);
    let order = std::fs::read_to_string(&log).expect("the task ran");
    let lines: Vec<&str> = order.lines().collect();
    let install = lines
        .iter()
        .position(|line| line.starts_with("mise install --yes"));
    let handler = lines.iter().position(|line| *line == "handler");
    assert!(
        install.is_some() && handler.is_some() && install < handler,
        "the preset's install precedes every handler: {order}"
    );
}
