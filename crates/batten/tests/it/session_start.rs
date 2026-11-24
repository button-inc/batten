//! `SessionStart` starts the setup task and returns inside the hook budget
//! (CLOUD-2840), over the compiled binary.
//!
//! The property is the one a session feels: the agent's first response no
//! longer waits on provisioning. A handler that blocks until the case releases
//! it, declared with a ten-minute bound, is the worst a consumer can write; the
//! door must still answer at once, the registry must name the task while it
//! runs, and what the handler said must reach the session exactly once after it
//! finishes.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::Streamed as _;
use batten::capture::StreamedChild as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{stderr, stdout, write};

/// How long a case polls for the task's terminal phase before it gives up. An
/// INPUT, never an assertion (`wall_clock.rs`): the loop ends the moment the
/// phase lands, and giving up is the failure.
const SETTLE: Duration = Duration::from_secs(120);

/// One hook call through the door: `event`, with `extra` merged into the payload.
pub(crate) fn door(repo: &Path, event: &str, extra: &serde_json::Value) -> (String, String) {
    use std::io::Write as _;
    let mut payload = serde_json::json!({
        "hook_event_name": event,
        "session_id": "session-start-fixture",
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

/// The setup task's record, once its phase is terminal.
///
/// GIVES UP AS SOON AS THE TASK CANNOT FINISH, not only at [`SETTLE`]
/// (CLOUD-2789): a task the registry never named, or one whose process is gone
/// with its phase short of terminal, will never land one, and waiting out the
/// bound for it read a broken start as a hung suite rather than a red case.
pub(crate) fn settle(repo: &Path) -> String {
    let terminal = |phase: &Option<String>| {
        phase
            .as_deref()
            .is_some_and(|phase| phase == "ok" || phase == "failed")
    };
    let began = Instant::now();
    let mut asked = None::<Instant>;
    while began.elapsed() < SETTLE {
        let phase = setup_phase(repo);
        if terminal(&phase) {
            return phase.unwrap_or_default();
        }
        // Registered before the door returns (`session_setup::start`), so a
        // registry that does not name it never will.
        assert!(phase.is_some(), "nothing registered the setup task");
        // Asked at most once a second: each ask is a process.
        if asked.is_none_or(|at| at.elapsed() >= Duration::from_secs(1)) {
            asked = Some(Instant::now());
            if !setup_alive(repo) {
                // Read once more: the phase lands before the process exits.
                let last = setup_phase(repo);
                assert!(terminal(&last), "the setup task exited at {last:?}");
                return last.unwrap_or_default();
            }
        }
        std::thread::yield_now();
    }
    panic!("the setup task never finished: {:?}", setup_phase(repo));
}

/// Write `line` into the FIFO at `gate` once the handler has opened it to
/// read, GIVING UP AS SOON AS NOTHING EVER WILL (CLOUD-2789), as [`settle`]
/// does. A blocking open waits for a reader forever: a setup task that
/// returned before its handlers ran hung this case to nextest's timeout
/// rather than turning it red. The open is non-blocking, so with no reader it
/// fails at once and the task's liveness decides whether to try again.
fn release(repo: &Path, gate: &Path, line: &str) {
    use rustix::fs::{Mode, OFlags};
    let began = Instant::now();
    let mut asked = None::<Instant>;
    while began.elapsed() < SETTLE {
        match rustix::fs::open(
            gate,
            OFlags::WRONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let wrote = rustix::io::write(&fd, line.as_bytes()).expect("write the gate");
                assert_eq!(wrote, line.len(), "the whole line reaches the handler");
                return;
            }
            Err(rustix::io::Errno::NXIO) => {}
            Err(other) => panic!("the gate cannot be opened: {other}"),
        }
        if asked.is_none_or(|at| at.elapsed() >= Duration::from_secs(1)) {
            asked = Some(Instant::now());
            assert!(
                setup_alive(repo),
                "the setup task exited before its handler read the gate: {:?}",
                setup_phase(repo)
            );
        }
        std::thread::yield_now();
    }
    panic!("the handler never opened the gate: {:?}", setup_phase(repo));
}

/// Whether `batten task alive` names the setup task as running, and its
/// process has not exited.
///
/// AN EXITED PROCESS NOBODY REAPED STILL ANSWERS `kill -0` (CLOUD-2789): the
/// door's detached task outlives the door, so its parent is whatever adopts
/// it, and where that never reaps, a task that exited without pushing a phase
/// read as running until [`SETTLE`]. Its `/proc` state says it exited.
fn setup_alive(repo: &Path) -> bool {
    let alive = common::batten()
        .current_dir(repo)
        .args(["task", "alive"])
        .streamed_output()
        .expect("the binary runs");
    stdout(&alive).contains("session-setup") && !setup_exited(repo)
}

/// Whether the setup task's registered process has exited and waits to be
/// reaped: state `Z` in `/proc/<pid>/stat`, read past the parenthesised name.
/// Off Linux there is no `/proc` to read, and nothing is read as exited.
fn setup_exited(repo: &Path) -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    setup_field(repo, "pid")
        .and_then(|pid| std::fs::read_to_string(format!("/proc/{pid}/stat")).ok())
        .is_some_and(|stat| {
            stat.rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
        })
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

/// Fails by: a `SessionStart` that waits on a declared handler — the inline
/// dispatch this replaced, which held the first response for the row's whole
/// bound; a task the registry cannot name while it runs; or an outcome that
/// never reaches the session, or reaches it twice.
#[test]
fn a_blocking_handler_holds_nothing_and_is_said_once() {
    let repo = bench(
        "session-start-detached",
        "read line < \"$(dirname \"$0\")/../gate\"\necho \"step finished: $line\"",
        600_000,
    );
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

    // THE FIFO IS THE BOUND, NOT A CLOCK (`wall_clock.rs`). The handler cannot
    // finish until this case writes to the pipe below, so the door returning
    // here at all is the proof it did not wait: a door that waited would hold
    // this case until nextest's own timeout, which is red. The 100 ms the hook
    // owes is measured where measurements live, the `session-start` perf arm.
    let (out, _) = door(&repo, "SessionStart", &serde_json::json!({}));
    assert!(!out.contains("step finished"), "{out}");

    // Registered before the door returned, so the very next read names it.
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
    assert!(
        !pre_tool(&repo).contains("step finished"),
        "nothing is said while the task runs"
    );

    release(&repo, &gate, "released\n");
    assert_eq!(settle(&repo), "failed", "a speaking handler is a finding");
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

/// Fails by: a `SessionStart` that runs its rows inline, which registers no
/// task, so nothing names the setup the moment the door returns.
///
/// Mutation, stated and applied by hand: `session_setup::detaches` returning
/// `false` (its comparison replaced with the literal) sends every row back
/// inline, and this case reddens on its first assertion.
#[test]
fn a_session_start_registers_its_task_before_it_returns() {
    let repo = bench("session-start-registers", "exit 0", 5000);
    let _ = door(&repo, "SessionStart", &serde_json::json!({}));
    assert!(
        setup_phase(&repo).is_some(),
        "the setup task is in the registry when the door returns"
    );
    let _ = settle(&repo);
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
                Some("mediator-matches-the-tree" | "engine-resolves-every-row")
            )
        })
        .cloned()
        .collect();
    assert_eq!(rows.len(), 2, "both engine rows are committed");
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
    command.env("PATH", path);
    let _ = common::stdin_run(
        &mut command,
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    let _ = settle(&repo);
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
    command.env("PATH", path);
    let _ = common::stdin_run(
        &mut command,
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    let _ = settle(&repo);
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
