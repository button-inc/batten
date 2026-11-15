//! `batten wiring register` at container setup, over the compiled binary
//! (CLOUD-2205).
//!
//! **THE ARM THAT RUNS BEFORE ANY SESSION EXISTS.** A cloud session over several
//! repositories is rooted above the clones, and the host reads project hooks only
//! from that root (CLOUD-2111). The repair that registers batten there is a
//! `[[startup]]` row, and `[[startup]]` runs from two places: the setup script,
//! before the session, and `SessionStart` — which is itself one of the hooks the
//! row registers. Measured 2026-10-11: the setup-script run had no `CLAUDE_PID`,
//! answered "no registration is owed", exited clean, and wrote nothing; the
//! `SessionStart` that would have retried never fired; the whole session ran
//! unmediated while the row read green.
//!
//! The fixture's `$HOME` is an ANCESTOR of the clone, so under the shipped bound
//! every candidate root the verb may write stays inside the scratch directory.
//! The bound itself is killed by a pure unit test in `lib.rs`
//! (`candidate_roots_stop_short_of_home_and_everything_above_it`), never through
//! this binary: an unbounded mutant driven from here would register on every
//! real ancestor of the fixture, the checkout and the session root included.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{StateHome as _, scratch, stderr};

/// `<home>/sessions/clones/repo`: a clone two directories below the home.
fn layout(name: &str) -> (PathBuf, PathBuf) {
    let home = scratch(name);
    let repo = home.join("sessions").join("clones").join("repo");
    std::fs::create_dir_all(&repo).expect("the fixture clone");
    common::init_repo(&repo);
    common::write(&repo, "batten.toml", "version = 1\n");
    (home, repo)
}

fn register(home: &Path, repo: &Path, environment: &str, args: &[&str]) -> Output {
    common::batten()
        .current_dir(repo)
        .args([&["wiring", "register"], args].concat())
        .at_home(home)
        .env("BATTEN_ENVIRONMENT", environment)
        .env_remove("CLAUDE_PID")
        .streamed_output()
        .expect("the binary runs")
}

fn registers_batten(root: &Path) -> bool {
    std::fs::read_to_string(root.join(".claude/settings.json"))
        .is_ok_and(|text| text.contains("batten adjudicate"))
}

#[test]
fn a_setup_run_registers_every_root_a_session_could_have() {
    // THE REGRESSION. Red before CLOUD-2205: exit 0, "no registration is owed",
    // and no file anywhere.
    let (home, repo) = layout("wiring-register-setup");
    let owed = register(&home, &repo, "disposable", &["--check"]);
    assert_eq!(
        owed.status.code(),
        Some(2),
        "with no session to name the root, a registration is OWED above the clone: {}",
        stderr(&owed)
    );
    let done = register(&home, &repo, "disposable", &[]);
    assert_eq!(done.status.code(), Some(0), "{}", stderr(&done));
    for root in [home.join("sessions").join("clones"), home.join("sessions")] {
        assert!(
            registers_batten(&root),
            "a session rooted at {} must load batten",
            root.display()
        );
    }
    let settled = register(&home, &repo, "disposable", &["--check"]);
    assert_eq!(settled.status.code(), Some(0), "{}", stderr(&settled));
}

#[test]
fn a_setup_run_never_registers_on_the_user_level_surface() {
    // The bound. The project surface at `$HOME` is the user-level one, loaded by a
    // session rooted AT the repository too — registering there fires batten
    // twice, the double authority `wiring::register` refuses.
    let (home, repo) = layout("wiring-register-home");
    let done = register(&home, &repo, "disposable", &[]);
    assert_eq!(done.status.code(), Some(0), "{}", stderr(&done));
    assert!(
        !home.join(".claude/settings.json").exists(),
        "nothing may be written at $HOME"
    );
}

/// A live process whose working directory is `dir`, standing in for the harness
/// `CLAUDE_PID` names: a hook blocked reading a payload it has not been sent.
/// Dropping the returned child's stdin ends it.
fn harness_in(dir: &Path) -> std::process::Child {
    let mut command = common::batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.spawn().expect("a stand-in harness process")
}

fn register_in_session(
    home: &Path,
    repo: &Path,
    environment: &str,
    harness: &std::process::Child,
    args: &[&str],
) -> Output {
    common::batten()
        .current_dir(repo)
        .args([&["wiring", "register"], args].concat())
        .at_home(home)
        .env("BATTEN_ENVIRONMENT", environment)
        .env("CLAUDE_PID", harness.id().to_string())
        .output()
        .expect("the binary runs")
}

fn end(mut harness: std::process::Child) {
    drop(harness.stdin.take());
    let _ = harness.wait();
}

#[test]
fn a_session_rooted_at_the_clone_still_registers_the_roots_above_it() {
    // THE REGRESSION (CLOUD-2751). A one-repository session is rooted IN the
    // clone, so its live root owed nothing; it then attached a second
    // repository, the restart rooted it at the parent, and no hook ran again.
    let (home, repo) = layout("wiring-register-live-clone");
    let harness = harness_in(&repo);
    let done = register_in_session(&home, &repo, "disposable", &harness, &[]);
    end(harness);
    assert_eq!(done.status.code(), Some(0), "{}", stderr(&done));
    let parent = repo.parent().expect("the clone's parent");
    let text = std::fs::read_to_string(parent.join(".claude/settings.json"))
        .unwrap_or_else(|error| panic!("the parent is registered: {error}: {}", stderr(&done)));
    let document: serde_json::Value = serde_json::from_str(&text).expect("a JSON surface");
    assert_eq!(
        document["hooks"].as_object().map(serde_json::Map::len),
        Some(8),
        "all eight events"
    );
    assert!(
        !home.join(".claude/settings.json").exists(),
        "and still nothing at $HOME"
    );
}

#[test]
fn a_real_machine_inside_a_session_writes_nothing_above_its_root() {
    let (home, repo) = layout("wiring-register-live-real");
    let harness = harness_in(&repo);
    let check = register_in_session(&home, &repo, "", &harness, &["--check"]);
    let done = register_in_session(&home, &repo, "", &harness, &[]);
    end(harness);
    assert_eq!(check.status.code(), Some(0), "{}", stderr(&check));
    let parent = repo.parent().expect("the clone's parent");
    let owed_at_parent = format!(" owed at {}", parent.display());
    assert!(
        !stderr(&check)
            .lines()
            .any(|line| line.ends_with(&owed_at_parent)),
        "no directory above the live root is owed: {}",
        stderr(&check)
    );
    assert_eq!(done.status.code(), Some(0), "{}", stderr(&done));
    assert!(
        !registers_batten(parent),
        "nothing is written above the root"
    );
}

#[test]
fn a_machine_not_declared_disposable_owes_nothing_outside_a_session() {
    // A developer's laptop or a CI runner: nothing may be written there, so
    // reporting a registration as owed would turn every `startup` red over a
    // non-defect. Unchanged from before CLOUD-2205.
    let (home, repo) = layout("wiring-register-real");
    let check = register(&home, &repo, "", &["--check"]);
    assert_eq!(check.status.code(), Some(0), "{}", stderr(&check));
    assert!(!registers_batten(&home.join("sessions").join("clones")));
}

// --- `register --all` and the live session root (CLOUD-2676) ------------------

/// Every harness's committed surface, and the token `generate hooks` takes.
const COMMITTED: &[(&str, &str)] = &[
    ("claude-code", ".claude/settings.json"),
    ("cursor", ".cursor/hooks.json"),
    ("gemini-cli", ".gemini/settings.json"),
    ("codex-cli", ".codex/hooks.json"),
    ("copilot-cli", ".github/hooks/batten.json"),
];

/// `wiring register --all` with no session and no disposable home: only the
/// committed half may write.
fn register_all(home: &Path, repo: &Path, args: &[&str]) -> Output {
    common::batten()
        .current_dir(repo)
        .args([&["wiring", "register", "--all"], args].concat())
        .at_home(home)
        .env_remove("BATTEN_ENVIRONMENT")
        .env_remove("CLAUDE_PID")
        .streamed_output()
        .expect("the binary runs")
}

fn doctor_hooks(home: &Path, repo: &Path, pid: Option<u32>) -> Output {
    let mut command = common::batten();
    command
        .current_dir(repo)
        .args(["doctor", "hooks", "--json"])
        .at_home(home)
        .env_remove("CLAUDE_PID");
    if let Some(pid) = pid {
        command.env("CLAUDE_PID", pid.to_string());
    }
    command.streamed_output().expect("the binary runs")
}

/// The events map a wiring document carries, wherever its host keys it.
fn events_of(document: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    document
        .get("hooks")
        .unwrap_or(document)
        .as_object()
        .cloned()
        .unwrap_or_default()
}

#[test]
fn register_all_writes_every_committed_surface() {
    let (home, repo) = layout("wiring-register-all");
    let owed = register_all(&home, &repo, &["--check"]);
    assert_eq!(owed.status.code(), Some(2), "{}", stderr(&owed));
    for (_, surface) in COMMITTED {
        assert!(!repo.join(surface).exists(), "--check wrote {surface}");
    }
    let written = register_all(&home, &repo, &[]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr(&written));
    let again = register_all(&home, &repo, &["--check"]);
    assert_eq!(again.status.code(), Some(0), "a second run owes nothing");

    let hooks = doctor_hooks(&home, &repo, None);
    let report: serde_json::Value =
        serde_json::from_slice(&hooks.stdout).expect("doctor hooks --json parses");
    assert_eq!(hooks.status.code(), Some(0), "{report}");
    for harness in report["harnesses"].as_array().expect("harnesses") {
        assert_eq!(harness["ok"], true, "{harness}");
    }

    for (token, surface) in COMMITTED {
        let generated = common::batten()
            .current_dir(&repo)
            .args(["generate", "hooks", "--harness", token])
            .streamed_output()
            .expect("the binary runs");
        let generated: serde_json::Value =
            serde_json::from_slice(&generated.stdout).expect("generate hooks parses");
        let file = std::fs::read_to_string(repo.join(surface)).expect("the surface was written");
        let file: serde_json::Value = serde_json::from_str(&file).expect("the surface parses");
        assert_eq!(
            events_of(&file),
            events_of(&generated),
            "{token}: register --all writes the entries generate derives"
        );
    }
}

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: a live session is a PROCESS whose cwd `/proc/<pid>/cwd` reads, which has no in-process form"
)]
fn doctor_reads_the_live_session_root() {
    let (home, repo) = layout("wiring-register-live-root");
    let root = repo.parent().expect("the clone has a parent").to_path_buf();
    // A live process rooted above the repository, held open on a pipe rather
    // than sleeping: its pid is the session.
    let mut session = std::process::Command::new("cat")
        .current_dir(&root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("cat runs");
    let pid = session.id();

    let claude = |output: &Output| -> serde_json::Value {
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("doctor hooks --json parses");
        report["harnesses"]
            .as_array()
            .expect("harnesses")
            .iter()
            .find(|harness| harness["harness"] == "claude-code")
            .cloned()
            .expect("claude-code is diagnosed")
    };
    let rooted_findings = |row: &serde_json::Value| -> Vec<serde_json::Value> {
        row["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter(|finding| {
                finding["file"]
                    .as_str()
                    .is_some_and(|file| file.starts_with("session-root:"))
            })
            .cloned()
            .collect()
    };

    let before = claude(&doctor_hooks(&home, &repo, Some(pid)));
    assert_eq!(before["session_root_registrations"], 0, "{before}");
    assert!(
        rooted_findings(&before).iter().any(|finding| {
            finding["file"] == "session-root:.claude/settings.json"
                && finding["reason"] == "hook-wiring-file-missing"
        }),
        "{before}"
    );

    let registered = common::batten()
        .current_dir(&repo)
        .args(["wiring", "register"])
        .at_home(&home)
        .env("BATTEN_ENVIRONMENT", "disposable")
        .env("CLAUDE_PID", pid.to_string())
        .streamed_output()
        .expect("the binary runs");
    assert_eq!(registered.status.code(), Some(0), "{}", stderr(&registered));

    let after = claude(&doctor_hooks(&home, &repo, Some(pid)));
    let derived = common::batten()
        .current_dir(&repo)
        .args(["generate", "hooks", "--harness", "claude-code"])
        .streamed_output()
        .expect("the binary runs");
    let derived: serde_json::Value =
        serde_json::from_slice(&derived.stdout).expect("generate hooks parses");
    assert_eq!(
        after["session_root_registrations"],
        events_of(&derived).len(),
        "{after}"
    );
    assert!(rooted_findings(&after).is_empty(), "{after}");

    let _ = session.kill();
    let _ = session.wait();
}

/// Fails by: a live session rooted beside the repository, rather than above
/// it, judged as the repository's session root.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: a live session is a PROCESS whose cwd `/proc/<pid>/cwd` reads, which has no in-process form"
)]
fn a_session_rooted_beside_the_repository_is_not_its_session_root() {
    let (home, repo) = layout("wiring-register-beside-root");
    let beside = repo
        .parent()
        .expect("the clone has a parent")
        .join("elsewhere");
    std::fs::create_dir_all(&beside).expect("a sibling directory");
    let mut session = std::process::Command::new("cat")
        .current_dir(&beside)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("cat runs");
    let output = doctor_hooks(&home, &repo, Some(session.id()));
    let _ = session.kill();
    let _ = session.wait();
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor hooks --json parses");
    let claude = report["harnesses"]
        .as_array()
        .expect("harnesses")
        .iter()
        .find(|harness| harness["harness"] == "claude-code")
        .expect("claude-code is diagnosed");
    assert!(claude["session_root_registrations"].is_null(), "{claude}");
}

#[test]
fn register_all_writes_flat_hosts_flat() {
    // CLOUD-2694: Copilot's file seeded with v0.0.220's nested batten entry is
    // migrated to the flat shape the host reads, and a second run is a no-op.
    let (home, repo) = layout("wiring-register-flat");
    common::write(
        &repo,
        ".github/hooks/batten.json",
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"batten adjudicate --harness copilot-cli"}]}]}}"#,
    );
    let written = register_all(&home, &repo, &[]);
    assert_eq!(written.status.code(), Some(0), "{}", stderr(&written));
    let path = repo.join(".github/hooks/batten.json");
    let first = std::fs::read(&path).expect("the surface");
    let file: serde_json::Value = serde_json::from_slice(&first).expect("the surface parses");
    assert_eq!(file["version"], 1, "{file}");
    for (_, entries) in events_of(&file) {
        for entry in entries.as_array().expect("an event's entries") {
            assert!(entry.get("hooks").is_none(), "no nested entry: {file}");
            assert!(entry["bash"].is_string(), "every entry is flat: {file}");
        }
    }
    assert_eq!(register_all(&home, &repo, &[]).status.code(), Some(0));
    assert_eq!(
        std::fs::read(&path).expect("the surface"),
        first,
        "idempotent"
    );
}
