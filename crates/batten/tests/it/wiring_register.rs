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
        .output()
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
