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

#[expect(
    clippy::disallowed_methods,
    reason = "bounded: `registers_batten` reads a test input: a fixture the case wrote or a file this repository tracks"
)]
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
