//! `batten offbox status` over the compiled binary (CLOUD-2718).
//!
//! The transport cases live beside the decision, in `crates/batten/src/offbox.rs`:
//! the only transport stand-in is compiled for the crate's own tests. What a
//! consumer depends on is here — the token, the exit, and that a machine which
//! never set the variable has nothing written under its name.

use crate::common::{self, StateHome as _, batten, git_in, scratch, scratch_repo, stdout};
use batten::session::STATE_REPO_ENV;

/// Fails by: an unset variable creating the feature's directory, or answering
/// anything but `off` with exit 0.
#[test]
fn unset_is_off_and_leaves_no_directory() {
    let repo = scratch_repo("offbox-status-unset");
    let home = scratch("offbox-status-unset-home");
    let output = batten()
        .args(["offbox", "status"])
        .current_dir(&repo)
        .state_home(&home)
        .output()
        .expect("run batten offbox status");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "off\n");
    // THE PREMISE: the redirect took, so the directory looked for below is the
    // one this run would have written.
    let root = home.join("data").join("batten");
    assert!(
        !root.join(batten::offbox::DIR).exists(),
        "off must leave no trace under {}",
        root.display()
    );
}

/// Fails by: a project with no http(s) origin being probed, or reading as off.
#[test]
fn a_local_path_origin_is_no_http_origin() {
    let repo = scratch_repo("offbox-status-local-origin");
    git_in(&repo, &["remote", "add", "origin", "/srv/git/widgets.git"]);
    let output = batten()
        .args(["offbox", "status"])
        .current_dir(&repo)
        .env(STATE_REPO_ENV, "example/state")
        .output()
        .expect("run batten offbox status");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "no-http-origin\n");
}

/// Fails by: a spawned `batten` inheriting the variable from the environment the
/// suite runs in, which a cloud session sets for every process.
#[test]
fn a_spawned_batten_does_not_inherit_the_state_repo() {
    assert!(common::AMBIENT_ENV_VARS.contains(&STATE_REPO_ENV));
    let command = batten();
    let removed = command
        .get_envs()
        .any(|(name, value)| name == STATE_REPO_ENV && value.is_none());
    assert!(removed, "`batten()` must remove {STATE_REPO_ENV} by name");
}
