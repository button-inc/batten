//! `batten offbox push` over the compiled binary (CLOUD-2720).
//!
//! The push itself is exercised beside the code, in `crates/batten/src/offbox.rs`,
//! over the transport stand-in only the crate's own tests compile. Here are the
//! two answers a consumer meets before any transport: the switch being off, and
//! a project whose origin names no host to derive the state repository from.

use crate::common::{StateHome as _, batten, git_in, scratch, scratch_repo, stdout};
use batten::session::STATE_REPO_ENV;

const PUSH: [&str; 6] = ["offbox", "push", "--session", "s", "--harness", "exit-code"];

/// Fails by: an unset variable building or sending anything.
#[test]
fn unset_is_off() {
    let repo = scratch_repo("offbox-push-unset");
    let home = scratch("offbox-push-unset-home");
    let output = batten()
        .args(PUSH)
        .current_dir(&repo)
        .state_home(&home)
        .output()
        .expect("run batten offbox push");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(stdout(&output), "off\n");
    assert!(
        !home
            .join("data")
            .join("batten")
            .join(batten::offbox::DIR)
            .exists(),
        "off must leave no trace"
    );
}

/// Fails by: a project with no http(s) origin being probed or pushed.
#[test]
fn a_local_path_origin_is_refused() {
    let repo = scratch_repo("offbox-push-local-origin");
    git_in(&repo, &["remote", "add", "origin", "/srv/git/widgets.git"]);
    let output = batten()
        .args(PUSH)
        .current_dir(&repo)
        .env(STATE_REPO_ENV, "example/state")
        .output()
        .expect("run batten offbox push");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "no-http-origin\n");
}
