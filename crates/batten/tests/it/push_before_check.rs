//! A slow local check over committed, unpushed work is refused (CLOUD-2489).
//!
//! Over the compiled binary: the hook resolves `head-unpushed` from the clone's
//! own refs, and the COMMITTED module refuses `mise run verify` while HEAD holds
//! a commit no remote-tracking ref reaches. The module's own `test_` cases
//! fabricate the fact; this tier proves the engine builds it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common;

const MODULE: &str = "policy/push-before-check.rego";

/// The committed row's shape plus the committed `[[pattern]]` table, read rather
/// than re-typed, so a `slow-check` regex edited there is the one tested here.
fn config() -> String {
    format!(
        "version = 1\n\n[[rule]]\nid = \"check run early\"\nkind = \"policy\"\n\
         scope = \"mediated_call\"\nmodule = \"{MODULE}\"\nseverity = \"deny\"\n\n{}",
        common::declared_patterns()
    )
}

/// A fixture carrying the config and the COMMITTED module, uncommitted.
fn fixture(name: &str) -> common::Fixture {
    common::Fixture::new(name).config(&config()).file(
        MODULE,
        &std::fs::read_to_string(common::at_root(MODULE)).expect("the committed module"),
    )
}

/// A repository whose HEAD carries one commit beyond its base; `pushed` pins
/// `origin/main` to that head, so the walk finds nothing unpushed.
fn repo(name: &str, pushed: bool) -> PathBuf {
    let dir = fixture(name).base_commit().work_commit().build();
    if pushed {
        common::pin_origin_main(&dir);
    }
    dir
}

fn decision(dir: &Path, command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let payload = format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{escaped},\"run_in_background\":true}}}}"
    );
    common::stdout(&common::run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    ))
}

/// THE REFUSAL, over a fact the engine resolved. `#MUTANT unpushed-ignored`
/// reddens here.
#[test]
fn an_unpushed_head_refuses_a_slow_check() {
    let dir = repo("push-before-check-unpushed", false);
    let out = decision(&dir, "mise run verify");
    assert!(
        out.contains("\"deny\"") && out.contains("check run early"),
        "{out}"
    );
    // The same checks under the spellings a pinned toolchain and mise's own
    // flags produce (review of #1228): a gate keyed to one spelling is evaded by
    // the next.
    for spelled in [
        "cargo +nightly test -p batten",
        "cargo t",
        "mise run -q verify",
        "mise r lint:clippy",
    ] {
        let out = decision(&dir, spelled);
        assert!(out.contains("check run early"), "{spelled}: {out}");
    }
    // ANTI-VACUITY: the same tree admits `land`, the push that is the remedy.
    let land = decision(&dir, "mise run land");
    assert!(!land.contains("check run early"), "{land}");
}

/// The pass side: once every commit is on a remote, the check runs.
#[test]
fn a_pushed_head_runs_the_check() {
    let dir = repo("push-before-check-pushed", true);
    let out = decision(&dir, "mise run verify");
    assert!(!out.contains("check run early"), "{out}");
}

/// COULD NOT LOOK DECIDES NOTHING. An unborn HEAD has no commit to walk from, so
/// the fact is `null`, and a gate refusing on its own failed query is a wall. The
/// same repository's config loads, so the silence is the module's and not a load
/// failure's. `#MUTANT could-not-look-refuses` reddens here.
#[test]
fn a_head_that_could_not_be_read_decides_nothing() {
    let dir = fixture("push-before-check-unborn").build();
    let out = decision(&dir, "mise run verify");
    assert!(!out.contains("check run early"), "{out}");
}

/// THE FIXED WORLD THE LIVE-ROOT CASES READ (CLOUD-2528): the committed tree,
/// HEAD pinned to a remote-tracking ref so this fact reads `false` there, and no
/// receipt store for a session's marker to sit in. `#MUTANT fixed-world-unpinned`
/// reddens here.
#[test]
fn the_committed_clone_is_pushed_and_carries_no_session_state() {
    let clone = common::committed_clone();
    let head = common::git_in(&clone, &["rev-parse", "HEAD"]);
    assert_eq!(
        common::git_in(&clone, &["rev-parse", "refs/remotes/origin/fixed-world"]),
        head
    );
    assert_eq!(batten::git::head_unpushed_to_a_remote(&clone), Some(false));
    // Other cases' adjudications write receipts here, since the clone is shared;
    // what must never be in it is a session's marker, which only a Stop writes.
    let carries_a_marker = std::fs::read_dir(clone.join(".git/batten-receipts"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("unlanded-nudged")
        });
    assert!(!carries_a_marker);
}

/// NOWHERE TO PUSH IS NOT "UNPUSHED" (review of #1228). A clone with no
/// remote-tracking ref at all has every commit unpushed and no push that could
/// change it, so reading it as `true` would refuse every check there for good.
#[test]
fn a_clone_with_no_remote_decides_nothing() {
    let dir = fixture("push-before-check-no-remote").work_commit().build();
    let out = decision(&dir, "mise run verify");
    assert!(!out.contains("check run early"), "{out}");
}
