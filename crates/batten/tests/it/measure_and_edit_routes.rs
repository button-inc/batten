//! The compiled-binary tier for three repository modules (`rules/policy-modules.md`):
//! `policy/profile-read-first.rego` (`program measure first`),
//! `policy/profile-stripped.rego` (`program measure unread`) and
//! `policy/sed-line-address.rego` (`path edit unsafe`).
//!
//! Each module's inline Rego tests fabricate the input they decide over. This
//! suite drives the real hook with this repository's own committed config and
//! modules, so a key the engine never fills, or a row that never installs the
//! module, turns a case here red. Each module's `#MUTANT` row names the case
//! below that reddens when its deciding conjunct is removed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, stderr};

/// This repository's own rows and modules, as committed: the same
/// `include_str!` contract `spawn_ceilings.rs` uses, so a hand-written copy of a
/// row cannot pass over a config that says something else.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory") {
        let path = entry.expect("a policy entry").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(path.file_name().expect("a file name")))
                .expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

/// What the hook said about one Bash `command`, stdout and stderr together.
fn said(repo: &Path, command: &str) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })
    .to_string();
    let output = common::stdin_run(
        &mut common::batten(),
        repo,
        &["adjudicate", "--harness", "claude-code"],
        &payload,
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    )
}

/// `program measure first`: a profiler run by hand is sent to the skill, and a
/// program that is not a profiler is not.
#[test]
fn a_profiler_is_sent_to_the_skill() {
    let repo = repo("measure-first");
    let refused = said(&repo, "hyperfine 'true'");
    assert!(refused.contains("program measure first"), "{refused}");
    let other = said(&repo, "cargo --version");
    assert!(!other.contains("program measure first"), "{other}");
}

/// `program measure unread`: callgrind on the stripped release binary is
/// refused, and on a binary built with symbols it is not.
#[test]
fn callgrind_on_a_release_binary_is_refused() {
    let repo = repo("measure-unread");
    let refused = said(
        &repo,
        "valgrind --tool=callgrind target/release/batten adjudicate",
    );
    assert!(refused.contains("program measure unread"), "{refused}");
    let symbols = said(
        &repo,
        "valgrind --tool=callgrind target/profiling/batten adjudicate",
    );
    assert!(!symbols.contains("program measure unread"), "{symbols}");
}

/// `path edit unsafe`: an in-place `sed` aimed by line number is refused, and
/// the same edit aimed by pattern is not.
#[test]
fn a_line_addressed_in_place_edit_is_refused() {
    let repo = repo("edit-unsafe");
    let refused = said(&repo, "sed -i 52s/a/b/ src/x.rs");
    assert!(refused.contains("path edit unsafe"), "{refused}");
    let pattern = said(&repo, "sed -i /fn x/s/a/b/ src/x.rs");
    assert!(!pattern.contains("path edit unsafe"), "{pattern}");
}
