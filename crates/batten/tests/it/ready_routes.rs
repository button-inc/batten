//! Every mediated ready route funnels through the one gated door (CLOUD-2260).
//!
//! The receipt rows key on `gh pr ready`, so a ready reached any other way — a
//! hand-written `markPullRequestReadyForReview` mutation through `gh api` — buys
//! the same CI matrix with none of the receipts asked for. These cases run over
//! THIS repository's committed rows, because a fixture config would prove a row
//! nobody ships.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// This repository's own rows and modules.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let path = entry.expect("a policy directory entry").path();
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

/// The rule that refused `command`, or `None` when nothing did.
fn refusing(dir: &Path, command: &str) -> Option<String> {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    let output = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &envelope.to_string(),
    );
    match output.status.code() {
        Some(0) => None,
        Some(2) => common::refusing_rule(&stderr(&output)),
        other => panic!("the hook did not judge: {other:?} {}", stderr(&output)),
    }
}

/// A GraphQL ready mutation is refused by `review reach loose`, and a `gh api`
/// call that readies nothing is not. Without the second arm the row could ban
/// every forge read and still pass the first.
#[test]
fn a_hand_written_ready_mutation_is_refused_and_a_plain_api_read_is_not() {
    let dir = repo("ready-route-graphql");
    let mutation = "gh api graphql -f query='mutation{markPullRequestReadyForReview(input:{pullRequestId:\"PR_x\"}){clientMutationId}}'";
    assert_eq!(
        refusing(&dir, mutation).as_deref(),
        Some("review reach loose")
    );
    for read in [
        "gh api repos/o/r/pulls/1",
        "gh api graphql -f query='{repository(owner:\"o\",name:\"r\"){pullRequest(number:1){timelineItems(itemTypes:[READY_FOR_REVIEW_EVENT],first:5){nodes{... on ReadyForReviewEvent{createdAt}}}}}}'",
    ] {
        assert_ne!(
            refusing(&dir, read).as_deref(),
            Some("review reach loose"),
            "{read}"
        );
    }
}
