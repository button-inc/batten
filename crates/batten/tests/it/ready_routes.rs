//! Every mediated ready route funnels through the one gated door (CLOUD-2260).
//!
//! The receipt rows key on `gh pr ready`, so a ready reached any other way — a
//! hand-written `markPullRequestReadyForReview` mutation through `gh api` — buys
//! the same CI matrix with none of the receipts asked for. `check open missing`
//! closes the rest on the engine's ready event (CLOUD-2873): the connector's
//! `draft: false` and its mediated spelling owe `verify`. These cases run over
//! THIS repository's committed rows, because a fixture config would prove a row
//! nobody ships.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// This repository's own rows and modules.
fn repo(name: &str) -> PathBuf {
    // Every file the committed `[epoch] tracked` names rides along, read from the
    // config rather than listed here: `receipt record` hashes each at HEAD and
    // refuses one that is absent, and a list in `crates/**` would name a
    // consumer's files (rule 1).
    let mut staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    let tracked = batten::config::load(&common::at_root("batten.toml"))
        .expect("the committed config loads")
        .epoch
        .map(|epoch| epoch.tracked)
        .unwrap_or_default();
    for path in tracked.iter().filter(|path| !path.ends_with("batten.toml")) {
        let bytes = std::fs::read_to_string(common::at_root(path))
            .expect("an epoch-tracked file is readable");
        staged = staged.file(path, &bytes);
    }
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

/// The connector's ready, as the harness hands it to the hook.
fn connector_ready() -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__github__update_pull_request",
        "tool_input": {"pullNumber": 1, "draft": false},
    })
}

/// The same ready through the mediated client.
fn mediated_ready() -> serde_json::Value {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "batten mcp call github update_pull_request '{\"pullNumber\":1,\"draft\":false}'",
        },
    })
}

/// Every line `payload` earned, with its exit code.
fn judged(dir: &Path, payload: &serde_json::Value) -> (Option<i32>, String) {
    let output = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    );
    (output.status.code(), stderr(&output))
}

/// The finding lines `check open missing` raised in `said`.
fn verify_row_lines(said: &str) -> Vec<&str> {
    said.lines()
        .filter(|line| batten::refusal::parse_finding(line).is_some())
        .filter(|line| common::refusing_rule(line).as_deref() == Some("check open missing"))
        .collect()
}

/// [`repo`], with an `origin/main` at its base so a receipt's trunk resolves.
fn repo_on_trunk(name: &str) -> PathBuf {
    let dir = repo(name);
    common::git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// Record `check` on HEAD through the engine's own writer.
fn record(dir: &Path, check: &str) {
    let output = common::batten()
        .args(["receipt", "record", check])
        .current_dir(dir)
        .streamed_output()
        .expect("run batten receipt record");
    assert!(
        output.status.success(),
        "recording {check} failed: {}",
        stderr(&output)
    );
}

/// PR #1281 (CLOUD-2873): the connector's `draft: false` readied a head no
/// `verify` had seen. It is refused by the row that owes the receipts, and the
/// cause it names is `missing`.
#[test]
fn a_connector_ready_without_a_green_verify_is_refused() {
    let dir = repo_on_trunk("ready-route-connector-red");
    let (code, said) = judged(&dir, &connector_ready());
    assert_eq!(code, Some(2), "{said}");
    let lines = verify_row_lines(&said);
    assert!(!lines.is_empty(), "the ready row refuses: {said}");
    assert!(
        lines.iter().any(|line| line.contains("missing")),
        "names the missing receipt: {said}"
    );
}

/// The discriminating arm: the same call on a head carrying both receipts is
/// not refused by this row. Without it the row could refuse every undraft and
/// still pass the case above.
#[test]
fn a_connector_ready_after_a_green_verify_is_allowed() {
    let dir = repo_on_trunk("ready-route-connector-green");
    record(&dir, "verify");
    record(&dir, "linear-check");
    let (_, said) = judged(&dir, &connector_ready());
    assert!(
        verify_row_lines(&said).is_empty(),
        "a verified head owes this row nothing: {said}"
    );
}

/// The mediated `batten mcp call` spelling is the same event, refused the same
/// way.
#[test]
fn a_mediated_ready_without_a_green_verify_is_refused() {
    let dir = repo_on_trunk("ready-route-mediated-red");
    let (code, said) = judged(&dir, &mediated_ready());
    assert_eq!(code, Some(2), "{said}");
    let lines = verify_row_lines(&said);
    assert!(!lines.is_empty(), "the ready row refuses: {said}");
    assert!(
        lines.iter().any(|line| line.contains("missing")),
        "names the missing receipt: {said}"
    );
}
