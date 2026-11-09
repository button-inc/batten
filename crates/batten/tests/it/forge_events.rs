//! `batten forge intake` over the compiled binary (CLOUD-2690): one forge event
//! payload on stdin, normalized by `forge_event`, deduplicated against the
//! seen ring, and dispatched through the handlers and rules a harness hook gets.
//!
//! Dispatches are counted by a fixture handler on `forge` that appends a line
//! to a marker file and exits with the code the fixture chose, so no case needs
//! the network, `gh` or a live server.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Output;

/// A repository whose `[[hook.handler]]` on `forge` selects
/// `pull_request.opened`, appends to `marker`, and exits `code`; `extra` is
/// appended to its config.
fn repo(name: &str, code: i32, extra: &str) -> PathBuf {
    let dir = common::scratch(name);
    let marker = dir.join("dispatched");
    let script = dir.join("handler");
    std::fs::write(
        &script,
        // A refusal states its reason on stderr, as the handler contract
        // requires: a silent exit 2 is a broken handler, not a deny.
        format!(
            "#!/bin/sh\necho x >> '{}'\n[ {code} -eq 0 ] || echo 'forge-pr refused' 1>&2\nexit {code}\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    common::write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n[[hook.handler]]\nid = \"forge-pr\"\non = \"forge\"\n\
             matcher = \"^pull_request\\\\.opened$\"\nrun = [{}]\ntimeout_ms = 5000\n\
             owner = \"CLOUD-2690\"\nexpires = \"2027-02-28\"\n{extra}",
            serde_json::to_string(script.to_str().unwrap()).unwrap()
        ),
    );
    common::init_repo(&dir);
    dir
}

/// How many times the handler ran.
fn dispatched(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("dispatched"))
        .unwrap_or_default()
        .lines()
        .count()
}

fn body(action: &str) -> String {
    serde_json::json!({
        "action": action,
        "pull_request": {"id": 11, "number": 7, "updated_at": "2026-11-09T00:00:00Z"},
        "repository": {"full_name": "o/r"}
    })
    .to_string()
}

fn intake(dir: &Path, args: &[&str], stdin: &str) -> Output {
    let mut command = vec!["forge", "intake"];
    command.extend_from_slice(args);
    common::run_with_stdin(dir, &command, stdin)
}

/// A claude-code user-prompt-submit payload whose prompt carries the wake.
fn wake(kind: &str, body: &str) -> String {
    serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": format!(
            "<wake reason=\"external-event\"><event source=\"github\" kind=\"{kind}\">{body}</event></wake>"
        ),
    })
    .to_string()
}

/// Fails at HEAD: there is no verb.
#[test]
fn intake_runs_handlers_and_exits_on_their_verdict() {
    let refusing = repo("forge-intake-refusing", 2, "");
    let out = intake(&refusing, &["--event", "pull_request"], &body("opened"));
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert_eq!(dispatched(&refusing), 1);

    let other = intake(&refusing, &["--event", "issues"], &body("opened"));
    assert_eq!(other.status.code(), Some(0), "{}", common::stderr(&other));
    assert_eq!(dispatched(&refusing), 1, "an issues event does not run it");

    let passing = repo("forge-intake-passing", 0, "");
    let out = intake(&passing, &["--event", "pull_request"], &body("opened"));
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(dispatched(&passing), 1);
}

#[test]
fn a_replayed_payload_dispatches_once() {
    let dir = repo("forge-intake-replay", 0, "");
    for _ in 0..2 {
        let out = intake(&dir, &["--event", "pull_request"], &body("opened"));
        assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    }
    assert_eq!(dispatched(&dir), 1, "the ring absorbs the replay");
    let common_dir = common::git_in(&dir, &["rev-parse", "--git-common-dir"]);
    let ring = dir
        .join(common_dir)
        .join("batten-forge-events")
        .join("seen");
    assert!(ring.is_file(), "{}", ring.display());
}

#[test]
fn a_wake_envelope_dispatches_once_and_its_webhook_twin_does_not() {
    let dir = repo("forge-intake-wake", 0, "");
    let out = intake(
        &dir,
        &["--from", "wake"],
        &wake("pull_request", &body("opened")),
    );
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(dispatched(&dir), 1, "the wake element is the event");
    let twin = intake(&dir, &["--event", "pull_request"], &body("opened"));
    assert_eq!(twin.status.code(), Some(0), "{}", common::stderr(&twin));
    assert_eq!(dispatched(&dir), 1, "one change, one key, one dispatch");
}

#[test]
fn a_wake_refusal_exits_zero_and_lands_in_the_findings_store() {
    let dir = repo("forge-intake-wake-refusal", 2, "");
    common::git_in(&dir, &["commit", "--allow-empty", "-qm", "seed"]);
    let out = intake(
        &dir,
        &["--from", "wake"],
        &wake("pull_request", &body("opened")),
    );
    assert_eq!(out.status.code(), Some(0), "{}", common::stderr(&out));
    assert_eq!(dispatched(&dir), 1);
    let store = batten::store::resolve(&dir)
        .ok()
        .and_then(|opened| batten::store::bound_dir(&opened))
        .expect("a bound store");
    let records = batten::findings::load_all(&store).unwrap();
    let forge: Vec<_> = records
        .iter()
        .filter(|record| record.rule == "forge-intake")
        .collect();
    assert_eq!(forge.len(), 1, "{records:?}");
    assert_eq!(forge[0].instances[0].path, "forge:pull_request.opened");
}

const FORGE_RULE: &str = r#"
[[rule]]
id = "forge-closed"
kind = "policy"
scope = "mediated_call"
module = "forge.rego"
severity = "deny"

[[verdict]]
id = "forge closed refused"
gloss = "a closed pull request was refused"
class = "A fixture class, raised only by this suite's forge module."

[[verdict.route]]
id = "forge closed read"
kind = "document"
target = "forge.rego"
"#;

const FORGE_MODULE: &str = r#"package batten.forge

import rego.v1

rules contains "forge-closed"

violation contains {
	"rule": "forge-closed",
	"verdict": "forge closed refused",
} if {
	input.call.event == "forge"
	input.call.forge.action == "closed"
}

test_a_closed_pull_request_fires if {
	some v in violation with input as {"call": {"event": "forge", "forge": {"action": "closed"}}}
	v.rule == "forge-closed"
}

test_an_opened_one_does_not if {
	count(violation) == 0 with input as {"call": {"event": "forge", "forge": {"action": "opened"}}}
}
"#;

#[test]
fn a_forge_rule_refuses_through_intake() {
    let dir = repo("forge-intake-rule", 0, FORGE_RULE);
    common::write(&dir, "forge.rego", FORGE_MODULE);
    let closed = intake(&dir, &["--event", "pull_request"], &body("closed"));
    assert_eq!(closed.status.code(), Some(2), "{}", common::stderr(&closed));
    let opened = intake(&dir, &["--event", "pull_request"], &body("opened"));
    assert_eq!(opened.status.code(), Some(0), "{}", common::stderr(&opened));
}

#[test]
fn an_unknown_event_name_is_a_usage_error() {
    let dir = repo("forge-intake-unknown", 0, "");
    let out = intake(&dir, &["--event", "not_a_github_event"], &body("opened"));
    assert_eq!(out.status.code(), Some(1), "{}", common::stderr(&out));
    let wake_out = intake(
        &dir,
        &["--from", "wake"],
        &wake("not_a_github_event", &body("opened")),
    );
    assert_eq!(wake_out.status.code(), Some(0));
    assert!(common::stderr(&wake_out).contains("forge intake:"));
    assert_eq!(dispatched(&dir), 0);
}
