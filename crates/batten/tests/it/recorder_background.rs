//! A backgrounded fetch is recorded from its output once the task exits
//! (CLOUD-2214), over the compiled binary and the committed authority's own
//! `pr-body-closes` row.
//!
//! Measured on PR #1132: a backgrounded `gh pr view --json body --jq .body`
//! returns `stdout: ""` and a `backgroundTaskId`, and the row recorded `closes 0`
//! over a body carrying 24 closing keys. These cases drive the hook with that
//! measured shape and read the record back through the engine's own path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

const FETCH: &str = "gh pr view 1 --json body --jq .body";

fn repo(name: &str) -> PathBuf {
    let root = common::scratch(name);
    common::init_repo(&root);
    common::git_in(&root, &["symbolic-ref", "HEAD", "refs/heads/work"]);
    std::fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    std::fs::write(root.join("batten.toml"), authority())
        .expect("install the recorder's authority");
    root
}

/// The committed authority's own `pr-body-closes` row and the patterns it reads,
/// cut from `batten.toml` rather than restated, so a change to the real row
/// reddens here. The whole file is not copied: it registers policy modules a
/// scratch repository does not hold, and the hook refuses to adjudicate without
/// them.
fn authority() -> String {
    let committed =
        std::fs::read_to_string(common::at_root("batten.toml")).expect("read the authority");
    let mut sections: Vec<Vec<&str>> = Vec::new();
    for line in committed.lines() {
        if line.starts_with('[') || sections.is_empty() {
            sections.push(Vec::new());
        }
        sections.last_mut().expect("a section").push(line);
    }
    let wanted_pattern = |body: &[&str]| {
        // Every row `Grammar::from_compiled` assembles (`ready-*` and
        // `clause-label`), because it answers could-not-look (`-`) when one is
        // missing.
        body.iter().any(|line| {
            line.starts_with("id = \"ready-")
                || ["id = \"clause-label\"", "id = \"gh-pr-body-fetch\""].contains(line)
        })
    };
    let mut kept = String::from("version = 1\n");
    let mut in_recorder = false;
    for section in &sections {
        let keep = match section[0] {
            "[[pattern]]" => wanted_pattern(section),
            "[[recorder]]" => {
                in_recorder = section.contains(&"name = \"pr-body-closes\"");
                in_recorder
            }
            "[[recorder.columns]]" => in_recorder,
            _ => {
                in_recorder = false;
                false
            }
        };
        if keep {
            for line in section.iter().filter(|line| !line.starts_with('#')) {
                kept.push_str(line);
                kept.push('\n');
            }
        }
    }
    kept
}

fn recorded(root: &Path) -> Option<String> {
    let git_dir = common::git_in(root, &["rev-parse", "--absolute-git-dir"]);
    let path = batten::recorder::record_path(Path::new(git_dir.trim()), "pr-closes", "work", None);
    std::fs::read_to_string(path).ok()
}

/// One hook call, with `transcript` named the way the host names it.
fn hook(root: &Path, event: &str, response: &serde_json::Value, transcript: &Path) {
    let payload = serde_json::json!({
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": FETCH},
        "tool_response": response,
        "transcript_path": transcript,
    });
    let out = common::run_with_stdin(
        root,
        &["adjudicate", "--harness", "exit-code"],
        &payload.to_string(),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

/// The measured backgrounded result.
fn backgrounded(id: &str) -> serde_json::Value {
    serde_json::json!({
        "stdout": "", "stderr": "", "interrupted": false, "isImage": false,
        "noOutputExpected": false, "backgroundTaskId": id,
    })
}

/// The measured notification line the host appends when task `id` exits.
fn notification(id: &str, output: &Path, status: &str) -> String {
    serde_json::json!({
        "type": "user",
        "origin": {"kind": "task-notification"},
        "message": {"role": "user", "content": format!(
            "<task-notification>\n<task-id>{id}</task-id>\n<output-file>{}</output-file>\n<status>{status}</status>\n</task-notification>",
            output.display()
        )},
    })
    .to_string()
}

#[test]
fn a_backgrounded_fetch_records_its_output_when_the_task_exits() {
    let root = repo("background-follow");
    let transcript = root.join("transcript.jsonl");
    std::fs::write(&transcript, "").expect("transcript");
    hook(&root, "PostToolUse", &backgrounded("b1"), &transcript);
    assert_eq!(
        recorded(&root),
        None,
        "the placeholder is not a body, so nothing is recorded yet"
    );

    let output = root.join("b1.output");
    std::fs::write(&output, "Consolidated.\n\nCloses CLOUD-1295\n").expect("output");
    std::fs::write(&transcript, notification("b1", &output, "completed") + "\n").expect("notify");
    hook(&root, "PreToolUse", &serde_json::Value::Null, &transcript);
    assert_eq!(recorded(&root).as_deref(), Some("closes 1:CLOUD-1295\n"));
}

#[test]
fn a_task_that_did_not_complete_records_nothing() {
    let root = repo("background-failed");
    let transcript = root.join("transcript.jsonl");
    std::fs::write(&transcript, "").expect("transcript");
    hook(&root, "PostToolUse", &backgrounded("b2"), &transcript);
    let output = root.join("b2.output");
    std::fs::write(&output, "Closes CLOUD-1295\n").expect("output");
    std::fs::write(&transcript, notification("b2", &output, "failed") + "\n").expect("notify");
    hook(&root, "PreToolUse", &serde_json::Value::Null, &transcript);
    assert_eq!(recorded(&root), None);
}

#[test]
fn an_unreadable_output_records_nothing() {
    let root = repo("background-absent");
    let transcript = root.join("transcript.jsonl");
    std::fs::write(&transcript, "").expect("transcript");
    hook(&root, "PostToolUse", &backgrounded("b3"), &transcript);
    std::fs::write(
        &transcript,
        notification("b3", &root.join("gone.output"), "completed") + "\n",
    )
    .expect("notify");
    hook(&root, "PreToolUse", &serde_json::Value::Null, &transcript);
    assert_eq!(recorded(&root), None);
}
