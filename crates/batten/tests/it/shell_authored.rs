//! A write that authors shell is refused at the write (CLOUD-2335).
//!
//! Over the compiled binary: the hook decides the `shell-introduced` fact in
//! Rust with `shell.rs`'s detector, and the `shell-hygiene` preset's mediated
//! module refuses on it with `shell write refused`. Each case is a host payload
//! through `batten adjudicate`; the reason and the could-not-look answers are
//! read off the same producer the binary calls, `batten::hook::shell_introduced`.
//!
//! A FIXTURE config rather than the committed table, for `head_push_unread.rs`'s
//! reason: a row naming a preset module the pinned engine does not ship is a
//! config that engine cannot load.
//!
//! Every shebang below is a Rust string literal, written to a scratch fixture at
//! test time: the bytes under test never sit in the tree as a shell file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use batten::config_model::Harness;
use batten::facts::Look;
use batten::hook::{SHEBANG, SHELL_PATH, decode, shell_introduced};

use crate::common;

/// The preset's write arm, enabled at the mediated surface.
const CONFIG: &str = "version = 1\n\n\
[[rule]]\nid = \"shell write refused\"\nkind = \"policy\"\n\
scope = \"mediated_call\"\npreset = \"shell-hygiene\"\nseverity = \"deny\"\n";

const VERDICT: &str = "shell write refused";

/// A committed fixture repository carrying `files` beside the config.
fn repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
    common::Fixture::new(name)
        .config(CONFIG)
        .files(files)
        .base_commit()
        .build()
}

fn payload(tool: &str, input: &serde_json::Value) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

fn write(path: &str, content: &str) -> String {
    payload(
        "Write",
        &serde_json::json!({"file_path": path, "content": content}),
    )
}

/// The deny reason the host would hand the model, or `None` for an allow.
fn denied(dir: &Path, payload: &str) -> Option<String> {
    let output = common::run_with_stdin(dir, &["adjudicate", "--harness", "claude-code"], payload);
    let raw = common::stdout(&output);
    if raw.trim().is_empty() {
        return None;
    }
    let document: serde_json::Value = serde_json::from_str(&raw).expect("stdout is one document");
    let inner = &document["hookSpecificOutput"];
    (inner["permissionDecision"] == "deny").then(|| {
        inner["permissionDecisionReason"]
            .as_str()
            .expect("a deny carries its reason")
            .to_owned()
    })
}

/// Whether this suite's verdict refused the payload.
fn refused(dir: &Path, payload: &str) -> bool {
    denied(dir, payload).is_some_and(|reason| reason.contains(VERDICT))
}

/// The fact the binary decides for this payload, by the same producer.
fn fact(dir: &Path, payload: &str) -> Look<&'static str> {
    let envelope = decode(Harness::ClaudeCode, payload).expect("the payload decodes");
    shell_introduced(dir, &envelope)
}

#[test]
fn a_write_creating_a_shell_suffixed_file_is_refused() {
    let dir = repo("shell-authored-suffix", &[]);
    // NO SHEBANG: only the path arm can see this one.
    let call = write("x.sh", "echo hi\n");
    assert_eq!(fact(&dir, &call), Look::Is(SHELL_PATH));
    let reason = denied(&dir, &call).expect("a created shell file is refused");
    assert!(reason.contains(VERDICT), "{reason}");
    assert!(
        reason.contains("x.sh"),
        "the pointer names the path\n{reason}"
    );
    assert!(
        !reason.contains("echo hi"),
        "pointer-only: the content never travels\n{reason}"
    );

    // ANTI-VACUITY: the same content under a name that is not shell passes.
    assert!(!refused(&dir, &write("x.txt", "echo hi\n")));
}

/// The fact is resolved only for a write about to happen: the same write
/// reported after it ran (`PostToolUse`) carries no `shell-introduced` fact,
/// so the row that refuses on it says nothing.
///
/// Fails by: `shell_introduced_for`'s event guard joined with `||`, so every
/// pre-tool call or a post-tool write resolves the fact and a write already
/// made is refused after the fact (CLOUD-2789).
#[test]
fn a_write_reported_after_it_ran_is_not_refused() {
    let dir = repo("shell-authored-post-tool", &[]);
    let before = write("x.sh", "echo hi\n");
    // ANTI-VACUITY: the same write, about to happen, is refused.
    assert!(refused(&dir, &before));
    let after = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "x.sh", "content": "echo hi\n"},
        "tool_response": {"filePath": "x.sh", "success": true},
    })
    .to_string();
    let output = common::run_with_stdin(&dir, &["adjudicate", "--harness", "claude-code"], &after);
    let said = format!("{}{}", common::stdout(&output), common::stderr(&output));
    assert!(
        !said.contains(VERDICT),
        "a post-tool write is past the gate: {said}"
    );
}

/// Only a target that does not exist is a creation: a target the disk cannot
/// answer for — a path beneath a regular file — is could-not-look.
///
/// Fails by: every metadata error read as an absent file, which hands a
/// could-not-look path to the shell-suffix arm as a fresh shell file.
#[test]
fn a_target_the_disk_cannot_answer_for_is_could_not_look() {
    if cfg!(windows) {
        // A path beneath a file reads as NotFound there, not NotADirectory.
        return;
    }
    let dir = repo("shell-authored-unanswerable", &[("plain", "body\n")]);
    assert_eq!(
        fact(&dir, &write("plain/x.sh", "echo hi\n")),
        Look::CouldNotLook
    );
    // ANTI-VACUITY: the same name where its parent is a directory is a creation.
    assert_eq!(
        fact(&dir, &write("x.sh", "echo hi\n")),
        Look::Is(SHELL_PATH)
    );
}

#[test]
fn a_write_landing_a_shell_shebang_is_refused_and_another_language_is_not() {
    let dir = repo("shell-authored-shebang", &[]);
    let call = write("x.txt", "#!/bin/bash\necho hi\n");
    assert_eq!(fact(&dir, &call), Look::Is(SHEBANG));
    assert!(refused(&dir, &call), "a shell shebang on line 1 is refused");

    let python = write("x.txt", "#!/usr/bin/env python3\nprint('hi')\n");
    assert_eq!(fact(&dir, &python), Look::IsNot);
    assert!(
        !refused(&dir, &python),
        "a shebang naming another language is not shell"
    );
}

/// The tree arms own shell already there: an overwrite keeping it adds none.
#[test]
fn an_overwrite_keeping_an_existing_shebang_is_not_refused() {
    let dir = repo(
        "shell-authored-overwrite",
        &[("tool", "#!/bin/bash\necho a\n"), ("plain", "echo a\n")],
    );
    let keep = write("tool", "#!/bin/bash\necho b\n");
    assert_eq!(fact(&dir, &keep), Look::IsNot);
    assert!(!refused(&dir, &keep), "keeping line 1 introduces nothing");

    // ANTI-VACUITY: the same write over a file whose line 1 named no shell is
    // refused, so the comparison against disk is what admitted the one above.
    assert!(refused(&dir, &write("plain", "#!/bin/bash\necho b\n")));
}

#[test]
fn an_edit_and_a_batch_putting_a_shebang_on_line_one_are_refused() {
    let dir = repo("shell-authored-edit", &[("notes.txt", "plain\nbody\n")]);
    let edit = payload(
        "Edit",
        &serde_json::json!({
            "file_path": "notes.txt",
            "old_string": "plain",
            "new_string": "#!/bin/bash\nplain",
        }),
    );
    assert_eq!(fact(&dir, &edit), Look::Is(SHEBANG));
    assert!(
        refused(&dir, &edit),
        "an edit spelling the shebang is refused"
    );

    // The shebang lands in the SECOND span, against the first's result.
    let batch = payload(
        "MultiEdit",
        &serde_json::json!({
            "file_path": "notes.txt",
            "edits": [
                {"old_string": "body", "new_string": "more"},
                {"old_string": "plain", "new_string": "#!/bin/sh\nplain"},
            ],
        }),
    );
    assert_eq!(fact(&dir, &batch), Look::Is(SHEBANG));
    assert!(
        refused(&dir, &batch),
        "a batch spelling the shebang is refused"
    );

    // An edit below line 1 introduces nothing.
    let below = payload(
        "Edit",
        &serde_json::json!({
            "file_path": "notes.txt",
            "old_string": "body",
            "new_string": "#!/bin/bash",
        }),
    );
    assert!(!refused(&dir, &below));
}

#[test]
fn a_file_over_the_bound_and_a_notebook_could_not_look_and_are_not_refused() {
    let big = "x".repeat((1 << 20) + 1);
    let dir = repo("shell-authored-could-not-look", &[("big.txt", &big)]);

    let over = write("big.txt", "#!/bin/bash\n");
    assert_eq!(fact(&dir, &over), Look::CouldNotLook);
    assert!(!refused(&dir, &over), "could-not-look abstains");

    let notebook = payload(
        "NotebookEdit",
        &serde_json::json!({
            "notebook_path": "n.ipynb",
            "cell_id": "one",
            "new_source": "#!/bin/bash\necho hi\n",
        }),
    );
    assert_eq!(fact(&dir, &notebook), Look::CouldNotLook);
    assert!(
        !refused(&dir, &notebook),
        "a cell's first line is not a file's"
    );
}

/// The operator's ruling: the ban covers what the repository commits, never the
/// agent's own tool calls.
#[test]
fn a_bash_call_is_never_refused_by_this_module() {
    let dir = repo("shell-authored-bash", &[]);
    let bash = payload(
        "Bash",
        &serde_json::json!({"command": "sh -c 'printf \"#!/bin/sh\" > y.sh'"}),
    );
    assert_eq!(fact(&dir, &bash), Look::CouldNotLook);
    assert!(!refused(&dir, &bash));
}

/// A write outside the repository commits nothing to it.
#[test]
fn a_write_outside_the_repository_is_not_refused() {
    let dir = repo("shell-authored-outside", &[]);
    let outside = common::scratch("shell-authored-outside-target").join("x.sh");
    let call = write(outside.to_str().expect("a UTF-8 path"), "echo hi\n");
    assert_eq!(fact(&dir, &call), Look::IsNot);
    assert!(!refused(&dir, &call));
}

/// THE FIRING RATE over the recorded corpus: every write-tool call in the
/// transcript fixtures, fed through the same path. The corpus is small — four
/// calls in two files — so this pins that nothing in it fires, not a rate.
#[test]
fn the_transcript_corpus_writes_fire_nothing() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/transcripts");
    let dir = repo("shell-authored-corpus", &[]);
    let (mut examined, mut fired) = (0_usize, 0_usize);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .expect("the transcript fixtures")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.to_string_lossy().ends_with(".jsonl.in"))
        .collect();
    files.sort();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a fixture reads");
        for line in text.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(content) = record
                .pointer("/message/content")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for block in content {
                let name = block["name"].as_str().unwrap_or_default();
                if block["type"] != "tool_use"
                    || !matches!(name, "Write" | "Edit" | "MultiEdit" | "NotebookEdit")
                {
                    continue;
                }
                // The recorded checkout was `/w`; this one is the fixture.
                let mut input = block["input"].clone();
                for key in ["file_path", "notebook_path"] {
                    if let Some(path) = input[key].as_str() {
                        input[key] =
                            serde_json::Value::from(path.strip_prefix("/w/").unwrap_or(path));
                    }
                }
                examined += 1;
                fired += usize::from(refused(&dir, &payload(name, &input)));
            }
        }
    }
    assert_eq!((examined, fired), (4, 0));
}

/// Only a target that is ABSENT reads as a created file: one that cannot be
/// stat'd for any other reason (here a regular file standing where a directory
/// must be) is could-not-look, never a new shell file.
///
/// Fails by: every stat error read as "absent", which would decide the path
/// arm over a target the producer never saw.
#[test]
fn a_target_that_cannot_be_stated_is_could_not_look() {
    let dir = repo("shell-authored-unstatable", &[("notes.txt", "plain\n")]);
    let call = write("notes.txt/run.sh", "echo hi\n");
    assert_eq!(fact(&dir, &call), Look::CouldNotLook);
    // ANTI-VACUITY: the same name under a real directory is a created shell file.
    assert_eq!(
        fact(&dir, &write("tools/run.sh", "echo hi\n")),
        Look::Is(SHELL_PATH)
    );
}
