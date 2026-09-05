//! Prospective write content as a fact, over the compiled binary (CLOUD-758).
//!
//! `Envelope::input` has held the whole `tool_input` since the adapter was
//! written, and nothing read it — so every write-shaped gate in the engine was
//! **path-keyed**: it could see which file a call would touch and not what would
//! end up in it. CLOUD-736 reports the symptom, a gate that refuses `git rm` on a
//! workflow and permits `Write` of one.
//!
//! Two properties carry the whole issue, and both are asserted here rather than
//! promised:
//!
//! * **Three-valued.** A tool whose shape carries no content yields *could not
//!   look*, never *empty*. Shown able to fail by collapsing the two.
//! * **Pointer-only.** A planted secret in the prospective content reaches no
//!   deny message, no `-J` document and nothing under the state root — the
//!   `secrets` acceptance, re-run on this path.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// A repository with one content-keyed row.
///
/// The row bans a conflict marker from anything a write would land — a predicate
/// that is genuinely about *content* and cannot be expressed as a path.
///
/// `(?m)` is not decoration. The predicate runs over the WHOLE prospective
/// content, so a bare `^` anchors to the start of the file rather than of a
/// line — which passes on a write whose first byte is the marker and misses the
/// same marker three lines in. Caught here by the edit case, which lands one in
/// the middle.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    std::fs::write(
        dir.join("batten.toml"),
        r#"version = 1

[[rule]]
id = "no-conflict-markers-written"
kind = "shape"
scope = "mediated_call"
severity = "deny"
content = "(?m)^<<<<<<< "
reason = "resolve the conflict before writing the file"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("notes.md"), "clean\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

/// One `PreToolUse` payload through `batten adjudicate --harness claude-code`.
fn hook(dir: &Path, payload: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

/// The deny reason the host would hand the model, if the call was refused.
fn denied(output: &Output) -> Option<String> {
    let raw = common::stdout(output);
    if raw.trim().is_empty() {
        return None;
    }
    let document: serde_json::Value = serde_json::from_str(&raw).expect("stdout is one document");
    let inner = &document["hookSpecificOutput"];
    if inner["permissionDecision"] != "deny" {
        return None;
    }
    Some(
        inner["permissionDecisionReason"]
            .as_str()
            .expect("a deny carries its reason")
            .to_owned(),
    )
}

fn write_payload(path: &str, content: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": path, "content": content },
    })
    .to_string()
}

#[test]
fn a_rule_decides_over_the_content_a_write_would_land() {
    // The capability the issue exists for: a mediated-call rule keyed on what
    // would be IN the file rather than on which file it is.
    let dir = fixture("prospective-write");
    let refused = hook(
        &dir,
        &write_payload("notes.md", "<<<<<<< HEAD\nmine\n=======\ntheirs\n"),
    );
    let reason = denied(&refused).expect("the content matches a refused shape");
    assert!(reason.contains("no-conflict-markers-written"), "{reason}");
    assert!(reason.contains("notes.md"), "the pointer names the file");

    // And the same path with clean content is allowed, so the row discriminates
    // on content rather than on the write.
    let allowed = hook(&dir, &write_payload("notes.md", "clean enough\n"));
    assert_eq!(allowed.status.code(), Some(0));
    assert_eq!(denied(&allowed), None);
}

#[test]
fn an_edit_is_judged_on_its_computed_post_edit_content() {
    // The arm that makes the fact `read` rather than `free`: the envelope carries
    // the two spans and nothing around them, so the result is computed against
    // the file on disk.
    let dir = fixture("prospective-edit");
    std::fs::write(dir.join("notes.md"), "one\ntwo\nthree\n").unwrap();

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "notes.md",
            "old_string": "two",
            "new_string": "<<<<<<< HEAD",
        },
    })
    .to_string();
    let reason = denied(&hook(&dir, &payload)).expect("the computed result matches");
    assert!(reason.contains("no-conflict-markers-written"), "{reason}");

    // An edit that lands clean content is allowed — the judgement is over the
    // RESULT, not over the spans in the envelope.
    let clean = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": "notes.md", "old_string": "two", "new_string": "four" },
    })
    .to_string();
    assert_eq!(denied(&hook(&dir, &clean)), None);
}

/// The BATCH spelling of an edit is inspected, not waved through.
///
/// The widest hole a content-keyed gate can have: the same edit, spelled the
/// other way, reaching adjudication as though nothing had been written. The
/// spans arrive under `edits` rather than at the top level, and a reader that
/// only knows the top-level shape allows every one of them.
///
/// Fails by: dropping the `/edits` arm from `edit_spans` — the batch then reads
/// as could-not-look and the row does not fire.
#[test]
fn a_batch_of_edits_is_judged_on_the_content_all_of_them_would_land() {
    let dir = fixture("prospective-multi-edit");
    std::fs::write(dir.join("notes.md"), "one\ntwo\nthree\n").unwrap();

    let payload = |edits: serde_json::Value| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "MultiEdit",
            "tool_input": { "file_path": "notes.md", "edits": edits },
        })
        .to_string()
    };

    // The marker is landed by the SECOND span, so a reader that stopped at the
    // first would allow it — the spans are applied in order, against the result
    // of the ones before.
    let refused = payload(serde_json::json!([
        { "old_string": "one", "new_string": "first" },
        { "old_string": "three", "new_string": "<<<<<<< HEAD" },
    ]));
    let reason = denied(&hook(&dir, &refused)).expect("the computed batch matches");
    assert!(reason.contains("no-conflict-markers-written"), "{reason}");

    // And a batch landing clean content is allowed, so the row still
    // discriminates on the result rather than on the shape of the call.
    let clean = payload(serde_json::json!([
        { "old_string": "one", "new_string": "first" },
        { "old_string": "three", "new_string": "third" },
    ]));
    assert_eq!(denied(&hook(&dir, &clean)), None);
}

/// A notebook cell's replacement source is content, and is inspected as content.
///
/// The JSON frame around it is not: a notebook's file bytes are a document
/// format, and a row asking what a write would land is asking about the source
/// the call carries, which arrives whole and already deserialized.
///
/// Fails by: dropping `/new_source` from the free arm of `prospective_facts`.
#[test]
fn a_notebook_cell_source_is_the_content_the_write_would_land() {
    let dir = fixture("prospective-notebook");

    let payload = |source: &str| {
        serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "notes.ipynb",
                "cell_id": "one",
                "new_source": source,
            },
        })
        .to_string()
    };

    let reason = denied(&hook(&dir, &payload("<<<<<<< HEAD\n"))).expect("the source matches");
    assert!(reason.contains("no-conflict-markers-written"), "{reason}");
    assert_eq!(denied(&hook(&dir, &payload("clean enough\n"))), None);
}

/// **The three-valued case.** A tool whose shape carries no content is *could
/// not look*, never *empty*.
///
/// Fails by: collapsing the two in `prospective_facts` — returning
/// `Look::Is(String::new())` for a call with no content instead of
/// `Look::CouldNotLook`. A row keyed on an empty result would then fire on every
/// shell command as though it had inspected one, which is failing open in the
/// one direction that looks like it looked.
#[test]
fn a_tool_carrying_no_content_could_not_look_rather_than_landing_nothing() {
    let dir = fixture("prospective-three-valued");

    // A shell call: no content in the envelope at all.
    let bash = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "echo hi" },
    })
    .to_string();
    let output = hook(&dir, &bash);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(denied(&output), None, "no row may fire on could-not-look");

    // The discriminator: a row keyed on the EMPTY result. Without `(?m)` the
    // anchors are the whole text's, so this matches an empty result and nothing
    // else. If could-not-look were
    // an empty result, this would refuse the shell call above — so its passing is
    // what proves the two answers are kept apart rather than merely spelled apart.
    let empty_row = scratch("prospective-empty-row");
    std::fs::write(
        empty_row.join("batten.toml"),
        "version = 1\n\n[[rule]]\nid = \"anything-at-all\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"deny\"\ncontent = \"^$\"\n\
         reason = \"matches an empty result\"\n",
    )
    .unwrap();
    common::git_in(&empty_row, &["init", "-q"]);
    common::git_in(&empty_row, &["add", "-A"]);
    common::git_in(&empty_row, &["commit", "-qm", "seed"]);

    assert_eq!(
        denied(&hook(&empty_row, &bash)),
        None,
        "a row matching an empty result must NOT fire on a call that carried none"
    );
    // And it does fire on a write that genuinely lands nothing, so the row is
    // able to match at all and the case above is not vacuous.
    assert!(
        denied(&hook(&empty_row, &write_payload("notes.md", ""))).is_some(),
        "the same row fires on a write whose content really is empty"
    );
}

/// **Pointer-only**, the `secrets` acceptance re-run on this path.
///
/// Fails by: putting the matched span in the refusal, or projecting the content
/// itself into the policy input. A policy module's message is free-form text a
/// consumer writes, so content in that document is content that can be echoed —
/// which is why the projection carries a shape and a count and the bytes stop at
/// the typed predicate.
#[test]
fn a_planted_secret_in_the_content_reaches_no_output_and_nothing_on_disk() {
    // Assembled rather than written, for the reason `contract_drift.rs` gives:
    // a credential-shaped literal in a tracked file is what `no-secrets` exists
    // to catch, and it is right to.
    let planted = format!("{}_{}", "ghp", "thisIsTheSortOfThingAWriteMustNeverEcho");
    let dir = scratch("prospective-pointer-only");
    std::fs::write(
        dir.join("batten.toml"),
        "version = 1\n\n[[rule]]\nid = \"no-tokens-written\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"deny\"\ncontent = \"ghp_[A-Za-z]+\"\n\
         reason = \"do not commit a credential\"\n",
    )
    .unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);

    let refused = hook(&dir, &write_payload("secrets.txt", &planted));
    let reason = denied(&refused).expect("the planted value matches the row");
    assert!(reason.contains("no-tokens-written"), "{reason}");
    assert!(reason.contains("secrets.txt"), "the pointer names the file");

    // Not in the deny message, on either stream.
    assert!(
        !reason.contains(&planted),
        "the matched byte must not travel"
    );
    assert!(!common::stdout(&refused).contains(&planted));
    assert!(!common::stderr(&refused).contains(&planted));

    // Nor anywhere under the repository's own state, which is where a cache or a
    // journal would put it if one were tempted to.
    for found in walk(&dir) {
        let body = std::fs::read(&found).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&body).contains(&planted),
            "{} carries the planted value",
            found.display()
        );
    }
}

/// Every file under `dir`, so the assertion above is over the whole state root
/// rather than over the two places one would think to look.
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn a_repository_with_no_content_keyed_row_pays_no_read_and_allows() {
    // The narrowing, observable from outside: a tree declaring no such row is
    // unaffected, which is what makes the `read` cost class acceptable.
    let dir = scratch("prospective-unnarrowed");
    std::fs::write(dir.join("batten.toml"), "version = 1\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);

    let output = hook(&dir, &write_payload("notes.md", "<<<<<<< HEAD\n"));
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(denied(&output), None);
}
