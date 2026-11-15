//! A protected path a shell call changed without naming it, refused after the
//! fact (step 14).
//!
//! `protected-mutation` judges the operands a command NAMES. A program writing a
//! protected path its command line never spells — a `python3` script, a `sed`
//! inside a variable, a `cp` of a parent, a redirect the text does not show —
//! passed it, and did: a session wrote registered modules through a `python3`
//! script with nothing refusing. The engine now snapshots the protected set
//! on the call's `PreToolUse` and compares on its `PostToolUse`, keyed by the
//! call id.
//!
//! The write itself is the test process's, between the two hook calls: what the
//! command text says is irrelevant to the comparison, which is the point — each
//! row's text names no protected path, so the pre-call gate allows all of them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stdout};

const GUARDED: &str = "guarded.txt";
const ORDINARY: &str = "notes.md";

fn fixture(name: &str) -> PathBuf {
    // The `[[verb]]` row makes the policy adjudicable (`mediated_admission.rs`
    // records why); it matches none of the calls below.
    Fixture::new(name)
        .config(
            "version = 1\n\
             protected = [\"guarded.txt\"]\n\n\
             [[verb]]\n\
             verb = \"shred\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(GUARDED, "guarded\n")
        .file(ORDINARY, "not protected\n")
        .git()
        .base_commit()
        .build()
}

fn payload(event: &str, call: &str, command: &str) -> String {
    let escaped = serde_json::to_string(command).expect("a command is encodable");
    let response = if event == "PostToolUse" {
        ",\"tool_response\":{\"stdout\":\"\",\"stderr\":\"\",\"interrupted\":false}"
    } else {
        ""
    };
    format!(
        "{{\"hook_event_name\":\"{event}\",\"session_id\":\"s1\",\"tool_use_id\":\"{call}\",\
         \"tool_name\":\"Bash\",\"tool_input\":{{\"command\":{escaped}}}{response}}}"
    )
}

/// Run one call through both hooks with `write` between them, returning the
/// post-call exit code and what it printed.
fn around(dir: &Path, call: &str, command: &str, write: &str) -> (Option<i32>, String) {
    let pre = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PreToolUse", call, command),
    );
    assert!(
        !stdout(&pre).contains("\"deny\""),
        "the command names no protected path, so the pre-call gate allows it: {command}\n{}",
        stdout(&pre)
    );
    std::fs::write(dir.join(write), "changed\n").expect("the write lands");
    let post = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &payload("PostToolUse", call, command),
    );
    (
        post.status.code(),
        format!("{}{}", stdout(&post), String::from_utf8_lossy(&post.stderr)),
    )
}

/// Every spelling that writes the protected path without naming it is refused
/// after the fact, naming the path and the override route.
#[test]
fn an_unnamed_protected_write_is_refused_after_the_fact() {
    let dir = fixture("protected-escape-refused");
    for (at, command) in [
        "python3 tool.py",
        "sed -i s/guarded/changed/ \"$TARGET\"",
        "cp /tmp/draft ./",
        "printf changed | tee \"$TARGET\"",
        "echo changed > \"$TARGET\"",
    ]
    .into_iter()
    .enumerate()
    {
        let (code, said) = around(&dir, &format!("t{at}"), command, GUARDED);
        assert_eq!(code, Some(2), "{command}: {said}");
        assert!(said.contains("\"decision\":\"block\""), "{command}: {said}");
        assert!(
            said.contains("path write refused at guarded.txt"),
            "{command}: the refusal names the path: {said}"
        );
        assert!(
            said.contains("batten override request --rule 'protected-mutation'"),
            "{command}: and the override route: {said}"
        );
    }
}

/// A write a spent admission names passes: the admission is the record a
/// deliberate protected write leaves.
#[test]
fn an_admitted_protected_write_passes() {
    let dir = fixture("protected-escape-admitted");
    let subject = "guarded.txt python3";
    let answers = "precondition=the owning surface cannot express this write\n\
                   lost=the fixture's guarded file stays stale\n\
                   rejected-route=the redirect names a surface this case does not have\n";
    let issued = run_with_stdin(
        &dir,
        &[
            "override",
            "request",
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            subject,
        ],
        answers,
    );
    assert!(
        issued.status.success(),
        "{}",
        String::from_utf8_lossy(&issued.stderr)
    );
    let admission = stdout(&issued)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned();
    let spent = run(
        &dir,
        &[
            "override",
            "spend",
            "--admission",
            &admission,
            "--rule",
            "protected-mutation",
            "--verdict",
            "path write refused",
            "--subject",
            subject,
        ],
    );
    assert!(
        spent.status.success(),
        "{}",
        String::from_utf8_lossy(&spent.stderr)
    );
    let (code, said) = around(&dir, "t-admitted", "python3 tool.py", GUARDED);
    assert_eq!(
        code,
        Some(0),
        "a spent admission naming the path admits it: {said}"
    );
}

/// A write to an unprotected path is none of this.
#[test]
fn an_unprotected_write_passes() {
    let dir = fixture("protected-escape-ordinary");
    let (code, said) = around(&dir, "t-ordinary", "python3 tool.py", ORDINARY);
    assert_eq!(code, Some(0), "{said}");
    assert!(!said.contains("path write refused"), "{said}");
}
