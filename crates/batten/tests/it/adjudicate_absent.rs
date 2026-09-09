//! A call this build cannot adjudicate is DENIED, never allowed by a failure.
//!
//! The tier that proves the engine does not fail open when it has read its own
//! authority and been told it cannot enforce it. Unit cases over `adjudicate`
//! cannot host this: the defect is not in the decision, it is in what the
//! BOUNDARY does with a load that failed, and only the compiled binary answers
//! that — `mediated_admission.rs`'s header records the same lesson, where unit
//! cases passed while the binary allowed the write.
//!
//! # The mirror is not decoration
//!
//! `a_loadable_config_still_allows_an_ordinary_call` is what stops this being
//! satisfied by an adjudicator that denies everything. A fail-closed hook that
//! refuses each call is not a fix, it is an outage — CLOUD-1688's falsifier says
//! so in as many words, and that is why the pair lands together.
//!
//! # Scope
//!
//! The CONFIG half of CLOUD-1688: a `batten.toml` this build cannot load. The
//! VERB half — a registration spelling a subcommand the installed binary does
//! not have — needs `doctor` to interrogate the installed artifact rather than
//! itself, because a self-check runs in the build that mise resolves and never
//! in the one the hook does. It lands with that part and belongs in this file.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin};

/// A `batten.toml` mid-edit, which is the largest measured bucket: seven windows
/// across one 5-day session, 1,149 calls, every one of them unjudged.
const WILL_NOT_PARSE: &str = "version = 1\nthis is not toml\n";

/// A config that loads and declares nothing this call matches.
const LOADS: &str = "version = 1\n";

/// A fixture carrying `body` as its committed authority.
fn fixture(name: &str, body: &str) -> PathBuf {
    Fixture::new(name)
        .config(body)
        .file("notes.md", "ordinary\n")
        .git()
        .base_commit()
        .build()
}

/// A Claude Code `PreToolUse` envelope carrying a command, so the boundary
/// treats it as adjudicable and reaches the config load at all.
fn payload() -> String {
    "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
     \"tool_input\":{\"command\":\"echo hello\"}}"
        .to_owned()
}

/// Adjudicate on the neutral adapter, where the VERDICT IS THE NUMBER.
///
/// `exit-code` rather than `claude-code` for the two cases that ask what the
/// code is: on Claude Code the deny is the JSON document at exit `0`, so a case
/// asserting a number there would assert the wrong channel. The document is
/// checked separately below.
fn code(dir: &Path) -> Option<i32> {
    run_with_stdin(dir, &["adjudicate", "--harness", "exit-code"], &payload())
        .status
        .code()
}

#[test]
fn a_config_this_build_cannot_load_denies_rather_than_failing_open() {
    // The defect: this was `2` only if the load succeeded. A `?` on the load
    // raised a `UsageError` — exit `1` — and a harness reads `1` as a
    // non-blocking hook error, so the mediated tool ran with nothing judging it.
    let dir = fixture("adjudicate-unloadable", WILL_NOT_PARSE);
    assert_eq!(
        code(&dir),
        Some(2),
        "a call nothing could judge must be refused, not allowed by the failure"
    );
}

#[test]
fn a_loadable_config_still_allows_an_ordinary_call() {
    // THE MIRROR. Without it the case above is satisfied by an adjudicator that
    // denies every call in the fleet, which is an outage wearing a fix's clothes.
    let dir = fixture("adjudicate-loadable", LOADS);
    assert_eq!(
        code(&dir),
        Some(0),
        "a config that loads and refuses nothing must still allow"
    );
}

#[test]
fn the_declared_hatch_still_reaches_a_clone_whose_config_will_not_load() {
    // What keeps a container recoverable rather than bricked. A stale binary
    // meeting a newer config refuses every call until one of them moves, so the
    // operator's declared escape has to survive exactly the state that needs it.
    //
    // `common::batten()` scrubs every bypass variable by construction, so setting
    // one here is the only way it is present — a case that inherited it from the
    // developer's shell would pass without testing anything.
    use std::io::Write as _;
    use std::process::Stdio;

    let dir = fixture("adjudicate-hatch", WILL_NOT_PARSE);
    let mut child = common::batten()
        .args(["adjudicate", "--harness", "exit-code"])
        .current_dir(&dir)
        .env("BATTEN_HOOK_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload().as_bytes())
        .expect("the payload is writable");
    let output = child.wait_with_output().expect("the binary answers");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the declared hatch must still pass a call the engine cannot judge"
    );
}

#[test]
fn on_claude_code_the_refusal_is_the_document_rather_than_the_number() {
    // THE CHANNEL IS PER-HARNESS AND THE NUMBER IS NOT (`run_hook`'s own
    // contract). This host reads the JSON decision object and ignores the code,
    // so a deny raised as `2` here would be a refusal nobody receives — which is
    // the reason this arm renders rather than raising a `Denial`.
    let dir = fixture("adjudicate-document", WILL_NOT_PARSE);
    let output = run_with_stdin(
        dir.as_path(),
        &["adjudicate", "--harness", "claude-code"],
        &payload(),
    );
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(
        rendered.contains("deny"),
        "the decision object must carry the deny: {rendered}"
    );
}
