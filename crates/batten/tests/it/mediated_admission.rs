//! A mediated refusal is admissible by a spent admission, and only by one.
//!
//! The tier that proves the ENGINE honours what the route advertises. Without it
//! `V-PROTECTED-MUTATION`'s `R-ARTICULATE-THE-WRITE` is a promise made in a
//! refusal message: `batten override request` would answer, mint a real record,
//! and the write would still be refused — the exact defect `verdict.rs`'s header
//! exists to kill, one layer along.
//!
//! # Why a fixture rather than `mediated_verbs.rs`
//!
//! That suite adjudicates against the LIVE repository root, which is right for
//! asking what the committed policy decides. It cannot host these cases: they
//! must WRITE an admission, and the store lives under `$GIT_DIR`, so the case
//! would deposit records in the developer's own repository and bind its real
//! HEAD. A fixture owns its store and its head.
//!
//! # The premise case is not decoration
//!
//! `a_write_to_a_protected_path_is_refused` asserts the deny that the other two
//! cases are about. Without it a fixture whose `protected` glob silently matched
//! nothing would pass the admission case for the wrong reason — the gate never
//! fired, so nothing needed admitting.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run, run_with_stdin, stdout};

/// The protected path under test, and one that is not.
const GUARDED: &str = "batten.toml";
const ORDINARY: &str = "notes.md";

/// The rule id the derived protected-path gate denies under, and its class.
///
/// Both are the engine's own constants rather than strings chosen here — a case
/// that spelled them itself would keep passing after a rename that broke every
/// consumer.
const RULE: &str = "protected-mutation";
const CLASS: &str = "V-PROTECTED-MUTATION";

/// A fixture whose committed authority protects itself.
///
/// `protected` naming `batten.toml` is this repository's own row, and it is the
/// case that matters: the file a registration has to edit is the file the gate
/// refuses, which is why `R-USE-THE-OWNING-SURFACE` cannot reach it.
fn fixture(name: &str) -> PathBuf {
    Fixture::new(name)
        // THE `[[verb]]` ROW IS LOAD-BEARING AND DOES NOT MATCH THIS CALL, which
        // reads as contradictory until `Policy::is_empty` explains it: that
        // predicate is `verbs.is_empty() || protected.is_empty()`, and it
        // short-circuits `adjudicate` before any gate runs. So a repository with
        // protected paths and NO verb rows cannot refuse a write tool — even
        // though `protected_tool_write` needs no matching row and treats a verb
        // miss as "no verb-level remedy" rather than as a reason to allow.
        //
        // The row below is therefore what makes the policy adjudicable at all,
        // not what selects this call. A fixture that omitted it would allow the
        // write and the premise case would fail — which is how this was found.
        .config(
            "version = 1\n\
             protected = [\"batten.toml\"]\n\n\
             [[verb]]\n\
             verb = \"tee\"\n\
             effect = \"write\"\n\
             redirect = \"write through the surface that owns the file\"\n",
        )
        .file(ORDINARY, "not protected\n")
        .git()
        .base_commit()
        .build()
}

/// A Claude Code `PreToolUse` envelope for a write tool aimed at `path`.
fn write_payload(path: &str) -> String {
    let escaped = serde_json::to_string(path).expect("a path is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Write\",\
         \"tool_input\":{{\"file_path\":{escaped},\"content\":\"x\"}}}}"
    )
}

/// Adjudicate one write against the fixture's policy, on the neutral adapter.
fn verdict(dir: &Path, path: &str) -> Option<i32> {
    run_with_stdin(
        dir,
        &["hook", "--harness", "exit-code"],
        &write_payload(path),
    )
    .status
    .code()
}

/// Answer all three declared questions and return the issued address.
///
/// The ids are `admission.rs`'s own — `precondition`, `lost`, `rejected-route` —
/// and the request is NOT interactive: it reads `<id>=<text>` lines from stdin,
/// which is what makes an override reachable from an autonomous session at all.
fn request(dir: &Path, subject: &str, reason: &str) -> String {
    let answers = format!(
        "precondition=the owning surface is the file being refused, so it cannot express this\n\
         lost={reason}\n\
         rejected-route=R-USE-THE-OWNING-SURFACE names batten.toml, which is the subject\n"
    );
    let output = run_with_stdin(
        dir,
        &[
            "override",
            "request",
            "--rule",
            RULE,
            "--verdict",
            CLASS,
            "--subject",
            subject,
        ],
        &answers,
    );
    assert!(
        output.status.success(),
        "request must issue: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout(&output)
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .to_owned()
}

/// Adjudicate one write with `BATTEN_HOOK_BYPASS` set, over the real binary.
///
/// `common::batten()` scrubs every bypass variable by construction, so setting one
/// here is the only way it is present — a case that inherited it from the
/// developer's shell would pass without testing anything.
fn verdict_under_bypass(dir: &Path, path: &str) -> Option<i32> {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = common::batten()
        .args(["hook", "--harness", "exit-code"])
        .current_dir(dir)
        .env("BATTEN_HOOK_BYPASS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn batten");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(write_payload(path).as_bytes());
    }
    child
        .wait_with_output()
        .expect("await batten")
        .status
        .code()
}

/// Spend an issued admission against the situation it was issued for.
fn spend(dir: &Path, admission: &str, subject: &str) -> bool {
    run(
        dir,
        &[
            "override",
            "spend",
            "--admission",
            admission,
            "--rule",
            RULE,
            "--verdict",
            CLASS,
            "--subject",
            subject,
        ],
    )
    .status
    .success()
}

/// THE PREMISE. Every case below is about admitting this refusal, so a fixture
/// where it never fires would pass them vacuously.
#[test]
fn a_write_to_a_protected_path_is_refused() {
    let dir = fixture("mediated-admission-premise");
    assert_eq!(verdict(&dir, GUARDED), Some(2), "the gate must fire");
    assert_eq!(
        verdict(&dir, ORDINARY),
        Some(0),
        "and must not fire on an unprotected path"
    );
}

/// The whole point: articulate, spend, and the same write goes through.
#[test]
fn a_spent_admission_admits_the_write_it_was_taken_for() {
    let dir = fixture("mediated-admission-admits");
    assert_eq!(verdict(&dir, GUARDED), Some(2), "the premise");

    let admission = request(&dir, GUARDED, "the rule cannot be registered any other way");
    assert!(spend(&dir, &admission, GUARDED), "spend must consume it");

    assert_eq!(
        verdict(&dir, GUARDED),
        Some(0),
        "a spent admission must admit the write it was taken for"
    );
}

/// An ISSUED admission does not admit — only a spent one does.
///
/// `admission.rs` calls this "the whole economy": a mint that suppressed on its
/// own would restore the bypass variable it replaced — hold the name, pay
/// nothing, override forever.
#[test]
fn an_issued_but_unspent_admission_does_not_admit() {
    let dir = fixture("mediated-admission-unspent");
    let _ = request(&dir, GUARDED, "issued and deliberately not spent");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(2),
        "articulating is not overriding until it is spent"
    );
}

/// THE HATCH DOES NOT OPEN THIS GATE, over the compiled binary.
///
/// `hook.rs`'s unit cases assert this against `adjudicate` directly, which is the
/// decision function — but the bypass is resolved at the BOUNDARY, in `run_hook`,
/// and a unit case cannot see that wiring. A consumer depends on the end-to-end
/// behaviour, so `.claude/rules/rust.md` asks for it here.
///
/// The second assertion is the discriminator: without it this case would pass
/// just as well if the hatch had been deleted outright, and a reader could not
/// tell a scoped exemption from a removal.
#[test]
fn the_bypass_hatch_does_not_open_the_protected_gate_over_the_binary() {
    let dir = fixture("mediated-admission-bypass");
    assert_eq!(
        verdict_under_bypass(&dir, GUARDED),
        Some(2),
        "the hatch must not suppress a protected-path refusal"
    );
    assert_eq!(
        verdict_under_bypass(&dir, ORDINARY),
        Some(0),
        "and an unprotected path is allowed either way"
    );
}

/// The binding is per subject, so an admission cannot be harvested onto another.
#[test]
fn an_admission_for_another_subject_does_not_admit_this_one() {
    let dir = fixture("mediated-admission-subject");
    let admission = request(&dir, ORDINARY, "taken against a different path entirely");
    assert!(spend(&dir, &admission, ORDINARY), "spend must consume it");
    assert_eq!(
        verdict(&dir, GUARDED),
        Some(2),
        "an admission bound elsewhere must not reach this refusal"
    );
}
