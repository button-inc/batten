//! The session-start container-health advisory, over the compiled binary
//! (CLOUD-1324).
//!
//! # Why this tier and not a unit test
//!
//! `src/doctor.rs` already pins what each check decides against explicit inputs.
//! What a unit test structurally cannot reach is the half this file exists for:
//! that the diagnosis is **wired to the advisory channel of the `hook` surface**,
//! at `SessionStart` and nowhere else, and that it rides it as one document
//! carrying no verdict. Every one of those is a property of the engine's own
//! plumbing, and `with input as`'s equivalent here — calling `diagnose` and
//! reading the `Report` — passes over a channel nothing writes to.
//!
//! That is the same class `.claude/rules/policy-modules.md` records for a dead
//! Rego clause, one layer over: a producer that resolves correctly and reaches
//! nobody looks exactly like a healthy container.
//!
//! # Why the report is pushed at all
//!
//! `batten doctor` has always answered this. Nobody ran it. A container missing
//! a declared program, or carrying a pin record that stopped validating, looks
//! identical to a healthy one right up until some gate silently decides nothing
//! — and the session's first moment is the only point at which that news is
//! still cheap.
//!
//! # The anti-vacuity half
//!
//! An advisory that fires on every fixture would satisfy the first case here and
//! mean nothing, so the discriminating assertion is the SUBJECT: the reachable
//! fixture's advisory must not name `command-programs`, over a tree identical to
//! the unreachable one except for the program the row spells. Same reason
//! `.claude/rules/policy-modules.md` demands a mirror beside every deny case.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::Path;
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// The check whose subject this suite discriminates on.
const CHECK: &str = "command-programs";

/// A repository declaring exactly one `command` rule, spelling `program`.
///
/// One row and nothing else: a fixture carrying a second declaration would let a
/// case pass on whichever check happened to fail, which is the failure the
/// subject assertions below exist to refuse.
fn fixture(name: &str, program: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    std::fs::write(
        dir.join("batten.toml"),
        format!(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"a-gate\"\n\
             kind = \"command\"\n\
             glob = \"**\"\n\
             check = \"{program} --version\"\n\
             severity = \"deny\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"a fixture repairs nothing\"\n"
        ),
    )
    .unwrap();
    std::fs::write(dir.join("a.txt"), "x\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

/// One hook call on `event`, through the door the host uses.
fn hook_on(dir: &Path, event: &str) -> Output {
    let payload = format!(r#"{{"hook_event_name":"{event}","session_id":"s-health","cwd":"/w"}}"#);
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
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
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "a health advisory is never a refusal — house-style §7"
    );
    output
}

/// The `additionalContext` the host would hand the model, if any.
///
/// Asserts ONE document for the reason `contract_drift`'s reader does: `run_hook`
/// has several advisory producers and a call can wake more than one; each writing
/// its own object would put two documents on a channel that carries one, and the
/// host would read the first and drop the rest.
fn advisory(output: &Output) -> Option<String> {
    let raw = common::stdout(output);
    if raw.trim().is_empty() {
        return None;
    }
    assert_eq!(
        raw.lines().filter(|line| !line.trim().is_empty()).count(),
        1,
        "exactly one advisory document reaches stdout per call: {raw}"
    );
    let document: serde_json::Value = serde_json::from_str(&raw).expect("stdout is one document");
    assert!(
        document["hookSpecificOutput"]["permissionDecision"].is_null(),
        "a health advisory carries no verdict field: SessionStart is not a call being adjudicated"
    );
    Some(
        document["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("an advisory carries additionalContext")
            .to_owned(),
    )
}

/// The measured shape: a declared program nothing can reach is said out loud, at
/// the session's first moment, naming the program rather than describing it.
///
/// `no-conflict-markers` is the instance — it declared `hk`, nothing a toolchain
/// manager provides is on bare `PATH`, and the merge-conflict gate had been
/// unable to launch for as long as the drift existed while `doctor` reported only
/// that SOME declared program was off `PATH`.
#[test]
fn a_declared_program_nothing_can_reach_is_reported_at_session_start() {
    let dir = fixture("health-unreachable", "batten-no-such-program-exists-here");
    let text = advisory(&hook_on(&dir, "SessionStart")).expect("a broken container is news");
    assert!(
        text.contains("container-health"),
        "the advisory names itself so a reader can tell the producers apart: {text}"
    );
    assert!(
        text.contains(CHECK),
        "the failing check is named: {text}"
    );
    assert!(
        text.contains("batten-no-such-program-exists-here"),
        "the SUBJECT is the program, not a count — a reader cannot fix `something is missing`: {text}"
    );
}

/// THE ANTI-VACUITY MIRROR. Without it the case above is satisfied by an
/// advisory that fires over every tree.
///
/// The two fixtures differ in one token, so a `command-programs` subject here
/// would be the check answering about something other than the program it read.
#[test]
fn a_reachable_program_is_not_reported_as_a_container_fault() {
    let dir = fixture("health-reachable", "git");
    let text = advisory(&hook_on(&dir, "SessionStart")).unwrap_or_default();
    assert!(
        !text.contains(CHECK),
        "a program the spawn would resolve is not a container fault: {text}"
    );
}

/// SESSION START AND NOWHERE ELSE.
///
/// The diagnosis is a statement about the machine this session got, which is
/// settled once; repeating it per batch is how an advisory channel becomes a
/// thing readers scroll past, and the contract reporter above already paid for
/// that lesson. Driven over the identical broken fixture so the silence is the
/// event's doing rather than the tree's.
#[test]
fn the_same_broken_container_is_silent_on_a_later_event() {
    let dir = fixture("health-later-event", "batten-no-such-program-exists-here");
    let text = advisory(&hook_on(&dir, "PostToolUse")).unwrap_or_default();
    assert!(
        !text.contains(CHECK),
        "a per-batch repeat of a per-session fact: {text}"
    );
}
