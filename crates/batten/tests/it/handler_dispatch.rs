//! The command selector, over the compiled binary and the real door (CLOUD-1650).
//!
//! # What this tier reaches that a unit case cannot
//!
//! `Handler::selects_command` is a pure function and its own cases pin the
//! decision. What they structurally cannot reach is everything between the
//! config file and that decision: that `command_matcher` parses at all, that
//! `resolve` carries it to the dispatch, that the boundary hands the ENVELOPE's
//! command to it rather than an empty string, and that a selected handler's
//! output arrives as `additionalContext` with the adjudicated call still
//! allowed.
//!
//! Each of those is a place the column can be completely dead while every unit
//! case passes — a config key the engine never reads is the class
//! `rules/policy-modules.md` records for a Rego predicate over a key nothing
//! builds.
//!
//! # Why the handler is a stub rather than `batten doctor mediator`
//!
//! The row this column exists for runs a real staleness check, and a fixture
//! that ran one would be testing the CONTAINER: whether the scratch repository
//! happens to build a mediator decides the verdict, and the case would pass or
//! fail for a reason that has nothing to do with the selector. The stub prints
//! the verdict token the real row's task prints, so what is under test is the
//! path the text travels rather than the text's author.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::PathBuf;

use common::{git_in, scratch, stdout, write};

/// ONE ROW, and no `[[rule]]` at all — `connector_allow_door`'s discipline, for
/// its reason: nothing in the engine may produce a verdict of its own and be
/// mistaken for the handler's.
///
/// `post-tool` is the event the row is declared on, and the choice is load
/// bearing rather than incidental. The question is whether the tree MOVED, which
/// is only answerable after the call ran; and `adjudicate` allows every
/// non-pre-tool event before any rule is consulted, so "this never denies" is
/// structural here rather than a promise the handler has to keep.
const CONFIG: &str = r#"version = 1

[[hook.handler]]
id = "head-move-mediator-check"
on = "post-tool"
run = ["mediator-advise.sh"]
matcher = "^Bash$"
command_matcher = "\\bgit\\b.*\\b(merge|pull|rebase|checkout|switch|reset)\\b"
timeout_ms = 5000
owner = "CLOUD-1650"
expires = "2027-03-31"
"#;

struct Bench {
    repo: PathBuf,
    ran: PathBuf,
}

/// What the door said to the host.
struct Door {
    out: String,
}

impl Bench {
    /// Hand one mediated call to the engine on the post side.
    fn door(&self, tool: &str, command: &str) -> Door {
        use std::io::Write as _;

        let payload = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
        })
        .to_string();

        let mut child = common::batten()
            .current_dir(&self.repo)
            .args(["adjudicate", "--harness", "claude-code"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the binary runs");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(payload.as_bytes())
            .expect("write stdin");
        let outcome = child.wait_with_output().expect("wait for batten");
        Door {
            out: stdout(&outcome),
        }
    }

    /// Whether the handler was spawned at all.
    ///
    /// A marker file rather than a reading of the output, because "did not fire"
    /// and "fired and said nothing" are the two states this suite most needs to
    /// keep apart — and on the advisory channel they render identically.
    fn spawned(&self) -> bool {
        self.ran.exists()
    }
}

/// A repository whose handler is a stub that records that it ran.
///
/// `verdict` is what the stub writes to stdout; empty means it exits 0 silently,
/// which is `Outcome::Pass` and carries no advisory.
fn bench(name: &str, verdict: &str) -> Bench {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    write(&repo, "batten.toml", CONFIG);
    write(&repo, "a.txt", "x\n");
    git_in(&repo, &["init", "-q", "-b", "main", "."]);

    let ran = repo.join("handler-ran");
    let body = if verdict.is_empty() {
        format!("#!/bin/sh\ntouch {:?}\nexit 0\n", ran.to_str().unwrap())
    } else {
        format!(
            "#!/bin/sh\ntouch {:?}\necho {verdict:?}\nexit 1\n",
            ran.to_str().unwrap()
        )
    };
    let script = repo.join("mediator-advise.sh");
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    Bench { repo, ran }
}

/// The advisory the row exists for reaches the agent, and the call is allowed.
///
/// Exit `1` from the handler is `Outcome::Reported`, which the boundary pushes at
/// `AdvisoryTier::Warning` — so the verdict token travels on `additionalContext`
/// and nothing about the git call's own decision moves. That pairing is the
/// row's whole acceptance: CLOUD-1326's posture is that a tree move is
/// legitimate work, so this may never deny.
#[test]
fn a_head_moving_git_call_carries_the_staleness_verdict_as_advice() {
    let bench = bench(
        "handler-head-move",
        "mediator failed mediator-build-behind-source",
    );
    let door = bench.door("Bash", "git checkout -");

    assert!(bench.spawned(), "the row selects this command");
    assert!(
        door.out.contains("mediator-build-behind-source"),
        "the verdict must reach the agent, not only the handler's own stdout: {}",
        door.out
    );
    assert!(
        !door.out.contains("\"permissionDecision\":\"deny\""),
        "a tree move is legitimate work — CLOUD-1326's posture — so this never denies: {}",
        door.out
    );
}

/// The mutation's target: a git call that moves no HEAD is not selected.
///
/// **This is the case the declared mutation reddens, and it asserts a NEGATIVE
/// deliberately.** A suite that only checked the advisory fires would stay green
/// with the selector dropped, because a handler that fires on everything fires on
/// the selected call too. What an over-firing row breaks is every call it should
/// have been silent on — so that is what is asserted.
#[test]
fn a_git_call_that_moves_no_head_is_not_selected() {
    let bench = bench(
        "handler-no-head-move",
        "mediator failed mediator-build-behind-source",
    );
    let door = bench.door("Bash", "git status --short");

    assert!(
        !bench.spawned(),
        "the handler must not even spawn: the saving is the process, not the output"
    );
    assert!(
        !door.out.contains("mediator-build-behind-source"),
        "a command that moved no HEAD must carry no staleness advisory: {}",
        door.out
    );
}

/// A tool with no command at all is not selected either.
///
/// The `None` arm of [`Handler::selects_command`], which is the opposite reading
/// from the tool matcher's could-not-look. A row declaring `command_matcher` has
/// said its subject is a command; firing it on every `Read` in the session is the
/// unnarrowed cost the column exists to remove — and an empty command reaching
/// the regex as `""` is how that happens by accident.
#[test]
fn a_tool_carrying_no_command_is_not_selected() {
    let bench = bench(
        "handler-no-command",
        "mediator failed mediator-build-behind-source",
    );
    let door = bench.door("Read", "");

    assert!(
        !bench.spawned(),
        "a non-command tool is not this row's subject"
    );
    assert!(!door.out.contains("mediator-build-behind-source"));
}

/// A current binary produces no advisory, though the handler did run.
///
/// The row's second acceptance clause, and the one that keeps the channel
/// credible: silence is the healthy answer, and a row that spoke on every HEAD
/// move would breach `[hook_output] max_repeats` within a turn. `spawned` is what
/// separates this from the case above — here the selector DID fire and the
/// handler had nothing to say.
#[test]
fn a_current_mediator_produces_no_advisory_on_the_same_call() {
    let bench = bench("handler-current", "");
    let door = bench.door("Bash", "git rebase origin/main");

    assert!(bench.spawned(), "the row still selects the call");
    assert!(
        !door.out.contains("mediator"),
        "exit 0 with no output is Pass, which carries nothing: {}",
        door.out
    );
}
