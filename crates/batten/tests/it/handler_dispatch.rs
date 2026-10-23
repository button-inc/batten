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

use common::{scratch, stdout, write};

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
run = ["./mediator-advise.sh"]
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
    err: String,
}

impl Bench {
    /// Hand one mediated call to the engine on the post side.
    fn door(&self, tool: &str, command: &str) -> Door {
        self.send(&serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": tool,
            "tool_input": { "command": command },
        }))
    }

    /// Hand one pre-tool `Write` of `file_path` to the engine (CLOUD-2390).
    fn write(&self, file_path: &str) -> Door {
        self.send(&serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": file_path, "content": "x" },
        }))
    }

    /// Hand `payload` to the engine's door.
    fn send(&self, payload: &serde_json::Value) -> Door {
        use std::io::Write as _;

        let payload = payload.to_string();
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
        // STDERR IS CARRIED because a door that REFUSED says so there, and a case
        // asserting only over stdout reports "the row did not select" for a call
        // the engine never adjudicated at all. Two different defects, one failure
        // message, and the wrong one is the easier to chase.
        let err = String::from_utf8_lossy(&outcome.stderr).into_owned();
        Door {
            out: stdout(&outcome),
            err,
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
    bench_with(name, CONFIG, verdict)
}

/// [`bench`] over another `batten.toml`, whose row runs the same stub.
fn bench_with(name: &str, config: &str, verdict: &str) -> Bench {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    write(&repo, "batten.toml", config);
    write(&repo, "a.txt", "x\n");
    common::init_repo(&repo);

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
/// Exit `1` from the handler is `Outcome::Reported`, which the boundary pushes as
/// advice — and MEASURED, that advice reaches the agent on **stderr**, not on
/// stdout. The distinction matters enough to assert on the real channel rather
/// than the assumed one: an earlier draft of this case asserted over stdout, went
/// red against a mechanism that was working, and reported "the verdict must reach
/// the agent" about a verdict that had.
///
/// The decision channel is stdout, so the two assertions read different streams
/// deliberately: the advice must arrive, and the call's own decision must not
/// move. That pairing is the row's whole acceptance — CLOUD-1326's posture is
/// that a tree move is legitimate work, so this may never deny.
#[test]
fn a_head_moving_git_call_carries_the_staleness_verdict_as_advice() {
    let bench = bench(
        "handler-head-move",
        "mediator failed mediator-build-behind-source",
    );
    let door = bench.door("Bash", "git checkout -");

    assert!(
        bench.spawned(),
        "the row selects this command; door said: {} / {}",
        door.out,
        door.err
    );
    assert!(
        door.err.contains("mediator-build-behind-source"),
        "the verdict must reach the agent on the advisory channel: {} / {}",
        door.out,
        door.err
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

/// A HANDLER READS THE HOST'S OWN BYTES (CLOUD-2224): the payload is spooled as
/// read, and a handler is handed that spool, never a re-serialized document.
/// The payload is written in a shape no serializer emits (spacing, key order),
/// so a re-serialization cannot pass. `#MUTANT handler-bytes-reserialized`.
#[test]
fn a_handler_reads_the_payload_the_host_sent() {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let repo = scratch("handler-host-bytes").join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    write(
        &repo,
        "batten.toml",
        r#"version = 1

[[hook.handler]]
id = "host-bytes"
on = "post-tool"
run = ["./copy-stdin.sh"]
matcher = "^Read$"
timeout_ms = 5000
owner = "CLOUD-2224"
expires = "2027-03-31"
"#,
    );
    common::init_repo(&repo);
    let got = repo.join("got.json");
    let script = repo.join("copy-stdin.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ncat > {:?}\nexit 0\n", got.to_str().unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let payload = "{ \"tool_response\" : {\"file\":{\"content\":\"x\"}} ,\n  \"tool_name\":\"Read\", \"hook_event_name\" :\"PostToolUse\",\"tool_input\":{\"file_path\":\"a\"} }";
    let mut child = common::batten()
        .current_dir(&repo)
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
    let received = std::fs::read_to_string(&got).unwrap_or_else(|_| {
        panic!(
            "the handler ran: {}",
            String::from_utf8_lossy(&outcome.stderr)
        )
    });
    assert_eq!(received, payload, "the handler read the host's bytes");
}

// ---------------------------------------------------------------------------
// `tree_only`: a write outside the repository is not a tree row's subject (CLOUD-2390)
// ---------------------------------------------------------------------------

/// A pre-tool row over every write whose subject is the tree, the shape
/// `filed-row-settled` declares, running the same stub as [`CONFIG`].
const TREE_CONFIG: &str = r#"version = 1

[[hook.handler]]
id = "tree-write-check"
on = "pre-tool"
run = ["./mediator-advise.sh"]
matcher = "^(Edit|Write|MultiEdit|NotebookEdit)$"
tree_only = true
timeout_ms = 5000
owner = "CLOUD-2390"
expires = "2027-03-31"
"#;

/// The host's plan file lies outside the repository, so it reaches the selector
/// as the absolute path the host sent.
#[test]
fn a_write_outside_the_tree_is_not_selected() {
    let bench = bench_with("handler-tree-outside", TREE_CONFIG, "");
    let door = bench.write("/root/.claude/plans/x.md");

    assert!(
        !bench.spawned(),
        "a write outside the tree must not spawn a tree-only row: {} / {}",
        door.out,
        door.err
    );
}

/// The mutation's target: an inverted selector would spare the tree instead.
#[test]
fn a_write_inside_the_tree_is_selected() {
    let bench = bench_with("handler-tree-inside", TREE_CONFIG, "");
    let target = bench.repo.join("a.txt");
    let door = bench.write(target.to_str().unwrap());

    assert!(
        bench.spawned(),
        "a tree write is still this row's subject: {} / {}",
        door.out,
        door.err
    );
}

/// A ROW NAMING THE ENGINE RUNS THE RUNNING IMAGE (CLOUD-1326), never whatever
/// `batten` a `PATH` lookup finds: here that lookup finds a stub, and the stub
/// must not run.
///
/// Fails by: the mediator's name resolved on `PATH` like any other program.
#[test]
fn a_row_naming_the_engine_runs_the_running_image() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch("handler-running-image");
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    write(
        &repo,
        "batten.toml",
        r#"version = 1

[[hook.handler]]
id = "engine-row"
on = "post-tool"
run = ["batten", "--version"]
matcher = "^Read$"
timeout_ms = 5000
owner = "CLOUD-1326"
expires = "2027-03-31"
"#,
    );
    common::init_repo(&repo);
    let stubs = dir.join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let ran = dir.join("stub-ran");
    let stub = stubs.join("batten");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\ntouch {:?}\nexit 0\n", ran.to_str().unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(stubs).chain(std::env::split_paths(&common::ambient_path())),
    )
    .unwrap();
    let mut command = common::batten();
    command.env("PATH", path);
    let outcome = common::stdin_run(
        &mut command,
        &repo,
        &["adjudicate", "--harness", "claude-code"],
        r#"{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"a"}}"#,
    );
    assert!(
        !ran.exists(),
        "the stub on PATH ran in place of the running image: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(
        outcome.status.success(),
        "the running image answered the row: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
}
