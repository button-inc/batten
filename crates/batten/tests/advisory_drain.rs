//! The advisory drain over the compiled binary (CLOUD-79).
//!
//! The unit tests in `src/drain.rs` pin the state machine against an explicit
//! clock. These pin the half a unit test structurally cannot reach: that the
//! drain is wired to the **post-tool event of the `hook` surface**, that its
//! pacing comes from `batten.toml` rather than from a constant, and that every
//! path through it exits `0`.
//!
//! A separate target rather than more of `tests/cli.rs`: this needs the same
//! store-and-home fixture the ledger tests use, and `cli.rs` is four thousand
//! lines with several sessions editing it. The helpers below are local for the
//! same reason the module doc of `tests/common/mod.rs` gives for existing at all
//! — they are about *what is written*, not *how*.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{Fixture, batten, scratch};

/// A `PostToolUse` payload in Claude Code's shape, for `session`.
fn post_tool(session: &str) -> String {
    format!(
        r#"{{"hook_event_name":"PostToolUse","session_id":"{session}","cwd":"/w","tool_name":"Bash","tool_input":{{"command":"echo hi"}}}}"#
    )
}

/// Run `batten hook --harness claude-code` in `dir` with `payload` on stdin, in a
/// scrubbed environment pointing at the fixture's own state home.
fn hook(dir: &Path, home: &Path, payload: &str) -> Output {
    hook_at(dir, home, payload, &[])
}

/// [`hook`] with extra arguments ahead of the verb — the §3 ladder flags, which
/// are read from raw argument order and so cannot be appended.
fn hook_at(dir: &Path, home: &Path, payload: &str, leading: &[&str]) -> Output {
    let mut command = batten();
    command
        .args(leading)
        .args(["hook", "--harness", "claude-code"])
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten hook");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(payload.as_bytes())
        .expect("write the payload");
    child.wait_with_output().expect("run batten hook")
}

/// Run any `batten` subcommand against the fixture's state home.
fn state_cmd(dir: &Path, home: &Path, args: &[&str]) -> Output {
    batten()
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten")
}

/// A repository with one recorded finding whose file is **dirty**, plus an
/// isolated state home.
///
/// The dirty working tree is load-bearing rather than incidental: the finding is
/// code-anchored, so it surfaces only while its file is inside the changed
/// scope. A fixture with a clean tree would assert the filter, not the drain —
/// which `filters_a_code_finding_whose_file_is_not_in_the_changed_scope` does
/// deliberately, and this one must not do by accident.
fn drained_fixture(name: &str, drain_table: &str) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let config = format!(
        "version = 1\n\n\
         [[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         severity = \"deny\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         no_fix_reason = \"delete the marker once the work behind it is done\"\n\
         {drain_table}"
    );
    let repo = Fixture::at(root.join("repo"))
        .config(&config)
        .file("src/a.rs", "fn main() {}\n// TODO fix me\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let recorded = state_cmd(&repo, &home, &["state", "record"]);
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "state record failed: {}",
        String::from_utf8_lossy(&recorded.stderr)
    );

    // Put the finding's file into the changed scope without re-recording, so the
    // stored instance still points at the path the filter is asked about.
    common::write(
        &repo,
        "src/a.rs",
        "fn main() {}\n// TODO fix me\n// edited\n",
    );
    (repo, home)
}

/// The drain payload on stderr, with Batten's own `batten: ` notes removed —
/// those are messages *about* Batten and travel on a different channel by
/// construction (`output::message` vs `output::verdict`).
fn payload(output: &Output) -> Vec<String> {
    common::stderr(output)
        .lines()
        .filter(|line| !line.starts_with("batten: "))
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn a_post_tool_event_drains_the_store_as_pointer_lines() {
    // The wiring, end to end: findings recorded by one verb are surfaced by the
    // hook surface at the post-tool event, and what comes back is a pointer —
    // a fingerprint, a rule id, a `path:line` and a count (rule 4).
    let (repo, home) = drained_fixture("drain-emits", "");

    let first = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(first.status.code(), Some(0), "the drain never denies");
    let lines = payload(&first);
    assert_eq!(lines.len(), 1, "one finding, one line: {lines:?}");
    let fields: Vec<&str> = lines[0].split(' ').collect();
    assert_eq!(fields.len(), 4, "fingerprint, rule, path:line, count");
    assert_eq!(fields[0].len(), 64, "a fingerprint is 64 hex characters");
    assert_eq!(fields[1], "no-todo");
    assert_eq!(fields[2], "src/a.rs:2");
    assert_eq!(fields[3], "1");
    assert!(
        !lines[0].contains("TODO"),
        "a pointer, never the matched content"
    );

    // Nothing goes to stdout: on this host stdout is the decision channel, and a
    // stray byte there is a document the host would try to read as one.
    assert!(common::stdout(&first).is_empty());
}

#[test]
fn a_pre_tool_event_never_drains() {
    // The drain is keyed to the event, not to the surface. Pre-tool is the one
    // event that adjudicates, and mixing an advisory payload into it would put
    // findings on the path that can deny.
    let (repo, home) = drained_fixture("drain-pre-tool", "");
    let output = hook(
        &repo,
        &home,
        r#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/w","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty(), "no advisory payload here");
}

#[test]
fn a_batch_of_wakes_drains_once_and_the_interval_is_config() {
    // Acceptance (a) and (c) together, over the binary and with no fake clock:
    // one fixture coalesces and one does not, and the ONLY difference between
    // them is `interval_ms` in `batten.toml`. A hard-coded window could not
    // produce both columns.
    let (coalescing, home_c) =
        drained_fixture("drain-window-wide", "\n[drain]\ninterval_ms = 600000\n");
    let mut emitted = 0;
    for _ in 0..4 {
        if !payload(&hook(&coalescing, &home_c, &post_tool("batch"))).is_empty() {
            emitted += 1;
        }
    }
    assert_eq!(
        emitted, 1,
        "four verifier results inside one window are one drain"
    );

    let (open, home_o) = drained_fixture("drain-window-zero", "\n[drain]\ninterval_ms = 0\n");
    // A zero window drains every wake. The second and later ones are silent for
    // a DIFFERENT reason — the `resultId` short-circuit — so this asserts the
    // window is open by watching the give-up counter never reach a state a
    // coalescing window would have prevented: the first wake speaks, and a
    // change to the store is picked up on the very next one.
    assert_eq!(payload(&hook(&open, &home_o, &post_tool("batch"))).len(), 1);
    common::write(&open, "src/b.rs", "fn other() {}\n// TODO also fix me\n");
    let recorded = state_cmd(&open, &home_o, &["state", "record"]);
    assert_eq!(recorded.status.code(), Some(0));
    assert_eq!(
        payload(&hook(&open, &home_o, &post_tool("batch"))).len(),
        2,
        "with no window, the next wake reports the new finding immediately"
    );
}

#[test]
fn an_unchanged_finding_set_is_not_repeated() {
    // Acceptance (e) over the binary: the second drain finds exactly what the
    // first did and says nothing, because repeating an identical payload spends
    // the agent's context to convey no information.
    let (repo, home) = drained_fixture("drain-result-id", "\n[drain]\ninterval_ms = 0\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("s1"))).len(), 1);
    assert!(
        payload(&hook(&repo, &home, &post_tool("s1"))).is_empty(),
        "the same set again is repetition, not news"
    );
}

#[test]
fn two_sessions_hold_independent_windows() {
    // The window is per session, so a second session's first wake is a first
    // wake — it has seen nothing, and must not inherit another session's silence.
    let (repo, home) = drained_fixture("drain-per-session", "\n[drain]\ninterval_ms = 600000\n");
    assert_eq!(payload(&hook(&repo, &home, &post_tool("alpha"))).len(), 1);
    assert!(
        payload(&hook(&repo, &home, &post_tool("alpha"))).is_empty(),
        "alpha is inside its own window"
    );
    assert_eq!(
        payload(&hook(&repo, &home, &post_tool("beta"))).len(),
        1,
        "beta has its own"
    );
}

#[test]
fn filters_a_code_finding_whose_file_is_not_in_the_changed_scope() {
    // The changed-scope filter, over the binary: same store, same event, clean
    // tree. The finding is real and stays in the store — it is simply not about
    // anything in front of the agent right now.
    let (repo, home) = drained_fixture("drain-scope-filter", "");
    common::git_in(&repo, &["checkout", "--", "src/a.rs"]);
    let output = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(
        payload(&output).is_empty(),
        "nothing to emit prints nothing"
    );

    // And it is recorded as withheld BY THE ENGINE — visible in the store
    // immediately, with no later verb needed to fold it, because the rate this
    // feeds reads records rather than shards.
    let shown = state_cmd(&repo, &home, &["state", "list", "-J"]);
    let document: serde_json::Value =
        serde_json::from_slice(&shown.stdout).expect("state list -J is JSON");
    assert_eq!(
        document[0]["presentation"]["not-shown"], "drain-suppressed",
        "the suppression is journalled, not merely skipped: {document}"
    );
}

#[test]
fn a_session_less_payload_degrades_without_draining_or_failing() {
    // CLOUD-43's contract: a missing session degrades to per-invocation
    // handling. Per-invocation is exactly the once-per-verifier behaviour the
    // window exists to prevent, so the honest degradation is to hold the wake —
    // loudly on the verbose rung, never as an error and never as a deny.
    const SESSIONLESS: &str = r#"{"hook_event_name":"PostToolUse","cwd":"/w","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#;

    let (repo, home) = drained_fixture("drain-no-session", "");
    let output = hook(&repo, &home, SESSIONLESS);
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
    assert!(
        !common::stderr(&output).contains("no session"),
        "and a default run is not told about it: on a host that never sends a \
         session this is the ordinary state, not news"
    );

    let loud = hook_at(&repo, &home, SESSIONLESS, &["-v"]);
    assert_eq!(loud.status.code(), Some(0));
    assert!(
        common::stderr(&loud).contains("no session"),
        "asking for detail produces it: {}",
        common::stderr(&loud)
    );
}

#[test]
fn a_repository_with_no_store_drains_nothing_and_still_allows() {
    // `batten hook` is registered once and then mediates every call wherever the
    // agent happens to be. A repository that has never recorded anything is the
    // ordinary first-run state, not an error — and must not become the reason a
    // session cannot proceed.
    let repo = Fixture::new("drain-unbound")
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::new("drain-unbound-home").build();
    let output = hook(&repo, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
}

#[test]
fn a_directory_that_is_not_a_batten_repository_drains_nothing() {
    // The cheapest refusal, and the one that runs most often: no committed
    // authority means there is nothing to pace against and nothing to read.
    let dir = common::scratch_outside_tree("batten-drain", "no-authority");
    let home = Fixture::at(dir.join("home")).build();
    let output = hook(&dir, &home, &post_tool("s1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(payload(&output).is_empty());
}
