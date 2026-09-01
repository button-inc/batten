//! `connector-allow-guard` driven THROUGH the door, over the compiled binary.
//!
//! **The second tier, and the tier that finds this class.**
//! `tests/connector-allow-guard.bats` runs the script directly and reads what it
//! printed; that is the bash equivalent of a Rego module's `with input as`, and
//! `.claude/rules/policy-modules.md` names its failure exactly — it fabricates
//! the shape the ENGINE may be unable to consume, so a guard can pass its own
//! suite green while the door discards every verdict it produces.
//!
//! **WHICH IS WHAT HAPPENED.** `connector-allow-guard` retired from a direct
//! `PreToolUse` registration into a `[[hook.handler]]` row (CLOUD-312 row 5) and
//! kept writing `hookSpecificOutput` on stdout. Behind the door that is
//! `Violation::ImpersonatedHost`: reported on stderr, never forwarded. Measured
//! 2026-08-26 on this repository's live wiring — the guard's deny document was
//! dropped and the refusal the host received came from an unrelated engine row
//! that happens to cover the same tool. Every deny in the committed permission
//! table is covered that way, which is precisely why nothing went red.
//!
//! **EVERY CASE RUNS AGAINST A FIXTURE REPOSITORY CARRYING ONE ROW**: the
//! handler and nothing else. That isolation is the whole design. Driving the
//! real `batten.toml` would let another rule's verdict stand in for this one —
//! the exact substitution that hid the defect for the life of the migration.
//!
//! **Rust rather than a `.bats` suite** (CLOUD-843): `shell-retirement` refuses
//! a new one, correctly. The fixture and the binary are the same either way.

//! **UNIX ONLY, and the gate is load-bearing rather than tidy.** Every case here
//! dispatches a `#!/usr/bin/env bash` program as a `[[hook.handler]]` row. On a
//! Windows runner the spawn ladder resolves the interpreter the shebang names
//! and cannot start it, so the door reports a could-not-run and forwards
//! nothing. The cases that assert an ABSENCE — a dropped verdict, an engine deny
//! standing alone — therefore passed there for the wrong reason, while the two
//! that assert a handler's deny and grant REACHING the host failed outright.
//! Half a suite green over a mechanism that never ran is the vacuous-pass class
//! this file was written to expose, so it is gated rather than split.
//!
//! `board_record.rs` gates its whole suite on the same rung of the same ladder,
//! and `tests/connector-allow-guard.bats` — the tier this one is the second half
//! of — never ran on Windows either, so nothing is narrowed that was covered.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{at_root, git_in, scratch, stderr, stdout, write};

/// ONE ROW. No `[[rule]]` at all, so nothing in the engine can produce a verdict
/// of its own and be mistaken for the handler's.
const CONFIG: &str = r#"version = 1

[[hook.handler]]
id = "connector-allow-guard"
on = "pre-tool"
run = ["mise-tasks/connector-allow-guard.sh"]
matcher = "^mcp__"
timeout_ms = 5000
preapproves = true
owner = "CLOUD-312"
expires = "2027-02-28"
"#;

/// THE DENIED VERB IS ONE NO ENGINE ROW COVERS. `send_later` would have been the
/// natural fixture and is the wrong one: this repository's own
/// `no-scheduled-self-wakeup` refuses it, so a case built on it passes whether
/// the handler spoke or not. That substitution is the defect, not a detail.
const SETTINGS: &str = r#"{"permissions":{
  "allow":["mcp__Claude_Code_Remote__create_session"],
  "deny":["mcp__Claude_Code_Remote__archive_session"]
}}
"#;

const MCP_CONFIG: &str = r#"{"mcpServers":{
  "bbbbbbbb-5555-6666-7777-888888888888":{"url":"https://api.anthropic.com/v1/code/mcp/proxy?mcp_url=https%3A%2F%2Fapi.anthropic.com%2Fv1%2Fcode%2Fmcp%2Fmeta"}
}}
"#;

const RESOLVABLE: &str = "mcp__bbbbbbbb-5555-6666-7777-888888888888";

struct Bench {
    repo: PathBuf,
    settings: PathBuf,
    mcp_config: PathBuf,
}

/// What the door said to the host, and what it said about the handler.
struct Door {
    out: String,
    err: String,
}

impl Bench {
    /// Hand one mediated call to the engine, keeping the two streams apart: the
    /// verdict is on stdout, and the door reports a contract violation on
    /// stderr. Merging them is how a dropped verdict reads as a delivered one.
    fn door(&self, tool: &str) -> Door {
        use std::io::Write as _;

        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {},
        })
        .to_string();

        let mut child = common::batten()
            .current_dir(&self.repo)
            .args(["hook", "--harness", "claude-code"])
            .env("BATTEN_MCP_SETTINGS", &self.settings)
            .env("BATTEN_MCP_CONFIG", &self.mcp_config)
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
            err: stderr(&outcome),
        }
    }
}

fn bench(name: &str) -> Bench {
    let dir = scratch(name);
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join("mise-tasks")).expect("the fixture repo");
    // Copied from the suite's own tree, so `mise run mutant` reaches this tier
    // too: under `mutant` that tree is the mutated one.
    for task in ["connector-allow-guard.sh", "connector-allow-resolve.sh"] {
        let to = repo.join("mise-tasks").join(task);
        std::fs::copy(at_root("mise-tasks").join(task), &to)
            .expect("the guard is copied from this tree");
        make_executable(&to);
    }
    write(&repo, "batten.toml", CONFIG);
    git_in(&repo, &["init", "-q", "-b", "main", "."]);

    let settings = dir.join("settings.json");
    std::fs::write(&settings, SETTINGS).expect("the committed permission table");
    let mcp_config = dir.join("mcp-config.json");
    std::fs::write(&mcp_config, MCP_CONFIG).expect("the session's injected config");

    Bench {
        repo,
        settings,
        mcp_config,
    }
}

// No `#[cfg(unix)]` pair here: the module gate above already decides the target,
// so a `#[cfg(not(unix))]` twin would be a definition nothing can reach.
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mut mode = std::fs::metadata(path)
        .expect("the copy exists")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(path, mode).expect("the copy is runnable");
}

/// Replace the copied guard with a stub that answers on the handler contract.
///
/// **The door's own channels are asserted through this rather than through the
/// committed guard**, and that separation is the point rather than convenience:
/// the guard cannot use those channels today (see
/// `the_committed_guard_writes_a_host_document_so_its_verdict_is_dropped`), so a
/// case driving it would assert the door's capability and fail for the guard's
/// reason. Stubbed, each case fails only when the thing it names breaks.
fn stub_guard(bench: &Bench, body: &str) {
    write(
        &bench.repo,
        "mise-tasks/connector-allow-guard.sh",
        &format!("#!/usr/bin/env bash\n{body}\n"),
    );
    make_executable(&bench.repo.join("mise-tasks/connector-allow-guard.sh"));
}

#[test]
fn the_committed_guard_writes_a_host_document_so_its_verdict_is_dropped() {
    // THE MEASURED DEFECT, asserted rather than described (2026-08-26, still true).
    // `mise-tasks/connector-allow-guard.sh` is dispatched as a handler and emits
    // `hookSpecificOutput` on stdout with exit 0. `impersonates_host` reads that
    // shape BEFORE the exit code, so the outcome is `Broke(ImpersonatedHost)` —
    // and every `Broke` variant ALLOWS. The verdict never reaches the host.
    //
    // Stated over the violation LINE rather than over the missing verdict,
    // because a missing verdict is also what a handler that never ran produces,
    // and this suite's whole subject is telling those two apart.
    //
    // WHY IT IS ASSERTED RATHER THAN FIXED: the repair is one `case` in a
    // governed shell file, which `shell-retirement` refuses unless the file is
    // retired — and it cannot be, because it reads `/tmp/mcp-config-cse_*.json`
    // per call, which no Rego module may do and no Rust port may carry into the
    // core (rule 1). So this case is the finding's durable home, and it FLIPS the
    // day the guard is repaired: that is what makes it evidence rather than a
    // note.
    // THE DIAGNOSTIC MOVED STREAMS, AND THAT IS NOT THIS SUITE'S SUBJECT
    // (CLOUD-1131). It used to be asserted on stderr, which read as a statement
    // about audience and was not one: `emit_advisory` puts advice on stdout when
    // the event's channel is reachable and falls back to the operator's stream
    // only when it is NOT, and `PreToolUse` was unreachable for its whole life on
    // an unprobed assumption. Now that it is probed and open, this notice lands
    // where the same notice at `PostToolBatch` always did. So the assertion reads
    // BOTH streams: what this case is evidence for is that the guard still
    // impersonates the host, never which pipe carries the complaint.
    let bench = bench("cad-measured-defect");
    let answer = bench.door(&format!("{RESOLVABLE}__archive_session"));
    let reported = format!("{}{}", answer.out, answer.err);
    assert!(
        reported.contains("hook.handler connector-allow-guard: wrote a host decision document"),
        "the committed guard still impersonates the host; if this now fails, the \
         guard was repaired and this suite's other cases should be restored to \
         asserting the real guard: {reported}"
    );
    // And nothing it wrote became a verdict — neither arm reaches the host.
    assert!(!answer.out.contains(r#""deny""#), "{}", answer.out);
    assert!(!answer.out.contains(r#""allow""#), "{}", answer.out);
    // Non-negotiable 4 holds even on the dropped path: the live key never travels.
    assert!(!answer.out.contains("bbbbbbbb"), "{}", answer.err);
}

#[test]
fn a_handler_deny_reaches_the_host_as_the_engines_own_refusal() {
    // Exit 2 with the reason on stderr is the contract, and this is the door
    // rendering it: attributed to the handler, written BY the engine. The
    // difference between a verdict that travelled and one a guard printed.
    let bench = bench("cad-deny");
    stub_guard(&bench, "printf 'archive_session is denied\\n' >&2\nexit 2");

    let answer = bench.door(&format!("{RESOLVABLE}__archive_session"));
    assert!(
        answer.out.contains(r#""permissionDecision":"deny""#),
        "{}",
        answer.out
    );
    assert!(
        answer.out.contains("hook.handler.connector-allow-guard"),
        "{}",
        answer.out
    );
    assert!(answer.out.contains("archive_session"), "{}", answer.out);
}

#[test]
fn a_handler_grant_reaches_the_host_as_a_preapproval_not_a_dropped_note() {
    // THE CHANNEL CLOUD-191 EXISTS FOR. Exit 0 with text on stdout is `Advise`,
    // and `preapproves` on the row is what turns those same bytes into a grant
    // the host honours — without it the reason lands on the engine's own stderr,
    // because `AdvisoryReach` for this host lists `PostToolBatch`, `SessionStart`
    // and `Stop`, not the pre-tool event, and the approval prompt comes back.
    //
    // Asserted over the DOCUMENT rather than over "not denied", because a
    // not-denied assertion is satisfied by a handler that never ran at all.
    let bench = bench("cad-allow");
    stub_guard(
        &bench,
        "printf 'the committed table already allows create_session on Claude_Code_Remote\\n'\nexit 0",
    );

    let answer = bench.door(&format!("{RESOLVABLE}__create_session"));
    assert!(
        answer.out.contains(r#""permissionDecision":"allow""#),
        "{}",
        answer.out
    );
    assert!(
        answer
            .out
            .contains("already allows create_session on Claude_Code_Remote"),
        "{}",
        answer.out
    );
    assert!(
        answer.out.contains("hook.handler.connector-allow-guard"),
        "{}",
        answer.out
    );
    // The grant is not ALSO advice: said twice, one copy would land on a channel
    // that delivers nothing here and the reader would see the same sentence from
    // two places.
    assert!(answer.err.is_empty(), "{}", answer.err);
}

#[test]
fn an_engine_deny_beats_a_handler_grant_on_the_same_call() {
    // The safety property of the whole channel, and the only case that can fail
    // if the composition is wrong. A grant may upgrade an allow and nothing else
    // — so a handler that would pre-approve a call the engine refuses must lose,
    // or a dispatched program could spend a verdict a rule reached.
    //
    // THE STUB IS WHAT KEEPS THIS FROM PASSING VACUOUSLY. Driven against the
    // committed guard it asserts nothing: that guard's grant is dropped before
    // composition is reached, so the engine's deny would stand unopposed and the
    // case would be green over a composition that had never run (CLOUD-418).
    let bench = bench("cad-engine-wins");
    stub_guard(
        &bench,
        "printf 'the committed table already allows create_session\\n'\nexit 0",
    );
    let config = format!(
        "{CONFIG}\n[[rule]]\nid = \"refuse-the-granted-tool\"\nkind = \"shape\"\n\
         scope = \"mediated_call\"\nseverity = \"deny\"\ntool = \"create_session\"\n\
         reason = \"the engine refuses this regardless of any grant\"\n"
    );
    write(&bench.repo, "batten.toml", &config);

    let answer = bench.door(&format!("{RESOLVABLE}__create_session"));
    assert!(
        answer.out.contains(r#""permissionDecision":"deny""#),
        "{}",
        answer.out
    );
    assert!(
        answer.out.contains("refuse-the-granted-tool"),
        "{}",
        answer.out
    );
    // And the grant is dropped rather than reported beside the refusal: printing
    // "a handler wanted to allow this" next to a deny reads as a disagreement
    // the reader has to arbitrate when the arbitration has already happened.
    assert!(!answer.out.contains(r#""allow""#), "{}", answer.out);
    assert!(!answer.out.contains("already allows"), "{}", answer.out);
}

#[test]
fn the_impersonation_detector_is_live_behind_this_row() {
    // THE POSITIVE CONTROL, and this suite is worth little without it: every
    // other case asserts the ABSENCE of a violation line, and absence is also
    // what a handler that never ran produces. So one case makes the handler
    // write the host document on purpose and requires the door to say so.
    //
    // `interpret`'s own unit case pins the same predicate. It could not catch
    // the defect this suite exists for, because what was wrong was a committed
    // handler ROW rather than the interpreter.
    let bench = bench("cad-impersonation");
    stub_guard(
        &bench,
        "printf '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"x\"}}\\n'",
    );

    let answer = bench.door(&format!("{RESOLVABLE}__archive_session"));
    // Both streams, for the reason the measured-defect case above states: the
    // stream is `emit_advisory`'s reachability fallback, not an audience.
    let reported = format!("{}{}", answer.out, answer.err);
    assert!(
        reported.contains("hook.handler connector-allow-guard: wrote a host decision document"),
        "{reported}"
    );
    // And the refusal it tried to write did NOT become one. Asserted over the
    // VERDICT FIELD rather than the bare token, because the diagnostic now
    // travels on stdout and quotes the shape it refused — so a substring test for
    // `"deny"` would match the complaint about the document and pass whether or
    // not the document became a verdict, which is the whole question.
    assert!(
        !answer.out.contains(r#""permissionDecision":"deny""#),
        "{}",
        answer.out
    );
}

#[test]
fn a_name_the_guard_cannot_resolve_leaves_the_call_undecided() {
    // The load-bearing negative: a guard that refused everything would satisfy
    // the deny case above and be useless (CLOUD-418).
    let bench = bench("cad-unresolvable");
    let answer = bench.door("mcp__cccccccc-9999-0000-1111-222222222222__archive_session");
    assert!(!answer.out.contains(r#""deny""#), "{}", answer.out);
    assert!(
        !answer.err.contains("hook.handler connector-allow-guard:"),
        "{}",
        answer.err
    );
}

#[test]
fn a_non_mcp_tool_never_reaches_the_handler_at_all() {
    // `matcher` is what keeps a narrowed handler from costing a process on every
    // call it is silent on, and a matcher selecting everything is expressible by
    // accident. Asserted through the door because `selects_tool` is the
    // engine's, not the script's.
    let bench = bench("cad-non-mcp");
    let answer = bench.door("Bash");
    assert!(!answer.out.contains(r#""deny""#), "{}", answer.out);
    assert!(answer.err.is_empty(), "{}", answer.err);
}
