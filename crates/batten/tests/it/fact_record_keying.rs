//! An agent-sourced record is filed under the subject its `receipt` row's `key`
//! names (CLOUD-859), ported from `tests/fact-record-keying.bats`.
//!
//! # Why this tier and not a unit test
//!
//! Stated because the temptation is real and `sourced_path` is a pure function two
//! lines long. A unit test over it asserts that a filename contains a subject
//! somebody passed in; it cannot show that the BOUNDARY resolves that subject and
//! hands it to both halves. The defect was never in the filename — it was that
//! nothing computed a subject at all. So every case here goes through the two real
//! hook calls a session makes: a `PostToolUse` envelope carrying the declared
//! command, which is what mints the record, and a `PreToolUse` `gh pr ready`,
//! which is what reads it. Nothing writes a receipt by hand and nothing inspects a
//! path to decide a case.
//!
//! # The anti-vacuity twin is the point of the suite
//!
//! Not a courtesy: head-keying everything would satisfy the first case and break
//! `claim` repo-wide, because a claim attests to a decision about an ISSUE and
//! every commit on the branch continues to serve it. CLOUD-516's incident read the
//! other way round. "a branch-keyed record survives a new commit" is the case that
//! has to stay green.
//!
//! # What the port changed, and what it deliberately did not
//!
//! One assertion moved. The bats case pinned the refusal's inline remedy
//! (`gh pr view --json reviewThreads`), which CLOUD-1286 took off the hot path:
//! ~300 refusals a session paid for that clause every time one fired. It now
//! asserts the declared CLASS and its pointers, which is the whole of what the
//! emitted line carries, and the remedy is one hop away through
//! `batten policy explain`. Every other case is the same predicate over the same
//! two envelopes.

// THE RETIREMENT LEDGER ARM, one per deleted path. `ported:` rather than
// `carried:` because the SUBJECT survives: `crates/batten/src/facts.rs` is engine
// source the campaign never retires, so this is the cases moving off bash while
// the thing under test stays exactly where it was.
//
// ported: tests/fact-record-keying.bats crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, run_with_stdin, scratch, stdout, write};

/// A CONSTANT string, which is what the channel requires: `Declared.command` is
/// compared byte-for-byte against what the agent ran, and that comparison is the
/// forgery control. The engine never executes it — it compares the command and
/// counts the result — so these cases can drive shapes a live `gh` could not be
/// made to produce on demand.
const COMMAND: &str =
    "gh pr view --json reviewThreads --jq '[.reviewThreads[] | select(.isResolved | not)]'";

/// Build the fixture repository with ONE `[[fact]]` and one `receipt` row keyed as
/// asked.
///
/// The keying is the only thing that varies between cases, which is what makes a
/// difference in verdict attributable to it.
fn fixture(name: &str, key: &str, max_age: Option<u64>) -> PathBuf {
    let dir = scratch(name);
    let aged = max_age.map_or_else(String::new, |seconds| format!("max_age = {seconds}\n"));
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n[[fact]]\nname = \"keyed\"\nreturns = \"json-array\"\n\
             command = {command}\n\n[[rule]]\nid = \"ready-needs-the-fact\"\n\
             kind = \"receipt\"\nscope = \"mediated_call\"\nseverity = \"deny\"\n\
             pattern = \"gh pr ready\"\nchecks = [\"keyed\"]\nkey = \"{key}\"\n{aged}\
             reason = \"run the declared command\"\n",
            command = serde_json::to_string(COMMAND).expect("a command is encodable"),
        ),
    );
    // `git_in` blanks global and system config for CLOUD-282's reason: a
    // contributor's own git settings must not be able to change a verdict here.
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    commit(&dir, "the first commit");
    dir
}

fn commit(dir: &Path, subject: &str) {
    git_in(dir, &["commit", "-q", "--allow-empty", "-m", subject]);
}

/// Mint the record the way a session does: a `PostToolUse` envelope carrying the
/// declared command and the buffer the host handed back.
fn record(dir: &Path, stdout_bytes: &str) -> Output {
    let envelope = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-keying",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {"command": COMMAND},
        "tool_response": {"stdout": stdout_bytes, "stderr": ""},
    });
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &envelope.to_string(),
    )
}

/// Read it: the call the receipt row judges.
fn ready(dir: &Path) -> Output {
    let envelope = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr ready 999"},
    });
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "claude-code"],
        &envelope.to_string(),
    )
}

/// BOTH HELPERS ASSERT THE EXIT STATUS, for `run-shape`'s measured reason:
/// `batten hook` prints nothing on an allow and exits 0 either way, so a substring
/// check over an empty string is true — including the empty output of a binary
/// that died before it judged anything.
fn denied(output: &Output) -> String {
    let text = stdout(output);
    assert_eq!(output.status.code(), Some(0), "the hook itself ran: {text}");
    assert!(
        text.contains("\"permissionDecision\":\"deny\""),
        "expected a deny: {text}"
    );
    text
}

fn allowed(output: &Output) {
    let text = stdout(output);
    assert_eq!(output.status.code(), Some(0), "the hook itself ran: {text}");
    assert!(!text.contains("\"deny\""), "expected an allow: {text}");
}

/// The record filenames in the store, sorted.
fn records(dir: &Path) -> Vec<String> {
    let store = dir.join(".git/batten-receipts");
    let Ok(entries) = std::fs::read_dir(&store) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("fact."))
        .collect();
    names.sort();
    names
}

/// Backdate every record in the store.
///
/// Aged rather than waited on: the property under test is that the bound is READ,
/// and a case that slept an hour would assert the same thing and cost an hour.
fn age_records(dir: &Path, seconds: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
    for name in records(dir) {
        let path = dir.join(".git/batten-receipts").join(name);
        let file = std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open a record to backdate it");
        file.set_modified(when).expect("backdate the record");
    }
}

// ported: "a head-keyed record cleared on one commit does not satisfy the check on the next" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs the remedy assertion moved from the inline `gh pr view --json reviewThreads` clause to the declared class and its pointers, because CLOUD-1286 took the `Fix:` half off the hot path — the predicate is unchanged and the remedy is one hop away through `batten policy explain`
#[test]
fn a_head_keyed_record_cleared_on_one_commit_does_not_satisfy_the_next() {
    // THE MEASURED DEFECT. Before CLOUD-859 the record filed under the fact's
    // name, so the second `ready` here was ALLOWED — an agent ran the command, got
    // a clear answer, pushed a fix nobody had reviewed, and readied it.
    let dir = fixture("fact-keying-head", "head", None);
    assert_eq!(record(&dir, "[]").status.code(), Some(0));
    allowed(&ready(&dir));

    commit(&dir, "a fix nobody has looked at");
    let text = denied(&ready(&dir));
    // The CLASS and its pointers, which is the whole of what the hot path emits
    // since CLOUD-1286: the declared token, the keying, and the row it belongs to.
    // The remedy is unchanged and still the declared command — it is one hop away
    // through `batten policy explain` rather than inline.
    assert!(text.contains("receipt read missing"), "{text}");
    assert!(text.contains("ready-needs-the-fact"), "{text}");
}

// ported: "ANTI-VACUITY: a branch-keyed record still satisfies the check after a new commit" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs
#[test]
fn anti_vacuity_a_branch_keyed_record_survives_a_new_commit() {
    // The case that has to stay green. `claim-needs-receipt` is keyed by branch
    // precisely because a claim attests to a decision about an issue that every
    // commit on the branch continues to serve. A fix that head-keyed every record
    // would pass the case above and make `claim` demand a re-claim per commit,
    // which is the false-positive rate that gets a guard bypassed.
    let dir = fixture("fact-keying-branch", "branch", None);
    assert_eq!(record(&dir, "[]").status.code(), Some(0));
    commit(&dir, "one more commit on the same claim");
    allowed(&ready(&dir));
}

// ported: "a branch-keyed record does not follow the checkout onto another branch" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs
#[test]
fn a_branch_keyed_record_does_not_follow_the_checkout_onto_another_branch() {
    // The twin's own twin: `branch` must be a real subject rather than a way of
    // spelling "never expires". A record minted on one branch is absent on the
    // next, which is the same could-not-look the missing-record arm carries.
    let dir = fixture("fact-keying-checkout", "branch", None);
    assert_eq!(record(&dir, "[]").status.code(), Some(0));
    allowed(&ready(&dir));

    git_in(&dir, &["checkout", "-q", "-b", "claude/somewhere-else"]);
    denied(&ready(&dir));
}

// ported: "head and branch keyings file the record under different names" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs
#[test]
fn head_and_branch_keyings_file_the_record_under_different_names() {
    // The cheapest statement of "the column is load-bearing": two fixtures
    // differing only in `key` put the record in two different places. Read off the
    // STORE rather than asserted about a path, so this fails if the boundary stops
    // resolving a subject even though `sourced_path` still accepts one.
    let head_dir = fixture("fact-keying-names-head", "head", None);
    assert_eq!(record(&head_dir, "[]").status.code(), Some(0));
    let head_named = records(&head_dir);
    assert!(!head_named.is_empty(), "a head-keyed record was filed");

    let branch_dir = fixture("fact-keying-names-branch", "branch", None);
    assert_eq!(record(&branch_dir, "[]").status.code(), Some(0));
    let branch_named = records(&branch_dir);
    assert!(!branch_named.is_empty(), "a branch-keyed record was filed");

    assert_ne!(head_named, branch_named);
    // The branch-keyed one names the branch; the head-keyed one does not.
    assert!(
        branch_named.iter().any(|name| name.contains("main")),
        "{branch_named:?}"
    );
    assert!(
        !head_named.iter().any(|name| name.contains("main")),
        "{head_named:?}"
    );
}

// ported: "max_age bounds an agent-sourced record, and an unaged one still passes" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs
#[test]
fn max_age_bounds_an_agent_sourced_record_and_an_unaged_one_still_passes() {
    // CLOUD-988's column reached `receipt_facts` and the agent-sourced loop never
    // read it, so neither the head nor the clock bounded the evidence. Both halves
    // here, because a bound that refused everything would pass the first assertion
    // alone.
    let dir = fixture("fact-keying-age", "head", Some(3600));
    assert_eq!(record(&dir, "[]").status.code(), Some(0));
    allowed(&ready(&dir));

    age_records(&dir, 7200);
    denied(&ready(&dir));
}

// ported: "a named keying over an agent-sourced fact is refused at LOAD, not at decision" crates/batten/tests/it/fact_record_keying.rs subject:crates/batten/src/facts.rs
#[test]
fn a_named_keying_over_an_agent_sourced_fact_is_refused_at_load_not_at_decision() {
    // The two halves run on different envelopes: the record is written on the
    // post-tool event of the fact's own command, and a `named` subject is
    // projected out of the call the row selects. So a `named` agent-sourced check
    // would deny forever and running the command it names would not satisfy it — a
    // gate nobody can clear, which is the failure the row exists to end. Refused
    // where it can still be fixed rather than shipped as a column that files
    // nothing.
    let dir = fixture("fact-keying-named", "head", None);
    let path = dir.join("batten.toml");
    let text = std::fs::read_to_string(&path).expect("read the fixture config");
    std::fs::write(
        &path,
        text.replace("key = \"head\"", "key = \"named\"\nkey_from = \"input-id\""),
    )
    .expect("write the patched config");

    let output = ready(&dir);
    // Exit 1 and a usage error, never exit 2: this is config the operator wrote
    // being refused, not a verdict about the call.
    assert_eq!(output.status.code(), Some(1), "{}", common::stderr(&output));
    let reason = common::stderr(&output);
    assert!(reason.contains("key = \"named\""), "{reason}");
    assert!(reason.contains("keyed"), "{reason}");
}
