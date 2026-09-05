//! The Todo promotion is an automatic boundary verdict (CLOUD-1100).
//!
//! CLOUD-375's slot, and the reason it stayed empty for so long is worth stating
//! before the cases: the verdict was *computable* the whole time and *unavailable*
//! at the moment of the write. `graph-check`'s `todo-not-ready` decides the same
//! question over a payload somebody remembered to pipe, which is a sweep rather
//! than a gate, and a bulk promotion put two unready rows in the ready queue
//! between one sweep and the next.
//!
//! What closed it is not a new predicate. The Ready-block grammar has been
//! `crates/batten/src/ready.rs` since CLOUD-1121; `[[mint]] issue-read` has minted
//! a receipt from every `get_issue` RESULT since CLOUD-1024; and
//! `an-update-owes-a-recent-read` has forced such a read within 300 seconds of any
//! write since CLOUD-312. This row is those three facts joined by one column:
//! the mint's body grew a sixth field carrying the compiled authority's verdict,
//! and `requires_field` lets the promotion row read it.
//!
//! # This is the SECOND tier, and the whole file exists because the first cannot
//! answer
//!
//! `.claude/rules/policy-modules.md` states the rule and this row is exactly its
//! shape: a `with input as`-style unit case fabricates the receipt the engine may
//! be unable to WRITE. Every case below therefore drives the compiled binary
//! twice — once on the `PostToolUse` event that mints, once on the `PreToolUse`
//! event that decides — and never writes a receipt by hand except in the one case
//! whose subject IS a hand-written receipt.
//!
//! # The discriminator, stated as the row's acceptance states it
//!
//! *"the promotion of a row whose last read was unready is denied, and the same
//! row groomed and re-read passes — the discriminator being that an extra
//! `get_issue` alone does not change the outcome."* That last clause is
//! [`a_second_read_of_the_same_unready_row_changes_nothing`], and it is the case
//! that makes this suite evidence rather than coverage: without it every
//! assertion here is satisfied by a gate that merely counts reads.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// This repository's own rows, as committed — never a fixture rewriting them.
///
/// `board_receipts.rs`'s helper, for its reason: the committed `batten.toml` is
/// the source of truth (§1), so a suite asserting a hand-written copy of the row
/// would pass over a config that says something else. `include_str!` reads it at
/// compile time, so a row edited in `batten.toml` is exercised by the next run
/// rather than by whoever remembers to update a duplicate.
fn repo(name: &str) -> PathBuf {
    let staged = Fixture::new(name).config(include_str!("../../../../batten.toml"));
    // Copied by ENUMERATION rather than by name, and staged before the commit so
    // they are tracked like the config is: naming a consumer's policy filenames
    // in `crates/**` is non-negotiable rule 1's violation, and `no-consumer-repo-
    // name` computes that rather than trusting a reader to notice.
    let modules = staged.path().join("policy");
    std::fs::create_dir_all(&modules).expect("the fixture's policy directory is creatable");
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("policy");
    for entry in std::fs::read_dir(&committed).expect("the committed policy directory is readable")
    {
        let entry = entry.expect("a policy directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
        {
            std::fs::copy(&path, modules.join(entry.file_name())).expect("copy a policy module");
        }
    }
    staged.git().base_commit().build()
}

/// A body whose Ready block opens and then says nothing checkable.
///
/// CLOUD-299's measured shape, which is the honest unready case rather than a
/// contrived one: the opener matches, zero clauses are found, and for the whole
/// life of the predecessor that combination exited 0 and sat in the ready queue.
/// **No §6 clause**, deliberately — the version arrow is the one input the
/// grammar needs that a payload does not carry, and a fixture reaching for it
/// would be asserting the fixture's `Cargo.toml` rather than this row.
const UNREADY_BODY: &str = "**Refinement — Ready**\\n\\nSomething will go here.";

/// The same block, groomed: one clause, in the canonical notation.
const READY_BODY: &str =
    "**Refinement — Ready**\\n\\n* **Authority boundary (§1).** The crate owns it.";

/// A `get_issue` result for `CLOUD-1` carrying the mint's declared field set.
fn read_result(description: &str) -> String {
    format!(
        "{{\"id\":\"CLOUD-1\",\"updatedAt\":\"2026-08-29T04:42:01.650Z\",\
         \"description\":\"{description}\",\"status\":\"Todo\"}}"
    )
}

/// A post-tool envelope: the event the mint reads, with the host's own result key.
fn post_tool(tool: &str, response: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!(
        "{{\"hook_event_name\":\"PostToolUse\",\"tool_name\":{encoded},\
         \"tool_input\":{{}},\"tool_response\":{response}}}"
    )
}

/// A pre-tool envelope: the event the row decides.
fn pre_tool(tool: &str, input: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{encoded},\"tool_input\":{input}}}")
}

/// Hand one completed call to the engine, as the host would.
fn completed(repo: &Path, tool: &str, response: &str) {
    // The STATUS is deliberately discarded: a post-tool event carries no verdict,
    // so asserting one would be asserting this call's own irrelevance.
    let _ = run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &post_tool(tool, response),
    );
}

/// Read the row, over the connector, exactly as an agent would.
fn read_the_row(repo: &Path, description: &str) {
    completed(repo, "mcp__Linear__get_issue", &read_result(description));
}

fn verdict(repo: &Path, input: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &pre_tool("mcp__Linear__save_issue", input),
    )
    .status
    .code()
}

/// What the receipt store holds for `name`, or `None` when nothing minted.
fn receipt(repo: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(repo.join(".git/batten-receipts").join(name)).ok()
}

/// The promotion this row exists to refuse.
const PROMOTION: &str = r#"{"id":"CLOUD-1","state":"Todo"}"#;

/// The acceptance clause, end to end and in the order that proves it.
///
/// Both directions in one case, for `board_receipts.rs`'s reason: a suite that
/// only asserts the deny passes over a row that refuses every promotion, and that
/// over-fire is the false-positive rate every retiring guard's header prices at
/// "switched off within a day".
#[test]
fn promoting_an_unready_row_is_refused_and_a_groomed_one_is_allowed() {
    let repo = repo("todo-promotion-unready-then-groomed");

    read_the_row(&repo, UNREADY_BODY);
    let minted = receipt(&repo, "issue-read.CLOUD-1").expect("the read minted its own receipt");
    let fields: Vec<&str> = minted.trim().split(' ').collect();
    assert_eq!(
        fields.len(),
        6,
        "the five fields the hand-run task writes, plus the verdict: {minted}"
    );
    assert_eq!(
        fields[5], "unready",
        "the sixth field is the compiled authority's verdict over the body the tracker \
         returned: {minted}"
    );

    assert_eq!(
        verdict(&repo, PROMOTION),
        Some(2),
        "a promotion into the ready queue is refused while the last read says unready"
    );

    read_the_row(&repo, READY_BODY);
    let groomed = receipt(&repo, "issue-read.CLOUD-1").expect("the second read replaced the first");
    assert_eq!(
        groomed.trim().split(' ').nth(5),
        Some("ready"),
        "and the groomed body re-mints the receipt with the other verdict: {groomed}"
    );

    assert_eq!(
        verdict(&repo, PROMOTION),
        Some(0),
        "so the same promotion is allowed, with no second call and nothing piped anywhere"
    );
}

/// THE DISCRIMINATOR. Without this case every assertion above is satisfied by a
/// gate that merely counts reads.
///
/// The row's own acceptance names it: *"the discriminator being that an extra
/// `get_issue` alone does not change the outcome."* A verdict that came from the
/// number of reads rather than from what they found would flip here.
#[test]
fn a_second_read_of_the_same_unready_row_changes_nothing() {
    let repo = repo("todo-promotion-reading-twice-is-not-grooming");

    read_the_row(&repo, UNREADY_BODY);
    assert_eq!(verdict(&repo, PROMOTION), Some(2));

    read_the_row(&repo, UNREADY_BODY);
    assert_eq!(
        verdict(&repo, PROMOTION),
        Some(2),
        "reading the row again without changing it must not move the verdict — only a \
         groom does, because the verdict comes from the body the tracker stored"
    );
}

/// The refusal names the row that refused and the state to reach.
///
/// The ROW is asserted, not just the code: three rows select this tool now, so an
/// exit 2 alone would be satisfied by `an-update-owes-a-recent-read` firing on the
/// same call — the misattribution `replay.sh` calls `denied-by-another-row`, and
/// here it would hide the whole of this change behind a gate that already existed.
#[test]
fn the_refusal_names_this_row_and_carries_no_body() {
    let repo = repo("todo-promotion-refusal-shape");
    read_the_row(&repo, UNREADY_BODY);

    let refusal = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        &pre_tool("mcp__Linear__save_issue", PROMOTION),
    );
    let text = stderr(&refusal);
    assert!(
        text.contains("a-todo-promotion-owes-a-ready-verdict"),
        "the refusing row must be nameable, or a reader cannot find it in the config: {text}"
    );
    assert!(
        text.contains("ready"),
        "and the state the row has to reach, which is what the reader acts on: {text}"
    );
    // Rule 4, and it is load-bearing here rather than editorial: the verdict was
    // computed over an issue body, and a refusal echoing what it read would put
    // somebody's tracker prose into CI logs.
    assert!(
        !text.contains("Something will go here"),
        "the refusal must carry no byte of the body it judged: {text}"
    );
}

/// A receipt minted by the hand-run task predates the column, and must still
/// authorise.
///
/// **This is the fail-open direction, and it is what let the column be declared
/// over a receipt family already on disk.** `mise run issue-read-check` writes
/// five fields; a host with no post-tool event has no other route; and a payload
/// the authority could not parse renders the absent token. All three arrive here
/// as "the field says nothing", and reading that as a refusal would speak a
/// verdict about the ENVIRONMENT in a verdict about the row.
#[test]
fn a_receipt_that_records_no_verdict_allows() {
    let repo = repo("todo-promotion-five-field-receipt");
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    // The hand-run task's own five fields, in its order.
    std::fs::write(
        store.join("issue-read.CLOUD-1"),
        format!("CLOUD-1 2026-08-29T04:42:01.650Z {now} - todo\n"),
    )
    .expect("mint the five-field receipt");

    assert_eq!(
        verdict(&repo, PROMOTION),
        Some(0),
        "a receipt with no sixth field is could-not-look, and could-not-look allows"
    );

    // The other spelling of the same answer: the field is present and is the
    // absent token, which is what a renderer writes when it could not judge.
    std::fs::write(
        store.join("issue-read.CLOUD-1"),
        format!("CLOUD-1 2026-08-29T04:42:01.650Z {now} - todo -\n"),
    )
    .expect("mint the receipt with an absent verdict");
    assert_eq!(
        verdict(&repo, PROMOTION),
        Some(0),
        "and an explicitly absent verdict allows for the same reason"
    );
}

/// Every other column is a different question with a different owner.
///
/// The over-fire this row must not have: a column that could only ask whether a
/// `state` was PRESENT would fire on every edit that named any, which is the
/// false-positive rate `when_value` exists to avoid. In Progress is
/// `claim-check`'s question and this row must not answer for it.
#[test]
fn a_move_to_another_column_is_not_gated_here() {
    let repo = repo("todo-promotion-other-columns");
    read_the_row(&repo, UNREADY_BODY);

    assert_eq!(
        verdict(&repo, r#"{"id":"CLOUD-1","state":"In Progress"}"#),
        Some(0),
        "pulling an unready row is `claim-check`'s question, not this row's"
    );
    assert_eq!(
        verdict(&repo, r#"{"id":"CLOUD-1","description":"groomed"}"#),
        Some(0),
        "and an edit that moves no column is gated only on the recent read it already has"
    );
}

/// A row whose id the receipt namespace cannot key resolves to could-not-look and
/// ALLOWS.
///
/// `key_shape`'s carve-out, asserted here rather than assumed from the row below
/// it: the `id` parameter accepts a UUID as well as an issue key, resolving one to
/// the other needs a tracker credential no hook has, and denying on a spelling the
/// agent is entitled to use is the false-positive rate that gets a guard bypassed
/// rather than satisfied.
#[test]
fn a_uuid_id_fails_open_rather_than_denying() {
    let repo = repo("todo-promotion-uuid-id");
    read_the_row(&repo, UNREADY_BODY);

    assert_eq!(
        verdict(
            &repo,
            r#"{"id":"3913e745-0a9c-4091-94ab-d264b7baca6a","state":"Todo"}"#
        ),
        Some(0),
        "an id this engine cannot key a receipt under is not having looked, and not looking allows"
    );
}
