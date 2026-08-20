//! The discarded-verdict corpus, over the compiled binary (CLOUD-443).
//!
//! `tests/run-shape-guard.bats`'s first family, translated into the surface that
//! now decides it: a `pipeline` row with its `verdict` and `filters` tables. The
//! bash guard keeps only the two families the engine cannot express — a
//! foreground `sleep` and an unsatisfiable `git commit` — so this file is what
//! keeps the split honest.
//!
//! **The allows are the load-bearing half.** Every deny here has a
//! near-identical allow beside it, and that is the whole design of the predicate
//! rather than test hygiene: CLOUD-199 measured that a guard with false positives
//! gets bypassed, and a bypassed guard enforces nothing. A suite asserting only
//! the denies would pass on a rule that refuses every pipeline in the repository.
//!
//! Judged against the **committed** `batten.toml`, because the tables are the
//! consumer's: a fixture-only suite would stay green after someone deleted the
//! `cargo` row, which is exactly the drift the corpus exists to catch.
//!
//! Every `cargo` sample is written `mise exec -- cargo …` since CLOUD-271: the
//! committed `no-bare-cargo` row refuses the unmediated route outright, so a
//! bare spelling would make the allows fail and — worse — make the denies pass
//! for the wrong row, which is coverage that has stopped testing this predicate.
//! The wrapper look-through means the mediated form is still judged as `cargo`,
//! so each case asks exactly what it asked before.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{run_with_stdin, stderr};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn payload(command: &str) -> String {
    let encoded = serde_json::to_string(command).expect("a command is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
         \"tool_input\":{{\"command\":{encoded}}}}}"
    )
}

fn verdict(command: &str) -> Option<i32> {
    run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload(command),
    )
    .status
    .code()
}

fn assert_denied(command: &str) {
    assert_eq!(verdict(command), Some(2), "must refuse: {command}");
}

fn assert_allowed(command: &str) {
    assert_eq!(verdict(command), Some(0), "must allow: {command}");
}

#[test]
fn a_verdict_piped_into_a_pager_or_filter_is_refused() {
    // The measured cases, each of which produced a confident "green" report over
    // a run that had failed.
    assert_denied("mise run verify 2>&1 | tail -6");
    assert_denied("mise run verify | head -20");
    assert_denied("git push origin branch | tail -2");
    assert_denied("mise exec -- cargo clippy | grep -E error");
    assert_denied("mise exec -- cargo test -p batten | wc -l");
    assert_denied("gh pr merge 42 | tail -1");
    // A filter two stages down substitutes just as completely as an adjacent one.
    assert_denied("mise run verify | sort | tail -3");
}

#[test]
fn a_read_only_query_carries_no_verdict_and_composes_freely() {
    // The false positive that would make this gate unusable: piping a query is
    // ordinary work, and its output IS its answer.
    assert_allowed("git log --oneline -5 | head -2");
    assert_allowed("git status --short | wc -l");
    assert_allowed("gh pr view 42 | tail -3");
    assert_allowed("mise exec -- cargo metadata | jq .packages");
    // `jq` is composition rather than a verdict substitute, so it is not a filter
    // even downstream of a real verdict.
    assert_allowed("gh pr view 42 --json title | jq -r .title");
}

#[test]
fn a_pager_over_a_file_is_fine_it_is_a_pager_over_a_live_task_that_is_not() {
    // This is the remedy the refusal itself recommends, so refusing it would make
    // the gate self-contradicting.
    assert_allowed("tail -6 /tmp/verify.log");
    assert_allowed("grep -E error /tmp/clippy.log");
}

#[test]
fn a_trailing_list_element_replaces_the_status() {
    // The laundered shape: it reads as correct, and the guard this ports used to
    // recommend it. Backgrounded it is worse than a misread — the completion
    // notification then carries the compound's status, so a failed task arrives
    // as `completed (exit code 0)`.
    assert_denied("mise run verify >log 2>&1; echo \"EXIT=$?\"");
    assert_denied("mise run fmt >log 2>&1 || echo failed");
    assert_denied("mise exec -- cargo test >log 2>&1; ls");
}

#[test]
fn an_and_chain_is_allowed_because_it_cannot_manufacture_a_green() {
    // The deliberate departure from the written acceptance, and the reason is
    // arithmetic rather than taste: `a && b` short-circuits, so a failure in `a`
    // still exits the list non-zero. There is no false green to stop, and
    // `verify`'s own body is built from guarded chains for that property.
    assert_allowed("mise run fmt && mise run verify");
    assert_allowed("git fetch origin main && git rebase origin/main");
    assert_allowed("mise exec -- cargo build && mise exec -- cargo test");
}

#[test]
fn detaching_a_verdict_orphans_it_from_the_tool_call() {
    assert_denied("nohup mise run land >/tmp/land.log 2>&1 &");
    assert_denied("mise run ci-wait &");
    assert_denied("nohup mise exec -- cargo test -p batten >/tmp/t.log 2>&1 &");
    // The wrapper is looked through, so the wrapped program is what is judged.
    assert_denied("nohup mise run verify");
}

#[test]
fn the_prescribed_form_is_allowed_including_its_redirection() {
    // THE regression test for the parser change. `2>&1` carries a literal `&`,
    // and the form this engine prescribes contains one — so an `&` test
    // that did not exempt redirections would refuse the exact idiom the refusal
    // recommends, which is the worst failure this gate could have.
    assert_allowed("mise run verify >/tmp/verify.log 2>&1");
    assert_allowed("mise run land >/tmp/land.log 2>&1");
    assert_allowed("mise exec -- cargo test -p batten >/tmp/test.log 2>&1");
    assert_allowed("git push origin branch >/tmp/push.log 2>&1");
    // The other redirection spellings that carry an `&`.
    assert_allowed("mise run verify &>/tmp/verify.log");
    assert_allowed("mise run verify >/tmp/v.log 2>&1 && echo queued");
}

#[test]
fn a_verdict_alone_in_the_call_is_the_prescribed_form() {
    assert_allowed("mise run verify");
    assert_allowed("mise exec -- cargo test -p batten");
    assert_allowed("git push origin branch");
    assert_allowed("bats tests/land.bats");
}

#[test]
fn a_bare_invocation_that_answers_nothing_is_not_a_verdict() {
    // A test runner with no suite, and a build tool with no subcommand, print
    // usage. Piping usage is not discarding a verdict, because there is none.
    assert_allowed("bats --version | head -1");
    assert_allowed("bats --help | tail -5");
    assert_allowed("mise exec -- cargo | head -3");
}

#[test]
fn a_command_describing_the_shape_is_not_the_shape() {
    // A commit message, an issue body, or documentation naming one of these
    // shapes is prose. The parser's quote handling is what makes this hold, and
    // it is pinned here because this repository's own commits say these things.
    assert_allowed("git commit -m \"never run mise run verify | tail -6\"");
    assert_allowed("git commit -m \"the nohup mise run land & shape is refused\"");
    assert_allowed("echo \"mise run verify | tail\" > /tmp/notes.md");
}

#[test]
fn a_pager_on_an_earlier_query_does_not_condemn_a_later_command() {
    // Judged per segment. A pager attached to a read-only first element says
    // nothing about a verdict-bearing second one, and judging the whole string
    // refused exactly that — a correct command using the recommended form.
    assert_allowed("git log --oneline | head -3 && mise run verify >/tmp/v.log 2>&1");
    // And the direction that matters: a write must not be excused by a read.
    assert_denied("git log --oneline | head -3 && mise run verify | tail -2");
}

#[test]
fn the_refusal_states_the_principle_rather_than_naming_one_command() {
    // CLOUD-199's second instance happened because an agent complied with the
    // narrower wording exactly and made the same error on the next command. The
    // cause therefore has to generalise, and the remedy has to be the row's.
    let refusal = stderr(&run_with_stdin(
        &root(),
        &["hook", "--harness", "exit-code"],
        &payload("mise run verify | tail -6"),
    ));
    assert!(
        refusal.contains("verdict-not-discarded"),
        "names the rule: {refusal}"
    );
    assert!(
        refusal.contains("exit status"),
        "states the principle: {refusal}"
    );
    assert!(
        refusal.contains("run_in_background"),
        "names the remedy: {refusal}"
    );
    // Pointer-only: the caller's own command line is never echoed back.
    assert!(
        !refusal.contains("tail -6"),
        "must not echo the mediated command: {refusal}"
    );
}

#[test]
fn each_shape_renders_its_own_cause() {
    // Three causes from one row, in `receipt_refusal`'s idiom. A single generic
    // message would leave the reader to work out which of three structures they
    // wrote.
    let cause = |command: &str| {
        stderr(&run_with_stdin(
            &root(),
            &["hook", "--harness", "exit-code"],
            &payload(command),
        ))
    };
    assert!(cause("mise run verify | tail -1").contains("pager or filter"));
    assert!(cause("mise run verify >log 2>&1; ls").contains("only the last element"));
    assert!(cause("nohup mise run verify &").contains("orphans it"));
}
