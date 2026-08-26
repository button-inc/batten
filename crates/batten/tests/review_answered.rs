//! The read-the-review gate over the compiled binary (CLOUD-859), ported off
//! `tests/review-answered.bats` under CLOUD-1059.
//!
//! # Why it moved, and it is the migration gate's own doing
//!
//! CLOUD-1050 deletes `msg` from every refusal: a refusal is
//! `{rule, verdict, subjects}` and its prose lives in a `[[verdict]]` row. The
//! retired suite asserted the refusal's PROSE — `*"4 blocking"*` — so the ABI
//! change reddened it, and `policy/shell-retirement.rego` refuses an authored
//! Bats suite edited in place. Retiring it is the specified remedy rather than a
//! consequence somebody chose: maintenance of a shell-tier rule is completed by
//! migrating it.
//!
//! # The tier is unchanged, which is the whole point of the port
//!
//! Every case still goes through TWO real hook calls in the order a session
//! makes them: a `PostToolUse` envelope carrying the declared command and a
//! buffer, which mints the record, then a `PreToolUse` `gh pr ready`, which
//! reads it. Nothing writes a receipt by hand. A module's own `test_` rules
//! cannot do this — a `with input as` case fabricates the very shape the engine
//! may be unable to produce, the defect class
//! `.claude/rules/policy-modules.md` records twice.
//!
//! The fixture reads the declared command out of this repository's own
//! `batten.toml` rather than retyping it, for the retired suite's reason:
//! byte-equality is the forgery control, so a copy that drifted would leave
//! every case passing over a string the real gate does not use.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
// carried: tests/review-answered.bats policy/review-answered.rego crates/batten/tests/review_answered.rs
//!
//! # RETIREMENT LEDGER — `tests/review-answered.bats`, 12 cases
//!
//! CARRIED — the property survives, proved here against the same two calls.
//!
// carried: "a ready with no record at all is refused, and the receipt row names the command" crates/batten/tests/review_answered.rs
// carried: "a head whose threads are all answered is allowed" crates/batten/tests/review_answered.rs
// carried: "VACUITY: a buffer that is not the declared shape records nothing rather than one row" crates/batten/tests/review_answered.rs
// carried: "VACUITY: an empty buffer is not zero rows" crates/batten/tests/review_answered.rs
// carried: "a buffer from a command nobody asked for never becomes the record" crates/batten/tests/review_answered.rs
// carried: "a re-draft is not a ready, even on a head carrying findings" crates/batten/tests/review_answered.rs
// carried: "a commit message naming the command is prose, not a ready" crates/batten/tests/review_answered.rs
// carried: "reading the review is never refused, so the remedy is reachable" crates/batten/tests/review_answered.rs
//!
//! CHANGED — the property survives and what it ASSERTS moved, because the
//! refusal it read is not a string any more. Each of these four asserted a
//! count inside prose; each now asserts the same count as the `Subject::Count`
//! the engine renders beside the token. The number is identical in every case,
//! which is what makes this a changed assertion rather than a dropped one.
//!
// changed: "review-answered::THE MEASURED SHAPE: a head carrying unresolved threads is refused, naming the count" crates/batten/tests/review_answered.rs
// changed: "review-answered::VACUITY: zero threads and no review reads as unreviewed, not as all-addressed" crates/batten/tests/review_answered.rs
// changed: "review-answered::VACUITY: a page the command could not read refuses rather than passing" crates/batten/tests/review_answered.rs
// changed: "review-answered::THE BYPASS: a compound command is still a ready" crates/batten/tests/review_answered.rs
//!
//! # One case the retired suite could not have
//!
//! `an undeclared class refuses with the token and says the registry is silent`
//! is new, and it is the ABI's own seam: a module may emit a verdict no
//! `[[verdict]]` row declares, and the engine must say so rather than print an
//! empty gloss. The retired suite had no registry to leave a hole in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{at_root, run_with_stdin, scratch};

/// The `command` of the `[[fact]]` row named `review-answered`, read out of this
/// repository's own committed config.
///
/// BY NAME rather than by position: taking the first `[[fact]]` block would let
/// a row added above this one silently repoint every case here at the wrong
/// command. Parsed with a line scan rather than a TOML crate for the same reason
/// the retired suite used one — what is being asserted is the literal bytes of
/// one declaration, and a parser that normalised them would dissolve the
/// coupling this exists to hold.
fn declared_command() -> String {
    let text = fs::read_to_string(at_root("batten.toml")).expect("read the committed config");
    let mut named = false;
    for block in text.split("[[fact]]").skip(1) {
        let mut command = None;
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("name = \"") {
                named = rest.strip_suffix('"') == Some("review-answered");
            }
            if let Some(rest) = line.strip_prefix("command = \"")
                && let Some(value) = rest.strip_suffix('"')
            {
                command = Some(value.to_owned());
            }
            if line.starts_with("[[") {
                break;
            }
        }
        if named && let Some(command) = command {
            return command;
        }
    }
    panic!("no [[fact]] row named review-answered in the committed config");
}

/// A fixture repository carrying the real module, the two rows that judge it,
/// and the verdict class the refusal resolves against.
///
/// `declared` is threaded in rather than re-read per call: the fixture's config
/// and every envelope below must name the same bytes, and reading it twice is
/// two chances to disagree.
fn repo(name: &str, declared: &str, declare_the_class: bool) -> PathBuf {
    let dir = scratch(name);
    fs::create_dir_all(dir.join("policy")).expect("create the policy directory");
    fs::copy(
        at_root("policy/review-answered.rego"),
        dir.join("policy/review-answered.rego"),
    )
    .expect("copy the module under test");
    let class = if declare_the_class { CLASS } else { "" };
    fs::write(
        dir.join("batten.toml"),
        format!("{CONFIG}command = \"{declared}\"\n{ROWS}{class}"),
    )
    .expect("write the fixture config");
    git(&dir, &["init", "--quiet", "--initial-branch", "main"]);
    git(&dir, &["config", "user.email", "fixture@example.invalid"]);
    git(&dir, &["config", "user.name", "fixture"]);
    // AND A COMMIT. The record is filed under the subject the row's
    // `key = "head"` names, so a repository whose HEAD does not resolve has no
    // subject — the boundary answers could-not-look and every case here would be
    // ALLOWED, which is the fail-open posture working rather than the thing
    // these cases are about.
    git(
        &dir,
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "the head this gate judges",
        ],
    );
    dir
}

#[expect(
    clippy::disallowed_types,
    reason = "stays — the fixture needs real git history for the head the record is keyed to, and \
              `board_record.rs`'s fixture is the precedent. Test-only, so no shipped path spawns \
              here."
)]
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        // A contributor's own git settings must not be able to move a verdict
        // here (CLOUD-282).
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// Mint the record the way a session does: a `PostToolUse` envelope carrying the
/// declared command and the buffer the host handed back.
fn record(dir: &Path, declared: &str, stdout: &str) {
    let payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "sess-review",
        "cwd": "/repo",
        "tool_name": "Bash",
        "tool_input": {"command": declared},
        "tool_response": {"stdout": stdout, "stderr": ""},
    });
    let output = run_with_stdin(
        dir,
        &["hook", "--harness", "claude-code"],
        &payload.to_string(),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "recording is not a verdict, so the call is allowed"
    );
}

/// Read it: the call the gate exists to judge.
fn call(dir: &Path, command: &str) -> String {
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    let output = run_with_stdin(
        dir,
        &["hook", "--harness", "claude-code"],
        &payload.to_string(),
    );
    // THE STATUS IS ASSERTED, for the retired suite's measured reason: this
    // harness prints nothing on an allow and exits 0 either way, so a substring
    // check over an empty string is true — including the empty output of a
    // binary that died before it judged anything.
    assert_eq!(
        output.status.code(),
        Some(0),
        "the claude-code harness answers on stdout and exits 0"
    );
    String::from_utf8(output.stdout).expect("the decision document is UTF-8")
}

fn ready(dir: &Path) -> String {
    call(dir, "gh pr ready 702")
}

fn denied(decision: &str) {
    assert!(
        decision.contains(r#""permissionDecision":"deny""#),
        "expected a deny, got: {decision}"
    );
}

fn allowed(decision: &str) {
    assert!(
        !decision.contains(r#""deny""#),
        "expected an allow, got: {decision}"
    );
}

// --- the two refusals, and which row owns each ------------------------------

#[test]
fn a_ready_with_no_record_at_all_is_refused_and_the_receipt_row_names_the_command() {
    // The did-you-look half. The deny is built from the DECLARED command rather
    // than from prose, which is the property that makes the remedy runnable.
    let declared = declared_command();
    let dir = repo("review-answered-no-record", &declared, true);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("gh api graphql"), "{decision}");
    assert!(decision.contains("reviewThreads"), "{decision}");
}

#[test]
fn the_measured_shape_a_head_carrying_unresolved_threads_is_refused_naming_the_count() {
    // #623's four open threads, as the projection emits them: one element per
    // thread id.
    let declared = declared_command();
    let dir = repo("review-answered-open-threads", &declared, true);
    record(&dir, &declared, r#"["PRRT_a","PRRT_b","PRRT_c","PRRT_d"]"#);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("review-unanswered"), "{decision}");
    // THE COUNT, as the typed ABI renders it: the token, its gloss, and the
    // `Subject::Count` beside them. The retired case read `4 blocking` out of a
    // free string; the number is the same and it is now a decoded subject.
    assert!(decision.contains("V-REVIEW-UNANSWERED"), "{decision}");
    assert!(
        decision.contains("blocking review conditions) 4"),
        "{decision}"
    );
    // Pointer-only (non-negotiable rule 4): the ids are not in the engine, so a
    // refusal naming one would be a payload this channel refuses to carry.
    assert!(!decision.contains("PRRT_a"), "{decision}");
}

#[test]
fn a_head_whose_threads_are_all_answered_is_allowed() {
    // THE LOAD-BEARING HALF. A predicate that only ever denied would satisfy
    // every case above and gate nothing (CLOUD-418). `[]` is the genuine zero:
    // the command looked and found none.
    let declared = declared_command();
    let dir = repo("review-answered-clean", &declared, true);
    record(&dir, &declared, "[]");
    allowed(&ready(&dir));
}

// --- the vacuity cases the row enumerates -----------------------------------

#[test]
fn vacuity_zero_threads_and_no_review_reads_as_unreviewed_not_as_all_addressed() {
    // #618 carries no threads and no review. The projection emits the PR
    // author's login when nothing but the author reviewed, so the honest count
    // is one — and a thread-only predicate would have read this as zero and
    // passed it.
    let declared = declared_command();
    let dir = repo("review-answered-unreviewed", &declared, true);
    record(&dir, &declared, r#"["wenzowski"]"#);
    let decision = ready(&dir);
    denied(&decision);
    assert!(
        decision.contains("blocking review conditions) 1"),
        "{decision}"
    );
}

#[test]
fn vacuity_a_buffer_that_is_not_the_declared_shape_records_nothing_rather_than_one_row() {
    // `returns = "json-array"` (CLOUD-993). A `gh` that printed an auth error,
    // or a wrapper that annotated its own output, must not become `rows 1` —
    // which would be a refusal nobody can clear — nor `rows 0`, which would be a
    // pass over a command that never answered. It records NOTHING, so the
    // receipt row's did-you-look refusal stands.
    let declared = declared_command();
    let dir = repo("review-answered-wrong-shape", &declared, true);
    record(
        &dir,
        &declared,
        "gh: could not determine the current repository",
    );
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("gh api graphql"), "{decision}");
}

#[test]
fn vacuity_an_empty_buffer_is_not_zero_rows() {
    // A command that printed nothing is could-not-look, not "there are none".
    // Recording a zero here would turn silence into a pass.
    let declared = declared_command();
    let dir = repo("review-answered-empty-buffer", &declared, true);
    record(&dir, &declared, "");
    denied(&ready(&dir));
}

#[test]
fn a_buffer_from_a_command_nobody_asked_for_never_becomes_the_record() {
    // The forgery control, over this fact: the agent chooses WHICH command runs
    // and does not author what it prints, so byte-equality against the
    // declaration is what stands between the two.
    let declared = declared_command();
    let dir = repo("review-answered-forged-buffer", &declared, true);
    record(&dir, "echo []", "[]");
    denied(&ready(&dir));
}

// --- what must NOT be refused ----------------------------------------------

#[test]
fn a_redraft_is_not_a_ready_even_on_a_head_carrying_findings() {
    // `land` re-drafts on a red run, and that is the one thing that stops the
    // next push buying another matrix (CLOUD-240). Refusing it would leave the
    // tap open on exactly the head this gate is keeping out of CI.
    let declared = declared_command();
    let dir = repo("review-answered-redraft", &declared, true);
    record(&dir, &declared, r#"["PRRT_a","PRRT_b"]"#);
    allowed(&call(&dir, "gh pr ready 702 --undo"));
}

#[test]
fn vacuity_a_page_the_command_could_not_read_refuses_rather_than_passing() {
    // GitHub caps a connection page at 100, so a PR with more threads than that
    // would have the surplus fall outside the query — and an unresolved thread
    // out there would leave `rows == 0`, a FALSE GREEN in the one direction this
    // gate exists to prevent. The projection emits an extra element per
    // truncated connection, so the buffer a clear-but-truncated head produces is
    // `[true]` rather than `[]`.
    //
    // THE DISCRIMINATING PAIR is this case beside "all answered": both are a
    // head with zero unresolved threads, and only the truncated one refuses.
    // Without the `pageInfo` clauses they would be the same buffer.
    let declared = declared_command();
    let dir = repo("review-answered-truncated", &declared, true);
    record(&dir, &declared, "[true]");
    let decision = ready(&dir);
    denied(&decision);
    assert!(
        decision.contains("blocking review conditions) 1"),
        "{decision}"
    );
}

#[test]
fn the_bypass_a_compound_command_is_still_a_ready() {
    // The case an earlier draft did not have, and the reason it did not: this
    // module anchored on `startswith`, so `cd /repo && gh pr ready 702` went
    // unjudged. The receipt row DOES select it, so an existing record satisfies
    // the did-you-look half — and with the count half silent the call was
    // allowed carrying two unresolved threads. Measured exactly that before the
    // anchor came out.
    //
    // End to end rather than only in the module's `test_` rules, because what
    // was wrong was the interaction between two rows: the receipt row's
    // selection and this module's narrowing disagreeing about one command.
    let declared = declared_command();
    let dir = repo("review-answered-compound", &declared, true);
    record(&dir, &declared, r#"["PRRT_a","PRRT_b"]"#);
    let decision = call(&dir, "cd /repo && gh pr ready 702");
    denied(&decision);
    assert!(
        decision.contains("blocking review conditions) 2"),
        "{decision}"
    );
}

#[test]
fn a_commit_message_naming_the_command_is_prose_not_a_ready() {
    // THE ANCHOR'S DISCRIMINATING CASE. This repository writes `gh pr ready`
    // down constantly — in commit messages, in issue bodies, in the module
    // itself — so a `contains` over the raw command would refuse its own
    // documentation, which is the hazard `run-shape.rego`'s header records for
    // the identical predicate.
    //
    // Over the binary rather than only in the module's own `test_` rules,
    // because what is at risk is the engine handing the whole command string
    // through: a `with input as` case fabricates that string and cannot show it
    // arrives raw.
    let declared = declared_command();
    let dir = repo("review-answered-prose", &declared, true);
    record(&dir, &declared, r#"["PRRT_a","PRRT_b"]"#);
    allowed(&call(
        &dir,
        r#"git commit -m "run gh pr ready once the review is answered""#,
    ));
}

#[test]
fn reading_the_review_is_never_refused_so_the_remedy_is_reachable() {
    // A gate whose own remedy it blocks is unsatisfiable. Both `gh pr view` and
    // the declared `gh api graphql` must pass on a head with findings recorded.
    let declared = declared_command();
    let dir = repo("review-answered-remedy", &declared, true);
    record(&dir, &declared, r#"["PRRT_a"]"#);
    for command in ["gh pr view 702 --json reviewDecision", declared.as_str()] {
        allowed(&call(&dir, command));
    }
}

// --- the ABI's own seam, which the retired suite had no registry to leave ----

#[test]
fn an_undeclared_class_refuses_with_the_token_and_says_the_registry_is_silent() {
    // A module may emit a verdict no `[[verdict]]` row declares. The refusal
    // still happens — the predicate decided — and the engine says the registry
    // is silent rather than printing an empty gloss, which would read as a class
    // with nothing to say about itself. The count still travels: a subject is
    // decoded from the violation, not from the registry.
    let declared = declared_command();
    let dir = repo("review-answered-no-class", &declared, false);
    record(&dir, &declared, r#"["PRRT_a","PRRT_b","PRRT_c"]"#);
    let decision = ready(&dir);
    denied(&decision);
    assert!(decision.contains("V-REVIEW-UNANSWERED"), "{decision}");
    assert!(
        decision.contains("no `[[verdict]]` row declares"),
        "{decision}"
    );
    assert!(decision.contains(") 3"), "{decision}");
}

/// The fixture config's head — everything up to the declared command, which is
/// interpolated so the bytes come from the committed row rather than from here.
const CONFIG: &str = r#"version = 1

[[fact]]
name = "review-answered"
returns = "json-array"
"#;

/// The two rows that judge the call: the receipt row that asks whether the agent
/// looked, and the policy row that reads what it found.
const ROWS: &str = r#"
[[rule]]
id = "ready-needs-an-answered-review"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr ready"
checks = ["review-answered"]
key = "head"
reason = "run the declared command"

[[rule]]
id = "review-answered"
kind = "policy"
scope = "mediated_call"
module = "policy/review-answered.rego"
severity = "deny"
"#;

/// The verdict class the module's refusal resolves against, omitted by exactly
/// one case above so the registry-is-silent branch is reachable.
const CLASS: &str = r#"
[[verdict]]
id = "V-REVIEW-UNANSWERED"
gloss = "readying would buy a CI matrix on a head carrying blocking review conditions"
class = """
Readying is the event that starts CI, and nothing in `land`'s pre-ready sequence \
asks about review.
"""

[[verdict.route]]
id = "R-ANSWER-THE-THREADS"
kind = "command"
target = "resolve each thread, then re-run the declared command and retry"
"#;
