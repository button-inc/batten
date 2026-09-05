//! Conditioning a mediated row on the arguments a call names (CLOUD-987).
//!
//! CLOUD-924 gave a row the tool a call names. This is the layer below it — the
//! call's own input — and the reason it exists is that CLOUD-312's rows 1 and 3
//! both turn on an argument rather than on the tool:
//!
//! * row 1 gates **creating** a tracker row and must not gate **editing** one,
//!   and the two differ only in whether the call named an `id`;
//! * row 3 fires only when a call **moves** something, which is a `state` it did
//!   or did not name.
//!
//! **THE ASYMMETRY IS THE PREDICATE, so both sides are asserted everywhere.** A
//! suite that only checked the deny would pass on a row that refuses every call,
//! and that specific over-fire is the one `issue-search-guard`'s own header
//! prices: *"Denying an update would demand a search before every edit to an
//! issue, which is absurd and would get the guard switched off within a day."* A
//! gate that gets switched off enforces nothing, so the allow cases are not
//! hygiene here — they are the thing being built.
//!
//! Fixture-scoped: the consumer rows arrive with CLOUD-312's rows 1-3, and a
//! suite written against a table that does not exist yet would assert nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, run_with_stdin, stderr};

/// A repository whose one row refuses `save_issue` only when no `id` is named.
///
/// This is CLOUD-312's row 1 as config: the tool selector from CLOUD-924 does the
/// selecting, and `when_absent` decides whether that selection refuses.
fn repo_gating_creates(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(
            r#"
version = 1

[[rule]]
id = "search-before-filing"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
severity = "deny"
reason = "search for an existing row before filing a new one; an update is never gated"
"#,
        )
        .git()
        .build()
}

/// A structured call carrying whatever `input` the case is about.
fn payload(tool: &str, input: &str) -> String {
    let encoded = serde_json::to_string(tool).expect("a tool name is encodable");
    format!("{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":{encoded},\"tool_input\":{input}}}")
}

fn verdict(repo: &Path, tool: &str, input: &str) -> Option<i32> {
    run_with_stdin(
        repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(tool, input),
    )
    .status
    .code()
}

/// ROW 1'S DISCRIMINATOR, both sides, in one case because they are one predicate.
///
/// A `save_issue` naming no `id` is a create and is gated; one naming an `id`
/// edits a row that already exists and is not. Asserting only the first would
/// pass on a build that refuses both, which is the guard-switched-off outcome the
/// module doc quotes.
///
/// Fails by: dropping the `when_absent` test from `tool_rules`, which reds the
/// second assertion — the row then refuses every `save_issue`.
#[test]
fn a_create_is_gated_and_an_update_is_not() {
    let repo = repo_gating_creates("args-create-vs-update");
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"title":"a new row"}"#),
        Some(2),
        "a call naming no id opens a row, and that is what the receipt gates"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"an edit"}"#
        ),
        Some(0),
        "a call naming an id edits an existing row and must never be gated"
    );
}

/// The absence test collapses missing, null, empty and wrong-typed alike.
///
/// One definition of absence, in the decoder, rather than a second one in the
/// modifier — every other reader of the allowlist sees `None` for all four, and a
/// modifier that disagreed would make `id: ""` mean something different here than
/// it does to `Field::read`'s other callers.
///
/// Fails by: reading absence with `get("id").is_none()` instead of through
/// `Field::read`, which admits `null` and `""` as present.
#[test]
fn absence_means_what_the_decoder_means_by_it() {
    let repo = repo_gating_creates("args-absence-shapes");
    for input in [
        r#"{"title":"no id key at all"}"#,
        r#"{"id":null}"#,
        r#"{"id":""}"#,
        r#"{"id":{"nested":"object"}}"#,
        r#"{"id":42}"#,
    ] {
        assert_eq!(
            verdict(&repo, "mcp__Linear__save_issue", input),
            Some(2),
            "none of these names an id a gate could compare: {input}"
        );
    }
}

/// The modifier narrows the row it is on and nothing else.
///
/// A neighbouring tool is still not selected, so `when_absent` cannot widen a
/// row onto calls its `tool` never named — the two modifiers compose in the one
/// direction that keeps a policy engine honest.
#[test]
fn the_modifier_does_not_widen_the_selection() {
    let repo = repo_gating_creates("args-no-widening");
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_comment",
            r#"{"body":"a comment"}"#
        ),
        Some(0),
        "a comment names no id either, and this row is not about comments"
    );
    assert_eq!(
        verdict(&repo, "Bash", r#"{"command":"echo hi"}"#),
        Some(0),
        "an unrelated tool naming no id is not this row's business"
    );
}

/// A repository declaring no such modifier is unaffected.
///
/// Without this the suite could not tell a working modifier from one that refuses
/// nothing anywhere.
#[test]
fn a_row_without_the_modifier_still_refuses_on_selection_alone() {
    let repo = Fixture::new("args-no-modifier")
        .config(
            r#"
version = 1

[[rule]]
id = "no-save-issue-at-all"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
severity = "deny"
reason = "this tool is refused outright here"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(2),
        "a bare tool row refuses whether or not an id was named"
    );
}

/// ROW 3'S DISCRIMINATOR: a move is gated, a plain edit is not.
///
/// `when_present`'s reason for existing. `board-move-guard` fires only when a
/// call moves a row between columns, and a call that merely edits one names no
/// `state`. A row without this modifier would gate every edit — the same
/// over-fire `when_absent` prevents one key over, which is why both polarities
/// had to land together rather than one at a time.
///
/// Fails by: dropping the `when_present` test, which reds the second assertion.
#[test]
fn a_move_is_gated_and_a_plain_edit_is_not() {
    let repo = Fixture::new("args-move-vs-edit")
        .config(
            r#"
version = 1

[[rule]]
id = "record-the-move"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_present = "input-state"
severity = "deny"
reason = "record the column move before making it"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","state":"In Progress"}"#
        ),
        Some(2),
        "a call naming a state moves the row, and that is what this gates"
    );
    assert_eq!(
        verdict(
            &repo,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1","title":"just an edit"}"#
        ),
        Some(0),
        "a call naming no state edits in place and must not be gated as a move"
    );
}

/// The two polarities over ONE projection can never fire, and are refused at
/// load rather than left to match nothing.
///
/// A row asking for the same key to be both absent and present is inert — it
/// loads, decides nothing, and reads from the file as a narrowing. Naming
/// *different* projections is legitimate, which the second half asserts so the
/// refusal cannot be over-broad.
///
/// Fails by: dropping `validate_polarity`, which makes the first call load and
/// silently gate nothing.
#[test]
fn the_two_polarities_over_one_projection_are_refused() {
    let contradictory = Fixture::new("args-contradiction")
        .config(
            r#"
version = 1

[[rule]]
id = "cannot-fire"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
when_present = "input-id"
severity = "deny"
reason = "unreachable"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(&contradictory, "mcp__Linear__save_issue", r"{}"),
        Some(1),
        "a row that can never fire is a usage error, not a silently inert gate"
    );

    let over_two = Fixture::new("args-two-projections")
        .config(
            r#"
version = 1

[[rule]]
id = "moved-without-an-id"
kind = "shape"
scope = "mediated_call"
tool = "save_issue"
when_absent = "input-id"
when_present = "input-state"
severity = "deny"
reason = "a move must name the row it moves"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(
            &over_two,
            "mcp__Linear__save_issue",
            r#"{"state":"In Progress"}"#
        ),
        Some(2),
        "different projections are a legitimate conjunction and must still load"
    );
}

/// A `named` receipt is keyed on the subject the call named, not on the branch.
///
/// CLOUD-508's incident replayed: a fresh read of issue A must not authorise a
/// write to issue B. `issue-read-check`'s header is explicit that a branch key
/// would do exactly that — *"a branch legitimately updates several issues"* — so
/// the two subjects resolving to two receipts is the predicate, not an
/// implementation detail.
///
/// Fails by: collapsing the key to `branch`, which makes both calls read one
/// receipt and the second assertion pass for the wrong reason.
#[test]
fn a_receipt_for_one_subject_does_not_authorise_another() {
    let repo = Fixture::new("args-named-receipt")
        .config(
            r#"
version = 1

[[rule]]
id = "read-receipt"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
key_from = "input-id"
severity = "deny"
reason = "read the row before writing it: mise run issue-read-check"
"#,
        )
        .git()
        .base_commit()
        .build();
    // A receipt for A only. Written where the store lives, which is the same
    // path the shell task mints into.
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    std::fs::write(store.join("issue-read.CLOUD-1"), "read_at 1\n").expect("a receipt for A");

    // BOTH SIDES, because one side alone asserts nothing here. A build that
    // ignored the subject and read one file per check would allow both; a build
    // that never consulted the row would also allow both. Only the pair
    // discriminates, and the second assertion is the one CLOUD-508 is about.
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(0),
        "the receipt names CLOUD-1, so writing CLOUD-1 is authorised"
    );
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-2"}"#),
        Some(2),
        "a receipt for CLOUD-1 is not a read of CLOUD-2"
    );
}

/// A subject this engine will not file under is could-not-look, and allows.
///
/// The path-safety refusal. A separator, `..` or a control character in the
/// subject would make the receipt path point somewhere the caller did not name,
/// and `safe_subject` refuses rather than rewriting — rewriting could file two
/// subjects under one receipt, which is the confusion the `named` key exists to
/// prevent. Refusing resolves the whole receipt question to could-not-look, which
/// allows, because a judgement about the shape of an argument is not a judgement
/// about the receipt.
#[test]
fn an_unfileable_subject_is_could_not_look_and_allows() {
    let repo = Fixture::new("args-unsafe-subject")
        .config(
            r#"
version = 1

[[rule]]
id = "read-receipt"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
key_from = "input-id"
severity = "deny"
reason = "read the row before writing it"
"#,
        )
        .git()
        .base_commit()
        .build();
    // THE CONTROL FIRST, because without it every assertion below passes on a
    // build where the row is never consulted at all. A safe subject with no
    // receipt in the store is the row firing.
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(2),
        "a fileable subject with no receipt denies — the row is live in this fixture"
    );
    for unsafe_id in [
        r#"{"id":"../escape"}"#,
        r#"{"id":".."}"#,
        r#"{"id":"a/b"}"#,
        r#"{"id":"a\\b"}"#,
    ] {
        assert_eq!(
            verdict(&repo, "mcp__Linear__save_issue", unsafe_id),
            Some(0),
            "an unfileable subject is not a receipt verdict: {unsafe_id}"
        );
    }
}

/// `key = "named"` and `key_from` travel together, both directions.
///
/// A `named` key with no projection would read one file for every call — the
/// branch key under another name, which is the collapse `ReceiptKey::Named`'s doc
/// refuses. A projection on some other key is a column that reads as configured
/// and is never consulted. Both are load errors rather than silent inertness.
#[test]
fn the_named_key_and_its_projection_travel_together() {
    let no_projection = Fixture::new("args-named-no-from")
        .config(
            r#"
version = 1

[[rule]]
id = "keyed-on-nothing"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
severity = "deny"
reason = "unreachable"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(
            &no_projection,
            "mcp__Linear__save_issue",
            r#"{"id":"CLOUD-1"}"#
        ),
        Some(1),
        "a named key with no projection is a usage error"
    );

    let wrong_key = Fixture::new("args-from-wrong-key")
        .config(
            r#"
version = 1

[[rule]]
id = "branch-keyed-with-a-projection"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "branch"
key_from = "input-id"
severity = "deny"
reason = "unreachable"
"#,
        )
        .git()
        .build();
    assert_eq!(
        verdict(&wrong_key, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(1),
        "a projection on a branch-keyed row is a usage error, not an ignored column"
    );
}

/// The refusal names the row and never the argument's value.
///
/// Rule 4, and the general form matters more than this instance: an issue key is
/// a pointer, but the allowlist's members include prose-bearing ones, so the rule
/// is that a projection may be COMPARED and never echoed. Asserted on a value
/// that would be unmistakable in the output.
#[test]
fn the_refusal_carries_no_argument_value() {
    let repo = repo_gating_creates("args-pointer-only");
    let secret = "hunter2-do-not-echo-me";
    let encoded = serde_json::to_string(secret).expect("encodable");
    let output = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        &payload(
            "mcp__Linear__save_issue",
            &format!("{{\"title\":{encoded}}}"),
        ),
    );
    let rendered = format!(
        "{}{}",
        stderr(&output),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(output.status.code(), Some(2), "the row must refuse");
    assert!(
        rendered.contains("search-before-filing"),
        "the refusal must name the row: {rendered}"
    );
    assert!(
        !rendered.contains(secret),
        "the refusal carried a byte of the call's arguments: {rendered}"
    );
}

/// Move a receipt's mtime `seconds` into the past.
///
/// **Set, never slept for.** A test that waits out its own bound grades on a wall
/// clock, and `.claude/rules/rust.md` is explicit that a timing assertion
/// discriminates nothing here — CLOUD-521 and CLOUD-724 are the recorded cost,
/// one asserting an exact elapsed second and one flaking a `land` lap. `std`'s
/// own `set_times` rather than a new dependency for two lines.
fn backdate(path: &Path, seconds: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(seconds);
    let file = std::fs::File::options()
        .write(true)
        .open(path)
        .expect("the fixture's own receipt is writable");
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("the fixture's own mtime is settable");
}

/// A RECEIPT OLDER THAN THE ROW ALLOWS IS NOT EVIDENCE (CLOUD-988).
///
/// CLOUD-312's row 2 is `issue-read-guard`, and its predicate is CLOUD-508's
/// bound: not *which* row was read but *how recently*. Existence was the whole
/// verdict until `max_age`, so a receipt minted once authorised every later write
/// forever — the defect that issue names.
///
/// Both sides, because one side alone asserts nothing. A fresh receipt must
/// ALLOW, or the column is indistinguishable from a row that refuses everything;
/// a stale one must DENY, or it is indistinguishable from no column at all. The
/// age is set on the file rather than waited for: a test that sleeps past its own
/// bound grades on a wall clock, which is what CLOUD-521 and CLOUD-724 are the
/// recorded cost of.
#[test]
fn a_receipt_older_than_the_row_allows_is_not_evidence() {
    let repo = Fixture::new("args-max-age")
        .config(
            r#"
version = 1

[[rule]]
id = "read-receipt"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
key_from = "input-id"
max_age = 300
severity = "deny"
reason = "read the row again: mise run issue-read-check"
"#,
        )
        .git()
        .base_commit()
        .build();
    let store = repo.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    let receipt = store.join("issue-read.CLOUD-1");
    std::fs::write(&receipt, "read_at 1\n").expect("mint a receipt");

    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(0),
        "a receipt written moments ago is inside the 300s bound"
    );

    // Backdated past the bound by setting the mtime, never by sleeping.
    backdate(&receipt, 3_600);
    assert_eq!(
        verdict(&repo, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(2),
        "an hour-old receipt is past the 300s this row allows"
    );
}

/// A row declaring no bound is unaffected, and `max_age = 0` will not load.
///
/// The first half is what makes the column additive: every committed receipt row
/// keeps meaning exactly what it meant, with existence as the whole verdict. The
/// second is the unsatisfiable-row refusal — a bound of zero expires a receipt the
/// instant it is written, so the row refuses every call while reading from the
/// file as though it permitted a fresh one.
#[test]
fn no_bound_means_existence_and_a_zero_bound_will_not_load() {
    let unbounded = Fixture::new("args-no-max-age")
        .config(
            r#"
version = 1

[[rule]]
id = "read-receipt"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
key_from = "input-id"
severity = "deny"
reason = "read the row before writing it"
"#,
        )
        .git()
        .base_commit()
        .build();
    let store = unbounded.join(".git/batten-receipts");
    std::fs::create_dir_all(&store).expect("the receipt store is creatable");
    let receipt = store.join("issue-read.CLOUD-1");
    std::fs::write(&receipt, "read_at 1\n").expect("mint a receipt");
    backdate(&receipt, 86_400 * 30);
    assert_eq!(
        verdict(&unbounded, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(0),
        "a month-old receipt still satisfies a row that declared no bound"
    );

    let zero = Fixture::new("args-zero-max-age")
        .config(
            r#"
version = 1

[[rule]]
id = "unsatisfiable"
kind = "receipt"
scope = "mediated_call"
tool = "save_issue"
checks = ["issue-read"]
key = "named"
key_from = "input-id"
max_age = 0
severity = "deny"
reason = "unreachable"
"#,
        )
        .git()
        .base_commit()
        .build();
    assert_eq!(
        verdict(&zero, "mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
        Some(1),
        "a bound of zero is a usage error, not a very strict policy"
    );
    let refusal = run_with_stdin(
        &zero,
        &["adjudicate", "--harness", "exit-code"],
        &payload("mcp__Linear__save_issue", r#"{"id":"CLOUD-1"}"#),
    );
    assert!(
        stderr(&refusal).contains("max_age = 0"),
        "the refusal names the column that cannot be satisfied: {}",
        stderr(&refusal)
    );
}

/// The BASE a keyed row resolves comes from an ADMITTED row, never an excluded one.
///
/// The fourth appearance of one defect, and the first test that can see it. The
/// modifier check was added to `tool_rules`, then `matching_receipt_rows`, then
/// `shape_rules` — three call sites in turn, each round leaving the next one out.
/// `Policy::key_base_for` was the one still missing it: it selected through
/// `matching_shape_rows`, which held the command string alone and so could not
/// read a projection of the call's arguments at all.
///
/// What that cost is not the verdict — `shape_rules` re-checks the modifier before
/// refusing — but the EVIDENCE. `key_base_for` returns the `base` of the first
/// `requires_key` row it matches, and the boundary reads commits since that rev.
/// So a row excluded by its own modifier handed the commit range to a later,
/// admitted row, which was then judged against a range it never declared.
///
/// Asserted over `key_base_for` directly because that is where the answer is: it
/// is `pub`, its output IS the base, and a case reading it cannot pass on some
/// other row's verdict. The end-to-end sibling above covers the adjudication half.
///
/// Fails by: reverting `matching_shape_rows` to take `&str`, or moving the
/// `modifier_admits` call back out of it into `shape_rules`. Either way this
/// returns `"excluded-base"`.
#[test]
fn a_keyed_row_excluded_by_its_modifier_does_not_supply_the_base() {
    let dir = std::env::temp_dir().join(format!("batten-keyed-base-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    // TWO keyed rows over one command, declaration order significant. The first
    // is excluded on this call (`input-state` is absent from the payload below);
    // the second is admitted. Different `base` values are what make which row
    // answered observable at all.
    std::fs::write(
        dir.join("batten.toml"),
        r#"version = 1

[[rule]]
id = "excluded-first"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr create"
requires_key = "TEAM-[0-9]+"
base = "excluded-base"
when_present = "input-state"
reason = "this row does not claim a call that names no state"

[[rule]]
id = "admitted-second"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "gh pr create"
requires_key = "TEAM-[0-9]+"
base = "admitted-base"
reason = "publishing needs a key"
"#,
    )
    .expect("write config");
    let resolved = batten::resolve::resolve(&dir, &batten::resolve::Overrides::default())
        .expect("the config resolves");
    let policy =
        batten::hook::Policy::from_resolved(&resolved, batten::hook::Harness::ExitCode, &dir, None)
            .expect("the policy assembles");

    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr create"},
    });
    let call = batten::hook::decode(batten::hook::Harness::ClaudeCode, &payload.to_string())
        .expect("the payload decodes");

    assert_eq!(
        policy.key_base_for(&call),
        Some("admitted-base"),
        "the base must come from the admitted row, not the one its modifier excludes"
    );

    // THE TWIN, and it is what keeps the assertion above from passing on a
    // `key_base_for` that simply never returns the first row. With `state`
    // present the first row IS admitted, so it decides — declaration order,
    // which is the documented tiebreak.
    let named = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr create", "state": "In Review"},
    });
    let named = batten::hook::decode(batten::hook::Harness::ClaudeCode, &named.to_string())
        .expect("the payload decodes");
    assert_eq!(
        policy.key_base_for(&named),
        Some("excluded-base"),
        "admitted on this call, the first row decides — or the case above proves nothing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `pattern`-keyed shape row honours the polarity modifier too.
///
/// `SHAPE_PERMITS` allows `when_absent`/`when_present`/`when_value` on ANY shape
/// row, but only the tool-keyed gate consulted them — so a command-matching row
/// carrying one fired regardless of it. `shape_rules` held the command string
/// alone and structurally could not read a projection of the call's arguments,
/// which is why it now takes the envelope. Caught in review on #680.
///
/// END-TO-END through the binary, not over `shape_rules` directly: the defect was
/// that one evaluator among four ignored the column, and a unit case aimed at the
/// evaluator is exactly the shape that missed it three rounds running.
#[test]
fn a_command_keyed_row_honours_the_polarity_modifier() {
    let repo = Fixture::new("shape-row-modifier")
        .config(
            r#"
version = 1

[[rule]]
id = "no-force-push-while-reviewing"
kind = "shape"
scope = "mediated_call"
severity = "deny"
pattern = "git push"
contains = "--force"
when_present = "input-state"
reason = "a force push while a review is open rewrites what the reviewer read"
"#,
        )
        .git()
        .base_commit()
        .build();

    // The projection is ABSENT, so the row does not fire even though the command
    // matches. This is the assertion the missing modifier check failed.
    let allowed = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force"}}"#,
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "the projection is absent, so the row does not claim this call: {}",
        stderr(&allowed)
    );

    // The same command WITH the projection present is refused — so the case above
    // discriminates the modifier rather than the pattern failing to match.
    let refused = run_with_stdin(
        &repo,
        &["adjudicate", "--harness", "exit-code"],
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force","state":"In Review"}}"#,
    );
    assert_eq!(
        refused.status.code(),
        Some(2),
        "the same command, projection present, is refused: {}",
        stderr(&refused)
    );
    assert!(
        stderr(&refused).contains("no-force-push-while-reviewing"),
        "and by this row: {}",
        stderr(&refused)
    );
}
