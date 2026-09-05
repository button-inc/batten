//! The board-write record, over the compiled binary (CLOUD-1051).
//!
//! # The tier this is, and why the retired suite could not be it
//!
//! `tests/board-write-record.bats` drove a shell program directly. This drives
//! `batten hook`, so it proves the ENGINE builds the record — the seam
//! `.claude/rules/policy-modules.md` names as the one a `with input as` case
//! cannot reach, one layer down: a fabricated invocation passes over a boundary
//! that may be unable to produce the shape at all.
//!
//! # The programs are STUBS, deliberately
//!
//! The retired suite ran the real `ready-lint.sh` and `board-diff-overlap.sh`,
//! so a change to either could redden it — which made it a test of the grammar
//! those own rather than of the recorder. Here each program is a fixture script
//! with a chosen exit status and stdout, so every case below discriminates one
//! property of the RECORDER: the selector, the trust split, the three-valued
//! reads, the column arithmetic, and the create/groom boundary. The two real
//! programs keep their own suites.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! The successor is `recorder.rs` rather than a module: a recorder decides
//! nothing, so there is no predicate for a `.rego` file to hold. It is a policy
//! surface under the gate's own definition (`policy/*.rego` OR
//! `crates/batten/src/*.rs`) for exactly that case.
//!
// carried: mise-tasks/board-write-record.sh crates/batten/src/recorder.rs kind:mechanism crates/batten/tests/it/board_record.rs
// carried: tests/board-write-record.bats crates/batten/src/recorder.rs kind:mechanism crates/batten/tests/it/board_record.rs
//!
//! # RETIREMENT LEDGER — `tests/board-write-record.bats`, 36 cases
//!
//! CARRIED — the property survives, proved here against the engine.
//!
// carried: "a created row is recorded with its id, updatedAt and a green verdict" crates/batten/tests/it/board_record.rs
// carried: "an unrefined row records a verdict of unready rather than being refused" crates/batten/tests/it/board_record.rs
// carried: "a row whose body names a changed file records a non-zero overlap" crates/batten/tests/it/board_record.rs
// carried: "A PATH NAMED ONLY OUTSIDE §1 IS IN THE NAMED COLUMN AND NOT THE §1 ONE" crates/batten/tests/it/board_record.rs
// carried: "a path named IN §1 reaches the §1 column, so a real claim is still visible" crates/batten/tests/it/board_record.rs
// carried: "a row naming nothing tracked records a zero" crates/batten/tests/it/board_record.rs
// carried: "updating an existing row is never recorded" crates/batten/tests/it/board_record.rs
// carried: "a groom of a row THIS branch filed is recorded" crates/batten/tests/it/board_record.rs
// carried: "a groom of a row this branch did NOT file is still skipped" crates/batten/tests/it/board_record.rs
// carried: "an id that merely PREFIXES a filed one does not count as filed here" crates/batten/tests/it/board_record.rs
// carried: "a groom whose §8 cites a blocker is unjudgeable, not unready" crates/batten/tests/it/board_record.rs
// carried: "a groom of a genuinely unready body still records unready" crates/batten/tests/it/board_record.rs
// carried: "a write records the rows its stored body cites" crates/batten/tests/it/board_record.rs
// carried: "a write passing exactly the rows it cites records zero" crates/batten/tests/it/board_record.rs
// carried: "zero and could-not-look are distinguishable in the record" crates/batten/tests/it/board_record.rs
// carried: "the row's own key is not counted as an edge to anywhere" crates/batten/tests/it/board_record.rs
// carried: "a write the producer never ran for records a dash, never a zero" crates/batten/tests/it/board_record.rs
// carried: "a comment records the issue key its input names, not the comment uuid" crates/batten/tests/it/board_record.rs
// carried: "REGRESSION: a comment row never records a uuid" crates/batten/tests/it/board_record.rs
// carried: "a reply, or a comment on a non-issue parent, records a dash rather than a guess" crates/batten/tests/it/board_record.rs
// carried: "all three live connector spellings are recorded identically" crates/batten/tests/it/board_record.rs
// carried: "a tool that does not write to the board is never recorded" crates/batten/tests/it/board_record.rs
// carried: "POINTER, NEVER PAYLOAD: no byte of the description reaches the record" crates/batten/tests/it/board_record.rs
// carried: "POINTER, NEVER PAYLOAD: the citing sentence does not reach the record" crates/batten/tests/it/board_record.rs
// carried: "a comment on a row does not make a later update to it recordable" crates/batten/tests/it/board_record.rs
// carried: "nothing from the body but a tracked path reaches the record" crates/batten/tests/it/board_record.rs
//!
//! SUBSUMED — the plumbing became the engine's, which is what a migration should
//! produce. Each names the general property that now covers it.
//!
// subsumed: "FAIL OPEN: an unreadable, nameless or resultless payload records nothing and says nothing" crates/batten/src/lib.rs kind:mechanism
// subsumed: "FAIL OPEN: a flat tool_response is not the MCP envelope and records nothing" crates/batten/src/facts.rs kind:mechanism
// subsumed: "FAIL OPEN: a detached HEAD has no branch to key a record to" crates/batten/src/lib.rs kind:mechanism
// subsumed: "FAIL OPEN: outside a git repository nothing is recorded and nothing is blocked" crates/batten/src/lib.rs kind:mechanism
// subsumed: "the settings entry is wired, on a suffix-anchored PostToolUse matcher" mise-tasks/hooks-wiring-check.sh
// subsumed: "the keys come from ready-lint's emission, not a second scan here" crates/batten/src/recorder.rs kind:mechanism
// subsumed: "a row whose §8 claims a blocker still records a green verdict" crates/batten/tests/it/board_record.rs
// subsumed: "A CREATE CITING A BLOCKER IT DID NOT PASS IS STILL UNREADY" crates/batten/tests/it/board_record.rs
//!
//! CHANGED — behaviour that diverges deliberately, each with its reason.
//!
// changed: "board-write-record.bats::the bypass is honoured" crates/batten/src/recorder.rs kind:mechanism BATTEN_BOARD_WRITE_BYPASS is gone rather than ported: a bypass exists to let an author past a REFUSAL, and a recorder refuses nothing, so the only thing it could buy was a quieter record — the one direction the gate reading it cannot detect
// changed: "board-write-record.bats::A FILE THIS BRANCH HAS NOT TOUCHED IS STILL RECORDED" crates/batten/tests/it/board_record.rs the overlap column holds the paths the body NAMES, intersected by the gate later rather than here, so the case is carried under a name that says what it measures
//!
//! `BATTEN_BOARD_WRITE_BYPASS` is **gone rather than ported**, and that is a
//! deliberate narrowing rather than an oversight. A bypass exists to let an
//! author past a REFUSAL; a recorder refuses nothing, so the only thing that
//! variable could buy was a quieter record — which is the one direction the gate
//! reading it cannot detect, since it passes on could-not-look by design. A
//! caller who wants no record removes the `[[recorder]]` row, which is a visible
//! config change rather than an invisible environment one. The engine's own
//! `BATTEN_HOOK_BYPASS` still suppresses the whole mediated path.
//!
//! The overlap column's meaning is unchanged — it holds the paths the body NAMES,
//! intersected later by the gate — so the retired case asserting an untouched
//! file is still recorded is carried under a name that says what it measures.

//! # UNIX-ONLY, and the narrowing costs nothing this replaced
//!
//! Every case here drives a `[[recorder]]` whose interesting columns are
//! PROGRAM-derived, and the fixtures are `#!/bin/sh` stubs. On a Windows runner
//! the spawn ladder's third rung resolves the interpreter a shebang names, and
//! `/bin/sh` is not a program a Windows runner can start — so every column came
//! back could-not-look and the suite asserted the ladder rather than the
//! recorder. `bundle.rs` gates its whole suite for exactly this reason and cites
//! the same row (CLOUD-113).
//!
//! The narrowing is smaller than it looks: `tests/board-write-record.bats`, the
//! suite this replaces, never ran on Windows either. What would be lost by
//! writing a `.cmd` fixture instead is the point of the stubs — their status and
//! stdout are chosen per case, so a column's value is a function of the
//! DECLARATION, and a second per-platform fixture grammar would be a second
//! authority over what the recorder read.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{run_with_stdin, scratch};

/// A fixture repository with a recorder table and two stub programs.
///
/// The stubs are what make each case below a test of the RECORDER: their status
/// and stdout are chosen per fixture, so a column's value is a function of the
/// declaration rather than of a grammar some other file owns.
fn repo(name: &str, lint_exit: i32, lint_stdout: &str, paths_stdout: &str) -> PathBuf {
    let dir = scratch(name);
    write_program(&dir, "lint.sh", lint_exit, lint_stdout);
    write_program(&dir, "paths.sh", 0, paths_stdout);
    fs::write(dir.join("batten.toml"), CONFIG).expect("write config");
    git(&dir, &["init", "--quiet", "--initial-branch", "work"]);
    git(&dir, &["config", "user.email", "t@example.com"]);
    git(&dir, &["config", "user.name", "t"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "--quiet", "-m", "seed"]);
    dir
}

fn write_program(dir: &Path, name: &str, exit: i32, stdout: &str) {
    let path = dir.join(name);
    fs::write(
        &path,
        // `%s\n` with the newline OWNED HERE rather than embedded in the
        // argument: a `\n` inside the Rust literal reaches bash escaped, so
        // `printf '%s'` prints it verbatim and glues it to the last token.
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' {stdout:?}\nexit {exit}\n"),
    )
    .expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
}

#[expect(
    clippy::disallowed_types,
    reason = "stays — a fixture repository needs real git history for the branch key the \
              recorder files under, and `git.rs`'s own test fixtures are the precedent. \
              Test-only, so no shipped path spawns here."
)]
fn git(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

/// The record this branch accumulated, or the empty string when none was written.
fn record(dir: &Path) -> String {
    fs::read_to_string(dir.join(".git/batten-receipts/board-writes.work")).unwrap_or_default()
}

/// Mint a claim receipt naming `ids`, the way `claim check` does on its pullable
/// path (CLOUD-1300).
///
/// Line 1 is the id list and `claim::mint` says so in as many words, so the
/// fixture writes the documented position rather than a shape guessed here.
fn claim(dir: &Path, ids: &str) {
    let receipts = dir.join(".git/batten-receipts");
    fs::create_dir_all(&receipts).expect("receipts dir");
    fs::write(
        receipts.join("claim.work"),
        format!("{ids}\nready-lint pass\nclaimed-at 2026-09-01T00:00:00Z\n"),
    )
    .expect("write claim");
}

/// The record filed under one claim's partition.
fn record_under(dir: &Path, claim: &str) -> String {
    fs::read_to_string(dir.join(format!(".git/batten-receipts/board-writes.work.{claim}")))
        .unwrap_or_default()
}

/// A `PostToolUse` envelope carrying an MCP content-block response.
fn payload(tool: &str, input: &str, result: &str) -> String {
    // The MCP envelope, which is the shape a connector actually sends: a
    // content-block list whose text is the row as JSON. The retired suite's
    // header recorded this as measured rather than assumed, because a body
    // written against the documented flat-object shape reads nothing.
    let text = serde_json::to_string(result).expect("encode result");
    let blocks = format!(r#"[{{"type":"text","text":{text}}}]"#);
    format!(
        r#"{{"hook_event_name":"PostToolUse","tool_name":{tool:?},"tool_input":{input},"tool_response":{blocks}}}"#
    )
}

fn hook(dir: &Path, tool: &str, input: &str, result: &str) {
    let output = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &payload(tool, input, result),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a recorder refuses nothing, so the call is always allowed"
    );
}

const CONFIG: &str = r#"
version = 1

[program.lint]
path = "lint.sh"

[program.paths]
path = "paths.sh"

[[pattern]]
id = "clause-label"
regex = '^\*\*[^*]*\(§[0-9]+\)'

[[pattern]]
id = "clause-one"
regex = '\(§1\)'

[[recorder]]
name = "created"
record = "board-writes"
tool = "save_issue"
key = "branch"
requires = ["id"]
refused-when-input = ["id"]

[[recorder.columns]]
name = "kind"
value = { literal = "issue" }

[[recorder.columns]]
name = "id"
value = { result = "id" }

[[recorder.columns]]
name = "updated"
value = { result = "updatedAt" }

[[recorder.columns]]
name = "verdict"
value = { program = { run = "lint", read = { status = { "0" = "ready", "1" = "unready" } }, stdin = { object = { id = { result = "id" }, description = { result = "description" }, relations = { object = { blockedBy = { wrap = { from = "blockedBy[]", key = "id" } } } } } } } }

[[recorder.columns]]
name = "overlap"
value = { program = { run = "paths", read = "stdout", stdin = { result = "description" } } }
zero-is-a-count = true

[[recorder.columns]]
name = "cites"
value = { program = { run = "lint", read = { stdout-line = "cites-body " }, stdin = { result = "description" } } }
minus = { inputs = ["relatedTo[]", "blockedBy[]", "blocks[]"] }
without = { result = "id" }
counted-with = ":"
zero-is-a-count = true

[[recorder.columns]]
name = "sec1"
value = { program = { run = "paths", read = "stdout", stdin = { section = { from = { result = "description" }, label = "clause-label", select = "clause-one" } } } }

[[recorder]]
name = "groomed"
record = "board-writes"
tool = "save_issue"
key = "branch"
requires = ["id"]
requires-recorded = { matches = { 0 = { literal = "issue" }, 1 = { result = "id" } } }

[[recorder.columns]]
name = "kind"
value = { literal = "issue" }

[[recorder.columns]]
name = "id"
value = { result = "id" }

[[recorder.columns]]
name = "updated"
value = { result = "updatedAt" }

[[recorder.columns]]
name = "verdict"
value = { program = { run = "lint", read = { status = { "0" = "ready", "1" = "unready" } }, stdin = { object = { id = { result = "id" }, description = { result = "description" } } } } }

[[recorder]]
name = "comment"
record = "board-writes"
tool = "save_comment"
key = "branch"
requires = ["id"]

[[recorder.columns]]
name = "kind"
value = { literal = "comment" }

[[recorder.columns]]
name = "id"
value = { input = "issueId" }

[[recorder.columns]]
name = "verdict"
value = { literal = "-" }
"#;

#[test]
fn a_created_row_is_recorded_with_its_id_updated_at_and_a_green_verdict() {
    let dir = repo("record-create", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"a finding"}"#,
        r#"{"id":"CLOUD-1","updatedAt":"2026-08-26T00:00:00Z","description":"body"}"#,
    );
    let line = record(&dir);
    let columns: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(columns[0], "issue", "got: {line:?}");
    assert_eq!(columns[1], "CLOUD-1", "got: {line:?}");
    assert_eq!(columns[2], "2026-08-26T00:00:00Z", "got: {line:?}");
    assert_eq!(columns[3], "ready", "got: {line:?}");
}

#[test]
fn an_unrefined_row_records_unready_rather_than_being_refused() {
    // The direction that matters: a recorder never refuses, so the write lands
    // and the verdict is what a later gate reads.
    let dir = repo("record-unready", 1, "", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-2","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(3),
        Some("unready"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn a_status_no_row_maps_is_could_not_look_never_a_refusal() {
    // CARRIES "a groom whose §8 cites a blocker is unjudgeable, not unready" and
    // "a write the producer never ran for records a dash, never a zero". The
    // retired program's exit 2 meant COULD NOT JUDGE, and folding anything
    // non-zero into the refusal would record a verdict about the environment
    // wearing the mask of a verdict about the row.
    let dir = repo("record-unjudgeable", 2, "", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-3","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(3),
        Some("-"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn zero_and_could_not_look_are_distinguishable_in_the_record() {
    // CLOUD-251's split, and the one this record shape cannot afford to lose: the
    // gate downstream PASSES on `-` by design, so a real measurement of nothing
    // rendering as `-` would be a finding silently waived.
    let dir = repo("record-zero", 0, "cites-body ", "");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-4","updatedAt":"t","description":"body"}"#,
    );
    let line = record(&dir);
    let columns: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        columns[4], "0",
        "an asked question that found nothing: {line:?}"
    );
    assert_eq!(
        columns[6], "-",
        "a narrowing that yielded no span is could-not-look: {line:?}"
    );
}

#[test]
fn a_row_whose_body_names_a_changed_file_records_a_non_zero_overlap() {
    let dir = repo("record-overlap", 0, "cites-body ", "2 a.rs b.rs");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-5","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(4),
        Some("2,a.rs,b.rs"),
        "one column, one token: {:?}",
        record(&dir)
    );
}

#[test]
fn a_path_named_only_outside_section_one_is_not_in_the_section_one_column() {
    // CLOUD-854's discriminator. A path-name intersection cannot tell a row
    // CLAIMING work on a file from one CITING it as evidence, so §1 — which names
    // the source of truth by construction — is read separately.
    let dir = repo("record-sec1-absent", 0, "cites-body ", "1 a.rs");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-6","updatedAt":"t","description":"**Evidence (§2).**\nmeasured on a.rs"}"#,
    );
    let line = record(&dir);
    let columns: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        columns[4], "1,a.rs",
        "the named column still sees it: {line:?}"
    );
    assert_eq!(
        columns[6], "-",
        "no §1 span, so the §1 column could not look: {line:?}"
    );
}

#[test]
fn a_path_named_in_section_one_reaches_the_section_one_column() {
    // The discriminator for the case above: without this, the §1 column could be
    // permanently `-` and the pair would still pass.
    let dir = repo("record-sec1-present", 0, "cites-body ", "1 a.rs");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-7","updatedAt":"t","description":"**Source of truth (§1).**\na.rs"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(6),
        Some("1,a.rs"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn updating_an_existing_row_is_never_recorded() {
    // An `id` in the INPUT is an update to a row that already exists, which is
    // not a board write this branch is answerable for.
    let dir = repo("record-update", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-8"}"#,
        r#"{"id":"CLOUD-8","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(record(&dir), "", "nothing recorded: {:?}", record(&dir));
}

#[test]
fn a_groom_of_a_row_this_branch_filed_is_recorded() {
    // CLOUD-514's third remedy, and without this it is unreachable: the gate
    // tells a branch to groom its unrefined row and re-run, but a groom carries
    // an id, so the create row refuses it and the creation-time verdict stands.
    let dir = repo("record-groom", 1, "", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-9","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(record(&dir).lines().count(), 1, "the create");

    // The groom, now that the record names this subject.
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-9"}"#,
        r#"{"id":"CLOUD-9","updatedAt":"t2","description":"groomed"}"#,
    );
    let written = record(&dir);
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(lines.len(), 2, "the groom is a second line: {lines:?}");
    assert!(lines[1].contains("CLOUD-9"), "got: {lines:?}");
}

#[test]
fn a_groom_of_a_row_this_branch_did_not_file_is_still_skipped() {
    // The narrowing that keeps the exception from becoming a hole: re-judging a
    // row this branch never filed would let it be re-judged on its own say-so.
    let dir = repo("record-groom-foreign", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-99"}"#,
        r#"{"id":"CLOUD-99","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(record(&dir), "", "nothing recorded: {:?}", record(&dir));
}

#[test]
fn an_id_that_merely_prefixes_a_filed_one_does_not_count_as_filed_here() {
    // The whole-column comparison, and the reason it is a column rather than a
    // substring: `CLOUD-1` must not match the `CLOUD-17` line beside it.
    let dir = repo("record-prefix", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-17","updatedAt":"t","description":"body"}"#,
    );
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-1"}"#,
        r#"{"id":"CLOUD-1","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).lines().count(),
        1,
        "the prefix did not admit a groom: {:?}",
        record(&dir)
    );
}

#[test]
fn a_write_records_the_rows_its_stored_body_cites() {
    let dir = repo("record-cites", 0, "cites-body CLOUD-20 CLOUD-21", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-10","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(5),
        Some("2:CLOUD-20,CLOUD-21"),
        "a count and the far-end keys: {:?}",
        record(&dir)
    );
}

#[test]
fn a_write_passing_exactly_the_rows_it_cites_records_zero() {
    // The set difference: a row passed as a relation is not "minted by prose"
    // however the body also mentions it.
    let dir = repo("record-cites-passed", 0, "cites-body CLOUD-20", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"relatedTo":["CLOUD-20"]}"#,
        r#"{"id":"CLOUD-11","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(5),
        Some("0"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn the_rows_own_key_is_not_counted_as_an_edge_to_anywhere() {
    let dir = repo("record-self-cite", 0, "cites-body CLOUD-12", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        r#"{"id":"CLOUD-12","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(5),
        Some("0"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn a_comment_records_the_issue_key_its_input_names_never_the_comment_uuid() {
    // REGRESSION, measured on the retired recorder's first five live rows: a
    // `save_comment` response is the COMMENT object, so its `id` is the comment's
    // own uuid and names no row. A uuid in an issue-key column is a wrong answer
    // wearing a right answer's shape.
    let dir = repo("record-comment", 0, "", "0");
    let uuid = "4d16245a-43ea-49ae-b67d-c2ee0b64b96e";
    hook(
        &dir,
        "mcp__Linear__save_comment",
        r#"{"issueId":"CLOUD-13"}"#,
        &format!(r#"{{"id":"{uuid}"}}"#),
    );
    let line = record(&dir);
    assert_eq!(
        line.split_whitespace().nth(1),
        Some("CLOUD-13"),
        "got: {line:?}"
    );
    assert!(!line.contains(uuid), "no uuid reaches the record: {line:?}");
}

#[test]
fn a_reply_or_a_comment_on_a_non_issue_parent_records_a_dash_rather_than_a_guess() {
    // A reply carries `parentId` and no `issueId`; the thread determines the
    // issue, which this boundary cannot see. Could-not-look, never a fallback.
    let dir = repo("record-reply", 0, "", "0");
    hook(
        &dir,
        "mcp__Linear__save_comment",
        r#"{"parentId":"abc"}"#,
        r#"{"id":"def"}"#,
    );
    assert_eq!(
        record(&dir).split_whitespace().nth(1),
        Some("-"),
        "got: {:?}",
        record(&dir)
    );
}

#[test]
fn a_comment_on_a_row_does_not_make_a_later_update_to_it_recordable() {
    // The groom precondition reads column 1 of any line, so a comment line for a
    // subject must not be mistaken for this branch having FILED it.
    let dir = repo("record-comment-then-update", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_comment",
        r#"{"issueId":"CLOUD-14"}"#,
        r#"{"id":"uuid"}"#,
    );
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"id":"CLOUD-14"}"#,
        r#"{"id":"CLOUD-14","updatedAt":"t","description":"body"}"#,
    );
    let lines = record(&dir);
    assert_eq!(
        lines.lines().count(),
        1,
        "only the comment; the update was not admitted: {lines:?}"
    );
    assert!(lines.starts_with("comment"), "got: {lines:?}");
}

#[test]
fn all_three_live_connector_spellings_are_recorded_identically() {
    // CLOUD-178: the same connector was exposed under three names over its
    // lifetime, so a selector naming one matches none of the others and the miss
    // is silent.
    for (index, tool) in [
        "mcp__Linear__save_issue",
        "mcp__b7f2__save_issue",
        "mcp__claude_ai_Linear__save_issue",
    ]
    .into_iter()
    .enumerate()
    {
        let dir = repo(&format!("record-spelling-{index}"), 0, "cites-body ", "0");
        hook(
            &dir,
            tool,
            "{}",
            r#"{"id":"CLOUD-15","updatedAt":"t","description":"body"}"#,
        );
        assert!(
            record(&dir).starts_with("issue CLOUD-15"),
            "{tool} recorded nothing: {:?}",
            record(&dir)
        );
    }
}

#[test]
fn a_tool_that_does_not_write_to_the_board_is_never_recorded() {
    let dir = repo("record-other-tool", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__get_issue",
        "{}",
        r#"{"id":"CLOUD-16","updatedAt":"t","description":"body"}"#,
    );
    assert_eq!(record(&dir), "", "nothing recorded: {:?}", record(&dir));
}

#[test]
fn pointer_never_payload_no_byte_of_the_description_reaches_the_record() {
    // Non-negotiable rule 4, and it is load-bearing here rather than decorative:
    // the text this reads is an entire issue body.
    let sentence = "SENTINELPROSE that must not travel";
    let dir = repo("record-pointer", 0, "cites-body CLOUD-30", "1 a.rs");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        "{}",
        &format!(
            r#"{{"id":"CLOUD-18","updatedAt":"t","description":"**Source of truth (§1).**\n{sentence} a.rs"}}"#
        ),
    );
    let line = record(&dir);
    assert!(!line.is_empty(), "the row was recorded");
    assert!(
        !line.contains("SENTINELPROSE"),
        "no prose reaches the record: {line:?}"
    );
    assert!(line.contains("a.rs"), "only a tracked path does: {line:?}");
}

// --- the claim partition (CLOUD-1300) ----------------------------------------
//
// A branch NAME outlives the branch it described. `git checkout -B <name>
// origin/main` discards the commits that were the branch while every name-keyed
// file survives — CLOUD-516's finding, which the claim receipt answers for itself
// by recording its base. A recorder's record had no such discriminator, so the
// next attempt on a reused name read the previous one's lines as its own.

/// THE DANGEROUS DIRECTION, AND IT IS THE ONE A NAIVE SUITE MISSES: a record
/// written under one claim is not read under the next.
///
/// Measured before the fix, on this repository's own branch: after PR #810 merged
/// and the branch was reset, `pr-closes.<branch>` still named that PR's keys, and
/// `filed-over-own-diff`'s exemption was evaluated against them. A row the
/// PREVIOUS PR closed would have been exempted on a PR that does not close it —
/// silently, with nothing downstream to re-check.
#[test]
fn a_record_from_a_previous_claim_is_not_read_under_the_next() {
    let dir = repo("record-claim-partition", 0, "cites-body ", "0");

    claim(&dir, "CLOUD-1");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"first attempt"}"#,
        r#"{"id":"CLOUD-1","updatedAt":"2026-08-26T00:00:00Z","description":"body"}"#,
    );
    assert!(
        record_under(&dir, "CLOUD-1").contains("CLOUD-1"),
        "the first attempt files under its own claim: {:?}",
        record_under(&dir, "CLOUD-1")
    );

    // The branch is reset and re-claimed for different work. Same branch NAME,
    // same record name, a different attempt.
    claim(&dir, "CLOUD-2");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"second attempt"}"#,
        r#"{"id":"CLOUD-2","updatedAt":"2026-08-27T00:00:00Z","description":"body"}"#,
    );

    let second = record_under(&dir, "CLOUD-2");
    assert!(
        second.contains("CLOUD-2"),
        "the second attempt records its own row: {second:?}"
    );
    assert!(
        !second.contains("CLOUD-1"),
        "AND IT DOES NOT INHERIT THE FIRST'S. This is the false-exemption \
         direction: a key from a finished attempt must not answer for this one. \
         Got: {second:?}"
    );
}

/// THE ANTI-VACUITY MIRROR FOR THE PARTITION. Without it the case above is
/// satisfied by a partition so eager that a record never survives at all — which
/// would break the thing records exist for, since `land` rebases every lap and a
/// record discarded per lap is a record no gate can read.
#[test]
fn one_claim_accumulates_across_calls() {
    let dir = repo("record-claim-stable", 0, "cites-body ", "0");
    claim(&dir, "CLOUD-1");

    for id in ["CLOUD-7", "CLOUD-8"] {
        hook(
            &dir,
            "mcp__Linear__save_issue",
            r#"{"title":"same attempt"}"#,
            &format!(r#"{{"id":"{id}","updatedAt":"2026-08-26T00:00:00Z","description":"body"}}"#),
        );
    }

    let lines = record_under(&dir, "CLOUD-1");
    assert!(
        lines.contains("CLOUD-7") && lines.contains("CLOUD-8"),
        "both writes of one attempt land in one record: {lines:?}"
    );
}

/// AN UNCLAIMED BRANCH KEEPS THE OLD PATH, which is what makes this a partition
/// rather than a migration: nothing that could not be attributed is moved, and a
/// reader of an unclaimed branch sees exactly what it saw before.
#[test]
fn an_unclaimed_branch_records_where_it_always_did() {
    let dir = repo("record-claim-absent", 0, "cites-body ", "0");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"no claim"}"#,
        r#"{"id":"CLOUD-3","updatedAt":"2026-08-26T00:00:00Z","description":"body"}"#,
    );
    assert!(
        record(&dir).contains("CLOUD-3"),
        "could-not-look keeps the unpartitioned path: {:?}",
        record(&dir)
    );
}

/// The order two keys were claimed in does not partition them apart, or a
/// re-claim of the same work would be invisible to its own record.
#[test]
fn a_multi_key_claim_is_order_insensitive() {
    let dir = repo("record-claim-order", 0, "cites-body ", "0");

    claim(&dir, "CLOUD-9 CLOUD-4");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"two keys"}"#,
        r#"{"id":"CLOUD-9","updatedAt":"2026-08-26T00:00:00Z","description":"body"}"#,
    );

    claim(&dir, "CLOUD-4 CLOUD-9");
    hook(
        &dir,
        "mcp__Linear__save_issue",
        r#"{"title":"same two keys, listed the other way"}"#,
        r#"{"id":"CLOUD-5","updatedAt":"2026-08-27T00:00:00Z","description":"body"}"#,
    );

    let lines = record_under(&dir, "CLOUD-4-CLOUD-9");
    assert!(
        lines.contains("CLOUD-9") && lines.contains("CLOUD-5"),
        "one attempt, one record, whichever order the keys were listed in: {lines:?}"
    );
}
