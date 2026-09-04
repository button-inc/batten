//! The landing-lease record, over the compiled binary (CLOUD-1298).
//!
//! # The tier this is, and what the preset's own suite structurally cannot prove
//!
//! `lease-authorises-the-branch` is a vendored preset, and
//! `crates/batten/tests/it/policy_presets.rs` already proves the PREDICATE decides
//! for a consumer with no vocabulary of its own. What neither that tier nor the
//! module's `test_` rules can prove is that the ENGINE writes the line the
//! predicate reads — a `with input as` case fabricates exactly the shape the
//! boundary may be unable to produce, which is CLOUD-845's class one layer down.
//!
//! So this drives `batten hook` and reads the file back off disk. It is the half
//! of the mechanism the preset cannot test, and the half where a wrong `[program]`
//! argv or a wrong `status` table is SILENT — both of which happened while this
//! row was being built.
//!
//! # The programs are STUBS, deliberately
//!
//! Driving the real `land-lock.sh` would make these cases a test of that program's
//! grammar and would need a remote to observe. Each stub has a chosen exit status
//! and stdout, so every case discriminates one property of the RECORDER: the
//! selector, the freshness mapping, the fail-open omission, and the branch column.
//! `land-lock.sh` keeps its own suite.

#![cfg(unix)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{run_with_stdin, scratch};

/// A fixture repository on a known branch, with both lease programs stubbed.
fn repo(name: &str, status_exit: i32, peek_stdout: &str) -> PathBuf {
    let dir = scratch(name);
    write_program(&dir, "status.sh", status_exit, "");
    write_program(&dir, "peek.sh", 0, peek_stdout);
    fs::write(dir.join("batten.toml"), CONFIG).expect("write config");
    commit_on_work(&dir);
    dir
}

/// The git history the recorder needs, and the ONE place it is built.
///
/// Written once rather than per fixture builder: the branch this seeds is the
/// key the record is filed under, so two builders spelling it separately is a
/// fixture that can drift from the path every case reads back.
fn commit_on_work(dir: &Path) {
    git(dir, &["init", "--quiet", "--initial-branch", "work"]);
    git(dir, &["config", "user.email", "t@example.com"]);
    git(dir, &["config", "user.name", "t"]);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "--quiet", "-m", "seed"]);
}

/// `printf '%s'` with NO trailing newline, so an empty stdout is genuinely empty.
///
/// `board_record.rs`'s stub writer appends one; here it would make the "no
/// reservation" case indistinguishable from a one-character answer, and that case
/// is exactly what the successor column's could-not-look reading turns on.
fn write_program(dir: &Path, name: &str, exit: i32, stdout: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let path = dir.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' {stdout:?}\nexit {exit}\n"),
    )
    .expect("write stub");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
}

#[expect(
    clippy::disallowed_types,
    reason = "stays — a fixture repository needs real git history for the branch key the \
              recorder files under, and `board_record.rs` is the precedent. Test-only, so no \
              shipped path spawns here."
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
    fs::read_to_string(dir.join(".git/batten-receipts/landing-lease.work")).unwrap_or_default()
}

/// The columns of the one line the record carries.
fn columns(line: &str) -> Vec<&str> {
    line.trim_end().split(' ').collect()
}

fn hook(dir: &Path, command: &str) {
    let input = serde_json::to_string(command).expect("encode command");
    let payload = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{{"command":{input}}},"tool_response":{{"stdout":"","exit_code":0}}}}"#
    );
    let output = run_with_stdin(dir, &["adjudicate", "--harness", "exit-code"], &payload);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a recorder refuses nothing, so the call is always allowed"
    );
}

/// The committed table's own shape, with the two programs pointed at stubs.
///
/// The `status` table maps only the two ANSWERING exit codes and deliberately
/// leaves could-not-look unmapped — that omission is the fail-open half, and one
/// case below is what holds it.
const CONFIG: &str = r#"
version = 1

[program.land-lock-status]
path = "status.sh"

[program.land-lock-peek]
path = "peek.sh"

[[pattern]]
id = "landing-lifecycle-call"
regex = '(?:^|&&|;|\|)\s*mise run linear-check\b'

[[recorder]]
name = "landing-lease"
record = "landing-lease"
tool = "Bash"
key = "branch"
requires-input-matching = { command = "landing-lifecycle-call" }

[[recorder.columns]]
name = "kind"
value = { literal = "lease" }

[[recorder.columns]]
name = "verdict"
value = { program = { run = "land-lock-status", read = { status = { "0" = "authorised", "1" = "held-elsewhere" } }, stdin = { literal = "" } } }

[[recorder.columns]]
name = "successor"
value = { program = { run = "land-lock-peek", read = "stdout", stdin = { literal = "" } } }

[[recorder.columns]]
name = "branch"
value = "branch"
"#;

/// The round trip: the engine writes a lease line, and it reads back in the shape
/// the predicate parses — four space-separated columns led by the generic kind.
#[test]
fn the_engine_writes_a_lease_line_the_predicate_can_parse() {
    let dir = repo("lease-roundtrip", 0, "");
    hook(&dir, "mise run linear-check");

    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(
        columns.len(),
        4,
        "the predicate asserts a count of four, so a fifth column re-lenses every \
         line silently: {line:?}"
    );
    assert_eq!(
        columns[0], "lease",
        "the generic kind the preset selects on"
    );
    assert_eq!(
        columns[1], "authorised",
        "exit 0 maps to the allowing token"
    );
    assert_eq!(
        columns[3], "work",
        "THE BRANCH COLUMN IS POPULATED, which is the whole of `Value::Branch`. A \
         dash here means the admitted-successor row can never match and the port \
         fails CLOSED where the bash it replaces allows."
    );
}

/// A lease held by another clone maps to the refusing token — the deny half.
#[test]
fn a_lease_held_elsewhere_maps_to_the_refusing_token() {
    let dir = repo("lease-held", 1, "");
    hook(&dir, "mise run linear-check");
    let line = record(&dir);
    assert_eq!(
        columns(&line)[1],
        "held-elsewhere",
        "exit 1 maps to the token the predicate refuses on: {line:?}"
    );
}

/// THE FAIL-OPEN HALF, AND IT IS AN OMISSION RATHER THAN A CLAUSE.
///
/// The producer fails CLOSED where it cannot observe the lease; the bash the
/// predicate replaces deliberately does not, because "a lease it cannot read stops
/// EVERY job in the fleet, where waving one matrix through costs one matrix". The
/// `status` table restores that by mapping only the answering codes, so an unmapped
/// status records could-not-look, which equals neither token.
///
/// ASSERTED ON THE RECORDED TOKEN, NOT ON THE FILE. A case that only checked a line
/// was written would pass over a table that DID map `2` — which is the edit this
/// case exists to catch, since adding that row inverts the one behaviour the port
/// exists to conserve.
#[test]
fn a_status_the_table_does_not_map_records_could_not_look_and_never_a_verdict() {
    let dir = repo("lease-unreadable", 2, "");
    assert!(record(&dir).is_empty(), "nothing recorded before the call");

    hook(&dir, "mise run linear-check");
    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(
        columns[1], "-",
        "an unmapped status is could-not-look, so the refusal cannot hold: {line:?}"
    );
    assert_ne!(columns[1], "held-elsewhere", "and it is NOT the refusal");
}

/// The successor field reaches the record when the producer prints one.
///
/// This is the case a wrong `[program]` argv makes silent: `land-lock peek` with no
/// field argument exits 2 and prints a USAGE line to stdout, `render_column` folds
/// its whitespace so the record's shape survives, and the successor column then
/// carries prose that can never equal a branch — a fail-closed deviation on the one
/// row `Value::Branch` exists to keep open.
#[test]
fn the_successor_field_reaches_the_record_when_one_stands() {
    let dir = repo("lease-successor", 1, "work");
    hook(&dir, "mise run linear-check");
    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(
        columns[2], "work",
        "the reserved branch, verbatim: {line:?}"
    );
    assert_eq!(
        columns[2], columns[3],
        "and it equals the branch column, which is what admits this lap"
    );
}

/// No reservation is could-not-look in the column, and *not this branch* to the
/// predicate — correct here and only here, because by the time it is compared the
/// lease is already known live and known to name somebody else.
#[test]
fn no_reservation_records_could_not_look_rather_than_an_empty_field() {
    let dir = repo("lease-no-successor", 1, "");
    hook(&dir, "mise run linear-check");
    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(columns[2], "-", "an empty stdout is a dash: {line:?}");
    assert_ne!(
        columns[2], columns[3],
        "so it cannot accidentally admit this branch"
    );
}

/// THE ANTI-VACUITY MIRROR FOR THE SELECTOR. Without it every case above is
/// satisfied by a recorder that fires on everything — the shape priced and rejected
/// in the row's own comment, since it would put a remote lease observation on the
/// mediated path of every call.
#[test]
fn a_call_the_selector_does_not_name_writes_nothing_at_all() {
    let dir = repo("lease-unselected", 0, "");
    hook(&dir, "git status");
    assert!(
        record(&dir).is_empty(),
        "an ordinary call spawns nothing and records nothing: {:?}",
        record(&dir)
    );
}

// --- the COMPILED arm (CLOUD-1148 §2) ---------------------------------------
//
// `batten.toml` no longer runs a `[program]` for either lease column: the paths
// those rows named are retired, and a `[program]` path resolves against the
// repository root, so neither could ever have named the compiled verb. The
// columns ask `authority = { ask = "lease-status" | "lease-successor" }`, which
// is CLOUD-1100's landed move for `ready-lint.sh` applied to the same shape.
//
// THE STUB CASES ABOVE STAY, AND THEY ARE NOT DEAD. They pin the RECORDER — the
// selector, the `status` mapping, the fail-open omission, the branch column —
// over an arm whose producer is chosen by the fixture. What they cannot pin is
// that the compiled arm is reached at all, and a `Value::Authority` naming a
// variant nothing dispatches would leave every case above green.
//
// A REAL LEASE IS NOT DRIVEN HERE, and the bound is stated rather than absorbed:
// the arm observes a remote ref, so proving the authorising and held-elsewhere
// answers needs a lease server. What IS drivable is the answer these fixtures
// genuinely produce — a clone with no remote — and that is the one arm the
// asymmetry turns on.

/// A repository with the lease columns on the COMPILED arm and a `status` table
/// the caller chooses.
fn compiled_repo(name: &str, status_table: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(
        dir.join("batten.toml"),
        COMPILED_CONFIG.replace("STATUS_TABLE", status_table),
    )
    .expect("write config");
    commit_on_work(&dir);
    dir
}

/// The shipped shape with no `[program]` table at all — which is the point: a
/// config declaring none still records both lease columns.
const COMPILED_CONFIG: &str = r#"
version = 1

[[pattern]]
id = "landing-lifecycle-call"
regex = '(?:^|&&|;|\|)\s*mise run linear-check\b'

[[recorder]]
name = "landing-lease"
record = "landing-lease"
tool = "Bash"
key = "branch"
requires-input-matching = { command = "landing-lifecycle-call" }

[[recorder.columns]]
name = "kind"
value = { literal = "lease" }

[[recorder.columns]]
name = "verdict"
value = { authority = { ask = "lease-status", read = { status = STATUS_TABLE }, stdin = { literal = "" } } }

[[recorder.columns]]
name = "successor"
value = { authority = { ask = "lease-successor", read = "stdout", stdin = { literal = "" } } }

[[recorder.columns]]
name = "branch"
value = "branch"
"#;

/// **THE UNCONDITIONAL ARM.** A probe table that maps could-not-look, so the
/// column carries a token only a producer that actually ran can have produced.
///
/// `.claude/rules/policy-modules.md` states the rule this case exists to obey:
/// confirm a channel with an arm that must speak, never with an arm over the
/// channel itself. A case asserting only `-` cannot tell a compiled arm that
/// answered could-not-look from a `Value::Authority` variant nothing dispatches
/// — both leave the column undefined, and `render_column` renders both as `-`.
#[test]
fn the_compiled_lease_arm_is_reached_and_answers() {
    let dir = compiled_repo("lease-compiled-probe", r#"{ "3" = "unknown" }"#);
    hook(&dir, "mise run linear-check");

    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(
        columns.len(),
        4,
        "the predicate asserts a count of four: {line:?}"
    );
    assert_eq!(
        columns[1], "unknown",
        "A CLONE WITH NO REMOTE IS COULD-NOT-LOOK, AND THE ARM SAID SO. A dash \
         here means nothing dispatched `lease-status` at all: {line:?}"
    );
    assert_eq!(
        columns[3], "work",
        "and the rest of the line is unchanged by the arm swap: {line:?}"
    );
}

/// The shipped table's omission is what makes that answer fail OPEN.
///
/// The numbers moved with the producer and the meanings did not: the shell
/// answered `1` held-elsewhere and `2` could-not-look, the engine answers `2`
/// and `3`, and `batten.toml`'s map is the one place the two vocabularies meet.
/// Mapping `3` there would invert the one behaviour the port exists to conserve
/// — "a lease it cannot read stops EVERY job in the fleet, where waving one
/// matrix through costs one matrix" — and this is the case that refuses it.
#[test]
fn the_shipped_table_leaves_the_compiled_could_not_look_unmapped() {
    let dir = compiled_repo(
        "lease-compiled-shipped",
        r#"{ "0" = "authorised", "2" = "held-elsewhere" }"#,
    );
    hook(&dir, "mise run linear-check");

    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(
        columns[1], "-",
        "an unmapped status is could-not-look, so the preset's refusal cannot \
         hold: {line:?}"
    );
    assert_ne!(columns[1], "held-elsewhere", "and it is NOT the refusal");
}

/// The successor arm answers nothing where there is no lease, which the column
/// records as could-not-look and the preset reads as *not this branch*.
#[test]
fn the_compiled_successor_arm_records_could_not_look_without_a_lease() {
    let dir = compiled_repo("lease-compiled-successor", r#"{ "3" = "unknown" }"#);
    hook(&dir, "mise run linear-check");

    let line = record(&dir);
    let columns = columns(&line);
    assert_eq!(columns[2], "-", "no lease names a successor: {line:?}");
    assert_ne!(
        columns[2], columns[3],
        "so it cannot accidentally admit this branch"
    );
}

/// A compound call still selects, because the pattern is anchored on a segment
/// boundary rather than on the start of the line — CLOUD-857's class, where
/// `git push --force origin main` denied while `cd /tmp && git push --force origin
/// main` was allowed, with a green suite over it.
#[test]
fn a_compound_call_still_selects() {
    let dir = repo("lease-compound", 0, "");
    hook(&dir, "cd /tmp && mise run linear-check");
    assert!(
        record(&dir).starts_with("lease "),
        "a lifecycle call is not exempted by what precedes it: {:?}",
        record(&dir)
    );
}
