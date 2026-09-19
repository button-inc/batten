//! `prose measure partial` over the compiled binary and the real census
//! (CLOUD-388, CLOUD-651, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/transcript-corpus.rego` carries seven load-time cases and every one
//! fabricates its input with `with input as`, which is the shape
//! `rules/policy-modules.md` warns about: the case asserts over a record the
//! engine may be unable to project, and the module stays green while the row
//! decides nothing on any real host.
//!
//! # And why the CENSUS is driven here rather than described
//!
//! Ten of the dying suite's seventeen cases are about WHAT COUNTS as an
//! independent session — the sidechain rule, the authored-content rule, two
//! files carrying one session, the exclusion and its absent-versus-empty
//! distinction, and an undecodable line. That is the entire substance of the
//! gate; the comparison it feeds is one `<`.
//!
//! Inlined into the task body they would be assertable by nothing.
//! `mise-tasks/transcript_census.py` instead, driven directly below, so they
//! carry. `shell-retirement.rego:159-163` excludes `.py` from
//! `under_mise_tasks`, so that file adds no shell rule.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! Four cases are not carried and each says why in its own row.
//!
// carried: mise-tasks/transcript-corpus-check.sh policy/transcript-corpus.rego kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: tests/transcript-corpus-check.bats policy/transcript-corpus.rego kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "an empty root is zero independent sessions, which is an answer and not a failure to look" policy/transcript-corpus.rego kind:mechanism
// carried: "one transcript is one session, and one is not a corpus" policy/transcript-corpus.rego kind:mechanism
// carried: "three distinct sessions satisfy the default threshold" policy/transcript-corpus.rego kind:mechanism
// carried: "the threshold is the argument, so the same corpus can fail a stricter one" policy/transcript-corpus.rego kind:mechanism
// carried: "a subagent stream is not an independent session" policy/transcript-corpus.rego kind:mechanism
// carried: "a transcript carrying only tool results has nobody in it" policy/transcript-corpus.rego kind:mechanism
// carried: "two files carrying one session are one session" policy/transcript-corpus.rego kind:mechanism
// carried: "a line this build cannot decode yields nothing rather than a failure to look" policy/transcript-corpus.rego kind:mechanism
// carried: "excluding the asking session turns its own transcript into zero" policy/transcript-corpus.rego kind:mechanism
// carried: "the exclusion defaults from the environment when no argument names one" policy/transcript-corpus.rego kind:mechanism
// carried: "an explicitly empty exclusion excludes nothing, and does not fall back to the environment" policy/transcript-corpus.rego kind:mechanism
// carried: "an absent root is exit 2, never a verdict about a corpus nobody looked at" policy/transcript-corpus.rego kind:mechanism
// carried: "the report is two counts and carries no byte of any transcript" policy/transcript-corpus.rego kind:mechanism
// changed: "a malformed threshold is exit 2" mise.toml argument validation is the PRODUCER's, so it moved with the census it guards: `transcript_census.py` refuses a non-numeric threshold at exit 2 and writes nothing, and `a_malformed_threshold_refuses_and_writes_nothing` below drives that. The module never sees an argument to malform
// changed: "more arguments than the contract names is exit 2" mise.toml the same split one argument over, and for the same reason: the arity contract belongs to the thing that takes the arguments
// withdrawn: "the refusal names what would raise the number, not just the arithmetic" the sentence is the `[[verdict]]` row's `class` now, which is config a reviewer reads rather than a string a case greps. `verdict declare refused` already refuses a class that is an override alone, and `remedy-authorship` holds the prose; a case re-asserting the wording here would be a second authority over it
// withdrawn: "the refusal does not tell the reader the count can never rise" the same row's `class`, and the same reason. Both cases asserted over a shell `echo` that no longer exists, and the claim they protected — that a low count is a PROGRESS reading rather than a permanent state — is stated in the class and in the module header where a reader meets it

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against the declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("transcript-corpus-{name}"));
    let module = std::fs::read_to_string("../../policy/transcript-corpus.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/transcript-corpus.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[verdict]]
id = "prose measure partial"
gloss = "this host carries fewer independent session transcripts than the caller asked for"
class = "A progress reading rather than a permanent state: the number rises as the collector reaches this host."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run transcript-corpus-record"

[[rule]]
id = "prose measure partial"
kind = "policy"
scope = "tree"
module = "policy/transcript-corpus.rego"
severity = "deny"

[[record]]
record = "transcript-corpus"
writer = "mise run transcript-corpus-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

fn record(dir: &std::path::Path, lines: &str) {
    let written = run_with_stdin(dir, &["record", "named", "transcript-corpus"], lines);
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

/// Run the REAL census over a scratch transcript root, exactly as the producer
/// does. `exclude` is `None` for an absent argument and `Some("")` for an
/// explicitly empty one — the distinction the contract turns on.
#[expect(
    clippy::disallowed_types,
    reason = "CLOUD-320's inventory row, and the verdict is that this spawn IS the subject under test: the census moved out of the dying program into `mise-tasks/transcript_census.py` precisely so a compiled case could drive it, and a harness re-implementing the independence rules in Rust would be a second authority over what counts as a session"
)]
fn census(
    root: &std::path::Path,
    threshold: &str,
    exclude: Option<&str>,
    env: Option<&str>,
) -> std::process::Output {
    let mut command = std::process::Command::new("python3");
    command
        .arg("../../mise-tasks/transcript_census.py")
        .arg(root)
        .arg(threshold);
    if let Some(value) = exclude {
        command.arg(value);
    }
    match env {
        Some(value) => command.env("BATTEN_SESSION_ID", value),
        None => command.env_remove("BATTEN_SESSION_ID"),
    };
    command.output().expect("the census runs")
}

fn counted(done: &std::process::Output) -> String {
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// A transcript root holding the given `(filename, contents)` pairs.
fn root(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = scratch(&format!("transcript-root-{name}"));
    for (file, contents) in files {
        write(&dir, file, contents);
    }
    dir
}

/// One authored, non-sidechain user record for `session`.
fn authored(session: &str) -> String {
    format!(
        r#"{{"type":"user","sessionId":"{session}","message":{{"content":[{{"type":"text","text":"hello"}}]}}}}"#
    )
}

// --- the decision, over the engine's own projection --------------------------

#[test]
fn one_transcript_is_one_session_and_one_is_not_a_corpus() {
    let dir = repo("thin");
    record(&dir, "sessions 1\nthreshold 2\n");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "one session is not a corpus\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn three_distinct_sessions_satisfy_the_default_threshold() {
    let dir = repo("enough");
    record(&dir, "sessions 3\nthreshold 2\n");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "a corpus that meets the bound is clean\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_refusing() {
    // The producer writes nothing when the root does not exist, so a module that
    // refused here would refuse every host that has never run the census.
    let dir = repo("unrecorded");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn the_report_is_two_counts_and_carries_no_byte_of_any_transcript() {
    // POINTER-ONLY IS A SECURITY PROPERTY over this input, not a style one: a
    // transcript is the richest source of secrets the engine can be pointed at.
    // The census is what must not leak, so this asserts over ITS bytes.
    let held = root(
        "secretive",
        &[(
            "a.jsonl",
            r#"{"type":"user","sessionId":"alpha","message":{"content":[{"type":"text","text":"SUPERSECRETSTRING"}]}}"#,
        )],
    );

    let done = census(&held, "2", Some(""), None);
    let said = format!(
        "{}{}",
        counted(&done),
        String::from_utf8_lossy(&done.stderr)
    );
    assert!(
        !said.contains("SUPERSECRETSTRING"),
        "no byte of a transcript reaches the record\n{said}"
    );
    assert!(!said.contains("alpha"), "and no session id does\n{said}");
    assert!(said.contains("sessions 1"), "only the counts do\n{said}");
}

// --- the census itself -------------------------------------------------------

#[test]
fn an_empty_root_is_zero_independent_sessions_which_is_an_answer() {
    let held = root("empty", &[("keep.txt", "not a transcript\n")]);
    let done = census(&held, "2", Some(""), None);
    assert!(done.status.success(), "an empty root is not a failure");
    assert!(
        counted(&done).contains("sessions 0"),
        "zero is an answer\n{}",
        counted(&done)
    );
}

#[test]
fn a_subagent_stream_is_not_an_independent_session() {
    // CLOUD-326 section 8.1 recorded "one session plus five subagent
    // transcripts" and correctly called that N=1.
    let held = root(
        "sidechain",
        &[(
            "sub.jsonl",
            r#"{"type":"user","sessionId":"beta","isSidechain":true,"message":{"content":[{"type":"text","text":"hi"}]}}"#,
        )],
    );
    let done = census(&held, "2", Some(""), None);
    assert!(
        counted(&done).contains("sessions 0"),
        "a sidechain is the orchestrator's own turns\n{}",
        counted(&done)
    );
}

#[test]
fn a_transcript_carrying_only_tool_results_has_nobody_in_it() {
    // A `tool_result` also arrives as a user record; that is the harness handing
    // work back, not a person speaking.
    let held = root(
        "toolonly",
        &[(
            "t.jsonl",
            r#"{"type":"user","sessionId":"gamma","message":{"content":[{"type":"tool_result","content":"out"}]}}"#,
        )],
    );
    let done = census(&held, "2", Some(""), None);
    assert!(
        counted(&done).contains("sessions 0"),
        "nobody was in it\n{}",
        counted(&done)
    );
}

#[test]
fn two_files_carrying_one_session_are_one_session() {
    let held = root(
        "split",
        &[
            ("one.jsonl", &authored("delta")),
            ("two.jsonl", &authored("delta")),
        ],
    );
    let done = census(&held, "2", Some(""), None);
    assert!(
        counted(&done).contains("sessions 1"),
        "distinct sessions, not distinct files\n{}",
        counted(&done)
    );
}

#[test]
fn a_line_this_build_cannot_decode_yields_nothing_rather_than_a_failure_to_look() {
    // The format is a HOST's and it moves. `transcript.rs`'s
    // forward-compatibility law, applied at the same boundary from this side.
    let held = root(
        "undecodable",
        &[(
            "mixed.jsonl",
            &format!("{{not json at all\n{}\n", authored("epsilon")),
        )],
    );
    let done = census(&held, "2", Some(""), None);
    assert!(done.status.success(), "one bad line is not a failed census");
    assert!(
        counted(&done).contains("sessions 1"),
        "the readable line still counts\n{}",
        counted(&done)
    );
}

#[test]
fn excluding_the_asking_session_turns_its_own_transcript_into_zero() {
    let held = root("selfonly", &[("self.jsonl", &authored("zeta"))]);
    let done = census(&held, "2", Some("zeta"), None);
    assert!(
        counted(&done).contains("sessions 0"),
        "a session is not independent evidence about itself\n{}",
        counted(&done)
    );
}

#[test]
fn the_exclusion_defaults_from_the_environment_when_no_argument_names_one() {
    let held = root("envexcl", &[("self.jsonl", &authored("eta"))]);
    let done = census(&held, "2", None, Some("eta"));
    assert!(
        counted(&done).contains("sessions 0"),
        "the ambient session id applies when nothing names one\n{}",
        counted(&done)
    );
}

#[test]
fn an_explicitly_empty_exclusion_excludes_nothing_and_does_not_fall_back_to_the_environment() {
    // ABSENT AND EMPTY ARE DIFFERENT CLAIMS. Defaulting an explicit empty would
    // launder "exclude nothing" into "exclude whatever the host happens to say".
    let held = root("emptyexcl", &[("self.jsonl", &authored("theta"))]);
    let done = census(&held, "2", Some(""), Some("theta"));
    assert!(
        counted(&done).contains("sessions 1"),
        "an explicit empty excludes nothing\n{}",
        counted(&done)
    );
}

#[test]
fn an_absent_root_is_could_not_look_and_writes_nothing() {
    // Never a verdict about a corpus nobody looked at.
    let missing = scratch("transcript-root-missing").join("nowhere");
    let done = census(&missing, "2", Some(""), None);
    assert_eq!(done.status.code(), Some(2), "could not look");
    assert!(
        counted(&done).is_empty(),
        "and writes nothing, so the module reads silence\n{}",
        counted(&done)
    );
}

#[test]
fn a_malformed_threshold_refuses_and_writes_nothing() {
    let held = root("badmin", &[("a.jsonl", &authored("iota"))]);
    let done = census(&held, "two", Some(""), None);
    assert_eq!(done.status.code(), Some(2), "a malformed threshold refuses");
    assert!(counted(&done).is_empty(), "and writes nothing");
}

#[test]
#[expect(
    clippy::disallowed_types,
    reason = "CLOUD-320's inventory row: the arity contract belongs to the thing that takes the arguments, so asserting it means invoking the producer with the wrong arity"
)]
fn more_arguments_than_the_contract_names_refuses() {
    let held = root("arity", &[("a.jsonl", &authored("kappa"))]);
    let done = std::process::Command::new("python3")
        .arg("../../mise-tasks/transcript_census.py")
        .arg(&held)
        .arg("2")
        .arg("")
        .arg("extra")
        .output()
        .expect("the census runs");
    assert_eq!(done.status.code(), Some(2), "an over-long call refuses");
}
