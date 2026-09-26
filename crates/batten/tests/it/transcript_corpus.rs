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
//! They live in `crates/batten/src/transcript.rs` — beside the parse that
//! already owns this host's format and declares the same pointer-only and
//! forward-compatibility laws, rather than in a module of its own. Its
//! `#[cfg(test)] mod tests` asserts each independence rule directly, plus three
//! the retired program never had: a nested project directory, an empty
//! `sessionId`, and an assistant turn.
//!
//! What stays HERE is the half a unit test cannot reach: that the engine
//! carries the count through `record derive` into a record the real module then
//! decides over, and that a root it could not walk writes NOTHING.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! Five cases are not carried and each says why in its own row.
//!
// carried: mise-tasks/transcript-corpus-check.sh policy/transcript-corpus.rego kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: tests/transcript-corpus-check.bats policy/transcript-corpus.rego kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "an empty root is zero independent sessions, which is an answer and not a failure to look" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "one transcript is one session, and one is not a corpus" policy/transcript-corpus.rego kind:mechanism
// carried: "three distinct sessions satisfy the default threshold" policy/transcript-corpus.rego kind:mechanism
// carried: "the threshold is the argument, so the same corpus can fail a stricter one" policy/transcript-corpus.rego kind:mechanism
// carried: "a subagent stream is not an independent session" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "a transcript carrying only tool results has nobody in it" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "two files carrying one session are one session" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "a line this build cannot decode yields nothing rather than a failure to look" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "excluding the asking session turns its own transcript into zero" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "an explicitly empty exclusion excludes nothing, and does not fall back to the environment" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// carried: "an absent root is exit 2, never a verdict about a corpus nobody looked at" policy/transcript-corpus.rego kind:mechanism
// carried: "the report is two counts and carries no byte of any transcript" crates/batten/src/transcript.rs kind:mechanism crates/batten/tests/it/transcript_corpus.rs
// changed: "a malformed threshold is exit 2" mise.toml argument validation is the PRODUCER's, so it moved with the census it guards. It is now `record derive transcript-corpus`, which refuses a non-numeric threshold as a USAGE error — exit 1 under the engine's one 0/1/2/3 table, where the retired program spent 2 — and writes nothing either way. `a_malformed_threshold_refuses_and_writes_nothing` below drives both halves. The module never sees an argument to malform
// changed: "more arguments than the contract names is exit 2" mise.toml the arity contract belongs to the thing that takes the arguments, and under named `--input` flags "too many positionals" ceases to exist as a concept. What replaces it is stricter rather than weaker: an input key no family declares is a usage error, which `an_input_key_the_family_does_not_read_is_a_usage_error` pins one tier over — a misspelled input can no longer exit clean from a reading that ran on something else
// changed: "the exclusion defaults from the environment when no argument names one" mise.toml the environment read is the PRODUCER's, not the reading's: the task adds `--input exclude=` only when `BATTEN_SESSION_ID` is set, which is what keeps absent and present-but-empty two different claims at the verb. The reading takes `Option<&str>` and `an_explicitly_empty_exclusion_excludes_nothing` pins the distinction in the engine module
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
fn a_torn_corpus_record_is_reported_rather_than_passing() {
    // Two DIFFERENT session counts used to raise `eval_conflict_error` inside the
    // module, which the engine reads as a fault — every predicate here silent at
    // exit 0. And a record missing its threshold decided nothing. Both are the
    // partial reading now, over the real projection.
    for (name, lines) in [
        ("conflict", "sessions 1\nsessions 5\nthreshold 2\n"),
        ("half", "sessions 9\n"),
    ] {
        let dir = repo(&format!("torn-{name}"));
        record(&dir, lines);
        let decided = run(&dir, &["check"]);
        assert_eq!(
            decided.status.code(),
            Some(2),
            "a {name} record is reported, not passed\n{}",
            String::from_utf8_lossy(&decided.stderr)
        );
    }
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

    let dir = repo("secretive");
    // `Some("")` is an EXPLICITLY EMPTY exclusion — "exclude nothing" — which is
    // a different claim from naming none at all, and the one that keeps the
    // count at 1 here.
    let done = derive(&dir, &held, "2", Some(""));
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

// --- the census, over the real verb ------------------------------------------

/// Drive the REAL census the producer runs, through the REAL verb.
///
/// `crates/batten/src/transcript.rs` is the one authority on what counts as an
/// independent session — beside the parse that already owns this host's format,
/// rather than in a module of its own. Its `#[cfg(test)] mod tests` asserts each
/// independence rule directly, plus three the retired program never had: a
/// nested project directory, an empty `sessionId`, and an assistant turn.
///
/// What THIS tier adds is the half a unit test cannot reach: that the engine
/// carries the count into a record the real module then decides over.
fn derive(
    dir: &std::path::Path,
    transcripts: &std::path::Path,
    threshold: &str,
    exclude: Option<&str>,
) -> std::process::Output {
    let mut args = vec![
        "record".to_owned(),
        "derive".to_owned(),
        "transcript-corpus".to_owned(),
        "--input".to_owned(),
        format!("root={}", transcripts.display()),
        "--input".to_owned(),
        format!("threshold={threshold}"),
    ];
    if let Some(value) = exclude {
        args.push("--input".to_owned());
        args.push(format!("exclude={value}"));
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_with_stdin(dir, &borrowed, "")
}

#[test]
fn the_verb_derives_a_thin_corpus_into_the_finding() {
    let dir = repo("derive-thin");
    let transcripts = root("derive-thin", &[("a.jsonl", &authored("only-one"))]);
    let written = derive(&dir, &transcripts, "2", None);
    assert!(
        written.status.success(),
        "the derivation lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    assert!(
        counted(&written).contains("sessions 1"),
        "the count reaches the record\n{}",
        counted(&written)
    );

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "one session is not a corpus\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn the_verb_derives_a_sufficient_corpus_into_silence() {
    let dir = repo("derive-enough");
    let transcripts = root(
        "derive-enough",
        &[
            ("a.jsonl", &authored("one")),
            ("b.jsonl", &authored("two")),
            ("c.jsonl", &authored("three")),
        ],
    );
    let written = derive(&dir, &transcripts, "2", None);
    assert!(written.status.success(), "the derivation lands");
    assert!(
        counted(&written).contains("sessions 3"),
        "{}",
        counted(&written)
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "three distinct sessions satisfy the threshold\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

/// THE QUESTION COULD NOT BE ASKED, so the producer writes NOTHING. An absent
/// record is "the producer did not run", which must never be spelled the same
/// way as a root that was walked and held no transcripts.
#[test]
fn an_absent_root_is_could_not_look_and_writes_nothing() {
    let dir = repo("derive-no-root");
    let refused = derive(&dir, std::path::Path::new("/nowhere/at/all"), "2", None);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a root that is not there is a usage error\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "and nothing was written, so the module says nothing\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_malformed_threshold_refuses_and_writes_nothing() {
    let dir = repo("derive-bad-threshold");
    let transcripts = root("derive-bad-threshold", &[("a.jsonl", &authored("one"))]);
    let refused = derive(&dir, &transcripts, "two", None);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a threshold that is not a number is a usage error\n{}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "and the refusal wrote no record\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

/// EXCLUDING YOURSELF IS THE POINT: a literal fitted to the single transcript it
/// was derived from is the unmeasured-shape failure the method exists to
/// prevent, so counting yourself is worse than counting nothing.
#[test]
fn excluding_the_asking_session_turns_its_own_transcript_into_zero() {
    let dir = repo("derive-exclude");
    let transcripts = root("derive-exclude", &[("a.jsonl", &authored("mine"))]);
    let written = derive(&dir, &transcripts, "2", Some("mine"));
    assert!(written.status.success(), "the derivation lands");
    assert!(
        counted(&written).contains("sessions 0"),
        "{}",
        counted(&written)
    );
}
