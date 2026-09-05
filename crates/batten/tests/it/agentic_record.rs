//! `policy/agentic-experiment-record.rego` over the compiled binary (CLOUD-1116).
//!
//! **This is the tier the module's own `test_` rules cannot be.** A `with input
//! as` block writes the shape it then reads, so it is green over a key the engine
//! never fills — the defect `rules/policy-modules.md` records both live instances
//! of. Three claims here are exactly of that kind and are asserted nowhere else:
//! that the engine PARSES `bench/agentic/trials.toml` and
//! `bench/agentic/method.toml` into `input.tree.documents` from a row declaring
//! them as `documents`; that an array of tables arrives as an array the predicate
//! can iterate; and that an absent record reaches `input.tree.missing` rather
//! than simply being absent from `documents`, which is the difference between a
//! could-not-look and a clean tree.
//!
//! **The `missing` distinction is the one worth naming, and this tier is what
//! found it.** The row's first spelling was `sources`, which is the GLOB field:
//! its entries are matched against the walked file list, so an absent record
//! matches nothing, is never declared, is never acquired, and never reaches
//! `input.tree.missing` — the could-not-look clause simply cannot fire.
//! `documents` is the literal field and is unioned into the declared set
//! unconditionally, so an absent path is acquired, fails, and is named with its
//! cause. Measured rather than reasoned: with `sources`, a tree carrying neither
//! record answered NOTHING at all, and `a_tree_with_no_records_at_all_is_silent`
//! is the case that caught it. Every other case here passed over that spelling,
//! which is the shape this second tier exists for.
//!
//! **The last case's subject is this repository rather than a fixture.** It runs
//! the committed module over the committed records, so the six declared trials
//! and the method record beside them are held to the gate on every commit — which
//! is the whole point of writing the records down.
//!
//! # THE MUTATION REPLAY (CLOUD-1116's acceptance clause)
//!
//! The row requires a replay over the record set BEFORE this rule is set to
//! `deny`, and `a_replay_over_the_committed_records_fires_on_every_required_key`
//! is it, run rather than written up. It takes the committed `trials.toml`,
//! removes each required key in turn from each declared trial, and asserts the
//! gate fires — so the replay is a test rather than a paragraph, and it re-runs
//! whenever the record set grows.
//!
//! Measured 2026-09-05 over the committed records: **6 trial rows examined, 13
//! required keys per row, 78 mutations, 78 fired, 0 false positives** — where a
//! false positive is the unmutated record set deciding anything, asserted
//! separately by `the_committed_records_satisfy_this_gate`. That is what licenses
//! `severity = "deny"` on the row.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::PathBuf;

use common::{batten, init_repo, scratch, stderr, stdout, write};

const TRIALS: &str = "bench/agentic/trials.toml";
const METHOD: &str = "bench/agentic/method.toml";

/// Exactly the three classes `policy/agentic-experiment-record.rego` raises.
///
/// **NAMED, NEVER PREFIX-MATCHED.** A prefix reads as "the module's families" and
/// is really "every class anybody ever names that way"; a rebase bringing in a
/// sibling's `test …` class would then be swept into a bundle that enables one
/// module, nothing there raises it, and the registry's both-directions check
/// fails the config LOAD rather than the case.
const RAISED: [&str; 3] = [
    "test declare partial",
    "test state early",
    "input read absent",
];

/// The committed verdict rows this module raises, rendered back as TOML.
///
/// DERIVED from the committed table rather than restated: a module raising a
/// token no row declares fails to LOAD, so a restated table that fell behind
/// would redden every case here over a module that is fine.
fn verdict_rows() -> String {
    let declared = common::verdicts_in(&common::at_root("."));
    let mut rows = String::new();
    for id in RAISED {
        // A MISS IS LOUD. Selecting by name means a rename in the committed table
        // yields a SHORT list rather than a wrong one, and a short list is a
        // fixture whose module raises a token nothing declares.
        assert!(
            declared.iter().any(|verdict| verdict.id == id),
            "the committed table no longer declares `{id}`, which \
             `policy/agentic-experiment-record.rego` raises — rename it in both places"
        );
        let _ = write!(
            rows,
            "[[verdict]]\nid = \"{id}\"\ngloss = \"a fixture gloss\"\nclass = \"A fixture class.\"\n\n\
             [[verdict.route]]\nid = \"module read first\"\nkind = \"document\"\n\
             target = \"policy/agentic-experiment-record.rego\"\n\n",
        );
    }
    rows
}

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "agentic-experiment-record"
kind = "policy"
scope = "tree"
documents = ["{TRIALS}", "{METHOD}"]
module = "policy/agentic-experiment-record.rego"
severity = "deny"

{}"#,
        verdict_rows()
    )
}

/// One complete, `pending` trial — the shape every case here mutates away from.
fn complete_trial() -> String {
    r#"[[trial]]
id = "a-trial"
question = "does returning the failed predicate change the next attempt?"
intended_outcome = "the floor"
intervention = "gate-feedback"
model = "claude-opus-5"
fixture = "03720c38"
runs = 10
governed_action = "git commit touching a protected path"
evidence = "the verdict token alone"
canary = "a commit touching no protected path must not be refused"

[trial.arms]
baseline = "the refusal as a bare exit code"
treatment = "the refusal carrying its verdict token"

[trial.falsifier]
statement = "denials before success do not fall"
downside = "a token with no prose reads as a code to look up"
disposition = "pending"
"#
    .to_owned()
}

fn complete_method() -> String {
    r#"[method]
attribution_window = "the governed action under test, plus every attempt at it"
held_constant = ["repository revision", "task definition"]

[method.outcomes]
measured = ["denials before success", "token cost"]
unmeasured = ["whether the agent's stated rationale is sound"]

[method.adjudication]
method = "paired difference on each measured outcome"
requires_both_arms = true
blocking_on_model_judgement = false
dispositions = ["pending", "gate-candidate", "rejected"]

[method.canary]
required = true
rule = "an arm reporting success on its own canary is discarded"
"#
    .to_owned()
}

/// A scratch repository carrying the fixture config, the COMMITTED module, and
/// whichever records the case supplies. `None` writes no file at all, which is
/// how the could-not-look arm is reached over a DECLARED path.
fn repo(name: &str, trials: Option<&str>, method: Option<&str>) -> PathBuf {
    let dir = scratch(&format!("agentic-record-{name}"));
    write(&dir, "batten.toml", &config());
    std::fs::create_dir_all(dir.join("bench/agentic")).expect("scratch bench dir");
    if let Some(body) = trials {
        write(&dir, TRIALS, body);
    }
    if let Some(body) = method {
        write(&dir, METHOD, body);
    }
    let module = common::at_root("policy/agentic-experiment-record.rego");
    std::fs::create_dir_all(dir.join("policy")).expect("scratch policy dir");
    std::fs::copy(module, dir.join("policy/agentic-experiment-record.rego"))
        .expect("install committed module");
    init_repo(&dir);
    dir
}

fn findings(dir: &std::path::Path) -> String {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    let outcome = command.output().expect("run batten check");

    // A NON-VERDICT EXIT IS NOT AN EMPTY ANSWER. `check` exits 0 clean and 2 on a
    // policy verdict; every other code is a statement about the INVOCATION — a
    // config that will not load exits 1 and says why on stderr. Discarding that
    // while returning an empty stdout is how a suite reports a dead module as a
    // partially working one.
    let code = outcome.status.code();
    assert!(
        matches!(code, Some(0 | 2)),
        "`batten check` exited {code:?} rather than deciding: the fixture config \
         did not load, so an empty answer here is a broken gate rather than a \
         clean tree.\nstderr: {}",
        stderr(&outcome)
    );
    stdout(&outcome)
}

#[test]
fn a_complete_pending_record_set_is_silent() {
    let dir = repo("clean", Some(&complete_trial()), Some(&complete_method()));
    let answer = findings(&dir);
    assert!(
        answer.trim().is_empty(),
        "a complete record set carrying only `pending` decides nothing:\n{answer}"
    );
}

#[test]
fn a_trial_missing_a_required_key_is_reported() {
    // THE ENGINE HALF: an array of tables reaching the predicate as an array it
    // can iterate, and one row's absent key being visible in it.
    let dir = repo(
        "no-fixture",
        Some(&complete_trial().replace("fixture = \"03720c38\"\n", "")),
        Some(&complete_method()),
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-record-incomplete"),
        "a trial naming no fixture cannot be rerun, so the row is incomplete:\n{answer}"
    );
}

#[test]
fn a_single_armed_trial_is_reported() {
    let dir = repo(
        "one-arm",
        Some(&complete_trial().replace("baseline = \"the refusal as a bare exit code\"\n", "")),
        Some(&complete_method()),
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-record-incomplete"),
        "a trial with no baseline arm is an anecdote with a run count:\n{answer}"
    );
}

#[test]
fn a_disposition_asserting_a_finding_without_a_result_is_reported() {
    // THE CLAUSE THAT WILL FIRE IN ANGER. Every committed row ships `pending`; the
    // moment somebody writes a finding, this asks for the result behind it.
    let dir = repo(
        "unsupported",
        Some(&complete_trial().replace(
            "disposition = \"pending\"",
            "disposition = \"gate-candidate\"",
        )),
        Some(&complete_method()),
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-finding-unsupported"),
        "a disposition asserting a finding owes a `[trial.result]`:\n{answer}"
    );
}

#[test]
fn a_disposition_asserting_a_finding_with_a_result_is_silent() {
    let mut body = complete_trial().replace(
        "disposition = \"pending\"",
        "disposition = \"gate-candidate\"",
    );
    body.push_str("\n[trial.result]\ndenials_before_success = \"3.1 against 6.4\"\n");
    let dir = repo("supported", Some(&body), Some(&complete_method()));
    let answer = findings(&dir);
    assert!(
        answer.trim().is_empty(),
        "a finding with its result beside it is exactly what the record set is for:\n{answer}"
    );
}

#[test]
fn a_disposition_the_method_record_does_not_declare_is_reported() {
    // THE JOINT HALF: the row's vocabulary is the method record's, so a
    // disposition invented at the row is refused even with a result beside it.
    let mut body = complete_trial().replace(
        "disposition = \"pending\"",
        "disposition = \"obviously-true\"",
    );
    body.push_str("\n[trial.result]\ndenials_before_success = \"3.1 against 6.4\"\n");
    let dir = repo("invented", Some(&body), Some(&complete_method()));
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-finding-unsupported"),
        "a disposition the method record does not declare means nothing:\n{answer}"
    );
}

#[test]
fn a_method_record_naming_no_unmeasured_dimension_is_reported() {
    // An unmeasured dimension that is not written down gets claimed anyway, which
    // is why the method record owes the list rather than merely the measurements.
    let dir = repo(
        "no-unmeasured",
        Some(&complete_trial()),
        Some(&complete_method().replace(
            "unmeasured = [\"whether the agent's stated rationale is sound\"]\n",
            "",
        )),
    );
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-record-incomplete"),
        "the method record owes the dimensions it deliberately does not measure:\n{answer}"
    );
}

#[test]
fn a_tree_with_no_records_at_all_is_silent() {
    // ABSENT IS NOT INCOMPLETE — but the row declares both paths literally, so an
    // absent one is ACQUIRED, fails, and is named. That is the could-not-look arm
    // and it is the honest answer for a declared path, not a pass.
    let dir = repo("absent", None, None);
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-record-unreadable"),
        "a declared record that could not be read is reported, never assumed clean:\n{answer}"
    );
}

#[test]
fn an_unreadable_method_record_is_reported() {
    // THE `missing` CLAUSE over the compiled binary and never with `with input
    // as` — the whole question is whether the ENGINE routes an unacquirable
    // declared path into `input.tree.missing`, and a fabricated input would answer
    // it by construction.
    let dir = repo("no-method", Some(&complete_trial()), None);
    let answer = findings(&dir);
    assert!(
        answer.contains("agentic-record-unreadable"),
        "the method record is half the joint predicate; its absence is not a clean tree:\n{answer}"
    );
}

/// Every key the module requires of a trial row, spelled as the TOML line that
/// declares it in the committed record.
///
/// A LINE RATHER THAN A KEY NAME, because removal has to be surgical: deleting
/// every line containing `id` would take `id = ` out of the arms table too, and a
/// mutation that removes more than it names cannot tell you which key the gate
/// caught.
const REQUIRED_LINES: [&str; 13] = [
    "id = ",
    "question = ",
    "intended_outcome = ",
    "intervention = ",
    "model = ",
    "fixture = ",
    "runs = ",
    "governed_action = ",
    "evidence = ",
    "canary = ",
    "baseline = ",
    "statement = ",
    "downside = ",
];

#[test]
fn the_committed_records_satisfy_this_gate() {
    // THE PER-COMMIT GATE, and the one case whose subject is this repository. It
    // is also the replay's zero: a false positive here would make every fired
    // mutation below unreadable.
    let trials = std::fs::read_to_string(common::at_root(TRIALS)).expect("the trials record");
    let method = std::fs::read_to_string(common::at_root(METHOD)).expect("the method record");
    let dir = repo("committed", Some(&trials), Some(&method));
    let answer = findings(&dir);
    assert!(
        answer.trim().is_empty(),
        "the committed agentic records must satisfy the gate that reads them:\n{answer}"
    );
}

#[test]
fn a_replay_over_the_committed_records_fires_on_every_required_key() {
    // CLOUD-1116'S ACCEPTANCE CLAUSE, run rather than written up. Each required
    // key is removed from the committed record set in turn and the gate must fire;
    // a key whose removal is SILENT is a required key nothing requires, which is
    // the dead-clause shape this repository keeps re-meeting.
    //
    // Removal is by line and by first occurrence per trial block, so the count
    // below is mutations rather than deleted lines.
    let trials = std::fs::read_to_string(common::at_root(TRIALS)).expect("the trials record");
    let method = std::fs::read_to_string(common::at_root(METHOD)).expect("the method record");

    let blocks: Vec<&str> = trials.split("\n[[trial]]").collect();
    let mut examined = 0_usize;
    let mut fired = 0_usize;

    for (block, _) in blocks.iter().enumerate().skip(1) {
        examined += 1;
        for (key, line) in REQUIRED_LINES.iter().enumerate() {
            let mutated = remove_first_line_starting_with(&trials, block, line);
            assert_ne!(
                mutated, trials,
                "the replay must actually mutate: trial block {block} carries no `{line}` line, \
                 so this key is declared required and is not present to be removed"
            );
            let dir = repo(
                &format!("replay-{block}-{key}"),
                Some(&mutated),
                Some(&method),
            );
            if findings(&dir).contains("agentic-record-incomplete") {
                fired += 1;
            }
        }
    }

    let mutations = examined * REQUIRED_LINES.len();
    assert_eq!(
        fired, mutations,
        "every required key's removal must be caught: {fired} of {mutations} mutations fired \
         over {examined} trial rows"
    );
}

/// Remove the first line inside trial block `block` (1-indexed, as
/// `split(\"\\n[[trial]]\")` yields it) whose trimmed form starts with `prefix`.
fn remove_first_line_starting_with(trials: &str, block: usize, prefix: &str) -> String {
    let mut seen = 0_usize;
    let mut removed = false;
    let mut out = String::new();
    for line in trials.lines() {
        if line.trim_start().starts_with("[[trial]]") {
            seen += 1;
        }
        if !removed && seen == block && line.trim_start().starts_with(prefix) {
            removed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}
