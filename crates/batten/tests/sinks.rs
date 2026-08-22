//! A rule can declare an output, and the boundary is what writes it (CLOUD-851).
//!
//! The three censused kinds are each exercised end to end through the compiled
//! binary, because the split this row adds is a split between the DECISION and
//! the BOUNDARY, and a unit test over either half alone cannot see it.
//!
//! WHAT EACH CASE IS FOR, since "it wrote a file" is the least interesting thing
//! here:
//!
//! * `check` decides identically and writes NOTHING, which is the §5 half — the
//!   read-effect verb must not change what it is judging;
//! * the keyed baseline is read back BY A LATER RUN as a fact, which is the only
//!   kind that makes one run's decision depend on another's and therefore the
//!   only one whose store has to be part of the tree surface's input;
//!   it is shown able to fail by dropping the read-back;
//! * byte-stability is asserted over repeated runs rather than once, because the
//!   failure it guards is an ordering-dependent fan-in and a single run cannot
//!   distinguish "stable" from "happened to finish in that order";
//! * rule 4 is asserted at the sink, where it binds harder than at a report: a
//!   record outlives the run and is read back, so a planted secret in a file the
//!   rule reads must reach no record.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{Fixture, run, stdout};

/// A `forbid` rule that fires on the fixture below, declaring a sink.
fn config(kind: &str, key: &str) -> String {
    format!(
        "version = 1\n\
         \n\
         [[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         severity = \"warn\"\n\
         scope = \"tree\"\n\
         no_fix_reason = \"delete the marker\"\n\
         \n\
         [rule.produces]\n\
         kind = \"{kind}\"\n\
         key = \"{key}\"\n"
    )
}

/// A fixture whose one source file trips the rule.
fn repo(name: &str, kind: &str, key: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config(kind, key))
        .file("src/lib.rs", "// TODO: something\n")
        .git()
        .base_commit()
        .build()
}

/// Where a record lands, mirroring `sink::path` rather than importing it — a
/// test that computes the path with the code under test asserts nothing about
/// where the record actually went.
fn record(dir: &Path, kind: &str, key: &str) -> Option<String> {
    fs::read_to_string(dir.join(".git/batten-sinks").join(kind).join(key)).ok()
}

#[test]
fn enforce_writes_the_record_a_rule_declared() {
    let dir = repo("sink-journal", "journal", "rule");
    let output = run(&dir, &["enforce"]);
    assert_eq!(output.status.code(), Some(0), "a warn-severity finding");

    let written = record(&dir, "journal", "no-todo").expect("the journal reached disk");
    // A digest and a count, and the rule that asked. No path, no line, no byte of
    // the file — the pointer discipline one surface further out than a finding.
    let fields: Vec<&str> = written.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        3,
        "rule, digest, count — nothing else: {written:?}"
    );
    assert_eq!(fields[0], "no-todo");
    assert_eq!(fields[1].len(), 64, "a sha256 in lowercase hex");
    assert_eq!(fields[2], "1");
}

#[test]
fn check_decides_the_same_and_writes_nothing() {
    // §5, and the reason the boundary half is a separate function: `check` is a
    // read-effect verb. It computes the same request set — the decision is the
    // same decision — and a record on disk after it would mean the verb changed
    // what it was judging.
    let dir = repo("sink-check-is-read", "journal", "rule");
    let checked = run(&dir, &["check"]);
    let enforced = run(
        &repo("sink-check-is-read-2", "journal", "rule"),
        &["enforce"],
    );

    assert_eq!(
        stdout(&checked),
        stdout(&enforced),
        "the two verbs report identically; only the write differs"
    );
    assert!(
        record(&dir, "journal", "no-todo").is_none(),
        "`check` is declared `read` (§5), so it must leave no record behind"
    );
}

#[test]
fn a_journal_accumulates_across_runs_and_a_baseline_replaces() {
    // The distinction that decides which of the three kinds a writer is: an
    // append journal is an audit trail, a baseline is the CURRENT answer. Getting
    // this backwards would make a ratchet compare against a concatenation.
    let journal = repo("sink-appends", "journal", "rule");
    let _ = run(&journal, &["enforce"]);
    let _ = run(&journal, &["enforce"]);
    assert_eq!(
        record(&journal, "journal", "no-todo")
            .unwrap()
            .lines()
            .count(),
        2,
        "a journal accumulates"
    );

    let baseline = repo("sink-replaces", "baseline", "rule");
    let _ = run(&baseline, &["enforce"]);
    let _ = run(&baseline, &["enforce"]);
    assert_eq!(
        record(&baseline, "baseline", "no-todo")
            .unwrap()
            .lines()
            .count(),
        1,
        "a baseline is the current answer, not a history of them"
    );
}

#[test]
fn a_marker_carries_no_content_at_all() {
    // Only presence is read, so the record has nothing in it. Any token would be
    // a second thing a reader could come to depend on — and a marker whose
    // content mattered would be a baseline wearing the cheaper kind's name.
    let dir = repo("sink-marker", "marker", "rule");
    let _ = run(&dir, &["enforce"]);
    assert_eq!(
        record(&dir, "marker", "no-todo").as_deref(),
        Some(""),
        "a marker's whole content is its existence"
    );
}

#[test]
fn the_record_is_byte_stable_across_repeated_runs() {
    // §6, asserted over repetition rather than once: the failure this guards is
    // an ordering-dependent fan-in under CLOUD-850's concurrent acquisition, and
    // a single run cannot tell "stable" from "finished in that order this time".
    let dir = repo("sink-stable", "baseline", "rule");
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let _ = run(&dir, &["enforce"]);
        seen.insert(record(&dir, "baseline", "no-todo").unwrap());
    }
    assert_eq!(seen.len(), 1, "eight runs, one record: {seen:?}");
}

#[test]
fn a_branch_keyed_record_is_filed_under_the_branch() {
    // The key is resolved at the BOUNDARY, never inside the decision: a branch is
    // a fact about the checkout, and resolving one during adjudication is exactly
    // the impurity the split exists to avoid.
    let dir = repo("sink-branch-key", "baseline", "branch");
    let _ = run(&dir, &["enforce"]);
    assert!(
        record(&dir, "baseline", "main").is_some(),
        "filed under the branch the checkout is on"
    );
    assert!(
        record(&dir, "baseline", "no-todo").is_none(),
        "and not under the rule id, which is the other key"
    );
}

#[test]
fn nothing_reaches_the_record_but_a_digest_and_a_count() {
    // Non-negotiable rule 4, at the sink. A record OUTLIVES the run and is read
    // back by a later one, so this binds harder here than on a finding: the
    // secrets acceptance, re-run on this path.
    let planted = "TODO aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
    let dir = Fixture::new("sink-pointer-only")
        .config(&config("baseline", "rule"))
        .file("src/lib.rs", &format!("// {planted}\n"))
        .git()
        .base_commit()
        .build();
    let _ = run(&dir, &["enforce"]);

    let written = record(&dir, "baseline", "no-todo").expect("the record reached disk");
    assert!(
        !written.contains("wJalrXUtnFEMIK"),
        "a matched byte reached the sink: {written:?}"
    );
    assert!(
        !written.contains("src/lib.rs"),
        "even the path stays out — the record names the rule, not the subject"
    );
}

#[test]
fn a_rule_that_did_not_evaluate_produces_nothing() {
    // CLOUD-81's fail-closed reading, one surface on. A record written by a rule
    // that never looked is a baseline a later run ratchets against having never
    // been measured — which is worse than no baseline, because it reads as one.
    let dir = Fixture::new("sink-not-evaluated")
        .config(&config("baseline", "rule").replace("**/*.rs", "**/*.never"))
        .file("src/lib.rs", "// TODO: something\n")
        .git()
        .base_commit()
        .build();
    let _ = run(&dir, &["enforce"]);
    assert!(
        record(&dir, "baseline", "no-todo").is_none(),
        "the glob matched nothing, so the rule was skipped and has nothing to attest"
    );
}

#[test]
fn a_sink_on_a_mediated_call_kind_is_refused_at_load() {
    // A `produces` there would parse, read as configured, and write nothing on
    // every call — the inert-coverage failure. Refused at LOAD rather than
    // skipped at run time, because a skip looks exactly like a run that had
    // nothing to produce.
    let dir = Fixture::new("sink-wrong-scope")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"no-force-push\"\n\
             kind = \"shape\"\n\
             pattern = \"git push --force\"\n\
             severity = \"deny\"\n\
             scope = \"mediated_call\"\n\
             no_fix_reason = \"push without the flag\"\n\
             \n\
             [rule.produces]\n\
             kind = \"journal\"\n",
        )
        .build();
    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("produces"),
        "the refusal names the column: {}",
        common::stderr(&output)
    );
}

#[test]
fn the_store_lives_under_the_git_dir_and_never_in_the_work_tree() {
    // A sink that could dirty the working tree would make `batten enforce` a verb
    // that changes what it is judging — the same argument as `check`'s, one level
    // out, and the reason every censused bash writer already chose `$GIT_DIR`.
    let dir = repo("sink-store-location", "journal", "rule");
    let _ = run(&dir, &["enforce"]);
    let dirty = common::git_in(&dir, &["status", "--porcelain"]);
    assert!(
        dirty.trim().is_empty(),
        "the run dirtied the tree: {dirty:?}"
    );
    assert!(
        dir.join(".git/batten-sinks").is_dir(),
        "the store is under the git dir"
    );
}

// --- the ratchet: a baseline one run writes and the next reads AS A FACT ------
//
// The kind that makes one run's decision depend on another's, and the only one
// whose store therefore has to be part of the tree surface's input. A journal
// nothing reads and a marker whose presence alone is read both fall out of the
// same machinery; this is the one worth an end-to-end arm, because it is the one
// where "the record was written" and "the record changed a verdict" are
// different claims.

/// A config whose `forbid` row produces a baseline and whose `policy` row
/// decides on whether that baseline exists yet.
fn ratchet_config(read_back: bool) -> String {
    let module = if read_back {
        "policy/ratchet.rego"
    } else {
        // THE RED ARM. The same run, the same record on disk, and a module that
        // does not consult it: the ratchet stops ratcheting and the row fires
        // forever. Without this the positive arm below proves only that a second
        // run is quieter than a first, which a great many bugs also produce.
        "policy/blind.rego"
    };
    format!(
        "version = 1\n\
         \n\
         [[rule]]\n\
         id = \"no-todo\"\n\
         kind = \"forbid\"\n\
         glob = \"**/*.rs\"\n\
         pattern = \"TODO\"\n\
         severity = \"warn\"\n\
         scope = \"tree\"\n\
         no_fix_reason = \"delete the marker\"\n\
         \n\
         [rule.produces]\n\
         kind = \"baseline\"\n\
         key = \"rule\"\n\
         \n\
         [[rule]]\n\
         id = \"needs-a-baseline\"\n\
         kind = \"policy\"\n\
         scope = \"tree\"\n\
         module = \"{module}\"\n\
         severity = \"warn\"\n\
         no_fix_reason = \"run enforce once to establish the baseline\"\n"
    )
}

// A module declares the ids it raises — the engine refuses one it did not, so a
// fixture module carries the same declaration a committed one does.
const READS_BACK: &str = "package batten\n\
    \n\
    rules contains \"needs-a-baseline\"\n\
    \n\
    violation contains {\n\
    \t\"rule\": \"needs-a-baseline\",\n\
    \t\"msg\": \"no baseline for no-todo yet\",\n\
    } if {\n\
    \tnot input.tree.produced[\"no-todo\"]\n\
    }\n";

const BLIND: &str = "package batten\n\
    \n\
    rules contains \"needs-a-baseline\"\n\
    \n\
    violation contains {\n\
    \t\"rule\": \"needs-a-baseline\",\n\
    \t\"msg\": \"no baseline for no-todo yet\",\n\
    }\n";

fn ratchet_repo(name: &str, read_back: bool) -> PathBuf {
    let module = if read_back {
        "policy/ratchet.rego"
    } else {
        "policy/blind.rego"
    };
    let body = if read_back { READS_BACK } else { BLIND };
    Fixture::new(name)
        .config(&ratchet_config(read_back))
        .file("src/lib.rs", "// TODO: something\n")
        .file(module, body)
        .git()
        .base_commit()
        .build()
}

#[test]
fn a_baseline_written_by_one_run_is_read_back_as_a_fact_by_the_next() {
    let dir = ratchet_repo("sink-ratchet", true);

    let first = run(&dir, &["enforce"]);
    assert!(
        stdout(&first).contains("needs-a-baseline"),
        "the first run has no baseline to read: {}",
        stdout(&first)
    );

    let second = run(&dir, &["enforce"]);
    assert!(
        !stdout(&second).contains("needs-a-baseline"),
        "the second run reads the baseline the first produced: {}",
        stdout(&second)
    );
}

#[test]
fn dropping_the_read_back_stops_the_ratchet() {
    // Shown able to fail (CLOUD-418), and it is the arm that makes the one above
    // mean something: identical config, identical record on disk, a module that
    // does not consult it — and the row fires on both runs.
    let dir = ratchet_repo("sink-ratchet-blind", false);

    let first = run(&dir, &["enforce"]);
    let second = run(&dir, &["enforce"]);
    assert!(stdout(&first).contains("needs-a-baseline"));
    assert!(
        stdout(&second).contains("needs-a-baseline"),
        "a module that reads no baseline cannot be ratcheted by one: {}",
        stdout(&second)
    );
}
