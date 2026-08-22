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
fn record(dir: &Path, kind: &str, rule: &str, discriminator: &str) -> Option<String> {
    fs::read_to_string(
        dir.join(".git/batten-sinks")
            .join(kind)
            .join(rule)
            .join(discriminator),
    )
    .ok()
}

#[test]
fn enforce_writes_the_record_a_rule_declared() {
    let dir = repo("sink-journal", "journal", "rule");
    let output = run(&dir, &["enforce"]);
    assert_eq!(output.status.code(), Some(0), "a warn-severity finding");

    let written = record(&dir, "journal", "no-todo", "rule").expect("the journal reached disk");
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
        record(&dir, "journal", "no-todo", "rule").is_none(),
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
        record(&journal, "journal", "no-todo", "rule")
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
        record(&baseline, "baseline", "no-todo", "rule")
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
        record(&dir, "marker", "no-todo", "rule").as_deref(),
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
        seen.insert(record(&dir, "baseline", "no-todo", "rule").unwrap());
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
        record(&dir, "baseline", "no-todo", "main").is_some(),
        "filed under the branch the checkout is on"
    );
    assert!(
        record(&dir, "baseline", "no-todo", "rule").is_none(),
        "and not under the rule-keyed discriminator, which is the other column value"
    );
}

#[test]
fn two_branch_keyed_rules_of_one_kind_do_not_share_a_destination() {
    // THE COLLISION THE FIRST VERSION SHIPPED, and the case eleven green tests
    // could not see: every one of them declared a SINGLE rule with a sink, so a
    // property of a rule SET was outside every assertion.
    //
    // `resolve` used to answer the branch for a branch-keyed sink and use it as
    // the whole filename, so these two rules wrote one path and the sorted order
    // decided which record survived — the other lost with no error. The rule is a
    // path segment now, which makes the collision inexpressible rather than
    // refused: rule ids are already unique in the config, so no two rules can
    // address the same record.
    let dir = Fixture::new("sink-two-rules")
        .config(
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
             key = \"branch\"\n\
             \n\
             [[rule]]\n\
             id = \"no-fixme\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"FIXME\"\n\
             severity = \"warn\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"delete the marker\"\n\
             \n\
             [rule.produces]\n\
             kind = \"baseline\"\n\
             key = \"branch\"\n",
        )
        .file(
            "src/lib.rs",
            "// TODO: one\n// FIXME: two\n// FIXME: three\n",
        )
        .git()
        .base_commit()
        .build();
    let _ = run(&dir, &["enforce"]);

    let todo = record(&dir, "baseline", "no-todo", "main").expect("the first rule's record");
    let fixme = record(&dir, "baseline", "no-fixme", "main").expect("the second rule's record");
    assert_ne!(
        todo, fixme,
        "two rules, two records — one finding against two, so the digests and counts differ"
    );
    assert!(todo.starts_with("no-todo "), "{todo:?}");
    assert!(fixme.starts_with("no-fixme "), "{fixme:?}");
}

#[test]
fn a_run_whose_rules_declare_no_sink_leaves_no_store_at_all() {
    // The acquisition guard, from the read side (CLOUD-851). Reading the store
    // means locating the git dir and, for a branch-keyed sink, reading HEAD, and
    // doing that unconditionally cost `check` a measured 2.103x against its merge
    // base — `perf-compare` refused the branch. A rule set that declares no sink
    // must do exactly what it did before this row landed.
    let dir = Fixture::new("sink-none-declared")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"no-todo\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"TODO\"\n\
             severity = \"warn\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"delete the marker\"\n",
        )
        .file("src/lib.rs", "// TODO: something\n")
        .git()
        .base_commit()
        .build();
    let _ = run(&dir, &["enforce"]);
    assert!(
        !dir.join(".git/batten-sinks").exists(),
        "a run with nothing to produce must not even create the store"
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

    let written = record(&dir, "baseline", "no-todo", "rule").expect("the record reached disk");
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
        record(&dir, "baseline", "no-todo", "rule").is_none(),
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

// --- three collisions and a leak, each found in review -----------------------

#[test]
fn the_component_encoding_is_injective() {
    // `replace('/', "%2F")` alone sends BOTH `a/b` and the literal `a%2Fb` to one
    // component, so two rules with those ids would share a destination and a
    // baseline write would replace the other's record — the same silent loss the
    // rule segment was added to remove, arrived at from the other end. Escaping
    // the escape character first is what makes it injective.
    let dir = Fixture::new("sink-injective")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"a/b\"\n\
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
             id = \"a%2Fb\"\n\
             kind = \"forbid\"\n\
             glob = \"**/*.rs\"\n\
             pattern = \"FIXME\"\n\
             severity = \"warn\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"delete the marker\"\n\
             \n\
             [rule.produces]\n\
             kind = \"baseline\"\n\
             key = \"rule\"\n",
        )
        .file(
            "src/lib.rs",
            "// TODO: one\n// FIXME: two\n// FIXME: three\n",
        )
        .git()
        .base_commit()
        .build();
    let _ = run(&dir, &["enforce"]);

    // `a/b` encodes to `a%2Fb`; the literal `a%2Fb` encodes to `a%252Fb`.
    let slashed = record(&dir, "baseline", "a%2Fb", "rule").expect("the slashed rule's record");
    let literal = record(&dir, "baseline", "a%252Fb", "rule").expect("the literal rule's record");
    assert!(slashed.starts_with("a/b "), "{slashed:?}");
    assert!(literal.starts_with("a%2Fb "), "{literal:?}");
}

#[test]
fn a_journal_never_reaches_the_policy_input() {
    // A journal is specified as an audit trail nothing reads back as a decision
    // input, and `Production::reads_back` says so — but for one commit that
    // predicate had NO CALL SITE, so `store` loaded journals beside baselines and
    // a module could decide on one. A statement without a mechanism is prose
    // (non-negotiable rule 2); the mechanism is `store`'s filter, and this is what
    // fails without it.
    let module = "package batten\n\
        \n\
        rules contains \"reads-the-journal\"\n\
        \n\
        violation contains {\n\
        \t\"rule\": \"reads-the-journal\",\n\
        \t\"msg\": \"the journal was readable\",\n\
        } if {\n\
        \tinput.tree.produced[\"no-todo\"]\n\
        }\n";
    let dir = Fixture::new("sink-journal-unreadable")
        .config(
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
             kind = \"journal\"\n\
             key = \"rule\"\n\
             \n\
             [[rule]]\n\
             id = \"reads-the-journal\"\n\
             kind = \"policy\"\n\
             scope = \"tree\"\n\
             module = \"policy/reads.rego\"\n\
             severity = \"warn\"\n\
             no_fix_reason = \"nothing to fix; this row exists to prove the journal is unreadable\"\n",
        )
        .file("src/lib.rs", "// TODO: something\n")
        .file("policy/reads.rego", module)
        .git()
        .base_commit()
        .build();

    // The first run writes the journal; the second is the one that could read it.
    let first = run(&dir, &["enforce"]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "two warn-severity rows: {}",
        stdout(&first)
    );
    assert!(
        record(&dir, "journal", "no-todo", "rule").is_some(),
        "the journal reached disk, so the second run has something to not-read"
    );
    let second = run(&dir, &["enforce"]);
    // THE EXIT CODE FIRST, AND THAT ORDER IS THE POINT. The absence of a string in
    // stdout is only evidence if the run that would have printed it got as far as
    // evaluating the policy: a second run dying at config load prints nothing and
    // satisfies the assertion below for the wrong reason — a vacuous pass of
    // exactly the class this bundle keeps finding (CLOUD-845).
    assert_eq!(
        second.status.code(),
        Some(0),
        "the second run has to reach policy evaluation for its silence to mean \
         anything: {}",
        stdout(&second)
    );
    assert!(
        !stdout(&second).contains("reads-the-journal"),
        "a write-only record reached the policy input: {}",
        stdout(&second)
    );
}

#[test]
fn a_declared_record_that_cannot_be_read_fails_the_run_rather_than_reading_as_absent() {
    // COULD-NOT-LOOK IS NOT ABSENT, and this is the arm that proves the store
    // distinguishes them. `store` read every declared key with `if let Ok(text)`,
    // so a baseline that exists and cannot be read arrived at the policy as "no
    // earlier run produced this" — the ratchet then compared against nothing and
    // passed. A silently-off gate is the failure this whole bundle is about.
    //
    // The unreadable condition is a DIRECTORY where the record belongs, not a
    // permission bit: this sandbox runs as root, so a mode-000 file is still
    // readable here and the arm would assert its own premise (`.claude/rules/rust.md`).
    //
    // SHOWN ABLE TO FAIL (CLOUD-418), observed rather than argued: with the read
    // restored to `if let Ok(text)` this case reports `left: Some(0)` — the run
    // decided, reported the `forbid` hit, and exited clean while the baseline it
    // declared had never been read.
    let dir = repo("sink-unreadable-baseline", "baseline", "rule");
    let occupied = dir.join(".git/batten-sinks/baseline/no-todo/rule");
    fs::create_dir_all(&occupied).unwrap();

    let output = run(&dir, &["enforce"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "an unreadable declared record is an internal failure, not a verdict and \
         not an absence: {}",
        stdout(&output)
    );
}

#[test]
fn a_mediated_call_scoped_row_may_not_declare_a_sink() {
    // `RuleKind::Policy` scopes to BOTH surfaces, so checking the KIND's
    // capability let a `scope = "mediated_call"` policy row carry `produces`: it
    // validated, the tree runner skipped it as another surface's business, and
    // the declared record was never written. The row's own scope is the question.
    let dir = Fixture::new("sink-wrong-scope-policy")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"call-shaped\"\n\
             kind = \"policy\"\n\
             scope = \"mediated_call\"\n\
             module = \"policy/call.rego\"\n\
             severity = \"deny\"\n\
             no_fix_reason = \"nothing to fix\"\n\
             \n\
             [rule.produces]\n\
             kind = \"journal\"\n",
        )
        .file(
            "policy/call.rego",
            "package batten\n\nrules contains \"call-shaped\"\n",
        )
        .build();
    let output = run(&dir, &["check"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("mediated_call"),
        "the refusal names the scope that cannot carry it: {}",
        common::stderr(&output)
    );
}
