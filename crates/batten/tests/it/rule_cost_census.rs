//! CLOUD-1217: the engine reports what each rule cost, so a slow gate is
//! attributable from its own output.
//!
//! **Why this exists at all.** `batten-check` ran 465s of a 1327s CI job and
//! emitted two lines. No rule kind reported its own duration and every
//! `command`-rule child has `Stdio::null()` on both streams, so the largest item
//! in this repository's CI was unattributable *by construction*. Two sessions in
//! a row attributed it confidently and wrongly — once to `source carry unsafe` (which
//! measures 3%) and once to `forbid`/`ratchet` read amplification (which
//! measures ~150ms) — before an instrument existed to ask. The census is that
//! instrument and this is its gate: without a case under it, it is a log rather
//! than a mechanism, which non-negotiable rule 2 refuses.
//!
//! **Its own test binary, for `document_read_count.rs`'s reason exactly**:
//! `rules::files_read` and `rules::bytes_read` are process-global counters read
//! as a delta, so a sibling case reading a file in the same process would race
//! the deltas below under a harness that threads rather than forks.
//!
//! **Counts are the assertion, never the clock.** `RuleCost::elapsed` is a
//! measurement and varies run to run; the counts are deterministic. Asserting a
//! duration here would discriminate nothing, which is the standing rule in
//! `rules/rust.md`.
//!
//! Asserted through `run_static` — the surface a consumer reaches — rather than
//! by widening anything to `pub` for a test's convenience.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule};

/// An empty vocabulary: every row here is a native `forbid`, which raises no
/// declared verdict token, and `load` refuses a table naming a token nothing
/// raises.
fn vocabulary() -> batten::policy::Vocabulary<'static> {
    batten::policy::Vocabulary {
        patterns: &[],
        verdicts: &[],
        words: None,
        recorders: &[],
    }
}

/// A `forbid` row over `glob`, looking for a literal that is never present — the
/// census is about what a rule READ, so a row that finds nothing still has to
/// report the files it opened to find that out.
fn row(id: &str, glob: &str) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "forbid",
        "scope": "tree",
        "glob": glob,
        "pattern": "a-literal-no-fixture-carries",
        "severity": "deny",
    }))
    .expect("a tree-scoped forbid row the loader accepts")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("batten-census-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("policy")).expect("scratch");
    dir
}

/// Write `count` files of known, distinct sizes and return their total bytes.
fn seed(root: &Path, count: usize) -> usize {
    (0..count)
        .map(|i| {
            let body = "x".repeat(i + 1);
            fs::write(root.join(format!("f{i}.txt")), &body).expect("fixture");
            body.len()
        })
        .sum()
}

#[test]
fn every_rule_gets_one_census_row_in_declaration_order() {
    // A rule whose glob selects nothing is SKIPPED, and it still earns a row
    // reporting zero. That is deliberate rather than incidental: "this rule cost
    // nothing" and "this rule is missing from the report" are different answers,
    // and collapsing them is how a rule that stopped running would look cheap.
    //
    // Fails by: pushing the cost inside the `if let Some(why)` arm, which drops
    // every rule that ran clean.
    let root = scratch("order");
    seed(&root, 2);

    rules::run_static(
        &[
            row("reads-the-txt", "*.txt"),
            row("matches-nothing", "*.no-such-extension"),
            row("reads-the-txt-again", "*.txt"),
        ],
        &[],
        vocabulary(),
        &root,
    )
    .expect("the read surface runs the rows");

    let costs = rules::rule_costs();
    let ids: Vec<&str> = costs.iter().map(|cost| cost.rule.as_str()).collect();
    assert_eq!(
        ids,
        ["reads-the-txt", "matches-nothing", "reads-the-txt-again"],
        "one census row per rule, in declaration order — a skipped rule included"
    );
    let skipped = costs
        .iter()
        .find(|cost| cost.rule == "matches-nothing")
        .expect("the skipped rule has a row");
    assert_eq!(
        (skipped.files_read, skipped.bytes_read),
        (0, 0),
        "a rule that selected nothing read nothing, and says so rather than being absent"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_rule_reports_one_read_per_file_its_glob_selected() {
    // THE PROPERTY THE CENSUS IS FOR. Attribution is only worth anything if the
    // counts track what a rule actually opened, so this pins the count to the
    // matched set and the byte total to those files' sizes.
    //
    // Fails by: dropping the `count_read` call in `forbid_in_files`, which makes
    // both deltas zero while the rule still runs.
    let root = scratch("counts");
    let bytes = seed(&root, 3);

    rules::run_static(&[row("reads-three", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");

    let costs = rules::rule_costs();
    let cost = costs.first().expect("the row has a census entry");
    assert_eq!(
        cost.files_read, 3,
        "three matched files is three reads — the census counts what was opened"
    );
    assert_eq!(
        cost.bytes_read, bytes,
        "the byte total is those files' own sizes, so a count cannot drift from what was read"
    );

    // ANTI-VACUITY, in the same function: a counter wired to a constant would
    // satisfy the assertions above however the engine behaved.
    let extra = "yyyy";
    fs::write(root.join("f3.txt"), extra).expect("fixture");
    rules::run_static(&[row("reads-four", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");
    let widened = rules::rule_costs();
    let widened = widened.first().expect("the row has a census entry");
    assert_eq!(
        (widened.files_read, widened.bytes_read),
        (4, bytes + extra.len()),
        "adding a file to the glob moves both counts, so the assertions above assert something"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_census_describes_the_last_run_rather_than_accumulating() {
    // THE ONE THING A PER-RULE LIST OWES OVER THE TWO COUNTERS IT IS BUILT FROM.
    // `files_read`/`bytes_read` are monotonic and read as a delta; a list read
    // that way would hand a caller the previous run's rows as well, so `run`
    // clears the store before it fills it. A caller therefore reads "the run that
    // just finished" rather than "every run this process has done".
    //
    // Fails by: dropping the `costs_lock().clear()` in `run`, which makes the
    // second census six rows rather than one.
    let root = scratch("perrun");
    seed(&root, 2);

    rules::run_static(
        &[
            row("first", "*.txt"),
            row("second", "*.txt"),
            row("third", "*.txt"),
        ],
        &[],
        vocabulary(),
        &root,
    )
    .expect("the read surface runs the rows");
    assert_eq!(
        rules::rule_costs().len(),
        3,
        "three rows, three census entries"
    );

    rules::run_static(&[row("alone", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");
    let after = rules::rule_costs();
    assert_eq!(
        after.len(),
        1,
        "the second run's census is its own, not appended to the first's"
    );
    assert_eq!(
        after[0].rule, "alone",
        "and it names the rule that actually ran"
    );

    let _ = fs::remove_dir_all(&root);
}

/// A `policy` row over `sources`, with a module that declares a predicate and
/// never violates.
///
/// Never violating is the point: this case is about what the rule READ, and a
/// finding would drag the verdict registry in for no gain — `vocabulary()` above
/// is empty by design, and a module raising a token nothing declares fails the
/// load.
fn policy_row(id: &str, sources: &[&str]) -> Rule {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "kind": "policy",
        "scope": "tree",
        "module": "policy/census-probe.rego",
        "sources": sources,
        "severity": "deny",
    }))
    .expect("a tree-scoped policy row the loader accepts")
}

fn install_probe(root: &Path) {
    fs::write(
        root.join("policy/census-probe.rego"),
        "package batten.census_probe\n\nimport rego.v1\n\nrules contains \"census-probe\"\n",
    )
    .expect("probe module");
}

/// Write `count` parseable documents of known, distinct sizes; return the total.
///
/// TOML rather than the `.txt` [`seed`] writes, and the difference is load-bearing
/// here: `.txt` names no `Format`, so a `sources` glob over it resolves to
/// `UnknownFormat` before any I/O and would measure the case below instead of
/// this one.
fn seed_documents(root: &Path, count: usize) -> usize {
    (0..count)
        .map(|i| {
            let body = format!("key = {}\n", "9".repeat(i + 1));
            fs::write(root.join(format!("d{i}.toml")), &body).expect("fixture");
            body.len()
        })
        .sum()
}

#[test]
fn the_shared_acquisition_reports_the_documents_it_read() {
    // CLOUD-1790. `acquire` is the one function that acquires a document and it
    // counted nothing, so these reads were counted NOWHERE — not in the global
    // counters, and therefore not in any census row.
    //
    // THE ROW IS THE STEP, NOT A RULE, and that is the correction this case
    // encodes. Declared documents are acquired ONCE for the whole run, before
    // the per-rule loop, so a `policy` row's reads fall outside its own
    // measurement window by construction: every such row reported
    // `0 file(s) 0 byte(s)`, the run total summed those zeros, and a reader
    // comparing that against a `forbid` row's real numbers concluded the policy
    // row had received no input. Charging the shared read to whichever row the
    // loop reached first would be the other error — the cache is shared on
    // purpose, so the cost is the step's.
    //
    // Fails by: dropping the `count_read` call in `acquire` (both counts go to
    // zero while the documents are still read and parsed), or by dropping the
    // census row (the step disappears and the reads are unattributed again).
    let root = scratch("declared-acquisition");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    install_probe(&root);
    let bytes = seed_documents(&root, 3);

    rules::run_static(
        &[policy_row("reads-three-documents", &["**/*.toml"])],
        &[],
        vocabulary(),
        &root,
    )
    .expect("the read surface runs the row");

    let costs = rules::rule_costs();
    let shared = costs
        .iter()
        .find(|cost| cost.rule == "(declared documents)")
        .expect("the shared acquisition earns its own census row");
    assert_eq!(
        shared.files_read, 3,
        "the shared step reports one read per document the rule set declared"
    );
    assert_eq!(
        shared.bytes_read, bytes,
        "and the bytes those reads returned, not a placeholder"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_rule_set_declaring_no_documents_earns_no_acquisition_row() {
    // The row appears only when there is a step to report. Without this, every
    // run of `forbid` rows would grow a zero row for work it never did — which is
    // the same "evaluated, and free" misreading the per-rule census already
    // refuses one level up.
    //
    // Fails by: pushing the acquisition row unconditionally.
    let root = scratch("no-acquisition");
    seed(&root, 2);

    rules::run_static(&[row("reads-the-txt", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");

    let costs = rules::rule_costs();
    assert!(
        !costs.iter().any(|cost| cost.rule == "(declared documents)"),
        "a rule set declaring no documents acquires nothing and reports no step"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_row_refused_before_any_io_reports_nothing_read() {
    // The other side of the fix, and the one that keeps it honest. An extension
    // this build has no parser for is `UnknownFormat`, decided BEFORE the file is
    // opened — so it must still report zero. Counting it would turn a config
    // fault that costs nothing into a charged read, which is the same class of
    // lie in the opposite direction.
    //
    // The fixture files EXIST, so a passing assertion here is about the
    // declaration rather than about an absent path.
    //
    // Fails by: moving the `count_read` call above the `UnknownFormat` early
    // return in `acquire`.
    let root = scratch("policy-unknown-format");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    install_probe(&root);
    seed(&root, 3);

    rules::run_static(
        &[policy_row("reads-nothing-parseable", &["**/*.txt"])],
        &[],
        vocabulary(),
        &root,
    )
    .expect("the read surface runs the row");

    let costs = rules::rule_costs();
    let cost = costs.first().expect("the row has a census entry");
    assert_eq!(
        (cost.files_read, cost.bytes_read),
        (0, 0),
        "a declaration decided before any I/O is not charged for a read it never made"
    );

    let _ = fs::remove_dir_all(&root);
}
