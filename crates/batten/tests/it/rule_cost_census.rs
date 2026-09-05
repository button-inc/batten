//! CLOUD-1217: the engine reports what each rule cost, so a slow gate is
//! attributable from its own output.
//!
//! **Why this exists at all.** `batten-check` ran 465s of a 1327s CI job and
//! emitted two lines. No rule kind reported its own duration and every
//! `command`-rule child has `Stdio::null()` on both streams, so the largest item
//! in this repository's CI was unattributable *by construction*. Two sessions in
//! a row attributed it confidently and wrongly — once to `no-secrets` (which
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
