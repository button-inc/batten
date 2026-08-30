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
//! `.claude/rules/rust.md` and the reason `RuleCost`'s `PartialEq` skips
//! `elapsed`.
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

    let scan = rules::run_static(
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

    let ids: Vec<&str> = scan.costs.iter().map(|cost| cost.rule.as_str()).collect();
    assert_eq!(
        ids,
        ["reads-the-txt", "matches-nothing", "reads-the-txt-again"],
        "one census row per rule, in declaration order — a skipped rule included"
    );
    let skipped = scan
        .costs
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

    let scan = rules::run_static(&[row("reads-three", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");

    let cost = scan.costs.first().expect("the row has a census entry");
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
    let widened = rules::run_static(&[row("reads-four", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");
    let widened = widened.costs.first().expect("the row has a census entry");
    assert_eq!(
        (widened.files_read, widened.bytes_read),
        (4, bytes + extra.len()),
        "adding a file to the glob moves both counts, so the assertions above assert something"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn the_census_measures_the_run_rather_than_identifying_it() {
    // `Scan` derives `PartialEq` and two runs over one unchanged tree are the
    // same scan — that is what byte-stability rests on. `RuleCost` therefore
    // compares on its DETERMINISTIC half and skips the clock, because a derived
    // comparison would make scan equality timing-dependent and quietly false.
    //
    // Fails by: deriving `PartialEq` on `RuleCost`, which makes these two unequal
    // whenever the two runs differ by a nanosecond — which is almost always.
    let root = scratch("equality");
    seed(&root, 2);

    let first = rules::run_static(&[row("reads-two", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");
    let second = rules::run_static(&[row("reads-two", "*.txt")], &[], vocabulary(), &root)
        .expect("the read surface runs the row");

    assert_eq!(
        first.costs, second.costs,
        "two runs over one unchanged tree carry the same census, whatever the clock said"
    );

    let _ = fs::remove_dir_all(&root);
}
