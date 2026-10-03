//! `policy/shell-retirement.rego`'s cost is flat in the deleted-path count
//! (CLOUD-1321).
//!
//! **THE BOUNDS ARE ALLOCATION COUNTS, AND THE CLOCK IS ONLY REPORTED (CLOUD-2022).**
//! This case was a wall-clock assertion, on the premise that no counter answered:
//! `RuleCost`'s `files_read` and `bytes_read` are identical across the arms, and
//! regorus exposes no evaluation-step counter. That premise was wrong. The scan
//! runs IN-PROCESS, and the `it` binary's allocator is `stats_alloc`'s counting
//! one (`main.rs`), so the number of allocations evaluation makes is the work
//! done, counted — and the same number on every runner.
//!
//! The clock failed green trees twice, each on the platform it had not been
//! measured on, and each time the answer was to widen it: 3x → 8x for Windows's
//! 8.1x, then 8x → 30x for macOS's 10.4x. A ratio over wall time between the
//! index-free floor and a deleting arm is a property of the machine, and a bound
//! that has to be re-widened per platform is measuring the platforms.
//!
//! Measured here, the warm run of each arm: 1,559,764 allocations at zero
//! deletions, 7,726,980 at one, 7,733,428 at two, 7,759,265 at six. The index
//! build is ~6.17M allocations and each further deleted path ~6.5k. The unflattened
//! module re-walks the corpus per path, so it pays the ~6M per path rather than
//! once. Repeat runs of one arm agree to within ~30 allocations of 7.7M; the
//! first run of the process is ~20k higher (one-time initialisation), which is why
//! the reading is the LAST run rather than the first.
//!
//! The wall-clock history this case carried, kept because it is why the
//! instrument changed:
//!
//! **What kept the clock from being a coin flip was the margin, not a tolerance band.**
//! Measured on this fixture, unflattened: 0.39s / 27.5s / 81.3s for zero, two and
//! six deleted paths — 210x the floor, reproducing the ~15s-per-path term
//! CLOUD-1321 measured on the #793 branch (0.43s / 29.6s / 96.2s). Flattened:
//! 0.36s / 0.85s / 0.91s here, and 0.68s / 1.99s / 2.10s on the Windows CI
//! runner. Both assertions below sit an order of magnitude clear of the
//! unflattened reading, so noise would have to dwarf the signal to flip either. A
//! percentage-band timing assertion would be the thing rust.md refuses; these are
//! step-change detectors.
//!
//! **The Windows reading is why `RATIO` stopped being 3, and macOS's (10.4x on
//! a fast runner) is why it stopped being 8; both are recorded rather than
//! tuned away.** The two platforms agree on the term this case names
//! — four more deletions cost 0.06s here and 0.12s there, against first-two steps
//! of 0.49s and 1.31s — and disagree on the ratio of the index build to the
//! floor, which is a machine property and not the module's. A bound that a green
//! tree fails on a slower or faster box is measuring the box.
//!
//! Three further guards: the floor case fails LOUDLY if the fixture corpus ever
//! stops being large enough for the term to exist (an anti-vacuity term — a
//! shrunken corpus would otherwise make the ratio pass over nothing), each arm is
//! the MINIMUM of three runs (a latency floor is a minimum; noise only adds), and
//! every arm asserts a clean verdict first, so the case can only ever be
//! measuring evaluation and never a finding.
//!
//! `rules::rule_costs()` is process-global and cleared per `run`, so the arms
//! live in one `#[test] fn`, read back between runs. Under nextest — which is how
//! `mise run test` invokes this — that function owns its process. Under a bare
//! `cargo test` a sibling could interleave, which is the hazard `mise.toml`
//! documents for exactly this reason.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::time::Duration;

use batten::rules;

use crate::shell_retirement::{Head, install_module, repo, scan};

/// How many times each arm is run. The count is the LAST run's, after the
/// process's one-time initialisation; the clock reading is the minimum.
const RUNS: usize = 3;

/// The absolute bound, in allocations: six deletions against ONE deletion.
///
/// **Against one deletion rather than zero, and that is the fix for the clock's
/// defect, not a detail.** Zero deletions build no index; one deletion builds it.
/// So one and six are the SAME work class — the scan plus the index — and the only
/// difference between them is the per-path term this case exists to bound.
/// Measured: 7,759,265 / 7,726,980 = 1.004x flattened. Unflattened, each path
/// re-walks the corpus (~6M allocations here), which reads ~5x. 2 sits ~2x above
/// the one and ~2.5x below the other.
const SAME_CLASS_BOUND: usize = 2;

/// Below this, the index build is too small for the per-path term to be told
/// apart from noise, and every bound would pass over nothing. Measured ~6.17M.
const MEASURABLE_ALLOCATIONS: usize = 1_000_000;

// THE WALL-CLOCK BOUND this case used to assert, six deletions against the
// zero-deletion floor. No longer asserted (CLOUD-2022); kept as the record of why
// a clock ratio cannot be the bound.
//
// **This ratio is over two different constants, which is why it is loose and
// why 3 was wrong.** The floor is one scan of the corpus with no index built at
// all — `arm_pairs`' first conjunct is `count(delta.deleted) > 0` — and every
// deleting arm is that scan PLUS the one-off index build. Those two are
// different work, so their ratio is a property of the machine rather than of the
// module: measured 2.5x on this container (0.36s / 0.91s) and **3.1x on the
// Windows CI runner** (0.68s / 2.10s), where the same flattened module is
// correct. A `RATIO` of 3 therefore failed a green tree on a slower box, which
// is the percentage-band assertion `rules/rust.md` refuses wearing a
// step-change detector's clothes.
//
// **And 8 was wrong for the same reason 3 was.** The macOS runner reads
// 10.4x on a green tree (0 deletions 67.8ms, 2 deletions 605ms, 6 deletions
// 702ms, #1051's matrix on 63a21a5a): a fast machine shrinks the floor's scan
// far more than the index build, so the ratio GROWS with speed. The linearity
// term on that same run passed by 5x (97ms against 537ms), so the module was
// correct and the bound was not.
//
// 30 is the step-change line: ~2.9x above the worst passing reading any
// platform has produced, and ~7x below the 210x the unflattened module reads.
// The linearity term below is what actually names the defect and it is
// unmoved; this is the coarse bound beside it, and it only has to refuse a
// shape nothing between those two numbers can produce.
//
// And 30 would have needed widening again on the next faster runner, which is
// the point: see [`SAME_CLASS_BOUND`] for the bound that replaced it.

/// A governed shell program, which is what `governed_when_deleted` classifies a
/// `mise-tasks/*.sh` path as.
const GATE: &str = "#!/usr/bin/env bash\n#MISE description=\"a gate\"\necho hi\n";

/// The corpus `arms_for` walks: files under `crates/batten/tests/`, which is the
/// prefix the module filters `input.tree.lines` to.
///
/// **Sized so one scan is measurable and a green run is still cheap.** The
/// production corpus is ~152k lines (`batten.toml`'s `line_sources` spans
/// `mise-tasks/*.sh`, `crates/batten/tests/**/*.rs` and `tests/**/*.bats`); this
/// is roughly a quarter of it. The unflattened module walked all of it once per
/// deleted path, so the six-deletion arm walked it six times.
const CORPUS_FILES: usize = 40;
const CORPUS_LINES: usize = 1_000;

/// One fully-mapped ledger arm per retired path, so every arm below is a clean
/// verdict rather than a refusal being timed.
fn ledger(index: usize) -> String {
    format!(
        "// carried: mise-tasks/gone-{index}.sh policy/gone-{index}.rego \
         crates/batten/tests/gone_{index}.rs\n"
    )
}

/// The base tree: the corpus, plus `count` governed programs and the ledger rows
/// that map them.
fn base(count: usize) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    for file in 0..CORPUS_FILES {
        let mut body = String::with_capacity(CORPUS_LINES * 24);
        for line in 0..CORPUS_LINES {
            // Ordinary source lines. None carries an arm marker, so every one of
            // them is a line the scan must look at and reject — which is the work
            // being measured.
            let _ = writeln!(body, "// corpus file {file} line {line}");
        }
        files.push((format!("crates/batten/tests/it/corpus_{file}.rs"), body));
    }
    // The ledger the retirements are mapped by, in one file, as the real one is.
    let mut rows = String::new();
    for index in 0..count {
        rows.push_str(&ledger(index));
    }
    files.push(("crates/batten/tests/it/ledger.rs".to_owned(), rows));
    for index in 0..count {
        files.push((format!("mise-tasks/gone-{index}.sh"), GATE.to_owned()));
        // The successors the ledger row names have to exist, or the arm is
        // refused for a reason that has nothing to do with cost.
        files.push((format!("policy/gone-{index}.rego"), String::new()));
        files.push((
            format!("crates/batten/tests/gone_{index}.rs"),
            String::new(),
        ));
    }
    files
}

/// What one arm costs: `count` governed paths deleted at head, everything else
/// unchanged. No EDITED governed file in any arm — CLOUD-1321's §2 protocol, and
/// the reason the `base_set` hoist that shipped alongside is not claimed here.
fn arm(name: &str, count: usize) -> (Duration, usize) {
    let owned = base(count);
    let base_files: Vec<(&str, &str)> = owned
        .iter()
        .map(|(path, body)| (path.as_str(), body.as_str()))
        .collect();
    let removed: Vec<String> = (0..count)
        .map(|index| format!("mise-tasks/gone-{index}.sh"))
        .collect();
    let removed_refs: Vec<&str> = removed.iter().map(String::as_str).collect();

    let root = repo(
        name,
        &base_files,
        &Head {
            written: &[],
            removed: &removed_refs,
        },
    );
    install_module(&root);

    let mut best = Duration::MAX;
    let mut counted: Option<usize> = None;
    for run in 0..RUNS {
        let region = stats_alloc::Region::new(crate::ALLOCATOR);
        let scanned = scan(&root);
        let allocations = region.change().allocations;
        // A COUNT THAT MOVES BETWEEN RUNS OF ONE ARM IS NOT A COUNT. Asserted, not
        // assumed: the case's whole claim is that this number is the same on every
        // runner, and the first place that could fail is the same process twice.
        // It used to say "asserted" over a binding that was only overwritten
        // (CLOUD-2059). Compared from the second run on: the first in a process
        // also pays its one-time memos, measured at ~21,000 allocations over the
        // second, while two runs after it differ by about 30 — so a thousand is a
        // count's tolerance and not a clock's.
        if run > 1
            && let Some(previous) = counted
        {
            assert!(
                allocations.abs_diff(previous) <= 1_000,
                "{name}: one arm counted {previous} and then {allocations} allocations, so the \
                 reading moves between runs and is not a count"
            );
        }
        counted = Some(allocations);
        assert!(
            scanned.findings.is_empty(),
            "{name}: every arm must be a CLEAN verdict, or the reading is timing a \
             refusal rather than the scan: {:?}",
            scanned
                .findings
                .iter()
                .map(|finding| finding.rule.as_str())
                .collect::<Vec<_>>()
        );
        let costs = rules::rule_costs();
        let cost = costs
            .iter()
            .find(|cost| cost.rule == "shell retire partial")
            .expect("the census carries the row that just ran");
        best = best.min(cost.elapsed);
    }
    (best, counted.expect("RUNS is at least one"))
}

/// The §2 table, as a case, counted: four more deletions cost less than the first
/// two, and six deletions stay within [`SAME_CLASS_BOUND`] of one — in allocations,
/// which read the same on every runner (CLOUD-2022).
///
/// Shown able to fail per CLOUD-418 by reverting `arms_for` in
/// `policy/shell-retirement.rego` to the per-call comprehension over
/// `input.tree.lines` that `arm_rows` replaced (CLOUD-1321). The declared
/// mutation, in a plain comment because the module's `#MUTANT-SUITE` is
/// `shell_retirement.rs` and one gate has one suite, so its kill is shown by hand;
/// `\x7c` is GNU sed's spelling of the comprehension's bar, which the row's own
/// field separator would otherwise swallow:
// MUTANT arms-for-rescans-corpus|s@^arms_for(path) := object.get(arm_rows, path, set())$@arms_for(path) := {trim_space(line) \x7c some file, lines in input.tree.lines; startswith(file, "crates/batten/tests/"); some line in lines; some marker in arm_markers; startswith(trim_space(line), marker); split(trim_space(substring(trim_space(line), count(marker), -1)), " ")[0] == path}@|deleting_six_governed_paths_costs_a_flat_multiple_of_the_floor
#[test]
fn deleting_six_governed_paths_costs_a_flat_multiple_of_the_floor() {
    let (floor, floor_n) = arm("cost-zero", 0);
    let (one, one_n) = arm("cost-one", 1);
    let (two, two_n) = arm("cost-two", 2);
    let (six, six_n) = arm("cost-six", 6);

    // The clock is REPORTED beside the count in every message, never bounded: it
    // is what a reader wants to see, and what no runner can be held to.
    let table = format!(
        "allocations 0={floor_n} 1={one_n} 2={two_n} 6={six_n} \
         (wall, reported only: {floor:?} / {one:?} / {two:?} / {six:?})"
    );

    // THE ANTI-VACUITY TERM. If the index build ever stops being large enough to
    // tell the per-path term apart, both bounds below would pass over nothing — so
    // this shouts rather than going quietly green.
    let index_build = one_n.saturating_sub(floor_n);
    assert!(
        index_build >= MEASURABLE_ALLOCATIONS,
        "the index build allocates {index_build} times, under {MEASURABLE_ALLOCATIONS}, \
         so the bounds below would pass over nothing: restore CORPUS_FILES x \
         CORPUS_LINES — {table}"
    );

    // THE LINEARITY TERM, and it is the one that names the defect. Going from two
    // deletions to six adds four more paths; going from zero to two pays the
    // one-off index build plus two. Flattened, the four-path step is ~26k
    // allocations against a ~6.2M first step; unflattened, each path re-walks the
    // corpus, so the four-path step is ~4 index builds against ~2.
    let first_step = two_n.saturating_sub(floor_n);
    let second_step = six_n.saturating_sub(two_n);
    assert!(
        second_step <= first_step,
        "the ledger scan is linear in the deleted-path count again: four more \
         deletions allocated {second_step} times where the first two allocated \
         {first_step}, so `arms_for` is scanning `input.tree.lines` per path instead \
         of looking its answer up in `arm_rows` — {table}"
    );

    // AND AN ABSOLUTE BOUND, because a linearity test alone would pass over a term
    // that grew quadratically and then flattened, or over one whose constant had
    // exploded. Against ONE deletion, the same work class, so the ratio is the
    // module's and not the machine's: 1.004x flattened, ~5x unflattened.
    assert!(
        six_n <= one_n * SAME_CLASS_BOUND,
        "six deletions allocated more than {SAME_CLASS_BOUND}x what one did — {table}"
    );
}
