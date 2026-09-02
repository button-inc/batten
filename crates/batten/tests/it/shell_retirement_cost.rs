//! `policy/shell-retirement.rego`'s cost is flat in the deleted-path count
//! (CLOUD-1321).
//!
//! **This is a wall-clock assertion, deliberately, and `.claude/rules/rust.md`'s
//! standing rule is why that needs saying.** That rule forbids a clock *where a
//! counter would answer* — "assert it with a counter and a repeat-run comparison,
//! never with wall clock: a timing assertion discriminates nothing here". Read
//! the clause, not the slogan. No counter answers this question: `RuleCost`'s
//! `files_read` and `bytes_read` are identical across all three arms below,
//! because the corpus is opened once per rule however many paths the delta
//! deletes, and regorus exposes no evaluation-step counter — its engine offers a
//! coverage report (which lines ran) and nothing that counts how often one ran.
//! The term being measured is precisely *work repeated per deleted path*, and the
//! clock is the only instrument that sees it. That is CLOUD-1321's own premise.
//!
//! **What keeps it from being a coin flip is the margin, not a tolerance band.**
//! Measured on this fixture, unflattened: 0.39s / 27.5s / 81.3s for zero, two and
//! six deleted paths — 210x the floor, reproducing the ~15s-per-path term
//! CLOUD-1321 measured on the #793 branch (0.43s / 29.6s / 96.2s). Flattened:
//! 0.36s / 0.85s / 0.91s. Both assertions below sit an order of magnitude clear
//! of both readings, so noise would have to dwarf the signal to flip either. A
//! percentage-band timing assertion would be the thing rust.md refuses; these are
//! step-change detectors.
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

use std::time::Duration;

use batten::rules;

use crate::shell_retirement::{Head, install_module, repo, scan};

/// How many times each arm is run. The reading is the MINIMUM across them.
const RUNS: usize = 3;

/// The absolute bound the six-deletion arm must stay inside, against the
/// zero-deletion floor.
///
/// CLOUD-1321's acceptance says 2x. It is 3x here, and the reason is that the fix
/// beat the row's own arithmetic rather than missing it: guarding `arm_pairs` so
/// the index is only built when the delta deletes something made the FLOOR
/// cheaper (0.39s -> 0.36s on this fixture), which shrinks the denominator the
/// ratio is taken against. Six deletions cost 0.91s where they cost 81.3s before.
/// The linearity term below is what actually names the defect; this is the
/// coarse bound beside it.
const RATIO: u32 = 3;

/// Below this, the fixture corpus is too small for the term to be measurable at
/// all and the ratio assertions would pass over nothing.
const MEASURABLE: Duration = Duration::from_millis(20);

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
            body.push_str(&format!("// corpus file {file} line {line}\n"));
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
fn arm(name: &str, count: usize) -> Duration {
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
    for _ in 0..RUNS {
        let scanned = scan(&root);
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
            .find(|cost| cost.rule == "shell-retirement")
            .expect("the census carries the row that just ran");
        best = best.min(cost.elapsed);
    }
    best
}

/// The §2 table, as a case: the six-deletion arm reads within `RATIO` of the
/// zero-deletion floor.
///
/// Shown able to fail per CLOUD-418 by reverting `arm_pairs`/`arm_rows` in
/// `policy/shell-retirement.rego` to the `arms_for(path) := rows if { … }`
/// function this replaced, and watching the ratio go to ~30x.
#[test]
fn deleting_six_governed_paths_costs_no_more_than_twice_the_floor() {
    let floor = arm("cost-zero", 0);
    let two = arm("cost-two", 2);
    let six = arm("cost-six", 6);

    // THE ANTI-VACUITY TERM. If the corpus ever stops being big enough for one
    // scan to be measurable, the ratios below would pass over nothing at all —
    // so this shouts rather than going quietly green.
    assert!(
        floor >= MEASURABLE,
        "the fixture corpus no longer makes this term measurable ({floor:?} < \
         {MEASURABLE:?}), so the ratio assertions below would pass over nothing: \
         restore CORPUS_FILES x CORPUS_LINES"
    );

    let table = format!("0 deletions {floor:?}, 2 deletions {two:?}, 6 deletions {six:?}");

    // THE LINEARITY TERM, and it is the one that names the defect. Going from two
    // deletions to six adds four more paths; going from zero to two pays the
    // one-off index build plus two. If the ledger is scanned per path then the
    // four-path step is roughly twice the two-path one and this fails; if the
    // index is built once then the four-path step is nearly free.
    //
    // Measured on this fixture: unflattened, 0.39s / 27.5s / 81.3s — the step is
    // 53.8s against 27.1s, so it fails by 2x. Flattened, 0.36s / 0.85s / 0.91s —
    // the step is 0.06s against 0.49s, so it passes by 8x. An order of magnitude
    // either side of the line.
    let first_step = two.saturating_sub(floor);
    let second_step = six.saturating_sub(two);
    assert!(
        second_step <= first_step,
        "the ledger scan is linear in the deleted-path count again — {table}; four \
         more deletions cost {second_step:?} where the first two cost {first_step:?}, \
         so `arms_for` is scanning `input.tree.lines` per path instead of looking \
         its answer up in `arm_rows`"
    );

    // AND AN ABSOLUTE BOUND, because a linearity test alone would pass over a term
    // that grew quadratically and then flattened, or over one whose constant had
    // exploded. `RATIO` is deliberately loose: the flattened six-deletion arm sits
    // at ~2.5x this floor because the guard on `arm_pairs` made the FLOOR cheaper
    // (0.39s -> 0.36s) rather than because the six-deletion arm got worse, and the
    // unflattened arm was 210x. Nothing between 3x and 210x is a shape this
    // module can produce.
    assert!(
        six <= floor * RATIO,
        "six deletions cost more than {RATIO}x the zero-deletion floor — {table}"
    );
}
