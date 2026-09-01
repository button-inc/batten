//! The paired measurement's contract, over the compiled engine (CLOUD-875).
//!
//! # Why this tier
//!
//! `crates/batten/src/perf.rs` unit-tests the skip predicate directly, which is
//! the right home for it: the predicate is pure, and keeping it exercisable
//! without a build is the whole reason it is separable from the measurement.
//! What those cases cannot establish is the part two FROZEN callers depend on —
//! that the binary actually answers the way `mise-tasks/perf-gate.sh` reads it.
//!
//! That reading is a contract, not a convention, and `perf-gate.sh` states it:
//! it redirects this command to a file and distinguishes a skip from a
//! measurement **by looking for `^arm=`, never by a second exit code**. Its own
//! comment gives the reason — flattening the two "would make a shallow clone
//! indistinguishable from a branch that made the hook slower, which is the
//! difference `verify` needs in order to tell 'fix your change' from 'fix your
//! checkout'." So a skip must exit 0 and print no record, and only a
//! could-not-look may be non-zero. Nothing below the boundary can assert that.
//!
//! # What is deliberately not here
//!
//! The measurement itself needs two release builds and a worktree, so it is not
//! exercised — the predecessor suite made the same call for the same reason.
//! `tests/perf-compare.bats` covers the decision over the records.
//!
//! # The retirement ledger
//!
//! `mise-tasks/perf-pair.sh` and `tests/perf-pair.bats` are retired here under
//! CLOUD-1059. The rows below are what `shell-retirement`'s arm C reads.
//!
//! WHY IT WAS MIGRATED AT ALL, which is the campaign working on its author a
//! second time (after `semver`). CLOUD-875 is a repair to the SKIP, and making it
//! meant editing an authored shell rule, which `V-SHELL-RULE-EDITED` refuses with
//! no override route. It is also a repair a shell skip could not express: the
//! widened set is DERIVED from the loaded config — every path a `policy` row
//! registers — rather than written down, and that is exactly what a `grep -cE`
//! over a literal alternation cannot do.
//
// The file granularity: each deleted path, and the two successors that hold what
// it held.
//
// changed: mise-tasks/perf-pair.sh crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_pair.rs
// changed: tests/perf-pair.bats crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_pair.rs
//
// The case granularity. Six of the eleven were TEXT ASSERTIONS OVER SHELL — they
// grepped the task's own source for a spelling — and a Rust port does not merely
// re-implement them, it makes most of them unrepresentable. That is `subsumed`
// rather than `carried`, and the distinction is the honest one: the property
// still holds, but nothing is checking a string any more because there is no
// string to check.
//
// subsumed: "no arm is measured in the checkout — a stale binary must not read HEAD's config" crates/batten/src/perf.rs kind:verb
// subsumed: "every arm is measured in the pinned fixture repo" crates/batten/src/perf.rs kind:verb
// subsumed: "the wired arms pin their binary per arm, not by resolution order" crates/batten/src/perf.rs kind:verb
// subsumed: "the helper cannot reach an arm's binary except through its parameter" crates/batten/src/perf.rs kind:verb
// subsumed: "each wired arm runs in its OWN tree, which is what replaced the cd" crates/batten/src/perf.rs kind:verb
// subsumed: "failures are not ignored — a broken binary is timeable and must not pass" crates/batten/src/perf.rs kind:verb
//
// The arm census. `perf-assert` still budgets the paths, and the port must still
// pair every one of them — but the assertion moved from counting `^pair ` lines
// in a shell file to the plan the module builds.
//
// carried: "every path perf-assert budgets is paired here" crates/batten/tests/it/perf_pair.rs
//
// The worktree recovery, and this pair is the most interesting entry in the
// ledger. Both cases guarded a MEASURED defect (2026-08-14): `git worktree add`
// leaves an admin entry under the git dir, this gate is killed routinely, and a
// killed run left the entry with its directory gone — after which every later
// `verify` in the clone failed at "could not create a worktree", having measured
// nothing. The predecessor answered with a prune-before-add recovery, and these
// two cases pinned it.
//
// The port does not carry that recovery, because it does not create a worktree:
// `git::materialize_rev` writes the base tree out instead, so there is no admin
// entry to leak and nothing to prune. `subsumed` rather than `carried` is the
// honest arm — the property still holds, and it holds by construction, which is
// why no case replaces them.
//
// subsumed: "a leaked worktree entry cannot wedge the next run: prune precedes add" crates/batten/src/perf.rs kind:verb
// subsumed: "the recovery prunes rather than removing, so a live worktree is untouched" crates/batten/src/perf.rs kind:verb
//
// And the two the ticket is about. `changed`, not `carried`: the predicate is
// deliberately WIDER than the one it replaces, which is the whole of CLOUD-875.
//
// changed: "the skip is keyed to the paths that can change the binary" crates/batten/src/perf.rs kind:verb the key is deliberately wider: crate source and the manifests bound four of the five arms, but `wired` adjudicates against the committed config, so the config and every path a `policy` row registers are consulted too. That is CLOUD-875, and a `carried` arm would claim the predicate is the same one.
// changed: "the skip also sees the wiring, not only the binary" crates/batten/src/perf.rs kind:verb the wiring half is no longer two literal paths but the set `Harness::wiring` already declares, so a repository wired to another host is covered by the same predicate rather than by a second list nobody updated.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{Fixture, run, stdout};

/// A checkout with a committed base and nothing after it, so HEAD IS its merge
/// base — the one skip path reachable without a network or a second commit.
fn repo(name: &str) -> std::path::PathBuf {
    Fixture::new(name)
        .config("[[rule]]\nid = \"noop\"\nkind = \"forbid\"\nglob = \"*.nothing\"\npattern = \"x\"\nseverity = \"warn\"\nscope = \"tree\"\n")
        .git()
        .base_commit()
        .build()
}

#[test]
fn a_skip_exits_zero_and_prints_no_record() {
    // THE CONTRACT `perf-gate.sh` READS, and the reason this tier exists. It
    // greps `^arm=` to tell a skip from a measurement, so a skip that exited
    // non-zero would be reported as "the paired measurement did not complete" and
    // a skip that printed a record would be handed to `perf-compare` as a
    // comparison of nothing.
    let repo = repo("perf-pair-skip");
    let output = run(&repo, &["perf", "pair"]);
    assert!(
        output.status.success(),
        "a skip is a pass: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let said = stdout(&output);
    assert!(
        !said.lines().any(|line| line.starts_with("arm=")),
        "a skip prints no record: {said}"
    );
}

#[test]
fn the_skip_says_why_rather_than_only_that() {
    // CLOUD-875 §5. The predecessor's line claimed "neither the binary nor its
    // wiring changed" having consulted neither the config nor the modules — a
    // sentence wider than its evidence, which is how the next surface added
    // outside the set stays silent instead of visible.
    let repo = repo("perf-pair-skip-names");
    let said = stdout(&run(&repo, &["perf", "pair"]));
    assert!(said.contains("Nothing measured."), "{said}");
}

#[test]
fn the_verb_is_reachable_and_declares_its_flag() {
    // The surface half: a verb nothing can invoke is the same as no verb, and
    // `--null` is what keeps `perf-compare`'s threshold re-measurable rather than
    // a number in a comment.
    let repo = repo("perf-pair-surface");
    let said = stdout(&run(&repo, &["perf", "pair", "--help"]));
    assert!(said.contains("--null"), "{said}");
}

#[test]
fn perf_is_a_noun_that_performs_no_default_action() {
    // House-style §2, and `surface::is_noun`'s other half. A bare noun lists its
    // sub-verbs rather than doing something.
    let repo = repo("perf-noun");
    let output = run(&repo, &["perf"]);
    assert!(
        !output.status.success(),
        "a bare noun is a usage error, not an action"
    );
}

/// Every path `perf-assert` budgets is still paired.
///
/// CARRIED from the retired suite, and the assertion had to move rather than be
/// dropped: it caught a real hole once already (CLOUD-697, where `perf-assert`
/// budgeted four paths and the pair measured three, so `perf-compare` was blind
/// to `wired` — the entry point an agent actually waits on).
///
/// Read as a SET rather than a count, which is stronger than what it replaces:
/// the shell case compared two integers, so a path renamed on one side and added
/// on the other would have balanced out.
#[test]
fn every_path_perf_assert_budgets_is_paired() {
    let budgets = std::fs::read_to_string(common::at_root("mise-tasks/perf-assert.sh"))
        .expect("the budget table is where the gate says it is");
    // READ THE BLOCK, NOT THE LINES, and both edges are the retired case's own
    // measured lesson arriving intact. The first entry shares its line with the
    // assignment (`BUDGETS='noop 100`) and the last carries the closing quote
    // (`wired 100'`), so a line-oriented read silently loses one at each end —
    // which is exactly what happened here on the first run of this port.
    let block = budgets
        .split_once("BUDGETS='")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(block, _)| block)
        .expect("the budget table is a single-quoted block");
    let budgeted: Vec<String> = block
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let budget = fields.next()?;
            (fields.next().is_none()
                && name.chars().all(|c| c.is_ascii_lowercase())
                && budget.chars().all(|c| c.is_ascii_digit()))
            .then(|| name.to_owned())
        })
        .collect();
    assert!(
        !budgeted.is_empty(),
        "the budget table must parse, or this case asserts nothing"
    );

    let module = std::fs::read_to_string(common::at_root("crates/batten/src/perf.rs"))
        .expect("the module is where the ledger says it is");
    for path in budgeted {
        assert!(
            module.contains(&format!("\"{path}\"")),
            "`perf-assert` budgets `{path}` and the pair does not measure it"
        );
    }
}
