//! The disk-floor reclaim's contract, over the compiled engine (CLOUD-1030).
//!
//! # Why this tier
//!
//! `crates/batten/src/prune.rs` unit-tests the pure parts — stem grouping, the
//! floor arithmetic, the date shape — and that is the right home for them: they
//! are functions of their arguments and keeping them exercisable without a build
//! is what makes them separable at all.
//!
//! What those cases cannot establish is the half `.claude/rules/policy-modules.md`
//! names for its own surface and which applies verbatim here: that the ENGINE
//! builds the input the predicate reads. The floors reach the decision through
//! `batten.toml`'s `[prune]` table, the config loader, `resolve`, and a `-y`
//! binding on a `CommandDecl` — four seams a `Prune { .. }` literal in a unit
//! test fabricates rather than exercises. A table that parses and never reaches
//! the comparison is byte-identical, on the decision surface, to a floor that
//! passed.
//!
//! Every case declares its own free space through `TARGET_PRUNE_FREE_MB`. That
//! is CLOUD-778's seam and it is not optional here: without it a case asserting a
//! successful run is answering "how full is this runner's disk", which is how
//! nine cases went red in CI at a single floor change. Declaring it in every case
//! also keeps this suite off `df`, so it decides the same way on every platform.
//!
//! # The retirement ledger
//!
//! `mise-tasks/target-prune.sh` and `tests/target-prune.bats` are retired here
//! under CLOUD-1059. The rows below are what `shell-retirement`'s arm C reads.
//!
//! WHY IT WAS MIGRATED AT ALL, and this one is the campaign working on its author
//! a third time — after `semver` and `perf-pair`, and less creditably than
//! either. CLOUD-1030 is a repair to the FLOOR, and making it meant editing an
//! authored shell rule, which `V-SHELL-RULE-EDITED` refuses with no override
//! route. The row was backlogged instead, on a two-part blocker whose decisive
//! half — "the effect cannot move into a read-only engine" — was asserted without
//! being checked and is false: `capture prune` has been `Effect::Destructive` in
//! this engine for months, `perf-pair.sh` (which spawns two cargo builds and
//! materialises a worktree) was ported in the same session, and this program's
//! entire effect is two removals. House-style §5's read-only promise is about the
//! MEDIATED CALL; `Surface::VerifyOnly` is the surface that exists precisely for
//! an effectful verb the hook can never reach.
//
// The file granularity: each deleted path, and the two successors that hold what
// it held.
//
// changed: mise-tasks/target-prune.sh crates/batten/src/prune.rs crates/batten/tests/target_prune.rs
// changed: tests/target-prune.bats crates/batten/src/prune.rs crates/batten/tests/target_prune.rs
//
// The retention rule. Seven cases, and every one of them is a property of the
// reclaim rather than of the program that ran it, so they port straight across
// into the module's own tier where they need no fixture tree at all.
//
// carried: "the newest K copies survive and the rest are removed" crates/batten/tests/target_prune.rs
// carried: "THE SPARE IS KEPT, so a reverted lap is not a full rebuild" crates/batten/tests/target_prune.rs
// carried: "a stem with fewer than K copies is untouched" crates/batten/tests/target_prune.rs
// carried: "stems are grouped separately — one binary's copies never count as another's" crates/batten/src/prune.rs
// carried: "NOTHING OUTSIDE deps IS CONSIDERED — a cache is not a superseded artifact" crates/batten/tests/target_prune.rs
// carried: "a cross-target deps directory is pruned too, on the same rule" crates/batten/tests/target_prune.rs
// carried: "a non-executable file beside the artifacts is left alone" crates/batten/tests/target_prune.rs
//
// The output contract.
//
// carried: "the report is a count and bytes, never a path listing" crates/batten/tests/target_prune.rs
// changed: "the report names the floor beside the free space, so both numbers travel" crates/batten/tests/target_prune.rs the report now names the floor's BASIS beside it, because there are two floors and a number alone cannot say which one is in force or why. A `carried` arm would claim the assertion is unchanged when it is strictly stronger.
//
// The argument surface. All three were assertions about a hand-rolled `while`
// loop over `$@`, and clap owns that now: an unknown flag, a missing value and
// the arity that made `shift 2` hang are `clap::Command`'s to refuse, pinned for
// every verb at once by `surface`'s own `clap_accepts_the_built_tree`. That is
// `subsumed` rather than `carried` — the property holds and nothing is checking a
// shell parser any more, because there is no shell parser.
//
// subsumed: "--root with no value is refused, and does not hang" crates/batten/src/surface.rs
// subsumed: "an unknown flag is a usage error" crates/batten/src/surface.rs
// changed: "an absent build directory is exit 2, never a silent pass" crates/batten/tests/target_prune.rs could-not-look is exit 3 rather than exit 2 under the engine's contract, which reserves 2 for a violation with no per-verb exception (house-style §6-§7). The predecessor was a standalone program with its own two-code table; what must NOT change is that it is non-zero and names what was not examined, and that is what the ported case asserts.
//
// The budget's self-check. Five cases, and all five were a program parsing its
// own source with a regex to prove a comment matched a variable. The floors are
// `[prune.warm]` and `[prune.cold]` now and `Prune::validate` decides the same
// arithmetic AT CONFIG LOAD, which is what that self-parse was reaching for one
// tier earlier. `subsumed` for the three that were about the parse itself,
// `carried` for the two that are about the arithmetic and still are.
//
// subsumed: "a floor with no budget comment is refused — a limit with no measurement" crates/batten/src/prune.rs
// subsumed: "a budget comment with no measurement date is refused" crates/batten/src/prune.rs
// subsumed: "an unreadable budget file is exit 2, never a silent pass" crates/batten/src/prune.rs
// carried: "a floor matching its declared basis passes" crates/batten/src/prune.rs
// carried: "a floor disagreeing with its declared basis is refused, and both numbers are named" crates/batten/src/prune.rs
//
// The order, and the refusal it protects.
//
// changed: "THE ORDER IS LOAD-BEARING: a prunable tree is never refused for being over budget" crates/batten/tests/target_prune.rs the predecessor asserted the order by comparing two LINE NUMBERS in its own source, which is the only instrument a shell suite had, and this arm claimed the port ran the thing instead. It does not, and #734's review is what caught the overclaim: the free-space seam is DECLARED, so a reading cannot rise because the reclaim freed something, and no fixture can put the judgement on the far side of a reclaim that moved it. What the ported case does assert is the weaker half that is still worth having — a tree full of superseded copies reclaims them and comes back exit 0 rather than being refused. The order itself is asserted where it IS expressible: `escalating_judges_against_the_cold_floor_it_just_created` only reaches a second reading because the reclaim ran first.
// carried: "a tree still below the floor after pruning is refused" crates/batten/tests/target_prune.rs
// carried: "the refusal explains how exhaustion would otherwise present" crates/batten/tests/target_prune.rs
//
// CLOUD-861's escalation, and the two rows CLOUD-1030 is about. The first two
// carry: the escalation still runs only when the floor is breached, and a tree
// above it still keeps its cache. The third is retired outright.
//
// carried: "CLOUD-861: a tree below the floor escalates and drops the incremental cache" crates/batten/tests/target_prune.rs
// carried: "CLOUD-861: a tree ABOVE the floor keeps its incremental cache" crates/batten/tests/target_prune.rs
// withdrawn: "CLOUD-861: the floor's basis names a lap no observed lap exceeds" it grepped the task's own source for `worst-lap=6242mb`, pinning ONE literal against ONE stale predecessor. The floors are config now and `Floor::validate` decides the arithmetic for whatever they say, so the case has no source line to read and the property it guarded is checked at load for every value rather than for one.
//
// CLOUD-778's hermeticity row. The seam widened — a comma-separated SEQUENCE
// rather than one number — because CLOUD-1030's discriminating case needs the
// second reading to differ from the first, and a single value makes the two equal
// by construction.
//
// changed: "CLOUD-778: the prune verdict is identical above and below the floor" crates/batten/tests/target_prune.rs the seam is now the readings a run takes IN ORDER, with the last repeating, so every single-valued caller means what it meant and the escalation's second reading becomes expressible.
//
// The fresh-clone path.
//
// carried: "an unbuilt tree beside a Cargo.toml prunes nothing and still judges the floor" crates/batten/tests/target_prune.rs
// carried: "an unbuilt tree below the floor still refuses, so the fresh-clone path is not an escape" crates/batten/tests/target_prune.rs
// changed: "no target and no Cargo.toml is still could-not-look" crates/batten/tests/target_prune.rs exit 3 rather than exit 2, for the reason the absent-build-directory row above states: the engine's contract reserves 2 for a violation and this is not one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, batten, stderr, stdout};

/// The floors every case is judged against, and they are the shape the committed
/// `[prune]` table has rather than round numbers: a fixture whose config is a
/// different SHAPE from the real one tests a loader nobody runs.
const WARM_MB: u64 = 6000;
const COLD_MB: u64 = 14000;

fn config() -> String {
    format!(
        "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
         [prune.warm]\nmb = {WARM_MB}\nworst_mb = {WARM_MB}\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
         [prune.cold]\nmb = {COLD_MB}\nworst_mb = {COLD_MB}\nmultiplier = 1\nmeasured = \"2026-08-29\"\n"
    )
}

/// A checkout carrying the `[prune]` table and a workspace manifest beside it.
fn repo(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config())
        .file("Cargo.toml", "[workspace]\n")
        .build()
}

/// An executable artifact with cargo's hash suffix, at a controlled mtime.
///
/// The mtime is what orders the copies, so it is explicit rather than incidental
/// — three files written in a loop can share a timestamp at this resolution, and
/// a retention rule reading an arbitrary order is not a retention rule.
fn artifact(deps: &Path, stem: &str, hash: &str, age_seconds: u64) {
    std::fs::create_dir_all(deps).unwrap();
    let path = deps.join(format!("{stem}-{hash}"));
    std::fs::write(&path, vec![0_u8; 16 * 1024]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut mode = std::fs::metadata(&path).unwrap().permissions();
        mode.set_mode(0o755);
        std::fs::set_permissions(&path, mode).unwrap();
    }
    // `File::set_modified` rather than a dev-dependency on `filetime`: the
    // std call has been stable since well before this crate's MSRV, and a new
    // dependency to move one timestamp is a dependency the whole workspace then
    // carries.
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_seconds);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// Run `target prune` in `dir` with the readings `free` declares.
fn prune(dir: &Path, free: &str, args: &[&str]) -> std::process::Output {
    batten()
        .arg("target")
        .arg("prune")
        .args(args)
        .env("TARGET_PRUNE_FREE_MB", free)
        .current_dir(dir)
        .output()
        .expect("run batten")
}

/// Everything the run said, on both channels.
fn said(output: &std::process::Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

/// The executable artifacts left under `deps`.
fn survivors(deps: &Path) -> usize {
    std::fs::read_dir(deps)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|entry| {
                    entry.file_name().to_string_lossy().contains('-')
                        && entry.metadata().is_ok_and(|meta| meta.is_file())
                })
                .count()
        })
        .unwrap_or(0)
}

// --- CLOUD-1030: the basis moves with the reclaim ----------------------------

#[test]
fn escalating_judges_against_the_cold_floor_it_just_created() {
    // THE DISCRIMINATING CASE, and it is red against the predecessor rather than
    // against a strawman. Two readings: 5000MB before the escalation, 9000MB
    // after it. The predecessor re-read free space exactly here and compared it
    // against the warm floor, so 9000 >= 6242 passed — on its way into a build
    // whose incremental cache it had just deleted, which is the one build the
    // warm number was never measured over. 9000 is below the cold floor, so the
    // repaired reading refuses.
    let repo = repo("target-prune-basis-moves");
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    let output = prune(&repo, "5000,9000", &["-y"]);
    let said = said(&output);
    assert!(
        !output.status.success(),
        "9000MB clears the warm floor and not the cold one, and the cold one is what the escalation just made apply: {said}"
    );
    assert!(
        said.contains("cold"),
        "the refusal names the basis in force, because a number alone cannot say why it is that number: {said}"
    );
    assert!(
        !repo.join("target/debug/incremental").exists(),
        "the escalation still runs — this case is about what it is judged against, not whether it happens"
    );
}

#[test]
fn a_run_that_never_escalates_is_judged_against_the_warm_floor() {
    // ANTI-VACUITY, and without it the fix above degenerates to "always judge
    // against the cold floor", which would refuse every ordinary lap on this
    // container: the cold floor is more than twice the warm one by measurement.
    // 7000MB clears the warm floor, nothing escalates, and the run passes.
    let repo = repo("target-prune-warm-basis");
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();

    let output = prune(&repo, "7000", &["-y"]);
    let said = said(&output);
    assert!(
        output.status.success(),
        "7000MB clears the warm floor: {said}"
    );
    assert!(
        said.contains("warm floor"),
        "the passing report names its basis too, or the basis is only ever visible on a failure: {said}"
    );
    assert!(
        !said.contains("escalated"),
        "nothing was breached, so nothing escalates: {said}"
    );
}

#[test]
fn the_escalation_says_that_the_basis_moved_and_not_only_that_it_ran() {
    // CLOUD-1030 §5. The predecessor's escalation line reported megabytes
    // dropped, which is what it DID; the thing a reader needs is that the number
    // being judged against changed underneath them.
    let repo = repo("target-prune-escalation-says-why");
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    let said = said(&prune(&repo, "5000,99999", &["-y"]));
    assert!(said.contains("incremental cache dropped"), "{said}");
    assert!(
        said.contains("the cold floor is what now applies"),
        "the line has to name the consequence, not only the act: {said}"
    );
}

// --- CLOUD-861: the escalation is conditional --------------------------------

#[test]
fn a_tree_below_the_floor_escalates_and_drops_the_incremental_cache() {
    // CARRIED. Red before the escalation existed: the run refused with the cache
    // untouched, which is exactly the state a human then cleared by hand, three
    // times in one session.
    let repo = repo("target-prune-escalates");
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c/s-abc");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    let said = said(&prune(&repo, "1,99999", &["-y"]));
    assert!(said.contains("incremental cache dropped"), "{said}");
    assert!(
        !repo.join("target/debug/incremental").exists(),
        "the cache is gone: {said}"
    );
}

#[test]
fn a_tree_above_the_floor_keeps_its_incremental_cache() {
    // CARRIED, and it is the reason the escalation is conditional. Dropping the
    // cache costs a full rebuild, so paying it every lap would trade a rare stall
    // for a permanent tax — a fix that always deleted it would pass the row above
    // and be worse than the defect.
    let repo = repo("target-prune-keeps-cache");
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c/s-abc");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(!said.contains("escalated"), "{said}");
    assert!(repo.join("target/debug/incremental").exists(), "{said}");
}

// --- the retention rule ------------------------------------------------------

#[test]
fn the_newest_k_copies_survive_and_the_rest_are_removed() {
    let repo = repo("target-prune-retention");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    let output = prune(&repo, "99999", &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(survivors(&deps), 2, "keep = 2, so the oldest of three goes");
    assert!(
        !deps.join("cli-aaaaaaaaaaaa").exists(),
        "the oldest is the one that goes"
    );
    assert!(
        deps.join("cli-cccccccccccc").exists(),
        "the newest is what the next build reads"
    );
}

#[test]
fn a_stem_with_fewer_than_keep_copies_is_untouched() {
    // CARRIED, and it had no home in either tier until #734's review said so —
    // the ledger named a file that did not carry it. The retention is a FLOOR as
    // well as a ceiling: a stem below `keep` has nothing superseded, and a rule
    // that took from one anyway would delete what the next build reads.
    //
    // Two stems, one at `keep` and one under it, so the case cannot pass by the
    // reclaim simply doing nothing at all.
    let repo = repo("target-prune-under-keep");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "solo", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "pair", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "pair", "cccccccccccc", 60);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert_eq!(survivors(&deps), 3, "nothing was superseded: {said}");
    assert!(
        said.contains("0 superseded artifact(s) removed"),
        "and the report says so rather than staying silent: {said}"
    );
}

#[test]
fn nothing_outside_deps_is_considered() {
    // CARRIED, and it is the distinction the whole task exists for: `incremental`
    // and the cross-target dirs REGROW, so deleting them costs a rebuild. That is
    // what made the two hand-remedies preceding this task re-consume the space
    // they freed.
    let repo = repo("target-prune-only-deps");
    let target = repo.join("target");
    std::fs::create_dir_all(target.join("debug/incremental")).unwrap();
    std::fs::create_dir_all(target.join("aarch64-apple-darwin/debug")).unwrap();
    std::fs::create_dir_all(target.join("debug/deps")).unwrap();
    std::fs::write(target.join("debug/incremental/blob"), vec![0_u8; 65536]).unwrap();
    std::fs::write(
        target.join("aarch64-apple-darwin/debug/blob"),
        vec![0_u8; 65536],
    )
    .unwrap();
    std::fs::write(target.join("debug/batten"), vec![0_u8; 65536]).unwrap();

    let output = prune(&repo, "99999", &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(target.join("debug/incremental/blob").exists());
    assert!(target.join("aarch64-apple-darwin/debug/blob").exists());
    assert!(
        target.join("debug/batten").exists(),
        "a live artifact addressed by a stable name is not superseded by anything"
    );
}

#[test]
fn a_cross_target_deps_directory_is_pruned_too() {
    let repo = repo("target-prune-cross-target");
    let deps = repo.join("target/aarch64-apple-darwin/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    let output = prune(&repo, "99999", &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(
        survivors(&deps),
        2,
        "the rule is about `deps`, not about `debug/deps`"
    );
}

#[cfg(unix)]
#[test]
fn a_non_executable_file_beside_the_artifacts_is_left_alone() {
    // CARRIED. `.d` depfiles and `.rlib`s are small, and a dangling one only makes
    // cargo rebuild — removing them buys nothing and risks confusing a live build.
    let repo = repo("target-prune-non-executable");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);
    std::fs::write(deps.join("cli-aaaaaaaaaaaa.d"), "dep\n").unwrap();

    let output = prune(&repo, "99999", &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(deps.join("cli-aaaaaaaaaaaa.d").exists());
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_build_tree_is_never_followed() {
    // RAISED ON #734 AND CONFIRMED, and it is a regression the PORT introduced
    // rather than a hole the predecessor had: `find -type d` does not follow a
    // link without `-L`, and `Path::is_dir` does. So a link under the build tree
    // pointing anywhere at all was descended into — its executables considered
    // for removal, and an `incremental` beneath it handed to `remove_dir_all`.
    //
    // The fixture is the shape that makes it reachable: something OUTSIDE the
    // tree, holding both things the reclaim looks for, reached only through a
    // link inside it. Red before the fix, on both halves.
    let repo = repo("target-prune-symlink");
    let outside = repo.join("not-the-build-tree");
    let deps = outside.join("debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);
    let cache = outside.join("debug/incremental/somebody-elses");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    std::fs::create_dir_all(repo.join("target")).unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("target/linked")).unwrap();

    // `1,99999` so the escalation is not merely allowed but REQUIRED to run: a
    // case where nothing escalates would pass without proving anything.
    let said = said(&prune(&repo, "1,99999", &["-y"]));
    assert_eq!(
        survivors(&deps),
        3,
        "nothing across a link is superseded — it is not this tree's to judge: {said}"
    );
    assert!(
        cache.exists(),
        "the escalation must not reach through a link either: {said}"
    );
}

// --- the output contract -----------------------------------------------------

#[test]
fn the_report_is_a_count_and_bytes_never_a_path_listing() {
    // CARRIED. Pointer-only per non-negotiable rule 4: a path list is unbounded,
    // and a caller who wants one can run `du`.
    let repo = repo("target-prune-pointer-only");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "SENTINELSTEM", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "SENTINELSTEM", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "SENTINELSTEM", "cccccccccccc", 60);

    let said = said(&prune(&repo, "99999", &["-y"]));
    assert!(
        !said.contains("SENTINELSTEM"),
        "the removed artifact's own name must not reach the report: {said}"
    );
    assert!(said.contains("superseded artifact(s) removed"), "{said}");
}

#[test]
fn the_report_names_the_floor_and_its_basis_beside_the_free_space() {
    // CHANGED rather than carried, and strictly stronger: there are two floors
    // now, so a number with no basis beside it cannot say which one is in force.
    let repo = repo("target-prune-report-floor");
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();

    let said = said(&prune(&repo, "99999", &["-y"]));
    assert!(said.contains("99999MB free"), "{said}");
    assert!(said.contains(&format!("warm floor {WARM_MB}MB")), "{said}");
}

// --- the floor, and the order it is judged in --------------------------------

#[test]
fn a_prunable_tree_is_never_refused_for_being_over_budget() {
    // A tree above the floor but full of superseded copies is this task's
    // ordinary case, not a stop: checking the floor first would turn every few
    // laps into a refusal for a condition the next four lines fix.
    //
    // WHAT THIS DOES NOT ASSERT, corrected on #734 rather than left implied: the
    // ORDER. The free-space seam is declared, so no reading can rise because the
    // reclaim freed something, and no fixture here can put the judgement on the
    // far side of a reclaim that moved it. The order is asserted where it is
    // expressible — `escalating_judges_against_the_cold_floor_it_just_created`
    // reaches its second reading only because the reclaim ran first.
    let repo = repo("target-prune-order");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    let output = prune(&repo, "99999", &["-y"]);
    assert!(
        output.status.success(),
        "the reclaim runs before the judgement: {}",
        said(&output)
    );
    assert_eq!(survivors(&deps), 2);
}

#[test]
fn a_tree_still_below_the_floor_after_pruning_is_refused() {
    let repo = repo("target-prune-refuses");
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();

    let output = prune(&repo, "1", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("below the measured"), "{said}");
    assert!(said.contains("free 1MB"), "{said}");
    assert!(said.contains("floor"), "{said}");
}

#[test]
fn the_refusal_explains_how_exhaustion_would_otherwise_present() {
    // CARRIED, and it is the whole point of the second half: without this the
    // next thing an author sees is a rustc IO error inside a test run, under a
    // `land` line telling them to fix their own diff.
    let repo = repo("target-prune-refusal-explains");
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();

    let said = said(&prune(&repo, "1", &["-y"]));
    assert!(said.contains("reads as a suite regression"), "{said}");
}

// --- the fresh-clone path ----------------------------------------------------

#[test]
fn an_unbuilt_tree_beside_a_manifest_prunes_nothing_and_still_judges_the_floor() {
    // CARRIED. Measured 2026-08-25: conflating an unbuilt tree with a wrong
    // directory made `verify` unrunnable on a fresh clone for three consecutive
    // `land` laps, on a tree whose only fault was a deleted `target/`.
    let repo = repo("target-prune-unbuilt");

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(said.contains("nothing built"), "{said}");
    assert!(
        said.contains("0 superseded artifact(s) removed"),
        "the floor is still decided, which is the half that must not be lost: {said}"
    );
}

#[test]
fn an_unbuilt_tree_below_the_floor_still_refuses() {
    // The fresh-clone path is not an escape: a clone starting with less space
    // than a lap needs has to be told so before it spends the lap.
    let repo = repo("target-prune-unbuilt-tight");

    let output = prune(&repo, "1", &["-y"]);
    assert!(!output.status.success(), "{}", said(&output));
}

#[test]
fn no_build_directory_and_no_manifest_is_could_not_look() {
    // CHANGED: exit 3 rather than the predecessor's exit 2, because the engine's
    // contract reserves 2 for a violation and this is not one — the cwd is not a
    // workspace root, so nothing was examined, which is not the same as nothing
    // to prune. What must not change is that it is non-zero and says so.
    let repo = Fixture::new("target-prune-elsewhere")
        .config(&config())
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    // THE CODE, not merely non-zero (raised on #734), and it is what makes the
    // ledger's `changed` arm true rather than asserted: an implementation still
    // returning the predecessor's exit 2 passes every other line here.
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert!(said.contains("nothing was examined"), "{said}");
}

#[test]
fn a_named_root_that_is_absent_is_could_not_look_whatever_the_cwd_holds() {
    // The other discriminator, and both are needed: somebody asked about a
    // SPECIFIC tree and it is not there, which is could-not-look even in a
    // workspace whose default root simply has not been built.
    let repo = repo("target-prune-named-absent");

    let output = prune(&repo, "99999", &["-y", "--root", "nowhere"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert!(said.contains("nothing was examined"), "{said}");
}

// --- the surface -------------------------------------------------------------

#[test]
fn the_destructive_verb_refuses_without_yes() {
    // House-style §5's binding, and `capture prune` carries the identical pairing
    // for the identical reason: the primary caller is `verify`, which is
    // non-interactive, and a gate that blocks on a Y/N is a dead gate. So the
    // consent is a FLAG rather than a prompt, and it is required.
    let repo = repo("target-prune-needs-yes");
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();

    let output = prune(&repo, "99999", &[]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("-y"), "the refusal names the flag: {said}");
}

#[test]
fn a_dry_run_removes_nothing_and_says_what_it_would_do() {
    let repo = repo("target-prune-dry-run");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    let output = prune(&repo, "99999", &["-n"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert_eq!(survivors(&deps), 3, "a dry run removes nothing: {said}");
}

#[test]
fn target_is_a_noun_that_performs_no_default_action() {
    // House-style §2, and `surface::is_noun`'s other half. A bare noun lists its
    // sub-verbs rather than doing something — which matters more here than
    // anywhere else on the surface, because the thing it would otherwise do is
    // delete files.
    let repo = repo("target-prune-noun");
    let output = batten()
        .arg("target")
        .current_dir(&repo)
        .output()
        .expect("run batten");
    assert!(
        !output.status.success(),
        "a bare noun is a usage error, not an action"
    );
}

// --- the config seam ---------------------------------------------------------

#[test]
fn a_repository_declaring_no_prune_table_reports_rather_than_refusing() {
    // Not a refusal, because nothing was asked for: a repository with no
    // `[prune]` table has no build tree named and no floor to judge against, and
    // inventing one would be the core holding a number about somebody else's
    // build (non-negotiable rule 1).
    let repo = Fixture::new("target-prune-no-table")
        .config("version = 1\n[[rule]]\nid = \"noop\"\nkind = \"forbid\"\nglob = \"*.nothing\"\npattern = \"x\"\nseverity = \"warn\"\nscope = \"tree\"\n")
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(said.contains("no [prune] table"), "{said}");
}

#[test]
fn a_floor_disagreeing_with_its_declared_basis_is_refused_at_load() {
    // CARRIED, and this is the case that proves the ENGINE reaches the
    // validation rather than that `Prune::validate` returns an error when called
    // — which a unit test already pins and which says nothing about whether
    // anything calls it. The predecessor answered the same question by parsing
    // its own source with a regex at runtime.
    let repo = Fixture::new("target-prune-basis-disagrees")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 5000\nworst_mb = 6242\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(
        said.contains("disagrees with the basis"),
        "and both numbers travel with the refusal: {said}"
    );
}

#[test]
fn a_cold_floor_at_or_below_the_warm_one_is_refused_at_load() {
    // The two-floor design's own vacuity guard. A cold floor that does not exceed
    // the warm one would make the second floor decide nothing — the escalation
    // drops the incremental cache, so a cold lap cannot need less — and it is the
    // shape of a number somebody copied rather than measured.
    let repo = Fixture::new("target-prune-cold-not-above")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("is not above the warm one"), "{said}");
}

#[test]
fn a_floor_carrying_no_measurement_date_is_refused_at_load() {
    // CLOUD-266's class: a stale measurement reads exactly like a fresh one, so
    // the date is required rather than commentary.
    let repo = Fixture::new("target-prune-no-date")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"recently\"\n\n\
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("not a YYYY-MM-DD date"), "{said}");
}
