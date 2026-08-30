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
// changed: "a non-executable file beside the artifacts is left alone" crates/batten/tests/target_prune.rs the scope is a KIND rather than the executable bit (CLOUD-1157). The bit was never the property worth pinning — it made `.rlib`, `.rmeta` and `.so` unreachable however many copies accumulated, while reading as a safety check — so the case is `a_file_of_a_kind_this_pass_does_not_reclaim_is_left_alone` and asserts the same thing about `.d` and about anything unrecognised, with three copies of one `.d` stem so it cannot pass by never reaching `keep`.
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

use common::{Fixture, batten, run_with_stdin, stderr, stdout};

/// The floors every case is judged against, and they are the shape the committed
/// `[prune]` table has rather than round numbers: a fixture whose config is a
/// different SHAPE from the real one tests a loader nobody runs.
const WARM_MB: u64 = 6000;
const COLD_MB: u64 = 14000;

/// The regrowable roots every case declares, and they are the shape the committed
/// table has for the same reason the floors are: one basis-moving, one not, and
/// one prefix. A fixture declaring only `incremental` could not tell a basis that
/// moves from a basis that was never asked to.
const REGROWABLE: &str = "[[prune.regrowable]]\nname = \"incremental\"\ncold = true\n\n\
                          [[prune.regrowable]]\nname = \"semver-checks\"\ncold = false\n\n\
                          [[prune.regrowable]]\nname = \"flycheck*\"\ncold = false\n";

/// The basis every fixture floor declares (CLOUD-1158).
///
/// `count = 0` over a glob no fixture writes a file for, so the ordinary case is a
/// tree that MATCHES its basis and the drift cases declare their own. A fixture
/// whose basis is stale by construction would make every other case in this file
/// depend on a number it does not care about.
const BASIS: &str = "glob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n";

fn config() -> String {
    format!(
        "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
         [prune.warm]\nmb = {WARM_MB}\nworst_mb = {WARM_MB}\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
         [prune.cold]\nmb = {COLD_MB}\nworst_mb = {COLD_MB}\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
         [prune.warm.basis]\n{BASIS}\n[prune.cold.basis]\n{BASIS}\n\
         {REGROWABLE}"
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
    kinded(deps, stem, hash, "", age_seconds);
}

/// The same, of a named kind — `rlib`, `rmeta`, `so`, or `""` for the
/// extension-less executable.
///
/// NOT EXECUTABLE FOR AN EXTENSIONED KIND, and that is deliberate rather than
/// incidental: cargo does not set the bit on a `.rlib`, so a fixture that did
/// would prove the pass reaches a file no build ever writes (CLOUD-1157).
fn kinded(deps: &Path, stem: &str, hash: &str, kind: &str, age_seconds: u64) {
    sized(deps, stem, hash, kind, age_seconds, 16 * 1024);
}

/// The same, of a chosen size.
///
/// The size is a parameter for exactly one case — the reclaim's own megabytes
/// have to appear in what a lap is recorded as consuming (CLOUD-861), and the
/// report counts whole megabytes, so a 16 KB artifact cannot express it.
fn sized(deps: &Path, stem: &str, hash: &str, kind: &str, age_seconds: u64, bytes: usize) {
    std::fs::create_dir_all(deps).unwrap();
    let suffix = if kind.is_empty() {
        String::new()
    } else {
        format!(".{kind}")
    };
    let path = deps.join(format!("{stem}-{hash}{suffix}"));
    std::fs::write(&path, vec![0_u8; bytes]).unwrap();
    #[cfg(unix)]
    if kind.is_empty() {
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

/// A BUILT tree: a `deps` directory that is not empty.
///
/// EMPTY IS NOT BUILT, and every fixture that created the directory and stopped
/// was declaring a tree whose next build writes everything — which `basis_of`
/// reads as `Basis::Cold`, while every assertion in those cases is about a warm
/// one. Seven of them went red the moment the basis stopped being read from the
/// escalation alone, which is the sensor discriminating rather than the fixtures
/// being wrong before.
///
/// NO HASH SUFFIX ON THE RESIDENT FILE, deliberately: it is not a name any pass
/// groups and not a file `survivors` counts, so a case's retention arithmetic is
/// untouched by the tree being warm.
fn built(repo: &Path) -> PathBuf {
    let deps = repo.join("target/debug/deps");
    std::fs::create_dir_all(&deps).unwrap();
    std::fs::write(deps.join("resident.rlib"), vec![0_u8; 1024]).unwrap();
    deps
}

/// The executable artifacts left under `deps`.
fn survivors(deps: &Path) -> usize {
    std::fs::read_dir(deps).map_or(0, |entries| {
        entries
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry.file_name().to_string_lossy().contains('-')
                    && entry.metadata().is_ok_and(|meta| meta.is_file())
            })
            .count()
    })
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
    built(&repo);

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
fn a_tree_emptied_by_something_other_than_the_escalation_is_still_a_cold_one() {
    // FOUND ON THIS BRANCH'S OWN LANDING LAP, and it poisoned the ratchet rather
    // than merely mis-reporting. The basis was read from the escalation alone —
    // `Cold` iff THIS run dropped a basis-moving root — so a human deleting
    // `target/debug` by hand to satisfy the floor was invisible: the lap that
    // followed built 110 test binaries from nothing, and the journal recorded that
    // 21226MB COLD lap as the worst WARM one on record. Every warm lap after it is
    // then admitted against a full rebuild's demand, which is the floor nothing can
    // satisfy that CLOUD-861's own §8 names as the failure getting a gate switched
    // off.
    let repo = repo("target-prune-emptied-by-hand");
    built(&repo);
    let warm = said(&prune(&repo, "20000", &["-y"]));
    assert!(warm.contains("warm floor"), "a built tree is warm: {warm}");

    // Nothing this run did, and that is the whole case: the artifacts are simply
    // gone, so the next build writes all of them.
    std::fs::remove_dir_all(repo.join("target/debug/deps")).unwrap();
    let output = prune(&repo, "20000", &["-y"]);
    let cold = said(&output);
    assert!(
        output.status.success(),
        "20000MB clears both floors: {cold}"
    );
    assert!(
        cold.contains("cold floor"),
        "the basis is a property of the TREE rather than of this invocation: {cold}"
    );
    assert!(
        !cold.contains("escalated"),
        "and no escalation ran, so the escalation's flag cannot be what said so: {cold}"
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
    assert!(said.contains("regrowable cache dropped"), "{said}");
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
    assert!(said.contains("regrowable cache dropped"), "{said}");
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

// --- CLOUD-1158: the floor's basis, and where the comparison may run --------

/// A checkout whose floors declare `basis` over `crates/**/*.rs`, at `count`.
///
/// `tolerance = 1`, which is what makes the drift cases and the anti-vacuity
/// cases differ by a number rather than by a mechanism.
fn based(name: &str, count: usize, files: &[(&str, &str)]) -> PathBuf {
    let basis = format!("glob = \"crates/**/*.rs\"\ncount = {count}\ntolerance = 1\n");
    let config = format!(
        "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
         [prune.warm]\nmb = {WARM_MB}\nworst_mb = {WARM_MB}\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
         [prune.cold]\nmb = {COLD_MB}\nworst_mb = {COLD_MB}\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
         [prune.warm.basis]\n{basis}\n[prune.cold.basis]\n{basis}"
    );
    Fixture::new(name)
        .config(&config)
        .file("Cargo.toml", "[workspace]\n")
        .files(files)
        .git()
        .base_commit()
        .build()
}

/// Four tracked files under the basis glob.
const BASIS_FILES: &[(&str, &str)] = &[
    ("crates/batten/tests/one.rs", "// one\n"),
    ("crates/batten/tests/two.rs", "// two\n"),
    ("crates/batten/tests/three.rs", "// three\n"),
    ("crates/batten/src/lib.rs", "// lib\n"),
];

#[test]
fn a_floor_whose_basis_has_moved_is_refused_naming_both_counts() {
    // THE DEFECT, as an assertion. `measured` is a POINTER to a basis nobody
    // wrote down, so nothing could tell whether the world under the number had
    // moved — and it moves on a schedule this repository sets for itself:
    // CLOUD-843's retirement owes a `crates/batten/tests/*.rs` per retired gate,
    // with 147 shell suites still standing.
    let repo = based("target-prune-basis-moved", 1, BASIS_FILES);
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(
        !output.status.success(),
        "the floor declares a basis of 1 file and the tree tracks 4: {said}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a verdict about the tree: {said}"
    );
    assert!(
        said.contains("declared 1, live 4"),
        "both counts travel: {said}"
    );
    assert!(
        said.contains("2026-08-22"),
        "and the date it was taken: {said}"
    );
    assert!(
        !said.contains("one.rs"),
        "POINTER-ONLY: the count is the finding and the paths are unbounded: {said}"
    );
}

#[test]
fn a_tree_at_its_declared_basis_loads_clean() {
    // ANTI-VACUITY, and the first of two: without it the check is "always red",
    // which is a gate nobody keeps.
    let repo = based("target-prune-basis-exact", 4, BASIS_FILES);
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "4 tracked, 4 declared: {said}");
    assert!(!said.contains("no longer exists"), "{said}");
}

#[test]
fn a_tree_inside_the_tolerance_loads_clean() {
    // The second, and it is what makes `tolerance` a real key rather than a
    // decoration: a gate that reds on the first added test file is one somebody
    // switches off, and the thing being watched is a trend.
    let repo = based("target-prune-basis-tolerated", 3, BASIS_FILES);
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(
        output.status.success(),
        "4 tracked, 3 declared, 1 allowed: {said}"
    );
    assert!(!said.contains("no longer exists"), "{said}");
}

#[test]
fn a_floor_declaring_no_basis_is_refused_at_load() {
    // On `measured`'s own ground (CLOUD-266): an absent basis reads exactly like a
    // satisfied one. An empty glob is the expressible form of absent — a missing
    // key is serde's refusal, and this is the engine's.
    let repo = Fixture::new("target-prune-basis-absent")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"\"\ncount = 0\ntolerance = 0\n\n\
             [prune.cold.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("[prune.warm.basis]"), "{said}");
}

#[test]
fn an_undeclared_basis_is_refused_on_the_verify_surface() {
    // THE SAME REFUSAL, ONE SURFACE LATER, and where it lives is the finding.
    //
    // `basis` was a required field, so a floor without one failed to PARSE. That
    // makes the key's own PR unlandable: `config-lint` loads
    // `origin/main:batten.toml` with the WORKING TREE's binary — house style §8's
    // out-of-band load, so a branch cannot lower the bar it is judged by — and the
    // base ref has no such key, so the load fails with `missing field` and the gate
    // reports could-not-look instead of a verdict. Measured on this row's own
    // landing lap, with the whole of the rest of the gate green.
    //
    // So the type takes `Option` and the refusal moves to the surface CLOUD-1158 §2
    // already puts the live comparison on. What must NOT change is that an absent
    // basis is refused at all — that is `measured`'s own ground — and this case is
    // what holds it.
    let repo = Fixture::new("target-prune-basis-undeclared")
        .config(&format!(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = {WARM_MB}\nworst_mb = {WARM_MB}\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = {COLD_MB}\nworst_mb = {COLD_MB}\nmultiplier = 1\nmeasured = \"2026-08-29\"\n"
        ))
        .file("Cargo.toml", "[workspace]\n")
        .files(BASIS_FILES)
        .git()
        .base_commit()
        .build();
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(
        !output.status.success(),
        "a date points at nothing without a basis: {said}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "a verdict about the tree rather than a usage error, because the config \
         loaded: {said}"
    );
    assert!(
        said.contains("[prune.warm] declares no basis"),
        "the refusal names the floor: {said}"
    );
    assert!(
        said.contains("2026-08-22"),
        "and the date that points at nothing: {said}"
    );
}

#[test]
fn a_checkout_with_no_index_is_not_refused_for_a_basis_nobody_could_count() {
    // COULD-NOT-LOOK ALLOWS, which is `git.rs`'s own stated posture for
    // `tracked_paths`: a tree that cannot be enumerated is never refused on the
    // strength of a count nobody took. The fixture is the drift case MINUS the
    // git repository, so the only difference is whether the count is available.
    let repo = Fixture::new("target-prune-basis-no-index")
        .config(&format!(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = {WARM_MB}\nworst_mb = {WARM_MB}\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = {COLD_MB}\nworst_mb = {COLD_MB}\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"crates/**/*.rs\"\ncount = 1\ntolerance = 1\n\n\
             [prune.cold.basis]\nglob = \"crates/**/*.rs\"\ncount = 1\ntolerance = 1\n"
        ))
        .file("Cargo.toml", "[workspace]\n")
        .files(BASIS_FILES)
        .build();
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(!said.contains("no longer exists"), "{said}");
}

#[test]
fn the_mediated_call_does_not_judge_the_basis() {
    // THE PLACEMENT CASE, and it is red against this row's own first draft, which
    // put the comparison in `Floor::validate`. `config.rs` calls that on the
    // shared config-load path, which EVERY `batten` invocation runs — `batten
    // hook` on every mediated tool call included — so a tracked-path enumeration
    // there is a tree read taxed onto the `PreToolUse` budget. The repository has
    // ruled on this exact shape once already: `claim-race-check` was moved off the
    // mediated call for it.
    //
    // The fixture's basis has moved (1 declared, 4 tracked), so a comparison at
    // load would refuse — and `batten target prune` over the same tree does refuse,
    // which is what makes this a placement assertion rather than a vacuous one.
    let repo = based("target-prune-basis-mediated", 1, BASIS_FILES);
    built(&repo);
    assert!(
        !prune(&repo, "99999", &["-y"]).status.success(),
        "the verify surface does refuse this tree, so the hook's silence below is \
         about WHERE the comparison runs rather than about whether it can fire"
    );

    let envelope = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\",\
                    \"tool_input\":{\"command\":\"echo hello\"}}";
    let output = run_with_stdin(&repo, &["hook", "--harness", "claude-code"], envelope);
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0), "the engine decided: {said}");
    assert!(
        !said.contains("\"permissionDecision\":\"deny\""),
        "a benign call is allowed over a tree whose basis has moved: {said}"
    );
    assert!(
        !said.contains("no longer exists"),
        "and the mediated call says nothing about the basis at all: {said}"
    );
}

// --- CLOUD-861: the floor is an invariant, and its basis ratchets ------------

/// A checkout that can keep a lap history: the `[prune]` fixture plus a `.git`.
///
/// The journal lives under `$GIT_DIR`, so a fixture without one decides on the
/// declared floors alone — which is what every other case in this file does, and
/// is asserted rather than assumed by
/// `a_checkout_with_no_lap_history_decides_on_the_declaration_alone`.
fn lapped(name: &str) -> PathBuf {
    Fixture::new(name)
        .config(&config())
        .file("Cargo.toml", "[workspace]\n")
        .git()
        .base_commit()
        .build()
}

/// The lap journal's raw bytes, or empty where none was written.
fn journal(repo: &Path) -> String {
    std::fs::read_to_string(repo.join(".git/batten-prune/laps.json")).unwrap_or_default()
}

#[test]
fn the_closing_reading_refuses_a_lap_that_spent_its_own_headroom() {
    // THE DEFECT, as an assertion, and it is red before this row because there is
    // no second reading to compare — the floor was read once, at the head of
    // `verify`, and answered "is there room to begin".
    //
    // Measured three times in one session: the prune passed at 6242MB free, the
    // `cargo test` link step inside the same lap took all of it, and the
    // exhaustion arrived as a rustc IO error under a `land` line telling the
    // author to fix their own diff.
    let repo = lapped("target-prune-lap-breach");
    built(&repo);

    let opened = said(&prune(&repo, "9000", &["-y"]));
    assert!(opened.contains("lap-open"), "{opened}");

    let output = prune(&repo, "2000", &["-y"]);
    let said = said(&output);
    assert!(
        !output.status.success(),
        "the lap was admitted at 9000MB and ended at 2000MB, below the 6000MB \
         floor it was admitted under: {said}"
    );
    assert!(said.contains("CLOSING reading"), "{said}");
    assert!(
        said.contains("consumed 7000MB"),
        "and the closing run names what the lap actually cost, which is the \
         quantity the floor is about and which nothing had ever printed: {said}"
    );
}

#[test]
fn a_closing_escalation_does_not_make_the_lap_it_closes_a_cold_one() {
    // FOUND ON THIS ROW'S OWN FIRST LIVE LAP, and it is the spiral the basis-of-
    // record rule exists against. A closing run whose reclaim escalates has moved
    // the basis for the NEXT build; it cannot retroactively make the lap being
    // closed a cold one. Judging it against the cold floor its own closing
    // reclaim just created is what made every full lap fail at its own close:
    // measured here at 9790MB free against a 14914MB cold floor.
    let repo = lapped("target-prune-close-basis-of-record");
    built(&repo);
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();
    // A NON-BASIS ROOT BESIDE IT, so the close has something it may still take and
    // the case can tell "escalated on what it is allowed to" apart from "did not
    // escalate at all".
    let regrowable = cache(&repo, "semver-checks", 200_000);

    // A warm lap opens above the floor.
    assert!(prune(&repo, "20000", &["-y"]).status.success());

    // The close is below the warm floor, so it escalates — and 8000MB clears the
    // 6000MB warm floor while not clearing the 14000MB cold one, so the two
    // readings of "which basis" give opposite verdicts.
    let output = prune(&repo, "5000,8000", &["-y"]);
    let closed = said(&output);
    assert!(closed.contains("regrowable cache dropped"), "{closed}");
    assert!(!regrowable.exists(), "the non-basis root goes: {closed}");
    assert!(
        output.status.success(),
        "the lap ran warm, so it is judged against the warm floor it was \
         admitted under: {closed}"
    );
    assert!(closed.contains("warm floor"), "{closed}");
    // AND THE BASIS-MOVING ROOT IS STILL THERE, because the cheap tier already
    // cleared the floor and the expensive one is only reached if it did not.
    // Measured twice on this row's own landing lap: the escalation took every root
    // at once, freed 5711MB, and thereby raised the floor the NEXT lap had to clear
    // from 6242MB to 14914MB on a tree a full lap leaves at ~8.7GB — so every
    // second `land` lap was refused for a full rebuild nothing had asked for. The
    // escalation created the demand that refused it.
    assert!(
        incremental.exists(),
        "the cheap tier cleared the floor, so the expensive one is never reached: {closed}"
    );
    assert!(
        closed.contains("none of those roots is the cargo build's basis"),
        "and it says so, rather than reporting a move it did not make: {closed}"
    );

    // And the next lap is admitted WARM, which is the whole point — 8000MB clears
    // the 6000MB warm floor and would not clear the cold one.
    let next = said(&prune(&repo, "8000", &["-y"]));
    assert!(
        next.contains("warm floor"),
        "the escalation left the basis alone, so the next lap is still a warm one: {next}"
    );
}

#[test]
fn the_ratchet_raises_the_floor_and_the_refusal_names_the_lap_that_set_it() {
    // The second half of the row: `worst_mb` was hand-declared at `x1`, so the
    // floor was exactly the worst lap somebody wrote down and a measurement taken
    // once read exactly like a fresh one forever.
    let repo = lapped("target-prune-ratchet");
    built(&repo);

    assert!(prune(&repo, "20000", &["-y"]).status.success());

    // 20000 -> 12000 is an 8000MB lap, worse than the 6000MB declaration, and it
    // is NOT refused: it is judged against the floor it was admitted under, which
    // is the ordering that keeps a machine's first lap from refusing itself for
    // the crime of being the thing that measured it.
    let observed = prune(&repo, "12000", &["-y"]);
    let raised = said(&observed);
    assert!(observed.status.success(), "{raised}");
    assert!(
        raised.contains("the observed warm floor rises to 8000MB from the next lap"),
        "{raised}"
    );

    // And from the next lap it binds: 7000MB clears the 6000MB declaration and
    // not the 8000MB observation.
    let refused = prune(&repo, "7000", &["-y"]);
    let denied = said(&refused);
    assert!(!refused.status.success(), "{denied}");
    assert!(denied.contains("floor 8000MB"), "{denied}");
    assert!(
        denied.contains("rather than declared"),
        "the refusal says the number is an observation and names the lap: {denied}"
    );
}

#[test]
fn the_ratchet_never_rises_above_what_the_lap_that_set_it_left_free() {
    // THE FLOOR MEANS "leave room for another lap like the last one", so clearing
    // it needs `free_at_open >= floor + spent` — twice a lap's cost. On a volume
    // that cannot hold two laps the observation sets a number the very measurement
    // it came from has already shown unreachable, and every later lap is refused
    // at its own close however much is reclaimed first. That is the "gate somebody
    // switches off" failure the anti-vacuity case below exists against, arriving
    // from the other side.
    //
    // Measured on a ~38GB container, ~11GB of it toolchains: a full gated lap
    // consumed 18541MB and closed at 7887MB, the ratchet stood at 20228MB, and
    // eight consecutive laps built cleanly and were refused. Emptying `target/`
    // and the cargo registry moved the close reading not at all — the build spends
    // what it is given.
    let repo = lapped("target-prune-ratchet-capped");
    built(&repo);

    // A lap that spends MORE than it leaves: 20000 -> 7000 is 13000MB spent
    // against 7000MB left. Uncapped it sets a 13000MB floor.
    assert!(prune(&repo, "20000", &["-y"]).status.success());
    let observed = said(&prune(&repo, "7000", &["-y"]));
    assert!(observed.contains("consumed 13000MB"), "{observed}");
    assert!(
        observed.contains("floor rises to 7000MB"),
        "the SPEND and the FLOOR are two different facts once the cap bites — the \
         lap really did cost 13000MB, and 7000MB is what it showed this volume \
         leaves over: {observed}"
    );

    // And the next lap of the same shape closes cleanly, which is the whole point.
    // Uncapped this is refused against 13000MB, and so is every lap after it.
    assert!(prune(&repo, "20000", &["-y"]).status.success());
    let output = prune(&repo, "7000", &["-y"]);
    let closed = said(&output);
    assert!(
        output.status.success(),
        "a volume that cannot hold two laps must still be able to run one: {closed}"
    );
}

#[test]
fn a_lap_that_stays_above_the_floor_is_not_refused_and_does_not_ratchet() {
    // ANTI-VACUITY, and without it the row degenerates to "refuse more", which is
    // a gate somebody switches off. A 1000MB lap is under the declaration, so
    // nothing is observed and the floor does not move.
    let repo = lapped("target-prune-quiet-lap");
    built(&repo);

    assert!(prune(&repo, "20000", &["-y"]).status.success());
    let output = prune(&repo, "19000", &["-y"]);
    let quiet = said(&output);
    assert!(output.status.success(), "{quiet}");
    assert!(quiet.contains("consumed 1000MB"), "{quiet}");
    assert!(
        !quiet.contains("rises to"),
        "1000MB is under the 6000MB declaration, which is a lower bound, so the \
         floor in force does not move and nothing announces that it did: {quiet}"
    );
    // The behavioural half, and it is the one worth having: the NEXT lap is still
    // admitted under the declared number. Asserting the journal's bytes would
    // pin the storage instead — and the journal legitimately records the
    // observation, because the worst lap seen is the history's answer whatever
    // the seed says.
    let next = said(&prune(&repo, "18000", &["-y"]));
    assert!(next.contains("warm floor 6000MB"), "{next}");
    assert!(!next.contains("rather than declared"), "{next}");
    assert!(!journal(&repo).is_empty(), "a lap history was kept");
}

#[test]
fn a_first_lap_below_the_declaration_is_refused_on_the_declaration_alone() {
    // The other anti-vacuity twin: with no lap open there is nothing to close and
    // no observation to appeal to, so the seed decides — which is the behaviour
    // every run had before the journal existed.
    let repo = lapped("target-prune-seed-alone");
    built(&repo);

    let output = prune(&repo, "1000", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("there is not room to begin"), "{said}");
    assert!(
        !said.contains("rather than declared"),
        "no lap has been observed, so the floor is the declared one: {said}"
    );
}

#[test]
fn a_warm_laps_consumption_does_not_raise_the_cold_floor() {
    // PER BASIS, and folding them together is the failure this pins: a warm lap's
    // consumption is a statement about an incremental build, and a cold floor
    // raised by one would refuse a lap for a demand nobody measured.
    let repo = lapped("target-prune-basis-not-shared");
    built(&repo);
    let incremental = repo.join("target/debug/incremental/batten-1a2b3c");
    std::fs::create_dir_all(&incremental).unwrap();
    std::fs::write(incremental.join("dep-graph.bin"), vec![0_u8; 200_000]).unwrap();

    // THE NUMBERS DISCRIMINATE, and that took a second pass: a warm observation
    // UNDER the cold declaration cannot tell a shared ratchet from a per-basis
    // one, because `max(14000, 8000)` is 14000 either way. Measured as a
    // surviving mutation. So the warm lap here observes 20000MB — above the
    // 14000MB cold declaration — and the cold reading below sits between the two.
    //
    // THE LAP LEAVES WHAT IT SPENT, deliberately, because the observation is
    // capped by the free space its own lap left over: a 40000 -> 18000 lap spends
    // 22000MB and would once have observed all of it, but caps to 18000MB, and
    // 18000 against an 18000MB reading is exactly the tie a leaked warm floor
    // would pass on. Spending 20000 and leaving 20000 puts the observation clear
    // of the cold declaration with a margin the cold lap below can fall inside.
    assert!(prune(&repo, "40000", &["-y"]).status.success());
    let warm = said(&prune(&repo, "20000", &["-y"]));
    assert!(
        warm.contains("the observed warm floor rises to 20000MB"),
        "{warm}"
    );

    // Now a lap that escalates: 5000 breaches the warm floor and the declared
    // `incremental` root is dropped, so the basis moves to cold — for the NEXT
    // lap, which is where that consequence belongs.
    assert!(prune(&repo, "5000,30000", &["-y"]).status.success());

    // THAT next lap is the cold one, and it is the reading that discriminates:
    // 18000MB clears the 14000MB cold declaration and would NOT clear a cold
    // floor raised to 22000MB by the warm lap above.
    let output = prune(&repo, "18000", &["-y"]);
    let cold = said(&output);
    assert!(output.status.success(), "{cold}");
    assert!(
        cold.contains("cold floor 14000MB"),
        "the cold floor is its own declaration, untouched by a warm observation: {cold}"
    );
    assert!(
        !cold.contains("rather than declared"),
        "no COLD lap has been observed: {cold}"
    );
}

#[test]
fn a_checkout_with_no_lap_history_decides_on_the_declaration_alone() {
    // The journal lives under `$GIT_DIR`, so a checkout without one has nowhere
    // to keep a history. Asserted rather than assumed, because it is what every
    // other case in this file silently relies on — and because "no history" must
    // be a state rather than a failure.
    let repo = repo("target-prune-no-history");
    built(&repo);

    let first = said(&prune(&repo, "20000", &["-y"]));
    let second = said(&prune(&repo, "19000", &["-y"]));
    assert!(first.contains("lap-open"), "{first}");
    assert!(
        second.contains("lap-open"),
        "nothing was recorded, so the second run opens rather than closes: {second}"
    );
    assert!(second.contains("0 superseded"), "{second}");
    assert!(journal(&repo).is_empty(), "and no journal was written");
}

#[test]
fn what_the_reclaim_freed_counts_toward_what_the_lap_consumed() {
    // THE ARITHMETIC, pinned rather than left to a difference of two readings:
    // `start - end + reclaimed_in_between`. Space this run handed back is space
    // the lap had spent, so a lap that reclaimed megabytes and ended level did not
    // consume nothing — which is exactly what subtracting two readings would say.
    let repo = lapped("target-prune-reclaim-counts");
    let deps = repo.join("target/debug/deps");
    sized(&deps, "cli", "aaaaaaaaaaaa", "", 3600, 1_100_000);
    sized(&deps, "cli", "bbbbbbbbbbbb", "", 1800, 1_100_000);

    assert!(prune(&repo, "20000", &["-y"]).status.success());
    // A third copy appears during the lap, so the closing run has exactly one
    // artifact to reclaim — and the reading does not move.
    sized(&deps, "cli", "cccccccccccc", "", 60, 1_100_000);

    let said = said(&prune(&repo, "20000", &["-y"]));
    assert!(said.contains("1MB reclaimed"), "{said}");
    assert!(
        said.contains("consumed 1MB"),
        "the free-space readings are level, so the whole of this lap's cost is \
         what the reclaim handed back: {said}"
    );
}

// --- CLOUD-1157: the escalation's roots are declared, and so is their cost ----

/// A regrowable root with something in it, at `target/<name>`.
fn cache(repo: &Path, name: &str, bytes: usize) -> PathBuf {
    let dir = repo.join("target").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("blob"), vec![0_u8; bytes]).unwrap();
    dir
}

#[test]
fn a_declared_root_that_is_not_the_cargo_basis_is_dropped_without_moving_the_floor() {
    // CLOUD-1157's second half, and the case that makes `cold` a per-row answer
    // rather than a constant. `semver-checks` held 2.6 GB on a real container and
    // was outside the walk entirely; dropping it makes only ITS next run cold, so
    // a lap judged against the 14000MB cold floor here would be refused for a full
    // rebuild that is not going to happen.
    //
    // Two readings: 5000MB before the escalation and 9000MB after it. 9000 clears
    // the warm floor and does NOT clear the cold one, so the two answers are
    // distinguishable by the exit code alone.
    let repo = repo("target-prune-warm-basis-root");
    built(&repo);
    let dropped = cache(&repo, "semver-checks", 200_000);

    let output = prune(&repo, "5000,9000", &["-y"]);
    let said = said(&output);
    assert!(!dropped.exists(), "the declared root is dropped: {said}");
    assert!(
        output.status.success(),
        "and the lap is judged against the WARM floor, because the next cargo \
         build is still incremental: {said}"
    );
    assert!(
        said.contains("none of those roots is the cargo build's basis"),
        "the report says why the floor did not move: {said}"
    );
    assert!(!said.contains("COLD"), "{said}");
}

#[test]
fn a_declared_basis_moving_root_still_moves_the_floor() {
    // The discriminating twin of the case above, on the same fixture shape and the
    // same readings: only the row's `cold` differs, and the verdict inverts. Under
    // a rule that ignored the flag both would pass, and under one that treated
    // every root as basis-moving both would refuse.
    let repo = repo("target-prune-cold-basis-root");
    let dropped = cache(&repo, "debug/incremental/batten-1a2b3c", 200_000);

    let output = prune(&repo, "5000,9000", &["-y"]);
    let said = said(&output);
    assert!(!dropped.exists(), "{said}");
    assert!(
        !output.status.success(),
        "9000MB does not fit a cold build, and `incremental` is declared as the \
         one whose loss makes the next build cold: {said}"
    );
    assert!(said.contains("COLD"), "{said}");
}

#[test]
fn a_prefix_row_reaches_every_numbered_instance() {
    // `flycheck*`, and the reason the key carries a wildcard at all:
    // rust-analyzer numbers a directory per instance, so an enumeration goes stale
    // the first time a second instance runs. Two instances, and a third directory
    // sharing the prefix's first letters but not the prefix.
    let repo = repo("target-prune-prefix-root");
    let zero = cache(&repo, "flycheck0", 200_000);
    let one = cache(&repo, "flycheck1", 200_000);
    let unrelated = cache(&repo, "fly", 200_000);

    let said = said(&prune(&repo, "1,99999", &["-y"]));
    assert!(!zero.exists(), "{said}");
    assert!(!one.exists(), "a prefix row is not one directory: {said}");
    assert!(
        unrelated.exists(),
        "and it is a PREFIX, not a substring — `fly` is not `flycheck*`: {said}"
    );
}

#[test]
fn a_declared_root_above_the_floor_keeps_its_bytes() {
    // ANTI-VACUITY, and the one that keeps this from being `cargo clean` on a
    // timer: every one of these roots regrows, so dropping them unconditionally
    // trades a rare stall for a permanent tax. The escalation is conditional, and
    // widening WHAT it may drop must not widen WHEN.
    let repo = repo("target-prune-roots-above-floor");
    let semver = cache(&repo, "semver-checks", 200_000);
    let flycheck = cache(&repo, "flycheck0", 200_000);
    let incremental = cache(&repo, "debug/incremental/batten-1a2b3c", 200_000);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(
        semver.exists() && flycheck.exists() && incremental.exists(),
        "{said}"
    );
    assert!(!said.contains("escalated"), "{said}");
}

#[test]
fn a_regrowable_root_that_is_not_a_name_is_refused_at_load() {
    // The engine tier for `Regrowable::validate`: a unit test pins that the
    // function returns an error when called, and says nothing about whether the
    // loader calls it. `remove_dir_all` is what runs at the far end of this key,
    // so a declaration meaning something wider than its author thinks must be
    // refused before anything is spent — `name = "*"` is `cargo clean` spelled as
    // a prefix.
    let repo = Fixture::new("target-prune-bad-root")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n\n\
             [prune.cold.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n\n\
             [[prune.regrowable]]\nname = \"*\"\ncold = false\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();
    built(&repo);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("[prune.regrowable]"), "{said}");
    assert!(
        repo.join("target/debug/deps").exists(),
        "a refusal at LOAD removes nothing: {said}"
    );
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
fn a_file_of_a_kind_this_pass_does_not_reclaim_is_left_alone() {
    // CHANGED under CLOUD-1157, and the change is the point of that row. This case
    // used to be `a_non_executable_file_beside_the_artifacts_is_left_alone` and
    // pinned the EXECUTABLE BIT as the scope — which is what made `.rlib`,
    // `.rmeta` and `.so` unreachable while reading as a safety check. The bit now
    // gates only the extension-less class, where it is the sole signal that a name
    // is an artifact rather than somebody's scratch.
    //
    // What is still left alone is a KIND the pass does not reclaim: `.d` (2.8 MB
    // across 666 files, measured — below the noise) and anything unrecognised.
    let repo = repo("target-prune-unreclaimed-kinds");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);
    // Three `.d` files under ONE stem, so the case cannot pass by the group
    // never reaching `keep` — it passes only because the kind is out of scope.
    std::fs::write(deps.join("cli-aaaaaaaaaaaa.d"), "dep\n").unwrap();
    std::fs::write(deps.join("cli-bbbbbbbbbbbb.d"), "dep\n").unwrap();
    std::fs::write(deps.join("cli-cccccccccccc.d"), "dep\n").unwrap();
    std::fs::write(deps.join("cli-aaaaaaaaaaaa.rcgu.o"), "obj\n").unwrap();
    std::fs::write(deps.join("notes-aaaaaaaaaaaa.txt"), "scratch\n").unwrap();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(deps.join("cli-aaaaaaaaaaaa.d").exists(), "{said}");
    assert!(
        deps.join("cli-bbbbbbbbbbbb.d").exists(),
        "the oldest of three `.d` copies is not superseded either — the class is \
         out of scope, not merely under `keep`: {said}"
    );
    assert!(deps.join("cli-aaaaaaaaaaaa.rcgu.o").exists(), "{said}");
    assert!(deps.join("notes-aaaaaaaaaaaa.txt").exists(), "{said}");
}

#[cfg(unix)]
#[test]
fn an_extensioned_stem_past_keep_loses_its_oldest_copy() {
    // RED BEFORE CLOUD-1157, and red for a structural reason rather than a tuning
    // one: `libbatten-42061777d57a0311.rlib` split on its last `-` gave a "hash"
    // of `42061777d57a0311.rlib`, the `.` failed the hex test, and the whole
    // filename became its own stem. Every extensioned artifact was a group of one,
    // and nothing in a group of one is ever past `keep`.
    let repo = repo("target-prune-extensioned");
    let deps = repo.join("target/debug/deps");
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rlib", 3600);
    kinded(&deps, "libbatten", "bbbbbbbbbbbb", "rlib", 1800);
    kinded(&deps, "libbatten", "cccccccccccc", "rlib", 60);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(
        !deps.join("libbatten-aaaaaaaaaaaa.rlib").exists(),
        "keep = 2, so the oldest of three goes: {said}"
    );
    assert!(deps.join("libbatten-bbbbbbbbbbbb.rlib").exists(), "{said}");
    assert!(
        deps.join("libbatten-cccccccccccc.rlib").exists(),
        "the newest is what the next build reads: {said}"
    );
    assert!(
        said.contains("1 superseded artifact(s) removed"),
        "exactly one, not the whole group: {said}"
    );
}

#[cfg(unix)]
#[test]
fn a_stem_carrying_two_kinds_retains_keep_of_each() {
    // THE DATA-LOSS CASE, and it is red against the first draft of CLOUD-1157
    // rather than against the code this repairs. A key of the stem ALONE puts
    // `libbatten`'s 2 `.rlib` and 6 `.rmeta` in one group of eight, where
    // `keep = 2` can retain two `.rmeta` and delete the LIVE `.rlib` — the
    // `keep = 0` failure `Prune::validate` already refuses, arriving through the
    // grouping instead of through the count.
    //
    // The mtimes are the shape that makes it bite: every `.rmeta` is newer than
    // every `.rlib`, which is what `check` and `clippy` produce on a lap that
    // rebuilt no binary.
    let repo = repo("target-prune-two-kinds");
    let deps = repo.join("target/debug/deps");
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rlib", 7200);
    kinded(&deps, "libbatten", "bbbbbbbbbbbb", "rlib", 6000);
    for (index, hash) in [
        "cccccccccccc",
        "dddddddddddd",
        "eeeeeeeeeeee",
        "ffffffffffff",
        "111111111111",
        "222222222222",
    ]
    .into_iter()
    .enumerate()
    {
        kinded(
            &deps,
            "libbatten",
            hash,
            "rmeta",
            3000 - (index as u64 * 300),
        );
    }

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(
        deps.join("libbatten-bbbbbbbbbbbb.rlib").exists(),
        "THE LIVE ARTIFACT SURVIVES — this is the assertion the whole key shape \
         exists for: {said}"
    );
    assert!(
        deps.join("libbatten-aaaaaaaaaaaa.rlib").exists(),
        "and so does its spare: two copies of a kind is `keep`, not a surplus: {said}"
    );
    let rmeta = |hash: &str| deps.join(format!("libbatten-{hash}.rmeta")).exists();
    assert!(rmeta("222222222222") && rmeta("111111111111"), "{said}");
    assert!(
        !rmeta("cccccccccccc") && !rmeta("dddddddddddd"),
        "the four oldest `.rmeta` are superseded: {said}"
    );
    assert!(
        said.contains("4 superseded artifact(s) removed"),
        "four `.rmeta` and no `.rlib`: {said}"
    );
}

#[cfg(unix)]
#[test]
fn a_stem_with_a_single_extensioned_copy_is_untouched() {
    // The anti-vacuity twin for the widening, and without it "reclaim the
    // extensioned kinds too" degenerates into a `cargo clean` that costs a full
    // rebuild every lap. One `.rlib`, one `.rmeta`, one `.so`, each alone.
    let repo = repo("target-prune-single-copies");
    let deps = repo.join("target/debug/deps");
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rlib", 3600);
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rmeta", 3600);
    kinded(&deps, "libserde_derive", "bbbbbbbbbbbb", "so", 3600);

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(deps.join("libbatten-aaaaaaaaaaaa.rlib").exists(), "{said}");
    assert!(deps.join("libbatten-aaaaaaaaaaaa.rmeta").exists(), "{said}");
    assert!(
        deps.join("libserde_derive-bbbbbbbbbbbb.so").exists(),
        "{said}"
    );
    assert!(said.contains("0 superseded artifact(s) removed"), "{said}");
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
    built(&repo);

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
    built(&repo);

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
    built(&repo);

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
    built(&repo);

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
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n\n\
             [prune.cold.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n",
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
             [prune.cold]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n\n\
             [prune.cold.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n",
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
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n\n\
             [prune.warm.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n\n\
             [prune.cold.basis]\nglob = \"src/*.rs\"\ncount = 0\ntolerance = 0\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, "99999", &["-y"]);
    let said = said(&output);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("not a YYYY-MM-DD date"), "{said}");
}
