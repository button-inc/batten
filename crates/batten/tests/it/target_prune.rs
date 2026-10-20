//! `batten target prune`'s contract, over the compiled engine (CLOUD-1030,
//! CLOUD-2198).
//!
//! # One forced collection, and no floor
//!
//! The verb is the disk collector run on demand: superseded units, then least
//! recently used ones, until `[prune] max_free_mb` is free, reporting
//! `disk-collected <freed_mb> <units> <free_after_mb>` and exiting 0. The floor
//! model this suite used to pin — warm and cold floors, a ratchet over a lap
//! journal, a basis count, a tiered escalation — retired with CLOUD-2198; its
//! cases went with the behaviour they tested. What stays is the superseded
//! pass's retention rule, the build-lock guard, and the verb's surface.
//!
//! # Why this tier
//!
//! `crates/batten/src/prune.rs` unit-tests the pure parts — the grouping key and
//! the table — and that is the right home for them. What those cases cannot
//! establish is that the ENGINE builds the input: the band reaches the
//! collection through `batten.toml`'s `[prune]` table, the config loader,
//! `resolve`, and a `-y` binding on a `CommandDecl` — four seams a `Prune { .. }`
//! literal fabricates rather than exercises.
//!
//! Every case declares its own free space through `TARGET_PRUNE_FREE_MB`
//! (CLOUD-778's seam), so the suite decides the same way on every runner.
//!
//!
//! `mise-tasks/target-prune.sh` and `tests/target-prune.bats` are retired here
//! under CLOUD-1059. The rows below are what `shell retire partial`'s arm C reads.
//!
//! WHY IT WAS MIGRATED AT ALL, and this one is the campaign working on its author
//! a third time — after `semver` and `perf-pair`, and less creditably than
//! either. CLOUD-1030 is a repair to the FLOOR, and making it meant editing an
//! authored shell rule, which `shell edit refused` refuses with no override
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
// changed: mise-tasks/target-prune.sh crates/batten/src/prune.rs kind:verb crates/batten/tests/it/target_prune.rs
// changed: tests/target-prune.bats crates/batten/src/prune.rs kind:verb crates/batten/tests/it/target_prune.rs
//
// The retention rule. Seven cases, and every one of them is a property of the
// reclaim rather than of the program that ran it, so they port straight across
// into the module's own tier where they need no fixture tree at all.
//
// carried: "the newest K copies survive and the rest are removed" crates/batten/tests/it/target_prune.rs
// carried: "THE SPARE IS KEPT, so a reverted lap is not a full rebuild" crates/batten/tests/it/target_prune.rs
// carried: "a stem with fewer than K copies is untouched" crates/batten/tests/it/target_prune.rs
// carried: "stems are grouped separately — one binary's copies never count as another's" crates/batten/src/prune.rs kind:verb
// carried: "NOTHING OUTSIDE deps IS CONSIDERED — a cache is not a superseded artifact" crates/batten/tests/it/target_prune.rs
// carried: "a cross-target deps directory is pruned too, on the same rule" crates/batten/tests/it/target_prune.rs
// changed: "a non-executable file beside the artifacts is left alone" crates/batten/tests/it/target_prune.rs the scope is a KIND rather than the executable bit (CLOUD-1157). The bit was never the property worth pinning — it made `.rlib`, `.rmeta` and `.so` unreachable however many copies accumulated, while reading as a safety check — so the case is `a_file_of_a_kind_this_pass_does_not_reclaim_is_left_alone` and asserts the same thing about `.d` and about anything unrecognised, with three copies of one `.d` stem so it cannot pass by never reaching `keep`.
//
// The output contract.
//
// carried: "the report is a count and bytes, never a path listing" crates/batten/tests/it/target_prune.rs
// changed: "the report names the floor beside the free space, so both numbers travel" crates/batten/tests/it/target_prune.rs the report now names the floor's BASIS beside it, because there are two floors and a number alone cannot say which one is in force or why. A `carried` arm would claim the assertion is unchanged when it is strictly stronger.
//
// The argument surface. All three were assertions about a hand-rolled `while`
// loop over `$@`, and clap owns that now: an unknown flag, a missing value and
// the arity that made `shift 2` hang are `clap::Command`'s to refuse, pinned for
// every verb at once by `surface`'s own `clap_accepts_the_built_tree`. That is
// `subsumed` rather than `carried` — the property holds and nothing is checking a
// shell parser any more, because there is no shell parser.
//
// subsumed: "--root with no value is refused, and does not hang" crates/batten/src/surface.rs kind:mechanism
// subsumed: "an unknown flag is a usage error" crates/batten/src/surface.rs kind:mechanism
// changed: "an absent build directory is exit 2, never a silent pass" crates/batten/tests/it/target_prune.rs could-not-look is exit 3 rather than exit 2 under the engine's contract, which reserves 2 for a violation with no per-verb exception (house-style §6-§7). The predecessor was a standalone program with its own two-code table; what must NOT change is that it is non-zero and names what was not examined, and that is what the ported case asserts.
//
// The budget's self-check. Five cases, and all five were a program parsing its
// own source with a regex to prove a comment matched a variable. The floors are
// `[prune.warm]` and `[prune.cold]` now and `Prune::validate` decides the same
// arithmetic AT CONFIG LOAD, which is what that self-parse was reaching for one
// tier earlier. `subsumed` for the three that were about the parse itself,
// `carried` for the two that are about the arithmetic and still are.
//
// subsumed: "a floor with no budget comment is refused — a limit with no measurement" crates/batten/src/prune.rs kind:verb
// subsumed: "a budget comment with no measurement date is refused" crates/batten/src/prune.rs kind:verb
// subsumed: "an unreadable budget file is exit 2, never a silent pass" crates/batten/src/prune.rs kind:verb
// carried: "a floor matching its declared basis passes" crates/batten/src/prune.rs kind:verb
// carried: "a floor disagreeing with its declared basis is refused, and both numbers are named" crates/batten/src/prune.rs kind:verb
//
// The order, and the refusal it protects.
//
// changed: "THE ORDER IS LOAD-BEARING: a prunable tree is never refused for being over budget" crates/batten/tests/it/target_prune.rs the predecessor asserted the order by comparing two LINE NUMBERS in its own source, which is the only instrument a shell suite had, and this arm claimed the port ran the thing instead. It does not, and #734's review is what caught the overclaim: the free-space seam is DECLARED, so a reading cannot rise because the reclaim freed something, and no fixture can put the judgement on the far side of a reclaim that moved it. What the ported case does assert is the weaker half that is still worth having — a tree full of superseded copies reclaims them and comes back exit 0 rather than being refused. The order itself is asserted where it IS expressible: `escalating_judges_against_the_cold_floor_it_just_created` only reaches a second reading because the reclaim ran first.
// carried: "a tree still below the floor after pruning is refused" crates/batten/tests/it/target_prune.rs
// carried: "the refusal explains how exhaustion would otherwise present" crates/batten/tests/it/target_prune.rs
//
// CLOUD-861's escalation, and the two rows CLOUD-1030 is about. The first two
// carry: the escalation still runs only when the floor is breached, and a tree
// above it still keeps its cache. The third is retired outright.
//
// carried: "CLOUD-861: a tree below the floor escalates and drops the incremental cache" crates/batten/tests/it/target_prune.rs
// carried: "CLOUD-861: a tree ABOVE the floor keeps its incremental cache" crates/batten/tests/it/target_prune.rs
// withdrawn: "CLOUD-861: the floor's basis names a lap no observed lap exceeds" it grepped the task's own source for `worst-lap=6242mb`, pinning ONE literal against ONE stale predecessor. The floors are config now and `Floor::validate` decides the arithmetic for whatever they say, so the case has no source line to read and the property it guarded is checked at load for every value rather than for one.
//
// CLOUD-778's hermeticity row. The seam widened — a comma-separated SEQUENCE
// rather than one number — because CLOUD-1030's discriminating case needs the
// second reading to differ from the first, and a single value makes the two equal
// by construction.
//
// changed: "CLOUD-778: the prune verdict is identical above and below the floor" crates/batten/tests/it/target_prune.rs the seam is now the readings a run takes IN ORDER, with the last repeating, so every single-valued caller means what it meant and the escalation's second reading becomes expressible.
//
// The fresh-clone path.
//
// carried: "an unbuilt tree beside a Cargo.toml prunes nothing and still judges the floor" crates/batten/tests/it/target_prune.rs
// carried: "an unbuilt tree below the floor still refuses, so the fresh-clone path is not an escape" crates/batten/tests/it/target_prune.rs
// changed: "no target and no Cargo.toml is still could-not-look" crates/batten/tests/it/target_prune.rs exit 3 rather than exit 2, for the reason the absent-build-directory row above states: the engine's contract reserves 2 for a violation and this is not one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, batten, stderr, stdout};

/// The band every case declares: wide enough that a reading of `FREE` asks the
/// collection for more than any fixture holds, so the superseded pass always
/// runs whole and the working set is what stops the live pass.
const MIN_FREE_MB: u64 = 100_000;
const MAX_FREE_MB: u64 = 200_000;
const FREE: &str = "99999";

fn config() -> String {
    format!(
        "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\nmin_free_mb = {MIN_FREE_MB}\nmax_free_mb = {MAX_FREE_MB}\n"
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
/// NOT EXECUTABLE FOR AN EXTENSIONED KIND, deliberately: cargo does not set the
/// bit on a `.rlib`, so a fixture that did would prove the pass reaches a file
/// no build ever writes (CLOUD-1157).
fn kinded(deps: &Path, stem: &str, hash: &str, kind: &str, age_seconds: u64) {
    sized(deps, stem, hash, kind, age_seconds, 16 * 1024);
}

/// The same, of a chosen size.
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

/// The units a run's `disk-collected <freed_mb> <units> <free_after_mb>` line
/// counts, or `None` where it printed none.
fn collected_units(said: &str) -> Option<usize> {
    said.lines()
        .find_map(|line| line.split_once("disk-collected ").map(|(_, fields)| fields))
        .and_then(|fields| fields.split_whitespace().nth(1))
        .and_then(|units| units.parse().ok())
}

/// A BUILT tree: a `deps` directory that is not empty.
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

// --- one forced collection, no floor (CLOUD-2198) ----------------------------

/// A live unit: an artifact and a fingerprint file whose last use is
/// `age_seconds` ago, `bytes` large.
fn live(profile: &Path, name: &str, hash: &str, age_seconds: u64, bytes: usize) {
    sized(&profile.join("deps"), name, hash, "", age_seconds, bytes);
    let fingerprint = profile.join(".fingerprint").join(format!("{name}-{hash}"));
    std::fs::create_dir_all(&fingerprint).unwrap();
    let file = fingerprint.join(format!("bin-{name}"));
    std::fs::write(&file, b"fingerprint").unwrap();
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_seconds);
    common::set_times(
        &file,
        std::fs::FileTimes::new()
            .set_accessed(when)
            .set_modified(when),
    );
}

/// THE COMMITTED `build` ROOT IS DECLARED BASIS-MOVING (CLOUD-2192). Losing the
/// compiled build scripts makes the next build cold, so the repository's own
/// `[[prune.regrowable]]` row says so; `#MUTANT build-root-declared-warm` turns
/// it warm and this case reads the committed file.
#[test]
fn the_committed_build_root_is_basis_moving() {
    let text = std::fs::read_to_string(common::at_root("batten.toml")).unwrap();
    let config: toml::Value = toml::from_str(&text).unwrap();
    let build = config
        .get("prune")
        .and_then(|prune| prune.get("regrowable"))
        .and_then(toml::Value::as_array)
        .and_then(|roots| {
            roots
                .iter()
                .find(|root| root.get("name").and_then(toml::Value::as_str) == Some("build"))
        })
        .expect("the committed batten.toml declares a `build` regrowable root");
    assert_eq!(
        build.get("cold").and_then(toml::Value::as_bool),
        Some(true),
        "the `build` root is basis-moving: losing it makes the next build cold"
    );
}

/// THE FOLLOWED BUILD IS A KEEP ROOT TOO, AND IT IS A DIFFERENT FILE
/// (CLOUD-2376).
///
/// The hook reaches the engine by two routes. The load-fault hand-off asks
/// `engine::checkout_build`, which reads no environment —
/// `prune_watch::the_checkout_build_is_never_collected` covers that one. The
/// follow asks `engine::own_build`, which honours `CARGO_TARGET_DIR`, because
/// for that caller the redirect is true. Sparing only the conventional path
/// left the pruner free to reclaim the very binary the follow was about to
/// exec, whenever the redirect lands inside the tree being walked.
///
/// The redirect is set on the CHILD rather than this process, because the
/// workspace forbids `unsafe` and `set_var` is unsafe — and because the verb is
/// what reads it in production. Nothing is written at `target/release`, so a
/// keep list carrying only `checkout_build` spares a file that is not there and
/// collects the one that is.
#[test]
fn the_followed_build_is_never_collected() {
    let dir = Fixture::new("prune-followed-build")
        .config(&config().replace("root = \"target\"", "root = \"redirected\""))
        .file("Cargo.toml", "[workspace]\n")
        .build();
    let profile = dir.join("redirected/release");
    live(&profile, "batten", "efefefefefefefef", 3 * 3600, 4 * 1024);
    std::fs::hard_link(
        profile.join("deps/batten-efefefefefefefef"),
        profile.join("batten"),
    )
    .unwrap();
    assert!(
        !dir.join("target/release/batten").exists(),
        "the only build is the redirected one"
    );

    let output = batten()
        .arg("target")
        .arg("prune")
        .env("TARGET_PRUNE_FREE_MB", FREE)
        .env("CARGO_TARGET_DIR", "redirected")
        .current_dir(&dir)
        .output()
        .expect("run batten");

    assert!(
        profile.join("deps/batten-efefefefefefefef").exists(),
        "the build the follow execs is never collected: {}",
        said(&output)
    );
}

/// THE VERB IS ONE COLLECTION, and the spec's own case. Two live units of known
/// size, free space one MiB short of `max_free_mb`: the older unit goes, the
/// line is `disk-collected …`, and the exit is 0 — no floor, no basis, no
/// escalation field. `#MUTANT prune-verb-skips-collect` returns before
/// collecting, and the older unit survives.
#[test]
fn target_prune_collects_to_max_free_without_a_floor() {
    let repo = repo("target-prune-collects");
    let profile = repo.join("target/debug");
    live(&profile, "stale", "aaaaaaaaaaaaaaaa", 7200, 2 << 20);
    live(&profile, "fresh", "bbbbbbbbbbbbbbbb", 7000, 1 << 20);

    let free = (MAX_FREE_MB - 1).to_string();
    let output = prune(&repo, &free, &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(
        !profile.join("deps/stale-aaaaaaaaaaaaaaaa").exists(),
        "the least recently used unit goes: {said}"
    );
    assert!(
        profile.join("deps/fresh-bbbbbbbbbbbbbbbb").exists(),
        "one MiB was asked for and the first unit freed two: {said}"
    );
    assert_eq!(collected_units(&said), Some(1), "{said}");
    for retired in ["floor", "basis", "escalat"] {
        assert!(!said.contains(retired), "no `{retired}` field: {said}");
    }
}

/// THE BAND IS IN MEBIBYTES AND THE NEED IN BYTES: one MiB short of
/// `max_free_mb` takes the two oldest of three 600 KiB units, since one frees
/// too little, and leaves the third.
#[test]
fn a_mebibyte_short_takes_units_until_a_mebibyte_is_freed() {
    let repo = repo("target-prune-mebibyte");
    let profile = repo.join("target/debug");
    live(&profile, "oldest", "aaaaaaaaaaaaaaaa", 7200, 600 << 10);
    live(&profile, "middle", "bbbbbbbbbbbbbbbb", 7100, 600 << 10);
    live(&profile, "newest", "cccccccccccccccc", 7000, 600 << 10);

    let free = (MAX_FREE_MB - 1).to_string();
    let output = prune(&repo, &free, &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(
        !profile.join("deps/oldest-aaaaaaaaaaaaaaaa").exists(),
        "{said}"
    );
    assert!(
        !profile.join("deps/middle-bbbbbbbbbbbbbbbb").exists(),
        "600 KiB is short of the MiB asked for: {said}"
    );
    assert!(
        profile.join("deps/newest-cccccccccccccccc").exists(),
        "two units free the MiB: {said}"
    );
}

/// A `[prune]` declaring no band collects at the default one (CLOUD-2197): with
/// it held, the collector a branch carried never armed and that branch's own
/// `verify` filled the disk. The retired floor tables still load beside it,
/// read and ignored, while the pin moves (CLOUD-2198's commit A).
#[test]
fn an_undeclared_band_collects_at_the_default() {
    let repo = Fixture::new("target-prune-unbanded")
        .config(
            "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n\n\
             [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
             [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n",
        )
        .file("Cargo.toml", "[workspace]\n")
        .build();
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    let output = prune(&repo, "1", &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(!said.contains("no min_free_mb/max_free_mb"), "{said}");
    assert!(
        survivors(&deps) < 3,
        "1 MB free is under the default 4096 MB floor, so the superseded copy goes: {said}"
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

    let output = prune(&repo, FREE, &["-y"]);
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

/// An executable artifact AND the fingerprint document cargo leaves beside it,
/// carrying the unit-identity fields `superseded_in` keys on (CLOUD-1975).
///
/// `path` and `profile` are the two a case varies; the rest are the constant
/// shape a real document has, so a case differing in one field is a case about
/// that field. `local` embeds the hash, as cargo's does — the field every
/// generation of one unit changes.
fn unit(deps: &Path, stem: &str, hash: &str, age_seconds: u64, path: u64, profile: u64) {
    artifact(deps, stem, hash, age_seconds);
    let dir = deps
        .parent()
        .unwrap()
        .join(".fingerprint")
        .join(format!("{stem}-{hash}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("dep-test-integration-test-{stem}")), b"").unwrap();
    std::fs::write(
        dir.join(format!("test-integration-test-{stem}.json")),
        format!(
            r#"{{"rustc":1,"features":"[]","declared_features":"[]","target":7,"profile":{profile},"path":{path},"deps":[],"local":[{{"CheckDepInfo":{{"dep_info":"debug/.fingerprint/{stem}-{hash}/dep-test-integration-test-{stem}","checksum":false}}}}],"rustflags":[],"config":3,"compile_kind":0}}"#
        ),
    )
    .unwrap();
}

/// CLOUD-1975. Three versions of one crate share a stem and nothing else — the
/// shape `Cargo.lock` has for `hashbrown` — and all three are live. Grouped by
/// stem under `keep = 2`, the oldest was evicted every lap and rebuilt the next.
#[test]
fn three_versions_of_one_crate_all_survive() {
    let repo = repo("target-prune-versions");
    let deps = repo.join("target/debug/deps");
    unit(&deps, "cli", "aaaaaaaaaaaa", 3600, 101, 5);
    unit(&deps, "cli", "bbbbbbbbbbbb", 1800, 102, 5);
    unit(&deps, "cli", "cccccccccccc", 60, 103, 5);

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(
        survivors(&deps),
        3,
        "three versions are three units, not three generations of one"
    );
}

/// CLOUD-1975. One crate under two profiles — a check unit beside a build unit —
/// is two live units. Three copies across them under `keep = 2`: the two profiles
/// each keep theirs, where stem grouping evicted the oldest outright.
#[test]
fn two_profiles_of_one_crate_both_survive() {
    let repo = repo("target-prune-profiles");
    let deps = repo.join("target/debug/deps");
    unit(&deps, "cli", "aaaaaaaaaaaa", 3600, 101, 5);
    unit(&deps, "cli", "bbbbbbbbbbbb", 1800, 101, 6);
    unit(&deps, "cli", "cccccccccccc", 60, 101, 6);

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(
        deps.join("cli-aaaaaaaaaaaa").exists(),
        "the only unit of its profile is never a rival of another profile's"
    );
    assert_eq!(survivors(&deps), 3);
}

/// CLOUD-1975's anti-vacuity half. Three generations of ONE unit — the same
/// identity, only `local` differing — are still rivals, so `keep = 2` still
/// reclaims the oldest. A key that made every artifact its own group would pass
/// both cases above and reclaim nothing, which is CLOUD-766's full disk.
#[test]
fn generations_of_one_unit_still_supersede() {
    let repo = repo("target-prune-generations");
    let deps = repo.join("target/debug/deps");
    unit(&deps, "cli", "aaaaaaaaaaaa", 3600, 101, 5);
    unit(&deps, "cli", "bbbbbbbbbbbb", 1800, 101, 5);
    unit(&deps, "cli", "cccccccccccc", 60, 101, 5);

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(survivors(&deps), 2, "keep = 2 of one unit's generations");
    assert!(!deps.join("cli-aaaaaaaaaaaa").exists(), "the oldest goes");
}

/// CLOUD-2047. cargo writes an example target's hashed generations to
/// `<profile>/examples`, `.dwo` sets beside them, under the same
/// `.fingerprint/<pkg>-<hash>` as a `deps` unit, and nothing ever reclaimed them:
/// 56 units for 4 benches, 1,082 MB, measured 2026-09-30. The pass over `deps`
/// applies unchanged.
///
/// The control is an `examples` directory that is NOT a profile's: a fixture under
/// `target/` can spell the name, and the reclaim may only reach cargo's own.
#[test]
fn superseded_example_generations_are_reclaimed_like_deps() {
    let repo = repo("target-prune-examples");
    let examples = repo.join("target/debug/examples");
    unit(&examples, "bench", "aaaaaaaaaaaa", 3600, 101, 5);
    unit(&examples, "bench", "bbbbbbbbbbbb", 1800, 101, 5);
    unit(&examples, "bench", "cccccccccccc", 60, 101, 5);
    let orphan = examples.join("bench-dddddddddddd.bench.1a2b3c4d-cgu.0.rcgu.dwo");
    std::fs::write(&orphan, b"debuginfo").unwrap();
    let foreign = repo.join("target/tmp/fixture/examples");
    artifact(&foreign, "bench", "aaaaaaaaaaaa", 3600);
    artifact(&foreign, "bench", "bbbbbbbbbbbb", 1800);
    artifact(&foreign, "bench", "cccccccccccc", 60);

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(
        survivors(&examples),
        2,
        "keep = 2 of the example's generations, and the orphan .dwo is gone"
    );
    assert!(
        !examples.join("bench-aaaaaaaaaaaa").exists(),
        "the oldest generation of an example goes, as a deps unit's would"
    );
    assert!(
        !orphan.exists(),
        "an example .dwo whose unit has no fingerprint goes too"
    );
    assert_eq!(
        survivors(&foreign),
        3,
        "an `examples` directory that is not a profile's is never reclaimed"
    );
}

/// CLOUD-1293. A `.dwo` whose owning unit has no fingerprint is reclaimed; one
/// whose unit is live is not. The live one is the control: the case cannot pass by
/// the pass sweeping `.dwo` wholesale, which would cost every live unit its
/// debuginfo and `file:line` in a backtrace.
//
// The declared mutation, in a plain comment for CLOUD-1913's reason below;
// killed by hand:
// MUTANT orphaned-dwo-kept|s@        if !live.contains(hash) {@        if false {@|a_dwo_whose_unit_has_no_fingerprint_is_reclaimed_and_a_live_ones_is_not
#[test]
fn a_dwo_whose_unit_has_no_fingerprint_is_reclaimed_and_a_live_ones_is_not() {
    let repo = repo("target-prune-dwo");
    let deps = repo.join("target/debug/deps");
    unit(&deps, "cli", "aaaaaaaaaaaa", 60, 101, 5);
    let live = deps.join("cli-aaaaaaaaaaaa.cli.1a2b3c4d-cgu.0.rcgu.dwo");
    let orphan = deps.join("cli-dddddddddddd.cli.1a2b3c4d-cgu.0.rcgu.dwo");
    std::fs::write(&live, b"debuginfo").unwrap();
    std::fs::write(&orphan, b"debuginfo").unwrap();

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(
        !orphan.exists(),
        "a .dwo whose unit has no fingerprint can never be read again and must go"
    );
    assert!(
        live.exists(),
        "a live unit keeps its debuginfo, or a backtrace loses file:line"
    );
    assert!(
        deps.join("cli-aaaaaaaaaaaa").exists(),
        "the live unit itself stays"
    );
}

// CLOUD-1913's declared mutation, in THIS file because `test name undefined`
// cannot see `crates/batten/src/**`. The expression belongs to `prune.rs`'s
// `reclaim_superseded`; inert under the sweep, its kill was demonstrated by hand
// against the case below.
/*
#MUTANT-SUITE crates/batten/tests/it/target_prune.rs
#MUTANT fingerprint-left-behind|s@^                        forget_fingerprint(fingerprints, victim);$@                        let _ = (fingerprints, victim);@|a_reclaimed_copy_takes_its_cargo_fingerprint_with_it
*/

#[test]
fn a_reclaimed_copy_takes_its_cargo_fingerprint_with_it() {
    // CLOUD-1913. A fingerprint naming a deleted artifact tells cargo the crate is
    // fresh, so the next build links against a file that is gone (E0460/E0463).
    // The survivor's fingerprint is the control: the case cannot pass by the
    // reclaim sweeping `.fingerprint` wholesale. Each fingerprint holds a file
    // read just now, so the live pass ranks it in the working set rather than
    // as a unit last used at the epoch.
    let repo = repo("target-prune-fingerprint");
    let deps = repo.join("target/debug/deps");
    let fingerprints = repo.join("target/debug/.fingerprint");
    for (hash, age) in [
        ("aaaaaaaaaaaa", 3600),
        ("bbbbbbbbbbbb", 1800),
        ("cccccccccccc", 60),
    ] {
        artifact(&deps, "cli", hash, age);
        let dir = fingerprints.join(format!("cli-{hash}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bin-cli"), b"fingerprint").unwrap();
    }

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(
        !fingerprints.join("cli-aaaaaaaaaaaa").exists(),
        "the reclaimed copy's fingerprint goes with it"
    );
    assert!(
        fingerprints.join("cli-cccccccccccc").exists(),
        "a survivor's fingerprint is untouched"
    );
}

// CLOUD-1913's second declared mutation, here for the same reason: a contended
// build lock read as free is the race that removed `target/clippy` under clippy.
/*
#MUTANT-SUITE crates/batten/tests/it/target_prune.rs
#MUTANT running-build-reclaimed|s@^            Err(std::fs::TryLockError::WouldBlock) => return None,$@            Err(std::fs::TryLockError::WouldBlock) => {}@|a_tree_a_running_build_holds_is_not_reclaimed
*/

#[test]
fn a_tree_a_running_build_holds_is_not_reclaimed() {
    // The lock is held by THIS process and the prune runs in another, which is
    // the shape of the race. The verb waits on a held TREE's lock, so the hold
    // here is the profile's `.cargo-lock`, which the pass skips rather than
    // waits on. Released, the same tree is reclaimed, so the case cannot pass by
    // the pass doing nothing.
    let repo = repo("target-prune-running-build");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);
    let lock = std::fs::File::create(repo.join("target/debug/.cargo-lock")).unwrap();
    lock.lock().unwrap();

    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(survivors(&deps), 3, "a building tree loses nothing");

    drop(lock);
    let output = prune(&repo, FREE, &["-y"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(survivors(&deps), 2, "released, keep = 2 applies again");
}

#[test]
fn a_stem_with_fewer_than_keep_copies_is_untouched() {
    // The retention is a FLOOR as well as a ceiling: a stem below `keep` has
    // nothing superseded, and a rule that took from one anyway would delete what
    // the next build reads. Two stems, one at `keep` and one under it, so the
    // case cannot pass by the reclaim simply doing nothing at all.
    let repo = repo("target-prune-under-keep");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "solo", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "pair", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "pair", "cccccccccccc", 60);

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert_eq!(survivors(&deps), 3, "nothing was superseded: {said}");
    assert_eq!(
        collected_units(&said),
        Some(0),
        "and the report says so rather than staying silent: {said}"
    );
}

#[test]
fn nothing_outside_deps_is_considered() {
    // `incremental` and the cross-target dirs REGROW, so deleting them costs a
    // rebuild. The superseded pass reaches `deps` alone.
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

    let output = prune(&repo, FREE, &["-y"]);
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

    let output = prune(&repo, FREE, &["-y"]);
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
    // What is left alone is a KIND the pass does not reclaim: `.d` (2.8 MB
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

    let output = prune(&repo, FREE, &["-y"]);
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
    // RED BEFORE CLOUD-1157: `libbatten-42061777d57a0311.rlib` split on its last
    // `-` gave a "hash" of `42061777d57a0311.rlib`, the `.` failed the hex test,
    // and every extensioned artifact was a group of one.
    let repo = repo("target-prune-extensioned");
    let deps = repo.join("target/debug/deps");
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rlib", 3600);
    kinded(&deps, "libbatten", "bbbbbbbbbbbb", "rlib", 1800);
    kinded(&deps, "libbatten", "cccccccccccc", "rlib", 60);

    let output = prune(&repo, FREE, &["-y"]);
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
    assert_eq!(
        collected_units(&said),
        Some(1),
        "exactly one, not the whole group: {said}"
    );
}

#[cfg(unix)]
#[test]
fn a_stem_carrying_two_kinds_retains_keep_of_each() {
    // THE DATA-LOSS CASE. A key of the stem ALONE puts `libbatten`'s 2 `.rlib`
    // and 6 `.rmeta` in one group of eight, where `keep = 2` can retain two
    // `.rmeta` and delete the LIVE `.rlib`. Every `.rmeta` is newer than every
    // `.rlib`, which is what `check` and `clippy` produce on a lap that rebuilt
    // no binary.
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

    let output = prune(&repo, FREE, &["-y"]);
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
    assert_eq!(
        collected_units(&said),
        Some(4),
        "four `.rmeta` and no `.rlib`: {said}"
    );
}

#[cfg(unix)]
#[test]
fn a_stem_with_a_single_extensioned_copy_is_untouched() {
    // The anti-vacuity twin for the widening: one `.rlib`, one `.rmeta`, one
    // `.so`, each alone, and none of them goes.
    let repo = repo("target-prune-single-copies");
    let deps = repo.join("target/debug/deps");
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rlib", 3600);
    kinded(&deps, "libbatten", "aaaaaaaaaaaa", "rmeta", 3600);
    kinded(&deps, "libserde_derive", "bbbbbbbbbbbb", "so", 3600);

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(deps.join("libbatten-aaaaaaaaaaaa.rlib").exists(), "{said}");
    assert!(deps.join("libbatten-aaaaaaaaaaaa.rmeta").exists(), "{said}");
    assert!(
        deps.join("libserde_derive-bbbbbbbbbbbb.so").exists(),
        "{said}"
    );
    assert_eq!(collected_units(&said), Some(0), "{said}");
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_build_tree_is_never_followed() {
    // RAISED ON #734: `Path::is_dir` follows a link, so a link under the build
    // tree pointing anywhere at all was descended into. The fixture is something
    // OUTSIDE the tree, holding what the reclaim looks for, reached only through
    // a link inside it.
    let repo = repo("target-prune-symlink");
    let outside = repo.join("not-the-build-tree");
    let deps = outside.join("debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);

    std::fs::create_dir_all(repo.join("target")).unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("target/linked")).unwrap();

    let said = said(&prune(&repo, FREE, &["-y"]));
    assert_eq!(
        survivors(&deps),
        3,
        "nothing across a link is superseded — it is not this tree's to judge: {said}"
    );
}

// --- the output contract -----------------------------------------------------

#[test]
fn the_report_is_a_count_and_bytes_never_a_path_listing() {
    // Pointer-only per non-negotiable rule 4: a path list is unbounded, and a
    // caller who wants one can run `du`.
    let repo = repo("target-prune-pointer-only");
    let deps = repo.join("target/debug/deps");
    artifact(&deps, "SENTINELSTEM", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "SENTINELSTEM", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "SENTINELSTEM", "cccccccccccc", 60);

    let said = said(&prune(&repo, FREE, &["-y"]));
    assert!(
        !said.contains("SENTINELSTEM"),
        "the removed artifact's own name must not reach the report: {said}"
    );
    assert!(said.contains("disk-collected "), "{said}");
    assert!(
        said.contains("disk-unlink-ms "),
        "the unlink cost is CLOUD-1945's figure: {said}"
    );
}

// --- the fresh-clone path ----------------------------------------------------

#[test]
fn an_unbuilt_tree_beside_a_manifest_collects_nothing_at_exit_zero() {
    // Measured 2026-08-25: conflating an unbuilt tree with a wrong directory
    // made `verify` unrunnable on a fresh clone for three consecutive `land`
    // laps, on a tree whose only fault was a deleted `target/`.
    let repo = repo("target-prune-unbuilt");

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert_eq!(collected_units(&said), Some(0), "{said}");
}

#[test]
fn no_build_directory_and_no_manifest_is_could_not_look() {
    // Exit 3: the cwd is not a workspace root, so nothing was examined, which is
    // not the same as nothing to collect.
    let repo = Fixture::new("target-prune-elsewhere")
        .config(&config())
        .build();

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert!(said.contains("nothing was examined"), "{said}");
}

#[test]
fn a_named_root_that_is_absent_is_could_not_look_whatever_the_cwd_holds() {
    // Somebody asked about a SPECIFIC tree and it is not there, which is
    // could-not-look even in a workspace whose default root is unbuilt.
    let repo = repo("target-prune-named-absent");

    let output = prune(&repo, FREE, &["-y", "--root", "nowhere"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert!(said.contains("nothing was examined"), "{said}");
}

// --- the surface -------------------------------------------------------------

#[test]
fn the_destructive_verb_refuses_without_yes() {
    // House-style §5's binding: the primary caller is non-interactive, and a gate
    // that blocks on a Y/N is a dead gate, so the consent is a required FLAG.
    let repo = repo("target-prune-needs-yes");
    built(&repo);

    let output = prune(&repo, FREE, &[]);
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

    let output = prune(&repo, FREE, &["-n"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert_eq!(survivors(&deps), 3, "a dry run removes nothing: {said}");
    assert!(said.contains("would collect"), "{said}");
}

#[test]
fn target_is_a_noun_that_performs_no_default_action() {
    // House-style §2: a bare noun lists its sub-verbs rather than doing
    // something — which matters most here, where the thing is deleting files.
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
    // Not a refusal, because nothing was asked for (non-negotiable rule 1).
    let repo = Fixture::new("target-prune-no-table")
        .config("version = 1\n[[rule]]\nid = \"noop\"\nkind = \"forbid\"\nglob = \"*.nothing\"\npattern = \"x\"\nseverity = \"warn\"\nscope = \"tree\"\n")
        .file("Cargo.toml", "[workspace]\n")
        .build();

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(said.contains("no [prune] table"), "{said}");
}

/// CLOUD-2225. A unit under a profile a running build holds is never collected,
/// and the run says which lock held it rather than reporting nothing to take:
/// measured on #1132, a pass passed over 1,026 such units and its report named
/// no cause. The case holds `target/debug/.cargo-lock` as cargo does.
#[test]
fn a_held_profile_is_reported_by_its_lock() {
    let repo = repo("target-prune-held");
    let profile = repo.join("target/debug");
    live(&profile, "stale", "cccccccccccccccc", 7200, 1 << 20);
    let lock = std::fs::File::create(profile.join(".cargo-lock")).unwrap();
    lock.lock().unwrap();

    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(
        profile.join("deps/stale-cccccccccccccccc").exists(),
        "a held profile is never collected: {said}"
    );
    let named = said.lines().any(|line| {
        line.contains("disk-held ")
            && line
                .trim_end()
                .ends_with(&format!("debug{}.cargo-lock", std::path::MAIN_SEPARATOR))
    });
    assert!(named, "the lock that held it is named: {said}");
    drop(lock);
}

/// `[tasks."target-prune"]`'s run, as the manifest carries it.
fn run_of(task: &str) -> String {
    let block = common::task_block(task).unwrap_or_else(|| panic!("{task} is a declared task"));
    common::task_value(&block, "run")
}

/// The task is the verb, and nothing in it builds: the point of this task is to
/// collect WITHOUT a build, which `cargo run` cannot do. Its lap-boundary twin
/// retired with the lap's reclaim step (CLOUD-2198).
#[test]
fn the_task_is_the_verb_and_builds_nothing() {
    assert_eq!(run_of("target-prune"), "batten target prune -y");
    assert!(
        common::task_block("target-prune:lap").is_none(),
        "the lap-boundary twin is retired"
    );
}

/// A config carrying a key no build knows — the shape a release meets on every
/// branch that adds one.
fn outran(name: &str, prune_key: Option<&str>) -> PathBuf {
    let extra = prune_key
        .map(|key| format!("{key} = 1\n"))
        .unwrap_or_default();
    let config = config()
        .replacen(
            "version = 1\n",
            "version = 1\nkey_this_build_predates = true\n",
            1,
        )
        .replacen("keep = 2\n", &format!("keep = 2\n{extra}"), 1);
    Fixture::new(name)
        .config(&config)
        .file("Cargo.toml", "[workspace]\n")
        .build()
}

/// **A BUILD THE CONFIG HAS OUTRUN STILL COLLECTS** (CLOUD-843, CLOUD-1146).
///
/// `Config` is `deny_unknown_fields`, so a binary older than the tree's config
/// refuses the whole file; the verb reads the one table it needs instead, and
/// says that it did.
#[test]
fn a_build_the_config_outran_reclaims_by_the_prune_table_alone() {
    let repo = outran("target-prune-outran", None);
    built(&repo);
    let output = prune(&repo, FREE, &["-y"]);
    let said = said(&output);
    assert!(output.status.success(), "{said}");
    assert!(
        said.contains("committed [prune] table alone"),
        "the reader is told the whole config was not loaded: {said}"
    );
}

/// **AND THE TABLE STAYS STRICT**: a `[prune]` key this build predates is still a
/// refusal — never a table read with the key silently dropped.
#[test]
fn a_prune_key_this_build_predates_is_still_refused() {
    let repo = outran("target-prune-outran-prune-key", Some("future_key"));
    built(&repo);
    let output = prune(&repo, FREE, &["-y"]);
    assert!(!output.status.success(), "{}", said(&output));
}
