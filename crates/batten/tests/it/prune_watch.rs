//! The disk collector and the watcher a long-running batten process hosts
//! (CLOUD-1937, CLOUD-2197), over the library and the binary.
//!
//! Below `[prune] min_free_mb`: superseded units first, then live units least
//! recently used first, until `max_free_mb` is free — never a unit a build holds,
//! never the running engine, and never a unit a live build has used. The watcher spans the
//! whole run it is hosted by; the hook collects before each mediated call.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;
use batten::capture::StreamedChild as _;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use batten::config_model::Prune;

/// A `[prune]` table rooted at `root`, with no band: a case sets its own.
fn rules(root: &str) -> Prune {
    Prune {
        root: root.to_owned(),
        keep: 2,
        warm: None,
        cold: None,
        regrowable: None,
        min_free_mb: None,
        max_free_mb: None,
    }
}

/// One hashed artifact, aged `age` seconds, in the shape cargo lays down.
fn artifact(deps: &Path, stem: &str, hash: &str, age: u64) {
    std::fs::create_dir_all(deps).unwrap();
    let path = deps.join(format!("lib{stem}-{hash}.rlib"));
    std::fs::write(&path, b"artifact").unwrap();
    let when = SystemTime::now() - Duration::from_secs(age);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// Wait until `lock` is actually free.
///
/// `drop` releases this case's handle, but a sibling case that forked between
/// `lock()` and here shares the open file description, and with it the `flock`,
/// until its child execs. Measured on #1132: the released reclaim found the lock
/// still held and kept all three copies, while the case alone passed every time.
/// So this takes the lock through `lock_wait::acquire`, which waits on the
/// event itself — the sibling's exec releasing the shared description — and
/// lets it go at once (CLOUD-2789).
fn released(lock: &std::path::Path) {
    let probe = std::fs::File::open(lock).unwrap();
    let taken = batten_facts::lock_wait::acquire(
        probe,
        lock,
        batten_facts::lock_wait::Mode::Exclusive,
        None,
    )
    .expect("the lock is taken once the sibling's child execs");
    drop(taken);
}

// --- the disk collector (CLOUD-2197) -----------------------------------------

/// One cargo unit in `profile`: a fingerprint file read `age` seconds ago and a
/// `deps` artifact of `bytes` real bytes. Returns the artifact's path.
fn unit(profile: &Path, name: &str, hash: &str, age: u64, bytes: usize) -> PathBuf {
    let fingerprint = profile.join(".fingerprint").join(format!("{name}-{hash}"));
    std::fs::create_dir_all(&fingerprint).unwrap();
    let file = fingerprint.join(format!("lib-{name}"));
    std::fs::write(&file, b"fingerprint").unwrap();
    let when = SystemTime::now() - Duration::from_secs(age);
    common::set_times(
        &file,
        std::fs::FileTimes::new()
            .set_accessed(when)
            .set_modified(SystemTime::now() - Duration::from_secs(age + 10)),
    );
    let deps = profile.join("deps");
    std::fs::create_dir_all(&deps).unwrap();
    let artifact = deps.join(format!("lib{name}-{hash}.rlib"));
    std::fs::write(&artifact, vec![7_u8; bytes]).unwrap();
    artifact
}

fn present(profile: &Path, name: &str, hash: &str) -> bool {
    profile
        .join(".fingerprint")
        .join(format!("{name}-{hash}"))
        .exists()
}

fn request<'a>(
    trees: &'a [PathBuf],
    kept: &'a [batten::collect::Kept],
    need: u64,
) -> batten::collect::Request<'a> {
    batten::collect::Request {
        trees,
        keep_generations: 2,
        kept,
        need_bytes: need,
        deadline: None,
        wait: false,
        stop: None,
        live_since: None,
        copies: None,
        fixtures_since: None,
        traces: None,
    }
}

/// [`request`], under a live build that started a minute ago: what it has used
/// since is its own, as a running suite's is.
fn request_under_a_live_build(trees: &[PathBuf], need: u64) -> batten::collect::Request<'_> {
    let mut ask = request(trees, &[], need);
    ask.live_since = Some(SystemTime::now() - Duration::from_secs(60));
    ask.fixtures_since = ask.live_since;
    ask
}

/// A directory holding one 64KiB file, both written `age` seconds ago: an
/// incremental session or a test fixture, as the collector dates it.
fn aged_dir(dir: &Path, age: u64) {
    std::fs::create_dir_all(dir).unwrap();
    let file = dir.join("payload");
    std::fs::write(&file, vec![7_u8; 64 * 1024]).unwrap();
    let when = SystemTime::now() - Duration::from_secs(age);
    for path in [&file, dir] {
        common::set_times(
            path,
            std::fs::FileTimes::new()
                .set_modified(when)
                .set_accessed(when),
        );
    }
}

/// THE INCREMENTAL CACHE IS RANKED (CLOUD-2197): measured on #1132, 8.1GB of
/// `incremental` sat outside every pass while 865 units freed 159MB. A stale
/// crate cache goes; one written inside the working set — the edit loop's own —
/// stays while a live build has used it. A mutant that skips ranking it leaves both.
#[test]
fn a_stale_incremental_cache_is_collected_and_a_fresh_one_kept() {
    let root = common::scratch("collect-incremental");
    let tree = root.join("target");
    let profile = tree.join("debug");
    std::fs::create_dir_all(profile.join(".fingerprint")).unwrap();
    aged_dir(&profile.join("incremental/stale-0aaaaaaaaaaaa/s-old"), 7200);
    aged_dir(&profile.join("incremental/stale-0aaaaaaaaaaaa"), 7200);
    aged_dir(&profile.join("incremental/fresh-0bbbbbbbbbbbb/s-new"), 1);
    let trees = [tree.clone()];
    // A BOUNDED NEED, because a cache is a compile's input and its root is the
    // compile's lock, not a run's clock: what keeps the edit loop's own cache
    // is least-recently-used order, so the stale one is taken first and the
    // pass stops there.
    let units = batten::collect::collect(&request_under_a_live_build(&trees, 1)).removed;
    assert_eq!(
        units, 1,
        "the least recently used cache goes first, and suffices"
    );
    assert!(!profile.join("incremental/stale-0aaaaaaaaaaaa").exists());
    assert!(
        profile.join("incremental/fresh-0bbbbbbbbbbbb").exists(),
        "the edit loop's cache is the last one taken"
    );
}

/// TEST SCRATCH IS RANKED TOO: cargo's `CARGO_TARGET_TMPDIR` held 4.1GB of
/// fixtures on #1132 that nothing removed until the next run's setup. A stale
/// fixture goes; a running suite's fresh one stays. A mutant that skips ranking
/// scratch leaves both.
#[test]
fn a_stale_test_scratch_entry_is_collected() {
    let root = common::scratch("collect-scratch");
    let tree = root.join("target");
    aged_dir(&tree.join("tmp/old-fixture"), 7200);
    aged_dir(&tree.join("tmp/live-fixture"), 1);
    let trees = [tree.clone()];
    let units = batten::collect::collect(&request_under_a_live_build(&trees, u64::MAX)).removed;
    assert_eq!(units, 1, "only the stale fixture is outside the live build");
    assert!(!tree.join("tmp/old-fixture").exists());
    assert!(tree.join("tmp/live-fixture").exists());
}

/// A FIXTURE A FINISHED SUITE WROTE GOES, EVEN INSIDE A LIVE BUILD'S WINDOW
/// (#1276): the `cargo run` hosting a lap lives as long as the lap, and every
/// fixture its suites wrote read as live until the mutation stage filled the
/// volume. With no suite running, nothing roots a fixture.
///
/// Fails by: fixtures judged by the build window rather than their own.
#[test]
fn a_fixture_no_running_suite_wrote_is_collected_inside_a_builds_window() {
    let root = common::scratch("collect-finished-suite");
    let tree = root.join("target");
    aged_dir(&tree.join("tmp/finished-suite-fixture"), 1);
    let trees = [tree.clone()];
    let mut ask = request_under_a_live_build(&trees, u64::MAX);
    ask.fixtures_since = None;
    let units = batten::collect::collect(&ask).removed;
    assert_eq!(
        units, 1,
        "the finished suite's fixture is outside every window"
    );
    assert!(!tree.join("tmp/finished-suite-fixture").exists());
}

/// A COPY A KILLED SWEEP LEFT IN THE TEMP DIRECTORY IS COLLECTED, AND A LIVE
/// SWEEP'S IS NOT (#1276). cargo-mutants removes its copy only on a clean exit,
/// and a lap began 4.5GB down beside its own live 12GB copy on a volume whose
/// every ranked tree was under the checkout.
///
/// THE LIVE COPY IS WRITTEN TWO LEVELS DOWN AND NOWHERE ELSE, because that is how
/// a sweep writes: a shallow date reads it as idle since it was staged.
///
/// Fails by: no copies read; any directory in the temp directory taken; a copy
/// dated shallow, which collects the live one.
#[test]
fn a_stale_mutant_copy_is_collected_and_a_live_one_kept() {
    let root = common::scratch("collect-mutant-copies");
    let temp = root.join("temp");
    let stale = temp.join("cargo-mutants-batten-AAAAAA.tmp");
    aged_dir(&stale.join("target/debug"), 7200);
    aged_dir(&stale.join("target"), 7200);
    aged_dir(&stale, 7200);
    let live = temp.join("cargo-mutants-batten-BBBBBB.tmp");
    aged_dir(&live.join("src/deep"), 1);
    aged_dir(&live.join("src"), 7200);
    aged_dir(&live, 7200);
    let other = temp.join("somebody-elses.tmp");
    aged_dir(&other, 7200);
    let tree = root.join("target");
    std::fs::create_dir_all(&tree).unwrap();
    let trees = [tree];
    let mut ask = request_under_a_live_build(&trees, u64::MAX);
    ask.copies = Some(&temp);
    let _ = batten::collect::collect(&ask);
    assert!(!stale.exists(), "a copy no live sweep writes goes");
    assert!(
        live.exists(),
        "a copy written since the live build began stays"
    );
    assert!(other.exists(), "only cargo-mutants' own copies are taken");
}

/// A BUILD INSIDE FRESH SCRATCH IS THE SCRATCH ENTRY'S, NOT A UNIT OF ITS OWN:
/// a suite's fixture tree under `tmp/` carries units of any age, and the entry
/// that holds them is what a live build's root judges. A mutant ranking the unit
/// itself collects the nested unit.
#[test]
fn a_build_inside_fresh_scratch_is_never_collected() {
    let root = common::scratch("collect-nested-scratch");
    let tree = root.join("target");
    let nested = tree.join("tmp/running-case/target/debug");
    unit(&nested, "fixture", "9999999999999999", 7200, 16);
    aged_dir(&tree.join("tmp/running-case"), 1);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request_under_a_live_build(&trees, u64::MAX));
    assert!(
        present(&nested, "fixture", "9999999999999999"),
        "a unit inside a fresh scratch entry is the entry's"
    );
}

/// A NESTED BUILD TREE'S SCRATCH IS RANKED LIKE THE CHECKOUT'S (CLOUD-2286):
/// measured on #1132, `target/replay/tmp` held 555 MB of fixtures that no pass
/// could see, because only `target/tmp` was scratch. A mutant that misses nested
/// scratch leaves the stale fixture.
#[test]
fn a_nested_build_trees_stale_scratch_is_collected() {
    let root = common::scratch("collect-nested-build-scratch");
    let tree = root.join("target");
    unit(
        &tree.join("replay/debug"),
        "replayed",
        "1212121212121212",
        30,
        16,
    );
    aged_dir(&tree.join("replay/tmp/old-fixture"), 7200);
    aged_dir(&tree.join("replay/tmp/live-fixture"), 1);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request_under_a_live_build(&trees, u64::MAX));
    assert!(
        !tree.join("replay/tmp/old-fixture").exists(),
        "the replay build's stale fixture went"
    );
    assert!(
        tree.join("replay/tmp/live-fixture").exists(),
        "a running suite's fixture stays"
    );
}

/// THE STAGED COPY IS ONE UNIT, RANKED BY ITS NEWEST WRITE (CLOUD-2286):
/// measured on #1132, `target/mutate` held 511 MB idle since the day before
/// while a lap removed the dependencies of the profiles the next lap built.
/// An idle copy goes before a built profile's older-looking unit; a copy a
/// running sweep just wrote stays whole. A mutant that skips ranking the copy
/// takes the dependency instead.
#[test]
fn an_idle_staged_copy_goes_before_a_built_profiles_units() {
    let root = common::scratch("collect-staged-copy");
    let tree = root.join("target");
    unit(&tree.join("debug"), "dep", "1313131313131313", 7200, 4096);
    unit(&tree.join("debug"), "fresh", "1414141414141414", 30, 4096);
    let staged = tree.join("mutate");
    aged_dir(&staged.join("crates/src"), 3600);
    aged_dir(&staged.join("crates"), 3600);
    aged_dir(&staged, 3600);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 1));
    assert!(!staged.exists(), "the idle staged copy went first, whole");
    assert!(
        present(&tree.join("debug"), "dep", "1313131313131313"),
        "the built profile's older-looking dependency stayed"
    );

    // A running sweep's copy: written deep since the live build started.
    aged_dir(&staged.join("crates/src"), 1);
    aged_dir(&staged.join("crates"), 3600);
    aged_dir(&staged, 3600);
    let _ = batten::collect::collect(&request_under_a_live_build(&trees, u64::MAX));
    assert!(
        staged.join("crates/src/payload").exists(),
        "a copy a live sweep wrote stays whole"
    );
}

#[test]
fn the_least_recently_used_live_unit_goes_first() {
    let root = common::scratch("collect-lru");
    let (one, two) = (root.join("a/target"), root.join("b/target"));
    unit(&one.join("debug"), "alpha", "1111111111111111", 3600, 4096);
    unit(&two.join("debug"), "beta", "2222222222222222", 1800, 4096);
    let trees = [one.clone(), two.clone()];
    let units = batten::collect::collect(&request(&trees, &[], 1)).removed;
    assert_eq!(units, 1, "one unit frees the one byte asked for");
    assert!(
        !present(&one.join("debug"), "alpha", "1111111111111111"),
        "the older unit went"
    );
    assert!(
        present(&two.join("debug"), "beta", "2222222222222222"),
        "the newer one stays"
    );
}

#[test]
fn a_unit_a_running_program_executes_is_never_collected() {
    // Measured on #1132: a hook collecting during a nextest run removed the
    // test binaries nextest was executing; no `.cargo-lock` was held. The
    // unit's binary here is a copy of the engine, held running by a verb that
    // blocks reading stdin, and it is the only unit. A copy keeps its mode bits
    // on unix and takes the platform's suffix, so the case runs everywhere the
    // collector ships.
    let root = common::scratch("collect-running");
    let profile = root.join("target/debug");
    unit(&profile, "runner", "5555555555555555", 7200, 16);
    let binary = profile.join(format!(
        "deps/runner-5555555555555555{}",
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::copy(env!("CARGO_BIN_EXE_batten"), &binary).unwrap();
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the case needs a process executing the unit's own binary, which `common::batten` cannot be"
    )]
    let mut command = std::process::Command::new(&binary);
    command
        .current_dir(&root)
        .args([
            "payload",
            "field",
            "--harness",
            "claude-code",
            "--name",
            "prompt",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut running = common::spawn_copy(&mut command);
    let kept = batten::collect::engine_kept();
    let trees = [root.join("target")];
    let _ = batten::collect::collect(&request(&trees, &kept, u64::MAX));
    let survived = binary.exists();
    let _ = running.kill();
    let _ = running.wait();
    assert!(
        survived,
        "a binary a process is executing is never collected"
    );
}

/// A LIVE RUN'S EXECUTABLES ARE ITS OWN (CLOUD-2197), however much is asked
/// for. Measured on #1132: collecting toward `max_free_mb` walked oldest first
/// into the `policy_modules` test binary built for the running suite, which no
/// build lock covers once the suite is running its tests.
#[test]
fn a_test_binary_a_live_run_built_is_never_collected() {
    let root = common::scratch("collect-live-build");
    let profile = root.join("target/debug");
    // A RUN STARTED TWO HOURS AGO still launches a binary it built an hour ago.
    unit(&profile, "in-use", "eeeeeeeeeeeeeeee", 3600, 4096);
    std::fs::write(profile.join("deps/in_use-eeeeeeeeeeeeeeee"), b"elf").unwrap();
    unit(&profile, "stale", "ffffffffffffffff", 3 * 3600, 4096);
    let trees = [root.join("target")];
    let mut ask = request(&trees, &[], u64::MAX);
    ask.live_since = Some(SystemTime::now() - Duration::from_hours(2));
    let pass = batten::collect::collect(&ask);
    assert_eq!(pass.removed, 1, "only the unit no live run reads goes");
    assert!(present(&profile, "in-use", "eeeeeeeeeeeeeeee"));
    assert!(!present(&profile, "stale", "ffffffffffffffff"));
    assert!(pass.held.live, "and the pass says a live run kept it");
}

/// A LIBRARY IS A COMPILE'S, AND ITS ROOT IS THE COMPILE'S LOCK (2026-10-13):
/// a live run's clock does not keep one. Measured: under an hour-long `verify`
/// the clock kept every unit every tree had used — clippy's, long after it
/// exited — and `land` collected nothing until the volume was full.
#[test]
fn a_library_a_finished_compile_used_is_collected_under_a_live_run() {
    let root = common::scratch("collect-live-run-library");
    let profile = root.join("target/clippy/debug");
    unit(&profile, "linted", "abcdabcdabcdabcd", 3600, 4096);
    let trees = [root.join("target")];
    let mut ask = request(&trees, &[], u64::MAX);
    ask.live_since = Some(SystemTime::now() - Duration::from_hours(2));
    let pass = batten::collect::collect(&ask);
    assert_eq!(pass.removed, 1, "no lock holds it, and no run launches it");
    assert!(!present(&profile, "linted", "abcdabcdabcdabcd"));
}

/// NO LIVE BUILD, NO ROOT: a unit used a minute ago is collectable once nothing
/// is running, which the age window refused, so a pressed volume was not freed.
#[test]
fn with_no_live_build_a_recent_unit_is_collected() {
    let root = common::scratch("collect-no-live-build");
    let profile = root.join("target/debug");
    unit(&profile, "recent", "abababababababab", 60, 4096);
    let trees = [root.join("target")];
    let pass = batten::collect::collect(&request(&trees, &[], u64::MAX));
    assert_eq!(pass.removed, 1);
    assert!(!present(&profile, "recent", "abababababababab"));
}

/// THE CHECKOUT'S BUILD IS A ROOT (CLOUD-2232): `target/release/batten` is what
/// the installed engine hands every call to, so it survives with nothing
/// running it. It shares its inode with the unit's artifact, as cargo's uplift
/// does.
/// A pass bound no case reaches. An unbounded pass also takes every
/// `cargo-mutants-*.tmp` copy in the temp directory whole, and the suite's
/// temp directory is shared: a stale copy a nested sweep left there was
/// collected by a case that never made it, and freed first, it decided what
/// else the pass took (CLOUD-2789). Bounded, a pass reads no copies.
fn unreached() -> std::time::Instant {
    std::time::Instant::now() + Duration::from_secs(3600)
}

#[test]
fn the_checkout_build_is_never_collected() {
    let repo = common::scratch("collect-checkout-build");
    common::init_repo(&repo);
    let profile = repo.join("target/release");
    let artifact = unit(&profile, "batten", "cdcdcdcdcdcdcdcd", 3 * 3600, 4096);
    std::fs::hard_link(&artifact, profile.join("batten")).unwrap();
    let mut config = rules("target");
    config.min_free_mb = Some(10);
    config.max_free_mb = Some(1 << 30);
    let done = batten::collect::collect_toward_max(
        &repo,
        &config,
        &[],
        0,
        &mut || Ok(0),
        Some(unreached()),
        false,
    );
    assert!(done.is_some());
    assert!(
        present(&profile, "batten", "cdcdcdcdcdcdcdcd"),
        "the build the installed engine follows is never collected"
    );
}

#[test]
fn a_unit_just_rebuilt_is_not_least_recently_used() {
    // Measured on #1132: a re-armed unit cargo then rebuilt under the same hash
    // has an old atime and a fresh mtime, and read by atime alone it was the
    // first collected: the test binary nextest was about to run.
    let root = common::scratch("collect-rebuilt");
    let (one, two) = (root.join("a/target"), root.join("b/target"));
    unit(
        &one.join("debug"),
        "rebuilt",
        "3333333333333333",
        7200,
        4096,
    );
    let fingerprint = one.join("debug/.fingerprint/rebuilt-3333333333333333/lib-rebuilt");
    std::fs::File::options()
        .write(true)
        .open(&fingerprint)
        .unwrap()
        .set_modified(SystemTime::now())
        .unwrap();
    unit(&two.join("debug"), "idle", "4444444444444444", 1800, 4096);
    let trees = [one.clone(), two.clone()];
    let units = batten::collect::collect(&request(&trees, &[], 1)).removed;
    assert_eq!(units, 1);
    assert!(
        present(&one.join("debug"), "rebuilt", "3333333333333333"),
        "the unit cargo just rewrote stays"
    );
    assert!(
        !present(&two.join("debug"), "idle", "4444444444444444"),
        "the one nothing has touched for a minute goes"
    );
}

#[test]
fn a_collected_unit_takes_its_artifacts() {
    // The fingerprint alone is a few bytes; the artifacts are the unit's size.
    let root = common::scratch("collect-artifacts");
    let tree = root.join("target");
    let artifact = unit(
        &tree.join("debug"),
        "heavy",
        "abababababababab",
        3600,
        1 << 20,
    );
    let trees = [tree.clone()];
    let pass = batten::collect::collect(&request(&trees, &[], 1));
    let (freed, units) = (pass.freed_bytes, pass.removed);
    assert_eq!(units, 1);
    assert!(!artifact.exists(), "the unit's deps artifact went with it");
    assert!(freed >= 1 << 20, "and its bytes were counted: {freed}");
}

#[test]
fn a_superseded_unit_goes_before_an_older_live_one() {
    let root = common::scratch("collect-superseded");
    let tree = root.join("target");
    let deps = tree.join("debug/deps");
    artifact(&deps, "cli", "aaaaaaaaaaaa", 3600);
    artifact(&deps, "cli", "bbbbbbbbbbbb", 1800);
    artifact(&deps, "cli", "cccccccccccc", 60);
    unit(&tree.join("debug"), "old", "3333333333333333", 7200, 4096);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 1));
    assert!(
        !deps.join("libcli-aaaaaaaaaaaa.rlib").exists(),
        "the superseded generation went"
    );
    assert!(
        present(&tree.join("debug"), "old", "3333333333333333"),
        "and the older live unit was never reached"
    );
}

/// **A PROFILE BEING BUILT KEEPS ITS OLD-LOOKING UNITS** while an idle profile
/// has any. Under `relatime` a dependency every build reads keeps the time it was
/// built, so by its own time it ranks first; measured on #1132, a lap removed
/// 1,308 of 1,482 units that way while an idle 2 GB profile survived.
#[test]
fn an_idle_profiles_units_go_before_a_built_profiles_older_ones() {
    let root = common::scratch("collect-idle-profile");
    let tree = root.join("target");
    unit(&tree.join("debug"), "dep", "4444444444444444", 7200, 4096);
    unit(&tree.join("debug"), "fresh", "5555555555555555", 30, 4096);
    unit(&tree.join("idle"), "stale", "6666666666666666", 3600, 4096);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 1));
    assert!(
        !present(&tree.join("idle"), "stale", "6666666666666666"),
        "the idle profile's unit went first"
    );
    assert!(
        present(&tree.join("debug"), "dep", "4444444444444444"),
        "the built profile's older-looking dependency stayed"
    );
}

/// **AN ARTIFACT NO FINGERPRINT NAMES GOES BEFORE ANY LIVE UNIT**: cargo reaches
/// an artifact only through its fingerprint's hash, so it costs no rebuild.
/// Measured on #1132: two ~300 MB `libbatten` rlibs two days old, 875 MB in all.
#[test]
fn an_artifact_no_fingerprint_names_is_collected_first() {
    let root = common::scratch("collect-orphan-artifact");
    let tree = root.join("target");
    let deps = tree.join("debug/deps");
    unit(&tree.join("debug"), "live", "7777777777777777", 7200, 4096);
    artifact(&deps, "gone", "dddddddddddddddd", 60);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 1));
    assert!(
        !deps.join("libgone-dddddddddddddddd.rlib").exists(),
        "the unreachable artifact went"
    );
    assert!(
        present(&tree.join("debug"), "live", "7777777777777777"),
        "and the oldest live unit was never reached"
    );
}

#[test]
fn collection_stops_at_max_free() {
    let root = common::scratch("collect-stops");
    let tree = root.join("target");
    let profile = tree.join("debug");
    for (index, hash) in ["4444444444444441", "4444444444444442", "4444444444444443"]
        .iter()
        .enumerate()
    {
        unit(
            &profile,
            &format!("u{index}"),
            hash,
            3000 - index as u64 * 1000,
            1 << 20,
        );
    }
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], (1 << 20) + (1 << 19)));
    assert!(!present(&profile, "u0", "4444444444444441"));
    assert!(!present(&profile, "u1", "4444444444444442"));
    assert!(
        present(&profile, "u2", "4444444444444443"),
        "it stops once the bytes asked for are freed"
    );

    // Anti-vacuity: above the minimum, nothing at all is collected.
    let mut rules = rules("target");
    rules.min_free_mb = Some(10);
    rules.max_free_mb = Some(20);
    let mut plenty = || Ok(1000);
    assert!(
        batten::collect::collect_if_pressed(&root, &rules, &[], &mut plenty, None, false).is_none()
    );
    assert!(present(&profile, "u2", "4444444444444443"));
}

#[test]
fn a_collection_re_arms_the_survivors() {
    let root = common::scratch("collect-rearm");
    let tree = root.join("target");
    unit(
        &tree.join("debug"),
        "keepme",
        "5555555555555555",
        1800,
        4096,
    );
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 0));
    let file = tree.join("debug/.fingerprint/keepme-5555555555555555/lib-keepme");
    let meta = std::fs::metadata(&file).unwrap();
    assert_eq!(
        meta.accessed().unwrap(),
        meta.modified().unwrap(),
        "atime re-armed to mtime"
    );
}

#[test]
fn a_tree_a_build_holds_is_never_collected() {
    let root = common::scratch("collect-held");
    let tree = root.join("target");
    let profile = tree.join("debug");
    unit(&profile, "busy", "6666666666666666", 3600, 4096);
    let lock = std::fs::File::create(profile.join(".cargo-lock")).unwrap();
    lock.try_lock()
        .expect("hold the build lock, free in a fresh fixture");
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], u64::MAX));
    assert!(
        present(&profile, "busy", "6666666666666666"),
        "a building profile loses nothing"
    );
    drop(lock);
    released(&profile.join(".cargo-lock"));
    let _ = batten::collect::collect(&request(&trees, &[], u64::MAX));
    assert!(
        !present(&profile, "busy", "6666666666666666"),
        "released, it is collectable"
    );
}

/// A BUILD DIRECTORY ANOTHER TARGET'S BUILD HOLDS IS NEVER COLLECTED
/// (CLOUD-2789). A mutation sweep builds with `CARGO_BUILD_BUILD_DIR` at the
/// checkout's `target` and its own `CARGO_TARGET_DIR`, so cargo holds only
/// `.cargo-build-lock` in `target/debug`, never `.cargo-lock`; reading the
/// latter alone, a pass removed the rlibs the sweep was about to link. Each of
/// cargo's three profile locks, held alone, keeps the profile.
///
/// Fails by: a profile read as free while any one of cargo's locks is held.
#[test]
fn a_profile_any_cargo_lock_holds_is_never_collected() {
    for (at, name) in [".cargo-build-lock", ".cargo-artifact-lock", ".cargo-lock"]
        .into_iter()
        .enumerate()
    {
        let root = common::scratch(&format!("collect-held-by-{}", name.trim_start_matches('.')));
        let tree = root.join("target");
        let profile = tree.join("debug");
        let hash = format!("{at}abcabcabcabcabc");
        unit(&profile, "linked", &hash, 3600, 4096);
        let lock = std::fs::File::create(profile.join(name)).unwrap();
        lock.try_lock()
            .expect("hold the lock, free in a fresh fixture");
        let trees = [tree.clone()];
        let _ = batten::collect::collect(&request(&trees, &[], u64::MAX));
        assert!(
            present(&profile, "linked", &hash),
            "{name} held: a building profile loses nothing"
        );
        drop(lock);
        released(&profile.join(name));
        let _ = batten::collect::collect(&request(&trees, &[], u64::MAX));
        assert!(
            !present(&profile, "linked", &hash),
            "{name} released: it is collectable"
        );
    }
}

#[test]
fn a_shared_inode_is_not_counted_until_its_last_name_goes() {
    let root = common::scratch("collect-inode");
    let tree = root.join("target");
    let profile = tree.join("debug");
    let older = unit(&profile, "shared", "7777777777777777", 3600, 1 << 20);
    unit(&profile, "next", "8888888888888888", 1800, 4096);
    std::fs::hard_link(&older, root.join("second-name")).unwrap();
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &[], 1 << 20));
    assert!(
        !present(&profile, "next", "8888888888888888"),
        "the hardlinked file freed nothing, so the collection went on to the next unit"
    );
}

#[test]
fn the_running_engine_is_never_collected() {
    let root = common::scratch("collect-engine");
    let tree = root.join("target");
    let profile = tree.join("release");
    let engine = unit(&profile, "batten", "9999999999999999", 7200, 4096);
    unit(&profile, "other", "aaaaaaaaaaaaaaaa", 1800, 4096);
    let installed = root.join("installed-batten");
    std::fs::hard_link(&engine, &installed).unwrap();
    let kept = batten::collect::kept(&[installed]);
    let trees = [tree.clone()];
    let _ = batten::collect::collect(&request(&trees, &kept, u64::MAX));
    assert!(
        present(&profile, "batten", "9999999999999999"),
        "the engine's unit survives as the oldest"
    );
    assert!(
        !present(&profile, "other", "aaaaaaaaaaaaaaaa"),
        "everything else was collectable"
    );
}

#[test]
fn a_sibling_worktrees_units_are_ranked_with_the_checkouts() {
    let root = common::scratch("collect-worktree");
    let repo = root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    common::init_repo(&repo);
    common::git_in(&repo, &["worktree", "add", "-q", "../sibling"]);
    let sibling = root.join("sibling");
    unit(
        &sibling.join("target/debug"),
        "far",
        "bbbbbbbbbbbbbbbb",
        7200,
        3 << 20,
    );
    unit(
        &repo.join("target/debug"),
        "near",
        "cccccccccccccccc",
        1800,
        3 << 20,
    );
    let mut rules = rules("target");
    rules.min_free_mb = Some(1);
    rules.max_free_mb = Some(2);
    let mut pressed = || Ok(0);
    let collected = batten::collect::collect_if_pressed(
        &repo,
        &rules,
        &[],
        &mut pressed,
        Some(unreached()),
        false,
    )
    .expect("below the minimum, it collects");
    assert!(collected.units >= 1);
    assert!(
        !present(&sibling.join("target/debug"), "far", "bbbbbbbbbbbbbbbb"),
        "the sibling's older unit went first"
    );
    assert!(present(
        &repo.join("target/debug"),
        "near",
        "cccccccccccccccc"
    ));
}

/// THE ARM SPANS THE RUN, NOT ONE STEP (CLOUD-2197 §1). The free-space series
/// stays above the minimum while a first step runs and returns, and falls only
/// during a later one: the watcher still collects, least recently used first,
/// and its lines carry the unlink cost. A watcher that ended with the first step
/// (`arm-ends-with-the-gate`) never sees the fall.
#[test]
fn the_arm_watches_past_the_gate() {
    let repo = common::scratch("prune-watch-past-the-gate");
    common::init_repo(&repo);
    let profile = repo.join("target/debug");
    unit(&profile, "stale", "eeeeeeeeeeeeeeee", 7200, 2 << 20);
    unit(&profile, "fresh", "ffffffffffffffff", 1, 1 << 20);
    let mut config = rules("target");
    config.min_free_mb = Some(10);
    config.max_free_mb = Some(11);
    // ABOVE, ABOVE, then BELOW: the fall arrives on the third sample, after the
    // first step has returned.
    let samples = std::sync::Arc::new(Samples::default());
    let counted = std::sync::Arc::clone(&samples);
    let fallen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fall = std::sync::Arc::clone(&fallen);
    let watch = batten::disk_watch::DiskWatch {
        repo: repo.clone(),
        config: &config,
        free_mb: Box::new(move || {
            let n = counted.take();
            Ok(
                if fall.load(std::sync::atomic::Ordering::SeqCst) && n >= 1 {
                    9
                } else {
                    50
                },
            )
        }),
        kept: Vec::new(),
        copies: own_copies(&repo),
        record: None,
    };
    let ((), lines) = batten::disk_watch::around(Some(watch), || {
        // THE FIRST STEP: the volume is fine while it runs, and it returns.
        samples.wait_until(|taken| taken >= 1);
        // A LATER STEP: the volume falls now, and the watcher must still be there.
        fallen.store(true, std::sync::atomic::Ordering::SeqCst);
        // Every read from here on is the fallen volume, and the wait ends on
        // THE EVENT, the unit going (CLOUD-2789). Not on a count of samples:
        // the watcher samples every millisecond, so two more say nothing about
        // a pass having finished. A watcher that left with the gate never takes
        // it, and the case hangs for the judge's cut to file as a timeout.
        samples.wait_until(|_| !present(&profile, "stale", "eeeeeeeeeeeeeeee"));
    });
    assert!(!present(&profile, "stale", "eeeeeeeeeeeeeeee"), "LRU went");
    assert!(
        present(&profile, "fresh", "ffffffffffffffff"),
        "the working set survives"
    );
    assert!(
        lines.iter().any(|line| line.starts_with("disk-collected ")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.starts_with("disk-unlink-ms ")),
        "the unlink cost is CLOUD-1945's figure and must be on record: {lines:?}"
    );
}

/// The hash of the least recently used unit a banded fixture carries.
const STALE: &str = "eeeeeeeeeeeeeeee";

/// A repository with one stale unit under a band of 10 to 11 MiB.
fn banded(name: &str) -> (PathBuf, PathBuf, Prune) {
    let repo = common::scratch(name);
    common::init_repo(&repo);
    let profile = repo.join("target/debug");
    unit(&profile, "stale", STALE, 7200, 2 << 20);
    let mut config = rules("target");
    config.min_free_mb = Some(10);
    config.max_free_mb = Some(11);
    (repo, profile, config)
}

/// A temp directory of the case's own for a spawned engine, whose unbounded
/// pass reads cargo-mutants copies from `TMPDIR`: a lap or a sweep under the
/// suite's shared one frees a copy another suite's sweep staged there
/// (CLOUD-2789).
fn own_temp(dir: &Path) -> PathBuf {
    let name = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("case");
    common::scratch(&format!("{name}-tmp"))
}

/// The directory a case's watcher reads cargo-mutants copies from: its own
/// and never created, so the unbounded pass frees no copy another suite's
/// sweep staged in the shared temp directory (CLOUD-2789).
fn own_copies(repo: &Path) -> PathBuf {
    repo.join("no-mutant-copies")
}

/// Watch `repo` under `config` with `free_mb` answering each sample by its
/// count, until `done` holds over the samples taken and what is present.
fn watched(
    repo: &Path,
    config: &Prune,
    free_mb: impl Fn(usize) -> u64 + Send + 'static,
    done: impl Fn(usize) -> bool,
) -> Vec<String> {
    let samples = std::sync::Arc::new(Samples::default());
    let counted = std::sync::Arc::clone(&samples);
    let watch = batten::disk_watch::DiskWatch {
        repo: repo.to_path_buf(),
        config,
        free_mb: Box::new(move || Ok(free_mb(counted.take()))),
        kept: Vec::new(),
        copies: own_copies(repo),
        record: None,
    };
    let ((), lines) = batten::disk_watch::around(Some(watch), || {
        samples.wait_until(&done);
    });
    lines
}

/// A sample exactly AT the minimum is not below it, so nothing goes.
///
/// Fails by: the band read as inclusive, which collects a volume sitting on
/// its floor on every sample.
#[test]
fn a_sample_at_the_minimum_collects_nothing() {
    let (repo, profile, config) = banded("prune-watch-at-the-minimum");
    // ONE SAMPLE IS ENOUGH: the watcher decides on a sample before it next
    // reads `stop`, and `around` joins any collection it started.
    let lines = watched(&repo, &config, |_| 10, |taken| taken >= 1);
    assert!(present(&profile, "stale", STALE), "{lines:?}");
    // Only the watcher's armed line (CLOUD-2782): no collection ran.
    assert!(
        lines
            .iter()
            .all(|line| line.starts_with("disk-watch-armed ")),
        "{lines:?}"
    );
}

/// The FIRST sample below the minimum collects, when no collection is already
/// running.
///
/// Fails by: the running-collection flag read the wrong way round, so the
/// sample that found none running starts none, and the volume is back above
/// the minimum before any sample does.
#[test]
fn the_first_sample_below_the_minimum_collects() {
    let (repo, profile, config) = banded("prune-watch-first-fall");
    unit(&profile, "fresh", "ffffffffffffffff", 1, 1 << 20);
    let gone = profile.clone();
    let lines = watched(
        &repo,
        &config,
        |taken| if taken == 0 { 9 } else { 50 },
        // THE EVENT, the unit going: the watcher samples every millisecond, so a
        // count of samples says nothing about a pass having finished.
        move |_| !present(&gone, "stale", STALE),
    );
    assert!(!present(&profile, "stale", STALE), "{lines:?}");
    assert!(
        lines.iter().any(|line| line.starts_with("disk-collected ")),
        "{lines:?}"
    );
}

/// The samples a case's watcher has taken, and the EVENT each one is
/// (CLOUD-2789): the watcher's `free_mb` calls [`Samples::take`], which rings
/// the bell, and a case waits on that bell rather than on a clock or a count
/// of polls.
///
/// No bound, deliberately. A watcher that never acts leaves the case waiting
/// on a sample that never satisfies it, and the mutation judge's per-case cut
/// files that as the timeout it is. CLOUD-2376 is why that is safe now:
/// [`batten::disk_watch::around`] stops its watcher on an unwind too, so a
/// case that fails cannot hang past its own failure.
#[derive(Default)]
struct Samples {
    taken: std::sync::Mutex<usize>,
    bell: std::sync::Condvar,
}

impl Samples {
    /// Count one sample and ring the bell; the count BEFORE this one.
    fn take(&self) -> usize {
        let mut taken = self.taken.lock().expect("the samples lock");
        let before = *taken;
        *taken += 1;
        drop(taken);
        self.bell.notify_all();
        before
    }

    /// Wait until `done` holds over the samples taken, re-asked at every
    /// sample. What `done` reads besides the count (a unit gone) is settled by
    /// the time the sample after it rings.
    fn wait_until(&self, done: impl Fn(usize) -> bool) {
        let taken = self.taken.lock().expect("the samples lock");
        drop(
            self.bell
                .wait_while(taken, |taken| !done(*taken))
                .expect("the samples lock"),
        );
    }
}

/// A band undeclared is the DEFAULT band, never the arm switched off
/// (CLOUD-2197): with the keys held for a release pin, "off" let a branch's
/// own `verify` fill the disk. This replaces a mirror that asserted nothing
/// went while its body returned before the watcher's first sample.
#[test]
fn an_undeclared_band_watches_at_the_default() {
    let watched = |name: &str, free: u64| {
        let repo = common::scratch(name);
        common::init_repo(&repo);
        let profile = repo.join("target/debug");
        unit(&profile, "stale", "eeeeeeeeeeeeeeee", 7200, 2 << 20);
        let config = rules("target");
        let samples = std::sync::Arc::new(Samples::default());
        let counted = std::sync::Arc::clone(&samples);
        let watch = batten::disk_watch::DiskWatch {
            repo: repo.clone(),
            config: &config,
            free_mb: Box::new(move || {
                counted.take();
                Ok(free)
            }),
            kept: Vec::new(),
            copies: own_copies(&repo),
            record: None,
        };
        // A floor the volume is under waits for THE EVENT, the unit going; one it
        // is above waits for two samples, which is all "watched and kept" can be.
        let collects = free < 100;
        let ((), lines) = batten::disk_watch::around(Some(watch), || {
            samples.wait_until(|taken| {
                if collects {
                    !present(&profile, "stale", "eeeeeeeeeeeeeeee")
                } else {
                    taken >= 2
                }
            });
        });
        (present(&profile, "stale", "eeeeeeeeeeeeeeee"), lines)
    };
    let (kept, lines) = watched("prune-watch-default-band", 1);
    assert!(!kept, "1 MB free is under the default floor: {lines:?}");
    // Anti-vacuity: above the default floor, the watcher samples and keeps.
    let (kept, lines) = watched("prune-watch-default-roomy", 5000);
    assert!(kept, "5000 MB free is above the default floor: {lines:?}");
}

// --- the hook's caller (CLOUD-2197) -------------------------------------------

/// A committed `[prune]` table, with the free-space band when `band` is set.
fn hook_config(band: bool) -> String {
    let band = if band {
        "min_free_mb = 100\nmax_free_mb = 200\n"
    } else {
        ""
    };
    format!(
        "version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\n{band}\n\
         [prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
         [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n"
    )
}

/// A checkout carrying `config`, with one aged unit in its `target/debug`.
fn hooked(name: &str, band: bool) -> PathBuf {
    let repo = common::Fixture::at(common::scratch(name).join("repo"))
        .config(&hook_config(band))
        .file("Cargo.toml", "[workspace]\n")
        .git()
        .base_commit()
        .build();
    unit(
        &repo.join("target/debug"),
        "aged",
        "dddddddddddddddd",
        7200,
        4096,
    );
    repo
}

/// One hook event through `batten adjudicate`, with `env` set.
fn hook(dir: &Path, event: &str, env: &[(&str, &str)]) -> std::process::Output {
    use std::io::Write as _;
    let payload = serde_json::json!({
        "hook_event_name": event,
        "session_id": common::session_id("disk"),
        "source": "startup",
        "tool_name": "Read",
        "tool_input": { "file_path": "Cargo.toml" },
    })
    .to_string();
    let mut command = common::batten();
    command
        .current_dir(dir)
        .args(["adjudicate", "--harness", "claude-code"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("the binary runs");
    // A child that answers before reading stdin is a legitimate outcome.
    let _ = child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(payload.as_bytes());
    child.streamed_wait().expect("wait for batten")
}

#[test]
fn the_hook_collects_before_admitting_under_pressure() {
    let dir = hooked("hook-collects", true);
    let profile = dir.join("target/debug");
    let said = hook(&dir, "PreToolUse", &[("TARGET_PRUNE_FREE_MB", "50")]);
    assert_eq!(said.status.code(), Some(0), "{}", common::stderr(&said));
    let out = String::from_utf8_lossy(&said.stdout);
    assert!(
        !present(&profile, "aged", "dddddddddddddddd"),
        "below min_free_mb, the unit was collected: {out}"
    );
    assert!(
        out.contains("cargo retire now"),
        "the collection is noted: {out}"
    );
    assert!(!out.contains("\"deny\""), "the hook never denies: {out}");

    // Anti-vacuity: above the minimum, nothing at all is collected.
    let roomy = hooked("hook-roomy", true);
    hook(&roomy, "PreToolUse", &[("TARGET_PRUNE_FREE_MB", "500")]);
    assert!(present(
        &roomy.join("target/debug"),
        "aged",
        "dddddddddddddddd"
    ));
}

#[test]
fn a_session_start_re_arms_every_fingerprint() {
    let dir = hooked("hook-rearm", true);
    let file = dir.join("target/debug/.fingerprint/aged-dddddddddddddddd/lib-aged");
    let before = std::fs::metadata(&file).unwrap();
    assert_ne!(before.accessed().unwrap(), before.modified().unwrap());
    let said = hook(&dir, "SessionStart", &[("TARGET_PRUNE_FREE_MB", "500")]);
    assert_eq!(said.status.code(), Some(0), "{}", common::stderr(&said));
    let after = std::fs::metadata(&file).unwrap();
    assert_eq!(
        after.accessed().unwrap(),
        after.modified().unwrap(),
        "atime re-armed to mtime"
    );
}

/// A `step run` build is watched (CLOUD-2197): it is not a tool call, so only
/// the watcher around it can collect while it runs. The step waits for the aged
/// unit to go — which only the watcher can make happen.
#[test]
fn a_step_run_build_is_watched() {
    if !cfg!(unix) {
        return;
    }
    let dir = hooked("step-run-watched", true);
    let profile = dir.join("target/debug");
    // THE STEP WAITS ON THE EVENT, the unit going, and on no clock (CLOUD-2789):
    // it spins on a builtin test of the very condition, so a watcher that never
    // collects hangs the case and the mutation judge's per-case cut files that
    // as the timeout it is. It used to poll `sleep 0.05` two hundred times,
    // which made a never-collecting watcher exit 1 at a guessed ten seconds.
    // The watcher samples at startup rather than after a tick, so on the real
    // path the collection lands in about a second (measured 1.092s).
    let waits = "while [ -e target/debug/.fingerprint/aged-dddddddddddddddd ]; do :; done";
    let ran = common::batten()
        .current_dir(&dir)
        .env("TMPDIR", own_temp(&dir))
        .args(["step", "run", "probe", "--", "sh", "-c", waits])
        .env("TARGET_PRUNE_FREE_MB", "50")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    let said = common::stderr(&ran);
    assert_eq!(
        ran.status.code(),
        Some(0),
        "the unit went while it ran: {said}"
    );
    assert!(!present(&profile, "aged", "dddddddddddddddd"), "{said}");
    assert!(said.contains("step run probe: disk-collected "), "{said}");
}

/// [`hooked`]'s checkout with a linked worktree beside it, holding an aged
/// unit of its own; the worktree.
fn linked(name: &str) -> PathBuf {
    let repo = hooked(name, true);
    common::git_in(&repo, &["worktree", "add", "-q", "../linked"]);
    let linked = repo
        .parent()
        .expect("the fixture has a parent")
        .join("linked");
    unit(
        &linked.join("target/debug"),
        "aged",
        "eeeeeeeeeeeeeeee",
        7200,
        4096,
    );
    linked
}

/// `batten step run probe` in `dir` below the floor, its command blocked on a
/// FIFO until the engine traces `event`: the test reads the trace as it is
/// written and releases the step at the first line `event` begins —
/// `disk-sample`, written on the wake that spawns the pass, or `disk-wait`,
/// written as the pass parks on a held tree. No clock decides
/// when the step ends, and none bounds it (CLOUD-2789): the case waits on the
/// engine's own exit, and a hang is the runner's to report.
///
/// The exit code and everything the engine wrote to stderr.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the step's command waits on a FIFO `mkfifo` makes, and the engine is read as it writes"
)]
fn step_released_at(case: &str, dir: &Path, event: &str) -> (Option<i32>, String) {
    use std::io::{BufRead as _, Write as _};
    // THE CASE'S OWN temp directory: `own_temp` names one after the fixture's
    // last component, `repo` for every hooked fixture, and a case running
    // beside this one remade it with the FIFO in it.
    let temp = common::scratch(&format!("{case}-tmp"));
    let fifo = temp.join("release");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo {}", fifo.display());
    let mut step = common::batten();
    step.current_dir(dir)
        .env("TMPDIR", &temp)
        .env("TARGET_PRUNE_FREE_MB", "50")
        .env("BATTEN_DISK_TRACE", "1")
        .args(["step", "run", "probe", "--", "sh", "-c"])
        // The command lets go of the engine's pipes first, so the engine's
        // stderr reaches EOF when the engine exits, whatever the command does.
        .arg("exec >/dev/null 2>&1; read _ < \"$1\"")
        .arg("sh")
        .arg(&fifo);
    let mut child = step
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let mut lines = std::io::BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
    let mut said = String::new();
    for line in lines.by_ref() {
        let line = line.expect("read the engine's stderr");
        said.push_str(&line);
        said.push('\n');
        if line.starts_with(event) {
            // The event the case waits for: let the step's command return.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo)
                .and_then(|mut release| release.write_all(b"\n"))
                .expect("release the step");
            break;
        }
    }
    for line in lines {
        said.push_str(&line.expect("read the engine's stderr"));
        said.push('\n');
    }
    let status = child.wait().expect("wait for the engine");
    (status.code(), said)
}

/// FROM A LINKED WORKTREE, EACH TREE ONCE (CLOUD-2789): git lists the worktree
/// a command runs in among the linked ones, so its `target/` came twice, and
/// a pass locked it and then waited on itself.
///
/// Fails by: the trees not deduplicated by identity.
#[test]
fn trees_from_a_linked_worktree_name_each_directory_once() {
    let linked = linked("trees-once");
    let trees = batten::collect::trees(&linked, &rules("target"));
    let mut seen: Vec<PathBuf> = trees
        .iter()
        .map(|tree| std::fs::canonicalize(tree).expect("a listed tree exists"))
        .collect();
    let listed = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), listed, "a directory listed twice: {trees:?}");
    assert!(
        seen.contains(&std::fs::canonicalize(linked.join("target")).unwrap()),
        "the worktree's own tree is ranked: {trees:?}"
    );
}

/// A WATCHED STEP IN A LINKED WORKTREE EXITS (CLOUD-2789). Shard 6 printed a
/// step's result and hung until it was killed: the watcher's pass locked the
/// worktree's tree under one name and blocked on its second.
///
/// Fails by: a pass that holds one lock while it blocks on another, or a
/// watcher whose join waits on a pass without bound.
#[test]
fn a_step_run_in_a_linked_worktree_exits_under_pressure() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let linked = linked("step-run-linked");
    let (code, said) = step_released_at("step-run-linked", &linked, "disk-sample ");
    assert_eq!(code, Some(0), "{said}");
    assert!(said.contains("step run probe: disk-watch-armed "), "{said}");
}

/// A TREE ANOTHER PROCESS HOLDS DOES NOT HOLD THE STEP (CLOUD-2789): the
/// watcher's pass waits on it only while the step runs, then stops and says
/// so, and the step exits.
///
/// Fails by: a blocking wait on the tree's lock, a pass that ignores its stop
/// flag, a stopped pass that reports nothing, or one left to the grace.
#[test]
fn a_held_tree_does_not_hold_a_watched_step_open() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let dir = hooked("step-run-held", true);
    let holder = std::fs::File::open(dir.join("target")).expect("open the tree");
    holder
        .try_lock()
        .expect("hold the tree as another collector would");
    let (code, said) = step_released_at("step-run-held", &dir, "disk-wait ");
    drop(holder);
    assert_eq!(code, Some(0), "{said}");
    // STOPPED: the pass ends because it observed the stop, and the step's
    // exit waits on nothing else.
    assert!(
        said.contains("step run probe: disk-stopped "),
        "the pass observed the stop and said so: {said}"
    );
    assert!(
        present(&dir.join("target/debug"), "aged", "dddddddddddddddd"),
        "nothing under a held tree is collected: {said}"
    );
}

/// `target prune` under the same two conditions (CLOUD-2789): from a linked
/// worktree it collects and exits, and a tree another process holds is WAITED
/// FOR — on the holder's release, an event, never a clock. The case releases
/// its holder at the `disk-wait <tree>` the engine traces as it parks, and the
/// unit under that tree is then collected.
///
/// Fails by: a duplicated tree, a blocking wait on a held one, a wait that
/// skips the tree, or one that never parks.
#[test]
fn a_forced_collection_exits_from_a_worktree_and_waits_out_a_held_tree() {
    use std::io::BufRead as _;
    if !cfg!(target_os = "linux") {
        return;
    }
    let forced = |dir: &Path| {
        let mut prune = common::batten();
        prune
            .current_dir(dir)
            .env("TARGET_PRUNE_FREE_MB", "50")
            .env("BATTEN_DISK_TRACE", "1")
            .args(["target", "prune", "-y"]);
        prune
    };
    let linked = linked("prune-linked");
    let ran = forced(&linked)
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    let said = format!("{}{}", common::stdout(&ran), common::stderr(&ran));
    assert_eq!(ran.status.code(), Some(0), "{said}");
    assert!(
        !present(&linked.join("target/debug"), "aged", "eeeeeeeeeeeeeeee"),
        "the worktree's unit was collected: {said}"
    );

    let dir = hooked("prune-held", true);
    let holder = std::fs::File::open(dir.join("target")).expect("open the tree");
    holder
        .try_lock()
        .expect("hold the tree as another collector would");
    let mut holder = Some(holder);
    let mut prune = forced(&dir);
    let mut child = prune
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let mut said = String::new();
    let stderr = std::io::BufReader::new(child.stderr.take().expect("stderr is piped"));
    for line in stderr.lines() {
        let line = line.expect("read the engine's stderr");
        if line.starts_with("disk-wait ") {
            // The pass parked on the held tree: let it go.
            drop(holder.take());
        }
        said.push_str(&line);
        said.push('\n');
    }
    let status = child.wait().expect("wait for the engine");
    assert!(holder.is_none(), "the pass never parked: {said}");
    assert_eq!(status.code(), Some(0), "{said}");
    assert!(
        !present(&dir.join("target/debug"), "aged", "dddddddddddddddd"),
        "the tree released mid-wait was collected: {said}"
    );
}

/// A COLLECTION IS NEVER CHARGED TO THE STEP IT RUNS BENEATH (CLOUD-2925).
/// Below the floor, a watched step's command is a compile through the rustc
/// wrapper, itself under `strace`, which records every path the command's
/// process tree opens: the trace a step's undeclared-read gate reads. The
/// wrapper collected there, and its walk of the build tree was charged to the
/// step; the step's own watcher collects from outside the command instead.
///
/// Fails by: a compile under a watched step collecting inside the command.
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: `which` finds the tracer the case needs, and skips it where there is none"
)]
fn a_collection_is_never_charged_to_the_step_it_runs_beneath() {
    if !cfg!(target_os = "linux")
        || !std::process::Command::new("strace")
            .arg("-V")
            .output()
            .is_ok_and(|ran| ran.status.success())
    {
        return;
    }
    let dir = hooked("step-run-uncharged", true);
    let bin = dir.join("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let rustc = bin.join("rustc");
    std::fs::write(&rustc, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&rustc, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let trace = own_temp(&dir).join("command.strace");
    let engine = common::batten().get_program().to_owned();
    let mut step = common::batten();
    step.current_dir(&dir)
        .env("TMPDIR", own_temp(&dir))
        .env("TARGET_PRUNE_FREE_MB", "50")
        .args([
            "step",
            "run",
            "probe",
            "--",
            "strace",
            "-f",
            "-e",
            "trace=open,openat",
            "-o",
        ])
        .arg(&trace)
        .arg(&engine)
        .arg(&rustc)
        .args(["--crate-name", "probe", "--out-dir"])
        .arg(dir.join("target/debug/deps"));
    let ran = step
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    let said = common::stderr(&ran);
    assert_eq!(ran.status.code(), Some(0), "{said}");
    let opened = std::fs::read_to_string(&trace).expect("the command was traced");
    assert!(
        opened.contains(&rustc.display().to_string()),
        "THE PREMISE: the trace saw the command's compile: {opened}"
    );
    assert!(
        !opened.contains(".fingerprint"),
        "the command's process tree walked the build tree: {}",
        opened
            .lines()
            .filter(|line| line.contains(".fingerprint"))
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// `BATTEN_DISK_TRACE=1` writes each sample the watcher takes to stderr, the
/// one record of how often the volume was read.
///
/// Fails by: the trace line never written, so a trace-on run reads as one the
/// watcher never sampled.
#[test]
fn a_traced_watch_writes_its_samples_to_stderr() {
    if !cfg!(unix) {
        return;
    }
    let dir = hooked("step-run-traced", true);
    // The step runs until the watcher has ACTED, an event that follows a
    // sample, rather than for a guessed half second (CLOUD-2789): under
    // pressure the watcher collects the aged unit, and a sample came first.
    let waits = "while [ -e target/debug/.fingerprint/aged-dddddddddddddddd ]; do :; done";
    let ran = common::batten()
        .current_dir(&dir)
        .env("TMPDIR", own_temp(&dir))
        .args(["step", "run", "probe", "--", "sh", "-c", waits])
        .env("TARGET_PRUNE_FREE_MB", "50")
        .env("BATTEN_DISK_TRACE", "1")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    let said = common::stderr(&ran);
    assert_eq!(ran.status.code(), Some(0), "{said}");
    assert!(said.contains("disk-sample"), "{said}");
}

/// Cargo's `RUSTC_WRAPPER` (CLOUD-2197): every compile unit, whoever started
/// the build, passes the collector first and then runs the compiler with its
/// own argv and exit code. A fake `rustc` stands in, so the case pays no build.
#[test]
fn a_wrapped_compile_collects_under_pressure() {
    if !cfg!(unix) {
        return;
    }
    let compile = |name: &str, free: &str| {
        let dir = hooked(name, true);
        let bin = dir.join("fake-bin");
        std::fs::create_dir_all(&bin).unwrap();
        let rustc = bin.join("rustc");
        std::fs::write(
            &rustc,
            "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/ran\"\nexit 7\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&rustc, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out_dir = dir.join("target/debug/deps");
        let ran = common::batten()
            .current_dir(&dir)
            .arg(&rustc)
            .args(["--crate-name", "probe", "--out-dir"])
            .arg(&out_dir)
            .env("TARGET_PRUNE_FREE_MB", free)
            .stdin(std::process::Stdio::null())
            .streamed_output_keeping(batten::capture::Keep {
                stdin: true,
                stdout: false,
                stderr: false,
            })
            .expect("the binary runs");
        let seen = std::fs::read_to_string(bin.join("ran")).unwrap_or_default();
        (dir, ran, seen)
    };
    let (dir, ran, seen) = compile("rustc-wrapped", "50");
    assert_eq!(
        ran.status.code(),
        Some(7),
        "the compiler's own code: {}",
        common::stderr(&ran)
    );
    assert!(
        seen.contains("--crate-name probe --out-dir"),
        "its own argv: {seen}"
    );
    assert!(
        !present(&dir.join("target/debug"), "aged", "dddddddddddddddd"),
        "below min_free_mb the unit went before the compile"
    );
    // Anti-vacuity: with room, the compile runs and nothing is collected.
    let (roomy, ran, _) = compile("rustc-wrapped-roomy", "500");
    assert_eq!(ran.status.code(), Some(7));
    assert!(present(
        &roomy.join("target/debug"),
        "aged",
        "dddddddddddddddd"
    ));
}

/// A compile in a linked worktree reads `[prune]` from the WORKTREE's
/// `batten.toml` (CLOUD-2532). The main checkout declares no `[prune]`, so a
/// read through `repo_root` — the main checkout from a worktree — finds no band
/// and collects nothing; the worktree's own table is what arms it.
#[test]
fn a_wrapped_compile_in_a_worktree_reads_the_worktrees_prune() {
    if !cfg!(unix) {
        return;
    }
    let base = common::scratch("rustc-wrapped-worktree");
    let main = common::Fixture::at(base.join("repo"))
        .config("version = 1\n")
        .file("Cargo.toml", "[workspace]\n")
        .git()
        .base_commit()
        .build();
    let linked = base.join("linked");
    common::git_in(
        &main,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "linked",
            linked.to_str().unwrap_or_default(),
            "HEAD",
        ],
    );
    common::write(&linked, "batten.toml", &hook_config(true));
    unit(
        &linked.join("target/debug"),
        "aged",
        "dddddddddddddddd",
        7200,
        4096,
    );
    let rustc = main.join("rustc");
    std::fs::write(&rustc, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&rustc, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out_dir = linked.join("target/debug/deps");
    std::fs::create_dir_all(&out_dir).unwrap();
    let ran = common::batten()
        .current_dir(&linked)
        .arg(&rustc)
        .arg("--out-dir")
        .arg(&out_dir)
        .env("TARGET_PRUNE_FREE_MB", "50")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_eq!(ran.status.code(), Some(0), "{}", common::stderr(&ran));
    assert!(
        !present(&linked.join("target/debug"), "aged", "dddddddddddddddd"),
        "the worktree's own [prune] band armed the collection"
    );
}

/// Above the default floor a wrapped compile reads no config at all: resolving
/// it per compile cost 26.6 ms each. A declared band ABOVE the default is the
/// witness — honouring it here would mean the config was read.
#[test]
fn a_wrapped_compile_above_the_floor_reads_no_config() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::Fixture::at(common::scratch("rustc-wrapped-floor").join("repo"))
        .config("version = 1\n\n[prune]\nroot = \"target\"\nkeep = 2\nmin_free_mb = 6000\nmax_free_mb = 7000\n")
        .file("Cargo.toml", "[workspace]\n")
        .git()
        .base_commit()
        .build();
    unit(
        &dir.join("target/debug"),
        "aged",
        "dddddddddddddddd",
        7200,
        4096,
    );
    let rustc = dir.join("rustc");
    std::fs::write(&rustc, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&rustc, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let ran = common::batten()
        .current_dir(&dir)
        .arg(&rustc)
        .arg("--out-dir")
        .arg(dir.join("target/debug/deps"))
        .env("TARGET_PRUNE_FREE_MB", "5000")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_eq!(ran.status.code(), Some(0), "{}", common::stderr(&ran));
    assert!(
        present(&dir.join("target/debug"), "aged", "dddddddddddddddd"),
        "5000 MB is above the default floor, so the declared 6000 was never read"
    );
}

/// A workspace wrapper between this one and the compiler, as cargo runs
/// `RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER rustc …` for `cargo auditable`
/// (CLOUD-2789): the wrapper runs, with the compiler and its argv after it,
/// and the compile's own exit code comes back.
///
/// Fails by: the wrapper's path parsed as a verb and refused, which failed
/// every local `mise run dist`; or the wrapper skipped and the compiler run
/// directly, dropping what it adds (the dependency list an SBOM reads).
#[test]
fn a_workspace_wrapper_between_is_run_with_the_compiler() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::scratch_repo("rustc-workspace-wrapped");
    let bin = dir.join("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let wrapper = bin.join("cargo-auditable");
    let rustc = bin.join("rustc");
    std::fs::write(
        &wrapper,
        "#!/bin/sh\necho wrapped > \"$(dirname \"$0\")/wrapped\"\nexec \"$@\"\n",
    )
    .unwrap();
    std::fs::write(
        &rustc,
        "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/ran\"\nexit 7\n",
    )
    .unwrap();
    #[cfg(unix)]
    for program in [&wrapper, &rustc] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let ran = common::batten()
        .current_dir(&dir)
        .arg(&wrapper)
        .arg(&rustc)
        .args(["-vV"])
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_eq!(
        ran.status.code(),
        Some(7),
        "the compiler's own code: {}",
        common::stderr(&ran)
    );
    assert!(bin.join("wrapped").is_file(), "the workspace wrapper ran");
    let seen = std::fs::read_to_string(bin.join("ran")).unwrap_or_default();
    assert_eq!(seen.trim(), "-vV", "the compiler's own argv");
    // A BARE NAME, as `RUSTC_WORKSPACE_WRAPPER=sccache` reaches it: no path
    // separator, so only the environment naming it marks it a wrapper.
    std::fs::remove_file(bin.join("wrapped")).unwrap();
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path =
        std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(&inherited)))
            .expect("a PATH entry carries no separator");
    let bare = common::batten()
        .current_dir(&dir)
        .arg("cargo-auditable")
        .arg(&rustc)
        .args(["-vV"])
        .env("PATH", &path)
        .env("RUSTC_WORKSPACE_WRAPPER", "cargo-auditable")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_eq!(bare.status.code(), Some(7), "{}", common::stderr(&bare));
    assert!(bin.join("wrapped").is_file(), "the bare-named wrapper ran");
    // THE SAME BARE NAME, UNNAMED by the environment: one path component and
    // no `RUSTC_WORKSPACE_WRAPPER` naming it, so it is a verb, never a
    // wrapper, and is neither run nor handed the compiler (CLOUD-2789).
    std::fs::remove_file(bin.join("wrapped")).unwrap();
    let unnamed = common::batten()
        .current_dir(&dir)
        .arg("cargo-auditable")
        .arg(&rustc)
        .args(["-vV"])
        .env("PATH", path)
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_ne!(
        unnamed.status.code(),
        Some(7),
        "{}",
        common::stderr(&unnamed)
    );
    assert!(
        !bin.join("wrapped").exists(),
        "a bare name the environment does not name is not a wrapper"
    );
}

/// A path whose next argument is no compiler is no workspace wrapper: it is
/// argv for a verb, and batten never runs it (CLOUD-2789).
///
/// Fails by: the wrapper test's `compiles(next) && !compiles(first)` joined by
/// `||`, so any path-shaped first argument is executed as a wrapper.
#[test]
fn a_path_not_followed_by_a_compiler_is_not_run_as_a_wrapper() {
    if !cfg!(unix) {
        return;
    }
    let dir = common::scratch_repo("rustc-not-wrapped");
    let bin = dir.join("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let program = bin.join("not-a-wrapper");
    std::fs::write(
        &program,
        "#!/bin/sh\necho ran > \"$(dirname \"$0\")/ran\"\nexit 7\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let refused = common::batten()
        .current_dir(&dir)
        .arg(&program)
        .args(["-vV"])
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_ne!(
        refused.status.code(),
        Some(7),
        "{}",
        common::stderr(&refused)
    );
    assert!(
        !bin.join("ran").exists(),
        "a path batten was not asked to wrap ran"
    );
}

/// The probe `mise.toml` sets `RUSTC_WRAPPER` from: this binary answers with
/// its own path; one without the wrapper answers nothing, leaving it unset.
#[test]
fn the_wrapper_probe_answers_with_this_binary() {
    let probed = common::batten()
        .args(["rustc", batten::RUSTC_WRAPPER_PROBE])
        .stdin(std::process::Stdio::null())
        .streamed_output_keeping(batten::capture::Keep {
            stdin: true,
            stdout: false,
            stderr: false,
        })
        .expect("the binary runs");
    assert_eq!(probed.status.code(), Some(0), "{}", common::stderr(&probed));
    let path = String::from_utf8_lossy(&probed.stdout).trim().to_owned();
    assert!(std::path::Path::new(&path).is_file(), "{path}");
}

#[test]
fn a_sweep_that_cannot_be_brought_above_the_minimum_stops_before_building() {
    let dir = hooked("sweep-exhausted", true);
    let sweep = |free: &str| {
        common::batten()
            .current_dir(&dir)
            .env("TMPDIR", own_temp(&dir))
            .args(["mutate", "sweep"])
            .env("MUTANT_GATES", "engine-fixture")
            .env("TARGET_PRUNE_FREE_MB", free)
            .stdin(std::process::Stdio::null())
            .streamed_output_keeping(batten::capture::Keep {
                stdin: true,
                stdout: false,
                stderr: false,
            })
            .expect("the binary runs")
    };
    let stopped = sweep("5");
    let said = common::stderr(&stopped);
    assert_eq!(stopped.status.code(), Some(3), "{said}");
    assert!(said.contains("min_free_mb 100"), "{said}");
    assert!(
        said.contains("mutate sweep: disk-collected "),
        "the collection ran first: {said}"
    );
    // Anti-vacuity: with room, the sweep is not stopped for disk.
    let roomy = sweep("500");
    assert!(!common::stderr(&roomy).contains("min_free_mb"));
}

#[test]
fn a_lap_whose_volume_cannot_be_freed_stops_before_the_gate() {
    // CLOUD-2197. A step the volume cannot hold never starts: below
    // `min_free_mb` the collector runs first, and a volume it cannot bring
    // back above the minimum refuses the step before the gate spends a build.
    // The gate is `git tag`, a program every platform's suite already runs, and
    // its tag is the trace that it started.
    let dir = hooked("land-step-exhausted", true);
    let marker = dir.join(".git/refs/tags/gate-ran");
    let verify = |free: &str| {
        common::batten()
            .current_dir(&dir)
            .env("TMPDIR", own_temp(&dir))
            .args(["land", "verify"])
            .env("LAND_VERIFY", "git tag gate-ran")
            .env("TARGET_PRUNE_FREE_MB", free)
            .streamed_output()
            .expect("the binary runs")
    };
    let stopped = verify("5");
    let said = common::stderr(&stopped);
    assert_eq!(stopped.status.code(), Some(2), "{said}");
    assert!(
        said.contains("land verify: disk-collected "),
        "the collection ran first: {said}"
    );
    assert!(said.contains("min_free_mb 100"), "{said}");
    assert!(!marker.exists(), "the gate never started");
    // Anti-vacuity: with room, the gate runs.
    let roomy = verify("500");
    assert!(marker.exists(), "{}", common::stderr(&roomy));
}

/// A LAP BELOW THE FLOOR WAITS FOR BATTEN'S OWN BACKGROUND BUILD (CLOUD-2286).
/// Measured on #1132's last lap: the `cross-turn` singleton's type-check held a
/// profile's build lock at 3,979 MB free against 4,096 and `land replay`
/// refused. Here the case holds `target/debug/.cargo-lock` and a live process
/// (this one) holds a singleton: the step blocks on the build lock, the case
/// lets go once the first pass has reported, and the second pass admits. With
/// no singleton the same volume refuses as before. A mutant that does not wait
/// on the singleton refuses both.
#[test]
fn a_lap_below_the_floor_waits_for_its_own_background_build() {
    use std::io::BufRead as _;
    let dir = hooked("land-waits-for-singleton", true);
    let marker = dir.join(".git/refs/tags/gate-ran");
    let build_lock = dir.join("target/debug/.cargo-lock");
    let lock = std::fs::File::create(&build_lock).unwrap();
    lock.try_lock()
        .expect("hold the build lock, free in a fresh fixture");
    let verify = || {
        let mut command = common::batten();
        command
            .current_dir(&dir)
            .env("TMPDIR", own_temp(&dir))
            .args(["land", "verify"])
            .env("LAND_VERIFY", "git tag gate-ran")
            // The first pass reads 5 twice; the pass after the wait reads 500.
            .env("TARGET_PRUNE_FREE_MB", "5,5,5,500")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    };

    let alone = verify().streamed_output().expect("the binary runs");
    let said = common::stderr(&alone);
    assert_eq!(alone.status.code(), Some(2), "{said}");
    assert!(!said.contains("disk-waited"), "{said}");
    assert!(!marker.exists(), "no singleton, so the gate never started");

    let singleton = dir.join(".git/batten-singleton/cross-turn");
    std::fs::create_dir_all(&singleton).unwrap();
    std::fs::write(singleton.join("pid"), std::process::id().to_string()).unwrap();
    let mut child = verify().spawn().expect("the binary runs");
    let taken = child.stderr.take().unwrap();
    // THE CASE AND THE CHILD WAIT ON EACH OTHER (CLOUD-2376), AND THE WAIT IS
    // ON THE EVENT (CLOUD-2789). The child blocks on the build lock this case
    // holds, and this case only lets go once the first pass has REPORTED. When
    // that line never comes the pair deadlocks — mutating the collection away
    // is exactly what stops it coming — and the case hangs on the read below.
    // That is the honest verdict: the mutation judge's per-case cut files it
    // as a timeout. A clock here would only race that cut, and the line either
    // arrives or it is never coming; an EOF before it fails the assertion.
    let mut stderr = std::io::BufReader::new(taken);
    let mut seen = String::new();
    let mut line = String::new();
    while stderr.read_line(&mut line).unwrap_or(0) > 0 {
        let reported = line.contains("land verify: disk-collected ");
        seen.push_str(&std::mem::take(&mut line));
        if reported {
            break;
        }
    }
    assert!(
        seen.contains("land verify: disk-collected "),
        "the first pass reported before the wait: {seen}"
    );
    drop(lock);
    // The rest arrives once the lock is gone: the child runs to completion and
    // closes stderr, which is the EOF this read ends on.
    let _ = std::io::Read::read_to_string(&mut stderr, &mut line);
    seen.push_str(&line);
    let _ = child.wait().unwrap();
    assert!(
        !seen.contains("min_free_mb 100"),
        "admitted, not refused: {seen}"
    );
    assert!(
        seen.contains("land verify: disk-waited cross-turn"),
        "{seen}"
    );
    assert!(
        marker.exists(),
        "the gate ran once the build let go: {seen}"
    );
}

#[test]
fn the_hook_traces_a_call_under_the_trace_variable() {
    let dir = hooked("hook-trace", false);
    let traced = hook(
        &dir,
        "PreToolUse",
        &[("TARGET_PRUNE_FREE_MB", "777"), ("BATTEN_DISK_TRACE", "1")],
    );
    assert!(
        common::stderr(&traced).contains("disk-call Read 777 777"),
        "{}",
        common::stderr(&traced)
    );
    let quiet = hook(&dir, "PreToolUse", &[("TARGET_PRUNE_FREE_MB", "777")]);
    assert!(!common::stderr(&quiet).contains("disk-call"));
}

/// Fails by: the collector's own `disk-pass` line left unprinted under the
/// trace variable (`collect::tracing` read as off), or printed without it.
#[test]
fn a_pressed_hook_traces_its_pass_under_the_trace_variable() {
    let dir = hooked("hook-pass-trace", true);
    let pass_lines = |env: &[(&str, &str)]| {
        let said = hook(&dir, "PreToolUse", env);
        common::stderr(&said)
            .lines()
            .filter(|line| line.starts_with("disk-pass "))
            .count()
    };
    assert_eq!(
        pass_lines(&[("TARGET_PRUNE_FREE_MB", "50")]),
        0,
        "untraced, the pass does not report itself"
    );
    assert_eq!(
        pass_lines(&[("TARGET_PRUNE_FREE_MB", "50"), ("BATTEN_DISK_TRACE", "1")]),
        1,
        "below the minimum, the traced pass reports itself once"
    );
}
