//! The disk collector and the watcher a long-running batten process hosts
//! (CLOUD-1937, CLOUD-2197), over the library and the binary.
//!
//! Below `[prune] min_free_mb`: superseded units first, then live units least
//! recently used first, until `max_free_mb` is free — never a unit a build holds,
//! never the running engine, and never a unit a live build has used. The watcher spans the
//! whole run it is hosted by; the hook collects before each mediated call.

// The rows this suite kills, declared beside the code they mutate and mirrored
// here so a board obligation naming this file binds:
/*
#MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
#MUTANT reclaim-under-held-lock|s@^            Err(std::fs::TryLockError::WouldBlock) => return None,$@            Err(std::fs::TryLockError::WouldBlock) => {}@|a_tree_a_build_holds_is_never_collected
#MUTANT reclaim-unlink-unmeasured|s@^            format!("disk-unlink-ms {}", self.wall_ms),$@@|the_arm_watches_past_the_gate
#MUTANT arm-ends-with-the-gate|s@^    while !stop.load(Ordering::Relaxed) {$@    for _ in 0..1 {@|the_arm_watches_past_the_gate
*/
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use batten::prune::Prune;

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
fn released(lock: &std::path::Path) {
    for _ in 0..200 {
        let probe = std::fs::File::open(lock).unwrap();
        if probe.try_lock().is_ok() {
            return;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "bounded by a real terminal state: the sibling's child execs and closes the shared description, capped at `200` tries"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "{} stayed locked after this case released it",
        lock.display()
    );
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
        live_since: None,
    }
}

/// [`request`], under a live build that started a minute ago: what it has used
/// since is its own, as a running suite's is.
fn request_under_a_live_build(trees: &[PathBuf], need: u64) -> batten::collect::Request<'_> {
    let mut ask = request(trees, &[], need);
    ask.live_since = Some(SystemTime::now() - Duration::from_secs(60));
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
/// stays while a live build has used it. `#MUTANT incremental-unranked` leaves both.
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
/// fixture goes; a running suite's fresh one stays. `#MUTANT scratch-unranked`
/// leaves both.
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

/// A BUILD INSIDE FRESH SCRATCH IS THE SCRATCH ENTRY'S, NOT A UNIT OF ITS OWN:
/// a suite's fixture tree under `tmp/` carries units of any age, and the entry
/// that holds them is what a live build's root judges. `#MUTANT scratch-unit-ranked`
/// collects the nested unit.
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
/// could see, because only `target/tmp` was scratch. `#MUTANT
/// nested-scratch-unseen` leaves the stale fixture.
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
/// running sweep just wrote stays whole. `#MUTANT staged-copy-unranked` takes
/// the dependency instead.
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
    let done =
        batten::collect::collect_toward_max(&repo, &config, &[], 0, &mut || Ok(0), None, false);
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
    lock.lock().unwrap();
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
    let collected =
        batten::collect::collect_if_pressed(&repo, &rules, &[], &mut pressed, None, false)
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
    let samples = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&samples);
    let fallen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fall = std::sync::Arc::clone(&fallen);
    let watch = batten::disk_watch::DiskWatch {
        repo: repo.clone(),
        config: &config,
        free_mb: Box::new(move || {
            let n = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(
                if fall.load(std::sync::atomic::Ordering::SeqCst) && n >= 1 {
                    9
                } else {
                    50
                },
            )
        }),
        kept: Vec::new(),
    };
    let ((), lines) = batten::disk_watch::around(Some(watch), || {
        // THE FIRST STEP: the volume is fine while it runs, and it returns.
        wait_for(|| samples.load(std::sync::atomic::Ordering::SeqCst) >= 1);
        // A LATER STEP: the volume falls now, and the watcher must still be there.
        fallen.store(true, std::sync::atomic::Ordering::SeqCst);
        // Every read from here on is the fallen volume. Two more mean a whole
        // pass has run over it: the sample that started it and the reading it
        // takes once it has removed what it will. So the wait ends on the
        // unit going or on a pass that did not take it, never on the bound.
        let fell_at = samples.load(std::sync::atomic::Ordering::SeqCst);
        wait_for(|| {
            !present(&profile, "stale", "eeeeeeeeeeeeeeee")
                || samples.load(std::sync::atomic::Ordering::SeqCst) >= fell_at + 2
        });
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

/// How many 50 ms polls [`wait_for`] takes before giving up: four of the
/// watcher's 5 s ticks, the longest a live watcher can take to act.
const WAIT_POLLS: u32 = 400;

/// Wait until `done`, counted rather than clocked: at most [`WAIT_POLLS`]
/// polls, then the case fails on the outcome it was waiting for.
fn wait_for(done: impl Fn() -> bool) {
    for _ in 0..WAIT_POLLS {
        if done() {
            return;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "bounded by a count: at most `WAIT_POLLS` polls, four of the watcher's own ticks"
        )]
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the watcher did not act within `WAIT_POLLS` polls");
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
        let samples = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&samples);
        let watch = batten::disk_watch::DiskWatch {
            repo: repo.clone(),
            config: &config,
            free_mb: Box::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(free)
            }),
            kept: Vec::new(),
        };
        let ((), lines) = batten::disk_watch::around(Some(watch), || {
            wait_for(|| {
                samples.load(std::sync::atomic::Ordering::SeqCst) >= 2
                    || !present(&profile, "stale", "eeeeeeeeeeeeeeee")
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
        "session_id": "disk",
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
    child.wait_with_output().expect("wait for batten")
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
/// the watcher around it can collect while it runs. The step waits, bounded,
/// for the aged unit to go — which only the watcher can make happen.
#[test]
fn a_step_run_build_is_watched() {
    if !cfg!(unix) {
        return;
    }
    let dir = hooked("step-run-watched", true);
    let profile = dir.join("target/debug");
    // 200 x 0.05s = 10s, which is TWO full `disk_watch::TICK`s against a MEASURED
    // 1.092s for the real path (nextest, this suite) — the watcher samples at
    // startup rather than after a tick, so the collection lands in about a
    // second. It was 400 (20s), and that margin is not free: under
    // `collect_toward_max -> None` the collection never comes, this poll runs to
    // its budget, and the suite then exceeds the per-mutant bound cargo-mutants
    // derives from the 9s unmutated baseline — reported as `suite-timed-out`,
    // which is could-not-look (CLOUD-1267), over a mutant ~40 cases in this file
    // DO catch. A failure budget wide enough to hide the catch is not margin
    // (CLOUD-2376).
    let waits = "for i in $(seq 1 200); do \
                 [ -e target/debug/.fingerprint/aged-dddddddddddddddd ] || exit 0; \
                 sleep 0.05; done; exit 1";
    let ran = common::batten()
        .current_dir(&dir)
        .args(["step", "run", "probe", "--", "sh", "-c", waits])
        .env("TARGET_PRUNE_FREE_MB", "50")
        .stdin(std::process::Stdio::null())
        .output()
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
            .output()
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
        .output()
        .expect("the binary runs");
    assert_eq!(ran.status.code(), Some(0), "{}", common::stderr(&ran));
    assert!(
        present(&dir.join("target/debug"), "aged", "dddddddddddddddd"),
        "5000 MB is above the default floor, so the declared 6000 was never read"
    );
}

/// The probe `mise.toml` sets `RUSTC_WRAPPER` from: this binary answers with
/// its own path; one without the wrapper answers nothing, leaving it unset.
#[test]
fn the_wrapper_probe_answers_with_this_binary() {
    let probed = common::batten()
        .args(["rustc", batten::RUSTC_WRAPPER_PROBE])
        .stdin(std::process::Stdio::null())
        .output()
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
            .args(["mutate", "sweep"])
            .env("MUTANT_GATES", "engine-fixture")
            .env("TARGET_PRUNE_FREE_MB", free)
            .stdin(std::process::Stdio::null())
            .output()
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
            .args(["land", "verify"])
            .env("LAND_VERIFY", "git tag gate-ran")
            .env("TARGET_PRUNE_FREE_MB", free)
            .output()
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
/// no singleton the same volume refuses as before. `#MUTANT singleton-unwaited`
/// refuses both.
#[test]
fn a_lap_below_the_floor_waits_for_its_own_background_build() {
    use std::io::BufRead as _;
    let dir = hooked("land-waits-for-singleton", true);
    let marker = dir.join(".git/refs/tags/gate-ran");
    let build_lock = dir.join("target/debug/.cargo-lock");
    let lock = std::fs::File::create(&build_lock).unwrap();
    lock.lock().unwrap();
    let verify = || {
        let mut command = common::batten();
        command
            .current_dir(&dir)
            .args(["land", "verify"])
            .env("LAND_VERIFY", "git tag gate-ran")
            // The first pass reads 5 twice; the pass after the wait reads 500.
            .env("TARGET_PRUNE_FREE_MB", "5,5,5,500")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    };

    let alone = verify().output().expect("the binary runs");
    let said = common::stderr(&alone);
    assert_eq!(alone.status.code(), Some(2), "{said}");
    assert!(!said.contains("disk-waited"), "{said}");
    assert!(!marker.exists(), "no singleton, so the gate never started");

    let singleton = dir.join(".git/batten-singleton/cross-turn");
    std::fs::create_dir_all(&singleton).unwrap();
    std::fs::write(singleton.join("pid"), std::process::id().to_string()).unwrap();
    let mut child = verify().spawn().expect("the binary runs");
    let taken = child.stderr.take().unwrap();
    // READ ON A THREAD, WITH A BOUND, BECAUSE THE CASE AND THE CHILD WAIT ON
    // EACH OTHER (CLOUD-2376). The child blocks on the build lock this case
    // holds, and this case only lets go once the first pass has REPORTED. When
    // that line never comes the pair deadlocks — and mutating the collection
    // away is exactly what stops it coming, so `collect_toward_max -> None` hung
    // the suite instead of being caught: `cargo-mutants` reported
    // `suite-timed-out`, which is could-not-look (CLOUD-1267), over a mutant
    // this case does catch. Measured: it ran a full 300s bound where the
    // baseline tests in 9s, which is what proved it a hang rather than a slow
    // catch.
    //
    // THE BOUND MUST STAY UNDER THE SUITE'S MUTATION BUDGET, which is the
    // non-obvious part: cargo-mutants derives a per-mutant bound from the
    // unmutated baseline, so a wait long enough to exceed that just reproduces
    // `suite-timed-out` by another route — and this is not the only case the
    // mutation makes wait. `a_step_run_build_is_watched` polls four
    // `disk_watch::TICK`s, 20s, for the same reason, and the two are summed
    // against one bound.
    //
    // Five seconds against a MEASURED 0.188s for the real path (nextest, this
    // suite) is ~26x margin and leaves the mutated suite near 34s against a
    // bound derived at ~46s from a 9s baseline. Raising it buys nothing: the
    // line either arrives in a fifth of a second or it is never coming.
    let waited = Duration::from_secs(5);
    let (lines, from_child) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut stderr = std::io::BufReader::new(taken);
        let mut line = String::new();
        while stderr.read_line(&mut line).unwrap_or(0) > 0 {
            if lines.send(std::mem::take(&mut line)).is_err() {
                break;
            }
        }
    });
    let mut seen = String::new();
    while let Ok(line) = from_child.recv_timeout(waited) {
        seen.push_str(&line);
        if line.contains("land verify: disk-collected ") {
            break;
        }
    }
    assert!(
        seen.contains("land verify: disk-collected "),
        "the first pass reported before the wait: {seen}"
    );
    drop(lock);
    // The rest arrives through the same bound: the child runs to completion once
    // the lock is gone, closing stderr, which ends the reader and the channel.
    while let Ok(line) = from_child.recv_timeout(waited) {
        seen.push_str(&line);
    }
    let _ = reader.join();
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
