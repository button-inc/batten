//! The disk arm of `land`'s gate race (CLOUD-1937), over the library.
//!
//! Three properties, each the reason the arm exists:
//!
//! * it reacts to a PROJECTED crossing, because a linker writes gigabytes between
//!   two samples and a floor reached is a floor crossed while reacting;
//! * it reclaims through the committed `[prune]` rules and never under a build
//!   lock, because the gate it watches is building while it reclaims;
//! * a volume that cannot hold the gate never starts it, and the lap stops as the
//!   environment's failure with the reclaim's wall time on record — the figure
//!   CLOUD-1945's runtime decision is made on.

// The rows this suite kills, declared beside the code they mutate and mirrored
// here so a board obligation naming this file binds:
/*
#MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
#MUTANT projection-unread|s@^        let projected = free_mb.saturating_sub(burn);$@        let projected = free_mb;@|a_falling_series_reclaims_before_the_floor_is_crossed
#MUTANT reclaim-under-held-lock|s@^            Err(std::fs::TryLockError::WouldBlock) => return None,$@            Err(std::fs::TryLockError::WouldBlock) => {}@|a_tree_under_a_held_build_lock_survives_the_reclaim
#MUTANT reclaim-unlink-unmeasured|s@^        lines.push(format!("disk-unlink-ms {}", self.wall_ms));$@@|an_exhausted_volume_never_starts_the_gate_and_records_the_reclaim
#MUTANT admission-floor-judged-mid-lap|s@^    floor.mb.saturating_sub(floor.worst_mb)$@    floor.mb@|a_lap_below_the_admission_floor_but_within_its_budget_runs
*/
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use batten::disk_watch::{HORIZON, Pressure, Reading};
use batten::prune::{Floor, Prune};

fn floor(mb: u64) -> Floor {
    Floor {
        mb,
        worst_mb: mb / 2,
        multiplier: 2,
        measured: String::from("2026-09-28"),
        basis: None,
    }
}

fn rules(root: &str, warm_mb: u64) -> Prune {
    Prune {
        root: root.to_owned(),
        keep: 2,
        warm: floor(warm_mb),
        cold: floor(warm_mb * 2),
        regrowable: Vec::new(),
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

fn survivors(deps: &Path) -> usize {
    std::fs::read_dir(deps).map_or(0, |entries| entries.flatten().count())
}

#[test]
fn a_falling_series_reclaims_before_the_floor_is_crossed() {
    // 3000MB, then 2000MB five seconds later: a burn of 200MB/s, so the next
    // thirty seconds hold 6000MB of writes against 2000MB free. Both samples sit
    // ABOVE the 1000MB floor — a check that waited for the floor would say clear.
    let mut pressure = Pressure::new(1000, HORIZON);
    assert_eq!(pressure.observe(0, 3000), Reading::Clear);
    assert_eq!(pressure.observe(5000, 2000), Reading::Reclaim);
}

#[test]
fn a_tree_under_a_held_build_lock_survives_the_reclaim() {
    // Two profiles, each with a superseded copy. `debug` is building — its lock is
    // held by THIS process — and `release` is not. Released, the same tree is
    // reclaimed, so the case cannot pass by the reclaim doing nothing.
    let repo = common::scratch("prune-watch-held-lock");
    let tree = repo.join("target");
    let debug = tree.join("debug/deps");
    let release = tree.join("release/deps");
    for deps in [&debug, &release] {
        artifact(deps, "cli", "aaaaaaaaaaaa", 3600);
        artifact(deps, "cli", "bbbbbbbbbbbb", 1800);
        artifact(deps, "cli", "cccccccccccc", 60);
    }
    std::fs::write(repo.join("Cargo.toml"), "[workspace]\n").unwrap();
    let lock = std::fs::File::create(tree.join("debug/.cargo-lock")).unwrap();
    lock.lock().unwrap();
    std::fs::File::create(tree.join("release/.cargo-lock")).unwrap();

    batten::disk_watch::reclaim(&tree, &rules("target", 1), 1).expect("reclaim");
    assert_eq!(survivors(&debug), 3, "a building profile loses nothing");
    assert_eq!(
        survivors(&release),
        2,
        "an idle one is reclaimed to keep = 2"
    );

    drop(lock);
    batten::disk_watch::reclaim(&tree, &rules("target", 1), 1).expect("reclaim");
    assert_eq!(survivors(&debug), 2, "released, keep = 2 applies again");
}

/// A repository whose gate writes a marker, so "the gate ran" is a file.
fn gated(name: &str) -> (PathBuf, Vec<String>) {
    let repo = common::scratch(name);
    std::fs::write(repo.join("Cargo.toml"), "[workspace]\n").unwrap();
    std::fs::create_dir_all(repo.join("target/debug/deps")).unwrap();
    common::init_repo(&repo);
    // `verify` reads HEAD, so the fixture needs a commit to have one.
    common::git_in(&repo, &["add", "Cargo.toml"]);
    common::git_in(&repo, &["commit", "-q", "-m", "fixture"]);
    let marker = repo.join("gate-ran.cfg");
    let command = vec![
        String::from("git"),
        String::from("config"),
        String::from("--file"),
        marker.to_string_lossy().into_owned(),
        String::from("gate.ran"),
        String::from("yes"),
    ];
    (repo, command)
}

#[test]
fn an_exhausted_volume_never_starts_the_gate_and_records_the_reclaim() {
    // A floor no volume holds, so the reclaim cannot clear it whatever this
    // machine has free: the arm must stop the lap before the gate starts.
    let (repo, command) = gated("prune-watch-exhausted");
    let config = rules("target", 100_000_000);
    let watch = batten::land::DiskWatch {
        tree: repo.join("target"),
        config: &config,
        free_mb: Box::new(|| Ok(10)),
    };
    let verified = batten::land::verify_raced(&repo, "work", &command, &[], &[], None, Some(watch))
        .expect("the lap answers");
    match verified {
        batten::land::Verified::Refused {
            cause: batten::land::Refusal::Environment { remedy },
            ..
        } => assert!(remedy.contains("floor"), "{remedy}"),
        other => panic!("an exhausted volume is the environment's stop: {other:?}"),
    }
    assert!(
        !repo.join("gate-ran.cfg").exists(),
        "the gate must not have started"
    );

    let git_dir = repo.join(".git");
    let record = batten::recorder::record_path(&git_dir, batten::land::LAP_RECORD, "work", None);
    let lines = std::fs::read_to_string(&record).expect("the lap record");
    assert!(lines.contains("disk-reclaimed "), "{lines}");
    assert!(
        lines.lines().any(|line| line.contains("disk-unlink-ms ")),
        "the reclaim's wall time is CLOUD-1945's figure and must be on record: {lines}"
    );
}

#[test]
fn a_volume_with_room_runs_the_gate() {
    // The mirror: the arm present and quiet, so the case above cannot pass by the
    // arm refusing everything.
    let (repo, command) = gated("prune-watch-room");
    let config = rules("target", 1);
    let watch = batten::land::DiskWatch {
        tree: repo.join("target"),
        config: &config,
        free_mb: Box::new(|| Ok(1_000_000)),
    };
    let verified = batten::land::verify_raced(&repo, "work", &command, &[], &[], None, Some(watch))
        .expect("the lap answers");
    assert!(
        matches!(verified, batten::land::Verified::Clean(_)),
        "{verified:?}"
    );
    assert!(repo.join("gate-ran.cfg").exists(), "the gate ran");
}

/// THE STOP #1036'S FIRST LAP MADE, as a case. A lap spends the headroom its
/// admission certified, so a reading below the warm floor is ordinary mid-gate.
/// Only past the worst measured lap — into the multiplier's margin — is it off
/// model. Here the floor is far above the reading, but the worst lap on record
/// leaves a reserve of 1MB, so 10MB free is a lap within its budget.
#[test]
fn a_lap_below_the_admission_floor_but_within_its_budget_runs() {
    let (repo, command) = gated("prune-watch-within-budget");
    let mut config = rules("target", 100_000_000);
    config.warm.worst_mb = 99_999_999;
    let watch = batten::land::DiskWatch {
        tree: repo.join("target"),
        config: &config,
        free_mb: Box::new(|| Ok(10)),
    };
    let verified = batten::land::verify_raced(&repo, "work", &command, &[], &[], None, Some(watch))
        .expect("the lap answers");
    assert!(
        matches!(verified, batten::land::Verified::Clean(_)),
        "{verified:?}"
    );
    assert!(repo.join("gate-ran.cfg").exists(), "the gate ran");
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
    std::fs::File::open(&file)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(when)
                .set_modified(SystemTime::now() - Duration::from_secs(age + 10)),
        )
        .unwrap();
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
    }
}

#[test]
fn the_least_recently_used_live_unit_goes_first() {
    let root = common::scratch("collect-lru");
    let (one, two) = (root.join("a/target"), root.join("b/target"));
    unit(&one.join("debug"), "alpha", "1111111111111111", 3600, 4096);
    unit(&two.join("debug"), "beta", "2222222222222222", 60, 4096);
    let trees = [one.clone(), two.clone()];
    let (_, units) = batten::collect::collect(&request(&trees, &[], 1));
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
    let (freed, units) = batten::collect::collect(&request(&trees, &[], 1));
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
    let mut rules = rules("target", 1);
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
    unit(&tree.join("debug"), "keepme", "5555555555555555", 60, 4096);
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
    unit(&profile, "next", "8888888888888888", 60, 4096);
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
    unit(&profile, "other", "aaaaaaaaaaaaaaaa", 60, 4096);
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
        60,
        3 << 20,
    );
    let mut rules = rules("target", 1);
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

#[test]
fn a_banded_lap_collects_least_recently_used_units_before_the_gate() {
    // Below min_free_mb at the first sample: the arm collects toward max_free_mb,
    // least recently used first, then the gate runs on the room it made.
    let (repo, command) = gated("prune-watch-banded");
    let profile = repo.join("target/debug");
    unit(&profile, "stale", "eeeeeeeeeeeeeeee", 7200, 2 << 20);
    unit(&profile, "fresh", "ffffffffffffffff", 60, 1 << 20);
    let mut config = rules("target", 1);
    config.min_free_mb = Some(10);
    config.max_free_mb = Some(11);
    let mut readings = [9_u64, 50].into_iter();
    let watch = batten::land::DiskWatch {
        tree: repo.join("target"),
        config: &config,
        free_mb: Box::new(move || Ok(readings.next().unwrap_or(50))),
    };
    let verified = batten::land::verify_raced(&repo, "work", &command, &[], &[], None, Some(watch))
        .expect("the lap answers");
    assert!(
        matches!(verified, batten::land::Verified::Clean(_)),
        "{verified:?}"
    );
    assert!(!present(&profile, "stale", "eeeeeeeeeeeeeeee"), "LRU went");
    assert!(
        present(&profile, "fresh", "ffffffffffffffff"),
        "the two MiB asked for were freed by the first unit"
    );
    let git_dir = repo.join(".git");
    let record = batten::recorder::record_path(&git_dir, batten::land::LAP_RECORD, "work", None);
    let lines = std::fs::read_to_string(&record).expect("the lap record");
    assert!(lines.contains("disk-collected "), "{lines}");
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
