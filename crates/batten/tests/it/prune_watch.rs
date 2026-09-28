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
