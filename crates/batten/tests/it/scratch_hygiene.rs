//! The scratch parent is collected once per run, and the collection is asserted
//! rather than declared (CLOUD-1879).
//!
//! # What went wrong
//!
//! `common::scratch` wipes its OWN path before writing, always. Nothing wiped the
//! PARENT, so every run left its fixtures behind — **3248 entries and ~300 MB per
//! run** — and the next run paid for them. Measured on this container, same
//! commit, same profile, same binary, idle box, varying only how many stale
//! directories `target/tmp` held at the start:
//!
//! | entries at start | wall | summed | `agentic_record` | `shell_retirement` |
//! | -- | -- | -- | -- | -- |
//! | 0 | 194.5s | 741.0s | 8.7s | 77.7s |
//! | ~1250 | 203.7s | 777.8s | 10.8s | 74.6s |
//! | 3750 | 220.9s | 846.3s | **93.5s** | 74.8s |
//!
//! **+13.5% wall clock, monotonic.** `shell_retirement` is flat across all three,
//! so the effect is specific rather than ambient noise. `agentic_record` swings
//! 10.7x on sibling count alone, uniformly across every case in that file —
//! including `a_tree_with_no_records_at_all_is_silent`, a synthetic empty-tree
//! fixture, at 0.20s → 4.51s. A 22x slowdown on a case with nothing to read is
//! not that case's own work.
//!
//! It also makes A/B measurement impossible: two arms run back to back are not
//! comparable, because the second starts with ~3250 more directories than the
//! first. Two arms of CLOUD-1878's experiment were voided by exactly that.
//!
//! # Why this asserts a RUN and not a CONFIG
//!
//! The obvious gate is "`.config/nextest.toml` declares a setup script". That is
//! the shape this repository has been bitten by: a gate that asserts a
//! declaration exists and is blind to whether it did anything —
//! `Builtins.shellcheck` read zero `.bats` files for its whole life and reported
//! green the entire time (`hk.pkl`).
//!
//! So the collector publishes its own reading through `$NEXTEST_ENV`, nextest's
//! sanctioned channel from a setup script to the tests, and this file asserts the
//! value arrived. A removed script, an unwired script, or one that failed before
//! its last statement all make the variable absent. **The gate fails when the
//! work did not happen, not when the declaration is missing.**

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

/// What the setup script publishes: how many entries the scratch parent held
/// *before* it was collected.
const COLLECTED: &str = "BATTEN_SCRATCH_COLLECTED";

/// What the setup script publishes beside the count: the scratch parents it
/// covered, `:`-separated, as `pwd -P` paths (CLOUD-1976).
const ROOTS: &str = "BATTEN_SCRATCH_ROOTS";

/// The scratch parent itself, as the harness resolves it.
fn parent() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

#[test]
fn the_collector_ran_for_this_run() {
    let reading = std::env::var(COLLECTED).unwrap_or_else(|_| {
        panic!(
            "{COLLECTED} is unset, so the scratch parent was not collected for this run. \
             It is published by the `clear-scratch` setup script in `.config/nextest.toml` \
             through $NEXTEST_ENV. Either the script is gone, or it is no longer wired to \
             this profile, or it failed before its last statement — and without it the \
             suite gets ~13.5% slower per accumulated run and no two timing arms are \
             comparable (CLOUD-1879)."
        )
    });

    // ANTI-VACUITY. A variable set to anything would satisfy a presence check, so
    // the published value must be the shape the script actually writes: a count.
    // This is what fails if the `$NEXTEST_ENV` line is reduced to a bare marker.
    //
    // `trim` BECAUSE A COUNT IS THE CONTRACT AND ITS PADDING IS NOT. BSD `wc -l`
    // pads to a fixed width where GNU `wc -l` does not, so this read `"       0"`
    // on macos and `"0"` on the two Linux lanes — one red case out of 5007, on the
    // one lane whose libc differs. The collector now normalises it, and trimming
    // here keeps the assertion about the VALUE rather than about which `wc` ran.
    reading.trim().parse::<u64>().unwrap_or_else(|_| {
        panic!("{COLLECTED} should be the entry count the collector found, got {reading:?}")
    });
}

/// THIS RUN'S SCRATCH IS ITS OWN, AND HELD FOR ITS LIFE (CLOUD-2789).
///
/// A case's fixtures live in `<parent>/run-<id>`, and while any case of the run
/// is alive no other process can take `run-<id>.lock` exclusively, which is the
/// one thing a reaper must do before removing it. Linux only: `flock(1)` is the
/// other process asking.
///
/// Fails by: the scratch root no longer per run, or the lock not held by a live
/// case, so another run's reap could take this one's fixtures mid-case.
#[test]
fn this_runs_scratch_is_its_own_and_held_while_it_runs() {
    let root = crate::common::target_tmp();
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a named run directory")
        .to_owned();
    assert!(
        name.starts_with("run-") && root.parent() == Some(parent().as_path()),
        "{} is not one run's directory under {}",
        root.display(),
        parent().display()
    );
    if !cfg!(target_os = "linux") {
        return;
    }
    let lock = parent().join(format!("{name}{}", crate::common::RUN_LOCK));
    assert!(
        !free_elsewhere(&lock),
        "{} is free while this run is alive, so another run's reap would take it",
        lock.display()
    );
}

/// CLOUD-2716. A case's `std::env::temp_dir()` is under a root the collector
/// covers, so unit-case scratch is collected with the rest. Before, it was the
/// system temp dir, which nothing collected: 29,597 entries filled the disk.
///
/// Fails by: the collector no longer publishing `TMPDIR`, or publishing one
/// outside its roots.
///
/// Off unix the case abstains: Windows' `GetTempPath` reads `TMP`/`TEMP`,
/// never `TMPDIR`, and Git Bash spells the roots `/d/a/...`.
#[test]
fn a_case_temp_dir_is_under_a_collected_root() {
    if !cfg!(unix) {
        return;
    }
    let roots = std::env::var(ROOTS).unwrap_or_default();
    let temp = std::env::temp_dir()
        .canonicalize()
        .expect("the temp dir resolves");
    assert!(
        std::env::split_paths(&roots).any(|root| temp.starts_with(root)),
        "{} is not under a root the collector covers ({roots:?})",
        temp.display()
    );
    let tree = crate::common::at_root(".")
        .canonicalize()
        .expect("the checkout resolves");
    assert!(
        !temp.starts_with(&tree),
        "{} is inside the checkout, where a not-a-repository fixture is one",
        temp.display()
    );
}

/// The collector's `TMPDIR` is `batten-suite` under the temp dir it was given,
/// published as its last covered root and created; a lone run takes the last
/// run's entries there, and a run beside another leaves them. The existence
/// half is unix only: Git Bash's `/d/a/...` spelling is not a path this
/// process can open.
///
/// Fails by: `TMPDIR` unpublished, published under `target/`, left out of the
/// roots, or collected under a live run.
#[test]
fn the_collector_publishes_a_temp_dir_it_owns() {
    for (others, kept) in [("", false), ("4242", true)] {
        let (survived, published) = collect_seeded(
            &format!("temp-dir-{}", others.len()),
            others,
            &["tmp", "../tmpdir/batten-suite"],
        );
        assert_eq!(survived[1], kept, "others={others:?}: {published}");
        let line = line_of(&published, "TMPDIR");
        let temp = line.trim_start_matches("TMPDIR=");
        assert!(
            line.starts_with("TMPDIR=") && temp.ends_with("/tmpdir/batten-suite"),
            "{published}"
        );
        let line = line_of(&published, ROOTS);
        let roots = line.trim_start_matches(&format!("{ROOTS}="));
        assert_eq!(roots.rsplit(':').next(), Some(temp), "{published}");
        assert!(
            !cfg!(unix) || PathBuf::from(temp).is_dir(),
            "the published TMPDIR exists: {published}"
        );
    }
}

/// The committed `clear-scratch` command, exactly as nextest runs it.
fn collector_command() -> String {
    let text = std::fs::read_to_string(crate::common::at_root(".config/nextest.toml"))
        .expect("nextest.toml");
    let config: toml::Table = text.parse().expect("nextest.toml parses");
    config["scripts"]["setup"]["clear-scratch"]["command"]
        .as_str()
        .expect("clear-scratch declares a command")
        .to_owned()
}

/// Run the collector over a fixture target dir holding one sentinel entry, with
/// a stub `pgrep` first on `PATH` that reports `others` as the live
/// `cargo-nextest` pids. Returns whether the sentinel survived and the count line
/// the collector published.
fn collect_beside(name: &str, others: &str) -> (bool, String) {
    let (survived, published) = collect_seeded(name, others, &["../tmpdir/batten-suite"]);
    (survived[0], line_of(&published, COLLECTED))
}

/// The `KEY=value` line the collector published for `key`, whole.
///
/// Line-wise since CLOUD-1976, because the collector now publishes a second line
/// beside the count, and comparing the whole file would couple every case to the
/// other line's bytes.
fn line_of(published: &str, key: &str) -> String {
    published
        .lines()
        .find(|line| line.starts_with(&format!("{key}=")))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The collector, run over a fixture target dir holding one sentinel under each
/// of `seeds` (paths relative to that target dir). Returns whether each sentinel
/// survived, in order, and everything the collector published.
fn collect_seeded(name: &str, others: &str, seeds: &[&str]) -> (Vec<bool>, String) {
    collect_seeded_at(&crate::common::scratch(name), others, seeds)
}

/// [`collect_seeded`] over a fixture root the caller already made, so a case can
/// point another process at its target dir before the collector runs.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is the shell command nextest runs, so asserting it means running `sh`"
)]
fn collect_seeded_at(root: &std::path::Path, others: &str, seeds: &[&str]) -> (Vec<bool>, String) {
    let root = root.to_path_buf();
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("pgrep");
    std::fs::write(&stub, format!("#!/bin/sh\nprintf '%s' '{others}'\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sentinels: Vec<PathBuf> = seeds
        .iter()
        .map(|seed| root.join("target").join(seed).join("sentinel"))
        .collect();
    for sentinel in &sentinels {
        std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
        std::fs::write(sentinel, "").unwrap();
    }
    let published = root.join("nextest-env");
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&crate::common::ambient_path())),
    )
    .unwrap();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(collector_command())
        .env("CARGO_TARGET_DIR", root.join("target"))
        // NOR THE RUNNING SUITE'S BUILD DIRECTORY: under a mutant sweep's
        // baseline it is set, and a fixture's lone-run collector then wiped the
        // real build directory's `tmp` under every other running case (#1276).
        .env_remove("CARGO_BUILD_BUILD_DIR")
        // ITS OWN TEMP DIR: a lone-run collector inheriting this suite's
        // `TMPDIR` would take the running suite's temp root.
        .env("TMPDIR", root.join("tmpdir"))
        .env("NEXTEST_ENV", &published)
        .env("PATH", path)
        .status()
        .expect("run the collector");
    assert!(status.success(), "the collector must exit 0");
    let reading = std::fs::read_to_string(&published).unwrap_or_default();
    (
        sentinels.iter().map(|path| path.exists()).collect(),
        reading,
    )
}

/// NO TARGET DIR'S SCRATCH IS THE COLLECTOR'S (CLOUD-2789).
///
/// The collector took `target/tmp` and every `target/*/tmp`, so a suite started
/// in a checkout wiped `target/replay/tmp` under a live `batten test replay`,
/// whose nextest runs from a tree outside the checkout with that nested target
/// dir. Each run's scratch is now removed by its own suite's reaper, under the
/// run's lock, so the setup script leaves every one of them, even alone.
///
/// Fails by: the collector globbing a target dir's `tmp` again, which takes all
/// three sentinels.
#[test]
fn no_target_dirs_scratch_is_the_collectors() {
    let (survived, published) = collect_seeded(
        "clear-scratch-target-dirs",
        "",
        &["tmp", "replay/tmp", "x86_64-unknown-linux-musl/tmp"],
    );
    assert_eq!(
        survived,
        vec![true, true, true],
        "a lone collector left every target dir's scratch to its own run: {published}"
    );
}

/// CLOUD-1912: `verify` runs several nextest invocations at once, and a later
/// run's wipe deleted a live case's scratch in an earlier one. With another run
/// alive the collector must leave the shared temp root alone.
///
/// MUTANT: dropping the `others -eq 0` guard (collect unconditionally) deletes
/// the sentinel here and this case goes red.
#[test]
fn the_collector_defers_while_another_run_is_alive() {
    let (survived, reading) = collect_beside("clear-scratch-defers", "999999\n");
    assert!(survived, "a live run's scratch was collected under it");
    assert_eq!(reading, format!("{COLLECTED}=0"));
}

/// ANTI-VACUITY: a collector that never collects passes the case above. Alone,
/// it must still take the previous run's entries.
#[test]
fn the_collector_collects_when_it_is_alone() {
    let (survived, reading) = collect_beside("clear-scratch-alone", "");
    assert!(
        !survived,
        "a lone run left the previous run's scratch behind"
    );
    assert_eq!(reading, format!("{COLLECTED}=1"));
}

/// A RUN'S SCRATCH OUTLIVES ANOTHER RUN'S REAP FOR AS LONG AS ITS CASES DO, AND
/// NOT ONE MOMENT LONGER (CLOUD-2789).
///
/// A second process holds `run-other.lock` shared, as a live case of that run
/// does, and a reap from `run-mine` must leave `run-other` whole; once the
/// holder exits, the next reap takes the directory and its lock file. The
/// holder is waited on by its own line and ended by closing its stdin, never by
/// a clock. Linux only: `flock(1)` is the other process.
///
/// Fails by: the reap removing an entry whose lock it did not take (the first
/// assertion), or never removing a finished run's (the second).
#[test]
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the other run is a real process holding a real advisory lock, which an in-process holder in the reaping thread could not contend"
)]
fn a_live_runs_scratch_survives_another_runs_reap() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let parent = crate::common::scratch("reap-live-run");
    let sentinel = parent.join("run-other").join("sentinel");
    std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
    std::fs::write(&sentinel, "").unwrap();
    let lock = parent.join(format!("run-other{}", crate::common::RUN_LOCK));
    let mut holder = std::process::Command::new("flock")
        .arg("-s")
        .arg(&lock)
        .args(["sh", "-c", "echo held; exec cat"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start the live run's holder");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(holder.stdout.take().expect("piped")),
        &mut line,
    )
    .expect("read the holder's line");
    assert_eq!(line.trim(), "held", "the holder took its lock");

    crate::common::reap_finished(&parent, "run-mine");
    let alive = sentinel.exists();

    drop(holder.stdin.take());
    let _ = holder.wait();
    crate::common::reap_finished(&parent, "run-mine");

    assert!(alive, "a live run's scratch was reaped under it");
    assert!(
        !sentinel.exists() && !lock.exists(),
        "a finished run's scratch and lock were left behind"
    );
}

/// An entry with no lock beside it predates the lock or is a stray, and is
/// reaped; the reaping run's own directory never is.
///
/// Fails by: a lockless entry kept forever, which is the CLOUD-1879 growth, or
/// a run reaping itself.
#[test]
fn a_lockless_entry_is_reaped_and_the_reapers_own_run_is_not() {
    let parent = crate::common::scratch("reap-lockless");
    let stray = parent.join("from-before-the-lock").join("sentinel");
    let own = parent.join("run-mine").join("sentinel");
    for path in [&stray, &own] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
    crate::common::reap_finished(&parent, "run-mine");
    assert!(!stray.exists(), "a lockless entry was left behind");
    assert!(own.exists(), "the reaping run took its own scratch");
}

/// Whether another process can take `lock` exclusively right now.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the question is whether ANOTHER process can take the lock, so another process asks"
)]
fn free_elsewhere(lock: &std::path::Path) -> bool {
    std::process::Command::new("flock")
        .args(["-x", "-n"])
        .arg(lock)
        .arg("true")
        .status()
        .expect("run flock")
        .success()
}

/// Every nextest run reports every failure, whichever caller forgot the flag.
///
/// The windows, macos and musl legs call `cargo nextest run --workspace` bare,
/// and nextest's default fail-fast stopped the macos leg at 2 failures with
/// 1,814 cases never run — one defect surfaced per CI round. The setting lives
/// in the default profile so it binds every invocation at once.
///
/// MUTANT: deleting `fail-fast = false` from `[profile.default]` reds this case.
#[test]
fn the_default_profile_never_fails_fast() {
    let text = std::fs::read_to_string(crate::common::at_root(".config/nextest.toml"))
        .expect("nextest.toml");
    let config: toml::Table = text.parse().expect("nextest.toml parses");
    assert_eq!(
        config["profile"]["default"].get("fail-fast"),
        Some(&toml::Value::Boolean(false)),
        "`[profile.default] fail-fast = false` is what makes a CI leg report every failure"
    );
}

/// NO PROFILE RETRIES A FAILURE (CLOUD-2789).
///
/// A retry passes a case whose result depends on load, timing or another run's
/// files on its second draw, so the flake is never seen and the gate built on
/// the suite decides by luck. `default` must say `retries = 0` itself, since
/// nextest's own default could change under it, and every other profile must
/// say 0 or inherit `default`'s. The tasks and CI must not raise it either.
///
/// Fails by: a profile, `NEXTEST_RETRIES` or a `--retries` flag naming any
/// retry count above 0.
#[test]
fn no_profile_retries_a_failure() {
    let text = std::fs::read_to_string(crate::common::at_root(".config/nextest.toml"))
        .expect("nextest.toml");
    let config: toml::Table = text.parse().expect("nextest.toml parses");
    let profiles = config["profile"].as_table().expect("a profile table");
    assert_eq!(
        profiles["default"].get("retries"),
        Some(&toml::Value::Integer(0)),
        "`[profile.default] retries = 0` is stated, not left to nextest's default"
    );
    for (name, profile) in profiles {
        let retries = profile.get("retries");
        assert!(
            retries.is_none() || retries == Some(&toml::Value::Integer(0)),
            "[profile.{name}] retries = {retries:?}"
        );
    }
    for file in ["mise.toml", ".github/workflows/ci.yml"] {
        let text = std::fs::read_to_string(crate::common::at_root(file)).expect(file);
        assert!(
            !text.contains("NEXTEST_RETRIES") && !text.contains("--retries"),
            "{file} raises nextest's retry count"
        );
    }
}

#[test]
fn the_parent_survives_its_own_collection() {
    // The collector removes the parent and recreates it. Recreating is not
    // optional: `common::scratch` joins onto this directory, so a collector that
    // deleted without recreating would take every fixture in the run with it —
    // and would do so only on the first run after a clean checkout, which is the
    // worst possible time to discover it.
    let parent = parent();
    assert!(
        parent.is_dir(),
        "the scratch parent {} must exist after collection — `common::scratch` joins onto it",
        parent.display()
    );
}

/// EVERY FIXTURE UNDER `target/` IS IN ITS RUN'S OWN SCRATCH (CLOUD-2789).
///
/// A run's scratch is safe from every other run only because it lives in
/// `run-<id>` under a lock its live cases hold (`common::target_tmp`). A case
/// that joined onto `CARGO_TARGET_TMPDIR` itself would write beside every run,
/// where no lock guards it and a reaper takes it as a stray mid-case: the
/// flake this design removed, regrown one call site at a time. So the variable
/// is read in exactly two places: the door, and the case asserting the parent.
///
/// Fails by: any other source naming the variable as a string literal, the
/// spelling `env!`, `var` and `var_os` all need.
#[test]
fn only_the_door_reads_the_target_tmpdir() {
    let allowed = ["tests/it/common/mod.rs", "tests/it/scratch_hygiene.rs"];
    let readers: Vec<String> = crate::common::rust_sources()
        .into_iter()
        .filter(|path| !allowed.iter().any(|door| path.ends_with(door)))
        .filter(|path| {
            std::fs::read_to_string(path).is_ok_and(|text| reads_the_target_tmpdir(&text))
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        readers.is_empty(),
        "these read CARGO_TARGET_TMPDIR around `common::target_tmp`, so their \
         fixtures sit outside any run's lock: {readers:?}"
    );
}

/// Whether `source` reads cargo's target tmpdir variable: names it quoted.
fn reads_the_target_tmpdir(source: &str) -> bool {
    source.contains(concat!("\"CARGO_TARGET_", "TMPDIR\""))
}

/// The reader the gate above stands on: a quoted read is caught in each
/// spelling, and prose naming the variable in backticks is not.
///
/// Fails by: the reader matching nothing (every gate above passes vacuously)
/// or matching prose (every doc mention becomes a finding).
#[test]
fn the_tmpdir_reader_tells_a_read_from_a_mention() {
    for read in [
        concat!("env!(\"CARGO_TARGET_", "TMPDIR\")"),
        concat!("std::env::var(\"CARGO_TARGET_", "TMPDIR\")"),
        concat!("std::env::var_os(\"CARGO_TARGET_", "TMPDIR\")"),
    ] {
        assert!(reads_the_target_tmpdir(read), "{read}");
    }
    assert!(!reads_the_target_tmpdir(
        "/// cargo's `CARGO_TARGET_TMPDIR` is integration-only"
    ));
}
