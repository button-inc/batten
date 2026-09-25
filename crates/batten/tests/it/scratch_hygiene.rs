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

/// What the setup script publishes: how many entries it removed.
const COLLECTED: &str = "BATTEN_SCRATCH_COLLECTED";

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
/// `cargo-nextest` pids. Returns whether the sentinel survived and the count the
/// collector published.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is the shell command nextest runs, so asserting it means running `sh`"
)]
fn collect_beside(name: &str, others: &str) -> (bool, String) {
    let root = crate::common::scratch(name);
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("pgrep");
    std::fs::write(&stub, format!("#!/bin/sh\nprintf '%s' '{others}'\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sentinel = root.join("target/tmp/sentinel");
    std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
    std::fs::write(&sentinel, "").unwrap();
    let published = root.join("nextest-env");
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(collector_command())
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("NEXTEST_ENV", &published)
        .env("PATH", path)
        .status()
        .expect("run the collector");
    assert!(status.success(), "the collector must exit 0");
    let reading = std::fs::read_to_string(&published).unwrap_or_default();
    (sentinel.exists(), reading.trim().to_owned())
}

/// CLOUD-1912: `verify` runs several nextest invocations at once, and a later
/// run's wipe deleted a live case's `current_dir` in an earlier one. With another
/// run alive the collector must leave the parent alone.
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

// --- the collector must not delete a concurrent run's scratch -----------------
//
// `verify` runs nextest more than once at a time — `test:cargo` beside seven
// narrow lanes — and the setup script runs at the start of each. The first
// version wiped the whole parent, so the lane that started last deleted the
// fixtures the others were using: `config_schema::every_verb_that_reads_config_
// reports_a_too_old_build` failed on `verify` with `run batten: NotFound`, its
// working directory gone. The cases below run the DECLARED command, read out of
// `.config/nextest.toml`, over a seeded parent — the same "assert the run, not
// the config" this file's header argues for, applied to what the run removes.

/// The `clear-scratch` command exactly as `.config/nextest.toml` declares it.
///
/// `cfg(unix)` with its only callers: the command is `sh` and the liveness probe
/// is `kill -0`, so the cases that run it are Unix-only, and an uncalled helper
/// is a denied warning on the Windows type-check (`cross-check`, CLOUD-397).
#[cfg(unix)]
fn declared_collector() -> String {
    let text = std::fs::read_to_string(crate::common::at_root(".config/nextest.toml"))
        .expect("read the nextest config");
    let config: toml::Value = toml::from_str(&text).expect("the nextest config parses");
    config["scripts"]["setup"]["clear-scratch"]["command"]
        .as_str()
        .expect("clear-scratch declares a command string")
        .to_owned()
}

/// A pid no process holds: one spawned, reaped, and so gone.
#[cfg(unix)]
fn a_dead_pid() -> u32 {
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject is a shell script's liveness probe, so the fixture needs a pid that provably belonged to a finished process"
    )]
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a process to outlive");
    let pid = child.id();
    child.wait().expect("reap it");
    pid
}

/// Seed a scratch parent under `root/tmp` and run the declared collector over it
/// with `lane` as the invocation's lane. Returns what the collector published.
#[cfg(unix)]
fn collect(root: &std::path::Path, lane: Option<&str>) -> String {
    let env_file = root.join("nextest-env");
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: the subject IS the declared shell command, so exercising it means running it"
    )]
    let mut command = std::process::Command::new("sh");
    command
        .arg("-c")
        .arg(declared_collector())
        .env("CARGO_TARGET_DIR", root)
        .env("NEXTEST_ENV", &env_file)
        .env_remove("BATTEN_TEST_SCRATCH_LANE");
    if let Some(lane) = lane {
        command.env("BATTEN_TEST_SCRATCH_LANE", lane);
    }
    let output = command.output().expect("run the collector");
    assert!(
        output.status.success(),
        "the collector must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_to_string(env_file).expect("the collector publishes a reading")
}

#[cfg(unix)]
fn seed(root: &std::path::Path) -> (String, String, String, String, String) {
    let live = format!("fixture.lane-narrow-{}", std::process::id());
    let dead = format!("fixture.lane-narrow-{}", a_dead_pid());
    let staging = format!("git-init-template-1-2.staging-{}", a_dead_pid());
    let template = "git-init-template-1-2".to_owned();
    let stale = "a-previous-runs-fixture".to_owned();
    for name in [&live, &dead, &staging, &template, &stale] {
        std::fs::create_dir_all(root.join("tmp").join(name).join("inner"))
            .expect("seed a scratch entry");
    }
    (live, dead, staging, template, stale)
}

#[cfg(unix)]
#[test]
fn the_default_run_spares_a_live_lane_and_the_shared_template() {
    let root = crate::common::scratch("hygiene-default-run");
    let (live, dead, staging, template, stale) = seed(&root);

    let published = collect(&root, None);

    let tmp = root.join("tmp");
    assert!(
        tmp.join(&live).is_dir(),
        "a live lane's fixtures must survive"
    );
    assert!(
        tmp.join(&template).is_dir(),
        "the shared template every run copies from must survive"
    );
    assert!(
        !tmp.join(&dead).exists(),
        "a dead lane's leftovers are collected"
    );
    assert!(
        !tmp.join(&staging).exists(),
        "a dead builder's staging dir is collected"
    );
    assert!(
        !tmp.join(&stale).exists(),
        "a previous run's fixture is collected"
    );
    assert_eq!(published.trim(), format!("{COLLECTED}=3"));
}

#[cfg(unix)]
#[test]
fn a_lane_run_collects_nothing() {
    // A lane cannot know what the concurrent `test:cargo` still holds open, and
    // its own names are pid-qualified, so it has nothing it may safely remove.
    let root = crate::common::scratch("hygiene-lane-run");
    let (live, dead, staging, template, stale) = seed(&root);

    let published = collect(&root, Some("narrow"));

    let tmp = root.join("tmp");
    for name in [&live, &dead, &staging, &template, &stale] {
        assert!(tmp.join(name).is_dir(), "a lane run removed {name}");
    }
    assert_eq!(published.trim(), format!("{COLLECTED}=0"));
}
