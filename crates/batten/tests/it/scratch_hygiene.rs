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

    // AND THE PARENT THIS RUN WRITES INTO IS ONE IT COVERED (CLOUD-1976). A count
    // alone passed on the musl lane while the collector took `target/tmp` and the
    // suite wrote into `target/<triple>/tmp`, which nothing ever collected.
    //
    // UNIX ONLY, and the reason is the spelling rather than the property: the
    // windows lane runs the collector under Git Bash, whose `pwd -P` answers
    // `/d/a/...` for a parent this process knows as `D:\a\...`, so the two could
    // never compare equal there however correct the collection was.
    #[cfg(unix)]
    {
        let roots = std::env::var(ROOTS).unwrap_or_default();
        let parent = parent()
            .canonicalize()
            .expect("the scratch parent resolves");
        assert!(
            std::env::split_paths(&roots).any(|root| root == parent),
            "{} is not among the roots the collector covered ({roots:?})",
            parent.display()
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

/// `command` split into the argv nextest execs — nextest splits a script's
/// command into words and runs no shell of its own, so neither does this file
/// (CLOUD-2336).
///
/// The committed command quotes with single quotes only, so that is the whole
/// grammar here; a double quote or backslash outside them panics rather than
/// being split some second way.
fn argv_of(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut started) = (false, false);
    for ch in command.chars() {
        match (quoted, ch) {
            (false, '\'') => (quoted, started) = (true, true),
            (true, '\'') => quoted = false,
            (false, blank) if blank.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (false, '"' | '\\') => {
                panic!("clear-scratch's command quotes outside single quotes: {command}")
            }
            (_, other) => {
                word.push(other);
                started = true;
            }
        }
    }
    assert!(!quoted, "clear-scratch's command leaves a quote open");
    if started {
        words.push(word);
    }
    words
}

/// Run the collector over a fixture target dir holding one sentinel entry, with
/// a stub `pgrep` first on `PATH` that reports `others` as the live
/// `cargo-nextest` pids. Returns whether the sentinel survived and the count line
/// the collector published.
fn collect_beside(name: &str, others: &str) -> (bool, String) {
    let (survived, published) = collect_seeded(name, others, &["tmp"]);
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
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the subject is the committed command nextest runs, so asserting it means spawning its argv as nextest does"
)]
fn collect_seeded(name: &str, others: &str, seeds: &[&str]) -> (Vec<bool>, String) {
    let root = crate::common::scratch(name);
    let bin = root.join("bin");
    // The stand-in as `pgrep` (`examples/stub.rs`, CLOUD-2336): it prints
    // `others`, unterminated, whatever it is asked.
    crate::common::stub_at(
        &bin.join("pgrep"),
        &serde_json::json!([{"steps": [{"stdout": others}]}]),
    );
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
        std::iter::once(bin.clone()).chain(std::env::split_paths(&crate::common::ambient_path())),
    )
    .unwrap();
    let argv = argv_of(&collector_command());
    let (program, args) = argv.split_first().expect("clear-scratch names a program");
    let status = std::process::Command::new(program)
        .args(args)
        // Closed: the stand-in `pgrep` reads its stdin whole before answering.
        .stdin(std::process::Stdio::null())
        // Named: the shell runs `pgrep` by bare name, so the stand-in's argv[0]
        // carries no directory to find its plan beside.
        .env("BATTEN_STUB_PLAN", bin.join("pgrep.plan.json"))
        .env("CARGO_TARGET_DIR", root.join("target"))
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

/// CLOUD-1976. A `--target <triple>` run's scratch parent is
/// `target/<triple>/tmp`, and the collector used to take `target/tmp` alone, so
/// the musl lane's parent grew across runs and rode the cache into the next job.
/// Alone, the collector takes both — and publishes both as covered roots.
//
// The declared mutation, in a plain comment because it is shell rather than
// prose. `.config/nextest.toml` has no `batten mutate` sweep route, so the row is
// inert under the sweep and its kill was shown by hand (CLOUD-1976):
// MUTANT collector-skips-triple-roots|s@ "$base"/\*/tmp; do@; do@|a_target_triples_scratch_is_collected_too
#[test]
fn a_target_triples_scratch_is_collected_too() {
    let (survived, published) = collect_seeded(
        "clear-scratch-triple",
        "",
        &["tmp", "x86_64-unknown-linux-musl/tmp"],
    );
    assert_eq!(
        survived,
        vec![false, false],
        "a lone run takes the native parent and the triple's alike"
    );
    assert_eq!(line_of(&published, COLLECTED), format!("{COLLECTED}=2"));
    let roots = line_of(&published, ROOTS);
    assert!(
        roots.contains("/target/tmp") && roots.contains("/target/x86_64-unknown-linux-musl/tmp"),
        "both roots are published as covered: {roots}"
    );
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
