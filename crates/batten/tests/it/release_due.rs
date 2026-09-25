//! `release grade early` over the compiled binary and the REAL producer
//! (CLOUD-319, CLOUD-1717).
//!
//! `[tasks.release-due-record]` is read out of `mise.toml` and run with its three
//! readings injected, so every branch — both boundaries included — is covered
//! offline with no stub for the forge. The engine then decides over the ages the
//! producer recorded. A HOLD is `check`'s exit 2 now, where the program used 1,
//! and `auto-release-land.yml` maps it accordingly; could-not-look is the
//! producer's exit 3.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/release-due.sh policy/release-due.rego kind:mechanism crates/batten/tests/it/release_due.rs
// carried: tests/release-due.bats policy/release-due.rego kind:mechanism crates/batten/tests/it/release_due.rs
// carried: "main quiet past the window is due" policy/release-due.rego kind:mechanism
// changed: "a busy main inside the max wait holds, and says what it is waiting on" policy/release-due.rego the hold is carried, as `check`'s exit 2 over `release ship early`; what it is waiting on is the class's own text, which `batten policy explain` prints, rather than a sentence of minutes composed per firing
// changed: "a hold carries no ::error:: annotation — it is the ordinary outcome" policy/release-due.rego a hold is a finding line through `check` now, which carries no `::error::` either; the case asserts the annotation is absent
// carried: "the max wait interrupts a main that never goes quiet" policy/release-due.rego kind:mechanism
// carried: "no release yet is due — nothing to wait out" policy/release-due.rego kind:mechanism
// carried: "the quiet window is inclusive at exactly 30 minutes" policy/release-due.rego kind:mechanism
// carried: "the max wait is inclusive at exactly 24 hours" policy/release-due.rego kind:mechanism
// carried: "both windows are honoured from the environment" policy/release-due.rego kind:mechanism
// changed: "a non-numeric window is exit 2, never a silent fall back to the default" mise.toml refused at the producer and never recorded, as before, but at exit 3: 2 is `check`'s hold now and the workflow reads it as "not yet", so could-not-look moved to the engine's own code for it
// changed: "an unparseable timestamp is exit 2, on either reading" mise.toml the same move as the case above: refused and unrecorded, at exit 3
// changed: "an empty last-commit reading is could-not-look, not a quiet main" mise.toml the same move: refused and unrecorded, at exit 3

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use common::{at_root, git_in, init_repo, scratch, write};

const NOW: &str = "2026-08-12T12:00:00Z";

fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("release-due-{name}"));
    let module = std::fs::read_to_string(at_root("policy/release-due.rego")).expect("the module");
    write(&dir, "policy/release-due.rego", &module);
    let verdict = |id: &str| {
        format!(
            "[[verdict]]\nid = \"{id}\"\ngloss = \"fixture\"\nclass = \"fixture\"\n\n\
             [[verdict.route]]\nid = \"task run first\"\nkind = \"command\"\n\
             target = \"mise run release-due-record\"\n\n"
        )
    };
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\nscope = [\"**\"]\n\n[[pattern]]\nid = \"whole-number\"\n\
             regex = '^[0-9]+$'\n\n{}{}\
             [[rule]]\nid = \"release grade early\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/release-due.rego\"\nseverity = \"deny\"\n\n\
             [[record]]\nrecord = \"release-due\"\nwriter = \"mise run release-due-record\"\n",
            verdict("release ship early"),
            verdict("release measure partial"),
        ),
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

/// Run the producer with the readings injected, plus any window overrides.
fn produce(dir: &Path, activity: &str, release: &str, knobs: &[(&str, &str)]) -> Output {
    let mut command = common::task_command(dir, "release-due-record");
    command
        .env("RELEASE_DUE_NOW", NOW)
        .env("RELEASE_DUE_LAST_ACTIVITY", activity)
        .env("RELEASE_DUE_LAST_RELEASE", release)
        .env_remove("RELEASE_QUIET_MINUTES")
        .env_remove("RELEASE_MAX_WAIT_HOURS")
        .stdin(Stdio::null());
    for (name, value) in knobs {
        command.env(name, value);
    }
    command.output().expect("run the producer")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce, assert it recorded, then decide: the exit code and what was said.
fn verdict(
    name: &str,
    activity: &str,
    release: &str,
    knobs: &[(&str, &str)],
) -> (Option<i32>, String) {
    let dir = repo(name);
    let produced = produce(&dir, activity, release, knobs);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    let decided = common::run(&dir, &["check", "--rule", "release grade early"]);
    (decided.status.code(), said(&decided))
}

#[test]
fn main_quiet_past_the_window_is_due() {
    let (code, text) = verdict("quiet", "2026-08-12T11:00:00Z", "2026-08-12T06:00:00Z", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_busy_main_inside_the_max_wait_holds() {
    let (code, text) = verdict("busy", "2026-08-12T11:55:00Z", "2026-08-12T06:00:00Z", &[]);
    assert_eq!(code, Some(2), "a hold: {text}");
    assert!(
        !text.contains("::error::"),
        "a hold is the ordinary outcome: {text}"
    );
}

#[test]
fn the_max_wait_interrupts_a_main_that_never_goes_quiet() {
    let (code, text) = verdict(
        "max-wait",
        "2026-08-12T11:59:00Z",
        "2026-08-11T06:00:00Z",
        &[],
    );
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn no_release_yet_is_due() {
    let (code, text) = verdict("no-release", "2026-08-12T11:59:00Z", "", &[]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn both_windows_are_inclusive_at_their_boundaries() {
    // Exactly 30 minutes quiet, and exactly 24 hours since the release.
    let (quiet, text) = verdict(
        "quiet-edge",
        "2026-08-12T11:30:00Z",
        "2026-08-12T06:00:00Z",
        &[],
    );
    assert_eq!(quiet, Some(0), "{text}");
    let (wait, text) = verdict(
        "wait-edge",
        "2026-08-12T11:59:00Z",
        "2026-08-11T12:00:00Z",
        &[],
    );
    assert_eq!(wait, Some(0), "{text}");
}

#[test]
fn both_windows_are_honoured_from_the_environment() {
    // 60 quiet minutes held under a 120-minute window, due under a 45-minute one.
    let long = [("RELEASE_QUIET_MINUTES", "120")];
    let (held, text) = verdict(
        "env-long",
        "2026-08-12T11:00:00Z",
        "2026-08-12T06:00:00Z",
        &long,
    );
    assert_eq!(held, Some(2), "{text}");
    let short = [("RELEASE_QUIET_MINUTES", "45")];
    let (due, text) = verdict(
        "env-short",
        "2026-08-12T11:00:00Z",
        "2026-08-12T06:00:00Z",
        &short,
    );
    assert_eq!(due, Some(0), "{text}");
    // And the max wait: a 1h wait makes a 6h-old release due on a busy main.
    let hour = [("RELEASE_MAX_WAIT_HOURS", "1")];
    let (wait, text) = verdict(
        "env-wait",
        "2026-08-12T11:59:00Z",
        "2026-08-12T06:00:00Z",
        &hour,
    );
    assert_eq!(wait, Some(0), "{text}");
}

#[test]
fn every_reading_the_producer_cannot_take_is_exit_3_and_records_nothing() {
    for (name, activity, release, knobs) in [
        (
            "bad-quiet",
            "2026-08-12T11:00:00Z",
            "",
            vec![("RELEASE_QUIET_MINUTES", "abc")],
        ),
        (
            "bad-wait",
            "2026-08-12T11:00:00Z",
            "",
            vec![("RELEASE_MAX_WAIT_HOURS", "1h")],
        ),
        ("bad-activity", "yesterday-ish", "", vec![]),
        ("bad-release", "2026-08-12T11:00:00Z", "not a time", vec![]),
        ("empty-activity", "", "", vec![]),
    ] {
        let dir = repo(name);
        let produced = produce(&dir, activity, release, &knobs);
        assert_eq!(
            produced.status.code(),
            Some(3),
            "{name}: {}",
            said(&produced)
        );
        let after = common::run(&dir, &["check", "--rule", "release grade early"]);
        assert_eq!(
            after.status.code(),
            Some(0),
            "{name}: nothing recorded to judge"
        );
    }
}

#[test]
fn a_release_due_record_missing_a_reading_is_torn() {
    let dir = repo("torn");
    let written =
        common::run_with_stdin(&dir, &["record", "named", "release-due"], "quiet\t1800\n");
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--rule", "release grade early"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}
