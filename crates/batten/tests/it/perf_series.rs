//! `batten perf measure` and `batten perf record` over the compiled binary —
//! CLOUD-207 and CLOUD-172, ported off `mise-tasks/perf.sh` and
//! `mise-tasks/perf-record.sh` under CLOUD-1753.
//!
//! # What a unit case cannot settle
//!
//! `record_series` is pure over its string, and its own cases cover the stray
//! line and the empty input. What they cannot show is that the VERB refuses off
//! trunk before reading stdin at all, that the note lands on `refs/notes/perf`
//! keyed to HEAD, that a second measurement of one commit APPENDS rather than
//! replaces, or that the record line `perf measure` prints is the one
//! `record tool perf-p95` reads. Each is a property of the compiled binary and
//! of a real repository.
//!
//! # THE APPEND CASE IS THE ONE THAT MATTERS
//!
//! A replace and an append are byte-identical on a commit measured once, so a
//! suite that only ever records one sample cannot tell them apart — and the
//! defect only shows up months later as a series with one reading per commit
//! where there should be two. `a_second_measurement_appends_rather_than_replacing`
//! is the case that sees it.
//
// carried: mise-tasks/perf.sh crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf
// carried: tests/perf-record.bats crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: mise-tasks/perf-record.sh crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
//
// carried: "MAIN ONLY, and this is a refusal rather than a convention" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "appending rather than replacing: a commit sampled twice keeps both readings" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "THE LABEL IS LOAD-BEARING — metric= guards against reading a wall-clock series as instruction counts" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "only records — a stray line would enter the series as a datum nothing can parse" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "its own ref, not refs/notes/commits: a series is not a comment" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "a pointer, never the payload: the ref and the commit" crates/batten/src/perf.rs kind:verb crates/batten/tests/it/perf_series.rs runs:mise+run+perf-record
// carried: "one KEY=VALUE record per path on stdout and nothing else" crates/batten/src/perf.rs
// carried: "a failed arm writes NO records" crates/batten/src/perf.rs
// carried: "the wired path is DERIVED from the settings file, selected by NAME rather than position" crates/batten/src/perf.rs
// changed: "exit 0 / 1 refuses off trunk / 2 could not look" crates/batten/src/perf.rs the shell corpus INVERTS the engine's table; off-trunk is a `Violation` (2) because the caller's request was wrong, and an unreadable input is `Internal` (3) because the engine could not look
// changed: "git notes append" crates/batten/src/perf.rs the note is written IN PROCESS through `git::append_note` — blob, tree and commit via gix — so a notes ref is not a reason for the engine to hold a child-process boundary it otherwise does not need
// changed: "hyperfine is invoked per measurement" crates/batten/src/perf.rs `perf measure`, `perf pair` and the acquisition sweep now share ONE `bench()` invocation; the sweep previously spelled its own argv, which is the second invocation this module's header says sharing exists to prevent

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{batten, git_in, scratch, stderr, stdout, write};

use std::path::{Path, PathBuf};
use std::process::Output;

const RECORDS: &str = "path=noop p50=4.6 p95=4.9 mean=4.6 runs=5\n\
                       path=check p50=6.2 p95=6.4 mean=6.3 runs=5\n";

/// A repository whose trunk is named `main` and which carries one commit.
fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("perf-series-{name}"));
    write(&dir, "batten.toml", "version = 1\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base"]);
    dir
}

fn record(dir: &Path, input: &str) -> Output {
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["perf", "record"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn batten perf record");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(input.as_bytes())
            .expect("write records");
    }
    child.wait_with_output().expect("run batten perf record")
}

/// The note this repository carries for HEAD, or `None`.
fn note(dir: &Path) -> Option<String> {
    let head = String::from_utf8(
        std::process::Command::new("git")
            .current_dir(dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("rev-parse")
            .stdout,
    )
    .expect("utf8");
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(["notes", "--ref=perf", "show", head.trim()])
        .output()
        .expect("git notes show");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn a_measurement_on_trunk_is_recorded_and_the_pointer_names_the_ref() {
    let dir = repo("on-trunk");
    let outcome = record(&dir, RECORDS);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(outcome.status.code(), Some(0), "{answer}{cause}");
    assert!(answer.contains("refs/notes/perf"), "{answer}");
    // A POINTER, NEVER THE PAYLOAD: the ref and the commit, not the numbers.
    assert!(
        !answer.contains("p95="),
        "the numbers stay in the note: {answer}"
    );

    let stored = note(&dir).expect("a note on HEAD");
    assert!(stored.contains("metric=wall-clock"), "{stored}");
    assert!(stored.contains("path=noop"), "{stored}");
}

/// CARRIES: "a branch's numbers are not the trunk's, and a series mixing them
/// cannot be read." Off trunk is a refusal and NOTHING is written.
#[test]
fn a_measurement_off_trunk_is_refused_and_nothing_is_written() {
    let dir = repo("off-trunk");
    git_in(&dir, &["checkout", "-q", "-b", "feature"]);
    let outcome = record(&dir, RECORDS);
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(2), "{cause}");
    assert!(cause.contains("not the trunk"), "{cause}");
    assert!(note(&dir).is_none(), "nothing was written");
}

/// CARRIES: "a commit sampled twice keeps both readings instead of the second
/// silently overwriting the first. Two readings of one commit is itself the
/// noise measurement a threshold wants."
#[test]
fn a_second_measurement_appends_rather_than_replacing() {
    let dir = repo("append");
    assert_eq!(record(&dir, RECORDS).status.code(), Some(0));
    assert_eq!(
        record(&dir, "path=noop p50=9.9 p95=9.9 mean=9.9 runs=5\n")
            .status
            .code(),
        Some(0)
    );
    let stored = note(&dir).expect("a note on HEAD");
    assert_eq!(
        stored.matches("metric=").count(),
        2,
        "both readings are kept: {stored}"
    );
    assert!(
        stored.contains("p95=4.9") && stored.contains("p95=9.9"),
        "{stored}"
    );
}

/// CARRIES: "a stray line would enter the series as a datum nothing can parse."
#[test]
fn a_line_that_is_not_a_record_is_refused() {
    let dir = repo("stray");
    let outcome = record(
        &dir,
        "path=noop p50=4 p95=5 mean=4 runs=5\nBuild finished.\n",
    );
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(3), "{cause}");
    assert!(note(&dir).is_none(), "nothing was written");
}

/// Empty stdin is could-not-look, never a silent empty note that later reads as
/// a measurement of zero.
#[test]
fn empty_input_is_refused_rather_than_recording_silence() {
    let dir = repo("empty");
    let outcome = record(&dir, "");
    let cause = stderr(&outcome);
    assert_eq!(outcome.status.code(), Some(3), "{cause}");
    assert!(note(&dir).is_none(), "nothing was written");
}

/// CARRIES: "THE LABEL IS LOAD-BEARING" — a later reader comparing a wall-clock
/// series against an instruction-count one would read the instrument change as a
/// regression, so the metric travels with every entry.
#[test]
fn the_metric_and_runner_are_stamped_into_the_record() {
    let dir = repo("stamp");
    let mut command = batten();
    command
        .current_dir(&dir)
        .args(["perf", "record"])
        .env("BENCH_METRIC", "instructions")
        .env("BENCH_RUNNER", "test-runner")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(RECORDS.as_bytes())
            .expect("write");
    }
    let outcome = child.wait_with_output().expect("run");
    assert_eq!(outcome.status.code(), Some(0), "{}", stderr(&outcome));

    let stored = note(&dir).expect("a note on HEAD");
    assert!(stored.contains("metric=instructions"), "{stored}");
    assert!(stored.contains("runner=test-runner"), "{stored}");
}

/// The series lives on its OWN ref: the default notes ref is what a contributor
/// is most likely to have local edits on, and a series is not a comment.
#[test]
fn the_series_is_not_written_to_the_default_notes_ref() {
    let dir = repo("own-ref");
    assert_eq!(record(&dir, RECORDS).status.code(), Some(0));
    let default = std::process::Command::new("git")
        .current_dir(&dir)
        .args(["notes", "show", "HEAD"])
        .output()
        .expect("git notes show");
    assert!(!default.status.success(), "refs/notes/commits is untouched");
}

/// The retired programs are gone and the task names their workflow uses survive.
#[test]
fn the_retired_programs_are_gone_and_their_task_names_survive() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    for path in [
        "mise-tasks/perf.sh",
        "mise-tasks/perf-record.sh",
        "tests/perf-record.bats",
    ] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    for declared in [r#"[tasks."perf"]"#, r#"[tasks."perf-record"]"#] {
        assert!(
            tasks.contains(declared),
            "{declared} is declared rather than auto-discovered, because perf.yml names it"
        );
    }
    assert!(tasks.contains("perf measure"), "and it calls the successor");
    assert!(tasks.contains("perf record"), "and so does the series task");
}
