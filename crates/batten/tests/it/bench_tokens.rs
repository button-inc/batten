//! `batten bench tokens` over the compiled binary — CLOUD-119, ported off
//! `mise-tasks/token-bench.sh` and `mise-tasks/token-bench-check.sh` under
//! CLOUD-1753.
//!
//! # The strongest evidence this port carries the decisions
//!
//! `the_committed_table_reproduces` runs the whole benchmark against this
//! repository's own fixtures and requires the result to equal the table the
//! SHELL program published, byte for byte. A port that had drifted on the
//! divisor, the rounding, the stream selection or the step ordering would differ —
//! there is no way to pass this by accident.
//!
//! # WHY THE HONESTY HALF IS NOT A REGO MODULE, stated because the first
//! # attempt was one
//!
//! It was written as `policy/token-bench-honesty.rego` and withdrawn. Its own
//! `test_` rules went green over fabricated `input.tree.lines` while the
//! ENGINE-fed path was dead: with all four `**Baseline**` lines deleted from the
//! real table, `batten check --rule` still exited 0, and an unconditional probe
//! proved the module evaluated while `count(lines)` did not hold. That is
//! exactly the class `rules/policy-modules.md` records — "a `with input as` case
//! fabricates the very shape the engine may be unable to produce" — and a gate
//! that reads clean over an artifact it never opened is worse than no gate.
//!
//! The predicate needs no projected fact: it reads one committed file that
//! `--check` already opens. So it lives beside the diff, where its input is that
//! same read and `an_unmethodical_table_is_refused` proves it fires.
//
// carried: mise-tasks/token-bench.sh crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench
// carried: mise-tasks/token-bench-check.sh crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench-check
// carried: tests/token-bench.bats crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs
//
// carried: "a committed table that reproduces exits 0" crates/batten/tests/it/bench_tokens.rs
// carried: "an edited figure is reported as drift with a pointer" crates/batten/tests/it/bench_tokens.rs
// carried: "a figure with no method line is refused" crates/batten/src/tokens.rs kind:mechanism
// carried: "a figure with no baseline is refused" crates/batten/src/tokens.rs kind:mechanism
// carried: "a not-measured capability with no stated reason is refused" crates/batten/src/tokens.rs kind:mechanism
// carried: "a not-measured capability WITH a reason passes, so the rule is not just a ban" crates/batten/src/tokens.rs kind:mechanism
// carried: "a missing table is a violation, never a quiet pass" crates/batten/tests/it/bench_tokens.rs
// carried: "the drift report is pointer-only — no fixture bytes echoed" crates/batten/tests/it/bench_tokens.rs
// carried: "a fixture file missing its .in suffix is an error, not a silent skip" crates/batten/src/tokens.rs kind:mechanism
// carried: "an arm that is not byte-stable reports not measured rather than an average" crates/batten/src/tokens.rs kind:mechanism
// carried: "the harness refuses to run without its declared method" crates/batten/src/tokens.rs kind:mechanism
// carried: tests/token-bench-check.bats crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs
//
// carried: "a missing table is refused, and named — never a pass for want of anything to read" crates/batten/tests/it/bench_tokens.rs
// carried: "THE DEFECT: a figure with no question is unmethodical, and the section is named" crates/batten/src/tokens.rs kind:mechanism
// carried: "a figure with no baseline is unmethodical" crates/batten/src/tokens.rs kind:mechanism
// carried: "a figure with no method or run count is unmethodical" crates/batten/src/tokens.rs kind:mechanism
// carried: "THE SILENT GAP: no figure and no stated reason is the worst of the three" crates/batten/src/tokens.rs kind:mechanism
// carried: "a stated reason stands in for a figure — the marker alone does not" crates/batten/src/tokens.rs kind:mechanism
// carried: "every unmethodical section is reported, not just the first" crates/batten/src/tokens.rs kind:mechanism
// carried: "a section closed by the next H2 is still judged" crates/batten/src/tokens.rs kind:mechanism
// carried: "output is pointer-only — no published prose reaches the log" crates/batten/tests/it/bench_tokens.rs
//
// carried: "it bakes in no price, no divisor, no re-run coefficient and no workload" crates/batten/src/tokens.rs
// carried: "the arithmetic is over BYTES, which are exact; a ratio is independent of the divisor" crates/batten/src/tokens.rs
// carried: "every arm runs `runs` times and is compared byte-for-byte" crates/batten/src/tokens.rs
// carried: "an arm that differs between runs carries no figure" crates/batten/src/tokens.rs
// carried: "no aggregate is published, and the refusal is printed rather than silent" crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench
// carried: "both streams are counted, because both reach the caller" crates/batten/src/tokens.rs
// carried: "the honesty gate re-reads the ARTIFACT rather than trusting the generator" crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench-check
// carried: "a figure obliges all four; a section with no figure obliges a stated reason" crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench-check
// carried: "regenerate into a scratch file: a gate that rewrites the tree it judges cannot fail twice" crates/batten/src/tokens.rs
// carried: "pointer-only: the gate names the file that drifted, never the diff body" crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs runs:mise+run+token-bench-check
// changed: "`taplo get` and `jq` read the method and the workloads" crates/batten/src/tokens.rs both are gone: the two TOML files are deserialised into types, so a malformed method is a parse error naming the file rather than an empty shell variable that silently prices everything at zero
// changed: "exit 0 pass / 1 fail" crates/batten/src/tokens.rs the port lands on the engine's table — `0` Success, `2` Violation for a drifted or unmethodical table, `3` Internal for an input it could not read

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common::{Fixture, batten, stderr, stdout};

use std::path::Path;
use std::process::Output;

/// The repository this campaign is running in — the benchmark's own fixtures
/// and method live here, so the reproduction case has a real subject.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
}

fn check(root: &Path) -> Output {
    let mut command = batten();
    command
        .current_dir(root)
        .args(["bench", "tokens", "--check"]);
    command.output().expect("run batten bench tokens --check")
}

/// THE REPRODUCTION, and it is the case that proves the port carries the
/// decisions rather than the shape.
///
/// The committed table was published by the SHELL program. A fresh run of the
/// Rust port must produce it byte for byte — so a drift in the divisor, the
/// rounding, which streams are counted, the step order or the ratio arithmetic
/// fails here, and there is no way to pass by accident.
#[test]
fn the_committed_table_reproduces() {
    let outcome = check(repo());
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "the Rust port must reproduce the table the shell program published\n{answer}{cause}"
    );
    assert!(answer.contains("reproduces"), "{answer}{cause}");
}

/// TWO RUNS AT ONCE DO NOT MEASURE EACH OTHER (review of #928).
///
/// The scratch root was a fixed `target/token-bench`, wiped on entry — so a
/// second invocation deleted the first's fixtures mid-measurement and the loser
/// reported drift. It is this suite's own tier that found it: nextest runs
/// cases in parallel processes, the two `--check` cases raced, and exactly one
/// of them failed each run while both passed when run alone.
///
/// SHOWN ABLE TO FAIL: with the fixed path restored, this case reports drift on
/// one thread or the other. A benchmark whose figure depends on what else is
/// running is the asserted-instead-of-measured claim the subject exists to
/// refuse, so the property is isolation rather than a lock.
#[test]
fn two_checks_at_once_do_not_measure_each_other() {
    let root = repo().to_owned();
    let other = std::thread::spawn(move || check(&root));
    let mine = check(repo());
    let theirs = other.join().expect("the second check ran");
    assert_eq!(
        (mine.status.code(), theirs.status.code()),
        (Some(0), Some(0)),
        "both reproduce; neither may see the other's scratch\n{}{}",
        stderr(&mine),
        stderr(&theirs)
    );
}

/// Copy `from` into `to`, recursively, files only.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the copy's directory");
    for entry in std::fs::read_dir(from).expect("read the benchmark tree") {
        let entry = entry.expect("a directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("an entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy a benchmark file");
        }
    }
}

/// THE HONESTY HALF FIRES, and this is the case the withdrawn rego module could
/// never give: it runs the engine-fed path over a table with its baselines
/// removed, rather than a fabricated input.
///
/// OVER A COPY, NEVER THE COMMITTED TABLE (CLOUD-1913). This case wrote the
/// stripped table over the real `bench/tokens/RESULTS.md` and restored it after.
/// Every concurrent reader in that window judged the damaged file: its sibling
/// `the_committed_table_reproduces` failed under `verify` with "4 published
/// figure(s) do not state their method" while passing alone, and a process
/// killed between the two writes would have left the published table damaged in
/// the tree. So the benchmark is copied into a repository of its own, the binary
/// linked beside it, and only the copy is perturbed.
#[test]
fn an_unmethodical_table_is_refused() {
    let copy = Fixture::new("bench-tokens-unmethodical").git().build();
    copy_tree(&repo().join("bench/tokens"), &copy.join("bench/tokens"));
    std::fs::create_dir_all(copy.join("target/debug")).expect("a binary directory");
    std::fs::hard_link(
        repo().join("target/debug/batten"),
        copy.join("target/debug/batten"),
    )
    .expect("link the binary under test");

    let published = copy.join("bench/tokens/RESULTS.md");
    let original = std::fs::read_to_string(&published).expect("the copied table");
    let mut stripped = String::new();
    for line in original
        .lines()
        .filter(|line| !line.starts_with("**Baseline**"))
    {
        stripped.push_str(line);
        stripped.push('\n');
    }
    assert_ne!(stripped, original, "the fixture must actually differ");
    std::fs::write(&published, &stripped).expect("perturb the copy");

    let outcome = check(&copy);
    let cause = stderr(&outcome);
    assert_eq!(
        outcome.status.code(),
        Some(2),
        "a figure with no baseline must refuse\n{cause}"
    );
    assert!(cause.contains("do not state their method"), "{cause}");
    // POINTER-ONLY: the file and the line, never the section's prose.
    assert!(cause.contains("bench/tokens/RESULTS.md:"), "{cause}");
}

/// The retired programs are gone and no caller resolves them by path.
#[test]
fn the_retired_programs_are_not_tracked() {
    let root = repo();
    for path in [
        "mise-tasks/token-bench.sh",
        "mise-tasks/token-bench-check.sh",
        "tests/token-bench.bats",
        "tests/token-bench-check.bats",
    ] {
        assert!(
            !root.join(path).exists(),
            "{path} is retired and must not be back"
        );
    }
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    assert!(
        !tasks.contains("token-bench.sh") && !tasks.contains("token-bench-check.sh"),
        "no caller resolves a retired program by path"
    );
    assert!(tasks.contains("bench tokens"), "the successor is what runs");
}

/// `taplo` and `jq` have left the benchmark path: the method and the workloads
/// are deserialised into types, so a malformed method is a parse error naming
/// the file rather than an empty shell variable that prices everything at zero.
#[test]
fn the_benchmark_reads_its_inputs_without_a_shell_toolchain() {
    let root = repo();
    let tasks = std::fs::read_to_string(root.join("mise.toml")).expect("mise.toml");
    let body = tasks
        .split("[tasks.\"token-bench\"]")
        .nth(1)
        .and_then(|rest| rest.split("[tasks.").next())
        .unwrap_or_default();
    for tool in ["taplo", "jq"] {
        assert!(
            !body.contains(tool),
            "{tool} is no longer part of pricing the benchmark: {body}"
        );
    }
}
