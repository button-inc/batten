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
// carried: tests/token-bench-check.bats crates/batten/src/tokens.rs kind:verb crates/batten/tests/it/bench_tokens.rs
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

use crate::common::{batten, stderr, stdout};

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

/// THE HONESTY HALF FIRES, and this is the case the withdrawn rego module could
/// never give: it runs over the REAL table with its baselines removed, which is
/// the engine-fed path rather than a fabricated input.
#[test]
fn an_unmethodical_table_is_refused() {
    let root = repo();
    let published = root.join("bench/tokens/RESULTS.md");
    let original = std::fs::read_to_string(&published).expect("the committed table");
    let stripped: String = original
        .lines()
        .filter(|line| !line.starts_with("**Baseline**"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(stripped, original, "the fixture must actually differ");

    std::fs::write(&published, &stripped).expect("perturb the table");
    let outcome = check(root);
    // RESTORED BEFORE ASSERTING, so a failing assertion cannot leave this
    // repository's own published table damaged.
    std::fs::write(&published, &original).expect("restore the table");

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
