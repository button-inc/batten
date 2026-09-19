//! `test judge never` over the compiled binary and the real producer (CLOUD-418,
//! CLOUD-831, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/evaluator-io-probe.rego` carries five load-time cases and every one
//! fabricates its input with `with input as`, which is the shape
//! `rules/policy-modules.md` warns about.
//!
//! # And why the PRODUCER's classification is driven here
//!
//! Three of the dying suite's five cases are about how the probe build's output
//! is READ, not about the verdict that follows: a build that passed, one that
//! failed to compile, and one where the named test never ran. Those three are
//! the whole substance — the module's half is two `in` tests — and the middle one
//! is the arm a gate written to the obvious shape gets wrong, because a non-zero
//! exit from `cargo test` means a compile error just as readily as a falsified
//! assertion.
//!
//! `EVALUATOR_IO_PROBE_CMD` is what makes that drivable without a two-minute
//! rebuild per case, and these cases use it exactly as the retired suite did.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/evaluator-io-check.sh policy/evaluator-io-probe.rego kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: tests/evaluator-io-check.bats policy/evaluator-io-probe.rego kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "a probe build in which the test PASSES is the finding, not a pass" policy/evaluator-io-probe.rego kind:mechanism
// carried: "a probe build in which the test FAILS is the pass" policy/evaluator-io-probe.rego kind:mechanism
// carried: "a probe build that failed to COMPILE is could-not-look, not the pass" policy/evaluator-io-probe.rego kind:mechanism
// carried: "a probe build where the named test never ran is could-not-look" policy/evaluator-io-probe.rego kind:mechanism
// carried: "the probe build's own output never reaches the gate's output" policy/evaluator-io-probe.rego kind:mechanism
// changed: "the refusal names the test to fix" batten.toml the retired program printed `<file> <test-name>`; the engine renders `<file> <rule-id>`, because `rules/policy-modules.md` makes the first path-bearing subject the finding's pointer whatever order the subjects are declared in. That is non-negotiable rule 5 — one output contract, no per-verb exception — so the test name moved to the `[[verdict]]` row's gloss and to the JSON channel, where a reader still meets it

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, init_repo, run, run_with_stdin, scratch, write};

/// A repository registering the real module against the declared family.
fn repo(name: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("evaluator-io-probe-{name}"));
    let module = std::fs::read_to_string("../../policy/evaluator-io-probe.rego")
        .expect("the module this tier exists for");
    write(&dir, "policy/evaluator-io-probe.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[verdict]]
id = "test judge never"
gloss = "the IO-free evaluator test stayed green with regorus's http feature on"
class = "A test green whether or not the evaluator can reach the network is not evidence that it cannot."

[[verdict.route]]
id = "test read first"
kind = "document"
target = "crates/batten/tests/policy_modules.rs"

[[verdict]]
id = "test run unread"
gloss = "the probe build exited non-zero without running the named test to a failure"
class = "Could not look: a compile error reads as a falsified assertion unless the harness line is what decides."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run evaluator-io-record"

[[rule]]
id = "test cover never"
kind = "policy"
scope = "tree"
module = "policy/evaluator-io-probe.rego"
severity = "deny"

[[record]]
record = "evaluator-io-probe"
writer = "mise run evaluator-io-record"
"#,
    );
    init_repo(&dir);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    dir
}

fn record(dir: &std::path::Path, verdict: &str) {
    let written = run_with_stdin(
        dir,
        &["record", "named", "evaluator-io-probe"],
        &format!("{verdict}\n"),
    );
    assert!(
        written.status.success(),
        "the setup write lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );
}

fn said(decided: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&decided.stdout),
        String::from_utf8_lossy(&decided.stderr)
    )
}

// --- the decision, over the engine's own projection --------------------------

#[test]
fn a_probe_build_in_which_the_test_passes_is_the_finding_not_a_pass() {
    // THE INVERSION IS THE GATE. A probe build that SUCCEEDED means the test
    // stayed green with `http` on, so it discriminates nothing.
    let dir = repo("passed");
    record(&dir, "probe passed");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a green probe is the finding\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
    // THE POINTER IS THE FILE, NOT THE TEST NAME, and that is the engine's
    // uniform output contract rather than a loss. `rules/policy-modules.md`:
    // "the first path-bearing subject becomes the finding's own pointer" — so a
    // `{path}` subject always renders in preference to an `{artifact}`, whatever
    // order they are declared in. The test name rides the JSON channel and the
    // verdict's own class; the line gives the reader the file to open.
    assert!(
        said(&decided).contains("crates/batten/tests/policy_modules.rs"),
        "and points at the file to open\n{}",
        said(&decided)
    );
}

#[test]
fn a_probe_build_in_which_the_test_fails_is_the_pass() {
    let dir = repo("failed");
    record(&dir, "probe failed");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "it failed, which is the pass\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

#[test]
fn a_probe_build_that_failed_to_compile_is_could_not_look_not_the_pass() {
    let dir = repo("unread");
    record(&dir, "probe unread");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "could not look is loud, never the pass\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn an_absent_record_says_nothing_rather_than_refusing() {
    let dir = repo("unrecorded");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is silence\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

// --- the producer's classification -------------------------------------------

/// Run the REAL reading the producer runs, over a status and a log.
///
/// `mise-tasks/probe_verdict.py` is the one authority on these three branches;
/// a copy of them here would be the second authority `cargo_graph.py` was
/// extracted to remove one gate over.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and it is the subject under test rather than a convenience: the classification of a probe build's output is what moved out of the dying program, and driving it directly is what keeps the three arms assertable without a two-minute rebuild per case"
)]
fn classify(name: &str, status: i32, log: &str) -> String {
    let dir = scratch(&format!("evaluator-io-stub-{name}"));
    write(&dir, "probe.log", log);

    let done = std::process::Command::new("python3")
        .arg("../../mise-tasks/probe_verdict.py")
        .arg(status.to_string())
        .arg(dir.join("probe.log"))
        .arg("no_evaluator_feature_admits_io")
        .output()
        .expect("the reading runs");
    assert!(
        done.status.success(),
        "the reading completes: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).trim().to_owned()
}

#[test]
fn a_probe_build_that_succeeds_classifies_as_passed() {
    assert_eq!(classify("green", 0, ""), "probe passed");
}

#[test]
fn a_probe_build_that_ran_the_named_test_to_a_failure_classifies_as_failed() {
    let harness = "failures:\n    no_evaluator_feature_admits_io\n\ntest result: FAILED. 0 passed; 1 failed\n";
    assert_eq!(classify("red", 101, harness), "probe failed");
}

#[test]
fn a_probe_build_that_failed_to_compile_classifies_as_unread() {
    // THE ARM A GATE WRITTEN TO THE OBVIOUS SHAPE GETS WRONG: non-zero, and no
    // harness line at all.
    let broken = "error[E0432]: unresolved import\n";
    assert_eq!(classify("compile", 101, broken), "probe unread");
}

#[test]
fn a_probe_build_where_the_named_test_never_ran_classifies_as_unread() {
    // A different test failed, so the harness says FAILED and the listing names
    // somebody else. Reading the exit code would call this the discrimination
    // this gate is looking for.
    let other = "failures:\n    some_other_test\n\ntest result: FAILED. 3 passed; 1 failed\n";
    assert_eq!(classify("other", 101, other), "probe unread");
}

#[test]
fn the_probe_builds_own_output_never_reaches_the_record() {
    // Pointer-only (rule 4): the probe log carries module bodies and paths, and
    // what the record receives is one token.
    let noisy = "SECRET_MODULE_BODY\nerror: build failed\n";
    let classified = classify("noisy", 101, noisy);
    assert_eq!(classified, "probe unread");
    assert!(
        !classified.contains("SECRET_MODULE_BODY"),
        "no byte of the probe log reaches the record\n{classified}"
    );
}
