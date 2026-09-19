//! `test judge never` over the compiled binary and the real producer (CLOUD-418,
//! CLOUD-831, CLOUD-1717).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! `policy/evaluator-io-probe.rego` carries five load-time cases and every one
//! fabricates its input with `with input as`, which is the shape
//! `rules/policy-modules.md` warns about.
//!
//! # And why the PRODUCER's reading is driven here
//!
//! Three of the dying suite's five cases are about how the probe build's output
//! is READ, not about the verdict that follows: a build that passed, one that
//! failed to compile, and one where the named test never ran. Those three are
//! the whole substance — the module's half is two `in` tests — and the middle one
//! is the arm a gate written to the obvious shape gets wrong, because a non-zero
//! exit from `cargo test` means a compile error just as readily as a falsified
//! assertion.
//!
//! Those three are now pinned where they belong: `crates/batten/src/probe_verdict.rs`
//! carries the classification and asserts all of them — plus two the retired
//! program never had, an unindented occurrence of the name and a longer name
//! containing it — in its own `#[cfg(test)] mod tests`, over fabricated
//! `(status, log)` pairs no build could be made to produce.
//!
//! What stays HERE is the half a unit test cannot reach: that the engine carries
//! that reading through `record derive` into a record the real module then
//! refuses over. The `--input` seam makes it drivable without a two-minute
//! rebuild per case, exactly as `EVALUATOR_IO_PROBE_CMD` did for the retired
//! program.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/evaluator-io-check.sh policy/evaluator-io-probe.rego kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: tests/evaluator-io-check.bats policy/evaluator-io-probe.rego kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "a probe build in which the test PASSES is the finding, not a pass" crates/batten/src/probe_verdict.rs kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "a probe build in which the test FAILS is the pass" crates/batten/src/probe_verdict.rs kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "a probe build that failed to COMPILE is could-not-look, not the pass" crates/batten/src/probe_verdict.rs kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "a probe build where the named test never ran is could-not-look" crates/batten/src/probe_verdict.rs kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
// carried: "the probe build's own output never reaches the gate's output" crates/batten/src/probe_verdict.rs kind:mechanism crates/batten/tests/it/evaluator_io_probe.rs
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

// --- the producer's reading, over the real verb ---------------------------------

/// Drive the REAL reading the producer runs, through the REAL verb.
///
/// `crates/batten/src/probe_verdict.rs` is the one authority on the three
/// branches, and its own `#[cfg(test)] mod tests` asserts them directly over
/// fabricated `(status, log)` pairs — that is where the classification is
/// pinned, because a unit test can produce an arbitrary pair and a build cannot.
///
/// What THIS tier adds is the half a unit test cannot reach: that the engine
/// carries the reading all the way to a record a module then refuses over. The
/// `--input` seam is what makes that drivable without a two-minute rebuild per
/// case, exactly as `EVALUATOR_IO_PROBE_CMD` did for the retired program.
fn derive(dir: &std::path::Path, status: i32, log: &str) -> std::process::Output {
    run_with_stdin(
        dir,
        &[
            "record",
            "derive",
            "evaluator-io-probe",
            "--input",
            &format!("status={status}"),
            "--input",
            "test=no_evaluator_feature_admits_io",
        ],
        log,
    )
}

#[test]
fn the_verb_derives_a_green_probe_into_the_finding() {
    // END TO END, and it is the arm no unit test reaches: a probe build that
    // SUCCEEDED is derived, written, read back by the real module, and refused.
    let dir = repo("derive-passed");
    let written = derive(&dir, 0, "");
    assert!(
        written.status.success(),
        "the derivation lands: {}",
        String::from_utf8_lossy(&written.stderr)
    );

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "a green probe is the finding\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn the_verb_derives_a_compile_failure_into_could_not_look() {
    // THE ARM A GATE WRITTEN TO THE OBVIOUS SHAPE GETS WRONG, carried all the
    // way through: non-zero, no harness line, and the engine must still refuse
    // rather than read the exit code as the discrimination it wanted.
    let dir = repo("derive-unread");
    let written = derive(&dir, 101, "error[E0432]: unresolved import\n");
    assert!(written.status.success(), "the derivation lands");

    let decided = run(&dir, &["check"]);
    assert_eq!(
        decided.status.code(),
        Some(2),
        "could not look is loud, never the pass\n{}",
        String::from_utf8_lossy(&decided.stderr)
    );
}

#[test]
fn the_verb_derives_a_real_failure_into_the_pass() {
    let dir = repo("derive-failed");
    let harness = "failures:\n    no_evaluator_feature_admits_io\n\ntest result: FAILED. 0 passed; 1 failed\n";
    let written = derive(&dir, 101, harness);
    assert!(written.status.success(), "the derivation lands");

    let quiet = run(&dir, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "it failed, which is the pass\n{}",
        String::from_utf8_lossy(&quiet.stderr)
    );
}

/// POINTER-ONLY THROUGH THE WHOLE PATH (rule 4). The unit test asserts the
/// verdict carries no log byte; this asserts the RECORD does not either, which
/// is the claim that matters — the record is a file on disk a module reads.
#[test]
fn no_byte_of_the_probe_log_reaches_the_record() {
    let dir = repo("derive-noisy");
    let written = derive(&dir, 101, "SECRET_MODULE_BODY\nerror: build failed\n");
    assert!(written.status.success(), "the derivation lands");

    // Every byte the engine wrote under the scratch repository's git dir,
    // walked rather than guessed at: the record's exact path is
    // `recorder::record_path`'s business, and a test naming it would be a
    // second authority over where records live.
    let mut stored = String::new();
    let mut pending = vec![dir.join(".git")];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(body) = std::fs::read_to_string(&path) {
                stored.push_str(&body);
            }
        }
    }
    assert!(
        !stored.contains("SECRET_MODULE_BODY"),
        "no byte of the probe log reaches anything the engine wrote\n{stored}"
    );
    assert!(
        !said(&written).contains("SECRET_MODULE_BODY"),
        "nor the verb's own output\n{}",
        said(&written)
    );
}

/// A KEY THE FAMILY DOES NOT READ IS A USAGE ERROR, never a silent default.
/// A caller who misspells an input would otherwise get a clean exit from a
/// reading that ran on something else, and the record would still be written.
#[test]
fn an_input_key_the_family_does_not_read_is_a_usage_error() {
    let dir = repo("derive-unknown-input");
    let refused = run_with_stdin(
        &dir,
        &[
            "record",
            "derive",
            "evaluator-io-probe",
            "--input",
            "status=0",
            "--input",
            "test=x",
            "--input",
            "nonsense=1",
        ],
        "",
    );
    assert_eq!(
        refused.status.code(),
        Some(1),
        "an unread input is a usage error\n{}",
        said(&refused)
    );
}

/// A family with no declared reading is a usage error too, rather than a record
/// written under a name nothing reads.
#[test]
fn a_family_with_no_declared_reading_is_a_usage_error() {
    let dir = repo("derive-unknown-family");
    let refused = run_with_stdin(&dir, &["record", "derive", "no-such-family"], "");
    assert_eq!(
        refused.status.code(),
        Some(1),
        "an undeclared family is a usage error\n{}",
        said(&refused)
    );
}
