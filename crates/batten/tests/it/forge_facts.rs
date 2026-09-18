//! `input.tree.forge`, over the compiled binary (CLOUD-1154).
//!
//! **The anti-forgery case is what this family lives or dies on.** A verdict
//! taken against a different commit is not evidence about this one, so
//! `a_record_keyed_to_another_sha_does_not_answer` is the case the row's
//! acceptance names — without it a gate could inherit a green reading from a
//! commit nobody asked about, reporting a judgement that was never made.
//!
//! The engine reads a record something else wrote and **opens no socket**;
//! `evaluator-io-check` is the gate on that and this suite does not duplicate it.
//! What it does assert is that the read reaches a module at all, which a
//! `with input as` case cannot (CLOUD-845, CLOUD-857).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{at_root, batten, git_in, init_repo, run_with_stdin, scratch, stderr, stdout, write};

/// The sha the row declares, and the one a record must be keyed to.
const DECLARED_SHA: &str = "1111111111111111111111111111111111111111";
/// A different commit entirely — the forgery the keying refuses.
const OTHER_SHA: &str = "2222222222222222222222222222222222222222";

fn config(sha: &str) -> String {
    format!(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"
forge = ["{sha}"]

[[verdict]]
id = "forge green probe"
gloss = "the declared sha's record says the required check passed"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe green probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "forge red probe"
gloss = "the declared sha's record says the required check failed"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe red probe"
kind = "document"
target = "probe.rego"
"#
    )
}

/// Two predicates over one key, and the pair is what discriminates.
///
/// A single "did I read a verdict" rule would be green whether the engine handed
/// back this sha's record or another's, which is the forgery the keying exists to
/// refuse.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-green"

rules contains "probe-red"

violation contains {
	"rule": "probe-green",
	"verdict": "forge green probe",
} if {
	is_object(input.tree.forge)
	some checks in input.tree.forge
	checks.final == "success"
}

violation contains {
	"rule": "probe-red",
	"verdict": "forge red probe",
} if {
	is_object(input.tree.forge)
	some checks in input.tree.forge
	checks.final == "failure"
}

test_a_green_record_fires if {
	some v in violation with input as {"tree": {"forge": {"abc": {"final": "success"}}}}
	v.rule == "probe-green"
}

test_a_red_record_fires_the_other_class if {
	some v in violation with input as {"tree": {"forge": {"abc": {"final": "failure"}}}}
	v.rule == "probe-red"
}

test_no_record_fires_neither if {
	count(violation) == 0 with input as {"tree": {"forge": {}}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"forge": null}}
}
"#;

/// A repository whose row declares `DECLARED_SHA`, plus a record written under
/// `record_sha` — which the cases vary to make the keying observable.
fn fixture(name: &str, record_sha: Option<&str>, conclusion: &str) -> PathBuf {
    let dir = scratch(&format!("forge-facts-{name}"));
    write(&dir, "batten.toml", &config(DECLARED_SHA));
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    if let Some(sha) = record_sha {
        // The producer's half, written here rather than fetched: the engine
        // reads a record something else wrote, which is the entire shape of the
        // family and why it needs no socket.
        let store = dir.join(".git").join("batten-forge");
        std::fs::create_dir_all(&store).expect("record store");
        std::fs::write(store.join(sha), format!("final {conclusion}\n")).expect("write record");
    }
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

/// The committed config, pointed at the REAL module rather than the probe.
///
/// The probe above pins the FACT — that the engine builds `input.tree.forge` and
/// keys it to the declared sha. It installs no module of this repository's, which
/// is exactly what `#MUTANT-OWNER CLOUD-845` declares on the suite: no case in it
/// can turn red under a mutation of the shipping predicate.
///
/// So the cases below install the real thing. They are the second tier
/// `rules/policy-modules.md` demands and the only one a `#MUTANT` row over
/// `forge-verdict-required` can name honestly.
fn real_config(sha: &str) -> String {
    format!(
        r#"version = 1

[[rule]]
id = "forge check red"
kind = "policy"
scope = "tree"
module = "forge-verdict-required.rego"
severity = "deny"
forge = ["{sha}"]

[[verdict]]
id = "forge check red"
gloss = "the forge judged this commit and its fan-in check did not pass"
class = "A fixture copy of the committed row; the id is what the module raises."

[[verdict.route]]
id = "module read first"
kind = "document"
target = "forge-verdict-required.rego"
"#
    )
}

/// A repository carrying the real module and a record whose body is `record`.
///
/// THE WHOLE RECORD rather than one conclusion, because the anti-vacuity case
/// needs a second line — a leaf skipping beside a fan-in that genuinely failed.
fn real_fixture(name: &str, record: &str) -> PathBuf {
    let dir = scratch(&format!("forge-real-{name}"));
    write(&dir, "batten.toml", &real_config(DECLARED_SHA));
    // THE REAL MODULE, read off the tree rather than restated. A fixture copy
    // would drift from the thing that ships, which is the whole failure this
    // tier exists to catch one level up.
    let module = std::fs::read_to_string(at_root("policy/forge-verdict-required.rego"))
        .expect("read the shipping module");
    write(&dir, "forge-verdict-required.rego", &module);
    // `init_repo`, never a `git init` fork: main's fixture-fork ratchet
    // (`test add duplicate`) prices every ADDED fork, and under
    // `CARGO_TARGET_TMPDIR` this copies the published template at zero forks.
    init_repo(&dir);
    let store = dir.join(".git").join("batten-forge");
    std::fs::create_dir_all(&store).expect("record store");
    std::fs::write(store.join(DECLARED_SHA), record).expect("write record");
    dir
}

#[test]
fn a_skipped_fan_in_is_not_refused() {
    // CLOUD-1831, over the compiled binary. A draft's checks are stamped
    // `skipped`; `record-verdicts` writes that record; this row used to refuse
    // it, and readying the pull request — the only thing that makes `final`
    // report anything else — is downstream of the `land` the refusal stops.
    //
    // Measured on #973 and again on #974, where it cost four laps.
    let dir = real_fixture("skipped", "final skipped\n");
    let outcome = check(&dir);
    assert!(
        outcome.status.success(),
        "a declined fan-in was read as a refusal\n{}{}",
        stdout(&outcome),
        stderr(&outcome)
    );
}

#[test]
fn a_cancelled_fan_in_is_not_refused() {
    // The same class one cause over: a run superseded before it could answer.
    // CLOUD-363 fixed this same word for `ci-wait` and `checks-green`.
    let dir = real_fixture("cancelled", "final cancelled\n");
    let outcome = check(&dir);
    assert!(
        outcome.status.success(),
        "a cancelled fan-in was read as a refusal\n{}{}",
        stdout(&outcome),
        stderr(&outcome)
    );
}

#[test]
fn a_failed_fan_in_beside_a_skipped_leaf_is_still_refused() {
    // THE HALF THAT KEEPS THE FIX FROM BECOMING CLOUD-900's FALSE PASS, and
    // without it the two cases above are satisfied by a module that refuses
    // nothing. The fan-in genuinely failed; a leaf skipping alongside it changes
    // nothing about that.
    let dir = real_fixture("failed-with-skip", "final failure\nwindows skipped\n");
    let outcome = check(&dir);
    assert!(
        !outcome.status.success(),
        "a failed fan-in stopped being refused\n{}{}",
        stdout(&outcome),
        stderr(&outcome)
    );
}

#[test]
fn a_declared_sha_reads_its_own_record() {
    // THE POSITIVE. Before this family a tree-scoped module asking about a
    // check-run read undefined, Rego took that as *does not hold*, and the gate
    // was byte-identical to a clean tree on the decision surface.
    let dir = fixture("green", Some(DECLARED_SHA), "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-green"),
        "the declared sha's record must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_projection_carries_the_recorded_conclusion() {
    // THE POSITIVE CONTROL (CLOUD-418). Without it the case above passes over a
    // projection that emitted `success` unconditionally — and telling `success`
    // from `failure` is the entire question a landing gate asks.
    let dir = fixture("red", Some(DECLARED_SHA), "failure");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-red"),
        "the record's own conclusion must decide\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-green"),
        "the projection must carry the recorded value, not a constant\n{answer}{cause}"
    );
}

#[test]
fn a_record_keyed_to_another_sha_does_not_answer() {
    // THE ANTI-FORGERY CASE, and the one the row's acceptance names. The record
    // exists, is readable, and says `success` — it is simply keyed to a different
    // commit. A gate that answered from it would inherit a green verdict from a
    // commit nobody asked about, which is a judgement that was never made
    // reported as one that was.
    let dir = fixture("other-sha", Some(OTHER_SHA), "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a record keyed to another sha must not answer\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-green"), "{answer}{cause}");
    assert!(!answer.contains("probe-red"), "{answer}{cause}");
}

#[test]
fn no_record_at_all_is_could_not_look() {
    // COULD-NOT-LOOK, told apart from a clean verdict by the only means that
    // discriminates: the control above fires `probe-red` on a record that says
    // `failure`, and this fires nothing, because nothing was read.
    //
    // Collapsing them would report green on a commit nothing ever judged — the
    // dead gate, on the surface that decides whether work lands.
    let dir = fixture("no-record", None, "success");
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an absent record must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-green"), "{answer}{cause}");
    assert!(!answer.contains("probe-red"), "{answer}{cause}");
}

// --- the PRODUCER half (CLOUD-1265) -----------------------------------------
//
// Every case above plants the record by hand, which is right for asserting what
// the READER does with one and cannot show that anything in the tree can write
// one. Nothing could: `git grep batten-forge` found this file and `forge.rs`, so
// `forge check red` — a registered `severity = "deny"` row — resolved
// `null` on every real checkout and decided nothing from the day it merged.
//
// These run `batten record forge`. The difference is the same one its sibling
// suite draws: a planted record agrees with the reader by construction, and a
// produced one proves writer and reader agree about the KEY.

/// A repository at a real commit, declaring that commit's own sha.
///
/// The sha cannot be a constant here: the producer RESOLVES the ref it is given,
/// so the fixture has to own a commit for it to resolve to — which is also what
/// makes `HEAD` and a literal sha two spellings of one key rather than two keys.
fn produced_fixture(name: &str) -> (PathBuf, String) {
    let dir = scratch(&format!("forge-produced-{name}"));
    write(&dir, "probe.rego", PROBE);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    write(&dir, "seed.txt", "seed\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "seed"]);
    let head = git_in(&dir, &["rev-parse", "HEAD"]).trim().to_owned();
    write(&dir, "batten.toml", &config(&head));
    (dir, head)
}

fn record_forge(dir: &Path, reference: &str, verdict: &str) -> std::process::Output {
    run_with_stdin(dir, &["record", "forge", reference], verdict)
}

#[test]
fn the_producer_writes_a_record_the_engine_reads_back() {
    // THE END-TO-END POSITIVE. No record is planted; the producer writes one and
    // the module then fires. Before this verb no sequence of commands could make
    // this assertion true.
    let (dir, _head) = produced_fixture("green");
    let written = record_forge(&dir, "HEAD", "final success\n");
    assert_eq!(
        written.status.code(),
        Some(0),
        "the producer must record a resolved commit's verdict\n{}{}",
        stdout(&written),
        stderr(&written)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-green"),
        "a produced record must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_producer_carries_the_conclusion_it_was_given() {
    // THE ANTI-VACUITY MIRROR (CLOUD-418). Without it the case above passes over a
    // producer that recorded `success` whatever the forge said — which is the
    // failure mode a landing gate can least afford, since its whole job is to
    // refuse a red commit.
    let (dir, _head) = produced_fixture("red");
    assert_eq!(
        record_forge(&dir, "HEAD", "final failure\n").status.code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-red"),
        "the producer must carry the conclusion it was given\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-green"),
        "a produced `failure` must not read as green\n{answer}{cause}"
    );
}

#[test]
fn the_producer_resolves_the_ref_rather_than_keying_to_its_spelling() {
    // THE RESOLUTION, and why the verb takes a ref rather than demanding a sha. A
    // producer naturally holds `HEAD` or a branch name; the reader keys on a sha.
    // Recording under the ref's own spelling would file the verdict BESIDE the key
    // every reader composes rather than under it — a record that exists, is
    // readable, and answers nothing.
    //
    // Asserted by recording through `HEAD` and reading back through the literal
    // sha the row declares, which are the same key only if the verb resolved.
    let (dir, head) = produced_fixture("resolved");
    assert_eq!(
        record_forge(&dir, "HEAD", "final success\n").status.code(),
        Some(0)
    );
    assert!(
        dir.join(".git").join("batten-forge").join(&head).is_file(),
        "the record must be keyed to the resolved sha, not to `HEAD`"
    );
}

#[test]
fn a_ref_that_resolves_to_nothing_is_refused() {
    // COULD-NOT-LOOK ON THE WRITE SIDE. Keying a verdict to a ref that names no
    // commit would put a record where nothing can ever read it, which is
    // indistinguishable from never having recorded — the silent failure this whole
    // row exists to end.
    let (dir, _head) = produced_fixture("unresolvable");
    let outcome = record_forge(&dir, "no-such-ref", "final success\n");
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(1),
        "an unresolvable ref is a usage error\n{answer}{cause}"
    );
    assert!(
        cause.contains("no-such-ref"),
        "the refusal names the ref it could not resolve\n{answer}{cause}"
    );
}
