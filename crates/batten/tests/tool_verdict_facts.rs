//! `input.tree["tool-verdict"]`, over the compiled binary (CLOUD-1171).
//!
//! **The keying is what this family lives or dies on, and it has two halves that
//! fail differently.** A record from a differently-pinned tool is the
//! anti-staleness case the row's acceptance names; a record taken over bytes that
//! have since changed is the one a version key alone can never catch, and it is
//! the case that makes a `status: clean` marker outlive the file it was about.
//! Both are asserted here rather than at the module, because both are properties
//! of the KEY THE ENGINE COMPOSES — a `with input as` case fabricates the very
//! shape the engine may be unable to produce (CLOUD-845, CLOUD-857), so it would
//! fabricate exactly the distinction the family exists for.
//!
//! **The benchmark half of CLOUD-1171 is deliberately absent**, by that row's own
//! recorded correction: `batten perf` already ships and already spawns
//! `hyperfine`, so a measurement was never blocked on a record family. A
//! benchmark key would also owe a machine identity and a declared null spread,
//! which is a different design and not this one.
//!
//! The engine reads a record something else wrote and **spawns nothing**;
//! `evaluator-io-check` and the spawn census are the gates on that and this suite
//! does not duplicate them.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, run_with_stdin, scratch, stderr, stdout, write};

/// The version the row declares, and the one a record must be keyed to.
const DECLARED_VERSION: &str = "1.1.0";
/// A different pin entirely — the staleness the keying refuses.
const OTHER_VERSION: &str = "1.2.0";
/// The subject's bytes at the moment the record is written.
const SUBJECT: &str = "declared = true\n";

fn config() -> String {
    format!(
        r#"version = 1

[[rule]]
id = "probe"
kind = "policy"
scope = "tree"
module = "probe.rego"
severity = "deny"

[[rule.tools]]
id = "validator"
tool = "checker"
version = "{DECLARED_VERSION}"
input = "subject.toml"

[[verdict]]
id = "V-TOOL-CLEAN"
gloss = "the declared key's record says the tool found nothing"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-CLEAN"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "V-TOOL-FINDING"
gloss = "the declared key's record carries a finding"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "R-PROBE-FINDING"
kind = "document"
target = "probe.rego"
"#
    )
}

/// Two predicates over one key, and the pair is what discriminates.
///
/// A single "did I read a verdict" rule would be green whether the engine handed
/// back this key's record or another's, and it could not tell a clean answer from
/// a finding — which is the whole question a validator gate asks.
const PROBE: &str = r#"package batten.probe

import rego.v1

rules contains "probe-clean"

rules contains "probe-finding"

violation contains {
	"rule": "probe-clean",
	"verdict": "V-TOOL-CLEAN",
} if {
	is_object(input.tree["tool-verdict"])
	some verdict in input.tree["tool-verdict"]
	verdict.status == "clean"
}

violation contains {
	"rule": "probe-finding",
	"verdict": "V-TOOL-FINDING",
} if {
	is_object(input.tree["tool-verdict"])
	some verdict in input.tree["tool-verdict"]
	verdict.status == "error"
}

test_a_clean_record_fires if {
	some v in violation with input as {"tree": {"tool-verdict": {"validator": {"status": "clean"}}}}
	v.rule == "probe-clean"
}

test_an_error_record_fires_the_other_class if {
	some v in violation with input as {"tree": {"tool-verdict": {"validator": {"status": "error"}}}}
	v.rule == "probe-finding"
}

test_no_record_fires_neither if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": {}}}
}

test_could_not_look_does_not_fault if {
	count(violation) == 0 with input as {"tree": {"tool-verdict": null}}
}
"#;

/// A repository whose row declares `DECLARED_VERSION` over `subject.toml`, plus a
/// record written under `record_version` over `recorded_bytes`.
///
/// Both key components the cases vary are parameters, because varying one while
/// holding the other is the only way either half is shown to discriminate.
fn fixture(name: &str, record: Option<(&str, &str)>, status: &str, subject_now: &str) -> PathBuf {
    let dir = scratch(&format!("tool-verdict-{name}"));
    write(&dir, "batten.toml", &config());
    write(&dir, "probe.rego", PROBE);
    write(&dir, "subject.toml", subject_now);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    if let Some((version, recorded_bytes)) = record {
        // The producer's half, written here rather than run: the engine reads a
        // record something else wrote, which is the entire shape of the family
        // and why `check` needs no spawn.
        //
        // The key is composed the same way `tools::record_key` composes it. Spelt
        // out rather than imported so the test states the contract the engine has
        // to meet, instead of agreeing with it by construction.
        let key = format!(
            "checker@{version}@{}",
            batten::tools::digest(recorded_bytes.as_bytes())
        );
        let store = dir.join(".git").join("batten-tools");
        std::fs::create_dir_all(&store).expect("record store");
        std::fs::write(store.join(key), format!("status {status}\n")).expect("write record");
    }
    dir
}

fn check(dir: &Path) -> std::process::Output {
    let mut command = batten();
    command.current_dir(dir).arg("check");
    command.output().expect("run batten check")
}

#[test]
fn a_declared_key_reads_its_own_record() {
    // THE POSITIVE. Before this family a tree-scoped module asking what a
    // validator found read undefined, Rego took undefined as *does not hold*, and
    // the gate was byte-identical to a clean tree on the decision surface.
    let dir = fixture("clean", Some((DECLARED_VERSION, SUBJECT)), "clean", SUBJECT);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-clean"),
        "the declared key's record must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_projection_carries_the_recorded_status() {
    // THE POSITIVE CONTROL (CLOUD-418). Without it the case above passes over a
    // projection that emitted `clean` unconditionally — and telling `clean` from
    // `error` is the entire question a validator gate asks.
    let dir = fixture("error", Some((DECLARED_VERSION, SUBJECT)), "error", SUBJECT);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-finding"),
        "the record's own status must decide\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-clean"),
        "the projection must carry the recorded value, not a constant\n{answer}{cause}"
    );
}

#[test]
fn a_record_from_another_version_does_not_answer() {
    // THE ANTI-STALENESS CASE, and the one the row's acceptance names. The record
    // exists, is readable, and says `clean` — it was simply taken by a
    // differently-pinned tool, whose answer is not this one's. CLOUD-646's shape
    // closed for this path: the pin is IN THE KEY, so this is mechanical rather
    // than a comparison a module could forget to make.
    let dir = fixture(
        "other-version",
        Some((OTHER_VERSION, SUBJECT)),
        "clean",
        SUBJECT,
    );
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a record from another version must not answer\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-clean"), "{answer}{cause}");
    assert!(!answer.contains("probe-finding"), "{answer}{cause}");
}

#[test]
fn a_verdict_does_not_survive_its_input() {
    // THE DIGEST HALF, and the one a version key alone structurally cannot catch:
    // the tool and the pin are identical, and only the subject moved. Without it
    // a `clean` marker outlives the file it was taken over — a gate reporting
    // green about bytes no validator ever read, which is CLOUD-845's dead gate
    // arrived at through time rather than through a missing key.
    let dir = fixture(
        "moved-input",
        Some((DECLARED_VERSION, SUBJECT)),
        "clean",
        "declared = false\n",
    );
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a verdict must not survive the bytes it was taken over\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-clean"), "{answer}{cause}");
    assert!(!answer.contains("probe-finding"), "{answer}{cause}");
}

#[test]
fn no_record_at_all_is_could_not_look() {
    // COULD-NOT-LOOK, told apart from "the tool ran and found nothing" by the
    // only means that discriminates: the control above fires `probe-finding` on a
    // record that says `error` and `probe-clean` on one that says `clean`, and
    // this fires nothing, because nothing was read.
    //
    // Collapsing them would report clean over a validator that never ran, on the
    // surface that decides whether work lands.
    let dir = fixture("no-record", None, "clean", SUBJECT);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_ne!(
        outcome.status.code(),
        Some(2),
        "an absent record must never be a policy verdict\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-clean"), "{answer}{cause}");
    assert!(!answer.contains("probe-finding"), "{answer}{cause}");
}

// --- the PRODUCER half (CLOUD-1265) -----------------------------------------
//
// Every case above writes the record by hand, which is the right shape for
// asserting what the READER does with one. It is the wrong shape for asserting
// that anything in the tree can produce one — and for the whole life of this
// family, nothing could: the only writer was the `fixture` helper thirty lines
// up, so `policy/validator-verdict-clean.rego` resolved `null` on every real
// checkout and decided nothing. CLOUD-845's dead gate, shipped.
//
// These cases run `batten record tool` instead. That is the difference between
// proving the reader composes a key and proving the WRITER AND READER COMPOSE THE
// SAME ONE — which no hand-written fixture can show, because it agrees with the
// reader by construction.

/// Run the producer in `dir`, handing it `verdict` on stdin.
fn record_tool(dir: &Path, id: &str, verdict: &str) -> std::process::Output {
    run_with_stdin(dir, &["record", "tool", id], verdict)
}

#[test]
fn the_producer_writes_a_record_the_engine_reads_back() {
    // THE END-TO-END POSITIVE, and the case this whole row exists for. No record
    // is planted: the fixture carries none, the producer writes one, and the
    // module then fires. Before this verb there was no sequence of commands that
    // could make this assertion true.
    let dir = fixture("produced-clean", None, "clean", SUBJECT);
    let written = record_tool(&dir, "validator", "status clean\n");
    assert_eq!(
        written.status.code(),
        Some(0),
        "the producer must record a declared row's verdict\n{}{}",
        stdout(&written),
        stderr(&written)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-clean"),
        "a produced record must reach the module\n{answer}{cause}"
    );
}

#[test]
fn the_producer_carries_the_verdict_it_was_given() {
    // THE ANTI-VACUITY MIRROR (CLOUD-418). Without it the case above passes over a
    // producer that wrote `clean` whatever it was handed — and a validator gate
    // that always records clean is worse than no gate, because its presence is
    // what stops anyone looking.
    let dir = fixture("produced-error", None, "clean", SUBJECT);
    assert_eq!(
        record_tool(&dir, "validator", "status error\n")
            .status
            .code(),
        Some(0)
    );

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-finding"),
        "the producer must carry the verdict it was given\n{answer}{cause}"
    );
    assert!(
        !answer.contains("probe-clean"),
        "a produced `error` must not read as clean\n{answer}{cause}"
    );
}

#[test]
fn a_produced_verdict_does_not_survive_its_input() {
    // THE KEYING, PROVEN THROUGH THE VERB rather than through a key this suite
    // spelled itself. `a_verdict_does_not_survive_its_input` above asserts the
    // reader ignores a record under a moved digest; it cannot tell that the
    // PRODUCER derives the same digest, because the fixture hands it one.
    //
    // Here the producer digests `subject.toml` itself, the file then changes, and
    // the record must go quiet. That is the anti-staleness property end to end,
    // and it is the reason the verb takes a row id and has no `--digest` flag: a
    // caller with an argument to pass could pass the wrong one.
    let dir = fixture("produced-then-moved", None, "clean", SUBJECT);
    assert_eq!(
        record_tool(&dir, "validator", "status clean\n")
            .status
            .code(),
        Some(0)
    );
    write(&dir, "subject.toml", "declared = false\n");

    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "a produced verdict must not survive the bytes it was taken over\n{answer}{cause}"
    );
    assert!(!answer.contains("probe-clean"), "{answer}{cause}");
    assert!(!answer.contains("probe-finding"), "{answer}{cause}");
}

#[test]
fn an_undeclared_id_is_refused_rather_than_recorded() {
    // A record for a tool nobody declared is UNSPELLABLE, and that is a property of
    // the argv rather than a check this verb performs: the only way to name a key
    // is to name a row the committed config already carries. So this is the
    // negative half of the anti-forgery property the keying gives the reader.
    let dir = fixture("undeclared", None, "clean", SUBJECT);
    let outcome = record_tool(&dir, "no-such-row", "status clean\n");
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(1),
        "an undeclared id is a usage error\n{answer}{cause}"
    );
    assert!(
        cause.contains("no-such-row"),
        "the refusal names the id it could not resolve\n{answer}{cause}"
    );
}

#[test]
fn a_line_carrying_no_token_is_refused() {
    // THE ONE PLACE THE WRITER IS STRICTER THAN THE READER, asserted so the
    // asymmetry is a decision rather than an accident. `forge::parse` SKIPS such a
    // line, because one torn record is not evidence about the others and a family
    // refused over a single bad line would go offline for a producer's transient
    // failure. The writer refuses it, because a producer emitting one has a bug and
    // the moment to say so is while its author is watching.
    let dir = fixture("torn-line", None, "clean", SUBJECT);
    let outcome = record_tool(&dir, "validator", "status clean\nlonely\n");
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(1),
        "a name with no token is a usage error\n{answer}{cause}"
    );
    assert!(
        cause.contains('2'),
        "the refusal names the offending line's number\n{answer}{cause}"
    );
    assert!(
        !cause.contains("lonely"),
        "the refusal must name the line's NUMBER and never its content (rule 4)\n{answer}{cause}"
    );
}

#[test]
fn a_subject_that_cannot_be_read_is_refused_rather_than_keyed() {
    // COULD-NOT-LOOK ON THE WRITE SIDE, which has no reader-side equivalent worth
    // confusing it with. The reader skips a row whose input will not read; the
    // writer must refuse, because the alternative is composing a key over bytes
    // nobody read — a verdict about a file that cannot be identified, which is
    // exactly what the digest in the key exists to make impossible.
    let dir = fixture("no-subject", None, "clean", SUBJECT);
    std::fs::remove_file(dir.join("subject.toml")).expect("remove the subject");
    let outcome = record_tool(&dir, "validator", "status clean\n");
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert_eq!(
        outcome.status.code(),
        Some(1),
        "an unreadable subject is a usage error\n{answer}{cause}"
    );
    assert!(
        cause.contains("subject.toml"),
        "the refusal names the input it could not read\n{answer}{cause}"
    );
}

#[test]
fn a_successful_record_says_nothing() {
    // §6: a clean run prints nothing. Stated as its own case because the producer
    // is handed a REDUCTION of a validator's report — the likeliest place in this
    // family for a secret to appear, per `tools.rs`'s own header — so "silent"
    // here is a rule-4 boundary rather than a matter of taste.
    let dir = fixture("quiet", None, "clean", SUBJECT);
    let outcome = record_tool(&dir, "validator", "status clean\nfinding hk.pkl:12\n");
    assert_eq!(outcome.status.code(), Some(0));
    assert!(
        stdout(&outcome).is_empty() && stderr(&outcome).is_empty(),
        "a recorded verdict is silent\n{}{}",
        stdout(&outcome),
        stderr(&outcome)
    );
}
