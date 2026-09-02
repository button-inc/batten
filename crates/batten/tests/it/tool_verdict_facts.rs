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
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! CLOUD-1199's disposition, applied: `pkl-check` RAN `pkl` and then adjudicated
//! its exit status in shell. The run stays outside either way — §9's prior art —
//! and what moves is the ADJUDICATION, onto the `config-validator`
//! `[[rule.tools]]` row and `policy/validator-verdict-clean.rego`, which were
//! both already in the tree and both deciding nothing until CLOUD-1265's producer
//! landed. So this retirement adds no rule, no module and no verb: it deletes the
//! wrapper and lets the row that was always meant to decide, decide.

// carried: mise-tasks/pkl-check.sh policy/validator-verdict-clean.rego crates/batten/tests/tool_verdict_facts.rs
// carried: tests/pkl-check.bats policy/validator-verdict-clean.rego crates/batten/tests/tool_verdict_facts.rs

//! # RETIREMENT LEDGER — `tests/pkl-check.bats`, 3 cases
//!
//! CARRIED — the verdict half, which is what the gate was for.

// carried: "a malformed .pkl file fails" crates/batten/tests/tool_verdict_facts.rs

//! WITHDRAWN — the two cache cases, and the reason is that their subject is not
//! this repository's verdict at all.
//!
//! Both measure `pkl`'s own PACKAGE CACHE against denied egress — cold fails,
//! warm succeeds — which is CLOUD-406's provisioning question. Neither asks
//! whether `hk.pkl` is valid, and neither has anything to say about a record.
//! Carrying them into a Rust tier would mean asserting a property of a JVM
//! native-image's network behaviour from a test that cannot deny egress, which is
//! the "assert your own premise" shape `.claude/rules/rust.md` refuses.
//!
//! What DOES survive is the mechanism they were written to protect: `run_pkl`'s
//! `--ca-certificates` selection is carried verbatim into
//! `[tasks.record-verdicts]`, so the proxy CA the sandbox needs is still supplied
//! at the one place pkl is invoked.

// withdrawn: "the coupling is real: a cold cache with egress denied cannot evaluate hk.pkl" CLOUD-406 owns pkl's package cache; the case measures pkl and the network rather than this repository's verdict, and the CA selection it protects is carried into `[tasks.record-verdicts]`
// withdrawn: "a warm cache breaks it: the same command with egress denied evaluates cleanly" CLOUD-406 owns pkl's package cache; the case skips outright on any host with no warm cache to copy, and the CA selection it protects is carried into `[tasks.record-verdicts]`

//! # RETIREMENT LEDGER, PER PATH — `renovate-config-validator` (CLOUD-1262)
//!
//! The same disposition one row over, and the retirement is what unblocks the
//! `npm:renovate` bump rather than a consequence of it. That program's seam was
//! the environment variable `RENOVATE_CONFIG` — the same name renovate 44 reads
//! as INLINE JSON5 config — so the validator was handed a PATH and died parsing
//! it as content. Renaming the seam meant editing authored shell frozen by
//! `shell edit refused`, whose sole route is `rule read first`. This is that
//! route: the path is now an argument in `[tasks.record-verdicts]` and the input
//! is `batten.toml`'s `renovate-config` row, so there is no variable left to
//! collide.

// carried: mise-tasks/renovate-config-validator.sh policy/validator-verdict-clean.rego crates/batten/tests/tool_verdict_facts.rs
// carried: tests/renovate-config-validator.bats policy/validator-verdict-clean.rego crates/batten/tests/tool_verdict_facts.rs

//! # RETIREMENT LEDGER — `tests/renovate-config-validator.bats`, 4 cases
//!
//! CARRIED — the verdict pair, which is the gate's whole content. A clean config
//! records `status clean` and denies nothing; a rejected or unparseable one
//! records `status error` and `validator-verdict-clean` refuses. The two
//! rejection cases collapse into one successor because the producer cannot tell
//! them apart and never could: both are "the validator exited non-zero", and the
//! REASON stays on the terminal rather than entering the record (rule 4).

// carried: "a config Renovate accepts passes" crates/batten/tests/tool_verdict_facts.rs
// carried: "a config Renovate rejects is refused" crates/batten/tests/tool_verdict_facts.rs
// carried: "a config that is not parseable at all is refused" crates/batten/tests/tool_verdict_facts.rs

//! CHANGED — the could-not-look arm, whose exit code moves and whose meaning does
//! not.

// changed: "an unreadable config is exit 2, never a pass" crates/batten/tests/tool_verdict_facts.rs the shell gate exited 2 itself when it could not read the config. The producer exits 1 instead — a usage error, since the caller named a row whose declared input is unreadable — and the ADJUDICATION side is unchanged in substance: no record is written, so the id is absent from the map and `validator-verdict-clean` refuses nothing rather than reporting clean. `a_subject_that_cannot_be_read_is_refused_rather_than_keyed` is the successor, and it asserts the stronger half the shell case could not: that no key is composed at all, so a later reader cannot find a verdict over bytes nobody read

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, run_with_stdin, scratch, stderr, stdout, write};

/// The version the row declares, and the one a record must be keyed to.
const DECLARED_VERSION: &str = "1.1.0";
/// A different pin entirely — the staleness the keying refuses.
const OTHER_VERSION: &str = "1.2.0";
/// The subject's bytes at the moment the record is written.
const SUBJECT: &str = "declared = true\n";

/// The committed row plus a declared PRODUCER, so the engine runs the validator
/// on a miss instead of waiting for a record somebody minted by hand.
///
/// `probe` is included because the two arms are inseparable in practice: a
/// consumer who declares a runner also has to say when that runner cannot run,
/// or the gate becomes a verdict about whether the tool is installed.
fn config_with_producer(runner: &str, probe: &[&str]) -> String {
    let probe = if probe.is_empty() {
        String::new()
    } else {
        format!(
            "probe = [{}]\n",
            probe
                .iter()
                .map(|word| format!("{word:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    config().replace(
        &format!("input = \"subject.toml\"\n"),
        &format!("input = \"subject.toml\"\nrun = {runner:?}\nargs = [\"judge\"]\n{probe}"),
    )
}

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
id = "tool clean probe"
gloss = "the declared key's record says the tool found nothing"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe clean probe"
kind = "document"
target = "probe.rego"

[[verdict]]
id = "tool finding probe"
gloss = "the declared key's record carries a finding"
class = "A fixture class, raised only by this suite's probe module."

[[verdict.route]]
id = "probe finding probe"
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
	"verdict": "tool clean probe",
} if {
	is_object(input.tree["tool-verdict"])
	some verdict in input.tree["tool-verdict"]
	verdict.status == "clean"
}

violation contains {
	"rule": "probe-finding",
	"verdict": "tool finding probe",
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

// ---------------------------------------------------------------------------
// THE PRODUCER (CLOUD-1265). Every case above writes the record by hand, which
// is what the family looked like when it had a reader and no writer: `batten
// record tool` mints these and nothing calls it, so on every real checkout the
// key resolved to nothing and the deny rows over it refused nothing.
//
// A `with input as` case cannot see this and neither can the cases above — they
// fabricate or hand-write the record, so they pass identically over an engine
// that produces nothing at all.
// ---------------------------------------------------------------------------

/// A validator written into the fixture, exiting `code` and recording its calls.
fn validator(dir: &Path, code: i32) {
    let path = dir.join("checker.sh");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = probe ]; then exit \"$(cat \"$(dirname \"$0\")/ready\")\"; fi\n\
             echo x >> \"$(dirname \"$0\")/calls\"\n\
             exit {code}\n"
        ),
    )
    .expect("write the validator");
    std::fs::write(dir.join("ready"), "0").expect("the probe answer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make it executable");
    }
}

fn producer_fixture(name: &str, code: i32, probe: &[&str]) -> PathBuf {
    let dir = scratch(&format!("tool-verdict-{name}"));
    write(
        &dir,
        "batten.toml",
        &config_with_producer("checker.sh", probe),
    );
    write(&dir, "probe.rego", PROBE);
    write(&dir, "subject.toml", SUBJECT);
    validator(&dir, code);
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    dir
}

fn calls(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("calls")).map_or(0, |text| text.lines().count())
}

/// THE ENGINE PRODUCES THE RECORD, which is the whole of CLOUD-1265. Without
/// this the family is a landed reader whose key nothing fills.
#[test]
fn a_declared_producer_mints_the_record_the_module_reads() {
    let dir = producer_fixture("produced-clean", 0, &[]);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-clean"),
        "the engine must run the validator and read what it concluded\n{answer}{cause}"
    );
    assert_eq!(calls(&dir), 1, "the miss ran the validator exactly once");
}

/// A NON-ZERO EXIT IS A VERDICT, NOT A FAILURE. The validator ran and objected,
/// so a record exists carrying a pointer — which is what a gate over this family
/// refuses on.
#[test]
fn a_validator_that_objects_records_a_finding() {
    let dir = producer_fixture("produced-finding", 1, &[]);
    let outcome = check(&dir);
    let (answer, cause) = (stdout(&outcome), stderr(&outcome));
    assert!(
        answer.contains("probe-finding"),
        "a validator that objected must reach the module as a finding\n{answer}{cause}"
    );
}

/// AND A HIT DOES NOT RE-RUN, so a validator stays affordable inside a gate that
/// runs every landing lap. Only a call count can show it: the record is
/// byte-identical either way.
#[test]
fn an_unchanged_input_is_a_cache_hit() {
    let dir = producer_fixture("produced-hit", 0, &[]);
    check(&dir);
    check(&dir);
    assert_eq!(calls(&dir), 1, "the second run read the record");
}

/// A VALIDATOR THAT CANNOT RUN HERE IS COULD-NOT-LOOK, never a finding. The
/// program is present, so no file-existence check could tell this from ready —
/// which is the arm the probe exists for.
#[test]
fn a_probe_that_says_not_ready_produces_nothing() {
    let dir = producer_fixture("produced-unready", 0, &["probe"]);
    std::fs::write(dir.join("ready"), "1").expect("the probe says not-ready");
    let outcome = check(&dir);
    let answer = stdout(&outcome);
    assert!(
        !answer.contains("probe-clean") && !answer.contains("probe-finding"),
        "an unavailable validator leaves the subject unjudged\n{answer}"
    );
    assert_eq!(calls(&dir), 0, "and nothing was run");
}
