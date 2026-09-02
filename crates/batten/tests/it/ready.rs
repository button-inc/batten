//! `batten ready lint` over the compiled binary (CLOUD-1121).
//!
//! The refinement gate's decision table, driven by `get_issue`-shaped payloads —
//! ported from `tests/ready-lint.bats` when CLOUD-1059 made editing a shell rule
//! refusable, so the migration replaced the program rather than maintaining it.
//!
//! **The cases that matter are the ones prose cannot fake:** a blocker asserted
//! in §8 text with no matching `blockedBy` relation, and a §6 bump that
//! disagrees with its own commit type. Everything else here pins the deliberate
//! NON-behaviours — chiefly that an omitted clause is not a violation, because
//! the gate document forbids restating clauses and the corpus's most thoroughly
//! refined issue omits one and is correctly Ready.
//!
//! **This tier is the compiled binary rather than the module's own unit tests,
//! and the difference is the point.** A unit test over `ready::lint` fabricates
//! the `Payload` the predicate expects; only a run of the binary proves the
//! ENGINE builds that shape from what a caller actually pipes — which is the
//! class `.claude/rules/policy-modules.md` records for `with input as`, and the
//! class CLOUD-1121 itself was filed over, where a fixture and a reader agreed
//! with each other and neither agreed with the writer.
//!
//! # THE EXIT CODES MOVED, ALL OF THEM, AND IT IS ONE DECISION RATHER THAN 80
//!
//! The shell program answered `1` for a violation and `2` for could-not-look.
//! This verb answers the crate's one table: `2` is the policy verdict everywhere
//! — a `check` violation and a `hook` deny alike — and `1` is a usage error,
//! which is what could-not-look is here. Non-negotiable rule 5 admits no per-verb
//! exception, so the two codes are the other way round and every case below reads
//! that way.
//!
//! The ledger records those cases as CARRIED rather than CHANGED, and the
//! distinction is deliberate: the PREDICATE is identical in every one — the same
//! bodies are refused, the same gaps are gaps, the same passes pass. What moved
//! is one numeric mapping, uniformly, by a rule that predates this port. Spelling
//! that as 80 independent behaviour changes would bury the one decision a reader
//! needs to see in a list nobody reads.
//!
//! # THE LEDGER IS WRITTEN AND THE PROGRAM IS NOT YET DELETED, DELIBERATELY
//!
//! `mise-tasks/ready-lint.sh` and `tests/ready-lint.bats` are still in the tree,
//! and the rows below are the mapping the deletion will redeem rather than a
//! claim that it has happened. The blocker is named rather than left to be
//! rediscovered: `mise-tasks/graph-check.sh` resolves this gate BY PATH and
//! branches on its exit codes, and both lines have to move for the program to
//! die — the path because there is no path any more, the codes because a
//! violation is `2` here where it was `1` there. `shell edit refused` admits an
//! edit to a caller only where every added line is a truncation of a removed one
//! or an exact path substitution at a declared successor (both arms are in
//! `policy/shell-retirement.rego`), and a shell sibling repointed at a compiled
//! verb is neither. So retiring this one reaches a second program, and that is a
//! change of its own rather than a line in this one.
//!
//! The claim gate's half of the same port DID land — its only caller named it by
//! task name, which is why `mise.toml` could answer for it unchanged.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
// carried: mise-tasks/ready-lint.sh crates/batten/src/ready.rs kind:verb crates/batten/tests/it/ready.rs
// carried: tests/ready-lint.bats crates/batten/src/ready.rs kind:verb crates/batten/tests/it/ready.rs
//!
//! # RETIREMENT LEDGER — `tests/ready-lint.bats`, 80 cases
//!
//! CARRIED — the property survives, proved here against the engine.
//!
// carried: "a well-formed block passes" crates/batten/tests/it/ready.rs
// carried: "omitted clauses are not a violation" crates/batten/tests/it/ready.rs
// carried: "a blocker cited in §8 with no relation is reported" crates/batten/tests/it/ready.rs
// carried: "the same citation passes when the relation actually exists" crates/batten/tests/it/ready.rs
// carried: "a blocker noted as closed still needs its relation" crates/batten/tests/it/ready.rs
// carried: "a blocker noted as closed passes when the relation is there, which it is" crates/batten/tests/it/ready.rs
// carried: "the body's cited keys are emitted before any verdict" crates/batten/tests/it/ready.rs
// carried: "THE §6 DECLARATION IS EMITTED, and none reaches the consumer as one token" crates/batten/tests/it/ready.rs
// carried: "a releasable type is emitted as what it declares, not as none" crates/batten/tests/it/ready.rs
// carried: "a body with no §6 clause emits no bump line at all — did not say is not none" crates/batten/tests/it/ready.rs
// carried: "an unrefined body still emits its cited keys" crates/batten/tests/it/ready.rs
// carried: "a body citing nothing emits the line and no keys" crates/batten/tests/it/ready.rs
// carried: "the §8 span's keys are emitted as their own set" crates/batten/tests/it/ready.rs
// carried: "§8 None is an explicit, valid answer" crates/batten/tests/it/ready.rs
// carried: "a relatedTo mention on the §8 line is not a claim" crates/batten/tests/it/ready.rs
// carried: "a house-style (§6) cross-reference is not the commit clause" crates/batten/tests/it/ready.rs
// carried: "§6 none is an explicit, valid no-commit declaration" crates/batten/tests/it/ready.rs
// carried: "a closed blocker in Linear's rendered-mention form is judged like any other" crates/batten/tests/it/ready.rs
// carried: "a rendered-mention blockedBy claim without a relation is still flagged" crates/batten/tests/it/ready.rs
// carried: "a cross-reference after the claim sentence is not a claim" crates/batten/tests/it/ready.rs
// carried: "feat to patch agrees below 0.1.0" crates/batten/tests/it/ready.rs
// carried: "a bump promising the retired arrow is reported below 0.1.0" crates/batten/tests/it/ready.rs
// carried: "a breaking change promising major is reported below 0.1.0" crates/batten/tests/it/ready.rs
// carried: "a breaking change declaring patch agrees below 0.1.0" crates/batten/tests/it/ready.rs
// carried: "a §6 clause denying a break is not read as declaring one" crates/batten/tests/it/ready.rs
// carried: "the marker on the type token still declares a break" crates/batten/tests/it/ready.rs
// carried: "a BREAKING CHANGE footer still declares a break" crates/batten/tests/it/ready.rs
// carried: "a §6 clause denying a break without naming a surface is refused" crates/batten/tests/it/ready.rs
// carried: "a denial qualified as consumer-facing passes" crates/batten/tests/it/ready.rs
// carried: "a denial qualified as the library API passes" crates/batten/tests/it/ready.rs
// carried: "a §6 clause making no breakage claim is untouched" crates/batten/tests/it/ready.rs
// carried: "CLOUD-832's §6 as written reproduces the refusal" crates/batten/tests/it/ready.rs
// carried: "the refusal carries no prose from the clause" crates/batten/tests/it/ready.rs
// carried: "a no-bump type does not collapse to patch below 0.1.0" crates/batten/tests/it/ready.rs
// carried: "an earlier code span whose prefix spells a type is not the declared type" crates/batten/tests/it/ready.rs
// carried: "the verdict follows the declared type, not the prefix that precedes it" crates/batten/tests/it/ready.rs
// carried: "a coincidental prefix no longer decides an honest no-bump line" crates/batten/tests/it/ready.rs
// carried: "a scoped commit type is still recognised" crates/batten/tests/it/ready.rs
// carried: "a disagreeing declaration beside a code span is still refused" crates/batten/tests/it/ready.rs
// carried: "the arrows fire again at 0.1.0 and above" crates/batten/tests/it/ready.rs
// carried: "patch under a released version is the disagreement" crates/batten/tests/it/ready.rs
// carried: "an unreadable workspace version exits 2, not a guessed verdict" crates/batten/tests/it/ready.rs
// carried: "an issue with no §6 clause needs no workspace version" crates/batten/tests/it/ready.rs
// carried: "a §6 clause naming no commit type is reported" crates/batten/tests/it/ready.rs
// carried: "an open-questions marker blocks Ready" crates/batten/tests/it/ready.rs
// carried: "the retired (clause N) dialect is reported, not silently accepted" crates/batten/tests/it/ready.rs
// carried: "an issue with no Ready block at all is reported" crates/batten/tests/it/ready.rs
// carried: "a parent's refinement-gate heading is a Ready block" crates/batten/tests/it/ready.rs
// carried: "a deeper refinement-gate heading is a Ready block too" crates/batten/tests/it/ready.rs
// carried: "clauses inside a parent block are still checked" crates/batten/tests/it/ready.rs
// carried: "a parent's §8 claim is held to the board like a leaf's" crates/batten/tests/it/ready.rs
// carried: "prose merely discussing refinement is not a Ready block" crates/batten/tests/it/ready.rs
// carried: "unparseable stdin exits 2, not 1" crates/batten/tests/it/ready.rs
// carried: "output is pointer-only — no issue prose echoed" crates/batten/tests/it/ready.rs
// carried: "a blocker claimed under a §8 HEADING with no relation is reported" crates/batten/tests/it/ready.rs
// carried: "the same claim with the relation present passes" crates/batten/tests/it/ready.rs
// carried: "a §8 heading claiming nothing is not a violation" crates/batten/tests/it/ready.rs
// carried: "the span stops at the next heading, so a later section is not §8 text" crates/batten/tests/it/ready.rs
// carried: "the span stops at the paragraph end, so a following paragraph is not the claim" crates/batten/tests/it/ready.rs
// carried: "a block that is only a refinement note carries no clause and is reported" crates/batten/tests/it/ready.rs
// carried: "a house-style cross-reference in prose does not satisfy the floor" crates/batten/tests/it/ready.rs
// carried: "a block carrying only §1 clears the floor — it is a floor, not a checklist" crates/batten/tests/it/ready.rs
// carried: "a heading-form label counts as a clause" crates/batten/tests/it/ready.rs
// carried: "a clause-free parent block is exempt from the floor" crates/batten/tests/it/ready.rs
// carried: "the non-canonical ready opener is reported, not treated as no block" crates/batten/tests/it/ready.rs
// carried: "a non-canonical opener still has its content judged" crates/batten/tests/it/ready.rs
// carried: "a payload with no description is exit 2 naming the field, never a verdict" crates/batten/tests/it/ready.rs
// carried: "a payload carrying only the declared field set is judged on its merits" crates/batten/tests/it/ready.rs
// carried: "(a) no relations key is a gap, never blocker-cited-without-relation" crates/batten/tests/it/ready.rs
// carried: "(b) relations present and empty is an answer, so the citation still reports" crates/batten/tests/it/ready.rs
// carried: "(c) relations present and carrying the cited id passes" crates/batten/tests/it/ready.rs
// carried: "(d) a judgeable violation outranks the gap: exit 1, not 2" crates/batten/tests/it/ready.rs
// carried: "the deferral rule has the same gap, and it reached further" crates/batten/tests/it/ready.rs
// carried: "a missing key costs nothing when the block cites nothing" crates/batten/tests/it/ready.rs
// carried: "a §7 introducing a deny gate with no replay is refused" crates/batten/tests/it/ready.rs
// carried: "a deny gate that reports its replay passes" crates/batten/tests/it/ready.rs
// carried: "a block declaring warn is not gated" crates/batten/tests/it/ready.rs
// carried: "a fenced [[rule]] at deny is a gate introduction too" crates/batten/tests/it/ready.rs
// carried: "a block introducing no gate is untouched by the replay clause" crates/batten/tests/it/ready.rs
// carried: "the deny-without-replay report carries no line of the block" crates/batten/tests/it/ready.rs

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, declared_patterns, run_with_stdin, stderr, stdout};

/// A repository whose workspace version puts it in the pre-0.1.0 regime.
///
/// The version is READ FROM THE TREE rather than hardcoded, because §6's arrows
/// depend on it: below 0.1.0 every releasable type collapses to a patch, and
/// enforcing the retired set made the honest declaration the failing one.
fn repo(name: &str, version: &str) -> PathBuf {
    Fixture::new(name)
        // The grammar is the consumer's (CLOUD-1100): without these rows the verb
        // reports could-not-look naming the first missing id, which is the right
        // answer for a repository that declared none and not what this suite is
        // about.
        .config(&format!("version = 1\n\n{}", declared_patterns()))
        .file(
            "Cargo.toml",
            &format!("[workspace.package]\nversion = \"{version}\"\n\n[workspace.dependencies]\nserde = \"1\"\n"),
        )
        .git()
        .base_commit()
        .build()
}

/// The pre-0.1.0 regime, which is this repository's own and every case's default.
fn pre_release(name: &str) -> PathBuf {
    repo(name, "0.0.125")
}

/// A `get_issue` payload: a body, and the `blockedBy` ids the board carries.
fn payload(description: &str, blocked_by: &[&str]) -> String {
    let relations = serde_json::json!({
        "blockedBy": blocked_by
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect::<Vec<_>>(),
    });
    serde_json::json!({
        "id": "CLOUD-999",
        "description": description,
        "relations": relations,
    })
    .to_string()
}

/// Lint a payload, with nothing on stdin but the payload itself.
fn lint(dir: &Path, body: &str) -> Output {
    run_with_stdin(dir, &["ready", "lint"], body)
}

/// A minimal well-formed block. Only the clauses under test are ever added.
fn block(extra: &str) -> String {
    format!(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready (a summary)**\n\n\
         * **Source of truth (§1).** One authoritative artifact.\n{extra}\n"
    )
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the verb exits rather than dying")
}

/// A fixture whose `mise.toml` declares tasks, so `gate.task` has something to
/// resolve against.
///
/// Separate from [`pre_release`] on purpose: a fixture with no manifest is the
/// could-not-look arm, and both arms are asserted below. Building the manifest
/// into every fixture would make the fail-open case untestable.
fn with_tasks(name: &str) -> PathBuf {
    Fixture::new(name)
        // The grammar is the consumer's (CLOUD-1146), so a fixture that declares
        // none gets could-not-look naming the first missing id rather than a
        // verdict — the right answer for such a repository, and not what these
        // cases are about. `repo` above opts in for the same reason.
        //
        // The prose-dialect threshold is DECLARED rather than defaulted
        // (CLOUD-472). A fixture omitting it gets `None` — could-not-look — and
        // every threshold case below would then pass for the wrong reason, which
        // is the shape a dead gate and a clean tree share.
        .config(&format!(
            "version = 1\n\n[ready]\nprose_dialect_required_from = \"2026-06-01T00:00:00.000Z\"\n\n{}",
            declared_patterns()
        ))
        .file(
            "Cargo.toml",
            "[workspace.package]\nversion = \"0.0.125\"\n\n[workspace.dependencies]\nserde = \"1\"\n",
        )
        .file(
            "mise.toml",
            "[tasks.verify]\nrun = \"true\"\n\n[tasks.\"test:cargo\"]\nrun = \"true\"\n",
        )
        .git()
        .base_commit()
        .build()
}

/// A Ready block carrying a fenced claims object.
fn claims_block(object: &str) -> String {
    format!(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready**\n\n\
         * **Source of truth (§1).** One authoritative artifact.\n\n\
         ```json\n{object}\n```\n"
    )
}

/// Every required key filled, so a case can remove exactly one.
fn complete_claims() -> serde_json::Value {
    serde_json::json!({
        "source_of_truth": "crates/batten/src/ready.rs",
        "gate": { "task": "verify", "exits": [0, 2] },
        "commit_type": "feat",
        "blockers": [],
        // A SLUG, NOT PROSE (CLOUD-472). This fixture carried
        // "drop the required-key check" — a sentence, which is what the field
        // meant under CLOUD-418 and which nothing can resolve. `batten mutate`
        // resolves a slug, so the obligation becomes checkable rather than
        // asserted, and every case below inherits the corrected shape.
        "tests": [{
            "file": "crates/batten/tests/it/ready.rs",
            "mutation": "required-key-unread",
        }],
    })
}

fn claims_payload(object: &serde_json::Value, blocked_by: &[&str]) -> String {
    payload(
        &claims_block(&serde_json::to_string_pretty(object).expect("encodable")),
        blocked_by,
    )
}

/// A row created after the fixture's cutover, so the prose dialect is refused.
const AFTER_CUTOVER: &str = "2026-07-01T00:00:00.000Z";
/// A row created before it, so the prose dialect still passes.
const BEFORE_CUTOVER: &str = "2026-01-01T00:00:00.000Z";

/// A payload carrying a chosen creation instant, for the cutover cases below.
///
/// Every other fixture here omits `createdAt` entirely, which is could-not-look
/// and exempt — that is why the whole prose corpus above stays clean, and why
/// these cases have to state their own instant rather than reusing the shared
/// builder.
fn dated_payload(created_at: Option<&str>, description: &str) -> String {
    let mut value = serde_json::json!({
        "id": "CLOUD-999",
        "description": description,
        "relations": { "blockedBy": [] },
    });
    if let Some(created_at) = created_at {
        value["createdAt"] = serde_json::json!(created_at);
    }
    value.to_string()
}

// ---------------------------------------------------------------------------
// CLOUD-472: the prose dialect is a LEGACY, not an alternative.
//
// `REQUIRED_CLAIMS` and `check_claimed_tests` already force a `mutation` onto
// every declared obligation — CLOUD-418's field. That mechanism was unreachable,
// because an absent fence dropped the author onto the prose path, and measured
// 2026-09-01 the object was used by nothing at all.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE PRESSURE-TEST CUTOVER (CLOUD-472), the SECOND ratchet on `[ready]`.
//
// Its own fixture rather than `with_tasks`, because the two cutovers are
// deliberately independent: a case that moved both at once could not tell which
// one refused, which is the whole reason they are separate fields.
//
// The runner is a STUB, on `judge_kind.rs`'s doctrine — the engine's contract
// with a dispatched program is what it writes and what it exits, so a stub
// exercises the whole of it, and it makes the no-runner arm reachable by simply
// not writing one.
// ---------------------------------------------------------------------------

/// A fixture declaring the pressure-test cutover and one `tracker-body` review.
///
/// `runner` is absolute so the row does not depend on `PATH`, and `with_runner`
/// false leaves the program absent — which is the could-not-look arm rather than
/// a refusal, and the case that keeps this gate from being a verdict about the
/// operator's machine.
fn with_pressure_test(name: &str, runner_exits: Option<i32>) -> PathBuf {
    // BUILT FIRST, CONFIGURED SECOND. The row's `runner` must be an absolute
    // path — a relative program is resolved against the PARENT's working
    // directory rather than the child's, which is a footgun that would make this
    // fixture pass or fail depending on where the suite was invoked from — and
    // the path is not known until the fixture exists.
    // A PLACEHOLDER CONFIG FIRST, because `base_commit` commits the tree and a
    // fixture with no files has nothing to commit. The real config is written
    // below, once the runner's absolute path exists to put in it.
    let dir = Fixture::new(name)
        .config("version = 1\n")
        .git()
        .base_commit()
        .build();
    let runner = dir.join("runner.sh");
    common::write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n[ready]\npressure_test_required_from = \"2026-06-01T00:00:00.000Z\"\n\n\
             [[rule]]\nid = \"review-dispatched\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/review-dispatched.rego\"\nseverity = \"deny\"\n\n\
             [[rule.review]]\nid = \"ready-pressure-test-body\"\nprompt = \"ready-pressure-test\"\n\
             runner = \"{}\"\nversion = \"0\"\nsubject = \"tracker-body\"\n\n{}",
            runner.display(),
            declared_patterns()
        ),
    );
    if let Some(code) = runner_exits {
        std::fs::write(&runner, format!("#!/bin/sh\ncat >/dev/null\nexit {code}\n"))
            .expect("write the stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755))
                .expect("make it executable");
        }
    }
    dir
}

/// PAST THE CUTOVER WITH NO RECORD IS REFUSED — the gate's whole point, and the
/// question no other clause here can ask. Every sibling reads the block and
/// infers quality from its SHAPE; this asks whether a named prompt ran over
/// these exact bytes, which better-shaped prose cannot satisfy because the prose
/// is the input to the hash.
#[test]
fn a_row_past_the_pressure_test_cutover_owes_a_dispatch() {
    let dir = with_pressure_test("ready-pressure-past-cutover", Some(0));
    // The stub exits 0 having printed nothing, which is a review that RAN and
    // pointed at nothing — so the first lint records and the row is clean.
    let output = lint(&dir, &dated_payload(Some(AFTER_CUTOVER), &block("")));
    assert!(
        !stderr(&output).contains("pressure-test-undispatched"),
        "the stub ran and recorded, so nothing is undispatched: {}",
        stderr(&output)
    );
}

/// THE REFUSAL FIRES, and this case is what gives every other one here meaning.
///
/// The four cases around it assert an ABSENCE — that the class does not appear —
/// and a suite of those passes trivially if the finding can never fire at all,
/// which is the shape a dead gate and a clean tree share. Here the runner is
/// present and was asked, and it exited non-zero: the review was owed, it was
/// dispatched, and it did not answer. That is the branch's problem rather than
/// the environment's, and the one state this gate exists to refuse.
#[test]
fn a_runner_that_answers_nothing_usable_is_refused() {
    let dir = with_pressure_test("ready-pressure-red-runner", Some(1));
    let output = lint(&dir, &dated_payload(Some(AFTER_CUTOVER), &block("")));
    assert!(
        stderr(&output).contains("pressure-test-undispatched"),
        "a dispatched review that gave nothing usable must refuse: {}",
        stderr(&output)
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
}

/// BEFORE THE CUTOVER IS UNJUDGED. Without this the flip refuses the standing
/// Todo queue at once and takes the ready frontier dark — CLOUD-858's measured
/// shape, and the reason this is a ratchet rather than a switch.
#[test]
fn a_row_created_before_the_pressure_test_cutover_is_not_judged() {
    let dir = with_pressure_test("ready-pressure-before-cutover", None);
    let output = lint(&dir, &dated_payload(Some(BEFORE_CUTOVER), &block("")));
    assert!(
        !stderr(&output).contains("pressure-test-undispatched"),
        "a row predating the cutover owes nothing: {}",
        stderr(&output)
    );
}

/// A PAYLOAD WITH NO CREATION INSTANT CANNOT BE PLACED against a cutover, so it
/// is could-not-look. Reading absent as "past the cutover" would turn a verdict
/// about the payload into a verdict about the row.
#[test]
fn a_payload_with_no_creation_instant_is_not_judged() {
    let dir = with_pressure_test("ready-pressure-undated", None);
    let output = lint(&dir, &dated_payload(None, &block("")));
    assert!(
        !stderr(&output).contains("pressure-test-undispatched"),
        "an unplaceable row owes nothing: {}",
        stderr(&output)
    );
}

/// NO RUNNER IS COULD-NOT-LOOK, NEVER A REFUSAL. A machine with no reviewer
/// installed cannot be asked whether it reviewed, and refusing there would fail
/// every fresh clone and every CI runner that has not installed the agent — a
/// verdict about the operator wearing a verdict about the row.
#[test]
fn a_row_past_the_cutover_with_no_runner_is_not_judged() {
    let dir = with_pressure_test("ready-pressure-no-runner", None);
    let output = lint(&dir, &dated_payload(Some(AFTER_CUTOVER), &block("")));
    assert!(
        !stderr(&output).contains("pressure-test-undispatched"),
        "an environment with no reviewer is unjudgeable, not guilty: {}",
        stderr(&output)
    );
}

/// A CONSUMER THAT DECLARED NO CUTOVER HAS NOT ASKED FOR THIS, so the standing
/// fixture — which declares only the prose cutover — must never see the class.
#[test]
fn a_consumer_declaring_no_pressure_test_cutover_is_untouched() {
    let dir = with_tasks("ready-pressure-undeclared");
    let output = lint(&dir, &dated_payload(Some(AFTER_CUTOVER), &block("")));
    assert!(
        !stderr(&output).contains("pressure-test-undispatched"),
        "an undeclared cutover asks nothing: {}",
        stderr(&output)
    );
}

#[test]
fn a_prose_block_past_the_cutover_is_refused() {
    let dir = with_tasks("ready-prose-past-cutover");
    let output = lint(
        &dir,
        &dated_payload(
            Some(AFTER_CUTOVER),
            &block("* **Test obligation (§7).** Three discriminating observations.\n"),
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("claims-object-absent"),
        "the refusal must name the class, or the author cannot act on it: {}",
        stderr(&output)
    );
}

#[test]
fn a_claims_object_past_the_cutover_is_clean() {
    // The remedy has to be REACHABLE from the refusal above, or the ratchet is a
    // wall. Same key, same fixture, the object supplied.
    let dir = with_tasks("ready-object-past-cutover");
    let object = serde_json::to_string_pretty(&complete_claims()).expect("encodable");
    let output = lint(
        &dir,
        &dated_payload(Some(AFTER_CUTOVER), &claims_block(&object)),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// THE ANTI-VACUITY MIRROR, and without it the arm is satisfied by a check that
/// refuses every prose block — which is the change that takes the board's ready
/// frontier dark in one step (CLOUD-858's measured shape).
#[test]
fn a_prose_block_before_the_cutover_is_clean() {
    let dir = with_tasks("ready-prose-before-cutover");
    let output = lint(
        &dir,
        &dated_payload(
            Some(BEFORE_CUTOVER),
            &block("* **Test obligation (§7).** Three discriminating observations.\n"),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// COULD-NOT-LOOK PASSES. A payload carrying no creation instant cannot be
/// placed against the cutover at all, so it is judged exactly as it was before
/// this clause existed. Reading "no stamp" as "past the cutover" would turn a
/// verdict about the payload into a verdict about the row — and this is the arm
/// that keeps every other fixture in this file, none of which sets `createdAt`,
/// passing for the RIGHT reason rather than by accident.
#[test]
fn a_payload_with_no_creation_instant_is_judged_as_before() {
    let dir = with_tasks("ready-no-stamp");
    let output = lint(
        &dir,
        &dated_payload(
            None,
            &block("* **Test obligation (§7).** Three discriminating observations.\n"),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// §453: the checkable half as data, and the prose path it does not disturb.
// ---------------------------------------------------------------------------

#[test]
fn a_complete_claims_object_passes_and_names_its_dialect() {
    let dir = with_tasks("ready-claims-complete");
    let output = lint(&dir, &claims_payload(&complete_claims(), &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).lines().any(|line| line == "dialect json"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_missing_required_key_is_refused_and_named() {
    // THE ROW'S WHOLE MECHANISM. The prose path validates the clauses that ARE
    // present and says nothing about absence, so a missing mechanism and a
    // mechanism the parser failed to find reach the same verdict: clean.
    // CLOUD-420 sat in the ready queue with a §2 saying its central design
    // decision was still to be made, and no gate could see it.
    //
    // A key cannot be well-formed prose. Every one is removed in turn rather
    // than one being sampled, because a check that covered four of five keys
    // would pass a case that tested the fifth.
    let dir = with_tasks("ready-claims-missing-key");
    for key in [
        "source_of_truth",
        "gate",
        "commit_type",
        "blockers",
        "tests",
    ] {
        let mut object = complete_claims();
        object
            .as_object_mut()
            .expect("the fixture is an object")
            .remove(key);
        let output = lint(&dir, &claims_payload(&object, &[]));
        assert_eq!(code(&output), 2, "{key}\n{}", stderr(&output));
        assert!(
            stderr(&output).contains(&format!("claim-missing ({key})")),
            "the refusal must NAME the key, or the author cannot act on it: {key}\n{}",
            stderr(&output)
        );
    }
}

#[test]
fn an_empty_value_is_an_omission_wearing_a_declarations_shape() {
    // The half a presence check misses. `"source_of_truth": ""` satisfies "the
    // key is there" and asserts nothing, which is the prose defect reproduced
    // inside the mechanism meant to remove it.
    //
    // `blockers: []` is the ONE deliberate exception, and it is the absence this
    // row exists to make writable: a row with no blockers must be able to SAY so.
    let dir = with_tasks("ready-claims-empty");
    let mut blank = complete_claims();
    blank["source_of_truth"] = serde_json::json!("   ");
    let output = lint(&dir, &claims_payload(&blank, &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("claim-missing (source_of_truth)"),
        "{}",
        stderr(&output)
    );

    let mut empty_tests = complete_claims();
    empty_tests["tests"] = serde_json::json!([]);
    let refused = lint(&dir, &claims_payload(&empty_tests, &[]));
    assert_eq!(code(&refused), 2, "{}", stderr(&refused));

    let none_blocked = lint(&dir, &claims_payload(&complete_claims(), &[]));
    assert_eq!(
        code(&none_blocked),
        0,
        "an explicit empty blocker list is a declaration, not an omission: {}",
        stderr(&none_blocked)
    );
}

/// CLOUD-472. `mutation` landed under CLOUD-418 as PROSE describing the change
/// that would kill the case — a better claim than nothing, and still joinable to
/// nothing. A slug is joinable: `batten mutate` resolves it, applies the
/// expression, runs the named case, and a survivor is the finding.
///
/// Shape only, at this tier and at this moment: the case does not exist at
/// refinement time, so resolving the slug here would refuse every honest row
/// before its code was written. Whitespace is the whole discriminator, because
/// `mutate`'s own three-field row format already forbids it in a slug.
#[test]
fn a_mutation_written_as_prose_rather_than_a_slug_is_refused() {
    let dir = with_tasks("ready-claims-mutation-prose");
    let mut object = complete_claims();
    object["tests"][0]["mutation"] = serde_json::json!("drop the required-key check");
    let output = lint(&dir, &claims_payload(&object, &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("test-claim-mutation-not-a-slug"),
        "the refusal must name the class: {}",
        stderr(&output)
    );

    // THE REMEDY IS REACHABLE, which is what keeps this from being a wall: the
    // unmodified fixture already carries a slug and passes.
    let clean = lint(&dir, &claims_payload(&complete_claims(), &[]));
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
}

#[test]
fn a_gate_that_names_no_task_is_refused() {
    // The half that makes the mechanism unwritable as prose, which is the row's
    // actual point: a field wants a command, and a sentence does not fit in it.
    //
    // WHETHER THE TASK EXISTS IS NOT ASKED HERE, and that is rule 1 rather than
    // an omission — resolving it means the core naming the consumer's task
    // manifest, which `document_facts.rs` refuses and which caught the first
    // draft of this doing it. `batten.toml`'s `command-task-defined` already
    // decides that question over the consumer's own declaration, so asking it
    // twice would be a second authority with only the newer one deciding.
    let dir = with_tasks("ready-claims-gate-task");
    for gate in [
        serde_json::json!({ "exits": [0, 2] }),
        serde_json::json!({ "task": "   ", "exits": [0, 2] }),
    ] {
        let mut object = complete_claims();
        object["gate"] = gate;
        let output = lint(&dir, &claims_payload(&object, &[]));
        assert_eq!(code(&output), 2, "{}", stderr(&output));
        assert!(
            stderr(&output).contains("gate-task-unnamed"),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn a_gate_exit_outside_the_one_contract_is_refused() {
    let dir = with_tasks("ready-claims-exits");
    let mut object = complete_claims();
    object["gate"] = serde_json::json!({ "task": "verify", "exits": [0, 7] });
    let output = lint(&dir, &claims_payload(&object, &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("gate-exit-outside-contract"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_commit_type_the_arrow_table_does_not_know_is_refused() {
    // THE HOLE THE DERIVATION OPENS, closed. With the bump computed rather than
    // declared there is no wrong answer for a typo to disagree with, so `fixx`
    // would fall through the default arm and read as "releases nothing" — a typo
    // silently becoming a claim. The prose path could not have this defect
    // because it compared two things.
    let dir = with_tasks("ready-claims-type");
    let mut object = complete_claims();
    object["commit_type"] = serde_json::json!("fixx");
    let output = lint(&dir, &claims_payload(&object, &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("commit-type-unknown (fixx)"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_bump_is_derived_from_the_type_rather_than_declared_beside_it() {
    // The class CLOUD-228 and CLOUD-1092 both lived in, removed rather than
    // checked: a declaration cannot disagree with a table it is not compared
    // against. Both arms of CLOUD-1092's split are asserted here too, since the
    // object path emits the fact independently of the prose path.
    let dir = with_tasks("ready-claims-bump");
    for (commit_type, expected) in [
        ("feat", "bump patch"),
        ("fix", "bump patch"),
        ("test", "bump no-release"),
        ("chore", "bump no-release"),
        ("none", "bump none"),
    ] {
        let mut object = complete_claims();
        object["commit_type"] = serde_json::json!(commit_type);
        let output = lint(&dir, &claims_payload(&object, &[]));
        assert_eq!(code(&output), 0, "{commit_type}\n{}", stderr(&output));
        assert!(
            stdout(&output).lines().any(|line| line == expected),
            "{commit_type} => {expected}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn a_claimed_blocker_is_cross_checked_exactly_as_the_prose_clause_is() {
    // The same predicate, reached without a claim scan: a list needs no anchor,
    // no span and no sentence boundary, so every defect CLOUD-1113 and its
    // neighbours record is unreachable from here by construction.
    let dir = with_tasks("ready-claims-blockers");
    let mut object = complete_claims();
    object["blockers"] = serde_json::json!(["CLOUD-29"]);

    let missing = lint(&dir, &claims_payload(&object, &[]));
    assert_eq!(code(&missing), 2, "{}", stderr(&missing));
    assert!(
        stderr(&missing).contains("blocker-cited-without-relation (CLOUD-29)"),
        "{}",
        stderr(&missing)
    );

    let present = lint(&dir, &claims_payload(&object, &["CLOUD-29"]));
    assert_eq!(code(&present), 0, "{}", stderr(&present));
}

#[test]
fn a_test_claim_missing_its_mutation_is_refused() {
    // CLOUD-418's obligation as a field. A §7 paragraph can promise a test and
    // name no way to tell a discriminating one from coverage; an entry missing
    // `mutation` cannot.
    let dir = with_tasks("ready-claims-tests");
    for key in ["file", "mutation"] {
        let mut object = complete_claims();
        let mut entry = serde_json::json!({
            "file": "crates/batten/tests/it/ready.rs",
            "mutation": "drop the required-key check",
        });
        entry.as_object_mut().expect("an object").remove(key);
        object["tests"] = serde_json::json!([entry]);
        let output = lint(&dir, &claims_payload(&object, &[]));
        assert_eq!(code(&output), 2, "{key}\n{}", stderr(&output));
        assert!(
            stderr(&output).contains(&format!("test-claim-incomplete ({key})")),
            "{key}\n{}",
            stderr(&output)
        );
    }
}

#[test]
fn the_object_wins_and_the_prose_goes_unread() {
    // ONE AUTHORITY PER FACT, applied inside a single body. Two readings of one
    // claim can disagree, and a row that disagrees with itself is the shape no
    // reviewer can adjudicate — so §6 and §8 are SKIPPED when an object is
    // present rather than run alongside it and reconciled.
    //
    // The prose here is wrong in both clauses at once: a §6 whose declaration
    // contradicts its type, and a §8 claiming a blocker the board does not
    // carry. Either would refuse the row on the prose path; neither is read.
    let dir = with_tasks("ready-claims-authority");
    let object = serde_json::to_string_pretty(&complete_claims()).expect("encodable");
    let body = format!(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready**\n\n\
         * **Source of truth (§1).** One authoritative artifact.\n\
         * **Commit / bump (§6).** `test` → **minor**.\n\
         * **Blockers (§8).** `blockedBy` CLOUD-404.\n\n\
         ```json\n{object}\n```\n"
    );
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(!text.contains("bump-disagrees-with-type"), "{text}");
    assert!(!text.contains("blocker-cited-without-relation"), "{text}");
    assert!(
        stdout(&output).lines().any(|line| line == "bump patch"),
        "the object's `feat` decides the fact, not the prose's `test`: {}",
        stdout(&output)
    );
}

#[test]
fn a_prose_only_block_still_passes_and_is_named_as_a_dialect() {
    // EVERY ISSUE READY TODAY IS STILL READY. Refusing a prose-only block would
    // refuse ~40 refined rows for being written before the mechanism existed,
    // which is the recognise-to-report bargain this gate already runs twice. The
    // dialect is a FACT rather than a verdict, so a caller can find the rows
    // still to convert without re-reading any body.
    let dir = with_tasks("ready-claims-prose");
    let output = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** `feat` → **patch**."), &[]),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).lines().any(|line| line == "dialect prose"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_body_with_no_ready_block_is_unchanged() {
    let dir = with_tasks("ready-claims-none");
    let output = lint(&dir, &payload("Just a description.\n", &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no-ready-block"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("dialect "),
        "a body with no block has no dialect to name: {}",
        stdout(&output)
    );
}

#[test]
fn a_fence_that_is_not_an_object_is_refused_rather_than_read_as_absent() {
    // The author reached for the mechanism and mis-typed it. Reading that as "no
    // object here" would silently drop them back onto the prose path — the
    // quietest possible failure, and the one this row exists to remove.
    let dir = with_tasks("ready-claims-unparseable");
    let output = lint(&dir, &payload(&claims_block("{ not json"), &[]));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("claims-object-unparseable"),
        "{}",
        stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// The floor, and the deliberate non-behaviour it stands beside.
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_block_passes_and_an_omitted_clause_is_not_a_violation() {
    // THE LOAD-BEARING NON-BEHAVIOUR. The gate document says bodies carry
    // specializations rather than restatements, and the corpus's most thoroughly
    // refined issue omits a clause entirely and is correctly Ready — a lint
    // demanding all eight would fail the best example it has.
    let dir = pre_release("ready-passes");
    let full = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** `ci` → **no bump**."), &[]),
    );
    assert_eq!(code(&full), 0, "{}", stderr(&full));
    let bare = lint(&dir, &payload(&block(""), &[]));
    assert_eq!(code(&bare), 0, "{}", stderr(&bare));
}

#[test]
fn a_block_carrying_no_clause_at_all_is_reported() {
    // CLOUD-299, and the floor exists because "only what is present" without one
    // makes a block with NOTHING present indistinguishable from a refined one.
    // Measured on CLOUD-59: its body opened `**Refinement from the identity
    // decision (CLOUD-123) …**`, carrying no clause — the opener matched, zero
    // clauses were found, zero were checked, and it sat in the ready queue.
    let dir = pre_release("ready-floor");
    let note = "**Refinement from the identity decision (CLOUD-123) — a constraint handed down.**\n\n\
                Nothing here is a clause.\n";
    let output = lint(&dir, &payload(note, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("ready-block-without-clauses"));
}

#[test]
fn a_house_style_cross_reference_does_not_satisfy_the_floor() {
    // The §N namespace is OVERLOADED, which is why the floor anchors on a
    // label+tag pair rather than on a bare `(§N)`: Ready blocks legitimately
    // cite house-style sections in prose, and counting any `(§N)` would let a
    // cross-reference satisfy the floor — the same vacuous pass in a narrower
    // form.
    let dir = pre_release("ready-floor-xref");
    let body = "**Refinement — Ready (a summary)**\n\n\
                Output is pointer-only per §6, and the config is narrow per (§8).\n";
    let output = lint(&dir, &payload(body, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("ready-block-without-clauses"));
}

#[test]
fn a_heading_form_label_counts_as_a_clause() {
    // The heading arm is load-bearing rather than defensive: bodies whose ONLY
    // clause is a `### Blockers (§8)` heading are on the board.
    let dir = pre_release("ready-floor-heading");
    let body = "**Refinement — Ready**\n\n### Blockers (§8)\n\nNone.\n";
    let output = lint(&dir, &payload(body, &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_clause_free_parent_block_is_exempt_from_the_floor() {
    // A parent is exempt BY OPENER, never by count. The gate document tells an
    // epic to "link this document … rather than copying the lists into each
    // issue", so a clause-free parent block is the prescribed shape. Keying the
    // exemption on the count instead would have exempted every empty leaf too.
    let dir = pre_release("ready-parent-floor");
    let body = "## Refinement gate\n\nThe gate for this epic's children.\n";
    let output = lint(&dir, &payload(body, &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// §8: blockers linked, not assumed — the only rule prose cannot fake.
// ---------------------------------------------------------------------------

#[test]
fn a_blocker_cited_in_section_eight_needs_a_matching_relation() {
    let dir = pre_release("ready-blockers");
    let body = block("* **Blockers (§8).** `blockedBy` CLOUD-29 (the loader this validates).");

    let missing = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&missing), 2);
    assert!(
        stderr(&missing).contains("blocker-cited-without-relation (CLOUD-29)"),
        "{}",
        stderr(&missing)
    );

    let present = lint(&dir, &payload(&body, &["CLOUD-29"]));
    assert_eq!(code(&present), 0, "{}", stderr(&present));
}

#[test]
fn a_blocker_noted_as_closed_is_held_to_the_board_like_any_other() {
    // THE `(closed)` EXEMPTION IS GONE, and it was dead code resting on a
    // premise this tracker does not have (CLOUD-678). It stripped `CLOUD-N
    // (closed)` before scanning, on the stated reason that the tracker drops the
    // relation when the dependency resolves. Measured, it is the opposite: the
    // relation SURVIVES — CLOUD-661 has been Done since 2026-08-18 and both of
    // its dependents still carry the edge.
    let dir = pre_release("ready-closed-blocker");
    let body = block("* **Blockers (§8).** `blockedBy` CLOUD-29 (closed).");
    let missing = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&missing), 2);
    assert!(stderr(&missing).contains("blocker-cited-without-relation (CLOUD-29)"));
    let present = lint(&dir, &payload(&body, &["CLOUD-29"]));
    assert_eq!(code(&present), 0, "{}", stderr(&present));
}

#[test]
fn only_a_blocked_by_claim_is_a_claim() {
    // CLAIMS, NOT MENTIONS. A well-formed §8 bullet also cross-references the
    // other relation directions — "`relatedTo` CLOUD-37 — the two share a
    // representation but neither strictly blocks the other" is CORRECT prose
    // whose board relation is relatedTo, and flagging it would punish precision.
    let dir = pre_release("ready-claims");
    for clause in [
        "* **Blockers (§8).** None.",
        "* **Blockers (§8).** `relatedTo` CLOUD-37 — neither strictly blocks the other.",
        "* **Blockers (§8).** `blockedBy` CLOUD-29. Grows in coverage as the tree fills (CLOUD-88).",
    ] {
        let output = lint(&dir, &payload(&block(clause), &["CLOUD-29"]));
        assert_eq!(code(&output), 0, "{clause}\n{}", stderr(&output));
    }
}

#[test]
fn the_english_spelling_of_a_blocker_claim_is_cross_checked_like_the_code_span() {
    // CLOUD-1113, and the measured row is the fixture: CLOUD-438 wrote "blocked
    // by CLOUD-435 phase 2" against `blockedBy: []` and exited 0. The anchor was
    // space-SENSITIVE, so the claim never parsed, the id loop never ran, and the
    // clause passed VACUOUSLY — which is the failure §8 exists to catch arriving
    // through §8's own anchor. Its claim was not merely unchecked but FALSE: the
    // blocker had been Done for some time while the row sat in Backlog behind it.
    //
    // RED BEFORE THE CHANGE (CLOUD-418): with the old `(?i)blockedBy` anchor this
    // case exits 0 on both arms, so it discriminates the widening rather than
    // restating a property that already held.
    let dir = pre_release("ready-english-blocker");
    let body = block(
        "* **Blockers (§8).** blocked by CLOUD-435 phase 2, which builds the invocation path \
         this must use.",
    );

    let missing = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&missing), 2, "{}", stderr(&missing));
    assert!(
        stderr(&missing).contains("blocker-cited-without-relation (CLOUD-435)"),
        "{}",
        stderr(&missing)
    );

    let present = lint(&dir, &payload(&body, &["CLOUD-435"]));
    assert_eq!(code(&present), 0, "{}", stderr(&present));
}

#[test]
fn every_spelling_of_one_claim_reaches_the_same_cross_check() {
    // ONE CONCEPT, THREE SPELLINGS, and the constant carries all three rather
    // than each call site re-spelling it. Capitalisation is the tracker's own —
    // its UI displays the relation as "Blocked by", which is exactly the form the
    // author copies and exactly the one that was invisible.
    let dir = pre_release("ready-blocker-spellings");
    for claim in [
        "`blockedBy` CLOUD-29",
        "blockedBy CLOUD-29",
        "blocked by CLOUD-29",
        "Blocked By CLOUD-29",
        "BLOCKED BY CLOUD-29",
    ] {
        let body = block(&format!("* **Blockers (§8).** {claim}."));
        let missing = lint(&dir, &payload(&body, &[]));
        assert_eq!(code(&missing), 2, "{claim}\n{}", stderr(&missing));
        assert!(
            stderr(&missing).contains("blocker-cited-without-relation (CLOUD-29)"),
            "{claim}\n{}",
            stderr(&missing)
        );
        let present = lint(&dir, &payload(&body, &["CLOUD-29"]));
        assert_eq!(code(&present), 0, "{claim}\n{}", stderr(&present));
    }
}

#[test]
fn the_transitive_blocker_named_in_the_same_sentence_is_a_claim_too() {
    // The second measured row (CLOUD-1089): "blocked by CLOUD-1008, which is
    // itself blocked by CLOUD-1009" while the board carried only the first edge.
    // Written with a space, BOTH ids were invisible; the span rules are untouched,
    // so with the anchor widened the second one is reported — which is the gate
    // working rather than a new strictness this row invents.
    let dir = pre_release("ready-transitive-blocker");
    let body =
        block("* **Blockers (§8).** blocked by CLOUD-1008, which is itself blocked by CLOUD-1009.");
    let partial = lint(&dir, &payload(&body, &["CLOUD-1008"]));
    assert_eq!(code(&partial), 2, "{}", stderr(&partial));
    let text = stderr(&partial);
    assert!(
        text.contains("blocker-cited-without-relation (CLOUD-1009)"),
        "{text}"
    );
    assert!(
        !text.contains("(CLOUD-1008)"),
        "the edge the board carries must not be reported: {text}"
    );

    let both = lint(&dir, &payload(&body, &["CLOUD-1008", "CLOUD-1009"]));
    assert_eq!(code(&both), 0, "{}", stderr(&both));
}

#[test]
fn widening_the_anchor_makes_nothing_else_a_claim() {
    // THE DISCRIMINATORS A CARELESS WIDENING BREAKS, asserted in the direction
    // that would go quiet rather than loud. Each of these must still exit 0 with
    // NO relation on the board at all: if any became a claim, the gate would be
    // refusing prose that asserts nothing about blocking, which is the
    // false-positive rate that gets a gate switched off rather than satisfied.
    let dir = pre_release("ready-anchor-not-wider");
    for clause in [
        // The other relation directions are still scrubbed, not claimed.
        "* **Blockers (§8).** `relatedTo` CLOUD-37 — neither strictly blocks the other.",
        "* **Blockers (§8).** `blocks` CLOUD-37, which waits on this.",
        // A discharged blocker named without a claim opener, which is how a row
        // records provenance: CLOUD-892's §8 relies on exactly this.
        "* **Blockers (§8).** None; the two it once waited on have landed.",
        // Intent-bearing verbs are CLOUD-454's question and are deliberately not
        // this anchor's. Reading them here would silently annex that row's scope.
        "* **Blockers (§8).** None. This depends on CLOUD-37 landing first.",
        "* **Blockers (§8).** None. It needs CLOUD-37 and waits for CLOUD-38.",
        // "blocker" is not "blocked by": a substring widening would match it.
        "* **Blockers (§8).** None. The blocker CLOUD-37 named was discharged.",
    ] {
        let output = lint(&dir, &payload(&block(clause), &[]));
        assert_eq!(code(&output), 0, "{clause}\n{}", stderr(&output));
    }
}

#[test]
fn the_sentence_boundary_still_ends_an_english_claim() {
    // The span rules are untouched by the widening, and this is the one that
    // would be easiest to lose: a trailing cross-reference after the claim
    // sentence asserts nothing about blocking. Asserted on the ENGLISH spelling,
    // because the code-span form already had a case and a widening that carried
    // the anchor but not the span would pass it.
    let dir = pre_release("ready-english-span");
    let body = block(
        "* **Blockers (§8).** blocked by CLOUD-29. Grows in coverage as the tree fills (CLOUD-88).",
    );
    let output = lint(&dir, &payload(&body, &["CLOUD-29"]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn the_rendered_and_stored_mention_forms_are_one_case() {
    // The tracker serialises a mention as `<issue …>CLOUD-N</issue>`, so patterns
    // written against the RENDERED form never match the stored one — and an
    // exemption tested only on plain-text fixtures is dead code in production.
    let dir = pre_release("ready-mentions");
    let body = block(
        "* **Blockers (§8).** `blockedBy` <issue id=\"x\" href=\"y\">CLOUD-29</issue> (closed).",
    );
    let missing = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&missing), 2);
    assert!(stderr(&missing).contains("blocker-cited-without-relation (CLOUD-29)"));
    let present = lint(&dir, &payload(&body, &["CLOUD-29"]));
    assert_eq!(code(&present), 0, "{}", stderr(&present));
}

#[test]
fn the_claim_span_is_a_heading_plus_its_first_paragraph_and_stops_there() {
    // Reading only the LABEL LINE made every heading-form issue pass VACUOUSLY —
    // observed: an issue claiming `blockedBy CLOUD-95` under a heading, with no
    // relation, passed clean. The span is bounded on purpose: a greedier one
    // would swallow later sections and flag ids that assert nothing about
    // blocking.
    let dir = pre_release("ready-span");

    let under_heading = "**Refinement — Ready**\n\n\
                         ### Blockers (§8)\n\n\
                         `blockedBy` CLOUD-95, which must land first.\n";
    let reported = lint(&dir, &payload(under_heading, &[]));
    assert_eq!(code(&reported), 2);
    assert!(stderr(&reported).contains("blocker-cited-without-relation (CLOUD-95)"));
    let linked = lint(&dir, &payload(under_heading, &["CLOUD-95"]));
    assert_eq!(code(&linked), 0, "{}", stderr(&linked));

    let empty_heading = "**Refinement — Ready**\n\n### Blockers (§8)\n\nNone.\n";
    let quiet = lint(&dir, &payload(empty_heading, &[]));
    assert_eq!(code(&quiet), 0, "{}", stderr(&quiet));

    // The span ends at the next heading …
    let next_heading = "**Refinement — Ready**\n\n\
                        ### Blockers (§8)\n\n\
                        None.\n\n\
                        ### Notes\n\n\
                        `blockedBy` CLOUD-77 is discussed here and claimed nowhere.\n";
    let bounded = lint(&dir, &payload(next_heading, &[]));
    assert_eq!(code(&bounded), 0, "{}", stderr(&bounded));

    // … and at the paragraph that ends it.
    let next_paragraph = "**Refinement — Ready**\n\n\
                          ### Blockers (§8)\n\n\
                          None.\n\n\
                          A later paragraph mentioning `blockedBy` CLOUD-78.\n";
    let stopped = lint(&dir, &payload(next_paragraph, &[]));
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
}

// ---------------------------------------------------------------------------
// §6: the commit type and the bump must agree, in the regime the tree is in.
// ---------------------------------------------------------------------------

/// A §6 clause, and the verdict the pre-0.1.0 regime reaches over it.
struct Bump {
    clause: &'static str,
    passes: bool,
    detail: &'static str,
}

#[test]
fn the_bump_agrees_with_the_type_in_the_regime_the_tree_is_in() {
    // WHICH ARROWS FIRE DEPENDS ON THE VERSION. §6 was amended after CLOUD-226
    // measured a `feat!` carrying a BREAKING CHANGE footer releasing as v0.0.23:
    // Cargo gives 0.0.x no compatibility guarantee, so release-plz bumps the
    // patch whatever the type says. Enforcing the retired set is not a neutral
    // staleness — it made the honest declaration the FAILING one, so the gate and
    // the document it gates demanded opposite bytes.
    let dir = pre_release("ready-bump");
    let cases = [
        Bump {
            clause: "* **Commit / bump (§6).** `feat` → **patch** until 0.1.0.",
            passes: true,
            detail: "",
        },
        Bump {
            clause: "* **Commit / bump (§6).** `feat` → **minor**.",
            passes: false,
            detail: "bump-disagrees-with-type (feat implies patch below 0.1.0)",
        },
        Bump {
            clause: "* **Commit / bump (§6).** `feat!` → **major**. BREAKING CHANGE: yes.",
            passes: false,
            detail: "bump-disagrees-with-type",
        },
        Bump {
            clause: "* **Commit / bump (§6).** `feat!` → **patch** until 0.1.0. BREAKING CHANGE: it is, for the consumer surface.",
            passes: true,
            detail: "",
        },
        // "no bump" does NOT collapse: a `ci`/`chore`-only change releases
        // nothing at any version, so folding it into patch would demand a bump
        // the tool never produces — the same error in the other direction.
        Bump {
            clause: "* **Commit / bump (§6).** `chore` → **no bump**.",
            passes: true,
            detail: "",
        },
        // "none" is a valid explicit answer: a tracker-only or repo-config change
        // lands no commit at all, and demanding a type there would force a lie.
        Bump {
            clause: "* **Commit / bump (§6).** **none** — nothing lands.",
            passes: true,
            detail: "",
        },
        Bump {
            clause: "* **Commit / bump (§6).** → **patch**.",
            passes: false,
            detail: "commit-type-missing",
        },
        // A scoped type is a legitimate Conventional Commit declaration.
        Bump {
            clause: "* **Commit / bump (§6).** `fix(gate)` → **patch**.",
            passes: true,
            detail: "",
        },
    ];
    for case in cases {
        let output = lint(&dir, &payload(&block(case.clause), &[]));
        if case.passes {
            assert_eq!(code(&output), 0, "{}\n{}", case.clause, stderr(&output));
        } else {
            assert_eq!(code(&output), 2, "{}", case.clause);
            assert!(
                stderr(&output).contains(case.detail),
                "{}\n{}",
                case.clause,
                stderr(&output)
            );
        }
    }
}

#[test]
fn the_type_token_is_a_whole_code_span_and_never_a_prefix() {
    // CLOUD-290. The closing backtick used to be optional, so the pattern matched
    // a PREFIX of any longer span and any backticked token beginning with a type
    // word was read as the declared type. Measured on two lines differing only in
    // the bump text: "`ci-local-parity`; `feat` → **patch** until 0.1.0" — an
    // honest declaration — was refused as `ci implies no bump`, and
    // "`tests/fanout-guard.bats`; `ci` → **no bump**" passed while reading the
    // type as `test`. The defect was loud exactly when the author was right and
    // silent exactly when it did no damage, which is why it survived.
    let dir = pre_release("ready-span-anchor");
    let honest =
        block("* **Commit / bump (§6).** `ci-local-parity`; `feat` → **patch** until 0.1.0.");
    let passed = lint(&dir, &payload(&honest, &[]));
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));

    let coincidental =
        block("* **Commit / bump (§6).** `tests/fanout-guard.bats`; `ci` → **no bump**.");
    let quiet = lint(&dir, &payload(&coincidental, &[]));
    assert_eq!(code(&quiet), 0, "{}", stderr(&quiet));

    // And a genuine disagreement beside a code span is still refused, so the
    // anchoring did not buy its correctness by going silent.
    let disagreeing =
        block("* **Commit / bump (§6).** `tests/fanout-guard.bats`; `ci` → **minor**.");
    let refused = lint(&dir, &payload(&disagreeing, &[]));
    assert_eq!(code(&refused), 2);
    assert!(stderr(&refused).contains("bump-disagrees-with-type"));
}

#[test]
fn a_house_style_cross_reference_is_not_the_commit_clause() {
    // Anchored on the LABEL + tag pair, never on a bare "(§6)": Ready blocks also
    // cite house-style sections as "(§6)", where §6 means the output contract
    // rather than this clause.
    let dir = pre_release("ready-six-xref");
    let body = block("* **Output (§1).** Pointer-only per (§6), so nothing echoes.");
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn the_break_marker_is_read_off_the_type_token_and_never_off_the_line() {
    // CLOUD-852. This was a match over the whole clause, which has no POLARITY:
    // the corpus's own way of DENYING a break is to write "Not `!`", and that
    // spelling made the gate read `expected = major`. Five rows on the board use
    // it, so the convention is not hypothetical.
    //
    // It went unnoticed because below 0.1.0 the false `major` collapses to
    // `patch`, exactly where `feat` and `fix` already collapse — so for every
    // releasable type the wrong reason produced the right answer. It surfaces
    // only on a type whose expectation is `no bump`, which does not collapse.
    let dir = pre_release("ready-break-polarity");
    let denying = block(
        "* **Commit / bump (§6).** `refactor` → **no bump**. Not `!` for the consumer surface.",
    );
    let output = lint(&dir, &payload(&denying, &[]));
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    // Both real declarations still declare.
    for declaring in [
        "* **Commit / bump (§6).** `refactor!` → **major**.",
        "* **Commit / bump (§6).** `refactor` → **major**. BREAKING CHANGE: the exit table moves.",
    ] {
        let refused = lint(&dir, &payload(&block(declaring), &[]));
        // Below 0.1.0 a declared break collapses to patch, so `major` disagrees.
        assert_eq!(code(&refused), 2, "{declaring}");
        assert!(stderr(&refused).contains("bump-disagrees-with-type"));
    }
}

#[test]
fn a_negative_break_claim_must_name_the_surface_it_denies_about() {
    // CLOUD-842. `batten` IS BOTH A BINARY AND A LIBRARY, so "breaking" names two
    // different objects and §6 has one word for them. Five rows of one bundle
    // declared "not `!`" and every one was reasoning CORRECTLY about the consumer
    // surface — and none of it is what the API comparison measures. The change
    // landed as a `feat(policy)!`.
    //
    // THE PREDICATE IS ABOUT THE CLAIM'S SHAPE, NEVER ITS TRUTH: at refinement
    // time there is no diff to compare, so a gate that guessed would be a judge.
    let dir = pre_release("ready-break-surface");
    let unqualified = block("* **Commit / bump (§6).** `feat` → **patch** until 0.1.0. Not `!`.");
    let refused = lint(&dir, &payload(&unqualified, &[]));
    assert_eq!(code(&refused), 2);
    assert!(stderr(&refused).contains("unqualified-break-claim"));

    for qualified in [
        "* **Commit / bump (§6).** `feat` → **patch** until 0.1.0. Not `!` for the consumer surface.",
        "* **Commit / bump (§6).** `feat` → **patch** until 0.1.0. Not breaking for the library API.",
    ] {
        let passed = lint(&dir, &payload(&block(qualified), &[]));
        assert_eq!(code(&passed), 0, "{qualified}\n{}", stderr(&passed));
    }

    // A clause making no breakage claim at all is untouched.
    let silent = block("* **Commit / bump (§6).** `feat` → **patch** until 0.1.0.");
    let quiet = lint(&dir, &payload(&silent, &[]));
    assert_eq!(code(&quiet), 0, "{}", stderr(&quiet));
}

#[test]
fn the_qualifier_must_attach_to_the_denial_and_not_merely_share_the_line() {
    // CLOUD-832 is exactly why. Its clause reads "Not `!`: the string `deny` path
    // is preserved, so no consumer shape breaks" — the word `consumer` IS on that
    // line, forty characters downstream, as part of the REASONING rather than as
    // the scope of the denial. A bare "does `consumer` appear anywhere" test
    // passes the one row this clause exists to refuse.
    let dir = pre_release("ready-break-attach");
    let as_written = block(
        "* **Commit / bump (§6).** `feat` → **patch** until 0.1.0. Not `!`: the string `deny` \
         path is preserved, so no consumer shape breaks.",
    );
    let output = lint(&dir, &payload(&as_written, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("unqualified-break-claim"));
    // POINTER-ONLY even here: the refusal names the rule and the line, and
    // carries no prose from the clause it refused.
    assert!(
        !stderr(&output).contains("the string `deny` path is preserved"),
        "the refusal echoed the clause: {}",
        stderr(&output)
    );
}

#[test]
fn the_arrows_fire_again_at_or_above_the_released_version() {
    // The regime is read out of the tree, so the gate is a property of the commit
    // rather than a hardcoded set.
    let dir = repo("ready-released", "0.2.0");
    let minor = block("* **Commit / bump (§6).** `feat` → **minor**.");
    let agrees = lint(&dir, &payload(&minor, &[]));
    assert_eq!(code(&agrees), 0, "{}", stderr(&agrees));

    let patch = block("* **Commit / bump (§6).** `feat` → **patch**.");
    let disagrees = lint(&dir, &payload(&patch, &[]));
    assert_eq!(code(&disagrees), 2);
    assert!(stderr(&disagrees).contains("bump-disagrees-with-type (feat implies minor)"));
}

#[test]
fn an_unreadable_workspace_version_is_could_not_look_and_never_a_guess() {
    // A gate that cannot establish its own regime must not guess: guessing either
    // way manufactures a violation or launders one. And the version is read
    // LAZILY, inside the clause — an issue with no §6 needs none, and demanding
    // one would break linting a payload from outside a checkout.
    let dir = Fixture::new("ready-no-version")
        // The grammar still has to be declared: this case is about a missing
        // workspace VERSION, and a fixture missing the grammar too would assert
        // about the wrong absence.
        .config(&format!("version = 1\n\n{}", declared_patterns()))
        .git()
        .base_commit()
        .build();
    let with_clause = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** `feat` → **patch**."), &[]),
    );
    assert_eq!(code(&with_clause), 1);
    let without = lint(&dir, &payload(&block(""), &[]));
    assert_eq!(code(&without), 0, "{}", stderr(&without));
}

// ---------------------------------------------------------------------------
// The openers, the dialects, and the promotion blocker.
// ---------------------------------------------------------------------------

#[test]
fn an_issue_with_no_ready_block_is_reported_and_prose_about_refinement_is_not_one() {
    // The anchors stay tight: a heading or a bold run at the start of a line,
    // never the bare word in prose, so a body that merely discusses refinement is
    // still blockless.
    let dir = pre_release("ready-openers");
    let none = lint(&dir, &payload("Just a description.\n", &[]));
    assert_eq!(code(&none), 2);
    assert!(stderr(&none).contains("no-ready-block"));

    let prose = lint(
        &dir,
        &payload("We should think about refinement before starting.\n", &[]),
    );
    assert_eq!(code(&prose), 2);
    assert!(stderr(&prose).contains("no-ready-block"));
}

#[test]
fn a_parents_refinement_gate_heading_is_a_ready_block() {
    // Matching only the leaf form reported `no-ready-block` on every correctly
    // refined epic, which is the worst kind of false negative: it would have
    // pushed authors to rename a heading the spec prescribes purely to satisfy a
    // lint. Measured on CLOUD-7 — identical content passes under the leaf opener
    // and fails under the parent's.
    let dir = pre_release("ready-parent");
    for heading in ["## Refinement gate", "### Refinement gate"] {
        let body = format!("{heading}\n\nThe gate for this epic's children.\n");
        let output = lint(&dir, &payload(&body, &[]));
        assert_eq!(code(&output), 0, "{heading}\n{}", stderr(&output));
    }

    // And a clause inside a parent block is still CHECKED — the exemption is from
    // the floor, never from the rules.
    let claiming = "## Refinement gate\n\n\
                    * **Blockers (§8).** `blockedBy` CLOUD-29.\n";
    let held = lint(&dir, &payload(claiming, &[]));
    assert_eq!(code(&held), 2);
    assert!(stderr(&held).contains("blocker-cited-without-relation (CLOUD-29)"));
}

#[test]
fn the_non_canonical_opener_is_reported_and_its_content_still_judged() {
    // CLOUD-299. The dialect four issues on the board actually use. Leaving it
    // unrecognised made the anchor wrong in BOTH directions at once: those bodies
    // reported no-ready-block, which was the right verdict for the three carrying
    // open preconditions but reached by accident. Recognising it moves the
    // verdict onto the content; naming it converges the corpus.
    let dir = pre_release("ready-opener-dialect");
    let body = "**Definition of ready**\n\n\
                * **Source of truth (§1).** One artifact.\n\
                * **Blockers (§8).** `blockedBy` CLOUD-29.\n";
    let output = lint(&dir, &payload(body, &[]));
    assert_eq!(code(&output), 2);
    let text = stderr(&output);
    assert!(text.contains("non-canonical-ready-opener"), "{text}");
    assert!(
        text.contains("blocker-cited-without-relation (CLOUD-29)"),
        "{text}"
    );
}

#[test]
fn the_retired_clause_notation_is_reported_rather_than_silently_accepted() {
    // Accepting both dialects silently is what lets drift accumulate, and nothing
    // lints today, so the cost of converging is at its minimum.
    let dir = pre_release("ready-notation");
    let body = block("* **Blockers (clause 8).** None.");
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("non-canonical-clause-notation"));
}

#[test]
fn an_open_questions_marker_blocks_ready() {
    // The questions-are-artifacts protocol: an agent that hits a real ambiguity
    // writes it onto the issue and moves on, and the issue stays OUT of the ready
    // queue. That only holds if the marker is a gate — otherwise a question can
    // be written and the issue promoted anyway, which is the silent-rot case.
    let dir = pre_release("ready-open-questions");
    let body = block("* **Open questions blocking Ready.** Which store owns this?");
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("open-questions-block-ready"));
}

// ---------------------------------------------------------------------------
// §7: a new deny gate reports its firing rate before its severity is chosen.
// ---------------------------------------------------------------------------

#[test]
fn a_deny_gate_owes_a_replay_and_a_warn_gate_does_not() {
    // CLOUD-751. THE CONJUNCTION IS WHAT KEEPS THIS OFF THE REST OF THE CORPUS:
    // it fires only on a block that BOTH introduces a gate AND declares `deny`. A
    // `warn` that fires often is noise a reader can weigh, where a `deny` that
    // fires often stops the fleet, which is why the obligation attaches to `deny`
    // alone.
    //
    // PRESENCE AND SHAPE ONLY, NEVER WHETHER THE NUMBER IS GOOD: judging an
    // acceptable false-positive rate is a model verdict. The author reports; the
    // reader decides.
    let dir = pre_release("ready-replay");

    let unmeasured =
        block("* **Mechanism (§7).** A new `mise-tasks/stray-check` with **deny** severity.");
    let refused = lint(&dir, &payload(&unmeasured, &[]));
    assert_eq!(code(&refused), 2);
    assert!(stderr(&refused).contains("deny-without-replay"));
    // Pointer-only: the report names the rule and the line and no text of the
    // block it refused.
    assert!(!stderr(&refused).contains("stray-check` with"));

    let measured = block(
        "* **Mechanism (§7).** A new `mise-tasks/stray-check` with **deny** severity.\n\
         * **Replay (§7).** Replayed over this repository's own history: 59 commits, 2 would-fire, \
         0 false positives.",
    );
    let passed = lint(&dir, &payload(&measured, &[]));
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));

    let warned =
        block("* **Mechanism (§7).** A new `mise-tasks/stray-check` at severity = \"warn\".");
    let untouched = lint(&dir, &payload(&warned, &[]));
    assert_eq!(code(&untouched), 0, "{}", stderr(&untouched));

    // A block introducing NO gate is untouched, which is most of the corpus.
    let ordinary = block("* **Mechanism (§7).** A new function in `capture.rs`, **deny** nothing.");
    let silent = lint(&dir, &payload(&ordinary, &[]));
    assert_eq!(code(&silent), 0, "{}", stderr(&silent));
}

#[test]
fn a_fenced_rule_declaration_is_a_gate_introduction_too() {
    let dir = pre_release("ready-replay-fence");
    let body = block(
        "* **Mechanism (§7).**\n\n```toml\n[[rule]]\nid = \"stray\"\nseverity = \"deny\"\n```",
    );
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("deny-without-replay"));
}

// ---------------------------------------------------------------------------
// The could-not-look channel, and what outranks it.
// ---------------------------------------------------------------------------

/// A payload built by hand, so a case can omit the `relations` key entirely —
/// which is a different answer from carrying it empty.
fn raw_payload(value: &serde_json::Value) -> String {
    value.to_string()
}

#[test]
fn a_missing_relations_key_is_a_gap_and_never_a_phantom_blocker() {
    // CLOUD-679. ABSENT AND PRESENT-BUT-EMPTY ARE TWO DIFFERENT ANSWERS, and for
    // the shell program's whole life they were one empty string: a caller who
    // fetched without the relations got every citation reported as
    // `blocker-cited-without-relation` — the gate accusing a correctly-refined
    // issue of citing a phantom blocker, and implying a remedy for a relation
    // that already exists. Measured on CLOUD-326, same body, only the key
    // differing: four violations with it stripped, exit 0 with it injected.
    let dir = pre_release("ready-gap");
    let body = block("* **Blockers (§8).** `blockedBy` CLOUD-29.");

    let no_key = raw_payload(&serde_json::json!({ "id": "CLOUD-999", "description": body }));
    let gap = lint(&dir, &no_key);
    assert_eq!(code(&gap), 1, "{}", stderr(&gap));
    let text = stderr(&gap);
    assert!(text.contains("unjudgeable-relations"), "{text}");
    assert!(!text.contains("blocker-cited-without-relation"), "{text}");

    // PRESENT AND EMPTY IS AN ANSWER, so the citation still reports.
    let empty = lint(&dir, &payload(&body, &[]));
    assert!(stderr(&empty).contains("blocker-cited-without-relation"));

    // And present and carrying the id passes.
    let carried = lint(&dir, &payload(&body, &["CLOUD-29"]));
    assert_eq!(code(&carried), 0, "{}", stderr(&carried));
}

#[test]
fn a_judgeable_violation_outranks_the_gap() {
    // THE ORDER IS THE RULE (CLOUD-679), and it is the OPPOSITE of the usual "2
    // outranks 1", deliberately: the block is wrong regardless of what could not
    // be seen, and downgrading it to could-not-look would launder a real defect
    // behind a caller's thin fetch. The pointer prints on both arms, so nothing
    // the gate noticed is swallowed.
    let dir = pre_release("ready-order");
    let body = block(
        "* **Blockers (§8).** `blockedBy` CLOUD-29.\n\
         * **Commit / bump (§6).** `feat` → **minor**.",
    );
    let value = serde_json::json!({ "id": "CLOUD-999", "description": body });
    let output = lint(&dir, &raw_payload(&value));
    assert_eq!(code(&output), 2);
    let text = stderr(&output);
    assert!(text.contains("bump-disagrees-with-type"), "{text}");
    assert!(text.contains("unjudgeable-relations"), "{text}");
}

#[test]
fn a_missing_key_costs_nothing_when_the_block_cites_nothing() {
    // Finding the citation is what makes "the missing key is the SOLE reason"
    // computable at all: a payload with no key and nothing cited lost nothing.
    let dir = pre_release("ready-gap-quiet");
    let value = serde_json::json!({ "id": "CLOUD-999", "description": block("") });
    let output = lint(&dir, &raw_payload(&value));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn the_deferral_rule_carries_the_same_gap_and_it_reaches_further() {
    // CLOUD-197. Unlike §8 this is checked over the WHOLE description: a deferral
    // is most often written in Done, in an Open questions list, or in an
    // out-of-scope note, and those are exactly the places an obligation goes to
    // die. So a key-stripped payload reported one phantom hand-off per citation
    // anywhere in the body — CLOUD-326 measured three.
    let dir = pre_release("ready-deferral");
    let body = format!("{}\n\nThe rest is deferred to CLOUD-44.\n", block(""));

    let no_key = serde_json::json!({ "id": "CLOUD-999", "description": body });
    let gap = lint(&dir, &raw_payload(&no_key));
    assert_eq!(code(&gap), 1);
    let text = stderr(&gap);
    assert!(text.contains("unjudgeable-relations"), "{text}");
    assert!(!text.contains("deferral-cited-without-relation"), "{text}");

    // Present and empty is an answer, so the hand-off is reported …
    let unlinked = serde_json::json!({
        "id": "CLOUD-999",
        "description": body,
        "relations": { "blockedBy": [] },
    });
    let reported = lint(&dir, &raw_payload(&unlinked));
    assert_eq!(code(&reported), 2);
    assert!(stderr(&reported).contains("deferral-cited-without-relation (CLOUD-44)"));

    // … and ANY relation direction satisfies it, because a deferral is not
    // necessarily a blocker and demanding `blockedBy` would push authors to
    // declare false dependencies to pass a lint.
    let related = serde_json::json!({
        "id": "CLOUD-999",
        "description": body,
        "relations": { "relatedTo": [{ "id": "CLOUD-44" }] },
    });
    let passed = lint(&dir, &raw_payload(&related));
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
}

#[test]
fn a_payload_with_no_description_is_could_not_look_and_names_the_field() {
    // Exit 2 is "I could not read the input", distinct from exit 1 "the block is
    // wrong" — a caller piping the wrong thing must not look like a failing issue.
    let dir = pre_release("ready-no-description");
    let output = lint(
        &dir,
        &raw_payload(&serde_json::json!({ "id": "CLOUD-999" })),
    );
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains(".description"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn unparseable_input_is_could_not_look_rather_than_a_verdict() {
    // CHANGED, and recorded rather than quietly carried: the shell program exited
    // 2 here through its own `jq` refusal, and this exits 2 through the crate's
    // usage channel — the same answer, reached by the exit table's own `1` for a
    // malformed invocation being unavailable to a verb whose could-not-look is
    // already 2. A caller branching on the code sees no change.
    let dir = pre_release("ready-unparseable");
    let output = lint(&dir, "not json at all\n");
    assert_eq!(code(&output), 1);
}

#[test]
fn a_payload_carrying_only_the_declared_field_set_is_judged_on_its_merits() {
    // CLOUD-526 declares that a caller may project everything but the fields the
    // predicate names away, so the narrowest legitimate payload must reach a
    // verdict rather than a refusal.
    let dir = pre_release("ready-projection");
    let value = serde_json::json!({
        "id": "CLOUD-999",
        "description": block("* **Commit / bump (§6).** `ci` → **no bump**."),
        "relations": { "blockedBy": [] },
    });
    let output = lint(&dir, &raw_payload(&value));
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

// ---------------------------------------------------------------------------
// The derived facts, and the position that makes them correct.
// ---------------------------------------------------------------------------

#[test]
fn the_bodys_cited_keys_are_emitted_before_any_verdict() {
    // CLOUD-806. The position is the whole of its correctness: `cites-body` is a
    // property of the BODY, not of the Ready block. An unrefined row still cites
    // rows, and the tracker still mints an edge per citation from it — so
    // emitting it after the `no-ready-block` refusal would make the fact
    // unavailable for exactly the rows most likely to carry a stray citation, and
    // a consumer would read that absence as "could not look" over a body read
    // perfectly well.
    let dir = pre_release("ready-emissions");

    let refined = lint(
        &dir,
        &payload(
            &block("* **Blockers (§8).** `blockedBy` CLOUD-29."),
            &["CLOUD-29"],
        ),
    );
    assert!(
        stdout(&refined).contains("cites-body CLOUD-29"),
        "{}",
        stdout(&refined)
    );

    // AN UNREFINED BODY STILL EMITS ITS CITED KEYS — the case the position exists
    // for.
    let unrefined = lint(
        &dir,
        &payload(
            "No block at all, but it cites CLOUD-29 and CLOUD-10.\n",
            &[],
        ),
    );
    assert_eq!(code(&unrefined), 2);
    assert!(
        stdout(&unrefined).contains("cites-body CLOUD-10 CLOUD-29"),
        "{}",
        stdout(&unrefined)
    );

    // Byte-stable and NUMERIC by issue number, not lexical: `CLOUD-10` sorts
    // before `CLOUD-9` lexically, so a caller diffing two runs could not tell an
    // ordering change from a content one.
    let ordered = lint(
        &dir,
        &payload("Cites CLOUD-9 then CLOUD-10 then CLOUD-9 again.\n", &[]),
    );
    assert!(
        stdout(&ordered).contains("cites-body CLOUD-9 CLOUD-10"),
        "{}",
        stdout(&ordered)
    );

    // A LINE PRESENT WITH NO KEYS is the honest empty set; an ABSENT line is
    // "this run never got here", which is a different answer.
    //
    // **THE TRAILING SEPARATOR IS PART OF THAT ANSWER** (CLOUD-1100). This case
    // asserted `line == "cites-body"` for its whole life, which carried the
    // property and lost the bytes: the program this replaced emits
    // `cites-body `, and the only mechanical consumer strips that exact prefix —
    // so the trimmed spelling reads to it as *could not look* rather than as the
    // empty set this case is about. Asserting the separator is what stops the
    // trim coming back.
    let nothing = lint(&dir, &payload(&block(""), &[]));
    assert!(
        stdout(&nothing).lines().any(|line| line == "cites-body "),
        "{}",
        stdout(&nothing)
    );
}

#[test]
fn the_section_eight_span_emits_its_keys_as_their_own_set() {
    // A SEPARATE LINE from `cites-body`, and not for tidiness: its span does not
    // exist until the §8 scan, so a caller can be handed one set and not the
    // other — and an absent line means "this run never got far enough to know",
    // per set.
    let dir = pre_release("ready-emissions-blockers");
    let body = block("* **Blockers (§8).** `blockedBy` CLOUD-29. See also CLOUD-88.");
    let output = lint(&dir, &payload(&body, &["CLOUD-29"]));
    let text = stdout(&output);
    assert!(text.contains("cites-blockers CLOUD-29"), "{text}");
    assert!(text.contains("cites-body CLOUD-29 CLOUD-88"), "{text}");
}

#[test]
fn the_section_six_declaration_is_emitted_as_one_token() {
    // CLOUD-735. `graph-check`'s `in-review-no-pr` keys on a PR attachment, which
    // a row that lands no commit can never acquire — so reading this fact lets it
    // exempt exactly the rows that SAY they land nothing, without inventing a
    // vocabulary and without judging prose.
    //
    // ONE TOKEN, and `none` rather than the internal `no bump`: every other
    // emission is whitespace-free so a consumer can read it with one split.
    //
    // **THIS CASE ASSERTED THE DEFECT** (CLOUD-1092). It read `` `ci` → **no
    // bump** `` and demanded `bump none`, which is exactly the collision: a
    // `ci`-typed row releases nothing AND lands a commit, and the one consumer
    // reads `none` as *lands nothing* and refuses the row at In Review for
    // carrying the PR it exists to carry. The type-bearing arm is now
    // `no-release`; the commitless arm below is what `none` is reserved for.
    let dir = pre_release("ready-emissions-bump");
    let landing = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** `ci` → **no bump**."), &[]),
    );
    assert!(
        stdout(&landing)
            .lines()
            .any(|line| line == "bump no-release"),
        "a non-releasing TYPE still lands a commit: {}",
        stdout(&landing)
    );

    let commitless = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** **none**."), &[]),
    );
    assert!(
        stdout(&commitless).lines().any(|line| line == "bump none"),
        "`none` is reserved for the row that declares it lands nothing: {}",
        stdout(&commitless)
    );

    let releasable = lint(
        &dir,
        &payload(
            &block("* **Commit / bump (§6).** `feat` → **patch** until 0.1.0."),
            &[],
        ),
    );
    assert!(
        stdout(&releasable).lines().any(|line| line == "bump patch"),
        "{}",
        stdout(&releasable)
    );

    // EMITTED INSIDE THE CLAUSE: unlike `cites-body`, whose span is the whole
    // body, this fact does not exist for a row carrying no §6 — and a row with no
    // clause must read as "did not say", never as "said none".
    let silent = lint(&dir, &payload(&block(""), &[]));
    assert!(
        !stdout(&silent).contains("bump "),
        "a row with no §6 clause must emit no bump line: {}",
        stdout(&silent)
    );
}

#[test]
fn every_non_releasing_type_lands_a_commit_and_says_so() {
    // THE PAIR IS THE DISCRIMINATOR, never either half alone (CLOUD-1092). A
    // split that quietly collapsed one arm into the other would pass a one-sided
    // test: emitting `no-release` everywhere loses CLOUD-735's exemption, and
    // emitting `none` everywhere restores the contradiction this row exists to
    // remove. So both are asserted here, over the same producer, in one case.
    let dir = pre_release("ready-bump-two-questions");

    // §6's arrow table maps ALL of these to `no bump`, so every one of them was
    // refused at In Review before this change. Enumerated rather than sampled:
    // the collision is a property of the arrow table's default arm, so a case
    // that tested one type would go quiet if the arm were narrowed.
    for commit_type in [
        "test", "ci", "chore", "docs", "refactor", "style", "build", "perf",
    ] {
        let output = lint(
            &dir,
            &payload(
                &block(&format!(
                    "* **Commit / bump (§6).** `{commit_type}` → **no bump**."
                )),
                &[],
            ),
        );
        assert_eq!(code(&output), 0, "{commit_type}\n{}", stderr(&output));
        assert!(
            stdout(&output)
                .lines()
                .any(|line| line == "bump no-release"),
            "{commit_type} releases nothing and still lands a commit: {}",
            stdout(&output)
        );
    }

    // CLOUD-735's shape, unchanged: no bump AND no type is the row that declares
    // it lands nothing — the only shape that can never acquire a PR, and so the
    // only one the consumer's exemption is for. `commit-type-missing` must not
    // fire on it either, which is what makes the declaration writable at all.
    let record = lint(
        &dir,
        &payload(&block("* **Commit / bump (§6).** **none**."), &[]),
    );
    assert_eq!(code(&record), 0, "{}", stderr(&record));
    assert!(
        stdout(&record).lines().any(|line| line == "bump none"),
        "{}",
        stdout(&record)
    );
}

#[test]
fn a_test_typed_row_can_satisfy_both_gates_at_once() {
    // CLOUD-106 is the live instance, and its §6 is the fixture: `test` → no
    // bump, a row that lands real work. Before this change it emitted `none` and
    // was refused at In Review as `declares-no-commit-with-pr` — the acceptance
    // clause, as a case.
    //
    // Both halves are asserted because passing §6 was never the problem: the row
    // ALWAYS exited 0 here. What changed is the fact it hands the consumer, so
    // the emission is the half that discriminates and the exit code is the half
    // that proves no clause was loosened to get it.
    let dir = pre_release("ready-bump-test-typed");
    let output = lint(
        &dir,
        &payload(
            &block(
                "* **Commit / bump (§6).** `test` → **no bump**: golden manifests change no \
                 behaviour.",
            ),
            &[],
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        !stdout(&output).lines().any(|line| line == "bump none"),
        "the fact the consumer reads as `lands nothing` must not be spent here: {}",
        stdout(&output)
    );
}

// ---------------------------------------------------------------------------
// Rule 4, asserted rather than hoped.
// ---------------------------------------------------------------------------

#[test]
fn no_line_of_the_issue_reaches_the_output() {
    // Issue bodies can carry consumer detail, and a lint that echoed them would
    // leak it through CI logs. Asserted as a SUBSTRING sweep over the body rather
    // than as a spot check on one message, because the property is about every
    // channel this verb writes.
    let dir = pre_release("ready-pointer-only");
    let secret = "ACME Corporation's production account 0123456789";
    let body = format!(
        "**Refinement — Ready**\n\n\
         * **Source of truth (§1).** {secret}\n\
         * **Blockers (§8).** `blockedBy` CLOUD-29.\n\
         * **Commit / bump (§6).** `feat` → **minor**.\n"
    );
    let output = lint(&dir, &payload(&body, &[]));
    assert_eq!(code(&output), 2);
    let emitted = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        !emitted.contains(secret),
        "the issue's prose reached the output: {emitted}"
    );
    assert!(
        !emitted.contains("One authoritative artifact"),
        "the issue's prose reached the output: {emitted}"
    );
    // And it still SAID something: a pointer-only assertion over a silent verb
    // would pass while measuring nothing.
    assert!(stderr(&output).contains("blocker-cited-without-relation"));
}

// ---------------------------------------------------------------------------
// `--issue`: the route that spends a payload without paying for it twice.
// ---------------------------------------------------------------------------

#[test]
fn an_issue_key_against_an_empty_store_is_could_not_look_and_never_a_verdict() {
    // THE DISCRIMINATING CASE for CLOUD-1121's arm, and the reason it is written
    // this way: the easy implementation falls through to stdin when the store
    // cannot answer, and given a key and a CLOSED stdin it then reads an empty
    // payload and reports the row unrefined — a verdict about the store wearing
    // the costume of a verdict about the issue. An empty store is the only input
    // that tells could-not-look from an unrefined block apart.
    let dir = pre_release("ready-empty-store");
    let output = run_with_stdin(&dir, &["ready", "lint", "--issue", "CLOUD-42"], "");
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("CLOUD-42"), "{text}");
    assert!(
        !text.contains("no-ready-block"),
        "an empty store must not read as an unrefined block: {text}"
    );
}

/// Seed a `get_issue` response into the repository's capture store by driving the
/// engine's own `PostToolUse` event.
///
/// **Written by the ENGINE rather than placed in the store by this test**, which
/// is the whole reason this tier exists: a fixture that assembled the store by
/// hand would prove the reader can read what the test writes, and say nothing
/// about whether the writer produces it.
fn seed_response(dir: &Path, home: &Path, document: &serde_json::Value) {
    use std::io::Write as _;
    use std::process::Stdio;

    let envelope = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "session_id": "ready-suite",
        "tool_name": "mcp__tracker__get_issue",
        "tool_input": {},
        "tool_response": [{ "type": "text", "text": document.to_string() }],
    })
    .to_string();
    let mut command = common::batten();
    command
        .args(["hook", "--harness", "claude-code"])
        .current_dir(dir)
        .env_remove("BATTEN_HOOK_BYPASS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    common::state_home(&mut command, home);
    let mut child = command.spawn().expect("spawn the post-tool hook");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(envelope.as_bytes())
        .expect("write the response");
    let recorded = child.wait_with_output().expect("record the response");
    assert_eq!(
        recorded.status.code(),
        Some(0),
        "the post-tool hook must accept the response: {}",
        String::from_utf8_lossy(&recorded.stderr)
    );
}

#[test]
fn an_issue_key_reaches_the_same_verdict_as_the_piped_payload_with_stdin_closed() {
    // THE ACCEPTANCE CASE for CLOUD-1121's resolve half. The premise the row was
    // filed over is that a board sweep spends ~234k tokens of context so a gate
    // can read the same bytes off disk; this is the assertion that the bytes are
    // reachable WITHOUT the read, and that the verdict is identical either way.
    //
    // Stdin is CLOSED, deliberately: an implementation that quietly keeps reading
    // it passes every manual test and fails only here.
    let dir = pre_release("ready-resolve");
    let home = dir.join(".home");
    std::fs::create_dir_all(&home).expect("a state home");

    let body = block("* **Commit / bump (§6).** `ci` → **no bump**.");
    let document = serde_json::json!({
        "id": "CLOUD-424",
        "status": "Todo",
        "description": body,
    });
    seed_response(&dir, &home, &document);

    let piped = {
        let mut command = common::batten();
        command.args(["ready", "lint"]).current_dir(&dir);
        common::state_home(&mut command, &home);
        run_piped(command, &raw_payload(&document))
    };
    assert_eq!(code(&piped), 0, "{}", stderr(&piped));

    let resolved = {
        let mut command = common::batten();
        command
            .args(["ready", "lint", "--issue", "CLOUD-424"])
            .current_dir(&dir);
        common::state_home(&mut command, &home);
        run_piped(command, "")
    };
    assert_eq!(code(&resolved), 0, "{}", stderr(&resolved));
    assert_eq!(
        stdout(&piped),
        stdout(&resolved),
        "the two routes must reach one verdict, byte for byte"
    );
}

/// Run a prepared command with `input` on stdin, closed immediately after.
///
/// A census row (CLOUD-320): this drives the verb under test as a consumer
/// invokes it, which is the whole point of the compiled-binary tier — `common`'s
/// helpers cannot both pipe stdin and carry a per-case state home.
#[expect(
    clippy::disallowed_types,
    reason = "stays, because the compiled-binary tier is a spawn by definition"
)]
fn run_piped(mut command: std::process::Command, input: &str) -> Output {
    use std::io::Write as _;
    use std::process::Stdio;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn batten");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("collect batten's output")
}

/// A clause label that lost its emphasis is STILL A CLAUSE (CLOUD-1330).
///
/// The tracker's normaliser first absorbs the trailing space into the bold and
/// then, on any later save, strips the emphasis outright — measured on
/// CLOUD-1221, where one `patch` appending a repair note left six of nine labels
/// plain. CLOUD-1082's `clause-label-not-anchored` reported that and asked for a
/// re-bold, which the next save undid: a treadmill. So a block whose EVERY label
/// is plain lints clean, and the §6 it carries is judged rather than skipped —
/// the disagreeing bump below is what proves the clause was read.
#[test]
fn a_block_whose_every_label_is_plain_is_judged_on_every_clause() {
    let dir = repo("plain-labels", "0.0.1");
    // No bolded label anywhere: [`block`]'s §1 is replaced wholesale.
    let body = payload(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready (a summary)**\n\n\
         * Source of truth (§1). One authoritative artifact.\n\
         * Test obligation (§7). Over the compiled binary.\n\
         * Commit / bump (§6). `feat` → **patch** until 0.1.0.\n",
        &[],
    );
    let output = lint(&dir, &body);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("ready-block-without-clauses") && !stderr.contains("not-anchored"),
        "plain labels are clauses, not a block with none: {stderr}"
    );
    assert_eq!(
        code(&output),
        0,
        "a wholly plain block lints clean: {stderr}"
    );

    // THE CLAUSE IS READ, NOT MERELY TOLERATED: the same block with a bump that
    // disagrees with its declared type is refused on §6, which a skipped clause
    // could not be.
    let disagreeing = payload(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready (a summary)**\n\n\
         * Source of truth (§1). One authoritative artifact.\n\
         * Commit / bump (§6). `feat` → **no bump**.\n",
        &[],
    );
    let output = lint(&dir, &disagreeing);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bump-disagrees-with-type"),
        "a plain §6 is judged, so a disagreeing bump is refused: {stderr}"
    );
}

/// THE ANTI-VACUITY HALF, in both directions. A block carrying NO clause still
/// hits the floor — so the plain arm is not "every bullet is a clause" — and a
/// bolded label beside prose that cites two clauses is still one clause and no
/// finding, which is what keeps the arm no looser than the anchor it joined.
#[test]
fn a_clause_free_block_still_hits_the_floor_and_prose_is_still_not_a_label() {
    let dir = repo("plain-labels-negative", "0.0.1");
    let none = payload(
        "**Why**\nSomething needs doing.\n\n\
         **Refinement — Ready (a summary)**\n\n\
         * The rationale is spelled out in §1 below, and see (§7) for the tier.\n\
         * A bullet that mentions clause 6 in passing and moves on.\n",
        &[],
    );
    let output = lint(&dir, &none);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ready-block-without-clauses"),
        "prose citing a clause is not a label, so this block has none: {stderr}"
    );

    let body = payload(
        &block(
            "* **Test obligation (§7).** Over the compiled binary.\n             * The rationale is spelled out in §1 below, and see (§7) for the tier.",
        ),
        &[],
    );
    let output = lint(&dir, &body);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(code(&output), 0, "nothing here is a violation: {stderr}");
}
