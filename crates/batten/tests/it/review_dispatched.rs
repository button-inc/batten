//! `review-dispatched`, over the engine that builds its input (CLOUD-472).
//!
//! # The seam, and why the module's own suite cannot reach it
//!
//! `policy/review-dispatched.rego`'s `test_` rules pin the predicate against a
//! fabricated document. The question that decides whether this gate is alive is a
//! different one, and it has two halves the module cannot ask:
//!
//! * does the ENGINE dispatch the vendored prompt on a miss, and put what came
//!   back at `input.tree.review` under the declared id?
//! * is the record KEYED so that a review of other bytes does not answer?
//!
//! The second is the one a `with input as` case actively hides: it fabricates the
//! map, so it fabricates the keying the whole fact turns on. A module suite would
//! pass identically over an engine that ignored the subject digest entirely.
//!
//! # The runner is a stub, and that is the whole contract
//!
//! `judge_kind.rs` states the doctrine for this repository and it carries here
//! unchanged: the engine's contract with a dispatched program is *what it writes
//! and what it exits*, so a stub that exits on demand exercises the whole of it.
//! Driving a real agent would make these cases a test of somebody's model rather
//! than of this wiring, and would make the failure arms — a non-zero exit, a
//! stream that is not pointers — unreachable, since you cannot ask a real agent to
//! misbehave on demand.

// UNIX-ONLY, AND THE WINDOWS FAILURE WOULD BE A FALSE GREEN RATHER THAN A
// COULD-NOT-RUN. Every case below drives a `#!/bin/sh` stub through
// `exec::piped`, and only unix makes it executable — the `set_permissions` call
// in `stub` is already `#[cfg(unix)]`. On Windows the spawn fails, the dispatch
// leaves no record, and absence is exactly what this gate refuses: the refusal
// cases would pass FOR THE WRONG REASON while
// `a_dispatched_review_reaches_the_predicate_and_is_clean` failed.
//
// That asymmetry is the reason to gate the module rather than the one clean case.
// A suite whose negative arms pass because the subject never ran is the vacuous
// pass this whole family exists to refuse, and it would read as coverage.
//
// `bot_lane.rs`, `session_provisioning.rs` and `connector_allow_door.rs` gate
// their whole suites on this rung for the same reason. A `.cmd` twin of the stub
// would be a second authority over what the runner answers.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

use batten::rules::{self, Rule, RuleKind, RuleScope};

const RULE: &str = "review-dispatched";
const REVIEW: &str = "ready-pressure-test";
const SUBJECT: &str = "subject.md";

/// A fixture repository carrying a subject and a stub runner.
///
/// `emits` is what the stub prints and `code` what it exits, so every arm of the
/// dispatch contract is reachable from one helper.
fn repo(name: &str, subject: &str, emits: &str, code: i32) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    common::git_in(&root, &["config", "user.email", "t@example.com"]);
    common::git_in(&root, &["config", "user.name", "t"]);
    fs::write(root.join(SUBJECT), subject).expect("the subject");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    // `origin/main` at the EMPTY tree, so the subject reads as added — the delta
    // the row's narrowing asks about. A local ref rather than a fetch: the
    // question is entirely local and a network round trip would make every case
    // below depend on it.
    let empty = common::git_in(&root, &["hash-object", "-t", "tree", "/dev/null"]);
    let base = common::git_in(&root, &["commit-tree", empty.trim(), "-m", "empty"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", base.trim()],
    );

    install_module(&root);
    stub(&root, emits, code);
    root
}

/// The stub runner, written where the row points and made executable.
///
/// It records every invocation by appending to `calls`, which is what the
/// cache-hit case reads: "did not spawn again" is only checkable by counting
/// spawns, never by looking at the record, since a hit and a second identical
/// dispatch leave byte-identical records.
fn stub(root: &Path, emits: &str, code: i32) {
    let path = root.join("runner.sh");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = setup ]; then printf '%s' \"$(cat \"$(dirname \"$0\")/ready\")\"; exit 0; fi\n\
             cat >/dev/null\n\
             echo \"$@\" >> \"$(dirname \"$0\")/calls\"\n\
             printf '%s' {emits:?}\n\
             exit {code}\n"
        ),
    )
    .expect("write the stub");
    // The probe's answer lives beside the stub so a case can set it without
    // rewriting the program: readiness is what varies, not the runner.
    fs::write(root.join("ready"), r#"{"ready": true}"#).expect("write the probe answer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("make it executable");
    }
}

fn calls(root: &Path) -> usize {
    fs::read_to_string(root.join("calls")).map_or(0, |text| text.lines().count())
}

fn install_module(root: &Path) {
    let source = common::at_root("policy/review-dispatched.rego")
        .canonicalize()
        .expect("the committed module is where the row says it is");
    fs::create_dir_all(root.join("policy")).expect("scratch policy dir");
    fs::copy(source, root.join("policy/review-dispatched.rego")).expect("install committed module");
}

/// The committed row's shape, with the runner repointed at the stub.
///
/// `declared` false builds the row with an EMPTY review list, which is how the
/// could-not-look arm is reached over the engine: no row declares the fact, so
/// the projection writes `null` rather than a map.
fn row(root: &Path, declared: bool) -> Rule {
    let reviews = if declared {
        serde_json::json!([{
            "id": REVIEW,
            "prompt": REVIEW,
            "runner": root.join("runner.sh").display().to_string(),
            "version": "0",
            "subject": "document",
            "path": SUBJECT,
        }])
    } else {
        serde_json::json!([])
    };
    serde_json::from_value(serde_json::json!({
        "id": RULE,
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": [SUBJECT],
        "module": "policy/review-dispatched.rego",
        "severity": "deny",
        "review": reviews,
    }))
    .expect("the loader accepts the committed row's shape")
}

fn verdicts_for(root: &Path, declared: bool) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row(root, declared)],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

fn verdicts(root: &Path) -> Vec<String> {
    verdicts_for(root, true)
}

// ---------------------------------------------------------------------------
// THE DISPATCH SEAM.
// ---------------------------------------------------------------------------

/// The engine dispatches on a miss and the record reaches the predicate. Without
/// this the whole module is a `with input as` suite over a key nothing fills.
#[test]
fn a_dispatched_review_reaches_the_predicate_and_is_clean() {
    let root = repo("review-dispatched-clean", "body\n", "", 0);
    assert!(
        verdicts(&root).is_empty(),
        "the stub ran and wrote a record, so nothing is undispatched: {:?}",
        verdicts(&root)
    );
    assert_eq!(calls(&root), 1, "the miss dispatched exactly once");
}

/// A REVIEW THAT POINTED AT SOMETHING STILL RAN. Refusing here would price
/// finding something, and the cheapest way past such a gate is an agent that
/// reports nothing.
#[test]
fn a_review_that_reported_findings_is_still_clean() {
    let root = repo("review-dispatched-findings", "body\n", "a.md 3 §7\n", 0);
    assert!(verdicts(&root).is_empty(), "{:?}", verdicts(&root));
}

/// NO RUNNER HERE IS COULD-NOT-LOOK, NEVER A REFUSAL, and this is the case that
/// keeps the gate from being a verdict about the operator.
///
/// A machine with no reviewer installed cannot be asked whether it reviewed.
/// Refusing here would fail every fixture, every fresh clone and every CI runner
/// that has not installed the agent — measured on this suite before the arm
/// existed, where it took four unrelated `cli.rs` cases red with it.
#[test]
fn a_missing_runner_is_could_not_look_and_never_a_refusal() {
    let root = repo("review-dispatched-no-runner", "body\n", "", 0);
    fs::remove_file(root.join("runner.sh")).expect("remove the runner");
    assert!(
        verdicts(&root).is_empty(),
        "an environment with no reviewer is unjudgeable, not guilty: {:?}",
        verdicts(&root)
    );
}

/// AND THE DELTA IS WHAT DECIDES WHETHER THE QUESTION IS PUT AT ALL. A branch
/// that did not touch the subject owes no review of it, so nothing is dispatched
/// and nothing is refused.
#[test]
fn a_branch_that_did_not_touch_the_subject_owes_no_review() {
    // THE RUNNER FAILS HERE ON PURPOSE, and that is what makes this case
    // discriminate. With a runner that exits 0 the record is present, so the
    // absence arm is false and the delta narrowing decides nothing observable:
    // the case passes whether the module reads the delta or not, which is exactly
    // what `untouched-subject-priced` measured when it SURVIVED. A failing runner
    // leaves no record, so absence holds and the ONLY thing keeping this tree
    // quiet is that the subject is outside the delta.
    let root = repo("review-dispatched-untouched", "body\n", "", 1);
    // Move `origin/main` up to HEAD, so the subject is no longer in the delta.
    let head = common::git_in(&root, &["rev-parse", "HEAD"]);
    common::git_in(
        &root,
        &["update-ref", "refs/remotes/origin/main", head.trim()],
    );
    assert!(
        verdicts(&root).is_empty(),
        "an untouched subject asks no question: {:?}",
        verdicts(&root)
    );
}

/// COULD NOT LOOK IS NOT A REFUSAL, and this arm is only reachable over the
/// engine: the fact is `null` when no row declared a review, which a fabricated
/// input cannot distinguish from a map that happens to be empty.
#[test]
fn a_review_the_engine_could_not_look_at_is_not_refused() {
    let root = repo("review-dispatched-undeclared", "body\n", "", 0);
    assert!(
        verdicts_for(&root, false).is_empty(),
        "a row declaring no review asked no question: {:?}",
        verdicts_for(&root, false)
    );
    assert_eq!(calls(&root), 0, "and nothing was dispatched");
}

// ---------------------------------------------------------------------------
// EVERY FAILURE LEAVES NO RECORD, so a broken agent and one that never ran are
// indistinguishable and both refuse. Writing an empty record on failure would
// turn a broken runner into a clean review.
// ---------------------------------------------------------------------------

/// THE REFUSAL ARM. The runner is here and was asked, and it gave nothing usable
/// — which is the branch's problem rather than the environment's, and the one
/// state this gate exists to refuse.
#[test]
fn an_absent_record_is_refused_over_the_engines_own_projection() {
    let root = repo("review-dispatched-red", "body\n", "", 1);
    assert_eq!(verdicts(&root), vec![RULE.to_owned()]);
}

/// THE EXIT STATUS DECIDES, NOT THE PARSE — and this case is what tells them
/// apart, because it hands the runner a PERFECTLY PARSEABLE stream and a
/// non-zero exit.
///
/// It replaces a case that asserted the opposite: a prose answer used to be a
/// failed dispatch, on `secrets.rs`' invariant that clean is never inferred from
/// a stream that failed to parse. That invariant still holds where it belongs —
/// a run that did not COMPLETE records nothing — but it was reaching too far.
/// The gate refuses absence and never reads a finding, so demanding Batten's
/// line format from the agent made every reviewer that speaks its own into a
/// failure, and refused the branch for somebody else's stdout.
#[test]
fn a_runner_that_exits_non_zero_leaves_no_record_even_with_clean_output() {
    let root = repo("review-red-but-parseable", "body\n", "a.md 3 §7\n", 1);
    assert_eq!(
        verdicts(&root),
        vec![RULE.to_owned()],
        "completion is the contract, and this run did not complete"
    );
}

// ---------------------------------------------------------------------------
// THE KEYING, which is the half a `with input as` case actively hides.
// ---------------------------------------------------------------------------

/// A record taken over other bytes does not answer. This is the anti-staleness
/// property the whole fact turns on, and the only tier that can see it.
#[test]
fn a_record_over_other_bytes_does_not_answer() {
    let root = repo("review-dispatched-stale", "body\n", "", 0);
    assert!(verdicts(&root).is_empty(), "the first run records");
    assert_eq!(calls(&root), 1);

    // The subject moves, so the composed key moves with it.
    fs::write(root.join(SUBJECT), "edited\n").expect("edit the subject");
    assert!(
        verdicts(&root).is_empty(),
        "the edit re-dispatches rather than refusing"
    );
    assert_eq!(
        calls(&root),
        2,
        "the record under the old digest did not answer for the new bytes"
    );
}

/// AND A HIT DOES NOT RE-SPAWN, which is what makes an agent affordable inside a
/// gate that runs every landing lap. Only a spawn count can show it: a hit and a
/// second identical dispatch leave byte-identical records.
#[test]
fn an_unchanged_subject_is_a_cache_hit() {
    let root = repo("review-dispatched-hit", "body\n", "", 0);
    assert!(verdicts(&root).is_empty());
    assert!(verdicts(&root).is_empty());
    assert_eq!(calls(&root), 1, "the second run read the record");
}

/// ANTI-VACUITY over the whole file: the row this suite exercises is the one the
/// committed config declares, so a rename or a scope change reddens here rather
/// than leaving every case above passing over a module nothing runs.
#[test]
fn the_committed_row_is_the_one_these_cases_exercise() {
    let committed = batten::config::load(&common::at_root("batten.toml"))
        .expect("the committed config loads")
        .rules;
    let declared = committed
        .iter()
        .find(|rule| rule.id == RULE)
        .expect("the committed config declares the row this suite exercises");
    assert_eq!(declared.kind, RuleKind::Policy);
    assert_eq!(declared.scope, RuleScope::Tree);
    let review = declared
        .review
        .first()
        .expect("the committed row declares a review, or the gate reads a null fact");
    assert_eq!(
        review.prompt, REVIEW,
        "the prompt id must name a VENDORED prompt: an id nothing vendors resolves \
         to no text, so no key is composable and the row goes silently inert"
    );
    assert!(
        batten::review::prompt(&review.prompt).is_some(),
        "the committed row's prompt id is one this binary vendors"
    );
}

/// The last argument the stub was invoked with, or the empty string.
///
/// This is what proves the prompt REACHED the runner. Nothing in the record can
/// show it: a review dispatched with the prompt discarded writes a record
/// byte-identical to one dispatched with it delivered, which is exactly why the
/// defect this case exists for survived being tested.
fn last_call(root: &Path) -> String {
    fs::read_to_string(root.join("calls")).unwrap_or_default()
}

fn row_with(root: &Path, extra: &serde_json::Value) -> Rule {
    let mut review = serde_json::json!({
        "id": REVIEW,
        "prompt": REVIEW,
        "runner": root.join("runner.sh").display().to_string(),
        "version": "0",
        "subject": "document",
        "path": SUBJECT,
    });
    let (Some(base), Some(more)) = (review.as_object_mut(), extra.as_object()) else {
        panic!("both are objects");
    };
    for (key, value) in more {
        base.insert(key.clone(), value.clone());
    }
    serde_json::from_value(serde_json::json!({
        "id": RULE,
        "kind": "policy",
        "scope": "tree",
        "base": "origin/main",
        "delta_sources": [SUBJECT],
        "module": "policy/review-dispatched.rego",
        "severity": "deny",
        "review": [review],
    }))
    .expect("the loader accepts the row")
}

fn verdicts_with(root: &Path, extra: &serde_json::Value) -> Vec<String> {
    let verdicts = common::verdicts_in(root);
    rules::run_static(
        &[row_with(root, extra)],
        &[],
        batten::policy::Vocabulary {
            patterns: &[],
            verdicts: &verdicts,
            recorders: &[],
        },
        root,
    )
    .expect("the read surface runs a policy row")
    .findings
    .into_iter()
    .map(|finding| finding.rule)
    .collect()
}

// ---------------------------------------------------------------------------
// THE PROMPT REACHES THE RUNNER, which no record can attest to.
// ---------------------------------------------------------------------------

/// A POSITIONAL runner is handed the prompt as an argument.
///
/// Measured against a real reviewer whose review subcommand takes focus as a
/// POSITIONAL and wires stdin only for a different subcommand: a prompt sent down
/// stdin is discarded in silence and the review runs unsteered, exiting zero. The
/// record is identical either way — only the invocation shows it.
#[test]
fn a_positional_runner_is_handed_the_prompt_as_an_argument() {
    let root = repo("review-prompt-positional", "body\n", "", 0);
    assert!(
        verdicts_with(&root, &serde_json::json!({"prompt_arg": "positional"})).is_empty(),
        "the dispatch completed"
    );
    // THE POINTER, not a phrase from the prompt: the prose is edited freely and
    // an assertion on it breaks for a reason that has nothing to do with the
    // channel. The subject pointer is the last thing written into the payload, so
    // finding it in argv proves the WHOLE payload arrived positionally.
    assert!(
        last_call(&root).contains(SUBJECT),
        "the prompt and its pointer must arrive as an argument: {:?}",
        last_call(&root)
    );
}

/// AND THE DEFAULT STILL SENDS IT ON STDIN, so the landed contract is unchanged
/// for a row that declares nothing.
#[test]
fn a_row_declaring_no_channel_still_sends_the_prompt_on_stdin() {
    let root = repo("review-prompt-stdin", "body\n", "", 0);
    assert!(verdicts(&root).is_empty(), "the dispatch completed");
    assert!(
        !last_call(&root).contains(SUBJECT),
        "the default channel is stdin, so no argument carries the payload: {:?}",
        last_call(&root)
    );
}

// ---------------------------------------------------------------------------
// READINESS IS THE RUNNER'S OWN ANSWER.
// ---------------------------------------------------------------------------

/// A runner that is INSTALLED and says it cannot review is could-not-look.
///
/// This is the arm `is_file()` cannot reach: the program is right there, so
/// every file-existence check says "runner present", and the branch would be
/// refused for an environment that is simply not authenticated.
#[test]
fn a_runner_whose_probe_says_it_is_not_ready_is_could_not_look() {
    let root = repo("review-probe-unready", "body\n", "", 0);
    fs::write(
        root.join("ready"),
        r#"{"ready": false, "nextSteps": ["authenticate the reviewer"]}"#,
    )
    .expect("the probe answers not-ready");
    assert!(
        verdicts_with(&root, &serde_json::json!({"probe": ["setup", "--json"]})).is_empty(),
        "an unauthenticated reviewer is unjudgeable, not guilty"
    );
    assert_eq!(calls(&root), 0, "and nothing was dispatched");
}

/// A ready runner dispatches, so the probe is a gate rather than a wall.
#[test]
fn a_runner_whose_probe_says_it_is_ready_dispatches() {
    let root = repo("review-probe-ready", "body\n", "", 0);
    assert!(
        verdicts_with(&root, &serde_json::json!({"probe": ["setup", "--json"]})).is_empty(),
        "the dispatch completed"
    );
    assert_eq!(calls(&root), 1, "the probe passed and the review ran");
}

// ---------------------------------------------------------------------------
// COMPLETION IS THE CONTRACT.
// ---------------------------------------------------------------------------

/// A REAL REVIEWER'S OUTPUT IS NOT A FAILED DISPATCH. The gate refuses absence
/// and never reads a finding, so demanding Batten's line format would reject
/// every reviewer that speaks its own — leaving no record, and refusing the
/// branch for somebody else's stdout.
#[test]
fn a_runner_that_answers_in_its_own_format_still_records() {
    let root = repo(
        "review-foreign-format",
        "body\n",
        "{\"exitStatus\":0,\"payload\":{\"findings\":[]}}\n",
        0,
    );
    assert!(
        verdicts(&root).is_empty(),
        "a completed review records whatever it said: {:?}",
        verdicts(&root)
    );
}
