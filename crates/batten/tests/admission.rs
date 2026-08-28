//! Issued admissions, over the store and the compiled binary (CLOUD-1051).
//!
//! # What is under test
//!
//! The claim this row makes is not about a hash function. It is that **the
//! record's existence and state are what authorize**, and that a record cannot be
//! moved to a different situation, spent twice, or edited after issuance without
//! that being detectable. Every case below reddens exactly one of those clauses.
//!
//! The address's own property is asserted in `admission.rs`'s unit tier — field
//! boundaries, escaping, order independence — because those are properties of the
//! canonicalization rather than of the store. This file is the other half: what
//! happens when two processes reach for one record, when a record is rewritten
//! under its own key, when a chain points at itself.
//!
//! # The anti-vacuity arm is the last case
//!
//! A scheme that refused every presentation would satisfy every negative case
//! here. `a_correctly_answered_override_completes_end_to_end` is what makes the
//! rest mean something (CLOUD-418).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use batten::admission::{self, Binding, Record, Refused, Situation, State};

/// A `[[verdict]]` row that CAN be overridden, and one that cannot.
///
/// # No class Batten ships declares an `override` route, and that is the default
///
/// Measured while writing this file: every one of `verdict::VENDORED`'s classes
/// — the seven native ones and the four preset ones — declares only `command`,
/// `document` and `issue` routes. So **nothing the binary itself refuses is
/// overridable**, which is CLOUD-1051's "a gate declaring no precondition simply
/// cannot be overridden" holding by construction rather than by anyone
/// remembering it.
///
/// Overridability is therefore a CONSUMER decision, declared in their own
/// authority, which is where it belongs under house style §8: whether a
/// repository's own gate has a legitimate break-glass is a question about that
/// repository. The fixture declares one so the end-to-end arm has something to
/// exercise; the negative arm uses a vendored class precisely because none of
/// them can be overridden.
const AUTHORITY: &str = r#"version = 1

[[verdict]]
id = "V-PROSE-ONLY-DIFF"
gloss = "a branch whose whole diff is comment lines buys a CI matrix that confirms nothing"
class = """
Every changed line is a comment and no test moved, so a full required matrix
would confirm nothing that could differ. Ride the next change these files carry.
"""

[[verdict.route]]
id = "R-BATCH-IT"
kind = "command"
target = "let the next change to these files carry it"

[[verdict.route]]
id = "R-OVERRIDE-PROSE-ONLY"
kind = "override"
precondition = "the prose IS the deliverable and cannot wait for the next change"
"#;

/// A throwaway repository with a real HEAD, so `override request` has one to
/// bind and the store has a state root to derive from.
fn fixture(name: &str) -> PathBuf {
    let root = common::scratch(&format!("admission-{name}"));
    common::write(&root, "batten.toml", AUTHORITY);
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-qm", "seed"]);
    // THE STORE OUTLIVES THE CHECKOUT, and that is the design rather than a
    // leak: an override record is an out-of-tree receipt, so `common::scratch`
    // recreating the tree does not clear it. A case is therefore not isolated by
    // a fresh directory alone — measured, `a_crash_between_issuance_and_
    // consumption_leaves_the_record_consumable` passed on a clean container and
    // read `Spent` on the second run, because the previous run's record for the
    // identical articulation was still there.
    //
    // Clearing it here is what makes each run independent. It is also the only
    // place in this file that reaches into the store as a directory rather than
    // through the module's own API, which is why it is here and not in a case.
    if let Ok(store) = admission::store_dir(&root) {
        let _ = std::fs::remove_dir_all(&store);
    }
    root
}

fn answers(reason: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "precondition".to_owned(),
            "the prose is the deliverable".to_owned(),
        ),
        ("lost".to_owned(), reason.to_owned()),
        (
            "rejected-route".to_owned(),
            "R-BATCH-IT: no next change is coming".to_owned(),
        ),
    ])
}

/// A binding for one case.
///
/// `reason` is what distinguishes cases from each other, and it has to: the
/// address is a pure function of the binding, so two cases articulating the
/// identical words would share one record. That is the scheme working — the same
/// reasoning IS the same admission — but it makes cases interfere, which is how
/// `a_crash_between_issuance_and_consumption_leaves_the_record_consumable` first
/// read `Spent`. Every caller below passes a distinct reason.
fn binding(subject: &str, head: &str, epoch: &str, reason: &str) -> Binding {
    Binding {
        rule: "prose-only".to_owned(),
        verdict: "V-PROSE-ONLY-DIFF".to_owned(),
        subject: subject.to_owned(),
        head: head.to_owned(),
        epoch: epoch.to_owned(),
        answers: answers(reason),
        prev: None,
        author: "alec@button.is".to_owned(),
    }
}

/// The situation the binding above was minted for.
fn situation<'a>(subject: &'a str, head: &'a str, epoch: &'a str) -> Situation<'a> {
    Situation {
        rule: "prose-only",
        verdict: "V-PROSE-ONLY-DIFF",
        subject,
        head,
        epoch,
    }
}

fn refusal(root: &Path, admission: &str, expected: &Situation<'_>) -> Refused {
    admission::consume(root, admission, expected)
        .expect("the store answered")
        .expect_err("the presentation was refused")
}

#[test]
fn an_admission_bound_to_another_subject_is_refused() {
    // The harvesting case, and the reason the subject is inside the hash rather
    // than beside it: an override earned for one diff must not release another.
    let root = fixture("other-subject");
    let issued = admission::issue(
        &root,
        binding("a.rs,b.rs", "head1", "epoch1", "the notes wait"),
    )
    .expect("issued");
    assert_eq!(
        refusal(&root, &issued, &situation("c.rs", "head1", "epoch1")),
        Refused::Unbound
    );
}

#[test]
fn an_admission_bound_to_another_head_is_refused() {
    // A branch that keeps committing keeps changing what it is asking to
    // release. Without HEAD in the binding, one articulation would cover every
    // later commit on the branch — which is the standing password again, with a
    // longer name.
    let root = fixture("other-head");
    let issued = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the notes wait for a head"),
    )
    .expect("issued");
    assert_eq!(
        refusal(&root, &issued, &situation("a.rs", "head2", "epoch1")),
        Refused::Unbound
    );
}

#[test]
fn an_admission_does_not_survive_the_config_generation_it_was_taken_under() {
    // THE CLAUSE THAT IS EASY TO LEAVE OUT. The most common honest reason to
    // override is that the gate is wrong — and the fix for a wrong gate is a
    // config change, which mints a new epoch. Binding the epoch means the
    // admission expires exactly when the thing that made it necessary is
    // repaired, rather than outliving it.
    let root = fixture("other-epoch");
    let issued = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the notes wait for an epoch"),
    )
    .expect("issued");
    assert_eq!(
        refusal(&root, &issued, &situation("a.rs", "head1", "epoch2")),
        Refused::Unbound
    );
}

#[test]
fn a_spent_admission_is_refused_and_the_same_words_reproduce_it() {
    // The two halves of "single-use per SITUATION", and they are one property.
    // Re-articulating with the SAME answers recomputes the SAME address, which is
    // already spent — so the counter a per-session scheme would need does not
    // exist, and overriding the same situation twice costs genuinely different
    // text rather than a second attempt.
    let root = fixture("spent");
    let situation = situation("a.rs", "head1", "epoch1");
    let issued = admission::issue(&root, binding("a.rs", "head1", "epoch1", "the notes wait"))
        .expect("issued");

    let spent = admission::consume(&root, &issued, &situation)
        .expect("the store answered")
        .expect("the first consume wins");
    assert_eq!(spent.state, State::Spent);

    assert_eq!(refusal(&root, &issued, &situation), Refused::Spent);

    // Re-issuing the identical articulation is idempotent on the address, and
    // does NOT reset the record — that would be the replay this exists to stop.
    let again = admission::issue(&root, binding("a.rs", "head1", "epoch1", "the notes wait"))
        .expect("issued");
    assert_eq!(again, issued);
    assert_eq!(refusal(&root, &again, &situation), Refused::Spent);
}

#[test]
fn genuinely_different_answers_are_a_different_address_and_are_issuable() {
    // The discriminating half of the case above. Without this, a scheme that
    // simply refused every second request for a situation would pass — and
    // re-articulation would be impossible rather than merely expensive.
    let root = fixture("re-articulated");
    let situation = situation("a.rs", "head1", "epoch1");
    let first = admission::issue(&root, binding("a.rs", "head1", "epoch1", "the notes wait"))
        .expect("issued");
    admission::consume(&root, &first, &situation)
        .expect("the store answered")
        .expect("spent");

    let second = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the release window closes today"),
    )
    .expect("issued");
    assert_ne!(second, first, "different reasoning is a different address");
    admission::consume(&root, &second, &situation)
        .expect("the store answered")
        .expect("the fresh articulation is consumable");
}

#[test]
fn a_record_edited_after_issuance_no_longer_recomputes_and_is_refused() {
    // THE SELF-VERIFICATION CLAUSE, and the reason the corpus is evidence rather
    // than a log. Under a random bearer token this edit is undetectable: the
    // token still matches the record it is filed under, because the token never
    // depended on the record's contents.
    let root = fixture("tampered");
    let issued = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the notes wait, edited later"),
    )
    .expect("issued");

    let path = admission::record_path(&root, &issued).expect("record path");
    let mut record: Record =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    record
        .binding
        .answers
        .insert("lost".to_owned(), "actually nothing".to_owned());
    assert!(!record.recomputes(), "the edit broke the address");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&record).expect("serialize"),
    )
    .expect("write");

    assert_eq!(
        refusal(&root, &issued, &situation("a.rs", "head1", "epoch1")),
        Refused::Tampered
    );
}

#[test]
fn a_cycle_cannot_be_constructed_without_breaking_an_address() {
    // WHAT THIS CASE MEASURED, and it is stronger than what it set out to assert.
    //
    // It was written as "a cycling `prev` chain is refused", and it does not
    // reach the chain predicate at all — because **a cycle is unconstructible
    // under content addressing**. To make two records name each other, each
    // address must be computed over a binding that already carries the other's
    // address, and neither exists until the other does. The only way to write
    // the pair is to compute both addresses first and then edit `prev` in — which
    // is precisely the edit `recomputes` catches, one clause earlier.
    //
    // So the honest statement is: the forger cannot reach `ChainBroken`, because
    // they are stopped at `Tampered` while still holding a well-formed pair. The
    // `ChainBroken` arm is not dead — its live case is the sibling below, a link
    // that resolves to nothing — but it is not what a cycle produces, and a case
    // asserting otherwise would have been describing a defence that never fires.
    let root = fixture("cycle");
    let mut left = binding("a.rs", "head1", "epoch1", "first");
    let mut right = binding("a.rs", "head1", "epoch1", "second");
    let left_id = admission::address(&left);
    let right_id = admission::address(&right);
    left.prev = Some(right_id.clone());
    right.prev = Some(left_id.clone());
    // Neither address survives that edit, which is the finding.
    assert_ne!(admission::address(&left), left_id);
    assert_ne!(admission::address(&right), right_id);

    for (id, forged) in [(&left_id, &left), (&right_id, &right)] {
        let record = Record {
            statement_type: "https://in-toto.io/Statement/v1".to_owned(),
            predicate_type: admission::PREDICATE_TYPE.to_owned(),
            admission: id.clone(),
            binding: forged.clone(),
            state: State::Issued,
        };
        let path = admission::record_path(&root, id).expect("record path");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("store dir");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&record).expect("serialize"),
        )
        .expect("write");
    }

    let situation = Situation {
        rule: "prose-only",
        verdict: "V-PROSE-ONLY-DIFF",
        subject: "a.rs",
        head: "head1",
        epoch: "epoch1",
    };
    assert_eq!(
        refusal(&root, &left_id, &situation),
        Refused::Tampered,
        "the forger is stopped before the chain is ever walked"
    );
}

#[test]
fn a_prev_that_resolves_to_nothing_is_refused_rather_than_treated_as_a_terminus() {
    // A chain that ends by pointing at nothing is indistinguishable from one
    // somebody deleted the middle of, and reading it as a terminus would make
    // deletion the way to launder a history.
    let root = fixture("broken-link");
    let mut orphan = binding("a.rs", "head1", "epoch1", "first");
    orphan.prev = Some("0".repeat(64));
    let issued = admission::issue(&root, orphan).expect("issued");
    assert_eq!(
        refusal(&root, &issued, &situation("a.rs", "head1", "epoch1")),
        Refused::ChainBroken
    );
}

#[test]
fn an_unknown_admission_is_refused_rather_than_minted_on_presentation() {
    // The address is not the authority. Presenting a well-formed one the store
    // has never seen must refuse — otherwise anyone who can compute a hash holds
    // the bypass, which is the property this whole row exists to remove.
    let root = fixture("unknown");
    let computed = admission::address(&binding("a.rs", "head1", "epoch1", "never issued"));
    assert_eq!(
        refusal(&root, &computed, &situation("a.rs", "head1", "epoch1")),
        Refused::Unknown
    );
}

#[test]
fn two_concurrent_consumes_resolve_to_exactly_one_winner() {
    // The compare-and-set, under the lock this row introduced — `receipt.rs`
    // carried none. Threads rather than a fabricated interleaving, because the
    // claim is about the LOCK and a fabricated one would test the code around it.
    //
    // The loser is a policy refusal (`Spent`), never an internal error: a caller
    // that lost a race has been told something true about the record, and
    // reporting a fault would send them looking for a broken store.
    let root = fixture("concurrent");
    let issued = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the notes wait, raced"),
    )
    .expect("issued");

    let outcomes: Vec<Result<Record, Refused>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let root = root.clone();
                let issued = issued.clone();
                scope.spawn(move || {
                    admission::consume(
                        &root,
                        &issued,
                        &Situation {
                            rule: "prose-only",
                            verdict: "V-PROSE-ONLY-DIFF",
                            subject: "a.rs",
                            head: "head1",
                            epoch: "epoch1",
                        },
                    )
                    .expect("the store answered")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the thread finished"))
            .collect()
    });

    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
        1,
        "exactly one consumer wins the compare-and-set"
    );
    for outcome in &outcomes {
        if let Err(refused) = outcome {
            assert_eq!(*refused, Refused::Spent, "a loser is a policy refusal");
        }
    }
}

#[test]
fn a_crash_between_issuance_and_consumption_leaves_the_record_consumable() {
    // There is no intermediate state to recover FROM: the state lives in one
    // record replaced by one atomic rename, so the only two things a crash can
    // leave are "issued" and "spent". This is the first of those, and a store
    // reopened from scratch is exactly what a crashed process leaves behind.
    let root = fixture("crash");
    let issued = admission::issue(
        &root,
        binding("a.rs", "head1", "epoch1", "the notes wait, interrupted"),
    )
    .expect("issued");
    // Nothing else happens — the "crash" is the absence of a consume — and a
    // fresh read of the store finds the record where it was.
    let record = admission::load(&root, &issued).expect("the record survived");
    assert_eq!(record.state, State::Issued);
    admission::consume(&root, &issued, &situation("a.rs", "head1", "epoch1"))
        .expect("the store answered")
        .expect("still consumable after the crash");
}

// ---------------------------------------------------------------------------
// The verb, over the compiled binary.
// ---------------------------------------------------------------------------

#[test]
fn an_unanswered_question_yields_no_admission_and_prints_what_to_answer() {
    // The two-step, and it is one case because it is one property: the questions
    // are what a caller has not yet answered. Exit 1 rather than 2 — this is a
    // statement about the request, not a policy verdict.
    let root = fixture("unanswered");
    let output = common::run_with_stdin(
        &root,
        &[
            "override",
            "request",
            "--rule",
            "prose-only",
            "--verdict",
            "V-PROSE-ONLY-DIFF",
            "--subject",
            "a.rs",
        ],
        "",
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "an unanswered request is a usage error: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        "and nothing was issued on the data channel"
    );
    assert!(
        stderr.contains("precondition") && stderr.contains("lost"),
        "the declared questions are re-presented: {stderr}"
    );
}

#[test]
fn a_class_declaring_no_override_route_cannot_be_overridden() {
    // The right default, and it composes with `verdict::validate`'s refusal of a
    // class whose ONLY route is an override: a class either offers a real way out
    // and may additionally be overridden, or it offers a real way out and may
    // not. `V-SPAWN-ON-READ-VERB` is the second kind.
    let root = fixture("no-override-route");
    let output = common::run_with_stdin(
        &root,
        &[
            "override",
            "request",
            "--rule",
            "check",
            "--verdict",
            "V-SPAWN-ON-READ-VERB",
            "--subject",
            "a.rs",
        ],
        "precondition=x\nlost=y\nrejected-route=z\n",
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code()),
        "a class with no override route refuses the request: {stderr}"
    );
    assert!(
        stderr.contains("declares no `override` route"),
        "and says which clause: {stderr}"
    );
}

#[test]
fn an_undeclared_class_is_refused_naming_the_registry_size() {
    // Pointer-shaped, and deliberately not a listing: the whole registry on
    // stderr would be the payload this surface's own row is careful about.
    let root = fixture("unknown-class");
    let output = common::run_with_stdin(
        &root,
        &[
            "override",
            "request",
            "--rule",
            "prose-only",
            "--verdict",
            "V-NO-SUCH-CLASS",
            "--subject",
            "a.rs",
        ],
        "precondition=x\nlost=y\nrejected-route=z\n",
    );
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Usage.code())
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("class(es)"),
        "the answer is a count, not the table"
    );
}

#[test]
fn a_correctly_answered_override_completes_end_to_end() {
    // THE ANTI-VACUITY ARM (CLOUD-418). Every case above is a refusal, and a
    // mechanism that refused everything would satisfy all of them. This is the
    // legitimate break-glass, demonstrated end to end over the binary: three
    // answers in, one admission out, and the record in the store consumable
    // exactly once against the situation it names.
    let root = fixture("end-to-end");
    let output = common::run_with_stdin(
        &root,
        &[
            "override",
            "request",
            "--rule",
            "prose-only",
            "--verdict",
            "V-PROSE-ONLY-DIFF",
            "--subject",
            "a.rs,b.rs",
        ],
        "precondition=the prose IS the deliverable — this branch is the release notes\n\
         lost=the notes miss the release window and ship describing the previous version\n\
         rejected-route=R-BATCH-IT assumes a next change to these files, and there is none queued\n",
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "a fully answered request issues: {stderr}"
    );
    let issued = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_eq!(issued.len(), 64, "one hex address on stdout: {issued:?}");
    assert!(
        issued.chars().all(|c| c.is_ascii_hexdigit()),
        "and nothing else: {issued:?}"
    );

    let record = admission::load(&root, &issued).expect("the store holds it");
    assert_eq!(record.state, State::Issued);
    assert!(record.recomputes(), "and it verifies against its own key");
    assert_eq!(record.binding.subject, "a.rs,b.rs");
    assert_eq!(record.binding.verdict, "V-PROSE-ONLY-DIFF");
    assert_eq!(
        record.binding.answers.len(),
        3,
        "all three declared answers are in the record, which is where the reasoning lives"
    );
}

// ─── THE VERDICT TERM (CLOUD-1051) ───────────────────────────────────────────

#[test]
fn an_admission_for_one_class_is_not_presentable_against_another() {
    // THE ONE BINDING TERM THE CASES ABOVE LEAVE OPEN. Subject, head and epoch
    // each have their own case; the class did not, and it is the term that makes
    // `verdict` a required flag rather than something derived from the rule —
    // one rule can refuse under more than one class, and an override earned for
    // one of them must not release the other.
    let root = fixture("other-class");
    let issued = admission::issue(&root, binding("a.rs", "HEAD1", "E1", "the class term"))
        .expect("the admission issues");

    let elsewhere = Situation {
        verdict: "V-SHELL-RULE-EDITED",
        ..situation("a.rs", "HEAD1", "E1")
    };
    assert_eq!(
        refusal(&root, &issued, &elsewhere),
        Refused::Unbound,
        "a different class is a different situation"
    );
}

// ─── THE VERB (CLOUD-1051) ───────────────────────────────────────────────────
//
// The cases above prove the MECHANISM. These three prove the surface, which is
// what the row's "no gate honours a bare env var" acceptance actually rests on:
// a gate calls this verb and reads its exit code, so the codes are the contract.

/// Issue an admission through the verb, and hand back the address it printed.
fn issued_through_the_verb(root: &Path, subject: &str) -> String {
    let output = common::run_with_stdin(
        root,
        &[
            "override",
            "request",
            "--rule",
            "prose-only",
            "--verdict",
            "V-PROSE-ONLY-DIFF",
            "--subject",
            subject,
        ],
        // The three ids the class's own `override.precondition` generates. A
        // request answering fewer is exit 1 and issues nothing, which is what
        // `an_unanswered_question_yields_no_admission_and_prints_what_to_answer`
        // asserts — so the helper answers all of them and the cases below are
        // about the SPEND rather than about the request.
        "precondition=the prose IS the deliverable — this branch is the release notes\n\
         lost=the notes miss the release window and ship describing the previous version\n\
         rejected-route=R-BATCH-IT assumes a next change to these files, and there is none queued\n",
    );
    assert_eq!(output.status.code(), Some(0), "the request succeeds");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn the_verb_spends_a_legitimate_admission_and_reports_it() {
    // ANTI-VACUITY FOR THE SURFACE. Every refusal below is only meaningful if
    // this completes — and it is the loop a gate's task actually walks: refuse,
    // request, answer, spend, proceed.
    let root = fixture("verb-happy");
    let admission = issued_through_the_verb(&root, "a.rs");

    let output = common::run(
        &root,
        &[
            "override",
            "spend",
            "--admission",
            &admission,
            "--rule",
            "prose-only",
            "--verdict",
            "V-PROSE-ONLY-DIFF",
            "--subject",
            "a.rs",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "a bound admission spends");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        stdout.contains("V-PROSE-ONLY-DIFF") && stdout.contains("spent"),
        "the class and the outcome: {stdout:?}"
    );
    // POINTER, NEVER THE ANSWERS (rule 4). The reasoning the author typed lives
    // in the record; a verb that echoed it would republish it on every gate run.
    assert!(
        !stdout.contains("deliverable"),
        "no answer text crosses stdout: {stdout:?}"
    );
}

#[test]
fn the_verb_refuses_a_replay_with_the_policy_code() {
    // Exit 2 rather than 1, and that is §7 rather than a choice here: a refusal
    // to release is a policy verdict, and `2` means that on every verb.
    let root = fixture("verb-replay");
    let admission = issued_through_the_verb(&root, "a.rs");
    let args = [
        "override",
        "spend",
        "--admission",
        admission.as_str(),
        "--rule",
        "prose-only",
        "--verdict",
        "V-PROSE-ONLY-DIFF",
        "--subject",
        "a.rs",
    ];
    assert_eq!(
        common::run(&root, &args).status.code(),
        Some(0),
        "the first spend succeeds"
    );

    let replay = common::run(&root, &args);
    assert_eq!(
        replay.status.code(),
        Some(2),
        "a replay is a policy refusal"
    );
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("spent"),
        "and it says which arm refused"
    );
}

#[test]
fn the_verb_refuses_an_admission_presented_for_another_subject() {
    // THE SITUATION IS RE-STATED, NOT REMEMBERED, and this is what makes that
    // load-bearing: if the verb read the subject out of the record instead of
    // comparing the one it was given, every spend would be self-consistent by
    // construction and the binding would be decorative.
    let root = fixture("verb-elsewhere");
    let admission = issued_through_the_verb(&root, "a.rs");

    let output = common::run(
        &root,
        &[
            "override",
            "spend",
            "--admission",
            &admission,
            "--rule",
            "prose-only",
            "--verdict",
            "V-PROSE-ONLY-DIFF",
            "--subject",
            "b.rs",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an admission earned for one subject releases no other"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unbound"),
        "and names the arm"
    );
}

// ─── THE ADMISSION MUST ACTUALLY ADMIT (CLOUD-1120) ──────────────────────────
//
// Every case above proves the record's own protocol: it binds one situation, it
// is spendable once, it cannot be edited or moved. None of them runs `check`,
// and that turned out to be the whole gap — `admission::` was reached only by
// the two `override` verbs, so a record could be articulated, bound and spent
// while the gate that refused went on refusing. Measured on this repository: a
// `spent` record whose rule, class, subject and HEAD all equalled the refusal's,
// against a class declaring four routes of which none was reachable.
//
// `prose_only.rs` conserves "the override admits the branch and records which
// one it admitted" onto this file. The recording half was held here; the
// ADMITTING half was not held anywhere, which is why the gap survived a ledger
// built to catch exactly that. These cases are the missing half.

/// A consumer authority whose one policy row always refuses, so a `check` has a
/// finding with a declared class for an admission to bind to.
///
/// Registry equality runs in both directions, so this table declares exactly the
/// one token the module raises and no more.
const ADMITS: &str = r#"version = 1

[[rule]]
id = "always-refuses"
kind = "policy"
scope = "tree"
bundle = "policy-admits/"
severity = "deny"

[[verdict]]
id = "V-ALWAYS"
gloss = "the fixture's row refuses unconditionally"
class = "A fixture predicate that always fires, so a case has a finding to admit."

[[verdict.route]]
id = "R-ADMITS-FIX"
kind = "command"
target = "change the thing the fixture refuses"

[[verdict.route]]
id = "R-OVERRIDE-ADMITS"
kind = "override"
precondition = "the refusal is the fixture's point and there is nothing to fix"
"#;

/// Unconditional, so the case is about the admission rather than about whether
/// the predicate fired.
const ALWAYS: &str = r#"
package batten.admits

import rego.v1

rules contains "always-refuses"

violation contains {
	"rule": "always-refuses",
	"verdict": "V-ALWAYS",
	"subjects": [{"path": "a.rs"}],
}
"#;

fn admits_fixture(name: &str) -> PathBuf {
    let root = common::scratch(&format!("admits-{name}"));
    common::write(&root, "batten.toml", ADMITS);
    common::write(&root, "policy-admits/gate.rego", ALWAYS);
    common::write(&root, "a.rs", "fn main() {}\n");
    common::write(&root, "b.rs", "fn other() {}\n");
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-qm", "seed"]);
    // The store outlives the checkout, for `fixture`'s reason.
    if let Ok(store) = admission::store_dir(&root) {
        let _ = std::fs::remove_dir_all(&store);
    }
    root
}

/// Mint and spend one admission for `subject`, through the verbs a human uses.
fn spend_for(root: &Path, subject: &str, reason: &str) -> String {
    let issued = common::run_with_stdin(
        root,
        &[
            "override",
            "request",
            "--rule",
            "always-refuses",
            "--verdict",
            "V-ALWAYS",
            "--subject",
            subject,
        ],
        &format!(
            "precondition=the refusal is the fixture's point\nlost={reason}\n\
             rejected-route=R-ADMITS-FIX has nothing to change\n"
        ),
    );
    let address = String::from_utf8_lossy(&issued.stdout).trim().to_owned();
    assert_eq!(address.len(), 64, "an address was issued: {address:?}");
    let spent = common::run(
        root,
        &[
            "override",
            "spend",
            "--admission",
            &address,
            "--rule",
            "always-refuses",
            "--verdict",
            "V-ALWAYS",
            "--subject",
            subject,
        ],
    );
    assert_eq!(
        spent.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "the admission spends: {}",
        common::stderr(&spent)
    );
    address
}

#[test]
fn a_spent_admission_admits_the_finding_it_was_issued_for() {
    // THE CASE THE LEDGER CLAIMED AND NOTHING HELD. Against the binary as it
    // stood, this reddens: the record was spent and `check` still exited 2.
    let root = admits_fixture("happy");
    let before = common::run(&root, &["check"]);
    assert_eq!(
        before.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "the fixture row refuses before any admission: {}",
        common::stderr(&before)
    );

    let address = spend_for(
        &root,
        "a.rs",
        "the fixture would have nothing to demonstrate",
    );

    let after = common::run(&root, &["check"]);
    assert_eq!(
        after.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "a spent admission admits it: {}",
        common::stderr(&after)
    );
    // AND THE SUPPRESSION IS OBSERVABLE. A silent one is the bypass variable
    // again — the whole argument for a record is that an override is traceable
    // to the reasoning that bought it.
    let reported = common::stderr(&after);
    assert!(
        reported.contains("admitted a.rs") && reported.contains(&address),
        "the run names what it admitted and which record did it: {reported}"
    );
}

#[test]
fn an_issued_admission_that_was_never_spent_admits_nothing() {
    // THE ECONOMY. Articulating costs thinking; spending is the act. A mint that
    // suppressed on its own would restore the bypass variable it replaced —
    // read the refusal, type three sentences, never spend, never be refused.
    let root = admits_fixture("unspent");
    let issued = common::run_with_stdin(
        &root,
        &[
            "override",
            "request",
            "--rule",
            "always-refuses",
            "--verdict",
            "V-ALWAYS",
            "--subject",
            "a.rs",
        ],
        "precondition=the refusal is the fixture's point\n\
         lost=nothing, which is the point of this case\n\
         rejected-route=R-ADMITS-FIX has nothing to change\n",
    );
    assert_eq!(
        issued.status.code(),
        Some(batten::exit::ExitCode::Success.code())
    );

    let after = common::run(&root, &["check"]);
    assert_eq!(
        after.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "an unspent admission suppresses nothing: {}",
        common::stderr(&after)
    );
}

#[test]
fn an_admission_for_another_subject_admits_nothing() {
    // The harvesting case at the suppression surface: one legitimate override
    // must not clear every finding the same rule raises.
    let root = admits_fixture("other-subject");
    spend_for(&root, "b.rs", "this case is about the subject term");

    let after = common::run(&root, &["check"]);
    assert_eq!(
        after.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "the finding on a.rs is untouched by an admission for b.rs: {}",
        common::stderr(&after)
    );
}

#[test]
fn an_admission_does_not_survive_the_commit_it_was_taken_against() {
    // HEAD is in the binding so an override cannot outlive the tree it was
    // reasoned about. Asserted here at the surface that consumes it, because the
    // protocol half above proves only that `consume` refuses the presentation.
    let root = admits_fixture("moved-head");
    spend_for(&root, "a.rs", "this case is about the head term");
    let admitted = common::run(&root, &["check"]);
    assert_eq!(
        admitted.status.code(),
        Some(batten::exit::ExitCode::Success.code()),
        "admitted at the head it was taken against: {}",
        common::stderr(&admitted)
    );

    common::write(&root, "c.rs", "fn later() {}\n");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-qm", "move head"]);

    let after = common::run(&root, &["check"]);
    assert_eq!(
        after.status.code(),
        Some(batten::exit::ExitCode::Violation.code()),
        "and refuses again once the tree has moved: {}",
        common::stderr(&after)
    );
}
