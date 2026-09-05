//! What a run of the adopted gate runner can be evidenced to have done
//! (CLOUD-950).
//!
//! # The state this exists to make impossible
//!
//! The runner provides machine-readable PLANNING and no trustworthy structured
//! per-step LIFECYCLE stream. That absence was undocumented, which is the
//! dangerous state rather than a tidy one: nothing stopped a step-level
//! execution receipt inferred from a process exit, and such a receipt reads
//! exactly like one backed by real evidence.
//!
//! The absence is committed data now — `contracts/hk-evidence.json` — and
//! [`batten::hk::attest`] reads it before it reads anything else. A step
//! attestation under `executionEvents: none` is therefore unwritable rather than
//! discouraged, which is what makes this a gate rather than a note.
//!
//! # The discriminating case
//!
//! [`a_perfect_stream_still_cannot_attest_under_the_shipped_fixture`]. An
//! implementation that only validated event streams passes every other fixture
//! here — the mismatches, the duplicates, the truncation — and fails only that
//! one, because it would accept a well-formed stream nobody could have produced
//! and emit a receipt for a step nobody watched.
//!
//! # Why a capable fixture is also exercised
//!
//! [`the_fixture_format_expresses_the_capability_that_does_not_hold_today`]. A
//! format that could only say "none" would be a comment with a schema, and
//! nothing would prove it able to carry the answer that arrives when the runner
//! gains a stream. Both shapes round-trip here.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use batten::hk::{self, Event, Evidence, ExecutionEvents, Incomplete};

/// The fixture this repository ships.
fn committed() -> Evidence {
    let text = fs::read_to_string(common::at_root(hk::EVIDENCE))
        .expect("the capability fixture is committed");
    Evidence::parse(&text).expect("the fixture is this build's shape")
}

/// The same fixture with the capability that does not hold today.
fn capable() -> Evidence {
    let mut evidence = committed();
    evidence.run_identity = true;
    evidence.plan_digest_binding = true;
    evidence.step_start_events = true;
    evidence.step_terminal_events = true;
    evidence.skipped_step_events = true;
    evidence.final_exit_events = true;
    evidence.execution_events = ExecutionEvents::Structured;
    evidence
}

/// A plan with two included steps and one the runner would skip.
fn plan() -> hk::Planned {
    let value = serde_json::json!({"steps": [
        {"name": "one", "status": "included", "orderIndex": 0, "parallelGroupId": "group_0"},
        {"name": "two", "status": "included", "orderIndex": 1, "parallelGroupId": "group_0"},
        {"name": "slow", "status": "skipped", "orderIndex": 2, "parallelGroupId": "group_0"},
    ]});
    let batten::facts::Look::Is(steps) = hk::planned_steps(&value) else {
        panic!("the fixture plan projects")
    };
    serde_json::from_value(serde_json::json!({
        "hook": "check",
        "runType": "check",
        "profiles": [],
        "invocation": ["check", "--all", "--plan", "--json"],
        "toolVersion": "hk 1.56.1",
        "contractDigest": null,
        "inputFingerprint": "fingerprint",
        "required": [],
        "prohibitedProfiles": [],
        "steps": serde_json::to_value(&steps).expect("the steps serialise"),
    }))
    .expect("a plan fixture")
}

fn event(step: Option<&str>, kind: &str, sequence: u64) -> Event {
    serde_json::from_value(serde_json::json!({
        "run": "run-1",
        "planDigest": "digest-1",
        "step": step,
        "kind": kind,
        "sequence": sequence,
    }))
    .expect("an event fixture")
}

/// A stream with nothing wrong with it: both included steps start and terminate
/// in order, and the run exits.
fn sound_stream() -> Vec<Event> {
    vec![
        event(Some("one"), "start", 0),
        event(Some("one"), "terminal", 1),
        event(Some("two"), "start", 2),
        event(Some("two"), "terminal", 3),
        event(Some("slow"), "skipped", 4),
        event(None, "exit", 5),
    ]
}

/// **The discriminating case.** The shipped fixture refuses a perfect stream.
///
/// This is the whole row: the capability is read first and unconditionally, so
/// no stream can produce a pass while the pinned runner declares none. An
/// implementation that validated the stream first would accept this and emit a
/// receipt for a step nobody watched.
#[test]
fn a_perfect_stream_still_cannot_attest_under_the_shipped_fixture() {
    let evidence = committed();
    assert_eq!(
        evidence.execution_events,
        ExecutionEvents::None,
        "this is the state the row records; if the runner gained a stream, the \
         fixture moves and this case's premise changes with it"
    );
    assert_eq!(
        hk::attest(&evidence, &plan(), "run-1", "digest-1", &sound_stream()),
        Err(Incomplete::Uncapable),
        "no stream attests while the declared capability is none"
    );
    // And with NO events at all, which is what actually reaches this today.
    assert_eq!(
        hk::attest(&evidence, &plan(), "run-1", "digest-1", &[]),
        Err(Incomplete::Uncapable)
    );
}

/// The format expresses the capability that does not hold today.
///
/// Anti-vacuity for the case above: a refusal that were unconditional would
/// satisfy it while proving nothing, so the capable fixture has to accept the
/// sound stream.
#[test]
fn the_fixture_format_expresses_the_capability_that_does_not_hold_today() {
    let capable = capable();
    assert_eq!(capable.execution_events, ExecutionEvents::Structured);
    assert_eq!(
        hk::attest(&capable, &plan(), "run-1", "digest-1", &sound_stream()),
        Ok(()),
        "a sound stream under a capable runner attests; without this the refusal \
         above would be unconditional and would prove nothing"
    );

    // And it round-trips, so the committed shape can carry either answer.
    let text = capable.render().expect("the capable fixture renders");
    assert_eq!(
        Evidence::parse(&text).expect("it reads back"),
        capable,
        "both capability shapes survive the committed format"
    );
}

/// Every incompleteness kind is reachable, and each is its own answer.
///
/// One case per row of the row's own list, over the capable fixture — because
/// under the shipped one they are all `Uncapable` and none of them would be
/// exercised at all.
#[test]
fn every_incompleteness_kind_is_distinct_and_reachable() {
    let capable = capable();
    let plan = plan();

    let mut other_run = sound_stream();
    for entry in &mut other_run {
        entry.run = "run-2".to_owned();
    }
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &other_run),
        Err(Incomplete::RunMismatch)
    );

    let mut other_plan = sound_stream();
    for entry in &mut other_plan {
        entry.plan_digest = "digest-2".to_owned();
    }
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &other_plan),
        Err(Incomplete::PlanMismatch)
    );

    let truncated: Vec<Event> = sound_stream()
        .into_iter()
        .filter(|entry| entry.kind != "exit")
        .collect();
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &truncated),
        Err(Incomplete::Truncated),
        "a stream with no final exit may have been cut off"
    );

    let missing: Vec<Event> = sound_stream()
        .into_iter()
        .filter(|entry| entry.step.as_deref() != Some("two"))
        .collect();
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &missing),
        Err(Incomplete::Missing {
            step: "two".to_owned()
        })
    );

    let mut duplicated = sound_stream();
    duplicated.push(event(Some("one"), "terminal", 6));
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &duplicated),
        Err(Incomplete::Duplicated {
            step: "one".to_owned()
        })
    );

    let out_of_order = vec![
        event(Some("one"), "terminal", 0),
        event(Some("one"), "start", 1),
        event(Some("two"), "start", 2),
        event(Some("two"), "terminal", 3),
        event(None, "exit", 4),
    ];
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &out_of_order),
        Err(Incomplete::OutOfOrder {
            step: "one".to_owned()
        })
    );

    let started_but_never_planned = {
        let mut stream = sound_stream();
        stream.push(event(Some("ghost"), "start", 6));
        stream
    };
    assert_eq!(
        hk::attest(
            &capable,
            &plan,
            "run-1",
            "digest-1",
            &started_but_never_planned
        ),
        Err(Incomplete::Unplanned {
            step: "ghost".to_owned()
        }),
        "a step ran that the plan does not contain"
    );

    // A step the plan SKIPPED needs no terminal, which is the asymmetry a naive
    // implementation gets wrong in the other direction.
    assert_eq!(
        hk::attest(&capable, &plan, "run-1", "digest-1", &sound_stream()),
        Ok(()),
        "a skipped step owes no start and no terminal"
    );
}

/// The kinds render as distinct pointer tokens, and none carries output.
///
/// Rule 4: the report is a kind and a step NAME, never a byte of what the runner
/// printed. Asserted over the rendering, because that is what a reader sees.
#[test]
fn a_kind_renders_as_a_pointer_and_never_as_output() {
    let rendered = [
        Incomplete::Uncapable.render(),
        Incomplete::PlanMismatch.render(),
        Incomplete::RunMismatch.render(),
        Incomplete::Truncated.render(),
        Incomplete::Missing {
            step: "one".to_owned(),
        }
        .render(),
        Incomplete::Duplicated {
            step: "one".to_owned(),
        }
        .render(),
        Incomplete::OutOfOrder {
            step: "one".to_owned(),
        }
        .render(),
        Incomplete::Unplanned {
            step: "one".to_owned(),
        }
        .render(),
    ];
    let unique: std::collections::BTreeSet<&String> = rendered.iter().collect();
    assert_eq!(
        unique.len(),
        rendered.len(),
        "each kind has its own token; a collapse would report two causes as one"
    );
    for token in &rendered {
        assert!(!token.contains('\n'), "a pointer is one line");
        assert!(token.len() < 40, "a pointer is not a payload");
    }
}

/// The committed fixture names the version it was established against.
///
/// A capability is a property of a BUILD. A fixture naming no version would
/// answer for a runner nobody measured — the same keying argument a tool verdict
/// makes, one question over.
#[test]
fn the_fixture_names_the_runner_it_was_established_against() {
    let evidence = committed();
    assert!(!evidence.tool_version.is_empty());
    assert_eq!(evidence.version, 1);
    assert!(
        evidence.plan_schema,
        "the plan IS machine-readable, and stating it is what makes the rest a contrast"
    );
    for absent in [
        evidence.run_identity,
        evidence.plan_digest_binding,
        evidence.step_start_events,
        evidence.step_terminal_events,
        evidence.skipped_step_events,
        evidence.final_exit_events,
    ] {
        assert!(
            !absent,
            "every lifecycle row is absent today; `executionEvents: none` is the summary of that, \
             not a separate claim"
        );
    }
}

/// The committed bytes are the ones this build emits.
///
/// The fixture lives under `contracts/`, which `deno fmt` deliberately does not
/// own — a formatter and a shape gate over one file's bytes are two authorities,
/// which is the fight `completions/*` is excluded from `shfmt` for. This is what
/// owns them instead, so the file has a formatter rather than none.
#[test]
fn the_committed_fixture_is_in_this_builds_own_shape() {
    let text = fs::read_to_string(common::at_root(hk::EVIDENCE))
        .expect("the capability fixture is committed");
    assert_eq!(
        text,
        committed().render().expect("the fixture renders"),
        "the committed bytes drifted from the shape this build emits"
    );
}

/// The fixture the tree ships agrees with the runner the tree pins.
///
/// The tier a fixture cannot reach: a capability recorded against one version
/// and shipped beside another answers for a runner nobody measured.
#[test]
fn the_fixture_and_the_committed_contract_name_one_runner() {
    let evidence = committed();
    let text = fs::read_to_string(common::at_root(hk::ARTIFACT))
        .expect("the surface contract is committed");
    let contract = hk::Contract::parse(&text).expect("the contract parses");
    assert_eq!(
        evidence.tool_version, contract.tool_version,
        "the capability fixture and the surface contract were taken at one pin"
    );
}
