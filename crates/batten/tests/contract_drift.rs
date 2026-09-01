//! Contract drift over the compiled binary (CLOUD-461, CLOUD-525).
//!
//! The unit tests in `src/contract.rs` pin the comparison and the rendering
//! against explicit maps. These pin the half a unit test structurally cannot
//! reach: that the predicate is wired to the **advisory channel** of the `hook`
//! surface, that it is silent by default and silent again the moment after it
//! speaks, and that every path through it exits `0`.
//!
//! This is `tests/contract-drift.bats` ported, and the exit numbers are
//! **translated rather than copied**: the shell tasks use `1 = violation`, where
//! batten's contract is the inverse (house-style §7). Carrying a bats
//! `assert_equal $status 1` across unchanged would assert "unreadable input"
//! while meaning "violation" — and it would pass, which is the false green that
//! hazard exists to name.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::process::{Output, Stdio};

use common::{batten, scratch};

/// The `[contract]` table this suite's fixtures declare.
const CONTRACT: &str = r#"
[contract]
tracked = ["AGENTS.md", ".claude/rules/**", ".claude/settings.json", "mise-tasks/**"]
wiring = [".claude/settings.json"]
"#;

/// A repository with a contract surface, in the shape a consumer declares one.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = scratch(name);
    std::fs::create_dir_all(dir.join(".claude/rules")).unwrap();
    std::fs::create_dir_all(dir.join("mise-tasks")).unwrap();
    std::fs::write(dir.join("batten.toml"), format!("version = 1\n{CONTRACT}")).unwrap();
    std::fs::write(dir.join("AGENTS.md"), "# the contract\n").unwrap();
    std::fs::write(dir.join(".claude/rules/rust.md"), "# rust\n").unwrap();
    std::fs::write(dir.join(".claude/settings.json"), "{\"hooks\":{}}\n").unwrap();
    std::fs::write(dir.join("mise-tasks/a-gate"), "#!/usr/bin/env bash\ntrue\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    dir
}

/// One `PostToolBatch` through `batten hook --harness claude-code`.
fn drift(dir: &Path, session: &str) -> Output {
    drift_on(dir, session, "PostToolBatch", &[])
}

/// The same, on a named event and with `env` set on the child.
///
/// Both parameters exist for one case each, and neither is speculative:
/// `SessionStart` is the second wiring the one body serves, and the environment
/// is how the engine's own hatch is reached. Defaulted away above so the twelve
/// call sites that care about neither still read as one statement.
fn drift_on(dir: &Path, session: &str, event: &str, env: &[(&str, &str)]) -> Output {
    let payload = format!(r#"{{"hook_event_name":"{event}","session_id":"{session}","cwd":"/w"}}"#);
    let mut command = batten();
    command
        .current_dir(dir)
        .args(["hook", "--harness", "claude-code"])
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "a drift notice is never a refusal — house-style §7, and CLOUD-97/CLOUD-219 both"
    );
    output
}

/// The `additionalContext` the host would hand the model, if any.
fn notice(output: &Output) -> Option<String> {
    let raw = common::stdout(output);
    if raw.trim().is_empty() {
        return None;
    }
    // ONE document, asserted rather than assumed. `run_hook` has two advisory
    // producers — the drain and the contract reporter — and a batch can wake
    // both; each writing its own object would put two documents on a channel
    // that carries one, and the host would read the first and drop the rest.
    // The parse below would report that as a trailing-characters error, which
    // names the symptom rather than the invariant.
    assert_eq!(
        raw.lines().filter(|line| !line.trim().is_empty()).count(),
        1,
        "exactly one advisory document reaches stdout per call: {raw}"
    );
    let document: serde_json::Value = serde_json::from_str(&raw).expect("stdout is one document");
    assert!(
        document["hookSpecificOutput"]["permissionDecision"].is_null(),
        "an advisory carries no verdict field"
    );
    Some(
        document["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("an advisory carries additionalContext")
            .to_owned(),
    )
}

/// **RE-DECIDED BY CLOUD-1085**, and the previous decision is quoted rather than
/// deleted because it was right about the case it named and wrong about the case
/// it covered.
///
/// This case read: *"A session that started AFTER a change has already read the
/// new files, so nudging it about them is the noise that gets an advisory channel
/// ignored"* — and asserted silence on the first `PostToolBatch` of a session.
/// The reasoning holds at `SessionStart`, which is the event that argument is
/// about. It does not hold here, and the mirror case below is where it now lives.
///
/// The reporter serves exactly two events and seeds at whichever arrives first,
/// so a seed at `PostToolBatch` means `SessionStart` never reached the engine.
/// Measured on the container that produced CLOUD-1085: SessionStart receipt at
/// 04:37:21, binary at 04:39:58, first snapshot at 04:40:48 — every mediated call
/// in that window failed open in silence, and nothing said so. This case is what
/// makes that observable.
#[test]
fn a_seed_at_a_later_event_reports_the_unmediated_start() {
    let dir = fixture("contract-seed");
    let told = drift(&dir, "s1")
        .pipe_notice()
        .expect("a seed at PostToolBatch means SessionStart never ran");
    assert!(
        told.contains("SessionStart registration did not run"),
        "the notice names the condition rather than the symptom: {told}"
    );
    assert!(
        told.contains("deps-install"),
        "a missing binary is a PROVISIONING failure and the notice names the step: {told}"
    );
    // Once per session. The write is the rate limit here exactly as it is for a
    // change-set, so the very next batch is silent — without this a session with
    // no binary would carry the same line on every batch it ever ran.
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

/// The anti-vacuity mirror, and the home of the reasoning the case above quotes.
///
/// A session whose `SessionStart` DID reach the engine seeds there, silently, and
/// stays silent on every later batch. Without this the case above would pass over
/// a reporter that simply nags on every seed, which is the noise the whole
/// channel is rate-limited to avoid.
///
/// Fails by: dropping the `SessionStart` arm of the event test, so the advisory
/// fires on the seeding event itself.
#[test]
fn a_session_seeded_at_session_start_is_silent_and_stays_silent() {
    let dir = fixture("contract-seeded-at-start");
    assert_eq!(
        drift_on(&dir, "s1", "SessionStart", &[]).pipe_notice(),
        None,
        "the seeding event is the one the silence argument is about"
    );
    assert_eq!(
        drift(&dir, "s1").pipe_notice(),
        None,
        "and a surface that has not moved stays quiet on every later batch"
    );
}

#[test]
fn a_moved_contract_file_is_reported_in_band() {
    let dir = fixture("contract-moved");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nmore\n").unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the surface moved");
    assert!(told.contains("AGENTS.md"), "{told}");
    assert!(told.contains("1 changed"), "{told}");
}

/// **The load-bearing bound.** A suite proving only that it fires would pass on
/// a hook that nags every batch, which is how an advisory channel becomes noise
/// and stops being read.
///
/// Fails by: moving `contract::record` after the emit's early return, or adding
/// a second piece of state that decides whether to speak. The write IS the rate
/// limit.
#[test]
fn a_change_set_is_reported_once_and_the_very_next_batch_is_silent() {
    let dir = fixture("contract-once");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nchange\n").unwrap();

    assert!(drift(&dir, "s1").pipe_notice().is_some(), "it fires");
    assert_eq!(
        drift(&dir, "s1").pipe_notice(),
        None,
        "and the very next batch is silent"
    );
}

#[test]
fn a_second_change_set_is_reported_again_and_quiet_is_not_permanent() {
    let dir = fixture("contract-second");
    drift(&dir, "s1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nfirst\n").unwrap();
    drift(&dir, "s1");
    std::fs::write(dir.join(".claude/rules/rust.md"), "# rust\nsecond\n").unwrap();

    let told = drift(&dir, "s1")
        .pipe_notice()
        .expect("a second change-set");
    assert!(told.contains(".claude/rules/rust.md"), "{told}");
    // The comparison is against what was last REPORTED, not against the
    // session's start, so an already-named file is not named twice.
    assert!(!told.contains("AGENTS.md"), "{told}");
}

#[test]
fn a_newly_added_contract_file_is_drift_and_a_deleted_one_is_too() {
    // The case `[epoch] tracked` structurally cannot express: a stated set of
    // literal paths cannot see a file that did not exist when it was written,
    // and here that file IS the drift.
    let dir = fixture("contract-added");
    drift(&dir, "s1");
    std::fs::write(dir.join("mise-tasks/brand-new-gate"), "#!/bin/sh\ntrue\n").unwrap();
    let added = drift(&dir, "s1")
        .pipe_notice()
        .expect("a new gate is drift");
    assert!(added.contains("mise-tasks/brand-new-gate"), "{added}");

    std::fs::remove_file(dir.join(".claude/rules/rust.md")).unwrap();
    let gone = drift(&dir, "s1").pipe_notice().expect("a removal is drift");
    assert!(gone.contains("no longer tracked"), "{gone}");
    assert!(gone.contains(".claude/rules/rust.md"), "{gone}");
}

#[test]
fn a_file_outside_the_declared_surface_is_not_drift() {
    let dir = fixture("contract-outside");
    drift(&dir, "s1");
    std::fs::write(dir.join("README.md"), "not the contract\n").unwrap();
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

#[test]
fn each_session_is_told_about_what_moved_under_it_and_not_about_the_rest() {
    // Keyed per session, so a session that started after a change is not nudged
    // about one it already has.
    let dir = fixture("contract-sessions");
    drift(&dir, "early");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nmid\n").unwrap();
    // A session whose first batch is now: it reads the CURRENT files at start, so
    // its snapshot is seeded with them and it is told nothing ABOUT THE DRIFT.
    //
    // Asserted over what the notice CLAIMS rather than over its presence, since
    // CLOUD-1085. This fixture drives `PostToolBatch` only, which is by
    // construction the "SessionStart never ran" condition, so `late` does now
    // receive that advisory — a different notice about a different fact. The
    // property this case owns is isolation: `late` never hears about a change-set
    // that predates it. Asserting silence would couple this case to the presence
    // of every other advisory the channel ever carries.
    let late = drift(&dir, "late").pipe_notice().unwrap_or_default();
    assert!(
        !late.contains("AGENTS.md"),
        "a session seeded now is not told about drift that predates it: {late}"
    );
    assert!(
        !late.contains("changed or added"),
        "and is told of no change-set at all: {late}"
    );
    // The session that was already running is told.
    assert!(drift(&dir, "early").pipe_notice().is_some());
}

/// Pointer-only, carried over verbatim in meaning from the bats suite.
///
/// Fails by: rendering content beside the path. A reminder carrying the new text
/// is a mirror, and a mirror is cleared by reading the hook instead of the file.
#[test]
fn the_notice_names_paths_and_never_a_byte_of_one() {
    // Assembled rather than written, and the reason is this repo's own gate:
    // a credential-shaped literal in a tracked file is what `no-secrets`
    // exists to catch, and it caught this one. The planted value is still
    // secret-shaped where it matters — in the file the fixture writes and in
    // every string this case then searches — while the SOURCE carries no
    // token-shaped literal for a scanner to be right about.
    let planted = format!("{}_{}", "ghp", "thisIsTheSortOfThingAFileMustNeverEcho");
    let planted = planted.as_str();
    let dir = fixture("contract-pointer");
    drift(&dir, "s1");
    std::fs::write(
        dir.join(".claude/settings.json"),
        format!("{{\"hooks\":{{}},\"note\":\"{planted}\"}}\n"),
    )
    .unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the surface moved");
    assert!(told.contains(".claude/settings.json"));
    assert!(!told.contains(planted), "the payload must never travel");
    assert!(
        !told.contains("+++") && !told.contains("@@"),
        "and no diff of any kind"
    );
    // Nor may it reach anything under the state root.
    let snapshot = dir.join(".git/batten-contract");
    for entry in std::fs::read_dir(&snapshot).unwrap() {
        let body = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!body.contains(planted), "the snapshot stores hashes only");
    }
}

/// CLOUD-525: the settings.json clause is REPLACED, not deleted, and what
/// replaces it is derivable from the change-set the predicate already has.
///
/// Fails by: emitting the wiring line unconditionally, or restoring a clause
/// whose subject is the session's loaded hook set — an instruction no mechanism
/// can answer, which an agent following it can only guess at.
#[test]
fn a_moved_wiring_file_says_so_computably_and_claims_nothing_about_the_session() {
    let dir = fixture("contract-wiring");
    drift(&dir, "s1");
    std::fs::write(
        dir.join(".claude/settings.json"),
        "{\"hooks\":{\"Stop\":[]}}\n",
    )
    .unwrap();

    let told = drift(&dir, "s1").pipe_notice().expect("the wiring moved");
    assert!(told.contains("The hook wiring is among them"), "{told}");
    assert!(told.contains("batten doctor hooks"), "{told}");
    assert!(
        !told.contains("self-enforced"),
        "the unactionable clause must not come back: {told}"
    );

    // And a change-set that did not touch the wiring says nothing about it.
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nelsewhere\n").unwrap();
    let other = drift(&dir, "s1").pipe_notice().expect("something moved");
    assert!(!other.contains("The hook wiring is among them"), "{other}");
}

#[test]
fn a_repository_that_declares_no_contract_surface_is_silent_rather_than_stable() {
    // Could-not-look, not "nothing moved". The two are different claims, and
    // collapsing them would report an unmeasured repository as stable forever.
    let dir = scratch("contract-undeclared");
    std::fs::write(dir.join("batten.toml"), "version = 1\n").unwrap();
    common::git_in(&dir, &["init", "-q"]);
    common::git_in(&dir, &["add", "-A"]);
    common::git_in(&dir, &["commit", "-qm", "seed"]);
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
    assert!(!dir.join(".git/batten-contract").exists());
}

#[test]
fn a_directory_that_is_not_a_repository_reports_nothing_and_still_allows() {
    // `scratch_outside_tree`, not `scratch`: this is the one fixture shape that
    // must not be inside ANY repository, and `target/tmp/` is inside this one —
    // so discovery would walk up, find the real authority, and the case would be
    // judging batten's own tree rather than an unrepository'd directory.
    let dir = common::scratch_outside_tree("batten-contract-drift", "contract-no-repo");
    std::fs::write(dir.join("batten.toml"), format!("version = 1\n{CONTRACT}")).unwrap();
    assert_eq!(drift(&dir, "s1").pipe_notice(), None);
}

/// A local convenience so the cases above read as one statement each.
trait PipeNotice {
    fn pipe_notice(&self) -> Option<String>;
}

impl PipeNotice for Output {
    fn pipe_notice(&self) -> Option<String> {
        notice(self)
    }
}

// --- the two gaps the CLOUD-908 calibration found ---------------------------
//
// Mapping the 22 bats cases this file replaced turned up two with no successor
// anything in the tree could name. Both are closed here rather than filed,
// because both were reachable from the fixtures already in this file — and a
// mapping arm pointing at a test that had to be written first is the honest
// outcome the ratchet exists to force.

/// One body serves both wirings, and each call says which one it was.
///
/// The bats predecessor asserted this over `SessionStart` and `PostToolBatch`
/// in one case. Nothing here reached `SessionStart` at all — `drift` hard-coded
/// the batch event — and `advisory_drain.rs` pins the echo for `PostToolBatch`
/// alone. So the "both wirings" half was asserted nowhere, which is exactly the
/// coverage evaporation `retires_with` admitted in silence.
///
/// `SessionStart` is the load-bearing half rather than the symmetric one: an
/// autonomous session's first batch is routinely fetch-and-rebase, so a snapshot
/// seeded only at a batch boundary would record post-rebase state and the session
/// would never learn what moved under it.
///
/// Fails by: hard-coding either event name in the emitted document, or wiring
/// the reporter to one event — both of which this suite could not have seen.
#[test]
fn each_wiring_names_the_event_it_was_called_on() {
    for event in ["SessionStart", "PostToolBatch"] {
        let dir = fixture(&format!("contract-event-{event}"));
        // Seed, so the second call is the one with something to say.
        drift_on(&dir, "s-1", event, &[]);
        std::fs::write(dir.join("AGENTS.md"), "# the contract\nmoved\n").unwrap();
        let output = drift_on(&dir, "s-1", event, &[]);

        let raw = common::stdout(&output);
        let document: serde_json::Value =
            serde_json::from_str(&raw).expect("stdout is one document");
        assert_eq!(
            document["hookSpecificOutput"]["hookEventName"], event,
            "the document names the event it was called on, not a constant: {raw}"
        );
        assert!(
            notice(&output).is_some_and(|text| text.contains("AGENTS.md")),
            "and it still reports the change on both wirings: {raw}"
        );
    }
}

/// The mediation hatch does not silence the advisory, and that is deliberate.
///
/// The bats predecessor had `BATTEN_CONTRACT_DRIFT_BYPASS`, and that variable is
/// gone. `.claude/rules/toolchain.md` said the mediated path "takes the engine's
/// own hatch" in its place; measured, it does not — `collect_batch_advice` runs
/// before the bypass reaches anything, and `report_contract_drift` never consults
/// it. This test pins the behaviour that actually holds, and the rule file is
/// corrected to match it rather than the other way round.
///
/// It is the right behaviour. The hatch means *do not mediate this call*, and an
/// advisory decides nothing: it carries no `permissionDecision` and cannot refuse
/// anything. Switching off a channel that only informs would suppress the notice
/// that a contract moved at exactly the moment somebody is working around a gate
/// — which is when knowing is worth most.
///
/// Fails by: gating `collect_batch_advice` or `report_contract_drift` on the
/// bypass, which would restore the retired variable's behaviour under a new name.
#[test]
fn the_mediation_hatch_does_not_silence_the_advisory() {
    let dir = fixture("contract-bypassed");
    drift(&dir, "s-1");
    std::fs::write(dir.join("AGENTS.md"), "# the contract\nmoved\n").unwrap();

    let output = drift_on(&dir, "s-1", "PostToolBatch", &[("BATTEN_HOOK_BYPASS", "1")]);
    assert!(
        notice(&output).is_some_and(|text| text.contains("AGENTS.md")),
        "a bypassed call is unmediated, not uninformed: {:?}",
        common::stdout(&output)
    );
}

// --- the mapping ledger: tests/contract-drift.bats, retired in dd1d6d8 -------
//
// CLOUD-908's calibration, and the retirement it calibrates against is the only
// one the campaign has actually completed. Every one of the 22 `@test` cases the
// deleted suite declared is claimed below by exactly one arm naming a successor
// that resolves. `bats-tests-not-deleted` reads this shape on every future
// deletion; here it is retroactive, because the deletion already landed and
// nothing recorded where the cases went.
//
// One block per retired suite, on its primary successor, so a resuming session
// reads progress off the tree rather than off a chat transcript. A case with no
// arm is untouched work; an arm naming a target this tree lacks is a migration
// that did not happen.
//
// Mapping all 22 turned two of them up as real gaps rather than as bookkeeping,
// which is the outcome the row said was worth more than the mechanism. Both are
// closed above rather than filed, and both arms below point at the test that had
// to be written to make the claim true.
//
// carried: "the first call is the session's start: silent, and it writes a snapshot" crates/batten/tests/contract_drift.rs
// carried: "an unchanged surface produces no output" crates/batten/src/contract.rs kind:mechanism
// carried: "THE GAP: a modified AGENTS.md is reported, naming the file" crates/batten/tests/contract_drift.rs
// carried: "it names the event it was called on, so one body serves both wirings" crates/batten/tests/contract_drift.rs
// carried: "ONCE PER CHANGE-SET: the very next call is silent" crates/batten/tests/contract_drift.rs
// carried: "a SECOND change-set is reported again — quiet is not permanent" crates/batten/tests/contract_drift.rs
// carried: "a newly tracked contract file is drift" crates/batten/tests/contract_drift.rs
// carried: "a contract file that stopped being tracked is drift too" crates/batten/tests/contract_drift.rs
// carried: "a file outside the surface does not fire it" crates/batten/tests/contract_drift.rs
// carried: "each session gets its own snapshot, so a session that started AFTER the change is not nudged" crates/batten/tests/contract_drift.rs
// carried: "a session id carrying path characters cannot escape the snapshot store" crates/batten/src/contract.rs kind:mechanism
// carried: "the reminder carries no byte of the changed file's content" crates/batten/tests/contract_drift.rs
// carried: "when settings.json moved it says a new hook may not be loaded in this session" crates/batten/tests/contract_drift.rs
// carried: "outside a checkout there is no surface to judge" crates/batten/tests/contract_drift.rs
//
// SUBSUMED — the plumbing the case tested became the engine's rather than the
// script's, which is what a migration should produce. Each names the general
// property that now covers it.
//
// subsumed: "the snapshot is one line per tracked contract file, hash and path" crates/batten/src/contract.rs kind:mechanism
// subsumed: "a payload with no session_id still works, on a shared key" crates/batten/src/contract.rs kind:mechanism
// subsumed: "unparseable input fails open" crates/batten/tests/cli.rs
// subsumed: "empty input fails open" crates/batten/tests/cli.rs
// subsumed: "it emits a count as well as the paths" crates/batten/src/contract.rs kind:mechanism
// subsumed: "the emitted document is the hook shape, and it parses" crates/batten/tests/advisory_drain.rs
//
// CHANGED — behaviour that diverges deliberately. The bats suite asserted the
// opposite of each of these, and nothing in the tree marked the change until now.
//
// changed: "an untracked file under mise-tasks is not contract" crates/batten/tests/contract_drift.rs the surface is globs now, so a newly added gate IS the drift — `[epoch] tracked`'s literal paths structurally cannot see a file that postdates the list
// changed: "the bypass is honoured" crates/batten/tests/contract_drift.rs BATTEN_CONTRACT_DRIFT_BYPASS is gone and the engine's hatch deliberately does not reach an advisory: it carries no verdict and refuses nothing, so a switch over it would only suppress news
