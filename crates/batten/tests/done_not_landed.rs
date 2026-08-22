//! Declared done with work not landed, over the compiled binary (CLOUD-97).
//!
//! The unit tests in `src/completion.rs` pin the predicate against explicit
//! values. These pin the half a unit test structurally cannot reach: that the
//! detector is wired to `state record`, that landedness is decided by **patch
//! identity** against a real repository rather than by ancestry, that the
//! finding **self-clears** when the work lands with nobody acknowledging
//! anything, and that no byte of a transcript reaches any stream.
//!
//! A separate target rather than more of `tests/cli.rs`, for the reason
//! `tests/advisory_drain.rs` gives for the same choice: this needs the
//! store-and-home fixture that suite uses, and `tests/cli.rs` is seven thousand
//! lines with several sessions editing it. The issue's §7 asks for E2E over the
//! compiled binary, which is what this is; only the file differs.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Fixture, StateHome, batten, git_in, scratch, stderr, stdout};

/// Every sentinel the three fixture transcripts carry.
///
/// A transcript is the single richest source of secrets the engine can be
/// pointed at, so rule 4 here is not a formality: each of these stands in for a
/// prompt, a command, a tool result, a model's own reasoning, and a hook's deny
/// text. None of them may appear in any output, on any channel.
const CANARIES: &[&str] = &[
    "CANARY-USER-PROMPT",
    "CANARY-THINKING",
    "CANARY-COMMAND",
    "CANARY-RESULT",
    "CANARY-SUMMARY",
    "CANARY-HOOK-STDERR",
];

/// A fixture transcript, read from the checked-in pack.
fn transcript(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transcripts")
        .join(format!("{name}.jsonl.in"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()))
}

/// Run any `batten` subcommand against the fixture's own state home.
fn batten_in(dir: &Path, home: &Path, args: &[&str]) -> Output {
    batten()
        .state_home(home)
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .output()
        .expect("run batten")
}

/// `batten state record`, asserting it exited clean.
///
/// **Always exit 0 is part of the claim**, not a convenience: the finding is
/// advisory, so neither raising it nor clearing it may ever move an exit code.
fn record(dir: &Path, home: &Path) -> Output {
    let output = batten_in(dir, home, &["state", "record"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "state record must stay exit 0 whatever it found: {}",
        stderr(&output)
    );
    output
}

/// The store's pointer lines for the completion rule: `<fp> <rule> <ref> <count>`.
fn recorded(dir: &Path, home: &Path) -> Vec<String> {
    let listed = batten_in(dir, home, &["state", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    stdout(&listed)
        .lines()
        .filter(|line| line.contains(batten::completion::RULE_ID))
        .map(ToOwned::to_owned)
        .collect()
}

/// The count column of the one expected pointer line.
fn one_count(dir: &Path, home: &Path) -> String {
    let lines = recorded(dir, home);
    assert_eq!(lines.len(), 1, "expected exactly one finding: {lines:?}");
    lines[0]
        .rsplit(' ')
        .next()
        .expect("a count column")
        .to_owned()
}

/// A repository whose `work` branch carries a commit `main` does not, plus an
/// isolated state home.
///
/// `must_land_on = "main"` rather than a remote's recorded default: the target
/// ladder is the same one either way ([`batten::worktree`]'s), and a declared
/// key keeps the fixture free of a remote it would otherwise have to fake.
fn unlanded_repo(name: &str, transcript_body: Option<&str>) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\
             must_land_on = \"main\"\n\n\
             [transcript]\n\
             path = \"session.jsonl\"\n",
        )
        .file("src/a.rs", "fn main() {}\n")
        .file(".gitignore", "session.jsonl\n")
        .git()
        .base_commit()
        .build();

    // The work: a commit on `work` with no equivalent on `main`.
    git_in(&repo, &["checkout", "-q", "-b", "work"]);
    common::write(&repo, "src/b.rs", "pub fn added() {}\n");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "add b"]);

    // Untracked, like a real one: a host writes the transcript beside the
    // checkout, and committing it would make the fixture assert a shape no
    // consumer produces.
    if let Some(body) = transcript_body {
        common::write(&repo, "session.jsonl", body);
    }
    let home = Fixture::at(root.join("home")).build();
    (repo, home)
}

#[test]
fn a_completion_signal_with_unlanded_work_raises_the_finding() {
    let (repo, home) = unlanded_repo("cloud97-raises", Some(&transcript("completed-session")));
    let output = record(&repo, &home);
    let reported = stderr(&output);
    assert!(
        reported.contains("completion: raised refs/heads/work"),
        "the report names the outcome and the ref: {reported}"
    );
    assert!(
        reported.contains("session.jsonl:4"),
        "and points at the marker's line: {reported}"
    );
    assert!(
        reported.contains("marker turn-end"),
        "and says which typed field answered: {reported}"
    );
    assert_eq!(one_count(&repo, &home), "1");
}

#[test]
fn a_stop_hook_record_does_not_raise_it() {
    // THE SECOND PRODUCER IS GONE, AND THAT IS THE FIX (CLOUD-887). This
    // asserted `marker stop-hook` — a Stop-family hook run counting as the model
    // declaring done. `transcript.rs` mints that record from ANY host-recorded
    // hook run, and this repository registers a hook on the Stop event that ran
    // on every single turn, so the conjunct CLOUD-97 specified as "declared
    // done" was satisfied by Batten's own bookkeeping and `completion.unlanded`
    // collapsed to `¬landed` — true for a feature branch's whole life.
    //
    // The original reasoning was that "neither producer may be the only one",
    // because a host might run a Stop hook without recording `stop_reason`. That
    // is true and is now answered the other way: a session with no stop reason
    // yields NO claim rather than a claim per hook run. Could-not-look is the
    // correct third value; a constant is not a detector.
    //
    // Fails by restoring the `HookDecision` arm in `completion::signal`.
    let (repo, home) = unlanded_repo("cloud97-stop-hook", Some(&transcript("stop-hook-session")));
    let reported = stderr(&record(&repo, &home));
    assert!(
        !reported.contains("marker stop-hook"),
        "a hook run is machinery observing a moment, never the model claiming one: {reported}"
    );
    // `recorded`, not `one_count`: the helper asserts a line EXISTS, which is the
    // right shape for every other case here and the wrong one for this. A
    // session that never declared anything raises no finding at all, so the
    // assertion is over the empty set rather than over a zero count.
    assert!(
        recorded(&repo, &home).is_empty(),
        "nothing is raised against a session that never declared anything"
    );
}

#[test]
fn landing_by_fast_forward_clears_it_with_no_manual_ack() {
    let (repo, home) = unlanded_repo("cloud97-clears", Some(&transcript("completed-session")));
    record(&repo, &home);
    assert_eq!(one_count(&repo, &home), "1", "raised first");

    // The landing: `main` fast-forwards onto the work, which is how every
    // branch in these repositories lands.
    git_in(&repo, &["branch", "-f", "main", "HEAD"]);

    // No acknowledgement, no disposition, no flag — the next evaluation alone.
    let reported = stderr(&record(&repo, &home));
    assert!(
        reported.contains("completion: cleared refs/heads/work"),
        "{reported}"
    );
    assert_eq!(one_count(&repo, &home), "0", "self-cleared");
}

#[test]
fn a_rebased_then_landed_branch_does_not_raise() {
    // Patch identity, never ancestry. After the cherry-pick `main` carries the
    // same change under a **different SHA** and the branch is not an ancestor
    // of anything — the shape `--is-ancestor` gets wrong and the one these
    // repositories actually produce.
    let (repo, home) = unlanded_repo("cloud97-rebased", Some(&transcript("completed-session")));
    git_in(&repo, &["checkout", "-q", "main"]);
    // `main` moves first, and it has to. A cherry-pick onto the branch's own
    // parent replays the identical tree under the identical parent, and git is
    // deterministic — so it reproduces the **same SHA**, and the fixture would
    // assert the rebased shape while exercising the trivial one. Landing behind
    // somebody else's commit is also what actually happens on a busy trunk.
    common::write(&repo, "src/other.rs", "pub fn elsewhere() {}\n");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "somebody else landed first"]);
    git_in(&repo, &["cherry-pick", "work"]);
    git_in(&repo, &["checkout", "-q", "work"]);

    let head = git_in(&repo, &["rev-parse", "HEAD"]);
    let landed = git_in(&repo, &["rev-parse", "main"]);
    assert_ne!(head, landed, "the fixture must land it under a new SHA");
    // The keystone, asserted rather than assumed: ancestry says this branch did
    // NOT land, and it is wrong. A detector built on `--is-ancestor` would flag
    // work that is already on the trunk — which is the false positive that
    // makes a self-clearing finding fail to clear.
    assert!(
        !common::git_command(&repo, &["merge-base", "--is-ancestor", "HEAD", "main"])
            .status()
            .expect("run git merge-base")
            .success(),
        "the landed branch must not be an ancestor, or the case proves nothing"
    );

    let reported = stderr(&record(&repo, &home));
    assert!(
        reported.contains("completion: cleared"),
        "content equivalence is landedness: {reported}"
    );
    assert!(
        recorded(&repo, &home).is_empty(),
        "a finding that never raised is never minted"
    );
}

#[test]
fn a_transcript_captured_mid_turn_does_not_raise() {
    // The conjunct is real: unlanded work alone is not this finding, or it
    // would fire on every session that ever paused — which is the rejected
    // alternative wearing a detector's clothes.
    let (repo, home) = unlanded_repo("cloud97-mid-turn", Some(&transcript("mid-turn-session")));
    let reported = stderr(&record(&repo, &home));
    assert!(recorded(&repo, &home).is_empty(), "{reported}");
}

#[test]
fn an_unconfigured_transcript_records_nothing_and_says_nothing() {
    // Absent is not empty: a repository that never named a transcript is not
    // missing one, so the run must be byte-identical to one where this feature
    // does not exist.
    let root = scratch("cloud97-unconfigured");
    let repo = Fixture::at(root.join("repo"))
        .config("version = 1\nmust_land_on = \"main\"\n")
        .file("src/a.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    git_in(&repo, &["checkout", "-q", "-b", "work"]);
    common::write(&repo, "src/b.rs", "pub fn added() {}\n");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "add b"]);
    let home = Fixture::at(root.join("home")).build();

    let reported = stderr(&record(&repo, &home));
    assert!(!reported.contains("completion:"), "{reported}");
    assert!(recorded(&repo, &home).is_empty());
}

#[test]
fn an_absent_transcript_holds_the_finding_rather_than_clearing_it() {
    // Two laws in one case, and the second is what `findings::record`'s
    // sequence skip exists for.
    //
    // A configured-but-unreadable transcript means the predicate did not run,
    // so an open finding must **hold**. Nothing here writes it — and that is
    // precisely the exposure: the rule scan beside it resolves every stored
    // identity it did not produce, and this identity has no producer in a rule
    // scan at all. Without the skip, a run that never looked at the transcript
    // clears the incident.
    let (repo, home) = unlanded_repo("cloud97-holds", Some(&transcript("completed-session")));
    record(&repo, &home);
    assert_eq!(one_count(&repo, &home), "1", "raised first");

    std::fs::remove_file(repo.join("session.jsonl")).expect("remove the transcript");
    let reported = stderr(&record(&repo, &home));
    assert!(
        reported.contains(batten::transcript::ABSENT_NOTICE),
        "a skipped predicate says so: {reported}"
    );
    assert_eq!(
        one_count(&repo, &home),
        "1",
        "a scan that never looked must not resolve it"
    );
}

#[test]
fn the_report_is_byte_identical_across_two_runs_over_the_same_inputs() {
    let (repo, home) = unlanded_repo("cloud97-stable", Some(&transcript("completed-session")));
    // The first run binds the store, which is a one-off note about
    // bookkeeping rather than about this predicate. The claim is over runs that
    // read the same world, so the comparison starts once it is bound.
    record(&repo, &home);
    let first = record(&repo, &home);
    let second = record(&repo, &home);
    assert_eq!(
        (stdout(&first), stderr(&first)),
        (stdout(&second), stderr(&second)),
        "same commit, same transcript, same answer, same bytes"
    );
}

#[test]
fn no_transcript_text_reaches_any_output_stream() {
    // The reason the detector reads typed fields and emits pointers. Every
    // canary below is content a session produced, and the store holds none of
    // it either — so the assertion runs over the listing as well as the run.
    for name in ["completed-session", "stop-hook-session"] {
        let (repo, home) =
            unlanded_repo(&format!("cloud97-opaque-{name}"), Some(&transcript(name)));
        let recorded_run = record(&repo, &home);
        let listed = batten_in(&repo, &home, &["state", "list", "-J"]);
        let seen = format!(
            "{}{}{}{}",
            stdout(&recorded_run),
            stderr(&recorded_run),
            stdout(&listed),
            stderr(&listed)
        );
        for canary in CANARIES {
            assert!(
                !seen.contains(canary),
                "{name}: {canary} reached an output stream"
            );
        }
    }
}

#[test]
fn the_finding_is_stored_as_a_settleable_advisory_at_a_latency_tier() {
    // What the drain refuses to emit is a finding with no check or no
    // remediation (CLOUD-81), and what the exit contract reads is a severity.
    // This finding must carry the first two and must never carry a blocking
    // third — asserted over the bytes on disk, because a write path that
    // derived any of them differently is invisible to a test that never wrote.
    let (repo, home) = unlanded_repo("cloud97-shape", Some(&transcript("completed-session")));
    record(&repo, &home);
    let listed = batten_in(&repo, &home, &["state", "list", "-J"]);
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&listed)).expect("the listing is JSON");
    let record = document
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .find(|record| record["rule"] == batten::completion::RULE_ID)
        })
        .expect("the finding is stored");
    assert_eq!(record["tier"], "caution", "CLOUD-80's latency axis");
    assert_eq!(
        record["severity"], "allow",
        "a severity the exit contract cannot promote"
    );
    assert_eq!(record["check"], "reevaluate", "the self-clearing predicate");
    assert!(
        record["remediation"]["no-fix"].is_string(),
        "a stated reason, since no argv this engine may name lands work"
    );
    assert!(
        record["disposition"].is_null(),
        "nothing has settled it yet"
    );
}

#[test]
fn a_spawning_rule_in_the_config_does_not_cost_the_repository_its_detector() {
    // THE STRAND, and the reason CLOUD-97 had never evaluated once in the
    // repository that ships it. `run_state_record` scanned with
    // `rules::run_static`, which refuses *before any work* when any configured
    // rule can spawn a process — so a config carrying one `command` or `secrets`
    // row bought exit 1, no store write, and no transcript detector, at a verb
    // that never wanted to run the rule in the first place. Every real consumer
    // declares such a rule; this repository declares sixteen.
    //
    // The recorder now WITHHOLDS a spawning kind instead: the rule lands in
    // `Scan::not_evaluated`, its findings hold, and everything else proceeds.
    let root = scratch("cloud97-spawning-rule");
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\
             must_land_on = \"main\"\n\n\
             [transcript]\n\
             path = \"session.jsonl\"\n\n\
             [[rule]]\n\
             id = \"spawns\"\n\
             kind = \"command\"\n\
             glob = \"src/**\"\n\
             check = \"true\"\n\
             severity = \"deny\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"fixture\"\n",
        )
        .file("src/a.rs", "fn main() {}\n")
        .file(".gitignore", "session.jsonl\n")
        .git()
        .base_commit()
        .build();
    git_in(&repo, &["checkout", "-q", "-b", "work"]);
    common::write(&repo, "src/b.rs", "pub fn added() {}\n");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "add b"]);
    common::write(&repo, "session.jsonl", &transcript("completed-session"));
    let home = Fixture::at(root.join("home")).build();

    let output = record(&repo, &home);
    assert!(
        output.status.success(),
        "the recorder completes rather than refusing: {}",
        stderr(&output)
    );

    let reported = stderr(&output);
    assert!(
        reported.contains("completion: raised refs/heads/work"),
        "and the detector it was blocking on actually ran: {reported}"
    );

    // Never silent about the half it could not do: a withheld rule that reported
    // nothing would be the false green `run_static`'s refusal exists to prevent.
    assert!(
        reported.contains("1 rule(s) not evaluated"),
        "the withheld rule is counted on the default rung: {reported}"
    );
    assert_eq!(one_count(&repo, &home), "1");
}

#[test]
fn a_withheld_rule_holds_its_findings_rather_than_resolving_them() {
    // The half that makes withholding honest rather than a silent skip. A rule
    // the recorder did not run must not read as "ran and found nothing", or
    // every finding it covers resolves on its silence — CLOUD-81's fail-closed
    // law, and the exact bug that would make this change worse than the refusal
    // it replaces. `-J` is asked, not the prose, so the assertion is over the
    // recorded observation rather than a sentence.
    let root = scratch("cloud97-withheld-holds");
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\
             must_land_on = \"main\"\n\n\
             [[rule]]\n\
             id = \"spawns\"\n\
             kind = \"command\"\n\
             glob = \"src/**\"\n\
             check = \"true\"\n\
             severity = \"deny\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"fixture\"\n",
        )
        .file("src/a.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();

    let output = record(&repo, &home);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("0 resolved"),
        "the withheld rule resolves nothing: {}",
        stderr(&output)
    );
}
