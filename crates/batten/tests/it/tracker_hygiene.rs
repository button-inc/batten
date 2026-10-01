//! The `tracker-hygiene` preset over the compiled binary: `batten record derive
//! <family>` reading a piped board or pull-request body, and `batten check`
//! deciding over what it recorded (CLOUD-843).
//!
//! # One tier for five gates, because they became one row
//!
//! `done-check`, `done-pr-check`, `duplicate-close-check`, `deferral-check` and
//! `closing-key-check` each ran a bash body — four of them a producer beside a
//! consumer module, one a whole gate — and each had its own suite over its own
//! body. The readings are now `crate::tracker_reading` and the decisions the
//! preset's modules, checked by one `[[rule]]` row; so every case here produces a
//! record with the real verb and asks the real row, the way `mise run <gate>`
//! does. Each gate's exit table is the engine's now: `0` clean, `2` refused, `1`
//! could not look (the producer refused and recorded nothing).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/done-check.sh crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: tests/done-check.bats crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: "a Done issue whose commits are in a release tag is left alone" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// carried: "a Done issue landed past the last tag is reported — this is the defect" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// carried: "landing then releasing clears the very same issue" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// carried: "a Done issue no commit names is noted, not failed" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// carried: "one released ref is enough, even with later unreleased ones" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// "a prefix does not match a longer id" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// "issues in other columns are none of this gate's business" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// "the pipeline does not eat the verdict" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// carried: "several issues are each judged, in stable numeric order" crates/batten/src/policy/presets/tracker-hygiene/done-is-released.rego kind:mechanism
// "output is a pointer — identifiers and target state, never issue bodies" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// "a concatenated payload stream is accepted, like graph-check's" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// "an unresolvable origin/main exits 2 — a checkout problem, not a clean board" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// carried: "a clone with no tags exits 2 — the opposite false verdict" crates/batten/src/tracker_reading.rs kind:mechanism
// "empty stdin exits 2, distinct from a clean board" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// "unparseable stdin exits 2" shares its title with a case already ledgered in `landed_check.rs`; a title owes exactly one arm, so that row answers for both suites.
// carried: mise-tasks/done-pr-check.sh crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: tests/done-pr-check.bats crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: "every attached PR merged: Done is licensed" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "an OPEN pull request refuses, and the refusal names its number" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "THE DEFECT: a DRAFT pull request refuses, and is named as a draft" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "one open PR among several merged still refuses — N=1 is the only safe case" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "a closed-unmerged PR does NOT refuse — a decided outcome is not work in flight" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "no pull request at all is refused — In Review already requires one" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "a non-PR attachment is ignored, not counted as a pull request" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "a PR-shaped URL on another host is not a PR — the filter is GitHub-anchored" crates/batten/src/tracker_reading.rs the reading uses the crate's one pull-request spelling, `landed::is_pull_request_url`, which CLOUD-1623 made host-free on purpose; a `/pull/<n>` URL on another forge is now a pull request, and with no state piped for it the gate is could-not-look rather than a pass — stricter, never looser
// carried: "an attachment whose URL only mentions pull is not a PR" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "COULD NOT LOOK: an attached PR with no state supplied is exit 2, never a licence" crates/batten/src/tracker_reading.rs still never a licence; the producer refuses, records nothing, and the gate exits 1 — the engine's could-not-look — where the body exited 2
// carried: "a missing pulls key is could-not-look too, not an empty set of blockers" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "several issues are each judged, and one bad issue refuses the batch" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "a duplicate attachment for one PR is counted once" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "empty stdin is exit 2, distinct from a licensed issue" crates/batten/src/tracker_reading.rs still distinct from a licence; exit 1, the engine's could-not-look, with nothing recorded
// changed: "unparseable stdin is exit 2" crates/batten/src/tracker_reading.rs exit 1, the engine's could-not-look, with nothing recorded
// changed: "a payload with no id is exit 2, never a pass" crates/batten/src/tracker_reading.rs exit 1, the engine's could-not-look, with nothing recorded
// carried: "a concatenated payload stream is accepted, like claim-check's" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "THE PROPERTY: output is a pointer — an id, a rule and a number, never a title" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: "THE REGRESSION: CLOUD-420's real shape refuses, naming the draft nobody noticed" crates/batten/src/policy/presets/tracker-hygiene/done-has-no-open-pull.rego kind:mechanism
// carried: mise-tasks/duplicate-close-check.sh crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego crates/batten/tests/it/tracker_hygiene.rs
// carried: tests/duplicate-close-check.bats crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego crates/batten/tests/it/tracker_hygiene.rs
// carried: "a duplicate close in the same operation as its target's close is refused" crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego kind:mechanism
// changed: "the refusal demands a decision rather than judging who was right" crates/batten/src/preset.rs the words moved from the adapter's stderr into the vendored `issue grade twice` class, which `batten policy explain` renders; the refusal itself is the pair pointer
// carried: "a duplicate close whose target completed days earlier passes" crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego kind:mechanism
// carried: "a duplicate close whose target is not completed at all passes" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a set with no duplicates at all passes" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a close one second outside the window passes, which is the stated bound" crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego kind:mechanism
// changed: "a set with no duplicateOf key anywhere is could not look" crates/batten/src/tracker_reading.rs never the clean line; the producer refuses, names the re-fetch and records nothing, and the gate exits 1 — the engine's could-not-look — where the adapter exited 2
// carried: "an explicit null duplicateOf is data, not an unjudgeable payload" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "a duplicate whose target was not piped is unjudgeable, never clean" crates/batten/src/tracker_reading.rs the producer's refusal naming both keys, with nothing recorded, at exit 1
// changed: "a duplicate close carrying no canceledAt is unjudgeable, never clean" crates/batten/src/tracker_reading.rs the producer's refusal naming the row, with nothing recorded, at exit 1
// changed: "could not look outranks a refusal, so a half-read set is never exit 1" crates/batten/src/tracker_reading.rs still never the refusal lane: a half-read set is the producer's refusal, which is exit 1 on the engine's table while a refusal is exit 2
// changed: "duplicate-close-check.bats::empty stdin is exit 2, never a verdict" crates/batten/src/tracker_reading.rs never a verdict; exit 1, the engine's could-not-look
// changed: "stdin that is not a payload set is exit 2" crates/batten/src/tracker_reading.rs exit 1, the engine's could-not-look
// carried: "the report carries no line of either body" crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego kind:mechanism
// carried: "duplicate-close-check.bats::the report is byte-stable across runs" crates/batten/src/policy/presets/tracker-hygiene/duplicate-close-is-argued.rego kind:mechanism
// carried: mise-tasks/deferral-check.sh crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: tests/deferral-check.bats crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: "a deferral with no owner in its paragraph fails" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "a deferral that names its owning issue passes" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "the scope is the paragraph, not the body" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a paragraph is read whole, so a key on another line of it still exempts" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "naming the phrase in a code span is not using it" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a body with no deferral shape passes" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "an empty body passes rather than erroring" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "the American spelling is caught too" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a deferral exempted only by the PR's own claimed issue fails" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "a deferral naming an issue the PR does not claim passes" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "naming both the claimed issue and a real owner passes" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "a closing keyword in the body claims that issue too" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "outside a git checkout the narrowing fails open" crates/batten/src/tracker_reading.rs the fail-open survives inside the producer — an unresolvable claim is recorded as `claimed -`, which subtracts nothing — but a producer outside a checkout has no repository to record INTO, so the old case's shape (a verdict with no checkout at all) no longer exists. `a_deferral_with_no_claim_is_owned_by_any_key_it_names` pins the half that remains
// carried: "an unverified claim with no owner fails — the second measured shape" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "an unverified claim that names its owner passes" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego kind:mechanism
// carried: "a dropped candidate shape does not fire" crates/batten/src/tracker_reading.rs kind:mechanism
// changed: "the report is a pointer, never the paragraph" crates/batten/src/policy/presets/tracker-hygiene/deferral-has-an-owner.rego the pointer is narrower now: the paragraph NUMBER, where the program printed the paragraph's first 60 characters. Those characters were prose on the decision surface, which rule 4 keeps off it; the case asserts the prose is absent
// carried: mise-tasks/closing-key-check.sh crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: tests/closing-key-check.bats crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism crates/batten/tests/it/tracker_hygiene.rs
// carried: "the measured failing body — named, never closed — is refused" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "the measured passing body — a closing keyword — is accepted" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "all three verbs in all three inflections close" crates/batten/src/ready.rs kind:mechanism
// carried: "case and the optional punctuation the integration tolerates" crates/batten/src/ready.rs kind:mechanism
// carried: "the keyword and the key must be ADJACENT, not merely both present" crates/batten/src/ready.rs kind:mechanism
// carried: "a body that MENTIONS the marker has not used it" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a closing key wins over a marker the body merely discusses" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "DO-NOT-CLOSE opts out — a PR that does not complete its issue" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a body that both closes and opts out is reported as closing" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "the marker may name the issue it declines to close" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a hyphen-prefixed verb is still not a close, wherever it appears" crates/batten/src/ready.rs kind:mechanism
// carried: "an indented marker still opts out — leading whitespace is not a mention" crates/batten/src/tracker_reading.rs kind:mechanism
// carried: "a body naming no key at all is the key rule's case, not this one" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "one closed key is enough, even beside a named-but-unclosed one" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a key embedded in a longer token is not a key" crates/batten/src/ready.rs kind:mechanism
// carried: "several named keys are each reported, in stable numeric order" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "output is a pointer — keys and a verdict, never a line of the body" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// changed: "empty stdin exits 2, distinct from a passing body" crates/batten/src/tracker_reading.rs still distinct from a passing body; exit 1, the engine's could-not-look, with nothing recorded
// changed: "whitespace-only stdin exits 2 as well" crates/batten/src/tracker_reading.rs exit 1 as well, with nothing recorded
// withdrawn: "the positive control: PR #491's real body closes every key its branch served" the case replayed one captured body against a served log passed through `--served-log`. That flag is gone — the producer reads the branch it runs on — and the property the control guarded, that a body closing every served key passes, is `a_body_closing_every_served_key_passes`
// carried: "a body closing a strict subset of the served keys is refused" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "the strand refusal names keys and a remedy, never a line of the body" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "only the FIRST key of a Refs: trailer is served — the rest are citations" crates/batten/src/race.rs kind:mechanism
// carried: "DO-NOT-CLOSE exempts the subtraction, not merely the closing form" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a branch whose commits carry no Refs: trailer is not judged" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a single-ticket PR is unaffected" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// withdrawn: "--served-log '' is distinct from the flag being absent" the flag was an injection seam for a suite run from inside this repository, so a served set read from git would depend on whichever branch was checked out. The producer runs in its fixture's own checkout, so there is no ambient branch to shield and no flag to distinguish
// changed: "--list decides nothing, even when keys are stranded" crates/batten/src/recorder.rs `--list` was the `pr-closes` recorder's only way to reuse the closing-verb regex without a second copy. That caller now asks the `closing-keys` authority, which is the grammar's own reading and decides nothing by construction — it returns keys and a zero status
// carried: "the served set ignores a closing keyword — the comparison is not circular" crates/batten/src/race.rs kind:mechanism
// carried: "a marker naming a key exempts THAT key and no other" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a keyed marker does not excuse a key it never named" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism
// carried: "a bare marker still declines the whole body" crates/batten/src/policy/presets/tracker-hygiene/closing-key-closes.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{git_in, init_repo, run, scratch, write};

/// The one row every tracker question is checked under — the committed one.
const ROW: &str = "issue state other";

/// The five families, each declared as a consumer declares any record a module
/// reads.
const FAMILIES: [&str; 5] = [
    "done",
    "done-pr",
    "duplicate-close",
    "deferral",
    "closing-key",
];

/// This repository's inputs for each family, as `mise.toml` passes them.
const DONE: [&str; 3] = ["released=v[0-9]*", "landed=origin/main", "done=Done"];
const DEFERRAL: [&str; 2] = ["shape=deferral-shape", "base=origin/main"];
const CLOSING: [&str; 2] = ["hold=closing-hold-marker", "base=origin/main"];

/// An authority enabling the preset under [`ROW`], declaring the five families,
/// with `patterns` appended.
fn authority(patterns: &str) -> String {
    let mut records = String::new();
    for family in FAMILIES {
        write!(
            records,
            "[[record]]\nrecord = \"{family}\"\nwriter = \"batten record derive {family}\"\n\n"
        )
        .expect("a String takes a write");
    }
    format!(
        "version = 1\nscope = [\"**\"]\n\n[[rule]]\nid = \"{ROW}\"\nkind = \"policy\"\n\
         scope = \"tree\"\npreset = \"tracker-hygiene\"\nseverity = \"deny\"\n\n{records}{patterns}"
    )
}

/// A fresh repository carrying [`authority`], with the committed `[[pattern]]`
/// rows when `patterns` — the key grammar and the two consumer concepts the
/// body-reading families take by id.
fn fixture(name: &str, patterns: bool) -> PathBuf {
    let dir = scratch(&format!("tracker-hygiene-{name}"));
    let table = if patterns {
        common::declared_patterns()
    } else {
        String::new()
    };
    write(&dir, "batten.toml", &authority(&table));
    init_repo(&dir);
    dir
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// `mise run <gate>`, spelled as its two argv entries: record the family over
/// `stdin`, then check the one row. The first entry's failure is the gate's
/// answer, exactly as a task runner reports it.
fn gate(dir: &Path, family: &str, inputs: &[&str], stdin: &str) -> (Option<i32>, String) {
    let mut args: Vec<&str> = vec!["record", "derive", family];
    for &input in inputs {
        args.extend(["--input", input]);
    }
    let produced = common::run_with_stdin(dir, &args, stdin);
    if !produced.status.success() {
        return (produced.status.code(), said(&produced));
    }
    let decided = run(dir, &["check", "--rule", ROW]);
    (
        decided.status.code(),
        format!("{}{}", said(&produced), said(&decided)),
    )
}

/// The row alone, over whatever the store holds.
fn decide(dir: &Path) -> (Option<i32>, String) {
    let decided = run(dir, &["check", "--rule", ROW]);
    (decided.status.code(), said(&decided))
}

/// A record written as-is, for the torn cases.
fn record_raw(dir: &Path, family: &str, lines: &str) {
    let written = common::run_with_stdin(dir, &["record", "named", family], lines);
    assert!(written.status.success(), "{}", said(&written));
}

// ---------------------------------------------------------------------------
// done — no issue reads Done while no release tag contains its commits.
// ---------------------------------------------------------------------------

/// `main` as the trunk, HEAD on a feature branch, and one release tag — every
/// case needs a tag or it meets the tagless refusal instead of the predicate.
fn done_repo(name: &str) -> PathBuf {
    let dir = fixture(&format!("done-{name}"), false);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    git_in(&dir, &["branch", "main"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "main"]);
    git_in(&dir, &["tag", "v0.0.1", "main"]);
    dir
}

/// A commit on `main` carrying `message`, with `origin/main` following it.
fn land(dir: &Path, message: &str) {
    git_in(dir, &["checkout", "-q", "main"]);
    git_in(dir, &["commit", "-q", "--allow-empty", "-m", message]);
    git_in(dir, &["update-ref", "refs/remotes/origin/main", "main"]);
}

fn release(dir: &Path, tag: &str) {
    git_in(dir, &["tag", tag, "main"]);
}

fn done_board(id: &str) -> String {
    format!("[{{\"id\":\"{id}\",\"status\":\"Done\"}}]")
}

#[test]
fn a_done_issue_landed_past_the_last_tag_is_refused() {
    let dir = done_repo("landed");
    land(&dir, "feat: work\n\nRefs: CLOUD-499");
    let (code, text) = gate(&dir, "done", &DONE, &done_board("CLOUD-499"));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-499"), "{text}");
}

#[test]
fn landing_then_releasing_clears_the_same_issue() {
    let dir = done_repo("released");
    land(&dir, "feat: work\n\nRefs: CLOUD-499");
    assert_eq!(
        gate(&dir, "done", &DONE, &done_board("CLOUD-499")).0,
        Some(2)
    );
    release(&dir, "v0.0.2");
    let (code, text) = gate(&dir, "done", &DONE, &done_board("CLOUD-499"));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn one_released_ref_is_enough_even_with_a_later_unreleased_one() {
    let dir = done_repo("most-released");
    land(&dir, "feat: first\n\nRefs: CLOUD-186");
    release(&dir, "v0.0.2");
    land(&dir, "feat: second\n\nRefs: CLOUD-186");
    let (code, text) = gate(&dir, "done", &DONE, &done_board("CLOUD-186"));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_done_issue_no_commit_names_is_not_judged() {
    let dir = done_repo("unlanded");
    let (code, text) = gate(&dir, "done", &DONE, &done_board("CLOUD-99999"));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_prefix_does_not_match_a_longer_id() {
    // CLOUD-17 must not be refuted by a commit naming CLOUD-179.
    let dir = done_repo("prefix");
    land(&dir, "feat: work\n\nRefs: CLOUD-179");
    let (code, text) = gate(&dir, "done", &DONE, &done_board("CLOUD-17"));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn an_issue_in_another_column_is_not_judged() {
    let dir = done_repo("columns");
    land(&dir, "feat: work\n\nRefs: CLOUD-5");
    let (code, text) = gate(
        &dir,
        "done",
        &DONE,
        r#"[{"id":"CLOUD-5","status":"In Review"},{"id":"CLOUD-5","status":"Todo"}]"#,
    );
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn several_issues_are_each_judged_and_the_output_is_a_pointer() {
    // Three landed commits, so a history read through a pipe that SIGPIPEd would
    // have found nothing; and a payload carrying prose that must not surface.
    let dir = done_repo("several");
    land(&dir, "feat: a\n\nRefs: CLOUD-2");
    land(&dir, "feat: b\n\nRefs: CLOUD-10");
    land(&dir, "feat: c\n\nRefs: CLOUD-3");
    let (code, text) = gate(
        &dir,
        "done",
        &DONE,
        "{\"id\":\"CLOUD-10\",\"status\":\"Done\",\"description\":\"customer detail\"}\n\
         {\"id\":\"CLOUD-2\",\"status\":\"Done\"}",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("CLOUD-10"),
        "{text}"
    );
    assert!(!text.contains("customer detail"), "pointer only: {text}");
}

#[test]
fn a_record_without_its_census_is_torn_rather_than_clean() {
    let dir = done_repo("torn");
    record_raw(&dir, "done", "issue\tCLOUD-1\tdone\tshipped\n");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
}

#[test]
fn the_done_reading_refuses_every_input_it_cannot_read_and_records_nothing() {
    // FOUR COULD-NOT-LOOKS, each exit 1 and each writing no record — so the
    // engine afterwards has nothing to judge and says nothing, rather than a
    // clean or a red verdict over a fetch problem.
    let empty = done_repo("empty-stdin");
    assert_eq!(gate(&empty, "done", &DONE, "").0, Some(1));
    let garbled = done_repo("garbled-stdin");
    assert_eq!(gate(&garbled, "done", &DONE, "not json").0, Some(1));

    let unresolved = done_repo("no-origin");
    git_in(
        &unresolved,
        &["update-ref", "-d", "refs/remotes/origin/main"],
    );
    let (code, text) = gate(&unresolved, "done", &DONE, &done_board("CLOUD-5"));
    assert_eq!(code, Some(1), "no trunk is a checkout problem: {text}");

    let tagless = done_repo("no-tags");
    land(&tagless, "feat: work\n\nRefs: CLOUD-5");
    git_in(&tagless, &["tag", "-d", "v0.0.1"]);
    let (code, text) = gate(&tagless, "done", &DONE, &done_board("CLOUD-5"));
    assert_eq!(code, Some(1), "no tags is a fetch problem: {text}");
    let (after, text) = decide(&tagless);
    assert_eq!(after, Some(0), "and nothing was recorded: {text}");
}

// ---------------------------------------------------------------------------
// done-pr — an issue may become Done only if none of its pull requests is open.
// ---------------------------------------------------------------------------

fn url(n: u32) -> String {
    format!("https://github.com/example-org/example-repo/pull/{n}")
}

fn pull(n: u32, state: &str, merged: bool, draft: bool) -> String {
    format!(r#"{{"number":{n},"state":"{state}","merged":{merged},"draft":{draft}}}"#)
}

fn merged(n: u32) -> String {
    pull(n, "closed", true, false)
}

/// One issue: its attachment URLs and the pull states the caller fetched.
fn issue(id: &str, urls: &[String], pulls: &[String]) -> String {
    let attachments: Vec<String> = urls.iter().map(|u| format!(r#"{{"url":"{u}"}}"#)).collect();
    format!(
        r#"{{"id":"{id}","attachments":[{}],"pulls":[{}]}}"#,
        attachments.join(","),
        pulls.join(",")
    )
}

fn set(issues: &[String]) -> String {
    format!("[{}]", issues.join(","))
}

/// The done-pr gate over `stdin`, in a fixture of its own.
fn done_pr(name: &str, stdin: &str) -> (Option<i32>, String) {
    let dir = fixture(&format!("done-pr-{name}"), false);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    gate(&dir, "done-pr", &[], stdin)
}

#[test]
fn every_attached_pr_merged_licenses_done() {
    let (code, text) = done_pr(
        "merged",
        &set(&[issue("CLOUD-425", &[url(346)], &[merged(346)])]),
    );
    assert_eq!(code, Some(0), "{text}");
    // Closed-unmerged is a decided outcome, not work in flight.
    let (code, text) = done_pr(
        "abandoned",
        &set(&[issue(
            "CLOUD-1",
            &[url(10), url(11)],
            &[pull(10, "closed", false, false), merged(11)],
        )]),
    );
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn an_open_pull_request_refuses_naming_its_number() {
    let (code, text) = done_pr(
        "open",
        &set(&[issue(
            "CLOUD-1",
            &[url(500)],
            &[pull(500, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-1#500"), "{text}");
    // One open among several merged still refuses.
    let (code, text) = done_pr(
        "one-of-three",
        &set(&[issue(
            "CLOUD-1",
            &[url(1), url(2), url(3)],
            &[merged(1), merged(2), pull(3, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-1#3"), "{text}");
}

#[test]
fn the_defect_a_draft_pull_request_refuses_named_as_a_draft() {
    let (code, text) = done_pr(
        "draft",
        &set(&[issue(
            "CLOUD-1",
            &[url(368)],
            &[pull(368, "open", false, true)],
        )]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-1#368:draft"), "{text}");
    // THE REGRESSION: CLOUD-420's real shape.
    let (code, text) = done_pr(
        "cloud-420",
        &set(&[issue(
            "CLOUD-420",
            &[url(362), url(363), url(366), url(368)],
            &[
                merged(362),
                merged(363),
                merged(366),
                pull(368, "open", false, true),
            ],
        )]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-420#368:draft"), "{text}");
}

#[test]
fn no_pull_request_at_all_is_refused() {
    let (code, text) = done_pr("no-pr", r#"[{"id":"CLOUD-1","attachments":[],"pulls":[]}]"#);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-1"), "{text}");
}

#[test]
fn a_non_pr_attachment_is_not_a_pull_request() {
    for (n, other) in [
        "https://tracker.example/document/x",
        "https://example.com/how-to-pull/123",
    ]
    .iter()
    .enumerate()
    {
        let (code, text) = done_pr(
            &format!("non-pr-{n}"),
            &set(&[issue(
                "CLOUD-1",
                &[(*other).to_owned(), url(7)],
                &[merged(7)],
            )]),
        );
        assert_eq!(code, Some(0), "{other}: {text}");
    }
}

/// CLOUD-1623's one spelling is host-free, so a `/pull/<n>` URL on another forge
/// is a pull request — and one nobody fetched a state for is could-not-look,
/// never a pass.
#[test]
fn a_pr_shaped_url_on_another_host_is_a_pr_and_needs_its_state() {
    let (code, text) = done_pr(
        "other-host",
        &set(&[issue(
            "CLOUD-1",
            &["https://forge.example/acme/x/pull/999".to_owned(), url(7)],
            &[merged(7)],
        )]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("#999"), "{text}");
}

#[test]
fn an_attached_pr_with_no_state_is_could_not_look() {
    let (code, text) = done_pr("no-state", &set(&[issue("CLOUD-1", &[url(42)], &[])]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("#42") && text.contains("no state"), "{text}");
    let missing = format!(
        r#"[{{"id":"CLOUD-1","attachments":[{{"url":"{}"}}]}}]"#,
        url(42)
    );
    assert_eq!(done_pr("no-pulls", &missing).0, Some(1));
}

#[test]
fn several_issues_are_judged_and_one_refuses_the_batch() {
    let (code, text) = done_pr(
        "batch",
        &set(&[
            issue("CLOUD-1", &[url(1)], &[merged(1)]),
            issue("CLOUD-2", &[url(2)], &[pull(2, "open", false, false)]),
        ]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-2#2"), "{text}");
    assert!(!text.contains("CLOUD-1#1"), "{text}");
    // A duplicate attachment for one PR is one pull request, recorded once.
    let (code, text) = done_pr(
        "duplicate",
        &set(&[issue(
            "CLOUD-1",
            &[url(9), url(9)],
            &[pull(9, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(2), "{text}");
    assert_eq!(text.matches("pull\tCLOUD-1\t9\t").count(), 1, "{text}");
}

#[test]
fn unreadable_stdin_is_could_not_look() {
    assert_eq!(done_pr("empty", "").0, Some(1));
    assert_eq!(done_pr("garbage", "not json").0, Some(1));
    assert_eq!(done_pr("no-id", r#"[{"attachments":[]}]"#).0, Some(1));
}

#[test]
fn a_concatenated_payload_stream_is_accepted() {
    let stream = format!(
        "{}\n{}\n",
        issue("CLOUD-1", &[url(1)], &[merged(1)]),
        issue("CLOUD-2", &[url(2)], &[merged(2)])
    );
    let (code, text) = done_pr("stream", &stream);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_output_is_a_pointer_never_a_title() {
    let payload = format!(
        r#"[{{"id":"CLOUD-1","attachments":[{{"url":"{}","title":"a distinctive title no gate may echo"}}],"pulls":[{{"number":500,"state":"open","merged":false,"draft":false,"title":"another distinctive title"}}]}}]"#,
        url(500)
    );
    let (code, text) = done_pr("pointer", &payload);
    assert_eq!(code, Some(2), "{text}");
    assert!(!text.contains("distinctive title"), "{text}");
}

#[test]
fn a_done_pr_record_without_its_census_is_torn() {
    let dir = fixture("done-pr-torn", false);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    record_raw(&dir, "done-pr", "issue\tCLOUD-1\t0\n");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
}

// ---------------------------------------------------------------------------
// duplicate-close — a duplicate close decided in its target's own operation.
// ---------------------------------------------------------------------------

const OP: &str = "2026-08-21T02:37:51.492Z";

/// `row(id, canceledAt, completedAt, duplicateOf)`; `None` is JSON null.
fn row(id: &str, cancel: Option<&str>, complete: Option<&str>, dup: Option<&str>) -> String {
    let quote = |v: Option<&str>| v.map_or("null".to_owned(), |v| format!("\"{v}\""));
    let dup = dup.map_or("null".to_owned(), |d| format!("{{\"id\":\"{d}\"}}"));
    format!(
        r#"{{"id":"{id}","canceledAt":{},"completedAt":{},"relations":{{"blockedBy":[],"blocks":[],"relatedTo":[],"duplicateOf":{dup}}}}}"#,
        quote(cancel),
        quote(complete)
    )
}

fn duplicate_repo(name: &str) -> PathBuf {
    let dir = fixture(&format!("duplicate-close-{name}"), false);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    dir
}

fn duplicate(dir: &Path, rows: &[String]) -> (Option<i32>, String) {
    gate(dir, "duplicate-close", &[], &rows.join("\n"))
}

fn pair() -> Vec<String> {
    vec![
        row("CLOUD-777", None, Some(OP), None),
        row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
    ]
}

#[test]
fn a_duplicate_close_in_its_targets_operation_is_refused() {
    let dir = duplicate_repo("measured");
    let (code, text) = duplicate(&dir, &pair());
    assert_eq!(code, Some(2), "{text}");
    // Both keys named: a reader must be able to find the decision taken beside.
    assert!(text.contains("CLOUD-817>CLOUD-777"), "{text}");
}

#[test]
fn closes_in_different_seconds_pass() {
    let dir = duplicate_repo("seconds");
    for target_at in ["2026-08-14T09:00:00.000Z", "2026-08-21T02:37:52.000Z"] {
        let rows = [
            row("CLOUD-777", None, Some(target_at), None),
            row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
        ];
        let (code, text) = duplicate(&dir, &rows);
        assert_eq!(code, Some(0), "{target_at}: {text}");
    }
}

#[test]
fn an_uncompleted_target_and_a_set_without_duplicates_pass() {
    let dir = duplicate_repo("clean");
    let uncompleted = [
        row("CLOUD-777", None, None, None),
        row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
    ];
    assert_eq!(duplicate(&dir, &uncompleted).0, Some(0));
    // An explicit null duplicateOf is data, never could-not-look.
    let (code, text) = duplicate(&dir, &[row("CLOUD-1", None, None, None)]);
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("re-fetch"), "{text}");
}

#[test]
fn a_set_with_no_duplicateof_key_anywhere_is_could_not_look() {
    let dir = duplicate_repo("unkeyed");
    let unkeyed = [String::from(
        r#"{"id":"CLOUD-1","canceledAt":null,"completedAt":null,"relations":{"blockedBy":[]}}"#,
    )];
    let (code, text) = duplicate(&dir, &unkeyed);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("includeRelations"), "{text}");
}

#[test]
fn a_duplicate_whose_target_was_not_piped_is_unjudgeable() {
    let dir = duplicate_repo("unpiped");
    let rows = [row("CLOUD-817", Some(OP), None, Some("CLOUD-777"))];
    let (code, text) = duplicate(&dir, &rows);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-777, which was not piped"), "{text}");
}

#[test]
fn a_duplicate_close_with_no_stamp_is_unjudgeable() {
    let dir = duplicate_repo("unstamped");
    let rows = [
        row("CLOUD-777", None, Some(OP), None),
        row("CLOUD-817", None, None, Some("CLOUD-777")),
    ];
    let (code, text) = duplicate(&dir, &rows);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("carries no canceledAt"), "{text}");
}

/// A real same-operation pair beside a target nobody piped: the set was not
/// judged, so the answer is could-not-look, never the refusal lane.
#[test]
fn could_not_look_outranks_a_refusal() {
    let dir = duplicate_repo("outranks");
    let mut rows = pair();
    rows.push(row("CLOUD-818", Some(OP), None, Some("CLOUD-999")));
    assert_eq!(duplicate(&dir, &rows).0, Some(1));
}

#[test]
fn a_duplicate_close_record_without_its_census_is_torn() {
    let dir = duplicate_repo("torn");
    record_raw(
        &dir,
        "duplicate-close",
        "dup\tCLOUD-817\t2026-08-21T02:37:52\tCLOUD-777\t2026-08-21T02:37:51\n",
    );
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
}

#[test]
fn unreadable_duplicate_stdin_is_could_not_look() {
    let dir = duplicate_repo("stdin");
    assert_eq!(gate(&dir, "duplicate-close", &[], "").0, Some(1));
    assert_eq!(gate(&dir, "duplicate-close", &[], "not json").0, Some(1));
}

#[test]
fn the_report_carries_no_body_and_is_byte_stable() {
    let dir = duplicate_repo("pointer");
    let with_bodies = [
        format!(
            r#"{{"id":"CLOUD-777","canceledAt":null,"completedAt":"{OP}","description":"the acceptance is satisfied vacuously and nobody noticed","relations":{{"blockedBy":[],"duplicateOf":null}}}}"#
        ),
        format!(
            r#"{{"id":"CLOUD-817","canceledAt":"{OP}","completedAt":null,"description":"CLOUD-777 passes vacuously, which is the whole finding","relations":{{"blockedBy":[],"duplicateOf":{{"id":"CLOUD-777"}}}}}}"#
        ),
    ];
    let first = duplicate(&dir, &with_bodies);
    assert_eq!(first.0, Some(2), "{}", first.1);
    assert!(!first.1.contains("vacuously"), "{}", first.1);
    assert_eq!(first, duplicate(&dir, &with_bodies));
}

// ---------------------------------------------------------------------------
// deferral — a PR body that defers a decision without naming its owner.
// ---------------------------------------------------------------------------

/// A repository on a keyless branch, carrying the committed pattern table.
fn deferral_repo(name: &str) -> PathBuf {
    let dir = fixture(&format!("deferral-{name}"), true);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    dir
}

fn deferral(name: &str, body: &str) -> (Option<i32>, String) {
    gate(&deferral_repo(name), "deferral", &DEFERRAL, body)
}

#[test]
fn a_deferral_with_no_owner_in_its_paragraph_is_refused() {
    let (code, text) = deferral("ownerless", "Intro.\n\nThis was a judgement call.\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("paragraph:2"),
        "the pointer is the paragraph: {text}"
    );
}

#[test]
fn a_deferral_naming_its_owner_passes_and_scope_is_the_paragraph() {
    let (owned, text) = deferral("owned", "This was a judgement call, owned by CLOUD-9.\n");
    assert_eq!(owned, Some(0), "{text}");
    let (elsewhere, text) = deferral(
        "elsewhere",
        "CLOUD-9 is named up here.\n\nThis was a judgement call.\n",
    );
    assert_eq!(
        elsewhere,
        Some(2),
        "a key in another paragraph does not own it: {text}"
    );
    let (whole, text) = deferral(
        "whole",
        "This was a judgement call\nthat CLOUD-9 now owns, on the next line.\n",
    );
    assert_eq!(whole, Some(0), "a paragraph is read whole: {text}");
}

#[test]
fn a_code_span_names_the_phrase_without_using_it_and_other_shapes_pass() {
    for (name, body) in [
        ("span", "The table row `judgement call` is a literal.\n"),
        ("none", "Nothing deferred here.\n"),
        ("empty", ""),
        ("dropped", "This was deliberately chosen.\n"),
    ] {
        let (code, text) = deferral(name, body);
        assert_eq!(code, Some(0), "{name}: {text}");
    }
}

#[test]
fn both_spellings_and_both_measured_shapes_fire() {
    for (name, body) in [
        ("american", "This was a judgment call.\n"),
        ("unverified", "The macOS half is not verified here.\n"),
    ] {
        let (code, text) = deferral(name, body);
        assert_eq!(code, Some(2), "{name}: {text}");
    }
    let (owned, text) = deferral(
        "unverified-owned",
        "Not verified here; CLOUD-282 owns it.\n",
    );
    assert_eq!(owned, Some(0), "{text}");
}

#[test]
fn a_deferral_owned_only_by_the_claimed_issue_is_refused() {
    // CLOUD-338: the natural key to write is the one the PR already claims, which
    // made the exemption self-satisfying. A closing keyword in the body claims.
    let (claimed_only, text) = deferral(
        "claimed-only",
        "Closes CLOUD-286\n\nNot verified here, see CLOUD-286.\n",
    );
    assert_eq!(claimed_only, Some(2), "{text}");
    let (real_owner, text) = deferral(
        "real-owner",
        "Closes CLOUD-286\n\nNot verified here; CLOUD-286 hands it to CLOUD-282.\n",
    );
    assert_eq!(real_owner, Some(0), "{text}");
    let (unclaimed, text) = deferral("unclaimed", "Not verified here; CLOUD-282 owns it.\n");
    assert_eq!(unclaimed, Some(0), "{text}");
}

#[test]
fn a_deferral_with_no_claim_is_owned_by_any_key_it_names() {
    // The fail-open half that survives: nothing claimed subtracts nothing.
    let (code, text) = deferral("no-claim", "This was a judgement call for CLOUD-5.\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_deferral_report_is_a_pointer_never_the_paragraph() {
    let (code, text) = deferral(
        "pointer",
        "A secret customer detail was a judgement call.\n",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(!text.contains("customer detail"), "{text}");
}

#[test]
fn a_deferral_record_without_its_census_is_torn() {
    let dir = deferral_repo("torn");
    record_raw(&dir, "deferral", "claimed\t-\ndeferral\t1\tCLOUD-9\n");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
}

// ---------------------------------------------------------------------------
// closing-key — a PR body that names its issue but never closes it.
// ---------------------------------------------------------------------------

/// `origin/main` at the base and a keyless branch `work` checked out, whose
/// commits serve `served` — each entry one commit's `Refs:` trailer.
fn closing_repo(name: &str, served: &[&str]) -> PathBuf {
    let dir = fixture(&format!("closing-key-{name}"), true);
    git_in(&dir, &["checkout", "-q", "-b", "main"]);
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "chore: init"]);
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "main"]);
    git_in(&dir, &["checkout", "-q", "-b", "work"]);
    for trailer in served {
        git_in(
            &dir,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("feat: part\n\n{trailer}"),
            ],
        );
    }
    dir
}

fn closing(name: &str, served: &[&str], body: &str) -> (Option<i32>, String) {
    gate(&closing_repo(name, served), "closing-key", &CLOSING, body)
}

#[test]
fn a_body_naming_its_issue_but_never_closing_it_is_refused() {
    // The measured pair: `Refs:` merged and never moved; `Closes` moved.
    let (code, text) = closing("named", &[], "Refs: CLOUD-192\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-192"), "{text}");
    let (closed, text) = closing("closed", &[], "Closes CLOUD-192\n");
    assert_eq!(closed, Some(0), "{text}");
}

#[test]
fn every_closing_verb_inflection_case_and_punctuation_closes() {
    for (n, body) in [
        "close CLOUD-1",
        "closes CLOUD-1",
        "closed CLOUD-1",
        "fix CLOUD-1",
        "fixes CLOUD-1",
        "fixed CLOUD-1",
        "resolve CLOUD-1",
        "resolves CLOUD-1",
        "resolved CLOUD-1",
        "CLOSES CLOUD-1",
        "Closes: CLOUD-1",
    ]
    .iter()
    .enumerate()
    {
        let (code, text) = closing(&format!("verb-{n}"), &[], &format!("{body}\n"));
        assert_eq!(code, Some(0), "`{body}` closes: {text}");
    }
}

#[test]
fn a_verb_must_be_adjacent_and_a_hyphen_prefix_or_embedded_key_is_not_a_close() {
    for (name, body) in [
        ("apart", "This fixes things.\n\nSee CLOUD-1.\n"),
        ("hyphen", "Some prose then pre-closes CLOUD-1 here.\n"),
        ("embedded", "Closes XCLOUD-1 but names CLOUD-1.\n"),
    ] {
        let (code, text) = closing(name, &[], body);
        assert_eq!(code, Some(2), "{name} closes nothing: {text}");
    }
}

#[test]
fn the_marker_opts_out_only_when_used_not_when_mentioned() {
    let (bare, text) = closing("bare", &[], "Refs: CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(bare, Some(0), "a bare marker opts out: {text}");
    let (indented, text) = closing("indented", &[], "Refs: CLOUD-1\n   DO-NOT-CLOSE\n");
    assert_eq!(indented, Some(0), "indentation is not a mention: {text}");
    let (keyed, text) = closing("keyed", &[], "Refs: CLOUD-388\nDO-NOT-CLOSE CLOUD-388\n");
    assert_eq!(keyed, Some(0), "the marker may name its issue: {text}");
    let (mentioned, text) = closing(
        "mentioned",
        &[],
        "Refs: CLOUD-1. This PR explains the DO-NOT-CLOSE marker.\n",
    );
    assert_eq!(mentioned, Some(2), "a mention is not a use: {text}");
    let (wins, text) = closing(
        "close-wins",
        &[],
        "Closes CLOUD-1. This PR explains the DO-NOT-CLOSE marker.\n",
    );
    assert_eq!(wins, Some(0), "a close is read first: {text}");
    let (both, text) = closing("both", &[], "Closes CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(both, Some(0), "closing and opting out is closing: {text}");
}

#[test]
fn no_key_passes_one_close_is_enough_and_every_named_key_is_reported() {
    let (none, text) = closing("no-key", &[], "A body with no key.\n");
    assert_eq!(none, Some(0), "not this gate's case: {text}");
    let (one, text) = closing("one-closed", &[], "Closes CLOUD-2, related to CLOUD-3.\n");
    assert_eq!(one, Some(0), "{text}");
    let (several, text) = closing(
        "several",
        &[],
        "A secret body line. Refs: CLOUD-10 and CLOUD-2.\n",
    );
    assert_eq!(several, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("CLOUD-10"),
        "{text}"
    );
    assert!(!text.contains("secret body line"), "pointer only: {text}");
}

#[test]
fn empty_or_whitespace_body_is_could_not_look() {
    for (name, body) in [("empty", ""), ("blank", "  \n\t\n")] {
        let (code, text) = closing(name, &[], body);
        assert_eq!(code, Some(1), "{name}: {text}");
    }
}

#[test]
fn a_body_closing_a_strict_subset_of_the_served_keys_is_refused() {
    // CLOUD-674: a bundle closing one of the rows its branch served.
    let (code, text) = closing(
        "strand",
        &["Refs: CLOUD-1", "Refs: CLOUD-2"],
        "Closes CLOUD-1\n",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-2"),
        "the stranded key is named: {text}"
    );
    assert!(
        !text.contains("Closes CLOUD-1"),
        "never a body line: {text}"
    );
}

#[test]
fn a_body_closing_every_served_key_passes() {
    let (code, text) = closing(
        "all-served",
        &["Refs: CLOUD-1", "Refs: CLOUD-2"],
        "Closes CLOUD-1\nCloses CLOUD-2\n",
    );
    assert_eq!(code, Some(0), "{text}");
    let (single, text) = closing("single", &["Refs: CLOUD-1"], "Closes CLOUD-1\n");
    assert_eq!(single, Some(0), "a single-ticket PR is unaffected: {text}");
}

#[test]
fn only_the_first_key_of_a_trailer_is_served_and_the_served_set_ignores_the_body() {
    let (code, text) = closing("first-key", &["Refs: CLOUD-1, CLOUD-2"], "Closes CLOUD-1\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_branch_with_no_refs_trailer_is_not_judged_by_the_subtraction() {
    let (code, text) = closing("no-refs", &[], "Closes CLOUD-1, see CLOUD-2.\n");
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_keyed_marker_does_not_excuse_a_key_it_never_named() {
    let served = &["Refs: CLOUD-1", "Refs: CLOUD-2", "Refs: CLOUD-3"];
    let (exempt, text) = closing(
        "keyed-exempt",
        served,
        "Closes CLOUD-1\nCloses CLOUD-3\nDO-NOT-CLOSE CLOUD-2\n",
    );
    assert_eq!(exempt, Some(0), "the named key is exempt: {text}");
    let (other, text) = closing(
        "keyed-other",
        served,
        "Closes CLOUD-1\nDO-NOT-CLOSE CLOUD-2\n",
    );
    assert_eq!(other, Some(2), "{text}");
    assert!(
        text.contains("CLOUD-3"),
        "the un-named key still strands: {text}"
    );
    let (global, text) = closing("global", served, "Closes CLOUD-1\nDO-NOT-CLOSE\n");
    assert_eq!(
        global,
        Some(0),
        "a bare marker declines the whole body: {text}"
    );
}

/// EVERY KEY OF A SPACE-SEPARATED MARKER IS HELD, not every other one (#1036).
#[test]
fn every_key_of_a_space_separated_marker_is_held() {
    let served = &[
        "Refs: CLOUD-1",
        "Refs: CLOUD-2",
        "Refs: CLOUD-3",
        "Refs: CLOUD-4",
    ];
    let (code, text) = closing(
        "marker-list",
        served,
        "Closes CLOUD-1\nDO-NOT-CLOSE CLOUD-2 CLOUD-3 CLOUD-4\n",
    );
    assert_eq!(code, Some(0), "the middle key is held too: {text}");
}

#[test]
fn every_key_of_a_list_on_one_line_is_named() {
    let (code, text) = closing("named-list", &[], "Refs CLOUD-1 CLOUD-2 CLOUD-3\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-2"), "the middle key is named: {text}");
}

#[test]
fn a_closing_key_record_missing_a_reading_is_torn() {
    let dir = closing_repo("torn", &[]);
    record_raw(&dir, "closing-key", "named\tCLOUD-1\nclosing\tCLOUD-1\n");
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(2), "{text}");
}

// ---------------------------------------------------------------------------
// The row, the store and the wiring.
// ---------------------------------------------------------------------------

/// ONE ROW JUDGES ALL FIVE, which is safe only because every reading clears the
/// other four first: a deferral left refusing on this branch must not answer a
/// later board question.
#[test]
fn a_tracker_question_clears_the_records_of_the_other_four() {
    let dir = deferral_repo("clears");
    let (refused, text) = gate(&dir, "deferral", &DEFERRAL, "This was a judgement call.\n");
    assert_eq!(refused, Some(2), "the premise: a refusing record: {text}");
    let (code, text) = gate(
        &dir,
        "done-pr",
        &[],
        &set(&[issue("CLOUD-1", &[url(1)], &[merged(1)])]),
    );
    assert_eq!(code, Some(0), "the deferral record is gone: {text}");
}

/// And a reading that refuses leaves nothing behind, its own family included —
/// a previous run's record must not answer as the question just asked.
#[test]
fn a_refusing_reading_leaves_no_record_answering() {
    let dir = duplicate_repo("stale");
    assert_eq!(duplicate(&dir, &pair()).0, Some(2), "the premise");
    assert_eq!(gate(&dir, "duplicate-close", &[], "not json").0, Some(1));
    let (code, text) = decide(&dir);
    assert_eq!(code, Some(0), "no stale record answers: {text}");
}

/// THE PRESET DECIDES FOR A CONSUMER THAT IS NOT THIS REPOSITORY: another
/// tracker's keys, another forge's host, and no `[[pattern]]` row at all.
#[test]
fn the_preset_decides_for_a_consumer_that_is_not_this_repository() {
    let dir = duplicate_repo("consumer");
    let open = r#"[{"id":"ACME-7","attachments":[{"url":"https://code.acme.example/team/app/pull/12"}],"pulls":[{"number":12,"state":"open","draft":false}]}]"#;
    let (code, text) = gate(&dir, "done-pr", &[], open);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("ACME-7#12"), "{text}");
    let same = [
        row("ACME-1", None, Some(OP), None),
        row("ACME-2", Some(OP), None, Some("ACME-1")),
    ];
    let (code, text) = duplicate(&dir, &same);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("ACME-2>ACME-1"), "{text}");
    let merged_only = r#"[{"id":"ACME-7","attachments":[{"url":"https://code.acme.example/team/app/pull/12"}],"pulls":[{"number":12,"state":"closed","draft":false}]}]"#;
    assert_eq!(gate(&dir, "done-pr", &[], merged_only).0, Some(0));
}

/// The committed gates record their family, then check the one row — and the
/// four producer tasks the bodies lived in are gone rather than hollowed.
#[test]
fn the_committed_gates_record_then_check_the_one_row() {
    for (task, family) in [
        ("done-check", "done"),
        ("done-pr-check", "done-pr"),
        ("duplicate-close-check", "duplicate-close"),
        ("deferral-check", "deferral"),
        ("closing-key-check", "closing-key"),
    ] {
        let block = common::task_block(task).unwrap_or_else(|| panic!("[tasks.{task}]"));
        let argv = common::task_value(&block, "run");
        assert!(
            argv.contains(&format!("record derive {family}")),
            "{task}: {argv}"
        );
        // THE BINARY UNDER TEST, never whatever workspace cargo finds: every
        // entry opens with the manifest's one `vars.batten`, which reads
        // `BATTEN_BIN` as the retired bodies did.
        assert!(
            !argv.contains("cargo run"),
            "{task} runs the batten BATTEN_BIN names: {argv}"
        );
        assert_eq!(
            argv.matches("{{vars.batten}} ").count(),
            2,
            "{task}: both entries open with vars.batten: {argv}"
        );
        // Composed from another tree, it judges THAT tree.
        assert_eq!(
            common::task_value(&block, "dir"),
            "{{cwd}}",
            "{task} runs in its caller's directory"
        );
        assert!(
            argv.contains(&format!("check --rule '{ROW}'")),
            "{task}: {argv}"
        );
    }
    for retired in [
        "done-record",
        "duplicate-close-record",
        "deferral-record",
        "closing-key-record",
    ] {
        assert!(
            common::task_block(retired).is_none(),
            "[tasks.{retired}] is retired"
        );
    }
}

// ---------------------------------------------------------------------------
// The committed tasks, end to end.
// ---------------------------------------------------------------------------

/// `mise run -q <name>` over the committed manifest, in `dir`, with `stdin`
/// piped — so what answers is the task's OWN wiring rather than [`gate`]'s copy
/// of it: the `'released=v[0-9]*'` quoting, the check entry running only when the
/// reading succeeded, the exit code the task runner reports, and `vars.batten`
/// resolving to the binary under test through `BATTEN_BIN`. `land` reaches the
/// two body gates the same way (`LAND_BODY_GATES`).
fn task(dir: &Path, name: &str, env: &[(&str, &str)], stdin: &str) -> (Option<i32>, String) {
    let output = common::mise_task(dir, name, env, stdin);
    (output.status.code(), said(&output))
}

#[test]
fn the_committed_done_check_refuses_until_a_release_contains_the_issue() {
    let dir = done_repo("task");
    land(&dir, "feat: work\n\nRefs: CLOUD-499");
    let (code, text) = task(&dir, "done-check", &[], &done_board("CLOUD-499"));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-499"), "{text}");
    release(&dir, "v0.0.2");
    let (code, text) = task(&dir, "done-check", &[], &done_board("CLOUD-499"));
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_committed_done_pr_check_refuses_a_draft_and_licenses_a_merge() {
    let dir = duplicate_repo("task-done-pr");
    let draft = set(&[issue(
        "CLOUD-420",
        &[url(7)],
        &[pull(7, "open", false, true)],
    )]);
    let (code, text) = task(&dir, "done-pr-check", &[], &draft);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-420"), "{text}");
    let landed = set(&[issue("CLOUD-420", &[url(7)], &[merged(7)])]);
    let (code, text) = task(&dir, "done-pr-check", &[], &landed);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_committed_deferral_check_refuses_an_ownerless_deferral_only() {
    let dir = deferral_repo("task");
    let (code, text) = task(
        &dir,
        "deferral-check",
        &[],
        "Intro.\n\nThis was a judgement call.\n",
    );
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("paragraph:2"), "{text}");
    let (code, text) = task(
        &dir,
        "deferral-check",
        &[],
        "This was a judgement call, owned by CLOUD-9.\n",
    );
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_committed_closing_key_check_refuses_a_named_key_and_cannot_look_at_nothing() {
    let dir = closing_repo("task", &[]);
    let (code, text) = task(&dir, "closing-key-check", &[], "Refs: CLOUD-192\n");
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("CLOUD-192"), "{text}");
    let (code, text) = task(&dir, "closing-key-check", &[], "Closes CLOUD-192\n");
    assert_eq!(code, Some(0), "{text}");
    // The reading refuses, so the check entry never runs: could-not-look.
    let (code, text) = task(&dir, "closing-key-check", &[], "");
    assert_eq!(code, Some(1), "{text}");
}

/// `DUPLICATE_CLOSE_WINDOW` still widens the window, as the retired body let it:
/// two closes a second apart pass at the default (the second) and are refused at
/// 16 characters (the minute), and a window that is not a whole number is
/// could-not-look rather than the default.
#[test]
fn the_committed_duplicate_close_check_honours_the_window_override() {
    let dir = duplicate_repo("task-window");
    let rows = [
        row("CLOUD-777", None, Some("2026-08-21T02:37:52.000Z"), None),
        row("CLOUD-817", Some(OP), None, Some("CLOUD-777")),
    ]
    .join("\n");
    let (code, text) = task(&dir, "duplicate-close-check", &[], &rows);
    assert_eq!(code, Some(0), "the default is the second: {text}");
    let (code, text) = task(
        &dir,
        "duplicate-close-check",
        &[("DUPLICATE_CLOSE_WINDOW", "16")],
        &rows,
    );
    assert_eq!(code, Some(2), "the minute: {text}");
    assert!(text.contains("CLOUD-817>CLOUD-777"), "{text}");
    let (code, text) = task(
        &dir,
        "duplicate-close-check",
        &[("DUPLICATE_CLOSE_WINDOW", "sixty")],
        &rows,
    );
    assert_eq!(code, Some(1), "not a whole number: {text}");
}
