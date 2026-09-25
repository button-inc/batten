//! `issue grade other` over the compiled binary and the REAL producer
//! (CLOUD-192, CLOUD-1717).
//!
//! # Both halves run, because both halves decide something a case can lose
//!
//! `policy/done.rego` decides, and its `test_` rules fabricate their input. The
//! reading — which issue a release, `main` or nothing carries — is
//! `[tasks.done-record]`'s, and that is where the retired suite's sharpest cases
//! lived: the bounded id match, the two git preconditions, the numeric order. So
//! this tier runs the producer's own body, read out of `mise.toml` rather than
//! copied, against a fixture repository, and then asks the engine over what it
//! recorded. A copy of the body here would pass while the manifest drifted.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/done-check.sh policy/done.rego kind:mechanism crates/batten/tests/it/done.rs
// carried: tests/done-check.bats policy/done.rego kind:mechanism crates/batten/tests/it/done.rs
// carried: "a Done issue whose commits are in a release tag is left alone" policy/done.rego kind:mechanism
// carried: "a Done issue landed past the last tag is reported — this is the defect" policy/done.rego kind:mechanism
// carried: "landing then releasing clears the very same issue" policy/done.rego kind:mechanism
// carried: "a Done issue no commit names is noted, not failed" policy/done.rego kind:mechanism
// carried: "one released ref is enough, even with later unreleased ones" policy/done.rego kind:mechanism
// carried: "a prefix does not match a longer id" policy/done.rego kind:mechanism
// carried: "issues in other columns are none of this gate's business" policy/done.rego kind:mechanism
// carried: "the pipeline does not eat the verdict" policy/done.rego kind:mechanism
// carried: "several issues are each judged, in stable numeric order" policy/done.rego kind:mechanism
// carried: "output is a pointer — identifiers and target state, never issue bodies" policy/done.rego kind:mechanism
// carried: "a concatenated payload stream is accepted, like graph-check's" policy/done.rego kind:mechanism
// carried: "an unresolvable origin/main exits 2 — a checkout problem, not a clean board" policy/done.rego kind:mechanism
// carried: "a clone with no tags exits 2 — the opposite false verdict" policy/done.rego kind:mechanism
// carried: "empty stdin exits 2, distinct from a clean board" policy/done.rego kind:mechanism
// carried: "unparseable stdin exits 2" policy/done.rego kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{at_root, git_in, init_repo, run, scratch, write};

/// A repository registering the real module, with `main` as the trunk, HEAD on a
/// feature branch, and one tag — every case needs a tag or it meets the tagless
/// precondition instead of the predicate under test.
fn repo(name: &str) -> PathBuf {
    let dir = scratch(&format!("done-{name}"));
    let module = std::fs::read_to_string(at_root("policy/done.rego"))
        .expect("the module this tier exists for");
    write(&dir, "policy/done.rego", &module);
    write(
        &dir,
        "batten.toml",
        r#"version = 1
scope = ["**"]

[[pattern]]
id = "whole-number"
regex = '^[0-9]+$'

[[verdict]]
id = "issue ship ahead"
gloss = "an issue reads Done while no release tag contains its commits"
class = "Landed-but-unreleased is In Review."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run done-record"

[[verdict]]
id = "issue read partial"
gloss = "the done record's census is missing or wrong"
class = "A torn record judges part of a board as all of it."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run done-record"

[[rule]]
id = "issue grade other"
kind = "policy"
scope = "tree"
module = "policy/done.rego"
severity = "deny"

[[record]]
record = "done"
writer = "mise run done-record"
"#,
    );
    init_repo(&dir);
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

/// A release tag at the tip of `main` — everything landed so far ships.
fn release(dir: &Path, tag: &str) {
    git_in(dir, &["tag", tag, "main"]);
}

/// `[tasks.done-record]`'s body, as the manifest declares it.
fn producer_body() -> String {
    let manifest = std::fs::read_to_string(at_root("mise.toml")).expect("the manifest");
    let parsed: toml::Value = toml::from_str(&manifest).expect("mise.toml parses as TOML");
    parsed["tasks"]["done-record"]["run"]
        .as_str()
        .expect("[tasks.done-record] declares a run body")
        .to_owned()
}

/// Run the producer over `board`, in `dir`, the way `mise run done-record`
/// would — with the engine the suite built, and the environment `batten()`
/// scrubs, so a developer's shell cannot move a reading.
fn produce(dir: &Path, board: &str) -> Output {
    use std::io::Write as _;

    let template = common::batten();
    let mut command = Command::new("bash");
    for (name, value) in template.get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    let mut child = command
        .args(["-c", &producer_body()])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the producer");
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(board.as_bytes());
    child.wait_with_output().expect("run the producer")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Produce, assert the producer succeeded, then decide.
fn decide(dir: &Path, board: &str) -> Output {
    let produced = produce(dir, board);
    assert!(
        produced.status.success(),
        "the producer records: {}",
        said(&produced)
    );
    run(dir, &["check", "--rule", "issue grade other"])
}

fn done(id: &str) -> String {
    format!("[{{\"id\":\"{id}\",\"status\":\"Done\"}}]")
}

#[test]
fn a_done_issue_landed_past_the_last_tag_is_refused() {
    // THE DEFECT: CLOUD-499 read Done at merge time with `main` past the tag.
    let dir = repo("landed");
    land(&dir, "feat: work\n\nRefs: CLOUD-499");
    let decided = decide(&dir, &done("CLOUD-499"));
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(said(&decided).contains("CLOUD-499"), "{}", said(&decided));
}

#[test]
fn landing_then_releasing_clears_the_same_issue() {
    let dir = repo("released");
    land(&dir, "feat: work\n\nRefs: CLOUD-499");
    assert_eq!(decide(&dir, &done("CLOUD-499")).status.code(), Some(2));
    release(&dir, "v0.0.2");
    let cleared = decide(&dir, &done("CLOUD-499"));
    assert_eq!(cleared.status.code(), Some(0), "{}", said(&cleared));
}

#[test]
fn one_released_ref_is_enough_even_with_a_later_unreleased_one() {
    // The documented bound: judged by the most-released ref (CLOUD-468 owns the
    // half-landed question).
    let dir = repo("most-released");
    land(&dir, "feat: first\n\nRefs: CLOUD-186");
    release(&dir, "v0.0.2");
    land(&dir, "feat: second\n\nRefs: CLOUD-186");
    let decided = decide(&dir, &done("CLOUD-186"));
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn a_done_issue_no_commit_names_is_not_judged() {
    // Board-only work, a duplicate, anything before the ref convention: git has
    // nothing to say, so neither does the gate.
    let dir = repo("unlanded");
    let decided = decide(&dir, &done("CLOUD-99999"));
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn a_prefix_does_not_match_a_longer_id() {
    // CLOUD-17 must not be refuted by a commit naming CLOUD-179.
    let dir = repo("prefix");
    land(&dir, "feat: work\n\nRefs: CLOUD-179");
    let decided = decide(&dir, &done("CLOUD-17"));
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn an_issue_in_another_column_is_not_judged() {
    let dir = repo("columns");
    land(&dir, "feat: work\n\nRefs: CLOUD-5");
    let decided = decide(
        &dir,
        r#"[{"id":"CLOUD-5","status":"In Review"},{"id":"CLOUD-5","status":"Todo"}]"#,
    );
    assert_eq!(decided.status.code(), Some(0), "{}", said(&decided));
}

#[test]
fn several_issues_are_each_judged_and_the_output_is_a_pointer() {
    // Three landed commits, so a log read through a pipe that SIGPIPEd would
    // have found nothing; and a payload carrying prose that must not surface.
    let dir = repo("several");
    land(&dir, "feat: a\n\nRefs: CLOUD-2");
    land(&dir, "feat: b\n\nRefs: CLOUD-10");
    land(&dir, "feat: c\n\nRefs: CLOUD-3");
    let decided = decide(
        &dir,
        r#"{"id":"CLOUD-10","status":"Done","description":"customer detail"}
{"id":"CLOUD-2","status":"Done"}"#,
    );
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    let text = said(&decided);
    assert!(
        text.contains("CLOUD-2") && text.contains("CLOUD-10"),
        "{text}"
    );
    assert!(!text.contains("customer detail"), "pointer only: {text}");
}

#[test]
fn a_record_without_its_census_is_torn_rather_than_clean() {
    // THE WRITE-COMPLETENESS HALF. A record with its `issue` lines but no
    // closing census is refused, not judged over part of a board.
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "done"],
        "issue\tCLOUD-1\tDone\tshipped\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = run(&dir, &["check", "--rule", "issue grade other"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
}

#[test]
fn the_producer_refuses_every_input_it_cannot_read_and_records_nothing() {
    // FOUR COULD-NOT-LOOKS, each exit 2 and each writing no record — so the
    // engine afterwards has nothing to judge and says nothing, rather than a
    // clean or a red verdict over a fetch problem.
    let empty = repo("empty-stdin");
    assert_eq!(produce(&empty, "").status.code(), Some(2));
    let garbled = repo("garbled-stdin");
    assert_eq!(produce(&garbled, "not json").status.code(), Some(2));

    let unresolved = repo("no-origin");
    git_in(
        &unresolved,
        &["update-ref", "-d", "refs/remotes/origin/main"],
    );
    assert_eq!(
        produce(&unresolved, &done("CLOUD-5")).status.code(),
        Some(2),
        "no origin/main is a checkout problem, not a clean board"
    );

    let tagless = repo("no-tags");
    land(&tagless, "feat: work\n\nRefs: CLOUD-5");
    git_in(&tagless, &["tag", "-d", "v0.0.1"]);
    let refused = produce(&tagless, &done("CLOUD-5"));
    assert_eq!(
        refused.status.code(),
        Some(2),
        "no tags is a fetch problem, not a board of unreleased work"
    );
    let after = run(&tagless, &["check", "--rule", "issue grade other"]);
    assert_eq!(
        after.status.code(),
        Some(0),
        "and nothing was recorded for the engine to judge: {}",
        said(&after)
    );
}
