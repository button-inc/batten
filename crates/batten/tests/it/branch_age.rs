//! `branch watch loose` over the compiled binary (CLOUD-349, CLOUD-1717; the
//! producer retired into forge queries under CLOUD-843).
//!
//! # Why this tier exists and the module's own `test_` rules do not suffice
//!
//! Every load-time case in `policy/branch-age.rego` fabricates its input with
//! `with input as`, which can assert over a fact the engine is unable to produce
//! — the state this module spent a whole session in (CLOUD-1810). The cases here
//! run the REAL producer, the three declared `[[forge.query]]` reads against the
//! `BATTEN_REST_FIXTURE` forge, and then the real module over the engine's own
//! projection of what it wrote.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
//! The program's successor was `policy/branch-age.rego` for every DECISION and
//! `[tasks.branch-age-record]`'s shell body for the reads and the civil-calendar
//! subtraction. The body is gone: the reads are `[[forge.query]]` rows, the age
//! is a `span` measured in UTC days against the PRODUCER's clock — the engine
//! still calls no clock on any evaluation path — and the trunk exclusion, which
//! the body applied before recording, is the module's again.
//!
// carried: mise-tasks/branch-age-check.sh policy/branch-age.rego kind:mechanism crates/batten/tests/it/branch_age.rs
// carried: tests/branch-age-check.bats policy/branch-age.rego kind:mechanism crates/batten/tests/it/branch_age.rs
// carried: "[tasks.branch-age-record]" crates/batten/src/forge_query.rs kind:mechanism crates/batten/tests/it/branch_age.rs
// carried: "a remote carrying only fresh branches passes" policy/branch-age.rego kind:mechanism
// carried: "a branch past the threshold is refused, and named with its age" policy/branch-age.rego kind:mechanism
// The title is qualified because `perf-compare.bats` carried one spelled
// identically, and two arms claiming one title is what `bats count dropped`
// reported at `perf_compare.rs:56`. The `suite::case` form is the corpus's
// own, used in `connector_verbs.rs` for the same collision.
// carried: "branch-age-check.bats::the threshold is a boundary, not a suggestion" policy/branch-age.rego kind:mechanism
// carried: "a name heading more than one merged PR is refused, and counted" policy/branch-age.rego kind:mechanism
// carried: "a reused name whose branch is already gone is not counted" policy/branch-age.rego kind:mechanism
// carried: "a clean remote reaches green, which is the state the gate must be able to reach" policy/branch-age.rego kind:mechanism
// carried: "a remote reporting no branches at all is exit 2, not a pass" policy/branch-age.rego kind:mechanism
// carried: "the trunk is never counted, however old or however many PRs it heads" policy/branch-age.rego kind:mechanism
// changed: "an unreadable refs reading is exit 2, not a pass" crates/batten/src/forge_query.rs a forge that will not answer is `record query`'s could-not-look: exit 3, and the family is REMOVED, so the module reads an absent record and says nothing — a module refusing there would refuse every checkout with no credential. `a_forge_that_will_not_answer_leaves_nothing_to_decide_over` holds it
// changed: "an unreadable PR reading is exit 2, not a pass" crates/batten/src/forge_query.rs the same split over the third read
// changed: "a custom threshold is honoured in both the verdict and the message" policy/branch-age.rego there is no custom threshold to honour: the figure is the practice's own "couple of days" and lives in the module, where moving it costs a diff a reviewer reads
// changed: "an unparseable tip date is reported rather than silently skipped" crates/batten/src/forge_query.rs the tip's date is read by the producer, and one that is not an RFC 3339 instant records a `null` age, which the module cannot compare and does not report — `the_tip_age_is_the_producers_count_of_days` pins the producer's half
// withdrawn: "a nonsense today is exit 2, not an arithmetic answer" there is no `today` for a caller to make nonsense of: the producer reads its own clock, and the module compares a number against a threshold

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{at_root, git_in, init_repo, scratch, stderr, stdout, write};

/// The repository the fixture forge answers for.
const REPO: &str = "acme/widgets";

/// A commit date no clock reaches, so its age is never over the threshold.
const FRESH: &str = "2999-01-01T00:00:00Z";

/// A commit date every clock this suite runs under is years past.
const ANCIENT: &str = "2020-01-01T00:00:00Z";

const CONFIG: &str = r#"version = 1
scope = ["**"]

[[verdict]]
id = "branch watch stale"
gloss = "a remote branch has outlived the story it was cut for"
class = "A branch is either finished, in which case delete it, or it is not short-lived."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[verdict]]
id = "branch name duplicate"
gloss = "one branch name heads more than one merged pull request and is still on the remote"
class = "A short-lived branch sleepwalking into a long-lived one."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[verdict]]
id = "branch list empty"
gloss = "the producer looked and the remote reported no branches at all"
class = "A remote with a trunk cannot report no branches; the listing failed while answering."

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run branch-age-record"

[[rule]]
id = "branch watch loose"
kind = "policy"
scope = "tree"
module = "policy/branch-age.rego"
severity = "deny"

[[record]]
record = "branch-heads"
writer = "mise run branch-age-record"

[[record]]
record = "branch-tips"
writer = "mise run branch-age-record"

[[record]]
record = "branch-merged"
writer = "mise run branch-age-record"

[[forge.query]]
id = "branch-heads"
endpoint = "repos/{owner}/{repo}/branches"
per_page = 100
max_pages = 1
select = ["name", "commit.sha"]

[[forge.query]]
id = "branch-tips"
endpoint = "repos/{owner}/{repo}/commits"
params = { sha = "{tip}" }
per_page = 1
max_pages = 1
select = ["commit.committer.date"]
each = { query = "branch-heads", field = "commit.sha", input = "tip" }

[[forge.query.span]]
name = "age"
from = "commit.committer.date"
unit = "days"

[[forge.query]]
id = "branch-merged"
endpoint = "repos/{owner}/{repo}/pulls"
params = { state = "closed", sort = "created", direction = "desc" }
per_page = 100
max_pages = 10
select = ["head.ref", "merged_at"]
"#;

/// A committed consumer registering the real module, and its fixture forge.
fn consumer(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(&format!("branch-age-{name}"));
    init_repo(&dir);
    write(&dir, "batten.toml", CONFIG);
    write(
        &dir,
        "policy/branch-age.rego",
        &std::fs::read_to_string(at_root("policy/branch-age.rego"))
            .expect("the module this tier exists for"),
    );
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-qm", "register the module"]);
    (dir, scratch(&format!("branch-age-{name}-forge")))
}

fn respond(forge: &Path, n: u32, body: &str) {
    std::fs::write(
        forge.join(format!("resp.{n}")),
        format!("HTTP/2 200\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
}

/// The forge's answers: `heads` as `(name, sha)`, one tip per DISTINCT sha in
/// first-seen order as `(sha, date)`, and the closed pulls as `(head, merged)`,
/// served a hundred to a page — a full last page is followed by an empty one,
/// because a page as long as `per_page` is how the walk knows to ask again.
fn forge_answers(
    forge: &Path,
    heads: &[(&str, &str)],
    tips: &[(&str, &str)],
    pulls: &[(&str, bool)],
) {
    let heads: Vec<String> = heads
        .iter()
        .map(|(name, sha)| {
            format!(r#"{{"name": "{name}", "commit": {{"sha": "{sha}"}}, "protected": false}}"#)
        })
        .collect();
    respond(forge, 1, &format!("[{}]", heads.join(", ")));
    let mut n = 2;
    for (sha, date) in tips {
        respond(
            forge,
            n,
            &format!(
                r#"[{{"sha": "{sha}", "commit": {{"committer": {{"date": "{date}"}}, "message": "a body nobody declared"}}}}]"#
            ),
        );
        n += 1;
    }
    let mut pages: Vec<&[(&str, bool)]> = pulls.chunks(100).collect();
    if pulls.len().is_multiple_of(100) {
        pages.push(&[]);
    }
    for page in pages {
        let rows: Vec<String> = page
            .iter()
            .map(|(head, merged)| {
                let at = if *merged {
                    "\"2026-08-01T00:00:00Z\""
                } else {
                    "null"
                };
                format!(r#"{{"head": {{"ref": "{head}"}}, "merged_at": {at}, "title": "t"}}"#)
            })
            .collect();
        respond(forge, n, &format!("[{}]", rows.join(", ")));
        n += 1;
    }
}

fn against(dir: &Path, forge: &Path, args: &[&str]) -> Output {
    common::batten()
        .args(args)
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", forge)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs")
}

/// `mise run branch-age-record`'s three reads, in its order, each asserted.
fn produce(dir: &Path, forge: &Path) {
    for id in ["branch-heads", "branch-tips", "branch-merged"] {
        let recorded = against(dir, forge, &["record", "query", id]);
        assert_eq!(
            recorded.status.code(),
            Some(0),
            "`record query {id}` records\n{}",
            stderr(&recorded)
        );
    }
}

fn said(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

#[test]
fn a_recorded_branch_past_the_threshold_is_reported_through_the_engines_own_projection() {
    let (dir, forge) = consumer("stale");
    forge_answers(
        &forge,
        &[
            ("main", "t0"),
            ("claude/ancient", "a1"),
            ("claude/fresh", "f1"),
        ],
        &[("t0", FRESH), ("a1", ANCIENT), ("f1", FRESH)],
        &[],
    );
    produce(&dir, &forge);
    let decided = against(&dir, &forge, &["check"]);
    assert_eq!(decided.status.code(), Some(2), "{}", said(&decided));
    assert!(
        said(&decided).contains("claude/ancient"),
        "the finding names the branch to delete\n{}",
        said(&decided)
    );
    assert!(
        !said(&decided).contains("claude/fresh"),
        "and says nothing about one inside the threshold\n{}",
        said(&decided)
    );
}

#[test]
fn a_clean_remote_reaches_green() {
    // THE ANTI-VACUITY MIRROR: the state the gate must be able to reach.
    let (dir, forge) = consumer("clean");
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/fresh", "f1")],
        &[("t0", FRESH), ("f1", FRESH)],
        &[("claude/fresh", true)],
    );
    produce(&dir, &forge);
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn the_trunk_is_never_counted_however_old() {
    let (dir, forge) = consumer("trunk");
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/fresh", "f1")],
        &[("t0", ANCIENT), ("f1", FRESH)],
        &[("main", true), ("main", true)],
    );
    produce(&dir, &forge);
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn the_tip_age_is_the_producers_count_of_days() {
    // THE ONE STEP THE MODULE CANNOT TAKE: the producer's record carries each
    // distinct tip once, tagged with its sha, with an age in whole days — and
    // not the commit message the forge sent beside the date.
    let (dir, forge) = consumer("age");
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/a", "s"), ("claude/b", "s")],
        &[("t0", FRESH), ("s", ANCIENT)],
        &[],
    );
    produce(&dir, &forge);
    let branch = git_in(&dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let tips = std::fs::read_to_string(batten::recorder::record_path(
        &dir.join(".git"),
        "branch-tips",
        &branch,
        None,
    ))
    .expect("the tips family was written where the projection reads it");
    assert_eq!(tips.matches("\"tip\":\"s\"").count(), 1, "{tips}");
    assert!(tips.contains("\"age\":"), "{tips}");
    assert!(!tips.contains("nobody declared"), "rule 4: {tips}");
    assert!(tips.contains("\tmembers=2\t"), "{tips}");
    let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    assert!(
        asked.contains(&format!("repos/{REPO}/commits?page=1&sha=s&per_page=1")),
        "the tip read is bound to the recorded sha: {asked}"
    );
    // Both branches at the ancient tip are stale.
    let decided = against(&dir, &forge, &["check"]);
    assert!(said(&decided).contains("claude/a"), "{}", said(&decided));
    assert!(said(&decided).contains("claude/b"), "{}", said(&decided));
}

#[test]
fn an_absent_record_says_nothing_rather_than_passing() {
    let (dir, forge) = consumer("absent");
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "an absent record is could-not-look\n{}",
        said(&quiet)
    );
}

#[test]
fn a_forge_that_will_not_answer_leaves_nothing_to_decide_over() {
    let (dir, forge) = consumer("refused");
    std::fs::write(
        forge.join("resp.1"),
        "HTTP/2 403\ncontent-type: application/json\n\n{\"message\": \"no\"}\n",
    )
    .expect("write the refusal");
    let refused = against(&dir, &forge, &["record", "query", "branch-heads"]);
    assert_eq!(refused.status.code(), Some(3), "{}", said(&refused));
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn a_present_record_naming_no_branch_is_refused_rather_than_read_as_clean() {
    // PRESENT-AND-EMPTY IS THE THIRD STATE: the listing answered and named no
    // branch at all, which cannot be true of a repository with a trunk.
    let (dir, forge) = consumer("empty");
    forge_answers(&forge, &[], &[], &[("claude/gone", true)]);
    produce(&dir, &forge);
    let refused = against(&dir, &forge, &["check"]);
    assert_eq!(refused.status.code(), Some(2), "{}", said(&refused));
}

#[test]
fn a_reused_name_still_on_the_remote_is_reported_and_one_already_deleted_is_not() {
    let (live, forge) = consumer("reused-live");
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/reused", "r")],
        &[("t0", FRESH), ("r", FRESH)],
        &[("claude/reused", true), ("claude/reused", true)],
    );
    produce(&live, &forge);
    let reported = against(&live, &forge, &["check"]);
    assert_eq!(reported.status.code(), Some(2), "{}", said(&reported));

    let (gone, forge) = consumer("reused-gone");
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/other", "o")],
        &[("t0", FRESH), ("o", FRESH)],
        &[("claude/deleted", true), ("claude/deleted", true)],
    );
    produce(&gone, &forge);
    let quiet = against(&gone, &forge, &["check"]);
    assert_eq!(
        quiet.status.code(),
        Some(0),
        "the same history with the branch deleted is clean — the remedy worked\n{}",
        said(&quiet)
    );
}

/// `count` distinct heads for pull requests closed before the ones a case is
/// about.
fn earlier(prefix: &str, count: usize) -> Vec<String> {
    (1..=count).map(|i| format!("claude/{prefix}{i}")).collect()
}

#[test]
fn only_the_two_hundred_most_recent_merged_pull_requests_are_counted() {
    // THE RETIRED BODY'S POPULATION: `gh pr list --state merged --limit 200`.
    // A name whose two merges both fall past the 200th most recent merge was
    // never in that list, so it is not reported. The window reads more than
    // 200 CLOSED rows only so that unmerged ones cannot shrink it.
    let (dir, forge) = consumer("merged-window");
    let older = earlier("f", 200);
    let mut pulls: Vec<(&str, bool)> = older.iter().map(|head| (head.as_str(), true)).collect();
    pulls.extend([("claude/reused", true), ("claude/reused", true)]);
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/reused", "r")],
        &[("t0", FRESH), ("r", FRESH)],
        &pulls,
    );
    produce(&dir, &forge);
    let quiet = against(&dir, &forge, &["check"]);
    assert_eq!(quiet.status.code(), Some(0), "{}", said(&quiet));
}

#[test]
fn an_unmerged_pull_request_takes_no_slot_in_the_merged_window() {
    // THE GAP A CLOSED-SET READ OPENS: 200 closed rows are not 200 merges, and
    // every unmerged one among them would push a merge out of what the retired
    // body saw. The cap counts merges, after the unmerged rows are dropped.
    let (dir, forge) = consumer("merged-window-unmerged");
    let closed = earlier("u", 200);
    let mut pulls: Vec<(&str, bool)> = closed.iter().map(|head| (head.as_str(), false)).collect();
    pulls.extend([("claude/reused", true), ("claude/reused", true)]);
    forge_answers(
        &forge,
        &[("main", "t0"), ("claude/reused", "r")],
        &[("t0", FRESH), ("r", FRESH)],
        &pulls,
    );
    produce(&dir, &forge);
    let reported = against(&dir, &forge, &["check"]);
    assert_eq!(reported.status.code(), Some(2), "{}", said(&reported));
    assert!(
        said(&reported).contains("claude/reused"),
        "{}",
        said(&reported)
    );
}
