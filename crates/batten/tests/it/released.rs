//! `[tasks.released]` — which issues a release tag shipped (CLOUD-174), and the
//! two refusals that make shipping necessary but not sufficient for Done: the
//! hold marker (CLOUD-257) and `batten board check`'s verdict (CLOUD-309).
//!
//! The task's body retired under CLOUD-843: the reading is `batten record derive
//! released` (`crate::released`) and the decision the `tracker-hygiene`
//! preset's `shipping-is-not-sufficient` module, checked by the one committed
//! row. Every case runs the committed TASK through `mise`, in a fixture clone
//! with two tags — `v0.0.1` naming CLOUD-1, and `v0.0.2` adding CLOUD-2 and
//! CLOUD-3 — whose `batten.toml` enables that row and carries this repository's
//! `[[pattern]]` rows and `[board]` table, so the task's own wiring answers. The
//! exit table is the engine's: `0` clean, `2` held or refused, `1` could not
//! look (the reading refused and recorded nothing).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// ported: mise-tasks/released.sh subject:mise.toml crates/batten/tests/it/released.rs
// ported: tests/released.bats subject:mise.toml crates/batten/tests/it/released.rs
// carried: "with no stdin it reports what the tag shipped" crates/batten/src/released.rs kind:mechanism
// carried: "an In Review issue the tag shipped is movable" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "an issue in any other state is left alone, never touched" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "THE REFUSAL: an issue holding itself open is HELD, not movable" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// changed: "the refusal says why shipping is not enough, not merely that it refused" crates/batten/src/preset.rs the words moved from the body's stderr into the vendored `issue ship held` gloss, which `check` renders beside the pointer
// carried: "a held issue does not suppress the movable ones beside it" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "the marker only holds an In Review issue — a Done one is already past it" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "an issue with no marker and no description still moves" crates/batten/src/released.rs kind:mechanism
// carried: "THE SECOND WAY IN: no ref in the range, but a commit the tag contains" crates/batten/src/released.rs kind:mechanism
// carried: "a commit shipped by an EARLIER tag is not new in this one" crates/batten/src/released.rs kind:mechanism
// carried: "a commit the tag does not contain is not movable" crates/batten/src/released.rs kind:mechanism
// carried: "a commit does not buy a way past the hold" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "an unknown or malformed commit is ignored, not fatal" crates/batten/src/released.rs kind:mechanism
// carried: "an issue matched BOTH ways is reported once" crates/batten/src/released.rs kind:mechanism
// carried: "a payload with no commit field behaves exactly as before" crates/batten/src/released.rs kind:mechanism
// carried: "a tag naming no issue still reports cleanly when no commit matches either" crates/batten/src/released.rs kind:mechanism
// carried: "a chore-only tag still matches an issue by commit" crates/batten/src/released.rs kind:mechanism
// changed: "a tag that does not exist is exit 2, not an empty release" crates/batten/src/released.rs still never an empty release; the reading refuses, records nothing and the task exits 1, the engine's could-not-look
// changed: "stdin that is not a payload set is exit 2, distinct from a stale board" crates/batten/src/released.rs still distinct from a verdict; exit 1, the engine's could-not-look, with nothing recorded
// carried: "THE SECOND REFUSAL: an In Review issue with no PR is REFUSED, not movable" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "the refusal names the rule that rejected it, not a generic failure" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "the same issue WITH a PR attachment still sweeps" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "a non-PR attachment is not a linked PR" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "a refused issue does not suppress the movable ones beside it" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "HELD and REFUSED are both reported, so one refusal never hides the other" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// carried: "the gate only judges In Review — a Done issue with no PR is left alone" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// changed: "COULD NOT LOOK: an In Review payload with no attachments KEY is exit 2" crates/batten/src/released.rs still could-not-look, naming the ids and the re-fetch; exit 1 on the engine's table
// changed: "a missing key on an issue this transition does not touch is not exit 2" crates/batten/src/released.rs still never could-not-look for a row outside the review column; the could-not-look exit is 1 now
// carried: "a blocker outside the piped set is NOT a refusal" crates/batten/src/policy/presets/tracker-hygiene/shipping-is-not-sufficient.rego kind:mechanism
// changed: "the ordering is composed, not copied — no second in-review-no-pr predicate" crates/batten/src/released.rs the reading composes `board_check::graph_findings` in process, and the case reads the reading's source for a pull-request spelling rather than the retired body
// changed: "the marker is stated once, in the task, not spread across issue prose" batten.toml the one authority is the `released-hold-marker` `[[pattern]]` row the task names by id; the case counts that row and reads the reading's source for the literal
// carried: "an In Review payload with no description is refused, and the ids are named" crates/batten/src/released.rs kind:mechanism
// carried: "an In Review payload with no relations is refused, and the ids are named" crates/batten/src/released.rs kind:mechanism
// carried: "PRESENCE, NOT TRUTHINESS: an empty description and an empty blockedBy are judged" crates/batten/src/released.rs kind:mechanism
// carried: "a key this transition does not read is not demanded of a non-In-Review issue" crates/batten/src/released.rs kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Output;

const PR: &str = r#"[{"url":"https://github.com/o/r/pull/1"}]"#;

/// The one row every tracker question is checked under — the committed one.
const ROW: &str = "issue state other";

fn git(repo: &Path, args: &[&str]) -> String {
    common::git_in(repo, args)
}

fn commit(repo: &Path, subject: &str, body: &str) {
    git(
        repo,
        &["commit", "-q", "--allow-empty", "-m", subject, "-m", body],
    );
}

/// An authority enabling the preset under [`ROW`], declaring the `released`
/// family, with `board` and this repository's `[[pattern]]` rows appended.
fn authority(board: &str) -> String {
    format!(
        "version = 1\nscope = [\"**\"]\n\n[[rule]]\nid = \"{ROW}\"\nkind = \"policy\"\n\
         scope = \"tree\"\npreset = \"tracker-hygiene\"\nseverity = \"deny\"\n\n\
         [[record]]\nrecord = \"released\"\nwriter = \"mise run released\"\n\n{board}\n{}",
        common::declared_patterns()
    )
}

/// A fixture clone judged against `board`, with the two tags every case reads.
fn repo_with(name: &str, board: &str) -> PathBuf {
    let repo = common::scratch(&format!("released-{name}"));
    common::write(&repo, "batten.toml", &authority(board));
    common::init_repo(&repo);
    git(&repo, &["config", "user.email", "t@example.com"]);
    git(&repo, &["config", "user.name", "t"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    git(&repo, &["config", "tag.gpgsign", "false"]);
    git(&repo, &["add", "batten.toml"]);
    commit(&repo, "feat: the first thing", "Refs: CLOUD-1");
    git(&repo, &["tag", "v0.0.1"]);
    commit(&repo, "feat: the second thing", "Refs: CLOUD-2");
    commit(&repo, "fix: the third thing", "Refs: CLOUD-3");
    git(&repo, &["tag", "v0.0.2"]);
    repo
}

/// [`repo_with`] this repository's committed `[board]` table.
fn repo(name: &str) -> PathBuf {
    repo_with(name, &common::declared_board())
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// `mise run -q released <tag>` over the committed manifest, with `stdin` piped:
/// `(exit, stdout+stderr)`. An empty `tag` passes no argument at all.
fn released(repo: &Path, tag: &str, stdin: &str) -> (Option<i32>, String) {
    let task = if tag.is_empty() {
        "released".to_owned()
    } else {
        format!("released {tag}")
    };
    let output = common::mise_task(repo, &task, &[], stdin);
    (output.status.code(), said(&output))
}

/// One issue carrying every key the gate decides on; `extra` is spliced in raw.
fn issue(id: &str, status: &str, description: &str, attachments: &str, extra: &str) -> String {
    format!(
        r#"{{"id":"{id}","status":"{status}","description":"{description}","attachments":{attachments},"relations":{{"blockedBy":[]}}{extra}}}"#
    )
}

fn set(issues: &[String]) -> String {
    format!("[{}]", issues.join(","))
}

fn in_review(id: &str) -> String {
    issue(id, "In Review", "", PR, "")
}

fn with_commit(id: &str, sha: &str, description: &str) -> String {
    issue(
        id,
        "In Review",
        description,
        PR,
        &format!(r#","commit":"{sha}""#),
    )
}

/// The record line a shipped, piped row carries.
fn row(id: &str, column: &str, hold: &str) -> String {
    format!("issue\t{id}\t{column}\t{hold}\n")
}

/// Whether any refusal line names `id` — the record's own lines are tab
/// separated, so a space-separated `<class> <id>` is the check's.
fn refused_line(text: &str, class: &str, id: &str) -> bool {
    text.lines()
        .any(|line| line.contains(class) && line.contains(id) && !line.contains('\t'))
}

#[test]
fn with_no_stdin_it_reports_what_the_tag_shipped() {
    let dir = repo("bare");
    let (code, text) = released(&dir, "v0.0.2", "");
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("range\tv0.0.1..v0.0.2\n"), "{text}");
    assert!(
        text.contains("shipped\tCLOUD-2\n") && text.contains("shipped\tCLOUD-3\n"),
        "{text}"
    );
    // Scoped to the range, so the previous tag's issue is not re-reported.
    assert!(!text.contains("CLOUD-1\n"), "{text}");
    assert!(text.contains("census\tissues=0\n"), "{text}");
}

#[test]
fn an_in_review_issue_the_tag_shipped_is_movable_and_others_are_left_alone() {
    let dir = repo("movable");
    let (code, text) = released(&dir, "v0.0.2", &set(&[in_review("CLOUD-2")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-2", "review", "free")), "{text}");
    assert!(text.contains("census\tissues=1\n"), "{text}");
    // A payload with no commit field behaves exactly as it always did.
    let done = issue("CLOUD-2", "Done", "", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[done]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-2", "other", "free")), "{text}");
}

#[test]
fn an_issue_holding_itself_open_is_held() {
    let dir = repo("held");
    let held = issue(
        "CLOUD-2",
        "In Review",
        "blocked, DO-NOT-CLOSE until the matrix is green",
        PR,
        "",
    );
    let (code, text) = released(&dir, "v0.0.2", &set(std::slice::from_ref(&held)));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains(&row("CLOUD-2", "review", "held")), "{text}");
    assert!(refused_line(&text, "issue ship held", "CLOUD-2"), "{text}");
    assert!(
        text.contains("necessary for Done, not sufficient"),
        "{text}"
    );
    // A held issue does not suppress the movable one beside it.
    let (code, text) = released(&dir, "v0.0.2", &set(&[held, in_review("CLOUD-3")]));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains(&row("CLOUD-3", "review", "free")), "{text}");
    assert!(!refused_line(&text, "issue ship", "CLOUD-3"), "{text}");
}

#[test]
fn the_marker_holds_only_in_review_and_is_opt_in() {
    let dir = repo("marker");
    let done = issue("CLOUD-2", "Done", "DO-NOT-CLOSE", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[done]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("issue ship held"), "{text}");
    // No marker and an empty description still moves.
    let (code, text) = released(&dir, "v0.0.2", &set(&[in_review("CLOUD-2")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-2", "review", "free")), "{text}");
}

#[test]
fn a_commit_the_tag_contains_is_a_second_way_in() {
    let dir = repo("second-way");
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.2", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-9", "review", "free")), "{text}");
    // A tag the commit is not in does not ship it.
    let (code, text) = released(&dir, "v0.0.1", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("CLOUD-9"), "{text}");
    // And a second way to be FOUND is never a way past being HELD.
    let held = with_commit("CLOUD-9", &tip, "DO-NOT-CLOSE");
    let (code, text) = released(&dir, "v0.0.2", &set(&[held]));
    assert_eq!(code, Some(2), "{text}");
    assert!(refused_line(&text, "issue ship held", "CLOUD-9"), "{text}");
}

#[test]
fn a_commit_an_earlier_tag_shipped_is_not_new() {
    let dir = repo("earlier");
    let first = git(&dir, &["rev-parse", "v0.0.1"]);
    let (code, text) = released(&dir, "v0.0.2", &set(&[with_commit("CLOUD-9", &first, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("CLOUD-9"), "{text}");
}

#[test]
fn an_unknown_commit_is_ignored_and_a_double_match_is_reported_once() {
    let dir = repo("commits");
    let bad = with_commit("CLOUD-9", "not-a-sha", "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[bad, in_review("CLOUD-2")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(&row("CLOUD-2", "review", "free")) && !text.contains("CLOUD-9"),
        "{text}"
    );
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.2", &set(&[with_commit("CLOUD-2", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(text.matches("shipped\tCLOUD-2\n").count(), 1, "{text}");
    assert_eq!(
        text.matches(&row("CLOUD-2", "review", "free")).count(),
        1,
        "{text}"
    );
}

#[test]
fn a_chore_only_tag_reports_cleanly_and_still_matches_by_commit() {
    let dir = repo("chore");
    commit(&dir, "chore: release v0.0.3", "");
    git(&dir, &["tag", "v0.0.3"]);
    let (code, text) = released(&dir, "v0.0.3", &set(&[in_review("CLOUD-9")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("shipped\t"), "{text}");
    assert!(text.contains("census\tissues=0\n"), "{text}");
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.3", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-9", "review", "free")), "{text}");
}

#[test]
fn an_absent_tag_or_unreadable_stdin_is_could_not_look() {
    let dir = repo("absent");
    let (code, text) = released(&dir, "v9.9.9", "");
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("no such tag"), "{text}");
    assert_eq!(released(&dir, "", "").0, Some(1));
    assert_eq!(released(&dir, "v0.0.2", "not json").0, Some(1));
}

#[test]
fn an_in_review_issue_with_no_pr_is_refused_by_rule() {
    let dir = repo("no-pr");
    let bare = issue("CLOUD-2", "In Review", "", "[]", "");
    let (code, text) = released(&dir, "v0.0.2", &set(std::slice::from_ref(&bare)));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        text.contains("refusal\tCLOUD-2\tin-review-no-pr\n"),
        "{text}"
    );
    assert!(
        refused_line(&text, "issue ship refused", "CLOUD-2 in-review-no-pr"),
        "{text}"
    );
    // A non-PR attachment is not a linked PR.
    let doc = issue(
        "CLOUD-2",
        "In Review",
        "",
        r#"[{"url":"https://example.com/notes"}]"#,
        "",
    );
    let (code, text) = released(&dir, "v0.0.2", &set(&[doc]));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        refused_line(&text, "issue ship refused", "CLOUD-2 in-review-no-pr"),
        "{text}"
    );
    // A refused issue does not suppress the movable one beside it.
    let (code, text) = released(&dir, "v0.0.2", &set(&[bare, in_review("CLOUD-3")]));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains(&row("CLOUD-3", "review", "free")), "{text}");
    assert!(!refused_line(&text, "issue ship", "CLOUD-3"), "{text}");
}

#[test]
fn held_and_refused_are_both_reported() {
    let dir = repo("both");
    let refused = issue("CLOUD-2", "In Review", "x", "[]", "");
    let held = issue("CLOUD-3", "In Review", "DO-NOT-CLOSE", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[refused, held]));
    assert_eq!(code, Some(2), "{text}");
    assert!(
        refused_line(&text, "issue ship refused", "CLOUD-2")
            && refused_line(&text, "issue ship held", "CLOUD-3"),
        "{text}"
    );
}

#[test]
fn a_done_issue_is_never_judged_nor_asked_for_keys() {
    let dir = repo("done");
    let (code, text) = released(
        &dir,
        "v0.0.2",
        r#"[{"id":"CLOUD-2","status":"Done","attachments":[],"relations":{"blockedBy":[]}}]"#,
    );
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(&row("CLOUD-2", "other", "free")) && !text.contains("issue ship"),
        "{text}"
    );
    let (code, text) = released(&dir, "v0.0.2", r#"[{"id":"CLOUD-2","status":"Done"}]"#);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        !text.contains("description") && !text.contains("relations"),
        "{text}"
    );
}

#[test]
fn an_in_review_payload_with_no_attachments_key_is_could_not_look() {
    let dir = repo("unattached");
    let (code, text) = released(
        &dir,
        "v0.0.2",
        r#"[{"id":"CLOUD-2","status":"In Review","description":"","relations":{"blockedBy":[]}}]"#,
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("attachments"),
        "{text}"
    );
}

#[test]
fn an_in_review_payload_with_no_description_is_refused_and_named() {
    let dir = repo("undescribed");
    let (code, text) = released(
        &dir,
        "v0.0.2",
        &format!(
            r#"[{{"id":"CLOUD-2","status":"In Review","attachments":{PR},"relations":{{"blockedBy":[]}}}}]"#
        ),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("description") && text.contains("re-fetch"),
        "{text}"
    );
}

#[test]
fn an_in_review_payload_with_no_relations_is_refused_and_named() {
    let dir = repo("unrelated");
    let (code, text) = released(
        &dir,
        "v0.0.2",
        &format!(
            r#"[{{"id":"CLOUD-2","status":"In Review","attachments":{PR},"description":"x"}}]"#
        ),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("includeRelations"),
        "{text}"
    );
}

#[test]
fn a_blocker_outside_the_piped_set_is_not_a_refusal() {
    let dir = repo("dangling");
    let dangling = format!(
        r#"{{"id":"CLOUD-2","status":"In Review","description":"","attachments":{PR},"relations":{{"blockedBy":[{{"id":"CLOUD-999"}}]}}}}"#
    );
    let (code, text) = released(&dir, "v0.0.2", &set(&[dangling]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains(&row("CLOUD-2", "review", "free")), "{text}");
    assert!(!text.contains("issue ship"), "{text}");
}

/// A GATE THAT DID NOT RUN IS NEVER A PASS. The retired body refused a child
/// `board check` that exited outside its own verdicts; the gate is composed in
/// process now, and its equivalent is a board vocabulary it cannot resolve — a
/// `[board]` naming the review column and nothing else the gate needs. An empty
/// report read as "nothing refused" would pass every shipped row.
#[test]
fn a_board_check_that_did_not_run_is_could_not_look() {
    let dir = repo_with("unrun", "[board]\nreview = \"In Review\"\n");
    let (code, text) = released(&dir, "v0.0.2", &set(&[in_review("CLOUD-2")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("could not run") && !text.contains("issue\tCLOUD-2"),
        "{text}"
    );
}

/// THE CENSUS CLOSES THE RECORD: one written without it is torn, and refused as
/// torn rather than judged as though it were the whole release.
#[test]
fn a_released_record_without_its_census_is_torn() {
    let dir = repo("torn");
    let written = common::run_with_stdin(
        &dir,
        &["record", "named", "released"],
        "issue\tCLOUD-2\treview\tfree\n",
    );
    assert!(written.status.success(), "{}", said(&written));
    let decided = common::run(&dir, &["check", "--rule", ROW]);
    let text = said(&decided);
    assert_eq!(decided.status.code(), Some(2), "{text}");
    assert!(text.contains("tag read partial"), "{text}");
}

/// The conjunction is composed, never copied, and the marker has one authority:
/// the reading spells no pull request, and names no marker literal — the task
/// hands it the one `[[pattern]]` row by id.
#[test]
fn the_reading_carries_no_pr_predicate_and_the_marker_has_one_authority() {
    let source = include_str!("../../src/released.rs");
    let pull = ["pull", "/"].concat();
    assert!(
        !source.contains(&pull),
        "a second in-review-no-pr predicate"
    );
    let marker = ["DO-NOT", "-CLOSE"].concat();
    assert!(
        !source.contains(&marker),
        "the marker is the row's, not the reading's"
    );
    let config = std::fs::read_to_string(common::at_root("batten.toml")).expect("the config");
    assert_eq!(
        config
            .lines()
            .filter(|line| *line == "id = \"released-hold-marker\"")
            .count(),
        1
    );
    let body = common::task_body("released");
    assert!(body.contains("--input hold=released-hold-marker"), "{body}");
}

/// The committed task records its family, then checks the one row, as every
/// sibling tracker gate does — and carries no shell of its own.
#[test]
fn the_committed_task_records_then_checks_the_one_row() {
    let block = common::task_block("released").expect("[tasks.released]");
    let argv = common::task_value(&block, "run");
    assert!(argv.contains("record derive released"), "{argv}");
    assert!(argv.contains(&format!("check --rule '{ROW}'")), "{argv}");
    assert_eq!(argv.matches("{{vars.batten}} ").count(), 2, "{argv}");
    assert_eq!(common::task_value(&block, "dir"), "{{cwd}}");
    assert!(common::task_value(&block, "shell").is_empty(), "{argv}");
}
