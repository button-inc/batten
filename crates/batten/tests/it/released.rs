//! `[tasks.released]` — which issues a release tag shipped (CLOUD-174), and the
//! two refusals that make shipping necessary but not sufficient for Done: the
//! hold marker (CLOUD-257) and `graph-check`'s verdict (CLOUD-309), over the
//! task's own body (CLOUD-1752).
//!
//! Every case runs the committed body in a fixture clone with two tags: `v0.0.1`
//! naming CLOUD-1, and `v0.0.2` adding CLOUD-2 and CLOUD-3. `graph-check`
//! resolves from this checkout's `mise-tasks/` through `MISE_CONFIG_FILE`, which
//! is how a caller's clone is judged by this manifest's gates.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/released.sh mise.toml kind:mechanism crates/batten/tests/it/released.rs
// carried: tests/released.bats mise.toml kind:mechanism crates/batten/tests/it/released.rs
// carried: "with no stdin it reports what the tag shipped" mise.toml kind:mechanism
// carried: "an In Review issue the tag shipped is movable" mise.toml kind:mechanism
// carried: "an issue in any other state is left alone, never touched" mise.toml kind:mechanism
// carried: "THE REFUSAL: an issue holding itself open is HELD, not movable" mise.toml kind:mechanism
// carried: "the refusal says why shipping is not enough, not merely that it refused" mise.toml kind:mechanism
// carried: "a held issue does not suppress the movable ones beside it" mise.toml kind:mechanism
// carried: "the marker only holds an In Review issue — a Done one is already past it" mise.toml kind:mechanism
// carried: "an issue with no marker and no description still moves" mise.toml kind:mechanism
// carried: "THE SECOND WAY IN: no ref in the range, but a commit the tag contains" mise.toml kind:mechanism
// carried: "a commit shipped by an EARLIER tag is not new in this one" mise.toml kind:mechanism
// carried: "a commit the tag does not contain is not movable" mise.toml kind:mechanism
// carried: "a commit does not buy a way past the hold" mise.toml kind:mechanism
// carried: "an unknown or malformed commit is ignored, not fatal" mise.toml kind:mechanism
// carried: "an issue matched BOTH ways is reported once" mise.toml kind:mechanism
// carried: "a payload with no commit field behaves exactly as before" mise.toml kind:mechanism
// carried: "a tag naming no issue still reports cleanly when no commit matches either" mise.toml kind:mechanism
// carried: "a chore-only tag still matches an issue by commit" mise.toml kind:mechanism
// carried: "a tag that does not exist is exit 2, not an empty release" mise.toml kind:mechanism
// carried: "stdin that is not a payload set is exit 2, distinct from a stale board" mise.toml kind:mechanism
// carried: "THE SECOND REFUSAL: an In Review issue with no PR is REFUSED, not movable" mise.toml kind:mechanism
// carried: "the refusal names the rule that rejected it, not a generic failure" mise.toml kind:mechanism
// carried: "the same issue WITH a PR attachment still sweeps" mise.toml kind:mechanism
// carried: "a non-PR attachment is not a linked PR" mise.toml kind:mechanism
// carried: "a refused issue does not suppress the movable ones beside it" mise.toml kind:mechanism
// carried: "HELD and REFUSED are both reported, so one refusal never hides the other" mise.toml kind:mechanism
// carried: "the gate only judges In Review — a Done issue with no PR is left alone" mise.toml kind:mechanism
// carried: "COULD NOT LOOK: an In Review payload with no attachments KEY is exit 2" mise.toml kind:mechanism
// carried: "a missing key on an issue this transition does not touch is not exit 2" mise.toml kind:mechanism
// carried: "a blocker outside the piped set is NOT a refusal" mise.toml kind:mechanism
// changed: "the ordering is composed, not copied — no second in-review-no-pr predicate" mise.toml the grep reads the inline task body rather than the retired file
// changed: "the marker is stated once, in the task, not spread across issue prose" mise.toml the count reads the inline task body rather than the retired file
// carried: "an In Review payload with no description is refused, and the ids are named" mise.toml kind:mechanism
// carried: "an In Review payload with no relations is refused, and the ids are named" mise.toml kind:mechanism
// carried: "PRESENCE, NOT TRUTHINESS: an empty description and an empty blockedBy are judged" mise.toml kind:mechanism
// carried: "a key this transition does not read is not demanded of a non-In-Review issue" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;

const PR: &str = r#"[{"url":"https://github.com/o/r/pull/1"}]"#;

fn git(repo: &Path, args: &[&str]) -> String {
    let out = common::program("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn commit(repo: &Path, subject: &str, body: &str) {
    git(
        repo,
        &["commit", "-q", "--allow-empty", "-m", subject, "-m", body],
    );
}

fn repo(name: &str) -> PathBuf {
    let repo = common::scratch(&format!("released-{name}"));
    common::init_repo(&repo);
    git(&repo, &["config", "user.email", "t@example.com"]);
    git(&repo, &["config", "user.name", "t"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    git(&repo, &["config", "tag.gpgsign", "false"]);
    commit(&repo, "feat: the first thing", "Refs: CLOUD-1");
    git(&repo, &["tag", "v0.0.1"]);
    commit(&repo, "feat: the second thing", "Refs: CLOUD-2");
    commit(&repo, "fix: the third thing", "Refs: CLOUD-3");
    git(&repo, &["tag", "v0.0.2"]);
    repo
}

/// The body on `tag` with `stdin` piped: `(exit, stdout+stderr)`.
fn released(repo: &Path, tag: &str, stdin: &str) -> (Option<i32>, String) {
    let mut child = common::task_command(repo, "released")
        .env("MISE_CONFIG_FILE", common::at_root("mise.toml"))
        .env("usage_tag", tag)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn released");
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes());
    let out = child.wait_with_output().expect("run released");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
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

#[test]
fn with_no_stdin_it_reports_what_the_tag_shipped() {
    let dir = repo("bare");
    let (code, text) = released(&dir, "v0.0.2", "");
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("CLOUD-2") && text.contains("CLOUD-3"),
        "{text}"
    );
    // Scoped to the range, so the previous tag's issue is not re-reported.
    assert!(!text.contains("CLOUD-1\n"), "{text}");
    assert!(!text.contains("  CLOUD-1"), "{text}");
}

#[test]
fn an_in_review_issue_the_tag_shipped_is_movable_and_others_are_left_alone() {
    let dir = repo("movable");
    let (code, text) = released(&dir, "v0.0.2", &set(&[in_review("CLOUD-2")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("CLOUD-2  In Review -> Done"), "{text}");
    assert!(text.contains("1 to move"), "{text}");
    // A payload with no commit field behaves exactly as it always did.
    let done = issue("CLOUD-2", "Done", "", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[done]));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("left alone") && !text.contains("-> Done"),
        "{text}"
    );
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
    let (code, text) = released(&dir, "v0.0.2", &set(&[held.clone()]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-2  HELD"), "{text}");
    assert!(
        text.contains("0 to move") && text.contains("1 HELD"),
        "{text}"
    );
    assert!(
        text.contains("necessary for Done, not sufficient"),
        "{text}"
    );
    // A held issue does not suppress the movable one beside it.
    let (code, text) = released(&dir, "v0.0.2", &set(&[held, in_review("CLOUD-3")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-3  In Review -> Done"), "{text}");
}

#[test]
fn the_marker_holds_only_in_review_and_is_opt_in() {
    let dir = repo("marker");
    let done = issue("CLOUD-2", "Done", "DO-NOT-CLOSE", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[done]));
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("left alone") && !text.contains("HELD"),
        "{text}"
    );
    // No marker and an empty description still moves.
    let (code, text) = released(&dir, "v0.0.2", &set(&[in_review("CLOUD-2")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("In Review -> Done"), "{text}");
}

#[test]
fn a_commit_the_tag_contains_is_a_second_way_in() {
    let dir = repo("second-way");
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.2", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("CLOUD-9  In Review -> Done"), "{text}");
    // A tag the commit is not in does not ship it.
    let (code, text) = released(&dir, "v0.0.1", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(!text.contains("CLOUD-9"), "{text}");
    // And a second way to be FOUND is never a way past being HELD.
    let held = with_commit("CLOUD-9", &tip, "DO-NOT-CLOSE");
    let (code, text) = released(&dir, "v0.0.2", &set(&[held]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-9  HELD"), "{text}");
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
        text.contains("CLOUD-2  In Review -> Done") && !text.contains("CLOUD-9"),
        "{text}"
    );
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.2", &set(&[with_commit("CLOUD-2", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert_eq!(
        text.matches("CLOUD-2  In Review -> Done").count(),
        1,
        "{text}"
    );
    assert!(text.contains("1 to move"), "{text}");
}

#[test]
fn a_chore_only_tag_reports_cleanly_and_still_matches_by_commit() {
    let dir = repo("chore");
    commit(&dir, "chore: release v0.0.3", "");
    git(&dir, &["tag", "v0.0.3"]);
    let (code, text) = released(&dir, "v0.0.3", &set(&[in_review("CLOUD-9")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("references no CLOUD-* issue"), "{text}");
    let tip = git(&dir, &["rev-parse", "HEAD"]);
    let (code, text) = released(&dir, "v0.0.3", &set(&[with_commit("CLOUD-9", &tip, "")]));
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("CLOUD-9  In Review -> Done"), "{text}");
}

#[test]
fn an_absent_tag_or_unreadable_stdin_is_could_not_look() {
    let dir = repo("absent");
    assert_eq!(released(&dir, "v9.9.9", "").0, Some(2));
    assert_eq!(released(&dir, "", "").0, Some(2));
    assert_eq!(released(&dir, "v0.0.2", "not json").0, Some(2));
}

#[test]
fn an_in_review_issue_with_no_pr_is_refused_by_rule() {
    let dir = repo("no-pr");
    let bare = issue("CLOUD-2", "In Review", "", "[]", "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[bare.clone()]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("CLOUD-2  REFUSED (in-review-no-pr)"),
        "{text}"
    );
    assert!(!text.contains("CLOUD-2  In Review -> Done"), "{text}");
    assert!(text.contains("0 to move"), "{text}");
    // A non-PR attachment is not a linked PR.
    let doc = issue(
        "CLOUD-2",
        "In Review",
        "",
        r#"[{"url":"https://example.com/notes"}]"#,
        "",
    );
    let (code, text) = released(&dir, "v0.0.2", &set(&[doc]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("REFUSED (in-review-no-pr)"), "{text}");
    // A refused issue does not suppress the movable one beside it.
    let (code, text) = released(&dir, "v0.0.2", &set(&[bare, in_review("CLOUD-3")]));
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-3  In Review -> Done"), "{text}");
    assert!(
        text.contains("1 to move") && text.contains("1 REFUSED"),
        "{text}"
    );
}

#[test]
fn held_and_refused_are_both_reported() {
    let dir = repo("both");
    let refused = issue("CLOUD-2", "In Review", "x", "[]", "");
    let held = issue("CLOUD-3", "In Review", "DO-NOT-CLOSE", PR, "");
    let (code, text) = released(&dir, "v0.0.2", &set(&[refused, held]));
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("CLOUD-2  REFUSED") && text.contains("CLOUD-3  HELD"),
        "{text}"
    );
    assert!(
        text.contains("1 HELD") && text.contains("1 REFUSED"),
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
        text.contains("left alone") && !text.contains("REFUSED"),
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
    assert_eq!(code, Some(2), "{text}");
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
    assert_eq!(code, Some(2), "{text}");
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
    assert_eq!(code, Some(2), "{text}");
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
    assert!(text.contains("CLOUD-2  In Review -> Done"), "{text}");
}

/// The conjunction is composed, never copied, and the marker has one authority.
#[test]
fn the_body_carries_no_pr_predicate_and_one_marker() {
    let body = common::task_body("released");
    assert!(
        !body.contains("pull/"),
        "a second in-review-no-pr predicate"
    );
    assert_eq!(
        body.lines()
            .filter(|line| line.starts_with("HOLD_MARKER="))
            .count(),
        1
    );
}
