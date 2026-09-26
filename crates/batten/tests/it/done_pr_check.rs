//! `[tasks.done-pr-check]` — an issue may become Done only if none of its own
//! pull requests is still open (CLOUD-468), over the task's own body
//! (CLOUD-1752). A pure function of stdin: no network, no credential.
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell retire partial` reads
//!
// carried: mise-tasks/done-pr-check.sh mise.toml kind:mechanism crates/batten/tests/it/done_pr_check.rs
// carried: tests/done-pr-check.bats mise.toml kind:mechanism crates/batten/tests/it/done_pr_check.rs
// carried: "every attached PR merged: Done is licensed" mise.toml kind:mechanism
// carried: "an OPEN pull request refuses, and the refusal names its number" mise.toml kind:mechanism
// carried: "THE DEFECT: a DRAFT pull request refuses, and is named as a draft" mise.toml kind:mechanism
// carried: "one open PR among several merged still refuses — N=1 is the only safe case" mise.toml kind:mechanism
// carried: "a closed-unmerged PR does NOT refuse — a decided outcome is not work in flight" mise.toml kind:mechanism
// carried: "no pull request at all is refused — In Review already requires one" mise.toml kind:mechanism
// carried: "a non-PR attachment is ignored, not counted as a pull request" mise.toml kind:mechanism
// carried: "a PR-shaped URL on another host is not a PR — the filter is GitHub-anchored" mise.toml kind:mechanism
// carried: "an attachment whose URL only mentions pull is not a PR" mise.toml kind:mechanism
// carried: "COULD NOT LOOK: an attached PR with no state supplied is exit 2, never a licence" mise.toml kind:mechanism
// carried: "a missing pulls key is could-not-look too, not an empty set of blockers" mise.toml kind:mechanism
// carried: "several issues are each judged, and one bad issue refuses the batch" mise.toml kind:mechanism
// carried: "a duplicate attachment for one PR is counted once" mise.toml kind:mechanism
// carried: "empty stdin is exit 2, distinct from a licensed issue" mise.toml kind:mechanism
// carried: "unparseable stdin is exit 2" mise.toml kind:mechanism
// carried: "a payload with no id is exit 2, never a pass" mise.toml kind:mechanism
// carried: "a concatenated payload stream is accepted, like claim-check's" mise.toml kind:mechanism
// carried: "THE PROPERTY: output is a pointer — an id, a rule and a number, never a title" mise.toml kind:mechanism
// carried: "THE REGRESSION: CLOUD-420's real shape refuses, naming the draft nobody noticed" mise.toml kind:mechanism

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

fn check(name: &str, stdin: &str) -> (Option<i32>, String) {
    let dir = common::scratch(&format!("done-pr-check-{name}"));
    let out = common::produce(&dir, "done-pr-check", stdin);
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn url(n: u32) -> String {
    format!("https://github.com/button-inc/batten/pull/{n}")
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

#[test]
fn every_attached_pr_merged_licenses_done() {
    let (code, text) = check(
        "merged",
        &set(&[issue("CLOUD-425", &[url(346)], &[merged(346)])]),
    );
    assert_eq!(code, Some(0), "{text}");
    // Closed-unmerged is a decided outcome, not work in flight.
    let (code, text) = check(
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
    let (code, text) = check(
        "open",
        &set(&[issue(
            "CLOUD-1",
            &[url(500)],
            &[pull(500, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-1 open-pr (#500)"), "{text}");
    // One open among several merged still refuses.
    let (code, text) = check(
        "one-of-three",
        &set(&[issue(
            "CLOUD-1",
            &[url(1), url(2), url(3)],
            &[merged(1), merged(2), pull(3, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("#3"), "{text}");
}

#[test]
fn the_defect_a_draft_pull_request_refuses_named_as_a_draft() {
    let (code, text) = check(
        "draft",
        &set(&[issue(
            "CLOUD-1",
            &[url(368)],
            &[pull(368, "open", false, true)],
        )]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-1 open-pr (#368, draft)"), "{text}");
    // THE REGRESSION: CLOUD-420's real shape.
    let (code, text) = check(
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
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-420 open-pr (#368, draft)"), "{text}");
}

#[test]
fn no_pull_request_at_all_is_refused() {
    let (code, text) = check("no-pr", r#"[{"id":"CLOUD-1","attachments":[],"pulls":[]}]"#);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-1 no-pr"), "{text}");
}

#[test]
fn a_non_pr_attachment_is_not_a_pull_request() {
    for other in [
        "https://linear.app/buttoninc/document/x",
        "https://example.com/how-to-pull/123",
    ] {
        let (code, text) = check(
            "non-pr",
            &set(&[issue("CLOUD-1", &[other.to_owned(), url(7)], &[merged(7)])]),
        );
        assert_eq!(code, Some(0), "{other}: {text}");
    }
}

/// Found by mutation: only a same-shaped URL on another forge tells a
/// host-anchored filter from `pull/[0-9]+`.
#[test]
fn a_pr_shaped_url_on_another_host_is_not_a_pr() {
    let (code, text) = check(
        "gitlab",
        &set(&[issue(
            "CLOUD-1",
            &["https://gitlab.com/acme/x/pull/999".to_owned(), url(7)],
            &[merged(7)],
        )]),
    );
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn an_attached_pr_with_no_state_is_could_not_look() {
    let (code, text) = check("no-state", &set(&[issue("CLOUD-1", &[url(42)], &[])]));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("#42") && text.contains("no state"), "{text}");
    let missing = format!(
        r#"[{{"id":"CLOUD-1","attachments":[{{"url":"{}"}}]}}]"#,
        url(42)
    );
    assert_eq!(check("no-pulls", &missing).0, Some(2));
}

#[test]
fn several_issues_are_judged_and_one_refuses_the_batch() {
    let (code, text) = check(
        "batch",
        &set(&[
            issue("CLOUD-1", &[url(1)], &[merged(1)]),
            issue("CLOUD-2", &[url(2)], &[pull(2, "open", false, false)]),
        ]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("CLOUD-2 open-pr (#2)"), "{text}");
    assert!(!text.contains("CLOUD-1 open-pr"), "{text}");
    // A duplicate attachment for one PR is counted once.
    let (code, text) = check(
        "duplicate",
        &set(&[issue(
            "CLOUD-1",
            &[url(9), url(9)],
            &[pull(9, "open", false, false)],
        )]),
    );
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(text.matches("open-pr").count(), 1, "{text}");
}

#[test]
fn unreadable_stdin_is_exit_2() {
    assert_eq!(check("empty", "").0, Some(2));
    assert_eq!(check("garbage", "not json").0, Some(2));
    assert_eq!(check("no-id", r#"[{"attachments":[]}]"#).0, Some(2));
}

#[test]
fn a_concatenated_payload_stream_is_accepted() {
    let stream = format!(
        "{}\n{}\n",
        issue("CLOUD-1", &[url(1)], &[merged(1)]),
        issue("CLOUD-2", &[url(2)], &[merged(2)])
    );
    let (code, text) = check("stream", &stream);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn the_output_is_a_pointer_never_a_title() {
    let payload = format!(
        r#"[{{"id":"CLOUD-1","attachments":[{{"url":"{}","title":"a distinctive title no gate may echo"}}],"pulls":[{{"number":500,"state":"open","merged":false,"draft":false,"title":"another distinctive title"}}]}}]"#,
        url(500)
    );
    let (code, text) = check("pointer", &payload);
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains("distinctive title"), "{text}");
}
