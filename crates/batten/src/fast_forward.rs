//! Asking the fast-forward bot to land a head, and reading the answer it gave
//! THIS request.
//!
//! # Why this is a module and not three lines in the lap
//!
//! The lap's other four steps decide from something local — a rebase outcome, a
//! gate's exit code, a push's CAS report. This one asks a THIRD PARTY and then
//! has to work out which of that party's answers was addressed to it, and the
//! whole difficulty is in the second half. So the protocol lives here, beside its
//! own join key, and [`crate::land`] orchestrates.
//!
//! # The join key, which is the entire correctness argument
//!
//! An `issue_comment` workflow run attaches to the DEFAULT BRANCH's tip. Its
//! `head_branch` and `head_sha` both name trunk on every one of these runs, and
//! no other field records which pull request asked. So a lap that polled by
//! timestamp alone would read strangers' refusals as its own — measured on the
//! predecessor at ~400 runs in thirty minutes, 243 of them refusals, which is a
//! near-certainty of finding somebody else's within any lap's window. That is how
//! "the bot is silent or slow" was concluded while the bot was in fact answering
//! every attempt within 23 seconds.
//!
//! [`key`] is what closes it: the comment id comes back from the POST that
//! created it, the workflow mints the same string as its `run-name`, and
//! `display_title` carries it. One request, one answer.
//!
//! # Two fences, and the client-side one is the correctness half
//!
//! `created=>=<since>` bounds the page server-side, which is what makes paging
//! terminate over a finite window rather than over all history. But a query
//! parameter is an OPTIMISATION: mistype it, or meet an endpoint that ignores it,
//! and the fence vanishes with nothing failing. The `created_at >= since`
//! comparison here is what actually holds the line, and it is also what stops an
//! EARLIER LAP of this same pull request being re-read as this lap's verdict —
//! the livelock the stamp exists to prevent, and the reason the stamp is taken
//! before the comment is posted rather than after.
//!
//! # Pointer-only
//!
//! A refusal names the status, the endpoint's last segment, or a conclusion
//! token. Never a response body: a forge error can echo a header dump back, and a
//! token with it (non-negotiable rule 4, and `bot::forge`'s own posture).

use anyhow::Result;

use crate::error::UsageError;

/// Runs per page when reading for the answer.
///
/// The maximum the endpoint offers, because the page size is not a fence — the
/// `created` window is — and a smaller page only costs more round trips inside
/// the same window.
const PER_PAGE: u32 = 100;

/// How many pages one read will walk before giving up.
///
/// A RUNAWAY BACKSTOP AND NOTHING ELSE. Paging stops when a page comes back
/// short, which terminates because `created>=since` bounds the set server-side.
/// Reaching this cap means that fence stopped being honoured, not that the window
/// is genuinely this deep: at the predecessor's measured 13 runs/minute, 2000
/// runs is ~2.5 hours, far outside any lap's stamp.
const MAX_PAGES: u32 = 20;

/// The open pull request for `branch`, where the forge names one.
///
/// HERE RATHER THAN IN THE LAP, for the reason [`crate::pr_watch::read`] states
/// about its own read: a lap that built the request itself would be a second
/// authority over the endpoint and the failure posture. `land` reaches this
/// module and no other, which is also what keeps `land -> bot` off the layering
/// table for one number.
///
/// **The `--jq` filter is gone with the spawn, and the guard it needed with it.**
/// The predecessor wrote `.[0].number // empty` because the client prints the
/// STRING `null` for a missing field — not empty, and it would sail past a
/// caller's guard as a pull request number. Reading the document here, an absent
/// entry is `None` by construction and there is no rendering to be fooled by.
#[must_use]
pub fn open_pull_request(repo: &str, branch: &str) -> Option<String> {
    let raw = run(&format!(
        "repos/{repo}/pulls?head={branch}&state=open&per_page=1"
    ))?;
    let document = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    let number = document.as_array()?.first()?.get("number")?;
    // A NUMBER OR A STRING, for `comment_id`'s reason one function down: the
    // forge sends a number, and a string-only read would answer `None` over a
    // good response.
    number
        .as_u64()
        .map(|found| found.to_string())
        .or_else(|| number.as_str().map(str::to_owned))
}

/// What the lap needs to ask, and to recognise the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The repository, in the forge's own `owner/name` spelling.
    pub repo: String,
    /// The pull request number, as written.
    pub pr: String,
    /// The workflow file whose runs carry the verdict.
    pub workflow: String,
}

/// The join key the workflow mints as its `run-name`.
///
/// Built from the comment id the POST returned, so it cannot be guessed ahead of
/// the request and cannot collide with another lap's.
#[must_use]
pub fn key(pr: &str, comment: &str) -> String {
    format!("fast-forward #{pr} @{comment}")
}

/// What asking produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    /// The comment exists, and this is the id the answer will be keyed to.
    Commented(String),
    /// The forge did not create it. Pointer-only: the status, never the body.
    ///
    /// **THE SUCCESS LINE IS A CONSEQUENCE OF THE COMMENT EXISTING**, not of
    /// control reaching the next statement. Measured on the predecessor at PR
    /// #330: the forge answered a secondary rate limit, the client exited
    /// non-zero, nobody read it, and the lap reported "commented /fast-forward …
    /// waiting for the merge" over a comment that was never created — then waited
    /// for a merge nothing had been asked to perform.
    Refused(u16),
}

/// Post the `/fast-forward` directive and read back the comment's own id.
///
/// # Errors
///
/// Only for an [`Ask`] naming no pull request. Every failure to REACH the forge
/// is an [`Asked::Refused`], because a lap must survive one.
pub fn ask(ask: &Ask) -> Result<Asked> {
    if ask.pr.is_empty() {
        return Err(UsageError::raise(String::from(
            "land: no pull request to ask for a fast-forward",
        )));
    }
    // `-i` so the RESPONSE HEADERS come back with the body: when this is refused,
    // the reason and the delay are stated there, and asking a second endpoint for
    // them would be one more request against the limit that just refused this one.
    //
    // The API rather than the client's own `pr comment` porcelain, and not for
    // style: this returns the created comment OBJECT, so `.id` — the key the read
    // below needs — comes back on stdout, and a non-2xx gives both a real
    // non-zero exit and a status worth naming.
    // THE API RATHER THAN THE CLIENT'S COMMENT PORCELAIN, and the predecessor's
    // reason survives the transport change: this returns the created comment
    // OBJECT, so `.id` — the key the read below needs — comes back in the body.
    //
    // The response headers used to need `-i` so a refusal's reason and delay
    // arrived with the body. They arrive typed now: `crate::rest::Answer`
    // carries the status the transport read, so there is no header block to
    // parse and no second request to ask for one.
    let endpoint = format!("repos/{}/issues/{}/comments", ask.repo, ask.pr);
    let body = serde_json::json!({ "body": "/fast-forward" });
    let Some(answer) = crate::rest::post_json(&endpoint, &body) else {
        return Ok(Asked::Refused(0));
    };
    let Some(id) = comment_id(&answer.body) else {
        return Ok(Asked::Refused(answer.status));
    };
    Ok(Asked::Commented(id))
}

/// The `id` field of a created comment, as a string whatever its JSON type.
///
/// The forge sends a NUMBER here, so a string-only read answers `None` over a
/// perfectly good response and the lap reports a comment it did create as
/// refused — which is the false-negative direction, and the one that costs a lap.
fn comment_id(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let id = value.get("id")?;
    if let Some(number) = id.as_u64() {
        return Some(number.to_string());
    }
    id.as_str().map(str::to_owned)
}

/// What the bot said about THIS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// No keyed run yet. The ordinary state, and not a verdict.
    Pending,
    /// It ran and did not refuse. The merge shows up as the pull request's own
    /// terminal state rather than here.
    Accepted,
    /// It ran and refused: the branch is no longer a direct descendant.
    Refused,
    /// It ran and decided nothing, or the answer could not be read. Carries the
    /// conclusion token, which is a closed vocabulary and never prose.
    ///
    /// **NEVER "main moved"** — that is a fact about a ref, and only the
    /// staleness arm may assert it. Reading every non-success conclusion as
    /// staleness is what the predecessor did, and across 24 laps of one landing
    /// that diagnosis was wrong twice over: 7 of 8 laps in one run reached green
    /// CI, and several refusals were the rate limit rather than trunk moving. The
    /// loop's response to being rate-limited was to generate more of exactly the
    /// request that had been refused.
    Unknown(String),
}

/// The API-relative path one page of the answer read asks for.
///
/// Built rather than formatted at the call site so the window, the page size and
/// the event filter are one object a test can read.
///
/// **A PATH RATHER THAN AN ARGV**, which is the shape change the in-process
/// transport buys: there is no `api` subcommand word to prepend and no client to
/// resolve, so what a case reads here is the endpoint itself.
#[must_use]
pub fn answer_request(ask: &Ask, since: &str, page: u32) -> String {
    format!(
        "repos/{}/actions/workflows/{}/runs?event=issue_comment&per_page={PER_PAGE}&page={page}&created=%3E%3D{since}",
        ask.repo, ask.workflow
    )
}

/// Read whether the run keyed to `comment` has concluded.
///
/// Pages until a page comes back short, which is what makes the depth a property
/// of the WINDOW rather than of a page size. The two limits are independent: the
/// key says which run is this lap's, the depth says whether this lap's run is in
/// the page at all. A keyed filter over a window that has already rolled past the
/// run returns empty, which reads as [`Answer::Pending`] — byte-identical to a
/// silent bot, and the reading that cost the predecessor its diagnosis.
#[must_use]
pub fn answer(ask: &Ask, since: &str, comment: &str) -> Answer {
    let wanted = key(&ask.pr, comment);
    let mut page = 1;
    while page <= MAX_PAGES {
        let Some(raw) = run(&answer_request(ask, since, page)) else {
            return Answer::Unknown(String::from("unreadable"));
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return Answer::Unknown(String::from("unreadable"));
        };
        // A body that is not a runs list can never read as an answer. Absent and
        // present-but-wrong-shape are one reading here on purpose: both mean the
        // question was not answered, and neither is a verdict about the branch.
        let Some(runs) = value.get("workflow_runs").and_then(|r| r.as_array()) else {
            return Answer::Unknown(String::from("unreadable"));
        };
        let seen = runs.len();
        if let Some(conclusion) = concluded(runs, since, &wanted) {
            return grade(&conclusion);
        }
        if seen < PER_PAGE as usize {
            break;
        }
        page += 1;
    }
    Answer::Pending
}

/// The conclusion of the first completed run carrying `wanted`, inside the window.
fn concluded(runs: &[serde_json::Value], since: &str, wanted: &str) -> Option<String> {
    runs.iter().find_map(|run| {
        let created = run.get("created_at").and_then(serde_json::Value::as_str)?;
        if created < since {
            return None;
        }
        let title = run
            .get("display_title")
            .and_then(serde_json::Value::as_str)?;
        if title != wanted {
            return None;
        }
        if run.get("status").and_then(serde_json::Value::as_str)? != "completed" {
            return None;
        }
        Some(
            run.get("conclusion")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-")
                .to_owned(),
        )
    })
}

/// A conclusion token, as the lap's three-valued reading of it.
///
/// A CLOSED VOCABULARY, and `failure` is the only one that is a verdict about the
/// branch. `skipped` joins `success` because the bot ran and did not refuse;
/// everything else — `cancelled`, `timed_out`, `startup_failure`, `stale`,
/// `action_required` — is the bot not deciding, which is not the branch's fault
/// and must not stop the landing.
fn grade(conclusion: &str) -> Answer {
    match conclusion {
        "success" | "skipped" => Answer::Accepted,
        "failure" => Answer::Refused,
        other => Answer::Unknown(other.to_owned()),
    }
}

/// One REST call, or `None` where the forge could not be reached.
///
/// **IN PROCESS, over [`crate::rest`].** This was a `gh` spawn annotated
/// `#[expect(clippy::disallowed_types)]` on the claim that the crate carries no
/// HTTP client that resolves a forge credential. It does — `fetch.rs`, vendored
/// under CLOUD-745 — and `lease.rs` was already using it with a bearer header.
/// Every one of the four spawns CLOUD-1338 removed carried that same sentence.
///
/// `None` rather than an error, for [`crate::main_watch::read`]'s reason: every
/// failure to reach the forge is a could-not-look the caller's own loop must
/// survive.
fn run(path: &str) -> Option<String> {
    crate::rest::get(path, None).map(|answer| answer.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_names_the_comment_rather_than_the_pull_request_alone() {
        // Two laps of ONE pull request must not share a key, which is the whole
        // reason the comment id is in it.
        assert_ne!(key("42", "1001"), key("42", "1002"));
        assert_eq!(key("42", "1001"), "fast-forward #42 @1001");
    }

    #[test]
    fn a_numeric_comment_id_is_read_as_readily_as_a_string_one() {
        // The forge sends a number. A string-only read answers `None` over a good
        // response, and the lap then reports a comment it DID create as refused.
        assert_eq!(comment_id(r#"{"id": 1001}"#), Some(String::from("1001")));
        assert_eq!(comment_id(r#"{"id": "1001"}"#), Some(String::from("1001")));
        assert_eq!(comment_id(r#"{"nothing": true}"#), None);
    }

    #[test]
    fn the_window_is_enforced_client_side_and_not_only_by_the_query() {
        // The server-side `created` bound is an optimisation; this is the fence.
        // A run carrying the right key from BEFORE the stamp is an earlier lap of
        // this same pull request, and reading it is the livelock.
        let runs = vec![serde_json::json!({
            "created_at": "2026-09-04T00:00:00Z",
            "display_title": "fast-forward #42 @1001",
            "status": "completed",
            "conclusion": "failure",
        })];
        assert_eq!(
            concluded(&runs, "2026-09-04T01:00:00Z", "fast-forward #42 @1001"),
            None,
            "a run predating the stamp is an earlier lap, never this one's verdict"
        );
        assert_eq!(
            concluded(&runs, "2026-09-03T23:00:00Z", "fast-forward #42 @1001"),
            Some(String::from("failure")),
            "the same run inside the window is this lap's answer"
        );
    }

    #[test]
    fn a_stranger_s_run_in_the_same_window_is_not_this_lap_s_answer() {
        // The measured failure: ~400 runs in thirty minutes, 243 refusals, all
        // attached to trunk's tip. Only the key tells them apart.
        let runs = vec![serde_json::json!({
            "created_at": "2026-09-04T02:00:00Z",
            "display_title": "fast-forward #99 @2002",
            "status": "completed",
            "conclusion": "failure",
        })];
        assert_eq!(
            concluded(&runs, "2026-09-04T01:00:00Z", "fast-forward #42 @1001"),
            None
        );
    }

    #[test]
    fn an_incomplete_run_is_not_yet_an_answer() {
        let runs = vec![serde_json::json!({
            "created_at": "2026-09-04T02:00:00Z",
            "display_title": "fast-forward #42 @1001",
            "status": "in_progress",
            "conclusion": serde_json::Value::Null,
        })];
        assert_eq!(
            concluded(&runs, "2026-09-04T01:00:00Z", "fast-forward #42 @1001"),
            None
        );
    }

    #[test]
    fn only_failure_is_a_verdict_about_the_branch() {
        assert_eq!(grade("success"), Answer::Accepted);
        assert_eq!(grade("skipped"), Answer::Accepted);
        assert_eq!(grade("failure"), Answer::Refused);
        for token in ["cancelled", "timed_out", "startup_failure", "stale"] {
            assert_eq!(
                grade(token),
                Answer::Unknown(token.to_owned()),
                "{token} is the bot not deciding, which is not the branch's fault"
            );
        }
    }

    #[test]
    fn the_answer_request_carries_both_the_window_and_the_event_filter() {
        let ask = Ask {
            repo: String::from("o/r"),
            pr: String::from("42"),
            workflow: String::from("land.yml"),
        };
        let url = answer_request(&ask, "2026-09-04T01:00:00Z", 3);
        assert!(
            !url.starts_with('/'),
            "API-relative, never rooted — a leading slash is a 404 that reads as \
             could-not-look: {url}"
        );
        assert!(url.contains("event=issue_comment"), "got {url}");
        assert!(url.contains("page=3"), "got {url}");
        assert!(url.contains("created=%3E%3D2026-09-04T01"), "got {url}");
    }
}
