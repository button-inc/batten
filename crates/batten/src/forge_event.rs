//! The forge's event vocabulary, normalized into one hook event (CLOUD-2689).
//!
//! GitHub names 73 webhook events, and every one of them is a moment a
//! consumer's `[[hook.handler]]` or rule may want to fire on. This module owns
//! the VOCABULARY and the NORMALIZATION and nothing else: a catalog row per
//! event name, two normalizers (a webhook body, an Events API item) that land
//! on one [`Envelope`] with [`Event::Forge`], and the content-derived key that
//! lets every source agree an occurrence is the same one. It reads no source
//! and opens no socket; the sources and the door that dispatches are their own
//! rows.
//!
//! **The names are the forge's vocabulary, not a consumer's identifier** (rule
//! 1), the same standing git's hook names have in [`crate::hook::GIT_HOOKS`].
//!
//! **Every projected value is a token, never a body** (rule 4): the envelope
//! carries the event name, action, repository, number, SHA, ref and key, and
//! the payload itself stays out of [`Envelope::input`].

use serde::Serialize;
use serde_json::Value;

use crate::hook::{Envelope, Event, Operation};

/// One webhook event GitHub documents, with where its subject lives.
///
/// `id` and `version` are JSON pointers into the payload (a webhook body, or an
/// Events API item's `payload`), tried in order, the first present winning.
/// They name the SUBJECT of the occurrence and its revision, which is what makes
/// the dedupe key agree across sources that each carry a different envelope id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogRow {
    /// The `X-GitHub-Event` name, e.g. `pull_request`.
    pub name: &'static str,
    /// The Events API `type` that carries the same event, where one does.
    pub events_type: Option<&'static str>,
    /// Pointers to the subject's identity.
    pub id: &'static [&'static str],
    /// Pointers to the subject's revision; empty where the event has none.
    pub version: &'static [&'static str],
}

/// A row whose subject is the object at `/<object>`: its `id`, revised by its
/// `updated_at`.
macro_rules! object {
    ($name:literal, $object:literal) => {
        object!($name, $object, None)
    };
    ($name:literal, $object:literal, $events:expr) => {
        CatalogRow {
            name: $name,
            events_type: $events,
            id: &[
                concat!("/", $object, "/id"),
                concat!("/", $object, "/node_id"),
            ],
            version: &[concat!("/", $object, "/updated_at")],
        }
    };
}

/// GitHub's webhook events, one row each, in the documentation's order.
///
/// The documented list is the authority, reproduced rather than restated:
/// `hook_sources::GITHUB_WEBHOOK_EVENTS` is the committed snapshot of the page
/// and `the_ci_vocabulary_is_the_forge_catalog` holds this table to it exactly.
pub const CATALOG: &[CatalogRow] = &[
    CatalogRow {
        name: "branch_protection_configuration",
        events_type: None,
        id: &["/repository/id"],
        version: &[],
    },
    object!("branch_protection_rule", "rule"),
    object!("check_run", "check_run"),
    object!("check_suite", "check_suite"),
    CatalogRow {
        name: "code_scanning_alert",
        events_type: None,
        id: &["/alert/number"],
        version: &["/alert/updated_at"],
    },
    object!("commit_comment", "comment", Some("CommitCommentEvent")),
    CatalogRow {
        name: "create",
        events_type: Some("CreateEvent"),
        id: &["/ref"],
        version: &["/ref_type"],
    },
    CatalogRow {
        name: "custom_property",
        events_type: None,
        id: &["/definition/property_name"],
        version: &[],
    },
    CatalogRow {
        name: "custom_property_values",
        events_type: None,
        id: &["/repository/id"],
        version: &[],
    },
    CatalogRow {
        name: "delete",
        events_type: Some("DeleteEvent"),
        id: &["/ref"],
        version: &["/ref_type"],
    },
    CatalogRow {
        name: "dependabot_alert",
        events_type: None,
        id: &["/alert/number"],
        version: &["/alert/updated_at"],
    },
    object!("deploy_key", "key"),
    object!("deployment", "deployment"),
    object!("deployment_protection_rule", "deployment"),
    object!("deployment_review", "workflow_run"),
    object!("deployment_status", "deployment_status"),
    object!("discussion", "discussion", Some("DiscussionEvent")),
    object!("discussion_comment", "comment"),
    object!("fork", "forkee", Some("ForkEvent")),
    CatalogRow {
        name: "github_app_authorization",
        events_type: None,
        id: &["/sender/id"],
        version: &[],
    },
    CatalogRow {
        name: "gollum",
        events_type: Some("GollumEvent"),
        id: &["/pages/0/page_name"],
        version: &["/pages/0/sha"],
    },
    object!("installation", "installation"),
    object!("installation_repositories", "installation"),
    CatalogRow {
        name: "installation_target",
        events_type: None,
        id: &["/account/id"],
        version: &[],
    },
    object!("issue_comment", "comment", Some("IssueCommentEvent")),
    CatalogRow {
        name: "issue_dependencies",
        events_type: None,
        id: &["/blocked_issue/id", "/issue/id"],
        version: &["/blocked_issue/updated_at", "/issue/updated_at"],
    },
    CatalogRow {
        name: "issue_relates_to",
        events_type: None,
        id: &["/issue/id"],
        version: &["/issue/updated_at"],
    },
    object!("issues", "issue", Some("IssuesEvent")),
    object!("label", "label"),
    CatalogRow {
        name: "marketplace_purchase",
        events_type: None,
        id: &["/marketplace_purchase/account/id"],
        version: &["/effective_date"],
    },
    CatalogRow {
        name: "member",
        events_type: Some("MemberEvent"),
        id: &["/member/id"],
        version: &[],
    },
    CatalogRow {
        name: "membership",
        events_type: None,
        id: &["/member/id"],
        version: &["/team/id"],
    },
    CatalogRow {
        name: "merge_group",
        events_type: None,
        id: &["/merge_group/head_ref"],
        version: &["/merge_group/head_sha"],
    },
    CatalogRow {
        name: "meta",
        events_type: None,
        id: &["/hook_id"],
        version: &[],
    },
    object!("milestone", "milestone"),
    CatalogRow {
        name: "org_block",
        events_type: None,
        id: &["/blocked_user/id"],
        version: &[],
    },
    CatalogRow {
        name: "organization",
        events_type: None,
        id: &["/organization/id"],
        version: &["/membership/user/id"],
    },
    object!("package", "package"),
    CatalogRow {
        name: "page_build",
        events_type: None,
        id: &["/id"],
        version: &["/build/updated_at"],
    },
    object!(
        "personal_access_token_request",
        "personal_access_token_request"
    ),
    CatalogRow {
        name: "ping",
        events_type: None,
        id: &["/hook_id"],
        version: &[],
    },
    object!("project", "project"),
    object!("project_card", "project_card"),
    object!("project_column", "project_column"),
    CatalogRow {
        name: "public",
        events_type: Some("PublicEvent"),
        id: &["/repository/id"],
        version: &[],
    },
    object!("pull_request", "pull_request", Some("PullRequestEvent")),
    CatalogRow {
        name: "pull_request_review",
        events_type: Some("PullRequestReviewEvent"),
        id: &["/review/id", "/review/node_id"],
        version: &["/review/submitted_at"],
    },
    object!(
        "pull_request_review_comment",
        "comment",
        Some("PullRequestReviewCommentEvent")
    ),
    CatalogRow {
        name: "pull_request_review_thread",
        events_type: Some("PullRequestReviewThreadEvent"),
        id: &["/thread/node_id"],
        version: &["/action"],
    },
    // The webhook body says `after`, the Events API says `head`: one SHA.
    CatalogRow {
        name: "push",
        events_type: Some("PushEvent"),
        id: &["/ref"],
        version: &["/after", "/head"],
    },
    object!("registry_package", "registry_package"),
    CatalogRow {
        name: "release",
        events_type: Some("ReleaseEvent"),
        id: &["/release/id", "/release/node_id"],
        version: &["/release/published_at", "/release/created_at"],
    },
    object!("repository", "repository"),
    CatalogRow {
        name: "repository_advisory",
        events_type: None,
        id: &["/repository_advisory/ghsa_id"],
        version: &["/repository_advisory/updated_at"],
    },
    CatalogRow {
        name: "repository_dispatch",
        events_type: None,
        id: &["/branch"],
        version: &[],
    },
    CatalogRow {
        name: "repository_import",
        events_type: None,
        id: &["/repository/id"],
        version: &["/status"],
    },
    object!("repository_ruleset", "repository_ruleset"),
    object!("repository_vulnerability_alert", "alert"),
    CatalogRow {
        name: "secret_scanning_alert",
        events_type: None,
        id: &["/alert/number"],
        version: &["/alert/updated_at"],
    },
    CatalogRow {
        name: "secret_scanning_alert_location",
        events_type: None,
        id: &["/alert/number"],
        version: &["/location/type"],
    },
    CatalogRow {
        name: "secret_scanning_scan",
        events_type: None,
        id: &["/repository/id"],
        version: &["/completed_at", "/started_at"],
    },
    CatalogRow {
        name: "security_advisory",
        events_type: None,
        id: &["/security_advisory/ghsa_id"],
        version: &["/security_advisory/updated_at"],
    },
    CatalogRow {
        name: "security_and_analysis",
        events_type: None,
        id: &["/repository/id"],
        version: &[],
    },
    CatalogRow {
        name: "sponsorship",
        events_type: Some("SponsorshipEvent"),
        id: &["/sponsorship/node_id"],
        version: &["/sponsorship/created_at"],
    },
    CatalogRow {
        name: "star",
        events_type: None,
        id: &["/sender/id"],
        version: &["/starred_at"],
    },
    CatalogRow {
        name: "status",
        events_type: None,
        id: &["/sha"],
        version: &["/updated_at", "/id"],
    },
    object!("sub_issues", "sub_issue"),
    object!("team", "team"),
    object!("team_add", "team"),
    CatalogRow {
        name: "watch",
        events_type: Some("WatchEvent"),
        id: &["/sender/id"],
        version: &[],
    },
    CatalogRow {
        name: "workflow_dispatch",
        events_type: None,
        id: &["/workflow"],
        version: &["/ref"],
    },
    object!("workflow_job", "workflow_job"),
    object!("workflow_run", "workflow_run"),
];

/// The catalog row for a webhook event name.
#[must_use]
pub fn row(name: &str) -> Option<&'static CatalogRow> {
    CATALOG.iter().find(|row| row.name == name)
}

/// The catalog row an Events API `type` carries.
#[must_use]
pub fn row_for_events_type(events_type: &str) -> Option<&'static CatalogRow> {
    CATALOG
        .iter()
        .find(|row| row.events_type == Some(events_type))
}

/// What a forge event projects into `input.call.forge` (CLOUD-2689): tokens
/// only, never a body (rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForgeCall {
    /// The catalog name, e.g. `pull_request`.
    pub event: String,
    /// The payload's `action`, where it carries one.
    pub action: Option<String>,
    /// `owner/name`.
    pub repo: Option<String>,
    /// The issue or pull request number, where the subject has one.
    pub number: Option<u64>,
    /// The commit the occurrence is about, where one is named.
    pub sha: Option<String>,
    /// The git ref, where one is named.
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    /// The content-derived dedupe key, 64 lowercase hex.
    pub key: String,
}

/// A webhook body as an envelope, given the `X-GitHub-Event` name it arrived
/// under; `None` for a name outside the catalog.
#[must_use]
pub fn normalize_webhook(name: &str, body: &Value) -> Option<Envelope> {
    let row = row(name)?;
    let repo = text(body, &["/repository/full_name"]);
    Some(envelope(row, body, repo))
}

/// An Events API item (`GET /repos/{owner}/{repo}/events`) as an envelope;
/// `None` for a `type` no catalog row carries.
#[must_use]
pub fn normalize_events_item(item: &Value) -> Option<Envelope> {
    let row = row_for_events_type(item.get("type")?.as_str()?)?;
    let payload = item.get("payload").unwrap_or(&Value::Null);
    let repo = text(item, &["/repo/name"]);
    Some(envelope(row, payload, repo))
}

/// The first string or number at any of `pointers`, as text.
fn text(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| value.pointer(pointer))
        .and_then(|found| match found {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
}

/// The content-derived key: SHA-256 over event, action, repo, subject id and
/// subject version, NUL-separated (CLOUD-2689).
///
/// **No delivery id and no Events API id enters it**: both are source-specific,
/// so a key built from either would fire one change once per source.
//MUTANT-SUITE crates/batten/src/forge_event.rs
//MUTANT dedupe-version-first-only|s@^    let version = row.version.iter().find_map(at);$@    let version = row.version.first().and_then(at);@|dedupe_key_agrees_across_sources
fn key(row: &CatalogRow, action: Option<&str>, repo: Option<&str>, payload: &Value) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let at = |pointer: &&str| payload.pointer(pointer);
    let id = row.id.iter().find_map(at);
    let version = row.version.iter().find_map(at);
    let token = |value: Option<&Value>| match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    let mut hasher = sha2::Sha256::new();
    for part in [
        row.name.to_owned(),
        action.unwrap_or_default().to_owned(),
        repo.unwrap_or_default().to_owned(),
        token(id),
        token(version),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher
        .finalize()
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// The envelope one occurrence normalizes to.
fn envelope(row: &CatalogRow, payload: &Value, repo: Option<String>) -> Envelope {
    let action = text(payload, &["/action"]);
    let raw_tool = match &action {
        Some(action) => format!("{}.{action}", row.name),
        None => row.name.to_owned(),
    };
    let number = ["/number", "/pull_request/number", "/issue/number"]
        .iter()
        .find_map(|pointer| payload.pointer(pointer).and_then(Value::as_u64));
    let sha = text(
        payload,
        &[
            "/after",
            "/head",
            "/pull_request/head/sha",
            "/check_run/head_sha",
            "/check_suite/head_sha",
            "/workflow_run/head_sha",
            "/workflow_job/head_sha",
            "/merge_group/head_sha",
            "/sha",
        ],
    );
    let git_ref = text(payload, &["/ref", "/pull_request/head/ref"]);
    let key = key(row, action.as_deref(), repo.as_deref(), payload);
    Envelope {
        event: Event::Forge,
        raw_event: Event::Forge.as_str().to_owned(),
        raw_tool,
        operation: Operation::Other(row.name.to_owned()),
        input: Value::Null,
        result: Value::Null,
        command: String::new(),
        writes: None,
        reads: None,
        cwd: None,
        session: None,
        agent: None,
        start_source: None,
        background_ceiling: None,
        stop_active: None,
        last_message: None,
        transcript: None,
        mode: None,
        forge: Some(ForgeCall {
            event: row.name.to_owned(),
            action,
            repo,
            number,
            sha,
            git_ref,
            key,
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key_of(envelope: &Envelope) -> String {
        envelope
            .forge
            .as_ref()
            .map(|forge| forge.key.clone())
            .unwrap_or_default()
    }

    /// Fails by: one change keyed differently by its webhook and its Events API
    /// shape, two revisions of one subject keyed alike, or a delivery id
    /// entering the key.
    #[test]
    fn dedupe_key_agrees_across_sources() {
        let push_hook = normalize_webhook(
            "push",
            &json!({"ref": "refs/heads/main", "after": "abc", "repository": {"full_name": "o/r"}}),
        )
        .unwrap();
        let push_item = normalize_events_item(&json!({
            "id": "999", "type": "PushEvent", "repo": {"name": "o/r"},
            "payload": {"ref": "refs/heads/main", "head": "abc"}
        }))
        .unwrap();
        assert_eq!(key_of(&push_hook), key_of(&push_item));
        assert_eq!(key_of(&push_hook).len(), 64);

        let pr = |updated: &str, delivery: &str| {
            json!({
                "action": "opened",
                "delivery": delivery,
                "pull_request": {"id": 7, "number": 3, "updated_at": updated},
                "repository": {"full_name": "o/r"}
            })
        };
        let hook = normalize_webhook("pull_request", &pr("t1", "d1")).unwrap();
        let item = normalize_events_item(&json!({
            "id": "1", "type": "PullRequestEvent", "repo": {"name": "o/r"},
            "payload": {"action": "opened", "pull_request": {"id": 7, "number": 3, "updated_at": "t1"}}
        }))
        .unwrap();
        assert_eq!(key_of(&hook), key_of(&item));
        let revised = normalize_webhook("pull_request", &pr("t2", "d1")).unwrap();
        assert_ne!(key_of(&hook), key_of(&revised));
        let redelivered = normalize_webhook("pull_request", &pr("t1", "d2")).unwrap();
        assert_eq!(key_of(&hook), key_of(&redelivered));
        assert_eq!(hook.raw_tool, "pull_request.opened");
        assert_eq!(push_hook.raw_tool, "push");
    }

    #[test]
    fn a_name_outside_the_catalog_normalizes_to_nothing() {
        assert!(normalize_webhook("not_a_github_event", &json!({})).is_none());
        assert!(normalize_events_item(&json!({"type": "NoSuchEvent"})).is_none());
    }

    #[test]
    fn every_catalog_row_names_its_subject() {
        for row in CATALOG {
            assert!(!row.id.is_empty(), "{} names no subject id", row.name);
        }
    }
}
