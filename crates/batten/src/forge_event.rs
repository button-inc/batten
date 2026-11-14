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

/// The seen ring's size: the last this many keys (CLOUD-2690). It must cover
/// a full re-read of every source's window: the Events API returns at most 300
/// events a repository and up to three pollers plus intake can replay one, so
/// at least 1,200 keys; 4096 is the next power of two with margin. A const,
/// not `[forge]` config (rule 6).
pub const SEEN_RING_KEYS: usize = 4096;

/// The directory the ring lives in, under the git COMMON dir: a forge event
/// belongs to the repository, so a per-worktree ring would fire one event once
/// per worktree (CLOUD-2690).
pub const RING_DIR: &str = "batten-forge-events";

/// The ring file under a git common dir.
#[must_use]
pub fn ring_path(common_dir: &std::path::Path) -> std::path::PathBuf {
    common_dir.join(RING_DIR).join("seen")
}

/// Whether `key` is NEW to the ring at `ring`: false once it was dispatched.
/// A ring that does not exist yet holds nothing; one that will not read is
/// could-not-look, never "new".
///
/// # Errors
///
/// When the ring exists and cannot be read.
pub fn unseen(ring_file: &std::path::Path, key: &str) -> std::io::Result<bool> {
    let ring = read_ring(ring_file)?;
    let key = key.to_owned();
    if ring.contains(&key) {
        return Ok(false);
    }
    Ok(true)
}

/// Append `key` to the ring, keeping the last [`SEEN_RING_KEYS`], written
/// whole (a temporary file, then a rename). Called only AFTER dispatch
/// returns, so a crash replays an event rather than dropping it.
///
/// # Errors
///
/// When the ring cannot be read or written.
pub fn remember(ring_file: &std::path::Path, key: &str) -> std::io::Result<()> {
    let mut ring = read_ring(ring_file)?;
    ring.push(key.to_owned());
    let keep = ring.len().saturating_sub(SEEN_RING_KEYS);
    let text: String = ring[keep..].iter().fold(String::new(), |mut text, key| {
        text.push_str(key);
        text.push('\n');
        text
    });
    if let Some(parent) = ring_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(ring_file, text)
}

fn read_ring(ring_file: &std::path::Path) -> std::io::Result<Vec<String>> {
    match crate::fsio::read_to_string(ring_file) {
        Ok(text) => Ok(text.lines().map(str::to_owned).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// How a wake element opens: the cloud connector's PR wake shape.
const WAKE_OPEN: &str = "<event source=\"github\"";

/// The forge event a harness user-prompt-submit payload carries, as `(catalog
/// name, body)` (CLOUD-2690).
///
/// Stdin is JSON with a string `prompt` (the field Claude Code and Codex send
/// at this event), else raw text. In that text, the first element opening with
/// `<event source="github"` is the event: its `kind` attribute names it, and
/// its body is the JSON between the first `{` and the last `}` before
/// `</event>` (a connector's leading comment is skipped). A `kind` spelled
/// `<event>.<action>` names the catalog event and, where the body carries no
/// `action`, supplies it.
#[must_use]
pub fn wake_event(stdin: &str) -> Option<(String, Value)> {
    let prompt = serde_json::from_str::<Value>(stdin)
        .ok()
        .and_then(|document| {
            document
                .get("prompt")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    wake_element(prompt.as_deref().unwrap_or(stdin))
}

fn wake_element(text: &str) -> Option<(String, Value)> {
    let start = text.find(WAKE_OPEN)?;
    let (tag, element) = text[start..].split_once('>')?;
    let kind = attribute(tag, "kind")?;
    let element = &element[..element.find("</event>").unwrap_or(element.len())];
    let body = &element[element.find('{')?..=element.rfind('}')?];
    let mut body: Value = serde_json::from_str(body).ok()?;
    let (name, action) = match kind.split_once('.') {
        Some((name, action)) => (name.to_owned(), Some(action.to_owned())),
        None => (kind, None),
    };
    if let (Some(action), Some(object)) = (action, body.as_object_mut()) {
        object
            .entry("action")
            .or_insert_with(|| Value::String(action));
    }
    Some((name, body))
}

/// One `name="value"` attribute of an opening tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let open = format!("{name}=\"");
    let from = tag.find(&open)? + open.len();
    let to = tag[from..].find('"')? + from;
    Some(tag[from..to].to_owned())
}

/// What one round read (CLOUD-2693).
#[derive(Debug)]
pub enum Round {
    /// No declared source was available: could-not-look, never "no events".
    CouldNotLook,
    /// The events the first available source produced, the cursor to save
    /// once they are dispatched, and where it is saved.
    Read {
        /// The envelopes to dispatch, in source order.
        events: Vec<Envelope>,
        /// The source's cursor after this round.
        cursor: Cursor,
        /// Where the cursor is saved.
        cursor_path: std::path::PathBuf,
    },
}

/// A source's position (CLOUD-2693): `last_id` for an `events` source, the
/// tracked values per key for a `snapshot` one.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    /// The largest numeric Events API id dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_id: Option<String>,
    /// key -> pointer -> value, as last seen.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tracked: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

impl Cursor {
    /// Whether an Events API item id is past this cursor. A non-numeric id is
    /// always read; the ring absorbs a repeat.
    #[must_use]
    pub fn is_newer(&self, id: &str) -> bool {
        match (
            self.last_id
                .as_deref()
                .and_then(|last| last.parse::<u128>().ok()),
            id.parse::<u128>(),
        ) {
            (Some(last), Ok(id)) => id > last,
            _ => true,
        }
    }

    fn advance(&mut self, id: &str) {
        if self.is_newer(id) && id.parse::<u128>().is_ok() {
            self.last_id = Some(id.to_owned());
        }
    }
}

/// A source's cursor file, beside the ring.
#[must_use]
pub fn cursor_path(common_dir: &std::path::Path, source: &str) -> std::path::PathBuf {
    common_dir.join(RING_DIR).join(format!("{source}.json"))
}

fn read_cursor(path: &std::path::Path) -> std::io::Result<Option<Cursor>> {
    match crate::fsio::read_to_string(path) {
        Ok(text) => Ok(serde_json::from_str(&text).ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Save a cursor, written whole. Called only after the round's events are
/// dispatched, so a crash replays (and the ring absorbs it) rather than drops.
///
/// # Errors
///
/// When the cursor cannot be written.
pub fn write_cursor(path: &std::path::Path, cursor: &Cursor) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(path, serde_json::to_string(cursor).unwrap_or_default())
}

/// The repository a round reads, as `(owner, repo)`.
pub type Slug = (String, String);

/// What a round needs from its caller.
#[derive(Debug)]
pub struct RoundInput<'a> {
    /// The repository root a command runs in and an MCP wiring resolves from.
    pub root: &'a std::path::Path,
    /// The git common dir the cursors live under.
    pub common_dir: &'a std::path::Path,
    /// The committed `[mcp]` table, where one is declared.
    pub mcp: Option<&'a crate::mcp::McpConfig>,
    /// The forge remote, where one resolves.
    pub slug: Option<&'a Slug>,
}

/// Read one round from the first available source (CLOUD-2693), naming each
/// skipped one on `err` as `forge poll: source <id> absent`.
///
/// # Errors
///
/// A cursor that cannot be read, or a stream that will not take a line.
pub fn read_round(
    forge: &crate::rest::Forge,
    input: &RoundInput<'_>,
    err: &mut dyn std::io::Write,
) -> crate::Result<Round> {
    for source in &forge.source {
        if !available(source, input) {
            writeln!(err, "forge poll: source {} absent", source.id)?;
            continue;
        }
        let Some(document) = read_document(source, input) else {
            writeln!(err, "forge poll: source {} could not be read", source.id)?;
            return Ok(Round::CouldNotLook);
        };
        let cursor_path = cursor_path(input.common_dir, &source.id);
        let cursor = read_cursor(&cursor_path)?;
        let items = document.as_array().cloned().unwrap_or_default();
        let (events, cursor) = match source.decode {
            crate::rest::Decode::Events => decode_events(&items, cursor),
            crate::rest::Decode::Snapshot => decode_snapshot(source, &items, cursor, input.slug),
        };
        return Ok(Round::Read {
            events,
            cursor,
            cursor_path,
        });
    }
    Ok(Round::CouldNotLook)
}

fn available(source: &crate::rest::Source, input: &RoundInput<'_>) -> bool {
    use crate::rest::SourceKind::{Command, Mcp};
    let answers =
        |mcp: &crate::mcp::McpConfig| crate::mcp::answers(mcp, input.root, &source.server);
    match source.kind {
        Mcp => input.mcp.is_some_and(answers),
        Command => {
            !source.available.is_empty()
                && crate::exec::piped_argv(
                    input.root,
                    &source.available,
                    "",
                    crate::exec::Diagnostics::Drop,
                    &[],
                )
                .is_some_and(|(code, _)| code == 0)
        }
    }
}

/// `{owner}` and `{repo}` filled into one word; `None` where the word needs a
/// part the remote did not give.
fn fill_word(word: &str, slug: Option<&Slug>) -> Option<String> {
    let mut filled = word.to_owned();
    for (name, part) in [
        ("{owner}", slug.map(|(owner, _)| owner.as_str())),
        ("{repo}", slug.map(|(_, repo)| repo.as_str())),
    ] {
        if filled.contains(name) {
            filled = filled.replace(name, part?);
        }
    }
    Some(filled)
}

fn read_document(source: &crate::rest::Source, input: &RoundInput<'_>) -> Option<Value> {
    use crate::rest::SourceKind::{Command, Mcp};
    match source.kind {
        Mcp => {
            let wiring = crate::mcp::wiring(input.mcp?, input.root, &source.server).ok()?;
            let template = if source.arguments.is_empty() {
                "{}"
            } else {
                source.arguments.as_str()
            };
            let arguments = crate::unsubscribe::fill_arguments(template, 0, "", input.slug)?;
            let params = serde_json::json!({"name": source.method, "arguments": arguments});
            let result = crate::mcp::dispatch(&wiring, "tools/call", &params).ok()?;
            Some(crate::mcp::payload(&result).value)
        }
        Command => {
            let argv = source
                .run
                .iter()
                .map(|word| fill_word(word, input.slug))
                .collect::<Option<Vec<_>>>()?;
            let (code, stdout) = crate::exec::piped_argv(
                input.root,
                &argv,
                "",
                crate::exec::Diagnostics::Drop,
                &[],
            )?;
            if code != 0 {
                return None;
            }
            serde_json::from_str(&stdout).ok()
        }
    }
}

fn decode_events(items: &[Value], cursor: Option<Cursor>) -> (Vec<Envelope>, Cursor) {
    let mut cursor = cursor.unwrap_or_default();
    let start = cursor.clone();
    let mut events = Vec::new();
    for item in items {
        let item_id = text(item, &["/id"]).unwrap_or_default();
        if !start.is_newer(&item_id) {
            continue;
        }
        if let Some(envelope) = normalize_events_item(item) {
            events.push(envelope);
        }
        cursor.advance(&item_id);
    }
    (events, cursor)
}

fn decode_snapshot(
    source: &crate::rest::Source,
    items: &[Value],
    cursor: Option<Cursor>,
    slug: Option<&Slug>,
) -> (Vec<Envelope>, Cursor) {
    let baseline = cursor.is_none();
    let previous = cursor.unwrap_or_default();
    let mut next = Cursor {
        last_id: previous.last_id.clone(),
        tracked: std::collections::BTreeMap::new(),
    };
    let mut events = Vec::new();
    for item in items {
        let Some(key) = text(item, &[source.key.as_str()]) else {
            continue;
        };
        let values: std::collections::BTreeMap<String, String> = source
            .track
            .iter()
            .map(|track| {
                let value = text(item, &[track.pointer.as_str()]).unwrap_or_default();
                (track.pointer.clone(), value)
            })
            .collect();
        let actions: Vec<String> = match previous.tracked.get(&key) {
            Some(seen) => source
                .track
                .iter()
                .filter(|track| seen.get(&track.pointer) != values.get(&track.pointer))
                .filter_map(|track| {
                    track.action.clone().or_else(|| {
                        let value = values.get(&track.pointer)?;
                        track.values.get(value).cloned()
                    })
                })
                .collect(),
            None if !baseline => source.new.iter().cloned().collect(),
            None => Vec::new(),
        };
        for action in actions {
            if let Some(envelope) = snapshot_event(source, item, &key, &action, slug) {
                events.push(envelope);
            }
        }
        next.tracked.insert(key, values);
    }
    (events, next)
}

/// A webhook-shaped body for one snapshot change, normalized through the
/// catalog so its key comes from the catalog's pointers. An object without an
/// `id` takes its `key` value as one.
fn snapshot_event(
    source: &crate::rest::Source,
    item: &Value,
    key: &str,
    action: &str,
    slug: Option<&Slug>,
) -> Option<Envelope> {
    let mut object = item.clone();
    if let Some(map) = object.as_object_mut() {
        map.entry("id")
            .or_insert_with(|| Value::String(key.to_owned()));
    }
    let mut body = serde_json::Map::new();
    body.insert("action".to_owned(), Value::String(action.to_owned()));
    body.insert(source.event.clone(), object);
    if let Some((owner, repo)) = slug {
        body.insert(
            "repository".to_owned(),
            serde_json::json!({"full_name": format!("{owner}/{repo}")}),
        );
    }
    normalize_webhook(&source.event, &Value::Object(body))
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

    /// Fails by: a read error other than an absent file taken as an empty ring
    /// or no cursor.
    #[test]
    fn only_an_absent_ring_or_cursor_reads_as_empty() {
        let dir = crate::scratch::scratch("forge-event-read-errors");
        assert!(read_ring(&dir.join("absent")).unwrap().is_empty());
        assert!(read_cursor(&dir.join("absent")).unwrap().is_none());
        assert!(read_ring(&dir).is_err());
        assert!(read_cursor(&dir).is_err());
    }
}
