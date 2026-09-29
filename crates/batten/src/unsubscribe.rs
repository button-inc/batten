//! A session's webhook subscription to a pull request: dropped, attested, and
//! read for a module (CLOUD-518, CLOUD-790; retired off `[tasks.pr-unsubscribed]`
//! under CLOUD-843).
//!
//! # Three arms, one receipt
//!
//! * **drop** is the actor. It asks the host's endpoint to unsubscribe and mints a
//!   receipt only for an ACCEPTED call. It fails open everywhere: every path it
//!   cannot establish says why on stdout and exits `0` without a receipt, because
//!   an actor that could refuse would put a second way to wedge a landing in
//!   front of the gate it exists to satisfy.
//! * **record** mints the same receipt from the agent's own tool answer on stdin,
//!   which must name this pull request.
//! * **check** records the reading — the session, the pull request, and whether
//!   this session holds a receipt for it — as the family a consumer module
//!   decides over. The engine never decides here.
//!
//! # Everything the host is, the consumer declares (non-negotiable rule 1)
//!
//! Which environment variable carries the session id, which carries the PATH of
//! the credential file, the endpoint's address (with `{session}` where the id
//! goes), the tool's name and the record family are all arguments. The engine
//! knows a JSON-RPC `tools/call` and a receipt's five lines, nothing else.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! No byte of an answer is printed or stored: the receipt holds a 12-hex digest
//! and a length, and the credential is read into a header and nowhere else.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::UsageError;
use crate::exit::ExitCode;

/// Which of the three arms runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Ask the endpoint to unsubscribe, and attest an accepted call.
    Drop,
    /// Attest the agent's own tool answer, read on stdin.
    Record,
    /// Record the reading a module decides over.
    Check,
}

impl Verb {
    /// The arm a positional names.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for any word but `drop`, `record` or `check`.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "drop" => Ok(Self::Drop),
            "record" => Ok(Self::Record),
            "check" => Ok(Self::Check),
            _ => Err(UsageError::raise(
                "pr unsubscribed: the verb is one of `drop`, `record` or `check`",
            )),
        }
    }
}

/// What the consumer declares about its host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// The NAME of the environment variable holding this host's session id.
    pub session_env: String,
    /// The NAME of the environment variable holding the credential file's path.
    pub token_env: Option<String>,
    /// The endpoint, with `{session}` where the session id goes.
    pub endpoint: Option<String>,
    /// The tool the endpoint is asked to call.
    pub tool: Option<String>,
    /// The record family, and the receipts' filename prefix.
    pub family: String,
}

/// A pull request number, or a usage error.
///
/// # Errors
///
/// A [`UsageError`] for anything but a whole number.
pub fn pr_number(raw: &str) -> Result<u64> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UsageError::raise(
            "pr unsubscribed: the pull request is not a number",
        ));
    }
    raw.parse::<u64>()
        .map_err(|_| UsageError::raise("pr unsubscribed: the pull request is not a number"))
}

/// This host's session, or `None` where there is none.
///
/// NO SESSION MEANS NO SUBSCRIPTION — a local clone, a CI runner — so every arm
/// reads its absence as "nothing to do", never as a refusal. An id that is not
/// one path component would put a receipt outside the store, so it reads as none.
#[must_use]
pub fn session(host: &Host) -> Option<String> {
    let value = std::env::var(&host.session_env).ok()?;
    let value = value.trim();
    let unsafe_id = value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\', '\0'])
        || value.chars().any(char::is_whitespace);
    (!unsafe_id).then(|| value.to_owned())
}

/// Where this session's receipt for `pr` lives.
fn receipt_path(git_dir: &Path, host: &Host, session: &str, pr: u64) -> PathBuf {
    git_dir
        .join("batten-receipts")
        .join(format!("{}.{session}.{pr}", host.family))
}

/// Whether an endpoint's answer attests an ACCEPTED call.
///
/// A receipt must attest an accepted call, not an attempted one: a `200` with a
/// body, and no MCP error carried inside it, since a tool that refused answers
/// `200` with `isError`.
#[must_use]
pub fn accepted(status: u16, body: &[u8]) -> bool {
    if status != 200 {
        return false;
    }
    if body.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(body);
    let tool_refused = text.contains("\"isError\":true") || text.contains("\"isError\": true");
    !tool_refused
}

/// Whether an answer names this pull request, as `#<pr>`.
///
/// It deliberately judges nothing else: matching an answer's phrasing would be a
/// gate estimating an outcome from wording (non-negotiable rule 3).
#[must_use]
pub fn names_pr(answer: &str, pr: u64) -> bool {
    answer.contains(&format!("#{pr}"))
}

/// Mint this session's receipt for `pr`: five pointer lines, never the answer.
///
/// # Errors
///
/// An internal error when the store cannot be written.
pub fn mint(
    git_dir: &Path,
    host: &Host,
    session: &str,
    pr: u64,
    answer: &[u8],
    via: &str,
) -> Result<String> {
    let digest: String = crate::receipt::hex_sha256(answer)
        .chars()
        .take(12)
        .collect();
    let path = receipt_path(git_dir, host, session, pr);
    if let Some(store) = path.parent() {
        std::fs::create_dir_all(store)?;
    }
    let body = format!(
        "pr {pr}\nsession {session}\nvia {via}\nanswer-sha256 {digest}\nanswer-bytes {}\n",
        answer.len()
    );
    crate::durable::replace(&path, body)?;
    Ok(digest)
}

/// The reading a module decides over, as the record family's body.
#[must_use]
pub fn reading(git_dir: &Path, host: &Host, pr: u64) -> String {
    let session = session(host);
    let receipt = match &session {
        Some(session) if receipt_path(git_dir, host, session, pr).is_file() => "present",
        _ => "absent",
    };
    let session = session.as_deref().unwrap_or("-");
    format!("session\t{session}\npr\t{pr}\nreceipt\t{receipt}\n")
}

/// Say why nothing was dropped, and pass: the manual path is unaffected.
fn give_up(out: &mut dyn Write, pr: u64, why: &str) -> Result<ExitCode> {
    writeln!(
        out,
        "pr unsubscribed: could not drop #{pr}'s webhook subscription ({why}) — the manual path is unaffected"
    )?;
    Ok(ExitCode::Success)
}

/// `owner` and `repo` from a slug, or `None` for a shape not to guess about.
fn owner_repo(slug: &str) -> Option<(String, String)> {
    let (owner, repo) = slug.trim().split_once('/')?;
    let tidy = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    (tidy(owner) && tidy(repo)).then(|| (owner.to_owned(), repo.to_owned()))
}

/// The actor: ask the endpoint to unsubscribe, and attest an accepted call.
///
/// # Errors
///
/// Only an output channel that cannot be written. Every failure to establish an
/// input or to reach the endpoint is a `give_up` at exit `0`.
pub fn drop_subscription(
    git_dir: &Path,
    host: &Host,
    pr: u64,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let Some(session) = session(host) else {
        return give_up(out, pr, "no session on this host");
    };
    let Some(token_file) = host.token_env.as_deref().and_then(std::env::var_os) else {
        return give_up(out, pr, "no credential file declared");
    };
    let Ok(token) = std::fs::read_to_string(&token_file) else {
        return give_up(out, pr, "the credential file will not read");
    };
    let token = token.trim_end();
    let (Some(endpoint), Some(tool)) = (host.endpoint.as_deref(), host.tool.as_deref()) else {
        return give_up(out, pr, "no endpoint or tool declared");
    };
    let Some((owner, repo)) = crate::repo_slug(Path::new("."))
        .as_deref()
        .and_then(owner_repo)
    else {
        return give_up(out, pr, "no owner/repo for this clone");
    };
    let url = endpoint.replace("{session}", &session);
    let document = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"owner": owner, "repo": repo, "pullNumber": pr},
        },
    });
    let Ok(bytes) = serde_json::to_vec(&document) else {
        return give_up(out, pr, "the request will not render");
    };
    let headers = vec![
        ("authorization".to_owned(), format!("Bearer {token}")),
        ("content-type".to_owned(), "application/json".to_owned()),
        (
            "accept".to_owned(),
            "application/json, text/event-stream".to_owned(),
        ),
    ];
    let call = crate::fetch::Call {
        url: &url,
        headers: &headers,
        body: Some(bytes.as_slice()),
        patch: false,
        direct: false,
    };
    let Ok(answers) = crate::fetch::spend(&[call]) else {
        return give_up(out, pr, "the endpoint could not be reached");
    };
    let Some(answer) = answers.first() else {
        return give_up(out, pr, "the endpoint returned no answer");
    };
    if !accepted(answer.status, &answer.body) {
        return give_up(out, pr, &format!("http {}", answer.status));
    }
    let Ok(digest) = mint(git_dir, host, &session, pr, &answer.body, "endpoint") else {
        return give_up(out, pr, "cannot write the receipt");
    };
    writeln!(
        out,
        "pr unsubscribed: recorded the drop of #{pr}'s webhook subscription via endpoint (answer {digest})"
    )?;
    Ok(ExitCode::Success)
}

/// Attest the agent's own tool answer.
///
/// # Errors
///
/// An internal error when the store cannot be written or a channel refuses.
pub fn record(
    git_dir: &Path,
    host: &Host,
    pr: u64,
    answer: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // Off harness this is a caller doing the right thing where there was nothing
    // to do: silent success, because a gate that scolds the honest case teaches
    // its own bypass.
    let Some(session) = session(host) else {
        writeln!(
            out,
            "pr unsubscribed: no session on this host, so no subscription — nothing to record for #{pr}"
        )?;
        return Ok(ExitCode::Success);
    };
    // COULD NOT LOOK, never a refusal: an empty pipe is a caller that never
    // reached the tool.
    if answer.trim().is_empty() {
        writeln!(
            err,
            "batten: pr unsubscribed: stdin is empty; pipe the tool's answer for #{pr}"
        )?;
        return Ok(ExitCode::Internal);
    }
    // THE ANSWER MUST NAME THIS PULL REQUEST, which is what stops the honest
    // error this exists for: pasting the previous PR's answer on a branch name
    // the harness reuses for a whole engagement.
    if !names_pr(answer, pr) {
        writeln!(
            err,
            "batten: pr unsubscribed: that answer does not name #{pr}, so it is not evidence about this pull request"
        )?;
        return Ok(ExitCode::Usage);
    }
    let digest = mint(git_dir, host, &session, pr, answer.as_bytes(), "agent")?;
    writeln!(
        out,
        "pr unsubscribed: recorded the drop of #{pr}'s webhook subscription via agent (answer {digest})"
    )?;
    Ok(ExitCode::Success)
}

//MUTANT-SUITE crates/batten/src/unsubscribe.rs
//MUTANT drop-mints-on-any-status|s@^    if status != 200 {$@    if false {@|a_refused_or_errored_call_is_not_accepted
//MUTANT tool-error-ignored|s@^    !tool_refused$@    true@|a_refused_or_errored_call_is_not_accepted
//MUTANT any-answer-names-the-pr|s@^    answer.contains(&format!("#{pr}"))$@    true@|an_answer_must_name_this_pr
//MUTANT receipt-ignores-session|s@^        .join(format!("{}.{session}.{pr}", host.family))$@        .join(format!("{}.{pr}", host.family))@|a_receipt_is_this_sessions_for_this_pr

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_or_errored_call_is_not_accepted() {
        assert!(accepted(200, br#"{"result":{"content":[]}}"#));
        assert!(!accepted(403, b"{}"));
        assert!(!accepted(200, b""));
        assert!(!accepted(200, br#"{"result":{"isError":true}}"#));
        assert!(!accepted(200, br#"{"result":{"isError": true}}"#));
    }

    #[test]
    fn an_answer_must_name_this_pr() {
        assert!(names_pr("No active subscription for o/r#489.", 489));
        assert!(!names_pr("No active subscription for o/r#490.", 489));
    }

    #[test]
    fn a_pull_request_is_a_number() {
        assert_eq!(pr_number("489").unwrap(), 489);
        assert!(pr_number("abc").is_err());
        assert!(pr_number("").is_err());
        assert!(Verb::parse("frob").is_err());
    }

    #[test]
    fn a_receipt_is_this_sessions_for_this_pr() {
        let dir = std::env::temp_dir().join(format!("batten-unsubscribe-{}", std::process::id()));
        let host = Host {
            session_env: "BATTEN_UNSUBSCRIBE_UNIT_NEVER_SET".to_owned(),
            family: "pr-unsubscribed".to_owned(),
            ..Host::default()
        };
        let digest = mint(&dir, &host, "cse_a", 489, b"secret answer", "agent").unwrap();
        assert_eq!(digest.len(), 12);
        let stored =
            std::fs::read_to_string(dir.join("batten-receipts/pr-unsubscribed.cse_a.489")).unwrap();
        assert!(stored.starts_with("pr 489\nsession cse_a\nvia agent\n"));
        assert!(!stored.contains("secret"), "never the answer");
        assert!(receipt_path(&dir, &host, "cse_a", 489).is_file());
        assert!(!receipt_path(&dir, &host, "cse_b", 489).is_file());
        assert!(!receipt_path(&dir, &host, "cse_a", 490).is_file());
        // The session variable is unset here, so the reading has no session.
        assert_eq!(
            reading(&dir, &host, 489),
            "session\t-\npr\t489\nreceipt\tabsent\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_slug_is_owner_and_repo_or_nothing() {
        assert_eq!(owner_repo("o/r"), Some(("o".to_owned(), "r".to_owned())));
        assert_eq!(owner_repo("o/r/x"), None);
        assert_eq!(owner_repo("/r"), None);
        assert_eq!(owner_repo("o"), None);
    }
}
