//! Parallel-session dispatch, cleared by receipt (CLOUD-1978).
//!
//! # The owner's ruling this implements
//!
//! Dispatch prompts are drafted, then put to the owner as a bundle through the
//! host's question tool. A rejection is a request to improve the prompts or to
//! wait — never a permanent refusal. Once a prompt has BOTH a valid-prompt
//! receipt and a human-approval receipt, starting or steering a sibling session
//! with exactly that prompt is pre-approved in auto mode, so the host does not
//! stop the owner a second time for a decision they already made.
//!
//! # The two receipts, and why each is keyed by the prompt's digest
//!
//! * `brief.<sha256>` — written by `batten lint brief` when the brief passes.
//! * `dispatch-approved.<sha256>` — written after the owner's answer to a
//!   question naming `brief:<sha256>` is the approve label.
//!
//! Keying both by the prompt's own bytes is what binds the grant to the prompt
//! the owner saw: a prompt edited after approval has a different digest and
//! clears nothing, so the host asks again. That is the direction every
//! could-not-look here fails in — toward the prompt, never toward a grant.
//!
//! # What never leaves here
//!
//! A digest and a boolean. Never a byte of a prompt (non-negotiable rule 4).
//!
//! # Why the answer is read from the RESULT and never from the input
//!
//! The question tool's input schema carries an `answers` member the caller can
//! fill. Reading it would let the drafting session approve its own bundle. The
//! result is what the host recorded from the human, so it is the only witness
//! this reads.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::Digest as _;

/// The receipt a passing brief lint writes.
pub const BRIEF: &str = "brief";

/// The receipt the owner's approval writes.
pub const APPROVED: &str = "dispatch-approved";

/// The answer that approves a bundle, verbatim.
///
/// A fixed label rather than a configured one: it is the engine's vocabulary
/// for its own receipt, names no consumer (rule 1), and a question offering it
/// states in words what choosing it does.
pub const APPROVE_LABEL: &str = "Approve dispatch";

/// The marker a question uses to name a prompt it asks about.
pub const TOKEN: &str = "brief:";

/// The host's question tool.
pub const QUESTION_TOOL: &str = "AskUserQuestion";

/// The session-management methods a cleared prompt pre-approves, and the
/// argument each carries its prompt in.
const METHODS: &[(&str, &str)] = &[("create_session", "prompt"), ("send_message", "message")];

/// The full-length hex SHA-256 of a prompt's bytes.
#[must_use]
pub fn digest(text: &str) -> String {
    let full = sha2::Sha256::digest(text.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in full {
        // `write!` to a `String` is infallible; discarded rather than unwrapped
        // because the library lints forbid an unwrap here.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn receipt(git_dir: &Path, name: &str, digest: &str) -> PathBuf {
    crate::minted::store_path(git_dir).join(format!("{name}.{digest}"))
}

fn write(git_dir: &Path, name: &str, digest: &str) -> std::io::Result<()> {
    let path = receipt(git_dir, name, digest);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    crate::durable::replace(path, format!("{now}\n"))
}

/// Record that this brief passed the lint.
///
/// # Errors
///
/// The store could not be written.
pub fn record_brief(git_dir: &Path, text: &str) -> std::io::Result<()> {
    write(git_dir, BRIEF, &digest(text))
}

/// Every `brief:<sha256>` a text names, in order, deduplicated.
#[must_use]
pub fn tokens(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(TOKEN) {
        let after = &rest[at + TOKEN.len()..];
        let hex: String = after.chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.len() == 64 {
            let lowered = hex.to_ascii_lowercase();
            if !found.contains(&lowered) {
                found.push(lowered);
            }
        }
        rest = after;
    }
    found
}

/// The text of one question and its options, where the tokens may appear.
fn question_text(question: &serde_json::Value) -> String {
    let mut text = question
        .get("question")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if let Some(options) = question
        .get("options")
        .and_then(serde_json::Value::as_array)
    {
        for option in options {
            for field in ["label", "description", "preview"] {
                if let Some(part) = option.get(field).and_then(serde_json::Value::as_str) {
                    text.push('\n');
                    text.push_str(part);
                }
            }
        }
    }
    text
}

/// The recorded answer to one question, from the host's result.
///
/// Two shapes are read: an `answers` object keyed by question text, and the
/// rendered sentence `"<question>"="<answer>"`. Anything else is no answer.
fn answer_to(result: &serde_json::Value, question: &str) -> Option<String> {
    if let Some(answer) = result
        .get("answers")
        .and_then(|answers| answers.get(question))
        .and_then(serde_json::Value::as_str)
    {
        return Some(answer.to_owned());
    }
    let rendered = result.as_str()?;
    let key = format!("\"{question}\"=\"");
    let start = rendered.find(&key)? + key.len();
    let end = rendered[start..].find('"')?;
    Some(rendered[start..start + end].to_owned())
}

/// The digests a completed question call approves.
///
/// A question approves the tokens it names only when the host's recorded
/// answer to it is [`APPROVE_LABEL`] exactly. Any other answer — a rejection,
/// a revision request, free text — approves nothing, which leaves the dispatch
/// waiting rather than refused.
#[must_use]
pub fn approvals(input: &serde_json::Value, result: &serde_json::Value) -> Vec<String> {
    let Some(questions) = input.get("questions").and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut approved: Vec<String> = Vec::new();
    for question in questions {
        let Some(asked) = question.get("question").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if answer_to(result, asked).as_deref().map(str::trim) != Some(APPROVE_LABEL) {
            continue;
        }
        for token in tokens(&question_text(question)) {
            if !approved.contains(&token) {
                approved.push(token);
            }
        }
    }
    approved
}

/// Record the owner's approval for every digest a question call approved.
///
/// # Errors
///
/// The store could not be written.
pub fn record_approvals(
    git_dir: &Path,
    input: &serde_json::Value,
    result: &serde_json::Value,
) -> std::io::Result<usize> {
    let approved = approvals(input, result);
    for token in &approved {
        write(git_dir, APPROVED, token)?;
    }
    Ok(approved.len())
}

/// The prompt a session-management call carries, if the call is one.
///
/// Matched on the method after the last `__`, so the server's name — which a
/// host may alias — decides nothing.
#[must_use]
pub fn prompt_of<'a>(tool: &str, arguments: &'a serde_json::Value) -> Option<&'a str> {
    if !tool.starts_with("mcp__") {
        return None;
    }
    let method = tool.rsplit("__").next()?;
    let (_, field) = METHODS.iter().find(|(name, _)| *name == method)?;
    arguments.get(*field).and_then(serde_json::Value::as_str)
}

/// Whether this prompt carries both receipts.
#[must_use]
pub fn cleared(git_dir: &Path, text: &str) -> bool {
    let digest = digest(text);
    receipt(git_dir, BRIEF, &digest).is_file() && receipt(git_dir, APPROVED, &digest).is_file()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn question(text: &str) -> serde_json::Value {
        serde_json::json!({ "questions": [{ "question": text, "options": [
            { "label": APPROVE_LABEL, "description": "run them" },
            { "label": "Revise", "description": "improve them" },
        ]}]})
    }

    #[test]
    fn only_the_approve_answer_approves() {
        let digest = digest("prompt one");
        let asked = format!("Dispatch brief:{digest}?");
        let input = question(&asked);
        let yes = serde_json::json!({ "answers": { asked.clone(): APPROVE_LABEL } });
        let no = serde_json::json!({ "answers": { asked.clone(): "Revise" } });
        assert_eq!(approvals(&input, &yes), vec![digest.clone()]);
        assert!(approvals(&input, &no).is_empty());
    }

    #[test]
    fn an_answer_the_caller_supplied_approves_nothing() {
        let digest = digest("prompt one");
        let asked = format!("Dispatch brief:{digest}?");
        let mut input = question(&asked);
        input["answers"] = serde_json::json!({ asked: APPROVE_LABEL });
        assert!(approvals(&input, &serde_json::Value::Null).is_empty());
    }

    #[test]
    fn the_rendered_answer_sentence_is_read() {
        let digest = digest("p");
        let asked = format!("Go brief:{digest}");
        let result = serde_json::json!(format!(
            "Your questions have been answered: \"{asked}\"=\"{APPROVE_LABEL}\". Continue."
        ));
        assert_eq!(approvals(&question(&asked), &result), vec![digest]);
    }

    #[test]
    fn a_short_token_is_not_a_digest() {
        assert!(tokens("brief:abc123").is_empty());
    }

    #[test]
    fn the_method_decides_and_the_server_alias_does_not() {
        let args = serde_json::json!({ "prompt": "p", "message": "m" });
        assert_eq!(
            prompt_of("mcp__Claude_Code_Remote__create_session", &args),
            Some("p")
        );
        assert_eq!(prompt_of("mcp__x__send_message", &args), Some("m"));
        assert_eq!(prompt_of("mcp__x__get_session", &args), None);
        assert_eq!(prompt_of("create_session", &args), None);
    }
}
