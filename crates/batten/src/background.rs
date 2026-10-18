//! A backgrounded call, followed to its output (CLOUD-2214).
//!
//! # What the host hands back, measured
//!
//! A backgrounded `Bash` call's post-tool result is `{"stdout": "", "stderr":
//! "", "interrupted": false, "isImage": false, "noOutputExpected": false,
//! "backgroundTaskId": "<id>"}` — read from a live Claude Code transcript on PR
//! #1132. The command has not run yet, so there is nothing a recorder can read,
//! and `pr-body-closes` read the empty `stdout` as a body closing nothing: three
//! fetches of a body carrying 24 closing keys each recorded `closes 0`.
//!
//! Refusing such a result only turns that false measurement into could-not-look,
//! and could-not-look never satisfies the closes exemption. Where every runner
//! call is backgrounded, which this repository's `AGENTS.md` requires, the gate
//! would then refuse every row a pull request closes, forever.
//!
//! # So the result is followed, not refused
//!
//! The result names its task. When the task exits the host appends a
//! notification to the transcript naming the same id, the file the output went
//! to, and how it ended:
//!
//! ```text
//! <task-notification>
//! <task-id>bwd83r7a0</task-id>
//! <output-file>/tmp/…/tasks/bwd83r7a0.output</output-file>
//! <status>completed</status>
//! …
//! ```
//!
//! [`defer`] keeps the call's tool and input; [`resolve`], run on every later
//! hook invocation, finds the notification and hands back that file's bytes as
//! the `stdout` the call would have returned in the foreground. A task that did
//! not complete, or whose file cannot be read, yields nothing — could-not-look,
//! never a guessed record.
//!
//! # Bounded
//!
//! An entry no notification ever answers — a host that writes none, a session
//! that ended — is dropped after [`STALE_AFTER`] rather than read forever.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where pending entries live, under the repository's git directory beside the
/// records they will become.
const DIR: &str = "batten-pending";

/// How long an unanswered entry is kept, in seconds.
pub const STALE_AFTER: u64 = 24 * 60 * 60;

/// A call whose result named a background task instead of its output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// The tool name as the host spelled it.
    pub tool: String,
    /// The call's input, which the recorder's selectors read.
    pub input: serde_json::Value,
    /// When it was deferred, in Unix seconds.
    pub at: u64,
}

/// The task id a result names, when it names one.
///
/// Only an id that can be a file name is accepted: it becomes one in [`defer`],
/// and a host value carrying a separator must not choose where that file goes.
#[must_use]
pub fn task_id(result: &serde_json::Value) -> Option<&str> {
    result.get("backgroundTaskId")?.as_str().filter(|id| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Keep `tool` and `input` until task `id` exits.
///
/// # Errors
///
/// The directory or file could not be written.
pub fn defer(git_dir: &Path, id: &str, pending: &Pending) -> std::io::Result<()> {
    let dir = git_dir.join(DIR);
    std::fs::create_dir_all(&dir)?;
    let body = serde_json::to_vec(pending).map_err(std::io::Error::other)?;
    crate::durable::replace(dir.join(format!("{id}.json")), body)
}

/// How a task ended, as its notification says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The file its output was written to.
    pub output: PathBuf,
    /// Whether it completed, rather than failed or was stopped.
    pub completed: bool,
}

/// The exits `transcript` reports for the ids in `wanted`.
///
/// A line that does not decode is skipped, never fatal: the host appends while
/// this reads, so the last line may be half-written, and one unreadable line must
/// not hide every exit before it.
#[must_use]
pub fn exits<S: std::hash::BuildHasher>(
    transcript: &str,
    wanted: &HashSet<String, S>,
) -> HashMap<String, Exit> {
    let mut found = HashMap::new();
    for line in transcript.lines() {
        if !line.contains("<task-notification>") {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if entry.get("type").and_then(serde_json::Value::as_str) != Some("user") {
            continue;
        }
        let Some(text) = message_text(&entry) else {
            continue;
        };
        let (Some(id), Some(output), Some(status)) = (
            tag(&text, "task-id"),
            tag(&text, "output-file"),
            tag(&text, "status"),
        ) else {
            continue;
        };
        if wanted.contains(id) {
            found.insert(
                id.to_owned(),
                Exit {
                    output: PathBuf::from(output),
                    completed: status == "completed",
                },
            );
        }
    }
    found
}

/// A user entry's message text, whether the host wrote a string or text blocks.
fn message_text(entry: &serde_json::Value) -> Option<String> {
    let content = entry.get("message")?.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text.to_owned());
    }
    let blocks = content.as_array()?;
    Some(
        blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The text between `<name>` and `</name>`, trimmed.
fn tag<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find(&close)?;
    Some(text[start..end].trim())
}

/// Every pending call whose task has exited, with the output it produced.
///
/// An answered entry is removed whether or not its output could be read: the
/// task has ended, so waiting longer cannot change the answer. An unanswered one
/// is kept until [`STALE_AFTER`].
//MUTANT-SUITE crates/batten/tests/it/recorder_background.rs
//MUTANT background-output-unfollowed|s@^                    resolved.push((pending, text));$@@|a_backgrounded_fetch_records_its_output_when_the_task_exits
#[must_use]
pub fn resolve(git_dir: &Path, transcript: Option<&Path>, now: u64) -> Vec<(Pending, String)> {
    let dir = git_dir.join(DIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut waiting = HashMap::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(id) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let Some(pending) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Pending>(&bytes).ok())
        else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        waiting.insert(id, (path, pending));
    }
    if waiting.is_empty() {
        return Vec::new();
    }
    let wanted: HashSet<String> = waiting.keys().cloned().collect();
    let answered = transcript
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| exits(&text, &wanted))
        .unwrap_or_default();
    let mut resolved = Vec::new();
    for (id, (path, pending)) in waiting {
        match answered.get(&id) {
            Some(exit) => {
                let _ = std::fs::remove_file(&path);
                if exit.completed
                    && let Ok(text) = std::fs::read_to_string(&exit.output)
                {
                    resolved.push((pending, text));
                }
            }
            None if now.saturating_sub(pending.at) > STALE_AFTER => {
                let _ = std::fs::remove_file(&path);
            }
            None => {}
        }
    }
    resolved
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn notification(id: &str, output: &str, status: &str) -> String {
        serde_json::json!({
            "type": "user",
            "origin": {"kind": "task-notification"},
            "message": {"role": "user", "content": format!(
                "<task-notification>\n<task-id>{id}</task-id>\n<output-file>{output}</output-file>\n<status>{status}</status>\n</task-notification>"
            )},
        })
        .to_string()
    }

    #[test]
    fn a_task_id_that_could_name_another_path_is_refused() {
        assert_eq!(
            task_id(&serde_json::json!({"backgroundTaskId": "b1x"})),
            Some("b1x")
        );
        assert_eq!(
            task_id(&serde_json::json!({"backgroundTaskId": "../x"})),
            None
        );
        assert_eq!(task_id(&serde_json::json!({"stdout": "x"})), None);
        assert_eq!(
            task_id(&serde_json::json!({"backgroundTaskId": "b-1_x"})),
            Some("b-1_x")
        );
    }

    /// Fails by: an unanswered entry dropped a second early or kept past a day.
    #[test]
    fn an_unanswered_entry_is_kept_for_a_day_and_dropped_after() {
        let git_dir = crate::scratch::scratch("background-stale");
        let now = 1_000_000;
        let pending = |at| Pending {
            tool: String::from("Bash"),
            input: serde_json::json!({}),
            at,
        };
        defer(&git_dir, "kept", &pending(now - 86_400)).expect("defer the kept entry");
        defer(&git_dir, "dropped", &pending(now - 86_401)).expect("defer the dropped entry");
        assert!(resolve(&git_dir, None, now).is_empty());
        let dir = git_dir.join(DIR);
        assert!(dir.join("kept.json").exists());
        assert!(!dir.join("dropped.json").exists());
    }

    #[test]
    fn an_exit_is_read_past_a_half_written_line() {
        let wanted: HashSet<String> = ["b1".to_owned(), "b2".to_owned()].into();
        let transcript = format!(
            "{}\n{}\n{{\"type\":\"user\",\"message\":{{\"content\":\"<task-notification>",
            notification("b1", "/t/b1.output", "completed"),
            notification("b2", "/t/b2.output", "failed"),
        );
        let found = exits(&transcript, &wanted);
        assert_eq!(
            found["b1"],
            Exit {
                output: PathBuf::from("/t/b1.output"),
                completed: true
            }
        );
        assert!(!found["b2"].completed);
    }

    #[test]
    fn an_assistant_line_quoting_a_notification_is_not_an_exit() {
        let wanted: HashSet<String> = ["b1".to_owned()].into();
        let quoted =
            notification("b1", "/t/b1.output", "completed").replace("\"user\"", "\"assistant\"");
        assert!(exits(&quoted, &wanted).is_empty());
    }
}
