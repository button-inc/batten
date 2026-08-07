//! The `hook` adjudicator (CLOUD-202): the agent-neutral envelope, the
//! wrapper-lookthrough command parser, and the first policy table, ported from
//! the battle-tested shell guards (`mise-tasks/gh-guard-check` et al.).
//!
//! Three layers, deliberately separated:
//!
//! * [`Envelope`] — the one normalized shape every harness adapter decodes
//!   into: `event`, `tool`, `input`, `cwd?`, `session?`. Harness-specific field
//!   names live in the adapter for that harness, never here.
//! * the parser — quoted spans are neutralised, segments split on shell
//!   separators, env prefixes and wrapper programs (`env`, `timeout`,
//!   `mise exec -- …`) looked through, so policy judges the **effective**
//!   program. Judging the wrapper token instead is the bug class CLOUD-181
//!   hardened the shell guards against; the port keeps that hard-won shape.
//! * the policy — a table from command shape to a deny with a fix pointer.
//!   This slice carries the `gh` lifecycle table; the receipt, issue-key,
//!   run-shape, and protected-path policies follow (CLOUD-202 items 3–5).
//!
//! **Posture: fail open.** Unreadable stdin, unparseable JSON, an envelope with
//! no command — all resolve to [`Decision::Allow`]. A guard must never be the
//! reason a session cannot proceed; the escape hatch (`BATTEN_GH_GUARD_BYPASS`)
//! is honoured exactly as the shell guard honours it. The exit-code contract
//! inversion (§7: under `hook`, exit `2` denies) lives at this layer only, in
//! [`Harness::exit_code_for`].

use serde::Serialize;
use serde_json::Value;

/// The harness adapters `batten hook` can speak. Each owns the decode of its
/// host's payload into an [`Envelope`] and the encode of a [`Decision`] into
/// what that host consumes; the core between them is harness-blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness {
    /// Claude Code's `PreToolUse` payload; a deny is returned as the
    /// `hookSpecificOutput.permissionDecision` JSON object on stdout with exit
    /// `0` — the channel the production shell guards already use.
    ClaudeCode,
    /// The neutral core contract: envelope in, decision as exit code out —
    /// `0` allow, `2` deny (reason on stderr). The §7 inversion, for any host
    /// whose only decision channel is an exit status.
    ExitCode,
}

/// The normalized hook envelope — the shape the core adjudicates, whatever the
/// host called its fields. `session` is optional by design: some harnesses
/// expose two ids, some events none, so anything keyed on it degrades to
/// per-invocation (contracts doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The lifecycle event, e.g. `PreToolUse`.
    pub event: String,
    /// The tool being mediated, e.g. `Bash`.
    pub tool: String,
    /// The command text for shell-shaped tools; empty when the tool has none.
    pub command: String,
}

/// The adjudication verdict. `Deny` carries the reason, which by the refusal
/// contract (CLOUD-122) names the redirect — the exact command to run instead —
/// and the bypass hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the mediated call proceed.
    Allow,
    /// Block the mediated call, with an actionable reason.
    Deny(String),
}

/// Decode a harness payload into the normalized envelope.
///
/// Fail-open by returning `None` for anything that does not decode: absent
/// fields are an allow, never an error. Claude Code's `PreToolUse` shape is
/// `{hook_event_name, tool_name, tool_input: {command, …}, …}`.
#[must_use]
pub fn decode(harness: Harness, raw: &str) -> Option<Envelope> {
    match harness {
        Harness::ClaudeCode | Harness::ExitCode => {
            let value: Value = serde_json::from_str(raw).ok()?;
            let command = value
                .pointer("/tool_input/command")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Some(Envelope {
                event: value
                    .get("hook_event_name")
                    .and_then(Value::as_str)
                    .unwrap_or("PreToolUse")
                    .to_owned(),
                tool: value
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                command,
            })
        }
    }
}

/// Adjudicate an envelope against the policy tables.
///
/// `bypass` is the caller-resolved escape hatch (the boundary reads
/// `BATTEN_GH_GUARD_BYPASS`, keeping this function pure and testable).
#[must_use]
pub fn adjudicate(envelope: &Envelope, bypass: bool) -> Decision {
    if bypass || envelope.command.is_empty() {
        return Decision::Allow;
    }
    gh_lifecycle(&envelope.command)
}

/// The `gh` lifecycle policy, ported from `mise-tasks/gh-guard-check`: deny a
/// hand-rolled shape this repo's config routes through a task, allow reads and
/// everything unrecognised.
fn gh_lifecycle(command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.split_whitespace().collect();
        let Some(program_index) = effective_program(&tokens) else {
            continue;
        };
        if tokens[program_index] != "gh" {
            continue;
        }
        // Subcommand words with flags dropped. A value-taking flag leaves its
        // value behind, but the blocked pairs are adjacent, so that never
        // hides a real match (`gh -R o/r pr merge` still matches; `gh pr view
        // merge-fix` never does).
        let words: Vec<&str> = tokens[program_index + 1..]
            .iter()
            .copied()
            .filter(|t| !t.starts_with('-'))
            .collect();
        for pair in words.windows(2) {
            let decision = match (pair[0], pair[1]) {
                ("pr", "merge") => Some(
                    "Refused: `gh pr merge` is blocked — it (like the merge button) rewrites \
                     commits under new SHAs, discarding the exact objects CI tested. Use `mise \
                     run land`, which comments /fast-forward so main advances to this branch's \
                     already-passed commits. Bypass with BATTEN_GH_GUARD_BYPASS=1.",
                ),
                // Only a comment carrying the landing directive; an ordinary
                // `gh pr comment` is not the lifecycle. Tested against the
                // ORIGINAL command, since the directive lives inside the
                // quoted --body that scrubbing neutralised.
                ("pr", "comment") if command.contains("fast-forward") => Some(
                    "Refused: commenting /fast-forward by hand only STARTS the merge — it does \
                     not wait for it, and the usual pairing with a guessed `sleep` reports \
                     before the merge lands. Use `mise run land` (backgrounded): it comments, \
                     then blocks until the PR is MERGED or the fast-forward bot refuses. Bypass \
                     with BATTEN_GH_GUARD_BYPASS=1.",
                ),
                ("pr", "checks") | ("run", "watch") => Some(
                    "Refused: hand-watching CI is the ad-hoc shape `mise run ci-wait` replaces. \
                     It polls check-runs for HEAD until every one is terminal, prints their \
                     conclusions, and exits non-zero unless all are green — with no timeout to \
                     reintroduce the VM-reap gap. Background it. (`gh pr view`/`list`/`create`, \
                     `gh pr ready`, `gh api`, `gh run view` are NOT blocked.) Bypass with \
                     BATTEN_GH_GUARD_BYPASS=1.",
                ),
                _ => None,
            };
            if let Some(reason) = decision {
                return Decision::Deny(reason.to_owned());
            }
        }
    }
    Decision::Allow
}

/// Neutralise quoted spans, then split the command on shell separators, so
/// `git commit -m "gh pr merge"` carries no `gh` segment at all.
fn segments(command: &str) -> Vec<String> {
    let mut scrubbed = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                let quote = c;
                // Consume through the closing quote; an unterminated span runs
                // to the end, which still neutralises it.
                for inner in chars.by_ref() {
                    if inner == quote {
                        break;
                    }
                }
                scrubbed.push_str("QUOTED");
            }
            _ => scrubbed.push(c),
        }
    }
    scrubbed
        .replace("&&", "\n")
        .replace("||", "\n")
        .replace([';', '|', '&'], "\n")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Find the index of the effective program in a segment's tokens: skip
/// `VAR=value` env prefixes, then look through known wrapper programs so the
/// wrapped program is judged, not the wrapper. Known wrappers only; anything
/// unrecognised keeps the fail-open posture.
fn effective_program(tokens: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < tokens.len() && is_env_assignment(tokens[i]) {
        i += 1;
    }
    loop {
        match *tokens.get(i)? {
            "env" | "command" | "nice" | "stdbuf" | "timeout" | "xargs" | "sudo" | "doas" => {
                i += 1;
                // The wrapper's own flags, env assignments, and bare numeric
                // arguments (timeout's duration) precede the wrapped program.
                while i < tokens.len()
                    && (tokens[i].starts_with('-')
                        || is_env_assignment(tokens[i])
                        || tokens[i].starts_with(|c: char| c.is_ascii_digit()))
                {
                    i += 1;
                }
            }
            "mise" => {
                // Only `mise exec` / `mise x` run another program; `mise run`
                // names a task, which is the sanctioned surface.
                match tokens.get(i + 1) {
                    Some(&("exec" | "x")) => {
                        i += 2;
                        // Tool pins (node@22), flags, and the `--` separator
                        // precede the program.
                        while i < tokens.len()
                            && (tokens[i].starts_with('-') || tokens[i].contains('@'))
                        {
                            i += 1;
                        }
                    }
                    _ => return Some(i),
                }
            }
            _ => return Some(i),
        }
    }
}

fn is_env_assignment(token: &str) -> bool {
    let mut chars = token.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && token
            .chars()
            .take_while(|&c| c != '=')
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && token.contains('=')
}

/// Claude Code's deny payload: the `hookSpecificOutput.permissionDecision`
/// object the host reads from stdout. Field order is struct order, so the
/// emission is byte-stable.
#[derive(Serialize)]
struct ClaudeDeny<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeDenyInner<'a>,
}

#[derive(Serialize)]
struct ClaudeDenyInner<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

/// Encode a deny for the Claude Code adapter.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_claude_deny(event: &str, reason: &str) -> serde_json::Result<String> {
    serde_json::to_string(&ClaudeDeny {
        hook_specific_output: ClaudeDenyInner {
            hook_event_name: event,
            permission_decision: "deny",
            permission_decision_reason: reason,
        },
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn adjudicate_command(command: &str) -> Decision {
        adjudicate(
            &Envelope {
                event: "PreToolUse".to_owned(),
                tool: "Bash".to_owned(),
                command: command.to_owned(),
            },
            false,
        )
    }

    fn is_deny(command: &str) -> bool {
        matches!(adjudicate_command(command), Decision::Deny(_))
    }

    #[test]
    fn blocked_shapes_are_denied() {
        assert!(is_deny("gh pr merge 42"));
        assert!(is_deny("gh pr checks --watch"));
        assert!(is_deny("gh run watch 123"));
        assert!(is_deny("gh pr comment 7 --body /fast-forward"));
    }

    #[test]
    fn wrapper_lookthrough_judges_the_effective_program() {
        // The web-sandbox shape: the wrapper form is the only working form, so
        // a guard that stops at the wrapper token sees none of the calls that
        // matter (CLOUD-181).
        assert!(is_deny("mise exec -- gh pr merge 42"));
        assert!(is_deny("env GH_PAGER= gh pr merge"));
        assert!(is_deny("timeout 30 gh pr checks"));
        assert!(is_deny("FOO=bar gh pr merge"));
    }

    #[test]
    fn interposed_flag_values_do_not_hide_a_match() {
        assert!(is_deny("gh -R owner/repo pr merge"));
    }

    #[test]
    fn reads_and_lookalikes_are_allowed() {
        assert!(!is_deny("gh pr view 42"));
        assert!(!is_deny("gh pr ready 42"));
        assert!(!is_deny("gh pr view merge-fix"));
        assert!(!is_deny("gh api repos/o/r/pulls"));
        assert!(!is_deny("mise run land"));
        assert!(!is_deny("gh pr comment 7 --body thanks"));
    }

    #[test]
    fn quoted_spans_are_not_commands() {
        assert!(!is_deny("git commit -m \"gh pr merge\""));
        assert!(!is_deny("echo 'gh run watch'"));
    }

    #[test]
    fn a_denied_shape_in_any_segment_is_a_deny() {
        assert!(is_deny("git push && gh pr merge 42"));
    }

    #[test]
    fn bypass_allows_everything() {
        let envelope = Envelope {
            event: "PreToolUse".to_owned(),
            tool: "Bash".to_owned(),
            command: "gh pr merge".to_owned(),
        };
        assert_eq!(adjudicate(&envelope, true), Decision::Allow);
    }

    #[test]
    fn decode_reads_the_claude_payload() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr merge"}}"#;
        let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
        assert_eq!(envelope.command, "gh pr merge");
        assert_eq!(envelope.tool, "Bash");
    }

    #[test]
    fn decode_fails_open_on_junk() {
        assert_eq!(decode(Harness::ClaudeCode, "not json"), None);
        // A payload with no command decodes to an empty command, which
        // adjudicates to Allow rather than erroring.
        let envelope = decode(Harness::ClaudeCode, "{}").expect("decodes");
        assert_eq!(adjudicate(&envelope, false), Decision::Allow);
    }

    #[test]
    fn the_claude_deny_shape_is_byte_stable() {
        let one = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        let two = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        assert_eq!(one, two);
        assert!(one.contains("\"permissionDecision\":\"deny\""));
    }
}
