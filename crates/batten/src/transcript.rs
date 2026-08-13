//! Completed-session transcripts as an optional `check` input (CLOUD-95).
//!
//! Several divergence signals are invisible to synchronous mediation and fully
//! recorded after the fact: declared-done with work not landed (CLOUD-97),
//! a mediated deny followed by an enforcement-disabled retry (CLOUD-98), a stop
//! with a non-empty frontier (CLOUD-219), an unprompted self-write (CLOUD-267).
//! Each needs the same parse, so it is factored out once here rather than
//! re-derived four times — the shared-primitive pattern `git.rs` already sets.
//!
//! # What is typed, and what is deliberately opaque
//!
//! Every event below is built from a **typed field**, never from reading prose:
//! a tool call's `name` and `input`, a result's `is_error` boolean, and a hook
//! decision's `exitCode`. That last one matters most: a host records its hook
//! runs structurally, so "was this call denied" is `exit_code == 2` against the
//! one §7 table — not a substring match on an error message. A predicate built
//! on prose would be a classifier wearing a gate's clothes.
//!
//! The free-text payload is **never interpreted and never emitted**. A
//! transcript is the single richest source of secrets the engine can be pointed
//! at — it holds every command, every file body, every prompt — so
//! [`Counts`] carries numbers and [`Record`] carries a line, and nothing here
//! renders content (non-negotiable rule 4).
//!
//! # Forward compatibility is a requirement, not a nicety
//!
//! The format is a **host's**, not ours, and it moves. One captured session
//! carried six top-level `type` values and eleven `attachment.type` values, most
//! of which mean nothing to any predicate here. So an unrecognized line yields
//! no events rather than an error: a host shipping a new record type must not
//! turn every downstream gate red. What *is* refused is a line that is not JSON
//! at all — see the degradation contract below.
//!
//! # Degradation: absent, present, and the one case that refuses
//!
//! This module has to answer the objection its own repo raises. `rules::run_static`
//! refuses a spawning rule rather than skipping it, `epoch` refuses an unreadable
//! tracked path, and `capture::store` errors rather than skipping — three
//! precedents against silent degradation, because a skipped gate that still exits
//! `0` is the false green Batten exists to catch.
//!
//! The distinction that reconciles them is `lint.rs`'s **"absent is not empty"**:
//!
//! * **Not configured** — the repository does not use the feature. Nothing is
//!   reported, exactly as a config that never mentions a key is not a smell.
//! * **Configured, nothing at the path** — the capability is *absent*. Dependent
//!   rules cannot run, so this is reported and the run continues at
//!   [`crate::ExitCode::Success`]. It is reported through **both** channels
//!   (a ladder-gated stderr line and a field in the `-J` document) precisely
//!   because the stderr half is silenceable: `--silent -J` must still carry it,
//!   or the skip becomes the false green after all.
//! * **Configured, present, and undecodable** — refused loudly as
//!   [`crate::error::UsageError`], exit `1`. A transcript the operator pointed at
//!   and Batten could not read means the rules keyed on it did not run, and
//!   allowing that to pass silently is the failure the three precedents above are
//!   about. Exit `1` and not `2`: §7 spends `2` on the policy verdict alone, so a
//!   parse failure must never reach a mediating harness as a deny.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::UsageError;

/// What the human channel says when a configured transcript is not there.
///
/// Stated once as a constant so the E2E assertion cites it rather than restating
/// the wording, and so the two halves of the report — this line and the `-J`
/// field — cannot drift into saying different things.
///
/// It names the consequence, not just the fact: "there is no transcript" is a
/// filesystem observation, "the rules that read it did not run" is what a reader
/// has to act on.
pub const ABSENT_NOTICE: &str =
    "transcript: configured but not readable, so the rules that read it did not run";

/// Whose turn a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Role {
    /// The operator, or something the host rendered in the user role.
    ///
    /// The *role* alone does not say which: see [`Origin`], carried alongside.
    User,
    /// The model.
    Assistant,
}

/// Whether a user-role turn was actually opened by a person (CLOUD-267).
///
/// The role is not the answer, and conflating the two is the whole reason this
/// type exists. A host renders tool results in the **user** role, so a span full
/// of them reads as "the user spoke" to anything that inspects `role` alone —
/// and "a turn carrying no user message" is exactly the predicate that would
/// then never fire.
///
/// Three values rather than two, because [`Origin::Unknown`] is a real answer.
/// House style §10's three-valued disposition applies here for the same reason
/// it applies to a finding: a span whose authorship cannot be reconstructed must
/// register as unresolved, never silently as either one. Guessing `Authored`
/// would be the false green; guessing `Synthetic` would manufacture findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Origin {
    /// A genuine message from the operator.
    Authored,
    /// The host rendered this in the user role, but nobody typed it: a tool
    /// result handed back, or a record the host marked meta.
    ///
    /// **An injected message is not authorization.** A turn opened by one of
    /// these is a turn with no user message, however the host chose to render
    /// it.
    Synthetic,
    /// Authorship could not be reconstructed from the typed fields available.
    Unknown,
    /// Not a user turn at all — the model's own.
    Assistant,
}

/// The exit code a host's hook run uses to deny, per house-style §7.
///
/// Named rather than spelled `2` inline: this is the same table
/// [`crate::ExitCode::Violation`] is on, read from the other side. A transcript
/// records what a hook returned, so reading a denial here and emitting one in
/// `hook` are two ends of one contract.
const DENY_EXIT: i64 = crate::ExitCode::Violation.code() as i64;

/// Why a turn ended, as the host recorded it (CLOUD-97).
///
/// A **typed vocabulary over the host's `stop_reason` token**, not the token
/// itself: the raw string never leaves this module, so no downstream predicate
/// can grow a substring match on it and no wording change upstream can move a
/// verdict. Which of these values counts as a *completion* is deliberately not
/// decided here — that is policy, and it lives with the predicate that reads it
/// ([`crate::completion`]). This module owns the vocabulary; the detector owns
/// the token set.
///
/// [`StopReason::Other`] absorbs both truncation (`max_tokens`) and any token a
/// later host ships. Collapsing them is right for every predicate this
/// vocabulary serves — neither is a turn the model chose to end — and the
/// forward-compatibility law above forbids failing on the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StopReason {
    /// The model ended the turn of its own accord.
    EndTurn,
    /// A configured stop sequence ended it.
    StopSequence,
    /// It ended to make a tool call — the model is **continuing**, not finished.
    ToolUse,
    /// Truncation, or a token this build does not know. Never a completion.
    Other,
}

impl StopReason {
    /// Normalize a host's token.
    ///
    /// Exact membership, and total by construction: an unknown token is
    /// [`StopReason::Other`] rather than an error, because the format is a
    /// host's and it moves.
    #[must_use]
    fn normalize(raw: &str) -> StopReason {
        match raw {
            "end_turn" => StopReason::EndTurn,
            "stop_sequence" => StopReason::StopSequence,
            "tool_use" => StopReason::ToolUse,
            _ => StopReason::Other,
        }
    }
}

/// One typed event in a session.
///
/// Deliberately not a catch-all: a variant exists here because a named
/// downstream predicate reads it. Anything a host records that no predicate
/// consumes is skipped rather than modelled, so this stays a vocabulary rather
/// than a re-typing of the host's schema.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A turn boundary — the unit CLOUD-267's "a turn carrying no user message"
    /// is counted over.
    ///
    /// Carries [`Origin`] beside [`Role`] because the role alone cannot answer
    /// the question: a host renders tool results in the user role, so a
    /// role-only reading sees a user message where nobody spoke.
    Turn(Role, Origin),
    /// How a turn ended, when the host recorded it (CLOUD-97).
    ///
    /// Its own event rather than a third field on [`Event::Turn`]: a host
    /// records the reason on some turns and not others, and an `Option` on the
    /// turn would make every consumer of the turn boundary handle a fact none of
    /// them asked for. Emitted on presence of the typed field alone — the role
    /// is not consulted, because reading a role to decide whether to trust a
    /// typed field is exactly the inference this module refuses.
    TurnEnd(StopReason),
    /// A tool call, with the arguments a predicate reads structurally.
    ///
    /// `input` is retained because CLOUD-98's bypass predicate is a JSON boolean
    /// in exactly this object, not a phrase in a log line. It is never emitted.
    ToolCall {
        /// The host's id for this call, which a result and a hook record join on.
        id: String,
        /// The tool's name, e.g. `Bash`.
        name: String,
        /// The whole argument object. Never rendered.
        input: Value,
    },
    /// A tool result, joined to its call.
    ToolResult {
        /// The call this answers.
        call: String,
        /// Whether the host flagged it an error — a typed boolean, not a phrase.
        failed: bool,
    },
    /// A hook run the host recorded, with the code it returned.
    HookDecision {
        /// The lifecycle event the hook fired on, as the host spelled it.
        event: String,
        /// The call it mediated, when the host joined one.
        call: Option<String>,
        /// The code the hook returned; [`DENY_EXIT`] is a refusal.
        exit_code: i64,
    },
}

/// One event and where it was found.
///
/// The line number is the pointer a finding cites — never the line's content
/// (rule 4).
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// 1-based line number within the transcript.
    pub line: usize,
    /// The typed event.
    pub event: Event,
}

/// A parsed session.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    /// The host's session id, when it reported one.
    ///
    /// `Option` for the same reason [`crate::hook::Envelope::session`] is:
    /// [`crate::identity::sequence_fingerprint`] hashes `None` distinctly from
    /// `Some("")`, so a session-less transcript folds to per-invocation handling
    /// by construction rather than through a second rule invented here.
    pub session: Option<String>,
    /// Every event, in file order.
    pub records: Vec<Record>,
}

/// Pointer-only counts over a stream — the whole of what may be rendered.
///
/// Byte-stable by construction: derived from the records, carrying no timestamp,
/// no duration and no path, so the same transcript yields the same document
/// however often it is read (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Counts {
    /// Turn boundaries.
    pub turns: usize,
    /// Tool calls.
    pub tool_calls: usize,
    /// Tool results the host flagged as errors.
    pub tool_errors: usize,
    /// Hook runs recorded.
    pub hook_decisions: usize,
    /// Hook runs that denied — `exit_code` equal to the §7 verdict code.
    pub hook_denials: usize,
}

/// Whether the transcript capability is available for this run.
#[derive(Debug, Clone, PartialEq)]
pub enum Capability {
    /// No transcript is configured — the repository does not use the feature.
    /// Distinct from [`Capability::Absent`]: absent is not empty.
    Unconfigured,
    /// Configured, but nothing readable at the path. Dependent rules cannot run.
    Absent,
    /// Configured and parsed.
    Present(Stream),
}

impl Capability {
    /// The stable token a report names this state by.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Capability::Unconfigured => "unconfigured",
            Capability::Absent => "absent",
            Capability::Present(_) => "present",
        }
    }
}

impl Stream {
    /// Count the stream, which is all a caller may render.
    #[must_use]
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for record in &self.records {
            match &record.event {
                Event::Turn(..) => counts.turns += 1,
                // Counted by nothing on purpose. `Counts` is the `-J`
                // document's shape, and a turn-end reason is an input to a
                // predicate rather than a fact a reader of the capability
                // report needs; adding a field would move a document four
                // landed assertions read for no consumer's benefit.
                Event::TurnEnd(_) => {}
                Event::ToolCall { .. } => counts.tool_calls += 1,
                Event::ToolResult { failed, .. } => {
                    if *failed {
                        counts.tool_errors += 1;
                    }
                }
                Event::HookDecision { exit_code, .. } => {
                    counts.hook_decisions += 1;
                    if *exit_code == DENY_EXIT {
                        counts.hook_denials += 1;
                    }
                }
            }
        }
        counts
    }
}

/// Resolve the capability for a configured path, relative to `root`.
///
/// `None` for `configured` is [`Capability::Unconfigured`]: a repository that
/// never named a transcript is not missing one.
///
/// # Errors
///
/// [`UsageError`] when the file exists but a line is not JSON — the operator
/// pointed at something Batten cannot read, so the rules keyed on it did not
/// run, and passing silently would be the false green this module exists to
/// avoid.
pub fn resolve(root: &Path, configured: Option<&str>) -> Result<Capability> {
    let Some(relative) = configured else {
        return Ok(Capability::Unconfigured);
    };
    let path = root.join(relative);
    let Ok(body) = std::fs::read_to_string(&path) else {
        // Unreadable and absent are one answer on purpose: both mean the
        // capability is not available, and distinguishing a missing file from an
        // unreadable one would report a permissions problem as a parse failure.
        return Ok(Capability::Absent);
    };
    Ok(Capability::Present(parse(&body, relative)?))
}

/// Parse a transcript body into the typed stream.
///
/// # Errors
///
/// [`UsageError`] naming the line that did not decode — a pointer, never the
/// line itself, which is the whole reason this module exists.
pub fn parse(body: &str, label: &str) -> Result<Stream> {
    let mut session = None;
    let mut records = Vec::new();
    for (index, text) in body.lines().enumerate() {
        let line = index + 1;
        if text.trim().is_empty() {
            continue;
        }
        let parsed: Line = serde_json::from_str(text).map_err(|_| {
            UsageError::raise(format!(
                "{label}:{line}: transcript line did not decode; the rules that read it did not run"
            ))
        })?;
        if session.is_none() {
            // Borrowed, not moved: `collect` reads the same value below, and an
            // empty id is normalized to absent here so `Some("")` never reaches a
            // consumer that would hash it as a real session.
            session = parsed
                .session_id
                .as_deref()
                .filter(|id| !id.is_empty())
                .map(ToOwned::to_owned);
        }
        collect(&parsed, line, &mut records);
    }
    Ok(Stream { session, records })
}

/// Turn one decoded line into zero or more events.
///
/// Zero is the common case and the important one: a host records far more than
/// any predicate reads, and an unrecognized shape must produce nothing rather
/// than fail.
fn collect(parsed: &Line, line: usize, records: &mut Vec<Record>) {
    if let Some(attachment) = &parsed.attachment {
        if let (Some(event), Some(exit_code)) = (&attachment.hook_event, attachment.exit_code) {
            records.push(Record {
                line,
                event: Event::HookDecision {
                    event: event.clone(),
                    call: attachment.tool_use_id.clone(),
                    exit_code,
                },
            });
        }
        return;
    }
    let Some(message) = &parsed.message else {
        return;
    };
    let role = match message.role.as_deref() {
        Some("user") => Some(Role::User),
        Some("assistant") => Some(Role::Assistant),
        _ => None,
    };
    if let Some(role) = role {
        records.push(Record {
            line,
            event: Event::Turn(role, origin_of(parsed, message, role)),
        });
    }
    // After the boundary, so the stream reads in the order the turn happened:
    // the turn opened, then it ended for this reason. A predicate scanning for
    // the last completion marker depends on that order (CLOUD-97).
    if let Some(reason) = message.stop_reason.as_deref() {
        records.push(Record {
            line,
            event: Event::TurnEnd(StopReason::normalize(reason)),
        });
    }
    // Content is an array of blocks, or a bare string when the turn is plain
    // text. A string carries no tool structure, so it yields the turn alone.
    let Some(Value::Array(blocks)) = &message.content else {
        return;
    };
    for block in blocks {
        let Ok(block) = serde_json::from_value::<Block>(block.clone()) else {
            continue;
        };
        match block.kind.as_str() {
            "tool_use" => {
                if let (Some(id), Some(name)) = (block.id, block.name) {
                    records.push(Record {
                        line,
                        event: Event::ToolCall {
                            id,
                            name,
                            input: block.input.unwrap_or(Value::Null),
                        },
                    });
                }
            }
            "tool_result" => {
                if let Some(call) = block.tool_use_id {
                    records.push(Record {
                        line,
                        event: Event::ToolResult {
                            call,
                            failed: block.is_error.unwrap_or(false),
                        },
                    });
                }
            }
            _ => {}
        }
    }
}

/// Decide whether a user-role turn was opened by a person (CLOUD-267).
///
/// Every branch is an exact read of a typed field — a boolean the host set, or
/// the `type` discriminant of a content block. Nothing here inspects prose, so
/// no wording change upstream can flip a verdict.
///
/// The ordering matters. A host-set meta marker is checked **first** and wins
/// outright: it is the host stating that it, not a person, produced the record,
/// and that statement is more authoritative than anything inferable from the
/// content. Then the content shape: a block array whose every element is a
/// `tool_result` is the harness handing work back, which is the common synthetic
/// case and the one the captured fixture carries.
///
/// A bare string is [`Origin::Authored`]: that is the shape a host uses for a
/// plain typed turn, and it carries no structure that could indicate otherwise.
///
/// Where the host supplies neither a marker nor a decodable content shape, the
/// answer is [`Origin::Unknown`] rather than a guess. Per CLOUD-45 this is a
/// per-host capability fact — a host that renders injected content in the user
/// role with no marker simply cannot be separated from one that does — and the
/// honest response is to surface it, not to pick a side.
fn origin_of(parsed: &Line, message: &Message, role: Role) -> Origin {
    if role == Role::Assistant {
        return Origin::Assistant;
    }
    // The host's own statement, and it outranks any inference below.
    if parsed.is_meta.unwrap_or(false) || parsed.is_synthetic.unwrap_or(false) {
        return Origin::Synthetic;
    }
    match &message.content {
        // A plain typed turn.
        Some(Value::String(_)) => Origin::Authored,
        Some(Value::Array(blocks)) if !blocks.is_empty() => {
            // Every block a tool result: the harness handing work back, in the
            // user role, with nobody having spoken.
            let all_results = blocks
                .iter()
                .all(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"));
            if all_results {
                Origin::Synthetic
            } else {
                Origin::Authored
            }
        }
        // No content at all, or an empty block array: nothing to read, and a
        // guess either way would be the failure this arm exists to avoid.
        _ => Origin::Unknown,
    }
}

/// One transcript line, typed to what a predicate reads.
///
/// Every field is optional and unknown keys are ignored — the opposite of
/// `config.rs`'s `deny_unknown_fields`, and deliberately so. That strictness is
/// right for an artifact this repo owns and wrong for one a host writes: here it
/// would turn every upstream addition into a red gate.
#[derive(Debug, Deserialize)]
struct Line {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    message: Option<Message>,
    attachment: Option<Attachment>,
    /// The host marking a record as its own rather than the operator's.
    ///
    /// Two spellings because hosts differ and neither is ours to choose; both
    /// mean the same thing to [`origin_of`], and a host that sets neither lands
    /// on the content-shape branch.
    #[serde(rename = "isMeta")]
    is_meta: Option<bool>,
    #[serde(rename = "isSynthetic")]
    is_synthetic: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Message {
    role: Option<String>,
    content: Option<Value>,
    /// Why the turn ended, in the host's own token — normalized to
    /// [`StopReason`] on the way in and never stored as text (CLOUD-97).
    #[serde(rename = "stop_reason")]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Attachment {
    #[serde(rename = "hookEvent")]
    hook_event: Option<String>,
    #[serde(rename = "toolUseID")]
    tool_use_id: Option<String>,
    #[serde(rename = "exitCode")]
    exit_code: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Block {
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
    name: Option<String>,
    input: Option<Value>,
    tool_use_id: Option<String>,
    is_error: Option<bool>,
}

/// The configured transcript path, as `batten.toml` declares it.
///
/// A path, not a format selector: which host wrote it is pinned by the fixtures,
/// and a repository that points at one is saying "read this", not "read this
/// dialect". Host-specific, never consumer-specific, so rule 1 holds — no
/// consumer's directory layout appears in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct TranscriptConfig {
    /// Repo-relative path to the completed session transcript.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The host's memory-root prefix, for CLOUD-267's self-persistence match.
    ///
    /// Host-adapter data on the same table rather than a second authority: the
    /// transcript's format and the host's memory layout are two facts about one
    /// host, and splitting them across tables would be the widening rule 6
    /// forbids. Omitted, [`crate::selfwrite::DEFAULT_MEMORY_ROOT`] applies.
    ///
    /// A **prefix matched against targets the transcript recorded** — never a
    /// path this engine opens, stats, or globs, which is what keeps the rule
    /// inside the repo root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_root: Option<String>,
}

/// Validate the table at load, the way every other config table is.
///
/// Takes an `Option` to match [`crate::budget::validate`]'s signature: `[budget]`
/// and `[transcript]` are both tables rather than lists, so neither is reached by
/// the `Vec<T>` census in `config.rs`, and both are called explicitly from
/// `parse_ungated` for that reason.
///
/// # Errors
///
/// [`UsageError`] when a declared path is empty — a key present and blank is a
/// different claim from a key absent, and the blank one is a mistake rather than
/// a repository opting out. Left unchecked it would join to the repository root
/// and be read as a directory, which surfaces as "undecodable transcript".
pub fn validate(config: Option<&TranscriptConfig>) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    if config.path.as_deref().is_some_and(str::is_empty) {
        return Err(UsageError::raise(
            "transcript.path: declared but empty; omit the key to opt out".to_owned(),
        ));
    }
    Ok(())
}

/// The path a run should read, if any.
#[must_use]
pub fn configured_path(config: Option<&TranscriptConfig>) -> Option<PathBuf> {
    config
        .and_then(|transcript| transcript.path.as_deref())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A miniature transcript in the host's real shape: an assistant turn making
    /// a tool call, a hook record denying it, and a user turn carrying the error.
    const SAMPLE: &str = r#"{"type":"assistant","sessionId":"s-1","message":{"role":"assistant","content":[{"type":"thinking","thinking":"private"},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"gh pr merge"}}]}}
{"type":"attachment","sessionId":"s-1","attachment":{"type":"hook_success","hookEvent":"PreToolUse","hookName":"PreToolUse:Bash","toolUseID":"t1","exitCode":2,"stderr":"secret reason"}}
{"type":"user","sessionId":"s-1","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":"secret body"}]}}
{"type":"queue-operation","sessionId":"s-1","content":"ignored"}
{"type":"user","sessionId":"s-1","message":{"role":"user","content":"a plain string turn"}}"#;

    fn sample() -> Stream {
        parse(SAMPLE, "t.jsonl").expect("parses")
    }

    #[test]
    fn the_sample_yields_the_expected_typed_stream() {
        let stream = sample();
        assert_eq!(stream.session.as_deref(), Some("s-1"));
        let counts = stream.counts();
        assert_eq!(counts.turns, 3, "two user turns and one assistant");
        assert_eq!(counts.tool_calls, 1);
        assert_eq!(counts.tool_errors, 1);
        assert_eq!(counts.hook_decisions, 1);
        assert_eq!(counts.hook_denials, 1, "exit 2 is the §7 verdict code");
    }

    #[test]
    fn a_hook_record_joins_its_call_and_reads_the_code_not_the_prose() {
        let stream = sample();
        let decision = stream
            .records
            .iter()
            .find_map(|record| match &record.event {
                Event::HookDecision {
                    call, exit_code, ..
                } => Some((call.clone(), *exit_code)),
                _ => None,
            })
            .expect("a hook record");
        assert_eq!(decision, (Some("t1".to_owned()), 2));
    }

    #[test]
    fn an_unrecognized_line_type_yields_nothing_rather_than_failing() {
        // The host ships new record types constantly; one captured session
        // carried eleven attachment subtypes. A gate that reddened on each would
        // be switched off within a release.
        let stream = parse(
            r#"{"type":"something-new","sessionId":"s","brandNew":{"nested":1}}"#,
            "t.jsonl",
        )
        .expect("parses");
        assert!(stream.records.is_empty());
    }

    #[test]
    fn a_line_that_is_not_json_is_refused_by_pointer_never_by_content() {
        let error =
            parse("{\"type\":\"user\"}\nnot json at all\n", "t.jsonl").expect_err("refuses");
        let rendered = error.to_string();
        assert!(rendered.contains("t.jsonl:2"), "got: {rendered}");
        assert!(
            !rendered.contains("not json at all"),
            "the refusal must not echo the line: {rendered}"
        );
    }

    #[test]
    fn counting_is_byte_stable_across_two_parses() {
        assert_eq!(sample().counts(), sample().counts());
        assert_eq!(
            serde_json::to_string(&sample().counts()).unwrap(),
            serde_json::to_string(&sample().counts()).unwrap()
        );
    }

    #[test]
    fn an_absent_or_unconfigured_path_are_different_answers() {
        let dir = std::env::temp_dir();
        assert_eq!(resolve(&dir, None).unwrap(), Capability::Unconfigured);
        assert_eq!(
            resolve(&dir, Some("no-such-transcript-here.jsonl")).unwrap(),
            Capability::Absent
        );
    }

    #[test]
    fn an_empty_session_id_is_none_never_some_empty() {
        let stream = parse(r#"{"type":"user","sessionId":""}"#, "t.jsonl").expect("parses");
        assert_eq!(stream.session, None);
    }

    #[test]
    fn a_declared_but_empty_path_is_refused_at_load() {
        assert!(
            validate(Some(&TranscriptConfig {
                path: Some(String::new()),
                ..TranscriptConfig::default()
            }))
            .is_err()
        );
        assert!(validate(Some(&TranscriptConfig::default())).is_ok());
        // No table at all is the ordinary case, not a finding.
        assert!(validate(None).is_ok());
    }

    #[test]
    fn a_turn_end_reason_is_a_typed_token_never_the_hosts_string() {
        let body = r#"{"type":"assistant","message":{"role":"assistant","content":[],"stop_reason":"end_turn"}}
{"type":"assistant","message":{"role":"assistant","content":[],"stop_reason":"tool_use"}}
{"type":"assistant","message":{"role":"assistant","content":[],"stop_reason":"max_tokens"}}
{"type":"assistant","message":{"role":"assistant","content":[],"stop_reason":"brand_new_token"}}"#;
        let reasons: Vec<StopReason> = parse(body, "t.jsonl")
            .expect("parses")
            .records
            .iter()
            .filter_map(|record| match record.event {
                Event::TurnEnd(reason) => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            reasons,
            vec![
                StopReason::EndTurn,
                StopReason::ToolUse,
                // Truncation and an unknown token collapse: neither is a turn
                // the model chose to end, and failing on the second would make
                // every host release a red gate.
                StopReason::Other,
                StopReason::Other,
            ]
        );
    }

    #[test]
    fn a_turn_with_no_stop_reason_yields_no_turn_end() {
        // Absent is not `Other`: a host that records nothing has said nothing,
        // and minting a reason here would manufacture the very field the
        // predicate reads.
        let stream = sample();
        assert!(
            !stream
                .records
                .iter()
                .any(|record| matches!(record.event, Event::TurnEnd(_))),
            "the captured sample carries no stop_reason"
        );
    }

    #[test]
    fn a_turn_end_follows_its_own_turn_boundary() {
        // The order is load-bearing for CLOUD-97's "last marker with no tool
        // call after it": a reason emitted before its boundary would sort the
        // stream against the sequence that actually happened.
        let stream = parse(
            r#"{"message":{"role":"assistant","content":[],"stop_reason":"end_turn"}}"#,
            "t.jsonl",
        )
        .expect("parses");
        assert!(matches!(
            stream.records.as_slice(),
            [
                Record {
                    event: Event::Turn(Role::Assistant, _),
                    ..
                },
                Record {
                    event: Event::TurnEnd(StopReason::EndTurn),
                    ..
                },
            ]
        ));
    }

    #[test]
    fn the_deny_code_is_the_one_exit_table_not_a_literal() {
        // Read from `ExitCode` rather than spelled `2`, so the two ends of the
        // contract — emitting a deny in `hook`, recognising one here — cannot
        // drift apart.
        assert_eq!(DENY_EXIT, 2);
    }
}
