//! The `hook` adjudicator (CLOUD-202): the agent-neutral envelope, the
//! wrapper-lookthrough command parser, and the first policy table, ported from
//! the battle-tested shell guards (`mise-tasks/gh-guard-check` et al.).
//!
//! Three layers, deliberately separated:
//!
//! * [`Envelope`] — the one normalized shape every harness adapter decodes
//!   into: a typed [`Event`], the host's own `raw_event` spelling, `tool`,
//!   the whole `input` object, its shell `command` projection, `cwd` and an
//!   optional `session` (CLOUD-43). Harness-specific field names live in the
//!   adapter for that harness, never here. `cwd` is carried but not yet
//!   consumed, which is why an absolute path argument is still compared as
//!   written rather than resolved against the repo root.
//! * the dispatch — **only the pre-tool event is adjudicated.** Before
//!   CLOUD-43 the event was decoded and never read, so a `PostToolUse` payload
//!   carrying a banned command was refused after the call had already run, at
//!   an event no host offers a deny channel for. Every other event allows by
//!   decision rather than by omission.
//! * the parser — quoted spans become words rather than a sentinel, segments
//!   split on unquoted shell separators, env prefixes and wrapper programs
//!   (`env`, `timeout`, `mise exec -- …`) looked through, so policy judges the
//!   **effective** program. Judging the wrapper token instead is the bug class
//!   CLOUD-181 hardened the shell guards against; the port keeps that hard-won
//!   shape, and CLOUD-269 extended it so a quoted operand survives as a word.
//! * the policy — **config, not code** (CLOUD-48). [`Policy`] is the
//!   `mediated_call`-scoped rows of the resolved `batten.toml`, so the shapes a
//!   repository refuses are readable without reading Rust (§9) and the engine
//!   carries no consumer's task names (non-negotiable rule 1). This module owns
//!   the matcher; the table lives in the consumer's config.
//! * the refusal — **one value, projected per channel** (CLOUD-122). Both deny
//!   paths here build a [`Refusal`] rather than a string, so neither can ship a
//!   bare "no": the constructor requires a [`Fix`], and a deny with none spells
//!   it. [`deny_text`] is the projection every host's channel carries.
//!
//! **Posture: fail open.** Unreadable stdin, unparseable JSON, an envelope with
//! no command — all resolve to [`Decision::Allow`]. A guard must never be the
//! reason a session cannot proceed; the escape hatch (`BATTEN_GH_GUARD_BYPASS`)
//! is honoured exactly as the shell guard honours it. Fail-open needs no care
//! here beyond the returns below: §7 spends `2` on the policy verdict alone, so
//! neither code a Batten failure can produce is one a host reads as a deny.

use std::path::PathBuf;

use serde::Serialize;
use serde_json::Value;

use crate::receipt::Validity;
use crate::refusal::{Fix, Refusal};
use crate::resolve::Resolved;
use crate::rules::{PathSet, Rule, RuleKind, RuleScope};
use crate::severity::{self, ReportLevel, RuleSeverity};
use crate::verbs::MutatingVerb;

/// The harness adapters `batten hook` can speak. Each owns the decode of its
/// host's payload into an [`Envelope`] and the encode of a [`Decision`] into
/// what that host consumes; the core between them is harness-blind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness {
    /// Claude Code's `PreToolUse` payload; a deny is returned as the
    /// `hookSpecificOutput.permissionDecision` JSON object on stdout with exit
    /// `0` — the channel the production shell guards already use.
    ClaudeCode,
    /// Cursor. Two payload families under one host: a generic `preToolUse` that
    /// looks like Claude's, and specialized events (`beforeShellExecution`,
    /// `beforeReadFile`, `beforeMCPExecution`) that carry the operand at top
    /// level and **no** `tool_name` at all. Session is `conversation_id`.
    Cursor,
    /// GitHub Copilot CLI, registered in its **`PascalCase`** dialect — which
    /// yields `hook_event_name` natively. The camelCase dialect omits the event
    /// name entirely, so Batten does not speak it.
    CopilotCli,
    /// Gemini CLI. Claude-identical payload fields, different event names
    /// (`BeforeTool` rather than `PreToolUse`).
    GeminiCli,
    /// Codex CLI, whose wire format is a near-verbatim clone of Claude Code's —
    /// its own repo says so. No payload shim is needed; the adapter exists so
    /// the host is nameable and its fixture is pinned against drift.
    CodexCli,
    /// The neutral core contract: envelope in, decision as exit code out —
    /// `0` allow, `2` deny (reason on stderr), for any host whose only decision
    /// channel is an exit status. Both codes are the §7 table's, unmodified.
    ExitCode,
}

impl Harness {
    /// Every harness, so anything ranging over them is derived rather than
    /// re-typed — the CLOUD-40 decision-channel matrix reads this, which is what
    /// stops a further adapter from landing with no fixture row.
    pub const ALL: &'static [Harness] = &[
        Harness::ClaudeCode,
        Harness::Cursor,
        Harness::CopilotCli,
        Harness::GeminiCli,
        Harness::CodexCli,
        Harness::ExitCode,
    ];

    /// The CLI token, identical to the `ValueEnum` spelling `--harness` accepts.
    ///
    /// Stated here rather than read off `clap` so the matrix can name a harness
    /// without building a command; `tests::every_harness_token_matches_its_clap_spelling`
    /// is what keeps the two from drifting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::Cursor => "cursor",
            Harness::CopilotCli => "copilot-cli",
            Harness::GeminiCli => "gemini-cli",
            Harness::CodexCli => "codex-cli",
            Harness::ExitCode => "exit-code",
        }
    }

    /// Whether a deny on this host must carry its reason **in the JSON body**
    /// rather than on stderr.
    ///
    /// Cursor is the one surveyed host that assigns no meaning to stderr, so
    /// CLOUD-122's refusal contract ("every deny points to the fix") is
    /// unsatisfiable there through the exit-code channel alone. Claude Code
    /// answers in-band for a different reason — exit 2 discards its stdout JSON,
    /// so the two channels are exclusive and it picks the richer one.
    #[must_use]
    pub const fn reason_travels_in_band(self) -> bool {
        matches!(self, Harness::ClaudeCode | Harness::Cursor)
    }

    /// The tools on this host whose call **writes the path it names**.
    ///
    /// A host fact, so it lives in the adapter rather than in `[[rule]]`: the
    /// consumer declares *which paths* are protected, and the adapter declares
    /// *which of its tools* are a write. Neither table can be derived from the
    /// other, and a consumer cannot be asked to name a host's tool inventory.
    ///
    /// The set has to be named because a path alone does not say what is being
    /// done to it. `Read` and `Write` both carry `file_path`, so judging every
    /// payload that has one would refuse reading a protected file — a deny with
    /// no rationale, and the kind of false positive that gets a guard switched
    /// off.
    ///
    /// Each host answers for itself even where the answers coincide, because
    /// coincidence is not agreement: [`Harness::CodexCli`] is a near-verbatim
    /// clone of Claude's wire format *today*, and folding it into a shared
    /// constant would silently re-point it if that ever stopped being true.
    #[must_use]
    pub const fn write_tools(self) -> &'static [&'static str] {
        match self {
            Harness::ClaudeCode | Harness::CodexCli => {
                &["Write", "Edit", "MultiEdit", "NotebookEdit"]
            }
            Harness::GeminiCli => &["WriteFile", "Edit", "Write", "MultiEdit", "NotebookEdit"],
            Harness::Cursor => &["Write", "Edit", "MultiEdit", "write", "edit"],
            Harness::CopilotCli => &["Write", "Edit", "MultiEdit", "StrReplaceEditor"],
            // The neutral contract: a caller composing the envelope by hand is
            // stating the normalized shape, so it gets the normalized spellings.
            Harness::ExitCode => &["Write", "Edit", "MultiEdit", "NotebookEdit"],
        }
    }
}

/// What one host can and cannot do (CLOUD-45).
///
/// A **host × capability** table, not a list of Claude-only events — the survey
/// (CLOUD-209) measured the asymmetry running both ways, and the issue's original
/// framing encoded a false premise. Gemini can rewrite model traffic and
/// constrain tool selection; Cursor sees file contents before a read; neither is
/// something Claude Code can do.
///
/// Declared as data the dispatcher consults, so no behaviour keys on an event
/// without asking whether the host emits it. A host's event set is stated here
/// and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
// `struct_excessive_bools` wants these folded into an enum or bitflags. Refused
// on purpose: this is a **matrix row**, and the lint's premise — that several
// bools are usually one state machine wearing a disguise — is false here. The
// fields are mutually independent measured facts about a third party, four of
// them found on different pages of different vendors' docs. An enum would have
// to enumerate 2^n combinations that carry no meaning, and bitflags would trade
// a named field for a bit position, which is exactly the readability this table
// exists to give the survey's findings.
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    /// The events this host emits, so Batten can be invoked on them.
    pub events: &'static [Event],
    /// Whether the host offers an escalate-to-human verdict.
    ///
    /// Absent on Gemini (allow/deny only) and not in effect on Codex (its schema
    /// lists `ask`; its docs mark it "parsed but not supported yet"). A policy
    /// wanting confirmation must hard-deny on those two — degrading to *allow*
    /// would turn "ask a human" into "go ahead".
    pub ask: bool,
    /// Whether a stop-family event can veto completion.
    ///
    /// **`false` on every surveyed host, Claude included** — all of them can only
    /// force continuation, with per-host loop caps. The field exists to make that
    /// checkable rather than remembered: behaviour keyed on "Stop blocks" is
    /// wrong everywhere, not degraded somewhere, and a table that omitted the
    /// column would let someone assume the opposite of a uniform fact.
    pub stop_vetoes_completion: bool,
    /// Whether a hook timeout fails open no matter what the config says.
    ///
    /// Copilot concedes this even for admin-deployed policy hooks, so a Batten
    /// hook that hangs cannot block there.
    pub timeout_fails_open: bool,
    /// Whether the host needs `failClosed` set explicitly to not fail open.
    pub needs_fail_closed_config: bool,
    /// Whether stray non-JSON stdout on exit 0 is read as an allow.
    ///
    /// Gemini's documented "Golden Rule": any unparseable stdout defaults to
    /// Allow and is treated as a `systemMessage`. Batten must keep stdout clean
    /// or exit 2 there.
    pub stdout_must_stay_clean: bool,
}

impl Capabilities {
    /// Whether this host emits `event`.
    #[must_use]
    pub fn emits(&self, event: Event) -> bool {
        self.events.contains(&event)
    }

    /// The event a policy keyed on `event` should actually watch on this host.
    ///
    /// `None` when nothing here stands in for it. The one substitution is the
    /// load-bearing case the survey named: a policy keyed on `TaskCompleted`
    /// degrades to the Stop family, which every surveyed host has. Degrading is
    /// not equivalence — Stop cannot veto anywhere — so a caller still has to
    /// read [`Capabilities::stop_vetoes_completion`] before assuming it can
    /// block. What the substitution buys is *observing* the moment, not
    /// refusing it.
    #[must_use]
    pub fn degrade(&self, event: Event) -> Option<Event> {
        if self.emits(event) {
            return Some(event);
        }
        match event {
            Event::TaskCompleted if self.emits(Event::Stop) => Some(Event::Stop),
            _ => None,
        }
    }
}

/// The events every surveyed host emits — the converged core.
const CONVERGED_EVENTS: &[Event] = &[
    Event::PreTool,
    Event::PostTool,
    Event::Stop,
    Event::SessionStart,
];

/// Claude Code's set: the converged core plus the two it alone offers.
const CLAUDE_EVENTS: &[Event] = &[
    Event::PreTool,
    Event::PostTool,
    Event::Stop,
    Event::SessionStart,
    Event::TaskCompleted,
    Event::ConfigChange,
];

impl Harness {
    /// This host's capability row.
    ///
    /// Every field is a survey finding (CLOUD-209), not a guess. The neutral
    /// `exit-code` adapter declares the converged core: it stands for "some host
    /// whose only channel is an exit status", and claiming a Claude-only event
    /// for it would be claiming something about a host nobody named.
    #[must_use]
    // `match_same_arms` would collapse the rows that happen to agree today.
    // Refused: two hosts whose measured capabilities coincide are still two
    // hosts, and each arm carries the citation for *why* its values are what
    // they are — Codex's `ask` is false because its docs say "parsed but not
    // supported yet", the neutral adapter's because it stands for a host nobody
    // named. Collapsing them would delete those reasons and make a future
    // divergence a structural edit rather than a one-value one.
    #[allow(clippy::match_same_arms)]
    pub const fn capabilities(self) -> Capabilities {
        match self {
            Harness::ClaudeCode => Capabilities {
                events: CLAUDE_EVENTS,
                ask: true,
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
            },
            Harness::Cursor => Capabilities {
                events: CONVERGED_EVENTS,
                // On shell and MCP events; `ask` parses but is unenforced on the
                // generic `preToolUse`, and is coerced to deny on `subagentStart`.
                ask: true,
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: true,
                stdout_must_stay_clean: false,
            },
            Harness::CopilotCli => Capabilities {
                events: CONVERGED_EVENTS,
                ask: true,
                stop_vetoes_completion: false,
                timeout_fails_open: true,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
            },
            Harness::GeminiCli => Capabilities {
                events: CONVERGED_EVENTS,
                ask: false,
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: true,
            },
            Harness::CodexCli => Capabilities {
                events: CONVERGED_EVENTS,
                // Advertised in the output schema, marked "parsed but not
                // supported yet" in the docs. Advertised is not available.
                ask: false,
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
            },
            Harness::ExitCode => Capabilities {
                events: CONVERGED_EVENTS,
                ask: false,
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
            },
        }
    }
}

/// The lifecycle events the core normalizes, whatever a host spells them.
///
/// A vocabulary enum with a `const ALL`, the shape [`Harness`],
/// [`crate::capture::Stream`] and [`crate::rules::RuleKind`] already use, so
/// anything ranging over events is derived rather than re-typed — the golden
/// census in `tests/cli.rs` reads this, which is what stops a new variant from
/// landing with no fixture.
///
/// The set is what the dependent surfaces consume, not everything a host emits:
/// which events a given host offers is the capability table's business
/// (CLOUD-45), and per-host spellings beyond the converged ones below are the
/// shims' (CLOUD-44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Before a tool runs — the only point at which a deny still prevents
    /// anything, and so the only event policy adjudicates.
    PreTool,
    /// After a tool ran. A deny here would refuse something that already
    /// happened, which no host honours and none of them offer.
    PostTool,
    /// End of turn: the reconciliation point the stop gate uses (CLOUD-85).
    Stop,
    /// Start of a session.
    SessionStart,
    /// A task was marked complete. **Claude-only** across the surveyed hosts,
    /// and the one Claude-exclusive capability that is load-bearing here: exit 2
    /// prevents the completion, which is the literal machine form of Batten's
    /// thesis about completion signals. A policy keyed on it degrades to the
    /// Stop family elsewhere (see [`Capabilities::degrade`]).
    TaskCompleted,
    /// A settings file is being edited mid-session. Claude-only; a
    /// self-protection surface no other surveyed host offers.
    ConfigChange,
    /// The host named an event this build does not normalize. Distinct from an
    /// absent one: absent means nobody said, this means somebody said something
    /// we do not know, and the two must not collapse.
    Unrecognized,
}

impl Event {
    /// Every event, so a census is derived rather than hand-maintained.
    pub const ALL: &'static [Event] = &[
        Event::PreTool,
        Event::PostTool,
        Event::Stop,
        Event::SessionStart,
        Event::TaskCompleted,
        Event::ConfigChange,
        Event::Unrecognized,
    ];

    /// The normalized token. Deliberately not a host spelling — a host's own
    /// word for an event travels in [`Envelope::raw_event`] and is echoed back
    /// verbatim, so this one is free to name the concept.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Event::PreTool => "pre-tool",
            Event::PostTool => "post-tool",
            Event::Stop => "stop",
            Event::SessionStart => "session-start",
            Event::TaskCompleted => "task-completed",
            Event::ConfigChange => "config-change",
            Event::Unrecognized => "unrecognized",
        }
    }

    /// Normalize a host's spelling.
    ///
    /// The spellings matched here are the converged ones — Claude Code's, which
    /// Codex CLI and Gemini CLI also ship (CLOUD-210). The residual renames
    /// (Cursor's split camelCase events, Gemini's `BeforeTool`) belong to the
    /// per-host shims in CLOUD-44, not here: normalizing them in the core would
    /// put host-specific vocabulary in the harness-blind layer.
    #[must_use]
    pub fn normalize(raw: &str) -> Event {
        match raw {
            "PreToolUse" => Event::PreTool,
            "PostToolUse" => Event::PostTool,
            "Stop" => Event::Stop,
            "SessionStart" => Event::SessionStart,
            "TaskCompleted" => Event::TaskCompleted,
            "ConfigChange" => Event::ConfigChange,
            _ => Event::Unrecognized,
        }
    }
}

/// The event assumed when a payload names none.
///
/// Conservative on purpose, and the landed behaviour this preserves: a mediation
/// gate that guessed "unrecognized" would stop adjudicating a payload whose host
/// simply omitted the field, turning a missing key into a silent bypass. Guessing
/// pre-tool can only ever over-adjudicate, which is the safe direction.
const ASSUMED_EVENT: &str = "PreToolUse";

/// The normalized hook envelope — the shape the core adjudicates, whatever the
/// host called its fields.
///
/// `raw_event` beside `event` is not two sources of truth: `event` is what
/// policy dispatches on, and `raw_event` is the host's own token, kept so a
/// decision document can echo it back in the host's vocabulary rather than in
/// ours. Normalizing inward and echoing outward are different directions.
///
/// `command` is the shell-shaped projection of `input`, kept as a field so the
/// parser and matcher read one decoded string rather than re-walking the JSON
/// per rule. `input` carries the whole object for the tools that are not
/// shell-shaped, and is **never emitted**: a tool input is among the likeliest
/// places in the engine for a secret to appear (rule 4).
///
/// Stated limit: `cwd` is decoded but not yet consumed, so an absolute or `..`
/// path operand is still compared as written. Resolving one against the repo
/// root is a behaviour change with its own issue, not a side effect of carrying
/// the field the host shims need.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Envelope {
    /// The normalized lifecycle event, which policy dispatches on.
    pub event: Event,
    /// The host's own spelling, echoed back in a decision document.
    pub raw_event: String,
    /// The tool being mediated, e.g. `Bash`.
    pub tool: String,
    /// The tool's whole input object; `Value::Null` when the payload had none.
    pub input: Value,
    /// The command text for shell-shaped tools; empty when the tool has none.
    pub command: String,
    /// The path this call writes, when the tool is one of its host's writers.
    ///
    /// Resolved by the adapter from [`Harness::write_tools`], so the core stays
    /// harness-blind: by the time [`adjudicate`] sees an envelope, "this is a
    /// write, and here is its target" is already a normalized fact rather than
    /// a tool-name comparison the policy layer would have to make.
    ///
    /// `None` for every read, for a shell call, and for a write whose payload
    /// named no path — all three are "nothing to judge here", which is not the
    /// same claim as an empty path.
    pub writes: Option<String>,
    /// The host's working directory, when it reported one.
    pub cwd: Option<PathBuf>,
    /// The host's session id, when it reported one.
    ///
    /// `None` rather than an empty string when absent, because the two are
    /// different claims and [`crate::identity::sequence_fingerprint`] already
    /// hashes them distinctly — that signature *is* the degradation contract,
    /// so a session-less host folds to per-invocation handling by construction
    /// instead of through a second rule invented here.
    pub session: Option<String>,
    /// Whether the host is re-entering a `Stop` hook it already ran.
    ///
    /// Read by the `Stop`-path guards, never by [`adjudicate`] — see
    /// [`field`] for why these three live here rather than in a second decoder.
    pub stop_active: Option<bool>,
    /// The assistant's last message, on the `Stop` event.
    pub last_message: Option<String>,
    /// The path to the session transcript, on the `Stop` event.
    pub transcript: Option<String>,
}

/// The payload fields a shell hook may ask for by name.
///
/// A FIXED ALLOWLIST, never a caller-supplied JSON path (CLOUD-479). The
/// difference is the whole safety argument: a path expression would reach
/// [`Envelope::input`], which is documented above as never emitted because a
/// tool input is among the likeliest places in this engine for a secret to
/// appear (non-negotiable rule 4). An enum cannot name it.
///
/// The set is exactly what the three registered shell hooks read today —
/// `stop-guard`, `contract-drift`, and nothing else. Growing it is a deliberate
/// edit here, which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[non_exhaustive]
pub enum Field {
    /// The host's own event spelling, echoed back untouched.
    ///
    /// UNNORMALIZED on purpose: [`Event`] knows neither `UserPromptSubmit` nor
    /// `PostToolBatch`, and `contract-drift` is wired to two events and echoes
    /// the name into its own reply — a normalized answer would be wrong at one
    /// of them.
    HookEventName,
    /// The host's session id.
    SessionId,
    /// The tool being mediated.
    ToolName,
    /// The command text, for shell-shaped tools.
    Command,
    /// The host's working directory.
    Cwd,
    /// Whether this is a re-entered `Stop` hook.
    StopHookActive,
    /// The assistant's last message.
    ///
    /// The one prose-bearing member, and it is here because `stop-guard`
    /// already receives exactly these bytes by exactly this route — it pipes
    /// them straight to `stop-posture-check`. Moving the read from `jq` to here
    /// changes which process parses the payload, not what flows where; rule 4
    /// governs what a CHECK reports, and this is a decoder, not a verdict.
    LastAssistantMessage,
    /// The path to the session transcript.
    TranscriptPath,
}

impl Field {
    /// This field's value in `envelope`, or `None` when the payload had none.
    ///
    /// Absent and empty are deliberately collapsed to `None` here, because the
    /// caller is a shell script whose `[ -n "$x" ]` cannot tell them apart
    /// anyway — and `jq -r '.x // empty'`, the spelling this replaces, collapses
    /// them identically. Preserving a distinction no consumer can read would be
    /// a difference that only ever surprises someone.
    #[must_use]
    pub fn read(self, envelope: &Envelope) -> Option<String> {
        let value = match self {
            Field::HookEventName => Some(envelope.raw_event.clone()),
            Field::SessionId => envelope.session.clone(),
            Field::ToolName => Some(envelope.tool.clone()),
            Field::Command => Some(envelope.command.clone()),
            Field::Cwd => envelope.cwd.as_ref().map(|path| path.display().to_string()),
            Field::StopHookActive => envelope.stop_active.map(|active| active.to_string()),
            Field::LastAssistantMessage => envelope.last_message.clone(),
            Field::TranscriptPath => envelope.transcript.clone(),
        };
        value.filter(|text| !text.is_empty())
    }
}

/// One payload field, read through the same decoder [`adjudicate`] uses.
///
/// CLOUD-479. Three hook registrations paid ~203ms of `mise` startup per call to
/// do single-digit milliseconds of work, and the obvious fix — invoke them by
/// path — was blocked by one thing: they shell out to `jq`, `mise.toml` pins
/// `jq`, and a by-path invocation does not get mise's env. It would resolve an
/// unpinned `/usr/bin/jq`, and on a container with none the `|| exit 0`
/// fail-open posture would turn a missing parser into a silent allow. A latency
/// fix that converts a pinned dependency into a silent fail-open is a worse
/// defect than the latency.
///
/// So the parser moves into the binary that is already on this path. No new
/// dependency, no second parser: [`decode`] handles BOM stripping and every
/// per-harness alias, and this is a projection of its result.
///
/// Returns `None` for an undecodable payload AND for an absent field, which is
/// the fail-open contract the callers already have — they read an empty answer
/// and allow. The distinction a caller DOES need is "the extractor is missing
/// entirely", and that is not expressible in this return type: it is the
/// launcher's job, loudly, the way `.claude/hooks/batten-hook.sh` reports a
/// missing binary.
#[must_use]
pub fn field(harness: Harness, raw: &str, field: Field) -> Option<String> {
    field.read(&decode(harness, raw)?)
}

/// The adjudication verdict.
///
/// `Deny` carries a [`Refusal`], not a string: by the refusal contract
/// (CLOUD-122) every deny names what refused, why, and what to run instead, and
/// carrying the *value* is what makes that structural — a deny site cannot
/// construct one without stating a [`Fix`]. The text a host reads is
/// [`deny_text`], a projection of the same value, so the two channels this
/// module encodes for cannot disagree about what the refusal said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the mediated call proceed.
    Allow,
    /// Block the mediated call, with an actionable refusal.
    Deny(Refusal),
}

/// Decode a harness payload into the normalized envelope.
///
/// Fail-open by returning `None` for anything that does not decode: absent
/// fields are an allow, never an error. Claude Code's `PreToolUse` shape is
/// `{hook_event_name, tool_name, tool_input: {command, …}, …}`.
#[must_use]
pub fn decode(harness: Harness, raw: &str) -> Option<Envelope> {
    // Strip a leading UTF-8 BOM before anything else, on every host. Cursor is
    // the measured case — its Windows stdin prefixes one, which breaks strict
    // JSON parsers and (staff-confirmed) degraded users' guards to allow-all —
    // but a BOM is never meaningful in any of these payloads, so removing it
    // once here beats remembering which host emits one.
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let value: Value = serde_json::from_str(raw).ok()?;

    let raw_event = value
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or(ASSUMED_EVENT)
        .to_owned();
    let event = normalize_event(harness, &raw_event);

    // Cursor's specialized events carry the operand at top level and no
    // `tool_name`; every other shape nests it under `tool_input`.
    let specialized = harness == Harness::Cursor && cursor_specialized_tool(&raw_event).is_some();
    let input = if specialized {
        cursor_specialized_input(&value)
    } else {
        // Copilot's `toolArgs` is typed `unknown` and its own docs show it
        // stringified, so the parser accepts both an object and a JSON string.
        let named = value
            .get("tool_input")
            .or_else(|| value.get("toolArgs"))
            .cloned()
            .unwrap_or(Value::Null);
        match named {
            Value::String(text) => serde_json::from_str(&text).unwrap_or(Value::String(text)),
            other => other,
        }
    };

    let tool = if specialized {
        cursor_specialized_tool(&raw_event)
            .unwrap_or_default()
            .to_owned()
    } else {
        value
            .get("tool_name")
            .or_else(|| value.get("toolName"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };

    // The write target, resolved here so the core never compares a tool name.
    // `notebook_path` is read alongside `file_path` because `NotebookEdit`
    // spells it differently and a notebook under a protected path is the same
    // write — omitting it would have left one tool in the matcher unjudged,
    // which is the CLOUD-185 shape (the guard was installed and one route
    // around it stayed open).
    let writes = harness
        .write_tools()
        .contains(&tool.as_str())
        .then(|| {
            input
                .pointer("/file_path")
                .or_else(|| input.pointer("/notebook_path"))
                .and_then(Value::as_str)
                .filter(|path| !path.is_empty())
                .map(ToOwned::to_owned)
        })
        .flatten();

    Some(Envelope {
        event,
        raw_event,
        tool,
        command: input
            .pointer("/command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        writes,
        input,
        cwd: value
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            // Cursor omits `cwd` on some non-tool events; its documented
            // fallback is the first workspace root.
            .or_else(|| {
                value
                    .pointer("/workspace_roots/0")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
            }),
        // One session field, three spellings. Empty is treated as absent, so
        // `Some("")` never reaches a consumer that would hash it as a real
        // session.
        session: ["session_id", "sessionId", "conversation_id"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .filter(|id| !id.is_empty())
            .map(ToOwned::to_owned),
        // The three `Stop`-event fields (CLOUD-479). Read by the Stop-path
        // guards through [`field`] and by nothing in [`adjudicate`] — they are
        // here rather than in a second decoder because a second decoder is a
        // second thing to keep in step with the BOM strip and the alias tables
        // above, for no gain. Three `get`s on an already-parsed value.
        stop_active: value.get("stop_hook_active").and_then(Value::as_bool),
        last_message: value
            .get("last_assistant_message")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        transcript: value
            .get("transcript_path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

/// Normalize a host's event spelling, applying that host's rename table.
///
/// The converged spellings live in [`Event::normalize`] — Claude Code's, which
/// Codex CLI and Copilot's `PascalCase` dialect ship verbatim. Only the two hosts
/// that genuinely diverge get a table here, which is what keeps host vocabulary
/// out of the harness-blind core.
fn normalize_event(harness: Harness, raw: &str) -> Event {
    let renamed = match harness {
        // Gemini's names are the only structural gap in an otherwise
        // Claude-identical payload.
        Harness::GeminiCli => match raw {
            "BeforeTool" => Some(Event::PreTool),
            "AfterTool" => Some(Event::PostTool),
            // `AfterAgent` is Gemini's end-of-turn; it is the Stop family's
            // member here even though the word differs.
            "AfterAgent" => Some(Event::Stop),
            _ => None,
        },
        // Cursor splits pre-tool across a generic event and three specialized
        // ones. All four adjudicate at the same moment, so all four normalize to
        // the same concept.
        Harness::Cursor => match raw {
            "preToolUse" | "beforeShellExecution" | "beforeMCPExecution" | "beforeReadFile" => {
                Some(Event::PreTool)
            }
            "afterFileEdit" => Some(Event::PostTool),
            "stop" | "subagentStop" => Some(Event::Stop),
            "sessionStart" => Some(Event::SessionStart),
            _ => None,
        },
        Harness::ClaudeCode | Harness::CopilotCli | Harness::CodexCli | Harness::ExitCode => None,
    };
    renamed.unwrap_or_else(|| Event::normalize(raw))
}

/// The tool name a Cursor specialized event stands for, if it is one.
///
/// These events carry no `tool_name`, so the adapter derives a constant from the
/// event. Deriving rather than defaulting to empty matters: a shape rule matches
/// on the effective program, and an empty tool would make every specialized
/// event look like the same anonymous call.
const fn cursor_specialized_tool(raw_event: &str) -> Option<&'static str> {
    match raw_event.as_bytes() {
        b"beforeShellExecution" => Some("Shell"),
        b"beforeReadFile" => Some("Read"),
        b"beforeMCPExecution" => Some("MCP"),
        _ => None,
    }
}

/// Assemble an `input` object from a Cursor specialized event's top-level fields.
///
/// Only the keys those events document are lifted, so the envelope's `input`
/// carries the operand and nothing incidental from the host frame.
fn cursor_specialized_input(value: &Value) -> Value {
    let mut input = serde_json::Map::new();
    for key in [
        "command",
        "file_path",
        "url",
        "sandbox",
        "tool_name",
        "args",
    ] {
        if let Some(found) = value.get(key) {
            input.insert(key.to_owned(), found.clone());
        }
    }
    Value::Object(input)
}

/// The escape hatch, named once so the boundary and the reason text agree.
pub const BYPASS_ENV: &str = "BATTEN_GH_GUARD_BYPASS";

/// The mediated-call policy this run adjudicates against.
///
/// Built from the *resolved* config (§8), not the committed file alone, so a
/// `batten.local.toml` that **adds** a shape row is a gate the hook actually
/// applies — the raise-only override model is worth nothing at a surface that
/// ignores it — and `--config-from` is inherited for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    shapes: Vec<Rule>,
    fail_on_warning: bool,
    /// Which programs change the world, and what to run instead (CLOUD-36).
    verbs: Vec<MutatingVerb>,
    /// Which paths are guarded (CLOUD-37).
    ///
    /// Crossed with `verbs` this is CLOUD-96's gate. It is a *derived* predicate
    /// rather than `[[rule]]` rows because the two tables are sets: expressing
    /// the cross product as rules would need one row per verb × path pair, and
    /// the config would restate what an intersection already says.
    protected: PathSet,
}

impl Policy {
    /// The policy that denies nothing.
    ///
    /// Not an error state: a repository with no authority, or a bypassed run, has
    /// declared no mediated-call policy, and "nothing declared" means "nothing
    /// denied". Mirrors `Config::declaring_nothing`.
    #[must_use]
    pub fn declaring_nothing() -> Policy {
        Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        }
    }

    /// Take the mediated-call rules out of a resolved config.
    ///
    /// Filters on `scope`, so the tree engine's rules are simply absent here
    /// rather than skipped per-call, and a spawning kind can never reach this
    /// surface — [`RuleKind::scopes`] pairs every spawning kind with
    /// [`RuleScope::Tree`] alone, which is what keeps `hook` structurally unable
    /// to execute a configured command.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when the protected list is malformed
    /// — a `!` entry in an include-only key. Never a deny: a policy that cannot be
    /// read must fail loud, not refuse the call.
    pub fn from_resolved(resolved: &Resolved) -> anyhow::Result<Policy> {
        Ok(Policy {
            shapes: resolved
                .rules
                .iter()
                .filter(|rule| rule.scope == RuleScope::MediatedCall)
                .cloned()
                .collect(),
            fail_on_warning: resolved.fail_on_warning,
            verbs: resolved.verbs.clone(),
            protected: PathSet::includes("protected", &resolved.protected)?,
        })
    }

    /// The receipt names this **command** needs proved, deduplicated.
    ///
    /// Scoped to the command, not to the policy (CLOUD-460). The earlier form
    /// asked only "does any row want receipts", which made one row in
    /// `batten.toml` enough to charge every mediated call: `receipt::verdicts`
    /// runs four git subprocesses (measured ~1.85ms each) plus a read per name,
    /// and it was being paid by `ls`, by `gh pr view`, and by every file edit —
    /// none of which a `pattern = "gh pr ready"` row could ever match.
    ///
    /// It fell inside the ≤100ms budget, so no gate caught it. That is the
    /// shape CLOUD-435 exists to prevent: a ceiling does not notice a fivefold
    /// move underneath it.
    ///
    /// The row selection is [`matching_receipt_rows`] — the same function
    /// [`receipt_rules`] adjudicates with, so what the boundary resolves and
    /// what the core then judges cannot disagree about which rows fire.
    #[must_use]
    pub fn required_checks_for(&self, command: &str) -> Vec<String> {
        let mut names: Vec<String> = matching_receipt_rows(self, command)
            .into_iter()
            .filter_map(|rule| rule.checks.as_ref())
            .flatten()
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Whether this policy can deny anything at all.
    ///
    /// Both halves must be empty. The protected gate needs *both* its tables to
    /// bite, so a repository declaring verbs but no protected paths (or the
    /// reverse) can deny nothing through it — but a shape row alone still can.
    ///
    /// This holds for the write gate too, and deliberately: a write tool is
    /// classified through the same `[[verb]]` table a shell program is, so
    /// "which calls mutate" stays one declared list rather than two.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shapes.is_empty() && (self.verbs.is_empty() || self.protected.is_empty())
    }
}

/// Adjudicate an envelope against the policy.
///
/// Pure: no I/O, no environment, no clock. `bypass` is the caller-resolved
/// escape hatch (the boundary reads [`BYPASS_ENV`]), and the policy arrives as a
/// value, so every verdict is a function of config plus argv and nothing else.
#[must_use]
pub fn adjudicate(
    policy: &Policy,
    envelope: &Envelope,
    bypass: bool,
    receipts: &ReceiptFacts,
    stop: &crate::stop::StopFacts,
) -> Decision {
    // The end-of-turn gate (CLOUD-85), which the note below anticipated: the
    // stop event has its own surface, and this is it. Its inputs arrive as a
    // value for the same reason `receipts` do — this function is contractually
    // pure, and the gate reads git and the findings store. A stop deny is exit 2
    // exactly as a pre-tool deny is; what makes the two distinct is the event,
    // never the code (§7 has no per-verb exception).
    //
    // Before the bypass check, deliberately. `BATTEN_HOOK_BYPASS` says "do not
    // adjudicate this call", and what is adjudicated here is not a call — it is
    // whether the turn's work is finished. A hatch for one mediated command
    // should not also wave through unlanded work.
    if envelope.event == Event::Stop {
        return match stop.refusal() {
            Some(refusal) => Decision::Deny(refusal),
            None => Decision::Allow,
        };
    }
    // Dispatch on the event FIRST, and allow every non-pre-tool one explicitly
    // (CLOUD-43). Before this the field was decoded and never read, so a
    // `PostToolUse` payload carrying a banned command in `tool_input.command`
    // was adjudicated as though the call had not happened yet — and denied.
    // That refusal is meaningless after the fact and is not a decision any host
    // offers at that event, so it could only ever be noise the model was handed
    // as a reason. Allowing here is a decision, not an omission: the events
    // below have their own surfaces (the stop gate is CLOUD-85, the post-tool
    // drain CLOUD-79), and neither is a deny channel.
    if envelope.event != Event::PreTool {
        return Decision::Allow;
    }
    if bypass || policy.is_empty() {
        return Decision::Allow;
    }
    // The write gate, before the command gate and not inside it: a write tool
    // carries no command, so every path below this point used to return Allow
    // for it. That is why the `Write|Edit|MultiEdit|NotebookEdit` matcher was
    // adjudicated by nothing at all — the rows existed, the payload decoded,
    // and `command.is_empty()` sent it home (CLOUD-312).
    //
    // The tool is classified through the SAME `[[verb]]` table a shell program
    // is, rather than through a second list of write tools in config. A `Write`
    // aimed at a protected path and an `echo x >` aimed at it are one predicate
    // — {mutating verb} × {protected path} — and splitting them into two tables
    // is how the two halves come to disagree. It also means the refusal keeps
    // its declared `redirect`, so the consumer's own remedy text survives the
    // move out of bash, which is what CLOUD-312's differential suite asserts.
    if let Some(path) = envelope.writes.as_deref() {
        if let Some(verb) = crate::verbs::classify(&policy.verbs, &envelope.tool) {
            if policy.protected.contains(normalise(path)) {
                return Decision::Deny(protected_refusal(&envelope.tool, path, verb));
            }
        }
    }
    if envelope.command.is_empty() {
        return Decision::Allow;
    }
    // Explicit rows first, then the derived gate: a row a reviewer wrote by hand
    // should be the one they see quoted back, and its reason is more specific
    // than the generic protected-path message.
    //
    // A ban outranks an unmet precondition: if a call is refused outright there
    // is no point telling its author which receipt to go and earn.
    match shape_rules(policy, &envelope.command) {
        Decision::Deny(refusal) => Decision::Deny(refusal),
        Decision::Allow => match receipt_rules(policy, &envelope.command, receipts) {
            Decision::Deny(refusal) => Decision::Deny(refusal),
            Decision::Allow => protected_mutation(policy, &envelope.command),
        },
    }
}

/// The text a host reads for one refusal — the deny's whole projection.
///
/// [`Refusal::render`] is the shared shape; this adds the one thing that is a
/// fact about *mediation* rather than about the refusal, and so has no place in
/// the payload: the escape hatch. `check`'s refusal of a rule it cannot honestly
/// run carries the same [`Refusal`] and no hatch, which is correct — there is
/// nothing to bypass in a read-only run.
#[must_use]
pub fn deny_text(refusal: &Refusal) -> String {
    format!("{} Bypass with {BYPASS_ENV}=1.", refusal.render())
}

/// The first shape row that matches the mediated command, in declaration order.
///
/// Declaration order is the tie-break rather than "most specific wins": a
/// reviewer reads the table top to bottom, and any cleverer precedence would be
/// a rule about rules that the config does not state.
/// The receipt verdicts a mediated call is judged against.
///
/// `None` is **could not look** — no checkout, or an `origin/main` that does
/// not resolve — and allows, which is the fail-open posture every retiring
/// guard has. `Some` map missing a name is treated as [`Validity::Missing`],
/// so a boundary that resolved fewer facts than the policy needs fails closed
/// rather than silently allowing.
pub type ReceiptFacts = Option<std::collections::BTreeMap<String, Validity>>;

/// Deny a call whose declared receipts are not all valid (CLOUD-312).
///
/// The port of `ready-guard`, and the shape of it matters: this refuses a
/// command whose *precondition has not been proved*, not a command that is
/// banned. The same call is allowed the moment the receipt exists, which is why
/// the refusal names the verdict — an operator who reads "stale-head" knows to
/// re-run, where "missing" alone would send them looking for a file.
/// The `receipt` rows whose trigger fires on this command.
///
/// One authority for "does this row apply", shared by the boundary that decides
/// which receipts to resolve and the adjudicator that judges them. Split out
/// because those two answering separately is how a call comes to pay for a
/// receipt no rule would have consulted (CLOUD-460).
fn matching_receipt_rows<'a>(policy: &'a Policy, command: &str) -> Vec<&'a Rule> {
    let mut matched: Vec<&Rule> = Vec::new();
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        let Some(program_index) = effective_program(&tokens) else {
            continue;
        };
        let words: Vec<&str> = tokens[program_index + 1..]
            .iter()
            .copied()
            .filter(|token| !token.starts_with('-'))
            .collect();
        for rule in &policy.shapes {
            if rule.kind != RuleKind::Receipt || !blocks(rule.severity(), policy.fail_on_warning) {
                continue;
            }
            let Some((program, wanted)) = rule.trigger() else {
                continue;
            };
            if tokens[program_index] != program {
                continue;
            }
            if !words
                .windows(wanted.len().max(1))
                .any(|w| w == wanted.as_slice())
            {
                continue;
            }
            if let Some(contains) = rule.contains.as_deref() {
                if !segment.raw.contains(contains) {
                    continue;
                }
            }
            // A command with several segments can match one row twice; the row
            // is still one obligation.
            if !matched.iter().any(|seen| std::ptr::eq(*seen, rule)) {
                matched.push(rule);
            }
        }
    }
    matched
}

fn receipt_rules(policy: &Policy, command: &str, facts: &ReceiptFacts) -> Decision {
    // No facts means the boundary could not look. Allow: a guard that cannot
    // read its own precondition must not become the reason work stops.
    let Some(facts) = facts.as_ref() else {
        return Decision::Allow;
    };
    for rule in matching_receipt_rows(policy, command) {
        // Every named receipt must be valid. An unresolved name is Missing,
        // never absent-and-therefore-fine: a boundary that answered for
        // fewer checks than the row requires has not proved the precondition.
        for check in rule.checks.iter().flatten() {
            let verdict = facts.get(check).copied().unwrap_or(Validity::Missing);
            if verdict != Validity::Valid {
                return Decision::Deny(receipt_refusal(rule, check, verdict));
            }
        }
    }
    Decision::Allow
}

/// Compose a receipt row's refusal, naming the check and what is wrong with it.
///
/// The verdict is in the cause rather than the fix because it is a *finding*
/// about the receipt, and the remedy is the row's declared `reason` — the same
/// contract a shape row keeps (CLOUD-122). Pointer-only: the check name and a
/// verdict token, never the receipt's contents.
fn receipt_refusal(rule: &Rule, check: &str, verdict: Validity) -> Refusal {
    let cause = match verdict {
        Validity::Missing => {
            format!("`{check}` has recorded no receipt for this commit in this checkout")
        }
        Validity::StaleHead => format!(
            "the `{check}` receipt was taken against a different commit — an amend or a rebase replaced the bytes it validated"
        ),
        Validity::StaleMain => format!(
            "the `{check}` receipt was taken against an older origin/main, which has since moved"
        ),
        // Not reachable from the caller, which only refuses a non-valid
        // verdict. Stated rather than unwrapped so the match stays total.
        Validity::Valid => format!("`{check}` is valid"),
    };
    Refusal::new(&rule.id, cause, Fix::declared(rule.reason.as_deref()))
}

fn shape_rules(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        let Some(program_index) = effective_program(&tokens) else {
            continue;
        };
        // Subcommand words with flags dropped. A value-taking flag leaves its
        // value behind, but the blocked words are adjacent, so that never hides
        // a real match (`gh -R o/r pr merge` still matches; `gh pr view
        // merge-fix` never does).
        let words: Vec<&str> = tokens[program_index + 1..]
            .iter()
            .copied()
            .filter(|token| !token.starts_with('-'))
            .collect();
        for rule in &policy.shapes {
            // Kind-filtered, not scope-filtered: `receipt` rows are
            // `mediated_call`-scoped too and carry a `pattern`, so without this
            // they would read as shape rules and refuse their trigger
            // unconditionally — turning a precondition into a ban.
            if rule.kind != RuleKind::Shape {
                continue;
            }
            if !blocks(rule.severity(), policy.fail_on_warning) {
                continue;
            }
            let Some((program, wanted)) = rule.shape() else {
                continue;
            };
            if tokens[program_index] != program {
                continue;
            }
            if !words
                .windows(wanted.len().max(1))
                .any(|w| w == wanted.as_slice())
            {
                continue;
            }
            // The extra literal is matched against the segment as written,
            // because the thing it looks for lives inside a quoted argument and
            // so is not one of the words above.
            if let Some(needle) = rule.contains.as_deref() {
                if !segment.raw.contains(needle) {
                    continue;
                }
            }
            return Decision::Deny(shape_refusal(rule));
        }
    }
    Decision::Allow
}

/// The id the derived protected-path gate denies under.
///
/// It has no `[[rule]]` row to name — the gate is an intersection of two config
/// tables, not a row — so the id is declared once here and used by both the
/// refusal and its tests, which is what stops the two from drifting.
pub const PROTECTED_MUTATION: &str = "protected-mutation";

/// The pseudo-programs a shell redirect is reported as.
///
/// A truncating redirect mutates a file with no program to classify: in
/// `cat x > p` the program is `cat`, which mutates nothing. So the operator is
/// surfaced *as if* it were a program, and a consumer that wants truncation
/// gated declares `verb = ">"` in `[[verb]]` like any other.
///
/// Declared as a constant because it is a crate↔config contract: a consumer
/// writing `verb = "redirect"` would get silence, and nothing else in the tree
/// would say why. `tests::the_redirect_pseudo_program_token_is_declared_not_implied`
/// is the gate.
pub const REDIRECT_VERBS: &[&str] = &[">", ">>"];

/// Deny a declared mutating verb aimed at a protected path (CLOUD-96).
///
/// The predicate is an intersection and nothing more: `{program ∈ [[verb]]} ×
/// {path ∈ protected}`. Both tables are the consumer's, so the crate holds no
/// path literal and no verb name (`tests::the_source_bakes_in_no_protected_path`).
fn protected_mutation(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        // Operands of the effective program, plus any redirect target. Both are
        // candidates; a redirect needs no program at all.
        let mut candidates: Vec<(&str, &str)> = Vec::new();
        if let Some(index) = effective_program(&tokens) {
            let program = tokens[index];
            for operand in operands(&tokens, index + 1) {
                candidates.push((program, operand));
            }
        }
        candidates.extend(redirect_targets(&tokens));

        for (program, path) in candidates {
            let Some(verb) = crate::verbs::classify(&policy.verbs, program) else {
                continue;
            };
            if !policy.protected.contains(normalise(path)) {
                continue;
            }
            return Decision::Deny(protected_refusal(program, path, verb));
        }
    }
    Decision::Allow
}

/// The non-flag, non-env operands of a segment, from `start`.
///
/// A `--` ends option parsing, and everything after it is an operand even if it
/// begins with a dash — the shape `rm -- -weird-name` uses, which a naive flag
/// filter would drop and so fail to guard.
fn operands<'a>(tokens: &[&'a str], start: usize) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut literal = false;
    for token in tokens.iter().skip(start) {
        if !literal && *token == "--" {
            literal = true;
            continue;
        }
        if !literal && (token.starts_with('-') || is_env_assignment(token)) {
            continue;
        }
        if REDIRECT_VERBS.iter().any(|op| token.starts_with(op)) {
            continue;
        }
        out.push(*token);
    }
    out
}

/// The `(operator, target)` pairs a segment's shell redirects name.
///
/// Handles the glued form (`>p`) and the separated one (`> p`), and normalises a
/// numbered descriptor (`2>p`). **Not** `&>`: [`segments`] splits on an unquoted
/// `&`, so that form never arrives here as one token — the `> p` remainder
/// becomes its own segment and is caught there instead.
fn redirect_targets<'a>(tokens: &[&'a str]) -> Vec<(&'static str, &'a str)> {
    let mut out = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        // A leading descriptor is shell syntax, not part of the operator.
        let bare = token.trim_start_matches(|c: char| c.is_ascii_digit());
        // Longest first, so `>>` is never read as `>` with a stray `>` target.
        let Some(op) = REDIRECT_VERBS
            .iter()
            .find(|op| bare.starts_with(**op))
            .copied()
        else {
            continue;
        };
        let target = bare.trim_start_matches('>').trim();
        if target.is_empty() {
            if let Some(next) = tokens.get(index + 1) {
                out.push((op, *next));
            }
        } else {
            out.push((op, target));
        }
    }
    out
}

/// Strip a leading `./`, which names the same path.
///
/// Deliberately the *only* normalisation. An absolute path, a `..` traversal, or
/// a `~` are not resolved against the repo root — `Envelope` carries no `cwd`, so
/// there is nothing honest to resolve against. Every such miss under-denies,
/// which is the sanctioned direction, and
/// `tests::an_absolute_path_is_not_resolved_against_the_repo_root` pins the limit
/// so it cannot change silently.
fn normalise(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

/// Compose the protected-path refusal: what was aimed where, and what to run.
///
/// The path is a *pointer* and rule 4 permits it — it is what the caller already
/// typed, and naming it is the difference between an actionable refusal and a
/// riddle. The file's contents never appear.
///
/// The fix is the verb's own declared `redirect`, and [`Fix::None`] where the
/// consumer declared none — stated rather than papered over with a catch-all
/// that pretends to be specific. That absence is the seam CLOUD-280 fills: the
/// useful redirect is a property of what is being protected, not of the verb
/// reaching for it, so a per-path-class table lands *here* and this fallback
/// becomes the third tier rather than the second.
fn protected_refusal(program: &str, path: &str, verb: &MutatingVerb) -> Refusal {
    Refusal::new(
        PROTECTED_MUTATION,
        format!("`{program}` targets the protected path {path}"),
        Fix::declared(verb.redirect.as_deref()),
    )
}

/// Whether a rule at this severity blocks, once promotion has been applied.
///
/// Routed through [`severity`] rather than matched here, so `allow` / `warn` /
/// `deny` mean the same thing at the mediation channel as in the checks
/// pipeline. One interpretation, two surfaces.
fn blocks(severity: RuleSeverity, fail_on_warning: bool) -> bool {
    severity::promote(severity::row_for_rule(severity).report, fail_on_warning) == ReportLevel::Fail
}

/// Compose a shape row's refusal: the rule that refused, why, and what to run.
///
/// Pointer-only (rule 4) — it names the rule and the fix, never the mediated
/// command, which is the caller's own text and could carry anything.
///
/// **The row's `reason` column is the fix**, which looks like a liberty and is
/// not: [`RuleKind::Shape`] *requires* that column
/// ([`crate::rules::RuleKind::requires`]) and it is documented as "why this rule
/// refuses, **and what to do instead** — the deny's whole text". So a shape deny
/// carries a declared remedy by construction, with no new config column, and the
/// crate supplies the cause clause it was never going to get from a consumer.
/// Splitting the column into a separate `reason` and `fix` — and the `--fix`
/// apply affordance that rides on it — is CLOUD-215's, deliberately not
/// pre-empted here. [`Fix::declared`] is what keeps a row whose reason is somehow
/// blank from rendering a fix clause that says nothing.
///
/// [`RuleKind::Shape`]: crate::rules::RuleKind::Shape
fn shape_refusal(rule: &Rule) -> Refusal {
    let mut cause = "the mediated call matches a refused command shape".to_owned();
    if let Some(url) = rule.policy_url.as_deref() {
        cause.push_str(". See ");
        cause.push_str(url);
    }
    Refusal::new(&rule.id, cause, Fix::declared(rule.reason.as_deref()))
}

/// One shell-separated span of a mediated command, in the two forms policy needs.
///
/// `words` is the span split into arguments with quoting resolved, so a quoted
/// operand survives as a single **word** rather than being thrown away. `raw` is
/// the same span exactly as written, for the one kind of predicate that must
/// look *inside* a quoted span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    /// The span's arguments, quotes resolved and escapes applied.
    words: Vec<String>,
    /// The span exactly as written, quotes and all.
    raw: String,
}

/// Split a command into shell-separated segments, resolving quotes as we go.
///
/// The earlier version replaced each quoted span with the literal sentinel
/// `QUOTED`. That got the `gh` policy right — `git commit -m "gh pr merge"` must
/// not read as an invocation — but it discarded the span's *contents*, so a path
/// gate could not see `rm "some/guarded path"` at all: the operand had become
/// the word `QUOTED`. Quoting a path is the ordinary way to write one with a
/// space in it, so that hole is the shape of a common, legitimate spelling
/// rather than an adversarial one (CLOUD-269, the same class as CLOUD-181).
///
/// Keeping the span as one word preserves every verdict the sentinel bought: a
/// quoted `gh pr merge` is a single word, and one word never equals the adjacent
/// pair the policy matches on. It tightens exactly one case — `gh "pr" "merge"`,
/// a real invocation, now denies.
///
/// **Bounds, deliberate.** This is a pre-execution textual gate, not a shell:
/// variable expansion, command substitution, and globbing all hide operands from
/// it, and nothing here pretends otherwise. Every such miss under-denies, which
/// is the sanctioned direction. An unterminated quote runs to the end of the
/// command and keeps its tail as one word.
fn segments(command: &str) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut has_word = false;
    let mut raw = String::new();
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' => {
                let quote = c;
                raw.push(c);
                // An empty `""` is still an argument, so the word exists the
                // moment the quote opens.
                has_word = true;
                while let Some(inner) = chars.next() {
                    raw.push(inner);
                    if inner == quote {
                        break;
                    }
                    // Inside single quotes a backslash is literal; inside double
                    // quotes it escapes only this handful. Written without a
                    // let-chain: those are unstable at the crate's 1.85 MSRV,
                    // and a newer local toolchain compiles them happily while
                    // `cross-check` does not.
                    if quote == '"'
                        && inner == '\\'
                        && chars
                            .peek()
                            .is_some_and(|next| matches!(*next, '"' | '\\' | '$' | '`'))
                    {
                        if let Some(next) = chars.next() {
                            raw.push(next);
                            word.push(next);
                        }
                        continue;
                    }
                    word.push(inner);
                }
            }
            '\\' => {
                raw.push(c);
                if let Some(next) = chars.next() {
                    raw.push(next);
                    word.push(next);
                    has_word = true;
                }
            }
            '&' | '|' | ';' => {
                // `&&` and `||` are one separator, not two.
                if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                    chars.next();
                }
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
                if !words.is_empty() {
                    out.push(Segment {
                        words: std::mem::take(&mut words),
                        raw: raw.trim().to_owned(),
                    });
                }
                raw.clear();
            }
            c if c.is_whitespace() => {
                raw.push(c);
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
            }
            _ => {
                raw.push(c);
                word.push(c);
                has_word = true;
            }
        }
    }
    if has_word {
        words.push(word);
    }
    if !words.is_empty() {
        out.push(Segment {
            words,
            raw: raw.trim().to_owned(),
        });
    }
    out
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

/// Cursor's deny body.
///
/// A different shape for a different reason than Claude's: Cursor documents no
/// meaning for stderr at all, so this is the **only** channel a reason can travel
/// on. `user_message` and `agent_message` are its documented fields, and both
/// carry the same text — the human and the model are being told the same thing,
/// and a refusal that told them different things would be two contracts.
#[derive(Serialize)]
struct CursorDeny<'a> {
    permission: &'a str,
    #[serde(rename = "user_message")]
    user_message: &'a str,
    #[serde(rename = "agent_message")]
    agent_message: &'a str,
}

/// Encode a deny for the Cursor adapter.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_cursor_deny(reason: &str) -> serde_json::Result<String> {
    serde_json::to_string(&CursorDeny {
        permission: "deny",
        user_message: reason,
        agent_message: reason,
    })
}

/// Encode a deny body for `harness`, when that host reads one.
///
/// `None` means the host's channel is the exit code alone and the reason belongs
/// on stderr — the neutral contract, and what Copilot, Gemini and Codex all read.
///
/// # Errors
///
/// Serialization of these fixed shapes cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_deny(
    harness: Harness,
    event: &str,
    reason: &str,
) -> serde_json::Result<Option<String>> {
    match harness {
        Harness::ClaudeCode => encode_claude_deny(event, reason).map(Some),
        Harness::Cursor => encode_cursor_deny(reason).map(Some),
        Harness::CopilotCli | Harness::GeminiCli | Harness::CodexCli | Harness::ExitCode => {
            Ok(None)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn shape(id: &str, pattern: &str, contains: Option<&str>) -> Rule {
        Rule {
            id: id.to_owned(),
            kind: crate::rules::RuleKind::Shape,
            glob: None,
            severity: Some(RuleSeverity::Deny),
            scope: RuleScope::MediatedCall,
            pattern: Some(pattern.to_owned()),
            regex: None,
            exclude: None,
            contains: contains.map(ToOwned::to_owned),
            reason: Some(format!("use the sanctioned path for {id}")),
            policy_url: None,
            check: None,
            fix: None,
            run: None,
            verbatim: None,
            identity_key: None,
            direction: None,
            base: None,
            criteria: None,
            tier: None,
            // A shape rule never reaches the findings store, so it is refused
            // the remediation column (CLOUD-81).
            no_fix_reason: None,
            checks: None,
            key: None,
        }
    }

    /// The `gh` lifecycle table as config, standing in for the rows this repo's
    /// own `batten.toml` now carries. The policy left the crate in CLOUD-48, so
    /// these tests supply it rather than assert against a baked-in table.
    fn verb(name: &str, redirect: Option<&str>) -> MutatingVerb {
        MutatingVerb {
            verb: name.to_owned(),
            effect: crate::effect::Effect::Destructive,
            redirect: redirect.map(ToOwned::to_owned),
        }
    }

    /// A policy with the CLOUD-96 cross product declared: two mutating verbs and
    /// one protected glob. Both tables are the consumer's, so a test supplies
    /// them exactly as a `batten.toml` would.
    fn protected_policy(verbs: Vec<MutatingVerb>) -> Policy {
        Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes(
                "protected",
                &[".serena/memories/**".to_owned(), "batten.toml".to_owned()],
            )
            .expect("the fixture protected set is well formed"),
        }
    }

    fn guarded(command: &str) -> Decision {
        adjudicate(
            &protected_policy(vec![
                verb("rm", Some("restore it with git")),
                verb("mv", None),
                verb(">", Some("write through the surface that owns it")),
            ]),
            &envelope(command),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    fn gh_policy() -> Policy {
        Policy {
            verbs: Vec::new(),
            protected: PathSet::empty(),
            shapes: vec![
                shape("gh-pr-merge", "gh pr merge", None),
                shape(
                    "gh-pr-comment-fast-forward",
                    "gh pr comment",
                    Some("fast-forward"),
                ),
                shape("gh-pr-checks", "gh pr checks", None),
                shape("gh-run-watch", "gh run watch", None),
            ],
            fail_on_warning: false,
        }
    }

    fn envelope(command: &str) -> Envelope {
        envelope_at(Event::PreTool, command)
    }

    fn envelope_at(event: Event, command: &str) -> Envelope {
        Envelope {
            event,
            raw_event: ASSUMED_EVENT.to_owned(),
            tool: "Bash".to_owned(),
            input: Value::Null,
            command: command.to_owned(),
            writes: None,
            cwd: None,
            session: None,
            // The Stop-path fields (CLOUD-479) are absent on a PreTool envelope,
            // which is the honest shape rather than a filler value.
            stop_active: None,
            last_message: None,
            transcript: None,
        }
    }

    /// A write-tool envelope: no command, a target path, as the adapter decodes
    /// one. The unit tests build it directly so the write gate is exercised
    /// without a harness in the way; `tests/cli.rs` covers the decode end.
    fn write_envelope(tool: &str, path: &str) -> Envelope {
        Envelope {
            event: Event::PreTool,
            raw_event: ASSUMED_EVENT.to_owned(),
            tool: tool.to_owned(),
            input: Value::Null,
            command: String::new(),
            writes: Some(path.to_owned()),
            cwd: None,
            session: None,
            stop_active: None,
            last_message: None,
            transcript: None,
        }
    }

    fn adjudicate_command(command: &str) -> Decision {
        adjudicate(
            &gh_policy(),
            &envelope(command),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    fn is_deny(command: &str) -> bool {
        matches!(adjudicate_command(command), Decision::Deny(_))
    }

    /// The text a host would read for a deny — what every assertion below reads.
    ///
    /// Since CLOUD-122 a deny carries a [`Refusal`] rather than a string, and the
    /// string is a projection. Asserting over the projection rather than over the
    /// struct's fields is deliberate: the projection is what reaches the model,
    /// so a change that kept every field and dropped the fix clause would still
    /// fail here.
    fn denial_text(decision: Decision) -> String {
        match decision {
            Decision::Deny(refusal) => deny_text(&refusal),
            Decision::Allow => panic!("expected a deny"),
        }
    }

    /// The refusal a deny carries, for the assertions that are about the value
    /// rather than its rendering.
    fn denial(decision: Decision) -> Refusal {
        match decision {
            Decision::Deny(refusal) => refusal,
            Decision::Allow => panic!("expected a deny"),
        }
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
    fn words_survive_quoting_while_a_quoted_span_is_never_a_command() {
        // Both halves of CLOUD-269 in one assertion pair. The span stays a
        // single WORD — so a path gate can read it, which the `QUOTED` sentinel
        // made impossible — and being one word is also exactly why it still
        // cannot match the adjacent pair the policy looks for.
        let parsed = segments("git commit -m \"gh pr merge\"");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].words,
            ["git", "commit", "-m", "gh pr merge"],
            "the quoted span is one word, contents intact"
        );
        assert!(!is_deny("git commit -m \"gh pr merge\""));
    }

    #[test]
    fn a_quoted_separator_does_not_split_a_segment() {
        let parsed = segments("echo \"x; gh pr merge\"");
        assert_eq!(parsed.len(), 1, "the `;` is inside quotes");
        assert_eq!(parsed[0].words, ["echo", "x; gh pr merge"]);
        assert!(!is_deny("echo \"x; gh pr merge\""));
    }

    #[test]
    fn a_quoted_operand_keeps_its_contents_for_a_path_gate() {
        // The case the sentinel form could not see at all: under `QUOTED` this
        // command carried no path token, so a protected-path gate had nothing
        // to match (CLOUD-96).
        let parsed = segments("rm \".serena/memories/x.md\"");
        assert_eq!(parsed[0].words, ["rm", ".serena/memories/x.md"]);
    }

    #[test]
    fn a_backslash_escape_keeps_one_word() {
        let parsed = segments("rm foo\\ bar.md");
        assert_eq!(parsed[0].words, ["rm", "foo bar.md"]);
    }

    #[test]
    fn a_quoted_invocation_is_still_an_invocation() {
        // The one intended tightening: a real `gh pr merge`, spelled with
        // quotes, that the sentinel form allowed through.
        assert!(is_deny("gh \"pr\" \"merge\""));
    }

    #[test]
    fn the_raw_text_is_scoped_to_its_own_segment() {
        // The directive predicate reads raw text because the directive lives
        // inside a quoted `--body`. Scoping it to the segment is what stops an
        // unrelated earlier mention from making a later comment look like the
        // landing directive.
        assert!(is_deny("gh pr comment 7 --body /fast-forward"));
        assert!(!is_deny(
            "echo fast-forward && gh pr comment 7 --body thanks"
        ));
    }

    #[test]
    fn an_unterminated_quote_keeps_its_tail_as_one_word() {
        let parsed = segments("rm \"unclosed path");
        assert_eq!(parsed[0].words, ["rm", "unclosed path"]);
    }

    #[test]
    fn a_denied_shape_in_any_segment_is_a_deny() {
        assert!(is_deny("git push && gh pr merge 42"));
    }

    #[test]
    fn bypass_allows_everything() {
        assert_eq!(
            adjudicate(
                &gh_policy(),
                &envelope("gh pr merge"),
                true,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn decode_reads_the_claude_payload() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr merge"}}"#;
        let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
        assert_eq!(envelope.command, "gh pr merge");
        assert_eq!(envelope.tool, "Bash");
    }

    #[test]
    fn decode_carries_cwd_session_and_the_whole_input() {
        let raw = r#"{"hook_event_name":"PreToolUse","session_id":"s1","cwd":"/w/r",
                      "tool_name":"Edit","tool_input":{"file_path":"/w/r/a.rs","command":"x"}}"#;
        let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
        assert_eq!(envelope.session.as_deref(), Some("s1"));
        assert_eq!(envelope.cwd, Some(PathBuf::from("/w/r")));
        // The whole object, not only the shell projection: a tool that is not
        // shell-shaped has its arguments here and nowhere else, which is what
        // CLOUD-44/45/79/91 read.
        assert_eq!(
            envelope.input.get("file_path").and_then(Value::as_str),
            Some("/w/r/a.rs")
        );
        assert_eq!(envelope.command, "x");
    }

    #[test]
    fn an_absent_or_empty_session_is_none_never_some_empty() {
        // `identity::sequence_fingerprint` hashes `None` and `Some("")`
        // distinctly, so letting an empty string through would mint a second
        // identity for "no session" and split a finding in two.
        for raw in [
            r#"{"hook_event_name":"PreToolUse"}"#,
            r#"{"hook_event_name":"PreToolUse","session_id":""}"#,
        ] {
            let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
            assert_eq!(envelope.session, None, "raw: {raw}");
        }
    }

    #[test]
    fn every_event_normalizes_and_round_trips_its_token() {
        // Totality over the vocabulary: a variant added with no `as_str` arm
        // would not compile, but one added with a duplicate token would, and
        // that silently merges two events in any census keyed on the string.
        let mut tokens: Vec<&str> = Event::ALL.iter().map(|event| event.as_str()).collect();
        tokens.sort_unstable();
        let unique = {
            let mut copy = tokens.clone();
            copy.dedup();
            copy
        };
        assert_eq!(tokens, unique, "two events share a token");
        assert_eq!(Event::normalize("PreToolUse"), Event::PreTool);
        assert_eq!(Event::normalize("PostToolUse"), Event::PostTool);
        assert_eq!(Event::normalize("Stop"), Event::Stop);
        assert_eq!(Event::normalize("SessionStart"), Event::SessionStart);
        // Unknown is a decision, not a fallback into the adjudicated event.
        assert_eq!(Event::normalize("BeforeTool"), Event::Unrecognized);
        assert_eq!(Event::normalize(""), Event::Unrecognized);
    }

    #[test]
    fn a_payload_naming_no_event_is_still_adjudicated() {
        // The assumed event, and why it is not `Unrecognized`: a host that omits
        // the field would otherwise turn a missing key into a silent bypass of
        // every rule. Over-adjudicating is the safe direction.
        let raw = r#"{"tool_name":"Bash","tool_input":{"command":"gh pr merge"}}"#;
        let envelope = decode(Harness::ClaudeCode, raw).expect("decodes");
        assert_eq!(envelope.event, Event::PreTool);
        assert!(matches!(
            adjudicate(
                &gh_policy(),
                &envelope,
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn no_event_but_pre_tool_reaches_the_matcher() {
        // The correctness fix, in-module: the same banned command is a deny
        // before the call and an allow at every other event. Ranged over
        // `Event::ALL` so a new variant defaults to the safe answer or fails.
        for &event in Event::ALL {
            let decision = adjudicate(
                &gh_policy(),
                &envelope_at(event, "gh pr merge 42"),
                false,
                &None,
                &crate::stop::StopFacts::default(),
            );
            if event == Event::PreTool {
                assert!(matches!(decision, Decision::Deny(_)), "{event:?}");
            } else {
                assert_eq!(decision, Decision::Allow, "{event:?}");
            }
        }
    }

    #[test]
    fn decode_fails_open_on_junk() {
        assert_eq!(decode(Harness::ClaudeCode, "not json"), None);
        // A payload with no command decodes to an empty command, which
        // adjudicates to Allow rather than erroring.
        let envelope = decode(Harness::ClaudeCode, "{}").expect("decodes");
        assert_eq!(
            adjudicate(
                &gh_policy(),
                &envelope,
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn an_empty_policy_denies_nothing() {
        // The default state, and the one most invocations are in: `hook` is
        // registered once and mediates calls in directories that declare no
        // policy at all.
        assert_eq!(
            adjudicate(
                &Policy::declaring_nothing(),
                &envelope("gh pr merge 42"),
                false,
                &None,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_deny_names_the_rule_and_its_reason() {
        // Acceptance (c). The id is what a reviewer greps for in `batten.toml`;
        // the reason is what the model acts on.
        let reason = denial_text(adjudicate_command("gh pr merge 42"));
        assert!(reason.contains("gh-pr-merge"), "names the rule: {reason}");
        assert!(reason.contains("sanctioned path"), "names why: {reason}");
        assert!(reason.contains(BYPASS_ENV), "names the hatch: {reason}");
    }

    #[test]
    fn a_shape_denys_fix_is_the_rows_declared_remedy() {
        // CLOUD-122's contract at the shape path. `reason` is a REQUIRED column
        // on this kind and is documented as "what to do instead", so a shape deny
        // carries a declared fix by construction — no new column, and no deny
        // site left free to ship a bare "no".
        let refusal = denial(adjudicate_command("gh pr merge 42"));
        assert_eq!(refusal.rule(), "gh-pr-merge");
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("use the sanctioned path for gh-pr-merge"),
            "the row's declared remedy is the fix pointer"
        );
    }

    #[test]
    fn the_deny_never_echoes_the_mediated_command() {
        // Rule 4 at the mediation channel. The command is the caller's own text
        // and can carry anything — a token, a path, a customer name — so a deny
        // names the policy that refused, never the thing refused.
        let secret = "gh pr merge --repo o/r-SENTINEL-9f3a";
        let reason = denial_text(adjudicate_command(secret));
        assert!(
            !reason.contains("SENTINEL"),
            "the deny echoed the mediated command: {reason}"
        );
    }

    #[test]
    fn a_shape_rule_at_allow_is_configured_off() {
        // `allow` is cargo-deny's "this rule is off", and it must mean the same
        // thing here as in the checks pipeline — that is what routing through
        // `severity::promote` buys.
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.severity = Some(RuleSeverity::Allow);
        let policy = Policy {
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(
                &policy,
                &envelope("gh pr merge 42"),
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn a_warn_shape_rule_blocks_only_once_promotion_is_on() {
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.severity = Some(RuleSeverity::Warn);
        let call = envelope("gh pr merge 42");

        let advisory = Policy {
            shapes: vec![rule.clone()],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(
                &advisory,
                &call,
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow,
            "a warn row does not block a mediated call on its own"
        );

        let promoted = Policy {
            shapes: vec![rule],
            fail_on_warning: true,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        assert!(
            matches!(
                adjudicate(
                    &promoted,
                    &call,
                    false,
                    &None,
                    &crate::stop::StopFacts::default()
                ),
                Decision::Deny(_)
            ),
            "promotion applies at the mediation channel too"
        );
    }

    #[test]
    fn the_first_matching_row_wins_in_declaration_order() {
        // Declaration order, not "most specific": a reviewer reads the table top
        // to bottom, and any cleverer precedence would be a rule about rules the
        // config never states.
        let policy = Policy {
            shapes: vec![
                shape("first", "gh pr merge", None),
                shape("second", "gh pr merge", None),
            ],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        ));
        assert!(reason.contains("first"), "got: {reason}");
    }

    #[test]
    fn an_extra_literal_condition_is_matched_against_the_command_as_written() {
        // `contains` exists for exactly this pair: the directive lives inside a
        // quoted argument, so it is not one of the words the shape matches.
        assert!(matches!(
            adjudicate_command("gh pr comment 7 --body /fast-forward"),
            Decision::Deny(_)
        ));
        assert_eq!(
            adjudicate_command("gh pr comment 7 --body thanks"),
            Decision::Allow,
            "an ordinary comment is not the lifecycle"
        );
    }

    #[test]
    fn a_policy_url_rides_the_deny_when_declared() {
        let mut rule = shape("gh-pr-merge", "gh pr merge", None);
        rule.policy_url = Some("https://example.invalid/policy".to_owned());
        let policy = Policy {
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        ));
        assert!(reason.contains("example.invalid/policy"), "got: {reason}");
    }

    #[test]
    fn a_mutating_verb_against_a_protected_path_is_denied() {
        // The incident this gate is written from: an agent reaching for `rm` on
        // its own managed state instead of the surface that owns it.
        assert!(matches!(
            guarded("rm .serena/memories/core.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_same_verb_against_an_unprotected_path_is_allowed() {
        assert_eq!(guarded("rm target/debug/scratch"), Decision::Allow);
    }

    /// The write gate's policy: the same two consumer tables, with the write
    /// TOOL declared as a mutating verb the way `batten.toml` declares it.
    fn write_guarded(tool: &str, path: &str) -> Decision {
        adjudicate(
            &protected_policy(vec![
                verb("rm", Some("restore it with git")),
                verb("Write", Some("use the surface that owns the file")),
            ]),
            &write_envelope(tool, path),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    /// A policy with one receipt row, as `batten.toml` declares it.
    fn receipt_policy() -> Policy {
        let mut rule = shape("ready-needs-receipts", "gh pr ready", None);
        rule.kind = RuleKind::Receipt;
        rule.reason = Some("run verify then linear-check, or just land".to_owned());
        rule.checks = Some(vec!["verify".to_owned(), "linear-check".to_owned()]);
        Policy {
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
        }
    }

    /// The resolved half of [`ReceiptFacts`] — what a boundary that COULD look
    /// hands in. Wrapped in `Some` at the call site, so the distinction between
    /// "looked and found nothing" and "could not look" stays visible in each
    /// case rather than hiding inside a helper.
    fn resolved(pairs: &[(&str, Validity)]) -> std::collections::BTreeMap<String, Validity> {
        pairs
            .iter()
            .map(|(name, verdict)| ((*name).to_owned(), *verdict))
            .collect()
    }

    fn adjudicate_ready(facts: &ReceiptFacts) -> Decision {
        adjudicate(
            &receipt_policy(),
            &envelope("gh pr ready 42"),
            false,
            facts,
            &crate::stop::StopFacts::default(),
        )
    }

    // --- what the boundary resolves (CLOUD-460) -----------------------------

    #[test]
    fn a_command_no_receipt_row_matches_resolves_no_checks() {
        // THE regression case, and the only one that fails on the old
        // behaviour: `required_checks` asked the policy, not the command, so a
        // single row in `batten.toml` charged every mediated call four git
        // subprocesses — `gh pr view`, `ls`, every file edit. A test that only
        // asserted the positive below passes on the eager form and proves
        // nothing.
        assert!(
            receipt_policy()
                .required_checks_for("gh pr view 42")
                .is_empty(),
            "a command no receipt row matches must resolve nothing"
        );
    }

    #[test]
    fn a_write_resolves_no_checks_because_it_carries_no_command() {
        // The write matcher pays the same toll otherwise, and no receipt row
        // has a write trigger today.
        assert!(receipt_policy().required_checks_for("").is_empty());
    }

    #[test]
    fn a_matching_command_resolves_exactly_the_rows_checks() {
        assert_eq!(
            receipt_policy().required_checks_for("gh pr ready 42"),
            vec!["linear-check".to_owned(), "verify".to_owned()],
        );
    }

    #[test]
    fn a_row_matched_by_two_segments_is_still_one_obligation() {
        // Deduplicated by row, not by name, so a command naming the same
        // trigger twice does not resolve the same receipt twice.
        assert_eq!(
            receipt_policy().required_checks_for("gh pr ready 1 && gh pr ready 2"),
            vec!["linear-check".to_owned(), "verify".to_owned()],
        );
    }

    #[test]
    fn a_receipt_row_fires_at_all() {
        // The regression this test exists for, found by running the binary
        // rather than by reading the code: `Rule::shape` returns None unless
        // the kind is `Shape`, so a receipt row matched NOTHING and allowed
        // every call — a rule that loads, matches nothing, and reads as
        // coverage. It is the exact defect this whole issue is about, and it
        // was invisible because an unmatched rule is silent.
        assert!(matches!(
            adjudicate_ready(&Some(resolved(&[
                ("verify", Validity::Missing),
                ("linear-check", Validity::Missing),
            ]))),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn every_named_receipt_must_be_valid_not_merely_one() {
        // The conjunction is the predicate: a branch that verified but is no
        // longer linear on the trunk cannot fast-forward-land.
        assert!(matches!(
            adjudicate_ready(&Some(resolved(&[
                ("verify", Validity::Valid),
                ("linear-check", Validity::StaleMain),
            ]))),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn all_receipts_valid_allows_the_call() {
        assert_eq!(
            adjudicate_ready(&Some(resolved(&[
                ("verify", Validity::Valid),
                ("linear-check", Validity::Valid),
            ]))),
            Decision::Allow
        );
    }

    #[test]
    fn a_receipt_the_boundary_did_not_resolve_fails_closed() {
        // Absent from the map is not "fine", it is unproven: a boundary that
        // answered for fewer checks than the row requires has not established
        // the precondition.
        assert!(matches!(
            adjudicate_ready(&Some(resolved(&[("verify", Validity::Valid)]))),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn no_facts_at_all_allows_because_the_boundary_could_not_look() {
        // Outside a checkout there are no git facts to judge against. Fail
        // open, the posture every retiring guard has: a guard that cannot read
        // its own precondition must not become the reason work stops. This is
        // deliberately distinct from `Some(Missing)`, which denies above.
        assert_eq!(adjudicate_ready(&None), Decision::Allow);
    }

    #[test]
    fn a_receipt_row_gates_only_its_own_trigger() {
        assert_eq!(
            adjudicate(
                &receipt_policy(),
                &envelope("gh pr view 42"),
                false,
                &Some(resolved(&[("verify", Validity::Missing)])),
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_refusal_names_the_check_and_what_is_wrong_with_it() {
        // Three verdicts, three causes — which is how `ready-guard`'s three
        // hand-written deny messages survive the move into one config row.
        let Decision::Deny(refusal) = adjudicate_ready(&Some(resolved(&[
            ("verify", Validity::Valid),
            ("linear-check", Validity::StaleHead),
        ]))) else {
            panic!("a stale receipt must deny");
        };
        let rendered = refusal.render();
        assert!(rendered.contains("linear-check"), "got: {rendered}");
        assert!(
            rendered.contains("amend") || rendered.contains("rebase"),
            "the cause must say what invalidated it; got: {rendered}"
        );
    }

    #[test]
    fn a_write_tool_against_a_protected_path_is_denied() {
        // The hole CLOUD-312 found: a write carries no command, and every path
        // in `adjudicate` returned Allow for it, so the whole
        // `Write|Edit|MultiEdit|NotebookEdit` matcher was adjudicated by
        // nothing while the rows sat in config reading as coverage.
        assert!(matches!(
            write_guarded("Write", ".serena/memories/core.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_write_tool_against_an_unprotected_path_is_allowed() {
        assert_eq!(
            write_guarded("Write", "crates/batten/src/new.rs"),
            Decision::Allow
        );
    }

    /// The false positive that would get this gate switched off.
    ///
    /// `Read` and `Write` both carry `file_path`, so a gate keyed on "the
    /// payload names a protected path" would refuse *reading* the policy file.
    /// The tool must be classified, and an unclassified one is not a write.
    #[test]
    fn an_undeclared_tool_against_a_protected_path_is_allowed() {
        assert_eq!(
            write_guarded("Read", ".serena/memories/core.md"),
            Decision::Allow
        );
    }

    #[test]
    fn a_write_deny_carries_the_declared_redirect_not_a_generic_message() {
        // The refusal contract (CLOUD-122) survives the move out of bash: the
        // consumer's own remedy text is what reaches the model, which is what
        // makes retiring `memory-guard` a port rather than a downgrade.
        let Decision::Deny(refusal) = write_guarded("Write", "batten.toml") else {
            panic!("a declared write verb against a protected path must deny");
        };
        let rendered = refusal.render();
        assert!(rendered.contains("Write"), "got: {rendered}");
        assert!(rendered.contains("batten.toml"), "got: {rendered}");
        assert!(
            rendered.contains("use the surface that owns the file"),
            "the declared redirect must reach the reader; got: {rendered}"
        );
    }

    #[test]
    fn a_write_is_judged_only_at_the_pre_tool_event() {
        // Same reading the command gate takes: a refusal after the fact is not
        // a decision any host offers, so it could only be noise.
        let mut envelope = write_envelope("Write", ".serena/memories/core.md");
        envelope.event = Event::PostTool;
        assert_eq!(
            adjudicate(
                &protected_policy(vec![verb("Write", Some("use the owning surface"))]),
                &envelope,
                false,
                &None,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn every_operand_is_a_candidate_so_a_destination_is_guarded_too() {
        // `mv` overwrites its destination, so guarding only the source would miss
        // the direction that destroys the protected file.
        assert!(matches!(
            guarded("mv notes.md batten.toml"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            guarded("mv batten.toml notes.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_redirect_target_is_a_mutation_even_with_no_program() {
        // A truncating redirect has no mutating program to classify — in
        // `cat x > p` the program is `cat` — so the operator is surfaced as a
        // pseudo-program the consumer declares like any other verb.
        for command in [
            "cat notes.md > batten.toml",
            "cat notes.md >batten.toml",
            "echo x >> batten.toml",
            "cat notes.md 2>batten.toml",
        ] {
            assert!(
                matches!(guarded(command), Decision::Deny(_)),
                "must deny: {command}"
            );
        }
    }

    #[test]
    fn an_undeclared_program_against_a_protected_path_is_allowed() {
        // The table is the authority on what mutates. `cat` reads, so it is not
        // this gate's business even against a protected path — the conservative
        // reading of an unknown program belongs to the consumer's config, not to
        // a guess here.
        assert_eq!(guarded("cat .serena/memories/core.md"), Decision::Allow);
    }

    #[test]
    fn the_deny_names_the_sanctioned_mutation_declared_beside_the_verb() {
        let reason = denial_text(guarded("rm .serena/memories/core.md"));
        assert!(
            reason.contains(PROTECTED_MUTATION),
            "names the gate: {reason}"
        );
        assert!(
            reason.contains("restore it with git"),
            "names the fix: {reason}"
        );
        assert!(
            reason.contains(".serena/memories/core.md"),
            "names where: {reason}"
        );
        // And as a value, not only as prose: the fix slot IS the verb's declared
        // redirect, which is what CLOUD-280 later re-sources per path class.
        assert_eq!(
            denial(guarded("rm .serena/memories/core.md"))
                .fix()
                .declared_alternative(),
            Some("restore it with git")
        );
    }

    #[test]
    fn both_deny_paths_render_one_shape_and_neither_can_drop_the_fix_clause() {
        // The contract's totality over this module's two deny paths — the
        // explicit `[[rule]]` rows and the derived protected-path gate. There is
        // no third, and a fourth could not be added without stating a `Fix`,
        // because `Refusal::new` requires one. This asserts the projection they
        // share: a `Refused by` clause, a `Fix:` clause, and the hatch.
        for decision in [
            adjudicate_command("gh pr merge 42"),
            guarded("rm .serena/memories/core.md"),
            guarded("mv batten.toml elsewhere"),
        ] {
            let text = denial_text(decision);
            assert!(text.starts_with("Refused by "), "got: {text}");
            assert!(
                text.contains(" Fix: "),
                "every deny points to a fix: {text}"
            );
            assert!(
                text.ends_with(&format!("Bypass with {BYPASS_ENV}=1.")),
                "{text}"
            );
        }
    }

    #[test]
    fn a_verb_with_no_redirect_declares_the_absence_rather_than_omitting_it() {
        // `redirect` is optional on a verb, so the refusal must still say
        // something actionable — CLOUD-280 is the per-path-class version.
        //
        // Since CLOUD-122 the absence is a VALUE (`Fix::None`), not a missing
        // field: the payload carries `"fix": null` and the rendering says so and
        // then gives the crate's general recourse. A consumer cannot tell an
        // omitted key from one the producer forgot, which is why the explicit
        // none is the contract rather than a nicety.
        let decision = guarded("mv batten.toml elsewhere");
        let refusal = denial(decision.clone());
        assert_eq!(refusal.fix(), &Fix::None, "nothing is declared for `mv`");
        assert!(
            refusal
                .to_json()
                .expect("the fixed shape serializes")
                .contains("\"fix\":null"),
            "the key is present and null"
        );
        let reason = denial_text(decision);
        assert!(reason.contains("Fix: none declared"), "got: {reason}");
        assert!(reason.contains("surface that owns it"), "got: {reason}");
    }

    #[test]
    fn flags_are_never_treated_as_paths() {
        // And `--` ends option parsing, so a dash-leading operand after it is
        // still an operand — the shape `rm -- -weird` uses.
        assert_eq!(guarded("rm -rf target"), Decision::Allow);
        assert!(matches!(guarded("rm -- batten.toml"), Decision::Deny(_)));
    }

    #[test]
    fn a_leading_dot_slash_is_the_same_path() {
        assert!(matches!(guarded("rm ./batten.toml"), Decision::Deny(_)));
    }

    #[test]
    fn an_absolute_path_is_not_resolved_against_the_repo_root() {
        // A stated limit, pinned so it cannot change silently. `Envelope` carries
        // no `cwd`, so there is nothing honest to resolve against; this
        // under-denies, which is the sanctioned direction.
        assert_eq!(guarded("rm /home/user/batten/batten.toml"), Decision::Allow);
    }

    #[test]
    fn a_quoted_protected_path_is_still_guarded() {
        // The whole reason CLOUD-269 landed first: under the old sentinel parser
        // this command carried no path token at all.
        assert!(matches!(
            guarded("rm \".serena/memories/core.md\""),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_protected_gate_denies_nothing_when_either_table_is_empty() {
        // The cross product needs both halves. A repository declaring verbs but
        // no protected paths — or the reverse — has declared no gate.
        let no_verbs = protected_policy(Vec::new());
        assert_eq!(
            adjudicate(
                &no_verbs,
                &envelope("rm batten.toml"),
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
        let no_paths = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: vec![verb("rm", None)],
            protected: PathSet::empty(),
        };
        assert_eq!(
            adjudicate(
                &no_paths,
                &envelope("rm batten.toml"),
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
    }

    #[test]
    fn an_explicit_row_wins_over_the_derived_protected_gate() {
        // A row a reviewer wrote by hand carries a more specific reason than the
        // generic protected-path message, so it should be the one quoted back.
        let mut policy = protected_policy(vec![verb("rm", Some("restore it with git"))]);
        policy.shapes = vec![shape("no-rm-memories", "rm .serena/memories/core.md", None)];
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("rm .serena/memories/core.md"),
            false,
            &None,
            &crate::stop::StopFacts::default(),
        ));
        assert!(reason.contains("no-rm-memories"), "got: {reason}");
    }

    #[test]
    fn the_protected_gate_honours_the_bypass_hatch() {
        assert_eq!(
            adjudicate(
                &protected_policy(vec![verb("rm", None)]),
                &envelope("rm batten.toml"),
                true,
                &None,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_redirect_pseudo_program_token_is_declared_not_implied() {
        // The crate↔config contract: a consumer declaring `verb = "redirect"`
        // would get silence, and nothing would say why. Naming the tokens here
        // is what makes the contract greppable.
        assert!(REDIRECT_VERBS.contains(&">"));
        assert!(REDIRECT_VERBS.contains(&">>"));
    }

    #[test]
    fn the_source_bakes_in_no_protected_path() {
        // Acceptance (d), in the `verbs::the_source_bakes_in_no_verb` idiom. The
        // literals are assembled so this test's own prose is not a match.
        //
        // Asserted behaviourally rather than by grepping the source. A grep is
        // what `verbs::the_source_bakes_in_no_verb` uses, and it works there
        // because a verb name is a short token. A *path* is not: the module doc
        // legitimately cites `mise-tasks/gh-guard-check` as the provenance of
        // this port, and prose examples name paths too, so a grep either fails on
        // documentation or needs an escape clause loose enough to pass always.
        // Both were tried; both were worse than the property itself.
        //
        // The property is that the set is *config*: the same command must get
        // opposite verdicts from two policies differing only in `protected`. A
        // hardcoded path could not produce that.
        let verbs = vec![verb("rm", None)];
        let guarding = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: verbs.clone(),
            protected: PathSet::includes("protected", &["guarded/**".to_owned()])
                .expect("well formed"),
        };
        let elsewhere = Policy {
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes("protected", &["other/**".to_owned()])
                .expect("well formed"),
        };
        let call = envelope("rm guarded/thing");
        assert!(
            matches!(
                adjudicate(
                    &guarding,
                    &call,
                    false,
                    &None,
                    &crate::stop::StopFacts::default()
                ),
                Decision::Deny(_)
            ),
            "the declared set must deny"
        );
        assert_eq!(
            adjudicate(
                &elsewhere,
                &call,
                false,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow,
            "a different declared set must allow the same command"
        );
    }

    /// Every host's checked-in fixture, paired with its `--harness` token.
    ///
    /// `include_str!` rather than a runtime read: the fixtures are part of the
    /// contract, and a test that could not find them should fail to compile
    /// rather than skip.
    const HOST_FIXTURES: &[(Harness, &str)] = &[
        (
            Harness::ClaudeCode,
            include_str!("../tests/fixtures/hooks/claude-code.json"),
        ),
        (
            Harness::CodexCli,
            include_str!("../tests/fixtures/hooks/codex-cli.json"),
        ),
        (
            Harness::CopilotCli,
            include_str!("../tests/fixtures/hooks/copilot-cli.json"),
        ),
        (
            Harness::GeminiCli,
            include_str!("../tests/fixtures/hooks/gemini-cli.json"),
        ),
        (
            Harness::Cursor,
            include_str!("../tests/fixtures/hooks/cursor.json"),
        ),
    ];

    #[test]
    fn every_hosts_fixture_normalizes_to_the_same_envelope() {
        // CLOUD-44's acceptance, stated directly rather than through behaviour:
        // five hosts, five wire formats, one envelope. The fields compared are
        // the ones policy dispatches on — the host's own `raw_event` and its
        // tool vocabulary deliberately differ, which is the whole point of
        // normalizing.
        for (harness, raw) in HOST_FIXTURES {
            let envelope = decode(*harness, raw)
                .unwrap_or_else(|| panic!("{} fixture decodes", harness.as_str()));
            assert_eq!(
                envelope.event,
                Event::PreTool,
                "{} must normalize its pre-tool event",
                harness.as_str()
            );
            assert_eq!(
                envelope.command,
                "gh pr merge 1",
                "{} must yield the same command",
                harness.as_str()
            );
            assert_eq!(
                envelope.cwd.as_deref(),
                Some(std::path::Path::new("/repo")),
                "{} must yield the same cwd",
                harness.as_str()
            );
            assert!(
                envelope.session.is_some(),
                "{} must yield a session id whatever it calls the key",
                harness.as_str()
            );
            assert!(
                !envelope.tool.is_empty(),
                "{} must yield a tool name, derived where the host sends none",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_cursor_payload_with_a_bom_decodes_identically() {
        // The measured Windows failure: a UTF-8 BOM on stdin breaks a strict
        // parser, and on Cursor that silently degraded guards to allow-all. A
        // BOM is never meaningful here, so it is stripped before parsing.
        let plain = decode(
            Harness::Cursor,
            include_str!("../tests/fixtures/hooks/cursor.json"),
        )
        .expect("the plain fixture decodes");
        let with_bom = decode(
            Harness::Cursor,
            include_str!("../tests/fixtures/hooks/cursor-bom.json"),
        )
        .expect("a BOM must not make a payload undecodable");
        assert_eq!(plain, with_bom);
    }

    #[test]
    fn a_cursor_specialized_event_derives_its_tool_and_lifts_its_operand() {
        // `beforeShellExecution` carries the command at top level and no
        // `tool_name` at all. An adapter that left the tool empty would make
        // every specialized event look like the same anonymous call.
        let envelope = decode(
            Harness::Cursor,
            include_str!("../tests/fixtures/hooks/cursor.json"),
        )
        .expect("decodes");
        assert_eq!(envelope.tool, "Shell");
        assert_eq!(envelope.raw_event, "beforeShellExecution");
        assert_eq!(
            envelope.input.pointer("/command").and_then(Value::as_str),
            Some("gh pr merge 1"),
            "the operand is lifted into `input` from the top level"
        );
        // The generic event still works the ordinary way.
        let generic = decode(
            Harness::Cursor,
            r#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"x"}}"#,
        )
        .expect("decodes");
        assert_eq!(generic.event, Event::PreTool);
        assert_eq!(generic.tool, "Shell");
    }

    #[test]
    fn copilots_tool_args_are_accepted_as_an_object_or_a_string() {
        // Copilot types `toolArgs` as `unknown` and its own docs show it
        // stringified, so a parser that assumed an object would read a real
        // payload as having no command — an allow, silently.
        let stringified = decode(
            Harness::CopilotCli,
            include_str!("../tests/fixtures/hooks/copilot-cli-stringified-args.json"),
        )
        .expect("decodes");
        assert_eq!(stringified.command, "gh pr merge 1");
    }

    #[test]
    fn geminis_event_names_are_renamed_and_claudes_are_not_disturbed() {
        // Gemini's names are the only structural gap in an otherwise
        // Claude-identical payload.
        for (raw, expected) in [
            ("BeforeTool", Event::PreTool),
            ("AfterTool", Event::PostTool),
            ("AfterAgent", Event::Stop),
        ] {
            assert_eq!(normalize_event(Harness::GeminiCli, raw), expected);
        }
        // A host with no rename table falls through to the converged spellings,
        // and a host's table never leaks into another's.
        assert_eq!(
            normalize_event(Harness::ClaudeCode, "BeforeTool"),
            Event::Unrecognized,
            "Gemini's vocabulary is not Claude's"
        );
        assert_eq!(
            normalize_event(Harness::CodexCli, "PreToolUse"),
            Event::PreTool
        );
    }

    #[test]
    fn only_the_hosts_with_no_stderr_reason_get_a_deny_body() {
        // Cursor documents no meaning for stderr, so its reason can only travel
        // in JSON; Claude discards stdout on exit 2, so it picks the richer
        // channel. Everything else answers with the exit code and stderr.
        for harness in Harness::ALL {
            let body = encode_deny(*harness, "PreToolUse", "use `mise run land`")
                .expect("the fixed shapes serialize");
            assert_eq!(
                body.is_some(),
                harness.reason_travels_in_band(),
                "{} channel disagrees with its declared posture",
                harness.as_str()
            );
            if let Some(body) = body {
                assert!(
                    body.contains("use `mise run land`"),
                    "{}: a deny body must carry the reason",
                    harness.as_str()
                );
            }
        }
    }

    #[test]
    fn every_host_declares_a_row_for_every_event_the_core_normalizes() {
        // Table totality (CLOUD-45 §7): the dispatcher keys on `Event`, so every
        // host owes a yes-or-no for each variant. `emits` answering at all is
        // the property — a host that simply omitted an event from its slice
        // would answer `false`, which is a decision, where a table missing the
        // *column* would be a question nobody asked.
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            for event in Event::ALL {
                let _ = capabilities.emits(*event);
            }
            assert!(
                capabilities.emits(Event::PreTool),
                "{}: pre-tool is the one event every surveyed host emits, and the \
                 only one a deny can still prevent anything at",
                harness.as_str()
            );
            assert!(
                !capabilities.emits(Event::Unrecognized),
                "{}: `unrecognized` is the core's word for 'the host said something \
                 we do not know', never something a host emits",
                harness.as_str()
            );
        }
    }

    #[test]
    fn no_surveyed_host_can_veto_completion_from_a_stop_event() {
        // A uniform fact, pinned as one. The survey's correction to this issue's
        // original framing: "Stop can block" is wrong on all five hosts, Claude
        // included — they can only force continuation. A capability keyed on the
        // opposite would be broken everywhere rather than degraded somewhere.
        for harness in Harness::ALL {
            assert!(
                !harness.capabilities().stop_vetoes_completion,
                "{}: no host vetoes completion from Stop",
                harness.as_str()
            );
            assert!(
                harness.capabilities().emits(Event::Stop),
                "{}: every host has a Stop-family event",
                harness.as_str()
            );
        }
    }

    #[test]
    fn task_completed_is_claude_only_and_degrades_to_the_stop_family() {
        // The one Claude-exclusive capability that is load-bearing for Batten's
        // completion-signal thesis.
        assert!(
            Harness::ClaudeCode
                .capabilities()
                .emits(Event::TaskCompleted)
        );
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            if *harness == Harness::ClaudeCode {
                assert_eq!(
                    capabilities.degrade(Event::TaskCompleted),
                    Some(Event::TaskCompleted),
                    "the host that has it watches it"
                );
                continue;
            }
            assert!(
                !capabilities.emits(Event::TaskCompleted),
                "{}: TaskCompleted is Claude-only across the surveyed hosts",
                harness.as_str()
            );
            assert_eq!(
                capabilities.degrade(Event::TaskCompleted),
                Some(Event::Stop),
                "{}: a policy keyed on completion watches the Stop family here",
                harness.as_str()
            );
        }
        // Degrading is not equivalence: the substitute cannot veto either, which
        // is why the caller still has to read the other field.
        assert!(!Harness::GeminiCli.capabilities().stop_vetoes_completion);
    }

    #[test]
    fn config_change_degrades_to_nothing_rather_than_to_something_weaker() {
        // Unlike TaskCompleted there is no honest stand-in for "a settings edit
        // is happening", so the answer is `None`. Substituting an unrelated
        // event would be worse than admitting the gap.
        for harness in Harness::ALL {
            if *harness == Harness::ClaudeCode {
                continue;
            }
            assert_eq!(
                harness.capabilities().degrade(Event::ConfigChange),
                None,
                "{}: nothing here stands in for ConfigChange",
                harness.as_str()
            );
        }
    }

    #[test]
    fn the_ask_verdict_is_absent_where_the_survey_found_it_absent() {
        // A policy wanting human confirmation must hard-deny on these two.
        // Degrading `ask` to *allow* would turn "check with a human" into "go
        // ahead", which is the one direction that must never be the fallback.
        assert!(!Harness::GeminiCli.capabilities().ask);
        assert!(!Harness::CodexCli.capabilities().ask);
        assert!(Harness::ClaudeCode.capabilities().ask);
    }

    #[test]
    fn the_fail_open_edges_are_per_host_capabilities_too() {
        // Each of these is a measured host behaviour Batten cannot change and
        // must not forget.
        assert!(
            Harness::CopilotCli.capabilities().timeout_fails_open,
            "Copilot concedes this even for admin policy hooks"
        );
        assert!(
            Harness::Cursor.capabilities().needs_fail_closed_config,
            "Cursor is fail-open unless a hook sets failClosed"
        );
        assert!(
            Harness::GeminiCli.capabilities().stdout_must_stay_clean,
            "Gemini reads unparseable stdout on exit 0 as Allow"
        );
        // And they are not universal — a blanket assumption would be as wrong as
        // forgetting them.
        assert!(!Harness::ClaudeCode.capabilities().timeout_fails_open);
        assert!(!Harness::ClaudeCode.capabilities().stdout_must_stay_clean);
    }

    #[test]
    fn every_harness_token_matches_its_clap_spelling() {
        // `as_str` exists so the E2E matrix can name a harness without building
        // a clap command. That is only safe while the two spellings agree, and
        // nothing else would notice if a `ValueEnum` rename left `as_str`
        // behind — the matrix would keep passing against a token the binary no
        // longer accepts.
        use clap::ValueEnum;
        for harness in Harness::ALL {
            let value = harness.to_possible_value().expect("harness is selectable");
            assert_eq!(harness.as_str(), value.get_name());
        }
    }

    #[test]
    fn the_claude_deny_shape_is_byte_stable() {
        let one = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        let two = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        assert_eq!(one, two);
        assert!(one.contains("\"permissionDecision\":\"deny\""));
    }
}
