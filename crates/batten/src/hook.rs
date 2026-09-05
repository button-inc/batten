//! The `hook` adjudicator (CLOUD-202): the agent-neutral envelope, the
//! wrapper-lookthrough command parser, and the first policy table, ported from
//! the battle-tested shell guards (`mise-tasks/gh-guard-check.sh` et al.).
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
//! reason a session cannot proceed; the general escape hatch (`BATTEN_HOOK_BYPASS`,
//! or a row's own `bypass_env`)
//! is honoured exactly as the shell guard honours it. Fail-open needs no care
//! here beyond the returns below: §7 spends `2` on the policy verdict alone, so
//! neither code a Batten failure can produce is one a host reads as a deny.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::receipt::Validity;
use crate::redirect::{self, Redirect};
use crate::refusal::{Fix, Refusal};
use crate::resolve::Resolved;
use crate::rules::{CeilingUnit, PathSet, ReceiptKey, ReceiptTrigger, Rule, RuleKind, RuleScope};
use crate::severity::{self, ReportLevel, RuleSeverity};
use crate::verbs::{MutatingVerb, OperandScope};

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

    /// Where this host reads its hook registrations, and which events to
    /// register under — or `None` for a variant that is a contract, not a host.
    ///
    /// CLOUD-62. The wiring is a derivation of the spec (§11) in exactly the
    /// sense completions and man pages are: which harnesses the binary speaks
    /// and which events each adapter dispatches are already data here, so the
    /// registrations they imply should be emitted rather than hand-kept. They
    /// were hand-kept, and every host adapter added would have needed another
    /// hand-written copy.
    ///
    /// **The match is exhaustive on purpose.** A new `Harness` variant does not
    /// compile until someone decides whether it is installable, which is the
    /// question a table of rows silently answers "no" to.
    ///
    /// Every row's facts — the config file and this host's event spellings —
    /// come from the CLOUD-209 harness capability matrix (M1), not from memory;
    /// that survey records measuring model recall of this space as "badly
    /// stale", with four of its own remembered URLs 404ing.
    ///
    /// The event *set* is not re-typed here: it is what this harness's
    /// [`Harness::capabilities`] already declares it emits, paired with the one
    /// spelling to register under. That pairing cannot be read off
    /// [`normalize_event`], which runs the other way and is many-to-one —
    /// Cursor's four pre-tool events all normalize to [`Event::PreTool`], so
    /// reversing it would have to invent which of the four to register.
    #[must_use]
    pub fn wiring(self) -> Option<Wiring> {
        match self {
            // The host merges hooks across its settings files and defines no
            // hooks-only project file, so batten owns a KEY here, never the
            // file: `.claude/settings.json` also carries configuration the
            // engine does not own.
            Harness::ClaudeCode => Some(Wiring {
                file: WiringFile::Key {
                    path: ".claude/settings.json",
                    key: "hooks",
                },
                spellings: CLAUDE_SPELLINGS,
            }),
            // "A near-verbatim clone of Claude Code's wire format, and the repo
            // says so out loud" (M1) — including the event names, so the
            // spellings are shared rather than copied.
            Harness::CodexCli => Some(Wiring {
                file: WiringFile::Whole(".codex/hooks.json"),
                spellings: CLAUDE_SPELLINGS,
            }),
            // Registered in the PascalCase dialect deliberately: M1 records that
            // the camelCase one omits `hook_event_name` entirely, and the casing
            // of the config key is what selects the dialect. So this row is not
            // merely a spelling — it is the reason the adapter can read an event
            // name at all.
            Harness::CopilotCli => Some(Wiring {
                file: WiringFile::Whole(".github/hooks/batten.json"),
                spellings: CLAUDE_SPELLINGS,
            }),
            // The one host whose names are a structural gap in an otherwise
            // Claude-identical payload (M1). `AfterAgent` is its end-of-turn —
            // the Stop family's member here even though the word differs.
            Harness::GeminiCli => Some(Wiring {
                file: WiringFile::Key {
                    path: ".gemini/settings.json",
                    key: "hooks",
                },
                spellings: &[
                    (Event::PreTool, "BeforeTool"),
                    (Event::PostTool, "AfterTool"),
                    (Event::Stop, "AfterAgent"),
                    (Event::SessionStart, "BeforeAgent"),
                ],
            }),
            // The generic `preToolUse` rather than one of the three specialized
            // events: it covers all tools, where each specialized event covers
            // one and carries no `tool_name` at all.
            Harness::Cursor => Some(Wiring {
                file: WiringFile::Whole(".cursor/hooks.json"),
                spellings: &[
                    (Event::PreTool, "preToolUse"),
                    (Event::PostTool, "afterFileEdit"),
                    (Event::Stop, "stop"),
                    (Event::SessionStart, "sessionStart"),
                ],
            }),
            // Not a host. `exit-code` is the neutral contract — envelope in,
            // decision as exit status out — for any host whose only channel is
            // an exit code. There is no file to register in, and inventing one
            // would be claiming something about a host nobody named.
            Harness::ExitCode => None,
        }
    }

    /// Whether a deny on this host must carry its reason **in the JSON body**
    /// rather than on stderr.
    ///
    /// The property is [`Capabilities::reason_travels_in_band`]'s and this reads
    /// it (CLOUD-372). It was a `matches!` over two harness names until then —
    /// a host property declared outside the table CLOUD-45 made the authority,
    /// so a seventh harness was correct only if whoever added it remembered the
    /// second place, and a forgotten `matches!` arm stays compiling and answers
    /// `false`. The accessor survives the move because callers ask a harness,
    /// not a table; what changed is where the answer comes from.
    #[must_use]
    pub const fn reason_travels_in_band(self) -> bool {
        self.capabilities().reason_travels_in_band
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

    /// Classify this host's tool name into the neutral [`Operation`] vocabulary.
    ///
    /// The write arm reuses [`Harness::write_tools`] rather than restating it:
    /// that table is what [`Envelope::writes`] is already derived from, and two
    /// lists of the same host fact is how the two come to disagree.
    ///
    /// **What is NOT declared here is as deliberate as what is.** Gemini and
    /// Copilot get no read/shell/MCP/subagent spellings, because the M1 survey
    /// (CLOUD-209) recorded their event names and their write tools and did not
    /// record those, and its own instruction is that "anything re-derived without
    /// a fetch should be assumed wrong". Their other calls therefore classify as
    /// [`Operation::Other`] — could not look — which every dispatch below reads
    /// as *unknown* rather than as *harmless*. Inventing a spelling would trade a
    /// safe unknown for a confident wrong answer.
    ///
    /// Cursor's three constants are the ones its specialized events already
    /// synthesize (`Shell`/`Read`/`MCP`, from `cursor_specialized_tool`), so this
    /// classifies what that adapter actually produces rather than a second guess
    /// at the same host.
    #[must_use]
    pub fn operation_of(self, raw_tool: &str) -> Operation {
        // An absent tool name is not a tool called "": it is a payload that did
        // not say. `Other` carries the empty spelling so the distinction stays
        // readable, and no arm below can mistake it for a classification.
        if raw_tool.is_empty() {
            return Operation::Other(String::new());
        }
        if self.write_tools().contains(&raw_tool) {
            return Operation::Write;
        }
        match self {
            // Codex is a near-verbatim clone of Claude's wire format and the
            // neutral contract states the normalized shape, so all three read the
            // converged vocabulary — each answering for itself, because
            // coincidence is not agreement.
            Harness::ClaudeCode | Harness::CodexCli | Harness::ExitCode => match raw_tool {
                "Bash" => Operation::Execute,
                "Read" => Operation::Read,
                "Task" => Operation::Subagent,
                other if other.starts_with(MCP_TOOL_PREFIX) => Operation::Mcp,
                other => Operation::Other(other.to_owned()),
            },
            Harness::Cursor => match raw_tool {
                "Shell" => Operation::Execute,
                "Read" => Operation::Read,
                "MCP" => Operation::Mcp,
                other => Operation::Other(other.to_owned()),
            },
            // Surveyed for writes and events, not for the rest — see the doc
            // above. Stated as its own arm rather than folded into a wildcard so
            // a later fetch has somewhere to land.
            Harness::GeminiCli | Harness::CopilotCli => Operation::Other(raw_tool.to_owned()),
        }
    }
}

/// How a host spells the agent's plan/todo tool, or that nobody has looked
/// (CLOUD-472).
///
/// **Two variants for a THREE-valued fact, and the third value is
/// `Surveyed(&[])`.** Collapsing "surveyed and this host has none" into the same
/// answer as "nobody checked" is the exact trap [`Harness::operation_of`]'s own
/// comment warns about, where Gemini and Copilot carry no spellings because the
/// CLOUD-209 survey did not record them — an absence of DATA that reads as an
/// absence of CAPABILITY. A reader who cannot tell those apart will report a
/// host as having no todo tool when the truth is that nobody asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanTools {
    /// Fetched from this host's own documentation. An empty slice is a measured
    /// "this host offers none", which is an answer.
    Surveyed(&'static [&'static str]),
    /// Nobody has looked, carrying the row that OWES the survey. NOT the same as
    /// none, and never reported as none.
    ///
    /// **The key changes no exit code, and that is deliberate** — it is
    /// `#MUTANT-OWNER`'s bargain, one layer over: a declaration that suppressed
    /// the finding would be the laundering the runner exists to refuse, so what
    /// the key buys is that the gap is STATED rather than that it is forgiven. A
    /// new harness added without a survey has to name who owes one, which is the
    /// moment an author either does the fetch or admits they did not.
    Unsurveyed(&'static str),
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
    /// How this host spells the agent's own plan/todo tool (CLOUD-472).
    ///
    /// **A column about what the AGENT can call, where the rest of this table is
    /// about what the ENGINE can reach** — and it is here anyway, because this is
    /// the one authority on host facts and a second table would be a second place
    /// for the same answer to drift.
    ///
    /// Batten does not gate on it. The plan record is written by
    /// [`crate::record::run_plan`], a verb, so the gate fails closed on every
    /// host regardless of what this says. What the column buys is the MIRROR —
    /// keeping the human's native todo view in step with the store — and an
    /// honest report of hosts where that view does not exist.
    ///
    /// Every spelling here was FETCHED, per CLOUD-209's rule that anything
    /// re-derived without one should be assumed wrong.
    pub plan_tools: PlanTools,
    /// Where an escalate-to-human verdict is actually reachable on this host
    /// (CLOUD-601).
    ///
    /// **Not a per-host bool, because the fact is not per-host.** Cursor honours
    /// `ask` on `beforeShellExecution` and `beforeMCPExecution` and merely parses
    /// it on the generic `preToolUse`, where an unenforced escalation *proceeds*
    /// — the one degradation direction CLOUD-45 §7(b) forbids. A row saying
    /// "Cursor has `ask`" is true of the host and false of the surface Batten
    /// registers, and once a rule can read the table that stops being a
    /// documentation defect and becomes a wrong answer the engine hands policy.
    ///
    /// One authority, two readings: [`AskReach::declared`] is what the host has,
    /// [`AskReach::enforced_on`] is where Batten can reach it, and
    /// [`Capabilities::ask_reachable`] is the only question a dispatch asks.
    pub ask: AskReach,
    /// Where a **non-blocking** message to the model is actually delivered on
    /// this host (CLOUD-461).
    ///
    /// The third channel, and the one the engine had no way to express. `ask`
    /// and the deny both answer *may this call proceed*; an advisory answers
    /// nothing — it carries context to the model and the call proceeds either
    /// way. `contract-drift` is the worked instance: a drift notice is not a
    /// refusal, and the only model-facing channel `PreToolUse` offers is exit 2,
    /// which blocks (CLOUD-97 and CLOUD-219 each ruled that out independently).
    ///
    /// Event-scoped for the same reason [`AskReach`] is, and here the reason is
    /// sharper: the channel is a property of the MOMENT rather than of the host.
    /// Claude Code delivers `additionalContext` at a batch boundary and at
    /// session start and says nothing about it on the pre-tool event, so a
    /// per-host bool could not express where an advisory actually lands.
    ///
    /// A host with no reachable surface produces **nothing** — never a deny, and
    /// never a fallback that blocks. That asymmetry is the mirror of
    /// [`encode_ask`]'s: an unreachable escalation degrades to a refusal because
    /// proceeding would invert the policy, and an unreachable advisory degrades
    /// to silence because refusing would invent one.
    pub advisory: AdvisoryReach,
    /// Where a **pre-approval** — allow this call and do not prompt — is actually
    /// honoured on this host.
    ///
    /// The fourth channel, and the only one that GRANTS. `ask` escalates, a deny
    /// refuses, an advisory says something and decides nothing; this one spends
    /// permission the operator already gave, by telling the host not to ask again.
    /// That direction is why it exists at all and why it is the narrowest column
    /// in this table: CLOUD-191's `connector-allow-guard` reads the session's
    /// injected MCP config to learn which of a server's two names — readable or
    /// UUID — is live *this* session, and applies the committed verdict to the
    /// live spelling. Without the channel, a grant the operator already wrote in
    /// `.claude/settings.json` stops matching the moment the host rotates the
    /// name, and every call prompts for the rest of the episode.
    ///
    /// **It grants nothing new, and that is the whole licence for it.** The reason
    /// a pre-approval carries is a projection of a committed rule onto a name the
    /// host chose; a handler that invented one would be Batten deciding a human's
    /// permission, which the scope reminder's "not a reference monitor" forbids.
    /// The engine enforces the direction rather than trusting it: a pre-approval
    /// can only ever upgrade a decision that was already [`Decision::Allow`], so
    /// no rule's refusal can be spent by one.
    ///
    /// Event-scoped for [`AdvisoryReach`]'s reason, and here the reading is the
    /// inverse of that column's: Claude Code honours `permissionDecision` on the
    /// pre-tool event and nowhere else, which is exactly the surface an advisory
    /// cannot reach. The two channels are complements rather than alternatives.
    ///
    /// An unreachable pre-approval degrades to **silence**, never to a deny and
    /// never to a bare allow document: silence hands the call back to the host's
    /// ordinary permission flow, which is what happens today and is the one
    /// degradation that cannot surprise anyone.
    pub preapprove: PreapproveReach,
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
    /// Whether a deny on this host must carry its reason **in the JSON body**
    /// rather than on stderr (CLOUD-372).
    ///
    /// Cursor is the one surveyed host that assigns no meaning to stderr, so
    /// CLOUD-122's refusal contract ("every deny points to the fix") is
    /// unsatisfiable there through the exit-code channel alone. Claude Code
    /// answers in-band for a different reason — exit 2 discards its stdout JSON,
    /// so the two channels are exclusive and it picks the richer one.
    ///
    /// **A row here rather than a `matches!` over harness names**, which is the
    /// whole of CLOUD-372. CLOUD-45 made this table the one authority on what a
    /// host can and cannot do, and a host property declared outside it is
    /// correct only while whoever adds the seventh harness remembers the second
    /// place. A missing arm in a `matches!` stays compiling and answers `false`;
    /// a missing field here does not compile, which is the asymmetry that made
    /// the split cost something.
    pub reason_travels_in_band: bool,
    /// What this host does to commit metadata, and what it exposes about its
    /// caller (CLOUD-276).
    ///
    /// A row group in the same table rather than a second per-host registry
    /// beside [`crate::attribution`]: the question "what can this host tell us"
    /// is the same kind of question as "what events does it emit", and two
    /// registries is how the answers come to disagree.
    pub attribution: AttributionCapabilities,
    /// How faithfully this host's tool responses can be captured, per response
    /// shape (CLOUD-917).
    ///
    /// A row group in the same table, for [`Capabilities::attribution`]'s
    /// reason. **Deliberately not a [`Capability`]**, and that is a decision
    /// rather than an omission: a [`crate::capture::Fidelity`] does not project
    /// to a [`Declaration`] without inventing a mapping — is `SpillFile` a
    /// `Yes`? is `Prefix` a `Partial`? — that would erase which of the five
    /// values was measured, which is the collapse `Declaration`'s own four
    /// values exist to prevent. So this is a second axis, exactly as
    /// [`Capabilities::events`] is, and [`Capabilities::fidelity`] is its
    /// projection. See [`Capability`]'s own doc: the scalar columns only.
    pub capture: CaptureCapabilities,
}

/// How faithfully one host's responses can be captured, per response shape
/// (CLOUD-917).
///
/// Per shape rather than per host, because the answer genuinely differs by
/// surface: a member on the payload, a file the host spilled into and the
/// transcript are three different reachability questions, and one value for all
/// three would be right about at most one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CaptureCapabilities {
    /// The response member on the post-tool payload — what [`decode`]'s alias
    /// walk reads into [`Envelope::result`].
    pub post_tool_member: crate::capture::Fidelity,
    /// A file the host spilled the response into, named on the payload.
    pub spill_path: crate::capture::Fidelity,
    /// The response as it appears in the host's transcript.
    pub transcript: crate::capture::Fidelity,
}

/// One surface a tool response can arrive on.
///
/// The axis [`Capabilities::fidelity`] ranges over, in [`Event`]'s shape. These
/// are the surfaces the code actually reads, deliberately **not** a restatement
/// of the [`crate::capture::Fidelity`] values — a `SpilledFile` *shape* beside a
/// `SpillFile` *fidelity* would make the census tautological, asserting only
/// that a name equals itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseShape {
    /// The response member on the post-tool payload.
    PostToolMember,
    /// A file the host spilled the response into.
    SpillPath,
    /// The host's transcript.
    Transcript,
}

impl ResponseShape {
    /// Every response shape, so a census is derived rather than hand-kept.
    pub const ALL: &'static [ResponseShape] = &[
        ResponseShape::PostToolMember,
        ResponseShape::SpillPath,
        ResponseShape::Transcript,
    ];

    /// The stable token, for byte-stable output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ResponseShape::PostToolMember => "post-tool-member",
            ResponseShape::SpillPath => "spill-path",
            ResponseShape::Transcript => "transcript",
        }
    }
}

/// What one host declares for one capability.
///
/// Four values, and the fourth pair is the whole point (CLOUD-276): **an absent
/// capability and an undeclared one must not be the same value.**
/// [`Declaration::No`] is a measured "this host does not have it";
/// [`Declaration::Unknown`] is "it may, but not through a surface Batten reads
/// at record time, and the survey cannot answer". Collapsing them would make a
/// gap in the evidence indistinguishable from a fact about the host.
///
/// The common projection every row has, whatever its own type: it is what makes
/// table totality checkable over `Harness::ALL × Capability::ALL` rather than as
/// a hand-kept list of per-field assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Declaration {
    /// The host has it, measured.
    Yes,
    /// The host does not have it, measured.
    No,
    /// A setting or surface exists but does not govern every path it would have
    /// to. Weaker than [`Declaration::Yes`] and not the same claim as
    /// [`Declaration::No`] — something is there and it is not enough.
    Partial,
    /// Undeclared: the evidence does not answer for this host. Never a silent
    /// `No`.
    Unknown,
}

impl Declaration {
    /// The stable lowercase token, for byte-stable output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Declaration::Yes => "yes",
            Declaration::No => "no",
            Declaration::Partial => "partial",
            Declaration::Unknown => "unknown",
        }
    }

    /// Whether this declaration lets a value be captured from the host.
    ///
    /// Only [`Declaration::Yes`] does. `Partial` deliberately does not: a
    /// surface that does not govern every path cannot be trusted to have
    /// governed this one, and a half-true capture is worse than an honest
    /// `unknown`.
    #[must_use]
    pub const fn is_capturable(self) -> bool {
        matches!(self, Declaration::Yes)
    }
}

/// What a host does to commit metadata, and what it exposes about its caller.
///
/// CLOUD-276's five row groups. **What the evidence actually answers, stated
/// once here rather than repeated per host:** the M1 harness capability matrix
/// surveys hook surfaces, and it carries exactly one of these five — the session
/// id, present natively on all five hosts. It has no row for git identity, for
/// injected trailers, or for an attribution config surface, so those are
/// [`Declaration::Unknown`] on every surveyed host except where this repository
/// measured its own commits (see [`crate::attribution`]'s module docs, measured
/// 2026-08-09). Declaring them `No` from memory is exactly what that survey
/// records as unsafe: it measured model recall of this space as "badly stale",
/// with four remembered URLs 404ing.
///
/// Filling the four unanswered groups needs an attribution-shaped survey pass,
/// which is a research issue rather than a value this module may guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttributionCapabilities {
    /// Whether the host itself writes a git identity for the commits it
    /// produces.
    ///
    /// `Unknown` on every named host, and the reason is a measurement rather
    /// than a gap: this repository found 39 of its first 50 `main` commits
    /// carrying an environment-injected vendor identity, and traced the
    /// injection to *container git config plus harness prompt*. That evidence
    /// cannot separate the host from the container it runs in, so attributing it
    /// to the host would be a claim the measurement does not support.
    pub sets_git_identity: Declaration,
    /// Whether the host adds a co-authorship trailer naming a model identity.
    ///
    /// The **shape**, never the spelling. `attribution.rs` extends non-negotiable
    /// rule 1 from consumers to vendors — "a vendor name is configuration here
    /// and never a literal in the crate" — so the engine declares that a
    /// coauthorship trailer is expected and `batten.toml`'s `trailer_deny` names
    /// it. A trailer key here would put a vendor's spelling in the core.
    pub injects_coauthorship_trailer: Declaration,
    /// Whether the host adds a trailer linking the session.
    pub injects_session_link_trailer: Declaration,
    /// Whether the host puts a model identity on the payload Batten reads.
    ///
    /// `Unknown` on every named host, and this is the case CLOUD-276's stated
    /// assumption anticipated. M1's field inventory is explicit and there is no
    /// model id in it on any host: Claude Code and Gemini CLI carry
    /// `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `tool_name`,
    /// `tool_input` and `tool_use_id`; Codex adds `turn_id`. Each host plainly
    /// runs a model whose identity exists somewhere — it is not on the surface
    /// read at record time, which is `Unknown` and not `No`.
    pub exposes_model_id: Declaration,
    /// Whether the host puts a session id on the payload Batten reads.
    ///
    /// The one row M1 answers for every host: `session_id` (Claude, Gemini,
    /// Codex), `sessionId` (Copilot), `conversation_id` (Cursor). [`decode`]
    /// already reads all three spellings.
    pub exposes_session_id: Declaration,
    /// Whether the host offers a setting that suppresses its own attribution
    /// injection, and whether that setting governs every path.
    ///
    /// `Partial` on Claude Code is a measurement, not a hedge: this repository
    /// found one trailer added by a path that ignores the off-switch, which is
    /// the whole reason `attribution.rs` is a gate over the produced commit
    /// rather than a settings check. Trusting configuration there would be
    /// trusting the thing that already lied.
    pub config_surface: Declaration,
}

/// One column of the host × capability table.
///
/// A vocabulary enum with a `const ALL`, the shape [`Harness`], [`Event`] and
/// [`crate::rules::RuleKind`] already use — so CLOUD-45 §7's totality obligation
/// is a test over `Harness::ALL × Capability::ALL` rather than a hand-kept list
/// of per-field assertions that a new row joins only if someone remembers.
///
/// The scalar columns only. [`Capabilities::events`] is a *set* rather than one
/// value, and its totality is the other axis —
/// `tests::every_host_declares_a_row_for_every_event_the_core_normalizes` ranges
/// over [`Event::ALL`]. Projecting a set into one [`Declaration`] would answer a
/// question nobody asked and hide the per-event answer that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// [`Capabilities::ask`].
    Ask,
    /// [`Capabilities::stop_vetoes_completion`].
    StopVetoesCompletion,
    /// [`Capabilities::timeout_fails_open`].
    TimeoutFailsOpen,
    /// [`Capabilities::needs_fail_closed_config`].
    NeedsFailClosedConfig,
    /// [`Capabilities::stdout_must_stay_clean`].
    StdoutMustStayClean,
    /// [`AttributionCapabilities::sets_git_identity`].
    SetsGitIdentity,
    /// [`AttributionCapabilities::injects_coauthorship_trailer`].
    InjectsCoauthorshipTrailer,
    /// [`AttributionCapabilities::injects_session_link_trailer`].
    InjectsSessionLinkTrailer,
    /// [`AttributionCapabilities::exposes_model_id`].
    ExposesModelId,
    /// [`AttributionCapabilities::exposes_session_id`].
    ExposesSessionId,
    /// [`AttributionCapabilities::config_surface`].
    AttributionConfigSurface,
    /// [`Capabilities::advisory`] (CLOUD-461).
    ///
    /// **Appended rather than slotted beside [`Capability::Ask`]**, where it
    /// belongs by meaning. `semver` reads a reordered variant as
    /// `enum_no_repr_variant_discriminant_changed`, so declaration order is an
    /// API fact and grouping is a readability one. [`Capability::ALL`] and
    /// [`Capability::DISPATCH`] carry the grouping — they are the order output
    /// is rendered in, and they are free to say what this list cannot.
    Advisory,
    /// [`Capabilities::preapprove`].
    ///
    /// Appended for the reason the row above it was, and the note is repeated
    /// rather than referenced because the next author reads the line they are
    /// adding after: declaration order here is an API fact `semver` reads as
    /// `enum_no_repr_variant_discriminant_changed`, so a new variant goes at the
    /// END and expresses its grouping through [`Capability::ALL`] and
    /// [`Capability::DISPATCH`] instead.
    Preapprove,
}

impl Capability {
    /// Every scalar capability, so a census is derived rather than hand-kept.
    pub const ALL: &'static [Capability] = &[
        Capability::Ask,
        Capability::Advisory,
        Capability::Preapprove,
        Capability::StopVetoesCompletion,
        Capability::TimeoutFailsOpen,
        Capability::NeedsFailClosedConfig,
        Capability::StdoutMustStayClean,
        Capability::SetsGitIdentity,
        Capability::InjectsCoauthorshipTrailer,
        Capability::InjectsSessionLinkTrailer,
        Capability::ExposesModelId,
        Capability::ExposesSessionId,
        Capability::AttributionConfigSurface,
    ];

    /// The rows the mediation dispatch keys on: what a host can decide, and how
    /// it fails.
    pub const DISPATCH: &'static [Capability] = &[
        Capability::Ask,
        Capability::Advisory,
        Capability::Preapprove,
        Capability::StopVetoesCompletion,
        Capability::TimeoutFailsOpen,
        Capability::NeedsFailClosedConfig,
        Capability::StdoutMustStayClean,
    ];

    /// The rows [`crate::attribution`] consults: what a host does to commit
    /// metadata, and what it can be asked about its caller (CLOUD-276).
    ///
    /// Named as a subset so the capture and expectation documents are *derived*
    /// from the table rather than re-listing it — a new attribution row joins
    /// them by being declared here.
    ///
    /// [`Capability::DISPATCH`] and this one **partition**
    /// [`Capability::ALL`], which is what makes the split checkable:
    /// `tests::the_two_capability_subsets_partition_the_whole_table` fails if a
    /// new capability joins neither, so it cannot land belonging to nothing.
    pub const ATTRIBUTION: &'static [Capability] = &[
        Capability::SetsGitIdentity,
        Capability::InjectsCoauthorshipTrailer,
        Capability::InjectsSessionLinkTrailer,
        Capability::ExposesModelId,
        Capability::ExposesSessionId,
        Capability::AttributionConfigSurface,
    ];

    /// The stable token, for byte-stable output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Ask => "ask",
            Capability::Advisory => "advisory",
            Capability::Preapprove => "preapprove",
            Capability::StopVetoesCompletion => "stop-vetoes-completion",
            Capability::TimeoutFailsOpen => "timeout-fails-open",
            Capability::NeedsFailClosedConfig => "needs-fail-closed-config",
            Capability::StdoutMustStayClean => "stdout-must-stay-clean",
            Capability::SetsGitIdentity => "sets-git-identity",
            Capability::InjectsCoauthorshipTrailer => "injects-coauthorship-trailer",
            Capability::InjectsSessionLinkTrailer => "injects-session-link-trailer",
            Capability::ExposesModelId => "exposes-model-id",
            Capability::ExposesSessionId => "exposes-session-id",
            Capability::AttributionConfigSurface => "attribution-config-surface",
        }
    }
}

/// A `bool` row's [`Declaration`] — a measured yes-or-no, never `Unknown`.
///
/// Free rather than a closure inside [`Capabilities::declares`] so that function
/// can stay `const`.
const fn measured(yes: bool) -> Declaration {
    if yes {
        Declaration::Yes
    } else {
        Declaration::No
    }
}

/// Where escalation is reachable on one host, and what that host declares.
///
/// The shape [`Capabilities::events`] already uses, applied to the second column
/// whose truth turned out to be envelope-scoped (CLOUD-601). Keeping both halves
/// in one value is the point: `ask_is_reachable` *beside* `ask` would leave two
/// facts where one belongs, and adjacency is not identity.
///
/// The events are the **host's own spellings**, not [`Event`]s, because that is
/// the granularity the divergence lives at: Cursor's four pre-tool events all
/// normalize to [`Event::PreTool`] and only two of them enforce the verdict, so a
/// normalized key could not express the fact at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AskReach {
    /// The host event spellings on which an emitted `ask` is **enforced**.
    ///
    /// Empty means Batten cannot escalate on this host at all — which resolves to
    /// a hard deny at the boundary, never an allow.
    pub enforced_on: &'static [&'static str],
    /// What the survey measured about the host itself, with its citation in the
    /// row's own comment.
    ///
    /// Distinct from `enforced_on` on purpose, and the gap between them is the
    /// thing that must be *stated* rather than merely true — see `ASK_GAPS`.
    pub declared: Declaration,
}

impl AskReach {
    /// The row for a host that cannot be asked at all.
    #[must_use]
    pub const fn unreachable(declared: Declaration) -> AskReach {
        AskReach {
            enforced_on: &[],
            declared,
        }
    }
}

/// Where a non-blocking message to the model is delivered on one host, and what
/// that host declares (CLOUD-461).
///
/// [`AskReach`]'s shape, applied to the advisory channel, and event-scoped for a
/// stronger reason than `ask` needed. `ask` is event-scoped because one host's
/// four pre-tool events disagree; this is event-scoped because **the channel
/// belongs to the moment**. Claude Code documents `additionalContext` at the
/// batch boundary — *"inject context once for the whole batch"* — and this
/// repository has run it there and at `SessionStart` and `Stop`; the pre-tool
/// event offers no such field at all, only the verdict. So "does this host have
/// an advisory channel" is not a question with one answer.
///
/// The events are the **host's own spellings**, for the reason [`AskReach`]
/// gives: normalizing them would erase the granularity the fact lives at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdvisoryReach {
    /// The host event spellings on which an emitted advisory actually reaches
    /// the model.
    ///
    /// Empty means Batten cannot speak to the model on this host without
    /// deciding something — which resolves to **silence** at the boundary, never
    /// to a deny. An advisory that degraded to a refusal would invent a verdict
    /// nobody asked for, which is the exact inversion [`encode_ask`] refuses in
    /// the other direction.
    pub delivered_on: &'static [&'static str],
    /// What the evidence says about the host itself, with its citation in the
    /// row's own comment.
    ///
    /// Distinct from `delivered_on` for the reason [`AskReach::declared`] is:
    /// the gap between what a host has and where Batten can reach it must be
    /// **stated** rather than merely true — see `ADVISORY_GAPS`.
    pub declared: Declaration,
}

impl AdvisoryReach {
    /// The row for a host Batten cannot speak to without deciding something.
    #[must_use]
    pub const fn unreachable(declared: Declaration) -> AdvisoryReach {
        AdvisoryReach {
            delivered_on: &[],
            declared,
        }
    }
}

/// Where a pre-approval is honoured on one host, and what that host declares.
///
/// [`AdvisoryReach`]'s shape a third time, and the repetition is deliberate:
/// three channels asking "where, on this host, does this land" answer it the same
/// way, so a reader who has understood one has understood all three. Collapsing
/// them into one generic would save lines and cost the per-channel doc comment
/// that carries each one's degradation direction, which is the part that differs.
///
/// The events are the **host's own spellings**, for the reason [`AskReach`]
/// gives: normalizing them would erase the granularity the fact lives at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreapproveReach {
    /// The host event spellings on which an emitted pre-approval actually stops
    /// the host prompting.
    ///
    /// Empty means Batten cannot spend a grant on this host — which resolves to
    /// **silence**, never to a deny and never to an allow document the host would
    /// read as something else. Silence returns the call to the ordinary permission
    /// flow, which is the host's own default and cannot surprise anyone.
    pub honoured_on: &'static [&'static str],
    /// What the evidence says about the host itself, with its citation in the
    /// row's own comment.
    ///
    /// Distinct from `honoured_on` for the reason the other two columns' pairs
    /// are: the gap between what a host has and where Batten reaches it must be
    /// **stated** rather than merely true — see `PREAPPROVE_GAPS`.
    pub declared: Declaration,
}

impl PreapproveReach {
    /// The row for a host on which Batten cannot spend a grant.
    #[must_use]
    pub const fn unreachable(declared: Declaration) -> PreapproveReach {
        PreapproveReach {
            honoured_on: &[],
            declared,
        }
    }
}

impl Capabilities {
    /// Whether this host emits `event`.
    #[must_use]
    pub fn emits(&self, event: Event) -> bool {
        self.events.contains(&event)
    }

    /// Whether an `ask` emitted at this host's `raw_event` is actually enforced.
    ///
    /// **The one authority a dispatch consults.** Before CLOUD-601 this was
    /// reconstructed inside [`encode_ask`]'s match arms, so the declaration and
    /// the reachability were two facts kept in step by hand.
    ///
    /// The comparison is on the host's own spelling, so it answers correctly for
    /// a host whose four pre-tool events do not agree with each other.
    #[must_use]
    pub fn ask_reachable(&self, raw_event: &str) -> bool {
        self.ask.enforced_on.contains(&raw_event)
    }

    /// Whether an advisory emitted at this host's `raw_event` reaches the model.
    ///
    /// **The one authority the advisory dispatch consults**, so no emitter
    /// reconstructs the answer from a host name — which is the drift
    /// [`Capabilities::ask_reachable`] was extracted to stop, one channel over.
    ///
    /// The comparison is on the host's own spelling, so it answers correctly for
    /// a host whose events do not agree with each other about the channel.
    #[must_use]
    pub fn advisory_reachable(&self, raw_event: &str) -> bool {
        self.advisory.delivered_on.contains(&raw_event)
    }

    /// Whether a pre-approval emitted at this host's `raw_event` stops the host
    /// prompting.
    ///
    /// The third of these, and the one whose wrong answer is worst in the quiet
    /// direction: an unhonoured pre-approval is not a broken verdict, it is a
    /// prompt the operator still sees — indistinguishable from the guard never
    /// having run. So the table answers rather than the emitter guessing, which is
    /// the drift [`Capabilities::ask_reachable`] was extracted to stop.
    #[must_use]
    pub fn preapprove_reachable(&self, raw_event: &str) -> bool {
        self.preapprove.honoured_on.contains(&raw_event)
    }

    /// How faithfully this host's response can be captured on one shape
    /// (CLOUD-917).
    ///
    /// The projection that makes the fidelity column's axis rangeable, the way
    /// [`Capabilities::declares`] does for the scalar columns and
    /// [`Capabilities::emits`] does for the event set. Every host answers for
    /// every shape: the exhaustive `match` in [`Harness::capabilities`] plus
    /// `#[non_exhaustive]` struct-literal construction already make a missing
    /// cell a compile error, and what this adds is *reachability* — a cell that
    /// is filled but that no [`ResponseShape`] can name would be a measurement
    /// nothing can read.
    #[must_use]
    pub const fn fidelity(&self, shape: ResponseShape) -> crate::capture::Fidelity {
        match shape {
            ResponseShape::PostToolMember => self.capture.post_tool_member,
            ResponseShape::SpillPath => self.capture.spill_path,
            ResponseShape::Transcript => self.capture.transcript,
        }
    }

    /// What this host declares for one scalar capability.
    ///
    /// The projection that makes the table's second axis rangeable. The `bool`
    /// rows map to [`Declaration::Yes`]/[`Declaration::No`] because a `bool`
    /// *is* a measured yes-or-no — a row whose evidence does not answer must be
    /// declared as a [`Declaration`] rather than guessed into a `bool`, which is
    /// why the attribution rows are not booleans.
    #[must_use]
    pub const fn declares(&self, capability: Capability) -> Declaration {
        match capability {
            Capability::Ask => self.ask.declared,
            Capability::Advisory => self.advisory.declared,
            Capability::Preapprove => self.preapprove.declared,
            Capability::StopVetoesCompletion => measured(self.stop_vetoes_completion),
            Capability::TimeoutFailsOpen => measured(self.timeout_fails_open),
            Capability::NeedsFailClosedConfig => measured(self.needs_fail_closed_config),
            Capability::StdoutMustStayClean => measured(self.stdout_must_stay_clean),
            Capability::SetsGitIdentity => self.attribution.sets_git_identity,
            Capability::InjectsCoauthorshipTrailer => self.attribution.injects_coauthorship_trailer,
            Capability::InjectsSessionLinkTrailer => self.attribution.injects_session_link_trailer,
            Capability::ExposesModelId => self.attribution.exposes_model_id,
            Capability::ExposesSessionId => self.attribution.exposes_session_id,
            Capability::AttributionConfigSurface => self.attribution.config_surface,
        }
    }

    /// The event a policy keyed on `event` should actually watch on this host.
    ///
    /// `None` when nothing here stands in for it. Two substitutions, both named
    /// by the survey: a policy keyed on `TaskCompleted` degrades to the Stop
    /// family, which every surveyed host has, and one keyed on `PostToolBatch`
    /// degrades to `PostTool`. Degrading is not equivalence — Stop cannot veto
    /// anywhere, so a caller still has to read
    /// [`Capabilities::stop_vetoes_completion`] before assuming it can block.
    /// What a substitution buys is *observing* the moment, not refusing it.
    ///
    /// The batch substitution is what makes the wake event a property of this
    /// table rather than of the caller (CLOUD-389): the drain asks for the batch
    /// boundary and is handed the exact event or the per-call one, so no consumer
    /// carries a second rule about which host has what. It is coarser rather than
    /// weaker — N `PostTool` wakes stand in for one batch, and the coalescing
    /// window is what turns them back into one drain.
    #[must_use]
    pub fn degrade(&self, event: Event) -> Option<Event> {
        if self.emits(event) {
            return Some(event);
        }
        match event {
            Event::TaskCompleted if self.emits(Event::Stop) => Some(Event::Stop),
            Event::PostToolBatch if self.emits(Event::PostTool) => Some(Event::PostTool),
            _ => None,
        }
    }
}

/// Where a host reads its hook registrations, and how batten's rows sit in it.
///
/// The distinction is load-bearing rather than cosmetic (CLOUD-62): a file
/// batten owns can be emitted whole, and a file it shares must be emitted as
/// just the key it owns, because the rest is configuration the engine has no
/// business rewriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringFile {
    /// A hooks-only file, owned whole.
    Whole(&'static str),
    /// One key inside a file the host shares with other configuration.
    Key {
        /// The file, repo-root-relative.
        path: &'static str,
        /// The key batten's registrations live under.
        key: &'static str,
    },
}

/// One host's hook wiring: where it lives, and what it calls each event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wiring {
    /// The host's hook-config surface.
    pub file: WiringFile,
    /// This host's name for each event it can name — a naming TABLE, not the
    /// set to register.
    ///
    /// The distinction is the whole point of CLOUD-62 and a row got it wrong
    /// first: three hosts share Claude's spellings, but only Claude emits
    /// `TaskCompleted` and `ConfigChange`, so a shared list registered Copilot
    /// under events it does not have — a hook that reads as installed and can
    /// never fire. [`Wiring::registrations`] intersects this with what the
    /// harness declares it emits, so the SET is derived and only the NAMES are
    /// declared.
    pub spellings: &'static [(Event, &'static str)],
}

impl Wiring {
    /// The events to register, with this host's name for each.
    ///
    /// Ordered by [`Event::ALL`] rather than by the table, so emission is
    /// byte-stable (§6) whatever order a row happens to list its names in.
    #[must_use]
    pub fn registrations(&self, harness: Harness) -> Vec<(Event, &'static str)> {
        let capabilities = harness.capabilities();
        Event::ALL
            .iter()
            .filter(|event| capabilities.emits(**event))
            .filter_map(|event| {
                self.spellings
                    .iter()
                    .find(|(named, _)| named == event)
                    .map(|(_, spelling)| (*event, *spelling))
            })
            .collect()
    }
}

/// Claude Code's event spellings, which Codex CLI and Copilot's `PascalCase`
/// dialect ship verbatim (M1) — so three wiring rows share this rather than
/// carrying three copies that could drift apart.
const CLAUDE_SPELLINGS: &[(Event, &str)] = &[
    (Event::PreTool, "PreToolUse"),
    (Event::PostTool, "PostToolUse"),
    (Event::Stop, "Stop"),
    (Event::SessionStart, "SessionStart"),
    (Event::TaskCompleted, "TaskCompleted"),
    (Event::ConfigChange, "ConfigChange"),
    // Safe to share even though only Claude emits it, and the reason is the
    // distinction this table's doc comment draws: a spelling is a NAME, not a
    // registration. `Wiring::registrations` intersects these names with what the
    // harness declares it emits, so Codex and Copilot — which ship Claude's
    // spellings — register nothing for an event their own rows do not list.
    (Event::PostToolBatch, "PostToolBatch"),
    // Safe to share for the same reason, and only Claude lists it in its own
    // event set: a spelling is a NAME, not a registration.
    (Event::UserPromptSubmit, "UserPromptSubmit"),
];

/// The command a host's registration invokes.
///
/// Neutral on purpose, and this is where non-negotiable rule 1 bites (CLOUD-62):
/// a consumer that needs an indirection in front of the binary resolves it in
/// that consumer's own gate, because naming its file layout here would put a
/// specific consumer's paths in the repo-agnostic core. So the emitter names the
/// binary and the harness, and nothing else.
///
/// **This repository ran such an indirection and no longer does** (CLOUD-824).
/// `.claude/hooks/batten-hook.sh` existed to `cd` so `load_policy` found the
/// authority and to resolve a binary that was not on PATH — two things
/// `settings.json` cannot express, and both binary defects paid for in shell.
/// The `cd` asked git for the WORKTREE's root where [`crate::git::repo_root`]
/// answers the repository's, so it defended against the wrong directory; that
/// job is the binary's now, in [`crate::git`], which names both spellings and is
/// the one module allowed to. The search was an install concern. What the
/// paragraph above still says is unchanged, and it is what keeps the emitter able
/// to serve a consumer that does need one.
///
/// **The argv is DERIVED from the `SURFACE` row, never spelled here**
/// (CLOUD-1191). This was `format!("batten hook --harness {}", …)`, one of three
/// independent spellings; renaming the row left this one behind, and the
/// resulting unknown subcommand is a clap error — exit `1` — which every host
/// reads as allow. The disagreement would not have broken loudly, it would have
/// turned enforcement off everywhere while `doctor` reported green.
///
/// A surface declaring no mediation row yields the binary and the harness with
/// no verb between them — a command that matches nothing, so every registration
/// reports as drift. That is the LOUD direction, and it is why there is no
/// literal fallback here: emitting `"hook"` when the declaration is gone would
/// be the fourth spelling this removes, and it would report healthy.
pub(crate) fn wiring_command(harness: Harness) -> String {
    let argv = crate::surface::mediation_argv().unwrap_or_default();
    let mut parts = vec![crate::surface::BINARY.to_owned()];
    parts.extend(argv);
    parts.push(harness.as_str().to_owned());
    parts.join(" ")
}

/// Render one harness's registrations as the JSON its host reads.
///
/// Byte-stable (§6): the events come back from [`Wiring::registrations`] in
/// [`Event::ALL`] order, and the object is built by hand rather than through a
/// map type, so key order is the code's and not a hash's.
///
/// **No matcher.** Which tool calls are actually mediated is `batten.toml`'s
/// `mediated_call` rows — the engine's own filter, and a consumer's policy. A
/// matcher emitted here would be the core asserting something about a consumer's
/// tool vocabulary, and a wrong one narrows enforcement silently. The host's
/// absent-matcher default is "every tool", which lets the engine's own filter be
/// the only narrowing.
#[must_use]
pub fn render_wiring(harness: Harness, wiring: &Wiring) -> String {
    // The values go through `serde_json` rather than being interpolated raw:
    // they are ASCII identifiers today, and a row that ever carries a quote or a
    // backslash would otherwise emit JSON that does not parse.
    let command = json_string(&wiring_command(harness));
    let registrations = wiring.registrations(harness);

    // Built as lines with an explicit indent rather than through a map type:
    // key order is the contract here (§6 byte-stability), and a map would sort
    // or hash it. The indent is a parameter so the same body serves a whole file
    // and a key's value, which differ only by one level.
    let entry = |spelling: &str, indent: &str| {
        [
            format!("{indent}{}: [", json_string(spelling)),
            format!("{indent}  {{"),
            format!("{indent}    \"hooks\": ["),
            format!("{indent}      {{"),
            format!("{indent}        \"type\": \"command\","),
            format!("{indent}        \"command\": {command}"),
            format!("{indent}      }}"),
            format!("{indent}    ]"),
            format!("{indent}  }}"),
            format!("{indent}]"),
        ]
        .join("\n")
    };

    match wiring.file {
        // The key's VALUE alone: the file carries configuration the engine does
        // not own, so emitting the file would be claiming the rest of it.
        WiringFile::Key { .. } => {
            let body: Vec<String> = registrations
                .iter()
                .map(|(_, spelling)| entry(spelling, "  "))
                .collect();
            format!("{{\n{}\n}}", body.join(",\n"))
        }
        // A hooks-only file, so the registrations are the whole document.
        WiringFile::Whole(_) => {
            let body: Vec<String> = registrations
                .iter()
                .map(|(_, spelling)| entry(spelling, "    "))
                .collect();
            format!("{{\n  \"hooks\": {{\n{}\n  }}\n}}", body.join(",\n"))
        }
    }
}

/// One JSON string literal, quoted and escaped.
///
/// Falls back to a bare quoting only if serialization somehow fails, which it
/// cannot for a `&str` — the library forbids `unwrap`, and a panic here would be
/// a panic in a read-only emitter.
fn json_string(raw: &str) -> String {
    serde_json::to_string(raw).unwrap_or_else(|_| format!("\"{raw}\""))
}

/// The events every surveyed host emits — the converged core.
const CONVERGED_EVENTS: &[Event] = &[
    Event::PreTool,
    Event::PostTool,
    Event::Stop,
    Event::SessionStart,
];

/// The attribution row group every named host shares: nothing the evidence
/// answers except the session id (CLOUD-276).
///
/// Shared rather than copied five times, because five identical copies of
/// "the survey does not say" would read as five independent findings. The one
/// host that diverges — Claude Code, where this repository measured its own
/// commits — states its own row group in full rather than spreading this one.
const UNSURVEYED_ATTRIBUTION: AttributionCapabilities = AttributionCapabilities {
    sets_git_identity: Declaration::Unknown,
    injects_coauthorship_trailer: Declaration::Unknown,
    injects_session_link_trailer: Declaration::Unknown,
    exposes_model_id: Declaration::Unknown,
    // The one row M1 answers for every host.
    exposes_session_id: Declaration::Yes,
    config_surface: Declaration::Unknown,
};

/// The capture row group every host but one shares: nothing reachable
/// (CLOUD-917).
///
/// Shared rather than copied five times, for [`UNSURVEYED_ATTRIBUTION`]'s
/// reason. **`Unavailable` is the honest value here and not a placeholder**: it
/// says the host does not make the bytes reachable *here*, which is exactly what
/// an unmeasured surface supports. Only Claude Code's post-tool payload has been
/// measured in this repository, so widening any other cell is a measurement,
/// filed per host.
const UNSURVEYED_CAPTURE: CaptureCapabilities = CaptureCapabilities {
    post_tool_member: crate::capture::Fidelity::Unavailable,
    spill_path: crate::capture::Fidelity::Unavailable,
    transcript: crate::capture::Fidelity::Unavailable,
};

/// Claude Code's set: the converged core plus the four it alone offers.
const CLAUDE_EVENTS: &[Event] = &[
    Event::PreTool,
    Event::PostTool,
    Event::Stop,
    Event::SessionStart,
    Event::TaskCompleted,
    Event::ConfigChange,
    // CLOUD-389. Measured rather than inferred from the docs: CLOUD-187 wired a
    // hook on it and watched it fire inside the session that added it. It is
    // here and nowhere else because this table is the one authority on which
    // events a host emits, and claiming it for the converged core would be
    // claiming something about hosts nobody surveyed.
    Event::PostToolBatch,
    // CLOUD-777. The eighth, and the one whose ABSENCE made an acceptance clause
    // vacuous: "every event a harness declares has a registration" demanded
    // nothing here while two bash guards sat on the surface, because
    // `Wiring::registrations` intersects with this list and this list did not
    // carry it. Claude-only for the same reason as the three above — no other
    // surveyed host emits it, and claiming it for the converged core would be
    // claiming something about hosts nobody surveyed.
    Event::UserPromptSubmit,
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
    // `too_many_lines` is the same misfire one axis over, and CLOUD-372 is what
    // crossed the threshold: this function is a DATA TABLE, so its length is the
    // host count times the column count and both of those are the point. The
    // remedy the lint implies — split it — would put one host's row away from
    // the others, which is the two-places defect CLOUD-372 exists to remove.
    // `expect` rather than `allow`, so if the table ever shrinks back under the
    // ceiling this annotation goes red instead of outliving its reason.
    #[expect(
        clippy::too_many_lines,
        reason = "a per-host capability table grows by rows; splitting it would re-create the split this row closed"
    )]
    pub const fn capabilities(self) -> Capabilities {
        match self {
            Harness::ClaudeCode => Capabilities {
                // Fetched: this session's own tool surface.
                plan_tools: PlanTools::Surveyed(&["TaskCreate", "TaskUpdate"]),
                events: CLAUDE_EVENTS,
                // Documented, and merged most-restrictive-first by the host
                // itself (`deny > defer > ask > allow`), so an ask cannot
                // override another hook's deny. `PreToolUse` is the only event
                // that carries the verdict and the only one Batten adjudicates.
                ask: AskReach {
                    enforced_on: &["PreToolUse"],
                    declared: Declaration::Yes,
                },
                // The four surfaces this repository has actually run an
                // advisory on, which is why they and not the other four are
                // listed. `PostToolBatch` is documented for exactly this —
                // "return additionalContext via hookSpecificOutput to inject
                // context once for the whole batch" — and CLOUD-187 measured the
                // entry firing; `SessionStart` seeds the same notice; `Stop`
                // carries the end-of-turn nudges, whose header records all three
                // channels verified by probe.
                //
                // `PreToolUse` IS ONE OF THEM, AND IT WAS ADDED BY MEASUREMENT
                // RATHER THAN BY READING THE DOCS (CLOUD-1131). It was excluded
                // for its whole life on the claim that this event's only
                // model-facing channel is exit 2 — a deny — so an advisory there
                // would either be discarded or become a refusal. **That claim was
                // never probed, and it is false.** Measured 2026-08-29 as a
                // discriminating pair over one command, one word of this list
                // apart: `jq --version` (which trips `pinned-toolchain-preset`,
                // a live `severity = "warn"` mediated row) delivered
                // `PreToolUse:Bash hook additional context: … pin reach loose …`
                // to the agent with the entry present, and delivered nothing with
                // it absent. The call was ALLOWED both times and the exit code
                // never moved, which is the half that matters: the host carries a
                // non-blocking advisory at `PreToolUse`, and the only thing that
                // had ever suppressed it was `encode_advice` consulting this list
                // before building a wire shape.
                //
                // The lesson is the `Unknown`-versus-`No` discipline read the
                // wrong way round. Leaving an unprobed surface out is the safe
                // default for DELIVERY — it costs silence rather than a notice
                // that vanishes — but it is not evidence about the host, and the
                // comment here had hardened into one. CLOUD-1131's first attempt
                // then cited this table's position as a measurement of Claude
                // Code and declined to ship a gate over it.
                //
                // `PostToolUse` and `UserPromptSubmit` are documented to accept
                // the field and are still NOT listed, because nothing here has
                // probed them — the discipline stands, now stated as what it is.
                // `ADVISORY_GAPS` names them.
                advisory: AdvisoryReach {
                    delivered_on: &["PreToolUse", "PostToolBatch", "SessionStart", "Stop"],
                    declared: Declaration::Yes,
                },
                // THE COMPLEMENT OF THE ROW ABOVE, and the only host that fills
                // this column. `permissionDecision: "allow"` is documented on
                // `PreToolUse` and is what stops the host prompting; the advisory
                // row reaches three OTHER events and not this one, so the two
                // columns partition the surfaces rather than overlapping on any.
                //
                // `PreToolUse` alone, not the other three pre-tool-ish events this
                // host emits: a permission decision is meaningless after the call
                // has run, and the host documents the field on exactly this one.
                // That is a measurement rather than a narrowing — there is no
                // `PostToolUse` prompt to suppress.
                preapprove: PreapproveReach {
                    honoured_on: &["PreToolUse"],
                    declared: Declaration::Yes,
                },
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                // exit 2 discards this host's stdout JSON, so the two channels are
                // exclusive and the richer one wins.
                reason_travels_in_band: true,
                // The one host whose attribution rows are not the shared
                // "unsurveyed" group, because this repository measured its own
                // history under it (2026-08-09, recorded in
                // [`crate::attribution`]'s module docs): 18 of the first 50
                // `main` commits carried a model-versioned co-authorship
                // trailer and 20 a session URL, and one trailer survived the
                // host's own off-switch.
                attribution: AttributionCapabilities {
                    // Measured as environment-injected — container git config
                    // plus harness prompt — which cannot separate the host from
                    // the container, so the host is not credited with it.
                    sets_git_identity: Declaration::Unknown,
                    injects_coauthorship_trailer: Declaration::Yes,
                    injects_session_link_trailer: Declaration::Yes,
                    exposes_model_id: Declaration::Unknown,
                    exposes_session_id: Declaration::Yes,
                    // A setting exists and demonstrably does not govern every
                    // injection path. Neither `Yes` nor `No` is true of it.
                    config_surface: Declaration::Partial,
                },
                // The one host with a measured capture row, and it is one cell
                // of three. `tests/board-write-record.bats` reads this host's
                // MCP content-block response shape, so the post-tool member is
                // reachable — as DECODED content, because [`decode`] hands the
                // engine an already-parsed value and the member's original
                // bytes are gone by then. `LexicalBytes` would need the decoder
                // to keep the member's raw span, which no surface here does, so
                // claiming it would be the one claim
                // [`crate::capture::Fidelity`]'s reserved word forbids.
                //
                // Nothing here spills a response to a file, and nothing reads
                // the transcript for one, so both are unreachable rather than
                // unmeasured — but `Unavailable` is the same answer either way
                // and does not overstate which.
                capture: CaptureCapabilities {
                    post_tool_member: crate::capture::Fidelity::DecodedContent,
                    spill_path: crate::capture::Fidelity::Unavailable,
                    transcript: crate::capture::Fidelity::Unavailable,
                },
            },
            Harness::Cursor => Capabilities {
                // Searched 2026-09-01 and NOT fetched: the host has a Todos
                // feature from 1.2, but no vendor-documented tool spelling was
                // found, and a name taken from a forum post is exactly what
                // CLOUD-209's "assume it wrong without a fetch" refuses.
                plan_tools: PlanTools::Unsurveyed("CLOUD-209"),
                events: CONVERGED_EVENTS,
                // The row that forced this column to become event-scoped
                // (CLOUD-601). M1 records the verdict vocabulary as
                // event-dependent: `allow|deny|ask` on `beforeShellExecution` and
                // `beforeMCPExecution`, `allow|deny` on the generic `preToolUse`
                // where `ask` "parses but is not enforced" — and coerced to deny
                // on `subagentStart`. `Harness::wiring` registers the generic
                // event, so escalation is declared and today unreachable; that
                // gap is stated in `ASK_GAPS` rather than smoothed over, and it
                // closes on its own when CLOUD-777 registers these two surfaces.
                ask: AskReach {
                    enforced_on: &["beforeShellExecution", "beforeMCPExecution"],
                    declared: Declaration::Yes,
                },
                // `Unknown`, not `No`: M1 surveys this host's verdict vocabulary
                // and carries no row for a non-blocking message to the model at
                // all, so the evidence does not answer. Recorded as a gap rather
                // than guessed into either value.
                advisory: AdvisoryReach::unreachable(Declaration::Unknown),
                // `Unknown` for this host's own reason: M1 surveys its verdict
                // vocabulary as allow/deny/ask and says nothing about a
                // pre-approval that suppresses a prompt. `ask` here is enforced on
                // two events, so the host clearly HAS a permission dialogue — what
                // the evidence does not answer is whether anything skips it.
                preapprove: PreapproveReach::unreachable(Declaration::Unknown),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: true,
                stdout_must_stay_clean: false,
                // the one surveyed host that assigns no meaning to stderr at all, so a
                // deny explained there would explain itself to nobody.
                reason_travels_in_band: true,
                attribution: UNSURVEYED_ATTRIBUTION,
                capture: UNSURVEYED_CAPTURE,
            },
            Harness::CopilotCli => Capabilities {
                // Not fetched, like the rest of this host's tool surface — the
                // same survey gap `operation_of` records for it.
                plan_tools: PlanTools::Unsurveyed("CLOUD-209"),
                events: CONVERGED_EVENTS,
                // `Unknown`, not `No`, and not `Yes` either: M1 confirms the
                // verdict exists and names the `preToolUse` output *fields*
                // (`permissionDecision`/`permissionDecisionReason`) without
                // naming the object they sit in. Claude's `hookSpecificOutput`
                // envelope is a guess on the strength of the field names, and a
                // guessed envelope that fails to parse is read as no decision —
                // an allow. "Could not confirm" is a legitimate stored answer
                // (CLOUD-757's three-valued discipline); guessing is not, so
                // `enforced_on` is empty until a primary-doc fetch fills it.
                ask: AskReach::unreachable(Declaration::Unknown),
                // Same evidentiary state as this host's `ask` row and for the
                // same reason: the output object is unconfirmed by primary
                // docs, so no envelope can be emitted without guessing one.
                advisory: AdvisoryReach::unreachable(Declaration::Unknown),
                // Same evidentiary state as this host's other two channels: M1
                // names the `preToolUse` output FIELDS without naming the object
                // they sit in, so no document can be emitted without guessing an
                // envelope, and a guessed envelope reads as no decision at all.
                preapprove: PreapproveReach::unreachable(Declaration::Unknown),
                stop_vetoes_completion: false,
                timeout_fails_open: true,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                // stderr carries the reason.
                reason_travels_in_band: false,
                attribution: UNSURVEYED_ATTRIBUTION,
                capture: UNSURVEYED_CAPTURE,
            },
            Harness::GeminiCli => Capabilities {
                // Fetched 2026-09-01 from the vendor docs: `write_todos`, on by
                // default and disableable with `"useWriteTodos": false`.
                plan_tools: PlanTools::Surveyed(&["write_todos"]),
                events: CONVERGED_EVENTS,
                // Allow/deny only. A policy wanting confirmation must hard-deny
                // here — degrading to *allow* would turn "ask a human" into "go
                // ahead".
                ask: AskReach::unreachable(Declaration::No),
                // REACHABLE SINCE CLOUD-1362, AND THE ROW ABOVE IT IS WHY IT
                // ALWAYS WAS. This read `AdvisoryReach::unreachable(Yes)` with
                // the reason "the only door is writing bytes this host's own
                // `stdout_must_stay_clean` row forbids". That conflated two
                // different things and stalled CLOUD-1152 for days.
                //
                // `stdout_must_stay_clean` is about STRAY output: unparseable
                // stdout ON EXIT 0 defaults to Allow and is read as a
                // `systemMessage`. The hazard it guards is a DECISION document
                // corrupted into an accidental allow. An advisory is not a
                // decision — it wants allow-plus-a-message, which is precisely
                // what the Golden Rule delivers. The door is the mechanism, not
                // the obstacle.
                //
                // The collision that would have made it an obstacle is closed by
                // construction: `emit_channel` returns early when the decision is
                // `Deny` or `Ask` (CLOUD-1175), so an advisory and a verdict never
                // share one invocation's stdout. On the path where advice is
                // emitted at all, the decision is already `Allow` — so the bytes
                // this host reads as "allow, and tell the model" say exactly what
                // the engine decided.
                //
                // Corroborated rather than argued: `admit_mediated` already
                // writes a bare prose line to stdout on the admitted-call path,
                // so this door has been open on a live allow path with no defect
                // reported, for the same reason.
                //
                // All four spellings, and the per-event probe discipline
                // `ADVISORY_GAPS` applies to Claude Code does NOT transfer here —
                // reading that rejection without its scope is the error
                // `.claude/rules/scanning.md` records. There the question is
                // whether a documented FIELD is honoured at a given event, which
                // is genuinely per-event. Here it is how the host parses a hook's
                // stdout, which is a property of the host's reader and not of the
                // moment. If it is ever measured otherwise the cost is silence,
                // the sanctioned direction.
                advisory: AdvisoryReach {
                    delivered_on: &["BeforeTool", "AfterTool", "AfterAgent", "BeforeAgent"],
                    declared: Declaration::Yes,
                },
                // `Unknown` rather than the `Yes` its advisory row carries. That
                // row is `Yes` because the host demonstrably HAS the channel and
                // Batten cannot reach it; here the evidence does not establish the
                // channel exists at all. Two different unreachabilities, and
                // collapsing them would be the guess `Declaration` exists to
                // refuse.
                preapprove: PreapproveReach::unreachable(Declaration::Unknown),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: true,
                // stderr carries the reason.
                reason_travels_in_band: false,
                attribution: UNSURVEYED_ATTRIBUTION,
                capture: UNSURVEYED_CAPTURE,
            },
            Harness::CodexCli => Capabilities {
                // Fetched 2026-09-01: `update_plan`, the built-in plan tool.
                plan_tools: PlanTools::Surveyed(&["update_plan"]),
                events: CONVERGED_EVENTS,
                // Advertised in the output schema, marked "parsed but not
                // supported yet" in the docs. Advertised is not available, and
                // that is a measurement rather than a gap — hence `No`.
                ask: AskReach::unreachable(Declaration::No),
                // The survey names this host's verdict fields and no advisory
                // one. Unanswered, so `Unknown`.
                advisory: AdvisoryReach::unreachable(Declaration::Unknown),
                // Unsurveyed, like this host's advisory row. Its `ask` field is
                // "parsed but not supported yet", which says nothing either way
                // about a grant.
                preapprove: PreapproveReach::unreachable(Declaration::Unknown),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                // stderr carries the reason.
                reason_travels_in_band: false,
                attribution: UNSURVEYED_ATTRIBUTION,
                capture: UNSURVEYED_CAPTURE,
            },
            Harness::ExitCode => Capabilities {
                // The neutral contract carries no host tool surface of its own.
                plan_tools: PlanTools::Surveyed(&[]),
                events: CONVERGED_EVENTS,
                // Not a host: the channel is the exit status alone, which has no
                // third value to carry an escalation. Measured, not unsurveyed.
                ask: AskReach::unreachable(Declaration::No),
                // `No`, and measured for the same reason: an exit status has no
                // room for a message. This is the normalized envelope Batten
                // itself defines, so the shape IS the answer rather than a gap
                // in somebody else's documentation.
                advisory: AdvisoryReach::unreachable(Declaration::No),
                // `No`, measured, for the reason this adapter's other channels
                // are: an exit status has three values and none of them can say
                // "and do not prompt". This is Batten's own normalized envelope,
                // so the shape IS the answer rather than a gap in somebody's
                // documentation.
                preapprove: PreapproveReach::unreachable(Declaration::No),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                // the caller reads the exit code and stderr; there is no document.
                reason_travels_in_band: false,
                // The one column that is `No` rather than `Unknown`, and it is a
                // measurement rather than a guess: this is not a third party. It
                // is the normalized envelope Batten itself defines, and that
                // shape carries a session and nothing else on this list — no
                // identity, no trailers, no model id, no config surface. A
                // caller composing it by hand states the shape, so the shape is
                // the answer.
                attribution: AttributionCapabilities {
                    sets_git_identity: Declaration::No,
                    injects_coauthorship_trailer: Declaration::No,
                    injects_session_link_trailer: Declaration::No,
                    exposes_model_id: Declaration::No,
                    exposes_session_id: Declaration::Yes,
                    config_surface: Declaration::No,
                },
                // `Unavailable` here is a measurement rather than a gap, for
                // this arm's usual reason: this is not a third party. It is the
                // normalized envelope Batten itself defines, and a caller
                // composing it by hand carries no response surface at all — so
                // the shape IS the answer. It coincides with the unsurveyed
                // group's value and does not mean the same thing, which is why
                // it is spelled out rather than borrowed.
                capture: CaptureCapabilities {
                    post_tool_member: crate::capture::Fidelity::Unavailable,
                    spill_path: crate::capture::Fidelity::Unavailable,
                    transcript: crate::capture::Fidelity::Unavailable,
                },
            },
        }
    }
}

impl Harness {
    /// The **home-relative** files this host merges hook configuration from,
    /// beyond the committed one [`Harness::wiring`] names (CLOUD-525).
    ///
    /// # Why this is a harness fact and not a consumer's
    ///
    /// Non-negotiable rule 1 keeps consumer identifiers out of the core, and
    /// this satisfies it exactly the way [`WiringFile`] does: **which files a
    /// host merges its own hook config from is a fact about the host**, no more
    /// a consumer identifier than `.claude/settings.json` is. A grep of
    /// `crates/batten` for any particular repository's names still returns
    /// nothing.
    ///
    /// # Home-relative, because absolute would be unstatable
    ///
    /// The paths are relative to the user's home directory and joined at the
    /// read. An absolute path differs per machine and per user, so it could not
    /// be a `const` here and could never be reported — §6 byte-stability and
    /// rule 4 both forbid emitting one. What the core states is the **layout**;
    /// where that layout lives is resolved once, at the boundary.
    ///
    /// # What this does NOT answer
    ///
    /// *What did this process load at start* — CLOUD-187's boundary, untouched
    /// and unreachable from inside. This answers *what does this host merge*,
    /// which is a different question with a different mechanism, and conflating
    /// the two is what made the census look impossible. The merged set is a
    /// strictly better approximation of the running wiring than the committed
    /// set alone, and it is what every reader of the committed file already
    /// treats as the whole story.
    #[must_use]
    // `match_same_arms` would collapse the two empty rows. Refused for the
    // reason `capabilities` refuses it: they are empty for DIFFERENT measured
    // reasons — three hosts declare a hooks-only project file and no user-level
    // merge, and the neutral adapter is not a host at all — and collapsing them
    // would delete the distinction and make a future divergence a structural
    // edit rather than a one-value one.
    #[allow(clippy::match_same_arms)]
    pub const fn merge_surfaces(self) -> &'static [&'static str] {
        match self {
            // Measured in one container 2026-08-21: the committed file declares
            // two `Stop` handlers and three on `SessionStart`, while the runtime
            // ran three and four. The extra registrations came from a
            // user-level file and a launcher-provisioned one, neither of which
            // any committed surface declares and neither of which any gate read.
            Harness::ClaudeCode => &[
                ".claude/settings.json",
                ".claude/settings.local.json",
                ".claude/launcher-settings.json",
            ],
            // Gemini merges the same user-level file its committed wiring is
            // keyed in — one layout, two locations.
            Harness::GeminiCli => &[".gemini/settings.json"],
            // EMPTY IS A MEASUREMENT HERE, not a gap: these hosts declare a
            // hooks-only project file and the survey records no user-level merge
            // for them, so there is nothing beyond the committed surface to
            // read. Stated per host rather than wildcarded, so a host that turns
            // out to merge has to be answered for rather than defaulting to
            // "does not".
            Harness::Cursor | Harness::CopilotCli | Harness::CodexCli => &[],
            // Not a host: the neutral contract is an envelope in and an exit
            // status out, with no file to merge.
            Harness::ExitCode => &[],
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
    // DECLARED AFTER the catch-all on purpose, which reads oddly and is the
    // cheaper of two honest options. This enum is field-less and carries no
    // `repr`, so a consumer may write `Event::Unrecognized as u8` and inserting
    // ahead of it shifts that value — `cargo semver-checks` calls it
    // `enum_no_repr_variant_discriminant_changed`. Appending keeps the change
    // patch-compatible instead of putting a break in the changelog for a
    // discriminant nothing observes. Reading order lives in `Event::ALL`, which
    // is what every census and the wiring emitter iterate, so nothing but this
    // declaration is affected.
    /// Every tool call in a batch has resolved, before the next model request
    /// (CLOUD-389). **Claude-only** across the surveyed hosts.
    ///
    /// The batch boundary [`crate::drain`] wants and, until this variant existed,
    /// inferred with a coalescing window on every host including the one that
    /// emits it. The window is not replaced — four of five surveyed hosts offer
    /// no batch event, and CLOUD-79 puts the once-per-batch guarantee in the mask
    /// rather than in any event — so this is the exact path where one exists and
    /// the window is the fallback it was designed as. A policy keyed on it
    /// degrades to [`Event::PostTool`] elsewhere (see [`Capabilities::degrade`]).
    ///
    /// No deny channel, and that is structural rather than a choice: a boundary
    /// between batches is not a decision point, and [`adjudicate`] allows every
    /// non-pre-tool event before any rule is consulted.
    PostToolBatch,
    /// A turn's prompt has been submitted, before the model sees it.
    /// **Claude-only** across the surveyed hosts.
    ///
    /// Appended for the reason [`Event::PostToolBatch`] above it was: this enum
    /// carries no `repr`, so inserting ahead of an existing variant shifts a
    /// discriminant a consumer may have cast, which `cargo semver-checks` reports
    /// as `enum_no_repr_variant_discriminant_changed`. Reading order is
    /// [`Event::ALL`]'s, which is what every census and the wiring emitter
    /// iterate.
    ///
    /// **It carries a deny channel, and that is measured rather than assumed**
    /// (CLOUD-777, 2026-08-21). This repository's own wiring was the evidence:
    /// two bash guards registered here reached `exit 2` on five paths between
    /// them and emitted no advisory shape — deny-issuing gates on this surface,
    /// honoured by the host. So this is **not** one of the stated no-ops beside
    /// it: [`adjudicated`]'s arm says the channel is real and that no rule kind
    /// selects for it yet, which is a gap with an owner rather than a decision
    /// that there is nothing to decide.
    ///
    /// **The evidence moved rather than expired** (CLOUD-898). One of those two
    /// guards is now a `[[hook.handler]]` dispatched by `batten hook` instead of
    /// registered beside it, so the count above is history. The conclusion is
    /// unchanged and is now demonstrated by the door itself: a handler exiting
    /// `2` at this event produces the host's own deny document, asserted in
    /// `tests/cli.rs`. What DID change is the advisory half — this host offers no
    /// `additionalContext` field here, so a handler's advice at this event
    /// degrades to the operator's stream. Deny reaches the model; advice does
    /// not.
    UserPromptSubmit,
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
        Event::PostToolBatch,
        // Grouped with the other host-exclusive events rather than placed at the
        // chronological start of a turn: this list is what the wiring emitter
        // iterates, so its order is a committed artifact's key order, and the
        // grouping that already holds — converged core, then the events one host
        // alone offers — is the one a reader can check against
        // `CONVERGED_EVENTS`. `Unrecognized` stays last because it is not a
        // moment.
        Event::UserPromptSubmit,
        Event::Unrecognized,
    ];

    /// Whether a refusal is a thing this moment can carry at all.
    ///
    /// **Four events cannot, and [`adjudicate`] returns [`Decision::Allow`] at
    /// each of them before any rule is read.** Their reasons differ and are
    /// stated on their own arms — `Stop` because CLOUD-889 made the end-of-turn
    /// gate structurally unable to refuse, `SessionStart` and `ConfigChange`
    /// because neither moment carries `Decision` semantics on any host,
    /// `TaskCompleted` because the stop gate is the one reconciliation point and
    /// deciding twice would give one question two answers.
    ///
    /// **This exists because that property has a SECOND producer now.** A
    /// `[[hook.handler]]` refusal becomes a [`Decision::Deny`] too, on a path
    /// that never consults [`adjudicate`] — so without one authority the engine
    /// could be structurally unable to refuse at `Stop` while a handler declared
    /// on `stop` refused every turn, which is the runaway CLOUD-889 removed,
    /// re-entering through the door CLOUD-898 added.
    ///
    /// `dispatch_handlers` consults this rather than re-listing the events,
    /// because a second list is a copy that can disagree — and
    /// `every_undecidable_event_allows_in_adjudicate` is the gate that this one
    /// and [`adjudicate`]'s arms still say the same thing.
    #[must_use]
    pub const fn carries_a_verdict(self) -> bool {
        !matches!(
            self,
            Event::Stop | Event::SessionStart | Event::ConfigChange | Event::TaskCompleted
        )
    }

    /// Whether this moment decides **permission** for a call that has not run.
    ///
    /// **Narrower than [`Event::carries_a_verdict`], and deliberately not derived
    /// from it.** The two questions look alike and diverge on exactly the events
    /// that matter: `post-tool` and `post-tool-batch` carry a verdict — a deny
    /// there is a finding about what already happened — and decide no permission,
    /// because the call is over. A grant on those surfaces would be permission for
    /// something already done, which is not a weaker version of a grant but a
    /// meaningless one. `user-prompt-submit` carries a verdict too and names no
    /// tool at all, so there is nothing to permit.
    ///
    /// This distinction was found by a test rather than by reading: the first
    /// version of [`crate::handler::Handler::preapproves`]' load-time refusal
    /// borrowed `carries_a_verdict`, which admitted `post-tool`.
    ///
    /// Host-independent by construction, which is what makes it usable at config
    /// load. WHICH host honours a grant on a permitted moment is
    /// [`Capabilities::preapprove_reachable`]'s question, asked at the boundary
    /// against the host's own event spelling.
    #[must_use]
    pub const fn decides_permission(self) -> bool {
        matches!(self, Event::PreTool)
    }

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
            Event::PostToolBatch => "post-tool-batch",
            Event::UserPromptSubmit => "user-prompt-submit",
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
            "PostToolBatch" => Event::PostToolBatch,
            "UserPromptSubmit" => Event::UserPromptSubmit,
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

/// The prefix every MCP-provided tool carries in the converged wire format.
///
/// A host fact rather than an invention: this repository's own
/// `.claude/settings.json` registers a `^mcp__` matcher, which is the same
/// convention the hosts that clone Claude's format inherit. Hosts whose MCP
/// spelling the M1 survey did not record classify as [`Operation::Other`]
/// instead of being credited with this one.
const MCP_TOOL_PREFIX: &str = "mcp__";

/// What a mediated call **does**, normalized across hosts (CLOUD-779).
///
/// The neutral layer [`Envelope::raw_tool`] was missing. `Event`/`raw_event`
/// already ship this shape one field up — abstract where the semantics converge,
/// the host's own word kept addressable where they do not — and tools had only
/// the second half, which is why a gate keyed on a tool name is a gate against
/// one host. Measured on `main` 2026-08-20: with the consumer's `[[verb]]` table
/// naming Claude Code's vocabulary, a write to a protected path arriving as
/// Cursor's `write`/`edit`, Gemini's `WriteFile` or Copilot's `StrReplaceEditor`
/// was allowed silently, because a rule that matches nothing is indistinguishable
/// from a rule with nothing to match.
///
/// **This is not [`crate::effect::Effect`] and must not become it** (CLOUD-312).
/// That vocabulary classifies *Batten's own* command surface for the house-style
/// §5 read-only allowlist and its consumer is `spec.rs`; importing it here would
/// put a classification of Batten's verbs in the path that judges a consumer's
/// shell commands. Two declared tables, two different objects.
///
/// [`Operation::Other`] is **could not look**, never "not a write" (CLOUD-757's
/// three-valued discipline). An adapter that meets a tool its host's survey never
/// recorded says so rather than guessing, and every predicate over this type
/// treats that answer as *unknown* — the write gate consults every source a call
/// could name a target through, rather than concluding the call is harmless.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// The call writes the path it names.
    Write,
    /// The call reads without changing anything.
    Read,
    /// The call runs a shell command; its targets live in the command text.
    Execute,
    /// The call reaches an MCP server.
    Mcp,
    /// The call spawns a subagent.
    Subagent,
    /// The adapter could not classify this host's tool, carrying its spelling.
    ///
    /// The honest escape, and the reason the variant is not called `Unknown`:
    /// something specific was seen and not recognized, which is a different claim
    /// from "nothing was there".
    Other(String),
}

impl Operation {
    /// The stable token, for a pointer-only report and the payload-field surface.
    ///
    /// [`Operation::Other`] renders as `other` and **never as the tool it
    /// carries**: a normalized vocabulary that leaked a host string would be the
    /// thing this type exists to stop, and the spelling is already addressable
    /// through [`Envelope::raw_tool`] for a rule that means to reach it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Operation::Write => "write",
            Operation::Read => "read",
            Operation::Execute => "execute",
            Operation::Mcp => "mcp",
            Operation::Subagent => "subagent",
            Operation::Other(_) => "other",
        }
    }

    /// Whether this operation is one the adapter could not classify.
    ///
    /// Read at every dispatch that would otherwise treat a non-`Write` as safe.
    #[must_use]
    pub const fn is_unclassified(&self) -> bool {
        matches!(self, Operation::Other(_))
    }
}

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
/// `cwd` IS consumed, and by exactly one reader (CLOUD-1109):
/// [`names_a_repository_path`], where a RELATIVE operand is resolved against the
/// call's own working directory before clause 3 asks whether the repository
/// contains it. Before that it was decoded and read by nothing, so a bare
/// relative path was judged as though every call ran from the repository root —
/// and one file named relatively and absolutely from one directory got opposite
/// verdicts.
///
/// The bound that survives: an ABSOLUTE operand is still excluded rather than
/// resolved and refused. Widening clause 3 to cover it would make a call that is
/// allowed today start failing, which the row this fix comes from rules out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Envelope {
    /// The normalized lifecycle event, which policy dispatches on.
    pub event: Event,
    /// The host's own spelling, echoed back in a decision document.
    pub raw_event: String,
    /// The host's own word for the tool being mediated, e.g. `Bash` on Claude
    /// Code and `Shell` on Cursor.
    ///
    /// The second layer of the pair [`Envelope::operation`] completes, and the
    /// same split [`Envelope::event`]/[`Envelope::raw_event`] makes one field up:
    /// `operation` is what policy dispatches on, this is the token echoed back in
    /// a decision document and still addressable by a rule that *means* to be
    /// harness-specific. Normalizing inward and echoing outward are different
    /// directions, and unportability is a diagnostic rather than something to
    /// design out (CLOUD-779).
    pub raw_tool: String,
    /// The normalized operation this call performs, which policy dispatches on.
    ///
    /// Derived by the adapter from [`Harness::operation_of`], so by the time
    /// [`adjudicate`] sees an envelope "this is write-shaped" is a normalized
    /// fact rather than a tool-name comparison the policy layer would have to
    /// make against one host's vocabulary.
    ///
    /// [`Operation::Other`] is **could not look**, never "not a write" — see the
    /// type's own doc.
    pub operation: Operation,
    /// The tool's whole input object; `Value::Null` when the payload had none.
    pub input: Value,
    /// The tool's whole RESULT object on a post-tool event; `Value::Null`
    /// otherwise (CLOUD-776).
    ///
    /// [`Envelope::input`]'s twin, one event later, and it is what turns "ask the
    /// agent to run a command" into a fact-acquisition channel: the engine denies
    /// with [`crate::refusal::Fix::Run`], the agent's own tool runs it, and the
    /// bytes arrive here. **The engine spawns nothing** — house-style §5's read
    /// promise is untouched, because reading a buffer the harness already handed
    /// us is not execution.
    ///
    /// Cheaper and more faithful than the re-typed payload the "agents fetch,
    /// gates decide" pattern uses elsewhere (CLOUD-526 measured that at ~15 KB of
    /// OUTPUT tokens per receipt, and seven forged receipts in one session): the
    /// model does not re-type a tool buffer, so there is no transcription to be
    /// unfaithful and no token cost proportional to the artifact.
    ///
    /// **Never emitted** (rule 4), and here that is load-bearing rather than
    /// formal: a command's stdout can carry anything, so this is the likeliest
    /// field in the envelope to hold a secret. It is decided OVER and never
    /// reproduced — not in a deny message, not in a `-J` document, and not under
    /// the state root.
    ///
    /// Carried as the raw [`Value`] rather than a projection because the shape is
    /// per-tool and only partly surveyed: an MCP tool returns a content-block
    /// array (measured — `tests/board-write-record.bats`), a shell tool returns
    /// something else this repository has not measured. A reader that does not
    /// recognise the shape answers **could not look**, never a fact.
    pub result: Value,
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
    ///
    /// **Repository-relative wherever the target is inside the repository**, and
    /// that is [`Envelope::relativise_writes`]'s doing rather than the adapter's
    /// (CLOUD-1133). The host sends what the host sends: Claude Code sends an
    /// ABSOLUTE `file_path`, and every reader of this field compares it against a
    /// repo-relative glob — `protected` in the typed table, and a consumer's own
    /// module over `input.call.writes`. So the field's spelling is normalized
    /// once, at the boundary that knows where the repository is, rather than by
    /// each reader learning what a root is.
    pub writes: Option<String>,
    /// The path a READ tool named, where the host said one (CLOUD-1258).
    ///
    /// The mirror of [`Envelope::writes`] and derived from the same keys, keyed
    /// on the neutral [`Operation::Read`] rather than on a second per-host tool
    /// list — two lists of one host fact is how the two come to disagree. `None`
    /// for every call that is not a read, which is what keeps the read-side gate
    /// off every other path.
    pub reads: Option<String>,
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
    /// The permission mode the host declares for this turn (CLOUD-895).
    ///
    /// **A HOST FACT, never an inference from the user's prose.** Whether a turn
    /// may write is something the harness states; reading intent out of what the
    /// user typed would be a model verdict, which non-negotiable rule 3 forbids.
    /// So this is the token the host sent and nothing else — the same
    /// echo-the-host's-spelling posture [`Envelope::raw_event`] takes.
    ///
    /// `None` where the host said nothing, which is could-not-look and NOT
    /// "writes are available": [`Envelope::writes_available`] is where that
    /// direction is decided, once.
    pub mode: Option<String>,
}

/// The mode a host names when the turn may propose but not perform.
///
/// Claude Code's spelling, and the only one measured. A host that spells it
/// differently is unrecognised rather than mis-read — which fails toward
/// speaking, the direction an advisory must fail in.
const PLAN_MODE: &str = "plan";

impl Envelope {
    /// Whether a remedy that asks for a WRITE is lawful on this turn
    /// (CLOUD-895).
    ///
    /// **The reader this row adds, and the whole of it — the envelope gains no
    /// authority.** In plan mode the agent may not commit, push, file or land, so
    /// an advisory saying "Land it" or "file it" names an action its recipient is
    /// forbidden to take. A channel that instructs the impossible teaches the
    /// recipient to override the channel, which is CLOUD-339's warning applied to
    /// the boundary that survived it — and `additionalContext` is delivered AFTER
    /// the user's message, so a machine-generated imperative displaces the human's
    /// own ask on every turn it fires.
    ///
    /// **Absent means available**, which is the failing-open direction: a host
    /// that declares no mode gets the advisories it has always had, and only an
    /// explicit `plan` suppresses. Reading silence as read-only would mute the
    /// channel on every host that never sends the field.
    #[must_use]
    pub fn writes_available(&self) -> bool {
        self.mode.as_deref() != Some(PLAN_MODE)
    }
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
impl Envelope {
    /// Read the write target as the REPOSITORY reads it (CLOUD-1133).
    ///
    /// # The defect, measured
    ///
    /// `Envelope::writes` is whatever the host put in `file_path`, verbatim, and
    /// Claude Code puts an ABSOLUTE path there. Every reader of the field
    /// compares it against a repo-relative glob — `protected` through
    /// `PathSet::contains`, and any consumer module over `input.call.writes` —
    /// and a glob anchored at `.serena/memories/` does not match a string that
    /// begins with a filesystem root. Measured over the shipped binary against
    /// this repository's own committed config: the relative spelling was refused
    /// with `path write refused`, the absolute one was **allowed**, and a live
    /// agent `Write` to a protected path created the file. `memory-guard` retired
    /// into that gate (CLOUD-442), so the write shapes it denied were ungated on
    /// the host that sends absolute paths.
    ///
    /// # Why here and not at the comparison
    ///
    /// One place, because there is more than one reader and a fix at one of them
    /// leaves the next author the same trap. It is not `decode`'s, which is pure
    /// and has no repository; it is not `PathSet`'s, which decides membership
    /// over the string it is handed and would answer differently per caller if it
    /// learned about roots.
    ///
    /// # Outside the repository stays outside
    ///
    /// A target that is not under `root` is left exactly as the host sent it: it
    /// must not be relativized into an accidental match, and it must not become a
    /// refusal either. That is the same line `claim-needs-receipt` already draws
    /// for its own predicate. A relative path is left alone too — it is already
    /// what the globs are written against.
    pub fn relativise_writes(&mut self, root: &Path) {
        // BOTH TARGETS, in one place, for the reason this function's own doc
        // gives: there is more than one reader, and a fix at one of them leaves
        // the next author the same trap. `reads` arrived from the same host keys
        // as `writes` (CLOUD-1258), so it arrives with the same absolute
        // spelling and needs the same one normalisation.
        for target in [&mut self.writes, &mut self.reads] {
            let Some(path) = target.as_deref() else {
                continue;
            };
            let Some(relative) = relative_to(root, path) else {
                continue;
            };
            *target = Some(relative);
        }
    }
}

/// The path a READ tool named, from the same keys a write is read from
/// (CLOUD-1258).
///
/// Keyed on the neutral [`Operation::Read`] rather than on a second per-host
/// tool list: [`Harness::write_tools`] exists because a write is what
/// [`Envelope::writes`] is derived from, and two lists of one host fact is how
/// the two come to disagree.
///
/// `notebook_path` is read beside `file_path` for [`Envelope::writes`]'s own
/// reason — a host spells one tool's target differently, and omitting it would
/// leave that tool unjudged, which is the CLOUD-185 shape.
fn read_target(operation: &Operation, input: &Value) -> Option<String> {
    if !matches!(operation, Operation::Read) {
        return None;
    }
    input
        .pointer("/file_path")
        .or_else(|| input.pointer("/notebook_path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
}

/// `path` as `root` would name it, or `None` where that is not a question this
/// can answer: a relative path, a root that will not canonicalize, a target
/// outside the tree.
///
/// **Canonicalized on both sides**, because the two strings are produced by
/// different parties: the host's path may traverse a symlink the root's does not,
/// and a prefix test over uncanonicalized strings answers "outside" for a target
/// that is plainly inside. A target that does not exist yet — the ordinary case
/// for a `Write` creating a file — has no canonical form of its own, so its
/// PARENT is canonicalized and the file name re-attached.
///
/// **The walk is up to the nearest EXISTING ancestor, not one level.** A single
/// `parent()` hop answers only where the write creates a file in a directory that
/// is already there; a write that creates its directory too — `.serena/memories/`
/// with one new topic folder — has no canonical parent either, so the hop failed,
/// the target kept its absolute spelling, and the repo-relative glob missed it.
/// That is CLOUD-1133's own bypass, reachable by writing one directory deeper
/// than the case that closed it, which is why the loop is the fix rather than a
/// second special case.
fn relative_to(root: &Path, path: &str) -> Option<String> {
    let candidate = Path::new(path);
    if candidate.is_relative() {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let resolved = candidate.canonicalize().ok().or_else(|| {
        // Peel components off the tail until something canonicalizes, then put
        // them back in the order they came off. `ancestors` walks parent-first,
        // so the first hit is the DEEPEST existing directory — the one whose
        // canonical form resolves the most symlinks, which is the reading the
        // prefix test below needs.
        let mut trailing: Vec<&std::ffi::OsStr> = vec![candidate.file_name()?];
        for ancestor in candidate.ancestors().skip(1) {
            if let Ok(base) = ancestor.canonicalize() {
                let mut resolved = base;
                for name in trailing.iter().rev() {
                    resolved.push(name);
                }
                return Some(resolved);
            }
            trailing.push(ancestor.file_name()?);
        }
        None
    })?;
    let relative = resolved.strip_prefix(&root).ok()?;
    // FORWARD SLASHES, NOT THE PLATFORM SEPARATOR (CLOUD-1141). Every reader of
    // this value compares it against a repo-relative glob — `protected` through
    // `PathSet::contains`, a consumer module over `input.call.writes` — and those
    // globs are written in git's spelling, which is `/` on every platform. On
    // Windows `Path::to_str` renders `mise-tasks\ready-lint.sh`, which matches
    // none of them, so the normalisation CLOUD-1133 added would hand every
    // Windows caller a string no glob can match: the same silent miss it fixed,
    // one platform over.
    //
    // Caught by CI rather than by reading — `the_absolute_spelling_the_host_sends`
    // is green on Linux and was red on the Windows job, which is exactly the
    // asymmetry a path rendered with `MAIN_SEPARATOR` produces.
    let rendered = relative.to_str()?.replace('\\', "/");
    (!rendered.is_empty()).then_some(rendered)
}

/// **Serialized in `clap`'s spelling, not serde's default** (CLOUD-925). A
/// `[[rule]]` ceiling names a projection with `measures`, so this enum is now
/// config vocabulary as well as CLI vocabulary — and `kebab-case` is what
/// `ValueEnum` already renders, so `--field last-assistant-message` and
/// `measures = "last-assistant-message"` are one spelling. Taking serde's
/// `snake_case` default would have given the same variant two names, which is
/// the drift the shared type is here to prevent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Field {
    /// The host's own event spelling, echoed back untouched.
    ///
    /// UNNORMALIZED on purpose, and the reason is now the ECHO rather than a gap
    /// in [`Event`].
    ///
    /// **The premise this cited is gone, re-read rather than amended a third
    /// time (CLOUD-777, 2026-08-21).** The comment argued from absence twice: it
    /// read *"knows neither `UserPromptSubmit` nor `PostToolBatch`"* until
    /// `PostToolBatch` landed (CLOUD-389), was corrected to cite
    /// `UserPromptSubmit` alone (CLOUD-817), and said in as many words that
    /// answering CLOUD-817 *yes* would remove the premise rather than amend it.
    /// It is answered yes: [`Event::UserPromptSubmit`] exists, so
    /// [`Event::normalize`] now knows every spelling a supported host emits and
    /// the absence argument has nothing left to stand on.
    ///
    /// What survives is a property of the CONSUMER rather than of the enum: a
    /// hook wired to more than one event echoes this value back into its own
    /// reply, and a host reads its own spelling there. `contract-drift` is the
    /// registered example. Normalizing here would hand it `session-start` where
    /// the host said `SessionStart`, so the field stays the host's token and
    /// [`Envelope::event`] stays the concept — the same split those two fields
    /// carry everywhere else.
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
    /// The prompt a subagent spawn commits a fresh context window to.
    ///
    /// The second prose-bearing member, admitted on `LastAssistantMessage`'s
    /// argument rather than a new one: this is a DECODER, and rule 4 governs
    /// what a check reports. `fanout-guard` (CLOUD-287) reads these bytes to
    /// count them and emits only a count, a cap and repo paths — never a byte of
    /// the prompt.
    ///
    /// It is also the member that could not be served any other way. A spawn is
    /// not shell-shaped, so `Command` is empty for it, and the prompt lives in
    /// [`Envelope::input`] — which is exactly what this allowlist exists to keep
    /// a caller from addressing by path. Naming this one projection is the
    /// deliberate edit the type's own doc calls for.
    ///
    /// APPENDED, never inserted. `semver` reads a reordered variant as
    /// `enum_no_repr_variant_discriminant_changed` — a break — and this addition
    /// is patch-compatible only at the end. The order carries no meaning.
    Prompt,
    /// Whether the host was asked to run this call in the background.
    ///
    /// `"true"` or `"false"`, never the flag's own JSON spelling: the caller is
    /// a shell script comparing against a literal, and a decoder that echoed
    /// `True` or `1` for some host would move the per-harness normalization out
    /// of here and into every script.
    ///
    /// THE SECOND MEMBER READ OUT OF [`Envelope::input`], and the less exposed
    /// of the two. The allowlist's safety argument is that it can never name
    /// [`Envelope::input`] wholesale, because a tool input is among the likeliest
    /// places in this engine for a secret to appear (non-negotiable rule 4); a
    /// boolean projection of one named key cannot carry one. Absent reads as
    /// absent rather than as `false` — "the host did not say" and "the host said
    /// no" are the same decision for every caller today, but collapsing them
    /// here would make them inseparable for one that is not.
    ///
    /// CLOUD-613 named this as a fact the mediated envelope hides, which is why
    /// `run-shape-guard`'s surviving families could not be expressed as config
    /// rows. It is hidden no longer; growing this allowlist is the deliberate
    /// edit the type's own doc calls for, and CLOUD-821 is the caller that
    /// needed it.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    RunInBackground,
    /// The `id` a structured call names its subject by (CLOUD-987).
    ///
    /// THE THIRD MEMBER READ OUT OF [`Envelope::input`], and it is what lets a
    /// row tell **creating** a thing from **annotating** one. CLOUD-312's rows 1
    /// and 3 both turn on it: a `save_issue` carrying no `id` opens a row, one
    /// carrying an `id` edits a row that already exists, and gating the second
    /// as though it were the first is the outcome `issue-search-guard`'s own
    /// header says *"would get the guard switched off within a day."*
    ///
    /// The allowlist's safety argument is unchanged and is the reason this is a
    /// MEMBER rather than a config-named key: it can never address
    /// [`Envelope::input`] wholesale, so a caller cannot point a rule at an
    /// arbitrary path in the likeliest place in the envelope for a secret. A key
    /// somebody enumerated here cannot carry one by accident.
    ///
    /// A non-string value reads as absent rather than as its debug rendering,
    /// [`Field::Prompt`]'s rule: a caller comparing identifiers must never be
    /// handed `{"a":1}` and told it is one.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    InputId,
    /// The `state` a structured call moves its subject to (CLOUD-987).
    ///
    /// The fourth and last member read out of [`Envelope::input`], on
    /// [`Field::InputId`]'s argument. `board-move-guard` (CLOUD-312's row 3)
    /// fires only when a call MOVES something rather than merely editing it, so
    /// without this the row would gate every edit — the same over-fire
    /// [`Field::InputId`] exists to prevent one key over.
    ///
    /// APPENDED, never inserted, for the reason stated on [`Field::Prompt`].
    InputState,
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
            Field::ToolName => Some(envelope.raw_tool.clone()),
            Field::Command => Some(envelope.command.clone()),
            Field::Cwd => envelope.cwd.as_ref().map(|path| path.display().to_string()),
            Field::StopHookActive => envelope.stop_active.map(|active| active.to_string()),
            Field::LastAssistantMessage => envelope.last_message.clone(),
            // Read out of `input`, and only ever this key. A
            // non-string value reads as absent rather than as its debug
            // rendering: a caller counting characters must never be handed
            // `{"a":1}` and told it is a prompt.
            Field::Prompt => envelope
                .input
                .get("prompt")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Field::TranscriptPath => envelope.transcript.clone(),
            // The second member read out of `input`, and only ever this key.
            // Two spellings because the hosts disagree the same way they do
            // over `tool_response`/`toolResponse`, and a caller must not have
            // to know which host it is behind.
            Field::RunInBackground => envelope
                .input
                .get("run_in_background")
                .or_else(|| envelope.input.get("runInBackground"))
                .and_then(Value::as_bool)
                .map(|flag| flag.to_string()),
            // The third and fourth members read out of `input`, and only ever
            // these keys. Both go through `as_str`, so a non-string value reads
            // as absent — `Field::Prompt`'s rule, and load-bearing for
            // `InputId`, whose whole job is to tell present from absent.
            Field::InputId => envelope
                .input
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Field::InputState => envelope
                .input
                .get("state")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
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
/// entirely", and that is not expressible in this return type. Since CLOUD-824
/// there is no launcher to report it: an absent binary is a command the host
/// cannot run, which every supported host reports through its own channel, and
/// this consumer's provisioning (`mise run install:local`, from
/// `session-start.sh`) fails loudly at the moment it could still be fixed.
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
    /// Escalate to a human rather than deciding (CLOUD-45).
    ///
    /// Carries a [`Refusal`] for the same reason [`Decision::Deny`] does: the
    /// person being asked needs to know what is being asked and what the
    /// sanctioned path is, and an escalation with nothing but an id is the
    /// un-actionable shape CLOUD-122 exists to prevent. It is also what makes
    /// the degradation lossless — where escalation is unreachable this value
    /// becomes a deny, and the deny already has everything it needs.
    ///
    /// **Not a third exit code.** §7's table has no room for one and needs none:
    /// an answered escalation is exit `0` with a body, and an unanswerable one is
    /// the policy verdict `2`. The variant exists so the *degradation* is decided
    /// once, at the boundary that consults the capability table, rather than
    /// guessed at each deny site.
    ///
    /// **Nothing in `batten.toml` produces this yet, deliberately.** CLOUD-45 owns
    /// the degradation — this value, [`encode_ask`], and the capability row they
    /// consult — and CLOUD-340 owns the *vocabulary* a consumer reaches it with,
    /// which its refinement records as an `ask` severity accepted only for
    /// `mediated_call` scope. Inventing a second column here would give one
    /// question two config surfaces and contradict a decision already taken
    /// (non-negotiable rule 6).
    Ask(Refusal),
    /// A deny a live waiver suppressed, carrying the record it owes (CLOUD-610).
    ///
    /// **An allow, not a fourth verdict.** The call proceeds, exit `0`, §7's
    /// table untouched — what distinguishes it from [`Decision::Allow`] is that
    /// something was refused and then let through, and that is a fact somebody
    /// has to be able to read afterwards. Collapsing it into `Allow` would make
    /// the suppression the one policy event that leaves no trace, which is the
    /// undesigned hatch the waiver table exists to replace (CLOUD-208).
    ///
    /// It is a variant rather than a side effect at the deny site for the reason
    /// [`Decision::Ask`] is one: this function is contractually pure and owns no
    /// channel. The boundary writes the line, so the audit and the verdict are
    /// decided in one place and cannot disagree about whether a call was waived.
    Waived(crate::waiver::Suppressed),
    /// An allow the host is told not to prompt about, with the reason it spends.
    ///
    /// **An allow, not a fifth verdict**, on [`Decision::Waived`]'s own reading:
    /// the call proceeds, exit `0`, §7's table untouched. What distinguishes it is
    /// that something the operator already permitted was about to be asked about
    /// again, and this says so instead.
    ///
    /// **It can only ever upgrade an [`Decision::Allow`], and the boundary enforces
    /// that rather than trusting it.** A pre-approval that could replace a `Deny`
    /// would let a dispatched program spend a refusal the engine's own rows
    /// reached — which is the one direction this whole surface must be unable to
    /// travel. `Deny`, `Ask` and `Waived` are all left standing.
    ///
    /// Carries a plain `String` rather than a [`Refusal`], and the asymmetry is the
    /// point: a `Refusal` exists to name a remedy, and a grant has nothing to
    /// remedy. What it owes instead is provenance — WHICH committed rule is being
    /// projected onto WHICH live name — and that is prose its producer writes,
    /// because only the producer knows. §5's "every refusal names something to
    /// run" does not reach here, there being no refusal.
    ///
    /// Degrades to a plain allow wherever [`Capabilities::preapprove`] is
    /// unreachable, which is silence and is the host's ordinary flow.
    Preapproved(String),
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

    // The neutral vocabulary, resolved here beside `writes` for the same reason
    // (CLOUD-779): by the time `adjudicate` sees an envelope, "what does this
    // call do" is already a normalized fact rather than a comparison the policy
    // layer would have to make against one host's tool names.
    let operation = harness.operation_of(&tool);

    let reads = read_target(&operation, &input);

    Some(Envelope {
        event,
        raw_event,
        raw_tool: tool,
        operation,
        command: input
            .pointer("/command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        writes,
        reads,
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
        // The result buffer (CLOUD-776), read the way `input` is: the host's own
        // key, with the aliases the survey recorded. Absent on every pre-tool
        // payload, which is `Value::Null` rather than an error — the field is a
        // post-tool fact and a pre-tool call simply does not have one.
        result: value
            .get("tool_response")
            .or_else(|| value.get("toolResponse"))
            .or_else(|| value.get("tool_result"))
            .cloned()
            .unwrap_or(Value::Null),
        stop_active: value.get("stop_hook_active").and_then(Value::as_bool),
        last_message: value
            .get("last_assistant_message")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        transcript: value
            .get("transcript_path")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // CLOUD-895, read the way the three above are and for the same reason:
        // a fourth `get` on an already-parsed value, rather than a second decoder
        // to keep in step with the BOM strip and the alias tables.
        mode: ["permission_mode", "permissionMode"]
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .filter(|mode| !mode.is_empty())
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

/// The GENERAL escape hatch: the whole-call "do not mediate this" switch, and
/// the fallback a row declaring no [`crate::rules::Rule::bypass_env`] advertises.
///
/// **Renamed from `BATTEN_GH_GUARD_BYPASS` by CLOUD-437, and the old name was a
/// fossil rather than a description.** It was the first retiring bash guard's
/// hatch, kept when that guard was ported and then inherited by every predicate
/// the engine absorbed after it — so a `protected-mutation` deny about a Serena
/// memory told its reader to set a `gh` variable. Measured on this tree:
///
/// ```text
/// Refused by protected-mutation: `Write` targets the protected path .serena/memories/core.md.
/// Fix: … Bypass with BATTEN_GH_GUARD_BYPASS=1.
/// ```
///
/// That breaks CLOUD-122's contract in a way worse than a missing pointer: an
/// operator who reads `GH_GUARD` concludes the refusal came from somewhere it did
/// not, and it reads as evidence that a `gh` guard is what is installed — the
/// exact mis-modelling this layer keeps producing.
///
/// `BATTEN_GH_GUARD_BYPASS` survives, but only where it is TRUE: as the declared
/// `bypass_env` of the `gh`-lifecycle rows that legitimately own it. There is no
/// dual-honour window — two live names for one hatch is the second authority this
/// module's one-definition property forbids, and there is no external consumer to
/// protect.
///
/// It stays resolved at the boundary before the config load, because per-row
/// hatches cannot be: which hatches exist is a property of the loaded rows, so
/// those resolve after the load and only for rows that declare one. That ordering
/// is why the general hatch survives as a separate switch rather than becoming
/// another row's name.
///
/// **It no longer skips the load, and that invariant is retired rather than
/// eroded.** This paragraph used to end "which is what keeps the hot path free: a
/// bypassed call must never pay a config read". It could not survive the
/// protected gate becoming non-bypassable — deciding whether a path is protected
/// needs the `protected` and `[[verb]]` tables, which are the config. A bypassed
/// adjudicable call pays one load, the `noop`-to-`check` difference in `perf`,
/// ~0.7 ms against a 100 ms budget. A call with nothing to adjudicate still skips
/// it, and that is the arm the hot path rides.
///
/// # It does not suppress the protected-path gate
///
/// One class is outside this hatch's reach: `path write refused` is adjudicated
/// even when this is set, because it declares an override route and the boundary
/// honours a spent admission for it. A refusal whose only way through is a string
/// somebody knows is a password rather than a gate, and this repository already
/// retired that shape once — `issue file same`'s two variables were deleted
/// rather than kept beside the admission mechanism, on the stated ground that *the
/// point of the admission mechanism is that the bare variable stops working*.
///
/// **The no-config-read property above still holds, and the cost that changed is
/// stated rather than left to be discovered.** A bypassed call reaching a
/// protected path now pays the two `protected_write` stages, which is CPU over an
/// envelope already decoded and a policy already in hand — no additional read, no
/// spawn, no clock. A bypassed call that names no protected path pays a path-set
/// comparison and nothing else.
pub const BYPASS_ENV: &str = "BATTEN_HOOK_BYPASS";

/// The mediated-call policy this run adjudicates against.
///
/// Built from the *resolved* config (§8), not the committed file alone, so a
/// `batten.local.toml` that **adds** a shape row is a gate the hook actually
/// applies — the raise-only override model is worth nothing at a surface that
/// ignores it — and `--config-from` is inherited for free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The host this policy is being applied on, and through it the
    /// [`Capabilities`] row a rule may branch on (CLOUD-779).
    ///
    /// **Engine-side plumbing, deliberately not a `[[rule]]` column.** The
    /// resolved config already travels this way into [`adjudicate`], so the
    /// harness's capability row travels the same way and the evaluator reads it
    /// from here — no config key, no schema regeneration, and no collision with
    /// the two issues that do add `Rule` columns and do regenerate the two schema
    /// files (CLOUD-772, CLOUD-773).
    ///
    /// It is data resolved at the boundary like every other fact, which is what
    /// keeps [`adjudicate`] contractually pure: nothing here reaches for the
    /// environment inside the evaluator.
    harness: Harness,
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
    /// What one emission of the advisory channel may cost (CLOUD-896).
    ///
    /// Engine-side plumbing on `harness`'s reading: resolved at the boundary and
    /// carried in, so the emission site can ask without reaching for config.
    pub advisory: Option<crate::advisory::Channel>,
    /// What ONE emitted mediated refusal line may cost (CLOUD-1050, CLOUD-1386).
    ///
    /// Carried here for `advisory`'s reason exactly — resolved at the boundary so
    /// the rendering site can ask without reaching for config, which is what keeps
    /// `render` unable to see the policy (CLOUD-898).
    ///
    /// ONE AUTHORITY OVER BOTH ARMS. `deny_text` renders a first sighting long and
    /// a repeat short, and before this only the repeat was bounded: the first
    /// sighting could carry a consumer `[[rule]]` row's whole `reason`, prose and
    /// all, because nothing measured it. A second ceiling for the other arm would
    /// have been two thresholds that can disagree about one line.
    pub refusal: Option<crate::refusal::Ceiling>,
    /// Programs known to only READ their operands (CLOUD-1141).
    ///
    /// The other half of the gate above, and the half that decides what an
    /// UNLISTED program means. `verbs` enumerates mutations, so before this a
    /// program in neither table wrote a protected file unrefused — measured,
    /// `python3 -c "open('batten.toml','w')"` and `perl -pi -e` were allowed
    /// where `echo >`, `sed -i` and `tee` were denied.
    ///
    /// With this set, an unlisted program naming a protected path is REFUSED, so
    /// the omission that used to be a hole is now a false refusal somebody
    /// notices. Enumerating readers is safe in the direction enumerating writers
    /// was not.
    protected_readers: Vec<String>,
    /// What to run instead, per protected path class (CLOUD-280).
    ///
    /// Message composition only — it never decides whether the gate fires, which
    /// is why it sits beside `protected` rather than inside it and why no
    /// raise-only clamp applies to it.
    redirects: Vec<Redirect>,
    /// The agent-sourced facts this repository declares (CLOUD-776).
    ///
    /// Carried on the policy for the reason `verbs` and `protected` are: the
    /// boundary needs them to resolve a check, and the refusal needs the declared
    /// command so the fix text and the verification target are ONE value. Two
    /// copies of that string is the defect CLOUD-779 and CLOUD-601 both were —
    /// a declaration kept in step by hand with what it implies — and here the
    /// drift would not be a silent allow but a forged fact.
    facts: Vec<crate::facts::Declared>,
    /// The receipts this repository mints from a tool result (CLOUD-1024).
    ///
    /// Carried here for `facts`' reason exactly: the boundary needs the table to
    /// decide what a completed call leaves behind, and [`adjudicate`] is
    /// contractually pure, so the table travels as a value rather than being
    /// re-read at the point of use.
    mints: Vec<crate::mint::Declared>,
    recorders: Vec<crate::recorder::Declared>,
    patterns: Vec<crate::pattern::NamedPattern>,
    programs: std::collections::BTreeMap<String, crate::recorder::Program>,
    /// The enabled policy bundles, compiled at the boundary (CLOUD-647,
    /// CLOUD-837).
    ///
    /// Here for the same reason `facts` and `verbs` are: [`adjudicate`] is
    /// contractually pure, so reading and compiling a bundle is the boundary's
    /// work and what reaches the evaluator is a value. It is also what makes a
    /// broken module a **config error at load** rather than a denied tool call —
    /// regorus reports a conflict or a recursion at evaluation, which on this
    /// path is the worst possible time and the wrong exit class.
    ///
    /// A BUNDLE rather than a module since CLOUD-837: one engine holds every
    /// module a row enables, so they compose into one rule set instead of N
    /// isolated ones that cannot share a helper.
    bundles: Vec<crate::policy::Bundle>,
    /// The refusal vocabulary this policy renders against (CLOUD-1050): the
    /// consumer's `[[verdict]]` rows unioned with what the binary vendors.
    ///
    /// Carried on the POLICY rather than looked up per call, because
    /// `adjudicate` is contractually pure — it may not read a config — and
    /// because the merge is fixed for the life of the load. A linear scan over a
    /// table this size is free against CLOUD-689's budget; what would not be is
    /// resolving the table again per mediated call.
    verdicts: Vec<crate::verdict::DeclaredVerdict>,
    /// The repository this policy speaks for, so an operand can be resolved the
    /// way the repository names it (CLOUD-1236).
    ///
    /// CLOUD-1133 measured that an ABSOLUTE path walks past `protected` — the
    /// globs are repo-relative and [`normalise`] strips only a leading `./` — and
    /// fixed it at [`Envelope::relativise_writes`], which had a root handed to it
    /// at its call site. It argued the fix belonged in one place *"because there
    /// is more than one reader and a fix at one of them leaves the next author the
    /// same trap"*, then scoped the command half out on the premise that a shell
    /// operand *"is usually relative"*.
    ///
    /// [`protected_mutation`] was that next reader, and the premise was false: it
    /// parses its own operands out of the command string and had nothing to
    /// resolve them against, so every protected path — the declared globs and the
    /// derived module paths alike — was reachable from the Bash surface on every
    /// mutating verb by spelling the operand absolutely.
    ///
    /// `None` where there is no repository to be relative to: a zero-config load,
    /// or a fixture that never named one. That degrades to exactly the behaviour
    /// before this field existed, which is the direction an omitted value must
    /// fail in.
    root: Option<std::path::PathBuf>,
}

impl Policy {
    /// The policy that denies nothing.
    ///
    /// Not an error state: a repository with no authority, or a bypassed run, has
    /// declared no mediated-call policy, and "nothing declared" means "nothing
    /// denied". Mirrors `Config::declaring_nothing`.
    #[must_use]
    pub fn declaring_nothing(harness: Harness) -> Policy {
        Policy {
            harness,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            // No authority means no repository to be relative to, and nothing is
            // protected here anyway — the set above is empty, so there is no
            // membership question for a root to change the answer to.
            root: None,
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
    pub fn from_resolved(
        resolved: &Resolved,
        harness: Harness,
        root: &std::path::Path,
        reference: Option<&str>,
    ) -> anyhow::Result<Policy> {
        Ok(Policy {
            harness,
            shapes: resolved
                .rules
                .iter()
                .filter(|rule| rule.scope == RuleScope::MediatedCall)
                .cloned()
                .collect(),
            fail_on_warning: resolved.fail_on_warning,
            verbs: resolved.verbs.clone(),
            // EVERY ENABLED MODULE **AND EVERY BUNDLE ROOT** IS A PROTECTED
            // PATH, derived rather than asked for (CLOUD-763's fourth bound,
            // CLOUD-833's sharpest consequence). §8's security property is that
            // "an agent's context can never influence the rules it is judged
            // by", and a module a consumer forgot to list in `protected` is
            // exactly that influence. Deriving it from the rule table means
            // enabling policy protects it by construction — there is no spelling
            // for an enabled-but-unprotected module, so the bound cannot be
            // half-configured.
            //
            // THE ROOT, NOT THE FILES UNDER IT, and that is the whole of the
            // extension: a bundle is a folder whose membership changes without a
            // config edit, so protecting the names present at load would lapse
            // the moment a module was added. `<root>/**` is what keeps the
            // property total — a folder must not be less protected than a named
            // file was, which is exactly what would have happened if this had
            // been left reading `module` alone.
            protected: PathSet::includes(
                "protected",
                &resolved
                    .protected
                    .iter()
                    .cloned()
                    .chain(
                        resolved
                            .rules
                            .iter()
                            .filter(|rule| rule.kind == RuleKind::Policy)
                            .flat_map(policy_protected_paths),
                    )
                    .collect::<Vec<String>>(),
            )?,
            advisory: resolved.advisory.clone(),
            refusal: resolved.refusal.clone(),
            protected_readers: resolved.protected_readers.clone(),
            redirects: resolved.redirects.clone(),
            facts: resolved.facts.clone(),
            mints: resolved.mints.clone(),
            recorders: resolved.recorders.clone(),
            patterns: resolved.patterns.clone(),
            programs: resolved.programs.clone(),
            // Boundary I/O, and this is the only place it happens: `load`
            // reads, compiles and smoke-queries every registered module here so
            // that `adjudicate` stays contractually pure and a broken module is
            // a config error rather than a denied tool call (CLOUD-647).
            //
            // NARROWED TO THIS SURFACE, which this function's own doc has always
            // claimed — "the tree engine's rules are simply absent here" — and
            // which the `shapes` field above does and this one did not. A
            // `scope = "tree"` policy row cannot fire on a mediated call, so
            // compiling its modules here buys a verdict nothing can read, on the
            // one path with a p95 budget.
            //
            // MEASURED, because that is the only reason it changed: adding
            // `shell-hygiene`'s two tree-scoped modules took `wired` from
            // 9.13 ms to 17.71 ms (1.94x, against a 1.30x gate) — `load`
            // compiles AND smoke-queries every module it is handed, so the cost
            // is per invocation and grows with every preset a consumer enables.
            // The narrowing has to happen before the call, not inside it, since
            // `load` is deliberately surface-blind.
            //
            // What this gives up, stated rather than absorbed: a broken
            // TREE-scoped module is no longer a config error at hook time. It
            // still is at `batten check`/`enforce`, which is where a tree rule
            // is evaluated and where `verify` and CI both reach it — so the
            // module is still refused before it can matter, one surface over.
            //
            // AND THE MODULE CHECKS DO NOT RUN HERE EITHER (CLOUD-885), which is
            // the same finding reached from the other side. Narrowing the rows
            // above removes the tree modules; this removes the AST walk over the
            // ones that remain. `check_no_inline_regex` and
            // `check_tree_paths_are_emittable` read a module through
            // `get_ast_as_json`, which serialises every rule of every module —
            // and their answer is a property of the module TEXT, so it is fixed
            // for the life of the load and identical on every surface. CI
            // measured re-deriving it per call at `wired` 14.03 ms -> 22.98 ms
            // (1.638x). Both are the same rule: the mediated call loads and
            // decides; a config fault is reported where config faults are
            // reported.
            bundles: crate::policy::load(
                root,
                &resolved
                    .rules
                    .iter()
                    .filter(|rule| rule.scope == RuleScope::MediatedCall)
                    .cloned()
                    .collect::<Vec<Rule>>(),
                crate::policy::Vocabulary {
                    patterns: &resolved.patterns,
                    verdicts: &resolved.verdicts,
                    recorders: &resolved.recorders,
                },
                crate::policy::ModuleChecks::SkipOnHotPath,
                reference,
            )?,
            verdicts: crate::policy::registry_for(&resolved.verdicts)?,
            // The root the caller already resolved to find this config, kept
            // rather than discarded (CLOUD-1236). It is the same authority
            // `relativise_writes` is given one layer up, which is the whole point:
            // both readers of `protected` now resolve a path the same way.
            root: Some(root.to_path_buf()),
        })
    }

    /// The host capability row this policy is being evaluated against
    /// (CLOUD-779, CLOUD-601).
    ///
    /// (See [`policy_protected_paths`] above for the derivation `protected`
    /// folds in.)
    ///
    /// The read side of the plumbing declared on [`Policy::harness`]: a gate that
    /// needs to know whether the host can be asked, whether its stop event can
    /// veto, or which events it emits, asks here rather than guessing or being
    /// silently degraded. Compiled-in data, so the answer costs nothing on the
    /// hottest path in the binary.
    #[must_use]
    pub const fn capabilities(&self) -> Capabilities {
        self.harness.capabilities()
    }

    /// The host this policy is being applied on.
    #[must_use]
    pub const fn harness(&self) -> Harness {
        self.harness
    }

    /// Every agent-sourced fact this repository declares (CLOUD-776).
    #[must_use]
    pub fn declared_facts(&self) -> &[crate::facts::Declared] {
        &self.facts
    }

    /// Every receipt this repository mints from a tool result (CLOUD-1024).
    ///
    /// The complement of [`Policy::declared_facts`] on the other selector — that
    /// one is keyed to a command the agent ran, this to the tool whose result
    /// carries the evidence — and read at the same boundary, on the same event.
    #[must_use]
    pub fn declared_mints(&self) -> &[crate::mint::Declared] {
        &self.mints
    }

    /// Every record this repository writes from a tool result (CLOUD-1051).
    ///
    /// [`Policy::declared_mints`]'s sibling on the same selector. The difference
    /// is what a column may carry: a mint renders a closed template over the
    /// payload, a recorder may additionally run a declared program and record
    /// what it decided.
    #[must_use]
    pub fn declared_recorders(&self) -> &[crate::recorder::Declared] {
        &self.recorders
    }

    /// The `[[pattern]]` table, compiled, for a recorder's `section` narrowing.
    ///
    /// Compiled HERE rather than held compiled, because this is the one caller
    /// and it is reached only once a recorder has already matched the tool — so
    /// the overwhelming majority of mediated calls never pay for it. A pattern
    /// that will not compile is dropped rather than raised: `pattern::validate`
    /// has already refused it at load, so reaching this with a bad one is
    /// impossible for a config that loaded, and a panic here would be a hook
    /// becoming the reason work stops.
    #[must_use]
    pub fn compiled_patterns(&self) -> std::collections::BTreeMap<String, regex::Regex> {
        crate::pattern::compiled(&self.patterns)
    }

    /// The programs a `[[recorder]]` may run, by id.
    ///
    /// Held beside the recorders rather than resolved per row, because
    /// `recorder::validate` has already refused any row naming an id this table
    /// does not carry — so a lookup here cannot fail for a config that loaded.
    #[must_use]
    pub fn declared_programs(
        &self,
    ) -> &std::collections::BTreeMap<String, crate::recorder::Program> {
        &self.programs
    }

    /// The agent-sourced fact this check names, if the consumer declared one
    /// (CLOUD-776).
    ///
    /// The one authority for both halves: the boundary asks it what command to
    /// verify a record against, and [`receipt_refusal`] asks it what command to
    /// tell the agent to run. A check naming no declared fact answers `None` and
    /// is an ordinary receipt, which is what keeps this additive.
    #[must_use]
    pub fn agent_fact(&self, check: &str) -> Option<&crate::facts::Declared> {
        self.facts.iter().find(|fact| fact.name == check)
    }

    /// The keying declared for `check` by the rows that require it (CLOUD-859).
    ///
    /// **Policy-wide, deliberately, where [`Policy::required_checks_for`] is
    /// scoped to the call.** The record is WRITTEN on the post-tool event of the
    /// declared command or tool — reading the review — and READ on the mediated call the
    /// receipt row selects — `gh pr ready`. Those are different envelopes, so a
    /// call-scoped lookup finds nothing at the moment the record is filed, and
    /// the two halves would file and look under different subjects.
    ///
    /// The first match is the answer because `rules::validate` refuses one check
    /// required under two keys: the keying is unambiguous by construction rather
    /// than by picking a winner here.
    #[must_use]
    pub fn receipt_key_for_check(&self, check: &str) -> Option<ReceiptKey> {
        self.shapes
            .iter()
            .filter(|rule| rule.kind == RuleKind::Receipt)
            .find(|rule| rule.receipt_names().any(|required| required == check))
            .map(Rule::receipt_key)
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
    ///
    /// Each name carries **its row's keying** (CLOUD-444), because that is what
    /// the boundary needs in order to look in the right place: a HEAD-keyed
    /// receipt lives in the content store under a fingerprint, a branch-keyed one
    /// beside the branch. `rules::validate` refuses one name required under two
    /// keys, so collapsing to a map cannot lose a distinction a config drew.
    #[must_use]
    pub fn required_checks_for(
        &self,
        envelope: &Envelope,
    ) -> std::collections::BTreeMap<String, ReceiptKey> {
        matching_receipt_rows(self, envelope)
            .into_iter()
            .flat_map(|rule| {
                let key = rule.receipt_key();
                rule.receipt_names().map(move |check| (check.clone(), key))
            })
            .collect()
    }

    /// The declared maximum age, per check, for the rows this call selects
    /// (CLOUD-988).
    ///
    /// Empty is the common answer and the point: a repository declaring no bound
    /// buys no `stat` per receipt, the same narrowing
    /// [`Policy::required_checks_for`] applies to the store itself.
    ///
    /// **The tightest bound wins where two rows disagree**, rather than
    /// declaration order. Everything else on this surface breaks a tie by
    /// declaration order, and that is right when the rows name alternatives — one
    /// `base` to read commits since, one subject to file under. A maximum age is
    /// not an alternative but a constraint, and two constraints over one check
    /// both hold: honouring the looser one would let adding a row RELAX a bound
    /// already declared, which is the raise-only discipline `[overrides]` keeps
    /// (house-style §8) read the same way.
    #[must_use]
    pub fn max_age_for(&self, envelope: &Envelope) -> std::collections::BTreeMap<String, u64> {
        let mut bounds: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for rule in matching_receipt_rows(self, envelope) {
            let Some(max_age) = rule.max_age else {
                continue;
            };
            for check in rule.receipt_names() {
                bounds
                    .entry(check.clone())
                    .and_modify(|current| *current = (*current).min(max_age))
                    .or_insert(max_age);
            }
        }
        bounds
    }

    /// The declared receipt-field bound, per check, for the rows this call
    /// selects (CLOUD-1100).
    ///
    /// [`Policy::max_age_for`]'s twin, and empty is the common answer for the
    /// same reason: a repository declaring no bound opens no receipt to read a
    /// field out of.
    ///
    /// **First declaration wins where two rows disagree**, which is the OPPOSITE
    /// tie-break from `max_age` and deliberately so. Two maximum ages over one
    /// check are two constraints and both hold, so the tighter one wins. Two
    /// required VALUES over one field are alternatives — at most one can be
    /// satisfied — so combining them would make the check unsatisfiable, which is
    /// the "very strict policy" that is really a config error. Declaration order
    /// is what every other alternative on this surface breaks a tie by.
    #[must_use]
    pub fn field_bound_for(
        &self,
        envelope: &Envelope,
    ) -> std::collections::BTreeMap<String, crate::rules::FieldBound> {
        let mut bounds: std::collections::BTreeMap<String, crate::rules::FieldBound> =
            std::collections::BTreeMap::new();
        for rule in matching_receipt_rows(self, envelope) {
            let Some(bound) = rule.requires_field.as_ref() else {
                continue;
            };
            for check in rule.receipt_names() {
                bounds.entry(check.clone()).or_insert_with(|| bound.clone());
            }
        }
        bounds
    }

    /// Whether any row on this call could read the pinned-program fact
    /// (CLOUD-1028).
    ///
    /// A `policy` row is the only consumer — the fact reaches a decision through
    /// the module document and through nothing else — so a repository declaring
    /// no mediated module pays no file read, which is the same narrowing
    /// [`Policy::reads_prospective`] applies one function down and for the same
    /// measured reason.
    ///
    /// It over-resolves deliberately: a module that never mentions the fact
    /// still buys the read. The alternative is asking a Rego bundle which keys
    /// it touches, which is a static analysis of somebody else's program — and
    /// under-resolving here would hand a module `null` and call it an answer.
    ///
    /// **Severity is NOT a conjunct here, and the first draft had it.** A row at
    /// `warn` still runs its module and still speaks, so narrowing to rows that
    /// BLOCK would have left the reporting landing of a predicate — the one
    /// CLOUD-320's discipline asks for before any promotion — resolving
    /// could-not-look on every call and reporting nothing. A predicate that
    /// cannot be measured cannot be promoted, so the narrowing would have made
    /// the discipline unsatisfiable rather than cheap.
    #[must_use]
    pub fn reads_pinned(&self, envelope: &Envelope) -> bool {
        self.shapes
            .iter()
            .any(|rule| rule.kind == RuleKind::Policy && modifier_admits(rule, envelope))
    }

    /// Whether any row on this call reads the task receipt (CLOUD-856).
    ///
    /// Narrower than [`Policy::reads_pinned`] by one term, deliberately: that
    /// fact is a property of the project and any policy row may want it, where
    /// this one is only ever read by a row that named a manifest. So a repository
    /// with mediated modules and no `[[rule.tasks]]` opens nothing — the
    /// CLOUD-460 narrowing that keeps a call no row selects for doing less work
    /// than `--help`.
    #[must_use]
    pub fn reads_tasks(&self, envelope: &Envelope) -> bool {
        self.shapes.iter().any(|rule| {
            rule.kind == RuleKind::Policy
                && !rule.tasks.is_empty()
                && modifier_admits(rule, envelope)
        })
    }

    /// Every transcript extraction this policy declares (CLOUD-1172).
    ///
    /// Not narrowed by an envelope: an extractor is declared by a row and its
    /// result is projected for every call that reaches a module, exactly as the
    /// counts it reduces are a property of the session rather than of one call.
    /// A repository declaring none opens nothing, which is the narrowing that
    /// matters.
    #[must_use]
    pub fn declared_extracts(&self) -> Vec<crate::facts::ExtractQuery> {
        self.shapes
            .iter()
            .filter(|rule| rule.kind == RuleKind::Policy)
            .flat_map(|rule| rule.extract.iter().cloned())
            .collect()
    }

    /// Every task manifest this policy declares, for the session-start mint.
    ///
    /// Not narrowed by an envelope, and that asymmetry with [`Policy::reads_tasks`]
    /// is the point: minting happens once for the whole session, so it must cover
    /// every row that could later read the record rather than the rows one call
    /// happens to select.
    #[must_use]
    pub fn declared_tasks(&self) -> Vec<crate::facts::TaskQuery> {
        self.shapes
            .iter()
            .filter(|rule| rule.kind == RuleKind::Policy)
            .flat_map(|rule| rule.tasks.iter().cloned())
            .collect()
    }

    /// Whether any row on this call decides over what the write would LAND
    /// (CLOUD-758).
    ///
    /// `false` is the common answer and the point of the function: a repository
    /// declaring no content-keyed row must not pay a file read on any call, and
    /// a call that is not a write must not pay one either. Same narrowing
    /// discipline as [`Policy::required_checks_for`] and
    /// [`Policy::key_base_for`] — CLOUD-460's lesson, which is why a call no row
    /// selects for still does less work than `--help`.
    #[must_use]
    pub fn reads_prospective(&self, envelope: &Envelope) -> bool {
        envelope.event == Event::PreTool
            && envelope.operation == Operation::Write
            && self.shapes.iter().any(|rule| {
                // The gate's own row filter, applied here too: `content_rules`
                // skips a row `blocks` says nothing about, so counting one
                // here would buy a file read for a verdict no row can reach.
                rule.kind == RuleKind::Shape
                    && rule.content.is_some()
                    && blocks(rule.severity(), self.fail_on_warning)
                    // Same cost argument as `manifest_ceiling_for`: `content_rules`
                    // re-checks the modifier before refusing, so an unadmitted row
                    // cannot deny here — it can only buy a file read for a verdict
                    // no row will reach, which is the one thing this function
                    // exists to avoid.
                    && modifier_admits(rule, envelope)
            })
    }

    /// The rev a `requires_key` row needs commit evidence read since, if one
    /// fires on this call at all (CLOUD-446).
    ///
    /// `None` is "do not look", and it is the common answer: a call that matches
    /// no keyed shape row — which is nearly every call — must not pay for a
    /// branch read and a `git log`. Same selection function [`shape_rules`]
    /// adjudicates with, so what the boundary resolves and what the core then
    /// judges cannot disagree about which rows fire.
    ///
    /// The **first** such row decides the range. Two keyed rows disagreeing about
    /// `base` is a config question with two answers, and declaration order is the
    /// tie-break everywhere else on this surface.
    #[must_use]
    pub fn key_base_for(&self, envelope: &Envelope) -> Option<&str> {
        if envelope.event != Event::PreTool || envelope.command.is_empty() {
            return None;
        }
        // The column test BEFORE the command parse, so "a repository declaring
        // no such row pays nothing" is true rather than nearly true: without
        // this, every mediated call would re-parse its segments on the way to
        // discovering there was no keyed row to match. Cheap-when-irrelevant on
        // the hottest path in the binary (§4), and the same shape CLOUD-460
        // applied to the receipt lookup.
        if !self.shapes.iter().any(|rule| {
            rule.requires_key.is_some() && blocks(rule.severity(), self.fail_on_warning)
        }) {
            return None;
        }
        // THE ADMITTED ROWS, which is the whole of the fix caught in review on
        // #680: this took the first `requires_key` row the command matched,
        // modifiers unread, so a row excluded by its own modifier could hand the
        // commit range to a later admitted row. `matching_shape_rows` applies
        // `modifier_admits` itself now, so what selects here and what
        // `shape_rules` adjudicates cannot disagree about which rows fire.
        matching_shape_rows(self, envelope)
            .into_iter()
            .find(|rule| rule.requires_key.is_some())
            .and_then(|rule| rule.base.as_deref())
    }

    /// The row whose `tracked-artifacts` ceiling selects this call, if any
    /// (CLOUD-925).
    ///
    /// **The column test before anything else** (§4, CLOUD-460's shape): this is
    /// what the boundary asks before it spawns git, so a repository declaring no
    /// such ceiling opens nothing on the hottest path in the binary. Returns the
    /// row rather than a boolean because the caller needs its projection and its
    /// rewrite table to resolve the count at all.
    ///
    /// First match wins, matching every other row family here: declaration order
    /// decides, and a second ceiling over one tool is a config question rather
    /// than a precedence rule nobody can read.
    #[must_use]
    pub fn manifest_ceiling_for(&self, envelope: &Envelope) -> Option<&Rule> {
        if envelope.event != Event::PreTool || envelope.raw_tool.is_empty() {
            return None;
        }
        self.shapes.iter().find(|rule| {
            rule.kind == RuleKind::Shape
                && rule.counts == Some(CeilingUnit::TrackedArtifacts)
                && rule.max.is_some()
                && blocks(rule.severity(), self.fail_on_warning)
                && rule.selects_tool(&envelope.raw_tool)
                // The modifiers, for the COST rather than the verdict — and the
                // distinction is worth stating, because review on #680 read this
                // as a row that could deny a call its modifier excludes. It
                // cannot: `ceiling_rules` re-checks `modifier_admits` before it
                // refuses anything. What an unadmitted row here buys is a git
                // query resolving a count nothing will read, which is exactly
                // the cheap-when-irrelevant discipline this function's header
                // claims (§4, CLOUD-460). So: a real defect, in cost.
                && modifier_admits(rule, envelope)
        })
    }

    /// The subject a [`crate::rules::ReceiptKey::Named`] row files under, read
    /// from the row's own [`Rule::key_from`] projection (CLOUD-987).
    ///
    /// **The column test comes first**, so a repository declaring no such row
    /// reads no projection — CLOUD-460's narrowing, applied to the one lookup
    /// this adds to the receipt path.
    ///
    /// One value per call rather than one per row: a mediated call names one
    /// subject, so two rows keyed on the same projection cannot disagree. Rows
    /// keyed on DIFFERENT projections would, and that is why the first declaring
    /// row decides — declaration order, which is the same tiebreak the rest of
    /// this table uses, rather than a merge nobody can read.
    #[must_use]
    pub fn named_receipt_subject(&self, envelope: &Envelope) -> Option<String> {
        // FROM THE ADMITTED ROWS, not from every receipt row that declares a
        // projection. Scanning `self.shapes` directly took the FIRST such row
        // whatever the modifiers said, so with two `key_from` rows an unadmitted
        // row's projection could supply the subject for an admitted row's
        // receipt — the same one-selector-two-implementations defect
        // `modifier_admits` exists to prevent, reintroduced one function over.
        // Latent today (one such row is declared) and fixed rather than filed,
        // because latent is what it was last time too. Caught in review on #680.
        matching_receipt_rows(self, envelope)
            .into_iter()
            .find(|rule| rule.key_from.is_some())
            .and_then(|rule| {
                let read = rule.key_from?.read(envelope)?;
                // THE SHAPE NARROWS WHAT COUNTS AS A SUBJECT (CLOUD-312 row 2),
                // and a value it does not match resolves to ABSENT rather than to
                // a subject nothing filed under. `verdicts` takes `None` to
                // could-not-look and therefore to allow, which is the retiring
                // guard's own posture on a UUID it cannot resolve — see
                // [`Rule::key_shape`] for why denying there is strictly worse
                // than the bash.
                match rule.key_shape.as_deref() {
                    None => Some(read),
                    Some(shape) => regex::Regex::new(shape)
                        .ok()
                        .filter(|expression| expression.is_match(&read))
                        .map(|_| read),
                }
            })
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
        self.shapes.is_empty()
            // A repository whose only mediated-call policy is a registered
            // module has declared something, and this predicate short-circuits
            // `adjudicated` before any gate runs — so omitting `bundles` here
            // makes the policy gate unreachable rather than merely unused.
            // Caught by `a_module_denies_through_the_adjudication_chain`, which
            // is the case the unit tests over `policy::deny` cannot make.
            && self.bundles.is_empty()
            && (self.verbs.is_empty() || self.protected.is_empty())
    }

    /// The hatch that suppresses the row with this id, or [`BYPASS_ENV`] where
    /// the row declares none or is not a `[[rule]]` row at all (CLOUD-437).
    ///
    /// The fallback carries both of the cases a derived gate produces: the
    /// protected-mutation gate and the verb table refuse under ids that are
    /// declared constants rather than rows, so there is nothing to look up and
    /// the general hatch is the honest answer. That is also why this cannot
    /// return an `Option` and leave the caller to decide — a deny with no hatch
    /// clause is the bare "no" CLOUD-122 forbids, and an `Option` invites one.
    #[must_use]
    pub fn bypass_env_for(&self, rule: &str) -> &str {
        self.shapes
            .iter()
            .find(|row| row.id == rule)
            .and_then(|row| row.bypass_env.as_deref())
            .unwrap_or(BYPASS_ENV)
    }

    /// Whether [`BYPASS_ENV`] may suppress a refusal of this class (CLOUD-1357).
    ///
    /// **False for any class that declares an override route carrying a
    /// precondition**, which is the generalisation of the carve-out `path write
    /// refused` has had since CLOUD-1051. A class with such a route already has a
    /// way through that leaves a record — `batten override request` generates its
    /// questions from exactly this field, and `admit_mediated` honours the spent
    /// admission — so taking the password away is a repair rather than a wall.
    ///
    /// **True for a class with no such route, and that is the row's own bound.**
    /// Removing the hatch where nothing replaces it is the wall CLOUD-1357
    /// explicitly refuses; each such class is a migration row of its own, which is
    /// the tracking CLOUD-1051's scoping sentence owed and never got.
    ///
    /// A refusal carrying no class token at all keeps the hatch by construction: a
    /// consumer `[[rule]]`-composed refusal is "deliberately not a Batten class …
    /// no token an admission could bind", so it can declare no precondition and
    /// there is nothing for an admission to bind against.
    ///
    /// Reads the same field [`crate::admission::questions_for`] does, so the two
    /// cannot disagree about which classes have a route — a disagreement here
    /// would mean a class the hatch stopped opening and no admission could open
    /// either, which is the wall in its worst form.
    ///
    /// Pure: a registry lookup over the policy already in hand, which is what lets
    /// [`adjudicate`] stay free of I/O, environment and clock.
    #[must_use]
    pub fn honours_hatch(&self, class: Option<&str>) -> bool {
        let Some(class) = class else {
            return true;
        };
        !self.verdicts.iter().any(|entry| {
            entry.id == class
                && entry.routes.iter().any(|route| {
                    route.kind == crate::verdict::RouteKind::Override
                        && route.precondition.is_some()
                })
        })
    }

    /// This policy with every row whose declared hatch is in `set` removed
    /// (CLOUD-437).
    ///
    /// **A row is REMOVED, never short-circuited to allow, and that is the whole
    /// design.** Suppressing a refusal post-hoc would stop adjudication at the
    /// row that fired, so setting one row's hatch would silently switch off every
    /// row behind it — which is exactly the invisible blast radius a single
    /// global hatch has and this column exists to end. The bash guards this
    /// surface inherited were separate programs, so suppressing `memory-guard`
    /// left `ready-guard` live; removing the row is what reproduces that.
    ///
    /// Cheap when irrelevant (house-style §4): the caller skips this entirely
    /// when nothing is set, so the ordinary mediated call — every call, on every
    /// tool use — clones nothing.
    #[must_use]
    pub fn without_hatched(&self, set: &std::collections::BTreeSet<String>) -> Policy {
        Policy {
            shapes: self
                .shapes
                .iter()
                .filter(|row| {
                    row.bypass_env
                        .as_deref()
                        .is_none_or(|hatch| !set.contains(hatch))
                })
                .cloned()
                .collect(),
            harness: self.harness,
            fail_on_warning: self.fail_on_warning,
            verbs: self.verbs.clone(),
            protected: self.protected.clone(),
            advisory: self.advisory.clone(),
            refusal: self.refusal.clone(),
            protected_readers: self.protected_readers.clone(),
            redirects: self.redirects.clone(),
            facts: self.facts.clone(),
            mints: self.mints.clone(),
            recorders: self.recorders.clone(),
            patterns: self.patterns.clone(),
            programs: self.programs.clone(),
            bundles: self.bundles.clone(),
            verdicts: self.verdicts.clone(),
            // Spending a hatch narrows which ROWS apply; it never changes which
            // repository this policy speaks for.
            root: self.root.clone(),
        }
    }

    /// Every distinct hatch the loaded rows declare, for the boundary to resolve
    /// against the environment (CLOUD-437).
    ///
    /// The boundary cannot read these before config loads — the rows are not
    /// known yet — so [`BYPASS_ENV`] keeps its early position as the whole-call
    /// switch and these are read after. Returning the names rather than reading
    /// them here is what keeps [`adjudicate`] pure: this module never touches the
    /// environment, and the caller hands back which of these were set.
    #[must_use]
    pub fn declared_hatches(&self) -> std::collections::BTreeSet<&str> {
        self.shapes
            .iter()
            .filter_map(|row| row.bypass_env.as_deref())
            .collect()
    }
}

/// Adjudicate an envelope against the policy, then apply the waivers.
///
/// Pure: no I/O, no environment, no clock. `bypass` is the caller-resolved
/// escape hatch (the boundary reads [`BYPASS_ENV`]), and the policy arrives as a
/// value, so every verdict is a function of config plus argv and nothing else.
///
/// `waived` is the fourth thing that arrives already decided, and it is what
/// keeps that list true with an expiry in the design (CLOUD-610). A waiver
/// lapses on a **date**, and reading one here would put a clock inside the pure
/// core — so the boundary reads it once, projects the table through
/// [`crate::waiver::live`], and hands down membership. Nothing below this line
/// can ask what day it is, which is the contract intact rather than relocated.
///
/// Suppression is applied **after** the verdict and only to a [`Decision::Deny`],
/// at this single site rather than at each deny arm. Two consequences worth
/// stating because they are decisions:
///
/// * an [`Decision::Ask`] is **not** suppressible. A waiver says "this refusal is
///   accepted for now", and an escalation has not refused anything yet — it asked
///   a person. Turning that into an allow would answer on their behalf.
/// * a **derived** gate is unreachable in practice even though it carries a rule
///   id here. [`crate::waiver::validate`]'s companion smell `waiver-names-no-rule`
///   fails `config lint` for a waiver naming no `[[rule]]` row, and a derived gate
///   has none — so a waiver over one is refused at the config surface long before
///   it could reach this match.
#[must_use]
pub fn adjudicate(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Decision {
    match adjudicated(policy, envelope, facts) {
        Decision::Deny(refusal) => match facts.waived.get(refusal.rule()) {
            Some(expires) => Decision::Waived(crate::waiver::Suppressed {
                rule: refusal.rule().to_owned(),
                expires: expires.clone(),
            }),
            None => Decision::Deny(refusal),
        },
        decided => decided,
    }
}

/// The verdict before waivers — every gate this module owns, and nothing else.
///
/// Split from [`adjudicate`] so the suppression is one predicate over one value
/// instead of a check repeated at each of the deny arms below. A deny site that
/// forgot it would be a rule quietly unwaivable, which is exactly the asymmetry
/// CLOUD-293 found and CLOUD-606 decided against.
/// Adjudicate, then apply the hatch to the OUTCOME rather than to the chain.
///
/// # What CLOUD-1357 changed
///
/// `BATTEN_HOOK_BYPASS` used to suppress every refusal class but one. The
/// argument against that shape was already written at [`BYPASS_ENV`] and applied
/// to `path write refused` alone: *a refusal whose only way through is a string
/// somebody knows is a password rather than a gate*. Nothing in it is specific to
/// protected paths.
///
/// It is general now. A class declaring an override route with a precondition is
/// not suppressed, because it already has a way through that leaves a record —
/// `batten override request` generates its questions from that field and
/// `admit_mediated` honours the spent admission. A class with no such route keeps
/// the hatch, which is the bound CLOUD-1357 draws for itself: taking the password
/// away where nothing replaces it is a wall, and each such class is a migration
/// row of its own.
///
/// # The chain now RUNS on a bypassed call, and that retires an argument
///
/// The previous arm ran the two `protected_write` stages and nothing else,
/// explaining that adjudicating there "rather than by hoisting the two gates"
/// avoided reordering every refusal a caller sees. **That constraint is gone
/// rather than worked around**: filtering the OUTCOME moves no gate, so every
/// refusal is still raised by the row a reviewer would see quoted back, in the
/// order it always was. The hoisting objection was correct about hoisting and
/// does not reach this shape.
///
/// **The cost, stated rather than left for a profile to find.** A bypassed
/// adjudicable call now walks the whole chain instead of two stages. That is pure
/// CPU over an envelope already decoded and a policy already in hand —
/// [`adjudicate`] is contractually free of I/O, environment and clock, and the
/// config load this arm already paid since the protected gate stopped being
/// bypassable is unchanged. A call with nothing to adjudicate still returns
/// before any of it.
///
/// # `Ask` stays suppressible, deliberately
///
/// Only a `Deny` is held back. `admit_mediated` does not filter `Ask` — "an
/// escalation is a question put to a person, and a record the asker wrote
/// themselves is not an answer to it" — so an `Ask` has no admission route, and
/// refusing to suppress one would be the wall this row refuses, not the repair it
/// makes.
fn adjudicated(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Decision {
    let decision = adjudicated_gates(policy, envelope, facts);
    if !facts.bypass {
        return decision;
    }
    match decision {
        Decision::Deny(refusal) if !policy.honours_hatch(refusal.verdict()) => {
            Decision::Deny(refusal)
        }
        _ => Decision::Allow,
    }
}

// `match_same_arms` would collapse the eight event arms below into one
// `_ => Decision::Allow`. Refused for the reason `capabilities` and `encode_ask`
// refuse it, and here the refusal IS the feature: the arms agree on the ANSWER
// and disagree on the REASON, and CLOUD-777 exists because a fall-through and a
// stated no-op are byte-identical at runtime and opposite as contracts. Merging
// them would restore the silence — an eighth `Event` would land in a wildcard
// nobody wrote for it, which is what registering on every surface makes likely
// rather than hypothetical.
#[allow(clippy::match_same_arms)]
fn adjudicated_gates(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Decision {
    // Destructured once so the chain below reads as it always has. The bundle is
    // about how the fact set TRAVELS; each gate still names the single fact it
    // decides on, which is what keeps a reader able to see that `shape_rules`
    // cannot see a receipt.
    //
    // `bypass` is deliberately NOT among them (CLOUD-1357). No gate in this chain
    // reads the hatch any more: the chain decides what the policy says, and
    // [`adjudicated`] decides which of those refusals the hatch may suppress. A
    // gate that could still see it would be a second place the answer is made.
    let Facts { receipts, keys, .. } = *facts;
    // The end-of-turn gate (CLOUD-85), and it no longer DENIES (CLOUD-889).
    //
    // It returned `Decision::Deny` here, which is exit 2 — the channel that
    // forces the host to continue the turn. Two facts made that unbounded:
    // `adjudicate` never reads `Envelope::stop_active` (stated as deliberate on
    // that field), so unlike both shell hooks on this boundary it had no
    // recursion bound; and the predicate is `AtRisk::any()`, whose `unlanded`
    // term is true for a feature branch's ENTIRE LIFE. Turn ends, deny, forced
    // continuation, turn ends, deny — terminating only at the host's own
    // continuation cap. The refusal even named a remedy that cannot clear it:
    // committing and pushing does not make work landed.
    //
    // THREE PRIOR DECISIONS SAID SO AND THIS ARM WAS THE OUTLIER. CLOUD-97 and
    // CLOUD-219 each independently concluded "detection and self-clearing, never
    // a hard deny", because pausing or handing off mid-task is legitimate and
    // blocking a completion signal punishes correct behaviour. `completion.rs`
    // implements exactly that and states the standard: an advisory surface must
    // be *structurally* unable to block (house style §0.3), not merely observed
    // not to. This arm now meets it — there is no `Deny` for a caller to reach.
    //
    // The at-risk report is not lost: it is registered in the store, `worktree
    // status` prints it, and the advisory channel carries it.
    if envelope.event == Event::Stop {
        return Decision::Allow;
    }
    // Dispatch on the event FIRST, and answer for EVERY one of them by name
    // (CLOUD-43, then CLOUD-777). Before CLOUD-43 the field was decoded and never
    // read, so a `PostToolUse` payload carrying a banned command in
    // `tool_input.command` was adjudicated as though the call had not happened
    // yet — and denied. That refusal is meaningless after the fact and is not a
    // decision any host offers at that event.
    //
    // CLOUD-43's fix was `if event != PreTool { Allow }`, which is right at
    // runtime and wrong as a contract. Batten is now registered on every surface
    // a host emits, so an event nobody considered arrives at this function rather
    // than never being delivered — and a fall-through absorbs it silently, with
    // the same bytes as a decision somebody made. **A stated no-op and a
    // fall-through are byte-identical at runtime and opposite as contracts.**
    //
    // So the match below is exhaustive with no wildcard: an eighth `Event` fails
    // to compile here until somebody says what it decides. Each arm's comment is
    // the answer, not decoration — that is the whole of what this replaced.
    match envelope.event {
        // The one adjudicated event. Everything past this point is its gate
        // chain.
        Event::PreTool => {}
        // No decision, by design. The post-tool moment has no deny channel on any
        // surveyed host — the call already happened — and its reader is the drain
        // (CLOUD-79). Reading a fact off the result is CLOUD-776's, and it lands
        // as a `Decision` here only once there is something to decide.
        Event::PostTool | Event::PostToolBatch => return Decision::Allow,
        // Handled ABOVE, before the bypass check, because what is judged there is
        // not a call but whether the turn's work is finished (CLOUD-85). Stated
        // rather than folded into the no-ops so this arm cannot silently become
        // the answer if that early return is ever moved.
        Event::Stop => return Decision::Allow,
        // No decision, by design, and not a gap waiting on CLOUD-461: neither
        // moment carries `Decision` semantics on ANY host. There is nothing to
        // allow or deny at the start of a session or a config reload — what a
        // policy might want there is advisory, which is a channel rather than a
        // verdict.
        Event::SessionStart | Event::ConfigChange => return Decision::Allow,
        // Claude Code's completion signal, and the one event whose exit 2
        // prevents completion. Batten does not use it yet: the stop gate is the
        // reconciliation point (house-style §10) and `Capabilities::degrade` maps
        // this to the Stop family elsewhere, so deciding here as well would give
        // one question two answers.
        Event::TaskCompleted => return Decision::Allow,
        // NOT a stated no-op, and the distinction is the point of the arm
        // (CLOUD-777). Measured 2026-08-21 on this repository's own wiring: the
        // two bash guards registered here reach `exit 2` on five paths between
        // them and emit no advisory shape at all, so Claude Code honours a deny
        // at this moment and the channel is real. What is missing is a rule kind
        // that selects for it — every kind in `rules.rs` keys on a mediated CALL,
        // and a submitted prompt is not one — so the honest answer today is
        // allow, with the gap named rather than dressed as a design decision.
        // CLOUD-312 owns the retirement of the two guards; when a kind can key on
        // this event, this arm is where it dispatches.
        Event::UserPromptSubmit => return Decision::Allow,
        // The host said something this build cannot normalize. Allow, loudly
        // elsewhere: an unrecognized event is a fact about the host, never a
        // reason to refuse a call (CLOUD-45), and guessing which moment it stands
        // for is how a gate fires at one nobody named.
        Event::Unrecognized => return Decision::Allow,
    }
    if policy.is_empty() {
        return Decision::Allow;
    }
    // The write gate, before the command gate and not inside it: a write tool
    // carries no command, so every path below this point used to return Allow
    // for it. That is why the `Write|Edit|MultiEdit|NotebookEdit` matcher was
    // adjudicated by nothing at all — the rows existed, the payload decoded,
    // and `command.is_empty()` sent it home (CLOUD-312).
    //
    // Dispatched on the NEUTRAL `Operation`, not on the host's tool name
    // (CLOUD-779). The predicate used to be `writes × verbs::classify(raw_tool) ×
    // protected`, which asked a consumer's `[[verb]]` table — Claude Code's
    // vocabulary — to recognise every host's spelling of a write. Measured on
    // `main` 2026-08-20: Cursor's `write`/`edit`, Gemini's `WriteFile` and
    // Copilot's `StrReplaceEditor` all reached a protected path and were allowed
    // silently, because a rule that matches nothing is indistinguishable from a
    // rule with nothing to match.
    //
    // The `[[verb]]` row survives as MESSAGE COMPOSITION — see `Target::redirect`
    // — so the consumer's own remedy text still travels wherever it is declared,
    // which is what CLOUD-312's differential suite asserts, and a spelling the
    // consumer never declared now denies with the path-class remedy instead of
    // not denying at all.
    match protected_write(policy, envelope, WriteStage::ToolNamed) {
        decided @ Decision::Deny(_) => return decided,
        // `protected_write` renders exactly one verdict; the others are stated as
        // arms rather than wildcarded so a fifth `Decision` variant has to come
        // back here and be decided rather than silently falling through.
        Decision::Allow | Decision::Ask(_) | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    // The content-keyed gate, AFTER the protected-path one and never instead of
    // it (CLOUD-758). The two ask different questions — which file, and what
    // would be in it — and CLOUD-736 is the case that needs both: a path gate
    // alone permits an unreviewed creation, and a content gate alone permits a
    // reviewed file being replaced wholesale.
    match content_rules(policy, envelope, facts.prospective) {
        decided @ Decision::Deny(_) => return decided,
        Decision::Allow | Decision::Ask(_) | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    // The tool-keyed gate (CLOUD-924), and its placement is the whole reason it
    // works: ABOVE the `command.is_empty()` early return, which every structured
    // call trips. An MCP call, a `Read` and a `Task` spawn carry no command line,
    // so a row keyed on the tool they name is unreachable from anywhere below.
    //
    // After the protected-path and content gates, keeping this chain's standing
    // precedence — a ban a reviewer wrote by hand outranks a derived one — and
    // before the receipt gates, on the same ban-outranks-precondition rule the
    // command paths follow: there is no point telling the author of a refused
    // call which receipt to earn.
    match tool_rules(policy, envelope) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    // The read-side redirect (CLOUD-1258), beside the tool gate for the same
    // reason: it rides a resolved tool fact and carries no command line. Below
    // the write gate on the standing precedence — a call that is refused as a
    // WRITE is not also told which reader to use — and above the ceilings,
    // because naming the instrument is more useful than sizing the wrong one.
    match redirected_read(policy, envelope) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    // The per-call ceiling (CLOUD-925), beside the tool gate because it rides the
    // same selection and the same reason for being above the command early
    // return: a `Task` spawn carries no command line.
    //
    // A ban outranks a ceiling: a call already refused outright is not told its
    // prompt is too big as well.
    // The manifest ceiling first, because its count is already resolved: the
    // boundary either counted or could not, and deciding from a fact in hand
    // before measuring anything keeps the order "cheapest decidable first".
    match manifest_ceiling(policy, envelope, facts.manifest) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    let mut measured = 0;
    let ceiling = ceiling_rules(policy, envelope, &mut measured);
    // Published to the process counter here rather than inside the gate, so the
    // gate stays a pure function of its inputs and a test can read the count it
    // produced without touching a global at all.
    if measured > 0 {
        CEILINGS_MEASURED.fetch_add(measured, Ordering::Relaxed);
    }
    match ceiling {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    // The write-triggered receipt gate (CLOUD-444), reached whether or not this
    // call also carries a command — a write tool carries none, and the early
    // return below is what made every write unjudgeable by anything but the
    // protected gate above.
    //
    // AFTER the protected gate and before everything else, which is the same
    // precedence the command paths keep: a ban outranks an unmet precondition,
    // because there is no point telling the author of a refused call which
    // receipt to go and earn.
    // The tool-keyed receipt gate, beside the two gates above because it rides
    // the same selector and needs the same placement above the command early
    // return. After them, on the standing rule that a ban outranks an unmet
    // precondition. See [`tool_receipt_rules`] for why this is its own narrow
    // gate rather than a wider condition on the write-triggered one below.
    match tool_receipt_rules(policy, envelope, receipts) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    if envelope.writes.is_some() {
        match receipt_rules(policy, envelope, receipts) {
            decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
            // `Waived` and `Preapproved` are grouped with `Allow` throughout this
            // chain, and both are invariants rather than cases: only [`adjudicate`]
            // mints a `Waived`, and only the BOUNDARY mints a `Preapproved` — from
            // this function's answer in each case — so no gate below can return
            // either. Stated as arms rather than a wildcard so a sixth variant
            // still fails to compile here, and grouped with `Allow` because that is
            // what a suppression and a grant both mean if the invariant breaks.
            //
            // The `Preapproved` half is the load-bearing one: a gate that could
            // return it would be a rule GRANTING permission, and the whole reason
            // that variant is minted outside this function is that no rule may.
            Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
        }
    }
    // THE HAND-WRITTEN COMMAND ROWS, and they sit ABOVE the module gate because
    // that is the precedence this chain has stated all along and did not keep.
    // The comment below the module gate has said since CLOUD-312 that "a row a
    // reviewer wrote by hand is the one they should see quoted back, and its
    // reason is more specific than a module's" — and `shape_rules` ran AFTER
    // `policy_rules`, so for every call both select, the module won.
    //
    // Measured, and the measurement is why this is a defect rather than a
    // preference. `cargo test -p batten` selects `no-bare-cargo`, whose reason
    // names both sanctioned routes (`mise run <task>` and `mise exec -- cargo`),
    // AND `task-substitution`, whose subject is whichever declared task happens
    // to lead with `cargo` — 13 of them do, so the refusal named
    // `attribution-identity`, a task that has nothing to do with running tests.
    // The reader was handed a remedy that does not do the job, which is exactly
    // the class CLOUD-1050 made unrepresentable for a verdict's own prose and
    // this reintroduced through the gate ordering.
    //
    // CI NEVER SAW IT, and that is the second half of why it stood. A module
    // reading `input.facts.tasks` is could-not-look until a session-start receipt
    // exists, so `task-substitution` is live in an agent session and inert on a
    // runner — every interaction it has with a hand-written row is invisible to
    // the thing that gates merges.
    //
    // Guarded on a non-empty command, which is what keeps the module gate's own
    // placement intact: a write tool carries no command line, so hoisting
    // `shape_rules` unguarded would move nothing and hoisting the module gate
    // with it would make modules silently inert on exactly the surface CLOUD-312
    // found unjudged.
    //
    // An `Ask` short-circuits exactly as a `Deny` does: the row matched, and what
    // it asked for is the answer. Falling through would let a second row overrule
    // an escalation the first one wanted, which declaration order decides.
    if !envelope.command.is_empty() {
        match shape_rules(policy, envelope, &envelope.command, keys) {
            decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
            Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
        }
    }
    // The policy gate sits here, before the command early-return, deliberately:
    // a write tool carries no command, and every gate below this point is about
    // a command line. A module decides over the call's FACTS, so it has an
    // answer for a write as much as for a shell command, and putting it below
    // would make it silently inert on exactly the surface CLOUD-312 found
    // unjudged.
    match policy_rules(policy, envelope, facts) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {}
    }
    if envelope.command.is_empty() {
        return Decision::Allow;
    }
    // The pipeline gate before the receipt one, and the ordering is the same
    // ban-outranks-precondition rule the rest of this chain follows: a call whose
    // verdict is thrown away is refused outright, so telling its author which
    // receipt to earn first would be advice about a call that is not going to run
    // (CLOUD-443). Then the derived protected-path gate last, for the reason the
    // hoisted rows above are first: a row a reviewer wrote by hand should be the
    // one they see quoted back, and its reason is more specific than the generic
    // path-class message.
    match pipeline_rules(policy, envelope) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => decided,
        Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {
            match receipt_rules(policy, envelope, receipts) {
                decided @ (Decision::Deny(_) | Decision::Ask(_)) => decided,
                Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {
                    protected_write(policy, envelope, WriteStage::CommandParsed)
                }
            }
        }
    }
}

/// The text a host reads for one refusal — the deny's whole projection.
///
/// [`Refusal::render`] is the shared shape; this adds the one thing that is a
/// fact about *mediation* rather than about the refusal, and so has no place in
/// the payload: the escape hatch. `check`'s refusal of a rule it cannot honestly
/// run carries the same [`Refusal`] and no hatch, which is correct — there is
/// nothing to bypass in a read-only run.
///
/// `hatch` is the name **this** refusal's row declared, or [`BYPASS_ENV`] where
/// it declared none (CLOUD-437). Passed in rather than read off the [`Refusal`]
/// deliberately: the hatch is a fact about mediation and the refusal is shared
/// with `check`, so putting it on the payload would give a read-only finding a
/// field that can only ever be meaningless there. [`Policy::bypass_env_for`] is
/// the one place the row is looked up, so the string a deny prints and the
/// variable the boundary reads stay one definition — the property this module's
/// single-constant comment has always claimed and could not keep once the hatch
/// stopped being single.
/// # A class the hatch cannot open must not advertise it
///
/// `path write refused` is adjudicated under the hatch, so printing "Bypass
/// with `BATTEN_HOOK_BYPASS`=1" on its refusal would name a remedy that does
/// nothing — the defect class `crate::verdict`'s own header exists to kill ("a
/// refusal could name no remedy, name a task that does not exist"), reintroduced
/// by the commit that closed the hatch.
///
/// This is not a list of exempt classes and must not become one. The predicate is
/// the same fact the boundary decides on: a class the hatch does not reach is one
/// whose way through is its declared `override` route, and `Refusal::render`
/// already carries that route as the fix. So the hatch sentence is simply
/// omitted, and what remains is the remedy that works.
/// # CLOUD-1286: a declared refusal emits its line and stops
///
/// Everything below this paragraph applies to a refusal with NO declared class.
/// A declared one emits `<token> <pointer…>` and nothing else — no `Refused by`
/// prefix, no gloss, no `Fix:` clause, and **no hatch sentence**, which is
/// CLOUD-437's defect finally removed rather than narrowed: it was identical on
/// every deny, so it was pure per-firing cost carrying no per-firing
/// information. The way through a class is its declared routes, and
/// `batten policy explain <token>` prints all of them; the hatch is a fact about
/// mediation that `crate::hook`'s own module header states once, where it costs
/// nothing to have already read.
///
/// The `path write refused` arm below therefore also goes: its whole purpose was
/// to surface an override route the `Fix:` clause could not reach, and `explain`
/// now reaches every route including that one. Composing an
/// `override request` command line per firing was ~40 tokens spent to save one
/// lookup.
/// # CLOUD-1386: the ROUTE comes back, because it was never the constant part
///
/// The paragraph above is right that a sentence identical on every deny is pure
/// per-firing cost, and the hatch stays gone for exactly that reason. It was
/// wrong to take the class's first `command` route with it. That route is not
/// constant — it differs per class, it is the shortest thing that turns a refusal
/// into the next action, and `Refusal::from_class` has already resolved it by the
/// time this runs. Dropping it made every declared refusal a bare noun phrase.
///
/// MEASURED, and the cost was not a lookup. A session pushed with a bare
/// `--force-with-lease`, read back `branch write unsafe leased-push`, and had no
/// way to tell that the class refuses one SPELLING and that
/// `--force-with-lease=<ref>:<sha>` is allowed — which the class says outright,
/// one `explain` away. It concluded instead that the landing lease gates pushing,
/// reported that to its reviewer as a design defect, and argued for changing a
/// rule that was working correctly. The remedy existed, was declared, and was one
/// clause short of arriving.
///
/// # ONCE PER SESSION, WHICH IS THE SHAPE BOTH EARLIER VERSIONS MISSED
///
/// The cost CLOUD-1286 measured is a REPEAT cost: prose that arrives on every
/// firing of a class a reader has already read. The value is a FIRST-SIGHTING
/// value: a reader who has never seen this class cannot act on a bare token. Both
/// are true, and neither "always" nor "never" can hold both.
///
/// So the class travels the first time it fires in a session and never again.
/// `first_sighting` is the caller's answer — the boundary consults a
/// session-scoped record and marks it, exactly as `expire_wiring_record` treats
/// `SessionStart` as the session identity. This function stays pure and stays the
/// one place the two renderings are chosen between.
///
/// **A fresh session and a compacted one are the same reader.** Batten cannot
/// observe compaction; what it can observe is the session-start event, and the
/// record is cleared there. So the guarantee is per session, which is the
/// implementable approximation of "the first time this reader sees it" — and it
/// errs toward saying it again rather than assuming it was retained.
///
/// # EVERY route, because "the first one" is a choice nobody made
///
/// The first-sighting arm renders all of the class's `command` routes rather than
/// the one `Fix:` carries. `Fix:` takes the first because it renders on every
/// firing and a list there is the repeat cost above. Once per session that budget
/// is not in force, and picking by declaration order is not a summary — it is one
/// alternative selected arbitrarily. `leased-push` is the measurement: it declares
/// the rebase first and `--force-with-lease=<ref>:<sha>` second, and the second is
/// the one that answers the reader who just hit it. Rendering the first alone is
/// what produced the defect report this row exists for.
///
/// The caller's own narrower alternative still leads when it has one, because a
/// consumer's `redirect` for a protected path knows something the class does not.
///
/// # AND THE CEILING GOVERNS THIS ARM TOO, WHICH IS THE HALF THAT SHIPPED WRONG
///
/// The once-per-session change re-pointed `refusal_ceiling` at the SECOND firing,
/// on the sound argument that `[refusal] max_tokens` was always about repeat cost.
/// The consequence was not sound: it left the FIRST sighting bounded by nothing at
/// all, in the same commit that made the first sighting the long one.
///
/// Measured, and by a case rather than by reading. A consumer `[[rule]]` row's
/// `reason` reaches here as the narrower [`Fix::Run`], and a `reason` is prose —
/// `an-update-owes-a-recent-read`'s is ~700 characters and ENDS by naming a
/// different rule. So the emitted line grew a second row's id, which is exactly
/// what CLOUD-1286 removed it to prevent, and
/// `board_receipts::an_update_is_not_row_ones_business` is what said so.
///
/// So the declared ceiling decides both arms and stays the ONE authority over an
/// emitted mediated line. Over budget, the routes clause is dropped whole rather
/// than truncated: half a command is not a way out, and a reader who can see the
/// class token can still run `batten policy explain`. Under it, nothing changes.
///
/// **A consumer that declares no ceiling gets no bound**, which is the same answer
/// every other budget gives an undeclared row — the ceiling is the consumer's
/// statement about their own line, and inventing one here would be this crate
/// deciding a consumer fact.
#[must_use]
pub fn deny_text(
    refusal: &Refusal,
    hatch: &str,
    first_sighting: bool,
    ceiling: Option<&crate::refusal::Ceiling>,
) -> String {
    if refusal.verdict().is_some() {
        if !first_sighting {
            return refusal.line();
        }
        let mut routes: Vec<&str> = Vec::new();
        for route in refusal
            .fix()
            .declared_alternative()
            .into_iter()
            .chain(refusal.routes().iter().map(String::as_str))
        {
            // The narrower fix is very often the class's own first route, and a
            // reader met with the same clause twice learns that the renderer
            // cannot count.
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
        if routes.is_empty() {
            return refusal.line();
        }
        let carried = format!("{} — {}", refusal.line(), routes.join("; "));
        return if ceiling.is_some_and(|declared| declared.over(&carried)) {
            refusal.line()
        } else {
            carried
        };
    }
    format!("{} Bypass with {hatch}=1.", refusal.render())
}

/// The first shape row that matches the mediated command, in declaration order.
///
/// Declaration order is the tie-break rather than "most specific wins": a
/// reviewer reads the table top to bottom, and any cleverer precedence would be
/// a rule about rules that the config does not state.
/// The receipt verdicts a mediated call is judged against.
///
/// Three-valued on [`crate::facts::Look`], which is the contract `facts.rs`
/// states and this alias now practises rather than restates (CLOUD-787). The
/// two answers that are not a verdict map both **allow** — the fail-open posture
/// every retiring guard has — and they are still two answers, because the
/// previous spelling had them as one:
///
/// * [`Look::CouldNotLook`](crate::facts::Look::CouldNotLook) — the question
///   could not be asked: no checkout, an `origin/main` that does not resolve, or
///   a detached HEAD where a branch-keyed row needs a branch.
/// * [`Look::IsNot`](crate::facts::Look::IsNot) — the boundary looked and there
///   is **nothing judgeable** here: no required check selected this call, or the
///   call writes a path policy does not judge (git-ignored, outside the
///   repository, inside `.git`), which is [`crate::receipt::judgeable`]'s answer
///   and CLOUD-444's exclusion set.
///
/// Both were `None` until CLOUD-787, so a reader reaching for `Option` got two
/// values where the contract has three, and the next call site written would
/// have collapsed "looked and found nothing" into "could not look". They allow
/// alike today and nothing here asks them to keep doing so: the point is that a
/// predicate can now tell them apart before deciding.
///
/// An [`Look::Is`](crate::facts::Look::Is) map missing a name is treated as
/// [`Validity::Missing`], so a boundary that resolved fewer facts than the
/// policy needs fails closed rather than silently allowing.
pub type ReceiptFacts = crate::facts::Look<std::collections::BTreeMap<String, Validity>>;

/// The checkout evidence a `requires_key` shape row is judged against
/// (CLOUD-446): the branch name, and the commit messages on `base..HEAD`.
///
/// [`Look::CouldNotLook`](crate::facts::Look::CouldNotLook) allows, exactly as
/// it does for [`ReceiptFacts`] — outside a checkout, on a detached HEAD, in a
/// shallow clone, or against a `base` git cannot resolve.
/// [`Look::IsNot`](crate::facts::Look::IsNot) is the other non-answer and is a
/// different one: no `requires_key` row selected this command, so the boundary
/// looked and found no key question to ask. Resolved at the boundary because
/// [`adjudicate`] is
/// contractually pure, and resolved only when a `requires_key` row has already
/// selected this command ([`Policy::key_base_for`]), so a repository declaring no
/// such row pays nothing on the hottest path in the binary.
///
/// Deliberately not a named struct with a `branch` and a `messages` field: every
/// reader asks the same question of all of it — does the expression match
/// anywhere — and a field a caller could *print* is one an unreviewed edit turns
/// into a leaked commit message (non-negotiable rule 4).
pub type KeyFacts = crate::facts::Look<Vec<String>>;

/// What the AGENT reported for each agent-sourced check (CLOUD-776, CLOUD-834).
///
/// `None` here is could-not-look. It is deliberately still an `Option` rather
/// than a [`crate::facts::Look`], and CLOUD-787 left it that way on purpose:
/// this fact has no `IsNot` producer — [`crate::lib`]'s `agent_records` answers
/// `None` only when no required check is agent-sourced — so the third arm would
/// be dead, and a three-valued type whose third value cannot occur misleads in
/// the other direction. A check absent from the map is one the boundary was not
/// asked about. Kept beside the
/// receipt verdicts rather than folded into them because they answer different
/// questions: a `Validity` says whether the check is satisfied, and this says
/// what the agent actually ran and what it found. Collapsing the two would give
/// [`crate::facts::Fact::AgentSourced`] no spelling of its own in the policy
/// input, which is the "exactly one key" property CLOUD-834 asserts.
pub type AgentFacts = Option<std::collections::BTreeMap<String, crate::facts::Sourced>>;

/// What a write would put on disk, resolved before it happens (CLOUD-758).
///
/// [`crate::facts::Look::CouldNotLook`] is the answer for a tool whose shape
/// carries no content — a shell command, an MCP call — and it is emphatically
/// **not** `Is(String::new())`, which means *this write would land an empty
/// file*. Collapsing the two is the failure the three-valued contract exists to
/// prevent: a content predicate would then fire on every `Bash` call as though
/// it had inspected something, failing open in the one direction that looks like
/// it looked.
///
/// **Never emitted**, for the reason [`Envelope::input`] is never emitted: this
/// is whatever the agent was about to write, which may be a secret, a customer
/// path, or the contents of a protected file. A rule may DECIDE over it; what is
/// reported is `path:line` and a rule id (non-negotiable rule 4).
pub type ProspectiveFacts = crate::facts::Look<String>;

/// Compute what `envelope`'s write would land, reading the file only when the
/// tool's shape requires it (CLOUD-758).
///
/// The two arms are the two acquisition paths [`crate::facts::PROSPECTIVE`]
/// meets over:
///
/// * a whole-file write hands over the content itself — genuinely free, already
///   deserialized by the time this is called.
/// * an edit hands over the old and new spans and nothing around them, so the
///   surrounding bytes come off disk. One bounded read of the one file the call
///   already names, which is what makes the fact `read` rather than `free`.
///
/// Dispatched on the NEUTRAL [`Operation`], never on a host's tool name
/// (CLOUD-779): every host spells its writes differently and
/// [`Harness::operation_of`] has already answered.
///
/// A write whose file cannot be read is [`crate::facts::Look::CouldNotLook`]
/// rather than an error — a gate that cannot look must never become a gate that
/// blocks everything.
///
/// Four payload shapes are recognised, which is every write shape the surveyed
/// hosts spell: whole-file content, a single old/new span, a BATCH of such spans
/// applied in order, and a notebook cell's replacement source. A batch shape left
/// unread would be the widest hole a content-keyed gate can have — the same edit,
/// spelled the other way, inspected by nothing.
#[must_use]
pub fn prospective_facts(root: &std::path::Path, envelope: &Envelope) -> ProspectiveFacts {
    use crate::facts::Look;

    if envelope.operation != Operation::Write {
        return Look::CouldNotLook;
    }
    // A whole-file write and a notebook cell's replacement source are both the
    // landed text itself, already deserialized — the free arm. A notebook's
    // file bytes are JSON around that source; the source is what a content row
    // is asking about, and the JSON frame is not content anyone wrote.
    for key in ["/content", "/new_source"] {
        if let Some(content) = envelope.input.pointer(key).and_then(Value::as_str) {
            return Look::Is(content.to_owned());
        }
    }
    let Some(target) = envelope.writes.as_deref() else {
        return Look::CouldNotLook;
    };
    let target = root.join(target);
    // The ceiling is the honest reading of "bounded" in
    // [`crate::facts::PROSPECTIVE`]: bounded by the file COUNT is not bounded by
    // the byte count, and one edit against a large generated or vendored file
    // would pay the whole allocation plus a full regex scan inside CLOUD-689's
    // 100ms budget. Past it the answer is could-not-look — a gate that declines
    // to look is better than one that blows the budget it is measured against.
    if std::fs::metadata(&target).is_ok_and(|meta| meta.len() > MAX_PROSPECTIVE_BYTES) {
        return Look::CouldNotLook;
    }
    let Ok(current) = std::fs::read_to_string(&target) else {
        return Look::CouldNotLook;
    };
    let Some(spans) = edit_spans(&envelope.input) else {
        return Look::CouldNotLook;
    };
    let mut landed = current;
    for (old, new, replace_all) in spans {
        // `replacen(.., 1)` rather than `replace`, and the default matters: the
        // surveyed hosts replace the FIRST occurrence unless the call says
        // otherwise, so modelling it as replace-all would decide over content
        // the call would not actually produce.
        landed = if replace_all {
            landed.replace(&old, &new)
        } else {
            landed.replacen(&old, &new, 1)
        };
    }
    Look::Is(landed)
}

/// The largest file the prospective read will pull into memory.
///
/// Not a policy number: the bound the `read` classification claims, made true by
/// construction rather than by the size of the files anyone happens to edit.
const MAX_PROSPECTIVE_BYTES: u64 = 1 << 20;

/// The old/new spans an edit-shaped payload carries, in application order.
///
/// One span for the single-edit shape, N for the batch shape. `None` is a
/// payload carrying neither, which the caller answers as could-not-look: a write
/// shape nothing here recognises must never read as inspected-and-clean.
fn edit_spans(input: &Value) -> Option<Vec<(String, String, bool)>> {
    let replace_all = |value: &Value| {
        value
            .pointer("/replace_all")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    let span = |value: &Value| {
        let old = value.pointer("/old_string").and_then(Value::as_str)?;
        let new = value.pointer("/new_string").and_then(Value::as_str)?;
        Some((old.to_owned(), new.to_owned(), replace_all(value)))
    };
    if let Some(one) = span(input) {
        return Some(vec![one]);
    }
    let edits = input.pointer("/edits").and_then(Value::as_array)?;
    // Every entry or none. A batch with one unreadable span would otherwise be
    // adjudicated as though the rest were the whole write, which is the
    // partial-look failure the three-valued contract refuses one level up.
    edits.iter().map(span).collect()
}

/// How many tracked artifacts a measured projection named, or `None` for
/// could-not-look (CLOUD-925).
///
/// An alias rather than a bare `Option<usize>` at the call sites, so "could not
/// count" is a named state a reader sees rather than an absence they infer — the
/// same reason [`ReceiptFacts`] and [`ProspectiveFacts`] are named.
pub type ManifestFacts = Option<usize>;

/// The resolved fact set one mediated call is adjudicated against (CLOUD-834).
///
/// **A struct rather than six parameters, and the compiler asked for it.** The
/// facts arrived one at a time — `receipts` with CLOUD-202, `keys` with
/// CLOUD-446, `stop` with CLOUD-85, `waived` with CLOUD-610 — each a positional
/// argument, and projecting the last two took the signature past
/// `clippy::too_many_arguments`. Collecting them is the fix the lint is for: the
/// thing being passed is *the fact set*, which is a noun `facts.rs` already
/// names, and a caller can no longer transpose two `&None`s of the same type.
///
/// **Resolved at the boundary, held by value.** Every field is a fact the
/// boundary already looked up before [`adjudicate`] was called — which is what
/// keeps that function contractually pure, and why projecting the set into the
/// policy input costs no resolution. A fact that was not resolved says so in its
/// own type — [`crate::facts::Look::CouldNotLook`] where the field carries one,
/// `Option::None` where it does not — and never "resolved to nothing".
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Facts<'a> {
    /// The caller-resolved [`BYPASS_ENV`] hatch.
    pub bypass: bool,
    /// The receipt verdicts this call is judged against.
    pub receipts: &'a ReceiptFacts,
    /// The tracker-key evidence a `requires_key` row is judged against.
    pub keys: &'a KeyFacts,
    /// The end-of-turn facts, default on every event but `Stop`.
    pub stop: &'a crate::stop::StopFacts,
    /// The rules a live waiver suppresses today, with the expiry each claims.
    pub waived: &'a crate::waiver::Live,
    /// What the agent reported for each agent-sourced check.
    pub sourced: &'a AgentFacts,
    /// What this call's write would land, before it happens (CLOUD-758).
    pub prospective: &'a ProspectiveFacts,
    /// How many tracked artifacts this call's measured projection names, for a
    /// [`CeilingUnit::TrackedArtifacts`] ceiling (CLOUD-925).
    ///
    /// **Resolved at the boundary, because the tracked set is a property of a
    /// checkout and not of the envelope** — `adjudicate` is contractually pure,
    /// so it cannot ask git anything. `None` is could-not-look and **allows**: a
    /// ceiling that could not count must not refuse, which is the same direction
    /// every other fact here fails in.
    ///
    /// Resolved only when a row actually declared such a ceiling AND selected
    /// this call, so a repository declaring none opens nothing (CLOUD-460's
    /// narrowing).
    pub manifest: ManifestFacts,
    /// The programs the project's pin puts on `PATH` (CLOUD-1028).
    ///
    /// A file read here and nothing more: asking the pin itself is
    /// [`crate::facts::Cost::Effect`], which this surface may not spend, so what
    /// the boundary resolves is the record written where an effect is
    /// admissible. Could-not-look — no pin, no record, a record under another
    /// key — allows, which for this fact is the only safe direction: it names
    /// every program in the project, so refusing on a failure to look would
    /// refuse the project.
    pub pinned: &'a crate::pinned::PinnedFacts,
    /// The task runner's own argv, from a receipt minted at session start
    /// (CLOUD-856).
    ///
    /// A file read here and nothing more, which is the entire point: the manifest
    /// parse that would be unbounded on this path happened once, elsewhere, and
    /// the record's key is recomputed from the manifest as it stands so a stale
    /// one does not answer. Could-not-look — no record, a record under another
    /// key, a schema this build does not read — allows, and must: a guard
    /// comparing a call against an empty task table would refuse every command
    /// the project runs.
    pub tasks: &'a crate::taskset::TaskFacts,
    /// What a declared extractor counted in this session's transcript
    /// (CLOUD-1172).
    ///
    /// Counts and nothing else — the extractor set is closed and every member
    /// resolves to an integer over typed events, so the richest source of secrets
    /// the engine can be pointed at reaches a module as numbers. Could-not-look
    /// is the COMMON case (CLOUD-388) and allows: a session with no transcript
    /// has not established that nothing was stranded.
    pub extracted: &'a crate::facts::Look<std::collections::BTreeMap<String, usize>>,
}

impl<'a> Facts<'a> {
    /// The fact set a caller that resolved nothing hands in.
    ///
    /// Every field its could-not-look value, which is what a surface with no
    /// question to ask should pass — never a fabricated empty answer.
    #[must_use]
    pub const fn none(
        stop: &'a crate::stop::StopFacts,
        waived: &'a crate::waiver::Live,
    ) -> Facts<'a> {
        Facts {
            bypass: false,
            receipts: &crate::facts::Look::CouldNotLook,
            keys: &crate::facts::Look::CouldNotLook,
            stop,
            waived,
            sourced: &None,
            // Could-not-look, never "an empty write". A `Facts::none` caller has
            // resolved nothing, which is a different claim from having looked
            // and found no content.
            prospective: &crate::facts::Look::CouldNotLook,
            // Could-not-look, never zero: a caller that resolved nothing has not
            // established that the projection names no artifact.
            manifest: None,
            // Could-not-look, never an empty set: "the pin provides nothing" is
            // a claim about a project, and a caller that resolved nothing is not
            // making it.
            pinned: &crate::facts::Look::CouldNotLook,
            // Could-not-look, never an empty table: "this project defines no
            // tasks" is a claim about a manifest, and a caller that resolved
            // nothing is not making it.
            tasks: &crate::facts::Look::CouldNotLook,
            // Could-not-look, never an empty count set: a caller that resolved
            // nothing has not established that this session did nothing.
            extracted: &crate::facts::Look::CouldNotLook,
        }
    }
}

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
/// Whether a row's polarity modifiers admit this call (CLOUD-987).
///
/// **One implementation, three readers**, and that is the mechanism rather than
/// tidiness. `tool_rules` decides with it, `tool_receipt_rules` decides with it,
/// and [`matching_receipt_rows`] selects with it — so what the boundary resolves
/// receipts for and what the gate then judges cannot disagree about which rows
/// fire. `key_base_for`'s header states the same obligation for `requires_key`,
/// and a second copy of this test is exactly the drift it warns about.
///
/// **ALL THREE of `matching_receipt_rows`' loops, not just the tool-keyed one.**
/// The first version applied it there alone, and the sentence above was then
/// false of the other two: a write- or command-triggered receipt row carrying a
/// modifier still reached `required_checks_for`, so the boundary resolved — and
/// paid git work for — an obligation the row does not admit, and the gate below
/// then judged a row the selection should have dropped. Caught in review on #680.
/// The invariant is per-loop, so it has to be written per-loop.
///
/// A row carrying neither modifier is admitted, which is every row that predates
/// CLOUD-987 — the columns are additive and absent means "this row is about the
/// selection alone".
fn modifier_admits(rule: &Rule, envelope: &Envelope) -> bool {
    if let Some(field) = rule.when_absent
        && field.read(envelope).is_some()
    {
        return false;
    }
    if let Some(field) = rule.when_present {
        let Some(read) = field.read(envelope) else {
            return false;
        };
        // The VALUE qualifier (CLOUD-312 row 3): present is not the question when
        // the row is about one transition. Normalised on both sides — see
        // [`Rule::when_value`] for why the tracker's three spellings of one move
        // are one value, and why normalising a comparison is not the same as
        // knowing a consumer's vocabulary.
        if let Some(wanted) = rule.when_value.as_deref()
            && !comparable(&read).eq(&comparable(wanted))
        {
            return false;
        }
    }
    true
}

/// Fold a value for [`Rule::when_value`]'s comparison.
///
/// Case-insensitive, and the three separators a tracker's state parameter treats
/// as noise are dropped. Deliberately NOT a general slug: nothing else is
/// stripped, so a value that differs by any other character still differs.
pub(crate) fn comparable(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, ' ' | '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn matching_receipt_rows<'a>(policy: &'a Policy, envelope: &Envelope) -> Vec<&'a Rule> {
    let mut matched: Vec<&Rule> = Vec::new();
    // The write-triggered rows first, and they are selected without looking at a
    // command at all (CLOUD-444): the precondition is due before the work is
    // touched, so what fires the row is that this call writes. Which writes are
    // JUDGEABLE — not ignored, inside the repository, outside `.git` — is a
    // question about a checkout and therefore the boundary's
    // (`receipt::judgeable`), never this table's.
    if envelope.writes.is_some() {
        for rule in &policy.shapes {
            if rule.kind != RuleKind::Receipt
                || rule.receipt_trigger() != ReceiptTrigger::Write
                || !blocks(rule.severity(), policy.fail_on_warning)
                || !modifier_admits(rule, envelope)
            {
                continue;
            }
            matched.push(rule);
        }
    }
    // The tool-keyed rows (CLOUD-924), selected without a command line at all —
    // which is the point, since a structured call has none and `segments("")`
    // yields nothing, so the loop below cannot reach them. CLOUD-312's rows 1-3
    // are exactly this shape: a precondition due on `.*save_issue`, whatever
    // prefix the host minted.
    //
    // Guarded on a non-empty name so an empty selector cannot meet an empty
    // tool, and placed before the command walk so a row carrying `tool` is
    // matched once rather than once per segment.
    if !envelope.raw_tool.is_empty() {
        for rule in &policy.shapes {
            if rule.kind != RuleKind::Receipt
                || !blocks(rule.severity(), policy.fail_on_warning)
                || !rule.selects_tool(&envelope.raw_tool)
                || !modifier_admits(rule, envelope)
            {
                continue;
            }
            matched.push(rule);
        }
    }
    for segment in segments(&envelope.command) {
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
            if rule.kind != RuleKind::Receipt
                || rule.receipt_trigger() != ReceiptTrigger::Command
                || !blocks(rule.severity(), policy.fail_on_warning)
                || !modifier_admits(rule, envelope)
            {
                continue;
            }
            let Some((program, wanted)) = rule.trigger() else {
                continue;
            };
            if tokens[program_index] != program {
                continue;
            }
            if !operands_match(&words, &wanted) {
                continue;
            }
            if let Some(contains) = rule.contains.as_deref()
                && !segment.raw.contains(contains)
            {
                continue;
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

/// The receipt gate over the rows CLOUD-924's selector picked, and only those.
///
/// It exists because a tool-keyed receipt row is otherwise UNREACHABLE, for the
/// same reason CLOUD-924's shape selector needed its own placement: a structured
/// call carries no write, so the write-triggered gate above sends it home, and it
/// carries no command, so `segments("")` gives the command walk nothing to match.
/// The row would load, validate, resolve its checks at the boundary, and then
/// decide nothing — inert exactly where CLOUD-312's row 2 needs it.
///
/// **WHY THIS IS A SEPARATE FUNCTION RATHER THAN A WIDER CONDITION ON THE GATE
/// ABOVE**, which is the version that was written first and measured wrong:
/// consulting [`receipt_rules`] for every call carrying a tool name reaches
/// COMMAND-KEYED rows early too, and `cli.rs`'s
/// `the_committed_shape_rules_fire_on_every_banned_shape` went red on it —
/// `gh pr ready 42` came back refused by this repository's `ready-needs-receipts`
/// instead of by `ready-names-an-issue`. That inverts the chain's standing
/// precedence, where a ban a reviewer wrote by hand outranks an unmet
/// precondition, on the reasoning that there is no point telling the author of a
/// refused call which receipt to go and earn. So the narrowing is the mechanism,
/// not a tidiness: this gate sees a row only if that row's own `tool` selected
/// this call.
fn tool_receipt_rules(policy: &Policy, envelope: &Envelope, facts: &ReceiptFacts) -> Decision {
    // Both non-answers allow, and for the same reason [`receipt_rules`] gives
    // them one arm: a boundary that had no question to ask and a boundary that
    // could not ask reach the same verdict here, and neither is evidence a
    // receipt is missing (CLOUD-787).
    let facts = match facts {
        crate::facts::Look::Is(resolved) => resolved,
        crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => return Decision::Allow,
    };
    if envelope.raw_tool.is_empty() {
        return Decision::Allow;
    }
    for rule in &policy.shapes {
        if rule.kind != RuleKind::Receipt
            || !blocks(rule.severity(), policy.fail_on_warning)
            || !rule.selects_tool(&envelope.raw_tool)
        {
            continue;
        }
        // THE MODIFIER DECIDES WHETHER THE SELECTION OWES THE RECEIPT, the same
        // suppression `tool_rules` applies and for the same measured reason: a
        // selecting row that carries a modifier must not fire on the bare
        // selection. CLOUD-312's row 1 is the case — the search receipt is due on
        // a call that CREATES a tracker row, and a row that gated every edit as
        // well is the false-positive rate its own header says gets a guard
        // switched off within a day.
        if !modifier_admits(rule, envelope) {
            continue;
        }
        if let Some(refusal) = receipt_verdict(policy, rule, facts) {
            return Decision::Deny(refusal);
        }
    }
    Decision::Allow
}

fn receipt_rules(policy: &Policy, envelope: &Envelope, facts: &ReceiptFacts) -> Decision {
    // Neither non-answer is a receipt question to answer here, and both allow: a
    // guard that cannot read its own precondition must not become the reason
    // work stops, and neither must one told there is nothing to judge. They
    // reach the same verdict by two different routes, which is the distinction
    // `Option` could not hold (CLOUD-787).
    let facts = match facts {
        crate::facts::Look::Is(resolved) => resolved,
        crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => return Decision::Allow,
    };
    for rule in matching_receipt_rows(policy, envelope) {
        // Every named receipt must be valid. An unresolved name is Missing,
        // never absent-and-therefore-fine: a boundary that answered for
        // fewer checks than the row requires has not proved the precondition.
        if let Some(refusal) = receipt_verdict(policy, rule, facts) {
            return Decision::Deny(refusal);
        }
    }
    Decision::Allow
}

/// Adjudicate one receipt row against the resolved facts (CLOUD-1297).
///
/// **One adjudicator for both call sites**, which is the point of extracting it:
/// the two loops it replaces were byte-identical, and adding the alternation to
/// one and not the other would have left a row that denies on the mediated path
/// and allows on the other — a disagreement no test over either path alone can
/// see.
///
/// The two columns are read APART because they mean different things.
/// [`Rule::checks`] is a conjunction: every name must be valid, and the first
/// that is not carries the refusal, so the reader is pointed at one receipt to
/// go and mint. [`Rule::checks_any`] is an alternation: it is satisfied as soon
/// as ONE name is valid, and only a row where none is refuses.
///
/// A row carrying both is their conjunction, and the order here is deliberate —
/// the conjunction is adjudicated first so a row missing a mandatory receipt
/// names that receipt rather than the alternation it also happens to fail.
fn receipt_verdict(
    policy: &Policy,
    rule: &Rule,
    facts: &std::collections::BTreeMap<String, Validity>,
) -> Option<Refusal> {
    let verdict_of = |check: &str| facts.get(check).copied().unwrap_or(Validity::Missing);
    for check in rule.checks.iter().flatten() {
        let verdict = verdict_of(check);
        if verdict != Validity::Valid {
            return Some(receipt_refusal(
                rule,
                check,
                verdict,
                policy.agent_fact(check),
            ));
        }
    }
    // An ABSENT alternation is not an unsatisfied one. `checks_any` is optional,
    // and a row that declares none has nothing to satisfy here — reading absence
    // as "no alternative was valid" would deny every row that uses only the
    // conjunction, which is every row that existed before this column.
    let alternatives: Vec<&String> = rule.checks_any.iter().flatten().collect();
    if alternatives.is_empty()
        || alternatives
            .iter()
            .any(|check| verdict_of(check) == Validity::Valid)
    {
        return None;
    }
    Some(receipt_alternation_refusal(
        rule,
        &alternatives,
        &verdict_of,
    ))
}

/// Compose the refusal for an alternation no receipt satisfied.
///
/// It names EVERY alternative and each one's verdict, where the conjunction's
/// refusal names one. That asymmetry follows the remedy rather than a house
/// style: a failed conjunction has exactly one thing to go and do, and a failed
/// alternation has several, any of which would clear it — a message naming only
/// the first would send a reader to mint a `claim` receipt on a branch where
/// minting a `carry` was the right move and half the work.
///
/// Pointer-only (rule 4): receipt names and verdict tokens, never a receipt's
/// contents. The names are sorted by the row's own declaration order rather than
/// alphabetically, so the row reads as written and the output stays byte-stable
/// under `-J` (house-style §6).
fn receipt_alternation_refusal(
    rule: &Rule,
    alternatives: &[&String],
    verdict_of: &impl Fn(&str) -> Validity,
) -> Refusal {
    let named = alternatives
        .iter()
        .map(|check| format!("`{check}` {}", verdict_of(check).as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    Refusal::new(
        &rule.id,
        format!("this call needs any one of these receipts valid, and none is: {named}"),
        Fix::declared(rule.reason.as_deref()),
    )
}

/// Compose a receipt row's refusal, naming the check and what is wrong with it.
///
/// The verdict is in the cause rather than the fix because it is a *finding*
/// about the receipt, and the remedy is the row's declared `reason` — the same
/// contract a shape row keeps (CLOUD-122). Pointer-only: the check name and a
/// verdict token, never the receipt's contents.
fn receipt_refusal(
    rule: &Rule,
    check: &str,
    verdict: Validity,
    sourced: Option<&crate::facts::Declared>,
) -> Refusal {
    // FOUR CLASSES, NOT ONE (CLOUD-1285). These were seven arms of one `format!`
    // and they are not one thing: a MISSING receipt is repaired by running the
    // check, an EXPIRED one by running it again, a REFUTED one by fixing what it
    // reported — running it again changes nothing — and a SUPERSEDED one is
    // evidence about bytes this head no longer carries. Collapsing them would
    // make the registry less precise than the prose it replaced, which is the
    // one way this conversion could lose something.
    //
    // The check NAME is the pointer and is the whole of what travels. The row's
    // subject is deliberately not named even where one exists: it is read from
    // the call's own arguments, so echoing it would put payload in a refusal
    // (rule 4). Which KIND of thing the receipt is keyed to is the class's, and
    // `batten policy explain` answers it.
    let native = match verdict {
        Validity::Expired => crate::verdict::Native::ReceiptExpired,
        Validity::Refuted => crate::verdict::Native::ReceiptRefuted,
        Validity::StaleHead => crate::verdict::Native::ReceiptSuperseded,
        Validity::StaleMain => crate::verdict::Native::ReceiptOffTrunk,
        // `Valid` is not reachable from the caller, which only refuses a
        // non-valid verdict. It resolves here rather than panicking so the match
        // stays total, and it renders as the missing case, which is the honest
        // reading of "there is no usable receipt".
        Validity::Missing | Validity::Valid => crate::verdict::Native::ReceiptUnusable,
    };
    // An agent-sourced fact's remedy is the DECLARED COMMAND, not the row's
    // prose (CLOUD-776). That is what makes the loop close: the agent is told
    // exactly the command whose output will be accepted, and it is the same
    // string the record is then verified against. A row's `reason` here would be
    // a second wording of the same thing, free to drift from what is checked —
    // and a fix that asks for one command while the gate accepts another is how
    // a forged fact gets a legitimate-looking path.
    //
    // A `tool`-selected row has no command to run (CLOUD-690), so its remedy is
    // the row's own prose — the one case where `reason` is not a second wording of
    // something checkable, because there is no command string to drift from. The
    // selector is still what verifies the record, so nothing about the forgery
    // control changes; what changes is that the engine cannot compose the remedy
    // and says so by deferring to the consumer, which is also the honest answer:
    // *which* invocation of a tool answers a fact is the consumer's knowledge.
    let fix = match sourced {
        Some(fact) => match fact.command.as_deref() {
            Some(command) => Fix::Run(command.to_owned()),
            None => Fix::declared(rule.reason.as_deref()),
        },
        None => Fix::declared(rule.reason.as_deref()),
    };
    // THE KEYING TRAVELS AS A SUBJECT, because it is what the reader acts on and
    // dropping it was a real loss the suite caught. "No receipt for this commit"
    // sends someone looking for a per-commit step when what is missing is a claim
    // the whole branch shares — the wrong pointer this composer's own comment
    // calls CLOUD-122's failure in its most confusing form. It is the KIND of
    // thing keyed on, never the subject itself, which is read from the call's own
    // arguments and would be payload (rule 4).
    let keyed = match rule.receipt_key() {
        ReceiptKey::Branch => "branch",
        ReceiptKey::Named => "row",
        ReceiptKey::Head => "commit",
    };
    // THE BOUND TRAVELS TOO, and only on the class it is the measure for. A
    // reader acting on an expiry needs to know what the age was measured
    // against — `300s` is the difference between "run it again" and "this row
    // wants a step nobody can satisfy" — and it is a declared number rather
    // than a byte of the call, so rule 4 is satisfied. It is omitted on every
    // other class because there it is not what refused.
    let mut subjects = vec![
        crate::verdict::Subject::Artifact {
            artifact: check.to_owned(),
        },
        crate::verdict::Subject::Artifact {
            artifact: keyed.to_owned(),
        },
    ];
    if let Some(bound) = rule
        .max_age
        .filter(|_| matches!(verdict, Validity::Expired))
    {
        subjects.push(crate::verdict::Subject::Artifact {
            artifact: format!("{bound}s"),
        });
    }
    Refusal::declared(&rule.id, native, &subjects, fix)
}

/// The id-free half of the pipeline verdict: which shape a command commits.
///
/// Three causes rather than three rules, on [`receipt_refusal`]'s precedent — the
/// row declares one obligation and the engine says which way it was broken. A
/// per-shape column would only ever be used to switch part of a rule off, which
/// is what `severity = "allow"` already does wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discard {
    /// Piped into a pager or filter: the pipeline exits with the filter's status.
    Piped,
    /// Followed by `;` or `||`: only the last element's status survives.
    Trailing,
    /// Detached by `nohup` or a trailing `&`: the call returns before the work.
    Orphaned,
}

/// Deny a verdict-bearing command whose exit status the surrounding structure
/// throws away (CLOUD-443).
///
/// Judged per SEGMENT against the operators the parser now retains. Every shape
/// here fails green — exit 0 over a failure — which is what makes them worth a
/// gate rather than a convention: nothing downstream can notice them.
///
/// `&&` is absent by construction rather than by exclusion: it is the one
/// separator that preserves a non-zero status, so there is no false green to
/// refuse and denying it would be a pure false positive.
fn pipeline_rules(policy: &Policy, envelope: &Envelope) -> Decision {
    let rows: Vec<&Rule> = policy
        .shapes
        .iter()
        .filter(|rule| {
            rule.kind == RuleKind::Pipeline && blocks(rule.severity(), policy.fail_on_warning)
        })
        .collect();
    if rows.is_empty() {
        return Decision::Allow;
    }
    let parsed = segments(&envelope.command);
    for rule in rows {
        // The substitution family (CLOUD-864), judged first because it decides
        // over the same parse and shares nothing else with the discard family.
        //
        // THE WHOLE ENVELOPE RATHER THAN ITS `command` (CLOUD-1109): clause 3 is
        // a question about WHERE a relative operand resolves, and the answer is
        // the call's own working directory. It was decoded and unconsumed.
        if let Some(substitutes) = rule.substitutes.as_deref()
            && let Some(refusal) = substitution_decision(
                rule,
                substitutes,
                &parsed,
                policy.root.as_deref(),
                envelope.cwd.as_deref(),
            )
        {
            return Decision::Deny(refusal);
        }
        let verdicts = rule.verdict.as_deref().unwrap_or_default();
        let filters = rule.filters.as_deref().unwrap_or_default();
        for (index, segment) in parsed.iter().enumerate() {
            let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
            let Some(program_index) = effective_program(&tokens) else {
                continue;
            };
            // A `nohup` wrapper is looked THROUGH by `effective_program`, so the
            // detach it performs has to be read off the raw span rather than off
            // the resolved program — otherwise the wrapper that orphans the run
            // is the one token the parser hides.
            let detached_here = tokens.contains(&"nohup");
            let words: Vec<&str> = tokens[program_index + 1..]
                .iter()
                .copied()
                .filter(|token| !token.starts_with('-'))
                .collect();
            if !verdicts
                .iter()
                .any(|entry| entry.matches(tokens[program_index], &words))
            {
                continue;
            }
            // Orphaned first: it discards the verdict AND the supervision, so it
            // is the more complete failure of the two a detached pipeline commits.
            if detached_here || segment.terminator == Some(Separator::Background) {
                return Decision::Deny(pipeline_refusal(rule, Discard::Orphaned));
            }
            if segment.terminator == Some(Separator::Pipe) {
                // Every stage downstream of the verdict, not merely the next: a
                // pager two stages along substitutes just as completely.
                let piped_into_filter = parsed[index + 1..]
                    .iter()
                    .take_while(|stage| {
                        // Stop at the end of THIS pipeline — a later list element
                        // is a different command's business.
                        stage
                            .terminator
                            .is_none_or(|separator| separator == Separator::Pipe)
                    })
                    .chain(parsed.get(index + 1))
                    .any(|stage| {
                        let stage_tokens: Vec<&str> =
                            stage.words.iter().map(String::as_str).collect();
                        effective_program(&stage_tokens).is_some_and(|at| {
                            filters.iter().any(|filter| filter == stage_tokens[at])
                        })
                    });
                if piped_into_filter {
                    return Decision::Deny(pipeline_refusal(rule, Discard::Piped));
                }
            }
            if matches!(segment.terminator, Some(Separator::Semi | Separator::Or))
                && parsed.get(index + 1).is_some()
            {
                return Decision::Deny(pipeline_refusal(rule, Discard::Trailing));
            }
        }
    }
    Decision::Allow
}

/// Does any segment reach for a text utility where a first-class tool answers?
///
/// The predicate is a conjunction of three things, and dropping any one of them
/// turns a working gate into a wrongly-refusing one (CLOUD-864):
///
/// 1. **the program is a declared substitute** — the row's list, never a literal
///    here, because which utilities a consumer has better tools for is the
///    consumer's fact;
/// 2. **the segment is not downstream of a pipe** — `git ls-files | grep
///    crates/batten` is a filter over another command's output, which no tool
///    replaces. This is the clause a `shape` row cannot express, and the reason
///    the predicate lives on this kind at all;
/// 3. **an operand names a path inside the repository** — a bare `grep` reading
///    stdin, or one aimed at `/tmp`, is not standing in for anything.
///
/// Deliberately blind to a path reached through a shell variable: `grep "$pat"
/// "$dir"` carries no path this can see, and guessing at one would refuse work
/// over a target nobody can name. Stated on the row rather than fixed here.
fn substitution_decision(
    rule: &Rule,
    substitutes: &[String],
    parsed: &[Segment],
    root: Option<&Path>,
    cwd: Option<&Path>,
) -> Option<Refusal> {
    for (index, segment) in parsed.iter().enumerate() {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        let program_index = effective_program(&tokens)?;
        let program = tokens[program_index];
        let operands = &tokens[program_index + 1..];
        if !substitutes
            .iter()
            .any(|entry| substitute_matches(entry, program, operands))
        {
            continue;
        }
        // Clause 2. The PRECEDING segment's terminator is what says whether this
        // stage was fed by a pipe — the existing discard predicate reads the
        // FOLLOWING one, which is why both live here rather than one deriving
        // the other.
        if index > 0 && parsed[index - 1].terminator == Some(Separator::Pipe) {
            continue;
        }
        // Operands only, and the scan STOPS at the first redirection: everything
        // past a `>` is a destination this call writes, never a target it read
        // instead of reaching for a tool. `grep pat > out.txt` is stdin-fed and
        // must allow, which a scan that merely skipped the `>` would not do.
        let Some(target) = tokens[program_index + 1..]
            .iter()
            .take_while(|token| !token.contains('>') && !token.contains('<'))
            .find(|token| !token.starts_with('-') && names_a_repository_path(token, root, cwd))
        else {
            continue;
        };
        return Some(substitution_refusal(rule, program, target));
    }
    None
}

/// Does this `substitutes` entry select this invocation?
///
/// An entry is either a bare program name — `cat`, `head`, `ls` — or a name
/// QUALIFIED BY A FLAG, `sed:-n`, meaning "only when that flag is present".
///
/// The qualifier exists because one entry was wrong without it, and wrong in the
/// direction that matters. `sed` reads a file two ways: `sed -n '1,40p' f`
/// PRINTS a range, which is exactly `Read(offset, limit)` and is the shape the
/// measured corpus is full of — while `sed 's/a/b/' f` TRANSFORMS the stream,
/// which no first-class tool does at all. Denying the second told the caller "a
/// first-class tool answers this directly", which is simply false, and a gate
/// whose stated reason does not hold is a defect rather than a strict reading
/// (`crates/batten/tests/it/mediated_verbs.rs` caught it).
///
/// Mirrors the `requires_flag` qualifier the `[[verb]]` table already carries for
/// the same distinction on `sed -i`, rather than inventing a second vocabulary
/// for "this program only counts in one of its modes".
fn substitute_matches(entry: &str, program: &str, operands: &[&str]) -> bool {
    match entry.split_once(':') {
        None => entry == program,
        Some((name, flag)) => {
            name == program
                && operands
                    .iter()
                    // A flag may be bundled (`-in`) or carry a value (`-i.bak`),
                    // so this is a prefix test over a single-dash token rather
                    // than equality — the same reading the verb table takes.
                    .any(|token| *token == flag || bundled_short_flag(token, flag))
        }
    }
}

/// Is `flag` present inside a bundled short-option token such as `-ni`?
///
/// Only for single-dash tokens. A LONG option that merely spells the same letter
/// is not the flag — `--posix` is not `-x` — and a naive `contains` over the
/// whole token would say it was.
fn bundled_short_flag(token: &str, flag: &str) -> bool {
    let (Some(short), Some(rest)) = (flag.strip_prefix('-'), token.strip_prefix('-')) else {
        return false;
    };
    if short.starts_with('-') || rest.starts_with('-') {
        return false;
    }
    rest.contains(short)
}

/// Does this operand name something inside the repository?
///
/// Conservative on purpose, and every exclusion is a case the gate must NOT
/// refuse: an absolute path is somewhere else (`>/tmp/x.log` is the shape
/// `verdict-not-discarded` mandates), a `-` is stdin, and a bare word with no
/// separator is a pattern rather than a path — `grep CLOUD file.md` must be
/// judged on `file.md`, never on `CLOUD`.
///
/// The last two exclusions are DEFECTS THIS RULE COMMITTED against its own
/// author within an hour of landing, which is why they are cases rather than a
/// tightened heuristic. `tail -40 f 2>/dev/null` refused naming `2>/dev/null`,
/// because a redirection reaches the word list as a word and the `/` test cannot
/// tell it from a path. `grep -E 'a|BATS_TEST_FILENAME|%.bats|c' f` refused
/// naming the PATTERN, because `.bats|c` reads as an extension. Both refusals
/// were correct in verdict and wrong in every pointer they gave, and a gate that
/// names the wrong operand teaches the caller nothing it can act on.
fn repo_relative_path(token: &str) -> bool {
    if token.starts_with('/') || token.starts_with('~') || token == "-" {
        return false;
    }
    if token.starts_with("..") {
        return false;
    }
    // Redirection syntax, not an operand. `2>/dev/null`, `>out.txt` and `<in`
    // all carry a `/` or an extension and would otherwise read as targets.
    if token.contains('>') || token.contains('<') {
        return false;
    }
    // A REGEX IS NOT A PATH, and this is the exclusion that had to be widened
    // twice before it held. `grep`, `rg` and `sed` all take their pattern as the
    // first non-flag operand, so the naive "first operand that looks like a
    // path" scan reaches the PATTERN first and names it as the target — a
    // refusal that is right in verdict and wrong in every pointer it gives.
    //
    // Three live misfires got it here, each escaping the previous fix:
    // `a|b|%.bats|c` (an alternation, and `.bats|c` read as an extension), then
    // `\)/[A-Za-z0-9_][A-Za-z0-9._-]*` (no `|` at all, but a `/` from the
    // character class). So the test is over the metacharacter SET rather than
    // one member of it: a backslash, an anchor, a group or a quantifier brace
    // never appears in a path this repository tracks, while `*` and `?`
    // deliberately do — `ls mise-tasks/*.sh` is a glob aimed at the tree and
    // `Glob` is exactly what answers it.
    if token.contains(['\\', '^', '$', '(', ')', '[', ']', '{', '}', '|', '+']) {
        return false;
    }
    // A separator or a known extension is what distinguishes a path from a
    // pattern. Both readings are cheap and neither opens the filesystem: a gate
    // that stat()ed its operands would answer differently on two checkouts.
    token.contains('/') || Path::new(token).extension().is_some()
}

/// Clause 3, resolved against the CALLER'S working directory (CLOUD-1109).
///
/// # The defect
///
/// [`repo_relative_path`] is purely lexical: it asks whether a token is SHAPED
/// like a relative path and calls that "inside the repository". Reproduced twice
/// on 2026-08-28, with cwd a scratch directory outside the repository:
/// `cat err.txt` refused, and the identical file named absolutely allowed. So the
/// corpus the guard thought it was protecting and the one it was reading were
/// different sets, and a transient scratch file was refused with a verdict
/// asserting the repository contained it.
///
/// # `cwd` was decoded and unconsumed, which is the whole of the fix
///
/// The harness supplies it, [`Envelope::cwd`] carries it, and [`Field::Cwd`]
/// already reads it. Joining the operand to it and asking [`relative_to`] the
/// one containment question the engine already owns makes the two spellings of
/// one file agree, without a `stat`, a spawn, or a second root resolver
/// (CLOUD-824's class).
///
/// # ABSOLUTE STAYS EXCLUDED, and that bound is deliberate
///
/// Resolving both spellings and refusing whichever lands inside the repository
/// would be tidier and would WIDEN what is refused — `cat <abs>/AGENTS.md` is
/// allowed today. The row is explicit that this change only ever narrows, so no
/// call that is allowed today starts failing, and `>/tmp/x.log` — the shape
/// `verdict-not-discarded` mandates — keeps its exclusion for free.
///
/// # An unknown cwd keeps today's answer rather than switching the gate off
///
/// A host that sends no `cwd` leaves nothing to resolve against, and reading
/// that as "outside" would silently disable clause 3 for that host — a gate that
/// found nothing looking exactly like a gate that passed. So the lexical reading
/// stands where there is nothing better, which is the same could-not-look
/// posture the rest of this module takes.
fn names_a_repository_path(token: &str, root: Option<&Path>, cwd: Option<&Path>) -> bool {
    if !repo_relative_path(token) {
        return false;
    }
    let (Some(root), Some(cwd)) = (root, cwd) else {
        return true;
    };
    // `relative_to` answers `None` for a path outside `root`, which is exactly
    // the question — and it is the same primitive `protects` asks, so the two
    // readers cannot disagree about containment the way two resolvers would.
    relative_to(root, &cwd.join(token).display().to_string()).is_some()
}

/// Compose a substitution refusal: what was reached for, and what answers it.
///
/// Names the displaced CAPABILITY rather than the principle, which is the
/// opposite of [`pipeline_refusal`]'s choice and deliberate. There the lesson was
/// that a refusal worded around one command taught nothing transferable
/// (CLOUD-199); here the transferable half is already in the row's `reason`, and
/// what the caller cannot work out for itself is what to reach for instead.
///
/// **Capability, not product** (CLOUD-998). This named `Read(offset, limit)`,
/// `Grep` and `Glob` as literals, on the premise that a tool name is the most
/// actionable thing a refusal can carry. It is — right up to the session that
/// does not have that tool, where a remedy naming it is unactionable and the
/// caller's only remaining move is the call that was just refused. Which
/// instruments a session carries varies; the four questions do not. So the cause
/// names the questions and lets the caller map them onto what it has, which is
/// the one part of this it can do and the engine cannot.
fn substitution_refusal(rule: &Rule, program: &str, target: &str) -> Refusal {
    // THE TWO POINTERS STAY INLINE and the paragraph does not (CLOUD-1285). Which
    // program was aimed at which path is what the caller acts on; the four
    // question classes and the downstream-of-a-pipe bound are the CLASS, and
    // `batten policy explain` is what fetches them. The path is first because
    // `Refusal::declared` binds an admission to the first path-bearing subject.
    Refusal::declared(
        &rule.id,
        crate::verdict::Native::ToolSubstituted,
        &[
            crate::verdict::Subject::Path {
                path: target.to_owned(),
            },
            crate::verdict::Subject::Artifact {
                artifact: program.to_owned(),
            },
        ],
        Fix::declared(rule.reason.as_deref()),
    )
}

/// Compose a pipeline refusal: which shape, and the row's declared remedy.
///
/// The cause states the **PRINCIPLE** rather than naming one command, and that is
/// CLOUD-199's measured lesson rather than a style choice: the predecessor guard
/// was worded around one command string, an agent complied with it exactly, and
/// made the identical error on the next command in the same session.
fn pipeline_refusal(rule: &Rule, discard: Discard) -> Refusal {
    // THREE SHAPES, THREE CLASSES (CLOUD-1285). They were three branches of one
    // `format!` and they are three different defects with three different
    // repairs, so collapsing them into one token would have made the registry
    // less precise than the prose it replaced. Each carries its own `class`, and
    // `batten policy explain` answers with the one that fired.
    let native = match discard {
        Discard::Piped => crate::verdict::Native::VerdictPiped,
        Discard::Trailing => crate::verdict::Native::VerdictTrailing,
        Discard::Orphaned => crate::verdict::Native::RunOrphaned,
    };
    Refusal::declared(&rule.id, native, &[], Fix::declared(rule.reason.as_deref()))
}

/// Judge the tool a mediated call names (CLOUD-924).
///
/// The third keying axis, and the only one a **structured** call can satisfy.
/// `adjudicated` returns `Allow` the moment `envelope.command` is empty, and an
/// MCP call, a `Read` and a `Task` spawn all carry an empty command — so every
/// gate below that early return is unreachable for them. That is the gap
/// CLOUD-312's rows 4 and 5 report: two connector guards keyed on a tool name,
/// with no config surface to retire onto.
///
/// Separate from [`shape_rules`] rather than threaded through it, and the
/// separation is the design: that function's whole body is a walk over
/// `segments(command)` deriving an effective program and its operands, none of
/// which exists here. Passing a tool name into it would mean a second predicate
/// inside a loop that runs zero times for the calls this exists to judge.
///
/// **Cheap when irrelevant** (§4, CLOUD-460's shape): the column test comes
/// before anything else, so a repository declaring no tool-keyed row pays one
/// `Iterator::any` over rows it has already loaded — and `passthrough` stays
/// below `noop`.
fn tool_rules(policy: &Policy, envelope: &Envelope) -> Decision {
    // A call the host named nothing for cannot match a selector, and asking
    // would let an empty selector meet an empty name.
    if envelope.raw_tool.is_empty() {
        return Decision::Allow;
    }
    for rule in &policy.shapes {
        if rule.kind != RuleKind::Shape || !blocks(rule.severity(), policy.fail_on_warning) {
            continue;
        }
        if !rule.selects_tool(&envelope.raw_tool) {
            continue;
        }
        // A ROW CARRYING A CEILING SELECTS HERE AND REFUSES ELSEWHERE, which is
        // the same split `shape_rules` makes for `requires_key`: the modifier
        // decides whether the selection refuses, so a bare deny here would refuse
        // every call the row selects and the cap would never be consulted.
        //
        // Measured, and only the end-to-end suite could see it: the unit cases
        // call `ceiling_rules` directly, so a `Task` row capped at 100 tokens
        // allowed a 100-token prompt there and was refused outright through the
        // binary. `.claude/rules/rust.md` prefers end-to-end for anything a
        // consumer depends on, and this is why.
        if rule.max.is_some() {
            continue;
        }
        // THE POLARITY MODIFIERS (CLOUD-987), which narrow a selection this
        // function already made rather than making one of their own.
        if !modifier_admits(rule, envelope) {
            continue;
        }
        return Decision::Deny(shape_refusal(rule));
    }
    Decision::Allow
}

/// Count the tracked artifacts `value` names, after the consumer's rewrites
/// (CLOUD-925).
///
/// The shell guard's derivation, moved: split on anything that cannot appear in a
/// repository path, keep the path-shaped tokens, rewrite each through the row's
/// own table, and count the ones the tree tracks. Deduped, because naming one
/// artifact twice is one artifact to read.
///
/// **Tracked is the whole of the membership test, and it is load-bearing rather
/// than convenient**: a token naming a path the repository does not carry is
/// naming nothing it can be made to read, so a URL, a branch name and a typo all
/// drop out by construction instead of through an allowlist somebody has to tune.
///
/// Pure: the tracked set is handed in, so this counts and never looks.
#[must_use]
pub fn count_named_artifacts(
    value: &str,
    resolves: &[crate::rules::Rewrite],
    tracked: &std::collections::BTreeSet<String>,
) -> usize {
    let compiled: Vec<(regex::Regex, &str)> = resolves
        .iter()
        .filter_map(|rewrite| {
            // Already compiled once at load, so a failure here cannot happen for
            // a row that loaded; skipping rather than panicking keeps the
            // mediated path free of a reachable panic (`.claude/rules/rust.md`).
            regex::Regex::new(&rewrite.reference)
                .ok()
                .map(|re| (re, rewrite.path.as_str()))
        })
        .collect();
    let mut named: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for token in value.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | '-' | ':'))
    }) {
        if token.is_empty() {
            continue;
        }
        let mut candidate = token.to_owned();
        for (pattern, replacement) in &compiled {
            if pattern.is_match(token) {
                candidate = pattern.replace(token, *replacement).into_owned();
                break;
            }
        }
        if tracked.contains(&candidate) {
            named.insert(candidate);
        }
    }
    named.len()
}

/// How many per-call ceilings this process has actually measured (CLOUD-925).
///
/// **A counter, because a clock cannot discriminate here** — the same argument
/// [`crate::rules::documents_acquired`] rests on, and the one
/// `.claude/rules/rust.md` makes for concurrency one section over: *"assert it
/// with a counter and a repeat-run comparison, never with wall clock."*
///
/// The claim it defends is CLOUD-925's cheap-when-irrelevant half: a repository
/// declaring no ceiling **measures nothing**. Timing cannot say that — reading a
/// decoded string and dividing by four is far inside the noise of a process
/// start, so a wall-clock assertion passes on a build that measures every call.
/// The row's §7 proposed the `passthrough`-below-`noop` reading as that test;
/// measured on this container, that relation does not hold at either arm of
/// `perf-pair`, so it could not have discriminated either.
///
/// Incremented at the point past which work is actually spent — after the row
/// selected and the projection turned out to be present — so a row that declared
/// a ceiling for a different tool, or a call whose projection the host did not
/// send, is deliberately not counted.
///
/// Monotonic and process-global, and **published by the caller rather than by
/// the gate** — `ceiling_rules` reports its count through an out-parameter and
/// `adjudicated` adds it here. That is what keeps the gate a pure function of its
/// inputs, and it is what the tests assert on: a process-global counter cannot be
/// read as a delta from a test binary whose sibling cases also measure, which is
/// the race `document_read_count.rs` needs its own binary to avoid. Measured
/// here: two ceiling cases in one binary, and the delta was wrong.
static CEILINGS_MEASURED: AtomicUsize = AtomicUsize::new(0);

/// How many per-call ceilings this process has measured.
#[must_use]
pub fn ceilings_measured() -> usize {
    CEILINGS_MEASURED.load(Ordering::Relaxed)
}

/// Judge a per-call ceiling over a named envelope projection (CLOUD-925).
///
/// `[budget.<name>]` is a **file-set** budget evaluated over the tree, so the
/// bound `fanout-guard` carries — count the prompt, refuse past a cap — had no
/// spelling as a row at all. This is that bound as config.
///
/// **Cheap when irrelevant, and the column test comes first** (§4, CLOUD-460's
/// shape): a repository declaring no ceiling reads no projection and counts
/// nothing. The `Iterator::any` below is over rows already loaded, so a call in
/// such a repository pays one pass over a slice and no measurement — which is
/// what `ceilings_measured` counts, and what the suite asserts rather than
/// timing.
///
/// Only [`CeilingUnit::Tokens`] is decided here, because only it is pure.
/// [`CeilingUnit::TrackedArtifacts`] needs the tracked set — a property of a
/// checkout, not of the envelope — so it is resolved at the boundary and arrives
/// as a fact; a row declaring it is skipped here and judged with that fact in
/// scope.
fn ceiling_rules(policy: &Policy, envelope: &Envelope, measured: &mut usize) -> Decision {
    for rule in &policy.shapes {
        if rule.kind != RuleKind::Shape || !blocks(rule.severity(), policy.fail_on_warning) {
            continue;
        }
        let (Some(field), Some(unit), Some(max)) = (rule.measures, rule.counts, rule.max) else {
            continue;
        };
        // `TrackedArtifacts` is decided below from the boundary's count; only
        // the pure unit is measured here.
        if unit != CeilingUnit::Tokens {
            continue;
        }
        // The row still selects on its own terms; the ceiling only decides
        // whether that selection refuses (the `requires_key` shape). A ceiling
        // row is tool-keyed by construction — `validate_ceiling` refuses any
        // other selector — so this is the whole of the selection.
        if envelope.raw_tool.is_empty() || !rule.selects_tool(&envelope.raw_tool) {
            continue;
        }
        // The polarity modifiers narrow that selection here too (CLOUD-987). They
        // are permitted on any `shape` row, so a ceiling row may carry one, and a
        // ceiling that ignored it would measure calls the row does not claim.
        if !modifier_admits(rule, envelope) {
            continue;
        }
        // ABSENT IS NOT ZERO. A projection the host did not send is "could not
        // look", and a row that read it as an empty payload would pass every call
        // while reporting a measurement it never took.
        let Some(value) = field.read(envelope) else {
            continue;
        };
        *measured += 1;
        let count = crate::budget::estimate_tokens(&value);
        // `>`, so exactly at the cap passes — `budget::Report::over_budget`'s
        // boundary, inherited rather than re-decided (CLOUD-925 §1).
        if count > max {
            return Decision::Deny(ceiling_refusal(rule, count, max));
        }
    }
    Decision::Allow
}

/// Judge a `tracked-artifacts` ceiling against the boundary's count (CLOUD-925).
///
/// Separate from [`ceiling_rules`] because the two units differ in where their
/// measurement comes from, not in what they then do with it: a token count is
/// arithmetic over bytes already decoded, and an artifact count is a question
/// about a checkout that only the boundary can ask.
///
/// **`None` allows**, and that is the same direction every fact here fails in: a
/// ceiling that could not count has established nothing, and a gate that refused
/// on a failed lookup would turn an unreadable tree into a policy verdict.
/// Deliberately distinct from `Some(0)` — counted, and it names nothing.
fn manifest_ceiling(policy: &Policy, envelope: &Envelope, counted: ManifestFacts) -> Decision {
    let Some(count) = counted else {
        return Decision::Allow;
    };
    let Some(rule) = policy.manifest_ceiling_for(envelope) else {
        return Decision::Allow;
    };
    let Some(max) = rule.max else {
        return Decision::Allow;
    };
    // `>`, so exactly at the cap passes — the boundary `budget::Report` owns.
    if count > max {
        return Decision::Deny(ceiling_refusal(rule, count, max));
    }
    Decision::Allow
}

/// Compose a ceiling breach's refusal (CLOUD-925).
///
/// **Pointer-only structurally**: the measurement, the cap and the row id reach
/// [`Refusal`], and the measured value is never passed to this function — so
/// there is no field a byte of it could occupy. That is what makes counting a
/// prompt admissible where echoing one is not.
/// A row's declared `policy_url` as a subject, so a converted refusal keeps it.
///
/// It was appended to four composers' cause strings as `". See <url>"`, and the
/// conversion to a declared class dropped it — a real pointer lost, which is the
/// one thing CLOUD-1285 must not do. It is the CONSUMER's declared pointer, so it
/// belongs beside the class's own route rather than inside the class prose, and a
/// tagged `Artifact` is what carries it without inventing a subject kind.
fn policy_url_subject(rule: &Rule) -> Vec<crate::verdict::Subject> {
    rule.policy_url
        .as_deref()
        .map(|url| {
            vec![crate::verdict::Subject::Artifact {
                artifact: url.to_owned(),
            }]
        })
        .unwrap_or_default()
}

fn ceiling_refusal(rule: &Rule, count: usize, max: usize) -> Refusal {
    // THE COUNT AND THE CEILING TRAVEL AS SUBJECTS (CLOUD-1285), not as prose.
    // `Subject::Count` is a tagged pointer, so the two numbers a reader acts on
    // stay in the line while the paragraph explaining what a ceiling IS moves
    // behind `batten policy explain`. The `policy_url` was a fourth copy of the
    // same "See <url>" tail in this file; it is the class's route now.
    let mut subjects = vec![
        crate::verdict::Subject::Count {
            count: count as u64,
        },
        crate::verdict::Subject::Count { count: max as u64 },
    ];
    subjects.extend(policy_url_subject(rule));
    Refusal::declared(
        &rule.id,
        crate::verdict::Native::CeilingExceeded,
        &subjects,
        Fix::declared(rule.reason.as_deref()),
    )
}

fn shape_rules(policy: &Policy, envelope: &Envelope, command: &str, keys: &KeyFacts) -> Decision {
    // The polarity modifiers (CLOUD-987) are the SELECTOR's now, not this
    // function's: `matching_shape_rows` takes the envelope and applies
    // `modifier_admits` itself, so `key_base_for` — which selects through the
    // same function — cannot resolve a base from a row this loop would refuse.
    // Checking here as well would be the second implementation of one rule.
    for rule in matching_shape_rows(policy, envelope) {
        // The key modifier (CLOUD-446). A row carrying it selected the command
        // and then declines to refuse it, which is the whole point: `continue`
        // rather than `return Allow`, so a later row that bans the same shape
        // outright still gets its say.
        if let Some(expression) = rule.requires_key.as_deref() {
            if key_present(expression, command, keys) {
                continue;
            }
            return Decision::Deny(unkeyed_refusal(rule));
        }
        return Decision::Deny(shape_refusal(rule));
    }
    Decision::Allow
}

/// Judge the content a write would land (CLOUD-758).
///
/// The first **content-keyed** gate on the mediated path. Every write-shaped
/// gate before it asked which file was being touched; this asks what would end
/// up in it, which is the half CLOUD-736 reports missing.
///
/// Three-valued, and the third value is what keeps it honest: a call whose shape
/// carries no content is [`crate::facts::Look::CouldNotLook`] and **no row
/// fires**. That is not "the content is empty" — a row keyed on an empty file
/// would then fire on every shell command as though it had inspected one.
///
/// Pointer-only (rule 4): the refusal names the rule and the path. The matched
/// bytes are not carried, and `Refusal` has no field one could occupy.
fn content_rules(policy: &Policy, envelope: &Envelope, prospective: &ProspectiveFacts) -> Decision {
    let crate::facts::Look::Is(content) = prospective else {
        return Decision::Allow;
    };
    for rule in &policy.shapes {
        if rule.kind != RuleKind::Shape {
            continue;
        }
        if !blocks(rule.severity(), policy.fail_on_warning) {
            continue;
        }
        let Some(expression) = rule.content.as_deref() else {
            continue;
        };
        // The polarity modifiers narrow a content row too (CLOUD-987): they are
        // permitted on any `shape` row, and a content gate that ignored them would
        // fire on calls the row's own arguments exclude.
        if !modifier_admits(rule, envelope) {
            continue;
        }
        // A pattern that does not compile matches NOTHING rather than
        // everything: `config lint` refuses it at load, and a hook that cannot
        // read a row must not turn that into a refusal of the call.
        let Ok(pattern) = regex::Regex::new(expression) else {
            continue;
        };
        if pattern.is_match(content) {
            return Decision::Deny(content_refusal(rule, envelope));
        }
    }
    Decision::Allow
}

/// The paths a `policy` row contributes to the `protected` set (CLOUD-833).
///
/// A row naming a `module` contributes that file. A row naming a `bundle`
/// contributes **the root and everything under it** — `<root>` so the folder
/// itself cannot be replaced, and `<root>/**` so its members cannot be edited.
///
/// Enumerating the files present at load would not do: a bundle's membership
/// changes without a config edit, so the set would silently stop covering a
/// module added afterwards. That is the same "holds for named files and lapses
/// for a folder" failure §8's out-of-band property cannot afford, which is why
/// this is a glob rather than a listing.
fn policy_protected_paths(rule: &Rule) -> Vec<String> {
    if let Some(module) = rule.module.as_deref() {
        return vec![module.to_owned()];
    }
    let Some(bundle) = rule.bundle.as_deref() else {
        return Vec::new();
    };
    let root = bundle.trim_end_matches('/');
    vec![root.to_owned(), format!("{root}/**")]
}

/// What a registered module says at the end of a turn, as ADVICE (CLOUD-1051).
///
/// # The dead gate this closes
///
/// [`adjudicated`] returns [`Decision::Allow`] at `Stop` **before any rule is
/// read**, which is CLOUD-889's runaway removed by construction and stays. The
/// consequence nobody had drawn: a `mediated_call` module also never runs there,
/// so `policy/stop-posture.rego` — a row whose whole subject is the turn's final
/// message, a field only `Stop` projects — could not fire on any event at all.
/// Its own `test_` rules passed the entire time, which is exactly the class
/// `.claude/rules/policy-modules.md` names: a dead gate and a clean tree are
/// byte-identical on the decision surface.
///
/// # Why this is a second function and not a widened `adjudicate`
///
/// `adjudicate`'s Stop arm is the mechanism that makes a refusal there
/// *unreachable*. Routing the modules through it would put a `Decision::Deny`
/// back on that path and re-open the runaway through the door CLOUD-898 warned
/// about. So the modules are evaluated here, the answer is TEXT rather than a
/// decision, and there is no value this function can return that refuses
/// anything — the same structural argument `completion.rs` makes for itself.
///
/// # The recursion bound is the payload's, not a state file
///
/// `stop_active` is false on the first `Stop` of a turn and true on the one a
/// previous `Stop` continuation caused, so returning `None` for it bounds this
/// to one nudge per turn deterministically. That is the bound the retired shell
/// hook used and the one `adjudicate` deliberately never read.
///
/// `None` for every other event, for could-not-look, and for a policy that
/// registers no module.
#[must_use]
pub fn stop_advice(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Option<String> {
    if envelope.event != Event::Stop {
        return None;
    }
    if envelope.stop_active == Some(true) {
        return None;
    }
    // A MODULE'S REFUSAL BECOMES ITS CAUSE AND ITS REMEDY, which is the same
    // demotion `dispatch_handlers` performs for a handler and for the same stated
    // reason — `Event::carries_a_verdict` is the one authority both producers ask.
    //
    // READ THROUGH `policy_refusal` RATHER THAN `policy_rules` (CLOUD-1131). That
    // function now consults the enabling row's severity, and a `warn` row's
    // violation comes back as `Allow` there — correctly, since nothing may refuse
    // on this event anyway. Reading the decision would therefore have dropped a
    // `warn` module's nudge at `Stop`, where every module's answer is text and the
    // severity column decides nothing.
    //
    // ASSEMBLED RATHER THAN `Refusal::render`d, and the difference is one word
    // that would be a lie: that projection opens `Refused by`, and nothing here
    // refuses. The id, the cause and the remedy all travel, so the fix clause is
    // present exactly as that contract insists.
    let (_, refusal) = policy_refusal(policy, envelope, facts)?;
    Some(render_advice(&refusal))
}

/// The policy gate: hand every registered module the call's facts and read back
/// its denials (CLOUD-647, CLOUD-689).
///
/// **Pure.** The modules were read, compiled and smoke-queried at the boundary
/// by [`crate::policy::load`], and the input document below is built from the
/// envelope this function was handed. Nothing here opens a file, starts a
/// process, or reads a clock, which is what lets a consumer-authored predicate
/// sit on the mediated path at all.
///
/// **Deny-only.** Only the module's `deny` set is consulted; there is no shape
/// here for an allow, so a module can raise a gate and never lower one (§8's
/// raise-only invariant, and the allow/deny contradiction class removed by
/// construction rather than detected).
///
/// **A module that cannot answer allows.** [`crate::facts::Look::CouldNotLook`]
/// is not a deny: a gate that refuses where it could not look becomes the reason
/// work cannot proceed, which is the same fail-open posture `ReceiptFacts` and
/// [`key_present`] already take. The load-time smoke query is what makes this
/// arm rare rather than routine — a module that faults here almost certainly
/// faulted there and never reached a running gate.
fn policy_rules(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Decision {
    // THE SEVERITY COLUMN REACHES THIS SURFACE (CLOUD-1131). It did not until
    // this row: every module violation became a `Decision::Deny`, so a row
    // declaring `severity = "warn"` denied exactly as `deny` did while its config
    // said otherwise. `blocks` is the same predicate every typed rule kind here
    // consults, so the two now answer one question.
    //
    // A NON-BLOCKING VIOLATION IS NOT DISCARDED, it is demoted — `policy_advice`
    // renders the same refusal as text, and `run_hook` puts it on the advisory
    // channel. A sensor with no reader is the defect this row exists inside, so
    // the demotion and the delivery land together or neither does.
    match policy_refusal(policy, envelope, facts) {
        Some((severity, refusal)) if blocks(severity, policy.fail_on_warning) => {
            Decision::Deny(refusal)
        }
        _ => Decision::Allow,
    }
}

/// The advisory half of [`policy_rules`]: what a NON-blocking module violation
/// says (CLOUD-1131).
///
/// `None` for silence, for a blocking violation — that one is the caller's
/// `Decision` and saying it twice would put one finding on two channels — and for
/// an event with no advisory channel, which is the host capability table's answer
/// rather than this function's.
///
/// **Assembled rather than `Refusal::render`ed**, for `stop_advice`'s reason: that
/// projection opens `Refused by`, and nothing here refuses. The id, the cause and
/// the remedy all travel, so a reader still gets the class and the way out.
#[must_use]
pub fn policy_advice(policy: &Policy, envelope: &Envelope, facts: &Facts<'_>) -> Option<String> {
    let (severity, refusal) = policy_refusal(policy, envelope, facts)?;
    if blocks(severity, policy.fail_on_warning) {
        return None;
    }
    Some(render_advice(&refusal))
}

/// One refusal's text on the advisory channel, with no word that claims a verdict.
fn render_advice(refusal: &Refusal) -> String {
    format!(
        "{}: {} {}",
        refusal.rule(),
        refusal.reason(),
        match refusal.fix() {
            crate::refusal::Fix::Run(text) => text.clone(),
            crate::refusal::Fix::None => String::new(),
        }
    )
    .trim_end()
    .to_owned()
}

/// The STRONGEST violation any enabled bundle raises, with the severity its
/// enabling row declared.
///
/// # Why not the first (CLOUD-1131)
///
/// Every other gate in this chain is first-match-wins, and this one was too until
/// the severity column reached this surface. That combination is unsound the
/// moment two rows can answer with different force: a `warn` bundle declared
/// ahead of a `deny` bundle, both matching one call, returned the `warn` — and
/// [`policy_rules`] then read `blocks` as false and **allowed a call that denied
/// before this row landed**. The refusal was not overridden by anything; it was
/// simply never reached, because declaration order decided a question only
/// severity can.
///
/// So the scan is total and the strongest wins. Declaration order survives as the
/// tie-break, which is what keeps output byte-stable between two rows of equal
/// force — the property first-match-wins was actually buying.
fn policy_refusal(
    policy: &Policy,
    envelope: &Envelope,
    facts: &Facts<'_>,
) -> Option<(RuleSeverity, Refusal)> {
    // NOTHING IS PROJECTED FOR A CALL NO ROW SELECTS FOR, and this early return
    // is where that is true rather than in a comment (CLOUD-460, CLOUD-834 §2).
    // It is also why widening the document costs the pass-through path nothing:
    // the facts below were resolved for the typed rule table whether or not a
    // module exists, and a repository with no policy row never reaches the
    // serialization at all.
    if policy.bundles.is_empty() {
        return None;
    }
    let Ok(input) = call_document(envelope, facts) else {
        return None;
    };
    let mut strongest: Option<(RuleSeverity, Refusal)> = None;
    for bundle in &policy.bundles {
        let crate::facts::Look::Is(denials) = crate::policy::deny(bundle, &input) else {
            continue;
        };
        // The first denial WITHIN a bundle decides for that bundle — one module's
        // own findings are ordered by its own declaration and share its row's
        // severity, so there is nothing to rank between them. Ranking happens
        // ACROSS bundles, below, where the severities can actually differ.
        if let Some(violation) = denials.first() {
            // THE POINTER IS THE PREDICATE, NOT THE BUNDLE (CLOUD-832).
            // `Module::attribute` resolves a `violation`'s own `rule` id when it
            // named one and falls back to the registering row's id otherwise —
            // which is the pre-CLOUD-832 behaviour, reached by a module that
            // uses the bare-string `deny` shape. One place decides that
            // fallback, because a waiver keys off the same answer and two
            // spellings of it would let a waiver suppress something a finding
            // does not name.
            //
            // THE CAUSE IS A TOKEN, A GLOSS AND A POINTER (CLOUD-1050).
            // It used to be the module's own prose, which nothing could check —
            // a refusal was free to name no remedy at all. Now both halves come
            // off the declared class: the line from `render_line`, and the fix
            // from the class's first `command` route, so "a refusal names a way
            // out" holds by construction rather than by each module's care.
            let severity = bundle.severity_for(violation.rule.as_deref());
            // STRICTLY GREATER, so an equal severity leaves the incumbent in
            // place and declaration order remains the tie-break.
            if strongest.as_ref().is_none_or(|(held, _)| severity > *held) {
                strongest = Some((
                    severity,
                    // RECORDS THE TOKEN IT ALREADY RENDERS (CLOUD-1285). This
                    // path was half-converted: it took the line from
                    // `render_line` and the fix from the class's first `command`
                    // route, and then called `Refusal::new`, which sets
                    // `verdict: None`. So `refusal.verdict()` was `None` on the
                    // module path too and `batten policy explain` was
                    // unreachable from the one surface that had already done the
                    // work of resolving the class.
                    Refusal::from_class(
                        bundle.attribute(violation),
                        &policy.verdicts,
                        &violation.verdict,
                        &violation.subjects,
                        Fix::None,
                    ),
                ));
            }
            // Nothing outranks `Deny`, so the remaining bundles cannot change the
            // answer and evaluating them would spend the mediated budget to learn
            // nothing.
            if severity == RuleSeverity::Deny {
                break;
            }
        }
    }
    strongest
}

/// The input document a policy module decides over.
///
/// **Neutral facts only.** Every field is the concept rather than the host's
/// spelling — `operation` and `event` are normalized (CLOUD-779), so a module
/// written once decides the same way on all five supported harnesses. Putting
/// `raw_tool` here would let a consumer write a predicate that silently stops
/// firing on a host whose vocabulary differs, which is the exact defect
/// CLOUD-779 measured on the protected-write gate.
///
/// # The `facts` half is a PROJECTION of `facts.rs`, never a second vocabulary
///
/// CLOUD-834. Before it, this document was four envelope fields and the typed
/// fact model reached Rego nowhere: `ReceiptFacts`, `KeyFacts`, `StopFacts` and
/// the live waivers were resolved at the boundary, handed to the typed rule
/// table, and invisible to a module. Two fact surfaces that did not meet.
///
/// So the keys under `facts` are [`crate::facts::Fact::as_str`] and the match
/// below is **exhaustive with no wildcard arm**: an eighth variant fails to
/// compile here rather than silently going unprojected. That is the same
/// discipline `Fact::class` already uses one layer down, and the reason this is
/// a projection rather than a widening — re-deriving the vocabulary in JSON is
/// exactly the defect CLOUD-757 exists to prevent.
///
/// **Which facts appear is `Class`'s answer, not this function's.**
/// [`crate::facts::Surface::Hook`] is the predicate, and `Document` is the one
/// variant it excludes today — the model says it is not resolvable here. If that
/// classification changes this function follows it rather than being edited to
/// agree, which is what
/// `every_hook_resolvable_fact_is_projected_under_its_own_token` decides.
///
/// # It costs no resolution, and that is measured rather than argued
///
/// Every fact projected here was **already resolved** at the boundary for the
/// typed rule table before `adjudicate` was called. This function serializes
/// what it is handed; it acquires nothing, and a call no policy row selects for
/// never reaches it at all (see [`policy_rules`]'s early return). The published
/// `passthrough` figure sitting *below* `noop` is the property that protects,
/// and `tests/agent_facts.rs` asserts it by counter rather than by clock.
///
/// # Null is could-not-look, and the key is always present
///
/// A fact the boundary could not resolve projects as `null`, never as absent
/// and never as a falsy default: `Look::CouldNotLook` and "resolved to nothing"
/// are different answers, and collapsing them is CLOUD-251's vacuous pass. One
/// shape always — a document whose keys come and go is unparseable, and in Rego
/// `input.facts.receipts == null` and `not input.facts.receipts` are distinct
/// tests, which is what makes the distinction usable by a predicate.
///
/// # Rule 4 governs OUTPUT, not input
///
/// A module receiving these facts in-process is not egress: nothing prints
/// them, `Module` holds no `source` field, and findings stay pointer-only. The
/// `Field` allowlist next door is narrow for a reason that does not transfer —
/// it prints values to a shell, and into the agent's context window.
// ONE FUNCTION BECAUSE THE DOCUMENT IS ONE OBJECT. The length is the fact table
// plus the call fields, each carrying the reason it is projected or is not;
// splitting it would put half the input document's shape in another function and
// leave a reader assembling the answer from two places. The per-fact arms are
// the correspondence property `no_hook_fact_is_left_unprojected` asserts.
#[expect(
    clippy::too_many_lines,
    reason = "the projected document is one object, and each arm carries why that fact is or is not in it"
)]
fn call_document(envelope: &Envelope, facts: &Facts<'_>) -> Result<String, serde_json::Error> {
    let mut projected_facts = serde_json::Map::new();
    for fact in crate::facts::Fact::ALL {
        // EXHAUSTIVE, NO WILDCARD ARM. `None` means "the model does not make
        // this resolvable on the hook surface", and `no_hook_fact_is_left_
        // unprojected` asserts that reading against `Class` in both directions.
        // Each fact answers in its OWN arm, which is the property #620 built
        // here (CLOUD-834): a wildcard would let a new variant join the model
        // and go silently unprojected. Three of those arms now answer `None`
        // with three different reasons written above them, and collapsing them
        // into one pattern would delete exactly the reasons — so the lint is
        // expected here rather than obeyed.
        #[expect(
            clippy::match_same_arms,
            reason = "one arm per fact is the correspondence property; the shared `None` is a coincidence of three distinct reasons"
        )]
        let projected = match *fact {
            crate::facts::Fact::Bypass => Some(serde_json::Value::Bool(facts.bypass)),
            // BOTH non-answers project as `null`, which is what keeps this a
            // type substitution rather than a document change (CLOUD-787): the
            // previous `Option` spelling emitted `null` for could-not-look and
            // for nothing-judgeable alike, and the bytes here are unchanged. The
            // distinction is live in Rust, where the next call site is written;
            // giving Rego its own spelling of it is a widening of the policy
            // input and belongs to whichever row needs a predicate on it.
            crate::facts::Fact::Receipts => Some(match facts.receipts {
                crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                    serde_json::Value::Null
                }
                crate::facts::Look::Is(verdicts) => {
                    // The VERDICT's stable token, never the receipt statement:
                    // a receipt carries a subject commit and a recorded ref, and
                    // a predicate decides on `valid` / `stale-head` /
                    // `stale-main` / `missing` — which is the whole of what
                    // `receipt status` reports too.
                    let mut out = serde_json::Map::new();
                    for (check, validity) in verdicts {
                        out.insert(check.clone(), serde_json::Value::from(validity.as_str()));
                    }
                    serde_json::Value::Object(out)
                }
            }),
            // Same reading as `Receipts` one arm up, and the same unchanged bytes.
            crate::facts::Fact::Keys => Some(match facts.keys {
                crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                    serde_json::Value::Null
                }
                crate::facts::Look::Is(found) => serde_json::json!(found),
            }),
            crate::facts::Fact::Stop => Some(serde_json::json!(facts.stop)),
            crate::facts::Fact::Waived => Some(serde_json::json!(facts.waived)),
            // NAMES, SORTED, AND `null` FOR BOTH NON-ANSWERS (CLOUD-1028). The
            // set is a `BTreeSet`, so the projection is byte-stable across runs
            // without the sink having to sort it — the same property §6 wants
            // everywhere and the reason the resolver does not hand back a `Vec`.
            crate::facts::Fact::Pinned => Some(match facts.pinned {
                crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                    serde_json::Value::Null
                }
                crate::facts::Look::Is(programs) => serde_json::json!(programs),
            }),
            crate::facts::Fact::AgentSourced => Some(facts.sourced.as_ref().map_or(
                serde_json::Value::Null,
                |records| {
                    // WHAT THE AGENT RAN, not what it printed. `Sourced` is
                    // payload-free by construction — `rows` is a COUNT reduced
                    // at the boundary and no byte of the buffer is stored — so
                    // this projects the whole record without a rule 4 question.
                    let mut out = serde_json::Map::new();
                    for (check, record) in records {
                        out.insert(
                            check.clone(),
                            serde_json::json!({
                                "command": record.command,
                                "seen-at": record.seen_at,
                                "rows": record.rows,
                            }),
                        );
                    }
                    serde_json::Value::Object(out)
                },
            )),
            // THE SHAPE, NEVER THE TEXT, and this is where non-negotiable rule 4
            // is decided for CLOUD-758 rather than promised.
            //
            // The content itself reaches the typed predicate and stops there. A
            // policy module's `msg` is free-form text a consumer writes, so
            // content placed in the policy input is content that can be echoed
            // into a finding — and `Finding` having no field for a matched byte
            // would then be a property of the renderer rather than of the type.
            // `AgentSourced` is the precedent one arm up: it projects a command,
            // a timestamp and a COUNT, and no byte of the buffer it summarizes.
            //
            // What a rule can ask here is whether there is content, and how much
            // of it — enough to select, never enough to leak.
            crate::facts::Fact::Prospective => {
                let look = facts.prospective.as_str();
                Some(match facts.prospective {
                    crate::facts::Look::Is(content) => serde_json::json!({
                        "look": look,
                        "bytes": content.len(),
                        "lines": content.lines().count(),
                    }),
                    // `null` rather than absent, one level down: the fact-level
                    // invariant `a_fact_the_boundary_could_not_resolve_is_null_rather_than_absent`
                    // states is what lets a predicate tell "no answer" from an
                    // answer of zero, and a nested key that vanishes gives back
                    // exactly the `undefined` that invariant refuses.
                    crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                        serde_json::json!({
                            "look": look,
                            "bytes": serde_json::Value::Null,
                            "lines": serde_json::Value::Null,
                        })
                    }
                })
            }
            // Not resolvable on the mediated call, per `facts.rs`'s own table:
            // `Document` parses a file of unbounded size, so its cost is
            // unbounded in the input where a git ref read is not. Stated as an
            // arm rather than a wildcard so a reclassification has to come
            // through here.
            //
            // **AND IT STAYS `None` — CLOUD-856 decided that rather than
            // inheriting it.** That row weighed widening this arm against moving
            // the acquisition, and moved it: `Fact::Tasks` above carries the one
            // predicate that genuinely needed a manifest here, from a receipt
            // minted at session start where a read of that size is admissible.
            // So the family that was blocked on this arm is unblocked WITHOUT it
            // changing, and a future row proposing to widen it is proposing to
            // put an unbounded parse back on the hot path.
            crate::facts::Fact::Document => None,
            // Not resolvable on the mediated call either, and for the same
            // reason one axis up: a walk of the working tree is unbounded in the
            // size of the repository where a git ref read is not (CLOUD-845).
            // `check` may hold it because `check` is bounded by the repository it
            // is pointed at and says so; a 100ms-per-call budget cannot be.
            //
            // This arm is what the compiler demanded when `Fact::Tracked`
            // landed, which is the property working: a new fact cannot join the
            // model and go silently unprojected here.
            crate::facts::Fact::Tracked => None,
            // Not resolvable on the mediated call, and stated rather than
            // wildcarded so a reclassification must come through here: reading a
            // file of unbounded size is unbounded in the input exactly as
            // parsing one is, and the 100ms budget is per call (CLOUD-846).
            crate::facts::Fact::Lines => None,
            // Not resolvable on the mediated call, for `Document`'s reason plus
            // one this family adds (CLOUD-1167): it opens and parses a file of
            // unbounded size, AND the file lives outside the repository, so the
            // per-call budget bounds neither the read nor where it reaches. A
            // hook body that wants to read a launcher's configuration file is
            // exactly the shape CLOUD-689's budget exists to refuse. Stated as an
            // arm rather than a wildcard so a reclassification has to come
            // through here.
            crate::facts::Fact::External => None,
            // Not resolvable on the mediated call, and the strongest case of the
            // three above: this PARSES a file of unbounded size where `Lines`
            // only reads one, so it is unbounded in the input twice over
            // (CLOUD-914). A call site is a property of committed source, which
            // is the tree surface's question, and the mediated path has no
            // budget for a syntax tree.
            crate::facts::Fact::Invocations => None,
            // Not resolvable on the mediated call, for `Invocations`' reason and
            // one more: a `use` graph is a property of the WHOLE crate, resolved
            // against the root's table across every declared file, so it is
            // unbounded in the tree rather than in one file (CLOUD-762).
            crate::facts::Fact::Uses => None,
            // Not resolvable on the mediated call, same axis and same reason
            // (CLOUD-851): the sink store is read for every key the RULESET
            // declares, and that count is unbounded in the ruleset where a single
            // named record is not. A hook-resolvable read of one named key is a
            // narrower fact than this one, and inventing it here rather than
            // stating this arm is how a surface classification gets decided by
            // whoever needed it first.
            crate::facts::Fact::Produced => None,
            // THE GIT FAMILY IS TREE-SURFACE IN THIS BUILD (CLOUD-907), and the
            // five arms are stated separately because they answer `None` for two
            // different reasons.
            //
            // `status` walks the working tree and a range grows with history, so
            // both are unbounded against a per-call budget and belong here for
            // `Document`'s reason one arm up.
            // `Landing` joins these two rather than the cheap three below, and it
            // is the clearest case of the three groups: a landing scan computes a
            // patch id per head-side commit, so its cost is the branch's length
            // and no declaration bounds that. Unbounded against a per-call budget
            // is exactly what puts a fact here (CLOUD-880).
            // `CommitMeta` joins these three, and is the strongest case of the
            // four: it peels a commit OBJECT per commit where `GitRange` reads a
            // subject, over a range no declaration bounds (CLOUD-1187).
            crate::facts::Fact::GitStatus
            | crate::facts::Fact::GitRange
            | crate::facts::Fact::CommitMeta
            | crate::facts::Fact::Landing
            // CLOUD-1203. `Staged` reads a blob of unbounded size off the index,
            // which is `Document`'s bound one side over; `State` reads every
            // record the store holds, which is a listing whose size is the
            // repository's history of findings. Neither fits a per-call budget,
            // and neither has a question to answer about a command.
            // CLOUD-1200. A history walk over an unbounded number of commits,
            // two tree lookups each — the least affordable read in the family
            // against a per-call budget.
            | crate::facts::Fact::GitHistory
            | crate::facts::Fact::Staged
            | crate::facts::Fact::State
            // CLOUD-1154: a mediated call has no SHA to ask about, and reading a
            // record set per call is a cost the budget does not have.
            | crate::facts::Fact::Forge
            // CLOUD-1424. A directory listing plus a file read and a `stat` per
            // entry — more than the one ref read that puts a fact in the cheap
            // group below, and bounded by how many worktrees exist rather than by
            // anything a row declares. Its subject is the checkout's own hygiene,
            // which is a gate's question and not a question about a command.
            | crate::facts::Fact::GitWorktrees => None,
            // The other three are cheap enough for this path — one ref read
            // each, under what `Receipts` already spends — and are absent anyway,
            // because NOTHING ON THIS PATH RESOLVES THEM. `facts.rs` classifies
            // them `Surface::Check` for exactly that: a fact whose class admits
            // the hook while the boundary never fills it is a schema key
            // `opa check -s` types green over a path that is undefined forever,
            // which is CLOUD-845's defect. The census says no mediated-call
            // consumer exists — all 22 gate tasks owing a git fact are tree
            // programs — and the day one does, the reclassification arrives with
            // the narrowing that makes it honest.
            crate::facts::Fact::GitHead
            | crate::facts::Fact::GitRemote
            | crate::facts::Fact::GitRef => None,
            // `Cost::Effect` (CLOUD-760), and the ONLY fact whose absence here is
            // a refusal rather than a classification. Resolving it runs an
            // analyser over the whole crate; a mediated call has a per-call
            // budget measured in milliseconds, and `run_static` already refuses a
            // spawning kind on this surface. `facts.rs` classifies it
            // `Surface::Check` so this arm is `None` by the model rather than by
            // this function's opinion — and `no_effect_fact_is_hook_resolvable`
            // is the assertion that keeps the two agreeing.
            crate::facts::Fact::Symbols => None,
            // Two unbounded walks — the base tree and the working tree — so this
            // sits with `GitStatus` above rather than with the cheap three, and
            // for a sharper version of the same reason (CLOUD-1059). Its
            // declaration bounds WHICH paths are reported and not what answering
            // costs: a glob is a selection over the whole tree either way. The
            // consumer is a migration gate, which is a `batten check` run by
            // construction, so no mediated-call consumer is being turned away.
            crate::facts::Fact::BaseDelta => None,
            // CLOUD-1051, and it sits with the two above rather than with the
            // cheap three for a reason that is about its CONSUMER rather than
            // its price. One branch-keyed file is what `Receipts` already spends,
            // so the hook could hold it. The gate that reads it decides at
            // landing and needs the branch's whole diff beside it — which is
            // `BaseDelta`, unbounded and `check`-only — so projecting this here
            // would put half a predicate within reach of a surface where the
            // other half can never follow. `facts.rs` carries the argument.
            crate::facts::Fact::Records => None,
            // CLOUD-1126. `Surface::Check` beside `Records`, and for the sharper
            // reason: this channel is WRITTEN on the mediated path — `append_all`
            // is what observes a selected call failing to answer — so projecting
            // it here would offer a hook predicate the store the same call is
            // still filling.
            crate::facts::Fact::RecordsBlocked => None,
            // CLOUD-1171. `Surface::Check` in `facts.rs`, so this arm is `None`
            // by the model rather than by this function's opinion — and the
            // reason it is classified there is the digest: answering means
            // opening the declared input and hashing it, per declared row, which
            // is a `check`-surface cost and not a mediated call's. A gate
            // adjudicating a validator is a `batten check` run by construction,
            // so no mediated-call consumer is being turned away.
            crate::facts::Fact::ToolVerdict => None,
            crate::facts::Fact::Minted => None,
            // The dispatch tier is `Surface::Check` (CLOUD-472): `run_static`
            // refuses a spawning kind on the mediated path, so a projection here
            // would offer a module a key the hook surface can never fill.
            crate::facts::Fact::Review => None,
            // CLOUD-1188. `Surface::Check` in `facts.rs`, so this arm is `None`
            // by the model rather than by this function's opinion. Answering
            // means reading and parsing the capture store until a declared key
            // matches, which is a tree-surface cost — and every consumer this
            // family exists for is a board gate, which is a `batten check` run.
            crate::facts::Fact::Captured => None,
            // CLOUD-1170, and its `None` is a statement about the QUESTION
            // rather than about a price. An instant costs nothing to project —
            // it is an integer the caller already handed in, `Cost::Free`, so
            // the budget argument every arm above makes does not apply here at
            // all. What is missing is a consumer: a lease is decided at a gate,
            // and a mediated call has no lease to ask about. Projecting it here
            // would put a schema key on the mediated document that `opa check
            // -s` types green while nothing on this path ever reads it, which is
            // CLOUD-845's defect written deliberately.
            crate::facts::Fact::Instant => None,
            // CLOUD-856, and the arm `Fact::Document` could never be. The record
            // is already resolved at the boundary, so projecting it costs
            // nothing here — which is what `Document` cannot say, and why that
            // arm stays `None` beside this one.
            // NULL FOR BOTH NON-ANSWERS, matching `Pinned` above and for its
            // invariant: the key is always present, because a key that comes and
            // goes cannot be written against at all — `not input.call.tasks` is
            // indistinguishable from a predicate that simply does not hold.
            // CLOUD-1172. NULL FOR EVERY NON-ANSWER, and there are four of them
            // — no transcript on the envelope, a host that keeps none, one that
            // would not parse, and nobody having declared an extractor. All four
            // are could-not-look, and every one of them is DIFFERENT from an
            // extractor that ran and counted zero, which is a real answer and
            // reaches a module as `0`.
            crate::facts::Fact::Extracted => Some(match facts.extracted {
                crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                    serde_json::Value::Null
                }
                crate::facts::Look::Is(counts) => serde_json::json!(counts),
            }),
            crate::facts::Fact::Tasks => Some(match facts.tasks {
                crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                    serde_json::Value::Null
                }
                crate::facts::Look::Is(tasks) => serde_json::json!(tasks),
            }),
        };
        if let Some(value) = projected {
            projected_facts.insert(fact.as_str().to_owned(), value);
        }
    }
    serde_json::to_string(&serde_json::json!({
        "call": {
            "event": envelope.event.as_str(),
            "operation": envelope.operation.as_str(),
            "command": envelope.command,
            "writes": envelope.writes,
            // THE TWO STOP PROJECTIONS (CLOUD-1051). Both are `null` on every
            // other event, because no other event carries them — which is the
            // three-valued read the whole fact model takes: a module asking at
            // `pre-tool` gets undefined, and Rego reads undefined as *does not
            // hold*, so a Stop predicate cannot silently fire on a tool call.
            //
            // They are CALL fields rather than facts, and the line is the one
            // this object's own description draws: a fact is resolved ABOUT the
            // call, these are what the harness handed the boundary. The final
            // message is the turn's own text and the transcript path is where
            // the host put the session — neither is looked up, both arrive.
            //
            // POINTER, NOT PAYLOAD, for the transcript: the PATH travels, never
            // a byte of what is in it. A module that wants the contents asks for
            // a fact the engine resolves, which is what keeps the reading
            // bounded and the projection cheap.
            "final-message": envelope.last_message,
            "transcript": envelope.transcript,
            // A FACT ABOUT THE CALL, NOT ABOUT THE COMMAND (CLOUD-613).
            //
            // The same class `segments` below is: something the engine already
            // reads and typed rows already select on — `Field::RunInBackground`
            // — that no module could see. `run-shape-guard`'s two sleep families
            // are the consumers, and the reason they stayed bash was this key's
            // absence rather than anything about the predicate: a foreground
            // `sleep` throws away the SESSION, while a backgrounded one wrapped
            // in `until`/`while` is the prescribed wait, and telling those apart
            // needs a property of the CALL that the command string does not
            // carry.
            //
            // BOTH SPELLINGS, resolved at the boundary. Hosts disagree here the
            // same way they do over `tool_response`/`toolResponse`, and a module
            // must not have to know which host it is behind — `Field` already
            // reads either, so this projects that answer rather than the raw key.
            //
            // `null` where the host said nothing, which Rego reads as *does not
            // hold*: an absent flag is not a false one, and a predicate about
            // backgrounding must not fire on a call whose host never spoke.
            "run-in-background": Field::RunInBackground
                .read(envelope)
                .and_then(|text| text.parse::<bool>().ok()),
            // THE SEGMENTATION THE ENGINE ALREADY COMPUTES (CLOUD-857).
            //
            // `command` above is the line EXACTLY as written, and for two years
            // that was the only spelling a module had. So every module anchoring
            // on a program wrote `split(input.call.command, " ")[0] == "git"` —
            // which asks about the first word of the whole LINE. Measured on the
            // vendored presets: `git push --force origin main` denies, and
            // `cd /tmp && git push --force origin main` is allowed. Real agent
            // commands are compound most of the time, so the deny was the rare
            // case and the silence was the common one.
            //
            // `segments` is the same parser `shape` and `pipeline` rows are
            // decided by (CLOUD-269 made it quote-aware, CLOUD-443 gave it the
            // terminator), and it is a pure function of a string already in this
            // document — `Cost::Free`, no new I/O, no fact class. Projecting it
            // makes the CORRECT predicate the short one:
            //
            //     some segment in input.call.segments
            //     segment.words[0] == "git"
            //
            // ONE PARSER, WHICH IS THE WHOLE POINT (CLOUD-857 §1). The
            // alternative was ~60 lines of core-builtin string work per module —
            // a list split, a pipe-stage split and a quoted-span scrub — because
            // this build of regorus carries no `regex` builtins. CLOUD-843's
            // wave 1 copies this template ~80 times, so that is 80 re-derivations
            // of a parser this repository already has and keeps refusing to grow
            // a second of.
            //
            // RULE 4 IS UNAFFECTED, and the row says so: `command` already
            // carries the text, so segmenting it exposes nothing new. A decoder
            // is not a verdict. What a FINDING may report is unchanged — a
            // predicate id and a pointer, never a span.
            "segments": segments(&envelope.command)
                .iter()
                .map(|segment| {
                    serde_json::json!({
                        "words": segment.words,
                        "raw": segment.raw,
                        // The operator that FOLLOWED this span, spelled as the
                        // shell spells it so a module reads what an author
                        // wrote. `null` where the command ended, which Rego
                        // reads as *does not hold* rather than as a value.
                        "terminator": segment.terminator.map(Separator::as_str),
                        // WHETHER THIS SPAN BINDS STDIN (CLOUD-613). A boolean
                        // and not the redirection's text, because the predicate
                        // it exists for is "did anything reach git's stdin
                        // HERE" — and a heredoc opener present in the command
                        // string says nothing about which element got it.
                        "input-redirect": segment.input_redirect,
                    })
                })
                .collect::<Vec<_>>(),
            // WHAT EACH SEGMENT ACTUALLY RUNS, AND WHETHER THE PIN SELECTED IT
            // (CLOUD-1028). One entry per segment, so a bare program in the
            // second half of a pipeline is as visible as one in the first.
            //
            // The boundary answers `mediated` rather than handing over the
            // tokens before the program, and that is the whole point: deciding
            // it in Rego would be a second implementation of `effective_program`
            // and `mediator_present` — the wrapper look-through, the env
            // assignments, `mise x` as well as `mise exec` — and a second
            // authority over an argv reading this engine already owns. A module
            // asks whether the program is one the pin provides; it does not
            // re-parse the command to find out what the program was.
            "programs": program_reach(&envelope.command),
            // THE RECURSION BOUND, PROJECTED RATHER THAN ENFORCED HERE. The host
            // sets it false on the first Stop of a turn and true on the one a
            // previous Stop caused, so a module that does not read it nudges
            // forever. Left to the module deliberately: which rules are bounded
            // by it is a policy question, and the engine deciding for every
            // module would be the engine holding a rule it cannot state.
            "stop-repeat": envelope.stop_active,
        },
        "facts": projected_facts,
    }))
}

/// The program a token names, with any path it was reached through dropped.
///
/// Deliberately not a filesystem question: this is the last `/`-separated
/// component of the token as written, which is what a caller means by "which
/// program". Canonicalising the path instead would make the answer depend on a
/// checkout the boundary may not have, and on a symlink target that says which
/// binary it is rather than which program was asked for.
fn program_name(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// Each segment's effective program, and whether the pin selected it
/// (CLOUD-1028).
///
/// A segment with no program at all — a bare redirection, an empty span — yields
/// nothing rather than a null entry: the list is the programs this call runs,
/// and a caller iterating it should not have to skip holes.
///
/// `RequireVia::Mise` is named because it is the only variant the model carries.
/// The day a second mediator exists this becomes a set and the key becomes a
/// name rather than a boolean; spelling it now would be a vocabulary with one
/// member and no consumer.
fn program_reach(command: &str) -> Vec<serde_json::Value> {
    segments(command)
        .iter()
        .filter_map(|segment| {
            let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
            let index = effective_program(&tokens)?;
            let program = program_token(tokens[index]);
            Some(serde_json::json!({
                "program": program,
                // THE NAME AS WELL AS THE TOKEN, because they are different
                // questions and a predicate about "which program is this" wants
                // the second. `./tests/bats/bin/bats` and `bats` are one program
                // reached two ways; a module comparing the token would answer no
                // for the spelling that produced the incident this exists for.
                //
                // Resolved here rather than in Rego for the reason the whole
                // projection exists: path splitting is argv reading, and a module
                // doing it would be a second authority over it.
                "name": program_name(program),
                // WHAT THIS PROGRAM WAS HANDED, so a module can anchor on the
                // program AND read its own argv without a join (CLOUD-1382).
                //
                // Without it a module correlating `programs` back to `segments`
                // has nothing to correlate ON: the list above is `filter_map`ed,
                // so a segment with no program yields no entry and the two
                // indices stop agreeing. The alternative was for every module to
                // re-find the program inside a segment's words, which is the
                // second authority over one argv that CLOUD-857 measured and
                // this whole projection exists to refuse.
                // NORMALISED THE SAME WAY THE PROGRAM IS, and for the same
                // measured reason: the closing paren of a grouped command lands
                // on the LAST argument, which is exactly the token an exact-match
                // predicate is decided on. `(git push origin main --force)` was
                // allowed with `--force)` here while the same flag written
                // earlier denied.
                "arguments": tokens[index + 1..]
                    .iter()
                    .map(|token| program_token(token))
                    .collect::<Vec<_>>(),
                "mediated": mediator_present(
                    crate::rules::RequireVia::Mise,
                    &tokens[..index],
                ),
            }))
        })
        .collect()
}

/// Whether the work this call belongs to names a tracker key (CLOUD-446).
///
/// Three sources, and the order is cheapest-first rather than
/// most-authoritative-first: the command as written, then the boundary's
/// evidence. A key typed into the call — `--body "… KEY-1 …"` — answers without
/// the checkout being consulted at all.
///
/// Evidence that is not [`Look::Is`](crate::facts::Look::Is) allows, and both
/// non-answers do. Outside a checkout, on a detached HEAD, or against a `base`
/// git cannot resolve, this predicate has no answer
/// ([`Look::CouldNotLook`](crate::facts::Look::CouldNotLook)), and a hook that
/// refuses where it cannot look is a hook that has become the reason work cannot
/// proceed. Where no `requires_key` row selected the command there was no
/// question ([`Look::IsNot`](crate::facts::Look::IsNot)). Same posture as
/// [`ReceiptFacts`].
///
/// An expression that will not compile also allows, and cannot be reached from a
/// config that loaded: [`crate::rules::Rule::validate`] compiles it first, so this
/// arm is the fail-open reading of an impossible state rather than a second
/// policy.
fn key_present(expression: &str, command: &str, keys: &KeyFacts) -> bool {
    let Ok(pattern) = regex::Regex::new(expression) else {
        return true;
    };
    if pattern.is_match(command) {
        return true;
    }
    let crate::facts::Look::Is(evidence) = keys else {
        return true;
    };
    evidence.iter().any(|text| pattern.is_match(text))
}

/// Every shape row this command matches, in declaration order within each
/// segment.
///
/// Split out of [`shape_rules`] for [`matching_receipt_rows`]'s reason: the
/// boundary has to know whether a `requires_key` row will fire *before* it
/// decides whether to spend two git queries resolving the evidence, and the two
/// answering separately is how a call comes to pay for a lookup no rule would
/// have consulted (CLOUD-460).
///
/// TAKES THE ENVELOPE, AND APPLIES THE MODIFIERS ITSELF. It held only the
/// command string, so [`shape_rules`] applied [`modifier_admits`] after the call
/// and [`Policy::key_base_for`] — the other caller — did not. Two callers of one
/// selector disagreeing about which rows fire is the defect `modifier_admits`
/// exists to prevent, and this is the fourth place it has surfaced: the
/// narrowing was added at three call sites in turn, each time leaving the next
/// one out. Putting it INSIDE the selector is what closes the class rather than
/// the instance, because a future caller cannot forget what it never had to
/// remember.
///
/// The cost of the omission was not hypothetical. `key_base_for` returns the
/// `base` of the first `requires_key` row it matches, so an earlier row excluded
/// by its own modifier supplied the commit range that a later, admitted row was
/// then judged against — wrong key evidence, from a row that was not even
/// supposed to fire.
fn matching_shape_rows<'a>(policy: &'a Policy, envelope: &Envelope) -> Vec<&'a Rule> {
    let mut matched: Vec<&Rule> = Vec::new();
    for segment in segments(&envelope.command) {
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
            // The polarity modifiers (CLOUD-987), applied HERE so every caller
            // gets them. See this function's header for why the check moved in
            // from `shape_rules` rather than being copied to the second caller.
            //
            // Both halves observed red, one mutation at a time (CLOUD-418):
            // commenting this out reds `a_keyed_row_excluded_by_its_modifier_
            // does_not_supply_the_base` AND the earlier round's
            // `a_command_keyed_row_honours_the_polarity_modifier`.
            if !modifier_admits(rule, envelope) {
                continue;
            }
            let Some((program, wanted)) = rule.shape() else {
                continue;
            };
            if tokens[program_index] != program {
                continue;
            }
            if !operands_match(&words, &wanted) {
                continue;
            }
            // The mediator, read from the segment AS WRITTEN (CLOUD-271). This
            // is the one place the sanctioned route and the bare one still
            // differ: `effective_program` has already looked through
            // `mise exec`, so by here both have resolved to the same program.
            // Present means the row does not fire — the objection is to the
            // toolchain selection, not to the program.
            if let Some(via) = rule.require_via()
                && mediator_present(via, &tokens[..program_index])
            {
                continue;
            }
            // The extra literal is matched against the segment as written,
            // because the thing it looks for lives inside a quoted argument and
            // so is not one of the words above.
            if let Some(needle) = rule.contains.as_deref()
                && !segment.raw.contains(needle)
            {
                continue;
            }
            matched.push(rule);
        }
    }
    matched
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
/// One resolved write target: the action that reaches for it, and the row that
/// declared that action mutating.
///
/// The declared remedy travels with the target rather than being looked up again
/// at the deny site, because since CLOUD-442 a program can carry more than one
/// row and only the one that *qualified* holds the right redirect. `subcommand`
/// is carried separately so the refusal can name the whole action (`<program>
/// <subcommand>`) while nothing is allocated on the allow path.
///
/// `redirect` is an `Option` rather than the row itself because since CLOUD-779
/// the `[[verb]]` row is **message composition, not the predicate**: a write
/// arriving under a host spelling the consumer never declared still fires the
/// gate, and simply has no verb-level remedy to offer. `redirect::resolve`'s
/// per-path tier answers first in any case, and `Fix::None` is the honest floor.
struct Target<'a> {
    program: &'a str,
    subcommand: Option<&'a str>,
    path: &'a str,
    redirect: Option<&'a str>,
}
/// Where in the gate chain the protected-path predicate is being asked.
///
/// **Two positions, one implementation, and the split is deliberate** — it is
/// what lets a Cursor `beforeShellExecution` reach the same gate a Claude Code
/// `Write` does without overturning a precedence this crate already decided.
///
/// * [`WriteStage::ToolNamed`] runs before the write-triggered receipt gate, so
///   "a ban outranks an unmet precondition" holds for a tool-named write.
/// * [`WriteStage::CommandParsed`] runs after the explicit `[[rule]]` rows, so
///   "a row a reviewer wrote by hand is the one they see quoted back" holds for a
///   shell command.
///
/// A deny at the first position returns immediately, so an [`Operation::Other`]
/// call — which is asked at both, because *could not look* must not be read as
/// *harmless* — can never be judged twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStage {
    /// The tool named its own target: [`Envelope::writes`].
    ToolNamed,
    /// The targets are inside the shell command text.
    CommandParsed,
}

impl Operation {
    /// Whether a call doing this can name a write target through `stage`.
    ///
    /// The three-valued reading lives here and nowhere else (CLOUD-757): a
    /// classified operation answers for exactly the source it uses, and
    /// [`Operation::Other`] answers `true` at **both** — an adapter that could not
    /// classify the tool has told us nothing about what the call touches, and
    /// reading that silence as "not a write" is the vacuous pass this whole issue
    /// is about. The cost of asking anyway is one lookup that finds no target.
    const fn names_targets_through(&self, stage: WriteStage) -> bool {
        match (self, stage) {
            (Operation::Write, WriteStage::ToolNamed)
            | (Operation::Execute, WriteStage::CommandParsed)
            | (Operation::Other(_), _) => true,
            (Operation::Write, WriteStage::CommandParsed)
            | (Operation::Execute, WriteStage::ToolNamed)
            | (Operation::Read | Operation::Mcp | Operation::Subagent, _) => false,
        }
    }
}

/// The derived protected-path gate: `{a write target} × {path ∈ protected}`.
///
/// One predicate over whichever source the call's [`Operation`] says names its
/// targets, so the question "does this call write a protected path" has a single
/// implementation rather than one per shape of call (CLOUD-779). What varies per
/// stage is only *where the targets are read from*, never what makes them refused.
fn protected_write(policy: &Policy, envelope: &Envelope, stage: WriteStage) -> Decision {
    if !envelope.operation.names_targets_through(stage) {
        return Decision::Allow;
    }
    match stage {
        WriteStage::ToolNamed => protected_tool_write(policy, envelope),
        WriteStage::CommandParsed => protected_mutation(policy, &envelope.command),
    }
}

/// Refuse a generic read of a path whose class declares the tool that answers it
/// (CLOUD-1258).
///
/// # What made this reachable by nothing
///
/// `no-tool-substitution` is `kind = "pipeline"` and decides over shell argv, so
/// a structured-tool call is invisible to it. `protected` crossed with
/// `[[verb]]` enumerates mutations, and CLOUD-442's port states "reads stay
/// allowed" — correct for the question that row answered, and the reason nobody
/// had asked whether a read through the wrong instrument matters. This is the
/// third face of the object CLOUD-185 and CLOUD-864 closed the other two of.
///
/// # `protected` is NOT consulted, and that is the design
///
/// The question here is "which instrument answers this path", not "is this path
/// guarded" — two different sets, and deriving one from the other is the
/// collapse CLOUD-37 exists to prevent. `[[redirect]]` already answers the first
/// for mutations, so the read remedy belongs beside it and a class with no
/// declared `read` is refused nothing.
///
/// # Pointer-only, and here that is the whole of the output
///
/// The path and the declared remedy. Never a byte of the file, which for a
/// memory is exactly the content a read gate must not become a mirror of.
fn redirected_read(policy: &Policy, envelope: &Envelope) -> Decision {
    let Some(path) = envelope.reads.as_deref() else {
        return Decision::Allow;
    };
    let Some(remedy) = crate::redirect::resolve_read(&policy.redirects, normalise(path)) else {
        return Decision::Allow;
    };
    Decision::Deny(Refusal::declared(
        PROTECTED_MUTATION,
        crate::verdict::Native::ToolSubstituted,
        &[
            crate::verdict::Subject::Path {
                path: path.to_owned(),
            },
            crate::verdict::Subject::Artifact {
                artifact: envelope.raw_tool.clone(),
            },
        ],
        Fix::Run(remedy.to_owned()),
    ))
}

/// The tool-named half: the adapter already resolved the target, so this is the
/// protected-set lookup and the refusal.
///
/// The target comes from [`Envelope::writes`], which the adapter derives from
/// [`Harness::write_tools`] — a **per-host** table, so it is already the neutral
/// fact the old `verbs::classify(raw_tool)` was failing to reconstruct from a
/// consumer's config. The `[[verb]]` row is consulted only for its remedy text,
/// and its absence costs a more specific sentence rather than the whole gate.
fn protected_tool_write(policy: &Policy, envelope: &Envelope) -> Decision {
    let Some(path) = envelope.writes.as_deref() else {
        return Decision::Allow;
    };
    // Through `protects` like every other reader (CLOUD-1236). The envelope's
    // target is already relativised upstream by `relativise_writes`, so this
    // changes no verdict here — which is the point: the two readers can no longer
    // drift apart, and a future call site that forgets the upstream step is
    // covered rather than silently open.
    if !protects(policy, path) {
        return Decision::Allow;
    }
    // Looked up by program alone, and since CLOUD-442 that is a decision rather
    // than an omission: `verbs::classify` is `qualify` over no arguments, so a row
    // whose mutation is qualified by a flag or a subcommand cannot match here. A
    // write tool names one path and no argv, so there is nothing a qualifier could
    // be satisfied by. Under CLOUD-779 a miss no longer suppresses the deny — it
    // only means this host's spelling carries no verb-level remedy.
    let redirect = crate::verbs::classify(&policy.verbs, &envelope.raw_tool)
        .and_then(|verb| verb.redirect.as_deref());
    Decision::Deny(protected_refusal(
        &policy.redirects,
        &Target {
            program: &envelope.raw_tool,
            subcommand: None,
            path,
            redirect,
        },
    ))
}

/// One segment's words, split where the caller wrote a NEWLINE (CLOUD-1287).
///
/// # The defect
///
/// A newline is whitespace to [`segments`], so a script written across lines is
/// one segment and `effective_program` resolves the FIRST line's program for the
/// whole thing. Measured over the shipped binary, one protected path and two
/// spellings of the same read: `stat -c %s batten.toml` allowed, and the
/// identical `stat` written on line two after `cd /tmp` REFUSED, naming `cd` —
/// so a declared `protected_readers` entry is unreachable from any script, which
/// is the surface `protected_readers` exists for.
///
/// That also makes `.claude/rules/policy-modules.md`'s "it under-denies, which
/// is the sanctioned direction" measurably backwards for this arm: it
/// OVER-denies, on a read, which is the direction that gets a guard switched
/// off. The prose is corrected in the same change.
///
/// # NARROW ON PURPOSE, and this is the whole of the narrowing
///
/// Segment identity is untouched: promoting a newline to a separator in
/// [`segments`] would change every landed `pipeline` verdict, and `terminator`
/// is what those rows are decided by. Only the two arms below — the mutation
/// walk and the unknown-program walk — stop at a line, because both are asking
/// "which program was handed this operand", a question a line answers and a
/// segment does not.
///
/// # There is still ONE parser
///
/// Each line goes back through [`segments`] rather than through a `split` of any
/// kind. A second tokenizer here is a second AUTHORITY (CLOUD-857), and it would
/// disagree with the one `shape` and `pipeline` rows are decided by over exactly
/// the quoting cases neither author had in mind. Re-entering is safe because a
/// segment's `raw` carries no separator by construction — it is what the parser
/// split ON — so each line yields at most one sub-segment.
///
/// Heredoc bodies are already gone from `raw`, which is what keeps a `rm` inside
/// a commit message from becoming a line of its own here (CLOUD-723).
fn line_bounded_words(segment: &Segment) -> Vec<Vec<String>> {
    // The common case is one line, and it must cost nothing: `batten hook` runs
    // on every mediated call under CLOUD-689's budget.
    if !segment.raw.contains('\n') {
        return vec![segment.words.clone()];
    }
    joined_lines(&segment.raw)
        .into_iter()
        .flat_map(|line| segments(&line).into_iter().map(|parsed| parsed.words))
        .filter(|words| !words.is_empty())
        .collect()
}

/// `raw`'s lines, with a BACKSLASH CONTINUATION joined back to the line it
/// continues.
///
/// **This is the one shape where a newline is not a boundary**, and getting it
/// wrong is a bypass rather than a false refusal: `rm \` then the path on the
/// next line is ONE command to bash, and splitting it hands line one an `rm`
/// with no operands and line two an operand with no program — so the protected
/// path is judged by nothing and the write is allowed. Caught in review of the
/// change that introduced the split, before it could be measured in the field.
///
/// An ODD number of trailing backslashes continues; an even number is escaped
/// backslashes and the line ends. `rm a\\` writes a literal backslash and is a
/// complete command, so counting rather than testing the last character is what
/// keeps that from continuing into the next line.
fn joined_lines(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for line in raw.lines() {
        let trailing = line.chars().rev().take_while(|c| *c == '\\').count();
        let continues = trailing % 2 == 1;
        // The continuation backslash is shell syntax, not an operand, so it is
        // dropped rather than carried into the token list where it would read as
        // a word.
        let body = if continues {
            &line[..line.len() - 1]
        } else {
            line
        };
        let mut current = pending.take().unwrap_or_default();
        current.push_str(body);
        if continues {
            pending = Some(current);
        } else {
            out.push(current);
        }
    }
    // A trailing continuation with nothing after it: keep what was collected
    // rather than dropping the line, which would lose its operands entirely.
    if let Some(last) = pending {
        out.push(last);
    }
    out
}

fn protected_mutation(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        for words in line_bounded_words(&segment) {
            let tokens: Vec<&str> = words.iter().map(String::as_str).collect();
            // Operands of the effective program, plus any redirect target. Both are
            // candidates; a redirect needs no program at all.
            let mut candidates: Vec<Target<'_>> = Vec::new();
            if let Some(index) = effective_program(&tokens) {
                // The PROGRAM rather than the token, so `(rm` is `rm` here as it
                // is in `programs` (CLOUD-1382). One identity, resolved once.
                let program = program_token(tokens[index]);
                // The row is resolved ONCE per segment, from the program and its
                // arguments together (CLOUD-442). Before this the lookup was by
                // program alone, so a program that mutates under one subcommand or
                // behind one flag could only be declared as mutating under all of
                // them — which is why five write shapes could not be expressed.
                if let Some(matched) =
                    crate::verbs::qualify(&policy.verbs, program, &tokens[index + 1..])
                {
                    // The OPERANDS as the program was handed them, with a
                    // group's closing punctuation off (CLOUD-1382): measured,
                    // `(rm batten.toml)` was allowed because the operand read
                    // `batten.toml)` and no protected path matches that, while
                    // `rm batten.toml` and `time rm batten.toml` both refuse.
                    let operands: Vec<&str> = operands(&tokens, index + 1 + matched.consumed)
                        .into_iter()
                        .map(program_token)
                        .collect();
                    // `Last` is the destination-only narrowing. An empty operand
                    // list has no last element and therefore no target, which is the
                    // same answer as before for a program invoked with none.
                    let targets: &[&str] = match matched.operands {
                        OperandScope::All => &operands,
                        OperandScope::Last => operands.last().map_or(&[], std::slice::from_ref),
                    };
                    for path in targets {
                        candidates.push(Target {
                            program,
                            subcommand: matched.verb.subcommand.as_deref(),
                            path,
                            redirect: matched.verb.redirect.as_deref(),
                        });
                    }
                }
            }
            // A redirect is a pseudo-program with no argv of its own, so it carries
            // no qualifier and is looked up by name.
            for (operator, path) in redirect_targets(&tokens) {
                if let Some(verb) = crate::verbs::classify(&policy.verbs, operator) {
                    candidates.push(Target {
                        program: operator,
                        subcommand: None,
                        path,
                        redirect: verb.redirect.as_deref(),
                    });
                }
            }

            for target in candidates {
                if !protects(policy, target.path) {
                    continue;
                }
                return Decision::Deny(protected_refusal(&policy.redirects, &target));
            }

            // THE UNKNOWN PROGRAM, WHICH USED TO FALL THROUGH TO ALLOW (CLOUD-1141).
            //
            // Everything above decides by NAMING the program: `verbs` enumerates
            // mutations, so a program it does not name produced no candidate and the
            // loop ended here allowing. Measured over the shipped binary, one
            // protected path and five spellings of writing it: `echo x >>`, `sed -i`
            // and `tee` denied; `python3 -c "open(...,'w')"` and `perl -pi -e`
            // ALLOWED. An allowlist-by-omission whose omissions are holes, and the
            // gate `memory-guard` was retired into (CLOUD-442).
            //
            // The direction is now inverted rather than the list extended. Adding the
            // measured interpreters would close two instances and leave the shape —
            // the next one is unrefused and the table would imply a completeness it
            // does not have. So an operand that is a protected path refuses unless
            // the program is KNOWN, and known means one of two things:
            //
            //   * it appears in `verbs` at all — the table encodes that program's
            //     argv grammar, so a non-matching invocation is a considered allow
            //     rather than an absence. `git add batten.toml` stays allowed because
            //     `git`'s mutating rows did not match, not because nobody looked.
            //   * it appears in `protected_readers` — declared to only read.
            //
            // Forgetting a reader is now a false refusal somebody fixes in a minute.
            // Forgetting a writer is no longer a silent hole. That asymmetry is the
            // whole change; the enumeration did not get longer, it got turned round.
            if let Some(index) = effective_program(&tokens) {
                // Same identity as the mutation walk above, and it matters more
                // here: an unresolved `(stat` is an UNKNOWN program, so a
                // declared `protected_readers` entry was unreachable behind a
                // grouping paren — CLOUD-1287's over-deny by a second road.
                let program = program_token(tokens[index]);
                let known = policy
                    .protected_readers
                    .iter()
                    .any(|reader| reader == program)
                    || policy.verbs.iter().any(|verb| verb.verb == program);
                if !known {
                    // OPERANDS, AND THE WIDER SCAN WAS TRIED AND REVERTED. Scanning
                    // every word for an embedded protected path catches
                    // `python3 -c "open('p','w')"` — the shape an agent actually
                    // reaches for — and it also refuses any unclassified program that
                    // merely MENTIONS a guarded path. Measured immediately: a `for`
                    // loop iterating probe commands was refused because one of its
                    // quoted words contained `batten.toml`. `echo "see batten.toml"`
                    // is the same shape.
                    //
                    // That is disqualifying rather than merely noisy. A guard that
                    // refuses ordinary mentions is one people switch off within a
                    // day, which is how this class of guard dies — the row that
                    // demanded this fix says so in as many words. An operand is a
                    // thing the program was handed; a substring of a quoted argument
                    // is not, and argv cannot tell a path being WRITTEN inside an
                    // interpreter's program text from one being TALKED ABOUT.
                    for path in operands(&tokens, index + 1).into_iter().map(program_token) {
                        // CLOUD-1141's arm asks the same membership question, so it
                        // had the same hole: an absolute operand was not recognised as
                        // protected here either, and the unknown program was allowed
                        // through the branch built to refuse it (CLOUD-1236).
                        if protects(policy, path) {
                            return Decision::Deny(unknown_program_refusal(program, path));
                        }
                    }
                }
            }
        }
    }
    Decision::Allow
}

/// Refuse a protected path named by a program neither table classifies.
///
/// # Why this reads differently from `protected_refusal`
///
/// That one names a mutation somebody declared, so it can say what to run
/// instead. This one is an admission: the boundary does not know what this
/// program does to its operands, and on a protected path it will not guess. The
/// remedy is therefore about the CONFIG rather than about the command — declare
/// the program a reader if it is one — plus the hatch for the case where it is a
/// deliberate write.
///
/// Pointer-only, like every refusal: the program, the path, and no operand text.
fn unknown_program_refusal(program: &str, path: &str) -> Refusal {
    Refusal::declared(
        PROTECTED_MUTATION,
        crate::verdict::Native::ProtectedMutation,
        // Same two tagged pointers, same order, as the declared-verb refusal: the
        // path first so it becomes the finding's own pointer, the program second
        // so the caller recognises which command of theirs was read this way.
        &[
            crate::verdict::Subject::Path {
                path: path.to_owned(),
            },
            crate::verdict::Subject::Artifact {
                artifact: program.to_owned(),
            },
        ],
        // The remedy is about the CONFIG rather than the command, which is what
        // makes this refusal different in kind from its sibling. That one names a
        // mutation somebody declared and can say what to run instead; this one is
        // an admission that the boundary does not know what the program does to
        // its operands and will not guess on a protected path.
        Fix::declared(Some(
            "declare it in `protected_readers` if it only reads, or take the hatch",
        )),
    )
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
/// Deliberately the *only* normalisation here. An absolute path, a `..`
/// traversal or a `~` are not resolved against the repo root by THIS function —
/// [`protects`] is where an absolute operand meets [`relative_to`], and this is
/// the string-level step before it. Every such miss under-denies, which is the
/// sanctioned direction for this arm, and
/// `tests::an_absolute_path_is_not_resolved_against_the_repo_root` pins the limit
/// so it cannot change silently.
///
/// **The reason this used to give was "`Envelope` carries no `cwd`", and it was
/// false** (CLOUD-1109): the field has been decoded since CLOUD-202 and is read
/// by [`names_a_repository_path`] now. A stale reason is worse than none, because
/// the next author reads it as a constraint and designs around a field that was
/// there all along. The limit above stands on its own terms, not on that one.
fn normalise(path: &str) -> &str {
    let path = path.strip_prefix("./").unwrap_or(path);
    // A TRAILING SEPARATOR NAMES THE SAME DIRECTORY (CLOUD-609), and stripping
    // it is half of that fix: `dir/` has to be asked as `dir` before the
    // containment question below can be asked at all. On its own it closes
    // nothing — `dir` is not inside `dir/**` either — which is why the row
    // answers "(1) AND (2)" rather than picking one.
    //
    // `/` alone is left as it is: trimming it would turn the filesystem root
    // into the empty string, and an empty path matches no glob for a reason
    // nobody could read back from the code.
    match path.strip_suffix('/') {
        Some(trimmed) if !trimmed.is_empty() => trimmed,
        _ => path,
    }
}

/// Is this path protected, asked the way the REPOSITORY names paths
/// (CLOUD-1236)?
///
/// # Why every reader goes through here
///
/// `protected` is a set of repo-relative globs, so the spelling of the path
/// decides the answer unless somebody normalises first. [`normalise`] takes a
/// leading `./` and nothing else, which leaves an absolute path — the spelling a
/// host sends and an agent routinely types — matching nothing.
///
/// CLOUD-1133 found that on the tool-write surface and fixed it at the envelope,
/// while writing down that the fix belonged in ONE place "because there is more
/// than one reader and a fix at one of them leaves the next author the same
/// trap". It then landed at one reader, and CLOUD-1236 is that trap arriving on
/// schedule: `rm <abs>/batten.toml` was allowed while `rm batten.toml` was
/// refused, for every declared glob and all 29 derived module paths.
///
/// So this is the one membership question, and all three readers ask it here.
///
/// # What it must not do, and does not by construction
///
/// [`relative_to`] answers `None` for a path that is already relative and for one
/// that resolves outside `root` — so a relative operand is judged exactly as it
/// was, and a path outside the repository is neither relativized into an
/// accidental match nor turned into a refusal. Those are CLOUD-1133's own two
/// bounds, inherited rather than restated.
///
/// The canonicalisation is not on the ordinary path: the early return above fires
/// for a relative operand, and `relative_to` returns before touching the
/// filesystem for one too, so the syscalls are paid only when an absolute operand
/// is not already a literal member.
fn protects(policy: &Policy, path: &str) -> bool {
    // `encloses` rather than `contains` (CLOUD-609): a DIRECTORY operand means
    // "write inside it", so membership is the wrong question and answering it
    // let `cp /tmp/draft.md .serena/memories/` through while the same copy
    // naming a file inside denied. This is the one call site that asks it;
    // `PathSet::contains` still means membership everywhere else.
    if policy.protected.encloses(normalise(path)) {
        return true;
    }
    let Some(root) = policy.root.as_deref() else {
        return false;
    };
    let Some(relative) = relative_to(root, path) else {
        return false;
    };
    policy.protected.encloses(normalise(&relative))
}

/// Compose the protected-path refusal: what was aimed where, and what to run.
///
/// The path is a *pointer* and rule 4 permits it — it is what the caller already
/// typed, and naming it is the difference between an actionable refusal and a
/// riddle. The file's contents never appear.
///
/// The fix is three-tiered (CLOUD-280): the `[[redirect]]` row for this path
/// class, else the verb's own declared `redirect`, else [`Fix::None`] — stated
/// rather than papered over with a catch-all that pretends to be specific. The
/// useful remedy is a property of what is being protected, not of the verb
/// reaching for it, which is why the table is consulted first; the two fallbacks
/// are CLOUD-96's behaviour unchanged, so the floor cannot regress.
///
/// It makes a refusal SPECIFIC; it does not make the named surface reachable.
/// CLOUD-663 was canceled on exactly that distinction — a redirect pointing at a
/// surface that is down is a defect in the surface.
///
/// A subcommand-qualified row names the whole action, not just the front-end:
/// `<program> <subcommand>` is what the caller typed and what a reader has to
/// recognise, and a refusal naming only the front-end would read as a ban on
/// every use of it (CLOUD-442).
fn protected_refusal(redirects: &[Redirect], target: &Target<'_>) -> Refusal {
    let action = match target.subcommand {
        Some(subcommand) => format!("{} {subcommand}", target.program),
        None => target.program.to_owned(),
    };
    Refusal::declared(
        PROTECTED_MUTATION,
        crate::verdict::Native::ProtectedMutation,
        // The path first, so it becomes the finding's own pointer; the action
        // second, because the class already says what a mutating verb is and the
        // caller needs to recognise WHICH command of theirs was read that way.
        // Both are tagged pointers rather than the prose they replaced, which is
        // what makes non-negotiable rule 4 structural here.
        &[
            crate::verdict::Subject::Path {
                path: target.path.to_owned(),
            },
            crate::verdict::Subject::Artifact { artifact: action },
        ],
        // Three tiers, narrowest first (CLOUD-280): the path class the consumer
        // declared, then the verb's own general remedy, then `Fix::None` — which
        // renders an explicit "none declared" and names the gate. The two
        // fallbacks are exactly CLOUD-96's behaviour, so this can only ever make
        // a refusal more specific, never less.
        //
        // The lookup takes `normalise`d path, the same value
        // `policy.protected.contains` was asked about, so the two tables cannot
        // disagree about WHICH path is under discussion. The message keeps the
        // path as the caller typed it, because that is the pointer they can act
        // on.
        Fix::declared(redirect::resolve(redirects, normalise(target.path)).or(target.redirect)),
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
    // NO SUBJECT, and that is rule 4 rather than an omission: the only thing this
    // refusal could point at is the command itself, which is the caller's own
    // text and could carry anything. The row id is the pointer.
    Refusal::declared(
        &rule.id,
        crate::verdict::Native::ShapeRefused,
        &policy_url_subject(rule),
        Fix::declared(rule.reason.as_deref()),
    )
}

/// Compose a content-keyed row's refusal (CLOUD-758).
///
/// **Pointer-only, and structurally rather than by discipline.** The cause names
/// the rule and the path the write would land on; the matched bytes are never
/// passed to this function, and [`Refusal`] has no field one could occupy —
/// the same property the `secrets` kind has for a matched secret. So an author
/// learns which row fired and which file to open, and the refusal cannot leak
/// the thing it refused.
fn content_refusal(rule: &Rule, envelope: &Envelope) -> Refusal {
    // THE DESTINATION IS THE POINTER, when the host reported one. What the
    // content IS never appears — this rule reads exactly the text somebody
    // wanted checked, which is the likeliest place in the surface for a secret,
    // so rule 4 is decided here at the composer rather than at the report.
    let subjects: Vec<crate::verdict::Subject> = envelope
        .writes
        .as_deref()
        .map(|path| {
            vec![crate::verdict::Subject::Path {
                path: path.to_owned(),
            }]
        })
        .unwrap_or_default();
    let mut subjects = subjects;
    subjects.extend(policy_url_subject(rule));
    Refusal::declared(
        &rule.id,
        crate::verdict::Native::ContentRefused,
        &subjects,
        Fix::declared(rule.reason.as_deref()),
    )
}

/// Compose a keyed shape row's refusal (CLOUD-446).
///
/// A distinct cause from [`shape_refusal`]'s, because the two say opposite things
/// about the same command: that one means *this is banned*, and this one means
/// *this is fine once the work is keyed*. Rendering both as "matches a refused
/// command shape" would send an author looking for a ban that is not there, which
/// is the un-actionable refusal CLOUD-122 exists to prevent.
///
/// Pointer-only, and here that is load-bearing rather than incidental: the
/// evidence this searched is a branch name and every commit message on the range,
/// and the cause names **none** of it (non-negotiable rule 4). What the author
/// needs is where to put a key, which is the row's own `reason`.
fn unkeyed_refusal(rule: &Rule) -> Refusal {
    // No subject: the three evidence sources are the CLASS, and none of them
    // produced a key to point at. Naming the command would be the caller's own
    // text back again.
    Refusal::declared(
        &rule.id,
        crate::verdict::Native::KeyMissing,
        &policy_url_subject(rule),
        Fix::declared(rule.reason.as_deref()),
    )
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
    /// The operator that FOLLOWED this span, or `None` where the command ended.
    ///
    /// Retained since CLOUD-443, and the reason is that three predicates are
    /// about the structure a command sits in rather than about its words: what
    /// its status is handed to, what replaces it, whether it was detached. The
    /// parser used to split on exactly these operators and discard them, so the
    /// structure was destroyed before any rule could see it.
    terminator: Option<Separator>,
    /// Whether this span binds an input redirection — `<`, `<<` or `<<<`.
    ///
    /// **Per SEGMENT, which is the entire predicate** (CLOUD-613). A heredoc
    /// opener binds to the element it is written in, so
    /// `git commit -F - && mise run land <<'EOF'` hands the message to `land`
    /// and leaves git reading the harness's `/dev/null`. The command STRING
    /// carries an opener either way; only the segment that owns it can tell
    /// those two apart, which is why this is a field here rather than a
    /// question a module could ask of [`crate::hook`]'s `command`.
    ///
    /// Read outside quoted spans only, so a `<` written inside a commit message
    /// is not a redirection — and heredoc BODIES are gone by the time this is
    /// set, so prose in a body cannot set it either.
    input_redirect: bool,
}

/// The shell operator between two segments — what happens to the first one's
/// exit status.
///
/// A vocabulary rather than a boolean because the four answers differ in the one
/// way that matters here. [`Separator::And`] is the only one that **preserves** a
/// failure: it short-circuits, so a non-zero status propagates and there is no
/// false green to stop. The other three each substitute something — the next
/// stage's status, the next element's, or nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Separator {
    /// `|` — the pipeline exits with the LAST stage's status.
    Pipe,
    /// `;` — the list exits with the last element's status.
    Semi,
    /// `||` — the list exits with the last element that ran.
    Or,
    /// `&&` — short-circuits, so a failure still propagates. Not a defect.
    And,
    /// `&` — detaches; the call returns before the work does.
    Background,
}

impl Separator {
    /// The operator as the shell spells it, for the policy input (CLOUD-857).
    ///
    /// The SHELL's spelling rather than the variant's name, so a module reads
    /// what an author wrote: a predicate about `&&` is written `"&&"`. Naming
    /// the variants would oblige every module to learn a second vocabulary for
    /// something the command line already states.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pipe => "|",
            Self::Semi => ";",
            Self::Or => "||",
            Self::And => "&&",
            Self::Background => "&",
        }
    }
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
/// **A heredoc BODY is not shell, and both directions of that are measured**
/// (CLOUD-613). Everything from the newline after a `<<WORD` opener to the line
/// that repeats the delimiter is data, and this drops it before tokenizing — so
/// a `;` in a commit message no longer splits the list, and a `nohup` in a
/// documentation paragraph is no longer an invocation. That second half is
/// CLOUD-723: `verdict-not-discarded` reads this parser's output, so it refused
/// correct commands whose heredoc prose happened to contain an operator, twice
/// in one session on the very commands that documented the rule. The opposite
/// direction is [`Segment::input_redirect`], which is only meaningful once
/// bodies are gone.
///
/// **Bounds, deliberate.** This is a pre-execution textual gate, not a shell:
/// variable expansion, command substitution, and globbing all hide operands from
/// it, and nothing here pretends otherwise. Every such miss under-denies, which
/// is the sanctioned direction. An unterminated quote runs to the end of the
/// command and keeps its tail as one word, and an unterminated heredoc runs to
/// the end of the command — which is what bash does with it too.
///
/// **A NEWLINE IS WHITESPACE HERE, NOT A SEPARATOR**, which bash disagrees with
/// and which is left standing deliberately. Making it a [`Separator::Semi`]
/// would be a change to every landed `pipeline` verdict — `mise run verify` on
/// one line and anything at all on the next becomes a discarded status — and
/// that is a decision about `verdict-not-discarded`'s reach rather than about
/// heredocs. The cost is stated rather than absorbed: the shell FOLLOWING a
/// heredoc's terminator joins the segment its opener was written in, so a
/// two-command call written across lines is judged as one. Every miss it causes
/// is a miss, never a false refusal.
#[expect(
    clippy::too_many_lines,
    reason = "one character walk, and splitting it is what the function exists to \
              prevent: quoting, redirection and heredoc openers are decided by the \
              SAME position in the same pass, and a second pass over the string is \
              the second parser this module refuses to grow"
)]
fn segments(command: &str) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut has_word = false;
    let mut raw = String::new();
    let mut input_redirect = false;
    // Delimiters whose bodies start at the next newline, in the order bash
    // consumes them: `cat <<A <<B` reads A's body first, then B's.
    let mut pending: Vec<String> = Vec::new();
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
                    // quotes it escapes only this handful.
                    if quote == '"'
                        && inner == '\\'
                        && chars
                            .peek()
                            .is_some_and(|next| matches!(*next, '"' | '\\' | '$' | '`'))
                        && let Some(next) = chars.next()
                    {
                        raw.push(next);
                        word.push(next);
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
            // AN INPUT REDIRECTION, and the heredoc opener that hides a body
            // (CLOUD-613). `<` in any of its three spellings binds stdin, which
            // is the whole of what `unsatisfiable-commit` needs to know: `git
            // commit -F -` is a message source iff something is redirected into
            // the SAME segment.
            //
            // `<<<` is a here-STRING and opens no body. Reading it as a heredoc
            // starts a skip that never terminates, which would swallow the rest
            // of the command — the same trap the bash guard's awk names.
            '<' => {
                input_redirect = true;
                raw.push(c);
                word.push(c);
                has_word = true;
                if chars.peek() == Some(&'<') {
                    chars.next();
                    raw.push('<');
                    word.push('<');
                    if chars.peek() == Some(&'<') {
                        chars.next();
                        raw.push('<');
                        word.push('<');
                    } else if let Some(delimiter) =
                        heredoc_delimiter(&mut chars, &mut raw, &mut word)
                    {
                        pending.push(delimiter);
                    }
                }
            }
            // The newline that ENDS an opener line is where its bodies begin.
            // Consuming them here, rather than scrubbing the string up front,
            // is what lets the quote state above decide whether a `<<` was an
            // opener at all: `echo "<<EOF"` never reaches this arm.
            '\n' if !pending.is_empty() => {
                raw.push(c);
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
                skip_heredoc_bodies(&mut chars, &mut pending);
            }
            // An `&` belonging to a REDIRECTION is not a separator (CLOUD-443).
            //
            // `2>&1`, `>&2` and `&>log` all carry a literal `&` that says nothing
            // about backgrounding, and the form this engine prescribes
            // — `mise run <task> >log 2>&1` — contains one. Splitting there both
            // mangles the segment and, once a background `&` became a verdict,
            // would refuse the exact idiom the refusal recommends.
            //
            // The test is positional and needs no lookbehind buffer: a
            // redirection's `&` is either directly after a `>` or directly before
            // one. Anything else unquoted is a real operator.
            '&' if raw.trim_end().ends_with('>') || chars.peek() == Some(&'>') => {
                raw.push(c);
                word.push(c);
                has_word = true;
            }
            '&' | '|' | ';' => {
                // `&&` and `||` are one separator, not two.
                let doubled = (c == '&' || c == '|') && chars.peek() == Some(&c);
                if doubled {
                    chars.next();
                }
                let separator = match (c, doubled) {
                    ('|', false) => Separator::Pipe,
                    ('|', true) => Separator::Or,
                    ('&', false) => Separator::Background,
                    ('&', true) => Separator::And,
                    _ => Separator::Semi,
                };
                if has_word {
                    words.push(std::mem::take(&mut word));
                    has_word = false;
                }
                if !words.is_empty() {
                    out.push(Segment {
                        words: std::mem::take(&mut words),
                        raw: raw.trim().to_owned(),
                        terminator: Some(separator),
                        input_redirect,
                    });
                }
                raw.clear();
                // The binding belongs to the segment that just closed. Carrying
                // it forward is the exact defect the field exists to catch:
                // `git commit -F - && mise run land <<'EOF'` would then read as
                // if git had been given the heredoc.
                input_redirect = false;
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
            // The command ended here, so nothing follows to take this segment's
            // status. `None` is what makes "alone in the call" — the prescribed
            // form — distinguishable from every shape that substitutes.
            terminator: None,
            input_redirect,
        });
    }
    out
}

/// Read a heredoc delimiter off the front of `chars`, echoing what it consumes.
///
/// Called with `<<` already consumed. Accepts the `<<-` tab-stripping form and
/// a delimiter in either quote style, which are the spellings that decide
/// whether the body is expanded — a distinction this parser does not care about,
/// since it drops the body either way.
///
/// **Everything consumed is echoed into `raw` and `word`**, so the opener
/// survives in the segment exactly as written. That is what keeps `<<'EOF'` a
/// visible token rather than a hole, and it is why the caller does not also have
/// to remember what this ate.
///
/// `None` where no delimiter word follows — `a << b` is an arithmetic shift or a
/// typo, and either way there is no body to skip. Reading one anyway would start
/// a skip that never terminates.
fn heredoc_delimiter(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    raw: &mut String,
    word: &mut String,
) -> Option<String> {
    let mut echo = |c: char| {
        raw.push(c);
        word.push(c);
    };
    if chars.peek() == Some(&'-') {
        chars.next();
        echo('-');
    }
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        if let Some(c) = chars.next() {
            echo(c);
        }
    }
    let quote = match chars.peek() {
        Some(&c @ ('\'' | '"')) => {
            chars.next();
            echo(c);
            Some(c)
        }
        _ => None,
    };
    let mut delimiter = String::new();
    while let Some(&c) = chars.peek() {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            break;
        }
        chars.next();
        echo(c);
        delimiter.push(c);
    }
    if let Some(quote) = quote
        && chars.peek() == Some(&quote)
    {
        chars.next();
        echo(quote);
    }
    (!delimiter.is_empty()).then_some(delimiter)
}

/// Consume every pending heredoc body, leaving `chars` on the shell that follows.
///
/// A line closes the front delimiter when it carries nothing but that word.
/// Trimmed rather than matched exactly, which is the reading both the bash
/// guard's awk and `policy/run-shape.rego` already take: `<<-` legitimately
/// indents its terminator, and being lenient here can only drop LESS text than
/// the shell would.
///
/// An unterminated body runs to the end of the command, which is what bash does
/// with it — the alternative, treating the remainder as shell, is the CLOUD-723
/// direction and is the one that produces a false refusal.
fn skip_heredoc_bodies(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    pending: &mut Vec<String>,
) {
    let mut line = String::new();
    for c in chars.by_ref() {
        if c != '\n' {
            line.push(c);
            continue;
        }
        if pending.first().is_some_and(|delim| line.trim() == delim) {
            pending.remove(0);
            if pending.is_empty() {
                return;
            }
        }
        line.clear();
    }
    pending.clear();
}

/// Do a row's operand words appear, adjacent and in order, in this command's
/// words?
///
/// **An empty operand list is the program alone, and matches any invocation of
/// it** (CLOUD-401). The program equality the callers test just above has
/// already decided such a row; there is nothing further to require, so
/// `cargo --version` — whose words are empty once flags are dropped — matches
/// too. The expression this replaced asked `windows(wanted.len().max(1))`, and
/// the `.max(1)` (there to stop `windows(0)`, which panics) made every window
/// one element long: no one-element window equals an empty slice, so a
/// program-only row was skipped on every command. It loaded clean and gated
/// nothing, which is the one failure a policy row must never have.
///
/// One function for BOTH matchers, deliberately. The arithmetic it replaces
/// lived twice, character for character, and the second copy stayed silent for
/// nine days after the first was measured — a shared authority is what stops
/// the twin recurring. The cases stay per-matcher (`rules::validate` and the
/// tests below), because sharing the decision must not also share the evidence.
fn operands_match(words: &[&str], wanted: &[&str]) -> bool {
    wanted.is_empty() || words.windows(wanted.len()).any(|window| window == wanted)
}

/// Did the call reach its program through the mediator a row requires?
///
/// Read from the tokens BEFORE the effective program, so a mediator named as an
/// argument (`cargo run --bin mise`) is not one, and every wrapper form is:
/// `effective_program` steps past `env`/`timeout`/… on its way, and this looks
/// at everything it stepped over. That is what stops
/// `env RUSTFLAGS=-Awarnings cargo build` from laundering the bare call.
fn mediator_present(via: crate::rules::RequireVia, before_program: &[&str]) -> bool {
    match via {
        // `mise exec -- cargo` and `mise x -- cargo` both leave `mise` here;
        // `mise run <task>` never reaches another program at all, so it is
        // judged as `mise` and no row keyed on the wrapped program sees it.
        crate::rules::RequireVia::Mise => before_program.contains(&"mise"),
    }
}

/// The wrapper programs [`effective_program`] looks through **unconditionally**.
///
/// Declared once because two surfaces read it: the matcher, to step past a
/// wrapper and judge what it wraps, and [`crate::rules::validate`], to refuse a
/// `pattern` naming one — by the time a pattern is compared the wrapper has
/// already been stepped past, so `pattern = "nohup rm"` is a row that can never
/// fire (CLOUD-401). A second copy of this list in the validator would drift,
/// and a drifted copy refuses rows the matcher would have honoured.
///
/// `mise` is deliberately **not** here: only `mise exec`/`mise x` is looked
/// through, so `mise run` is judged as `mise` and `pattern = "mise run"` is a
/// row the matcher honours.
const LOOKTHROUGH_WRAPPERS: [&str; 9] = [
    "env", "command", "nice", "stdbuf", "timeout", "xargs", "sudo", "doas", "nohup",
];

/// Is this token a program [`effective_program`] always looks through?
#[must_use]
pub(crate) fn is_lookthrough_wrapper(token: &str) -> bool {
    LOOKTHROUGH_WRAPPERS.contains(&token)
}

/// Shell GRAMMAR that may stand where a program is written — CLOUD-1382's
/// **declared stopgap**, and it is one on purpose.
///
/// # What it buys
///
/// A module anchoring on the first word of a segment was one keystroke from
/// silence. Measured 2026-09-03 and re-measured 2026-09-05 against the shipped
/// binary, this repository's committed config, adjudication only:
/// `git push --force origin main` refused, and `(git push --force origin main)`,
/// `time …`, `! …`, `{ …; }`, `command …` and `if true; then … fi` every one
/// exited 0. All six run the force push. `!` inverts a status and still
/// executes; `time` executes and reports; both grouping forms execute;
/// `command` bypasses function and alias lookup only.
///
/// # AND WHY IT IS NOT THE FIX
///
/// **A list cannot enumerate a grammar.** These six were the ones someone
/// thought of, and [`effective_program`] states the posture that makes the next
/// one silent too — *"Known wrappers only; anything unrecognised keeps the
/// fail-open posture."* CLOUD-1382's own Ready block refuses a prefix list as
/// the answer, in as many words, because adding to a table reproduces the defect
/// one token later. The real fix is a parsed command line, which is CLOUD-1381,
/// and CLOUD-1382 stays OPEN behind it rather than closing on this.
///
/// So the bound is stated rather than absorbed: every token here is one a shell
/// may place before a program, none of them is a program this repository would
/// ever judge in its own right, and the walk below steps past one only when a
/// further token exists — so a segment that is nothing but grammar (`fi`, `}`,
/// `done`) keeps exactly the answer it had, and no landed verdict moves.
///
/// `for` and `in` are deliberately absent: they are followed by a variable name
/// rather than by a command, so stepping past one would name an operand as the
/// program — a misidentification, where every token here is a correction.
const SHELL_GRAMMAR: [&str; 9] = [
    "!", "time", "if", "then", "elif", "else", "while", "until", "do",
];

/// The token with any GROUPING punctuation it was written against removed.
///
/// `(git` is one word to [`segments`], because `(` is not a separator and a
/// grouping construct needs no space after it. So the identity and the token are
/// different strings here in exactly the way they are for `/usr/bin/git`, and
/// [`program_name`] is the precedent: the boundary answers what this IS, and a
/// caller comparing the raw token answers no for the spelling that carries the
/// bypass.
///
/// # BOTH ENDS, and the opening-only version was a bypass of its own
///
/// This stripped `(` and said a trailing `)` *"belongs to whichever operand it
/// was written against"*. That reasoning holds for a path and is false for the
/// LAST token of a grouped command, which is where the closing paren actually
/// lands — and every predicate matching an exact flag or an exact path is
/// decided on exactly that token. Measured over the shipped binary, this
/// repository's committed config:
///
/// * `(git push origin main --force)` — allowed, because `arguments` ended
///   `--force)` and `no-force-push` compares for equality. The same command with
///   the flag written earlier denied, so the bypass was a matter of word order.
/// * `(rm batten.toml)` — allowed, because the operand was `batten.toml)` and no
///   protected path matches it. That one predates this row and is the same
///   defect one gate over: `rm batten.toml` and `time rm batten.toml` both
///   refuse.
///
/// # The bound, stated
///
/// Leading `(`/`{` are stripped unconditionally; trailing `)`/`}` are stripped
/// only where the remainder carries no opener of its own. That keeps a command
/// substitution intact — `binary=$(which gh)` is ONE word to [`segments`], and
/// its `)` closes the `$(` inside it rather than a group around it — while
/// reaching every case above. It is a rule about two characters, not a parser,
/// and CLOUD-1381 is still what replaces it.
fn program_token(token: &str) -> &str {
    let opened = token.trim_start_matches(['(', '{']);
    if opened.contains(['(', '{']) {
        return opened;
    }
    opened.trim_end_matches([')', '}'])
}

/// Is this token shell grammar standing where a program is written?
///
/// Decided on the STRIPPED token, which is what keeps the two cases apart: a
/// bare `(` strips to nothing and is grammar, while `(git` strips to `git` and
/// is the program itself, reached at the very same index.
fn is_shell_grammar(token: &str) -> bool {
    let bare = program_token(token);
    bare.is_empty() || SHELL_GRAMMAR.contains(&bare)
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
            // SHELL GRAMMAR BEFORE THE PROGRAM (CLOUD-1382), and the guard is
            // half the arm: stepping past requires a further token, so a
            // segment that is only grammar keeps the answer it already had.
            // An environment assignment may follow one — `time FOO=1 git …` —
            // so the prefix skip is repeated rather than done once at the top.
            grammar if is_shell_grammar(grammar) && i + 1 < tokens.len() => {
                i += 1;
                while i < tokens.len() && is_env_assignment(tokens[i]) {
                    i += 1;
                }
            }
            // `nohup` joins the list with CLOUD-443, and it was a gap in every
            // gate rather than only the new one: with the wrapper unresolved,
            // `nohup rm <protected>` presented `nohup` as its program and the
            // protected-path gate saw nothing to classify. Looking through a
            // wrapper can only ever find MORE real programs, which is the safe
            // direction. The detach it performs is read off the raw tokens by
            // `pipeline_rules`, precisely because this function hides it.
            wrapper if is_lookthrough_wrapper(wrapper) => {
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

pub(crate) fn is_env_assignment(token: &str) -> bool {
    let mut chars = token.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && token
            .chars()
            .take_while(|&c| c != '=')
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && token.contains('=')
}

/// Claude Code's verdict payload: the `hookSpecificOutput.permissionDecision`
/// object the host reads from stdout. Field order is struct order, so the
/// emission is byte-stable.
#[derive(Serialize)]
struct ClaudeVerdict<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeVerdictInner<'a>,
}

#[derive(Serialize)]
struct ClaudeVerdictInner<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'a str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

/// Encode one Claude Code verdict body, whatever the verdict word.
///
/// One function for `deny` and `ask` rather than two, because the envelope is the
/// same object and two copies of it are two things to keep in step. The verdict
/// word is the only difference, and it is the caller's — [`encode_ask`] reaches
/// this only after the capability table said the host has `ask`.
fn encode_claude_verdict(event: &str, verdict: &str, reason: &str) -> serde_json::Result<String> {
    serde_json::to_string(&ClaudeVerdict {
        hook_specific_output: ClaudeVerdictInner {
            hook_event_name: event,
            permission_decision: verdict,
            permission_decision_reason: reason,
        },
    })
}

/// Encode a deny for the Claude Code adapter.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_claude_deny(event: &str, reason: &str) -> serde_json::Result<String> {
    encode_claude_verdict(event, "deny", reason)
}

/// Claude Code's advisory payload: the `hookSpecificOutput.additionalContext`
/// object the host reads from stdout on exit 0 (CLOUD-461).
///
/// **A different object from [`ClaudeVerdict`], not a variant of it**, and the
/// separation is the contract rather than a serde detail. A verdict body carries
/// `permissionDecision`; this one structurally cannot, so an advisory has no
/// field a refusal could occupy and no code path can turn one into the other by
/// passing a different word. That is the same property `Finding` has for matched
/// bytes (non-negotiable rule 4) — structural, not disciplined.
///
/// Field order is struct order, so the emission is byte-stable (§6).
#[derive(Serialize)]
struct ClaudeAdvice<'a> {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: ClaudeAdviceInner<'a>,
}

#[derive(Serialize)]
struct ClaudeAdviceInner<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'a str,
    #[serde(rename = "additionalContext")]
    additional_context: &'a str,
}

/// Encode an advisory for the Claude Code adapter.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_claude_advice(event: &str, context: &str) -> serde_json::Result<String> {
    serde_json::to_string(&ClaudeAdvice {
        hook_specific_output: ClaudeAdviceInner {
            hook_event_name: event,
            additional_context: context,
        },
    })
}

/// Cursor's verdict body, shared by every token it documents.
///
/// A different shape for a different reason than Claude's: Cursor documents no
/// meaning for stderr at all, so this is the **only** channel a reason can travel
/// on. `user_message` and `agent_message` are its documented fields, and both
/// carry the same text — the human and the model are being told the same thing,
/// and a refusal that told them different things would be two contracts.
#[derive(Serialize)]
struct CursorVerdict<'a> {
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
    encode_cursor_verdict("deny", reason)
}

/// Encode any one of Cursor's documented verdicts into its body shape.
///
/// The shape is the host's and does not vary by verdict — only the token does —
/// so `deny` and `ask` share one encoder rather than two that could drift. Which
/// verdicts are *reachable* is not this function's question: [`encode_ask`] asks
/// [`Capabilities::ask_reachable`] first, so an escalation never reaches a
/// surface that would parse and ignore it.
fn encode_cursor_verdict(permission: &str, reason: &str) -> serde_json::Result<String> {
    serde_json::to_string(&CursorVerdict {
        permission,
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

/// Encode an **escalation** body for `harness`, or `None` where escalation is not
/// reachable on the surface Batten registers (CLOUD-45 §7(b)).
///
/// `None` is the caller's instruction to hard-deny. It is never an allow, and
/// that asymmetry is the whole clause: degrading "ask a human" to "go ahead"
/// would turn a policy into its opposite, where degrading it to a refusal costs
/// only a false positive an operator can see and bypass.
///
/// This is the half CLOUD-45 owes: before it, `Capabilities::ask` was a column
/// declared by every host and consulted by nothing, because nothing could express
/// wanting an escalation. **The capability table is consulted first**, so no
/// behaviour here keys on escalation without asking whether the host has it. Then the body shape, which
/// is a second and narrower question — a host can have the verdict while Batten
/// has no verified wire shape for it, and inventing one is exactly what the M1
/// survey records as unsafe.
///
/// **The event is part of the question, not decoration** (CLOUD-601). It was
/// already a parameter and was only echoed into the body; the reachability it
/// decides was reconstructed below, in the match arms, so the row and the
/// dispatch were two facts kept in step by hand. Cursor is why: its verdict
/// vocabulary is *event-dependent* — `ask` is honoured on `beforeShellExecution`
/// and `beforeMCPExecution` and "parses but is not enforced" on the generic
/// `preToolUse`, and an unenforced ask **proceeds**. One host, two answers, and
/// no per-host bool can hold both.
///
/// Copilot CLI is the other measured `None` and is a different question:
/// M1 confirms the verdict exists and names the output *fields*
/// (`permissionDecision`/`permissionDecisionReason`) without naming the object
/// they sit in. Emitting Claude's `hookSpecificOutput` envelope on the strength
/// of the field names would be a guess, and a guessed envelope that fails to
/// parse is read as no decision at all — an allow. Both gaps are declared in
/// `ASK_GAPS` and asserted over `Harness::ALL`.
///
/// # Errors
///
/// Serialization of these fixed shapes cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_ask(
    harness: Harness,
    event: &str,
    reason: &str,
) -> serde_json::Result<Option<String>> {
    // The table, consulted before the shape — and asked about THIS EVENT, which
    // is the whole of CLOUD-601. A host that does not enforce the verdict on the
    // surface Batten is standing on cannot be sent one, whatever its wire format
    // looks like and whatever the host-level row says it has.
    if !harness.capabilities().ask_reachable(event) {
        return Ok(None);
    }
    match harness {
        // Documented, and merged most-restrictive-first by the host itself
        // (`deny > defer > ask > allow`), so an ask here cannot override another
        // hook's deny.
        Harness::ClaudeCode => encode_claude_verdict(event, "ask", reason).map(Some),
        // Reachable on `beforeShellExecution` and `beforeMCPExecution` only, which
        // the guard above has already established by the time this arm runs. The
        // body is the host's one documented verdict shape, the same one a deny
        // travels in — so this arm is a projection rather than a second guess.
        Harness::Cursor => encode_cursor_verdict("ask", reason).map(Some),
        // No reachable surface: Copilot because its output object is unconfirmed,
        // the other three because the verdict is absent or inert. Unreachable
        // through the guard above, and stated rather than wildcarded so a row that
        // ever gains an `enforced_on` entry has to come back here and answer for
        // its wire shape.
        Harness::CopilotCli | Harness::GeminiCli | Harness::CodexCli | Harness::ExitCode => {
            Ok(None)
        }
    }
}

/// Encode an **advisory** body for `harness`, or `None` where no non-blocking
/// channel to the model is reachable on this surface (CLOUD-461).
///
/// `None` is the caller's instruction to say **nothing to the model**. It is
/// never a deny and never a verdict of any kind, and that asymmetry is the whole
/// clause — the exact mirror of [`encode_ask`]'s. An unreachable escalation
/// degrades to a refusal because proceeding would invert a policy somebody
/// wrote; an unreachable advisory degrades to silence because refusing would
/// invent a policy nobody wrote. A drift notice that blocked a call would be the
/// deny CLOUD-97 and CLOUD-219 each ruled out.
///
/// **The capability table is consulted first, and asked about THIS EVENT.** The
/// channel is a property of the moment rather than of the host: Claude Code
/// delivers `additionalContext` at a batch boundary and offers no such field on
/// the pre-tool event, where the only model-facing channel is exit 2. Asking the
/// host-level question would put an advisory on a surface that discards it,
/// which is indistinguishable from a notice nobody wrote.
///
/// A `None` here costs a line the model does not see. It never costs a verdict,
/// so there is no degradation direction to forbid — which is why this function
/// has no counterpart to [`encode_ask`]'s hard-deny instruction.
///
/// # Errors
///
/// Serialization of these fixed shapes cannot practically fail; the `Result` is
/// the honest signature for a serde boundary.
pub fn encode_advice(
    harness: Harness,
    event: &str,
    context: &str,
) -> serde_json::Result<Option<String>> {
    // The table, consulted before the shape, and asked about this event.
    if !harness.capabilities().advisory_reachable(event) {
        return Ok(None);
    }
    match harness {
        Harness::ClaudeCode => encode_claude_advice(event, context).map(Some),
        // THE GOLDEN RULE IS THE WIRE SHAPE (CLOUD-1362). Gemini documents that
        // unparseable stdout on exit 0 defaults to Allow and is surfaced as a
        // `systemMessage`, so the advisory body is the TEXT — deliberately not
        // JSON, because a document that parsed would be read as a decision and
        // this must never be one. The capability row above carries the argument
        // for why writing here is safe rather than a violation of that host's
        // `stdout_must_stay_clean`.
        Harness::GeminiCli => Ok(Some(context.to_owned())),
        // No reachable surface, and stated rather than wildcarded so a row that
        // ever gains a `delivered_on` entry has to come back here and answer for
        // its wire shape. Cursor documents a verdict body and no advisory one;
        // Copilot's output object is unconfirmed; Codex is unsurveyed; the
        // neutral adapter has an exit status and nothing else.
        Harness::Cursor | Harness::CopilotCli | Harness::CodexCli | Harness::ExitCode => Ok(None),
    }
}

/// Encode a **pre-approval** body for `harness`, or `None` where a grant is not
/// honoured on this surface.
///
/// `None` is the caller's instruction to say nothing — which returns the call to
/// the host's ordinary permission flow. That is the same degradation
/// [`encode_advice`] takes and for a sharper reason: an unhonoured pre-approval
/// costs a prompt the operator sees, where an undelivered advisory costs a line
/// nobody reads. Neither may degrade to a deny, because refusing a call the
/// operator already permitted inverts the policy in the direction that hurts.
///
/// **The one thing this must never do is manufacture permission.** The reason it
/// carries is a projection of a committed rule onto the name the host chose this
/// session, and the boundary only ever calls this after the engine's own decision
/// came back [`Decision::Allow`] — so a pre-approval cannot spend a refusal any
/// rule reached. That ordering is what keeps Batten a gate rather than the
/// reference monitor the scope reminder forbids.
///
/// **The capability table is consulted first, and asked about THIS EVENT.** Claude
/// Code honours `permissionDecision` on `PreToolUse` and nowhere else — a
/// permission decision after the call has run decides nothing — so a host-level
/// question would put a grant on a surface that discards it, which reads exactly
/// like the guard never running.
///
/// # Errors
///
/// Serialization of this fixed shape cannot practically fail; the `Result` is the
/// honest signature for a serde boundary.
pub fn encode_preapproval(
    harness: Harness,
    event: &str,
    reason: &str,
) -> serde_json::Result<Option<String>> {
    // The table, consulted before the shape, and asked about this event.
    if !harness.capabilities().preapprove_reachable(event) {
        return Ok(None);
    }
    match harness {
        // The same envelope a deny and an ask travel in, with the third verdict
        // word. Reusing `encode_claude_verdict` is what stops this arm becoming a
        // second opinion about the host's shape — the object is one object, and
        // the word is the caller's.
        Harness::ClaudeCode => encode_claude_verdict(event, "allow", reason).map(Some),
        // No honoured surface, stated rather than wildcarded so a row that ever
        // gains an `honoured_on` entry has to come back here and answer for its
        // wire shape. Cursor's verdict vocabulary is surveyed and carries no
        // prompt-suppressing value; Copilot's output object is unconfirmed;
        // Gemini's and Codex's are unsurveyed for this channel; the neutral
        // adapter's exit status has no room to say "and do not prompt".
        Harness::Cursor
        | Harness::CopilotCli
        | Harness::GeminiCli
        | Harness::CodexCli
        | Harness::ExitCode => Ok(None),
    }
}

/// Surfaces where an advisory is documented and Batten does not use it,
/// **stated** (CLOUD-461).
///
/// `ASK_GAPS`' discipline applied to the third channel, and it is worth the
/// table for a reason `ask` did not have: an advisory that goes nowhere is
/// **silent by design**, so the failure mode of a wrong row here is a notice
/// nobody ever sees and nobody can tell from a notice nobody wrote. A deny that
/// fails to reach a host is loud; this is not.
///
/// The census over `Harness::ALL` fails when a host declares the channel and
/// reaches none of it and no row says so, **and** when a row here no longer
/// describes a gap — so probing a surface fails until its row is removed.
///
/// `pub` because being readable IS the mechanism.
pub const ADVISORY_GAPS: &[(Harness, &str)] = &[(
    Harness::ClaudeCode,
    "`PostToolUse` and `UserPromptSubmit` are documented to accept \
         `additionalContext` and are NOT in `delivered_on`, because nothing here \
         has probed them. Listing an unprobed surface costs a notice that \
         vanishes silently; leaving it out costs only silence. `PreToolUse` was \
         a third entry here until CLOUD-1131 probed it and it delivered — so a \
         row leaving this table is what closing a gap looks like, and the \
         absence of a probe is never itself a finding about the host.",
)];

/// Surfaces where a pre-approval is honoured and Batten does not spend one,
/// **stated**.
///
/// `ADVISORY_GAPS`' discipline on the fourth channel, and the failure mode it
/// guards is the quietest of the four: an unspent grant costs a permission
/// prompt, which looks exactly like the guard not being installed. A deny that
/// fails to reach a host is loud, an undelivered advisory is silent, and this is
/// silent AND visibly annoying to the operator, who has no way to tell which
/// layer failed.
///
/// **Empty today, and the census below is what keeps that honest rather than
/// convenient.** Only Claude Code declares the channel, and it is honoured on
/// every surface where the question means anything — a permission decision after
/// the call has run decides nothing, so `PreToolUse` is not a subset of a wider
/// set that Batten declines to reach. There is no gap to state. Every other host
/// declares `No` or `Unknown`, and neither states a gap: measured-absent has
/// nothing to disagree with and unsurveyed has nothing to disagree *from*.
///
/// `pub` because being readable IS the mechanism.
pub const PREAPPROVE_GAPS: &[(Harness, &str)] = &[];

/// Hosts whose declared escalation and reachable escalation disagree, **stated**.
///
/// CLOUD-601's load-bearing half: the current state must be *declared*, not
/// merely true. A host that says it has `ask` and cannot be asked on the surface
/// [`Harness::wiring`] registers is a fact somebody has to be able to read, and a
/// table nobody keeps is how the two answers drifted apart in the first place.
///
/// The census over `Harness::ALL` fails when a disagreement exists and is missing
/// here, **and** when a row here no longer describes a disagreement — so closing
/// one (CLOUD-777 registers Cursor's specialized events) fails until the row is
/// removed, rather than leaving a stale citation behind.
///
/// `pub` because being readable IS the mechanism: a table only the tests can see
/// states the gap to nobody, which is the shape of the defect this closes.
pub const ASK_GAPS: &[(Harness, &str)] = &[
    (
        Harness::Cursor,
        "declared on the host, enforced only on `beforeShellExecution` and \
         `beforeMCPExecution`; `wiring` registers the generic `preToolUse`, where \
         an ask parses and is ignored. CLOUD-777 registers the specialized events.",
    ),
    (
        Harness::CopilotCli,
        "the verdict exists and the `preToolUse` output OBJECT is unconfirmed by \
         primary docs, so no envelope can be emitted without guessing; recorded \
         `Unknown` rather than `No`.",
    ),
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A class declaring two `command` routes and one `override`, so a renderer
    /// that takes "the first one" and one that takes them all are distinguishable.
    fn two_route_class() -> Vec<crate::verdict::DeclaredVerdict> {
        let route = |id: &str, kind, target: &str| crate::verdict::Route {
            id: id.to_owned(),
            kind,
            target: target.to_owned(),
            precondition: match kind {
                crate::verdict::RouteKind::Override => Some("why it should not stand".to_owned()),
                _ => None,
            },
        };
        vec![crate::verdict::DeclaredVerdict {
            id: "branch write unsafe".to_owned(),
            gloss: "branch write unsafe".to_owned(),
            class: "The long definition of the class.".to_owned(),
            routes: vec![
                route(
                    "branch read first",
                    crate::verdict::RouteKind::Command,
                    "git pull --rebase",
                ),
                route(
                    "branch write refused",
                    crate::verdict::RouteKind::Command,
                    "git push --force-with-lease=<ref>:<sha>",
                ),
                route(
                    "branch write first",
                    crate::verdict::RouteKind::Override,
                    "branch write unsafe",
                ),
            ],
            successor: None,
            withdrawn: None,
        }]
    }

    /// CLOUD-1386: the first sighting carries EVERY declared `command` route.
    ///
    /// Measured on `leased-push`, which declares the rebase first and the
    /// explicit `--force-with-lease=<ref>:<sha>` second. A session that read only
    /// the first could not tell the class refuses a SPELLING rather than the
    /// action, and reported a working gate as a design defect. So the assertion
    /// that matters is on the SECOND route: a renderer taking `Fix:`'s single
    /// route passes every other clause of this case.
    #[test]
    fn a_first_sighting_carries_every_command_route() {
        let registry = two_route_class();
        let refusal = Refusal::from_class(
            "leased-push",
            &registry,
            "branch write unsafe",
            &[],
            crate::refusal::Fix::None,
        );
        let text = deny_text(&refusal, "BATTEN_HOOK_BYPASS", true, None);
        assert!(
            text.contains("git push --force-with-lease=<ref>:<sha>"),
            "the second route is the one that answers the reader: {text}"
        );
        assert!(text.contains("git pull --rebase"), "{text}");
        assert!(
            !text.contains("override"),
            "a way out that begins by asking to be excused is not an alternative: {text}"
        );
    }

    /// The repeat is the bare line — the cost CLOUD-1286 measured, still unpaid.
    #[test]
    fn a_repeat_sighting_carries_no_route_at_all() {
        let registry = two_route_class();
        let refusal = Refusal::from_class(
            "leased-push",
            &registry,
            "branch write unsafe",
            &[],
            crate::refusal::Fix::None,
        );
        let text = deny_text(&refusal, "BATTEN_HOOK_BYPASS", false, None);
        assert!(!text.contains("git pull --rebase"), "{text}");
        assert!(!text.contains(" — "), "{text}");
    }

    /// A first sighting is bounded by the SAME declared ceiling as a repeat.
    ///
    /// The once-per-session change re-pointed `refusal_ceiling` at the second
    /// firing, which left this arm bounded by nothing in the same commit that made
    /// it the long one. Measured on a consumer `[[rule]]` row's `reason` reaching
    /// `Fix::Run` as prose — ~700 characters ending in a DIFFERENT rule's id, which
    /// is what `board_receipts::an_update_is_not_row_ones_business` caught.
    ///
    /// Dropped WHOLE rather than truncated: half a command is not a way out, and
    /// the class token is still on the line for `batten policy explain`.
    /// THE FIXTURE IS PROSE BECAUSE THE DEFECT WAS PROSE, and a shorter one does
    /// not reach the bound. Measured while writing this: the class's own two
    /// routes compose an 82-character line — about 20 estimated tokens, UNDER the
    /// declared 24 — so a case built on them asserts the ceiling drops something
    /// it never had cause to drop, and fails for being wrong about its own
    /// premise rather than about the engine.
    ///
    /// A consumer `[[rule]]` row's `reason` is what actually arrives here, and
    /// `an-update-owes-a-recent-read`'s is ~700 characters ending in another
    /// rule's id. This mirrors that shape rather than lowering the ceiling until
    /// a short line trips it, which would have measured the fixture.
    const PROSE_FIX: &str = "Re-read the row. That is the whole remedy: read it \
         again with its relations, and the receipt mints itself from that result \
         — there is no second call and no payload to pipe anywhere. Then make the \
         write from what you just read, not from the plan you built earlier: if \
         the row changed, that is the point, so decide again. This bounds how old \
         the read was; it cannot prove the row is unchanged, because the tracker \
         offers no precondition on write.";

    #[test]
    fn a_first_sighting_over_the_declared_ceiling_drops_its_routes() {
        let registry = two_route_class();
        let refusal = Refusal::from_class(
            "row-one",
            &registry,
            "branch write unsafe",
            &[],
            crate::refusal::Fix::Run(PROSE_FIX.to_owned()),
        );
        let ceiling = crate::refusal::Ceiling { max_tokens: 24 };
        let bounded = deny_text(&refusal, "BATTEN_HOOK_BYPASS", true, Some(&ceiling));
        let unbounded = deny_text(&refusal, "BATTEN_HOOK_BYPASS", true, None);
        assert!(
            unbounded.contains("Re-read the row"),
            "the premise: unbounded, this arm carries the prose — {unbounded}"
        );
        assert!(
            ceiling.over(&unbounded),
            "the premise: the unbounded line is over the ceiling — {unbounded}"
        );
        assert!(
            !ceiling.over(&bounded),
            "the emitted line is over the declared ceiling: {bounded}"
        );
        assert_eq!(bounded, refusal.line(), "{bounded}");
    }

    /// And a SHORT route still travels, or the bound above is just the old
    /// never-render behaviour wearing a ceiling.
    ///
    /// The class's own two routes at the REAL declared ceiling of 24, which is the
    /// case the row exists for: `leased-push`'s explicit lease form has to reach a
    /// reader who has just been refused, and it does.
    #[test]
    fn a_first_sighting_inside_the_ceiling_still_carries_its_routes() {
        let registry = two_route_class();
        let refusal = Refusal::from_class(
            "leased-push",
            &registry,
            "branch write unsafe",
            &[],
            crate::refusal::Fix::None,
        );
        let ceiling = crate::refusal::Ceiling { max_tokens: 24 };
        let text = deny_text(&refusal, "BATTEN_HOOK_BYPASS", true, Some(&ceiling));
        assert!(
            text.contains("git push --force-with-lease=<ref>:<sha>"),
            "{text}"
        );
    }

    /// The caller's narrower alternative leads and is not said twice.
    ///
    /// A consumer's `redirect` for a protected path knows something the class does
    /// not, and it is very often the class's own first route — so a renderer that
    /// concatenates rather than merges emits the same clause twice.
    #[test]
    fn a_narrower_fix_leads_and_is_never_repeated() {
        let registry = two_route_class();
        let refusal = Refusal::from_class(
            "leased-push",
            &registry,
            "branch write unsafe",
            &[],
            crate::refusal::Fix::Run("git pull --rebase".to_owned()),
        );
        let text = deny_text(&refusal, "BATTEN_HOOK_BYPASS", true, None);
        assert_eq!(text.matches("git pull --rebase").count(), 1, "{text}");
        let routes = text.split(" — ").nth(1).expect("the routes clause");
        assert!(routes.starts_with("git pull --rebase"), "{text}");
        assert!(
            routes.contains("git push --force-with-lease=<ref>:<sha>"),
            "{text}"
        );
    }

    /// [`super::adjudicate`] with **no waiver declared** — the shape every case
    /// below this line was written against.
    ///
    /// A deliberate shadow rather than a sixth argument typed thirty times: a
    /// waiver table is empty in almost every scenario this suite describes, and
    /// spelling that out at each call would bury the handful of cases where it is
    /// the subject. The cases that ARE about suppression call `super::adjudicate`
    /// by its full path, so the reader can see at the call which world they are in.
    fn adjudicate(
        policy: &Policy,
        envelope: &Envelope,
        bypass: bool,
        receipts: &ReceiptFacts,
        keys: &KeyFacts,
        stop: &crate::stop::StopFacts,
    ) -> Decision {
        super::adjudicate(
            policy,
            envelope,
            &Facts {
                bypass,
                receipts,
                keys,
                stop,
                waived: &crate::waiver::Live::new(),
                sourced: &None,
                prospective: &crate::facts::Look::CouldNotLook,
                manifest: None,
                tasks: &crate::facts::Look::CouldNotLook,
                extracted: &crate::facts::Look::CouldNotLook,
                pinned: &crate::facts::Look::CouldNotLook,
            },
        )
    }

    /// A live waiver table over one rule, expiring on a date the case names.
    fn waiving(rule: &str, expires: &str) -> crate::waiver::Live {
        let mut live = crate::waiver::Live::new();
        live.insert(rule.to_owned(), expires.to_owned());
        live
    }

    fn shape(id: &str, pattern: &str, contains: Option<&str>) -> Rule {
        Rule {
            review: Vec::new(),
            id: id.to_owned(),
            kind: crate::rules::RuleKind::Shape,
            glob: None,
            severity: Some(RuleSeverity::Deny),
            scope: RuleScope::MediatedCall,
            pattern: Some(pattern.to_owned()),
            regex: None,
            exclude: None,
            content: None,
            tool: None,
            measures: None,
            counts: None,
            max: None,
            resolves: Vec::new(),
            when_absent: None,
            when_present: None,
            when_value: None,
            key_from: None,
            key_shape: None,
            max_age: None,
            requires_field: None,
            contains: contains.map(ToOwned::to_owned),
            require_via: None,
            requires_key: None,
            reason: Some(format!("use the sanctioned path for {id}")),
            policy_url: None,
            bypass_env: None,
            check: None,
            fix: None,
            produces: None,
            exclude_paths: Vec::new(),
            symbols: false,
            run: None,
            verbatim: None,
            identity_key: None,
            direction: None,
            base: None,
            retires_with: None,
            conserves: None,
            admits_with: None,
            format: None,
            node: None,
            derives: None,
            reads: None,
            module: None,
            bundle: None,
            preset: None,
            documents: Vec::new(),
            requires_path: Vec::new(),
            sources: Vec::new(),
            lines: Vec::new(),
            line_sources: Vec::new(),
            invocations: Vec::new(),
            invocation_sources: Vec::new(),
            uses: Vec::new(),
            use_sources: Vec::new(),
            git: Vec::new(),
            refs: Vec::new(),
            ranges: Vec::new(),
            commits: Vec::new(),
            staged: Vec::new(),
            history: Vec::new(),
            state: Vec::new(),
            forge: Vec::new(),
            tools: Vec::new(),
            minted: Vec::new(),
            captured: Vec::new(),
            tasks: Vec::new(),
            extract: Vec::new(),
            landing: Vec::new(),
            delta_sources: Vec::new(),
            external: Vec::new(),
            predicate_severity: None,
            criteria: None,
            tier: None,
            // A shape rule never reaches the findings store, so it is refused
            // the remediation column (CLOUD-81).
            no_fix_reason: None,
            checks: None,
            checks_any: None,
            key: None,
            trigger: None,
            verdict: None,
            filters: None,
            substitutes: None,
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
            subcommand: None,
            requires_flag: None,
            operands: None,
        }
    }

    /// The three qualifier shapes CLOUD-442 adds, each as a row a `batten.toml`
    /// could carry. Written as builders over [`verb`] so the unqualified default
    /// stays the thing every other test in this module declares.
    fn destination_only(name: &str, redirect: Option<&str>) -> MutatingVerb {
        MutatingVerb {
            operands: Some(OperandScope::Last),
            ..verb(name, redirect)
        }
    }

    fn behind_flag(name: &str, flags: &[&str], redirect: Option<&str>) -> MutatingVerb {
        MutatingVerb {
            requires_flag: Some(flags.iter().map(|flag| (*flag).to_owned()).collect()),
            ..verb(name, redirect)
        }
    }

    fn under_subcommand(name: &str, subcommand: &str, redirect: Option<&str>) -> MutatingVerb {
        MutatingVerb {
            subcommand: Some(subcommand.to_owned()),
            ..verb(name, redirect)
        }
    }

    /// A policy with the CLOUD-96 cross product declared: two mutating verbs and
    /// one protected glob. Both tables are the consumer's, so a test supplies
    /// them exactly as a `batten.toml` would.
    fn protected_policy(verbs: Vec<MutatingVerb>) -> Policy {
        protected_policy_with(verbs, Vec::new())
    }

    /// The same fixture with a declared `[[redirect]]` table (CLOUD-280).
    fn protected_policy_with(verbs: Vec<MutatingVerb>, redirects: Vec<Redirect>) -> Policy {
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            // THE VENDORED REGISTRY, because every real `Policy` carries it and a
            // case built on an empty one tests a shape the engine cannot produce
            // (CLOUD-1357). `Policy::from_resolved` builds this field with
            // `policy::registry_for`, which merges the vendored classes into
            // whatever the consumer declared — so `path write refused` and its
            // `articulate the write` route are present in every loaded policy.
            //
            // It became load-bearing when the hatch's carve-out stopped being a
            // branch naming one gate and became a property of the CLASS: with an
            // empty registry `honours_hatch` cannot see the precondition, reads
            // the class as bare, and suppresses a refusal production never
            // suppresses. Found by `the_bypass_hatch_does_not_reach_the_protected_gate`
            // going red — the fixture was the thing that was wrong.
            verdicts: crate::verdict::vendored(),
            root: None,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes(
                "protected",
                &[".serena/memories/**".to_owned(), "batten.toml".to_owned()],
            )
            .expect("the fixture protected set is well formed"),
            // EMPTY ON PURPOSE. This fixture's cases are about the declared-verb
            // half, and an empty reader set is the strictest setting for the
            // unknown-program half — so a case here that starts refusing is the
            // new clause reaching a shape the old gate let through, which is
            // exactly what should be visible rather than absorbed.
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects,
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
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        )
    }

    /// A policy carrying only the rows a ceiling case declares.
    ///
    /// `gh_policy`'s shape with the shape list parameterised: these cases decide
    /// nothing about verbs, protected paths or bundles, and spelling the empty
    /// ones out per case would bury the one field under test.
    fn ceiling_policy(rows: Vec<Rule>) -> Policy {
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
            shapes: rows,
            fail_on_warning: false,
        }
    }

    /// A tool-keyed row capping the prompt at `max` estimated tokens (CLOUD-925).
    ///
    /// Built by clearing `shape`'s `pattern`: a ceiling row is keyed on `tool`,
    /// and carrying both would be refused at load as two selectors.
    fn ceiling_row(id: &str, tool: &str, max: usize) -> Rule {
        Rule {
            pattern: None,
            tool: Some(tool.to_owned()),
            measures: Some(Field::Prompt),
            counts: Some(CeilingUnit::Tokens),
            max: Some(max),
            ..shape(id, "unused", None)
        }
    }

    /// [`ceiling_row`]'s manifest twin: the same cap over a count of artifacts.
    fn manifest_row(id: &str, tool: &str, max: usize) -> Rule {
        Rule {
            counts: Some(CeilingUnit::TrackedArtifacts),
            ..ceiling_row(id, tool, max)
        }
    }

    /// A subagent spawn: a tool name, a prompt in `input`, and NO command line —
    /// which is the shape that made this whole family unreachable before
    /// CLOUD-924.
    fn task_spawn(prompt: &str) -> Envelope {
        task_spawn_named("Task", prompt)
    }

    /// [`task_spawn`] under another tool name, for the narrowing case.
    fn task_spawn_named(tool: &str, prompt: &str) -> Envelope {
        Envelope {
            raw_tool: tool.to_owned(),
            input: serde_json::json!({ "prompt": prompt }),
            ..envelope_at(Event::PreTool, "")
        }
    }

    /// A call naming a tool and carrying no prompt at all — the could-not-look
    /// case, distinct from a prompt that is present and empty.
    fn envelope_for_tool(tool: &str) -> Envelope {
        Envelope {
            raw_tool: tool.to_owned(),
            input: Value::Null,
            ..envelope_at(Event::PreTool, "")
        }
    }

    fn gh_policy() -> Policy {
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
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
            raw_tool: "Bash".to_owned(),
            operation: Operation::Execute,
            input: Value::Null,
            result: Value::Null,
            command: command.to_owned(),
            writes: None,
            reads: None,
            cwd: None,
            session: None,
            // The Stop-path fields (CLOUD-479) are absent on a PreTool envelope,
            // which is the honest shape rather than a filler value.
            stop_active: None,
            last_message: None,
            transcript: None,
            mode: None,
        }
    }

    /// A write-tool envelope: no command, a target path, as the adapter decodes
    /// one. The unit tests build it directly so the write gate is exercised
    /// without a harness in the way; `tests/cli.rs` covers the decode end.
    ///
    /// **`writes` and `operation` are DERIVED here, exactly as `decode` derives
    /// them** (CLOUD-779), rather than being handed in. Both come from the same
    /// `write_tools` lookup in the adapter, so a hand-built fixture that carried a
    /// target while claiming not to be write-shaped — or the reverse — would
    /// describe an envelope no host can produce, and every case resting on it
    /// would be asserting its own premise. `Harness::ExitCode` is the neutral
    /// contract these unit cases speak; per-host spellings are `tests/cli.rs`'s.
    fn write_envelope(tool: &str, path: &str) -> Envelope {
        write_envelope_on(Harness::ExitCode, tool, path)
    }

    /// [`write_envelope`] under a named host, for the per-harness vocabulary
    /// cases — the same derivation, a different table to derive from.
    fn write_envelope_on(harness: Harness, tool: &str, path: &str) -> Envelope {
        let writes = harness
            .write_tools()
            .contains(&tool)
            .then(|| path.to_owned());
        Envelope {
            event: Event::PreTool,
            raw_event: ASSUMED_EVENT.to_owned(),
            raw_tool: tool.to_owned(),
            operation: harness.operation_of(tool),
            input: Value::Null,
            result: Value::Null,
            command: String::new(),
            writes,
            reads: None,
            cwd: None,
            session: None,
            stop_active: None,
            last_message: None,
            transcript: None,
            mode: None,
        }
    }

    /// A repository declaring no ceiling MEASURES NOTHING; one declaring a
    /// ceiling measures exactly once (CLOUD-925).
    ///
    /// **A counter, because a clock cannot discriminate here.** Reading a decoded
    /// string and dividing by four is far inside the noise of a process start, so
    /// a timing assertion passes on a build that measures every call — the
    /// CLOUD-418 failure of shipping a test unable to tell the two apart.
    ///
    /// §7 proposed the `passthrough`-below-`noop` reading as that discriminator.
    /// Measured with `perf-pair` on this container it does not reproduce at
    /// EITHER arm (2.95 > 2.57 base, 2.98 > 2.55 head), so it could not have
    /// discriminated anything; the counter is the clause §7 names first and is
    /// the sound one. Recorded on CLOUD-925.
    ///
    /// **Asserted on the gate's own out-parameter, never on the process
    /// counter.** The first draft of this case took deltas from
    /// `ceilings_measured()` and failed: two ceiling cases in this binary run
    /// concurrently, so each saw the other's increment. That is exactly the race
    /// `document_read_count.rs` needs a separate binary to avoid, and reporting
    /// the count out of the gate removes it instead of working around it.
    ///
    /// Fails by: hoisting the measurement above the row selection, or above the
    /// projection's presence test, in `ceiling_rules`.
    #[test]
    fn only_a_declared_and_selected_ceiling_is_measured() {
        let over_any_cap = "x".repeat(40_000);
        let spawn = task_spawn(&over_any_cap);

        let plain = ceiling_policy(vec![shape("unrelated", "gh pr merge", None)]);
        let mut without = 0;
        let _ = ceiling_rules(&plain, &spawn, &mut without);

        let capped = ceiling_policy(vec![ceiling_row("fanout-prompt-budget", "Task", 100)]);
        let mut with = 0;
        let _ = ceiling_rules(&capped, &spawn, &mut with);

        // A ceiling declared for ANOTHER tool: the CLOUD-460 narrowing, which
        // separates "nothing declared" from "declared for something else".
        let mut other_tool = 0;
        let _ = ceiling_rules(
            &capped,
            &task_spawn_named("Read", &over_any_cap),
            &mut other_tool,
        );

        assert_eq!(
            without, 0,
            "a repository declaring no ceiling must measure nothing"
        );
        assert_eq!(
            with, 1,
            "a declared ceiling must be measured exactly once — the positive twin, \
             without which the first assertion passes on a counter that never moves"
        );
        assert_eq!(
            other_tool, 0,
            "a row selecting another tool must not measure this call"
        );
    }

    /// The reading manifest counts TRACKED artifacts the projection names, after
    /// the consumer's own rewrites (CLOUD-925).
    ///
    /// Tracked is the whole membership test, and these are the four shapes that
    /// makes different: a plain tracked path counts, an untracked one does not, a
    /// consumer shorthand counts once rewritten, and naming one artifact twice is
    /// still one artifact to read.
    ///
    /// **The rewrite table is the consumer's** — `mem:` and the memories tree are
    /// this repository's convention, not the engine's, so they appear here as
    /// fixture data and nowhere in `crates/batten` (non-negotiable rule 1).
    ///
    /// Fails by: dropping the tracked-set intersection, which makes every
    /// path-shaped token in a prompt count.
    #[test]
    fn the_manifest_counts_tracked_artifacts_after_the_consumers_rewrites() {
        let tracked: std::collections::BTreeSet<String> = [
            "AGENTS.md",
            "crates/batten/src/hook.rs",
            ".serena/memories/core.md",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
        let resolves = vec![crate::rules::Rewrite {
            reference: "^mem:(.+)$".to_owned(),
            path: ".serena/memories/$1.md".to_owned(),
        }];

        let count = |text: &str| count_named_artifacts(text, &resolves, &tracked);

        assert_eq!(
            count("read AGENTS.md before you start"),
            1,
            "a tracked path"
        );
        assert_eq!(
            count("read docs/architecture.md before you start"),
            0,
            "an untracked path names nothing this repository can be made to read"
        );
        assert_eq!(count("start at mem:core"), 1, "a rewritten reference");
        assert_eq!(
            count("mem:core and .serena/memories/core.md"),
            1,
            "one artifact named twice is one artifact to read"
        );
        assert_eq!(
            count("see https://example.com/AGENTS.md.html"),
            0,
            "a URL is not a tracked path, and drops out by construction"
        );
        assert_eq!(
            count("read AGENTS.md and crates/batten/src/hook.rs and mem:core"),
            3,
            "three distinct artifacts"
        );
    }

    /// A repository declaring no `tracked-artifacts` ceiling is not asked for one,
    /// so the boundary never enumerates the tree.
    ///
    /// **This is the acquisition half of cheap-when-irrelevant**, and the one
    /// CLOUD-925 prices explicitly: the token conjunct is arithmetic over bytes
    /// already decoded, but this unit spawns git. `manifest_ceiling_for` is the
    /// column test the boundary asks BEFORE it does, so a `None` here means no
    /// enumeration happened at all.
    ///
    /// Fails by: resolving the manifest unconditionally in `manifest_for`, which
    /// puts a `git ls-files` on every mediated call in every repository.
    #[test]
    fn no_manifest_ceiling_means_the_tree_is_never_enumerated() {
        let spawn = task_spawn("read AGENTS.md");
        let token_only = ceiling_policy(vec![ceiling_row("tokens", "Task", 100)]);
        assert!(
            token_only.manifest_ceiling_for(&spawn).is_none(),
            "a TOKEN ceiling asks no question about the tree"
        );
        let none = ceiling_policy(vec![shape("unrelated", "gh pr merge", None)]);
        assert!(
            none.manifest_ceiling_for(&spawn).is_none(),
            "a repository declaring no ceiling asks nothing"
        );
        let manifest = ceiling_policy(vec![manifest_row("manifest", "Task", 5)]);
        assert!(
            manifest.manifest_ceiling_for(&spawn).is_some(),
            "a declared manifest ceiling is what authorises the enumeration"
        );
        assert!(
            manifest
                .manifest_ceiling_for(&task_spawn_named("Read", "read AGENTS.md"))
                .is_none(),
            "and only for the tool it names"
        );
    }

    /// A manifest count that could not be taken ALLOWS, and is not read as zero.
    ///
    /// `None` is could-not-look: a tree the boundary could not enumerate has
    /// established nothing about what a prompt names, and refusing on it would
    /// turn an unreadable checkout into a policy verdict. Distinct from `Some(0)`,
    /// which is counted and names nothing — also an allow here, but for the
    /// opposite reason, which is why both are asserted.
    #[test]
    fn a_manifest_that_could_not_be_counted_allows() {
        let policy = ceiling_policy(vec![manifest_row("manifest", "Task", 2)]);
        let spawn = task_spawn("read AGENTS.md");
        assert!(matches!(
            manifest_ceiling(&policy, &spawn, None),
            Decision::Allow
        ));
        assert!(matches!(
            manifest_ceiling(&policy, &spawn, Some(0)),
            Decision::Allow
        ));
        assert!(
            matches!(manifest_ceiling(&policy, &spawn, Some(2)), Decision::Allow),
            "exactly at the cap passes, the same boundary the token unit inherits"
        );
        assert!(matches!(
            manifest_ceiling(&policy, &spawn, Some(3)),
            Decision::Deny(_)
        ));
    }

    /// The ceiling boundary is `<=`, inherited from `budget::Report::over_budget`
    /// rather than decided again (CLOUD-925 §1).
    ///
    /// Both sides, because one side alone cannot see which way the comparison
    /// leans — and which side of a boundary is inclusive is precisely the detail
    /// that drifts silently.
    ///
    /// Fails by: turning the ceiling's `>` into `>=`.
    #[test]
    fn exactly_at_the_ceiling_passes_and_one_over_refuses() {
        let capped = ceiling_policy(vec![ceiling_row("cap", "Task", 100)]);
        let mut measured = 0;
        assert!(
            matches!(
                ceiling_rules(&capped, &task_spawn(&"x".repeat(400)), &mut measured),
                Decision::Allow
            ),
            "exactly at budget passes"
        );
        assert!(
            matches!(
                ceiling_rules(&capped, &task_spawn(&"x".repeat(404)), &mut measured),
                Decision::Deny(_)
            ),
            "one estimated token over the cap refuses"
        );
        assert_eq!(
            measured, 2,
            "both calls were measured, and neither was skipped"
        );
    }

    /// A projection the host did not send is COULD-NOT-LOOK, never an empty
    /// payload — so the row does not fire and nothing is counted.
    ///
    /// Collapsing the two would make a ceiling fire on every call as though it
    /// had measured one, which is CLOUD-251's vacuous pass on a new surface.
    #[test]
    fn an_absent_projection_is_not_measured_as_empty() {
        let capped = ceiling_policy(vec![ceiling_row("cap", "Task", 0)]);
        // A `Task` call carrying no `prompt` at all: the row selects the tool and
        // finds nothing to measure. A cap of 0 makes this unambiguous — an empty
        // string estimates to 0 tokens, which `<=` would ALLOW, so allowing here
        // proves nothing on its own. The counter is what distinguishes them.
        let no_prompt = envelope_for_tool("Task");
        let mut measured = 0;
        assert!(matches!(
            ceiling_rules(&capped, &no_prompt, &mut measured),
            Decision::Allow
        ));
        assert_eq!(
            measured, 0,
            "an absent projection must not be measured as an empty one"
        );
    }
    /// The same call `adjudicate_command` makes, with a waiver table applied.
    fn adjudicate_command_waiving(command: &str, waived: &crate::waiver::Live) -> Decision {
        super::adjudicate(
            &gh_policy(),
            &envelope(command),
            &Facts::none(&crate::stop::StopFacts::default(), waived),
        )
    }

    // CLOUD-610. The mediation channel's hatch, asserted on the surface that
    // grants it. `gh_policy`'s `no-merge` row denies `gh pr merge`, so each case
    // below is the same call under a different waiver table — which is the only
    // variable, and is what makes these four a decision table rather than four
    // scenarios.

    #[test]
    fn a_live_waiver_suppresses_a_mediation_deny_and_says_what_it_suppressed() {
        let decision =
            adjudicate_command_waiving("gh pr merge 42", &waiving("gh-pr-merge", "2099-01-01"));
        assert_eq!(
            decision,
            Decision::Waived(crate::waiver::Suppressed {
                rule: "gh-pr-merge".to_owned(),
                expires: "2099-01-01".to_owned(),
            })
        );
    }

    #[test]
    fn an_expired_waiver_does_not_suppress_a_mediation_deny() {
        // THE PROPERTY THE WHOLE DESIGN RESTS ON. `live` is what decides lapse,
        // at the boundary, so an expired waiver is simply absent from the table
        // this function is handed — and the deny stands with nobody having acted.
        // Asserted here, on the consuming surface, because a lapse that worked in
        // `waiver` and was then dropped on the way in would pass that suite.
        let lapsed = crate::waiver::live(
            &[crate::waiver::Waiver {
                rule: "gh-pr-merge".to_owned(),
                reason: "tracked".to_owned(),
                expires: "2020-01-01".to_owned(),
                path: None,
            }],
            crate::waiver::Date::parse("2026-08-15").unwrap(),
        );
        assert!(matches!(
            adjudicate_command_waiving("gh pr merge 42", &lapsed),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_waiver_over_another_rule_suppresses_nothing() {
        // The half that keeps the hatch narrow: membership is by rule id, so a
        // waiver is not a blanket quiet mode for the mediated channel.
        assert!(matches!(
            adjudicate_command_waiving("gh pr merge 42", &waiving("some-other-rule", "2099-01-01")),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn the_suppression_record_carries_no_command() {
        // Non-negotiable 4 on this channel: the audit line names the rule and the
        // expiry, and the thing it structurally cannot carry is the command that
        // was about to be refused.
        let Decision::Waived(suppressed) =
            adjudicate_command_waiving("gh pr merge 42", &waiving("gh-pr-merge", "2099-01-01"))
        else {
            panic!("expected a suppression");
        };
        let line = suppressed.line_text();
        assert!(!line.contains("gh pr merge"), "{line}");
        assert!(!line.contains("42"), "{line}");
        assert_eq!(line, "waived gh-pr-merge (expires 2099-01-01)");
    }

    #[test]
    fn adjudicate_reads_no_clock_even_now_that_a_waiver_can_lapse() {
        // The purity contract, pinned where it is most likely to be relocated.
        // The body between `adjudicate`'s signature and the end of `adjudicated`
        // must name no clock: a `Date` parameter, a `SystemTime`, or a call to
        // `waiver::today` would each move the lapse question into the core, which
        // is the answer CLOUD-606 rejected by name.
        let source = include_str!("hook.rs");
        let start = source
            .find("pub fn adjudicate(")
            .expect("adjudicate is defined here");
        let end = source[start..]
            .find("/// The text a host reads for one refusal")
            .expect("the chain ends before deny_text");
        let body = &source[start..start + end];
        for clock in ["SystemTime", "waiver::today", "today()", "Date"] {
            assert!(
                !body.contains(clock),
                "adjudicate must read no clock, and it named {clock}"
            );
        }
    }

    fn adjudicate_command(command: &str) -> Decision {
        adjudicate(
            &gh_policy(),
            &envelope(command),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
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
            // FIRST SIGHTING, because that is the projection a reader meets when
            // the class is new to them — the one these assertions are about. The
            // repeat rendering has its own cases, where the difference IS the
            // subject rather than incidental to it.
            Decision::Deny(refusal) => deny_text(&refusal, BYPASS_ENV, true, None),
            // An `Ask` is not a deny, and collapsing the two here would let a
            // row that silently started escalating keep passing every assertion
            // below about what a refusal says. A `Waived` is not one either, and
            // for a sharper reason: it is a deny that was let through, so folding
            // it in here would let a suppression pass every assertion about what
            // a refusal says while the call actually ran.
            Decision::Ask(_) | Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {
                panic!("expected a deny")
            }
        }
    }

    /// The refusal a deny carries, for the assertions that are about the value
    /// rather than its rendering.
    fn denial(decision: Decision) -> Refusal {
        match decision {
            Decision::Deny(refusal) => refusal,
            Decision::Ask(_) | Decision::Allow | Decision::Waived(_) | Decision::Preapproved(_) => {
                panic!("expected a deny")
            }
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

    /// One program-only `shape` row and nothing else (CLOUD-401).
    ///
    /// Deliberately NOT shared with the receipt cases further down, and not
    /// parameterised over a helper that serves both: the same window arithmetic
    /// was wrong in two matchers, character for character, so a fix applied to
    /// one site must leave the other site's cases red.
    fn program_only_shape_policy() -> Policy {
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![shape("no-bare-cargo", "cargo", None)],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    fn program_only_shape_denies(command: &str) -> bool {
        matches!(
            adjudicate(
                &program_only_shape_policy(),
                &envelope(command),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Deny(_)
        )
    }

    #[test]
    fn a_program_only_shape_pattern_denies_any_invocation() {
        // THE SILENT NO-OP REGRESSION. `pattern = "cargo"` reads as "any cargo
        // invocation", loaded clean, was accepted by `validate` — and matched
        // nothing, ever, because `windows(0.max(1))` compared one-element
        // windows against an empty slice.
        assert!(program_only_shape_denies("cargo test -p batten"));
    }

    #[test]
    fn a_program_only_shape_pattern_denies_a_flags_only_invocation() {
        // The second, independent path to the same silence: with every flag
        // dropped these carry no operand words at all, so the flag-stripping
        // must not be what decides them. An argument-less reach is still a
        // reach.
        assert!(program_only_shape_denies("cargo --version"));
        assert!(program_only_shape_denies("cargo"));
    }

    #[test]
    fn a_program_only_shape_pattern_does_not_reach_through_mise_run() {
        // The sanctioned surface, and it stays open by the PROGRAM TOKEN rather
        // than by luck: `mise run` names a task, so `effective_program` stops at
        // `mise` and a row keyed on `cargo` never gets as far as its operands.
        // This is the case that makes a program-only row usable at all — one
        // that denied the mediated form too would ban the toolchain outright.
        assert!(!program_only_shape_denies("mise run test"));
        assert!(!program_only_shape_denies("mise run verify"));
    }

    #[test]
    fn a_program_only_shape_pattern_fires_through_mise_exec() {
        // `mise exec` IS looked through, so the effective program here is
        // `cargo` and the row fires. Pinned as behaviour rather than left
        // implicit, because it is the whole reason a "no bare cargo" row cannot
        // be spelled `program == "cargo"`: that reading denies the mediated
        // form, and the predicate has to be "reached WITHOUT a mise mediator".
        assert!(program_only_shape_denies("mise exec -- cargo test"));
        assert!(program_only_shape_denies(
            "mise exec rust@1.85 -- cargo build"
        ));
    }

    /// The program-only row again, this time carrying the mediator requirement
    /// (CLOUD-271). Same row shape as `program_only_shape_policy`, one key more,
    /// so the pair of policies isolates what the key changes.
    fn require_via_policy() -> Policy {
        let mut rule = shape("no-bare-cargo", "cargo", None);
        rule.require_via = Some(crate::rules::RequireVia::Mise);
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    fn require_via_denies(command: &str) -> bool {
        matches!(
            adjudicate(
                &require_via_policy(),
                &envelope(command),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Deny(_)
        )
    }

    #[test]
    fn require_via_denies_the_unmediated_reach() {
        assert!(require_via_denies("cargo test -p batten"));
        assert!(require_via_denies("cargo build"));
    }

    #[test]
    fn require_via_allows_the_mediated_reach() {
        // The distinction the key exists for. `effective_program` looks through
        // `mise exec`, so both of these resolve to the program `cargo` and the
        // shape half of the row matches identically -- the mediator is read
        // from the segment as written, which is the one place they still differ.
        assert!(!require_via_denies("mise exec -- cargo test -p batten"));
        assert!(!require_via_denies("mise x -- cargo build"));
        assert!(!require_via_denies("mise run test:cargo"));
    }

    #[test]
    fn a_wrapper_does_not_launder_an_unmediated_reach() {
        // `effective_program` steps past these to find `cargo`, and the mediator
        // is looked for in everything it stepped over -- so a wrapper cannot
        // hide the missing pin, and a mise the wrapper DOES carry still counts.
        assert!(require_via_denies("env RUSTFLAGS=-Awarnings cargo build"));
        assert!(require_via_denies("timeout 300 cargo test"));
        assert!(require_via_denies("nohup cargo build"));
        assert!(!require_via_denies("env FOO=1 mise exec -- cargo build"));
    }

    #[test]
    fn a_mediator_named_as_an_argument_is_not_a_mediator() {
        // Read from the tokens BEFORE the program, so the word appearing later
        // in the line is subject matter rather than a route.
        assert!(require_via_denies("cargo run --bin mise"));
    }

    #[test]
    fn a_row_without_require_via_is_unnarrowed() {
        // The column is optional and absence means "no mediator required", so
        // every row that predates the key keeps denying every route to its
        // program. Pinned here because a default would have silently narrowed
        // the four committed `gh` rows.
        assert!(is_deny("mise exec -- gh pr merge 42"));
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
    fn a_heredoc_binds_to_the_element_that_writes_it() {
        // THE MEASURED SHAPE (CLOUD-488, PR #375). The opener is present in the
        // command STRING and absent from the element that needed it, so nothing
        // short of a per-segment answer can tell this from the pair below.
        let parsed = segments("git commit -F - && mise run land <<'EOF'\nmsg\nEOF\n");
        assert_eq!(parsed.len(), 2);
        assert!(
            !parsed[0].input_redirect,
            "git got the harness's /dev/null: {:?}",
            parsed[0]
        );
        assert!(parsed[1].input_redirect, "`land` got the message");
    }

    #[test]
    fn a_heredoc_in_the_same_element_binds_there() {
        let parsed = segments("git commit -F - <<'EOF'\nmsg\nEOF\n");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].input_redirect);
        assert_eq!(parsed[0].words, ["git", "commit", "-F", "-", "<<'EOF'"]);
    }

    #[test]
    fn every_spelling_of_an_input_redirection_binds() {
        // One field for all three, because the predicate that reads it asks "did
        // anything reach stdin here" and cannot be wrong about which.
        for command in [
            "git commit -F - < msg.txt",
            "git commit -F - <<EOF\nmsg\nEOF\n",
            "git commit -F - <<-EOF\n\tmsg\n\tEOF\n",
            "git commit -F - <<< \"$msg\"",
        ] {
            assert!(
                segments(command)[0].input_redirect,
                "`{command}` binds stdin"
            );
        }
        assert!(
            !segments("git commit -F - > out.log")
                .pop()
                .unwrap()
                .input_redirect
        );
    }

    #[test]
    fn a_heredoc_body_is_not_shell() {
        // CLOUD-723, and it is a FALSE REFUSAL rather than a miss: every
        // `pipeline` row decides over these segments, so a `;` in prose split
        // the list and `verdict-not-discarded` refused correct commands — twice
        // in one session, both times on the command documenting the rule.
        let parsed = segments("cat > notes.md <<'EOF'\nfirst; then nohup x &\nEOF\n");
        assert_eq!(parsed.len(), 1, "the body carried `;` and `&`: {parsed:?}");
        assert_eq!(parsed[0].words, ["cat", ">", "notes.md", "<<'EOF'"]);
        assert_eq!(parsed[0].terminator, None);
    }

    #[test]
    fn a_here_string_opens_no_body() {
        // `<<<` read as a heredoc starts a skip that never terminates, which
        // swallows the rest of the command — so the gate stops looking and the
        // suite stays green. Everything after must still be judged.
        let parsed = segments("echo x <<< \"$msg\" && git commit");
        assert_eq!(parsed.len(), 2, "the `&&` survived: {parsed:?}");
        assert_eq!(parsed[1].words, ["git", "commit"]);
    }

    #[test]
    fn a_quoted_heredoc_opener_is_not_one() {
        // Decided by the SAME quote state the words are, which is why this walks
        // the string once rather than scrubbing it first: a pre-pass has no
        // quote state to consult and would skip to a delimiter that never comes.
        let parsed = segments("echo \"<<EOF\" && git commit");
        assert_eq!(parsed.len(), 2, "nothing was swallowed: {parsed:?}");
        assert_eq!(parsed[1].words, ["git", "commit"]);
    }

    #[test]
    fn two_openers_on_one_line_close_in_order() {
        let parsed = segments("cat <<A <<B && git commit\nfirst\nA\nsecond\nB\n");
        assert_eq!(parsed.len(), 2, "{parsed:?}");
        assert_eq!(parsed[1].words, ["git", "commit"]);
    }

    #[test]
    fn an_unterminated_heredoc_runs_to_the_end() {
        // What bash does with it. The alternative — treating the remainder as
        // shell — is the CLOUD-723 direction, and it is the one that produces a
        // refusal rather than a miss.
        let parsed = segments("cat <<'EOF'\nfirst; then nohup x &\n");
        assert_eq!(parsed.len(), 1, "{parsed:?}");
        assert_eq!(parsed[0].words, ["cat", "<<'EOF'"]);
    }

    #[test]
    fn a_shift_operator_opens_no_body() {
        // `<< ` with no delimiter word is arithmetic or a typo, and reading a
        // delimiter anyway starts a skip with nothing that can close it.
        let parsed = segments("echo $((1 << 2)) && git commit");
        assert_eq!(parsed.len(), 2, "{parsed:?}");
        assert_eq!(parsed[1].words, ["git", "commit"]);
    }

    #[test]
    fn the_binding_does_not_carry_across_a_separator() {
        // The reset is the predicate: without it the element AFTER a redirected
        // one inherits the binding, which is the measured shape read backwards.
        let parsed = segments("cat < in.txt | git commit -F -");
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].input_redirect);
        assert!(!parsed[1].input_redirect, "{parsed:?}");
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
        assert_eq!(envelope.raw_tool, "Bash");
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
                &Policy::declaring_nothing(Harness::ExitCode),
                &envelope("gh pr merge 42"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn the_deny_names_the_rule_and_its_class() {
        // Acceptance (c), as CLOUD-1286 leaves it. The id is still what a
        // reviewer looks up in `batten.toml` and still travels; the row's own
        // prose and the hatch do not, because neither varies between firings and
        // both are one `batten policy explain` away.
        let decision = adjudicate_command("gh pr merge 42");
        let refusal = denial(decision.clone());
        let reason = denial_text(decision);
        assert!(reason.contains("gh-pr-merge"), "names the rule: {reason}");
        assert!(
            reason.contains("call name refused"),
            "and the class, which is what carries the why now: {reason}"
        );
        assert!(
            !reason.contains(BYPASS_ENV),
            "the hatch sentence is off the hot path: {reason}"
        );
        // The row's prose is not lost, it is dereferenced — asserted on the
        // typed field so this case still fails if a deny stops carrying it.
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("use the sanctioned path for gh-pr-merge"),
        );
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
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &policy,
                &envelope("gh pr merge 42"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule.clone()],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &advisory,
                &call,
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow,
            "a warn row does not block a mediated call on its own"
        );

        let promoted = Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: true,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        assert!(
            matches!(
                adjudicate(
                    &promoted,
                    &call,
                    false,
                    &crate::facts::Look::CouldNotLook,
                    &crate::facts::Look::CouldNotLook,
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
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![
                shape("first", "gh pr merge", None),
                shape("second", "gh pr merge", None),
            ],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
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
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
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
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    /// A policy carrying one registered module, compiled from a real file.
    ///
    /// Built through [`crate::policy::load`] rather than by hand, because a
    /// `Module` with no compiled engine is not a thing the boundary can produce
    /// and a test that fabricated one would be exercising a state the loader
    /// refuses.
    ///
    /// **Keyed by CASE as well as by process.** Every caller writes `gate.rego`,
    /// so a directory keyed on the pid alone is shared by all of them — and the
    /// stock harness runs a file's cases as threads in ONE process, so one case
    /// can overwrite the module between another's write and its `policy::load`.
    /// That surfaces as an intermittent wrong-module failure which reads as a
    /// policy defect rather than as a fixture collision. `cargo nextest`, which
    /// `test:cargo` uses, forks per case and hides it; the hazard is real for
    /// anyone running the suite any other way.
    fn module_policy(case: &str, source: &str) -> Policy {
        let dir =
            std::env::temp_dir().join(format!("batten-hook-policy-{case}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        std::fs::write(dir.join("gate.rego"), source).expect("write module");
        let row: Rule = serde_json::from_value(serde_json::json!({
            "id": "module-gate",
            "kind": "policy",
            "scope": "mediated_call",
            "module": "gate.rego",
            "severity": "deny",
        }))
        .expect("a policy row the loader accepts");
        // Every token this module's fixtures raise. Declared rather than
        // skipped, because registry equality is exactly what `load` is being
        // asked to enforce here — a fixture loading through a hole would be
        // testing the hole.
        // Only the tokens THIS source raises. Registry equality runs in both
        // directions, so declaring the other fixture's class here would be dead
        // vocabulary and the load would refuse it — which is the check doing its
        // job, and the reason the list is derived from the module rather than
        // shared across the cases.
        let fixture_verdicts = ["verify receipt stale", "refused by themodule"]
            .into_iter()
            .filter(|id| source.contains(id))
            .map(|id| crate::verdict::DeclaredVerdict {
                id: id.to_owned(),
                gloss: format!("the fixture class {id}"),
                class: format!("What {id} means, at length."),
                routes: vec![crate::verdict::Route {
                    id: "read the authority".to_owned(),
                    kind: crate::verdict::RouteKind::Document,
                    target: "batten.toml".to_owned(),
                    precondition: None,
                }],
                successor: None,
                withdrawn: None,
            })
            .collect::<Vec<crate::verdict::DeclaredVerdict>>();
        Policy {
            harness: Harness::ExitCode,
            // A module fixture, so it protects nothing and has no membership
            // question for a root to change the answer to.
            root: None,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: crate::policy::load(
                &dir,
                &[row],
                crate::policy::Vocabulary {
                    patterns: &[],
                    verdicts: &fixture_verdicts,
                    recorders: &[],
                },
                crate::policy::ModuleChecks::Run,
                None,
            )
            .expect("load"),
            // The consumer half is the fixtures' own vocabulary; the vendored
            // half is unioned in by `registry_for`, which is what the rendering
            // path reads.
            verdicts: crate::policy::registry_for(&fixture_verdicts)
                .expect("no vendored collision"),
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    /// EVERY HOOK-RESOLVABLE FACT IS PROJECTED, AND NOTHING ELSE IS.
    ///
    /// CLOUD-834's acceptance, in both directions, because the document drifts
    /// from the model the moment only one of them is checked — which is exactly
    /// how `Field`'s allowlist drifted from the envelope.
    ///
    /// The compile-time half is `call_document`'s wildcard-free match: an eighth
    /// `Fact` variant fails to build. This is the runtime half, and it is the
    /// one that catches a variant given an arm that quietly returns `None`.
    ///
    /// Fails by: dropping a `Some(...)` arm to `None`, or inventing a `facts`
    /// key that no `Fact` variant names.
    #[test]
    fn every_hook_resolvable_fact_is_projected_under_its_own_token() {
        let document = call_document(
            &envelope("git status"),
            &Facts::none(
                &crate::stop::StopFacts::default(),
                &crate::waiver::Live::new(),
            ),
        )
        .expect("the document serializes");
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the document parses");
        let facts = parsed
            .get("facts")
            .and_then(serde_json::Value::as_object)
            .expect("the document carries a facts object");

        let expected: std::collections::BTreeSet<&str> = crate::facts::Fact::ALL
            .iter()
            .filter(|fact| fact.class().resolvable_on(crate::facts::Surface::Hook))
            .map(|fact| fact.as_str())
            .collect();
        let projected: std::collections::BTreeSet<&str> =
            facts.keys().map(String::as_str).collect();

        assert_eq!(
            projected, expected,
            "the projected keys and the model's hook-resolvable facts disagree"
        );
        assert!(
            !expected.is_empty(),
            "a vacuous pass: the model says no fact is resolvable on the hook \
             surface, so this case would hold over an empty document"
        );
    }

    /// A fact the boundary could not resolve is `null`, never absent.
    ///
    /// One shape always. `Look::CouldNotLook` and "resolved to nothing" are
    /// different answers, and a Rego predicate distinguishes them only if the
    /// key is present — `input.facts.receipts == null` against
    /// `not input.facts.receipts`. A document whose keys come and go cannot be
    /// written against at all.
    ///
    /// Fails by: skipping the insert when the `Option` is `None`.
    #[test]
    fn a_fact_the_boundary_could_not_resolve_is_null_rather_than_absent() {
        let document = call_document(
            &envelope("git status"),
            &Facts::none(
                &crate::stop::StopFacts::default(),
                &crate::waiver::Live::new(),
            ),
        )
        .expect("the document serializes");
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the document parses");
        for could_not_look in ["receipts", "keys"] {
            assert_eq!(
                parsed
                    .get("facts")
                    .and_then(|facts| facts.get(could_not_look)),
                Some(&serde_json::Value::Null),
                "`{could_not_look}` must be present and null, never missing"
            );
        }
    }

    /// The two non-answers are DIFFERENT VALUES that project to the SAME bytes.
    ///
    /// CLOUD-787's whole claim in one case. Before it, `receipts` and `keys`
    /// spelled could-not-look and nothing-judgeable as one `None`, so no call
    /// site could tell them apart; they are `Look::CouldNotLook` and
    /// `Look::IsNot` now, and `as_str` separates them.
    ///
    /// The second half is what makes this a type substitution rather than a
    /// change: both still project as `null`, exactly what the `Option` spelling
    /// emitted, so no consumer module and no schema moved. Giving Rego its own
    /// spelling of the distinction is a widening of the document and belongs to
    /// whichever row needs a predicate on it.
    ///
    /// Fails by: collapsing the two arms at the call site — give `IsNot` the
    /// same token as `CouldNotLook` and the first assertion goes red; project
    /// `IsNot` as anything but `null` and the second does.
    #[test]
    fn the_two_non_answers_are_distinct_values_projecting_identical_bytes() {
        let is_not: ReceiptFacts = crate::facts::Look::IsNot;
        let could_not: ReceiptFacts = crate::facts::Look::CouldNotLook;
        assert_ne!(
            is_not.as_str(),
            could_not.as_str(),
            "looked-and-found-nothing must not share a token with could-not-look"
        );
        assert!(!is_not.could_not_look() && could_not.could_not_look());

        let stop = crate::stop::StopFacts::default();
        let waived = crate::waiver::Live::new();
        let rendered = |receipts: &ReceiptFacts, keys: &KeyFacts| {
            let document = call_document(
                &envelope("git status"),
                &Facts {
                    receipts,
                    keys,
                    ..Facts::none(&stop, &waived)
                },
            )
            .expect("the document serializes");
            let parsed: serde_json::Value =
                serde_json::from_str(&document).expect("the document parses");
            parsed["facts"].clone()
        };
        assert_eq!(
            rendered(&crate::facts::Look::IsNot, &crate::facts::Look::IsNot),
            rendered(
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook
            ),
            "the split is a Rust distinction; the policy input is unchanged"
        );
        assert_eq!(
            rendered(&crate::facts::Look::IsNot, &crate::facts::Look::IsNot)["receipts"],
            serde_json::Value::Null
        );
    }

    /// The projection carries the VERDICT token, never the receipt statement.
    ///
    /// A receipt records a subject commit and the `origin/main` it was linear
    /// against. A predicate decides on `valid` / `stale-head` / `stale-main` /
    /// `missing`, which is the whole of what `receipt status` reports, and
    /// widening the projection to the statement would put git object ids in
    /// front of consumer-authored code for no predicate that needs them.
    ///
    /// Fails by: serializing the statement instead of `Validity::as_str`.
    #[test]
    fn a_receipt_projects_its_verdict_token_and_nothing_else() {
        let mut verdicts = std::collections::BTreeMap::new();
        verdicts.insert("verify".to_owned(), crate::receipt::Validity::StaleHead);
        let document = call_document(
            &envelope("git status"),
            &Facts {
                receipts: &crate::facts::Look::Is(verdicts),
                ..Facts::none(
                    &crate::stop::StopFacts::default(),
                    &crate::waiver::Live::new(),
                )
            },
        )
        .expect("the document serializes");
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("the document parses");
        assert_eq!(
            parsed["facts"]["receipts"]["verify"],
            serde_json::Value::from("stale-head")
        );
    }

    /// A MODULE CAN DECIDE ON A PROJECTED FACT, and goes green when it changes.
    ///
    /// CLOUD-834 §7(a). The end-to-end case: before this row a predicate could
    /// decide on the call and nothing about the checkout, so a module reading
    /// `input.facts` matched nothing and every such gate silently allowed.
    ///
    /// Both directions in one pair, because a deny alone would also be produced
    /// by a module that ignored the fact and denied unconditionally.
    #[test]
    fn a_module_decides_on_a_projected_fact() {
        const READS_A_RECEIPT: &str = r#"
package batten.receipts

import rego.v1

rules contains "verify-receipt-stale"

violation contains {
	"rule": "verify-receipt-stale",
	"verdict": "verify receipt stale",
} if {
	input.facts.receipts.verify == "stale-head"
}
"#;
        let policy = module_policy("projected-fact", READS_A_RECEIPT);
        let stale = {
            let mut verdicts = std::collections::BTreeMap::new();
            verdicts.insert("verify".to_owned(), crate::receipt::Validity::StaleHead);
            crate::facts::Look::Is(verdicts)
        };
        let fresh = {
            let mut verdicts = std::collections::BTreeMap::new();
            verdicts.insert("verify".to_owned(), crate::receipt::Validity::Valid);
            crate::facts::Look::Is(verdicts)
        };
        let envelope = envelope("git push");

        let denied = adjudicate(
            &policy,
            &envelope,
            false,
            &stale,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        );
        assert!(
            matches!(denied, Decision::Deny(_)),
            "a module reading a projected fact must be able to decide on it: {denied:?}"
        );

        // THE DISCRIMINATOR. Same module, same call, one changed fact.
        let allowed = adjudicate(
            &policy,
            &envelope,
            false,
            &fresh,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        );
        assert_eq!(
            allowed,
            Decision::Allow,
            "the deny above must come from the FACT, not from the module firing \
             unconditionally"
        );

        // AND THE WITHHELD CASE (§7(a)): a boundary that could not look
        // resolves to null, which the predicate must not read as a match.
        let unresolved = adjudicate(
            &policy,
            &envelope,
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        );
        assert_eq!(
            unresolved,
            Decision::Allow,
            "could-not-look must not read as the verdict the predicate tests for"
        );
    }

    /// A bundle ROOT joins `protected`, and so does everything under it.
    ///
    /// **CLOUD-833's sharpest consequence.** §8's security property is that
    /// policy loads out-of-band of the model's context window, so an agent's
    /// context can never influence the rules it is judged by. That held for a
    /// named `module` because the path was in the config. A bundle is a FOLDER
    /// whose membership changes without a config edit, so the property would
    /// have held for named files and silently lapsed for a folder — an agent
    /// could add or edit a `.rego` under an enabled root and change what judges
    /// it.
    ///
    /// Fails by: deriving the files present at load instead of the root glob,
    /// which covers today's modules and nothing added afterwards.
    #[test]
    fn a_bundle_root_and_its_members_are_protected_paths() {
        let bundle: Rule = serde_json::from_value(serde_json::json!({
            "id": "repo-policy",
            "kind": "policy",
            "scope": "tree",
            "bundle": "policy/",
            "documents": ["batten.toml"],
            "severity": "deny",
        }))
        .expect("a tree-scoped policy row");
        let derived = policy_protected_paths(&bundle);
        assert!(
            derived.iter().any(|path| path == "policy"),
            "the root itself, so the folder cannot be replaced: {derived:?}"
        );
        assert!(
            derived.iter().any(|path| path == "policy/**"),
            "AND everything under it, so a module added after load is covered \
             too — enumerating the files present would lapse the moment one \
             arrived: {derived:?}"
        );
    }

    /// A `module` row still contributes exactly its file.
    ///
    /// The other half of the pair: widening the derivation must not have turned
    /// a named file into a folder glob, which would protect paths the config
    /// never named.
    #[test]
    fn a_named_module_still_contributes_only_itself() {
        let named: Rule = serde_json::from_value(serde_json::json!({
            "id": "one-module",
            "kind": "policy",
            "scope": "mediated_call",
            "module": "policy/gate.rego",
            "severity": "deny",
        }))
        .expect("a module row");
        assert_eq!(policy_protected_paths(&named), vec!["policy/gate.rego"]);
    }

    /// The wiring assertion (CLOUD-418), and the one the six `policy_modules`
    /// cases cannot make: those exercise `policy::load` and `policy::deny`
    /// directly, so every one of them passes on a chain that never calls
    /// `policy_rules`. This drives the real entry point.
    #[test]
    fn a_module_denies_through_the_adjudication_chain() {
        const DENIES_A_COMMAND: &str = r#"
package batten

import rego.v1

deny contains "refused by themodule" if {
    contains(input.call.command, "forbidden")
}
"#;
        let policy = module_policy("adjudication-chain", DENIES_A_COMMAND);

        let decision = adjudicate(
            &policy,
            &envelope("run forbidden thing"),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        );
        match decision {
            Decision::Deny(refusal) => {
                let rendered = format!("{refusal:?}");
                // THE TOKEN AND ITS GLOSS TRAVEL (CLOUD-1050). It used to be
                // the module's own prose; now the class is a name the registry
                // resolves, so this asserts the name rather than a substring of
                // a sentence — an assertion that survives a reworded gloss and
                // fails a changed class, which is the discrimination the old one
                // had backwards.
                assert!(
                    rendered.contains("refused by themodule"),
                    "the class the module raised travels: {rendered}"
                );
                // THE GLOSS DOES NOT (CLOUD-1286). It was inlined on every
                // firing and it is the class's own definition, which the
                // registry declares once and `batten policy explain` prints on
                // request. Asserted in the negative rather than dropped, because
                // a silent re-inlining is the exact regression this row exists
                // to stop and nothing else in this test would see it.
                assert!(
                    !rendered.contains("the fixture class"),
                    "and the gloss is dereferenced rather than carried: {rendered}"
                );
                assert!(
                    !rendered.contains("deny contains"),
                    "no byte of the policy body reaches the refusal (rule 4): {rendered}"
                );
            }
            other => panic!("the chain did not reach the policy gate: {other:?}"),
        }

        // The same policy, a command it does not match: the gate ran and had no
        // answer, which must not be a deny.
        assert_eq!(
            adjudicate(
                &policy,
                &envelope("run something else"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow,
            "a module that matches nothing allows"
        );
    }

    /// CLOUD-763's fourth bound, DERIVED rather than configured.
    ///
    /// §8's security property is that an agent's context can never influence the
    /// rules it is judged by, and a module a consumer forgot to list in
    /// `protected` is exactly that influence. Registering it protects it, so
    /// "registered but unprotected" has no spelling.
    ///
    /// Driven through `resolve` rather than a hand-built `Resolved`, because the
    /// derivation lives in `from_resolved`: a struct literal would assert the
    /// field the test set rather than the one the loader computes.
    #[test]
    fn a_registered_module_is_protected_without_being_listed() {
        let dir = std::env::temp_dir().join(format!("batten-protect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        std::fs::write(
            dir.join("guard.rego"),
            "package batten\n\nimport rego.v1\n\ndeny contains \"x\" if { false }\n",
        )
        .expect("write module");
        std::fs::write(
            dir.join("batten.toml"),
            // NOTHING in `protected` — that absence is the premise.
            "version = 1\n\n[[rule]]\nid = \"policy-guard\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\nmodule = \"guard.rego\"\nseverity = \"deny\"\n",
        )
        .expect("write authority");

        let resolved = crate::resolve::resolve(&dir, &crate::resolve::Overrides::default())
            .expect("the authority resolves");
        assert!(
            resolved.protected.is_empty(),
            "the consumer declared no protected paths, which is what makes this a real case"
        );

        let policy =
            Policy::from_resolved(&resolved, Harness::ExitCode, &dir, None).expect("policy loads");
        assert!(
            policy.protected.contains("guard.rego"),
            "a registered module is protected by construction, not by configuration"
        );
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
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        )
    }

    /// The claim row: a write-triggered, branch-keyed receipt (CLOUD-444).
    fn claim_policy() -> Policy {
        let mut rule = shape("claim-needs-receipt", "unused", None);
        rule.kind = RuleKind::Receipt;
        rule.pattern = None;
        rule.trigger = Some(ReceiptTrigger::Write);
        rule.key = Some(ReceiptKey::Branch);
        rule.reason = Some("pipe the issue payload to `mise run claim-check`".to_owned());
        rule.checks = Some(vec!["claim".to_owned()]);
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    fn adjudicate_write(facts: &ReceiptFacts) -> Decision {
        adjudicate(
            &claim_policy(),
            &write_envelope("Write", "crates/batten/src/new.rs"),
            false,
            facts,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        )
    }

    #[test]
    fn a_write_triggered_row_fires_on_a_write_that_carries_no_command() {
        // The gap this closes: every write returned Allow before the command
        // gate ran, so a receipt row could never be a precondition for editing.
        assert!(matches!(
            adjudicate_write(&crate::facts::Look::Is(resolved(&[(
                "claim",
                Validity::Missing
            )]))),
            Decision::Deny(_)
        ));
        assert_eq!(
            adjudicate_write(&crate::facts::Look::Is(resolved(&[(
                "claim",
                Validity::Valid
            )]))),
            Decision::Allow
        );
    }

    #[test]
    fn a_write_triggered_row_ignores_a_command_and_a_command_row_ignores_a_write() {
        // The two triggers select disjointly, which is what keeps adding one from
        // charging the other's calls.
        assert_eq!(
            adjudicate(
                &claim_policy(),
                &envelope("gh pr ready 42"),
                false,
                &crate::facts::Look::Is(resolved(&[("claim", Validity::Missing)])),
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow,
            "a write-triggered row must not judge a command"
        );
        assert_eq!(
            adjudicate(
                &receipt_policy(),
                &write_envelope("Write", "notes.md"),
                false,
                &crate::facts::Look::Is(resolved(&[("verify", Validity::Missing)])),
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow,
            "a command-triggered row must not judge a write"
        );
    }

    #[test]
    fn a_write_the_boundary_did_not_judge_is_allowed() {
        // Neither non-answer is a receipt question here, and both allow — the
        // load-bearing half: a gate that refused them would refuse every write
        // in the container and be switched off within the hour.
        //
        // CLOUD-787 split what this comment used to list as one value. A
        // git-ignored path, one outside the repository and one inside `.git`
        // are `IsNot` — the boundary looked and there is nothing to judge — and
        // a detached HEAD is `CouldNotLook`. The assertion is unchanged in both
        // arms; only the spelling of the fact moved.
        assert_eq!(
            adjudicate_write(&crate::facts::Look::CouldNotLook),
            Decision::Allow
        );
        assert_eq!(
            adjudicate_write(&crate::facts::Look::IsNot),
            Decision::Allow
        );
    }

    #[test]
    fn a_branch_keyed_refusal_says_branch_rather_than_commit() {
        // The wrong pointer this avoids: "no receipt for this commit" sends the
        // reader looking for a per-commit step, when what is missing is a claim
        // the whole branch shares.
        let reason = denial_text(adjudicate_write(&crate::facts::Look::Is(resolved(&[(
            "claim",
            Validity::Missing,
        )]))));
        assert!(reason.contains("branch"), "names the keying: {reason}");
        assert!(
            !reason.contains("this commit"),
            "must not name a commit: {reason}"
        );
        // THE ROUTE IS NO LONGER ON THIS LINE, and that is CLOUD-1286 rather
        // than a loss: `mise run claim-check` is the class's declared route, it
        // does not vary between firings, and `batten policy explain` prints it
        // along with every other route the class carries. What must stay inline
        // is the pointer — the check whose receipt is missing — because that is
        // the half that changes per firing and the half a reader acts on.
        assert!(reason.contains("claim"), "names the check: {reason}");
        assert!(
            !reason.contains("Fix:"),
            "and dereferences the remedy rather than inlining it: {reason}"
        );
    }

    #[test]
    fn a_write_row_resolves_its_checks_with_its_own_keying() {
        // What the boundary needs in order to look in the right place at all: a
        // HEAD-keyed receipt lives in the content store, a branch-keyed one
        // beside the branch.
        let required = claim_policy().required_checks_for(&write_envelope("Write", "crates/x.rs"));
        assert_eq!(required.get("claim"), Some(&ReceiptKey::Branch));
        assert_eq!(
            receipt_policy()
                .required_checks_for(&envelope("gh pr ready 42"))
                .get("verify"),
            Some(&ReceiptKey::Head)
        );
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
                .required_checks_for(&envelope("gh pr view 42"))
                .is_empty(),
            "a command no receipt row matches must resolve nothing"
        );
    }

    #[test]
    fn a_write_resolves_no_checks_unless_a_row_asked_for_writes() {
        // The write matcher pays the same toll otherwise. Since CLOUD-444 a row
        // CAN ask for writes, so the assertion is about this policy's rows —
        // command-triggered, therefore silent on a write — rather than about the
        // trigger being unreachable.
        assert!(
            receipt_policy()
                .required_checks_for(&write_envelope("Write", "notes.md"))
                .is_empty()
        );
    }

    #[test]
    fn a_matching_command_resolves_exactly_the_rows_checks() {
        assert_eq!(
            receipt_policy()
                .required_checks_for(&envelope("gh pr ready 42"))
                .into_keys()
                .collect::<Vec<String>>(),
            vec!["linear-check".to_owned(), "verify".to_owned()],
        );
    }

    #[test]
    fn a_row_matched_by_two_segments_is_still_one_obligation() {
        // Deduplicated by row, not by name, so a command naming the same
        // trigger twice does not resolve the same receipt twice.
        assert_eq!(
            receipt_policy()
                .required_checks_for(&envelope("gh pr ready 1 && gh pr ready 2"))
                .into_keys()
                .collect::<Vec<String>>(),
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
            adjudicate_ready(&crate::facts::Look::Is(resolved(&[
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
            adjudicate_ready(&crate::facts::Look::Is(resolved(&[
                ("verify", Validity::Valid),
                ("linear-check", Validity::StaleMain),
            ]))),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn all_receipts_valid_allows_the_call() {
        assert_eq!(
            adjudicate_ready(&crate::facts::Look::Is(resolved(&[
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
            adjudicate_ready(&crate::facts::Look::Is(resolved(&[(
                "verify",
                Validity::Valid
            )]))),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn no_facts_at_all_allows_because_the_boundary_could_not_look() {
        // Outside a checkout there are no git facts to judge against. Fail
        // open, the posture every retiring guard has: a guard that cannot read
        // its own precondition must not become the reason work stops. This is
        // deliberately distinct from `Look::Is(Missing)`, which denies above —
        // and, since CLOUD-787, from `IsNot`, which allows for the other reason.
        assert_eq!(
            adjudicate_ready(&crate::facts::Look::CouldNotLook),
            Decision::Allow
        );
        assert_eq!(
            adjudicate_ready(&crate::facts::Look::IsNot),
            Decision::Allow
        );
    }

    #[test]
    fn a_receipt_row_gates_only_its_own_trigger() {
        assert_eq!(
            adjudicate(
                &receipt_policy(),
                &envelope("gh pr view 42"),
                false,
                &crate::facts::Look::Is(resolved(&[("verify", Validity::Missing)])),
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }

    /// The receipt twin of [`program_only_shape_policy`]: one row whose
    /// **trigger** is a program alone (CLOUD-401).
    ///
    /// Its own row, its own policy, its own assertions. The receipt matcher
    /// carried the identical defect and nothing in the tree exercised it,
    /// because every committed `trigger` carries operands — so these cases must
    /// be able to stay red while the shape cases above go green.
    fn program_only_receipt_policy() -> Policy {
        let mut rule = shape("cargo-needs-receipt", "cargo", None);
        rule.kind = RuleKind::Receipt;
        rule.reason = Some("prove the toolchain first".to_owned());
        rule.checks = Some(vec!["toolchain".to_owned()]);
        Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        }
    }

    /// Does the program-only receipt row fire on this command? The one named
    /// check is unresolved, so a row that fires denies and a row that does not
    /// allows — which is exactly the silence being tested for.
    fn program_only_receipt_fires(command: &str) -> bool {
        matches!(
            adjudicate(
                &program_only_receipt_policy(),
                &envelope(command),
                false,
                &crate::facts::Look::Is(resolved(&[("toolchain", Validity::Missing)])),
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Deny(_)
        )
    }

    #[test]
    fn a_program_only_receipt_trigger_fires_on_any_invocation() {
        // The twin of the shape regression: a `receipt` row whose trigger names
        // a program alone was inert too, so its precondition was never demanded
        // — a gate that reads as present and asks for nothing.
        assert!(program_only_receipt_fires("cargo test -p batten"));
    }

    #[test]
    fn a_program_only_receipt_trigger_fires_on_a_flags_only_invocation() {
        assert!(program_only_receipt_fires("cargo --version"));
        assert!(program_only_receipt_fires("cargo"));
    }

    #[test]
    fn a_program_only_receipt_trigger_does_not_reach_through_mise_run() {
        assert!(!program_only_receipt_fires("mise run test"));
    }

    #[test]
    fn a_program_only_receipt_trigger_fires_through_mise_exec() {
        assert!(program_only_receipt_fires("mise exec -- cargo test"));
    }

    #[test]
    fn the_refusal_names_the_check_and_what_is_wrong_with_it() {
        // Three verdicts, three causes — which is how `ready-guard`'s three
        // hand-written deny messages survive the move into one config row.
        let Decision::Deny(refusal) = adjudicate_ready(&crate::facts::Look::Is(resolved(&[
            ("verify", Validity::Valid),
            ("linear-check", Validity::StaleHead),
        ]))) else {
            panic!("a stale receipt must deny");
        };
        let rendered = refusal.render();
        assert!(rendered.contains("linear-check"), "got: {rendered}");
        // WHAT INVALIDATED IT IS THE CLASS, not a phrase inside a sentence
        // (CLOUD-1285, then CLOUD-1286). `receipt read other` is the amend-or-
        // rebase case and `receipt read stale` is the moved-trunk one; they are
        // separate declared classes precisely so this distinction survives
        // without the prose that used to carry it, and `batten policy explain`
        // is where the words "amend" and "rebase" now live.
        assert_eq!(
            refusal.verdict(),
            Some(crate::verdict::Native::ReceiptSuperseded.id()),
            "the class must say what invalidated it; got: {rendered}"
        );
        assert!(
            rendered.contains("receipt read other"),
            "and it travels on the line: {rendered}"
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
    /// `Read` and `Write` both carry `file_path`, so a gate keyed on "the payload
    /// names a protected path" would refuse *reading* the policy file. What keeps
    /// them apart is the host's own `write_tools` table, read once in the adapter
    /// — so a read resolves no `writes` and classifies as [`Operation::Read`], and
    /// two independent facts have to agree before anything is refused.
    ///
    /// Since CLOUD-779 this is no longer the same question as "is the tool in
    /// `[[verb]]`": a consumer's verb table is one host's vocabulary, and reading
    /// its silence as "not a write" is what let three harnesses through.
    #[test]
    fn a_read_against_a_protected_path_is_allowed() {
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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

    /// Adjudicate `command` against a policy carrying exactly `verbs`.
    ///
    /// [`guarded`] pins the unqualified table; this is its sibling for the
    /// qualifier rows, so each test declares the rows it is about.
    fn guarded_by(verbs: Vec<MutatingVerb>, command: &str) -> Decision {
        adjudicate(
            &protected_policy(verbs),
            &envelope(command),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        )
    }

    #[test]
    fn a_destination_only_verb_denies_the_write_and_allows_the_read() {
        // CLOUD-442's load-bearing case, and the ALLOW is the half that matters:
        // the gate treats every operand as a candidate, so a row for a
        // destination-only program used to refuse copying a guarded file OUT —
        // a read, denied. A guard that refuses reads is one people switch off.
        let table = vec![destination_only(
            "cp",
            Some("write through the owning surface"),
        )];
        assert!(
            matches!(
                guarded_by(table.clone(), "cp draft.md batten.toml"),
                Decision::Deny(_)
            ),
            "the destination is the write"
        );
        assert_eq!(
            guarded_by(table.clone(), "cp batten.toml /tmp/backup.toml"),
            Decision::Allow,
            "copying the protected file out is a read"
        );
        // A value-taking flag leaves its value among the operands, which can only
        // ADD one — the destination is still last.
        assert!(matches!(
            guarded_by(table.clone(), "cp -m 644 draft.md batten.toml"),
            Decision::Deny(_)
        ));
        // And with no operand at all there is no last one, so nothing is a target.
        assert_eq!(guarded_by(table, "cp --help"), Decision::Allow);
    }

    #[test]
    fn a_flag_qualified_verb_denies_only_with_the_flag() {
        let table = vec![behind_flag(
            "sed",
            &["-i", "--in-place"],
            Some("change it through the owning surface"),
        )];
        for command in [
            "sed -i s/a/b/ batten.toml",
            "sed --in-place s/a/b/ batten.toml",
            "sed -i.bak s/a/b/ batten.toml",
            // The wrapper form, which the parser already looks through: in this
            // sandbox it is often the only working spelling.
            "mise exec -- sed -i s/a/b/ batten.toml",
        ] {
            assert!(
                matches!(guarded_by(table.clone(), command), Decision::Deny(_)),
                "must deny: {command}"
            );
        }
        for command in [
            "sed --version",
            "sed s/a/b/ batten.toml",
            "sed -n 1p batten.toml",
        ] {
            assert_eq!(
                guarded_by(table.clone(), command),
                Decision::Allow,
                "must allow: {command}"
            );
        }
    }

    #[test]
    fn a_subcommand_qualified_verb_denies_only_under_that_subcommand() {
        // The effective program is the same word either way, so before the column
        // existed a row for it would have refused every read it spells too.
        let table = vec![
            under_subcommand("git", "mv", Some("rename through the owning surface")),
            under_subcommand("git", "rm", Some("restore it with a checkout")),
        ];
        assert!(matches!(
            guarded_by(table.clone(), "git mv batten.toml elsewhere.toml"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            guarded_by(table.clone(), "git rm .serena/memories/core.md"),
            Decision::Deny(_)
        ));
        for command in [
            "git log --oneline batten.toml",
            "git show HEAD:batten.toml",
            "git diff batten.toml",
            "git mv src/a.rs src/b.rs",
        ] {
            assert_eq!(
                guarded_by(table.clone(), command),
                Decision::Allow,
                "must allow: {command}"
            );
        }
        // Each subcommand resolves to its OWN row, which is what makes two rows
        // for one front-end worth having: the redirect differs.
        assert_eq!(
            denial(guarded_by(table.clone(), "git mv batten.toml x.toml"))
                .fix()
                .declared_alternative(),
            Some("rename through the owning surface")
        );
        assert_eq!(
            denial(guarded_by(table, "git rm batten.toml"))
                .fix()
                .declared_alternative(),
            Some("restore it with a checkout")
        );
    }

    #[test]
    fn a_subcommand_deny_names_the_whole_action_not_just_the_front_end() {
        // A refusal naming only the front-end reads as a ban on every use of it,
        // which is the opposite of what a subcommand-qualified row says.
        let reason = denial_text(guarded_by(
            vec![under_subcommand("git", "mv", None)],
            "git mv batten.toml elsewhere.toml",
        ));
        assert!(reason.contains("git mv"), "names the action: {reason}");
        assert!(reason.contains("batten.toml"), "names where: {reason}");
    }

    #[test]
    fn a_qualified_row_narrows_the_shell_path_and_no_longer_suppresses_a_write() {
        // CLOUD-442's narrowing is about ARGV: `sed -i` writes and bare `sed`
        // reads, and only a command line can say which. A write tool names one
        // path and carries no arguments, so a qualifier has nothing to be
        // satisfied by there.
        //
        // What CHANGED in CLOUD-779 is what that unsatisfiable qualifier means.
        // It used to suppress the deny, because the `[[verb]]` row WAS the
        // predicate — so a consumer's one host's vocabulary decided whether a
        // write existed at all. It does not: `Harness::write_tools` is the host's
        // own statement that this tool writes the path it names, and a consumer
        // cannot be asked to name a host's tool inventory. The row is message
        // composition now, so a qualifier it cannot satisfy costs the refusal its
        // specific remedy and never the refusal itself.
        for row in [
            behind_flag("Write", &["-i"], None),
            under_subcommand("Write", "mv", None),
        ] {
            assert!(
                matches!(
                    adjudicate(
                        &protected_policy(vec![row]),
                        &write_envelope("Write", "batten.toml"),
                        false,
                        &crate::facts::Look::CouldNotLook,
                        &crate::facts::Look::CouldNotLook,
                        &crate::stop::StopFacts::default(),
                    ),
                    Decision::Deny(_)
                ),
                "a qualifier a write tool cannot satisfy must not read as `not a write`"
            );
        }
        // The unqualified row still denies, so this is a narrowing rather than a
        // hole: the surface did not stop working.
        assert!(matches!(
            adjudicate(
                &protected_policy(vec![verb("Write", None)]),
                &write_envelope("Write", "batten.toml"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_qualified_verb_is_judged_per_segment_like_every_other() {
        // A read in one segment must not be condemned by a write in another, and
        // — the direction that matters — a write must not be excused by a read.
        let table = vec![
            behind_flag("sed", &["-i"], None),
            destination_only("cp", None),
        ];
        assert_eq!(
            guarded_by(
                table.clone(),
                "sed -n 1p batten.toml; cp batten.toml /tmp/x"
            ),
            Decision::Allow
        );
        assert!(matches!(
            guarded_by(table, "cat /tmp/x; sed -i s/a/b/ batten.toml"),
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
    fn an_undeclared_program_against_a_protected_path_is_refused() {
        // THIS CASE ASSERTED THE OPPOSITE UNTIL CLOUD-1141, and the reversal is
        // the point rather than a detail. It read:
        //
        //   "The table is the authority on what mutates. `cat` reads, so it is
        //    not this gate's business even against a protected path — the
        //    conservative reading of an unknown program belongs to the
        //    consumer's config, not to a guess here."
        //
        // The second half of that is right and is what the fix implements: the
        // conservative reading DOES belong to the consumer's config. What was
        // wrong is how "belongs to the config" was spelled — as ALLOW BY
        // DEFAULT, so a config that never spoke got the permissive answer and
        // every program nobody had enumerated wrote a protected path unrefused.
        // Measured: `python3 write.py batten.toml` and `perl -pi -e … batten.toml`
        // were allowed where `echo >`, `sed -i` and `tee` were denied.
        //
        // Now the consumer says which programs read, in `protected_readers`, and
        // silence means refuse. No guess was added — a declaration is required.
        // This fixture declares no readers, which is the strictest setting and
        // why `cat` refuses here while the committed config allows it.
        assert!(matches!(
            guarded("cat .serena/memories/core.md"),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn a_declared_reader_against_a_protected_path_is_allowed() {
        // The other half, and the one that decides whether the gate survives
        // contact with daily use: a guard that refuses ordinary reads is one
        // people switch off. A reader the consumer declared is allowed against
        // the same path the undeclared program above was refused for, which is
        // what makes the pair discriminate rather than either case alone.
        let mut policy = protected_policy_with(vec![verb("rm", None)], Vec::new());
        policy.protected_readers = vec!["cat".to_owned()];
        assert_eq!(
            protected_mutation(&policy, "cat .serena/memories/core.md"),
            Decision::Allow
        );
    }

    #[test]
    fn the_deny_names_the_sanctioned_mutation_declared_beside_the_verb() {
        let decision = guarded("rm .serena/memories/core.md");
        let reason = denial_text(decision.clone());
        assert!(
            reason.contains(PROTECTED_MUTATION),
            "names the gate: {reason}"
        );
        // The verb's declared redirect is the fix, and CLOUD-1286 moved it off
        // the emitted line onto the dereference. Asserted on the typed field,
        // which is the stronger read anyway: a substring could be satisfied by
        // the same words appearing in the class prose.
        assert_eq!(
            denial(decision).fix().declared_alternative(),
            Some("restore it with git"),
            "the verb's own redirect is still the fix"
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
        // because `Refusal::new` requires one.
        //
        // THE SHARED PROJECTION IS THE DECLARED LINE (CLOUD-1286): a class and
        // its pointers, the rule id among them, and nothing else. The three
        // clauses this used to require — `Refused by`, `Fix:`, and the hatch
        // sentence — were each a copy of something declared once, restated on
        // every one of a session's ~300 firings.
        //
        // The contract they enforced is NOT weakened, it MOVED, and asserting
        // that move is the whole of what remains here: every deny still owes a
        // fix, so the fix is asserted on the typed field, where it cannot be
        // satisfied by a substring and where a deny that offers nothing still
        // fails.
        for decision in [
            adjudicate_command("gh pr merge 42"),
            guarded("rm .serena/memories/core.md"),
            guarded("mv batten.toml elsewhere"),
        ] {
            let refusal = denial(decision.clone());
            assert!(
                matches!(refusal.fix(), Fix::Run(_)),
                "every deny still points to a fix: {refusal:?}"
            );
            let text = denial_text(decision);
            assert!(
                !text.starts_with("Refused by "),
                "and the emitted line carries no prefix restating the token: {text}"
            );
            assert!(
                !text.contains(" Fix: "),
                "nor the remedy, which `batten policy explain` prints: {text}"
            );
            assert!(
                text.contains(refusal.rule()),
                "the rule that fired stays inline, because two rows can raise one \
                 class and `explain` cannot say which: {text}"
            );
        }
        // THE HATCH SENTENCE IS GONE FROM EVERY DENY, which is CLOUD-437 closed
        // rather than narrowed. It was byte-identical on every firing, so it was
        // pure per-firing cost carrying no per-firing information — and the one
        // deny that used to omit it was omitting it because it was WRONG there,
        // never because the sentence was worth its price anywhere else.
        for decision in [
            adjudicate_command("gh pr merge 42"),
            guarded("rm .serena/memories/core.md"),
            guarded("mv batten.toml elsewhere"),
        ] {
            let text = denial_text(decision);
            assert!(
                !text.contains(BYPASS_ENV),
                "no deny advertises the hatch on the hot path: {text}"
            );
            assert!(
                !text.contains("batten override request"),
                "and none composes an override command line per firing: {text}"
            );
        }
    }

    #[test]
    fn a_verb_with_no_redirect_falls_back_to_the_classs_own_route() {
        // WHAT CLOUD-1050 CHANGED HERE, and it is the change the row exists for.
        //
        // This case used to assert `Fix::None` — that a verb declaring no
        // `redirect` produced a refusal whose remedy was the crate's generic "none
        // declared" line. That was CLOUD-122's contract met by CONVENTION: the
        // remedy was whatever the deny site remembered, and where it remembered
        // nothing the reader got a sentence naming no verb.
        //
        // A native refusal now names a declared class, and `verdict::validate`
        // refuses a class with no route and refuses one whose only route is an
        // override. So the third tier is no longer a generic apology: it is
        // `path write refused`'s own `patch run first`. The tiering is unchanged and
        // is asserted by its siblings — a consumer's `[[redirect]]` still wins, and
        // a verb's own `redirect` still wins over the class — this is only the
        // floor, and the floor got a verb.
        let decision = guarded("mv batten.toml elsewhere");
        let refusal = denial(decision.clone());
        assert_eq!(
            refusal.fix(),
            &Fix::Run("git restore".to_owned()),
            "the class's declared route is the floor now, not a generic apology"
        );
        assert_eq!(
            refusal.verdict(),
            Some("path write refused"),
            "and the refusal says which class it belongs to"
        );
        let reason = denial_text(decision);
        // The FIX is still on the refusal — the assertion above reads it off the
        // typed field — and it is what `explain` prints. What the hot path emits
        // is the token and the pointer and stops (CLOUD-1286), so the gloss's
        // opening parenthesis is the thing that must NOT be there.
        assert!(
            reason.starts_with("path write refused"),
            "the hot path leads with the token: {reason}"
        );
        assert!(
            !reason.contains("path write refused ("),
            "and does not inline the class's own definition after it: {reason}"
        );
        assert!(
            reason.contains("batten.toml"),
            "with the pointer inline rather than behind `explain`: {reason}"
        );
    }

    #[test]
    fn a_refusal_from_consumer_prose_still_declares_an_absent_fix_rather_than_omitting_it() {
        // The half the case above used to carry, kept on the path where it is
        // still reachable. A refusal composed from a `[[rule]]` row's own
        // `reason` is the CONSUMER's statement and names no Batten class, so
        // there is no declared route to fall back to — and the absence stays a
        // VALUE. A consumer cannot tell an omitted key from one the producer
        // forgot, which is why the explicit none is the contract.
        let refusal = crate::refusal::Refusal::new("some-row", "it fired", Fix::None);
        assert_eq!(refusal.verdict(), None);
        assert!(
            refusal
                .to_json()
                .expect("the fixed shape serializes")
                .contains("\"fix\":null"),
            "the key is present and null"
        );
        assert!(refusal.render().contains("Fix: none declared"));
        assert!(refusal.render().contains("surface that owns it"));
    }

    /// Adjudicate against the protected fixture with a declared redirect table.
    fn guarded_with(redirects: Vec<Redirect>, command: &str) -> Decision {
        adjudicate(
            &protected_policy_with(
                vec![verb("rm", Some("restore it with git")), verb("mv", None)],
                redirects,
            ),
            &envelope(command),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        )
    }

    fn redirect_row(glob: &str, mutation: &str) -> Redirect {
        Redirect {
            glob: glob.to_owned(),
            mutation: mutation.to_owned(),
            read: None,
        }
    }

    #[test]
    fn the_path_class_redirect_outranks_the_verbs_own() {
        // Tier one (CLOUD-280). `rm` declares "restore it with git", which is
        // true of most paths and useless for this one: agent memory has a write
        // surface, and that is the fact the PATH knows and the verb cannot.
        let refusal = denial(guarded_with(
            vec![redirect_row(
                ".serena/memories/**",
                "write it through the memory surface that owns it",
            )],
            "rm .serena/memories/core.md",
        ));
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("write it through the memory surface that owns it"),
            "the class the config declared beats the verb's general remedy"
        );
    }

    #[test]
    fn a_class_no_row_claims_falls_back_to_the_verbs_redirect() {
        // Tier two, and the floor this issue promised not to regress: with a
        // table declared but silent about this path, the answer is exactly what
        // CLOUD-96 shipped.
        let refusal = denial(guarded_with(
            vec![redirect_row(
                ".serena/memories/**",
                "use the memory surface",
            )],
            "rm batten.toml",
        ));
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("restore it with git"),
            "an unclaimed class leaves the verb's own redirect standing"
        );
    }

    #[test]
    fn neither_tier_declaring_anything_still_names_the_gate() {
        // Tier three, and CLOUD-1050 is what changed it: `mv` declares no
        // redirect and no row claims the path, so both consumer tiers are silent
        // — and what stands underneath is no longer an absence but the CLASS's
        // own declared route. The tiering itself is untouched, which is what the
        // non-matching redirect glob above is here to show: a row that speaks for
        // a different path does not reach this one.
        let decision = guarded_with(
            vec![redirect_row("somewhere/else/**", "irrelevant")],
            "mv batten.toml elsewhere",
        );
        let refusal = denial(decision.clone());
        assert_eq!(refusal.fix(), &Fix::Run("git restore".to_owned()));
        assert!(denial_text(decision).contains(PROTECTED_MUTATION));
    }

    #[test]
    fn the_redirect_lookup_sees_the_same_path_the_protected_check_did() {
        // Both tables must discuss ONE path. `./x` and `x` are the same file, and
        // `protected.contains` is asked about the normalised form — so a lookup
        // on the raw operand would guard the path and then fail to find the class
        // that speaks for it, producing a deny whose fix silently fell back a
        // tier for a spelling.
        let refusal = denial(guarded_with(
            vec![redirect_row("batten.toml", "change it in a reviewed PR")],
            "rm ./batten.toml",
        ));
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("change it in a reviewed PR")
        );
        // And the message still points at what the caller actually typed.
        assert!(
            refusal.reason().contains("./batten.toml"),
            "got: {}",
            refusal.reason()
        );
    }

    #[test]
    fn the_declared_order_decides_which_class_answers() {
        // The tie-break, at the surface that consumes it rather than only in the
        // table's own unit tests: two rows match, and the one declared first
        // wins, because the config author orders the table.
        let refusal = denial(guarded_with(
            vec![
                redirect_row(".serena/memories/**", "the narrow answer"),
                redirect_row("**", "the catch-all"),
            ],
            "rm .serena/memories/core.md",
        ));
        assert_eq!(
            refusal.fix().declared_alternative(),
            Some("the narrow answer")
        );
    }

    #[test]
    fn a_redirect_changes_the_message_and_never_the_verdict() {
        // The claim that exempts this table from the raise-only clamp, asserted
        // rather than assumed: the same command against the same policy is a
        // deny with the table and a deny without it, and an ALLOW stays an allow.
        // If a redirect could ever flip a verdict it would be policy-bearing and
        // would need a clamp (the issue's stated assumption 1).
        let rows = vec![redirect_row("**", "some remedy")];
        assert!(matches!(
            guarded_with(rows.clone(), "rm batten.toml"),
            Decision::Deny(_)
        ));
        assert!(matches!(
            guarded_with(Vec::new(), "rm batten.toml"),
            Decision::Deny(_)
        ));
        assert_eq!(
            guarded_with(rows, "rm target/debug/scratch"),
            Decision::Allow,
            "a redirect matching every path cannot make an unprotected one deny"
        );
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
        // A stated limit, pinned so it cannot change silently: `guarded` builds
        // an envelope with no `policy.root`, so there is nothing to resolve
        // against here. This under-denies, which is the sanctioned direction.
        //
        // The reason this comment used to give — "`Envelope` carries no `cwd`" —
        // was false and is corrected (CLOUD-1109). The field has been decoded
        // since CLOUD-202; what was missing was a reader, and `protects` now has
        // one for the absolute case and `names_a_repository_path` for the
        // relative one.
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
        let no_paths = Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: vec![verb("rm", None)],
            protected: PathSet::empty(),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &no_paths,
                &envelope("rm batten.toml"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        ));
        assert!(reason.contains("no-rm-memories"), "got: {reason}");
    }

    /// THE HATCH NO LONGER REACHES THIS CLASS, and this case is the inversion of
    /// the one it replaces.
    ///
    /// `the_protected_gate_honours_the_bypass_hatch` asserted the opposite and was
    /// correct for its whole life: `BATTEN_HOOK_BYPASS` was the only way through a
    /// protected-path refusal, so honouring it was the difference between a gate
    /// and a wall. That is what made the refusal a password — a knowable string
    /// the guarded party can set, recording nothing.
    ///
    /// The class declares an override route now and the boundary honours a spent
    /// admission for it, so there is a way through that leaves a record. Taking
    /// the variable away is therefore a repair rather than a tightening, and this
    /// case is where that shows: the deny is what a caller gets, and
    /// `mediated_admission.rs` is what proves the record still opens it.
    #[test]
    fn the_bypass_hatch_does_not_reach_the_protected_gate() {
        assert!(
            matches!(
                adjudicate(
                    &protected_policy(vec![verb("rm", None)]),
                    &envelope("rm batten.toml"),
                    true,
                    &crate::facts::Look::CouldNotLook,
                    &crate::facts::Look::CouldNotLook,
                    &crate::stop::StopFacts::default(),
                ),
                Decision::Deny(_)
            ),
            "the hatch must not suppress a protected-path refusal"
        );
    }

    /// ...AND STILL REACHES EVERY OTHER ROW, which is the half that keeps the
    /// change narrow.
    ///
    /// Without this the case above would pass just as well if the hatch had been
    /// deleted outright, and a reader could not tell a scoped exemption from a
    /// removal. `shape` rows are the rest of the mediated surface, so one of them
    /// under the hatch is the discriminator.
    #[test]
    fn the_bypass_hatch_still_reaches_an_explicit_row() {
        let mut policy = protected_policy(vec![verb("rm", None)]);
        policy.shapes = vec![shape("no-touching", "touch scratch", None)];
        assert_eq!(
            adjudicate(
                &policy,
                &envelope("touch scratch"),
                true,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow,
            "the hatch must still suppress a row that is not the protected gate"
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
        // legitimately cites `mise-tasks/gh-guard-check.sh` as the provenance of
        // this port, and prose examples name paths too, so a grep either fails on
        // documentation or needs an escape clause loose enough to pass always.
        // Both were tried; both were worse than the property itself.
        //
        // The property is that the set is *config*: the same command must get
        // opposite verdicts from two policies differing only in `protected`. A
        // hardcoded path could not produce that.
        let verbs = vec![verb("rm", None)];
        let guarding = Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: verbs.clone(),
            protected: PathSet::includes("protected", &["guarded/**".to_owned()])
                .expect("well formed"),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        let elsewhere = Policy {
            harness: Harness::ExitCode,
            facts: Vec::new(),
            mints: Vec::new(),
            recorders: Vec::new(),
            patterns: Vec::new(),
            programs: std::collections::BTreeMap::new(),
            bundles: Vec::new(),
            verdicts: Vec::new(),
            root: None,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes("protected", &["other/**".to_owned()])
                .expect("well formed"),
            advisory: None,
            refusal: None,
            protected_readers: Vec::new(),
            redirects: Vec::new(),
        };
        let call = envelope("rm guarded/thing");
        assert!(
            matches!(
                adjudicate(
                    &guarding,
                    &call,
                    false,
                    &crate::facts::Look::CouldNotLook,
                    &crate::facts::Look::CouldNotLook,
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
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
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
                !envelope.raw_tool.is_empty(),
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
        assert_eq!(envelope.raw_tool, "Shell");
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
        assert_eq!(generic.raw_tool, "Shell");
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
    fn every_host_declares_a_row_for_every_scalar_capability() {
        // Table totality on the OTHER axis (CLOUD-45 §7(d)). The event axis is
        // pinned above; this is the (host, capability) pair the issue's clause
        // names, and it is a test rather than a compiler guarantee for a reason
        // the compiler cannot cover: the exhaustive `match` in `capabilities`
        // forces every host to fill every FIELD, and `#[non_exhaustive]` plus
        // struct-literal construction forces a new field into all six arms — but
        // neither notices a field that exists, is filled, and is reachable
        // through no `Capability`. That is a row nothing can range over, which is
        // how a capability comes to be declared and consulted by nothing.
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            for capability in Capability::ALL {
                let declared = capabilities.declares(*capability);
                // Answering at all is the property. Every value is a decision,
                // including `Unknown` — which is why `Unknown` had to be a
                // value rather than an absent row.
                assert!(
                    !declared.as_str().is_empty(),
                    "{} declares nothing for {}",
                    harness.as_str(),
                    capability.as_str()
                );
            }
        }
    }

    #[test]
    fn every_host_declares_a_fidelity_for_every_response_shape_the_core_reads() {
        // CLOUD-917's totality clause, and the third axis of this table after
        // the event set and the scalar columns. Same division of labour as the
        // scalar census above: the exhaustive `match` in `capabilities` plus
        // `#[non_exhaustive]` struct-literal construction already make a missing
        // CELL a compile error, so what this covers is the part the compiler
        // cannot — a cell that is filled and that no `ResponseShape` names,
        // which is a measurement nothing can range over.
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            for shape in ResponseShape::ALL {
                let declared = capabilities.fidelity(*shape);
                assert!(
                    !declared.as_str().is_empty(),
                    "{} declares nothing for {}",
                    harness.as_str(),
                    shape.as_str()
                );
            }
        }
    }

    #[test]
    fn no_capability_token_names_the_fidelity_column() {
        // What keeps the partition test below a two-subset XOR by CONSTRUCTION
        // rather than by luck. The fidelity column is deliberately off the
        // `Capability` axis (a `Fidelity` does not project to a `Declaration`
        // without erasing which of five values was measured), so a later hand
        // adding it there would have to add a third subset or break the
        // partition — and this fails first, naming the reason.
        for capability in Capability::ALL {
            let token = capability.as_str();
            assert!(
                !token.contains("fidelity") && !token.contains("capture"),
                "{token} looks like the fidelity column, which is a second axis \
                 rather than a scalar capability — see `Capabilities::capture`"
            );
        }
    }

    #[test]
    fn five_of_six_hosts_declare_the_response_bytes_unreachable_rather_than_guessing() {
        // The honest-value discipline, as a count. An unsurveyed response
        // surface is `Unavailable`, never a guess, and exactly one host has a
        // measurement here: Claude Code's post-tool member, read as DECODED
        // content because the decoder hands the engine an already-parsed value.
        let unreachable = Harness::ALL
            .iter()
            .filter(|harness| {
                let capabilities = harness.capabilities();
                ResponseShape::ALL.iter().all(|shape| {
                    capabilities.fidelity(*shape) == crate::capture::Fidelity::Unavailable
                })
            })
            .count();
        assert_eq!(
            unreachable, 5,
            "exactly one host has a measured capture row; widening another is a \
             measurement, filed per host"
        );
        assert_eq!(
            Harness::ClaudeCode
                .capabilities()
                .fidelity(ResponseShape::PostToolMember),
            crate::capture::Fidelity::DecodedContent,
        );
    }

    #[test]
    fn an_unreachable_capture_is_a_different_value_from_a_decoded_one() {
        // `an_absent_capability_is_a_different_value_from_an_undeclared_one`'s
        // discipline on the fidelity axis: "nothing is reachable here" and "the
        // decoded member is reachable" are two answers, and a reader that
        // collapsed them would replay bytes it never had.
        assert_ne!(
            crate::capture::Fidelity::Unavailable,
            crate::capture::Fidelity::DecodedContent,
        );
        // And the reserved word separates them too, in the direction that
        // matters: neither may be called byte-perfect.
        assert!(!crate::capture::Fidelity::Unavailable.is_byte_perfect());
        assert!(!crate::capture::Fidelity::DecodedContent.is_byte_perfect());
    }

    #[test]
    fn the_two_capability_subsets_partition_the_whole_table() {
        // What keeps `Capability::ATTRIBUTION` honest as a derivation source. The
        // attribution document is built from that subset, so a new attribution
        // row omitted from it would be declared, consulted by the totality test
        // above, and silently missing from every document a consumer reads —
        // present in the table and absent from the answer.
        for capability in Capability::ALL {
            let dispatch = Capability::DISPATCH.contains(capability);
            let attribution = Capability::ATTRIBUTION.contains(capability);
            assert!(
                dispatch ^ attribution,
                "{} belongs to {} of the two subsets; every capability belongs to \
                 exactly one",
                capability.as_str(),
                if dispatch { "both" } else { "neither" }
            );
        }
        assert_eq!(
            Capability::DISPATCH.len() + Capability::ATTRIBUTION.len(),
            Capability::ALL.len(),
            "a subset lists a capability twice, or one that is not in ALL"
        );
    }

    #[test]
    fn every_capability_token_is_distinct() {
        // The tokens reach a byte-stable document (§6), where two rows sharing
        // one name would make the document ambiguous rather than merely ugly.
        let mut tokens: Vec<&str> = Capability::ALL
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        tokens.sort_unstable();
        let count = tokens.len();
        tokens.dedup();
        assert_eq!(tokens.len(), count, "two capabilities share a token");
    }

    #[test]
    fn an_absent_capability_is_a_different_value_from_an_undeclared_one() {
        // CLOUD-276's stated assumption, as a predicate. The neutral contract is
        // the one column that can honestly say `No` — it is the envelope Batten
        // itself defines, not a third party — and every named host says `Unknown`
        // for the same row. Collapsing the two would make a gap in the evidence
        // read as a fact about the host.
        assert_eq!(
            Harness::ExitCode
                .capabilities()
                .declares(Capability::ExposesModelId),
            Declaration::No,
        );
        for harness in Harness::ALL {
            if *harness == Harness::ExitCode {
                continue;
            }
            assert_eq!(
                harness.capabilities().declares(Capability::ExposesModelId),
                Declaration::Unknown,
                "{}: no surveyed host puts a model id on the payload Batten reads, and \
                 each plainly runs a model — that is unknown, not absent",
                harness.as_str()
            );
        }
        // And neither reads as capturable, which is the only thing the capture
        // path asks of them.
        assert!(!Declaration::No.is_capturable());
        assert!(!Declaration::Unknown.is_capturable());
        assert!(!Declaration::Partial.is_capturable());
        assert!(Declaration::Yes.is_capturable());
    }

    #[test]
    fn the_session_id_is_the_one_attribution_row_the_survey_answers() {
        // M1's field inventory covers it on all five hosts (`session_id`,
        // `sessionId`, `conversation_id`) and `decode` already reads all three,
        // so this is the row that is `Yes` rather than a gap.
        for harness in Harness::ALL {
            assert_eq!(
                harness
                    .capabilities()
                    .declares(Capability::ExposesSessionId),
                Declaration::Yes,
                "{}: the session id is present natively",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_host_setting_that_does_not_govern_every_path_is_partial_not_yes() {
        // Measured on this repository (2026-08-09): one trailer is added by a
        // path that ignores the host's own off-switch. `Yes` would say the
        // setting can be trusted, which is what the attribution gate exists
        // because it cannot; `No` would say there is no setting at all.
        assert_eq!(
            Harness::ClaudeCode
                .capabilities()
                .declares(Capability::AttributionConfigSurface),
            Declaration::Partial,
        );
        // And the injection rows this repo measured are the one host's, not a
        // shared assumption about all of them.
        assert_eq!(
            Harness::ClaudeCode
                .capabilities()
                .declares(Capability::InjectsCoauthorshipTrailer),
            Declaration::Yes,
        );
        assert_eq!(
            Harness::GeminiCli
                .capabilities()
                .declares(Capability::InjectsCoauthorshipTrailer),
            Declaration::Unknown,
            "nothing measured this host; unknown is the honest row"
        );
    }

    #[test]
    fn an_escalation_is_encodable_only_where_the_table_says_ask_is_reachable() {
        // §7(b) at the encoder. `None` is the caller's instruction to hard-deny,
        // so what this pins is that `Some` never appears where the row says the
        // host has no `ask` — the direction that would emit a verdict the host
        // does not understand, which Gemini reads as an allow.
        for harness in Harness::ALL {
            let body = encode_ask(*harness, "PreToolUse", "reason").expect("serializes");
            if body.is_some() {
                assert!(
                    harness.capabilities().ask_reachable("PreToolUse"),
                    "{}: an ask body was encoded for an event the row calls unreachable",
                    harness.as_str()
                );
            }
        }
        // Claude Code is the one host where escalation is both declared and
        // reachable on the event Batten registers.
        let claude = encode_ask(Harness::ClaudeCode, "PreToolUse", "reason")
            .expect("serializes")
            .expect("claude code can escalate");
        assert!(claude.contains("\"permissionDecision\":\"ask\""));
        assert!(claude.contains("\"permissionDecisionReason\":\"reason\""));

        // Cursor and Copilot declare `ask` and still answer `None`, each for a
        // measured reason about the surface Batten registers: on Cursor the
        // verdict parses unenforced on the generic `preToolUse`, and an
        // unenforced ask proceeds; on Copilot no verified body envelope exists.
        // Both therefore hard-deny, which is the safe direction.
        for harness in [Harness::Cursor, Harness::CopilotCli] {
            assert_ne!(
                harness.capabilities().declares(Capability::Ask),
                Declaration::No,
                "{}: the host is not measured as lacking the verdict",
                harness.as_str()
            );
            assert_eq!(
                encode_ask(harness, "PreToolUse", "reason").expect("serializes"),
                None,
                "{}: declared, and not reachable on the event Batten registers",
                harness.as_str()
            );
        }
    }

    #[test]
    fn the_ask_and_deny_bodies_share_one_envelope() {
        // Two shapes for one object is two things to keep in step; this is what
        // says they are one. The verdict word is the only difference.
        let deny = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        let ask = encode_ask(Harness::ClaudeCode, "PreToolUse", "reason")
            .expect("serializes")
            .expect("claude code can escalate");
        assert_eq!(deny.replace("\"deny\"", "\"ask\""), ask);
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
        for harness in [Harness::GeminiCli, Harness::CodexCli] {
            assert_eq!(
                harness.capabilities().declares(Capability::Ask),
                Declaration::No,
                "{}: measured absent, not merely unsurveyed",
                harness.as_str()
            );
            assert!(
                harness.capabilities().ask.enforced_on.is_empty(),
                "{}: a host without the verdict can have no surface enforcing it",
                harness.as_str()
            );
        }
        assert_eq!(
            Harness::ClaudeCode.capabilities().declares(Capability::Ask),
            Declaration::Yes
        );
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
    fn every_harness_declares_a_wiring_row_or_declares_itself_not_a_host() {
        // CLOUD-62's totality obligation. The `match` in `wiring()` already
        // makes a new variant a COMPILE error, which is the strong half. This
        // is the half a compiler cannot give: a variant added as `None` to make
        // the build pass, with nobody deciding whether it is installable.
        //
        // So the non-installable set is named here, once. Adding a variant to it
        // is a deliberate edit in a test that says what the claim means; adding
        // one silently is a failure.
        const NOT_A_HOST: &[Harness] = &[Harness::ExitCode];

        for &harness in Harness::ALL {
            let wiring = harness.wiring();
            if NOT_A_HOST.contains(&harness) {
                assert!(
                    wiring.is_none(),
                    "{} is declared a contract rather than a host, so it must have no \
                     wiring row",
                    harness.as_str()
                );
                continue;
            }
            let wiring = wiring.unwrap_or_else(|| {
                panic!(
                    "{} has no wiring row and is not in NOT_A_HOST — decide which it is \
                     rather than leaving it unregisterable",
                    harness.as_str()
                )
            });
            let registrations = wiring.registrations(harness);
            assert!(
                !registrations.is_empty(),
                "{}'s wiring registers no event, so installing it would wire nothing",
                harness.as_str()
            );

            // Every event the adapter dispatches must have a name here, or it
            // silently goes unregistered — the adapter would be ready to handle
            // an event nothing ever sends it. This is the direction
            // `registrations` cannot police for itself: it drops an unnamed
            // event rather than failing, which is right at runtime and wrong to
            // leave unnoticed.
            let capabilities = harness.capabilities();
            for event in Event::ALL.iter().filter(|e| capabilities.emits(**e)) {
                assert!(
                    registrations.iter().any(|(named, _)| named == event),
                    "{} emits {event:?} but its wiring names no spelling for it, so the \
                     registration would be silently dropped",
                    harness.as_str()
                );
            }
            for (event, spelling) in &registrations {
                assert!(
                    !spelling.is_empty(),
                    "{} registers {event:?} under an empty spelling",
                    harness.as_str()
                );
            }
        }
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

    // ---------------------------------------------------------------------
    // CLOUD-461: the advisory channel.
    // ---------------------------------------------------------------------

    #[test]
    fn the_claude_advice_shape_is_byte_stable() {
        let one = encode_claude_advice("PostToolBatch", "context").expect("serializes");
        let two = encode_claude_advice("PostToolBatch", "context").expect("serializes");
        assert_eq!(one, two);
        assert_eq!(
            one,
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PostToolBatch\",\
             \"additionalContext\":\"context\"}}",
            "the advisory body is pinned by bytes, not by substring (§6)"
        );
    }

    /// An advisory can never carry a verdict, and that is structural.
    ///
    /// Fails by: giving [`ClaudeAdvice`] a `permissionDecision` field, or routing
    /// the advisory through [`encode_claude_verdict`] to "reuse the envelope".
    /// Both would compile and both would let a notice refuse a call — the thing
    /// CLOUD-97 and CLOUD-219 each ruled out independently, arriving through a
    /// serde detail rather than through a decision.
    #[test]
    fn an_advisory_body_has_no_field_a_verdict_could_occupy() {
        let body = encode_claude_advice("PostToolBatch", "context").expect("serializes");
        assert!(!body.contains("permissionDecision"));
        assert!(!body.contains("permissionDecisionReason"));
        // And the two objects are genuinely different shapes rather than one
        // shape with a field omitted, so no caller can turn one into the other.
        let verdict = encode_claude_deny("PreToolUse", "reason").expect("serializes");
        assert!(!verdict.contains("additionalContext"));
    }

    /// [`Event::carries_a_verdict`] and [`adjudicate`]'s arms say the same thing.
    ///
    /// The predicate exists because the "this moment cannot refuse" property
    /// gained a SECOND producer — a `[[hook.handler]]` refusal, on a path that
    /// never calls `adjudicate` — and two lists of the same events are two lists
    /// that can disagree. This is what makes them one.
    ///
    /// Driven over `Event::ALL` rather than a written-out set, so an event added
    /// later is judged rather than quietly skipped.
    ///
    /// Fails by: dropping an arm from `carries_a_verdict`, or making one of
    /// `adjudicate`'s four early-return arms reach the rule table.
    #[test]
    fn every_undecidable_event_allows_in_adjudicate() {
        // The policy is one that WOULD refuse — a deny row matching the command
        // in every envelope below — so an arm that reached the rule table would
        // come back `Deny` and fail here. Against an empty policy this case would
        // pass on both sides of the property and prove nothing.
        let policy = Policy {
            shapes: vec![shape("no-merge", "gh pr merge", None)],
            ..protected_policy(Vec::new())
        };
        for event in Event::ALL {
            if event.carries_a_verdict() {
                continue;
            }
            let envelope = envelope_at(*event, "gh pr merge");
            let decision = adjudicate(
                &policy,
                &envelope,
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            );
            assert!(
                matches!(decision, Decision::Allow),
                "{} does not carry a verdict, so adjudicate must allow even a \
                 command a deny row matches — and `dispatch_handlers` demotes a \
                 handler's refusal to advice on this same reading",
                event.as_str()
            );
        }
    }

    /// The channel is asked about the EVENT, never about the host.
    ///
    /// **The unreachable surface here is `PostToolUse`, and it used to be
    /// `PreToolUse` (CLOUD-1131).** The swap is the whole point of the rewrite:
    /// this test's job is to pin that the question is per-event, and it was
    /// doing that job over an example chosen from an *unprobed* surface, whose
    /// doc comment then hardened into a claim that `PreToolUse`'s only
    /// model-facing channel is exit 2. Measured, that was false — a `warn` at
    /// `PreToolUse` arrives as `additionalContext` with the call still allowed —
    /// so the example moved to a surface that genuinely is not probed.
    ///
    /// `PostToolUse` is a HONEST example of the same shape: documented to accept
    /// `additionalContext`, deliberately not in `delivered_on`, named in
    /// `ADVISORY_GAPS`. If somebody probes it and it delivers, this test moves
    /// again rather than the discipline bending — which is exactly what should
    /// have happened to the first version instead of it being cited as evidence.
    ///
    /// Fails by: making `advisory_reachable` a per-host bool, or listing a
    /// surface in `delivered_on` that nobody has run an advisory on.
    /// The advisory channel reaches more than one host, and Gemini's body is
    /// TEXT rather than a document (CLOUD-1362).
    ///
    /// The count is asserted because CLOUD-1152's acceptance is a count: a
    /// relocation of doctrine onto this channel that left it at one host would
    /// have moved prose rather than fixed reach.
    ///
    /// **The `is_err` arm is the load-bearing one.** Gemini reads unparseable
    /// stdout as an allow plus a `systemMessage`, so a body that PARSED as JSON
    /// would be read as a decision — turning an advisory into a verdict on the
    /// one host where that inversion is expressible. This asserts the emitted
    /// bytes cannot be taken for a document.
    ///
    /// Fails by: emitting JSON for Gemini, emptying its `delivered_on`, or
    /// reverting the row to `unreachable`.
    #[test]
    fn the_advisory_channel_reaches_a_second_host_and_never_as_a_document() {
        let reaching: Vec<Harness> = Harness::ALL
            .iter()
            .copied()
            .filter(|h| !h.capabilities().advisory.delivered_on.is_empty())
            .collect();
        assert_eq!(
            reaching,
            vec![Harness::ClaudeCode, Harness::GeminiCli],
            "the advisory channel's reach is a stated count, not an impression"
        );

        let body = encode_advice(Harness::GeminiCli, "BeforeTool", "drift: 1 changed")
            .expect("serializes")
            .expect("Gemini delivers an advisory on BeforeTool");
        assert_eq!(body, "drift: 1 changed", "the body is the text, verbatim");
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_err(),
            "a Gemini advisory that parsed as JSON would be read as a DECISION: {body}"
        );
    }

    #[test]
    fn an_advisory_is_silent_on_a_surface_that_would_not_deliver_it() {
        let claude = Harness::ClaudeCode;
        assert!(claude.capabilities().advisory_reachable("PostToolBatch"));
        assert!(!claude.capabilities().advisory_reachable("PostToolUse"));
        assert_eq!(
            encode_advice(claude, "PostToolUse", "context").expect("serializes"),
            None,
            "an unprobed surface emits nothing, so a notice cannot vanish there"
        );
        assert!(
            encode_advice(claude, "PostToolBatch", "context")
                .expect("serializes")
                .is_some()
        );
    }

    /// A `warn` at `PreToolUse` reaches the agent, and this is the measurement.
    ///
    /// CLOUD-1131's acceptance clause is that the signal is OBSERVED reaching the
    /// agent rather than merely emitted, so the transcript is the evidence and
    /// this is its regression guard. Measured 2026-08-29 as a discriminating pair
    /// over one command, one word of `delivered_on` apart: `jq --version` — which
    /// trips the live `severity = "warn"` `pinned-toolchain-preset` row —
    /// delivered `PreToolUse:Bash hook additional context: … pin reach loose …`
    /// with the entry present and nothing with it absent, and was ALLOWED both
    /// times.
    ///
    /// The allow is half the assertion: an advisory that arrived by becoming a
    /// deny would be the outcome the old comment feared, and it is not what
    /// happens.
    ///
    /// Fails by: dropping `PreToolUse` from `delivered_on`, or giving
    /// `encode_claude_advice` a per-event body that omits it.
    #[test]
    fn a_pre_tool_advisory_reaches_the_agent_without_becoming_a_verdict() {
        let claude = Harness::ClaudeCode;
        assert!(
            claude.capabilities().advisory_reachable("PreToolUse"),
            "measured: the host delivers additionalContext at PreToolUse"
        );
        let encoded = encode_advice(claude, "PreToolUse", "context")
            .expect("serializes")
            .expect("the pre-tool surface carries an advisory");
        assert!(
            encoded.contains("additionalContext"),
            "the advisory travels as additionalContext, never as a verdict field: {encoded}"
        );
        assert!(
            encoded.contains("PreToolUse"),
            "the wire shape echoes the host's own event spelling: {encoded}"
        );
        assert!(
            !encoded.contains("permissionDecision"),
            "an advisory must not carry a verdict field, or it becomes the deny \
             CLOUD-97 and CLOUD-219 each ruled out: {encoded}"
        );
    }

    /// An unreachable advisory degrades to SILENCE, never to a verdict.
    ///
    /// The mirror of `encode_ask`'s hard-deny instruction, and the asymmetry is
    /// the point: degrading an escalation to an allow would invert a policy
    /// somebody wrote, and degrading an advisory to a deny would invent one
    /// nobody wrote.
    ///
    /// Fails by: giving any non-Claude arm of [`encode_advice`] a body, or making
    /// the `None` path return an `Err`.
    /// The read is NARROWED at the planner, not skipped downstream (CLOUD-758).
    ///
    /// The observable behaviour of a repository with no content-keyed row is
    /// identical either way — an unconditional resolver would take the free
    /// `Write` arm and reach the same allow — so the narrowing has to be
    /// asserted where it is decided. This is the `read` cost class's whole
    /// argument: a call no row selects for pays nothing.
    ///
    /// Fails by: returning `true` unconditionally from `reads_prospective`, or
    /// dropping either narrowing term.
    #[test]
    fn a_call_no_content_row_selects_for_reads_no_prospective_content() {
        let mut write = write_envelope("Write", "notes.md");
        write.operation = Operation::Write;

        let mut policy = gh_policy();
        assert!(
            !policy.reads_prospective(&write),
            "no content-keyed row: a write must not pay a read"
        );

        let mut row = shape("conflict-markers", "unused", None);
        row.pattern = None;
        row.content = Some("(?m)^<<<<<<< ".to_owned());
        policy.shapes.push(row);
        assert!(
            policy.reads_prospective(&write),
            "one content-keyed row: the write is the call it selects for"
        );

        // ...and the narrowing terms, each on its own.
        let execute = envelope("gh pr merge");
        assert!(
            !policy.reads_prospective(&execute),
            "a call that is not a write carries no content to read"
        );
        let mut after = write.clone();
        after.event = Event::PostTool;
        assert!(
            !policy.reads_prospective(&after),
            "after the write there is nothing PROSPECTIVE left to decide over"
        );

        // A row the severity policy cannot reach buys nothing either: the gate
        // skips it, so counting it here is a file read for an unreachable verdict.
        policy.shapes.last_mut().unwrap().severity = Some(RuleSeverity::Warn);
        assert!(
            !policy.reads_prospective(&write),
            "a row `blocks` says nothing about must not buy a read"
        );
    }

    #[test]
    fn an_advisory_on_a_host_with_no_channel_is_silence_rather_than_a_deny() {
        // THE EXCLUSION IS DERIVED FROM THE TABLE, NEVER A HOST NAME
        // (CLOUD-1362). This read `if *harness == Harness::ClaudeCode`, so it
        // pinned "every host but that one is silent" — a claim that went false
        // the moment a second host gained a channel, and it went red for
        // exactly that reason rather than because anything here broke. A name
        // has to be added per host forever; asking `delivered_on` asks the
        // question the test is actually about.
        //
        // `exercised` is the guard against the other failure: if every host
        // ever declares a channel this loop covers nothing and passes, which is
        // a green test asserting an empty set.
        let mut exercised = 0_usize;
        for harness in Harness::ALL {
            if !harness.capabilities().advisory.delivered_on.is_empty() {
                continue;
            }
            exercised += 1;
            // A wiring-less harness is a CONTRACT rather than a host, so it has
            // no spellings of its own — the normalized tokens are what a caller
            // composing the envelope by hand sends. Iterating only `wiring()`
            // skipped `ExitCode` entirely, which is the one row whose `advisory`
            // is a measured `No`: the census covered it, the encoder did not.
            let spellings: Vec<&str> = match harness.wiring() {
                Some(wiring) => wiring.spellings.iter().map(|(_, name)| *name).collect(),
                None => Event::ALL.iter().map(|event| event.as_str()).collect(),
            };
            for spelling in spellings {
                assert_eq!(
                    encode_advice(*harness, spelling, "context").expect("serializes"),
                    None,
                    "{}: no advisory channel is declared here, so nothing may be emitted \
                     on `{spelling}`",
                    harness.as_str()
                );
            }
        }
        assert!(
            exercised > 0,
            "every host now declares an advisory channel, so this case asserts \
             nothing — replace it rather than letting it pass empty"
        );
    }

    /// Every host that declares the channel reaches some of it, or the gap is
    /// **stated**.
    ///
    /// `ASK_GAPS`' census one channel over, and it matters more here: an advisory
    /// that goes nowhere is silent by design, so a wrong row produces a notice
    /// nobody sees and nobody can distinguish from a notice nobody wrote.
    ///
    /// Fails by: probing `PostToolUse` into Claude Code's `delivered_on` without
    /// deleting its `ADVISORY_GAPS` row, or adding a `delivered_on` entry to a
    /// host whose row says it has none.
    #[test]
    fn a_declared_advisory_is_delivered_somewhere_or_the_gap_is_stated() {
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            let declared = capabilities.declares(Capability::Advisory);
            let stated = ADVISORY_GAPS.iter().any(|(row, _)| row == harness);

            // `No` and `Unknown` both mean nothing is reachable, for opposite
            // reasons, and NEITHER states a gap. A gap is a disagreement between
            // what a host has and what Batten reaches — measured-absent has
            // nothing to disagree with, and unsurveyed has nothing to disagree
            // *from*. `declared` already carries the difference, and duplicating
            // it in a second table is how the two answers come to drift.
            if matches!(declared, Declaration::No | Declaration::Unknown) {
                assert!(
                    capabilities.advisory.delivered_on.is_empty(),
                    "{}: declares `{}` and delivers an advisory anyway — a channel \
                     nothing measured cannot be one something reaches",
                    harness.as_str(),
                    declared.as_str()
                );
                assert!(
                    !stated,
                    "{}: declares `{}`, which is not a gap between a host and Batten; \
                     the unanswered state IS the record",
                    harness.as_str(),
                    declared.as_str()
                );
                continue;
            }

            // Every host a row names must actually have something unreached: a
            // stale citation is the failure this table exists to prevent, and it
            // is invisible without this half.
            let events = capabilities.events.len();
            let reached = capabilities.advisory.delivered_on.len();
            if stated {
                assert!(
                    reached < events,
                    "{}: ADVISORY_GAPS names it and every emitted surface is already \
                     delivered on — remove the row rather than leaving the citation",
                    harness.as_str()
                );
            } else {
                assert!(
                    reached > 0,
                    "{}: declares the channel, reaches none of it, and states no gap. \
                     A gap must be STATED, never merely true",
                    harness.as_str()
                );
            }
        }
        assert!(
            !ADVISORY_GAPS.is_empty(),
            "the census is vacuous if no row exists to judge"
        );
    }

    /// Every host that declares a pre-approval honours some of it, or the gap is
    /// **stated**.
    ///
    /// `ADVISORY_GAPS`' census on the fourth channel, and it needs the same
    /// discipline for a worse failure mode: an unspent grant costs the operator a
    /// permission prompt, which is indistinguishable from the guard not being
    /// installed at all.
    ///
    /// **The non-emptiness assertion the advisory census carries is deliberately
    /// absent, and replaced rather than dropped.** `PREAPPROVE_GAPS` is empty
    /// today because there is genuinely no gap: one host declares the channel and
    /// honours it on every surface where a permission decision means anything.
    /// Asserting non-emptiness would demand a gap be invented to satisfy a test.
    /// What would make this census vacuous is no host declaring the channel at
    /// all, so that is what is asserted instead — the loop must have judged at
    /// least one declaring host.
    ///
    /// Fails by: adding an `honoured_on` surface to a host whose row says it has
    /// none, or declaring the channel `Yes` on a host and reaching nothing without
    /// writing the row.
    #[test]
    fn a_declared_preapproval_is_honoured_somewhere_or_the_gap_is_stated() {
        let mut judged = 0_usize;
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            let declared = capabilities.declares(Capability::Preapprove);
            let stated = PREAPPROVE_GAPS.iter().any(|(row, _)| row == harness);

            // `No` and `Unknown` both mean nothing is reachable, for opposite
            // reasons, and NEITHER states a gap — the advisory census's own
            // reading, and it holds here unchanged: measured-absent has nothing to
            // disagree with, unsurveyed has nothing to disagree *from*.
            if matches!(declared, Declaration::No | Declaration::Unknown) {
                assert!(
                    !stated,
                    "{}: declares `{}`, which is not a gap between a host and \
                     Batten; the unanswered state IS the record",
                    harness.as_str(),
                    declared.as_str()
                );
                assert!(
                    capabilities.preapprove.honoured_on.is_empty(),
                    "{}: honours a pre-approval somewhere while declaring `{}` — \
                     the column and the declaration disagree",
                    harness.as_str(),
                    declared.as_str()
                );
                continue;
            }

            judged += 1;
            let events = capabilities.events.len();
            let reached = capabilities.preapprove.honoured_on.len();
            if stated {
                assert!(
                    reached < events,
                    "{}: PREAPPROVE_GAPS names it and every emitted surface already \
                     honours a grant — remove the row rather than leaving the citation",
                    harness.as_str()
                );
            } else {
                assert!(
                    reached > 0,
                    "{}: declares the channel, honours none of it, and states no \
                     gap. A gap must be STATED, never merely true",
                    harness.as_str()
                );
            }
        }
        assert!(
            judged > 0,
            "no host declares a pre-approval, so this census judged nothing"
        );
    }

    // ---------------------------------------------------------------------
    // CLOUD-779: the neutral operation layer, and CLOUD-601's event-scoped ask.
    // ---------------------------------------------------------------------

    /// Each host's own word for "write this file", one row per harness.
    ///
    /// The census below is exhaustive over [`Harness::ALL`], so a seventh adapter
    /// cannot land with the fact unmapped, and it is the CLOUD-418 lever: delete a
    /// harness's vocabulary mapping from [`Harness::write_tools`] and that row
    /// turns red rather than quietly allowing.
    ///
    /// Three of these are the measured hole. On `main`, 2026-08-20, against a
    /// `[[verb]]` table naming Claude Code's four write tools, a call to a
    /// protected path under `write`, `WriteFile` or `StrReplaceEditor` was
    /// **allowed**: the gate asked `verbs::classify(raw_tool)`, the consumer's
    /// table did not know the spelling, and a rule that matches nothing is
    /// indistinguishable from a rule with nothing to match.
    const WRITE_SPELLINGS: &[(Harness, &str)] = &[
        (Harness::ClaudeCode, "Write"),
        (Harness::Cursor, "write"),
        (Harness::CopilotCli, "StrReplaceEditor"),
        (Harness::GeminiCli, "WriteFile"),
        (Harness::CodexCli, "NotebookEdit"),
        (Harness::ExitCode, "Write"),
    ];

    /// A new adapter must either name a fetched plan spelling or say who owes
    /// the survey. CLOUD-472's column exists to keep those apart, so a row that
    /// declares neither is the one thing it cannot express.
    #[test]
    fn every_harness_declares_a_plan_surface_or_names_who_owes_the_survey() {
        for harness in Harness::ALL {
            if let PlanTools::Unsurveyed(owner) = harness.capabilities().plan_tools {
                assert!(
                    !owner.is_empty(),
                    "{}: unsurveyed with no owner — the gap has to be stated, \
                     which is `#MUTANT-OWNER`'s bargain one layer over",
                    harness.as_str()
                );
            }
        }
    }

    /// SURVEYED-AND-NONE IS AN ANSWER; UNSURVEYED IS NOT. The whole reason the
    /// column has two variants is that collapsing them reproduces the trap
    /// `operation_of`'s own comment records — an absence of DATA reading as an
    /// absence of CAPABILITY. Asserted over the committed table so a later edit
    /// cannot quietly turn one into the other.
    #[test]
    fn an_unsurveyed_plan_surface_is_never_reported_as_having_none() {
        assert_eq!(
            Harness::ExitCode.capabilities().plan_tools,
            PlanTools::Surveyed(&[]),
            "the neutral contract carries no host tool surface, which is a measured none"
        );
        assert!(
            matches!(
                Harness::Cursor.capabilities().plan_tools,
                PlanTools::Unsurveyed(_)
            ),
            "Cursor has a Todos feature and no vendor-documented spelling was fetched, \
             so it is unsurveyed rather than none"
        );
    }

    #[test]
    fn every_harness_classifies_its_own_write_spelling_as_write() {
        for harness in Harness::ALL {
            let (_, spelling) = WRITE_SPELLINGS
                .iter()
                .find(|(row, _)| row == harness)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: no write spelling declared — a new adapter must name one",
                        harness.as_str()
                    )
                });
            assert_eq!(
                harness.operation_of(spelling),
                Operation::Write,
                "{}: `{spelling}` is in this host's write_tools and must classify as write",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_tool_no_survey_recorded_is_could_not_look_rather_than_not_a_write() {
        // The three-valued discipline at the harness boundary (CLOUD-757). An
        // adapter that meets a spelling its host's survey never recorded says so;
        // it does not guess, and nothing downstream may read that silence as
        // "harmless".
        let unknown = Harness::GeminiCli.operation_of("SomeToolNobodySurveyed");
        assert_eq!(
            unknown,
            Operation::Other("SomeToolNobodySurveyed".to_owned()),
            "an unrecognised tool carries its spelling rather than vanishing"
        );
        assert!(unknown.is_unclassified());
        assert!(
            unknown.names_targets_through(WriteStage::ToolNamed)
                && unknown.names_targets_through(WriteStage::CommandParsed),
            "could not look must ask every source, or it has silently become `false`"
        );
        // And the classified operations answer for exactly the source they use,
        // so the fallback above is a genuine widening rather than the default.
        assert!(!Operation::Read.names_targets_through(WriteStage::ToolNamed));
        assert!(!Operation::Mcp.names_targets_through(WriteStage::CommandParsed));
        assert!(!Operation::Subagent.names_targets_through(WriteStage::ToolNamed));
        assert!(!Operation::Write.names_targets_through(WriteStage::CommandParsed));
        assert!(!Operation::Execute.names_targets_through(WriteStage::ToolNamed));
    }

    #[test]
    fn the_operation_token_never_leaks_the_host_spelling_it_carries() {
        // Rule 4 on a type whose whole job is to be reported: `Other` renders the
        // reading, never the payload. The spelling stays addressable through
        // `raw_tool` for a rule that means to reach it.
        assert_eq!(
            Operation::Other("mcp__secretserver__do".to_owned()).as_str(),
            "other"
        );
        for (operation, token) in [
            (Operation::Write, "write"),
            (Operation::Read, "read"),
            (Operation::Execute, "execute"),
            (Operation::Mcp, "mcp"),
            (Operation::Subagent, "subagent"),
        ] {
            assert_eq!(operation.as_str(), token);
        }
    }

    /// THE PINNED REGRESSION (CLOUD-779).
    ///
    /// Every harness that can emit a write-shaped call denies the same protected
    /// path, under the host's own spelling and against a `[[verb]]` table that
    /// names only Claude Code's. Red on `main` for Cursor, Gemini and Copilot.
    #[test]
    fn a_protected_write_denies_on_every_harness_under_its_own_vocabulary() {
        // Deliberately Claude Code's four names and nothing else — the table a
        // consumer actually writes, and the one this issue measured.
        let policy = protected_policy(vec![
            verb("Write", Some("use the surface that owns the file")),
            verb("Edit", Some("use the surface that owns the file")),
            verb("MultiEdit", Some("use the surface that owns the file")),
            verb("NotebookEdit", Some("use the surface that owns the file")),
        ]);
        for (harness, spelling) in WRITE_SPELLINGS {
            let decision = adjudicate(
                &policy,
                &write_envelope_on(*harness, spelling, "batten.toml"),
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            );
            assert!(
                matches!(decision, Decision::Deny(_)),
                "{}: `{spelling}` reached a protected path and was not refused — \
                 the gate reads as coverage on every harness and enforces on one",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_write_under_an_undeclared_spelling_still_names_a_fix() {
        // The `[[verb]]` row is message composition now, so a spelling the
        // consumer never declared loses the verb's remedy and keeps the refusal.
        // `redirect::resolve`'s per-path tier is what answers instead, which is
        // why the deny is still actionable rather than a bare no (CLOUD-122).
        let policy = protected_policy_with(
            vec![verb("Write", Some("use the surface that owns the file"))],
            vec![Redirect {
                glob: "batten.toml".to_owned(),
                mutation: "change it in a pull request".to_owned(),
                read: None,
            }],
        );
        let Decision::Deny(refusal) = adjudicate(
            &policy,
            &write_envelope_on(Harness::GeminiCli, "WriteFile", "batten.toml"),
            false,
            &crate::facts::Look::CouldNotLook,
            &crate::facts::Look::CouldNotLook,
            &crate::stop::StopFacts::default(),
        ) else {
            panic!("a host-spelled write against a protected path must deny");
        };
        let rendered = refusal.render();
        assert!(rendered.contains("WriteFile"), "got: {rendered}");
        assert!(
            rendered.contains("change it in a pull request"),
            "the path class must answer where the verb row cannot; got: {rendered}"
        );
    }

    #[test]
    fn a_shell_call_reaches_the_same_protected_gate_a_tool_named_write_does() {
        // CLOUD-779's routing: `beforeShellExecution` is `Operation::Execute`, and
        // an Execute names its targets inside the command text rather than in a
        // `writes` field. One gate, two sources — so "which stage answers" is a
        // property of the operation and not a second implementation that could
        // drift from the first.
        let envelope = decode(
            Harness::Cursor,
            r#"{"hook_event_name":"beforeShellExecution","cwd":"/repo","command":"rm batten.toml"}"#,
        )
        .expect("decodes");
        assert_eq!(envelope.operation, Operation::Execute);
        assert_eq!(envelope.raw_tool, "Shell");
        assert!(
            envelope.writes.is_none(),
            "a shell call names no target through the tool, which is why the \
             stage split exists"
        );
        assert_eq!(
            protected_write(
                &protected_policy(vec![verb("rm", Some("restore it with git"))]),
                &envelope,
                WriteStage::ToolNamed
            ),
            Decision::Allow,
            "an Execute has nothing to say at the tool-named stage"
        );
        assert!(
            matches!(
                protected_write(
                    &protected_policy(vec![verb("rm", Some("restore it with git"))]),
                    &envelope,
                    WriteStage::CommandParsed
                ),
                Decision::Deny(_)
            ),
            "and everything to say at the command stage"
        );
    }

    /// CLOUD-601: the declaration and the reachability are one fact, and where
    /// they still disagree the disagreement is DECLARED rather than merely true.
    #[test]
    fn a_declared_escalation_is_reachable_or_the_gap_is_stated() {
        for harness in Harness::ALL {
            let capabilities = harness.capabilities();
            // The surface Batten actually registers on this host. `ExitCode` has
            // no wiring — it is a contract, not a host — so there is no
            // registration for a declaration to disagree with.
            let Some(wiring) = harness.wiring() else {
                assert!(
                    capabilities.ask.enforced_on.is_empty(),
                    "{}: nothing is registered here, so nothing can enforce a verdict",
                    harness.as_str()
                );
                continue;
            };
            let registered = wiring
                .spellings
                .iter()
                .find(|(event, _)| *event == Event::PreTool)
                .map(|(_, spelling)| *spelling)
                .expect("every wired host registers a pre-tool surface");

            let declared = capabilities.declares(Capability::Ask);
            let reachable = capabilities.ask_reachable(registered);
            let stated = ASK_GAPS.iter().any(|(row, _)| row == harness);

            if declared == Declaration::No {
                assert!(
                    !reachable,
                    "{}: measured as lacking the verdict and enforcing it anyway",
                    harness.as_str()
                );
                assert!(
                    !stated,
                    "{}: a host with no verdict has no gap to declare",
                    harness.as_str()
                );
                continue;
            }
            assert_eq!(
                stated,
                !reachable,
                "{}: declared `{}` and reachable on `{registered}` = {reachable}, but \
                 ASK_GAPS says {stated}. A gap must be STATED, and a gap that has \
                 closed must be removed rather than left as a stale citation.",
                harness.as_str(),
                declared.as_str()
            );
        }
        // Shown able to fail (CLOUD-418): the case discriminates. Cursor is the
        // live gap — re-declare its generic `preToolUse` as enforcing and the
        // equality above flips, which is exactly what CLOUD-777 will do and what
        // must then force the row out of ASK_GAPS.
        assert!(
            !Harness::Cursor.capabilities().ask_reachable("preToolUse"),
            "an ask parses unenforced here, and an unenforced ask PROCEEDS"
        );
        assert!(
            Harness::Cursor
                .capabilities()
                .ask_reachable("beforeShellExecution"),
            "the two surfaces that do honour it are what the row records"
        );
    }

    #[test]
    fn an_unreachable_escalation_hard_denies_and_never_degrades_to_allow() {
        // CLOUD-45 §7(b), now asked per event rather than per host. `None` is the
        // boundary's instruction to hard-deny; the direction that must never be
        // reachable is a `Some` on a surface that would parse and ignore it.
        for harness in Harness::ALL {
            for event in ["PreToolUse", "preToolUse", "BeforeTool", "afterFileEdit"] {
                let body = encode_ask(*harness, event, "reason").expect("serializes");
                assert_eq!(
                    body.is_some(),
                    harness.capabilities().ask_reachable(event),
                    "{}: an ask body at `{event}` disagrees with the one authority",
                    harness.as_str()
                );
            }
        }
        // And where it IS reachable the body is that host's own documented shape,
        // not a shared guess — Cursor assigns stderr no meaning at all, so the
        // body is the only channel a reason can travel on.
        let cursor = encode_ask(Harness::Cursor, "beforeShellExecution", "reason")
            .expect("serializes")
            .expect("reachable on this surface");
        assert!(cursor.contains("\"permission\":\"ask\""), "got: {cursor}");
        assert!(
            cursor.contains("\"user_message\":\"reason\""),
            "got: {cursor}"
        );
    }

    #[test]
    fn the_capability_row_is_readable_through_the_policy_a_rule_is_judged_by() {
        // CLOUD-779 item 2: engine-side plumbing through `Policy`, deliberately
        // not a `Rule` column — no config key, no schema regeneration, and no
        // collision with the two issues that do add columns (CLOUD-772/773).
        // `adjudicate` stays pure: this is compiled-in data resolved at the
        // boundary like every other fact.
        for harness in Harness::ALL {
            let policy = Policy::declaring_nothing(*harness);
            assert_eq!(policy.harness(), *harness);
            assert_eq!(
                policy.capabilities().declares(Capability::Ask),
                harness.capabilities().declares(Capability::Ask),
                "{}: the policy must hand a rule the same row the table holds",
                harness.as_str()
            );
        }
    }

    #[test]
    fn a_pass_through_call_resolves_nothing_it_does_not_need() {
        // CLOUD-777's acceptance, asserted structurally rather than only as a
        // latency figure: under match-all every tool call reaches the engine, so
        // the COMMON case is now a call no rule selects. It must cost what
        // looking costs and nothing more.
        //
        // The two resolutions that are not free are the ones asked here. Both
        // are boundary work `adjudicate` cannot do — a receipt reads a file and
        // two git refs, a key read runs `git log` — and both are narrowed by
        // asking the policy FIRST whether any row could want them (CLOUD-460's
        // lesson, after one receipt row made every mediated call pay four git
        // subprocesses). A pass-through that answered `Some` here would pay for
        // policy it never runs, and nothing else in the suite would notice.
        let policy = receipt_policy();
        let read = Envelope {
            event: Event::PreTool,
            raw_event: ASSUMED_EVENT.to_owned(),
            raw_tool: "Read".to_owned(),
            operation: Operation::Read,
            input: Value::Null,
            result: Value::Null,
            command: String::new(),
            writes: None,
            reads: None,
            cwd: None,
            session: None,
            stop_active: None,
            last_message: None,
            transcript: None,
            mode: None,
        };
        assert!(
            policy.required_checks_for(&read).is_empty(),
            "a read resolves no receipts — a receipt read is a file and two git refs"
        );
        assert_eq!(
            policy.key_base_for(&read),
            None,
            "a read resolves no key facts — a key read is a branch and a `git log`"
        );
        // And the same call is allowed, so the cheapness above is the cheapness
        // of the path actually taken rather than of one the gate skipped.
        assert_eq!(
            adjudicate(
                &policy,
                &read,
                false,
                &crate::facts::Look::CouldNotLook,
                &crate::facts::Look::CouldNotLook,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow
        );
    }
}
