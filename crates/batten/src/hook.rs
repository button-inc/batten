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
use crate::redirect::{self, Redirect};
use crate::refusal::{Fix, Refusal};
use crate::resolve::Resolved;
use crate::rules::{PathSet, ReceiptKey, ReceiptTrigger, Rule, RuleKind, RuleScope};
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
    /// What this host does to commit metadata, and what it exposes about its
    /// caller (CLOUD-276).
    ///
    /// A row group in the same table rather than a second per-host registry
    /// beside [`crate::attribution`]: the question "what can this host tell us"
    /// is the same kind of question as "what events does it emit", and two
    /// registries is how the answers come to disagree.
    pub attribution: AttributionCapabilities,
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
}

impl Capability {
    /// Every scalar capability, so a census is derived rather than hand-kept.
    pub const ALL: &'static [Capability] = &[
        Capability::Ask,
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
];

/// The command a host's registration invokes.
///
/// Neutral on purpose, and this is where non-negotiable rule 1 bites (CLOUD-62):
/// this repository's own wiring runs `.claude/hooks/batten-hook.sh`, a launcher
/// that `cd`s so `load_policy` finds the authority, resolves a binary that is not
/// on PATH, and fails open — all things `settings.json` cannot express. That
/// launcher is a CONSUMER's fact, and naming its path here would put a specific
/// consumer's file layout in the repo-agnostic core. So the emitter names the
/// binary and the harness, and a consumer's own gate is where the indirection is
/// resolved.
fn wiring_command(harness: Harness) -> String {
    format!("batten hook --harness {}", harness.as_str())
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

/// Claude Code's set: the converged core plus the three it alone offers.
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
                // Documented, and merged most-restrictive-first by the host
                // itself (`deny > defer > ask > allow`), so an ask cannot
                // override another hook's deny. `PreToolUse` is the only event
                // that carries the verdict and the only one Batten adjudicates.
                ask: AskReach {
                    enforced_on: &["PreToolUse"],
                    declared: Declaration::Yes,
                },
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
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
            },
            Harness::Cursor => Capabilities {
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
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: true,
                stdout_must_stay_clean: false,
                attribution: UNSURVEYED_ATTRIBUTION,
            },
            Harness::CopilotCli => Capabilities {
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
                stop_vetoes_completion: false,
                timeout_fails_open: true,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                attribution: UNSURVEYED_ATTRIBUTION,
            },
            Harness::GeminiCli => Capabilities {
                events: CONVERGED_EVENTS,
                // Allow/deny only. A policy wanting confirmation must hard-deny
                // here — degrading to *allow* would turn "ask a human" into "go
                // ahead".
                ask: AskReach::unreachable(Declaration::No),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: true,
                attribution: UNSURVEYED_ATTRIBUTION,
            },
            Harness::CodexCli => Capabilities {
                events: CONVERGED_EVENTS,
                // Advertised in the output schema, marked "parsed but not
                // supported yet" in the docs. Advertised is not available, and
                // that is a measurement rather than a gap — hence `No`.
                ask: AskReach::unreachable(Declaration::No),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
                attribution: UNSURVEYED_ATTRIBUTION,
            },
            Harness::ExitCode => Capabilities {
                events: CONVERGED_EVENTS,
                // Not a host: the channel is the exit status alone, which has no
                // third value to carry an escalation. Measured, not unsurveyed.
                ask: AskReach::unreachable(Declaration::No),
                stop_vetoes_completion: false,
                timeout_fails_open: false,
                needs_fail_closed_config: false,
                stdout_must_stay_clean: false,
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
            Event::PostToolBatch => "post-tool-batch",
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
            // The one member read out of `input`, and only ever this key. A
            // non-string value reads as absent rather than as its debug
            // rendering: a caller counting characters must never be handed
            // `{"a":1}` and told it is a prompt.
            Field::Prompt => envelope
                .input
                .get("prompt")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
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
    /// What to run instead, per protected path class (CLOUD-280).
    ///
    /// Message composition only — it never decides whether the gate fires, which
    /// is why it sits beside `protected` rather than inside it and why no
    /// raise-only clamp applies to it.
    redirects: Vec<Redirect>,
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
            redirects: Vec::new(),
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
    pub fn from_resolved(resolved: &Resolved, harness: Harness) -> anyhow::Result<Policy> {
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
            protected: PathSet::includes("protected", &resolved.protected)?,
            redirects: resolved.redirects.clone(),
        })
    }

    /// The host capability row this policy is being evaluated against
    /// (CLOUD-779, CLOUD-601).
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
                rule.checks
                    .iter()
                    .flatten()
                    .map(move |check| (check.clone(), key))
            })
            .collect()
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
        matching_shape_rows(self, &envelope.command)
            .into_iter()
            .find(|rule| rule.requires_key.is_some())
            .and_then(|rule| rule.base.as_deref())
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
pub fn adjudicate(
    policy: &Policy,
    envelope: &Envelope,
    bypass: bool,
    receipts: &ReceiptFacts,
    keys: &KeyFacts,
    stop: &crate::stop::StopFacts,
    waived: &crate::waiver::Live,
) -> Decision {
    match adjudicated(policy, envelope, bypass, receipts, keys, stop) {
        Decision::Deny(refusal) => match waived.get(refusal.rule()) {
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
fn adjudicated(
    policy: &Policy,
    envelope: &Envelope,
    bypass: bool,
    receipts: &ReceiptFacts,
    keys: &KeyFacts,
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
        Decision::Allow | Decision::Ask(_) | Decision::Waived(_) => {}
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
    if envelope.writes.is_some() {
        match receipt_rules(policy, envelope, receipts) {
            decided @ (Decision::Deny(_) | Decision::Ask(_)) => return decided,
            // `Waived` is grouped with `Allow` throughout this chain, and it is an
            // invariant rather than a case: only [`adjudicate`] mints one, from
            // this function's answer, so no gate below can return it. Stated as an
            // arm rather than a wildcard so a fifth variant still fails to compile
            // here, and grouped with `Allow` because that is what a suppression
            // means if the invariant ever breaks.
            Decision::Allow | Decision::Waived(_) => {}
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
    // An `Ask` short-circuits exactly as a `Deny` does: the row matched, and what
    // it asked for is the answer. Falling through to the receipt gate would let a
    // second row overrule an escalation the first one wanted, which declaration
    // order is supposed to decide.
    match shape_rules(policy, &envelope.command, keys) {
        decided @ (Decision::Deny(_) | Decision::Ask(_)) => decided,
        // The pipeline gate before the receipt one, and the ordering is the same
        // ban-outranks-precondition rule the rest of this chain follows: a call
        // whose verdict is thrown away is refused outright, so telling its author
        // which receipt to earn first would be advice about a call that is not
        // going to run (CLOUD-443).
        Decision::Allow | Decision::Waived(_) => match pipeline_rules(policy, &envelope.command) {
            decided @ (Decision::Deny(_) | Decision::Ask(_)) => decided,
            Decision::Allow | Decision::Waived(_) => {
                match receipt_rules(policy, envelope, receipts) {
                    decided @ (Decision::Deny(_) | Decision::Ask(_)) => decided,
                    Decision::Allow | Decision::Waived(_) => {
                        protected_write(policy, envelope, WriteStage::CommandParsed)
                    }
                }
            }
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
/// `None` is **no receipt question to answer here**, and allows — the fail-open
/// posture every retiring guard has. Two things resolve to it, and both are the
/// boundary's to decide because both are questions about a checkout:
///
/// * **could not look** — no checkout, an `origin/main` that does not resolve, or
///   a detached HEAD where a branch-keyed row needs a branch;
/// * **nothing judgeable** — the call writes a path policy does not judge
///   (git-ignored, outside the repository, inside `.git`), which is
///   [`crate::receipt::judgeable`]'s answer and CLOUD-444's exclusion set.
///
/// `Some` map missing a name is treated as [`Validity::Missing`], so a boundary
/// that resolved fewer facts than the policy needs fails closed rather than
/// silently allowing.
pub type ReceiptFacts = Option<std::collections::BTreeMap<String, Validity>>;

/// The checkout evidence a `requires_key` shape row is judged against
/// (CLOUD-446): the branch name, and the commit messages on `base..HEAD`.
///
/// `None` is **could not look** and allows, exactly as it does for
/// [`ReceiptFacts`] — outside a checkout, on a detached HEAD, or against a `base`
/// git cannot resolve. Resolved at the boundary because [`adjudicate`] is
/// contractually pure, and resolved only when a `requires_key` row has already
/// selected this command ([`Policy::key_base_for`]), so a repository declaring no
/// such row pays nothing on the hottest path in the binary.
///
/// Deliberately not a named struct with a `branch` and a `messages` field: every
/// reader asks the same question of all of it — does the expression match
/// anywhere — and a field a caller could *print* is one an unreviewed edit turns
/// into a leaked commit message (non-negotiable rule 4).
pub type KeyFacts = Option<Vec<String>>;

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

fn receipt_rules(policy: &Policy, envelope: &Envelope, facts: &ReceiptFacts) -> Decision {
    // No facts means there is no receipt question to answer here. Allow: a guard
    // that cannot read its own precondition must not become the reason work
    // stops.
    let Some(facts) = facts.as_ref() else {
        return Decision::Allow;
    };
    for rule in matching_receipt_rows(policy, envelope) {
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
        // The cause names what the receipt is keyed to (CLOUD-444), because that
        // is what the reader has to act on: "no receipt for this commit" sends
        // someone looking for a per-commit step when what is missing is a claim
        // the whole branch shares, and a wrong pointer is CLOUD-122's failure in
        // its most confusing form.
        Validity::Missing if rule.receipt_key() == ReceiptKey::Branch => {
            format!("this branch carries no `{check}` receipt")
        }
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
fn pipeline_rules(policy: &Policy, command: &str) -> Decision {
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
    let parsed = segments(command);
    for rule in rows {
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

/// Compose a pipeline refusal: which shape, and the row's declared remedy.
///
/// The cause states the **PRINCIPLE** rather than naming one command, and that is
/// CLOUD-199's measured lesson rather than a style choice: the predecessor guard
/// was worded around one command string, an agent complied with it exactly, and
/// made the identical error on the next command in the same session.
fn pipeline_refusal(rule: &Rule, discard: Discard) -> Refusal {
    let cause = match discard {
        Discard::Piped => {
            "piping a verdict-bearing command into a pager or filter discards its \
             exit status — the pipeline exits with the filter's, which is 0 whether the command \
             passed or failed. A verdict is read from the harness, never inferred from output"
        }
        Discard::Trailing => {
            "a verdict-bearing command followed by `;` or `||` has its exit \
             status replaced — only the last element's survives. This is the laundered shape: it \
             reads as correct, and backgrounded it is worse than a misread, because the completion \
             notification then carries the compound's status. (`&&` is fine: it short-circuits, \
             so a failure still propagates.)"
        }
        Discard::Orphaned => {
            "detaching a verdict-bearing command with `nohup` or a trailing `&` \
             orphans it from the tool call: the call returns at once, the harness records it \
             complete, and the session loses the wake-up it would get when the work exits"
        }
    };
    Refusal::new(&rule.id, cause, Fix::declared(rule.reason.as_deref()))
}

fn shape_rules(policy: &Policy, command: &str, keys: &KeyFacts) -> Decision {
    for rule in matching_shape_rows(policy, command) {
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

/// Whether the work this call belongs to names a tracker key (CLOUD-446).
///
/// Three sources, and the order is cheapest-first rather than
/// most-authoritative-first: the command as written, then the boundary's
/// evidence. A key typed into the call — `--body "… KEY-1 …"` — answers without
/// the checkout being consulted at all.
///
/// `None` evidence is **could not look**, and allows. Outside a checkout, on a
/// detached HEAD, or against a `base` git cannot resolve, this predicate has no
/// answer, and a hook that refuses where it cannot look is a hook that has become
/// the reason work cannot proceed. Same posture as [`ReceiptFacts`].
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
    let Some(evidence) = keys else {
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
fn matching_shape_rows<'a>(policy: &'a Policy, command: &str) -> Vec<&'a Rule> {
    let mut matched: Vec<&Rule> = Vec::new();
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
    if !policy.protected.contains(normalise(path)) {
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

fn protected_mutation(policy: &Policy, command: &str) -> Decision {
    for segment in segments(command) {
        let tokens: Vec<&str> = segment.words.iter().map(String::as_str).collect();
        // Operands of the effective program, plus any redirect target. Both are
        // candidates; a redirect needs no program at all.
        let mut candidates: Vec<Target<'_>> = Vec::new();
        if let Some(index) = effective_program(&tokens) {
            let program = tokens[index];
            // The row is resolved ONCE per segment, from the program and its
            // arguments together (CLOUD-442). Before this the lookup was by
            // program alone, so a program that mutates under one subcommand or
            // behind one flag could only be declared as mutating under all of
            // them — which is why five write shapes could not be expressed.
            if let Some(matched) =
                crate::verbs::qualify(&policy.verbs, program, &tokens[index + 1..])
            {
                let operands = operands(&tokens, index + 1 + matched.consumed);
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
            if !policy.protected.contains(normalise(target.path)) {
                continue;
            }
            return Decision::Deny(protected_refusal(&policy.redirects, &target));
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
    Refusal::new(
        PROTECTED_MUTATION,
        format!("`{action}` targets the protected path {}", target.path),
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
    let mut cause = "the mediated call matches a refused command shape".to_owned();
    if let Some(url) = rule.policy_url.as_deref() {
        cause.push_str(". See ");
        cause.push_str(url);
    }
    Refusal::new(&rule.id, cause, Fix::declared(rule.reason.as_deref()))
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
    let mut cause =
        "the work this call publishes names no tracker key — not in the command, the branch, \
         or any commit on it"
            .to_owned();
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
    /// The operator that FOLLOWED this span, or `None` where the command ended.
    ///
    /// Retained since CLOUD-443, and the reason is that three predicates are
    /// about the structure a command sits in rather than about its words: what
    /// its status is handed to, what replaces it, whether it was detached. The
    /// parser used to split on exactly these operators and discard them, so the
    /// structure was destroyed before any rule could see it.
    terminator: Option<Separator>,
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
            // The command ended here, so nothing follows to take this segment's
            // status. `None` is what makes "alone in the call" — the prescribed
            // form — distinguishable from every shape that substitutes.
            terminator: None,
        });
    }
    out
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
            bypass,
            receipts,
            keys,
            stop,
            &crate::waiver::Live::new(),
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
            id: id.to_owned(),
            kind: crate::rules::RuleKind::Shape,
            glob: None,
            severity: Some(RuleSeverity::Deny),
            scope: RuleScope::MediatedCall,
            pattern: Some(pattern.to_owned()),
            regex: None,
            exclude: None,
            contains: contains.map(ToOwned::to_owned),
            require_via: None,
            requires_key: None,
            reason: Some(format!("use the sanctioned path for {id}")),
            policy_url: None,
            check: None,
            fix: None,
            run: None,
            verbatim: None,
            identity_key: None,
            direction: None,
            base: None,
            format: None,
            node: None,
            criteria: None,
            tier: None,
            // A shape rule never reaches the findings store, so it is refused
            // the remediation column (CLOUD-81).
            no_fix_reason: None,
            checks: None,
            key: None,
            trigger: None,
            verdict: None,
            filters: None,
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
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes(
                "protected",
                &[".serena/memories/**".to_owned(), "batten.toml".to_owned()],
            )
            .expect("the fixture protected set is well formed"),
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
            &None,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    fn gh_policy() -> Policy {
        Policy {
            harness: Harness::ExitCode,
            verbs: Vec::new(),
            protected: PathSet::empty(),
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
            command: String::new(),
            writes,
            cwd: None,
            session: None,
            stop_active: None,
            last_message: None,
            transcript: None,
        }
    }

    /// The same call `adjudicate_command` makes, with a waiver table applied.
    fn adjudicate_command_waiving(command: &str, waived: &crate::waiver::Live) -> Decision {
        super::adjudicate(
            &gh_policy(),
            &envelope(command),
            false,
            &None,
            &None,
            &crate::stop::StopFacts::default(),
            waived,
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
            &None,
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
            // An `Ask` is not a deny, and collapsing the two here would let a
            // row that silently started escalating keep passing every assertion
            // below about what a refusal says. A `Waived` is not one either, and
            // for a sharper reason: it is a deny that was let through, so folding
            // it in here would let a suppression pass every assertion about what
            // a refusal says while the call actually ran.
            Decision::Ask(_) | Decision::Allow | Decision::Waived(_) => {
                panic!("expected a deny")
            }
        }
    }

    /// The refusal a deny carries, for the assertions that are about the value
    /// rather than its rendering.
    fn denial(decision: Decision) -> Refusal {
        match decision {
            Decision::Deny(refusal) => refusal,
            Decision::Ask(_) | Decision::Allow | Decision::Waived(_) => {
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
            shapes: vec![shape("no-bare-cargo", "cargo", None)],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        }
    }

    fn program_only_shape_denies(command: &str) -> bool {
        matches!(
            adjudicate(
                &program_only_shape_policy(),
                &envelope(command),
                false,
                &None,
                &None,
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
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        }
    }

    fn require_via_denies(command: &str) -> bool {
        matches!(
            adjudicate(
                &require_via_policy(),
                &envelope(command),
                false,
                &None,
                &None,
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
                &None,
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
                &Policy::declaring_nothing(Harness::ExitCode),
                &envelope("gh pr merge 42"),
                false,
                &None,
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
            harness: Harness::ExitCode,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &policy,
                &envelope("gh pr merge 42"),
                false,
                &None,
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
            harness: Harness::ExitCode,
            shapes: vec![rule.clone()],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &advisory,
                &call,
                false,
                &None,
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow,
            "a warn row does not block a mediated call on its own"
        );

        let promoted = Policy {
            harness: Harness::ExitCode,
            shapes: vec![rule],
            fail_on_warning: true,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        assert!(
            matches!(
                adjudicate(
                    &promoted,
                    &call,
                    false,
                    &None,
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
            harness: Harness::ExitCode,
            shapes: vec![
                shape("first", "gh pr merge", None),
                shape("second", "gh pr merge", None),
            ],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &None,
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
            harness: Harness::ExitCode,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        let reason = denial_text(adjudicate(
            &policy,
            &envelope("gh pr merge"),
            false,
            &None,
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
            harness: Harness::ExitCode,
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
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
            &None,
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
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
            redirects: Vec::new(),
        }
    }

    fn adjudicate_write(facts: &ReceiptFacts) -> Decision {
        adjudicate(
            &claim_policy(),
            &write_envelope("Write", "crates/batten/src/new.rs"),
            false,
            facts,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    #[test]
    fn a_write_triggered_row_fires_on_a_write_that_carries_no_command() {
        // The gap this closes: every write returned Allow before the command
        // gate ran, so a receipt row could never be a precondition for editing.
        assert!(matches!(
            adjudicate_write(&Some(resolved(&[("claim", Validity::Missing)]))),
            Decision::Deny(_)
        ));
        assert_eq!(
            adjudicate_write(&Some(resolved(&[("claim", Validity::Valid)]))),
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
                &Some(resolved(&[("claim", Validity::Missing)])),
                &None,
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
                &Some(resolved(&[("verify", Validity::Missing)])),
                &None,
                &crate::stop::StopFacts::default(),
            ),
            Decision::Allow,
            "a command-triggered row must not judge a write"
        );
    }

    #[test]
    fn a_write_the_boundary_did_not_judge_is_allowed() {
        // `None` is the boundary saying there is no receipt question here — a
        // git-ignored path, one outside the repository, one inside `.git`, or a
        // detached HEAD. Every one of them allows, and they are the load-bearing
        // half: a gate that refused them would refuse every write in the
        // container and be switched off within the hour.
        assert_eq!(adjudicate_write(&None), Decision::Allow);
    }

    #[test]
    fn a_branch_keyed_refusal_says_branch_rather_than_commit() {
        // The wrong pointer this avoids: "no receipt for this commit" sends the
        // reader looking for a per-commit step, when what is missing is a claim
        // the whole branch shares.
        let reason = denial_text(adjudicate_write(&Some(resolved(&[(
            "claim",
            Validity::Missing,
        )]))));
        assert!(reason.contains("branch"), "names the keying: {reason}");
        assert!(
            !reason.contains("this commit"),
            "must not name a commit: {reason}"
        );
        assert!(reason.contains("claim-check"), "names the route: {reason}");
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
                &None,
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
            shapes: vec![rule],
            fail_on_warning: false,
            verbs: Vec::new(),
            protected: PathSet::empty(),
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
                &Some(resolved(&[("toolchain", Validity::Missing)])),
                &None,
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
                &None,
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

    /// Adjudicate `command` against a policy carrying exactly `verbs`.
    ///
    /// [`guarded`] pins the unqualified table; this is its sibling for the
    /// qualifier rows, so each test declares the rows it is about.
    fn guarded_by(verbs: Vec<MutatingVerb>, command: &str) -> Decision {
        adjudicate(
            &protected_policy(verbs),
            &envelope(command),
            false,
            &None,
            &None,
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
                        &None,
                        &None,
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
                &None,
                &None,
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

    /// Adjudicate against the protected fixture with a declared redirect table.
    fn guarded_with(redirects: Vec<Redirect>, command: &str) -> Decision {
        adjudicate(
            &protected_policy_with(
                vec![verb("rm", Some("restore it with git")), verb("mv", None)],
                redirects,
            ),
            &envelope(command),
            false,
            &None,
            &None,
            &crate::stop::StopFacts::default(),
        )
    }

    fn redirect_row(glob: &str, mutation: &str) -> Redirect {
        Redirect {
            glob: glob.to_owned(),
            mutation: mutation.to_owned(),
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
        // Tier three, also unchanged: `mv` declares no redirect and no row
        // claims the path, so the absence is stated as a value.
        let decision = guarded_with(
            vec![redirect_row("somewhere/else/**", "irrelevant")],
            "mv batten.toml elsewhere",
        );
        let refusal = denial(decision.clone());
        assert_eq!(refusal.fix(), &Fix::None);
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
                &None,
                &crate::stop::StopFacts::default()
            ),
            Decision::Allow
        );
        let no_paths = Policy {
            harness: Harness::ExitCode,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: vec![verb("rm", None)],
            protected: PathSet::empty(),
            redirects: Vec::new(),
        };
        assert_eq!(
            adjudicate(
                &no_paths,
                &envelope("rm batten.toml"),
                false,
                &None,
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
            harness: Harness::ExitCode,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs: verbs.clone(),
            protected: PathSet::includes("protected", &["guarded/**".to_owned()])
                .expect("well formed"),
            redirects: Vec::new(),
        };
        let elsewhere = Policy {
            harness: Harness::ExitCode,
            shapes: Vec::new(),
            fail_on_warning: false,
            verbs,
            protected: PathSet::includes("protected", &["other/**".to_owned()])
                .expect("well formed"),
            redirects: Vec::new(),
        };
        let call = envelope("rm guarded/thing");
        assert!(
            matches!(
                adjudicate(
                    &guarding,
                    &call,
                    false,
                    &None,
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
                &None,
                &None,
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
            }],
        );
        let Decision::Deny(refusal) = adjudicate(
            &policy,
            &write_envelope_on(Harness::GeminiCli, "WriteFile", "batten.toml"),
            false,
            &None,
            &None,
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
}
