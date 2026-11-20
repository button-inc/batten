//! Typed errors that carry their intended process exit code.
//!
//! Most failures in the library are genuine internal errors ([`ExitCode::Internal`]).
//! A [`UsageError`] is different: it marks an *expected* bad-input condition —
//! a malformed config, an unknown key, an unsupported version — that the
//! exit-code contract (§7) maps to [`ExitCode::Usage`] (exit `1`), not to an
//! internal failure. The binary boundary downcasts to it to pick the code.
//!
//! [`Denial`] is not a failure at all: it is the mediation verdict travelling to
//! the one place allowed to write stderr. It rides the error channel because the
//! library never prints, and the boundary maps it to [`ExitCode::Violation`]
//! (exit `2`) — printing the reason *unprefixed*, since a verdict is an answer
//! and must not read as a crash.
//!
//! [`ExitCode::Internal`]: crate::ExitCode::Internal
//! [`ExitCode::Usage`]: crate::ExitCode::Usage
//! [`ExitCode::Violation`]: crate::ExitCode::Violation
//! [`Denial`]: crate::refusal::Denial

use std::fmt;

/// A wrapped command's own exit code, travelling to the boundary that reports it.
///
/// **Not a failure, and not Batten's answer.** `batten exec` is a transparent
/// passthrough (CLOUD-285): the code belongs to the child, so it is neither a
/// policy verdict nor a statement about the invocation, and it is deliberately
/// outside [`crate::ExitCode`]'s table. That table stays total over the four codes
/// Batten *chooses*; this type is how a code Batten did not choose reaches the
/// process without pretending to be one of them.
///
/// It rides the error channel for the same reason [`Denial`] does — the library
/// never exits a process — and the boundary maps it to the child's code with no
/// output of its own.
///
/// The property that matters is preserved: **Batten never mints a `2` here.** A
/// `2` from `exec` is the child's. Mediated calls are adjudicated by
/// [`crate::hook`], never by this path, so nothing reads an `exec` code as a deny.
///
/// [`Denial`]: crate::refusal::Denial
#[derive(Debug)]
pub struct Passthrough(pub i32);

impl fmt::Display for Passthrough {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the wrapped command exited {}", self.0)
    }
}

impl std::error::Error for Passthrough {}

impl Passthrough {
    /// Build a [`Passthrough`] as an [`anyhow::Error`], ready to `return Err(..)`.
    #[must_use]
    pub fn raise(code: i32) -> anyhow::Error {
        anyhow::Error::new(Passthrough(code))
    }

    /// The byte a process exit status can actually carry.
    ///
    /// Saturates rather than truncating. A code outside one byte can only come
    /// from a non-POSIX child, and taking its low byte could turn a failure into a
    /// success — `0x100` would report `0`. Saturating keeps a non-zero code
    /// non-zero, which is the only property a caller can act on.
    #[must_use]
    pub fn byte(&self) -> u8 {
        u8::try_from(self.0).unwrap_or(u8::MAX)
    }
}

/// An expected bad-input error that maps to [`ExitCode::Usage`] (exit `1`).
///
/// # The class is a field, not a formatted prefix
///
/// CLOUD-1050's measured lesson is that a refusal carried as a free `String`
/// makes a bad refusal **expressible and uncheckable** — that is why a policy
/// `violation` binds `{rule, verdict, subjects}` and has no `msg`. The
/// config-load surface had the same defect: ~172 `raise` sites, none naming a
/// class, so `batten policy explain` could not resolve a config fault and no
/// gate held one to the `[[verdict]]` registry (CLOUD-1313).
///
/// Formatting a token into the message would have reproduced that defect one
/// surface over, because nothing would check that the token is declared.
/// [`Native`] is an enum, so a raise site can only name a class that exists,
/// and `the_vendored_table_validates` proves every variant carries a row.
///
/// [`ExitCode::Usage`]: crate::ExitCode::Usage
#[derive(Debug)]
pub struct UsageError {
    /// The prose. Unchanged from the pre-class shape, deliberately: rewording
    /// the twelve validators' refusals is explicitly outside CLOUD-1313.
    pub message: String,
    /// The declared class this fault belongs to, where one is known.
    ///
    /// `None` is not a gap to be closed everywhere — most `UsageError`s are
    /// argument faults, not config faults, and inventing a class for each would
    /// be the per-site explosion CLOUD-1313 rejected. It is `Some` exactly where
    /// a raiser can name the table it was validating.
    pub verdict: Option<Native>,
}

impl fmt::Display for UsageError {
    /// `<class>: <message>` when a class is known, the bare message otherwise.
    ///
    /// The separator is a deliberate deviation from CLOUD-1286's
    /// `<class> <pointer…>`, and the reason is that these messages are PROSE.
    /// That shape reads as a class followed by pointers precisely because
    /// nothing separates them; running a class straight into a sentence would
    /// make the first three words of the sentence look like part of the class.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.verdict {
            Some(native) => write!(f, "{}: {}", native.id(), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for UsageError {}

impl UsageError {
    /// Build a classless [`UsageError`] as an [`anyhow::Error`], ready to
    /// `return Err(..)`.
    ///
    /// Named `raise` rather than `new` because it returns an [`anyhow::Error`]
    /// wrapping the `UsageError`, not `Self`.
    pub fn raise(message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(UsageError {
            message: message.into(),
            verdict: None,
        })
    }

    /// Build a [`UsageError`] that names the class it belongs to.
    ///
    /// Callers are the config loader's per-table wrappers; see
    /// [`crate::config`]'s `under`.
    pub fn raise_as(verdict: Native, message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(UsageError {
            message: message.into(),
            verdict: Some(verdict),
        })
    }
}

// ─── The crate's own refusal classes (moved from `crate::verdict`) ───────────

// Declared through `token_enum!` (CLOUD-2442). Declaration order is kept, so
// discriminants (which `semver` reads as API) do not move.
token_enum! {
/// A refusal class the CRATE owns, as opposed to one a consumer declares.
///
/// # Why this is an enum and not a table of strings
///
/// The registry's whole claim is that a token cannot be raised without being
/// declared. On the policy side that is enforced by reading the module's AST at
/// load; on the native side there is no AST to read, so the coupling has to be
/// in the type system or it is a convention. An enum gives it for free: a native
/// site names a variant, [`Native::ALL`] and each token are generated from the
/// one declaration (`token_enum!`), and a site raising a class nobody declared is a
/// compile error rather than a finding.
///
/// The coupling `crate::facts::Fact` also wants, and for the same reason;
/// `Fact` still keeps its list by hand (CLOUD-2454 moves it where it fits).
///
/// # These are Batten's OWN words
///
/// Every variant here is a class the crate states about itself: a protected path
/// was targeted, a scanner is unpinned, a read-effect verb was asked to spawn. A
/// refusal composed from a consumer's `[[rule]]` row is a different thing — the
/// remedy is the consumer's declared `reason` and lives in their authority under
/// house style §8 — and it is not represented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Native by id {
    /// A mutating verb was aimed at a path the config protects.
    ProtectedMutation => "path write refused",
    /// `batten init` would overwrite the committed authority.
    InitWouldOverwrite => "config write refused",
    /// A configured hook handler denied the call.
    HandlerDenied => "handler answer denied",
    /// A `secrets` rule needs a scanner and the config pins none.
    ScannerUnpinned => "scanner pin missing",
    /// The pinned scanner is not in the provision cache.
    ScannerUnprovisioned => "scanner install missing",
    /// A rule kind that spawns was reached through a read-effect verb.
    SpawningRuleOnReadVerb => "spawn run refused",
    /// The end-of-turn facts do not permit stopping.
    StopConditionUnmet => "turn finish unmet",
    /// A `git reset --hard` would leave commits reachable from no remote.
    HistoryDropUnpushed => "history drop unpushed",
    /// A task a live process already holds the singleton lock for.
    SingletonHeld => "task run twice",
    // ─── the mediated composers' own classes (CLOUD-1285) ────────────────────
    //
    // These are Batten's OWN words about generic concepts, which is what puts
    // them here rather than in a consumer `[[verdict]]` row. The engine composed
    // each cause as a hardcoded `format!` in `hook.rs` and then threw the class
    // away by calling `Refusal::new`, so `refusal.verdict()` was `None` on eight
    // of ten mediated deny paths and `batten policy explain` was unreachable from
    // every path that actually fires.
    //
    // The consumer's `[[rule]]` row still supplies the FIX -- `Refusal::declared`
    // takes it as a parameter and a narrower one wins -- so this does not move
    // the remedy into the crate. It moves the CAUSE, which was already here.
    /// No receipt at all for what the row keys on.
    ReceiptUnusable => "receipt read missing",
    /// The receipt exists and is older than the row allows.
    ReceiptExpired => "receipt read late",
    /// The receipt records something the row does not accept.
    ReceiptRefuted => "receipt carry other",
    /// An amend or a rebase replaced the bytes the receipt validated.
    ReceiptSuperseded => "receipt read other",
    /// The receipt was taken against a trunk this branch has moved off.
    ReceiptOffTrunk => "receipt read stale",
    /// A shell text utility stood in for the structured file surface.
    ToolSubstituted => "tool run loose",
    /// A verdict-bearing command was piped into a pager or filter.
    VerdictPiped => "verdict read dropped",
    /// A verdict-bearing command was followed by `;`, `||` or a newline.
    VerdictTrailing => "verdict carry other",
    /// A verdict-bearing command was detached from its tool call.
    RunOrphaned => "turn watch dropped",
    /// The call measures over a declared ceiling.
    CeilingExceeded => "call count over",
    /// The call matches a refused command shape.
    ShapeRefused => "call name refused",
    /// The boundary repaired what it refused; re-issue the identical call.
    ///
    /// Raised in place of the original class when a row's `fix` ran and the
    /// class declares [`crate::verdict::Applicability::Retry`] (CLOUD-1639). Still a refusal:
    /// the call as made did not happen.
    CallRetryNow => "call retry now",
    /// The boundary repaired it and let the call through, owing a record.
    ///
    /// The `silent` posture's class. It rides `additionalContext` rather than a
    /// refusal, because the call was allowed — the record is the point.
    CallFixSilent => "call fix silent",
    /// The content this call would write matches a refused shape.
    ContentRefused => "input write refused",
    /// The work this call publishes names no tracker key.
    KeyMissing => "issue name missing",
    // ─── the config loader's own classes (CLOUD-1313) ────────────────────────
    //
    // A load-time refusal was a bare `UsageError(String)` across ~172 sites, so
    // a config fault was the ONE refusal class in this engine that
    // `batten policy explain` could not resolve and no gate held to the
    // registry -- CLOUD-1050's defect, one surface over.
    //
    // ONE CLASS PER TABLE, NOT PER SITE. Only ~30 of those raises sit at a
    // top-level `validate`; the rest are in per-entry helpers, so a class per
    // site is unbuildable. The class says WHICH TABLE would not load and the
    // message carries the row and key, which is the same division `[[verdict]]`
    // draws between a class and its subjects.
    //
    // They are `Native` rather than consumer rows for the reason the enum's own
    // doc gives: the loader raises them BEFORE any config exists to declare
    // them, so a declared-row spelling would be unsatisfiable at exactly the
    // moment it fires. That also makes them resolvable from `vendored()` with
    // no config load, which is what keeps `policy explain` usable over a config
    // that will not parse.
    /// The `[[verb]]` table would not load.
    VerbTableRefused => "verb declare refused",
    /// The `[[pattern]]` table would not load.
    PatternTableRefused => "pattern declare refused",
    /// The `[[traversal]]` table would not load.
    TraversalTableRefused => "traversal declare refused",
    /// The `[[verdict]]` table would not load.
    VerdictTableRefused => "verdict declare refused",
    /// The `[[redirect]]` table would not load.
    RedirectTableRefused => "redirect declare refused",
    /// The `[[deferral]]` table would not load.
    DeferralTableRefused => "deferral declare refused",
    /// A declared remedy names no command that exists (CLOUD-1189's class).
    RemedyUnresolved => "remedy resolve missing",
    /// The `[[marker]]` table would not load.
    MarkerTableRefused => "marker declare refused",
    /// The `[[rule]]` table would not load.
    RuleTableRefused => "rule declare refused",
    /// The `[[exec_pattern]]` table would not load.
    OutputTableRefused => "output declare refused",
    /// The `[[verify_environment_pattern]]` table would not load.
    ///
    /// A SECOND CLASS OVER THE SAME TYPE, and the census refuses sharing one:
    /// both tables are `OutputPattern`, but a refusal has to name which table to
    /// edit, and one class over two tables sends a reader to the wrong one.
    VerifyEnvironmentTableRefused => "environment declare refused",
    /// The `[[waiver]]` table would not load.
    WaiverTableRefused => "waiver declare refused",
    /// The `[[fact]]` table would not load.
    FactTableRefused => "fact declare refused",
    /// The `[[mint]]` table would not load.
    MintTableRefused => "mint declare refused",
    /// The `[[recorder]]` table would not load.
    RecorderTableRefused => "recorder declare refused",
    /// The `[[provision]]` table would not load.
    ProvisionTableRefused => "provision declare refused",
    /// The `[[startup]]` table would not load.
    StartupTableRefused => "startup declare refused",
    /// The `[[outcome]]` table would not load.
    OutcomeTableRefused => "outcome table refused",
    /// The committed plan projection no longer matches the pinned runner.
    ///
    /// Batten's OWN word about a generic concept — an adopted tool's contract
    /// and the artifact that records it — which is what puts it here rather
    /// than in a consumer `[[verdict]]` row. No consumer can name the class,
    /// because the engine is what takes the plan and what compares it.
    PlanReadStale => "plan read stale",
    /// The declaration could not be READ AT ALL — not valid TOML.
    ///
    /// **APPENDED, NEVER INSERTED.** This enum carries no `repr`, so a variant
    /// added in the middle shifts every later discriminant and
    /// `enum_no_repr_variant_discriminant_changed` reads the whole tail as
    /// broken — measured here, where placing it beside the other config classes
    /// moved eighteen of them. Position is API; the reading order below is not.
    ///
    /// **Deliberately not in [`Native::CONFIG_FAULTS`]**, which is the per-TABLE
    /// set and is censused in both directions against `config.rs`'s own list. This
    /// one has no table: it is raised before any table exists, by the parse that
    /// every table's validator runs after.
    ///
    /// # Why it needs a class when the other parse failures do not
    ///
    /// A class here is not for `explain` — it is the DISCRIMINATOR the mediated
    /// boundary acts on (CLOUD-1677). Gates are registered fail-open, and a gate
    /// that fails open is inert: it neither allows nor denies, it is absent. So a
    /// config fault is never a choice between refusing and allowing, it is a
    /// choice between keeping the enforcement surface we still have and losing it
    /// entirely.
    ///
    /// An unknown key, a version this build is too old for, a row whose validator
    /// refused — each leaves every OTHER row readable and enforceable, and leaves
    /// an agent that can still be told to repair the one that is broken. Failing
    /// the whole load there buys nothing and costs the surface that would have
    /// carried the repair instruction.
    ///
    /// A file that is not TOML is the one case with no partial function to
    /// preserve: zero rows are readable, so refusing the call is the only signal
    /// left, and the declared hatch is the recovery path. That asymmetry is why
    /// this class exists and why it is exactly one class wide.
    ConfigUnreadable => "config read refused",
    /// The boundary cannot classify the program, so it will not guess.
    ///
    /// **APPENDED, NEVER INSERTED**, per [`Native::ConfigUnreadable`]'s note: this
    /// enum carries no `repr`, so a variant placed beside its relatives shifts
    /// every later discriminant.
    ///
    /// # Why this is not [`Native::ProtectedMutation`], which it was (CLOUD-1804)
    ///
    /// The unknown-program arm and the declared-verb arm are different claims and
    /// raised one class between them. That class's gloss reads *"a mutating verb
    /// was aimed at a path the config protects"*, and for this arm it is **false
    /// every time it fires**: `hook`'s own composer says the boundary does not
    /// know what the program does to its operands and will not guess, which is
    /// the opposite of asserting a mutation.
    ///
    /// The cost was not cosmetic. The reporting consumer read the class over a
    /// config whose `protected` was EMPTY — the paths were derived from their
    /// `[[rule]]` rows — and spent the time ruling out their own configuration
    /// that a class saying "this program is unclassified" would have saved.
    ///
    /// It also makes the remedy reachable. `unknown_program_refusal` already
    /// carried its own fix — declare the program a reader if it only reads — and
    /// `batten policy explain` could not reach it, because the class it resolved
    /// belonged to the other arm.
    ProgramUnknown => "program name unknown",
    /// The `[[record]]` table would not load (CLOUD-1810).
    ///
    /// Its own class rather than the recorder's, on the reason the environment
    /// pair states: the two tables carry different rows and a refusal has to name
    /// which one to edit.
    ///
    /// **APPENDED, BECAUSE THE VARIANT ABOVE SAYS SO AND THIS ONE DID NOT LISTEN.**
    /// It landed beside the other config classes — between `RecorderTableRefused`
    /// and `ProvisionTableRefused`, where it reads best — and that shifted the
    /// discriminants of `ProvisionTableRefused`, `StartupTableRefused`,
    /// `OutcomeTableRefused`, `PlanReadStale` and `ConfigUnreadable`, which is the
    /// whole tail `enum_no_repr_variant_discriminant_changed` reads as broken.
    /// Position is API; the reading order is not. `Native::ALL` follows
    /// declaration order since CLOUD-2442, so grouping by meaning lives in the
    /// subsets (`CONFIG_FAULTS`), never in a reordered list.
    RecordTableRefused => "record declare refused",
    /// The `[[step]]` table would not load (CLOUD-843).
    ///
    /// **APPENDED LAST**, for [`Native::RecordTableRefused`]'s reason: position is
    /// API.
    StepTableRefused => "step declare refused",
    /// A structured READ of a path whose `[[redirect]]` row declares its own
    /// read route (CLOUD-1929). Not [`Native::ToolSubstituted`]: no shell
    /// utility was involved, and that class's route pointed a memory reader at
    /// `rules/scanning.md` instead of the tool the row names.
    ReadRedirected => "path read routed",
    /// A commit subject does not match `[commit] subject_pattern` (CLOUD-1960).
    ///
    /// **APPENDED LAST**, with the nine below, for [`Native::RecordTableRefused`]'s
    /// reason. These ten are the commit-msg channel's classes: `[commit]` and
    /// `[attribution]` are the engine's own tables, so a consumer that declares
    /// either and no `[[verdict]]` row still gets a token `explain` resolves.
    SubjectUnconventional => "commit spelling wrong",
    /// A commit in a judged range names no tracker row and no exemption covers it.
    CommitUnclaimed => "commit name missing",
    /// A commit wrote a protected path and carries no articulation block for it.
    ArticulationMissing => "commit admit missing",
    /// An articulation block claims a path and does not hash to its address.
    ArticulationTampered => "commit admit other",
    /// A commit introduces a conserves-ledger arm and spends it at once.
    ArmSelfAuthorized => "commit admit same",
    /// A commit's author or committer matches `[attribution] identity_deny`.
    IdentityDenied => "commit own refused",
    /// A commit carries a trailer `[attribution] trailer_deny` refuses.
    TrailerDenied => "commit carry refused",
    /// A commit message body matches `[attribution] body_deny`.
    BodyDenied => "commit state refused",
    /// A tag was cut by an identity `tag_identity_allow` does not permit.
    TaggerUnaccountable => "tag own refused",
    /// A tag carries no tagger identity at all.
    TaggerUnannotated => "tag own unnamed",
    /// A config string is longer than the cap its column declares (CLOUD-1642).
    ///
    /// **APPENDED LAST**, for [`Native::RecordTableRefused`]'s reason. A config
    /// fault, raised by the loader after every table validator, so it is in
    /// [`Native::CONFIG_FAULTS`].
    ProseColumnRefused => "prose declare refused",
    /// The `[[register]]` table would not load (CLOUD-2005).
    ///
    /// **APPENDED LAST**, for [`Native::ProseColumnRefused`]'s reason: a
    /// variant inserted mid-enum moves every later discriminant, which
    /// `semver` refuses. A config fault, so it is in [`Native::CONFIG_FAULTS`].
    RegisterTableRefused => "register declare refused",
    /// A config row was changed by a context that has not read its history
    /// (CLOUD-2144).
    ///
    /// **APPENDED LAST**, for [`Native::ProseColumnRefused`]'s reason.
    RuleReadMissing => "rule read missing",
    // ── the unclassed emitters' classes (CLOUD-2078) ───────────────────────
    // One class per emitter FAMILY, never one per site (CLOUD-1313's rule):
    // the site's own message travels as a subject. APPENDED LAST, for
    // [`Native::ProseColumnRefused`]'s reason.
    /// A CLI invocation refused before it ran: a classless `UsageError` or a
    /// clap usage error.
    UsageRefused => "input parse refused",
    /// Any other CLI failure: a diagnosis of Batten, not a verdict on the work.
    RunBroken => "verb run broken",
    /// `pr derive` cannot derive the row a bot PR implies.
    IssueFileRefused => "issue file refused",
    /// An ingested layer would replace a committed value it may only tighten.
    LayerCarryRefused => "layer carry refused",
    /// A fetched provision does not match its pin.
    ProvisionPinOther => "provision pin other",
    /// The Stop ladder's unlanded rung.
    CommitShipMissing => "commit ship missing",
    /// The Stop ladder's unlanded rung, on a clone too shallow to look.
    CommitShipUnknown => "commit ship unknown",
    /// The Stop ladder's unlanded rung, where a person merges and the work is
    /// not pushed.
    CommitPushMissing => "commit push missing",
    /// The Stop ladder's unlanded rung, where a person merges what is pushed.
    CommitMergeHeld => "commit merge held",
    /// The Stop ladder's filed-set rung.
    IssueListUnclear => "issue list unclear",
    /// A `[[hook.handler]]` reported on this call.
    HookReportNow => "hook report now",
    /// A `[[hook.handler]]` broke its contract.
    HookAnswerBroken => "hook answer broken",
    /// A response this call should have captured was not.
    OutputWriteMissing => "output write missing",
    /// A failing doctor check or startup row.
    WorkspaceStateBroken => "workspace state broken",
    /// A call a declared rule or handler pre-approved.
    CallGrantNow => "call grant now",
    /// A land replay conflicted and stopped.
    CommitPortBlocked => "commit port blocked",
    /// The configured gate refused the head `land` verified.
    CheckRunRed => "check run red",
    /// A required CI check failed on the head `land` waited on.
    JobRunRed => "job run red",
    /// `land` spent every lap without landing.
    LaneCountSpent => "lane run spent",
    /// A declared contract file moved under a running session.
    ContractReadStale => "contract read stale",
    /// The engine did not run at this session's start.
    HookRunMissing => "hook run missing",
    /// A drain's delta did not fit its token budget, so the relief valve cut
    /// it (CLOUD-2175).
    DrainFitBroken => "drain fit broken",
    /// An issue fails a checkable Ready clause (`ready lint`).
    IssueGradeRefused => "issue grade refused",
    /// `ready lint` could not judge an issue's relations: the fetch lacked them.
    IssueGradePartial => "issue grade partial",
    /// `claim check` refused to mint the claim: someone holds it, or the
    /// refinement sequence was not followed.
    ClaimMintRefused => "claim mint refused",
    /// A reduced read stored the whole response and points at a view of it,
    /// field by field (CLOUD-2207).
    OutputPointNow => "output point now",
    /// Free space fell below `[prune] min_free_mb`, so the disk collector
    /// removed cargo units before the call ran (CLOUD-2197).
    CargoRetireNow => "cargo retire now",
    /// A script interpreter ran a script file outside the repository (CLOUD-2304).
    ///
    /// **APPENDED LAST**, for [`Native::ProseColumnRefused`]'s reason.
    ScriptRunLoose => "script run loose",
    /// A call reached a repository other than its session's home, where the
    /// home arms the reach gate (CLOUD-2672). Appended last, as above.
    CallReachLoose => "call reach loose",
}
}
