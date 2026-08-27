//! The rule and check engine (CLOUD-12).
//!
//! A rule is a **declarative predicate over the repository**: it selects files
//! with a `glob` and applies a `kind`-specific test to them, mapping the outcome
//! onto the exit-code contract (§7) through the rule's `severity` (CLOUD-61) —
//! a clean run exits `0`, any `deny` finding exits `2`, a `warn` finding is
//! reported without failing the run, and an `allow` rule is configured off.
//! `severity` is required per rule with no implicit fallback, and is a separate
//! key from `scope` ([`RuleScope`]) — where a rule looks is never what a match
//! does.
//!
//! **Two entry points, split by effect (§5, CLOUD-170).** [`run_static`] backs
//! the `read`-effect `batten check` and admits only kinds that cannot spawn a
//! process; [`run_all`] backs the unclassified `batten enforce` and admits
//! every kind. The split is what keeps `check`'s `read` classification — and so
//! the derived agent read-only allowlist — honest once a kind can execute a
//! command declared in `batten.toml`. `check` **refuses** such a rule rather
//! than skipping it, because a skipped gate that still exits `0` is the
//! false-green Batten exists to catch.
//!
//! Three kinds ship: [`RuleKind::Forbid`], a static banned-shape literal check
//! over files; [`RuleKind::Command`], the dynamic escape hatch that runs a
//! configured command and reads its exit code as the predicate; and
//! [`RuleKind::Shape`], a banned *command* shape adjudicated by `batten hook`
//! against one mediated call. [`RuleScope`] is what routes a rule to the surface
//! that evaluates it, and [`RuleKind::scopes`] pairs the two so a rule no
//! surface would ever run cannot load. Two properties are load-bearing and
//! preserved by every kind added later:
//!
//! * **Pointer-only output** (non-negotiable rule 4): a finding is a
//!   `path:line`, never the matched bytes.
//! * **Byte-stable results** (§6): findings are sorted, so identical input yields
//!   identical output — and rule-scoped findings are deduped *before* that sort
//!   ([`dedup_scoped`]), so a `command` rule failing in every batch of a large
//!   match set reports once rather than once per batch (CLOUD-396).
//!
//! File selection is intentionally simple at this stage: a walk of the working
//! tree, skipping `.git`. Scoping selection to the git change-set / protected /
//! unlanded sets is a separate concern (CLOUD-36, CLOUD-37) that layers on top of
//! this walk without changing the rule model.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::ValueEnum;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::findings::{Check, NotObserved, Remediation};
use crate::identity;
use crate::refusal::{Fix, Refusal};
use crate::severity::{self, AdvisoryTier, ReportLevel, RuleSeverity};

/// The columns a [`RuleKind::Pipeline`] row may carry — both predicate families
/// plus the shared remedy (CLOUD-864).
///
/// Named rather than inlined in `RuleKind::permits` because the substitution
/// family's column takes the list past one line, and eight more lines inside
/// that match pushes the function past its length ceiling.
///
/// It was once "the only list worth naming", on the grounds that `pipeline` was
/// the only kind carrying two predicates. That stopped being true when CLOUD-924
/// gave `shape` a third keying column and `receipt` a second, so the two lists
/// below join it here for the same length reason rather than a new one.
const PIPELINE_PERMITS: &[&str] = &[
    "verdict",
    "filters",
    "substitutes",
    "reason",
    "policy_url",
    "bypass_env",
    "severity",
];

/// One reference-to-path rewrite for a [`CeilingUnit::TrackedArtifacts`] ceiling
/// (CLOUD-925).
///
/// Both fields are the **consumer's**. A shorthand a repository writes in its own
/// prompts to name its own files is a property of that repository, so naming
/// either half in `crates/batten` would be the consumer-specific identifier
/// non-negotiable rule 1 forbids — the same split
/// [`crate::budget::EmbeddedDecl`] already makes for a config key it counts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    /// The reference shape, as a regular expression over one candidate token.
    /// Capture groups are available to `path`.
    pub reference: String,
    /// The repository-relative path the reference names, with `$1`-style
    /// references to `reference`'s capture groups.
    pub path: String,
}

/// What a [`Rule::max`] ceiling counts over its declared projection (CLOUD-925).
///
/// Two units rather than one, because `fanout-guard`'s two conjuncts measure the
/// same bytes and differ in the *subject* of the cap: the prompt's own size, and
/// how many tracked artifacts it names. A single unit would have forced one of
/// them into a second rule kind.
///
/// **The unit cannot be inferred from the projection**, which is why this is a
/// column rather than a derivation: one prompt has both a token count and a
/// manifest count, and a row has to say which one it is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CeilingUnit {
    /// Estimated tokens over the projection, via [`crate::budget::estimate_tokens`].
    ///
    /// **The same estimator the file-set budget uses**, not a second one: CLOUD-925
    /// §1 requires one authority for what a ceiling is, so a per-call cap must not
    /// arrive with its own arithmetic. `free` — the bytes are already decoded.
    Tokens,
    /// How many **tracked** repository artifacts the projection names.
    ///
    /// The reading manifest: path-shaped tokens intersected with the tracked set,
    /// plus resolvable memory references. Tracked is the whole of it — a spawn
    /// naming a path this repository does not carry is naming nothing it can be
    /// made to read, so it does not count, and a URL or a branch name drops out
    /// by construction rather than by an allowlist somebody has to tune.
    ///
    /// **This unit is the one that acquires.** It needs the tracked set, which is
    /// a property of a checkout and not of the envelope, so it is resolved at the
    /// boundary and reaches [`crate::hook::adjudicate`] as a fact — never opened
    /// from inside the decision, which stays pure.
    TrackedArtifacts,
}

/// The columns a [`RuleKind::Shape`] row may carry.
///
/// Three keying columns, exactly one of which a row carries — `pattern` (a
/// command line), `content` (what a write would land), `tool` (the tool a call
/// names, CLOUD-924). A flat list cannot say "one of", so
/// `Rule::validate_shape_columns` carries that refusal; this list is only what
/// the kind *accepts*.
///
/// `requires_key` brings `base` with it — the range its evidence is read over —
/// which is why the ratchet's column is permitted here rather than duplicated
/// under another name (CLOUD-446). No `identity_key` or `verbatim`: a shape row
/// is adjudicated per mediated call and never reaches the store, so an identity
/// column on one is decorative by construction (non-negotiable rule 6).
const SHAPE_PERMITS: &[&str] = &[
    "pattern",
    "content",
    "tool",
    // The per-call ceiling, a modifier rather than a fourth keying column
    // (CLOUD-925): the row selects on its own terms and these decide whether that
    // selection refuses.
    "measures",
    "counts",
    "max",
    "resolves",
    // CLOUD-987: the row selects, this decides whether the selection refuses.
    "when_absent",
    "when_present",
    "when_value",
    "reason",
    "contains",
    "require_via",
    "requires_key",
    "base",
    "policy_url",
    "bypass_env",
    "severity",
];

/// The columns a [`RuleKind::Receipt`] row may carry.
///
/// Two selectors, `pattern` and `tool`, and a row carries one — CLOUD-312's rows
/// 1-3 are receipt rows keyed on `.*save_issue`, a structured call with no
/// command line for `pattern` to match. `key` and `trigger` are optional with
/// pinned defaults, so a row omitting either is still total: `key` selects which
/// git fact the receipt is keyed to, `trigger` what makes the row fire.
const RECEIPT_PERMITS: &[&str] = &[
    "pattern",
    "tool",
    "checks",
    "key",
    "key_from",
    "key_shape",
    "max_age",
    // CLOUD-987's modifiers, on this kind too and for CLOUD-312's row 1 exactly:
    // the precondition is due only when the call CREATES a tracker row, which is
    // the call that named no `id`. Gating an update would demand a search before
    // every edit — "absurd, and would get the guard switched off within a day" in
    // the guard's own words. A row that cannot say WHICH calls owe the receipt has
    // to gate all of them, which is the false-positive rate that gets a guard
    // switched off rather than satisfied.
    "when_absent",
    "when_present",
    "when_value",
    "trigger",
    "reason",
    "contains",
    "policy_url",
    "bypass_env",
    "severity",
];

/// The kind of predicate a [`Rule`] applies to its matched files.
///
/// Serialized as a lowercase `kind = "..."` token in `batten.toml`. Marked
/// `#[non_exhaustive]` because the engine is designed to grow kinds (the dynamic
/// `command` kind is CLOUD-89) without that being a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleKind {
    /// A static banned shape, one line at a time. Every line of a matched file
    /// that carries the banned shape is a finding, unless `exclude` takes it
    /// back out. The check is inspection-only.
    ///
    /// The shape is either the literal `pattern` or the expression `regex` —
    /// exactly one, never both (CLOUD-283). The literal is the common case and
    /// the readable one; the expression is for a predicate that genuinely is a
    /// shape, such as a flag cluster judged by its letters.
    Forbid,
    /// A dynamic check: run the `check` template and treat its exit code as the
    /// predicate — `0` passes, non-zero is a violation. The sanctioned escape
    /// hatch for rules no static shape can express.
    ///
    /// The kind carries house style §9's **`check`/`fix` duality**: `check` is
    /// the inspection-only gate and the only side enforcement ever runs, `fix`
    /// is the optional mutating half. The duality is a contract with the config
    /// author that Batten cannot verify — an arbitrary command declared as a
    /// check may still write — so it governs how a rule is *authored* and never
    /// licenses the verb that runs it to claim `read`.
    ///
    /// It is an **exit-code predicate, not a judge** (CLOUD-93): the command's
    /// output is never parsed for meaning. Because it executes a process
    /// declared in `batten.toml`, it runs only on the non-`read` surface (§5,
    /// CLOUD-170).
    Command,
    /// A banned **command shape**: the mediated call `batten hook` is
    /// adjudicating matches `pattern` read as an effective program plus the
    /// adjacent words that must follow it.
    ///
    /// Distinct from [`RuleKind::Command`], which *runs* a declared command.
    /// This one runs nothing — it is a string match over a command line the
    /// host handed us, so it cannot spawn and stays on the read-safe surface.
    Shape,
    /// A **count that may only move one way** (CLOUD-55): the total occurrences
    /// of `pattern` across files matching `glob`, compared between a base rev
    /// and the working tree, must not move in the banned `direction`.
    ///
    /// The kind exists because the property worth gating on a test suite is not
    /// immutability — tests are edited every day, so a protected path would
    /// block writing them — but *direction of change*. That is the same shape
    /// `trust.rs` already encodes for config: which way is weakening is a
    /// property of the key.
    ///
    /// Counted in **aggregate per rule**, never per file: a test moved between
    /// two files matching the glob changes nothing, so renames and
    /// consolidations that preserve the suite are clean with no rename tracking.
    /// The price is that the finding names counts rather than locations, and
    /// `git diff` answers *where*.
    Ratchet,
    /// A mediated call that requires a **verification receipt** to be valid
    /// before it is allowed (CLOUD-312, over CLOUD-203's receipt store).
    ///
    /// Distinct from [`RuleKind::Shape`], which refuses a command outright:
    /// this one refuses a command *whose precondition has not been proved*, and
    /// the same command is allowed the moment the receipt exists. The predicate
    /// is [`crate::receipt::validity`] — already total and fail-closed — so this
    /// kind adds a trigger and a refusal, never a second opinion about what a
    /// valid receipt is.
    ///
    /// The verdicts are resolved at the hook's boundary and handed to the
    /// adjudicator as data, because adjudication is contractually pure. That is
    /// the same split the bypass hatch already uses.
    Receipt,
    /// A mediated call whose **exit status is discarded by the structure it sits
    /// in** (CLOUD-443).
    ///
    /// Distinct from [`RuleKind::Shape`] by what it reads, not by severity. A
    /// shape row matches a program and its adjacent words; this one is about what
    /// SURROUNDS the command — what its status is handed to (a pipe), what
    /// replaces it (a following `;` or `||` element), and whether it was detached
    /// (`nohup`, a trailing `&`). Those are properties of the operators between
    /// segments, which the parser used to discard, so no amount of word matching
    /// could express them.
    ///
    /// Every shape it denies **fails green** — exit 0 with plausible output —
    /// which is why noticing them repeatedly did not stop them. `&&` is
    /// deliberately not among them: it short-circuits, so a failure still
    /// propagates and there is no false green to refuse.
    ///
    /// The row carries the two tables the predicate is defined over: which
    /// programs are verdict-bearing (`verdict`) and which stages substitute
    /// output for status (`filters`). Both are the consumer's — one repository's
    /// build command is another's irrelevance — so the crate names neither.
    Pipeline,
    /// A **model-validated** rule (CLOUD-56): hand the row's `criteria` and the
    /// admitted classes of its matched files to the command in `[judge].run`,
    /// and read that command's exit code.
    ///
    /// The kind exists for the predicates no static shape can express — "this
    /// test asserts behaviour, not a tautology" — and it is the one kind whose
    /// outcome is **advisory-only and structurally unable to block** (house
    /// style §0.3; the 2026-08-07 evidence base measured model judges at AUROC
    /// ≤0.65 on false-success detection, so a judge verdict may inform and never
    /// gate).
    ///
    /// "Structurally" is literal, and it is why this variant looks unfinished
    /// next to the others: a judge outcome **never becomes a [`Finding`]**.
    /// `run_rule` cannot produce one — the row is `allow`, which that walker
    /// already skips — so [`any_blocking`] and `--fail-on-warning` have nothing
    /// to see. Blocking is not forbidden here, it is unrepresentable.
    ///
    /// Distinct from [`RuleKind::Command`], which also runs something and reads
    /// an exit code: that one is an *exit-code predicate* whose command is a
    /// gate, and its findings deny. This one's command consults a model, and its
    /// findings advise. The gate/judge line (CLOUD-93) is exactly this pair.
    Judge,
    /// A **credential in the tree** (CLOUD-59): run the pinned secret scanner
    /// over the matched paths and turn each match into a pointer.
    ///
    /// The kind exists because [`RuleKind::Forbid`] bans literals named in
    /// advance, and a credential is the banned shape nobody can enumerate — so a
    /// committed secret passes every other gate this engine has. Detection is
    /// adopted prior art; what this kind owns is **containment**, in
    /// [`crate::secrets`].
    ///
    /// Distinct from [`RuleKind::Command`], which could run the same binary and
    /// could not express this: a command rule's contract is the exit code alone,
    /// with both child streams nulled, so it yields one batch verdict per glob —
    /// no per-secret `path:line`, no per-secret identity, and nothing to key.
    /// Reading the scanner's output is precisely what makes this kind different,
    /// and precisely what makes it dangerous: the scanner prints the byte it
    /// matched. Every span is opaque from the parse boundary onward
    /// ([`crate::identity::SecretSpan`]), and [`Finding`] has no field one could
    /// occupy, so pointer-only output is structural rather than a property of
    /// the renderer.
    Secrets,
    /// Address a node in a structured document and compare it to a literal
    /// (CLOUD-772).
    ///
    /// The kind that turns a parsed document into policy. It reads a file the
    /// `glob` selects, parses it as the declared `format`, walks to `node`, and
    /// reports when the value there is not `pattern`. What it never does is name
    /// an artifact: `format` and `node` are the consumer's, so a rule over a
    /// workflow file and a rule over a package manifest are the same code
    /// (non-negotiable rule 1).
    ///
    /// Three-valued (CLOUD-757), which is the whole reason it exists. A file
    /// that does not parse is **could not look** and is reported, never silently
    /// clean — an extraction that returns nothing reading as agreement is the
    /// live failure mode of every hand-rolled reader this replaces.
    Document,
    /// A **registered policy module** evaluated over the resolved fact set
    /// (CLOUD-647, CLOUD-689): the module contributes denials, and decides
    /// nothing else.
    ///
    /// The kind exists because the rule table is a flat loop — no row consumes
    /// another's verdict — so a predicate over *relationships* between facts is
    /// not expressible as a row at all. The layer this engine is absorbing shows
    /// what that costs: 57 of 126 tasks compose over a sibling's exit code, a
    /// three-state channel that forces every consumer to re-derive the
    /// producer's structure.
    ///
    /// **Admitted to [`RuleScope::MediatedCall`], which is the whole point**, and
    /// admitted on [`Authority::Supplied`] rather than by exception. A
    /// [`RuleKind::Command`] row spawns a process that can read any file and
    /// reach the network; a module evaluated over `Facts` sees the fields the
    /// boundary resolved and acquires nothing. The fact set *is* the bound, which
    /// is why it had to exist before this kind could (CLOUD-763).
    ///
    /// **Deny-only, and that is structural.** Only the module's `deny` set is
    /// read; there is no spelling for an allow that overrides a TOML deny. That
    /// preserves §8's raise-only invariant *and* removes the allow/deny
    /// contradiction class by construction, leaving nothing for a consumer to
    /// get wrong in the direction that weakens a gate.
    ///
    /// The module is **registered**, never discovered: `module` names it in the
    /// one committed authority. §8 forbids the upward directory walk and the
    /// `conf.d` merge — that is, implicit discovery — and naming each module in
    /// the authority is the opposite of both. Globbing a policy directory would
    /// be the thing §8 refuses.
    Policy,
}

/// What a rule kind may reach beyond the inputs the boundary handed it
/// (CLOUD-763).
///
/// Three values rather than a boolean, because the boolean could not express the
/// case the fact model creates. `carries_ambient_authority` asked *does it start a
/// program?*, which is a proxy: what actually decides admission to the mediated
/// call is whether a kind can acquire anything its inputs did not already carry.
/// A kind that reaches the network without spawning would have passed the old
/// question and must fail the new one, which is exactly what makes the
/// replacement pin **strictly stronger** rather than a rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Authority {
    /// Reads only what the boundary supplied: the resolved facts, the envelope,
    /// the files the glob already selected, and fixed VCS queries whose only
    /// configured input is data. The fact set is the whole world it sees.
    Supplied,
    /// Reaches beyond its inputs without running a configured program — a
    /// network client, an unbounded walk, a warm process it did not start.
    ///
    /// **No kind carries this today**, and it is a variant rather than a comment
    /// for the reason the whole issue turns on: the retired predicate would have
    /// admitted such a kind to the mediated call, silently, because it does not
    /// spawn. Naming the value is what lets a test prove the new pin refuses it.
    Acquires,
    /// Runs a program a `batten.toml` named, which can do everything above and
    /// more: any file, any process, the network, with the calling user's
    /// authority.
    Spawns,
}

impl Authority {
    /// Every authority the model knows, so the partitions below are total.
    pub const ALL: &'static [Authority] =
        &[Authority::Supplied, Authority::Acquires, Authority::Spawns];

    /// The stable lowercase token used in machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Authority::Supplied => "supplied",
            Authority::Acquires => "acquires",
            Authority::Spawns => "spawns",
        }
    }

    /// Whether this authority reaches beyond the inputs it was handed.
    ///
    /// The one predicate `scopes` and `run_static` both read. Exhaustive with no
    /// wildcard arm, so a fourth value cannot default to "safe" — the direction
    /// this mistake is expensive in.
    #[must_use]
    pub const fn is_ambient(self) -> bool {
        match self {
            Authority::Supplied => false,
            Authority::Acquires | Authority::Spawns => true,
        }
    }
}

/// Whether a kind carrying `authority` may be adjudicated on the mediated call.
///
/// The admission predicate, as a free function over the authority rather than
/// over a [`RuleKind`], so a test can feed it [`Authority::Acquires`] — a value
/// no kind carries yet — and prove the pin refuses it (CLOUD-418: a gate never
/// shown to fail ships as coverage).
#[must_use]
pub const fn admissible_at_mediated_call(authority: Authority) -> bool {
    !authority.is_ambient()
}

impl RuleKind {
    /// Every kind the engine knows, so the partitions below are total.
    ///
    /// A new variant must be added here or [`tests::all_covers_every_kind`]
    /// fails — which is what keeps [`RuleKind::carries_ambient_authority`] from silently
    /// defaulting a spawning kind to "safe".
    pub const ALL: &'static [RuleKind] = &[
        RuleKind::Forbid,
        RuleKind::Command,
        RuleKind::Shape,
        RuleKind::Ratchet,
        RuleKind::Receipt,
        RuleKind::Pipeline,
        RuleKind::Judge,
        RuleKind::Secrets,
        RuleKind::Document,
        RuleKind::Policy,
    ];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleKind::Forbid => "forbid",
            RuleKind::Command => "command",
            RuleKind::Shape => "shape",
            RuleKind::Ratchet => "ratchet",
            RuleKind::Receipt => "receipt",
            RuleKind::Pipeline => "pipeline",
            RuleKind::Judge => "judge",
            RuleKind::Secrets => "secrets",
            RuleKind::Document => "document",
            RuleKind::Policy => "policy",
        }
    }

    /// What this kind may reach beyond the inputs the boundary handed it
    /// (CLOUD-763).
    ///
    /// # The axis is ambient authority, and it always was
    ///
    /// This predicate used to be spelled `carries_ambient_authority`, and its own comment
    /// conceded the name was wrong — *"this predicate is about user-supplied
    /// code, not about spawning at all."* Half right. The axis is neither
    /// spawning nor authorship: it is **ambient authority**. A `command` row is
    /// excluded from the mediated call because the process it starts can read
    /// any file, spawn anything and reach the network — unbounded — not because
    /// a consumer wrote the line that starts it.
    ///
    /// "Consumer-authored" was a serviceable proxy while nobody could describe
    /// what a module could see. [`crate::facts`] makes that describable: a pure
    /// evaluator over supplied facts has exactly the authority the boundary
    /// handed it, and the fact set **is** the whole world it can see. So the
    /// proxy retires and the real axis is stated.
    ///
    /// # Stated per kind, and the classification is what `scopes` rests on
    ///
    /// [`RuleKind::scopes`] pairs every kind carrying ambient authority with
    /// [`RuleScope::Tree`] alone, and `hook`'s `Policy::from_resolved` filters on
    /// scope — so this is the property that filter relies on.
    /// `tests::no_mediated_call_kind_carries_ambient_authority` pins the whole
    /// cross product, and it is **strictly stronger** than the spawn-only pin it
    /// replaces: [`Authority::Acquires`] passes "does it spawn?" and fails this.
    #[must_use]
    pub const fn authority(self) -> Authority {
        match self {
            // `Ratchet` reaches git plumbing, which is a *process* — and still
            // `Supplied`, because the invocations are fixed literals in this
            // crate and the only configured value crossing into them is a rev,
            // which is data. `receipt status` carries the same reading with its
            // own `rev-parse`: a read verb may run a fixed VCS query, and what it
            // must never reach is a command a config named. Reading it the other
            // way would make the kind enforce-only and cost it `check`, which is
            // the surface the gate is worth having on (CLOUD-55).
            //
            // `Receipt` reads a file and two git refs — same reading. `Pipeline`
            // reads the operators between a command's segments and nothing else.
            // `Forbid`, `Shape` and `Document` read only what the glob or the
            // envelope already selected.
            RuleKind::Forbid
            | RuleKind::Shape
            | RuleKind::Ratchet
            | RuleKind::Receipt
            | RuleKind::Pipeline
            | RuleKind::Document
            // The one kind that is consumer-authored code and STILL `Supplied`,
            // which is the distinction CLOUD-763 re-axed `scopes` to express. A
            // module is a pure function over the input document: it cannot open a
            // file, start a process or reach the network, and the feature set
            // that keeps that true is pinned in the workspace manifest. Authorship
            // was only ever a proxy for authority, and this kind separates them.
            | RuleKind::Policy => Authority::Supplied,
            // All three run a program a `batten.toml` named. That a judge's
            // consults a model, a command's decides a gate and a secrets rule's
            // scans for credentials makes no difference to the axis: each starts
            // a process with the ambient authority of the calling user.
            RuleKind::Command | RuleKind::Judge | RuleKind::Secrets => Authority::Spawns,
        }
    }

    /// Whether this kind may reach beyond its supplied inputs at all.
    ///
    /// The `scopes` predicate and `run_static`'s refusal both read this and
    /// nothing else, so "which kinds are excluded from the mediated call" and
    /// "which kinds `batten check` refuses" cannot drift apart.
    #[must_use]
    pub const fn carries_ambient_authority(self) -> bool {
        self.authority().is_ambient()
    }

    /// The columns this kind cannot load without.
    #[must_use]
    pub const fn requires(self) -> &'static [&'static str] {
        match self {
            // `pattern` is deliberately absent: `forbid` requires exactly one of
            // `pattern` or `regex`, and this list cannot express "one of"
            // (CLOUD-283). `validate` carries that check, which is also where
            // the both-columns case is refused.
            // `Secrets` shares the pair, and for a related reason: for both, the
            // `glob` is the gate before it is anything else — no match means no
            // file is read and, for the scanner, no process is spawned at all.
            // `severity` is required of every non-judge kind because it is what
            // reaches the exit contract. The secrets kind takes nothing further:
            // the issue's own constraint is that it permits no NEW column, so
            // the scanner's identity is a constant in the adapter rather than a
            // row every config repeats.
            RuleKind::Forbid | RuleKind::Secrets => &["glob", "severity"],
            // `check`, never `fix`: enforcement is always the check side (§9),
            // so the gate half is what a row cannot load without. A row
            // carrying only a `fix` declares a mutation with nothing deciding
            // when it is needed.
            RuleKind::Command => &["glob", "check", "severity"],
            // A shape row's `reason` is required, not optional: the deny it
            // produces reaches a model as the whole explanation, and a refusal
            // with nothing but an id is the un-actionable shape CLOUD-122 exists
            // to prevent.
            // `pattern` is NOT here since CLOUD-758, and — exactly as the
            // `receipt` note below says of the same move — its absence is a
            // CONDITIONAL requirement rather than a relaxation. A shape row is
            // keyed on a command line (`pattern`) or on the content a write
            // would land (`content`), and a write carries no command line, so
            // requiring the column unconditionally would make the content
            // predicate unusable. `validate_shape_columns` refuses a row
            // carrying neither, and one carrying both.
            //
            // IDENTICAL TO `Pipeline`'s LIST BY COINCIDENCE, NOT BY A SHARED
            // RULE, so the arms stay apart. Each arrived at `reason` +
            // `severity` by its own conditional-column move — this one
            // CLOUD-758's, `Pipeline`'s CLOUD-864's — and each can regain a
            // column without the other. Merging the patterns would put two
            // unrelated rationales on one arm and assert they move together.
            // `#[expect]` rather than `#[allow]` for the reason the spawn
            // census gives: the day the lists diverge, this goes red and is
            // deleted rather than lingering as a licence.
            #[expect(
                clippy::match_same_arms,
                reason = "the two lists are equal by coincidence; see the note above"
            )]
            RuleKind::Shape => &["reason", "severity"],
            RuleKind::Ratchet => &["glob", "pattern", "direction", "base", "severity"],
            // Same `reason` obligation as a shape row, for the same reason: the
            // deny reaches a model as the whole explanation. `checks` is
            // required because a receipt row naming none would gate its trigger
            // on nothing and allow every call — a rule that loads, matches, and
            // decides nothing.
            //
            // `pattern` is NOT here since CLOUD-444, and its absence is a
            // conditional requirement rather than a relaxation: a
            // command-triggered row still cannot load without one, refused in
            // [`Rule::validate`] where the trigger is in scope. A write-triggered
            // row has no command line to match, so requiring the column
            // unconditionally would make the new trigger unusable.
            RuleKind::Receipt => &["checks", "reason", "severity"],
            // `verdict` and `filters` are NOT here since CLOUD-864, and their
            // absence is a conditional requirement rather than a relaxation —
            // the same move `Receipt`'s `pattern` makes above, for the same
            // reason. This kind now carries two predicates: the discard family
            // (`verdict` + `filters`) and the substitution family
            // (`substitutes`). Requiring the discard pair unconditionally would
            // oblige a substitution row to declare two tables it never reads,
            // and a table nobody reads is the next thing to drift.
            //
            // A row must still declare ONE of the two whole — enforced in
            // [`Rule::validate_pipeline_tables`], where the sibling columns are
            // in scope. A pipeline row declaring neither loads, matches, and
            // decides nothing, which is the present-and-inert gate this file is
            // written against. `reason` carries the shared remedy, since the
            // engine renders the per-shape cause itself.
            RuleKind::Pipeline => &["reason", "severity"],
            // `criteria` is what the model is asked, and a judge row without one
            // sends a payload with no question attached. `no_fix_reason` is
            // required rather than merely permitted because a judge finding
            // reaches the store and CLOUD-81's ingest refuses one nothing can
            // close — and a judge finding has no mechanical `fix` by
            // construction, so the authored reason is the only remediation it
            // can carry. Requiring it here is what keeps that refusal
            // unreachable from a config that parses.
            RuleKind::Judge => &["glob", "criteria", "no_fix_reason"],
            // All four, and none of them has a defensible default. `format` is
            // stated rather than inferred from the path's extension, because an
            // extension is a naming convention and this is the one column that
            // decides which parser reads the bytes — a `.json` file that is
            // really JSON5 would parse-fail and report "could not look" forever,
            // blaming the file for the guess. `node` is what the rule addresses;
            // a row without one selects a document and asks nothing of it.
            // `pattern` is the value the node must hold, so a row without one
            // loads, matches, and decides nothing.
            // `pattern` is deliberately absent, the shape `forbid` already uses
            // (CLOUD-283): a document row carries exactly one of `pattern` (a
            // literal) or `reads` (another rule's derived value), and a flat
            // column list cannot express "one of". `validate` carries that.
            RuleKind::Document => &["glob", "format", "node", "severity"],
            // No `glob`: a policy row is not selected by the files it reads, it
            // is handed the fact set.
            //
            // `module` is NOT in the required list since CLOUD-833, and its
            // absence here is load-bearing rather than a relaxation: a row names
            // exactly one of `module` (a file) or `bundle` (a folder), and a
            // flat column list cannot express "one of". `validate` carries that,
            // the same split `Document`'s `pattern`/`reads` pair already uses —
            // and a row naming NEITHER is still refused there, so nothing got
            // looser.
            RuleKind::Policy => &["severity"],
        }
    }

    /// Every column this kind accepts — a superset of [`RuleKind::requires`].
    ///
    /// Anything outside this set is a usage error rather than an ignored key: a
    /// `glob` on a shape rule selects files a shape rule never reads, so
    /// accepting it would let a reviewer believe a rule is scoped when it is not.
    #[must_use]
    pub const fn permits(self) -> &'static [&'static str] {
        match self {
            // `verbatim` narrows a hashed span, so only the kind that hashes one
            // accepts it: a `verbatim` on a command rule would name a
            // normalization that applies to nothing, and reading as configured.
            RuleKind::Forbid => &[
                "glob",
                "pattern",
                "regex",
                "exclude",
                "verbatim",
                "identity_key",
                "no_fix_reason",
                "severity",
            ],
            RuleKind::Command => &[
                "glob",
                "check",
                "fix",
                "identity_key",
                "no_fix_reason",
                "severity",
            ],
            // Three lists are named rather than inlined, each for the length
            // reason `PIPELINE_PERMITS`' doc gives; the per-kind rationale that
            // used to sit here travels with each constant.
            RuleKind::Shape => SHAPE_PERMITS,
            // No `identity_key` or `verbatim`: a ratchet hashes no span — its
            // finding is a pair of integers about a whole rule — so either
            // column would name a normalization that applies to nothing.
            RuleKind::Ratchet => &[
                "glob",
                "pattern",
                "direction",
                "base",
                // Optional, and optional is the whole of its compatibility story
                // (CLOUD-807): a ratchet without it behaves exactly as it did
                // before the column existed. Listed here rather than in
                // `requires` for the reason `require_via` gives — a modifier
                // that narrows by DEFAULT would silently change every row that
                // never asked for it.
                "retires_with",
                // Optional for the same reason, one level in (CLOUD-908): a
                // `retires_with` row without it behaves exactly as it did before
                // this column existed. What it adds is not a second admission but
                // an OBLIGATION inside the first one, which is why it is listed
                // here and refused at load without `retires_with` to refine.
                "conserves",
                // Optional for the same reason, on the other side of the count
                // (CLOUD-929): a ratchet without it behaves exactly as it did
                // before the column existed. It is `retires_with`'s sibling
                // rather than the same key, because the two read DIFFERENT
                // trees — see the column's own doc for why that asymmetry is
                // forced rather than chosen.
                "admits_with",
                "reason",
                "policy_url",
                "no_fix_reason",
                "severity",
            ],
            RuleKind::Receipt => RECEIPT_PERMITS,
            RuleKind::Pipeline => PIPELINE_PERMITS,
            // No `fix`: a judge finding is advisory, and a mutating repair
            // attached to a model's opinion is the shortest path from "may
            // inform" to "acted on the repository". No `severity` either — that
            // column is the exit contract, and the axis a judge feeds is `tier`.
            RuleKind::Judge => &[
                "glob",
                "criteria",
                "tier",
                "identity_key",
                "reason",
                "policy_url",
                "no_fix_reason",
            ],
            // `identity_key` is permitted and `verbatim` is not: a secret span
            // hashes, so an override has something to split, but the
            // normalization is not the author's to choose — a secret IS literal
            // content, so `secret_code_fingerprint` forces `Verbatim` and a
            // column offering the other value would name a choice that does not
            // exist.
            RuleKind::Secrets => &[
                "glob",
                "severity",
                "identity_key",
                "reason",
                "policy_url",
                "no_fix_reason",
            ],
            // No `verbatim`: the span a document finding points at is a node,
            // not a line of text, so whitespace normalization names nothing here.
            RuleKind::Document => &[
                "glob",
                "format",
                "node",
                "pattern",
                "derives",
                "reads",
                "severity",
                "identity_key",
                "reason",
                "policy_url",
                "no_fix_reason",
            ],
            // No `pattern` and no `regex`: the predicate is the module, and a
            // second shape column beside it would be a rule with two authorities
            // over one decision.
            RuleKind::Policy => &[
                "module",
                "bundle",
                "preset",
                "documents",
                "sources",
                "lines",
                "line_sources",
                // CLOUD-1059. `delta_sources` is a declared READ and so escapes
                // this census with the git family, but the rev it reads against
                // is `base` — which is in the census, because a ratchet's
                // direction is judged against it. So the column is permitted
                // here rather than duplicated under a second name: one spelling
                // of "the rev this branch is compared to" is the point, and a
                // `delta_base` beside it would be the second authority
                // CLOUD-1050 is about, one layer down. Optional, and optional is
                // its whole compatibility story — a policy row without it
                // behaves exactly as it did before the column reached this kind.
                "base",
                "invocations",
                "invocation_sources",
                "uses",
                "use_sources",
                "severity",
                "predicate_severity",
                "identity_key",
                "reason",
                "policy_url",
                // Permitted because this kind takes BOTH scopes: a
                // `mediated-call` policy row denies through the same channel a
                // `shape` row does, so it owes the same findable hatch. On a
                // `tree`-scoped row it names nothing and costs nothing —
                // `check` is read-only and has no mediation to suppress, which
                // is the same reason `deny_text` is `hook`'s and not
                // `Refusal`'s.
                "bypass_env",
                "no_fix_reason",
            ],
        }
    }

    /// The scopes this kind may declare.
    ///
    /// The pairing is what makes the scope key a real router rather than a label:
    /// a file kind scoped to the mediated call, or a shape kind scoped to the
    /// tree, would be a rule that no surface ever evaluates — present, inert, and
    /// reading as covered.
    #[must_use]
    pub const fn scopes(self) -> &'static [RuleScope] {
        match self {
            // `Document` is `Tree` alone, and that pairing is `facts::DOCUMENT`
            // read back: the fact's narrowest surface is `facts::Surface::Check`,
            // so a row scoped to the mediated call would be a rule no surface
            // could ever evaluate.
            RuleKind::Forbid
            | RuleKind::Command
            | RuleKind::Ratchet
            | RuleKind::Judge
            | RuleKind::Secrets
            | RuleKind::Document => &[RuleScope::Tree],
            RuleKind::Shape | RuleKind::Receipt | RuleKind::Pipeline => &[RuleScope::MediatedCall],
            // `Policy` is the only kind that takes BOTH, and CLOUD-833 is why.
            //
            // It arrived `MediatedCall`-alone, which was right for what
            // CLOUD-689 built and wrong for what the retirement campaign needs:
            // 79 of 133 `mise-tasks` programs are gate-described, and nearly
            // every one is a predicate over files and repo state with no
            // mediated call in sight. A kind confined to the hook gave that
            // campaign nowhere to migrate to.
            //
            // **Admitting it to the read-only surface makes `check` more capable
            // without making it less honest, and that is the argument rather
            // than a convenience.** `run_static` refuses any kind that
            // `carries_ambient_authority`, because a `command` row spawns a
            // process with the calling user's authority. A policy module is
            // `Authority::Supplied` — a pure function over an input document
            // that cannot open a file, start a process or reach the network, a
            // property CLOUD-831 now gates rather than asserts. So a tree-scoped
            // policy row is admissible exactly where a `command` row is not.
            //
            // The pairing is still `fact_class` read back, as every other row
            // here is — the class is now a function of kind AND scope, and the
            // `Tree` half is `Read` x `Check`.
            RuleKind::Policy => &[RuleScope::MediatedCall, RuleScope::Tree],
        }
    }

    /// What evaluating this kind costs, and the narrowest surface it may be
    /// evaluated on (CLOUD-757's two axes, CLOUD-773's composition input).
    ///
    /// Stated per kind rather than inferred, for [`RuleKind::carries_ambient_authority`]'s
    /// reason: a kind that lands unclassified would compose as whatever the
    /// default happened to be, and the cheap default is the one direction the
    /// mistake is expensive in. This is the value [`Rule::derives`] publishes and
    /// [`Rule::reads`] is judged against — a reference that would make the
    /// reading rule more expensive or narrower than it declares is refused at
    /// load rather than answering from a fact that was never resolvable there.
    #[must_use]
    pub const fn fact_class(self, scope: RuleScope) -> crate::facts::Class {
        use crate::facts::{Class, Cost, Surface};
        match self {
            // Reads matched files, on the tree surface. `Ratchet` adds fixed git
            // plumbing, which is the same bounded read.
            RuleKind::Forbid | RuleKind::Ratchet | RuleKind::Document => {
                Class::new(Cost::Read, Surface::Check)
            }
            // All three run a program a config named, which is `Cost::Effect` by
            // definition — and `scopes` already pairs each with `Tree` alone.
            RuleKind::Command | RuleKind::Secrets => Class::new(Cost::Effect, Surface::Check),
            // A judge consults a model: it spawns, and its verdict is advisory,
            // so it may not be resolved anywhere a gate reads it.
            RuleKind::Judge => Class::new(Cost::Effect, Surface::VerifyOnly),
            // Adjudicated per mediated call over data the boundary already
            // carries: `Pipeline` reads only the envelope, which is `Cost::Free`
            // — already in hand.
            RuleKind::Pipeline => Class::new(Cost::Free, Surface::Hook),
            // `Shape` moved from `Free` to `Read` with CLOUD-758, for the reason
            // CLOUD-834 records one arm down: a `content` row decides over what
            // the write would LAND, and the edit arm of `hook::prospective_facts`
            // reads the target off disk to compute it. `facts::PROSPECTIVE` is
            // `Cost::Read`, and a row deciding over a fact is a row reading it.
            // `Receipt` pays a bounded git read for the same class of reason.
            RuleKind::Shape | RuleKind::Receipt => Class::new(Cost::Read, Surface::Hook),
            // THE ONE KIND WHOSE CLASS DEPENDS ON ITS SCOPE (CLOUD-833), which
            // is why this function takes one at all.
            //
            // On the mediated call it is `Read` x `Hook`, and the COST moved
            // there in CLOUD-834. It was `Free` for one reason — the input
            // document was four envelope fields, all `Cost::Free`, so evaluating
            // a bundle acquired nothing. (Measured against the pinned toolchain:
            // ~39us per call at one predicate, ~2.2ms at seventy-nine, against
            // the 100ms ceiling; the full series is on
            // [`crate::policy::Bundle`], and that CPU figure is unchanged.)
            //
            // `hook::call_document` now projects the resolved fact set, and four
            // of the five facts it carries — `Receipts`, `Keys`, `Stop`,
            // `Waived` — are `Cost::Read` in `facts.rs`'s own table. A row
            // deciding over them is a row reading them, so `Class::meet` gives
            // `Read`, and this must say so.
            //
            // **It is the composition claim that moves, not the invoice.** Those
            // facts are resolved at the boundary for the typed rule table
            // whether or not any module exists, so nothing here made the
            // mediated call more expensive — measured, `perf-pair` unmoved. What
            // would be false is a rule composing over a policy row as though the
            // read were free, which is precisely the widening
            // `validate_composition` exists to refuse (CLOUD-757). The cheap
            // default is the one direction the mistake is expensive in.
            //
            // On the tree it is `Read` x `Check`: the bundle's declared
            // documents have to come off disk before there is an input document
            // to decide over, which is exactly what `Forbid` and `Document` pay
            // and exactly what `Surface::Check` is for.
            RuleKind::Policy => match scope {
                RuleScope::MediatedCall => Class::new(Cost::Read, Surface::Hook),
                RuleScope::Tree => Class::new(Cost::Read, Surface::Check),
            },
        }
    }
}

/// Which file domain a rule evaluates over — *where a rule looks*, never what a
/// match does (CLOUD-61).
///
/// Scope and severity are two independent keys on a [`Rule`], deliberately: the
/// question "which files does this gate watch" and the question "what happens
/// when it matches" ([`RuleSeverity`]) are different axes, and conflating them
/// is the config bug this type makes inexpressible. Neither vocabulary
/// deserializes as the other, so a severity token in the `scope` key (or the
/// reverse) is a usage error (exit `1`), never a silent reinterpretation.
///
/// Marked `#[non_exhaustive]` like [`RuleKind`]: the git change-set / protected
/// / unlanded domains (CLOUD-36, CLOUD-37) slot in as new variants without a
/// breaking change. The default is pinned as data —
/// [`tests::scope_default_is_pinned`] asserts it — so it is an explicit,
/// per-field default rather than an implicit fallback buried in code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleScope {
    /// The whole working tree: every file the walk yields. The pinned default.
    #[default]
    Tree,
    /// The single command `batten hook` is adjudicating — not a file domain at
    /// all, which is why a rule declaring it reads no `glob`.
    ///
    /// Spelled `mediated_call` rather than `command` on purpose: `command` is
    /// already a [`RuleKind`] token meaning "run this", and one word meaning two
    /// unrelated things across two keys is the cross-vocabulary confusion
    /// [`tests::severity_and_scope_vocabularies_do_not_cross`] exists to prevent.
    MediatedCall,
}

impl RuleScope {
    /// Every scope the engine knows, so vocabulary tests stay total.
    pub const ALL: &'static [RuleScope] = &[RuleScope::Tree, RuleScope::MediatedCall];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleScope::Tree => "tree",
            RuleScope::MediatedCall => "mediated_call",
        }
    }
}

/// The published schema for [`Rule::preset`]: a string constrained to the
/// **embedded** preset names (CLOUD-836 §4).
///
/// Generated from [`crate::policy::preset_names`] rather than written out, so
/// the schema and the binary cannot disagree about what may be enabled. A
/// hand-maintained enum here would be a second authority over the same set, and
/// the failure mode is the quiet one: an editor accepting a name the loader then
/// refuses, or refusing one it accepts.
fn preset_name_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let _ = generator;
    let names: Vec<serde_json::Value> = crate::policy::preset_names()
        .into_iter()
        .map(|name| serde_json::Value::String(name.to_owned()))
        .collect();
    schemars::json_schema!({
        "type": ["string", "null"],
        "enum": names,
    })
}

/// One declarative rule from `batten.toml`'s `[[rule]]` array.
///
/// `deny_unknown_fields` keeps the surface narrow (§8): a mistyped key is a hard
/// error, never a silently ignored setting that disables a gate. The struct is
/// flat rather than an enum with `#[serde(flatten)]` precisely so this guarantee
/// holds — `flatten` silently defeats `deny_unknown_fields`.
/// `severity` is required by every kind but `judge`, which is refused it
/// (CLOUD-445). The field is an `Option` so a judge row can omit it, so the
/// derived `required` list cannot carry it — and a schema that merely dropped it
/// would stop flagging the missing key on the four kinds that must have one,
/// moving a check out of the editor with nothing taking its place.
///
/// This conditional puts it back, stated once here and derived into both
/// published schemas. It mirrors [`RuleKind::requires`] and
/// [`RuleKind::permits`]; `tests::the_schema_conditional_matches_the_column_census`
/// is what keeps the two from drifting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("allOf" = serde_json::json!([{
    "if": { "properties": { "kind": { "const": "judge" } }, "required": ["kind"] },
    "then": { "not": { "required": ["severity"] } },
    "else": { "required": ["severity"] }
}])))]
pub struct Rule {
    /// A stable identifier for the rule, surfaced in findings so a violation
    /// points back at the policy that produced it.
    pub id: String,
    /// Which predicate to apply to the matched files.
    pub kind: RuleKind,
    /// The glob selecting which files the rule inspects, matched against
    /// repo-relative paths (`/`-separated). `**` matches any run of path
    /// segments, `*` and `?` match within a single segment.
    ///
    /// Optional at the type level and required per-kind: a file kind cannot load
    /// without it, and [`RuleKind::Shape`] — which inspects no files — rejects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
    /// What a match does: `deny` fails the run, `warn` reports without failing
    /// (until `--fail-on-warning` promotes it, CLOUD-49), `allow` switches the
    /// rule off (cargo-deny's model, CLOUD-61).
    ///
    /// **Required for every kind but one**, and required *per kind* rather than
    /// by the type (CLOUD-445). Every committed rule states what a match does
    /// explicitly, with no implicit fallback — omitting the key is a usage error
    /// (exit `1`), never a silently assumed level.
    ///
    /// The exception is [`RuleKind::Judge`], which is **refused** the column: a
    /// judge verdict is advisory and must not reach the exit contract by any
    /// path, so the axis it declares instead is [`Rule::tier`]. Both halves come
    /// free from the ordinary column census — `severity` is in
    /// [`RuleKind::requires`] for the other four kinds and absent from
    /// [`RuleKind::permits`] for this one — which is why this is an `Option`
    /// rather than a required field with a loader-side exception. A type that
    /// demanded the key would make a valid judge config undeserializable, and
    /// the derived JSON Schema would flag the one row that must not carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<RuleSeverity>,
    /// Which file domain the rule evaluates over. Independent of `severity` —
    /// scope says *where* the rule looks, severity says *what a match does* —
    /// and neither key's vocabulary parses as the other's. Defaults to
    /// [`RuleScope::Tree`], the pinned per-field default.
    #[serde(default)]
    pub scope: RuleScope,
    /// The literal shape this rule bans — one meaning, two domains.
    ///
    /// For [`RuleKind::Forbid`] it is a substring banned from matched *files*.
    /// For [`RuleKind::Shape`] it is a banned *command line*: the first word is
    /// the effective program (matched after wrapper look-through) and the rest
    /// are the adjacent non-flag words that must follow it, so
    /// `pattern = "gh pr merge"` reads exactly as a reviewer would say it aloud.
    /// Required by both kinds, rejected by [`RuleKind::Command`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The banned shape as a regular expression — [`RuleKind::Forbid`]'s
    /// **alternative** to `pattern`, never an addition to it (CLOUD-283).
    ///
    /// A row carries exactly one of the two, and one carrying both is a load
    /// error rather than a precedence rule nobody can read. `pattern` stays the
    /// common case because a literal is the readable one (§9); this is the
    /// escape for a predicate that genuinely is a *shape* — a flag cluster
    /// judged by its letters, where `-qxF` must count as `-q` and an enumeration
    /// of spellings rots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// A regex that **un**-matches: a matched line carrying it is not a finding.
    ///
    /// [`RuleKind::Forbid`] only, and regex-only with no literal twin — an
    /// exclusion is inherently shape-based, and the measured one (a whole-line
    /// comment, `^[[:space:]]*#`) cannot be written as a literal at all.
    ///
    /// Comment-awareness lives here, in the consumer's config, rather than as a
    /// `skip_comments` flag in the engine: per-language comment syntax inside
    /// `crates/batten` would break non-negotiable rule 1, and it would also be
    /// wrong — `no-conflict-markers` must still fire inside a comment. What a
    /// comment looks like is a property of a repository, not of Batten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// A regex over the content a write would LAND, for a
    /// [`RuleKind::Shape`] row on the mediated path (CLOUD-758).
    ///
    /// **The first content-keyed predicate on this surface.** Every write-shaped
    /// gate before it was path-keyed — it could see which file was being touched
    /// and not what would end up in it, which is CLOUD-736's reported symptom:
    /// `git rm` on a workflow refused and a `Write` of one permitted.
    ///
    /// Regex-only with no literal twin, for [`Rule::exclude`]'s reason: a
    /// predicate over file content is inherently shape-based, and an enumeration
    /// of spellings rots.
    ///
    /// **Rule 4 is the load-bearing clause.** A row here DECIDES over the
    /// content and the refusal carries this rule's id and the path — never a
    /// matched byte. The content reaches the typed predicate and stops: it is
    /// projected into the policy input as a shape and a count, so no free-form
    /// consumer message can echo it.
    ///
    /// **The predicate runs over the whole prospective content**, so a bare `^`
    /// anchors to the start of the FILE rather than of a line. A per-line
    /// predicate wants `(?m)`, and the difference is not academic: without it a
    /// row catches a marker a write puts on the first byte and misses the same
    /// marker three lines in.
    ///
    /// A tool whose shape carries no content — a shell command, an MCP call —
    /// yields [`crate::facts::Look::CouldNotLook`], and a row here does not fire
    /// on it. That is *not* the same as matching an empty file, and collapsing
    /// the two would make the row fire on every call as though it had looked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// The tool a `mediated_call` row is **about** — matched exactly, or as a
    /// `__`-delimited suffix (CLOUD-924).
    ///
    /// **The third way to key a mediated row**, beside [`Rule::pattern`] (a
    /// command line) and [`Rule::content`] (what a write would land), and the
    /// only one a *structured* call can satisfy. `adjudicate` returns `Allow`
    /// the moment `envelope.command` is empty, and an MCP call, a `Read` and a
    /// `Task` spawn all carry an empty command — so before this column the two
    /// connector guards had nothing to retire onto, which is CLOUD-312's rows 4
    /// and 5. It reads [`crate::hook::Envelope::raw_tool`], the host's own word,
    /// and never the normalized [`crate::hook::Event`] (CLOUD-779's split).
    ///
    /// # Why a suffix, and why not a bare one
    ///
    /// **The suffix half is not a convenience.** A host mints the prefix of an
    /// MCP tool name and rotates it: CLOUD-665 and CLOUD-684 are the same
    /// measured failure twice, a rule naming a server label the host never
    /// registers under, matching nothing, silently. A consumer that already
    /// keyed its own hook matchers on a trailing pattern did so for exactly that
    /// reason. An exact-only selector here would rebuild the defect those two
    /// rows closed.
    ///
    /// **A bare suffix over-matches, so the delimiter is load-bearing.**
    /// `tool = "Edit"` would select `NotebookEdit`, and `tool = "Read"` any tool
    /// whose name happens to end in those bytes — a row selecting a neighbouring
    /// tool nobody named is the widening direction a policy engine may never
    /// drift in. So a match is the whole name, or the whole final `__`-delimited
    /// segment of it, which is `board-payloads`' own rule (`endswith("__get_issue")`)
    /// and carries its reasoning: MCP names are `mcp__<server>__<tool>`, and the
    /// tool is the last segment. `save_issue` therefore selects
    /// `mcp__Linear__save_issue` and `mcp__cc451d34-…__save_issue` alike, and
    /// `Edit` selects `Edit` alone.
    ///
    /// Permitted on [`RuleKind::Shape`] and [`RuleKind::Receipt`] — the kinds a
    /// row can key on a tool with no command in hand. **Not** on
    /// [`RuleKind::Pipeline`], whose predicate is the operators *between* a
    /// command's segments: a structured call has none, so the column would load,
    /// match nothing, and read as coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Narrow a `mediated_call` row to a call whose named projection is
    /// **absent** (CLOUD-987).
    ///
    /// A MODIFIER, not a selector: the row still selects on its own terms —
    /// `tool` for a structured call, `pattern` for a shell one — and this decides
    /// whether that selection refuses. The same shape [`Rule::requires_key`] and
    /// [`Rule::require_via`] already carry, and it is listed in `permits` rather
    /// than `requires` for the reason `require_via` gives: a modifier that
    /// narrowed by DEFAULT would silently change every row that never asked.
    ///
    /// **It exists because the absence is the predicate.** CLOUD-312's row 1
    /// gates *creating* a tracker row and must not gate *editing* one, and the
    /// two differ only in whether the call named an id. Its own header:
    /// *"Denying an update would demand a search before every edit to an issue,
    /// which is absurd and would get the guard switched off within a day."* A row
    /// that could not say "only when this is absent" would be that guard.
    ///
    /// Absent means the projection read `None` — which for
    /// [`crate::hook::Field`] collapses missing, null, empty and
    /// wrong-typed, exactly as every other reader of that allowlist sees it. One
    /// definition of absence, in the decoder, rather than a second one here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_absent: Option<crate::hook::Field>,
    /// Which projection supplies the subject for a [`ReceiptKey::Named`] receipt
    /// (CLOUD-987).
    ///
    /// Required by that key and refused without it: a `named` receipt with no
    /// projection has no subject to file under, and a receipt keyed on nothing
    /// would read the same file for every call — which is
    /// [`ReceiptKey::Branch`] wearing a different name, and the exact collapse
    /// that variant's doc refuses.
    ///
    /// A [`crate::hook::Field`] rather than a free-form key, for the reason the
    /// allowlist exists: the subject of a receipt is about to become a path
    /// component under `$GIT_DIR`, so which values can reach it must be a closed
    /// set somebody enumerated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_from: Option<crate::hook::Field>,
    /// Narrow [`Rule::when_present`] from *the key is there* to *the key holds
    /// THIS value* (CLOUD-312 row 3).
    ///
    /// **Presence was not enough, and row 3 is the measured case.** That guard
    /// gates one transition — a move to In Review — and its header prices the
    /// alternative in the same terms row 1's does: gating every column "would
    /// demand a graph-check before every edit, which is how a guard gets switched
    /// off within a day (CLOUD-199)." A row that could only ask whether the call
    /// named a state would fire on every edit that named any, so the guard stayed
    /// bash on a column boundary rather than on a missing projection.
    ///
    /// **The comparison is normalised, and the normalisation is generic rather
    /// than a consumer's.** Case is folded and spaces, underscores and hyphens are
    /// dropped from both sides, because a tracker's state parameter accepts a
    /// type, a name or an id, so a column's three spellings are one move. What is normalised is the SHAPE of a comparison; which value matters
    /// is the consumer's and lives in their `batten.toml` (non-negotiable rule 1).
    ///
    /// It qualifies `when_present` rather than standing alone: a value with no
    /// projection names nothing to read it out of, and that is a load error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_value: Option<String>,
    /// The shape a value must have to be a receipt subject at all (CLOUD-312
    /// row 2).
    ///
    /// **A projection can legitimately carry a value that names no subject, and
    /// reading one as a missing receipt is a false positive rather than a
    /// finding.** Row 2 is the measured case: the tracker's `id` parameter takes
    /// an issue key OR a UUID, the receipt namespace is keyed by key, and
    /// resolving a UUID needs a credential no hook has. The retiring guard calls
    /// that a genuine cannot-look and ALLOWS, in its own words because denying
    /// "would refuse a legitimate update over a spelling the agent is entitled to
    /// use, which is the false-positive rate that gets a guard bypassed and then
    /// enforces nothing."
    ///
    /// Without this the engine would file the UUID as a subject, find no file and
    /// deny — strictly worse than the bash it replaced, on the call the bash was
    /// careful about.
    ///
    /// So a value the shape does not match resolves the subject to **absent**,
    /// which [`crate::receipt::verdicts`] already takes to could-not-look and
    /// therefore to allow. It narrows what counts as a subject; it never denies.
    ///
    /// The expression is the CONSUMER's, because what a tracker's identifiers look
    /// like is a consumer fact (non-negotiable rule 1) — the core knows only that
    /// a subject may be shape-constrained.
    ///
    /// Compiled at load by [`Rule::validate_receipt_columns`], so a bad expression
    /// is a config error rather than a per-call surprise. That sentence was here
    /// before the check was, which is the defect review caught on #680: an
    /// unparseable expression was discarded per call and the row it qualified went
    /// quietly dead. The direction matters — the failure ALLOWED — and a comment
    /// asserting an invariant nothing enforces is what stops the next reader
    /// looking for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_shape: Option<String>,
    /// How old a receipt for this row may be, in seconds (CLOUD-988).
    ///
    /// **Existence was the whole verdict until this column, and for CLOUD-312's
    /// row 2 existence is the wrong question.** `issue-read-guard`'s predicate is
    /// CLOUD-508's bound — not *which* row was read but *how recently* — and a
    /// receipt that merely exists answers a read of unbounded age, which is the
    /// defect that issue names. So the row declares the bound and the engine
    /// compares.
    ///
    /// **THE CLOCK IS THE BOUNDARY'S, NEVER `adjudicate`'s.** The comparison
    /// happens where the receipt is already being read — [`crate::receipt`],
    /// called from the boundary — and reaches the decision as an ordinary
    /// [`crate::receipt::Validity`], exactly as staleness does. That is the
    /// waiver table's precedent: a waiver lapses on a date, and `today()` is
    /// handed in rather than taken inside, pinned by
    /// `adjudicate_reads_no_clock_even_now_that_a_waiver_can_lapse`. This column
    /// buys a fourth `Validity` and no clock in the core.
    ///
    /// Seconds rather than a duration string, because the output contract is
    /// byte-stable and a parsed duration is a second spelling of one number.
    /// Zero is refused: a receipt that is expired the instant it is written
    /// refuses every call and reads as a bound from the file.
    ///
    /// Absent means what it always meant — existence is the verdict — so no
    /// committed row changes meaning by this column arriving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
    /// Narrow a `mediated_call` row to a call whose named projection is
    /// **present** (CLOUD-987).
    ///
    /// [`Rule::when_absent`]'s mirror, and the pair is what makes CLOUD-312's
    /// rows 1 and 3 different rules rather than one with a flag: row 1 gates the
    /// call that named NO id, row 3 gates the call that DID name a state. Same
    /// modifier shape, opposite polarity, and neither is the default.
    ///
    /// **It exists because "moved" is a fact about the arguments.**
    /// `board-move-guard` fires only when a call moves a row between columns, and
    /// a call that merely edits one names no `state`. Without this the row would
    /// gate every edit — the same over-fire `when_absent` prevents one key over,
    /// and the reason both directions had to land together.
    ///
    /// Present means the projection read `Some` — one definition of presence, in
    /// the decoder, shared with `when_absent` so the two cannot disagree about
    /// what `state: ""` means.
    ///
    /// A row may carry both, over different projections: row 3 wants *a state was
    /// named* and, in principle, *an id was named*. Carrying both over the SAME
    /// projection is refused at load, because it can never fire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_present: Option<crate::hook::Field>,
    /// The envelope projection a [`Rule::max`] ceiling measures (CLOUD-925).
    ///
    /// A [`crate::hook::Field`], reusing the existing named allowlist rather than
    /// minting a second vocabulary for the same thing — and inheriting its safety
    /// argument, which is what makes this admissible at all: the allowlist can
    /// never name `Envelope::input` wholesale, so a ceiling can only ever be
    /// pointed at a projection somebody deliberately exposed.
    ///
    /// Required with `max` and `counts`, refused without them: a projection named
    /// with no cap measures something and decides nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measures: Option<crate::hook::Field>,
    /// What the [`Rule::max`] ceiling counts over [`Rule::measures`] (CLOUD-925).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<CeilingUnit>,
    /// The per-CALL ceiling: the largest measurement that still passes
    /// (CLOUD-925).
    ///
    /// **A ceiling whose subject is one call, which `[budget.<name>]` structurally
    /// cannot express** — that table is a file set, `files` globs plus
    /// `max_tokens`, evaluated over the tree by `policy budget`. So the bound
    /// `fanout-guard` carries (count the prompt, count the reading manifest,
    /// refuse past a cap) had no spelling as a row, and CLOUD-312's row 6 read
    /// "config" with no mechanism behind it.
    ///
    /// **The boundary is `<=`: exactly at the cap passes.** Inherited from
    /// [`crate::budget::Report::over_budget`] rather than decided again, because
    /// CLOUD-925 §1 requires one authority for what a ceiling *is* — a second
    /// comparison semantics for the same word is how the two would drift, and
    /// which side of the boundary is inclusive is precisely the kind of detail
    /// that drifts silently.
    ///
    /// **A modifier, not a keying column.** The row still selects on its own
    /// terms — `tool` for a structured call (CLOUD-924), `pattern` for a shell
    /// one — and this decides whether that selection refuses. Same shape
    /// [`Rule::requires_key`] already carries, and for the same reason: the
    /// selection half is unchanged.
    ///
    /// Rule 4 holds structurally: a breach reports the measurement, the cap and
    /// the row id. Never a byte of what was measured — which is the argument
    /// [`crate::hook::Field::Prompt`] already carries for counting bytes it may
    /// not echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// How a reference in the measured projection resolves to a repository path,
    /// for a [`CeilingUnit::TrackedArtifacts`] ceiling (CLOUD-925).
    ///
    /// **The consumer's vocabulary, and non-negotiable rule 1 is why it is a
    /// column.** A repository that writes `mem:core` in a prompt to mean one of
    /// its own files knows that mapping; `crates/batten` must not. So the engine
    /// knows only the RELATIONSHIP — a token is rewritten, and the result is
    /// counted if the tree tracks it — and the shorthand itself is config.
    ///
    /// Each entry is a regular expression and a replacement, applied to a
    /// candidate token before the tracked-set lookup. A token no entry matches is
    /// looked up as written, so a plain path needs no rewrite at all and the
    /// column stays absent for every consumer that uses none.
    ///
    /// Compiled at load like `regex`, `exclude` and `content`: left to
    /// adjudication an unparseable expression is skipped on every call, which is
    /// a ceiling that reads as configured and counts less than it should — the
    /// permissive direction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolves: Vec<Rewrite>,
    /// An extra literal that must appear in the mediated command **as written**
    /// for a [`RuleKind::Shape`] rule to fire. Optional, that kind only.
    ///
    /// It exists for one real case rather than as a general escape hatch: a
    /// landing directive lives inside a quoted `--body`, so it is not one of the
    /// words the shape matches, and without this an ordinary `gh pr comment`
    /// would be denied alongside the one that carries the directive. Matched
    /// against the raw text of the same segment, quotes included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Narrow a [`RuleKind::Shape`] deny to a call that reached its program
    /// **without** the named mediator (CLOUD-271).
    ///
    /// The row still selects on the command shape; this decides whether that
    /// selection refuses. Without it a row keyed on `cargo` denies every route
    /// to `cargo`, the sanctioned one included — because
    /// `hook::effective_program` looks *through* `mise exec` by design, so the
    /// mediated call resolves to the same program as the bare one. The
    /// objection here is not to the program but to the **toolchain selection**:
    /// a bare `cargo` compiles against whatever is ambient, and the pin is what
    /// makes a local green mean anything.
    ///
    /// So the mediator is read from the segment **as written**, which is the
    /// one place the two routes still differ, and a wrapper cannot launder it:
    /// `env RUSTFLAGS=-Awarnings cargo build` names no mediator and is refused,
    /// while `env FOO=1 mise exec -- cargo build` names one and is not.
    ///
    /// A closed set rather than a free string: an unrecognised mediator would
    /// be a row that never finds what it is looking for and therefore denies
    /// everything, which is the loud half of the same silence
    /// [`validate`] exists to refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_via: Option<RequireVia>,
    /// Narrow a [`RuleKind::Shape`] deny to work that names **no** tracker key
    /// (CLOUD-446).
    ///
    /// A bare shape row means *this command is banned*. This modifier turns the
    /// same row into *this command is banned unless the work is keyed*: the row
    /// still selects on the command shape, and the expression decides whether
    /// that selection refuses. It is a modifier rather than a kind of its own
    /// precisely because the selection half is unchanged.
    ///
    /// The evidence is the mediated command itself plus, resolved at the
    /// boundary, the branch name and the commit subjects on
    /// `<base>..HEAD` — the same fixed VCS-query class [`RuleKind::Receipt`]
    /// already makes, which is why [`RuleKind::carries_ambient_authority`] stays `false`.
    /// Requires `base`, since the range has to be named by the consumer rather
    /// than by a trunk name baked into the crate.
    ///
    /// **The vocabulary is the consumer's.** `CLOUD-<n>` is this repository's
    /// tracker, not Batten's, so what a key looks like is an expression in
    /// `batten.toml` (non-negotiable rule 1). Compiled at load, like `regex` and
    /// `exclude`, so a bad one names its row rather than becoming a gate that
    /// silently allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_key: Option<String>,
    /// Why this rule refuses, and what to do instead — the deny's whole text.
    ///
    /// Required by [`RuleKind::Shape`], where the refusal is all a caller gets;
    /// optional elsewhere, where a `path:line` pointer plus the id already says
    /// where to look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// An optional link to the policy this rule enforces, appended to the deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
    /// The environment variable that suppresses **this row**, named in this
    /// row's own deny (CLOUD-437).
    ///
    /// Absent means the general hatch, [`crate::hook::BYPASS_ENV`]. That default
    /// is not a hedge — it is what keeps the guarantee true as rows are added:
    /// per-row with no fallback would leave the next row hatchless and silent,
    /// which is the failure that produced this column. A row declaring one is
    /// declaring that its bypass is a *separate decision* from every other row's.
    ///
    /// Why a per-row column rather than one global name: the bash guards this
    /// surface inherited each had their own hatch, so an operator could suppress
    /// `memory-guard` alone while `ready-guard` stayed live. One global name
    /// silently widens the blast radius of every bypass — invisibly, because the
    /// deny text cannot say what else it just switched off.
    ///
    /// It is an environment variable rather than a `batten.local.toml` key on
    /// purpose. A hatch LOWERS policy, and house-style §8's override channel is
    /// raise-only; an env var is a per-invocation decision, visible in the
    /// command that took it and gone when the process exits, where a config key
    /// would make the same lowering persistent and invisible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_env: Option<String>,
    /// The **inspection-only** command template a [`RuleKind::Command`] rule
    /// runs as its gate. Required by that kind, rejected by any other.
    ///
    /// Split on whitespace into `program` plus arguments and executed
    /// **directly — never through a shell**, so what runs is exactly what a
    /// reviewer reads (§9: rules "name a command already on the operator's
    /// PATH"). A bare [`FILES_PLACEHOLDER`] argument expands in place to the
    /// matched paths; omit it and the command self-discovers.
    ///
    /// Named for the half it is, not for the act of running: §9's duality has
    /// two commands, and a column called `run` could name either. Enforcement
    /// is always this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// The **mutating** half of §9's duality: the command that repairs what
    /// `check` condemned. Optional, [`RuleKind::Command`] only.
    ///
    /// Parsed today and **executed by nothing**: serialised fix execution is an
    /// engine capability that does not exist yet. The key is reserved now
    /// rather than later because §2 declares no back-compatibility surface, so
    /// a config author who writes one is writing the final spelling.
    ///
    /// A row carrying it is refused by [`run_all`] rather than quietly ignored
    /// — a declared repair that silently never runs is the false green this
    /// engine exists to refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// What this rule PRODUCES: the record the boundary writes after the rule has
    /// decided (CLOUD-851).
    ///
    /// The first column on this struct that is not an input selector. Every other
    /// path-shaped key — `glob`, `documents`, `pattern` — narrows what the rule
    /// READS; this one names what the run leaves behind, which is the notion the
    /// model had none of and which eleven bash writers need somewhere to land.
    ///
    /// **It does not make the rule impure and it does not make it spawn.** The
    /// rule stays [`crate::facts::Cost::Read`] and
    /// [`RuleKind::carries_ambient_authority`] is untouched: a declaration here
    /// yields a [`crate::sink::Requested`] value, and the boundary performs it.
    /// `the_two_axes_agree_about_every_kind` still holds, which is the assertion
    /// that a sink was added as a third axis rather than `Cost::Effect` quietly
    /// repurposed into meaning "mutates".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produces: Option<Sink>,
    /// Path globs this rule's [`Rule::glob`] selects but must NOT judge
    /// (CLOUD-883).
    ///
    /// **`glob` could say "these files" and not "these files except those",** so
    /// a broad rule and a precise one could not compose over one tree: the broad
    /// one always double-reported what the narrow one owned. Measured on
    /// CLOUD-881, whose `forbid` row over `**` reports `Cargo.toml:225` — a
    /// legitimate dependency pin — because deciding that needs the TOML table the
    /// line sits in, which is a `policy` row's question and not a literal's.
    ///
    /// **Not [`Rule::exclude`], which is a regex over the matched LINE and never
    /// sees a path.** The two are confused often enough that this column is named
    /// for what it subtracts rather than for the globs it holds.
    ///
    /// # Narrowing is structural here
    ///
    /// Selection is a [`PathSet`]: `glob` is the only include and these are the
    /// excludes, so the selected set is a SUBSET of what `glob` alone selects, by
    /// construction. `PathSet`'s rule is that an exclude beats an include and the
    /// outcome does not depend on the order patterns were written in — which is
    /// what makes this safe where gitignore's last-match-wins is not. There, a
    /// later positive pattern re-includes, so a negation can WIDEN, and widening
    /// is the one direction a policy engine may never drift ([`Selector`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
    /// The retired spelling of [`Rule::check`], present only so the refusal can
    /// name its replacement.
    ///
    /// Carried as a field rather than left to `deny_unknown_fields` for the
    /// same reason [`crate::config::OverrideConfig::min_batten_version`] is:
    /// "unknown field `run`" reads as a typo, where this is a rename with one
    /// specific fix. Every deny points to it (CLOUD-122).
    ///
    /// Deliberately absent from [`Rule::columns`]: that census classifies the
    /// columns a kind may *carry*, and no kind carries this one — it is refused
    /// outright by [`Rule::validate`], ahead of any per-kind question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// Hash the matched span **verbatim** rather than collapsing its whitespace.
    ///
    /// For a rule whose subject *is* literal content, where a reformat genuinely
    /// changes the thing being flagged. The default collapses whitespace on the
    /// `git patch-id` model, so a formatter reflow does not re-mint an identity;
    /// a `verbatim` rule trades that for sensitivity to the bytes it is about.
    /// `Option<bool>` rather than `bool` so the column census can see presence
    /// (`Rule::columns`), which is what makes a `verbatim` on a kind that hashes
    /// no span a usage error instead of an ignored key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbatim: Option<bool>,
    /// A per-rule identity discriminator: split one identity into several.
    ///
    /// **Split-only by construction, not by validation.** The default identity
    /// is hashed as a field of the override's preimage
    /// ([`crate::identity::override_fingerprint`]), so two spans with different
    /// default identities cannot collide under any discriminator — this can
    /// fragment a group and is mathematically unable to merge two. Changing it
    /// is a deliberate re-mint, not a rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    /// Which way a [`RuleKind::Ratchet`] count may move. Required by that kind,
    /// rejected by every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    /// The git rev a [`RuleKind::Ratchet`] counts against, and the one a
    /// `requires_key` shape row reads commit subjects since. Any rev git
    /// resolves; one it cannot is a usage error naming the rev for the ratchet,
    /// and "could not look" for the shape row — a tree gate owes an answer where
    /// a mediated call must not become un-runnable outside a checkout.
    ///
    /// One column for both because it is one question — *since where* — and a
    /// second spelling of it would be the trunk name written twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The header token a [`RuleKind::Ratchet`]'s files declare their SUBJECT
    /// with, turning the row into *a decrease is admitted when the subject
    /// died* (CLOUD-807).
    ///
    /// A bare ratchet means *this count may not fall*, and the only hatch for a
    /// legitimate reduction is a `[[waiver]]` — which expires, and which cannot
    /// say WHICH reductions are legitimate. This modifier says it. The value is
    /// the line prefix a matched file writes its subject after; everything to
    /// the end of that line is read as whitespace-separated paths.
    ///
    /// **The vocabulary is the consumer's** (non-negotiable rule 1). `#
    /// subject:` is one repository's comment syntax, not Batten's, so the token
    /// is config and this crate never names a specific repo's files. What the
    /// core knows is the RELATIONSHIP: a file declares paths, and those paths
    /// dying is what buys its own deletion.
    ///
    /// Declaring it has two consequences, and the second is what makes the
    /// first honest:
    ///
    /// 1. **Admission.** A decrease is admitted iff every file whose own count
    ///    fell declares a subject, and every path that subject names was a blob
    ///    at `base` and is absent from the working tree.
    /// 2. **Obligation.** EVERY matched file must carry a resolvable header —
    ///    not merely the ones a given change touches. Absent, empty, or naming
    ///    a path that no longer exists is a finding at the row's severity.
    ///
    /// Without (2) the admission rests on a header nobody checks, and a suite
    /// outliving its subject — the header rotted into a lie — reads exactly
    /// like one that never had a subject at all.
    ///
    /// **Headers are read from the BASE tree.** A retired file does not exist
    /// in the working tree, so base is the only place its subject can be read —
    /// and it is also the right place: a change cannot rewrite its own
    /// permission by editing the header in the same commit. The price is that
    /// widening a too-narrow header before a retirement takes a prior landed
    /// commit, which is the correct direction for the trade, since a header
    /// narrower than the truth is a hole and one wider than it is only friction.
    ///
    /// Requires `base`, like the ratchet's count itself: the admission is
    /// decidable from two trees and one of them has to be named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retires_with: Option<String>,
    /// How a deletion proves it conserved logic, not merely files (CLOUD-908).
    ///
    /// [`Rule::retires_with`] buys a decrease with a dead subject; this obliges
    /// every named case inside that decrease to be claimed by exactly one arm in
    /// the head tree. See [`Conserves`] for the three arms and what each owes.
    ///
    /// Requires `retires_with`, and therefore `base`: it refines that column's
    /// admission rather than standing beside it, and a mapping with no admission
    /// to refine would decide nothing on a rule that never permits a decrease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conserves: Option<Conserves>,
    /// How a change declares that a newly added file cannot migrate (CLOUD-929).
    ///
    /// [`Rule::retires_with`] admits a DECREASE with a subject that died; this
    /// admits an INCREASE with a reason the author writes down. Both let a
    /// ratchet permit the movement it exists to refuse, so both are the same
    /// shape — a line prefix, read for a declaration — and neither is a waiver:
    /// the permit lives in the rule rather than in a row that expires.
    ///
    /// **It is read from the WORKING tree, and that asymmetry is the whole
    /// design rather than an oversight.** `retires_with` reads the BASE tree
    /// because a retired file has no working copy, and because reading base is
    /// what stops a change rewriting its own permission in the commit that
    /// spends it. For an increase that inverts exactly: a new file is absent
    /// from base, so the working tree is the only place its marker can be read,
    /// and a change therefore *can* write its own permission.
    ///
    /// So this column is **structurally weaker than its sibling and must not be
    /// described as the same guarantee**. It is a declaration a reviewer reads in
    /// the diff, not a proof the engine verified against a tree the author could
    /// not edit. What it buys is still worth having: it converts a silent
    /// increase into a visible, attributed one, and it makes the author name the
    /// reason at the moment they incur it rather than in a retrospective.
    ///
    /// The engine checks only that a declaration is PRESENT and non-empty. Any
    /// convention about what it must say — an issue key, a bucket name — is the
    /// consumer's, because a tracker's vocabulary inside this crate is
    /// non-negotiable rule 1's violation.
    ///
    /// Requires `base` for its sibling's reason: the admission is decidable only
    /// against two trees, since "newly added" means "absent from base".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admits_with: Option<String>,
    /// How to parse the documents a [`RuleKind::Document`] row selects. Required
    /// by that kind, rejected by every other.
    ///
    /// **Declared, never inferred from the path.** An extension is a naming
    /// convention — a JSON5 file is conventionally `.json5` and legally
    /// anything — and this column is what decides which parser reads the bytes.
    /// Guessing wrong yields "could not look" on a file that is perfectly well
    /// formed, which blames the document for the engine's inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<crate::facts::Format>,
    /// The dotted node path a [`RuleKind::Document`] row addresses — `a.b.0.c`,
    /// walking maps by key and lists by index. Required by that kind, rejected
    /// by every other.
    ///
    /// The path is the consumer's, like every other artifact-shaped value here:
    /// `crates/batten` knows how to walk a document and nothing about what any
    /// particular one contains (non-negotiable rule 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The name this rule publishes its derived value under, for another rule to
    /// read (CLOUD-773). [`RuleKind::Document`] only.
    ///
    /// **A value, not a verdict.** Composition already exists in the layer this
    /// engine is absorbing: 57 of 126 tasks invoke a sibling and branch on its
    /// exit code. That channel carries three states and nothing else, so a
    /// consumer that needs the producer's *structure* re-derives it — measured,
    /// `graph-check` spawns `ready-lint` and then re-spells the issue-key regex
    /// three times. The re-derivation is caused by values not crossing the
    /// boundary, which is what this column is for.
    ///
    /// Names are global to the config and unique: two rows deriving one name is
    /// refused at load, because "which one did I read" is not a question a
    /// reviewer should have to answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derives: Option<String>,
    /// The derived value this rule compares its node against — [`Rule::pattern`]'s
    /// **alternative**, never an addition to it. [`RuleKind::Document`] only.
    ///
    /// A row carries exactly one of the two, the shape `forbid`'s
    /// `pattern`/`regex` pair already uses (CLOUD-283): a row carrying both is a
    /// load error rather than a precedence rule nobody can read.
    ///
    /// Three checks run at load and never later (house-style §8, and CLOUD-647
    /// measured that the obvious candidate engine reports the third at
    /// *evaluation*, which on the mediated path is the worst possible time):
    /// the name must be derived by some row, the reference graph must be
    /// acyclic, and the derivation's [`RuleKind::fact_class`] must not make this
    /// rule more expensive or narrower than its own kind already is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reads: Option<String>,
    /// Per-predicate severity, keyed by an id the module publishes (CLOUD-832).
    /// [`RuleKind::Policy`] only.
    ///
    /// **Why a row's single `severity` is not enough.** A bundle carries many
    /// predicates and this repository's own rules span `deny` and lower
    /// severities; one row cannot carry both, so without this key every
    /// predicate in a bundle inherits one verdict and the bundle is as strict as
    /// its strictest member or as lax as its laxest. That is the "severity
    /// flattens" half of CLOUD-832, and it is the half a waiver cannot stand in
    /// for — a waiver suppresses, it does not lower.
    ///
    /// Absent, and absent per key, means [`Rule::severity`] — the row's own
    /// value is the default for every predicate it registers, so the narrow case
    /// stays one line. A key naming an id no module publishes is refused at
    /// load by [`crate::policy::load`], which is the only place that sees both
    /// the row and the module's declared set; it would otherwise be a setting
    /// that parses and does nothing, which house style §8 refuses everywhere
    /// else.
    ///
    /// This does NOT widen §8's raise-only invariant, and the argument is worth
    /// stating rather than leaving to luck, because the key appears in the
    /// OVERRIDE schema too. Three refusals already standing close it:
    /// [`crate::config::OverrideConfig`] admits rules a local file *adds* and
    /// refuses a redefinition of a committed id, so there is no committed bar
    /// here to lower; [`crate::policy::load`] refuses two rows registering one
    /// module, so an override cannot re-register the same bundle at a lower
    /// severity; and it refuses two modules publishing one predicate id, so an
    /// override cannot smuggle a laxer copy of a predicate in beside the
    /// original. On top of that a module is deny-only by construction — there is
    /// no spelling for an allow — so a predicate's severity chooses how loudly it
    /// refuses, never whether some other gate stops refusing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_severity: Option<BTreeMap<String, RuleSeverity>>,
    /// The vendored preset this rule enables, by name (CLOUD-836).
    /// [`RuleKind::Policy`] only, and the third of the three mutually-exclusive
    /// sources — [`Rule::module`] is one file, [`Rule::bundle`] one folder, this
    /// one a bundle compiled into the binary.
    ///
    /// **A preset is not an authority; it is content the authority enables.**
    /// That is what keeps it clear of CLOUD-29's one-committed-authority rule,
    /// and why enabling one is explicit here rather than default-on: a consumer
    /// who enables nothing gets nothing, so this adds no implicit behaviour for
    /// §8 to have an opinion about.
    ///
    /// The valid names are [`crate::policy::preset_names`], derived from the
    /// embedded set — an unknown name is a config error at load (exit `1`),
    /// never a silent no-op, and the published schema's enum is generated from
    /// the same list so the two cannot disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preset_name_schema")]
    pub preset: Option<String>,
    /// The bundle root this rule enables, as a repository-relative directory
    /// (CLOUD-833). [`RuleKind::Policy`] only, and the **alternative** to
    /// [`Rule::module`] rather than an addition to it.
    ///
    /// A row carries exactly one of the two, the shape `forbid`'s
    /// `pattern`/`regex` pair already uses (CLOUD-283): a row carrying both is a
    /// load error rather than a precedence rule nobody can read.
    ///
    /// **Why a folder does not reopen §8.** §8 forbids *implicit discovery* —
    /// the upward directory walk and the `conf.d` merge — because merging can
    /// weaken. Nothing here merges. The one committed authority names the root
    /// explicitly, and every module inside it is deny-only by construction, so
    /// enumerating them can only ADD refusals. §8's invariant is raise-only, and
    /// a set that cannot subtract satisfies it more strongly than the typed rule
    /// table does. Globbing for `*.rego` anywhere ELSE would be the thing §8
    /// refuses; naming this root is the opposite of it.
    ///
    /// The root joins the `protected` set for the same reason a named module
    /// does — see [`Rule::module`]. A folder must not be less protected than a
    /// file was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    /// The documents a tree-scoped policy row hands its bundle (CLOUD-833).
    /// [`RuleKind::Policy`] with [`RuleScope::Tree`] only.
    ///
    /// **Bounded by declaration, never by an ambient walk.** A bundle is handed
    /// exactly the documents its row names, the way [`crate::facts::Declared`]
    /// already works — which is what keeps house style §4's "cheap when
    /// irrelevant" true: a row whose declared inputs are unchanged does no work
    /// at all. A rule that walked the tree would pay for every file on every
    /// invocation and would make the `read` classification a lie by degrees.
    ///
    /// Each entry is a repository-relative path. The parsed result is
    /// `input.tree.documents[<path>]`, built by
    /// [`crate::rules::tree_document`] from `facts.rs`'s existing `Format`/`Node`
    /// substrate (CLOUD-772) — reused rather than re-implemented, so no second
    /// parser lands.
    ///
    /// A declared document the tree does not carry is
    /// [`crate::facts::Look::CouldNotLook`] and never an empty input: a module
    /// that could not see its subject has not established anything about it,
    /// which is CLOUD-251's vacuous pass in the place it would be least visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<String>,
    /// The documents a tree-scoped policy row hands its bundle, **selected by
    /// glob** (CLOUD-850).
    ///
    /// [`Rule::documents`]'s sibling and the reason it stopped being the only
    /// spelling. `documents` is literal-path only — the sole path handling was
    /// `root.join(path)`, no expansion — so `documents = ["mise-tasks/*"]` was
    /// read as a file with a `*` in its name, failed, landed in `missing`, and
    /// skipped the whole rule. Silently, green. A policy row was the one kind
    /// excluded from the glob machinery every other kind uses, and it is the kind
    /// the entire retirement campaign migrates onto: 27 of the 82 bash gates open
    /// more than five files.
    ///
    /// Resolved with [`Selector`] — `globset` with `literal_separator(true)` —
    /// against the run's one `ignore` walk, exactly as every glob-taking kind
    /// already does. No second matcher.
    ///
    /// **Additive, and `documents` is unchanged.** A row may declare either or
    /// both; the union is what its bundle is handed. Keeping the literal spelling
    /// working is what makes this not a breaking change, and it stays the right
    /// spelling for the ~55 gates that each open one to four named paths.
    ///
    /// A glob that matches nothing is a **stated** skip rather than a silent one,
    /// for the reason the whole row exists: a selector that selects nothing and a
    /// tree that satisfies the predicate are otherwise the same green.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// The files a tree-scoped policy row hands its bundle as **lines**
    /// (CLOUD-846).
    ///
    /// [`Rule::documents`]'s unparsed sibling, and the ceiling it lifts was
    /// measured: of the 20 tree-scoped gates, 8 read structured config and 12
    /// read content no fact could carry — 4 markdown, 5 `.bats`/`.rs`/`.pkl`
    /// source, 3 no file literals at all. `Format::for_path` answers `None` for
    /// every one of those, so the path landed in `missing` and the row skipped.
    ///
    /// The value is `input.tree.lines[<path>]`, an array of strings. A path that
    /// cannot be read stays in `missing` — **could-not-look, never an empty
    /// array**, which is the distinction that keeps CLOUD-251's vacuous pass out:
    /// a file nobody could read and a file with no matching line are not the same
    /// answer.
    ///
    /// **Bounded by declaration, exactly as `documents` is.** A row reads the
    /// paths it names and no others.
    ///
    /// **Rule 4 is what picks this shape over raw text.** A module may SEE a
    /// line; a finding may not CARRY one. Lines are the widest shape that cannot
    /// put content into a finding by accident, and `tests/pointer_only.rs` holds
    /// that structurally rather than by review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<String>,
    /// The files a tree-scoped policy row hands its bundle as lines, **selected
    /// by glob** (CLOUD-864).
    ///
    /// [`Rule::lines`] is to this what [`Rule::documents`] is to
    /// [`Rule::sources`], and the pair landed asymmetric: CLOUD-850 gave the
    /// parsed half a glob and the unparsed half kept literal paths only. That
    /// leaves the fact model's widest surface reachable only by naming every
    /// path — and the gates that need LINES rather than a parsed document are
    /// precisely the ones reading many files, since `Format::for_path` answers
    /// `None` for source text.
    ///
    /// Measured need: the shebang rule this column was added for decides over
    /// **137** shell programs. Enumerating them is a list that goes stale the
    /// next time one is added, silently and green — the failure the declaration
    /// bound is supposed to prevent, reintroduced by the spelling.
    ///
    /// Same [`Selector`], same union semantics, same stated-skip on a glob that
    /// matches nothing. Additive: `lines` is unchanged and stays right for a row
    /// naming one or two paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_sources: Vec<String>,
    /// The Rust files this policy row reads as **call sites**, by literal path
    /// (CLOUD-914).
    ///
    /// [`Rule::lines`]' sibling one tier up: `lines` answers *does this token
    /// appear in this file*, and this answers *does it appear in command
    /// position*. A row wanting the second must say so, because parsing is
    /// strictly more expensive than splitting and nobody should pay it by
    /// accident.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<String>,
    /// The same, glob-selected (CLOUD-914).
    ///
    /// Ships WITH its literal column rather than arriving a row later, which is
    /// the asymmetry `line_sources` records having to fix: a gate over call
    /// sites is a gate over many files by construction, so the enumerated
    /// spelling would go stale the first time a module was added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invocation_sources: Vec<String>,
    /// The Rust files this policy row reads as a **`use` graph**, by literal path
    /// (CLOUD-762).
    ///
    /// Separate from [`Rule::invocations`] because the two answer different
    /// questions over the same parse — what a file CALLS versus what it REACHES —
    /// and a row wanting one should not pay to project the other.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<String>,
    /// The same, glob-selected (CLOUD-762).
    ///
    /// A layering rule decides over every module by construction, so the glob is
    /// the spelling that matters and it ships with its literal column.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub use_sources: Vec<String>,
    /// The git facts this policy row reads, **declared** (CLOUD-907).
    ///
    /// [`Rule::documents`]'s sibling for the family that is not a file, and the
    /// declaration is load-bearing twice over.
    ///
    /// **It is what keeps `Cost::Read` honest.** `bench/gates/RESULTS.md`
    /// re-derived the corpus and 22 gate tasks need a git fact the engine could
    /// not emit; every one of them names which. Resolving the family ambiently
    /// instead would make every run pay for every variant — and this tree has
    /// already measured that bill: CLOUD-851 took `check` from a p50 of 4.76ms to
    /// 10.01ms, 2.103x, by locating the git dir and reading HEAD unconditionally
    /// for a question no rule had asked.
    ///
    /// **And it is what makes the acquisition auditable.** A reader of
    /// `batten.toml` sees exactly which rows read the checkout's state, which is
    /// the same property `documents` gives for files.
    ///
    /// Refs and ranges are [`Rule::refs`] and [`Rule::ranges`] rather than
    /// entries here, because those two carry a parameter and these three do not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitRead>,
    /// Whether this policy row reads the **resolved-symbol** fact (CLOUD-760).
    ///
    /// A bare flag rather than a path list, because the fact is one whole-crate
    /// value: a delegated analyser resolves names across the compilation, and
    /// asking it about one file would be asking a different, cheaper question
    /// that [`Rule::invocations`] already answers.
    ///
    /// **Declared rather than ambient, and here the reason is the cost class.**
    /// This is the first `Cost::Effect` fact — resolving it RUNS `cargo clippy`
    /// over the crate, which is seconds rather than the milliseconds every other
    /// fact costs. Every git fact is declared for a bill CLOUD-851 measured at
    /// 2.103x; this one would be far worse, and a run that paid it without being
    /// asked would make `check` unusable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub symbols: bool,
    /// The refs this policy row resolves, **declared** (CLOUD-907).
    ///
    /// Each becomes an entry of `input.tree["git-refs"]` carrying the commit it
    /// names and whether HEAD descends from it. A ref that does not resolve is
    /// **absent from that map**, never present with `ancestor_of_head: false`:
    /// `origin/main` missing in a shallow clone is not "the branch has not
    /// landed", and a gate reading it that way reports the wrong verdict with
    /// full confidence.
    ///
    /// Separate from [`Rule::ranges`] although git's own ref-name rules would
    /// make one column injective — `git check-ref-format` forbids `..` in a ref
    /// name, so an entry containing it could only be a range. Two columns
    /// anyway: the two ask different questions, they sit on different surfaces
    /// (a ref is bounded and a range is not), and CLOUD-883's lesson is that a
    /// column earns its name from what it does rather than from what it can be
    /// packed with.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    /// The commit ranges this policy row reads, **declared** (CLOUD-907).
    ///
    /// Spelled `<base>..<head>`, and each becomes an entry of
    /// `input.tree["git-ranges"]` carrying that range's commits as a sha and a
    /// subject each. A range whose endpoints do not resolve is **absent**, never
    /// an empty list — "nothing landed in this range" and "I could not read this
    /// range" are the two answers a migration gate most needs kept apart.
    ///
    /// Pointer-only at the boundary: a subject is git's `%s`, which is how the
    /// log itself points at a commit. A message body or a diff would put tracked
    /// content on the policy input, and rule 4 is decided at the acquisition
    /// rather than at the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<String>,
    /// The landing targets this policy row asks about, **declared** (CLOUD-880).
    ///
    /// Each becomes an entry of `input.tree.landing` answering whether THIS
    /// checkout's work is on that target — **by patch identity**, because CLOUD-36
    /// decides merged-ness that way and a rebased landing is invisible to
    /// ancestry. That is the question [`Rule::refs`] deliberately does not answer:
    /// a ref resolves to a commit there, and reachability was refused precisely so
    /// this column could carry the honest test instead.
    ///
    /// A target that cannot be scanned is **absent**, never a negative. It is the
    /// same absence-versus-empty rule as `refs` and `ranges`, and here it is the
    /// most dangerous of the three to get wrong: `landed: false` fabricated from a
    /// failed scan reads as *this work is outstanding* and a gate acts on it.
    ///
    /// Declaration bounds the cost. A scan walks the head-side commits and
    /// computes a patch id per commit, so it is one scan per named target rather
    /// than an ambient sweep of the trunk — the same bound `refs` puts on ref
    /// resolution, and what makes `Cost::Read` an honest classification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub landing: Vec<String>,
    /// The globs whose paths this policy row wants classified against
    /// [`Rule::base`] — added, edited or deleted (CLOUD-1059).
    ///
    /// **Requires `base`**, and the load refuses the column without it, because a
    /// delta with no rev to compare against is not a narrower question but an
    /// unanswerable one. That is [`Rule::retires_with`]'s rule, and this column
    /// shares the `base` it reads on purpose: two spellings of "what did this
    /// branch change" is the drift a single column exists to prevent.
    ///
    /// Declaration bounds WHICH paths are reported and deliberately does not bound
    /// what answering costs — a glob is a selection over the whole tree, so the
    /// walk happens either way. That is why [`crate::facts::BASE_DELTA`] is
    /// `Surface::Check` and never `Hook`.
    ///
    /// A base that does not resolve leaves the whole fact `None`, projected as
    /// `null`, never an empty delta: "this branch changed nothing" and "I could
    /// not read the base" are the two answers a migration gate must keep apart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delta_sources: Vec<String>,
    /// The registered policy module this rule evaluates, as a repository-relative
    /// path (CLOUD-647). [`RuleKind::Policy`] only.
    ///
    /// **Registration, never discovery.** §8 forbids the upward directory walk
    /// and the `conf.d` merge; naming the module here, in the one committed
    /// authority, is the opposite of both, and the list of registered modules is
    /// itself reviewable data. Globbing a policy directory would be the thing §8
    /// refuses, and is why this is a path per row rather than a directory key.
    ///
    /// The path is what a reader reviews and what `[epoch] tracked` should hash;
    /// the module's SOURCE never appears in any emitted document, because a
    /// rendered policy body is a payload and rule 4 admits only pointers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Why this rule's findings have no fix — the stated answer, which is not
    /// the same as an absent one (CLOUD-81).
    ///
    /// A finding a caller can neither clear nor act on spends attention for
    /// nothing, so "there is no fix" must be *said*. The **alternative** to
    /// [`Rule::fix`], never an addition: a row carrying both is a load error
    /// rather than a precedence rule nobody can read.
    ///
    /// This is the only column CLOUD-81 adds. `fix` already exists — CLOUD-215
    /// reserved it as the `command` kind's repair side — and
    /// [`Rule::remediation`] reads it rather than declaring a second spelling of
    /// the same thing. Recording a repair on a finding is not *running* one, so
    /// this does not disturb `run_all`'s refusal of a rule that declares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_fix_reason: Option<String>,
    /// The receipts a [`RuleKind::Receipt`] row requires, all of which must be
    /// valid before the matched call is allowed. Required by that kind,
    /// rejected by every other.
    ///
    /// A list rather than a single name because the predicate this ports is
    /// already a conjunction — readying a PR requires that the branch both
    /// verified and is linear on the trunk — and expressing it as two rows
    /// would let one be deleted while the other kept the gate looking whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<String>>,
    /// Which git fact a [`RuleKind::Receipt`] row's receipts are keyed to.
    ///
    /// Optional with a pinned default of [`ReceiptKey::Head`], the conservative
    /// one: a HEAD-keyed receipt expires on an amend or a rebase, so omitting
    /// the key can only make a gate stricter than intended, never weaker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<ReceiptKey>,
    /// What makes a [`RuleKind::Receipt`] row fire — a command shape, or the fact
    /// that the call writes (CLOUD-444).
    ///
    /// Optional with a pinned default of [`ReceiptTrigger::Command`], which is
    /// what every row written before this column meant. The axis is orthogonal to
    /// `key`: a trigger says *when* the precondition is due, a key says *what
    /// invalidates* the proof of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<ReceiptTrigger>,
    /// The programs whose exit status IS the answer, for a
    /// [`RuleKind::Pipeline`] row (CLOUD-443).
    ///
    /// Declared on the rule rather than as a config-root table because it is what
    /// this rule is *defined over*: a global table would be a second authority
    /// with no other consumer, and the set would outlive the row that reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Vec<VerdictProgram>>,
    /// The pipeline stages that substitute output for status — pagers and
    /// filters alike, since each replaces the verdict with its own.
    ///
    /// A plain name list, not a `VerdictProgram`: a filter's identity is the
    /// program, and no subcommand makes `tail` more or less of one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filters: Option<Vec<String>>,
    /// The text utilities whose use **as a first stage over a repository path**
    /// stands in for a first-class tool, for a [`RuleKind::Pipeline`] row
    /// (CLOUD-864).
    ///
    /// The second predicate this kind carries, and it belongs here for the
    /// reason the kind exists: what separates a substitution from a legitimate
    /// filter is not the program but **what surrounds it**. `grep pat crates/`
    /// answers a question `Grep` answers better; `git ls-files | grep crates/`
    /// is a filter over another command's output and no tool replaces it. Same
    /// program, same operand, opposite verdicts — and only the position in the
    /// pipeline tells them apart, which is precisely what a `shape` row cannot
    /// see (`matching_shape_rows` iterates every segment with no index in scope,
    /// so it would refuse the filter too).
    ///
    /// A plain name list, like `filters` and for the same reason: a substitute's
    /// identity is the program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substitutes: Option<Vec<String>>,
    /// What a [`RuleKind::Judge`] row asks the model — the committed evaluation
    /// instruction handed to the judge command (CLOUD-56).
    ///
    /// **Committed, and that is the point.** The question a model is asked is
    /// policy: it belongs in the authority a reviewer reads and a diff shows,
    /// not in a prompt assembled at run time out of something else. It is also
    /// the one payload class that carries no egress question at all
    /// ([`crate::judge::RuleText`]) — it is the config author's own words, on
    /// their way back to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criteria: Option<String>,
    /// How fast a [`RuleKind::Judge`] finding must be answered
    /// ([`crate::severity::AdvisoryTier`], CLOUD-80). Absent means
    /// [`AdvisoryTier::Advisory`], the least-urgent rank.
    ///
    /// This is the axis a judge row declares **instead of** `severity`, and the
    /// substitution is the whole advisory bound: `severity` decides the exit
    /// contract, `tier` decides a response deadline. A judge row is refused the
    /// `severity` column outright, so the axis a model's opinion could ride into
    /// the exit code does not exist for this kind.
    ///
    /// A default rather than a required column, unlike `severity` on every other
    /// kind: an omitted deadline resolves to the weakest one, which withholds no
    /// gate because there is no gate here to withhold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<AdvisoryTier>,
}

/// Which git fact a receipt is keyed to, and therefore what invalidates it.
///
/// The distinction is not a tuning knob, it is what the receipt *attests*.
/// A `head` receipt claims something about those exact bytes, so an amend or a
/// rebase must expire it. A `branch` receipt claims a decision about the work,
/// which every commit on the branch continues to serve, so a SHA-keyed one
/// would demand a re-claim per commit — the false-positive rate that gets a
/// guard bypassed. Both spellings are carried from the shell layer that proved
/// them (`ready-guard` keys by SHA, `claim-check` by branch).
///
/// **`ValueEnum` because the CLI selects the same keying** (CLOUD-741). A
/// `receipt` rule is pinned to [`RuleScope::MediatedCall`], so `batten check`
/// can never evaluate one and `verify` cannot reach this predicate through the
/// engine — which left `verify` re-implementing it in shell, weakly enough that
/// CLOUD-516's own incident passed. `receipt status --key branch` is how the
/// tree surface reaches the one implementation instead, so config and CLI must
/// name the keying with the same tokens or the two surfaces disagree about what
/// they asked for. `clap`'s and serde's renames both land on `head`/`branch`;
/// the `clap(rename_all)` is stated rather than inferred so a future variant
/// cannot drift them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
#[derive(Default)]
pub enum ReceiptKey {
    /// Keyed to the exact commit; an amend, a rebase, or a moved trunk expires it.
    #[default]
    Head,
    /// Keyed to the branch; every commit on it continues to serve the claim.
    Branch,
    /// Keyed to a value the CALL names, read through [`Rule::key_from`]
    /// (CLOUD-987).
    ///
    /// **The subject is one row of somebody's board, not one checkout**, and that
    /// is the whole reason this variant exists. CLOUD-312's row 2 bounds how stale
    /// a read may be before a write is authorised, and `issue-read-check`'s header
    /// says why the key cannot be the branch: *"a branch legitimately updates
    /// several issues; a branch key would let a fresh read of one issue authorise
    /// a stale write to another."* So collapsing this to [`ReceiptKey::Branch`]
    /// is not a simplification — it is the defect that comment refuses, and
    /// CLOUD-508 is the incident.
    ///
    /// **The value becomes a filename, so it is refused rather than sanitised.**
    /// [`SinkKey`]'s doc already states the hazard for a config-spelled key; a
    /// PAYLOAD-supplied one is strictly worse, because the call is what a rule is
    /// judging. A value that is not a single safe path component — empty, or
    /// carrying a separator, or `.`/`..`, or absurdly long — resolves to
    /// could-not-look and **allows**, rather than being rewritten into something
    /// that would file under a subject the caller did not name. Rewriting could
    /// silently collide two subjects onto one receipt, which is the one outcome
    /// worse than not looking.
    Named,
}

/// What a rule's produced record is filed under (CLOUD-851).
///
/// Two, and both are answers the BOUNDARY has: the rule's own id, which is
/// constant, and the current branch, which is a fact about the checkout. Deliberately
/// not a free-form string — a key a config could spell arbitrarily is a filename a
/// config could point anywhere, and the store lives under `$GIT_DIR`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SinkKey {
    /// Filed under the rule's own id: one record per rule, whatever the checkout
    /// is doing. The right key for a journal.
    #[default]
    Rule,
    /// Filed under the current branch, so every commit on it continues to serve
    /// the same record — `claim.<branch>`'s shape, and the reason
    /// [`crate::rules::ReceiptKey::Branch`] exists for the reading half.
    Branch,
}

/// Whether `selector` names `raw_tool`: the whole name, or its whole final
/// `__`-delimited segment.
///
/// **One authority, because two callers need the identical answer** (CLOUD-1024).
/// [`Rule::selects_tool`] decides which rows adjudicate a call and
/// [`crate::mint::Declared::tool`] decides which results mint a receipt; a rule
/// that fires on a call whose result minted nothing is a gate nobody can satisfy,
/// and that is exactly what two hand-rolled matchers would eventually produce.
///
/// Never a bare suffix: that would make `Edit` select `NotebookEdit`, widening a
/// row onto a tool nobody named. The delimiter is what lets a selector survive
/// the host rotating the server label it was minted under (CLOUD-178, CLOUD-665,
/// CLOUD-684) — measured on one connector exposed under three names across
/// registration episodes, where a row naming one matched none of the others and
/// the miss was silent.
///
/// An empty selector is refused at load by both callers, so it cannot reach here
/// and match the empty final segment of a name ending in `__`.
#[must_use]
pub fn selects_tool_name(selector: &str, raw_tool: &str) -> bool {
    if raw_tool == selector {
        return true;
    }
    // `strip_suffix` then a `__` test, rather than `ends_with("__{selector}")`
    // built by formatting: the same answer without allocating a string per row
    // per call, on the hottest path in the binary.
    raw_tool
        .strip_suffix(selector)
        .is_some_and(|prefix| prefix.ends_with("__"))
}

/// A git fact a rule declares reading, for the three variants that take no
/// parameter (CLOUD-907).
///
/// The parameterised two are [`Rule::refs`] and [`Rule::ranges`]. A closed enum
/// rather than a string, for [`SinkKey`]'s reason: a name the config could spell
/// arbitrarily is a question the engine would have to answer at runtime, and an
/// unknown variant here is a load error rather than a fact that silently
/// resolves to undefined — which is the shape a Rego predicate reads as "does
/// not hold".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum GitRead {
    /// [`crate::facts::Fact::GitHead`] — HEAD's commit, branch and detachedness.
    Head,
    /// [`crate::facts::Fact::GitStatus`] — how the working tree differs from
    /// HEAD. Tree surface only: it walks the checkout.
    Status,
    /// [`crate::facts::Fact::GitRemote`] — the configured remotes and HEAD's
    /// upstream. Read from `.git/config`; never over the network.
    Remote,
}

/// A rule's declared output (CLOUD-851).
///
/// A kind and a key, and nothing else. There is no path column on purpose: a
/// sink that could name its own destination is a config that can write anywhere,
/// and the store's layout is the engine's to own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sink {
    /// Which of the three censused kinds this is, deciding whether the record is
    /// appended, replaced, or merely touched — and whether a later run reads it
    /// back as a fact.
    pub kind: crate::facts::Production,
    /// What the record is filed under.
    #[serde(default)]
    pub key: SinkKey,
}

/// How a deletion proves it conserved LOGIC and not merely files (CLOUD-908).
///
/// [`Rule::retires_with`] admits a decrease when the deleted file's declared
/// subject died. That conserves **files**: it asks *is the subject gone* and never
/// *did the cases move*, so a migration can delete a suite and land green with
/// nothing asserting what replaced it. Measured on the one retirement that has
/// happened — 22 named cases deleted, 18 successors, six identifiable from
/// nothing in the tree, and one whose behaviour changed deliberately with no
/// mark on it.
///
/// This column closes that. Every named case in a file whose count fell must be
/// claimed, in the HEAD tree, by exactly one of three arms:
///
/// | arm | means | obliges |
/// | --- | --- | --- |
/// | `carried` | the same assertion, in a new home | a target that resolves; feeds the differential replay |
/// | `subsumed` | a general property elsewhere now covers it | a target that resolves |
/// | `changed` | it diverges deliberately | a target that resolves **and** a reason |
///
/// An unclaimed case, an arm naming a target this tree does not have, or one case
/// claimed twice, all refuse the deletion.
///
/// **Declared, never inferred.** The same argument [`Rule::retires_with`] makes
/// for `# subject:`: a name heuristic over case titles would be worse than
/// nothing, because titles are prose. The engine knows the RELATIONSHIP — a
/// deleted named thing is claimed by exactly one arm naming something that
/// exists — and every token spelling it is the consumer's (non-negotiable rule 1).
///
/// **The arms live on their targets, and the walk that finds them is bounded by
/// declaration.** `declared_in` is the glob the head tree is read over, never an
/// ambient sweep: the same posture the git facts take, and the reason a mapping
/// is greppable rather than filed in a second register nothing keeps current.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Conserves {
    /// The line prefix a named case is declared after, in the file being deleted.
    ///
    /// The name STARTS immediately after this token and ENDS at the next
    /// [`Conserves::close`], so a token ending in the opening delimiter — `@test
    /// "` — reads the quoted title and nothing else on the line.
    pub case: String,
    /// The delimiter a case name ends at, in a dying file and in an arm alike.
    ///
    /// One field for both, because they are one question: an arm has to spell the
    /// case it claims the same way the case spells itself, or the match is between
    /// two different vocabularies and the mapping decides nothing.
    pub close: String,
    /// The token an arm claiming *the same assertion, moved* is written after.
    pub carried: String,
    /// The token an arm claiming *a general property covers this now* is written
    /// after.
    pub subsumed: String,
    /// The token an arm claiming *this diverges, deliberately* is written after.
    /// Alone among the three it also owes a reason — the text after its target.
    pub changed: String,
    /// The token an arm claiming *nothing replaces this, the subject is gone* is
    /// written after (CLOUD-1080). Optional, so a row without it behaves exactly
    /// as it did before this column existed.
    ///
    /// **The other three all name a successor, and a WITHDRAWAL has none.** They
    /// describe a suite migrating into another mechanism; this describes a feature
    /// removed, where the honest mapping is that there is nothing to map. Without
    /// it the only ways past a withdrawal are a false `subsumed` — a ledger entry
    /// that lies to pass — or a `[[waiver]]`, which `config-lint` refuses as
    /// `waiver-added` unless the weakening was groomed onto the issue before the
    /// work. So the gate had no honest path, which is a defect rather than a
    /// verdict.
    ///
    /// **It is admissible ONLY where the dying file's declared subject is absent
    /// at head**, which is what keeps it strictly narrower than the waiver it
    /// replaces: it cannot excuse deleting cases whose subject is still standing,
    /// and that is the abuse a bare fourth verb would open. It owes a reason and
    /// names no target, for the same reason it exists — there is no successor to
    /// name, and a column demanding one would be the false `subsumed` again.
    pub withdrawn: Option<String>,
    /// The glob the head tree is read over to find arms.
    ///
    /// Required rather than defaulted to the rule's own `glob`: the successors of
    /// a retired suite are by definition NOT under the glob the suite was, so a
    /// default would look total and select nothing — a mapping that admits
    /// everything, which is the failure this column exists to end.
    pub declared_in: String,
}

/// One program family whose **exit status is the answer** (CLOUD-443).
///
/// Enumerable on purpose. "Is this command's status the thing the caller wants"
/// is not decidable in general, and an open predicate would be a judgement
/// (non-negotiable rule 3) — so the set is a closed list the consumer declares,
/// and the read-only member of each family is excluded by name, because a query's
/// output *is* its answer and piping it is ordinary composition.
///
/// The four optional columns are not four ideas: each is the shape one real
/// family needs, and no row may carry two that contradict.
///
/// | column | matches | the family it exists for |
/// | --- | --- | --- |
/// | `subcommands` | first non-flag word is one of these | a task runner's `run`, a VCS's mutating verbs |
/// | `nested` | second non-flag word is one of these | a forge CLI's `<noun> <verb>` |
/// | `except` | a first word exists and is NOT listed | a build tool with far more verdict subcommands than query ones |
/// | `any_argument` | a first word merely exists | a test runner, where a bare invocation prints usage and answers nothing |
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerdictProgram {
    /// The program name as it appears on a command line. Matched exactly, on the
    /// EFFECTIVE program — wrapper lookthrough is the hook parser's, not a second
    /// implementation here.
    pub program: String,
    /// The first non-flag words that make this program verdict-bearing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommands: Option<Vec<String>>,
    /// The second non-flag words, for a program that dispatches twice. Requires
    /// `subcommands`, since a nested word with nothing above it names no action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested: Option<Vec<String>>,
    /// The first non-flag words that are **queries** — everything else is a
    /// verdict. The inverse of `subcommands` and refused alongside it: a row
    /// cannot both allow-list and deny-list the same position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub except: Option<Vec<String>>,
    /// Whether any first non-flag word at all makes this a verdict, for a program
    /// whose bare form answers nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any_argument: Option<bool>,
}

impl VerdictProgram {
    /// Whether `program` and `words` — the effective program and the non-flag
    /// words after it — make this invocation verdict-bearing.
    ///
    /// The program is compared FIRST and exactly. Leaving it out was a real
    /// defect for the length of one differential run: an `except` row is a
    /// deny-list over subcommands, so with no program test it matched every
    /// command carrying any argument, and `git log … | head` — a read-only query,
    /// the exact false positive this kind must not produce — was refused.
    #[must_use]
    pub(crate) fn matches(&self, program: &str, words: &[&str]) -> bool {
        if self.program != program {
            return false;
        }
        let first = words.first().copied();
        if let Some(allowed) = self.subcommands.as_deref() {
            let Some(first) = first else { return false };
            if !allowed.iter().any(|candidate| candidate == first) {
                return false;
            }
            let Some(nested) = self.nested.as_deref() else {
                return true;
            };
            return words
                .get(1)
                .is_some_and(|second| nested.iter().any(|candidate| candidate == second));
        }
        if let Some(queries) = self.except.as_deref() {
            return first.is_some_and(|first| !queries.iter().any(|query| query == first));
        }
        self.any_argument.unwrap_or_default() && first.is_some()
    }

    /// Reject a row that cannot mean anything.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `program`, an empty
    /// list in any column, a `nested` with no `subcommands`, a row carrying both
    /// `subcommands` and `except`, an `any_argument` beside either of them, and a
    /// row declaring no column at all. Every one of those either matches nothing
    /// or contradicts itself, and both read as coverage from the file.
    fn validate(&self, rule: &str) -> anyhow::Result<()> {
        let refuse = |detail: &str| {
            Err(UsageError::raise(format!(
                "rule {rule}: verdict {}: {detail}",
                self.program
            )))
        };
        if self.program.trim().is_empty() || self.program.split_whitespace().count() != 1 {
            return Err(UsageError::raise(format!(
                "rule {rule}: a verdict entry names one program, not {:?}",
                self.program
            )));
        }
        for (name, list) in [
            ("subcommands", self.subcommands.as_deref()),
            ("nested", self.nested.as_deref()),
            ("except", self.except.as_deref()),
        ] {
            if list.is_some_and(<[String]>::is_empty) {
                return refuse(&format!("`{name}` is empty, so it narrows nothing"));
            }
        }
        if self.subcommands.is_some() && self.except.is_some() {
            return refuse("`subcommands` and `except` are opposite readings of the same position");
        }
        if self.nested.is_some() && self.subcommands.is_none() {
            return refuse(
                "`nested` needs `subcommands` — a second word with no first names nothing",
            );
        }
        let any = self.any_argument.unwrap_or_default();
        if any && (self.subcommands.is_some() || self.except.is_some()) {
            return refuse("`any_argument` already admits every word, so it cannot be narrowed");
        }
        if !any && self.subcommands.is_none() && self.except.is_none() {
            return refuse("declares no condition, so it never matches");
        }
        Ok(())
    }
}

/// The mediator a [`Rule::require_via`] row requires (CLOUD-271).
///
/// One variant, deliberately, and it is a variant rather than a string because
/// the set is the set of mediators the matcher knows how to look for. A free
/// string would let a typo load as a row that never finds its mediator and
/// therefore refuses every call — a gate that reads as narrow and denies wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RequireVia {
    /// The pinned toolchain: the call reached its program through `mise`.
    ///
    /// `mise run <task>` and `mise exec -- <program>` both count. They are the
    /// same fact for this key — the program was selected by the pin rather than
    /// by `PATH` — and only the second reaches the program token at all, since
    /// `mise run` names a task and is judged as `mise` itself.
    Mise,
}

/// What makes a receipt row fire (CLOUD-444).
///
/// The two triggers answer different questions and neither subsumes the other. A
/// [`ReceiptTrigger::Command`] row says "before you run *this*, prove *that*" —
/// the precondition is due at one recognisable invocation, and the row names it
/// with a `pattern`. A [`ReceiptTrigger::Write`] row says the precondition is due
/// before the work is *touched at all*, which no command shape can express:
/// the claim gate fires on every write precisely because the edit it exists to
/// catch is the first one, whatever tool makes it.
///
/// A write-triggered row therefore carries no `pattern` and no `contains` — both
/// name a command line a write does not have — and its exclusions (git-ignored,
/// outside the repository, inside `.git`) are boundary facts rather than config,
/// because they are questions about a checkout and this table is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptTrigger {
    /// Fires on a mediated command matching the row's `pattern`.
    #[default]
    Command,
    /// Fires on any mediated call that writes a judgeable path.
    Write,
}

/// Which way a ratcheted count may move.
///
/// Named for the *permitted* direction rather than the banned one, so a config
/// row reads as the promise it makes: `non_decreasing` says this count will not
/// fall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Direction {
    /// The count may rise or hold, never fall. The test-deletion guard.
    NonDecreasing,
    /// The count may fall or hold, never rise. The new-`#[ignore]` guard.
    NonIncreasing,
}

impl Direction {
    /// Every direction, so a census is derived rather than hand-maintained.
    pub const ALL: &'static [Direction] = &[Direction::NonDecreasing, Direction::NonIncreasing];

    /// The stable config token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::NonDecreasing => "non_decreasing",
            Direction::NonIncreasing => "non_increasing",
        }
    }

    /// Whether moving from `base` to `working` broke the promise.
    ///
    /// Equality is never a violation in either direction — a ratchet bans
    /// movement, not stasis.
    #[must_use]
    pub const fn violated(self, base: usize, working: usize) -> bool {
        match self {
            Direction::NonDecreasing => working < base,
            Direction::NonIncreasing => working > base,
        }
    }
}

impl Rule {
    /// The program a [`RuleKind::Command`] rule invokes: the first
    /// whitespace-separated token of [`Rule::check`].
    ///
    /// Shared rather than re-split at each caller, so `doctor`'s PATH probe
    /// (CLOUD-66) and the runner below can never disagree about which token is
    /// the program — a probe that checked a different word than the one executed
    /// would report health about the wrong binary.
    ///
    /// The **check** half, never the fix: enforcement only ever runs that side
    /// (§9), so a probe over the other one would report health about a command
    /// this engine cannot invoke at all.
    ///
    /// `None` for any other kind, and for a `check` with no tokens (which the
    /// runner refuses as a usage error).
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        if self.kind != RuleKind::Command {
            return None;
        }
        self.check.as_deref()?.split_whitespace().next()
    }

    /// What a match does, for the kinds that decide anything.
    ///
    /// Shares its name with the field on purpose: every existing caller wanted
    /// *the effective severity*, and a differently-named accessor beside a
    /// public `Option` field would leave the field as a second, wronger way to
    /// ask.
    ///
    /// A [`RuleKind::Judge`] row has none and answers [`RuleSeverity::Allow`],
    /// which is not a fallback but the accurate statement: `allow` is this
    /// engine's word for "a match here is not a finding at all", and it is
    /// exactly what the walker acts on to skip the row. For every other kind the
    /// column is required at load, so the `unwrap_or` is unreachable through a
    /// config that parsed.
    #[must_use]
    pub fn severity(&self) -> RuleSeverity {
        self.severity.unwrap_or(RuleSeverity::Allow)
    }

    /// The severity a denial is reported at: the predicate's own when
    /// [`Rule::predicate_severity`] names it, the row's otherwise (CLOUD-832).
    ///
    /// One place, for [`crate::policy::Module::attribute`]'s reason: the id a
    /// finding is reported under and the severity it is reported at have to be
    /// resolved from the same answer, or a waiver written against what a reader
    /// sees suppresses something else. `predicate` is `None` for every kind but
    /// [`RuleKind::Policy`] and for a bare-string `deny`, and both answer
    /// [`Rule::severity`] — which is the pre-CLOUD-832 behaviour reached without
    /// a special case.
    #[must_use]
    pub fn severity_for(&self, predicate: Option<&str>) -> RuleSeverity {
        let Some(predicate) = predicate else {
            return self.severity();
        };
        self.predicate_severity
            .as_ref()
            .and_then(|table| table.get(predicate))
            .copied()
            .unwrap_or_else(|| self.severity())
    }

    /// The obligation [`RuleKind::permits`] cannot express (CLOUD-758).
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a shape row carrying neither column, or
    /// both, or a `content` expression the matcher cannot compile.
    ///
    /// A shape row is keyed on a command or on content — exactly one (CLOUD-758).
    ///
    /// The "one of" `forbid`'s `pattern`/`regex` pair carries, and for the same
    /// reason: a row with NEITHER loads, matches every mediated call, and turns
    /// a ban into a universal gate; a row with BOTH is two predicates where the
    /// reader can see one, and a precedence rule nobody can read is worse than a
    /// refusal.
    ///
    /// # Errors
    ///
    fn validate_shape_columns(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Shape {
            return Ok(());
        }
        // THREE KEYING COLUMNS NOW, EXACTLY ONE OF WHICH A ROW CARRIES
        // (CLOUD-924). Counted rather than matched as a tuple: a 2x2 match was
        // already at its readable limit and a 2x2x2 one would spell six
        // impossible arms to reach the two that matter.
        let keys: Vec<&str> = [
            ("pattern", self.pattern.is_some()),
            ("content", self.content.is_some()),
            ("tool", self.tool.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect();
        if keys.len() > 1 {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" carries {}; a row is keyed on a command \
                 (`pattern`), on written content (`content`), or on the tool a call names \
                 (`tool`) — never on more than one",
                self.id,
                keys.join(" and ")
            )));
        }
        if let Some(selector) = self.tool.as_deref() {
            // Refused at load rather than at adjudication, where an empty
            // selector would match the empty final segment of every name ending
            // in `__` — a row that reads as naming one tool and selects a family.
            if selector.is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `tool` is empty; name the tool this row is about",
                    self.id
                )));
            }
            // The same command-only modifiers `content` refuses below, refused
            // for the same reason one column over: a structured call carries no
            // argv either, so each would read as configured and narrow nothing.
            self.refuse_command_modifiers("tool")?;
            return self.validate_ceiling();
        }
        match (self.pattern.is_some(), self.content.as_deref()) {
            (true, None) => self.validate_ceiling(),
            // Compiled at load, the way `regex`, `exclude` and `requires_key`
            // already are. Left to adjudication an unparseable expression is
            // skipped on every mediated call, which is a gate that reads as
            // configured in the file and denies nothing — the one failure this
            // kind's whole validation surface exists to close.
            (false, Some(expression)) => {
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!(
                        "rule {}: `content` is not a valid regular expression: {err}",
                        self.id
                    ))
                })?;
                // AND THE COMMAND-ONLY MODIFIERS ARE REFUSED HERE, because the
                // column census permits them on this kind and `adjudicate`
                // evaluates only `content` for a content-keyed row. Left to load
                // they are accepted, ignored on every call, and the row denies
                // writes the configuration appears to narrow — a rule that reads
                // as scoped and is not, which is the same inert-coverage failure
                // the `content` compile above closes one column over.
                //
                self.refuse_command_modifiers("content")?;
                self.validate_ceiling()
            }
            (false, None) => Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" requires `pattern` (a command line), `content` (a \
                 regex over what a write would land), or `tool` (the tool a call names)",
                self.id
            ))),
            // Unreachable: the count above refuses every row carrying more than
            // one keying column, and this is one of those. Kept as an arm rather
            // than wildcarded so a fourth keying column has to come back here and
            // be decided (non-negotiable rule 6's shape, applied to a match).
            (true, Some(_)) => Err(UsageError::raise(format!(
                "rule {}: kind \"shape\" carries both `pattern` and `content`; a row is keyed \
                 on a command or on written content, never on both",
                self.id
            ))),
        }
    }

    /// The three ceiling columns travel together, or none of them does
    /// (CLOUD-925).
    ///
    /// A value inside the row decides the obligation, so the per-kind census
    /// structurally cannot state it — the same reason `receipt`'s
    /// trigger-dependent columns and `policy`'s one-of-three source live here.
    ///
    /// Each partial row is a distinct silent failure and that is why all three
    /// are refused rather than defaulted: a `max` with no `measures` caps
    /// something unnamed, a `measures` with no `max` measures and decides
    /// nothing, and a pair with no `counts` cannot say whether 6000 means tokens
    /// or artifacts — which is a cap off by three orders of magnitude, in the
    /// permissive direction.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the columns a partial row is missing.
    /// The two polarity modifiers may not name the same projection (CLOUD-987).
    ///
    /// A row asking for one key to be both absent and present can never fire, so
    /// it loads, matches nothing, and reads from the file as a narrowing — the
    /// inert-coverage failure this whole validation surface refuses. Naming
    /// *different* projections is legitimate and is what row 3 wants.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the projection asked for twice.
    fn validate_polarity(&self) -> anyhow::Result<()> {
        if let (Some(absent), Some(present)) = (self.when_absent, self.when_present)
            && absent == present
        {
            return Err(UsageError::raise(format!(
                "rule {}: `when_absent` and `when_present` both name the same projection, so \
                 this row can never fire; name different ones or drop one",
                self.id
            )));
        }
        // THE VALUE QUALIFIER TRAVELS WITH ITS PROJECTION (CLOUD-312 row 3), and
        // both directions are refused because each is a different silent failure.
        //
        // A value with no `when_present` names nothing to read it out of, so the
        // row compares against a projection it never took — a column that reads as
        // a narrowing and performs none.
        //
        // **HERE RATHER THAN IN `validate_receipt_columns`**, which is where these
        // two were written first and where they were half-dead: `when_value` is
        // permitted on `shape` as well as `receipt`, and that function returns
        // early for every other kind — so a `shape` row carrying the column with
        // no projection loaded clean and narrowed nothing. Caught in review on
        // #680. Every kind that can carry the column reaches this function.
        if self.when_value.is_some() && self.when_present.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `when_value` qualifies `when_present` — name the projection whose value \
                 this is, or the row compares against nothing and narrows nothing",
                self.id
            )));
        }
        // EMPTY **AFTER FOLDING**, not before, and the difference is the whole
        // check. The comparison drops spaces, underscores and hyphens, so `"___"`
        // and `"---"` fold to nothing and then compare equal to any value made
        // only of separators — a match nobody intended. Testing the raw string for
        // emptiness caught `""` and let the other two through, which is the defect
        // the previous version of this comment described without covering.
        if self
            .when_value
            .as_deref()
            .is_some_and(|value| crate::hook::comparable(value).is_empty())
        {
            return Err(UsageError::raise(format!(
                "rule {}: `when_value` folds to nothing, so it matches any value made only of \
                 spaces, underscores or hyphens; name the value this row is about",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_ceiling(&self) -> anyhow::Result<()> {
        let declared: Vec<&str> = [
            ("measures", self.measures.is_some()),
            ("counts", self.counts.is_some()),
            ("max", self.max.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, present)| present.then_some(name))
        .collect();
        if declared.is_empty() {
            // A rewrite table with no ceiling to serve rewrites nothing, and
            // reads from the file as though it narrowed a count.
            if !self.resolves.is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `resolves` needs a `counts = \"tracked-artifacts\"` ceiling to \
                     serve; on its own it rewrites nothing",
                    self.id
                )));
            }
            return Ok(());
        }
        if declared.len() != 3 {
            return Err(UsageError::raise(format!(
                "rule {}: a per-call ceiling needs `measures`, `counts` and `max` together; \
                 this row carries only {}. A partial ceiling measures something it cannot \
                 decide over, or caps a number whose unit is unstated",
                self.id,
                declared.join(" and ")
            )));
        }
        // TOOL-KEYED ONLY, and narrower than the column census can say.
        //
        // A ceiling is a modifier over a selection, and the only selection it has
        // a consumer for is a tool: CLOUD-312's row 6 is `fanout-guard`, which
        // fires on `Task`. Admitting it on a `pattern` row would ship a
        // combination with no test behind it and no caller asking for it, and
        // `.claude/rules/rust.md`'s reading is that the cheap default is the one
        // direction the mistake is expensive in. Widening this is one line plus
        // the cases that prove it.
        if self.tool.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: a per-call ceiling is keyed on `tool` — the ceiling decides whether \
                 that selection refuses, and a command-keyed one has no consumer yet",
                self.id
            )));
        }
        // A rewrite table only means something to the unit that resolves paths.
        // On a token ceiling it would load, rewrite nothing, and read as a
        // narrowing — the inert-coverage failure this whole surface refuses.
        if !self.resolves.is_empty() && self.counts != Some(CeilingUnit::TrackedArtifacts) {
            return Err(UsageError::raise(format!(
                "rule {}: `resolves` belongs to `counts = \"tracked-artifacts\"`; a token \
                 ceiling resolves no paths",
                self.id
            )));
        }
        // Compiled at load, the way `regex`, `exclude` and `content` are: left to
        // adjudication an unparseable expression is skipped on every call, which
        // makes the ceiling count LESS than it should — the permissive direction,
        // and silent.
        for rewrite in &self.resolves {
            Regex::new(&rewrite.reference).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `resolves.reference` is not a valid regular expression: {err}",
                    self.id
                ))
            })?;
        }
        Ok(())
    }

    /// Refuse the command-only modifiers on a row keyed by `keyed_on`, a column
    /// that names no command line.
    ///
    /// Shared by the `content` and `tool` arms of [`Rule::validate_shape_columns`]
    /// because the argument is identical one column over, and stating it twice is
    /// how the two would drift when a fifth modifier lands. Each of the four
    /// names a COMMAND: `contains` and `require_via` are substring and via-shape
    /// tests over an argv, `requires_key` asks whether the work is keyed before a
    /// command may run, and `base` exists only to tell `requires_key` which
    /// commits to read. A write and a structured call carry no argv for any of
    /// them to read, so left to load they are accepted, ignored on every call,
    /// and the row narrows nothing the configuration appears to narrow.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) naming the first modifier present.
    fn refuse_command_modifiers(&self, keyed_on: &str) -> anyhow::Result<()> {
        for (field, present) in [
            ("contains", self.contains.is_some()),
            ("require_via", self.require_via.is_some()),
            ("requires_key", self.requires_key.is_some()),
            ("base", self.base.is_some()),
        ] {
            if present {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"shape\" keyed on `{keyed_on}` cannot carry `{field}`; \
                     that column narrows a command line, and this row names none",
                    self.id
                )));
            }
        }
        Ok(())
    }

    /// The obligations a receipt row carries that [`RuleKind::permits`] cannot
    /// express (CLOUD-444).
    ///
    /// Which columns a receipt row owes depends on its `trigger`, a value inside
    /// the row — so the per-kind census cannot state it, exactly as it cannot
    /// state a policy row's one-of-three source. Both refusals have the same
    /// reasoning: a column that reads as configured and decides nothing is the
    /// defect this kind was added to close.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) for a command-triggered row with no
    /// `pattern`, for a write-triggered row carrying either command column, and
    /// for an empty `checks` list.
    fn validate_receipt_columns(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Receipt {
            return Ok(());
        }
        // `key = "branch"` was refused from this same spot until the
        // branch-keyed store existed; every refusal here has that one's
        // reasoning — a column that reads as configured and decides nothing is
        // the defect this kind was added to close.
        match self.receipt_trigger() {
            // A command-triggered row selecting on NOTHING matches every
            // mediated call, turning a precondition into a universal gate.
            // `tool` satisfies the obligation as well as `pattern` does
            // (CLOUD-924): both name what the row is about, one by command line
            // and one by the tool a structured call names — and CLOUD-312's rows
            // 1-3 are precisely the second shape.
            ReceiptTrigger::Command if self.pattern.is_none() && self.tool.is_none() => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" with `trigger = \"command\"` (the default) requires `pattern` (the command whose precondition this is) or `tool` (the tool a structured call names)",
                    self.id
                )));
            }
            // Both columns key on one call, and a row carrying both is two
            // selectors where a reader can see one — `validate_shape_columns`'
            // argument, on the kind that shares the columns.
            ReceiptTrigger::Command if self.pattern.is_some() && self.tool.is_some() => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" carries both `pattern` and `tool`; a row is keyed on a command line or on the tool a call names, never on both",
                    self.id
                )));
            }
            // A write carries no command line, so either column would sit there
            // matching nothing while reading as a narrowing. `tool` is NOT
            // refused here: a write tool has a name, and keying a write-triggered
            // row to one is how a precondition narrows from every write to the
            // writes a particular tool makes.
            ReceiptTrigger::Write if self.pattern.is_some() || self.contains.is_some() => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"receipt\" with `trigger = \"write\"` takes neither `pattern` nor `contains` — a write has no command line for either to match",
                    self.id
                )));
            }
            _ => {}
        }
        // THE `named` KEY AND ITS PROJECTION TRAVEL TOGETHER (CLOUD-987), and
        // both halves are refused because each is a different silent failure.
        //
        // A `named` key with no projection has no subject, so it would read one
        // file for every call — `ReceiptKey::Branch` under another name, and the
        // collapse that variant's doc refuses. A projection with some other key
        // is a column that reads as configured and is never consulted.
        match (self.receipt_key(), self.key_from) {
            (ReceiptKey::Named, None) => {
                return Err(UsageError::raise(format!(
                    "rule {}: `key = \"named\"` requires `key_from` — the projection that supplies \
                     the subject. Without one the receipt would be keyed on nothing and read the \
                     same file for every call",
                    self.id
                )));
            }
            (key, Some(_)) if key != ReceiptKey::Named => {
                return Err(UsageError::raise(format!(
                    "rule {}: `key_from` belongs to `key = \"named\"`; a {} receipt takes its \
                     subject from the checkout, not from the call",
                    self.id,
                    match key {
                        ReceiptKey::Head => "head-keyed",
                        ReceiptKey::Branch => "branch-keyed",
                        ReceiptKey::Named => unreachable!("guarded by the arm above"),
                    }
                )));
            }
            _ => {}
        }
        // COMPILED AT LOAD, for the reason `resolves.reference` is and with the
        // failure running the same direction: left to adjudication an unparseable
        // expression is discarded per call, the subject resolves to absent,
        // `verdicts` reads that as could-not-look, and the call is ALLOWED. So a
        // typo silently disables the row it was meant to qualify — the permissive
        // direction, and invisible.
        //
        // This clause is here because the column shipped without it while its own
        // doc comment claimed it: caught in review on #680, and the comment was
        // the worse half, because a stated invariant is what stops the next reader
        // checking.
        if let Some(shape) = self.key_shape.as_deref() {
            Regex::new(shape).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `key_shape` is not a valid regular expression: {err}",
                    self.id
                ))
            })?;
        }
        // A zero bound expires a receipt the instant it is written, so the row
        // refuses every call it selects while reading from the file as though it
        // permitted a fresh one. Same shape as the empty-`checks` refusal below:
        // a column whose value makes the row unsatisfiable is a config error, not
        // a very strict policy.
        if self.max_age == Some(0) {
            return Err(UsageError::raise(format!(
                "rule {}: `max_age = 0` expires every receipt the moment it is written, so no call \
                 can satisfy this row; name the number of seconds a receipt stays good for",
                self.id
            )));
        }
        // Refused for `validate_shape_columns`' reason, on the kind that shares
        // the column: an empty selector would match the empty final segment of
        // every name ending in `__`.
        if self.tool.as_deref().is_some_and(str::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: `tool` is empty; name the tool this row is about",
                self.id
            )));
        }
        // A row naming an empty `checks` list gates its trigger on nothing and
        // allows every call, which reads as coverage from the file.
        if self.checks.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"receipt\" requires at least one entry in `checks`; an empty list gates nothing",
                self.id
            )));
        }
        Ok(())
    }

    /// The three obligations a policy row carries that [`RuleKind::permits`]
    /// cannot express (CLOUD-833, CLOUD-836).
    ///
    /// All three depend on a value INSIDE the row rather than on its kind, which
    /// is what a flat per-kind column list structurally cannot say — the same
    /// reason `forbid`'s `pattern`/`regex` pair and `receipt`'s trigger-dependent
    /// columns live in `validate` rather than in the census.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (→ exit `1`) when the row names no source or more than
    /// one, when a mediated-call row declares `documents`, or when a tree-scoped
    /// row declares none.
    fn validate_policy_source(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Policy {
            return Ok(());
        }
        // A policy row names exactly one source, and `permits` cannot say so —
        // a flat column list has no "one of" (CLOUD-833). Same split
        // `Document`'s `pattern`/`reads` pair already carries, and the same
        // reason: a row with both is a load error rather than a precedence rule
        // nobody can read.
        let sources = [
            self.module.as_deref().map(|_| "module"),
            self.bundle.as_deref().map(|_| "bundle"),
            self.preset.as_deref().map(|_| "preset"),
        ];
        let named: Vec<&str> = sources.into_iter().flatten().collect();
        match named.len() {
            0 => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"policy\" requires one of `module` (one file), \
                         `bundle` (a folder) or `preset` (a vendored bundle); a row naming \
                         none enables no policy and could only ever decide nothing",
                    self.id
                )));
            }
            1 => {}
            _ => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"policy\" takes exactly one of `module`, `bundle` or \
                         `preset`, and this names {}; two sources for one row is a precedence \
                         question nobody should have to answer",
                    self.id,
                    named.join(" and ")
                )));
            }
        }
        // `documents` is what a TREE row is handed. On the mediated call the
        // input is the envelope the boundary already carries, so a `documents`
        // list there is a key that parses and is never read — the shape §8
        // refuses everywhere else in this config.
        if self.scope == RuleScope::MediatedCall && !self.documents.is_empty() {
            return Err(UsageError::raise(format!(
                "rule {}: `documents` is what a `scope = \"tree\"` row hands its bundle; \
                     on the mediated call the input is the call's own facts, so this list \
                     would never be read",
                self.id
            )));
        }
        // `sources` and `lines` are tree columns for the same reason `documents`
        // is, and they were added to `permits` without this — so a mediated-call
        // row could declare either and have it silently never read.
        if self.scope == RuleScope::MediatedCall && !self.sources.is_empty() {
            return Err(UsageError::raise(format!(
                "rule {}: `sources` is what a `scope = \"tree\"` row hands its bundle; \
                 on the mediated call the input is the call's own facts, so this list \
                 would never be read",
                self.id
            )));
        }
        if self.scope == RuleScope::MediatedCall && !self.line_sources.is_empty() {
            return Err(UsageError::raise(format!(
                "rule {}: `line_sources` selects files and a mediated call judges a command, not a tree",
                self.id
            )));
        }
        if self.scope == RuleScope::MediatedCall
            && !(self.uses.is_empty() && self.use_sources.is_empty())
        {
            return Err(UsageError::raise(format!(
                "rule {}: `uses` reads a tree's module graph and a mediated call judges a command, not a tree",
                self.id
            )));
        }
        if self.scope == RuleScope::MediatedCall
            && !(self.invocations.is_empty() && self.invocation_sources.is_empty())
        {
            return Err(UsageError::raise(format!(
                "rule {}: `invocations` parses tree files and a mediated call judges a command, not a tree",
                self.id
            )));
        }
        if self.scope == RuleScope::MediatedCall && !self.lines.is_empty() {
            return Err(UsageError::raise(format!(
                "rule {}: `lines` is what a `scope = \"tree\"` row hands its bundle; \
                 on the mediated call the input is the call's own facts, so this list \
                 would never be read",
                self.id
            )));
        }
        // A MALFORMED SELECTOR IS A CONFIG FAULT, REFUSED HERE. `acquire_declared`
        // and `policy_rule` both discard the error `declared_documents` returns —
        // deliberately, because by then the run is under way — so without this the
        // row would be SILENTLY SKIPPED under `check` while `policy test` (which
        // propagates it) hard-failed. A bad pattern disabling a gate quietly is
        // the exact failure CLOUD-845 and CLOUD-850 exist to close, and adding a
        // column without this check reopened it for the new field.
        for pattern in &self.sources {
            Selector::new(pattern).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `sources` pattern `{pattern}` is not valid: {err}",
                    self.id
                ))
            })?;
        }
        // A DECLARED DOCUMENT THIS BUILD CAN NEVER PARSE IS A CONFIG FAULT, not
        // a verdict (CLOUD-845). It used to be neither: `tree_document` checked
        // the extension BEFORE any I/O and dropped the path into `missing`, so
        // `policy_rule` skipped the whole rule — silently, green, without the
        // file ever being opened. A row declaring a prose, script or
        // configuration-language path this build parses none of therefore looked
        // exactly like a row whose document was absent, and a migrated gate could
        // go dead by declaring the wrong extension just as surely as by naming a
        // field the engine never emits.
        //
        // The split is what §5's exit-1 attaches to: no state of the filesystem
        // makes an unparseable extension parseable, so reporting it as
        // could-not-look would report a permanent authoring error as a transient
        // one. Absent, unreadable and unparsed stay verdicts; this one is caught
        // at load, where a config error belongs.
        for path in &self.documents {
            if crate::facts::Format::for_path(path).is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `documents` names `{path}`, whose extension this build has no \
                     parser for — the row would skip silently rather than decide. Parseable \
                     extensions are TOML, YAML, JSON and JSON5",
                    self.id
                )));
            }
        }
        // THE CONVERSE WAS A REFUSAL AND IS NOT ONE ANY MORE (CLOUD-845). It
        // read: a tree row with no declared documents "is handed an empty tree
        // and decides nothing about the repository", so refusing it was better
        // than letting it read as a configured gate.
        //
        // That reasoning was exactly right while `documents` was the ONLY thing
        // the tree document carried. It is not any more: `tracked` is emitted on
        // every tree evaluation, from the walk the run already did, so a row
        // declaring no documents is handed the checkout's path list and can
        // decide plenty about the repository — `no-docs-tree`-shaped predicates
        // over *which files exist* are precisely that row, and CLOUD-846 counts
        // three of the twenty tree-scoped gates that read no file literals at
        // all.
        //
        // The bound the old refusal protected still holds and is unweakened,
        // because it was a bound on CONTENT: a row still reads no file it did
        // not name. `tracked` is paths, costs nothing per rule, and cannot carry
        // a byte of any file — which is why widening here does not widen what a
        // module may see of a file's insides.
        Ok(())
    }

    /// Validate that the per-kind fields present match the declared `kind`.
    ///
    /// The struct is flat (a `#[serde(flatten)]` enum would silently defeat
    /// `deny_unknown_fields`), so the kind/field agreement that a tagged enum
    /// would give for free is asserted here instead — and a field belonging to
    /// another kind is an *error*, never ignored, so a rule can never half-apply.
    /// Every optional column, paired with whether this rule carries it.
    ///
    /// The census is what keeps [`Rule::validate`] total. The previous version
    /// hand-wrote one match arm per kind naming one required and one forbidden
    /// field, which was correct for two kinds and two columns and goes stale
    /// silently the moment either grows: a new column simply appears in no arm,
    /// so every kind accepts it. Listing the columns once and asking each kind
    /// about all of them makes that failure impossible, and
    /// [`tests::every_optional_rule_field_is_classified_by_every_kind`] fails if
    /// a column is added here without being placed.
    fn columns(&self) -> [(&'static str, bool); 51] {
        [
            // In the census because it is now per-kind, which is what makes
            // "required by every kind but the judge" a fact the existing
            // machinery decides rather than a special case anyone maintains.
            ("severity", self.severity.is_some()),
            ("criteria", self.criteria.is_some()),
            ("tier", self.tier.is_some()),
            ("no_fix_reason", self.no_fix_reason.is_some()),
            ("glob", self.glob.is_some()),
            ("pattern", self.pattern.is_some()),
            ("regex", self.regex.is_some()),
            ("exclude", self.exclude.is_some()),
            ("content", self.content.is_some()),
            ("tool", self.tool.is_some()),
            ("measures", self.measures.is_some()),
            ("counts", self.counts.is_some()),
            ("max", self.max.is_some()),
            ("resolves", !self.resolves.is_empty()),
            ("when_absent", self.when_absent.is_some()),
            ("when_present", self.when_present.is_some()),
            ("when_value", self.when_value.is_some()),
            ("key_from", self.key_from.is_some()),
            ("key_shape", self.key_shape.is_some()),
            ("max_age", self.max_age.is_some()),
            ("check", self.check.is_some()),
            ("fix", self.fix.is_some()),
            ("contains", self.contains.is_some()),
            ("require_via", self.require_via.is_some()),
            ("requires_key", self.requires_key.is_some()),
            ("reason", self.reason.is_some()),
            ("policy_url", self.policy_url.is_some()),
            ("bypass_env", self.bypass_env.is_some()),
            ("verbatim", self.verbatim.is_some()),
            ("identity_key", self.identity_key.is_some()),
            ("direction", self.direction.is_some()),
            ("base", self.base.is_some()),
            ("retires_with", self.retires_with.is_some()),
            ("conserves", self.conserves.is_some()),
            ("admits_with", self.admits_with.is_some()),
            ("format", self.format.is_some()),
            ("node", self.node.is_some()),
            ("derives", self.derives.is_some()),
            ("reads", self.reads.is_some()),
            ("module", self.module.is_some()),
            ("checks", self.checks.is_some()),
            ("key", self.key.is_some()),
            ("trigger", self.trigger.is_some()),
            ("verdict", self.verdict.is_some()),
            ("filters", self.filters.is_some()),
            ("substitutes", self.substitutes.is_some()),
            // `landing` is NOT here, and neither are `git`, `refs` or `ranges`
            // (CLOUD-880, following CLOUD-907). The census drives the per-kind
            // permit/require validation, and a column in it owes an entry in some
            // kind's `permits()` — `every_optional_rule_field_is_classified_by_
            // every_kind` is the gate, and it caught this column the first time it
            // was added here. The four git-family columns are declared reads
            // rather than per-kind capabilities, so they follow their siblings
            // rather than inventing a fifth classification for one of them.
            ("line_sources", !self.line_sources.is_empty()),
            ("invocations", !self.invocations.is_empty()),
            ("invocation_sources", !self.invocation_sources.is_empty()),
            ("uses", !self.uses.is_empty()),
            ("use_sources", !self.use_sources.is_empty()),
        ]
    }

    /// What makes this row fire, with the pinned default applied — the one place
    /// absence is resolved, so no call site reads it a second way.
    #[must_use]
    pub fn receipt_trigger(&self) -> ReceiptTrigger {
        self.trigger.unwrap_or_default()
    }

    /// Which git fact this row's receipts are keyed to, default applied.
    #[must_use]
    pub fn receipt_key(&self) -> ReceiptKey {
        self.key.unwrap_or_default()
    }

    /// The mediator this row requires, if it requires one.
    ///
    /// Absence is "no mediator required", which is every row that predates
    /// CLOUD-271 and is why the column is optional rather than defaulted: a
    /// default would silently narrow every existing shape row.
    #[must_use]
    pub fn require_via(&self) -> Option<RequireVia> {
        self.require_via
    }

    fn validate(&self) -> anyhow::Result<()> {
        let kind = self.kind.as_str();
        // Ahead of every per-kind question, so the rename is what the author
        // reads. Left to the census, a `run` on a command rule would report
        // "requires `check`" — true, and silent about the key already holding
        // the value.
        if self.run.is_some() {
            return Err(UsageError::raise(format!(
                "rule {}: `run` is now `check` (house style §9's check/fix duality); rename the key",
                self.id
            )));
        }
        self.validate_pipeline_tables()?;
        self.validate_sink()?;
        self.validate_exclude_paths()?;
        // The key modifier's own obligations (CLOUD-446). Both here rather than
        // in the column census for the reason stated below it: the census is a
        // per-kind const, and these depend on a value inside the row.
        if let Some(expression) = self.requires_key.as_deref() {
            // Without a range there is nothing to read commit subjects over, so
            // the row would fall back to the branch name alone — a narrowing
            // nobody wrote, arrived at by omission.
            if self.base.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `requires_key` requires `base` — the rev its commit evidence is read since",
                    self.id
                )));
            }
            // Compiled at load, like `regex` and `exclude`: an expression the
            // matcher cannot parse must name its row. Left to adjudication it
            // would fail open on every call, which is a gate that reads as
            // present and denies nothing.
            Regex::new(expression).map_err(|err| {
                UsageError::raise(format!(
                    "rule {}: `requires_key` is not valid: {err}",
                    self.id
                ))
            })?;
        }
        self.validate_admission_columns()?;
        self.validate_conserves()?;
        // Extracted for `validate_policy_source`'s reason, and it is the same
        // class of obligation: which columns a receipt row owes depends on a
        // value inside it, which the per-kind census cannot say.
        self.validate_shape_columns()?;
        self.validate_polarity()?;
        self.validate_receipt_columns()?;
        // Extracted rather than inlined, because `validate` is at its line ceiling
        // and a per-kind block is what it should shed first: the census above is
        // the general mechanism, and these are the three things a flat column
        // list structurally cannot say about one kind.
        self.validate_policy_source()?;
        for column in self.kind.requires() {
            let present = self
                .columns()
                .into_iter()
                .any(|(name, present)| name == *column && present);
            if !present {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"{kind}\" requires `{column}`",
                    self.id
                )));
            }
        }
        for (name, present) in self.columns() {
            if present && !self.kind.permits().contains(&name) {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` is not valid for kind \"{kind}\"",
                    self.id
                )));
            }
        }
        // Scope routes a rule to the surface that evaluates it, so a pairing the
        // engine cannot honour must be refused rather than accepted and never
        // run. An inert rule reads as coverage.
        if !self.kind.scopes().contains(&self.scope) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"{kind}\" does not evaluate over scope \"{}\"",
                self.id,
                self.scope.as_str()
            )));
        }
        if self.glob.as_deref().is_some_and(str::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: `glob` must not be empty",
                self.id
            )));
        }
        // Compiled at load, like `regex` and `exclude` above it (CLOUD-214): a
        // pattern the matcher cannot parse must name the row that carries it,
        // rather than becoming a rule that selects nothing and reads as a gate
        // that found nothing wrong.
        if let Some(glob) = self.glob.as_deref() {
            Selector::new(glob)
                .map_err(|err| UsageError::raise(format!("rule {}: {err}", self.id)))?;
        }
        self.validate_command_pattern()?;
        self.validate_forbid_predicate()?;
        self.validate_document_predicate()?;
        self.validate_remediation()
    }

    /// The pipeline row's own tables (CLOUD-443).
    ///
    /// Refused for the reason everything in [`Rule::validate`] is refused: a
    /// list that narrows nothing, or a row whose conditions contradict, loads
    /// clean and decides nothing. Extracted rather than inlined so `validate`
    /// stays under the line limit as columns accumulate — the census below it
    /// is the part that must stay whole.
    fn validate_pipeline_tables(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Pipeline {
            return Ok(());
        }
        for entry in self.verdict.iter().flatten() {
            entry.validate(&self.id)?;
        }
        if self.verdict.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `verdict` entry; with none it judges no command",
                self.id
            )));
        }
        if self.filters.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `filters` entry; with none it cannot recognise the substitution it refuses",
                self.id
            )));
        }
        if self.substitutes.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" requires at least one `substitutes` entry; with none it recognises no substitution",
                self.id
            )));
        }
        // ONE of the two families, whole (CLOUD-864). The per-kind required
        // table cannot express this — it is a disjunction over sibling columns,
        // and that table is a flat list — so the obligation lands here, which is
        // the same place `Receipt`'s conditional `pattern` requirement lives.
        //
        // Stated as a disjunction rather than as "at least one column set" on
        // purpose: a row carrying `verdict` and no `filters` recognises a
        // verdict-bearing command and nothing that could discard it, which
        // matches and decides nothing. Half a family is the inert row, not a
        // narrower gate.
        let discard_family = self.verdict.is_some() && self.filters.is_some();
        let substitution_family = self.substitutes.is_some();
        if !discard_family && !substitution_family {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"pipeline\" needs either `verdict` AND `filters` (the discard family) or `substitutes` (the substitution family); with neither it matches nothing",
                self.id
            )));
        }
        Ok(())
    }

    /// Refuse a `pattern` the command matcher cannot honour (CLOUD-401).
    ///
    /// The empty-operand fix closed one row that loaded into silence; this
    /// closes the **class**. `hook::matching_shape_rows` and
    /// `hook::matching_receipt_rows` compare a pattern against a command that
    /// has already been normalised two ways — `effective_program` has stepped
    /// past env assignments and look-through wrappers, and the operand words
    /// have had every flag dropped — so a pattern naming what that
    /// normalisation removes is a row that can never fire. It loads clean,
    /// gates nothing, and reads as coverage, which is the exact defect
    /// [`validate`]'s doc comment is written against.
    ///
    /// Refused here rather than in the per-kind column census because the
    /// census is a const list of column NAMES: this depends on the value inside
    /// the column. Both surfaces that key on a command line are covered — a
    /// `shape` row's ban and a `receipt` row's trigger read the same pattern
    /// through the same matcher (`Rule::trigger`), so a rule inert on one is
    /// inert on the other.
    ///
    /// A program-only pattern is **valid**, and that is the point: it is the
    /// reading `Rule::pattern`'s doc comment already invites, and the one this
    /// validator must not take back.
    fn validate_command_pattern(&self) -> anyhow::Result<()> {
        // The kinds that key on a command line. A `write`-triggered receipt row
        // is refused a `pattern` outright above, so it never reaches here.
        let keys_on_a_command = self.kind == RuleKind::Shape
            || (self.kind == RuleKind::Receipt
                && self.receipt_trigger() == ReceiptTrigger::Command);
        if !keys_on_a_command {
            return Ok(());
        }
        if self.pattern.is_none() {
            return Ok(());
        }
        // `trigger()` yields nothing for a pattern with no word in it, and a
        // row it cannot read is a row the matcher skips.
        let Some((program, wanted)) = self.trigger() else {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` names no program; a pattern of only whitespace matches no command",
                self.id
            )));
        };
        if crate::hook::is_lookthrough_wrapper(program) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` names the wrapper `{program}`, which the matcher looks THROUGH to judge the program it wraps; name that program instead",
                self.id
            )));
        }
        if crate::hook::is_env_assignment(program) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` starts with the environment assignment `{program}`, which the matcher steps past; name the program instead",
                self.id
            )));
        }
        if let Some(flag) = wanted.iter().find(|word| word.starts_with('-')) {
            return Err(UsageError::raise(format!(
                "rule {}: `pattern` requires the flag `{flag}`, and the matcher compares operand words with flags already dropped; use `contains` for a flag",
                self.id
            )));
        }
        Ok(())
    }

    /// `fix` and `no_fix_reason` are alternatives, never both (CLOUD-81).
    ///
    /// Not expressible in [`RuleKind::requires`] for the same reason
    /// `pattern`-xor-`regex` is not: that list is columns that must *all* be
    /// present. [`RuleKind::permits`] carries the other half — a `shape` row is
    /// refused both columns there, because it is adjudicated per mediated call
    /// and never reaches the store, the same reasoning that already denies it
    /// `identity_key`.
    ///
    /// **Carrying neither is refused at ingest, not here** (§5). A rule with no
    /// remediation still loads and still gates: `check` and `enforce` render its
    /// findings and exit on them exactly as before. What it cannot do is put one
    /// in the store, because a *stored* finding is one something later has to
    /// close. Refusing at load would instead make an un-actionable rule
    /// un-runnable, which turns a store-shaped requirement into a gate outage
    /// for every consumer whose config predates this field.
    /// A declared sink must be on a kind that can actually request one
    /// (CLOUD-851).
    ///
    /// The request set is built from a [`Scan`], which only the TREE surface
    /// produces: `adjudicate` returns a decision about one call and has no
    /// findings vector to digest. So a `produces` on a `mediated_call`-only kind
    /// would parse, read as configured, and write nothing on every call — the
    /// inert-coverage failure `validate_shape_columns` and
    /// `validate_receipt_columns` each close one column over, and the same one
    /// `Rule::fix`'s refusal states rather than pretends about.
    ///
    /// Refused at LOAD rather than skipped at run time, because a skip is
    /// invisible: the run reports its findings and the record simply is not
    /// there, which looks exactly like a run that had nothing to produce.
    fn validate_sink(&self) -> anyhow::Result<()> {
        if self.produces.is_none() {
            return Ok(());
        }
        // THE ROW'S OWN SCOPE, not the kind's CAPABILITY, and the difference is a
        // real hole the first version left. `RuleKind::Policy` scopes to BOTH
        // surfaces, so `kind.scopes().contains(&Tree)` is true for a policy row
        // configured `scope = "mediated_call"` — it passed validation, the tree
        // runner skipped it as another surface's business, `requested_sinks`
        // excluded it as not-evaluated, and the declared record was never
        // written. Exactly the inert-coverage failure this function exists to
        // refuse, reached through the one kind that spans both scopes.
        if self.scope != RuleScope::Tree {
            return Err(UsageError::raise(format!(
                "rule {}: `produces` on a `{}`-scoped row, which is decided by `adjudicate` \
                 rather than by a findings scan; there is nothing for a sink to summarise \
                 and the record would never be written",
                self.id,
                self.scope.as_str()
            )));
        }
        Ok(())
    }

    /// The value-dependent obligations on the two ratchet admission columns,
    /// [`Rule::retires_with`] and [`Rule::admits_with`].
    ///
    /// Extracted from [`Rule::validate`] for `validate_conserves`'s reason — the
    /// per-kind census sees a present column and nothing about what is inside it
    /// — and the two are here together because they are the same three refusals
    /// mirrored, so a reader comparing them should not have to hold two screens.
    ///
    /// Each column admits ONE direction of change, and all three refusals close
    /// the same failure: a column that reads as a configured permission and
    /// decides nothing.
    ///
    /// * **`base` must be there.** Each column asks a question about another
    ///   tree — was this subject alive, was this file absent — and there is no
    ///   such tree without it. The ratchet kind already requires `base`, but the
    ///   obligation is on the VALUE, so a future kind taking either column
    ///   inherits the refusal rather than the omission.
    /// * **The token must not be blank.** An empty prefix matches at the start of
    ///   every line, so every file would "declare" whatever its first line
    ///   happens to say. That is `requires_key`'s compile-at-load failure in the
    ///   one form these columns can take it.
    /// * **The direction must be the one the column governs.** This is the blank
    ///   token's failure reached by the other axis, and it is the sharper of the
    ///   two because the column is not merely inert on the wrong row — it
    ///   switches the row OFF. `retires_with`'s block inspects only the files
    ///   whose count FELL, so on a `non_increasing` row it collects no subject,
    ///   leaves the blocker set empty, and the evaluator returns clean over every
    ///   increase. `undeclared_growth` is the mirror: it inspects only the files
    ///   that ROSE, so on a `non_decreasing` row every decrease is admitted in
    ///   silence. Found by review of #694 on `admits_with`; the sibling had
    ///   carried it latent since CLOUD-807.
    fn validate_admission_columns(&self) -> anyhow::Result<()> {
        for (name, token, wanted, wanted_name, base_reason) in [
            (
                "retires_with",
                self.retires_with.as_deref(),
                Direction::NonDecreasing,
                "DECREASE",
                "the rev a subject must have been alive at",
            ),
            (
                "admits_with",
                self.admits_with.as_deref(),
                Direction::NonIncreasing,
                "INCREASE",
                "an increase is only decidable against the tree a file was absent from",
            ),
        ] {
            let Some(token) = token else {
                continue;
            };
            if self.base.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` requires `base` — {base_reason}",
                    self.id
                )));
            }
            if token.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` cannot be blank — it is the line prefix a declaration is read after, and an empty one matches every line",
                    self.id
                )));
            }
            if self.direction != Some(wanted) {
                return Err(UsageError::raise(format!(
                    "rule {}: `{name}` requires `direction = \"{}\"` — it admits a {wanted_name}, and on a row that refuses the other direction it switches the row off instead of refining it",
                    self.id,
                    wanted.as_str(),
                )));
            }
        }
        Ok(())
    }

    /// Every token in a [`Conserves`] decides something, so a blank one is a
    /// configured admission (CLOUD-908).
    ///
    /// The obligations, and each closes a way the mapping could read as present
    /// and decide nothing:
    ///
    /// * **`retires_with` must be there.** This column refines that admission. A
    ///   ratchet that never permits a decrease has no deletion to map, so the
    ///   mapping would be inert — and inert coverage is what the whole row is
    ///   about.
    /// * **No token may be blank.** An empty prefix matches at the start of every
    ///   line, so every line would "declare" a case or claim one. The same
    ///   reading `retires_with` takes over its own token.
    /// * **The three arms must be distinct.** Two arms spelled alike make "exactly
    ///   one arm" undecidable: one line would claim a case twice, and the refusal
    ///   for a double claim would fire on every correct mapping instead.
    /// * **`declared_in` must compile.** A glob `globset` cannot parse selects
    ///   nothing, and a mapping read over nothing admits every deletion.
    fn validate_conserves(&self) -> anyhow::Result<()> {
        let Some(conserves) = self.conserves.as_ref() else {
            return Ok(());
        };
        if self.retires_with.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `conserves` requires `retires_with` — it obliges a mapping INSIDE that column's admission, and a ratchet that admits no decrease has no deletion to map",
                self.id
            )));
        }
        for (name, token) in [
            ("case", &conserves.case),
            ("close", &conserves.close),
            ("carried", &conserves.carried),
            ("subsumed", &conserves.subsumed),
            ("changed", &conserves.changed),
            ("declared_in", &conserves.declared_in),
        ] {
            if token.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves.{name}` cannot be blank — every token here decides something, and an empty one matches every line",
                    self.id
                )));
            }
        }
        // Blank is refused for the optional arm too, where it is DECLARED: an
        // empty token matches every line, so `withdrawn = ""` would claim every
        // case in the ledger. Absent and blank are different answers, and only the
        // first one means "this row has three arms".
        if let Some(token) = conserves.withdrawn.as_deref()
            && token.trim().is_empty()
        {
            return Err(UsageError::raise(format!(
                "rule {}: `conserves.withdrawn` is declared but blank — an empty token matches every line, which would claim every case. Remove the key to keep three arms.",
                self.id
            )));
        }
        let arms: Vec<&String> = [
            Some(&conserves.carried),
            Some(&conserves.subsumed),
            Some(&conserves.changed),
            conserves.withdrawn.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        for (index, arm) in arms.iter().enumerate() {
            if arms[index + 1..].contains(arm) {
                return Err(UsageError::raise(format!(
                    "rule {}: `conserves` spells two arms alike, so \"exactly one arm\" cannot be decided — one line would claim a case twice",
                    self.id
                )));
            }
        }
        Selector::new(&conserves.declared_in)?;
        Ok(())
    }

    /// `exclude_paths` has to be honoured by everything that reads the rule's
    /// selection, and two shapes cannot honour it (CLOUD-883).
    ///
    /// **No `glob`.** The column subtracts from an include set, so with nothing to
    /// subtract from it narrows nothing while reading as a narrowing — the
    /// inert-coverage failure `validate_sink` and `validate_shape_columns` each
    /// close one column over.
    ///
    /// **A ratchet.** Its verdict compares the working tree against a count taken
    /// at the base rev by `git::count_at_rev`, which globs on its own and knows
    /// nothing of this column. The two sides would select different sets, and the
    /// direction is the dangerous one CLOUD-328 measured: a working side narrowed
    /// below a base that counted everything sits permanently under its baseline,
    /// so no addition could ever push it over and **the gate cannot fail**.
    /// Refused rather than half-implemented, because a ratchet that cannot fail
    /// reads exactly like one that is passing.
    fn validate_exclude_paths(&self) -> anyhow::Result<()> {
        if self.exclude_paths.is_empty() {
            return Ok(());
        }
        if self.glob.is_none() {
            return Err(UsageError::raise(format!(
                "rule {}: `exclude_paths` subtracts from `glob`, and this row declares none — \
                 it would narrow nothing while reading as a narrowing",
                self.id
            )));
        }
        if self.kind == RuleKind::Ratchet {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"ratchet\" counts the base rev with its own glob, which cannot \
                 read `exclude_paths`; the two sides would select different sets and the \
                 working side could never rise above the base, so the gate could not fail",
                self.id
            )));
        }
        Ok(())
    }

    fn validate_remediation(&self) -> anyhow::Result<()> {
        if self.fix.is_some() && self.no_fix_reason.is_some() {
            return Err(UsageError::raise(format!(
                "rule {}: `fix` and `no_fix_reason` are alternatives; a row carries exactly one, \
                 never both",
                self.id
            )));
        }
        Ok(())
    }

    /// The predicate that settles this rule's findings (CLOUD-81).
    ///
    /// Derived rather than declared, and that is the whole design. A
    /// [`RuleKind::Command`] rule already carries an exit-code predicate — its
    /// [`Rule::check`] column, which CLOUD-215 named for exactly this role — so
    /// reusing it keeps one authority for what that rule executes (house style
    /// §9's check/fix duality). Every other storable kind is re-evaluated by the
    /// engine, whose own verdict is the exit code; demanding an argv there would
    /// mean writing "the banned literal is *gone*" as a command, which needs a
    /// shell negation this engine deliberately does not offer.
    ///
    /// Named `settling_check` rather than `check` because that spelling is the
    /// column itself: this answers what settles a *finding*, which for two of
    /// the three storable kinds is not a command at all.
    ///
    /// `None` for [`RuleKind::Shape`], which never reaches the store.
    #[must_use]
    pub fn settling_check(&self) -> Option<Check> {
        match self.kind {
            RuleKind::Command => Some(Check::Argv(
                self.check
                    .as_deref()
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(ToOwned::to_owned)
                    .collect(),
            )),
            // Re-running the gate is what settles all three, and `Document`
            // joins them: re-reading the file and re-walking the node is exactly
            // how a document finding is re-decided, and there is no argv to put
            // on the record because the parse happens in-process.
            // For `Secrets` the
            // important half is what this is NOT: an `Argv` here would put the
            // scanner's invocation on the record, and the whole design is that
            // nothing carrying a matched byte leaves the adapter. It is also the
            // honest answer — unlike a judge's verdict, the engine can re-decide
            // a secret finding by scanning again.
            RuleKind::Forbid | RuleKind::Ratchet | RuleKind::Secrets | RuleKind::Document => {
                Some(Check::Reevaluate)
            }
            // None of the four reaches the store: each is adjudicated per
            // mediated call and produces a decision, not a finding. `Policy`
            // belongs here rather than beside `Judge` — its verdict is a real
            // deny that the engine could re-decide, it simply has no stored
            // finding to re-decide, which is `Shape`'s situation exactly.
            RuleKind::Shape | RuleKind::Receipt | RuleKind::Pipeline | RuleKind::Policy => None,
            // Neither of the other two answers is true for a judge.
            // `Reevaluate` would claim the engine can re-decide the finding, and
            // it cannot — a model reached that verdict and only the model can
            // revisit it. `None` means "never reaches the store", which is the
            // shape rule's situation and not this one. So: re-run the judge,
            // which is exactly what re-decides it.
            //
            // The argv is resolved by the caller and threaded in through
            // [`Rule::settling_argv`], because it lives in the `[judge]` table
            // rather than on the row — this method sees only the row.
            RuleKind::Judge => Some(Check::Argv(Vec::new())),
        }
    }

    /// [`Rule::settling_check`] for a judge row, given the resolved command.
    ///
    /// Split from the method above because the judge's argv is not on the row:
    /// `[judge].run` is a table-level key, so the row alone cannot answer, and
    /// returning a placeholder that a caller *might* fill would be the kind of
    /// half-built value that reads as complete. This one takes what it needs.
    #[must_use]
    pub fn settling_argv(&self, argv: &[String]) -> Option<Check> {
        match self.kind {
            RuleKind::Judge => Some(Check::Argv(argv.to_vec())),
            _ => self.settling_check(),
        }
    }

    /// The fix, or the stated reason there is none.
    ///
    /// Reads the existing [`Rule::fix`] column rather than declaring a second
    /// spelling of it. CLOUD-215 reserved `fix` and has `run_all` refuse a rule
    /// that declares one, because serialised fix execution is not a capability
    /// this build has — but *recording* a repair on a finding is not running it,
    /// so the two coexist: the column says what would fix this, and nothing here
    /// executes it.
    ///
    /// `None` for a row carrying neither, which is what
    /// [`crate::findings::record`] refuses at ingest.
    #[must_use]
    pub fn remediation(&self) -> Option<Remediation> {
        if let Some(fix) = &self.fix {
            return Some(Remediation::Fix(
                fix.split_whitespace().map(ToOwned::to_owned).collect(),
            ));
        }
        self.no_fix_reason.clone().map(Remediation::NoFix)
    }

    /// The `pattern`-xor-`regex` rule, and the regexes' own well-formedness.
    ///
    /// Not expressible in [`RuleKind::requires`], which is a flat list of
    /// columns that must all be present — "exactly one of these two" needs a
    /// check of its own (CLOUD-283). Refusing a row that carries both is what
    /// keeps this a *choice* rather than a precedence rule a reader has to know.
    ///
    /// Each expression is compiled here, at load, so a bad one is a config error
    /// naming the row rather than a failure part-way through a scan.
    /// A document row's predicate: exactly one of `pattern` or `reads`.
    ///
    /// The same "one of" the forbid predicate carries and for the same reason —
    /// a flat column list cannot express it, so it lives here where the pair is
    /// in scope. A row with neither loads, matches a document, and asks nothing
    /// of it; a row with both declares two answers to one comparison.
    fn validate_document_predicate(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Document {
            return Ok(());
        }
        match (self.pattern.is_some(), self.reads.is_some()) {
            (true, true) => Err(UsageError::raise(format!(
                "rule {}: `pattern` and `reads` are alternatives; a row carries exactly one, \
                 never both",
                self.id
            ))),
            (false, false) => Err(UsageError::raise(format!(
                "rule {}: kind \"document\" requires `pattern` (a literal) or `reads` (another \
                 rule's derived value)",
                self.id
            ))),
            _ => Ok(()),
        }
    }

    fn validate_forbid_predicate(&self) -> anyhow::Result<()> {
        if self.kind != RuleKind::Forbid {
            return Ok(());
        }
        match (self.pattern.is_some(), self.regex.is_some()) {
            (true, true) => {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` and `regex` are alternatives; a row carries exactly one, \
                     never both",
                    self.id
                )));
            }
            (false, false) => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"forbid\" requires `pattern` (a literal) or `regex` (a shape)",
                    self.id
                )));
            }
            _ => {}
        }
        for (column, expression) in [("regex", &self.regex), ("exclude", &self.exclude)] {
            if let Some(expression) = expression {
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!("rule {}: `{column}` is not valid: {err}", self.id))
                })?;
            }
        }
        Ok(())
    }

    /// Whether this row's [`Rule::tool`] selector names `raw_tool` (CLOUD-924).
    ///
    /// `false` for a row carrying no selector, so a caller can ask this of any
    /// row without first testing the column — the same totality every other
    /// modifier accessor here has.
    ///
    /// The match is the whole name **or** the whole final `__`-delimited segment
    /// of it, never a bare suffix. `Rule::tool`'s doc carries the argument; the
    /// short form is that a bare suffix makes `Edit` select `NotebookEdit`,
    /// which widens a row onto a tool nobody named, while the delimiter is what
    /// lets `save_issue` survive the host rotating the server label it minted
    /// (CLOUD-665, CLOUD-684).
    ///
    /// An empty selector is refused at load, so it cannot reach here and match
    /// the empty segment of a name ending in `__`.
    #[must_use]
    pub fn selects_tool(&self, raw_tool: &str) -> bool {
        let Some(selector) = self.tool.as_deref() else {
            return false;
        };
        selects_tool_name(selector, raw_tool)
    }

    /// The banned command shape: the effective program, then the adjacent words
    /// that must follow it.
    ///
    /// `None` for any kind but [`RuleKind::Shape`], and for a `pattern` with no
    /// program token.
    #[must_use]
    pub fn shape(&self) -> Option<(&str, Vec<&str>)> {
        if self.kind != RuleKind::Shape {
            return None;
        }
        self.trigger()
    }

    /// The command shape this row keys on, for **any** kind that keys on one.
    ///
    /// Split out of [`Rule::shape`] because two kinds now match a command line
    /// and they mean different things by it: `shape` names a command that is
    /// banned, `receipt` names one that is gated on a precondition. `shape()`
    /// keeps its kind check so its existing callers cannot be handed a receipt
    /// row by accident — the failure that costs nothing to prevent here and is
    /// invisible when it happens, since an unmatched rule simply allows.
    #[must_use]
    pub fn trigger(&self) -> Option<(&str, Vec<&str>)> {
        let mut words = self.pattern.as_deref()?.split_whitespace();
        let program = words.next()?;
        Some((program, words.collect()))
    }
}

/// Validate a whole `[[rule]]` table, and refuse a duplicated id.
///
/// Called at **load** rather than only by a runner (`config::parse_ungated`),
/// because there are now two runners: the tree engine and `batten hook`. A rule
/// validated only by the surface that happens to run it is a rule the other
/// surface accepts malformed — and for the hook that means a policy row that
/// loads, matches nothing, and reads as coverage.
///
/// Two rows for one id is a policy question with two answers, and silently
/// taking the first is how a tightening edit gets lost behind a stale row. Same
/// reasoning, and the same shape, as [`crate::verbs::validate`].
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated rule.
pub fn validate(rules: &[Rule]) -> anyhow::Result<()> {
    validate_rows(rules)?;
    validate_composition(rules, None)
}

/// Everything [`validate`] checks except the cross-row composition — split out so
/// [`validate_in`] can run the composition half with a locator instead of
/// running it twice and reporting the unlocated message first.
fn validate_rows(rules: &[Rule]) -> anyhow::Result<()> {
    for (index, rule) in rules.iter().enumerate() {
        rule.validate()?;
        if rules[..index].iter().any(|prior| prior.id == rule.id) {
            return Err(UsageError::raise(format!(
                "rule {}: declared twice; a rule has one definition",
                rule.id
            )));
        }
        // One check name, one keying (CLOUD-444). The boundary resolves each
        // required name to a single verdict, so two rows disagreeing about what
        // invalidates the same receipt would silently resolve it one row's way —
        // a branch-keyed claim expiring per commit, or a HEAD-keyed verification
        // outliving the bytes it validated. Both are false greens, and the
        // per-row `validate` cannot see the collision, so it is refused here.
        for prior in &rules[..index] {
            let (Some(mine), Some(theirs)) = (rule.checks.as_ref(), prior.checks.as_ref()) else {
                continue;
            };
            if rule.receipt_key() == prior.receipt_key() {
                continue;
            }
            if let Some(shared) = mine.iter().find(|check| theirs.contains(check)) {
                return Err(UsageError::raise(format!(
                    "rules {} and {}: both require the receipt `{shared}` under different `key` values; one check name has one keying",
                    prior.id, rule.id
                )));
            }
        }
    }
    Ok(())
}

/// [`validate`], with the config text in hand so a composition refusal can point
/// at a **line** rather than only at a rule id (CLOUD-773's §5).
///
/// The located form is what the two real loaders call; the bare [`validate`]
/// stays for callers holding a rule table and no file — the defaults, and the
/// runner's own defence in depth. One implementation, an optional locator, so
/// the two can never disagree about what is refused.
///
/// # Errors
///
/// As [`validate`].
pub fn validate_in(rules: &[Rule], text: &str, source: &str) -> anyhow::Result<()> {
    validate_rows(rules)?;
    validate_composition(rules, Some(Located { text, source }))
}

/// The config text and its path, for turning a rule id into `path:line`.
#[derive(Clone, Copy)]
struct Located<'a> {
    text: &'a str,
    source: &'a str,
}

impl Located<'_> {
    /// `<source>:<line>` for the row declaring `id`, or `<source>` where the
    /// declaration cannot be located.
    ///
    /// A literal search for the `id` key rather than a second TOML parse: the
    /// pointer is a courtesy on an error path, and a parser here would be a
    /// second reader of the file the loader already read.
    fn pointer(self, id: &str) -> String {
        let needle = format!("id = \"{id}\"");
        for (index, line) in self.text.lines().enumerate() {
            if line.trim_start().starts_with(&needle) {
                return format!("{}:{}", self.source, index + 1);
            }
        }
        self.source.to_owned()
    }
}

/// Where a rule id renders when there is no config text to locate it in.
fn pointer_for(at: Option<Located<'_>>, id: &str) -> String {
    match at {
        Some(located) => located.pointer(id),
        None => format!("rule {id}"),
    }
}

/// Refuse a composition a run could not honour, **at load and never later**.
///
/// Four refusals, and the ordering matters only in that each is checked over the
/// whole table rather than per row — which is why this cannot live in
/// [`Rule::validate`]:
///
/// 1. **Two rows deriving one name.** "Which one did I read" is not a question a
///    reviewer should have to answer, and the answer would be positional.
/// 2. **A reference to a name nothing derives.** The row loads, matches a
///    document, and compares against a value that will never exist — the
///    present-and-inert gate this file is written against.
/// 3. **A cycle.** Once B can reference A, A can reference B. CLOUD-647 measured
///    that the obvious candidate engine reports cycles at *evaluation*, which on
///    the mediated path is the worst possible time and the wrong exit class.
/// 4. **A reference that changes the reading rule's class.** CLOUD-757 settled
///    composition as the **meet on both axes**: a derived fact is at most as
///    cheap as its most expensive input and at most as wide as its narrowest.
///    So if meeting the derivation's class with the reader's own moves it, the
///    reader is not the rule it declares itself to be — a `read`-class row would
///    silently inherit an `effect`-class dependency, or a hook-surface row would
///    answer from a fact never resolvable there.
///
/// Pointer-only (rule 4): a `path:line` and a rule id, never a derived value.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for each of the four. A config declaring a
/// composition the engine cannot honour is the config-or-usage class, never a
/// policy verdict about the repository.
fn validate_composition(rules: &[Rule], at: Option<Located<'_>>) -> anyhow::Result<()> {
    let mut derived: BTreeMap<&str, &Rule> = BTreeMap::new();
    for rule in rules {
        let Some(name) = rule.derives.as_deref() else {
            continue;
        };
        if let Some(prior) = derived.insert(name, rule) {
            return Err(UsageError::raise(format!(
                "{} and {}: both derive `{name}`; a derived value has one definition",
                pointer_for(at, &prior.id),
                pointer_for(at, &rule.id)
            )));
        }
    }
    for rule in rules {
        let Some(name) = rule.reads.as_deref() else {
            continue;
        };
        let Some(producer) = derived.get(name).copied() else {
            return Err(UsageError::raise(format!(
                "{}: reads `{name}`, which no rule derives",
                pointer_for(at, &rule.id)
            )));
        };
        // The meet on BOTH axes. Equality with the reader's own class is the
        // predicate rather than a comparison per axis, because "did this
        // reference move me" is one question and asking it twice invites the
        // two halves to drift.
        //
        // EACH SIDE IS JUDGED AT ITS OWN SCOPE (CLOUD-833). `fact_class` used to
        // key on the kind alone; a `policy` row is `Free` x `Hook` on the
        // mediated call and `Read` x `Check` on the tree, so asking for one
        // rule's class while holding the other's scope would compare two things
        // neither row declares. `rule.scope` and `producer.scope` are the values
        // each row actually carries, and passing anything else here is how this
        // check would start answering a question nobody asked.
        let mine = rule.kind.fact_class(rule.scope);
        let theirs = producer.kind.fact_class(producer.scope);
        if mine.meet(theirs) != mine {
            return Err(UsageError::raise(format!(
                "{}: reads `{name}`, derived by {} at cost `{}` on surface `{}`, which a rule at \
                 cost `{}` on surface `{}` cannot carry — composition takes the meet on both axes",
                pointer_for(at, &rule.id),
                pointer_for(at, &producer.id),
                theirs.cost.as_str(),
                theirs.surface.as_str(),
                mine.cost.as_str(),
                mine.surface.as_str()
            )));
        }
    }
    // Depth-first over the reference edges. The graph is tiny — one edge per row
    // that reads — so the walk is the whole algorithm and there is nothing to
    // memoise that would pay for itself.
    for rule in rules {
        if rule.reads.is_none() {
            continue;
        }
        let mut seen: Vec<&str> = vec![rule.id.as_str()];
        let mut here = rule;
        while let Some(name) = here.reads.as_deref() {
            let Some(next) = derived.get(name).copied() else {
                break;
            };
            if seen.contains(&next.id.as_str()) {
                return Err(UsageError::raise(format!(
                    "{} and {}: their `reads`/`derives` references form a cycle, so neither \
                     value can be resolved; refused at load, where a cycle costs a config error \
                     rather than a decision",
                    pointer_for(at, &here.id),
                    pointer_for(at, &next.id)
                )));
            }
            seen.push(next.id.as_str());
            here = next;
        }
    }
    Ok(())
}

/// A single policy finding: the rule that fired and where, as a pointer only.
///
/// A finding never carries the matched bytes (non-negotiable rule 4) — only the
/// rule id and a `path:line` location the caller can open.
///
/// The `severity` is the producing rule's — the value the exit contract
/// consumes: a `deny` finding fails the run, a `warn` finding reports without
/// failing it (CLOUD-49 promotes it). It rides along for that decision only; it
/// is **never** an identity input (see [`crate::identity`] — re-rating a
/// finding must not re-mint it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The [`Rule::id`] that produced this finding.
    pub rule: String,
    /// The producing rule's [`Rule::severity`], for the exit-contract decision.
    pub severity: RuleSeverity,
    /// Where the violation is. A file-scoped kind reports the repo-relative
    /// path (`/`-separated); a rule-scoped kind — a command whose exit code
    /// condemns a whole batch rather than one line — reports the rule's `glob`,
    /// which is the tightest honest pointer available for it.
    pub path: String,
    /// The 1-based line number of the offending line, when the kind locates one.
    /// `None` for a rule-scoped finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// The finding's identity, minted **engine-side** (CLOUD-164).
    ///
    /// Position is deliberately not an input: `line` moves when a neighbour is
    /// inserted and this does not, which is what lets a store recognise the same
    /// defect across an edit. Before this field existed the churn pack read the
    /// matched line and hashed it test-side, which could pin the identity
    /// *function* but never the extractor — there was none. This is the
    /// extractor, and deleting that test-side join is how the pack now proves it
    /// picks the right span.
    pub identity: crate::identity::StoredIdentity,
    /// The predicate that settles this finding, captured from the producing rule
    /// (CLOUD-81). Carried on the finding rather than looked up later, so the
    /// store never has to reach back into a config it cannot see.
    pub check: Check,
    /// The fix, or the stated reason there is none. `None` only for a rule
    /// [`Rule::validate`] would have refused; [`crate::findings::record`]
    /// refuses to store one.
    pub remediation: Option<Remediation>,
}

/// One run's findings, plus which rules never actually looked (CLOUD-81).
///
/// The second half is what keeps the store fail-closed. A rule that did not
/// evaluate reports no findings, and a consumer reading that silence as "clean"
/// resolves every finding the rule covers — the fail-open this type exists to
/// make inexpressible. Absence from `not_evaluated` means the rule ran, so a
/// caller cannot forget to ask.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    /// Everything the run found, sorted for byte-stability.
    pub findings: Vec<Finding>,
    /// The rules that did **not** run, by id, and why. Empty when every
    /// configured rule evaluated.
    pub not_evaluated: BTreeMap<String, NotObserved>,
    /// What the run asks the boundary to WRITE (CLOUD-851), sorted.
    ///
    /// A request, never a write: this field is the whole of "the decision
    /// requests an effect and the boundary performs it". Sorted here rather than
    /// at the sink so the set is byte-stable at the moment it is produced, which
    /// is what makes a concurrent fan-in above it unable to change the answer.
    ///
    /// **Only rules that RAN may request.** A rule in `not_evaluated` produces
    /// nothing, because a record written by a rule that never looked is a
    /// baseline a later run would ratchet against having never been measured —
    /// CLOUD-81's fail-closed reading, one surface further on.
    pub requested: Vec<crate::sink::Requested>,
}

/// The name of the verb that runs process-spawning rule kinds, quoted in the
/// refusal [`run_static`] emits. Named once so the message and the surface
/// cannot drift.
pub const SPAWNING_VERB: &str = "batten enforce";

/// Run only the rules that cannot spawn a process — the surface a `read`-effect
/// verb is allowed to reach (house-style §5, CLOUD-170).
///
/// A configured rule whose kind *can* spawn is **refused loudly**, never
/// silently skipped: a skipped gate that still exits `0` is exactly the
/// false-green Batten exists to catch.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when any configured rule's kind spawns
/// processes, naming [`SPAWNING_VERB`] as the verb that runs it, and for a
/// malformed rule. An I/O failure propagates as an internal error (→ exit `3`).
pub fn run_static(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    // The declared pattern table (CLOUD-885), riding beside `provisions` for the
    // same reason it does: a second config table the rule set evaluates against.
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
) -> anyhow::Result<Scan> {
    run_over(
        rules,
        provisions,
        vocabulary,
        root,
        crate::policy::ModuleChecks::Run,
        RunKind::Static,
    )
}

/// [`run_static`] with the config-fault checks the caller is entitled to make
/// (CLOUD-1051).
///
/// The four-argument entry points stay, and every caller that does not narrow
/// keeps using them: `ModuleChecks` is a question about ONE caller — the one that
/// passed `--rule` — and widening sixteen call sites to carry a constant would be
/// churn that says nothing.
///
/// # Errors
///
/// As [`run_static`]: a config fault at load, or a declared row this surface
/// cannot honestly run.
pub fn run_static_over(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    checks: crate::policy::ModuleChecks,
) -> anyhow::Result<Scan> {
    run_over(rules, provisions, vocabulary, root, checks, RunKind::Static)
}

/// [`run_all`] with the config-fault checks the caller is entitled to make.
///
/// # Errors
///
/// As [`run_all`]: a config fault at load, or a rule whose command fails to run.
pub fn run_all_over(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    checks: crate::policy::ModuleChecks,
) -> anyhow::Result<Scan> {
    run_over(rules, provisions, vocabulary, root, checks, RunKind::All)
}

/// Which surface a run is on. One enum rather than two near-identical bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunKind {
    /// `check`: refuse before any work if a declared row would spawn.
    Static,
    /// `enforce`: every kind runs.
    All,
}

fn run_over(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    checks: crate::policy::ModuleChecks,
    kind: RunKind,
) -> anyhow::Result<Scan> {
    match kind {
        RunKind::Static => run_static_inner(rules, provisions, vocabulary, root, checks),
        RunKind::All => run_all_inner(rules, provisions, vocabulary, root, checks),
    }
}

fn run_static_inner(
    rules: &[Rule],
    _provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    checks: crate::policy::ModuleChecks,
) -> anyhow::Result<Scan> {
    // POLICY BUNDLES ARE LOADED HERE, on the read surface, and that is
    // CLOUD-833's substantive claim rather than a formality. `run_static` backs
    // `check` and refuses any kind that `carries_ambient_authority` — a
    // `command` row spawns a process with the calling user's authority, which is
    // why it is confined to `enforce`. A policy module is `Authority::Supplied`:
    // a pure function over an input document that cannot open a file, start a
    // process or reach the network, a property CLOUD-831 gates rather than
    // asserts. So admitting it here makes `check` MORE capable without making it
    // less honest, and the spawning refusal below is untouched.
    let bundles = crate::policy::load(root, rules, vocabulary, checks, None)?;
    // Refuse before any work: the read-only surface must not even begin a run
    // it cannot complete honestly.
    for rule in rules {
        if rule.kind.carries_ambient_authority() {
            // The refusal contract (CLOUD-122) covers this deny site too, and it
            // is the one that most needed it: a refusal naming only what it would
            // not do leaves the caller to guess the verb that would. Exit 1 rather
            // than 2 — this is a statement about the invocation, not a policy
            // verdict — and the `batten:` prefix the boundary adds is correct for
            // that code (§7).
            return Err(UsageError::raise(
                Refusal::declared(
                    &rule.id,
                    crate::verdict::Native::SpawningRuleOnReadVerb,
                    &[crate::verdict::Subject::Artifact {
                        artifact: rule.kind.as_str().to_owned(),
                    }],
                    Fix::Run(SPAWNING_VERB.to_owned()),
                )
                .render(),
            ));
        }
    }
    run(rules, &[], root, &bundles, vocabulary)
}

/// Run only the rules that cannot spawn a process, and report the ones that can
/// as **not evaluated** rather than refusing (CLOUD-97's strand).
///
/// The third scan surface, and it exists because the other two answer a question
/// the *recording* verb never asked. [`run_static`] refuses a spawning kind
/// because a `read`-effect verb that skipped one would exit `0` having gated
/// nothing — the false green. [`run_all`] runs it, which a verb that writes the
/// store may not do: `batten state record`'s own rustdoc refuses to put
/// user-supplied code behind a store write. So the recorder inherited a refusal
/// whose stated reason is about `batten check`, and the cost was total — the
/// refusal returns *before any work*, so every repository declaring one spawning
/// rule got no scan, no transcript detectors, and no store write at all.
///
/// **Skipping is safe here and unsafe in `run_static` for one structural
/// reason**: this surface's caller folds [`Scan::not_evaluated`] into the store,
/// where a withheld rule's findings **hold** instead of resolving
/// ([`crate::findings::Observation`]'s whole purpose). `check` has no such
/// destination — its silence reaches a human as an exit code and nothing else —
/// so there the only honest answer is to refuse. Same omission, two surfaces,
/// two correct answers.
///
/// Nothing here spawns: the withheld rules are partitioned out *before*
/// [`run`] sees them, so the no-user-code-behind-a-store-write property is a
/// property of the argument list rather than a promise. The partition asks
/// [`RuleKind::carries_ambient_authority`] — the same question [`run_static`]
/// refuses on, deliberately the identical call rather than a second predicate,
/// so the two surfaces can disagree about what to DO with such a kind and never
/// about which kinds they are.
///
/// # Errors
///
/// As [`run`]: a [`UsageError`] (→ exit `1`) for a malformed rule, and an I/O
/// failure while walking the tree as an internal error (→ exit `3`).
pub fn run_recorded(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
) -> anyhow::Result<Scan> {
    let (evaluable, withheld): (Vec<&Rule>, Vec<&Rule>) = rules
        .iter()
        .partition(|rule| !rule.kind.carries_ambient_authority());
    let evaluable: Vec<Rule> = evaluable.into_iter().cloned().collect();
    let bundles = crate::policy::load(
        root,
        &evaluable,
        vocabulary,
        crate::policy::ModuleChecks::Run,
        None,
    )?;
    let mut scan = run(&evaluable, provisions, root, &bundles, vocabulary)?;
    for rule in withheld {
        // `RuleSkipped`, not a variant of its own. The distinction between "the
        // input precondition was unmet" and "this surface cannot run the kind"
        // changes no decision downstream — both mean the rule did not look, and
        // both must hold — so a third variant would widen a stored enum to carry
        // a difference nothing reads (CLOUD-78's no-implicit-upgrade rule makes
        // that cost real).
        scan.not_evaluated
            .insert(rule.id.clone(), NotObserved::RuleSkipped);
    }
    Ok(scan)
}

/// Run every configured rule, including process-spawning kinds.
///
/// This is the non-`read` surface: it may execute commands declared in
/// `batten.toml`, so its verb is classified `unclassified` (§5).
///
/// # Errors
///
/// As [`run_static`], minus the spawning-kind refusal — plus one of its own: a
/// rule declaring [`Rule::fix`] is refused, because serialised fix execution is
/// a capability this engine does not have. Returns a [`UsageError`] (→ exit
/// `1`): a config naming a capability the binary lacks is the config-or-usage
/// class (§7), never a policy verdict about the repository.
pub fn run_all(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
) -> anyhow::Result<Scan> {
    run_over(
        rules,
        provisions,
        vocabulary,
        root,
        crate::policy::ModuleChecks::Run,
        RunKind::All,
    )
}

fn run_all_inner(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    checks: crate::policy::ModuleChecks,
) -> anyhow::Result<Scan> {
    // Refuse before any work, the shape `run_static` above already uses: the
    // alternative is running the check side, exiting on its verdict, and having
    // silently ignored a repair the config declared. A key that parses and does
    // nothing is indistinguishable from one the engine honoured.
    for rule in rules {
        if rule.fix.is_some() {
            return Err(UsageError::raise(format!(
                "rule {}: `fix` declares a repair, and serialised fix execution is not a \
                 capability this build has; remove the key or run the repair yourself",
                rule.id
            )));
        }
    }
    let bundles = crate::policy::load(root, rules, vocabulary, checks, None)?;
    run(rules, provisions, root, &bundles, vocabulary)
}

/// Run every rule in `rules` against the tree rooted at `root`, returning all
/// findings sorted for byte-stability plus the rules that never looked.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed rule (e.g. an empty
/// `glob`). An I/O failure while walking the tree propagates as an internal
/// error (→ exit `3`).
fn run(
    rules: &[Rule],
    provisions: &[crate::provision::Provision],
    root: &Path,
    bundles: &[crate::policy::Bundle],
    // The declared recorders, so their records can be projected (CLOUD-1051).
    // Config rather than a per-rule column: the fact is what THIS REPOSITORY's
    // recorders accumulated, so a second declaration on the rule would be a
    // second home for one answer.
    vocabulary: crate::policy::Vocabulary<'_>,
) -> anyhow::Result<Scan> {
    let recorders = vocabulary.recorders;
    let files = tree_files(root)?;
    // Resolved ONCE for the whole run, before any rule is evaluated (CLOUD-773).
    // That is the entire point: the shell layer this replaces re-derives because
    // a producer's value cannot cross the boundary, so it pays the extraction
    // per consumer. Here the producer pays once and every reader reads.
    let derived = resolve_derived(rules, root, &files);
    // Resolved ONCE for the whole run, beside the two above and for the same
    // reason (CLOUD-850): every document the rule set declares, read and parsed
    // once rather than once per rule. `documents_acquired` is what asserts it.
    let documents = acquire_declared(rules, root, &files)?;

    // WHAT EARLIER RUNS PRODUCED, acquired once for the whole run beside the
    // three above and for the same reason (CLOUD-851). Bounded by DECLARATION —
    // only the keys this rule set's sinks name — never a walk of the store, which
    // is what keeps `Fact::Produced`'s `read` classification honest.
    //
    // NOT BEING IN A CHECKOUT is could-not-look over the whole store and yields an
    // empty map: with no store at all a ratchet has nothing to ratchet against, and
    // a rule reads the absence rather than a fabricated record. A record that IS
    // there and cannot be read is the other answer entirely, and `sink::store`
    // returns it as an error rather than as absence — see its doc comment.
    // GUARDED ON THE DECLARATION, and that guard is not an optimisation. Locating
    // the git dir and reading HEAD unconditionally cost `check` a measured p50 of
    // 4.76ms -> 10.01ms (2.103x) against the merge base — `perf-compare` refused
    // the branch — for a question no rule in the set had asked. A run whose rules
    // declare no sink now does exactly what it did before this row landed.
    let produced = if crate::sink::any_declared(rules) {
        match crate::git::git_dir(root) {
            Err(_) => BTreeMap::new(),
            Ok(git_dir) => {
                // The branch is a second read, so it is resolved only when a sink is
                // keyed by one — the economy `receipt::verdicts` already states.
                let branch = if crate::sink::any_branch_keyed(rules) {
                    crate::git::current_branch(root).ok().flatten()
                } else {
                    None
                };
                crate::sink::store(
                    &git_dir,
                    &crate::sink::declared_records(rules, branch.as_deref()),
                )?
            }
        }
    } else {
        BTreeMap::new()
    };

    // THE GIT FACT FAMILY (CLOUD-907), acquired once for the whole run beside
    // the four above and, like `produced`, ONLY FOR WHAT A RULE DECLARED.
    //
    // The guard is the classification. `Fact::GitHead` and its siblings are
    // `Cost::Read`, and that stays true only because the reads are bounded by the
    // ruleset rather than taken ambiently — CLOUD-851 measured what the other way
    // costs, taking `check` from a p50 of 4.76ms to 10.01ms (2.103x) for a
    // question no rule in the set had asked. A run whose rules declare no git
    // fact does exactly what it did before this row landed.
    //
    // Every failure is could-not-look and yields `None`, which the projection
    // writes as `null`: outside a checkout there is no answer to give, and a
    // fabricated one is worse than none.
    let git = git_facts(rules, root);
    // The one acquisition of the `Cost::Effect` fact (CLOUD-760), beside the git
    // family and for the same reason: a projection must not spawn, so the spend
    // happens once here and only when a row declared it.
    let symbols = symbols_fact(rules, root);

    // THE RECORDER RECORDS (CLOUD-1051), and guarded on the declaration for the
    // reason `produced` above is: locating the git dir and resolving the branch
    // are reads a run whose rules ask for neither must not pay. A ruleset naming
    // no `records` fact does exactly what it did before this landed.
    //
    // ABSENT RATHER THAN EMPTY on every failure. A recorder that never ran and a
    // record this could not read are different answers, and the gate downstream
    // passes on the second by design — so fabricating an empty list here would
    // turn could-not-look into a measured nothing, which is the collapse the
    // whole fact model refuses.
    //
    // The guard is the RECORDER TABLE rather than a per-rule column, because a
    // recorder is config: the fact is "what this repository's recorders
    // accumulated", so a repository declaring none has nothing to read and a
    // per-rule declaration would be a second place for the same answer to live.
    let records = if recorders.is_empty() {
        BTreeMap::new()
    } else {
        match (crate::git::git_dir(root), crate::git::current_branch(root)) {
            (Ok(git_dir), Ok(Some(branch))) => recorder_records(&git_dir, &branch, recorders),
            _ => BTreeMap::new(),
        }
    };

    let inputs = RunInputs {
        provisions,
        files: &files,
        derived: &derived,
        documents: &documents,
        produced: &produced,
        records: &records,
        git: &git,
        symbols: &symbols,
        bundles,
    };

    let mut scan = Scan::default();
    for rule in rules {
        if let Some(why) = run_rule(rule, root, &inputs, &mut scan.findings)? {
            scan.not_evaluated.insert(rule.id.clone(), why);
        }
    }
    // BEFORE the sort, deliberately (CLOUD-396): the sort is what makes the
    // output byte-stable, so a dedup running after it would be reading an order
    // it also has to preserve, and "which duplicate survived" would become a
    // property of the comparator. Run first and the survivor is the one the
    // engine emitted first — a function of the walk, which is already sorted.
    dedup_scoped(&mut scan.findings);
    // Sort by the pointer tuple so identical input yields identical output.
    scan.findings.sort_by(|a, b| {
        (a.path.as_str(), a.line, a.rule.as_str()).cmp(&(b.path.as_str(), b.line, b.rule.as_str()))
    });
    scan.requested = requested_sinks(rules, &scan);
    Ok(scan)
}

/// What the run asks the boundary to write (CLOUD-851).
///
/// PURE, AND COMPUTED AFTER THE FINDINGS RATHER THAN INSIDE EACH RULE KIND. Both
/// halves are deliberate. Pure, because this is the decision half of the split
/// and a decision that touched the filesystem would end `adjudicate`'s
/// contract — every value here comes off the rule table and the sorted findings.
/// After, because a sink is a fact about what the rule DECIDED, so computing it
/// per kind would oblige eleven call sites to agree about a digest, which is the
/// hand-projection drift `tree_document` iterating `Fact::ALL` exists to avoid.
///
/// The digest is over the finding IDENTITIES, never their content: an identity is
/// already the pointer-shaped half of a finding, so rule 4 holds structurally
/// rather than by remembering to hash the right field.
///
/// A rule that did not evaluate requests nothing — see [`Scan::requested`].
fn requested_sinks(rules: &[Rule], scan: &Scan) -> Vec<crate::sink::Requested> {
    let mut requested: Vec<crate::sink::Requested> = rules
        .iter()
        .filter(|rule| !scan.not_evaluated.contains_key(&rule.id))
        .filter_map(|rule| {
            let sink = rule.produces.as_ref()?;
            let mut subject = String::new();
            let mut count = 0usize;
            for finding in scan.findings.iter().filter(|f| f.rule == rule.id) {
                subject.push_str(&finding.identity.fingerprint.to_hex());
                subject.push('\n');
                count += 1;
            }
            Some(crate::sink::Requested {
                rule: rule.id.clone(),
                key: sink.key,
                kind: sink.kind,
                // A marker's content is its existence, so it carries no digest to
                // read back — and giving it one would invite a predicate to read
                // the content of a record whose whole contract is presence.
                digest: if sink.kind == crate::facts::Production::Marker {
                    String::new()
                } else {
                    crate::receipt::hex_sha256(subject.as_bytes())
                },
                count,
            })
        })
        .collect();
    requested.sort();
    requested
}

/// Collapse rule-scoped findings that the same rule raised more than once,
/// keeping the first of each identity (CLOUD-396).
///
/// A `command` rule whose match set exceeds [`MAX_FILES_BYTES`] runs once per
/// [`batches`] group, and a rule-scoped finding condemns the **batch** rather
/// than a span — so its identity carries nothing telling one batch from
/// another, and a rule failing in N batches emitted N byte-identical findings.
/// Batching is an argv bound, an implementation detail this module's own
/// [`MAX_FILES_BYTES`] doc promises is "invisible to the predicate"; a finding
/// count that moves with the caller's path count is that detail leaking into
/// the output contract (§6).
///
/// **Identity is the unit, not the whole value**, because identity is already
/// what "one finding" means downstream: [`crate::findings`] holds one record per
/// identity, so two findings sharing one is one finding there whatever this
/// function does. Emitting both is the leak, not the disagreement.
///
/// **Only [`identity::FindingKind::Scope`]**, and the two exclusions are for
/// different reasons. A span-keyed kind may legitimately raise the same identity
/// twice — the same banned text on two lines is two pointers, and collapsing
/// them would delete a location nothing else reports. An identity this build
/// cannot classify (`kind()` is `None`) is left alone for
/// [`crate::findings`]'s reason: guessing a kind for one a later version minted
/// would silently drop findings by a rule nobody wrote here.
fn dedup_scoped(findings: &mut Vec<Finding>) {
    let mut seen: BTreeSet<identity::StoredIdentity> = BTreeSet::new();
    findings.retain(|finding| {
        if finding.identity.kind() != Some(identity::FindingKind::Scope) {
            return true;
        }
        // `insert` answers false for an identity already held, which is the
        // "drop this one" verdict — first occurrence wins, and `retain` keeps
        // the order the engine emitted in.
        seen.insert(finding.identity.clone())
    });
}

/// Read each declared recorder's branch-keyed record, skipping any that is not
/// there or cannot be read.
///
/// A skipped record is ABSENT from the map rather than present and empty, which
/// is the could-not-look channel this whole model keeps open: the gate reading
/// this passes on absence, so a fabricated empty list would be a measured
/// nothing and would silently satisfy a predicate about the record's contents.
///
/// Keyed by the RECORD, not by the recorder row. Several rows may write one
/// file — that many-to-one is the recorder model's own — so reading per row
/// would open the same file once per row and project the same lines under
/// several names.
fn recorder_records(
    git_dir: &std::path::Path,
    branch: &str,
    recorders: &[crate::recorder::Declared],
) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for recorder in recorders {
        if found.contains_key(&recorder.record) {
            continue;
        }
        let path = crate::recorder::record_path(git_dir, &recorder.record, branch);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        found.insert(
            recorder.record.clone(),
            text.lines().map(str::to_owned).collect(),
        );
    }
    found
}

/// Apply one rule to the pre-collected, sorted `files` list.
///
/// Returns `Some(reason)` when the rule **did not evaluate** — which is not the
/// same as evaluating to nothing. Only that distinction lets the store hold a
/// finding whose rule never looked instead of resolving it (CLOUD-81).
/// What a run resolves ONCE, before any rule evaluates, and every rule then
/// reads: the tree walk, the derived facts, and the acquired documents, plus
/// the provisions and bundles the config carries. Grouped rather than passed
/// one by one because it is exactly the set `run` hoists above its loop, and
/// because it grows by a field every time an acquisition row lands.
struct RunInputs<'a> {
    provisions: &'a [crate::provision::Provision],
    files: &'a [String],
    derived: &'a BTreeMap<String, crate::facts::Look<String>>,
    documents: &'a BTreeMap<(String, Wanted), Acquired>,
    /// What earlier runs produced, for the keys this rule set declares
    /// (CLOUD-851). One read for the whole run, beside `documents`.
    produced: &'a BTreeMap<String, String>,
    /// The recorder records this branch accumulated (CLOUD-1051). One read for
    /// the whole run, beside `produced`.
    records: &'a BTreeMap<String, Vec<String>>,
    /// The git facts this rule set declared (CLOUD-907).
    git: &'a crate::git::GitFacts,
    /// The symbol census, iff this rule set declared it (CLOUD-760).
    symbols: &'a crate::facts::Look<crate::symbols::Resolved>,
    bundles: &'a [crate::policy::Bundle],
}

fn run_rule(
    rule: &Rule,
    root: &Path,
    inputs: &RunInputs<'_>,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Option<NotObserved>> {
    // Validation first, and it owns the empty-glob refusal now: the census in
    // `Rule::validate` is the one place that knows which columns a kind needs,
    // so a second check here could only disagree with it.
    rule.validate()?;
    // A rule the tree engine does not evaluate is not this surface's business.
    // `validate` has already refused an unevaluable kind/scope pairing, so a
    // skip here is a rule another surface owns, never one nothing runs.
    if rule.scope != RuleScope::Tree {
        return Ok(Some(NotObserved::RuleSkipped));
    }
    // BEFORE THE GLOB GATE, because a policy row has no glob (CLOUD-833). It is
    // not selected by the files it reads — it is handed the documents it
    // declares — so the census does not ask it for one and the early return
    // below would skip every such row silently.
    //
    // Also before the `allow` check, deliberately: severity on this kind is
    // resolved PER PREDICATE (CLOUD-832), so a row whose own severity is `allow`
    // may still carry predicates tuned to `deny`. The per-violation check inside
    // is what decides, and returning here would switch those off by a value
    // nobody aimed at them.
    if rule.kind == RuleKind::Policy {
        return Ok(policy_rule(rule, inputs, findings));
    }
    let Some(glob) = rule.glob.as_deref() else {
        // Unreachable for a tree-scoped kind, whose census requires `glob`.
        return Ok(Some(NotObserved::RuleSkipped));
    };
    // An `allow` rule is configured off: a match is not a finding at all. It is
    // still validated above — a malformed rule is a config error even when off,
    // because "off" must never double as "unreadable" — but it matches nothing
    // and (for a command kind) never spawns. Severity does not change which
    // surface admits a rule: `run_static`'s spawning refusal fires first,
    // regardless of severity, so the two axes stay independent.
    if rule.severity() == RuleSeverity::Allow {
        return Ok(Some(NotObserved::RuleSkipped));
    }
    // Compiled once for this rule, then matched against every path — never
    // re-parsed per file (CLOUD-214). A `PathSet` since CLOUD-883: `glob` is the
    // include and `exclude_paths` the excludes, so the selection can only ever be
    // a SUBSET of what the glob alone names.
    let selection = PathSet::selecting(&rule.id, glob, &rule.exclude_paths)?;
    let matched: Vec<&String> = inputs
        .files
        .iter()
        .filter(|path| selection.contains(path))
        .collect();

    // A ratchet is evaluated BEFORE the empty-match skip below, and the
    // distinction is the whole gate: for every other kind an empty match set
    // means "nothing to inspect", but for a ratchet it means the working tree
    // now contains none of the files the base did — which is the maximal
    // deletion this kind exists to catch. Skipping there would make the gate
    // silent in exactly its worst case.
    if rule.kind == RuleKind::Ratchet {
        ratchet_rule(rule, root, glob, inputs.files, &matched, findings)?;
        return Ok(None);
    }

    // The glob is a gate before it is an argv source (§4 "cheap when
    // irrelevant"): no match means the rule is skipped entirely — for a command
    // rule, without ever spawning. **Skipped, not clean**: the rule never read a
    // file, so its silence is not evidence the defect is gone, and reporting
    // that here is what keeps the store from resolving on it (CLOUD-81).
    if matched.is_empty() {
        return Ok(Some(NotObserved::RuleSkipped));
    }
    match rule.kind {
        RuleKind::Forbid => {
            for path in matched {
                forbid_in_file(rule, root, path, findings)?;
            }
        }
        RuleKind::Command => command_rule(rule, root, &matched, findings)?,
        RuleKind::Document => {
            for path in matched {
                document_in_file(rule, root, path, inputs.derived, findings)?;
            }
        }
        RuleKind::Secrets => {
            crate::secrets::scan(rule, inputs.provisions, root, &matched, findings)?;
        }
        // Unreachable: the shape, receipt, pipeline and policy kinds are
        // `mediated_call`-scoped and a ratchet
        // returned above. Stated rather than caught by a wildcard so adding a
        // kind that *is* tree-scoped has to come here.
        //
        // `Judge` is tree-scoped and still unreachable, by a different and
        // load-bearing route: a judge row is refused the `severity` column, so
        // `Rule::severity` answers `allow` for it and the check twenty lines up
        // returns before this match. That is not an accident of ordering — it is
        // what makes "a judge outcome is never a `Finding`" a property of the
        // walker rather than a convention. The judge runs in its own pass, over
        // in `lib.rs`, beside `findings` and never into it.
        RuleKind::Shape
        | RuleKind::Ratchet
        | RuleKind::Receipt
        | RuleKind::Pipeline
        | RuleKind::Policy
        | RuleKind::Judge => {} // `Policy` is unreachable here for a THIRD reason as of CLOUD-833: it
                                // returns above, before the glob gate, because it has no glob to be
                                // selected by. Left in the list rather than removed so adding a scope to
                                // it has to come back to this match.
    }
    Ok(None)
}

/// Why a declared document could not be handed to a predicate (CLOUD-849).
///
/// **Four causes, and before this type they were three different mappings.**
/// `Fact::Document` was acquired at three sites — `tree_document`,
/// `document_in_file`, `derive_one` — each with its own error handling, already
/// diverged: the first could not tell a non-UTF-8 file from a missing one and
/// its two siblings could. That is the re-derived-copy shape CLOUD-647 counts
/// elsewhere, and it left nowhere to put a cache, a read budget or a pool.
///
/// Each arm is a *different remedy*, which is why they are not one value:
/// [`UnknownFormat`](Self::UnknownFormat) means the row declares a path this
/// build can never parse — a **config fault**, decidable before any I/O;
/// [`Absent`](Self::Absent) means the tree does not carry it;
/// [`Unreadable`](Self::Unreadable) means the bytes could not be got or are not
/// text; [`Unparsed`](Self::Unparsed) means the parser refused them. Collapsing
/// them is what let a gate go silent-and-green by declaring the wrong
/// extension — CLOUD-845's second false-green road.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotAcquired {
    /// The extension names no parser in this build.
    ///
    /// Decided **before any I/O**, and it is the one arm that is a config fault
    /// rather than a verdict: no state of the filesystem makes a declared
    /// `.md`/`.bats`/`.pkl` path parseable, so reporting it as could-not-look
    /// would be a gate reporting a permanent authoring error as a transient
    /// one.
    UnknownFormat,
    /// `ENOENT` — the tree does not carry the declared path.
    Absent,
    /// Opened and could not be read as text: `EACCES`, `EISDIR`, any other I/O
    /// failure, or bytes that are not UTF-8.
    ///
    /// Non-UTF-8 rides here rather than with [`Unparsed`](Self::Unparsed)
    /// because nothing was ever handed to a parser.
    Unreadable,
    /// Read as text, and the parser refused it.
    Unparsed,
}

impl NotAcquired {
    /// The stable token (§6) a skip reports, so a could-not-look names its
    /// cause instead of being anonymous.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            NotAcquired::UnknownFormat => "unknown-format",
            NotAcquired::Absent => "absent",
            NotAcquired::Unreadable => "unreadable",
            NotAcquired::Unparsed => "unparsed",
        }
    }
}

/// What a caller wants a declared file read AS (CLOUD-846).
///
/// The reason this is a parameter rather than a second function: [`acquire`] is
/// the ONE place this crate opens a declared file, and
/// `tests::one_document_acquisition_exists` is what keeps it one. A separate
/// `acquire_lines` would be a second boundary with its own error mapping — the
/// exact shape CLOUD-849 collapsed three of.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Want {
    /// Parsed into the canonical tree, by the stated format.
    Parsed(crate::facts::Format),
    /// Split into lines, unparsed (CLOUD-846).
    Lines,
    /// Parsed as Rust, and reduced to its call sites (CLOUD-914).
    Invocations,
    /// Parsed as Rust, and reduced to its `use` edges (CLOUD-762).
    Uses,
}

/// WHICH FORM a path was acquired as — the cache's key alongside the path.
///
/// **This exists because keying the cache on the path alone is a defect, and it
/// shipped twice before anything could see it.** One path holds one answer, so
/// two rows declaring the same file differently — one `line_sources`, one
/// `invocation_sources` over the same glob — had to be resolved by a precedence
/// rule, and precedence serves one row by STARVING the other: the loser's loop
/// finds the wrong variant and reports every one of its own declared files as
/// could-not-look. Measured at 65 paths, as `policy test`'s `fixture-missing`,
/// the first time two rows in this repository wanted one glob two ways.
///
/// Payload-free deliberately, where [`Want`] carries a [`crate::facts::Format`]:
/// the format is recoverable from the path, and keeping it out of the key means
/// no public type has to grow an ordering to be a `BTreeMap` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Wanted {
    /// Parsed into the canonical tree.
    Document,
    /// Split into lines, unparsed.
    Lines,
    /// Parsed as Rust, reduced to call sites.
    Invocations,
    /// Parsed as Rust, reduced to `use` edges.
    Uses,
}

/// A declared file, acquired — or the stated reason it was not.
#[derive(Debug)]
pub(crate) enum Acquired {
    /// Parsed into the one canonical tree CLOUD-772 landed.
    Parsed(crate::facts::Node),
    /// The file's lines, in order, with line endings removed.
    Lines(Vec<String>),
    /// The file's call sites, parsed (CLOUD-914). An EMPTY vector is a file that
    /// parsed and calls nothing — a real answer. A file the parser refused is
    /// [`NotAcquired::Unparsed`], never this.
    Invocations(Vec<crate::invocation::Invocation>),
    /// The file's `use` edges and its own export table (CLOUD-762). Both halves,
    /// because resolution is a post-pass across the declared set and the crate
    /// root's table is what it reads.
    Uses(crate::uses::UseFile),
    /// Not acquired, and why.
    No(NotAcquired),
}

/// How many documents this process has acquired (CLOUD-850).
///
/// **A counter, because a clock cannot discriminate here** — the same argument
/// [`crate::git::queries_spawned`] rests on. The claim it defends is that N rows
/// declaring one path read and parse it ONCE, and a single small read is well
/// inside the noise of a process start, so a timing assertion would see nothing.
///
/// Sound because [`acquire_document`] is the ONE place a document is read, kept
/// one by `tests::one_document_acquisition_exists`.
///
/// Monotonic and process-global: a caller takes a delta, which is why the test
/// asserting one lives in its own binary.
static DOCUMENTS_ACQUIRED: AtomicUsize = AtomicUsize::new(0);

/// How many documents this process has acquired.
#[must_use]
pub fn documents_acquired() -> usize {
    DOCUMENTS_ACQUIRED.load(Ordering::Relaxed)
}

/// **The one function that acquires a document** (CLOUD-849).
///
/// Every `Fact::Document` in this crate is read and parsed here and nowhere
/// else, which is what `tests::one_document_acquisition_exists` keeps true — the
/// same source-level shape [`crate::git::tests::no_second_git_invoker_exists`]
/// uses to keep git spawning single. Being one function is not tidiness: it is
/// the only place a cache, a read budget or a worker pool can go, and CLOUD-850
/// puts all three here.
///
/// The mapping is stated once, in [`NotAcquired`]'s arms. Reading is `fs::read`
/// plus an explicit `String::from_utf8` rather than `fs::read_to_string`,
/// because the latter answers `InvalidData` for non-UTF-8 and `NotFound` for an
/// absent file through one `io::Error` that the collapsed site then has to
/// re-split — which is exactly how `tree_document` came to report a binary file
/// and a missing one identically.
///
/// `format` is `None` when the caller could not classify the extension; that is
/// [`NotAcquired::UnknownFormat`] and costs no I/O.
pub(crate) fn acquire(root: &Path, rel_path: &str, want: Option<Want>) -> Acquired {
    let Some(want) = want else {
        // Before any I/O, deliberately: an extension this build cannot parse is
        // a config fault, and opening the file first would spend a read to
        // learn nothing.
        return Acquired::No(NotAcquired::UnknownFormat);
    };
    // Counted here rather than at the call sites: this is the point past which
    // work is actually spent, and the `UnknownFormat` arm above deliberately
    // costs nothing and is deliberately not counted.
    DOCUMENTS_ACQUIRED.fetch_add(1, Ordering::Relaxed);
    let bytes = match fs::read(root.join(rel_path)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Acquired::No(NotAcquired::Absent);
        }
        // EACCES, EISDIR and every other I/O failure. A gate that cannot look
        // reports rather than aborts the run — which is the posture `facts.rs`'s
        // header already states and the one behaviour `document_in_file` did not
        // share with its siblings before this collapse.
        Err(_) => return Acquired::No(NotAcquired::Unreadable),
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Acquired::No(NotAcquired::Unreadable);
    };
    match want {
        // LINES ARE NOT PARSED, so there is no `Unparsed` arm to reach: any text
        // splits into lines, and a file that could not be read as text was
        // already `Unreadable` above. That asymmetry is the point of the fact —
        // it is what lets markdown, `.bats` and Rust source reach a predicate at
        // all.
        //
        // `lines()` drops the terminator and handles CRLF, so a module's line
        // numbers are the ones an editor shows and a Windows checkout does not
        // change the answer.
        Want::Lines => Acquired::Lines(text.lines().map(ToOwned::to_owned).collect()),
        // The other `want` a parser can refuse after a successful read, and it
        // is spelled `Unparsed` rather than `Unreadable` for the same reason:
        // the bytes were fine and the grammar was not. CLOUD-310 made this the
        // price of embedding a matcher, after measuring one that emitted zero
        // nodes and zero errors over a file it had only partly parsed.
        // Same contract as `Invocations` below: the bytes read and the grammar
        // refused, which is `Unparsed` rather than `Unreadable`.
        Want::Uses => match crate::uses::use_facts(&text) {
            crate::facts::Look::Is(facts) => Acquired::Uses(facts),
            crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                Acquired::No(NotAcquired::Unparsed)
            }
        },
        Want::Invocations => match crate::invocation::invocations(&text) {
            crate::facts::Look::Is(sites) => Acquired::Invocations(sites),
            crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                Acquired::No(NotAcquired::Unparsed)
            }
        },
        // THE ONE `Format::read` CALL IN THE CRATE.
        Want::Parsed(format) => match format.read(&text) {
            crate::facts::Look::Is(node) => Acquired::Parsed(node),
            // A file that will not parse says nothing about what it contains,
            // which is `Format::read`'s own three-valued contract. `IsNot` rides
            // here for the reason `document_in_file` already gives: the arm
            // exists so the type stays total, and what it must never resolve to
            // is silence.
            crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                Acquired::No(NotAcquired::Unparsed)
            }
        },
    }
}

/// The most documents one run may acquire before it refuses (CLOUD-850).
///
/// **A backstop, not a tuned threshold, and the distinction is the whole
/// justification.** `mise-tasks/perf-assert.sh` budgets four paths and deliberately
/// budgets no `check` path, on a reason that is sound and stays: *"`check` is
/// bounded by the repository it is pointed at — a tree walk over a large
/// consumer repo is legitimately slower and no ceiling here could tell that
/// apart from a regression."* What follows is not that `check` needs no bound;
/// it is that the bound cannot be a **time**. This is a COUNT, which is a
/// property of the rule set rather than of the machine, so it discriminates
/// exactly where a clock could not.
///
/// The value is deliberately far above any real rule set — CLOUD-843's whole
/// campaign is 82 gates, and the worst-behaved of them opens 673 files — because
/// a backstop that a legitimate consumer can reach is a gate that fails on
/// correct use. Non-negotiable rule 3 says a gate decides rather than estimates,
/// and what this decides is "the read set stopped being declared", not "this
/// repository is too big".
///
/// Not a config key: house style §8 keeps configuration narrow, and a consumer
/// raising its own ceiling would be a consumer switching off the only bound this
/// surface has.
const READ_BUDGET: usize = 10_000;

/// What a declared path should be read as: lines if a row asked for lines,
/// otherwise the parse its extension names (CLOUD-846).
///
/// `None` is [`NotAcquired::UnknownFormat`] — an extension this build has no
/// parser for, asked for as a document. A path asked for as LINES never lands
/// there, which is the ceiling this fact lifts: `Format::for_path` returning
/// `None` was the whole reason 12 of the 20 tree-scoped gates had no fact to
/// decide over.
/// **THERE IS NO PRECEDENCE HERE ANY MORE, AND ITS ABSENCE IS THE FIX.** The
/// earlier signature took a flag per form and returned the winner, which is only
/// a question worth asking when one path can hold one answer. Now the caller
/// acquires each form a row asked for, so this answers exactly the form named.
pub(crate) fn want_for(path: &str, wanted: Wanted) -> Option<Want> {
    match wanted {
        Wanted::Lines => Some(Want::Lines),
        Wanted::Invocations => Some(Want::Invocations),
        Wanted::Uses => Some(Want::Uses),
        Wanted::Document => crate::facts::Format::for_path(path).map(Want::Parsed),
    }
}

/// Refuse a run whose declared read set has passed `limit` (CLOUD-850).
///
/// **Extracted so it is testable at any size**, which is `.claude/rules/rust.md`'s
/// standing instruction: where the environment cannot cheaply produce the failing
/// condition, extract the decision and test it directly rather than asserting a
/// conclusion over a precondition that was never created. Building a
/// ten-thousand-file fixture to exercise a `>=` would be that precondition, and
/// a test that skipped it would assert its own premise.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) carrying a COUNT and a LIMIT and nothing else.
/// §5's pointer-only rule is stricter than usual here: the natural thing to print
/// is the path list, and that list is exactly the consumer's file names, so a
/// refusal that printed it would put the shape of a private tree into an error
/// message. A count is not a pointer — it is less — and that is the right amount.
fn refuse_over_budget(acquired: usize, limit: usize) -> anyhow::Result<()> {
    if acquired < limit {
        return Ok(());
    }
    Err(UsageError::raise(format!(
        "the declared read set exceeds this run\u{2019}s budget: {} documents, limit {limit}. \
         A rule set this wide has stopped declaring what it reads",
        acquired + 1
    )))
}

/// The documents one policy row hands its bundle: its literal [`Rule::documents`]
/// plus everything its [`Rule::sources`] globs select (CLOUD-850).
///
/// Sorted and deduplicated, so a row declaring a path both ways reads it once
/// and the document's key order is the paths' rather than the declaration's —
/// §6 byte-stability, and the property a cache would otherwise have to restore.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a `sources` pattern `globset` cannot parse,
/// which is bad config and is refused rather than allowed to select nothing.
pub(crate) fn declared_documents(rule: &Rule, files: &[String]) -> anyhow::Result<Vec<String>> {
    select_declared(&rule.documents, &rule.sources, files)
}

/// Every path a row hands its bundle as **lines**: its literal [`Rule::lines`]
/// plus everything its [`Rule::line_sources`] globs select (CLOUD-864).
///
/// [`declared_documents`]'s sibling, and it exists because the two columns that
/// landed together did not land symmetric. `documents` got a glob spelling in
/// CLOUD-850 and `lines` did not, which leaves the unparsed half of the fact
/// model reachable only by naming every path — and the gates that need lines are
/// exactly the ones over many files. Enumerating 137 shell programs in a row is
/// a list that goes stale the next time one is added, silently, green.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a pattern `globset` cannot parse, matching
/// `declared_documents` rather than selecting nothing.
pub(crate) fn declared_lines(rule: &Rule, files: &[String]) -> anyhow::Result<Vec<String>> {
    select_declared(&rule.lines, &rule.line_sources, files)
}

/// Every path a row hands its bundle as **call sites**: its literal
/// [`Rule::invocations`] plus everything its [`Rule::invocation_sources`] globs
/// select (CLOUD-914).
///
/// [`declared_lines`]' sibling, glob-selected from the start rather than gaining
/// the spelling later — the asymmetry that row records is not worth reproducing.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a pattern `globset` cannot parse, matching
/// its two siblings rather than selecting nothing.
pub(crate) fn declared_invocations(rule: &Rule, files: &[String]) -> anyhow::Result<Vec<String>> {
    select_declared(&rule.invocations, &rule.invocation_sources, files)
}

/// Every path a row hands its bundle as a **`use` graph** (CLOUD-762).
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a pattern `globset` cannot parse, matching
/// its siblings rather than selecting nothing.
pub(crate) fn declared_uses(rule: &Rule, files: &[String]) -> anyhow::Result<Vec<String>> {
    select_declared(&rule.uses, &rule.use_sources, files)
}

/// The literal-plus-glob union both declaration pairs resolve through.
///
/// One implementation rather than two, so `lines` cannot drift from `documents`
/// in how a pattern is matched — which is the drift that produced the asymmetry
/// this function exists to close.
fn select_declared(
    literals: &[String],
    patterns: &[String],
    files: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut declared: BTreeSet<String> = literals.iter().cloned().collect();
    for pattern in patterns {
        // `Selector` — the one matcher, `literal_separator(true)` — never a
        // second implementation (CLOUD-850). A policy row was the single kind
        // excluded from it, and it is the kind the retirement migrates onto.
        let selector = Selector::new(pattern)?;
        for path in files.iter().filter(|path| selector.matches(path)) {
            declared.insert(path.clone());
        }
    }
    Ok(declared.into_iter().collect())
}

/// Every document the whole rule set declares, acquired **once** for the run
/// (CLOUD-850).
///
/// The defect this removes: `run`'s `for rule in rules` wrapped `tree_document`'s
/// `for path in documents` with no dedup and no cache, so two rows declaring one
/// path read and parsed it twice — 79 rules x N documents is 79N reads plus 79N
/// parses. Today each bash gate is its own process, so sharing a read is not
/// even possible; porting them into one engine is what makes it possible, and
/// the shared read is the whole affordability argument for doing so.
///
/// Hoisted beside `tree_files` and `resolve_derived`, both already commented
/// *"Resolved ONCE for the whole run"* (CLOUD-773) — an existing pattern, not a
/// new one. Declaring sources is what makes the read set knowable up front, and
/// knowable up front is what makes it cacheable.
///
/// Keyed by repo-relative path in a [`BTreeMap`], so iteration order is the
/// paths' and never the rules' — the ordering property that has to hold before
/// the batch could ever be filled concurrently.
pub(crate) fn acquire_declared(
    rules: &[Rule],
    root: &Path,
    files: &[String],
) -> anyhow::Result<BTreeMap<(String, Wanted), Acquired>> {
    let mut cache: BTreeMap<(String, Wanted), Acquired> = BTreeMap::new();
    // THE THREE COLLECT-FIRST SETS ARE GONE, and their absence is the fix. They
    // existed so a path two rows wanted differently would not resolve by
    // whichever row the loop reached first — a hazard that only exists while one
    // path can hold one answer. Keyed by `(path, form)` there is nothing to
    // resolve: each row's declaration is acquired in the form it asked for, and
    // rule order cannot change any answer.
    for rule in rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::Policy && rule.scope == RuleScope::Tree)
    {
        // A malformed `sources` glob is refused by `validate` before any rule
        // evaluates, so a failure here cannot be a config fault arriving late —
        // it is a row this surface does not own, and skipping it leaves the
        // per-rule path to report.
        let Ok(declared) = declared_documents(rule, files) else {
            continue;
        };
        // ONE PASS PER FORM THE ROW ASKED FOR, never one pass picking a winner.
        // A path a row wants as lines and another row wants as call sites is two
        // entries, and both rows get their own fact — which is the whole of the
        // defect this shape fixes.
        let wanted: [(Wanted, Vec<String>); 4] = [
            (Wanted::Document, declared),
            (
                Wanted::Lines,
                declared_lines(rule, files).unwrap_or_default(),
            ),
            (
                Wanted::Invocations,
                declared_invocations(rule, files).unwrap_or_default(),
            ),
            (Wanted::Uses, declared_uses(rule, files).unwrap_or_default()),
        ];
        for (form, paths) in wanted {
            for path in paths {
                let key = (path, form);
                if cache.contains_key(&key) {
                    // THE CACHE, and the assertion `documents_acquired` makes: N
                    // rows over one path IN ONE FORM is one read and one parse.
                    // Two rows wanting two forms is two, which is honest — they
                    // are two different parses of the same bytes.
                    continue;
                }
                // THE BUDGET, checked before the read rather than after it, so
                // the refusal is a bound and not a report of one already
                // exceeded. It now counts (path, form) pairs: a file wanted
                // three ways costs three, because it IS three parses.
                //
                // POINTER-ONLY, and here that means less than a pointer (§5): a
                // count and a limit, never the path list. The list is exactly
                // the consumer's file names, and a refusal that printed it would
                // put the shape of a private tree into an error message.
                refuse_over_budget(cache.len(), READ_BUDGET)?;
                let acquired = acquire(root, &key.0, want_for(&key.0, form));
                cache.insert(key, acquired);
            }
        }
    }
    Ok(cache)
}

/// The input document a tree-scoped policy bundle decides over (CLOUD-833),
/// **projected from the fact model** (CLOUD-845).
///
/// Mirrors [`crate::hook::call_document`] on the mediated side — and now in
/// mechanism, not only in role. The two answer different questions (the hook's
/// document is the CALL, this one is the TREE), but both are built by iterating
/// [`crate::facts::Fact::ALL`] under an exhaustive wildcard-free match, keyed by
/// a token the model owns.
///
/// ```text
/// {"tree": {"documents": {"<declared path>": <parsed>},
///           "tracked":   ["<repo-relative path>"],
///           "missing":   ["<path>"]}}
/// ```
///
/// **This function hand-wrote its keys until CLOUD-845, and that is exactly how
/// `input.tree.tracked` came to be documented and never built.** `policy.rs`'s
/// module doc — the example an author copies for their first module — iterated a
/// field the engine never emitted. Rego makes an undefined path silent, so the
/// predicate was undefined, so the deny set was empty, so a dead gate and a clean
/// tree were byte-identical on the decision surface. Nothing could catch it,
/// because no table said what the tree emits. Now one does: the key set here IS
/// [`crate::facts::Fact::tree_key`] over the `Surface::Check` facts, asserted in
/// both directions by `tests/policy_tree.rs`.
///
/// **Bounded by declaration for content, never by an ambient walk.** Only the
/// paths a row names are read and parsed. `tracked` is the deliberate exception
/// and is bounded differently — it is the walk the run already did, hoisted once
/// in [`run`] and handed in, so it costs nothing per rule, and it carries PATHS
/// and never content, which is what keeps rule 4 structural rather than careful.
///
/// **A declared document the tree does not carry is named in `missing`, not
/// omitted.** Omitting it would hand the module an input where the key is simply
/// absent, and a Rego predicate over an absent key is silently undefined —
/// CLOUD-251's vacuous pass, arriving as a clean gate. `missing` is a
/// could-not-look CHANNEL rather than a fact, which is why it has no
/// `tree_key` and why the correspondence test subtracts it explicitly instead of
/// letting it drift into the fact vocabulary.
///
/// The parsed value is [`crate::facts::Node::to_json`], the projection of the
/// one canonical tree CLOUD-772 landed — never a second parser.
/// Acquire exactly the git facts this rule set declared (CLOUD-907).
///
/// **The declaration is the bound**, and the bound is what makes
/// [`crate::facts::GIT_HEAD`]'s `Cost::Read` an honest classification rather than
/// an aspiration. A run whose rules name no git fact resolves nothing here, opens
/// no ref and does not even locate the git dir.
///
/// A read that fails leaves its member `None` — could-not-look, projected as
/// `null`. Outside a checkout there is no answer to give, and the alternative is
/// a fabricated one that a module cannot tell from a real answer.
fn git_facts(rules: &[Rule], root: &Path) -> crate::git::GitFacts {
    let mut declared_reads: BTreeSet<GitRead> = BTreeSet::new();
    let mut declared_refs: BTreeSet<String> = BTreeSet::new();
    let mut declared_ranges: BTreeSet<String> = BTreeSet::new();
    let mut declared_landings: BTreeSet<String> = BTreeSet::new();
    // The delta is ONE object, so the rows declaring it must agree on the rev it
    // is against. Collected as a set rather than taking the first: two rows
    // naming different bases is a question with two answers, and silently
    // answering one of them is how a gate reports about a comparison nobody
    // asked for. Disagreement leaves the fact `None` — could-not-look, which is
    // the honest shape and the one a predicate reads as undefined.
    let mut declared_deltas: BTreeSet<String> = BTreeSet::new();
    let mut delta_bases: BTreeSet<&str> = BTreeSet::new();
    for rule in rules {
        declared_reads.extend(rule.git.iter().copied());
        declared_refs.extend(rule.refs.iter().cloned());
        declared_ranges.extend(rule.ranges.iter().cloned());
        declared_landings.extend(rule.landing.iter().cloned());
        if !rule.delta_sources.is_empty()
            && let Some(base) = rule.base.as_deref()
        {
            declared_deltas.extend(rule.delta_sources.iter().cloned());
            delta_bases.insert(base);
        }
    }
    if declared_reads.is_empty()
        && declared_refs.is_empty()
        && declared_ranges.is_empty()
        && declared_landings.is_empty()
        && declared_deltas.is_empty()
    {
        return crate::git::GitFacts::default();
    }
    let refs: Vec<String> = declared_refs.into_iter().collect();
    let ranges: Vec<String> = declared_ranges.into_iter().collect();
    let landings: Vec<String> = declared_landings.into_iter().collect();
    let deltas: Vec<String> = declared_deltas.into_iter().collect();
    crate::git::GitFacts {
        head: declared_reads
            .contains(&GitRead::Head)
            .then(|| crate::git::head_fact(root).ok())
            .flatten(),
        status: declared_reads
            .contains(&GitRead::Status)
            .then(|| crate::git::status_fact(root).ok())
            .flatten(),
        remote: declared_reads
            .contains(&GitRead::Remote)
            .then(|| crate::git::remote_fact(root).ok())
            .flatten(),
        refs: (!refs.is_empty())
            .then(|| crate::git::ref_facts(root, &refs).ok())
            .flatten(),
        ranges: (!ranges.is_empty())
            .then(|| crate::git::range_facts(root, &ranges).ok())
            .flatten(),
        landing: (!landings.is_empty())
            .then(|| crate::git::landing_facts(root, &landings).ok())
            .flatten(),
        base_delta: match (delta_bases.len(), deltas.is_empty()) {
            (1, false) => delta_bases
                .iter()
                .next()
                .and_then(|base| crate::git::base_delta(root, base, &deltas).ok())
                .flatten(),
            _ => None,
        },
    }
}

/// One path's projection for one fact family: the value, or why it could not be
/// looked at.
///
/// Extracted from [`tree_document`], where the identical shape was written four
/// times — once per family — and each copy had to remember that a path acquired
/// as a DIFFERENT projection is `Absent` rather than an empty answer. That is
/// the vacuous pass CLOUD-251 names, and four chances to get it wrong is three
/// too many.
///
/// The `wanted` and the [`Acquired`] variant must agree, and the mismatch arm is
/// what enforces it: a path in the cache under another projection is not this
/// family's answer, and reporting it as an empty one would be a module finding
/// nothing and reporting clean.
fn project_declared(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    path: &str,
    wanted: Wanted,
) -> Result<serde_json::Value, NotAcquired> {
    match cache.get(&(path.to_owned(), wanted)) {
        Some(Acquired::Parsed(node)) if wanted == Wanted::Document => Ok(node.to_json()),
        Some(Acquired::Lines(text)) if wanted == Wanted::Lines => Ok(serde_json::json!(text)),
        // COULD NOT LOOK, NEVER AN EMPTY ARRAY, and for call sites the parser is
        // the one that can say so: `NotAcquired::Unparsed` is a file whose bytes
        // read fine and whose grammar did not. CLOUD-310 measured a matcher
        // emitting zero nodes and zero errors over a partially-parsed file, and
        // made a parse-coverage assertion the price of embedding one.
        Some(Acquired::Invocations(sites)) if wanted == Wanted::Invocations => {
            Ok(serde_json::json!(sites))
        }
        // The `use` family is handled by its caller rather than here, because an
        // edge set is completed against the crate root's re-export table and that
        // table is one value for the whole declared set — a per-path projection
        // cannot see it.
        Some(Acquired::No(why)) => Err(*why),
        // Acquired under a different projection, or never declared. Neither is
        // this family's answer and neither is an empty one.
        _ => Err(NotAcquired::Absent),
    }
}

/// The paths each row DECLARED, one list per projection (CLOUD-914, CLOUD-762).
///
/// Four lists rather than one, for the reason the cache is keyed on a pair: a
/// path can be acquired as more than one fact, so which projection it belongs to
/// is the caller's declaration and never a guess from the extension.
///
/// Grouped into a struct rather than passed as four parameters because they are
/// one thing — the declared set — and splitting them across the signature is
/// what pushed this function past the argument ceiling when the third and fourth
/// arrived.
pub(crate) struct Declared<'a> {
    /// Files a row declared as parsed documents.
    pub documents: &'a [String],
    /// Files a row declared as line sets.
    pub lines: &'a [String],
    /// Rust files a row declared as call sites.
    pub invocations: &'a [String],
    /// Rust files a row declared as a `use` graph.
    pub uses: &'a [String],
}

/// Project the `use` family, resolving every edge against ONE re-export table.
///
/// Separate from [`project_declared`] rather than folded into it, and the reason
/// is the whole of CLOUD-762's finding: an edge naming a crate-root item cannot
/// be completed from the file it appears in. The root's own `mod` declarations
/// are what disambiguate `use error::X` (a module) from `use anyhow::X` (a
/// crate), so the table is one value for the entire declared set and a per-path
/// projection structurally cannot see it.
fn project_uses(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    uses: &[String],
    out: &mut serde_json::Map<String, serde_json::Value>,
    missing: &mut Vec<String>,
    causes: &mut Vec<(String, NotAcquired)>,
) {
    // The root is named by Rust's own convention — a library crate's root is
    // `lib.rs` — which is a language fact and not a consumer identifier, so
    // non-negotiable rule 1 is untouched: nothing here names a repository, an
    // account or an entity path. A declared set with no root simply resolves
    // nothing, and every crate-root edge stays `root-item` with an empty
    // destination. That is the honest failure direction: visibly unresolved
    // rather than plausibly wrong.
    // EXACTLY ONE ROOT, OR NONE — and the `find` this replaced is why the
    // paragraph above was a promise the code did not keep. It took the FIRST
    // `lib.rs` and resolved every declared path's edges against that one table,
    // so a set spanning two crates resolved crate B's edges against crate A's
    // `mod` list: the plausibly-wrong answer, in the function whose own header
    // disclaims it. `use_sources` makes it reachable — a workspace glob such as
    // `crates/**/src/**/*.rs` selects several roots — and this tree carries one
    // crate today, so it was latent rather than absent. Caught in review on #680.
    //
    // Two roots now resolve NOTHING, which routes the multi-crate case into the
    // same honest failure the no-root case already had: every crate-root edge
    // stays `root-item` with an empty destination, and a layering gate reading it
    // sees unresolved rather than confidently wrong.
    let mut roots = uses.iter().filter(|path| {
        std::path::Path::new(path.as_str()).file_name() == Some(std::ffi::OsStr::new("lib.rs"))
    });
    let root_table = match (roots.next(), roots.next()) {
        (Some(path), None) => match cache.get(&(path.clone(), Wanted::Uses)) {
            Some(Acquired::Uses(facts)) => facts.exports.clone(),
            _ => crate::uses::RootExports::default(),
        },
        _ => crate::uses::RootExports::default(),
    };
    for path in uses {
        match cache.get(&(path.clone(), Wanted::Uses)) {
            Some(Acquired::Uses(facts)) => {
                let mut edges = facts.edges.clone();
                crate::uses::resolve(&mut edges, &root_table);
                out.insert(path.clone(), serde_json::json!(edges));
            }
            // COULD NOT LOOK, NEVER AN EMPTY EDGE SET. A layering gate whose
            // corpus failed to parse would otherwise report clean, which is
            // CLOUD-251's vacuous pass arriving as a green board.
            Some(Acquired::No(why)) => {
                missing.push(path.clone());
                causes.push((path.clone(), *why));
            }
            Some(Acquired::Parsed(_) | Acquired::Lines(_) | Acquired::Invocations(_)) | None => {
                missing.push(path.clone());
                causes.push((path.clone(), NotAcquired::Absent));
            }
        }
    }
}

/// Resolve the symbol fact, and ONLY when a row declared it (CLOUD-760).
///
/// `git_facts`' shape exactly, for a sharper version of its reason. That
/// function's header records CLOUD-851 taking `check` from 4.76ms to 10.01ms by
/// reading HEAD unconditionally — a 2.103x bill for one cheap read. This fact
/// spawns `cargo clippy` over the whole crate, so the same mistake here would not
/// be a slowdown but a different tool.
///
/// The `Look` is carried rather than unwrapped: a missing analyser is
/// could-not-look, and a projection that turned it into an empty site list would
/// report a crate with no spawns at all.
fn symbols_fact(rules: &[Rule], root: &Path) -> crate::facts::Look<crate::symbols::Resolved> {
    if !rules.iter().any(|rule| rule.symbols) {
        // Nothing asked, so nothing is spent — and the projection below emits
        // `null` rather than an empty census, which a module would read as
        // "resolved, found nothing".
        return crate::facts::Look::IsNot;
    }
    crate::symbols::resolve(root)
}

/// The [`crate::facts::Fact::Symbols`] projection, split out of
/// [`tree_document`] when the recorder fact pushed that function past the line
/// ceiling.
///
/// The three-valued distinction the doc comment at its call site describes lives
/// here rather than there, and the seam is the one that survives: this is the
/// only arm whose value is a nested document rather than a `json!` of a field.
fn symbols_value(symbols: &crate::facts::Look<crate::symbols::Resolved>) -> serde_json::Value {
    match symbols {
        crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => serde_json::Value::Null,
        crate::facts::Look::Is(resolved) => serde_json::json!({
            "provenance": {
                "tool": resolved.provenance.tool,
                "version": resolved.provenance.version,
                "invocation": resolved.provenance.invocation,
            },
            "sites": resolved
                .sites
                .iter()
                .map(|site| serde_json::json!({
                    "path": site.path,
                    "line": site.line,
                    "lint": site.lint,
                }))
                .collect::<Vec<_>>(),
        }),
    }
}

pub(crate) fn tree_document(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    declared: &Declared<'_>,
    tracked: &[String],
    // What earlier runs produced, acquired once at the boundary (CLOUD-851).
    // Handed in rather than read here for `Fact::Produced`'s whole reason: the
    // projection is pure, and the read that fills this map is the caller's.
    produced: &BTreeMap<String, String>,
    // The recorder records this branch accumulated (CLOUD-1051). Handed in for
    // `produced`'s reason, and absent rather than empty when the store could not
    // be read: a recorder that never ran and one whose file is unreadable are
    // different answers, and the gate reading this passes on the second.
    records: &BTreeMap<String, Vec<String>>,
    // The git fact family, acquired once at the boundary and only for what the
    // ruleset DECLARED (CLOUD-907). Handed in for `produced`'s reason: the
    // projection is pure, and the reads that fill this are the caller's.
    git: &crate::git::GitFacts,
    // The `Cost::Effect` fact (CLOUD-760), acquired once at the boundary and only
    // when a row DECLARED it. Handed in for `git`'s reason, and for a stronger
    // one: this is the only fact whose acquisition runs an analyser, so leaving
    // the spend to the caller is what keeps a projection from spawning.
    symbols: &crate::facts::Look<crate::symbols::Resolved>,
) -> (String, Vec<(String, NotAcquired)>) {
    let Declared {
        documents,
        lines,
        invocations,
        uses,
    } = *declared;
    let mut produced_records: serde_json::Map<String, serde_json::Value> = produced
        .iter()
        .map(|(key, record)| (key.clone(), serde_json::json!(record)))
        .collect();
    let mut recorder_lines: serde_json::Map<String, serde_json::Value> = records
        .iter()
        .map(|(name, lines)| (name.clone(), serde_json::json!(lines)))
        .collect();
    let mut parsed = serde_json::Map::new();
    let mut read_lines = serde_json::Map::new();
    let mut call_sites = serde_json::Map::new();
    let mut use_edges = serde_json::Map::new();
    let mut missing = Vec::new();
    // The same set as `missing`, carrying WHY (CLOUD-845). `missing` stays a
    // bare path list in the document because that is what a module reads; the
    // cause is the caller's, so a skip can name its reason instead of being
    // anonymous.
    let mut causes: Vec<(String, NotAcquired)> = Vec::new();
    // ONE LOOP OVER THREE FAMILIES, driven by a table rather than written out
    // three times. Each family names the projection it wants and the map it
    // fills; `project_declared` owns the could-not-look distinction that all
    // three share, so there is one place for it to be right rather than three.
    //
    // `uses` is deliberately NOT in this table: its edges are completed against
    // the crate root's re-export table below, which is one value for the whole
    // declared set and so cannot be resolved per path.
    for (paths, wanted, out) in [
        (documents, Wanted::Document, &mut parsed),
        (lines, Wanted::Lines, &mut read_lines),
        (invocations, Wanted::Invocations, &mut call_sites),
    ] {
        for path in paths {
            match project_declared(cache, path, wanted) {
                Ok(value) => {
                    out.insert(path.clone(), value);
                }
                Err(why) => {
                    missing.push(path.clone());
                    causes.push((path.clone(), why));
                }
            }
        }
    }
    // The `use` family, whose edges are completed against one table for the
    // whole declared set — see `project_uses`.
    project_uses(cache, uses, &mut use_edges, &mut missing, &mut causes);
    // THE PROJECTION (CLOUD-845), on `hook::call_document`'s shape. Iterating
    // `Fact::ALL` rather than writing keys means a fact the tree surface gains
    // cannot arrive unprojected, and a key the tree emits cannot fail to name a
    // fact — which is the pair of failures that let `input.tree.tracked` be
    // documented and never built.
    let mut tree = serde_json::Map::new();
    for fact in crate::facts::Fact::ALL {
        // Only what this surface CAN resolve, and `resolvable_on` is the
        // predicate rather than an equality — which is the axis as
        // `facts::Surface` documents it: `Hook` is the NARROWEST surface a fact
        // may be resolved on, so every wider one may resolve it too. The
        // equality read the same as this while every tree-emitted fact happened
        // to be `Surface::Check`, and stopped when the git family arrived with
        // three members cheap enough for the hook and consumers on the tree.
        // A reclassification still MOVES the document rather than needing it
        // edited to agree, which is the property CLOUD-834 established.
        if !fact.class().resolvable_on(crate::facts::Surface::Check) {
            continue;
        }
        let Some(key) = fact.tree_key() else {
            continue;
        };
        // EXHAUSTIVE, NO WILDCARD ARM. A new `Surface::Check` fact fails to
        // compile here rather than going silently unprojected.
        let value = match *fact {
            crate::facts::Fact::Document => serde_json::Value::Object(std::mem::take(&mut parsed)),
            crate::facts::Fact::Tracked => serde_json::json!(tracked),
            crate::facts::Fact::Lines => serde_json::Value::Object(std::mem::take(&mut read_lines)),
            // A path the parser refused is in `missing` rather than here,
            // carrying `unparsed` as its cause — so a module reads could-not-look
            // exactly as it does for a document, and a path present with an
            // empty array is a file that parsed and calls nothing. Those are the
            // two answers CLOUD-310's parse-coverage obligation demands stay
            // apart, and the projection is where they would have collapsed.
            crate::facts::Fact::Invocations => {
                serde_json::Value::Object(std::mem::take(&mut call_sites))
            }
            crate::facts::Fact::Uses => serde_json::Value::Object(std::mem::take(&mut use_edges)),
            // Hook-surface facts, filtered above. Stated as an arm so a
            // reclassification has to come through here.
            crate::facts::Fact::Produced => {
                serde_json::Value::Object(std::mem::take(&mut produced_records))
            }
            // CLOUD-1051. Handed in for `produced`'s reason: the projection is
            // pure, and the read that fills this is the caller's.
            crate::facts::Fact::Records => {
                serde_json::Value::Object(std::mem::take(&mut recorder_lines))
            }
            // The git family (CLOUD-907). `null` rather than a skip when a
            // member is `None`, which is the same invariant the mediated
            // document holds: a key that comes and goes cannot be written
            // against at all, and `not input.tree["git-head"]` is indist-
            // inguishable from a predicate that simply does not hold.
            crate::facts::Fact::GitHead => serde_json::json!(git.head),
            crate::facts::Fact::GitStatus => serde_json::json!(git.status),
            crate::facts::Fact::GitRemote => serde_json::json!(git.remote),
            crate::facts::Fact::GitRef => serde_json::json!(git.refs),
            crate::facts::Fact::GitRange => serde_json::json!(git.ranges),
            crate::facts::Fact::Landing => serde_json::json!(git.landing),
            // The `Cost::Effect` fact (CLOUD-760). THREE-VALUED, and the three
            // answers get three different projections, because collapsing any
            // pair of them is CLOUD-251's vacuous pass:
            //
            // * `IsNot` — no row declared it, so nothing ran.
            // * `CouldNotLook` — the analyser ran and its stream did not parse,
            //   or it could not be run at all.
            //
            //   Both project `null`, and the KEY IS ALWAYS PRESENT. That is the
            //   git family's invariant (CLOUD-907) and it decides here too: a key
            //   that comes and goes cannot be written against at all, because
            //   `not input.tree.symbols` is indistinguishable from a predicate
            //   that simply does not hold. What must never happen is either of
            //   them reaching a module as an empty `sites` list — clean is never
            //   inferred from a stream that failed to parse, and never from an
            //   analyser nobody asked to run.
            //
            // * `Is` — the census, WITH its provenance. Tool, version and the
            //   pinned invocation travel beside the sites because §6 byte-
            //   stability is a claim about a named producer; a bare site list
            //   is not attributable to anything. An EMPTY `sites` here is the
            //   third answer and a real one: the analyser ran and resolved no
            //   site. `null` and `[]` are the pair this projection keeps apart.
            crate::facts::Fact::Symbols => symbols_value(symbols),
            // CLOUD-1059, and `null` here carries BOTH could-not-look conditions
            // the family already collapses: no row declared a delta, and a row
            // declared one whose base did not resolve. A migration gate reads the
            // second as "I could not read the base" rather than "this branch
            // changed nothing", which is the distinction the whole fact exists
            // to keep.
            crate::facts::Fact::BaseDelta => serde_json::json!(git.base_delta),
            crate::facts::Fact::Bypass
            | crate::facts::Fact::Receipts
            | crate::facts::Fact::Keys
            | crate::facts::Fact::Stop
            | crate::facts::Fact::Waived
            | crate::facts::Fact::AgentSourced
            | crate::facts::Fact::Prospective => continue,
        };
        tree.insert(key.to_owned(), value);
    }
    // `missing` is the could-not-look CHANNEL, not a fact — it has no
    // `tree_key`, and it is inserted here rather than in the loop so the
    // correspondence test can subtract exactly one known name instead of
    // guessing which keys are facts.
    tree.insert(String::from("missing"), serde_json::json!(missing));
    let document = serde_json::json!({ "tree": serde_json::Value::Object(tree) });
    // `to_string` on a value this function built cannot fail, and the fallback is
    // an input the evaluator will reject rather than a silent empty tree — which
    // the caller reads as could-not-look, the honest answer if it ever happened.
    (
        serde_json::to_string(&document).unwrap_or_else(|_| String::from("{")),
        causes,
    )
}

/// Evaluate a tree-scoped [`RuleKind::Policy`] row against its bundle.
///
/// Infallible by construction, and that is worth stating rather than inferring
/// from the signature: every way this can fail to decide is a VERDICT here, not
/// an error. A bundle the caller did not load, a declared document the tree
/// lacks, a module that faults — each is could-not-look, which the caller holds
/// rather than resolves. The failures that ARE errors (an unreadable module, an
/// undeclared id, a colliding one) were refused at load, where a config fault
/// belongs.
/// The boundary-acquired inputs arrive as one struct rather than as seven
/// positionals, which is what `RunInputs` already exists for. Enumerating them
/// was affordable while the set was small; CLOUD-760's `symbols` made it the
/// seventh and the arity lint the messenger, and passing the group means the
/// next acquisition row reaches here without touching this signature.
///
/// `tracked` is `inputs.files`: the SUBJECT's path list, and the subject is
/// always the working tree — `--config-from` redirects the policy AUTHORITY
/// (which rules and which module bytes), never what is being judged. So there is
/// no ref branch here and no could-not-look arm for one.
fn policy_rule(
    rule: &Rule,
    inputs: &RunInputs<'_>,
    findings: &mut Vec<Finding>,
) -> Option<NotObserved> {
    let &RunInputs {
        files: tracked,
        documents,
        produced,
        records,
        git,
        symbols,
        bundles,
        ..
    } = inputs;
    let Some(bundle) = bundles.iter().find(|bundle| bundle.id() == rule.id) else {
        // The row enabled a bundle the caller did not load. Not a pass: this
        // surface has nothing to decide with, and reporting clean would be a
        // gate that never ran reading as one that found nothing.
        return Some(NotObserved::RuleSkipped);
    };
    // The row's declared set: literal `documents` plus everything `sources`
    // selects out of the run's one walk (CLOUD-850). A malformed glob was
    // refused at load, so this cannot fail late.
    let Ok(declared) = declared_documents(rule, tracked) else {
        return Some(NotObserved::RuleSkipped);
    };
    // `ok()?` rather than `?`: this function returns `Option<NotObserved>`, and a
    // malformed glob is refused by `validate` before any rule evaluates — so a
    // failure here is a row this surface does not own, treated the same way
    // `declared_documents` is treated a few lines up.
    let declared_line_paths = declared_lines(rule, tracked).ok()?;
    let declared_invocation_paths = declared_invocations(rule, tracked).ok()?;
    let declared_use_paths = declared_uses(rule, tracked).ok()?;
    // A row that declared a selector and matched nothing has not established
    // anything, and saying so is the point: a selector selecting nothing and a
    // tree satisfying the predicate are otherwise the same green.
    //
    // EVERY GLOB COLUMN, not just `sources`, and the omission was live
    // (CLOUD-359). This tested `rule.sources` alone while three more glob
    // spellings had landed beside it — `line_sources` (CLOUD-864),
    // `invocation_sources` and `use_sources`. A row selecting only through one
    // of those, in a tree carrying no such file, ran its module against an empty
    // document instead of being skipped: the module then decides over nothing
    // and whatever it says is a verdict about a tree it never read. Measured
    // here on a fixture repo with no Rust in it.
    //
    // `delta_sources` COUNTS TOO, and leaving it out was live the moment the
    // column landed (CLOUD-1059). The delta is a git fact rather than a
    // glob-selected document, so a row whose only resolved input is the delta
    // read `selected_nothing` as true and skipped — and the case where that
    // happens is precisely the one the row exists for: a migration that deletes
    // the last `mise-tasks/*.sh` and writes no Rust successor leaves both line
    // globs matching nothing, so the gate refusing an unmapped deletion is the
    // gate the deletion switches off. Measured on the fixtures in
    // `crates/batten/tests/shell_retirement.rs`.
    //
    // A resolved delta is what counts, not a non-empty one: an empty delta is
    // the row having looked and found nothing changed, which IS establishing
    // something. `None` is could-not-look and still skips.
    let selectors_declared = !rule.sources.is_empty()
        || !rule.line_sources.is_empty()
        || !rule.invocation_sources.is_empty()
        || !rule.use_sources.is_empty()
        || !rule.delta_sources.is_empty();
    let delta_resolved = !rule.delta_sources.is_empty() && git.base_delta.is_some();
    let selected_nothing = declared.is_empty()
        && declared_line_paths.is_empty()
        && declared_invocation_paths.is_empty()
        && declared_use_paths.is_empty()
        && !delta_resolved;
    if selected_nothing && selectors_declared {
        return Some(NotObserved::RuleSkipped);
    }
    let (input, not_acquired) = tree_document(
        documents,
        &Declared {
            documents: &declared,
            lines: &declared_line_paths,
            invocations: &declared_invocation_paths,
            uses: &declared_use_paths,
        },
        tracked,
        produced,
        records,
        git,
        symbols,
    );
    if !not_acquired.is_empty() {
        // COULD NOT LOOK, and never an empty deny set (CLOUD-251). A bundle
        // handed a document the tree does not carry has not established anything
        // about it, and the store holds the finding rather than resolving it.
        return Some(NotObserved::RuleSkipped);
    }
    let crate::facts::Look::Is(violations) = crate::policy::deny(bundle, &input) else {
        return Some(NotObserved::RuleSkipped);
    };
    for violation in &violations {
        let id = bundle.attribute(violation);
        let severity = rule.severity_for(violation.rule.as_deref());
        if severity == RuleSeverity::Allow {
            continue;
        }
        let (pointer, line) = first_pointer(&violation.subjects);
        findings.push(Finding {
            // THE PREDICATE'S ID, not the row's (CLOUD-832). `waiver::apply`
            // matches on this field, so a waiver names the gate a reader saw
            // rather than the bundle that happens to hold it.
            rule: id.to_owned(),
            severity,
            // THE MODULE'S OWN POINTER WHEN IT GAVE ONE (CLOUD-1050), and the
            // bundle root otherwise.
            //
            // Before the typed ABI a tree finding could only ever point at the
            // bundle, because the module's only channel was prose and prose is
            // not a pointer — so `check` reported `policy/x.rego  some-rule` and
            // left the reader to find the file themselves. A `subjects` entry IS
            // a pointer, which is the whole reason the field is tagged rather
            // than free, so the first path-bearing one is what the finding
            // carries. A class whose subjects are counts or artifacts still
            // falls back to the bundle root, which is the honest pointer when
            // the finding is about a set rather than a file.
            path: pointer.clone().unwrap_or_else(|| {
                rule.bundle
                    .clone()
                    .or_else(|| rule.module.clone())
                    .unwrap_or_else(|| rule.id.clone())
            }),
            line,
            check: rule.settling_check().unwrap_or(Check::Reevaluate),
            remediation: rule.remediation(),
            identity: identity::StoredIdentity::new(
                identity::FindingKind::Scope,
                // KEYED ON `(rule, verdict, subjects)` (CLOUD-1050). It used to
                // be keyed on the module's prose, so rewording a message reset
                // every baseline entry for that predicate while changing nothing
                // it decided. The token and the pointers are what the finding IS,
                // and they move only when the finding does.
                identity::scope_fingerprint(id, &fingerprint_of(violation)),
            ),
        });
    }
    None
}

/// The first subject a violation carries, as a finding's pointer (CLOUD-1050).
///
/// FIRST rather than all of them, because a `Finding` carries one pointer and
/// the ordering of `subjects` is the module's own statement of which matters
/// most. A class with several files to name declares them in the order a reader
/// should follow; picking any other one would silently disagree with that.
///
/// # A path-bearing subject wins, and a count or a name still reaches the reader
///
/// This preferred a path and then gave up, so a class whose only subjects were a
/// COUNT or a NAME rendered as `<module> <rule>` and the subject reached nobody
/// (CLOUD-1051, measured on `prose-only`, whose whole pointer is a count).
/// A dead channel that renders as a clean pointer is the shape this engine
/// argues against everywhere, so the fallback is here rather than a note saying
/// modules should not declare one.
///
/// It rides in `path` because a line-less finding renders as `<path> <rule>` and
/// that is the one field which can carry it without a second output shape — the
/// same reading `ratchet_rule` already takes for its two counts. The rendering is
/// [`crate::verdict::Subject::render`]'s, so a count says the same thing here as
/// it does on the mediated path, and a reader cannot mistake `2 file(s)` for a
/// file they could open.
fn first_pointer(subjects: &[crate::verdict::Subject]) -> (Option<String>, Option<usize>) {
    for subject in subjects {
        match subject {
            crate::verdict::Subject::Line { path, line } => {
                return (Some(path.clone()), usize::try_from(*line).ok());
            }
            crate::verdict::Subject::Path { path } => return (Some(path.clone()), None),
            // Held back for the second pass: a path is the pointer a reader can
            // act on directly, so one anywhere in the list outranks a count at
            // the front of it.
            crate::verdict::Subject::Count { .. } | crate::verdict::Subject::Artifact { .. } => {}
        }
    }
    match subjects.first() {
        Some(subject) => (Some(subject.render()), None),
        None => (None, None),
    }
}

/// The identity ingredient a policy finding is keyed on: its class and its
/// pointers, in order.
///
/// Rendered rather than hashed structurally so the value is readable in a
/// baseline diff — the same reason `scope_fingerprint`'s sibling ingredients are
/// strings. The token comes first because it is what the finding IS; the
/// pointers separate two instances of one class.
fn fingerprint_of(violation: &crate::policy::Violation) -> String {
    let pointers = crate::verdict::render_subjects(&violation.subjects);
    if pointers.is_empty() {
        violation.verdict.clone()
    } else {
        format!("{} {pointers}", violation.verdict)
    }
}

/// Evaluate a [`RuleKind::Ratchet`]: count at the base rev, count in the working
/// tree, and report if the aggregate moved the banned way.
///
/// Both counts use the crate's single glob matcher and the single git entry
/// point; the working-tree side reuses the walk the caller already did. There is
/// no second implementation of any of the three.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `base` names a rev git cannot
/// resolve — never a pass. A ratchet that cannot see its own baseline has not
/// established that the count held.
fn ratchet_rule(
    rule: &Rule,
    root: &Path,
    glob: &str,
    files: &[String],
    matched: &[&String],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    // An `allow` row is configured off. Checked here rather than inherited from
    // the caller's guard, because the ratchet path returns before it.
    if rule.severity() == RuleSeverity::Allow {
        return Ok(());
    }
    let (Some(pattern), Some(direction), Some(base)) = (
        rule.pattern.as_deref(),
        rule.direction,
        rule.base.as_deref(),
    ) else {
        // Unreachable: the census requires all three for this kind.
        return Ok(());
    };

    // The base half, per file rather than summed, so ONE walk answers both the
    // aggregate the direction is judged on and the per-file deltas
    // `retires_with` needs. A row without the column sums this and asks nothing
    // else, which is what makes the column's absence byte-identical to the
    // behaviour before it existed.
    let mut base_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut base_text: BTreeMap<String, String> = BTreeMap::new();
    let retires_with = rule.retires_with.as_deref();
    crate::git::for_each_blob_at_rev(root, base, glob, |path, text| {
        base_counts.insert(path.to_owned(), text.matches(pattern).count());
        // Held only for the columns that read it: a ratchet with neither
        // `retires_with` nor `conserves` must not start buffering the base
        // tree's text. `conserves` is named here as well as `retires_with`
        // because its check no longer runs inside the other's block.
        if retires_with.is_some() || rule.conserves.is_some() {
            base_text.insert(path.to_owned(), text.to_owned());
        }
    })?;
    let base_count: usize = base_counts.values().sum();

    let mut working_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut working_count = 0;
    // Which working files carry an `admits_with` declaration (CLOUD-929).
    // Presence is recorded here rather than buffering every file's text: the
    // admission below asks one boolean per path, and holding the tree's bytes to
    // answer it would give this column the cost `base_text` is careful to charge
    // only to the rows that need it.
    let admits_with = rule.admits_with.as_deref();
    let mut working_declared: BTreeSet<&str> = BTreeSet::new();
    for path in matched {
        let text = fs::read_to_string(root.join(path)).unwrap_or_default();
        let count = text.matches(pattern).count();
        working_count += count;
        working_counts.insert(path.as_str(), count);
        if let Some(token) = admits_with
            && !declared_subject(&text, token).is_empty()
        {
            working_declared.insert(path.as_str());
        }
        // Consequence two of the column (CLOUD-807): EVERY matched file owes a
        // resolvable subject, not merely the ones this change touched. Without
        // it the admission below rests on a header nobody checks, and a suite
        // that outlived its subject is indistinguishable from one that never
        // declared one.
        if let Some(token) = retires_with {
            unresolved_subject(rule, path, &text, token, files, findings);
        }
    }

    // CONSERVATION RUNS BEFORE THE AGGREGATE RETURN, and over names rather than
    // counts (CLOUD-480, found on review of #660). It used to sit inside the
    // admission block below, which the aggregate guard returns before — so a
    // change deleting one case and adding another kept the total level and the
    // deleted case owed no mapping at all. The two questions are different, so
    // only the aggregate finding below stays conditional on
    // `direction.violated`; the reasoning is on `conserve_case_names`.
    //
    // ONE ANSWER TO "DID THE SUBJECT DIE", RESOLVED HERE (CLOUD-1080). Both the
    // aggregate admission below and the `withdrawn` arm inside
    // `conserve_case_names` rest on it, and conservation runs before the aggregate
    // return — so it has to be resolved ahead of both rather than inside either.
    // Two derivations of one git fact is the drift this file already documents
    // elsewhere; the round trip is skipped entirely when nothing decreased.
    let subjects = match retires_with {
        Some(token) => subject_facts(
            root,
            base,
            token,
            &base_counts,
            &working_counts,
            &base_text,
            files,
        )?,
        None => SubjectFacts::default(),
    };

    let fully_mapped = conserve_case_names(
        rule,
        root,
        files,
        &base_counts,
        &base_text,
        &subjects,
        findings,
    );

    if !direction.violated(base_count, working_count) {
        return Ok(());
    }

    // The admission (CLOUD-807). A decrease is bought by the affected files'
    // subjects having DIED — declared at `base`, alive at `base`, absent now.
    // Anything else falls through to the refusal below, so a row that cannot
    // justify its decrease still denies at its own severity.
    //
    // The git fact itself was resolved ABOVE, before `conserve_case_names`,
    // because the `withdrawn` arm reads the same fact and one answer serves both.
    // What is left here is the composition, which is this column's alone: the
    // `fully_mapped` skip is CLOUD-1050's arm and has no bearing on the per-case
    // question.
    let mut blockers: BTreeSet<String> = BTreeSet::new();
    if retires_with.is_some() {
        blockers = retirement_blockers(&subjects, &fully_mapped);
        if blockers.is_empty() {
            // Every affected file's subject died in this same change, or its
            // cases are fully mapped. This is the retirement the `[[waiver]]`
            // used to have to express by switching the whole rule off.
            return Ok(());
        }
    }

    // The admission for an INCREASE (CLOUD-929), the mirror of the block above
    // and deliberately the weaker one. Reasoning is on `undeclared_growth`.
    if admits_with.is_some() {
        blockers.extend(undeclared_growth(
            &base_counts,
            &working_counts,
            &working_declared,
        ));
        if blockers.is_empty() {
            // Every file that grew said why. The surface moved in the refused
            // direction and the change owns that in writing.
            return Ok(());
        }
    }

    ratchet_finding(rule, glob, base_count, working_count, &blockers, findings);
    Ok(())
}

/// One resolution of "did each dying file's declared subject die too", shared by
/// the two columns that ask it (CLOUD-1080).
///
/// `retires_with` asks it to admit an AGGREGATE decrease; `conserves`'s
/// `withdrawn` arm asks it PER CASE. Answering it twice would put a header reader
/// and a tree reader in one decision, disagreeing on exactly the rebase where it
/// counts — the drift CLOUD-1037 already recorded for this same ledger.
///
/// Resolution and composition are deliberately split: this carries only facts, and
/// [`retirement_blockers`] turns them into that column's verdict. The
/// `fully_mapped` skip is CLOUD-1050's and belongs to the composition alone, since
/// it has no bearing on whether a subject died.
#[derive(Debug, Default)]
struct SubjectFacts {
    /// Every DYING path's base-declared subjects. A path present here decreased
    /// and declared at least one subject.
    declared: BTreeMap<String, BTreeSet<String>>,
    /// The dying paths whose base header declared no subject at all.
    undeclared: BTreeSet<String>,
    /// Which of the declared subjects existed at `base`.
    alive_at_base: BTreeSet<String>,
    /// Which of the declared subjects the head tree still carries.
    still_present: BTreeSet<String>,
}

impl SubjectFacts {
    /// Whether every subject `path` declared was alive at `base` and is gone now.
    ///
    /// EVERY subject, not any: a suite declaring two subjects of which one still
    /// stands has work left, and admitting it on the strength of the other is how
    /// a partial retirement passes as a whole one.
    fn died(&self, path: &str) -> bool {
        self.declared.get(path).is_some_and(|subjects| {
            subjects.iter().all(|subject| {
                self.alive_at_base.contains(subject) && !self.still_present.contains(subject)
            })
        })
    }
}

/// Resolve [`SubjectFacts`] for one ratchet run.
///
/// # The base text, never the working one
///
/// A retired file has no working copy to read, and reading the working copy would
/// let a change rewrite its own permission in the commit that spends it.
///
/// # Alive at `base` is the anti-rot term
///
/// Without it a header naming a path that never existed reports "absent from the
/// working tree" and admits the very deletion it was supposed to justify.
fn subject_facts(
    root: &Path,
    base: &str,
    token: &str,
    base_counts: &BTreeMap<String, usize>,
    working_counts: &BTreeMap<&str, usize>,
    base_text: &BTreeMap<String, String>,
    files: &[String],
) -> anyhow::Result<SubjectFacts> {
    let mut facts = SubjectFacts::default();
    for (path, was) in base_counts {
        let now = working_counts.get(path.as_str()).copied().unwrap_or(0);
        if now >= *was {
            continue;
        }
        let subject = base_text
            .get(path)
            .map(|text| declared_subject(text, token))
            .unwrap_or_default();
        if subject.is_empty() {
            facts.undeclared.insert(path.clone());
            continue;
        }
        facts.declared.insert(path.clone(), subject);
    }
    let declared: BTreeSet<String> = facts.declared.values().flatten().cloned().collect();
    // NO DECREASE MEANS NO QUESTION, AND NO ROUND TRIP. This resolution now runs
    // above the aggregate guard, so a ratchet moving in the permitted direction
    // must not start paying for a git read it never used to make.
    if !declared.is_empty() {
        facts.alive_at_base = crate::git::paths_present_at_rev(root, base, &declared)?;
        facts.still_present = files
            .iter()
            .filter(|path| declared.contains(path.as_str()))
            .cloned()
            .collect();
    }
    Ok(facts)
}

/// What stops a DECREASE from being admitted, per CLOUD-807's column.
///
/// Extracted from [`ratchet_rule`] so that function stays under the line lint;
/// the reasoning for each clause is on the clause. Returns the empty set when
/// every affected path answered — which is the admission — and the caller reads
/// that rather than this deciding the rule's verdict, because a `retires_with`
/// row that admits still owes the increase half its own question.
///
/// Pure over [`SubjectFacts`] since CLOUD-1080: the git read moved up to the one
/// resolution both columns share, and what is left here is this column's own
/// composition.
fn retirement_blockers(
    subjects: &SubjectFacts,
    fully_mapped: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut blockers: BTreeSet<String> = BTreeSet::new();
    // THE MAPPED-SUCCESSOR ARM (CLOUD-1050). `retires_with` buys a decrease with
    // a subject that DIED, and that is the right question for a suite whose
    // subject is a shell program the migration deletes. It is the wrong question
    // for a suite whose subject is a `.rego` module the migration KEEPS and
    // rewrites: the module is alive, so the subject-death arm refuses, and the
    // suite — which asserts the refusal text the rewrite just changed — cannot be
    // edited either, because `shell-retirement` refuses editing a bats suite in
    // place. Both doors shut on a deletion whose logic is provably accounted for.
    //
    // So a complete CLOUD-908 ledger is the second admission: every case this
    // change dropped from this path resolved to exactly one arm, naming a target
    // the tree carries, with a reason where `changed` demands one. That is
    // strictly more evidence than subject death, which asks nothing about where
    // the cases went — and it is why this arm is an addition rather than a
    // loosening.
    for path in &subjects.undeclared {
        if !fully_mapped.contains(path) {
            blockers.insert(format!("{SUBJECT_UNDECLARED} {path}"));
        }
    }
    let considered: BTreeSet<&String> = subjects
        .declared
        .iter()
        .filter(|(path, _)| !fully_mapped.contains(path.as_str()))
        .flat_map(|(_, subjects)| subjects)
        .collect();
    for subject in considered {
        if !subjects.alive_at_base.contains(subject) {
            blockers.insert(format!("{SUBJECT_NEVER_EXISTED} {subject}"));
        } else if subjects.still_present.contains(subject) {
            blockers.insert(format!("{SUBJECT_ALIVE} {subject}"));
        }
    }
    blockers
}

/// The refusal a ratchet raises when neither admission answered.
///
/// Extracted alongside [`retirement_blockers`] for the same reason, and it is the
/// half worth keeping whole: every field below carries an argument about what a
/// ratchet finding may and may not say, and splitting them across a call site
/// would separate each from its reason.
fn ratchet_finding(
    rule: &Rule,
    glob: &str,
    base_count: usize,
    working_count: usize,
    blockers: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding {
        // The plain rule id, deliberately: `waiver::apply` matches on this
        // field, so decorating it would make a ratchet the one finding kind
        // no waiver could suppress — and the waiver is the designed hatch
        // for a legitimate reduction.
        rule: rule.id.clone(),
        severity: rule.severity(),
        // The glob plus the two counts. The glob is the tightest honest
        // pointer — the finding is about the whole matched set, not a file,
        // and naming one would misdirect — and the counts ride here because
        // a line-less finding renders as `<path> <rule>`, so this is the one
        // field that can carry them without a second output shape. `git
        // diff` answers *where*; the deleted text itself is payload and
        // never appears (rule 4).
        //
        // A `retires_with` row appends WHY the decrease was not admitted, which
        // the row's §5 asks for: the subject paths are the consumer's own
        // declared config text — the same reading that lets a `document` row
        // report its node path — and they are what a reader needs to find the
        // header again. Never a case name, never a line of the deleted suite.
        path: format!(
            "{glob} {base_count}->{working_count}{}",
            render_blockers(blockers)
        ),
        line: None,
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
        identity: identity::StoredIdentity::new(
            identity::FindingKind::Scope,
            // Keyed on the rule and its glob, never the counts: the same
            // ratchet breaking again is one finding, not a new one per
            // integer pair.
            identity::scope_fingerprint(&rule.id, glob),
        ),
    });
}

/// Which files grew without declaring a reason (CLOUD-929).
///
/// The mirror of `retires_with`'s admission, and deliberately the weaker half.
/// Every file whose own count ROSE — a file absent from `base`, or one already
/// there that grew — owes a declaration in its OWN WORKING TEXT, because a file
/// absent from base has no other copy to read. Its sibling reads base precisely
/// so a change cannot rewrite its own permission; here that is not available, so
/// this admission is a declaration a reviewer reads rather than a proof the
/// engine checked. [`Rule::admits_with`] carries the full argument.
///
/// Per file rather than on the aggregate: a change that adds two programs and
/// declares one has not declared the increase, and summing would let the
/// declared one pay for the silent one.
fn undeclared_growth(
    base_counts: &BTreeMap<String, usize>,
    working_counts: &BTreeMap<&str, usize>,
    working_declared: &BTreeSet<&str>,
) -> BTreeSet<String> {
    let mut blockers = BTreeSet::new();
    for (path, now) in working_counts {
        let was = base_counts.get(*path).copied().unwrap_or(0);
        if *now > was && !working_declared.contains(path) {
            blockers.insert(format!("{GROWTH_UNDECLARED} {path}"));
        }
    }
    blockers
}

/// The paths `text` declares as its subject after `token` (CLOUD-807).
///
/// Every declaring line is read and the paths unioned, rather than the first
/// winning. Two declarations naming different subjects then require BOTH to die,
/// which is the refusing direction: a stray line can only make a retirement
/// harder to buy, never easier.
fn declared_subject(text: &str, token: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix(token))
        .flat_map(str::split_whitespace)
        .map(ToOwned::to_owned)
        .collect()
}

/// Which arm claimed a case, and what that arm therefore owes (CLOUD-908).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// The same assertion, in a new home.
    Carried,
    /// A general property elsewhere covers it now.
    Subsumed,
    /// It diverges deliberately, and owes a reason for that.
    Changed,
    /// Nothing replaces it, because the subject is gone (CLOUD-1080). Owes a
    /// reason and names no target — there is no successor to name — and is
    /// admissible only where the dying file's declared subject died too.
    Withdrawn,
}

impl Arm {
    /// The token this arm is reported under, so a refusal names the arm the
    /// author wrote rather than a variant name only this crate knows.
    fn as_str(self) -> &'static str {
        match self {
            Arm::Carried => "carried",
            Arm::Subsumed => "subsumed",
            Arm::Changed => "changed",
            Arm::Withdrawn => "withdrawn",
        }
    }

    /// Whether this arm names a successor the head tree must carry.
    ///
    /// Three of the four do, and the exception is the whole point of the fourth:
    /// a withdrawal has no successor, so demanding a resolvable target would
    /// force the author back to the false `subsumed` this arm exists to replace.
    const fn owes_a_target(self) -> bool {
        !matches!(self, Arm::Withdrawn)
    }
}

/// One arm's claim on one case: where it was written, and what it named.
#[derive(Debug, Clone)]
struct Claim {
    arm: Arm,
    /// The file the arm was written in — the pointer a refusal about the arm
    /// carries, because that is where the fix goes.
    path: String,
    line: usize,
    /// The successor the arm names, which must resolve in the head tree.
    target: String,
    /// Everything after the target. Only [`Arm::Changed`] owes this.
    reason: String,
}

/// Every claim the head tree makes, keyed by the case name it claims.
///
/// A `Vec` per name rather than one claim, deliberately: "exactly one arm" is a
/// refusal this has to be able to REPORT, and a map that kept only the last
/// claim would silently admit the case it exists to catch.
#[derive(Debug, Default)]
struct ClaimedCases {
    claims: BTreeMap<String, Vec<Claim>>,
}

/// What one file's deletion is judged against: the vocabulary, the head tree's
/// claims, and the head tree's paths.
///
/// Grouped because they travel together and mean one thing — "the mapping" — and
/// because eight loose parameters is what `too_many_arguments` is for. The
/// alternative was an `#[allow]`, which would have kept a signature nobody can
/// read at a call site.
struct Mapping<'a> {
    conserves: &'a Conserves,
    claimed: &'a ClaimedCases,
    files: &'a [String],
    /// Whether THIS path's declared subject died in this change (CLOUD-1080).
    ///
    /// Passed in rather than derived here, and that is the load-bearing part: the
    /// aggregate admission already asks git the same question, and two readers of
    /// "did the subject die" would be the drift this repo keeps paying for — one
    /// answering by header and one by tree, disagreeing on exactly the rebase that
    /// matters. [`subject_facts`] answers it once and both consumers read that.
    subject_died: bool,
}

/// Read every arm the head tree declares, bounded by `declared_in`.
///
/// # Bounded by declaration, never an ambient walk
///
/// `files` is the head tree's own path list, already in hand, and `declared_in`
/// narrows it before a single file is opened. An unreadable file contributes
/// nothing rather than failing the scan: it cannot be a successor a mapping
/// names, and a mapping that could not be read reports through the unmapped
/// cases it fails to claim — which is the refusing direction.
fn claimed_cases(root: &Path, conserves: &Conserves, files: &[String]) -> ClaimedCases {
    let Ok(selector) = Selector::new(&conserves.declared_in) else {
        // Unreachable: `validate_conserves` compiled this at load. Reached only
        // by a caller that skipped validation, and the safe reading is "no arms",
        // which refuses every deletion rather than admitting one.
        return ClaimedCases::default();
    };
    // The fourth arm is included only where the row declares it, so a row without
    // the column reads exactly the three tokens it always did.
    let mut arms = vec![
        (Arm::Carried, conserves.carried.as_str()),
        (Arm::Subsumed, conserves.subsumed.as_str()),
        (Arm::Changed, conserves.changed.as_str()),
    ];
    if let Some(token) = conserves.withdrawn.as_deref() {
        arms.push((Arm::Withdrawn, token));
    }
    let mut claimed = ClaimedCases::default();
    for path in files.iter().filter(|path| selector.matches(path)) {
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            for &(arm, token) in &arms {
                let Some(rest) = trimmed.strip_prefix(token) else {
                    continue;
                };
                let Some((case, tail)) = opened_case(rest, &conserves.close) else {
                    // An arm whose case name never closes claims nothing, which
                    // leaves the case it meant to claim unmapped. Reported there
                    // rather than here: one refusal per unconserved case, at the
                    // case, is what §5 asks for.
                    continue;
                };
                let mut words = tail.split_whitespace();
                let target = words.next().unwrap_or_default().to_owned();
                let reason = words.collect::<Vec<&str>>().join(" ");
                claimed.claims.entry(case).or_default().push(Claim {
                    arm,
                    path: path.clone(),
                    line: index + 1,
                    target,
                    reason,
                });
            }
        }
    }
    claimed
}

/// Every case name `text` declares, for comparing two revs of one file.
///
/// A name that never closes is not collected: it is reported where it is, by the
/// scan, rather than made to look like a survivor here.
fn case_names(text: &str, conserves: &Conserves) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix(&conserves.case))
        .filter_map(|rest| quoted_case(rest, &conserves.close))
        .map(|(case, _)| case)
        .collect()
}

/// The same, for an arm, whose opening delimiter has NOT been consumed.
///
/// A case's own token ends with the opener — `@test "` — so the name starts
/// immediately. An arm's token does not: `// carried:` is followed by whitespace
/// and then the delimiter, because an arm has to spell the case the same way the
/// case spells itself, and that spelling includes its quotes. So the opener is
/// skipped here and the same reader runs underneath.
///
/// One field for both delimiters is what makes this possible, and it is why the
/// column carries `close` rather than an open/close pair: a case name is
/// symmetrically quoted in every language that has this problem.
fn opened_case(rest: &str, close: &str) -> Option<(String, String)> {
    quoted_case(rest.trim_start().strip_prefix(close)?, close)
}

/// The case name `rest` opens with, and whatever follows its closing delimiter.
///
/// `rest` is the text after a case's token — which ends with the opener — so the
/// name runs to the first `close`. `None` when it never closes: an unterminated
/// name is not a name, and guessing where it ended is how a mapping starts
/// matching prose.
fn quoted_case(rest: &str, close: &str) -> Option<(String, String)> {
    let (case, tail) = rest.split_once(close)?;
    let case = case.trim();
    if case.is_empty() {
        return None;
    }
    Some((case.to_owned(), tail.to_owned()))
}

/// Raise a finding per case in `text` that the head tree does not conserve.
///
/// # Pointer-only (non-negotiable rule 4)
///
/// Two pointers, and which one a finding carries is the whole of its usefulness.
/// An UNMAPPED case points at the dying suite and the line the case was declared
/// on at `base` — a path that no longer exists in the head tree, which is exactly
/// where the reader has to look. A BAD ARM points at the arm's own file and line,
/// because that is where the fix goes. Neither carries the case body, the
/// deleted assertion, or the reason text.
fn unconserved_cases(
    rule: &Rule,
    path: &str,
    text: &str,
    survivors: &str,
    mapping: &Mapping<'_>,
    findings: &mut Vec<Finding>,
) {
    let Mapping {
        conserves,
        claimed,
        files,
        subject_died,
    } = mapping;
    // What the head tree still declares under this path. A deletion is judged on
    // what it DROPPED: a suite that lost one case of twenty owes one arm, and
    // demanding twenty would make every partial deletion unbuyable — a gate that
    // cannot be satisfied gets switched off, which is how coverage evaporates by
    // a different route than the one this column closes.
    let alive: BTreeSet<String> = case_names(survivors, conserves);
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix(&conserves.case) else {
            continue;
        };
        let line_number = index + 1;
        let Some((case, _)) = quoted_case(rest, &conserves.close) else {
            // A case whose own name never closes cannot be claimed by anything,
            // because no arm could spell it. That is a defect in the DYING file,
            // reported where it is rather than counted as unmapped.
            // No case name exists here — the name failing to close IS the defect — so
            // the line is the only discriminator this site can offer.
            push_case_finding(
                rule,
                path,
                line_number,
                &line_number.to_string(),
                CASE_UNREADABLE,
                findings,
            );
            continue;
        };
        if alive.contains(&case) {
            continue;
        }
        // THE SUITE-QUALIFIED ARM IS TRIED FIRST, then the bare one — the same
        // resolution order `mise-tasks/replay.sh` uses over the same arms, because
        // one ledger with two readers and two grammars is a ledger that reports
        // different things to different gates.
        //
        // A case TITLE is not unique across suites, and the two arms of one tool
        // are the common case rather than the exotic one: retiring CLOUD-312's row
        // 2 brought a suite sharing four titles with row 1's, whose arms were
        // already landed and bare. Without this, a qualified arm was a key nothing
        // looked up, so thirteen conserved cases read as unmapped while the
        // fourteenth — the one whose title happened to have a bare arm from the
        // OTHER suite — resolved by borrowing it. Both directions of that are
        // wrong, and the borrow is the worse one.
        //
        // Bare stays supported, so no landed block has to be rewritten.
        let suite = std::path::Path::new(path)
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        let qualified = format!("{suite}::{case}");
        let claims = claimed
            .claims
            .get(&qualified)
            .or_else(|| claimed.claims.get(&case))
            .map_or(&[][..], Vec::as_slice);
        match claims {
            [] => push_case_finding(rule, path, line_number, &case, CASE_UNMAPPED, findings),
            [claim] => {
                // The arm resolved. Now what it owes, which differs by arm: three
                // owe a target this tree has, `changed` owes a reason too, and
                // `withdrawn` owes a reason and a DEAD SUBJECT instead of a target.
                if !claim.arm.owes_a_target() {
                    // THE CONDITION THAT KEEPS THIS NARROWER THAN A WAIVER
                    // (CLOUD-1080). A withdrawal is only honest where the subject
                    // went with it; over a subject still standing this arm would be
                    // a blanket permission to delete cases, which is the thing the
                    // column exists to refuse. `*subject_died` comes from
                    // `subject_facts`, the same read the aggregate admission uses.
                    if *subject_died {
                        if claim.target.trim().is_empty() && claim.reason.trim().is_empty() {
                            // No target to name, so the whole tail is the reason —
                            // and it is owed, because "nothing replaces this" is a
                            // claim a reader has to be able to check.
                            push_case_finding(
                                rule,
                                &claim.path,
                                claim.line,
                                &case,
                                CASE_WITHDRAWAL_UNEXPLAINED,
                                findings,
                            );
                        }
                    } else {
                        push_case_finding(
                            rule,
                            &claim.path,
                            claim.line,
                            &case,
                            CASE_WITHDRAWN_SUBJECT_ALIVE,
                            findings,
                        );
                    }
                } else if !files.iter().any(|have| have == &claim.target) {
                    push_case_finding(
                        rule,
                        &claim.path,
                        claim.line,
                        &case,
                        CASE_TARGET_MISSING,
                        findings,
                    );
                } else if claim.arm == Arm::Changed && claim.reason.trim().is_empty() {
                    push_case_finding(
                        rule,
                        &claim.path,
                        claim.line,
                        &case,
                        CASE_CHANGE_UNEXPLAINED,
                        findings,
                    );
                }
            }
            // More than one arm. Reported at the SECOND claim rather than the
            // first: the first is the one that was probably right, and pointing
            // at it would send the reader to the line they should keep.
            [_, extra, ..] => push_case_finding(
                rule,
                &extra.path,
                extra.line,
                &case,
                &format!("{CASE_CLAIMED_TWICE}:{}", extra.arm.as_str()),
                findings,
            ),
        }
    }
}

/// Demand a mapping for every case name the head tree dropped (CLOUD-908), over
/// every file the base carried.
///
/// **Above the aggregate guard, and counting nothing, because of a defect found
/// on review of #660** (CLOUD-480). This ran inside `retires_with`'s admission
/// block, below `direction.violated`'s early return, and only for files whose
/// count had fallen. Two evasions followed from that, and the second is why the
/// count is gone entirely:
///
/// * A change deleting one case and adding another kept the aggregate level, so
///   the guard saw no violation and the deleted case owed no mapping.
/// * RENAMING a case keeps the per-file count level too, so a per-file
///   `now < was` guard — the obvious repair — still admits it. The count was only
///   ever a proxy: [`unconserved_cases`] already compares the base's case NAMES
///   against the head's, which is the thing being conserved. A rename is a
///   deletion plus an addition, and the deletion half owes an arm like any other.
///
/// So every file the base carried is asked, and a file whose names are unchanged
/// answers in a set comparison and raises nothing. The aggregate direction is a
/// different question — the SUITE's size — and stays conditional on the ratchet
/// firing; this one is about whether each dropped name has a successor somebody
/// named.
fn conserve_case_names(
    rule: &Rule,
    root: &Path,
    files: &[String],
    base_counts: &BTreeMap<String, usize>,
    base_text: &BTreeMap<String, String>,
    subjects: &SubjectFacts,
    findings: &mut Vec<Finding>,
) -> BTreeSet<String> {
    let mut fully_mapped = BTreeSet::new();
    let Some(conserves) = rule.conserves.as_ref() else {
        return fully_mapped;
    };
    // Read ONCE for the whole scan rather than per file, and lazy: a change that
    // dropped no case name reads no successor at all.
    let mut arms: Option<ClaimedCases> = None;
    for path in base_counts.keys() {
        let Some(text) = base_text.get(path) else {
            continue;
        };
        let claimed = match arms.as_ref() {
            Some(claimed) => claimed,
            None => arms.insert(claimed_cases(root, conserves, files)),
        };
        // The head copy, if the file survived. A PARTIAL deletion owes a mapping
        // for the cases it dropped and nothing for the ones still standing, so
        // the surviving names have to be read rather than assumed absent.
        let survivors = fs::read_to_string(root.join(path)).unwrap_or_default();
        let mapping = Mapping {
            conserves,
            claimed,
            files,
            subject_died: subjects.died(path),
        };
        // PER PATH, so the mapped-successor arm below can ask about one file
        // (CLOUD-1050). A path whose every dropped case resolved to exactly one
        // well-formed arm has had its logic accounted for, which is a different
        // question from whether its SUBJECT died — and it is the question a
        // migration can actually answer when the subject is a `.rego` module
        // that is still very much alive.
        let before = findings.len();
        unconserved_cases(rule, path, text, &survivors, &mapping, findings);
        if findings.len() == before {
            fully_mapped.insert(path.clone());
        }
    }
    fully_mapped
}

/// File one mapping refusal, keyed so the same case reported twice is one
/// finding rather than a new one per run.
///
/// **`subject` is the CASE NAME, never the line** (CLOUD-480, found on review).
/// The preimage carried `line`, which contradicts [`Finding::identity`]'s own
/// rule — *"position is deliberately not an input: `line` moves when a neighbour
/// is inserted and this does not, which is what lets a store recognise the same
/// defect across an edit"* — and the two sibling sites, `unresolved_subject` and
/// `document_in_file`, both agree with that doc. The consequence was a waiver
/// written against one unmapped case silently ceasing to match the moment any
/// line was inserted above it in the dying file. The case name is what separates
/// two refusals in one file, and unlike the line it does not move.
///
/// The one site with no case name is `case-unreadable`, where the name failing to
/// close is the defect itself; it passes its line, because a file offering no
/// stable name to key on offers this function nothing better.
fn push_case_finding(
    rule: &Rule,
    path: &str,
    line: usize,
    subject: &str,
    reason: &str,
    findings: &mut Vec<Finding>,
) {
    let Ok(default) = identity::code_fingerprint(
        &rule.id,
        path,
        &format!("conserves {reason} {subject}"),
        identity::SpanNormalization::Verbatim,
    ) else {
        return;
    };
    findings.push(Finding {
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: path.to_owned(),
        line: Some(line),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
    });
}

/// A deleted case that nothing in the head tree claims — the defect CLOUD-908
/// exists for, and the one `retires_with` alone admits silently.
const CASE_UNMAPPED: &str = "case-unmapped";

/// A case whose own declaration never closes its name, so no arm could spell it.
const CASE_UNREADABLE: &str = "case-unreadable";

/// An arm naming a successor this tree does not have.
const CASE_TARGET_MISSING: &str = "case-target-missing";

/// One case claimed by more than one arm, so "exactly one" does not hold.
const CASE_CLAIMED_TWICE: &str = "case-claimed-twice";

/// A `changed` arm with no reason, which is the arm's whole obligation.
const CASE_CHANGE_UNEXPLAINED: &str = "case-change-unexplained";

/// A `withdrawn` arm over a subject the head tree still carries (CLOUD-1080).
///
/// The refusal that keeps the arm narrower than the waiver it replaces: without
/// it, "nothing replaces this" would admit deleting cases whose subject is still
/// standing, which is a blanket permission wearing a ledger entry's clothes.
const CASE_WITHDRAWN_SUBJECT_ALIVE: &str = "case-withdrawn-subject-alive";

/// A `withdrawn` arm with no reason. It names no target, so the reason is the
/// only thing a reader can check the claim against.
const CASE_WITHDRAWAL_UNEXPLAINED: &str = "case-withdrawal-unexplained";

/// Raise a finding when `path` does not declare a subject that still resolves.
///
/// # Pointer-only (non-negotiable rule 4)
///
/// The finding carries the file and the LINE OF THE DECLARATION — so the dead
/// path a reader needs is the line the pointer already lands on, and nothing of
/// the suite's own content has to travel to say it. A file with no declaration
/// at all points at line 1, where the header belongs.
fn unresolved_subject(
    rule: &Rule,
    path: &str,
    text: &str,
    token: &str,
    files: &[String],
    findings: &mut Vec<Finding>,
) {
    let declaration = text
        .lines()
        .enumerate()
        .find(|(_, line)| line.starts_with(token));
    let (line, reason) = match declaration {
        None => (1, SUBJECT_UNDECLARED),
        Some((index, _)) => {
            let subject = declared_subject(text, token);
            if subject.is_empty() {
                (index + 1, SUBJECT_UNDECLARED)
            } else if subject
                .iter()
                .all(|named| files.iter().any(|have| have == named))
            {
                return;
            } else {
                // The header rotted into a lie: it names a path this tree no
                // longer has. That is the row's §7(c) — a suite outliving its
                // subject — caught by the same resolution that catches a
                // missing header, because they are the same defect.
                (index + 1, SUBJECT_UNRESOLVABLE)
            }
        }
    };
    let Ok(default) = identity::code_fingerprint(
        &rule.id,
        path,
        &format!("{token} {reason}"),
        identity::SpanNormalization::Verbatim,
    ) else {
        return;
    };
    findings.push(Finding {
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: path.to_owned(),
        line: Some(line),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
    });
}

/// Render why a decrease was refused, bounded and sorted.
///
/// Sorted because the report is byte-stable across runs in both channels, and
/// a `BTreeSet` iterated in order is what makes that a property of the type
/// rather than of the walk. Bounded because a change deleting many suites at
/// once would otherwise put an unbounded list in one finding — the same reading
/// `cardinality_cap` applies one level up, at the scale this field can carry.
fn render_blockers(blockers: &BTreeSet<String>) -> String {
    if blockers.is_empty() {
        return String::new();
    }
    let shown: Vec<&str> = blockers
        .iter()
        .take(MAX_BLOCKERS_REPORTED)
        .map(String::as_str)
        .collect();
    let rest = blockers.len().saturating_sub(shown.len());
    let more = if rest == 0 {
        String::new()
    } else {
        format!(" +{rest} more")
    };
    format!(" [{}{more}]", shown.join(", "))
}

/// An affected file that declared no subject, so nothing bought its decrease.
const SUBJECT_UNDECLARED: &str = "subject-undeclared";

/// A file whose count ROSE without declaring why, so nothing bought its increase
/// (CLOUD-929). Named for the movement rather than for a subject, because this
/// column's declaration is a reason and not a path.
const GROWTH_UNDECLARED: &str = "growth-undeclared";

/// A declared subject that is still present, so the suite still has work to do.
const SUBJECT_ALIVE: &str = "subject-alive";

/// A declared subject that was not a blob at `base` — a header that was already
/// a lie before this change, and which would otherwise admit any deletion.
const SUBJECT_NEVER_EXISTED: &str = "subject-never-existed";

/// A declared subject this tree no longer has, under a suite that survived it.
const SUBJECT_UNRESOLVABLE: &str = "subject-unresolvable";

/// How many refusal reasons one ratchet finding names before it summarises.
const MAX_BLOCKERS_REPORTED: usize = 3;

/// The argument a `check` template uses to mark where the matched paths go.
pub const FILES_PLACEHOLDER: &str = "{{files}}";

/// The upper bound, in bytes, on the matched paths handed to one invocation.
///
/// Kept well under every platform's real argv limit (Windows' ~32 KiB command
/// line is the tightest), so a large match set is split across independent
/// invocations instead of overflowing. Batching is invisible to the predicate:
/// a non-zero exit in *any* batch is a violation — and invisible to the
/// **count** too, since [`dedup_scoped`] collapses the one finding per batch a
/// failing rule would otherwise emit (CLOUD-396).
pub const MAX_FILES_BYTES: usize = 16_384;

/// Run a [`RuleKind::Command`] rule over its matched paths.
///
/// If the template contains [`FILES_PLACEHOLDER`], the paths are substituted at
/// that position, batched under [`MAX_FILES_BYTES`]; otherwise the command runs
/// once and self-discovers its own inputs (the glob still gated it).
fn command_rule(
    rule: &Rule,
    root: &Path,
    matched: &[&String],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let template = rule.check.as_deref().ok_or_else(|| {
        UsageError::raise(format!(
            "rule {}: kind \"command\" requires `check`",
            rule.id
        ))
    })?;
    let tokens: Vec<&str> = template.split_whitespace().collect();
    let Some((program, args)) = tokens.split_first() else {
        return Err(UsageError::raise(format!(
            "rule {}: `check` must not be empty",
            rule.id
        )));
    };

    if !args.contains(&FILES_PLACEHOLDER) {
        // Self-discovering form: one invocation, no paths passed.
        run_once(rule, root, program, args, &[], findings)?;
        return Ok(());
    }

    for batch in batches(matched) {
        run_once(rule, root, program, args, &batch, findings)?;
    }
    Ok(())
}

/// Split `matched` into groups whose joined byte length stays under
/// [`MAX_FILES_BYTES`]. Order is preserved, so batching is deterministic and the
/// resulting findings stay byte-stable (§6).
pub(crate) fn batches<'a>(matched: &[&'a String]) -> Vec<Vec<&'a str>> {
    let mut batches = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut bytes = 0usize;
    for path in matched {
        let len = path.len() + 1;
        // Always place at least one path per batch, so a single path longer
        // than the bound still runs rather than looping forever.
        if !current.is_empty() && bytes + len > MAX_FILES_BYTES {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        current.push(path.as_str());
        bytes += len;
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// The interpreter a `#!` line names, resolved to something PATH can find.
///
/// CLOUD-617. `CreateProcess` runs PE images and does not read `#!`, so a
/// checker written as a shell script — the ordinary shape for the extension
/// surface CLOUD-88 calls universal — cannot be spawned on Windows at all. The
/// kernel does this for us on Unix; this is that resolution, done by hand, for
/// the platform whose loader will not.
///
/// Returns the interpreter and any single argument the shebang carries, e.g.
/// `#!/usr/bin/awk -f` -> `["awk", "-f"]`. Two rules, both deliberate:
///
///   * **By basename.** `/bin/sh` is not a path that can exist on Windows, so
///     resolving the literal string is guaranteed to fail; the basename is the
///     part PATH can answer for.
///   * **`env` is unwrapped, never run.** `#!/usr/bin/env python3` names
///     `python3`; `env` is the indirection being resolved, not the program.
///
/// `None` for anything that is not a shebang — no `#!`, unreadable, or a binary
/// whose first bytes merely look like text. The caller must then report the
/// original spawn error unchanged: this may only ever turn a failure into a
/// success, never one failure into a different one.
pub(crate) fn shebang_interpreter(path: &Path) -> Option<Vec<String>> {
    // Two bytes of prefix, then a bounded line. A binary file is not read into
    // memory to discover it is binary.
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 256];
    let read = std::io::Read::read(&mut file, &mut head).ok()?;
    let head = head.get(..read)?;
    let line = head.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    // `trim_end` and not just `trim_end_matches('\r')`: a CRLF checkout is the
    // reason this file's own gates had to be fixed (CLOUD-612), and a trailing
    // `\r` welded to the interpreter name resolves as "not on PATH", which is
    // the same failure wearing a misleading message.
    let line = line.strip_prefix("#!")?.trim();
    let mut words = line.split_whitespace();
    let first = words.next()?;
    let program = Path::new(first).file_name()?.to_str()?;
    let mut resolved = Vec::new();
    if program == "env" {
        // `env` with no program after it names nothing to run.
        resolved.push(words.next()?.to_owned());
    } else {
        resolved.push(program.to_owned());
    }
    resolved.extend(words.map(str::to_owned));
    Some(resolved)
}

/// The first entry on `PATH` that is `program`, bare or under an executable
/// extension.
///
/// **The bare name and the extensions, not one or the other**, and the reason is
/// a correction rather than a preference. This started as a verbatim lookup on
/// the theory that mise installs extensionless binaries, which the tenth Windows
/// run of CLOUD-113 disproved: `where.exe hk` resolved
/// `…\installs\hk\1.54.0\hk.exe`, a proper `.exe`, so a verbatim search could
/// never have found it and the fallback could never have fired. A lookup written
/// for one spelling is a lookup that answers only when that guess was right.
///
/// So it tries both, which also makes the function answer the question its
/// caller actually has — *is this program on PATH under any name Windows would
/// run* — instead of a narrower one that happens to be cheap.
///
/// A `program` carrying a separator is not a PATH lookup at all and is left
/// alone. `None` leaves the caller reporting the original spawn error, the
/// one-way discipline the shebang fallback keeps.
pub(crate) fn on_path_verbatim(program: &str) -> Option<std::path::PathBuf> {
    lookup_verbatim(program, &std::env::var_os("PATH")?)
}

/// The executable extensions to try after the bare name, lowercase and without
/// the leading dot handling `PATHEXT` would need.
///
/// Read from `PATHEXT` when it is set, because a host may add to it; the default
/// is what Windows ships. Empty on Unix by construction — the variable is unset
/// there, and the bare name is the only spelling — so this costs a lookup that
/// finds what a direct spawn already would.
fn executable_extensions() -> Vec<String> {
    let Some(raw) = std::env::var_os("PATHEXT") else {
        return Vec::new();
    };
    raw.to_string_lossy()
        .split(';')
        .map(|ext| ext.trim().to_owned())
        .filter(|ext| !ext.is_empty())
        .collect()
}

/// [`on_path_verbatim`] over a supplied `PATH`, which is the whole of its
/// decision.
///
/// Split out so the case can be tested without mutating the process
/// environment: `unsafe` is forbidden here and `set_var` is unsafe, so a test
/// that reached for the real variable could not be written at all. This is the
/// `markers::scannable` shape the Rust rules prescribe — test the decision, not
/// a conclusion drawn over a precondition the suite cannot create.
fn lookup_verbatim(program: &str, path: &std::ffi::OsStr) -> Option<std::path::PathBuf> {
    lookup_on(program, path, &executable_extensions())
}

/// [`lookup_verbatim`] over a supplied extension list too, so the Windows
/// spelling is exercised on any host.
///
/// Directory-major: every spelling is tried in one PATH entry before moving to
/// the next, which is the order Windows itself resolves in. Trying the bare name
/// across all of PATH first would let a distant `hk` shadow a near `hk.exe`.
fn lookup_on(
    program: &str,
    path: &std::ffi::OsStr,
    extensions: &[String],
) -> Option<std::path::PathBuf> {
    if program.contains('/') || program.contains('\\') {
        return None;
    }
    for dir in std::env::split_paths(path) {
        let bare = dir.join(program);
        if bare.is_file() {
            return Some(bare);
        }
        for extension in extensions {
            // LOWERCASED, and that is what makes this testable rather than a
            // Windows-only article of faith. `PATHEXT` ships uppercase
            // (`.COM;.EXE;.BAT;.CMD`) while the file is `hk.exe`; Windows folds
            // case so either spelling matches there, and a case-sensitive
            // filesystem matches neither unless one is chosen. Choosing the
            // lower one costs nothing on Windows and lets the case run on Linux.
            let candidate = dir.join(format!("{program}{}", extension.to_lowercase()));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Whether an OS spawn error means "this file is not an executable image",
/// which is the one failure a shebang can rescue.
///
/// Raw codes rather than [`std::io::ErrorKind`]: both of these still map to
/// `Uncategorized` on stable, which is not matchable.
pub(crate) fn is_not_an_executable_image(err: &std::io::Error) -> bool {
    // 193 = ERROR_BAD_EXE_FORMAT (Windows), 8 = ENOEXEC (Unix).
    matches!(err.raw_os_error(), Some(193 | 8))
}

/// Spawn `program`, resolving the two ways Windows refuses a program a shell
/// would have run.
///
/// **One ladder, shared by every spawning kind** (CLOUD-617). `command`,
/// `secrets` and `judge` each spawn a program a config names, so each meets the
/// same two refusals, and three copies of the recovery is three chances for one
/// of them to be a step short. This is that recovery, once:
///
///   1. **Spawn it directly.** On Unix this is the whole function — the kernel
///      resolves `PATH` and reads `#!` itself, so neither rung below fires for a
///      well-formed program.
///   2. **`NotFound` → look `PATH` up by hand.** `CreateProcess` appends the
///      `PATHEXT` extensions and never tries the bare name, so an extensionless
///      executable is invisible to it while a shell finds it. Spawn what the
///      lookup found, by absolute path, which `CreateProcess` takes as given.
///   3. **Not an executable image → read the `#!`.** `CreateProcess` runs PE
///      images and does not read a shebang, so a shell-script checker — the
///      ordinary shape for the extension surface CLOUD-88 calls universal —
///      cannot be spawned at all. Resolve the interpreter and pass the script to
///      it as an argument.
///
/// **Rungs 2 and 3 compose, and that is the fix rather than a tidy-up.** They
/// were written as two independent `if`s over one program string, so each could
/// only rescue what it saw first: a *root-relative* script reached rung 3 and a
/// *`PATH`* binary reached rung 2, while a bare name resolving on `PATH` to an
/// extensionless script — `#!/bin/sh` with no suffix, which is what a stub
/// installed into a `bin/` on `PATH` looks like — needed both and got neither.
/// Rung 2 found the file, rung 3 then looked for a shebang at `root/<program>`,
/// where nothing was. Measured on the eighteenth Windows run of CLOUD-113:
/// `judge_kind` failed 7 of 14 with `cannot run judge program 'judge-stub'`,
/// every case reporting a plumbing failure in place of its subject. Threading
/// the resolved path from 2 into 3 is what makes the ladder a ladder.
///
/// `root` is **the directory a relative program name resolves against**, which
/// is what rung 3 reads the `#!` from when rung 2 found nothing. A caller that
/// sets `current_dir` passes that; one that inherits the working directory
/// passes `Path::new(".")`, since that is where its own spawn will look. `None`
/// is for a caller whose program is already absolute, where a relative name
/// cannot arise — never a shrug, because a wrong directory here means reading a
/// shebang out of a file the spawn never referred to.
///
/// `spawn` receives the program to run and a prefix of arguments to place before
/// the caller's own — the interpreter's flags and the script path, when rung 3
/// fires, and empty otherwise.
///
/// **A rung's own failure is never what gets reported.** Rung 3 reports nothing
/// of its own — an unreadable script, no `#!`, an interpreter that is itself
/// missing all leave the refusal that reached it standing — because `sh: not
/// found` in place of `judge-stub: not found` sends the reader to the wrong
/// missing program. Rung 2 is the one place the error advances, and only because
/// it advances toward the file: once the lookup has found `<dir>/judge-stub`,
/// "not an executable image" is a truer account of that path than "not found on
/// PATH", which is now false.
pub(crate) fn spawn_resolving<T>(
    root: Option<&Path>,
    program: &str,
    spawn: impl FnMut(&str, &[&str]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    spawn_resolving_on(
        std::env::var_os("PATH").as_deref(),
        root,
        program,
        &executable_extensions(),
        spawn,
    )
}

/// [`spawn_resolving`] over a supplied `PATH` and extension list.
///
/// The same seam, and for the same reason, as [`lookup_verbatim`] under
/// [`on_path_verbatim`]: `unsafe` is forbidden here and `set_var` is unsafe, so
/// a test that reached for the real environment could not be written at all.
/// What this exposes is the part that decides — *which rung fires, in what
/// order, over which path* — which is exactly the composition that was missing
/// when the two rungs were independent `if`s. Testing it here means the Windows
/// ladder is falsifiable on a Linux host rather than only on a runner.
fn spawn_resolving_on<T>(
    path: Option<&std::ffi::OsStr>,
    root: Option<&Path>,
    program: &str,
    extensions: &[String],
    mut spawn: impl FnMut(&str, &[&str]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let first = match spawn(program, &[]) {
        Ok(ok) => return Ok(ok),
        Err(err) => err,
    };

    // Rung 2. The resolved path is kept rather than discarded on failure: it is
    // the only handle rung 3 has on the file, since the name that reached us is
    // one `CreateProcess` could not resolve.
    let mut found = None;
    let mut latest = first;
    if latest.kind() == std::io::ErrorKind::NotFound
        && let Some(path) = path.and_then(|path| lookup_on(program, path, extensions))
        && let Some(as_str) = path.to_str()
    {
        match spawn(as_str, &[]) {
            Ok(ok) => return Ok(ok),
            Err(err) => {
                found = Some(path.clone());
                latest = err;
            }
        }
    }

    // Rung 3, over whichever path is known to point at the file — which is
    // exactly the path the spawn referred to, and never a guess at one:
    //
    //   * what rung 2 resolved, when it resolved something;
    //   * the program itself, when it is already absolute — `secrets` spawns the
    //     provision cache's binary that way, and reading anything else would be
    //     reading a different file;
    //   * the program under `root`, when it is relative and a root is known.
    //
    // A bare name rung 2 could not find falls through with nothing, because
    // joining it to `root` would name a file the spawn never referred to.
    //
    // The absolute arm is not hypothetical: it was missing for one run, and the
    // whole of `secrets` went with it — CLOUD-113's nineteenth Windows run had
    // four `cli.rs` cases reporting `%1 is not a valid Win32 application` over
    // the fixture's seeded `#!/bin/sh` stub scanner, a file the ladder had every
    // means to run and no path to read.
    if is_not_an_executable_image(&latest) {
        let as_path = Path::new(program);
        let script = match &found {
            Some(path) => Some(path.clone()),
            None if as_path.is_absolute() => Some(as_path.to_owned()),
            None => root.map(|root| root.join(program)),
        };
        if let Some(script) = script
            && let Some((interpreter, leading)) = shebang_interpreter(&script)
                .as_deref()
                .and_then(<[String]>::split_first)
            && let Some(script) = script.to_str()
        {
            let mut extra: Vec<&str> = leading.iter().map(String::as_str).collect();
            extra.push(script);
            if let Ok(ok) = spawn(interpreter, &extra) {
                return Ok(ok);
            }
        }
    }

    Err(latest)
}

/// Spawn one invocation, substituting `files` for [`FILES_PLACEHOLDER`], and
/// record a finding if it exits non-zero.
///
/// A command that cannot run at all (missing binary, not executable) is a
/// *config* error (exit `1`), never a silent pass — the failure mode that would
/// turn a broken gate into a false green.
fn run_once(
    rule: &Rule,
    root: &Path,
    program: &str,
    args: &[&str],
    files: &[&str],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let mut expanded: Vec<&str> = Vec::with_capacity(args.len() + files.len());
    for arg in args {
        if *arg == FILES_PLACEHOLDER {
            expanded.extend_from_slice(files);
        } else {
            expanded.push(arg);
        }
    }

    // The predicate is the exit code alone; the command's own streams are not
    // parsed for meaning (CLOUD-93) and are not surfaced here — a bounded,
    // pointer-only drain is the advisory subsystem's job (CLOUD-82).
    #[expect(
        clippy::disallowed_types,
        reason = "stays: a `command` rule IS a consumer's checker program, which is why the kind carries ambient authority and `RuleKind::scopes` keeps it off the mediated call entirely (CLOUD-763)"
    )]
    let spawn = |program: &str, args: &[&str], extra: &[&str]| {
        std::process::Command::new(program)
            .args(extra)
            .args(args)
            .current_dir(root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    };

    // CLOUD-617's whole resolution, shared with `secrets` and `judge` rather
    // than restated here — the two Windows refusals and the order they compose
    // in are one decision, and this kind is not the one that gets to own it.
    let status = spawn_resolving(Some(root), program, |program, extra| {
        spawn(program, &expanded, extra)
    });

    let status = match status {
        Ok(status) => status,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "rule {}: cannot run `{program}`: not found on PATH",
                rule.id
            )));
        }
        Err(err) => {
            return Err(UsageError::raise(format!(
                "rule {}: cannot run `{program}`: {err}",
                rule.id
            )));
        }
    };

    if !status.success() {
        // A command condemns a batch rather than a span, so its identity is the
        // scope kind keyed on the glob it selected — the same pointer the
        // finding reports.
        let scope_key = rule.glob.as_deref().unwrap_or(&rule.id);
        let default = identity::scope_fingerprint(&rule.id, scope_key);
        findings.push(Finding {
            rule: rule.id.clone(),
            severity: rule.severity(),
            identity: identity_of(rule, identity::FindingKind::Scope, default),
            // The rule's glob is the tightest honest pointer for a finding a
            // command condemned as a batch. A command kind cannot load without
            // one, so the fallback is unreachable; naming the rule id rather
            // than an empty string keeps it a usable pointer if it ever is not.
            path: rule.glob.as_deref().unwrap_or(&rule.id).to_owned(),
            line: None,
            check: rule.settling_check().unwrap_or(Check::Reevaluate),
            remediation: rule.remediation(),
        });
    }
    Ok(())
}

/// Whether a set of findings fails the run: does any finding's severity rank as
/// a blocking [`ReportLevel::Fail`], once the resolved `fail_on_warning` setting
/// has been applied?
///
/// The one place the rule axis is converted for the exit contract, derived
/// through the severity taxonomy's own table ([`severity::row_for_rule`])
/// rather than a name-match — a `warn` finding renders and does not block until
/// [`severity::promote`] lifts it (CLOUD-49).
///
/// `fail_on_warning` is a parameter rather than a value read here so that the
/// §8 chain resolves it exactly once, in [`crate::resolve`], and every caller is
/// forced by the signature to supply that resolved value. A default read inside
/// this function would be a second place the setting could be decided.
#[must_use]
pub fn any_blocking(findings: &[Finding], fail_on_warning: bool) -> bool {
    findings.iter().any(|finding| {
        severity::promote(
            severity::row_for_rule(finding.severity).report,
            fail_on_warning,
        ) == ReportLevel::Fail
    })
}

/// Mint a finding's identity for `rule`, applying its per-rule identity keys.
///
/// One function so the two construction sites cannot drift on how `verbatim` and
/// `identity_key` are read. The override is composed *after* the default, which
/// is what keeps it split-only: the default is a field of the override's
/// preimage, so no discriminator can merge two defaults.
fn identity_of(
    rule: &Rule,
    kind: identity::FindingKind,
    default: identity::Fingerprint,
) -> identity::StoredIdentity {
    let fingerprint = match rule.identity_key.as_deref() {
        Some(discriminator) => identity::override_fingerprint(default, discriminator),
        None => default,
    };
    identity::StoredIdentity::new(kind, fingerprint)
}

/// How a rule's matched span is normalized before hashing.
fn span_mode(rule: &Rule) -> identity::SpanNormalization {
    if rule.verbatim == Some(true) {
        identity::SpanNormalization::Verbatim
    } else {
        identity::SpanNormalization::Collapsed
    }
}

/// Emit a finding for every line of `rel_path` that contains the rule's literal
/// `pattern`. A non-UTF-8 file cannot contain the literal, so it never matches.
/// A `forbid` rule's line predicate: what makes a line a finding, and what
/// takes it back out again.
///
/// One compiled value per file rather than a pair of `Option`s consulted per
/// line, so the "exactly one of literal-or-shape" choice is made once, where it
/// can be read, instead of re-derived inside the scan.
enum Matcher {
    /// `pattern`: a case-sensitive literal substring — the readable common case.
    Literal(String),
    /// `regex`: the escape for a predicate that genuinely is a shape.
    Shape(Regex),
}

impl Matcher {
    /// Compile `rule`'s predicate, plus its optional `exclude`.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a row carrying both columns or
    /// neither, or an expression that does not compile.
    fn for_rule(rule: &Rule) -> anyhow::Result<(Self, Option<Regex>)> {
        let matcher = match (rule.pattern.as_deref(), rule.regex.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(UsageError::raise(format!(
                    "rule {}: `pattern` and `regex` are alternatives; a row carries exactly one, \
                     never both",
                    rule.id
                )));
            }
            (Some(literal), None) => Matcher::Literal(literal.to_owned()),
            (None, Some(shape)) => Matcher::Shape(Regex::new(shape).map_err(|err| {
                UsageError::raise(format!("rule {}: `regex` is not valid: {err}", rule.id))
            })?),
            (None, None) => {
                return Err(UsageError::raise(format!(
                    "rule {}: kind \"forbid\" requires `pattern` (a literal) or `regex` (a shape)",
                    rule.id
                )));
            }
        };
        let exclude = rule
            .exclude
            .as_deref()
            .map(|expression| {
                Regex::new(expression).map_err(|err| {
                    UsageError::raise(format!("rule {}: `exclude` is not valid: {err}", rule.id))
                })
            })
            .transpose()?;
        Ok((matcher, exclude))
    }

    /// Whether `line` matches this rule's banned shape.
    fn matches(&self, line: &str) -> bool {
        match self {
            Matcher::Literal(pattern) => line.contains(pattern.as_str()),
            Matcher::Shape(regex) => regex.is_match(line),
        }
    }
}

fn forbid_in_file(
    rule: &Rule,
    root: &Path,
    rel_path: &str,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    let contents = match fs::read(root.join(rel_path)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let Ok(text) = String::from_utf8(contents) else {
        return Ok(());
    };
    // Compiled once per file, never per line: an expression recompiled inside
    // the loop would make the scan's cost a function of the tree's size times
    // the pattern's, and `Regex::new` is the expensive half.
    //
    // `Rule::validate` has already refused a malformed expression and the
    // both-columns row, so these are defence in depth on the same reading
    // `run_rule` applies — the runner re-validates rather than trusting that
    // every path reached it through the loader.
    let (matcher, exclude) = Matcher::for_rule(rule)?;
    let mode = span_mode(rule);
    for (index, line) in text.lines().enumerate() {
        // Excluded lines are dropped AFTER matching, never instead of it: the
        // exclusion is about what a matched line turns out to be — a comment,
        // a case pattern — not about narrowing what counts as a match.
        if matcher.matches(line) && !exclude.as_ref().is_some_and(|re| re.is_match(line)) {
            // The whole matched line is the span, which is exactly what the
            // churn pack hashed test-side before this existed — so its fixtures
            // keep their assertions, and that unchanged-ness is the evidence the
            // engine picks the same span.
            let default = identity::code_fingerprint(&rule.id, rel_path, line, mode)?;
            findings.push(Finding {
                rule: rule.id.clone(),
                severity: rule.severity(),
                path: rel_path.to_owned(),
                line: Some(index + 1),
                identity: identity_of(rule, identity::FindingKind::Code, default),
                check: rule.settling_check().unwrap_or(Check::Reevaluate),
                remediation: rule.remediation(),
            });
        }
    }
    Ok(())
}

/// Evaluate a [`RuleKind::Document`] row against one file.
///
/// # The three answers, and why the third is the point
///
/// * The node holds `pattern` — clean, no finding.
/// * The node holds something else, or is not there — a finding, reported at the
///   node path.
/// * The document **could not be looked at** — it does not parse, or its format
///   has no parser here — also a finding, under its own reason, and *never*
///   silence.
///
/// That last arm is what the whole kind is for (CLOUD-772). Every hand-rolled
/// reader it replaces defaults an empty extraction to agreement, so a file the
/// reader cannot understand passes the gate over it: the gate is loudest exactly
/// when it has seen the least. [`crate::facts::Look`] makes the two absences
/// different values, and this is the call site where the difference is spent.
///
/// # Pointer-only (non-negotiable rule 4)
///
/// A finding carries the path, the rule id and — through the identity — nothing
/// of the document's content. These files carry tokens and internal hostnames,
/// so the value read is compared and discarded, never reported. The node path is
/// the consumer's own config text and is what a reader needs to find the row
/// again; the value at it is the thing that must not travel.
fn document_in_file(
    rule: &Rule,
    root: &Path,
    rel_path: &str,
    derived: &BTreeMap<String, crate::facts::Look<String>>,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    // `validate` has already refused a row missing either column, so both are
    // defence in depth on the same reading `forbid_in_file` applies.
    let (Some(format), Some(node_path)) = (rule.format, rule.node.as_deref()) else {
        return Ok(());
    };
    // The comparand: a literal the row states, or another row's derived value
    // (CLOUD-773). `validate` has already refused a row carrying neither or both,
    // and refused a reference nothing derives — so an absent value here can only
    // mean the producer could not look.
    //
    // THREE-VALUED COMPOSITION, and this is the arm the whole issue turns on: a
    // derived fact over a base that could not be looked at is itself **could not
    // look**, never false. Reading it as false is CLOUD-251's vacuous pass — the
    // comparison "succeeds" against nothing and the gate reports agreement.
    let expected = match rule.reads.as_deref() {
        None => rule.pattern.as_deref().map(ToOwned::to_owned),
        Some(name) => match derived.get(name) {
            Some(crate::facts::Look::Is(value)) => Some(value.clone()),
            Some(crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook) | None => None,
        },
    };
    let Some(expected) = expected else {
        findings.push(unreadable_document(rule, rel_path, node_path)?);
        return Ok(());
    };
    // THE ONE ACQUISITION (CLOUD-849). Two behaviours of this site move, both
    // toward what its siblings already did: an absent file is still an early
    // `Ok(())`, but EACCES/EISDIR is now a could-not-look FINDING rather than
    // `Err` → exit 3. A gate that cannot look reports; it does not abort the
    // run it was one row of.
    let outcome = acquire(root, rel_path, Some(Want::Parsed(format)));
    // One arm per acquisition outcome, wildcard-free, so a new `NotAcquired`
    // cause or a new `Acquired` shape has to be decided here rather than
    // defaulting to silence. Two of the arms report the same reason today for
    // two unrelated causes, and merging them would delete the comments that say
    // why each is here.
    //
    // The `#[expect(clippy::match_same_arms)]` that used to sit here is GONE
    // rather than kept, and its going is the annotation working. CLOUD-914 and
    // CLOUD-762 added `Invocations` and `Uses` to the acquisition outcomes, which
    // regrouped this match until the lint stopped firing — and because it was
    // `expect` rather than `allow`, the now-unfulfilled expectation went red
    // instead of sitting here forever as a claim about a lint nobody triggers.
    // If a later edit makes two arms identical again, clippy says so, which is
    // the answer this attribute was standing in for.
    let reason = match &outcome {
        // The tree does not carry it. Not this row's business and not a
        // finding — unchanged.
        Acquired::No(NotAcquired::Absent) => return Ok(()),
        // `Unparsed` and `Unreadable` share one reported reason here, and
        // `UnknownFormat` is unreachable because `format` is `Some` — but it is
        // an arm rather than a wildcard so a fourth cause has to come through
        // here rather than defaulting to silence.
        Acquired::No(
            NotAcquired::Unparsed | NotAcquired::Unreadable | NotAcquired::UnknownFormat,
        ) => Some(DOCUMENT_UNREADABLE),
        // Unreachable: this site always asks for `Want::Parsed`. Arms rather
        // than a wildcard so a caller that ever asks for lines or call sites
        // here has to decide what a node path means over them.
        Acquired::Lines(_) | Acquired::Invocations(_) | Acquired::Uses(_) => {
            Some(DOCUMENT_UNREADABLE)
        }
        Acquired::Parsed(document) => match document.at(node_path) {
            crate::facts::Look::IsNot => Some(DOCUMENT_NODE_ABSENT),
            crate::facts::Look::CouldNotLook => Some(DOCUMENT_UNREADABLE),
            crate::facts::Look::Is(node) => {
                if node.scalar().as_deref() == Some(expected.as_str()) {
                    None
                } else {
                    Some(DOCUMENT_NODE_DIFFERS)
                }
            }
        },
    };
    let Some(reason) = reason else {
        return Ok(());
    };
    // The identity spans the rule, the file and the NODE PATH — never the value.
    // Two rows addressing different nodes of the same file are different
    // findings, and a value that changes without the node moving is the same
    // one, which is what lets a waiver mean something across a version bump.
    let default = identity::code_fingerprint(
        &rule.id,
        rel_path,
        &format!("{node_path} {reason}"),
        identity::SpanNormalization::Verbatim,
    )?;
    findings.push(Finding {
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: rel_path.to_owned(),
        // Line 1 rather than a located node: the parsers here answer with values,
        // not spans, and inventing a line by re-scanning the text would be a
        // second reader of the document — the exact thing this kind deletes.
        line: Some(1),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
    });
    Ok(())
}

/// The finding a row raises when it could not look — factored out because two
/// call sites reach it now: the document itself was unreadable, or the derived
/// value it compares against was.
fn unreadable_document(rule: &Rule, rel_path: &str, node_path: &str) -> anyhow::Result<Finding> {
    let default = identity::code_fingerprint(
        &rule.id,
        rel_path,
        &format!("{node_path} {DOCUMENT_UNREADABLE}"),
        identity::SpanNormalization::Verbatim,
    )?;
    Ok(Finding {
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: rel_path.to_owned(),
        line: Some(1),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
    })
}

/// Resolve every rule that derives a value, once for the whole run (CLOUD-773).
///
/// Resolving once is the entire point. The layer this absorbs re-derives because
/// a producer's value cannot cross the boundary — 57 of 126 tasks invoke a
/// sibling and get three states back — so the extraction is paid per consumer.
/// Here the producer pays once and every reader reads.
///
/// The graph is acyclic and every reference resolves: `validate_composition`
/// refused both at load. So this is a fold rather than a fixed point — a pass
/// resolves every row whose input is already in hand, and a chain of N rows
/// needs at most N passes. The alternative, a recursive walk, would carry its
/// own cycle guard duplicating the one the loader already owns.
///
/// Three-valued (CLOUD-757): a producer whose document does not parse, whose
/// node is absent, or whose own input could not be resolved yields
/// [`crate::facts::Look::CouldNotLook`] — never a value that reads as agreement.
fn resolve_derived(
    rules: &[Rule],
    root: &Path,
    files: &[String],
) -> BTreeMap<String, crate::facts::Look<String>> {
    let mut resolved: BTreeMap<String, crate::facts::Look<String>> = BTreeMap::new();
    let producers: Vec<&Rule> = rules.iter().filter(|rule| rule.derives.is_some()).collect();
    for _ in 0..producers.len() {
        let mut advanced = false;
        for rule in &producers {
            let Some(name) = rule.derives.as_deref() else {
                continue;
            };
            if resolved.contains_key(name) {
                continue;
            }
            // A producer that itself reads waits for its input; the loader
            // guarantees the wait terminates.
            if let Some(input) = rule.reads.as_deref()
                && !resolved.contains_key(input)
            {
                continue;
            }
            resolved.insert(name.to_owned(), derive_one(rule, root, files));
            advanced = true;
        }
        if !advanced {
            break;
        }
    }
    resolved
}

/// The value one deriving row publishes: the scalar at its node, three-valued.
fn derive_one(rule: &Rule, root: &Path, files: &[String]) -> crate::facts::Look<String> {
    use crate::facts::Look;
    let (Some(format), Some(node_path), Some(glob)) =
        (rule.format, rule.node.as_deref(), rule.glob.as_deref())
    else {
        return Look::CouldNotLook;
    };
    // A `PathSet`, NOT a bare `Selector` (CLOUD-480, found on review of #660).
    // `run_rule` narrows its selection with `exclude_paths` and this did not, so a
    // `derives` row could read a path its own row excludes and publish that value
    // to every reader — an exclusion that holds for the rule's own findings and
    // leaks through its derivation is the kind of half-applied narrowing that
    // reads as covered. The include and the excludes are one object here for the
    // same reason they are there: the selection can only ever be a SUBSET of what
    // the glob alone names.
    let Ok(selection) = PathSet::selecting(&rule.id, glob, &rule.exclude_paths) else {
        return Look::CouldNotLook;
    };
    // The FIRST matching path, in the walk's sorted order. A derivation is one
    // value, so a glob matching several documents has to pick, and picking by
    // the sorted walk is the one choice that does not depend on the filesystem's
    // order. A row meaning "these must all agree" writes several READING rows
    // instead, which is what keeps each clause independently nameable.
    let Some(path) = files.iter().find(|path| selection.contains(path)) else {
        return Look::CouldNotLook;
    };
    // THE ONE ACQUISITION (CLOUD-849). Externally unchanged: every way this can
    // fail to acquire was already `CouldNotLook` here, and still is. What moves
    // is that the four causes are now *stated* in one place rather than three
    // `let ... else` arms that happened to agree.
    match acquire(root, path, Some(Want::Parsed(format))) {
        // Unreachable: this site always asks for `Want::Parsed`. An arm rather
        // than a wildcard, so a caller that ever asks for lines here has to
        // decide what a node path means over them.
        Acquired::No(_) | Acquired::Lines(_) | Acquired::Invocations(_) | Acquired::Uses(_) => {
            Look::CouldNotLook
        }
        Acquired::Parsed(document) => match document.at(node_path) {
            Look::Is(node) => match node.scalar() {
                Some(value) => Look::Is(value),
                // A container is not a value a comparison can consume. "Looked,
                // and there is no scalar here" is the honest answer, and it is
                // not the same as a parse failure.
                None => Look::IsNot,
            },
            Look::IsNot => Look::IsNot,
            Look::CouldNotLook => Look::CouldNotLook,
        },
    }
}

/// The document could not be looked at — it does not parse, is not UTF-8, or its
/// declared format has no parser in this build.
const DOCUMENT_UNREADABLE: &str = "could-not-look";

/// The document parsed and the addressed node is not in it.
const DOCUMENT_NODE_ABSENT: &str = "node-absent";

/// The node is there and holds something other than the declared literal.
const DOCUMENT_NODE_DIFFERS: &str = "node-differs";

/// The entry whose presence makes a directory a repository of its own — git's
/// own boundary marker, and therefore the one this crate reads.
///
/// It is a *directory* in a plain clone and a *file* in a submodule or a linked
/// worktree, which is why presence is what is tested and never the kind.
pub const NESTED_REPOSITORY_MARKER: &str = ".git";

/// Every file under `root`, as sorted repo-relative `/`-separated paths — the
/// one tree walk the crate has.
///
/// Sorted, so any pass over it is deterministic (§6), and `.git` is skipped:
/// the object store is never policy input. A second walker would be a second
/// answer to "what does Batten look at", which is the divergence
/// [`crate::markers`] reuses this to avoid.
///
/// # Ignored files are not policy input (CLOUD-214)
///
/// The walk is the [`ignore`] crate's — ripgrep's — so "which files does this
/// repository consider its own" is answered by the `.gitignore` the contributors
/// already maintain rather than by a second list here. Adopted, not rebuilt:
/// nested `.gitignore` files, negations, and `.git/info/exclude` all come with
/// it, and none of them is this crate's to re-implement.
///
/// The measurement that decided it, on this repository after one `cargo build`:
/// the hand-rolled walk yielded **9221** paths, of which **8891 (96%)** were
/// ignored build output under `target/` and only 330 were the repository's own.
/// A `forbid` rule was one broad glob away from reporting findings against
/// compiler artifacts, and every rule paid to walk them.
///
/// Two settings are load-bearing and pinned by tests rather than left to the
/// crate's defaults:
///
/// * **Hidden entries are walked** (`hidden(false)`). `ignore` skips dotfiles by
///   default, which would silently drop `.github/`, `.serena/` and `.claude/` —
///   three directories this repository's committed rules select outright, so the
///   default would turn live gates into dead ones with no diagnostic.
/// * **Ignore files are honoured, `require_git` off.** A fixture that is not a
///   git repository still reads its own `.gitignore`, so the selection does not
///   change shape depending on whether git happens to be initialised.
///
/// # The selection stops at a nested repository (CLOUD-328)
///
/// A directory carrying [`NESTED_REPOSITORY_MARKER`] is a repository of its
/// own, and this walk does not enter it. **This is the single statement of
/// which files a glob selects, and the base-rev half of a ratchet
/// ([`crate::git::count_at_rev`]) reads the same rule** — it skips gitlink
/// entries — so the two halves select the same set by construction rather than
/// by a consumer's care with globs.
///
/// Without it the two disagree, and the direction is the dangerous one: a
/// `non_decreasing` row whose glob spans a submodule sits permanently above a
/// base that counted one gitlink, so no deletion could ever pull it back under
/// and **the gate cannot fail**. Measured on this repository at the commit that
/// raised CLOUD-328: base 637 against working 1404, a fixed `+767` in a tree
/// where nothing had been added.
///
/// It is not a ratchet-only property, because this is not a ratchet-only
/// walker: it is also what stops a `forbid` rule reporting findings against
/// vendored third-party code, and a `budget` or a marker scan from measuring a
/// checkout that is not this one. The rule is stated in git's terms rather than
/// as a submodule list precisely so a linked worktree — `.claude/worktrees/`,
/// where agents work — is bounded by the same reading.
///
/// `root` itself is never a boundary: it carries the marker by definition, and
/// only *descended* directories are tested.
///
/// # Errors
///
/// An I/O failure while walking propagates as an internal error (→ exit `3`).
pub fn tree_files(root: &Path) -> anyhow::Result<Vec<String>> {
    let root = root.to_path_buf();
    let mut walker = ignore::WalkBuilder::new(&root);
    walker
        // Dotfiles are ordinary policy input here; see the doc comment.
        .hidden(false)
        // A `.gitignore` means what it says whether or not `git init` has run,
        // so the selection does not change shape under a fixture.
        .require_git(false)
        // The repository's own ignore surface, and only it. A developer's global
        // excludes are a property of their machine, not of this repository, and
        // a gate whose file set varies per workstation is not one gate.
        .git_global(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(false)
        // One filesystem: a walk that follows a mount out of the repository is
        // measuring somebody else's disk.
        .same_file_system(true)
        .follow_links(false);
    // The CLOUD-328 boundary, restated on the adopted walker. `ignore` skips the
    // root's own `.git` but knows nothing about a nested repository, so the rule
    // this crate states has to be applied here or it would be silently dropped
    // by the very change that adopts a better walk. `tests/submodule.rs` is what
    // catches that, and it is why those assertions landed first.
    let boundary = root.clone();
    walker.filter_entry(move |entry| {
        if entry.file_type().is_some_and(|kind| !kind.is_dir()) {
            return true;
        }
        // The object store is never policy input, and this skip cannot be left
        // to the walker: `ignore` excludes `.git` as a *hidden* entry, and
        // `hidden(false)` above — which this repository's own rules require, to
        // reach `.github/` and `.serena/` — switches that off along with it.
        // Dropping it would put every blob, ref and hook body into the file set.
        if entry.file_name() == std::ffi::OsStr::new(NESTED_REPOSITORY_MARKER) {
            return false;
        }
        // `root` carries the marker by definition; testing it would empty every
        // walk, so only descended directories are judged.
        if entry.path() == boundary {
            return true;
        }
        !entry.path().join(NESTED_REPOSITORY_MARKER).exists()
    });

    let mut files = Vec::new();
    for entry in walker.build() {
        let entry = entry?;
        // Directories, and the root itself, are not files; a symlink is not
        // followed, so it never contributes a path outside the tree.
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        if let Ok(rel) = entry.path().strip_prefix(&root) {
            files.push(rel_to_slash(rel));
        }
    }
    // `ignore` yields in directory order; §6 byte-stability is this sort.
    files.sort();
    Ok(files)
}

/// Render a relative path with `/` separators, so globbing and output are
/// identical across platforms (§6 byte-stability spans OSes).
fn rel_to_slash(rel: &Path) -> String {
    rel.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The marker that turns a glob into an exclude inside an ordered
/// include/exclude list: gitignore's `!` prefix, so a reader who knows one knows
/// the other.
const EXCLUDE_PREFIX: char = '!';

/// One glob evaluator over repo-relative, `/`-separated paths.
///
/// A set answers exactly one question — *is this path a member?* — from its own
/// list and nothing else. Two sets built from two lists share no state, so
/// membership in each is computed independently (CLOUD-37). That independence is
/// the whole point: `scope`, `protected` and `unlanded` overlap in practice but
/// are not the same set, and collapsing them changes policy silently.
///
/// **An exclude beats an include.** Membership is `any include matches AND no
/// exclude matches`, so the outcome does not depend on the order the patterns
/// were written in — the strongest reading of "excludes win", and the one that
/// makes evaluation deterministic and order-stable for identical config (§6).
///
/// An empty include list makes the set empty. Absent config is *not* read as
/// "everything": a set that silently defaults to universal membership is a
/// widening, and widening is the one direction a policy engine may never drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSet {
    includes: Vec<Selector>,
    excludes: Vec<Selector>,
}

impl PathSet {
    /// The set that contains nothing.
    ///
    /// Spelled out rather than derived as `Default`, because the safe empty value
    /// and the *obvious* one point in opposite directions here: an absent list
    /// must mean "no paths", never "all paths", and a `Default` impl is exactly
    /// the thing a future caller reaches for without reading which way it went
    /// (see the type's own doc comment). [`PathSet::contains`] needs at least one
    /// matching include, so this matches nothing by construction.
    #[must_use]
    pub const fn empty() -> Self {
        PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        }
    }

    /// Whether this set can match anything.
    ///
    /// A set with no includes contains nothing, so a caller can skip the work of
    /// even asking. Excludes alone cannot make a set non-empty — they only
    /// subtract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.includes.is_empty()
    }
}

impl PathSet {
    /// Build the ordered include/exclude set the `scope` key declares: a plain
    /// glob includes, a `!`-prefixed glob excludes.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!` with no glob after it —
    /// an exclude that excludes nothing is a typo, not an empty instruction —
    /// and for a glob that does not compile, which is refused here rather than
    /// silently narrowing the set to nothing.
    pub fn scope(patterns: &[String]) -> anyhow::Result<Self> {
        let mut set = PathSet {
            includes: Vec::new(),
            excludes: Vec::new(),
        };
        for pattern in patterns {
            match pattern.strip_prefix(EXCLUDE_PREFIX) {
                Some("") => {
                    return Err(UsageError::raise(
                        "scope: `!` must be followed by a glob".to_owned(),
                    ));
                }
                Some(rest) => set.excludes.push(Selector::new(rest)?),
                None => set.includes.push(Selector::new(pattern)?),
            }
        }
        Ok(set)
    }

    /// The set one tree-scoped rule selects: its `glob` as the sole include, its
    /// `exclude_paths` as excludes (CLOUD-883).
    ///
    /// Built here rather than as a bare [`Selector`] so a rule's selection gets
    /// this type's stated semantics for free — an exclude beats an include, and
    /// the answer does not depend on the order the author wrote the patterns in.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a glob that does not compile, and
    /// for a `!`-prefixed exclusion. The second is the load-bearing refusal: this
    /// column is ALREADY the negative half, so a `!` here is a double negative
    /// that reads as re-inclusion — the one direction that would widen the
    /// selection past what `glob` names, which is what this type's own doc says a
    /// policy engine may never drift towards.
    pub fn selecting(rule: &str, glob: &str, exclude_paths: &[String]) -> anyhow::Result<Self> {
        let mut set = PathSet {
            includes: vec![Selector::new(glob)?],
            excludes: Vec::with_capacity(exclude_paths.len()),
        };
        for pattern in exclude_paths {
            if pattern.starts_with(EXCLUDE_PREFIX) {
                return Err(UsageError::raise(format!(
                    "rule {rule}: `exclude_paths` entry `{pattern}` starts with `!`, and this \
                     column is already the exclusion — a `!` here reads as re-including what \
                     `glob` selected, which widens the rule past what its author wrote"
                )));
            }
            if pattern.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {rule}: `exclude_paths` carries an empty entry, which excludes nothing \
                     while reading as a narrowing"
                )));
            }
            set.excludes.push(
                Selector::new(pattern)
                    .map_err(|err| UsageError::raise(format!("rule {rule}: {err}")))?,
            );
        }
        Ok(set)
    }

    /// Build a plain include set from `key`'s list.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a `!`-prefixed entry. Only
    /// `scope` carries exclude semantics, so a `!` here would either be read as
    /// a literal glob or silently dropped — and a pattern the author believes
    /// excludes a path while the engine treats it as an include is precisely the
    /// silent policy change this issue exists to prevent. Refuse instead. A glob
    /// that does not compile is refused here too, for the same reason.
    pub fn includes(key: &str, patterns: &[String]) -> anyhow::Result<Self> {
        let mut includes = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if pattern.starts_with(EXCLUDE_PREFIX) {
                return Err(UsageError::raise(format!(
                    "{key}: `{pattern}` — only `scope` takes `!` excludes; {key} is a plain \
                     include set"
                )));
            }
            includes.push(
                Selector::new(pattern).map_err(|err| UsageError::raise(format!("{key}: {err}")))?,
            );
        }
        Ok(PathSet {
            includes,
            excludes: Vec::new(),
        })
    }

    /// Whether `path` is a member of this set, computed from this set's lists
    /// alone.
    #[must_use]
    pub fn contains(&self, path: &str) -> bool {
        self.includes.iter().any(|selector| selector.matches(path))
            && !self.excludes.iter().any(|selector| selector.matches(path))
    }
}

/// The three sets Batten's policy is defined over, each parsed from its own list
/// in `batten.toml` (CLOUD-37).
///
/// Grouped for construction only. Nothing here consults another field: a path's
/// membership in `scope`, in `protected`, and in `unlanded` are three separate
/// answers, and no code may derive one from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sets {
    /// The paths policy applies to — the one ordered include/exclude set.
    pub scope: PathSet,
    /// The paths whose modification is guarded.
    pub protected: PathSet,
    /// The paths whose work is not yet landed.
    pub unlanded: PathSet,
}

impl Sets {
    /// Build all three evaluators from a parsed config.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when a list is malformed — a bare
    /// `!` in `scope`, or a `!` entry in an include-only key.
    pub fn from_config(config: &crate::config::Config) -> anyhow::Result<Self> {
        Ok(Sets {
            scope: PathSet::scope(&config.scope)?,
            protected: PathSet::includes("protected", &config.protected)?,
            unlanded: PathSet::includes("unlanded", &config.unlanded)?,
        })
    }
}

/// One compiled glob, matched against repo-relative `/`-separated paths
/// (CLOUD-214).
///
/// [`globset`] rather than a hand-rolled matcher: the replaced one backtracked
/// over every `**` split point — exponential on a pattern with several — and
/// knew only `*`, `?` and `**`, so a consumer had no character classes, no
/// braces and no way to say "not this". Adopting the matcher ripgrep already
/// ships is the wrap-don't-rebuild directive applied to the one thing every rule
/// runs through.
///
/// **Compiled once, matched many.** A pattern is parsed when the rule loads, not
/// once per candidate path, which is what keeps the selection linear in the size
/// of the tree rather than in tree × pattern-length.
///
/// # Semantics, pinned rather than inherited
///
/// `literal_separator(true)` is the one non-default setting and it is
/// load-bearing: without it `*` crosses `/`, so `*.rs` would select every Rust
/// file at every depth and a rule scoped to one directory would silently widen.
/// Widening is the single direction a policy engine may never drift, and
/// [`tests::glob_semantics_are_pinned_at_the_shipped_patterns`] is what holds it.
#[derive(Debug, Clone)]
pub struct Selector {
    pattern: String,
    matcher: globset::GlobMatcher,
}

impl Selector {
    /// Compile `pattern`.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for a pattern `globset` cannot
    /// parse — an unclosed character class, a stray `**` inside a component.
    /// A malformed glob is bad config, and refusing it at load is what stops it
    /// reaching a run as a rule that quietly selects nothing.
    pub fn new(pattern: &str) -> anyhow::Result<Self> {
        let glob = globset::GlobBuilder::new(pattern)
            // See the type's doc comment: without this, `*` crosses `/` and
            // every rule's scope widens.
            .literal_separator(true)
            .build()
            .map_err(|err| UsageError::raise(format!("glob `{pattern}` is not valid: {err}")))?;
        Ok(Selector {
            pattern: pattern.to_owned(),
            matcher: glob.compile_matcher(),
        })
    }

    /// Whether `path` — repo-relative, `/`-separated — is selected.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        self.matcher.is_match(path)
    }

    /// The pattern this was compiled from, as the consumer wrote it.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Two selectors are the same selector when they came from the same pattern.
///
/// Hand-written because a compiled matcher has no equality of its own, and
/// stated over the pattern rather than derived so the compiled form stays an
/// implementation detail: a [`PathSet`] comparison is a comparison of the
/// config that built it.
impl PartialEq for Selector {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for Selector {}

/// Match a `/`-separated glob against a `/`-separated path, compiling the
/// pattern for this one call.
///
/// The convenience form, for a caller holding a single pattern and a single
/// path. A caller testing many paths against one pattern must build a
/// [`Selector`] instead — compiling per call is the cost this type exists to
/// avoid.
///
/// A pattern that does not compile matches **nothing**, which is the safe
/// direction: it can only ever produce fewer findings than the consumer asked
/// for, never more. It is also unreachable for a rule, because [`Rule::validate`]
/// refuses a malformed `glob` at load, where the diagnostic names the row.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    Selector::new(pattern).is_ok_and(|selector| selector.matches(path))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    // --- one document acquisition (CLOUD-849) --------------------------------

    /// Every `.rs` under `src/`, so the scan is over the crate rather than over
    /// the file that happens to hold the assertion.
    ///
    /// A near-copy of `git.rs`'s own `crate_sources`, which is `#[cfg(test)]`
    /// and private to that module. Copied rather than hoisted deliberately:
    /// making it shared would put a test helper on the crate's real surface to
    /// save fifteen lines, and the two gates it serves are independent.
    fn crate_sources() -> Vec<(std::path::PathBuf, String)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        // WALKS THE SUBTREE, not one directory. `read_dir` does not descend, so
        // a `.rs` file under a future `src/<module>/` would never be scanned and
        // the gate would stop holding SILENTLY — the failure mode of every
        // scanner gate. The crate is flat today, which is exactly when this is
        // cheap to get right.
        let mut pending = vec![src];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension() != Some(std::ffi::OsStr::new("rs")) {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                sources.push((path, source));
            }
        }
        // `read_dir` order is filesystem-defined; a gate's failure message must
        // not depend on it.
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        sources
    }

    /// The 22 `@test` cases `tests/contract-drift.bats` declared at `dd1d6d8^`,
    /// the last rev at which it existed (CLOUD-908).
    ///
    /// **Committed rather than read from git, and that is the honest shape here.**
    /// The clone is routinely shallow — CI's is — so a test that resolved
    /// `dd1d6d8^` would either hard-fail where the rev is absent or, far worse,
    /// skip and read as coverage. The names are the whole object of a mapping;
    /// the case bodies are not. So the list is tracked text, taken from that rev
    /// once, and the half that CANNOT be transcribed — whether the head tree
    /// claims each one — is read live below.
    const RETIRED_CONTRACT_DRIFT_CASES: [&str; 22] = [
        "the first call is the session\'s start: silent, and it writes a snapshot",
        "an unchanged surface produces no output",
        "the snapshot is one line per tracked contract file, hash and path",
        "THE GAP: a modified AGENTS.md is reported, naming the file",
        "it names the event it was called on, so one body serves both wirings",
        "ONCE PER CHANGE-SET: the very next call is silent",
        "a SECOND change-set is reported again \u{2014} quiet is not permanent",
        "a newly tracked contract file is drift",
        "a contract file that stopped being tracked is drift too",
        "an untracked file under mise-tasks is not contract",
        "a file outside the surface does not fire it",
        "each session gets its own snapshot, so a session that started AFTER the change is not nudged",
        "a payload with no session_id still works, on a shared key",
        "a session id carrying path characters cannot escape the snapshot store",
        "the reminder carries no byte of the changed file\'s content",
        "it emits a count as well as the paths",
        "when settings.json moved it says a new hook may not be loaded in this session",
        "unparseable input fails open",
        "empty input fails open",
        "outside a checkout there is no surface to judge",
        "the bypass is honoured",
        "the emitted document is the hook shape, and it parses",
    ];

    /// Every `.rs` under the crate, repo-relative, as the head tree\'s path list.
    ///
    /// The same subtree walk `crate_sources` does and for the same reason, over
    /// both `src/` and `tests/`: an arm may live on a successor in either, and a
    /// walk that missed one would report a real mapping as a phantom target.
    fn crate_paths() -> Vec<String> {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap();
        let mut paths = Vec::new();
        let mut pending = vec![manifest.join("src"), manifest.join("tests")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension() == Some(std::ffi::OsStr::new("rs")) {
                    // Joined from components rather than `to_string_lossy`: the
                    // engine's paths are `/`-separated everywhere, and a host
                    // separator leaking in here would make every arm look like a
                    // phantom target on one platform only.
                    let relative = path.strip_prefix(root).unwrap();
                    let joined: Vec<String> = relative
                        .components()
                        .map(|part| part.as_os_str().to_string_lossy().into_owned())
                        .collect();
                    paths.push(joined.join("/"));
                }
            }
        }
        paths.sort();
        paths
    }

    #[test]
    fn a_suite_qualified_arm_resolves_and_does_not_borrow_a_neighbours() {
        // CLOUD-908's grammar has two readers — this ratchet and `replay.sh` — and
        // for a while only one of them knew the qualified form. Measured retiring
        // CLOUD-312's row 2: thirteen conserved cases read as unmapped because
        // their arms were qualified, and the fourteenth resolved by BORROWING row
        // 1's bare arm for an identically titled case in a different suite. This
        // pins both halves at the site that resolves them.
        let conserves = Conserves {
            case: "@test \"".to_owned(),
            close: "\"".to_owned(),
            carried: "// carried:".to_owned(),
            subsumed: "// subsumed:".to_owned(),
            changed: "// changed:".to_owned(),
            withdrawn: None,
            declared_in: "ledger.rs".to_owned(),
        };
        let root = temp_dir("qualified-arm");
        // One title, two suites: the shape that makes qualification necessary.
        write(
            &root,
            "ledger.rs",
            "// carried: \"two.bats::the shared title\" ledger.rs\n",
        );
        let files = vec!["ledger.rs".to_owned()];
        let claimed = claimed_cases(&root, &conserves, &files);
        let mapping = Mapping {
            conserves: &conserves,
            claimed: &claimed,
            files: &files,
            // This case is about arm RESOLUTION, not about the withdrawal
            // condition: no `withdrawn` arm is in play, so the value cannot change
            // its verdict either way.
            subject_died: false,
        };
        let rule = Rule {
            glob: Some("tests/**/*.bats".to_owned()),
            pattern: Some("@test \"".to_owned()),
            direction: Some(Direction::NonDecreasing),
            base: Some("origin/main".to_owned()),
            retires_with: Some("# subject:".to_owned()),
            conserves: Some(conserves.clone()),
            ..blank("r", RuleKind::Ratchet)
        };
        let dying = "@test \"the shared title\" {\n}\n";

        let mut mine = Vec::new();
        unconserved_cases(&rule, "tests/two.bats", dying, "", &mapping, &mut mine);
        assert!(
            mine.is_empty(),
            "the qualified arm names this suite, so its case is conserved: {mine:?}"
        );

        // THE ANTI-BORROW HALF, and the one that makes the first mean something: a
        // different suite with the same case title must NOT be conserved by an arm
        // that named its neighbour.
        let mut theirs = Vec::new();
        unconserved_cases(&rule, "tests/one.bats", dying, "", &mapping, &mut theirs);
        assert_eq!(
            theirs.len(),
            1,
            "an arm qualified to another suite conserves nothing here: {theirs:?}"
        );
    }

    #[test]
    fn the_one_completed_retirement_is_mapped_case_for_case() {
        // THE CALIBRATION (CLOUD-908), and the reason this row shipped a
        // mechanism rather than a review checklist. `dd1d6d8` deleted a 259-line
        // suite and its 215-line subject, replacing them with 12 `#[test]` cases
        // and 6 unit tests. It is a careful port — and it was unverifiable, so
        // six of the 22 had no successor anything in the tree could name.
        //
        // Read through the SAME parser the ratchet uses, deliberately: a
        // hand-rolled reader here would be a second authority that could agree
        // with a mapping the gate rejects, which is the shape of every ledger
        // that drifts from the thing it describes.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap().parent().unwrap();
        let conserves = Conserves {
            case: "@test \"".to_owned(),
            close: "\"".to_owned(),
            carried: "// carried:".to_owned(),
            subsumed: "// subsumed:".to_owned(),
            changed: "// changed:".to_owned(),
            withdrawn: None,
            declared_in: "crates/batten/tests/*.rs".to_owned(),
        };
        let files = crate_paths();
        let claimed = claimed_cases(root, &conserves, &files);

        for case in RETIRED_CONTRACT_DRIFT_CASES {
            let claims = claimed.claims.get(case).map_or(&[][..], Vec::as_slice);
            assert_eq!(
                claims.len(),
                1,
                "exactly one arm claims {case:?}; found {}",
                claims.len()
            );
            let claim = &claims[0];
            assert!(
                files.contains(&claim.target),
                "the arm for {case:?} names {} , which this tree does not have",
                claim.target
            );
            // The `changed` arm owes a reason, and these two are the cases whose
            // behaviour the port deliberately inverted.
            if claim.arm == Arm::Changed {
                assert!(
                    !claim.reason.trim().is_empty(),
                    "the deliberate divergence on {case:?} carries its reason"
                );
            }
        }
    }

    #[test]
    fn one_document_acquisition_exists() {
        // THE GATE THAT SHIPS WITH THE RULE (CLOUD-849). `Fact::Document` was
        // acquired at three sites with three different error mappings, already
        // diverged — `tree_document` could not tell a non-UTF-8 file from a
        // missing one and its two siblings could. This keeps the collapse
        // collapsed, on the source-level model `no_second_git_invoker_exists`
        // set for git spawning.
        //
        // The needle is the PARSE, not the read: `fs::read` has legitimate
        // non-document callers in this file (`forbid_in_file`'s byte scan, the
        // ratchet's pattern count), and every one of those would make a
        // read-counting gate either noisy or vacuous. A document acquisition is
        // exactly a read paired with `Format::read`, so the pair's second half
        // is what identifies it.
        //
        // Fails by: adding a second `fs::read` + `Format::read` pair anywhere in
        // the crate, which is §7(a)'s stated mutation.
        let needle = ["format", ".read("].concat();
        let sites: Vec<String> = crate_sources()
            .into_iter()
            .flat_map(|(path, source)| {
                let count = source.matches(needle.as_str()).count();
                std::iter::repeat_n(path.display().to_string(), count)
            })
            .collect();

        // ANTI-VACUITY, in the same function (CLOUD-418): a gate whose needle
        // stopped matching would report "one" as "zero" and pass forever. The
        // count must be exactly one, so zero fails here too.
        assert_eq!(
            sites.len(),
            1,
            "exactly one function in the crate may acquire a document — \
             `rules::acquire_document`. Found {} site(s): {sites:?}. A second \
             one is a second error mapping, and there is then nowhere to put \
             the cache, the read budget or the pool (CLOUD-849).",
            sites.len()
        );
    }

    #[test]
    fn a_document_that_cannot_be_acquired_names_which_way() {
        // §7(c), and the half CLOUD-845's second false-green road turns on: the
        // four causes are DISTINGUISHED, not collapsed. Before this, an
        // extension with no parser, an absent file, a binary file and a syntax
        // error all produced the same anonymous skip — so a migrated gate could
        // go silent-and-green by declaring the wrong extension.
        // Keyed by CASE as well as by process: the harness runs a file's cases as
        // threads in one process, so a name shared with a sibling would have this
        // case's `remove_dir_all` delete the other's fixtures mid-run.
        let dir = std::env::temp_dir().join(format!("batten-acq-causes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A parseable document, so the fixture proves the happy path too.
        std::fs::write(dir.join("good.toml"), "key = 1\n").unwrap();
        // Bytes that are not UTF-8 — the case site 1 could not tell from absent.
        std::fs::write(dir.join("binary.toml"), [0xff_u8, 0xfe, 0x00]).unwrap();
        // Text that will not parse.
        std::fs::write(dir.join("broken.toml"), "key = = =\n").unwrap();
        // An extension this build has no parser for. Note it EXISTS: the point
        // is that the cause is the declaration, not the filesystem.
        std::fs::write(dir.join("prose.md"), "# heading\n").unwrap();

        let acquire =
            |name: &str| super::acquire(&dir, name, super::want_for(name, super::Wanted::Document));

        assert!(
            matches!(acquire("good.toml"), super::Acquired::Parsed(_)),
            "a parseable declared document is acquired"
        );
        assert!(
            matches!(
                acquire("absent.toml"),
                super::Acquired::No(super::NotAcquired::Absent)
            ),
            "an absent file is `Absent`"
        );
        assert!(
            matches!(
                acquire("binary.toml"),
                super::Acquired::No(super::NotAcquired::Unreadable)
            ),
            "NON-UTF-8 IS NOT ABSENT — the exact pair `tree_document` collapsed"
        );
        assert!(
            matches!(
                acquire("broken.toml"),
                super::Acquired::No(super::NotAcquired::Unparsed)
            ),
            "a syntax error is `Unparsed`, distinct from unreadable bytes"
        );
        assert!(
            matches!(
                acquire("prose.md"),
                super::Acquired::No(super::NotAcquired::UnknownFormat)
            ),
            "an extension with no parser is a CONFIG fault, and is reached \
             without opening the file"
        );

        // And the four tokens are distinct, or naming the cause would not
        // discriminate — the failure this whole split exists to prevent.
        let tokens = [
            super::NotAcquired::UnknownFormat.as_str(),
            super::NotAcquired::Absent.as_str(),
            super::NotAcquired::Unreadable.as_str(),
            super::NotAcquired::Unparsed.as_str(),
        ];
        let unique: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
        assert_eq!(
            unique.len(),
            tokens.len(),
            "each cause reports its own token"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- the tree document corresponds to the fact model (CLOUD-845) -------
    /// The keys `tree_document` actually emits, read off a real build of it.
    fn emitted_tree_keys(_root: &std::path::Path) -> Vec<String> {
        let empty: BTreeMap<(String, super::Wanted), super::Acquired> = BTreeMap::new();
        let (input, _) = super::tree_document(
            &empty,
            &super::Declared {
                documents: &[],
                lines: &[],
                invocations: &[],
                uses: &[],
            },
            &[],
            &BTreeMap::new(),
            &BTreeMap::new(),
            &crate::git::GitFacts::default(),
            &crate::facts::Look::IsNot,
        );
        let parsed: serde_json::Value = serde_json::from_str(&input).expect("the input is JSON");
        let tree = parsed
            .get("tree")
            .and_then(serde_json::Value::as_object)
            .expect("the document has a `tree` object");
        let mut keys: Vec<String> = tree.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// **The property whose absence is CLOUD-845.**
    ///
    /// `policy.rs`'s own module doc iterated `input.tree.tracked`, which
    /// `tree_document` never built. Rego makes an undefined path silent, so the
    /// predicate was undefined, so the deny set was empty, so a dead gate and a clean
    /// tree were byte-identical on the decision surface. Nothing caught it because
    /// nothing compared what the engine emits against what the model says it should.
    ///
    /// This is PR #620's `every_hook_resolvable_fact_is_projected_under_its_own_token`
    /// ported to the tree surface — asserted in BOTH directions, because each
    /// direction catches a different bug: a fact the tree gains and forgets to
    /// project, and a key the tree emits that names no fact.
    ///
    /// Fails by: dropping an arm from `tree_document`'s projection, or giving a
    /// `Surface::Check` fact a `tree_key` the projection does not write.
    #[test]
    fn every_check_resolvable_fact_is_projected_under_its_own_tree_key() {
        let root = std::env::temp_dir();

        // THE PREDICATE IS `tree_key`, not the surface, and the two stopped
        // agreeing when the git family arrived (CLOUD-907): three of its members
        // are `Surface::Hook` — the narrowest surface they may be resolved on,
        // which is a statement about their cost — and all five are emitted here
        // because the consumers the census found are gate tasks. A
        // surface-equality expectation would have demanded the tree drop them.
        //
        // Both directions still hold, and the second one is asserted separately
        // below: a fact the tree emits must name a `tree_key`, and no fact may
        // name one it cannot be resolved on.
        let mut expected: Vec<String> = crate::facts::Fact::ALL
            .iter()
            .filter_map(|fact| fact.tree_key().map(ToOwned::to_owned))
            .collect();
        for fact in crate::facts::Fact::ALL {
            assert!(
                fact.tree_key().is_none()
                    || fact.class().resolvable_on(crate::facts::Surface::Check),
                "{}: names a tree key it cannot be resolved on — which is \
                 `input.tree.tracked`'s defect exactly, a key the document \
                 promises and the engine never fills",
                fact.as_str()
            );
        }
        // `missing` is the could-not-look CHANNEL, not a fact. Named explicitly
        // rather than filtered by a heuristic: if it ever becomes a fact, this line
        // is where somebody has to decide that.
        expected.push(String::from("missing"));
        expected.sort();

        // ANTI-VACUITY, in the same function (CLOUD-418): an empty expectation
        // compared against an empty emission passes and asserts nothing, which is
        // exactly the vacuous shape this suite exists to refuse.
        assert!(
            expected.len() >= 3,
            "the model must place at least `documents`, `tracked` and `missing` on \
             this surface, or the comparison below is decorative: {expected:?}"
        );

        assert_eq!(
            emitted_tree_keys(&root),
            expected,
            "the tree document's keys and the model's `Surface::Check` facts \
             disagree. A key here that names no fact is how `input.tree.tracked` \
             was documented and never built; a fact with no key here is one a \
             module can never see."
        );
    }

    /// (d) from the row: an example in `policy.rs`'s module doc that references a
    /// field the engine cannot emit turns a test red.
    ///
    /// The shape `spawn_census.rs` uses against `clippy.toml` — an assertion over
    /// committed text rather than over behaviour, because the defect is that a
    /// reader copies the text. CLOUD-589's class, given a mechanism instead of a
    /// second pair of eyes.
    #[test]
    fn every_input_path_in_the_module_doc_names_a_key_the_engine_emits() {
        let root = std::env::temp_dir();
        let emitted = emitted_tree_keys(&root);

        let source = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("policy.rs"),
        )
        .expect("policy.rs is readable");

        let mut checked = 0_usize;
        for (offset, _) in source.match_indices("input.tree.") {
            let rest = &source[offset + "input.tree.".len()..];
            let key: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if key.is_empty() {
                continue;
            }
            checked += 1;
            assert!(
                emitted.contains(&key),
                "`policy.rs`'s module doc shows `input.tree.{key}`, which \
                 `tree_document` does not emit. Emitted: {emitted:?}. This is the \
                 exact defect CLOUD-845 reproduced — an author copies the example, \
                 Rego reads the undefined path as silent, and the gate is dead."
            );
        }

        // ANTI-VACUITY: a doc rewritten to show no `input.tree.` example at all
        // would pass this trivially, and the example is the thing being protected.
        assert!(
            checked > 0,
            "the module doc shows no `input.tree.` example; this gate is reading \
             nothing and would pass on any document"
        );
    }

    // --- the per-run read budget (CLOUD-850) ---------------------------------

    #[test]
    fn the_read_budget_refuses_at_the_limit_and_not_below_it() {
        // §7(d), both halves in one function, because either alone is a gate
        // that cannot discriminate: one that never refuses is not a budget, and
        // one that always refuses is not usable.
        //
        // `perf-assert` budgets no `check` path, on the sound reason that a tree
        // walk over a large consumer repo is legitimately slower and no TIME
        // could tell that apart from a regression. This is a COUNT — a property
        // of the rule set rather than of the machine — which is exactly where a
        // clock could not decide and this can.
        super::refuse_over_budget(0, 4).expect("an empty read set is under any budget");
        super::refuse_over_budget(3, 4).expect("just below the limit does not refuse");

        let err = super::refuse_over_budget(4, 4).expect_err("at the limit it refuses");
        let message = format!("{err}");
        assert!(
            message.contains('4'),
            "the refusal names the limit it enforced: {message}"
        );

        // POINTER-ONLY, and here LESS than a pointer (§5). The natural thing to
        // print is the path list, and that list is the consumer's own file
        // names — a refusal that printed it would put the shape of a private
        // tree into an error message. A count carries the same decision and
        // none of the content.
        assert!(
            !message.contains('/') && !message.contains(".toml"),
            "no path, no extension, nothing shaped like a file name: {message}"
        );
    }

    // --- the ratchet kind (CLOUD-55) -----------------------------------------

    #[test]
    fn a_ratchet_bans_movement_never_stasis() {
        // Equality passes in both directions: a ratchet is about direction of
        // change, so "unchanged" is the case it exists to permit.
        for direction in Direction::ALL {
            assert!(
                !direction.violated(3, 3),
                "{}: equal counts are never a violation",
                direction.as_str()
            );
            assert!(!direction.violated(0, 0));
        }

        // non_decreasing: falling is the violation, rising is fine.
        assert!(Direction::NonDecreasing.violated(2, 1));
        assert!(Direction::NonDecreasing.violated(1, 0));
        assert!(!Direction::NonDecreasing.violated(1, 2));

        // non_increasing: the mirror. This is the `#[ignore]` guard, where the
        // dangerous direction is the one that adds.
        assert!(Direction::NonIncreasing.violated(0, 1));
        assert!(!Direction::NonIncreasing.violated(1, 0));
    }

    #[test]
    fn every_direction_token_round_trips() {
        for direction in Direction::ALL {
            let json = format!("\"{}\"", direction.as_str());
            assert_eq!(
                serde_json::from_str::<Direction>(&json).unwrap(),
                *direction
            );
        }
        // The two vocabularies do not overlap: a severity token in `direction`
        // is a usage error, never a reinterpretation.
        assert!(serde_json::from_str::<Direction>("\"deny\"").is_err());
        assert!(serde_json::from_str::<Direction>("\"decreasing\"").is_err());
    }

    #[test]
    fn a_ratchet_requires_its_own_columns_and_rejects_the_others() {
        let base = Rule {
            glob: Some("**/*.rs".to_owned()),
            pattern: Some("#[test]".to_owned()),
            direction: Some(Direction::NonDecreasing),
            base: Some("origin/main".to_owned()),
            ..blank("r", RuleKind::Ratchet)
        };
        assert!(base.validate().is_ok());

        // Each required column, omitted in turn.
        for missing in [
            Rule {
                direction: None,
                ..base.clone()
            },
            Rule {
                base: None,
                ..base.clone()
            },
            Rule {
                pattern: None,
                ..base.clone()
            },
            Rule {
                glob: None,
                ..base.clone()
            },
        ] {
            assert!(
                missing.validate().is_err(),
                "a ratchet missing a required column is a usage error"
            );
        }

        // A column this kind does not accept. `verbatim` names a span
        // normalization, and a ratchet hashes no span — so accepting it would
        // let a reviewer believe something was configured that is not.
        assert!(
            Rule {
                verbatim: Some(true),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Rule {
                check: Some("true".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        // Same for the other half of §9's duality: a ratchet runs nothing.
        assert!(
            Rule {
                fix: Some("true".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_err()
        );

        // `retires_with` (CLOUD-807), the optional half. Present with `base` it
        // loads; the two value-dependent refusals are the ones the column
        // census cannot express, so they are asserted here rather than left to
        // the generic driver above.
        assert!(
            Rule {
                retires_with: Some("# subject:".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_ok(),
            "a ratchet may declare the header its files name a subject with"
        );
        assert!(
            Rule {
                retires_with: Some("# subject:".to_owned()),
                base: None,
                ..base.clone()
            }
            .validate()
            .is_err(),
            "`retires_with` without `base` has no rev to ask a subject was alive at"
        );
        // A blank token strips off the front of EVERY line, so every file would
        // declare whatever its first line happens to say — an admission that
        // reads as configured and decides nothing.
        for blank_token in ["", "   "] {
            assert!(
                Rule {
                    retires_with: Some(blank_token.to_owned()),
                    ..base.clone()
                }
                .validate()
                .is_err(),
                "a blank `retires_with` is refused at load, not discovered at scan"
            );
        }
        // And it is a ratchet's column alone: no other kind compares two trees,
        // so nothing else could act on a declared subject.
        assert!(
            Rule {
                kind: RuleKind::Forbid,
                direction: None,
                retires_with: Some("# subject:".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "`retires_with` on a kind that reads one tree is refused"
        );
        // AND IT IS PAIRED WITH THE DIRECTION IT ADMITS. Each column admits one
        // direction of change, and its admission block inspects only the files
        // that moved that way — so on the opposite row it collects nothing,
        // leaves the blocker set empty and the whole row returns clean. The pair
        // below is the one that matters: not "the column is useless there" but
        // "the column switches the row off there", which is the same class as
        // the blank token and is why both are refused at load.
        assert!(
            Rule {
                direction: Some(Direction::NonIncreasing),
                retires_with: Some("# subject:".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "`retires_with` on a `non_increasing` row would admit every increase, not refine a decrease"
        );
        assert!(
            Rule {
                direction: Some(Direction::NonIncreasing),
                admits_with: Some("# stays:".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_ok(),
            "`admits_with` belongs on the row that refuses an increase"
        );
        assert!(
            Rule {
                admits_with: Some("# stays:".to_owned()),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "`admits_with` on a `non_decreasing` row would admit every decrease, not refine an increase"
        );

        // `conserves` (CLOUD-908), the obligation inside that admission. Every
        // refusal here is value-dependent — the census sees a present column and
        // nothing about what is inside it.
        let conserves = Conserves {
            case: "@test \"".to_owned(),
            close: "\"".to_owned(),
            carried: "// carried:".to_owned(),
            subsumed: "// subsumed:".to_owned(),
            changed: "// changed:".to_owned(),
            withdrawn: None,
            declared_in: "crates/**/*.rs".to_owned(),
        };
        assert!(
            Rule {
                retires_with: Some("# subject:".to_owned()),
                conserves: Some(conserves.clone()),
                ..base.clone()
            }
            .validate()
            .is_ok(),
            "a retiring ratchet may oblige a per-case mapping"
        );
        assert!(
            Rule {
                conserves: Some(conserves.clone()),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "`conserves` with no `retires_with` refines an admission that does not exist"
        );
        // A blank token in any position is the same defect `retires_with` refuses
        // in its own: an empty prefix matches the start of every line, so every
        // line declares a case or claims one.
        for blank in ["", "   "] {
            for field in 0..6 {
                let mut broken = conserves.clone();
                match field {
                    0 => broken.case = blank.to_owned(),
                    1 => broken.close = blank.to_owned(),
                    2 => broken.carried = blank.to_owned(),
                    3 => broken.subsumed = blank.to_owned(),
                    4 => broken.changed = blank.to_owned(),
                    _ => broken.declared_in = blank.to_owned(),
                }
                assert!(
                    Rule {
                        retires_with: Some("# subject:".to_owned()),
                        conserves: Some(broken),
                        ..base.clone()
                    }
                    .validate()
                    .is_err(),
                    "a blank token in `conserves` is refused at load, not discovered at scan"
                );
            }
        }
        // Two arms spelled alike make "exactly one arm" undecidable: one line
        // claims a case twice, so the double-claim refusal would fire on every
        // correct mapping instead of on the defect it names.
        for clash in [
            ("// same:", "// same:", "// changed:"),
            ("// carried:", "// same:", "// same:"),
            ("// same:", "// subsumed:", "// same:"),
        ] {
            assert!(
                Rule {
                    retires_with: Some("# subject:".to_owned()),
                    conserves: Some(Conserves {
                        carried: clash.0.to_owned(),
                        subsumed: clash.1.to_owned(),
                        changed: clash.2.to_owned(),
                        ..conserves.clone()
                    }),
                    ..base.clone()
                }
                .validate()
                .is_err(),
                "two arms spelled alike are refused at load"
            );
        }
        // A glob `globset` cannot parse selects nothing, and a mapping read over
        // nothing claims no case and so admits every deletion.
        assert!(
            Rule {
                retires_with: Some("# subject:".to_owned()),
                conserves: Some(Conserves {
                    declared_in: "crates/[unclosed".to_owned(),
                    ..conserves.clone()
                }),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "an unparseable `declared_in` is refused at load"
        );

        // `direction`/`base` on a kind that is not a ratchet is equally refused.
        assert!(
            Rule {
                kind: RuleKind::Forbid,
                direction: Some(Direction::NonDecreasing),
                base: None,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn a_ratchet_is_tree_scoped_and_spawns_no_configured_command() {
        // The two properties that keep it on `check`'s read surface: it looks at
        // the tree, and it reaches no user-supplied code. Reading
        // `carries_ambient_authority` as "no process at all" would make it enforce-only
        // and cost it the surface worth having (CLOUD-55, assumption 1).
        assert_eq!(RuleKind::Ratchet.scopes(), &[RuleScope::Tree]);
        assert!(!RuleKind::Ratchet.carries_ambient_authority());
    }

    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        // `CARGO_TARGET_TMPDIR` is only defined for integration-test crates, not
        // the library's own unit tests, so derive a scratch dir at runtime.
        let dir = std::env::temp_dir().join("batten-rules-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    /// TWO ROWS, ONE GLOB, TWO FORMS — each gets its own fact.
    ///
    /// The regression for the defect the `(path, form)` key exists to fix, and
    /// the case the single-key cache never had. Keyed on the path alone, one
    /// file holds one answer, so a precedence rule decided which of two rows was
    /// served and the loser's projection reported every one of its own declared
    /// files as could-not-look. It shipped twice — through CLOUD-914 and
    /// CLOUD-762 — because no rule set until CLOUD-756 wanted one file two ways.
    /// Measured when one finally did: 65 paths, as `policy test`'s
    /// `fixture-missing`.
    ///
    /// Fails by: keying the cache on the path alone again. Whichever form
    /// `acquire_declared` reaches second finds the other's entry and this goes
    /// red on the row that lost.
    #[test]
    fn two_rows_over_one_glob_each_get_their_own_form() {
        let dir = std::env::temp_dir().join(format!("batten-two-forms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subject.rs"), "fn f() { g(\"x\"); }\n").unwrap();

        let as_lines = Rule {
            scope: RuleScope::Tree,
            line_sources: vec!["*.rs".to_owned()],
            ..blank("wants-lines", RuleKind::Policy)
        };
        let as_calls = Rule {
            scope: RuleScope::Tree,
            invocation_sources: vec!["*.rs".to_owned()],
            ..blank("wants-calls", RuleKind::Policy)
        };
        let files = vec!["subject.rs".to_owned()];
        let cache = super::acquire_declared(&[as_lines.clone(), as_calls.clone()], &dir, &files)
            .expect("acquisition succeeds");

        // BOTH entries exist, under the same path. That is the whole property:
        // one file, two parses, neither displacing the other.
        assert!(
            matches!(
                cache.get(&("subject.rs".to_owned(), super::Wanted::Lines)),
                Some(super::Acquired::Lines(_))
            ),
            "the lines row must get lines"
        );
        assert!(
            matches!(
                cache.get(&("subject.rs".to_owned(), super::Wanted::Invocations)),
                Some(super::Acquired::Invocations(_))
            ),
            "the call-sites row must get call sites"
        );

        // AND THE PROJECTION AGREES, which is where the defect actually bit: the
        // cache could have held both and the document still reported one row's
        // files missing if a lookup asked for the wrong form.
        let (_, not_acquired) = super::tree_document(
            &cache,
            &super::Declared {
                documents: &[],
                lines: &["subject.rs".to_owned()],
                invocations: &["subject.rs".to_owned()],
                uses: &[],
            },
            &files,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &crate::git::GitFacts::default(),
            &crate::facts::Look::IsNot,
        );
        assert!(
            not_acquired.is_empty(),
            "neither row may report its own declared file as could-not-look: {not_acquired:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TWO CRATE ROOTS RESOLVE NOTHING, rather than resolving both crates
    /// against whichever sorts first.
    ///
    /// [`project_uses`]'s header promises the honest failure direction —
    /// *"visibly unresolved rather than plausibly wrong"* — and covered the
    /// no-root case. The multi-root case did the opposite: a `find` took the
    /// FIRST `lib.rs` and resolved every declared path's edges against that one
    /// export table, so a declared set spanning two crates resolved crate B's
    /// edges against crate A's `mod` list. `use_sources` makes it reachable, since
    /// a workspace glob like `crates/**/src/**/*.rs` selects several roots; this
    /// tree carries one crate, so it was latent rather than absent. Caught in
    /// review on #680.
    ///
    /// Fails by: restoring the `find`. The first assertion then resolves
    /// `Wrong` — a name only the OTHER crate's root exports — which is precisely
    /// the plausibly-wrong answer, and it looks identical to a correct one.
    #[test]
    fn two_crate_roots_resolve_no_edge_at_all() {
        let facts = |source: &str| match crate::uses::use_facts(source) {
            crate::facts::Look::Is(file) => Acquired::Uses(file),
            _ => panic!("the fixture source must parse"),
        };
        // Each root re-exports a DIFFERENT name, so which table was consulted is
        // observable in the resolved edge rather than inferred.
        let mut cache = BTreeMap::new();
        cache.insert(
            ("a/lib.rs".to_owned(), Wanted::Uses),
            facts("mod right;\npub use right::Right;\n"),
        );
        cache.insert(
            ("b/lib.rs".to_owned(), Wanted::Uses),
            facts("mod wrong;\npub use wrong::Wrong;\n"),
        );
        // A consumer whose edge names a crate-root item — the only edge class
        // that needs the root table at all.
        cache.insert(
            ("a/consumer.rs".to_owned(), Wanted::Uses),
            facts("use crate::Right;\n"),
        );

        let both = [
            "a/lib.rs".to_owned(),
            "b/lib.rs".to_owned(),
            "a/consumer.rs".to_owned(),
        ];
        let mut out = serde_json::Map::new();
        let (mut missing, mut causes) = (Vec::new(), Vec::new());
        project_uses(&cache, &both, &mut out, &mut missing, &mut causes);
        let edges = out
            .get("a/consumer.rs")
            .and_then(|value| value.as_array())
            .expect("the consumer was projected");
        assert!(
            edges
                .iter()
                .all(|edge| { edge.get("to").and_then(serde_json::Value::as_str) == Some("") }),
            "two roots must leave every root-item edge unresolved: {edges:?}"
        );

        // THE TWIN. With one root declared the same edge DOES resolve, so the
        // assertion above discriminates the root count rather than a projection
        // that never resolves anything.
        let one = ["a/lib.rs".to_owned(), "a/consumer.rs".to_owned()];
        let mut out = serde_json::Map::new();
        let (mut missing, mut causes) = (Vec::new(), Vec::new());
        project_uses(&cache, &one, &mut out, &mut missing, &mut causes);
        let edges = out
            .get("a/consumer.rs")
            .and_then(|value| value.as_array())
            .expect("the consumer was projected");
        assert!(
            edges.iter().any(|edge| {
                edge.get("to").and_then(serde_json::Value::as_str) == Some("right")
            }),
            "one root resolves the edge through its own table: {edges:?}"
        );
    }

    /// A rule with every column empty, for a test to fill in the one it means.
    ///
    /// Keeps the fixtures below from re-listing six `None`s each, so adding a
    /// column touches this one place rather than every test.
    fn blank(id: &str, kind: RuleKind) -> Rule {
        Rule {
            id: id.to_owned(),
            kind,
            glob: None,
            // Per kind, because `severity` is now a per-kind column: the judge
            // kind is refused it, so handing every fixture one would make the
            // one kind that must not carry it unloadable in every test here.
            severity: kind
                .permits()
                .contains(&"severity")
                .then_some(RuleSeverity::Deny),
            scope: kind.scopes()[0],
            pattern: None,
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
            contains: None,
            require_via: None,
            requires_key: None,
            reason: None,
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
            landing: Vec::new(),
            delta_sources: Vec::new(),
            predicate_severity: None,
            criteria: None,
            tier: None,
            // The one that needs no argv, so a fixture about a different column
            // does not have to invent a fix command. A `shape` row is refused
            // this column (CLOUD-81), so it gets none — and a kind that also
            // permits `fix` gets none either, so a fixture setting `fix` is not
            // silently pushed into the both-columns state the xor refuses.
            no_fix_reason: (kind.permits().contains(&"no_fix_reason")
                && !kind.permits().contains(&"fix"))
            .then(|| "fixture".to_owned()),
            // Same shape as the columns above: filled only for the kind that
            // permits it, so a fixture for another kind is not born invalid.
            checks: kind
                .permits()
                .contains(&"checks")
                .then(|| vec!["verify".to_owned()]),
            key: None,
            trigger: None,
            verdict: None,
            filters: None,
            substitutes: None,
        }
    }

    /// The findings half of a scan. Every assertion below is about what was
    /// found; [`Scan::not_evaluated`] has its own tests, so shadowing keeps the
    /// suite reading as it did before that half existed.
    fn run_static(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
        super::run_static(rules, &[], crate::policy::Vocabulary::EMPTY, root)
            .map(|scan| scan.findings)
    }

    fn run_all(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
        super::run_all(rules, &[], crate::policy::Vocabulary::EMPTY, root).map(|scan| scan.findings)
    }

    fn forbid(id: &str, glob: &str, pattern: &str) -> Rule {
        Rule {
            glob: Some(glob.to_owned()),
            pattern: Some(pattern.to_owned()),
            ..blank(id, RuleKind::Forbid)
        }
    }

    fn command(id: &str, glob: &str, check: &str) -> Rule {
        Rule {
            glob: Some(glob.to_owned()),
            check: Some(check.to_owned()),
            ..blank(id, RuleKind::Command)
        }
    }

    fn shape(id: &str, pattern: &str, reason: &str) -> Rule {
        Rule {
            pattern: Some(pattern.to_owned()),
            reason: Some(reason.to_owned()),
            ..blank(id, RuleKind::Shape)
        }
    }

    #[test]
    fn the_two_remediation_columns_are_alternatives_never_both() {
        // CLOUD-81's config half. Carrying both is a contradiction with two
        // answers, refused here; carrying neither is refused at *ingest*
        // instead (§5), so a rule that predates the field still gates.
        //
        // Total over every kind whose findings reach the store, and over all
        // four present/absent combinations — the exactly-one-of shape
        // `requires()` structurally cannot express, the same reason
        // `pattern`-xor-`regex` needs a check of its own.
        for kind in [RuleKind::Forbid, RuleKind::Command, RuleKind::Ratchet] {
            let base = match kind {
                RuleKind::Forbid => forbid("r", "**", "TODO"),
                RuleKind::Command => command("r", "**", "true"),
                _ => Rule {
                    glob: Some("**".to_owned()),
                    pattern: Some("TODO".to_owned()),
                    direction: Some(Direction::NonDecreasing),
                    base: Some("HEAD".to_owned()),
                    ..blank("r", RuleKind::Ratchet)
                },
            };
            let with = |fix: Option<&str>, reason: Option<&str>| Rule {
                fix: fix.map(ToOwned::to_owned),
                no_fix_reason: reason.map(ToOwned::to_owned),
                ..base.clone()
            };

            assert!(with(None, Some("by hand")).validate().is_ok());
            assert!(
                with(None, None).validate().is_ok(),
                "neither loads and still gates; the store is what refuses it"
            );
            assert_eq!(
                with(None, None).remediation(),
                None,
                "…and it reaches ingest as the absence ingest refuses"
            );

            // `fix` is CLOUD-215's reserved repair column, and `permits` puts it
            // on the `command` kind alone. So the xor only has a second column to
            // contradict there; on the other two the census refuses `fix` before
            // this check is reached, which is the same answer one layer earlier.
            let with_fix = with(Some("cargo fmt"), None).validate();
            let both = with(Some("cargo fmt"), Some("by hand")).validate();
            if kind == RuleKind::Command {
                assert!(with_fix.is_ok());
                assert_eq!(
                    with(Some("cargo fmt"), None).remediation(),
                    Some(Remediation::Fix(vec!["cargo".to_owned(), "fmt".to_owned()])),
                    "the reserved repair column is READ here, never run — recording a \
                     repair on a finding is not executing one"
                );
                let err = both.unwrap_err();
                assert!(
                    err.to_string().contains("alternatives"),
                    "a row carries exactly one, never both: {err}"
                );
            } else {
                for refused in [with_fix, both] {
                    let err = refused.unwrap_err();
                    assert!(
                        err.to_string().contains("`fix` is not valid"),
                        "the census refuses `fix` on {}: {err}",
                        kind.as_str()
                    );
                }
            }
        }
    }

    #[test]
    fn a_shape_rule_is_refused_both_remediation_columns() {
        // A shape rule is adjudicated per mediated call and never reaches the
        // store, so a remediation on one is decorative by construction — the
        // same reasoning that already denies it `identity_key`.
        for column in ["fix", "no_fix_reason"] {
            let rule = Rule {
                fix: (column == "fix").then(|| "cargo fmt".to_owned()),
                no_fix_reason: (column == "no_fix_reason").then(|| "by hand".to_owned()),
                ..shape("s", "gh pr merge", "use the task")
            };
            let err = rule.validate().unwrap_err();
            assert!(
                err.to_string().contains(column),
                "`{column}` must be refused on a shape rule: {err}"
            );
        }
        assert!(shape("s", "gh pr merge", "use the task").validate().is_ok());
        assert_eq!(
            shape("s", "gh pr merge", "use the task").settling_check(),
            None,
            "a rule that never reaches the store has no check to carry"
        );
    }

    #[test]
    fn a_check_is_derived_from_the_kind_never_declared_twice() {
        // The design decision this issue turns on: a `command` rule already IS
        // an exit-code predicate, so its `check` column is reused rather than
        // restated as a second column that could disagree with it (house style
        // §9's duality, which CLOUD-215 named the column for). Every other
        // storable kind is re-evaluated by the
        // engine, whose own verdict is the exit code — which is what avoids
        // writing "the banned literal is gone" as a shell negation the engine
        // deliberately does not offer.
        assert_eq!(
            command("r", "**", "cargo fmt --check").settling_check(),
            Some(Check::Argv(vec![
                "cargo".to_owned(),
                "fmt".to_owned(),
                "--check".to_owned(),
            ])),
            "the command rule's own `check`, split exactly as it is executed"
        );
        assert_eq!(
            forbid("r", "**", "TODO").settling_check(),
            Some(Check::Reevaluate)
        );

        // The remediation is data on the rule, split the same way. `fix` lives
        // on the `command` kind alone (CLOUD-215's reserved repair column), so
        // that is where the argv form is expressible.
        assert_eq!(
            Rule {
                fix: Some("cargo fmt".to_owned()),
                no_fix_reason: None,
                ..command("r", "**", "true")
            }
            .remediation(),
            Some(Remediation::Fix(vec!["cargo".to_owned(), "fmt".to_owned()]))
        );
        assert_eq!(
            forbid("r", "**", "TODO").remediation(),
            Some(Remediation::NoFix("fixture".to_owned()))
        );
    }

    #[test]
    fn a_rule_that_matched_nothing_reports_skipped_rather_than_clean() {
        // The producer side of CLOUD-81's fail-closed law. A rule whose glob
        // matched no file emits exactly what a clean rule emits — nothing — so
        // the findings list alone cannot tell the two apart. `Scan` carries the
        // difference, and the store holds on it rather than resolving.
        let dir = temp_dir("scan-skipped");
        write(&dir, "src/a.rs", "fine\n");

        let clean = super::run_static(
            &[forbid("looked", "**/*.rs", "TODO")],
            &[],
            crate::policy::Vocabulary::EMPTY,
            &dir,
        )
        .unwrap();
        assert!(clean.findings.is_empty());
        assert!(
            clean.not_evaluated.is_empty(),
            "a rule that read a file and found nothing DID evaluate"
        );

        let skipped = super::run_static(
            &[forbid("never-looked", "**/*.md", "TODO")],
            &[],
            crate::policy::Vocabulary::EMPTY,
            &dir,
        )
        .unwrap();
        assert!(skipped.findings.is_empty());
        assert_eq!(
            skipped.not_evaluated.get("never-looked"),
            Some(&NotObserved::RuleSkipped),
            "an empty match set is a rule that did not look, not a clean one"
        );

        // An `allow` row is configured off, which is also not an evaluation: it
        // must not clear the findings it covered while it was on.
        let off = super::run_static(
            &[Rule {
                severity: Some(RuleSeverity::Allow),
                ..forbid("switched-off", "**/*.rs", "TODO")
            }],
            &[],
            crate::policy::Vocabulary::EMPTY,
            &dir,
        )
        .unwrap();
        assert_eq!(
            off.not_evaluated.get("switched-off"),
            Some(&NotObserved::RuleSkipped)
        );
    }

    #[test]
    fn glob_star_stays_within_a_segment() {
        assert!(glob_match("*.rs", "lib.rs"));
        assert!(!glob_match("*.rs", "src/lib.rs"));
    }

    #[test]
    fn glob_double_star_spans_segments() {
        assert!(glob_match("**/*.rs", "src/a/b/lib.rs"));
        assert!(glob_match("**/*.rs", "lib.rs"));
        assert!(glob_match("src/**", "src/a/b/c"));
        assert!(!glob_match("src/**/*.rs", "other/lib.rs"));
    }

    #[test]
    fn glob_question_matches_one_char() {
        assert!(glob_match("a?c.txt", "abc.txt"));
        assert!(!glob_match("a?c.txt", "ac.txt"));
    }

    #[test]
    fn glob_semantics_are_pinned_at_the_shipped_patterns() {
        // The parity obligation of adopting `globset` (CLOUD-214). The three
        // cases above pin the vocabulary; these pin the patterns consumer #1
        // actually ships, because a matcher swap that widened or narrowed one of
        // them would change which files a live gate judges with nothing red.
        //
        // The load-bearing one is `**` matching ZERO intervening components:
        // every bats suite in this repository sits directly in `tests/`, so if
        // `tests/**/*.bats` stopped selecting `tests/land.bats` the ratchet
        // CLOUD-328 widened would silently select nothing and read as green.
        assert!(glob_match("tests/**/*.bats", "tests/land.bats"));
        assert!(glob_match("tests/**/*.bats", "tests/suite/deep.bats"));
        assert!(!glob_match("tests/**/*.bats", "crates/land.bats"));

        assert!(glob_match("crates/**/*.rs", "crates/batten/src/rules.rs"));
        assert!(glob_match("crates/**/*.rs", "crates/lib.rs"));
        assert!(glob_match("crates/**", "crates/batten/Cargo.toml"));
        assert!(!glob_match("crates/**", "batten.toml"));

        // A dot-directory two segments deep, spelled generically: naming a real
        // consumer's automation directory here would put that consumer's
        // identifier in the core (non-negotiable rule 1), which
        // `tests/document_facts.rs` gates. The shape under test is the path
        // shape, not whose path it is.
        assert!(glob_match(".ci/jobs/*.yml", ".ci/jobs/build.yml"));
        // Single-segment `*` must NOT reach a nested file, or the row would
        // judge files its author did not name.
        assert!(!glob_match(".ci/jobs/*.yml", ".ci/jobs/nested/build.yml"));
        assert!(glob_match(
            ".serena/memories/**",
            ".serena/memories/core.md"
        ));
        assert!(glob_match("batten.toml", "batten.toml"));
        assert!(!glob_match("batten.toml", "crates/batten.toml"));
    }

    #[test]
    fn a_glob_that_does_not_compile_is_refused_where_it_is_named() {
        // `globset` can reject a pattern the hand-rolled matcher silently
        // accepted, so the failure has to land at load, naming the row — not as
        // a rule that quietly selects nothing and reads as a gate finding
        // nothing wrong.
        let malformed = Rule {
            glob: Some("crates/[unclosed".to_owned()),
            pattern: Some("x".to_owned()),
            ..blank("bad-glob", RuleKind::Forbid)
        };
        let err = malformed.validate().unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a malformed glob is bad config, not an internal failure"
        );
        let text = err.to_string();
        assert!(text.contains("bad-glob"), "names the row: {text}");

        // And the convenience form cannot manufacture a match from one.
        assert!(!glob_match("crates/[unclosed", "crates/anything"));
    }

    #[test]
    fn forbid_reports_pointer_only_findings() {
        let dir = temp_dir("rules-forbid-hit");
        write(&dir, "src/a.rs", "ok line\nTODO here\nanother TODO\n");
        write(&dir, "README.md", "TODO in docs is ignored by the glob\n");

        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();

        // Projected rather than compared whole: a finding now carries a
        // fingerprint, and rebuilding the expected one here would be the
        // test-side join CLOUD-164 exists to delete. What this test is about is
        // which lines matched.
        assert_eq!(
            findings
                .iter()
                .map(|f| (f.rule.as_str(), f.path.as_str(), f.line))
                .collect::<Vec<_>>(),
            vec![
                ("no-todo", "src/a.rs", Some(2)),
                ("no-todo", "src/a.rs", Some(3)),
            ]
        );
        // The two matched lines differ in content ("TODO here" vs "another
        // TODO"), so they are two identities — identity is derived from the
        // span, not from the path the finding points at. The same-span-twice
        // case is one identity with a count, and is pinned where it belongs, in
        // `identity`'s own pack and the churn fixtures.
        assert_ne!(findings[0].identity, findings[1].identity);
        assert_eq!(
            findings[0].identity.version,
            identity::FindingKind::Code.identity_version()
        );
    }

    #[test]
    fn clean_tree_yields_no_findings() {
        let dir = temp_dir("rules-forbid-clean");
        write(&dir, "src/a.rs", "all clear\n");
        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn results_are_byte_stable_across_runs() {
        let dir = temp_dir("rules-stable");
        write(&dir, "b.rs", "TODO\n");
        write(&dir, "a.rs", "TODO\n");
        write(&dir, "src/c.rs", "TODO\n");
        let rule = forbid("no-todo", "**/*.rs", "TODO");
        let first = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        let second = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert_eq!(first, second);
        // Sorted by path: a.rs, b.rs, src/c.rs.
        let paths: Vec<&str> = first.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["a.rs", "b.rs", "src/c.rs"]);
    }

    #[test]
    fn git_directory_is_never_inspected() {
        let dir = temp_dir("rules-skip-git");
        write(&dir, ".git/config", "TODO must not be read\n");
        write(&dir, "a.rs", "clean\n");
        let findings = run_static(&[forbid("no-todo", "**", "TODO")], &dir).unwrap();
        assert!(findings.is_empty(), "the .git dir must be skipped");
    }

    #[test]
    fn non_utf8_file_never_matches() {
        let dir = temp_dir("rules-binary");
        fs::write(dir.join("blob.rs"), [0xff, 0xfe, 0x00]).unwrap();
        let findings = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn every_optional_rule_field_is_classified_by_every_kind() {
        // The census's own gate. Every column a rule can carry must be either
        // required or permitted by at least one kind — a column classified by no
        // kind is one every kind rejects, which is a field nobody can ever set.
        // This is what the hand-written per-kind match could not give: it named
        // fields, so a new one simply appeared in no arm.
        let all = blank("probe", RuleKind::Forbid).columns();
        for (name, _) in all {
            let classified = RuleKind::ALL
                .iter()
                .any(|kind| kind.permits().contains(&name));
            assert!(
                classified,
                "column `{name}` is permitted by no kind, so it can never be set"
            );
        }
        // And `requires` must be a subset of `permits` for every kind, or a kind
        // would demand a column it then rejects.
        for kind in RuleKind::ALL {
            for required in kind.requires() {
                assert!(
                    kind.permits().contains(required),
                    "{kind:?} requires `{required}` but does not permit it"
                );
            }
        }
    }

    #[test]
    fn no_mediated_call_kind_carries_ambient_authority() {
        // What actually makes `hook`'s dispatch structurally unable to reach past
        // its inputs, stated over the whole cross product rather than a named
        // pair. `Policy::from_resolved` filters on scope alone, so this is the
        // property that filter relies on.
        //
        // The REPLACEMENT for `no_mediated_call_kind_spawns_a_process`, and
        // strictly stronger rather than a rename: that pin asked "does it
        // spawn?", so a kind reaching the network without starting a program
        // would have passed it. This asks whether the kind can acquire anything
        // its inputs did not carry, which refuses that kind too — whatever wrote
        // it, and whatever it happens to spawn.
        for kind in RuleKind::ALL {
            if kind.scopes().contains(&RuleScope::MediatedCall) {
                assert!(
                    admissible_at_mediated_call(kind.authority()),
                    "{kind:?} is adjudicable at the mediation channel and carries `{}` authority",
                    kind.authority().as_str()
                );
            }
        }
    }

    #[test]
    fn the_replacement_pin_is_strictly_stronger_than_the_one_it_retired() {
        // CLOUD-418: a gate never shown to fail ships as coverage. The pin above
        // cannot fail today — every kind is classified correctly — so strictness
        // is proved over the AUTHORITY rather than over the kind table, by
        // feeding the admission predicate a value no kind carries yet.
        //
        // The retired predicate, written out so the comparison is a comparison
        // and not a claim about one.
        let spawn_only = |authority: Authority| !matches!(authority, Authority::Spawns);

        // The case that separates them: `Acquires` reaches the network without
        // starting a program. The old question admitted it to the mediated call.
        assert!(
            spawn_only(Authority::Acquires),
            "the retired pin admitted a kind that acquires without spawning"
        );
        assert!(
            !admissible_at_mediated_call(Authority::Acquires),
            "the replacement must refuse it — that is the whole strengthening"
        );

        // And nothing the retired pin refused is admitted by the replacement, so
        // "stronger" is not bought by relaxing somewhere else.
        for authority in Authority::ALL {
            if !spawn_only(*authority) {
                assert!(
                    !admissible_at_mediated_call(*authority),
                    "{} was refused before and must stay refused",
                    authority.as_str()
                );
            }
        }
    }

    #[test]
    fn bound_one_the_fact_set_is_the_whole_input() {
        // CLOUD-763's first bound, as a check rather than an intention: a kind
        // admitted to the mediated call reads only what the boundary handed it,
        // and that is asserted on BOTH classifications rather than one — the
        // authority axis says it acquires nothing, and CLOUD-757's cost axis says
        // resolving its facts spends nothing beyond a bounded read. Two
        // classifications of one property that disagreed would be worse than one.
        for kind in RuleKind::ALL {
            if !kind.scopes().contains(&RuleScope::MediatedCall) {
                continue;
            }
            assert_eq!(
                kind.authority(),
                Authority::Supplied,
                "{kind:?} reaches the mediated call and is not supplied-only"
            );
            // At the scope the bound is ABOUT (CLOUD-833). `fact_class` is a
            // function of kind and scope now, and a kind that takes both — today
            // `Policy` — has a different class on each. Asking for its tree
            // class here would judge the mediated-call bound against a surface
            // the mediated call never uses.
            let mediated = kind.fact_class(RuleScope::MediatedCall);
            assert!(
                matches!(
                    mediated.cost,
                    crate::facts::Cost::Free | crate::facts::Cost::Read
                ),
                "{kind:?} reaches the mediated call at cost `{}`",
                mediated.cost.as_str()
            );
            assert_eq!(
                mediated.surface,
                crate::facts::Surface::Hook,
                "{kind:?} reaches the mediated call from a narrower surface"
            );
        }
    }

    #[test]
    fn the_two_axes_agree_about_every_kind() {
        // The converse of the bound above, which is where a drift would actually
        // land: a kind classified `Supplied` must not be classified `effect` by
        // the cost axis, and one that spawns must not read as free. Adding a kind
        // and classifying it on one axis only is the mistake this catches.
        // OVER EVERY PAIRING, not every kind (CLOUD-833). The class is a
        // function of kind and scope, so a sweep over kinds alone would judge
        // each one at whichever scope this loop happened to pick — and would go
        // silent on exactly the kind that has two.
        for kind in RuleKind::ALL {
            for scope in kind.scopes() {
                let class = kind.fact_class(*scope);
                let spends = matches!(
                    class.cost,
                    crate::facts::Cost::Effect | crate::facts::Cost::Stateful
                );
                assert_eq!(
                    kind.carries_ambient_authority(),
                    spends,
                    "{kind:?} at scope `{}` is `{}` on the authority axis and `{}` on the \
                     cost axis",
                    scope.as_str(),
                    kind.authority().as_str(),
                    class.cost.as_str()
                );
            }
        }
    }

    #[test]
    fn kind_and_scope_vocabularies_do_not_cross() {
        // The same separation `severity_and_scope_vocabularies_do_not_cross`
        // enforces, applied to the pair that nearly collided: `command` is a
        // kind, and naming a scope `command` too would make one word mean two
        // unrelated things across two keys in the same table.
        for kind in RuleKind::ALL {
            for scope in RuleScope::ALL {
                assert_ne!(
                    kind.as_str(),
                    scope.as_str(),
                    "the token {:?} names both a kind and a scope",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn a_kind_only_accepts_its_own_scopes() {
        // A kind/scope pairing the engine cannot honour must be refused, never
        // accepted and then never evaluated. An inert rule reads as coverage,
        // which is the failure this whole file is written against.
        for kind in RuleKind::ALL {
            for scope in RuleScope::ALL {
                let mut rule = blank("pairing", *kind);
                rule.scope = *scope;
                // Fill whatever this kind requires so the only possible
                // complaint is the pairing.
                for column in kind.requires() {
                    match *column {
                        "glob" => rule.glob = Some("**".to_owned()),
                        "pattern" => rule.pattern = Some("x".to_owned()),
                        "check" => rule.check = Some("true".to_owned()),
                        "reason" => rule.reason = Some("because".to_owned()),
                        "direction" => rule.direction = Some(Direction::NonDecreasing),
                        "base" => rule.base = Some("HEAD".to_owned()),
                        "checks" => rule.checks = Some(vec!["verify".to_owned()]),
                        // `blank` already sets one; naming it here keeps the
                        // census total now that it is a per-kind column.
                        "severity" => rule.severity = Some(RuleSeverity::Deny),
                        "verdict" => {
                            rule.verdict = Some(vec![VerdictProgram {
                                program: "p".to_owned(),
                                subcommands: Some(vec!["run".to_owned()]),
                                nested: None,
                                except: None,
                                any_argument: None,
                            }]);
                        }
                        "filters" => rule.filters = Some(vec!["tail".to_owned()]),
                        "criteria" => rule.criteria = Some("intentional?".to_owned()),
                        "no_fix_reason" => rule.no_fix_reason = Some("answered by hand".to_owned()),
                        "format" => rule.format = Some(crate::facts::Format::Toml),
                        "node" => rule.node = Some("a.b".to_owned()),
                        // A path, not a body: this census is about scope
                        // pairings, and `policy::load` is what decides whether
                        // the file behind it compiles.
                        "module" => rule.module = Some("policy/x.rego".to_owned()),
                        other => panic!("unclassified required column `{other}`"),
                    }
                }
                // `requires()` alone does not make a loadable `forbid` row: its
                // requirement is "exactly one of `pattern` or `regex`", which a
                // flat column list cannot express, so neither appears there
                // (CLOUD-283). This test is about scope pairings, so it supplies
                // the literal and lets `validate_forbid_predicate` be tested by
                // the cases that are about it.
                if *kind == RuleKind::Forbid {
                    rule.pattern = Some("x".to_owned());
                }
                // The same shape, for the same reason: a receipt row's `pattern`
                // is required only under the default `command` trigger
                // (CLOUD-444), which a flat column list cannot express either, so
                // it does not appear in `requires()`. Supplied here so the only
                // possible complaint stays the pairing.
                if *kind == RuleKind::Receipt {
                    rule.pattern = Some("x".to_owned());
                }
                // And a sixth (CLOUD-758): a shape row carries exactly one of
                // `pattern` or `content`, which the flat column list cannot say
                // for the reason the five below give. Supplied so the only
                // possible complaint stays the pairing.
                if *kind == RuleKind::Shape {
                    rule.pattern = Some("x".to_owned());
                }
                // And once more, for the third "one of" (CLOUD-773): a document
                // row carries exactly one of `pattern` or `reads`, which the flat
                // column list cannot say either. Supplied so the only possible
                // complaint stays the pairing.
                if *kind == RuleKind::Document {
                    rule.pattern = Some("x".to_owned());
                }
                // And the fourth and fifth, both CLOUD-833's. A policy row
                // carries exactly one of `module` or `bundle`, which a flat
                // column list cannot express any more than the four above; and a
                // tree-scoped one is required `documents`, which depends on the
                // row's SCOPE rather than on its kind — something `requires()`
                // is keyed on the kind alone and structurally cannot say.
                // Supplied here so the only possible complaint stays the
                // pairing, which is what this test is about.
                if *kind == RuleKind::Policy {
                    rule.module = Some("policy/x.rego".to_owned());
                    if *scope == RuleScope::Tree {
                        rule.documents = vec!["batten.toml".to_owned()];
                    }
                }
                // And the sixth, CLOUD-864's. A pipeline row carries one of two
                // FAMILIES — the discard pair (`verdict` + `filters`) or the
                // substitution list (`substitutes`) — which a flat column list
                // cannot express for the same reason as the five above, so
                // neither appears in `requires()`. Supplied here so the only
                // possible complaint stays the pairing.
                if *kind == RuleKind::Pipeline {
                    rule.substitutes = Some(vec!["cat".to_owned()]);
                }
                let result = rule.validate();
                if kind.scopes().contains(scope) {
                    assert!(result.is_ok(), "{kind:?}/{scope:?} must load");
                } else {
                    let err = result.expect_err("an unevaluable pairing must be refused");
                    assert!(err.downcast_ref::<UsageError>().is_some());
                }
            }
        }
    }

    /// A loadable receipt row with the trigger under test.
    fn receipt_row(trigger: Option<ReceiptTrigger>) -> Rule {
        let mut rule = blank("r", RuleKind::Receipt);
        rule.scope = RuleScope::MediatedCall;
        rule.reason = Some("earn it".to_owned());
        rule.checks = Some(vec!["claim".to_owned()]);
        rule.trigger = trigger;
        rule
    }

    #[test]
    fn a_command_triggered_receipt_row_still_requires_its_pattern() {
        // `pattern` left `requires()` so a write trigger could exist; the
        // requirement did not go away, it became conditional. A command row
        // without one would match every mediated call, turning a precondition
        // into a universal gate.
        for trigger in [None, Some(ReceiptTrigger::Command)] {
            let row = receipt_row(trigger);
            let err = row.validate().unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "a command-triggered row needs a pattern: {trigger:?}"
            );
            let mut with_pattern = receipt_row(trigger);
            with_pattern.pattern = Some("gh pr ready".to_owned());
            assert!(with_pattern.validate().is_ok());
        }
    }

    #[test]
    fn a_write_triggered_receipt_row_refuses_a_command_shape_column() {
        // Both columns name a command line, and a write has none — so either
        // would sit there matching nothing while reading as a narrowing.
        assert!(receipt_row(Some(ReceiptTrigger::Write)).validate().is_ok());
        let mut with_pattern = receipt_row(Some(ReceiptTrigger::Write));
        with_pattern.pattern = Some("gh pr ready".to_owned());
        assert!(with_pattern.validate().is_err());
        let mut with_contains = receipt_row(Some(ReceiptTrigger::Write));
        with_contains.contains = Some("fast-forward".to_owned());
        assert!(with_contains.validate().is_err());
    }

    #[test]
    fn a_branch_keyed_receipt_row_loads_now_that_the_store_exists() {
        // This column was refused at load until CLOUD-444, naming that issue.
        // The refusal going away IS the change, so it is asserted rather than
        // left to the absence of a test.
        let mut row = receipt_row(Some(ReceiptTrigger::Write));
        row.key = Some(ReceiptKey::Branch);
        assert!(row.validate().is_ok());
        assert_eq!(row.receipt_key(), ReceiptKey::Branch);
        // And the defaults still resolve one way each.
        assert_eq!(receipt_row(None).receipt_key(), ReceiptKey::Head);
        assert_eq!(receipt_row(None).receipt_trigger(), ReceiptTrigger::Command);
    }

    #[test]
    fn one_check_name_cannot_be_required_under_two_keys() {
        // The false green this refuses: whichever row the boundary resolved
        // first would decide what invalidates the other's receipt — a
        // branch-keyed claim expiring per commit, or a HEAD-keyed verification
        // outliving the bytes it validated.
        let mut branch = receipt_row(Some(ReceiptTrigger::Write));
        branch.id = "claim-needs-receipt".to_owned();
        branch.key = Some(ReceiptKey::Branch);
        let mut head = receipt_row(None);
        head.id = "other".to_owned();
        head.pattern = Some("gh pr ready".to_owned());
        head.checks = Some(vec!["claim".to_owned()]);
        let err = validate(&[branch.clone(), head.clone()]).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        // The same name under the SAME key is not a collision: two rows may
        // legitimately depend on one receipt.
        head.key = Some(ReceiptKey::Branch);
        head.trigger = Some(ReceiptTrigger::Write);
        head.pattern = None;
        assert!(validate(&[branch, head]).is_ok());
    }

    #[test]
    fn a_shape_rule_requires_a_pattern_and_a_reason() {
        let mut no_pattern = blank("s", RuleKind::Shape);
        no_pattern.reason = Some("because".to_owned());
        assert!(no_pattern.validate().is_err(), "a shape needs a pattern");

        let mut no_reason = blank("s", RuleKind::Shape);
        no_reason.pattern = Some("gh pr merge".to_owned());
        // A mediated deny reaches a model as the whole explanation, so a row
        // that would refuse with nothing but an id cannot load (CLOUD-122).
        assert!(no_reason.validate().is_err(), "a shape needs a reason");
    }

    /// A shape row is keyed on a command, on content, or on a tool — exactly one.
    ///
    /// The one-of `permits()` structurally cannot express, so it has its own
    /// predicate and needs its own case. A row with NONE matches every
    /// mediated call and turns a ban into a universal gate; a row with more than
    /// one is two predicates where the reader can see one.
    ///
    /// **Three columns since CLOUD-924, and the pairs are enumerated rather than
    /// sampled**: with two columns "both" was the only collision there was, so
    /// one case covered it. With three there are three pairs, and asserting one
    /// of them would leave two combinations able to load a row with two
    /// predicates in it.
    ///
    /// Fails by: returning `Ok(())` from any arm of `validate_shape_columns`.
    #[test]
    fn a_shape_row_is_keyed_on_a_command_or_on_content_never_both() {
        let mut content_only = blank("s", RuleKind::Shape);
        content_only.reason = Some("because".to_owned());
        content_only.content = Some("(?m)^<<<<<<< ".to_owned());
        assert!(
            content_only.validate().is_ok(),
            "a content-keyed shape row loads without a command line"
        );

        let mut tool_only = blank("s", RuleKind::Shape);
        tool_only.reason = Some("because".to_owned());
        tool_only.tool = Some("save_issue".to_owned());
        assert!(
            tool_only.validate().is_ok(),
            "a tool-keyed shape row loads without a command line"
        );

        // An empty selector would match the empty final segment of every name
        // ending in `__`, so it is refused at load rather than at adjudication.
        let mut empty_tool = blank("s", RuleKind::Shape);
        empty_tool.reason = Some("because".to_owned());
        empty_tool.tool = Some(String::new());
        let err = empty_tool.validate().expect_err("an empty selector");
        assert!(
            format!("{err}").contains("`tool` is empty"),
            "the refusal must name the empty selector: {err}"
        );

        // All three pairs, because three columns have three collisions.
        for (label, mutate) in [
            (
                "pattern and content",
                &(|rule: &mut Rule| {
                    rule.content = Some("(?m)^x".to_owned());
                    rule.pattern = Some("gh pr merge".to_owned());
                }) as &dyn Fn(&mut Rule),
            ),
            (
                "pattern and tool",
                &(|rule: &mut Rule| {
                    rule.pattern = Some("gh pr merge".to_owned());
                    rule.tool = Some("save_issue".to_owned());
                }),
            ),
            (
                "content and tool",
                &(|rule: &mut Rule| {
                    rule.content = Some("(?m)^x".to_owned());
                    rule.tool = Some("save_issue".to_owned());
                }),
            ),
        ] {
            let mut both = blank("s", RuleKind::Shape);
            both.reason = Some("because".to_owned());
            mutate(&mut both);
            let err = both
                .validate()
                .expect_err("two predicates, one row: {label}");
            assert!(
                format!("{err}").contains("never on more than one"),
                "the refusal must name the collision ({label}): {err}"
            );
        }

        let mut neither = blank("s", RuleKind::Shape);
        neither.reason = Some("because".to_owned());
        let err = neither.validate().expect_err("a row keyed on nothing");
        assert!(
            format!("{err}").contains("`content`") && format!("{err}").contains("`tool`"),
            "the refusal must name every column it would accept: {err}"
        );
    }

    /// A `content` expression that will not compile is refused at LOAD.
    ///
    /// `a_key_expression_that_does_not_compile_is_refused_at_load`, one column
    /// over. Left to adjudication the row is skipped on every mediated call —
    /// present in the file, configured to the reader, denying nothing.
    ///
    /// Fails by: dropping the `Regex::new` from `validate_shape_columns`.
    #[test]
    fn a_content_expression_that_does_not_compile_is_refused_at_load() {
        let mut rule = blank("s", RuleKind::Shape);
        rule.reason = Some("because".to_owned());
        rule.content = Some("[unterminated".to_owned());
        let err = rule
            .validate()
            .expect_err("an unparseable content expression");
        assert!(
            format!("{err}").contains("`content`"),
            "the refusal must name the column: {err}"
        );
    }

    /// A content-keyed shape row cannot carry a column that narrows a COMMAND.
    ///
    /// The census permits `contains`, `require_via`, `requires_key` and `base` on
    /// this kind, because a command-keyed row wants all four — and `adjudicate`
    /// evaluates only `content` once a row is content-keyed. So each of them
    /// loaded clean and was ignored on every call, leaving a row that reads as
    /// narrowed in the file and is not: the inert-configuration failure this
    /// file's validation surface exists to close, one column further along than
    /// the compile check above.
    ///
    /// Each is asserted SEPARATELY rather than as one row carrying all four,
    /// because a single combined case passes as soon as the first column is
    /// rejected and says nothing about the other three.
    ///
    /// Fails by: dropping any arm from the modifier loop in
    /// `validate_shape_columns`.
    #[test]
    fn a_content_keyed_shape_row_refuses_every_command_only_column() {
        let base = || {
            let mut rule = blank("s", RuleKind::Shape);
            rule.reason = Some("because".to_owned());
            rule.content = Some("(?m)^<<<<<<< ".to_owned());
            rule
        };
        assert!(
            base().validate().is_ok(),
            "the bare content row is the control, and must still load"
        );

        // Each row built and asserted through one closure rather than a table of
        // function pointers: the columns have four different types, so a table
        // needs `fn(&mut Rule)` and that trips `clippy::type_complexity` for no
        // reading benefit.
        let refused = |column: &str, rule: Rule| {
            let Err(err) = rule.validate() else {
                panic!("a content-keyed row carrying `{column}` must be refused at load");
            };
            assert!(
                format!("{err}").contains(column),
                "the refusal must name the column it rejected: {err}"
            );
        };

        let mut with_contains = base();
        with_contains.contains = Some("secret".to_owned());
        refused("contains", with_contains);

        let mut with_require_via = base();
        with_require_via.require_via = Some(RequireVia::Mise);
        refused("require_via", with_require_via);

        let mut with_requires_key = base();
        with_requires_key.requires_key = Some("CLOUD-[0-9]+".to_owned());
        refused("requires_key", with_requires_key);

        let mut with_base = base();
        with_base.base = Some("origin/main".to_owned());
        refused("base", with_base);
    }

    /// `content` is a shape row's column and no other kind's.
    ///
    /// Carried by the census, so a kind that does not name it is refused rather
    /// than silently ignoring it — the present-and-inert column this file's
    /// whole validation surface exists to close.
    ///
    /// Fails by: dropping `content` from `Rule::columns`.
    #[test]
    fn content_on_a_kind_that_reads_none_is_refused() {
        let mut rule = blank("f", RuleKind::Forbid);
        rule.glob = Some("**/*.rs".to_owned());
        rule.pattern = Some("todo".to_owned());
        assert!(rule.validate().is_ok(), "the fixture itself must load");
        rule.content = Some("anything".to_owned());
        let err = rule
            .validate()
            .expect_err("`content` is not a forbid row's column");
        assert!(
            format!("{err}").contains("content"),
            "the refusal must name the column: {err}"
        );
    }

    #[test]
    fn a_key_modifier_is_refused_without_the_range_it_reads() {
        // The two columns are one predicate (CLOUD-446). A row carrying the
        // expression and no `base` would silently fall back to the branch name
        // alone — a narrowing nobody wrote, arrived at by omission, and the
        // shape this file exists to refuse.
        let mut rule = shape("s", "gh pr create", "name the issue");
        rule.requires_key = Some(r"\bKEY-[0-9]+\b".to_owned());
        let err = rule
            .validate()
            .expect_err("a key modifier with no range reads nothing");
        assert!(
            format!("{err}").contains("`base`"),
            "the refusal must name the missing column: {err}"
        );

        rule.base = Some("origin/main".to_owned());
        assert!(rule.validate().is_ok(), "the pair loads");
    }

    #[test]
    fn a_key_expression_that_does_not_compile_is_refused_at_load() {
        // Same reasoning as `regex` and `exclude` above: left to adjudication an
        // unparseable expression fails open on every call, which is a gate that
        // reads as present in the file and denies nothing.
        let mut rule = shape("s", "gh pr create", "name the issue");
        rule.base = Some("origin/main".to_owned());
        rule.requires_key = Some("[unterminated".to_owned());
        let err = rule
            .validate()
            .expect_err("an unparseable key expression cannot load");
        assert!(
            format!("{err}").contains("requires_key"),
            "the refusal must name the column: {err}"
        );
    }

    #[test]
    fn a_shape_rule_rejects_a_glob_and_a_check() {
        for column in ["glob", "check", "fix"] {
            let mut rule = shape("s", "gh pr merge", "because");
            match column {
                "glob" => rule.glob = Some("**".to_owned()),
                "fix" => rule.fix = Some("true".to_owned()),
                _ => rule.check = Some("true".to_owned()),
            }
            let err = rule
                .validate()
                .expect_err("a shape rule inspects no files and runs nothing");
            assert!(
                format!("{err}").contains(column),
                "the refusal must name `{column}`"
            );
        }
    }

    #[test]
    fn the_tree_engine_skips_a_mediated_call_rule_without_running_it() {
        // Routing, from the tree side: a shape row contributes no finding and no
        // error to `check`. It must not be refused either — `check` refusing a
        // rule another surface owns would make every hook-using repo unable to
        // run `check` at all.
        let dir = temp_dir("rules-skip-mediated");
        write(&dir, "a.rs", "gh pr merge\n");
        let rule = shape("no-hand-merge", "gh pr merge", "use the landing path");
        let findings = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert!(findings.is_empty(), "a shape rule is not a file rule");
    }

    #[test]
    fn a_rule_id_declared_twice_is_a_usage_error() {
        // Two rows for one id is a policy question with two answers, and taking
        // the first silently is how a tightening edit gets lost behind a stale
        // row. Same reasoning as the verb table's duplicate refusal.
        let rules = [forbid("dup", "**", "a"), forbid("dup", "**", "b")];
        let err = validate(&rules).expect_err("a duplicated id must be refused");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn the_schema_conditional_matches_the_column_census() {
        // The published schema states the severity rule a SECOND time, as a
        // JSON Schema conditional, because a derived `required` list cannot
        // express "per kind". A second authority narrows silently, so this
        // asserts the two agree: exactly one kind is refused the column, it is
        // the one the conditional names, and every other kind requires it.
        let refused: Vec<RuleKind> = RuleKind::ALL
            .iter()
            .copied()
            .filter(|kind| !kind.permits().contains(&"severity"))
            .collect();
        assert_eq!(
            refused,
            vec![RuleKind::Judge],
            "the schema's `if kind == judge` conditional names exactly one kind; \
             change it in rules.rs's `extend` attribute when this set changes"
        );
        for kind in RuleKind::ALL {
            let required = kind.requires().contains(&"severity");
            assert_eq!(
                required,
                *kind != RuleKind::Judge,
                "{kind:?}: the schema's else-branch requires `severity` of every \
                 non-judge kind, so `requires()` must too"
            );
        }
    }

    #[test]
    fn a_judge_row_is_refused_the_severity_column() {
        // The bound, at the column census: `severity` decides the exit contract
        // and a judge verdict must not reach it by any path. Refused rather
        // than ignored — a key that parses and does nothing reads to a reviewer
        // as a setting that applies.
        let mut rule = blank("j", RuleKind::Judge);
        rule.glob = Some("**".to_owned());
        rule.criteria = Some("does this read as intentional".to_owned());
        rule.no_fix_reason = Some("answered by hand".to_owned());
        assert!(rule.validate().is_ok(), "the row without it loads");

        rule.severity = Some(RuleSeverity::Deny);
        let err = rule
            .validate()
            .expect_err("a judge row declaring severity is refused");
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(err.to_string().contains("severity"), "{err}");
    }

    #[test]
    fn a_judge_rows_effective_severity_is_allow_so_the_walker_skips_it() {
        // Not a fallback: `allow` is this engine's word for "a match here is not
        // a finding at all", and it is exactly what `run_rule` acts on. This is
        // the walker-side half of "a judge outcome is never a Finding".
        let rule = blank("j", RuleKind::Judge);
        assert_eq!(
            rule.severity, None,
            "the column is refused, so it is absent"
        );
        assert_eq!(rule.severity(), RuleSeverity::Allow);
    }

    /// A deriving/reading pair, built directly rather than through a config, so
    /// the composition checks can be exercised over kind combinations the column
    /// tables do not permit a config to write today.
    ///
    /// That gap is stated rather than hidden: `derives` and `reads` are permitted
    /// on the document kind alone, so the cost half of the load refusal has no
    /// reachable config spelling YET — it becomes reachable the day a second kind
    /// derives, and it is live and failable now.
    fn pair(reader_kind: RuleKind, producer_kind: RuleKind) -> Vec<Rule> {
        let mut producer = blank("producer", producer_kind);
        producer.derives = Some("pin".to_owned());
        let mut reader = blank("reader", reader_kind);
        reader.reads = Some("pin".to_owned());
        vec![producer, reader]
    }

    #[test]
    fn a_reference_to_a_name_nothing_derives_is_refused() {
        // The row loads, matches a document, and compares against a value that
        // will never exist — present, inert, and reading as coverage.
        let mut reader = blank("reader", RuleKind::Document);
        reader.reads = Some("pin".to_owned());
        let err = validate_composition(&[reader], None).expect_err("an undefined name is refused");
        assert!(err.to_string().contains("which no rule derives"));
    }

    #[test]
    fn two_rows_deriving_one_name_are_refused() {
        // "Which one did I read" is not a question a reviewer should have to
        // answer, and the answer would be positional.
        let mut first = blank("first", RuleKind::Document);
        first.derives = Some("pin".to_owned());
        let mut second = blank("second", RuleKind::Document);
        second.derives = Some("pin".to_owned());
        let err = validate_composition(&[first, second], None)
            .expect_err("a duplicated derived name is refused");
        assert!(
            err.to_string()
                .contains("a derived value has one definition")
        );
    }

    #[test]
    fn a_cycle_is_refused_at_load_and_names_both_sites() {
        // CLOUD-647 measured that the obvious candidate engine reports cycles at
        // EVALUATION, which on the mediated path is the worst possible time and
        // the wrong exit class. This is the refusal moved to where a config fault
        // belongs, and the message names both ends so a reader can open either.
        let mut first = blank("first", RuleKind::Document);
        first.derives = Some("a".to_owned());
        first.reads = Some("b".to_owned());
        let mut second = blank("second", RuleKind::Document);
        second.derives = Some("b".to_owned());
        second.reads = Some("a".to_owned());
        let err =
            validate_composition(&[first, second], None).expect_err("a cycle is refused at load");
        let text = err.to_string();
        assert!(text.contains("form a cycle"));
        assert!(text.contains("first"), "the message names one end");
        assert!(text.contains("second"), "and the other");
    }

    #[test]
    fn a_reference_that_widens_the_readers_surface_is_refused() {
        // The second axis, and the one a single-axis reading loses: a
        // hook-surface rule reading a derivation resolvable only on the tree
        // would answer from a fact that was never resolvable where it runs.
        //
        // Fails by: meeting only the cost axis in `validate_composition`.
        assert_eq!(
            RuleKind::Receipt
                .fact_class(RuleScope::MediatedCall)
                .surface,
            crate::facts::Surface::Hook
        );
        assert_eq!(
            RuleKind::Document.fact_class(RuleScope::Tree).surface,
            crate::facts::Surface::Check
        );
        let err = validate_composition(&pair(RuleKind::Receipt, RuleKind::Document), None)
            .expect_err("a hook-surface rule cannot read a check-surface derivation");
        assert!(err.to_string().contains("the meet on both axes"));
    }

    #[test]
    fn a_reference_that_makes_the_reader_more_expensive_is_refused() {
        // The first axis: a `read`-class row silently inheriting an
        // `effect`-class dependency is the composition defect CLOUD-757 named,
        // and it is refused by the same equality rather than by a second check.
        //
        // Fails by: meeting only the surface axis in `validate_composition`.
        assert_eq!(
            RuleKind::Document.fact_class(RuleScope::Tree).cost,
            crate::facts::Cost::Read
        );
        assert_eq!(
            RuleKind::Secrets.fact_class(RuleScope::Tree).cost,
            crate::facts::Cost::Effect
        );
        let err = validate_composition(&pair(RuleKind::Document, RuleKind::Secrets), None)
            .expect_err("a read-class rule cannot read an effect-class derivation");
        assert!(err.to_string().contains("the meet on both axes"));
    }

    #[test]
    fn a_reference_that_moves_neither_axis_is_admitted() {
        // The gate must not simply refuse everything: two rows of the same class
        // compose, which is the whole point of the column existing.
        validate_composition(&pair(RuleKind::Document, RuleKind::Document), None)
            .expect("a same-class reference composes");
    }

    #[test]
    fn no_column_can_reorder_the_adjudication_chain() {
        // CLOUD-773 decision 5, as a gate rather than a stated intention.
        // `adjudicated`'s four stages stay a hard-coded match: referenceable
        // VALUES are in scope, configurable ORDERING is out. A chain a consumer
        // can misorder is one that puts the protected-mutation gate behind a
        // shape rule that allows, and the failure is silent.
        //
        // Fails by: adding a rule column whose name could carry a stage position.
        let named: Vec<&str> = blank("any", RuleKind::Document)
            .columns()
            .iter()
            .map(|(name, _)| *name)
            .collect();
        for banned in ["stage", "order", "before", "after", "priority", "phase"] {
            assert!(
                !named.contains(&banned),
                "a `{banned}` column would make the adjudication chain data (CLOUD-773 decision 5)"
            );
        }
    }

    #[test]
    fn all_covers_every_kind() {
        // The spawn partition must be total. `ALL` is what the gate below
        // iterates, so a kind missing from it would be silently untested —
        // exactly how a spawning kind could slip onto the read-only surface.
        // The match is exhaustive by the compiler; this asserts `ALL` agrees.
        for kind in RuleKind::ALL {
            match kind {
                RuleKind::Forbid
                | RuleKind::Command
                | RuleKind::Shape
                | RuleKind::Ratchet
                | RuleKind::Receipt
                | RuleKind::Pipeline
                | RuleKind::Judge
                | RuleKind::Secrets
                | RuleKind::Document
                | RuleKind::Policy => {}
            }
        }
        assert_eq!(
            RuleKind::ALL.len(),
            10,
            "a new RuleKind must be added to RuleKind::ALL"
        );
    }

    #[test]
    fn the_read_only_surface_refuses_every_spawning_kind() {
        // CLOUD-170's computable gate, stated over *every* kind rather than a
        // named one: no kind that can spawn a process may run under
        // `run_static` (the `read`-effect `check`). Vacuous while `forbid` is
        // the only kind; it starts biting the moment CLOUD-89 adds `command`,
        // which is the point — the invariant is in place before the risk is.
        let dir = temp_dir("rules-spawn-gate");
        write(&dir, "a.rs", "TODO\n");
        for kind in RuleKind::ALL {
            if !kind.carries_ambient_authority() {
                continue;
            }
            let rule = Rule {
                glob: Some("**".to_owned()),
                check: Some("true".to_owned()),
                ..blank("spawner", *kind)
            };
            let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "a spawning kind must be refused as a usage error, not run"
            );
            assert!(
                err.to_string().contains(SPAWNING_VERB),
                "the refusal must name the verb that does run it"
            );
        }
    }

    #[test]
    fn non_spawning_kinds_run_on_both_surfaces() {
        // The split must not change *results* for admissible kinds — only which
        // kinds are admissible. Otherwise the two verbs drift.
        let dir = temp_dir("rules-both-surfaces");
        write(&dir, "a.rs", "TODO\n");
        let rule = forbid("no-todo", "**/*.rs", "TODO");
        assert_eq!(
            run_static(std::slice::from_ref(&rule), &dir).unwrap(),
            run_all(std::slice::from_ref(&rule), &dir).unwrap()
        );
    }

    #[test]
    fn command_exit_zero_passes_and_non_zero_is_a_violation() {
        let dir = temp_dir("cmd-exit");
        write(&dir, "a.rs", "x\n");
        let pass = run_all(&[command("ok", "**/*.rs", "true")], &dir).unwrap();
        assert!(pass.is_empty(), "exit 0 must pass");

        let fail = run_all(&[command("bad", "**/*.rs", "false")], &dir).unwrap();
        assert_eq!(
            fail.iter()
                .map(|f| (f.rule.as_str(), f.path.as_str(), f.line))
                .collect::<Vec<_>>(),
            // Rule-scoped: the exit code condemns the batch, not a line.
            vec![("bad", "**/*.rs", None)]
        );
        // A command rule mints the scope kind, not the code kind.
        assert_eq!(
            fail[0].identity.version,
            identity::FindingKind::Scope.identity_version()
        );
    }

    #[test]
    fn a_glob_matching_nothing_never_spawns() {
        // §4 "cheap when irrelevant": the glob gates before it feeds argv. The
        // canary is a command that would fail loudly if it ever ran — a missing
        // binary is a usage error, so reaching the spawn would surface here.
        let dir = temp_dir("cmd-no-match");
        write(&dir, "a.txt", "x\n");
        let findings = run_all(
            &[command(
                "never",
                "**/*.rs",
                "definitely-not-a-real-binary-xyz",
            )],
            &dir,
        )
        .unwrap();
        assert!(
            findings.is_empty(),
            "an unmatched glob must skip, not spawn"
        );
    }

    #[test]
    fn missing_binary_is_a_usage_error_not_a_silent_pass() {
        let dir = temp_dir("cmd-missing-bin");
        write(&dir, "a.rs", "x\n");
        let err = run_all(
            &[command(
                "gone",
                "**/*.rs",
                "definitely-not-a-real-binary-xyz",
            )],
            &dir,
        )
        .unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a command that cannot run is a config error (exit 1), never a pass"
        );
    }

    #[test]
    fn files_placeholder_receives_the_matched_paths() {
        // `test -e <path>` succeeds only if the path was actually substituted
        // and resolves relative to the run root, so this asserts interpolation
        // rather than merely that something ran.
        let dir = temp_dir("cmd-files");
        write(&dir, "present.rs", "x\n");
        let findings = run_all(&[command("subst", "**/*.rs", "test -e {{files}}")], &dir).unwrap();
        assert!(findings.is_empty(), "the matched path must reach the argv");
    }

    #[test]
    fn a_template_without_the_placeholder_runs_once_and_self_discovers() {
        // Three matches, no placeholder: the command still runs exactly once.
        // `false` fails every time it runs, so one finding proves one spawn.
        let dir = temp_dir("cmd-self-discover");
        write(&dir, "a.rs", "x\n");
        write(&dir, "b.rs", "x\n");
        write(&dir, "c.rs", "x\n");
        let findings = run_all(&[command("once", "**/*.rs", "false")], &dir).unwrap();
        assert_eq!(findings.len(), 1, "self-discovering form runs once");
    }

    #[test]
    fn matched_paths_are_batched_under_the_argv_bound() {
        // Every batch stays under the documented bound, and batching preserves
        // order — the property that keeps findings byte-stable (§6).
        let paths: Vec<String> = (0..2000).map(|i| format!("src/file-{i:04}.rs")).collect();
        let refs: Vec<&String> = paths.iter().collect();
        let batches = batches(&refs);
        assert!(batches.len() > 1, "a large match set must split");
        for batch in &batches {
            let bytes: usize = batch.iter().map(|p| p.len() + 1).sum();
            assert!(bytes <= MAX_FILES_BYTES, "batch overflows the argv bound");
        }
        let flattened: Vec<&str> = batches.concat();
        let expected: Vec<&str> = paths.iter().map(String::as_str).collect();
        assert_eq!(flattened, expected, "batching must preserve order");
    }

    /// Enough matching files under `dir` that [`batches`] has to split them,
    /// sized off [`MAX_FILES_BYTES`] rather than a magic count — the bound is
    /// the thing under test, so a fixture that hard-codes a number stops
    /// splitting the day the bound moves and the case passes vacuously.
    ///
    /// Long names rather than many files: the argv bound is bytes, so 130 files
    /// carry it as cheaply as 2000 short ones and the case stays fast.
    fn files_forcing_a_split(dir: &Path) {
        let stem = "b".repeat(120);
        // `+ 1` per path is the separator `batches` accounts for; `+ 2` files
        // past the bound guarantees a second group rather than an exact fill.
        let count = MAX_FILES_BYTES / (stem.len() + ".0000.rs".len() + 1) + 2;
        for i in 0..count {
            write(dir, &format!("{stem}.{i:04}.rs"), "x\n");
        }
    }

    #[test]
    fn a_command_rule_failing_in_every_batch_reports_once() {
        // CLOUD-396. The match set is large enough that `command_rule` spawns
        // per batch and `false` fails in every one of them, so the pre-dedup
        // engine emitted one byte-identical finding per batch — a count moving
        // with the caller's path count, which is the argv bound leaking into
        // the output contract.
        let dir = temp_dir("cmd-multi-batch");
        files_forcing_a_split(&dir);

        // The premise, asserted rather than assumed: this match set really does
        // split. Without it a fixture that stopped splitting would report one
        // finding for the trivial reason and still pass.
        let files = tree_files(&dir).unwrap();
        let matched: Vec<&String> = files.iter().collect();
        assert!(
            batches(&matched).len() > 1,
            "the fixture must force more than one batch, or this proves nothing"
        );

        let findings = run_all(&[command("multi", "**/*.rs", "false {{files}}")], &dir).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "batching is invisible to the predicate: one failing rule is one finding"
        );
    }

    #[test]
    fn dedup_collapses_one_rule_and_never_two() {
        // The other half, and the one that stops the fix from over-reaching:
        // two failing rules over the same split match set are two findings, not
        // one. The identities differ by rule id, so nothing here rests on the
        // findings' other fields differing — they do not.
        let dir = temp_dir("cmd-multi-batch-two-rules");
        files_forcing_a_split(&dir);

        let findings = run_all(
            &[
                command("first", "**/*.rs", "false {{files}}"),
                command("second", "**/*.rs", "false {{files}}"),
            ],
            &dir,
        )
        .unwrap();
        assert_eq!(findings.len(), 2, "one finding per failing rule");
        let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, ["first", "second"], "and both rules are named");
    }

    #[test]
    fn dedup_leaves_span_findings_at_two_lines_alone() {
        // The exclusion the dedup rests on. A `forbid` rule reports a pointer
        // per line, and its identity is not the scope kind — so two matches of
        // the same text are two findings, and collapsing them would delete a
        // location nothing else reports.
        let dir = temp_dir("dedup-spans-survive");
        write(&dir, "a.rs", "TODO\nfine\nTODO\n");
        let findings = run_static(&[forbid("todo", "**/*.rs", "TODO")], &dir).unwrap();
        assert_eq!(findings.len(), 2, "each matched line keeps its own pointer");
        let lines: Vec<Option<usize>> = findings.iter().map(|f| f.line).collect();
        assert_eq!(lines, [Some(1), Some(3)]);
    }

    #[test]
    fn the_retired_run_key_names_its_replacement() {
        // §2 declares no back-compatibility surface, so `run` is not an alias —
        // it is a key that used to work. The refusal has to carry the one fix,
        // or an author whose config stops loading learns only that it stopped
        // (CLOUD-122).
        let rule = Rule {
            glob: Some("**".to_owned()),
            run: Some("true".to_owned()),
            ..blank("retired", RuleKind::Command)
        };
        let err = rule.validate().expect_err("`run` no longer loads");
        assert!(err.downcast_ref::<UsageError>().is_some());
        let text = err.to_string();
        assert!(text.contains("`check`"), "the refusal must name `check`");
        // And it must win over the census, which would otherwise report the
        // absent `check` and say nothing about the key holding its value.
        assert!(
            !text.contains("requires"),
            "the rename must be reported ahead of the missing-column complaint"
        );
    }

    #[test]
    fn a_declared_fix_is_refused_rather_than_run() {
        // The key parses — that is the whole point of reserving the vocabulary
        // now — but the half that would execute it does not exist, and a repair
        // that silently never runs is the false green this engine refuses.
        let dir = temp_dir("rules-fix-reserved");
        write(&dir, "a.rs", "x\n");
        let rule = Rule {
            fix: Some("true".to_owned()),
            ..command("fixer", "**", "true")
        };
        rule.validate().expect("`fix` is a loadable column");
        let err = run_all(std::slice::from_ref(&rule), &dir)
            .expect_err("an unexecutable repair must not be ignored");
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a capability this build lacks is the config class (exit 1), not a policy verdict"
        );
        assert!(
            err.to_string().contains("`fix`"),
            "the refusal must name the key it is about"
        );
    }

    #[test]
    fn a_kind_only_accepts_its_own_fields() {
        // The flat-struct tension: without a tagged enum, kind/field agreement
        // is asserted here. A field from another kind is an error, never ignored.
        let dir = temp_dir("cmd-schema");
        write(&dir, "a.rs", "x\n");
        let cases = [
            // command with no `check`
            Rule {
                glob: Some("**".into()),
                ..blank("a", RuleKind::Command)
            },
            // command carrying a forbid-only column
            Rule {
                glob: Some("**".into()),
                pattern: Some("x".into()),
                check: Some("true".into()),
                ..blank("b", RuleKind::Command)
            },
            // forbid with no `pattern`
            Rule {
                glob: Some("**".into()),
                ..blank("c", RuleKind::Forbid)
            },
            // forbid carrying a command-only column
            Rule {
                glob: Some("**".into()),
                pattern: Some("x".into()),
                check: Some("true".into()),
                ..blank("d", RuleKind::Forbid)
            },
        ];
        for rule in cases {
            let id = rule.id.clone();
            let err = run_all(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "rule {id}: mismatched kind/fields must be a usage error"
            );
        }
    }

    #[test]
    fn empty_glob_is_a_usage_error() {
        let dir = temp_dir("rules-empty-glob");
        write(&dir, "a.rs", "TODO\n");
        let err = run_static(&[forbid("bad", "", "TODO")], &dir).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn scope_default_is_pinned() {
        // The per-field default, as data: `tree` is what an omitted `scope` key
        // means, byte-stable in both directions. This is the "pinned" in
        // "per-field-pinned default" — the fallback is a declared, tested value,
        // never an accident of code.
        assert_eq!(RuleScope::default(), RuleScope::Tree);
        assert_eq!(RuleScope::default().as_str(), "tree");
        for &scope in RuleScope::ALL {
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json, format!("\"{}\"", scope.as_str()));
            assert_eq!(serde_json::from_str::<RuleScope>(&json).unwrap(), scope);
        }
        // `ALL` stays total: a new variant must extend it or this stops compiling.
        for scope in RuleScope::ALL {
            match scope {
                RuleScope::Tree | RuleScope::MediatedCall => {}
            }
        }
    }

    #[test]
    fn severity_and_scope_vocabularies_do_not_cross() {
        // The key separation, one layer below the config file: a severity token
        // does not deserialize as a scope, nor a scope token as a severity, so
        // conflating the two keys cannot even be *expressed* — it fails as a
        // usage error at parse time rather than silently re-reading one axis as
        // the other.
        for &severity in RuleSeverity::ALL {
            let token = format!("\"{}\"", severity.as_str());
            assert!(
                serde_json::from_str::<RuleScope>(&token).is_err(),
                "severity token {token} must not parse as a scope"
            );
        }
        for &scope in RuleScope::ALL {
            let token = format!("\"{}\"", scope.as_str());
            assert!(
                serde_json::from_str::<RuleSeverity>(&token).is_err(),
                "scope token {token} must not parse as a severity"
            );
        }
    }

    #[test]
    fn an_allow_rule_is_configured_off() {
        // `allow` means off: a match is not a finding at all, on both surfaces.
        let dir = temp_dir("rules-allow-off");
        write(&dir, "a.rs", "TODO\n");
        let mut rule = forbid("no-todo", "**/*.rs", "TODO");
        rule.severity = Some(RuleSeverity::Allow);
        assert!(
            run_static(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
        assert!(
            run_all(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
    }

    /// A `shape` row keyed on a command line, for the pattern-shape refusals.
    fn shape_pattern(pattern: &str) -> Rule {
        shape("row", pattern, "use the sanctioned path")
    }

    #[test]
    fn require_via_is_a_shape_column_only() {
        // The census decides it, so this case is what proves the column was
        // actually declared per-kind rather than left open to every row. A
        // `forbid` row reads file contents and reaches no command, so a
        // mediator requirement on one would narrow nothing while reading as a
        // narrowing.
        let mut rule = forbid("no-todo", "**/*.rs", "TODO");
        rule.require_via = Some(RequireVia::Mise);
        let err = validate(&[rule]).unwrap_err().to_string();
        assert!(err.contains("require_via"), "{err}");
    }

    #[test]
    fn require_via_loads_on_a_shape_row() {
        let mut rule = shape("no-bare-cargo", "cargo", "use the pinned toolchain");
        rule.require_via = Some(RequireVia::Mise);
        assert!(validate(&[rule]).is_ok());
    }

    #[test]
    fn a_program_only_pattern_is_valid_because_the_matcher_honours_it() {
        // The reading `Rule::pattern`'s doc comment invites, and the one this
        // validator must not take back: an empty operand list is "the program
        // alone". Refusing it at load would turn the documented reading into a
        // config error and leave the exact-program predicate inexpressible.
        assert!(validate(&[shape_pattern("cargo")]).is_ok());
        assert!(validate(&[shape_pattern("gh pr merge")]).is_ok());
        // `mise run` is judged as `mise`, so this one the matcher DOES honour.
        assert!(validate(&[shape_pattern("mise run land")]).is_ok());
    }

    #[test]
    fn a_pattern_requiring_a_flag_is_refused() {
        // The matcher compares operand words with every flag already dropped,
        // so this row could never fire. Refused rather than loaded silent —
        // that is the property, not the one empty-operand instance.
        let err = validate(&[shape_pattern("cargo --version")]).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(err.to_string().contains("--version"), "{err}");
    }

    #[test]
    fn a_pattern_naming_a_looked_through_wrapper_is_refused() {
        // `effective_program` steps past these to judge what they wrap, so a
        // pattern naming one is compared against a program token that can never
        // be the wrapper.
        for pattern in ["nohup rm", "sudo rm", "timeout 30 cargo", "xargs rm"] {
            let err = validate(&[shape_pattern(pattern)]).unwrap_err().to_string();
            assert!(err.contains("looks THROUGH"), "{pattern}: {err}");
        }
    }

    #[test]
    fn a_pattern_starting_with_an_env_assignment_is_refused() {
        let err = validate(&[shape_pattern("GH_PAGER= gh pr merge")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("environment assignment"), "{err}");
    }

    #[test]
    fn a_whitespace_only_pattern_is_refused() {
        let err = validate(&[shape_pattern("   ")]).unwrap_err().to_string();
        assert!(err.contains("names no program"), "{err}");
    }

    #[test]
    fn a_receipt_trigger_is_held_to_the_same_pattern_shape() {
        // Both surfaces read the pattern through `Rule::trigger` and the same
        // matcher, so a row inert as a `shape` is inert as a `receipt` trigger.
        // Refusing only the kind that happened to be measured would leave the
        // other half of the class open.
        let mut rule = shape_pattern("cargo --version");
        rule.kind = RuleKind::Receipt;
        rule.checks = Some(vec!["toolchain".to_owned()]);
        assert!(
            validate(&[rule])
                .unwrap_err()
                .to_string()
                .contains("--version")
        );
    }

    #[test]
    fn an_allow_rule_is_still_validated() {
        // "Off" must never double as "unreadable": a malformed rule is a config
        // error even at severity `allow`, so flipping a broken rule on can
        // never be the moment its config first fails to parse.
        let dir = temp_dir("rules-allow-validated");
        write(&dir, "a.rs", "x\n");
        let mut rule = forbid("broken", "**/*.rs", "x");
        rule.severity = Some(RuleSeverity::Allow);
        rule.pattern = None;
        let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_allow_command_rule_never_spawns() {
        // The missing binary would be a usage error if the spawn were reached,
        // so a clean exit proves the `allow` skip happens before any process.
        let dir = temp_dir("rules-allow-no-spawn");
        write(&dir, "a.rs", "x\n");
        let mut rule = command("off", "**/*.rs", "definitely-not-a-real-binary-xyz");
        rule.severity = Some(RuleSeverity::Allow);
        assert!(
            run_all(std::slice::from_ref(&rule), &dir)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn severity_never_changes_which_surface_admits_a_rule() {
        // Scope ≠ severity, and severity ≠ effect either: the §5 spawning
        // refusal on the read-only surface fires for a command rule at *every*
        // severity, `allow` included. An axis that silently widened the read
        // surface would conflate "what a match does" with "what may run".
        let dir = temp_dir("rules-allow-still-refused");
        write(&dir, "a.rs", "x\n");
        for &severity in RuleSeverity::ALL {
            let mut rule = command("spawner", "**/*.rs", "true");
            rule.severity = Some(severity);
            let err = run_static(std::slice::from_ref(&rule), &dir).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "severity {} must not admit a spawning kind to `check`",
                severity.as_str()
            );
        }
    }

    #[test]
    fn warn_findings_report_without_blocking() {
        // The middle rank end to end at the library layer: a `warn` finding is
        // produced and carries its severity, and the exit-contract predicate
        // says it does not block — that promotion is `--fail-on-warning`'s job
        // (CLOUD-49), not the default's.
        let dir = temp_dir("rules-warn-reports");
        write(&dir, "a.rs", "TODO\n");
        let mut rule = forbid("no-todo", "**/*.rs", "TODO");
        rule.severity = Some(RuleSeverity::Warn);
        let findings = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RuleSeverity::Warn);
        assert!(
            !any_blocking(&findings, false),
            "a warn finding must not block"
        );
        // …and the same finding, unchanged, blocks once the setting promotes it
        // (CLOUD-49). The finding itself is identical in both runs: promotion
        // acts on the exit decision, never on what was stored or reported.
        assert!(
            any_blocking(&findings, true),
            "fail_on_warning must promote a warn finding"
        );

        let deny = run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).unwrap();
        for promote in [false, true] {
            assert!(
                any_blocking(&deny, promote),
                "a deny finding must block either way"
            );
            assert!(!any_blocking(&[], promote), "no findings, nothing blocks");
        }
    }

    /// The three-set fixture (CLOUD-37), written as the config it is.
    ///
    /// Deliberately overlapping and deliberately not nested: `src/**` is in
    /// scope, `src/generated/**` is excluded from it, `src/api.rs` is protected,
    /// and `src/draft.rs` is unlanded but *not* protected — the case the
    /// acceptance names, and the one a collapsed set gets wrong.
    const SETS_FIXTURE: &str = "\
version = 1
scope = [\"src/**\", \"!src/generated/**\"]
protected = [\"src/api.rs\", \"migrations/**\"]
unlanded = [\"src/draft.rs\", \"src/generated/**\"]
";

    fn sets(text: &str) -> Sets {
        let config = crate::config::parse(text, "test").unwrap();
        Sets::from_config(&config).unwrap()
    }

    #[test]
    fn three_independent_evaluators_exist() {
        // (a) Three sets, each answering from its own list alone. Every
        // assertion below is a path where at least two of the three disagree —
        // if any pair were collapsed, one of these flips.
        let sets = sets(SETS_FIXTURE);

        // In scope, protected, not unlanded.
        assert!(sets.scope.contains("src/api.rs"));
        assert!(sets.protected.contains("src/api.rs"));
        assert!(!sets.unlanded.contains("src/api.rs"));

        // Protected but out of scope: `migrations/**` is in no scope include.
        assert!(!sets.scope.contains("migrations/001.sql"));
        assert!(sets.protected.contains("migrations/001.sql"));
        assert!(!sets.unlanded.contains("migrations/001.sql"));

        // Unlanded and excluded from scope: membership in one says nothing
        // about the other, in either direction.
        assert!(!sets.scope.contains("src/generated/api.rs"));
        assert!(sets.unlanded.contains("src/generated/api.rs"));
        assert!(!sets.protected.contains("src/generated/api.rs"));
    }

    #[test]
    fn a_path_in_unlanded_but_not_protected_is_classified_by_each_set() {
        // (b) The acceptance's named case, stated as three independent answers
        // about one path. A single collapsed set cannot produce this row.
        let sets = sets(SETS_FIXTURE);
        assert!(sets.unlanded.contains("src/draft.rs"), "unlanded: yes");
        assert!(!sets.protected.contains("src/draft.rs"), "protected: no");
        assert!(sets.scope.contains("src/draft.rs"), "scope: yes");
    }

    #[test]
    fn an_exclude_beats_an_include_inside_scope() {
        // (c) `src/generated/api.rs` matches the `src/**` include and the
        // `!src/generated/**` exclude. The exclude wins.
        let sets = sets(SETS_FIXTURE);
        assert!(sets.scope.contains("src/a.rs"), "a plain include matches");
        assert!(
            !sets.scope.contains("src/generated/api.rs"),
            "an exclude must beat an overlapping include"
        );

        // …and it wins from either position in the list, so "excludes win" is a
        // property of the set rather than an artifact of authoring order.
        let reversed =
            PathSet::scope(&["!src/generated/**".to_owned(), "src/**".to_owned()]).unwrap();
        assert!(!reversed.contains("src/generated/api.rs"));
        assert!(reversed.contains("src/a.rs"));
    }

    #[test]
    fn evaluation_is_deterministic_for_identical_config() {
        // (d) Same config, same paths, same answers — twice over, across
        // separately-built evaluators, so nothing is carried between runs.
        let paths = [
            "src/a.rs",
            "src/api.rs",
            "src/draft.rs",
            "src/generated/api.rs",
            "migrations/001.sql",
            "README.md",
        ];
        let first = sets(SETS_FIXTURE);
        let second = sets(SETS_FIXTURE);
        assert_eq!(first, second, "identical config builds identical sets");
        for path in paths {
            assert_eq!(first.scope.contains(path), second.scope.contains(path));
            assert_eq!(
                first.protected.contains(path),
                second.protected.contains(path)
            );
            assert_eq!(
                first.unlanded.contains(path),
                second.unlanded.contains(path)
            );
            // Repeating a query on one evaluator is stable too: `contains` is a
            // pure function of the set, with no memo to go stale.
            assert_eq!(first.scope.contains(path), first.scope.contains(path));
        }
    }

    #[test]
    fn an_absent_list_is_the_empty_set_never_everything() {
        // The widening a default must never perform: no `scope` key means
        // nothing is in scope, not that every path is.
        let sets = sets("version = 1\n");
        for path in ["src/a.rs", "README.md", ""] {
            assert!(!sets.scope.contains(path));
            assert!(!sets.protected.contains(path));
            assert!(!sets.unlanded.contains(path));
        }
    }

    #[test]
    fn an_exclude_in_an_include_only_key_is_a_usage_error() {
        // Only `scope` carries exclude semantics. A `!` elsewhere would read as
        // an exclude to its author and as an include to the engine, so it is
        // refused rather than reinterpreted.
        for key in ["protected", "unlanded"] {
            let text = format!("version = 1\n{key} = [\"!src/**\"]\n");
            let config = crate::config::parse(&text, "test").unwrap();
            let err = Sets::from_config(&config).unwrap_err();
            assert!(err.downcast_ref::<UsageError>().is_some());
            assert!(
                err.to_string().contains(key),
                "the refusal must name the key, got: {err}"
            );
        }
    }

    #[test]
    fn a_bare_exclude_marker_is_a_usage_error() {
        let config = crate::config::parse("version = 1\nscope = [\"!\"]\n", "test").unwrap();
        let err = Sets::from_config(&config).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    // --- CLOUD-617: the shebang the Windows loader will not read --------------
    //
    // The composition — that a `#!/bin/sh` checker actually runs a rule to a
    // verdict — is asserted by the `windows` job over the acceptance corpus,
    // which is where this defect was found and which is a required check. What
    // is worth unit-testing is the parsing, because that is where the decisions
    // are: the cases below are the ones that would each fail differently.

    /// Write a program file and ask what interpreter, if any, it names.
    fn interpreter_of(name: &str, contents: &str) -> Option<Vec<String>> {
        let dir = temp_dir(&format!("shebang-{name}"));
        write(&dir, "prog", contents);
        shebang_interpreter(&dir.join("prog"))
    }

    #[test]
    fn a_shebang_resolves_to_the_interpreters_basename() {
        // `/bin/sh` cannot exist on Windows, so the literal path is the one
        // string guaranteed not to resolve. The basename is what PATH answers.
        assert_eq!(
            interpreter_of("absolute", "#!/bin/sh\nexit 0\n"),
            Some(vec!["sh".to_owned()])
        );
    }

    #[test]
    fn env_is_unwrapped_rather_than_run() {
        // `env` is the indirection being resolved. Running `env` itself on
        // Windows would fail exactly as the script did.
        assert_eq!(
            interpreter_of("env", "#!/usr/bin/env python3\n"),
            Some(vec!["python3".to_owned()])
        );
    }

    #[test]
    fn an_interpreter_argument_is_carried() {
        assert_eq!(
            interpreter_of("arg", "#!/usr/bin/awk -f\n"),
            Some(vec!["awk".to_owned(), "-f".to_owned()])
        );
    }

    #[test]
    fn a_carriage_return_does_not_weld_itself_to_the_interpreter() {
        // A clone without `.gitattributes` hands us `#!/bin/sh\r`, and `sh\r` is
        // "not on PATH" — the same failure wearing a message that sends the
        // reader looking for a missing shell (CLOUD-612's line-ending shape,
        // one layer down).
        assert_eq!(
            interpreter_of("crlf", "#!/bin/sh\r\nexit 0\r\n"),
            Some(vec!["sh".to_owned()])
        );
    }

    #[test]
    fn what_is_not_a_shebang_resolves_to_nothing() {
        // Each of these must leave the caller reporting the ORIGINAL spawn
        // error: the fallback may turn a failure into a success, never one
        // failure into a different one.
        assert_eq!(interpreter_of("none", "exit 0\n"), None);
        assert_eq!(interpreter_of("empty", ""), None);
        assert_eq!(interpreter_of("bang-only", "#!\n"), None);
        assert_eq!(interpreter_of("env-alone", "#!/usr/bin/env\n"), None);
        // A PE image's first bytes are `MZ`, not `#!`.
        assert_eq!(interpreter_of("binary", "MZ\u{0}\u{0}\u{1}"), None);
        assert!(shebang_interpreter(Path::new("no/such/program")).is_none());
    }

    #[test]
    fn path_is_searched_for_the_name_verbatim() {
        // The Windows case this exists for is reproducible here, because the
        // lookup is the part that differs, not the file: a name `CreateProcess`
        // would only try as `name.exe` is found by this as `name`.
        let windows = [".COM".to_owned(), ".EXE".to_owned(), ".CMD".to_owned()];

        // THE CASE THAT WAS MISSED. `where.exe` resolved `hk.exe` on the runner
        // while batten reported `hk` not found, and the first version of this
        // lookup searched only the bare name — so it could not have rescued the
        // one spelling the failure was actually about.
        let exe = temp_dir("on-path-exe");
        write(&exe, "hk.exe", "MZ\u{0}");
        let exe_path = std::env::join_paths([exe.as_path()]).unwrap();
        assert_eq!(
            lookup_on("hk", &exe_path, &windows).as_deref(),
            Some(exe.join("hk.exe").as_path()),
            "the name is `hk`; the file Windows would run is `hk.exe`"
        );

        // The bare name still resolves, so widening did not trade one spelling
        // for the other.
        let bare = temp_dir("on-path-bare");
        write(&bare, "hk", "#!/bin/sh\nexit 0\n");
        let bare_path = std::env::join_paths([bare.as_path()]).unwrap();
        assert_eq!(
            lookup_on("hk", &bare_path, &windows).as_deref(),
            Some(bare.join("hk").as_path())
        );

        // Directory-major: a nearer `hk.exe` wins over a further bare `hk`,
        // which is the order Windows resolves in.
        let both = std::env::join_paths([exe.as_path(), bare.as_path()]).unwrap();
        assert_eq!(
            lookup_on("hk", &both, &windows).as_deref(),
            Some(exe.join("hk.exe").as_path()),
            "the first PATH entry decides, across every spelling"
        );

        assert_eq!(
            lookup_on("no-such-program-anywhere", &bare_path, &windows),
            None
        );
        assert_eq!(
            lookup_on("./hk", &bare_path, &windows),
            None,
            "a separator means it is not a PATH lookup"
        );
        // With no extensions — the Unix case — only the bare name is tried.
        assert_eq!(lookup_on("hk", &exe_path, &[]), None);
    }

    #[test]
    fn only_a_bad_executable_image_is_rescued() {
        // The trigger is narrow on purpose. A missing program is a real config
        // error and must keep reporting as one rather than being re-tried as a
        // script that does not exist either.
        use std::io::{Error, ErrorKind};
        assert!(is_not_an_executable_image(&Error::from_raw_os_error(193)));
        assert!(is_not_an_executable_image(&Error::from_raw_os_error(8)));
        assert!(!is_not_an_executable_image(&Error::from(
            ErrorKind::NotFound
        )));
        assert!(!is_not_an_executable_image(&Error::from(
            ErrorKind::PermissionDenied
        )));
    }

    /// A spawn that answers the way `CreateProcess` does, so the ladder can be
    /// driven on a host whose loader is more forgiving than the one it is for.
    ///
    /// Three rules, each one a thing the real loader does:
    ///
    ///   * **A bare name resolves only as `<name>.exe`**, searched across `dirs`.
    ///     That is the refusal rung 2 exists for — and it is why the interpreter
    ///     rung 3 names still runs: `sh` is invisible, `sh.exe` is not.
    ///   * **A path to a file with no `MZ` header is `ERROR_BAD_EXE_FORMAT`.**
    ///     No shebang is read; that is the refusal rung 3 exists for.
    ///   * Anything else runs.
    ///
    /// Every call is recorded, because *which programs were tried, in what
    /// order* is the property — a ladder that reached the right answer by a wrong
    /// route would pass a bare assertion on the outcome.
    fn windows_like_spawn<'a>(
        cwd: &'a Path,
        dirs: &'a [std::path::PathBuf],
        log: &'a std::cell::RefCell<Vec<(String, Vec<String>)>>,
    ) -> impl FnMut(&str, &[&str]) -> std::io::Result<&'static str> + 'a {
        move |program, extra| {
            log.borrow_mut().push((
                program.to_owned(),
                extra.iter().map(|arg| (*arg).to_owned()).collect(),
            ));
            let bare = !program.contains('/') && !program.contains('\\');
            // A relative program name resolves against the working directory the
            // caller set, which is the `root` it hands the ladder — the fact that
            // makes rung 3's choice of directory the right one to assert.
            let resolved = if bare {
                dirs.iter()
                    .map(|dir| dir.join(format!("{program}.exe")))
                    .find(|candidate| candidate.is_file())
            } else {
                Some(cwd.join(program))
            };
            let Some(resolved) = resolved else {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            };
            if !resolved.is_file() {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            if !std::fs::read(&resolved)
                .unwrap_or_default()
                .starts_with(b"MZ")
            {
                return Err(std::io::Error::from_raw_os_error(193));
            }
            Ok("ran")
        }
    }

    /// A directory holding a stub `sh.exe` the fake loader will run, so rung 3
    /// has an interpreter to reach — the Git Bash `sh.exe` a real runner has.
    fn with_shell(dir: &Path) {
        write(dir, "sh.exe", "MZ\u{0}");
    }

    #[test]
    fn a_path_resolved_script_needs_both_rungs_and_gets_them() {
        // THE CASE THE INDEPENDENT `if`s COULD NOT REACH, and the one that failed
        // seven of `judge_kind`'s fourteen cases on the eighteenth Windows run:
        // a bare name that resolves on PATH to an EXTENSIONLESS SHELL SCRIPT.
        // Rung 2 alone finds the file and still cannot execute it; rung 3 alone
        // has no path to read a `#!` from, because the name never resolved. Only
        // the composition answers, which is why this asserts the whole route.
        let bin = temp_dir("ladder-path-script");
        write(&bin, "judge-stub", "#!/bin/sh\nexit 0\n");
        with_shell(&bin);
        let path = std::env::join_paths([bin.as_path()]).unwrap();
        let script = bin.join("judge-stub");
        let dirs = vec![bin.clone()];

        let log = std::cell::RefCell::new(Vec::new());
        let out = spawn_resolving_on(
            Some(path.as_os_str()),
            Some(Path::new("/nowhere")),
            "judge-stub",
            &[".EXE".to_owned()],
            windows_like_spawn(Path::new("/nowhere"), &dirs, &log),
        );

        assert!(
            out.is_ok(),
            "the script is runnable through its interpreter"
        );
        let calls = log.into_inner();
        assert_eq!(
            calls,
            vec![
                ("judge-stub".to_owned(), vec![]),
                (script.display().to_string(), vec![]),
                ("sh".to_owned(), vec![script.display().to_string()],),
            ],
            "direct, then the PATH-resolved absolute path, then its interpreter \
             handed THAT path — not the bare name, which no interpreter could open"
        );
    }

    #[test]
    fn a_rescue_that_cannot_help_leaves_the_refusal_it_found() {
        // The one-way discipline, at the rung most able to break it: a script
        // whose interpreter is itself missing must still report the script's own
        // failure. Reporting `no-such-interpreter: not found` would send the
        // reader to a program their config never named.
        let bin = temp_dir("ladder-missing-interpreter");
        write(&bin, "stub", "#!/nope/no-such-interpreter\nexit 0\n");
        let path = std::env::join_paths([bin.as_path()]).unwrap();
        let dirs = vec![bin.clone()];

        let log = std::cell::RefCell::new(Vec::new());
        let err = spawn_resolving_on(
            Some(path.as_os_str()),
            None,
            "stub",
            &[".EXE".to_owned()],
            windows_like_spawn(&bin, &dirs, &log),
        )
        .expect_err("nothing here can run it");
        assert_eq!(
            err.raw_os_error(),
            Some(193),
            "the file was found and is not an executable image — which is truer \
             than the `not found` the first rung reported"
        );

        // A program that is genuinely absent keeps reporting as absent: the
        // lookup finds nothing, so the error never advances past rung 1.
        let absent = spawn_resolving_on(
            Some(path.as_os_str()),
            None,
            "no-such-program-anywhere",
            &[".EXE".to_owned()],
            windows_like_spawn(&bin, &dirs, &std::cell::RefCell::new(Vec::new())),
        )
        .expect_err("it is not there");
        assert_eq!(absent.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn an_absolute_script_is_read_from_itself_rather_than_from_a_root() {
        // THE `secrets` SHAPE, and the one the first ladder dropped. A
        // provisioned scanner is spawned by the absolute path `provision`
        // resolved, so there is no relative name and the caller passes no root —
        // and for one run that meant rung 3 had nothing to read, while the file
        // it needed was the program itself. Four `cli.rs` cases reported `%1 is
        // not a valid Win32 application` over a `#!/bin/sh` stub the ladder could
        // have run.
        let cache = temp_dir("ladder-absolute-script");
        write(&cache, "ripsecrets", "#!/bin/sh\nexit 0\n");
        with_shell(&cache);
        let scanner = cache.join("ripsecrets");
        let dirs = vec![cache.clone()];

        let log = std::cell::RefCell::new(Vec::new());
        let out = spawn_resolving_on(
            Some(std::ffi::OsStr::new("")),
            None,
            &scanner.display().to_string(),
            &[".EXE".to_owned()],
            windows_like_spawn(Path::new("/nowhere"), &dirs, &log),
        );

        assert!(out.is_ok(), "the stub is runnable through its interpreter");
        assert_eq!(
            log.into_inner(),
            vec![
                (scanner.display().to_string(), vec![]),
                ("sh".to_owned(), vec![scanner.display().to_string()]),
            ],
            "no PATH rung for a path-bearing program — straight from the refusal to its shebang"
        );
    }

    #[test]
    fn a_root_relative_script_still_resolves_without_the_path_rung() {
        // The `acceptance_corpus` shape — `bin/checker` under the repo root —
        // which reaches rung 3 directly, since a name carrying a separator is
        // not a PATH lookup at all. Kept as its own case so collapsing the two
        // rungs into one ladder cannot silently drop the one that already worked.
        let root = temp_dir("ladder-root-relative");
        write(&root.join("bin"), "checker", "#!/bin/sh\nexit 0\n");
        with_shell(&root);
        let dirs = vec![root.clone()];

        let log = std::cell::RefCell::new(Vec::new());
        let out = spawn_resolving_on(
            Some(std::ffi::OsStr::new("")),
            Some(root.as_path()),
            "bin/checker",
            &[".EXE".to_owned()],
            windows_like_spawn(&root, &dirs, &log),
        );
        assert!(out.is_ok());
        assert_eq!(
            log.into_inner().last().map(|(program, _)| program.clone()),
            Some("sh".to_owned())
        );
    }
    /// An unparseable `key_shape` is a LOAD error, never a per-call discard.
    ///
    /// The direction is what makes this worth a case: discarded per call, the
    /// subject resolves to absent, `verdicts` reads that as could-not-look, and
    /// the call is ALLOWED — so a typo silently disabled the row it qualified.
    /// The column shipped with a doc comment claiming this check existed and
    /// without the check; caught in review on #680.
    #[test]
    fn an_unparseable_key_shape_is_refused_at_load() {
        let mut rule = blank("r", RuleKind::Receipt);
        rule.tool = Some("save_issue".to_owned());
        rule.checks = Some(vec!["c".to_owned()]);
        rule.key = Some(ReceiptKey::Named);
        rule.key_from = Some(crate::hook::Field::InputId);
        rule.reason = Some("re-read the row before editing it".to_owned());
        rule.key_shape = Some("[unclosed".to_owned());
        let err = rule
            .validate()
            .expect_err("an unparseable key_shape is refused")
            .to_string();
        assert!(
            err.contains("`key_shape` is not a valid regular expression"),
            "the refusal names the column and the cause: {err}"
        );

        // The control: a well-formed expression loads, so the case above
        // discriminates the expression rather than the column's presence.
        rule.key_shape = Some("^[A-Z]+-[0-9]+$".to_owned());
        rule.validate().expect("a valid key_shape loads");
    }

    /// The value qualifier is refused on EVERY kind that may carry it, and the
    /// emptiness test is over the FOLDED value.
    ///
    /// Both halves were wrong when the column landed: the checks sat in
    /// `validate_receipt_columns`, which returns early for a `shape` row, and the
    /// emptiness test read the raw string — so `"___"` loaded clean and then
    /// compared equal to any value made only of separators. Caught in review on
    /// #680, and this is the case that discriminates both.
    #[test]
    fn a_value_qualifier_is_refused_on_every_kind_that_carries_it() {
        for kind in [RuleKind::Shape, RuleKind::Receipt] {
            let mut rule = blank("r", kind);
            rule.tool = Some("save_issue".to_owned());
            rule.checks = Some(vec!["c".to_owned()]);
            rule.when_value = Some("in review".to_owned());
            rule.when_present = None;
            let err = rule
                .validate()
                .expect_err("a value with no projection is refused")
                .to_string();
            assert!(err.contains("qualifies `when_present`"), "{kind:?}: {err}");

            for folds_to_nothing in ["", "___", "---", " _- "] {
                let mut rule = blank("r", kind);
                rule.tool = Some("save_issue".to_owned());
                rule.checks = Some(vec!["c".to_owned()]);
                rule.when_present = Some(crate::hook::Field::InputState);
                rule.when_value = Some(folds_to_nothing.to_owned());
                let err = rule
                    .validate()
                    .expect_err("a value folding to nothing is refused")
                    .to_string();
                assert!(
                    err.contains("folds to nothing"),
                    "{kind:?} {folds_to_nothing:?}: {err}"
                );
            }
        }
    }
}
