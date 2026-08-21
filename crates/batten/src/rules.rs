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

use clap::ValueEnum;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::findings::{Check, NotObserved, Remediation};
use crate::identity;
use crate::refusal::{Fix, Refusal};
use crate::severity::{self, AdvisoryTier, ReportLevel, RuleSeverity};

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
            RuleKind::Shape => &["pattern", "reason", "severity"],
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
            // Both tables are required: a pipeline row with no verdict-bearing
            // programs judges nothing, and one with no filters cannot recognise
            // the substitution it exists to refuse. Either way the row loads,
            // matches, and decides nothing — the present-and-inert gate this
            // file is written against. `reason` carries the shared remedy, since
            // the engine renders the per-shape cause itself.
            RuleKind::Pipeline => &["verdict", "filters", "reason", "severity"],
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
            // is handed the fact set. `module` is the registration itself — a row
            // without one names no policy and could only ever decide nothing.
            RuleKind::Policy => &["module", "severity"],
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
            // A shape rule is adjudicated per mediated call and never reaches
            // the store, so an identity column on one is decorative by
            // construction (non-negotiable rule 6).
            // `requires_key` brings `base` with it — the range its evidence is
            // read over — which is why the ratchet's column is permitted here
            // rather than duplicated under another name (CLOUD-446).
            RuleKind::Shape => &[
                "pattern",
                "reason",
                "contains",
                "require_via",
                "requires_key",
                "base",
                "policy_url",
                "severity",
            ],
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
                "reason",
                "policy_url",
                "no_fix_reason",
                "severity",
            ],
            // Two optional columns, both with pinned defaults so a row omitting
            // either is still total: `key` selects which git fact the receipt is
            // keyed to, `trigger` what makes the row fire.
            RuleKind::Receipt => &[
                "pattern",
                "checks",
                "key",
                "trigger",
                "reason",
                "contains",
                "policy_url",
                "severity",
            ],
            // No `pattern` and no `glob`: this kind is defined over the operators
            // between segments, so a column selecting a command or a file would
            // narrow nothing it reads.
            RuleKind::Pipeline => &["verdict", "filters", "reason", "policy_url", "severity"],
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
                "severity",
                "predicate_severity",
                "identity_key",
                "reason",
                "policy_url",
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
            // `Policy` is `MediatedCall` alone, and the pairing is `fact_class`
            // read back exactly as `Document`'s is: the class is
            // `Free` x `Hook`, so the mediated call is the surface it was built
            // for. It is here rather than beside `Command` because `authority`
            // says `Supplied` -- the pin over that axis is what admits it, and a
            // kind that could acquire would be refused this scope no matter what
            // this table said.
            RuleKind::Shape | RuleKind::Receipt | RuleKind::Pipeline | RuleKind::Policy => {
                &[RuleScope::MediatedCall]
            }
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
    pub const fn fact_class(self) -> crate::facts::Class {
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
            // carries. `Receipt` pays a bounded git read there; the other two
            // read only the envelope, which is `Cost::Free` — already in hand.
            // `Policy` joins them: evaluating a module is CPU over data already
            // in hand, and it acquires nothing. Measured 2026-08-20 against the
            // pinned toolchain -- ~0.1ms to parse and compile, ~0.5ms p95 for the
            // whole path on a fresh process, against the 100ms ceiling.
            RuleKind::Shape | RuleKind::Pipeline | RuleKind::Policy => {
                Class::new(Cost::Free, Surface::Hook)
            }
            RuleKind::Receipt => Class::new(Cost::Read, Surface::Hook),
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
    fn columns(&self) -> [(&'static str, bool); 30] {
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
            ("check", self.check.is_some()),
            ("fix", self.fix.is_some()),
            ("contains", self.contains.is_some()),
            ("require_via", self.require_via.is_some()),
            ("requires_key", self.requires_key.is_some()),
            ("reason", self.reason.is_some()),
            ("policy_url", self.policy_url.is_some()),
            ("verbatim", self.verbatim.is_some()),
            ("identity_key", self.identity_key.is_some()),
            ("direction", self.direction.is_some()),
            ("base", self.base.is_some()),
            ("retires_with", self.retires_with.is_some()),
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
        // The same shape for `retires_with` (CLOUD-807), and here rather than in
        // the census for the reason stated above it: `base` is already required
        // by the ratchet kind, but the obligation is on the VALUE, so a future
        // kind taking this column inherits the refusal rather than the omission.
        if let Some(token) = self.retires_with.as_deref() {
            if self.base.is_none() {
                return Err(UsageError::raise(format!(
                    "rule {}: `retires_with` requires `base` — the rev a subject must have been alive at",
                    self.id
                )));
            }
            // An empty token matches at the start of every line, so every file
            // would "declare" a subject of whatever its first line happens to
            // say. That reads as a configured admission and decides nothing —
            // the failure `requires_key`'s compile-at-load closes, in the one
            // form this column can take it.
            if token.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "rule {}: `retires_with` cannot be blank — it is the line prefix a subject is declared after, and an empty one matches every line",
                    self.id
                )));
            }
        }
        // The two trigger-dependent obligations (CLOUD-444). They live here
        // rather than in the column census because the census is a per-kind
        // const, and which columns a receipt row owes depends on a value inside
        // it. `key = "branch"` was refused from this same spot until the
        // branch-keyed store existed; both refusals below have that one's
        // reasoning — a column that reads as configured and decides nothing is
        // the defect this kind was added to close.
        if self.kind == RuleKind::Receipt {
            match self.receipt_trigger() {
                // A command-triggered row with no pattern matches every mediated
                // call, turning a precondition into a universal gate.
                ReceiptTrigger::Command if self.pattern.is_none() => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" with `trigger = \"command\"` (the default) requires `pattern` — the command whose precondition this is",
                        self.id
                    )));
                }
                // A write carries no command line, so either column would sit
                // there matching nothing while reading as a narrowing.
                ReceiptTrigger::Write if self.pattern.is_some() || self.contains.is_some() => {
                    return Err(UsageError::raise(format!(
                        "rule {}: kind \"receipt\" with `trigger = \"write\"` takes neither `pattern` nor `contains` — a write has no command line for either to match",
                        self.id
                    )));
                }
                _ => {}
            }
        }
        // A receipt row naming an empty `checks` list gates its trigger on
        // nothing and allows every call, which reads as coverage from the file.
        if self.kind == RuleKind::Receipt && self.checks.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "rule {}: kind \"receipt\" requires at least one entry in `checks`; an empty list gates nothing",
                self.id
            )));
        }
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
        let mine = rule.kind.fact_class();
        if mine.meet(producer.kind.fact_class()) != mine {
            return Err(UsageError::raise(format!(
                "{}: reads `{name}`, derived by {} at cost `{}` on surface `{}`, which a rule at \
                 cost `{}` on surface `{}` cannot carry — composition takes the meet on both axes",
                pointer_for(at, &rule.id),
                pointer_for(at, &producer.id),
                producer.kind.fact_class().cost.as_str(),
                producer.kind.fact_class().surface.as_str(),
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
    _provisions: &[crate::provision::Provision],
    root: &Path,
) -> anyhow::Result<Scan> {
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
                Refusal::new(
                    &rule.id,
                    "this rule kind runs a configured command, which `batten check` \
                     (a read-effect verb) will not do",
                    Fix::Run(SPAWNING_VERB.to_owned()),
                )
                .render(),
            ));
        }
    }
    run(rules, &[], root)
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
    root: &Path,
) -> anyhow::Result<Scan> {
    let (evaluable, withheld): (Vec<&Rule>, Vec<&Rule>) = rules
        .iter()
        .partition(|rule| !rule.kind.carries_ambient_authority());
    let evaluable: Vec<Rule> = evaluable.into_iter().cloned().collect();
    let mut scan = run(&evaluable, provisions, root)?;
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
    root: &Path,
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
    run(rules, provisions, root)
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
) -> anyhow::Result<Scan> {
    let files = tree_files(root)?;
    // Resolved ONCE for the whole run, before any rule is evaluated (CLOUD-773).
    // That is the entire point: the shell layer this replaces re-derives because
    // a producer's value cannot cross the boundary, so it pays the extraction
    // per consumer. Here the producer pays once and every reader reads.
    let derived = resolve_derived(rules, root, &files);

    let mut scan = Scan::default();
    for rule in rules {
        if let Some(why) = run_rule(rule, provisions, root, &files, &derived, &mut scan.findings)? {
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
    Ok(scan)
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

/// Apply one rule to the pre-collected, sorted `files` list.
///
/// Returns `Some(reason)` when the rule **did not evaluate** — which is not the
/// same as evaluating to nothing. Only that distinction lets the store hold a
/// finding whose rule never looked instead of resolving it (CLOUD-81).
fn run_rule(
    rule: &Rule,
    provisions: &[crate::provision::Provision],
    root: &Path,
    files: &[String],
    derived: &BTreeMap<String, crate::facts::Look<String>>,
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
    // re-parsed per file (CLOUD-214).
    let selector = Selector::new(glob)?;
    let matched: Vec<&String> = files.iter().filter(|path| selector.matches(path)).collect();

    // A ratchet is evaluated BEFORE the empty-match skip below, and the
    // distinction is the whole gate: for every other kind an empty match set
    // means "nothing to inspect", but for a ratchet it means the working tree
    // now contains none of the files the base did — which is the maximal
    // deletion this kind exists to catch. Skipping there would make the gate
    // silent in exactly its worst case.
    if rule.kind == RuleKind::Ratchet {
        ratchet_rule(rule, root, glob, files, &matched, findings)?;
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
                document_in_file(rule, root, path, derived, findings)?;
            }
        }
        RuleKind::Secrets => crate::secrets::scan(rule, provisions, root, &matched, findings)?,
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
        | RuleKind::Judge => {}
    }
    Ok(None)
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
        // Held only for the column that reads it: a ratchet without
        // `retires_with` must not start buffering the base tree's text.
        if retires_with.is_some() {
            base_text.insert(path.to_owned(), text.to_owned());
        }
    })?;
    let base_count: usize = base_counts.values().sum();

    let mut working_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut working_count = 0;
    for path in matched {
        let text = fs::read_to_string(root.join(path)).unwrap_or_default();
        let count = text.matches(pattern).count();
        working_count += count;
        working_counts.insert(path.as_str(), count);
        // Consequence two of the column (CLOUD-807): EVERY matched file owes a
        // resolvable subject, not merely the ones this change touched. Without
        // it the admission below rests on a header nobody checks, and a suite
        // that outlived its subject is indistinguishable from one that never
        // declared one.
        if let Some(token) = retires_with {
            unresolved_subject(rule, path, &text, token, files, findings);
        }
    }

    if !direction.violated(base_count, working_count) {
        return Ok(());
    }

    // The admission (CLOUD-807). A decrease is bought by the affected files'
    // subjects having DIED — declared at `base`, alive at `base`, absent now.
    // Anything else falls through to the refusal below, so a row that cannot
    // justify its decrease still denies at its own severity.
    let mut blockers: BTreeSet<String> = BTreeSet::new();
    if let Some(token) = retires_with {
        let mut declared: BTreeSet<String> = BTreeSet::new();
        for (path, was) in &base_counts {
            let now = working_counts.get(path.as_str()).copied().unwrap_or(0);
            if now >= *was {
                continue;
            }
            // Read from the BASE text, never the working one. A retired file has
            // no working copy to read, and allowing the working copy would let a
            // change rewrite its own permission in the commit that spends it.
            let subject = base_text
                .get(path)
                .map(|text| declared_subject(text, token))
                .unwrap_or_default();
            if subject.is_empty() {
                blockers.insert(format!("{SUBJECT_UNDECLARED} {path}"));
                continue;
            }
            declared.extend(subject);
        }
        // Alive at `base` is the anti-rot term: without it a header naming a
        // path that never existed reports "absent from the working tree" and
        // admits the very deletion it was supposed to justify.
        let alive_at_base = crate::git::paths_present_at_rev(root, base, &declared)?;
        let present: BTreeSet<&str> = files.iter().map(String::as_str).collect();
        for path in &declared {
            if !alive_at_base.contains(path) {
                blockers.insert(format!("{SUBJECT_NEVER_EXISTED} {path}"));
            } else if present.contains(path.as_str()) {
                blockers.insert(format!("{SUBJECT_ALIVE} {path}"));
            }
        }
        if blockers.is_empty() {
            // Every affected file's subject died in this same change. This is
            // the retirement the `[[waiver]]` used to have to express by
            // switching the whole rule off.
            return Ok(());
        }
    }

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
            render_blockers(&blockers)
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
    Ok(())
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
    let contents = match fs::read(root.join(rel_path)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    // Bytes that are not UTF-8 are a document nothing here can parse, which is
    // "could not look" and not "no rows" — the same arm a syntax error takes.
    let outcome = match String::from_utf8(contents) {
        Ok(text) => format.read(&text),
        Err(_) => crate::facts::Look::CouldNotLook,
    };
    let reason = match &outcome {
        // `IsNot` rides with `CouldNotLook` rather than standing apart, and the
        // pairing is not laziness: `Format::read` answers only `Is` or
        // `CouldNotLook`, because a file that fails to parse says nothing at all
        // about what it contains. The arm exists so the type stays total and
        // resolves to the same honest answer if that ever changes — what it must
        // never resolve to is silence.
        crate::facts::Look::CouldNotLook | crate::facts::Look::IsNot => Some(DOCUMENT_UNREADABLE),
        crate::facts::Look::Is(document) => match document.at(node_path) {
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
    let Ok(selector) = Selector::new(glob) else {
        return Look::CouldNotLook;
    };
    // The FIRST matching path, in the walk's sorted order. A derivation is one
    // value, so a glob matching several documents has to pick, and picking by
    // the sorted walk is the one choice that does not depend on the filesystem's
    // order. A row meaning "these must all agree" writes several READING rows
    // instead, which is what keeps each clause independently nameable.
    let Some(path) = files.iter().find(|path| selector.matches(path)) else {
        return Look::CouldNotLook;
    };
    let Ok(bytes) = fs::read(root.join(path)) else {
        return Look::CouldNotLook;
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Look::CouldNotLook;
    };
    match format.read(&text) {
        Look::Is(document) => match document.at(node_path) {
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
        Look::IsNot | Look::CouldNotLook => Look::CouldNotLook,
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
            contains: None,
            require_via: None,
            requires_key: None,
            reason: None,
            policy_url: None,
            check: None,
            fix: None,
            run: None,
            verbatim: None,
            identity_key: None,
            direction: None,
            base: None,
            retires_with: None,
            format: None,
            node: None,
            derives: None,
            reads: None,
            module: None,
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
        }
    }

    /// The findings half of a scan. Every assertion below is about what was
    /// found; [`Scan::not_evaluated`] has its own tests, so shadowing keeps the
    /// suite reading as it did before that half existed.
    fn run_static(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
        super::run_static(rules, &[], root).map(|scan| scan.findings)
    }

    fn run_all(rules: &[Rule], root: &Path) -> anyhow::Result<Vec<Finding>> {
        super::run_all(rules, &[], root).map(|scan| scan.findings)
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

        let clean = super::run_static(&[forbid("looked", "**/*.rs", "TODO")], &[], &dir).unwrap();
        assert!(clean.findings.is_empty());
        assert!(
            clean.not_evaluated.is_empty(),
            "a rule that read a file and found nothing DID evaluate"
        );

        let skipped =
            super::run_static(&[forbid("never-looked", "**/*.md", "TODO")], &[], &dir).unwrap();
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
            assert!(
                matches!(
                    kind.fact_class().cost,
                    crate::facts::Cost::Free | crate::facts::Cost::Read
                ),
                "{kind:?} reaches the mediated call at cost `{}`",
                kind.fact_class().cost.as_str()
            );
            assert_eq!(
                kind.fact_class().surface,
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
        for kind in RuleKind::ALL {
            let spends = matches!(
                kind.fact_class().cost,
                crate::facts::Cost::Effect | crate::facts::Cost::Stateful
            );
            assert_eq!(
                kind.carries_ambient_authority(),
                spends,
                "{kind:?} is `{}` on the authority axis and `{}` on the cost axis",
                kind.authority().as_str(),
                kind.fact_class().cost.as_str()
            );
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
                // And once more, for the third "one of" (CLOUD-773): a document
                // row carries exactly one of `pattern` or `reads`, which the flat
                // column list cannot say either. Supplied so the only possible
                // complaint stays the pairing.
                if *kind == RuleKind::Document {
                    rule.pattern = Some("x".to_owned());
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
            RuleKind::Receipt.fact_class().surface,
            crate::facts::Surface::Hook
        );
        assert_eq!(
            RuleKind::Document.fact_class().surface,
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
            RuleKind::Document.fact_class().cost,
            crate::facts::Cost::Read
        );
        assert_eq!(
            RuleKind::Secrets.fact_class().cost,
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
}
