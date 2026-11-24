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

use crate::config_check::rules::RuleExt as _;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::config_check::rules::Declared;
#[cfg(test)]
use crate::config_check::rules::Located;
#[cfg(test)]
use crate::config_check::rules::validate;
#[cfg(test)]
use crate::config_check::rules::validate_composition;
use crate::config_check::rules::{COLUMN_CENSUS, Declares};
use crate::config_model::CeilingUnit;
use crate::config_model::Conserves;
use crate::config_model::Direction;
#[cfg(test)]
use crate::config_model::FieldBound;
use crate::config_model::GitRead;
use crate::config_model::NativeGate;
#[cfg(test)]
use crate::config_model::ReceiptKey;
#[cfg(test)]
use crate::config_model::ReceiptTrigger;
use crate::config_model::RequireVia;
#[cfg(test)]
use crate::config_model::Rewrite;
use crate::config_model::Rule;
use crate::config_model::RuleKind;
#[cfg(test)]
use crate::config_model::VerdictProgram;
#[cfg(test)]
use crate::config_model::preset_name_schema;
use crate::error::UsageError;
use crate::findings::{Check, NotObserved, Remediation};
use crate::identity;
use crate::preset_catalog::RuleScope;
use crate::refusal::{Fix, Refusal};
use crate::selector::glob_match;
use crate::severity::{self, ReportLevel, RuleSeverity};
use crate::surface_table::Half;

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
    "interprets",
    "reason",
    "policy_url",
    "bypass_env",
    "severity",
    "no_retry_reason",
];

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
    // The other polarity of `contains` (CLOUD-1477's sibling). `shape` only: it
    // switches a deny OFF, and a column that does that has no business on a
    // precondition row, where the same bytes would silently stop demanding a
    // receipt.
    "unless_contains",
    // CLOUD-2669: one whole argv word, by anchored expression. `unless_word`
    // switches a deny off, so it is `shape` only for `unless_contains`'s reason.
    "word",
    "unless_word",
    // CLOUD-2662: an event the engine resolves on every route it knows.
    "on",
    "require_via",
    "requires_key",
    "base",
    "policy_url",
    "bypass_env",
    "severity",
    "no_retry_reason",
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
    // CLOUD-2662: the third selector, an event rather than a spelling.
    "on",
    "checks",
    "checks_any",
    "key",
    "key_from",
    "key_base",
    "key_shape",
    "max_age",
    "requires_field",
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
    // CLOUD-1390's third polarity: a condition on the BRANCH rather than on this
    // call, which is the one a punt needs — the turn that punted is over, and no
    // projection of the next call carries it.
    "while_marker",
    // The harm a punt row names, read directly: whether HEAD is on any remote.
    "while_unpushed",
    "trigger",
    "reason",
    "contains",
    "policy_url",
    "bypass_env",
    "severity",
    "no_retry_reason",
];

/// The severity `rules` grade `gate` at (CLOUD-2291): the strongest `native` row
/// naming it, or `deny` where none does.
///
/// THE ONE DEFINITION, read by the hook that enforces the grade and by the
/// weakening diff that judges a change to it, so the two cannot disagree. The
/// STRONGEST, never the first, so declaration order decides nothing; and `deny`
/// for no row, so no addition can lower a gate it does not name. A config that
/// predates the kind keeps every gate refusing.
#[must_use]
pub fn native_grade(rules: &[Rule], gate: NativeGate) -> RuleSeverity {
    rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::Native && rule.gate == Some(gate))
        .map(Rule::severity)
        .max()
        .unwrap_or(absent_grade(gate))
}

/// The grade of a gate no row names: `deny`, so no addition lowers a gate it
/// does not name, EXCEPT `repository-reach` (CLOUD-2672), which is `allow` until
/// a row arms it. A session spanning several repositories is the ordinary case
/// on every host that documents one, so a default-on gate would refuse it in
/// every consumer.
fn absent_grade(gate: NativeGate) -> RuleSeverity {
    match gate {
        NativeGate::RepositoryReach => RuleSeverity::Allow,
        _ => RuleSeverity::Deny,
    }
}

/// The columns a [`RuleKind::Reference`] row accepts (CLOUD-2005): its `cites`
/// table, the citer's `glob` with one of `regex` or `format` + `node`, and the
/// columns every reporting kind shares. A const of its own so
/// [`RuleKind::permits`] stays one arm per kind.
const REFERENCE_COLUMNS: &[&str] = &[
    "cites",
    "glob",
    "regex",
    "format",
    "node",
    "exclude_paths",
    "reason",
    "policy_url",
    "no_fix_reason",
    "severity",
];

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

/// `RuleKind` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait RuleKindExt: Sized {
    /// Every kind the engine knows, so the partitions below are total.
    ///
    /// A new variant must be added here or [`tests::all_covers_every_kind`]
    /// fails — which is what keeps [`RuleKind::carries_ambient_authority`] from silently
    /// defaulting a spawning kind to "safe".
    const ALL: &'static [RuleKind];

    /// The stable lowercase token used in config and machine output (§6).
    #[must_use]
    fn as_str(&self) -> &'static str;

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
    fn authority(self) -> Authority;

    /// Whether this kind may reach beyond its supplied inputs at all.
    ///
    /// The `scopes` predicate and `run_static`'s refusal both read this and
    /// nothing else, so "which kinds are excluded from the mediated call" and
    /// "which kinds `batten check` refuses" cannot drift apart.
    #[must_use]
    fn carries_ambient_authority(self) -> bool;

    /// The columns this kind cannot load without.
    #[must_use]
    fn requires(self) -> &'static [&'static str];

    /// Whether this kind's predicate **decides** the question it claims to
    /// answer, or only approximates it (CLOUD-331).
    ///
    /// The bar to block is decidability against a declared OBJECT, not mere
    /// computability. A rule can be perfectly deterministic and still be an
    /// approximation, because the question it is asked is open-ended: `CodeShield`
    /// is Semgrep and regex with no model in the loop, and its measured recall
    /// is 0.79 — so 21% of what it looks for passes silently while a
    /// computability test admits it as blocking.
    ///
    /// **The classification is authored, and that is the honest bound on it.**
    /// What the mechanism buys is that the claim is written down per kind, in
    /// one place, and that violating it is a failure rather than a design drift.
    ///
    /// **Absence fails safe to `Approximating`** — the same reading
    /// [`crate::effect::Effect::Ask`] gives an unlisted command. A Rust `match`
    /// has no absent arm, so that default lives where a kind can actually be
    /// missing: [`decidability_of`], over a finding whose owning row cannot be
    /// resolved.
    #[must_use]
    fn decidability(self) -> Decidability;

    /// Every column this kind accepts — a superset of [`RuleKind::requires`].
    ///
    /// Anything outside this set is a usage error rather than an ignored key: a
    /// `glob` on a shape rule selects files a shape rule never reads, so
    /// accepting it would let a reviewer believe a rule is scoped when it is not.
    #[must_use]
    /// Whether a `fix` on this kind is executed at the mediated boundary
    /// (CLOUD-1639).
    ///
    /// **The kinds that reach `crate::hook`.** `fix` lived on `Command` alone,
    /// which is a TREE-scope check kind — so the repair column sat on the one
    /// kind that never sees a call, and `run_all` refused it outright because
    /// nothing there could run it. These three DO see a call, and the boundary
    /// runs their repair under the raised class's
    /// [`crate::preset_catalog::Applicability`].
    ///
    /// A match with no wildcard: a kind added later is a compile error here
    /// rather than one silently answered `false`, which would be a repair a
    /// consumer declared and nothing ran — the exact false green `run_all`'s
    /// refusal exists to prevent.
    fn repairs_at_the_boundary(self) -> bool;

    #[must_use]
    fn permits(self) -> &'static [&'static str];

    /// The scopes this kind may declare.
    ///
    /// The pairing is what makes the scope key a real router rather than a label:
    /// a file kind scoped to the mediated call, or a shape kind scoped to the
    /// tree, would be a rule that no surface ever evaluates — present, inert, and
    /// reading as covered.
    #[must_use]
    fn scopes(self) -> &'static [RuleScope];

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
    fn fact_class(self, scope: RuleScope) -> crate::facts::Class;
}

impl RuleKindExt for RuleKind {
    const ALL: &'static [RuleKind] = &[
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
        RuleKind::Reference,
        RuleKind::Native,
    ];

    fn as_str(&self) -> &'static str {
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
            RuleKind::Reference => "reference",
            RuleKind::Native => "native",
        }
    }

    fn authority(self) -> Authority {
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
            | RuleKind::Policy
            // Reads the declared register paths and the citer paths, both
            // through the one document acquisition; it names no program.
            | RuleKind::Reference
            // The engine's own gate over facts the boundary resolved; the row
            // names no program and no path.
            | RuleKind::Native => Authority::Supplied,
            // All three run a program a `batten.toml` named. That a judge's
            // consults a model, a command's decides a gate and a secrets rule's
            // scans for credentials makes no difference to the axis: each starts
            // a process with the ambient authority of the calling user.
            RuleKind::Command | RuleKind::Judge | RuleKind::Secrets => Authority::Spawns,
        }
    }

    fn carries_ambient_authority(self) -> bool {
        self.authority().is_ambient()
    }

    fn requires(self) -> &'static [&'static str] {
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
            // `pattern` is absent for `forbid`'s reason: a ratchet counts exactly
            // one of `pattern` or `regex` (CLOUD-2059), which `validate` checks.
            RuleKind::Ratchet => &["glob", "direction", "base", "severity"],
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
            // `checks` is NOT here since CLOUD-1297, and its absence is a
            // conditional requirement rather than a relaxation — the same move
            // `pattern` makes above and `verdict` makes below. A receipt row
            // must still name at least one receipt, but it may do so in either
            // column: `checks` for the conjunction, `checks_any` for the
            // alternation. Requiring `checks` unconditionally would make the
            // alternation unusable on its own, which is the whole of the column.
            // [`Rule::validate_receipt_columns`] refuses a row naming neither.
            //
            // NOW EQUAL TO `Shape`'s AND `Pipeline`'s LISTS, and by the same
            // coincidence those two already record: three kinds arrived at
            // `reason` + `severity` by three unrelated conditional-column moves
            // — CLOUD-758's, CLOUD-864's and this one — and each can regain a
            // column without the others. `#[expect]` rather than `#[allow]` so
            // the day the lists diverge this goes red and is deleted.
            #[expect(
                clippy::match_same_arms,
                reason = "the lists are equal by coincidence; see the note above"
            )]
            RuleKind::Receipt => &["reason", "severity"],
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
            // `glob` is absent for `Policy`'s reason: a row citing another
            // register's column has no glob. `validate` carries which citer
            // shape needs which column.
            RuleKind::Reference => &["cites", "severity"],
            // Which gate, and how hard: the whole of what the row decides.
            RuleKind::Native => &["gate", "severity"],
        }
    }

    fn decidability(self) -> Decidability {
        match self {
            // THE ONE APPROXIMATING KIND, and it is the archetype: a judge
            // returns a model's opinion, which is CLOUD-93's rejection arriving
            // as a corollary of this rule rather than as a special case.
            RuleKind::Judge => Decidability::Approximating,
            // Every other kind decides its own object, and the object is the
            // point — never the open-ended question a reader might project onto
            // it. `forbid` is asked "does this declared pattern occur in these
            // selected files", not "is this code wrong"; its recall against THAT
            // is 1.0 by construction. Same for `document` (does this node hold
            // this value), `ratchet` (are these two counts ordered), `shape`,
            // `receipt`, `pipeline` and `policy` (does this module's predicate
            // hold over the fact set it was handed).
            //
            // `secrets` is the closest call and lands here deliberately. Its
            // object is the PINNED SCANNER'S REPORT rather than "are there
            // credentials in this tree", and `secrets::cross_check` is what
            // makes that exact: a scanner whose exit status and output disagree
            // is exit 3, never a quiet verdict. So its silence is evidence about
            // a reading it actually took, which is what the other kinds' silence
            // is too. A build that swapped in a detector without that
            // cross-check would have to move this arm.
            RuleKind::Forbid
            | RuleKind::Command
            | RuleKind::Shape
            | RuleKind::Ratchet
            | RuleKind::Receipt
            | RuleKind::Pipeline
            | RuleKind::Secrets
            | RuleKind::Document
            | RuleKind::Policy
            // Is this token a key of that set: a membership test over a set the
            // row declared, which is decided exactly.
            | RuleKind::Reference
            // Reachability, a lock holder, a history receipt: each decided.
            | RuleKind::Native => Decidability::Deciding,
        }
    }

    fn repairs_at_the_boundary(self) -> bool {
        match self {
            // `policy` AND ONLY `policy`, AND THE FIXTURE IS WHAT NARROWED IT.
            //
            // The first draft answered `true` for `receipt`, `shape` and
            // `pipeline` — the kinds that reach the mediated boundary — and a
            // fixture exercising a `shape` row could not be written. A repair is
            // admissible only where the row's CLASS declares `applicability`, and
            // a native-kind row declares no class: every `shape` row raises
            // `call name refused`, every `receipt` row one of four receipt
            // classes. Putting `applicability` on those would make every row of
            // the kind repairable at once, which is not a thing any consumer
            // could want and not what the column means.
            //
            // A `policy` row is the one kind whose module raises a class the
            // CONSUMER declared, so it is the one kind where "this row's class
            // says repair" is a sentence with a subject. `[[rule]].verdict` is
            // the pipeline program list and not a class, so no other kind can
            // name one (CLOUD-1638 measures that seam over 66 rows).
            RuleKind::Policy => true,
            RuleKind::Receipt
            | RuleKind::Shape
            | RuleKind::Pipeline
            | RuleKind::Forbid
            | RuleKind::Command
            | RuleKind::Ratchet
            | RuleKind::Judge
            | RuleKind::Secrets
            | RuleKind::Document
            | RuleKind::Reference
            | RuleKind::Native => false,
        }
    }

    fn permits(self) -> &'static [&'static str] {
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
                "regex",
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
                // CLOUD-2663: the token measure `policy budget` uses, as the
                // counted unit in place of `pattern` or `regex`; exactly one of the
                // three is refused in `validate_forbid_predicate`.
                "counts",
                // CLOUD-2663: each matched file judged against its own base count.
                "per_file",
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
            RuleKind::Reference => REFERENCE_COLUMNS,
            // No `reason`: the refusal is the gate's own, with its own routes.
            RuleKind::Native => &["gate", "severity", "no_fix_reason"],
            RuleKind::Policy => &[
                // CLOUD-1639, and this is the ONE kind that may carry `fix` at
                // the mediated boundary: a repair is admissible only where the
                // row's CLASS declares `applicability`, and a `policy` row's
                // module raises a class the CONSUMER declared. Whether the row
                // then OWES `no_retry_reason` depends on which applicability
                // that class declares, which a flat per-kind list cannot say —
                // `validate_repair` carries the conditional, the same split
                // `Document`'s `pattern`/`reads` pair already uses.
                "fix",
                "no_retry_reason",
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
                "unit_sources",
                // CLOUD-1167. A declared READ like the four above, and the only
                // one whose subject lives outside the repository — which is why
                // it is permitted on this kind alone: `check` is bounded by the
                // tree it is pointed at, and a row that reaches past that bound
                // has to be one a reviewer can see in the committed authority.
                "external",
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
                // CLOUD-1049's second half. The EXTENSION decides a declared
                // path's format wherever it can, and this says what to do where
                // it cannot: a `staged` path whose extension no `Format` owns is
                // `UnknownFormat` before a byte is read, so a row declaring one
                // was registered and decided nothing on every run. Lockfiles are
                // the family that provokes it — several ecosystems write one
                // format under an extension that names another — and WHICH path
                // carries which format is the consumer's `batten.toml` to say,
                // never this crate's to know (rule 1, CLOUD-772).
                //
                // A FALLBACK, NOT AN OVERRIDE, and the bound is what keeps
                // `facts.rs`'s "the extension is the honest default there" true:
                // a path whose extension IS known ignores this column entirely,
                // so a row cannot re-declare `.json` as TOML and blame the file
                // for the parse failure. Guessing stays refused; declaring does
                // not.
                //
                // Not extended to `documents`, and that is deliberate rather than
                // unfinished: an unknown-extension DOCUMENT is already a hard
                // config fault at load, which is a designed answer and a louder
                // one than this. `staged` never got that check, which is why the
                // silence landed there.
                "format",
                "no_fix_reason",
            ],
        }
    }

    fn scopes(self) -> &'static [RuleScope] {
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
            | RuleKind::Document
            | RuleKind::Reference => &[RuleScope::Tree],
            RuleKind::Shape | RuleKind::Receipt | RuleKind::Pipeline | RuleKind::Native => {
                &[RuleScope::MediatedCall]
            }
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

    fn fact_class(self, scope: RuleScope) -> crate::facts::Class {
        use crate::facts::{Class, Cost, Surface};
        match self {
            // Reads matched files, on the tree surface. `Ratchet` adds fixed git
            // plumbing, which is the same bounded read.
            RuleKind::Forbid | RuleKind::Ratchet | RuleKind::Document | RuleKind::Reference => {
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
            // `Native` reads what the boundary resolved for the gate: the
            // reset's reachability and the history receipts are bounded reads.
            RuleKind::Shape | RuleKind::Receipt | RuleKind::Native => {
                Class::new(Cost::Read, Surface::Hook)
            }
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

use crate::sink::Sink;
#[cfg(test)]
use crate::sink::SinkKey;

/// Each rule that declares a sink, as its id and that sink: what `sink`'s
/// store questions take, so the store never needs the whole `Rule`.
fn declared_sinks(rules: &[Rule]) -> impl Iterator<Item = (&str, &Sink)> {
    rules
        .iter()
        .filter_map(|rule| Some((rule.id.as_str(), rule.produces.as_ref()?)))
}

// Housed in `crate::facts` (CLOUD-2789), which reads it too; the path here is
// unchanged.
use crate::facts::selects_tool_name;

/// `Rule` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait RuleExt: Sized {
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
    fn program(&self) -> Option<&str>;

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
    fn severity(&self) -> RuleSeverity;

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
    fn severity_for(&self, predicate: Option<&str>) -> RuleSeverity;

    /// Every receipt name this row mentions, in either column (CLOUD-1297).
    ///
    /// **The one place a resolution site may read, and it exists to close a dead
    /// gate rather than to save typing.** The boundary decides which facts to
    /// resolve by walking a row's receipt names; a site that walked `checks`
    /// alone after `checks_any` existed would leave every alternation name
    /// unresolved, and an unresolved name reads [`Validity::Missing`], so the
    /// alternation could never be satisfied and the row would deny every call it
    /// selected. That failure is invisible from the config — the row reads as
    /// configured and the refusal names a real receipt — which is the class
    /// `rules/policy-modules.md` records one layer down for a key the
    /// engine never builds.
    ///
    /// So ADJUDICATION reads the two columns apart, because they mean different
    /// things, and RESOLUTION reads them together, because the question there is
    /// only "which facts does this row need answered".
    fn receipt_names(&self) -> impl Iterator<Item = &String>;

    /// The mediator this row requires, if it requires one.
    ///
    /// Absence is "no mediator required", which is every row that predates
    /// CLOUD-271 and is why the column is optional rather than defaulted: a
    /// default would silently narrow every existing shape row.
    #[must_use]
    fn require_via(&self) -> Option<RequireVia>;

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
    fn settling_check(&self) -> Option<Check>;

    /// [`Rule::settling_check`] for a judge row, given the resolved command.
    ///
    /// Split from the method above because the judge's argv is not on the row:
    /// `[judge].run` is a table-level key, so the row alone cannot answer, and
    /// returning a placeholder that a caller *might* fill would be the kind of
    /// half-built value that reads as complete. This one takes what it needs.
    #[must_use]
    fn settling_argv(&self, argv: &[String]) -> Option<Check>;

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
    fn remediation(&self) -> Option<Remediation>;

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
    fn selects_tool(&self, raw_tool: &str) -> bool;

    /// The banned command shape: the effective program, then the adjacent words
    /// that must follow it.
    ///
    /// `None` for any kind but [`RuleKind::Shape`], and for a `pattern` with no
    /// program token.
    #[must_use]
    fn shape(&self) -> Option<(&str, Vec<&str>)>;

    /// Every fact this row declares, read off [`COLUMN_CENSUS`] (step 13a).
    fn census_facts(&self) -> impl Iterator<Item = crate::facts::Fact> + '_;

    /// Which half of a split `enforce` judges this row (step 13a).
    ///
    /// [`Half::Tree`] only where the verdict is provably a function of the
    /// indexed tree, so a receipt keyed on that tree may stand in for it; every
    /// other answer — and every answer this cannot establish — is
    /// [`Half::Live`], the half that always re-runs.
    ///
    /// * `forbid`, `document`, `secrets`, `reference`: tree when every fact the
    ///   row declares is [`crate::facts::Subject::Tree`].
    /// * `ratchet`: tree when its `base` is one of `keyed_bases` — the refs the
    ///   caller's receipt keys the merge base of — and its facts are tree.
    /// * `policy`: tree when its facts are tree and its bundle's
    ///   [`crate::policy::Bundle::tree_reads`] names only tree keys. No bundle
    ///   is live.
    /// * every spawning, mediated or native kind, any `scope = "mediated_call"`
    ///   row, and any row gated on `requires_path` (an existence test the tree
    ///   key does not cover, since the path may be ignored): live.
    #[must_use]
    fn half(&self, bundle: Option<&crate::policy::Bundle>, keyed_bases: &[String]) -> Half;

    /// The command shape this row keys on, for **any** kind that keys on one.
    ///
    /// Split out of [`Rule::shape`] because two kinds now match a command line
    /// and they mean different things by it: `shape` names a command that is
    /// banned, `receipt` names one that is gated on a precondition. `shape()`
    /// keeps its kind check so its existing callers cannot be handed a receipt
    /// row by accident — the failure that costs nothing to prevent here and is
    /// invisible when it happens, since an unmatched rule simply allows.
    #[must_use]
    fn trigger(&self) -> Option<(&str, Vec<&str>)>;

    /// The first [`Rule::requires_path`] entry the tree does not carry, or
    /// `None` when the rule's declared inputs are all present (CLOUD-125).
    ///
    /// **The FIRST rather than all of them**, which is the pointer discipline
    /// applied to a precondition: the reader has one thing to go and create, and
    /// a row declaring four absent paths reports one line rather than four
    /// saying the same thing. Declaration order decides, so the answer is
    /// byte-stable for a given config (§6) — it does not depend on the walk, the
    /// filesystem's ordering, or how many entries happen to be missing.
    ///
    /// A rule declaring nothing answers `None`, so a caller can ask this of any
    /// row without first testing the column — the totality every other modifier
    /// accessor here has.
    ///
    /// This is the one place the precondition touches the filesystem, and it is
    /// a `try_exists` per declared entry: no glob expansion, no read, and
    /// nothing spawned. A path that exists but cannot be *stated* (a permission
    /// error on an ancestor) counts as missing, which is the fail-closed
    /// reading — could-not-look is not evidence the input is there.
    #[must_use]
    fn unmet_requirement(&self, root: &Path) -> Option<&str>;
}

impl RuleExt for Rule {
    fn program(&self) -> Option<&str> {
        if self.kind != RuleKind::Command {
            return None;
        }
        self.check.as_deref()?.split_whitespace().next()
    }

    fn severity(&self) -> RuleSeverity {
        self.severity.unwrap_or(RuleSeverity::Allow)
    }

    fn severity_for(&self, predicate: Option<&str>) -> RuleSeverity {
        let Some(predicate) = predicate else {
            return self.severity();
        };
        self.predicate_severity
            .as_ref()
            .and_then(|table| table.get(predicate))
            .copied()
            .unwrap_or_else(|| self.severity())
    }

    fn receipt_names(&self) -> impl Iterator<Item = &String> {
        self.checks
            .iter()
            .flatten()
            .chain(self.checks_any.iter().flatten())
    }

    fn require_via(&self) -> Option<RequireVia> {
        self.require_via
    }

    fn settling_check(&self) -> Option<Check> {
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
            RuleKind::Forbid
            | RuleKind::Ratchet
            | RuleKind::Secrets
            | RuleKind::Document
            | RuleKind::Reference => Some(Check::Reevaluate),
            // None of the four reaches the store: each is adjudicated per
            // mediated call and produces a decision, not a finding. `Policy`
            // belongs here rather than beside `Judge` — its verdict is a real
            // deny that the engine could re-decide, it simply has no stored
            // finding to re-decide, which is `Shape`'s situation exactly.
            RuleKind::Shape
            | RuleKind::Receipt
            | RuleKind::Pipeline
            | RuleKind::Policy
            | RuleKind::Native => None,
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

    fn settling_argv(&self, argv: &[String]) -> Option<Check> {
        match self.kind {
            RuleKind::Judge => Some(Check::Argv(argv.to_vec())),
            _ => self.settling_check(),
        }
    }

    fn remediation(&self) -> Option<Remediation> {
        if let Some(fix) = &self.fix {
            return Some(Remediation::Fix(
                fix.split_whitespace().map(ToOwned::to_owned).collect(),
            ));
        }
        self.no_fix_reason.clone().map(Remediation::NoFix)
    }

    fn selects_tool(&self, raw_tool: &str) -> bool {
        let Some(selector) = self.tool.as_deref() else {
            return false;
        };
        selects_tool_name(selector, raw_tool)
    }

    fn shape(&self) -> Option<(&str, Vec<&str>)> {
        if self.kind != RuleKind::Shape {
            return None;
        }
        self.trigger()
    }

    fn census_facts(&self) -> impl Iterator<Item = crate::facts::Fact> + '_ {
        COLUMN_CENSUS
            .iter()
            .filter_map(|column| match column.declares {
                Declares::Fact(fact, declared) if declared(self) => Some(fact),
                Declares::Fact(..) | Declares::NotFactBearing(_) => None,
            })
    }

    fn half(&self, bundle: Option<&crate::policy::Bundle>, keyed_bases: &[String]) -> Half {
        if self.scope == RuleScope::MediatedCall || !self.requires_path.is_empty() {
            return Half::Live;
        }
        // `base-delta` is the diff against this row's own `base`, so it is keyed
        // as a ratchet is: by that base's commit, when it is a keyed base
        // (CLOUD-2329).
        let base_keyed = self
            .base
            .as_ref()
            .is_some_and(|base| keyed_bases.contains(base));
        let keyable = |fact: crate::facts::Fact| {
            keyable_in_tree_half(fact) || (fact == crate::facts::Fact::BaseDelta && base_keyed)
        };
        let facts_tree = self.census_facts().all(keyable);
        let tree = match self.kind {
            RuleKind::Forbid | RuleKind::Document | RuleKind::Secrets | RuleKind::Reference => {
                facts_tree
            }
            RuleKind::Ratchet => facts_tree && base_keyed,
            RuleKind::Policy => {
                facts_tree
                    && bundle.is_some_and(|bundle| match bundle.tree_reads() {
                        crate::policy::Reads::Known(keys) => keys.iter().all(|key| {
                            key == TREE_MISSING_KEY
                                || crate::facts::Fact::from_tree_key(key).is_some_and(keyable)
                        }),
                        crate::policy::Reads::Opaque => false,
                    })
            }
            RuleKind::Command
            | RuleKind::Judge
            | RuleKind::Receipt
            | RuleKind::Shape
            | RuleKind::Pipeline
            | RuleKind::Native => false,
        };
        if tree { Half::Tree } else { Half::Live }
    }

    fn trigger(&self) -> Option<(&str, Vec<&str>)> {
        let mut words = self.pattern.as_deref()?.split_whitespace();
        let program = words.next()?;
        Some((program, words.collect()))
    }

    fn unmet_requirement(&self, root: &Path) -> Option<&str> {
        self.requires_path
            .iter()
            .find(|declared| !root.join(declared).try_exists().unwrap_or(false))
            .map(String::as_str)
    }
}
// CLOUD-2669: `refuse_command_modifiers` above, which a row inside the `impl`
// cannot sit beside at column 0.
// CLOUD-2662's `validate_on_columns`, in the same `impl`.

// `Finding` lives in `findings` (CLOUD-2789), beside the `Check` and
// `Remediation` it carries, so the modules below `rules` can name a finding
// without reaching up here.
use crate::findings::Finding;

/// Whether a rule kind's predicate decides its question or approximates it
/// (CLOUD-331).
///
/// Not a severity and not a tier: those say how loud a finding is, this says
/// whether the finding is allowed to be a verdict at all. A kind can carry
/// `severity = "deny"` in config and still be unable to block, because the two
/// axes answer different questions and the stricter one wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decidability {
    /// The predicate IS the question, exact against its declared object. Only
    /// this may reach a blocking exit code.
    Deciding,
    /// The predicate estimates an open-ended question. Advisory only, and no
    /// flag promotes it — see [`decidability_of`].
    Approximating,
}

impl Decidability {
    /// Every value, so a census is derived rather than typed twice.
    pub const ALL: &'static [Decidability] = &[Decidability::Deciding, Decidability::Approximating];

    /// The stable token used in output and in `-J` (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Decidability::Deciding => "deciding",
            Decidability::Approximating => "approximating",
        }
    }

    /// Whether a finding from this class may reach a blocking exit code.
    #[must_use]
    pub const fn may_block(self) -> bool {
        matches!(self, Decidability::Deciding)
    }
}

/// The decidability of the row that owns `finding`, given the configured rules.
///
/// **An unresolvable owner is [`Decidability::Approximating`]**, which is the
/// fail-safe direction and the whole reason this is a function rather than a
/// field lookup: a finding whose row this run cannot name is one nothing has
/// classified, and an unclassified predicate must not be able to block. The
/// effect table takes the same reading of absence with `Effect::Ask`.
///
/// `attributed` is consulted because one kind's findings do not carry their own
/// row's id: a `policy` module reports the PREDICATE that fired, which is a
/// separate namespace from `Rule::id` (CLOUD-1083). Looking up only by
/// `finding.rule` would therefore classify every policy finding as
/// unresolvable, and this bound would silently switch off the whole kind.
#[must_use]
pub fn decidability_of(finding: &Finding, rules: &[Rule]) -> Decidability {
    // THE FINDING SAYS WHO OWNS IT (CLOUD-1087). This used to consult
    // `Scan::attributed`, keyed on the scope fingerprint — a value that means
    // "this finding's identity", not "this finding's row", and one a `command`
    // row can mint identically to a policy predicate's. Nothing is looked up
    // now, so nothing can collide.
    let owner = finding.owner.as_deref().unwrap_or(&finding.rule);
    rules
        .iter()
        .find(|rule| rule.id == owner)
        .map_or(Decidability::Deciding, |rule| rule.kind.decidability())
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
    /// Which declared class a FINGERPRINT was refused under (CLOUD-1120), for the
    /// findings that have one. Sparse, and written only by `policy`, for
    /// [`Scan::attributed`]'s reason: only there does the fact exist.
    ///
    /// **A finding that cannot name its own class cannot be admitted.** CLOUD-1050
    /// made the class a token so a gate could read it, and the tree path then
    /// dropped it on the way from [`crate::policy::Violation`] to [`Finding`] —
    /// so an issued, bound and spent admission had nothing to match against and
    /// the refusal stood. Carrying it here rather than on [`Finding`] is the same
    /// trade `attributed` already made: the fact belongs to one kind, and a field
    /// on the shared type would be `None` at thirty-eight construction sites that
    /// have no class to give.
    ///
    /// Keyed on the fingerprint for `attributed`'s reason too — a predicate id and
    /// a `Rule::id` are separate namespaces, so a map keyed by either could hand
    /// one finding's class to another. A fingerprint already names ONE finding.
    ///
    /// A lookup that MISSES means "no declared class", which is true of every
    /// native refusal and every consumer `[[rule]]` row; those are simply not
    /// admissible, because there is no token an admission could bind.
    pub classes: BTreeMap<String, String>,
    /// The rules a declared input-precondition held back, and which requirement
    /// went unmet (CLOUD-125). A subset of [`Scan::not_evaluated`]'s keys.
    ///
    /// A second map rather than a third [`NotObserved`] variant, and that is the
    /// same trade the note in [`run_recorded`] already made for the other
    /// direction: the STORE cannot tell "the precondition was unmet" from "this
    /// surface does not run the kind", because both mean the rule did not look
    /// and both must hold. What differs is only what a *reader* can be told, and
    /// widening a persisted enum to carry that would make CLOUD-78's
    /// no-implicit-upgrade rule pay for a distinction the store never reads.
    ///
    /// **Pointer-only** (rule 4): the value is the declared path itself — a
    /// requirement the author wrote in `batten.toml` — never anything read from
    /// the tree. A rule skipped for one of the engine's own reasons (wrong
    /// scope, no glob, `allow`, empty match set) is deliberately absent: it has
    /// no unmet requirement to name, and inventing one would report the engine's
    /// routing as if the config had asked for it.
    pub unmet: BTreeMap<String, String>,
    /// The rules whose evaluation errored, and the class of failure
    /// (CLOUD-126). A subset of [`Scan::not_evaluated`]'s keys, each carrying
    /// [`NotObserved::RuleErrored`] there.
    ///
    /// **The reason travels, and that is a considered divergence from
    /// CLOUD-126 §5**, which says to keep the id and a class token and never the
    /// message. §5's stated reason is that "the error's payload may carry file
    /// contents or command output" — true of a foreign payload, and not true of
    /// an error this crate constructs, because non-negotiable rule 4 binds every
    /// one of them to be a pointer already. `secrets.rs` is the case that
    /// settles it: its fail-closed cross-checks are deliberately plain internal
    /// errors carrying a rule id and a count, `secrets_kind.rs`'s `nowhere`
    /// helper is the standing gate that no byte of a secret reaches any channel,
    /// and four landed tests read the reason. Dropping it would leave an
    /// operator told only that a gate "errored" when the engine knows, and used
    /// to say, that a scanner and its own output disagreed.
    pub errored: BTreeMap<String, RuleFailure>,
    /// The rows a split `enforce` left to the OTHER half (step 13a): neither
    /// judged here nor withheld, so a baseline entry for one of them is the
    /// other half's to apply and never stale in this one. Empty on an unsplit run.
    pub other_half: BTreeSet<String>,
}

/// What a contained failure is reported as: its class, and the reason it gave.
///
/// The reason is the error's `Display`, never its `Debug` chain — the boundary
/// used to print the latter, which is anyhow's full context stack and is
/// deliberately not what a policy tool emits about a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuleFailure {
    /// Which kind of failure this was.
    pub class: ErrorClass,
    /// What the gate said went wrong, pointer-only by the construction of every
    /// error in this crate. Empty for a panic, whose payload is the runtime's
    /// rather than the engine's and is left to the panic hook.
    pub reason: String,
}

/// How an isolated rule failed (CLOUD-126).
///
/// Two classes, because only two failures are a *gate's* to contain — see
/// [`isolate`] for which are deliberately not, and why that boundary is the one
/// that keeps the exit contract whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// The rule returned a failure: an I/O error reading a file it selected, or
    /// anything else the boundary would otherwise map to exit `3`.
    Internal,
    /// The rule panicked. Its own class rather than folding into `Internal`,
    /// because the two say different things about the rule: one returned a
    /// failure it anticipated, the other did not return at all — and a panic is
    /// a Batten bug where an I/O error may be the operator's tree.
    Panic,
}

impl ErrorClass {
    /// Every class, so a census over them is derived rather than typed twice.
    pub const ALL: &'static [ErrorClass] = &[ErrorClass::Internal, ErrorClass::Panic];

    /// The stable token used in output and in `-J` (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Internal => "internal",
            ErrorClass::Panic => "panic",
        }
    }
}

/// What one rule's isolated evaluation produced (CLOUD-126).
#[derive(Debug)]
enum Isolated {
    /// The rule evaluated. Its findings are already in the scan.
    Evaluated,
    /// The rule did not look, for one of the engine's own reasons.
    NotEvaluated(NotObserved),
    /// The rule failed and was contained.
    Errored(RuleFailure),
    /// A **typed** failure that is not this rule's to contain, travelling on to
    /// the boundary that knows which code it is.
    Propagate(anyhow::Error),
}

/// Run `body` with a panic caught, and decide whether what came back is a gate
/// fault to contain or a typed answer to let through (CLOUD-126).
///
/// # What is contained, and what deliberately is not
///
/// Isolation is for a gate that **could not complete**. Two of the failures a
/// rule can return are not that, and containing them would break the exit
/// contract rather than harden it:
///
/// * a [`UsageError`] is a statement about the **configuration**, not about this
///   gate — it is the same answer for the whole run, and every sibling config
///   error in this tree is exit `1`. Reporting it as `3` would tell a caller
///   "Batten could not answer" about a file they can fix, and would silently
///   move a landed contract (`enforce`'s missing-binary refusal) from `1` to
///   `3`;
/// * a [`crate::refusal::Denial`] is a **verdict**. Containing it would downgrade
///   a decided refusal into an infrastructure complaint — the identical mistake
///   CLOUD-126's own precedence row exists to refuse, arriving one layer down.
///
/// So both travel on unchanged and the boundary maps them as it always has.
/// What is left — an I/O failure inside a rule body, or a panic — is exactly the
/// class the boundary would have mapped to `Internal` anyway, which is why
/// containing it changes which *gates run* without changing which code any
/// failure means.
///
/// # The panic hook is deliberately not replaced
///
/// A panic is a bug in Batten rather than a policy outcome, and its message is
/// diagnostic information an operator needs. Rule 4 governs what Batten emits
/// *about the repository*, and a panic payload is the runtime's own; what this
/// engine emits for a contained failure is still an id and a class token (see
/// [`Scan::errored`]). Swapping the hook per run would also be a process-global
/// mutation on a path that has none today.
fn isolate(body: impl FnOnce() -> anyhow::Result<Option<NotObserved>>) -> Isolated {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(None)) => Isolated::Evaluated,
        Ok(Ok(Some(why))) => Isolated::NotEvaluated(why),
        Ok(Err(failure)) => {
            if failure.downcast_ref::<UsageError>().is_some()
                || failure.downcast_ref::<crate::refusal::Denial>().is_some()
            {
                Isolated::Propagate(failure)
            } else {
                Isolated::Errored(RuleFailure {
                    class: ErrorClass::Internal,
                    reason: failure.to_string(),
                })
            }
        }
        Err(_) => Isolated::Errored(RuleFailure {
            class: ErrorClass::Panic,
            reason: String::new(),
        }),
    }
}

/// What one rule cost, as a pointer rather than a payload (non-negotiable rule 4).
///
/// A rule id, two counts and a duration. No path list and no scanned bytes — the
/// census answers *how much*, and the findings answer *where*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCost {
    /// The rule's id.
    pub rule: String,
    /// Wall clock for this rule's whole evaluation, including whatever it spawned.
    pub elapsed: std::time::Duration,
    /// Files this rule caused to be read.
    pub files_read: usize,
    /// Bytes those reads returned.
    pub bytes_read: usize,
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
    provisions: &[crate::config_model::Provision],
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
        RunOptions {
            half: None,
            keyed_bases: &[],
            checks: crate::policy::ModuleChecks::Run,
            scope: &Scope::Tree,
            // The tree verbs, so the surface their `Cost::Effect` facts are
            // classed for (CLOUD-1480).
            surface: crate::facts::Surface::Check,
            // No caller supplied one on this entry point, and `None` is the
            // honest answer rather than a clock read this module may not make.
            now: None,
        },
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
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    opts: RunOptions<'_>,
) -> anyhow::Result<Scan> {
    run_over(rules, provisions, vocabulary, root, opts, RunKind::Static)
}

/// [`run_all`] with the config-fault checks the caller is entitled to make.
///
/// # Errors
///
/// As [`run_all`]: a config fault at load, or a rule whose command fails to run.
pub fn run_all_over(
    rules: &[Rule],
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    opts: RunOptions<'_>,
) -> anyhow::Result<Scan> {
    run_over(rules, provisions, vocabulary, root, opts, RunKind::All)
}

/// What a caller asked a run to narrow (CLOUD-519).
///
/// Two orthogonal narrowings, grouped because they arrive together and travel
/// together: [`ModuleChecks`](crate::policy::ModuleChecks) narrows WHICH ROWS
/// run, [`Scope`] narrows WHICH FILES they are selected against. Passing them as
/// one value is also what keeps the runner's arity from growing per narrowing.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions<'a> {
    /// Which config-fault checks this caller is entitled to make.
    pub checks: crate::policy::ModuleChecks,
    /// Which files rules are selected against.
    pub scope: &'a Scope,
    /// WHICH SURFACE THIS RUN IS ON, for the `Cost::Effect` facts (CLOUD-1480).
    ///
    /// A third narrowing, and it rides here for the reason the header gives:
    /// grouping is what keeps the runner's arity from growing per narrowing, and
    /// adding this one as an eighth positional argument is what
    /// `clippy::too_many_arguments` refused.
    ///
    /// It is `facts::Surface` and never `RunKind`: that one is a DISPATCH enum —
    /// `check`, `baseline` and the mediated recorder all arrive as `Static` — so
    /// gating a fact on it disables the fact on surfaces its own `Class` admits.
    pub surface: crate::facts::Surface,
    /// The epoch second the BOUNDARY read, for the one freshness comparison a
    /// tree run makes: `[[rule.minted]]`'s `max_age_days` (CLOUD-1187).
    ///
    /// Supplied rather than read here, and that is the whole reason the field
    /// exists. `rules/policy-modules.md` states the principle for the
    /// two landed cases this joins — a waiver's expiry and a receipt's age:
    /// **the clock is the boundary's, never the decision's.** `rules.rs` holds
    /// the projection, so a `SystemTime::now` here would put a value that
    /// differs per invocation onto the input document, which is what
    /// `ambient_authority.rs`'s `the_evaluation_path_reads_no_wall_clock`
    /// refuses and what house style §6's byte-stable output cannot survive.
    ///
    /// **NOT [`crate::facts::Fact::Instant`], and the two must not be merged.**
    /// That one is the instant a CALLER names with `hook --instant` so a lease
    /// predicate is reproducible, and it is consumed at the boundary and reaches
    /// no module. This is the engine's own read-time clock for a fact it
    /// acquires. They differ in who supplies them and in what reads the answer.
    ///
    /// `None` is could-not-look — nobody handed one over — and is never
    /// defaulted to a clock read. [`minted_facts`] then judges against `0`,
    /// which makes every reading look ancient and so refuses rather than
    /// admits: the fail-closed direction for a bound whose job is to stop a
    /// stale answer being trusted.
    pub now: Option<u64>,
    /// Which half of a split `enforce` this run judges (step 13a), or `None`
    /// for every row — what `enforce` has always meant.
    ///
    /// Partitioned after the bundles load, because a policy row's half is read
    /// off its compiled modules. Under [`Half::Tree`] the backstop also nulls
    /// every live key of the tree document and skips acquiring the live
    /// families, so a misclassified row reads `null` rather than a moved world.
    pub half: Option<Half>,
    /// The refs a tree-half receipt keys the merge base of (`--keyed-base`), which
    /// is what admits a `ratchet` row to [`Half::Tree`].
    pub keyed_bases: &'a [String],
}

/// The one `input.tree` key no fact carries: the could-not-look causes of the
/// per-path facts the row itself declared. Under a tree-half row every declared
/// fact is tree, so its causes are too.
const TREE_MISSING_KEY: &str = "missing";

/// Which files a run selects rules against (CLOUD-519).
///
/// `check` re-reads the whole tree to judge the two files the caller just
/// touched, and a caller who already knows its change-set can say so. This is
/// that narrowing, and it is a narrowing of the **inputs only**: the verdict for
/// a file that IS scanned must be byte-identical to what an unnarrowed run would
/// have said about it, so this must never become a second answer to "which files
/// does a glob select". [`PathSet`] stays the only one.
///
/// **A ratchet is not narrowed**, and the reason is in [`run_rule`] where the
/// exemption is applied rather than restated here.
#[derive(Debug, Clone, Default)]
pub enum Scope {
    /// Every file the walk yields — what `check` has always meant.
    #[default]
    Tree,
    /// Only these repo-relative paths, as the caller's change-set named them.
    ///
    /// A path the walk does not yield is simply absent from the intersection: the
    /// change-set is a filter over the tree, never a source of paths, so a deleted
    /// or ignored file cannot enter a run through it.
    Changed(BTreeSet<String>),
}

impl Scope {
    /// `files` narrowed to this scope, or `files` itself when nothing narrowed it.
    ///
    /// Borrowing in the unnarrowed case is what keeps the ordinary run allocating
    /// nothing: the flag is absent on every invocation that does not pass it, and
    /// §4 asks a feature to be cheap when it is irrelevant.
    /// The change-set this scope narrows to, or `None` for the whole tree.
    fn changed(&self) -> Option<&BTreeSet<String>> {
        match self {
            Scope::Tree => None,
            Scope::Changed(changed) => Some(changed),
        }
    }

    fn apply<'a>(&self, files: &'a [String]) -> std::borrow::Cow<'a, [String]> {
        match self {
            Scope::Tree => std::borrow::Cow::Borrowed(files),
            Scope::Changed(changed) => std::borrow::Cow::Owned(
                files
                    .iter()
                    .filter(|path| changed.contains(*path))
                    .cloned()
                    .collect(),
            ),
        }
    }
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
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    opts: RunOptions<'_>,
    kind: RunKind,
) -> anyhow::Result<Scan> {
    match kind {
        RunKind::Static => run_static_inner(rules, provisions, vocabulary, root, opts),
        RunKind::All => run_all_inner(rules, provisions, vocabulary, root, opts),
    }
}

fn run_static_inner(
    rules: &[Rule],
    _provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    opts: RunOptions<'_>,
) -> anyhow::Result<Scan> {
    // Only `checks` is read here; `scope`, `now` and `surface` travel on to
    // `run` inside the bag rather than being unpacked and re-passed.
    let RunOptions { checks, .. } = opts;
    // POLICY BUNDLES ARE LOADED HERE, on the read surface, and that is
    // CLOUD-833's substantive claim rather than a formality. `run_static` backs
    // `check` and refuses any kind that `carries_ambient_authority` — a
    // `command` row spawns a process with the calling user's authority, which is
    // why it is confined to `enforce`. A policy module is `Authority::Supplied`:
    // a pure function over an input document that cannot open a file, start a
    // process or reach the network, a property CLOUD-831 gates rather than
    // asserts. So admitting it here makes `check` MORE capable without making it
    // less honest, and the spawning refusal below is untouched.
    // Refuse before any work: the read-only surface must not even begin a run
    // it cannot complete honestly. BEFORE THE BUNDLES LOAD, too (#1276): loading
    // first let an unreadable module's usage error answer for a config whose
    // real refusal is the spawning kind, and which of the two a caller saw
    // turned on what the loader could resolve.
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
                    crate::error::Native::SpawningRuleOnReadVerb,
                    &[crate::verdict::Subject::Artifact {
                        artifact: rule.kind.as_str().to_owned(),
                    }],
                    Fix::Run(SPAWNING_VERB.to_owned()),
                )
                .render_finding(crate::refusal::Arm::Full),
            ));
        }
    }
    let bundles = crate::policy::load(root, rules, vocabulary, checks, None)?;
    run(rules, &[], root, &bundles, vocabulary, opts)
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
/// **Whether anything here spawns is the CALLER's answer, not this function's**
/// (CLOUD-1480), and stating it as the function's was this paragraph's defect
/// twice over.
///
/// The withheld rules are partitioned out *before* [`run`] sees them, which an
/// earlier revision called "a property of the argument list rather than a
/// promise" — true of every spawning KIND and false of the two `Cost::Effect`
/// FACTS, which no partition over [`RuleKind`] can reach. `symbols` spawned
/// `cargo clippy` from this surface for as long as that sentence stood.
///
/// The replacement then claimed "the property holds on both halves", which is
/// true only of the mediated caller. `surface` decides it: `Surface::Hook` bars
/// both facts and nothing spawns, while the `state record` VERB passes
/// `Surface::Check` — the surface those facts are classed for — and still
/// resolves `symbols`, spawning the analyser before its store write. That is
/// correct rather than an oversight: a verb a human ran is entitled to the
/// census, and a per-call budget is what the hook has and the verb does not.
///
/// So the honest sentence is the conditional one. Read `surface` at the call
/// site to know which answer applies; do not read a promise here.
///
/// The partition asks [`RuleKind::carries_ambient_authority`] — the same
/// question [`run_static`] refuses on, deliberately the identical call rather
/// than a second predicate, so the two surfaces can disagree about what to DO
/// with such a kind and never about which kinds they are.
///
/// # Errors
///
/// As [`run`]: a [`UsageError`] (→ exit `1`) for a malformed rule, and an I/O
/// failure while walking the tree as an internal error (→ exit `3`).
pub fn run_recorded(
    rules: &[Rule],
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    // WHICH CONFIG-FAULT CHECKS THIS CALLER IS ENTITLED TO (CLOUD-1480). The
    // `state record` VERB reports config faults and passes `Run`; the mediated
    // Stop path does not — it is the caller `SkipOnHotPath` was written for, in
    // that variant's own words: "the caller is the mediated path, where the
    // answer is already known and the budget is per call". Hardcoding `Run` here
    // made the end-of-turn boundary re-derive every module's smoke query.
    checks: crate::policy::ModuleChecks,
    // AND WHICH SURFACE IT RUNS ON, for the `Cost::Effect` facts (CLOUD-1480).
    // The verb is a tree verb and passes `Surface::Check`; the mediated
    // recorder passes `Surface::Hook`, which is what bars a fact classed
    // `Surface::Check` from resolving there — `admits` is one-directional and
    // that direction is the whole point.
    surface: crate::facts::Surface,
) -> anyhow::Result<Scan> {
    let (evaluable, withheld): (Vec<&Rule>, Vec<&Rule>) = rules
        .iter()
        .partition(|rule| !rule.kind.carries_ambient_authority());
    let evaluable: Vec<Rule> = evaluable.into_iter().cloned().collect();
    let bundles = crate::policy::load(root, &evaluable, vocabulary, checks, None)?;
    let mut scan = run(
        &evaluable,
        provisions,
        root,
        &bundles,
        vocabulary,
        RunOptions {
            half: None,
            keyed_bases: &[],
            checks,
            scope: &Scope::Tree,
            // The caller's surface: `Surface::Check` for the `state record`
            // verb, `Surface::Hook` for the mediated recorder (CLOUD-1480).
            surface,
            // This caller supplies none, and `None` is the honest answer rather
            // than a clock read this module may not make.
            now: None,
        },
    )?;
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
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
) -> anyhow::Result<Scan> {
    run_over(
        rules,
        provisions,
        vocabulary,
        root,
        RunOptions {
            half: None,
            keyed_bases: &[],
            checks: crate::policy::ModuleChecks::Run,
            scope: &Scope::Tree,
            // The tree verbs, so the surface their `Cost::Effect` facts are
            // classed for (CLOUD-1480).
            surface: crate::facts::Surface::Check,
            // No caller supplied one on this entry point, and `None` is the
            // honest answer rather than a clock read this module may not make.
            now: None,
        },
        RunKind::All,
    )
}

fn run_all_inner(
    rules: &[Rule],
    provisions: &[crate::config_model::Provision],
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    opts: RunOptions<'_>,
) -> anyhow::Result<Scan> {
    // Only `checks` is read here; `scope`, `now` and `surface` travel on to
    // `run` inside the bag rather than being unpacked and re-passed.
    let RunOptions { checks, .. } = opts;
    // Refuse before any work, the shape `run_static` above already uses: the
    // alternative is running the check side, exiting on its verdict, and having
    // silently ignored a repair the config declared. A key that parses and does
    // nothing is indistinguishable from one the engine honoured.
    // NARROWED TO THE TREE PATH, NOT LIFTED (CLOUD-1639). The refusal stands for
    // every kind this function actually runs: `run_all` walks the TREE, and a
    // `fix` on a `command` row is still a repair nothing here executes, so
    // honouring the key silently would be the same false green.
    //
    // What changed is that `fix` is no longer `command`-only. The mediated kinds
    // may now carry one, and theirs is executed at the boundary rather than here
    // — `crate::hook` is where that happens, under the class's `applicability`.
    // Refusing those rows here would refuse a `batten check` run over a config
    // whose repairs are perfectly reachable from the hook, which is a tree-side
    // gate deciding a boundary-side question.
    for rule in rules {
        if rule.fix.is_some() && !rule.kind.repairs_at_the_boundary() {
            return Err(UsageError::raise(format!(
                "rule {}: `fix` declares a repair, and serialised fix execution is not a \
                 capability this build has; remove the key or run the repair yourself",
                rule.id
            )));
        }
    }
    let bundles = crate::policy::load(root, rules, vocabulary, checks, None)?;
    let Some(half) = opts.half else {
        return run(rules, provisions, root, &bundles, vocabulary, opts);
    };
    let (kept, bundles) = partition_half(rules, bundles, half, opts.keyed_bases, checks)?;
    let mut scan = run(&kept, provisions, root, &bundles, vocabulary, opts)?;
    scan.other_half = rules
        .iter()
        .filter(|rule| !kept.iter().any(|judged| judged.id == rule.id))
        .map(|rule| rule.id.clone())
        .collect();
    Ok(scan)
}

/// The rows of `rules` that `half` judges, and the bundles they own (step 13a).
///
/// After [`crate::policy::load`], because a policy row's half is read off its
/// compiled modules. A row the caller SELECTED by `--rule` that belongs to the
/// other half is refused rather than dropped: a narrowed run that silently
/// judged nothing would report a pass from a gate that never ran, which is
/// exactly what `--rule`'s own unknown-id refusal exists to prevent.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the first selected row of the other half.
pub fn partition_half(
    rules: &[Rule],
    bundles: Vec<crate::policy::Bundle>,
    half: Half,
    keyed_bases: &[String],
    checks: crate::policy::ModuleChecks,
) -> anyhow::Result<(Vec<Rule>, Vec<crate::policy::Bundle>)> {
    let (kept, other): (Vec<&Rule>, Vec<&Rule>) = rules.iter().partition(|rule| {
        let bundle = bundles.iter().find(|bundle| bundle.id() == rule.id);
        rule.half(bundle, keyed_bases) == half
    });
    if checks == crate::policy::ModuleChecks::RunOverSelection
        && let Some(rule) = other.first()
    {
        return Err(UsageError::raise(format!(
            "rule `{}` is judged by the other half of a split `enforce`, not `--half {}`; \
             select it under `--half {}`, or drop `--half`",
            rule.id,
            half.as_str(),
            match half {
                Half::Tree => Half::Live.as_str(),
                Half::Live => Half::Tree.as_str(),
            }
        )));
    }
    let kept: Vec<Rule> = kept.into_iter().cloned().collect();
    let bundles = bundles
        .into_iter()
        .filter(|bundle| kept.iter().any(|rule| rule.id == bundle.id()))
        .collect();
    Ok((kept, bundles))
}

/// The tree half's backstop (step 13a): `document` with every live key of
/// `input.tree` set to `null`.
///
/// [`Rule::half`] is what keeps a live read out of the tree half; this is what
/// keeps a misclassification from reaching a module as a moved world. `null` is
/// could-not-look on every tree key, so a module reading one stays silent
/// rather than judging state the receipt does not key. A key no fact carries,
/// bar `missing`, is nulled too — unknown is live. A document that will not
/// parse is returned unchanged, since the engine refuses it as before.
#[must_use]
/// Whether the tree half may read `fact`: a tree fact, or out-of-tree state
/// whose exact bytes [`crate::step::tree_inputs_digest`] folds into the half's
/// key, so a receipt over it is a hit only on identical state (CLOUD-2329).
/// The recorder stores are the second kind: [`crate::recorder::recorded_for_digest`]
/// digests precisely what [`crate::recorder::recorded_stores`] hands the run.
pub(crate) fn keyable_in_tree_half(fact: crate::facts::Fact) -> bool {
    fact.subject() == crate::facts::Subject::Tree
        || matches!(
            fact,
            crate::facts::Fact::Records | crate::facts::Fact::RecordsBlocked
        )
}

pub fn null_live_keys(document: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(document) else {
        return document.to_owned();
    };
    if let Some(tree) = value
        .get_mut("tree")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (key, slot) in tree.iter_mut() {
            // `base-delta` is kept: only rows whose `base` is a keyed base reach
            // the tree half (`Rule::half`), so the delta here is over one.
            let tree_fact = key == TREE_MISSING_KEY
                || crate::facts::Fact::from_tree_key(key).is_some_and(|fact| {
                    keyable_in_tree_half(fact) || fact == crate::facts::Fact::BaseDelta
                });
            if !tree_fact {
                *slot = serde_json::Value::Null;
            }
        }
    }
    serde_json::to_string(&value).unwrap_or_else(|_| document.to_owned())
}

/// How many threads evaluate a surface's due rules: one on the hook, which
/// `rules/rust.md` holds to a single thread, else every core.
fn workers_for(surface: crate::facts::Surface) -> usize {
    if surface == crate::facts::Surface::Hook {
        1
    } else {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }
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
    provisions: &[crate::config_model::Provision],
    root: &Path,
    bundles: &[crate::policy::Bundle],
    // The declared recorders, so their records can be projected (CLOUD-1051).
    // Config rather than a per-rule column: the fact is what THIS REPOSITORY's
    // recorders accumulated, so a second declaration on the rule would be a
    // second home for one answer.
    vocabulary: crate::policy::Vocabulary<'_>,
    // Which files rules are SELECTED against (CLOUD-519), the boundary's
    // instant, and the surface — the three narrowings, as the one bag whose
    // whole purpose is that arity does not grow per narrowing.
    opts: RunOptions<'_>,
) -> anyhow::Result<Scan> {
    // WHY THE SURFACE IS HERE AT ALL (CLOUD-1480). `run_static` refuses a
    // spawning KIND before any work, and that read as the whole of §5's
    // read-only promise — but a `Cost::Effect` FACT is not a kind, so
    // `symbols_fact` and `review_fact` below were guarded by DECLARATION alone
    // and spawned on the mediated boundary. Measured: the mediated verb on a
    // Stop payload exec'd `cargo clippy`.
    let RunOptions {
        checks: _,
        scope,
        surface,
        now,
        half,
        keyed_bases: _,
    } = opts;
    // The tree half's backstop (step 13a): the families no tree row declares are
    // not acquired at all, and `null_live_keys` nulls what remains.
    let tree_half = half == Some(Half::Tree);
    let recorders = vocabulary.recorders;
    let files = tree_files(root)?;
    // The narrowed selection, computed once beside the walk. Every acquisition
    // below still reads the FULL set: a document a rule declares, a derived fact
    // and the symbol census are all properties of the repository rather than of
    // the caller's change-set, and narrowing them would change what a scanned
    // file's verdict says instead of which files are scanned.
    let scoped = scope.apply(&files);
    // Resolved ONCE for the whole run, before any rule is evaluated (CLOUD-773).
    // That is the entire point: the shell layer this replaces re-derives because
    // a producer's value cannot cross the boundary, so it pays the extraction
    // per consumer. Here the producer pays once and every reader reads.
    let derived = resolve_derived(rules, root, &files);
    // Resolved ONCE for the whole run, beside the two above and for the same
    // reason (CLOUD-850), and measured onto its own census row. Extracted rather
    // than inline only because it put `run` over `too_many_lines`; the reasoning
    // it carries is the callee's own.
    let documents = acquire_declared_measured(rules, root, &files, &scoped)?;

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
    let produced = if !tree_half && crate::sink::any_declared(declared_sinks(rules)) {
        match crate::git::git_dir(root) {
            Err(_) => BTreeMap::new(),
            Ok(git_dir) => {
                // The branch is a second read, so it is resolved only when a sink is
                // keyed by one — the economy `receipt::verdicts` already states.
                let branch = if crate::sink::any_branch_keyed(declared_sinks(rules)) {
                    crate::git::current_branch(root).ok().flatten()
                } else {
                    None
                };
                crate::sink::store(
                    &git_dir,
                    &crate::sink::declared_records(declared_sinks(rules), branch.as_deref()),
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
    let git = git_facts_within(rules, root, scope.changed());
    // The one acquisition of the `Cost::Effect` fact (CLOUD-760), beside the git
    // family and for the same reason: a projection must not spawn, so the spend
    // happens once here and only when a row declared it.
    let (symbols, review) = effect_facts(rules, root, surface);
    // THE OUT-OF-ROOT FILES (CLOUD-1167), acquired once for the whole run beside
    // the families above and, like every one of them, ONLY FOR WHAT A ROW
    // DECLARED. A ruleset naming no `[[rule.external]]` reads no environment
    // variable and opens no file, which is what keeps this `Cost::Read` honest
    // and what makes the family a projection rather than a scanner.
    //
    // It shares `READ_BUDGET` with the document family rather than carrying its
    // own: both are "declared files this run may open", and two budgets over one
    // resource is two numbers that can disagree.
    let external = external_facts(rules, READ_BUDGET);
    // THE ENGINE'S OWN FINDING STORE (CLOUD-1203 unit B), per declared ref and
    // guarded on the declaration for `produced`'s reason: resolving the store
    // locates the git dir and reads every record file, which a run whose rows ask
    // for none must not pay for.
    //
    // `None` covers BOTH could-not-look conditions — nobody declared a ref, and
    // no store is bound to this checkout — and the projection writes `null` for
    // it. An empty MAP would be a third claim ("the store was read and holds
    // nothing"), which is exactly what a gate over unlanded work must not infer
    // from a store that was never opened.
    let declared_state: Vec<String> = {
        let mut refs: BTreeSet<String> = BTreeSet::new();
        for rule in rules {
            refs.extend(rule.state.iter().cloned());
        }
        refs.into_iter().collect()
    };
    // THE FORGE RECORDS (CLOUD-1154) — see `forge_facts`, extracted because
    // `run` is at its line ceiling and the fact model keeps growing families.
    let forge = forge_facts(rules, root);
    // THE TOOL VERDICTS (CLOUD-1171) — `forge_facts`' mechanism with a different
    // key, extracted for the same reason.
    let tool_verdicts = tool_facts(rules, root);
    let plan = plan_facts(rules, root);
    let minted = minted_facts(rules, root, now);
    // THE CAPTURED REDUCTIONS (CLOUD-1188) — guarded on the declaration for
    // `forge_facts`' reason, and here the guard matters more: resolving this
    // reads and parses every response in the store, so a run whose rows ask for
    // none must not pay for one.
    let captured = captured_facts(rules, root);
    let state = if tree_half || declared_state.is_empty() {
        None
    } else {
        crate::store::resolve(root)
            .ok()
            .and_then(|opened| crate::store::bound_dir(&opened))
            .and_then(|dir| crate::findings::load_all(&dir).ok())
            .map(|records| crate::findings::pointer_lines_for(&records, &declared_state))
    };

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
    // VERB-WRITTEN STORES ARE READ UNCONDITIONALLY, which is why the guard above
    // is no longer the whole answer (CLOUD-472). A `[[recorder]]` store exists
    // because config declared one, so a repository declaring none has nothing to
    // read. `crate::config_check::record::VERB_WRITTEN` is different in kind: the ENGINE owns
    // both the writer and the reader, so there is no declaration for a consumer
    // to forget and no config to make the gate conditional on. Reading them only
    // when some unrelated recorder happened to be declared would make a gate's
    // liveness depend on a table it has nothing to do with.
    // `record_key`, not `current_branch`: the key the producers wrote under, which
    // on a detached HEAD (every CI checkout) is the commit rather than nothing.
    let (records, records_blocked) =
        crate::recorder::recorded_stores(root, recorders, vocabulary.records);

    // The union the engine DECIDES against, built once for the run (CLOUD-1220).
    // `registry_for` is the one authority on it, and a vendored class replaces a
    // consumer row of the same token, so resolving a module's token against
    // anything narrower would answer for half the classes a module may raise.
    let registry = crate::policy::registry_for(vocabulary.verdicts)?;
    let tables = RunTables::new(vocabulary, root, &files)?;

    let inputs = RunInputs {
        provisions,
        files: &files,
        scoped: &scoped,
        derived: &derived,
        documents: &documents,
        external: &external,
        produced: &produced,
        records: &records,
        records_blocked: &records_blocked,
        git: &git,
        surface,
        symbols: &symbols,
        review: &review,
        state: state.as_ref(),
        forge: forge.as_ref(),
        tool_verdicts: tool_verdicts.as_ref(),
        plan: plan.as_ref(),
        minted: minted.as_ref(),
        captured: captured.as_ref(),
        bundles,
        verdicts: &registry,
        tables: &tables,
        half,
    };

    let mut scan = Scan::default();
    evaluate_rules(rules, root, &inputs, &mut scan)?;
    // BEFORE the sort, deliberately (CLOUD-396): the sort is what makes the
    // output byte-stable, so a dedup running after it would be reading an order
    // it also has to preserve, and "which duplicate survived" would become a
    // property of the comparator. Run first and the survivor is the one the
    // engine emitted first — a function of the walk, which is already sorted.
    dedup_scoped(&mut scan.findings);
    // Sort by the pointer tuple so identical input yields identical output.
    // `order_key` carries why the key is the five fields it is.
    scan.findings
        .sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    scan.requested = requested_sinks(rules, &scan);
    Ok(scan)
}

/// The declared fact this run could not resolve for `rule`, if any (CLOUD-1480).
///
/// DECLARED is the whole predicate. A run resolves the `Cost::Effect` facts only
/// when a row asks for one, so a rule that asked for nothing can never be
/// withheld here — the answer is `None` for every row that does not carry the
/// column, which is what keeps this additive.
///
/// Returns the COLUMN NAME rather than a sentence: it lands in `Scan::unmet`
/// beside the input-precondition's missing path, and both are read as pointers
/// (rule 4). A reader gets "this rule asked for `symbols` and the run had none",
/// which names the remedy without describing the tree.
///
/// `Look::IsNot` is deliberately NOT withheld. That arm means the question was
/// asked and the answer is no — a real census with no sites — and a rule is
/// entitled to decide on it. Only `CouldNotLook` is the could-not-ask.
fn unresolved_declared_fact(
    rule: &Rule,
    inputs: &RunInputs<'_>,
    surface: crate::facts::Surface,
) -> Option<&'static str> {
    // THE MEDIATED SURFACE ONLY, and scoping it was the correction (CLOUD-1480).
    //
    // Unscoped, this withheld on `check` and `enforce` too — and there
    // could-not-look means the ANALYSER is unreachable, or the tree does not
    // compile, which is precisely when `spawn-adapters`' `symbol count absent`
    // verdict is written to refuse. Skipping instead of denying makes breaking
    // the build switch the gate off: a fail-open EXIT-CODE FLIP on the
    // enforcement surface, which is strictly worse than the spurious deny this
    // clause was added to stop.
    //
    // On the hook the same arm is honest, because there the fact is barred by
    // the SURFACE rather than missing from the environment — nobody looked, so
    // no verdict about the tree is available to give.
    if !matches!(surface, crate::facts::Surface::Hook) {
        return None;
    }
    if rule.symbols && matches!(inputs.symbols, crate::facts::Look::CouldNotLook) {
        return Some("symbols");
    }
    if !rule.review.is_empty() && matches!(inputs.review, crate::facts::Look::CouldNotLook) {
        return Some("review");
    }
    None
}

/// Evaluate every rule into `scan`, each one contained (CLOUD-126) and each one
/// gated on its declared inputs first (CLOUD-125).
///
/// Split out of [`run`] because that function is at clippy's line ceiling and
/// this is the half with its own reason to be read: `run` resolves the facts a
/// run shares, and this decides what each rule then did with them.
fn evaluate_rules(
    rules: &[Rule],
    root: &Path,
    inputs: &RunInputs<'_>,
    scan: &mut Scan,
) -> anyhow::Result<()> {
    let mut due: Vec<&Rule> = Vec::new();
    for rule in rules {
        // A COPY BEHIND ITS PRESET (CLOUD-2290), on the tree verbs only and for
        // every scope: an ejected module usually decides the mediated call, which
        // `check` never evaluates, so this cannot wait for the row to run.
        if rule.kind == RuleKind::Policy && inputs.surface != crate::facts::Surface::Hook {
            ejected_behind(rule, root, inputs.verdicts, &mut scan.findings);
        }
        // THE DECLARED INPUT-PRECONDITION, BEFORE THE BODY (CLOUD-125). Here
        // rather than inside `run_rule` for the reason the row's acceptance
        // states as a clause: "the precondition never invokes the check body".
        // Deciding it at the call site makes that structural — the body is not
        // entered because the call is not made — where a guard on the first line
        // of `run_rule` would make it a property of that function's ordering,
        // which the next kind added below it could quietly break.
        //
        // `validate` is NOT re-run before this. Every path into `run` comes from
        // a loaded config, and `config::parse_ungated` already put the whole
        // table through `rules::validate`, so a malformed row cannot reach here
        // to be skipped instead of refused. `run_rule`'s own `validate` call
        // stays where it is; re-running it here would recompile every row's
        // regexes a second time per run to re-refuse what cannot arrive.
        if let Some(missing) = rule.unmet_requirement(root) {
            scan.not_evaluated
                .insert(rule.id.clone(), NotObserved::RuleSkipped);
            scan.unmet.insert(rule.id.clone(), missing.to_owned());
            continue;
        }
        // THE DECLARED FACT-PRECONDITION, beside the input one above and for its
        // reason (CLOUD-1480). A rule that DECLARED a fact the run could not
        // resolve has not been given what it asked for, and evaluating it anyway
        // hands the module a `null` it cannot tell from a measured answer.
        //
        // WHY THIS IS NOT OPTIONAL, measured on this branch. Barring the two
        // `Cost::Effect` facts from the mediated surface left
        // `input.tree.symbols` null while `spawn-adapters.rego` — a `policy` row,
        // so still evaluable on the recorder's partition — refuses on exactly
        // that shape (`no_census if not input.tree.symbols.sites`). Every end of
        // turn therefore wrote a spurious `symbol count absent` deny into the
        // state store: a gate reporting on a census nobody took. Trading a slow
        // hook for a hook that records false findings is the worse half of the
        // trade, and it was caught by review rather than by me.
        //
        // WITHHELD RATHER THAN PASSED, which is the whole point and the direction
        // `Scan::not_evaluated` exists to keep honest. A withheld rule's silence
        // is not evidence of a clean tree, so its findings HOLD; passing it would
        // be CLOUD-251's vacuous pass in the one place a reader would never look.
        // `.claude/rules/policy-modules.md` already states the engine half of
        // this for a module that cannot look: "the engine reports `RuleSkipped`
        // for it rather than a clean tree".
        //
        // It also repairs a case that predates this branch: `symbols_fact`
        // answers could-not-look wherever the analyser is absent, so every
        // checkout without the delegated toolchain was taking that same spurious
        // deny — a verdict about the OPERATOR wearing a verdict about the tree.
        if let Some(fact) = unresolved_declared_fact(rule, inputs, inputs.surface) {
            scan.not_evaluated
                .insert(rule.id.clone(), NotObserved::RuleSkipped);
            scan.unmet.insert(rule.id.clone(), fact.to_owned());
            continue;
        }
        // FAIL-CLOSED ISOLATION (CLOUD-126). This loop used to carry a `?`, so
        // one rule's I/O error propagated out of the whole scan: no findings at
        // all were emitted and no later rule ran, over a failure in one row.
        // Containing it here means the other gates still evaluate and still
        // report, and the failure becomes a value in the fold rather than an
        // unwind — which is what lets `Violation` outrank `Internal` at all,
        // since an unwound run has no violation left to outrank with.
        //
        // The scan's three mutable maps are destructured inside the block so
        // their borrows end before `not_evaluated` is written below.
        // THE CENSUS IS TAKEN AROUND THE DISPATCH, not inside each kind
        // (CLOUD-1217). One site sees every rule, so a kind added later is
        // measured without anyone remembering to instrument it — the inverse of
        // the state this row found, where nothing reported and the largest item
        // in CI was a silent span.
        //
        // Deltas over this THREAD's read counters ([`thread_reads`]) rather
        // than an accumulator threaded through nine read sites: rules run side
        // by side off the hook surface (#1276), so the process-global counters
        // interleave and only a thread's own count is one rule's.
        //
        // AROUND `isolate` RATHER THAN AROUND `run_rule`, which is where the
        // precondition skip above puts it: a rule held back by an unmet
        // requirement never enters the body, so it has no cost to report and a
        // zero row for it would read as "evaluated, and free".
        due.push(rule);
    }
    // EVERY DUE RULE IS EVALUATED, THEN FOLDED IN DECLARATION ORDER (#1276).
    // The loop above stays serial: it is cheap and writes the scan in order.
    // Evaluation runs on `workers` threads off the tree verbs — measured on
    // #1276, `enforce --half live` spent ~200 s on one core of four, every
    // rule reading shared, read-only inputs and writing only its own findings
    // and classes. Each rule fills its own buffers and they are folded in the
    // order the table declares, so the output is byte-for-byte what the serial
    // loop produced (§6). The hook surface stays on one thread: `rules/rust.md`
    // holds `batten hook` to at most one runtime and never a multi-thread one.
    let workers = workers_for(inputs.surface);
    let evaluated = evaluate_due(&due, root, inputs, workers);
    for (rule, done) in due.iter().zip(evaluated) {
        scan.findings.extend(done.findings);
        scan.classes.extend(done.classes);
        costs_lock().push(done.cost);
        match done.outcome {
            Isolated::Evaluated => {}
            Isolated::NotEvaluated(why) => {
                scan.not_evaluated.insert(rule.id.clone(), why);
            }
            // A typed answer the boundary owns — see `isolate` for why these two
            // are not a gate's to contain. The first in declaration order wins,
            // as it did when the loop stopped there.
            Isolated::Propagate(failure) => return Err(failure),
            Isolated::Errored(failure) => {
                // Both maps, and both are load-bearing: `not_evaluated` is what
                // keeps the store fail-closed, so an errored rule HOLDS its
                // findings exactly as a skipped one does — its silence is not
                // evidence either. `errored` is what a reader is told.
                scan.not_evaluated
                    .insert(rule.id.clone(), NotObserved::RuleErrored);
                scan.errored.insert(rule.id.clone(), failure);
            }
        }
    }
    Ok(())
}

/// One rule's evaluation, held until it is folded in declaration order.
struct Evaluated {
    findings: Vec<Finding>,
    classes: BTreeMap<String, String>,
    outcome: Isolated,
    cost: RuleCost,
}

/// Evaluate each of `due` on up to `workers` scoped threads, answering in
/// `due`'s order. A worker takes the next index until none is left, so a slow
/// rule holds one thread and the rest drain past it.
///
/// THE CENSUS IS TAKEN AROUND THE DISPATCH, not inside each kind (CLOUD-1217),
/// and its read counts are THIS THREAD'S ([`thread_reads`]): the process-wide
/// counters interleave once rules run side by side.
fn evaluate_due(
    due: &[&Rule],
    root: &Path,
    inputs: &RunInputs<'_>,
    workers: usize,
) -> Vec<Evaluated> {
    let one = |rule: &Rule| {
        let started = std::time::Instant::now();
        let (files_before, bytes_before) = thread_reads();
        let mut findings = Vec::new();
        let mut classes = BTreeMap::new();
        let outcome = isolate(|| run_rule(rule, root, inputs, &mut findings, &mut classes));
        let (files_after, bytes_after) = thread_reads();
        Evaluated {
            findings,
            classes,
            outcome,
            cost: RuleCost {
                rule: rule.id.clone(),
                elapsed: started.elapsed(),
                files_read: files_after.saturating_sub(files_before),
                bytes_read: bytes_after.saturating_sub(bytes_before),
            },
        }
    };
    let workers = workers.clamp(1, due.len().max(1));
    if workers == 1 {
        return due.iter().map(|rule| one(rule)).collect();
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<Evaluated>>> = due.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let at = next.fetch_add(1, Ordering::Relaxed);
                    let Some(rule) = due.get(at) else {
                        break;
                    };
                    let done = one(rule);
                    if let Some(slot) = slots.get(at) {
                        *slot
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(done);
                    }
                }
            });
        }
    });
    slots
        .into_iter()
        .zip(due)
        .map(|(slot, rule)| {
            slot.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unwrap_or_else(|| Evaluated {
                    findings: Vec::new(),
                    classes: BTreeMap::new(),
                    outcome: Isolated::Errored(RuleFailure {
                        class: ErrorClass::Panic,
                        reason: String::new(),
                    }),
                    cost: RuleCost {
                        rule: rule.id.clone(),
                        elapsed: std::time::Duration::ZERO,
                        files_read: 0,
                        bytes_read: 0,
                    },
                })
        })
        .collect()
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
    // KEYED ON THE FINGERPRINT, NOT THE PREDICATE ID (CLOUD-1083, found on
    // review of #721). A predicate id and a `Rule::id` are separate namespaces
    // and nothing checks one against the other, so a module may declare a
    // predicate whose id is also a row's. A map keyed by that id could not tell
    // the two apart, and would hand one row's findings to the other — the same
    // misattribution this issue is about, pointing the other way. A fingerprint
    // already names ONE finding, so the lookup is exact and the collision is
    // inexpressible rather than something a later reader has to refuse.
    let mut requested: Vec<crate::sink::Requested> = rules
        .iter()
        .filter(|rule| !scan.not_evaluated.contains_key(&rule.id))
        .filter_map(|rule| {
            let sink = rule.produces.as_ref()?;
            let mut subject = String::new();
            let mut count = 0usize;
            // THE CONTAINING ROW, NOT THE PREDICATE (CLOUD-1083, by the field
            // since CLOUD-1087). `f.rule` is the predicate a reader saw, and for
            // every kind but `policy` the two are the same string — which is why
            // a filter on `f.rule` looked right and was silently empty for the
            // one kind where they differ.
            //
            // The finding now SAYS whose it is instead of being looked up in a
            // map keyed on its fingerprint. `None` means the rule id is the
            // owner, true for every kind that never needed the map.
            for finding in scan
                .findings
                .iter()
                .filter(|f| f.owner.as_deref().unwrap_or(&f.rule) == rule.id)
            {
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
                    crate::digest::sha256_hex(subject.as_bytes())
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
/// The total order [`run`] sorts findings by, at module scope because it is a
/// definition rather than a step: declared inside the function it would sit
/// after statements, and `run` is already at its line budget.
///
/// THE KEY IS TOTAL, AND THE THREE-FIELD VERSION WAS NOT. `sort_by` is stable,
/// so any two findings the comparator called equal kept the order they were
/// PUSHED in — which made byte-stability (house style §6, the property the sort
/// exists to establish) rest on emission order rather than on the comparator.
///
/// THE EQUAL CASE IS REACHABLE, not theoretical: a `policy` rule's
/// [`Finding::rule`] is the PREDICATE id and [`Finding::owner`] the row id, so
/// two predicates of one bundle reporting the same line agree on all three
/// fields the old key read and differ only in fields it did not.
///
/// `owner` and `identity` close it. [`crate::identity::StoredIdentity`] already
/// derives `Ord` — it keys the `BTreeSet` in [`dedup_scoped`] — and is unique
/// per finding by construction, so the order is a function of the SET rather
/// than of the walk that produced it.
fn order_key(
    finding: &Finding,
) -> (
    &str,
    Option<usize>,
    &str,
    &Option<String>,
    &crate::identity::StoredIdentity,
) {
    (
        finding.path.as_str(),
        finding.line,
        finding.rule.as_str(),
        &finding.owner,
        &finding.identity,
    )
}

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
/// What a run resolves ONCE, before any rule evaluates, and every rule then
/// reads: the tree walk, the derived facts, and the acquired documents, plus
/// the provisions and bundles the config carries. Grouped rather than passed
/// one by one because it is exactly the set `run` hoists above its loop, and
/// because it grows by a field every time an acquisition row lands.
struct RunInputs<'a> {
    /// Which half of a split `enforce` this run judges (step 13a); under
    /// [`Half::Tree`] the tree document passes through [`null_live_keys`].
    half: Option<Half>,
    provisions: &'a [crate::config_model::Provision],
    files: &'a [String],
    /// The file set a rule is SELECTED against, which is `files` narrowed by the
    /// caller's declared change-set (CLOUD-519), and `files` itself when no flag
    /// narrowed it.
    ///
    /// A second list rather than a narrowed `files`, because one kind must not
    /// see the narrowing — see [`Scope`].
    scoped: &'a [String],
    derived: &'a BTreeMap<String, crate::facts::Look<String>>,
    documents: &'a BTreeMap<(String, Wanted), Acquired>,
    /// What earlier runs produced, for the keys this rule set declares
    /// (CLOUD-851). One read for the whole run, beside `documents`.
    produced: &'a BTreeMap<String, String>,
    /// The recorder records this branch accumulated (CLOUD-1051). One read for
    /// the whole run, beside `produced`.
    records: &'a BTreeMap<String, Vec<String>>,
    records_blocked: &'a BTreeMap<String, String>,
    /// The git facts this rule set declared (CLOUD-907).
    git: &'a crate::git::GitFacts,
    /// WHICH SURFACE THIS RUN IS ON (CLOUD-1480), beside the two facts whose
    /// resolvability it decides.
    ///
    /// Here rather than as a parameter to `evaluate_rules`, because the question
    /// it answers — may this fact be resolved at all — is about the same values
    /// this bag already carries, and a run-wide input passed separately is the
    /// one that drifts out of step with them.
    surface: crate::facts::Surface,
    /// The symbol census, iff this rule set declared it (CLOUD-760).
    symbols: &'a crate::facts::Look<crate::symbols::Resolved>,
    review: &'a crate::facts::Look<std::collections::BTreeMap<String, crate::review::Record>>,
    /// The engine's own finding store, per declared ref (CLOUD-1203). `None` is
    /// could-not-look and covers both nobody-asked and no-store-bound.
    state: Option<&'a BTreeMap<String, Vec<String>>>,
    /// The forge's verdicts, per declared SHA (CLOUD-1154). `None` is
    /// could-not-look: nobody asked, or no record store is readable.
    forge: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// A third-party tool's verdicts, per declared id (CLOUD-1171). `None` is
    /// could-not-look, for `forge`'s two reasons.
    tool_verdicts: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// The effective plan per declared row (CLOUD-949).
    plan: Option<&'a BTreeMap<String, Option<crate::hk::Planned>>>,
    minted: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// The declared reductions over the capture store (CLOUD-1188). `None` is
    /// could-not-look: nobody asked, or no store is readable.
    captured: Option<&'a BTreeMap<String, serde_json::Value>>,
    /// The out-of-root files this rule set declared (CLOUD-1167). One read per
    /// declared id for the whole run, beside `documents`, and empty when no row
    /// declared one — which is what keeps a run that asks for none from reading
    /// an environment variable at all.
    external: &'a BTreeMap<String, Acquired>,
    bundles: &'a [crate::policy::Bundle],
    /// The verdict registry a `policy` row's finding takes its remedy from
    /// (CLOUD-1220).
    ///
    /// The UNION — consumer rows plus this binary's vendored classes — because a
    /// module may raise a preset's class as readily as a consumer's, and a
    /// registry missing half of them would resolve one and not the other.
    ///
    /// Here rather than re-resolved per violation: it is config, fixed for the
    /// life of the run, and this is the shape `Vocabulary` already threads for
    /// exactly that reason.
    verdicts: &'a [crate::config_model::DeclaredVerdict],
    /// The declared tables a `reference` row and a traversal read, resolved
    /// once for the run (CLOUD-2005, CLOUD-1868).
    tables: &'a RunTables<'a>,
}

/// The per-run tables the reference kind and the traversal fact read.
///
/// One value rather than three `RunInputs` fields because `run` sits on
/// clippy's line ceiling, and these three are built together and read
/// together.
pub(crate) struct RunTables<'a> {
    /// The `[[register]]` table a `reference` row resolves against.
    registers: &'a [crate::register::DeclaredRegister],
    /// The `[[pattern]]` table, compiled once for the run.
    patterns: BTreeMap<String, regex::Regex>,
    /// Each declared traversal's answer, keyed id -> seed.
    traversals: serde_json::Value,
    /// The working tree the shell fact reads past a row's `line_sources`
    /// (CLOUD-2628), shared by every row so the tree is probed once. `None`
    /// where no tree is under judgement.
    shell: Option<crate::census::TreeReader<'a>>,
}

impl<'a> RunTables<'a> {
    /// Compile the patterns and walk every declared traversal.
    fn new(
        vocabulary: crate::policy::Vocabulary<'a>,
        root: &'a Path,
        files: &'a [String],
    ) -> anyhow::Result<Self> {
        let patterns = crate::pattern::compiled(vocabulary.patterns);
        let traversals = walk_traversals(vocabulary, root, files, &patterns)?;
        Ok(Self {
            registers: vocabulary.registers,
            patterns,
            traversals,
            shell: Some(crate::census::TreeReader::new(root, files)),
        })
    }
}

fn run_rule(
    rule: &Rule,
    root: &Path,
    inputs: &RunInputs<'_>,
    findings: &mut Vec<Finding>,
    // See [`Scan::classes`]. Threaded because it is the same
    // kind and the same one place the fact exists (CLOUD-1120).
    classes: &mut BTreeMap<String, String>,
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
        return policy_rule(rule, inputs, findings, classes);
    }
    // Before the glob gate for `Policy`'s reason: a row citing another
    // register's column has no glob, and its registers are declared paths, not
    // the files the glob selects (CLOUD-2005). And before the `allow` check
    // below would matter, a reference row being deny-only by construction.
    if rule.kind == RuleKind::Reference {
        if rule.severity() == RuleSeverity::Allow {
            return Ok(Some(NotObserved::RuleSkipped));
        }
        return reference_rule(rule, root, inputs, findings);
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
    // A RATCHET SELECTS FROM THE WHOLE TREE, whatever narrowed the run
    // (CLOUD-519). Its verdict is a comparison of two aggregate counts over one
    // glob — the base rev's and the working tree's — so narrowing only the
    // working-tree side would report every unscanned file as deleted and
    // manufacture the exact refusal the kind exists to raise. CLOUD-328 measured
    // that shape from a different cause: when a ratchet's two halves disagree
    // about which files they count, the gate stops being able to fail honestly.
    //
    // Structural rather than remembered: the two kinds read different lists here,
    // so a later reader cannot narrow a ratchet by editing one filter.
    let candidates = if rule.kind == RuleKind::Ratchet {
        inputs.files
    } else {
        inputs.scoped
    };
    let matched: Vec<&String> = candidates
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
        RuleKind::Forbid => forbid_in_files(rule, root, &matched, findings)?,
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
        | RuleKind::Reference
        | RuleKind::Native
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
    /// `.bats`/`.pkl` path parseable, so reporting it as could-not-look would be
    /// a gate reporting a permanent authoring error as a transient one.
    ///
    /// `.md` was in that list until CLOUD-1787 and no longer is — it names
    /// [`crate::facts::Format::Markdown`], whose frontmatter is a document this
    /// build can read.
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
    /// Read as text in full, and the format found no document in it
    /// (CLOUD-1787).
    ///
    /// Its own arm rather than [`Unparsed`](Self::Unparsed), for the reason
    /// [`RootUnset`](Self::RootUnset) has one below: a different claim and a
    /// different remedy. `Unparsed` says *this document is malformed, fix it*;
    /// this says *there is no document here to fix*. A markdown file with no
    /// frontmatter fence is the only source of it today, and it is precisely the
    /// case CLOUD-1787 reports being reported as the other one.
    ///
    /// **Not silence, and not an empty document.** It reaches `missing` like
    /// every other cause, so a module that iterates only what it could read
    /// still cannot report green over it — which is the vacuous pass the whole
    /// three-valued contract exists to refuse.
    NoDocument,
    /// An `[[rule.external]]` row named a root environment variable this machine
    /// does not set, or sets to nothing (CLOUD-1167).
    ///
    /// Its own arm rather than [`Absent`](Self::Absent), because it is a
    /// different remedy and a different claim. `Absent` says *this root does not
    /// carry that file*; this says *this host has no such root at all*, so
    /// nothing was even looked for. Collapsing them would let a gate over a
    /// launcher's wiring report the same answer on a host that has the launcher
    /// and on one that has never heard of it — CLOUD-845's false green, arriving
    /// as a clean tree.
    RootUnset,
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
            NotAcquired::NoDocument => "no-document",
            NotAcquired::RootUnset => "root-unset",
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
    /// Parsed by its language's backend and reduced to D4 unit nodes
    /// (CLOUD-1008).
    Units,
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
    /// Parsed by its language's backend, reduced to unit nodes.
    Units,
    /// A declared unit path read at the row's `base` rev (plan item 4). Keyed
    /// `<rev>:<path>`, git's own spelling, since two rows may name two bases.
    BaseUnits,
    /// A declared `use` path read at the row's `base` rev, reduced to its edges
    /// and resolved against the BASE root's table (plan step 3, 4b's input).
    BaseUses,
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
    /// The file's unit nodes (CLOUD-1008), already in their projected shape.
    /// An EMPTY vector is a file that parsed and holds no unit; a file its
    /// backend refused is [`NotAcquired::Unparsed`], never this.
    Units(Vec<serde_json::Value>),
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

/// How many working-tree files this process has read on a rule's behalf
/// (CLOUD-1217), and how many bytes those reads returned.
///
/// **Two counters beside [`DOCUMENTS_ACQUIRED`] rather than one widened counter**,
/// because they answer different questions. That one is bounded to the document
/// cache and is what `document_read_count.rs` asserts; these cover every read a
/// rule kind performs for itself — the `forbid` scan, both of a `ratchet`'s
/// passes, and the two conservation walks — which is precisely the population the
/// cache never covered.
///
/// **Monotonic and process-global.** A rule's census reads its delta from
/// [`thread_reads`], this thread's share, because rules run side by side off
/// the hook surface (#1276); these stay the process totals a test reads, which
/// is why that test lives in its own binary, exactly as
/// `document_read_count.rs` does and for the same reason.
static FILES_READ: AtomicUsize = AtomicUsize::new(0);
static BYTES_READ: AtomicUsize = AtomicUsize::new(0);

/// Record one read of `bytes` bytes against the counters above.
///
/// Called at each site that reads on a rule's behalf, after the read has
/// succeeded — a read that failed spent an `open` and returned nothing, and
/// counting it would make an absent file indistinguishable from an empty one.
fn count_read(bytes: usize) {
    FILES_READ.fetch_add(1, Ordering::Relaxed);
    BYTES_READ.fetch_add(bytes, Ordering::Relaxed);
    THREAD_READS.with(|reads| {
        let (files, total) = reads.get();
        reads.set((files + 1, total + bytes));
    });
}

thread_local! {
    /// This thread's share of [`FILES_READ`] and [`BYTES_READ`]: what a rule's
    /// census reads as its delta once rules run side by side (#1276).
    static THREAD_READS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// The files and bytes this thread has read on a rule's behalf.
fn thread_reads() -> (usize, usize) {
    THREAD_READS.with(std::cell::Cell::get)
}

/// How many files this process has read on a rule's behalf.
#[must_use]
pub fn files_read() -> usize {
    FILES_READ.load(Ordering::Relaxed)
}

/// How many bytes those reads returned.
#[must_use]
pub fn bytes_read() -> usize {
    BYTES_READ.load(Ordering::Relaxed)
}

/// What each rule of the LAST run cost (CLOUD-1217), in declaration order.
///
/// **Out of [`Scan`] deliberately, and the gate is what settled it.** It was a
/// `pub` field on that struct for one commit; `batten semver check` refused the
/// branch with `constructible_struct_adds_field`, because a consumer
/// constructing `Scan { .. }` cannot keep compiling across the addition. The
/// refusal was right on the API, and reading it also settled the design
/// question: a census is a MEASUREMENT ABOUT a run, not part of the run's value,
/// and the tell was that keeping it on `Scan` forced a hand-written `PartialEq`
/// that skipped the clock so scan equality would not become timing-dependent. A
/// value type that has to lie about one of its fields to stay comparable is
/// carrying something that is not its own.
///
/// **Cleared at the top of every [`run`], not appended to forever**, which is the
/// one thing this owes over the two counters above: they are monotonic and read
/// as a delta, and a per-rule LIST read that way would hand a caller the previous
/// run's rows as well. Reading it therefore means "the run that just finished",
/// and a caller reads it immediately after the runner returns.
///
/// Process-global for the counters' reason, with the counters' consequence: the
/// test that reads it lives in its own binary.
static RULE_COSTS: Mutex<Vec<RuleCost>> = Mutex::new(Vec::new());

/// Take the lock, treating a poisoned one as the data it still holds.
///
/// A panic in another thread says nothing about whether this census is readable,
/// and the workspace lints refuse an `unwrap` on a reachable path besides.
fn costs_lock() -> std::sync::MutexGuard<'static, Vec<RuleCost>> {
    RULE_COSTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What each rule of the last [`run`] cost, in declaration order.
#[must_use]
pub fn rule_costs() -> Vec<RuleCost> {
    costs_lock().clone()
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
    let mut read = None;
    acquire_reading(root, rel_path, want, &mut read)
}

/// [`acquire`], reading the file into `read` only where it holds nothing yet,
/// so one file wanted in several forms is read once (CLOUD-2830). The counters
/// still count each form: each is an acquisition, and the census's numbers do
/// not move with the read's reuse.
fn acquire_reading(
    root: &Path,
    rel_path: &str,
    want: Option<Want>,
    read: &mut Option<Result<Vec<u8>, std::io::ErrorKind>>,
) -> Acquired {
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
    let read = read
        .get_or_insert_with(|| crate::fsio::read(root.join(rel_path)).map_err(|err| err.kind()));
    let bytes = match read {
        Ok(bytes) => bytes.clone(),
        Err(std::io::ErrorKind::NotFound) => {
            return Acquired::No(NotAcquired::Absent);
        }
        // EACCES, EISDIR and every other I/O failure. A gate that cannot look
        // reports rather than aborts the run — which is the posture `facts.rs`'s
        // header already states and the one behaviour `document_in_file` did not
        // share with its siblings before this collapse.
        Err(_) => return Acquired::No(NotAcquired::Unreadable),
    };
    // COUNTED HERE, AND IT WAS COUNTED NOWHERE BEFORE (CLOUD-1790). This is the
    // one function that acquires a document, so every `policy` and `document`
    // rule's reads ran past `count_read` entirely and each reported
    // `0 file(s) 0 byte(s)` however much it had read. The `forbid`/`ratchet`
    // family counts at its own read sites, so the census was not empty — it was
    // SELECTIVELY empty, which is worse: the kinds reporting nothing are exactly
    // the kinds whose silence is hardest to tell from a gate that decided
    // nothing.
    //
    // Measured: that false zero is what CLOUD-1790 was filed on, as "tree-scoped
    // policy rules receive no input at all". They receive it — a row in the
    // reporter's own shape reads its source, decides, and emits a finding while
    // reporting zero. A consumer compared that zero against a `forbid` row in the
    // same config reporting real numbers and rewrote three modules and about
    // twenty predicates around a defect that was in the odometer.
    //
    // AFTER `fs::read` AND BEFORE THE UTF-8 DECODE, which is `count_read`'s own
    // contract read literally: it counts a read that SUCCEEDED, and decoding is
    // parsing rather than reading. A file of non-UTF-8 bytes cost exactly the
    // open and the bytes this counter exists to account for, and skipping it
    // would under-report the case most expensive to discover. The
    // `UnknownFormat` arm above stays uncounted for the reason stated there — it
    // is decided before any I/O — which is the same asymmetry `DOCUMENTS_ACQUIRED`
    // is placed for.
    count_read(bytes.len());
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
        // The backend seam (CLOUD-1578): the extension routes to the one parser
        // that answers for that language, and a refusal from any of them is
        // `Unparsed`, never an empty node list.
        Want::Units => match unit_nodes(rel_path, &text) {
            Some(nodes) => Acquired::Units(nodes),
            None => Acquired::No(NotAcquired::Unparsed),
        },
        Want::Parsed(format) => match parse_node(format, &text) {
            Ok(node) => Acquired::Parsed(node),
            Err(why) => Acquired::No(why),
        },
    }
}

/// Parse already-read bytes into a document node — **the one `Format::read` call
/// in the crate** (CLOUD-849).
///
/// Extracted rather than repeated, and the reason is the gate's own: a second
/// call site is a second error mapping, and two mappings diverge. That is not
/// hypothetical here — CLOUD-1203's staged family added one, and
/// `one_document_acquisition_exists` is what caught it.
///
/// **The bytes are the caller's**, which is what lets three very different
/// sources share one parse: [`acquire`] reads the working tree, the staged family
/// reads the index, and [`crate::captured`] reads the capture store. Where the
/// bytes came from is exactly what those three disagree about, and how a document
/// is parsed and how a parse failure is CLASSIFIED is exactly what they must not.
///
/// # Errors
///
/// [`NotAcquired::Unparsed`] when the grammar refused. A file that will not parse
/// says nothing about what it contains, which is `Format::read`'s own
/// three-valued contract — and the one thing it must never resolve to is silence.
///
/// [`NotAcquired::NoDocument`] when the format read the file completely and
/// found no document in it — today only [`crate::facts::Format::Markdown`] over
/// a file with no frontmatter fence. Its own cause rather than `Unparsed`,
/// because the remedy is the opposite one: `Unparsed` says *fix this fence*,
/// this says *there is no fence*.
pub(crate) fn parse_node(
    format: crate::facts::Format,
    text: &str,
) -> Result<crate::facts::Node, NotAcquired> {
    match format.read(text) {
        crate::facts::Look::Is(node) => Ok(node),
        // Both are non-answers, and they are DIFFERENT non-answers. Collapsing
        // them — which this did until CLOUD-1787 — reports "no frontmatter" as
        // a parse failure and sends an author looking for a malformed fence
        // that is simply absent.
        crate::facts::Look::IsNot => Err(NotAcquired::NoDocument),
        crate::facts::Look::CouldNotLook => Err(NotAcquired::Unparsed),
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
        Wanted::Units => Some(Want::Units),
        // Read from git objects by `acquire_declared`, never from the file.
        Wanted::BaseUnits | Wanted::BaseUses => None,
        Wanted::Document => crate::facts::Format::for_path(path).map(Want::Parsed),
    }
}

/// Refuse a run whose declared read set has passed `limit` (CLOUD-850).
///
/// **Extracted so it is testable at any size**, which is `rules/rust.md`'s
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

/// Everything a row's [`Rule::unit_sources`] globs select (CLOUD-1008).
///
/// # Errors
///
/// A [`UsageError`] for a pattern `globset` cannot parse, as its siblings.
pub(crate) fn declared_units(rule: &Rule, files: &[String]) -> anyhow::Result<Vec<String>> {
    select_declared(&[], &rule.unit_sources, files)
}

/// One file's unit nodes, through the backend its extension routes to
/// (CLOUD-1578's seam): Rust through the one lossless parse, Rego through
/// regorus. `None` when the backend refused the text or no backend owns the
/// extension, which the caller reads as could-not-look.
///
/// A Rust `fn` node's counts gain `tokens`: `o200k_base` over exactly the slice
/// the capture-view reader would serve, so a fact about a unit agrees with what
/// a reader of that unit is handed. Comments and strings are not tokenized.
fn unit_nodes(rel_path: &str, text: &str) -> Option<Vec<serde_json::Value>> {
    let extension = rel_path.rsplit_once('.')?.1;
    // MEMOISED PER BLOB, across calls (plan item 4, CLOUD-1008's lazy half): a
    // node list is a pure function of the language and the text, so an unchanged
    // file is one cache read. Keyed by content and the running binary
    // (`cache::key`), so an edit or a new engine is a miss, never a stale answer;
    // a refusal (`None`) is not cached, so a file is never wrongly settled as
    // could-not-look.
    let entry = units_cache().map(|dir| {
        let at = dir.join(
            blake3::hash(&[extension.as_bytes(), b"\0", text.as_bytes()].concat())
                .to_hex()
                .as_str(),
        );
        let key = crate::cache::key(UNITS_FORMAT, &[extension.as_bytes(), text.as_bytes()]);
        (at, key)
    });
    if let Some(nodes) = entry
        .as_ref()
        .and_then(|(at, key)| crate::cache::read(at, key))
        .and_then(|body| serde_json::from_slice(&body).ok())
    {
        return Some(nodes);
    }
    let nodes = unit_nodes_uncached(extension, rel_path, text)?;
    if let (Some((at, key)), Ok(body)) = (&entry, serde_json::to_vec(&nodes)) {
        crate::cache::write(at, key, &body);
    }
    Some(nodes)
}

/// The `units` memo's entry format: bumped when the node shape changes, so an
/// entry written by an older shape is a miss.
const UNITS_FORMAT: &str = "units-v1";

/// The directory the `units` memo writes under, resolved once per process.
fn units_cache() -> Option<&'static Path> {
    static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let state = crate::state::state_root().ok()?;
        let dir = crate::cache::root_under(&state)?.join("units");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir)
    })
    .as_deref()
}

/// One parser behind the unit seam (CLOUD-1578): text in, unit nodes out.
///
/// The answer is a [`crate::facts::Look`], so a backend's three outcomes are
/// three values: `Is(nodes)`, `IsNot` ("this path is not my language") and
/// `CouldNotLook` ("it is mine and I could not parse it"). CLOUD-310 admits a
/// backend to a VERDICT only if it can abstain, and this type is how that is
/// held: a backend that cannot say `IsNot` cannot be written, and
/// `every_unit_backend_abstains_off_its_language` checks that each one does.
type UnitBackend = fn(&str, &str) -> crate::facts::Look<Vec<serde_json::Value>>;

/// The routing table: which parser serves which language, and why. Adding a
/// language is a row, not a new architecture (CLOUD-1578's point, mined from
/// `mehen`'s shape with no code taken). A path whose extension has no row has
/// no unit fact: absent, never an empty node list.
const UNIT_BACKENDS: &[(&str, UnitBackend, &str)] = &[
    (
        "rs",
        rust_units,
        "ra_ap_syntax, the one lossless Rust parse (CLOUD-1008 D4); tree-sitter is refused for verdicts (CLOUD-310)",
    ),
    (
        "rego",
        rego_units,
        "regorus, the engine's own evaluator, so a unit is what the runtime itself parsed",
    ),
];

/// The Rust backend: the D4 units from the one lossless parse, each `fn`
/// carrying the o200k token count of the slice a reader would be served.
fn rust_units(rel_path: &str, text: &str) -> crate::facts::Look<Vec<serde_json::Value>> {
    if !std::path::Path::new(rel_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    {
        return crate::facts::Look::IsNot;
    }
    let crate::facts::Look::Is(units) = crate::units::units(text) else {
        return crate::facts::Look::CouldNotLook;
    };
    crate::facts::Look::Is(
        units
            .into_iter()
            .map(|unit| {
                let slice = (unit.kind == "fn")
                    .then(|| text.get(unit.offset..unit.offset + unit.bytes))
                    .flatten();
                let mut node = serde_json::json!(unit);
                if let Some(slice) = slice {
                    node["counts"]["tokens"] = serde_json::json!(crate::o200k::tokens(slice));
                }
                node
            })
            .collect(),
    )
}

/// The Rego backend, over the module regorus parses.
fn rego_units(rel_path: &str, text: &str) -> crate::facts::Look<Vec<serde_json::Value>> {
    if !std::path::Path::new(rel_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rego"))
    {
        return crate::facts::Look::IsNot;
    }
    crate::rego_units::units(rel_path, text)
        .map_or(crate::facts::Look::CouldNotLook, crate::facts::Look::Is)
}

/// Route a path to its backend by extension and read its answer. Both refusals
/// are `None` here because the fact's contract is "absent, never empty"; the
/// distinction matters to the type and to verdict admission, not to a row.
fn unit_nodes_uncached(
    extension: &str,
    rel_path: &str,
    text: &str,
) -> Option<Vec<serde_json::Value>> {
    let (_, backend, _) = UNIT_BACKENDS.iter().find(|(owns, ..)| *owns == extension)?;
    match backend(rel_path, text) {
        crate::facts::Look::Is(nodes) => Some(nodes),
        crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => None,
    }
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
/// [`acquire_declared`] for one whole run, clearing the census first and charging
/// what it read to a row of its own.
///
/// MEASURED, AND ON ITS OWN CENSUS ROW (CLOUD-1790). The per-rule deltas wrap
/// `run_rule`, and this runs once before that loop — so a `policy` row's declared
/// reads happen outside every rule's measurement window and each such row reports
/// `0 file(s) 0 byte(s)` however much the run read on its behalf. The run total is
/// a SUM of those rows, so the reads were invisible at both levels, and a reader
/// comparing a policy row's zero against a `forbid` row's real numbers concludes
/// the policy row received nothing. That is what CLOUD-1790 was filed on.
///
/// ATTRIBUTED TO THE STEP RATHER THAN TO A RULE, which is the only honest place
/// for it. The cache is shared deliberately — N rows over one path in one form is
/// one read — so charging it to whichever row the loop reached first would starve
/// the others of an answer they equally caused, the same error the `(path, form)`
/// key exists to prevent one level down.
///
/// ONLY WHEN THERE IS A STEP TO REPORT: a rule set declaring no documents acquires
/// nothing and gets no row, so a run of `forbid` rows reads exactly as it did
/// before this landed.
///
/// CLEARED HERE, not appended to, and at the TOP of the run rather than the top of
/// the rule loop — which is where the clear sat and what this needs (CLOUD-1790).
/// The census describes THIS run, and the acquisition is part of it and measured
/// before any rule evaluates, so a clear placed after it wipes the row that
/// measured it — silently, since a missing census row and a step that cost nothing
/// read identically.
fn acquire_declared_measured(
    rules: &[Rule],
    root: &Path,
    files: &[String],
    line_files: &[String],
) -> anyhow::Result<BTreeMap<(String, Wanted), Acquired>> {
    costs_lock().clear();
    let started = std::time::Instant::now();
    let (files_before, bytes_before) = (files_read(), bytes_read());
    let documents = acquire_declared(rules, root, files, line_files)?;
    if !documents.is_empty() {
        costs_lock().push(RuleCost {
            rule: DECLARED_ACQUISITION.to_owned(),
            elapsed: started.elapsed(),
            files_read: files_read().saturating_sub(files_before),
            bytes_read: bytes_read().saturating_sub(bytes_before),
        });
    }
    Ok(documents)
}

///
/// `line_files` is the list `line_sources` selects from: the run's scope, which
/// is `files` itself unless `check --staged`/`--since` narrowed it (CLOUD-2789).
/// Reading every tracked `.rs` file's lines to judge the one being committed is
/// what made the commit-time cfg-gated-test step 4.4 s.
pub(crate) fn acquire_declared(
    rules: &[Rule],
    root: &Path,
    files: &[String],
    line_files: &[String],
) -> anyhow::Result<BTreeMap<(String, Wanted), Acquired>> {
    let mut cache: BTreeMap<(String, Wanted), Acquired> = BTreeMap::new();
    let mut pending: std::collections::BTreeSet<(String, Wanted)> =
        std::collections::BTreeSet::new();
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
        let wanted: [(Wanted, Vec<String>); 5] = [
            (Wanted::Document, declared),
            (
                Wanted::Lines,
                declared_lines(rule, line_files).unwrap_or_default(),
            ),
            (
                Wanted::Invocations,
                declared_invocations(rule, files).unwrap_or_default(),
            ),
            (Wanted::Uses, declared_uses(rule, files).unwrap_or_default()),
            (
                Wanted::Units,
                declared_units(rule, files).unwrap_or_default(),
            ),
        ];
        for (form, paths) in wanted {
            pending.extend(paths.into_iter().map(|path| (path, form)));
        }
        // THE BASE SIDE (plan item 4): each declared unit path read at the row's
        // `base` rev, from git OBJECTS, so an edit in flight cannot change it.
        // Keyed `<rev>:<path>`, and memoised by content through `unit_nodes`,
        // so a base every branch shares is parsed once across sessions.
        if let Some(base) = rule.base.as_deref() {
            for path in declared_units(rule, files).unwrap_or_default() {
                let key = (format!("{base}:{path}"), Wanted::BaseUnits);
                if cache.contains_key(&key) {
                    continue;
                }
                refuse_over_budget(cache.len(), READ_BUDGET)?;
                let acquired = match crate::git::read_at(root, base, &path) {
                    Ok(crate::git::BaseBlob::Found { text, .. }) => unit_nodes(&path, &text)
                        .map_or(Acquired::No(NotAcquired::Unparsed), Acquired::Units),
                    Ok(_) => Acquired::No(NotAcquired::Absent),
                    Err(_) => Acquired::No(NotAcquired::Unreadable),
                };
                cache.insert(key, acquired);
            }
            // The `use` family at the base, by the same read: the ratchet over
            // module edges (plan step 3) compares head and base graphs, and both
            // must be resolved by one function, so the base keeps the head's
            // shape (`Acquired::Uses`) and `project_uses` reads either.
            for path in declared_uses(rule, files).unwrap_or_default() {
                let key = (format!("{base}:{path}"), Wanted::BaseUses);
                if cache.contains_key(&key) {
                    continue;
                }
                refuse_over_budget(cache.len(), READ_BUDGET)?;
                let acquired = match crate::git::read_at(root, base, &path) {
                    Ok(crate::git::BaseBlob::Found { text, .. }) => {
                        match crate::uses::use_facts(&text) {
                            crate::facts::Look::Is(facts) => Acquired::Uses(facts),
                            crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => {
                                Acquired::No(NotAcquired::Unparsed)
                            }
                        }
                    }
                    Ok(_) => Acquired::No(NotAcquired::Absent),
                    Err(_) => Acquired::No(NotAcquired::Unreadable),
                };
                cache.insert(key, acquired);
            }
        }
    }
    // PATH-MAJOR, EVERY ROW'S WANTS TOGETHER (CLOUD-2830): one file's forms are
    // acquired back to back, so the Rust tree its call sites, `use` edges and
    // units are each read from is parsed once ([`batten_facts::source::rust_tree`]
    // answers the repeat of the text it parsed last). Acquired row by row and
    // form by form, a file wanted two ways was parsed twice: measured 14% of
    // `policy test`'s samples.
    // The file the last key read, reused by the next key on the same path.
    let mut read: (String, Option<Result<Vec<u8>, std::io::ErrorKind>>) = (String::new(), None);
    for key in pending {
        if cache.contains_key(&key) {
            // THE CACHE, and the assertion `documents_acquired` makes: N rows
            // over one path IN ONE FORM is one read and one parse.
            continue;
        }
        if read.0 != key.0 {
            read = (key.0.clone(), None);
        }
        // THE BUDGET, checked before the read rather than after it, so the
        // refusal is a bound and not a report of one already exceeded. It
        // counts (path, form) pairs: a file wanted three ways costs three.
        //
        // POINTER-ONLY, and here that means less than a pointer (§5): a count
        // and a limit, never the path list. The list is exactly the consumer's
        // file names, and a refusal that printed it would put the shape of a
        // private tree into an error message.
        refuse_over_budget(cache.len(), READ_BUDGET)?;
        let acquired = acquire_reading(root, &key.0, want_for(&key.0, key.1), &mut read.1);
        cache.insert(key, acquired);
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
#[cfg(test)]
fn git_facts(rules: &[Rule], root: &Path) -> crate::git::GitFacts {
    git_facts_within(rules, root, None)
}

/// [`git_facts`] for a run narrowed to a change-set: the base delta compares
/// only `within`'s paths on the working side (CLOUD-2789,
/// [`crate::git::base_delta_within`]).
fn git_facts_within(
    rules: &[Rule],
    root: &Path,
    within: Option<&BTreeSet<String>>,
) -> crate::git::GitFacts {
    let mut declared_reads: BTreeSet<GitRead> = BTreeSet::new();
    let mut declared_refs: BTreeSet<String> = BTreeSet::new();
    let mut declared_ranges: BTreeSet<String> = BTreeSet::new();
    let mut declared_metadata: BTreeSet<String> = BTreeSet::new();
    let mut declared_staged: BTreeSet<String> = BTreeSet::new();
    let mut declared_history: Vec<crate::facts::HistoryQuery> = Vec::new();
    let mut declared_landings: BTreeSet<String> = BTreeSet::new();
    // CLOUD-843's three members, acquired on their own declarations first and
    // carried into whichever value this returns — including the early one below,
    // which would otherwise drop them for a rule set declaring nothing else.
    let state = repository_state_facts(rules, root);
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
        declared_metadata.extend(rule.commits.iter().cloned());
        declared_staged.extend(rule.staged.iter().cloned());
        for query in &rule.history {
            // Deduped by id: `validate` refuses two rows declaring one id
            // differently, so first-wins cannot be a silent precedence rule.
            if !declared_history.iter().any(|seen| seen.id == query.id) {
                declared_history.push(query.clone());
            }
        }
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
        && declared_metadata.is_empty()
        && declared_staged.is_empty()
        && declared_history.is_empty()
        && declared_landings.is_empty()
        && declared_deltas.is_empty()
    {
        return state;
    }
    let refs: Vec<String> = declared_refs.into_iter().collect();
    let ranges: Vec<String> = declared_ranges.into_iter().collect();
    let metadata: Vec<String> = declared_metadata.into_iter().collect();
    let staged: Vec<String> = declared_staged.into_iter().collect();
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
        // CLOUD-1424. Guarded on the declaration like the rest: a run whose rows
        // ask nothing about the registry never opens the common dir's
        // `worktrees/` directory.
        worktrees: declared_reads
            .contains(&GitRead::Worktrees)
            .then(|| crate::git::worktree_fact(root).ok())
            .flatten(),
        refs: (!refs.is_empty())
            .then(|| crate::git::ref_facts(root, &refs).ok())
            .flatten(),
        ranges: (!ranges.is_empty())
            .then(|| crate::git::range_facts(root, &ranges).ok())
            .flatten(),
        // CLOUD-1187, on its own declaration for the reason `Rule::commits`
        // states: this peels an object per commit where `ranges` reads a
        // subject, so a row wanting subjects must not pay for it.
        metadata: (!metadata.is_empty())
            .then(|| crate::git::metadata_facts(root, &metadata).ok())
            .flatten(),
        // CLOUD-1203 unit A. Guarded on the declaration like the rest: a run
        // whose rows name no staged path opens no index.
        staged: (!staged.is_empty())
            .then(|| crate::git::staged_facts(root, &staged).ok())
            .flatten(),
        // CLOUD-1200. `.ok().flatten()` is what turns a shallow clone into
        // `null` — `history_facts` raises for it deliberately, so the
        // could-not-look reaches the projection through the shape every other
        // git fact already uses rather than through a second channel.
        history: (!declared_history.is_empty())
            .then(|| crate::git::history_facts(root, &declared_history).ok())
            .flatten(),
        landing: (!landings.is_empty())
            .then(|| crate::git::landing_facts(root, &landings).ok())
            .flatten(),
        base_delta: match (delta_bases.len(), deltas.is_empty()) {
            (1, false) => delta_bases
                .iter()
                .next()
                // RESOLVED UNCONDITIONALLY, AND THE OPTIMISATION THAT WAS HERE IS
                // WITHDRAWN (CLOUD-1484).
                //
                // A review asked for this to be declaration-gated, as every other
                // git fact here is, and the gating shipped keyed on
                // `!rule.minted.is_empty()`. That is not the declaration that reads
                // `patch-id`: a module may read the fact with no sibling
                // `[[rule.minted]]` row, and it would then see `null`, decide
                // nothing, and exit 0 — a dead gate bought to save a merge-base
                // walk. Worse for the row that prompted it, where dropping the
                // minted block would have silenced `code-review-dispatched`
                // through two channels at once.
                //
                // The cost is real and is accepted rather than hidden: a second
                // repository open, a merge-base walk and a tree diff, on every
                // `check` declaring any `delta_sources`. Gating it honestly needs a
                // column that says WHICH FACTS a row reads, which is a bigger
                // change than this row and does not belong inside it.
                .and_then(|base| {
                    crate::git::base_delta_within(root, base, &deltas, true, within).ok()
                })
                .flatten(),
            _ => None,
        },
        ..state
    }
}

/// The repository-STATE members of [`git_facts`] — tags, config, index — each on
/// its own declaration (CLOUD-843).
///
/// Its own function for `git_facts`' line ceiling, and returning a [`GitFacts`]
/// with only those three set so the caller spreads it into whichever value it
/// returns: a rule set declaring ONLY one of these must not lose it to the early
/// return that answers "nothing else was declared".
///
/// Guarded like every other member, so a run naming no tag glob opens no
/// reference, one naming no key reads no config, and one naming no pathspec
/// hashes no file.
///
/// [`GitFacts`]: crate::git::GitFacts
fn repository_state_facts(rules: &[Rule], root: &Path) -> crate::git::GitFacts {
    // Sets, like every other declared read: two rows naming one glob, key or
    // pathspec ask one question and read one answer.
    let mut tags: BTreeSet<String> = BTreeSet::new();
    let mut config: BTreeSet<String> = BTreeSet::new();
    let mut index: BTreeSet<String> = BTreeSet::new();
    for rule in rules {
        tags.extend(rule.tags.iter().cloned());
        config.extend(rule.git_config.iter().cloned());
        index.extend(rule.index.iter().cloned());
    }
    let tags: Vec<String> = tags.into_iter().collect();
    let config: Vec<String> = config.into_iter().collect();
    let index: Vec<String> = index.into_iter().collect();
    crate::git::GitFacts {
        tags: (!tags.is_empty())
            .then(|| crate::git::tag_facts(root, &tags).ok())
            .flatten(),
        config: (!config.is_empty())
            .then(|| crate::git::config_facts(root, &config).ok())
            .flatten(),
        index: (!index.is_empty())
            .then(|| crate::git::index_facts(root, &index).ok())
            .flatten(),
        ..crate::git::GitFacts::default()
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
        // The same contract for units (CLOUD-1008): a refused parse arrived
        // as `Acquired::No(Unparsed)`, so a present path is always a real answer.
        Some(Acquired::Units(nodes)) if wanted == Wanted::Units => {
            Ok(serde_json::json!({"nodes": nodes}))
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
/// What the RUN resolved once at the boundary, for every row to read.
///
/// [`Declared`]'s counterpart: that struct is what one ROW named, this is what
/// the boundary already went and got. Grouped for [`Declared`]'s reason and a
/// measured one — `tree_document` reached clippy's argument ceiling the first
/// time a family was added after the git one, and the fact model has more
/// families coming. A struct absorbs each new one as a field rather than as a
/// seventh, eighth and ninth parameter.
///
/// Every member is a value the projection READS and never resolves: the reads
/// are the caller's, which is what keeps `tree_document` pure and what stops a
/// projection spawning an analyser or opening an environment variable.
pub(crate) struct Resolved<'a> {
    /// What earlier runs produced, for the keys this rule set declares
    /// (CLOUD-851).
    pub produced: &'a BTreeMap<String, String>,
    /// Each declared traversal's answer per seed (CLOUD-1868), computed once
    /// for the run. `null` where none is declared.
    pub traversals: &'a serde_json::Value,
    /// The recorder records this branch accumulated (CLOUD-1051).
    pub records: &'a BTreeMap<String, Vec<String>>,
    /// [`crate::facts::Fact::RecordsBlocked`] — recorder id -> reason class.
    pub records_blocked: &'a BTreeMap<String, String>,
    /// The git facts this rule set declared (CLOUD-907).
    pub git: &'a crate::git::GitFacts,
    /// The symbol census, iff this rule set declared it (CLOUD-760).
    pub symbols: &'a crate::facts::Look<crate::symbols::Resolved>,
    pub review: &'a crate::facts::Look<std::collections::BTreeMap<String, crate::review::Record>>,
    /// The out-of-root files this rule set declared (CLOUD-1167).
    pub external: &'a BTreeMap<String, Acquired>,
    /// The engine's own finding store, per declared ref (CLOUD-1203). `None`
    /// when no row declared one AND when no store is bound to this checkout —
    /// both are could-not-look, and neither is an empty listing.
    pub state: Option<&'a BTreeMap<String, Vec<String>>>,
    /// The forge's verdicts, per declared SHA (CLOUD-1154), read back from a
    /// record a producer wrote outside the engine.
    pub forge: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// A third-party tool's verdicts, per declared id (CLOUD-1171), read back
    /// from a record keyed to (tool, pinned version, input digest).
    pub tool_verdicts: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// The effective plan per declared row (CLOUD-949).
    pub plan: Option<&'a BTreeMap<String, Option<crate::hk::Planned>>>,
    /// One declared field of each already-minted receipt, per `[[rule.minted]]`
    /// row (CLOUD-1310). `None` is could-not-look for both of its conditions.
    pub minted: Option<&'a BTreeMap<String, BTreeMap<String, String>>>,
    /// The declared reductions over the capture store (CLOUD-1188) — the answers
    /// a row asked for, never the responses they came from.
    pub captured: Option<&'a BTreeMap<String, serde_json::Value>>,
    /// How far the shell fact reads past the row's `line_sources`
    /// (CLOUD-2628). `None` reads the declared lines alone, which is what a
    /// module's own suite and a fabricated tree want.
    pub shell: Option<crate::census::Reach<'a, 'a>>,
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
    key: &dyn Fn(&str) -> (String, Wanted),
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
        (Some(path), None) => match cache.get(&key(path)) {
            Some(Acquired::Uses(facts)) => facts.exports.clone(),
            _ => crate::uses::RootExports::default(),
        },
        _ => crate::uses::RootExports::default(),
    };
    for path in uses {
        match cache.get(&key(path)) {
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
            Some(
                Acquired::Parsed(_)
                | Acquired::Lines(_)
                | Acquired::Invocations(_)
                | Acquired::Units(_),
            )
            | None => {
                missing.push(path.clone());
                causes.push((path.clone(), NotAcquired::Absent));
            }
        }
    }
}

/// Acquire exactly the out-of-root files this rule set declared (CLOUD-1167).
///
/// [`git_facts`]' shape and its reason: **the declaration is the bound**, and the
/// bound is what makes [`crate::facts::EXTERNAL`]'s `Cost::Read` an honest
/// classification rather than an aspiration. A run whose rows declare no
/// `[[rule.external]]` reads no environment variable and opens no file.
///
/// # This is the anti-scanner half, and it is structural
///
/// Nothing here walks a directory. The loop is over DECLARED rows, one read per
/// row, and the path it opens is `root`'s expansion joined with a `path` the
/// config loader already refused if it could walk upward
/// ([`crate::facts::Rooted::escapes`]). So the set of files any module can reach
/// is exactly the set some row named, and a module asking for an id no row
/// declares finds the key absent.
///
/// # Three could-not-look answers, kept apart
///
/// * [`NotAcquired::RootUnset`] — this host does not set that variable, so
///   nothing was looked for;
/// * [`NotAcquired::Absent`] / [`NotAcquired::Unreadable`] — the root exists and
///   the file does not, or could not be read;
/// * [`NotAcquired::UnknownFormat`] / [`NotAcquired::Unparsed`] — the extension
///   names no parser in this build, or the parser refused the bytes.
///
/// All five leave the id ABSENT from the map and named in the caller's `missing`
/// channel with its cause. None of them ever yields an empty node, because a
/// module reading one would decide over a file it never saw.
///
/// Keyed by the row's `id`, and the resolved absolute path never leaves this
/// function: it is a machine's home directory, and non-negotiable rule 4 keeps
/// one off the policy input and out of every finding.
///
/// Reading goes through [`acquire`] rather than a second `fs::read`, so
/// `tests::one_document_acquisition_exists` stays true and this family inherits
/// the read budget, the counter and the error mapping the document family
/// already has.
fn external_facts(rules: &[Rule], budget: usize) -> BTreeMap<String, Acquired> {
    let mut acquired: BTreeMap<String, Acquired> = BTreeMap::new();
    for rule in rules
        .iter()
        .filter(|rule| rule.kind == RuleKind::Policy && rule.scope == RuleScope::Tree)
    {
        for row in &rule.external {
            if acquired.contains_key(&row.id) {
                // The cache, for `acquire_declared`'s reason: N rows naming one
                // id is one read. `validate` refuses two rows declaring one id
                // with different roots or paths, so first-wins cannot be a
                // silent precedence rule here.
                continue;
            }
            // The bound, checked before the read rather than reported after it.
            // Pointer-free, like `refuse_over_budget`: the ids and the resolved
            // paths are the consumer's, so an over-budget run simply stops
            // acquiring rather than naming what it would have opened.
            if acquired.len() >= budget {
                break;
            }
            // A ROOT THIS HOST DOES NOT SET IS NOT AN ABSENT FILE. Empty counts
            // as unset: an empty variable would resolve the row to a relative
            // path against the process's working directory, which is a different
            // file on every invocation and exactly the ambient read this fact
            // exists to refuse.
            let Some(dir) = std::env::var_os(&row.root).filter(|value| !value.is_empty()) else {
                acquired.insert(row.id.clone(), Acquired::No(NotAcquired::RootUnset));
                continue;
            };
            let want = want_for(&row.path, Wanted::Document);
            acquired.insert(row.id.clone(), acquire(Path::new(&dir), &row.path, want));
        }
    }
    acquired
}

/// Every per-path family's map, plus the one could-not-look channel they share.
///
/// One value rather than nine locals, so [`tree_document`] can hand the
/// projection loop a single thing and a new family is a field here instead of a
/// tenth `let mut` in a function already at its line ceiling.
pub(crate) struct Projected {
    /// [`crate::facts::Fact::Document`] — path -> parsed node.
    pub parsed: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Lines`] — path -> the file's lines.
    pub read_lines: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Invocations`] — path -> its call sites.
    pub call_sites: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Units`] — path -> its D4 unit nodes (CLOUD-1008).
    pub units: serde_json::Map<String, serde_json::Value>,
    /// The base side of the unit family (plan item 4): path -> `{nodes}` at the
    /// row's `base` rev. A path the base does not hold, or whose blob its parser
    /// refused, is absent, and is NOT a missing path of the row: a file new on
    /// this branch is the ordinary case.
    pub base_units: serde_json::Map<String, serde_json::Value>,
    /// The base side of the `use` family: path -> its edges at the row's
    /// `base` rev, resolved against the base root's table. Absent like
    /// [`Self::base_units`] for a path the base does not hold.
    pub base_uses: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Coupling`] — the measures over the head and base
    /// `use` graphs, computed once from the two maps above.
    pub coupling: serde_json::Value,
    /// [`crate::facts::Fact::Uses`] — path -> its resolved `use` edges.
    pub use_edges: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::External`] — declared id -> parsed node.
    pub external_files: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Staged`] — declared path -> its staged node.
    pub staged_nodes: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Produced`] — sink key -> an earlier run's record.
    pub produced_records: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::Records`] — record name -> this branch's lines.
    pub recorder_lines: serde_json::Map<String, serde_json::Value>,
    /// [`crate::facts::Fact::RecordsBlocked`] — recorder id -> reason class.
    pub recorder_blocked: serde_json::Map<String, serde_json::Value>,
    /// What could not be looked at, as the bare names the SKIP guard counts.
    ///
    /// Not what the document carries: since CLOUD-1309 the projection builds
    /// `input.tree.missing` from [`Projected::causes`] instead, so a module reads
    /// a name -> cause map. This stays because the guard downstream asks only
    /// whether anything failed to acquire, and a count is cheaper than a map for
    /// that question.
    pub missing: Vec<String>,
    /// The same set carrying WHY (CLOUD-845), and since CLOUD-1309 the source the
    /// document is projected from.
    ///
    /// The causes were always computed and always dropped at the projection site,
    /// which made `rules/policy-modules.md`'s "a module may rely on that"
    /// true of this enum and false of the surface a module actually reads.
    pub causes: Vec<(String, NotAcquired)>,
}

/// [`project_paths`]'s base side and the measures over both sides: each
/// declared unit file's base nodes, the base's `use` edges by the SAME
/// [`project_uses`] over the base's own blobs (so head and base resolve
/// identically, each against its own root table), and the coupling measures of
/// head and base, one graph per side.
fn project_base_side(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    declared: &Declared<'_>,
    out: &mut Projected,
) {
    if let Some(base) = declared.base {
        for path in declared.units {
            if let Some(Acquired::Units(nodes)) =
                cache.get(&(format!("{base}:{path}"), Wanted::BaseUnits))
            {
                out.base_units
                    .insert(path.clone(), serde_json::json!({"nodes": nodes}));
            }
        }
    }
    // A path the base lacks is a new file, not a missing input of the
    // row, so its could-not-look is dropped rather than reported.
    if let Some(base) = declared.base {
        let (mut absent, mut why) = (Vec::new(), Vec::new());
        project_uses(
            cache,
            declared.uses,
            &|path| (format!("{base}:{path}"), Wanted::BaseUses),
            &mut out.base_uses,
            &mut absent,
            &mut why,
        );
    }
    // The measures, from the two edge maps just projected: one graph per side,
    // so head and base are measured by the same function over the same shape.
    if !declared.uses.is_empty() {
        let measure = |uses: &serde_json::Map<String, serde_json::Value>| {
            serde_json::json!(crate::coupling::measure(&crate::coupling::file_graph(uses)))
        };
        let mut coupling = serde_json::json!({"head": measure(&out.use_edges)});
        if declared.base.is_some() {
            coupling["base"] = measure(&out.base_uses);
        }
        out.coupling = coupling;
    }
}

/// Project every per-path family a row declared.
///
/// Split out of [`tree_document`] so that function stays under its line ceiling
/// as the fact model grows: the families accumulate here, and the projection
/// loop that reads [`crate::facts::Fact::ALL`] stays one loop.
fn project_paths(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    declared: &Declared<'_>,
    resolved: &Resolved<'_>,
) -> Projected {
    let mut out = Projected {
        parsed: serde_json::Map::new(),
        read_lines: serde_json::Map::new(),
        call_sites: serde_json::Map::new(),
        units: serde_json::Map::new(),
        base_units: serde_json::Map::new(),
        base_uses: serde_json::Map::new(),
        coupling: serde_json::Value::Null,
        use_edges: serde_json::Map::new(),
        external_files: serde_json::Map::new(),
        staged_nodes: serde_json::Map::new(),
        produced_records: resolved
            .produced
            .iter()
            .map(|(key, record)| (key.clone(), serde_json::json!(record)))
            .collect(),
        recorder_lines: resolved
            .records
            .iter()
            .map(|(name, lines)| (name.clone(), serde_json::json!(lines)))
            .collect(),
        recorder_blocked: resolved
            .records_blocked
            .iter()
            .map(|(recorder, reason)| (recorder.clone(), serde_json::json!(reason)))
            .collect(),
        missing: Vec::new(),
        causes: Vec::new(),
    };
    // ONE LOOP OVER THREE FAMILIES, driven by a table rather than written out
    // three times. Each family names the projection it wants and the map it
    // fills; `project_declared` owns the could-not-look distinction that all
    // three share, so there is one place for it to be right rather than three.
    //
    // `uses` is deliberately NOT in this table: its edges are completed against
    // the crate root's re-export table below, which is one value for the whole
    // declared set and so cannot be resolved per path.
    for (paths, wanted, target) in [
        (declared.documents, Wanted::Document, &mut out.parsed),
        (declared.lines, Wanted::Lines, &mut out.read_lines),
        (
            declared.invocations,
            Wanted::Invocations,
            &mut out.call_sites,
        ),
        (declared.units, Wanted::Units, &mut out.units),
    ] {
        for path in paths {
            match project_declared(cache, path, wanted) {
                Ok(value) => {
                    target.insert(path.clone(), value);
                }
                Err(why) => {
                    out.missing.push(path.clone());
                    out.causes.push((path.clone(), why));
                }
            }
        }
    }
    // The `use` family, whose edges are completed against one table for the
    // whole declared set — see `project_uses`.
    project_uses(
        cache,
        declared.uses,
        &|path| (path.to_owned(), Wanted::Uses),
        &mut out.use_edges,
        &mut out.missing,
        &mut out.causes,
    );
    project_base_side(cache, declared, &mut out);
    // The out-of-root family, keyed by a declared ID rather than by a path — see
    // `project_external` (CLOUD-1167).
    project_external(
        resolved.external,
        declared.external,
        &mut out.external_files,
        &mut out.missing,
        &mut out.causes,
    );
    // THE STAGED FAMILY (CLOUD-1203 unit A). Its own loop rather than a row in
    // the table above, because the bytes do not come from `acquire`: they come
    // off the INDEX, which is the whole point of the family. Parsing is the same
    // `Format::read` every other document goes through, so a module reads a node
    // exactly as it does for `documents` and the only difference is which side of
    // the index the bytes came from.
    for path in declared.staged {
        // The acquisition failed entirely, or this path has no staged entry, or
        // its bytes were not UTF-8 — `staged_facts` leaves all three absent, and
        // absent is could-not-look here rather than an empty node.
        let Some(text) = resolved
            .git
            .staged
            .as_ref()
            .and_then(|staged| staged.get(path))
        else {
            out.missing.push(path.clone());
            out.causes.push((path.clone(), NotAcquired::Absent));
            continue;
        };
        // An extension this build cannot parse is a CONFIG FAULT decided before
        // anything is read, exactly as `acquire`'s own `UnknownFormat` arm is —
        // unless the row DECLARED what to read it as, which is the one escape and
        // is consulted only here, where the extension has already failed.
        let Some(format) = crate::facts::Format::for_path(path).or(declared.staged_format) else {
            out.missing.push(path.clone());
            out.causes.push((path.clone(), NotAcquired::UnknownFormat));
            continue;
        };
        // THROUGH `parse_node`, which is the one `Format::read` call in the
        // crate. This loop used to call it directly, which made two error
        // mappings over one grammar — `one_document_acquisition_exists` is the
        // gate that caught it, and CLOUD-849 is why it exists.
        match parse_node(format, text) {
            Ok(node) => {
                out.staged_nodes.insert(path.clone(), node.to_json());
            }
            // The bytes read and the grammar refused — `Unparsed`, never
            // `Unreadable`, matching `acquire`'s split one family over.
            Err(why) => {
                out.missing.push(path.clone());
                out.causes.push((path.clone(), why));
            }
        }
    }
    out
}

/// Project the out-of-root family, keyed by DECLARED ID (CLOUD-1167).
///
/// Its own function for [`project_uses`]' reason rather than a row in
/// `tree_document`'s table: every other family is keyed by a repository-relative
/// PATH, and this one cannot be. The resolved path is a machine's home
/// directory, so neither the projected map nor the could-not-look channel may
/// carry one — which means `missing` gets the row's `id` here where its
/// neighbours get a path.
///
/// That is not a cosmetic difference. A module reading `missing` gets back a
/// name it declared and can act on; what it never gets, on any channel, is where
/// on this machine that name resolved to. Non-negotiable rule 4 is decided here
/// rather than at the report.
///
/// **Could-not-look, never an empty node**, and the cause survives: a root this
/// host does not set stays distinguishable from a file that is not there, from
/// one that would not parse, and from one the read budget refused. A module
/// handed an empty document for any of them would decide over a file it never
/// saw — CLOUD-845's dead gate, arriving as a clean tree.
fn project_external(
    external: &BTreeMap<String, Acquired>,
    declared: &[crate::facts::Rooted],
    out: &mut serde_json::Map<String, serde_json::Value>,
    missing: &mut Vec<String>,
    causes: &mut Vec<(String, NotAcquired)>,
) {
    for row in declared {
        match external.get(&row.id) {
            Some(Acquired::Parsed(node)) => {
                out.insert(row.id.clone(), node.to_json());
            }
            Some(Acquired::No(why)) => {
                missing.push(row.id.clone());
                causes.push((row.id.clone(), *why));
            }
            // Acquired under another projection, or never reached because the
            // run's read budget was already spent. Neither is this family's
            // answer and neither is an empty one.
            Some(
                Acquired::Lines(_)
                | Acquired::Invocations(_)
                | Acquired::Units(_)
                | Acquired::Uses(_),
            )
            | None => {
                missing.push(row.id.clone());
                causes.push((row.id.clone(), NotAcquired::Absent));
            }
        }
    }
}

/// Read the forge's verdict for each DECLARED sha (CLOUD-1154).
///
/// `git_facts`' shape and its reason: **the declaration is the bound.** A run
/// whose rows name no sha reads no record directory — and, the point of the whole
/// family, the engine never reaches the forge itself. The producer fetched once,
/// outside, and this reads what it wrote; `evaluator-io-check` is the gate on the
/// engine opening nothing.
///
/// `None` covers BOTH could-not-look conditions — nobody declared a sha, and no
/// git directory is resolvable — and the projection writes `null`. An empty MAP
/// would be a third claim ("records were read and none exist"), which a landing
/// gate must not infer from a directory nobody opened.
fn forge_facts(rules: &[Rule], root: &Path) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let declared: Vec<String> = {
        let mut shas: BTreeSet<String> = BTreeSet::new();
        for rule in rules {
            shas.extend(rule.forge.iter().cloned());
        }
        shas.into_iter().collect()
    };
    if declared.is_empty() {
        return None;
    }
    // EACH DECLARED TOKEN IS RESOLVED AS A REF FIRST, so a row can name `HEAD`
    // and mean the commit under judgement rather than a literal sha that goes
    // stale the moment anything lands. A token that resolves to nothing is used
    // as written, which keeps a literal sha working and keeps this from being a
    // second ref vocabulary beside `Rule::refs`.
    //
    // The map stays keyed by the DECLARED token — that is what a module wrote
    // and what it reads back — while the RECORD is looked up under the resolved
    // sha. The anti-forgery property is unchanged: a record written against a
    // different commit lives under a different filename and does not answer.
    let resolved = crate::git::ref_facts(root, &declared).unwrap_or_default();
    let git_dir = crate::git::git_dir(root).ok()?;
    let mut found = BTreeMap::new();
    for token in &declared {
        let sha = resolved.get(token).unwrap_or(token);
        let mut one = crate::forge::verdicts(&git_dir, std::slice::from_ref(sha));
        if let Some(checks) = one.remove(sha) {
            found.insert(token.clone(), checks);
        }
    }
    Some(found)
}

/// Read a third-party tool's verdict for each DECLARED row (CLOUD-1171).
///
/// [`forge_facts`]' shape and its reason one family over: **the declaration is
/// the bound**, and the engine never runs the tool. `check` is `read` and
/// structurally cannot; the producer ran it once, outside, and this reads what it
/// wrote — which `evaluator-io-check` and the spawn census both stay green over.
///
/// The DIGEST is taken here rather than declared, which is what makes a verdict
/// stale by construction: the key moves when the input does, so the old record is
/// not found rather than found and wrong.
///
/// `None` covers BOTH could-not-look conditions — nobody declared a tool, and no
/// git directory is resolvable. An empty MAP would be a third claim ("records
/// were read and none exist"), which a gate over a validator must not infer from
/// a directory nobody opened.
/// Acquire the adopted gate runner's effective plan for every declared row
/// (CLOUD-949).
///
/// [`tool_facts`]' shape with the staleness half inverted: **the declaration is
/// still the bound**, so a run whose rows declare no plan spawns nothing, but a
/// declared one is taken NOW rather than read back. A plan binds to a working
/// tree, and a working tree has no digest a record could be keyed by.
///
/// `None` is nobody declared a plan. A declared id that could not be acquired is
/// present with a `null` VALUE rather than absent — the reacquire arm, and the
/// one place this family departs from "absent is could-not-look".
///
/// **The departure is load-bearing.** Everywhere else the declared set is
/// recoverable from the config a module cannot see, so absence is the only
/// signal available. Here a module must be able to refuse a plan that could NOT
/// be taken, and a row that vanished on failure would make that refusal
/// unwritable: the id nobody could acquire is exactly the id the module needs to
/// name. A plan nobody could read and a plan with nothing wrong are otherwise
/// identical on the decision surface, which is what this row exists to prevent.
fn plan_facts(rules: &[Rule], root: &Path) -> Option<BTreeMap<String, Option<crate::hk::Planned>>> {
    plan_facts_from(rules, root, crate::hk::acquire)
}

/// [`plan_facts`] over an injected plan runner, so the arm that KEEPS a taken
/// plan is reachable without a real hk run.
fn plan_facts_from(
    rules: &[Rule],
    root: &Path,
    acquire: impl Fn(&Path, &crate::config_model::PlanQuery) -> crate::facts::Look<crate::hk::Planned>,
) -> Option<BTreeMap<String, Option<crate::hk::Planned>>> {
    let declared: Vec<crate::config_model::PlanQuery> = rules
        .iter()
        .flat_map(|rule| rule.plan.iter().cloned())
        .collect();
    if declared.is_empty() {
        return None;
    }
    let mut acquired = BTreeMap::new();
    for query in &declared {
        let taken = match acquire(root, query) {
            crate::facts::Look::Is(planned) => Some(planned),
            _ => None,
        };
        acquired.insert(query.id.clone(), taken);
    }
    Some(acquired)
}

fn tool_facts(rules: &[Rule], root: &Path) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let declared: Vec<crate::facts::ToolQuery> = rules
        .iter()
        .flat_map(|rule| rule.tools.iter().cloned())
        .collect();
    if declared.is_empty() {
        return None;
    }
    let git_dir = crate::git::git_dir(root).ok()?;
    Some(crate::tools::verdicts(&git_dir, root, &declared))
}

/// Read one declared field of each already-minted receipt (CLOUD-1310).
///
/// [`tool_facts`]' shape a family over: **the declaration is the bound**, so a
/// run whose rows declare no mint never lists the receipt store, and the engine
/// fetches nothing — the boundary already did, in a session that had a
/// credential.
///
/// The CLOCK is read here rather than declared, for the reason the digest is
/// taken in [`tool_facts`]: a caller that supplied "now" could supply a time that
/// makes a stale reading answer, which is the one direction this fact must not
/// fail in.
///
/// `None` covers BOTH could-not-look conditions — nobody declared a mint, and no
/// git directory is resolvable. An empty MAP would be a third claim ("the store
/// was listed and holds nothing"), and on a fresh clone or any CI runner that is
/// precisely the wrong claim to make: the store is empty there by construction,
/// so a gate reading it as agreement would report clean exactly where it matters
/// least.
fn minted_facts(
    rules: &[Rule],
    root: &Path,
    now: Option<u64>,
) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let declared: Vec<crate::facts::MintedQuery> = rules
        .iter()
        .flat_map(|rule| rule.minted.iter().cloned())
        .collect();
    if declared.is_empty() {
        return None;
    }
    let git_dir = crate::git::git_dir(root).ok()?;
    // `0` where nobody supplied an instant: every reading then looks ancient and
    // the bound refuses rather than admits, which is the fail-closed direction
    // for a fact whose job is to stop a stale answer being trusted.
    Some(crate::minted::fields(&git_dir, &declared, now.unwrap_or(0)))
}

/// Reduce the capture store for each DECLARED row (CLOUD-1188).
///
/// [`tool_facts`]' shape and its reason: **the declaration is the bound**, and a
/// run whose rows declare no reduction never opens the store. That guard is
/// sharper here than anywhere else in the family, because resolving this reads
/// and parses every captured response rather than one keyed file.
///
/// `None` is could-not-look for both of its conditions — nobody declared a
/// reduction, and no store is readable. An empty MAP would be a third claim ("the
/// store was read and answered nothing"), which is exactly what a board gate must
/// not infer from a store nobody filled.
fn captured_facts(rules: &[Rule], root: &Path) -> Option<BTreeMap<String, serde_json::Value>> {
    let declared: Vec<crate::facts::CaptureQuery> = rules
        .iter()
        .flat_map(|rule| rule.captured.iter().cloned())
        .collect();
    if declared.is_empty() {
        return None;
    }
    // `reduce`'s OWN `None` rides through rather than being flattened: a store
    // that could not be addressed is could-not-look, and turning it into an empty
    // map here would undo the distinction the function just made.
    crate::captured::reduce(root, &declared)
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
/// The two `Cost::Effect` facts, resolved only where the SURFACE admits them.
///
/// # The surface is the other half of the guard (CLOUD-1480)
///
/// Declaration alone was never enough. [`crate::facts::Fact::Symbols`] is
/// classed `Cost::Effect` × `Surface::Check`, and `Surface::Check` names the
/// NARROWEST surface it may be resolved on — so resolving it from a narrower
/// one contradicts the class the fact already carries. The predicate is
/// [`crate::facts::Class::resolvable_on`], which already existed; an earlier
/// revision of this guard read a private DISPATCH enum instead and disabled
/// both facts on a read surface their own class admits.
///
/// # Could-not-look, and not `IsNot`
///
/// The two are different claims and this rationale endorsed the wrong one for a
/// revision: `IsNot` says the question was asked and the answer is no, which
/// about a crate nobody analysed is a measured nothing. The surface could not
/// ask, so [`crate::facts::Look::CouldNotLook`] is the arm. Both project `null`
/// today, which is exactly why the distinction has to be right here rather than
/// in whichever arm happens to render the same.
fn effect_facts(
    rules: &[Rule],
    root: &Path,
    surface: crate::facts::Surface,
) -> (
    crate::facts::Look<crate::symbols::Resolved>,
    crate::facts::Look<std::collections::BTreeMap<String, crate::review::Record>>,
) {
    let admitted = |class: crate::facts::Class| class.resolvable_on(surface);
    let symbols = if admitted(crate::facts::Fact::Symbols.class()) {
        symbols_fact(rules, root)
    } else {
        crate::facts::Look::CouldNotLook
    };
    let review = if admitted(crate::facts::Fact::Review.class()) {
        review_fact(rules, root)
    } else {
        crate::facts::Look::CouldNotLook
    };
    (symbols, review)
}

fn symbols_fact(rules: &[Rule], root: &Path) -> crate::facts::Look<crate::symbols::Resolved> {
    if !rules.iter().any(|rule| rule.symbols) {
        // Nothing asked, so nothing is spent — and the projection below emits
        // `null` rather than an empty census, which a module would read as
        // "resolved, found nothing".
        return crate::facts::Look::IsNot;
    }
    crate::symbols::resolve(root, &symbols_launcher(root))
}

/// How to reach the analyser [`crate::symbols`] spawns, resolved through the
/// toolchain pin (CLOUD-1324).
///
/// **Here rather than in `symbols` because of the direction**
/// `policy/module-layering.rego` holds: `symbols -> rules` is a forbidden
/// back-edge, and that module's own doc says acquisition is the CALLER's. This is
/// the caller, and [`spawn_resolving`] is the one authority over what a program
/// name resolves to — a second one in the adapter could disagree with it about
/// the same argv.
///
/// Public so the fact's own suite reaches the analyser the engine would, rather
/// than whichever build happens to be first on the test runner's `PATH`. That is
/// not a convenience: a suite resolving it differently would assert the census
/// against a tool the engine never runs.
///
/// **MEMBERSHIP IS THE WRONG QUESTION FOR THIS ONE PROGRAM, and that is the
/// measurement rather than a special case.** [`spawn_resolving`]'s rung 0 asks
/// whether the pin PROVIDES a program, resolved as a `PATH` difference — which is
/// right for a tool the pin installs and blind to a tool the pin merely GOVERNS.
/// The analyser is the second kind here: it sits in a directory both the ambient
/// and the composed `PATH` carry, so the difference cannot see it, while the
/// pin's environment is what selects which toolchain it compiles with. Measured
/// in this container: the bare spawn found a build that refuses the crate's own
/// `rust-version` and exited non-zero, so the census was could-not-look and
/// `spawn-adapters` refused a tree with nothing wrong in it — while the same
/// invocation through the mediator resolved 329 diagnostics.
///
/// So a READABLE pin is the condition, not membership in it. Could-not-look falls
/// through to the bare program, which is what a project with no pin has anyway.
#[must_use]
pub fn symbols_launcher(root: &Path) -> crate::symbols::Launcher {
    // THE EAGER DOOR, AND THE LAZY ONE IS REFUSED HERE — measured, having tried
    // it (CLOUD-1371).
    //
    // With the record gone, `symbols` cannot reach the analyser through the pin
    // and the census is could-not-look, so `re_resolved` here looks like the
    // obvious fix. It is not: "once per run" is true of a REAL tree and false of
    // the suite, where every fixture root is its own tree with no record, so the
    // lazy door spawns the runner twice per fixture and the memo bounds only the
    // repeat. That is the exact storm the eager door's narrowness exists to
    // prevent, and this row's own acceptance forbids it: *a fixture repository
    // with no declared pin pays zero runner spawns*.
    //
    // Measured rather than reasoned, and only under the full suite:
    // `stop_posture::a_turn_that_strands_nothing_is_silent` went red under
    // `verify` and PASSED run alone — the load-sensitive shape the original bound
    // was measured on ("concurrent `git commit`s inside those fixtures began
    // failing under the load, at ~50x their isolated duration").
    //
    // What the census gives up is one run of latency, not the recovery: the
    // ladder's lazy retry rebuilds the record on the first spawn that fails
    // anywhere, and the next census reads it. Recovering a fact one run later is
    // cheap; making every fixture pay two runner spawns is not.
    let read = crate::pinned::cached(root);
    let pinned = match read {
        crate::facts::Look::CouldNotLook => crate::pinned::repaired(root),
        other => other,
    };
    if matches!(pinned, crate::facts::Look::Is(_)) {
        let (mediator, prefix) = crate::pinned::mediated(crate::symbols::ANALYSER);
        return crate::symbols::Launcher::new(mediator, &prefix);
    }
    crate::symbols::Launcher::new(crate::symbols::ANALYSER, &[])
}

/// The [`crate::facts::Fact::Symbols`] projection, split out of
/// [`tree_document`] when the recorder fact pushed that function past the line
/// ceiling.
///
/// The three-valued distinction the doc comment at its call site describes lives
/// here rather than there, and the seam is the one that survives: this is the
/// only arm whose value is a nested document rather than a `json!` of a field.
/// Resolve the review fact, or say the run was never asked for one.
///
/// `IsNot` when no row declares a review, which is what keeps the cost off every
/// other consumer — the same gating `symbols_fact` applies one rung down.
fn review_fact(
    rules: &[Rule],
    root: &Path,
) -> crate::facts::Look<std::collections::BTreeMap<String, crate::review::Record>> {
    let declared: Vec<crate::facts::ReviewQuery> = rules
        .iter()
        .flat_map(|rule| rule.review.iter().cloned())
        .collect();
    crate::review::resolve(root, &declared)
}

/// The review fact as the tree document carries it.
///
/// A declared id ABSENT from the map is the refusal a gate reads, so this map is
/// deliberately partial: an id whose prompt has not run over its subject
/// contributes no entry, where one that ran and pointed at nothing contributes an
/// entry with an empty `findings`. Merging those two is the false clean the whole
/// fact exists to prevent.
fn review_value(
    review: &crate::facts::Look<std::collections::BTreeMap<String, crate::review::Record>>,
) -> serde_json::Value {
    match review {
        crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => serde_json::Value::Null,
        crate::facts::Look::Is(found) => serde_json::Value::Object(
            found
                .iter()
                .map(|(id, record)| {
                    (
                        id.clone(),
                        serde_json::json!({
                            "provenance": {
                                "tool": record.provenance.tool,
                                "version": record.provenance.version,
                                "invocation": record.provenance.invocation,
                                "prompt": record.provenance.prompt,
                            },
                            "subject": {
                                "kind": record.subject.kind,
                                "digest": record.subject.digest,
                            },
                            "findings": record
                                .findings
                                .iter()
                                .map(|finding| serde_json::json!({
                                    "path": finding.path,
                                    "line": finding.line,
                                    "clause": finding.clause,
                                }))
                                .collect::<Vec<_>>(),
                        }),
                    )
                })
                .collect(),
        ),
    }
}

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

/// One tree-surface fact's value, moved out of the projection; `None` for a
/// hook-surface fact the tree does not project. EXHAUSTIVE, NO
/// WILDCARD ARM: a new `Surface::Check` fact fails to compile here rather than
/// going silently unprojected.
fn fact_value(
    fact: crate::facts::Fact,
    projected: &mut Projected,
    shell: &mut serde_json::Value,
    tracked: &[String],
    resolved: &Resolved<'_>,
) -> Option<serde_json::Value> {
    Some(match fact {
        crate::facts::Fact::Document => serde_json::Value::Object(std::mem::take(&mut projected.parsed)),
        crate::facts::Fact::Tracked => serde_json::json!(tracked),
        crate::facts::Fact::Traversals => resolved.traversals.clone(),
        crate::facts::Fact::Lines => serde_json::Value::Object(std::mem::take(&mut projected.read_lines)),
        // A path the parser refused is in `missing` rather than here,
        // carrying `unparsed` as its cause — so a module reads could-not-look
        // exactly as it does for a document, and a path present with an
        // empty array is a file that parsed and calls nothing. Those are the
        // two answers CLOUD-310's parse-coverage obligation demands stay
        // apart, and the projection is where they would have collapsed.
        crate::facts::Fact::Invocations => {
            serde_json::Value::Object(std::mem::take(&mut projected.call_sites))
        }
        crate::facts::Fact::Uses => serde_json::Value::Object(std::mem::take(&mut projected.use_edges)),
        crate::facts::Fact::Units => serde_json::Value::Object(std::mem::take(&mut projected.units)),
        crate::facts::Fact::Coupling => std::mem::take(&mut projected.coupling),
        crate::facts::Fact::Base => {
            serde_json::json!({
                "units": std::mem::take(&mut projected.base_units),
                "uses": std::mem::take(&mut projected.base_uses),
            })
        }
        // CLOUD-1167. Keyed by the row's declared id, so an id this row did
        // not name is simply not here — the negative half that makes this a
        // projection of a declared set rather than a filesystem scan.
        crate::facts::Fact::External => {
            serde_json::Value::Object(std::mem::take(&mut projected.external_files))
        }
        // Hook-surface facts, filtered above. Stated as an arm so a
        // reclassification has to come through here.
        crate::facts::Fact::Produced => {
            serde_json::Value::Object(std::mem::take(&mut projected.produced_records))
        }
        // CLOUD-1051. Handed in for `produced`'s reason: the projection is
        // pure, and the read that fills this is the caller's.
        crate::facts::Fact::Records => {
            serde_json::Value::Object(std::mem::take(&mut projected.recorder_lines))
        }
        // CLOUD-1126. An EMPTY object is an answer here and means no declared
        // row was blocked on this branch, which is why this is not `null` when
        // the store is missing: the store is written only when something is
        // blocked, so its absence and its emptiness are the same fact.
        crate::facts::Fact::RecordsBlocked => {
            serde_json::Value::Object(std::mem::take(&mut projected.recorder_blocked))
        }
        // The git family (CLOUD-907). `null` rather than a skip when a
        // member is `None`, which is the same invariant the mediated
        // document holds: a key that comes and goes cannot be written
        // against at all, and `not input.tree["git-head"]` is indist-
        // inguishable from a predicate that simply does not hold.
        crate::facts::Fact::GitHead => serde_json::json!(resolved.git.head),
        crate::facts::Fact::GitStatus => serde_json::json!(resolved.git.status),
        crate::facts::Fact::GitRemote => serde_json::json!(resolved.git.remote),
        // CLOUD-1424. `null` when nobody declared it AND when the registry
        // could not be read; an empty `linked` list is the third answer and
        // means the registry was read and holds nothing.
        crate::facts::Fact::GitWorktrees => serde_json::json!(resolved.git.worktrees),
        crate::facts::Fact::GitRef => serde_json::json!(resolved.git.refs),
        crate::facts::Fact::GitRange => serde_json::json!(resolved.git.ranges),
        // CLOUD-1187. Identity fields only — the type carries no body, so
        // there is nothing here for rule 4 to have to exclude.
        crate::facts::Fact::CommitMeta => serde_json::json!(resolved.git.metadata),
        crate::facts::Fact::Landing => serde_json::json!(resolved.git.landing),
        // CLOUD-1200. `null` for both could-not-look conditions — nobody
        // declared a pattern, and the clone is shallow.
        crate::facts::Fact::GitHistory => serde_json::json!(resolved.git.history),
        // CLOUD-843. `null` for both could-not-look conditions — nobody
        // declared one, and the read failed. One level down each keeps its
        // own ANSWER apart from that: a glob that matched no tag is an empty
        // list, a key no scope sets has a null `effective`, a pathspec that
        // selects nothing has three empty lists.
        crate::facts::Fact::GitTags => serde_json::json!(resolved.git.tags),
        crate::facts::Fact::GitConfig => serde_json::json!(resolved.git.config),
        crate::facts::Fact::GitIndex => serde_json::json!(resolved.git.index),
        // CLOUD-1203 unit A. The staged bytes, PARSED by each path's own
        // format — so a module reads a node exactly as it does for
        // `documents`, and the only difference is which side of the index
        // the bytes came from. A path that could not be staged-read is in
        // `missing` with its cause rather than here.
        crate::facts::Fact::Staged => {
            serde_json::Value::Object(std::mem::take(&mut projected.staged_nodes))
        }
        // CLOUD-1203 unit B. `null` for both could-not-look conditions —
        // nobody declared a ref, and no store is bound — because an empty
        // listing is a third answer and means the store was read and held
        // nothing.
        crate::facts::Fact::State => serde_json::json!(resolved.state),
        // CLOUD-1154. `null` for both could-not-look conditions — nobody
        // declared a SHA, and no record store is readable. A declared SHA
        // with no record is ABSENT from the map, which is a third answer.
        crate::facts::Fact::Forge => serde_json::json!(resolved.forge),
        // CLOUD-1171. `null` for both could-not-look conditions — nobody
        // declared a tool, and no record store is readable. A declared id
        // whose KEY has no record is ABSENT from the map, which is the third
        // answer and the one the whole keying exists to produce.
        crate::facts::Fact::ToolVerdict => serde_json::json!(resolved.tool_verdicts),
        crate::facts::Fact::Plan => serde_json::json!(resolved.plan),
        crate::facts::Fact::Minted => serde_json::json!(resolved.minted),
        // CLOUD-1188. `null` for both could-not-look conditions — nobody
        // declared a reduction, and no store is readable. A declared id no
        // capture answered is ABSENT from the map, which is the third answer
        // and the one a board gate must not read as a negative.
        crate::facts::Fact::Captured => serde_json::json!(resolved.captured),
        // Hook-surface (CLOUD-856), filtered above by `tree_key`. Named as an
        // arm rather than wildcarded so a reclassification has to come
        // through here — the same discipline every hook-only fact in this
        // match already keeps.
        // Hook-surface, filtered above by `tree_key`, and named rather than
        // wildcarded so a reclassification has to come through here. Two
        // facts with one reason each: the task receipt exists so the
        // MEDIATED call need not parse a manifest (CLOUD-856), and the
        // extractor's subject is THIS session's transcript, which a tree run
        // has no way to be inside of (CLOUD-1172).
        // CLOUD-1170 joins them, and for a reason neither of those two has:
        // the instant is CONSUMED AT THE BOUNDARY and reaches no module on
        // any surface, so this arm is unreachable rather than merely filtered
        // — `tree_key` answers `None`, and the loop above has already
        // continued. Named anyway, because the whole value of this match
        // having no wildcard is that a fact gaining a surface has to come
        // through here rather than defaulting into a projection.
        crate::facts::Fact::Tasks
        | crate::facts::Fact::Extracted
        | crate::facts::Fact::Instant => serde_json::Value::Null,
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
        crate::facts::Fact::Symbols => symbols_value(resolved.symbols),
        crate::facts::Fact::Review => review_value(resolved.review),
        // CLOUD-1059, and `null` here carries BOTH could-not-look conditions
        // the family already collapses: no row declared a delta, and a row
        // declared one whose base did not resolve. A migration gate reads the
        // second as "I could not read the base" rather than "this branch
        // changed nothing", which is the distinction the whole fact exists
        // to keep.
        crate::facts::Fact::BaseDelta => serde_json::json!(resolved.git.base_delta),
        // CLOUD-2625. Computed before this loop takes `documents` and
        // `lines`, because it is derived from both.
        crate::facts::Fact::Shell => std::mem::take(shell),
        crate::facts::Fact::Receipts
        | crate::facts::Fact::Keys
        | crate::facts::Fact::Stop
        | crate::facts::Fact::Waived
        | crate::facts::Fact::AgentSourced
        | crate::facts::Fact::Prospective
        // CLOUD-1028: hook-surface, and its question is about a command the
        // tree surface does not have.
        | crate::facts::Fact::Pinned
        // CLOUD-1978: hook-surface; its question is about a call's argument.
        | crate::facts::Fact::DispatchBrief
        // CLOUD-2270: hook-surface; its question is about a push.
        | crate::facts::Fact::RedHead
        | crate::facts::Fact::LandLive
        | crate::facts::Fact::InstallPending
        | crate::facts::Fact::StateRepo
        | crate::facts::Fact::PathspecStatus
        | crate::facts::Fact::Budgeted
        // CLOUD-2335: hook-surface; its question is about a write.
        | crate::facts::Fact::ShellIntroduced => return None,
    })
}

pub(crate) fn tree_document(
    cache: &BTreeMap<(String, Wanted), Acquired>,
    declared: &Declared<'_>,
    tracked: &[String],
    // Everything the boundary already resolved (CLOUD-851, CLOUD-907, CLOUD-760,
    // CLOUD-1051, CLOUD-1167). Handed in as one value rather than one parameter
    // each, for the reason `Resolved`'s own doc states: the projection is pure,
    // the reads are the caller's, and the model keeps growing families.
    resolved: &Resolved<'_>,
) -> (String, Vec<(String, NotAcquired)>) {
    // Every per-path family, projected once (CLOUD-1167 split this out). The
    // extraction is not tidiness: `tree_document` reached clippy's line ceiling
    // the first time a family landed after the git one, and the fact model has
    // more coming. The prelude grows per family; the projection loop below does
    // not.
    let mut projected = project_paths(cache, declared, resolved);
    // `input.tree.shell` (CLOUD-2625): the detector over the declared homes,
    // read off the two maps the loop below moves out.
    let mut shell = crate::census::tree_fact(
        &projected.parsed,
        &projected.read_lines,
        resolved.git.base_delta.as_ref(),
        tracked,
        resolved.shell,
    );

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
        let Some(value) = fact_value(*fact, &mut projected, &mut shell, tracked, resolved) else {
            continue;
        };
        tree.insert(key.to_owned(), value);
    }
    // `missing` is the could-not-look CHANNEL, not a fact — it has no
    // `tree_key`, and it is inserted here rather than in the loop so the
    // correspondence test can subtract exactly one known name instead of
    // guessing which keys are facts.
    // COULD-NOT-LOOK CARRIES ITS CAUSE (CLOUD-1309). A bare list of names let a
    // module see THAT a declared source was not acquired and never WHY, so
    // `rules/policy-modules.md`'s promise -- "the two causes stay distinct
    // and a module may rely on that" -- was false of the projection while true of
    // the Rust enum. The causes were computed here all along and discarded one
    // line later; this is the same data, keyed.
    //
    // A MAP RATHER THAN A LIST OF PAIRS, so a module asks by name
    // (`input.tree.missing[path] == "unparsed"`) instead of scanning. Every
    // reader migrates in the same change: `some path in` over an array binds the
    // VALUES, so leaving one behind would silently rebind `path` to a cause
    // string and report a gate over a name no tree carries -- a wrong gate rather
    // than a broken one, which is the class this whole channel exists to prevent.
    let missing: serde_json::Map<String, serde_json::Value> = projected
        .causes
        .iter()
        .map(|(name, why)| {
            (
                name.clone(),
                serde_json::Value::String(why.as_str().to_owned()),
            )
        })
        .collect();
    tree.insert(String::from("missing"), serde_json::Value::Object(missing));
    let document = serde_json::json!({ "tree": serde_json::Value::Object(tree) });
    // `to_string` on a value this function built cannot fail, and the fallback is
    // an input the evaluator will reject rather than a silent empty tree — which
    // the caller reads as could-not-look, the honest answer if it ever happened.
    (
        serde_json::to_string(&document).unwrap_or_else(|_| String::from("{")),
        projected.causes,
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
/// The resolved half of [`tree_document`]'s input, projected out of one run's
/// [`RunInputs`].
///
/// Extracted for the reason `Projected` and `Declared` were: [`policy_rule`] sits
/// on clippy's line ceiling, and a struct literal that grows a line every time
/// the fact model does is what puts it over. The mapping is mechanical and every
/// field is already a reference, so this copies no fact and resolves nothing —
/// it only says which half of a run's inputs the tree surface reads.
fn resolved_of<'a>(inputs: &RunInputs<'a>) -> Resolved<'a> {
    Resolved {
        review: inputs.review,
        produced: inputs.produced,
        traversals: &inputs.tables.traversals,
        records: inputs.records,
        records_blocked: inputs.records_blocked,
        git: inputs.git,
        symbols: inputs.symbols,
        external: inputs.external,
        state: inputs.state,
        forge: inputs.forge,
        tool_verdicts: inputs.tool_verdicts,
        plan: inputs.plan,
        minted: inputs.minted,
        captured: inputs.captured,
        // Read past the line sources only where a `[census.shell]` table is
        // handed over; `policy_rule` widens it for the preset's own row.
        shell: inputs
            .tables
            .shell
            .as_ref()
            .map(|reader| crate::census::Reach {
                reader,
                always: false,
            }),
    }
}

/// The preset whose ban judges shell's presence over the whole tree, a
/// consumer declaring no `[census.shell]` included (CLOUD-2628).
const SHELL_PRESET: &str = "shell-hygiene";

/// The class a copy behind its preset raises (CLOUD-2290).
pub const MODULE_PIN_STALE: &str = "module pin stale";

/// Warn for each module this row loads that `batten preset eject` copied at a
/// preset version older than the one this binary ships (CLOUD-2290).
///
/// A pointer and two numbers, never a diff (rule 4): what changed upstream is
/// the release notes' to say, and merging it is the consumer's call.
fn ejected_behind(
    rule: &Rule,
    root: &Path,
    registry: &[crate::config_model::DeclaredVerdict],
    findings: &mut Vec<Finding>,
) {
    let paths: Vec<String> = match (rule.module.as_deref(), rule.bundle.as_deref()) {
        (Some(module), _) => vec![module.to_owned()],
        (None, Some(bundle)) => {
            let Ok(entries) = std::fs::read_dir(root.join(bundle)) else {
                return;
            };
            let mut paths: Vec<String> = entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|file| {
                    Path::new(file)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("rego"))
                })
                .map(|file| format!("{}/{file}", bundle.trim_end_matches('/')))
                .collect();
            paths.sort();
            paths
        }
        (None, None) => return,
    };
    for path in paths {
        let Ok(source) = crate::fsio::read_to_string(root.join(&path)) else {
            continue;
        };
        let Some((preset, module, recorded)) = crate::preset::ejected_from(&source) else {
            continue;
        };
        let Some(shipped) =
            crate::preset_catalog::find(&preset).map(|manifest| manifest.version.clone())
        else {
            continue;
        };
        if crate::version::precedence(&recorded, &shipped).is_ge() {
            continue;
        }
        let Ok(default) = identity::code_fingerprint(
            &rule.id,
            &path,
            &format!("{MODULE_PIN_STALE} {preset}/{module} {recorded} {shipped}"),
            identity::SpanNormalization::Verbatim,
        ) else {
            continue;
        };
        findings.push(Finding {
            carried: vec![format!(
                "{preset}/{module} copied at version {recorded}, shipped at {shipped}"
            )],
            owner: Some(rule.id.clone()),
            rule: MODULE_PIN_STALE.to_owned(),
            severity: stale_severity(&recorded, &shipped),
            path,
            line: Some(1),
            identity: identity_of(rule, identity::FindingKind::Code, default),
            check: Check::Reevaluate,
            remediation: policy_remediation(registry, MODULE_PIN_STALE),
            reason: None,
        });
    }
}

/// How loudly a copy behind its preset is reported (CLOUD-2822).
///
/// A major bump means the shipped preset refuses something the copy admits, so
/// the copy is a gate the binary no longer agrees with: `deny`. A minor or patch
/// bump only admits more or rewords, so the copy is stricter or equal: `advise`.
fn stale_severity(recorded: &semver::Version, shipped: &semver::Version) -> RuleSeverity {
    if recorded.major < shipped.major {
        RuleSeverity::Deny
    } else {
        RuleSeverity::Advise
    }
}

/// Whether `rule` declares any glob column or a delta, the selectors whose
/// matching nothing means the row established nothing (CLOUD-359, CLOUD-1059).
fn declares_a_selector(rule: &Rule) -> bool {
    !rule.sources.is_empty()
        || !rule.line_sources.is_empty()
        || !rule.invocation_sources.is_empty()
        || !rule.use_sources.is_empty()
        || !rule.unit_sources.is_empty()
        || !rule.delta_sources.is_empty()
}

fn policy_rule(
    rule: &Rule,
    inputs: &RunInputs<'_>,
    findings: &mut Vec<Finding>,
    // And the class, for the same reason: `Violation` carries the token, and by
    // the time a `Finding` exists it is gone (CLOUD-1120).
    classes: &mut BTreeMap<String, String>,
) -> anyhow::Result<Option<NotObserved>> {
    // Only the three this function itself reads. Everything else the tree surface
    // needs goes through `resolved_of`, which is what keeps this destructure from
    // growing a line every time the fact model does.
    let &RunInputs {
        files: tracked,
        scoped,
        documents,
        git,
        bundles,
        verdicts: registry,
        ..
    } = inputs;
    let Some(bundle) = bundles.iter().find(|bundle| bundle.id() == rule.id) else {
        // The row enabled a bundle the caller did not load. Not a pass: this
        // surface has nothing to decide with, and reporting clean would be a
        // gate that never ran reading as one that found nothing.
        return Ok(Some(NotObserved::RuleSkipped));
    };
    // The row's declared set: literal `documents` plus everything `sources`
    // selects out of the run's one walk (CLOUD-850). A malformed glob was
    // refused at load, so this cannot fail late.
    let Ok(declared) = declared_documents(rule, tracked) else {
        return Ok(Some(NotObserved::RuleSkipped));
    };
    // `?`, and no longer `ok()?` (CLOUD-2789): that returned `None`, which is
    // EVALUATED, so a selector failing here read as a pass. A malformed glob is
    // refused by `validate` before any rule evaluates, so this is unreachable
    // in a valid config; if it is ever reached, the row errors rather than passes.
    // LINES FOLLOW THE RUN'S SCOPE (CLOUD-2789). Under `check --staged` a module
    // reads the lines of the change-set's files only: the commit-time
    // cfg-gated-test step read every tracked `.rs` file (4.4 s p50) to judge the
    // one being committed, and refused the commit for an unstaged file beside it.
    // Unnarrowed, `scoped` IS `tracked`, so a tree run reads what it always did.
    // The other selectors stay on the full set, for the header's reason: a
    // declared document or unit is a property of the repository.
    let declared_line_paths = declared_lines(rule, scoped)?;
    let declared_invocation_paths = declared_invocations(rule, tracked)?;
    let declared_use_paths = declared_uses(rule, tracked)?;
    let declared_unit_paths = declared_units(rule, tracked)?;
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
    // `crates/batten/tests/it/shell_retirement.rs`.
    //
    // A resolved delta is what counts, not a non-empty one: an empty delta is
    // the row having looked and found nothing changed, which IS establishing
    // something. `None` is could-not-look and still skips.
    let selectors_declared = declares_a_selector(rule);
    let delta_resolved = !rule.delta_sources.is_empty() && git.base_delta.is_some();
    // An `[[rule.external]]` row is a declaration like the rest, so a row whose
    // only input is an out-of-root file has established something the moment that
    // file resolved (CLOUD-1167). Leaving it out would make the gate over a
    // launcher's wiring skip itself on exactly the trees it exists to judge —
    // the omission CLOUD-359 and CLOUD-1059 each measured one column at a time.
    let external_declared = !rule.external.is_empty();
    let selected_nothing = declared.is_empty()
        && declared_line_paths.is_empty()
        && declared_invocation_paths.is_empty()
        && declared_use_paths.is_empty()
        && declared_unit_paths.is_empty()
        && !delta_resolved
        && !external_declared;
    if selected_nothing && selectors_declared {
        return Ok(Some(NotObserved::RuleSkipped));
    }
    let mut resolved = resolved_of(inputs);
    if rule.preset.as_deref() == Some(SHELL_PRESET) {
        resolved.shell = resolved.shell.map(|reach| crate::census::Reach {
            always: true,
            ..reach
        });
    }
    let (input, not_acquired) = tree_document(
        documents,
        &Declared {
            documents: &declared,
            lines: &declared_line_paths,
            invocations: &declared_invocation_paths,
            uses: &declared_use_paths,
            units: &declared_unit_paths,
            base: rule.base.as_deref(),
            staged: &rule.staged,
            staged_format: rule.format,
            external: &rule.external,
        },
        tracked,
        &resolved,
    );
    let input = if inputs.half == Some(Half::Tree) {
        null_live_keys(&input)
    } else {
        input
    };
    // A MODULE THAT COULD NOT LOOK IS A GATE THAT DID NOT DECIDE, AND THAT IS AN
    // ERROR, NEVER A SKIP (CLOUD-2789). It returned `RuleSkipped`, which folds to
    // no exit code and prints nothing, so a module faulting on every input — an
    // undefined helper, a runtime error, a shape it stopped emitting — read as
    // a clean tree: three gates were dead for weeks that way. As an error it
    // reaches `isolate`, which records the row in `Scan::errored` with this
    // reason, prints `errored <rule> — internal — <reason>` and exits 3. The one
    // deliberate abstention, a module with no clause for an input it was not
    // handed, stays a skip below, after the module has been asked.
    let violations = match crate::policy::deny_why(bundle, &input) {
        Ok(violations) => violations,
        Err(why) => anyhow::bail!("could not look: {why}"),
    };
    // COULD NOT LOOK, and never an empty deny set (CLOUD-251) — BUT THE MODULE IS
    // ASKED FIRST (CLOUD-1049). This guard used to sit ABOVE `deny` and return on
    // a non-empty `not_acquired`, which threw away the very document that names
    // what could not be looked at: `tree_document` has already built `input` with
    // a correct `input.tree.missing` (inserted outside the `Fact::ALL` loop,
    // because `missing` is a channel rather than a fact), and nothing ever read
    // it. So a module's `missing` clause could not fire — and, because the return
    // was unconditional, neither could any OTHER predicate in the same module,
    // including one whose body is `true`.
    //
    // Measured over the compiled binary, one tree and one module, varying only
    // the declared source: valid fires at exit 2; present-and-unparseable and
    // absent-via-`documents` were both SILENT at exit 0, taking an unconditional
    // predicate down with them. That is a gate switched off by the state of one
    // of its own inputs, which is strictly worse than the vacuous pass CLOUD-251
    // was guarding against — and `rules/policy-modules.md` requires every
    // module to write a clause that could never fire.
    //
    // Evaluating first preserves what CLOUD-251 actually wanted. A module that
    // carries the clause SPEAKS: it has established something about the path it
    // could not read, which is the opposite of reporting clean. A module that
    // carries no such clause has established nothing, so it still abstains here
    // rather than reporting clean, and `RuleSkipped` remains the engine's own
    // record of the abstention.
    if !not_acquired.is_empty() && violations.is_empty() {
        return Ok(Some(NotObserved::RuleSkipped));
    }
    for violation in &violations {
        let id = bundle.attribute(violation);
        let severity = rule.severity_for(violation.rule.as_deref());
        if severity == RuleSeverity::Allow {
            continue;
        }
        let (pointer, line) = first_pointer(&violation.subjects);
        let identity = identity::StoredIdentity::new(
            identity::FindingKind::Scope,
            // KEYED ON `(rule, verdict, subjects)` (CLOUD-1050). It used to
            // be keyed on the module's prose, so rewording a message reset
            // every baseline entry for that predicate while changing nothing
            // it decided. The token and the pointers are what the finding IS,
            // and they move only when the finding does.
            identity::scope_fingerprint(id, &fingerprint_of(violation)),
        );
        // THE OWNER IS ON THE FINDING NOW (CLOUD-1087), set at its construction
        // below rather than recorded in a side map here. `Scan::attributed` was
        // keyed on the scope fingerprint, and a `command` row whose id equals a
        // predicate id and whose glob equals the verdict token mints the same
        // one — so the map could hand this row's findings to that one. Nothing
        // is looked up any more, so nothing can collide.
        // THE CLASS, beside the owner and for the same reason (CLOUD-1120): this
        // is the one place it exists. `Violation` carries the token the module
        // raised, `Finding` has nowhere to put it, and without it a spent
        // admission has no term to match on — which is how an override could be
        // articulated, bound and consumed while the gate went on refusing.
        classes.insert(identity.fingerprint.to_hex(), violation.verdict.clone());
        findings.push(Finding {
            // THE ONE KIND WHOSE FINDING IS NOT ITS ROW'S (CLOUD-1087).
            // `rule` above carries the PREDICATE id (CLOUD-832); the row that
            // enabled the module is what a sink is asked about, and it is in hand
            // right here rather than reconstructible from a fingerprint later.
            owner: Some(rule.id.clone()),
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
            // carries. A path-less list carries its first rendered subject
            // (`first_pointer`); the bundle root is reached only for an empty
            // list, where the finding has nothing narrower to point at.
            path: pointer.clone().unwrap_or_else(|| {
                rule.bundle
                    .clone()
                    .or_else(|| rule.module.clone())
                    .unwrap_or_else(|| rule.id.clone())
            }),
            line,
            check: rule.settling_check().unwrap_or(Check::Reevaluate),
            // THE REMEDY COMES FROM THE CLASS, NOT THE ROW (CLOUD-1220).
            //
            // `rule.remediation()` reads the row's own `fix`/`no_fix_reason`, and a
            // `policy` row carries neither: `RuleKind::Policy` requires only
            // `severity`, where `RuleKind::Judge` requires `no_fix_reason` outright —
            // with a comment saying exactly why, that a judge finding "reaches the
            // store and CLOUD-81's ingest refuses one nothing can close". Policy rows
            // never got that treatment, so every one of their findings was dropped
            // before `findings::record`, and the whole findings subsystem — baseline,
            // dedup, disposition, sink accounting — was blind to the one rule kind
            // CLOUD-843's campaign is porting ~132 gates onto.
            //
            // The remedy was never missing, only unreachable: the `[[verdict]]` token
            // this violation raises declares its routes, and this is the hop that was
            // absent. No row's `fix` column is consulted for a policy finding — a
            // second spelling of a remedy the registry already carries is the
            // duplication that registry exists to remove.
            remediation: policy_remediation(registry, &violation.verdict),
            identity,
            reason: None,
            carried: carried_subjects(&violation.subjects),
        });
    }
    Ok(None)
}

/// The remedy a raised class declares, as a [`Remediation`] (CLOUD-1220).
///
/// # Why a policy finding cannot take the row's own remedy
///
/// [`Rule::remediation`] reads the `fix`/`no_fix_reason` columns, and a `policy`
/// row carries neither — `RuleKind::Policy` requires only `severity`. That is
/// not an oversight in the row: a module's remedy is per PREDICATE, and one row
/// can carry many (CLOUD-832), so a single column on the row could not say which
/// violation it answered. The `[[verdict]]` registry is where it already lives.
///
/// # The two shapes, and why the second is not "no remedy"
///
/// A `command` route is a runnable fix and becomes [`Remediation::Fix`]. Every
/// other route — a document to read, an issue to file, an override to request —
/// is a remedy a human performs, so it becomes [`Remediation::NoFix`] carrying
/// the route ids and kinds. That is a real answer rather than an absence:
/// `verdict::validate` already refuses a class with no route at all, and one
/// whose only route is an override, so a resolved class always names somewhere
/// to go.
///
/// **Pointer-only** (rule 4): route ids and kinds, never a route's target prose
/// and never the finding's content. The full text is one hop away through
/// `batten policy explain`, which is CLOUD-1286's settled position.
///
/// `None` only where the token resolves to nothing — which
/// `check_verdicts_are_declared` refuses at load, so it is the residue of a
/// registry narrower than the one the module was compiled against rather than a
/// state a loaded config can reach.
fn policy_remediation(
    registry: &[crate::config_model::DeclaredVerdict],
    token: &str,
) -> Option<Remediation> {
    if let Some(command) = crate::verdict::first_command_route(registry, token) {
        return Some(Remediation::Fix(
            command.split_whitespace().map(ToOwned::to_owned).collect(),
        ));
    }
    let (entry, _) = crate::verdict::resolve(registry, token)?;
    let routes: Vec<String> = entry
        .routes
        .iter()
        .map(|route| format!("{} ({})", route.id, route.kind.as_str()))
        .collect();
    Some(Remediation::NoFix(format!(
        "{token}: {} — `batten policy explain` carries the detail",
        routes.join(", ")
    )))
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
///
/// # The tree pointer, deliberately not the mediated binding
///
/// This is the tree finding's pointer and its admission subject, anchored by
/// fingerprint. A mediated refusal binds every pointer it prints instead
/// (`refusal::admission_bindings`, CLOUD-1826): a tree finding has one `path`
/// slot, and forcing the two to agree would widen tree output or drop pointers
/// from the mediated binding.
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

/// Every subject but the one [`first_pointer`] chose, rendered (CLOUD-2213).
fn carried_subjects(subjects: &[crate::verdict::Subject]) -> Vec<String> {
    let skip = pointer_index(subjects);
    subjects
        .iter()
        .enumerate()
        .filter(|(index, _)| Some(*index) != skip)
        .map(|(_, subject)| subject.render())
        .collect()
}

/// The index [`first_pointer`] takes its pointer from: the first path-bearing
/// subject, else the first subject.
fn pointer_index(subjects: &[crate::verdict::Subject]) -> Option<usize> {
    subjects
        .iter()
        .position(|subject| {
            matches!(
                subject,
                crate::verdict::Subject::Line { .. } | crate::verdict::Subject::Path { .. }
            )
        })
        .or_else(|| (!subjects.is_empty()).then_some(0))
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

/// What one file counts under a ratchet row.
///
/// # Errors
///
/// Returns an error when `regex` does not compile; `validate` has refused that
/// at load, so this is the belt to its suspenders.
fn ratchet_tally(rule: &Rule) -> anyhow::Result<impl Fn(&str) -> usize + Sync + '_> {
    // THE COUNTED TOKEN: a literal, or an expression for one a literal cannot spell
    // (CLOUD-2059). `validate` admits exactly one and has compiled the expression,
    // so the `None` arm is unreachable and counts nothing.
    let expression = rule.regex.as_deref().map(Regex::new).transpose()?;
    // Or the token measure `policy budget` takes per file (CLOUD-2663): the same
    // function over the same loaded text, so the ratchet and the budget cannot
    // disagree about one file.
    // NEITHER A LITERAL NOR AN EXPRESSION IS THE TOKEN MEASURE: `validate`
    // admits exactly one of the three, and refuses any ratchet `counts` but
    // `tokens` (`validate_ratchet_measure`).
    // Or a lint's escapes, read off the parsed syntax (#1276): `pattern` names
    // the lint, and the count is of attributes, never of text.
    let lint = rule
        .pattern
        .as_deref()
        .filter(|_| rule.counts == Some(CeilingUnit::LintEscapes));
    Ok(move |text: &str| {
        if let Some(lint) = lint {
            return crate::codemod::lint_escapes(text, crate::codemod::Edition::E2024, lint);
        }
        match (&expression, rule.pattern.as_deref()) {
            (Some(expression), _) => expression.find_iter(text).count(),
            (None, Some(pattern)) => text.matches(pattern).count(),
            (None, None) => crate::budget::estimate_tokens(&crate::budget::loaded(text)),
        }
    })
}

/// One ratchet row a mediated write would move the banned way (CLOUD-2692).
///
/// `was` and `now` are the written file's own count before and after the write:
/// the pointer a reader needs to find what moved. The row is the subject, so a
/// waiver keyed on its id answers it at the call as it does in `check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CallRatchet {
    /// The row's id.
    pub rule: String,
    /// The written path.
    pub path: String,
    /// The path's count before the write.
    pub was: usize,
    /// The path's count after it.
    pub now: usize,
}

/// Whether `rule` is a ratchet a mediated write can be judged against
/// (CLOUD-2692).
///
/// Every ratchet but the two whose admission reads subject facts: `retires_with`
/// asks whether a declared subject died, and `conserves` maps case names across
/// the whole set, and neither is a single-file question. Those stay `check`'s.
#[must_use]
pub fn judged_at_call(rule: &Rule) -> bool {
    rule.kind == RuleKind::Ratchet
        && rule.severity() != RuleSeverity::Allow
        && rule.direction.is_some()
        && rule.base.is_some()
        && rule.glob.is_some()
        && rule.retires_with.is_none()
        && rule.conserves.is_none()
}

/// The cache format; bump when [`BlobCounts`], [`FileCounts`] or a key's
/// inputs change.
const CALL_RATCHET_FORMAT: &str = "batten-call-ratchet-4";

/// What a row counts, as cache-key bytes: two rows with the same counter share
/// their counts, and a row whose counter changed reads none of its old ones.
fn counter_key(rule: &Rule) -> Vec<u8> {
    format!(
        "{}\0{}\0{:?}",
        rule.pattern.as_deref().unwrap_or_default(),
        rule.regex.as_deref().unwrap_or_default(),
        rule.counts
    )
    .into_bytes()
}

/// One persisted count table under the cache's `ratchet-counts` directory,
/// keyed by `name` within this repository and counter.
fn count_entry(
    cache: Option<&Path>,
    root: &Path,
    counter: &[u8],
    name: &str,
) -> Option<(std::path::PathBuf, String)> {
    cache.map(|dir| {
        let at = dir.join("ratchet-counts").join(
            blake3::hash(
                &[
                    root.display().to_string().as_bytes(),
                    b"\0",
                    name.as_bytes(),
                    b"\0",
                    counter,
                ]
                .concat(),
            )
            .to_hex()
            .as_str(),
        );
        (
            at,
            crate::cache::key(CALL_RATCHET_FORMAT, &[name.as_bytes(), counter]),
        )
    })
}

/// Each committed blob's count under one counter, by blob id, persisted
/// (CLOUD-2692).
///
/// **A count is a pure function of a blob's content and the counter**, so it is
/// cached by content: a blob is read and counted once, ever. The blobs asked
/// for are the merge base's, which every branch and session shares, so after
/// the first call on a base they are all held.
struct BlobCounts {
    entry: Option<(std::path::PathBuf, String)>,
    counts: BTreeMap<String, usize>,
    added: bool,
}

impl BlobCounts {
    fn load(counter: &[u8], root: &Path, cache: Option<&Path>) -> Self {
        let entry = count_entry(cache, root, counter, "blobs");
        let counts = entry
            .as_ref()
            .and_then(|(at, key)| crate::cache::read(at, key))
            .and_then(|body| serde_json::from_slice(&body).ok())
            .unwrap_or_default();
        Self {
            entry,
            counts,
            added: false,
        }
    }

    fn missing<'a>(&self, ids: &[&'a str]) -> Vec<&'a str> {
        ids.iter()
            .copied()
            .filter(|id| !self.counts.contains_key(*id))
            .collect()
    }

    fn get(&self, id: Option<&str>) -> usize {
        id.and_then(|id| self.counts.get(id)).copied().unwrap_or(0)
    }

    fn save(&self) {
        if let (true, Some((at, key))) = (self.added, &self.entry)
            && let Ok(body) = serde_json::to_vec(&self.counts)
        {
            crate::cache::write(at, key, &body);
        }
    }
}

/// What a working file's count is keyed by: the file's identity and the stat
/// fields any write moves, git's index heuristic. A file whose key is unchanged
/// is not read again.
type Stamp = (u64, u64, u64, i128);

/// Each working file's count under one counter, by path, keyed by its
/// [`Stamp`], persisted (CLOUD-2692).
///
/// **The working side is read from the files, never from HEAD's blobs**: the
/// sum the row asks about is the tree as it stands, which a file read answers
/// directly, uncompressed, and an uncommitted edit to a changed path is counted
/// where a HEAD read would have missed it. A file is re-read only when its
/// stamp moved.
struct FileCounts {
    entry: Option<(std::path::PathBuf, String)>,
    counts: BTreeMap<String, (Stamp, usize)>,
    added: bool,
}

impl FileCounts {
    fn load(counter: &[u8], root: &Path, cache: Option<&Path>) -> Self {
        let entry = count_entry(cache, root, counter, "files");
        let counts = entry
            .as_ref()
            .and_then(|(at, key)| crate::cache::read(at, key))
            .and_then(|body| serde_json::from_slice(&body).ok())
            .unwrap_or_default();
        Self {
            entry,
            counts,
            added: false,
        }
    }

    /// The held count of `path`, when it was taken at `stamp`.
    fn fresh(&self, path: &str, stamp: Stamp) -> Option<usize> {
        self.counts
            .get(path)
            .filter(|(held, _)| *held == stamp)
            .map(|(_, count)| *count)
    }

    fn put(&mut self, path: &str, stamp: Stamp, count: usize) {
        self.counts.insert(path.to_owned(), (stamp, count));
        self.added = true;
    }

    fn save(&self) {
        if let (true, Some((at, key))) = (self.added, &self.entry)
            && let Ok(body) = serde_json::to_vec(&self.counts)
        {
            crate::cache::write(at, key, &body);
        }
    }
}

/// A file's [`Stamp`]: device, inode, size and modification time in
/// nanoseconds. Off unix the identity half is zero and size and time decide.
fn stamp(meta: &fs::Metadata) -> Stamp {
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt as _;
        (meta.dev(), meta.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, 0);
    let modified = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| {
            i128::try_from(since.as_nanos()).unwrap_or(i128::MAX)
        });
    (dev, ino, meta.len(), modified)
}

/// A count as a signed quantity, for the movement arithmetic.
fn signed(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Judge the ratchet rows a mediated write to `target` selects (CLOUD-2692):
/// each row the write moves the banned way past its base.
///
/// `current` is the target's text now (`None` for a new file) and `projected`
/// its text after the write. Cheapest first:
///
/// * **The write's own move**, with no read at all: a write that holds or
///   moves the file's count the allowed way is never refused, so a repair of a
///   standing breach goes through, and a rise the row's `admits_with` token
///   declares in the written text is admitted, as `check` admits it.
/// * **`per_file`**: the projected file against its own count at the merge
///   base. A path absent at the base has no ceiling and is not judged.
/// * **Aggregate**: the sum's movement from the merge base, over the paths the
///   branch changed, plus the target: each path's count in the WORKING TREE
///   (the target's projected) less its count at the base. A path the tree diff
///   does not name holds the same count on both sides, so it cannot move the
///   sum, and is never read.
///
/// **Every read is put in flight before any is made**: readahead is submitted
/// for every changed working file, and for the packs when a base count is not
/// yet held, so a cold page cache returns all the bytes at the device's queue
/// depth rather than one fault at a time. Working counts are keyed by each
/// file's stat and base counts by blob id, so a warm call reads nothing but the
/// target.
///
/// **Uncommitted edits to files no commit changed are not read**: the one
/// primitive that sees them, the worktree status, measured 91 ms here. `check`
/// still judges the whole tree.
///
/// # Errors
///
/// When a row's counter does not compile, or git cannot read the repository.
pub fn ratchets_at_call(
    rules: &[&Rule],
    root: &Path,
    target: &str,
    current: Option<&str>,
    projected: &str,
    cache: Option<&Path>,
) -> anyhow::Result<Vec<CallRatchet>> {
    let moving = moving_rows(rules, target, current, projected)?;
    if moving.is_empty() {
        return Ok(Vec::new());
    }
    let mut counters = counter_states(&moving, root, cache)?;
    let sets = changed_sets(&moving, root, target, cache)?;
    let stamps = working_stamps(&sets, root, target);
    count_base(&sets, &mut counters, root)?;
    count_working(&stamps, &mut counters, root);
    let found = moving
        .into_iter()
        .filter_map(|row| judge(row, &sets, &counters, &stamps, target))
        .collect();
    for state in counters.values() {
        state.blobs.save();
        state.files.save();
    }
    Ok(found)
}

/// A row this write moves in its banned direction: the row, its direction, base
/// and glob, and the target's count before and after the write.
type Moving<'a> = (&'a Rule, Direction, &'a str, &'a str, usize, usize);

/// The rows the write's own move breaches, with no IO: everything later reads
/// only for these.
fn moving_rows<'a>(
    rules: &[&'a Rule],
    target: &str,
    current: Option<&str>,
    projected: &str,
) -> anyhow::Result<Vec<Moving<'a>>> {
    let mut moving = Vec::new();
    for rule in rules {
        let (Some(direction), Some(base), Some(glob)) =
            (rule.direction, rule.base.as_deref(), rule.glob.as_deref())
        else {
            continue;
        };
        if !judged_at_call(rule) || !glob_match(glob, target) {
            continue;
        }
        let tally = ratchet_tally(rule)?;
        let was = current.map_or(0, &tally);
        let now = tally(projected);
        if !direction.violated(was, now) {
            continue;
        }
        // A RISE, said by the direction: a violated row moved, so a
        // non-increasing one rose and a non-decreasing one fell.
        if direction == Direction::NonIncreasing
            && let Some(token) = rule.admits_with.as_deref()
            && !declared_subject(projected, token).is_empty()
        {
            continue;
        }
        moving.push((*rule, direction, base, glob, was, now));
    }
    Ok(moving)
}

/// ONE COUNTER PER DISTINCT DEFINITION, each with its own persisted tables, so
/// every blob and file is read once and counted for all of them.
fn counter_states<'a>(
    moving: &[Moving<'a>],
    root: &Path,
    cache: Option<&Path>,
) -> anyhow::Result<BTreeMap<Vec<u8>, CounterState<'a>>> {
    let mut counters: BTreeMap<Vec<u8>, CounterState<'a>> = BTreeMap::new();
    for (rule, ..) in moving {
        if let std::collections::btree_map::Entry::Vacant(slot) = counters.entry(counter_key(rule))
        {
            let key = slot.key().clone();
            slot.insert(CounterState {
                tally: Box::new(ratchet_tally(rule)?),
                blobs: BlobCounts::load(&key, root, cache),
                files: FileCounts::load(&key, root, cache),
            });
        }
    }
    Ok(counters)
}

/// THE CHANGED SET per (base, glob), keyed by (HEAD, base, glob): two id
/// lookups through one open, so a warm call walks no commit graph and diffs no
/// tree.
fn changed_sets<'a>(
    moving: &[Moving<'a>],
    root: &Path,
    target: &str,
    cache: Option<&Path>,
) -> anyhow::Result<BTreeMap<(&'a str, &'a str), Changed>> {
    let refs: Vec<&str> = std::iter::once("HEAD")
        .chain(moving.iter().map(|(_, _, base, ..)| *base))
        .collect();
    let ids = crate::git::rev_ids(root, &refs)?;
    let head = ids.first().cloned().flatten().unwrap_or_default();
    let mut sets: BTreeMap<(&str, &str), Changed> = BTreeMap::new();
    for (index, (_, _, base, glob, ..)) in moving.iter().enumerate() {
        if sets.contains_key(&(*base, *glob)) {
            continue;
        }
        let base_id = ids.get(index + 1).cloned().flatten().unwrap_or_default();
        let changed = changed_set(root, &head, base, &base_id, glob, target, cache)?;
        sets.insert((*base, *glob), changed);
    }
    Ok(sets)
}

/// Each changed working file's stat, the target excepted (its count is the
/// projected one).
fn working_stamps<'s>(
    sets: &'s BTreeMap<(&str, &str), Changed>,
    root: &Path,
    target: &str,
) -> BTreeMap<&'s str, Option<Stamp>> {
    let mut stamps: BTreeMap<&str, Option<Stamp>> = BTreeMap::new();
    for changed in sets.values() {
        for (path, _) in &changed.paths {
            if path != target {
                stamps
                    .entry(path.as_str())
                    .or_insert_with(|| fs::metadata(root.join(path)).ok().map(|meta| stamp(&meta)));
            }
        }
    }
    stamps
}

/// The base side: each blob no counter holds, inflated once and in parallel,
/// counted for every counter inside its reader. EVERY READ IN FLIGHT BEFORE
/// ANY IS MADE (operator ruling, 2026-11-11): the packs are prefetched first.
fn count_base(
    sets: &BTreeMap<(&str, &str), Changed>,
    counters: &mut BTreeMap<Vec<u8>, CounterState<'_>>,
    root: &Path,
) -> anyhow::Result<()> {
    let base_ids: BTreeSet<&str> = sets
        .values()
        .flat_map(|changed| changed.paths.iter().filter_map(|(_, id)| id.as_deref()))
        .collect();
    let base_ids: Vec<&str> = base_ids.into_iter().collect();
    let unread: BTreeSet<&str> = counters
        .values()
        .flat_map(|state| state.blobs.missing(&base_ids))
        .collect();
    if unread.is_empty() {
        return Ok(());
    }
    let _ = crate::git::prefetch_packs(root);
    let tallies: Vec<&(dyn Fn(&str) -> usize + Sync)> =
        counters.values().map(|state| &*state.tally).collect();
    let unread: Vec<&str> = unread.into_iter().collect();
    let counted = crate::git::map_blobs(root, &unread, &|text: &str| {
        tallies
            .iter()
            .map(|tally| tally(text))
            .collect::<Vec<usize>>()
    })?;
    for (index, state) in counters.values_mut().enumerate() {
        for id in &unread {
            let count = counted.get(*id).map_or(0, |counts| counts[index]);
            state.blobs.counts.insert((*id).to_owned(), count);
        }
        state.blobs.added = true;
    }
    Ok(())
}

/// The working side: every file a counter does not hold at its stamp, read in
/// one completion batch and counted once for every counter.
fn count_working(
    stamps: &BTreeMap<&str, Option<Stamp>>,
    counters: &mut BTreeMap<Vec<u8>, CounterState<'_>>,
    root: &Path,
) {
    let stale: Vec<&str> = stamps
        .iter()
        .filter_map(|(path, stamped)| {
            let stamped = (*stamped)?;
            counters
                .values()
                .any(|state| state.files.fresh(path, stamped).is_none())
                .then_some(*path)
        })
        .collect();
    let sized: Vec<(std::path::PathBuf, u64)> = stale
        .iter()
        .map(|path| {
            let size = stamps
                .get(path)
                .copied()
                .flatten()
                .map_or(0, |(_, _, size, _)| size);
            (root.join(path), size)
        })
        .collect();
    let texts: Vec<Option<String>> = crate::fsio::read_many(&sized)
        .into_iter()
        .map(|bytes| bytes.and_then(|bytes| String::from_utf8(bytes).ok()))
        .collect();
    for (path, text) in stale.iter().zip(texts) {
        let Some(Some(stamped)) = stamps.get(path) else {
            continue;
        };
        let text = text.unwrap_or_default();
        for state in counters.values_mut() {
            state.files.put(path, *stamped, (state.tally)(&text));
        }
    }
}

/// One moving row's verdict: a per-file row against the target's base blob, an
/// aggregate as the summed movement over every changed path.
fn judge(
    (rule, direction, base, glob, was, now): Moving<'_>,
    sets: &BTreeMap<(&str, &str), Changed>,
    counters: &BTreeMap<Vec<u8>, CounterState<'_>>,
    stamps: &BTreeMap<&str, Option<Stamp>>,
    target: &str,
) -> Option<CallRatchet> {
    let changed = &sets[&(base, glob)];
    let state = counters.get(&counter_key(rule))?;
    let breached = if rule.per_file {
        changed
            .paths
            .iter()
            .find(|(path, _)| path == target)
            .and_then(|(_, id)| id.as_deref())
            .is_some_and(|id| direction.violated(state.blobs.get(Some(id)), now))
    } else {
        let mut movement = 0_i64;
        for (path, id) in &changed.paths {
            let working = if path == target {
                now
            } else {
                stamps
                    .get(path.as_str())
                    .copied()
                    .flatten()
                    .map_or(0, |stamped| state.files.fresh(path, stamped).unwrap_or(0))
            };
            movement += signed(working) - signed(state.blobs.get(id.as_deref()));
        }
        match direction {
            Direction::NonDecreasing => movement < 0,
            Direction::NonIncreasing => movement > 0,
        }
    };
    breached.then(|| CallRatchet {
        rule: rule.id.clone(),
        path: target.to_owned(),
        was,
        now,
    })
}

/// One counter's tally and its two persisted tables, for one call.
struct CounterState<'a> {
    tally: Box<dyn Fn(&str) -> usize + Sync + 'a>,
    blobs: BlobCounts,
    files: FileCounts,
}

/// The paths a branch changed under one glob since its merge base, each with
/// its blob id at the base (`None` where it is absent there), the target always
/// among them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Changed {
    paths: Vec<(String, Option<String>)>,
}

/// [`Changed`] for (`head`, `base_id`, `glob`), from the cache when this HEAD
/// was diffed against this base before: the merge base and the tree diff are
/// taken only when HEAD or the base ref moved.
fn changed_set(
    root: &Path,
    head: &str,
    base: &str,
    base_id: &str,
    glob: &str,
    target: &str,
    cache: Option<&Path>,
) -> anyhow::Result<Changed> {
    let entry = cache.map(|dir| {
        let at = dir.join("ratchet-changed").join(
            blake3::hash(format!("{}\0{base}\0{glob}", root.display()).as_bytes())
                .to_hex()
                .as_str(),
        );
        let key = crate::cache::key(
            CALL_RATCHET_FORMAT,
            &[head.as_bytes(), base_id.as_bytes(), glob.as_bytes()],
        );
        (at, key)
    });
    let cached = entry
        .as_ref()
        .and_then(|(at, key)| crate::cache::read(at, key))
        .and_then(|body| serde_json::from_slice::<(String, Changed)>(&body).ok());
    let (merge_base, mut set) = if let Some(cached) = cached {
        cached
    } else {
        // As `ratchet_rule` reads it (CLOUD-405), falling back to the
        // declared ref exactly where it does.
        let merge_base = crate::git::merge_base(root, base)
            .ok()
            .flatten()
            .unwrap_or_else(|| base.to_owned());
        let set = Changed {
            paths: crate::git::blobs_changed_between(root, &merge_base, head, glob)?
                .into_iter()
                .map(|(path, at_base, _)| (path, at_base))
                .collect(),
        };
        if let Some((at, key)) = &entry
            && let Ok(body) = serde_json::to_vec(&(&merge_base, &set))
        {
            crate::cache::write(at, key, &body);
        }
        (merge_base, set)
    };
    // The target is always judged, committed or not.
    if !set.paths.iter().any(|(path, _)| path == target) {
        let at_base = crate::git::blob_ids_at(root, &merge_base, &[target])?.remove(target);
        set.paths.push((target.to_owned(), at_base));
    }
    Ok(set)
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
    let (Some(direction), Some(base)) = (rule.direction, rule.base.as_deref()) else {
        // Unreachable: the census requires both for this kind.
        return Ok(());
    };
    let tally = ratchet_tally(rule)?;

    // THE COUNT IS TAKEN AT THE MERGE BASE, NOT AT THE DECLARED REF'S TIP
    // (CLOUD-405). The question a ratchet asks is "did THIS change move the
    // count", and the commit that question is relative to is where this branch
    // and the declared ref diverged. Counting at the tip asks a different
    // question — "does this branch differ from wherever the ref happens to be
    // right now" — whose answer is a function of WHEN the run happened.
    //
    // Measured 2026-08-11 on CLOUD-122: `verify` green locally and CI red on the
    // same commit, on a branch touching no `.bats` file at all. `main` had gained
    // ten tests while the branch waited; nothing was deleted. Same bytes, two
    // verdicts — which is exactly the property `check` claims to have and did not.
    //
    // The declared `base` column is UNCHANGED and every row still reads
    // `base = "origin/main"`: the ref stays the ref to compare against, and this
    // is the engine resolving it. No row is edited to get the property.
    //
    // It moves verdicts in BOTH directions, which is why it needed its own
    // acceptance. It removes the false refusal above, and it restores one the tip
    // reading can mask: a deletion landing on the base after the merge base
    // raises the base count, which can hide the branch's own deletion inside the
    // aggregate.
    //
    // FALLING BACK TO THE DECLARED REF IS DELIBERATE, and it is the conservative
    // reading rather than a swallowed error. `merge_base` answers `None` for a ref
    // that does not resolve and for two histories that share no commit, and errors
    // when the repository cannot be opened or has no HEAD; in every one of those
    // cases this behaves exactly as it did before, which keeps the refusal below
    // intact — `for_each_blob_at_rev` still raises a `UsageError` for a rev git
    // cannot resolve, so a ratchet that cannot see its baseline still refuses
    // rather than passing.
    let resolved = crate::git::merge_base(root, base)
        .ok()
        .flatten()
        .unwrap_or_else(|| base.to_owned());
    let base = resolved.as_str();

    // The base half, per file rather than summed, so ONE walk answers both the
    // aggregate the direction is judged on and the per-file deltas
    // `retires_with` needs. A row without the column sums this and asks nothing
    // else, which is what makes the column's absence byte-identical to the
    // behaviour before it existed.
    let mut base_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut base_text: BTreeMap<String, String> = BTreeMap::new();
    let retires_with = rule.retires_with.as_deref();
    crate::git::for_each_blob_at_rev(root, base, glob, |path, text| {
        // Counted here rather than inside the walker: a blob decompressed out of
        // the object store is a read this rule caused, and the census must not
        // report a ratchet as cheaper than a forbid merely because its bytes came
        // from git. Counting it in `git.rs` would also point that module at this
        // one, which the layering table declares the wrong way round.
        count_read(text.len());
        base_counts.insert(path.to_owned(), tally(text));
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
        let text = crate::fsio::read_to_string(root.join(path)).unwrap_or_default();
        count_read(text.len());
        let count = tally(&text);
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

    // PER FILE, NO AGGREGATE (CLOUD-2663): each path is judged on its own base
    // count, and the sum is never asked, so one file shrinking cannot pay for
    // another growing.
    if rule.per_file {
        per_file_findings(
            rule,
            direction,
            &base_counts,
            &working_counts,
            &working_declared,
            findings,
        );
        return Ok(());
    }

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
    /// Which dying paths the head tree no longer carries at all (CLOUD-1130).
    ///
    /// The discriminator between a RETIREMENT and a partial reduction, and the two
    /// owe different things. A file that lost one case of twenty is still there,
    /// still runs, and still tests its subject — so a complete ledger for the case
    /// it dropped is the whole of what it owes. A file that is GONE tests nothing
    /// any more, which is the moment its subject's fate becomes a question.
    ///
    /// Read off the head tree's own path list rather than off the pattern counts:
    /// a suite emptied of every case still exists and still owes the weaker
    /// obligation, and a count of zero cannot tell that from a deletion.
    gone: BTreeSet<String>,
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
        if !files.iter().any(|have| have == path) {
            facts.gone.insert(path.clone());
        }
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
fn retirement_blockers(subjects: &SubjectFacts, mapped: &MappedLedger) -> BTreeSet<String> {
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
        if !mapped.mapped(path) {
            blockers.insert(format!("{SUBJECT_UNDECLARED} {path}"));
        }
    }
    // AND THE LEDGER DISCHARGES THE MAPPING, NEVER THE SUBJECT'S DEATH
    // (CLOUD-1130). The arm above read as a substitute for both questions, so a
    // suite could be deleted with a complete per-case ledger while the program it
    // tested stayed alive and untested: `fully_mapped` filtered the path out of
    // this loop before `SUBJECT_ALIVE` could be reached, and no other predicate
    // in either authority relates a suite to its subject. Measured green on the
    // tree as it stood.
    //
    // WHAT SEPARATES CLOUD-1050'S CASE FROM THAT EXPLOIT IS ONE QUESTION: is the
    // surviving subject the very thing the cases were mapped ONTO? A suite whose
    // subject is a `.rego` module the migration keeps and rewrites names that
    // module as its arms' target, so the ledger says where the logic went AND
    // accounts for the survivor. A suite mapped onto a policy module and a Rust
    // test while its shell program stands untouched names the survivor nowhere,
    // and that is the shape with no answer. So the mapping stays an admission and
    // gains a term rather than being removed.
    //
    // NOTHING HERE INFERS A SUBJECT FROM A FILENAME. The subject is the one
    // `retires_with`'s `# subject:` marker declared, read out of the base text by
    // `subject_facts`; 19 of this repository's 142 suites have no same-named
    // program, so a stem pairing would refuse those and admit the exploit
    // elsewhere.
    for (path, declared) in &subjects.declared {
        if let Some(targets) = mapped.targets(path) {
            // A PARTIAL REDUCTION IS NOT A RETIREMENT, and only the second one
            // raises the question. A suite that dropped one case still stands and
            // still tests its subject, so the ledger for that case is all it owes;
            // demanding subject death there is the wall CLOUD-1050 removed.
            if !subjects.gone.contains(path) {
                continue;
            }
            for subject in declared {
                // A SUBJECT THAT NEVER EXISTED IS NOT A DEAD ONE, and the ledger
                // does not discharge that either. `# subject: programs/typo` plus
                // a complete ledger otherwise reads as "the thing this tested is
                // gone", when what it says is that the header names nothing the
                // base tree ever carried — so the claim is unverifiable rather
                // than satisfied, and the same fabricated header buys the
                // deletion under any marker.
                //
                // PRE-EXISTING rather than opened by CLOUD-1130: the
                // `fully_mapped` filter this arm replaced skipped these paths
                // before either question was asked, so the check was unreachable
                // for a mapped path then too. Closed here because it is one
                // conjunct in the arm being rewritten, not because it regressed.
                if !subjects.alive_at_base.contains(subject) {
                    blockers.insert(format!("{SUBJECT_NEVER_EXISTED} {subject}"));
                    continue;
                }
                if subjects.still_present.contains(subject) && !targets.contains(subject) {
                    blockers.insert(format!("{SUBJECT_ALIVE} {subject}"));
                }
            }
            continue;
        }
        for subject in declared {
            if !subjects.alive_at_base.contains(subject) {
                blockers.insert(format!("{SUBJECT_NEVER_EXISTED} {subject}"));
            } else if subjects.still_present.contains(subject) {
                blockers.insert(format!("{SUBJECT_ALIVE} {subject}"));
            }
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
        carried: Vec::new(),
        owner: None,
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
        reason: None,
    });
}

/// One finding per path whose own count moved the banned way (CLOUD-2663).
///
/// Judged over the union of base and working paths. A path absent at base has
/// no ceiling and is skipped; a path absent now counts `0`, so a deletion is a
/// fall exactly as the aggregate reads it. A rising path that declares the
/// `admits_with` token is admitted, and one that does not is refused with the
/// same blocker an aggregate row prints.
fn per_file_findings(
    rule: &Rule,
    direction: Direction,
    base_counts: &BTreeMap<String, usize>,
    working_counts: &BTreeMap<&str, usize>,
    working_declared: &BTreeSet<&str>,
    findings: &mut Vec<Finding>,
) {
    let paths: BTreeSet<&str> = base_counts
        .keys()
        .map(String::as_str)
        .chain(working_counts.keys().copied())
        .collect();
    for path in paths {
        let Some(&was) = base_counts.get(path) else {
            continue;
        };
        let now = working_counts.get(path).copied().unwrap_or(0);
        if !direction.violated(was, now) {
            continue;
        }
        let mut blockers = BTreeSet::new();
        // A RISE, said by the direction: the row was violated, so it moved.
        if rule.admits_with.is_some() && direction == Direction::NonIncreasing {
            if working_declared.contains(path) {
                continue;
            }
            blockers.insert(format!("{GROWTH_UNDECLARED} {path}"));
        }
        ratchet_finding(rule, path, was, now, &blockers, findings);
    }
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
pub(crate) fn declared_subject(text: &str, token: &str) -> BTreeSet<String> {
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
    /// It moved to a new home and the subject STAYED (CLOUD-1268). Owes a target
    /// AND the surviving subject, and is admissible only where the dying file's
    /// declared subject is still standing — the exact mirror of [`Arm::Withdrawn`].
    Ported,
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
            Arm::Ported => "ported",
        }
    }

    /// Whether this arm names a successor the head tree must carry.
    ///
    /// Four of the five do, and the exception is the whole point of `withdrawn`:
    /// a withdrawal has no successor, so demanding a resolvable target would
    /// force the author back to the false `subsumed` this arm exists to replace.
    /// `ported` is on the demanding side and then owes a second field besides —
    /// it is the arm that obliges MOST, which is what keeps it from being a way
    /// around the subject-alive refusal rather than a spelling for it.
    const fn owes_a_target(self) -> bool {
        !matches!(self, Arm::Withdrawn)
    }

    /// Whether this arm names the surviving subject it continues to account for.
    ///
    /// Only `ported` does. The other four describe a subject that died with the
    /// suite or that the ledger never had to mention, so a field demanded of them
    /// would be ceremony; here it is the only thing a reader can check the claim
    /// against, exactly as `withdrawn`'s reason is.
    const fn owes_a_subject(self) -> bool {
        matches!(self, Arm::Ported)
    }
}

/// The declared-subject set for a path whose base header named none.
///
/// A `static` rather than a per-call allocation, and at module scope rather than
/// inside the loop that reads it, because `items_after_statements` is right: an
/// item declared mid-function is in scope from the top of the block regardless of
/// where it is written.
static NO_SUBJECTS: BTreeSet<String> = BTreeSet::new();

/// The marked field a [`Arm::Ported`] row names its surviving subject with.
///
/// Marked rather than positional for the reason the `runs:` and `kind:` fields
/// already give on their own rows: nothing positional separates the tail's fields,
/// because more than one of them is optional.
const PORTED_SUBJECT_FIELD: &str = "subject:";

/// The surviving subject a `ported` arm's tail declares, if it declares one.
fn ported_subject(reason: &str) -> Option<&str> {
    reason
        .split_whitespace()
        .find_map(|field| field.strip_prefix(PORTED_SUBJECT_FIELD))
        .filter(|subject| !subject.is_empty())
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
    /// What THIS path's `# subject:` header declared at base (CLOUD-1268).
    ///
    /// The [`Arm::Ported`] arm's anti-fabrication term. Its `subject:` field has
    /// to name one of these, so an author cannot pick a convenient survivor: the
    /// subject is the one the DYING FILE declared, read out of the base text by
    /// [`subject_facts`], never chosen on the row. Passed in for
    /// [`Mapping::subject_died`]'s reason — one reader of the base header, not two.
    declared_subjects: &'a BTreeSet<String>,
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
    // The two optional arms are included only where the row declares them, so a
    // row without either column reads exactly the three tokens it always did.
    let mut arms = vec![
        (Arm::Carried, conserves.carried.as_str()),
        (Arm::Subsumed, conserves.subsumed.as_str()),
        (Arm::Changed, conserves.changed.as_str()),
    ];
    if let Some(token) = conserves.withdrawn.as_deref() {
        arms.push((Arm::Withdrawn, token));
    }
    if let Some(token) = conserves.ported.as_deref() {
        arms.push((Arm::Ported, token));
    }
    let mut claimed = ClaimedCases::default();
    for path in files.iter().filter(|path| selector.matches(path)) {
        let Ok(text) = crate::fsio::read_to_string(root.join(path)) else {
            continue;
        };
        count_read(text.len());
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
    targets: &mut BTreeSet<String>,
) {
    let Mapping {
        conserves, claimed, ..
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
            [claim] => resolved_claim(rule, claim, &case, mapping, findings, targets),
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

/// What the ONE arm claiming a case owes, which differs by arm.
///
/// Four owe a target this tree carries; `changed` owes a reason besides;
/// `withdrawn` owes a reason and a DEAD subject INSTEAD of a target; `ported`
/// owes a target and a LIVE subject the dying file itself declared.
///
/// Extracted from [`unconserved_cases`] so that function stays under the line
/// lint, and the seam is the natural one: everything above it resolves a case
/// NAME to its claims, and everything here judges the claim that resolved.
fn resolved_claim(
    rule: &Rule,
    claim: &Claim,
    case: &str,
    mapping: &Mapping<'_>,
    findings: &mut Vec<Finding>,
    targets: &mut BTreeSet<String>,
) {
    let &Mapping {
        files,
        subject_died,
        declared_subjects,
        ..
    } = mapping;
    if !claim.arm.owes_a_target() {
        // THE CONDITION THAT KEEPS THIS NARROWER THAN A WAIVER (CLOUD-1080). A
        // withdrawal is only honest where the subject went with it; over a subject
        // still standing this arm would be a blanket permission to delete cases,
        // which is the thing the column exists to refuse. `subject_died` comes
        // from `subject_facts`, the same read the aggregate admission uses.
        if !subject_died {
            push_case_finding(
                rule,
                &claim.path,
                claim.line,
                case,
                CASE_WITHDRAWN_SUBJECT_ALIVE,
                findings,
            );
        } else if claim.target.trim().is_empty() && claim.reason.trim().is_empty() {
            // No target to name, so the whole tail is the reason — and it is owed,
            // because "nothing replaces this" is a claim a reader has to be able
            // to check.
            push_case_finding(
                rule,
                &claim.path,
                claim.line,
                case,
                CASE_WITHDRAWAL_UNEXPLAINED,
                findings,
            );
        }
        return;
    }
    if !files.iter().any(|have| have == &claim.target) {
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_TARGET_MISSING,
            findings,
        );
        return;
    }
    // A RESOLVED TARGET, RECORDED (CLOUD-1130). Only one this tree actually
    // carries: an arm naming a path that is not there was refused above, and
    // letting it count toward the aggregate admission would let a fabricated
    // successor name a surviving subject into acceptability.
    targets.insert(claim.target.clone());
    if claim.arm == Arm::Changed && claim.reason.trim().is_empty() {
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_CHANGE_UNEXPLAINED,
            findings,
        );
    }
    if claim.arm.owes_a_subject() {
        ported_subject_finding(
            rule,
            claim,
            case,
            subject_died,
            declared_subjects,
            files,
            findings,
            targets,
        );
    }
}

/// What a [`Arm::Ported`] claim owes beyond its target (CLOUD-1268).
///
/// Extracted rather than inlined for [`retirement_blockers`]'s reason: the branch
/// it hangs off is already the widest in [`unconserved_cases`], and each clause
/// below carries its own argument.
///
/// # Pointer-only (non-negotiable rule 4)
///
/// Every finding points at the ARM's own file and line, because that is where the
/// fix goes, and carries the case name the arm already spells. Never a case body
/// and never a line of the dying suite.
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a distinct fact one clause below reads, and the alternative is a struct that exists only to be destructured at the single call site"
)]
fn ported_subject_finding(
    rule: &Rule,
    claim: &Claim,
    case: &str,
    subject_died: bool,
    declared_subjects: &BTreeSet<String>,
    files: &[String],
    findings: &mut Vec<Finding>,
    targets: &mut BTreeSet<String>,
) {
    // THE MIRROR OF `withdrawn`'s CONDITION, and it is what keeps the two arms
    // from overlapping. A port-without-retirement describes a subject that STAYED;
    // over a subject that died it is a plain retirement wearing a longer row, and
    // `carried` already spells that with less. Admitting both here would make the
    // ledger record the same event two ways, which is the drift every seam in this
    // file is written to avoid.
    if subject_died {
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_PORT_SUBJECT_DEAD,
            findings,
        );
        return;
    }
    let Some(subject) = ported_subject(&claim.reason) else {
        // NAMING THE SURVIVOR IS THE WHOLE ARM. Without the field this is
        // `carried` with a different word on it, and it would clear the aggregate
        // subject-alive term while accounting for nothing — the exploit CLOUD-1130
        // closed, re-opened by a fifth marker. So the field is owed, not optional.
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_PORT_SUBJECT_UNNAMED,
            findings,
        );
        return;
    };
    // THE ANTI-FABRICATION TERM. The subject is the one the DYING FILE declared in
    // its own `# subject:` header at base, so an author cannot name a convenient
    // survivor and buy the deletion with it. This is the same discipline
    // `retirement_blockers` applies one level up — nothing here infers a subject
    // from a filename, and nothing takes the author's word for it.
    if !declared_subjects.contains(subject) {
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_PORT_SUBJECT_UNDECLARED,
            findings,
        );
        return;
    }
    // A SUBJECT THIS TREE DOES NOT CARRY IS NOT A SURVIVING ONE. Reported as a
    // missing target rather than a fifth token: the arm named a path the tree does
    // not have, which is exactly what that refusal already says.
    if !files.iter().any(|have| have == subject) {
        push_case_finding(
            rule,
            &claim.path,
            claim.line,
            case,
            CASE_TARGET_MISSING,
            findings,
        );
        return;
    }
    // AND THE SURVIVOR TRAVELS WITH THE VERDICT. This is the one line that makes
    // the arm do anything: `retirement_blockers` clears its subject-alive term for
    // a subject the ledger NAMES, so recording it here is how a complete port arm
    // buys the deletion — honestly, by accounting for the survivor, rather than by
    // a `carried` row falsely claiming the case moved into it.
    targets.insert(subject.to_owned());
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
) -> MappedLedger {
    let mut fully_mapped = MappedLedger::default();
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
        let survivors = crate::fsio::read_to_string(root.join(path)).unwrap_or_default();
        count_read(survivors.len());
        let mapping = Mapping {
            conserves,
            claimed,
            files,
            subject_died: subjects.died(path),
            // EMPTY WHERE THE FILE DECLARED NO SUBJECT, which refuses rather than
            // admits: a `ported` arm naming anything at all then fails the
            // containment test, so a headerless suite cannot be ported. That is
            // the right direction — a file with no declared subject has nothing
            // for the arm to account for, and `SUBJECT_UNDECLARED` is already the
            // verdict for it.
            declared_subjects: subjects.declared.get(path).unwrap_or(&NO_SUBJECTS),
        };
        // PER PATH, so the mapped-successor arm below can ask about one file
        // (CLOUD-1050). A path whose every dropped case resolved to exactly one
        // well-formed arm has had its logic accounted for, which is a different
        // question from whether its SUBJECT died — and it is the question a
        // migration can actually answer when the subject is a `.rego` module
        // that is still very much alive.
        let before = findings.len();
        // AND WHAT THE ARMS NAMED TRAVELS WITH THE VERDICT (CLOUD-1130). The
        // aggregate admission needs to know not only that every dropped case
        // resolved, but WHERE to — a surviving subject that is itself the
        // successor is accounted for, and one the ledger never mentions is not.
        // Collected here rather than re-derived, because resolving a case name to
        // its arm is `unconserved_cases`'s own reading and a second walk over the
        // same ledger is a second authority over it.
        let mut targets = BTreeSet::new();
        unconserved_cases(
            rule,
            path,
            text,
            &survivors,
            &mapping,
            findings,
            &mut targets,
        );
        if findings.len() == before {
            fully_mapped.targets.insert(path.clone(), targets);
        }
    }
    fully_mapped
}

/// What a COMPLETE ledger named, per dying path (CLOUD-1130).
///
/// A path is present exactly when every case it dropped resolved to one
/// well-formed arm — which is what [`conserve_case_names`] used to report as a
/// bare set — and its value is the successors those arms named. The value is the
/// half that was missing: "the cases are accounted for" and "the thing this file
/// tested is accounted for" are two questions, and a set of paths can only answer
/// the first.
///
/// Empty for a `withdrawn` arm, which names no successor by design. That is the
/// right reading rather than a gap: a withdrawal's subject died, so the aggregate
/// admission's subject-alive term does not hold for it anyway.
#[derive(Debug, Default)]
struct MappedLedger {
    /// Dying path -> the successors its arms named.
    targets: BTreeMap<String, BTreeSet<String>>,
}

impl MappedLedger {
    /// Whether this path's dropped cases were fully mapped.
    fn mapped(&self, path: &str) -> bool {
        self.targets.contains_key(path)
    }

    /// The successors this path's arms named, or `None` where it was not fully
    /// mapped — a distinction the caller reads, since "mapped onto nothing" and
    /// "not mapped" are different admissions.
    fn targets(&self, path: &str) -> Option<&BTreeSet<String>> {
        self.targets.get(path)
    }
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
        carried: Vec::new(),
        owner: None,
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: path.to_owned(),
        line: Some(line),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
        reason: None,
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

/// A `ported` arm over a subject that died with the suite (CLOUD-1268).
///
/// The mirror of [`CASE_WITHDRAWN_SUBJECT_ALIVE`], and the pair is what keeps the
/// two arms from describing one event two ways: `carried` already spells a
/// retirement, with less.
const CASE_PORT_SUBJECT_DEAD: &str = "case-port-subject-dead";

/// A `ported` arm that names no surviving subject.
///
/// Without the field the arm is `carried` under another word, and it would clear
/// the aggregate subject-alive term while accounting for nothing — CLOUD-1130's
/// exploit re-opened by a fifth marker.
const CASE_PORT_SUBJECT_UNNAMED: &str = "case-port-subject-unnamed";

/// A `ported` arm naming a subject the dying file never declared.
///
/// The anti-fabrication term: the subject is the one the base `# subject:` header
/// carried, never one chosen on the row to make the deletion buyable.
const CASE_PORT_SUBJECT_UNDECLARED: &str = "case-port-subject-undeclared";

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
        carried: Vec::new(),
        owner: None,
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: path.to_owned(),
        line: Some(line),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
        reason: None,
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

/// The executable extensions to try after the bare name, parsed from a
/// `PATHEXT` value.
///
/// The callers pass the variable, because a host may add to it; Windows sets it
/// in every environment it starts. Empty where it is unset, which on Unix is by
/// construction: the bare name is the only spelling there, so this costs a
/// lookup that finds what a direct spawn already would. An argument rather
/// than a read, so the Windows spelling is parsed on every leg (CLOUD-2509):
/// `set_var` is `unsafe`, so no unix case could set it.
fn executable_extensions(pathext: Option<&std::ffi::OsStr>) -> Vec<String> {
    let Some(raw) = pathext else {
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
    lookup_on(
        program,
        path,
        &executable_extensions(std::env::var_os("PATHEXT").as_deref()),
    )
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

/// `pr watch --progress`'s recorder, run as a program the CALLER names
/// (CLOUD-2789): resolved through [`spawn_resolving`], the engine's one way to
/// find a program, and handed to `pr_watch` as its `spawn`, so that module names
/// nothing above it. Every failure is ignored: progress is a signal, never a
/// verdict.
pub fn record_progress(program: &str, args: &[String]) {
    let _ = spawn_resolving(Some(Path::new(".")), program, |program, extra| {
        quiet_status(Path::new("."), program, extra, args)
    });
}

/// Run `program` with `extra` then `args` at `root`, both of its outputs
/// discarded, and answer its exit status: the one spawn a `command` rule's
/// checker and `pr watch --progress`'s recorder share. Both are a program the
/// CALLER names, so neither has an in-process form, and the verdict is the
/// exit code alone, never what the program said (CLOUD-93).
///
/// ONE ESCAPE FOR BOTH (CLOUD-2789): the recorder's own copy, moved here from
/// the crate root, was a second census row for the same spawn.
#[expect(
    clippy::disallowed_types,
    reason = "stays: a `command` rule IS a consumer's checker program, and the progress recorder a program its caller names, which is why the kind carries ambient authority and `RuleKind::scopes` keeps it off the mediated call entirely (CLOUD-763, CLOUD-320)"
)]
fn quiet_status(
    root: &Path,
    program: &str,
    extra: &[&str],
    args: &[impl AsRef<std::ffi::OsStr>],
) -> std::io::Result<std::process::ExitStatus> {
    std::process::Command::new(program)
        .args(extra)
        .args(args)
        .current_dir(root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
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
    spawn_resolving_pinned(&TOOLCHAIN, root, program, spawn)
}

/// Where [`spawn_resolving`] asks the toolchain pin: the cheap reading, the
/// eager repair and the lazy re-ask, as [`crate::pinned`] answers them.
///
/// A table of functions rather than direct calls so a case can stand up a pin
/// that answers each rung as it needs, which a real pin cannot be made to do on
/// demand: a record that stops answering mid-session is the case both repairs
/// exist for.
struct Toolchain {
    cached: fn(&Path) -> crate::pinned::PinnedFacts,
    repaired: fn(&Path) -> crate::pinned::PinnedFacts,
    re_resolved: fn(&Path) -> crate::pinned::PinnedFacts,
}

/// The pin [`spawn_resolving`] asks outside a case.
const TOOLCHAIN: Toolchain = Toolchain {
    cached: crate::pinned::cached,
    repaired: crate::pinned::repaired,
    re_resolved: crate::pinned::re_resolved,
};

/// [`spawn_resolving`] over the pin `toolchain` answers.
fn spawn_resolving_pinned<T>(
    toolchain: &Toolchain,
    root: Option<&Path>,
    program: &str,
    spawn: impl FnMut(&str, &[&str]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    // THE PIN IS READ FIRST, AND ASKED ONLY WHERE THE READING CANNOT ANSWER.
    // `pinned::cached` is a file read with an honest could-not-look, so the
    // ordinary call pays a file read and nothing else.
    //
    // THE REPAIR IS HERE RATHER THAN AT THE FOOT OF THE LADDER (CLOUD-1324). The
    // record is memoised and keyed to the pin's configuration as it stands, so a
    // manifest edited mid-session invalidates it and every pinned program reads
    // as missing until the next session start — measured: one of the pin's own
    // configuration files changed, a record written the previous day stopped
    // validating, and a `command` rule could not launch the tool it declared.
    // The files and the tool go unnamed deliberately: they are a consumer's, and
    // this crate may not carry one (non-negotiable rule 1).
    //
    // A STALE MEMO IS THE ENGINE'S OWN BOOKKEEPING, NOT A FACT ABOUT THE TREE,
    // and it must not decide whether a gate can run. So could-not-look re-asks
    // the pin and re-records, and the next call is a file read again.
    //
    // Repairing the ANSWER rather than delegating the SPAWN is the part that has
    // to stay this way. A recovery rung that handed an unresolved program to the
    // runner would spawn the runner successfully and report a program the pin
    // does not provide as ran-and-failed, which is a different fix from
    // not-installed and the distinction `action` reports on.
    //
    // `IsNot` is left alone rather than folded into the repair: it is a resolved
    // answer — the pin was reached and provides nothing — and re-asking would
    // turn every unpinned project's spawn into two.
    //
    // Bounded to ONCE PER ROOT PER PROCESS by `pinned::repaired`, and that bound
    // is not an optimisation — see its own doc for what an unbounded repair costs.
    let read = root.map_or(crate::facts::Look::CouldNotLook, toolchain.cached);
    // Kept as a bool rather than by cloning the set: the retry below asks only
    // whether the CHEAP reading could answer, and a clone here would copy every
    // pinned program's name on the ordinary path to serve one branch that rarely
    // runs.
    let unread = matches!(read, crate::facts::Look::CouldNotLook);
    let pinned = match (&read, root) {
        (crate::facts::Look::CouldNotLook, Some(root)) => (toolchain.repaired)(root),
        _ => read,
    };
    let path = std::env::var_os("PATH");
    let extensions = executable_extensions(std::env::var_os("PATHEXT").as_deref());
    // THE IMAGE THAT ASKS, for rung -1 (CLOUD-2386). `ok()` rather than a
    // refusal: an unreadable `/proc` is a fact about this process, not about the
    // row, and the ladder then decides exactly as it did before the rung existed.
    //
    // ASKED ONLY WHERE THE RUNG CAN FIRE, for the reason the `unread` bool above
    // is a bool: the overwhelming majority of declared programs are `hk`, a
    // judge stub, a sweep row — never `batten` — and a readlink of
    // `/proc/self/exe` plus its allocation on every one of them buys a branch
    // that rarely runs.
    let running = is_own_image(program)
        .then(std::env::current_exe)
        .and_then(Result::ok);
    let mut spawn = spawn;
    let first = spawn_resolving_on_image(
        path.as_deref(),
        root,
        running.as_deref(),
        program,
        &extensions,
        &pinned,
        &mut spawn,
    );

    // AND ONE LAST ASK, ONLY ONCE THE LADDER HAS ALREADY FAILED (CLOUD-1371).
    //
    // The eager repair above fires only where a record EXISTS and stopped
    // answering, which leaves the case that cost a whole session: a record that
    // STOPS EXISTING mid-session. Nothing re-created it, `cached` answered
    // could-not-look forever, and every pinned program read as absent until the
    // next session start — measured in this container, where `no-conflict-markers`
    // could not launch the tool it declares while `doctor` reported the record
    // healthy.
    //
    // LAZY IS WHAT MAKES IT AFFORDABLE, and it is the whole reason the ask is
    // here rather than folded into the eager arm. An unbounded eager repair pays
    // two runner spawns for every program of every rule — measured as fixture
    // `git commit`s at ~50x under a parallel suite. Asked here it costs nothing
    // on every path that resolves, and a root only reaches it by failing a spawn
    // outright, which is the exception rather than the rule.
    //
    // THE RECOVERY-RUNG DISTINCTION IS PRESERVED, which is the constraint the
    // foot of the ladder refuses to give up: the retry happens only when the
    // REFRESHED answer says the pin provides THIS program. A program nothing
    // provides still comes back as could-not-spawn rather than as ran-and-failed,
    // so `action` can still tell not-installed from a real failure.
    if first.as_ref().err().map(std::io::Error::kind) == Some(std::io::ErrorKind::NotFound)
        && unread
        && let Some(root) = root
    {
        let afresh = (toolchain.re_resolved)(root);
        if matches!(&afresh, crate::facts::Look::Is(programs) if programs.contains(program)) {
            // The imageless arity, because rung -1 already had its turn: this
            // retry is reached only once the ladder itself failed, and
            // re-offering the image would spawn a file that just declined to
            // run (CLOUD-2386).
            return spawn_resolving_on(
                path.as_deref(),
                root.into(),
                program,
                &extensions,
                &afresh,
                spawn,
            );
        }
    }
    first
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
///
/// NO RUNNING IMAGE (CLOUD-2386). [`spawn_resolving_on_image`] is the whole
/// ladder; this is that ladder with no image, which is what a caller holding no
/// readable `/proc` has — and what the CLOUD-1371 re-resolve retry wants, since
/// rung -1 has already had its turn by then. Keeping this arity also keeps every
/// case written against it running unmodified.
fn spawn_resolving_on<T>(
    path: Option<&std::ffi::OsStr>,
    root: Option<&Path>,
    program: &str,
    extensions: &[String],
    pinned: &crate::pinned::PinnedFacts,
    spawn: impl FnMut(&str, &[&str]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    spawn_resolving_on_image(path, root, None, program, extensions, pinned, spawn)
}

/// Whether a declared program names this engine, and so resolves to the running
/// image rather than to `PATH` or the pin (CLOUD-2386).
///
/// One definition, because `doctor` mirrors this rung in two probes and a grep
/// for the predicate has to find them: a widening here that the probes missed is
/// exactly the disagreement `handler_program_resolves` exists to refuse.
pub(crate) fn is_own_image(program: &str) -> bool {
    program == crate::surface::BINARY
}

/// Whether a running image's file is this engine's binary, and not a test
/// harness or a replaced file that only shares its path.
fn names_this_engine(image: &Path) -> bool {
    image
        .file_stem()
        .is_some_and(|stem| stem == crate::surface::BINARY)
}

/// Whether a spawn of the running image failed because the FILE could not be
/// executed, rather than with an answer of the image's own.
fn image_unusable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ExecutableFileBusy
            | std::io::ErrorKind::PermissionDenied
    )
}

/// [`spawn_resolving_on`], plus the image that asked — the full ladder, rung -1
/// included.
fn spawn_resolving_on_image<T>(
    path: Option<&std::ffi::OsStr>,
    root: Option<&Path>,
    running: Option<&Path>,
    program: &str,
    extensions: &[String],
    pinned: &crate::pinned::PinnedFacts,
    mut spawn: impl FnMut(&str, &[&str]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    // RUNG -1: A DECLARED `batten` IS THE ENGINE ASKING ITSELF, SO THE ENGINE
    // THAT ASKS IS THE ONE THAT ANSWERS (CLOUD-1326, CLOUD-2386).
    //
    // `run = ["batten", ...]` is the engine asking itself a question. Resolved on
    // `PATH` that is whatever RELEASE is installed, answering about a tree it was
    // not built from: a row added in the same commit as the verb it calls is a
    // handler that silently cannot run until the next release, and a row whose
    // answer changed in the tree keeps reporting the old one. Structural version
    // skew inside batten's own hook, and it is the quiet half of the same class
    // that killed `.mcp.json` — quiet only because `doctor egress` happens to be
    // released.
    //
    // ONE PREDICATE, HERE, RATHER THAN AT ONE SPAWN SITE (CLOUD-2386). This began
    // as `handler.rs`'s own mapping, which left every other declared argv
    // resolving on `PATH`: the `[[board.sweep]]` rows, the lease census notes, a
    // declared repair, and the generic declared-argv spawns. Under a source pin,
    // or after `engine update`, each of those children ran a different engine
    // from the one that spawned it. Every caller of this resolver is covered now,
    // the operator-typed `batten exec -- batten …` included, and that is intended.
    // `mutate::spawn_as` is not a caller: it spawns its declared runner directly,
    // so a `[mutate]` row naming `batten` still resolves on `PATH`.
    //
    // BEFORE THE PIN, which is what makes it a rung rather than a preference. The
    // pin rung below fires only where `PATH` cannot resolve the program, so a
    // `batten` the pin provides and `PATH` cannot see would otherwise be spawned
    // through the mediator — the pinned release, not this image.
    //
    // AN IMAGE THE RUNG DECLINES FALLS THROUGH, AND IS NOT RETRIED. After
    // `engine update` replaces the file, Linux resolves `/proc/self/exe` to a
    // path marked `… (deleted)`, which the stem check below declines, and the
    // ladder then reaches the release the operator just installed — the right
    // answer rather than a consolation. CLOUD-1371's re-resolve branch therefore
    // sees only the ladder's own result. (The unreadable case is decided in
    // `spawn_resolving_pinned`, where the image is read.)
    //
    // ONLY AN IMAGE NAMED `batten` IS THIS ENGINE. Under `cargo test`,
    // `current_exe` is the TEST HARNESS, and libtest reads the declared verb's
    // words as test-name filters: an in-process case reaching this resolver
    // spawned the harness, which ran every case matching `board`, `check` or
    // `config` in parallel, each able to spawn it again. Measured: two full
    // `verify` runs on this change each ended with the container at a load
    // above 7000 and out of memory. A comment saying no such case existed was
    // the only guard; the stem is the mechanism.
    //
    // ONLY AN IMAGE THAT COULD NOT BE EXECUTED FALLS THROUGH: gone (`NotFound`),
    // mid-rebuild (`ExecutableFileBusy`), or not executable
    // (`PermissionDenied`). Those are facts about the file, and the release on
    // `PATH` can still answer; a handler handed one of them would otherwise
    // allow unjudged. Any other error — `EAGAIN` from a fork under pressure, or
    // a closure's failure after the child already ran — is the image's answer,
    // and walking the ladder on it would add spawns while forking fails, or run
    // a side-effecting row twice on a different engine.
    if is_own_image(program)
        && let Some(image) = running
            .filter(|image| names_this_engine(image))
            .and_then(Path::to_str)
    {
        match spawn(image, &[]) {
            Err(error) if image_unusable(&error) => {}
            other => return other,
        }
    }

    // RUNG 0: THE PIN, AND IT IS FIRST RATHER THAN A FALLBACK (CLOUD-1324).
    //
    // A project that pins its tools gets the pinned ones, so where the pin
    // provides this program the pinned build IS the program and a `PATH` hit
    // would be a different one — a different version, a different environment.
    // That is `pinned-toolchain`'s own argument, which refuses exactly this for
    // an agent's argv; the engine's own spawn had no such rung and reached
    // around the pin every time.
    //
    // MEASURED: `no-conflict-markers` declared `hk`, nothing a toolchain manager
    // provides is on bare `PATH` -- nor should it be -- so the rule could not
    // launch and contributed nothing. A merge-conflict gate that silently never
    // ran, and `doctor` could say only that SOME declared program was missing.
    //
    // REWRITTEN RATHER THAN REFUSED, which is the whole point: a config row names
    // the tool it means, the boundary resolves how to reach it, and no author has
    // to know that the answer is spelled through a runner. A gate refusing the
    // direct spelling would put that knowledge back on every author and every
    // consumer, for a problem the engine can simply solve.
    //
    // Could-not-look falls straight through to the ladder below. A pin that
    // cannot be read is not evidence the program is unpinned, and refusing on it
    // would make every spawn depend on a memoised file.
    // AND IT FIRES ONLY WHERE `PATH` HAS NO ANSWER, which is the bound the first
    // version lacked and which cost a whole landing lap to find.
    //
    // The motivating case is a program `PATH` cannot resolve at all: a tool the
    // pin installs into a directory the ambient `PATH` never carries. Where
    // `PATH` DOES resolve the name, that resolution is by construction not the
    // pin's own — this fact is the DIFFERENCE between the composed and the
    // ambient `PATH`, so the pin's directories are the ones `PATH` does not have
    // — which makes a hit here a directory the caller deliberately put in front.
    //
    // MEASURED, and by the worst instrument available: `pr_watch`'s fixture
    // stubs the forge's client at the head of `PATH` and hands the binary that
    // `PATH`. The client is pinned, so an unbounded rung 0 reached past the stub
    // to the real program, which then polled a network this container fences —
    // four tests that never terminated, a `verify` that could not finish inside
    // the window `main` stays still for, and two landing laps lost to what looked
    // like contention. A gate cannot be stubbed if the boundary refuses to be
    // told what to run.
    //
    // Nothing the rung was built for is given up. A pinned program `PATH` cannot
    // see still reaches the mediator here; a pinned program `PATH` CAN see is
    // found by the next rung, which is either the pin's own shim or the override
    // the caller composed — and both are the answer that caller asked for.
    if matches!(pinned, crate::facts::Look::Is(programs) if programs.contains(program))
        && path
            .and_then(|path| lookup_on(program, path, extensions))
            .is_none()
    {
        let (mediator, prefix) = crate::pinned::mediated(program);
        let prefix: Vec<&str> = prefix.iter().map(String::as_str).collect();
        if let Ok(ok) = spawn(mediator, &prefix) {
            return Ok(ok);
        }
    }

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

    // NO RECOVERY RUNG HERE, DELIBERATELY. Handing an unresolved program to the
    // runner as a last resort spawns the runner — which is on `PATH`, that being
    // what a pin IS — so it succeeds, and a program nothing provides comes back
    // as ran-and-failed instead of could-not-spawn. Measured on
    // `action::tests::a_clean_action_says_nothing_and_an_unspawnable_one_is_distinguishable`:
    // not-installed is a different fix from ran-and-failed, and that rung erased
    // the difference. The staleness this was reaching for is repaired in
    // `spawn_resolving`, over the ANSWER rather than over the spawn.
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
    let spawn =
        |program: &str, args: &[&str], extra: &[&str]| quiet_status(root, program, extra, args);

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
            carried: Vec::new(),
            owner: None,
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
            reason: None,
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
///
/// **A finding from an `approximating` kind can never make this true**
/// (CLOUD-331), and the bound sits INSIDE the `any` rather than beside its call
/// sites deliberately: `--fail-on-warning` promotes through
/// [`severity::promote`], so a bound applied outside would be reachable by that
/// flag and the whole claim would be one CLI argument from false. Here the flag
/// promotes a level that is then discarded, which is why "no flag combination
/// blocks an approximating rule" is a property of this function rather than a
/// convention its callers keep.
#[must_use]
pub fn any_blocking(findings: &[Finding], fail_on_warning: bool, rules: &[Rule]) -> bool {
    findings.iter().any(|finding| {
        decidability_of(finding, rules).may_block()
            && severity::report_for(finding.severity, fail_on_warning) == ReportLevel::Fail
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

/// Evaluate a [`RuleKind::Forbid`] row against every path its glob selected.
///
/// **The whole matched set, not one path** (CLOUD-1217), and that boundary is
/// the fix rather than a refactor. The predecessor took one `rel_path` and was
/// called once per file from [`run_rule`], so [`Matcher::for_rule`] — and with
/// it `Regex::new` — ran once per *(rule, file)* pair. Over this repository's own
/// ruleset that is ~3 300 compilations per run, of 17 expressions.
///
/// The comment that used to sit on that call said the compile was hoisted out of
/// the *line* loop because "`Regex::new` is the expensive half". It was right
/// about the cost and stopped one loop short; the expression is a property of the
/// ROW, so it is compiled where the row is.
fn forbid_in_files(
    rule: &Rule,
    root: &Path,
    paths: &[&String],
    findings: &mut Vec<Finding>,
) -> anyhow::Result<()> {
    // Compiled once per RULE, never per file and never per line.
    //
    // `Rule::validate` has already refused a malformed expression and the
    // both-columns row, so these are defence in depth on the same reading
    // `run_rule` applies — the runner re-validates rather than trusting that
    // every path reached it through the loader. Hoisting it here also moves that
    // refusal from "once the first matched file is read" to "before any file is
    // read", which is the direction a config fault should travel.
    let (matcher, exclude) = Matcher::for_rule(rule)?;
    let mode = span_mode(rule);
    for rel_path in paths {
        let rel_path = rel_path.as_str();
        let contents = match crate::fsio::read(root.join(rel_path)) {
            Ok(bytes) => bytes,
            // A path the walk listed and the read cannot find is a tree that
            // moved under us, not a finding — the same silence as before, per
            // file rather than per call.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        count_read(contents.len());
        let Ok(text) = String::from_utf8(contents) else {
            continue;
        };
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
                    carried: Vec::new(),
                    owner: None,
                    rule: rule.id.clone(),
                    severity: rule.severity(),
                    path: rel_path.to_owned(),
                    line: Some(index + 1),
                    identity: identity_of(rule, identity::FindingKind::Code, default),
                    check: rule.settling_check().unwrap_or(Check::Reevaluate),
                    remediation: rule.remediation(),
                    reason: None,
                });
            }
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
        // `Unparsed` and `Unreadable` share one reported reason here;
        // `UnknownFormat` is unreachable because `format` is `Some`, and
        // `RootUnset` is unreachable because this site reads a path INSIDE the
        // repository and so has no root variable to resolve (CLOUD-1167). Both
        // are arms rather than a wildcard, which is the discipline this match
        // was already keeping: a fifth cause has to come through here rather
        // than defaulting to silence.
        Acquired::No(
            NotAcquired::Unparsed
            | NotAcquired::Unreadable
            | NotAcquired::UnknownFormat
            | NotAcquired::RootUnset,
        ) => Some(DOCUMENT_UNREADABLE),
        // Read in full, and there is no document in it — its own reason rather
        // than folded into the arm above (CLOUD-1787). Still a FINDING and
        // never silence, which is CLOUD-772's decision and unchanged: a row
        // pointed at a file carrying no document has not been satisfied, it has
        // been unable to look. What changes is that it now says which.
        Acquired::No(NotAcquired::NoDocument) => Some(DOCUMENT_NO_DOCUMENT),
        // Unreachable: this site always asks for `Want::Parsed`. Arms rather
        // than a wildcard so a caller that ever asks for lines or call sites
        // here has to decide what a node path means over them.
        Acquired::Lines(_) | Acquired::Invocations(_) | Acquired::Units(_) | Acquired::Uses(_) => {
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
        carried: Vec::new(),
        owner: None,
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
        // The reason was already computed and already in the fingerprint above;
        // until CLOUD-1787 it stopped there, so `node-differs` and
        // `could-not-look` printed the same bytes.
        reason: Some(reason),
    });
    Ok(())
}

/// The finding a row raises when it could not look — factored out because two
/// call sites reach it now: the document itself was unreadable, or the derived
/// value it compares against was.
/// A cited token is not a key of the register (CLOUD-2005).
const REFERENCE_UNRESOLVED: &str = "unresolved";
/// A key no citer names, under `inverse`.
const REFERENCE_UNCITED: &str = "uncited";
/// A key on a second row of a `unique` table register.
const REGISTER_DUPLICATED: &str = "register-key-duplicated";
/// A data row whose cell count is not the declared width.
const REGISTER_WIDTH: &str = "register-row-width";
/// A key or a patterned cell that does not match its `[[pattern]]`.
const REGISTER_MALFORMED: &str = "register-cell-malformed";

/// Evaluate a [`RuleKind::Reference`] row (CLOUD-2005).
///
/// Builds each register the row names ONCE, gathers every citation in one pass
/// over the citer files, and hands both to [`crate::register::resolve`], whose
/// join is a map probe per citation. That is the whole performance argument:
/// the consumer this replaces rescanned every register row per row.
///
/// Could-not-look is reported, never read as an empty set: a register whose
/// declared paths match nothing, or whose witness will not parse, is one
/// finding under [`DOCUMENT_UNREADABLE`] at the path that could not be read.
fn reference_rule(
    rule: &Rule,
    root: &Path,
    inputs: &RunInputs<'_>,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Option<NotObserved>> {
    use crate::register::{self, Built, Refusal, Witness};
    let Some(cites) = rule.cites.as_ref() else {
        return Ok(Some(NotObserved::RuleSkipped));
    };
    let register_inputs = RegisterInputs {
        files: inputs.files,
        patterns: &inputs.tables.patterns,
    };
    let build = |id: &str| -> anyhow::Result<Built> {
        let declared = inputs
            .tables
            .registers
            .iter()
            .find(|row| row.id == id)
            .ok_or_else(|| {
                crate::error::UsageError::raise(format!(
                    "rule `{}`: register `{id}` is not declared in [[register]]",
                    rule.id
                ))
            })?;
        build_register(declared, root, &register_inputs)
    };
    let target = build(&cites.register)?;
    let within = cites.within.as_deref().map(build).transpose()?;
    // An undeclared partition is refused, never read as "no partition": that
    // would widen the join to every partition and admit a cross-partition key.
    let partition = match cites.partition.as_deref() {
        None => None,
        Some(id) => Some(inputs.tables.patterns.get(id).ok_or_else(|| {
            UsageError::raise(format!(
                "rule `{}`: partition `{id}` is not a declared [[pattern]]",
                rule.id
            ))
        })?),
    };

    let Some(citations) = gather_citations(rule, cites, root, inputs, &register_inputs, findings)?
    else {
        return Ok(Some(NotObserved::RuleSkipped));
    };

    for refusal in register::resolve(
        &target,
        &citations,
        within.as_ref(),
        partition,
        cites.inverse,
    ) {
        let (at, span, reason): (Witness, String, &'static str) = match refusal {
            Refusal::Unresolved(citation) => (citation.at, citation.token, REFERENCE_UNRESOLVED),
            Refusal::Uncited(witness) => (witness, String::new(), REFERENCE_UNCITED),
            Refusal::Register(defect) => match defect {
                register::Defect::Duplicated(w) => (w, String::new(), REGISTER_DUPLICATED),
                register::Defect::Width(w) => (w, String::new(), REGISTER_WIDTH),
                register::Defect::Malformed(w) => (w, String::new(), REGISTER_MALFORMED),
            },
            Refusal::CouldNotLook(at) => (
                Witness {
                    path: at,
                    line: None,
                },
                String::new(),
                DOCUMENT_UNREADABLE,
            ),
        };
        // POINTER-ONLY: the token is hashed into the identity and never
        // printed; the finding carries the rule, the path and the line.
        let default = identity::code_fingerprint(
            &rule.id,
            &at.path,
            &format!("{} {reason} {span}", cites.register),
            identity::SpanNormalization::Verbatim,
        )?;
        findings.push(Finding {
            carried: Vec::new(),
            owner: None,
            rule: rule.id.clone(),
            severity: rule.severity(),
            path: at.path,
            line: Some(at.line.unwrap_or(1)),
            identity: identity_of(rule, identity::FindingKind::Code, default),
            check: rule.settling_check().unwrap_or(Check::Reevaluate),
            remediation: rule.remediation(),
            reason: Some(reason),
        });
    }
    Ok(None)
}

/// Every token a [`RuleKind::Reference`] row's citer cites (CLOUD-2005).
///
/// `None` where the row names no citer it can read (no `glob` and no
/// `from_register`): the rule is skipped, never read as citing nothing. A
/// document the frontmatter citer cannot parse is a could-not-look finding
/// pushed onto `findings`, beside whatever else resolves.
fn gather_citations(
    rule: &Rule,
    cites: &crate::register::Cites,
    root: &Path,
    inputs: &RunInputs<'_>,
    register_inputs: &RegisterInputs<'_>,
    findings: &mut Vec<Finding>,
) -> anyhow::Result<Option<Vec<crate::register::Citation>>> {
    use crate::register;
    let mut citations: Vec<register::Citation> = Vec::new();
    if let Some(source_id) = cites.from_register.as_deref() {
        // A register's own column is the citer: read its rows with the same
        // grammar the register was built with, so a cell means one thing.
        let declared = inputs
            .tables
            .registers
            .iter()
            .find(|row| row.id == source_id)
            .ok_or_else(|| {
                crate::error::UsageError::raise(format!(
                    "rule `{}`: register `{source_id}` is not declared in [[register]]",
                    rule.id
                ))
            })?;
        let column = cites.column.unwrap_or(1).saturating_sub(1);
        for path in register_paths(declared, register_inputs)? {
            let Acquired::Lines(lines) = acquire(root, &path, Some(Want::Lines)) else {
                continue;
            };
            for (line, row) in register::keyed_rows(&declared.source, &lines) {
                let Some(cell) = row.get(column) else {
                    continue;
                };
                push_tokens(&mut citations, cites, &path, Some(line), cell);
            }
        }
    } else {
        let Some(glob) = rule.glob.as_deref() else {
            return Ok(None);
        };
        let selection = PathSet::selecting(&rule.id, glob, &rule.exclude_paths)?;
        let matched: Vec<&String> = inputs
            .scoped
            .iter()
            .filter(|path| selection.contains(path))
            .collect();
        if let Some(pattern) = rule.regex.as_deref() {
            let re = regex::Regex::new(pattern)?;
            for path in matched {
                let Acquired::Lines(lines) = acquire(root, path, Some(Want::Lines)) else {
                    continue;
                };
                for (index, text) in lines.iter().enumerate() {
                    for caps in re.captures_iter(text) {
                        let hit = caps.get(1).or_else(|| caps.get(0));
                        if let Some(hit) = hit {
                            push_tokens(&mut citations, cites, path, Some(index + 1), hit.as_str());
                        }
                    }
                }
            }
        } else if let (Some(format), Some(node)) = (rule.format, rule.node.as_deref()) {
            for path in matched {
                match acquire(root, path, Some(Want::Parsed(format))) {
                    Acquired::Parsed(doc) => {
                        for value in register::scalars(&doc, node) {
                            push_tokens(&mut citations, cites, path, None, &value);
                        }
                    }
                    Acquired::No(NotAcquired::Absent) => {}
                    _ => findings.push(unreadable_document(rule, path, node)?),
                }
            }
        }
    }

    Ok(Some(citations))
}

/// Add each token `cell` cites, honouring `split` and `relative_to`.
///
/// An EMPTY token is never a citation: an empty cell is a claim of absence
/// (a by-reference capture, say), not a reference to a key named "".
fn push_tokens(
    out: &mut Vec<crate::register::Citation>,
    cites: &crate::register::Cites,
    path: &str,
    line: Option<usize>,
    cell: &str,
) {
    let members: Vec<&str> = match cites.split.as_deref() {
        Some(sep) => cell.split(sep).collect(),
        None => vec![cell],
    };
    for member in members {
        let token = member.trim();
        if token.is_empty() {
            continue;
        }
        let token = match cites.relative_to {
            Some(crate::register::RelativeTo::Citer) => crate::register::joined(path, token),
            None => token.to_owned(),
        };
        out.push(crate::register::Citation {
            token,
            at: crate::register::Witness {
                path: path.to_owned(),
                line,
            },
        });
    }
}

/// What building a register reads: the tracked paths and the compiled
/// `[[pattern]]` table. Its own type because the traversal walk builds
/// registers before a run's [`RunInputs`] exists.
struct RegisterInputs<'a> {
    files: &'a [String],
    patterns: &'a BTreeMap<String, regex::Regex>,
}

/// Every tracked path one of `declared`'s globs selects, unioned, in order.
fn register_paths(
    declared: &crate::register::DeclaredRegister,
    inputs: &RegisterInputs<'_>,
) -> anyhow::Result<Vec<String>> {
    let mut sets = Vec::new();
    for glob in &declared.paths {
        sets.push(PathSet::selecting(&declared.id, glob, &[])?);
    }
    Ok(inputs
        .files
        .iter()
        .filter(|path| sets.iter().any(|set| set.contains(path)))
        .cloned()
        .collect())
}

/// Build one declared register from the tracked tree.
fn build_register(
    declared: &crate::register::DeclaredRegister,
    root: &Path,
    inputs: &RegisterInputs<'_>,
) -> anyhow::Result<crate::register::Built> {
    use crate::register::{Input, Source};
    let paths = register_paths(declared, inputs)?;
    let mut lines: Vec<(String, Vec<String>)> = Vec::new();
    let mut docs: Vec<(String, Option<crate::facts::Node>)> = Vec::new();
    for path in &paths {
        match &declared.source {
            Source::Table { .. } => match acquire(root, path, Some(Want::Lines)) {
                Acquired::Lines(text) => lines.push((path.clone(), text)),
                _ => {
                    return Ok(crate::register::Built::CouldNotLook { at: path.clone() });
                }
            },
            Source::Documents { .. } => {
                let parsed = match acquire(
                    root,
                    path,
                    Some(Want::Parsed(crate::facts::Format::Markdown)),
                ) {
                    Acquired::Parsed(node) => Some(node),
                    _ => None,
                };
                docs.push((path.clone(), parsed));
            }
            Source::Tree { .. } => {}
        }
    }
    let inputs_view: Vec<Input<'_>> = match &declared.source {
        Source::Table { .. } => lines
            .iter()
            .map(|(path, text)| Input::Lines { path, lines: text })
            .collect(),
        Source::Documents { .. } => docs
            .iter()
            .map(|(path, node)| Input::Document {
                path,
                node: node.as_ref(),
            })
            .collect(),
        Source::Tree { .. } => paths.iter().map(|path| Input::Path(path)).collect(),
    };
    Ok(crate::register::build(
        declared,
        inputs.patterns,
        &inputs_view,
    ))
}

/// Walk every declared `[[traversal]]` once for the run (CLOUD-1868), and
/// return `input.tree.traversals`: id -> seed -> [`crate::traversal::answer`].
///
/// `null` when nothing is declared, so a run that asks for no walk reads no
/// document for one. Each walk reads frontmatter through [`acquire`], the one
/// acquisition, and only for the nodes it visits.
fn walk_traversals(
    vocabulary: crate::policy::Vocabulary<'_>,
    root: &Path,
    files: &[String],
    patterns: &BTreeMap<String, regex::Regex>,
) -> anyhow::Result<serde_json::Value> {
    if vocabulary.traversals.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    let inputs_for_registers = RegisterInputs { files, patterns };
    // Every register a walk names, as a terminal or as an edge target, built
    // ONCE. One set rather than two branches: cargo-mutants showed each
    // branch could be broken while the other covered for it.
    let mut needed: BTreeMap<&str, &str> = BTreeMap::new();
    for row in vocabulary.traversals {
        let targets = row.edges.iter().filter_map(|edge| match &edge.to {
            crate::traversal::EdgeTarget::Register(id) => Some(id.as_str()),
            _ => None,
        });
        for id in row.until_register.as_deref().into_iter().chain(targets) {
            needed.entry(id).or_insert(row.id.as_str());
        }
    }
    let mut registers: BTreeMap<String, crate::register::Built> = BTreeMap::new();
    for (id, traversal) in needed {
        let declared = vocabulary
            .registers
            .iter()
            .find(|register| register.id == id)
            .ok_or_else(|| {
                crate::error::UsageError::raise(format!(
                    "traversal `{traversal}`: register `{id}` is not declared in [[register]]"
                ))
            })?;
        registers.insert(
            id.to_owned(),
            build_register(declared, root, &inputs_for_registers)?,
        );
    }
    let read = |path: &str, field: &str| -> crate::traversal::Read {
        match acquire(
            root,
            path,
            Some(Want::Parsed(crate::facts::Format::Markdown)),
        ) {
            Acquired::Parsed(node) => {
                crate::traversal::Read::Values(crate::register::scalars(&node, field))
            }
            Acquired::No(NotAcquired::Absent | NotAcquired::NoDocument) => {
                crate::traversal::Read::Absent
            }
            _ => crate::traversal::Read::CouldNotLook,
        }
    };
    let is_key =
        |register: &str, key: &str| -> Option<bool> { registers.get(register)?.contains(key) };
    let mut out = serde_json::Map::new();
    for row in vocabulary.traversals {
        let select = |glob: &str| -> anyhow::Result<Vec<String>> {
            let set = PathSet::selecting(&row.id, glob, &[])?;
            Ok(files
                .iter()
                .filter(|path| set.contains(path))
                .cloned()
                .collect())
        };
        let graph = crate::traversal::DocumentGraph::new(row, &select, &is_key, &read)?;
        let seeds: Vec<String> = match row.seeds.as_deref() {
            Some(glob) => {
                let set = PathSet::selecting(&row.id, glob, &[])?;
                files
                    .iter()
                    .filter(|path| set.contains(path))
                    .cloned()
                    .collect()
            }
            None => vec![row.seed.clone()],
        };
        let mut answers = serde_json::Map::new();
        for seed in seeds {
            let outcome = row.compiled_from(&seed).run(&graph);
            answers.insert(seed, crate::traversal::answer(&outcome));
        }
        out.insert(row.id.clone(), serde_json::Value::Object(answers));
    }
    Ok(serde_json::Value::Object(out))
}

fn unreadable_document(rule: &Rule, rel_path: &str, node_path: &str) -> anyhow::Result<Finding> {
    let default = identity::code_fingerprint(
        &rule.id,
        rel_path,
        &format!("{node_path} {DOCUMENT_UNREADABLE}"),
        identity::SpanNormalization::Verbatim,
    )?;
    Ok(Finding {
        carried: Vec::new(),
        owner: None,
        rule: rule.id.clone(),
        severity: rule.severity(),
        path: rel_path.to_owned(),
        line: Some(1),
        identity: identity_of(rule, identity::FindingKind::Code, default),
        check: rule.settling_check().unwrap_or(Check::Reevaluate),
        remediation: rule.remediation(),
        // The same token the fingerprint above already carries.
        reason: Some(DOCUMENT_UNREADABLE),
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
        Acquired::No(_)
        | Acquired::Lines(_)
        | Acquired::Invocations(_)
        | Acquired::Units(_)
        | Acquired::Uses(_) => Look::CouldNotLook,
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

/// The census row naming the one shared acquisition rather than a rule
/// (CLOUD-1790).
///
/// Parenthesised so it cannot collide with a [`Rule::id`]: a row id is a config
/// key and this is a step, and a reader sorting the census by cost must be able
/// to tell "this gate was expensive" from "the run read this much before any gate
/// ran".
pub const DECLARED_ACQUISITION: &str = "(declared documents)";

/// The file was read in full and holds no document at all — today a markdown
/// file with no frontmatter fence (CLOUD-1787).
///
/// Distinct from [`DOCUMENT_UNREADABLE`] because the remedy is the opposite one.
/// `could-not-look` says *this document is malformed*; this says *there is no
/// document here*, and an author told the first about the second goes looking
/// for a fence that is simply absent — which is the report CLOUD-1787 was filed
/// on.
const DOCUMENT_NO_DOCUMENT: &str = "no-document";

// The tree walk and its boundary marker live in `git`, and the glob in the
// `selector` leaf (CLOUD-2789), so `git` reads the tree without reaching up
// into `rules`.
use crate::git::tree_files;
use crate::path_set::PathSet;
use crate::selector::Selector;

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
    pub fn from_config(config: &crate::config_model::Config) -> anyhow::Result<Self> {
        Ok(Sets {
            scope: PathSet::scope(&config.scope)?,
            protected: PathSet::includes("protected", &config.protected)?,
            unlanded: PathSet::includes("unlanded", &config.unlanded)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::PathSet;
    #[cfg(test)]
    #[cfg(test)]
    use crate::rules::RuleExt as _;
    #[cfg(test)]
    use crate::rules::RuleKindExt as _;

    /// Fails by: a function's token count read from a slice that does not end
    /// at `offset + bytes` (`*` for `+`), so a unit past the first byte counts
    /// another span's tokens or none.
    #[test]
    fn a_function_counts_the_tokens_of_its_own_span() {
        let text = "struct Pad;\n\n\
                    fn f() {\n    let alpha = 1;\n}\n\
                    fn g() {\n    let beta = vec![1, 2, 3];\n    let gamma = beta.len();\n}\n";
        let crate::facts::Look::Is(nodes) = super::rust_units("src/x.rs", text) else {
            panic!("a rust file is read");
        };
        let functions: Vec<&serde_json::Value> =
            nodes.iter().filter(|node| node["kind"] == "fn").collect();
        assert_eq!(functions.len(), 2, "{nodes:?}");
        for node in functions {
            let offset = usize::try_from(node["offset"].as_u64().unwrap()).unwrap();
            let bytes = usize::try_from(node["bytes"].as_u64().unwrap()).unwrap();
            assert!(offset > 1, "the premise: a span past the first byte");
            assert_eq!(
                node["counts"]["tokens"],
                serde_json::json!(crate::o200k::tokens(&text[offset..offset + bytes])),
                "{node}"
            );
        }
    }

    /// CLOUD-1578 / CLOUD-310: a backend admitted to a verdict must abstain on a
    /// language it does not own, with `IsNot`, rather than parse it and answer
    /// (or fail and read as could-not-look). Every routed backend is handed every
    /// OTHER route's path and must say `IsNot`, and each answers its own.
    #[test]
    fn every_unit_backend_abstains_off_its_language() {
        let samples = [("rs", "pub fn f() {}\n"), ("rego", "package p\n\nx := 1\n")];
        assert_eq!(
            UNIT_BACKENDS.len(),
            samples.len(),
            "a new route brings its sample"
        );
        for (owns, backend, why) in UNIT_BACKENDS {
            assert!(!why.is_empty(), "the `{owns}` route names its reason");
            for (extension, text) in samples {
                let answer = backend(&format!("m.{extension}"), text);
                if extension == *owns {
                    assert!(
                        matches!(answer, crate::facts::Look::Is(_)),
                        "the `{owns}` backend answers its own language"
                    );
                } else {
                    assert!(
                        matches!(answer, crate::facts::Look::IsNot),
                        "the `{owns}` backend abstains on a `.{extension}` path"
                    );
                }
            }
        }
    }

    /// The `units` memo round-trips: after one acquisition the entry exists at
    /// its content address and reads back as the same node list, and a second
    /// acquisition returns it. Fails by: the memo never written, written under a
    /// key the read does not use, or the read returning another shape.
    #[test]
    fn a_unit_list_is_read_back_from_its_memo() {
        // ITS OWN STATE ROOT (CLOUD-2936): against the developer's store, the
        // entry one recording wrote was the one the next read, and ran nothing
        // that writes it.
        crate::testing::contain_state(&crate::scratch::scratch("rules-units-memo").join("state"));
        let text = "pub fn memo_probe(x: u8) -> u8 { x.saturating_add(1) }\n";
        let first = super::unit_nodes("memo_probe.rs", text).expect("a parsed file");
        // FAILS rather than skips without a state root: a suite host always has
        // one, and a case that could pass without asserting proves nothing
        // (`silent_skip.rs`).
        let dir = super::units_cache().expect("the suite resolves a state root");
        let at = dir.join(
            blake3::hash(&[b"rs".as_slice(), b"\0", text.as_bytes()].concat())
                .to_hex()
                .as_str(),
        );
        let key = crate::cache::key(super::UNITS_FORMAT, &[b"rs", text.as_bytes()]);
        let held: Vec<serde_json::Value> =
            serde_json::from_slice(&crate::cache::read(&at, &key).expect("the entry was written"))
                .expect("the entry is the node list");
        assert_eq!(held, first);
        assert_eq!(super::unit_nodes("memo_probe.rs", text), Some(first));
    }

    /// CLOUD-2075 §7 case 21: a `check` finding labels its rule.
    #[test]
    fn a_check_finding_line_labels_its_rule() {
        use crate::output::Line as _;
        let finding = crate::findings::Finding {
            carried: Vec::new(),
            owner: None,
            rule: "r".to_owned(),
            severity: crate::severity::RuleSeverity::Deny,
            path: "src/a.rs".to_owned(),
            line: Some(3),
            identity: crate::identity::StoredIdentity::new(
                crate::identity::FindingKind::Scope,
                crate::identity::scope_fingerprint("r", "src/a.rs"),
            ),
            check: crate::findings::Check::Reevaluate,
            remediation: Some(crate::findings::Remediation::NoFix("fixture".to_owned())),
            reason: None,
        };
        assert_eq!(finding.line(), "batten deny r at src/a.rs:3");
    }

    /// CLOUD-2213: the row id `issue file same` carries after its path reaches
    /// the line, so the refusal names the row it judged.
    #[test]
    fn a_policy_findings_other_subjects_ride_its_line() {
        use crate::output::Line as _;
        let subjects = [
            crate::verdict::Subject::Path {
                path: "src/a.rs".to_owned(),
            },
            crate::verdict::Subject::Artifact {
                artifact: "CLOUD-1".to_owned(),
            },
        ];
        let finding = crate::findings::Finding {
            owner: None,
            rule: "issue file same".to_owned(),
            severity: RuleSeverity::Deny,
            path: "src/a.rs".to_owned(),
            line: None,
            identity: crate::identity::StoredIdentity::new(
                crate::identity::FindingKind::Scope,
                crate::identity::scope_fingerprint("r", "src/a.rs"),
            ),
            check: crate::findings::Check::Reevaluate,
            remediation: None,
            reason: None,
            carried: super::carried_subjects(&subjects),
        };
        assert_eq!(
            finding.line(),
            "batten deny issue file same at src/a.rs CLOUD-1"
        );
    }

    /// CLOUD-609's guard on the change itself: `contains` still means MEMBERSHIP.
    ///
    /// Asserted directly rather than through a caller, because widening it would
    /// change `scope` and `unlanded` — two callers that never asked the
    /// containment question — and would look like nothing in the diff. This is
    /// the case that would otherwise ship silently.
    #[test]
    fn contains_still_answers_membership_and_never_enclosure() {
        let set = PathSet::includes("protected", &[".serena/memories/**".to_owned()]).unwrap();
        assert!(set.contains(".serena/memories/core.md"));
        assert!(
            !set.contains(".serena/memories"),
            "a directory is not a member of `dir/**`, and that reading is unchanged"
        );
    }

    /// The new question, and the neighbour it must not swallow.
    #[test]
    fn encloses_answers_the_directory_and_stops_at_the_separator() {
        let set = PathSet::includes("protected", &[".serena/memories/**".to_owned()]).unwrap();
        assert!(set.encloses(".serena/memories"));
        assert!(set.encloses(".serena/memories/"));
        // A member is still enclosed, so the one call site needs no second test.
        assert!(set.encloses(".serena/memories/core.md"));
        // THE DISCRIMINATOR. `.serena/memories` is a string prefix of
        // `.serena/memoriesx` and not a path prefix; without the separator in
        // the comparison this would refuse a sibling nobody guarded.
        assert!(!set.encloses(".serena/memoriesx"));
        // AN ANCESTOR ENCLOSES TOO, and that is the predicate working rather
        // than overreaching: `rm -rf .serena` destroys the guarded tree, so a
        // gate that allowed it while refusing `rm -rf .serena/memories` would be
        // guarding the smaller blast radius and not the larger one. It is a
        // widening, and the sanctioned kind — no call a correct reading allows
        // starts failing.
        assert!(set.encloses(".serena"));
    }

    // --- one document acquisition (CLOUD-849) --------------------------------

    /// Every `.rs` under EVERY workspace crate's `src/`, so the scan is over the
    /// product rather than over the file that happens to hold the assertion.
    ///
    /// The crates are ENUMERATED from the workspace root (CLOUD-2789): this
    /// walked `crates/batten/src` when that was the whole product, and a second
    /// document acquisition cut into `batten-base` would have left it silently.
    ///
    /// A near-copy of `batten-core` `git.rs`'s own `workspace_sources`, which is
    /// `#[cfg(test)]` and private to that module. Copied rather than hoisted
    /// deliberately: making it shared would put a test helper on the crate's
    /// real surface to save fifteen lines, and the two gates it serves are
    /// independent.
    fn crate_sources() -> Vec<(std::path::PathBuf, String)> {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("a workspace member sits under `crates/`");
        let mut sources = Vec::new();
        // WALKS THE SUBTREE, not one directory. `read_dir` does not descend, so
        // a `.rs` file under a future `src/<module>/` would never be scanned and
        // the gate would stop holding SILENTLY — the failure mode of every
        // scanner gate. The crate is flat today, which is exactly when this is
        // cheap to get right.
        let mut pending: Vec<std::path::PathBuf> = std::fs::read_dir(crates)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|member| member.join("Cargo.toml").is_file())
            .map(|member| member.join("src"))
            .filter(|src| src.is_dir())
            .collect();
        assert!(
            pending.len() > 1,
            "the workspace walk found {} crate(s); the product is more than one",
            pending.len()
        );
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
                let source = crate::fsio::read_to_string(&path).unwrap();
                sources.push((path, source));
            }
        }
        // `read_dir` order is filesystem-defined; a gate's failure message must
        // not depend on it.
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        // EVERY MEMBER CONTRIBUTES (CLOUD-2789): `pending.len() > 1` passes a
        // walk that dropped all but two crates. The expected members are read
        // again, independently of the walk above, so a filter introduced there
        // is caught here rather than agreed with.
        let silent: Vec<std::path::PathBuf> = std::fs::read_dir(crates)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|member| member.join("Cargo.toml").is_file() && member.join("src").is_dir())
            .filter(|member| {
                !sources
                    .iter()
                    .any(|(path, _)| path.starts_with(member.join("src")))
            })
            .collect();
        assert!(
            silent.is_empty(),
            "the workspace walk read no `src/` file of {silent:?}"
        );
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
            ported: None,
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
            // its verdict either way. The same holds for the `ported` arm's
            // subject set, which no arm here reads.
            subject_died: false,
            declared_subjects: &NO_SUBJECTS,
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
        unconserved_cases(
            &rule,
            "tests/two.bats",
            dying,
            "",
            &mapping,
            &mut mine,
            &mut BTreeSet::new(),
        );
        assert!(
            mine.is_empty(),
            "the qualified arm names this suite, so its case is conserved: {mine:?}"
        );

        // THE ANTI-BORROW HALF, and the one that makes the first mean something: a
        // different suite with the same case title must NOT be conserved by an arm
        // that named its neighbour.
        let mut theirs = Vec::new();
        unconserved_cases(
            &rule,
            "tests/one.bats",
            dying,
            "",
            &mapping,
            &mut theirs,
            &mut BTreeSet::new(),
        );
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
            ported: None,
            // `**/*.rs`, matching the committed row. The engine's globs use
            // `literal_separator(true)`, so `*` stops at a `/` — and CLOUD-1210
            // moved every test file one segment deeper into `tests/it/`, which
            // left the old spelling selecting NOTHING and this calibration
            // reporting zero arms for every case it is supposed to find.
            declared_in: "crates/batten/tests/**/*.rs".to_owned(),
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
        //
        // `.bats` RATHER THAN `.md`, WHICH IS WHAT THIS FIXTURE USED TO BE
        // (CLOUD-1787). `.md` names `Format::Markdown` now, so it is parseable
        // and lands two lines down under its own cause. Swapping the extension
        // keeps the case this assertion is about — a declaration the build
        // cannot honour, decided before any I/O — rather than deleting it.
        std::fs::write(dir.join("script.bats"), "@test \"x\" { true; }\n").unwrap();
        // Read in full, and there is no document in it. A markdown file with no
        // frontmatter fence: not a config fault, not a syntax error, and not an
        // empty document either.
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
                acquire("script.bats"),
                super::Acquired::No(super::NotAcquired::UnknownFormat)
            ),
            "an extension with no parser is a CONFIG fault, and is reached \
             without opening the file"
        );
        assert!(
            matches!(
                acquire("prose.md"),
                super::Acquired::No(super::NotAcquired::NoDocument)
            ),
            "A MARKDOWN FILE WITH NO FENCE IS `NoDocument`, NOT `Unparsed` — the \
             pair CLOUD-1787 was filed on. `Unparsed` sends an author looking \
             for a malformed fence that is simply absent"
        );

        // And the tokens are distinct, or naming the cause would not
        // discriminate — the failure this whole split exists to prevent.
        let tokens = [
            super::NotAcquired::UnknownFormat.as_str(),
            super::NotAcquired::Absent.as_str(),
            super::NotAcquired::Unreadable.as_str(),
            super::NotAcquired::Unparsed.as_str(),
            super::NotAcquired::NoDocument.as_str(),
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
            &crate::config_check::rules::Declared {
                documents: &[],
                lines: &[],
                invocations: &[],
                uses: &[],
                units: &[],
                base: None,
                staged: &[],
                staged_format: None,
                external: &[],
            },
            &[],
            &super::Resolved {
                traversals: &serde_json::Value::Null,
                review: &crate::facts::Look::IsNot,
                produced: &BTreeMap::new(),
                records: &BTreeMap::new(),
                records_blocked: &BTreeMap::new(),
                git: &crate::git::GitFacts::default(),
                symbols: &crate::facts::Look::IsNot,
                external: &BTreeMap::new(),
                state: None,
                forge: None,
                tool_verdicts: None,
                plan: None,
                minted: None,
                captured: None,
                shell: None,
            },
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

        let source = crate::fsio::read_to_string(
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

    /// A mediated write is judged against a denying ratchet that names its
    /// direction, base and glob, and against nothing else (CLOUD-2692).
    ///
    /// Fails by: an allowed ratchet judged at the call, or a row of another
    /// kind carrying a ratchet's columns judged as one (an `&&` read as `||`).
    #[test]
    fn only_a_denying_ratchet_with_its_columns_is_judged_at_the_call() {
        let ratchet = Rule {
            glob: Some("**/*.rs".to_owned()),
            pattern: Some("#[test]".to_owned()),
            direction: Some(Direction::NonDecreasing),
            base: Some("origin/main".to_owned()),
            severity: Some(RuleSeverity::Deny),
            ..blank("r", RuleKind::Ratchet)
        };
        assert!(judged_at_call(&ratchet));
        for unjudged in [
            Rule {
                severity: None,
                ..ratchet.clone()
            },
            Rule {
                severity: Some(RuleSeverity::Allow),
                ..ratchet.clone()
            },
            Rule {
                kind: RuleKind::Command,
                ..ratchet.clone()
            },
            Rule {
                direction: None,
                ..ratchet.clone()
            },
            Rule {
                base: None,
                ..ratchet.clone()
            },
            Rule {
                glob: None,
                ..ratchet.clone()
            },
        ] {
            assert!(!judged_at_call(&unjudged), "{unjudged:?}");
        }
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
        // CLOUD-2663: `counts = "tokens"` stands in for the literal, alone.
        let tokens = Rule {
            pattern: None,
            counts: Some(CeilingUnit::Tokens),
            ..base.clone()
        };
        assert!(tokens.validate().is_ok());
        for refused in [
            Rule {
                pattern: Some("#[test]".to_owned()),
                ..tokens.clone()
            },
            Rule {
                counts: Some(CeilingUnit::TrackedArtifacts),
                ..tokens.clone()
            },
            Rule {
                per_file: true,
                retires_with: Some("# subject:".to_owned()),
                ..base.clone()
            },
            Rule {
                per_file: true,
                conserves: Some(ledger_vocabulary()),
                ..base.clone()
            },
        ] {
            assert!(refused.validate().is_err(), "{refused:?}");
        }
        assert!(
            Rule {
                per_file: true,
                ..base.clone()
            }
            .validate()
            .is_ok()
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
            ported: None,
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
        // the library's own unit tests, so derive a scratch dir at runtime —
        // through `crate::scratch`, whose per-process root keeps two concurrent
        // runs (cargo-mutants' parallel jobs) from deleting each other's fixture.
        let dir = crate::scratch::scratch(&format!("rules-tests-{name}"));
        assert!(
            dir.is_dir(),
            "the scratch fixture {dir:?} could not be created"
        );
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
        let cache =
            super::acquire_declared(&[as_lines.clone(), as_calls.clone()], &dir, &files, &files)
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
            &crate::config_check::rules::Declared {
                documents: &[],
                lines: &["subject.rs".to_owned()],
                invocations: &["subject.rs".to_owned()],
                uses: &[],
                units: &[],
                base: None,
                staged: &[],
                staged_format: None,
                external: &[],
            },
            &files,
            &super::Resolved {
                traversals: &serde_json::Value::Null,
                review: &crate::facts::Look::IsNot,
                produced: &BTreeMap::new(),
                records: &BTreeMap::new(),
                records_blocked: &BTreeMap::new(),
                git: &crate::git::GitFacts::default(),
                symbols: &crate::facts::Look::IsNot,
                external: &BTreeMap::new(),
                state: None,
                forge: None,
                tool_verdicts: None,
                plan: None,
                minted: None,
                captured: None,
                shell: None,
            },
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
        project_uses(
            &cache,
            &both,
            &|path| (path.to_owned(), Wanted::Uses),
            &mut out,
            &mut missing,
            &mut causes,
        );
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
        project_uses(
            &cache,
            &one,
            &|path| (path.to_owned(), Wanted::Uses),
            &mut out,
            &mut missing,
            &mut causes,
        );
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
    /// A [`RunInputs`] carrying `files` and nothing else.
    ///
    /// Every acquisition family is empty, which is exactly right for these
    /// fixtures: the rules under test declare no documents, no facts and no
    /// bundles, so a populated input would be scenery the assertions do not
    /// read. `scoped` is `files` — nothing narrowed these runs.
    struct BareFacts {
        derived: BTreeMap<String, crate::facts::Look<String>>,
        documents: BTreeMap<(String, Wanted), Acquired>,
        external: BTreeMap<String, Acquired>,
        produced: BTreeMap<String, String>,
        records: BTreeMap<String, Vec<String>>,
        records_blocked: BTreeMap<String, String>,
        git: crate::git::GitFacts,
        symbols: crate::facts::Look<crate::symbols::Resolved>,
    }

    impl BareFacts {
        fn new() -> Self {
            BareFacts {
                derived: BTreeMap::new(),
                documents: BTreeMap::new(),
                external: BTreeMap::new(),
                produced: BTreeMap::new(),
                records: BTreeMap::new(),
                records_blocked: BTreeMap::new(),
                git: crate::git::GitFacts::default(),
                symbols: crate::facts::Look::IsNot,
            }
        }

        fn inputs<'a>(&'a self, files: &'a [String]) -> RunInputs<'a> {
            RunInputs {
                half: None,
                provisions: &[],
                files,
                scoped: files,
                // The TREE surface, which is what these unit cases exercise: the
                // mediated arm is driven through the compiled binary in
                // `review_dispatched.rs`, because a `with input as`-shaped
                // fabrication here could not tell a barred fact from an absent
                // one.
                surface: crate::facts::Surface::Check,
                derived: &self.derived,
                documents: &self.documents,
                external: &self.external,
                produced: &self.produced,
                records: &self.records,
                records_blocked: &self.records_blocked,
                git: &self.git,
                symbols: &self.symbols,
                review: &crate::facts::Look::IsNot,
                state: None,
                forge: None,
                tool_verdicts: None,
                plan: None,
                minted: None,
                captured: None,
                bundles: &[],
                // Empty, and that is honest for this harness: it builds no
                // bundle, so no `policy` row runs and nothing here resolves a
                // class. A fixture supplying a registry no consumer supplies is
                // how a deny case passes for the wrong reason
                // (`rules/policy-modules.md`), and the tier that DOES
                // drive a module is the compiled-binary one.
                verdicts: &[],
                tables: &NO_TABLES,
            }
        }
    }

    static NO_TABLES: super::RunTables<'static> = super::RunTables {
        registers: &[],
        patterns: BTreeMap::new(),
        traversals: serde_json::Value::Null,
        shell: None,
    };

    /// Fails by: a row that is not a ratchet, or one configured off, judged at
    /// the call because it carries a glob (CLOUD-2789).
    #[test]
    fn only_a_live_single_file_ratchet_is_judged_at_the_call() {
        let ratchet = Rule {
            glob: Some("src/**/*.rs".to_owned()),
            pattern: Some("unwrap(".to_owned()),
            direction: Some(Direction::NonIncreasing),
            base: Some("origin/main".to_owned()),
            ..blank("r", RuleKind::Ratchet)
        };
        assert!(judged_at_call(&ratchet), "premise: the whole row is judged");
        let shape = Rule {
            kind: RuleKind::Shape,
            ..ratchet.clone()
        };
        assert!(!judged_at_call(&shape), "a shape row is not a ratchet");
        let off = Rule {
            severity: Some(RuleSeverity::Allow),
            ..ratchet.clone()
        };
        assert!(!judged_at_call(&off), "an allow row is configured off");
        let unbased = Rule {
            base: None,
            ..ratchet.clone()
        };
        assert!(!judged_at_call(&unbased), "no base, no count to hold");
        let retiring = Rule {
            retires_with: Some("# subject:".to_owned()),
            ..ratchet
        };
        assert!(!judged_at_call(&retiring), "a subject read stays `check`'s");
    }

    // The row a config would carry with only `id` and `kind` written: every
    // other column at its serde default, exactly as a consumer's blank row
    // loads. Built through serde rather than a literal listing every column,
    // which had outgrown the function-length lint; the census a new column owes
    // is `Rule::columns` and its classification test, not this fixture. The
    // three columns whose blank value depends on the kind are filled by
    // [`per_kind`].
    fn blank(id: &str, kind: RuleKind) -> Rule {
        let row: Rule = serde_json::from_value(serde_json::json!({
            "id": id,
            "kind": kind,
            "scope": kind.scopes()[0],
        }))
        .expect("an id, a kind and a scope are a whole blank row");
        per_kind(row)
    }

    /// The columns whose blank value depends on `rule.kind`, each filled only for
    /// a kind that permits it, so a fixture for another kind is not born invalid.
    fn per_kind(rule: Rule) -> Rule {
        let permits = rule.kind.permits();
        Rule {
            // Per kind, because `severity` is now a per-kind column: the judge
            // kind is refused it, so handing every fixture one would make the
            // one kind that must not carry it unloadable in every test here.
            severity: permits.contains(&"severity").then_some(RuleSeverity::Deny),
            // The one that needs no argv, so a fixture about a different column
            // does not have to invent a fix command. A `shape` row is refused
            // this column (CLOUD-81), so it gets none — and a kind that also
            // permits `fix` gets none either, so a fixture setting `fix` is not
            // silently pushed into the both-columns state the xor refuses.
            no_fix_reason: (permits.contains(&"no_fix_reason") && !permits.contains(&"fix"))
                .then(|| "fixture".to_owned()),
            checks: permits
                .contains(&"checks")
                .then(|| vec!["verify".to_owned()]),
            ..rule
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
    fn an_unset_root_is_a_different_cause_from_an_absent_file() {
        // THE CAUSE DISTINCTION (CLOUD-1167), asserted here because it is not
        // observable through the binary: `tree_document`'s causes are the
        // caller's, and `check` reports a skipped rule without them. The
        // compiled-binary tier in `tests/external_facts.rs` proves the ENGINE
        // reaches the file at all; this proves the two silences are told apart.
        //
        // Collapsing them is what would ship the gate silently off. A launcher
        // wiring gate must read "this host has no such root" differently from
        // "the root is there and the file is not", or it reports the same answer
        // on a host running the launcher and on one that has never heard of it.
        let root = "BATTEN_UNIT_EXTERNAL_ROOT_THAT_IS_NOT_SET";
        // Belt and braces: the assertion is about an UNSET variable, so the test
        // must not depend on the ambient environment happening not to carry one.
        // SAFETY-EQUIVALENT REASONING: this is a single-threaded assertion about
        // a name no other test uses, and it is removed rather than set.
        assert!(
            std::env::var_os(root).is_none(),
            "the fixture variable must be unset for this case to mean anything"
        );

        let mut rule = blank("external-probe", RuleKind::Policy);
        rule.scope = RuleScope::Tree;
        rule.module = Some(String::from("probe.rego"));
        rule.external = vec![
            crate::facts::Rooted {
                id: String::from("no-root"),
                root: String::from(root),
                path: String::from("wiring.json"),
            },
            crate::facts::Rooted {
                id: String::from("no-file"),
                // A variable every process has, pointing at a directory that
                // certainly does not carry this file — so the root RESOLVES and
                // the read is the thing that fails.
                root: String::from("PATH"),
                path: String::from("batten-fixture-file-that-does-not-exist.json"),
            },
        ];

        let acquired = super::external_facts(std::slice::from_ref(&rule), READ_BUDGET);

        assert!(
            matches!(
                acquired.get("no-root"),
                Some(Acquired::No(NotAcquired::RootUnset))
            ),
            "an unset root variable is `root-unset`, never `absent`: {:?}",
            acquired.get("no-root")
        );
        assert!(
            !matches!(
                acquired.get("no-file"),
                Some(Acquired::No(NotAcquired::RootUnset)) | None
            ),
            "a root that resolves and a file that does not is not `root-unset`: {:?}",
            acquired.get("no-file")
        );
    }

    #[test]
    fn an_undeclared_external_row_acquires_nothing() {
        // THE ANTI-SCANNER HALF, one level below the compiled-binary tier: a run
        // whose rows declare no `[[rule.external]]` reads no environment variable
        // and opens no file. That guard is what keeps `crate::facts::EXTERNAL`'s
        // `Cost::Read` honest — CLOUD-851 measured what an unguarded read costs,
        // taking `check` from p50 4.76ms to 10.01ms for a question no rule asked.
        let mut rule = blank("no-external", RuleKind::Policy);
        rule.scope = RuleScope::Tree;
        assert!(
            super::external_facts(std::slice::from_ref(&rule), READ_BUDGET).is_empty(),
            "a row declaring no out-of-root file must acquire nothing"
        );
    }

    #[test]
    fn a_path_that_escapes_its_root_is_refused_at_load() {
        // REFUSED AT LOAD, not at resolution: no state of the filesystem makes
        // `../../etc/shadow` an admissible declaration, so reporting it as
        // could-not-look would present a permanent authoring error as a
        // transient one. A declaration that can walk back out of the root it
        // named is a scanner with a configuration file in front of it.
        for path in ["../outside.json", "/etc/shadow", "nested/../../up.json"] {
            let mut rule = blank("escaping", RuleKind::Policy);
            rule.module = Some(String::from("probe.rego"));
            rule.external = vec![crate::facts::Rooted {
                id: String::from("escape"),
                root: String::from("HOME"),
                path: String::from(path),
            }];
            assert!(
                rule.validate().is_err(),
                "`{path}` leaves the root it was declared beneath and must be refused"
            );
        }
    }

    /// A `provider` with no `preset` to qualify is refused at load (CLOUD-1625).
    ///
    /// The column is read in exactly one place — [`crate::policy::preset_sources`],
    /// which only runs for a row naming a preset. So without one the key parses,
    /// loads, and decides nothing: a consumer declaring their CI provider would be
    /// told nothing while the row reads no provider at all.
    #[test]
    fn a_provider_with_no_preset_is_refused_at_load() {
        let mut rule = blank("dangling-provider", RuleKind::Policy);
        rule.module = Some(String::from("probe.rego"));
        rule.provider = Some(String::from("github-actions"));
        let err = rule
            .validate()
            .expect_err("a provider qualifying nothing must not load");
        assert!(
            format!("{err}").contains("provider"),
            "the refusal names the column to remove: {err}"
        );
    }

    /// The anti-vacuity mirror: the same row loads once a preset is there to
    /// qualify. Without this the case above is satisfied by a build that refuses
    /// every `provider`, which would name the column every time and prove nothing.
    #[test]
    fn the_same_provider_loads_beside_the_preset_it_qualifies() {
        let mut rule = blank("qualified-provider", RuleKind::Policy);
        // `ci-hygiene` decides the tree, and `sources` is a tree-surface column:
        // left at `blank`'s mediated-call default the row is refused for a reason
        // that has nothing to do with `provider`, which would pass this test while
        // observing the wrong refusal.
        rule.scope = RuleScope::Tree;
        rule.preset = Some(String::from("ci-hygiene"));
        rule.sources = vec![String::from("**/*.yml")];
        rule.provider = Some(String::from("github-actions"));
        assert!(
            rule.validate().is_ok(),
            "a provider beside the preset it selects within must load: {:?}",
            rule.validate().err()
        );
    }

    /// Every `Rule` column, read off the struct's own source.
    fn rule_fields() -> Vec<&'static str> {
        // `Rule` moved to `config_model` (CLOUD-2789 phase 2).
        let source = include_str!("config_model.rs");
        let start = source
            .find("pub struct Rule {")
            .expect("Rule is declared here");
        let rest = &source[start..];
        let body = &rest[..rest.find("\n}").expect("the struct closes")];
        body.lines()
            .filter_map(|line| line.trim().strip_prefix("pub "))
            .filter_map(|rest| rest.split_once(':'))
            .map(|(field, _)| field)
            .collect()
    }

    #[test]
    fn every_rule_column_carries_a_fact_verdict() {
        // THE ARM THAT MAKES THE DERIVATION ASSERTED RATHER THAN CLAIMED
        // (CLOUD-1282). A column added to `Rule` fails here until somebody says
        // what it declares, which is the property the six hand-written blocks
        // this replaced did not have — their own comment recorded the list
        // lagging the struct, and it still did by fourteen columns.
        let fields = rule_fields();
        assert!(
            fields.len() > 40,
            "the struct scan must actually find fields: {fields:?}"
        );

        let missing: Vec<&str> = fields
            .iter()
            .copied()
            .filter(|field| !COLUMN_CENSUS.iter().any(|row| row.field == *field))
            .collect();
        assert!(
            missing.is_empty(),
            "these `Rule` columns carry no fact verdict: {missing:?}. Say what each one \
             declares — a `Fact`, or not fact-bearing with the reason. Silence is not one \
             of the two, because a tree-only column nobody classified is declarable on a \
             mediated row and read by nothing."
        );

        for row in COLUMN_CENSUS {
            assert!(
                fields.contains(&row.field),
                "the census names `{}`, which `Rule` no longer declares",
                row.field
            );
            assert_eq!(
                COLUMN_CENSUS
                    .iter()
                    .filter(|other| other.field == row.field)
                    .count(),
                1,
                "`{}` carries two verdicts; one column, one answer",
                row.field
            );
            if let Declares::NotFactBearing(reason) = row.declares {
                assert!(
                    !reason.trim().is_empty(),
                    "`{}` is recorded not fact-bearing for no stated reason",
                    row.field
                );
            }
        }
    }

    #[test]
    fn the_derivation_reaches_the_columns_the_hand_written_list_never_did() {
        // The fourteen columns that were declarable on a mediated row and read
        // by nothing. Asserted through `tree_only_column` rather than through
        // `validate`, so the case names the COLUMN it is about and a refusal for
        // some other reason cannot make it pass.
        let mut rule = blank("probe", RuleKind::Policy);
        rule.scope = RuleScope::MediatedCall;
        rule.module = Some(String::from("probe.rego"));
        assert!(
            rule.tree_only_column().is_none(),
            "a mediated row declaring no fact column is clean"
        );

        rule.refs = vec![String::from("refs/heads/main")];
        assert_eq!(
            rule.tree_only_column().map(|column| column.field),
            Some("refs"),
            "`refs` was never in the hand-written list"
        );
        rule.refs.clear();

        rule.symbols = true;
        assert_eq!(
            rule.tree_only_column().map(|column| column.field),
            Some("symbols")
        );
        rule.symbols = false;

        rule.landing = vec![String::from("origin/main")];
        assert_eq!(
            rule.tree_only_column().map(|column| column.field),
            Some("landing")
        );
        rule.landing.clear();

        // THE ANTI-VACUITY MIRROR, and it is the half that decides whether this
        // is a derivation or a blanket refusal: `checks` is a `Surface::Hook`
        // fact, so a mediated row declaring it is asking for something the
        // boundary already resolved — which is what makes `ready-guard` a
        // mediated row at all.
        rule.checks = Some(vec![String::from("verify")]);
        assert!(
            rule.tree_only_column().is_none(),
            "a hook-resolvable column on a mediated row is not this refusal's business"
        );
    }

    #[test]
    fn one_external_id_names_one_file() {
        // Acquisition caches by id across the whole rule set, so two rows
        // declaring one id differently would resolve by whichever row the loop
        // reached first — a silent precedence rule over which file a module
        // actually reads. `Wanted` records the same lesson one family over,
        // where keying a cache on the path alone starved the losing row.
        let mut rule = blank("two-answers", RuleKind::Policy);
        // TREE SCOPE EXPLICITLY (CLOUD-1282). `external` is a `Surface::Check`
        // fact, so a mediated row declaring it is now refused for that reason
        // alone — which would make this case pass for the wrong one and stop
        // saying anything about id uniqueness.
        rule.scope = RuleScope::Tree;
        rule.module = Some(String::from("probe.rego"));
        rule.external = vec![
            crate::facts::Rooted {
                id: String::from("wiring"),
                root: String::from("HOME"),
                path: String::from("a.json"),
            },
            crate::facts::Rooted {
                id: String::from("wiring"),
                root: String::from("HOME"),
                path: String::from("b.json"),
            },
        ];
        assert!(
            rule.validate().is_err(),
            "one id declared twice with different paths must be refused at load"
        );

        // The same id declared twice IDENTICALLY is not a contradiction — it is
        // a duplicate, and the cache already collapses it. Refusing it would
        // price tidiness rather than ambiguity.
        rule.external[1].path = String::from("a.json");
        assert!(
            rule.validate().is_ok(),
            "an identical duplicate names one file and is not ambiguous"
        );
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
    fn isolate_contains_a_returned_failure_and_a_panic_and_lets_typed_answers_through() {
        // CLOUD-126's four arms, exercised directly. THIS IS THE EXTRACTED
        // DECISION, not a convenience: `rules/rust.md` requires a test be
        // shown able to fail, and neither of the two contained shapes has a
        // config-reachable input in this environment — see
        // `an_erroring_rule_is_contained_and_its_siblings_still_report` for the
        // measurement. The panic arm is stronger still: the workspace lints
        // forbid `panic!` in library code, so no `[[rule]]` can reach it at all.
        // `markers::scannable` is the precedent (CLOUD-249).
        assert!(matches!(isolate(|| Ok(None)), Isolated::Evaluated));
        assert!(matches!(
            isolate(|| Ok(Some(NotObserved::RuleSkipped))),
            Isolated::NotEvaluated(NotObserved::RuleSkipped)
        ));
        // A plain failure is the gate's own, and is contained — carrying the
        // reason it gave, so an operator is not told merely that something
        // "errored" when the gate said exactly what went wrong.
        let contained = isolate(|| Err(anyhow::anyhow!("the rule could not read its input")));
        match contained {
            Isolated::Errored(failure) => {
                assert_eq!(failure.class, ErrorClass::Internal);
                assert_eq!(failure.reason, "the rule could not read its input");
            }
            other => panic!("a plain failure must be contained: {other:?}"),
        }
        // A panic is contained too, and under its OWN class: it says something
        // different about the rule than a failure it anticipated and returned.
        match isolate(|| panic!("a rule that did not return at all")) {
            Isolated::Errored(failure) => {
                assert_eq!(failure.class, ErrorClass::Panic);
                assert!(
                    failure.reason.is_empty(),
                    "a panic payload is the runtime's, not the engine's: {failure:?}"
                );
            }
            other => panic!("a panic must be contained: {other:?}"),
        }
        // And the two typed answers travel on, because neither is a gate fault:
        // a config error is the same answer for the whole run (exit 1), and a
        // verdict must not be downgraded into an infrastructure complaint.
        assert!(matches!(
            isolate(|| Err(UsageError::raise("the config is wrong"))),
            Isolated::Propagate(_)
        ));
        assert!(matches!(
            isolate(|| Err(crate::refusal::Denial::raise(
                &crate::refusal::Refusal::new("r", "refused", crate::refusal::Fix::None),
                crate::refusal::Arm::Full,
            ))),
            Isolated::Propagate(_)
        ));
    }

    #[test]
    fn an_erroring_rule_is_contained_and_its_siblings_still_report() {
        // THE ANTI-COLLATERAL ASSERTION, over the real loop rather than over
        // `isolate` alone. Before CLOUD-126 this loop carried a `?`, so one
        // rule's I/O error propagated out of the whole scan: no findings at all
        // and no later rule run.
        //
        // The erroring input is a DIRECTORY named like a source file, handed to
        // the loop through `scoped`. That bypasses exactly one thing — the tree
        // walk, which filters every non-regular entry — and nothing else: the
        // rule, the glob, `run_rule` and `forbid_in_file` are the production
        // path, and `fs::read` over a directory is `EISDIR`, which is not the
        // `NotFound` that site absorbs.
        //
        // Bypassing the walk is what makes this a library test rather than one
        // over the compiled binary, and the reason is measured rather than
        // preferred: CLOUD-849 converted the acquisition failures into
        // could-not-look FINDINGS ("a gate that cannot look reports; it does not
        // abort the run it was one row of"), and the walker drops directories,
        // FIFOs and symlinks — so no `[[rule]]` a config can express reaches
        // `forbid_in_file`'s non-`NotFound` arm. Recorded on CLOUD-126.
        let root = std::env::temp_dir().join("batten-isolate-siblings");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("errors.rs")).expect("a directory named like a file");
        fs::write(root.join("reports.rs"), "TODO fix\n").expect("write the readable sibling");

        let mut errs = blank("reads-a-directory", RuleKind::Forbid);
        errs.glob = Some("errors.rs".to_owned());
        errs.pattern = Some("TODO".to_owned());
        let mut ok = blank("reads-a-file", RuleKind::Forbid);
        ok.glob = Some("reports.rs".to_owned());
        ok.pattern = Some("TODO".to_owned());

        let files = vec!["errors.rs".to_owned(), "reports.rs".to_owned()];
        let facts = BareFacts::new();
        let inputs = facts.inputs(&files);
        let mut scan = Scan::default();
        evaluate_rules(&[errs, ok], &root, &inputs, &mut scan).expect("the loop does not unwind");

        assert_eq!(
            scan.not_evaluated.get("reads-a-directory"),
            Some(&NotObserved::RuleErrored),
            "an errored rule HOLDS, exactly as a skipped one does: its silence is not evidence"
        );
        assert_eq!(
            scan.errored.get("reads-a-directory").map(|f| f.class),
            Some(ErrorClass::Internal)
        );
        assert_eq!(
            scan.findings.len(),
            1,
            "the sibling rule still evaluated and still reported"
        );
        assert_eq!(scan.findings[0].rule, "reads-a-file");
        assert!(
            !scan.not_evaluated.contains_key("reads-a-file"),
            "a rule that completed is not recorded as having failed to"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_declared_precondition_skips_before_the_body_and_names_what_it_wanted() {
        // CLOUD-125 at the loop. The rule's glob matches a file that WOULD fire,
        // so the absence of a finding is the precondition and nothing else.
        let root = std::env::temp_dir().join("batten-precondition-loop");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("lib.rs"), "TODO fix\n").expect("write source");

        let mut rule = blank("needs-an-input", RuleKind::Forbid);
        rule.glob = Some("**/*.rs".to_owned());
        rule.pattern = Some("TODO".to_owned());
        rule.requires_path = vec!["absent/input.json".to_owned()];

        let files = vec!["lib.rs".to_owned()];
        let facts = BareFacts::new();
        let inputs = facts.inputs(&files);
        let mut scan = Scan::default();
        evaluate_rules(std::slice::from_ref(&rule), &root, &inputs, &mut scan).expect("no unwind");

        assert_eq!(
            scan.not_evaluated.get("needs-an-input"),
            Some(&NotObserved::RuleSkipped),
            "an unmet precondition is a skip, never a failure and never an error"
        );
        assert_eq!(
            scan.unmet.get("needs-an-input").map(String::as_str),
            Some("absent/input.json"),
            "the skip names the requirement, not merely the rule"
        );
        assert!(scan.findings.is_empty(), "the body was not entered");
        assert!(
            !scan.errored.contains_key("needs-an-input"),
            "a skip is not an error"
        );

        // And the same rule with its input present fires normally — the
        // compatibility half, and what proves the fixture would otherwise match.
        fs::create_dir_all(root.join("absent")).expect("create the declared dir");
        fs::write(root.join("absent/input.json"), "{}\n").expect("write the declared input");
        let mut met = Scan::default();
        evaluate_rules(std::slice::from_ref(&rule), &root, &inputs, &mut met).expect("no unwind");
        assert_eq!(met.findings.len(), 1, "a met precondition is not a filter");
        assert!(met.unmet.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_first_declared_requirement_decides_and_it_is_declaration_order() {
        // Byte-stability (§6): which requirement a skip names must be a function
        // of the config, never of the filesystem's ordering or of how many
        // entries happen to be missing.
        let root = std::env::temp_dir().join("batten-precondition-order");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create root");

        let mut rule = blank("wants-three", RuleKind::Forbid);
        rule.glob = Some("**/*.rs".to_owned());
        rule.pattern = Some("TODO".to_owned());
        rule.requires_path = vec![
            "first.json".to_owned(),
            "second.json".to_owned(),
            "third.json".to_owned(),
        ];
        assert_eq!(rule.unmet_requirement(&root), Some("first.json"));

        fs::write(root.join("first.json"), "{}").expect("write the first");
        assert_eq!(
            rule.unmet_requirement(&root),
            Some("second.json"),
            "satisfying one entry advances to the next in DECLARATION order"
        );
        for name in ["second.json", "third.json"] {
            fs::write(root.join(name), "{}").expect("write");
        }
        assert_eq!(
            rule.unmet_requirement(&root),
            None,
            "a rule whose declared inputs are all present is unconditional"
        );
        // Totality: a row declaring nothing answers `None` rather than needing
        // the caller to test the column first.
        assert_eq!(
            blank("declares-none", RuleKind::Forbid).unmet_requirement(&root),
            None
        );
        let _ = fs::remove_dir_all(&root);
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
                        "cites" => {
                            rule.cites = Some(crate::register::Cites {
                                register: "r".to_owned(),
                                from_register: Some("r".to_owned()),
                                column: Some(1),
                                split: None,
                                within: None,
                                partition: None,
                                relative_to: None,
                                inverse: false,
                            });
                        }
                        "gate" => rule.gate = Some(NativeGate::Singleton),
                        other => panic!("unclassified required column `{other}`"),
                    }
                }
                // `requires()` alone does not make a loadable `forbid` row: its
                // requirement is "exactly one of `pattern` or `regex`", which a
                // flat column list cannot express, so neither appears there
                // (CLOUD-283). This test is about scope pairings, so it supplies
                // the literal and lets `validate_forbid_predicate` be tested by
                // the cases that are about it.
                if matches!(*kind, RuleKind::Forbid | RuleKind::Ratchet) {
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

    /// CLOUD-2304: `interprets` alone is a whole substitution family, and an
    /// empty list is refused rather than loading as a row that recognises no
    /// interpreter.
    #[test]
    fn an_interprets_row_loads_alone_and_an_empty_one_is_refused() {
        let mut rule = blank("loose script", RuleKind::Pipeline);
        rule.scope = RuleScope::MediatedCall;
        rule.interprets = Some(vec!["python3".to_owned()]);
        rule.reason = Some("edit with the host's tools".to_owned());
        if let Err(err) = rule.validate() {
            panic!("an interprets-only row must load: {err}");
        }
        rule.interprets = Some(Vec::new());
        let err = rule
            .validate()
            .expect_err("an empty interprets list is refused");
        assert!(err.to_string().contains("`interprets`"), "{err}");
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
        with_requires_key.requires_key = Some("TEAM-[0-9]+".to_owned());
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

    /// CLOUD-2291/2442: the spelling a `gate = "..."` row parses is the token
    /// the weakening diff reports. `token_enum!`'s `serde` arm makes them one
    /// literal; this pins that serde HONOURS it, so an enum attribute added
    /// later (a `rename_all`, an `alias`) cannot split the two silently.
    #[test]
    fn native_gate_all_is_every_gate_and_as_str_is_its_token() {
        for gate in NativeGate::ALL {
            let expected = serde_json::json!(gate.as_str());
            let token = serde_json::to_value(gate).expect("a gate serializes");
            assert_eq!(token, expected);
            // PARSES, not only renders: a deserialize-side rename would leave
            // the line above green while a `gate = "..."` row read differently.
            let parsed: NativeGate = serde_json::from_value(expected).expect("its token parses");
            assert_eq!(parsed, *gate);
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
                | RuleKind::Policy
                | RuleKind::Reference
                | RuleKind::Native => {}
            }
        }
        assert_eq!(
            RuleKind::ALL.len(),
            12,
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
    fn an_approximating_row_cannot_block_through_any_flag() {
        // CLOUD-331's bound, composed where it can actually be reached.
        //
        // NOT an end-to-end case, and that is a property of the one
        // approximating kind rather than a gap: `judge` carries ambient
        // authority, so `check` refuses the run before classification happens,
        // and under `enforce` a judge outcome never becomes a `Finding` at all
        // — so no config can put an approximating finding in front of
        // `any_blocking`. The composition is what there is to test.
        //
        // The SAME findings are classified twice, against two tables that differ
        // only in the row's `kind`. That is what isolates the bound: severity,
        // content, identity and the promotion flag are all held fixed, so a
        // difference in verdict can only come from the classification.
        let dir = temp_dir("rules-approximating-cannot-block");
        write(&dir, "a.rs", "TODO\n");
        let deciding = forbid("no-todo", "**/*.rs", "TODO");
        let findings = run_static(std::slice::from_ref(&deciding), &dir).unwrap();
        assert_eq!(findings.len(), 1, "the fixture must produce a finding");

        let mut approximating = blank("no-todo", RuleKind::Judge);
        approximating.glob = Some("**/*.rs".to_owned());
        let approximating = std::slice::from_ref(&approximating);

        for promote in [false, true] {
            assert!(
                any_blocking(&findings, promote, std::slice::from_ref(&deciding)),
                "a deciding row blocks (fail_on_warning={promote})"
            );
            // …and the identical findings under an approximating row do not,
            // through EITHER setting. The flag is the point of the second arm:
            // it promotes through `severity::promote`, so a bound applied
            // outside `any_blocking` would be reachable by one CLI argument.
            assert!(
                !any_blocking(&findings, promote, approximating),
                "an approximating row must not block (fail_on_warning={promote})"
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
        rule.severity = Some(RuleSeverity::Advise);
        let findings = run_static(std::slice::from_ref(&rule), &dir).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RuleSeverity::Advise);
        // THE TABLE IS PASSED, not `&[]`. `any_blocking` resolves each finding's
        // owning row to classify it (CLOUD-331), so a fixture that supplied no
        // table would be asserting over a classification path this test does not
        // mean to exercise rather than over the severity rank it does.
        let table = std::slice::from_ref(&rule);
        assert!(
            !any_blocking(&findings, false, table),
            "a warn finding must not block"
        );
        // …and the same finding, unchanged, blocks once the setting promotes it
        // (CLOUD-49). The finding itself is identical in both runs: promotion
        // acts on the exit decision, never on what was stored or reported.
        assert!(
            any_blocking(&findings, true, table),
            "fail_on_warning must promote a warn finding"
        );

        let deny_rule = forbid("no-todo", "**/*.rs", "TODO");
        let deny_table = std::slice::from_ref(&deny_rule);
        let deny = run_static(deny_table, &dir).unwrap();
        for promote in [false, true] {
            assert!(
                any_blocking(&deny, promote, deny_table),
                "a deny finding must block either way"
            );
            assert!(
                !any_blocking(&[], promote, deny_table),
                "no findings, nothing blocks"
            );
        }

        // An UNATTRIBUTABLE finding still blocks, and that is the corrected
        // reading rather than a gap: a finding with no owning row was minted by
        // the ENGINE — baseline staleness, a budget overrun — and those
        // predicates are exact against their own object. Classifying them
        // approximating disarmed three subsystems that never had a rule kind to
        // classify, which is what this arm now holds shut.
        assert!(
            any_blocking(&deny, true, &[]),
            "an engine-minted finding is not silenced by having no configured row"
        );
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

    /// CLOUD-2509: `PATHEXT` is parsed on every leg, not only the one that sets
    /// it. Fails by: an unset variable reading as extensions, a blank entry
    /// surviving the split (a bare-name retry under another name), or the split
    /// dropping the entries it was asked for.
    #[test]
    fn pathext_is_split_into_its_extensions() {
        assert_eq!(executable_extensions(None), Vec::<String>::new());
        assert_eq!(
            executable_extensions(Some(std::ffi::OsStr::new(".COM; .EXE;;.CMD "))),
            [".COM", ".EXE", ".CMD"],
            "trimmed, in order, and no blank entry"
        );
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
            if !crate::fsio::read(&resolved)
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
            &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
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
            &crate::facts::Look::CouldNotLook,
            windows_like_spawn(&root, &dirs, &log),
        );
        assert!(out.is_ok());
        assert_eq!(
            log.into_inner().last().map(|(program, _)| program.clone()),
            Some("sh".to_owned())
        );
    }

    /// A program the pin provides is reached THROUGH the pin, before `PATH`.
    ///
    /// Asserted as the FIRST logged spawn rather than as "the call succeeded":
    /// nothing a toolchain manager provides is on bare `PATH`, so a ladder that
    /// reached the pinned program some other way would be running a different
    /// build — the failure `pinned-toolchain` refuses for an agent's argv and the
    /// engine's own spawn had no rung for. Measured: `no-conflict-markers`
    /// declared `hk`, and the rule could not launch at all.
    ///
    /// The two arms differ only in the fact, which is what makes this
    /// discriminate: could-not-look must fall straight through, since a pin that
    /// cannot be read is not evidence the program is unpinned.
    #[test]
    fn a_pinned_program_is_reached_through_the_pin_and_an_unread_pin_is_not() {
        let attempts = |pinned: &crate::pinned::PinnedFacts| {
            let log = std::cell::RefCell::new(Vec::new());
            let _out = spawn_resolving_on(
                Some(std::ffi::OsStr::new("")),
                None,
                "hk",
                &[".EXE".to_owned()],
                pinned,
                |program: &str, extra: &[&str]| {
                    log.borrow_mut().push((
                        program.to_owned(),
                        extra
                            .iter()
                            .map(|arg| (*arg).to_owned())
                            .collect::<Vec<_>>(),
                    ));
                    Err::<&'static str, _>(std::io::Error::from(std::io::ErrorKind::NotFound))
                },
            );
            log.into_inner()
        };

        let provided = crate::facts::Look::Is(
            ["hk".to_owned()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        assert_eq!(
            attempts(&provided).first().cloned(),
            Some((
                crate::pinned::MEDIATOR.to_owned(),
                vec!["exec".to_owned(), "--".to_owned(), "hk".to_owned()]
            )),
            "the pin is rung 0, not a fallback"
        );

        assert_eq!(
            attempts(&crate::facts::Look::CouldNotLook).first().cloned(),
            Some(("hk".to_owned(), vec![])),
            "could-not-look falls through to the ladder rather than assuming the pin"
        );
    }

    /// A pinned program `PATH` CAN see is left to `PATH`, so the boundary can be
    /// told what to run.
    ///
    /// **The bound rung 0 shipped without, and it cost a landing lap to find.**
    /// The fact is the DIFFERENCE between the composed and the ambient `PATH`, so
    /// the pin's own directories are the ones `PATH` does not carry — which makes
    /// a hit here a directory somebody deliberately put in front. Reaching past it
    /// is how a stubbed program becomes unstubabble: `pr_watch`'s fixture puts the
    /// forge's client at the head of `PATH` and hands the binary that `PATH`, and
    /// an unbounded rung 0 ran the real client against a fenced network instead —
    /// four tests that never terminated and a `verify` that could not finish.
    ///
    /// The sibling above is the other half and they share a program name on
    /// purpose: same fact, same pinned name, and only the `PATH` differs.
    #[test]
    fn a_pinned_program_that_path_resolves_is_left_to_path() {
        let dir = std::env::temp_dir().join(format!("batten-rung0-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the stub directory is created");
        let stub = dir.join("hk");
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").expect("the stub is written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
                .expect("the stub is executable");
        }

        let pinned = crate::facts::Look::Is(
            ["hk".to_owned()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        let log = std::cell::RefCell::new(Vec::new());
        let _out = spawn_resolving_on(
            Some(dir.as_os_str()),
            None,
            "hk",
            &[".EXE".to_owned()],
            &pinned,
            |program: &str, _extra: &[&str]| {
                log.borrow_mut().push(program.to_owned());
                Err::<&'static str, _>(std::io::Error::from(std::io::ErrorKind::NotFound))
            },
        );
        let attempts = log.into_inner();

        assert_eq!(
            attempts.first().map(String::as_str),
            Some("hk"),
            "a name PATH resolves is spawned as written, never rewritten to the mediator: {attempts:?}"
        );
        assert!(
            !attempts
                .iter()
                .any(|program| program == crate::pinned::MEDIATOR),
            "and the mediator is not reached at all on this path: {attempts:?}"
        );

        std::fs::remove_dir_all(&dir).expect("remove the case's scratch directory");
    }

    /// A program only the pin provides, named so no `PATH` resolves it.
    const PIN_ONLY: &str = "batten-pin-only-program";

    /// The pin's answer naming [`PIN_ONLY`].
    fn pins_it(_: &Path) -> crate::pinned::PinnedFacts {
        crate::facts::Look::Is(std::iter::once(PIN_ONLY.to_owned()).collect())
    }

    /// The pin's answer when its record cannot be read.
    fn unread(_: &Path) -> crate::pinned::PinnedFacts {
        crate::facts::Look::CouldNotLook
    }

    /// Every program `spawn_resolving_pinned` tried, under a spawn that only
    /// the mediator answers.
    fn attempts_under(toolchain: &Toolchain) -> (bool, Vec<String>) {
        let mut attempts = Vec::new();
        let ran =
            spawn_resolving_pinned(toolchain, Some(Path::new(".")), PIN_ONLY, |program, _| {
                attempts.push(program.to_owned());
                if program == crate::pinned::MEDIATOR {
                    Ok(())
                } else {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                }
            });
        (ran.is_ok(), attempts)
    }

    /// A pin record that stopped answering is repaired BEFORE the ladder, so the
    /// pinned program reaches the mediator on the first spawn (CLOUD-1324).
    ///
    /// Fails by: the could-not-look-with-a-root arm dropped, which leaves the
    /// unread record standing and spawns the bare name first.
    #[test]
    fn an_unread_pin_is_repaired_before_the_first_spawn() {
        let (ran, attempts) = attempts_under(&Toolchain {
            cached: unread,
            repaired: pins_it,
            re_resolved: unread,
        });
        assert!(ran, "{attempts:?}");
        assert_eq!(attempts, [crate::pinned::MEDIATOR], "{attempts:?}");
    }

    /// A pin that only the LAZY re-ask finds is spawned through the mediator
    /// once the ladder has failed `NotFound` (CLOUD-1371).
    ///
    /// Fails by: the retry taken on any error but `NotFound`, which skips the
    /// re-ask on exactly the failure it exists for.
    #[test]
    fn a_pin_only_the_re_ask_finds_is_spawned_once_the_ladder_fails() {
        let (ran, attempts) = attempts_under(&Toolchain {
            cached: unread,
            repaired: unread,
            re_resolved: pins_it,
        });
        assert!(ran, "{attempts:?}");
        assert_eq!(
            attempts.first().map(String::as_str),
            Some(PIN_ONLY),
            "{attempts:?}"
        );
        assert_eq!(
            attempts.last().map(String::as_str),
            Some(crate::pinned::MEDIATOR),
            "{attempts:?}"
        );
    }

    /// An unread pin with no re-ask that finds the program leaves the ladder's
    /// own `NotFound` standing.
    #[test]
    fn a_pin_nothing_finds_leaves_not_found_standing() {
        let (ran, attempts) = attempts_under(&Toolchain {
            cached: unread,
            repaired: unread,
            re_resolved: unread,
        });
        assert!(!ran, "{attempts:?}");
        assert!(
            !attempts
                .iter()
                .any(|program| program == crate::pinned::MEDIATOR),
            "{attempts:?}"
        );
    }

    /// A `PATH` directory holding a `batten` stub, and the path of an image that
    /// is deliberately NEVER created: the ladder is asked what it SPAWNS, and the
    /// spawn is [`ladder_walk`]'s closure, which reads no file.
    fn rung_minus_one_fixture() -> (PathBuf, PathBuf) {
        let dir = temp_dir("rung-minus-one");
        write(&dir, crate::surface::BINARY, "#!/bin/sh\nexit 0\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.join(crate::surface::BINARY),
                fs::Permissions::from_mode(0o755),
            )
            .expect("the stub is executable");
        }
        let image = dir.join("image").join(crate::surface::BINARY);
        (dir, image)
    }

    /// Every program the ladder tried, in order, and whether it ended `Ok`.
    ///
    /// `runnable` is the ONE program the fake loader admits; everything else
    /// reports `NotFound`, so the log is the whole route rather than just its
    /// head — which is what lets a case assert ORDER and not only outcome.
    ///
    /// The pin provides `batten` AND `hk`, so one fact serves both the arm that
    /// asks whether the image beats the pin and the arm that asks whether any
    /// other program still reaches it.
    fn ladder_walk(
        path: &str,
        running: Option<&Path>,
        program: &str,
        runnable: Option<&str>,
    ) -> (bool, Vec<String>) {
        let pinned = crate::facts::Look::Is(
            [crate::surface::BINARY.to_owned(), "hk".to_owned()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
        );
        let log = std::cell::RefCell::new(Vec::new());
        let out = spawn_resolving_on_image(
            Some(std::ffi::OsStr::new(path)),
            None,
            running,
            program,
            &[".EXE".to_owned()],
            &pinned,
            |program: &str, _extra: &[&str]| {
                log.borrow_mut().push(program.to_owned());
                if runnable == Some(program) {
                    Ok("ran")
                } else {
                    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                }
            },
        );
        (out.is_ok(), log.into_inner())
    }

    /// A declared `batten` runs the image that asked — before `PATH`, before the
    /// pin.
    ///
    /// Why the rung exists: see [`spawn_resolving_on_image`]'s rung -1.
    ///
    /// Five arms, because each is a way the rung can be written wrong: deleting
    /// it, matching on any program, ordering it after the pin, dropping the
    /// `running = None` case, or returning a `NotFound` image's error rather than
    /// falling through. Which errors fall through, and which images are declined,
    /// is the case below.
    #[test]
    fn a_declared_batten_resolves_to_the_running_image_before_the_pin() {
        let (dir, image) = rung_minus_one_fixture();
        let image_name = image.display().to_string();
        let attempts = ladder_walk;

        let on_path = dir.to_str().expect("the temp path is UTF-8");

        // 1. The image wins over a `batten` PATH can see and a pin that provides
        //    it. Deleting the rung, or matching nothing, fails here.
        let (ok, walked) = attempts(
            on_path,
            Some(image.as_path()),
            crate::surface::BINARY,
            Some(&image_name),
        );
        assert!(ok, "the image ran");
        assert_eq!(
            walked,
            vec![image_name.clone()],
            "the running image is spawned first and nothing else is tried"
        );

        // 2. ANY OTHER PROGRAM resolves exactly as it does today. A rung that
        //    matched on more than the binary name fails here.
        let (_, walked) = attempts(on_path, Some(image.as_path()), "hk", None);
        assert_eq!(
            walked.first().map(String::as_str),
            Some(crate::pinned::MEDIATOR),
            "`hk` is still the pin's, never the image's: {walked:?}"
        );
        assert!(
            !walked.contains(&image_name),
            "and the image is not reached for it at all: {walked:?}"
        );

        // 3. NO IMAGE, today's answer. `current_exe` failing is a fact about
        //    `/proc`, not about the row.
        let (_, walked) = attempts(on_path, None, crate::surface::BINARY, None);
        assert_eq!(
            walked.first().map(String::as_str),
            Some(crate::surface::BINARY),
            "without an image the PATH-resolved name is spawned as written: {walked:?}"
        );

        // 4. BEFORE THE PIN, which a `PATH` stub alone cannot show: rung 0 fires
        //    only where `PATH` cannot resolve the program, so this is the only
        //    shape that orders the two. A rung placed after the pin records the
        //    mediator here.
        let (ok, walked) = attempts(
            "",
            Some(image.as_path()),
            crate::surface::BINARY,
            Some(&image_name),
        );
        assert!(ok, "the image ran");
        assert_eq!(
            walked,
            vec![image_name.clone()],
            "the image is reached before the pin, not after it"
        );

        // 5. AN IMAGE WHOSE SPAWN FINDS NOTHING FALLS THROUGH, and is not
        //    retried.
        let (_, walked) = attempts("", Some(image.as_path()), crate::surface::BINARY, None);
        assert_eq!(
            walked.first().map(String::as_str),
            Some(image_name.as_str()),
            "the image is still tried first: {walked:?}"
        );
        assert_eq!(
            walked.get(1).map(String::as_str),
            Some(crate::pinned::MEDIATOR),
            "and the ladder then picks what it would have picked today: {walked:?}"
        );
        assert_eq!(
            walked
                .iter()
                .filter(|program| **program == image_name)
                .count(),
            1,
            "the image is tried once and never retried: {walked:?}"
        );

        std::fs::remove_dir_all(&dir).expect("remove the case's scratch directory");
    }

    /// Rung -1 spawns only an image named `batten`, and answers with any spawn
    /// error but `NotFound` rather than walking the ladder on it.
    ///
    /// Split from the case above for length; these are the two guards whose
    /// absence ran the suite recursively (CLOUD-2386).
    #[test]
    fn rung_minus_one_declines_a_foreign_image_and_keeps_its_own_error() {
        let (dir, image) = rung_minus_one_fixture();
        let image_name = image.display().to_string();
        let on_path = dir.to_str().expect("the temp path is UTF-8");
        let attempts = ladder_walk;

        // AN IMAGE NOT NAMED `batten` IS NEVER SPAWNED — under `cargo test`
        // it is the harness, and spawning it ran the suite recursively. The
        // library's own harness is `batten-<hash>`, so a prefix match would
        // still spawn it. After `engine update`, `/proc/self/exe` reads
        // `batten (deleted)`, which is declined the same way.
        for declined in [
            "batten-0123456789abcdef",
            "it-0123456789abcdef",
            "batten (deleted)",
        ] {
            let other = dir.join("image").join(declined);
            let other_name = other.display().to_string();
            let (_, walked) =
                attempts(on_path, Some(other.as_path()), crate::surface::BINARY, None);
            assert!(
                !walked.contains(&other_name),
                "`{declined}` is not this engine and is never spawned as it: {walked:?}"
            );
        }

        // AN IMAGE THAT COULD NOT BE EXECUTED FALLS THROUGH; ANY OTHER ERROR IS
        // ITS ANSWER, and the ladder is not walked on it. Every spawn fails with
        // `kind` here, so the route is the whole answer.
        let pinned = crate::facts::Look::Is(std::iter::once("hk".to_owned()).collect());
        let walk = |kind: std::io::ErrorKind| {
            let mut tried = Vec::new();
            let out = spawn_resolving_on_image(
                Some(std::ffi::OsStr::new(on_path)),
                None,
                Some(image.as_path()),
                crate::surface::BINARY,
                &[".EXE".to_owned()],
                &pinned,
                |program: &str, _extra: &[&str]| -> std::io::Result<()> {
                    tried.push(program.to_owned());
                    Err(std::io::Error::from(kind))
                },
            );
            (out.map_err(|error| error.kind()), tried)
        };
        let (out, tried) = walk(std::io::ErrorKind::WouldBlock);
        assert_eq!(
            out,
            Err(std::io::ErrorKind::WouldBlock),
            "the image's own error is returned"
        );
        assert_eq!(
            tried,
            vec![image_name.clone()],
            "and nothing else is spawned"
        );
        let (_, tried) = walk(std::io::ErrorKind::ExecutableFileBusy);
        assert_eq!(
            tried.first(),
            Some(&image_name),
            "the busy image is tried first"
        );
        assert!(tried.len() > 1, "and the ladder is walked on it: {tried:?}");

        std::fs::remove_dir_all(&dir).expect("remove the case's scratch directory");
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
        rule.key_from = Some(crate::config_model::Field::InputId);
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
    /// Both halves of a field bound that cannot decide are refused at LOAD.
    ///
    /// `max_age = 0`'s reason, one column over: a value that makes the column
    /// decide nothing reads from the file as though it decided something, and
    /// this one fails in the PERMISSIVE direction — `at = 0` never matches a
    /// field, so the row would satisfy every call through the
    /// absent-is-could-not-look arm while looking like a gate.
    #[test]
    fn a_field_bound_that_can_never_decide_is_refused_at_load() {
        let row = |bound: FieldBound| {
            let mut rule = receipt_row(Some(ReceiptTrigger::Write));
            rule.requires_field = Some(bound);
            rule.validate()
        };
        assert!(
            row(FieldBound {
                at: 0,
                is: "ready".to_owned()
            })
            .is_err(),
            "field 0 does not exist under 1-indexed counting"
        );
        assert!(
            row(FieldBound {
                at: 6,
                is: String::new()
            })
            .is_err(),
            "an empty required value can never be matched by a whitespace-split field"
        );
        assert!(
            row(FieldBound {
                at: 6,
                is: "ready".to_owned()
            })
            .is_ok(),
            "and a bound that can decide loads"
        );
    }

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
                rule.when_present = Some(crate::config_model::Field::InputState);
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

    // ---------------------------------------------------------------------
    // CLOUD-2485: cases for mutants the CLOUD-2453 sweep left unkilled.
    // ---------------------------------------------------------------------

    /// The text of a refusal, or empty for a pass.
    fn refusal(result: anyhow::Result<()>) -> String {
        result.err().map(|err| err.to_string()).unwrap_or_default()
    }

    /// Only a `native` row grades a native gate.
    ///
    /// Fails by: reading the grade off a row of another kind.
    #[test]
    fn only_a_native_row_grades_a_native_gate() {
        let graded = |kind| Rule {
            gate: Some(NativeGate::History),
            severity: Some(RuleSeverity::Allow),
            ..blank("g", kind)
        };
        assert_eq!(
            native_grade(&[graded(RuleKind::Native)], NativeGate::History),
            RuleSeverity::Allow
        );
        assert_eq!(
            native_grade(&[graded(RuleKind::Shape)], NativeGate::History),
            RuleSeverity::Deny
        );
    }

    /// Each authority has its own stable token.
    ///
    /// Fails by: an empty or placeholder token.
    #[test]
    fn every_authority_has_its_token() {
        let tokens: Vec<&str> = Authority::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(tokens, ["supplied", "acquires", "spawns"]);
    }

    fn verdict_program(program: &str) -> VerdictProgram {
        VerdictProgram {
            program: program.to_owned(),
            subcommands: None,
            nested: None,
            except: None,
            any_argument: None,
        }
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| (*word).to_owned()).collect()
    }

    /// A verdict program matches its own program, then its subcommand and
    /// nested word, its non-query words, or any word at all.
    ///
    /// Fails by: a constant answer, the program test inverted, any list test
    /// inverted, or `any_argument` admitting a bare invocation.
    #[test]
    fn a_verdict_program_matches_each_columns_reading() {
        let nested = VerdictProgram {
            subcommands: Some(words(&["pr"])),
            nested: Some(words(&["merge"])),
            ..verdict_program("gh")
        };
        assert!(nested.matches("gh", &["pr", "merge"]));
        assert!(!nested.matches("gh", &["pr", "view"]));
        assert!(!nested.matches("hub", &["pr", "merge"]));
        let except = VerdictProgram {
            except: Some(words(&["log"])),
            ..verdict_program("git")
        };
        assert!(except.matches("git", &["push"]));
        assert!(!except.matches("git", &["log"]));
        let any = VerdictProgram {
            any_argument: Some(true),
            ..verdict_program("cargo")
        };
        assert!(any.matches("cargo", &["test"]));
        assert!(!any.matches("cargo", &[]));
        assert!(!verdict_program("cargo").matches("cargo", &["test"]));
    }

    /// A verdict program naming two words, or `any_argument` beside a list,
    /// is refused.
    ///
    /// Fails by: passing every row, or either disjunction conjoined.
    #[test]
    fn a_verdict_program_refuses_two_words_and_a_narrowed_any() {
        let two_words = VerdictProgram {
            subcommands: Some(words(&["x"])),
            ..verdict_program("git push")
        };
        assert!(refusal(two_words.validate("r")).contains("names one program"));
        let narrowed = VerdictProgram {
            any_argument: Some(true),
            subcommands: Some(words(&["x"])),
            ..verdict_program("git")
        };
        assert!(refusal(narrowed.validate("r")).contains("cannot be narrowed"));
        let fine = VerdictProgram {
            subcommands: Some(words(&["x"])),
            ..verdict_program("git")
        };
        assert_eq!(refusal(fine.validate("r")), "");
    }

    /// Only a command row has a program, and it is the check's first word.
    ///
    /// Fails by: answering `None`, or for the wrong kinds.
    #[test]
    fn only_a_command_row_has_a_program() {
        assert_eq!(
            command("c", "*.rs", "cargo test --all").program(),
            Some("cargo")
        );
        let forbid_with_check = Rule {
            check: Some(String::from("cargo test")),
            ..forbid("f", "*.rs", "x")
        };
        assert_eq!(forbid_with_check.program(), None);
    }

    /// A partial ceiling is refused, and a rewrite table on a token ceiling
    /// is too.
    ///
    /// Fails by: passing every row, or the unit test inverted.
    #[test]
    fn a_ceiling_is_whole_and_its_rewrites_belong_to_the_artifact_unit() {
        let partial = Rule {
            measures: Some(crate::config_model::Field::Prompt),
            ..blank("c", RuleKind::Shape)
        };
        assert!(
            refusal(partial.validate_ceiling()).contains("needs `measures`, `counts` and `max`")
        );
        let ceiling = |counts| Rule {
            tool: Some(String::from("Task")),
            measures: Some(crate::config_model::Field::Prompt),
            counts: Some(counts),
            max: Some(3),
            resolves: vec![Rewrite {
                reference: String::from("a"),
                path: String::from("b"),
            }],
            ..blank("c", RuleKind::Shape)
        };
        assert!(
            refusal(ceiling(CeilingUnit::Tokens).validate_ceiling())
                .contains("belongs to `counts = \"tracked-artifacts\"`")
        );
        assert!(
            !refusal(ceiling(CeilingUnit::TrackedArtifacts).validate_ceiling())
                .contains("belongs to `counts = \"tracked-artifacts\"`")
        );
    }

    /// A delta key needs its base, and a base belongs to a delta key only.
    ///
    /// Fails by: passing every row, or dropping either arm.
    #[test]
    fn a_delta_key_and_its_base_travel_together() {
        let receipt = |key, base: Option<&str>| Rule {
            key: Some(key),
            key_base: base.map(ToOwned::to_owned),
            ..blank("r", RuleKind::Receipt)
        };
        assert!(
            refusal(receipt(ReceiptKey::Delta, None).validate_delta_base())
                .contains("requires `key_base`")
        );
        assert!(
            refusal(receipt(ReceiptKey::Head, Some("origin/main")).validate_delta_base())
                .contains("belongs to `key = \"delta\"`")
        );
        assert_eq!(
            refusal(receipt(ReceiptKey::Delta, Some("origin/main")).validate_delta_base()),
            ""
        );
    }

    /// A receipt row keyed on both a pattern and a tool is refused, and a
    /// named key and its projection travel together.
    ///
    /// Fails by: dropping the both-selectors guard or either named-key arm.
    #[test]
    fn a_receipt_rows_selectors_and_named_key_are_refused_when_inconsistent() {
        let both = Rule {
            pattern: Some(String::from("gh pr ready")),
            tool: Some(String::from("save_issue")),
            ..blank("r", RuleKind::Receipt)
        };
        assert!(
            refusal(both.validate_receipt_columns()).contains("carries both `pattern` and `tool`")
        );
        let keyed = |key, from| Rule {
            pattern: Some(String::from("gh pr ready")),
            key: Some(key),
            key_from: from,
            ..blank("r", RuleKind::Receipt)
        };
        assert!(
            refusal(keyed(ReceiptKey::Named, None).validate_receipt_columns())
                .contains("requires `key_from`")
        );
        assert!(
            refusal(
                keyed(
                    ReceiptKey::Head,
                    Some(crate::config_model::Field::SessionId)
                )
                .validate_receipt_columns()
            )
            .contains("belongs to `key = \"named\"`")
        );
    }

    /// A marker naming no branch-keyed family is refused.
    ///
    /// Fails by: passing every row.
    #[test]
    fn a_marker_must_name_a_branch_keyed_family() {
        let marked = |marker: &str| Rule {
            while_marker: Some(marker.to_owned()),
            ..blank("m", RuleKind::Shape)
        };
        assert!(
            refusal(marked("no-such-family").validate_marker())
                .contains("names no branch-keyed receipt family")
        );
        assert_eq!(
            refusal(marked(crate::config_model::BRANCH_KEYED_RECEIPTS[0]).validate_marker()),
            ""
        );
    }

    /// An empty `checks` list is refused.
    ///
    /// Fails by: passing every row.
    #[test]
    fn an_empty_checks_list_is_refused() {
        let empty = Rule {
            checks: Some(Vec::new()),
            ..blank("r", RuleKind::Receipt)
        };
        assert!(refusal(empty.validate_receipt_names()).contains("at least one entry in `checks`"));
    }

    /// `ask` is refused off the mediated call, and a deny row there is not
    /// held to `ask`'s obligations.
    ///
    /// Fails by: passing every row, or applying the `ask` checks to `deny`.
    #[test]
    fn ask_is_a_mediated_call_disposition_only() {
        let tree_ask = Rule {
            severity: Some(RuleSeverity::Ask),
            ..forbid("f", "*.rs", "x")
        };
        assert!(
            refusal(tree_ask.validate_ask_disposition()).contains("hands the decision to a human")
        );
        let reasonless_deny = Rule {
            reason: None,
            ..blank("s", RuleKind::Shape)
        };
        assert_eq!(refusal(reasonless_deny.validate_ask_disposition()), "");
    }

    /// An empty tag glob is refused.
    ///
    /// Fails by: passing every row.
    #[test]
    fn an_empty_tag_glob_is_refused() {
        let row = Rule {
            tags: vec![String::new()],
            ..blank("p", RuleKind::Policy)
        };
        assert!(refusal(row.validate_repository_state()).contains("empty glob"));
    }

    /// A policy row naming no source is refused as naming none, never as
    /// naming two.
    ///
    /// Fails by: dropping the no-source arm.
    #[test]
    fn a_policy_row_naming_no_source_is_refused_as_such() {
        let row = Rule {
            module: None,
            bundle: None,
            preset: None,
            ..blank("p", RuleKind::Policy)
        };
        assert!(refusal(row.validate_policy_source()).contains("requires one of `module`"));
    }

    /// `environments` and `install_env` each qualify `preset`, so either one
    /// alone on a row naming no preset is a dead column.
    ///
    /// Fails by: the two read as one conjunction (`&&`), which refuses only a
    /// row declaring both and loads one declaring either alone (CLOUD-2789).
    #[test]
    fn either_install_column_without_a_preset_is_refused() {
        for row in [
            Rule {
                environments: Some(vec!["agent".to_owned()]),
                ..blank("p", RuleKind::Policy)
            },
            Rule {
                install_env: vec!["MISE_ENV=agent".to_owned()],
                ..blank("p", RuleKind::Policy)
            },
        ] {
            assert!(
                refusal(row.validate_policy_source()).contains("names no preset"),
                "{row:?}"
            );
        }
    }

    /// A declared format must agree with the glob's extension.
    ///
    /// Fails by: passing every row, or the agreement test inverted.
    #[test]
    fn a_declared_format_must_agree_with_the_globs_extension() {
        let row = |format| Rule {
            glob: Some(String::from("*.json")),
            format: Some(format),
            ..blank("d", RuleKind::Document)
        };
        assert!(
            refusal(row(crate::facts::Format::Toml).validate_declared_format_matches_glob())
                .contains("whose extension names")
        );
        assert_eq!(
            refusal(row(crate::facts::Format::Json).validate_declared_format_matches_glob()),
            ""
        );
    }

    /// An external row whose path climbs out of its root is refused, as is
    /// an empty one.
    ///
    /// Fails by: requiring the path be both empty and escaping.
    #[test]
    fn an_external_path_must_be_non_empty_and_stay_beneath_its_root() {
        for path in ["", "../x"] {
            let row = Rule {
                external: vec![crate::facts::Rooted {
                    id: String::from("e"),
                    root: String::from("HOME"),
                    path: String::from(path),
                }],
                ..blank("p", RuleKind::Policy)
            };
            assert!(
                refusal(row.validate_external_rows()).contains("stays beneath its root"),
                "{path:?}"
            );
        }
    }

    fn tool_query(id: &str, tool: &str, version: &str, input: &str) -> crate::facts::ToolQuery {
        crate::facts::ToolQuery {
            id: id.to_owned(),
            tool: tool.to_owned(),
            version: version.to_owned(),
            input: input.to_owned(),
            run: Vec::new(),
        }
    }

    /// A tool row needs both an id and an input, and one id names one key:
    /// a second declaration differing in any component is refused, and an
    /// identical one is not.
    ///
    /// Fails by: passing every row, either emptiness test conjoined, or any
    /// component comparison inverted or conjoined.
    #[test]
    fn a_tool_rows_id_names_one_key() {
        let rows = |tools| Rule {
            tools,
            ..blank("p", RuleKind::Policy)
        };
        assert!(
            refusal(rows(vec![tool_query("", "t", "1", "a")]).validate_tool_rows())
                .contains("non-empty `id` and `input`")
        );
        let base = tool_query("v", "t", "1", "a");
        for other in [
            tool_query("v", "u", "1", "a"),
            tool_query("v", "t", "2", "a"),
            tool_query("v", "t", "1", "b"),
        ] {
            assert!(
                refusal(rows(vec![base.clone(), other.clone()]).validate_tool_rows())
                    .contains("declared twice"),
                "{other:?}"
            );
        }
        assert_eq!(
            refusal(rows(vec![base.clone(), base]).validate_tool_rows()),
            ""
        );
    }

    fn minted_query(
        id: &str,
        mint: &str,
        field: usize,
        recency: usize,
        age: u32,
    ) -> crate::facts::MintedQuery {
        crate::facts::MintedQuery {
            id: id.to_owned(),
            mint: mint.to_owned(),
            field,
            recency,
            max_age_days: age,
        }
    }

    /// A minted row's value and recency are different columns, and one id
    /// names one question: a second declaration differing in any component
    /// is refused, and an identical one is not.
    ///
    /// Fails by: passing every row, the column test inverted, or any
    /// component comparison inverted or conjoined.
    #[test]
    fn a_minted_rows_id_names_one_question() {
        let rows = |minted| Rule {
            minted,
            ..blank("p", RuleKind::Policy)
        };
        assert!(
            refusal(rows(vec![minted_query("m", "issue-read", 1, 1, 7)]).validate_minted_rows())
                .contains("same index")
        );
        let base = minted_query("m", "issue-read", 1, 2, 7);
        assert_eq!(refusal(rows(vec![base.clone()]).validate_minted_rows()), "");
        for other in [
            minted_query("m", "issue-search", 1, 2, 7),
            minted_query("m", "issue-read", 3, 2, 7),
            minted_query("m", "issue-read", 1, 3, 7),
            minted_query("m", "issue-read", 1, 2, 8),
        ] {
            assert!(
                refusal(rows(vec![base.clone(), other.clone()]).validate_minted_rows())
                    .contains("declared twice"),
                "{other:?}"
            );
        }
        assert_eq!(
            refusal(rows(vec![base.clone(), base]).validate_minted_rows()),
            ""
        );
    }

    /// A sink is refused off the tree surface.
    ///
    /// Fails by: passing every row, or the scope test inverted.
    #[test]
    fn a_sink_belongs_to_a_tree_scoped_row() {
        let sinking = |scope| Rule {
            scope,
            produces: Some(Sink {
                kind: crate::facts::Production::Journal,
                key: SinkKey::Rule,
            }),
            ..forbid("f", "*.rs", "x")
        };
        assert!(
            refusal(sinking(RuleScope::MediatedCall).validate_sink())
                .contains("nothing for a sink")
        );
        assert!(!refusal(sinking(RuleScope::Tree).validate_sink()).contains("nothing for a sink"));
    }

    /// `exclude_paths` with no glob to subtract from is refused.
    ///
    /// Fails by: passing every row.
    #[test]
    fn exclude_paths_need_a_glob() {
        let row = Rule {
            glob: None,
            exclude_paths: vec![String::from("vendor/**")],
            ..blank("f", RuleKind::Forbid)
        };
        assert!(refusal(row.validate_exclude_paths()).contains("declares none"));
    }

    /// A judge row's settling check is the resolved argv it is handed.
    ///
    /// Fails by: answering `None`, or the row's own empty argv.
    #[test]
    fn a_judge_settles_on_the_resolved_argv() {
        let argv = vec![String::from("judge"), String::from("--run")];
        assert_eq!(
            blank("j", RuleKind::Judge).settling_argv(&argv),
            Some(Check::Argv(argv))
        );
    }

    /// A document row carries exactly one of `pattern` and `reads`, and a
    /// forbid row exactly one of `pattern` and `regex`.
    ///
    /// Fails by: dropping any arm.
    #[test]
    fn each_predicate_pair_is_exactly_one() {
        let document = |pattern: bool, reads: bool| Rule {
            pattern: pattern.then(|| String::from("x")),
            reads: reads.then(|| String::from("y")),
            ..blank("d", RuleKind::Document)
        };
        assert!(refusal(document(true, true).validate_document_predicate()).contains("never both"));
        assert!(
            refusal(document(false, false).validate_document_predicate())
                .contains("requires `pattern`")
        );
        let both = Rule {
            regex: Some(String::from("x")),
            ..forbid("f", "*.rs", "x")
        };
        assert!(refusal(both.validate_forbid_predicate()).contains("never both"));
    }

    /// Only `policy` repairs at the boundary.
    ///
    /// Fails by: answering `false` for every kind.
    #[test]
    fn a_policy_row_repairs_at_the_boundary() {
        assert!(RuleKind::Policy.repairs_at_the_boundary());
    }

    /// The preset schema enumerates the embedded preset names.
    ///
    /// Fails by: an empty schema.
    #[test]
    fn the_preset_schema_enumerates_the_embedded_names() {
        let schema = preset_name_schema(&mut schemars::SchemaGenerator::default());
        let names = schema
            .get("enum")
            .and_then(serde_json::Value::as_array)
            .expect("an enum of names");
        assert_eq!(names.len(), crate::config_model::preset_names().len());
        assert!(!names.is_empty());
    }

    /// A located rule id points at its declaring line, or at the source.
    ///
    /// Fails by: an empty or placeholder pointer.
    #[test]
    fn a_located_id_points_at_its_line() {
        let at = Located {
            text: "version = 1\n\n[[rule]]\nid = \"r\"\n",
            source: "batten.toml",
        };
        assert_eq!(at.pointer("r"), "batten.toml:4");
        assert_eq!(at.pointer("absent"), "batten.toml");
    }

    /// Each decidability and error class has its own stable token.
    ///
    /// Fails by: an empty or placeholder token.
    #[test]
    fn every_decidability_and_error_class_has_its_token() {
        let decidability: Vec<&str> = Decidability::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(decidability, ["deciding", "approximating"]);
        let classes: Vec<&str> = ErrorClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(classes, ["internal", "panic"]);
    }

    fn tree_options(scope: &Scope) -> RunOptions<'_> {
        RunOptions {
            half: None,
            keyed_bases: &[],
            checks: crate::policy::ModuleChecks::Run,
            scope,
            surface: crate::facts::Surface::Check,
            now: None,
        }
    }

    /// Both narrowed entry points and the recorded one run the rows they are
    /// handed, and the recorded one withholds a spawning row.
    ///
    /// Fails by: returning an empty scan, or withholding the non-spawning rows
    /// instead of the spawning ones.
    #[test]
    fn every_entry_point_runs_its_rows() {
        let dir = temp_dir("rules-entry-points");
        write(&dir, "src/a.rs", "TODO\n");
        let rows = [forbid("no-todo", "**/*.rs", "TODO")];
        let found = |scan: anyhow::Result<Scan>| scan.expect("runs").findings.len();
        let tree = Scope::Tree;
        assert_eq!(
            found(run_static_over(
                &rows,
                &[],
                crate::policy::Vocabulary::EMPTY,
                &dir,
                tree_options(&tree)
            )),
            1
        );
        assert_eq!(
            found(run_all_over(
                &rows,
                &[],
                crate::policy::Vocabulary::EMPTY,
                &dir,
                tree_options(&tree)
            )),
            1
        );
        let recorded = [rows[0].clone(), command("spawns", "**/*.rs", "false")];
        let scan = run_recorded(
            &recorded,
            &[],
            crate::policy::Vocabulary::EMPTY,
            &dir,
            crate::policy::ModuleChecks::Run,
            crate::facts::Surface::Check,
        )
        .expect("runs");
        let fired: Vec<&str> = scan.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(fired, ["no-todo"]);
        assert_eq!(
            scan.not_evaluated.get("spawns"),
            Some(&NotObserved::RuleSkipped)
        );
        assert_eq!(scan.not_evaluated.get("no-todo"), None);
    }

    /// A scan counts the files and bytes it read, and records a cost row per
    /// rule.
    ///
    /// Fails by: a counter answering a constant, `count_read` counting
    /// nothing, or an empty cost census.
    #[test]
    fn a_scan_counts_what_it_read_and_what_each_rule_cost() {
        let dir = temp_dir("rules-read-counters");
        write(&dir, "src/a.rs", "TODO one\n");
        write(&dir, "src/b.rs", "TODO two\n");
        let (files, bytes) = (files_read(), bytes_read());
        run_static(&[forbid("no-todo", "**/*.rs", "TODO")], &dir).expect("runs");
        assert!(files_read() >= files + 2, "two files read");
        assert!(bytes_read() >= bytes + 18, "eighteen bytes read");
        let costs: Vec<String> = rule_costs().into_iter().map(|cost| cost.rule).collect();
        // Exact, because the census is cleared per run and this case is the only
        // run in its process: nextest forks per case, which `test:cargo` uses.
        assert_eq!(costs, ["no-todo"]);
    }

    /// Each acquisition is counted, and a target that is not a readable file
    /// is unreadable rather than absent.
    ///
    /// Fails by: a constant counter, or reading every failure as absent.
    #[test]
    fn an_acquisition_is_counted_and_a_directory_is_unreadable() {
        let dir = temp_dir("rules-acquire");
        fs::create_dir_all(dir.join("dir.json")).expect("a directory");
        let want = want_for("dir.json", Wanted::Document);
        let before = documents_acquired();
        assert!(matches!(
            acquire(&dir, "dir.json", want),
            Acquired::No(NotAcquired::Unreadable)
        ));
        assert!(matches!(
            acquire(&dir, "absent.json", want),
            Acquired::No(NotAcquired::Absent)
        ));
        assert!(documents_acquired() >= before + 2);
    }

    /// A row's declared documents and uses are its literals plus what its
    /// globs select, sorted.
    ///
    /// Fails by: any placeholder list.
    #[test]
    fn declared_documents_and_uses_are_literals_plus_selections() {
        let files = vec![String::from("x.toml"), String::from("y.rs")];
        let row = Rule {
            documents: vec![String::from("a.json")],
            sources: vec![String::from("*.toml")],
            uses: vec![String::from("lib.rs")],
            use_sources: vec![String::from("*.rs")],
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            declared_documents(&row, &files).expect("selects"),
            ["a.json", "x.toml"]
        );
        assert_eq!(
            declared_uses(&row, &files).expect("selects"),
            ["lib.rs", "y.rs"]
        );
    }

    /// Only a tree-scoped policy row's documents are acquired, and the
    /// acquisition gets its own cost row only when it read something.
    ///
    /// Fails by: acquiring a mediated row's documents, returning nothing, or
    /// recording a cost row for an empty acquisition.
    #[test]
    fn only_a_tree_policy_rows_documents_are_acquired_and_costed() {
        let dir = temp_dir("rules-acquire-declared");
        write(&dir, "a.json", "{}");
        let files = vec![String::from("a.json")];
        let row = |scope| Rule {
            scope,
            documents: vec![String::from("a.json")],
            ..blank("p", RuleKind::Policy)
        };
        let tree = acquire_declared_measured(&[row(RuleScope::Tree)], &dir, &files, &files)
            .expect("acquires");
        assert_eq!(tree.len(), 1);
        // Exact, for `a_scan_counts_what_it_read_and_what_each_rule_cost`'s reason:
        // one run per process under nextest, which `test:cargo` uses.
        let rows = || -> Vec<String> { rule_costs().into_iter().map(|cost| cost.rule).collect() };
        assert_eq!(
            rows(),
            [DECLARED_ACQUISITION],
            "the acquisition is its own cost row"
        );
        let mediated =
            acquire_declared_measured(&[row(RuleScope::MediatedCall)], &dir, &files, &files)
                .expect("acquires");
        assert!(mediated.is_empty());
        assert!(rows().is_empty(), "nothing read, no row");
    }

    /// A one-commit repository carrying `a.txt`, its index written.
    fn seeded(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        write(&dir, "a.txt", "a\n");
        crate::gitwrite::commit_paths(&dir, &[String::from("a.txt")], "fixture").expect("seed");
        dir
    }

    /// A rule set declaring only a HEAD read still gets it: the early return
    /// is for a rule set declaring nothing at all.
    ///
    /// Fails by: any conjunct of the nothing-declared test disjoined, which
    /// returns before reading the one declared member.
    #[test]
    fn a_lone_git_read_is_still_answered() {
        let dir = seeded("rules-git-lone-read");
        let row = Rule {
            git: vec![GitRead::Head],
            ..blank("p", RuleKind::Policy)
        };
        let facts = git_facts(&[row], &dir);
        assert!(facts.head.is_some(), "{facts:?}");
        assert_eq!(facts.head, crate::git::head_fact(&dir).ok());
    }

    /// History queries are deduplicated by id, and only by id.
    ///
    /// Fails by: the dedup test inverted, which drops every query after the
    /// first that carries a different id.
    #[test]
    fn history_queries_are_deduplicated_by_id() {
        let dir = seeded("rules-git-history-dedup");
        let query = |id: &str| crate::facts::HistoryQuery {
            id: String::from(id),
            tags: Some(String::from("*")),
            path: None,
            filter: None,
        };
        let distinct = [query("first"), query("second")];
        let rows = [
            Rule {
                history: vec![distinct[0].clone(), distinct[0].clone()],
                ..blank("p", RuleKind::Policy)
            },
            Rule {
                history: vec![distinct[1].clone()],
                ..blank("q", RuleKind::Policy)
            },
        ];
        let facts = git_facts(&rows, &dir);
        let expected = crate::git::history_facts(&dir, &distinct).ok();
        assert!(expected.is_some());
        assert_eq!(facts.history, expected);
    }

    /// Every declared git member is read, each from its own reader.
    ///
    /// Fails by: dropping any member from the returned facts, or inverting
    /// any member's declaration test.
    #[test]
    fn every_declared_git_member_is_read() {
        let dir = seeded("rules-git-every-member");
        let refs = vec![String::from("HEAD")];
        let row = Rule {
            git: vec![
                GitRead::Head,
                GitRead::Status,
                GitRead::Remote,
                GitRead::Worktrees,
            ],
            refs: refs.clone(),
            ranges: refs.clone(),
            commits: refs.clone(),
            staged: vec![String::from("a.txt")],
            history: vec![crate::facts::HistoryQuery {
                id: String::from("h"),
                tags: Some(String::from("*")),
                path: None,
                filter: None,
            }],
            landing: refs.clone(),
            delta_sources: vec![String::from("*.txt")],
            base: Some(String::from("HEAD")),
            tags: vec![String::from("*")],
            git_config: vec![String::from("user.name")],
            index: vec![String::from("a.txt")],
            ..blank("p", RuleKind::Policy)
        };
        let facts = git_facts(std::slice::from_ref(&row), &dir);
        assert_eq!(facts.head, crate::git::head_fact(&dir).ok());
        assert_eq!(facts.status, crate::git::status_fact(&dir).ok());
        assert_eq!(facts.remote, crate::git::remote_fact(&dir).ok());
        assert_eq!(facts.worktrees, crate::git::worktree_fact(&dir).ok());
        assert_eq!(facts.refs, crate::git::ref_facts(&dir, &refs).ok());
        assert_eq!(facts.ranges, crate::git::range_facts(&dir, &refs).ok());
        assert_eq!(facts.metadata, crate::git::metadata_facts(&dir, &refs).ok());
        assert_eq!(
            facts.staged,
            crate::git::staged_facts(&dir, &row.staged).ok()
        );
        assert_eq!(
            facts.history,
            crate::git::history_facts(&dir, &row.history).ok()
        );
        assert_eq!(facts.landing, crate::git::landing_facts(&dir, &refs).ok());
        assert_eq!(
            facts.base_delta,
            crate::git::base_delta(&dir, "HEAD", &row.delta_sources, true)
                .ok()
                .flatten()
        );
        assert_eq!(facts.tags, crate::git::tag_facts(&dir, &row.tags).ok());
        assert_eq!(
            facts.config,
            crate::git::config_facts(&dir, &row.git_config).ok()
        );
        assert_eq!(facts.index, crate::git::index_facts(&dir, &row.index).ok());
        let missing: Vec<&str> = [
            ("head", facts.head.is_some()),
            ("status", facts.status.is_some()),
            ("remote", facts.remote.is_some()),
            ("worktrees", facts.worktrees.is_some()),
            ("refs", facts.refs.is_some()),
            ("ranges", facts.ranges.is_some()),
            ("metadata", facts.metadata.is_some()),
            ("staged", facts.staged.is_some()),
            ("history", facts.history.is_some()),
            ("landing", facts.landing.is_some()),
            ("base_delta", facts.base_delta.is_some()),
            ("tags", facts.tags.is_some()),
            ("config", facts.config.is_some()),
            ("index", facts.index.is_some()),
        ]
        .into_iter()
        .filter(|(_, present)| !present)
        .map(|(member, _)| member)
        .collect();
        assert_eq!(missing, Vec::<&str>::new(), "declared and readable here");
        assert_eq!(
            git_facts(&[blank("p", RuleKind::Policy)], &dir),
            crate::git::GitFacts::default()
        );
    }

    fn checks(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// A declared forge token is resolved as a ref and answered from the
    /// record written for its commit; an undeclared family reads nothing.
    ///
    /// Fails by: any placeholder map, or answering for a family nobody
    /// declared.
    #[test]
    fn a_forge_verdict_is_read_for_its_declared_ref() {
        let dir = seeded("rules-forge-facts");
        let git_dir = crate::git::git_dir(&dir).expect("a git dir");
        let head =
            crate::git::ref_facts(&dir, &[String::from("HEAD")]).expect("HEAD resolves")["HEAD"]
                .clone();
        let record = crate::forge::record_path(&git_dir, &head);
        fs::create_dir_all(record.parent().expect("a directory")).expect("mkdir");
        fs::write(&record, "ci success\n").expect("write record");
        let row = Rule {
            forge: vec![String::from("HEAD")],
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            forge_facts(&[row], &dir),
            Some(BTreeMap::from([(
                String::from("HEAD"),
                checks(&[("ci", "success")])
            )]))
        );
        assert_eq!(forge_facts(&[blank("p", RuleKind::Policy)], &dir), None);
    }

    /// A declared tool row is answered from the record keyed on its input's
    /// digest.
    ///
    /// Fails by: any placeholder map, or answering for a family nobody
    /// declared.
    #[test]
    fn a_tool_verdict_is_read_for_its_declared_row() {
        let dir = seeded("rules-tool-facts");
        let git_dir = crate::git::git_dir(&dir).expect("a git dir");
        let query = tool_query("probe", "validator", "1.0", "a.txt");
        let key = crate::tools::record_key(&query, &crate::tools::digest(b"a\n"));
        let record = crate::tools::record_path(&git_dir, &key);
        fs::create_dir_all(record.parent().expect("a directory")).expect("mkdir");
        fs::write(&record, "lint pass\n").expect("write record");
        let row = Rule {
            tools: vec![query],
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            tool_facts(&[row], &dir),
            Some(BTreeMap::from([(
                String::from("probe"),
                checks(&[("lint", "pass")])
            )]))
        );
        assert_eq!(tool_facts(&[blank("p", RuleKind::Policy)], &dir), None);
    }

    /// A declared minted row is answered from its mint's receipts at the
    /// instant supplied.
    ///
    /// Fails by: any placeholder map, or answering for a family nobody
    /// declared.
    #[test]
    fn a_minted_field_is_read_for_its_declared_row() {
        let dir = seeded("rules-minted-facts");
        let git_dir = crate::git::git_dir(&dir).expect("a git dir");
        let store = crate::minted::store_path(&git_dir);
        fs::create_dir_all(&store).expect("mkdir");
        fs::write(store.join("issue-read.CLOUD-1"), "1000 Todo\n").expect("write receipt");
        let row = Rule {
            minted: vec![minted_query("status", "issue-read", 1, 0, 1)],
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            minted_facts(&[row], &dir, Some(1000)),
            Some(BTreeMap::from([(
                String::from("status"),
                checks(&[("CLOUD-1", "Todo")])
            )]))
        );
        assert_eq!(
            minted_facts(&[blank("p", RuleKind::Policy)], &dir, Some(1000)),
            None
        );
    }

    /// A row declaring nothing declares no fact through any census column.
    ///
    /// Fails by: a census closure answering a row with an empty column as
    /// declaring it (the `tasks` and `extract` negations dropped).
    #[test]
    fn an_empty_row_declares_no_census_fact() {
        let row = blank("p", RuleKind::Policy);
        let declaring: Vec<&str> = COLUMN_CENSUS
            .iter()
            .filter(|column| match column.declares {
                Declares::Fact(_, declared) => declared(&row),
                Declares::NotFactBearing(_) => false,
            })
            .map(|column| column.field)
            .collect();
        assert_eq!(declaring, Vec::<&str>::new());
    }

    /// `base` acquires the base fact on a `policy` row alone: on a ratchet it
    /// names the rev a count is read since, and acquires nothing.
    ///
    /// Fails by: the kind test negated (`==` for `!=`), so a ratchet's `base`
    /// declares the fact and a policy row's does not (CLOUD-2789).
    #[test]
    fn only_a_policy_rows_base_declares_the_base_fact() {
        let declares_base = |kind| {
            Rule {
                base: Some(String::from("origin/main")),
                ..blank("p", kind)
            }
            .census_facts()
            .any(|fact| fact == crate::facts::Fact::Base)
        };
        assert!(declares_base(RuleKind::Policy));
        assert!(!declares_base(RuleKind::Ratchet));
    }

    /// A pipeline row carrying `verdict` without `filters` is half a family and
    /// is refused; carrying both is whole.
    ///
    /// Fails by: the discard family read as either column rather than both.
    #[test]
    fn half_a_discard_family_is_refused() {
        let row = |filters: Option<Vec<String>>| Rule {
            verdict: Some(vec![VerdictProgram {
                subcommands: Some(words(&["pr"])),
                ..verdict_program("gh")
            }]),
            filters,
            ..blank("p", RuleKind::Pipeline)
        };
        let half = refusal(row(None).validate_pipeline_tables());
        assert!(half.contains("needs either"), "{half}");
        assert_eq!(
            refusal(row(Some(vec![String::from("jq")])).validate_pipeline_tables()),
            ""
        );
    }

    /// A declared effect fact the run could not resolve withholds its rule on
    /// the hook surface only, and only for the rule that declared it.
    ///
    /// Fails by: answering `None` always, the surface test inverted, or either
    /// declaration test negated or disjoined.
    #[test]
    fn an_unresolved_effect_fact_withholds_only_its_declaring_rule_on_the_hook() {
        let files: Vec<String> = Vec::new();
        let blind = BareFacts {
            symbols: crate::facts::Look::CouldNotLook,
            ..BareFacts::new()
        };
        let could_not_look = crate::facts::Look::CouldNotLook;
        let inputs = RunInputs {
            half: None,
            review: &could_not_look,
            ..blind.inputs(&files)
        };
        let review: crate::facts::ReviewQuery = serde_json::from_value(serde_json::json!({
            "id": "r", "prompt": "p", "runner": "x", "version": "1", "subject": "document"
        }))
        .expect("a review row");
        let symbols = Rule {
            symbols: true,
            ..blank("s", RuleKind::Policy)
        };
        let reviewing = Rule {
            review: vec![review],
            ..blank("r", RuleKind::Policy)
        };
        let neither = blank("n", RuleKind::Policy);
        let hook = crate::facts::Surface::Hook;
        assert_eq!(
            unresolved_declared_fact(&symbols, &inputs, hook),
            Some("symbols")
        );
        assert_eq!(
            unresolved_declared_fact(&reviewing, &inputs, hook),
            Some("review")
        );
        assert_eq!(unresolved_declared_fact(&neither, &inputs, hook), None);
        assert_eq!(
            unresolved_declared_fact(&symbols, &inputs, crate::facts::Surface::Check),
            None
        );
        let sighted = BareFacts::new();
        let resolved = sighted.inputs(&files);
        assert_eq!(unresolved_declared_fact(&symbols, &resolved, hook), None);
        assert_eq!(unresolved_declared_fact(&reviewing, &resolved, hook), None);
    }

    /// The first manifest a preset ships, and a module header copied from it at
    /// `version`.
    fn ejected_header(version: &str) -> String {
        let manifest = &crate::preset_catalog::MANIFESTS[0];
        format!(
            "# batten-ejected: {}/m version {version}\npackage batten.x\n",
            manifest.name
        )
    }

    /// A module copied at an older preset version warns, through `module` or
    /// through a bundle directory's `.rego` files; a current copy does not.
    ///
    /// Fails by: emitting nothing, or the version comparison inverted.
    #[test]
    fn a_copy_behind_its_preset_warns() {
        let shipped = crate::preset_catalog::MANIFESTS[0].version.to_string();
        assert!(
            crate::preset_catalog::MANIFESTS[0].version > semver::Version::new(0, 0, 0),
            "a stale copy needs a version below the shipped one"
        );
        let dir = temp_dir("rules-ejected-behind");
        write(&dir, "old.rego", &ejected_header("0.0.0"));
        write(&dir, "current.rego", &ejected_header(&shipped));
        write(&dir, "pol/old.rego", &ejected_header("0.0.0"));
        write(&dir, "pol/notes.txt", &ejected_header("0.0.0"));
        let warned = |rule: Rule| {
            let mut findings = Vec::new();
            ejected_behind(&rule, &dir, &[], &mut findings);
            findings
                .into_iter()
                .map(|finding| (finding.rule, finding.path))
                .collect::<Vec<_>>()
        };
        let module = |path: &str| Rule {
            module: Some(path.to_owned()),
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            warned(module("old.rego")),
            [(MODULE_PIN_STALE.to_owned(), String::from("old.rego"))]
        );
        assert_eq!(
            warned(module("current.rego")),
            Vec::<(String, String)>::new()
        );
        let bundle = Rule {
            bundle: Some(String::from("pol")),
            ..blank("p", RuleKind::Policy)
        };
        assert_eq!(
            warned(bundle),
            [(MODULE_PIN_STALE.to_owned(), String::from("pol/old.rego"))]
        );
    }

    /// A copy a major version behind is refused; a minor or patch behind is
    /// advice (CLOUD-2822).
    ///
    /// Fails by: the major comparison inverted, or reading minor as major.
    #[test]
    fn a_copy_a_major_behind_is_refused_and_a_minor_behind_advises() {
        let at = |major, minor, patch| semver::Version::new(major, minor, patch);
        assert_eq!(
            stale_severity(&at(1, 4, 0), &at(2, 0, 0)),
            RuleSeverity::Deny
        );
        assert_eq!(
            stale_severity(&at(2, 0, 0), &at(2, 1, 0)),
            RuleSeverity::Advise
        );
        assert_eq!(
            stale_severity(&at(2, 1, 0), &at(2, 1, 3)),
            RuleSeverity::Advise
        );
        assert_eq!(
            stale_severity(&at(0, 0, 1), &at(0, 0, 2)),
            RuleSeverity::Advise
        );
    }

    /// Only a policy row is checked for a stale copy, and only off the hook.
    ///
    /// Fails by: the kind test inverted, the conjunction disjoined, or the
    /// surface test inverted.
    #[test]
    fn only_a_policy_row_off_the_hook_is_checked_for_a_stale_copy() {
        let dir = temp_dir("rules-evaluate-ejected");
        write(&dir, "old.rego", &ejected_header("0.0.0"));
        // Held back by an unmet requirement, so only the stale-copy check runs.
        let held = |id: &str, kind| Rule {
            module: Some(String::from("old.rego")),
            requires_path: vec![String::from("absent")],
            ..blank(id, kind)
        };
        let rows = [
            held("p", RuleKind::Policy),
            Rule {
                glob: Some(String::from("*.rs")),
                pattern: Some(String::from("x")),
                ..held("f", RuleKind::Forbid)
            },
        ];
        let files: Vec<String> = Vec::new();
        let facts = BareFacts::new();
        let owners = |surface| {
            let inputs = RunInputs {
                half: None,
                surface,
                ..facts.inputs(&files)
            };
            let mut scan = Scan::default();
            evaluate_rules(&rows, &dir, &inputs, &mut scan).expect("evaluates");
            scan.findings
                .into_iter()
                .map(|finding| finding.owner)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            owners(crate::facts::Surface::Check),
            [Some(String::from("p"))]
        );
        assert_eq!(
            owners(crate::facts::Surface::Hook),
            Vec::<Option<String>>::new()
        );
    }

    /// A sink is requested per evaluated producing row, over the findings it
    /// owns: a digest and count for a journal, a count alone for a marker.
    ///
    /// Fails by: requesting nothing, requesting for a withheld row, counting
    /// another row's findings, a count that does not add, or the marker test
    /// inverted.
    #[test]
    fn a_sink_is_requested_over_the_findings_its_row_owns() {
        let dir = temp_dir("rules-requested-sinks");
        write(&dir, "a.rs", "TODO\nTODO\n");
        write(&dir, "c.rs", "TODO\n");
        let producing = |id: &str, glob: &str, kind| Rule {
            produces: Some(Sink {
                kind,
                key: SinkKey::Rule,
            }),
            ..forbid(id, glob, "TODO")
        };
        let rules = [
            producing("a", "a.rs", crate::facts::Production::Journal),
            Rule {
                requires_path: vec![String::from("absent")],
                ..producing("b", "a.rs", crate::facts::Production::Journal)
            },
            producing("c", "c.rs", crate::facts::Production::Marker),
            forbid("d", "c.rs", "TODO"),
        ];
        let scan =
            super::run_static(&rules, &[], crate::policy::Vocabulary::EMPTY, &dir).expect("runs");
        let subject: String = scan
            .findings
            .iter()
            .filter(|finding| finding.rule == "a")
            .map(|finding| finding.identity.fingerprint.to_hex() + "\n")
            .collect();
        assert_eq!(
            scan.requested,
            [
                crate::sink::Requested {
                    rule: String::from("a"),
                    key: SinkKey::Rule,
                    kind: crate::facts::Production::Journal,
                    digest: crate::digest::sha256_hex(subject.as_bytes()),
                    count: 2,
                },
                crate::sink::Requested {
                    rule: String::from("c"),
                    key: SinkKey::Rule,
                    kind: crate::facts::Production::Marker,
                    digest: String::new(),
                    count: 1,
                },
            ]
        );
    }

    /// The recorder's could-not-look lines are read last-write-wins, and a
    /// line missing either half is skipped.
    ///
    /// Fails by: any placeholder map, or either half's emptiness test negated
    /// or disjoined.
    #[test]
    fn a_blocked_recorder_line_needs_both_halves() {
        let git_dir = temp_dir("rules-recorder-blocked");
        let path = crate::recorder::blocked_path(&git_dir, "feature/x", None);
        fs::create_dir_all(path.parent().expect("a directory")).expect("mkdir");
        fs::write(&path, "one first\nhalf \n alone\nbare\none second\n").expect("write");
        assert_eq!(
            crate::recorder::recorder_blocked(&git_dir, "feature/x"),
            BTreeMap::from([(String::from("one"), String::from("second"))])
        );
    }

    /// A claimed branch's records are read under its claim, except the claim
    /// receipt itself, which is never partitioned by its own token.
    ///
    /// Fails by: any placeholder map, or the claim exception inverted.
    #[test]
    fn the_claim_record_is_read_unpartitioned_and_the_rest_under_the_claim() {
        let git_dir = temp_dir("rules-recorder-records");
        let receipts = git_dir.join("batten-receipts");
        fs::create_dir_all(&receipts).expect("mkdir");
        fs::write(receipts.join("claim.b"), "CLOUD-1\n").expect("claim");
        fs::write(receipts.join("plan.b.CLOUD-1"), "x\ny\n").expect("partitioned");
        fs::write(receipts.join("plan.b"), "stale\n").expect("unpartitioned");
        fs::write(receipts.join("claim.b.CLOUD-1"), "wrong\n").expect("decoy");
        assert_eq!(
            crate::recorder::recorder_records(
                &git_dir,
                "b",
                &[],
                &[],
                &["claim", "plan", "absent"]
            ),
            BTreeMap::from([
                (String::from("claim"), vec![String::from("CLOUD-1")]),
                (
                    String::from("plan"),
                    vec![String::from("x"), String::from("y")]
                ),
            ])
        );
    }

    /// One path's projection answers only from the entry acquired as the form
    /// asked for, and carries a could-not-look cause through.
    ///
    /// Fails by: a constant answer, any guard forced or inverted, or the
    /// could-not-look arm dropped.
    #[test]
    fn a_projection_answers_only_from_its_own_form() {
        let dir = temp_dir("rules-project-declared");
        write(&dir, "d.json", "{\"a\": 1}");
        let parsed = || acquire(&dir, "d.json", want_for("d.json", Wanted::Document));
        assert!(matches!(parsed(), Acquired::Parsed(_)));
        let key = |path: &str, wanted| (path.to_owned(), wanted);
        let cache: BTreeMap<(String, Wanted), Acquired> = BTreeMap::from([
            (key("d.json", Wanted::Document), parsed()),
            (
                key("l.txt", Wanted::Lines),
                Acquired::Lines(vec![String::from("x")]),
            ),
            (
                key("i.rs", Wanted::Invocations),
                Acquired::Invocations(Vec::new()),
            ),
            (
                key("u.json", Wanted::Document),
                Acquired::No(NotAcquired::Unreadable),
            ),
            (key("m", Wanted::Lines), parsed()),
            (
                key("m", Wanted::Document),
                Acquired::Lines(vec![String::from("y")]),
            ),
            (key("m", Wanted::Uses), Acquired::Invocations(Vec::new())),
            (key("n.rs", Wanted::Units), Acquired::Units(Vec::new())),
            (key("n.rs", Wanted::Lines), Acquired::Units(Vec::new())),
        ]);
        assert_eq!(
            project_declared(&cache, "n.rs", Wanted::Units),
            Ok(serde_json::json!({"nodes": []}))
        );
        assert_eq!(
            project_declared(&cache, "n.rs", Wanted::Lines),
            Err(NotAcquired::Absent),
            "units held under another projection are not its answer"
        );
        let document = project_declared(&cache, "d.json", Wanted::Document).expect("parsed");
        assert_eq!(document["a"], serde_json::json!(1), "{document}");
        assert_eq!(
            project_declared(&cache, "l.txt", Wanted::Lines),
            Ok(serde_json::json!(["x"]))
        );
        assert_eq!(
            project_declared(&cache, "i.rs", Wanted::Invocations),
            Ok(serde_json::json!([]))
        );
        assert_eq!(
            project_declared(&cache, "u.json", Wanted::Document),
            Err(NotAcquired::Unreadable)
        );
        for wanted in [Wanted::Lines, Wanted::Document, Wanted::Uses] {
            assert_eq!(
                project_declared(&cache, "m", wanted),
                Err(NotAcquired::Absent),
                "{wanted:?}"
            );
        }
    }

    /// Only a tree-scoped policy row's external rows are acquired.
    ///
    /// Fails by: the kind-and-scope conjunction disjoined.
    #[test]
    fn only_a_tree_policy_rows_external_rows_are_acquired() {
        let external = vec![crate::facts::Rooted {
            id: String::from("e"),
            root: String::from("BATTEN_RULES_TEST_ROOT_NEVER_SET"),
            path: String::from("x.json"),
        }];
        let row = |kind, scope| Rule {
            scope,
            external: external.clone(),
            ..blank("r", kind)
        };
        let acquired = |rule: Rule| {
            external_facts(&[rule], usize::MAX)
                .into_iter()
                .map(|(id, outcome)| (id, matches!(outcome, Acquired::No(NotAcquired::RootUnset))))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            acquired(row(RuleKind::Policy, RuleScope::Tree)),
            [(String::from("e"), true)]
        );
        let nothing: Vec<(String, bool)> = Vec::new();
        assert_eq!(
            acquired(row(RuleKind::Policy, RuleScope::MediatedCall)),
            nothing
        );
        assert_eq!(acquired(row(RuleKind::Forbid, RuleScope::Tree)), nothing);
    }

    /// An external file is projected when parsed and named missing, with its
    /// cause, otherwise.
    ///
    /// Fails by: projecting nothing.
    #[test]
    fn an_external_file_is_projected_or_named_missing() {
        let dir = temp_dir("rules-project-external");
        write(&dir, "x.json", "{\"k\": 2}");
        let rooted = |id: &str| crate::facts::Rooted {
            id: id.to_owned(),
            root: String::from("R"),
            path: String::from("x.json"),
        };
        let external = BTreeMap::from([
            (
                String::from("p"),
                acquire(&dir, "x.json", want_for("x.json", Wanted::Document)),
            ),
            (String::from("n"), Acquired::No(NotAcquired::RootUnset)),
            (String::from("l"), Acquired::Lines(Vec::new())),
        ]);
        let mut out = serde_json::Map::new();
        let (mut missing, mut causes) = (Vec::new(), Vec::new());
        project_external(
            &external,
            &[rooted("p"), rooted("n"), rooted("l"), rooted("gone")],
            &mut out,
            &mut missing,
            &mut causes,
        );
        assert_eq!(
            out.get("p").map(|node| node["k"].clone()),
            Some(serde_json::json!(2))
        );
        assert_eq!(missing, ["n", "l", "gone"]);
        assert_eq!(
            causes,
            [
                (String::from("n"), NotAcquired::RootUnset),
                (String::from("l"), NotAcquired::Absent),
                (String::from("gone"), NotAcquired::Absent),
            ]
        );
    }

    /// A declared plan nobody could take is present with no value, and an
    /// undeclared family reads nothing.
    ///
    /// Fails by: any placeholder map.
    #[test]
    fn a_declared_plan_that_could_not_be_taken_is_present_and_empty() {
        let dir = temp_dir("rules-plan-facts");
        let row = Rule {
            plan: vec![crate::config_model::PlanQuery {
                id: String::from("q"),
                hook: String::from("no-such-hook"),
                required: Vec::new(),
                prohibited_profiles: Vec::new(),
                profile: Vec::new(),
            }],
            ..blank("p", RuleKind::Policy)
        };
        let taken = plan_facts(&[row], &dir).map(|plans| {
            plans
                .into_iter()
                .map(|(id, plan)| (id, plan.is_some()))
                .collect::<Vec<_>>()
        });
        assert_eq!(taken, Some(vec![(String::from("q"), false)]));
        assert!(plan_facts(&[blank("p", RuleKind::Policy)], &dir).is_none());
    }

    /// A plan the runner DID take is kept under its id, whatever the runner
    /// answered for the others.
    ///
    /// Fails by: the `Look::Is` arm dropped, which reads every taken plan as
    /// one nobody could take.
    #[test]
    fn a_declared_plan_the_runner_took_is_kept() {
        let dir = temp_dir("rules-plan-taken");
        let query = |id: &str| crate::config_model::PlanQuery {
            id: String::from(id),
            hook: String::from(id),
            required: Vec::new(),
            prohibited_profiles: Vec::new(),
            profile: Vec::new(),
        };
        let row = Rule {
            plan: vec![query("taken"), query("refused")],
            ..blank("p", RuleKind::Policy)
        };
        let planned = |hook: &str| crate::hk::Planned {
            hook: String::from(hook),
            run_type: String::from("check"),
            profiles: Vec::new(),
            invocation: Vec::new(),
            tool_version: String::from("1"),
            contract_digest: None,
            input_fingerprint: String::new(),
            required: Vec::new(),
            prohibited_profiles: Vec::new(),
            steps: Vec::new(),
        };
        let taken = plan_facts_from(&[row], &dir, |_, query| {
            if query.id == "taken" {
                crate::facts::Look::Is(planned(&query.hook))
            } else {
                crate::facts::Look::IsNot
            }
        });
        let mut expected = BTreeMap::new();
        expected.insert(String::from("refused"), None);
        expected.insert(String::from("taken"), Some(planned("taken")));
        assert_eq!(taken, Some(expected));
    }

    /// A declared capture reduction is answered by the capture store's own
    /// reducer, and an undeclared family reads nothing.
    ///
    /// Fails by: any placeholder map.
    #[test]
    fn a_declared_capture_reduction_is_the_reducers_answer() {
        let dir = temp_dir("rules-captured-facts");
        let declared = vec![crate::facts::CaptureQuery {
            id: String::from("c"),
            key: String::from("BATTEN-RULES-NO-SUCH-KEY"),
            key_at: None,
            node: String::from("status"),
            reduce: crate::facts::Reduction::Present,
        }];
        let row = Rule {
            captured: declared.clone(),
            ..blank("p", RuleKind::Policy)
        };
        let answer = captured_facts(&[row], &dir);
        assert!(answer.is_some(), "the store is addressable here");
        assert_eq!(answer, crate::captured::reduce(&dir, &declared));
        assert_eq!(captured_facts(&[blank("p", RuleKind::Policy)], &dir), None);
    }

    /// A rule set declaring no symbols spends nothing and answers "not asked".
    ///
    /// Fails by: the declaration test negated, which resolves the census for
    /// a run that asked for none.
    #[test]
    fn an_undeclared_symbol_census_is_not_taken() {
        let dir = temp_dir("rules-symbols-undeclared");
        assert!(matches!(
            symbols_fact(&[blank("p", RuleKind::Policy)], &dir),
            crate::facts::Look::IsNot
        ));
    }

    /// The review and symbol facts project their records field by field, and
    /// `null` when nothing resolved.
    ///
    /// Fails by: projecting a default value.
    #[test]
    fn the_review_and_symbol_facts_project_their_records() {
        let record = crate::review::Record {
            provenance: crate::review::Provenance {
                tool: String::from("agent"),
                version: String::from("1"),
                invocation: vec![String::from("--x")],
                prompt: String::from("d1"),
            },
            subject: crate::review::Subject {
                kind: String::from("document"),
                digest: String::from("d2"),
            },
            findings: vec![crate::review::Finding {
                path: String::from("a.md"),
                line: 3,
                clause: String::from("§7"),
            }],
        };
        let review = crate::facts::Look::Is(BTreeMap::from([(String::from("r"), record)]));
        assert_eq!(
            review_value(&review),
            serde_json::json!({"r": {
                "provenance": {"tool": "agent", "version": "1", "invocation": ["--x"], "prompt": "d1"},
                "subject": {"kind": "document", "digest": "d2"},
                "findings": [{"path": "a.md", "line": 3, "clause": "§7"}],
            }})
        );
        assert_eq!(
            review_value(&crate::facts::Look::IsNot),
            serde_json::Value::Null
        );
        let resolved = crate::symbols::Resolved {
            provenance: crate::symbols::Provenance {
                tool: String::from("lint"),
                version: String::from("2"),
                invocation: vec![String::from("--y")],
            },
            sites: vec![crate::symbols::Site {
                path: String::from("a.rs"),
                line: 4,
                lint: String::from("clippy::x"),
            }],
        };
        assert_eq!(
            symbols_value(&crate::facts::Look::Is(resolved)),
            serde_json::json!({
                "provenance": {"tool": "lint", "version": "2", "invocation": ["--y"]},
                "sites": [{"path": "a.rs", "line": 4, "lint": "clippy::x"}],
            })
        );
        assert_eq!(
            symbols_value(&crate::facts::Look::CouldNotLook),
            serde_json::Value::Null
        );
    }

    fn line_subject(path: &str, line: u64) -> crate::verdict::Subject {
        crate::verdict::Subject::Line {
            path: path.to_owned(),
            line,
        }
    }

    /// A finding's pointer is the first path-bearing subject, else the first
    /// subject rendered, else nothing.
    ///
    /// Fails by: any constant pointer, or the pointer index answering for an
    /// empty list or skipping a leading count.
    #[test]
    fn a_policy_findings_pointer_prefers_a_path() {
        let count = crate::verdict::Subject::Count { count: 2 };
        let path = crate::verdict::Subject::Path {
            path: String::from("b.rs"),
        };
        assert_eq!(
            first_pointer(&[count.clone(), line_subject("a.rs", 4)]),
            (Some(String::from("a.rs")), Some(4))
        );
        assert_eq!(
            first_pointer(&[crate::verdict::artifact("t"), path.clone()]),
            (Some(String::from("b.rs")), None)
        );
        assert_eq!(
            first_pointer(std::slice::from_ref(&count)),
            (Some(String::from("2")), None)
        );
        assert_eq!(first_pointer(&[]), (None, None));
        assert_eq!(pointer_index(&[count.clone(), path]), Some(1));
        assert_eq!(pointer_index(&[count]), Some(0));
        assert_eq!(pointer_index(&[]), None);
    }

    /// A policy finding's fingerprint ingredient is its class, then its
    /// pointers.
    ///
    /// Fails by: a constant ingredient.
    #[test]
    fn a_policy_fingerprint_is_the_class_then_its_pointers() {
        let violation = |subjects| crate::policy::Violation {
            rule: None,
            verdict: String::from("some class"),
            subjects,
            counted: false,
        };
        assert_eq!(fingerprint_of(&violation(Vec::new())), "some class");
        assert_eq!(
            fingerprint_of(&violation(vec![
                line_subject("a.rs", 1),
                crate::verdict::Subject::Count { count: 2 }
            ])),
            "some class a.rs:1 2"
        );
    }

    /// A raised class's remedy comes from the registry, and an unknown class
    /// has none.
    ///
    /// Fails by: answering no remedy for a declared class.
    #[test]
    fn a_policy_remedy_comes_from_the_registry() {
        let registry = crate::policy::registry_for(&[]).expect("the vendored registry");
        assert!(policy_remediation(&registry, MODULE_PIN_STALE).is_some());
        assert!(policy_remediation(&registry, "no such class anywhere").is_none());
    }

    /// One bundle compiled from one module, under `id`.
    fn compiled(id: &str, source: &str) -> crate::policy::Bundle {
        crate::policy::compile(
            id,
            &[(String::from("probe.rego"), source.to_owned())],
            &crate::pattern::data_document(&[]),
        )
        .expect("the probe module compiles")
    }

    const FIRING: &str = r#"package batten.probe

import rego.v1

rules contains "probe-fires"

violation contains {
	"rule": "probe-fires",
	"verdict": "module pin stale",
	"subjects": [{"path": "a.txt", "line": 3}],
} if {
	true
}
"#;

    const SILENT: &str = r#"package batten.probe

import rego.v1

rules contains "probe-silent"

violation contains {
	"rule": "probe-silent",
	"verdict": "module pin stale",
	"subjects": [{"path": "a.txt"}],
} if {
	input.never == true
}
"#;

    /// A policy row evaluates its own bundle, is skipped when a declared
    /// selector selects nothing, and evaluates when anything resolved.
    ///
    /// Fails by: any arm of the selection census negated, conjoined or
    /// disjoined, the bundle lookup inverted, the abstention test negated or
    /// disjoined, or the `allow` test inverted.
    #[test]
    fn a_policy_row_is_skipped_only_when_its_declared_selectors_select_nothing() {
        let files = vec![String::from("a.txt")];
        let firing = compiled("p", FIRING);
        let silent = compiled("p", SILENT);
        let run =
            |rule: Rule, bundle: Option<&crate::policy::Bundle>, git: crate::git::GitFacts| {
                let facts = BareFacts {
                    git,
                    ..BareFacts::new()
                };
                let inputs = RunInputs {
                    half: None,
                    bundles: bundle.map_or(&[][..], std::slice::from_ref),
                    ..facts.inputs(&files)
                };
                let (mut findings, mut classes) = (Vec::new(), BTreeMap::new());
                let skipped = matches!(
                    policy_rule(&rule, &inputs, &mut findings, &mut classes)
                        .expect("no row here faults"),
                    Some(NotObserved::RuleSkipped)
                );
                let pointers: Vec<(String, Option<usize>, Option<String>)> = findings
                    .into_iter()
                    .map(|finding| (finding.path, finding.line, finding.owner))
                    .collect();
                (skipped, pointers)
            };
        let fired = vec![(String::from("a.txt"), Some(3), Some(String::from("p")))];
        let row = || blank("p", RuleKind::Policy);
        let none = crate::git::GitFacts::default;
        assert_eq!(run(row(), None, none()), (true, Vec::new()), "no bundle");
        assert_eq!(run(row(), Some(&firing), none()), (false, fired.clone()));
        assert_eq!(run(row(), Some(&silent), none()), (false, Vec::new()));
        let selecting_nothing = || Rule {
            sources: vec![String::from("*.none")],
            ..row()
        };
        assert_eq!(
            run(selecting_nothing(), Some(&firing), none()),
            (true, Vec::new())
        );
        // Each selector column alone counts as a declaration.
        let selecting_nothing_by = [
            Rule {
                line_sources: vec![String::from("*.none")],
                ..row()
            },
            Rule {
                invocation_sources: vec![String::from("*.none")],
                ..row()
            },
            Rule {
                use_sources: vec![String::from("*.none")],
                ..row()
            },
        ];
        for rule in selecting_nothing_by {
            assert_eq!(run(rule, Some(&firing), none()), (true, Vec::new()));
        }
        let delta = crate::git::GitFacts {
            base_delta: Some(crate::git::BaseDelta::default()),
            ..crate::git::GitFacts::default()
        };
        assert_eq!(
            run(selecting_nothing(), Some(&firing), delta),
            (true, Vec::new()),
            "a delta nobody declared resolves nothing"
        );
        let undelivered_delta = Rule {
            delta_sources: vec![String::from("*.sh")],
            ..row()
        };
        assert_eq!(
            run(undelivered_delta, Some(&firing), none()),
            (true, Vec::new())
        );
        let literal = Rule {
            documents: vec![String::from("x.json")],
            ..selecting_nothing()
        };
        assert_eq!(
            run(literal, Some(&firing), none()),
            (false, fired),
            "a literal document is a selection, and a speaking module is heard over its absence"
        );
    }

    /// A policy row sees this branch's recorder records and its blocked lines.
    ///
    /// Fails by: dropping either read of the record store.
    #[test]
    fn a_policy_row_sees_this_branchs_records_and_blocked_lines() {
        let dir = seeded("rules-run-records");
        let git_dir = crate::git::git_dir(&dir).expect("a git dir");
        let branch = crate::git::record_key(&dir).expect("a record key");
        let record = crate::recorder::record_path(&git_dir, "plan", &branch, None);
        fs::create_dir_all(record.parent().expect("a directory")).expect("mkdir");
        fs::write(&record, "planned\n").expect("record");
        fs::write(
            crate::recorder::blocked_path(&git_dir, &branch, None),
            "recorder why\n",
        )
        .expect("blocked");
        write(
            &dir,
            "probe.rego",
            r#"package batten.probe

import rego.v1

rules contains "records-seen"

rules contains "blocked-seen"

violation contains {
	"rule": "records-seen",
	"verdict": "module pin stale",
	"subjects": [{"artifact": "r"}],
} if {
	count(input.tree.records) > 0
}

violation contains {
	"rule": "blocked-seen",
	"verdict": "module pin stale",
	"subjects": [{"artifact": "b"}],
} if {
	count(input.tree["records-blocked"]) > 0
}
"#,
        );
        let row = Rule {
            module: Some(String::from("probe.rego")),
            scope: RuleScope::Tree,
            ..blank("p", RuleKind::Policy)
        };
        let tree = Scope::Tree;
        let scan = run_static_over(
            &[row],
            &[],
            crate::policy::Vocabulary::EMPTY,
            &dir,
            RunOptions {
                half: None,
                keyed_bases: &[],
                checks: crate::policy::ModuleChecks::SkipOnHotPath,
                ..tree_options(&tree)
            },
        )
        .expect("runs");
        let fired: BTreeSet<&str> = scan.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(
            fired,
            BTreeSet::from(["blocked-seen", "records-seen"]),
            "{:?}",
            scan.not_evaluated
        );
    }

    /// A repository whose one commit carries `base`, its working tree then
    /// rewritten to `head` (an empty text deletes the file).
    fn ratchet_repo(name: &str, base: &[(&str, &str)], head: &[(&str, &str)]) -> PathBuf {
        let dir = temp_dir(name);
        for (rel, text) in base {
            write(&dir, rel, text);
        }
        let paths: Vec<String> = base.iter().map(|(rel, _)| (*rel).to_owned()).collect();
        crate::gitwrite::commit_paths(&dir, &paths, "base").expect("commit the base");
        for (rel, text) in head {
            if text.is_empty() {
                fs::remove_file(dir.join(rel)).expect("delete");
            } else {
                write(&dir, rel, text);
            }
        }
        dir
    }

    /// Two rows count the same only when their counters match: pattern,
    /// regex and what is counted all key the persisted tables.
    ///
    /// Fails by: a constant key, which shares one row's counts with another's.
    #[test]
    fn rows_share_counts_only_when_their_counters_match() {
        let row = |pattern: Option<&str>, regex: Option<&str>| Rule {
            pattern: pattern.map(String::from),
            regex: regex.map(String::from),
            ..ratchet_row(Direction::NonIncreasing)
        };
        let base = counter_key(&row(Some("x"), None));
        assert_eq!(base, counter_key(&row(Some("x"), None)));
        assert_ne!(base, counter_key(&row(Some("y"), None)));
        assert_ne!(base, counter_key(&row(None, Some("x"))));
    }

    /// A write moves only the rows judged at the call whose glob holds the
    /// target: a row `check` alone judges, or one over other paths, is not
    /// read.
    ///
    /// Fails by: a row admitted when either condition holds rather than both.
    #[test]
    fn only_a_call_judged_row_over_the_target_moves() {
        let judged = Rule {
            base: Some(String::from("origin/main")),
            ..ratchet_row(Direction::NonIncreasing)
        };
        let retiring = Rule {
            retires_with: Some(String::from("# subject:")),
            ..judged.clone()
        };
        let elsewhere = Rule {
            glob: Some(String::from("*.md")),
            ..judged.clone()
        };
        let rows = [&judged, &retiring, &elsewhere];
        let moving = moving_rows(&rows, "t.bats", Some(""), ONE_CASE).expect("counts");
        assert_eq!(moving.len(), 1, "only the judged row over *.bats moves");
        assert!(std::ptr::eq(moving[0].0, std::ptr::from_ref(&judged)));
    }

    /// The changed set follows its base ref: moving the base while HEAD stays
    /// put is a different set, not the cached one.
    ///
    /// Fails by: the set's cache keyed on another row's ref (HEAD's id), which
    /// answers the old set after the base moved.
    #[test]
    fn a_moved_base_is_a_new_changed_set_with_head_unmoved() {
        let dir = ratchet_repo("rules-changed-base-moved", &[("a.bats", ONE_CASE)], &[]);
        let head = || {
            crate::git::rev_ids(&dir, &["HEAD"]).expect("ids")[0]
                .clone()
                .expect("HEAD resolves")
        };
        let point_base = |id: String| {
            fs::write(dir.join(".git/refs/heads/base"), format!("{id}\n")).expect("ref");
        };
        point_base(head());
        write(&dir, "b.bats", ONE_CASE);
        // A commit's tree is the paths it is handed, so `a.bats` is carried.
        let both = [String::from("a.bats"), String::from("b.bats")];
        crate::gitwrite::commit_paths(&dir, &both, "second").expect("commit");
        let cache = temp_dir("rules-changed-base-moved-cache");
        let row = Rule {
            base: Some(String::from("base")),
            ..ratchet_row(Direction::NonIncreasing)
        };
        let moving = [(&row, Direction::NonIncreasing, "base", "*.bats", 0, 1)];
        let paths = |sets: BTreeMap<(&str, &str), Changed>| {
            sets.into_values()
                .flat_map(|set| set.paths.into_iter().map(|(path, _)| path))
                .collect::<Vec<_>>()
        };
        let before = changed_sets(&moving, &dir, "t.bats", Some(&cache)).expect("diffed");
        assert_eq!(paths(before), ["b.bats", "t.bats"]);
        point_base(head());
        let after = changed_sets(&moving, &dir, "t.bats", Some(&cache)).expect("diffed");
        assert_eq!(paths(after), ["t.bats"], "the base now carries b.bats");
    }

    fn ratchet_row(direction: Direction) -> Rule {
        Rule {
            glob: Some(String::from("*.bats")),
            pattern: Some(String::from("@test \"")),
            direction: Some(direction),
            base: Some(String::from("HEAD")),
            ..blank("r", RuleKind::Ratchet)
        }
    }

    /// What a run of `rule` over `dir` found, by path, and the rows it did not
    /// evaluate.
    fn ratchet_run(rule: Rule, dir: &Path) -> (Vec<String>, Vec<String>) {
        let scan =
            super::run_static(&[rule], &[], crate::policy::Vocabulary::EMPTY, dir).expect("runs");
        (
            scan.findings
                .into_iter()
                .map(|finding| finding.path)
                .collect(),
            scan.not_evaluated.into_keys().collect(),
        )
    }

    const TWO_CASES: &str = "@test \"a\" {\n}\n@test \"b\" {\n}\n";
    const ONE_CASE: &str = "@test \"a\" {\n}\n";

    /// A ratchet refuses a count that moved the banned way and passes one that
    /// held.
    ///
    /// Fails by: never refusing, the `allow` test inverted, the working count
    /// not summing, or the direction test negated.
    #[test]
    fn a_ratchet_refuses_a_fall_and_passes_a_level_count() {
        let fell = ratchet_repo(
            "rules-ratchet-fell",
            &[("t.bats", TWO_CASES)],
            &[("t.bats", ONE_CASE)],
        );
        assert_eq!(
            ratchet_run(ratchet_row(Direction::NonDecreasing), &fell),
            (vec![String::from("*.bats 2->1")], Vec::new())
        );
        let held = ratchet_repo("rules-ratchet-held", &[("t.bats", TWO_CASES)], &[]);
        assert_eq!(
            ratchet_run(ratchet_row(Direction::NonDecreasing), &held),
            (Vec::new(), Vec::new())
        );
    }

    fn md_row(per_file: bool) -> Rule {
        Rule {
            glob: Some(String::from("docs/*.md")),
            counts: Some(CeilingUnit::Tokens),
            direction: Some(Direction::NonIncreasing),
            base: Some(String::from("HEAD")),
            per_file,
            ..blank("r", RuleKind::Ratchet)
        }
    }

    /// A token ratchet counts exactly what `policy budget` counts per file, over
    /// loaded text: growth inside an HTML comment is not growth.
    ///
    /// Fails by: the tokens arm counting nothing.
    #[test]
    fn a_token_ratchet_counts_what_the_budget_counts() {
        let base_text = "# Title\n\nSome body text here.\n";
        let n = crate::budget::estimate_tokens(&crate::budget::loaded(base_text));
        assert!(n > 0);
        let grown = format!("{base_text}12345678");
        let dir = ratchet_repo(
            "rules-ratchet-tokens-grew",
            &[("docs/a.md", base_text)],
            &[("docs/a.md", &grown)],
        );
        assert_eq!(
            ratchet_run(md_row(false), &dir),
            (vec![format!("docs/*.md {n}->{}", n + 2)], Vec::new())
        );
        let commented = format!("{base_text}<!-- a long comment the loader drops -->\n");
        let dir = ratchet_repo(
            "rules-ratchet-tokens-comment",
            &[("docs/a.md", base_text)],
            &[("docs/a.md", &commented)],
        );
        assert_eq!(ratchet_run(md_row(false), &dir), (Vec::new(), Vec::new()));
    }

    /// One file shrinking does not pay for another growing on a per-file row.
    ///
    /// Fails by: the per-file branch skipped, judging the sum.
    #[test]
    fn a_per_file_ratchet_refuses_growth_another_file_paid_for() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "bbbbbbbbbbbbbbbb";
        let dir = ratchet_repo(
            "rules-ratchet-per-file",
            &[("docs/a.md", a), ("docs/b.md", b)],
            &[("docs/a.md", &a[..16]), ("docs/b.md", &format!("{b}bbbb"))],
        );
        assert_eq!(ratchet_run(md_row(false), &dir), (Vec::new(), Vec::new()));
        assert_eq!(
            ratchet_run(md_row(true), &dir),
            (vec![String::from("docs/b.md 4->5")], Vec::new())
        );
    }

    /// A file the branch creates has no ceiling on a per-file row.
    ///
    /// Fails by: judging a new path against a base count of zero.
    #[test]
    fn a_per_file_ratchet_does_not_judge_a_path_new_at_base() {
        let dir = ratchet_repo(
            "rules-ratchet-per-file-new",
            &[("docs/a.md", "aaaaaaaa")],
            &[("docs/new.md", "nnnnnnnnnnnnnnnn")],
        );
        assert_eq!(ratchet_run(md_row(true), &dir), (Vec::new(), Vec::new()));
    }

    /// A deleted file is a fall to zero on a per-file row.
    ///
    /// Fails by: skipping a path absent from the working tree.
    #[test]
    fn a_per_file_non_decreasing_ratchet_refuses_a_deleted_file() {
        let dir = ratchet_repo(
            "rules-ratchet-per-file-deleted",
            &[("t.bats", TWO_CASES), ("u.bats", ONE_CASE)],
            &[("t.bats", "")],
        );
        let rule = Rule {
            per_file: true,
            ..ratchet_row(Direction::NonDecreasing)
        };
        assert_eq!(
            ratchet_run(rule, &dir),
            (vec![String::from("t.bats 2->0")], Vec::new())
        );
    }

    /// A per-file rise that declares the `admits_with` token is admitted; a silent
    /// one is refused with the aggregate's blocker.
    #[test]
    fn a_per_file_ratchet_admits_a_declared_rise_only() {
        let declared = ratchet_repo(
            "rules-ratchet-per-file-declared",
            &[("docs/a.md", "aaaaaaaa")],
            &[("docs/a.md", "aaaaaaaa\nadmits: x\n")],
        );
        let rule = || Rule {
            admits_with: Some(String::from("admits:")),
            ..md_row(true)
        };
        assert_eq!(ratchet_run(rule(), &declared), (Vec::new(), Vec::new()));
        let silent = ratchet_repo(
            "rules-ratchet-per-file-silent",
            &[("docs/a.md", "aaaaaaaa")],
            &[("docs/a.md", "aaaaaaaa\nmore text\n")],
        );
        assert_eq!(
            ratchet_run(rule(), &silent),
            (
                vec![format!("docs/a.md 2->4 [{GROWTH_UNDECLARED} docs/a.md]")],
                Vec::new()
            )
        );
    }

    /// A deleted suite whose declared subject died with it buys its decrease,
    /// which needs the base text read for a `retires_with` row alone.
    ///
    /// Fails by: buffering the base text only when `conserves` is also set.
    #[test]
    fn a_retirement_whose_subject_died_is_admitted() {
        let dir = ratchet_repo(
            "rules-ratchet-retired",
            &[
                ("t.bats", "# subject: prog\n@test \"a\" {\n}\n"),
                ("prog", "#!/bin/sh\n"),
            ],
            &[("t.bats", ""), ("prog", "")],
        );
        let rule = Rule {
            retires_with: Some(String::from("# subject:")),
            ..ratchet_row(Direction::NonDecreasing)
        };
        assert_eq!(ratchet_run(rule, &dir), (Vec::new(), Vec::new()));
    }

    /// A file that grew and declares why buys its increase; one that did not
    /// declare is refused.
    ///
    /// Fails by: recording the files that declared NOTHING as the declaring
    /// ones.
    #[test]
    fn a_growth_that_declares_its_reason_is_admitted() {
        let row = || Rule {
            admits_with: Some(String::from("# stays:")),
            ..ratchet_row(Direction::NonIncreasing)
        };
        let grown = format!("# stays: a reason\n{TWO_CASES}");
        let declared = ratchet_repo(
            "rules-ratchet-declared-growth",
            &[("t.bats", ONE_CASE)],
            &[("t.bats", grown.as_str())],
        );
        assert_eq!(ratchet_run(row(), &declared), (Vec::new(), Vec::new()));
        let silent = ratchet_repo(
            "rules-ratchet-silent-growth",
            &[("t.bats", ONE_CASE)],
            &[("t.bats", TWO_CASES)],
        );
        assert_eq!(
            ratchet_run(row(), &silent),
            (
                vec![String::from("*.bats 1->2 [growth-undeclared t.bats]")],
                Vec::new()
            )
        );
    }

    /// A file's subjects died only when every one was alive at base and none
    /// is present now.
    ///
    /// Fails by: a constant answer, or either term disjoined or un-negated.
    #[test]
    fn a_subject_died_only_when_every_one_was_alive_and_is_gone() {
        let facts = |alive: &[&str], present: &[&str]| SubjectFacts {
            declared: BTreeMap::from([(
                String::from("t"),
                BTreeSet::from([String::from("s1"), String::from("s2")]),
            )]),
            alive_at_base: alive.iter().map(|s| (*s).to_owned()).collect(),
            still_present: present.iter().map(|s| (*s).to_owned()).collect(),
            ..SubjectFacts::default()
        };
        assert!(facts(&["s1", "s2"], &[]).died("t"));
        assert!(!facts(&["s1", "s2"], &["s2"]).died("t"));
        assert!(!facts(&["s1"], &[]).died("t"));
        assert!(!facts(&["s1", "s2"], &[]).died("other"));
    }

    /// Only a path whose count fell is resolved: one declaring nothing is
    /// undeclared, one the head tree lost is gone, and a declared subject is
    /// checked against the base and the head.
    ///
    /// Fails by: a default answer, the fall test inverted, the gone test
    /// negated or inverted, or skipping the base read for a declared subject.
    #[test]
    fn subject_facts_resolve_only_the_paths_that_fell() {
        let dir = seeded("rules-subject-facts");
        let base_counts = BTreeMap::from([
            (String::from("a"), 2),
            (String::from("b"), 1),
            (String::from("c"), 1),
        ]);
        let working_counts: BTreeMap<&str, usize> = BTreeMap::from([("a", 1), ("b", 1)]);
        let base_text = BTreeMap::from([
            (String::from("a"), String::from("no header\n")),
            (String::from("c"), String::from("# subject: a.txt\n")),
        ]);
        let files = vec![String::from("a"), String::from("b"), String::from("a.txt")];
        let facts = subject_facts(
            &dir,
            "HEAD",
            "# subject:",
            &base_counts,
            &working_counts,
            &base_text,
            &files,
        )
        .expect("resolves");
        let set = |items: &[&str]| -> BTreeSet<String> {
            items.iter().map(|item| (*item).to_owned()).collect()
        };
        assert_eq!(facts.undeclared, set(&["a"]));
        assert_eq!(
            facts.declared,
            BTreeMap::from([(String::from("c"), set(&["a.txt"]))])
        );
        assert_eq!(facts.gone, set(&["c"]));
        assert_eq!(facts.alive_at_base, set(&["a.txt"]));
        assert_eq!(facts.still_present, set(&["a.txt"]));
    }

    /// What blocks a decrease: an unmapped undeclared path, a subject that
    /// never existed, and a surviving subject no ledger arm names — and a
    /// mapped path that merely shrank owes nothing.
    ///
    /// Fails by: any placeholder set, any negation dropped, the surviving-
    /// subject conjunction disjoined, or the ledger answering for every path.
    #[test]
    fn retirement_blockers_name_what_the_ledger_does_not_discharge() {
        let set = |items: &[&str]| -> BTreeSet<String> {
            items.iter().map(|item| (*item).to_owned()).collect()
        };
        let subjects = SubjectFacts {
            declared: BTreeMap::from([
                (String::from("m-partial"), set(&["s-alive"])),
                (
                    String::from("m-gone"),
                    set(&["s-never", "s-target", "s-untargeted", "s-dead"]),
                ),
                (String::from("free"), set(&["f-never", "f-alive", "f-dead"])),
            ]),
            undeclared: set(&["u1", "u2"]),
            alive_at_base: set(&[
                "s-alive",
                "s-target",
                "s-untargeted",
                "s-dead",
                "f-alive",
                "f-dead",
            ]),
            still_present: set(&["s-alive", "s-target", "s-untargeted", "f-alive"]),
            gone: set(&["m-gone"]),
        };
        let mapped = MappedLedger {
            targets: BTreeMap::from([
                (String::from("u1"), set(&[])),
                (String::from("m-partial"), set(&[])),
                (String::from("m-gone"), set(&["s-target"])),
            ]),
        };
        assert_eq!(
            retirement_blockers(&subjects, &mapped),
            set(&[
                "subject-undeclared u2",
                "subject-never-existed s-never",
                "subject-alive s-untargeted",
                "subject-never-existed f-never",
                "subject-alive f-alive",
            ])
        );
    }

    /// Only a file whose own count rose without declaring why blocks an
    /// increase.
    ///
    /// Fails by: any placeholder set, the growth comparison changed, or the
    /// declaration test disjoined or un-negated.
    #[test]
    fn undeclared_growth_names_only_the_silent_risers() {
        let base = BTreeMap::from([(String::from("a"), 1), (String::from("b"), 2)]);
        let working: BTreeMap<&str, usize> =
            BTreeMap::from([("a", 2), ("b", 2), ("c", 1), ("d", 1)]);
        let declared: BTreeSet<&str> = BTreeSet::from(["c"]);
        assert_eq!(
            undeclared_growth(&base, &working, &declared),
            BTreeSet::from([
                String::from("growth-undeclared a"),
                String::from("growth-undeclared d"),
            ])
        );
    }

    /// Every declaring line's paths are unioned.
    ///
    /// Fails by: any placeholder set.
    #[test]
    fn declared_subjects_union_every_declaring_line() {
        assert_eq!(
            declared_subject("# subject: a b\nother\n# subject: c\n", "# subject:"),
            BTreeSet::from([String::from("a"), String::from("b"), String::from("c")])
        );
    }

    /// Each arm has its own token, owes a target unless it withdraws, and owes
    /// a subject only when it ports.
    ///
    /// Fails by: an empty or placeholder token, or a constant obligation.
    #[test]
    fn each_arm_has_its_token_and_its_obligations() {
        let arms = [
            Arm::Carried,
            Arm::Subsumed,
            Arm::Changed,
            Arm::Withdrawn,
            Arm::Ported,
        ];
        let tokens: Vec<&str> = arms.iter().map(|arm| arm.as_str()).collect();
        assert_eq!(
            tokens,
            ["carried", "subsumed", "changed", "withdrawn", "ported"]
        );
        let targets: Vec<bool> = arms.iter().map(|arm| arm.owes_a_target()).collect();
        assert_eq!(targets, [true, true, true, false, true]);
        let subjects: Vec<bool> = arms.iter().map(|arm| arm.owes_a_subject()).collect();
        assert_eq!(subjects, [false, false, false, false, true]);
    }

    /// A ported arm's subject is its non-empty `subject:` field.
    ///
    /// Fails by: a constant answer, or the emptiness filter inverted.
    #[test]
    fn a_ported_subject_is_its_non_empty_field() {
        assert_eq!(
            ported_subject("why subject:src/a.rs more"),
            Some("src/a.rs")
        );
        assert_eq!(ported_subject("why subject: more"), None);
        assert_eq!(ported_subject("no field"), None);
    }

    fn ledger_vocabulary() -> Conserves {
        Conserves {
            case: String::from("@test \""),
            close: String::from("\""),
            carried: String::from("// carried:"),
            subsumed: String::from("// subsumed:"),
            changed: String::from("// changed:"),
            withdrawn: Some(String::from("// withdrawn:")),
            ported: Some(String::from("// ported:")),
            declared_in: String::from("ledger.rs"),
        }
    }

    /// An arm's claim records the 1-based line it was written on, and a dying
    /// file's case names are every closed one.
    ///
    /// Fails by: a zero-based line, or any placeholder name set.
    #[test]
    fn claims_and_cases_are_read_with_their_lines_and_names() {
        let dir = temp_dir("rules-claimed-cases");
        write(&dir, "ledger.rs", "\n// carried: \"one\" kept.rs\n");
        let conserves = ledger_vocabulary();
        let claimed = claimed_cases(&dir, &conserves, &[String::from("ledger.rs")]);
        let lines: Vec<usize> = claimed.claims["one"]
            .iter()
            .map(|claim| claim.line)
            .collect();
        assert_eq!(lines, [2]);
        assert_eq!(
            case_names(
                "@test \"a\" {\n  @test \"b\"\n@test \"unclosed\n",
                &conserves
            ),
            BTreeSet::from([String::from("a"), String::from("b")])
        );
        let rule = Rule {
            conserves: Some(conserves.clone()),
            ..ratchet_row(Direction::NonDecreasing)
        };
        let empty = ClaimedCases::default();
        let mapping = Mapping {
            conserves: &conserves,
            claimed: &empty,
            files: &[],
            subject_died: false,
            declared_subjects: &NO_SUBJECTS,
        };
        let mut findings = Vec::new();
        unconserved_cases(
            &rule,
            "t.bats",
            "x\n@test \"lost\" {\n",
            "",
            &mapping,
            &mut findings,
            &mut BTreeSet::new(),
        );
        let at: Vec<Option<usize>> = findings.iter().map(|finding| finding.line).collect();
        assert_eq!(at, [Some(2)]);
    }

    /// What one resolved claim owes: a withdrawal a dead subject and a reason,
    /// a port a declared, present survivor that then travels as a target.
    ///
    /// Fails by: the withdrawal's subject test un-negated, its emptiness
    /// conjunction disjoined, the port check dropped, or either of its
    /// containment tests un-negated or inverted.
    #[test]
    fn a_resolved_claim_owes_what_its_arm_owes() {
        let conserves = ledger_vocabulary();
        let claimed = ClaimedCases::default();
        let rule = Rule {
            conserves: Some(conserves.clone()),
            ..ratchet_row(Direction::NonDecreasing)
        };
        let files = vec![String::from("kept.rs"), String::from("subject.rs")];
        let judge = |arm, target: &str, reason: &str, died: bool, declared: &[&str]| {
            let declared: BTreeSet<String> = declared.iter().map(|s| (*s).to_owned()).collect();
            let mapping = Mapping {
                conserves: &conserves,
                claimed: &claimed,
                files: &files,
                subject_died: died,
                declared_subjects: &declared,
            };
            let claim = Claim {
                arm,
                path: String::from("ledger.rs"),
                line: 1,
                target: target.to_owned(),
                reason: reason.to_owned(),
            };
            let (mut findings, mut targets) = (Vec::new(), BTreeSet::new());
            resolved_claim(&rule, &claim, "case", &mapping, &mut findings, &mut targets);
            (findings.len(), targets.into_iter().collect::<Vec<_>>())
        };
        let none: Vec<String> = Vec::new();
        assert_eq!(
            judge(Arm::Withdrawn, "gone", "because", false, &[]),
            (1, none.clone())
        );
        assert_eq!(
            judge(Arm::Withdrawn, "gone", "", true, &[]),
            (0, none.clone())
        );
        assert_eq!(judge(Arm::Withdrawn, "", "", true, &[]), (1, none.clone()));
        assert_eq!(
            judge(
                Arm::Ported,
                "kept.rs",
                "subject:subject.rs",
                false,
                &["subject.rs"]
            ),
            (0, vec![String::from("kept.rs"), String::from("subject.rs")])
        );
        assert_eq!(
            judge(
                Arm::Ported,
                "kept.rs",
                "subject:other.rs",
                false,
                &["other.rs"]
            ),
            (1, vec![String::from("kept.rs")])
        );
        assert_eq!(
            judge(
                Arm::Ported,
                "kept.rs",
                "subject:subject.rs",
                true,
                &["subject.rs"]
            ),
            (1, vec![String::from("kept.rs")])
        );
    }

    /// A subject that does not resolve is reported at its declaring line, or
    /// at line 1 where there is none.
    ///
    /// Fails by: raising nothing, a wrong line, or the resolution test
    /// inverted.
    #[test]
    fn an_unresolved_subject_is_reported_at_its_declaration() {
        let rule = ratchet_row(Direction::NonDecreasing);
        let files = vec![String::from("here")];
        let lines = |text: &str| {
            let mut findings = Vec::new();
            unresolved_subject(&rule, "t.bats", text, "# subject:", &files, &mut findings);
            findings
                .into_iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>()
        };
        assert_eq!(lines("x\n# subject:\n"), [Some(2)]);
        assert_eq!(lines("x\n# subject: gone\n"), [Some(2)]);
        assert_eq!(lines("no header\n"), [Some(1)]);
        assert_eq!(lines("# subject: here\n"), Vec::<Option<usize>>::new());
    }

    /// Blockers render bounded and sorted, and nothing for none.
    ///
    /// Fails by: a placeholder rendering, or the overflow test inverted.
    #[test]
    fn blockers_render_bounded() {
        let set = |items: &[&str]| -> BTreeSet<String> {
            items.iter().map(|item| (*item).to_owned()).collect()
        };
        assert_eq!(render_blockers(&set(&[])), "");
        assert_eq!(render_blockers(&set(&["b", "a"])), " [a, b]");
        assert_eq!(
            render_blockers(&set(&["a", "b", "c", "d", "e"])),
            " [a, b, c +2 more]"
        );
    }

    /// A check with no `{{files}}` runs once even over an empty match.
    ///
    /// Fails by: the placeholder test negated, which batches an empty match
    /// into no run at all.
    #[test]
    fn a_self_discovering_check_runs_once() {
        let dir = temp_dir("rules-command-once");
        let mut findings = Vec::new();
        command_rule(&command("c", "*.none", "false"), &dir, &[], &mut findings).expect("runs");
        assert_eq!(findings.len(), 1);
    }

    /// Paths are batched while they fit, and split only past the bound.
    ///
    /// Fails by: splitting every path, multiplying the running length, or the
    /// bound comparison changed.
    #[test]
    fn batches_split_only_past_the_bound() {
        let sizes = |paths: &[String]| {
            let refs: Vec<&String> = paths.iter().collect();
            batches(&refs).iter().map(Vec::len).collect::<Vec<_>>()
        };
        assert_eq!(sizes(&[String::from("a"), String::from("b")]), [2]);
        let half = "x".repeat(MAX_FILES_BYTES / 2 - 1);
        assert_eq!(
            sizes(&[half.clone(), half.clone()]),
            [2],
            "exactly at the bound"
        );
        assert_eq!(
            sizes(&[half.clone(), half.clone(), String::from("c")]),
            [2, 1]
        );
        assert_eq!(sizes(&["y".repeat(10_000), "z".repeat(10)]), [2]);
    }

    /// A program on `PATH` is found by name, through the real `PATH` and a
    /// supplied one.
    ///
    /// Fails by: answering `None`.
    #[test]
    fn a_program_on_path_is_found() {
        if cfg!(unix) {
            assert!(
                on_path_verbatim("sh").is_some(),
                "`sh` is on every Unix PATH"
            );
        }
        let dir = temp_dir("rules-lookup-verbatim");
        write(&dir, "tool", "");
        assert_eq!(
            lookup_verbatim("tool", dir.as_os_str()),
            Some(dir.join("tool"))
        );
    }

    /// A program not on `PATH` is refused as such, and any other spawn failure
    /// keeps its own cause.
    ///
    /// Fails by: the not-found guard forced either way, or inverted.
    #[test]
    fn a_spawn_failure_names_its_own_cause() {
        let dir = temp_dir("rules-run-once");
        let rule = command("c", "*", "x");
        let refused = |program: &str| {
            run_once(&rule, &dir, program, &[], &[], &mut Vec::new())
                .expect_err("refused")
                .to_string()
        };
        assert!(refused("batten-rules-no-such-program").contains("not found on PATH"));
        // An interior NUL is refused by the standard library before any OS
        // call, so this is a non-NotFound spawn failure on every platform.
        let other = refused("data\0x");
        assert!(other.contains("cannot run"), "{other}");
        assert!(!other.contains("not found on PATH"), "{other}");
    }

    /// Only `verbatim = true` hashes a span verbatim.
    ///
    /// Fails by: a constant mode, or the test inverted.
    #[test]
    fn only_a_verbatim_row_hashes_verbatim() {
        let row = |verbatim| Rule {
            verbatim,
            ..forbid("f", "*.rs", "x")
        };
        assert!(matches!(
            span_mode(&row(Some(true))),
            crate::identity::SpanNormalization::Verbatim
        ));
        assert!(matches!(
            span_mode(&row(None)),
            crate::identity::SpanNormalization::Collapsed
        ));
        assert!(matches!(
            span_mode(&row(Some(false))),
            crate::identity::SpanNormalization::Collapsed
        ));
    }

    /// A listed path the read cannot find is skipped, not an error.
    ///
    /// Fails by: the not-found guard forced false.
    #[test]
    fn a_vanished_path_is_skipped_by_forbid() {
        let dir = temp_dir("rules-forbid-vanished");
        let absent = String::from("absent.rs");
        let mut findings = Vec::new();
        forbid_in_files(&forbid("f", "*.rs", "x"), &dir, &[&absent], &mut findings)
            .expect("a vanished path is not an error");
        assert!(findings.is_empty());
    }

    /// A document row passes a node holding its literal and refuses one that
    /// differs.
    ///
    /// Fails by: passing every file, or the comparison inverted.
    #[test]
    fn a_document_row_compares_its_node() {
        let dir = temp_dir("rules-document-in-file");
        write(&dir, "same.json", "{\"a\": \"1\"}");
        write(&dir, "other.json", "{\"a\": \"2\"}");
        let rule = Rule {
            glob: Some(String::from("*.json")),
            format: Some(crate::facts::Format::Json),
            node: Some(String::from("a")),
            pattern: Some(String::from("1")),
            ..blank("d", RuleKind::Document)
        };
        let found = |path: &str| {
            let mut findings = Vec::new();
            document_in_file(&rule, &dir, path, &BTreeMap::new(), &mut findings).expect("reads");
            findings.len()
        };
        assert_eq!(found("same.json"), 0);
        assert_eq!(found("other.json"), 1);
    }

    fn table_register(id: &str, path: &str, width: usize) -> crate::register::DeclaredRegister {
        crate::register::DeclaredRegister {
            id: id.to_owned(),
            paths: vec![path.to_owned()],
            source: crate::register::Source::Table {
                key: 1,
                width,
                row_prefix: None,
                key_pattern: None,
                patterns: BTreeMap::new(),
                unique: false,
            },
        }
    }

    fn cites(register: &str) -> crate::register::Cites {
        crate::register::Cites {
            register: register.to_owned(),
            from_register: None,
            column: None,
            split: None,
            within: None,
            partition: None,
            relative_to: None,
            inverse: false,
        }
    }

    const KEYS: &str = "| key | note |\n| --- | --- |\n| alpha | a |\n| beta | b |\n";

    /// Two tables over one fixture: the `keys` register and a one-column
    /// `src` register.
    fn register_tables() -> Vec<crate::register::DeclaredRegister> {
        vec![
            table_register("keys", "reg.md", 2),
            table_register("src", "src.md", 1),
        ]
    }

    fn reference_fixture(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        write(&dir, "reg.md", KEYS);
        write(&dir, "src.md", "| key |\n| --- |\n| delta |\n");
        write(&dir, "cite.txt", "x\nsee alpha and gamma\n");
        write(&dir, "c1.json", "{\"refs\": [\"alpha\"]}");
        write(&dir, "bad.json", "{not json");
        dir
    }

    fn regex_reference() -> Rule {
        Rule {
            glob: Some(String::from("cite.txt")),
            regex: Some(String::from(r"\b(alpha|gamma)\b")),
            cites: Some(cites("keys")),
            ..blank("ref", RuleKind::Reference)
        }
    }

    /// A reference row resolves its citations against its register, reporting
    /// the unresolved one; a row citing nothing is skipped.
    ///
    /// Fails by: reporting nothing, or the register lookup inverted.
    #[test]
    fn a_reference_row_reports_the_token_its_register_lacks() {
        let dir = reference_fixture("rules-reference-rule");
        let files = vec![
            String::from("cite.txt"),
            String::from("reg.md"),
            String::from("src.md"),
        ];
        let registers = register_tables();
        let tables = RunTables {
            registers: &registers,
            patterns: BTreeMap::new(),
            traversals: serde_json::Value::Null,
            shell: None,
        };
        let facts = BareFacts::new();
        let inputs = RunInputs {
            half: None,
            tables: &tables,
            ..facts.inputs(&files)
        };
        let mut findings = Vec::new();
        assert!(matches!(
            reference_rule(&regex_reference(), &dir, &inputs, &mut findings),
            Ok(None)
        ));
        let at: Vec<(String, Option<usize>)> = findings
            .iter()
            .map(|finding| (finding.path.clone(), finding.line))
            .collect();
        assert_eq!(at, [(String::from("cite.txt"), Some(2))]);
        let uncited = Rule {
            cites: None,
            ..regex_reference()
        };
        assert!(matches!(
            reference_rule(&uncited, &dir, &inputs, &mut Vec::new()),
            Ok(Some(NotObserved::RuleSkipped))
        ));
        // `run_rule` reaches it for a deny row and skips an `allow` one.
        let (mut found, mut classes) = (Vec::new(), BTreeMap::new());
        assert!(matches!(
            run_rule(&regex_reference(), &dir, &inputs, &mut found, &mut classes),
            Ok(None)
        ));
        let allowed = Rule {
            severity: Some(RuleSeverity::Allow),
            ..regex_reference()
        };
        assert!(matches!(
            run_rule(&allowed, &dir, &inputs, &mut Vec::new(), &mut classes),
            Ok(Some(NotObserved::RuleSkipped))
        ));
    }

    /// Each citer shape gathers its tokens with their lines: a line regex, a
    /// register's column, and a document node — an absent document is
    /// skipped and an unparseable one reported.
    ///
    /// Fails by: gathering nothing, a wrong line, the register lookup
    /// inverted, or either document arm dropped.
    #[test]
    fn every_citer_shape_gathers_its_tokens() {
        let dir = reference_fixture("rules-gather-citations");
        let files = vec![
            String::from("bad.json"),
            String::from("c1.json"),
            String::from("c2.json"),
            String::from("cite.txt"),
            String::from("reg.md"),
            String::from("src.md"),
        ];
        let registers = register_tables();
        let tables = RunTables {
            registers: &registers,
            patterns: BTreeMap::new(),
            traversals: serde_json::Value::Null,
            shell: None,
        };
        let facts = BareFacts::new();
        let inputs = RunInputs {
            half: None,
            tables: &tables,
            ..facts.inputs(&files)
        };
        let register_inputs = RegisterInputs {
            files: &files,
            patterns: &tables.patterns,
        };
        let gather = |rule: &Rule| {
            let mut findings = Vec::new();
            let citations = gather_citations(
                rule,
                rule.cites.as_ref().expect("cites"),
                &dir,
                &inputs,
                &register_inputs,
                &mut findings,
            )
            .expect("gathers")
            .expect("a citer");
            let tokens: Vec<(String, String, Option<usize>)> = citations
                .into_iter()
                .map(|citation| (citation.token, citation.at.path, citation.at.line))
                .collect();
            (tokens, findings.len())
        };
        let cited = |token: &str, path: &str, line| (token.to_owned(), path.to_owned(), line);
        assert_eq!(
            gather(&regex_reference()),
            (
                vec![
                    cited("alpha", "cite.txt", Some(2)),
                    cited("gamma", "cite.txt", Some(2))
                ],
                0
            )
        );
        let column = Rule {
            glob: None,
            regex: None,
            cites: Some(crate::register::Cites {
                from_register: Some(String::from("src")),
                column: Some(1),
                ..cites("keys")
            }),
            ..regex_reference()
        };
        assert_eq!(gather(&column).0, [cited("delta", "src.md", Some(3))]);
        let node = Rule {
            glob: Some(String::from("*.json")),
            regex: None,
            format: Some(crate::facts::Format::Json),
            node: Some(String::from("refs")),
            ..regex_reference()
        };
        assert_eq!(gather(&node), (vec![cited("alpha", "c1.json", None)], 1));
    }

    /// A register reads the tracked paths its globs select, a table from its
    /// lines and a document set from its frontmatter.
    ///
    /// Fails by: any placeholder path list, or either acquisition arm dropped.
    #[test]
    fn a_register_is_built_from_the_paths_it_selects() {
        let dir = temp_dir("rules-build-register");
        write(&dir, "reg.md", KEYS);
        write(&dir, "d.md", "---\nid: omega\n---\nbody\n");
        let files = vec![
            String::from("a.md"),
            String::from("b.txt"),
            String::from("reg.md"),
        ];
        let patterns = BTreeMap::new();
        let inputs = RegisterInputs {
            files: &files,
            patterns: &patterns,
        };
        let globbed = crate::register::DeclaredRegister {
            paths: vec![String::from("*.md")],
            ..table_register("keys", "unused", 2)
        };
        assert_eq!(
            register_paths(&globbed, &inputs).expect("selects"),
            ["a.md", "reg.md"]
        );
        let table = table_register("keys", "reg.md", 2);
        let built = build_register(&table, &dir, &inputs).expect("builds");
        assert_eq!(built.contains("alpha"), Some(true));
        let doc_files = vec![String::from("d.md")];
        let documents = crate::register::DeclaredRegister {
            id: String::from("docs"),
            paths: vec![String::from("d.md")],
            source: crate::register::Source::Documents {
                key_node: String::from("id"),
                refused_values: BTreeMap::new(),
            },
        };
        let built = build_register(
            &documents,
            &dir,
            &RegisterInputs {
                files: &doc_files,
                patterns: &patterns,
            },
        )
        .expect("builds");
        assert_eq!(built.contains("omega"), Some(true));
    }

    /// Derived values resolve through a chain declared out of order, and a
    /// producer whose input nothing derives stays unresolved.
    ///
    /// Fails by: resolving nothing, the wait negated, or stopping after the
    /// first pass that advanced.
    #[test]
    fn derived_values_resolve_through_a_chain() {
        let dir = temp_dir("rules-resolve-derived");
        write(&dir, "a.json", "{\"v\": \"1\"}");
        write(&dir, "b.json", "{\"v\": \"2\"}");
        let files = vec![String::from("a.json"), String::from("b.json")];
        let producer = |id: &str, derives: &str, reads: Option<&str>, glob: &str| Rule {
            glob: Some(glob.to_owned()),
            format: Some(crate::facts::Format::Json),
            node: Some(String::from("v")),
            derives: Some(derives.to_owned()),
            reads: reads.map(ToOwned::to_owned),
            ..blank(id, RuleKind::Document)
        };
        let rules = [
            producer("b", "b", Some("a"), "b.json"),
            producer("c", "c", Some("nothing"), "a.json"),
            producer("a", "a", None, "a.json"),
        ];
        let resolved: Vec<(String, Option<String>)> = resolve_derived(&rules, &dir, &files)
            .into_iter()
            .map(|(name, look)| {
                let value = match look {
                    crate::facts::Look::Is(value) => Some(value),
                    crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook => None,
                };
                (name, value)
            })
            .collect();
        assert_eq!(
            resolved,
            [
                (String::from("a"), Some(String::from("1"))),
                (String::from("b"), Some(String::from("2"))),
            ]
        );
    }

    /// The walk stops at a nested repository but never at its own root.
    ///
    /// Fails by: the root test inverted, which judges every directory but the
    /// root as the root.
    #[test]
    fn the_walk_stops_at_a_nested_repository() {
        let dir = temp_dir("rules-tree-files-nested");
        write(&dir, "a.txt", "a\n");
        write(&dir, "sub/.git/HEAD", "ref\n");
        write(&dir, "sub/b.txt", "b\n");
        assert_eq!(tree_files(&dir).expect("walks"), ["a.txt"]);
    }

    /// The empty set is empty, and two selectors are equal only over one
    /// pattern.
    ///
    /// Fails by: a constant answer.
    #[test]
    fn emptiness_and_selector_equality_are_read_off_the_config() {
        assert!(PathSet::empty().is_empty());
        let selector = |glob: &str| Selector::new(glob).expect("compiles");
        assert_eq!(selector("*.rs"), selector("*.rs"));
        assert_ne!(selector("*.rs"), selector("*.md"));
    }

    /// A non-ratchet row selects from the narrowed list, never the whole tree.
    ///
    /// Fails by: the ratchet test inverted.
    #[test]
    fn only_a_ratchet_selects_from_the_whole_tree() {
        let dir = temp_dir("rules-run-rule-scoped");
        write(&dir, "a.rs", "TODO\n");
        write(&dir, "b.rs", "TODO\n");
        let files = vec![String::from("a.rs"), String::from("b.rs")];
        let scoped = vec![String::from("a.rs")];
        let facts = BareFacts::new();
        let inputs = RunInputs {
            half: None,
            scoped: &scoped,
            ..facts.inputs(&files)
        };
        let (mut findings, mut classes) = (Vec::new(), BTreeMap::new());
        run_rule(
            &forbid("f", "*.rs", "TODO"),
            &dir,
            &inputs,
            &mut findings,
            &mut classes,
        )
        .expect("runs");
        let paths: Vec<&str> = findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect();
        assert_eq!(paths, ["a.rs"]);
    }

    /// A declared walk is answered per seed, reading present and absent
    /// documents and building the register an edge names.
    ///
    /// Fails by: answering `null`, the register an edge names left unbuilt, the
    /// register lookup inverted, or either document arm dropped.
    #[test]
    fn a_declared_walk_is_answered_per_seed() {
        let dir = temp_dir("rules-walk-traversals");
        write(&dir, "reg.md", KEYS);
        write(&dir, "s1.md", "---\nspec: alpha\n---\nbody\n");
        let files = vec![
            String::from("reg.md"),
            String::from("s1.md"),
            String::from("s2.md"),
        ];
        let registers = vec![table_register("keys", "reg.md", 2)];
        let traversals: Vec<crate::traversal::DeclaredTraversal> = vec![
            serde_json::from_value(serde_json::json!({
                "id": "t",
                "seeds": "s*.md",
                "edge": [{"label": "spec", "field": "spec", "to": {"register": "keys"}}],
                "max_visits": 10,
                "max_depth": 5,
                "reduce": "path",
            }))
            .expect("a traversal row"),
        ];
        let vocabulary = crate::policy::Vocabulary {
            registers: &registers,
            traversals: &traversals,
            ..crate::policy::Vocabulary::EMPTY
        };
        let walked = walk_traversals(vocabulary, &dir, &files, &BTreeMap::new()).expect("walks");
        let outcome = |seed: &str| walked["t"][seed]["outcome"].clone();
        assert_eq!(outcome("s1.md"), serde_json::json!("exhausted"), "{walked}");
        assert_eq!(outcome("s2.md"), serde_json::json!("exhausted"), "{walked}");
        assert_eq!(
            walked["t"]["s1.md"]["visited"],
            serde_json::json!(2),
            "the seed and the register node it names: {walked}"
        );
    }

    /// A register only an edge names must be declared, as one `until_register`
    /// names must.
    ///
    /// Fails by: dropping the edge targets from the registers the walk builds.
    #[test]
    fn an_edge_naming_an_undeclared_register_is_refused() {
        let dir = temp_dir("rules-walk-undeclared-register");
        let traversals: Vec<crate::traversal::DeclaredTraversal> = vec![
            serde_json::from_value(serde_json::json!({
                "id": "t",
                "seeds": "s*.md",
                "edge": [{"label": "spec", "field": "spec", "to": {"register": "missing"}}],
                "max_visits": 10,
                "max_depth": 5,
                "reduce": "path",
            }))
            .expect("a traversal row"),
        ];
        let vocabulary = crate::policy::Vocabulary {
            traversals: &traversals,
            ..crate::policy::Vocabulary::EMPTY
        };
        let refused = walk_traversals(vocabulary, &dir, &[], &BTreeMap::new())
            .expect_err("an undeclared register is refused");
        assert!(refused.to_string().contains("`missing`"), "{refused}");
    }
}

/// Step 13a: the split `enforce`'s classifier, partition and backstop.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod half_tests {
    use super::null_live_keys;
    #[cfg(test)]
    use crate::config_check::rules::RuleExt as _;
    use crate::config_model::{Rule, RuleKind};
    #[cfg(test)]
    use crate::facts::{Fact, Subject};
    use crate::preset_catalog::RuleScope;
    #[cfg(test)]
    use crate::rules::RuleExt as _;
    #[cfg(test)]
    use crate::rules::RuleKindExt as _;
    use crate::surface_table::Half;

    /// A blank row of `kind` on its first permitted scope, plus `extra`.
    fn row(kind: RuleKind, extra: &serde_json::Value) -> Rule {
        let mut value = serde_json::json!({
            "id": "r",
            "kind": kind,
            "scope": kind.scopes()[0],
        });
        if let (Some(object), Some(more)) = (value.as_object_mut(), extra.as_object()) {
            object.extend(more.clone());
        }
        serde_json::from_value(value).expect("a blank row deserialises")
    }

    const KEYED: &[String] = &[];

    #[test]
    fn the_tree_subjects_are_exactly_the_indexed_facts() {
        let tree: Vec<Fact> = Fact::ALL
            .iter()
            .copied()
            .filter(|fact| fact.subject() == Subject::Tree)
            .collect();
        assert_eq!(
            tree,
            vec![
                Fact::Document,
                Fact::Tracked,
                Fact::Traversals,
                Fact::Lines,
                Fact::GitIndex,
                Fact::Staged,
                Fact::Invocations,
                Fact::Units,
                Fact::Base,
                Fact::Coupling,
                Fact::Uses,
                Fact::Shell,
            ],
            "a fact joins the tree half only by an edit here, never by default"
        );
        for fact in tree {
            let key = fact
                .tree_key()
                .expect("a tree subject is projected on the tree surface");
            assert_eq!(Fact::from_tree_key(key), Some(fact), "{key} round-trips");
        }
        assert_eq!(Fact::from_tree_key("missing"), None);
    }

    #[test]
    fn each_kind_falls_on_its_half() {
        for kind in RuleKind::ALL {
            let blank = row(*kind, &serde_json::json!({}));
            let expected = match kind {
                RuleKind::Forbid | RuleKind::Document | RuleKind::Secrets | RuleKind::Reference => {
                    Half::Tree
                }
                // A ratchet with no keyed base, and a policy row with no bundle,
                // cannot be shown to be tree.
                RuleKind::Ratchet
                | RuleKind::Policy
                | RuleKind::Command
                | RuleKind::Judge
                | RuleKind::Receipt
                | RuleKind::Shape
                | RuleKind::Pipeline
                | RuleKind::Native => Half::Live,
            };
            let got = if blank.scope == RuleScope::MediatedCall {
                Half::Live
            } else {
                expected
            };
            assert_eq!(blank.half(None, KEYED), got, "{}", kind.as_str());
        }
    }

    /// Fails by: a tree fact read as live (a tree row re-run every lap), a
    /// live fact read as tree (a receipt standing in for a live verdict), or
    /// the row's declared facts not read at all.
    #[test]
    fn a_rows_declared_facts_decide_its_half() {
        let lines = row(RuleKind::Forbid, &serde_json::json!({"lines": ["x"]}));
        assert_eq!(lines.half(None, KEYED), Half::Tree);
        let symbols = row(RuleKind::Forbid, &serde_json::json!({"symbols": true}));
        assert_eq!(symbols.half(None, KEYED), Half::Live);
        assert_eq!((Half::Tree.as_str(), Half::Live.as_str()), ("tree", "live"));
    }

    /// Fails by: a lint count taking a `regex` beside its lint, or one naming
    /// no lint.
    #[test]
    fn a_lint_count_names_its_lint_and_nothing_else() {
        let count = |extra: serde_json::Value| {
            let mut fields = serde_json::json!({"counts": "lint_escapes"});
            fields
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            row(RuleKind::Ratchet, &fields).validate_ratchet_measure()
        };
        assert!(count(serde_json::json!({"pattern": "clippy::x"})).is_ok());
        assert!(count(serde_json::json!({})).is_err(), "no lint");
        assert!(
            count(serde_json::json!({"pattern": "clippy::x", "regex": "y"})).is_err(),
            "a regex beside the lint"
        );
    }

    /// Fails by: the hook evaluating on more than one thread, or another
    /// surface on one.
    #[test]
    fn only_the_hook_evaluates_on_one_thread() {
        assert_eq!(super::workers_for(crate::facts::Surface::Hook), 1);
        assert_eq!(
            super::workers_for(crate::facts::Surface::Check),
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        );
    }

    #[test]
    fn a_ratchet_is_tree_only_against_a_keyed_base() {
        let ratchet = row(
            RuleKind::Ratchet,
            &serde_json::json!({"base": "origin/main"}),
        );
        assert_eq!(ratchet.half(None, &[]), Half::Live);
        assert_eq!(ratchet.half(None, &["origin/other".to_owned()]), Half::Live);
        assert_eq!(ratchet.half(None, &["origin/main".to_owned()]), Half::Tree);
    }

    #[test]
    fn a_base_delta_row_is_tree_only_against_a_keyed_base() {
        // CLOUD-2329: `base-delta` is the diff against the row's own `base`, so
        // it is keyed exactly as a ratchet is, by the base's commit.
        let delta = row(
            RuleKind::Forbid,
            &serde_json::json!({"base": "origin/main", "delta_sources": ["**"]}),
        );
        assert_eq!(delta.half(None, &[]), Half::Live);
        assert_eq!(delta.half(None, &["origin/other".to_owned()]), Half::Live);
        assert_eq!(delta.half(None, &["origin/main".to_owned()]), Half::Tree);
    }

    #[test]
    fn a_live_fact_or_an_existence_test_moves_a_tree_kind_live() {
        let forbid = row(RuleKind::Forbid, &serde_json::json!({}));
        assert_eq!(forbid.half(None, KEYED), Half::Tree, "the premise");
        let required = Rule {
            requires_path: vec!["target/x".to_owned()],
            ..forbid.clone()
        };
        assert_eq!(required.half(None, KEYED), Half::Live);
        let mediated = Rule {
            scope: RuleScope::MediatedCall,
            ..forbid
        };
        assert_eq!(mediated.half(None, KEYED), Half::Live);
    }

    #[test]
    fn a_policy_row_is_tree_only_when_its_bundle_reads_tree_keys() {
        let policy = row(RuleKind::Policy, &serde_json::json!({"scope": "tree"}));
        let module = |body: &str| {
            format!(
                "package batten.r\n\nimport rego.v1\n\nrules contains \"x probe probex\"\n\n\
                 violation contains {{\"rule\": \"x probe probex\", \"verdict\": \"x probe probex\", \
                 \"subjects\": []}} if {{\n{body}\n}}\n"
            )
        };
        let bundle = |body: &str| {
            crate::policy::compile(
                "r",
                &[("policy/r.rego".to_owned(), module(body))],
                &serde_json::json!({}),
            )
            .expect("the fixture compiles")
        };
        let tree = bundle("\tinput.tree.documents.x != null\n\tinput.tree.missing != null");
        assert_eq!(policy.half(Some(&tree), KEYED), Half::Tree);
        // `records` is out-of-tree state with a digest: the tree half's inputs
        // digest folds in exactly the records a run reads (CLOUD-2329).
        let records = bundle("\tinput.tree.records.x != null");
        assert_eq!(policy.half(Some(&records), KEYED), Half::Tree);
        let forge = bundle("\tinput.tree.forge.x != null");
        assert_eq!(policy.half(Some(&forge), KEYED), Half::Live);
        let aliased = bundle("\tt := input.tree\n\tt.documents != null");
        assert_eq!(policy.half(Some(&aliased), KEYED), Half::Live);
    }

    #[test]
    fn the_backstop_nulls_every_live_key_and_keeps_the_tree() {
        let document = serde_json::json!({"tree": {
            "documents": {"a": 1},
            "staged": {"b": 2},
            "missing": {"c": "unparsed"},
            "records": {"runs": ["row\tx"]},
            "git-head": "abc",
            "forge": {},
            "unheard-of": 1,
        }});
        let nulled: serde_json::Value =
            serde_json::from_str(&null_live_keys(&document.to_string())).expect("json");
        let tree = &nulled["tree"];
        assert_eq!(tree["documents"], serde_json::json!({"a": 1}));
        assert_eq!(tree["staged"], serde_json::json!({"b": 2}));
        assert_eq!(tree["missing"], serde_json::json!({"c": "unparsed"}));
        assert_eq!(tree["records"], serde_json::json!({"runs": ["row\tx"]}));
        for live in ["git-head", "forge", "unheard-of"] {
            assert!(tree[live].is_null(), "{live} is nulled");
        }
    }

    #[test]
    fn the_committed_rules_partition_by_what_they_read() {
        // THE PROPERTY OVER THE ROWS THAT SHIP. Every committed row lands on one
        // half; a tree row declares only tree facts and is a kind that cannot
        // spawn; and the split buys something — some rows are tree.
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml"),
        )
        .expect("the committed authority reads");
        let table: toml::Table = toml::from_str(&text).expect("the committed authority parses");
        let rows: Vec<Rule> = table
            .get("rule")
            .and_then(toml::Value::as_array)
            .expect("the authority declares rows")
            .iter()
            .map(|value| {
                value
                    .clone()
                    .try_into()
                    .expect("a committed row deserialises")
            })
            .collect();
        let keyed = ["origin/main".to_owned()];
        let mut tree = 0;
        for rule in &rows {
            match rule.half(None, &keyed) {
                Half::Tree => {
                    tree += 1;
                    // The one spawning kind a tree row may be: the secrets
                    // scanner, pinned by a checksum the authority itself keys.
                    assert!(
                        !rule.kind.carries_ambient_authority() || rule.kind == RuleKind::Secrets,
                        "{}",
                        rule.id
                    );
                    assert_ne!(
                        rule.kind,
                        RuleKind::Policy,
                        "{}: no bundle is live",
                        rule.id
                    );
                    assert!(
                        rule.census_facts()
                            .all(|fact| fact.subject() == Subject::Tree),
                        "{}",
                        rule.id
                    );
                }
                Half::Live => {}
            }
        }
        assert!(
            tree > 0,
            "no committed row is tree, so the split would buy nothing"
        );
    }

    /// Fails by: a token count carried on a comment or string span, or missed
    /// on the `fn` a reader would be served.
    #[test]
    fn only_a_rust_fn_unit_carries_its_token_count() {
        let crate::facts::Look::Is(nodes) =
            super::rust_units("a.rs", "// lead\nfn f() { let s = \"hi\"; }\n")
        else {
            panic!("parses");
        };
        let (fns, spans): (Vec<_>, Vec<_>) = nodes.iter().partition(|node| node["kind"] == "fn");
        assert_eq!(fns.len(), 1);
        assert!(
            fns[0]["counts"]["tokens"].as_u64().is_some_and(|n| n > 0),
            "{}",
            fns[0]
        );
        assert!(
            !spans.is_empty(),
            "the premise: a comment and a string span"
        );
        for span in spans {
            assert!(span["counts"]["tokens"].is_null(), "{span}");
        }
    }
}
