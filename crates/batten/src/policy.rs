//! The policy evaluator: an enabled bundle decides over the resolved facts
//! (CLOUD-647, CLOUD-689, CLOUD-837).
//!
//! # Why a second language at all
//!
//! [`crate::rules::run`] is a flat loop and no row consumes another row's
//! verdict, so a predicate over *relationships between facts* is not expressible
//! as a row. The layer this engine is absorbing shows the price: 57 of 126
//! `mise-tasks` compose over a sibling's exit code — a three-state channel — so a
//! consumer that needs the producer's structure re-derives it. The measured
//! instance is `graph-check` spawning `ready-lint`, the one program that parses a
//! Ready block and names every key it cites, and then re-spelling the issue-key
//! regex three times anyway.
//!
//! This module is not here to write shorter predicates than Rust would. It is
//! here so one composed rule set decides from one fact set, instead of the same
//! predicate being re-derived per consumer.
//!
//! **That sentence was false for as long as it stood, and CLOUD-837 made it
//! true.** `Engine::new()` sat inside `load`'s loop, so every registered module
//! got its own isolated evaluator: there was no composed rule set, there were N
//! isolated ones, and nothing could reach across them. Two predicates needing
//! the same path normalisation had to define it twice — the defect this section
//! opens by decrying, rebuilt in a second language. The unit is the [`Bundle`]
//! now: one engine, `add_policy` once per file into it, one compile.
//!
//! Bundles stay isolated from *each other*, which is the other half of the same
//! decision: a vendored preset cannot silently supply a helper an in-repo module
//! depends on, and a consumer's module cannot shadow a preset's internals.
//! Cross-bundle id collisions are still caught, because [`load`] sees every
//! declared id set regardless of which engine holds it.
//!
//! # The bound is the fact set, and it is why facts came first
//!
//! [`crate::rules::Authority`] is the axis CLOUD-763 re-decided `scopes` on, and
//! a policy row is [`crate::rules::Authority::Supplied`]: the module is a pure
//! function over the input document. It cannot open a file, start a process, or
//! reach the network — the workspace manifest pins `default-features = false`
//! precisely so `http` and `jsonschema` never enter the closure.
//!
//! **Two mechanisms keep that from drifting, and until CLOUD-831 there were
//! zero.** This paragraph cited a test named `no_evaluator_feature_admits_io`
//! that did not exist — one grep hit, and it was this comment making the claim
//! (CLOUD-589's class, on the highest-consequence claim in the crate). Both
//! halves are real now, and they answer different questions:
//!
//! * `no_evaluator_feature_admits_io` in `crates/batten/tests/policy_modules.rs`
//!   is the BEHAVIOURAL half: it hands [`deny`] a module invoking `http.send`
//!   and asserts it does not answer. That asks *can a module reach the network*
//!   rather than testing a string in a manifest, so it stays true when the
//!   feature arrives by Cargo's cross-graph feature unification rather than by
//!   an edit. Shown able to fail under `--features probe-evaluator-io`.
//! * `mise-tasks/evaluator-closure-check.sh`, wired as `batten.toml`'s
//!   `evaluator-closure-io-free` row, is the CLOSURE half: it walks the resolved
//!   graph from the `regorus` node and refuses any of the nine IO-bearing crates
//!   the manifest names becoming reachable.
//!
//! Neither subsumes the other. The first would still pass if an IO crate entered
//! the closure behind a builtin nothing calls; the second would still pass if a
//! future evaluator gained IO with no new dependency.
//!
//! That is the whole argument for admitting consumer-authored code to the
//! mediated call. A [`crate::rules::RuleKind::Command`] row spawns a process with
//! the calling user's authority and can acquire anything; a module sees the
//! fields the boundary resolved and acquires nothing. "Consumer-authored" was
//! only ever a proxy for "ambient authority", and this kind separates them.
//!
//! # Deny-only, structurally
//!
//! Only the module's `deny` set is read. There is no spelling here for an allow,
//! which does two things at once: it preserves §8's raise-only invariant for a
//! new surface, and it removes the allow/deny contradiction class **by
//! construction** rather than by detecting it later. A consumer cannot author a
//! module that weakens a gate, because the shape that would weaken one does not
//! exist.
//!
//! # Refused at load, never at adjudication
//!
//! Regorus reports a rule conflict or a recursion at **evaluation**, not at
//! `add_policy` — five cases, measured on 0.11.0. On the mediated path that is
//! the worst possible time and the wrong exit class: house style §8 wants a
//! config fault refused by `config lint` / `doctor`, so [`load`] compiles every
//! module and drives a smoke query at load time, where a fault is a config error
//! rather than a denied tool call.
//!
//! # Three-valued
//!
//! A module that cannot be evaluated is [`crate::facts::Look::CouldNotLook`],
//! never an empty deny set. An extraction that returns nothing must not read as
//! agreement — CLOUD-251's vacuous pass, which is exactly the failure this
//! surface could rebuild.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Result;
use crate::error::UsageError;
use crate::facts::Look;
use crate::rules::{Rule, RuleKind};

/// The unattributed deny set: a set of bare strings, and the shape CLOUD-689
/// shipped.
///
/// Fixed rather than configurable: what a policy row decides must be the same
/// question for every module, or a reviewer reading `batten.toml` cannot tell
/// what a row does without opening the module.
///
/// **Kept unchanged, and that is CLOUD-832's whole back-compatibility claim.** A
/// bare string here yields a [`Violation`] whose `rule` is `None`, attributed to
/// the registering row exactly as before, so the existing fixture and its tests
/// pass untouched.
/// The one query, and the package prefix it is rooted at.
///
/// **Fixed rather than configurable, and that reasoning is kept**: what a policy
/// row decides must be the same question for every module, or a reviewer reading
/// `batten.toml` cannot tell what a row does without opening the module.
///
/// What CLOUD-837 changed is the LEVEL it is pinned at. This was
/// `data.batten.deny`, which fixed both halves — and the comment above it
/// claimed "the package is the consumer's; the rule name is Batten's" while the
/// constant said the opposite. The fixtures confirmed the constant won: every
/// test module declared `package batten`, and `package batten.git`,
/// `batten.ci`, `batten.board` were unreachable. For a bundle that meant no
/// namespacing at all — 79 predicates in one flat namespace, and by
/// [`Bundle`]'s own reason unable to share anything across it either.
///
/// So the PREFIX is Batten's and the sub-package is the consumer's, and what
/// stays fixed is the three rule names below.
const PACKAGE_QUERY: &str = "data.batten";

/// The unattributed deny set: a set of bare strings, and the shape CLOUD-689
/// shipped.
///
/// **Kept unchanged, and that is the back-compatibility claim.** A bare string
/// here yields a [`Violation`] whose `rule` is `None`, attributed to the
/// registering row exactly as before, so the existing fixture and its tests pass
/// untouched.
const DENY_RULE: &str = "deny";

/// The attributed deny set — Conftest's `violation` shape (CLOUD-832).
///
/// ```text
/// violation contains {"rule": "no-stray-artifact", "msg": "a tracked build product"} if {
///   some p in input.tree.tracked
///   endswith(p, ".o")
/// }
/// ```
///
/// This is what lets one module carry many *identified* predicates. Without it a
/// bundle collapses every predicate it holds into one rule id, one severity and
/// one waiver target — attribution dies (every finding names the bundle rather
/// than the gate), severity flattens, and `mise run mutant` cannot be satisfied
/// at all, because a single id has no per-gate mutation to declare.
///
/// Read *alongside* [`DENY_RULE`] rather than replacing it: this is additive.
const VIOLATION_RULE: &str = "violation";

/// The ids a module publishes — a set of strings.
///
/// ```text
/// rules contains "no-stray-artifact"
/// ```
///
/// **The id set must be declarable or waivers and `mutant` have nothing to
/// name.** A `[[waiver]]` naming an id no module declares becomes reportable
/// (CLOUD-208's dead-waiver diagnostic, for free), and a `violation` carrying an
/// id its module never published is refused rather than silently attributed.
///
/// Reading this is reading an *enabled* artifact, not discovering an authority,
/// so house style §8 is untouched.
const RULES_RULE: &str = "rules";

/// The key a `violation` names its declared class under (CLOUD-1050).
///
/// Held to `verdict.rs`'s registry by [`check_verdicts_are_declared`], and to
/// the schema by `rules-drift`, so the three spellings of this one name cannot
/// drift apart.
const VERDICT_KEY: &str = "verdict";

/// The key a `violation` used to name its prose under, and no longer may.
///
/// Kept as a constant rather than deleted with the field, because the load-time
/// refusal has to be able to NAME the thing it is refusing — a module carrying
/// this key gets told which key, which is what makes the migration one edit
/// rather than a hunt.
const RETIRED_MSG_KEY: &str = "msg";

/// One denial a module produced: the predicate that fired, the class it fired
/// under, and what it points at.
///
/// `rule` is `Option` and the two arms are the two shapes, not a convenience:
/// `None` is a bare token from [`DENY_RULE`], attributed to the registering
/// row; `Some` is a [`VIOLATION_RULE`] entry naming a predicate the module
/// published. [`Bundle::attribute`] is the one place that collapses them, so no
/// caller re-derives the fallback and gets it differently.
///
/// # `verdict` replaced `msg`, and that is CLOUD-1050's whole content
///
/// The field this carried was the module's own **prose**. Nothing could check
/// it: a refusal could name no remedy, name a task that does not exist, offer an
/// override with no precondition, or spell one concept nineteen ways, and every
/// one of those passes a `String`. So the class is a **token** declared in
/// [`crate::verdict`], where the prose lives once and a gate can read it, and
/// the pointers are [`crate::verdict::Subject`]s — tagged, ordered, and
/// structurally incapable of carrying a payload (non-negotiable rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The predicate id, when the module named one.
    pub rule: Option<String>,
    /// The declared class this refusal belongs to.
    pub verdict: String,
    /// What it points at, in the order the module gave them.
    pub subjects: Vec<crate::verdict::Subject>,
}

/// Every vendored preset: its name, and the modules it ships.
///
/// # Why Batten ships defaults at all
///
/// A consumer adopting Batten got an empty `batten.toml` and had to author every
/// predicate from scratch, which is the anomaly rather than the discipline —
/// Conftest ships OCI bundles, Semgrep `p/default`, `ESLint`'s `recommended`,
/// Clippy its lint groups. And the non-negotiable that looks like it forbids
/// this argues *for* it: "adopt prior art; don't expand the core". A preset is
/// prior art shipped **as data**, which is the opposite of expanding the core.
///
/// # Why this is not the OCI distribution CLOUD-129 rejected
///
/// That verdict was about *remote policy fetch* being a supply-chain surface,
/// and it is intact. There is no network here, no registry and no
/// trust-on-first-use: `include_str!` at build time, so the bytes ship inside
/// the binary the operator already trusts, under the same checksum as everything
/// else in it. Its other ground — one committed authority per repo — does not
/// reach a preset either, because **a preset is not an authority; it is content
/// the authority enables.**
///
/// # Rule 1 lives here, and this is the most inviting place in the crate to
/// break it
///
/// The temptation is to vendor *this repository's* gates. A preset may contain
/// predicates true of a **practice** — trunk-based branching, commit shape — and
/// never one naming a path, a task, a tracker key or an entity. The mechanism
/// is not new prose: `batten.toml`'s rule-1 `forbid` rows glob `crates/**`, and
/// these sources are under it, so they are already scanned on every gate
/// invocation. `presets_are_inside_the_rule_one_glob` asserts that coverage
/// rather than leaving it to be true by accident.
///
/// # One list, derived
///
/// The valid name set is [`preset_names`], read off this table — never a
/// hand-maintained second list, which is `surface::SURFACE`'s discipline and the
/// reason a preset cannot be enabled that does not exist.
const PRESETS: &[(&str, &[(&str, &str)])] = &[
    (
        "commit-hygiene",
        &[(
            "<preset:commit-hygiene>/no-empty-commit.rego",
            include_str!("policy/presets/commit-hygiene/no-empty-commit.rego"),
        )],
    ),
    (
        "trunk-based",
        &[(
            "<preset:trunk-based>/no-force-push.rego",
            include_str!("policy/presets/trunk-based/no-force-push.rego"),
        )],
    ),
    // The first TREE-scoped preset (CLOUD-864). The two above judge a command;
    // this one judges files, which is why it is the one that needed `lines` to
    // reach paths by glob — a practice about 143 files cannot be a row that
    // names 143 paths.
    (
        "shell-hygiene",
        &[
            (
                "<preset:shell-hygiene>/shebang-names-its-language.rego",
                include_str!("policy/presets/shell-hygiene/shebang-names-its-language.rego"),
            ),
            (
                "<preset:shell-hygiene>/sibling-resolves.rego",
                include_str!("policy/presets/shell-hygiene/sibling-resolves.rego"),
            ),
        ],
    ),
];

/// Every vendored preset's name, in a stable order.
///
/// Derived from [`PRESETS`] so the binary and the published schema cannot
/// disagree about what may be enabled — the same discipline `surface::SURFACE`
/// carries, and the reason an unknown name is a config error rather than a
/// silent no-op.
#[must_use]
pub fn preset_names() -> Vec<&'static str> {
    PRESETS.iter().map(|(name, _)| *name).collect()
}

/// The modules a named preset ships, or `None` when nothing ships under that
/// name.
///
/// The pointer paths are `<preset:name>/…` rather than a filesystem path,
/// deliberately: a preset has no path in the consumer's tree, and printing one
/// would send a reader looking for a file that is not there. A finding still
/// names the PREDICATE rather than this, so it stays indistinguishable in shape
/// from an in-repo one.
fn preset_modules(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    PRESETS
        .iter()
        .find(|(preset, _)| *preset == name)
        .map(|(_, modules)| *modules)
}

/// One module inside a bundle: its repository-relative path, and nothing else.
///
/// **It no longer holds an engine, and that is CLOUD-837's whole change.**
/// `Engine::new()` used to sit inside `load`'s loop, so every registered module
/// got its own isolated evaluator. There was therefore no composed rule set —
/// there were N isolated ones, and nothing could reach across them: two
/// predicates needing the same path normalisation had to define it twice, which
/// is *verbatim the defect this module's own doc opens by decrying*. CLOUD-647's
/// evidence table already counts the live instance in the layer being replaced —
/// nine re-derived copies of the issue-key regex, already diverged in
/// case-sensitivity — and per-module isolation rebuilds exactly that, in a second
/// language.
///
/// What survives here is the pointer. A parse diagnostic names a file, and a
/// bundle that fails to compile has to say which of its modules did.
///
/// The **source is not a field**: nothing downstream may render a policy body,
/// and the cheapest way to keep that true is to give it nowhere to live past
/// compilation (rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    /// The repository-relative path, for the pointer in a finding.
    path: String,
}

impl Module {
    /// The module's repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One enabled bundle: **one engine**, the modules that compiled into it, and
/// the predicate ids they publish (CLOUD-837).
///
/// # One engine per bundle, not per module
///
/// `add_policy` is called once per file into the shared engine and the bundle
/// compiles once. This is how Conftest and OPA load a policy directory, and it
/// is what makes a helper defined in one module callable from another — the
/// property that stops 79 predicates re-deriving the same path test 79 times.
///
/// # Bundles stay isolated from each other
///
/// A vendored preset is its own bundle with its own engine, never merged into a
/// consumer's. So a preset cannot silently supply a helper an in-repo module
/// depends on, and a consumer's module cannot shadow a preset's internals.
/// Cross-bundle *id* collision stays detectable regardless, because [`load`]
/// sees every declared id set no matter which engine holds it (CLOUD-832).
///
/// # What this cost, measured rather than assumed
///
/// The published `wired` figure of 8.4ms was taken at **N = 1**, and a
/// 79-predicate bundle had never been priced at all — the same class of unpriced
/// per-call multiplication CLOUD-460 measured when one `receipt` row cost every
/// mediated call four git subprocesses. Re-measured on the pinned toolchain,
/// release profile, 200 warm iterations per point:
///
/// ```text
/// N=  1  load=  0.57ms  per-call=    39us      <- the baseline the 8.4ms figure was taken at
/// N= 10  load=  0.84ms  per-call=   270us
/// N= 40  load=  3.15ms  per-call=  1065us
/// N= 79  load=  5.83ms  per-call=  2150us
/// ```
///
/// **Per-call cost is still proportional to the predicate count, and saying so
/// is the point.** One engine per bundle removed N `Engine::new()` calls and N
/// `engine.clone()` calls per adjudication; it did not and could not make
/// evaluation flat, because a query over `data.batten` reaches every rule in the
/// package. Reporting this as "composition made it cheap" would be the same
/// mistake the 8.4ms figure invited — a number taken at one N and quoted at
/// another.
///
/// At the realistic end that is ~2.2ms against the 100ms ceiling, so the surface
/// is affordable; what the numbers say is that the budget is spent on
/// *predicates*, and a bundle that grows past a few hundred is the thing to
/// measure again rather than assume.
///
/// # Attribution is structural now, not convenient
///
/// With one engine there is no "which module answered" to report, because the
/// engine is the unit. A finding's pointer therefore comes from the violation's
/// own `rule` id — which is why CLOUD-832 had to land first, and is the
/// strongest form of that row's argument.
pub struct Bundle {
    /// The `id` of the [`RuleKind::Policy`] row that enabled this bundle.
    id: String,
    /// The modules compiled into this bundle's engine, in load order.
    modules: Vec<Module>,
    /// The predicate ids the bundle's modules published through [`RULES_RULE`].
    ///
    /// Read at load, once, and never re-queried: it is what a `violation`'s
    /// `rule` is checked against and what a `[[waiver]]` is judged reachable
    /// against. `BTreeSet` so the collision refusal names ids in a stable order —
    /// §6's byte-stability reaches a config error's text too.
    declared: BTreeSet<String>,
    /// The one compiled evaluator, ready to take an input document.
    engine: regorus::Engine,
}

impl Bundle {
    /// The enabling rule's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The modules compiled into this bundle.
    #[must_use]
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    /// The predicate ids this bundle publishes.
    #[must_use]
    pub fn declared(&self) -> &BTreeSet<String> {
        &self.declared
    }

    /// The pointer a bundle-level diagnostic is reported against: its first
    /// module's path, or the enabling row's id when it holds none.
    ///
    /// One accessor rather than the expression re-derived per call site, for
    /// [`Bundle::attribute`]'s reason — two spellings of a pointer send two
    /// readers to two places for one fault.
    #[must_use]
    pub fn pointer(&self) -> &str {
        self.modules
            .first()
            .map_or(self.id.as_str(), |module| module.path.as_str())
    }

    /// The id a denial is reported under: the predicate's own when it named one,
    /// the enabling row's otherwise.
    ///
    /// **One place, deliberately.** Severity resolution, `[[waiver]]`
    /// suppression, `Refusal::new` and a tree `Finding`'s `rule` field all need
    /// this fallback, and four spellings of it is how a waiver ends up
    /// suppressing something a finding does not name. It is also what makes a
    /// vendored preset's denial and an in-repo one indistinguishable in a
    /// finding: neither carries a category, both carry an id.
    #[must_use]
    pub fn attribute<'a>(&'a self, violation: &'a Violation) -> &'a str {
        violation.rule.as_deref().unwrap_or(&self.id)
    }
}

impl std::fmt::Debug for Bundle {
    /// Names the row, its modules' paths and the ids they publish — and **never
    /// a source**, so a policy body cannot reach a log through a derived `Debug`
    /// (rule 4). Inherited from `Module`'s hand-written one rather than
    /// re-derived, which is the requirement CLOUD-837 §5 states outright.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("id", &self.id)
            .field("modules", &self.modules)
            // The published ids are POINTERS — the same class as a rule id in a
            // finding — so they are admissible here where a body never is. They
            // are also the field a reader debugging an attribution question
            // actually wants.
            .field("declared", &self.declared)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Bundle {
    /// Equality is the **enablement**, never the compiled engine.
    ///
    /// `regorus::Engine` has no meaningful equality, and it does not need one:
    /// [`load`] refuses two rows enabling one module, so within a resolved
    /// policy the `(id, modules)` pair determines the bundle. Comparing that is
    /// what a caller asking "is this the same policy?" actually means —
    /// `Policy` derives `PartialEq` for exactly that question.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.modules == other.modules
    }
}

impl Eq for Bundle {}

impl Clone for Bundle {
    /// Written out rather than derived so the `Debug` above cannot be silently
    /// re-derived alongside it, which would put a policy body back in reach of a
    /// log (rule 4).
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            modules: self.modules.clone(),
            declared: self.declared.clone(),
            engine: self.engine.clone(),
        }
    }
}

/// Every `Engine::new()` this process has performed.
///
/// A **counter, not a timing assertion**, and CLOUD-837 §7 says why: the claim
/// is "N modules yield one engine", and a wall-clock measurement of that
/// discriminates nothing — engine construction is cheap enough that a
/// per-module implementation and a per-bundle one are indistinguishable on a
/// clock, which is exactly how the N-linear cost went unmeasured for as long as
/// it did.
///
/// Read it with [`engines_constructed`], around a single [`load`] call. The
/// count is process-global, so a test asserting a delta must be the only thing
/// building engines in its process — `tests/policy_engine_count.rs` is its own
/// binary for that reason.
static ENGINES_CONSTRUCTED: AtomicUsize = AtomicUsize::new(0);

/// The one place an evaluator is constructed.
///
/// Funnelled through a single function so [`ENGINES_CONSTRUCTED`] cannot be
/// bypassed by a second `Engine::new()` appearing elsewhere — the counter would
/// then under-report, and a gate that under-reports is worse than none.
fn new_engine() -> regorus::Engine {
    ENGINES_CONSTRUCTED.fetch_add(1, Ordering::Relaxed);
    regorus::Engine::new()
}

/// How many evaluators this process has constructed.
///
/// Exposed for the construction-count assertion described on
/// [`ENGINES_CONSTRUCTED`]. Monotonic: callers take a delta.
#[must_use]
pub fn engines_constructed() -> usize {
    ENGINES_CONSTRUCTED.load(Ordering::Relaxed)
}

/// The declared vocabulary a policy module reads: named patterns, and the
/// refusal classes it may raise.
///
/// **One parameter rather than two**, and that is a decision rather than
/// packaging. Both tables are config the consumer declares, both are fixed for
/// the life of the load, both are projected into the evaluator's `data`
/// document, and both are read by exactly the same call sites — so a caller that
/// has one always has the other. Threading them separately would have added a
/// fifth positional argument to every scan entry point and its ~50 call sites,
/// which is how a signature nobody can read at a call site gets built one
/// well-motivated parameter at a time.
#[derive(Debug, Clone, Copy)]
pub struct Vocabulary<'a> {
    /// The `[[pattern]]` table (CLOUD-885).
    pub patterns: &'a [crate::pattern::NamedPattern],
    /// The `[[verdict]]` table (CLOUD-1050).
    pub verdicts: &'a [crate::verdict::DeclaredVerdict],
    /// The `[[recorder]]` table (CLOUD-1051).
    ///
    /// Here for the reason stated above rather than as a third thing bolted on:
    /// it is config the consumer declares, fixed for the life of the load, and
    /// read at exactly the call sites that already hold this — the record a
    /// module reads is projected from it, so a caller with the patterns always
    /// has the recorders too. The alternative was a fifth positional on four
    /// public entry points, which is the shape this parameter exists to prevent.
    pub recorders: &'a [crate::recorder::Declared],
}

impl Vocabulary<'_> {
    /// A consumer declaring neither table.
    ///
    /// Not the same as "no vocabulary at all": this binary's vendored classes
    /// are unioned in at load, so a preset still loads and a native refusal
    /// still resolves. What is empty here is the CONSUMER's half.
    pub const EMPTY: Vocabulary<'static> = Vocabulary {
        patterns: &[],
        verdicts: &[],
        recorders: &[],
    };
}

impl<'a> From<&'a crate::config::Config> for Vocabulary<'a> {
    fn from(config: &'a crate::config::Config) -> Self {
        Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        }
    }
}

/// Whether a `load` re-derives the AST-borne config checks.
///
/// **A placement decision, and it was measured rather than reasoned.** The two
/// checks below read a module's AST through `Engine::get_ast_as_json`, which
/// serialises every rule of every module in the bundle. Their answer is a
/// property of the module TEXT, so it is identical on every surface and fixed
/// for the life of the load — but `hook` calls `load` once per mediated call,
/// so running them there re-derives a constant answer inside CLOUD-689's 100ms
/// budget. CI measured the cost as `wired` p50 14.03ms -> 22.98ms, a 1.638x
/// regression against a 1.30x gate, on a branch whose local `verify` was green.
///
/// So they run where a config fault is REPORTED — `check`, `enforce`, `config
/// lint`, `doctor` — which is house style §8's placement independently of the
/// cost, and never on the adjudication path. A module with an inline pattern is
/// refused by this repository's own gate chain exactly as a `no-docs-tree`
/// violation is; what the mediated call must do is load and decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleChecks {
    /// Run the AST checks, but NOT registry equality's exhausted half
    /// (CLOUD-1051).
    ///
    /// For a run the caller narrowed with `check --rule`. "Is every declared
    /// `[[verdict]]` row raised by something" is a property of the AUTHORITY, and
    /// a one-row selection would answer it with every other module's classes
    /// reported as unemitted — measured the first time `--rule` ran: twenty-six
    /// tokens named, none of them the caller's business. A selection must not be
    /// able to change a verdict about the config, so this variant asks the
    /// questions that are about the MODULES that loaded and leaves the one that
    /// is about the table to the unnarrowed run every `verify` already does.
    RunOverSelection,
    /// Re-derive them: the caller is a surface that reports config faults.
    Run,
    /// Skip them: the caller is the mediated path, where the answer is already
    /// known and the budget is per call.
    SkipOnHotPath,
}

/// Load, compile and smoke-test every module the rule set registers.
///
/// Boundary I/O, called once per process from the config resolution path — never
/// from [`crate::hook::adjudicate`], which is contractually pure.
///
/// `reference` is the `--config-from` ref when one is in play. It is not
/// optional politeness: the module has to come from the same place the rules
/// did, or a base-ref comparison reads the working tree's predicates.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when a row registers no module, when the file is
/// absent or unreadable, when it does not compile, or when the smoke query
/// faults. Every one of those is a config error at load rather than a surprise
/// at the gate, which is the whole reason this function drives a query it throws
/// away.
pub fn load(
    root: &Path,
    rules: &[Rule],
    vocabulary: Vocabulary<'_>,
    checks: ModuleChecks,
    reference: Option<&str>,
) -> Result<Vec<Bundle>> {
    let Vocabulary {
        patterns,
        verdicts,
        recorders: _,
    } = vocabulary;
    // The table is validated at PARSE, beside `verbs` and `redirects` and for
    // their reason (`config.rs`'s `VALIDATED_AT_LOAD` census asserts the call
    // site exists). Validating again here would be a second authority for one
    // question, which is the shape `rules-drift` exists to refuse.
    let pattern_data = crate::pattern::data_document(patterns);
    let declared_patterns: BTreeSet<&str> = patterns.iter().map(|p| p.id.as_str()).collect();
    // The refusal vocabulary (CLOUD-1050): the consumer's rows unioned with what
    // this binary ships. The vendored half is not optional politeness — a
    // preset reaches a consumer who wrote no `[[verdict]]` row at all, so
    // holding it to their table would make an enabled preset unloadable with no
    // fix available.
    let registry = registry_for(verdicts)?;
    let mut emitted: BTreeSet<String> = BTreeSet::new();
    let mut bundles = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    // Every predicate id published so far, and the module that published it —
    // the value is what lets the collision refusal name BOTH sides, which is the
    // difference between a pointer and a complaint.
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for rule in rules.iter().filter(|r| r.kind == RuleKind::Policy) {
        // `validate` already refuses a policy row naming none of the three
        // sources, and one naming more than one; this is the located
        // restatement, so a caller reaching `load` directly cannot get a silent
        // skip instead of a refusal.
        let source_key = rule
            .module
            .as_deref()
            .or(rule.bundle.as_deref())
            .or(rule.preset.as_deref())
            .ok_or_else(|| {
                UsageError::raise(format!(
                    "rule `{}` is a policy row naming neither `module`, `bundle` nor `preset`",
                    rule.id
                ))
            })?;
        // Two rows naming one source is dead config: the second enablement
        // decides nothing the first did not, and "which one denied me" is not a
        // question a reviewer should have to answer.
        if !seen.insert(source_key) {
            return Err(UsageError::raise(format!(
                "rule `{}` registers `{source_key}`, which another rule already registers",
                rule.id
            )));
        }

        // The module comes from wherever the RULES came from, and that is the
        // whole of this branch. Under `--config-from <ref>` the authority is
        // read from the ref (`trust::load_base`), so reading the module off disk
        // would pair a base's rules with the working tree's predicates — and an
        // agent editing an enabled `.rego` would change what the BASE policy
        // decides. That is exactly the influence `--config-from` exists to
        // exclude, and it is CLOUD-243's shape on the surface where it bites
        // hardest.
        //
        // `git::show` is the gix-backed reader CLOUD-718 hardened, and it takes
        // the path as data rather than interpolating it into an argv.
        //
        // A `Vec` because the unit is the BUNDLE: today a row names one file,
        // and the moment a row can name a folder this is the only line that
        // changes. Writing it as a scalar is how per-module isolation got built
        // the first time.
        //
        // A `bundle` row enumerates the `.rego` files under its root; a `module`
        // row is the one-file case. **Enumeration inside an explicitly enabled
        // folder is not the implicit discovery §8 forbids** — the authority
        // names the root, nothing merges, and every module is deny-only by
        // construction, so the set can only ADD refusals.
        // A PRESET IS READ FROM THE BINARY, not from the tree, which is the whole
        // of its supply-chain claim: no network, no registry, no
        // trust-on-first-use, and nothing for `--config-from` to disagree about
        // because the bytes are the same at every ref this binary is run at.
        //
        // An unknown name is a config error rather than a silent no-op — a
        // consumer who enabled `trunk-basd` should be told, not quietly gated by
        // nothing.
        if let Some(name) = rule.preset.as_deref() {
            let modules = preset_modules(name).ok_or_else(|| {
                UsageError::raise(format!(
                    "rule `{}` enables the preset `{name}`, which this binary does not ship; \
                     the ones it does are {}",
                    rule.id,
                    preset_names().join(", ")
                ))
            })?;
            let sources: Vec<(String, String)> = modules
                .iter()
                .map(|(path, source)| ((*path).to_owned(), (*source).to_owned()))
                .collect();
            let bundle = compile(&rule.id, &sources, &pattern_data)?;
            let declared = bundle.declared.clone();
            check_predicate_severity(rule, &declared, source_key)?;
            // A PRESET IS A MODULE TOO, and this branch's `continue` skipped the
            // tree-key check when it first landed. A tree-scoped row may name a
            // preset, so a preset reading an unemittable `input.tree` key would
            // have loaded as a dead gate — the exact failure the check exists to
            // refuse, arriving through the one source that bypasses it.
            if checks != ModuleChecks::SkipOnHotPath {
                check_tree_paths_are_emittable(rule, &bundle, source_key)?;
                check_no_inline_regex(rule, &bundle, &declared_patterns, source_key)?;
                check_verdicts_are_declared(rule, &bundle, &registry, source_key)?;
                emitted.extend(emitted_verdicts(&bundle));
            }
            claim_ids(&mut ids, &declared, source_key)?;
            bundles.push(bundle);
            continue;
        }

        let paths = match (rule.module.as_deref(), rule.bundle.as_deref()) {
            (Some(module), _) => vec![module.to_owned()],
            (None, Some(bundle)) => bundle_members(root, bundle, reference, &rule.id)?,
            (None, None) => Vec::new(),
        };
        let sources = read_sources(root, &paths, reference, &rule.id, checks)?;

        // EVERYTHING PAST THE READ IS PURE, and the split is what lets the
        // composition property be tested without a filesystem: `compile` builds
        // one engine from N sources, which is the whole of CLOUD-837.
        let bundle = compile(&rule.id, &sources, &pattern_data)?;
        let declared = bundle.declared.clone();

        // The pointer a bundle-level fault is reported against.
        let where_it_came_from = source_key;

        check_predicate_severity(rule, &declared, where_it_came_from)?;

        if checks != ModuleChecks::SkipOnHotPath {
            check_tree_paths_are_emittable(rule, &bundle, where_it_came_from)?;
            check_no_inline_regex(rule, &bundle, &declared_patterns, where_it_came_from)?;
            check_verdicts_are_declared(rule, &bundle, &registry, where_it_came_from)?;
            emitted.extend(emitted_verdicts(&bundle));
        }

        claim_ids(&mut ids, &declared, where_it_came_from)?;

        bundles.push(bundle);
    }

    if checks == ModuleChecks::Run {
        check_registry_is_exhausted(verdicts, &emitted)?;
    }
    Ok(bundles)
}

/// Read one row's declared module text, from the working tree or from a ref.
///
/// Split out of [`load`] when the hot-path strip below pushed that function past
/// the line ceiling, and the seam is where the I/O already was: everything past
/// this read is pure, which is what lets [`compile`]'s composition property be
/// tested without a filesystem.
fn read_sources(
    root: &Path,
    paths: &[String],
    reference: Option<&str>,
    rule_id: &str,
    checks: ModuleChecks,
) -> Result<Vec<(String, String)>> {
    let mut sources = Vec::new();
    for path in paths {
        let source = match reference {
            Some(reference) => crate::git::show(root, reference, path).map_err(|_| {
                UsageError::raise(format!(
                    "rule `{rule_id}` registers `{path}`, which is absent at {reference}"
                ))
            })?,
            None => std::fs::read_to_string(root.join(path)).map_err(|_| {
                UsageError::raise(format!(
                    "rule `{rule_id}` registers `{path}`, which cannot be read"
                ))
            })?,
        };
        // The hot path drops the module's own `test_` rules (CLOUD-1051):
        // nothing queries one, and evaluating them cost 25 ms per mediated call.
        // `policy test` and every checked load compile the full text.
        let source = if checks == ModuleChecks::SkipOnHotPath {
            without_test_rules(&source)
        } else {
            source
        };
        sources.push((path.clone(), source));
    }
    Ok(sources)
}

/// Drop a module's own `test_` rules before it reaches the hot path.
///
/// # 25 milliseconds per mediated call, measured
///
/// A module's `test_` rules are the LOAD-TIME tier: `batten policy test` runs
/// them and nothing else ever queries one. They were nonetheless compiled into
/// every bundle and evaluated with it, because `data.batten.deny` is answered by
/// evaluating the package — so every tool call paid for a suite that decides
/// nothing about that call.
///
/// Measured on the wired path, release binary, 40 runs: registering
/// `policy/stop-posture.rego` cost 28 ms, of which 1 ms was the registration and
/// **25 ms was its thirteen `test_` rules**, each running the module's own regex
/// scrub over a prose fixture. The same tax was already being paid by every
/// other mediated module, unnoticed because no branch had added one large enough
/// to cross `perf-compare`'s threshold.
///
/// # It strips a NAME, not a shape
///
/// A rule head begins at column zero — that is Rego's own layout, and the same
/// discriminator `rules.rs`'s case scanner already uses one layer over. So a
/// line starting `test_` at column zero opens a test rule, and everything up to
/// the next column-zero line that opens something else belongs to it.
///
/// **`ModuleChecks::SkipOnHotPath` is the only caller**, which is what keeps this
/// from being a way to lose a test: `policy test` compiles the full text, and so
/// does every load that runs the module checks. A stripped module is never the
/// one anything is graded against.
fn without_test_rules(source: &str) -> String {
    let mut kept = String::with_capacity(source.len());
    let mut dropping = false;
    for line in source.lines() {
        // A rule HEAD is at column zero; so is the `}` that closes its body, and
        // treating that brace as a new head is what made the first draft emit a
        // stray `}` and break the parse. A closing delimiter continues whatever
        // is open rather than opening anything.
        let opens_a_rule = !line.is_empty()
            && !line.starts_with([' ', '\t'])
            && !line.starts_with(['}', ']', ')']);
        if opens_a_rule {
            dropping = line.starts_with("test_");
        }
        if !dropping {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

/// Compose `sources` into **one** bundle: one engine, one compile, one smoke
/// query (CLOUD-837).
///
/// This is the composition half of [`load`], split from its I/O so the property
/// that matters can be tested without a filesystem — and so the loop that adds
/// modules to an engine has exactly one implementation.
///
/// `sources` is `(path, text)`. The path is the pointer a parse diagnostic
/// names; the text is dropped after `add_policy`, which is what keeps a policy
/// body out of reach of a log (rule 4).
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when any module fails to compile — **a malformed
/// module fails its whole bundle**, which is correct: a bundle is one rule set,
/// and half of one decides nothing coherent — when the bundle faults answering
/// the smoke query, when `rules` answers a shape that is not a set of ids, or
/// when a `violation` reachable on an empty document raises an id the bundle
/// does not declare.
pub fn compile(
    id: &str,
    sources: &[(String, String)],
    // The declared pattern table as a `data` document (CLOUD-885). Handed in
    // rather than read here, so `compile` stays a pure function of what it is
    // given and the one authority for the table remains `Config`.
    data: &serde_json::Value,
) -> Result<Bundle> {
    // ONE ENGINE FOR THE WHOLE BUNDLE. `add_policy` once per file into it, so
    // the bundle compiles once and a helper defined in one module is callable
    // from another. This is how Conftest and OPA load a policy directory, and
    // constructing the engine outside the loop is the entire fix: it used to sit
    // inside it, which is why there was no composed rule set to speak of.
    let mut engine = new_engine();
    // BEFORE `add_policy`, so a module compiled against the table cannot be
    // compiled against an empty one. An unusable data document is a config
    // fault at exit 1, not a silent empty map — a module reading
    // `data.batten.patterns["x"]` against an absent table gets UNDEFINED, and
    // Rego reads undefined as "this rule body does not hold", which is
    // CLOUD-251's vacuous pass with a regex in it.
    engine
        .add_data(
            regorus::Value::from_json_str(&data.to_string()).map_err(|err| {
                UsageError::raise(format!("the declared pattern table is not usable: {err}"))
            })?,
        )
        .map_err(|err| {
            UsageError::raise(format!(
                "the declared pattern table could not be loaded: {err}"
            ))
        })?;
    let mut modules = Vec::new();
    for (path, source) in sources {
        engine
            .add_policy(path.clone(), source.clone())
            .map_err(|err| UsageError::raise(format!("`{path}` does not compile: {err}")))?;
        modules.push(Module { path: path.clone() });
    }

    // The pointer a bundle-level fault is reported against: the first module,
    // because regorus's own diagnostics already name the offending file and this
    // is the fallback for the queries below, which are over the composed set
    // rather than over any one module.
    let pointer = sources
        .first()
        .map_or_else(|| id.to_owned(), |(path, _)| path.clone());

    // The smoke query, and it is the point of this function rather than a
    // precaution. Regorus reports a rule conflict and a recursion at EVALUATION;
    // without driving one here, the first thing that discovers a cyclic module
    // is a denied tool call, at the wrong time and in the wrong exit class.
    engine.set_input_json("{}").map_err(|err| {
        UsageError::raise(format!(
            "`{pointer}` rejected an empty input document: {err}"
        ))
    })?;
    let smoke = engine
        .eval_query(PACKAGE_QUERY.to_owned(), false)
        .map_err(|err| UsageError::raise(format!("`{pointer}` faults when evaluated: {err}")))?;

    // WHAT THE BUNDLE PUBLISHES, read once. A bundle whose modules carry no
    // `rules` rule publishes nothing, which is exactly the pre-CLOUD-832 module
    // and is not an error — it simply cannot use the attributed shape.
    let declared = collect_strings(&smoke, RULES_RULE).ok_or_else(|| {
        UsageError::raise(format!(
            "`{pointer}` answered `{RULES_RULE}` with a shape that is not a set of ids"
        ))
    })?;

    // An id a `violation` names and the bundle never published is a config error
    // HERE rather than a surprise at the gate — the same posture the smoke query
    // above takes, applied to attribution. This can only see the violations the
    // empty document reaches; `deny` treats an undeclared id met later as
    // could-not-look, because a denial this gate cannot attribute is not one it
    // can honestly report.
    for violation in collect_violations(&smoke).unwrap_or_default() {
        let Some(named) = violation.rule.as_deref() else {
            continue;
        };
        if !declared.contains(named) {
            return Err(UsageError::raise(format!(
                "`{pointer}` raises `{named}`, which it does not declare in `{RULES_RULE}`"
            )));
        }
    }

    Ok(Bundle {
        id: id.to_owned(),
        modules,
        declared,
        engine,
    })
}

/// Walk a `data.batten` result for every member named `rule_name`, at any depth,
/// and read its strings.
///
/// **This is what pins the RULE NAME rather than the package** (CLOUD-837). The
/// query is rooted at `data.batten` and this walk finds `deny`, `violation` and
/// `rules` wherever they sit under it — so `package batten.git`,
/// `package batten.ci` and `package batten.board` are all reachable, and 79
/// predicates need not share one flat namespace.
///
/// `None` is could-not-look at every call site, never "no denials": a member
/// whose value is neither a set nor an array decided nothing readable, and
/// guessing it is empty is CLOUD-251's vacuous pass.
fn collect_strings(results: &regorus::QueryResults, rule_name: &str) -> Option<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for value in package_members(results, rule_name) {
        match value {
            regorus::Value::Set(items) => {
                for item in items.iter() {
                    if let Ok(text) = item.as_string() {
                        found.insert(text.to_string());
                    }
                }
            }
            regorus::Value::Array(items) => {
                for item in items.iter() {
                    if let Ok(text) = item.as_string() {
                        found.insert(text.to_string());
                    }
                }
            }
            // Undefined is the ordinary shape of a package that has no rule of
            // this name at all, which is entirely valid — an empty contribution,
            // not an unreadable one.
            regorus::Value::Undefined => {}
            _ => return None,
        }
    }
    Some(found)
}

/// The same walk over [`DENY_RULE`], preserving order.
///
/// A `BTreeSet` would be wrong here: two predicates may legitimately produce the
/// same token, and collapsing them would under-report.
///
/// **Since CLOUD-1050 the strings on this channel are VERDICT TOKENS**, not
/// prose. That is what keeps the house-style-named `deny` root meaningful
/// without reopening the free-string hole: a bare member is a class with no
/// predicate id and no pointers, attributed to the enabling row, and it is held
/// to the registry exactly as an attributed one is.
fn collect_deny_messages(results: &regorus::QueryResults) -> Option<Vec<String>> {
    let mut messages = Vec::new();
    for value in package_members(results, DENY_RULE) {
        match value {
            regorus::Value::Set(items) => {
                for item in items.iter() {
                    if let Ok(text) = item.as_string() {
                        messages.push(text.to_string());
                    }
                }
            }
            regorus::Value::Array(items) => {
                for item in items.iter() {
                    if let Ok(text) = item.as_string() {
                        messages.push(text.to_string());
                    }
                }
            }
            regorus::Value::Undefined => {}
            _ => return None,
        }
    }
    Some(messages)
}

/// The `{"rule": …, "verdict": …, "subjects": […]}` members of every
/// `violation` under the package, or `None` for a shape this gate cannot read.
///
/// A member missing `verdict` is unreadable rather than unclassified: a refusal
/// with no declared class is the free string CLOUD-1050 retired, and admitting
/// one here would let the old shape back in through the decoder — which is the
/// half-migration that leaves two ABIs and a reader that accepts both. A member
/// missing `rule` is fine and falls back to the row, which is [`DENY_RULE`]'s
/// behaviour reached by a different spelling.
///
/// `subjects` is optional and defaults to empty: a class whose whole content is
/// "this tree, as a whole" has nothing to point at, and demanding a pointer
/// there would be satisfied by an invented one. A `subjects` that is present and
/// is NOT a list of readable shapes is could-not-look, because a module speaking
/// a dialect this decoder does not have is not a module reporting nothing.
fn collect_violations(results: &regorus::QueryResults) -> Option<Vec<Violation>> {
    let mut violations = Vec::new();
    for value in package_members(results, VIOLATION_RULE) {
        let items: Vec<&regorus::Value> = match value {
            regorus::Value::Set(items) => items.iter().collect(),
            regorus::Value::Array(items) => items.iter().collect(),
            regorus::Value::Undefined => continue,
            _ => return None,
        };
        for item in items {
            let object = item.as_object().ok()?;
            let verdict = object.get(&"verdict".into())?.as_string().ok()?;
            let rule = object
                .get(&"rule".into())
                .and_then(|value| value.as_string().ok())
                .map(std::string::ToString::to_string);
            let subjects = match object.get(&"subjects".into()) {
                None | Some(regorus::Value::Undefined) => Vec::new(),
                Some(raw) => read_subjects(raw)?,
            };
            violations.push(Violation {
                rule,
                verdict: verdict.to_string(),
                subjects,
            });
        }
    }
    Some(violations)
}

/// One violation's `subjects` array, or `None` for a shape this cannot read.
///
/// Goes through `serde_json` rather than walking `regorus::Value` by hand,
/// because [`crate::verdict::Subject::from_json`] is the ONE reader for this
/// shape and a second one here is how the two arms of `{path}` and
/// `{path, line}` end up ordered differently on two surfaces.
fn read_subjects(value: &regorus::Value) -> Option<Vec<crate::verdict::Subject>> {
    let items = match value {
        regorus::Value::Array(items) => items.iter().collect::<Vec<&regorus::Value>>(),
        // A SET is admitted as well as an array, because Rego's comprehension
        // over a set is the natural spelling and a module author should not have
        // to know which one the decoder prefers. Ordering is then the set's own,
        // which regorus keeps sorted — so §6 byte-stability holds either way.
        regorus::Value::Set(items) => items.iter().collect(),
        _ => return None,
    };
    let mut subjects = Vec::new();
    for item in items {
        let json = serde_json::to_value(item).ok()?;
        subjects.push(crate::verdict::Subject::from_json(&json)?);
    }
    Some(subjects)
}

/// Every value named `rule_name` anywhere under the queried package.
///
/// Recurses into object values, which is what a sub-package is in the `data`
/// document: `package batten.git`'s rules appear as `{"git": {"deny": …}}` under
/// `data.batten`. Only objects are descended into — a rule's own value is a set,
/// an array or a scalar, and treating one of those as a namespace would let a
/// module's DATA masquerade as a predicate.
fn package_members<'a>(
    results: &'a regorus::QueryResults,
    rule_name: &str,
) -> Vec<&'a regorus::Value> {
    let mut found = Vec::new();
    for result in &results.result {
        for expression in &result.expressions {
            descend(&expression.value, rule_name, &mut found);
        }
    }
    found
}

/// The recursive half of [`package_members`].
fn descend<'a>(value: &'a regorus::Value, rule_name: &str, found: &mut Vec<&'a regorus::Value>) {
    let Ok(object) = value.as_object() else {
        return;
    };
    for (key, child) in object {
        let Ok(name) = key.as_string() else {
            continue;
        };
        if name.as_ref() == rule_name {
            found.push(child);
        } else {
            // A sub-package, or a helper rule whose value happens to be an
            // object. Descending into the latter costs a walk and finds nothing,
            // which is cheaper than the alternative — asking regorus which
            // members are packages, a distinction the `data` document does not
            // carry.
            descend(child, rule_name, found);
        }
    }
}

/// Evaluate a bundle over an input document and return its denials.
///
/// Pure: no I/O, no environment, no clock. The engine was compiled at the
/// boundary and the input is data the caller already holds, which is what lets
/// this be called from [`crate::hook::adjudicate`]'s chain.
///
/// **One engine, one clone.** Before CLOUD-837 this cloned an engine per module
/// per mediated call, an N-linear cost on the 100ms path that had only ever been
/// measured at N = 1. A bundle clones once whatever it holds.
///
/// **Both shapes, one answer.** The bare-string [`DENY_RULE`] set and the
/// attributed [`VIOLATION_RULE`] set are read into one `Vec<Violation>`, in that
/// order. A bare string yields `rule: None` and is attributed to the enabling
/// row exactly as it was before CLOUD-832.
///
/// Returns [`Look::CouldNotLook`] when the bundle faults or the input will not
/// serialize — never an empty deny set, because "it ran and found nothing" and
/// "it could not run" are different answers and collapsing them is CLOUD-251's
/// vacuous pass.
///
/// **An undeclared id is also could-not-look**, and that arm is the one worth
/// stating: a module raising a `violation` whose `rule` its bundle never
/// published gives this gate a denial it cannot attribute, and the two
/// alternatives are both wrong — reporting it under the ROW id silently
/// re-flattens the very attribution CLOUD-832 exists to add, and dropping it
/// turns a real refusal into a pass. [`load`] refuses this outright for every
/// violation the empty document reaches; this is the residue, on inputs load
/// could not exercise.
#[must_use]
pub fn deny(bundle: &Bundle, input: &str) -> Look<Vec<Violation>> {
    let mut engine = bundle.engine.clone();
    if engine.set_input_json(input).is_err() {
        return Look::CouldNotLook;
    }
    // ONE QUERY for both shapes, because the engine is the unit now: the whole
    // `data.batten` document comes back once and is walked twice, rather than
    // paying an evaluation per rule name.
    let Ok(answered) = engine.eval_query(PACKAGE_QUERY.to_owned(), false) else {
        return Look::CouldNotLook;
    };

    let mut violations = Vec::new();
    match collect_deny_messages(&answered) {
        Some(tokens) => violations.extend(tokens.into_iter().map(|verdict| Violation {
            rule: None,
            verdict,
            subjects: Vec::new(),
        })),
        None => return Look::CouldNotLook,
    }
    match collect_violations(&answered) {
        Some(entries) => {
            for entry in entries {
                if let Some(named) = entry.rule.as_deref()
                    && !bundle.declared.contains(named)
                {
                    return Look::CouldNotLook;
                }
                violations.push(entry);
            }
        }
        None => return Look::CouldNotLook,
    }

    Look::Is(violations)
}

/// The `.rego` modules inside an enabled bundle root, in sorted order.
///
/// # Why enumerating here does not reopen §8
///
/// §8 forbids *implicit discovery* — the upward directory walk and the `conf.d`
/// merge — because merging can weaken. This does neither. The one committed
/// authority names the root explicitly, so nothing is found that was not
/// enabled; and every module inside is deny-only by construction, so the set can
/// only ADD refusals. §8's invariant is raise-only, and a set that cannot
/// subtract satisfies it more strongly than the typed rule table does.
///
/// **Sorted, because the order is part of the answer.** Two modules in one
/// bundle compose into one engine, and a bundle that compiled in directory order
/// would produce a different diagnostic on two machines for the same tree —
/// §6's byte-stability reaches a config error's text.
///
/// Non-recursive, deliberately: a bundle is a folder of modules, and descending
/// would make "which files am I enabling" a question a reader answers by walking
/// the tree rather than by reading the row.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the root cannot be listed, and when it
/// contains no `.rego` module at all — an empty bundle enables nothing while
/// reading in the config as a configured gate, which is the shape house style §8
/// refuses everywhere else.
fn bundle_members(
    root: &Path,
    bundle: &str,
    reference: Option<&str>,
    rule_id: &str,
) -> Result<Vec<String>> {
    let prefix = bundle.trim_end_matches('/');
    let mut members: Vec<String> = if let Some(reference) = reference {
        // UNDER `--config-from`, THE MEMBERSHIP COMES FROM THE REF TOO. Listing
        // the working tree here would pair a base's rules with the working
        // tree's module SET — an agent could add a module and change what the
        // base policy decides, which is precisely the influence that flag exists
        // to exclude, arriving through the folder instead of through a file.
        crate::git::list_tree(root, reference, prefix).map_err(|_| {
            UsageError::raise(format!(
                "rule `{rule_id}` enables `{prefix}`, which cannot be listed at {reference}"
            ))
        })?
    } else {
        let dir = root.join(prefix);
        let entries = std::fs::read_dir(&dir).map_err(|_| {
            UsageError::raise(format!(
                "rule `{rule_id}` enables `{prefix}`, which cannot be listed"
            ))
        })?;
        entries
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.path().is_file())
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .map(|name| format!("{prefix}/{name}"))
            })
            .collect()
    };
    // `Path::extension` rather than `ends_with(".rego")`, and clippy is right for
    // a reason worth stating: a file literally named `.rego` ends with the
    // string and has no extension, so the string test enables a dotfile nobody
    // wrote a module in. The comparison stays case-SENSITIVE deliberately —
    // `.REGO` is a different filename on the platforms this ships to, and
    // matching it would enable a file the author did not name.
    members.retain(|path| {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|extension| extension == "rego")
    });
    members.sort();
    if members.is_empty() {
        return Err(UsageError::raise(format!(
            "rule `{rule_id}` enables `{prefix}`, which carries no `.rego` module; an empty \
             bundle enables nothing while reading as a configured gate"
        )));
    }
    Ok(members)
}

/// Refuse a `predicate_severity` key naming an id the bundle never published.
///
/// A setting that parses and does nothing is the shape house style §8 refuses
/// everywhere else in this config, and this is the only place that sees both the
/// row and the bundle's declared set — `Rule::validate` has the row and not the
/// module. Same shape as CLOUD-208's dead-waiver diagnostic, and for the same
/// reason: a severity aimed at nothing leaves a reader believing a predicate is
/// tuned when it is not.
///
/// One function rather than a copy per source kind, because an in-repo bundle
/// and a vendored preset must be judged identically — the moment they are not,
/// "which kind of bundle is this" becomes a question a reader has to ask about
/// their own config.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the key and the source it was aimed at.
/// Refuse a tree-scoped module that reads an `input.tree.<key>` the engine
/// cannot produce (CLOUD-845).
///
/// **This is the class, not the instance.** The instance was
/// `input.tree.tracked` — documented in this file's own module doc, never built
/// by `rules::tree_document`, and therefore silent: Rego reads an undefined path
/// as undefined, so the rule body never holds, so the `violation` set is empty,
/// so a dead gate and a clean tree are byte-identical on the decision surface.
/// A module's own `test_` rule cannot catch it either, because `with input as`
/// lets the author supply the very shape the engine cannot make.
///
/// So the check is against the ENGINE's key set rather than against a list kept
/// here: `Fact::tree_key` over the `Surface::Check` facts, plus the
/// could-not-look channel. One table, read — never restated, which is the defect
/// this whole row is an instance of.
///
/// **At load rather than in `policy test`.** CLOUD-845 §2(c) asks for the
/// refusal in `policy test`; doing it here is strictly stronger and costs
/// nothing extra, because a module that reads an unemittable key is dead on
/// `check` too, and `check` is where it would actually be trusted. §5's exit
/// class is unchanged: a config fault at load, exit `1`, never a policy verdict.
///
/// Mediated-call rows are untouched — they read `input.call` and `input.facts`,
/// which `hook::call_document` owns and CLOUD-834 already asserts.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the offending key and the module path.
/// Pointer-only: never a line of the module body.
fn check_tree_paths_are_emittable(rule: &Rule, bundle: &Bundle, source: &str) -> Result<()> {
    if rule.scope != crate::rules::RuleScope::Tree {
        return Ok(());
    }
    let emittable = tree_keys();
    let Some(described) = describe(&bundle.engine) else {
        // Could-not-look on the AST is not a refusal: `load` has already
        // compiled and smoke-queried this module, so a shape this reader does
        // not recognise is its own limitation, and failing the config over it
        // would make a reader upgrade a breaking change.
        return Ok(());
    };
    for module in &described {
        for rule_ast in &module.rules {
            for path in &rule_ast.input_paths {
                let Some(key) = path.strip_prefix("tree.") else {
                    continue;
                };
                // Only the first segment names a key; `tree.documents["x"].y`
                // arrives here as `tree.documents`.
                let key = key.split('.').next().unwrap_or(key);
                if key.is_empty() || emittable.contains(key) {
                    continue;
                }
                let mut known: Vec<&str> = emittable.iter().copied().collect();
                known.sort_unstable();
                return Err(UsageError::raise(format!(
                    "rule `{}` registers `{source}`, whose module {} reads \
                     `input.tree.{key}`, which the engine never emits — the \
                     predicate would be undefined and the gate silent. Emitted: {}",
                    rule.id,
                    module.path,
                    known.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// The other direction of registry equality, once over the whole rule set
/// (CLOUD-1050).
///
/// A declared token nothing emits is **dead vocabulary**: it reads as coverage
/// in `batten policy explain`, and its routes — the remedy a reader would be
/// sent down — have never been exercised by anything. That is the same defect a
/// `[[waiver]]` naming an undeclared rule has, arriving from the other side.
///
/// **The consumer's own rows only.** The vendored half is this binary's
/// vocabulary rather than the consumer's config, and a vendored class is not
/// dead just because the tree in front of it enables no preset that raises one —
/// refusing there would make every consumer answer for a table they did not
/// write.
///
/// **Tombstones are exempt by construction rather than by a clause**: a retired
/// entry is filtered out here, because being explainable and unemitted is its
/// whole purpose.
///
/// Called only where the module checks ran, because only then was `emitted`
/// populated: the mediated path skips the AST read for CLOUD-689's budget, and
/// asserting equality against a set nothing filled would refuse every token on
/// every hook call.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the unraised tokens.
fn check_registry_is_exhausted(
    verdicts: &[crate::verdict::DeclaredVerdict],
    emitted: &BTreeSet<String>,
) -> Result<()> {
    let native = crate::verdict::native_tokens();
    let unemitted: Vec<&str> = verdicts
        .iter()
        .filter(|entry| !entry.retired())
        .map(|entry| entry.id.as_str())
        .filter(|token| !emitted.contains(*token) && !native.contains(token))
        .collect();
    if let Some(first) = unemitted.first() {
        return Err(UsageError::raise(format!(
            "`[[verdict]]` declares `{first}`, which nothing raises — not a policy module \
and not a native refusal site. A class no gate reaches reads as coverage in `batten policy \
explain` and its routes have never been walked by anybody. Delete the row, or give it a \
`successor` so it becomes a tombstone. Unemitted: {}",
            unemitted.join(", ")
        )));
    }
    Ok(())
}

/// The registry a load decides against: the consumer's rows, then this binary's.
///
/// **A collision is refused rather than resolved.** Letting the consumer's row
/// win would let a `batten.toml` silently redefine a class a vendored preset
/// raises — the preset's refusal would then carry words its author never wrote,
/// which is the same defect as a second authority for one question. Letting the
/// vendored one win would make a consumer's declaration inert while reading as
/// live. Both are worse than saying so.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the colliding token.
pub fn registry_for(
    verdicts: &[crate::verdict::DeclaredVerdict],
) -> Result<Vec<crate::verdict::DeclaredVerdict>> {
    let mut registry = verdicts.to_vec();
    let declared: BTreeSet<&str> = verdicts.iter().map(|entry| entry.id.as_str()).collect();
    for entry in crate::verdict::vendored() {
        if declared.contains(entry.id.as_str()) {
            return Err(UsageError::raise(format!(
                "`[[verdict]]` declares `{}`, which this binary already ships — \
                 a class with two definitions renders one refusal under words its \
                 emitter never wrote. Pick a token this binary does not vendor",
                entry.id
            )));
        }
        registry.push(entry);
    }
    Ok(registry)
}

/// Refuse a module whose refusals the registry does not declare (CLOUD-1050).
///
/// Three clauses, and they are three different defects rather than one:
///
/// * **the retired key.** A module still binding `msg` speaks the ABI the
///   decoder no longer reads, so its refusals would arrive as could-not-look —
///   a gate that loads, evaluates and reports nothing. Refused where it is
///   written.
/// * **a composed token.** `"verdict": sprintf(…)` is a class no reader can
///   resolve and no registry can be held to. The whole point of a token is that
///   being told it twice is being told the same thing twice, and a composed one
///   cannot promise that.
/// * **an undeclared or retired token.** A token the registry does not carry has
///   no gloss, no class definition and no routes, so the refusal it produces is
///   the bare no CLOUD-122 named; a token declared as a TOMBSTONE has all three
///   and is still wrong to emit, because a tombstone's whole meaning is that
///   nothing emits it any more.
///
/// **The other direction — a declared token nothing emits — is deliberately NOT
/// refused here**, and that is a bound rather than an omission. This function
/// sees one bundle; "nothing emits it" is a property of every bundle plus every
/// native site, and refusing per bundle would refuse a token the module across
/// the file emits. `load` closes that half once, over the whole rule set.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the module, the rule and the token.
/// Pointer-only: never a line of the module body.
fn check_verdicts_are_declared(
    rule: &Rule,
    bundle: &Bundle,
    registry: &[crate::verdict::DeclaredVerdict],
    source: &str,
) -> Result<()> {
    // Derived here rather than handed in, so the call site is one line at each
    // of its two positions. The table is tens of entries and this is the load
    // path, not the mediated one — `ModuleChecks::SkipOnHotPath` is what keeps
    // it off the 100ms budget, and re-deriving a set that small is free against
    // the AST read it sits beside.
    let declared = crate::verdict::declared_tokens(registry);
    let emittable = crate::verdict::live_tokens(registry);
    let Some(described) = describe(&bundle.engine) else {
        // Could-not-look on the AST is not a refusal, for the reason the sibling
        // checks state.
        return Ok(());
    };
    for module in &described {
        for rule_ast in &module.rules {
            if rule_ast.name.starts_with(TEST_PREFIX) {
                // A module's own test may legitimately construct a violation
                // object to compare against, and holding a test to the registry
                // would make a case that pins the OLD token unwritable — which
                // is exactly the case a retirement needs.
                continue;
            }
            if rule_ast.binds_msg {
                return Err(UsageError::raise(format!(
                    "rule `{}` registers `{source}`, whose module {} still binds `{RETIRED_MSG_KEY}` \
in `{}`. A refusal is `{{rule, {VERDICT_KEY}, subjects}}` since CLOUD-1050: the prose moved into a \
`[[verdict]]` row, where a gate can read it, and this key is no longer decoded — a module carrying \
it loads clean and reports nothing",
                    rule.id, module.path, rule_ast.name,
                )));
            }
            if rule_ast.composes_verdict {
                return Err(UsageError::raise(format!(
                    "rule `{}` registers `{source}`, whose module {} COMPOSES its `{VERDICT_KEY}` in \
`{}` rather than naming one. A token is a name a reader can look up and a registry can be held to; \
a composed one is neither",
                    rule.id, module.path, rule_ast.name,
                )));
            }
            // THE BARE-STRING CHANNEL IS HELD TO THE SAME REGISTRY. A member of
            // `deny` is a verdict token since CLOUD-1050, so its literals are
            // tokens too — and leaving them unchecked would keep one spelling of
            // a refusal that can say anything, which is the hole the whole row
            // exists to close.
            let tokens: Vec<&String> = if rule_ast.name == DENY_RULE {
                rule_ast
                    .head_literal
                    .iter()
                    .chain(&rule_ast.verdict_literals)
                    .collect()
            } else {
                rule_ast.verdict_literals.iter().collect()
            };
            for token in tokens {
                if emittable.contains(token.as_str()) {
                    continue;
                }
                let retired = declared.contains(token.as_str());
                let mut known: Vec<&str> = emittable.iter().copied().collect();
                known.sort_unstable();
                return Err(UsageError::raise(format!(
                    "rule `{}` registers `{source}`, whose module {} raises the verdict \
`{token}` in `{}`, which {}. Declared and emittable: {}",
                    rule.id,
                    module.path,
                    rule_ast.name,
                    if retired {
                        "the registry declares as RETIRED — a tombstone exists so a historical token \
stays explainable, never so a live predicate can keep raising it"
                    } else {
                        "no `[[verdict]]` row declares — the refusal would carry no gloss, no class \
definition and no route, which is the bare no this ABI exists to refuse"
                    },
                    if known.is_empty() {
                        String::from("none")
                    } else {
                        known.join(", ")
                    },
                )));
            }
        }
    }
    Ok(())
}

/// Every verdict token a bundle's non-test rules name.
///
/// The other half of [`check_verdicts_are_declared`]: that one asks whether an
/// emitted token is declared, and [`load`] uses this to ask whether a declared
/// token is emitted.
fn emitted_verdicts(bundle: &Bundle) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let Some(described) = describe(&bundle.engine) else {
        return found;
    };
    for module in &described {
        for rule_ast in &module.rules {
            if rule_ast.name.starts_with(TEST_PREFIX) {
                continue;
            }
            found.extend(rule_ast.verdict_literals.iter().cloned());
            if rule_ast.name == DENY_RULE {
                found.extend(rule_ast.head_literal.iter().cloned());
            }
        }
    }
    found
}

/// Refuse a regex written inline in a module (CLOUD-885).
///
/// **The lever is cost, not prohibition**, and this is the half that applies it.
/// "Do not regex things that are not regular" cannot be a gate — that is a
/// judgement, and non-negotiable rule 3 says a gate resolves to a command and an
/// exit code over an object it decides. Where a pattern LIVES is decidable, so
/// that is what is decided: a regex costs an id and a row in `batten.toml`,
/// while the same question asked of a parsed document costs a field access. The
/// cheap path becomes the correct one without anyone having to reason about
/// regularity.
///
/// Three things follow, and [`crate::pattern`] carries the argument for each:
/// rule 1 (a tracker-key expression is a consumer identifier and belongs in the
/// consumer's config), duplication becoming unwritable rather than merely
/// detectable, and the pattern inventory becoming reviewable data (§11).
///
/// **`test_` rules are exempt**, and it is a real case rather than a hatch: a
/// test legitimately matches a declared pattern against a literal subject
/// (`regex.match(patterns.key, "CLOUD-1")`), which this check would otherwise
/// read as an inline pattern. The prefix is the one `policy test` already keys
/// on, so no second convention is introduced.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the module and the remedy (CLOUD-437).
/// **The expression is named**, and that is inside rule 4 rather than an
/// exception to it: a pattern is a declaration the config author wrote — the
/// class `config show` exists to echo — not content read out of a subject file.
fn check_no_inline_regex(
    rule: &Rule,
    bundle: &Bundle,
    declared: &BTreeSet<&str>,
    source: &str,
) -> Result<()> {
    let Some(described) = describe(&bundle.engine) else {
        // Could-not-look on the AST is not a refusal, for the reason the sibling
        // checks state: `load` has already compiled this module, so a shape this
        // reader does not recognise is its own limitation, and failing the config
        // over it would make a reader upgrade a breaking change.
        return Ok(());
    };
    // A REFERENCE TO AN UNDECLARED ID IS THE SAME DEFECT ONE STEP LATER, and
    // refusing the inline form without refusing this would leave the hole the
    // mechanism exists to close: `data.batten.patterns["typo"]` resolves to
    // UNDEFINED, Rego reads undefined as "this rule body does not hold", so the
    // module loads clean, evaluates clean and gates nothing. That is CLOUD-251's
    // vacuous pass, and it is exactly what `WeakeningKind::PatternRemoved`
    // describes arriving by a different route — a typo rather than a deletion.
    // Same shape as `check_tree_paths_are_emittable`: refuse a reference the
    // engine cannot satisfy, at load, against the table rather than a list.
    // A VENDORED PRESET IS EXEMPT, and it is the rule's own scope rather than a
    // hatch in it. The declaration requirement exists because a pattern written
    // into a module smuggles a CONSUMER fact into a place consumer facts may not
    // live (non-negotiable rule 1) — which is why `Config::verbs` states the
    // same argument for its table. A preset ships INSIDE the crate, so rule 1
    // already forces its patterns to be repo-agnostic: `shell-hygiene`'s
    // `\$\{?BASH_SOURCE|\$0` names no consumer and could not, or the preset
    // itself would fail the rule.
    //
    // It is also unsatisfiable as a demand. A preset is compiled in; a consumer
    // cannot add a `[[pattern]]` row on its behalf, and the preset cannot read
    // one — so refusing it would make a vendored bundle unloadable with no fix
    // available, which is the wrongly-refusing gate AGENTS.md calls a defect.
    // Caught by `the_committed_delegating_rule_*` on the first run against a
    // preset that uses one.
    if rule.preset.is_some() {
        return Ok(());
    }
    for module in &described {
        for rule_ast in &module.rules {
            for referenced in &rule_ast.pattern_refs {
                if declared.contains(referenced.as_str()) {
                    continue;
                }
                let mut known: Vec<&str> = declared.iter().copied().collect();
                known.sort_unstable();
                return Err(UsageError::raise(format!(
                    "rule `{}` registers `{source}`, whose module {} references \
`data.batten.patterns[\"{referenced}\"]`, which no `[[pattern]]` row declares — the \
reference would be undefined and the predicate silent. Declared: {}",
                    rule.id,
                    module.path,
                    if known.is_empty() {
                        String::from("none")
                    } else {
                        known.join(", ")
                    },
                )));
            }
            if rule_ast.name.starts_with("test_") {
                continue;
            }
            let Some(pattern) = rule_ast.inline_regex.first() else {
                continue;
            };
            return Err(UsageError::raise(format!(
                "rule `{}` registers `{source}`, whose module {} writes the regex `{pattern}` \
inline in `{}`. Declare it once as a `[[pattern]]` row and reference it as \
`data.batten.patterns[\"<id>\"]`: an expression is a consumer fact, so it belongs in \
the config rather than in a module (rule 1), and a named pattern has one home, which \
is what stops one concept acquiring several spellings",
                rule.id, module.path, rule_ast.name,
            )));
        }
    }
    Ok(())
}

/// The keys `rules::tree_document` emits, derived from the fact model.
///
/// Named once here so the refusal above and the engine agree by construction
/// rather than by two people keeping two lists in step.
fn tree_keys() -> BTreeSet<&'static str> {
    // `tree_key` IS the predicate, not the surface. The two agreed while every
    // tree-emitted fact happened to be `Surface::Check`, and stopped when the git
    // family arrived (CLOUD-907): three of its members are `Surface::Hook`, which
    // names the NARROWEST surface they may be resolved on and therefore admits
    // the wider tree, and all five are emitted because the consumers the census
    // found are gate tasks. Filtering on surface equality here refused
    // `input.tree["git-head"]` as a key the engine never emits, in the same
    // breath as the engine emitting it.
    let mut keys: BTreeSet<&'static str> = crate::facts::Fact::ALL
        .iter()
        .filter_map(|fact| fact.tree_key())
        .collect();
    // The could-not-look channel, which is not a fact and deliberately has no
    // `tree_key` — a module may legitimately decide ABOUT an absence.
    keys.insert("missing");
    keys
}

fn check_predicate_severity(rule: &Rule, declared: &BTreeSet<String>, source: &str) -> Result<()> {
    let Some(table) = rule.predicate_severity.as_ref() else {
        return Ok(());
    };
    for named in table.keys() {
        if !declared.contains(named.as_str()) {
            return Err(UsageError::raise(format!(
                "rule `{}` sets a severity for `{named}`, which `{source}` does not declare in \
                 `{RULES_RULE}`",
                rule.id
            )));
        }
    }
    Ok(())
}

/// Claim a bundle's predicate ids, refusing one another bundle already claimed.
///
/// **Across every bundle this load sees**, and that is what keeps a folder from
/// becoming a merge: there is no precedence to resolve because a collision is
/// refused outright rather than silently won by whichever loaded last. It is the
/// clause that makes enumerating modules inside an enabled bundle safe
/// (CLOUD-129's corrected shape).
///
/// It reaches **across the vendored/in-repo boundary** for free, because a
/// preset is just another bundle with a declared id set — so a consumer can
/// never be silently shadowed by a vendored predicate, nor shadow one. Bundles
/// are isolated as *engines* and still visible to each other here, and that
/// difference is the whole design: a preset cannot supply a helper, and cannot
/// steal an id either.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the id and **both** sources that declare
/// it — a message naming one sends the reader to whichever the loader happened
/// to reach second.
fn claim_ids(
    ids: &mut BTreeMap<String, String>,
    declared: &BTreeSet<String>,
    source: &str,
) -> Result<()> {
    for id in declared {
        if let Some(owner) = ids.get(id) {
            return Err(UsageError::raise(format!(
                "`{source}` and `{owner}` both declare the rule id `{id}`; a finding names one \
                 predicate, so there is no precedence to resolve here"
            )));
        }
    }
    for id in declared {
        ids.insert(id.clone(), source.to_owned());
    }
    Ok(())
}

/// What a whole-set sweep found (CLOUD-647).
///
/// # Why a set-level answer is needed at all
///
/// Batten's stability now depends on properties of the rule *set* — a rule that
/// can never fire, two that contradict, a cycle — and nothing decided any of
/// them. At 33 committed rows that was still tractable by reading; it does not
/// stay tractable, and "read it carefully" is not a gate: non-negotiable rule 3
/// makes a model verdict inadmissible, so the alternative to a decidable
/// mechanism here is not careful review, it is nothing.
///
/// # Why the sweep has to be DRIVEN
///
/// Regorus refuses a conflict and a recursion at **evaluation**, never at
/// `add_policy` — five cases, measured on 0.11.0. So a conflict on a path no
/// query exercises is silently unreported, and "load the policies and get a
/// verdict on the set" is not what the engine offers. Something has to reach
/// every rule, and something has to PROVE it reached them, or a green sweep and
/// a sweep that analysed nothing are the same answer.
///
/// [`analyse`] drives one query over the whole package and reads regorus's
/// `coverage` report back to establish the second half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// Module paths the sweep entered — at least one line evaluated.
    pub swept: Vec<String>,
    /// Module paths the sweep never entered at all.
    ///
    /// **The anti-vacuity term, and the whole reason `coverage` is a pinned
    /// feature rather than a reporting nicety.** A module the sweep never
    /// reached contributes nothing to the analysis, so every conflict and cycle
    /// inside it is unreported — and the run is green. That is precisely the
    /// false green this row opened on: a policy set that loads clean, passes
    /// every per-row check, and contains a rule that can never fire.
    ///
    /// Not the same as "not covered": a predicate body that is simply FALSE on
    /// the input is not covered and is entirely healthy. Entering the file at
    /// all is what is asserted here.
    pub unswept: Vec<String>,
}

// ─── The module test surface (CLOUD-835) ─────────────────────────────────────

/// The prefix that marks a rule as one of the module's own tests.
///
/// Conftest and OPA's own convention, adopted rather than reinvented — "adopt
/// prior art; don't expand the core" is the scope rule, and a consumer who has
/// written `opa test` fixtures should not have to learn a second spelling.
const TEST_PREFIX: &str = "test_";

/// One module, as its own AST describes it.
///
/// **Read from the AST rather than from the `data` document, and that is the
/// whole design.** An unsatisfied Rego body evaluates to **undefined** — which
/// is how a test ordinarily fails — so a suite enumerated by reading what the
/// package evaluates to is blind to exactly the tests that failed: they are
/// simply absent, indistinguishable from tests nobody wrote. That is CLOUD-251's
/// vacuous pass wearing a test harness. The AST names every rule whatever it
/// answers, so an undefined test is a **failure with a name attached**.
struct Described {
    /// The path `add_policy` was given for this module.
    path: String,
    /// The package it declares, e.g. `batten.trunk_based`.
    package: String,
    /// Its top-level rules.
    rules: Vec<DescribedRule>,
}

/// One top-level rule, as [`Described`] reads it.
struct DescribedRule {
    /// The rule's own name — `violation`, `rules`, `test_no_force_push`.
    name: String,
    /// The first line of the rule's HEAD, 1-based.
    ///
    /// **The head rather than the body, and this is a measurement rather than a
    /// preference.** Referencing `violation` in Rego evaluates *every* rule that
    /// contributes to it, so the BODY of a predicate that did not match is
    /// covered exactly like the body of one that did — a coverage read over the
    /// whole rule cannot tell "a test made this predicate fire" from "a test
    /// mentioned `violation`". The head is only constructed when the body
    /// succeeds, so its line is covered if and only if the rule fired.
    ///
    /// Measured on regorus 0.11.0, 2026-08-21, in both head shapes:
    ///
    /// ```text
    /// COV  10 violation contains {          <- fired
    /// COV  11    "rule": "fires",
    /// COV  14    input.call.command == "a"
    /// ---  17 violation contains {          <- did not fire
    /// ---  18    "rule": "quiet",
    /// COV  21    input.call.command == "b"  <- body covered anyway
    /// ```
    ///
    /// The first line alone is enough, which is what keeps this from needing the
    /// module text: an end line would have to be counted off `source.contents`,
    /// and not reading that field at all is the strongest form of rule 4 this
    /// function can take.
    head_line: u32,
    /// Every string literal the rule's own text carries.
    ///
    /// This is how a predicate id is bound to the rule that raises it, with no
    /// naming convention in between: `no-stray-artifact` is a literal inside the
    /// `violation` rule that produces it. A convention (`test_<id>` covers
    /// `<id>`) would be satisfied by a test that never touches the predicate,
    /// which is the decorative coverage this row exists to refuse.
    literals: Vec<String>,
    /// Every `input.<dotted path>` this rule's AST reads (CLOUD-845).
    ///
    /// The reference is what makes a predicate dead when the engine cannot
    /// produce the path — so this is the thing to check, not the string
    /// literals beside it. Paths only: a reference is a NAME, never a value, so
    /// rule 4 has nothing to say about carrying it.
    input_paths: Vec<String>,
    /// Every string literal this rule hands to a `regex.*` builtin (CLOUD-885).
    ///
    /// A subset of [`Self::literals`], separated because the question is
    /// different: that field binds a predicate id to the rule raising it, this
    /// one asks whether a pattern was written inline instead of declared.
    inline_regex: Vec<String>,
    /// Every `data.batten.patterns["<id>"]` this rule references (CLOUD-885).
    ///
    /// The ids only. A reference the config does not declare resolves to
    /// undefined, which Rego reads as "this rule body does not hold" — so this
    /// is what makes a typo a refusal rather than a silent disarm.
    pattern_refs: Vec<String>,
    /// Every string literal this rule binds to a `verdict` key (CLOUD-1050).
    ///
    /// **Read off the AST rather than off an evaluation**, for [`Described`]'s
    /// own reason: a `violation` whose body does not hold on the empty document
    /// evaluates to undefined, so a registry-equality check driven by evaluation
    /// would be blind to exactly the predicates that did not fire — which is
    /// most of them, most of the time. The AST names the token whatever the body
    /// answers.
    ///
    /// A token composed at runtime (`sprintf`, a variable) is deliberately not
    /// resolved. That is could-not-look rather than a guess, and the Regal rule
    /// beside this refuses the composition outright, so the case is closed at
    /// the source rather than approximated here.
    verdict_literals: Vec<String>,
    /// Whether this rule COMPOSES a verdict rather than naming one.
    ///
    /// `"verdict": sprintf(…)` is a token no reader can resolve and no registry
    /// can be held to, so it is refused where it is written rather than
    /// approximated here.
    composes_verdict: bool,
    /// The string literal this rule's HEAD contributes, when it contributes one
    /// (CLOUD-1050).
    ///
    /// `deny contains "V-X" if …` builds a set of strings, and the member is the
    /// head's key. Read from the head rather than from the rule's literals,
    /// because a rule's literals include every argument it passes: the fixture
    /// `deny contains "V-X" if contains(input.call.command, "forbidden")` has two
    /// string literals and exactly one of them is a token. Taking both reported
    /// `forbidden` as an undeclared class, which is this reader's own first
    /// firing and was caught by the suite rather than by reading.
    head_literal: Option<String>,
    /// Whether this rule binds anything to a `msg` key (CLOUD-1050).
    ///
    /// The retired shape. Refused at load rather than left to the linter,
    /// because a module carrying it is a module whose refusals the decoder
    /// cannot read, and discovering that at adjudication is the worst time.
    binds_msg: bool,
}

/// Read every module's rule names, spans and literals off the compiled AST.
///
/// `Engine::get_ast_as_json` is a **stable public** method — the alternative,
/// `get_modules()`, reaches the same three facts but only through
/// `regorus::unstable`, which upstream marks `#[doc(hidden)]` and "likely to
/// change". The `ast` feature that gates it is declared `[]` upstream: it names
/// no package, so the closure and the lockfile are untouched (measured, and
/// recorded in `Cargo.toml` beside the same argument for `http`).
///
/// **The document it parses carries the policy body**, in its top-level
/// `source.contents`. Nothing here lets that escape: the text is read only to
/// count newlines, and every value that leaves this function is a name, a path
/// or a line number. Rule 4 admits a pointer and refuses a payload.
///
/// `None` is could-not-look — the AST would not serialize, or its shape is not
/// the one this reads. Never an empty description, which would report a module
/// with no rules at all.
fn describe(engine: &regorus::Engine) -> Option<Vec<Described>> {
    let json = engine.get_ast_as_json().ok()?;
    let policies: Vec<serde_json::Value> = serde_json::from_str(&json).ok()?;
    let mut described = Vec::new();
    for policy in &policies {
        // `source.file` and nothing else. The sibling `source.contents` carries
        // the whole policy body, and this function never touches it — rule 4.
        let path = policy.get("source")?.get("file")?.as_str()?.to_owned();
        let ast = policy.get("ast")?;
        let package = reference_path(ast.get("package")?.get("refr")?)?;

        let mut rules = Vec::new();
        for rule in ast.get("rules")?.as_array()? {
            // `Default` is the other variant, and it is skipped deliberately: a
            // `default x := false` has no body to enter, so it can be neither a
            // test nor the rule that raises a predicate.
            let Some(spec) = rule.get("Spec") else {
                continue;
            };
            let Some((name, head_line)) = spec.get("head").and_then(head_of) else {
                continue;
            };
            let mut literals = Vec::new();
            collect_literals(rule, &mut literals);
            let mut input_paths = Vec::new();
            collect_input_paths(rule, &mut input_paths);
            let mut inline_regex = Vec::new();
            collect_inline_regex(rule, &mut inline_regex);
            let mut pattern_refs = Vec::new();
            collect_pattern_refs(rule, &mut pattern_refs);
            // ONLY THE RULES THAT PUBLISH A REFUSAL. A helper may legitimately
            // carry a field named `verdict` bound to a variable — the route
            // projection in `policy/verdict-routes-resolve.rego` does, and
            // reading it as a composed token was this check's own first firing,
            // caught by running it over the corpus rather than by reading.
            //
            // The cost, stated rather than discovered: a module that builds its
            // refusal object in a helper and yields it from `violation` is not
            // read here. That is could-not-look — the registry-equality pass
            // then sees no token for it — and the honest answer is that this
            // reader does not follow a value across a rule boundary.
            let publishes = name == VIOLATION_RULE || name == DENY_RULE;
            let mut verdict_literals = Vec::new();
            let mut composes_verdict = false;
            let mut msg_literals = Vec::new();
            let mut composes_msg = false;
            let head_literal = spec.get("head").and_then(head_literal_of);
            if publishes {
                collect_bound_values(
                    rule,
                    VERDICT_KEY,
                    &mut verdict_literals,
                    &mut composes_verdict,
                );
                collect_bound_values(rule, RETIRED_MSG_KEY, &mut msg_literals, &mut composes_msg);
            }
            rules.push(DescribedRule {
                name,
                head_line,
                literals,
                input_paths,
                inline_regex,
                pattern_refs,
                head_literal,
                verdict_literals,
                composes_verdict,
                binds_msg: !msg_literals.is_empty() || composes_msg,
            });
        }
        described.push(Described {
            path,
            package,
            rules,
        });
    }
    Some(described)
}

/// The string literal a `contains` rule head builds its member from, if any.
///
/// Only [`regorus::ast::Expr::Set`]'s `key` — an `if`-shaped or function head
/// contributes no set member, so there is nothing to read there and answering
/// `None` is the honest result rather than a fallback.
fn head_literal_of(head: &serde_json::Value) -> Option<String> {
    Some(
        head.get("Set")?
            .get("key")?
            .get("String")?
            .get("value")?
            .as_str()?
            .to_owned(),
    )
}

/// A rule head's name and the line it starts on, whichever head shape it is.
///
/// `Compr` (`x := 1`, `test_x if …`), `Set` (`violation contains …`) and `Func`
/// (`f(x) := …`) all carry a `refr` and a `span`, and reading them in one place
/// is what keeps a `contains` rule and an `if` rule from needing two spellings
/// here.
fn head_of(head: &serde_json::Value) -> Option<(String, u32)> {
    for shape in ["Compr", "Set", "Func"] {
        if let Some(inner) = head.get(shape) {
            let name = reference_path(inner.get("refr")?)?;
            let line = u32::try_from(inner.get("span")?.get("line")?.as_u64()?).ok()?;
            return Some((name, line));
        }
    }
    None
}

///// The JSON Schema for the **tree** surface's `input` document, derived from
/// [`crate::facts::Fact`] (CLOUD-879).
///
/// # Derived, because a checked-in schema is a second authority
///
/// This document was hand-written and checked in, with a test asserting its key
/// set matched `Fact::tree_key()`. That test is the shape a drift gate takes when
/// the artifact is not derived, and it can only ever say *these two disagree* —
/// never keep them from disagreeing. The projection in
/// [`crate::rules::tree_document`] already iterates `Fact::ALL`; so does this, so
/// a fact that gains a tree key gains a schema entry in the same edit and
/// `mise run schema` is the only thing anyone has to remember.
///
/// # `missing` is here and is not a fact, deliberately
///
/// Could-not-look is not something the boundary *resolved*; it is the record of
/// what it could not. Modelling it as a fact would make `Fact::ALL` a list of
/// answers plus one non-answer, and every match over it would have to special-case
/// the member that is not a fact. So it is stated here, at the one place the
/// surface is described, and its distinctness from an empty result is the whole
/// point (CLOUD-251, CLOUD-845).
///
/// # Errors
///
/// Propagates a serialization failure, which the shapes below cannot produce.
pub fn tree_input_schema() -> Result<String> {
    let mut properties = serde_json::Map::new();
    for fact in crate::facts::Fact::ALL {
        if let Some(key) = fact.tree_key() {
            properties.insert(key.to_owned(), fact.schema_fragment());
        }
    }
    properties.insert(
        "missing".to_owned(),
        serde_json::json!({
            "type": "array",
            "description": "Could-not-look, and NOT a Fact: a declared path the engine could not acquire. Distinct from an empty result, which is the distinction that keeps a vacuous pass out (CLOUD-251, CLOUD-845).",
            "items": {"type": "string"},
        }),
    );
    let document = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "batten tree-surface policy input",
        "description": "The document a tree-scoped Rego module reads as `input`. CLOUD-876: `opa check -s` types a module against this at build time, so a rule naming a key the engine never emits fails the build rather than evaluating to undefined and reporting green. Generated from `Fact::tree_key()` by `batten generate schema --surface policy-input` (CLOUD-879); edit the facts, never this file.",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "tree": {
                "type": "object",
                "description": "The tree surface. `additionalProperties: false` is the load-bearing line: it is what turns a misspelled key, and CLOUD-845's documented-but-never-built one, into a build-time error instead of a silent undefined.",
                "additionalProperties": false,
                "properties": properties,
            },
        },
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

/// The JSON Schema for the **mediated-call** surface's `input` document, derived
/// from [`crate::facts::Fact`] (CLOUD-879).
///
/// Companion to [`tree_input_schema`], and the two share no keys — a module type
/// checked against the wrong one is CLOUD-845's defect deliberately introduced.
/// The fact half keys off [`crate::facts::Fact::as_str`], filtered to
/// [`crate::facts::Surface::Hook`], exactly as [`crate::hook::call_document`]
/// projects it.
///
/// The `call` envelope is stated rather than derived, because it is not facts: it
/// is what the harness said is being ATTEMPTED, before anything has been resolved
/// about it. Deriving it from the fact model would mean modelling the envelope as
/// facts, which would put "what is being attempted" and "what is known about it"
/// on one axis — the distinction the two surfaces exist to keep.
///
/// # Errors
///
/// Propagates a serialization failure, which the shapes below cannot produce.
pub fn call_input_schema() -> Result<String> {
    let mut facts = serde_json::Map::new();
    for fact in crate::facts::Fact::ALL {
        if fact.class().surface == crate::facts::Surface::Hook {
            facts.insert(fact.as_str().to_owned(), fact.schema_fragment());
        }
    }
    let document = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "batten mediated-call policy input",
        "description": "The document a `scope = \"mediated_call\"` Rego module reads as `input`. Companion to policy-input.schema.json, which describes the TREE surface: the two share no keys, and a module type checked against the wrong one is CLOUD-845's defect deliberately introduced. Generated from `Fact::ALL` filtered to `Surface::Hook` by `batten generate schema --surface policy-call` (CLOUD-879); edit the facts, never this file.",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "call": {
                "type": "object",
                "description": "The envelope the harness handed the boundary -- what is being attempted, never a fact resolved about it.",
                "additionalProperties": false,
                "properties": {
                    "event": {"type": "string"},
                    "operation": {"type": "string"},
                    "command": {},
                    // THE SEGMENTED COMMAND (CLOUD-857). Constrained rather than
                    // left open like its neighbours, because a module reads a
                    // FIELD of each entry and `additionalProperties: false` is
                    // what makes `segment.word` a build-time error instead of an
                    // undefined path that denies nothing — the same load-bearing
                    // line the `facts` object below carries, for the same reason.
                    "segments": {
                        "type": "array",
                        "description": "`hook::segments` over `command`: one entry per shell-separated element, quote-aware. Anchor a program here rather than on `command`, whose first word is the first word of the whole LINE.",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "words": {"type": "array", "items": {"type": "string"}},
                                "raw": {"type": "string"},
                                "terminator": {"type": ["string", "null"]},
                            },
                        },
                    },
                    "writes": {},
                    "final-message": {},
                    "transcript": {},
                    "stop-repeat": {},
                },
            },
            "facts": {
                "type": "object",
                "description": "The `Surface::Hook` fact set, keyed by each fact's stable lowercase token (`Fact::as_str`). `additionalProperties: false` is the load-bearing line, exactly as on the tree surface: it is what makes `input.facts.receipt` a build-time error rather than an unconstrained `Any` that is undefined forever.",
                "additionalProperties": false,
                "properties": facts,
            },
        },
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

/// A reference expression as a dotted path: `batten.trunk_based`, `violation`.
fn reference_path(expr: &serde_json::Value) -> Option<String> {
    if let Some(var) = expr.get("Var") {
        return Some(var.get("value")?.as_str()?.to_owned());
    }
    if let Some(dot) = expr.get("RefDot") {
        let head = reference_path(dot.get("refr")?)?;
        let field = dot.get("field")?.as_array()?.get(1)?.as_str()?;
        return Some(format!("{head}.{field}"));
    }
    // `input.tree["documents"]` is a `RefBrack` around `input.tree`, and Rego
    // treats it as identical to `input.tree.documents`. Reading only the dotted
    // half would let `check_tree_paths_are_emittable` see the path as `tree`
    // with an empty key and skip it — the gate bypassed by a spelling.
    //
    // Only a STRING-LITERAL index resolves to a name. A variable index
    // (`input.tree[k]`) is a path this reader cannot know statically, and
    // answering `None` for it is could-not-look rather than a guess.
    if let Some(brack) = expr.get("RefBrack") {
        let head = reference_path(brack.get("refr")?)?;
        let index = brack.get("index")?.get("String")?.get("value")?.as_str()?;
        return Some(format!("{head}.{index}"));
    }
    None
}

/// Every `input.<dotted path>` a rule's AST subtree reads, without the `input.`
/// prefix (CLOUD-845).
///
/// Built on [`reference_path`], which already renders a `RefDot` chain as a
/// dotted string — so `input.tree.documents` arrives as `tree.documents` and a
/// bracket index (`input.tree.documents["x"]`) simply stops the chain, which is
/// what the caller wants: the KEY is the first segment and the rest is the
/// module's business.
fn collect_input_paths(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(path) = reference_path(value)
                && let Some(rest) = path.strip_prefix("input.")
            {
                found.push(rest.to_owned());
            }
            for child in object.values() {
                collect_input_paths(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_input_paths(item, found);
            }
        }
        _ => {}
    }
}

/// Every string literal a rule hands to a `regex.*` builtin (CLOUD-885).
///
/// A call is `{"Call": {"fcn": <expr>, "params": [<expr>, …]}}`, and `fcn`
/// resolves through [`reference_path`] exactly as an input reference does —
/// `regex.match` is a `RefDot` over the var `regex`.
///
/// **Every parameter, and the recursion into each is what closes the hole.**
/// The builtins disagree on argument order — `regex.match(pattern, value)`
/// against `regex.replace(s, pattern, value)` — so a per-builtin position table
/// would be a second thing to keep in step with upstream. Reading them all is
/// wider, and the width is load-bearing rather than lazy: recursing means
/// `regex.match(concat("", ["CLOUD", "-[0-9]+"]), s)` is caught too, which a
/// direct-parameter check would wave through.
///
/// A reference to `data.batten.patterns["x"]` carries no literal, so the
/// sanctioned form passes by construction rather than by exemption.
fn collect_inline_regex(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(call) = object.get("Call")
                && let Some(name) = call.get("fcn").and_then(reference_path)
                && name.starts_with("regex.")
                && let Some(params) = call.get("params").and_then(serde_json::Value::as_array)
            {
                for param in params {
                    // A REFERENCE IS NOT A LITERAL, even though it contains one.
                    // `data.batten.patterns["x"]` is a `RefBrack` whose index is
                    // the string `"x"`, so a naive literal sweep reads the
                    // sanctioned form as the refused one and no module can load
                    // at all. Skipping the subtree is right rather than
                    // convenient: the id is a NAME, and the expression it names
                    // lives in the config, which is the property being enforced.
                    if reference_path(param)
                        .is_some_and(|path| path.starts_with("data.batten.patterns."))
                    {
                        continue;
                    }
                    // BOTH SPELLINGS. A Rego backtick literal serialises as
                    // `RawString`, not `String`, and it is the spelling a regex
                    // is almost always written in — backticks are what let a
                    // pattern carry backslashes unescaped. Reading only
                    // `collect_literals` let every realistic inline pattern
                    // through, which is what the AST probe measured rather than
                    // what this reader assumed.
                    collect_string_values(param, "String", found);
                    collect_string_values(param, "RawString", found);
                }
            }
            for child in object.values() {
                collect_inline_regex(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_inline_regex(item, found);
            }
        }
        _ => {}
    }
}

/// Every pattern id a rule reaches through `data.batten.patterns[…]`
/// (CLOUD-885).
///
/// [`reference_path`] already resolves a string-literal index, so
/// `data.batten.patterns["x"]` arrives as the dotted path
/// `data.batten.patterns.x` and the id is its last segment. A VARIABLE index is
/// deliberately not resolved — that path is not statically knowable, and
/// answering `None` for it is could-not-look rather than a guess, which is the
/// same posture `reference_path` already takes.
fn collect_pattern_refs(value: &serde_json::Value, found: &mut Vec<String>) {
    const PREFIX: &str = "data.batten.patterns.";
    match value {
        serde_json::Value::Object(object) => {
            if let Some(path) = reference_path(value)
                && let Some(rest) = path.strip_prefix(PREFIX)
                && !rest.is_empty()
            {
                found.push(rest.split('.').next().unwrap_or(rest).to_owned());
            }
            for child in object.values() {
                collect_pattern_refs(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_pattern_refs(item, found);
            }
        }
        _ => {}
    }
}

/// Every `{"<kind>": {"value": "…"}}` node in a subtree, for one node kind.
///
/// Rego has two literal spellings and regorus gives them different nodes:
/// `"x"` is a `String` and `` `x` `` is a `RawString`. A reader that knows only
/// one of them is blind to the other, and for a regex the backtick form is the
/// usual one, since it carries backslashes unescaped.
fn collect_string_values(value: &serde_json::Value, kind: &str, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(node) = object.get(kind)
                && let Some(text) = node.get("value").and_then(serde_json::Value::as_str)
            {
                found.push(text.to_owned());
            }
            for child in object.values() {
                collect_string_values(child, kind, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_string_values(item, kind, found);
            }
        }
        _ => {}
    }
}

/// Every value a rule's object literals bind to the key `key` (CLOUD-1050).
///
/// regorus serialises an object literal as
/// `{"Object": {"fields": [[<span>, <key expr>, <value expr>], …]}}`, so a field
/// is a three-element array and the pair this asks about is positional. Reading
/// it that way rather than scanning for adjacent string literals is what keeps
/// `{"verdict": "V-X"}` distinguishable from `{"x": "verdict"}` — the second is
/// two literals in the same order and a proximity reader cannot tell them apart.
///
/// `found` collects the STRING-literal values only. A value composed at runtime
/// is reported through `composed` instead: it is could-not-look on the token,
/// and the two must not be spelled the same way, because a registry-equality
/// check that silently skipped composed tokens would pass over exactly the
/// modules that reintroduced free prose.
fn collect_bound_values(
    value: &serde_json::Value,
    key: &str,
    found: &mut Vec<String>,
    composed: &mut bool,
) {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(fields) = object
                .get("Object")
                .and_then(|node| node.get("fields"))
                .and_then(serde_json::Value::as_array)
            {
                for field in fields {
                    let Some(pair) = field.as_array() else {
                        continue;
                    };
                    let (Some(name), Some(bound)) = (pair.get(1), pair.get(2)) else {
                        continue;
                    };
                    let named = name
                        .get("String")
                        .and_then(|node| node.get("value"))
                        .and_then(serde_json::Value::as_str);
                    if named != Some(key) {
                        continue;
                    }
                    match bound
                        .get("String")
                        .and_then(|node| node.get("value"))
                        .and_then(serde_json::Value::as_str)
                    {
                        Some(literal) => found.push(literal.to_owned()),
                        None => *composed = true,
                    }
                }
            }
            for child in object.values() {
                collect_bound_values(child, key, found, composed);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_bound_values(item, key, found, composed);
            }
        }
        _ => {}
    }
}

/// Every string literal in a rule's AST subtree.
fn collect_literals(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                if key == "String"
                    && let Some(text) = child.get("value").and_then(serde_json::Value::as_str)
                {
                    found.push(text.to_owned());
                }
                collect_literals(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_literals(item, found);
            }
        }
        _ => {}
    }
}

/// One test rule, named by the module it is written in.
///
/// Both halves travel because neither alone is a pointer: two packages may
/// publish one test name, and one module may hold many.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct TestId {
    /// The module file the rule is written in.
    pub module: String,
    /// The rule's own name.
    pub name: String,
}

/// What a bundle's own test suite reported (CLOUD-835).
///
/// # Why a module test surface is a blocker rather than a nicety
///
/// `tests/policy_modules.rs` exercises the **evaluator** — load, deny,
/// could-not-look, a cyclic module refused. None of it exercises a **module**,
/// so a consumer who writes a predicate has no way to assert it decides
/// correctly. The retirement campaign has to move 1,570 of 2,485 bats cases onto
/// policy rows, and without this their only destinations are deletion (which
/// falsifies CLOUD-807's coverage-conservation claim at the moment it is
/// load-bearing) or 1,570 binary-spawning Rust tests, which is `test:bats`'s own
/// pole in a new language.
///
/// **And the translation is the known trap.** CLOUD-202 measured it: the shell
/// tasks spell `1 = violation, 2 = could not read` and this engine's contract is
/// the exact inverse, so *"translate the number, never copy it"*. A port with no
/// native test surface is a port where every miscarried case passes.
///
/// # The two anti-vacuity terms are two different questions
///
/// [`Suite::passed`] and [`Suite::failed`] are the suite's own verdict. The
/// other two are what stop a green suite from meaning nothing, and they are
/// deliberately not the same check:
///
/// * [`Suite::unexercised`] is a **coverage** answer about a PREDICATE — a
///   published id whose raising rule no test entered. It is measured off the
///   test sweep alone; see [`test`] for why that distinction is the point.
/// * [`Suite::untested_modules`] is a **structural** answer about a MODULE — one
///   carrying no `test_` rule at all. It decides nothing on its own, because its
///   predicates already fall out as unexercised; it is the pointer that says
///   where to start writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suite {
    /// Tests that evaluated to `true`.
    pub passed: Vec<TestId>,
    /// Tests that did not.
    ///
    /// `false` **and undefined** both land here, and collapsing them is correct:
    /// an unsatisfied Rego body is undefined, which is how a test ordinarily
    /// fails, and the name is known regardless because the AST carries it.
    pub failed: Vec<TestId>,
    /// Published predicate ids no test caused to be entered.
    pub unexercised: Vec<String>,
    /// Module paths carrying no `test_` rule at all.
    pub untested_modules: Vec<String>,
    /// Mediated-call module paths whose every `test_` rule passes a BARE
    /// command (CLOUD-857).
    ///
    /// The third anti-vacuity term, and it asks a question the other two
    /// cannot. [`Suite::unexercised`] asks whether a predicate was entered and
    /// [`Suite::untested_modules`] whether a module has any test at all — this
    /// one asks whether the tests hand the predicate the SHAPE the engine
    /// actually produces.
    ///
    /// The measured instance is the row this term ships with. Both vendored
    /// presets anchored `split(input.call.command, " ")[0] == "git"`, which asks
    /// about the first word of the whole LINE, so `cd /tmp && git push --force`
    /// was allowed. Every one of their `test_` rules passed a bare command, so
    /// the suite was green, the predicate WAS exercised, and the module WAS
    /// tested — neither existing term fired. CLOUD-845 is the same false green
    /// by its first road, where a module fabricated an input *key* the engine
    /// cannot build; this is a fabricated input *shape*, and real agent commands
    /// are compound most of the time, so the fabricated shape was the common
    /// case rather than the rare one.
    pub bare_only_modules: Vec<String>,
}

impl Suite {
    /// Whether this suite is a violation — exit `2` rather than `0`.
    ///
    /// A failing test is one. So is a published predicate no test exercised:
    /// CLOUD-835's §7(b) is explicit that such a suite is *"reported, not
    /// green"*, and a term that is reported without deciding anything is the
    /// decorative coverage this surface exists to refuse.
    ///
    /// [`Suite::untested_modules`] deliberately does NOT decide. Every predicate
    /// in such a module is already unexercised, so counting it again would be
    /// one fault reported as two.
    ///
    /// [`Suite::bare_only_modules`] DOES decide, and the asymmetry is the point.
    /// Its modules are not already counted by anything: their predicates are
    /// exercised and their tests pass, which is exactly how the defect it names
    /// shipped green twice. A term that only reported would be the decorative
    /// coverage this surface refuses — CLOUD-857 §2(c) asks for *"refused, or
    /// reported"*, and reported-without-deciding is what let the first road
    /// (CLOUD-845) stay open long enough to be found by a second.
    #[must_use]
    pub fn is_violation(&self) -> bool {
        !self.failed.is_empty()
            || !self.unexercised.is_empty()
            || !self.bare_only_modules.is_empty()
    }
}

/// Run a bundle's own `test_` rules and report what they left unexercised
/// (CLOUD-835).
///
/// **Discovery is by prefix over the AST, never by a second declaration.** The
/// row's words are *"every `test_` rule in every registered module"*, and
/// [`describe`] is what makes that computable — including the undefined tests
/// the `data` document cannot show.
///
/// **`input` is the fixture the row declared.** `batten.toml`'s `documents` key
/// (CLOUD-833) already means "the documents this row hands its bundle", parsed
/// by `rules::tree_document`, with a declared-but-absent one returned rather
/// than guessed — so the fixtures §1 gives `batten.toml` need no new key and
/// non-negotiable 6 is untouched. A test wanting a synthetic input still writes
/// `with input as {…}`, which is OPA and Conftest's own shape; the two coexist.
///
/// **Coverage is read off the TEST SWEEP, and that is the load-bearing
/// difference.** Driving [`PACKAGE_QUERY`] enters every evaluable rule in the
/// bundle, so a coverage term computed that way is [`analyse`]'s answer wearing
/// a test harness's name — it would call a predicate exercised because the
/// engine evaluated it, not because a test did. Here each test is driven by
/// path on its own coverage-enabled engine, so an entered line is one a test
/// entered.
///
/// Returns [`Look::CouldNotLook`] when the sweep cannot run — never an empty
/// suite, because a suite that did not run has established nothing (CLOUD-251).
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the input will not parse. A config fault,
/// kept apart from a test failure because that is CLOUD-202's whole lesson: a
/// run that could not evaluate must not be reported as one that found nothing.
pub fn test(bundle: &Bundle, input: &str, mediated: bool) -> Result<Look<Suite>> {
    let Some(described) = describe(&bundle.engine) else {
        return Ok(Look::CouldNotLook);
    };

    let mut untested_modules = Vec::new();
    let mut bare_only_modules = Vec::new();
    let mut discovered = Vec::new();
    for module in &described {
        let mut carries_a_test = false;
        let mut carries_a_compound_test = false;
        for rule in &module.rules {
            if !rule.name.starts_with(TEST_PREFIX) {
                continue;
            }
            carries_a_test = true;
            if rule.literals.iter().any(|text| names_a_list_operator(text)) {
                carries_a_compound_test = true;
            }
            discovered.push((
                TestId {
                    module: module.path.clone(),
                    name: rule.name.clone(),
                },
                format!("data.{}.{}", module.package, rule.name),
            ));
        }
        if !carries_a_test {
            untested_modules.push(module.path.clone());
        // ONLY ON THE MEDIATED SURFACE, and the scope arrives from the caller
        // rather than being sniffed here. A tree-scoped module is not handed a
        // command at all, so "did a test pass a compound one" is not a question
        // about it — asking anyway would report every `check` module forever,
        // which is the noise that gets a term switched off.
        } else if mediated && !carries_a_compound_test {
            bare_only_modules.push(module.path.clone());
        }
    }

    let mut engine = bundle.engine.clone();
    engine.set_enable_coverage(true);
    engine.set_input_json(input).map_err(|err| {
        UsageError::raise(format!(
            "`{}` was handed an input document that will not parse: {err}",
            bundle.pointer()
        ))
    })?;

    // A TEST THAT ANSWERS ANYTHING BUT `true` HAS FAILED. `false` and undefined
    // are one answer here, and an `eval_rule` that errors is a third spelling of
    // the same thing — a test whose body faults has not passed. None of the
    // three is a config fault: the set already compiled, at load.
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for (id, path) in &discovered {
        if matches!(
            engine.eval_rule(path.clone()),
            Ok(regorus::Value::Bool(true))
        ) {
            passed.push(id.clone());
        } else {
            failed.push(id.clone());
        }
    }

    // `file.code` is untouched: a coverage report is the most payload-shaped
    // thing in this crate and rule 4 admits a pointer.
    let Ok(report) = engine.get_coverage_report() else {
        return Ok(Look::CouldNotLook);
    };
    let mut entered: BTreeMap<&str, &BTreeSet<u32>> = BTreeMap::new();
    for file in &report.files {
        entered.insert(file.path.as_str(), &file.covered);
    }

    // Tests ran and the report mentions nothing at all: the coverage read did
    // not happen, which is a different answer from "no test entered anything"
    // and must not be reported as one (CLOUD-251).
    if !discovered.is_empty() && report.files.iter().all(|file| file.covered.is_empty()) {
        return Ok(Look::CouldNotLook);
    }

    // A PUBLISHED PREDICATE NO TEST MADE FIRE. Two halves, and each is doing
    // work:
    //
    // * The id is found as a LITERAL inside the rule that raises it, so the
    //   binding needs no naming convention — which is what stops a test called
    //   `test_<id>` that never touches `<id>` from counting. `RULES_RULE` is
    //   excluded because the declaration carries the id too, and entering a
    //   declaration is not exercising a predicate.
    // * The rule counts as fired when its HEAD line is covered, never its body
    //   — see [`DescribedRule::head_line`] for the measurement. This is what
    //   makes the term CLOUD-418's "shown able to fail" rather than "shown to
    //   have been evaluated".
    let mut unexercised = Vec::new();
    for id in &bundle.declared {
        let mut reached = false;
        for module in &described {
            let Some(covered) = entered.get(module.path.as_str()) else {
                continue;
            };
            for rule in &module.rules {
                if rule.name == RULES_RULE || !rule.literals.iter().any(|text| text == id) {
                    continue;
                }
                if covered.contains(&rule.head_line) {
                    reached = true;
                    break;
                }
            }
            if reached {
                break;
            }
        }
        if !reached {
            unexercised.push(id.clone());
        }
    }

    passed.sort();
    failed.sort();
    untested_modules.sort();
    Ok(Look::Is(Suite {
        passed,
        failed,
        unexercised,
        untested_modules,
        bare_only_modules,
    }))
}

/// Whether a string literal carries a shell list operator (CLOUD-857).
///
/// **The discriminator is the operator, not the module's spelling.** A module
/// reading `input.call.command` writes the compound case as one string —
/// `"cd /tmp && git push --force"` — and one reading `input.call.segments`
/// writes it as a `terminator` of `"&&"` beside two `words` arrays. Both carry
/// the operator as a literal, so one predicate covers a module before and after
/// its migration, which is what stops this term from having to know which
/// spelling a module happens to use today.
///
/// `|` is tested last and covers `||` by containment; listing it separately
/// would decide nothing. `&` alone is deliberately NOT here: it is a background
/// detach rather than a list of two programs, so a test carrying only `&` has
/// still never handed the predicate a second program to anchor on.
fn names_a_list_operator(literal: &str) -> bool {
    ["&&", ";", "|"]
        .iter()
        .any(|operator| literal.contains(operator))
}

/// Drive a sweep over a bundle's composed rule set and prove it reached every
/// module (CLOUD-647).
///
/// One query over [`PACKAGE_QUERY`], which forces evaluation of every rule in
/// the package rather than the one rule name a narrower query would reach — the
/// property CLOUD-837 bought by pinning the rule names instead of the package,
/// and the reason this analysis is possible at all. A conflict or a recursion
/// anywhere under it surfaces here as an evaluation error.
///
/// **Pointer-only, and this function is where that takes real care.**
/// `regorus::coverage::File` carries a `code` field holding the policy body, and
/// `Report::to_string_pretty` renders the whole of it. Neither reaches this
/// return value: only line SETS are read, and only their emptiness is used.
/// Rule 4 admits a pointer and refuses a payload, and a coverage report is the
/// most payload-shaped thing in this crate.
///
/// Returns [`Look::CouldNotLook`] when the sweep cannot run — never an empty
/// finding set, because a sweep that did not happen has established nothing.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the composed set faults: a rule conflict or
/// a recursion, refused where a config error belongs rather than at the gate.
pub fn analyse(bundle: &Bundle) -> Result<Look<Analysis>> {
    let mut engine = bundle.engine.clone();
    engine.set_enable_coverage(true);
    if engine.set_input_json("{}").is_err() {
        return Ok(Look::CouldNotLook);
    }
    // The driven sweep. An error here is the set refusing itself — a conflict
    // between two complete rules, or a cycle — which regorus reports with the
    // offending rule sites and a dependency chain. That diagnostic is
    // pointer-shaped already, which is what makes it admissible.
    engine
        .eval_query(PACKAGE_QUERY.to_owned(), false)
        .map_err(|err| {
            UsageError::raise(format!(
                "`{}` does not resolve as a set: {err}",
                bundle.pointer()
            ))
        })?;

    let Ok(report) = engine.get_coverage_report() else {
        return Ok(Look::CouldNotLook);
    };

    // MEASURED, AND IT CHANGED THE IMPLEMENTATION: a module the sweep never
    // entered produces **no report entry at all**, not an entry whose `covered`
    // set is empty. So "unswept" cannot be read off the report — it is the
    // difference between what the bundle HOLDS and what the report mentions.
    // Reading it the other way returned an empty `unswept` for a bundle that was
    // half dark, which is the exact false green this analysis exists to refuse,
    // reproduced inside the thing meant to catch it.
    //
    // `file.code` is deliberately untouched throughout. Only the PATH travels
    // and only whether any line was entered is read: a coverage report is the
    // most payload-shaped thing in this crate, and rule 4 admits a pointer.
    let reached: BTreeSet<&str> = report
        .files
        .iter()
        .filter(|file| !file.covered.is_empty())
        .map(|file| file.path.as_str())
        .collect();

    // A bundle that holds modules and produced no coverage entry at all is
    // could-not-look rather than "every module dark". The report is how this
    // function knows anything, and an empty one cannot tell a sweep that reached
    // nothing from a coverage read that did not happen — so it reports neither.
    if reached.is_empty() && !bundle.modules.is_empty() {
        return Ok(Look::CouldNotLook);
    }

    let mut swept = Vec::new();
    let mut unswept = Vec::new();
    for module in &bundle.modules {
        if reached.contains(module.path.as_str()) {
            swept.push(module.path.clone());
        } else {
            unswept.push(module.path.clone());
        }
    }
    swept.sort();
    unswept.sort();
    Ok(Look::Is(Analysis { swept, unswept }))
}
