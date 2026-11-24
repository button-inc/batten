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
//! halves are real now, and they answer different questions
//! (verified-by: `no_evaluator_feature_admits_io` — the behavioural half named
//! immediately below, which is the whole point of the correction this paragraph
//! records; `assertion_gates.rs` is what now refuses the state it describes):
//!
//! * `no_evaluator_feature_admits_io` in `crates/batten/tests/it/policy_modules.rs`
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
//! mediated call. A [`crate::config_model::RuleKind::Command`] row spawns a process with
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

use crate::preset::ManifestExt as _;
use crate::preset::PresetModuleExt as _;
use crate::rules::RuleExt as _;
use crate::verdict::DeclaredVerdictExt as _;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Result;
use crate::config_model::preset_names;
use crate::config_model::{Rule, RuleKind};
use crate::error::UsageError;
use crate::facts::Look;

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

/// The pre-approval set: the ids of this module's rules that hold for a call
/// the host should run without prompting (CLOUD-1949).
///
/// **Not an allow, and not a second authority.** It is read only after every
/// bundle's deny set came back empty and the engine's own decision was `Allow`,
/// so it can never lower a refusal: it tells the HOST not to prompt for a call
/// batten already allowed. The raise-only invariant (house style §8) is about
/// batten's refusals, and those stay deny-first by construction.
const PREAPPROVE_RULE: &str = "preapprove";

/// The rewrite set: `{"rule": id, "key": k, "value": v}` members naming a tool
/// input key a granted call should run with (CLOUD-2157).
///
/// **Rides a pre-approval and nothing else.** A host applies a rewritten input
/// only beside a permission decision, and the one Batten speaks is the grant, so
/// a rewrite is read only where [`PREAPPROVE_RULE`] already held. It can never
/// lower a refusal for the reason the grant cannot.
const REWRITE_RULE: &str = "rewrite";

/// The tool input keys a module may rewrite, each to a non-negative integer.
///
/// **An engine allowlist, never a module's choice**, for `Field`'s reason: a
/// rewrite that could address `command` would let a config replace the call it
/// was asked to judge, which is a reference monitor, not a gate. `timeout` is
/// the one a host default makes wrong for the slow path a background row
/// prescribes — Claude Code kills a backgrounded call at 30 minutes when it
/// names none, measured 2026-10-08 on a mutant sweep (CLOUD-2157).
const REWRITABLE: &[&str] = &["timeout"];

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
    /// The module asked for each firing to be counted (`"counted": true`,
    /// CLOUD-2292), so the engine names no rule `batten doctor gaps` counts.
    pub counted: bool,
}

// `PRESETS` moved to `crate::preset_catalog::MANIFESTS` (CLOUD-1181). It was one of
// three parallel tables describing a preset, none of which knew about the
// others; the doc comment that stood here — why Batten ships defaults, why this
// is not the OCI distribution CLOUD-129 rejected, and why rule 1 is most
// inviting to break at a preset — moved with it.
//
// CLOUD-129's VERDICT IS UNCHANGED TODAY and the manifest is not permission to
// fetch one: `include_str!` at build time, no network, no registry, no
// trust-on-first-use. `crate::preset`'s own header says so at length, because a
// reader arriving at a "manifest" reasonably wonders whether something resolves
// it, and the answer is that nothing does.
//
// AND THE VERDICT IS NOW AMENDED RATHER THAN ABSOLUTE (CLOUD-970, 2026-09-05).
// The rejection's stated GROUND was "there is no network here", and that ground
// is not what CLOUD-129 actually objected to — `provision apply` has fetched
// pinned artifacts over the network since CLOUD-90, under an operator-run `write`
// verb, against a digest in the committed authority, into an out-of-tree cache.
// A preset is data with the same properties, so a rejection resting on the
// absence of any fetch at all would refuse the thing it already sanctions one
// table over.
//
// So the standing verdict is option 2 of CLOUD-970's three: what stays refused is
// UNPINNED, EVALUATION-TIME, TRUST-ON-FIRST-USE resolution — a module arriving
// because something looked it up while deciding. What is permitted, if and when a
// resolver lands, is the `provision apply` shape: a deliberate `write` verb, a
// digest the consumer committed, a cache read offline thereafter, and `batten
// hook` and evaluation reaching no socket.
//
// **This is a decision about what MAY be built, and nothing is built yet.**
// CLOUD-970 landed the backend indirection and the `native` backend only, so the
// property below still holds by construction rather than by policy: `Backend`
// declares exactly one variant, it resolves a URL the consumer pinned, and there
// is no code path by which a preset can arrive from anywhere but `include_str!`.
// The boundary test option 2 owes — that `hook` and evaluation cannot reach the
// network — belongs to the row that lands a resolver, because a test asserting it
// today would assert its own premise (`.claude/rules/rust.md`).
//
// The reason this comment says so at all is the failure CLOUD-970 names: a
// resolver landing while this text still claims no network exists, so the next
// reader inherits a guarantee nobody is holding.

// `preset_modules` is gone (CLOUD-1181): the load site reads the whole manifest
// now, so a second lookup returning only the modules was one more place that
// could answer about a preset without seeing its scope — which is the fact the
// manifest exists to stop being separable.

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
    /// The packages the bundle's modules declared, relative to `data.batten`
    /// (CLOUD-1969).
    ///
    /// Recorded from `add_policy`'s own answer at [`compile`], because the
    /// result document cannot say which of its members are packages and which
    /// are rule values — and reading a rule value as a package is how a parsed
    /// document's own `deny` key became a finding.
    packages: BTreeSet<Vec<String>>,
    /// The enabling row's severity, and its per-predicate overrides (CLOUD-1131).
    ///
    /// **The bundle carried none until this row, and the mediated surface read
    /// none**, so `severity = "warn"` on a `scope = "mediated_call"` policy row
    /// denied exactly as `deny` did: `hook::policy_rules` turned any violation
    /// into a `Decision::Deny`, and `hook::blocks` — the function every typed rule
    /// kind consults — was never asked. A configured advisory was therefore a
    /// refusal, silently, which is the one direction a severity column must never
    /// fail in.
    ///
    /// `Deny` where nothing sets it, which is what [`compile`] leaves behind: a
    /// bundle built outside [`load`] has no enabling row to read, and the strict
    /// reading is the safe default for a value that decides whether a refusal
    /// refuses.
    severity: crate::severity::RuleSeverity,
    /// The `predicate_severity` table of the enabling row, if it declared one.
    predicate_severity: BTreeMap<String, crate::severity::RuleSeverity>,
    /// The one compiled evaluator, ready to take an input document: the
    /// interpreter, or the bytecode a hook call loaded from [`Compiled`]'s
    /// cache (CLOUD-2236).
    evaluator: Evaluator,
    /// The engine's [`describe`] reading, taken once and never re-queried
    /// (CLOUD-1875) — `declared`'s rationale, one field over. Six callers read
    /// it, and each used to re-serialise every module's whole AST. The engine is
    /// immutable after [`compile`], so there is nothing to invalidate. The inner
    /// `Option` keeps could-not-look distinct from not-yet-read, and `Arc` keeps
    /// the live-path clone a refcount rather than a copy.
    described: std::sync::OnceLock<Option<std::sync::Arc<Vec<Described>>>>,
    /// The interpreter's [`Ast`], rendered once on first use (CLOUD-2830):
    /// `described`'s rationale for every other reader of the same engine's AST
    /// — the load's `:=` check, the verdict compile's refusals and guard, and
    /// the suite plan, each of which rendered it again.
    ast: std::sync::OnceLock<Option<std::sync::Arc<Ast>>>,
    /// An interpreted bundle's [`Bundle::tree_reads`], taken once: seeded from
    /// the cache entry under the bundle's key where one holds it
    /// ([`remember_reads`]), so the two halves of a split `enforce` do not both
    /// describe it from scratch. Bytecode reads its own header instead.
    reads: std::sync::OnceLock<Reads>,
}

/// What a bundle reads off the tree input document: see [`Bundle::tree_reads`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reads {
    /// Exactly these `input.tree` keys, and nothing else on the input.
    Known(BTreeSet<String>),
    /// A read this reader cannot name, so any key may be read.
    Opaque,
}

impl Bundle {
    /// This bundle's [`describe`] reading, computed on first use.
    fn described(&self) -> Option<&[Described]> {
        self.described
            .get_or_init(|| describe_of(self.ast()?).map(std::sync::Arc::new))
            .as_deref()
            .map(Vec::as_slice)
    }

    /// This bundle's interpreter's [`Ast`], rendered on first use; `None`
    /// without an interpreter or where the AST will not serialise.
    fn ast(&self) -> Option<&Ast> {
        self.ast
            .get_or_init(|| Ast::of(self.evaluator.engine()?).map(std::sync::Arc::new))
            .as_deref()
    }
    /// Seed this bundle, compiled from `full`'s sources through
    /// [`without_test_rules`], with `full`'s reading less its `test_` rules.
    ///
    /// ONE LOAD DESCRIBES EACH BUNDLE ONCE (CLOUD-1875), and a checked load's
    /// bytecode miss holds two: the full-text interpreter its checks read, and
    /// the stripped one its program and cache header are taken from. Describing
    /// both serialised every module's AST twice. The stripped text is the full
    /// text with exactly the column-zero `test_` rules removed, and [`describe`]
    /// reads each rule on its own, so the full reading filtered by that name is
    /// the stripped reading: the program's reads and facts come out the same,
    /// and the AST is serialised once. A `full` with no reading leaves this one
    /// to describe itself, as before.
    fn seed_stripped_from(&self, full: &Self) {
        let Some(described) = full.described() else {
            return;
        };
        let stripped = described
            .iter()
            .map(|module| Described {
                path: module.path.clone(),
                package: module.package.clone(),
                rules: module
                    .rules
                    .iter()
                    .filter(|rule| !rule.name.starts_with("test_"))
                    .cloned()
                    .collect(),
            })
            .collect();
        let _ = self.described.set(Some(std::sync::Arc::new(stripped)));
    }

    /// Whether this bundle evaluates as bytecode (CLOUD-2236).
    #[must_use]
    pub fn is_bytecode(&self) -> bool {
        matches!(self.evaluator, Evaluator::Compiled(..))
    }

    /// Which evaluator decides this bundle's verdicts, and why where it is the
    /// interpreter (#1276).
    #[must_use]
    pub fn execution(&self) -> Execution {
        match &self.evaluator {
            Evaluator::Compiled(compiled, _) => Execution::Bytecode {
                cached: compiled.cached,
            },
            Evaluator::Interpreted { why, .. } => Execution::Interpreted(*why),
        }
    }

    /// What the bytecode compiler said when it refused this bundle, if it did.
    #[must_use]
    pub fn fallback_detail(&self) -> Option<&str> {
        match &self.evaluator {
            Evaluator::Interpreted { detail, .. } => detail.as_deref(),
            Evaluator::Compiled(..) => None,
        }
    }

    /// This bundle evaluating on its interpreter, where it holds one: what a
    /// parity check compares bytecode against. `None` for a hot-path bundle
    /// read from the cache, which carries no interpreter.
    #[must_use]
    pub fn as_interpreted(&self) -> Option<Self> {
        let engine = self.evaluator.engine()?.clone();
        Some(Self {
            evaluator: Evaluator::Interpreted {
                engine: Box::new(engine),
                why: Fallback::NotOffered,
                detail: None,
            },
            ..self.clone()
        })
    }

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

    /// Every session-start fact this bundle's modules dereference (CLOUD-1760).
    ///
    /// # Derived, never restated
    ///
    /// The edge from a rule to the facts it depends on is read off the compiled
    /// AST — the same [`describe`] reading `check_tree_paths_are_emittable`
    /// already trusts — and filtered through
    /// [`crate::facts::Fact::minted_at_session_start`]. A hand-maintained second
    /// list is what the row this closes forbids, and it would drift in the one
    /// direction that matters: a module gaining a dependency nobody added to the
    /// list goes back to failing silently.
    ///
    /// A bracket index is handled by [`reference_path`], so
    /// `input.facts["pinned-programs"]` and `input.facts.tasks` are read the same
    /// way. A VARIABLE index resolves to no name and is not read at all — that is
    /// could-not-look about one reference rather than a claim the module depends
    /// on nothing, and it fails toward under-reporting, which is stated here
    /// because it is the bound on what this can promise.
    ///
    /// An AST this reader does not recognise yields nothing, for [`describe`]'s
    /// own reason: the bundle has already compiled and smoke-queried, so an
    /// unfamiliar shape is this reader's limitation and not the module's fault.
    #[must_use]
    pub fn session_start_facts(&self) -> BTreeSet<&'static str> {
        // Bytecode carries no AST, so its reading was taken when the cache
        // entry was written, from the same source this would describe. A
        // checked load keeps its interpreter, and reads its own full text.
        if let Evaluator::Compiled(compiled, None) = &self.evaluator {
            return compiled
                .facts
                .iter()
                .filter_map(|token| crate::facts::Fact::from_token(token))
                .map(crate::facts::Fact::as_str)
                .collect();
        }
        let mut found = BTreeSet::new();
        let Some(described) = self.described() else {
            return found;
        };
        for module in described {
            for rule in &module.rules {
                for path in &rule.input_paths {
                    let Some(key) = path.strip_prefix("facts.") else {
                        continue;
                    };
                    // The first segment is the fact; anything after it is the
                    // module's own business (`facts.receipts.verify`).
                    let token = key.split('.').next().unwrap_or(key);
                    if let Some(fact) = crate::facts::Fact::from_token(token)
                        && fact.minted_at_session_start()
                    {
                        found.insert(fact.as_str());
                    }
                }
            }
        }
        found
    }

    /// Every `input.tree` key this bundle's modules read, or [`Reads::Opaque`]
    /// when that cannot be established statically (step 13a).
    ///
    /// Derived from the same [`describe`] reading [`Self::session_start_facts`]
    /// trusts, and conservative everywhere it cannot see: a bundle with no
    /// reading, a bare `input` or `input.tree` (an alias such as
    /// `t := input.tree`, or a variable index `input.tree[k]`, arrives as one of
    /// these), any read of `input.facts`/`input.call` or of a top-level key the
    /// tree document does not emit, and a bytecode entry written without the
    /// read set are all `Opaque`. Opaque is what makes a policy row LIVE, which
    /// is the side an undeterminable answer must fall on.
    #[must_use]
    pub fn tree_reads(&self) -> Reads {
        if let Evaluator::Compiled(compiled, None) = &self.evaluator {
            return compiled.reads.as_ref().map_or(Reads::Opaque, |keys| {
                Reads::Known(keys.iter().cloned().collect())
            });
        }
        self.reads.get_or_init(|| self.described_reads()).clone()
    }

    /// [`Self::tree_reads`] read off the [`describe`] reading.
    fn described_reads(&self) -> Reads {
        let Some(described) = self.described() else {
            return Reads::Opaque;
        };
        let mut keys = BTreeSet::new();
        for module in described {
            for rule in &module.rules {
                for path in &rule.input_paths {
                    let Some(rest) = path.strip_prefix("tree.") else {
                        return Reads::Opaque;
                    };
                    let key = rest.split('.').next().unwrap_or(rest);
                    if key.is_empty() {
                        return Reads::Opaque;
                    }
                    keys.insert(key.to_owned());
                }
            }
        }
        Reads::Known(keys)
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

    /// Record the enabling row's severity on the compiled bundle (CLOUD-1131).
    ///
    /// Applied at [`load`] rather than inside [`compile`], so `compile` stays the
    /// pure "N sources, one engine" function CLOUD-837 made it and its callers
    /// keep their signature.
    #[must_use]
    pub fn with_severity(mut self, rule: &crate::config_model::Rule) -> Self {
        self.severity = rule.severity();
        self.predicate_severity = rule.predicate_severity.clone().unwrap_or_default();
        self
    }

    /// The severity a denial from this bundle is reported at.
    ///
    /// Resolved exactly as [`crate::config_model::Rule::severity_for`] resolves it —
    /// the predicate's own where the row named one, the row's otherwise
    /// (CLOUD-832) — because the id a finding is reported under and the severity
    /// it is reported at have to come from one answer.
    #[must_use]
    pub fn severity_for(&self, predicate: Option<&str>) -> crate::severity::RuleSeverity {
        predicate
            .and_then(|named| self.predicate_severity.get(named))
            .copied()
            .unwrap_or(self.severity)
    }
}

/// The enabling-row ids of every bundle that publishes `predicate` (CLOUD-1571).
///
/// **The narrowing a mint needs, and the reason it is a function rather than a
/// filter written at its one call site.** [`crate::admission`]'s anchor has to
/// re-run the rule a refusal named in order to recover its fingerprint, and
/// `--rule` carries a PREDICATE id — `filed-here` publishes `issue file same`
/// — so a row-id match selects nothing and the mint silently binds the head
/// (CLOUD-1087, CLOUD-1125). Widening from there to every `policy` row fixed that
/// and cost 2m22s per mint, because "which KIND of row" is not "which row":
/// `protected-mutation` is an engine-side name no bundle can publish, and 58
/// modules were evaluated over the whole tree to produce findings the caller
/// discarded one line later.
///
/// Asking each bundle's own published set answers the question exactly. An EMPTY
/// result is therefore a real answer — *nothing can raise this predicate, so
/// there is nothing to scan for* — and never a could-not-look: a caller reads it
/// as "skip the scan", which is only sound because [`Bundle::declared`] is the
/// same authority [`Bundle::attribute`] resolves a violation's id against.
///
/// Borrowed rather than owned, so a caller filtering its own rows against the
/// result allocates nothing per row.
#[must_use]
pub fn publishers_of<'a>(bundles: &'a [Bundle], predicate: &str) -> BTreeSet<&'a str> {
    bundles
        .iter()
        .filter(|bundle| bundle.declared().contains(predicate))
        .map(Bundle::id)
        .collect()
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
            packages: self.packages.clone(),
            severity: self.severity,
            predicate_severity: self.predicate_severity.clone(),
            evaluator: self.evaluator.clone(),
            described: self.described.clone(),
            ast: self.ast.clone(),
            reads: self.reads.clone(),
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

/// Every whole-AST [`describe`] this process has performed (CLOUD-1875).
///
/// [`ENGINES_CONSTRUCTED`]'s shape and caveat: a counter at the single funnel,
/// read as a delta around one [`load`], and process-global.
static AST_DESCRIPTIONS: AtomicUsize = AtomicUsize::new(0);

/// How many AST descriptions this process has performed. Monotonic.
#[must_use]
pub fn ast_descriptions() -> usize {
    AST_DESCRIPTIONS.load(Ordering::Relaxed)
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
    pub verdicts: &'a [crate::config_model::DeclaredVerdict],
    /// The `[vocabulary]` word lists (CLOUD-1638).
    ///
    /// `None` where the consumer declared none, which is the same exemption the
    /// class grammar takes: a tree with no lists cannot satisfy membership, so
    /// holding its finding ids to them would be a demand with no fix available.
    pub words: Option<&'a crate::config_model::Vocabulary>,
    /// The `[[recorder]]` table (CLOUD-1051).
    ///
    /// Here for the reason stated above rather than as a third thing bolted on:
    /// it is config the consumer declares, fixed for the life of the load, and
    /// read at exactly the call sites that already hold this — the record a
    /// module reads is projected from it, so a caller with the patterns always
    /// has the recorders too. The alternative was a fifth positional on four
    /// public entry points, which is the shape this parameter exists to prevent.
    pub recorders: &'a [crate::config_model::RecorderDeclared],
    /// The `[[register]]` table (CLOUD-2005), read by a `reference` rule.
    ///
    /// Here for `recorders`' reason: config the consumer declares, fixed for the
    /// life of the load, and needed at the call sites that already hold this.
    pub registers: &'a [crate::register::DeclaredRegister],
    /// The `[[traversal]]` table (CLOUD-1868), walked once per run for
    /// `input.tree.traversals`.
    pub traversals: &'a [crate::traversal::DeclaredTraversal],
    /// The `[[record]]` table (CLOUD-1810).
    ///
    /// Here for the same reason `recorders` is, and it is the same question: a
    /// module reads a record projected from a DECLARATION, so a caller holding
    /// the recorders needs the verb-written families too or half the store is
    /// invisible to it. Carrying it on this struct is what keeps the arity of the
    /// four public entry points from growing again.
    pub records: &'a [crate::config_model::RecordDeclared],
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
        words: None,
        recorders: &[],
        registers: &[],
        traversals: &[],
        records: &[],
    };
}

impl<'a> From<&'a crate::config_model::Config> for Vocabulary<'a> {
    fn from(config: &'a crate::config_model::Config) -> Self {
        Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            words: (!config.vocabulary.is_empty()).then_some(&config.vocabulary),
            recorders: &config.recorders,
            registers: &config.registers,
            traversals: &config.traversals,
            records: &config.records,
        }
    }
}

/// The same four tables off a RESOLVED config (CLOUD-1638).
///
/// `check` and `enforce` resolve before they load, so a converter that only
/// took `Config` left every real run hand-rolling the struct — and the finding
/// grammar reached none of them, because the hand-rolled sites had no `words`.
impl<'a> From<&'a crate::resolve::Resolved> for Vocabulary<'a> {
    fn from(resolved: &'a crate::resolve::Resolved) -> Self {
        Vocabulary {
            patterns: &resolved.patterns,
            verdicts: &resolved.verdicts,
            words: (!resolved.vocabulary.is_empty()).then_some(&resolved.vocabulary),
            recorders: &resolved.recorders,
            registers: &resolved.registers,
            traversals: &resolved.traversals,
            records: &resolved.records,
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

/// Which source a policy row names: its `module`, `bundle` or `preset`.
///
/// Extracted from [`load`] rather than inlined, and the reason is the same one
/// that keeps it a refusal at all: `validate` already refuses a policy row naming
/// none of the three and one naming more than one, so this is the LOCATED
/// restatement — a caller reaching `load` directly cannot get a silent skip
/// instead of a refusal.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) for a policy row naming none of the three.
fn source_key(rule: &Rule) -> Result<&str> {
    rule.module
        .as_deref()
        .or(rule.bundle.as_deref())
        .or(rule.preset.as_deref())
        .ok_or_else(|| {
            UsageError::raise(format!(
                "rule `{}` is a policy row naming neither `module`, `bundle` nor `preset`",
                rule.id
            ))
        })
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
        words,
        recorders: _,
        registers: _,
        traversals: _,
        records: _,
    } = vocabulary;
    // The table is validated at PARSE, beside `verbs` and `redirects` and for
    // their reason (`config.rs`'s `VALIDATED_AT_LOAD` census asserts the call
    // site exists). Validating again here would be a second authority for one
    // question, which is the shape `rules-drift` exists to refuse.
    let pattern_data = crate::pattern::data_document(patterns);
    let pattern_text = PatternText::new();
    let data = (&pattern_data, &pattern_text);
    let declared_patterns: BTreeSet<&str> = patterns.iter().map(|p| p.id.as_str()).collect();
    // The refusal vocabulary (CLOUD-1050): the consumer's rows unioned with what
    // this binary ships. The vendored half is not optional politeness — a
    // preset reaches a consumer who wrote no `[[verdict]]` row at all, so
    // holding it to their table would make an enabled preset unloadable with no
    // fix available. Built only where a check reads it (`check_tables`).
    let (registry, tokens) = check_tables(verdicts, checks)?;
    let mut emitted: BTreeSet<String> = BTreeSet::new();
    // What each policy row raises, kept PER ROW as well as unioned into
    // `emitted` (CLOUD-1638). The union answers "is every declared class
    // raised"; the collapse predicate needs the other direction — how many
    // classes THIS row raises — and a set that has already been merged cannot
    // answer it.
    let mut per_rule: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut bundles = Vec::new();
    // Keyed on the scope's WORD rather than the enum, so this set does not oblige
    // `RuleScope` to carry `Ord` for one local lookup — the derive would be a
    // public-surface change made to satisfy a private detail.
    let mut seen: BTreeSet<(&str, &'static str)> = BTreeSet::new();
    // Every predicate id published so far, and the module that published it —
    // the value is what lets the collision refusal name BOTH sides, which is the
    // difference between a pointer and a complaint.
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for rule in rules.iter().filter(|r| r.kind == RuleKind::Policy) {
        let source_key = source_key(rule)?;
        // Two rows naming one source AT ONE SCOPE is dead config: the second
        // enablement decides nothing the first did not, and "which one denied
        // me" is not a question a reviewer should have to answer.
        //
        // THE KEY IS THE PAIR SINCE CLOUD-1672, and the scope half is what makes
        // a preset spanning two surfaces enableable at all. A rule row carries
        // one scope, so a preset deciding both is enabled by two rows — and
        // keyed on the name alone the second reads as the duplicate this refuses.
        // It is not: each row compiles the modules at its own scope, so they
        // share a name and decide disjoint surfaces. Narrower rather than looser
        // for a module or a bundle, where the pair still collapses to the name
        // in practice because those decide exactly one surface.
        if !seen.insert((source_key, rule.scope.as_str())) {
            return Err(UsageError::raise(format!(
                "rule `{}` registers `{source_key}` at scope `{}`, which another rule already \
                 registers at that scope",
                rule.id,
                rule.scope.as_str()
            )));
        }

        // The module comes from wherever the RULES came from, and that is the
        // whole of this branch. Under `--config-from <ref>` the authority is
        // read from the ref (`trust_pin::load_base`), so reading the module off disk
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
            let manifest = crate::preset_catalog::find(name).ok_or_else(|| {
                UsageError::raise(format!(
                    "rule `{}` enables the preset `{name}`, which this binary does not ship; \
                     the ones it does are {}",
                    rule.id,
                    preset_names().join(", ")
                ))
            })?;
            // THE SCOPE CHECK (CLOUD-1181) — AND WHAT IT DOES IS NOT WHAT THE
            // ROW PREDICTED, WHICH IS WORTH THE PARAGRAPH.
            //
            // The row expected a scope mismatch to produce an empty violation
            // set: modules read the other surface's `input.*` keys, read
            // undefined, refuse nothing, and a dead gate is byte-identical to a
            // clean tree. MEASURED, THAT WAS ALREADY REFUSED. With this branch
            // disabled and the binary rebuilt, enabling `trunk-based` at `tree`
            // still fails to load — `check_tree_paths_are_emittable` catches the
            // module reading `input.call` on the tree surface and says so.
            //
            // So this is not a hole being closed. What it buys is narrower and
            // still worth having: the refusal now PRECEDES compilation and names
            // the preset the consumer enabled, where the existing one names a
            // module inside the binary that the consumer never wrote and cannot
            // open. And the manifest's `scope` is a DECLARATION — the row's real
            // gap was that "a consumer enabling a preset today cannot see which
            // surface it decides", which no refusal fixes because it is a
            // question asked before anything is enabled.
            //
            // Stated rather than absorbed, because shipping this as "closes the
            // silent dead gate" would have been a claim about a channel nobody
            // measured, which is the defect `rules/policy-modules.md`
            // records against its own earlier revisions.
            //
            // SINCE CLOUD-1672 THE MANIFEST DECLARES A SCOPE PER MODULE, so the
            // question is no longer "does the preset's one scope equal this
            // row's" but "does ANY module here decide it". A preset spanning
            // both surfaces is enabled by two rows, one per scope, and each row
            // compiles only the modules at its own — which is what keeps a tree
            // module from being compiled onto the call surface, where it would
            // read keys the engine never builds there.
            check_preset_scope(rule, manifest, name)?;
            // The provider comparison (CLOUD-1625), in its own function for
            // `clippy::too_many_lines`: a nameable step lifted out whole, which is
            // the remedy `lib.rs` takes for the same lint rather than raising a cap.
            let mut sources: Vec<(String, String)> = preset_sources(rule, manifest, name)?;
            // THE HOT PATH STRIPS A PRESET'S CASES TOO, as `read_sources` does a
            // module's (#1276). It did not, so its key was the full text's while
            // every checked load keyed the stripped one: each mediated call
            // recompiled every preset row and overwrote the entry, and the next
            // `check` recompiled it back.
            if checks == ModuleChecks::SkipOnHotPath {
                for (_, text) in &mut sources {
                    *text = without_test_rules(text);
                }
            }
            let bundle = compile_for(root, &rule.id, &sources, data, checks)?;
            let declared = bundle.declared.clone();
            check_predicate_severity(rule, &declared, source_key)?;
            // A PRESET IS A MODULE TOO, and this branch's `continue` skipped the
            // tree-key check when it first landed. A tree-scoped row may name a
            // preset, so a preset reading an unemittable `input.tree` key would
            // have loaded as a dead gate — the exact failure the check exists to
            // refuse, arriving through the one source that bypasses it.
            if let Some(registry) = registry.as_deref() {
                let raised = (&mut emitted, &mut per_rule);
                check_loaded(
                    rule,
                    &bundle,
                    (&declared_patterns, None),
                    registry,
                    source_key,
                    raised,
                )?;
            }
            claim_ids(&mut ids, &declared, source_key)?;
            bundles.push(bundle.with_severity(rule));
            continue;
        }

        let paths = match (rule.module.as_deref(), rule.bundle.as_deref()) {
            (Some(module), _) => vec![module.to_owned()],
            (None, Some(bundle)) => bundle_members(root, bundle, reference, &rule.id)?,
            (None, None) => Vec::new(),
        };
        let sources = read_sources(root, &paths, reference, &rule.id, checks)?;
        if checks != ModuleChecks::SkipOnHotPath {
            check_finding_ids(&sources, words, &tokens)?;
        }

        // EVERYTHING PAST THE READ IS PURE, and the split is what lets the
        // composition property be tested without a filesystem: `compile` builds
        // one engine from N sources, which is the whole of CLOUD-837. The hot
        // path reads it from the bytecode cache when nothing it is a function
        // of has changed (CLOUD-2236).
        let bundle = compile_for(root, &rule.id, &sources, data, checks)?;
        let declared = bundle.declared.clone();

        // The pointer a bundle-level fault is reported against.
        let where_it_came_from = source_key;

        check_predicate_severity(rule, &declared, where_it_came_from)?;

        if let Some(registry) = registry.as_deref() {
            let raised = (&mut emitted, &mut per_rule);
            check_loaded(
                rule,
                &bundle,
                (&declared_patterns, Some(sources.as_slice())),
                registry,
                where_it_came_from,
                raised,
            )?;
        }

        claim_ids(&mut ids, &declared, where_it_came_from)?;

        bundles.push(bundle.with_severity(rule));
    }

    if checks == ModuleChecks::Run {
        check_no_vendored_collision(verdicts)?;
        check_registry_is_exhausted(verdicts, &emitted)?;
        check_collapse(rules, &per_rule, &tokens)?;
    }
    Ok(bundles)
}

/// The verdict registry and the collidable tokens, built exactly off the hot path
/// (CLOUD-2315): they feed `check_loaded`, `check_finding_ids` and
/// `check_collapse`, none of which runs there (CLOUD-885), and building them on
/// every hook call was 0.65 ms spent on nothing. `Some` registry is therefore
/// also what gates [`check_loaded`].
fn check_tables(
    verdicts: &[crate::config_model::DeclaredVerdict],
    checks: ModuleChecks,
) -> Result<(
    Option<Vec<crate::config_model::DeclaredVerdict>>,
    BTreeSet<String>,
)> {
    if checks == ModuleChecks::SkipOnHotPath {
        return Ok((None, BTreeSet::new()));
    }
    Ok((Some(registry_for(verdicts)?), collidable_tokens(verdicts)))
}

/// Refuse a preset enabled at a scope none of its modules decide (CLOUD-1181,
/// CLOUD-1672) — see the call site in [`load`] for why this precedes
/// compilation. Lifted out whole for `clippy::too_many_lines`.
fn check_preset_scope(
    rule: &Rule,
    manifest: &crate::preset_catalog::Manifest,
    name: &str,
) -> Result<()> {
    if manifest.decides(rule.scope) {
        return Ok(());
    }
    let decided: Vec<&str> = manifest
        .scopes()
        .into_iter()
        .map(crate::preset_catalog::RuleScope::as_str)
        .collect();
    Err(UsageError::raise(format!(
        "rule `{}` enables the preset `{name}` at scope `{}`, but its modules \
         decide {} — at the wrong scope they read keys the engine never builds, \
         so the rule would evaluate and refuse nothing",
        rule.id,
        rule.scope.as_str(),
        decided.join(" and ")
    )))
}

/// What a bundle's regex check reads: the declared pattern ids, and — for a
/// module row, never a preset — the sources, which may be copies `batten preset
/// eject` wrote (CLOUD-2290).
type Cited<'a> = (&'a BTreeSet<&'a str>, Option<&'a [(String, String)]>);

/// What a load records as raised: the union every closing check reads, and the
/// same per row for the collapse predicate (CLOUD-1638).
type Raised<'a> = (
    &'a mut BTreeSet<String>,
    &'a mut BTreeMap<String, BTreeSet<String>>,
);

/// The checks one loaded bundle owes off the hot path (CLOUD-885): the tree keys
/// it reads are emittable, it cites no inline regex, every class it raises is
/// declared, and what it raises is recorded for the load's own closing checks.
/// Lifted out of [`load`] whole, where both the preset and the module arm ran it,
/// for `clippy::too_many_lines`.
fn check_loaded(
    rule: &Rule,
    bundle: &Bundle,
    (declared_patterns, sources): Cited<'_>,
    registry: &[crate::config_model::DeclaredVerdict],
    source: &str,
    (emitted, per_rule): Raised<'_>,
) -> Result<()> {
    check_tree_paths_are_emittable(rule, bundle, source)?;
    // A `:=` the bytecode guard cannot cover would decide differently on the
    // hook path than under `policy test` (#1276), so it is a config fault here.
    if let Some(at) = bundle.ast().and_then(unguardable_assignment) {
        return Err(UsageError::raise(format!(
            "rule `{}`: `{at}` binds `:=` to a pattern naming no variable, which the bytecode \
             cannot guard against an undefined right side; bind a named variable, or test \
             definedness with `_ := e`",
            rule.id
        )));
    }
    // A module row's sources may be copies `batten preset eject` wrote
    // (CLOUD-2290); a preset arm passes none and takes the plain check.
    match sources {
        Some(sources) => check_copy_regex(rule, bundle, declared_patterns, source, sources)?,
        None => check_no_inline_regex(rule, bundle, declared_patterns, source)?,
    }
    check_verdicts_are_declared(rule, bundle, registry, source)?;
    record_raised(rule, bundle, emitted, per_rule);
    Ok(())
}

/// The pattern table's text and its digest, written once per load by the first
/// cache read that needs them (CLOUD-2315): every bundle's key and entry carry
/// the table, and each used to serialise it, then hash all of it, again.
type PatternText = std::cell::OnceCell<(String, [u8; 32])>;

/// One row's bundle: from the bytecode cache on the hot path, whose loads skip
/// every check that needs the interpreter's AST, and compiled from source
/// everywhere else (CLOUD-2236).
fn compile_for(
    root: &Path,
    id: &str,
    sources: &[(String, String)],
    (pattern_data, pattern_text): (&serde_json::Value, &PatternText),
    checks: ModuleChecks,
) -> Result<Bundle> {
    let (text, digest) = pattern_text.get_or_init(|| {
        let text = pattern_data.to_string();
        let digest = *blake3::hash(text.as_bytes()).as_bytes();
        (text, digest)
    });
    if checks == ModuleChecks::SkipOnHotPath {
        compile_cached(root, id, sources, pattern_data, (text, digest))
    } else {
        // EVERY LOAD DECIDES ON BYTECODE (#1276). A surface that reports
        // config faults still compiles from source, because its checks read
        // the interpreter's AST; the interpreter rides along for them and the
        // verdicts run on the program the hot path runs, from the same entry.
        // It used to stop here, so `check` and `enforce` interpreted every
        // bundle and the lap's live half spent most of its time in regorus's
        // tree walker with nothing recording it.
        let bundle = compile(id, sources, pattern_data)?;
        Ok(with_bytecode(
            root,
            (id, sources),
            (pattern_data, text, digest),
            bundle,
            true,
        ))
    }
}

/// Which of a preset's modules this row compiles, given the CI provider it
/// declares — refusing where that selection is empty (CLOUD-1625).
///
/// Lifted out of [`load`] whole rather than inlined: `clippy::too_many_lines`
/// refuses the flat function, and moving a nameable step is the remedy this
/// crate already takes for that lint instead of raising a cap.
fn preset_sources(
    rule: &Rule,
    manifest: &crate::preset_catalog::Manifest,
    name: &str,
) -> Result<Vec<(String, String)>> {
    // THE PROVIDER COMPARISON, AND UNLIKE THE SCOPE ONE ITS CALLER RUNS FIRST,
    // IT CLOSES A REAL HOLE (CLOUD-1625). That scope refusal's comment is candid
    // that `check_tree_paths_are_emittable` catches a wrong-surface
    // module downstream anyway. **Nothing downstream notices a consumer
    // on another CI provider**: `ci-hygiene`'s modules key on documents
    // carrying a `jobs:` mapping, which GitLab, Buildkite and a
    // Jenkinsfile all fail to produce, so the rule set evaluates over an
    // empty document set, refuses nothing, and reports clean. A dead gate
    // and a clean tree, byte-identical from outside.
    //
    // Per MODULE, not per manifest, because a preset can mix: `mise`
    // ships one module reading a step's `uses:` coordinate and one
    // deciding task argv on any host. Filtering rather than refusing the
    // whole preset is what keeps the second one working off GitHub.
    let declared_provider = rule.provider.as_deref();
    // AN `except` NAMING NO MODULE IS REFUSED (CLOUD-2290), because it excepts
    // nothing: the vendored module it meant to switch off keeps running beside
    // the copy that was meant to replace it, and the two collide or, worse, both
    // decide. Checked against the module's scope too, since a row compiles only
    // its own scope's modules and excepting one from the other scope is the same
    // no-op.
    if let Some(unknown) = rule.except.iter().find(|excepted| {
        manifest
            .module(excepted)
            .is_none_or(|module| module.scope != rule.scope)
    }) {
        let here: Vec<&str> = manifest
            .modules
            .iter()
            .filter(|module| module.scope == rule.scope)
            .map(crate::preset_catalog::PresetModule::name)
            .collect();
        return Err(UsageError::raise(format!(
            "rule `{}` excepts `{unknown}`, which the preset `{name}` does not ship at scope \
             `{}`; the modules there are {}",
            rule.id,
            rule.scope.as_str(),
            here.join(", ")
        )));
    }
    let sources: Vec<(String, String)> =
        manifest.modules_for(rule.scope, declared_provider, &rule.except);
    if sources.is_empty() && !rule.except.is_empty() {
        return Err(UsageError::raise(format!(
            "rule `{}` excepts every module the preset `{name}` compiles at scope `{}`, so it \
             decides nothing; delete the row instead",
            rule.id,
            rule.scope.as_str()
        )));
    }
    // REFUSED WHEN THE SELECTION IS EMPTY, for the reason the scope arm
    // refuses: a row that compiles no modules is a rule that decides
    // nothing, and shipping it silently is the state this row exists to
    // end. Named both ways — what the preset reads, and what the row
    // declared — so the reader can see which half to change.
    if sources.is_empty() {
        let reads: Vec<&str> = manifest.providers_at(rule.scope);
        let repair = provider_repair(&reads);
        return Err(UsageError::raise(format!(
            "rule `{}` enables the preset `{name}` at scope `{}`, but every module \
             there reads {}, and this row declares {} — on another provider those \
             modules match nothing and would report a clean tree they never read{repair}",
            rule.id,
            rule.scope.as_str(),
            reads.join(" and "),
            declared_provider.map_or_else(|| String::from("no provider"), |p| format!("`{p}`")),
        )));
    }
    Ok(sources)
}

/// The repair a provider refusal ends with (CLOUD-2658): the column and the
/// values the preset's modules read, so the reader does not have to know the
/// key. Empty when no module names a provider.
fn provider_repair(reads: &[&str]) -> String {
    let values: Vec<String> = reads
        .iter()
        .filter(|read| **read != "no provider")
        .map(|read| format!("provider = \"{read}\""))
        .collect();
    if values.is_empty() {
        return String::new();
    }
    format!("; declare it on the row as {}", values.join(" or "))
}

/// Read one row's declared module text, from the working tree or from a ref.
///
/// Split out of [`load`] when the hot-path strip below pushed that function past
/// the line ceiling, and the seam is where the I/O already was: everything past
/// this read is pure, which is what lets [`compile`]'s composition property be
/// tested without a filesystem.
/// Each source `batten preset eject` wrote, keyed by path, to the vendored
/// module source its header names (CLOUD-2290). A header naming nothing this
/// binary ships maps to nothing, so it exempts nothing.
fn ejected_originals(
    sources: &[(String, String)],
) -> BTreeMap<String, std::borrow::Cow<'static, str>> {
    sources
        .iter()
        .filter_map(|(path, text)| {
            let (preset, module, _) = crate::preset::ejected_from(text)?;
            let original = crate::preset_catalog::find(&preset)?
                .module(&module)?
                .text();
            Some((path.clone(), original))
        })
        .collect()
}

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
            None => crate::fsio::read_to_string(root.join(path)).map_err(|_| {
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
/// **Only verdict programs are compiled from its output**, which is what keeps
/// this from being a way to lose a test: the hot path's sources, and the
/// bytecode a checked load decides on (#1276). `policy test` compiles the full
/// text, and so does every load's interpreter that runs the module checks. A
/// stripped module is never the one anything is graded against.
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
    let mut packages = BTreeSet::new();
    for (path, source) in sources {
        let package = engine
            .add_policy(path.clone(), source.clone())
            .map_err(|err| UsageError::raise(format!("`{path}` does not compile: {err}")))?;
        // A PACKAGE OUTSIDE `data.batten` IS REFUSED, NOT SKIPPED (CLOUD-2696).
        // The one query this gate runs never reaches it, so live it decided
        // nothing and the call was allowed, while `policy test` evaluated its
        // cases directly and passed them: a module green under its own tests and
        // inert at the gate, with nothing to tell the two apart.
        let Some(relative) = relative_package(&package) else {
            return Err(UsageError::raise(format!(
                "`{path}` declares `{package}`, outside `data.batten`, so the gate's query \
                 never reaches it and it would decide nothing live; name it \
                 `package batten.<name>`"
            )));
        };
        packages.insert(relative);
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
    let smoke = Answer::of(&smoke);

    // WHAT THE BUNDLE PUBLISHES, read once. A bundle whose modules carry no
    // `rules` rule publishes nothing, which is exactly the pre-CLOUD-832 module
    // and is not an error — it simply cannot use the attributed shape.
    let declared = collect_strings(&smoke, &packages, RULES_RULE).ok_or_else(|| {
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
    for violation in collect_violations(&smoke, &packages).unwrap_or_default() {
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
        packages,
        // `Deny` until an enabling row says otherwise: `compile` is handed
        // sources rather than a rule, and the strict reading is the safe default
        // for the value that decides whether a refusal refuses.
        severity: crate::severity::RuleSeverity::Deny,
        predicate_severity: BTreeMap::new(),
        evaluator: Evaluator::Interpreted {
            engine: Box::new(engine),
            why: Fallback::NotOffered,
            detail: None,
        },
        described: std::sync::OnceLock::new(),
        ast: std::sync::OnceLock::new(),
        reads: std::sync::OnceLock::new(),
    })
}

/// Read the strings of every rule named `rule_name` in the bundle's packages.
///
/// **This is what pins the RULE NAME rather than the package** (CLOUD-837). The
/// query is rooted at `data.batten` and this reads `deny`, `violation` and
/// `rules` in every package a module declared under it — so `package batten.git`,
/// `package batten.ci` and `package batten.board` are all reachable, and 79
/// predicates need not share one flat namespace.
///
/// `None` is could-not-look at every call site, never "no denials": a member
/// whose value is neither a set nor an array decided nothing readable, and
/// guessing it is empty is CLOUD-251's vacuous pass.
fn collect_strings(
    answer: &Answer,
    packages: &BTreeSet<Vec<String>>,
    rule_name: &str,
) -> Option<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for value in package_members(answer, packages, rule_name) {
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
            // NO `Undefined` ARM: a package with no rule of this name is ABSENT
            // from both answers (`package_members` finds no member, and both
            // evaluators drop an undefined entry), so the arm had no input.
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
fn collect_deny_messages(answer: &Answer, packages: &BTreeSet<Vec<String>>) -> Option<Vec<String>> {
    collect_string_list(answer, packages, DENY_RULE)
}

/// Every string in a set- or array-valued rule named `rule` under the package,
/// or `None` for a shape this gate cannot read.
fn collect_string_list(
    answer: &Answer,
    packages: &BTreeSet<Vec<String>>,
    rule: &str,
) -> Option<Vec<String>> {
    let mut messages = Vec::new();
    for value in package_members(answer, packages, rule) {
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
fn collect_violations(answer: &Answer, packages: &BTreeSet<Vec<String>>) -> Option<Vec<Violation>> {
    let mut violations = Vec::new();
    for value in package_members(answer, packages, VIOLATION_RULE) {
        let items: Vec<&regorus::Value> = match value {
            regorus::Value::Set(items) => items.iter().collect(),
            regorus::Value::Array(items) => items.iter().collect(),
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
            // Optional like `subjects`; present and not a boolean is a dialect
            // this decoder does not have, so could-not-look.
            let counted = match object.get(&"counted".into()) {
                None | Some(regorus::Value::Undefined) => false,
                Some(raw) => raw.as_bool().ok().copied()?,
            };
            violations.push(Violation {
                rule,
                verdict: verdict.to_string(),
                subjects,
                counted,
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

/// Every value named `rule_name` that is a RULE of one of the bundle's own
/// packages (CLOUD-1969).
///
/// `package batten.git`'s rules appear as `{"git": {"deny": …}}` under
/// `data.batten`, so a package is an address into the result, and `packages` is
/// the set of addresses the bundle's modules declared — [`compile`] records each
/// one from `add_policy`'s own answer. The member is read AT that address and
/// nowhere below it.
///
/// **THIS USED TO BE A WALK OF EVERY OBJECT, AND THAT WAS THE DEFECT.** The walk
/// descended into any object-valued member on the premise that a helper rule
/// whose value is an object "finds nothing". A rule bound to a parsed document
/// is exactly such a helper, and a document is free to carry a `deny`,
/// `violation`, `rules` or `preapprove` key of its own. Measured:
/// a consumer module bound its harness settings file as a rule, and that file's
/// six-entry `permissions.deny` came back as six unattributed findings on a tree
/// the module judged clean. On the `preapprove` channel the same shape would have
/// been a GRANT authored by a data file. The `data` document does not say which
/// members are packages; the modules do, so the answer comes from them.
fn package_members<'a>(
    answer: &'a Answer,
    packages: &BTreeSet<Vec<String>>,
    rule_name: &str,
) -> Vec<&'a regorus::Value> {
    let mut found = Vec::new();
    match answer {
        Answer::Documents(roots) => {
            let rule = regorus::Value::from(rule_name);
            for root in roots {
                for package in packages {
                    if let Some(member) = at_package(root, package)
                        .and_then(|value| value.as_object().ok())
                        .and_then(|object| object.get(&rule))
                    {
                        found.push(member);
                    }
                }
            }
        }
        // Addressed by (package, rule) already, so the helper-document defect
        // above has no walk to enter: only a declared package's rule is read.
        Answer::Members(members) => {
            for package in packages {
                if let Some(member) = members.get(&(package.clone(), rule_name.to_owned())) {
                    found.push(member);
                }
            }
        }
    }
    found
}

/// One evaluation's answer, in the shape its evaluator produced it.
///
/// The interpreter answers the whole `data.batten` document; bytecode answers
/// each entry point, addressed by package and rule. [`package_members`] reads
/// both, so every collector above decides from either without knowing which.
#[derive(Clone)]
enum Answer {
    /// The `data.batten` documents of an interpreted query.
    Documents(Vec<regorus::Value>),
    /// Each defined `(package, rule)` entry point's value.
    Members(BTreeMap<(Vec<String>, String), regorus::Value>),
}

impl Answer {
    /// The documents an interpreted query returned.
    fn of(results: &regorus::QueryResults) -> Self {
        Self::Documents(
            results
                .result
                .iter()
                .flat_map(|result| result.expressions.iter().map(|e| e.value.clone()))
                .collect(),
        )
    }
}

/// How a bundle evaluates (CLOUD-2236).
#[derive(Clone)]
enum Evaluator {
    /// The interpreter, compiled from source in this process, and WHY it is not
    /// bytecode (#1276). Boxed: an engine is several times the size of the
    /// shared bytecode handle.
    Interpreted {
        engine: Box<regorus::Engine>,
        why: Fallback,
        /// What the bytecode compiler said, where it refused.
        detail: Option<std::sync::Arc<str>>,
    },
    /// Bytecode, read from the cache or compiled by this process. The
    /// interpreter rides along where a surface that reports config faults
    /// loaded it: its checks, `policy test` and the sweeps read the AST, which
    /// bytecode does not carry. It never decides a verdict here. Shared, so a
    /// bundle clone stays a refcount.
    Compiled(
        std::sync::Arc<Compiled>,
        Option<std::sync::Arc<regorus::Engine>>,
    ),
}

impl Evaluator {
    /// The interpreter, where this bundle has one: always for an interpreted
    /// bundle, and for bytecode loaded off the hot path.
    fn engine(&self) -> Option<&regorus::Engine> {
        match self {
            Self::Interpreted { engine, .. } => Some(engine.as_ref()),
            Self::Compiled(_, engine) => engine.as_deref(),
        }
    }
}

/// Why a bundle evaluates on the tree-walking interpreter rather than on
/// bytecode (#1276).
///
/// **A CLOSED SET, AND EVERY INTERPRETED BUNDLE CARRIES ONE.** `enforce` and
/// `check` once loaded every bundle interpreted with nothing recording it — the
/// bytecode cache served only the hook path — and the lap's live half spent
/// most of its 824 s in the interpreter unnoticed. A fallback is now a value the
/// type requires, read by `-vv`'s census and by the gate that holds every
/// shipped module on bytecode (`policy_execution`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fallback {
    /// Built by [`compile`] alone and never offered to the bytecode compiler:
    /// a test, analysis or lint surface that asked for the interpreter.
    NotOffered,
    /// The `:=` guard could not be spliced into the source
    /// ([`guarded_sources`]): the AST would not serialise, or an offset is not
    /// a character boundary.
    GuardUnavailable,
    /// A guarded module would not parse again.
    GuardedSourceRefused,
    /// The bundle defines none of the [`ANSWERED_RULES`], so no entry point
    /// exists to compile.
    NoAnsweredRule,
    /// The bytecode compiler refused a construct the bundle uses.
    CompileRefused,
    /// A partial set under an indexed reference (`f[k] contains v`), which the
    /// bytecode compiler accepts and answers wrongly ([`keyed_partial_set`]).
    KeyedPartialSet,
    /// A rule with an `else` body, which the bytecode drops after a body that
    /// iterates nothing ([`rule_else`]).
    RuleElse,
    /// A `policy test` case whose `with` modifiers the suite program cannot
    /// desugar ([`plan_suite`]): the bytecode compiler has no `with`.
    TestWith,
}

impl Fallback {
    /// The reason's stable token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotOffered => "not-offered",
            Self::GuardUnavailable => "guard-unavailable",
            Self::GuardedSourceRefused => "guarded-source-refused",
            Self::NoAnsweredRule => "no-answered-rule",
            Self::CompileRefused => "compile-refused",
            Self::KeyedPartialSet => "keyed-partial-set",
            Self::RuleElse => "rule-else",
            Self::TestWith => "test-with",
        }
    }
}

/// Which evaluator a bundle's verdicts run on (#1276).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Execution {
    /// Bytecode: `cached` when the program was read from the `.rvm` entry
    /// rather than compiled by this process.
    Bytecode {
        /// Read from the cache, not compiled here.
        cached: bool,
    },
    /// The interpreter, for this reason.
    Interpreted(Fallback),
}

impl std::fmt::Display for Execution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytecode { cached: true } => f.write_str("bytecode cached"),
            Self::Bytecode { cached: false } => f.write_str("bytecode compiled"),
            Self::Interpreted(why) => write!(f, "interpreter {}", why.as_str()),
        }
    }
}

/// Every verdict evaluation this process ran, per bundle and evaluator: the
/// census `-vv` prints and `policy_execution` gates. A counter, never a clock.
static EXECUTIONS: std::sync::Mutex<BTreeMap<(String, Execution), usize>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Count one verdict evaluation of `bundle`.
fn record_execution(bundle: &Bundle) {
    record_as(&bundle.id, bundle.execution());
}

/// Count one evaluation of bundle `id` against the evaluator `how` that ran it:
/// a verdict, or a `policy test` case, which decides that verb's verdict.
fn record_as(id: &str, how: Execution) {
    if let Ok(mut held) = EXECUTIONS.lock() {
        *held.entry((id.to_owned(), how)).or_insert(0) += 1;
    }
}

/// Every verdict evaluation this process has run: `(bundle id, evaluator,
/// count)`, by id (#1276).
#[must_use]
pub fn execution_census() -> Vec<(String, Execution, usize)> {
    EXECUTIONS.lock().map_or_else(
        |_| Vec::new(),
        |held| {
            held.iter()
                .map(|((id, how), count)| (id.clone(), *how, *count))
                .collect()
        },
    )
}

/// Evaluate `bundle` over `input`, reading only the rules named (CLOUD-2236).
///
/// The interpreter evaluates the whole package whatever is asked; bytecode runs
/// only the named rules' entry points, which is most of what it saves on a
/// call that asks one question.
///
/// `None` is could-not-look: the input will not parse or the bundle faults.
fn answer(bundle: &Bundle, input: &str, rules: &[&str]) -> Option<Answer> {
    record_execution(bundle);
    match &bundle.evaluator {
        Evaluator::Interpreted { engine, .. } => {
            let mut engine = engine.clone();
            engine.set_input_json(input).ok()?;
            let results = engine.eval_query(PACKAGE_QUERY.to_owned(), false).ok()?;
            Some(Answer::of(&results))
        }
        Evaluator::Compiled(compiled, _) => {
            if !Answers::open() {
                return compiled.answer(&regorus::Value::from_json_str(input).ok()?, rules);
            }
            // ONE VM PER BUNDLE PER INPUT, AND EACH FAULT ITS OWN RULE'S. The
            // first ask evaluates every rule; each later ask reads back exactly
            // what an unscoped call over its rules returns — could-not-look if
            // one of THEM faulted, else their members — so a sibling's fault
            // never reaches a verdict.
            if let Some(answer) = Answers::recall(compiled, input, |held| select(held, rules)) {
                return answer;
            }
            let evaluated = compiled.evaluate_all(&Answers::parsed(input)?)?;
            let answer = select(&evaluated, rules);
            Answers::keep(compiled, input, evaluated);
            answer
        }
    }
}

/// What an unscoped call over `rules` answers, read off a bundle's evaluation:
/// could-not-look if one of them faulted, else their members.
fn select(evaluated: &Evaluated, rules: &[&str]) -> Option<Answer> {
    let (faulted, members) = evaluated;
    if rules.iter().any(|rule| faulted.contains(*rule)) {
        return None;
    }
    Some(Answer::Members(
        members
            .iter()
            .filter(|((_, rule), _)| rules.contains(&rule.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

/// ONE EVALUATION PER BUNDLE PER CALL (CLOUD-2315).
///
/// A mediated call asked each bundle the same question with the same input up
/// to four times — `deny` from the adjudication, `deny` again for the advisory
/// half, `rewrite` for the grant, `preapprove` — and each ask built a VM, cloned
/// the data document and re-parsed the input. Measured on this repository: 64
/// evaluations over 19 bundles, 16.7 ms, on an allowed call against a 10 ms
/// budget. An answer is a pure function of the program and the input, so the
/// first ask evaluates every rule in one VM and a later ask reads it back. A
/// fault is recorded against its own rule and reaches only an ask that names
/// it: one rule's fault never reaches a sibling's verdict (code review of
/// CLOUD-2315), and evaluating per ask instead would build a VM per rule set.
///
/// **SCOPED, never process-wide**, for `HookLoads`' reason: the memo exists only
/// while an [`AnswerScope`] is alive, and `run_hook` holds the only one. Keyed
/// on the program's `Arc` — HELD in the key, so its address cannot be freed and
/// reused within the scope — and on the exact input text. Only bytecode is
/// memoised; the interpreter path is the rare fallback and is left as it was.
///
/// The INPUT is parsed once per call too: every bundle is handed the same
/// document text, and each used to parse it into a `regorus::Value` of its own.
/// Each distinct text is held once, with the evaluations over it.
struct Answers {
    /// Every distinct input the call asked over, held once with its parse and
    /// each bundle's evaluation over it: a call can ask over more than one
    /// document, and alternating between them must not cost the answers
    /// already had (code review of CLOUD-2315).
    inputs: Vec<Asked>,
}

/// One input's text, its parse, and every bundle evaluated over it.
type Asked = (
    String,
    regorus::Value,
    Vec<(std::sync::Arc<Compiled>, Evaluated)>,
);

/// One program over one input, every rule evaluated: the rules that faulted, and
/// what the rest defined.
type Evaluated = (
    BTreeSet<String>,
    BTreeMap<(Vec<String>, String), regorus::Value>,
);

thread_local! {
    static ANSWERS: std::cell::RefCell<Option<Answers>> = const { std::cell::RefCell::new(None) };
}

/// Every bytecode evaluation this process has run — a counter, never a clock,
/// for `engines_constructed`'s reason.
static BYTECODE_EVALUATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// How many bytecode evaluations this process has run (CLOUD-2315).
#[must_use]
pub fn bytecode_evaluations() -> usize {
    BYTECODE_EVALUATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The guard [`answer_scope`] returns: the memo dies with it.
#[derive(Debug)]
pub struct AnswerScope;

impl Drop for AnswerScope {
    fn drop(&mut self) {
        ANSWERS.with(|cell| *cell.borrow_mut() = None);
    }
}

/// Open the per-call answer memo for the life of the returned guard.
#[must_use]
pub fn answer_scope() -> AnswerScope {
    ANSWERS.with(|cell| {
        *cell.borrow_mut() = Some(Answers { inputs: Vec::new() });
    });
    AnswerScope
}

impl Answers {
    fn open() -> bool {
        ANSWERS.with(|cell| cell.borrow().is_some())
    }

    /// Which of the held inputs `input` is.
    fn input_at(&self, input: &str) -> Option<usize> {
        self.inputs.iter().position(|(text, _, _)| text == input)
    }

    /// `input` parsed, once per distinct text within the scope.
    fn parsed(input: &str) -> Option<regorus::Value> {
        ANSWERS.with(|cell| {
            let mut borrowed = cell.borrow_mut();
            let answers = borrowed.as_mut()?;
            if let Some(at) = answers.input_at(input) {
                return Some(answers.inputs[at].1.clone());
            }
            let value = regorus::Value::from_json_str(input).ok()?;
            answers
                .inputs
                .push((input.to_owned(), value.clone(), Vec::new()));
            Some(value)
        })
    }

    /// `read` over `compiled`'s evaluation of `input`, if it was evaluated: read
    /// under the borrow, so nothing unasked is copied out.
    fn recall<R>(
        compiled: &std::sync::Arc<Compiled>,
        input: &str,
        read: impl FnOnce(&Evaluated) -> R,
    ) -> Option<R> {
        ANSWERS.with(|cell| {
            let borrowed = cell.borrow();
            let answers = borrowed.as_ref()?;
            let at = answers.input_at(input)?;
            let (_, evaluated) = answers.inputs[at]
                .2
                .iter()
                .find(|(held, _)| std::sync::Arc::ptr_eq(held, compiled))?;
            Some(read(evaluated))
        })
    }

    /// Hold `compiled`'s evaluation over `input`, which [`Answers::parsed`] holds.
    fn keep(compiled: &std::sync::Arc<Compiled>, input: &str, evaluated: Evaluated) {
        ANSWERS.with(|cell| {
            if let Some(answers) = cell.borrow_mut().as_mut()
                && let Some(at) = answers.input_at(input)
            {
                answers.inputs[at]
                    .2
                    .push((std::sync::Arc::clone(compiled), evaluated));
            }
        });
    }
}

/// A bundle's bytecode, and what its load read off the source (CLOUD-2236).
///
/// # Why a hook call loads this instead of compiling
///
/// Every mediated call is a fresh process, and every one re-parsed and
/// re-compiled every enabled module and drove the smoke query over them:
/// measured on this repository, `policy::compile` was 21% of a call's
/// instructions and the smoke query 26%, and the parser raises an `anyhow`
/// error per backtracked production — 2,526 per call, each capturing a
/// backtrace under `RUST_BACKTRACE=1` (62 ms of a 205 ms p50). None of it
/// depends on the call: it is a function of the module text, the pattern table
/// and this binary. So the first call compiles as before, every check included,
/// and writes the result; later calls deserialize it.
///
/// # What the key covers
///
/// [`cache_key`] digests the format, this binary's identity, the row id, every
/// module's path and text, and the data document. A change to any of them is a
/// different key, so a stale entry is never read — it is a miss, and the miss
/// rewrites it. Nothing here weakens a check: [`compile`] still validates a
/// bundle the first time its key is seen.
///
/// # What stays interpreted
///
/// A bundle the bytecode compiler cannot express — two tree-scope modules
/// today, measured: a `some … in` it does not hoist, and a partial object rule
/// with nested bracket keys — is simply not cached and keeps the interpreter.
/// Answers agree where both run: `bytecode_answers_as_the_interpreter_does`.
pub(crate) struct Compiled {
    program: std::sync::Arc<regorus::rvm::program::Program>,
    /// The pattern table, set as the VM's `data` exactly as `compile` sets it.
    data: regorus::Value,
    /// Every `(package, rule)` the bundle defines among the rules read.
    entries: BTreeSet<(Vec<String>, String)>,
    /// The session-start facts the bundle reads, from [`Bundle::session_start_facts`].
    facts: Vec<String>,
    /// The tree keys the bundle reads, from [`Bundle::tree_reads`]; `None` is
    /// [`Reads::Opaque`] (step 13a). Bytecode carries no AST, so the reading is
    /// taken when the entry is written, as `facts` is.
    reads: Option<Vec<String>>,
    /// Read from the `.rvm` entry rather than compiled by this process.
    cached: bool,
}

/// The text bytecode is compiled from: each module as written, with every `:=`
/// statement followed by a check that what it bound is defined (#1276,
/// CLOUD-2696).
///
/// **THE BYTECODE COMPILER DROPS A GUARD THE LANGUAGE REQUIRES.** regorus 0.15
/// (and its `main`) emits `Guard NotUndefined` after every binding context but
/// `:=` — `PlanContext::require_defined_values` in its `destructuring.rs` omits
/// `ColonAssignment` — so `x := f(a)` with `f` undefined for `a` binds
/// `Undefined` and the body runs on, where OPA and regorus's own interpreter
/// fail it. Under a `not` over `x` that is a violation no case raises
/// (`an_undefined_helper_decides_alike_in_both_evaluators`).
///
/// The guard is restored at the source: after each such statement, `; v == v`
/// for every variable its left side binds. An equality over `Undefined` fails
/// the body exactly as the missing guard would have, and over a defined value
/// it holds. Only the program is compiled from this text; the interpreter,
/// `policy test` and every pointer keep the module as written, so ONE evaluator
/// decides, once, from the cached program. CLOUD-2696's first answer re-decided
/// every bytecode refusal by compiling an interpreter from source, which cost
/// every refusing or advising hook call a parse (measured 1.68× on `wired`).
///
/// `None` is could-not-look: the AST would not serialize, or an offset is not a
/// boundary of its module's text. The bundle then stays interpreted.
fn guarded_sources(engine: &regorus::Engine) -> Option<Vec<(String, String)>> {
    guarded_sources_of(&Ast::of(engine)?)
}

/// One engine's modules as `Engine::get_ast_as_json` renders them, parsed once
/// (CLOUD-2830).
///
/// SHARED BY EVERY READING OF ONE ENGINE. The refusals of regorus's known
/// miscompiles and the `:=` guard each read the same AST, and each once
/// rendered it to pretty JSON and parsed it back: four renders per verdict
/// program and five per suite program, measured at 26% of `policy test`'s
/// samples against main's one. Built once per engine and handed to each, the
/// answers are the same and the render is paid once.
struct Ast(Vec<serde_json::Value>);

impl Ast {
    /// `engine`'s modules, or `None` where the AST will not serialise.
    fn of(engine: &regorus::Engine) -> Option<Self> {
        let json = engine.get_ast_as_json().ok()?;
        serde_json::from_str(&json).ok().map(Self)
    }
}

/// [`guarded_sources`] over an [`Ast`] already in hand.
fn guarded_sources_of(ast: &Ast) -> Option<Vec<(String, String)>> {
    let policies = &ast.0;
    let mut out = Vec::with_capacity(policies.len());
    for policy in policies {
        let source = policy.get("source")?;
        let path = source.get("file")?.as_str()?.to_owned();
        let mut text = source.get("contents")?.as_str()?.to_owned();
        let mut guards = Vec::new();
        colon_assignments(policy.get("ast")?, &mut guards);
        // Every guard as text edits `(offset, bytes replaced, text)`.
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for guard in guards {
            // A STRING LITERAL'S SPAN STOPS BEFORE ITS CLOSING DELIMITER (#1276):
            // regorus's span of `"x"` ends before the closing quote, so a
            // statement ending `p := "x"` ended one byte early and the guard
            // landed INSIDE the string — `p` bound `"x; p == p"`. The
            // interpreter never saw it; the bytecode did, and
            // `rules-drift.rego` answered differently.
            let end = match text.as_bytes().get(guard.end) {
                Some(b'"' | b'`') => guard.end + 1,
                _ => guard.end,
            };
            // A BRACELESS BODY (`p if x := e`) TAKES ONE EXPRESSION, so the
            // statement and its guard are braced to stay one body.
            let braceless = text
                .get(..guard.start)?
                .trim_end()
                .strip_suffix("if")
                .is_some_and(|head| head.ends_with(|c: char| c.is_whitespace() || c == ')'));
            if braceless {
                edits.push((guard.start, 0, String::from("{ ")));
                edits.push((end, 0, format!("{} }}", guard.checks)));
            } else {
                edits.push((end, 0, guard.checks));
            }
            if let Some((at, name)) = guard.wildcard {
                edits.push((at, 1, name));
            }
        }
        // Spliced from the end, so each offset still holds when it is used; at
        // one offset the replacement first, so an insertion there (a brace
        // before a renamed wildcard) lands in front of it, not inside it.
        edits.sort_by_key(|(at, replaced, _)| std::cmp::Reverse((*at, *replaced)));
        for (at, replaced, insert) in edits {
            if !text.is_char_boundary(at) || !text.is_char_boundary(at + replaced) {
                return None;
            }
            text.replace_range(at..at + replaced, &insert);
        }
        out.push((path, text));
    }
    Some(out)
}

/// Every input a bundle's own cases hand it: the term of each
/// `with input as <term>` modifier in its modules, evaluated by the interpreter
/// in the module's package so its helpers resolve (#1276).
///
/// **THE PARITY CORPUS.** Bytecode and interpreter must decide alike, and a
/// handful of fixed calls never reached the input that split them over an
/// undefined helper (CLOUD-2696). A module's cases are exactly the inputs its
/// author proved decisions over, so they are the inputs the two evaluators must
/// agree on. A term that reads a variable local to a function body (a case
/// helper's own parameters) does not stand alone and is not an input here.
///
/// `None` is could-not-look: a bundle with no interpreter, or an AST that will
/// not serialize. Each input is a JSON document.
#[must_use]
pub fn case_inputs(bundle: &Bundle) -> Option<Vec<String>> {
    let engine = bundle.evaluator.engine()?;
    let json = engine.get_ast_as_json().ok()?;
    let policies: Vec<serde_json::Value> = serde_json::from_str(&json).ok()?;
    let mut inputs = BTreeSet::new();
    for policy in &policies {
        let text = policy.get("source")?.get("contents")?.as_str()?;
        let ast = policy.get("ast")?;
        let package = reference_path(ast.get("package")?.get("refr")?)?;
        let mut terms = Vec::new();
        input_terms(ast, text, &mut terms);
        for term in terms {
            let mut probe = engine.clone();
            let module =
                format!("package {package}\n\nimport rego.v1\n\nbatten_case_input := {term}\n");
            if probe
                .add_policy(String::from("batten-case-input.rego"), module)
                .is_err()
            {
                continue;
            }
            let Ok(results) = probe.eval_query(format!("data.{package}.batten_case_input"), false)
            else {
                continue;
            };
            let value = results
                .result
                .first()
                .and_then(|result| result.expressions.first())
                .map(|expression| expression.value.clone());
            if let Some(value) = value.filter(|value| *value != regorus::Value::Undefined)
                && let Ok(document) = value.to_json_str()
            {
                inputs.insert(document);
            }
        }
    }
    Some(inputs.into_iter().collect())
}

/// The source text of every `with input as <term>` term under `node`.
fn input_terms(node: &serde_json::Value, text: &str, found: &mut Vec<String>) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(mods) = map.get("with_mods").and_then(serde_json::Value::as_array) {
                for modifier in mods {
                    let names_input = modifier
                        .get("refr")
                        .and_then(reference_path)
                        .is_some_and(|path| path == "input");
                    if let Some(term) = modifier
                        .get("as")
                        .filter(|_| names_input)
                        .and_then(|term| expr_text(term, text))
                    {
                        found.push(term.to_owned());
                    }
                }
            }
            for value in map.values() {
                input_terms(value, text, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                input_terms(item, text, found);
            }
        }
        _ => {}
    }
}

/// An expression's own source text, by the span of its single variant.
fn expr_text<'t>(expr: &serde_json::Value, text: &'t str) -> Option<&'t str> {
    let span = expr.as_object()?.values().next()?.get("span")?;
    let start = usize::try_from(span.get("start")?.as_u64()?).ok()?;
    let end = usize::try_from(span.get("end")?.as_u64()?).ok()?;
    text.get(start..end)
}

/// Every `:=` statement under `node`: the byte offset its statement ends at,
/// with the guard that goes there.
fn colon_assignments(node: &serde_json::Value, found: &mut Vec<Guard>) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(stmts) = map.get("stmts").and_then(serde_json::Value::as_array) {
                found.extend(stmts.iter().filter_map(statement_guard));
            }
            for value in map.values() {
                colon_assignments(value, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                colon_assignments(item, found);
            }
        }
        _ => {}
    }
}

/// A statement's guard, when it is a `:=` binding at least one named variable
/// or a bare `_` (renamed so the guard can name it):
/// `; v == v` per variable, at the statement's end — after any `with` modifier,
/// which the statement's span covers.
fn statement_guard(stmt: &serde_json::Value) -> Option<Guard> {
    let assign = stmt
        .get("literal")?
        .get("Expr")?
        .get("expr")?
        .get("AssignExpr")?;
    if assign.get("op")?.as_str()? != "ColEq" {
        return None;
    }
    let lhs = assign.get("lhs")?;
    let span = |node: &serde_json::Value, edge: &str| -> Option<usize> {
        usize::try_from(node.get("span")?.get(edge)?.as_u64()?).ok()
    };
    let mut vars = BTreeSet::new();
    bound_vars(lhs, &mut vars);
    vars.remove("_");
    // A BARE `_ := e` BINDS NOTHING A GUARD CAN NAME (#1276), and it is the
    // spelling of "e is defined" — `on_pull_request(path) if _ :=
    // triggers(path).pull_request`. Unguarded, the bytecode binds `Undefined`
    // and the rule holds for every path. The wildcard is renamed to a variable
    // the guard can test, which binds exactly what `_` did.
    let mut wildcard = None;
    if vars.is_empty() {
        let bare = lhs.get("Var")?;
        if bare.get("value")?.as_str()? != "_" {
            return None;
        }
        let at = span(bare, "start")?;
        let name = format!("__batten_defined_{at}");
        vars.insert(name.clone());
        wildcard = Some((at, name));
    }
    let mut checks = String::new();
    for var in &vars {
        checks.push_str("; ");
        checks.push_str(var);
        checks.push_str(" == ");
        checks.push_str(var);
    }
    Some(Guard {
        start: span(stmt, "start")?,
        end: span(stmt, "end")?,
        checks,
        wildcard,
    })
}

/// One `:=` statement's guard ([`statement_guard`]).
struct Guard {
    /// Where the statement starts and ends, in its module's bytes.
    start: usize,
    end: usize,
    /// `; v == v` for each variable it binds.
    checks: String,
    /// A bare `_` on the left, renamed: its offset and the name it takes.
    wildcard: Option<(usize, String)>,
}

/// The variables a binding pattern names: a bare variable, or each one inside
/// an array or object pattern.
fn bound_vars(node: &serde_json::Value, vars: &mut BTreeSet<String>) {
    if let Some(name) = node
        .get("Var")
        .and_then(|var| var.get("value"))
        .and_then(serde_json::Value::as_str)
    {
        vars.insert(name.to_owned());
        return;
    }
    match node {
        serde_json::Value::Object(map) => {
            for value in map.values() {
                bound_vars(value, vars);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                bound_vars(item, vars);
            }
        }
        _ => {}
    }
}

/// [`compile`] on the hot path, through the bytecode cache (CLOUD-2236).
///
/// A hit skips the parse, the compile and the smoke query: the entry was
/// written by a call that ran all three over exactly these sources. A miss runs
/// [`compile`] unchanged, so a broken module is refused exactly as before, and
/// then evaluates as bytecode — written for the next call, and used by this
/// one, so the answer a call gets never depends on whether the cache was warm.
/// A bundle the bytecode compiler cannot express stays interpreted.
///
/// The cache is best-effort by construction: an unwritable state directory or
/// an unreadable entry is a miss, never an error.
fn compile_cached(
    root: &Path,
    id: &str,
    sources: &[(String, String)],
    data: &serde_json::Value,
    (text, digest): (&str, &[u8; 32]),
) -> Result<Bundle> {
    let key = cache_key(id, sources, digest);
    if let Some(bundle) = cache_path(root, id)
        .as_deref()
        .and_then(|path| read_cached(path, &key, id, sources, text))
    {
        return Ok(bundle);
    }
    let bundle = compile(id, sources, data)?;
    Ok(with_bytecode(
        root,
        (id, sources),
        (data, text, digest),
        bundle,
        false,
    ))
}

/// `bundle`, freshly compiled from source, deciding on bytecode: the cached
/// program where the entry under its key holds one, else compiled here and
/// written for the next load. Where the bytecode compiler refuses, the bundle
/// stays interpreted and says why ([`Fallback`]).
///
/// `keep_ast` keeps the interpreter beside the program, for a surface whose
/// checks read the AST. The hot path drops it, so a miss and a hit hand the
/// mediated call the same shape of bundle.
fn with_bytecode(
    root: &Path,
    (id, sources): (&str, &[(String, String)]),
    (data, text, digest): (&serde_json::Value, &str, &[u8; 32]),
    bundle: Bundle,
    keep_ast: bool,
) -> Bundle {
    // ONE ENTRY PER ROW, WHOEVER LOADS IT. The hot path strips `test_` rules
    // before it keys ([`without_test_rules`]), so a checked load keys and
    // compiles its program from the same stripped text: otherwise the two
    // overwrite each other's entry and every load after a hook call is a miss.
    // The checked bundle keeps its full-text interpreter for `policy test`
    // and the checks; only the verdict program is the stripped one, which the
    // hot path already proves answers alike.
    let stripped: Vec<(String, String)>;
    let sources = if keep_ast {
        stripped = sources
            .iter()
            .map(|(path, text)| (path.clone(), without_test_rules(text)))
            .collect();
        &stripped[..]
    } else {
        sources
    };
    let key = cache_key(id, sources, digest);
    let path = cache_path(root, id);
    if keep_ast
        && let Some((_, compiled)) = path
            .as_deref()
            .and_then(|path| read_program(path, &key, text))
    {
        return compiled.into_bundle(bundle, keep_ast);
    }
    let program = if keep_ast {
        match compile(id, sources, data) {
            Ok(program) => {
                program.seed_stripped_from(&bundle);
                Some(program)
            }
            Err(err) => return interpreted_because(bundle, Fallback::CompileRefused, &err),
        }
    } else {
        None
    };
    let program = program.as_ref().unwrap_or(&bundle);
    let compiled = match Compiled::from_bundle(program, data) {
        Ok(compiled) => compiled,
        Err((why, detail)) => {
            if let Some(path) = path.as_deref() {
                remember_reads(path, &key, program);
            }
            return interpreted_because(bundle, why, &detail);
        }
    };
    if let Some(path) = path {
        write_cached(&path, &key, program, &compiled);
        // THE RETIRED LOCATION GOES ON A MISS (CLOUD-2315): format 1 wrote
        // beside the state rather than under `cache/`, and nothing reads it now.
        // Here, never on a hit, so the warm path pays nothing for the move.
        if let Ok(dir) = crate::state::repo_state_dir(&crate::git::canonical(root)) {
            let _ = std::fs::remove_dir_all(dir.join("policy"));
        }
    }
    compiled.into_bundle(bundle, keep_ast)
}

/// Every rule of `bundle` whose value over `input` differs between bytecode and
/// the interpreter, as `rule: bytecode <v> interpreter <v>` (#1276).
///
/// A diagnostic for localising a split the parity gate reports to the rule
/// that introduces it: every non-test rule becomes an entry point, so an
/// intermediate set that diverges is named rather than only the `violation`
/// it feeds. Empty where there is no interpreter or nothing compiles.
#[doc(hidden)]
#[must_use]
pub fn rule_splits(bundle: &Bundle, data: &serde_json::Value, input: &str) -> Vec<String> {
    use regorus::languages::rego::compiler::Compiler;
    let Some(source) = bundle.evaluator.engine() else {
        return Vec::new();
    };
    let Some(guarded) = guarded_sources(source) else {
        return Vec::new();
    };
    let mut engine = new_engine();
    let Ok(value) = regorus::Value::from_json_str(&data.to_string()) else {
        return Vec::new();
    };
    if engine.add_data(value.clone()).is_err() {
        return Vec::new();
    }
    for (path, text) in guarded {
        if engine.add_policy(path, text).is_err() {
            return Vec::new();
        }
    }
    let Some(first) = bundle.packages.iter().find_map(|package| {
        ANSWERED_RULES.iter().find_map(|rule| {
            engine
                .compile_with_entrypoint(&entry_point(package, rule).as_str().into())
                .ok()
        })
    }) else {
        return Vec::new();
    };
    let names: Vec<String> = first
        .get_rules()
        .keys()
        .map(ToString::to_string)
        .filter(|name| !name.rsplit('.').next().unwrap_or("").starts_with("test_"))
        .collect();
    let mut splits = Vec::new();
    let Ok(parsed) = regorus::Value::from_json_str(input) else {
        return Vec::new();
    };
    let mut engine = source.clone();
    if engine.set_input_json(input).is_err() {
        return Vec::new();
    }
    for name in names {
        let Ok(program) = Compiler::compile_from_policy(&first, &[name.as_str()]) else {
            splits.push(format!("{name}: bytecode refused"));
            continue;
        };
        let mut vm = regorus::rvm::vm::RegoVM::new();
        vm.load_program(program);
        vm.set_strict_builtin_errors(true);
        vm.set_max_instructions(usize::MAX);
        if vm.set_data(value.clone()).is_err() {
            continue;
        }
        vm.set_input(parsed.clone());
        let bytecode = vm.execute_entry_point_by_name(&name);
        let interpreted = engine.eval_rule(name.clone());
        let shown = |v: &regorus::Value| format!("{v}");
        let (left, right) = (
            bytecode
                .as_ref()
                .map_or_else(|err| format!("fault {err:?}"), shown),
            interpreted
                .as_ref()
                .map_or_else(|err| format!("fault {err:?}"), shown),
        );
        if left == right {
            continue;
        }
        // Sets and arrays as their difference, so a long answer names what
        // differs rather than a prefix the two share.
        let members = |v: &regorus::Value| -> Option<BTreeSet<String>> {
            match v {
                regorus::Value::Set(items) => Some(items.iter().map(shown).collect()),
                regorus::Value::Array(items) => Some(items.iter().map(shown).collect()),
                _ => None,
            }
        };
        let cut = |s: &str| s.chars().take(600).collect::<String>();
        if let (Ok(a), Ok(b)) = (&bytecode, &interpreted)
            && let (Some(a), Some(b)) = (members(a), members(b))
        {
            let only = |x: &BTreeSet<String>, y: &BTreeSet<String>| {
                cut(&x.difference(y).cloned().collect::<Vec<_>>().join(" | "))
            };
            splits.push(format!(
                "{name}: only bytecode [{}] only interpreter [{}]",
                only(&a, &b),
                only(&b, &a)
            ));
        } else {
            splits.push(format!(
                "{name}: bytecode {} interpreter {}",
                cut(&left),
                cut(&right)
            ));
        }
    }
    splits
}

/// The first rule whose head is a partial SET under an indexed reference —
/// `f[k] contains v` — as `path:line`, or `None` (#1276).
///
/// regorus 0.15's bytecode compiler accepts the head and answers it as the
/// flat set of every `v`, dropping the keys
/// (`a_keyed_partial_set_is_refused_bytecode_rather_than_flattened`). A
/// miscompile it does not refuse, so batten refuses it: the bundle stays on
/// the interpreter with [`Fallback::KeyedPartialSet`]. Also `None` where the AST
/// will not serialise, which [`guarded_sources`] then reports.
fn keyed_partial_set(ast: &Ast) -> Option<String> {
    first_construct(ast, &|map| {
        let head = map.get("Set")?;
        head.get("refr")?.get("RefBrack")?;
        head.get("span")?.get("line")?.as_u64()
    })
}

/// The first `else` following a body that can ITERATE, as `path:line`, or
/// `None` (#1276).
///
/// regorus 0.15's bytecode drops an `else` after a body that fails by
/// iterating nothing — `release-tracking.rego`'s `first_job(path)` answered
/// `""` interpreted and undefined on bytecode, so a finding vanished. A body
/// failing on a comparison or an undefined call keeps it
/// (`a_rule_else_after_an_empty_iteration_is_lost_on_bytecode` pins both).
/// So an `else` is refused when a body before it holds a `some`, an `every`,
/// or a bracket index by a variable — every spelling of iteration, and some
/// that only look up, which costs the interpreter's speed and never a verdict.
fn rule_else(ast: &Ast) -> Option<String> {
    fn iterates(node: &serde_json::Value) -> bool {
        match node {
            serde_json::Value::Object(map) => {
                ["SomeIn", "SomeVars", "Every"]
                    .iter()
                    .any(|key| map.contains_key(*key))
                    || map
                        .get("RefBrack")
                        .and_then(|brack| brack.get("index"))
                        .is_some_and(|index| index.get("Var").is_some())
                    || map.values().any(iterates)
            }
            serde_json::Value::Array(items) => items.iter().any(iterates),
            _ => false,
        }
    }
    first_construct(ast, &|map| {
        let bodies = map.get("bodies")?.as_array()?;
        let is_else =
            |body: &serde_json::Value| body.get("is_else").and_then(serde_json::Value::as_bool);
        let at = bodies.iter().position(|body| is_else(body) == Some(true))?;
        bodies[..at]
            .iter()
            .any(|body| body.get("query").is_some_and(iterates))
            .then(|| bodies[at].get("span")?.get("line")?.as_u64())?
    })
}

/// The first `:=` the guard splice cannot cover, as `path:line`, or `None`
/// (#1276): a left side binding no variable the guard can name and not a bare
/// `_` — `[_, _] := e`, `{"k": _} := e`.
///
/// Every other `:=` is guarded ([`statement_guard`]), which is what makes the
/// bytecode fail its body over an undefined right side as the interpreter does
/// (CLOUD-2696). This shape would bind `Undefined` unguarded, so a module using
/// it is refused at load ([`check_loaded`]) rather than decided differently on
/// the hook path, and never compiled to bytecode.
fn unguardable_assignment(ast: &Ast) -> Option<String> {
    first_construct(ast, &|map| {
        let assign = map
            .get("literal")?
            .get("Expr")?
            .get("expr")?
            .get("AssignExpr")?;
        if assign.get("op")?.as_str()? != "ColEq" {
            return None;
        }
        let lhs = assign.get("lhs")?;
        if lhs
            .get("Var")
            .and_then(|var| var.get("value"))
            .and_then(serde_json::Value::as_str)
            .is_some()
        {
            return None;
        }
        let mut vars = BTreeSet::new();
        bound_vars(lhs, &mut vars);
        vars.remove("_");
        if !vars.is_empty() {
            return None;
        }
        map.get("span")?.get("line")?.as_u64()
    })
}

/// The first AST object `matches` answers a line for, as `path:line`.
fn first_construct(
    ast: &Ast,
    matches: &dyn Fn(&serde_json::Map<String, serde_json::Value>) -> Option<u64>,
) -> Option<String> {
    fn found(
        node: &serde_json::Value,
        matches: &dyn Fn(&serde_json::Map<String, serde_json::Value>) -> Option<u64>,
    ) -> Option<u64> {
        match node {
            serde_json::Value::Object(map) => {
                matches(map).or_else(|| map.values().find_map(|value| found(value, matches)))
            }
            serde_json::Value::Array(items) => items.iter().find_map(|item| found(item, matches)),
            _ => None,
        }
    }
    ast.0.iter().find_map(|policy| {
        let line = found(policy.get("ast")?, matches)?;
        let path = policy.get("source")?.get("file")?.as_str()?;
        Some(format!("{path}:{line}"))
    })
}

/// Every `input` path `bundle`'s non-test rules read, dotted (`facts.land-live`,
/// `call.command`), from the [`describe`] reading; empty without an
/// interpreter (#1276).
///
/// What the parity gate sets to `null` and removes in each case input: a
/// builtin over a fact that is null or absent is where the two evaluators part
/// (a `concat` over a `null` element faults the bytecode's whole bundle where
/// the interpreter reads the call as undefined), and a module's own cases
/// rarely pass a null.
#[doc(hidden)]
#[must_use]
pub fn input_paths(bundle: &Bundle) -> Vec<String> {
    let Some(described) = bundle.described() else {
        return Vec::new();
    };
    let paths: BTreeSet<String> = described
        .iter()
        .flat_map(|module| &module.rules)
        .filter(|rule| !rule.name.starts_with("test_"))
        .flat_map(|rule| rule.input_paths.iter().cloned())
        .collect();
    paths.into_iter().collect()
}

/// Every `input` path the non-test rules of the one module `source` read,
/// dotted as [`input_paths`] renders them, or `None` when it will not parse or
/// cannot be described (CLOUD-2789).
///
/// What an admission's epoch is narrowed to (`epoch::for_rule`): a module row
/// compiles from its one file, so these paths are the whole of what its input
/// can hand it. Parsed, never compiled against a table: the question is which
/// names the code reads, not what they evaluate to.
pub(crate) fn module_input_paths(path: &str, source: &str) -> Option<BTreeSet<String>> {
    let mut engine = new_engine();
    engine.add_policy(path.to_owned(), source.to_owned()).ok()?;
    let described = describe(&engine)?;
    Some(
        described
            .iter()
            .flat_map(|module| &module.rules)
            .filter(|rule| !rule.name.starts_with("test_"))
            .flat_map(|rule| rule.input_paths.iter().cloned())
            .collect(),
    )
}

/// `bundle`, still on its interpreter, recording why.
fn interpreted_because(bundle: Bundle, why: Fallback, detail: &dyn std::fmt::Display) -> Bundle {
    let Evaluator::Interpreted { engine, .. } = bundle.evaluator else {
        return bundle;
    };
    Bundle {
        evaluator: Evaluator::Interpreted {
            engine,
            why,
            detail: Some(detail.to_string().into()),
        },
        ..bundle
    }
}

/// What an entry's body records beside the bytecode, on its first line.
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheHeader {
    declared: BTreeSet<String>,
    packages: BTreeSet<Vec<String>>,
    entries: BTreeSet<(Vec<String>, String)>,
    facts: Vec<String>,
    /// The tree read set (step 13a); absent reads as [`Reads::Opaque`].
    #[serde(default)]
    reads: Option<Vec<String>>,
}

/// The cache format; a change to [`CacheHeader`] or to how bytecode is written
/// bumps it, which makes every older entry a miss. `2` since the entry moved
/// onto `crate::cache` (CLOUD-2315): the key left the header for the entry's own
/// key line, and the binary is identified by its build ID. `3` keys the pattern
/// table by its digest rather than its text. `4` records the tree read set
/// (step 13a), without which a bytecode bundle can only answer `Opaque`.
const CACHE_FORMAT: &str = "batten-policy-rvm-5";

/// The entry for row `id`, under the repository's cache directory: one file per
/// row, overwritten on a miss, so the cache never grows past the row count.
fn cache_path(root: &Path, id: &str) -> Option<std::path::PathBuf> {
    // Resolved once per root, not once per row (CLOUD-2315): every bundle of a
    // load asked, and each answer canonicalised the root, derived the state
    // directory and probed the cache directory again.
    // Keyed by the state root too, which a test moves under one process, and by
    // the working directory where `root` is relative — the hook hands `.`, which
    // names a different repository after a `chdir` (code review of CLOUD-2315).
    type Asked = (std::path::PathBuf, std::path::PathBuf);
    type Held = Option<(Asked, Option<std::path::PathBuf>)>;
    thread_local! {
        static DIR: std::cell::RefCell<Held> = const { std::cell::RefCell::new(None) };
    }
    let asked: Asked = (
        std::path::absolute(root).ok()?,
        crate::state::state_root().ok()?,
    );
    let dir = DIR.with(|cell| {
        let mut held = cell.borrow_mut();
        if let Some((for_asked, dir)) = held.as_ref()
            && *for_asked == asked
        {
            return dir.clone();
        }
        // Canonical first: the hook hands `.`, and the state directory is named
        // from the repository's own directory, which `.` does not carry.
        let dir = crate::state::repo_state_dir(&crate::git::canonical(root))
            .ok()
            .and_then(|dir| crate::cache::root_under(&dir))
            .map(|cache| cache.join("policy"));
        *held = Some((asked, dir.clone()));
        dir
    })?;
    Some(dir.join(format!("{}.rvm", blake3::hash(id.as_bytes()).to_hex())))
}

/// The key an entry must carry to be read: everything the bytecode is a
/// function of, through `crate::cache::key`, which adds the format and the
/// running binary's build ID — so a rebuild that changes the code, a regorus bump
/// included, is a miss, and a relink to identical code is not. The pattern
/// table enters by its digest, taken once per load, which names its content
/// exactly as its text would.
fn cache_key(id: &str, sources: &[(String, String)], data: &[u8; 32]) -> String {
    let mut fields: Vec<&[u8]> = Vec::with_capacity(2 + 2 * sources.len());
    fields.push(id.as_bytes());
    for (path, source) in sources {
        fields.push(path.as_bytes());
        fields.push(source.as_bytes());
    }
    fields.push(data);
    crate::cache::key(CACHE_FORMAT, &fields)
}

/// The data document as a `regorus::Value`, parsed once per distinct text
/// (CLOUD-2315): every bundle of one load shares the pattern table, and each
/// cache hit used to re-parse it. Keyed by the text itself, so a different
/// document can never be answered from this one.
fn data_value(text: &str) -> Option<regorus::Value> {
    thread_local! {
        static LAST: std::cell::RefCell<Option<(String, regorus::Value)>> =
            const { std::cell::RefCell::new(None) };
    }
    LAST.with(|cell| {
        let mut last = cell.borrow_mut();
        if let Some((held, value)) = last.as_ref()
            && held == text
        {
            return Some(value.clone());
        }
        let value = regorus::Value::from_json_str(text).ok()?;
        *last = Some((text.to_owned(), value.clone()));
        Some(value)
    })
}

/// The program the entry at `path` holds under `key`, with its header: `None`
/// for a miss, an unreadable entry, or one holding only a read set.
fn read_program(path: &Path, key: &str, data: &str) -> Option<(CacheHeader, Compiled)> {
    let bytes = crate::cache::read(path, key)?;
    let split = bytes.iter().position(|byte| *byte == b'\n')?;
    let (head, body) = bytes.split_at(split);
    let header: CacheHeader = serde_json::from_slice(head).ok()?;
    // Only a whole program: a partial one is regorus asking to recompile, and
    // none at all is an interpreted bundle's read set ([`remember_reads`]).
    let program = body.get(1..).filter(|program| !program.is_empty())?;
    let regorus::rvm::program::DeserializationResult::Complete(program) =
        regorus::rvm::program::Program::deserialize_binary(program).ok()?
    else {
        return None;
    };
    let compiled = Compiled {
        program: std::sync::Arc::new(program),
        data: data_value(data)?,
        entries: header.entries.clone(),
        facts: header.facts.clone(),
        reads: header.reads.clone(),
        cached: true,
    };
    Some((header, compiled))
}

/// The cached bundle for `id`, when the entry at `path` was written from
/// exactly these inputs.
fn read_cached(
    path: &Path,
    key: &str,
    id: &str,
    sources: &[(String, String)],
    data: &str,
) -> Option<Bundle> {
    let (header, compiled) = read_program(path, key, data)?;
    Some(Bundle {
        id: id.to_owned(),
        modules: sources
            .iter()
            .map(|(path, _)| Module { path: path.clone() })
            .collect(),
        declared: header.declared,
        packages: header.packages,
        severity: crate::severity::RuleSeverity::Deny,
        predicate_severity: BTreeMap::new(),
        evaluator: Evaluator::Compiled(std::sync::Arc::new(compiled), None),
        described: std::sync::OnceLock::new(),
        ast: std::sync::OnceLock::new(),
        reads: std::sync::OnceLock::new(),
    })
}

/// Seed interpreted `bundle`'s read set from the entry at `path` under `key`,
/// or describe it and write an entry holding it: the same [`CacheHeader`]
/// with no program after it, which [`read_cached`] never reads as bytecode.
///
/// THE HALF A ROW IS JUDGED IN IS READ OFF THIS SET ([`Bundle::tree_reads`]),
/// so a bundle the bytecode compiler cannot express, which every load
/// compiles afresh, still classifies once per key rather than once per half.
/// Best-effort like every entry: one that cannot be read or written costs a
/// description, never an answer.
fn remember_reads(path: &Path, key: &str, bundle: &Bundle) {
    let held = crate::cache::read(path, key).and_then(|bytes| {
        let head = bytes.split(|byte| *byte == b'\n').next()?;
        serde_json::from_slice::<CacheHeader>(head).ok()
    });
    if let Some(header) = held {
        let reads = header.reads.map_or(Reads::Opaque, |keys| {
            Reads::Known(keys.into_iter().collect())
        });
        let _ = bundle.reads.set(reads);
        return;
    }
    let header = CacheHeader {
        declared: bundle.declared.clone(),
        packages: bundle.packages.clone(),
        entries: BTreeSet::new(),
        facts: Vec::new(),
        reads: match bundle.tree_reads() {
            Reads::Known(keys) => Some(keys.into_iter().collect()),
            Reads::Opaque => None,
        },
    };
    let Ok(mut bytes) = serde_json::to_vec(&header) else {
        return;
    };
    bytes.push(b'\n');
    crate::cache::write(path, key, &bytes);
}

/// Write the entry for `bundle`, atomically; a failure leaves the next call a
/// miss, which costs it the compile and nothing else.
fn write_cached(path: &Path, key: &str, bundle: &Bundle, compiled: &Compiled) {
    let header = CacheHeader {
        declared: bundle.declared.clone(),
        packages: bundle.packages.clone(),
        entries: compiled.entries.clone(),
        facts: compiled.facts.clone(),
        reads: compiled.reads.clone(),
    };
    let (Ok(mut bytes), Ok(program)) = (
        serde_json::to_vec(&header),
        compiled.program.serialize_binary(),
    ) else {
        return;
    };
    bytes.push(b'\n');
    bytes.extend_from_slice(&program);
    crate::cache::write(path, key, &bytes);
}

/// The rule names any caller reads off a bundle's answer.
const ANSWERED_RULES: [&str; 5] = [
    DENY_RULE,
    VIOLATION_RULE,
    RULES_RULE,
    PREAPPROVE_RULE,
    REWRITE_RULE,
];

/// Whether the bytecode compiler's `err` refused an entry point for not being
/// defined, rather than a construct the bundle uses.
fn undefined_entry_point(err: &str) -> bool {
    ["not found", "undefined", "not a valid rule path"]
        .iter()
        .any(|words| err.contains(words))
}

/// The entry point a `(package, rule)` pair compiles to.
fn entry_point(package: &[String], rule: &str) -> String {
    let mut path = String::from(PACKAGE_QUERY);
    for segment in package {
        path.push('.');
        path.push_str(segment);
    }
    path.push('.');
    path.push_str(rule);
    path
}

impl Compiled {
    /// Compile `bundle`'s interpreter to bytecode, or say why the bytecode
    /// compiler cannot express it: the [`Fallback`] and the compiler's words.
    fn from_bundle(
        bundle: &Bundle,
        data: &serde_json::Value,
    ) -> std::result::Result<Self, (Fallback, String)> {
        // The constructs regorus 0.15 compiles WRONGLY rather than refusing:
        // batten refuses them, so a bundle using one decides on the
        // interpreter, which answers as OPA does (#1276).
        // ONE RENDER OF THE AST for the refusals and the guard (CLOUD-2830).
        let ast = bundle.ast();
        if let Some(ast) = ast {
            if let Some(at) = unguardable_assignment(ast) {
                return Err((Fallback::GuardUnavailable, at));
            }
            if let Some(at) = keyed_partial_set(ast) {
                return Err((Fallback::KeyedPartialSet, at));
            }
            if let Some(at) = rule_else(ast) {
                return Err((Fallback::RuleElse, at));
            }
        }
        Self::compile_guarded(bundle, data, ast)
    }

    /// [`Self::from_bundle`] without batten's refusals of known miscompiles:
    /// the cases that pin each refusal compile around it.
    #[cfg(test)]
    fn compile_unchecked(
        bundle: &Bundle,
        data: &serde_json::Value,
    ) -> std::result::Result<Self, (Fallback, String)> {
        Self::compile_guarded(bundle, data, bundle.ast())
    }

    /// The program compiled from `ast`'s guarded text, `ast` being `bundle`'s
    /// interpreter's, or `None` where it would not serialise.
    fn compile_guarded(
        bundle: &Bundle,
        data: &serde_json::Value,
        ast: Option<&Ast>,
    ) -> std::result::Result<Self, (Fallback, String)> {
        use regorus::languages::rego::compiler::Compiler;
        // `Debug`, not `Display`: the compiler's errors can render empty.
        let refused = |err: &dyn std::fmt::Debug| (Fallback::CompileRefused, format!("{err:?}"));
        // The program is compiled from the guarded text ([`guarded_sources`]),
        // over the same data the interpreter holds. `compile` already refused
        // a data document that will not load, so those two arms do not fire.
        let value = regorus::Value::from_json_str(&data.to_string()).map_err(|e| refused(&e))?;
        let mut engine = new_engine();
        engine.add_data(value.clone()).map_err(|e| refused(&e))?;
        if bundle.evaluator.engine().is_none() {
            return Err((Fallback::GuardUnavailable, String::from("no interpreter")));
        }
        let Some(guarded) = ast.and_then(guarded_sources_of) else {
            return Err((
                Fallback::GuardUnavailable,
                String::from("the AST would not serialise, or an offset is not a boundary"),
            ));
        };
        for (path, text) in guarded {
            engine
                .add_policy(path.clone(), text)
                .map_err(|e| (Fallback::GuardedSourceRefused, format!("{path}: {e}")))?;
        }
        let mut candidates = Vec::new();
        for package in &bundle.packages {
            for rule in ANSWERED_RULES {
                candidates.push((package.clone(), rule.to_owned()));
            }
        }
        // regorus prepares the whole rule set whichever entry point it is
        // handed, but refuses one the bundle does not define, so the first
        // defined candidate stands in for all of them.
        let mut last = None;
        let policy = candidates.iter().find_map(|(package, rule)| {
            engine
                .compile_with_entrypoint(&entry_point(package, rule).as_str().into())
                .map_err(|err| last = Some(format!("{err:?}")))
                .ok()
        });
        let Some(policy) = policy else {
            return Err(match last {
                // Every candidate refused for being undefined is a bundle with
                // nothing to answer; anything else is the compiler's refusal.
                // regorus 0.15 words an undefined entry point "not a valid rule
                // path", which neither older spelling matched.
                Some(err) if !undefined_entry_point(&err) => (Fallback::CompileRefused, err),
                other => (
                    Fallback::NoAnsweredRule,
                    other.unwrap_or_else(|| String::from("no package")),
                ),
            });
        };
        let rules = policy.get_rules();
        let entries: BTreeSet<(Vec<String>, String)> = candidates
            .into_iter()
            .filter(|(package, rule)| rules.contains_key(&entry_point(package, rule)))
            .collect();
        let names: Vec<String> = entries.iter().map(|(p, r)| entry_point(p, r)).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let program = Compiler::compile_from_policy(&policy, &names).map_err(|e| refused(&e))?;
        Ok(Self {
            program,
            data: value,
            cached: false,
            entries,
            facts: bundle
                .session_start_facts()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            reads: match bundle.tree_reads() {
                Reads::Known(keys) => Some(keys.into_iter().collect()),
                Reads::Opaque => None,
            },
        })
    }

    /// `bundle` evaluating through this bytecode rather than its interpreter,
    /// which it keeps for its AST readers where `keep_ast`.
    fn into_bundle(self, bundle: Bundle, keep_ast: bool) -> Bundle {
        let ast = match bundle.evaluator {
            Evaluator::Interpreted { engine, .. } if keep_ast => Some(std::sync::Arc::new(*engine)),
            Evaluator::Compiled(_, engine) if keep_ast => engine,
            _ => None,
        };
        Bundle {
            evaluator: Evaluator::Compiled(std::sync::Arc::new(self), ast),
            described: if keep_ast {
                bundle.described
            } else {
                std::sync::OnceLock::new()
            },
            ast: if keep_ast {
                bundle.ast
            } else {
                std::sync::OnceLock::new()
            },
            ..bundle
        }
    }

    /// Run the named rules' entry points over `input`.
    /// A VM over this program, `data` and `input`: one evaluation.
    fn vm(&self, input: &regorus::Value) -> Option<regorus::rvm::vm::RegoVM> {
        BYTECODE_EVALUATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut vm = regorus::rvm::vm::RegoVM::new();
        vm.load_program(self.program.clone());
        // The interpreter's semantics, not the VM's defaults: a builtin error
        // is an error, and no instruction budget cuts a module short — the
        // interpreter has none, and a budget hit would read as a fault.
        vm.set_strict_builtin_errors(true);
        vm.set_max_instructions(usize::MAX);
        vm.set_data(self.data.clone()).ok()?;
        vm.set_input(input.clone());
        Some(vm)
    }

    /// Every entry evaluated in one VM, each rule's fault recorded against that
    /// rule alone: a VM that faulted is replaced before the next entry runs, so
    /// no rule's answer is read off a VM a sibling left mid-fault.
    ///
    /// No module can be written to reach this: regorus's VM reads an error in
    /// a rule body as undefined, and what still propagates is a resource limit
    /// (none is set) or the VM's own inconsistency. The record is what keeps a
    /// scoped answer equal to an unscoped one by construction if one does.
    fn evaluate_all(&self, input: &regorus::Value) -> Option<Evaluated> {
        let mut vm = self.vm(input)?;
        let (mut faulted, mut members) = (BTreeSet::new(), BTreeMap::new());
        for (package, rule) in &self.entries {
            match vm.execute_entry_point_by_name(&entry_point(package, rule)) {
                Ok(regorus::Value::Undefined) => {}
                Ok(value) => {
                    members.insert((package.clone(), rule.clone()), value);
                }
                Err(_) => {
                    faulted.insert(rule.clone());
                    vm = self.vm(input)?;
                }
            }
        }
        Some((faulted, members))
    }

    fn answer(&self, input: &regorus::Value, rules: &[&str]) -> Option<Answer> {
        let mut vm = self.vm(input)?;
        let mut members = BTreeMap::new();
        for (package, rule) in &self.entries {
            if !rules.contains(&rule.as_str()) {
                continue;
            }
            let value = vm
                .execute_entry_point_by_name(&entry_point(package, rule))
                .ok()?;
            if value != regorus::Value::Undefined {
                members.insert((package.clone(), rule.clone()), value);
            }
        }
        Some(Answer::Members(members))
    }
}

/// The object a package occupies in a `data.batten` result, if the result has it.
///
/// Absent is ordinary rather than a fault: a package whose rules all came back
/// undefined contributes no key at all, which is the empty contribution.
fn at_package<'a>(root: &'a regorus::Value, package: &[String]) -> Option<&'a regorus::Value> {
    package.iter().try_fold(root, |value, segment| {
        value
            .as_object()
            .ok()?
            .get(&regorus::Value::from(segment.as_str()))
    })
}

/// A package path as `add_policy` reports it, relative to [`PACKAGE_QUERY`].
///
/// `data.batten` is the root (`[]`) and `data.batten.git.ci` is `["git", "ci"]`.
/// A package outside `data.batten` is `None`: the query never reaches it, so it
/// can contribute nothing to this gate, which is what an unreachable address
/// should mean.
fn relative_package(package: &str) -> Option<Vec<String>> {
    let rest = package.strip_prefix(PACKAGE_QUERY)?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let rest = rest.strip_prefix('.')?;
    Some(rest.split('.').map(ToOwned::to_owned).collect())
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
    deny_why(bundle, input).map_or(Look::CouldNotLook, Look::Is)
}

/// [`deny`], with the reason a could-not-look carries (CLOUD-2789): the tree
/// surface reports a module that could not look by rule AND reason, so the
/// reason has to survive the evaluation rather than fold into one variant.
///
/// # Errors
///
/// The could-not-look arms of [`deny`], each as a fixed phrase naming which.
pub fn deny_why(bundle: &Bundle, input: &str) -> Result<Vec<Violation>, String> {
    // ONE EVALUATION for both shapes, because the engine is the unit now: the
    // answer comes back once and is walked twice, rather than paying an
    // evaluation per rule name.
    denials(bundle, answer(bundle, input, &[DENY_RULE, VIOLATION_RULE]))
}

/// The violations an answer carries, or why it could not look: it carries none
/// readable, or names an id the bundle never declared.
fn denials(bundle: &Bundle, answered: Option<Answer>) -> Result<Vec<Violation>, String> {
    let Some(answered) = answered else {
        return Err(String::from(
            "the module faulted evaluating its input (an undefined reference or a runtime error)",
        ));
    };

    let mut violations = Vec::new();
    match collect_deny_messages(&answered, &bundle.packages) {
        Some(tokens) => violations.extend(tokens.into_iter().map(|verdict| Violation {
            rule: None,
            verdict,
            subjects: Vec::new(),
            counted: false,
        })),
        None => return Err(String::from("its `deny` set is not a set of strings")),
    }
    match collect_violations(&answered, &bundle.packages) {
        Some(entries) => {
            for entry in entries {
                if let Some(named) = entry.rule.as_deref()
                    && !bundle.declared.contains(named)
                {
                    return Err(format!(
                        "a violation names `{named}`, which the bundle never declared"
                    ));
                }
                violations.push(entry);
            }
        }
        None => return Err(String::from("its `violation` set has an unreadable entry")),
    }

    Ok(violations)
}

/// The ids of this bundle's rules that pre-approve the call (CLOUD-1949).
///
/// Could-not-look on a fault, on an unreadable shape, and on an id the bundle
/// never declared in `rules` — the same attribution rule [`deny`] applies, so a
/// pre-approval always names a declared, waivable, mutable predicate.
#[must_use]
pub fn preapprove(bundle: &Bundle, input: &str) -> Look<Vec<String>> {
    let Some(answered) = answer(bundle, input, &[PREAPPROVE_RULE]) else {
        return Look::CouldNotLook;
    };
    let Some(ids) = collect_string_list(&answered, &bundle.packages, PREAPPROVE_RULE) else {
        return Look::CouldNotLook;
    };
    if ids.iter().any(|id| !bundle.declared.contains(id.as_str())) {
        return Look::CouldNotLook;
    }
    Look::Is(ids)
}

/// One input key a granted call runs with, from a module's [`REWRITE_RULE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    /// The declared rule id that asked for it.
    pub rule: String,
    /// A [`REWRITABLE`] tool input key.
    pub key: String,
    /// The value the key takes.
    pub value: u64,
}

/// Whether a module may rewrite this tool input key ([`REWRITABLE`]).
#[must_use]
pub fn rewritable(key: &str) -> bool {
    REWRITABLE.contains(&key)
}

/// This bundle's rewrites for the call (CLOUD-2157).
///
/// Could-not-look on a fault, on an unreadable member, on an id the bundle never
/// declared, and on a key outside [`REWRITABLE`] or a value that is not a
/// non-negative integer — [`preapprove`]'s attribution rule, plus the allowlist.
/// The caller treats could-not-look as no rewrite: the call runs as written.
#[must_use]
pub fn rewrite(bundle: &Bundle, input: &str) -> Look<Vec<Rewrite>> {
    let Some(answered) = answer(bundle, input, &[REWRITE_RULE]) else {
        return Look::CouldNotLook;
    };
    let mut found = Vec::new();
    for value in package_members(&answered, &bundle.packages, REWRITE_RULE) {
        let items: Vec<regorus::Value> = match value {
            regorus::Value::Set(items) => items.iter().cloned().collect(),
            regorus::Value::Array(items) => items.iter().cloned().collect(),
            _ => return Look::CouldNotLook,
        };
        for item in items {
            let field = |name: &str| item[&regorus::Value::from(name)].clone();
            let text = |name: &str| field(name).as_string().ok().map(ToString::to_string);
            let (Some(rule), Some(key)) = (text("rule"), text("key")) else {
                return Look::CouldNotLook;
            };
            let Ok(value) = field("value").as_u64() else {
                return Look::CouldNotLook;
            };
            if !bundle.declared.contains(rule.as_str()) {
                return Look::CouldNotLook;
            }
            if !rewritable(&key) {
                return Look::CouldNotLook;
            }
            found.push(Rewrite { rule, key, value });
        }
    }
    Look::Is(found)
}

/// Every string a set- or array-valued rule named `rule` holds under the
/// package, for a verb that reads a bundle's NON-REFUSAL answer beside its
/// violations (CLOUD-1221).
///
/// **Not a second refusal channel, and that is why it is a different function
/// rather than a wider [`deny`].** `batten board check` evaluates the
/// `tracker-hygiene` preset over its own reading and prints a ready frontier
/// and a set of honest exclusions: the preset decides both, and neither is a
/// refusal, so neither may ride `violation` — the registry holds refusals, and
/// a frontier row declared as a class would read as one. What comes back here
/// never becomes a `Finding` and never moves an exit code by itself.
///
/// Could-not-look on a fault and on a shape this cannot read, for [`deny`]'s
/// reason: an empty answer and an unreadable one are different facts. An absent
/// rule is an EMPTY answer, which is `collect_string_list`'s reading of a
/// package that simply does not define it.
#[must_use]
pub fn strings(bundle: &Bundle, input: &str, rule: &str) -> Look<Vec<String>> {
    // An arbitrary rule name has no entry point, so this reads the interpreter
    // only — its callers load with every check, never from the cache. Not a
    // verdict evaluation, so it is not counted in [`execution_census`].
    let Some(engine) = bundle.evaluator.engine() else {
        return Look::CouldNotLook;
    };
    let mut engine = engine.clone();
    if engine.set_input_json(input).is_err() {
        return Look::CouldNotLook;
    }
    let Ok(answered) = engine.eval_query(PACKAGE_QUERY.to_owned(), false) else {
        return Look::CouldNotLook;
    };
    let answered = Answer::of(&answered);
    collect_string_list(&answered, &bundle.packages, rule).map_or(Look::CouldNotLook, Look::Is)
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
/// **A mediated-call row is judged too, and used not to be** (CLOUD-1279). This
/// clause previously read *"mediated-call rows are untouched — they read
/// `input.call` and `input.facts`"*, which is what such a module SHOULD read and
/// was never a reason nothing checked. An early return on every non-tree scope
/// left the class above open in the other direction: a `mediated_call` module
/// reading `input.tree.<anything>` loads clean, evaluates, refuses nothing, and
/// is byte-identical to a clean tree — CLOUD-845 exactly, reached through the
/// scope the guard declined to look at.
///
/// The asymmetry is real and is why this is two arms rather than one predicate.
/// On the tree surface the question is *which* key, because `tree_document`
/// emits a known set and a typo inside it is the likely error. On the mediated
/// surface the question is *whether* any `tree.` path appears at all, because
/// `hook::call_document` emits `{call, facts}` and never `tree` — so no key is
/// the right one and none has to be enumerated here.
///
/// It cannot refuse a correct module: reaching a key the document does not carry
/// is the whole defect, and a module that reads only what its own surface emits
/// never reaches either arm.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the offending key and the module path.
/// Pointer-only: never a line of the module body.
fn check_tree_paths_are_emittable(rule: &Rule, bundle: &Bundle, source: &str) -> Result<()> {
    let tree_scoped = rule.scope == crate::preset_catalog::RuleScope::Tree;
    let emittable = tree_keys();
    let Some(described) = bundle.described() else {
        // Could-not-look on the AST is not a refusal: `load` has already
        // compiled and smoke-queried this module, so a shape this reader does
        // not recognise is its own limitation, and failing the config over it
        // would make a reader upgrade a breaking change.
        return Ok(());
    };
    for module in described {
        for rule_ast in &module.rules {
            for path in &rule_ast.input_paths {
                let Some(key) = path.strip_prefix("tree.") else {
                    // THE TREE ROW READING THE OTHER SURFACE (CLOUD-1279). The
                    // mirror of the arm below, and it used to fall through here
                    // for a different reason: this loop only inspected what it
                    // could `strip_prefix("tree.")`, so a tree-scoped module
                    // reading `input.facts.receipts` was never looked at at all.
                    // `rules::tree_document` emits `tree` and `missing` and
                    // neither `facts` nor `call`, so those reads are undefined
                    // and the gate is silent — the same class, third direction.
                    if tree_scoped {
                        let head = path.split('.').next().unwrap_or(path);
                        if head == "facts" || head == "call" {
                            return Err(UsageError::raise(format!(
                                "rule `{}` registers `{source}`, whose module {} \
                                 reads `input.{head}` on the tree surface, where \
                                 the engine emits `tree` and never `{head}` — the \
                                 predicate would be undefined and the gate \
                                 silent. Move the row to `scope = \
                                 \"mediated_call\"`, or read a fact the tree \
                                 carries",
                                rule.id, module.path
                            )));
                        }
                    }
                    continue;
                };
                // Only the first segment names a key; `tree.documents["x"].y`
                // arrives here as `tree.documents`.
                let key = key.split('.').next().unwrap_or(key);
                if !tree_scoped {
                    // THE MEDIATED ARM (CLOUD-1279), and it enumerates nothing:
                    // `hook::call_document` emits `{call, facts}`, so every
                    // `tree.` path is unreachable here whatever it names — even
                    // one this engine emits perfectly well on the other surface,
                    // which is the case a key-set comparison would wave through.
                    return Err(UsageError::raise(format!(
                        "rule `{}` registers `{source}`, whose module {} reads \
                         `input.tree.{key}` on the mediated call, where the \
                         engine emits `call` and `facts` and never `tree` — the \
                         predicate would be undefined and the gate silent. Move \
                         the row to `scope = \"tree\"`, or read a fact the \
                         mediated call carries",
                        rule.id, module.path
                    )));
                }
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
/// Record what one bundle raised, in the two shapes the checks below need.
///
/// `emitted` answers "is every declared class raised"; `per_rule` answers how
/// many classes ONE row raises, which the collapse predicate needs and a set
/// already merged cannot give back (CLOUD-1638). Both arms of [`load`]'s loop
/// owe this, and a second copy is where the two drift.
fn record_raised(
    rule: &Rule,
    bundle: &Bundle,
    emitted: &mut BTreeSet<String>,
    per_rule: &mut BTreeMap<String, BTreeSet<String>>,
) {
    let classes = emitted_verdicts(bundle);
    per_rule
        .entry(rule.id.clone())
        .or_default()
        .extend(classes.iter().cloned());
    emitted.extend(classes);
}

/// Every class token a rule id could collide with: declared, live, and native.
///
/// A RETIRED class is excluded deliberately — its token is a tombstone rather
/// than a name in use, and refusing a row for spelling one would refuse a name
/// nothing answers to.
fn collidable_tokens(verdicts: &[crate::config_model::DeclaredVerdict]) -> BTreeSet<String> {
    // ALL THREE SOURCES. The consumer's rows, this binary's native sites, and
    // the VENDORED PRESETS — the third is the one that bites: `trunk push
    // forced` is a preset's class, and a set built from the first two refuses
    // a name the collapse arm requires.
    let vendored = crate::config_check::preset::verdict_rows();
    verdicts
        .iter()
        .filter(|entry| !entry.retired())
        .map(|entry| entry.id.clone())
        .chain(vendored.into_iter().map(|entry| entry.id))
        .chain(
            crate::verdict::native_tokens()
                .iter()
                .map(|token| (*token).to_owned()),
        )
        .collect()
}

/// Every finding id a module declares is a name in the grammar (CLOUD-1638).
///
/// # Why the SOURCE and not the compiled set
///
/// `Bundle::declared` is read back from the engine, and it is not a clean list
/// of finding ids: a module with a nested `rules` key — `module-layering`'s
/// `forbidden["rules"] contains "hook"` — surfaces `hook` there, so holding
/// that set to the grammar refuses a name no reader ever meets. The literals
/// are exact and every one of the 136 in this tree is written out, so the
/// source is both the simpler reader and the correct one.
///
/// # Why here at all
///
/// A module's `"rule":` is a FINDING name, not the `[[rule]]` row id —
/// `run-shape.rego` declares five under one row — and it is what the emitted
/// line and `policy rule` carry. Migrating the row ids alone would leave half
/// the names a reader meets as free-text kebab.
///
/// Two exemptions, both inherited rather than invented: a consumer declaring no
/// vocabulary is not held to it, and an id that IS a class token is governed by
/// the class registry, since a vendored preset may spell a word no consumer
/// declares.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the module and the id.
fn check_finding_ids(
    sources: &[(String, String)],
    vocabulary: Option<&crate::config_model::Vocabulary>,
    tokens: &BTreeSet<String>,
) -> Result<()> {
    let Some(grammar) = vocabulary else {
        return Ok(());
    };
    for (path, text) in sources {
        for id in finding_ids(text) {
            if tokens.contains(&id) {
                continue;
            }
            crate::verdict::check_rule_id(&id, grammar)
                .map_err(|error| UsageError::raise(format!("`{path}` declares `{id}`: {error}")))?;
        }
    }
    Ok(())
}

/// The finding ids a module's SOURCE declares, in declaration order.
///
/// Both spellings the engine honours: `rules contains "<id>"`, which publishes
/// the id, and a violation's `"rule": "<id>"`, which names it. Read as literals
/// because every one of them is written out — a computed id would be invisible
/// here, and is also invisible to a reader of the module, which is the same
/// objection.
pub(crate) fn finding_ids(text: &str) -> BTreeSet<String> {
    /// The first double-quoted run after `from`, if the line has one.
    fn quoted(line: &str, from: usize) -> Option<&str> {
        let rest = line.get(from..)?;
        let open = rest.find('"')?;
        let after = rest.get(open + 1..)?;
        let close = after.find('"')?;
        after.get(..close)
    }

    let mut ids = BTreeSet::new();
    // PER LINE, because both spellings are single-line literals and a reader
    // scanning across them runs from one declaration into the next — measured,
    // on the first draft of this function, which spliced `violation contains {`
    // into an id and reported it as an undeclared subject.
    for line in text.lines() {
        // AT THE START OF THE LINE. `rules contains` is a substring of
        // `named_rules contains`, and `rules-drift.rego` has one — a reader
        // matching anywhere took `path` out of its `{"path": path, …}` body.
        if let Some(rest) = line.strip_prefix("rules contains ")
            && let Some(id) = quoted(rest, 0)
        {
            ids.insert(id.to_owned());
        }
        // `"rule":` must be followed by a STRING. A module's own test fixtures
        // carry `"rule": [{"id": "r", …}]` — the consumer's `[[rule]]` TABLE as
        // input — and a reader taking the next quoted run out of that returns
        // `id`, which is what the first draft reported as a one-word name.
        if let Some(at) = line.find("\"rule\"")
            && let Some(colon) = line.get(at..).and_then(|rest| rest.find(':'))
            && line
                .get(at + colon + 1..)
                .is_some_and(|rest| rest.trim_start().starts_with('"'))
            && let Some(id) = quoted(line, at + colon)
        {
            ids.insert(id.to_owned());
        }
    }
    ids
}

/// One name where a rule and a class name one thing (CLOUD-1638).
///
/// # The predicate is a property of the PAIR, in both directions
///
/// A rule's `id` equals a class token **iff** the rule raises exactly one class
/// **and** that class has exactly one raiser. Both clauses are refused:
///
/// * a row satisfying both whose id differs from that class — two names for one
///   thing, which is the cost this row removes;
/// * a row NOT satisfying both whose id equals any class token — one name for
///   two things, which is worse, because a reader who dereferences it gets an
///   answer about the other one.
///
/// # Why both directions, measured
///
/// The issue's Ready block asked only for the first, on a census that counted
/// classes-with-one-raiser (170 of 174) and read it as rules-with-one-class.
/// Those are opposite directions. Measured on this tree: **20** policy rows
/// raise exactly one class and **39** raise more — `ci-parity` raises 21,
/// `shell-retirement` 13, `lock-complete` 10. The one-directional rule would
/// have demanded `ci-parity` carry twenty-one ids at once, so it was
/// unsatisfiable and could not have shipped in that form.
///
/// A row this function never sees a class for — every native-kind row, whose
/// class the ENGINE picks rather than a module — is correctly handled by the
/// second clause alone: it raises no module class, so it is not collapsible,
/// so its id must not be a class token.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming the row and which direction it broke.
fn check_collapse(
    rules: &[Rule],
    per_rule: &BTreeMap<String, BTreeSet<String>>,
    registry: &BTreeSet<String>,
) -> Result<()> {
    let raisers: BTreeMap<&str, usize> = {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for classes in per_rule.values() {
            for class in classes {
                *counts.entry(class.as_str()).or_default() += 1;
            }
        }
        counts
    };
    // EVERY VIOLATION, NOT THE FIRST. A migration is the case this fires on,
    // and one-at-a-time turns a single reading into N builds — measured on
    // CLOUD-1638's own migration, where the first two runs each bought one
    // rename. Reporting the set is also what lets a reader see whether the
    // config disagrees with the modules in one place or systematically.
    let mut findings: Vec<String> = Vec::new();
    for rule in rules {
        // A ROW OUTSIDE THE GRAMMAR IS NOT IN THIS CONVERSATION.
        //
        // The collapse rule decides WHICH of two grammar names a row carries;
        // a row whose id is not a three-word name carries only one, so there is
        // nothing to collapse and nothing to disambiguate. This is not a hole a
        // consumer can hide in: `config::validate_tables` refuses a non-grammar
        // id outright once they declare a vocabulary, so adopting the grammar is
        // what brings a row into scope here, and the two arms compose.
        //
        // Measured: without this, 49 cases across fifteen suites failed — every
        // fixture that declares a `policy` row raising one class, none of which
        // has adopted the vocabulary and none of which the rule is about.
        if rule.id.split(' ').count() != 3 {
            continue;
        }
        let empty = BTreeSet::new();
        let classes = per_rule.get(&rule.id).unwrap_or(&empty);
        let sole = match (classes.len(), classes.iter().next()) {
            (1, Some(class)) if raisers.get(class.as_str()) == Some(&1) => Some(class.as_str()),
            _ => None,
        };
        match sole {
            Some(class) if rule.id != class => findings.push(format!(
                "rule `{}` is the only raiser of `{class}` and raises nothing else, so the two \
                 are one thing and owe one name: rename the row to `{class}`",
                rule.id
            )),
            None if registry.contains(&rule.id) => findings.push(format!(
                "rule `{}` is spelled as a class token but is not that class's sole raiser, so \
                 the name answers for two different things — give the row a distinct three-word \
                 id",
                rule.id
            )),
            _ => {}
        }
    }
    if !findings.is_empty() {
        return Err(UsageError::raise(findings.join("\n")));
    }
    Ok(())
}

fn check_registry_is_exhausted(
    verdicts: &[crate::config_model::DeclaredVerdict],
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
/// **A collision resolves to the binary's definition, and is refused one surface
/// over.** The vendored row replaces a consumer row carrying the same token, so
/// a refusal a preset raises always renders in its author's words. The other
/// half — a consumer declaration made inert while reading as live — is answered
/// where authoring properties are answered: [`check_no_vendored_collision`] runs
/// on every load that runs the module checks (`check`, `enforce`), so a dead
/// row cannot land.
///
/// # Why the boundary does not refuse it (CLOUD-2089)
///
/// The collision's commonest cause is not a redefinition: it is a binary NEWER
/// than the checked-out branch. A trunk change moves a class from `batten.toml`
/// into the binary, the session updates the engine to its release pin, and a
/// branch cut before the move still declares the class. Refusing here made
/// every mediated call unadjudicable — measured 2026-10-03, a session was
/// refused everything but `Read` and an authority `Edit`, the rebuild, the fetch
/// and the rebase that are the only ways out included, and every pre-approval
/// with them, because a policy that does not load grants nothing.
///
/// # Errors
///
/// None today; the `Result` stays so every caller keeps one fault channel.
pub fn registry_for(
    verdicts: &[crate::config_model::DeclaredVerdict],
) -> Result<Vec<crate::config_model::DeclaredVerdict>> {
    let mut registry = verdicts.to_vec();
    for entry in crate::config_check::verdict::vendored() {
        registry.retain(|row| row.id != entry.id);
        registry.push(entry);
    }
    Ok(registry)
}

/// Refuse a consumer `[[verdict]]` row whose token this binary ships, on a load
/// that runs the module checks (CLOUD-2089).
///
/// The authoring half of [`registry_for`]'s resolution: such a row is dead —
/// the binary's definition is the one that renders — whether the branch merely
/// predates the move or means to redefine the class. Either way it must not
/// land, and either way the mediated boundary is the wrong place to say so.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) naming every colliding token.
fn check_no_vendored_collision(verdicts: &[crate::config_model::DeclaredVerdict]) -> Result<()> {
    let vendored: BTreeSet<String> = crate::config_check::verdict::vendored()
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    let collisions: Vec<&str> = verdicts
        .iter()
        .map(|entry| entry.id.as_str())
        .filter(|token| vendored.contains(*token))
        .collect();
    if let Some(first) = collisions.first() {
        return Err(UsageError::raise(format!(
            "`[[verdict]]` declares `{first}`, which this binary already ships — the row is \
             dead, because the binary's definition is the one that renders. Delete it; a \
             branch that predates the move rebases onto the trunk that deleted it. \
             Shipped: {}",
            collisions.join(", ")
        )));
    }
    Ok(())
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
    registry: &[crate::config_model::DeclaredVerdict],
    source: &str,
) -> Result<()> {
    // Derived here rather than handed in, so the call site is one line at each
    // of its two positions. The table is tens of entries and this is the load
    // path, not the mediated one — `ModuleChecks::SkipOnHotPath` is what keeps
    // it off the 100ms budget, and re-deriving a set that small is free against
    // the AST read it sits beside.
    let declared = crate::verdict::declared_tokens(registry);
    let emittable = crate::verdict::live_tokens(registry);
    let Some(described) = bundle.described() else {
        // Could-not-look on the AST is not a refusal, for the reason the sibling
        // checks state.
        return Ok(());
    };
    for module in described {
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
    let Some(described) = bundle.described() else {
        return found;
    };
    for module in described {
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
    check_patterns(rule, bundle, declared, source, &BTreeMap::new())
}

/// [`check_no_inline_regex`] for an in-repo row whose `sources` may include
/// copies `batten preset eject` wrote (CLOUD-2290). A wrapper rather than a
/// fifth argument at the call site, which `load` has no line to spare for.
fn check_copy_regex(
    rule: &Rule,
    bundle: &Bundle,
    declared: &BTreeSet<&str>,
    source: &str,
    sources: &[(String, String)],
) -> Result<()> {
    check_patterns(rule, bundle, declared, source, &ejected_originals(sources))
}

fn check_patterns(
    rule: &Rule,
    bundle: &Bundle,
    declared: &BTreeSet<&str>,
    source: &str,
    // Module path to the VENDORED source it was ejected from (CLOUD-2290).
    vendored: &BTreeMap<String, std::borrow::Cow<'static, str>>,
) -> Result<()> {
    let Some(described) = bundle.described() else {
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
    for module in described {
        // The vendored source of an ejected copy (CLOUD-2290): what the copy
        // inherits from it is exempt below, and nothing else.
        let original = vendored.get(&module.path);
        for rule_ast in &module.rules {
            for referenced in &rule_ast.pattern_refs {
                if declared.contains(referenced.as_str()) {
                    continue;
                }
                // A preset may read a consumer pattern that is optional — "no
                // row, no grant" — and its copy reads it the same way.
                let spelled = format!("data.batten.patterns[\"{referenced}\"]");
                if original.is_some_and(|text| text.contains(&spelled)) {
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
            // AN EJECTED COPY KEEPS THE PRESET'S OWN PATTERNS (CLOUD-2290), and
            // only those. The exemption above is the preset's, and a copy
            // `batten preset eject` wrote is the preset's text; but the
            // exemption follows the PATTERN, not the file, so a regex the
            // consumer adds to the copy afterwards is refused like any other.
            let Some(pattern) = rule_ast
                .inline_regex
                .iter()
                .find(|pattern| !original.is_some_and(|text| text.contains(pattern.as_str())))
            else {
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
/// makes a gated-model verdict inadmissible, so the alternative to a decidable
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
#[derive(Clone)]
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
    /// `deny contains "x probe probex" if …` builds a set of strings, and the member is the
    /// head's key. Read from the head rather than from the rule's literals,
    /// because a rule's literals include every argument it passes: the fixture
    /// `deny contains "x probe probex" if contains(input.call.command, "forbidden")` has two
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
    let Some(ast) = Ast::of(engine) else {
        AST_DESCRIPTIONS.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    describe_of(&ast)
}

/// [`describe`] over an [`Ast`] already in hand.
fn describe_of(ast: &Ast) -> Option<Vec<Described>> {
    AST_DESCRIPTIONS.fetch_add(1, Ordering::Relaxed);
    let mut described = Vec::new();
    for policy in &ast.0 {
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
            "type": "object",
            "description": "Could-not-look, and NOT a Fact: a declared name the engine could not acquire, mapped to WHY (CLOUD-1309). Distinct from an empty result, which is the distinction that keeps a vacuous pass out (CLOUD-251, CLOUD-845). The cause is one of `absent`, `unparsed`, `unreadable`, `unknown-format`, `root-unset` or `no-document` -- `NotAcquired::as_str`'s own tokens -- and carrying it is what makes `rules/policy-modules.md`'s \"the two causes stay distinct and a module may rely on that\" true of this surface rather than only of the Rust enum. A module keys by name: `input.tree.missing[path] == \"unparsed\"`. It was an array of bare names until CLOUD-1309, so a predicate could see THAT a source failed and never WHY, and firing on membership alone reddened every consumer that declares an optional source.",
            "additionalProperties": {"type": "string"},
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
    let mut document = serde_json::json!({
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
                    "tool": {"type": "string"},
                    "arguments": {},
                    "command": {},
                    // A property of the CALL rather than of the command string
                    // (CLOUD-613): `true`, `false`, or `null` where the host said
                    // nothing. Three-valued deliberately — an absent flag is not
                    // a false one, and a predicate about backgrounding must not
                    // fire on a call whose host never spoke.
                    "run-in-background": {"type": ["boolean", "null"]},
                    // The host's background ceiling in milliseconds, or `null`
                    // where the host reports none (CLOUD-2365). Resolved by the
                    // host's adapter at decode, so the core carries no host's
                    // arithmetic.
                    "background-max": {"type": ["integer", "null"]},
                    // THE SEGMENTED COMMAND (CLOUD-857). Constrained rather than
                    // left open like its neighbours, because a module reads a
                    // FIELD of each entry and `additionalProperties: false` is
                    // what makes `segment.word` a build-time error instead of an
                    // undefined path that denies nothing — the same load-bearing
                    // line the `facts` object below carries, for the same reason.
                    "segments": {
                        "type": ["array", "null"],
                        "description": "`hook::segments` over `command`: one entry per shell-separated element, quote-aware. For the SPAN's structure -- its terminator, its input redirection, its raw text. A PROGRAM is anchored on `programs`, not on `words[0]`, which is the first word and not the first program (CLOUD-1382).",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "words": {"type": "array", "items": {"type": "string"}},
                                "raw": {"type": "string"},
                                "terminator": {"type": ["string", "null"]},
                                "input-redirect": {"type": "boolean"},
                                // CLOUD-1949: output sent into a file, which
                                // makes any reader in the segment a writer.
                                "output-redirect": {"type": "boolean"},
                                // #1276: the output redirections' targets,
                                // never an operator token or a `&` duplication.
                                "redirect-writes": {"type": "array", "items": {"type": "string"}},
                                // CLOUD-1381. `null` at the top level; a
                                // `kind`/`role` pair inside a control-flow node,
                                // so a module decides from the node rather than
                                // from a keyword a parse does not produce.
                                "construct": {
                                    "type": ["object", "null"],
                                    "additionalProperties": false,
                                    "properties": {
                                        "kind": {"type": "string"},
                                        "role": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                    "writes": {},
                    "final-message": {},
                    "transcript": {},
                    "stop-repeat": {},
                    // CLOUD-1028. One entry per segment of the command, each the
                    // effective program, WHAT IT WAS HANDED, and whether the pin
                    // selected it — constrained here rather than left open
                    // because the whole point of the key is that a module reads a
                    // PARSED argv it does not have to parse, and an unconstrained
                    // shape would let a predicate ask for a field the boundary
                    // never emits.
                    "programs": {
                        "type": "array",
                        "description": "Each segment's effective program, resolved through environment assignments, wrapper programs and shell grammar. ANCHOR A PROGRAM HERE: `segments[_].words[0]` is the first WORD, which six one-keystroke shell constructs occupy in their own right (CLOUD-1382).",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "program": {"type": "string"},
                                "name": {"type": "string"},
                                // WHAT THIS PROGRAM WAS HANDED (CLOUD-1382), so
                                // a module anchoring on the program reads its
                                // own argv rather than joining back to a segment
                                // by value — a join that stops agreeing the
                                // moment the two readings differ, which is the
                                // whole reason this key exists.
                                "arguments": {"type": "array", "items": {"type": "string"}},
                                "mediated": {"type": "boolean"},
                                // CLOUD-1949. Whether the program is one the
                                // boundary knows leaves its operands alone.
                                "reads-only": {"type": "boolean"},
                                // The effect the surface declares for the
                                // deepest `batten` subcommand this argv names;
                                // `null` for any other program.
                                "batten-effect": {"type": ["string", "null"]},
                            },
                        },
                    },
                    // CLOUD-1949. The host's permission mode as it spelled it;
                    // `null` when it sent none.
                    "permission-mode": {"type": ["string", "null"]},
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
    extend_call_schema(&mut document);
    Ok(serde_json::to_string_pretty(&document)?)
}

/// Step 23 (#1276, CLOUD-2775): an interpreter's spawn whose argv is not a
/// literal — reached but unreadable — names the file it came from and whether
/// that file is tracked and clean. Absent on every other `programs` entry.
fn opaque_reach_keys(program: &mut serde_json::Map<String, serde_json::Value>) {
    for (key, kind) in [
        ("opaque", "boolean"),
        ("source", "string"),
        ("trusted", "boolean"),
    ] {
        program.insert(key.to_owned(), serde_json::json!({ "type": kind }));
    }
}

/// The call's `lap-held` key (CLOUD-2832): each of the call's writes that lands
/// in the live lap's checkout, judged by the checkout it lands in.
fn lap_held_schema() -> serde_json::Value {
    serde_json::json!({
        "type": ["array", "null"],
        "description": "Each write of this call that lands in the checkout a live `land` lap holds (`input.facts[\"land-live\"]`): `{\"path\": <target as written>}` for a write tool's or an output redirection's target, `{\"git\": <subcommand>}` for a git program acting there. Judged by the checkout the write lands in, never by its path prefix, so a clone nested inside the lap's directory is not the lap's. NULL while no lap is live, or where the writes could not be placed.",
        "items": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "path": {"type": "string"},
                "git": {"type": ["string", "null"]}
            }
        }
    })
}

/// The keys `call_input_schema` adds after its `json!` document is built: one
/// more key inline exceeds the macro's recursion limit.
///
/// * `forge` (CLOUD-2689): a forge event's tokens, never a body.
/// * a segment's `redirects` (CLOUD-2670): the suffix of its `words`.
/// * a program's `subcommand` and `global-options` (CLOUD-2354): its first verb
///   past its own value-taking options, and the words before it.
/// * a program's `via`, `unread`, `nested` and `tasks`, and the call's
///   `task-programs` (step 14) and `step-programs` (step 21).
/// * the call's `lap-held` (CLOUD-2832), from [`lap_held_schema`].
fn extend_call_schema(document: &mut serde_json::Value) {
    let forge = serde_json::json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "properties": {
            "event": {"type": ["string", "null"]},
            "action": {"type": ["string", "null"]},
            "repo": {"type": ["string", "null"]},
            "number": {"type": ["integer", "null"]},
            "sha": {"type": ["string", "null"]},
            "ref": {"type": ["string", "null"]},
            "key": {"type": ["string", "null"]},
        },
    });
    if let Some(call) = document
        .pointer_mut("/properties/call/properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        call.insert("forge".to_owned(), forge);
        call.insert("lap-held".to_owned(), lap_held_schema());
        // CLOUD-2709: the kind of machine, as the environment declared it —
        // `disposable` where `BATTEN_ENVIRONMENT` says so, `machine` otherwise.
        call.insert(
            "host".to_owned(),
            serde_json::json!({"type": "string", "enum": ["disposable", "machine"]}),
        );
        // CLOUD-2672: where the call stands, what it reaches, and its home.
        call.insert(
            "cwd".to_owned(),
            serde_json::json!({"type": ["string", "null"]}),
        );
        call.insert(
            "roots".to_owned(),
            serde_json::json!({"type": ["array", "null"], "items": {"type": "string"}}),
        );
        call.insert(
            "home".to_owned(),
            serde_json::json!({"type": ["string", "null"]}),
        );
    }
    if let Some(segment) = document
        .pointer_mut("/properties/call/properties/segments/items/properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        segment.insert(
            "redirects".to_owned(),
            serde_json::json!({"type": "array", "items": {"type": "string"}}),
        );
    }
    if let Some(program) = document
        .pointer_mut("/properties/call/properties/programs/items/properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        program.insert(
            "subcommand".to_owned(),
            serde_json::json!({"type": ["string", "null"]}),
        );
        program.insert(
            "global-options".to_owned(),
            serde_json::json!({"type": ["array", "null"], "items": {"type": "string"}}),
        );
        // Step 14: how the entry was reached, whether its text parsed, the
        // verb after the subcommand, and the tasks a `mise` starts.
        program.insert(
            "via".to_owned(),
            serde_json::json!({"type": ["string", "null"], "enum": [null, "script", "cargo run", "step run", "ci step", "exec", "task"]}),
        );
        program.insert("unread".to_owned(), serde_json::json!({"type": "boolean"}));
        program.insert(
            "receipted".to_owned(),
            serde_json::json!({"type": "boolean"}),
        );
        program.insert(
            "nested".to_owned(),
            serde_json::json!({"type": ["string", "null"]}),
        );
        program.insert(
            "tasks".to_owned(),
            serde_json::json!({"type": ["array", "null"], "items": {"type": "string"}}),
        );
        opaque_reach_keys(program);
    }
    // Step 14: every program the call's tasks reach, each a `programs` entry
    // carrying the `task` whose body ran it; `null` where the task receipt
    // could not be read.
    let entry = document
        .pointer("/properties/call/properties/programs/items")
        .cloned();
    if let (Some(mut entry), Some(call)) = (
        entry,
        document
            .pointer_mut("/properties/call/properties")
            .and_then(serde_json::Value::as_object_mut),
    ) {
        if let Some(properties) = entry
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
        {
            properties.insert("task".to_owned(), serde_json::json!({"type": "string"}));
        }
        call.insert(
            "task-programs".to_owned(),
            serde_json::json!({"type": ["array", "null"], "items": entry.clone()}),
        );
        call.insert(
            "step-programs".to_owned(),
            serde_json::json!({"type": ["array", "null"], "items": entry}),
        );
    }
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
///
/// **The longest resolvable reference only** (step 13a): the head of a chain
/// is not recorded beside it, so `input.tree.documents` yields `tree.documents`
/// and never also `tree`. A chain whose outer link does not resolve — a
/// variable index, `input.tree[k]` — records its longest resolvable head,
/// `tree`. A bare `input` that is not the head of a chain (`x := input`) is
/// recorded as the empty path, so a reader asking "which keys" can tell an
/// unknowable read from none.
fn collect_input_paths(value: &serde_json::Value, found: &mut Vec<String>) {
    collect_input_paths_at(value, found, false);
}

/// [`collect_input_paths`], told whether `value` is the `refr` of a chain whose
/// outer link already resolved — in which case `value` is a head, not a read.
fn collect_input_paths_at(value: &serde_json::Value, found: &mut Vec<String>, head: bool) {
    match value {
        serde_json::Value::Object(object) => {
            let resolved = reference_path(value);
            if !head && let Some(path) = resolved.as_deref() {
                if path == "input" {
                    found.push(String::new());
                } else if let Some(rest) = path.strip_prefix("input.") {
                    found.push(rest.to_owned());
                }
            }
            // A link that resolved makes its `refr` a head; one that did not
            // (a variable index) leaves the `refr` as the longest read.
            let chained = resolved.is_some() || head;
            for (name, child) in object {
                match name.as_str() {
                    "RefDot" | "RefBrack" => {
                        for (field, inner) in child.as_object().into_iter().flatten() {
                            collect_input_paths_at(inner, found, field == "refr" && chained);
                        }
                    }
                    _ => collect_input_paths_at(child, found, false),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_input_paths_at(item, found, false);
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
/// `{"verdict": "x probe probex"}` distinguishable from `{"x": "verdict"}` — the second is
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

// ─── The suite on bytecode (#1276) ───────────────────────────────────────────

/// The `data` key a desugared `with` reads its rules' values from.
const WITH_DATA: &str = "__batten_with";

/// One case's place in its bundle's suite program (#1276).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PlannedTest {
    /// The module the case is written in.
    module: String,
    /// The case's own name.
    name: String,
    /// The program entry point deciding it, or why the program cannot.
    decided_by: std::result::Result<String, String>,
    /// Every `with` statement's context, in the order the case writes them.
    contexts: Vec<PlannedContext>,
}

/// One desugared `with` statement: its context, and what it reads under it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PlannedContext {
    /// The key its values sit under in `data.__batten_with`.
    key: String,
    /// The entry point evaluating its `input` term, where it has one.
    input: Option<String>,
    /// Each `data.batten.patterns` override: the key under the table (`None`
    /// for the whole table) and the entry point evaluating its term.
    patterns: Vec<(Option<String>, String)>,
    /// Each rule the statement reads under the context: name and entry point.
    rules: Vec<(String, String)>,
}

/// A bundle's `test_` rules, desugared and compiled to bytecode (#1276).
///
/// # Why a desugaring at all
///
/// regorus 0.15's bytecode compiler refuses `with`, and nearly every case
/// writes one: `some v in violation with input as {…}`. So `policy test` ran
/// every case on the tree-walking interpreter, every lap. A `with` is undone
/// here in three steps, each on bytecode:
///
/// 1. each `with` term is its own rule, evaluated in the case's own context;
/// 2. each rule the statement reads is evaluated again with the VM's `input`
///    (and pattern table) set to those values — the context the `with` names;
/// 3. the statement reads those values from `data.__batten_with` instead, so
///    the case itself runs with no `with` left in it.
///
/// A case the steps cannot express — a `with` inside a nested query, a helper
/// that writes its own `with`, a function reading the input under one — keeps
/// the interpreter and says so ([`Fallback::TestWith`]), counted on `-vv`.
struct SuiteProgram {
    program: std::sync::Arc<regorus::rvm::program::Program>,
    /// The bundle's `data` document, the pattern table.
    data: regorus::Value,
    tests: Vec<PlannedTest>,
    /// Read from the `.rvm` entry rather than compiled by this process.
    cached: bool,
}

/// What a module's rules are, by name, for the desugaring: whether the name
/// is a function, whether it (transitively) writes a `with`, and whether it
/// (transitively) reads `input` or `data`.
#[derive(Default)]
struct RuleFacts {
    function: bool,
    with: bool,
    reads: bool,
    refs: BTreeSet<String>,
}

/// `text[start..end]` for an AST span, widened over a string literal's
/// delimiters, which regorus's span of a string excludes (`guarded_sources`).
fn spanned(text: &str, start: usize, end: usize) -> Option<&str> {
    let quote = |at: usize| matches!(text.as_bytes().get(at), Some(b'"' | b'`'));
    let start = if start > 0 && quote(start - 1) {
        start - 1
    } else {
        start
    };
    let end = if quote(end) { end + 1 } else { end };
    text.get(start..end)
}

/// A node's own `span`, as byte offsets.
fn span_of(node: &serde_json::Value) -> Option<(usize, usize)> {
    let span = node.get("span")?;
    Some((
        usize::try_from(span.get("start")?.as_u64()?).ok()?,
        usize::try_from(span.get("end")?.as_u64()?).ok()?,
    ))
}

/// Whether `key` appears anywhere under `node`.
fn holds_key(node: &serde_json::Value, key: &str) -> bool {
    match node {
        serde_json::Value::Object(map) => {
            map.contains_key(key) || map.values().any(|value| holds_key(value, key))
        }
        serde_json::Value::Array(items) => items.iter().any(|item| holds_key(item, key)),
        _ => false,
    }
}

/// Every variable `node` references: its name, its span, and whether it is a
/// called function's name. A dotted callee (`regex.match`) names no rule and
/// is skipped.
fn referenced_vars(node: &serde_json::Value, found: &mut Vec<(String, usize, usize, bool)>) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(var) = map.get("Var") {
                if let (Some(name), Some((start, end))) = (
                    var.get("value").and_then(serde_json::Value::as_str),
                    span_of(var),
                ) {
                    found.push((name.to_owned(), start, end, false));
                }
                return;
            }
            if let Some(call) = map.get("Call") {
                if let Some(var) = call.get("fcn").and_then(|fcn| fcn.get("Var"))
                    && let (Some(name), Some((start, end))) = (
                        var.get("value").and_then(serde_json::Value::as_str),
                        span_of(var),
                    )
                {
                    found.push((name.to_owned(), start, end, true));
                }
                if let Some(params) = call.get("params") {
                    referenced_vars(params, found);
                }
                return;
            }
            for value in map.values() {
                referenced_vars(value, found);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                referenced_vars(item, found);
            }
        }
        _ => {}
    }
}

/// The variables a case body binds at its top level: `some` declarations, a
/// `some … in`'s key and value, and the left side of `:=` or either side of
/// `=` — never a rule's name, which `=` only reads.
fn case_locals(
    stmts: &[serde_json::Value],
    text: &str,
    facts: &BTreeMap<String, RuleFacts>,
) -> BTreeSet<String> {
    let mut locals = BTreeSet::new();
    for stmt in stmts {
        let Some(literal) = stmt.get("literal") else {
            continue;
        };
        if let Some(some) = literal.get("SomeVars") {
            for var in some
                .get("vars")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(name) = span_of(&serde_json::json!({ "span": var }))
                    .and_then(|(start, end)| text.get(start..end))
                {
                    locals.insert(name.to_owned());
                }
            }
        }
        if let Some(some) = literal.get("SomeIn") {
            for side in ["key", "value"] {
                if let Some(node) = some.get(side) {
                    bound_vars(node, &mut locals);
                }
            }
        }
        if let Some(assign) = literal
            .get("Expr")
            .and_then(|expr| expr.get("expr"))
            .and_then(|expr| expr.get("AssignExpr"))
        {
            let mut bound = BTreeSet::new();
            if let Some(lhs) = assign.get("lhs") {
                bound_vars(lhs, &mut bound);
            }
            if assign.get("op").and_then(serde_json::Value::as_str) == Some("Eq")
                && let Some(rhs) = assign.get("rhs")
            {
                bound_vars(rhs, &mut bound);
            }
            locals.extend(bound.into_iter().filter(|name| !facts.contains_key(name)));
        }
    }
    locals.remove("_");
    locals
}

/// The variable a reference chain starts from: `a` for `a`, `a.b` and `a[k]`.
fn base_var(expr: &serde_json::Value) -> Option<String> {
    if let Some(var) = expr.get("Var") {
        return Some(var.get("value")?.as_str()?.to_owned());
    }
    ["RefDot", "RefBrack"]
        .iter()
        .find_map(|link| base_var(expr.get(link)?.get("refr")?))
}

/// Every package's rules, by name, with what [`RuleFacts`] records, closed
/// over references.
fn package_facts(policies: &[serde_json::Value]) -> BTreeMap<String, BTreeMap<String, RuleFacts>> {
    let mut packages: BTreeMap<String, BTreeMap<String, RuleFacts>> = BTreeMap::new();
    for policy in policies {
        let Some(ast) = policy.get("ast") else {
            continue;
        };
        let Some(package) = ast
            .get("package")
            .and_then(|package| package.get("refr"))
            .and_then(reference_path)
        else {
            continue;
        };
        let facts = packages.entry(package).or_default();
        for rule in ast
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            // THE BASE VARIABLE, which is what a reference names: `latest[id] :=`
            // is the rule `latest`, and `head_of` answers nothing for a head
            // indexed by a variable, which left such a rule unread under `with`.
            let (name, function) = if let Some(spec) = rule.get("Spec") {
                let head = spec.get("head");
                let Some(name) = head.and_then(|head| {
                    ["Compr", "Set", "Func"]
                        .iter()
                        .find_map(|shape| base_var(head.get(shape)?.get("refr")?))
                }) else {
                    continue;
                };
                (name, head.is_some_and(|head| head.get("Func").is_some()))
            } else if let Some(name) = rule
                .get("Default")
                .and_then(|default| default.get("refr"))
                .and_then(base_var)
            {
                (name, false)
            } else {
                continue;
            };
            let mut vars = Vec::new();
            referenced_vars(rule, &mut vars);
            let entry = facts.entry(name).or_default();
            entry.function |= function;
            entry.with |= holds_key(rule, "with_mods");
            entry.reads |= vars.iter().any(|(var, ..)| var == "input" || var == "data");
            entry.refs.extend(vars.into_iter().map(|(var, ..)| var));
        }
    }
    for facts in packages.values_mut() {
        // BOUNDED BY THE RULE COUNT (CLOUD-2789): each pass reads the sets as
        // the previous one left them, so it carries a flag one reference
        // further, and no chain of distinct rules is longer than the rules.
        // `len + 1` passes reach the fixed point and see it hold; a change that
        // stops a pass from converging ends with a wrong answer a case can
        // see, rather than spinning until the suite's timeout.
        for _ in 0..=facts.len() {
            let reads: BTreeSet<String> = facts
                .iter()
                .filter(|(_, fact)| fact.reads)
                .map(|(name, _)| name.clone())
                .collect();
            let with: BTreeSet<String> = facts
                .iter()
                .filter(|(_, fact)| fact.with)
                .map(|(name, _)| name.clone())
                .collect();
            let mut changed = false;
            for (name, fact) in facts.iter_mut() {
                let reaches =
                    |set: &BTreeSet<String>| fact.refs.iter().any(|r| r != name && set.contains(r));
                if !fact.reads && reaches(&reads) {
                    fact.reads = true;
                    changed = true;
                }
                if !fact.with && reaches(&with) {
                    fact.with = true;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }
    packages
}

/// What one case's statement walk reads throughout: its module's text and
/// package, the package's rule facts, and the variables the case binds.
struct CaseText<'a> {
    text: &'a str,
    package: &'a str,
    facts: &'a BTreeMap<String, RuleFacts>,
    locals: &'a BTreeSet<String>,
}

/// A variable a statement references: name, span, and whether it is called.
type ReferencedVar = (String, usize, usize, bool);

/// One case desugared: the rules it becomes, and its contexts — or why it
/// cannot be ([`SuiteProgram`]).
fn plan_case(
    at: usize,
    spec: &serde_json::Value,
    text: &str,
    (package, facts): (&str, &BTreeMap<String, RuleFacts>),
) -> std::result::Result<(String, Vec<PlannedContext>), String> {
    let (name, stmts) = case_statements(spec)?;
    let locals = case_locals(stmts, text, facts);
    let case = CaseText {
        text,
        package,
        facts,
        locals: &locals,
    };
    let mut lines: Vec<String> = Vec::new();
    let mut contexts = Vec::new();
    let mut prelude = String::new();
    let mut plain = true;
    for (index, stmt) in stmts.iter().enumerate() {
        let literal = stmt.get("literal").ok_or("no literal")?;
        if holds_key(literal, "with_mods") {
            return Err(String::from("a `with` inside a nested query"));
        }
        let mut vars = Vec::new();
        referenced_vars(literal, &mut vars);
        if vars
            .iter()
            .any(|(var, ..)| !locals.contains(var) && facts.get(var).is_some_and(|fact| fact.with))
        {
            return Err(String::from("a helper that writes its own `with`"));
        }
        let (start, end) = span_of(stmt).ok_or("no span")?;
        let mods = stmt
            .get("with_mods")
            .and_then(serde_json::Value::as_array)
            .filter(|mods| !mods.is_empty());
        let Some(mods) = mods else {
            lines.push(
                spanned(text, start, end)
                    .ok_or("a span off its text")?
                    .to_owned(),
            );
            continue;
        };
        let plain_before = plain;
        plain = false;
        let key = format!("c{at}_{index}");
        let (statement, read) = redirected_statement(&case, start, mods, &vars, &key)?;
        lines.push(statement);
        let mut context = PlannedContext {
            key,
            input: None,
            patterns: Vec::new(),
            rules: read
                .into_iter()
                .map(|rule| {
                    let entry = format!("data.{package}.{rule}");
                    (rule, entry)
                })
                .collect(),
        };
        let hoist = plain_before.then(|| &lines[..index]);
        with_terms(&case, mods, (at, index), hoist, &mut context, &mut prelude)?;
        contexts.push(context);
    }
    Ok((
        format!("\n{name} if {{\n\t{}\n}}\n{prelude}", lines.join("\n\t")),
        contexts,
    ))
}

/// A case's name and its one body's statements, or why it cannot be
/// desugared: a case taking arguments or assigning a value, or one with an
/// `else` or a second body.
fn case_statements(
    spec: &serde_json::Value,
) -> std::result::Result<(String, &Vec<serde_json::Value>), String> {
    let head = spec.get("head").ok_or("no head")?;
    let (name, _) = head_of(head).ok_or("no head")?;
    if head.get("Func").is_some() {
        return Err(String::from("a case taking arguments"));
    }
    if head
        .get("Compr")
        .and_then(|compr| compr.get("assign"))
        .is_some_and(|assign| !assign.is_null())
    {
        return Err(String::from("a case assigning a value"));
    }
    let bodies = spec
        .get("bodies")
        .and_then(serde_json::Value::as_array)
        .ok_or("no body")?;
    let [body] = bodies.as_slice() else {
        return Err(String::from("an `else` or a second body"));
    };
    let stmts = body
        .get("query")
        .and_then(|query| query.get("stmts"))
        .and_then(serde_json::Value::as_array)
        .ok_or("no statements")?;
    Ok((name, stmts))
}

/// A `with` statement's text up to its first modifier, each rule it reads
/// redirected to the value its context computes under `data.__batten_with`
/// at `key`, and the rules so read. A read of `input` or `data`, or a function
/// reading the input, under `with` is refused.
fn redirected_statement(
    case: &CaseText<'_>,
    start: usize,
    mods: &[serde_json::Value],
    vars: &[ReferencedVar],
    key: &str,
) -> std::result::Result<(String, BTreeSet<String>), String> {
    let text = case.text;
    let (cut, _) = span_of(&mods[0]).ok_or("no span")?;
    let from = if start > 0 && matches!(text.as_bytes().get(start - 1), Some(b'"' | b'`')) {
        start - 1
    } else {
        start
    };
    let mut statement = text
        .get(from..cut)
        .ok_or("a span off its text")?
        .trim_end()
        .to_owned();
    let mut edits = Vec::new();
    let mut read = BTreeSet::new();
    for (var, var_start, var_end, called) in vars {
        if case.locals.contains(var) {
            continue;
        }
        if var == "input" || var == "data" {
            return Err(String::from("a read of `input` or `data` under `with`"));
        }
        let Some(fact) = case.facts.get(var) else {
            continue;
        };
        if !fact.reads {
            continue;
        }
        if *called || fact.function {
            return Err(String::from("a function reading the input under `with`"));
        }
        edits.push((
            var_start - from,
            var_end - from,
            format!("data.{WITH_DATA}[\"{key}\"][\"{var}\"]"),
        ));
        read.insert(var.clone());
    }
    edits.sort_by_key(|(at, ..)| std::cmp::Reverse(*at));
    for (edit_start, edit_end, replacement) in edits {
        if edit_end > statement.len()
            || !statement.is_char_boundary(edit_start)
            || !statement.is_char_boundary(edit_end)
        {
            return Err(String::from("a span off its text"));
        }
        statement.replace_range(edit_start..edit_end, &replacement);
    }
    Ok((statement, read))
}

/// Each `with` term of statement `index` of case `at`, as a rule in `prelude`
/// its `context` names: `input` and the pattern table are the targets a term
/// may replace. `hoist` is the statements before this one where none of them
/// bound under `with`, which a term reading a case variable is evaluated
/// under; `None` refuses such a term.
fn with_terms(
    case: &CaseText<'_>,
    mods: &[serde_json::Value],
    (at, index): (usize, usize),
    hoist: Option<&[String]>,
    context: &mut PlannedContext,
    prelude: &mut String,
) -> std::result::Result<(), String> {
    for (term_at, modifier) in mods.iter().enumerate() {
        let target = modifier
            .get("refr")
            .and_then(reference_path)
            .ok_or("a `with` on a computed path")?;
        let term = modifier.get("as").ok_or("no term")?;
        let (term_start, term_end) = term
            .as_object()
            .and_then(|object| object.values().next())
            .and_then(span_of)
            .ok_or("no span")?;
        let term_text = spanned(case.text, term_start, term_end).ok_or("a span off its text")?;
        let mut term_vars = Vec::new();
        referenced_vars(term, &mut term_vars);
        let hoisted = term_vars
            .iter()
            .any(|(var, _, _, called)| !called && case.locals.contains(var));
        let rule = format!("__batten_in_{at}_{index}_{term_at}");
        let body = if hoisted {
            let Some(before) = hoist else {
                return Err(String::from(
                    "a `with` term reading a variable bound under `with`",
                ));
            };
            format!(" if {{\n\t{}\n}}", before.join("\n\t"))
        } else {
            String::new()
        };
        for piece in ["\n", rule.as_str(), " := ", term_text, body.as_str(), "\n"] {
            prelude.push_str(piece);
        }
        let entry = format!("data.{}.{rule}", case.package);
        match target.as_str() {
            "input" if context.input.is_none() => context.input = Some(entry),
            "data.batten.patterns" => context.patterns.push((None, entry)),
            other => match other.strip_prefix("data.batten.patterns.") {
                Some(key) if !key.contains('.') => {
                    context.patterns.push((Some(key.to_owned()), entry));
                }
                _ => return Err(format!("a `with` on `{other}`")),
            },
        }
    }
    Ok(())
}

/// The desugared sources, `(path, text)`, and each case's plan.
type Planned = (Vec<(String, String)>, Vec<PlannedTest>);

/// Every module's text with its cases desugared, and each case's plan
/// ([`SuiteProgram`]). `None` where the AST will not serialise.
fn plan_suite(ast: &Ast) -> Option<Planned> {
    let policies = &ast.0;
    let packages = package_facts(policies);
    // A case NAME DEFINED TWICE in a package is one rule with two bodies,
    // which a desugared single body cannot stand for.
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for policy in policies {
        let package = reference_path(policy.get("ast")?.get("package")?.get("refr")?)?;
        for rule in policy.get("ast")?.get("rules")?.as_array()? {
            if let Some((name, _)) = rule
                .get("Spec")
                .and_then(|spec| spec.get("head"))
                .and_then(head_of)
                .filter(|(name, _)| name.starts_with(TEST_PREFIX))
            {
                *seen.entry((package.clone(), name)).or_insert(0) += 1;
            }
        }
    }
    let mut sources = Vec::new();
    let mut tests = Vec::new();
    for policy in policies {
        let source = policy.get("source")?;
        let path = source.get("file")?.as_str()?.to_owned();
        let text = source.get("contents")?.as_str()?;
        let ast = policy.get("ast")?;
        let package = reference_path(ast.get("package")?.get("refr")?)?;
        let empty = BTreeMap::new();
        let facts = packages.get(&package).unwrap_or(&empty);
        let mut generated = String::new();
        for rule in ast.get("rules")?.as_array()? {
            let Some(spec) = rule.get("Spec") else {
                continue;
            };
            let Some((name, _)) = spec
                .get("head")
                .and_then(head_of)
                .filter(|(name, _)| name.starts_with(TEST_PREFIX))
            else {
                continue;
            };
            let planned = if seen.get(&(package.clone(), name.clone())) == Some(&1) {
                plan_case(tests.len(), spec, text, (&package, facts))
            } else {
                Err(String::from("a case defined more than once"))
            };
            let (decided_by, contexts) = match planned {
                Ok((rules, contexts)) => {
                    generated.push_str(&rules);
                    (Ok(format!("data.{package}.{name}")), contexts)
                }
                Err(why) => (Err(why), Vec::new()),
            };
            tests.push(PlannedTest {
                module: path.clone(),
                name,
                decided_by,
                contexts,
            });
        }
        sources.push((path, format!("{}{generated}", without_test_rules(text))));
    }
    Some((sources, tests))
}

/// The key a bundle's suite program is cached under: its modules as written
/// and its `data` document, which is everything [`plan_suite`] reads.
fn suite_key(id: &str, engine: &regorus::Engine) -> Option<String> {
    let sources: Vec<(String, String)> = engine
        .get_policies()
        .ok()?
        .iter()
        .map(|source| (source.file().clone(), source.contents().clone()))
        .collect();
    let data = engine.get_data().to_json_str().ok()?;
    Some(cache_key(
        &format!("{id}\0suite"),
        &sources,
        blake3::hash(data.as_bytes()).as_bytes(),
    ))
}

/// What one desugared `with` statement reads under its context.
enum Reading {
    /// The values of the rules it reads, by name.
    Values(regorus::Value),
    /// A `with` term that is undefined, which leaves the statement undefined.
    Undefined,
}

impl SuiteProgram {
    /// `id`'s suite program: the cached entry under `root` where it holds one,
    /// else compiled from `engine` and written for the next run. `Err` is why
    /// no case can decide on bytecode.
    fn load(
        id: &str,
        (engine, ast): (&regorus::Engine, Option<&Ast>),
        root: Option<&Path>,
    ) -> std::result::Result<Self, (Fallback, String)> {
        let key = suite_key(id, engine);
        let path = root.and_then(|root| cache_path(root, &format!("{id}\0suite")));
        if let (Some(path), Some(key)) = (path.as_deref(), key.as_deref())
            && let Some(program) = Self::read(path, key, engine)
        {
            return Ok(program);
        }
        let program = Self::compile_with(engine, ast)?;
        if let (Some(path), Some(key)) = (path.as_deref(), key.as_deref()) {
            program.write(path, key);
        }
        Ok(program)
    }

    fn read(path: &Path, key: &str, engine: &regorus::Engine) -> Option<Self> {
        let bytes = crate::cache::read(path, key)?;
        let split = bytes.iter().position(|byte| *byte == b'\n')?;
        let (head, body) = bytes.split_at(split);
        let tests: Vec<PlannedTest> = serde_json::from_slice(head).ok()?;
        let regorus::rvm::program::DeserializationResult::Complete(program) =
            regorus::rvm::program::Program::deserialize_binary(body.get(1..)?).ok()?
        else {
            return None;
        };
        Some(Self {
            program: std::sync::Arc::new(program),
            data: engine.get_data(),
            tests,
            cached: true,
        })
    }

    fn write(&self, path: &Path, key: &str) {
        let (Ok(mut bytes), Ok(program)) = (
            serde_json::to_vec(&self.tests),
            self.program.serialize_binary(),
        ) else {
            return;
        };
        bytes.push(b'\n');
        bytes.extend_from_slice(&program);
        crate::cache::write(path, key, &bytes);
    }

    /// Desugar and compile, with batten's refusals of regorus's known
    /// miscompiles and the `:=` guard, exactly as a verdict program
    /// ([`Compiled::compile_unchecked`]).
    fn compile(engine: &regorus::Engine) -> std::result::Result<Self, (Fallback, String)> {
        Self::compile_with(engine, Ast::of(engine).as_ref())
    }

    /// [`Self::compile`] over `engine`'s [`Ast`] already in hand, or `None`
    /// where it would not serialise.
    fn compile_with(
        engine: &regorus::Engine,
        ast: Option<&Ast>,
    ) -> std::result::Result<Self, (Fallback, String)> {
        use regorus::languages::rego::compiler::Compiler;
        let refused = |err: &dyn std::fmt::Debug| (Fallback::CompileRefused, format!("{err:?}"));
        let unserialisable = || {
            (
                Fallback::GuardUnavailable,
                String::from("the AST would not serialise, or an offset is not a boundary"),
            )
        };
        let (sources, tests) = ast.and_then(plan_suite).ok_or_else(unserialisable)?;
        let data = engine.get_data();
        let mut desugared = new_engine();
        desugared.add_data(data.clone()).map_err(|e| refused(&e))?;
        for (path, text) in &sources {
            desugared
                .add_policy(path.clone(), text.clone())
                .map_err(|e| (Fallback::GuardedSourceRefused, format!("{path}: {e}")))?;
        }
        // ONE RENDER OF THE DESUGARED AST for the refusals and the guard
        // (CLOUD-2830).
        let ast = Ast::of(&desugared).ok_or_else(unserialisable)?;
        if let Some(at) = unguardable_assignment(&ast) {
            return Err((Fallback::GuardUnavailable, at));
        }
        if let Some(at) = keyed_partial_set(&ast) {
            return Err((Fallback::KeyedPartialSet, at));
        }
        if let Some(at) = rule_else(&ast) {
            return Err((Fallback::RuleElse, at));
        }
        let guarded = guarded_sources_of(&ast).ok_or_else(unserialisable)?;
        let mut compiling = new_engine();
        compiling.add_data(data.clone()).map_err(|e| refused(&e))?;
        for (path, text) in guarded {
            compiling
                .add_policy(path.clone(), text)
                .map_err(|e| (Fallback::GuardedSourceRefused, format!("{path}: {e}")))?;
        }
        let mut entries = BTreeSet::new();
        for test in &tests {
            if let Ok(entry) = &test.decided_by {
                entries.insert(entry.clone());
            }
            for context in &test.contexts {
                entries.extend(context.input.iter().cloned());
                entries.extend(context.patterns.iter().map(|(_, entry)| entry.clone()));
                entries.extend(context.rules.iter().map(|(_, entry)| entry.clone()));
            }
        }
        let first = entries.iter().next().ok_or_else(|| {
            (
                Fallback::TestWith,
                String::from("no case the suite program can express"),
            )
        })?;
        let policy = compiling
            .compile_with_entrypoint(&first.as_str().into())
            .map_err(|e| refused(&e))?;
        let rules = policy.get_rules();
        let names: Vec<&str> = entries
            .iter()
            .filter(|entry| rules.contains_key(entry.as_str()))
            .map(String::as_str)
            .collect();
        let program = Compiler::compile_from_policy(&policy, &names).map_err(|e| refused(&e))?;
        Ok(Self {
            program,
            data,
            tests,
            cached: false,
        })
    }

    /// A VM over this program, `data` and `input`: one evaluation.
    fn vm(&self, input: &regorus::Value, data: regorus::Value) -> Option<regorus::rvm::vm::RegoVM> {
        BYTECODE_EVALUATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut vm = regorus::rvm::vm::RegoVM::new();
        vm.load_program(self.program.clone());
        vm.set_strict_builtin_errors(true);
        vm.set_max_instructions(usize::MAX);
        vm.set_data(data).ok()?;
        vm.set_input(input.clone());
        Some(vm)
    }

    /// Each case's verdict over `input`, in plan order: `Some(passed)` where the
    /// program decided it, `None` where it could not and the interpreter must.
    fn run(&self, input: &regorus::Value) -> Vec<Option<bool>> {
        let mut outer = None;
        let mut plain = None;
        self.tests
            .iter()
            .map(|test| {
                let entry = test.decided_by.as_ref().ok()?;
                if test.contexts.is_empty() {
                    if plain.is_none() {
                        plain = self.vm(input, self.data.clone());
                    }
                    let answer = plain.as_mut()?.execute_entry_point_by_name(entry);
                    if answer.is_err() {
                        // A faulted VM is never asked again.
                        plain = None;
                    }
                    return Some(matches!(answer, Ok(regorus::Value::Bool(true))));
                }
                let mut with = regorus::Value::new_object();
                for context in &test.contexts {
                    let Reading::Values(values) = self.context(context, input, &mut outer)? else {
                        // A `with` term that is undefined: the statement is.
                        return Some(false);
                    };
                    with.as_object_mut()
                        .ok()?
                        .insert(regorus::Value::from(context.key.as_str()), values);
                }
                let mut data = self.data.clone();
                data.as_object_mut()
                    .ok()?
                    .insert(regorus::Value::from(WITH_DATA), with);
                let mut vm = self.vm(input, data)?;
                Some(matches!(
                    vm.execute_entry_point_by_name(entry),
                    Ok(regorus::Value::Bool(true))
                ))
            })
            .collect()
    }

    /// The values of the rules `context`'s statement reads, under the input and
    /// pattern table its `with` names. `None` is could-not-decide (a term or a
    /// rule faulted).
    fn context(
        &self,
        context: &PlannedContext,
        input: &regorus::Value,
        outer: &mut Option<regorus::rvm::vm::RegoVM>,
    ) -> Option<Reading> {
        let mut term = |entry: &str| -> Option<regorus::Value> {
            if outer.is_none() {
                *outer = self.vm(input, self.data.clone());
            }
            let value = outer.as_mut()?.execute_entry_point_by_name(entry);
            if value.is_err() {
                // A faulted VM is never asked again (`Compiled::evaluate_all`).
                *outer = None;
            }
            value.ok()
        };
        let mut data = self.data.clone();
        for (key, entry) in &context.patterns {
            let value = term(entry)?;
            if value == regorus::Value::Undefined {
                return Some(Reading::Undefined);
            }
            let batten = data
                .as_object_mut()
                .ok()?
                .get_mut(&regorus::Value::from("batten"))?;
            let table = batten.as_object_mut().ok()?;
            match key {
                None => {
                    table.insert(regorus::Value::from("patterns"), value);
                }
                Some(key) => {
                    table
                        .get_mut(&regorus::Value::from("patterns"))?
                        .as_object_mut()
                        .ok()?
                        .insert(regorus::Value::from(key.as_str()), value);
                }
            }
        }
        let input = match &context.input {
            Some(entry) => {
                let value = term(entry)?;
                if value == regorus::Value::Undefined {
                    return Some(Reading::Undefined);
                }
                value
            }
            None => input.clone(),
        };
        let mut vm = self.vm(&input, data)?;
        let mut values = regorus::Value::new_object();
        for (rule, entry) in &context.rules {
            let value = vm.execute_entry_point_by_name(entry).ok()?;
            if value != regorus::Value::Undefined {
                values
                    .as_object_mut()
                    .ok()?
                    .insert(regorus::Value::from(rule.as_str()), value);
            }
        }
        Some(Reading::Values(values))
    }
}

/// Every case of `bundle` whose bytecode verdict differs from the
/// interpreter's over `input`, or that the suite program cannot decide, as
/// one line each (#1276). The parity gate for [`SuiteProgram`]'s desugaring.
#[doc(hidden)]
#[must_use]
pub fn suite_splits(bundle: &Bundle, input: &str) -> Vec<String> {
    let Some(engine) = bundle.evaluator.engine() else {
        return vec![format!("{}: no interpreter", bundle.id)];
    };
    let has_cases = describe(engine).is_some_and(|described| {
        described.iter().any(|module| {
            module
                .rules
                .iter()
                .any(|rule| rule.name.starts_with(TEST_PREFIX))
        })
    });
    if !has_cases {
        return Vec::new();
    }
    let program = match SuiteProgram::compile(engine) {
        Ok(program) => program,
        Err((why, detail)) => return vec![format!("{}: {}: {detail}", bundle.id, why.as_str())],
    };
    let Ok(document) = regorus::Value::from_json_str(input) else {
        return vec![format!("{}: the input will not parse", bundle.id)];
    };
    let mut reference = engine.clone();
    if reference.set_input_json(input).is_err() {
        return vec![format!("{}: the input will not parse", bundle.id)];
    }
    let packages: BTreeMap<String, String> = describe(engine)
        .into_iter()
        .flatten()
        .map(|described| (described.path, described.package))
        .collect();
    let mut splits = Vec::new();
    for (test, decided) in program.tests.iter().zip(program.run(&document)) {
        let package = packages.get(&test.module).map_or("", String::as_str);
        let expected = matches!(
            reference.eval_rule(format!("data.{package}.{}", test.name)),
            Ok(regorus::Value::Bool(true))
        );
        splits.extend(case_split(&bundle.id, test, decided, expected));
    }
    splits
}

/// One case's [`suite_splits`] line: `None` where the bytecode `decided` the
/// interpreter's `expected` verdict, else what split them.
///
/// Apart from the evaluation so a case can hand it a disagreement: both
/// engines are given one data and one input, so no fixture makes them differ,
/// and the line a real miscompile would print is decided here.
fn case_split(
    bundle: &str,
    test: &PlannedTest,
    decided: Option<bool>,
    expected: bool,
) -> Option<String> {
    let at = format!("{bundle}: {} {}", test.module, test.name);
    match (decided, &test.decided_by) {
        (Some(verdict), _) if verdict == expected => None,
        (Some(verdict), _) => Some(format!("{at}: bytecode {verdict} interpreter {expected}")),
        (None, Err(why)) => Some(format!("{at}: not on bytecode: {why}")),
        (None, Ok(_)) => Some(format!("{at}: not on bytecode: a term or a rule faulted")),
    }
}

/// How many cases the coverage sweep ran on the interpreter (#1276): a
/// report, never a verdict, so it is counted apart from [`execution_census`].
static COVERAGE_CASES: AtomicUsize = AtomicUsize::new(0);

/// How many cases this process's coverage sweeps ran on the interpreter.
#[must_use]
pub fn coverage_cases() -> usize {
    COVERAGE_CASES.load(Ordering::Relaxed)
}

/// `input` as a document, parsed once per process per distinct text
/// (CLOUD-2830).
///
/// `policy test` hands every bundle the input its row declares, and rows that
/// declare the same facts are handed the same text. Parsing it into regorus's
/// value, and dropping that value after each bundle, measured 20% of the run's
/// samples. A value is shared by reference count, so a clone handed out here is
/// the same document, never a copy; keyed by the whole text's digest, so two
/// texts never share one.
fn parsed_input(input: &str) -> anyhow::Result<regorus::Value> {
    type Parsed = std::collections::HashMap<[u8; 32], regorus::Value>;
    thread_local! {
        static PARSED: std::cell::RefCell<Parsed> = std::cell::RefCell::default();
    }
    let key = *blake3::hash(input.as_bytes()).as_bytes();
    if let Some(found) = PARSED.with(|parsed| parsed.borrow().get(&key).cloned()) {
        return Ok(found);
    }
    let value = regorus::Value::from_json_str(input)?;
    PARSED.with(|parsed| parsed.borrow_mut().insert(key, value.clone()));
    Ok(value)
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
pub fn test(
    bundle: &Bundle,
    input: &str,
    mediated: bool,
    cache: Option<&Path>,
) -> Result<Look<Suite>> {
    let Some(described) = bundle.described() else {
        return Ok(Look::CouldNotLook);
    };
    let Discovered {
        cases: discovered,
        mut untested_modules,
        bare_only_modules,
    } = discover(described, mediated);
    let Some(engine) = bundle.evaluator.engine() else {
        return Ok(Look::CouldNotLook);
    };
    let document = parsed_input(input).map_err(|err| {
        UsageError::raise(format!(
            "`{}` was handed an input document that will not parse: {err}",
            bundle.pointer()
        ))
    })?;
    let (mut passed, mut failed) = verdicts(bundle, engine, &document, &discovered, cache);
    let Some(unexercised) = unexercised(bundle, engine, &document, &discovered, described) else {
        return Ok(Look::CouldNotLook);
    };
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

/// A bundle's cases and the modules that carry none ([`test`]'s discovery).
struct Discovered {
    /// Each `test_` rule and its entry point, in module order.
    cases: Vec<(TestId, String)>,
    /// The modules declaring no `test_` rule.
    untested_modules: Vec<String>,
    /// The mediated modules whose cases never pass a compound command.
    bare_only_modules: Vec<String>,
}

/// Every `test_` rule `described` declares, by prefix over the AST.
fn discover(described: &[Described], mediated: bool) -> Discovered {
    let mut untested_modules = Vec::new();
    let mut bare_only_modules = Vec::new();
    let mut discovered = Vec::new();
    for module in described {
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
    Discovered {
        cases: discovered,
        untested_modules,
        bare_only_modules,
    }
}

/// Each case's verdict over `document`: the cases that passed, then those
/// that failed, in discovery order.
fn verdicts(
    bundle: &Bundle,
    engine: &regorus::Engine,
    document: &regorus::Value,
    discovered: &[(TestId, String)],
    cache: Option<&Path>,
) -> (Vec<TestId>, Vec<TestId>) {
    // A TEST THAT ANSWERS ANYTHING BUT `true` HAS FAILED. `false` and undefined
    // are one answer here, and an evaluation that errors is a third spelling of
    // the same thing — a test whose body faults has not passed. None of the
    // three is a config fault: the set already compiled, at load.
    //
    // DECIDED ON BYTECODE (#1276): the cases run on the bundle's suite program,
    // cached beside its verdict program. A case the program cannot express
    // runs on the interpreter, and is counted against it with its reason.
    let program = if discovered.is_empty() {
        Err((Fallback::TestWith, String::from("no case")))
    } else {
        SuiteProgram::load(&bundle.id, (engine, bundle.ast()), cache)
    };
    let (decided, cached, why) = match &program {
        Ok(program) => {
            let decided: BTreeMap<(&str, &str), Option<bool>> = program
                .tests
                .iter()
                .zip(program.run(document))
                .map(|(test, decided)| ((test.module.as_str(), test.name.as_str()), decided))
                .collect();
            (decided, program.cached, Fallback::TestWith)
        }
        Err((why, _)) => (BTreeMap::new(), false, *why),
    };
    let mut interpreter: Option<regorus::Engine> = None;
    let mut passed = Vec::new();
    let mut failed = Vec::new();
    for (id, path) in discovered {
        let verdict =
            if let Some(Some(verdict)) = decided.get(&(id.module.as_str(), id.name.as_str())) {
                record_as(&bundle.id, Execution::Bytecode { cached });
                *verdict
            } else {
                record_as(&bundle.id, Execution::Interpreted(why));
                if interpreter.is_none() {
                    let mut fresh = engine.clone();
                    // The document already parsed above, not the text again.
                    fresh.set_input(document.clone());
                    interpreter = Some(fresh);
                }
                matches!(
                    interpreter
                        .as_mut()
                        .map(|engine| engine.eval_rule(path.clone())),
                    Some(Ok(regorus::Value::Bool(true)))
                )
            };
        if verdict {
            passed.push(id.clone());
        } else {
            failed.push(id.clone());
        }
    }
    (passed, failed)
}

/// The predicates `bundle` publishes that no case entered, or `None` where
/// the coverage read did not happen (CLOUD-251).
///
/// THE COVERAGE SWEEP IS THE INTERPRETER'S ONE JOB HERE (#1276), and it stops
/// as soon as it has answered. Coverage is a report about which predicates the
/// cases ENTERED, which bytecode cannot read; it decides only `unexercised`, so
/// once every published predicate is entered no further case can change the
/// answer. Cases are swept in doubling batches, so a suite that covers
/// everything early pays for a few cases, and a predicate no case enters still
/// costs the whole sweep, exactly as before.
fn unexercised(
    bundle: &Bundle,
    engine: &regorus::Engine,
    document: &regorus::Value,
    discovered: &[(TestId, String)],
    described: &[Described],
) -> Option<Vec<String>> {
    let mut unexercised: Vec<String> = bundle.declared.iter().cloned().collect();
    if !unexercised.is_empty() && !discovered.is_empty() {
        let mut sweep = engine.clone();
        sweep.set_enable_coverage(true);
        // The document already parsed, not the text again.
        sweep.set_input(document.clone());
        let mut swept = 0;
        let mut batch = 1;
        // BOUNDED BY THE CASE COUNT (CLOUD-2789): every pass runs at least one
        // case, so `discovered.len()` passes reach the end. A batch that stops
        // growing then ends the sweep with a wrong answer a case can see,
        // rather than spinning until the suite's timeout.
        for _ in 0..discovered.len() {
            if swept == discovered.len() || unexercised.is_empty() {
                break;
            }
            let upto = (swept + batch).min(discovered.len());
            for (_, path) in &discovered[swept..upto] {
                let _ = sweep.eval_rule(path.clone());
            }
            COVERAGE_CASES.fetch_add(upto - swept, Ordering::Relaxed);
            swept = upto;
            batch *= 2;
            // `file.code` is untouched: a coverage report is the most
            // payload-shaped thing in this crate and rule 4 admits a pointer.
            let Ok(report) = sweep.get_coverage_report() else {
                return None;
            };
            // Cases ran and the report mentions nothing at all: the coverage
            // read did not happen, which is a different answer from "no test
            // entered anything" and must not be reported as one (CLOUD-251).
            if report.files.iter().all(|file| file.covered.is_empty()) {
                if sweep_spent(swept, discovered.len()) {
                    return None;
                }
                continue;
            }
            let entered: BTreeMap<&str, &BTreeSet<u32>> = report
                .files
                .iter()
                .map(|file| (file.path.as_str(), &file.covered))
                .collect();
            unexercised.retain(|id| !entered_predicate(described, &entered, id));
        }
    }
    Some(unexercised)
}

/// Whether a sweep that has run `swept` of `total` cases and read an empty
/// coverage report is done: only once every case has run. Before that a later
/// batch may yet report.
///
/// Apart from the sweep so a case can reach it: a bundle that compiles runs
/// only cases that cover at least their own line (measured: a constant, a
/// `false`, a `default` and a `true` case each cover theirs), and one that
/// faults is refused at compile, so no fixture produces the empty report.
const fn sweep_spent(swept: usize, total: usize) -> bool {
    swept == total
}

/// Whether a case entered the rule raising predicate `id`: its HEAD line is
/// covered in `entered` (CLOUD-835).
fn entered_predicate(
    described: &[Described],
    entered: &BTreeMap<&str, &BTreeSet<u32>>,
    id: &str,
) -> bool {
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
    described.iter().any(|module| {
        entered.get(module.path.as_str()).is_some_and(|covered| {
            module.rules.iter().any(|rule| {
                rule.name != RULES_RULE
                    && rule.literals.iter().any(|text| text == id)
                    && covered.contains(&rule.head_line)
            })
        })
    })
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
    let Some(engine) = bundle.evaluator.engine() else {
        return Ok(Look::CouldNotLook);
    };
    let mut engine = engine.clone();
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

/// Run each registered module's own `test_` rules (CLOUD-835).
///
/// **The gap this closes.** `crates/batten/tests/it/policy_modules.rs` exercises
/// the *evaluator*; nothing exercises a *module*. That is a blocker rather than
/// a nicety because the retirement campaign has to move 1,570 of 2,485 bats
/// cases onto policy rows, and CLOUD-202 measured the trap that makes an
/// untested port worse than none — the shell tasks spell `1 = violation,
/// 2 = could not read` and this contract is the exact inverse.
///
/// **The fixture is the row's own `documents`.** No new config key: CLOUD-833
/// already gave a tree-scoped policy row the documents it hands its bundle, and
/// `crate::rules::tree_document` already parses them and returns the ones the tree does
/// not carry rather than guessing. Non-negotiable 6 keeps configuration narrow,
/// and this is the reuse that honours it.
///
/// # Exit codes, and the two faults kept apart
///
/// `2` when a test failed or a published predicate went unexercised — the row's
/// §7(b) is explicit that the latter is *"reported, not green"*. `1` when the
/// suite could not run: a declared fixture the tree does not carry, or a sweep
/// that did not happen. Separating them is CLOUD-202's whole lesson, and
/// `tests/policy_test.rs` asserts each independently so the port cannot
/// reintroduce the inversion it exists to avoid.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the config will not resolve or a registered
/// module will not load — both refused by [`load`] with their own
/// message, at the boundary where a config fault belongs.
/// The tree input one policy suite runs against.
///
/// Split out of `run_policy_test` so that function reads as a loop over rows;
/// what it holds is the pair of deliberate omissions, which are easier to see
/// stated together than buried in an argument list.
///
/// **A SUITE RUNS AGAINST NO PRODUCED RECORD** (CLOUD-851). A module's tests must
/// decide the same way on every machine, and the sink store is per-checkout state
/// that differs between them — so a test that wants a baseline supplies it with
/// `with input as`, the same way a mediated-call suite supplies its call.
///
/// **AND AGAINST NO GIT FACT**, for exactly the same reason (CLOUD-907). HEAD, the
/// branch, the remotes and whether a ref resolves are all per-checkout state: a
/// suite that read them would pass on the author's machine and fail in CI's
/// detached, remote-less clone, which is a test asserting its environment rather
/// than its module.
pub(crate) fn suite_input(
    rule: &crate::config_model::Rule,
    documents: &std::collections::BTreeMap<(String, crate::rules::Wanted), crate::rules::Acquired>,
    tracked: &[String],
) -> Result<SuiteInput> {
    Ok(suite_input_of(
        &SuiteDeclared::of(rule, tracked)?,
        documents,
        tracked,
    ))
}

/// A suite input and the declared paths it could not acquire.
pub(crate) type SuiteInput = (String, Vec<(String, crate::rules::NotAcquired)>);

/// Everything of a row [`suite_input`] reads: the paths it declares in each
/// form, matched against the tracked list, and its base (CLOUD-2830).
///
/// THE KEY A RUN PROJECTS BY. Rows declaring the same paths are handed the same
/// input, and projecting the acquired facts into it again for each measured
/// 12% of `policy test`'s samples; `policy test` projects once per distinct
/// value of this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SuiteDeclared {
    documents: Vec<String>,
    lines: Vec<String>,
    invocations: Vec<String>,
    uses: Vec<String>,
    units: Vec<String>,
    base: Option<String>,
}

impl SuiteDeclared {
    /// What `rule` declares over `tracked`.
    pub(crate) fn of(rule: &crate::config_model::Rule, tracked: &[String]) -> Result<Self> {
        Ok(Self {
            documents: crate::rules::declared_documents(rule, tracked)?,
            lines: crate::rules::declared_lines(rule, tracked)?,
            invocations: crate::rules::declared_invocations(rule, tracked)?,
            uses: crate::rules::declared_uses(rule, tracked)?,
            units: crate::rules::declared_units(rule, tracked)?,
            base: rule.base.clone(),
        })
    }
}

/// [`suite_input`] for a declaration already matched.
pub(crate) fn suite_input_of(
    declared: &SuiteDeclared,
    documents: &std::collections::BTreeMap<(String, crate::rules::Wanted), crate::rules::Acquired>,
    tracked: &[String],
) -> SuiteInput {
    // A mediated-call row declares no documents, so its tests run against `{}`
    // and supply their own input with `with input as` — OPA and Conftest's own
    // shape, and the reason neither surface needs a fixture key.
    crate::rules::tree_document(
        documents,
        &crate::config_check::rules::Declared {
            documents: &declared.documents,
            lines: &declared.lines,
            invocations: &declared.invocations,
            uses: &declared.uses,
            units: &declared.units,
            base: declared.base.as_deref(),
            // EMPTY, unlike its neighbours above, and the asymmetry is the
            // point (CLOUD-1167). `documents` and the three beside it name paths
            // INSIDE the repository, so a declared one that is missing is a
            // fixture the author owes. An `[[rule.external]]` row names a file
            // outside it — a launcher's settings, a toolchain's data directory —
            // which is legitimately absent on a CI runner, in a fresh container,
            // and on any host that does not run that launcher. Resolving the
            // declared list here would report every such host as a missing
            // fixture and fail `policy test` for a file the module's own `test_`
            // rules never read: they supply their input with `with input as`,
            // which is what this call is building the SHAPE for.
            //
            // Whether a declared out-of-root file actually resolves is `check`'s
            // question, and `check` answers it the way the family requires — the
            // id goes to `input.tree.missing` with its cause and the row is
            // skipped, rather than running against a fabricated empty document.
            // EMPTY for `external`'s reason: a staged read needs an index this
            // shape-building call has no reason to open.
            staged: &[],
            // Nothing to fall back FOR: the list above is empty, so no path ever
            // reaches the extension test this would answer.
            staged_format: None,
            external: &[],
        },
        tracked,
        // A module's own `test_` rules supply their input with `with input as`,
        // so every member here is empty for one reason: this call builds the
        // SHAPE, and the case chooses the values.
        &crate::rules::Resolved {
            traversals: &serde_json::Value::Null,
            review: &crate::facts::Look::IsNot,
            produced: &std::collections::BTreeMap::new(),
            records: &std::collections::BTreeMap::new(),
            records_blocked: &std::collections::BTreeMap::new(),
            git: &crate::git::GitFacts::default(),
            symbols: &crate::facts::Look::IsNot,
            external: &std::collections::BTreeMap::new(),
            state: None,
            forge: None,
            tool_verdicts: None,
            plan: None,
            minted: None,
            captured: None,
            shell: None,
        },
    )
}

/// Whether one policy module's own `test_<case>` rule passes under `root`'s
/// committed config: `Some(true)` passed, `Some(false)` failed, `None` when no
/// registered rule's module is `module` or the module declares no such test
/// (CLOUD-2255).
///
/// THE MUTATION SWEEP'S REGO SUITE, IN PROCESS. A `#MUTANT` row in a module
/// that names one of the module's own tests is judged by that test, the way
/// `opa test --run` selects one: through the same load, input and evaluator
/// `policy test` uses, over the staged (mutated) tree, so the registry data the
/// module reads is supplied and nothing is spawned. Conftest, the other `.rego`
/// suite, supplies none of it.
///
/// # Errors
///
/// When the config under `root` does not resolve or a bundle does not load:
/// could-not-look, never a pass.
pub fn case(root: &Path, module: &str, case: &str) -> Result<Option<bool>> {
    let config = crate::resolve::resolve(root, &crate::resolve::Overrides::default())?;
    let Some(rule) = config.rules.iter().find(|rule| {
        rule.kind == crate::config_model::RuleKind::Policy && rule.module.as_deref() == Some(module)
    }) else {
        return Ok(None);
    };
    // EVERY ROW LOADED, ONE EVALUATED: the registry check holds the declared
    // verdicts against the raisers among the loaded bundles, so loading the one
    // row would refuse every class another module raises.
    let bundles = load(
        root,
        &config.rules,
        Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            words: (!config.vocabulary.is_empty()).then_some(&config.vocabulary),
            recorders: &config.recorders,
            registers: &config.registers,
            traversals: &config.traversals,
            records: &config.records,
        },
        ModuleChecks::Run,
        None,
    )?;
    let Some(bundle) = bundles.iter().find(|bundle| bundle.id() == rule.id) else {
        return Ok(None);
    };
    let tracked = crate::git::tree_files(root)?;
    let documents =
        crate::rules::acquire_declared(std::slice::from_ref(rule), root, &tracked, &tracked)?;
    let (input, _) = suite_input(rule, &documents, &tracked)?;
    let crate::facts::Look::Is(suite) = test(
        bundle,
        &input,
        rule.scope == crate::preset_catalog::RuleScope::MediatedCall,
        Some(root),
    )?
    else {
        return Ok(None);
    };
    let name = format!("test_{case}");
    let named = |ids: &[TestId]| ids.iter().any(|id| id.name == name);
    Ok(if named(&suite.passed) {
        Some(true)
    } else if named(&suite.failed) {
        Some(false)
    } else {
        None
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(test)]
    /// One module publishing `a`, refusing a write, with one test that does.
    const MODULE: &str = "package batten.a\nimport rego.v1\n\nrules contains \"a\"\n\n\
violation contains {\"rule\": \"a\", \"verdict\": \"a\"} if {\n\tinput.call.operation == \"write\"\n}\n\n\
test_a_write_is_refused if {\n\tcount(violation) == 1 with input as {\"call\": {\"operation\": \"write\"}}\n}\n";

    fn sources_of(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
            .collect()
    }

    fn bundle_of(id: &str, sources: &[(&str, &str)]) -> Bundle {
        compile(id, &sources_of(sources), &serde_json::json!({})).expect("the fixture compiles")
    }

    /// The verdicts `deny` answers over `input`, or `None` for could-not-look.
    fn verdicts(bundle: &Bundle, input: &str) -> Option<Vec<String>> {
        match deny(bundle, input) {
            Look::Is(found) => Some(found.into_iter().map(|v| v.verdict).collect()),
            Look::CouldNotLook | Look::IsNot => None,
        }
    }

    /// The desugared sources, and each case by name with how it is decided.
    type Plans = (
        Vec<(String, String)>,
        Vec<(String, std::result::Result<String, String>)>,
    );

    /// Fails by: a rule's function head folded into its facts with `&=`, so
    /// no rule is ever recorded as a function.
    #[test]
    fn a_function_rule_is_recorded_as_one_and_a_plain_rule_is_not() {
        const MODULE: &str = "package batten.p\nimport rego.v1\n\nf(x) := input.a\n\nr := 1\n";
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let engine = bundle.evaluator.engine().expect("an interpreter");
        let ast = Ast::of(engine).expect("the AST serialises");
        let packages = package_facts(&ast.0);
        let rules = packages.values().next().expect("the package's facts");
        assert!(
            rules["f"].function,
            "{:?}",
            rules.keys().collect::<Vec<_>>()
        );
        assert!(!rules["r"].function);
    }

    /// Fails by: a `with` or an input read carried less than the whole way
    /// along a chain of rules: the propagation's `!` dropped, so a rule
    /// already marked is the only one marked again, or the fixed point left
    /// after the first pass that changed anything, so a rule two references
    /// away is never reached (CLOUD-2789).
    #[test]
    fn a_with_and_an_input_read_reach_every_rule_a_chain_leads_to() {
        const MODULE: &str = "package batten.p\nimport rego.v1\n\n\
            c if {\n\tinput.x with input as {\"x\": 1}\n}\n\n\
            b if {\n\tc\n}\n\n\
            a if {\n\tb\n}\n";
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let engine = bundle.evaluator.engine().expect("an interpreter");
        let ast = Ast::of(engine).expect("the AST serialises");
        let packages = package_facts(&ast.0);
        let rules = packages.values().next().expect("the package's facts");
        assert!(
            rules["c"].with && rules["c"].reads,
            "the premise: `c` writes a `with` and reads the input"
        );
        for name in ["b", "a"] {
            assert!(rules[name].with, "`{name}` reaches the `with`");
            assert!(rules[name].reads, "`{name}` reaches the input read");
        }
    }

    /// Each case of one module by name with how it is decided, and the
    /// desugared sources the suite program compiles.
    fn planned(source: &str) -> Plans {
        let bundle = bundle_of("row", &[("policy/a.rego", source)]);
        let engine = bundle.evaluator.engine().expect("an interpreter");
        let ast = Ast::of(engine).expect("the AST serialises");
        let (sources, tests) = plan_suite(&ast).expect("the suite plans");
        let tests = tests
            .into_iter()
            .map(|test| (test.name, test.decided_by))
            .collect();
        (sources, tests)
    }

    /// Fails by: a rule two references from `input`, or from a `with`, left
    /// unmarked (the spread stops a level short or never starts), or a rule
    /// reaching neither marked anyway; or a spread that never settles.
    #[test]
    fn reads_and_with_spread_through_references_and_nowhere_else() {
        const MODULE: &str = "package batten.p\nimport rego.v1\n\n\
            a := input.x\n\nb := a\n\nc := b\n\nd := 1\n\n\
            w if {\n\tcount([1]) == 1 with data.q as 1\n}\n\nv := w\n\nu := v\n";
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let engine = bundle.evaluator.engine().expect("an interpreter");
        let ast = Ast::of(engine).expect("the AST serialises");
        let packages = package_facts(&ast.0);
        let rules = packages.values().next().expect("the package's facts");
        let marked = |flag: fn(&RuleFacts) -> bool| -> Vec<&str> {
            rules
                .iter()
                .filter(|(_, fact)| flag(fact))
                .map(|(name, _)| name.as_str())
                .collect()
        };
        // `w`'s `with data.q` reads `data` too, so its chain reads; `d` alone
        // reaches neither.
        assert_eq!(marked(|fact| fact.reads), ["a", "b", "c", "u", "v", "w"]);
        assert_eq!(marked(|fact| fact.with), ["u", "v", "w"]);
    }

    /// A module whose one case writes `with data.batten.patterns.<key>` as
    /// `key`, over a rule reading `data.batten.patterns.a.b`.
    fn patterns_case(key: &str, term: &str) -> String {
        format!(
            "package batten.a\nimport rego.v1\n\nrules contains \"a\"\n\n\
violation contains {{\"rule\": \"a\", \"verdict\": \"a\"}} if {{\n\tdata.batten.patterns.a.b == 1\n}}\n\n\
test_patterns if {{\n\tcount(violation) == 1 with data.batten.patterns.{key} as {term}\n}}\n"
        )
    }

    /// Fails by: a `with` on a DOTTED key under the pattern table taken as a
    /// key of the table itself, which the desugaring cannot override.
    #[test]
    fn a_with_on_a_dotted_pattern_key_keeps_the_interpreter() {
        let (_, whole) = planned(&patterns_case("a", "{\"b\": 1}"));
        assert!(
            whole[0].1.is_ok(),
            "THE PREMISE: a single key plans: {whole:?}"
        );
        let (_, dotted) = planned(&patterns_case("a.b", "1"));
        let why = dotted[0].1.as_ref().expect_err("a dotted key cannot plan");
        assert!(why.contains("data.batten.patterns.a.b"), "{why}");
    }

    /// Fails by: a helper's own `with`, which sits inside its body's list of
    /// statements, not seen, so a case reading the helper is desugared and
    /// the helper's `with` reaches the bytecode compiler.
    #[test]
    fn a_helper_writing_its_own_with_keeps_the_interpreter() {
        let source = "package batten.a\nimport rego.v1\n\nrules contains \"a\"\n\n\
violation contains {\"rule\": \"a\", \"verdict\": \"a\"} if {\n\tinput.call.operation == \"write\"\n}\n\n\
writes_with if {\n\tcount(violation) == 1 with input as {\"call\": {\"operation\": \"write\"}}\n}\n\n\
test_helper if {\n\twrites_with\n}\n";
        let (_, tests) = planned(source);
        let why = tests[0]
            .1
            .as_ref()
            .expect_err("the helper's `with` cannot plan");
        assert!(why.contains("helper"), "{why}");
    }

    /// Fails by: a string literal's opening quote cut off its span, so the
    /// desugared case is no longer Rego.
    #[test]
    fn a_string_keeps_both_quotes_in_the_desugared_case() {
        let source = "package batten.a\nimport rego.v1\n\nrules contains \"a\"\n\n\
violation contains {\"rule\": \"a\", \"verdict\": \"a\"} if {\n\tinput == \"write\"\n}\n\n\
test_string if {\n\t\"x\" == \"x\"\n\tcount(violation) == 1 with input as \"write\"\n}\n";
        let (sources, tests) = planned(source);
        assert!(tests[0].1.is_ok(), "{tests:?}");
        let text = &sources[0].1;
        assert!(text.contains(":= \"write\""), "{text}");
        assert!(text.contains("\t\"x\" == \"x\""), "{text}");
    }

    /// Fails by: a suite program not written to its cache, so every run
    /// compiles it again.
    #[test]
    fn a_suite_program_is_read_back_from_its_cache() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let engine = bundle.evaluator.engine().expect("an interpreter");
        let root = crate::scratch::scratch("policy-suite-cache");
        let Ok(first) = SuiteProgram::load("row", (engine, bundle.ast()), Some(&root)) else {
            panic!("the suite program compiles");
        };
        assert!(!first.cached, "THE PREMISE: an empty cache holds nothing");
        let Ok(second) = SuiteProgram::load("row", (engine, bundle.ast()), Some(&root)) else {
            panic!("the suite program loads");
        };
        assert!(second.cached);
    }

    /// Fails by: a split invented, or a case-only rule taken as an entry, in
    /// the parity diagnostics over a bundle whose engines agree.
    #[test]
    fn agreeing_engines_report_no_split_and_name_only_non_test_input() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        assert_eq!(suite_splits(&bundle, "{}"), Vec::<String>::new());
        assert_eq!(
            rule_splits(&bundle, &serde_json::json!({}), "{}"),
            Vec::<String>::new()
        );
        let paths = input_paths(&bundle);
        assert!(
            !paths.is_empty() && paths.iter().all(|path| !path.is_empty()),
            "{paths:?}"
        );
        assert_eq!(bytecode(bundle).fallback_detail(), None);
    }

    fn suite_of(bundle: &Bundle, mediated: bool) -> Suite {
        match test(bundle, "{}", mediated, None).expect("the input parses") {
            Look::Is(suite) => suite,
            Look::CouldNotLook | Look::IsNot => panic!("the sweep ran"),
        }
    }

    /// Fails by: a string's opening delimiter looked for after the span's
    /// start rather than before it, so the literal is cut at its first byte.
    #[test]
    fn a_spanned_string_keeps_both_its_delimiters() {
        assert_eq!(spanned("x = \"abc\"", 5, 8), Some("\"abc\""));
        assert_eq!(spanned("x = abc", 4, 7), Some("abc"));
    }

    /// Fails by: the `test_` rules' reads reported as the module's, and its
    /// verdict rules' reads dropped.
    #[test]
    fn a_bundles_input_paths_are_its_verdict_rules_reads() {
        const READS: &str = "package batten\n\nimport rego.v1\n\n\
            violation contains \"a\" if input.tree.staged == 1\n\n\
            test_reads_more if {\n\tinput.tree.tracked == 1\n\tinput.facts.session == 1\n}\n";
        let bundle = bundle_of("row", &[("policy/a.rego", READS)]);
        assert_eq!(input_paths(&bundle), [String::from("tree.staged")]);
    }

    /// Fails by: a case's `with` on one named pattern key refused as a `with`
    /// on a path the plan cannot bind, so the case leaves the bytecode.
    #[test]
    fn a_with_on_one_pattern_key_stays_on_bytecode() {
        const KEYED: &str = "package batten.p\n\nimport rego.v1\n\n\
            violation contains \"hit\" if data.batten.patterns.foo == 1\n\n\
            test_a_keyed_pattern_is_read if {\n\
            \tcount(violation) == 1 with data.batten.patterns.foo as 1\n}\n";
        let bundle = compile(
            "row",
            &sources_of(&[("policy/p.rego", KEYED)]),
            &serde_json::json!({"batten": {"patterns": {"foo": 0}}}),
        )
        .expect("the fixture compiles");
        assert_eq!(suite_splits(&bundle, "{}"), Vec::<String>::new());
    }

    /// Fails by: two set answers that differ reported whole rather than as
    /// what each holds that the other does not. The two engines are handed
    /// different `data` here, which is how a split is made to appear.
    #[test]
    fn a_set_split_names_each_sides_own_members() {
        const SET: &str = "package batten.s\n\nimport rego.v1\n\n\
            violation contains x if some x in data.extra\n";
        let bundle = bundle_of("row", &[("policy/s.rego", SET)]);
        let splits = rule_splits(&bundle, &serde_json::json!({"extra": ["a"]}), "{}");
        assert_eq!(splits.len(), 1, "{splits:?}");
        assert!(
            splits[0].contains("only bytecode [\"a\"] only interpreter []"),
            "{splits:?}"
        );
    }

    /// Fails by: an empty coverage report read as final before every case has
    /// run (a later batch may yet report), or swept on past the last case, so
    /// a coverage read that never happened reads as "no case entered anything".
    #[test]
    fn an_empty_coverage_report_is_final_only_once_every_case_ran() {
        assert!(super::sweep_spent(3, 3));
        assert!(!super::sweep_spent(1, 3));
    }

    /// Fails by: a bytecode verdict that differs from the interpreter's read
    /// as agreement, so the parity gate never reports the miscompile it exists
    /// for; or one that agrees reported as a split.
    #[test]
    fn a_case_split_is_reported_only_where_the_verdicts_differ() {
        let test = PlannedTest {
            module: String::from("policy/a.rego"),
            name: String::from("test_a"),
            decided_by: Ok(String::from("data.a.test_a")),
            contexts: Vec::new(),
        };
        assert_eq!(super::case_split("row", &test, Some(true), true), None);
        assert_eq!(super::case_split("row", &test, Some(false), false), None);
        assert_eq!(
            super::case_split("row", &test, Some(true), false).as_deref(),
            Some("row: policy/a.rego test_a: bytecode true interpreter false")
        );
        assert_eq!(
            super::case_split("row", &test, Some(false), true).as_deref(),
            Some("row: policy/a.rego test_a: bytecode false interpreter true")
        );
    }

    #[test]
    fn a_bundle_answers_for_its_row_its_modules_and_what_it_publishes() {
        let before = engines_constructed();
        let a = bundle_of("row", &[("policy/a.rego", MODULE)]);
        assert!(engines_constructed() > before, "compile counts its engine");
        assert_eq!(a.id(), "row");
        assert_eq!(a.pointer(), "policy/a.rego");
        assert_eq!(
            a.modules().iter().map(Module::path).collect::<Vec<_>>(),
            vec!["policy/a.rego"]
        );
        assert_eq!(a.declared(), &BTreeSet::from(["a".to_owned()]));
        assert!(!a.is_bytecode());
        assert_eq!(a, bundle_of("row", &[("policy/a.rego", MODULE)]));
        assert_ne!(a, bundle_of("other", &[("policy/a.rego", MODULE)]));
        assert_ne!(a, bundle_of("row", &[("policy/b.rego", MODULE)]));
        let quiet = bundle_of(
            "quiet",
            &[("policy/q.rego", "package batten.q\nimport rego.v1\n")],
        );
        assert_eq!(quiet.pointer(), "policy/q.rego");
        let bundles = [a.clone(), quiet];
        assert_eq!(publishers_of(&bundles, "a"), BTreeSet::from(["row"]));
        assert!(publishers_of(&bundles, "nothing").is_empty());
        assert_eq!(preset_names(), crate::preset_catalog::names());
    }

    #[test]
    fn a_violation_is_raised_for_the_call_its_module_refuses_and_no_other() {
        let a = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let Look::Is(refused) = deny(&a, r#"{"call":{"operation":"write"}}"#) else {
            panic!("the bundle answers");
        };
        assert_eq!(
            refused
                .iter()
                .map(|v| v.rule.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("a")]
        );
        assert_eq!(a.attribute(&refused[0]), "a");
        let Look::Is(allowed) = deny(&a, r#"{"call":{"operation":"read"}}"#) else {
            panic!("the bundle answers");
        };
        assert!(allowed.is_empty());
    }

    /// The stripped bundle a checked load's program is taken from reads what
    /// describing its own text reads, without describing it: the seed is the
    /// full reading less the `test_` rules. A `test_` rule here reads a tree key
    /// and a fact no verdict rule reads, so a seed that kept them, or dropped a
    /// verdict rule, answers differently from describing the stripped text.
    #[test]
    fn a_stripped_bundle_seeded_from_the_full_reading_reads_what_describing_it_reads() {
        const READS: &str = "package batten\n\nimport rego.v1\n\n\
            violation contains \"a\" if input.tree.staged == 1\n\n\
            test_reads_more if {\n\tinput.tree.tracked == 1\n\tinput.facts.session == 1\n}\n";
        let full = bundle_of("row", &[("policy/a.rego", READS)]);
        let stripped = || bundle_of("row", &[("policy/a.rego", &without_test_rules(READS))]);
        let described = stripped();
        let seeded = stripped();
        let before = ast_descriptions();
        seeded.seed_stripped_from(&full);
        assert_eq!(ast_descriptions() - before, 1, "the full bundle, once");
        assert_eq!(
            seeded.tree_reads(),
            Reads::Known(BTreeSet::from([String::from("staged")]))
        );
        let before = ast_descriptions();
        assert_eq!(seeded.tree_reads(), described.tree_reads());
        assert_eq!(
            seeded.session_start_facts(),
            described.session_start_facts()
        );
        assert_eq!(ast_descriptions() - before, 1, "only the control describes");
    }

    /// A suite is a violation when a test fails, a predicate goes unexercised,
    /// or a mediated module's tests never pass a compound command.
    #[test]
    fn a_suite_is_a_violation_for_each_of_its_three_faults() {
        let before = ast_descriptions();
        let a = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let clean = suite_of(&a, false);
        assert!(
            ast_descriptions() > before,
            "the suite describes the bundle"
        );
        assert_eq!(clean.passed.len(), 1);
        assert!(clean.failed.is_empty() && clean.unexercised.is_empty());
        assert!(!clean.is_violation());

        let failing = MODULE.replace("count(violation) == 1", "count(violation) == 2");
        let failed = suite_of(&bundle_of("row", &[("policy/a.rego", &failing)]), false);
        assert_eq!(failed.failed.len(), 1);
        assert!(failed.is_violation());

        let untested = "package batten.u\nimport rego.v1\n\nrules contains \"u\"\n\n\
violation contains {\"rule\": \"u\", \"verdict\": \"u\"} if {\n\tinput.call.operation == \"write\"\n}\n";
        let unexercised = suite_of(&bundle_of("row", &[("policy/u.rego", untested)]), false);
        assert_eq!(
            unexercised.untested_modules,
            vec!["policy/u.rego".to_owned()]
        );
        assert_eq!(unexercised.unexercised, vec!["u".to_owned()]);
        assert!(unexercised.is_violation());

        let bare = suite_of(&a, true);
        assert_eq!(bare.bare_only_modules, vec!["policy/a.rego".to_owned()]);
        assert!(bare.failed.is_empty() && bare.unexercised.is_empty());
        assert!(bare.is_violation());
    }

    #[test]
    fn a_bundle_names_the_session_start_facts_its_modules_read() {
        let pinned = crate::facts::Fact::Pinned.as_str();
        let module = format!(
            "package batten.f\nimport rego.v1\n\nreads if {{\n\tinput.facts[\"{pinned}\"]\n}}\n\n\
             also if {{\n\tinput.facts.receipts\n}}\n"
        );
        let facts = bundle_of("row", &[("policy/f.rego", &module)]).session_start_facts();
        assert_eq!(facts, BTreeSet::from([pinned]));
    }

    #[test]
    fn a_module_s_own_tests_are_dropped_from_the_hot_path_and_nothing_else_is() {
        let source = "package p\n\ntest_one if {\n\ttrue\n}\n\nkept if {\n\ttrue\n}\n\ntest_two := 1\nlast := 2\n";
        assert_eq!(
            without_test_rules(source),
            "package p\n\nkept if {\n\ttrue\n}\n\nlast := 2\n"
        );
    }

    #[test]
    fn a_finding_id_is_read_off_a_declaration_or_a_rule_string_and_nothing_else() {
        let text = "rules contains \"x\"\nnamed_rules contains \"y\"\n\
violation contains {\"rule\": \"z\", \"msg\": \"m\"}\n\"rule\": [{\"id\": \"r\"}]\n\
rules contains not_quoted\n";
        assert_eq!(
            finding_ids(text),
            BTreeSet::from(["x".to_owned(), "z".to_owned()])
        );
    }

    /// A deny-severity policy row `id` at `scope`, naming its `source` line.
    fn policy_row(id: &str, scope: &str, source: &str, extra: &str) -> Rule {
        toml::from_str(&format!(
            "id = \"{id}\"\nkind = \"policy\"\nscope = \"{scope}\"\n{source}\n\
             severity = \"deny\"\n{extra}"
        ))
        .expect("the fixture row loads")
    }

    fn git_row(extra: &str) -> Rule {
        policy_row("git calls", "mediated_call", "preset = \"git\"", extra)
    }

    #[test]
    fn a_preset_row_compiles_its_scope_s_modules_less_what_it_excepts() {
        let manifest = crate::preset_catalog::find("git").expect("git ships");
        let names: Vec<_> = manifest
            .modules
            .iter()
            .map(crate::preset_catalog::PresetModule::name)
            .collect();
        let sources = preset_sources(&git_row(""), manifest, "git").unwrap();
        assert_eq!(sources.len(), names.len());
        assert!(names.len() > 1, "the fixture needs a module to keep");
        assert!(
            preset_sources(&git_row("except = [\"no-such-module\"]\n"), manifest, "git").is_err()
        );
        let one = preset_sources(
            &git_row(&format!("except = [\"{}\"]\n", names[0])),
            manifest,
            "git",
        )
        .unwrap();
        assert_eq!(
            one.len(),
            names.len() - 1,
            "an excepted module is not compiled"
        );
        let every = names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            preset_sources(&git_row(&format!("except = [{every}]\n")), manifest, "git").is_err(),
            "excepting every module decides nothing"
        );
        let mut tree = git_row("");
        tree.scope = crate::preset_catalog::RuleScope::Tree;
        assert!(
            preset_sources(&tree, manifest, "git").is_err(),
            "no module at that scope"
        );
    }

    #[test]
    fn an_ejected_copy_is_paired_with_the_vendored_module_its_header_names() {
        let manifest = crate::preset_catalog::find("git").expect("git ships");
        let module = &manifest.modules[0];
        let copy = format!(
            "# batten-ejected: git/{} version {}\npackage x\n",
            module.name(),
            manifest.version
        );
        let originals = ejected_originals(&[
            ("policy/git/copy.rego".to_owned(), copy),
            ("policy/own.rego".to_owned(), "package own\n".to_owned()),
            (
                "policy/stale.rego".to_owned(),
                "# batten-ejected: git/gone version 1\n".to_owned(),
            ),
        ]);
        assert_eq!(
            originals,
            BTreeMap::from([("policy/git/copy.rego".to_owned(), module.text())])
        );
    }

    #[test]
    fn both_input_schemas_are_objects_with_properties() {
        for schema in [tree_input_schema().unwrap(), call_input_schema().unwrap()] {
            let parsed: serde_json::Value = serde_json::from_str(&schema).unwrap();
            assert!(
                parsed
                    .get("properties")
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|properties| !properties.is_empty()),
                "{schema}"
            );
        }
        let call: serde_json::Value = serde_json::from_str(&call_input_schema().unwrap()).unwrap();
        let facts = &call["properties"]["facts"]["properties"];
        for fact in crate::facts::Fact::ALL {
            assert_eq!(
                facts.get(fact.as_str()).is_some(),
                fact.class().surface == crate::facts::Surface::Hook,
                "{}",
                fact.as_str()
            );
        }
    }

    fn module_row(id: &str, scope: &str, extra: &str) -> Rule {
        policy_row(id, scope, "module = \"policy/m.rego\"", extra)
    }

    fn class(id: &str, extra: &str) -> crate::config_model::DeclaredVerdict {
        toml::from_str(&format!(
            "id = \"{id}\"\ngloss = \"g\"\nclass = \"c\"\n{extra}"
        ))
        .expect("the fixture class loads")
    }

    /// Refuses through the bare `deny` channel on any input carrying `go`.
    const GATED: &str =
        "package batten.d\nimport rego.v1\n\ndeny contains \"tok\" if {\n\tinput.go\n}\n";
    const GO: &str = r#"{"go":true}"#;
    const STOP: &str = r#"{"stop":true}"#;

    fn bytecode(bundle: Bundle) -> Bundle {
        Compiled::from_bundle(&bundle, &serde_json::json!({}))
            .expect("the fixture compiles to bytecode")
            .into_bundle(bundle, false)
    }

    /// [`bytecode`] past batten's own refusals of known miscompiles, to show
    /// what regorus would answer.
    fn bytecode_unchecked(bundle: Bundle) -> Bundle {
        Compiled::compile_unchecked(&bundle, &serde_json::json!({}))
            .expect("regorus compiles the fixture")
            .into_bundle(bundle, false)
    }

    /// CLOUD-2696's shape: a helper function undefined for the call, bound with
    /// `:=` and then negated over. Both evaluators must read the undefined
    /// helper as no violation. Fails by: the bytecode deciding a violation the
    /// interpreter — and so `policy test` — does not.
    const UNDEFINED_HELPER: &str = r#"package batten.helper

import rego.v1

rules contains "commit name refused"

subject(args) := message if {
	some i, word in args
	word == "-m"
	message := args[i + 1]
}

violation contains {"rule": "commit name refused", "verdict": "commit name refused", "subjects": []} if {
	some program in input.call.programs
	message := subject(program.arguments)
	not regex.match(`^feat`, message)
}
"#;

    #[test]
    fn an_undefined_helper_decides_alike_in_both_evaluators() {
        let none = r#"{"call":{"programs":[{"arguments":["commit","--amend"]}]}}"#;
        let wrong = r#"{"call":{"programs":[{"arguments":["commit","-m","fix: x"]}]}}"#;
        let right = r#"{"call":{"programs":[{"arguments":["commit","-m","feat: x"]}]}}"#;
        let interpreted = bundle_of("row", &[("policy/h.rego", UNDEFINED_HELPER)]);
        // As `compile_cached` builds it, and nothing re-decides its answer.
        let compiled = bytecode(bundle_of("row", &[("policy/h.rego", UNDEFINED_HELPER)]));
        assert!(compiled.is_bytecode());
        let before = engines_constructed();
        let _ = verdicts(&compiled, wrong);
        assert_eq!(
            engines_constructed() - before,
            0,
            "the program decides a refusal alone: no interpreter is built to re-decide it"
        );
        let refused = Some(vec!["commit name refused".to_owned()]);
        for (evaluator, bundle) in [("interpreted", &interpreted), ("bytecode", &compiled)] {
            assert_eq!(
                verdicts(bundle, none),
                Some(Vec::new()),
                "{evaluator}: no -m, no subject"
            );
            assert_eq!(verdicts(bundle, wrong), refused, "{evaluator}");
            assert_eq!(verdicts(bundle, right), Some(Vec::new()), "{evaluator}");
        }
    }

    /// A `:=` whose right side is a string literal, the last token of its
    /// statement (#1276). Fails by: the guard spliced inside the literal, so the
    /// bytecode binds `"x; p == p"` and refuses nothing where the interpreter
    /// refuses — `rules-drift.rego`'s `authority_needed`, measured.
    const LITERAL_BINDING: &str = "package batten.lit\nimport rego.v1\n\n\
        named contains p if {\n\tinput.go\n\tp := \"x\"\n}\n\n\
        deny contains \"tok\" if {\n\t\"x\" in named\n}\n\n\
        raw contains q if {\n\tinput.go\n\tq := `y`\n}\n\n\
        deny contains \"raw\" if {\n\t\"y\" in raw\n}\n";

    #[test]
    fn a_binding_ending_in_a_string_literal_decides_alike_in_both_evaluators() {
        let guarded = guarded_sources(
            bundle_of("row", &[("policy/l.rego", LITERAL_BINDING)])
                .evaluator
                .engine()
                .expect("interpreted"),
        )
        .expect("the guard splices");
        assert!(
            guarded[0].1.contains("p := \"x\"; p == p"),
            "the guard follows the closing quote: {}",
            guarded[0].1
        );
        assert!(
            guarded[0].1.contains("q := `y`; q == q"),
            "and a raw string's backtick: {}",
            guarded[0].1
        );
        let interpreted = bundle_of("row", &[("policy/l.rego", LITERAL_BINDING)]);
        let compiled = bytecode(bundle_of("row", &[("policy/l.rego", LITERAL_BINDING)]));
        for (evaluator, bundle) in [("interpreted", &interpreted), ("bytecode", &compiled)] {
            assert_eq!(
                verdicts(bundle, GO),
                Some(vec!["raw".to_owned(), "tok".to_owned()]),
                "{evaluator}"
            );
            assert_eq!(verdicts(bundle, STOP), Some(Vec::new()), "{evaluator}");
        }
    }

    /// `_ := e` as a braceless body, the spelling of "e is defined" (#1276):
    /// `ci-parity.rego`'s `on_pull_request(path) if _ :=
    /// triggers(path).pull_request`. Fails by: the wildcard left unguarded, so
    /// the bytecode binds `Undefined` and `on("b")` holds where the interpreter
    /// — and OPA — say it does not.
    const WILDCARD_BINDING: &str = "package batten.w\nimport rego.v1\n\n\
        on(x) if _ := input.triggers[x]\n\n\
        deny contains x if {\n\tsome x in [\"a\", \"b\"]\n\ton(x)\n}\n";

    #[test]
    fn a_wildcard_binding_decides_alike_in_both_evaluators() {
        let input = r#"{"triggers":{"a":{}}}"#;
        let interpreted = bundle_of("row", &[("policy/w.rego", WILDCARD_BINDING)]);
        let compiled = bytecode(bundle_of("row", &[("policy/w.rego", WILDCARD_BINDING)]));
        for (evaluator, bundle) in [("interpreted", &interpreted), ("bytecode", &compiled)] {
            assert_eq!(
                verdicts(bundle, input),
                Some(vec!["a".to_owned()]),
                "{evaluator}: only the defined trigger holds"
            );
        }
    }

    /// A `:=` whose pattern names no variable cannot be guarded (#1276).
    /// Fails by: the shape reaching bytecode, where it binds `Undefined`
    /// unguarded and the body holds over a missing pair.
    const UNGUARDABLE: &str = "package batten.u\nimport rego.v1\n\n\
        deny contains \"pair\" if {\n\t[_, _] := input.pair\n}\n";

    #[test]
    fn a_binding_naming_no_variable_is_refused_bytecode() {
        let interpreted = bundle_of("row", &[("policy/u.rego", UNGUARDABLE)]);
        assert_eq!(verdicts(&interpreted, "{}"), Some(Vec::new()), "no pair");
        let refused = Compiled::from_bundle(&interpreted, &serde_json::json!({}))
            .err()
            .expect("the shape is not compiled");
        assert_eq!(refused.0, Fallback::GuardUnavailable, "{refused:?}");
        assert_eq!(refused.1, "policy/u.rego:5", "names the statement");
        let named = bundle_of("row", &[("policy/n.rego", LITERAL_BINDING)]);
        assert!(
            named.ast().and_then(unguardable_assignment).is_none(),
            "a named binding is guardable"
        );
    }

    /// A function's `else` after a body that fails, three ways (#1276):
    /// `release-tracking.rego`'s `first_job(path)` answered `""` interpreted and
    /// undefined on bytecode, over a path with no calls.
    const FUNCTION_ELSE: &str = "package batten.e\nimport rego.v1\n\n\
        f(x) := \"body\" if { x == 1 } else := \"else\"\n\n\
        g(x) := m if { m := min({v | some v in x}) } else := \"else\"\n\n\
        h(x) := c if {\n\ts := {v | some v in x}\n\tsome c in x\n\tc == min(s)\n} else := \"else\"\n\n\
        i(x) := c if { some c in x } else := \"else\"\n\n\
        j(x) := c if { c := x[_] } else := \"else\"\n\n\
        k := c if { some c in input.none } else := \"else\"\n\n\
        deny contains \"f\" if f(2) == \"else\"\n\n\
        deny contains \"g\" if g([]) == \"else\"\n\n\
        deny contains \"h\" if h([]) == \"else\"\n\n\
        deny contains \"i\" if i([]) == \"else\"\n\n\
        deny contains \"j\" if j([]) == \"else\"\n\n\
        deny contains \"k\" if k == \"else\"\n";

    /// The upstream defect, pinned: regorus 0.15's bytecode drops an `else`
    /// after a body that fails by ITERATING NOTHING (`some c in []`, `x[_]`
    /// over `[]`), where a body failing on a comparison or an undefined call
    /// takes it. Batten therefore keeps every bundle with an `else` on the
    /// interpreter ([`Fallback::RuleElse`]); this case says which spellings the
    /// bytecode gets wrong, so the refusal can narrow when regorus is fixed.
    #[test]
    fn a_rule_else_after_an_empty_iteration_is_lost_on_bytecode() {
        let interpreted = bundle_of("row", &[("policy/e.rego", FUNCTION_ELSE)]);
        let all: Vec<String> = ["f", "g", "h", "i", "j", "k"].map(str::to_owned).into();
        assert_eq!(verdicts(&interpreted, "{}"), Some(all), "interpreted");
        let refused = Compiled::from_bundle(&interpreted, &serde_json::json!({}))
            .err()
            .expect("a bundle with an `else` is not compiled");
        assert_eq!(refused.0, Fallback::RuleElse, "{refused:?}");
        // What regorus's bytecode answers past the refusal: the `else` kept
        // after a failing comparison (`f`) or an undefined call (`g`), and
        // lost after every body that iterates nothing (`h` to `k`). When this
        // fails, regorus changed: narrow `rule_else` to what it still drops.
        let forced = bytecode_unchecked(bundle_of("row", &[("policy/e.rego", FUNCTION_ELSE)]));
        assert_eq!(
            verdicts(&forced, "{}"),
            Some(vec!["f".to_owned(), "g".to_owned()]),
            "the upstream defect, as regorus 0.15 has it"
        );
    }

    /// A partial SET under a variable key, `f[k] contains v` (#1276): regorus
    /// 0.15's bytecode answers it as the flat set of every `v`, dropping the
    /// keys, where the interpreter (and OPA) answer `{k: {v, …}}`. Measured on
    /// `module-layering.rego`'s `forbidden[from] contains to`. The upstream
    /// repro is this module over `{}`: `data.batten.k.f` is `{"a": {"x"},
    /// "b": {"y"}}` interpreted and `{"x", "y"}` on bytecode.
    const KEYED_SET: &str = "package batten.k\nimport rego.v1\n\n\
        f[k] contains v if {\n\tsome k, vs in {\"a\": {\"x\"}, \"b\": {\"y\"}}\n\tsome v in vs\n}\n\n\
        deny contains \"keyed\" if f.b == {\"y\"}\n";

    #[test]
    fn a_keyed_partial_set_is_refused_bytecode_rather_than_flattened() {
        let interpreted = bundle_of("row", &[("policy/k.rego", KEYED_SET)]);
        assert_eq!(
            verdicts(&interpreted, "{}"),
            Some(vec!["keyed".to_owned()]),
            "the interpreter answers the keyed set"
        );
        let refused = Compiled::from_bundle(&interpreted, &serde_json::json!({}))
            .err()
            .expect("the bytecode would flatten it, so it is not compiled");
        assert_eq!(refused.0, Fallback::KeyedPartialSet, "{refused:?}");
        assert!(
            refused.1.contains("policy/k.rego"),
            "names the module: {refused:?}"
        );
    }

    /// The same undefined helper behind an ARRAY pattern, so the guard covers
    /// every variable a pattern binds. No `with`: the RVM refuses the keyword
    /// and such a bundle stays interpreted; where the guard lands after a
    /// modifier is the text-level case below. Fails by: a pattern's variable
    /// left unguarded.
    const UNDEFINED_PAIR: &str = r#"package batten.pair

import rego.v1

rules contains "pair refused"

pair(args) := [first, rest] if {
	some i, word in args
	word == "-m"
	first := args[i + 1]
	rest := args[i + 2]
}

violation contains {"rule": "pair refused", "verdict": "pair refused", "subjects": []} if {
	some program in input.call.programs
	[first, _] := pair(program.arguments)
	not startswith(first, "feat")
}
"#;

    #[test]
    fn a_pattern_binding_an_undefined_helper_decides_alike_in_both_evaluators() {
        let none = r#"{"call":{"programs":[{"arguments":["commit","--amend"]}]}}"#;
        let wrong = r#"{"call":{"programs":[{"arguments":["commit","-m","fix","x"]}]}}"#;
        let interpreted = bundle_of("row", &[("policy/p.rego", UNDEFINED_PAIR)]);
        let compiled = bytecode(bundle_of("row", &[("policy/p.rego", UNDEFINED_PAIR)]));
        assert!(compiled.is_bytecode());
        for (evaluator, bundle) in [("interpreted", &interpreted), ("bytecode", &compiled)] {
            assert_eq!(verdicts(bundle, none), Some(Vec::new()), "{evaluator}");
            assert_eq!(
                verdicts(bundle, wrong),
                Some(vec!["pair refused".to_owned()]),
                "{evaluator}"
            );
        }
    }

    /// Fails by: a `:=` statement left unguarded, a guard for `_` or for an `=`
    /// statement, or a guard placed before the statement's `with` modifier.
    #[test]
    fn every_colon_binding_is_guarded_after_its_whole_statement() {
        let module = "package batten.g\nimport rego.v1\n\nx if {\n\ta := input.a\n\t[b, _] := input.b with input.c as 1\n\td = input.d\n}\n";
        let bundle = bundle_of("row", &[("policy/g.rego", module)]);
        let guarded = guarded_sources(bundle.evaluator.engine().expect("interpreted"))
            .expect("the AST serializes");
        assert_eq!(
            guarded,
            vec![(
                String::from("policy/g.rego"),
                module
                    .replacen("a := input.a", "a := input.a; a == a", 1)
                    .replacen("with input.c as 1", "with input.c as 1; b == b", 1),
            )]
        );
    }

    /// Fails by: a bundle that dropped its interpreter keeping the reading or
    /// the AST its interpreter had already rendered, so an AST reader judges
    /// a bundle that no longer has one.
    #[test]
    fn a_bundle_that_drops_its_interpreter_drops_what_it_had_read() {
        let bundle = bundle_of("row", &[("policy/d.rego", GATED)]);
        assert!(bundle.ast().is_some(), "the interpreter renders its AST");
        assert!(bundle.described().is_some(), "and describes it");
        let compiled = bytecode(bundle);
        assert!(compiled.is_bytecode());
        assert!(compiled.ast().is_none(), "no interpreter, no AST");
        assert!(compiled.described().is_none(), "no AST, no reading");
    }

    #[test]
    fn bytecode_answers_with_or_without_a_scope_and_once_per_input_within_one() {
        let bundle = bytecode(bundle_of("row", &[("policy/d.rego", GATED)]));
        assert!(bundle.is_bytecode());
        assert!(
            bundle.described().is_none(),
            "bytecode carries no AST to describe"
        );
        assert!(matches!(
            test(&bundle, "{}", false, None),
            Ok(Look::CouldNotLook)
        ));
        let tok = Some(vec!["tok".to_owned()]);
        assert!(!Answers::open());
        let before = bytecode_evaluations();
        for _ in 0..2 {
            assert_eq!(verdicts(&bundle, GO), tok);
        }
        assert_eq!(
            bytecode_evaluations() - before,
            2,
            "unscoped, every ask evaluates"
        );
        {
            let _scope = answer_scope();
            assert!(Answers::open());
            let before = bytecode_evaluations();
            for _ in 0..2 {
                assert_eq!(verdicts(&bundle, GO), tok);
                assert_eq!(verdicts(&bundle, STOP), Some(Vec::new()));
            }
            assert_eq!(
                bytecode_evaluations() - before,
                2,
                "scoped, each input once"
            );
        }
        assert!(!Answers::open(), "the memo dies with its scope");
    }

    fn hot(
        root: &Path,
        id: &str,
        sources: &[(String, String)],
        data: &serde_json::Value,
    ) -> Bundle {
        let text = PatternText::new();
        compile_for(
            root,
            id,
            sources,
            (data, &text),
            ModuleChecks::SkipOnHotPath,
        )
        .expect("the fixture loads")
    }

    #[test]
    fn a_warm_hot_load_reads_back_the_bytecode_written_for_exactly_its_inputs() {
        let dir = crate::scratch::scratch("policy-cache");
        crate::testing::contain_state(&dir.join("state"));
        let root = dir.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let module =
            "package batten.c\nimport rego.v1\n\ndeny contains \"on\" if {\n\tdata.flag\n}\n";
        let on = serde_json::json!({"flag": true});
        let off = serde_json::json!({"flag": false});
        let sources = sources_of(&[("policy/c.rego", module)]);
        assert!(hot(&root, "one", &sources, &on).is_bytecode());
        hot(&root, "two", &sources, &off);
        let before = engines_constructed();
        let warm_on = hot(&root, "one", &sources, &on);
        let warm_off = hot(&root, "two", &sources, &off);
        assert_eq!(
            engines_constructed(),
            before,
            "a warm load compiles nothing"
        );
        assert_eq!(verdicts(&warm_on, "{}"), Some(vec!["on".to_owned()]));
        assert_eq!(verdicts(&warm_off, "{}"), Some(Vec::new()));
        let edited = module.replace("\"on\"", "\"edited\"");
        let edited = hot(
            &root,
            "one",
            &sources_of(&[("policy/c.rego", &edited)]),
            &on,
        );
        assert_eq!(verdicts(&edited, "{}"), Some(vec!["edited".to_owned()]));
    }

    /// Fails by: a suite program written to the cache never read back, so
    /// every run recompiles and none decides on cached bytecode.
    #[test]
    fn a_warm_suite_decides_on_its_cached_program() {
        let dir = crate::scratch::scratch("policy-suite-cache");
        crate::testing::contain_state(&dir.join("state"));
        let root = dir.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let bundle = bundle_of("suite-cached", &[("policy/a.rego", MODULE)]);
        for _ in 0..2 {
            test(&bundle, "{}", false, Some(&root)).unwrap();
        }
        assert!(
            execution_census()
                .iter()
                .any(|(id, how, _)| id == "suite-cached"
                    && *how == Execution::Bytecode { cached: true }),
            "{:?}",
            execution_census()
        );
    }

    /// Fails by: an evaluator rendered as nothing in the `-vv` census.
    #[test]
    fn an_execution_names_its_evaluator() {
        assert_eq!(
            Execution::Bytecode { cached: true }.to_string(),
            "bytecode cached"
        );
        assert_eq!(
            Execution::Bytecode { cached: false }.to_string(),
            "bytecode compiled"
        );
        assert_eq!(
            Execution::Interpreted(Fallback::TestWith).to_string(),
            format!("interpreter {}", Fallback::TestWith.as_str())
        );
    }

    /// Fails by: `Fallback::as_str` answering `""` for every fallback, so the
    /// `-vv` line and the evaluator report name no reason at all.
    #[test]
    fn every_fallback_names_its_own_token() {
        let tokens = [
            (Fallback::NotOffered, "not-offered"),
            (Fallback::GuardUnavailable, "guard-unavailable"),
            (Fallback::GuardedSourceRefused, "guarded-source-refused"),
            (Fallback::NoAnsweredRule, "no-answered-rule"),
            (Fallback::CompileRefused, "compile-refused"),
            (Fallback::KeyedPartialSet, "keyed-partial-set"),
            (Fallback::RuleElse, "rule-else"),
            (Fallback::TestWith, "test-with"),
        ];
        for (fallback, token) in tokens {
            assert_eq!(fallback.as_str(), token, "{fallback:?}");
        }
    }

    /// Fails by: a rule both evaluators agree on reported as a split (the
    /// comparison inverted), so the parity gate reads every bundle as split.
    #[test]
    fn rules_the_evaluators_agree_on_are_no_split() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        assert_eq!(
            rule_splits(&bundle, &serde_json::json!({}), "{}"),
            Vec::<String>::new()
        );
        assert_eq!(
            rule_splits(
                &bundle,
                &serde_json::json!({}),
                r#"{"call": {"operation": "write"}}"#
            ),
            Vec::<String>::new()
        );
    }

    /// Fails by: the input paths the parity gate hollows answered as a fixed
    /// path rather than those the non-test rules read.
    #[test]
    fn a_bundles_input_paths_are_what_its_rules_read() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        assert_eq!(input_paths(&bundle), ["call.operation"]);
    }

    /// Fails by: the interpreter kept on a bytecode bundle that was asked to
    /// drop it, so its AST readers run on the engine bytecode replaced.
    #[test]
    fn a_bytecode_bundle_keeps_its_interpreter_only_when_asked() {
        let dropped = bytecode(bundle_of("row", &[("policy/a.rego", MODULE)]));
        assert!(dropped.evaluator.engine().is_none());
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let kept = Compiled::from_bundle(&bundle, &serde_json::json!({}))
            .expect("the fixture compiles to bytecode")
            .into_bundle(bundle, true);
        assert!(kept.evaluator.engine().is_some());
    }

    /// Fails by: a bundle that only defines helpers read as a compile
    /// refusal (regorus words its undefined entry point "not a valid rule
    /// path"), or a construct the bytecode compiler refuses read as a bundle
    /// with nothing to answer.
    #[test]
    fn a_bundle_answering_nothing_is_told_from_one_the_compiler_refuses() {
        let helpers = bundle_of(
            "row",
            &[(
                "policy/a.rego",
                "package batten.h\nimport rego.v1\n\nhelper(x) := x\n",
            )],
        );
        let reason = Compiled::compile_unchecked(&helpers, &serde_json::json!({}))
            .err()
            .map(|(reason, _)| reason);
        assert_eq!(reason, Some(Fallback::NoAnsweredRule));
        let with = bundle_of(
            "row",
            &[(
                "policy/a.rego",
                "package batten.w\nimport rego.v1\n\ndeny contains \"t\" if {\n\tinput.a with input as {\"a\": true}\n}\n",
            )],
        );
        let reason = Compiled::compile_unchecked(&with, &serde_json::json!({}))
            .err()
            .map(|(reason, _)| reason);
        assert_eq!(reason, Some(Fallback::CompileRefused));
        assert!(undefined_entry_point("not a valid rule path"));
        assert!(!undefined_entry_point("with is not supported"));
    }

    /// Fails by: a string literal's opening delimiter missed (the bound read
    /// as `>=`, which underflows at offset 0, or the step back as `/`).
    #[test]
    fn a_span_widens_over_its_string_delimiters() {
        let text = "x \"ab\" y";
        assert_eq!(spanned(text, 3, 5), Some("\"ab\""));
        assert_eq!(spanned(text, 0, 1), Some("x"));
        assert_eq!(spanned("\"ab\"", 1, 3), Some("\"ab\""));
    }

    /// Fails by: a key held only by a nested value missed when the outer
    /// object does not also hold it, or one held at the top missed.
    #[test]
    fn a_key_is_held_at_any_depth() {
        assert!(holds_key(&serde_json::json!({"a": {"b": 1}}), "a"));
        assert!(holds_key(&serde_json::json!({"x": [{"b": 1}]}), "b"));
        assert!(!holds_key(&serde_json::json!({"x": 1}), "b"));
    }

    /// Fails by: a `with` statement cut from the byte before its start when
    /// no delimiter is there (`||` for `&&`, which also underflows at 0) or
    /// from after a delimiter (`+` for `-`); or an edit whose start falls
    /// inside a character applied (`&&` for `||`), which panics.
    #[test]
    fn a_with_statement_is_cut_at_its_own_start() {
        let facts: BTreeMap<String, RuleFacts> = [(
            String::from("v"),
            RuleFacts {
                reads: true,
                ..RuleFacts::default()
            },
        )]
        .into();
        let locals = BTreeSet::new();
        let case = |text| CaseText {
            text,
            package: "p",
            facts: &facts,
            locals: &locals,
        };
        let cut_at = |at: usize| [serde_json::json!({"span": {"start": at, "end": at + 4}})];
        let bare = case("ab cd WITH");
        assert_eq!(
            redirected_statement(&bare, 3, &cut_at(6), &[], "k"),
            Ok((String::from("cd"), BTreeSet::new()))
        );
        let quoted = case("a\"b\" WITH");
        assert_eq!(
            redirected_statement(&quoted, 2, &cut_at(5), &[], "k"),
            Ok((String::from("\"b\""), BTreeSet::new()))
        );
        let wide = case("\u{e9}x WITH");
        let inside = [(String::from("v"), 1, 2, false)];
        assert_eq!(
            redirected_statement(&wide, 0, &cut_at(3), &inside, "k"),
            Err(String::from("a span off its text"))
        );
    }

    /// Fails by: a `with` over one key of the pattern table refused as a
    /// `with` on an unsupported path.
    #[test]
    fn a_with_over_one_pattern_key_is_a_pattern_override() {
        let facts = BTreeMap::new();
        let locals = BTreeSet::new();
        let case = CaseText {
            text: "x with data.batten.patterns.k as 1",
            package: "p",
            facts: &facts,
            locals: &locals,
        };
        let modifier = |path: &str| {
            serde_json::json!({
                "refr": {"Var": {"value": path}},
                "as": {"Number": {"span": {"start": 33, "end": 34}}},
            })
        };
        let mut context = PlannedContext {
            key: String::from("k"),
            input: None,
            patterns: Vec::new(),
            rules: Vec::new(),
        };
        let mut prelude = String::new();
        with_terms(
            &case,
            &[modifier("data.batten.patterns.k")],
            (0, 0),
            None,
            &mut context,
            &mut prelude,
        )
        .unwrap();
        assert_eq!(
            context.patterns,
            [(
                Some(String::from("k")),
                String::from("data.p.__batten_in_0_0_0")
            )]
        );
        assert!(
            with_terms(
                &case,
                &[modifier("data.batten.patterns.k.deeper")],
                (0, 0),
                None,
                &mut context,
                &mut prelude,
            )
            .is_err()
        );
    }

    /// Fails by: the no-case early answer inverted, so a bundle WITH cases
    /// is never compared and its case that cannot go on bytecode is unsaid.
    #[test]
    fn a_case_that_cannot_go_on_bytecode_is_a_suite_split() {
        let module = "package batten.w\nimport rego.v1\n\nrules contains \"w\"\n\n\
            violation contains {\"rule\": \"w\", \"verdict\": \"w\"} if {\n\tdata.other.on\n}\n\n\
            test_w if {\n\tcount(violation) == 1 with data.other as {\"on\": true}\n}\n";
        let bundle = bundle_of("with-other", &[("policy/w.rego", module)]);
        let splits = suite_splits(&bundle, "{}");
        assert_eq!(
            splits,
            ["with-other: test-with: no case the suite program can express"]
        );
    }

    /// Fails by: the coverage sweep's batch grown by addition rather than
    /// doubled, or its case count read as zero: a predicate first entered by
    /// the fourth of seven cases is answered after a sweep of all seven
    /// (batches of 1, 2 and 4), where `+= 2` stops at four.
    #[test]
    fn the_coverage_sweep_doubles_its_batch_and_counts_each_case() {
        let trivial = |name: &str| format!("test_{name} if {{\n\ttrue\n}}\n\n");
        let module = format!(
            "package batten.v\nimport rego.v1\n\nrules contains \"v\"\n\n\
             violation contains {{\"rule\": \"v\", \"verdict\": \"v\"}} if {{\n\tinput.go\n}}\n\n\
             {}{}{}test_d if {{\n\tcount(violation) == 1 with input as {{\"go\": true}}\n}}\n\n{}{}{}",
            trivial("a"),
            trivial("b"),
            trivial("c"),
            trivial("e"),
            trivial("f"),
            trivial("g"),
        );
        let bundle = bundle_of("swept", &[("policy/v.rego", module.as_str())]);
        let before = coverage_cases();
        let suite = suite_of(&bundle, false);
        assert!(suite.unexercised.is_empty(), "{:?}", suite.unexercised);
        assert_eq!(coverage_cases() - before, 7);
    }

    #[test]
    fn the_hot_path_reads_a_module_without_its_tests_and_every_other_load_whole() {
        let root = crate::scratch::scratch("policy-read-sources");
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let text = "package p\n\ntest_one if {\n\ttrue\n}\n\nkept := 1\n";
        std::fs::write(root.join("policy/t.rego"), text).unwrap();
        let read = |path: &str, checks| {
            read_sources(&root, &[path.to_owned()], None, "row", checks).map(|mut s| s.remove(0).1)
        };
        assert_eq!(read("policy/t.rego", ModuleChecks::Run).unwrap(), text);
        assert_eq!(
            read("policy/t.rego", ModuleChecks::SkipOnHotPath).unwrap(),
            without_test_rules(text)
        );
        assert_ne!(without_test_rules(text), text);
        assert!(read("policy/absent.rego", ModuleChecks::Run).is_err());
    }

    #[test]
    fn a_bundle_enables_exactly_its_rego_files_in_sorted_order() {
        let root = crate::scratch::scratch("policy-bundle-members");
        let dir = root.join("set");
        std::fs::create_dir_all(dir.join("nested.rego")).unwrap();
        for name in ["b.rego", "a.rego", ".rego", "notes.txt"] {
            std::fs::write(dir.join(name), "package x\n").unwrap();
        }
        assert_eq!(
            bundle_members(&root, "set/", None, "row").unwrap(),
            vec!["set/a.rego".to_owned(), "set/b.rego".to_owned()]
        );
        std::fs::create_dir_all(root.join("empty")).unwrap();
        assert!(bundle_members(&root, "empty", None, "row").is_err());
        assert!(bundle_members(&root, "absent", None, "row").is_err());
    }

    /// Two tree modules, one reading a provider's language, and one mediated.
    const MIXED: crate::preset_catalog::Manifest = crate::preset_catalog::Manifest {
        name: "mixed",
        version: semver::Version::new(0, 0, 1),
        suggested: true,
        install: None,
        modules: &[
            crate::preset_catalog::PresetModule {
                scope: crate::preset_catalog::RuleScope::Tree,
                provider: None,
                pointer: "<preset:mixed>/t1.rego",
                embedded_source: "package t1\n",
            },
            crate::preset_catalog::PresetModule {
                scope: crate::preset_catalog::RuleScope::Tree,
                provider: Some("github"),
                pointer: "<preset:mixed>/t2.rego",
                embedded_source: "package t2\n",
            },
            crate::preset_catalog::PresetModule {
                scope: crate::preset_catalog::RuleScope::MediatedCall,
                provider: None,
                pointer: "<preset:mixed>/m.rego",
                embedded_source: "package m\n",
            },
        ],
        verdicts: &[],
        patterns: &[],
    };

    #[test]
    fn an_except_names_a_module_at_the_row_s_scope_and_leaves_one_standing() {
        let pointers = |extra: &str| {
            let row = policy_row("mixed", "tree", "preset = \"mixed\"", extra);
            preset_sources(&row, &MIXED, "mixed")
                .map(|sources| sources.into_iter().map(|(p, _)| p).collect::<Vec<_>>())
                .map_err(|err| format!("{err:#}"))
        };
        assert_eq!(pointers("").unwrap(), vec!["<preset:mixed>/t1.rego"]);
        assert_eq!(
            pointers("provider = \"github\"\nexcept = [\"t1\"]\n").unwrap(),
            vec!["<preset:mixed>/t2.rego"]
        );
        let other_scope = pointers("except = [\"m\"]\n").unwrap_err();
        assert!(
            other_scope.contains("the modules there are t1, t2"),
            "{other_scope}"
        );
        let every = pointers("except = [\"t1\"]\n").unwrap_err();
        assert!(every.contains("excepts every module"), "{every}");
    }

    #[test]
    fn ids_and_refusals_read_in_either_collection_shape_and_an_undeclared_raise_is_refused() {
        let raised = "package batten.v\nimport rego.v1\n\nrules contains \"v\"\n\n\
violation contains {\"rule\": \"v\", \"verdict\": \"v\"} if {\n\tnot input.quiet\n}\n";
        let set = bundle_of("row", &[("policy/v.rego", raised)]);
        assert_eq!(set.declared(), &BTreeSet::from(["v".to_owned()]));
        let undeclared = raised.replace("rules contains \"v\"", "rules contains \"w\"");
        let undeclared = sources_of(&[("policy/v.rego", &undeclared)]);
        assert!(compile("row", &undeclared, &serde_json::json!({})).is_err());

        let arrays = "package batten.v\nimport rego.v1\n\nrules := [\"v\"]\n\n\
violation := [{\"rule\": \"v\", \"verdict\": \"v\"}]\n\ndeny := [\"bare\"]\n\nfrontier := [\"y\"]\n";
        let arrays = bundle_of("row", &[("policy/v.rego", arrays)]);
        assert_eq!(arrays.declared(), &BTreeSet::from(["v".to_owned()]));
        assert_eq!(
            verdicts(&arrays, "{}"),
            Some(vec!["bare".to_owned(), "v".to_owned()])
        );
        assert_eq!(read(&arrays, "frontier"), Some(vec!["y".to_owned()]));

        let sets = "package batten.s\nimport rego.v1\n\ndeny contains \"bare\"\n\nfrontier contains \"x\"\n";
        let sets = bundle_of("row", &[("policy/s.rego", sets)]);
        assert_eq!(verdicts(&sets, "{}"), Some(vec!["bare".to_owned()]));
        assert_eq!(read(&sets, "frontier"), Some(vec!["x".to_owned()]));
        assert_eq!(read(&sets, "absent"), Some(Vec::new()));
    }

    /// The strings rule `rule` answers over an empty input, or `None` for
    /// could-not-look.
    fn read(bundle: &Bundle, rule: &str) -> Option<Vec<String>> {
        match strings(bundle, "{}", rule) {
            Look::Is(found) => Some(found),
            Look::CouldNotLook | Look::IsNot => None,
        }
    }

    #[test]
    fn a_rewrite_is_read_from_a_set_or_an_array() {
        let member = "{\"rule\": \"r\", \"key\": \"timeout\", \"value\": 5}";
        let expected = vec![Rewrite {
            rule: "r".to_owned(),
            key: "timeout".to_owned(),
            value: 5,
        }];
        for body in [
            format!("rewrite contains {member}\n"),
            format!("rewrite := [{member}]\n"),
        ] {
            let module =
                format!("package batten.w\nimport rego.v1\n\nrules contains \"r\"\n\n{body}");
            let bundle = bundle_of("row", &[("policy/w.rego", &module)]);
            assert!(
                matches!(rewrite(&bundle, "{}"), Look::Is(found) if found == expected),
                "{module}"
            );
        }
    }

    #[test]
    fn only_a_refusing_rule_s_literals_count_as_emitted() {
        let helper = format!("{MODULE}\nroute := {{\"verdict\": \"helper\"}}\n");
        assert_eq!(
            emitted_verdicts(&bundle_of("row", &[("policy/a.rego", &helper)])),
            BTreeSet::from(["a".to_owned()])
        );
        let bare = "package batten.d\nimport rego.v1\n\nrules contains \"x\"\n\n\
deny contains \"tok\" if {\n\tinput.go\n}\n";
        assert_eq!(
            emitted_verdicts(&bundle_of("row", &[("policy/d.rego", bare)])),
            BTreeSet::from(["tok".to_owned()])
        );
    }

    #[test]
    fn a_module_raises_only_live_declared_tokens_and_names_them_literally() {
        let row = module_row("a", "mediated_call", "");
        let check = |bundle: &Bundle, registry: &[crate::config_model::DeclaredVerdict]| {
            check_verdicts_are_declared(&row, bundle, registry, "policy/a.rego")
                .map_err(|err| format!("{err:#}"))
        };
        let source = |text: &str| bundle_of("row", &[("policy/a.rego", text)]);
        let module = source(MODULE);
        let live = [class("a", "")];
        assert!(check(&module, &live).is_ok());
        let undeclared = check(&module, &[]).unwrap_err();
        assert!(
            undeclared.contains("no `[[verdict]]` row declares"),
            "{undeclared}"
        );
        let retired = [class("a", "successor = \"b\"\n")];
        assert!(check(&module, &retired).unwrap_err().contains("RETIRED"));
        let msg =
            source(&MODULE.replace("\"verdict\": \"a\"}", "\"verdict\": \"a\", \"msg\": \"m\"}"));
        assert!(check(&msg, &live).unwrap_err().contains("still binds"));
        let composed = source(&MODULE.replace(
            "\"verdict\": \"a\"}",
            "\"verdict\": sprintf(\"%s\", [\"a\"])}",
        ));
        assert!(check(&composed, &live).unwrap_err().contains("COMPOSES"));
    }

    #[test]
    fn a_tree_row_reads_only_keys_the_tree_carries_and_a_call_row_reads_no_tree() {
        // Whether a tree row and a call row each admit a module reading `path`.
        let admits = |path: &str| {
            let module = format!("package batten.t\nimport rego.v1\n\nhit if {{\n\t{path}\n}}\n");
            let bundle = bundle_of("row", &[("policy/t.rego", &module)]);
            let by = |scope| {
                check_tree_paths_are_emittable(
                    &module_row("t", scope, ""),
                    &bundle,
                    "policy/t.rego",
                )
                .is_ok()
            };
            (by("tree"), by("mediated_call"))
        };
        assert_eq!(admits("input.tree.missing"), (true, false));
        // Split, because `rules`' doc check reads every tree path this file spells.
        assert_eq!(admits(concat!("input.tree", ".nope")), (false, false));
        assert_eq!(admits("input.call.tool"), (false, true));
        assert_eq!(admits("input.facts.receipts"), (false, true));
    }

    #[test]
    fn every_live_declared_class_is_raised_or_native_and_collides_with_a_row_id() {
        let live = class("x y z", "");
        let retired = class("old y z", "successor = \"x y z\"\n");
        let raised = BTreeSet::from(["x y z".to_owned()]);
        let none = BTreeSet::new();
        assert!(check_registry_is_exhausted(&[live.clone(), retired.clone()], &raised).is_ok());
        assert!(check_registry_is_exhausted(std::slice::from_ref(&live), &none).is_err());
        assert!(check_registry_is_exhausted(std::slice::from_ref(&retired), &none).is_ok());
        let native = crate::verdict::native_tokens()
            .into_iter()
            .next()
            .expect("a native class");
        assert!(check_registry_is_exhausted(&[class(native, "")], &none).is_ok());

        let tokens = collidable_tokens(&[live, retired]);
        assert!(tokens.contains("x y z") && !tokens.contains("old y z"));
        assert!(tokens.contains(native));
        let vendored = crate::config_check::preset::verdict_rows()
            .into_iter()
            .next()
            .expect("a vendored class");
        assert!(tokens.contains(&vendored.id));
    }

    #[test]
    fn a_row_spelled_as_a_class_it_does_not_solely_raise_is_refused() {
        let rows = [module_row("x y z", "tree", "")];
        let registry = BTreeSet::from(["x y z".to_owned()]);
        assert!(check_collapse(&rows, &BTreeMap::new(), &registry).is_err());
        assert!(check_collapse(&rows, &BTreeMap::new(), &BTreeSet::new()).is_ok());
    }

    #[test]
    fn ids_are_held_to_the_grammar_claimed_once_and_declared_before_a_severity_names_them() {
        let sources = sources_of(&[("policy/x.rego", "rules contains \"x\"\n")]);
        let grammar = crate::config_model::Vocabulary::default();
        let x = BTreeSet::from(["x".to_owned()]);
        assert!(check_finding_ids(&sources, Some(&grammar), &BTreeSet::new()).is_err());
        assert!(check_finding_ids(&sources, Some(&grammar), &x).is_ok());
        assert!(check_finding_ids(&sources, None, &BTreeSet::new()).is_ok());

        let row = module_row("x", "tree", "predicate_severity = { y = \"warn\" }\n");
        assert!(check_predicate_severity(&row, &x, "src").is_err());
        assert!(check_predicate_severity(&row, &BTreeSet::from(["y".to_owned()]), "src").is_ok());

        let mut ids = BTreeMap::new();
        assert!(claim_ids(&mut ids, &x, "a").is_ok());
        assert!(claim_ids(&mut ids, &x, "b").is_err());
    }

    #[test]
    fn a_module_cites_a_declared_pattern_and_writes_no_regex_inline() {
        let row = module_row("r", "tree", "");
        let check = |body: &str, declared: &[&str]| {
            let module = format!("package batten.r\nimport rego.v1\n\nhit if {{\n\t{body}\n}}\n");
            let bundle = bundle_of("row", &[("policy/r.rego", &module)]);
            let declared: BTreeSet<&str> = declared.iter().copied().collect();
            let plain = check_no_inline_regex(&row, &bundle, &declared, "src")
                .map_err(|err| format!("{err:#}"));
            let copy = check_copy_regex(&row, &bundle, &declared, "src", &[])
                .map_err(|err| format!("{err:#}"));
            assert_eq!(plain, copy, "a row with no ejected copy is the plain check");
            plain
        };
        let inline = check("regex.match(`[0-9]+`, input.x)", &[]).unwrap_err();
        assert!(inline.contains("`[0-9]+`"), "{inline}");
        assert!(
            check(
                "regex.match(concat(\"\", [\"[a-z]\", \"+\"]), input.x)",
                &[]
            )
            .is_err()
        );
        let cited = "regex.match(data.batten.patterns[\"p\"], input.x)";
        assert!(check(cited, &["p"]).is_ok());
        let undeclared = check(cited, &[]).unwrap_err();
        assert!(undeclared.contains("patterns[\"p\"]"), "{undeclared}");
    }

    #[test]
    fn a_test_that_never_fires_its_predicate_leaves_it_unexercised() {
        let quiet = "package batten.n\nimport rego.v1\n\nrules contains \"n\"\n\n\
violation contains {\"rule\": \"n\", \"verdict\": \"n\"} if {\n\tinput.call.operation == \"write\"\n}\n\n\
helper := \"z\"\n\n\
test_n_is_declared_and_quiet if {\n\t\"n\" in rules\n\thelper == \"z\"\n\
\tcount(violation) == 0 with input as {\"call\": {\"operation\": \"read\"}}\n}\n";
        let suite = suite_of(&bundle_of("row", &[("policy/n.rego", quiet)]), false);
        assert_eq!(suite.passed.len(), 1);
        assert_eq!(suite.unexercised, vec!["n".to_owned()]);
    }

    /// Fails by: the coverage sweep's batch shrinking rather than doubling,
    /// so it never runs past the first case and a predicate only the second
    /// case fires is never entered. That sweep spins, so the case owns its
    /// deadline and a spin reads as a failure rather than a hung suite.
    #[test]
    fn a_predicate_only_a_later_case_fires_is_exercised() {
        let module = "package batten.n\nimport rego.v1\n\nrules contains \"n\"\n\n\
violation contains {\"rule\": \"n\", \"verdict\": \"n\"} if {\n\tinput.call.operation == \"write\"\n}\n\n\
test_a_quiet if {\n\tcount(violation) == 0 with input as {\"call\": {\"operation\": \"read\"}}\n}\n\n\
test_b_fires if {\n\tcount(violation) == 1 with input as {\"call\": {\"operation\": \"write\"}}\n}\n";
        let (sent, got) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let suite = suite_of(&bundle_of("row", &[("policy/n.rego", module)]), false);
            let _ = sent.send((suite.passed.len(), suite.unexercised));
        });
        let (passed, unexercised) = got
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the coverage sweep ends");
        assert_eq!(passed, 2);
        assert!(unexercised.is_empty(), "{unexercised:?}");
    }

    #[test]
    fn a_sweep_names_the_modules_it_never_entered() {
        let dark = "package batten.f\nimport rego.v1\n\nf(x) := x\n";
        let both = bundle_of("row", &[("policy/a.rego", MODULE), ("policy/f.rego", dark)]);
        let Look::Is(half) = analyse(&both).unwrap() else {
            panic!("the sweep ran");
        };
        assert_eq!(half.swept, vec!["policy/a.rego".to_owned()]);
        assert_eq!(half.unswept, vec!["policy/f.rego".to_owned()]);
        let only_dark = bundle_of("row", &[("policy/f.rego", dark)]);
        assert!(matches!(analyse(&only_dark).unwrap(), Look::CouldNotLook));
    }

    #[test]
    fn a_row_names_its_source_and_a_config_its_words() {
        assert_eq!(
            source_key(&module_row("m", "tree", "")).unwrap(),
            "policy/m.rego"
        );
        let mut preset = git_row("");
        assert_eq!(source_key(&preset).unwrap(), "git");
        preset.preset = None;
        assert!(source_key(&preset).is_err());

        let mut config: crate::config_model::Config = toml::from_str("version = 1\n").unwrap();
        assert!(Vocabulary::from(&config).words.is_none());
        config
            .vocabulary
            .subject
            .push(crate::config_model::VocabularyWord {
                word: "x".to_owned(),
                gloss: "g".to_owned(),
            });
        assert!(Vocabulary::from(&config).words.is_some());
    }

    // ── step 13a: the tree read set ────────────────────────────────────────

    /// A tree-scope module with `body` as its one rule body.
    fn reading(body: &str) -> String {
        format!(
            "package batten.reads\n\nimport rego.v1\n\nrules contains \"x probe probex\"\n\n\
             violation contains {{\"rule\": \"x probe probex\", \"verdict\": \"x probe probex\", \
             \"subjects\": []}} if {{\n{body}\n}}\n"
        )
    }

    fn reads_of(body: &str) -> Reads {
        let module = reading(body);
        bundle_of("row", &[("policy/r.rego", &module)]).tree_reads()
    }

    fn known(keys: &[&str]) -> Reads {
        Reads::Known(keys.iter().map(|key| (*key).to_owned()).collect())
    }

    #[test]
    fn a_dotted_or_literal_index_read_names_its_key() {
        assert_eq!(
            reads_of("\tsome path, _ in input.tree.documents\n\tpath != \"\""),
            known(&["documents"])
        );
        assert_eq!(
            reads_of("\tinput.tree[\"git-index\"] != null"),
            known(&["git-index"]),
            "a string-literal index is the dotted read"
        );
    }

    #[test]
    fn a_read_this_reader_cannot_name_is_opaque() {
        // An alias, a variable index, a bare `input`, and the other surface: each
        // could read any key, so none may be read as a closed set.
        for body in [
            "\tt := input.tree\n\tt.documents != null",
            "\tsome k\n\tinput.tree[k] != null",
            "\tx := input\n\tx.tree.documents != null",
            "\tinput.facts.receipts != null",
            "\tinput.call.command != null",
        ] {
            assert_eq!(reads_of(body), Reads::Opaque, "{body}");
        }
    }

    #[test]
    fn a_chain_records_its_longest_read_and_never_its_head() {
        // THE FIX THE OPAQUE ARM DEPENDS ON: the walk used to record every link of
        // a chain, so `input.tree.documents` also recorded `tree` and every module
        // would have read as a bare `input.tree`.
        let module = reading("\tinput.tree.documents.x != null");
        let bundle = bundle_of("row", &[("policy/r.rego", &module)]);
        let described = bundle.described().expect("the fixture describes");
        let paths: Vec<&String> = described
            .iter()
            .flat_map(|module| module.rules.iter())
            .flat_map(|rule| rule.input_paths.iter())
            .collect();
        assert_eq!(paths, vec!["tree.documents.x"]);
    }

    #[test]
    fn bytecode_carries_the_read_set_and_an_entry_without_one_is_opaque() {
        let module = reading("\tsome path, _ in input.tree.lines\n\tpath != \"\"");
        let sources = sources_of(&[("policy/r.rego", &module)]);
        let data = serde_json::json!({});
        let bundle = compile("row", &sources, &data).expect("the fixture compiles");
        let compiled =
            Compiled::from_bundle(&bundle, &data).expect("the fixture compiles to bytecode");
        let carried =
            compiled.into_bundle(compile("row", &sources, &data).expect("compiles"), false);
        assert!(carried.is_bytecode());
        assert_eq!(carried.tree_reads(), known(&["lines"]));
        // An entry written before the read set existed deserialises with none.
        let header: CacheHeader =
            serde_json::from_str(r#"{"declared":[],"packages":[],"entries":[],"facts":[]}"#)
                .expect("an old header still parses");
        assert!(header.reads.is_none(), "an old entry carries no read set");
        let old = Compiled::from_bundle(&bundle, &data).expect("bytecode");
        let old = Compiled {
            reads: header.reads,
            ..old
        }
        .into_bundle(bundle, false);
        assert_eq!(old.tree_reads(), Reads::Opaque);
    }

    /// Fails by: an interpreted bundle describing its read set afresh where an
    /// entry under its key holds one (both halves of a split `enforce`
    /// classifying from scratch), the entry it writes read back as bytecode,
    /// or the set it writes not the one it describes.
    #[test]
    fn an_interpreted_bundle_reads_its_read_set_off_the_entry_under_its_key() {
        let module = reading("\tsome path, _ in input.tree.lines\n\tpath != \"\"");
        let sources = sources_of(&[("policy/r.rego", &module)]);
        let data = serde_json::json!({});
        let path = crate::scratch::scratch("policy-interpreted-reads").join("row.rvm");
        let key = cache_key("row", &sources, &[0; 32]);
        let first = compile("row", &sources, &data).expect("the fixture compiles");
        remember_reads(&path, &key, &first);
        assert_eq!(first.tree_reads(), known(&["lines"]));
        assert!(
            read_cached(&path, &key, "row", &sources, "{}").is_none(),
            "a read set alone is no bytecode"
        );
        let second = compile("row", &sources, &data).expect("the fixture compiles");
        remember_reads(&path, &key, &second);
        assert_eq!(second.tree_reads(), known(&["lines"]), "read back");
        // A SENTINEL THE MODULE NEVER READS proves the entry answered, not a
        // fresh description.
        let header = CacheHeader {
            declared: BTreeSet::new(),
            packages: BTreeSet::new(),
            entries: BTreeSet::new(),
            facts: Vec::new(),
            reads: Some(vec![String::from("sentinel")]),
        };
        let mut bytes = serde_json::to_vec(&header).unwrap();
        bytes.push(b'\n');
        crate::cache::write(&path, &key, &bytes);
        let third = compile("row", &sources, &data).expect("the fixture compiles");
        remember_reads(&path, &key, &third);
        assert_eq!(third.tree_reads(), known(&["sentinel"]));
    }

    /// Fails by: a string's span widened past its opening quote.
    #[test]
    fn a_string_span_widens_over_exactly_its_delimiters() {
        assert_eq!(spanned("x \"ab\" y", 3, 5), Some("\"ab\""));
        assert_eq!(spanned("x ab y", 2, 4), Some("ab"));
    }

    /// Fails by: a reading rule refused under `with` only when it is both
    /// called and a function (`||` for `&&`), so a call of a reading rule, or a
    /// reading function named bare, is redirected instead of refused.
    #[test]
    fn a_reading_function_or_a_called_reader_under_with_is_refused() {
        let refused = Err(String::from("a function reading the input under `with`"));
        let locals = BTreeSet::new();
        let mods = [serde_json::json!({"span": {"start": 6, "end": 10}})];
        for (function, called) in [(false, true), (true, false)] {
            let facts: BTreeMap<String, RuleFacts> = [(
                String::from("r"),
                RuleFacts {
                    reads: true,
                    function,
                    ..RuleFacts::default()
                },
            )]
            .into();
            let case = CaseText {
                text: "x := r WITH",
                package: "p",
                facts: &facts,
                locals: &locals,
            };
            assert_eq!(
                redirected_statement(&case, 0, &mods, &[(String::from("r"), 5, 6, called)], "k"),
                refused,
                "function {function}, called {called}"
            );
        }
    }

    /// Fails by: a rewrite whose start falls inside a character applied (a
    /// panic) because its end happens to fall on a boundary.
    #[test]
    fn a_rewrite_off_a_char_boundary_at_either_end_is_refused() {
        let facts: std::collections::BTreeMap<String, RuleFacts> = std::iter::once((
            "r".to_owned(),
            RuleFacts {
                reads: true,
                ..RuleFacts::default()
            },
        ))
        .collect();
        let locals = std::collections::BTreeSet::new();
        let case = CaseText {
            text: "\u{e9}\u{e9} r",
            package: "p",
            facts: &facts,
            locals: &locals,
        };
        let mods = [serde_json::json!({"span": {"start": 6, "end": 6}})];
        let at = |start: usize, end: usize| {
            redirected_statement(&case, 0, &mods, &[("r".to_owned(), start, end, false)], "k")
        };
        assert_eq!(at(1, 5), Err(String::from("a span off its text")));
        assert_eq!(at(5, 6).map(|(_, read)| read.len()), Ok(1));
    }

    /// Fails by: a span starting at byte 0 widened backwards, which underflows.
    #[test]
    fn a_span_at_the_start_of_the_text_is_not_widened_backwards() {
        assert_eq!(spanned("ab", 0, 2), Some("ab"));
        assert_eq!(spanned("\"ab\"", 1, 3), Some("\"ab\""));
    }

    /// Fails by: a key held by the node itself missed unless a value under it
    /// holds the key too.
    #[test]
    fn a_key_the_node_itself_holds_is_held() {
        assert!(holds_key(&serde_json::json!({"Var": 1}), "Var"));
        assert!(holds_key(&serde_json::json!([{"x": {"Var": 1}}]), "Var"));
        assert!(!holds_key(&serde_json::json!({"x": 1}), "Var"));
    }

    /// Fails by: the parity gate nulling a path no rule reads, and none it does.
    #[test]
    fn the_input_paths_are_the_ones_a_rule_reads() {
        let paths = input_paths(&bundle_of("row", &[("policy/a.rego", MODULE)]));
        assert!(
            paths.iter().any(|path| path.contains("operation")),
            "{paths:?}"
        );
        assert!(
            !paths.iter().any(|path| path.contains("xyzzy")),
            "{paths:?}"
        );
    }

    /// A module whose case binds its pattern row with a single-segment `with`.
    const PATTERNED: &str = "package batten.p\nimport rego.v1\n\nrules contains \"p\"\n\n\
violation contains {\"rule\": \"p\", \"verdict\": \"p\"} if {\n\tsome word in data.batten.patterns.p\n\tinput.call.command == word\n}\n\n\
test_p_matches if {\n\tcount(violation) == 1 with input as {\"call\": {\"command\": \"x\"}} with data.batten.patterns.p as [\"x\"]\n}\n";

    /// A `with` on one pattern row is planned: the plan refuses only a deeper
    /// path. What the planned case then decides is the run's, not the plan's,
    /// so every line this suite reports names the case it planned.
    ///
    /// Fails by: `with data.batten.patterns.p` refused at planning, as though
    /// it named a path inside a row, which leaves the suite program no case.
    #[test]
    fn a_with_on_one_pattern_row_is_planned() {
        let bundle = bundle_of("row", &[("policy/p.rego", PATTERNED)]);
        let splits = suite_splits(&bundle, "{}");
        assert!(
            splits
                .iter()
                .all(|line| line.contains("test_p_matches") && !line.contains("a `with` on")),
            "{splits:?}"
        );
    }

    /// Fails by: a suite carrying cases skipped as though it had none, so an
    /// input the program cannot read is never reported.
    #[test]
    fn a_suite_with_cases_reports_an_input_it_cannot_read() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let splits = suite_splits(&bundle, "not json");
        assert!(
            splits
                .iter()
                .any(|line| line.contains("the input will not parse")),
            "{splits:?}"
        );
    }

    /// Fails by: a rule the bytecode and the interpreter answer alike reported
    /// as a split.
    #[test]
    fn a_rule_both_evaluators_answer_alike_is_no_split() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let input = r#"{"call": {"operation": "write"}}"#;
        assert_eq!(
            rule_splits(&bundle, &serde_json::json!({}), input),
            Vec::<String>::new()
        );
    }

    /// Eight cases, only `test_5` entering the predicate: the sweep doubles its
    /// batches (1, 2, 4), so it stops after seven cases, where batches growing
    /// by one (1, 2, 3) stop after six. Each nextest case is its own process,
    /// so the counter's delta is this sweep's alone.
    ///
    /// Fails by: the batches growing by addition, which pays a sweep per case
    /// on a suite that covers its predicates late.
    #[test]
    fn the_coverage_sweep_doubles_its_batches() {
        let mut module = String::from(
            "package batten.d\nimport rego.v1\n\nrules contains \"d\"\n\n\
violation contains {\"rule\": \"d\", \"verdict\": \"d\"} if {\n\tinput.call.operation == \"write\"\n}\n",
        );
        for case in 1..=8 {
            if case == 5 {
                module.push_str("\ntest_5 if {\n\tcount(violation) == 1 with input as {\"call\": {\"operation\": \"write\"}}\n}\n");
            } else {
                for piece in ["\ntest_", &case.to_string(), " if {\n\ttrue\n}\n"] {
                    module.push_str(piece);
                }
            }
        }
        let bundle = bundle_of("row", &[("policy/d.rego", &module)]);
        let before = coverage_cases();
        let suite = suite_of(&bundle, false);
        assert!(suite.unexercised.is_empty(), "{:?}", suite.unexercised);
        assert_eq!(coverage_cases() - before, 7);
    }

    /// Fails by: a fallback reason with no token, or two sharing one, so a
    /// `-vv` count cannot say which refusal kept a bundle off bytecode.
    #[test]
    fn every_fallback_names_its_own_stable_token() {
        let all = [
            Fallback::NotOffered,
            Fallback::GuardUnavailable,
            Fallback::GuardedSourceRefused,
            Fallback::NoAnsweredRule,
            Fallback::CompileRefused,
            Fallback::KeyedPartialSet,
            Fallback::RuleElse,
            Fallback::TestWith,
        ];
        let tokens: BTreeSet<&str> = all.iter().map(|why| why.as_str()).collect();
        assert_eq!(tokens.len(), all.len(), "{tokens:?}");
        assert!(!tokens.contains(""), "{tokens:?}");
        assert_eq!(Fallback::RuleElse.as_str(), "rule-else");
    }

    /// Fails by: a detail invented for a bundle the compiler never refused, or
    /// the compiler's own words replaced.
    #[test]
    fn a_fallback_detail_is_the_refusal_said_and_nothing_else() {
        let module = [("policy/d.rego", GATED)];
        assert_eq!(bundle_of("row", &module).fallback_detail(), None);
        assert_eq!(bytecode(bundle_of("row", &module)).fallback_detail(), None);
        let refused = interpreted_because(bundle_of("row", &module), Fallback::RuleElse, &"why");
        assert_eq!(refused.fallback_detail(), Some("why"));
    }

    /// Fails by: a statement whose previous line merely ENDS in `if` (a
    /// reference like `input.motif`) read as a braceless body, so the binding
    /// and its guard are wrapped in braces the body never had.
    #[test]
    fn a_line_ending_in_if_inside_a_braced_body_is_not_a_braceless_head() {
        const MOTIF: &str = "package batten.m\nimport rego.v1\n\n\
            deny contains p if {\n\tinput.motif\n\tp := 1\n}\n";
        let guarded = guarded_sources(
            bundle_of("row", &[("policy/m.rego", MOTIF)])
                .evaluator
                .engine()
                .expect("interpreted"),
        )
        .expect("the guard splices");
        assert!(
            guarded[0].1.contains("\tp := 1; p == p\n"),
            "{}",
            guarded[0].1
        );
        assert!(!guarded[0].1.contains("{ p :="), "{}", guarded[0].1);
    }

    /// Fails by: the parity gate handed no input path to null, so a fact the
    /// rules read is never tried absent.
    #[test]
    fn input_paths_name_what_the_rules_read() {
        let paths = input_paths(&bundle_of("row", &[("policy/a.rego", MODULE)]));
        assert!(paths.contains(&"call.operation".to_owned()), "{paths:?}");
    }

    /// Fails by: a bundle that answers no rule the boundary reads reported as
    /// the compiler refusing it.
    #[test]
    fn a_bundle_answering_no_rule_is_said_so_not_refused() {
        const NONE: &str = "package batten.none\nimport rego.v1\n\nhelper := 1\n";
        let refused = Compiled::from_bundle(
            &bundle_of("row", &[("policy/none.rego", NONE)]),
            &serde_json::json!({}),
        )
        .err()
        .expect("nothing to answer");
        assert_eq!(refused.0, Fallback::NoAnsweredRule, "{refused:?}");
    }

    /// Fails by: a string literal's opening delimiter, which regorus's span
    /// excludes, left off the desugared text.
    #[test]
    fn a_span_is_widened_over_both_string_delimiters() {
        assert_eq!(spanned("a \"x\" b", 3, 4), Some("\"x\""));
        assert_eq!(spanned("a `y` b", 3, 4), Some("`y`"));
        assert_eq!(spanned("x == 1", 0, 6), Some("x == 1"));
    }

    /// Fails by: two array answers that differ reported as their whole
    /// renderings rather than as what each holds alone. Over the keyed set
    /// regorus 0.15's bytecode flattens, `a` is `[]` on bytecode and `["y"]`
    /// interpreted.
    #[test]
    fn an_array_split_names_the_members_each_side_holds_alone() {
        const ARRAYED: &str = "package batten.k\nimport rego.v1\n\n\
            f[k] contains v if {\n\tsome k, vs in {\"a\": {\"x\"}, \"b\": {\"y\"}}\n\tsome v in vs\n}\n\n\
            a := [v | some v in f.b]\n\n\
            deny contains \"keyed\" if f.b == {\"y\"}\n";
        let bundle = bundle_of("row", &[("policy/k.rego", ARRAYED)]);
        let found = rule_splits(&bundle, &serde_json::json!({}), "{}");
        assert!(
            found
                .iter()
                .any(|line| line.ends_with(".a: only bytecode [] only interpreter [\"y\"]")),
            "{found:?}"
        );
    }

    fn splits(source: &str) -> Vec<String> {
        suite_splits(&bundle_of("row", &[("policy/s.rego", source)]), "{}")
    }

    /// Fails by: a bundle whose cases all decide alike reported as split.
    #[test]
    fn a_suite_deciding_alike_has_no_splits() {
        assert_eq!(splits(MODULE), Vec::<String>::new());
    }

    /// Fails by: a statement that starts with a string literal desugared
    /// without its opening quote, plain or under `with`, so the suite program
    /// will not compile and no case decides on bytecode.
    #[test]
    fn a_statement_opening_on_a_string_desugars_whole() {
        const STRINGS: &str = "package batten.s\nimport rego.v1\n\n\
            names := input.n\n\n\
            test_plain if {\n\t\"a\" in [\"a\"]\n}\n\n\
            test_with if {\n\t\"a\" in names with input as {\"n\": [\"a\"]}\n}\n";
        assert_eq!(splits(STRINGS), Vec::<String>::new());
    }

    /// Fails by: a `with` term reading a case's own binding not hoisted under
    /// the statements that bind it, so the term names an unbound variable.
    #[test]
    fn a_with_term_reading_a_case_binding_is_hoisted() {
        const HOISTED: &str = "package batten.h\nimport rego.v1\n\n\
            p if input.v == 1\n\n\
            test_x if {\n\tx := {\"v\": 1}\n\tp with input as x\n}\n";
        assert_eq!(splits(HOISTED), Vec::<String>::new());
    }

    /// Fails by: `=` binding only its left side, so a variable unified on the
    /// RIGHT is not one of the case's own and the `with` term reading it is
    /// left unhoisted, naming an unbound variable.
    #[test]
    fn a_with_term_reading_a_variable_unified_on_the_right_is_hoisted() {
        const HOISTED: &str = "package batten.h\nimport rego.v1\n\n\
            p if input.v == 1\n\n\
            test_x if {\n\t{\"v\": 1} = x\n\tp with input as x\n}\n";
        assert_eq!(splits(HOISTED), Vec::<String>::new());
    }

    /// Fails by: a read of `input` under `with` desugared rather than refused.
    #[test]
    fn a_read_of_input_under_with_stays_on_the_interpreter() {
        const READ: &str = "package batten.i\nimport rego.v1\n\n\
            test_i if {\n\tinput.x == 1 with input as {\"x\": 1}\n}\n\n\
            test_plain if {\n\t1 == 1\n}\n";
        let found = splits(READ);
        assert!(
            found
                .iter()
                .any(|line| line.contains("a read of `input` or `data` under `with`")),
            "{found:?}"
        );
    }

    /// Fails by: a `:=` binding's right side taken as bound, as only `=`'s is,
    /// so `input` read before a `with` counts as a case local and the read of
    /// `input` under `with` is desugared rather than refused (CLOUD-2789).
    #[test]
    fn a_colon_assignment_reading_input_binds_only_its_left_side() {
        const READ: &str = "package batten.c\nimport rego.v1\n\n\
            test_c if {\n\ty := input\n\tinput.x == 1 with input as {\"x\": 1}\n}\n\n\
            test_plain if {\n\t1 == 1\n}\n";
        let found = splits(READ);
        assert!(
            found
                .iter()
                .any(|line| line.contains("a read of `input` or `data` under `with`")),
            "{found:?}"
        );
    }

    /// Fails by: a helper that writes its own `with` not recorded as one, so a
    /// case calling it is desugared as if the helper were plain.
    #[test]
    fn a_case_calling_a_helper_that_writes_with_stays_on_the_interpreter() {
        const HELPER: &str = "package batten.w\nimport rego.v1\n\n\
            h if {\n\tinput.x == 1 with input as {\"x\": 1}\n}\n\n\
            test_h if {\n\th\n}\n\n\
            test_plain if {\n\t1 == 1\n}\n";
        let found = splits(HELPER);
        assert!(
            found
                .iter()
                .any(|line| line.contains("a helper that writes its own `with`")),
            "{found:?}"
        );
    }

    /// Fails by: a cached suite program not read back as one, so every run
    /// recompiles it.
    #[test]
    fn a_written_suite_program_reads_back_as_cached() {
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let engine = bundle.evaluator.engine().expect("interpreted");
        let Ok(program) = SuiteProgram::compile(engine) else {
            panic!("the suite compiles");
        };
        assert!(!program.cached);
        let path = crate::scratch::scratch("suite-program-cache").join("row.rvm");
        program.write(&path, "key");
        let read = SuiteProgram::read(&path, "key", engine).expect("read back");
        assert!(read.cached);
        assert_eq!(read.tests.len(), program.tests.len());
    }

    /// Fails by: the coverage census counting a batch by more than the cases
    /// it ran. Three cases that never enter the predicate are swept in two
    /// batches, one case then two.
    #[test]
    fn the_coverage_census_counts_each_swept_case_once() {
        const UNENTERED: &str = "package batten.n\nimport rego.v1\n\nrules contains \"n\"\n\n\
violation contains {\"rule\": \"n\", \"verdict\": \"n\"} if {\n\tinput.call.operation == \"write\"\n}\n\n\
test_a if {\n\t\"n\" in rules\n}\n\n\
test_b if {\n\t\"n\" in rules\n}\n\n\
test_c if {\n\t\"n\" in rules\n}\n";
        let bundle = bundle_of("row", &[("policy/n.rego", UNENTERED)]);
        let before = coverage_cases();
        let suite = suite_of(&bundle, false);
        assert_eq!(suite.unexercised, vec!["n".to_owned()]);
        assert_eq!(coverage_cases() - before, 3);
    }

    /// Fails by: a bundle already on bytecode, compiled again with its AST
    /// kept, dropping the interpreter it held (`keep_ast` read as `false` on
    /// the compiled arm of `into_bundle`).
    #[test]
    fn a_compiled_bundle_compiled_again_keeps_its_interpreter_where_asked() {
        let data = serde_json::json!({});
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let first = Compiled::from_bundle(&bundle, &data).expect("compiles to bytecode");
        let second = Compiled::from_bundle(&bundle, &data).expect("compiles to bytecode");
        let third = Compiled::from_bundle(&bundle, &data).expect("compiles to bytecode");
        let kept = first.into_bundle(bundle, true);
        assert!(kept.as_interpreted().is_some(), "the interpreter is kept");
        let again = second.into_bundle(kept, true);
        assert!(again.is_bytecode());
        assert!(
            again.as_interpreted().is_some(),
            "a compiled bundle keeps the interpreter it held"
        );
        let dropped = third.into_bundle(again, false);
        assert!(dropped.as_interpreted().is_none(), "the hot path drops it");
    }

    /// A bytecode bundle read as interpreted evaluates on its interpreter, not
    /// on the bytecode it was compiled to (CLOUD-2789).
    ///
    /// Fails by: the interpreter evaluator dropped from `as_interpreted`'s
    /// bundle, so the parity check compares bytecode against itself.
    #[test]
    fn a_bundle_read_as_interpreted_evaluates_on_its_interpreter() {
        let data = serde_json::json!({});
        let bundle = bundle_of("row", &[("policy/a.rego", MODULE)]);
        let compiled = Compiled::from_bundle(&bundle, &data).expect("compiles to bytecode");
        let kept = compiled.into_bundle(bundle, true);
        assert!(kept.is_bytecode());
        let interpreted = kept.as_interpreted().expect("the interpreter is kept");
        assert!(!interpreted.is_bytecode());
        assert_eq!(
            interpreted.execution(),
            Execution::Interpreted(Fallback::NotOffered)
        );
    }

    /// Fails by: a case writing `input` twice desugared as its last write
    /// rather than refused (the `context.input.is_none()` guard of
    /// `with_terms` read as `true`).
    #[test]
    fn a_case_writing_input_twice_is_refused_bytecode() {
        let twice = "package batten.w\nimport rego.v1\n\n\
            violation contains \"w\" if {\n\tinput.go\n}\n\n\
            test_once if {\n\tcount(violation) == 1 with input as {\"go\": true}\n}\n\n\
            test_twice if {\n\tcount(violation) == 1 with input as {\"go\": false} with input as {\"go\": true}\n}\n";
        let splits = suite_splits(&bundle_of("row", &[("policy/w.rego", twice)]), "{}");
        assert!(
            splits
                .iter()
                .any(|line| line.contains("test_twice") && line.contains("a `with` on `input`")),
            "a second `with input` is refused, never desugared: {splits:?}"
        );
    }
}
