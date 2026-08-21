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
//! * `mise-tasks/evaluator-closure-check`, wired as `batten.toml`'s
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

/// One denial a module produced: the predicate that fired, and its own message.
///
/// `rule` is `Option` and the two arms are the two shapes, not a convenience:
/// `None` is a bare string from [`DENY_RULE`], attributed to the registering
/// row; `Some` is a [`VIOLATION_RULE`] entry naming a predicate the module
/// published. [`Bundle::attribute`] is the one place that collapses them, so no
/// caller re-derives the fallback and gets it differently.
///
/// `msg` is the **module's own text**, exactly as a row's `reason` is the
/// consumer's — never a rendering of the policy body, which rule 4 would refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The predicate id, when the module named one.
    pub rule: Option<String>,
    /// The module's message.
    pub msg: String,
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
pub fn load(root: &Path, rules: &[Rule], reference: Option<&str>) -> Result<Vec<Bundle>> {
    let mut bundles = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    // Every predicate id published so far, and the module that published it —
    // the value is what lets the collision refusal name BOTH sides, which is the
    // difference between a pointer and a complaint.
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for rule in rules.iter().filter(|r| r.kind == RuleKind::Policy) {
        // `validate` already refuses a policy row with no `module`; this is the
        // located restatement, so a caller reaching `load` directly cannot get a
        // silent skip instead of a refusal.
        let path = rule.module.as_deref().ok_or_else(|| {
            UsageError::raise(format!(
                "rule `{}` is a policy row with no `module`",
                rule.id
            ))
        })?;
        // Two rows naming one module is dead config: the second registration
        // decides nothing the first did not, and "which one denied me" is not a
        // question a reviewer should have to answer.
        if !seen.insert(path) {
            return Err(UsageError::raise(format!(
                "rule `{}` registers `{path}`, which another rule already registers",
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
        let mut sources = Vec::new();
        for path in [path] {
            let source = match reference {
                Some(reference) => crate::git::show(root, reference, path).map_err(|_| {
                    UsageError::raise(format!(
                        "rule `{}` registers `{path}`, which is absent at {reference}",
                        rule.id
                    ))
                })?,
                None => std::fs::read_to_string(root.join(path)).map_err(|_| {
                    UsageError::raise(format!(
                        "rule `{}` registers `{path}`, which cannot be read",
                        rule.id
                    ))
                })?,
            };
            sources.push((path.to_owned(), source));
        }

        // EVERYTHING PAST THE READ IS PURE, and the split is what lets the
        // composition property be tested without a filesystem: `compile` builds
        // one engine from N sources, which is the whole of CLOUD-837.
        let bundle = compile(&rule.id, &sources)?;
        let declared = bundle.declared.clone();

        // The pointer a bundle-level fault is reported against.
        let where_it_came_from = path;

        // A `predicate_severity` key naming an id the bundle never published is a
        // setting that parses and does nothing, which is the shape house style
        // §8 refuses everywhere else in this config. This is the only place that
        // sees both the row and the bundle's declared set, so it is the only
        // place the check can live — `Rule::validate` has the row and not the
        // module. Same shape as CLOUD-208's dead-waiver diagnostic, and for the
        // same reason: a suppression or a severity aimed at nothing is a reader
        // believing a gate is tuned when it is not.
        if let Some(table) = rule.predicate_severity.as_ref() {
            for named in table.keys() {
                if !declared.contains(named.as_str()) {
                    return Err(UsageError::raise(format!(
                        "rule `{}` sets a severity for `{named}`, which `{where_it_came_from}` \
                         does not declare in `{RULES_RULE}`",
                        rule.id
                    )));
                }
            }
        }

        // ACROSS EVERY BUNDLE THIS LOAD SEES, and that is what keeps a folder
        // from becoming a merge: there is no precedence to resolve because a
        // collision is refused outright rather than silently won by whichever
        // loaded last. It is also the clause that makes enumerating modules
        // inside an enabled bundle safe (CLOUD-129's corrected shape), and it
        // reaches across the vendored/in-repo boundary for free — a preset is
        // just another bundle with a declared id set. Bundles are ISOLATED as
        // engines and still visible to each other HERE, which is the whole
        // point: a preset cannot supply a helper, and cannot silently shadow an
        // id either.
        for id in &declared {
            if let Some(owner) = ids.get(id) {
                return Err(UsageError::raise(format!(
                    "`{where_it_came_from}` and `{owner}` both declare the rule id `{id}`; a \
                     finding names one predicate, so there is no precedence to resolve here"
                )));
            }
        }
        for id in &declared {
            ids.insert(id.clone(), where_it_came_from.to_owned());
        }

        bundles.push(bundle);
    }
    Ok(bundles)
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
pub fn compile(id: &str, sources: &[(String, String)]) -> Result<Bundle> {
    // ONE ENGINE FOR THE WHOLE BUNDLE. `add_policy` once per file into it, so
    // the bundle compiles once and a helper defined in one module is callable
    // from another. This is how Conftest and OPA load a policy directory, and
    // constructing the engine outside the loop is the entire fix: it used to sit
    // inside it, which is why there was no composed rule set to speak of.
    let mut engine = new_engine();
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
/// same message, and collapsing them would under-report.
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

/// The `{"rule": …, "msg": …}` members of every `violation` under the package,
/// or `None` for a shape this gate cannot read.
///
/// A member missing `msg` is unreadable rather than empty-messaged: a refusal
/// whose text is the empty string tells its reader nothing, and inventing one
/// here would put Batten's words in the consumer's mouth. A member missing
/// `rule` is fine and falls back to the row, which is [`DENY_RULE`]'s behaviour
/// reached by a different spelling.
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
            let msg = object.get(&"msg".into())?.as_string().ok()?;
            let rule = object
                .get(&"rule".into())
                .and_then(|value| value.as_string().ok())
                .map(std::string::ToString::to_string);
            violations.push(Violation {
                rule,
                msg: msg.to_string(),
            });
        }
    }
    Some(violations)
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
        Some(messages) => violations.extend(
            messages
                .into_iter()
                .map(|msg| Violation { rule: None, msg }),
        ),
        None => return Look::CouldNotLook,
    }
    match collect_violations(&answered) {
        Some(entries) => {
            for entry in entries {
                if let Some(named) = entry.rule.as_deref() {
                    if !bundle.declared.contains(named) {
                        return Look::CouldNotLook;
                    }
                }
                violations.push(entry);
            }
        }
        None => return Look::CouldNotLook,
    }

    Look::Is(violations)
}
