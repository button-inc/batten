//! The policy evaluator: a registered module decides over the resolved facts
//! (CLOUD-647, CLOUD-689).
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
const DENY_QUERY: &str = "data.batten.deny";

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
/// Read *alongside* [`DENY_QUERY`] rather than replacing it: this is additive.
const VIOLATION_QUERY: &str = "data.batten.violation";

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
const RULES_QUERY: &str = "data.batten.rules";

/// One denial a module produced: the predicate that fired, and its own message.
///
/// `rule` is `Option` and the two arms are the two shapes, not a convenience:
/// `None` is a bare string from [`DENY_QUERY`], attributed to the registering
/// row; `Some` is a [`VIOLATION_QUERY`] entry naming a predicate the module
/// published. [`Module::attribute`] is the one place that collapses them, so no
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

/// One registered module, loaded and compiled.
///
/// Holds the rule's `id` and the module's path for pointer-only reporting, and
/// the compiled engine. The **source is not a field**: nothing downstream may
/// render a policy body, and the cheapest way to keep that true is to give it
/// nowhere to live past compilation (rule 4).
pub struct Module {
    /// The `id` of the [`RuleKind::Policy`] row that registered this module.
    id: String,
    /// The repository-relative path, for the pointer in a finding.
    path: String,
    /// The predicate ids this module published through [`RULES_QUERY`].
    ///
    /// Read at load, once, and never re-queried: it is what a `violation`'s
    /// `rule` is checked against and what a `[[waiver]]` is judged reachable
    /// against. `BTreeSet` so the collision refusal names ids in a stable order
    /// — §6's byte-stability reaches a config error's text too.
    declared: BTreeSet<String>,
    /// The compiled evaluator, ready to take an input document.
    engine: regorus::Engine,
}

impl Module {
    /// The registering rule's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The module's repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The predicate ids this module published.
    #[must_use]
    pub fn declared(&self) -> &BTreeSet<String> {
        &self.declared
    }

    /// The id a denial is reported under: the predicate's own when it named one,
    /// the registering row's otherwise.
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

impl std::fmt::Debug for Module {
    /// Names the row and the path and **never the source**, so a policy body
    /// cannot reach a log through a derived `Debug` (rule 4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("id", &self.id)
            .field("path", &self.path)
            // The published ids are POINTERS — the same class as a rule id in a
            // finding — so they are admissible here where a body never is. They
            // are also the field a reader debugging an attribution question
            // actually wants.
            .field("declared", &self.declared)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Module {
    /// Equality is the **registration**, never the compiled engine.
    ///
    /// `regorus::Engine` has no meaningful equality, and it does not need one:
    /// [`load`] refuses two rows registering one path, so within a resolved
    /// policy the `(id, path)` pair determines the module. Comparing the
    /// registration is what a caller asking "is this the same policy?" actually
    /// means — `Policy` derives `PartialEq` for exactly that question.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.path == other.path
    }
}

impl Eq for Module {}

impl Clone for Module {
    /// Derived by hand only because [`Module`] hand-writes [`Debug`]; the engine
    /// itself is `Clone`, so this is the ordinary field-wise clone.
    ///
    /// Written out rather than derived so the `Debug` above cannot be silently
    /// re-derived alongside it, which would put a policy body back in reach of a
    /// log (rule 4).
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            path: self.path.clone(),
            declared: self.declared.clone(),
            engine: self.engine.clone(),
        }
    }
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
pub fn load(root: &Path, rules: &[Rule], reference: Option<&str>) -> Result<Vec<Module>> {
    let mut modules = Vec::new();
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
        // THE MODULE COMES FROM WHEREVER THE RULES CAME FROM, and that is the
        // whole of this branch. Under `--config-from <ref>` the authority is read
        // from the ref (`trust::load_base`), so reading the module off disk would
        // pair a base's rules with the working tree's predicates — and an agent
        // editing a registered `.rego` would change what the BASE policy decides.
        // That is exactly the influence `--config-from` exists to exclude, and it
        // is CLOUD-243's shape on the surface where it bites hardest.
        //
        // `git::show` is the gix-backed reader CLOUD-718 hardened, and it takes
        // the path as data rather than interpolating it into an argv.
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
        let mut engine = regorus::Engine::new();
        // The error is the engine's own, and it names a line in the MODULE, not
        // a byte of it — a parse diagnostic is a pointer, which is what rule 4
        // admits. The source itself never travels.
        engine
            .add_policy(path.to_owned(), source)
            .map_err(|err| UsageError::raise(format!("`{path}` does not compile: {err}")))?;
        // The smoke query, and it is the point of this function rather than a
        // precaution. Regorus reports a rule conflict and a recursion at
        // EVALUATION; without driving one here, the first thing that discovers a
        // cyclic module is a denied tool call, at the wrong time and in the wrong
        // exit class.
        engine.set_input_json("{}").map_err(|err| {
            UsageError::raise(format!("`{path}` rejected an empty input document: {err}"))
        })?;
        engine
            .eval_query(DENY_QUERY.to_owned(), false)
            .map_err(|err| UsageError::raise(format!("`{path}` faults when evaluated: {err}")))?;
        // The attributed set is smoke-queried too, and for the same reason: a
        // conflict or a recursion reachable only through `violation` would
        // otherwise be discovered by a denied tool call.
        let smoke = engine
            .eval_query(VIOLATION_QUERY.to_owned(), false)
            .map_err(|err| UsageError::raise(format!("`{path}` faults when evaluated: {err}")))?;

        // WHAT THE MODULE PUBLISHES, read once. A module carrying no `rules`
        // rule publishes nothing, which is exactly the pre-CLOUD-832 module and
        // is not an error — it simply cannot use the attributed shape.
        let declared = declared_ids(&mut engine).map_err(|err| {
            UsageError::raise(format!("`{path}` cannot publish its rule ids: {err}"))
        })?;

        // An id a `violation` names and the module never published is a config
        // error HERE rather than a surprise at the gate — the same posture the
        // smoke query above takes, applied to attribution. This can only see the
        // violations the empty document reaches; `deny` treats an undeclared id
        // met later as could-not-look, because a denial this gate cannot
        // attribute is not one it can honestly report.
        for violation in read_violations(&smoke).unwrap_or_default() {
            let Some(named) = violation.rule.as_deref() else {
                continue;
            };
            if !declared.contains(named) {
                return Err(UsageError::raise(format!(
                    "`{path}` raises `{named}`, which it does not declare in `{RULES_QUERY}`"
                )));
            }
        }

        // A `predicate_severity` key naming an id the module never published is a
        // setting that parses and does nothing, which is the shape house style
        // §8 refuses everywhere else in this config. This is the only place that
        // sees both the row and the module's declared set, so it is the only
        // place the check can live — `Rule::validate` has the row and not the
        // module. Same shape as CLOUD-208's dead-waiver diagnostic, and for the
        // same reason: a suppression or a severity aimed at nothing is a reader
        // believing a gate is tuned when it is not.
        if let Some(table) = rule.predicate_severity.as_ref() {
            for named in table.keys() {
                if !declared.contains(named.as_str()) {
                    return Err(UsageError::raise(format!(
                        "rule `{}` sets a severity for `{named}`, which `{path}` does not \
                         declare in `{RULES_QUERY}`",
                        rule.id
                    )));
                }
            }
        }

        // ACROSS EVERY MODULE THIS LOAD SEES, and that is what keeps a folder
        // from becoming a merge: there is no precedence to resolve because a
        // collision is refused outright rather than silently won by whichever
        // loaded last. It is also the clause that makes enumerating modules
        // inside an enabled bundle safe (CLOUD-129's corrected shape), and it
        // reaches across the vendored/in-repo boundary for free — a preset is
        // just another module with a declared id set.
        for id in &declared {
            if let Some(owner) = ids.get(id.as_str()) {
                return Err(UsageError::raise(format!(
                    "`{path}` and `{owner}` both declare the rule id `{id}`; a finding                      names one predicate, so there is no precedence to resolve here"
                )));
            }
        }
        for id in &declared {
            ids.insert(id.clone(), path.to_owned());
        }

        modules.push(Module {
            id: rule.id.clone(),
            path: path.to_owned(),
            declared,
            engine,
        });
    }
    Ok(modules)
}

/// The ids a compiled module publishes through [`RULES_QUERY`].
///
/// An absent or non-set `rules` rule is an EMPTY set rather than an error: a
/// module written before CLOUD-832, or one using only the bare-string `deny`
/// shape, publishes nothing and is entirely valid. Only a module that *faults*
/// answering the query is a fault.
fn declared_ids(engine: &mut regorus::Engine) -> Result<BTreeSet<String>, anyhow::Error> {
    let results = engine.eval_query(RULES_QUERY.to_owned(), false)?;
    let mut ids = BTreeSet::new();
    for result in results.result {
        for value in result.expressions {
            match &value.value {
                regorus::Value::Set(items) => {
                    for item in items.iter() {
                        if let Ok(text) = item.as_string() {
                            ids.insert(text.to_string());
                        }
                    }
                }
                regorus::Value::Array(items) => {
                    for item in items.iter() {
                        if let Ok(text) = item.as_string() {
                            ids.insert(text.to_string());
                        }
                    }
                }
                // Undefined is the ordinary case for a module with no `rules`
                // rule. Anything else is a shape this gate cannot read, and
                // reading it as "declares nothing" would turn every id the
                // module raises into an undeclared-id refusal — a confusing
                // error a long way from its cause.
                regorus::Value::Undefined => {}
                other => {
                    anyhow::bail!(
                        "`{RULES_QUERY}` answered a {} rather than a set of ids",
                        shape(other)
                    )
                }
            }
        }
    }
    Ok(ids)
}

/// The stable one-word name of a value's shape, for a diagnostic.
///
/// The SHAPE and never the value (rule 4): a module's data is the consumer's,
/// and a diagnostic that quoted it back would put policy content into a log.
const fn shape(value: &regorus::Value) -> &'static str {
    match value {
        regorus::Value::Null => "null",
        regorus::Value::Bool(_) => "boolean",
        regorus::Value::Number(_) => "number",
        regorus::Value::String(_) => "string",
        regorus::Value::Array(_) => "array",
        regorus::Value::Set(_) => "set",
        regorus::Value::Object(_) => "object",
        regorus::Value::Undefined => "undefined",
    }
}

/// Evaluate one module over an input document and return its denials.
///
/// Pure: no I/O, no environment, no clock. The engine was compiled at the
/// boundary and the input is data the caller already holds, which is what lets
/// this be called from [`crate::hook::adjudicate`]'s chain.
///
/// **Both shapes, one answer.** The bare-string [`DENY_QUERY`] set and the
/// attributed [`VIOLATION_QUERY`] set are read into one `Vec<Violation>`, in
/// that order — `deny` first, so a module carrying both keeps the declaration
/// order a reviewer reads. A bare string yields `rule: None` and is attributed
/// to the registering row exactly as it was before CLOUD-832.
///
/// Returns [`Look::CouldNotLook`] when the module faults or the input will not
/// serialize — never an empty deny set, because "it ran and found nothing" and
/// "it could not run" are different answers and collapsing them is CLOUD-251's
/// vacuous pass.
///
/// **An undeclared id is also could-not-look**, and that arm is the one worth
/// stating: a module raising a `violation` whose `rule` it never published gives
/// this gate a denial it cannot attribute, and the two alternatives are both
/// wrong — reporting it under the ROW id silently re-flattens the very
/// attribution CLOUD-832 exists to add, and dropping it turns a real refusal
/// into a pass. `load` refuses this outright for every violation the empty
/// document reaches; this is the residue, on inputs load could not exercise.
#[must_use]
pub fn deny(module: &Module, input: &str) -> Look<Vec<Violation>> {
    let mut engine = module.engine.clone();
    if engine.set_input_json(input).is_err() {
        return Look::CouldNotLook;
    }
    let mut violations = Vec::new();

    let Ok(unattributed) = engine.eval_query(DENY_QUERY.to_owned(), false) else {
        return Look::CouldNotLook;
    };
    match read_strings(&unattributed) {
        Some(messages) => violations.extend(
            messages
                .into_iter()
                .map(|msg| Violation { rule: None, msg }),
        ),
        None => return Look::CouldNotLook,
    }

    let Ok(attributed) = engine.eval_query(VIOLATION_QUERY.to_owned(), false) else {
        return Look::CouldNotLook;
    };
    match read_violations(&attributed) {
        Some(entries) => {
            for entry in entries {
                if let Some(named) = entry.rule.as_deref() {
                    if !module.declared.contains(named) {
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

/// The bare-string members of a `deny` result, or `None` for a shape this gate
/// cannot read.
///
/// `None` is could-not-look at every call site, never "no denials": a module
/// whose `deny` is neither a set nor an array decided nothing readable, and
/// guessing it is empty is CLOUD-251's vacuous pass.
fn read_strings(results: &regorus::QueryResults) -> Option<Vec<String>> {
    let mut messages = Vec::new();
    for result in &results.result {
        for value in &result.expressions {
            match &value.value {
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
                // Undefined is the ordinary shape of a module that has no
                // `deny` rule at all, which is entirely valid once `violation`
                // exists — it is an empty contribution, not an unreadable one.
                regorus::Value::Undefined => {}
                _ => return None,
            }
        }
    }
    Some(messages)
}

/// The `{"rule": …, "msg": …}` members of a `violation` result, or `None` for a
/// shape this gate cannot read.
///
/// A member missing `msg` is unreadable rather than empty-messaged: a refusal
/// whose text is the empty string tells its reader nothing, and inventing one
/// here would put Batten's words in the consumer's mouth. A member missing
/// `rule` is fine and falls back to the row, which is [`DENY_QUERY`]'s
/// behaviour reached by a different spelling.
fn read_violations(results: &regorus::QueryResults) -> Option<Vec<Violation>> {
    let mut violations = Vec::new();
    for result in &results.result {
        for value in &result.expressions {
            let items: Vec<&regorus::Value> = match &value.value {
                regorus::Value::Set(items) => items.iter().collect(),
                regorus::Value::Array(items) => items.iter().collect(),
                regorus::Value::Undefined => continue,
                _ => return None,
            };
            for item in items {
                let msg = item
                    .as_object()
                    .ok()?
                    .get(&"msg".into())?
                    .as_string()
                    .ok()?;
                let rule = item
                    .as_object()
                    .ok()?
                    .get(&"rule".into())
                    .and_then(|value| value.as_string().ok())
                    .map(|text| text.to_string());
                violations.push(Violation {
                    rule,
                    msg: msg.to_string(),
                });
            }
        }
    }
    Some(violations)
}
