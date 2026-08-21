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
//! precisely so `http` and `jsonschema` never enter the closure, and
//! `no_evaluator_feature_admits_io` is what keeps that from drifting.
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

use std::collections::BTreeSet;
use std::path::Path;

use crate::Result;
use crate::error::UsageError;
use crate::facts::Look;
use crate::rules::{Rule, RuleKind};

/// The query every module answers, and the only one.
///
/// A fixed query rather than a configurable one: what a policy row decides must
/// be the same question for every module, or a reviewer reading `batten.toml`
/// cannot tell what a row does without opening the module. The package is the
/// consumer's; the rule name is Batten's.
const DENY_QUERY: &str = "data.batten.deny";

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
}

impl std::fmt::Debug for Module {
    /// Names the row and the path and **never the source**, so a policy body
    /// cannot reach a log through a derived `Debug` (rule 4).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("id", &self.id)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

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
            engine: self.engine.clone(),
        }
    }
}

/// Load, compile and smoke-test every module the rule set registers.
///
/// Boundary I/O, called once per process from the config resolution path — never
/// from [`crate::hook::adjudicate`], which is contractually pure.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when a row registers no module, when the file is
/// absent or unreadable, when it does not compile, or when the smoke query
/// faults. Every one of those is a config error at load rather than a surprise
/// at the gate, which is the whole reason this function drives a query it throws
/// away.
pub fn load(root: &Path, rules: &[Rule]) -> Result<Vec<Module>> {
    let mut modules = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
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
        let source = std::fs::read_to_string(root.join(path)).map_err(|_| {
            UsageError::raise(format!(
                "rule `{}` registers `{path}`, which cannot be read",
                rule.id
            ))
        })?;
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
        modules.push(Module {
            id: rule.id.clone(),
            path: path.to_owned(),
            engine,
        });
    }
    Ok(modules)
}

/// Evaluate one module over an input document and return its denials.
///
/// Pure: no I/O, no environment, no clock. The engine was compiled at the
/// boundary and the input is data the caller already holds, which is what lets
/// this be called from [`crate::hook::adjudicate`]'s chain.
///
/// Returns [`Look::CouldNotLook`] when the module faults or the input will not
/// serialize — never an empty deny set, because "it ran and found nothing" and
/// "it could not run" are different answers and collapsing them is CLOUD-251's
/// vacuous pass.
#[must_use]
pub fn deny(module: &Module, input: &str) -> Look<Vec<String>> {
    let mut engine = module.engine.clone();
    if engine.set_input_json(input).is_err() {
        return Look::CouldNotLook;
    }
    let Ok(results) = engine.eval_query(DENY_QUERY.to_owned(), false) else {
        return Look::CouldNotLook;
    };
    let mut denials = Vec::new();
    for result in results.result {
        for value in result.expressions {
            match &value.value {
                regorus::Value::Set(items) => {
                    for item in items.iter() {
                        if let Ok(text) = item.as_string() {
                            denials.push(text.to_string());
                        }
                    }
                }
                regorus::Value::Array(items) => {
                    for item in items.iter() {
                        if let Ok(text) = item.as_string() {
                            denials.push(text.to_string());
                        }
                    }
                }
                // A module whose `deny` is neither a set nor an array decided
                // nothing this gate can read. Stated rather than wildcarded to
                // "no denials": a shape we do not understand is could-not-look,
                // and guessing it is empty is the vacuous pass again.
                _ => return Look::CouldNotLook,
            }
        }
    }
    Look::Is(denials)
}
