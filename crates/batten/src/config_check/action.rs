use crate::config_model::Action;
use crate::config_model::Event;
use crate::error::UsageError;
use crate::hook::EventExt as _;
use std::collections::BTreeSet;

/// Reject a table that cannot honestly fire, and duplicate ids within it.
///
/// A duplicate id is refused rather than merged: two actions reporting failures
/// under one name make the pointer ambiguous, which is the one thing the id
/// exists to prevent.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for any invalid row, or a repeated `id`.
pub fn validate(actions: &[Action]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for action in actions {
        action.validate()?;
        if !seen.insert(action.id.as_str()) {
            return Err(UsageError::raise(format!(
                "hook.action {}: declared twice; ids identify a row in its failure report",
                action.id
            )));
        }
    }
    Ok(())
}

/// `Action` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub(crate) trait ActionExt: Sized {
    /// Reject an action that cannot honestly fire.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
    /// no known event or naming `pre-tool` (see the module docs), an empty
    /// `run`, or a `run` whose program is empty.
    fn validate(&self) -> anyhow::Result<()>;
}

impl ActionExt for Action {
    fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("hook.action: `id` must not be empty"));
        }
        let Some(event) = event_of(&self.on) else {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` names no event ({:?}); expected one of {}",
                self.id,
                self.on,
                declarable_tokens().join(", ")
            )));
        };
        // The two reasons are in the module docs; the message carries the one an
        // author can act on.
        if event == Event::PreTool {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` may not be {:?} — it is the event policy adjudicates, so a \
                 side effect there would run before a possible deny",
                self.id,
                Event::PreTool.as_str()
            )));
        }
        // Not a moment, but the absence of one Batten could name. An action
        // keyed here would fire on any host event this build has never heard
        // of — the widest possible trigger, chosen by nobody.
        if event == Event::Unrecognized {
            return Err(UsageError::raise(format!(
                "hook.action {}: `on` may not be {:?} — it names no moment, only that the host \
                 said something this build does not normalize",
                self.id,
                Event::Unrecognized.as_str()
            )));
        }
        if self.run.is_empty() {
            return Err(UsageError::raise(format!(
                "hook.action {}: `run` must name a command",
                self.id
            )));
        }
        if self.run[0].is_empty() {
            return Err(UsageError::raise(format!(
                "hook.action {}: `run`'s first element is the program and must not be empty",
                self.id
            )));
        }
        Ok(())
    }
}

/// Resolve a normalized event token, or `None` when it names none.
///
/// Derived from [`Event::ALL`] rather than a second table, so an event added to
/// the enum is declarable here in the same change.
pub(crate) fn event_of(token: &str) -> Option<Event> {
    Event::ALL
        .iter()
        .copied()
        .find(|event| event.as_str() == token)
}

/// Every token an action may declare: the events, minus the two an action may
/// not attach to.
///
/// `unrecognized` is excluded for a different reason than `pre-tool`: it is not
/// a moment, it is the *absence* of one Batten could name, so an action keyed on
/// it would fire on any host event this build has never heard of.
pub(crate) fn declarable_tokens() -> Vec<&'static str> {
    Event::ALL
        .iter()
        .filter(|event| !matches!(event, Event::PreTool | Event::Unrecognized))
        .map(|event| event.as_str())
        .collect()
}
