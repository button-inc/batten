use crate::config_model::RecordDeclared as Declared;
use crate::error::UsageError;

use anyhow::Result;

/// The record names this crate's own VERBS write, as opposed to the ones a
/// `[[recorder]]` row mints from a tool envelope (CLOUD-472).
///
/// # Why a verb writes this at all, which is the whole design decision
///
/// A hook mediates a call the agent makes to somebody ELSE's tool, so it is
/// per-harness by nature: `TaskCreate`/`TaskUpdate` here, `write_todos` on
/// Gemini CLI, `todowrite` on `OpenCode`, `update_plan` on Codex. Recording from
/// those envelopes needs a spelling per host, and its failure mode is the one
/// this whole module exists to name — an unsurveyed harness, a tool a setting
/// switched off, and an agent that did as it was told all produce NOTHING, so the gate reads
/// clean. `OpenCode` makes that concrete: `todowrite` is denied to subagents at
/// session creation regardless of configuration.
///
/// A verb inverts the direction. The agent TELLS the engine, so a missing record
/// refuses on every harness identically — no survey, no per-host spelling, and no
/// setting that can quietly disarm it. Discovery still has a job (reporting which
/// native surface exists, so a mirror can be kept for the human's benefit), but
/// the gate reads this store and only this store.
/// `claim` is here for a second reason worth stating: `claim check` writes it and
/// nothing read it from a module before, but it is the honest signal for "this
/// branch is doing tracked work". A gate that demands a plan from EVERY tree with
/// a diff refuses every scratch fixture and every consumer checkout — measured,
/// it reddened four `cli.rs` cases that only wanted to exercise other rules.
/// Keyed to a claim, it asks the question exactly where the answer is owed.
/// `lap` joins them for the same reason and with one difference worth stating:
/// it is the only one of the three that is a HISTORY rather than a current
/// state. `land::replay` appends a line per lap, and
/// `replay halt conflict` reads the last one — so a conflict resolved by
/// a later lap stops refusing, which a store keeping only the newest line could
/// not express.
pub const VERB_WRITTEN: &[&str] = &["claim", "plan", crate::config_model::LAP_RECORD];

/// Prove every declared family well formed (CLOUD-253's obligation).
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for a family whose name is not a single path
/// component, for an empty `writer`, and for two rows naming one family — the
/// last because a second row is a second answer to "who writes this", which is
/// the one question the table exists to settle.
pub fn validate(
    declared: &[Declared],
    recorders: &[crate::config_model::RecorderDeclared],
) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for family in declared {
        // ONE NAME, ONE SOURCE. The projection resolves a `[[recorder]]` row's
        // record, then a `[[record]]` family, then a verb-written store, and
        // keeps the first — so a family sharing a name with either was silently
        // shadowed, its producer writing a store no module reads as its own.
        if VERB_WRITTEN.contains(&family.record.as_str()) {
            return Err(UsageError::raise(format!(
                "record `{}` is a store the engine writes itself; a declared family \
                 of that name would be a second writer for it",
                family.record
            )));
        }
        if recorders
            .iter()
            .any(|recorder| recorder.record == family.record)
        {
            return Err(UsageError::raise(format!(
                "record `{}` is already a `[[recorder]]` row's record; a declared family \
                 of that name would be shadowed by it",
                family.record
            )));
        }
        // The same grammar the writer enforces, checked here so the refusal lands
        // at load. A name that escapes its store is why `safe_component` exists;
        // reaching it only from `run_named` would let a config sit green until a
        // producer ran.
        safe_component("record", &family.record)?;
        if family.writer.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "record `{}`: `writer` names what fills this store and is empty, so the \
                 family could only ever read could-not-look",
                family.record
            )));
        }
        if !seen.insert(family.record.as_str()) {
            return Err(UsageError::raise(format!(
                "record `{}` is declared twice; one family has one writer",
                family.record
            )));
        }
    }
    Ok(())
}

/// A family name that cannot escape its store.
///
/// **A path component, checked rather than trusted.** The family and the key both
/// reach this from a caller's argv, and a `..` or a `/` in either would put a
/// record outside the store the reader looks in — which is not a security
/// boundary here so much as a silent miss: the write succeeds, the read finds
/// nothing, and the gate reads clean.
pub(crate) fn safe_component(what: &str, value: &str) -> Result<String> {
    let clean = value.trim();
    if clean.is_empty()
        || clean == "."
        || clean == ".."
        || clean.contains('/')
        || clean.contains('\\')
        || clean.contains('\0')
    {
        return Err(UsageError::raise(format!(
            "the {what} must be one path component and must not be `.`, `..`, or contain a separator"
        )));
    }
    Ok(clean.to_owned())
}
