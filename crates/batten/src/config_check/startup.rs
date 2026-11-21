use crate::config_model::Startup;
use crate::error::UsageError;
use anyhow::Result;

/// Refuse a row the engine cannot act on, at LOAD rather than at the first run.
///
/// An empty `check` is the one that matters: [`ran_clean`] would answer
/// could-not-look forever, so the row would report a failure nobody can fix and
/// its repair would never run. Refusing it at load says which row and why, once,
/// instead of once per session — the same direction `[[pattern]]`'s load-time
/// refusal takes one surface over.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row's id.
pub fn validate(rows: &[Startup]) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for row in rows {
        if row.check.is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `check` is empty, so the row could never decide anything",
                row.id
            )));
        }
        if row.repair.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `repair` is present and empty — omit the key for a \
                 diagnose-only row rather than declaring a repair that runs nothing",
                row.id
            )));
        }
        if row.gloss.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `gloss` is empty, and the report is pointer-only — this is \
                 the one place the row's meaning can be written down",
                row.id
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: declared twice — one id, one row, or a report names a \
                 verdict a reader cannot trace back",
                row.id
            )));
        }
    }
    Ok(())
}
