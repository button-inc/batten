use crate::config_model::Marker;
use crate::error::UsageError;

use anyhow::Result;

/// Validate a whole table, and refuse a duplicate `id`.
///
/// Called at config load ([`crate::config`]), which is the point: before
/// CLOUD-253 the only caller was [`find`], and `find` had no caller in `src/`,
/// so every refusal below was a refusal that could not fire. A validator
/// reachable only from its own tests is prose (non-negotiable rule 2) — the
/// same defect CLOUD-242 fixed in the verb table, which shipped in the same
/// commit as this one and was corrected without it.
///
/// Two rows under one `id` are refused for the reason the two fields are
/// separate axes at all: `id` is the name a count is reported under, so a
/// duplicate makes a count that answers no question — is it one marker
/// re-spelled, or two the author wanted counted apart?
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated entry.
pub fn validate(table: &[Marker]) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        entry.validate()?;
        if table[..index].iter().any(|prior| prior.id == entry.id) {
            return Err(UsageError::raise(format!(
                "marker {}: declared twice; an id is the name one count is reported under",
                entry.id
            )));
        }
    }
    Ok(())
}
