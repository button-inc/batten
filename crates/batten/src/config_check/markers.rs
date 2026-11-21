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

/// `Marker` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub(crate) trait MarkerExt: Sized {
    /// Reject a marker that cannot honestly be counted.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an empty
    /// `token` — which would match every line of every file — or an empty
    /// `glob`, which reads as "everywhere" but selects nothing.
    fn validate(&self) -> Result<()>;
}

impl MarkerExt for Marker {
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("marker: `id` must not be empty"));
        }
        if self.token.is_empty() {
            return Err(UsageError::raise(format!(
                "marker {}: `token` must not be empty; an empty token matches every line",
                self.id
            )));
        }
        if self.glob.as_deref() == Some("") {
            return Err(UsageError::raise(format!(
                "marker {}: `glob` must not be empty; omit the key to scan the whole tree",
                self.id
            )));
        }
        Ok(())
    }
}
