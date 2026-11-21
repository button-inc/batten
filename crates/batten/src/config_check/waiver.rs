use crate::config_model::Waiver;
use crate::error::UsageError;
use crate::waiver::WaiverExt as _;

use anyhow::Result;

/// Refuse a malformed waiver table at load, so a typo cannot sit inert.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for an empty rule id, an empty reason,
/// an unparseable expiry, or the same rule-and-path waived twice.
pub fn validate(table: &[Waiver]) -> Result<()> {
    for (index, waiver) in table.iter().enumerate() {
        if waiver.rule.trim().is_empty() {
            return Err(UsageError::raise(
                "waiver: rule must not be empty — a waiver that names no rule suppresses nothing",
            ));
        }
        if waiver.reason.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "waiver {}: reason is required — an unjustified waiver is exactly the hatch this \
                 table exists to replace",
                waiver.rule
            )));
        }
        waiver.expiry()?;
        if table[..index]
            .iter()
            .any(|prior| prior.key() == waiver.key())
        {
            return Err(UsageError::raise(format!(
                "{}: declared twice",
                waiver.key()
            )));
        }
    }
    Ok(())
}
