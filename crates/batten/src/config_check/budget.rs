use crate::budget::BudgetExt as _;
use crate::config_model::Budget;
use crate::error::UsageError;

use anyhow::Result;

/// Validate the `[budget]` table at load.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a `[budget]` table declaring no
/// budget. A table that parses and gates nothing is the half-change
/// non-negotiable rule 2 exists to refuse.
pub fn validate(budget: Option<&Budget>) -> Result<()> {
    let Some(budget) = budget else {
        return Ok(());
    };
    if budget.is_empty() {
        return Err(UsageError::raise(
            "budget: the table declares no set; remove it or declare [budget.<name>]".to_owned(),
        ));
    }
    Ok(())
}
