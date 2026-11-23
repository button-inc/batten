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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config_model::BudgetSet;
    use std::collections::BTreeMap;

    fn budget_of(name: &str) -> Budget {
        Budget(
            [(
                name.to_owned(),
                BudgetSet {
                    files: vec!["AGENTS.md".to_owned()],
                    max_tokens: 1,
                    max_lines: None,
                    max_bytes_per_file: None,
                    embedded: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    #[test]
    fn a_budget_table_declaring_no_budget_is_refused() {
        let err = validate(Some(&Budget(BTreeMap::new()))).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(validate(None).is_ok());
        assert!(validate(Some(&budget_of("instructions"))).is_ok());
    }

    #[test]
    fn a_set_name_is_the_consumers_and_the_engine_carries_none() {
        // Rule 1: the engine must hold no consumer-specific identifier. Any name
        // works, because the table is a map rather than a field per set — before
        // this, a second consumer's budget needed an engine change.
        for name in ["instructions", "prompts", "whatever-they-call-it"] {
            let budget = budget_of(name);
            assert!(validate(Some(&budget)).is_ok());
            let (declared, _) = budget.sets().next().unwrap();
            assert_eq!(declared, name);
        }
    }
}
