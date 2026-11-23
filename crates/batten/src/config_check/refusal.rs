use crate::config_model::Ceiling;

/// Refuse a `[refusal]` table that declares a ceiling nothing could satisfy.
///
/// A zero ceiling would refuse every line including the shortest possible one,
/// which is the switched-off gate CLOUD-418 names: it fires on everything, so
/// the first person to run it turns it off. Refused at load, in the same
/// direction and for the same reason `budget.rs` refuses an empty set.
///
/// # Errors
///
/// When the declared ceiling is zero.
pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
    let Some(declared) = ceiling else {
        return Ok(());
    };
    if declared.max_tokens == 0 {
        return Err(
            "`[refusal] max_tokens = 0` refuses every line a refusal could emit, including the \
             shortest one the grammar can spell — a ceiling nothing can satisfy is a gate that \
             gets switched off rather than one that holds"
                .to_owned(),
        );
    }
    if declared.first_sighting_max_tokens == Some(0) {
        return Err(
            "`[refusal] first_sighting_max_tokens = 0` refuses every first sighting a refusal \
             could emit, including the irreducible one — and the first sighting is the only \
             firing that carries the class definition, so a zero there withholds the remedy \
             from the one reader who has not read it"
                .to_owned(),
        );
    }
    // The first sighting carries strictly more than the repeat — the same line
    // plus a gloss and at least one route — so a first-sighting ceiling at or
    // below the repeat's cannot be met by any line that arm can compose. Refused
    // here rather than discovered as an arm that silently never renders its
    // definition, which is the defect this row exists to remove.
    if let Some(first) = declared.first_sighting_max_tokens
        && first <= declared.max_tokens
    {
        return Err(format!(
            "`[refusal] first_sighting_max_tokens = {first}` is not above `max_tokens = {}`, and \
             a first sighting is the repeat line plus a gloss and a route — so no line this arm \
             can compose would fit, and the definition would never render",
            declared.max_tokens
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A `[refusal]` ceiling of `max` tokens and an optional first-sighting one.
    fn ceiling(max: usize, first: Option<usize>) -> Ceiling {
        Ceiling {
            max_tokens: max,
            first_sighting_max_tokens: first,
        }
    }

    /// Fails by: a ceiling nothing can satisfy admitted at load, or one that can
    /// refused.
    #[test]
    fn a_ceiling_nothing_can_satisfy_is_refused() {
        assert!(validate(None).is_ok());
        assert!(validate(Some(&ceiling(1, None))).is_ok());
        assert!(validate(Some(&ceiling(5, Some(6)))).is_ok());
        assert!(validate(Some(&ceiling(0, None))).is_err());
        assert!(validate(Some(&ceiling(5, Some(0)))).is_err());
        assert!(validate(Some(&ceiling(5, Some(5)))).is_err());
    }
}
