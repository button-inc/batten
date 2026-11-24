//! The harness-surface census (CLOUD-1636): a consumer declaring where harness
//! configuration lives declares it for every harness, or the load says which
//! one it left out.
//!
//! The declaration is a `[[pattern]]` family, `harness-config-<harness>`, one
//! row per [`Harness`] whose hook registration lives in a file. A module reads
//! the family to recognise a write to any harness's configuration, and to name
//! the harnesses a write left behind. Which spelling of a surface is legitimate
//! here is the consumer's (non-negotiable rule 1); which harnesses exist is the
//! core's, so the census is the core's too.
//!
//! WHY A NEW HARNESS IS REFUSED RATHER THAN DEFAULTED: a variant with no row
//! would read to every module over the family as "this harness keeps no
//! configuration", which is a confident wrong answer where the honest one is
//! "nobody declared it". A harness with no wiring file (the neutral exit-code
//! contract) keeps none by construction, so it owes no row.

use std::collections::BTreeSet;

use anyhow::Result;

use crate::config_model::Harness;
use crate::error::UsageError;
use crate::hook::HarnessExt as _;

/// The id prefix of the harness-surface family.
pub const FAMILY: &str = "harness-config-";

/// Refuse a harness-surface family that omits a harness with wiring, or names
/// a harness that does not exist. A table declaring no family is not judged:
/// a consumer that has not adopted the declaration owes nothing.
///
/// # Errors
///
/// A [`UsageError`] naming the harness left out, or the row naming no harness.
pub fn validate(patterns: &[crate::pattern::NamedPattern]) -> Result<()> {
    let declared: BTreeSet<&str> = patterns
        .iter()
        .filter_map(|pattern| pattern.id.strip_prefix(FAMILY))
        .collect();
    if declared.is_empty() {
        return Ok(());
    }
    if let Some(unknown) = declared
        .iter()
        .find(|name| !Harness::ALL.iter().any(|harness| harness.as_str() == **name))
    {
        return Err(UsageError::raise(format!(
            "[[pattern]] {FAMILY}{unknown}: names no harness this engine adapts, so no \
             write can be attributed to it"
        )));
    }
    if let Some(missing) = Harness::ALL
        .iter()
        .find(|harness| harness.wiring().is_some() && !declared.contains(harness.as_str()))
    {
        return Err(UsageError::raise(format!(
            "[[pattern]] {FAMILY}{}: missing — the family declares harness configuration \
             surfaces, and this harness keeps its hook registration in a file the family \
             does not name",
            missing.as_str()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str) -> crate::pattern::NamedPattern {
        crate::pattern::NamedPattern {
            id: id.to_owned(),
            regex: String::from("x"),
        }
    }

    fn family(skip: Option<&str>) -> Vec<crate::pattern::NamedPattern> {
        Harness::ALL
            .iter()
            .filter(|harness| harness.wiring().is_some())
            .map(|harness| harness.as_str())
            .filter(|name| Some(*name) != skip)
            .map(|name| row(&format!("{FAMILY}{name}")))
            .collect()
    }

    #[test]
    fn a_whole_family_loads() {
        assert!(validate(&family(None)).is_ok());
    }

    #[test]
    fn no_family_is_not_judged() {
        assert!(validate(&[row("unrelated")]).is_ok());
    }

    #[test]
    fn a_harness_left_out_is_refused_by_name() {
        let error = validate(&family(Some("cursor"))).expect_err("cursor is missing");
        assert!(error.to_string().contains("harness-config-cursor"), "{error}");
    }

    #[test]
    fn a_row_naming_no_harness_is_refused() {
        let mut rows = family(None);
        rows.push(row("harness-config-nonesuch"));
        let error = validate(&rows).expect_err("nonesuch is no harness");
        assert!(error.to_string().contains("nonesuch"), "{error}");
    }
}
