//! A deferral's reversal condition, as data rather than as prose (CLOUD-759).
//!
//! # Why this exists
//!
//! CLOUD-686 is the diagnosis and had no mechanism: *"a deferral names the
//! condition for its own reversal, the condition is later satisfied, and nothing
//! re-fires — every discharge so far was a human re-reading prose."*
//!
//! Two instances were found by accident in one session on 2026-08-20, which is
//! the point: nothing was watching. CLOUD-647 deferred adopting regorus on
//! `rust-version = 1.88.0` against a `1.85.0` pin, and the pin has since moved
//! past it — fully discharged and still carried as blocking. CLOUD-310 deferred
//! ast-grep on a conjunction whose MSRV half is likewise satisfied. One fact, the
//! toolchain pin, with three issue bodies reasoning from a stale copy of it.
//!
//! # The bound, stated rather than hidden
//!
//! This reaches only conditions expressible over facts the tree holds. *"Upstream
//! declares a stable public API"* is not one, and CLOUD-310's predicate is a
//! conjunction of one reachable half and one unreachable half. **Reporting the
//! reachable half is still the whole finding** — both measured instances would
//! have fired on the MSRV clause alone.
//!
//! # One authority for the pin
//!
//! The task runner's tool pin is the authority, and the workspace manifest's
//! `rust-version` is a derived copy that `msrv-pin-agreement` already holds to
//! it. This reads the derived copy because it is the one a Cargo consumer
//! resolves against, and the two cannot disagree without that gate firing first
//! — so there is no second authority here, only the nearer of two spellings of
//! one.
//!
//! Which PATHS carry those two spellings is the consumer's to say, never this
//! module's (non-negotiable rule 1): the core knows the manifest FORMAT and the
//! key inside it, and the tree it reads is handed in.

use serde::{Deserialize, Serialize};

use schemars::JsonSchema;

/// One deferred decision and the condition that would reverse it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Deferral {
    /// The row that owns the decision. A pointer, never the prose.
    pub issue: String,
    /// The fact the condition compares. One name today, and a closed set on
    /// purpose: an open one would let a row name a fact nothing produces and
    /// read as watched while nothing watched it.
    pub fact: Fact,
    /// The value at which the deferral reverses, as a version.
    ///
    /// Read as **at or above**: the condition holds once the fact reaches this.
    /// That is the direction both measured deferrals are written in — *"its
    /// `rust-version` is at or below this repo's pin"* is this comparison with
    /// the operands named the other way round.
    pub reaches: String,
    /// Why the decision was deferred, for the reader who meets the refusal.
    ///
    /// Prose, and deliberately not compared: the gate decides on `reaches`, and
    /// this is what tells a human which of the two remedies applies.
    pub reason: String,
}

/// The facts a deferral may compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Fact {
    /// The workspace's `rust-version`.
    RustVersion,
}

/// Refuse a `[[deferral]]` table whose entries cannot be evaluated.
///
/// At LOAD, so a row whose condition could never be compared is a config fault
/// rather than a deferral that quietly never fires. `Fact` is a closed enum, so
/// serde already refuses an unknown fact name; what serde cannot check is that
/// `reaches` parses as a version, and an unparseable one would make
/// [`satisfied`] answer `false` forever — a row that reads as watched while
/// nothing watches it.
///
/// # Errors
///
/// [`crate::UsageError`] naming the row and the key.
pub fn validate(deferrals: &[Deferral]) -> crate::Result<()> {
    for deferral in deferrals {
        if semver::Version::parse(&deferral.reaches).is_err() {
            return Err(crate::UsageError::raise(format!(
                "deferral {}: `reaches = \"{}\"` is not a version, so its condition could \
                 never be compared",
                deferral.issue, deferral.reaches
            )));
        }
        if deferral.reason.trim().is_empty() {
            return Err(crate::UsageError::raise(format!(
                "deferral {}: `reason` is empty, so the refusal would name no decision",
                deferral.issue
            )));
        }
    }
    Ok(())
}

/// Whether `reaches` has been met by `pin`.
///
/// Both are parsed as semver; either failing to parse is **not satisfied**,
/// which is the could-not-look direction for a gate that adds a refusal: a
/// deferral is reported only when the tree can show the condition holds.
#[must_use]
pub fn satisfied(reaches: &str, pin: &str) -> bool {
    let parse = |text: &str| {
        // `rust-version = "1.98"` is a valid manifest value and not valid
        // semver, so a missing patch is filled rather than refused.
        let filled = if text.split('.').count() == 2 {
            format!("{text}.0")
        } else {
            text.to_owned()
        };
        semver::Version::parse(&filled).ok()
    };
    match (parse(reaches), parse(pin)) {
        (Some(reaches), Some(pin)) => pin >= reaches,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_at_or_past_the_condition_satisfies_it_and_an_earlier_one_does_not() {
        // CLOUD-647's measured instance: deferred at 1.88.0, pin now 1.98.
        assert!(satisfied("1.88.0", "1.98"));
        assert!(satisfied("1.88.0", "1.88.0"));
        assert!(!satisfied("1.99.0", "1.98"));
    }

    #[test]
    fn an_unparseable_version_on_either_side_is_not_satisfied() {
        // The could-not-look direction for a gate that ADDS a refusal: report a
        // deferral only when the tree can show the condition holds. The opposite
        // reading would refuse every deferral on a manifest it could not parse.
        assert!(!satisfied("nightly", "1.98"));
        assert!(!satisfied("1.88.0", "stable"));
    }
}
