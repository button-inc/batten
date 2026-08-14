//! The severity taxonomy: three axes, one rank, one table (CLOUD-168).
//!
//! Three severity vocabularies legitimately coexist, because each owns a
//! different layer of the system. Nothing is duplicated between them and none
//! is redundant — but a reader who has not seen this table will map them by
//! name, which is wrong. The mapping is by **rank**:
//!
//! | rank   | rule (config) | tier (store) | report (render) |
//! | ------ | ------------- | ------------ | --------------- |
//! | high   | `deny`        | `warning`    | `fail`          |
//! | middle | `warn`        | `caution`    | `warn`          |
//! | low    | `allow`       | `advisory`   | `message`       |
//!
//! # The layer each axis owns
//!
//! * [`RuleSeverity`] (`deny`/`warn`/`allow`, cargo-deny's model; CLOUD-61) is
//!   **config-time rule severity**: what fails a check. Authored in
//!   `batten.toml` as each rule's **required** `severity` key — explicit per
//!   committed rule, no implicit fallback (omission is a usage error, exit
//!   `2`) — and independent of the rule's `scope` key
//!   ([`crate::rules::RuleScope`]): where a rule looks is a different axis
//!   from what a match does, and neither vocabulary deserializes as the other.
//! * [`AdvisoryTier`] (`warning`/`caution`/`advisory`; CLOUD-80) is **required
//!   response latency**: how fast an advisory must be answered. Latency is the
//!   *only* axis it keys on — any other reading of these three words is a
//!   defect in that store.
//! * [`ReportLevel`] (`fail`/`warn`/`message`, Danger's spine; CLOUD-130) is
//!   **how a finding renders**, mapped onto the exit contract: `fail` is a
//!   [`crate::ExitCode::Violation`], `warn` is non-blocking until
//!   `--fail-on-warning` promotes it (CLOUD-49), and `message` is pointer-only.
//!
//! # One stored field; everything else derived
//!
//! The findings store persists **exactly one severity field, the
//! [`AdvisoryTier`]** (CLOUD-78). The rule severity and the report level are
//! *derived* through [`row_for_tier`] at the boundary where they are needed,
//! never persisted alongside it. A second stored severity is a second source of
//! truth, and two sources drift.
//!
//! # The trap this table exists to kill
//!
//! **Rank-match, never name-match.** The vocabularies share the token `warn`
//! and near-share `warning`, and those are *not* the same rank:
//!
//! * config `warn` maps to tier **`caution`** — not tier `warning`;
//! * tier `warning` maps to config **`deny`** — not config `warn`.
//!
//! [`tests::the_name_collision_trap_is_pinned`] holds that shut, and
//! [`tests::cross_axis_token_is_rejected`] holds it shut one layer lower: a
//! token from one axis does not deserialize as another axis's type, so the
//! confusion cannot even be *expressed* in config or in the store.
//!
//! # Why the mapping is forced rather than chosen
//!
//! CLOUD-130 pins both endpoints (a blocking `fail` is the `deny` rank; a
//! pointer-only `message` is the advisory rank), and the tiers are ordered by
//! required response latency. A total, order-preserving map between three
//! three-valued ordered sets with both endpoints pinned is unique — so this
//! table is the only coherent mapping, not a preference.
//!
//! # Rank is declaration order
//!
//! Each enum declares its variants **weakest-first**, so the derived [`Ord`] is
//! the severity rank itself and no separate rank field can drift from it.
//! [`tests::table_ranks_agree_across_all_three_axes`] pins that the three
//! orderings and the table agree, so a reordering cannot silently re-map the
//! taxonomy.
//!
//! # Closed enums, deliberately
//!
//! Unlike [`crate::config::Strictness`] and [`crate::rules::RuleKind`], these
//! three are **not** `#[non_exhaustive]`. Their contract is a total bijection
//! across three axes, so a fourth rank is not an additive variant — it is a
//! redesign of the taxonomy that must break every consumer's match. Keeping
//! them closed makes the compiler say so. Do not "fix" this to match the other
//! enums.
//!
//! # The one promotion point
//!
//! [`promote`] is the **only** place `fail_on_warning` (CLOUD-49) touches this
//! taxonomy: it lifts the middle rank's [`ReportLevel::Warn`] to the blocking
//! [`ReportLevel::Fail`] and leaves the other two ranks alone. The setting is
//! resolved once through the §8 precedence chain
//! ([`crate::resolve::Resolved::fail_on_warning`]) and every consumer reads that
//! resolved value; nothing re-declares a promotion knob of its own.
//!
//! **`batten exec` is deliberately not a consumer** (CLOUD-117). An exec output
//! match always fails, because a warn-but-pass match would be invisible to an
//! agent whose only actionable surface is the exit code — reproducing the exact
//! false-green `exec` exists to catch. That is structural rather than a promise:
//! `exec` does not call this function, and there is no exec-local knob to add.
//!
//! # Not an identity input
//!
//! Severity is deliberately excluded from every finding-identity tuple (see
//! [`crate::identity`]): re-rating a finding's severity must never re-mint its
//! identity. Nothing in this module may feed a fingerprint preimage.
//!
//! # Deferred invariants (owned elsewhere, named here)
//!
//! Two invariants belong to this taxonomy but are only testable once the
//! machinery that could violate them exists. They land with that machinery, in
//! its issue, asserted against this table:
//!
//! * **A duplicate-occurrence count never escalates a tier** — CLOUD-80's
//!   no-escalation law. Lands with the findings store (CLOUD-78).
//! * **Baseline count drift may invalidate a baseline entry but never moves a
//!   tier.** Landed with the `baseline` command (CLOUD-67), and structural
//!   rather than asserted-and-hoped: [`crate::baseline::apply`] only ever
//!   *removes* elements from the finding vector and never constructs or mutates
//!   one, so a re-raised finding carries the severity its rule declared and
//!   resolves through this table unchanged. There is no code path there that
//!   could move a tier. `baseline_count_drift_never_moves_a_tier` in
//!   `tests/baseline.rs` pins it over the compiled binary anyway, because
//!   "structural" is a claim about today's code.
//!
//! # Sources (public prior art)
//!
//! cargo-deny's `deny`/`warn`/`allow` severity model; Danger's
//! `fail`/`warn`/`message` graduated model over git state; Alertmanager's
//! `repeat_interval` as the precedent for keying a tier on response latency.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Config-time rule severity — *what fails a check* (cargo-deny's model,
/// CLOUD-61).
///
/// Declared weakest-first: derived [`Ord`] is the severity rank.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RuleSeverity {
    /// The rule is configured off: a match is not a finding at all.
    Allow,
    /// A match is reported but does not by itself fail the run (it can be
    /// promoted by `--fail-on-warning`, CLOUD-49).
    Warn,
    /// A match fails the run.
    Deny,
}

impl RuleSeverity {
    /// Every severity, weakest-first, so the [`TABLE`] coverage test is total.
    ///
    /// A new variant must be added here or
    /// [`tests::table_covers_every_variant_exactly_once`] fails.
    pub const ALL: &'static [RuleSeverity] =
        &[RuleSeverity::Allow, RuleSeverity::Warn, RuleSeverity::Deny];

    /// The stable lowercase token used in config and machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RuleSeverity::Allow => "allow",
            RuleSeverity::Warn => "warn",
            RuleSeverity::Deny => "deny",
        }
    }
}

/// Advisory severity as **required response latency** — *how fast it must be
/// answered* (CLOUD-80).
///
/// This is the one severity field the findings store persists (CLOUD-78);
/// [`RuleSeverity`] and [`ReportLevel`] are derived from it through [`TABLE`].
/// Declared weakest-first (longest permitted latency first): derived [`Ord`] is
/// the severity rank.
///
/// `JsonSchema` because CLOUD-56 made it a *config* vocabulary as well as a
/// stored one: a `judge` row declares `tier` where every other kind declares
/// `severity`, so the published schema has to describe it or an editor would
/// flag the one column that kind cannot do without.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryTier {
    /// Answer eventually: no bounded response deadline.
    Advisory,
    /// Answer soon: a bounded deadline, but the session need not stop.
    Caution,
    /// Answer now: the response is due before the work continues.
    Warning,
}

impl AdvisoryTier {
    /// Every tier, weakest-first, so the [`TABLE`] coverage test is total.
    pub const ALL: &'static [AdvisoryTier] = &[
        AdvisoryTier::Advisory,
        AdvisoryTier::Caution,
        AdvisoryTier::Warning,
    ];

    /// The stable lowercase token used in the store and machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            AdvisoryTier::Advisory => "advisory",
            AdvisoryTier::Caution => "caution",
            AdvisoryTier::Warning => "warning",
        }
    }
}

/// Reporting level — *how a finding renders* (Danger's spine, CLOUD-130).
///
/// Declared weakest-first: derived [`Ord`] is the severity rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportLevel {
    /// Informational: emitted as a pointer, never blocking.
    Message,
    /// Reported with a warning marker; non-blocking until `--fail-on-warning`
    /// promotes it (CLOUD-49).
    Warn,
    /// Blocking: the run exits [`crate::ExitCode::Violation`].
    Fail,
}

impl ReportLevel {
    /// Every level, weakest-first, so the [`TABLE`] coverage test is total.
    pub const ALL: &'static [ReportLevel] =
        &[ReportLevel::Message, ReportLevel::Warn, ReportLevel::Fail];

    /// The stable lowercase token used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            ReportLevel::Message => "message",
            ReportLevel::Warn => "warn",
            ReportLevel::Fail => "fail",
        }
    }
}

/// One rank of the taxonomy: the three axes' values that mean the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The config-time rule severity at this rank.
    pub rule: RuleSeverity,
    /// The advisory latency tier at this rank — the stored axis.
    pub tier: AdvisoryTier,
    /// The reporting level at this rank.
    pub report: ReportLevel,
}

/// The taxonomy as data: one row per rank, weakest-first, matching each enum's
/// own declaration order.
///
/// This is the single source the three lookups read; the drain policy's
/// repeat-interval table (CLOUD-79) reads its tiers from here too, rather than
/// restating them.
pub const TABLE: [Mapping; 3] = [
    Mapping {
        rule: RuleSeverity::Allow,
        tier: AdvisoryTier::Advisory,
        report: ReportLevel::Message,
    },
    Mapping {
        rule: RuleSeverity::Warn,
        tier: AdvisoryTier::Caution,
        report: ReportLevel::Warn,
    },
    Mapping {
        rule: RuleSeverity::Deny,
        tier: AdvisoryTier::Warning,
        report: ReportLevel::Fail,
    },
];

/// The row for a config-time rule severity.
///
/// Total by construction: an exhaustive match into [`TABLE`], so there is no
/// "not found" arm to guess at and no reachable panic.
/// [`tests::lookups_agree_with_the_table`] pins the indices against the table
/// itself, so a reordered table cannot leave a stale index behind.
#[must_use]
pub const fn row_for_rule(rule: RuleSeverity) -> Mapping {
    match rule {
        RuleSeverity::Allow => TABLE[0],
        RuleSeverity::Warn => TABLE[1],
        RuleSeverity::Deny => TABLE[2],
    }
}

/// The row for an advisory latency tier — the stored axis, and so the lookup
/// through which the other two are derived.
#[must_use]
pub const fn row_for_tier(tier: AdvisoryTier) -> Mapping {
    match tier {
        AdvisoryTier::Advisory => TABLE[0],
        AdvisoryTier::Caution => TABLE[1],
        AdvisoryTier::Warning => TABLE[2],
    }
}

/// The row for a reporting level.
#[must_use]
pub const fn row_for_report(report: ReportLevel) -> Mapping {
    match report {
        ReportLevel::Message => TABLE[0],
        ReportLevel::Warn => TABLE[1],
        ReportLevel::Fail => TABLE[2],
    }
}

/// Apply the resolved `fail_on_warning` setting to a reporting level (CLOUD-49).
///
/// The middle rank — [`ReportLevel::Warn`], which renders and does not block —
/// becomes the blocking [`ReportLevel::Fail`] when the setting is on. The other
/// two ranks are returned unchanged, and that is where two of this issue's
/// acceptance clauses come from rather than from a branch of their own:
///
/// * [`ReportLevel::Message`] is never promoted, so a pointer-only finding stays
///   pointer-only however the setting is resolved;
/// * [`ReportLevel::Fail`] passes through, so no already-blocking finding has to
///   be present for a promotion to happen.
///
/// The result is idempotent and never lowers a rank —
/// [`tests::promotion_only_lifts_the_middle_rank`] pins both, so the setting can
/// never weaken a gate on the way to the exit contract.
///
/// See the module docs for why `batten exec` does not call this.
#[must_use]
pub const fn promote(report: ReportLevel, fail_on_warning: bool) -> ReportLevel {
    match report {
        ReportLevel::Warn if fail_on_warning => ReportLevel::Fail,
        other => other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn table_covers_every_variant_exactly_once() {
        // Totality and bijectivity: the adapter can convert any value of any
        // axis, and no rank is reachable by two different values of one axis.
        assert_eq!(TABLE.len(), RuleSeverity::ALL.len());
        assert_eq!(TABLE.len(), AdvisoryTier::ALL.len());
        assert_eq!(TABLE.len(), ReportLevel::ALL.len());

        for &rule in RuleSeverity::ALL {
            let hits = TABLE.iter().filter(|row| row.rule == rule).count();
            assert_eq!(hits, 1, "{} appears {hits} times", rule.as_str());
        }
        for &tier in AdvisoryTier::ALL {
            let hits = TABLE.iter().filter(|row| row.tier == tier).count();
            assert_eq!(hits, 1, "{} appears {hits} times", tier.as_str());
        }
        for &report in ReportLevel::ALL {
            let hits = TABLE.iter().filter(|row| row.report == report).count();
            assert_eq!(hits, 1, "{} appears {hits} times", report.as_str());
        }
    }

    #[test]
    fn lookups_agree_with_the_table() {
        // The lookups match into TABLE by literal index. This is what makes
        // that safe: reorder the table without reordering a match and the row
        // a lookup returns stops being its own row.
        for row in &TABLE {
            assert_eq!(row_for_rule(row.rule), *row);
            assert_eq!(row_for_tier(row.tier), *row);
            assert_eq!(row_for_report(row.report), *row);
        }
    }

    #[test]
    fn every_documented_pair_round_trips() {
        // CLOUD-168's v1 acceptance: the adapter round-trips every documented
        // pair. All six directed conversions between the three axes compose to
        // identity, over every variant of every axis.
        for &rule in RuleSeverity::ALL {
            let row = row_for_rule(rule);
            assert_eq!(row_for_tier(row.tier).rule, rule);
            assert_eq!(row_for_report(row.report).rule, rule);
        }
        for &tier in AdvisoryTier::ALL {
            let row = row_for_tier(tier);
            assert_eq!(row_for_rule(row.rule).tier, tier);
            assert_eq!(row_for_report(row.report).tier, tier);
        }
        for &report in ReportLevel::ALL {
            let row = row_for_report(report);
            assert_eq!(row_for_rule(row.rule).report, report);
            assert_eq!(row_for_tier(row.tier).report, report);
        }
    }

    #[test]
    fn table_ranks_agree_across_all_three_axes() {
        // Rank is declaration order on all three enums, and the table is
        // ordered by that same rank. A reordering of any one enum, or of the
        // table, breaks the agreement here rather than silently re-mapping the
        // taxonomy.
        for pair in TABLE.windows(2) {
            let (lower, higher) = (pair[0], pair[1]);
            assert!(lower.rule < higher.rule);
            assert!(lower.tier < higher.tier);
            assert!(lower.report < higher.report);
        }

        // The ALL consts carry the same weakest-first order as the table.
        let rules: Vec<RuleSeverity> = TABLE.iter().map(|row| row.rule).collect();
        let tiers: Vec<AdvisoryTier> = TABLE.iter().map(|row| row.tier).collect();
        let reports: Vec<ReportLevel> = TABLE.iter().map(|row| row.report).collect();
        assert_eq!(rules, RuleSeverity::ALL);
        assert_eq!(tiers, AdvisoryTier::ALL);
        assert_eq!(reports, ReportLevel::ALL);
    }

    #[test]
    fn vocabulary_is_byte_stable() {
        // The documented tokens, asserted as literals: this is the vocabulary
        // config files and stored records are written in, so it is a
        // compatibility surface, not an implementation detail (§6).
        assert_eq!(
            TABLE.map(|row| row.rule.as_str()),
            ["allow", "warn", "deny"]
        );
        assert_eq!(
            TABLE.map(|row| row.tier.as_str()),
            ["advisory", "caution", "warning"]
        );
        assert_eq!(
            TABLE.map(|row| row.report.as_str()),
            ["message", "warn", "fail"]
        );

        // Serde and `as_str` are one vocabulary, not two that happen to agree
        // today — and every token parses back to the variant it came from.
        for &rule in RuleSeverity::ALL {
            let json = serde_json::to_string(&rule).unwrap();
            assert_eq!(json, format!("\"{}\"", rule.as_str()));
            assert_eq!(serde_json::from_str::<RuleSeverity>(&json).unwrap(), rule);
        }
        for &tier in AdvisoryTier::ALL {
            let json = serde_json::to_string(&tier).unwrap();
            assert_eq!(json, format!("\"{}\"", tier.as_str()));
            assert_eq!(serde_json::from_str::<AdvisoryTier>(&json).unwrap(), tier);
        }
        for &report in ReportLevel::ALL {
            let json = serde_json::to_string(&report).unwrap();
            assert_eq!(json, format!("\"{}\"", report.as_str()));
            assert_eq!(serde_json::from_str::<ReportLevel>(&json).unwrap(), report);
        }
    }

    /// A TOML document is a table, so the axes round-trip inside one rather
    /// than as bare values.
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    struct Doc {
        rule: RuleSeverity,
        tier: AdvisoryTier,
        report: ReportLevel,
    }

    #[test]
    fn severity_round_trips_through_toml() {
        let text = "rule = \"warn\"\ntier = \"caution\"\nreport = \"warn\"\n";
        let doc: Doc = toml::from_str(text).unwrap();
        assert_eq!(
            doc,
            Doc {
                rule: RuleSeverity::Warn,
                tier: AdvisoryTier::Caution,
                report: ReportLevel::Warn,
            }
        );
        assert_eq!(toml::to_string(&doc).unwrap(), text);
    }

    #[test]
    fn the_name_collision_trap_is_pinned() {
        // The whole reason this table exists. The axes share the token `warn`
        // and near-share `warning`, and those are different ranks: mapping by
        // name silently mis-rates a finding by one whole rank in both
        // directions. Rank-match, never name-match.
        assert_eq!(row_for_rule(RuleSeverity::Warn).tier, AdvisoryTier::Caution);
        assert_eq!(row_for_tier(AdvisoryTier::Warning).rule, RuleSeverity::Deny);

        // The same trap on the reporting axis: report `warn` is the middle
        // rank, so it is tier `caution`, not tier `warning`.
        assert_eq!(
            row_for_report(ReportLevel::Warn).tier,
            AdvisoryTier::Caution
        );
        assert_eq!(
            row_for_tier(AdvisoryTier::Warning).report,
            ReportLevel::Fail
        );
    }

    #[test]
    fn promotion_is_the_identity_when_the_setting_is_off() {
        // The default (CLOUD-49): nothing moves, so a `warn` finding reports and
        // exits clean exactly as it did before the setting existed.
        for &report in ReportLevel::ALL {
            assert_eq!(promote(report, false), report);
        }
    }

    #[test]
    fn promotion_only_lifts_the_middle_rank() {
        // Totality over the axis, both settings, asserted against the ranks
        // themselves rather than a second table that could drift from TABLE.
        assert_eq!(promote(ReportLevel::Message, true), ReportLevel::Message);
        assert_eq!(promote(ReportLevel::Warn, true), ReportLevel::Fail);
        assert_eq!(promote(ReportLevel::Fail, true), ReportLevel::Fail);

        for &report in ReportLevel::ALL {
            for on in [false, true] {
                let promoted = promote(report, on);
                // Raise-only at the severity layer too: a promotion may lift a
                // rank, never lower one. A weakening here would let the setting
                // turn a `deny` finding into a passing run.
                assert!(promoted >= report, "{} was lowered", report.as_str());
                // Idempotent: promoting an already-promoted level is a no-op, so
                // a value that passes through twice cannot climb a second rank.
                assert_eq!(promote(promoted, on), promoted);
            }
        }
    }

    #[test]
    fn the_promoted_rank_is_the_one_a_deny_already_reaches() {
        // A promoted `warn` is not a new fourth outcome: it lands on exactly the
        // rank a committed `deny` rule already produces, which is what makes the
        // exit code the same verdict rather than a parallel one (§7).
        assert_eq!(
            promote(row_for_rule(RuleSeverity::Warn).report, true),
            row_for_rule(RuleSeverity::Deny).report
        );
        // …and the low rank is untouched by the setting, so an `allow` rule's
        // rank cannot be promoted into a gate.
        assert_eq!(
            promote(row_for_rule(RuleSeverity::Allow).report, true),
            row_for_rule(RuleSeverity::Allow).report
        );
    }

    #[test]
    fn cross_axis_token_is_rejected() {
        // One layer below the trap above: an axis's vocabulary does not leak
        // into another axis's type, so a config or stored record cannot even
        // express the confusion. Each token is rejected by the axes that do
        // not own it.
        assert!(serde_json::from_str::<RuleSeverity>("\"warning\"").is_err());
        assert!(serde_json::from_str::<RuleSeverity>("\"message\"").is_err());
        assert!(serde_json::from_str::<AdvisoryTier>("\"deny\"").is_err());
        assert!(serde_json::from_str::<AdvisoryTier>("\"fail\"").is_err());
        assert!(serde_json::from_str::<ReportLevel>("\"deny\"").is_err());
        assert!(serde_json::from_str::<ReportLevel>("\"advisory\"").is_err());

        // `warn` is the one token two axes genuinely share — and at the same
        // rank, which is why it is not a collision.
        assert_eq!(
            serde_json::from_str::<RuleSeverity>("\"warn\"").unwrap(),
            RuleSeverity::Warn
        );
        assert_eq!(
            serde_json::from_str::<ReportLevel>("\"warn\"").unwrap(),
            ReportLevel::Warn
        );
        assert!(serde_json::from_str::<AdvisoryTier>("\"warn\"").is_err());
    }
}
