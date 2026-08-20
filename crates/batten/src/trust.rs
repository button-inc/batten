//! Config trust: judge by a base ref, and name what the working tree weakened
//! (house-style §8, CLOUD-31).
//!
//! A pull request that edits `batten.toml` would otherwise relax the rules it is
//! judged by. `--config-from <ref>` closes that: the committed authority is read
//! from a git ref the branch cannot edit, so policy loads **out of band** of the
//! change being reviewed.
//!
//! Precedence is unchanged (§8). The ref-loaded file simply *is* the committed
//! authority for the run; env, flag and `batten.local.toml` overrides still
//! stack on top under the same raise-only clamp. No second config surface is
//! introduced — there is one `batten.toml`, read from a different place.
//!
//! # Two jobs, deliberately separate
//!
//! * **Judging** by the base config is what makes the gate un-loweable, and it
//!   is the exit code's business.
//! * **Naming** the weakening is what makes it reviewable by a human, and it is
//!   pointer-only output. It does not change the exit code here; the predicate
//!   that turns a weakening into a violation on its own is `config lint`
//!   (CLOUD-87), which reuses [`load_base`] rather than growing a second
//!   trusted-load path.
//!
//! # What counts as weakening
//!
//! The same monotonicity §8's raise-only clamp is defined over: a change is
//! *weakening* when it lowers the bar. Adding a protected path, raising
//! strictness, or turning promotion on are all tightening and are not reported.
//! Narrowing `scope` is likewise **not** weakening — §8 names "narrow scope"
//! among the tightening moves, because a smaller scope polices less but forgives
//! nothing inside what remains.
//!
//! **Weakening is not the same as removal, and a waiver is where the two part.**
//! Every comparison here used to run in one direction — present in the base,
//! absent or rank-lowered in the working tree — because for `protected`,
//! `unlanded` and `rule` alike, more entries meant a higher bar. A `[[waiver]]`
//! (CLOUD-208) is the first config entity whose *presence* lowers it: adding one
//! switches a gate off for what it covers. So [`added_entries`] exists beside
//! [`removed_entries`], and "which direction is weakening" is a property of the
//! key rather than of this module. Adding a `protected` path is still clean;
//! adding a waiver is not.
//!
//! # Coverage is a census, not a habit (CLOUD-721)
//!
//! This comparison once covered six keys of a twenty-eight-key struct, and
//! nothing noticed: `hk` re-runs `config-lint` on a diff touching *this* file
//! and never on one that grows `config.rs` a key, so every key landed since
//! CLOUD-31 arrived with no prompt to ask whether it has a weakening direction.
//! For `check` that only under-reports; for `config lint` the weakening list
//! **is** the verdict, so an uncovered key is a weakening that gate cannot see.
//!
//! [`CENSUS`] closes it as a mechanism rather than a longer list. Its field list
//! is read off [`Config`]'s own source, so a field added to the struct fails the
//! census until somebody records one of three answers — compared, no monotone
//! reading, or not policy-bearing — with the reason beside the last two. Silence
//! is not one of the three, which is what the first version of this module let
//! it be.
//!
//! Every comparison is key-local and order-independent, so the report is a
//! deterministic function of the two configs and nothing else.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;

use crate::config::{self, Config, Strictness};
use crate::git;
use crate::rules::Rule;
use crate::severity::RuleSeverity;
use crate::waiver;

/// Load the committed authority from a git ref instead of the working tree.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the ref is unknown, the
/// config is absent at that ref, or it fails to parse — every one a statement
/// about the *invocation*, never a policy verdict.
pub fn load_base(dir: &Path, reference: &str) -> Result<Config> {
    let text = git::show(dir, reference, config::CONFIG_FILE)?;
    config::parse(&text, &format!("{reference}:{}", config::CONFIG_FILE))
}

/// What kind of weakening a [`Weakening`] is, as a stable identifier.
///
/// The id is the *name* a report keys on, so it is declared once here rather
/// than reconstructed from the key path's shape — parsing `rule[x].severity`
/// back into a category would make the identifier depend on formatting.
/// `config lint` (CLOUD-87) emits these as its base-ref smell ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeakeningKind {
    /// The effective `strictness` floor dropped.
    StrictnessLowered,
    /// A committed `fail_on_warning = true` was turned off.
    PromotionDisabled,
    /// A `protected` entry is gone.
    ProtectedRemoved,
    /// An `unlanded` entry is gone.
    UnlandedRemoved,
    /// A whole rule is gone.
    RuleRemoved,
    /// A rule survives at a lower severity rank.
    SeverityLowered,
    /// A waiver the base did not carry (CLOUD-208) — the one *added*-direction
    /// weakening, because a waiver suppresses findings the base ref would report.
    ///
    /// Reported whether or not it has expired: a lapsed waiver suppresses nothing
    /// today and the pointer would then depend on the date the comparison ran,
    /// which §6 forbids. The expiry is what the *run* evaluates; whether the diff
    /// added a suppression is a property of the two files alone.
    WaiverAdded,
    /// A waiver's expiry moved later, extending a suppression the base ref had
    /// bounded (CLOUD-721).
    ///
    /// The identity in [`crate::waiver::Waiver::key`] deliberately omits
    /// `expires`, so a base waiver lapsed in 2020 and a working one live until
    /// 2099 are the *same* key and [`added_entries`] sees nothing — while the
    /// second suppresses every finding of its rule and the first suppresses
    /// none. Extending a dead waiver is the canonical way to weaken a
    /// suppression, and this is the key that exists to catch it.
    ///
    /// `WaiverAdded`'s note about dates does not reach this: that one is about
    /// judging one waiver against *today*, where a clock would make the pointer
    /// depend on the run's date. This compares one file's `expires` against the
    /// other's, which is date-independent and byte-stable.
    WaiverExpiryExtended,
    /// A rule's predicate changed while its id and severity stayed put — a glob
    /// narrowed, a pattern rewritten, an exclusion added.
    ///
    /// Reported as a *change*, never as a ranking: whether one glob is narrower
    /// than another is a judgement this module refuses to make, but that the
    /// predicate moved at all is a byte comparison. A glob narrowed to match
    /// nothing is the case that used to survive silently.
    RulePredicateChanged,
    /// The `min_batten_version` floor dropped, or stopped being declared —
    /// admitting a binary that does not understand the rules (CLOUD-33).
    MinVersionLowered,
    /// A path is gone from `epoch.tracked`, so the `config_epoch` attributes
    /// less than it did (CLOUD-32).
    EpochPathRemoved,
    /// A `[[verb]]` row is gone, so a mutating tool call is no longer mediated
    /// at the `PreToolUse` boundary (CLOUD-36).
    VerbRemoved,
    /// An agent-sourced fact's declared command changed (CLOUD-776).
    ///
    /// The one weakening on this table whose payoff is a FORGED FACT rather than
    /// a skipped gate. The declared command is read twice — it is what the deny
    /// asks the agent to run, and what the stored record is verified against — so
    /// a branch that rewrites it to something trivial makes the gate ask for that
    /// trivial thing, accept its output, and pass. Compared as a byte change for
    /// the reason `RulePredicateChanged` is: there is no ranking of two commands,
    /// only "this is not what the trusted file said".
    FactCommandChanged,
    /// An agent-sourced fact was removed (CLOUD-776).
    ///
    /// Reported for completeness rather than danger: a `receipt` row naming a
    /// fact nobody declares can never be satisfied, so the removal TIGHTENS. It
    /// is on the table because a reader comparing two configs should see the row
    /// vanish rather than infer it, and because "tightening" is a judgement the
    /// census should state rather than assume.
    FactRemoved,
    /// A `[[marker]]` row is gone, so its suppressions stop being counted.
    MarkerRemoved,
    /// An `[[exec_pattern]]` row is gone, so a lying exit `0` carrying it stops
    /// being promoted (CLOUD-117).
    ExecPatternRemoved,
    /// A `[[provision]]` row is gone, so a pinned tool stops being verified.
    ProvisionRemoved,
    /// A required check is gone from the `[ci]` projection (CLOUD-54).
    CiMergeCheckRemoved,
    /// The merge-method constraint admits a method it did not, or stopped
    /// constraining methods at all.
    CiMergeMethodAdded,
    /// A pattern is gone from one of `[attribution]`'s deny lists, so a
    /// spelling it refused is admitted again (CLOUD-274).
    AttributionDenyRemoved,
    /// A pattern arrived in `attribution.trailer_allow`, widening the carve-out
    /// from the trailer deny list.
    AttributionAllowAdded,
    /// The `[defects]` table is gone, so the append-only ledger gate is no
    /// longer active (CLOUD-52).
    DefectsLedgerRemoved,
    /// A class arrived in `defects.classes`, so a record the ledger refused is
    /// admitted.
    DefectsClassAdded,
    /// The transcript path is gone, so `check` stops reading the completed
    /// session it judged against (CLOUD-95).
    TranscriptPathRemoved,
    /// A `[budget.<name>]` table is gone, so nothing is counted for it
    /// (CLOUD-50).
    BudgetSetRemoved,
    /// A counted file glob is gone from a budget set.
    BudgetFileRemoved,
    /// An `[[budget.<name>.embedded]]` declaration is gone, so a string a host
    /// always loads stops being counted (CLOUD-298).
    BudgetEmbeddedRemoved,
    /// A ceiling rose, or stopped being declared. For a budget smaller is
    /// stricter, so §8's "may not weaken" reads as "may not raise" — the
    /// direction inverts, exactly as `design::effective_cap` says.
    BudgetLimitRaised,
    /// `must_land_on` is gone, so `worktree status` has no target to judge work
    /// against (CLOUD-51).
    MustLandOnRemoved,
    /// The worktree pileup threshold rose, or stopped being declared. The
    /// verdict is `count >= threshold`, so a higher number tolerates more
    /// (CLOUD-46).
    PileupThresholdRaised,
    /// A content class arrived in `judge.raw`, so bytes that could not cross
    /// into a model call now can (CLOUD-135).
    JudgeRawClassAdded,
    /// The assembled-payload ceiling rose, so more bytes may cross.
    JudgePayloadLimitRaised,
    /// The per-capture byte ceiling rose, so a larger capture stops being worth
    /// a second look (CLOUD-53).
    DesignCaptureLimitRaised,
}

impl WeakeningKind {
    /// Every kind, so anything ranging over the vocabulary is derived rather
    /// than re-typed — the idiom [`crate::effect::Effect::ALL`] and
    /// [`crate::outputs::Watched::ALL`] already use.
    ///
    /// [`CENSUS`] reads this: a kind added here without a field claiming it, or
    /// claimed by two fields, fails the census rather than sitting unattributed.
    pub const ALL: &'static [WeakeningKind] = &[
        WeakeningKind::StrictnessLowered,
        WeakeningKind::PromotionDisabled,
        WeakeningKind::ProtectedRemoved,
        WeakeningKind::UnlandedRemoved,
        WeakeningKind::RuleRemoved,
        WeakeningKind::SeverityLowered,
        WeakeningKind::WaiverAdded,
        WeakeningKind::WaiverExpiryExtended,
        WeakeningKind::RulePredicateChanged,
        WeakeningKind::MinVersionLowered,
        WeakeningKind::EpochPathRemoved,
        WeakeningKind::VerbRemoved,
        WeakeningKind::FactCommandChanged,
        WeakeningKind::FactRemoved,
        WeakeningKind::MarkerRemoved,
        WeakeningKind::ExecPatternRemoved,
        WeakeningKind::ProvisionRemoved,
        WeakeningKind::CiMergeCheckRemoved,
        WeakeningKind::CiMergeMethodAdded,
        WeakeningKind::AttributionDenyRemoved,
        WeakeningKind::AttributionAllowAdded,
        WeakeningKind::DefectsLedgerRemoved,
        WeakeningKind::DefectsClassAdded,
        WeakeningKind::TranscriptPathRemoved,
        WeakeningKind::BudgetSetRemoved,
        WeakeningKind::BudgetFileRemoved,
        WeakeningKind::BudgetEmbeddedRemoved,
        WeakeningKind::BudgetLimitRaised,
        WeakeningKind::MustLandOnRemoved,
        WeakeningKind::PileupThresholdRaised,
        WeakeningKind::JudgeRawClassAdded,
        WeakeningKind::JudgePayloadLimitRaised,
        WeakeningKind::DesignCaptureLimitRaised,
    ];

    /// The stable, lowercase identifier used in machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            WeakeningKind::StrictnessLowered => "strictness-lowered",
            WeakeningKind::PromotionDisabled => "promotion-disabled",
            WeakeningKind::ProtectedRemoved => "protected-removed",
            WeakeningKind::UnlandedRemoved => "unlanded-removed",
            WeakeningKind::RuleRemoved => "rule-removed",
            WeakeningKind::SeverityLowered => "severity-lowered",
            WeakeningKind::WaiverAdded => "waiver-added",
            WeakeningKind::WaiverExpiryExtended => "waiver-expiry-extended",
            WeakeningKind::RulePredicateChanged => "rule-predicate-changed",
            WeakeningKind::MinVersionLowered => "min-version-lowered",
            WeakeningKind::EpochPathRemoved => "epoch-path-removed",
            WeakeningKind::VerbRemoved => "verb-removed",
            WeakeningKind::FactCommandChanged => "fact-command-changed",
            WeakeningKind::FactRemoved => "fact-removed",
            WeakeningKind::MarkerRemoved => "marker-removed",
            WeakeningKind::ExecPatternRemoved => "exec-pattern-removed",
            WeakeningKind::ProvisionRemoved => "provision-removed",
            WeakeningKind::CiMergeCheckRemoved => "ci-merge-check-removed",
            WeakeningKind::CiMergeMethodAdded => "ci-merge-method-added",
            WeakeningKind::AttributionDenyRemoved => "attribution-deny-removed",
            WeakeningKind::AttributionAllowAdded => "attribution-allow-added",
            WeakeningKind::DefectsLedgerRemoved => "defects-ledger-removed",
            WeakeningKind::DefectsClassAdded => "defects-class-added",
            WeakeningKind::TranscriptPathRemoved => "transcript-path-removed",
            WeakeningKind::BudgetSetRemoved => "budget-set-removed",
            WeakeningKind::BudgetFileRemoved => "budget-file-removed",
            WeakeningKind::BudgetEmbeddedRemoved => "budget-embedded-removed",
            WeakeningKind::BudgetLimitRaised => "budget-limit-raised",
            WeakeningKind::MustLandOnRemoved => "must-land-on-removed",
            WeakeningKind::PileupThresholdRaised => "pileup-threshold-raised",
            WeakeningKind::JudgeRawClassAdded => "judge-raw-class-added",
            WeakeningKind::JudgePayloadLimitRaised => "judge-payload-limit-raised",
            WeakeningKind::DesignCaptureLimitRaised => "design-capture-limit-raised",
        }
    }
}

/// What [`weakenings`] does about one [`Config`] field.
///
/// Three answers and no fourth, because the fourth is silence — and silence is
/// what let this comparison fall to six keys of a twenty-eight-key struct
/// without anything noticing (CLOUD-721). A field is either compared, or it has
/// no monotone reading, or it is not policy-bearing; the last two carry their
/// reason here so the next person reads it instead of re-deriving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Coverage {
    /// Compared, by exactly these kinds. Each kind belongs to one field.
    Compared(&'static [WeakeningKind]),
    /// Policy-bearing, but neither direction lowers a bar — with the reason.
    NoMonotoneReading(&'static str),
    /// Not policy-bearing at all: no reading of the key sets a bar to lower.
    NotPolicyBearing(&'static str),
}

/// One [`Config`] field and what this module does about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldCoverage {
    /// The field's name in [`Config`], exactly as the struct spells it.
    pub field: &'static str,
    /// The verdict.
    pub coverage: Coverage,
}

/// The verdict for every [`Config`] field, as data.
///
/// **Not the source of the field list** — that is [`Config`] itself, read from
/// its own source by [`tests::every_config_field_carries_a_verdict`]. This table
/// only says what happens to each one, so a field added to the struct fails the
/// census until somebody decides. A hand-kept list of *fields* would drift on the
/// next key added, which is the defect rather than a second copy of it.
pub const CENSUS: &[FieldCoverage] = &[
    FieldCoverage {
        field: "version",
        coverage: Coverage::NotPolicyBearing(
            "the schema version this build understands. A file declaring another one is \
             refused at parse rather than partially interpreted, so no value of it lowers \
             a bar",
        ),
    },
    FieldCoverage {
        field: "min_batten_version",
        coverage: Coverage::Compared(&[WeakeningKind::MinVersionLowered]),
    },
    FieldCoverage {
        field: "strictness",
        coverage: Coverage::Compared(&[WeakeningKind::StrictnessLowered]),
    },
    FieldCoverage {
        field: "fail_on_warning",
        coverage: Coverage::Compared(&[WeakeningKind::PromotionDisabled]),
    },
    FieldCoverage {
        field: "rules",
        coverage: Coverage::Compared(&[
            WeakeningKind::RuleRemoved,
            WeakeningKind::SeverityLowered,
            WeakeningKind::RulePredicateChanged,
        ]),
    },
    FieldCoverage {
        field: "scope",
        coverage: Coverage::NoMonotoneReading(
            "§8 lists narrowing scope among the TIGHTENING moves — a smaller scope polices \
             less but forgives nothing inside what remains — and widening it polices more. \
             Neither direction lowers a bar",
        ),
    },
    FieldCoverage {
        field: "protected",
        coverage: Coverage::Compared(&[WeakeningKind::ProtectedRemoved]),
    },
    FieldCoverage {
        field: "unlanded",
        coverage: Coverage::Compared(&[WeakeningKind::UnlandedRemoved]),
    },
    FieldCoverage {
        field: "epoch",
        coverage: Coverage::Compared(&[WeakeningKind::EpochPathRemoved]),
    },
    FieldCoverage {
        field: "verbs",
        coverage: Coverage::Compared(&[WeakeningKind::VerbRemoved]),
    },
    FieldCoverage {
        field: "facts",
        coverage: Coverage::Compared(&[
            WeakeningKind::FactCommandChanged,
            WeakeningKind::FactRemoved,
        ]),
    },
    FieldCoverage {
        field: "redirects",
        coverage: Coverage::NotPolicyBearing(
            "a redirect changes what a refusal SAYS, never whether it fires (CLOUD-280); \
             `the_protected_weakening_key_survives_the_redirect_table` asserts both \
             directions are clean",
        ),
    },
    FieldCoverage {
        field: "exec_patterns",
        coverage: Coverage::Compared(&[WeakeningKind::ExecPatternRemoved]),
    },
    FieldCoverage {
        field: "exec",
        coverage: Coverage::NoMonotoneReading(
            "dispatch shape and presentation: process-group ownership, tee, format, style, \
             jobs, continue-on-error. None of them decides whether a finding is produced or \
             what it is judged against — `exec`'s verdict is the child's own exit code plus \
             `exec_pattern`, which is compared on its own row",
        ),
    },
    FieldCoverage {
        field: "markers",
        coverage: Coverage::Compared(&[WeakeningKind::MarkerRemoved]),
    },
    FieldCoverage {
        field: "waivers",
        coverage: Coverage::Compared(&[
            WeakeningKind::WaiverAdded,
            WeakeningKind::WaiverExpiryExtended,
        ]),
    },
    FieldCoverage {
        field: "budget",
        coverage: Coverage::Compared(&[
            WeakeningKind::BudgetSetRemoved,
            WeakeningKind::BudgetFileRemoved,
            WeakeningKind::BudgetEmbeddedRemoved,
            WeakeningKind::BudgetLimitRaised,
        ]),
    },
    FieldCoverage {
        field: "must_land_on",
        coverage: Coverage::Compared(&[WeakeningKind::MustLandOnRemoved]),
    },
    FieldCoverage {
        field: "worktree",
        coverage: Coverage::Compared(&[WeakeningKind::PileupThresholdRaised]),
    },
    FieldCoverage {
        field: "hook",
        coverage: Coverage::NoMonotoneReading(
            "an action is a side effect attached to a hook event (CLOUD-91), not a bar: \
             removing one stops something running and adding one runs more, and neither \
             forgives a finding. What an action may BE is refused at load, which is where \
             that risk is decided",
        ),
    },
    FieldCoverage {
        field: "judge",
        coverage: Coverage::Compared(&[
            WeakeningKind::JudgeRawClassAdded,
            WeakeningKind::JudgePayloadLimitRaised,
        ]),
    },
    FieldCoverage {
        field: "design",
        coverage: Coverage::Compared(&[WeakeningKind::DesignCaptureLimitRaised]),
    },
    FieldCoverage {
        field: "ci",
        coverage: Coverage::Compared(&[
            WeakeningKind::CiMergeCheckRemoved,
            WeakeningKind::CiMergeMethodAdded,
        ]),
    },
    FieldCoverage {
        field: "defects",
        coverage: Coverage::Compared(&[
            WeakeningKind::DefectsLedgerRemoved,
            WeakeningKind::DefectsClassAdded,
        ]),
    },
    FieldCoverage {
        field: "provisions",
        coverage: Coverage::Compared(&[WeakeningKind::ProvisionRemoved]),
    },
    FieldCoverage {
        field: "transcript",
        coverage: Coverage::Compared(&[WeakeningKind::TranscriptPathRemoved]),
    },
    FieldCoverage {
        field: "drain",
        coverage: Coverage::NoMonotoneReading(
            "`resolve` already makes this argument for the same table: an interval has no \
             direction at all — a longer window is quieter and a shorter one is louder, and \
             neither is a weakening the raise-only clamp could measure. The caps beside it \
             pace the same emitter",
        ),
    },
    FieldCoverage {
        field: "attribution",
        coverage: Coverage::Compared(&[
            WeakeningKind::AttributionDenyRemoved,
            WeakeningKind::AttributionAllowAdded,
        ]),
    },
    FieldCoverage {
        field: "commit",
        coverage: Coverage::NoMonotoneReading(
            "one key, a subject pattern, and two regexes cannot be ranked without a \
             judgement. Its absence forgives nothing either: the gate reports an absent \
             table as exit 1, never as a clean pass over commits it had no rule to judge",
        ),
    },
];

/// One key the working tree weakened relative to the base ref.
///
/// Pointer-only by construction (non-negotiable rule 4): a key path and two
/// verdict *tokens*, never the config bytes that produced them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Weakening {
    /// The key path, as it would be addressed in `batten.toml`
    /// (`strictness`, `protected[crates/**]`, `rule[no-todo].severity`).
    pub key: String,
    /// The base ref's value, as a stable token.
    pub base: String,
    /// The working tree's value, as a stable token.
    pub working: String,
    /// Which kind of weakening this is, as a stable identifier.
    pub kind: WeakeningKind,
}

impl Weakening {
    fn new(
        kind: WeakeningKind,
        key: impl Into<String>,
        base: impl Into<String>,
        working: impl Into<String>,
    ) -> Self {
        Weakening {
            key: key.into(),
            base: base.into(),
            working: working.into(),
            kind,
        }
    }

    /// The pointer line this weakening renders as (§6), without a trailing
    /// newline: `batten.toml:<key> <base>→<working>`.
    ///
    /// The shape mirrors a finding's `path:line rule-id` — a location in a file,
    /// then the verdict — with the key path standing in for the line, because a
    /// key path *is* the pointer into a config.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{}:{} {}→{}",
            config::CONFIG_FILE,
            self.key,
            self.base,
            self.working
        )
    }
}

/// The tokens a rule severity is written as, read off the type rather than
/// re-tabulated.
fn severity_token(severity: RuleSeverity) -> &'static str {
    severity.as_str()
}

/// Every key the `working` config weakened relative to `base`, sorted.
///
/// Sorted by key so the report is byte-stable for identical input (§6) —
/// without that the drift between two runs would be ordering noise, and a
/// caller could not diff two reports.
#[must_use]
pub fn weakenings(base: &Config, working: &Config) -> Vec<Weakening> {
    let mut found = Vec::new();

    // `strictness` absent means "this file does not speak to the key", which
    // resolves to the compiled-in default — so compare effective values, not
    // Options, or removing the key would read as no change while lowering the
    // floor.
    let (base_strictness, working_strictness) = (
        base.strictness.unwrap_or_default(),
        working.strictness.unwrap_or_default(),
    );
    if working_strictness < base_strictness {
        found.push(Weakening::new(
            WeakeningKind::StrictnessLowered,
            "strictness",
            strictness_token(base_strictness),
            strictness_token(working_strictness),
        ));
    }

    // `false < true` is the ordering "tighten" is defined over for the promotion
    // setting, exactly as `resolve` clamps it.
    if base.fail_on_warning.unwrap_or(false) && !working.fail_on_warning.unwrap_or(false) {
        found.push(Weakening::new(
            WeakeningKind::PromotionDisabled,
            "fail_on_warning",
            "true",
            "false",
        ));
    }

    // A guarded path that stops being guarded is the headline case: it is how a
    // branch would make its own files editable without the gate noticing.
    found.extend(removed_entries(
        WeakeningKind::ProtectedRemoved,
        &base.protected,
        &working.protected,
        "protected",
    ));
    // Same shape: a path no longer declared unlanded stops being flagged.
    found.extend(removed_entries(
        WeakeningKind::UnlandedRemoved,
        &base.unlanded,
        &working.unlanded,
        "unlanded",
    ));
    // `scope` is deliberately absent from this list — §8 counts narrowing scope
    // as *tightening*, so a removed scope entry is not a weakening.

    found.extend(rule_weakenings(&base.rules, &working.rules));

    // The added direction (CLOUD-208). A waiver the base does not carry is a
    // suppression the branch introduced, which is the one shape where "the
    // working tree has more" means "the bar is lower". Keyed by
    // `crate::waiver::Waiver::key`, so a whole-rule waiver and a path-narrowed
    // one are distinct entries rather than one that swallows the other.
    found.extend(added_entries(
        WeakeningKind::WaiverAdded,
        &base
            .waivers
            .iter()
            .map(waiver::Waiver::key)
            .collect::<Vec<_>>(),
        &working
            .waivers
            .iter()
            .map(waiver::Waiver::key)
            .collect::<Vec<_>>(),
    ));

    // Everything below arrived with CLOUD-721, in `Config`'s own declaration
    // order. Which keys are compared at all is no longer a matter of what
    // occurred to an author: `CENSUS` records a verdict for every field and its
    // test fails on any field carrying none.
    found.extend(entry_weakenings(base, working));
    found.extend(scalar_weakenings(base, working));

    found.sort();
    found
}

/// Keys whose entries are a set: an entry gone is a gate that stops firing.
///
/// Split out of [`weakenings`] because the comparison is now over a
/// twenty-eight-key struct rather than six keys, and a function long enough to
/// scroll is one a reader checks by sampling.
fn entry_weakenings(base: &Config, working: &Config) -> Vec<Weakening> {
    let mut found = Vec::new();

    found.extend(min_version_weakening(base, working));

    // The epoch's tracked set: a path removed is a file the `config_epoch` stops
    // attributing, so a change to it stamps nothing (CLOUD-32).
    found.extend(removed_entries(
        WeakeningKind::EpochPathRemoved,
        &tracked_paths(base),
        &tracked_paths(working),
        "epoch.tracked",
    ));

    // The mutating-verb table: a removed row un-gates a tool call at the
    // `PreToolUse` boundary, which is the most consequential of these.
    found.extend(removed_entries(
        WeakeningKind::VerbRemoved,
        &verb_entries(base),
        &verb_entries(working),
        "verb",
    ));

    // The agent-sourced facts (CLOUD-776). Removal is reported and is a
    // tightening; a CHANGED command is the dangerous direction, because the same
    // string is both what the agent is told to run and what the record is checked
    // against — so rewriting it to something trivial makes the gate ask for the
    // trivial thing and then accept it.
    found.extend(removed_entries(
        WeakeningKind::FactRemoved,
        &ids(base.facts.iter().map(|fact| fact.name.clone())),
        &ids(working.facts.iter().map(|fact| fact.name.clone())),
        "fact",
    ));
    for base_fact in &base.facts {
        if let Some(working_fact) = working
            .facts
            .iter()
            .find(|candidate| candidate.name == base_fact.name)
            && working_fact.command != base_fact.command
        {
            // Pointer-only (rule 4): the fact's name and two digests, never the
            // commands — one of which is the trusted file's and one of which is
            // whatever a branch wrote.
            found.push(Weakening {
                kind: WeakeningKind::FactCommandChanged,
                key: format!("fact[{}].command", base_fact.name),
                base: column_token(&serde_json::Value::String(base_fact.command.clone())),
                working: column_token(&serde_json::Value::String(working_fact.command.clone())),
            });
        }
    }

    found.extend(removed_entries(
        WeakeningKind::MarkerRemoved,
        &ids(base.markers.iter().map(|marker| marker.id.clone())),
        &ids(working.markers.iter().map(|marker| marker.id.clone())),
        "marker",
    ));
    found.extend(removed_entries(
        WeakeningKind::ExecPatternRemoved,
        &ids(base.exec_patterns.iter().map(|row| row.id.clone())),
        &ids(working.exec_patterns.iter().map(|row| row.id.clone())),
        "exec_pattern",
    ));
    found.extend(removed_entries(
        WeakeningKind::ProvisionRemoved,
        &ids(base.provisions.iter().map(|row| row.name.clone())),
        &ids(working.provisions.iter().map(|row| row.name.clone())),
        "provision",
    ));

    found
}

/// Keys whose weakening is a threshold, a presence, or a table's own contents.
///
/// The sibling of [`entry_weakenings`], and the half where direction is the
/// subtle part: a ceiling inverts, an absent `[judge]` is the tightest setting
/// there is, and a dropped table means different things to different gates.
fn scalar_weakenings(base: &Config, working: &Config) -> Vec<Weakening> {
    let mut found = Vec::new();
    // The escape hatch's second direction (CLOUD-721): the key pairs the two
    // files, and the expiry inside it is what the pairing was blind to.
    found.extend(waiver_expiry_weakenings(&base.waivers, &working.waivers));

    found.extend(budget_weakenings(
        base.budget.as_ref(),
        working.budget.as_ref(),
    ));

    // `must_land_on` gone leaves `worktree status` with no target — exit 1, and
    // a gate that cannot judge. A *changed* ref is not compared: two trunk names
    // cannot be ranked without knowing which repository they belong to.
    if base.must_land_on.is_some() && working.must_land_on.is_none() {
        found.push(Weakening::new(
            WeakeningKind::MustLandOnRemoved,
            "must_land_on",
            "present",
            "absent",
        ));
    }

    // `count >= pileup_threshold`, so a higher number tolerates more and an
    // absent one takes the predicate out of the verdict entirely (CLOUD-46).
    found.extend(ceiling_raised(
        WeakeningKind::PileupThresholdRaised,
        "worktree.pileup_threshold",
        base.worktree
            .as_ref()
            .and_then(|table| table.pileup_threshold),
        working
            .worktree
            .as_ref()
            .and_then(|table| table.pileup_threshold),
    ));

    // The judge's privacy boundary (CLOUD-135). Compared from both sides
    // regardless of whether either declares the table: an absent `[judge]` is
    // the *tightest* setting — pointer-only, at the engine's ceiling — so a
    // working tree that adds one widens the boundary and must be reported.
    found.extend(added_entries(
        WeakeningKind::JudgeRawClassAdded,
        &raw_classes(base),
        &raw_classes(working),
    ));
    found.extend(ceiling_raised(
        WeakeningKind::JudgePayloadLimitRaised,
        "judge.max_payload_bytes",
        Some(payload_ceiling(base)),
        Some(payload_ceiling(working)),
    ));

    // `design::effective_cap` states the direction: for a budget smaller is
    // stricter, so §8's "may not weaken" reads as "may not raise" here.
    found.extend(ceiling_raised(
        WeakeningKind::DesignCaptureLimitRaised,
        "design.max_capture_bytes",
        Some(capture_ceiling(base)),
        Some(capture_ceiling(working)),
    ));

    found.extend(ci_weakenings(base.ci.as_ref(), working.ci.as_ref()));
    found.extend(attribution_weakenings(
        base.attribution.as_ref(),
        working.attribution.as_ref(),
    ));
    found.extend(defects_weakenings(
        base.defects.as_ref(),
        working.defects.as_ref(),
    ));

    // A transcript path gone stops `check` reading the session it judged
    // against (CLOUD-95). Keyed on the effective path rather than the table, so
    // deleting `[transcript]` and blanking its `path` report the same key.
    if transcript_path(base).is_some() && transcript_path(working).is_none() {
        found.push(Weakening::new(
            WeakeningKind::TranscriptPathRemoved,
            "transcript.path",
            "present",
            "absent",
        ));
    }

    found
}

/// The `epoch.tracked` set, or an empty one when the table is absent.
fn tracked_paths(config: &Config) -> Vec<String> {
    config
        .epoch
        .as_ref()
        .map_or_else(Vec::new, |epoch| epoch.tracked.clone())
}

/// Each `[[verb]]` row as the entry a weakening keys on.
///
/// The rendering is the report's, not a second definition of a verb's identity:
/// it is the same pair `crate::verbs` matches on — the program and the
/// subcommand that qualifies it — written the way an author typed the row, so
/// `verb[git push]` reads as the call it un-gates.
fn verb_entries(config: &Config) -> Vec<String> {
    config
        .verbs
        .iter()
        .map(|row| match row.subcommand.as_deref() {
            None => row.verb.clone(),
            Some(subcommand) => format!("{} {subcommand}", row.verb),
        })
        .collect()
}

/// The ids of a table, collected so [`removed_entries`] can compare them.
fn ids(entries: impl Iterator<Item = String>) -> Vec<String> {
    entries.collect()
}

/// The content classes admitted raw into a model call, as rendered key paths.
///
/// Empty — including for a config with no `[judge]` at all — is the pointer-only
/// default, which is why an absent table compares as the tightest setting.
fn raw_classes(config: &Config) -> Vec<String> {
    config.judge.as_ref().map_or_else(Vec::new, |judge| {
        judge
            .raw
            .iter()
            .map(|class| format!("judge.raw[{}]", class.as_str()))
            .collect()
    })
}

/// The effective assembled-payload ceiling: the declared one, or the engine's.
fn payload_ceiling(config: &Config) -> usize {
    config
        .judge
        .as_ref()
        .and_then(|judge| judge.max_payload_bytes)
        .unwrap_or(crate::judge::DEFAULT_MAX_PAYLOAD_BYTES)
}

/// The effective per-capture ceiling: the declared one, or the engine's.
fn capture_ceiling(config: &Config) -> usize {
    config
        .design
        .as_ref()
        .and_then(|design| design.max_capture_bytes)
        .unwrap_or(crate::design::DEFAULT_MAX_CAPTURE_BYTES)
}

/// The effective transcript path, or `None` when the table or the key is absent.
fn transcript_path(config: &Config) -> Option<&str> {
    config
        .transcript
        .as_ref()
        .and_then(|table| table.path.as_deref())
}

/// A ceiling that rose, or stopped being declared at all.
///
/// The inverted direction, stated once: for a threshold a *larger* number
/// forgives more, so `working > base` is the weakening — and `None` where the
/// base had a value is the widest of all, because the predicate stops
/// participating. Callers that have a compiled-in default pass the effective
/// value on both sides instead, so "the key was deleted" and "the key was set to
/// the default" cannot read differently.
fn ceiling_raised(
    kind: WeakeningKind,
    key: &str,
    base: Option<usize>,
    working: Option<usize>,
) -> Option<Weakening> {
    match (base, working) {
        (Some(base), None) => Some(Weakening::new(kind, key, base.to_string(), "absent")),
        (Some(base), Some(working)) if working > base => Some(Weakening::new(
            kind,
            key,
            base.to_string(),
            working.to_string(),
        )),
        _ => None,
    }
}

/// Entries rendered as their own key paths, for [`added_entries`].
fn keyed(key: &str, entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| format!("{key}[{entry}]"))
        .collect()
}

/// The `min_batten_version` floor, lowered or dropped.
///
/// A binary below the floor is refused at parse (CLOUD-33), so lowering it
/// admits one that does not understand the rules — and deleting the key admits
/// every build there has ever been, which is why absence is the weakest value
/// rather than "no opinion". An unparseable version cannot reach here: the same
/// parse that produced these configs refuses it.
fn min_version_weakening(base: &Config, working: &Config) -> Option<Weakening> {
    let declared = base.min_batten_version.as_deref()?;
    let floor = semver::Version::parse(declared).ok()?;
    match working.min_batten_version.as_deref() {
        None => Some(Weakening::new(
            WeakeningKind::MinVersionLowered,
            "min_batten_version",
            declared,
            "absent",
        )),
        Some(candidate) => match semver::Version::parse(candidate) {
            Ok(parsed) if parsed < floor => Some(Weakening::new(
                WeakeningKind::MinVersionLowered,
                "min_batten_version",
                declared,
                candidate,
            )),
            _ => None,
        },
    }
}

/// Waivers whose expiry the working tree pushed further out.
///
/// Paired by [`crate::waiver::Waiver::key`], which is the identity two waivers
/// may not share — and which deliberately omits `expires`, so this comparison is
/// exactly the blind spot that identity leaves: same rule, same path, a date
/// moved from lapsed to live suppresses everything the base ref reported and
/// [`added_entries`] sees no new key at all.
///
/// Date-independent, so §6 holds: one file's `expires` against the other's,
/// never against today. A malformed expiry is refused at load, so a pair that
/// cannot both be parsed is unreachable through the loader and is skipped rather
/// than guessed at.
fn waiver_expiry_weakenings(base: &[waiver::Waiver], working: &[waiver::Waiver]) -> Vec<Weakening> {
    base.iter()
        .filter_map(|row| {
            let other = working.iter().find(|other| other.key() == row.key())?;
            let (Ok(from), Ok(to)) = (row.expiry(), other.expiry()) else {
                return None;
            };
            (to > from).then(|| {
                Weakening::new(
                    WeakeningKind::WaiverExpiryExtended,
                    format!("{}.expires", row.key()),
                    row.expires.clone(),
                    other.expires.clone(),
                )
            })
        })
        .collect()
}

/// Budget sets removed, files or embedded declarations dropped, ceilings raised.
fn budget_weakenings(
    base: Option<&crate::budget::Budget>,
    working: Option<&crate::budget::Budget>,
) -> Vec<Weakening> {
    let mut found = Vec::new();
    let Some(base) = base else {
        return found;
    };
    for (name, set) in base.sets() {
        let Some(other) = working
            .and_then(|table| table.sets().find(|(other, _)| *other == name))
            .map(|(_, set)| set)
        else {
            found.push(Weakening::new(
                WeakeningKind::BudgetSetRemoved,
                format!("budget[{name}]"),
                "present",
                "absent",
            ));
            continue;
        };
        found.extend(removed_entries(
            WeakeningKind::BudgetFileRemoved,
            &set.files,
            &other.files,
            &format!("budget[{name}].files"),
        ));
        found.extend(removed_entries(
            WeakeningKind::BudgetEmbeddedRemoved,
            &embedded_entries(set),
            &embedded_entries(other),
            &format!("budget[{name}].embedded"),
        ));
        found.extend(ceiling_raised(
            WeakeningKind::BudgetLimitRaised,
            &format!("budget[{name}].max_tokens"),
            Some(set.max_tokens),
            Some(other.max_tokens),
        ));
        found.extend(ceiling_raised(
            WeakeningKind::BudgetLimitRaised,
            &format!("budget[{name}].max_lines"),
            set.max_lines,
            other.max_lines,
        ));
    }
    found
}

/// Each embedded declaration as one entry: the document, then the key in it.
fn embedded_entries(set: &crate::budget::BudgetSet) -> Vec<String> {
    set.embedded
        .iter()
        .map(|decl| format!("{}#{}", decl.path, decl.key))
        .collect()
}

/// Required checks dropped, and merge methods admitted.
///
/// The projection is a copy of the host ruleset a gate polices (CLOUD-54), so
/// dropping a check from it is how a branch would stop `config lint --host-rules`
/// asking about that check at all. An absent `allowed_merge_methods` is
/// *unconstrained*, which is why losing the key is a weakening on its own and
/// carries a key of its own rather than one entry per method nobody listed.
fn ci_weakenings(base: Option<&crate::ci::Ci>, working: Option<&crate::ci::Ci>) -> Vec<Weakening> {
    let mut found = Vec::new();
    let Some(base) = base else {
        return found;
    };
    let working_checks = working.map_or_else(Vec::new, |ci| ci.required_checks.clone());
    found.extend(removed_entries(
        WeakeningKind::CiMergeCheckRemoved,
        &base.required_checks,
        &working_checks,
        "ci.required_checks",
    ));

    if let Some(declared) = base.allowed_merge_methods.as_ref() {
        match working.and_then(|ci| ci.allowed_merge_methods.as_ref()) {
            None => found.push(Weakening::new(
                WeakeningKind::CiMergeMethodAdded,
                "ci.allowed_merge_methods",
                "constrained",
                "unconstrained",
            )),
            Some(candidate) => found.extend(added_entries(
                WeakeningKind::CiMergeMethodAdded,
                &keyed("ci.allowed_merge_methods", declared),
                &keyed("ci.allowed_merge_methods", candidate),
            )),
        }
    }
    found
}

/// Deny patterns dropped, and carve-outs added.
///
/// Dropping the whole table drops every pattern with it, and it is reported that
/// way — one pointer per pattern rather than one saying `[attribution]` is gone.
/// The per-key precision is CLOUD-233's rule: what distinguishes two weakenings
/// belongs in the key, and "which refusals this branch dropped" is exactly what a
/// reviewer needs. The gate refuses an absent table loudly on its own (exit 1),
/// which is a second signal rather than a reason for this one to stay quiet.
///
/// The `identity` beneath the lists is not compared: which name and email a
/// repository holds itself accountable to is that repository's own decision, and
/// two identities cannot be ranked.
fn attribution_weakenings(
    base: Option<&crate::attribution::Attribution>,
    working: Option<&crate::attribution::Attribution>,
) -> Vec<Weakening> {
    let mut found = Vec::new();
    let Some(base) = base else {
        return found;
    };
    let empty: Vec<String> = Vec::new();
    for (index, (key, declared)) in deny_lists(base).into_iter().enumerate() {
        let candidate = working.map_or(&empty, |other| deny_lists(other)[index].1);
        found.extend(removed_entries(
            WeakeningKind::AttributionDenyRemoved,
            declared,
            candidate,
            key,
        ));
    }
    let candidate = working.map_or(&empty, |other| &other.trailer_allow);
    found.extend(added_entries(
        WeakeningKind::AttributionAllowAdded,
        &keyed("attribution.trailer_allow", &base.trailer_allow),
        &keyed("attribution.trailer_allow", candidate),
    ));
    found
}

/// The three deny lists, keyed as `batten.toml` spells them.
fn deny_lists(attribution: &crate::attribution::Attribution) -> [(&'static str, &Vec<String>); 3] {
    [
        ("attribution.identity_deny", &attribution.identity_deny),
        ("attribution.trailer_deny", &attribution.trailer_deny),
        ("attribution.body_deny", &attribution.body_deny),
    ]
}

/// The ledger gone, or its class set widened.
///
/// Absence here reads differently from `[attribution]`'s: a repository with no
/// `[defects]` keeps no in-tree ledger and the gate is simply not active, so
/// deleting the table is a silent deactivation rather than a loud refusal. A
/// class *added* admits a record the ledger used to refuse.
fn defects_weakenings(
    base: Option<&crate::defects::Defects>,
    working: Option<&crate::defects::Defects>,
) -> Vec<Weakening> {
    let Some(base) = base else {
        return Vec::new();
    };
    let Some(working) = working else {
        return vec![Weakening::new(
            WeakeningKind::DefectsLedgerRemoved,
            "defects",
            "present",
            "absent",
        )];
    };
    added_entries(
        WeakeningKind::DefectsClassAdded,
        &keyed("defects.classes", &base.classes),
        &keyed("defects.classes", &working.classes),
    )
}

/// Entries present in `base` and absent from `working`, as weakenings of `key`.
fn removed_entries(
    kind: WeakeningKind,
    base: &[String],
    working: &[String],
    key: &str,
) -> Vec<Weakening> {
    let present: BTreeSet<&str> = working.iter().map(String::as_str).collect();
    base.iter()
        .filter(|entry| !present.contains(entry.as_str()))
        .map(|entry| Weakening::new(kind, format!("{key}[{entry}]"), "present", "absent"))
        .collect()
}

/// Entries present in `working` and absent from `base`, as weakenings.
///
/// The mirror of [`removed_entries`], for a key where *more* is weaker. The
/// entries arrive as their own rendered key paths rather than as a key plus an
/// index, because a waiver's identity is already two fields and reconstructing it
/// here would be a second definition of it.
fn added_entries(kind: WeakeningKind, base: &[String], working: &[String]) -> Vec<Weakening> {
    let known: BTreeSet<&str> = base.iter().map(String::as_str).collect();
    working
        .iter()
        .filter(|entry| !known.contains(entry.as_str()))
        // The tokens are the mirror image too: this key went from absent to
        // present, and printing it that way is what makes the arrow readable.
        .map(|entry| Weakening::new(kind, entry.clone(), "absent", "present"))
        .collect()
}

/// Rules the working tree removed, or whose severity it lowered.
///
/// Keyed by rule `id`, which is the rule's stable identity — a rule whose glob
/// or pattern changed is a different question (is it still the same gate?) that
/// this comparison deliberately does not answer, because any answer would be a
/// judgement rather than a predicate.
fn rule_weakenings(base: &[Rule], working: &[Rule]) -> Vec<Weakening> {
    base.iter()
        .filter_map(|rule| {
            match working.iter().find(|other| other.id == rule.id) {
                None => Some(Weakening::new(
                    WeakeningKind::RuleRemoved,
                    format!("rule[{}]", rule.id),
                    "present",
                    "absent",
                )),
                // Severity's rank *is* its ordering (CLOUD-61): `allow < warn <
                // deny`, so "lowered" is a comparison rather than a name match.
                Some(other) if other.severity < rule.severity => Some(Weakening::new(
                    WeakeningKind::SeverityLowered,
                    format!("rule[{}].severity", rule.id),
                    severity_token(rule.severity()),
                    severity_token(other.severity()),
                )),
                Some(_) => None,
            }
        })
        .chain(base.iter().flat_map(|rule| {
            working
                .iter()
                .find(|other| other.id == rule.id)
                .map_or_else(Vec::new, |other| rule_predicate_weakenings(rule, other))
        }))
        .collect()
}

/// Rule columns that are not the rule's predicate, each with why not.
///
/// Every *other* column is compared, which is the fail-safe direction: a column
/// added to [`Rule`] is compared until somebody exempts it here with a reason,
/// rather than silently joining the set nothing looks at — the same defect one
/// level down from the one [`CENSUS`] closes.
const RULE_NON_PREDICATE: &[(&str, &str)] = &[
    (
        "id",
        "the rule's identity: it is what this comparison is keyed BY, so a changed id \
         is a removed rule and an added one",
    ),
    (
        "severity",
        "compared as a rank of its own by `severity-lowered`, because severity has an \
         ordering where a predicate does not",
    ),
    (
        "reason",
        "prose a refusal prints. It changes what a reader is told, never whether the \
         rule fires",
    ),
    (
        "policy_url",
        "a pointer at the documentation behind `reason`, for `reason`'s reason",
    ),
    (
        "fix",
        "the remediation offered after a finding, never whether one is produced",
    ),
];

/// Predicate columns of one rule that the working tree changed.
///
/// **A change, never a ranking.** Whether a narrowed glob is weaker than the one
/// it replaced is a judgement about two patterns, and this module does not make
/// judgements. That the predicate moved at all is a byte comparison, and it is
/// the fact that used to be reported nowhere: a rule whose glob matches nothing
/// keeps its id and its severity, so the comparison called it unchanged while it
/// gated nothing.
///
/// Read off the rule's own serialization rather than a hand-kept column list,
/// which would drift the next time [`Rule`] grows one. The tokens are digests:
/// a config's patterns are the consumer's, and a pointer names *which* column
/// moved without carrying what it now says (non-negotiable rule 4).
fn rule_predicate_weakenings(base: &Rule, working: &Rule) -> Vec<Weakening> {
    let (Ok(serde_json::Value::Object(from)), Ok(serde_json::Value::Object(to))) =
        (serde_json::to_value(base), serde_json::to_value(working))
    else {
        return Vec::new();
    };
    let mut columns: Vec<&String> = from.keys().chain(to.keys()).collect();
    columns.sort_unstable();
    columns.dedup();
    columns
        .into_iter()
        .filter(|column| {
            !RULE_NON_PREDICATE
                .iter()
                .any(|(exempt, _)| exempt == column)
        })
        .filter_map(|column| {
            let (was, now) = (
                from.get(column).unwrap_or(&serde_json::Value::Null),
                to.get(column).unwrap_or(&serde_json::Value::Null),
            );
            (was != now).then(|| {
                Weakening::new(
                    WeakeningKind::RulePredicateChanged,
                    format!("rule[{}].{column}", base.id),
                    column_token(was),
                    column_token(now),
                )
            })
        })
        .collect()
}

/// One column's value as a stable token: a digest, or `absent`.
///
/// Never the value itself. A rule's patterns are the consumer's config, and §6's
/// byte-stability is satisfied by a hash of them exactly as it is by a name —
/// two runs over the same pair of files produce the same token, and neither run
/// prints what the pattern says.
fn column_token(value: &serde_json::Value) -> String {
    if value.is_null() {
        return "absent".to_owned();
    }
    let digest = crate::receipt::hex_sha256(value.to_string().as_bytes());
    format!("sha256:{}", &digest[..12])
}

/// The lowercase token a [`Strictness`] is written as, read off its `ValueEnum`
/// derive rather than re-tabulated here.
fn strictness_token(strictness: Strictness) -> String {
    use clap::ValueEnum;
    strictness
        .to_possible_value()
        .map_or_else(|| "unknown".to_owned(), |v| v.get_name().to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Config {
        config::parse(text, "test").unwrap()
    }

    fn rule(id: &str, severity: &str) -> String {
        format!(
            "\n[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\nseverity = \"{severity}\"\n"
        )
    }

    #[test]
    fn an_identical_config_weakens_nothing() {
        let text = format!("version = 1\nprotected = [\"a\"]\n{}", rule("r", "deny"));
        assert!(weakenings(&parse(&text), &parse(&text)).is_empty());
    }

    #[test]
    fn lowering_strictness_is_a_weakening() {
        let base = parse("version = 1\nstrictness = \"strict\"\n");
        let working = parse("version = 1\nstrictness = \"permissive\"\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::StrictnessLowered,
                "strictness",
                "strict",
                "permissive"
            )]
        );
    }

    #[test]
    fn raising_strictness_is_not_a_weakening() {
        let base = parse("version = 1\nstrictness = \"permissive\"\n");
        let working = parse("version = 1\nstrictness = \"strict\"\n");
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn removing_strictness_entirely_is_compared_against_the_default() {
        // The trap: comparing `Option`s would read a removed key as "no change"
        // while the effective floor dropped from strict to the default.
        let base = parse("version = 1\nstrictness = \"strict\"\n");
        let working = parse("version = 1\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::StrictnessLowered,
                "strictness",
                "strict",
                "standard"
            )]
        );
    }

    #[test]
    fn removing_a_protected_path_is_a_weakening() {
        let base = parse("version = 1\nprotected = [\"a\", \"b\"]\n");
        let working = parse("version = 1\nprotected = [\"a\"]\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::ProtectedRemoved,
                "protected[b]",
                "present",
                "absent"
            )]
        );
    }

    #[test]
    fn the_protected_weakening_key_survives_the_redirect_table() {
        // CLOUD-280's load-bearing non-change. The obvious way to give a
        // protected path its own redirect is to widen `protected` to a table of
        // `{glob, mutation}` — and that breaks THIS key, because `removed_entries`
        // renders `format!("{key}[{entry}]")` over a list of strings. A consumer
        // reading `protected[b]` out of a trust report, and every gate keyed on
        // that spelling, would start seeing something else.
        //
        // So the redirect landed as a sibling table and `protected` kept its
        // element type. Asserted byte-for-byte, and with a redirect declared, so
        // the assertion is about the shape that shipped rather than about a
        // config the feature does not exist in.
        let base = parse(
            "version = 1\nprotected = [\"a\", \"b\"]\n\n[[redirect]]\nglob = \"b\"\nmutation = \"use the surface that owns it\"\n",
        );
        let working = parse(
            "version = 1\nprotected = [\"a\"]\n\n[[redirect]]\nglob = \"b\"\nmutation = \"use the surface that owns it\"\n",
        );
        let found = weakenings(&base, &working);
        assert_eq!(found.len(), 1, "one removed path, one weakening: {found:?}");
        assert_eq!(
            found[0].key, "protected[b]",
            "the key format is the signature this design preserves"
        );
        // And the redirect table itself contributes no weakening in either
        // direction: it is not policy-bearing, so adding or removing a row
        // cannot lower a bar.
        let with_row = parse(
            "version = 1\nprotected = [\"a\"]\n\n[[redirect]]\nglob = \"a\"\nmutation = \"x\"\n",
        );
        let without = parse("version = 1\nprotected = [\"a\"]\n");
        assert!(weakenings(&with_row, &without).is_empty());
        assert!(weakenings(&without, &with_row).is_empty());
    }

    #[test]
    fn adding_a_protected_path_is_not_a_weakening() {
        let base = parse("version = 1\nprotected = [\"a\"]\n");
        let working = parse("version = 1\nprotected = [\"a\", \"b\"]\n");
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn removing_an_unlanded_path_is_a_weakening() {
        // `unlanded` is evaluated independently of `protected` (CLOUD-37), so it
        // needs its own case: the two sets must never be collapsed, and a test
        // that only covered one would not notice if they were. That this case was
        // missing is what `every_kind_is_exercised_by_a_case_in_this_module`
        // found on the tree CLOUD-721 arrived at.
        let base = parse("version = 1\nunlanded = [\"a\", \"b\"]\n");
        let working = parse("version = 1\nunlanded = [\"a\"]\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::UnlandedRemoved,
                "unlanded[b]",
                "present",
                "absent"
            )]
        );
        assert!(weakenings(&working, &base).is_empty());
    }

    #[test]
    fn narrowing_scope_is_not_a_weakening() {
        // §8 lists "narrow scope" among the *tightening* moves: a smaller scope
        // polices less but forgives nothing inside what remains.
        let base = parse("version = 1\nscope = [\"a\", \"b\"]\n");
        let working = parse("version = 1\nscope = [\"a\"]\n");
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn removing_a_rule_is_a_weakening() {
        let base = parse(&format!("version = 1\n{}", rule("r", "deny")));
        let working = parse("version = 1\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::RuleRemoved,
                "rule[r]",
                "present",
                "absent"
            )]
        );
    }

    #[test]
    fn lowering_a_rules_severity_is_a_weakening() {
        let base = parse(&format!("version = 1\n{}", rule("r", "deny")));
        let working = parse(&format!("version = 1\n{}", rule("r", "warn")));
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::SeverityLowered,
                "rule[r].severity",
                "deny",
                "warn"
            )]
        );
    }

    #[test]
    fn raising_a_rules_severity_is_not_a_weakening() {
        let base = parse(&format!("version = 1\n{}", rule("r", "warn")));
        let working = parse(&format!("version = 1\n{}", rule("r", "deny")));
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn adding_a_rule_is_not_a_weakening() {
        let base = parse("version = 1\n");
        let working = parse(&format!("version = 1\n{}", rule("r", "deny")));
        assert!(weakenings(&base, &working).is_empty());
    }

    fn waiver_row(rule: &str, path: Option<&str>) -> String {
        let narrowing = path.map_or_else(String::new, |glob| format!("path = \"{glob}\"\n"));
        format!(
            "\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked\"\nexpires = \"2099-01-01\"\n{narrowing}"
        )
    }

    #[test]
    fn adding_a_waiver_is_a_weakening() {
        // The first added-direction case in this module: every other comparison
        // asks what the working tree REMOVED, because for every other key more
        // entries meant a higher bar. A waiver inverts that.
        let base = parse("version = 1\n");
        let working = parse(&format!("version = 1\n{}", waiver_row("r", None)));
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::WaiverAdded,
                "waiver[r]",
                "absent",
                "present",
            )]
        );
    }

    #[test]
    fn removing_a_waiver_is_not_a_weakening() {
        // The mirror, and the reason the direction has to be per-key rather than
        // global: deleting a suppression raises the bar.
        let base = parse(&format!("version = 1\n{}", waiver_row("r", None)));
        let working = parse("version = 1\n");
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn a_waiver_kept_unchanged_is_not_a_weakening() {
        let text = format!("version = 1\n{}", waiver_row("r", None));
        assert!(weakenings(&parse(&text), &parse(&text)).is_empty());
    }

    #[test]
    fn narrowing_a_waiver_reports_the_narrowed_one_as_added() {
        // A path-narrowed waiver is a different identity from the whole-rule one,
        // so replacing one with the other reads as an addition rather than as no
        // change. That is the honest answer: Batten cannot tell that the new row
        // is narrower than the old across arbitrary globs, and the pointer names
        // exactly what appeared.
        let base = parse(&format!("version = 1\n{}", waiver_row("r", None)));
        let working = parse(&format!("version = 1\n{}", waiver_row("r", Some("src/**"))));
        let found = weakenings(&base, &working);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, "waiver[r][src/**]");
    }

    #[test]
    fn two_added_waivers_of_one_rule_are_two_distinct_weakenings() {
        let base = parse("version = 1\n");
        let working = parse(&format!(
            "version = 1\n{}{}",
            waiver_row("r", Some("src/**")),
            waiver_row("r", Some("vendor/**"))
        ));
        let found = weakenings(&base, &working);
        assert_eq!(found.len(), 2, "neither may swallow the other (CLOUD-233)");
    }

    #[test]
    fn turning_off_promotion_is_a_weakening() {
        let base = parse("version = 1\nfail_on_warning = true\n");
        let working = parse("version = 1\nfail_on_warning = false\n");
        assert_eq!(
            weakenings(&base, &working),
            vec![Weakening::new(
                WeakeningKind::PromotionDisabled,
                "fail_on_warning",
                "true",
                "false",
            )]
        );
    }

    #[test]
    fn the_report_is_sorted_and_so_byte_stable() {
        // Authoring order must not reach the output, or two runs over the same
        // pair of configs could disagree and a caller could not diff reports.
        let base = parse(&format!(
            "version = 1\nprotected = [\"z\", \"a\"]\nstrictness = \"strict\"\n{}",
            rule("r", "deny")
        ));
        let working = parse("version = 1\n");
        let keys: Vec<&str> = weakenings(&base, &working)
            .iter()
            .map(|w| w.key.as_str())
            .map(|k| Box::leak(k.to_owned().into_boxed_str()) as &str)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "the report must be sorted");
    }

    #[test]
    fn the_line_is_a_pointer_never_the_config_bytes() {
        let weakening = Weakening::new(
            WeakeningKind::SeverityLowered,
            "rule[no-todo].severity",
            "deny",
            "warn",
        );
        assert_eq!(
            weakening.line(),
            "batten.toml:rule[no-todo].severity deny→warn"
        );
    }

    /// Every field [`Config`] declares, read off its own source.
    ///
    /// The struct-source scan `config.rs`'s own
    /// `every_typed_config_table_has_a_validation_call_site` already performs,
    /// for the same reason: the authority on which fields exist is the struct,
    /// and any second list of them is the drift being fixed.
    fn config_fields() -> Vec<&'static str> {
        let source = include_str!("config.rs");
        let start = source
            .find("pub struct Config {")
            .expect("Config is declared here");
        let rest = &source[start..];
        let body = &rest[..rest.find("\n}").expect("the struct closes")];
        body.lines()
            .filter_map(|line| line.trim().strip_prefix("pub "))
            .filter_map(|rest| rest.split_once(':'))
            .map(|(field, _)| field)
            .collect()
    }

    #[test]
    fn every_config_field_carries_a_verdict() {
        // CLOUD-721's gate, and the reason it is written before the coverage it
        // demands: on arrival this failed with twenty-two field names, and that
        // list WAS the work. A key added to `Config` with a weakening direction
        // nobody considered is how the comparison fell to six of twenty-eight,
        // and prose asking the next author to consider it is feedforward only
        // (non-negotiable rule 2).
        let fields = config_fields();
        assert!(
            fields.len() > 10,
            "the struct scan must actually find fields: {fields:?}"
        );

        let missing: Vec<&str> = fields
            .iter()
            .copied()
            .filter(|field| !CENSUS.iter().any(|row| row.field == *field))
            .collect();
        assert!(
            missing.is_empty(),
            "these `Config` fields carry no weakening verdict: {missing:?}. Say what \
             `trust` does about each one — compared (with its kind), no monotone \
             reading (with the reason), or not policy-bearing (with the reason). \
             Silence is not one of the three."
        );

        for row in CENSUS {
            assert!(
                fields.contains(&row.field),
                "the census names `{}`, which `Config` no longer declares",
                row.field
            );
            assert_eq!(
                CENSUS
                    .iter()
                    .filter(|other| other.field == row.field)
                    .count(),
                1,
                "`{}` carries two verdicts; one field, one answer",
                row.field
            );
            match row.coverage {
                Coverage::Compared(kinds) => assert!(
                    !kinds.is_empty(),
                    "`{}` is recorded compared by no kind at all",
                    row.field
                ),
                Coverage::NoMonotoneReading(reason) | Coverage::NotPolicyBearing(reason) => {
                    assert!(
                        !reason.trim().is_empty(),
                        "`{}` declines to compare without saying why",
                        row.field
                    );
                }
            }
        }
    }

    #[test]
    fn every_weakening_kind_is_claimed_by_exactly_one_field() {
        // The other half of the census: a kind nothing claims is a comparison
        // whose key nobody can name, and a kind two fields claim makes the
        // verdict ambiguous about which key moved.
        for kind in WeakeningKind::ALL {
            let claimants: Vec<&str> = CENSUS
                .iter()
                .filter(|row| match row.coverage {
                    Coverage::Compared(kinds) => kinds.contains(kind),
                    _ => false,
                })
                .map(|row| row.field)
                .collect();
            assert_eq!(
                claimants.len(),
                1,
                "{} is claimed by {claimants:?}; exactly one field owns a kind",
                kind.as_str()
            );
        }
    }

    #[test]
    fn the_kind_vocabulary_is_derived_rather_than_re_typed() {
        // `ALL` is what the census ranges over, so a variant missing from it
        // would be a kind the census cannot see — the same hole one level down.
        let source = include_str!("trust.rs");
        let start = source
            .find("pub enum WeakeningKind {")
            .expect("the kind enum is declared here");
        let rest = &source[start..];
        let body = &rest[..rest.find("\n}").expect("the enum closes")];
        let declared = body
            .lines()
            .filter(|line| {
                let line = line.trim();
                line.ends_with(',')
                    && !line.starts_with("///")
                    && line.starts_with(|c: char| c.is_ascii_uppercase())
            })
            .count();
        assert_eq!(
            declared,
            WeakeningKind::ALL.len(),
            "every variant must be in `ALL`"
        );

        let mut tokens: Vec<&str> = WeakeningKind::ALL.iter().map(|k| k.as_str()).collect();
        tokens.sort_unstable();
        let count = tokens.len();
        tokens.dedup();
        assert_eq!(tokens.len(), count, "two kinds share one token");
    }

    // --- CLOUD-721: one both-directions case per newly compared key ----------
    //
    // The shape the six original cases use, and the reason it is repeated per
    // key rather than folded into a table: the *direction* is a property of the
    // key, so a case that only proved "something is reported" would pass on a
    // comparison wired backwards.

    fn config(extra: &str) -> Config {
        parse(&format!("version = 1\n{extra}"))
    }

    /// The single weakening a pair must produce, or a panic naming what it did.
    fn only(base: &Config, working: &Config) -> Weakening {
        let found = weakenings(base, working);
        assert_eq!(found.len(), 1, "expected exactly one weakening: {found:?}");
        found[0].clone()
    }

    #[test]
    fn lowering_or_deleting_the_version_floor_is_a_weakening() {
        // Below the running build in both directions, or `parse` would refuse
        // the fixture before the comparison could see it (CLOUD-33).
        let base = config("min_batten_version = \"0.0.10\"\n");
        let lower = config("min_batten_version = \"0.0.5\"\n");
        assert_eq!(
            only(&base, &lower),
            Weakening::new(
                WeakeningKind::MinVersionLowered,
                "min_batten_version",
                "0.0.10",
                "0.0.5",
            )
        );
        // Deleting it admits every build there has ever been, so absence is the
        // weakest value rather than "no opinion".
        assert_eq!(only(&base, &config("")).working, "absent");
        // The other direction, and the unchanged one.
        assert!(weakenings(&lower, &base).is_empty());
        assert!(weakenings(&base, &base).is_empty());
    }

    #[test]
    fn dropping_a_tracked_epoch_path_is_a_weakening() {
        let base = config("[epoch]\ntracked = [\"a\", \"b\"]\n");
        let working = config("[epoch]\ntracked = [\"a\"]\n");
        assert_eq!(
            only(&base, &working),
            Weakening::new(
                WeakeningKind::EpochPathRemoved,
                "epoch.tracked[b]",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&working, &base).is_empty());
    }

    fn verb_row(verb: &str, subcommand: Option<&str>) -> String {
        let qualifier =
            subcommand.map_or_else(String::new, |sub| format!("subcommand = \"{sub}\"\n"));
        format!("\n[[verb]]\nverb = \"{verb}\"\neffect = \"write\"\n{qualifier}")
    }

    #[test]
    fn removing_a_mutating_verb_row_is_a_weakening() {
        // The most consequential of the keys CLOUD-721 added: a row that is gone
        // is a tool call nothing mediates at the `PreToolUse` boundary.
        let base = config(&format!(
            "{}{}",
            verb_row("rm", None),
            verb_row("git", Some("push"))
        ));
        let working = config(&verb_row("rm", None));
        assert_eq!(
            only(&base, &working),
            Weakening::new(
                WeakeningKind::VerbRemoved,
                "verb[git push]",
                "present",
                "absent",
            ),
            "the subcommand is part of the row's identity, so it is part of the key"
        );
        assert!(weakenings(&working, &base).is_empty());
    }

    #[test]
    fn removing_a_marker_or_an_exec_pattern_or_a_provision_is_a_weakening() {
        let marker = "\n[[marker]]\nid = \"m\"\ntoken = \"SUPPRESSED-HERE\"\n";
        assert_eq!(
            only(&config(marker), &config("")),
            Weakening::new(
                WeakeningKind::MarkerRemoved,
                "marker[m]",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&config(""), &config(marker)).is_empty());

        let pattern =
            "\n[[exec_pattern]]\nid = \"p\"\npattern = \"warning\"\nreason = \"fix it\"\n";
        assert_eq!(
            only(&config(pattern), &config("")),
            Weakening::new(
                WeakeningKind::ExecPatternRemoved,
                "exec_pattern[p]",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&config(""), &config(pattern)).is_empty());

        let provision = concat!(
            "\n[[provision]]\nname = \"tool\"\nversion = \"1.0.0\"\n",
            "unpack = \"tar_gz\"\nbinary = \"tool\"\n",
            "url = \"https://example.invalid/tool.tar.gz\"\n",
            "sha256 = \"",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "\"\n"
        );
        assert_eq!(
            only(&config(provision), &config("")),
            Weakening::new(
                WeakeningKind::ProvisionRemoved,
                "provision[tool]",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&config(""), &config(provision)).is_empty());
    }

    fn dated_waiver(rule: &str, expires: &str) -> String {
        format!("\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked\"\nexpires = \"{expires}\"\n")
    }

    #[test]
    fn extending_a_lapsed_waiver_is_a_weakening() {
        // CLOUD-721's named case, and it was reported CLEAN before this landed:
        // `Waiver::key` omits `expires`, so a base waiver lapsed in 2020 and a
        // working one live until 2099 are the same key and `added_entries` sees
        // nothing — while the second suppresses every finding of its rule and the
        // first suppresses none.
        let base = config(&dated_waiver("r", "2020-01-01"));
        let working = config(&dated_waiver("r", "2099-01-01"));
        assert_eq!(
            only(&base, &working),
            Weakening::new(
                WeakeningKind::WaiverExpiryExtended,
                "waiver[r].expires",
                "2020-01-01",
                "2099-01-01",
            )
        );
        // Pulling an expiry IN raises the bar, and the comparison is against the
        // other file rather than against today, so neither direction depends on
        // the date the comparison ran (§6).
        assert!(weakenings(&working, &base).is_empty());
        assert!(weakenings(&working, &working).is_empty());
    }

    #[test]
    fn a_narrowed_waiver_path_keeps_its_own_expiry_key() {
        // Two waivers of one rule differ by their path, so the expiry pointers do
        // too — neither may swallow the other (CLOUD-233).
        let row = |path: &str, expires: &str| {
            format!(
                "\n[[waiver]]\nrule = \"r\"\nreason = \"tracked\"\nexpires = \"{expires}\"\npath = \"{path}\"\n"
            )
        };
        let base = config(&format!(
            "{}{}",
            row("src/**", "2020-01-01"),
            row("vendor/**", "2020-01-01")
        ));
        let working = config(&format!(
            "{}{}",
            row("src/**", "2099-01-01"),
            row("vendor/**", "2099-01-01")
        ));
        let found = weakenings(&base, &working);
        assert_eq!(found.len(), 2, "one pointer per waiver, not one per rule");
        assert_eq!(found[0].key, "waiver[r][src/**].expires");
        assert_eq!(found[1].key, "waiver[r][vendor/**].expires");
    }

    #[test]
    fn narrowing_a_rules_glob_to_match_nothing_is_reported() {
        // The other case CLOUD-721 named, also clean before this landed: the id
        // and the severity are untouched, so the comparison called the rule
        // unchanged while it gated nothing.
        let base = config(&rule("r", "deny"));
        let working = config(&rule("r", "deny").replace("**/*.rs", "nothing/here/**"));
        let found = only(&base, &working);
        assert_eq!(found.kind, WeakeningKind::RulePredicateChanged);
        assert_eq!(found.key, "rule[r].glob");
        // A pointer, never the pattern: the glob is the consumer's config, and
        // naming which column moved does not require printing what it now says
        // (non-negotiable rule 4).
        assert!(
            !found.working.contains("nothing"),
            "the token must be a digest: {found:?}"
        );
        assert!(found.working.starts_with("sha256:"));
        // Byte-stable: the same pair produces the same tokens on a second run.
        assert_eq!(weakenings(&base, &working), weakenings(&base, &working));
        // And a rule nobody touched reports nothing at all.
        assert!(weakenings(&base, &base).is_empty());
    }

    #[test]
    fn a_lowered_severity_is_not_also_reported_as_a_predicate_change() {
        // `severity` is exempt from the predicate columns because it has a rank
        // of its own — reporting both would be one edit with two pointers.
        let base = config(&rule("r", "deny"));
        let working = config(&rule("r", "warn"));
        assert_eq!(only(&base, &working).kind, WeakeningKind::SeverityLowered);
    }

    #[test]
    fn every_rule_column_exemption_names_a_real_column_and_a_reason() {
        // The fail-safe direction one level down from `CENSUS`: a column added to
        // `Rule` is compared until somebody exempts it here, so this only has to
        // keep the exemptions honest.
        let source = include_str!("rules.rs");
        let start = source
            .find("pub struct Rule {")
            .expect("Rule is declared here");
        let rest = &source[start..];
        let body = &rest[..rest.find("\n}").expect("the struct closes")];
        for (column, reason) in RULE_NON_PREDICATE {
            assert!(
                body.contains(&format!("pub {column}:")),
                "`{column}` is exempted from the predicate comparison but `Rule` has no such column"
            );
            assert!(
                !reason.trim().is_empty(),
                "`{column}` is exempted without saying why"
            );
        }
    }

    const BUDGET: &str = "\n[budget.set]\nfiles = [\"a.md\", \"b.md\"]\nmax_tokens = 100\nmax_lines = 10\n\n[[budget.set.embedded]]\npath = \"x.toml\"\nkey = \"a.b\"\n";

    #[test]
    fn every_way_of_relaxing_a_budget_is_a_weakening() {
        let base = config(BUDGET);
        // The whole set gone: nothing is counted for it at all.
        assert_eq!(
            only(&base, &config("")),
            Weakening::new(
                WeakeningKind::BudgetSetRemoved,
                "budget[set]",
                "present",
                "absent",
            )
        );
        // A counted file gone.
        assert_eq!(
            only(
                &base,
                &config(&BUDGET.replace("\"a.md\", \"b.md\"", "\"a.md\""))
            ),
            Weakening::new(
                WeakeningKind::BudgetFileRemoved,
                "budget[set].files[b.md]",
                "present",
                "absent",
            )
        );
        // An embedded declaration gone: a string the host always loads stops
        // being counted (CLOUD-298).
        let without_embedded = &BUDGET[..BUDGET.find("\n\n[[budget.set.embedded]]").unwrap()];
        assert_eq!(
            only(&base, &config(without_embedded)),
            Weakening::new(
                WeakeningKind::BudgetEmbeddedRemoved,
                "budget[set].embedded[x.toml#a.b]",
                "present",
                "absent",
            )
        );
        // A ceiling raised. The direction inverts for a budget: bigger forgives
        // more, which `design::effective_cap` states in the same words.
        assert_eq!(
            only(
                &base,
                &config(&BUDGET.replace("max_tokens = 100", "max_tokens = 200"))
            ),
            Weakening::new(
                WeakeningKind::BudgetLimitRaised,
                "budget[set].max_tokens",
                "100",
                "200",
            )
        );
        // A ceiling deleted, which is wider still: the predicate stops
        // participating.
        assert_eq!(
            only(&base, &config(&BUDGET.replace("max_lines = 10\n", ""))),
            Weakening::new(
                WeakeningKind::BudgetLimitRaised,
                "budget[set].max_lines",
                "10",
                "absent",
            )
        );
        // Tightening in each direction is clean.
        assert!(
            weakenings(
                &base,
                &config(&BUDGET.replace("max_tokens = 100", "max_tokens = 50"))
            )
            .is_empty()
        );
        assert!(weakenings(&config(""), &base).is_empty());
    }

    #[test]
    fn losing_the_landing_target_is_a_weakening() {
        let base = config("must_land_on = \"origin/main\"\n");
        assert_eq!(
            only(&base, &config("")),
            Weakening::new(
                WeakeningKind::MustLandOnRemoved,
                "must_land_on",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&config(""), &base).is_empty());
    }

    #[test]
    fn raising_the_pileup_threshold_is_a_weakening() {
        // `count >= threshold`, so a higher number tolerates more (CLOUD-46).
        let base = config("[worktree]\npileup_threshold = 3\n");
        let raised = config("[worktree]\npileup_threshold = 5\n");
        assert_eq!(
            only(&base, &raised),
            Weakening::new(
                WeakeningKind::PileupThresholdRaised,
                "worktree.pileup_threshold",
                "3",
                "5",
            )
        );
        assert_eq!(only(&base, &config("")).working, "absent");
        assert!(weakenings(&raised, &base).is_empty());
    }

    #[test]
    fn widening_the_judges_privacy_boundary_is_a_weakening() {
        // An absent `[judge]` is the TIGHTEST setting — pointer-only, at the
        // engine's ceiling — so a working tree that adds one widens the boundary
        // and both halves compare from an absent base.
        let none = config("");
        let raw = config("[judge]\nraw = [\"span_text\"]\n");
        assert_eq!(
            only(&none, &raw),
            Weakening::new(
                WeakeningKind::JudgeRawClassAdded,
                "judge.raw[span_text]",
                "absent",
                "present",
            )
        );
        assert!(weakenings(&raw, &none).is_empty());

        let base = config("[judge]\nmax_payload_bytes = 100\n");
        assert_eq!(
            only(&base, &config("[judge]\nmax_payload_bytes = 200\n")),
            Weakening::new(
                WeakeningKind::JudgePayloadLimitRaised,
                "judge.max_payload_bytes",
                "100",
                "200",
            )
        );
        // Deleting the key is compared against the engine's default rather than
        // read as "no change", the trap `strictness` already documents.
        assert_eq!(
            only(&base, &none).working,
            crate::judge::DEFAULT_MAX_PAYLOAD_BYTES.to_string()
        );
    }

    #[test]
    fn raising_the_capture_ceiling_is_a_weakening() {
        let base = config("[design]\nmax_capture_bytes = 1024\n");
        assert_eq!(
            only(&base, &config("[design]\nmax_capture_bytes = 2048\n")),
            Weakening::new(
                WeakeningKind::DesignCaptureLimitRaised,
                "design.max_capture_bytes",
                "1024",
                "2048",
            )
        );
        assert!(weakenings(&base, &config("[design]\nmax_capture_bytes = 512\n")).is_empty());
    }

    #[test]
    fn relaxing_the_merge_contract_projection_is_a_weakening() {
        let base = config(
            "[ci]\nrequired_checks = [\"a\", \"b\"]\nallowed_merge_methods = [\"squash\"]\n",
        );
        let fewer =
            config("[ci]\nrequired_checks = [\"a\"]\nallowed_merge_methods = [\"squash\"]\n");
        assert_eq!(
            only(&base, &fewer),
            Weakening::new(
                WeakeningKind::CiMergeCheckRemoved,
                "ci.required_checks[b]",
                "present",
                "absent",
            )
        );
        assert!(weakenings(&fewer, &base).is_empty());

        let more = config(
            "[ci]\nrequired_checks = [\"a\", \"b\"]\nallowed_merge_methods = [\"squash\", \"merge\"]\n",
        );
        assert_eq!(
            only(&base, &more),
            Weakening::new(
                WeakeningKind::CiMergeMethodAdded,
                "ci.allowed_merge_methods[merge]",
                "absent",
                "present",
            )
        );
        // Losing the key entirely is unconstrained, which is wider than any list
        // — and it carries its own pointer rather than one per method nobody
        // listed.
        assert_eq!(
            only(&base, &config("[ci]\nrequired_checks = [\"a\", \"b\"]\n")),
            Weakening::new(
                WeakeningKind::CiMergeMethodAdded,
                "ci.allowed_merge_methods",
                "constrained",
                "unconstrained",
            )
        );
    }

    const ATTRIBUTION: &str = "\n[attribution]\nidentity_deny = [\"vendor\", \"other\"]\ntrailer_deny = [\"Co-Made-By\"]\nbody_deny = [\"advert\"]\ntrailer_allow = [\"Signed-off-by\"]\n\n[attribution.identity]\nname = \"A Person\"\nemail = \"person@example.invalid\"\n";

    #[test]
    fn shrinking_a_deny_list_or_widening_the_carve_out_is_a_weakening() {
        let base = config(ATTRIBUTION);
        assert_eq!(
            only(&base, &config(&ATTRIBUTION.replace("\"vendor\", ", ""))).key,
            "attribution.identity_deny[vendor]"
        );
        assert_eq!(
            only(
                &base,
                &config(&ATTRIBUTION.replace(
                    "trailer_allow = [\"Signed-off-by\"]",
                    "trailer_allow = [\"Signed-off-by\", \"Co-Made-By\"]"
                ))
            ),
            Weakening::new(
                WeakeningKind::AttributionAllowAdded,
                "attribution.trailer_allow[Co-Made-By]",
                "absent",
                "present",
            )
        );
        // Dropping the whole table drops every pattern with it, and each one
        // keeps its own pointer rather than collapsing into "the table is gone"
        // (CLOUD-233). Four patterns, four keys.
        let dropped = weakenings(&base, &config(""));
        assert_eq!(
            dropped.len(),
            4,
            "one pointer per dropped pattern: {dropped:?}"
        );
        assert!(
            dropped
                .iter()
                .all(|found| found.kind == WeakeningKind::AttributionDenyRemoved),
            "the carve-out shrank too, and a shrinking carve-out is tightening: {dropped:?}"
        );
        // The other direction: declaring the table where there was none refuses
        // more than before.
        assert!(weakenings(&config(""), &base).is_empty());
    }

    #[test]
    fn deactivating_the_defect_ledger_or_widening_its_classes_is_a_weakening() {
        let base = config("[defects]\npath = \"defects.jsonl\"\nclasses = [\"a\"]\n");
        assert_eq!(
            only(&base, &config("")),
            Weakening::new(
                WeakeningKind::DefectsLedgerRemoved,
                "defects",
                "present",
                "absent",
            ),
            "an absent [defects] is a silent deactivation, unlike [attribution]'s loud one"
        );
        assert_eq!(
            only(
                &base,
                &config("[defects]\npath = \"defects.jsonl\"\nclasses = [\"a\", \"b\"]\n")
            ),
            Weakening::new(
                WeakeningKind::DefectsClassAdded,
                "defects.classes[b]",
                "absent",
                "present",
            )
        );
        assert!(weakenings(&config(""), &base).is_empty());
    }

    #[test]
    fn losing_the_transcript_path_is_a_weakening() {
        let base = config("[transcript]\npath = \"session.jsonl\"\n");
        assert_eq!(
            only(&base, &config("")),
            Weakening::new(
                WeakeningKind::TranscriptPathRemoved,
                "transcript.path",
                "present",
                "absent",
            )
        );
        // Keyed on the effective path rather than the table, so blanking the key
        // and deleting the table report the same pointer.
        assert_eq!(
            only(&base, &config("[transcript]\n")).key,
            "transcript.path"
        );
        assert!(weakenings(&config(""), &base).is_empty());
    }

    #[test]
    fn every_kind_is_exercised_by_a_case_in_this_module() {
        // Rules ship with their mechanism (non-negotiable rule 2): a kind with
        // no case is a comparison nothing shows can fire, which is how a
        // comparison comes to report the wrong direction and pass.
        let source = include_str!("trust.rs");
        let tests = &source[source
            .find("mod tests {")
            .expect("the test module is declared here")..];
        for kind in WeakeningKind::ALL {
            assert!(
                tests.contains(&format!("WeakeningKind::{kind:?}")),
                "{} has no case in this module",
                kind.as_str()
            );
        }
    }

    #[test]
    fn a_rewritten_fact_command_is_a_weakening() {
        // The one weakening whose payoff is a FORGED FACT rather than a skipped
        // gate (CLOUD-776). The declared command is read twice — it is what the
        // deny asks the agent to run, and what the stored record is verified
        // against — so a branch that rewrites it to something trivial makes the
        // gate ask for the trivial thing and then accept its output.
        let mut base = Config::declaring_nothing();
        base.facts = vec![crate::facts::Declared {
            name: "claimed-key".to_owned(),
            command: "gh pr list --state open".to_owned(),
        }];
        let mut working = base.clone();
        working.facts[0].command = "echo '[]'".to_owned();

        let found = weakenings(&base, &working);
        let kinds: Vec<WeakeningKind> = found.iter().map(|weakening| weakening.kind).collect();
        assert!(
            kinds.contains(&WeakeningKind::FactCommandChanged),
            "got: {kinds:?}"
        );
        // Pointer-only (rule 4): the fact's name and two digests, never either
        // command — one of which is whatever a branch wrote.
        let changed = found
            .iter()
            .find(|weakening| weakening.kind == WeakeningKind::FactCommandChanged)
            .expect("the weakening is present");
        assert_eq!(changed.key, "fact[claimed-key].command");
        assert!(changed.base.starts_with("sha256:"), "got: {}", changed.base);
        assert!(
            !changed.working.contains("echo"),
            "the command must not be reproduced; got: {}",
            changed.working
        );
    }

    #[test]
    fn an_unchanged_fact_command_is_not_reported() {
        // The other direction, so the case above discriminates rather than
        // firing on any config carrying a fact at all.
        let mut base = Config::declaring_nothing();
        base.facts = vec![crate::facts::Declared {
            name: "claimed-key".to_owned(),
            command: "gh pr list --state open".to_owned(),
        }];
        let working = base.clone();
        assert!(weakenings(&base, &working).is_empty());
    }

    #[test]
    fn a_removed_fact_is_reported_and_is_a_tightening() {
        // Reported for completeness rather than danger: a `receipt` row naming a
        // fact nobody declares can never be satisfied, so the removal tightens.
        // It is on the table because a reader comparing two configs should see
        // the row vanish rather than infer it.
        let mut base = Config::declaring_nothing();
        base.facts = vec![crate::facts::Declared {
            name: "claimed-key".to_owned(),
            command: "gh pr list --state open".to_owned(),
        }];
        let working = Config::declaring_nothing();
        let kinds: Vec<WeakeningKind> = weakenings(&base, &working)
            .iter()
            .map(|weakening| weakening.kind)
            .collect();
        assert!(
            kinds.contains(&WeakeningKind::FactRemoved),
            "got: {kinds:?}"
        );
    }
}
