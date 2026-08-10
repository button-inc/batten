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
}

impl WeakeningKind {
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
        }
    }
}

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

    found.sort();
    found
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
                    severity_token(rule.severity),
                    severity_token(other.severity),
                )),
                Some(_) => None,
            }
        })
        .collect()
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
    fn adding_a_protected_path_is_not_a_weakening() {
        let base = parse("version = 1\nprotected = [\"a\"]\n");
        let working = parse("version = 1\nprotected = [\"a\", \"b\"]\n");
        assert!(weakenings(&base, &working).is_empty());
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
}
