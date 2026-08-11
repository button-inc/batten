//! The designed escape hatch: per-rule waivers that lapse (CLOUD-208).
//!
//! A gate with no override gets removed, and a gate with an unaudited override
//! becomes decoration. So the hatch is a designed feature: a waiver names the
//! rule it suppresses, carries a **required justification** and a **required
//! expiry**, and every application it makes writes an audit line to stderr.
//!
//! ## Why expiry is load-bearing rather than decorative
//!
//! The dead-waiver diagnostic ([`crate::lint`]) catches a waiver matching
//! *nothing*. That is a strict subset of the rot. The larger set is the waiver
//! that still matches and is no longer *warranted* — the code was fixed
//! differently, the risk changed, the author left — and no predicate over the
//! tree can tell that one from a good one, so calling it unwarranted would be a
//! judgement rather than a check.
//!
//! Justification and the diagnostic both leave "the waiver persists" as what
//! happens when nobody looks. **Expiry is the only computable mechanism that
//! inverts that default**: it makes "the waiver lapses" what happens when nobody
//! looks. Every failure in the literature this is drawn from is a failure of
//! *attention*, and a mechanism that requires attention cannot fix a problem
//! caused by its absence.
//!
//! That forces the placement. An expired waiver **simply stops applying**, so
//! the underlying rule fires again and the run exits `2`. A report-only expiry
//! never lapses, and therefore does not fulfil the reasoning it is drawn from.
//!
//! ## Byte-stability holds because the date is an input
//!
//! §6 requires identical input to produce identical bytes, and this module never
//! reads a clock inside the predicate: [`apply`] takes `today` as a [`Date`]
//! parameter. That is the idiom [`crate::output::resolve_with`] already
//! established for ambient facts — it takes the environment and both TTY states
//! and the real ones are read only at the binary boundary. The property is
//! **same commit + same date → same bytes**, which the unit tests check by
//! passing two fixed dates. [`today`] is the single boundary reader.
//!
//! ## Why [`crate::receipt`]'s "expiry is a git fact, never a clock" does not
//! generalise
//!
//! A receipt's claim is *about a specific SHA*, so a SHA comparison is the right
//! invalidator and a clock there would be a bug. A waiver's claim is about a
//! human judgement whose warrant decays in calendar time for reasons that leave
//! no git trace — so a git-fact expiry would mean a waiver over a file nobody
//! touches never expires, which is the rot restated. Different claim, different
//! invalidator; both modules say so where a reader meets them.
//!
//! ## A waiver is a filter, never a fourth severity
//!
//! [`crate::severity`] states that its three enums are a total bijection across
//! three axes and that a fourth rank is a redesign, not an additive variant.
//! "Waived" is not a rank — it is a statement about whether a finding is
//! *counted*. So this module filters the findings vector before the verdict is
//! taken, and nothing about the severity taxonomy changes.
//!
//! ## Scope bound: a shape rule cannot be waived
//!
//! [`crate::hook::adjudicate`] returns a `Decision`, not a
//! [`crate::rules::Finding`], and is contractually clock-free ("no I/O, no
//! environment, no clock"). Mediated calls therefore sit outside this filter by
//! construction, and a waiver naming a `kind = "shape"` rule suppresses nothing.
//! Stated rather than silently true, because a consumer will eventually want it.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::{self, Finding};

/// A calendar date, to the day.
///
/// Field order **is** the comparison order, so the derived [`Ord`] is calendar
/// order and "has this lapsed" is `expires < today` rather than any arithmetic.
/// A day is the finest granularity a config author can honestly write and the
/// coarsest that still lapses, which is why there is no time-of-day here: an
/// expiry accurate to the second would imply a precision the author does not
/// have and would make the verdict depend on when in the day CI ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    /// The proleptic Gregorian year.
    pub year: u64,
    /// The month, 1–12.
    pub month: u64,
    /// The day of the month, 1–31, validated against the month and the year.
    pub day: u64,
}

/// Days in `month` of `year`, Gregorian.
///
/// `u64` throughout, matching [`Date`]'s fields: the epoch conversion below is
/// `u64` arithmetic, and a narrower field would put a truncating cast on the one
/// path that mints a date from a clock.
const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        // The full Gregorian rule, not the four-year approximation: 1900 was not
        // a leap year and 2000 was, and a parser that accepted 1900-02-29 would
        // accept an expiry that never arrives.
        _ => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
    }
}

impl Date {
    /// Parse `YYYY-MM-DD`.
    ///
    /// Strict about width as well as range: `2026-8-1` is refused rather than
    /// silently accepted, because the only reason to admit a second spelling is
    /// to make two configs that mean the same thing look different.
    ///
    /// A longer string whose prefix is a date — an RFC 3339 timestamp — is
    /// refused too. An expiry is a day, and quietly discarding a time the author
    /// wrote would make the config say something Batten did not read.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for anything that is not exactly a
    /// well-formed calendar date. Never a silent skip: an unparseable expiry that
    /// loaded clean would be a waiver with no expiry at all.
    pub fn parse(text: &str) -> Result<Date> {
        let bad = || UsageError::raise(format!("invalid date {text:?}: expected YYYY-MM-DD"));
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(bad());
        }
        let number = |from: usize, to: usize| -> Result<u64> {
            text.get(from..to)
                .filter(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|part| part.parse().ok())
                .ok_or_else(bad)
        };
        let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return Err(bad());
        }
        Ok(Date { year, month, day })
    }

    /// The date of an instant given as seconds since the Unix epoch, UTC.
    ///
    /// The standard era-based civil-from-days algorithm, hand-written so a date
    /// costs no dependency — the same reason [`crate::receipt`] gives for its
    /// timestamp formatter, which now reads its date half from here rather than
    /// carrying a second copy of this arithmetic.
    #[must_use]
    pub fn from_unix_seconds(seconds: u64) -> Date {
        // Shift to the era starting 0000-03-01; every quantity below is
        // non-negative, so the arithmetic stays in u64.
        let z = seconds / 86_400 + 719_468;
        let era = z / 146_097;
        let day_of_era = z % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let mp = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        Date {
            year: year_of_era + era * 400 + u64::from(month <= 2),
            month,
            day,
        }
    }

    /// The canonical `YYYY-MM-DD` spelling — the one [`Date::parse`] accepts.
    #[must_use]
    pub fn text(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// The one clock read in this module, at the boundary rather than the predicate.
///
/// Everything that decides anything takes a [`Date`]; this exists so a run can
/// obtain today's. Mirrors [`crate::output::resolve`] standing in front of
/// `resolve_with`: the ambient fact is fetched once, at the edge, and threaded
/// in as data.
///
/// # Errors
///
/// Returns an internal error (→ exit `3`) if the system clock is before the Unix
/// epoch. Not a silent fallback: a machine whose clock says 1969 would otherwise
/// have every waiver in the file read as live forever.
pub fn today() -> Result<Date> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(Date::from_unix_seconds(since.as_secs()))
}

/// One declared waiver: which rule, why, until when, and optionally where.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// The [`crate::rules::Rule::id`] this waiver suppresses findings of.
    pub rule: String,
    /// Why the finding is being waived. Required, and required to be non-empty:
    /// an unjustified waiver is the undesigned hatch this table replaces, and a
    /// reason nobody had to write is one nobody can review.
    pub reason: String,
    /// The last day this waiver applies, `YYYY-MM-DD`. Required — see the module
    /// docs on why a waiver with no expiry is the rot rather than a convenience.
    pub expires: String,
    /// A glob narrowing the waiver to some of the rule's findings.
    ///
    /// Absent means the whole rule, which is the widest a waiver can be and
    /// therefore the one that must be typed deliberately rather than reached by
    /// omitting a field nobody noticed. Matched with
    /// [`crate::rules::glob_match`], so a waiver's path vocabulary is the one the
    /// rules use and not a second dialect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Waiver {
    /// The parsed expiry.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] when [`Waiver::expires`] is not a calendar date.
    /// Callers past load do not have to handle it — [`validate`] runs at parse
    /// time, so a resolved config's waivers all carry parseable dates.
    pub fn expiry(&self) -> Result<Date> {
        Date::parse(&self.expires).map_err(|err| {
            UsageError::raise(format!("waiver {}: {}", self.rule, root_message(&err)))
        })
    }

    /// Whether this waiver covers `finding` on `today`.
    ///
    /// A malformed expiry covers **nothing**. That is the fail-closed reading and
    /// the only safe one: a waiver whose lapse cannot be computed must not
    /// suppress a finding, or an unparseable date would be the strongest waiver
    /// in the file. [`validate`] makes the case unreachable through the loader;
    /// this is the belt.
    #[must_use]
    pub fn covers(&self, finding: &Finding, today: Date) -> bool {
        if self.rule != finding.rule {
            return false;
        }
        let Ok(expiry) = self.expiry() else {
            return false;
        };
        // `expires` is the last day it applies, so equality is still live: a
        // waiver written "expires 2026-08-10" that stopped working on the 10th
        // would surprise every author who read the key as a deadline.
        if expiry < today {
            return false;
        }
        match &self.path {
            None => true,
            Some(glob) => rules::glob_match(glob, &finding.path),
        }
    }

    /// The identity two waivers may not share: the rule and the path it narrows
    /// to.
    ///
    /// One rendering, so a load refusal, a [`crate::lint`] pointer and a
    /// [`crate::trust`] weakening all name a waiver the same way — the property
    /// `rule[{id}]` already holds for rules, and the reason CLOUD-233's dedup bug
    /// cannot return is that two waivers of one rule differ here by their path.
    #[must_use]
    pub fn key(&self) -> String {
        match &self.path {
            None => format!("waiver[{}]", self.rule),
            Some(path) => format!("waiver[{}][{path}]", self.rule),
        }
    }
}

/// The bottom message of an error chain, so a wrapper does not stack prefixes.
fn root_message(err: &anyhow::Error) -> String {
    err.chain()
        .last()
        .map_or_else(|| err.to_string(), std::string::ToString::to_string)
}

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

/// One suppression this run performed, as an audit record.
///
/// Pointer-only (non-negotiable rule 4): the finding's location, the rule, and
/// the expiry the waiver claimed — never the bytes that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The waived finding's path.
    pub path: String,
    /// The waived finding's line, when it had one.
    pub line: Option<usize>,
    /// The rule that would have fired.
    pub rule: String,
    /// The expiry the applied waiver carried.
    pub expires: String,
}

impl Applied {
    /// The audit line this application renders as, without a trailing newline:
    /// `waived <path>[:<line>] <rule> (expires <date>)`.
    ///
    /// The finding's own pointer shape with a verdict word in front, so a reader
    /// who greps `check` output can grep this.
    #[must_use]
    pub fn line_text(&self) -> String {
        match self.line {
            Some(line) => format!(
                "waived {}:{} {} (expires {})",
                self.path, line, self.rule, self.expires
            ),
            None => format!(
                "waived {} {} (expires {})",
                self.path, self.rule, self.expires
            ),
        }
    }
}

/// Partition `findings` into the ones that survive and the suppressions applied.
///
/// This is the whole predicate, and it is a pure function of its three inputs —
/// which is what keeps §6's byte-stability true with an expiry in the design.
/// A finding no waiver covers, and a finding whose only waiver has lapsed, both
/// come back in the surviving vector; nothing is rewritten, and no severity is
/// altered.
///
/// Order is preserved on both sides, so a caller that sorted its findings gets a
/// sorted answer without re-sorting.
#[must_use]
pub fn apply(
    findings: Vec<Finding>,
    waivers: &[Waiver],
    today: Date,
) -> (Vec<Finding>, Vec<Applied>) {
    // Cheap when irrelevant (house-style §4): no waivers means no per-finding
    // work at all, and the vector is handed straight back.
    if waivers.is_empty() {
        return (findings, Vec::new());
    }
    let mut kept = Vec::with_capacity(findings.len());
    let mut applied = Vec::new();
    for finding in findings {
        match waivers.iter().find(|waiver| waiver.covers(&finding, today)) {
            Some(waiver) => applied.push(Applied {
                path: finding.path,
                line: finding.line,
                rule: finding.rule,
                expires: waiver.expires.clone(),
            }),
            None => kept.push(finding),
        }
    }
    (kept, applied)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::severity::RuleSeverity;

    fn waiver(rule: &str, expires: &str) -> Waiver {
        Waiver {
            rule: rule.to_owned(),
            reason: "tracked in CLOUD-1".to_owned(),
            expires: expires.to_owned(),
            path: None,
        }
    }

    fn finding(rule: &str, path: &str) -> Finding {
        Finding {
            rule: rule.to_owned(),
            severity: RuleSeverity::Deny,
            path: path.to_owned(),
            line: Some(3),
            // A real minted identity rather than a placeholder: waiving is
            // orthogonal to identity, and a fabricated one would let these
            // fixtures pass over a shape the engine cannot produce.
            identity: crate::identity::StoredIdentity::new(
                crate::identity::FindingKind::Code,
                crate::identity::code_fingerprint(
                    rule,
                    path,
                    "span",
                    crate::identity::SpanNormalization::Collapsed,
                )
                .expect("a repo-relative fixture path"),
            ),
            check: crate::findings::Check::Reevaluate,
            remediation: Some(crate::findings::Remediation::NoFix("fixture".to_owned())),
        }
    }

    const TODAY: Date = Date {
        year: 2026,
        month: 8,
        day: 10,
    };

    #[test]
    fn a_waiver_requires_a_justification() {
        let mut bad = waiver("r", "2099-01-01");
        bad.reason = "   ".to_owned();
        let err = validate(&[bad]).expect_err("an empty reason is refused");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn a_waiver_naming_no_rule_is_a_usage_error() {
        let mut bad = waiver("", "2099-01-01");
        bad.rule = String::new();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn an_unparseable_expiry_is_a_usage_error() {
        // Every shape that would otherwise become "no expiry at all".
        for text in [
            "",
            "soon",
            "2026-13-01",
            "2026-02-30",
            "2026-8-1",
            "1900-02-29",
        ] {
            assert!(
                validate(&[waiver("r", text)]).is_err(),
                "{text:?} must not load as an expiry"
            );
        }
        // And the leap-year rule in the direction that admits a real date.
        assert!(validate(&[waiver("r", "2000-02-29")]).is_ok());
    }

    #[test]
    fn a_full_timestamp_is_refused_rather_than_truncated() {
        // Silently dropping the time would make the config say something Batten
        // did not read.
        assert!(Date::parse("2026-08-10T00:00:00Z").is_err());
    }

    #[test]
    fn the_same_rule_and_path_cannot_be_waived_twice() {
        let rows = [waiver("r", "2099-01-01"), waiver("r", "2098-01-01")];
        assert!(validate(&rows).is_err());
        // A narrowed waiver beside a whole-rule one is a different key, so both
        // stand: they say different things, and refusing that would force an
        // author to widen a waiver to add one.
        let mut narrowed = waiver("r", "2099-01-01");
        narrowed.path = Some("src/**".to_owned());
        assert!(validate(&[waiver("r", "2099-01-01"), narrowed]).is_ok());
    }

    #[test]
    fn a_live_waiver_suppresses_and_records_an_audit_line() {
        let (kept, applied) = apply(
            vec![finding("r", "src/a.rs")],
            &[waiver("r", "2099-01-01")],
            TODAY,
        );
        assert!(kept.is_empty());
        assert_eq!(applied.len(), 1);
        assert_eq!(
            applied[0].line_text(),
            "waived src/a.rs:3 r (expires 2099-01-01)"
        );
        assert!(
            !applied[0].line_text().contains("deny"),
            "a waiver is not a severity, so the audit line does not name one"
        );
    }

    #[test]
    fn a_lapsed_waiver_stops_suppressing() {
        // The property the whole design rests on: nobody had to act for this
        // waiver to stop working.
        let (kept, applied) = apply(
            vec![finding("r", "src/a.rs")],
            &[waiver("r", "2020-01-01")],
            TODAY,
        );
        assert_eq!(kept.len(), 1, "the finding is back, unmodified");
        assert_eq!(kept[0].severity, RuleSeverity::Deny);
        assert!(applied.is_empty(), "and nothing was audited as waived");
    }

    #[test]
    fn the_expiry_day_itself_is_still_live() {
        let today = TODAY;
        let (kept, _) = apply(
            vec![finding("r", "src/a.rs")],
            &[waiver("r", &today.text())],
            today,
        );
        assert!(kept.is_empty(), "`expires` is the last day it applies");
    }

    #[test]
    fn the_same_commit_and_date_yield_the_same_verdict() {
        // §6 restated as this module can hold it: the date is an input, so two
        // runs agree iff their inputs do — and two DIFFERENT dates are allowed to
        // disagree, which is the whole mechanism.
        let waivers = [waiver("r", "2026-08-10")];
        let first = apply(vec![finding("r", "src/a.rs")], &waivers, TODAY);
        let second = apply(vec![finding("r", "src/a.rs")], &waivers, TODAY);
        assert_eq!(first, second);

        let later = Date {
            year: 2026,
            month: 8,
            day: 11,
        };
        let after = apply(vec![finding("r", "src/a.rs")], &waivers, later);
        assert_ne!(first.0.len(), after.0.len());
    }

    #[test]
    fn a_path_glob_narrows_a_waiver_to_part_of_a_rule() {
        let mut narrowed = waiver("r", "2099-01-01");
        narrowed.path = Some("vendor/**".to_owned());
        let (kept, applied) = apply(
            vec![finding("r", "vendor/x.rs"), finding("r", "src/a.rs")],
            &[narrowed],
            TODAY,
        );
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].path, "src/a.rs");
        assert_eq!(applied.len(), 1);
    }

    #[test]
    fn a_waiver_never_touches_another_rules_findings() {
        let (kept, applied) = apply(
            vec![finding("other", "src/a.rs")],
            &[waiver("r", "2099-01-01")],
            TODAY,
        );
        assert_eq!(kept.len(), 1);
        assert!(applied.is_empty());
    }

    #[test]
    fn an_unparseable_expiry_suppresses_nothing() {
        // Fail closed: a waiver whose lapse cannot be computed must not be the
        // strongest waiver in the file.
        let mut broken = waiver("r", "whenever");
        broken.expires = "whenever".to_owned();
        let (kept, applied) = apply(vec![finding("r", "src/a.rs")], &[broken], TODAY);
        assert_eq!(kept.len(), 1);
        assert!(applied.is_empty());
    }

    #[test]
    fn a_rule_scoped_finding_with_no_line_still_audits() {
        let mut scoped = finding("r", "**/*.rs");
        scoped.line = None;
        let (_, applied) = apply(vec![scoped], &[waiver("r", "2099-01-01")], TODAY);
        assert_eq!(
            applied[0].line_text(),
            "waived **/*.rs r (expires 2099-01-01)"
        );
    }

    #[test]
    fn no_waivers_hands_the_findings_straight_back() {
        let findings = vec![finding("r", "src/a.rs")];
        let (kept, applied) = apply(findings.clone(), &[], TODAY);
        assert_eq!(kept, findings);
        assert!(applied.is_empty());
    }

    #[test]
    fn the_parser_round_trips_every_date_the_formatter_emits() {
        // Swept over the epoch-derived constructor, which is the one production
        // path that mints a `Date` without going through the parser — so this
        // pairs the two directions rather than testing the parser against itself.
        // Exhaustive over every day from 1970 to 2120 rather than sampled: a
        // sampled stride is how a leap-day or century-boundary bug survives, and
        // 55,000 parses cost nothing.
        for day in 0_u64..55_000 {
            let date = Date::from_unix_seconds(day * 86_400);
            assert_eq!(Date::parse(&date.text()).unwrap(), date, "day {day}");
        }
        // And the anchors, against hand-computed answers.
        assert_eq!(Date::from_unix_seconds(0).text(), "1970-01-01");
        assert_eq!(Date::from_unix_seconds(86_399).text(), "1970-01-01");
        assert_eq!(Date::from_unix_seconds(86_400).text(), "1970-01-02");
        // 2000-02-29 exists; 1900-02-29 did not, which is the century rule.
        assert_eq!(Date::from_unix_seconds(951_782_400).text(), "2000-02-29");
    }

    #[test]
    fn dates_order_as_a_calendar() {
        let dates = [
            Date::parse("2025-12-31").unwrap(),
            Date::parse("2026-01-01").unwrap(),
            Date::parse("2026-01-02").unwrap(),
            Date::parse("2026-02-01").unwrap(),
        ];
        for pair in dates.windows(2) {
            assert!(pair[0] < pair[1], "{pair:?} must be in calendar order");
        }
    }
}
