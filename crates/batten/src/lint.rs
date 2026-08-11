//! Config lint: name the policy smells a valid config can still carry
//! (CLOUD-87).
//!
//! Schema validation says the config is *well-formed*; `--config-from` (CLOUD-31)
//! makes CI *judge by* base policy. Neither says "this config parses fine and
//! gates nothing." That is this module's question, and its answer is an exit
//! code rather than advice.
//!
//! # It complements trusted loading, it does not replace it
//!
//! CLOUD-31 makes a weakening *ineffective* — the run is judged by the base ref
//! whatever the branch wrote. This makes the same weakening *visible*, named and
//! located, so a human reviewing the diff sees what was attempted rather than
//! only that the gate held. Both are wanted: one is the control, the other is
//! the alarm.
//!
//! # Two classes of smell, split by what they need
//!
//! * **Single-tree** smells are computable from the working-tree `batten.toml`
//!   alone: a set that is declared and empty, a rule that is switched off.
//! * **Base-ref** smells need the trusted base, and reuse
//!   [`crate::trust::weakenings`] — the same comparison `check` reports, keyed
//!   by the same [`crate::trust::WeakeningKind`] ids. There is no second
//!   trusted-load path and no second definition of "weakened"
//!   (Definition of Ready §1).
//!
//! # Absent is not empty
//!
//! A key the config never mentions means "this repository does not use the
//! feature"; a key declared and empty means "this repository uses the feature
//! and it covers nothing." Only the second is a smell. Flagging absence would
//! fire on every minimal config — including a freshly scaffolded one — which is
//! how a lint teaches people to ignore it. The *deletion* of a populated set is
//! caught, but by the base-ref comparison, where it is a weakening rather than a
//! smell.

use std::fmt;
use std::path::Path;

use anyhow::Result;
use serde::Deserialize;
use toml::Spanned;

use crate::config::{self, Config};
use crate::severity::RuleSeverity;
use crate::trust;

/// Where in `batten.toml` a smell sits.
///
/// Two shapes, because a config has two kinds of location and collapsing them
/// into one is what made a weakening's pointer point nowhere (CLOUD-233):
///
/// * A **single-tree** smell is a span in the working file, so a line is its
///   natural location and `toml::Spanned` supplies it.
/// * A **base-ref weakening** is a *key*. [`trust`] has already located it
///   precisely, and for a key the working tree removed there is no line to
///   have — which is why substituting `0` threw away the only location the
///   pointer ever carried, and why two weakenings of one kind then compared
///   equal and one was silently dropped by `dedup`.
///
/// [`Ord`] is derived, so ordering is total and deterministic: lines first, in
/// numeric order, then keys lexicographically. That is what keeps the report
/// byte-stable for identical input (§6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Where {
    /// The 1-based line the smell sits on, in the working `batten.toml`.
    Line(usize),
    /// The key path, exactly as `batten.toml` addresses it
    /// (`rule[no-todo].severity`, `protected[crates/**]`).
    Key(String),
}

impl fmt::Display for Where {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Where::Line(line) => write!(f, "{line}"),
            Where::Key(key) => write!(f, "{key}"),
        }
    }
}

/// One policy smell, located in `batten.toml`.
///
/// Pointer-only by construction (non-negotiable rule 4): a location and a stable
/// identifier, never the config bytes that produced it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Smell {
    /// Where the smell sits — a line in the working file, or the key path.
    pub at: Where,
    /// The stable, lowercase smell identifier.
    pub id: &'static str,
}

impl Smell {
    /// The pointer line this smell renders as (§6), without a trailing newline:
    /// `batten.toml:<line-or-key> <smell-id>`.
    ///
    /// Exactly a finding's `path:line rule-id` shape, so a caller that already
    /// parses `check` output needs no second parser. For a base-ref weakening
    /// the location half is the same key path [`trust::Weakening::line`] prints,
    /// so one weakening has one pointer whichever verb reports it.
    #[must_use]
    pub fn line_text(&self) -> String {
        format!("{}:{} {}", config::CONFIG_FILE, self.at, self.id)
    }
}

/// A set declared in the config but covering nothing.
const EMPTY_PROTECTED_SET: &str = "empty-protected-set";
/// As above, for `unlanded`.
const EMPTY_UNLANDED_SET: &str = "empty-unlanded-set";
/// As above, for `scope`.
const EMPTY_SCOPE_SET: &str = "empty-scope-set";
/// A rule that is present but switched off.
const RULE_DISABLED: &str = "rule-disabled";
/// A waiver whose `rule` no `[[rule]]` declares: it suppresses nothing, and reads
/// in the file as an exemption someone is relying on (CLOUD-208).
const WAIVER_NAMES_NO_RULE: &str = "waiver-names-no-rule";
/// A waiver whose expiry has passed. It has already stopped suppressing — this is
/// the alarm that says so, rather than leaving a dead row in the file forever.
const WAIVER_EXPIRED: &str = "waiver-expired";
/// The spans of the keys the lint locates.
///
/// A parallel view over the same TOML, deserialized with [`Spanned`] so a smell
/// can carry a line. It deliberately does **not** re-validate: [`config::parse`]
/// has already refused anything malformed, so this view only has to find where
/// the keys are, and any field it does not know about is ignored rather than
/// rejected twice.
#[derive(Debug, Deserialize)]
struct Located {
    #[serde(default)]
    protected: Option<Spanned<Vec<String>>>,
    #[serde(default)]
    unlanded: Option<Spanned<Vec<String>>>,
    #[serde(default)]
    scope: Option<Spanned<Vec<String>>>,
    #[serde(default, rename = "rule")]
    rules: Vec<LocatedRule>,
    #[serde(default, rename = "waiver")]
    waivers: Vec<LocatedWaiver>,
}

#[derive(Debug, Deserialize)]
struct LocatedRule {
    id: Spanned<String>,
    severity: RuleSeverity,
}

/// A waiver's span, located by the one field a smell has to name: the rule it
/// waives. `expires` is read as a plain string — [`config::parse`] above has
/// already refused an unparseable one, so this view never has to re-decide it.
#[derive(Debug, Deserialize)]
struct LocatedWaiver {
    rule: Spanned<String>,
    expires: String,
    #[serde(default)]
    path: Option<String>,
}

/// Convert a byte offset into a 1-based line number.
fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(1, |prefix| prefix.matches('\n').count() + 1)
}

/// Every smell in `text`, sorted.
///
/// `base` supplies the trusted comparison when the caller named a ref; without
/// one, only the single-tree smells are computable and the base-ref class is
/// simply absent rather than silently reported as clean.
///
/// Sorted by `(at, id)` so the report is byte-stable for identical input (§6).
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the config does not parse.
pub fn smells(
    text: &str,
    source: &str,
    base: Option<&Config>,
    today: crate::waiver::Date,
) -> Result<Vec<Smell>> {
    // Parse through the real loader first, so a malformed config produces the
    // same message it would anywhere else rather than this module's own.
    let config = config::parse(text, source)?;
    let located: Located = toml::from_str(text)
        .map_err(|err| crate::UsageError::raise(format!("invalid config {source}: {err}")))?;

    let mut found = Vec::new();

    // A set declared and empty: the config uses the feature and the feature
    // covers nothing. Absence is not flagged — see the module docs.
    for (declared, id) in [
        (located.protected.as_ref(), EMPTY_PROTECTED_SET),
        (located.unlanded.as_ref(), EMPTY_UNLANDED_SET),
        (located.scope.as_ref(), EMPTY_SCOPE_SET),
    ] {
        // A `let`-chain would read better, but it is unstable before 1.88 and
        // this crate pins 1.85.
        let Some(spanned) = declared else { continue };
        if !spanned.get_ref().is_empty() {
            continue;
        }
        found.push(Smell {
            at: Where::Line(line_of(text, spanned.span().start)),
            id,
        });
    }

    // A rule at `allow` is configured off (CLOUD-61): it reads as a gate in the
    // file and is not one. Legal, and occasionally deliberate — which is exactly
    // why it deserves to be named rather than left to be noticed.
    for rule in &located.rules {
        if rule.severity == RuleSeverity::Allow {
            found.push(Smell {
                at: Where::Line(line_of(text, rule.id.span().start)),
                id: RULE_DISABLED,
            });
        }
    }

    // The dead-suppression diagnostic (CLOUD-208), in the two shapes computable
    // from this file alone. Both are located by the waiver's `rule` span, which
    // gives two waivers of one rule distinct locations — the property that keeps
    // CLOUD-233's dedup bug from returning through a new smell.
    //
    // Deliberately NOT here: a waiver over a live rule that matches no finding.
    // That needs the rules run, and `rules::run_all` can spawn processes — putting
    // one behind `config lint` would put a spawning path behind a verb the derived
    // read-only allowlist pins as `read`. Filed rather than smuggled in.
    for waiver in &located.waivers {
        let at = Where::Line(line_of(text, waiver.rule.span().start));
        if !config
            .rules
            .iter()
            .any(|rule| rule.id == *waiver.rule.get_ref())
        {
            found.push(Smell {
                at: at.clone(),
                id: WAIVER_NAMES_NO_RULE,
            });
        }
        // The expiry is a date, and `today` is the injected input the module docs
        // in `crate::waiver` explain: the smell list for a given config is a
        // function of (bytes, date), never of when the process happened to start.
        if crate::waiver::Date::parse(&waiver.expires).is_ok_and(|expiry| expiry < today) {
            found.push(Smell {
                at,
                id: WAIVER_EXPIRED,
            });
        }
        // `path` is read but not linted: whether a glob matches anything is a
        // question about the tree, not about this file, and answering it here
        // would be the runtime diagnostic above wearing a disguise.
        let _ = &waiver.path;
    }

    // `judge-over-protected-unstated` used to live here (CLOUD-135). It is gone
    // with the key it asked about: protected content now refuses the whole
    // invocation, so there is no longer a question for a config to leave
    // unanswered. A smell over a decision the engine makes structurally would be
    // a lint that can never fire.

    // The base-ref class, reusing the one definition of "weakened" — and its
    // location. A weakening arrives from `trust` already carrying the key path
    // it applies to, so the conversion keeps it rather than substituting a line
    // number the working file may not have: `rule[no-todo].severity` locates a
    // lowered severity exactly, and `protected[crates/**]` locates a removed
    // entry exactly *because* a key path does not depend on the key still being
    // in the file. Keeping the key is also what makes two weakenings of one kind
    // distinct, so the `dedup` below can no longer swallow the second (CLOUD-233).
    if let Some(base) = base {
        found.extend(trust::weakenings(base, &config).into_iter().map(|w| Smell {
            at: Where::Key(w.key),
            id: w.kind.as_str(),
        }));
    }

    found.sort();
    found.dedup();
    Ok(found)
}

/// Lint the config in `dir`, with `base_ref` naming the trusted base when the
/// caller wants the comparison smells too.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the working config or the
/// base-ref config cannot be read or parsed.
pub fn run(dir: &Path, base_ref: Option<&str>, today: crate::waiver::Date) -> Result<Vec<Smell>> {
    let path = dir.join(config::CONFIG_FILE);
    let text = std::fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            crate::UsageError::raise(format!("no config found at {}", path.display()))
        } else {
            err.into()
        }
    })?;
    let base = base_ref
        .map(|reference| trust::load_base(dir, reference))
        .transpose()?;
    smells(&text, &path.display().to_string(), base.as_ref(), today)
}

/// Compare the committed `[ci]` against a host ruleset payload (CLOUD-54).
///
/// The payload comes from the caller — a path, or `-` for stdin — because
/// **agents fetch, gates decide**. Deriving it here would put a credentialed
/// network call inside a gate, and a gate that can fail because a token expired
/// is not a gate.
///
/// The committed `[ci]` is read through the **resolved** config, so
/// `--config-from` applies: a branch cannot edit its own projection to agree
/// with itself.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) when the payload cannot be read
/// or is not a rules-API array, and when the config declares no `[ci]` at all —
/// the caller asked for a comparison one side cannot participate in, and
/// answering "no drift" there would be a pass over nothing.
pub fn host_drift(
    dir: &Path,
    source: &str,
    overrides: &crate::resolve::Overrides,
) -> Result<Vec<Smell>> {
    let payload = if source == "-" {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)?;
        buffer
    } else {
        std::fs::read_to_string(source).map_err(|err| {
            crate::UsageError::raise(format!("cannot read host rules from {source}: {err}"))
        })?
    };
    let host = crate::ci::derive(&payload)?;

    let resolved = crate::resolve::resolve(dir, overrides)?;
    let Some(committed) = resolved.ci.as_ref() else {
        return Err(crate::UsageError::raise(format!(
            "--host-rules asked for a comparison, but {} declares no [ci] table",
            config::CONFIG_FILE
        )));
    };

    Ok(crate::ci::drift(committed, &host)
        .into_iter()
        .map(|drift| Smell {
            // Located by key path rather than line: the drift is about a *value*
            // the host disagrees with, and the key plus the differing tokens is
            // what tells an author exactly what to write. `trust`'s weakenings
            // use the same location shape for the same reason.
            at: Where::Key(format!("{} {}", drift.key, drift.rendered())),
            id: drift.id,
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::waiver::Date;

    /// A fixed date, so a lint verdict never depends on when the suite ran — the
    /// point of `waiver`'s injected-date design, exercised here.
    fn today() -> Date {
        Date::parse("2026-08-10").unwrap()
    }

    fn ids(text: &str) -> Vec<&'static str> {
        smells(text, "test", None, today())
            .unwrap()
            .into_iter()
            .map(|smell| smell.id)
            .collect()
    }

    #[test]
    fn a_clean_config_has_no_smells() {
        let text = "version = 1\nprotected = [\"a\"]\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\nseverity = \"deny\"\n";
        assert!(ids(text).is_empty());
    }

    #[test]
    fn a_declared_but_empty_protected_set_is_a_smell() {
        assert_eq!(
            ids("version = 1\nprotected = []\n"),
            vec![EMPTY_PROTECTED_SET]
        );
    }

    #[test]
    fn an_absent_protected_set_is_not_a_smell() {
        // Absent means "this repository does not use the feature". Flagging it
        // would fire on every minimal config, which is how a lint teaches people
        // to ignore it.
        assert!(ids("version = 1\n").is_empty());
    }

    #[test]
    fn an_empty_scope_or_unlanded_set_is_a_smell_too() {
        assert_eq!(ids("version = 1\nscope = []\n"), vec![EMPTY_SCOPE_SET]);
        assert_eq!(
            ids("version = 1\nunlanded = []\n"),
            vec![EMPTY_UNLANDED_SET]
        );
    }

    #[test]
    fn a_rule_switched_off_is_a_smell() {
        let text = "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\nseverity = \"allow\"\n";
        assert_eq!(ids(text), vec![RULE_DISABLED]);
    }

    #[test]
    fn a_smell_carries_the_line_its_key_sits_on() {
        let text = "version = 1\n\nprotected = []\n";
        let found = smells(text, "test", None, today()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].at,
            Where::Line(3),
            "the line the key is written on"
        );
        assert_eq!(found[0].line_text(), "batten.toml:3 empty-protected-set");
    }

    #[test]
    fn base_ref_smells_reuse_the_one_weakening_definition() {
        let base = config::parse(
            "version = 1\nprotected = [\"a\"]\nstrictness = \"strict\"\n",
            "base",
        )
        .unwrap();
        let found = smells("version = 1\n", "test", Some(&base), today()).unwrap();
        let ids: Vec<&str> = found.iter().map(|smell| smell.id).collect();
        assert!(ids.contains(&"protected-removed"), "got: {ids:?}");
        assert!(ids.contains(&"strictness-lowered"), "got: {ids:?}");
    }

    #[test]
    fn each_weakening_keeps_the_key_trust_located_it_by() {
        // The pointer half of CLOUD-233: a weakening arrives already located, and
        // the conversion must not trade that key for a line number the working
        // file may not even have. `batten.toml:0` pointed nowhere.
        let base = config::parse("version = 1\nprotected = [\"a\"]\n", "base").unwrap();
        let found = smells("version = 1\n", "test", Some(&base), today()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].at, Where::Key("protected[a]".to_owned()));
        assert_eq!(
            found[0].line_text(),
            "batten.toml:protected[a] protected-removed"
        );
    }

    #[test]
    fn two_weakenings_of_one_kind_both_survive_dedup() {
        // The counting half of CLOUD-233, and the assertion whose absence let the
        // defect ship: `Smell` identity used to be `(line, id)` with every
        // weakening given line 0, so two rules lowered in one edit compared equal
        // and `dedup` discarded the second. The verb then reported one smell for
        // two weakenings — the more a config was weakened, the more was swallowed.
        let rule = |id: &str, severity: &str| {
            format!(
                "[[rule]]\nid = \"{id}\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\npattern = \"x\"\nseverity = \"{severity}\"\nscope = \"tree\"\n"
            )
        };
        let base = config::parse(
            &format!(
                "version = 1\n{}{}",
                rule("one", "deny"),
                rule("two", "deny")
            ),
            "base",
        )
        .unwrap();
        let working = format!(
            "version = 1\n{}{}",
            rule("one", "warn"),
            rule("two", "warn")
        );
        let found = smells(&working, "test", Some(&base), today()).unwrap();
        let lowered: Vec<&Smell> = found
            .iter()
            .filter(|smell| smell.id == "severity-lowered")
            .collect();
        assert_eq!(lowered.len(), 2, "both lowerings survive: {found:?}");
        assert_eq!(
            lowered
                .iter()
                .map(|smell| smell.line_text())
                .collect::<Vec<_>>(),
            vec![
                "batten.toml:rule[one].severity severity-lowered",
                "batten.toml:rule[two].severity severity-lowered",
            ]
        );
    }

    #[test]
    fn without_a_base_ref_the_comparison_smells_are_absent_not_clean() {
        // The distinction that keeps the lint honest: a run with no base ref
        // simply cannot answer the comparison question, and must not report a
        // clean answer to it.
        let text = "version = 1\n";
        assert!(smells(text, "test", None, today()).unwrap().is_empty());
    }

    #[test]
    fn the_report_is_sorted_and_so_byte_stable() {
        let text = "version = 1\nunlanded = []\nscope = []\nprotected = []\n";
        let found = smells(text, "test", None, today()).unwrap();
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(found, sorted);
    }

    /// A config with one live rule, plus whatever waiver rows the case needs.
    fn with_waivers(waivers: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**/*.rs\"\n\
             pattern = \"x\"\nseverity = \"deny\"\n{waivers}"
        )
    }

    fn waiver_row(rule: &str, expires: &str) -> String {
        format!("\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked\"\nexpires = \"{expires}\"\n")
    }

    #[test]
    fn a_waiver_naming_no_declared_rule_is_a_smell() {
        // The dead-suppression case computable from this file alone: it reads as
        // an exemption someone relies on and suppresses nothing.
        let text = with_waivers(&waiver_row("typo", "2099-01-01"));
        assert_eq!(ids(&text), vec![WAIVER_NAMES_NO_RULE]);
        // And the live rule's own waiver is not a smell.
        let clean = with_waivers(&waiver_row("r", "2099-01-01"));
        assert!(ids(&clean).is_empty());
    }

    #[test]
    fn a_lapsed_waiver_is_a_smell_and_the_date_is_the_input() {
        let text = with_waivers(&waiver_row("r", "2026-08-09"));
        assert_eq!(ids(&text), vec![WAIVER_EXPIRED]);
        // The same bytes, judged on a date before the expiry, are clean — which is
        // §6 holding with a clock in the design: the verdict is a function of
        // (bytes, date) and of nothing else.
        let earlier = smells(&text, "test", None, Date::parse("2026-01-01").unwrap()).unwrap();
        assert!(earlier.is_empty());
    }

    #[test]
    fn the_waiver_pointer_names_the_line_the_rule_key_sits_on() {
        let text = with_waivers(&waiver_row("typo", "2099-01-01"));
        let found = smells(&text, "test", None, today()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_text(), "batten.toml:11 waiver-names-no-rule");
        assert!(
            !found[0].line_text().contains("tracked"),
            "the pointer must never carry the justification text"
        );
    }

    #[test]
    fn two_dead_waivers_of_one_kind_both_survive_dedup() {
        // CLOUD-233's bug, in the shape a new smell could reintroduce it: two
        // waivers of one kind must be located distinctly or `dedup` eats the
        // second, and "the more a config was weakened, the more was swallowed".
        let text = with_waivers(&format!(
            "{}{}",
            waiver_row("typo-one", "2099-01-01"),
            waiver_row("typo-two", "2099-01-01")
        ));
        assert_eq!(
            ids(&text),
            vec![WAIVER_NAMES_NO_RULE, WAIVER_NAMES_NO_RULE],
            "both must be reported, at their own lines"
        );
    }

    #[test]
    fn one_waiver_can_carry_both_smells() {
        // Dead in two ways at once, and each is separately actionable — reporting
        // only the first would hide the other after a fix.
        let text = with_waivers(&waiver_row("typo", "2020-01-01"));
        let mut found = ids(&text);
        found.sort_unstable();
        assert_eq!(found, vec![WAIVER_EXPIRED, WAIVER_NAMES_NO_RULE]);
    }

    #[test]
    fn adding_a_waiver_reaches_the_lint_as_a_base_ref_weakening() {
        // The added-direction weakening arrives through the one definition of
        // "weakened" rather than a second copy in this module.
        let base = config::parse(&with_waivers(""), "base").unwrap();
        let working = with_waivers(&waiver_row("r", "2099-01-01"));
        let found = smells(&working, "test", Some(&base), today()).unwrap();
        let ids: Vec<&str> = found.iter().map(|smell| smell.id).collect();
        assert!(ids.contains(&"waiver-added"), "got: {ids:?}");
    }

    #[test]
    fn a_malformed_config_is_a_usage_error() {
        let err = smells("version = 1\nnot toml\n", "test", None, today()).unwrap_err();
        assert!(err.downcast_ref::<crate::UsageError>().is_some());
    }
}
