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

//! # A deliberate weakening is ADMITTED, and only on two sources that agree
//!
//! House style §8 loads policy out of band precisely so a branch cannot lower the
//! bar it is judged by, so there is no flag, environment variable or config key
//! that waives a base-ref smell — anything an author can set at PR time is a
//! self-issued permit. What admits one instead is evidence from two places
//! written at different moments, decided by [`admissions`]:
//!
//! * a `Weakens: <smell> <key>` **commit trailer** on this branch, which travels
//!   with the change and is what CI can read; and
//! * the **groomed body** that named the same pair before the work started,
//!   copied into the branch's claim receipt by [`crate::claim::mint`].
//!
//! The receipt lives under `$GIT_DIR` and dies with the container, so CI has none
//! — which is why its absence falls back to the trailer rather than refusing.
//!
//! # Absent, empty and matching are THREE states, and collapsing two is CLOUD-841
//!
//! A receipt that does not exist is *could not look*. A receipt that exists and
//! names no weakening is *the groom looked and admitted nothing* — evidence of
//! absence rather than absence of evidence, and it must REFUSE. Reading the second
//! as the first is what let a trailer minted inside the change that performs a
//! weakening admit it, which is exactly the shape §8 exists to refuse; measured
//! 2026-08-21, and again on this campaign's own branch.
//!
//! That defect had a layer underneath it that its own row assumed away: the port
//! onto `batten claim` stopped writing the `weakens` line at all, so every receipt
//! in every clone read as *empty* and the lenient arm was the only one reachable.
//! Both halves are fixed together, because either alone still ships a gate that
//! decides nothing.

use std::collections::BTreeSet;
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

/// One `config lint` smell, located by `toml::Spanned` so the pointer carries a
/// line.
///
/// Forwards to [`Smell::line_text`] rather than restating it: CLOUD-371 unifies
/// which types may reach the data channel, never what any of them renders, so
/// the bytes here are the bytes this type already emitted.
impl crate::output::Line for Smell {
    fn line(&self) -> String {
        Smell::line_text(self).to_string()
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
/// A policy bundle whose composed rule set will not resolve: two complete rules
/// conflicting, or a cycle (CLOUD-647).
///
/// **Refused HERE rather than at the gate**, which is the whole reason this
/// smell exists. Regorus reports a conflict and a recursion at *evaluation*,
/// never at `add_policy`, so left alone the first thing to discover a cyclic
/// bundle is a denied tool call — the worst possible moment and the wrong exit
/// class, where house style §8 wants a config fault refused by `config lint`.
const POLICY_SET_UNRESOLVABLE: &str = "policy-set-unresolvable";
/// A module inside an enabled bundle that the whole-set sweep never entered
/// (CLOUD-647).
///
/// **The anti-vacuity term.** A module the sweep did not reach contributes
/// nothing to the analysis, so every conflict and cycle inside it goes
/// unreported and the run is green — a policy set that loads clean, passes every
/// per-row check, and contains a rule that can never fire. That false green is
/// what this row was opened about, and without this smell the two above pass on
/// a gate that analysed nothing.
const POLICY_MODULE_UNSWEPT: &str = "policy-module-unswept";
/// A waiver over a rule whose `kind` mints no [`crate::rules::Finding`], so
/// [`crate::waiver::apply`] never sees one to suppress (CLOUD-293). The third
/// dead-suppression shape, and the one that survives both the others: the rule
/// exists, so `waiver-names-no-rule` is satisfied, and the expiry is in the
/// future, so `waiver-expired` is too.
const WAIVER_UNREACHABLE_KIND: &str = "waiver-unreachable-kind";
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

/// A rule's span, located by its `id`, plus the one column a smell reads.
///
/// `severity` is **optional here** and must stay so: a `judge` row is refused
/// that column outright ([`crate::rules::RuleKind::permits`]), so a required
/// field made this whole view unparseable for any config carrying one — `config
/// lint` answered exit 1 with serde's "missing field severity" on a config the
/// real loader accepts. This mirror exists only to recover spans `config::parse`
/// discards, so anything it demands beyond what that loader demands is a second,
/// stricter authority on what a config may be.
#[derive(Debug, Deserialize)]
struct LocatedRule {
    id: Spanned<String>,
    #[serde(default)]
    severity: Option<RuleSeverity>,
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
    bundles: &[crate::policy::Bundle],
) -> Result<Vec<Smell>> {
    // Parse through the real loader first, so a malformed config produces the
    // same message it would anywhere else rather than this module's own.
    let config = config::parse(text, source)?;
    let located: Located =
        toml::from_str(text).map_err(|err| config::config_error(source, &err))?;

    let mut found = Vec::new();

    // A set declared and empty: the config uses the feature and the feature
    // covers nothing. Absence is not flagged — see the module docs.
    for (declared, id) in [
        (located.protected.as_ref(), EMPTY_PROTECTED_SET),
        (located.unlanded.as_ref(), EMPTY_UNLANDED_SET),
        (located.scope.as_ref(), EMPTY_SCOPE_SET),
    ] {
        if let Some(spanned) = declared
            && spanned.get_ref().is_empty()
        {
            found.push(Smell {
                at: Where::Line(line_of(text, spanned.span().start)),
                id,
            });
        }
    }

    // A rule at `allow` is configured off (CLOUD-61): it reads as a gate in the
    // file and is not one. Legal, and occasionally deliberate — which is exactly
    // why it deserves to be named rather than left to be noticed.
    for rule in &located.rules {
        // An absent `severity` is a judge row, which cannot be at `allow` because
        // it cannot carry the column at all — so it is not "configured off", it is
        // a kind with no on/off axis. Reporting it here would name every judge row
        // in the file as a disabled gate.
        if rule.severity == Some(RuleSeverity::Allow) {
            found.push(Smell {
                at: Where::Line(line_of(text, rule.id.span().start)),
                id: RULE_DISABLED,
            });
        }
    }

    // WHOLE-SET ANALYSIS OVER THE COMPOSED REGO SETS (CLOUD-647). Every other
    // smell in this function is a property of one row or one pair of rows; these
    // two are properties of a SET, which is the class nothing decided before.
    //
    // The bundles arrive already loaded, so this function stays a pure function
    // of its inputs — `lint::run` owns the I/O, the way it already owns reading
    // the base ref. A `smells` that loaded bundles itself would be doing
    // acquisition inside a predicate, which is the shape the fact model exists
    // to keep out.
    //
    // Located at the enabling row's `id` span, so two bundles report at two
    // lines — the property CLOUD-233's dedup bug returned through when two
    // smells shared a location.
    for bundle in bundles {
        let Some(row) = located
            .rules
            .iter()
            .find(|rule| rule.id.get_ref() == bundle.id())
        else {
            continue;
        };
        let at = Where::Line(line_of(text, row.id.span().start));
        match crate::policy::analyse(bundle) {
            // The set refuses itself: a conflict between two complete rules, or
            // a cycle. Regorus names both sites and the dependency chain, and
            // that diagnostic is pointer-shaped already — but it is the ENGINE's
            // text, so only the smell id travels here and the operator reads the
            // detail from `check`'s own refusal.
            Err(_) => found.push(Smell {
                at,
                id: POLICY_SET_UNRESOLVABLE,
            }),
            Ok(crate::facts::Look::Is(analysis)) => {
                // One smell per unswept module rather than one per bundle: a
                // reader fixing this needs to know how many modules are dark,
                // and a single pointer would hide the second.
                for _ in &analysis.unswept {
                    found.push(Smell {
                        at: at.clone(),
                        id: POLICY_MODULE_UNSWEPT,
                    });
                }
            }
            // COULD NOT LOOK IS NOT CLEAN, and it is not a smell either. The
            // sweep did not happen, so nothing about this set has been
            // established — reporting a smell would name a defect nobody has
            // evidence for, and reporting nothing is what a caller already reads
            // as "asked and found nothing". This is the one arm that is silent
            // on purpose, and `config lint`'s exit code is unchanged by it.
            Ok(crate::facts::Look::IsNot | crate::facts::Look::CouldNotLook) => {}
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
    //
    // The located view is paired with the parsed one by position: both
    // deserialize the same `[[waiver]]` array from the same bytes, in order, so
    // index `i` is one row seen two ways. That pairing is what lets a pointer
    // reuse `Waiver::key`'s single rendering instead of re-deriving `rule` and
    // `path` into a second spelling of the same identity.
    for (waiver, parsed) in located.waivers.iter().zip(&config.waivers) {
        let at = Where::Line(line_of(text, waiver.rule.span().start));
        match config
            .rules
            .iter()
            .find(|rule| rule.id == *waiver.rule.get_ref())
        {
            None => found.push(Smell {
                at: at.clone(),
                id: WAIVER_NAMES_NO_RULE,
            }),
            // The rule exists and still cannot be waived: `apply` filters
            // findings, and this kind mints none (`waiver::reaches` says which,
            // and says it once — this module must not carry a second list that
            // can disagree with the filter it describes).
            //
            // Located by key rather than line, which is what carries the
            // unreachable kind alongside the waiver's identity in one pointer —
            // `host_drift` below composes a `Where::Key` for the same reason. The
            // key is distinct per waiver, so two of them cannot collapse under
            // `dedup` (CLOUD-233).
            Some(rule) if !crate::waiver::reaches(rule.kind) => found.push(Smell {
                at: Where::Key(format!("{} {}", parsed.key(), rule.kind.as_str())),
                id: WAIVER_UNREACHABLE_KIND,
            }),
            Some(_) => {}
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
    // THE BASE REF IS LOADED FIRST, and the order is the contract rather than a
    // style choice (CLOUD-719). A ref this binary cannot read stays exit `1`
    // whatever the working tree looks like, so it must be asked before the
    // working file's absence can route anywhere.
    let base = base_ref
        .map(|reference| trust::load_base(dir, reference))
        .transpose()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // THE MAXIMAL WEAKENING IS A VERDICT, NOT A USAGE ERROR. Deleting
            // `batten.toml` is the most complete relaxation available, and under
            // `--config-from` it used to answer `1` — "bad config" — where §7
            // reserves `2` for the policy verdict on every surface (CLOUD-226).
            // A consumer that is not this repo's own workflow reads `1` as its
            // own mistake and moves on.
            //
            // An absent authority grants no policy, so it is compared as one
            // that declares nothing: every key the base declares reports as
            // removed, each under its own key path. That is `run_rules`'
            // treatment of the same condition, arrived at the same way
            // (CLOUD-243), and it is both true and the loudest this report can
            // be. The single-tree smells are skipped rather than faked — there
            // is no file to carry a line number, and inventing one would put a
            // location in the report that no reader could open.
            let Some(base) = base.as_ref() else {
                // No ref named: absence is still zero-config onboarding, and
                // still not this verb's business to refuse differently.
                return Err(crate::UsageError::raise(format!(
                    "no config found at {}",
                    path.display()
                )));
            };
            let mut found: Vec<Smell> =
                trust::weakenings(base, &config::Config::declaring_nothing())
                    .into_iter()
                    .map(|w| Smell {
                        at: Where::Key(w.key),
                        id: w.kind.as_str(),
                    })
                    .collect();
            found.sort();
            found.dedup();
            return Ok(found);
        }
        Err(err) => return Err(err.into()),
    };
    // THE BUNDLES ARE LOADED HERE, where the I/O already lives (CLOUD-647).
    // `smells` stays a pure function of its inputs; this function already owns
    // reading the working file and the base ref, so it owns this too.
    //
    // A bundle that will not LOAD is a different fault from one that will not
    // RESOLVE, and it is already refused with its own message by
    // `policy::load` — an unreadable module, an undeclared id, a colliding one.
    // Reaching that refusal here would replace a specific diagnostic with a
    // generic smell, so a load failure yields no bundles and the set analysis
    // reports nothing about a set it never saw.
    let bundles = config::parse(&text, &path.display().to_string())
        .ok()
        .map(|config| {
            crate::policy::load(
                dir,
                &config.rules,
                crate::policy::Vocabulary::from(&config),
                crate::policy::ModuleChecks::Run,
                base_ref,
            )
        })
        .and_then(std::result::Result::ok)
        .unwrap_or_default();
    smells(
        &text,
        &path.display().to_string(),
        base.as_ref(),
        today,
        &bundles,
    )
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

/// The trailer key that declares a deliberate weakening.
///
/// Batten's own vocabulary rather than a consumer's, which is what keeps this
/// constant on the right side of non-negotiable rule 1: it names a
/// [`trust::WeakeningKind`], a concept the core already owns, and no tracker,
/// branch convention or repository is spelled anywhere near it.
const ADMISSION_TRAILER: &str = "Weakens";

/// What the groom recorded, or that there was no groom to read.
///
/// **Three states, and the third exists because two of them were one** — see this
/// module's header. [`Groom::Silent`] is a receipt that EXISTS and admits nothing,
/// which refuses; [`Groom::Unreadable`] is no receipt at all, which falls back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Groom {
    /// No receipt could be read — CI, a detached HEAD, a branch never claimed.
    /// Could-not-look, so the trailer alone decides.
    Unreadable,
    /// A receipt was read. The set is what it admits, and it may be empty.
    Read(BTreeSet<String>),
}

/// Why one smell was admitted, or that it was not.
///
/// **Pointer-only** (rule 4): a verdict word. The clause's prose lives in the
/// groomed body and never travels into a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// No trailer names it, or a groom that looked did not.
    Refused,
    /// A trailer names it and there is no groom to check it against.
    TrailerAlone,
    /// A trailer names it and the groom named it too.
    Groomed,
}

impl Admission {
    /// The stable lowercase token (§6).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Admission::Refused => "refused",
            Admission::TrailerAlone => "trailer-alone",
            Admission::Groomed => "groomed",
        }
    }
}

/// Read what the groom admitted for `branch`, from the claim receipt store.
///
/// The distinguishing fact is **the receipt's existence**, never whether it
/// carries a `weakens` line — a receipt is minted whenever a claim is made,
/// including one that admitted nothing, so an empty set is a real answer.
#[must_use]
pub fn groom(receipts: &Path, branch: Option<&str>) -> Groom {
    let Some(branch) = branch else {
        // A detached HEAD has no branch to key on, which a rebase produces
        // routinely. That is could-not-look and not a refusal.
        return Groom::Unreadable;
    };
    let path = receipts.join(crate::claim::receipt_name(branch));
    let Ok(body) = std::fs::read_to_string(path) else {
        return Groom::Unreadable;
    };
    Groom::Read(
        body.lines()
            .filter_map(|line| line.strip_prefix("weakens "))
            // The issue key is PROVENANCE for a human reading a refusal, not part
            // of the pair being matched: which story groomed a weakening does not
            // change whether this one was groomed.
            .filter_map(|rest| rest.split_once(' ').map(|(_key, pair)| pair.to_owned()))
            .collect(),
    )
}

/// The `Weakens:` pairs this branch's commits declare, over `base..HEAD`.
///
/// `base..HEAD` rather than the whole history: a trailer inherited from the trunk
/// would admit the same weakening on every branch cut afterwards.
///
/// Read through git's own trailer parse ([`crate::git::commit_record`]), never a
/// scan of the message body, so a line quoted mid-message cannot pose as one and
/// this cannot disagree with what `attribution` reports about the same commit.
///
/// # Errors
///
/// Returns whatever [`crate::git::commits_in_range`] raises when the range will
/// not resolve — a base ref this binary cannot read is exit `1`, never "no
/// trailers".
pub fn declared(dir: &Path, base: &str) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for sha in crate::git::commits_in_range(dir, base, "HEAD")? {
        let Ok(record) = crate::git::commit_record(dir, &sha) else {
            // One unreadable commit is not evidence about the others, and the
            // range resolved — so this is a gap in the scan rather than a
            // could-not-look about the branch.
            continue;
        };
        for trailer in record.trailers {
            if let Some(pair) = trailer
                .strip_prefix(ADMISSION_TRAILER)
                .and_then(|rest| rest.strip_prefix(": "))
                .map(str::trim)
                // An EMPTY trailer declares nothing while reading as a
                // declaration — `config weakens unnamed`'s class. Dropping it
                // here means it can never admit anything.
                .filter(|pair| !pair.is_empty())
            {
                found.insert(pair.to_owned());
            }
        }
    }
    Ok(found)
}

/// Adjudicate each smell against the two sources.
///
/// The pair a clause must name is exactly what a reader already sees in the
/// pointer line — `<smell-id> <key>` — so there is nothing to look up and no
/// second spelling to keep in step.
#[must_use]
pub fn admissions(
    smells: &[Smell],
    trailers: &BTreeSet<String>,
    groomed: &Groom,
) -> Vec<(Smell, Admission)> {
    smells
        .iter()
        .map(|smell| {
            let pair = format!("{} {}", smell.id, smell.at);
            let admission = if trailers.contains(&pair) {
                match groomed {
                    // CI's half: no receipt to consult, and refusing on its
                    // absence would fail every branch whose local run already
                    // proved it.
                    Groom::Unreadable => Admission::TrailerAlone,
                    Groom::Read(admitted) if admitted.contains(&pair) => Admission::Groomed,
                    // THE ONE CLOUD-841 CHANGED. A groom that looked and did not
                    // name this pair refuses it, whatever the trailer says.
                    Groom::Read(_) => Admission::Refused,
                }
            } else {
                Admission::Refused
            };
            (smell.clone(), admission)
        })
        .collect()
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
        smells(text, "test", None, today(), &[])
            .unwrap()
            .into_iter()
            .map(|smell| smell.id)
            .collect()
    }

    fn smell(id: &'static str, key: &str) -> Smell {
        Smell {
            at: Where::Key(key.to_owned()),
            id,
        }
    }

    fn pairs(of: &[&str]) -> BTreeSet<String> {
        of.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_groom_that_looked_and_named_nothing_refuses_the_trailer() {
        // THE CASE THAT IS GREEN TODAY AND MUST GO RED (CLOUD-841). A receipt
        // that exists and admits nothing is evidence of absence; reading it as
        // absence of evidence is what let a trailer minted inside the change
        // that performs the weakening admit it.
        let found = [smell("waiver-added", "waiver[x]")];
        let admitted = admissions(
            &found,
            &pairs(&["waiver-added waiver[x]"]),
            &Groom::Read(BTreeSet::new()),
        );
        assert_eq!(admitted[0].1, Admission::Refused);
    }

    #[test]
    fn no_receipt_at_all_lets_the_trailer_admit_because_that_is_ci() {
        // The anti-vacuity mirror for the case above, and the one that keeps the
        // fix from being "refuse everything": the receipt store lives under
        // `$GIT_DIR` and never reaches a runner, so refusing on its absence
        // would fail every CI run over work a local `verify` already proved.
        let found = [smell("waiver-added", "waiver[x]")];
        let admitted = admissions(
            &found,
            &pairs(&["waiver-added waiver[x]"]),
            &Groom::Unreadable,
        );
        assert_eq!(admitted[0].1, Admission::TrailerAlone);
    }

    #[test]
    fn a_groom_naming_the_pair_admits_it() {
        let found = [smell("waiver-added", "waiver[x]")];
        let admitted = admissions(
            &found,
            &pairs(&["waiver-added waiver[x]"]),
            &Groom::Read(pairs(&["waiver-added waiver[x]"])),
        );
        assert_eq!(admitted[0].1, Admission::Groomed);
    }

    #[test]
    fn a_groom_naming_a_different_pair_refuses_this_one() {
        // The admission is keyed to the smell AND the key, not to either alone —
        // otherwise grooming one weakening would licence every other of its kind.
        let found = [smell("waiver-added", "waiver[x]")];
        let admitted = admissions(
            &found,
            &pairs(&["waiver-added waiver[x]"]),
            &Groom::Read(pairs(&["waiver-added waiver[y]"])),
        );
        assert_eq!(admitted[0].1, Admission::Refused);
    }

    #[test]
    fn a_groom_alone_admits_nothing_without_a_trailer() {
        // The other direction of "they AGREE": a groomed clause that no commit
        // names is a plan, not a declaration, and the trailer is the half that
        // travels to CI.
        let found = [smell("waiver-added", "waiver[x]")];
        let admitted = admissions(
            &found,
            &BTreeSet::new(),
            &Groom::Read(pairs(&["waiver-added waiver[x]"])),
        );
        assert_eq!(admitted[0].1, Admission::Refused);
    }

    #[test]
    fn one_unadmitted_smell_leaves_the_others_admitted() {
        // Each smell is adjudicated on its own evidence; the caller decides the
        // verdict over the set. Collapsing them here would make one ungroomed
        // weakening hide which of the others were fine.
        let found = [
            smell("waiver-added", "waiver[x]"),
            smell("rule-predicate-changed", "rule[r].tools"),
        ];
        let admitted = admissions(
            &found,
            &pairs(&["waiver-added waiver[x]"]),
            &Groom::Read(pairs(&["waiver-added waiver[x]"])),
        );
        assert_eq!(admitted[0].1, Admission::Groomed);
        assert_eq!(admitted[1].1, Admission::Refused);
    }

    #[test]
    fn the_receipts_issue_key_is_provenance_and_not_part_of_the_pair() {
        let dir = std::env::temp_dir().join("batten-lint-groom");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(crate::claim::receipt_name("user/x")),
            "CLOUD-1\nready-lint pass\nweakens CLOUD-1 waiver-added waiver[x]\n",
        )
        .unwrap();
        assert_eq!(
            groom(&dir, Some("user/x")),
            Groom::Read(pairs(&["waiver-added waiver[x]"])),
        );
        // And the two could-not-look arms, which no receipt content can produce.
        assert_eq!(groom(&dir, Some("user/absent")), Groom::Unreadable);
        assert_eq!(groom(&dir, None), Groom::Unreadable);
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
        let found = smells(text, "test", None, today(), &[]).unwrap();
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
        let found = smells("version = 1\n", "test", Some(&base), today(), &[]).unwrap();
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
        let found = smells("version = 1\n", "test", Some(&base), today(), &[]).unwrap();
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
        let found = smells(&working, "test", Some(&base), today(), &[]).unwrap();
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
        assert!(smells(text, "test", None, today(), &[]).unwrap().is_empty());
    }

    #[test]
    fn the_report_is_sorted_and_so_byte_stable() {
        let text = "version = 1\nunlanded = []\nscope = []\nprotected = []\n";
        let found = smells(text, "test", None, today(), &[]).unwrap();
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
        let earlier = smells(&text, "test", None, Date::parse("2026-01-01").unwrap(), &[]).unwrap();
        assert!(earlier.is_empty());
    }

    #[test]
    fn the_waiver_pointer_names_the_line_the_rule_key_sits_on() {
        let text = with_waivers(&waiver_row("typo", "2099-01-01"));
        let found = smells(&text, "test", None, today(), &[]).unwrap();
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

    /// A config declaring one `judge` rule, plus whatever waiver rows follow.
    ///
    /// `judge` is the one kind left outside [`crate::waiver::reaches`] since
    /// CLOUD-610, so it is the only fixture this smell can be exercised with. It
    /// reads no `severity` — a judge row is refused that column, which is exactly
    /// why it can decide nothing and why a waiver over it suppresses nothing.
    fn with_judge_rule(waivers: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"intentional\"\nkind = \"judge\"\n\
             glob = \"**/*.rs\"\ncriteria = \"does this read as intentional\"\n\
             tier = \"advisory\"\nno_fix_reason = \"answered by a person\"\n{waivers}"
        )
    }

    /// A config declaring one `shape` rule, plus whatever waiver rows follow.
    ///
    /// A shape row reads no `glob` — it matches a mediated command line — so it
    /// is spelled out rather than reusing [`with_waivers`]'s forbid row.
    fn with_shape_rule(waivers: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"no-merge\"\nkind = \"shape\"\n\
             scope = \"mediated_call\"\npattern = \"gh pr merge\"\n\
             reason = \"land by fast-forward\"\nseverity = \"deny\"\n{waivers}"
        )
    }

    #[test]
    fn a_waiver_over_a_kind_that_can_decide_nothing_is_a_smell() {
        // The rule exists and the expiry is live, so neither sibling smell fires
        // — and the waiver still suppresses nothing, because a judge row mints no
        // finding for `apply` to filter and renders no `Decision` for the hook to
        // suppress.
        let text = with_judge_rule(&waiver_row("intentional", "2099-01-01"));
        assert_eq!(ids(&text), vec![WAIVER_UNREACHABLE_KIND]);
    }

    #[test]
    fn the_unreachable_pointer_names_the_waiver_and_the_kind() {
        let text = with_judge_rule(&waiver_row("intentional", "2099-01-01"));
        let found = smells(&text, "test", None, today(), &[]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].line_text(),
            "batten.toml:waiver[intentional] judge waiver-unreachable-kind"
        );
        assert!(
            !found[0].line_text().contains("tracked"),
            "the pointer must never carry the justification text"
        );
        assert!(
            !found[0].line_text().contains("intentional\""),
            "nor the criteria the waived rule judges by"
        );
    }

    #[test]
    fn a_waiver_over_a_reachable_kind_is_not_the_smell() {
        // The half that keeps the lint worth reading: it must not fire on every
        // waiver in the file. `forbid` mints findings, so its waiver is live.
        let text = with_waivers(&waiver_row("r", "2099-01-01"));
        assert!(ids(&text).is_empty());
    }

    #[test]
    fn a_waiver_over_a_mediated_kind_stopped_being_the_smell_with_cloud_610() {
        // The retirement CLOUD-610 bought, asserted rather than assumed: the flip
        // is one line in `waiver::reaches` and this is the surface that proves the
        // set was READ from there and not restated here. A `shape` row is now
        // waivable, because `hook::adjudicate` consults the same table.
        let text = with_shape_rule(&waiver_row("no-merge", "2099-01-01"));
        assert!(ids(&text).is_empty());
    }

    #[test]
    fn a_narrowed_and_a_whole_rule_waiver_of_one_kind_both_survive_dedup() {
        // CLOUD-233's shape again: two waivers of ONE rule are located by the
        // same line, so a line-keyed pointer would collapse them. The waiver key
        // distinguishes them by the path they narrow to.
        let text = with_judge_rule(&format!(
            "{}\n[[waiver]]\nrule = \"intentional\"\nreason = \"tracked\"\n\
             expires = \"2099-01-01\"\npath = \"vendor/**\"\n",
            waiver_row("intentional", "2099-01-01")
        ));
        let found = smells(&text, "test", None, today(), &[]).unwrap();
        assert_eq!(
            found.iter().map(Smell::line_text).collect::<Vec<_>>(),
            vec![
                "batten.toml:waiver[intentional] judge waiver-unreachable-kind",
                "batten.toml:waiver[intentional][vendor/**] judge waiver-unreachable-kind",
            ]
        );
    }

    #[test]
    fn an_unreachable_waiver_that_also_lapsed_carries_both_smells() {
        // Separately actionable, and reported separately: fixing the expiry must
        // not hide the fact that the row could never have applied.
        let text = with_judge_rule(&waiver_row("intentional", "2020-01-01"));
        let mut found = ids(&text);
        found.sort_unstable();
        assert_eq!(found, vec![WAIVER_EXPIRED, WAIVER_UNREACHABLE_KIND]);
    }

    #[test]
    fn adding_a_waiver_reaches_the_lint_as_a_base_ref_weakening() {
        // The added-direction weakening arrives through the one definition of
        // "weakened" rather than a second copy in this module.
        let base = config::parse(&with_waivers(""), "base").unwrap();
        let working = with_waivers(&waiver_row("r", "2099-01-01"));
        let found = smells(&working, "test", Some(&base), today(), &[]).unwrap();
        let ids: Vec<&str> = found.iter().map(|smell| smell.id).collect();
        assert!(ids.contains(&"waiver-added"), "got: {ids:?}");
    }

    #[test]
    fn a_malformed_config_is_a_usage_error() {
        let err = smells("version = 1\nnot toml\n", "test", None, today(), &[]).unwrap_err();
        assert!(err.downcast_ref::<crate::UsageError>().is_some());
    }
}
