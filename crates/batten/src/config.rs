//! The `batten.toml` loader (house-style §8).
//!
//! Configuration is **one committed authority** — the repo `batten.toml` — plus
//! raise-only overrides (env, flags, a git-ignored `batten.local.toml`). This
//! module loads and validates *one file*; [`crate::resolve`] layers the files
//! and the overrides in the §8 precedence order and applies the raise-only
//! clamp (the standalone config-lint predicate over that clamp is CLOUD-87).
//!
//! The surface is deliberately narrow (non-negotiable rule 6): the config is a
//! typed struct with **no unknown keys** — a typo is an error, not a silently
//! ignored setting — and a required schema `version` so an incompatible file
//! fails loudly rather than being half-understood.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::Rule;
use crate::{outputs, waiver};

/// The config schema version this build understands. A file declaring any other
/// version is refused rather than partially interpreted.
pub const SUPPORTED_VERSION: u32 = 1;

/// The committed authority Batten reads: the repo `batten.toml` in the working
/// directory. No upward walk, no `conf.d` merge (§8).
pub const CONFIG_FILE: &str = "batten.toml";

/// How strictly Batten applies its gates — the ordered, policy-bearing key the
/// §8 raise-only rule is defined over.
///
/// The ordering **is** the policy semantics: `Permissive < Standard < Strict`,
/// so "tighten" is the computable predicate `candidate >= current` rather than a
/// judgement call. Derived `Ord` follows declaration order, which is why the
/// variants are declared weakest-first; [`tests::strictness_orders_weakest_first`]
/// pins that so a reordering cannot silently invert the clamp.
///
/// Resolution is this issue's deliverable (CLOUD-29); the verbs that *read* the
/// resolved value attach as they land (`--fail-on-warning` is CLOUD-49).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Deserialize,
    Serialize,
    ValueEnum,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Strictness {
    /// Advisory: findings are reported without failing the run.
    Permissive,
    /// The default: a finding is a violation.
    #[default]
    Standard,
    /// Everything `Standard` fails on, plus anything advisory.
    Strict,
}

/// A parsed, validated `batten.toml`.
///
/// `deny_unknown_fields` makes an unrecognised key a hard error (§8): the config
/// surface stays narrow and a typo can never silently disable a gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The config schema version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// The minimum Batten version permitted to read this file (semver).
    /// Enforced at parse time by [`check_min_version`]: a binary below it is
    /// refused with a [`UsageError`] (→ exit `1`) rather than allowed to report
    /// green over rules it does not understand (CLOUD-33).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
    /// How strictly the gates apply. Absent means "this file does not speak to
    /// strictness", which is what lets [`crate::resolve`] attribute the
    /// effective value to the layer that actually set it. Policy-bearing, so an
    /// override may only raise it (§8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<Strictness>,
    /// Whether a `warn`-severity finding is promoted to a violation (CLOUD-49).
    /// Absent means "this file does not speak to the setting", which is what
    /// lets [`crate::resolve`] attribute the effective value to the layer that
    /// actually set it. Policy-bearing, so an override may only turn it *on*
    /// (§8): `false` over a committed `true` is refused, never applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_warning: Option<bool>,
    /// The declarative rules run against the repository. Absent or empty means
    /// "no rules configured" and nothing is reported. Which of these a given
    /// verb admits is the §5 effect split: `check` runs only non-spawning kinds
    /// and refuses the rest, `enforce` runs all of them (CLOUD-170).
    ///
    /// Every rule pins its `severity` explicitly — the key is required, with no
    /// implicit fallback — and carries a separate `scope` key whose vocabulary
    /// never conflates with severity's (CLOUD-61). Both disciplines are
    /// enforced at parse time: omission or conflation is a usage error here,
    /// never a value quietly assumed.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// The paths policy applies to, as an **ordered include/exclude list**: a
    /// plain glob includes, a `!`-prefixed glob excludes, and an exclude beats
    /// an include (CLOUD-37). Absent or empty means the set is empty — nothing
    /// is in scope — not "everything", because a set that silently defaults to
    /// universal membership is the widening a policy engine must never do.
    ///
    /// Not to be confused with [`Rule::scope`] ([`crate::rules::RuleScope`]),
    /// which is a per-rule axis saying *where a rule looks*. The two share a
    /// token and nothing else; their vocabularies never cross, exactly as
    /// severity's three axes do not (see [`crate::severity`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Paths whose modification is guarded. A plain include set — no `!`
    /// entries — evaluated independently of [`Config::scope`] and
    /// [`Config::unlanded`]. CLOUD-31's config-trust diff defends this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<String>,
    /// Paths whose work is not yet landed. A plain include set, evaluated
    /// independently of the other two: a path may be `unlanded` without being
    /// `protected`, and the sets must never be collapsed (CLOUD-37).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlanded: Vec<String>,
    /// Which files make up the governing config surface the `config_epoch`
    /// hashes (CLOUD-32). Absent means the default: this file alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<Epoch>,
    /// The mutating-verb table (CLOUD-36): which programs change the world, in
    /// the one §5 effect vocabulary. Consumer-specific by nature, so it lives
    /// here and never in the crate (non-negotiable rule 1); the type and its
    /// lookup are [`crate::verbs`].
    #[serde(default, rename = "verb", skip_serializing_if = "Vec::is_empty")]
    pub verbs: Vec<crate::verbs::MutatingVerb>,
    /// Output predicates over a wrapped command's captured streams (CLOUD-117):
    /// literals that, found in `batten exec`'s output, promote a lying exit `0`
    /// to a violation. Consumer-specific by nature — which warning means
    /// not-actually-done is a property of the tools a repository runs — so it
    /// lives here and never in the crate (non-negotiable rule 1). The type and
    /// the predicate are [`crate::outputs`].
    #[serde(
        default,
        rename = "exec_pattern",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exec_patterns: Vec<crate::outputs::OutputPattern>,
    /// The suppression markers to count (CLOUD-36). Which comment shape waves
    /// a rule through is a property of the repository being gated, never of
    /// Batten; the type and the counting are [`crate::markers`].
    #[serde(default, rename = "marker", skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<crate::markers::Marker>,
    /// The designed escape hatch (CLOUD-208): per-rule waivers, each carrying a
    /// required justification and a required expiry.
    ///
    /// A waiver suppresses findings of the rule it names, and **lapses on its own
    /// date** — which is what makes the suppression set stop growing
    /// monotonically without anyone having to look at it. Not a severity: the
    /// filter runs over findings before the verdict, and [`crate::severity`]'s
    /// three axes are untouched. The type and the predicate are
    /// [`crate::waiver`].
    #[serde(default, rename = "waiver", skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<crate::waiver::Waiver>,
    /// The thresholds this repository holds itself to (CLOUD-50). Today one:
    /// `[budget.instructions]`, the always-loaded instruction set and what it
    /// may cost. Absent means no budget is declared and none is enforced — a
    /// threshold nobody wrote down is not a threshold of zero. The type and the
    /// predicate are [`crate::budget`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
    /// The ref work must land on (CLOUD-51) — the target `worktree status`
    /// judges at-risk work against. Consumer-specific by nature: which ref is
    /// the trunk is a property of the repository being gated, never of Batten
    /// (non-negotiable rule 1), so the core ships no default and an absent key
    /// means the gate has no target rather than a guessed one.
    ///
    /// Deliberately not [`Config::unlanded`], which is a path-membership set the
    /// rule engine evaluates over tree content. The two are orthogonal — one is
    /// VCS state, the other is which paths policy calls unlanded — and folding
    /// them together would give one key two meanings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_land_on: Option<String>,
    /// The optional LLM judge's payload-privacy boundary (CLOUD-135): what may
    /// cross into a model call. Absent means no judge is configured; present and
    /// empty means pointers and hashes only, which is also what every field
    /// defaults to. The type and the pure builder are [`crate::judge`].
    ///
    /// This table lands **before** the judge that reads it, deliberately: a
    /// boundary written after the code it bounds is a boundary that code has
    /// already crossed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::judge::Judge>,
    /// The merge contract this repository commits to (CLOUD-54), **derived**
    /// from the host ruleset. Absent means the contract is not projected here;
    /// present, it is what `config lint --host-rules` compares against. The host
    /// is always the authority — this is a copy a gate polices, never a second
    /// place the fact is decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<crate::ci::Ci>,
    /// The append-only defect ledger (CLOUD-52): where it lives and what may be
    /// in it. Absent means this repository keeps no in-tree ledger and the gate
    /// is simply not active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defects: Option<crate::defects::Defects>,
    /// Pinned tools this repository provisions (CLOUD-90): version, URL,
    /// checksum, unpack behaviour, binary name. Consumer-specific by nature —
    /// which tools a repository needs is that repository's business, never
    /// Batten's (non-negotiable rule 1) — so the core carries the mechanism and
    /// this table carries the answer. The type and both halves of the
    /// check/fix pair are [`crate::provision`].
    #[serde(default, rename = "provision", skip_serializing_if = "Vec::is_empty")]
    pub provisions: Vec<crate::provision::Provision>,
    /// The completed-session transcript this repository points `check` at
    /// (CLOUD-95). Host-specific, never consumer-specific: which file a host
    /// writes its transcript to is a property of the harness, not of any one
    /// repository, so rule 1 holds. Absent means the repository does not use
    /// the capability — a different claim from a path that resolves to
    /// nothing, which is why `resolve` answers with three states and not two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<crate::transcript::TranscriptConfig>,
}

/// The `[epoch]` table: which files govern this repository.
///
/// Declared as **config** rather than compiled in, because which files govern a
/// repository is that repository's business: an agent settings file, a
/// contributor guide, a hook config — each meaningful in one repository and
/// meaningless in the next. The core therefore carries only the default (this
/// file), and every consumer's own list lives in that consumer's own config, so
/// a grep of `crates/batten` for any consumer's identifiers returns nothing
/// (non-negotiable rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    /// Repo-relative paths whose bytes the epoch covers. Order is irrelevant —
    /// [`crate::epoch::tracked_paths`] sorts and deduplicates, so the value is a
    /// function of the set rather than of how it was written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked: Vec<String>,
}

/// Parse and validate a `batten.toml` from `text`, attributing errors to
/// `source` (a path or label) in their messages.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed file, an unknown key,
/// or an unsupported [`Config::version`]. These are bad *input*, not internal
/// failures.
pub fn parse(text: &str, source: &str) -> Result<Config> {
    let config = parse_ungated(text, source)?;
    check_min_version(&config, source)?;
    Ok(config)
}

/// The override surface: exactly what `batten.local.toml` may carry.
///
/// A **second type**, not a second reading of [`Config`], and that is the whole
/// point (CLOUD-239). The subset used to exist only as `local.*` reads inside
/// [`crate::resolve`] — invisible to a validator, so the published schema
/// vouched for keys the loader silently dropped and for one it refused outright.
/// With the surface written as a type, the schema derives from it and the two
/// cannot disagree.
///
/// `deny_unknown_fields` is what makes the refusal total and free: every
/// authority-only key (`epoch`, `marker`, `verb`, `budget`, `must_land_on`,
/// `judge`, `ci`, `defects`, `provision`, `transcript`) becomes a hard parse
/// error here rather than a silently discarded tightening. A hand-maintained
/// refusal list would be a second authority, and would drift the moment a field
/// is added to [`Config`].
///
/// Every key here is **raise-only**; [`crate::resolve`] holds that invariant,
/// and the per-field docs say which direction "raise" means.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverrideConfig {
    /// The schema version, required exactly as the authority requires it.
    pub version: u32,
    /// Present only so the refusal can name it.
    ///
    /// Carried as a field rather than left to `deny_unknown_fields` because
    /// "authority-only, an override may not restate it" tells the author what
    /// they did wrong, where "unknown field" would suggest a typo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
    /// Raised, never lowered: a committed `strict` cannot be relaxed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<Strictness>,
    /// Raised, never lowered: a committed `true` cannot be turned off here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_warning: Option<bool>,
    /// Rules this file **adds**. Redefining a committed id is refused.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Scope narrowing, and **excludes only** — a plain include is refused.
    ///
    /// Includes union, so a local include could only ever *widen* the set,
    /// which is exactly what §8's raise-only clause forbids. Excludes are purely
    /// subtractive, so appending them to the authority's ordered list is
    /// provably narrowing and needs no reasoning about entry order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    /// Protected paths this file **adds** — §8's "add protected paths" verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<String>,
    /// Unlanded paths this file **adds**; an include-only set, like `protected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unlanded: Vec<String>,
    /// `exec` output predicates this file **adds**. A duplicate id is refused.
    #[serde(
        default,
        rename = "exec_pattern",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exec_patterns: Vec<outputs::OutputPattern>,
    /// Waivers this file adds, for rules the authority does not declare. A
    /// waiver over a committed rule lowers that bar and is refused.
    #[serde(default, rename = "waiver", skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<waiver::Waiver>,
}

/// Parse an *override* layer, without the [`Config::min_batten_version`] gate.
///
/// `min_batten_version` is an **authority-only** key: [`crate::resolve`] refuses
/// a `batten.local.toml` that sets it at all. Gating on it here would fire
/// first and replace that refusal — telling an author their binary is too old
/// when the real problem is that they set the key in a file that may not carry
/// it. The more specific message is the useful one, so the override layer parses
/// ungated and lets the authority-only check speak.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed file, an unsupported
/// `version`, a table that fails its own validator, or **any key outside the
/// override surface** — including one that is perfectly valid in the file it was
/// copied from, which is the case this type exists to catch.
pub fn parse_override(text: &str, source: &str) -> Result<OverrideConfig> {
    let config: OverrideConfig = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    if config.version != SUPPORTED_VERSION {
        return Err(UsageError::raise(format!(
            "unsupported config version {} in {source}; this build supports version {SUPPORTED_VERSION}",
            config.version
        )));
    }
    // The same validators the authority runs, over the same tables. An override
    // row is a policy row: one that loads here and gates nothing is the defect
    // CLOUD-242 named, and it does not become acceptable for being uncommitted.
    crate::rules::validate(&config.rules)?;
    crate::outputs::validate(&config.exec_patterns)?;
    crate::waiver::validate(&config.waivers)?;
    Ok(config)
}

/// The override surface's JSON schema, derived from [`OverrideConfig`].
///
/// A second artifact rather than a second reading of the first: `.taplo.toml`
/// binds `batten.local.toml` to this one, so an editor and `taplo lint` agree
/// with the loader about which keys that file may carry.
///
/// # Errors
///
/// Returns an error when the schema cannot be serialized.
pub fn override_schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        OverrideConfig
    ))?)
}

/// The shared body: deserialize and check the schema `version`.
fn parse_ungated(text: &str, source: &str) -> Result<Config> {
    let config: Config = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    if config.version != SUPPORTED_VERSION {
        return Err(UsageError::raise(format!(
            "unsupported config version {} in {source}; this build supports version {SUPPORTED_VERSION}",
            config.version
        )));
    }
    // The verb table is validated here, at load, because nothing else validates
    // it anywhere: `verbs::validate` had no caller outside its own tests, so a
    // `[[verb]]` row that is inert — `effect = "read"` in a table named for
    // mutation, matching nothing while reading as covered — loaded clean, as did
    // a verb declared twice. A refusal with no call site is prose (non-negotiable
    // rule 2), and this one was asserted present by a doc comment, a merged PR
    // body and a passing test that reached past `parse` to call the validator by
    // hand (CLOUD-242).
    //
    // In `parse_ungated` rather than `parse` so an override layer is held to it
    // too: `batten.local.toml` may add verb rows, and a raise-only override that
    // adds an inert one has still written something that cannot mean anything.
    crate::verbs::validate(&config.verbs)?;
    // And the marker table, for the identical reason in the identical shape
    // (CLOUD-253). Both tables arrived in one commit; CLOUD-242 wired one of
    // them up and nobody checked the sibling, so an empty `token` — which
    // matches every line of every file — still loaded clean. The completeness
    // test below is what stops the next table arriving orphaned the same way.
    crate::markers::validate(&config.markers)?;
    // And the rule table, which used to be validated only by the runner that
    // happened to evaluate it (CLOUD-48). That was defensible while the tree
    // engine was the only runner; `batten hook` is now a second one, and a
    // malformed `mediated_call` row validated only by `check` is a policy row
    // that loads, matches nothing at the mediation channel, and reads as
    // coverage. `run_rule` still calls `Rule::validate` as defence in depth.
    crate::rules::validate(&config.rules)?;
    crate::outputs::validate(&config.exec_patterns)?;
    // And the waiver table, where the stakes are inverted from every other row
    // here: a malformed rule fails to gate, but a malformed *waiver* is a hatch
    // whose expiry nobody could read. Refusing at load is what makes "every
    // waiver carries an expiry" true of the resolved config rather than aspirational.
    crate::waiver::validate(&config.waivers)?;
    // `[budget]` is a table rather than a list, so the census below (which scans
    // `Vec<T>` fields) does not reach it — but the failure it guards against is
    // the same one: a table that parses and gates nothing. A `[budget]` header
    // with no `[budget.instructions]` under it is refused here (CLOUD-50).
    crate::budget::validate(config.budget.as_ref())?;
    // Validated at parse, like `[[verb]]` and `[[marker]]`: CLOUD-242's lesson
    // is that a table nothing validates is coverage that means nothing.
    if let Some(ci) = &config.ci {
        ci.validate()?;
    }
    if let Some(defects) = &config.defects {
        defects.validate()?;
    }
    // `[transcript]` is a table too, so the census does not reach it either; the
    // guarded failure is a `path` key present and blank, which would resolve to
    // the repository root and read as an unparseable transcript (CLOUD-95).
    crate::transcript::validate(config.transcript.as_ref())?;
    // A pin that can never match, a name that owns a cache path twice, an empty
    // required field: each is refused here rather than at fetch time, where the
    // failure would blame the artifact for a typo in this file.
    crate::provision::validate(&config.provisions)?;
    Ok(config)
}

/// The version of the running binary, as `Cargo.toml` declares it.
///
/// Read from the compiled-in package version rather than re-typed, so the gate
/// compares against the build that is actually running.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Refuse a config this build is too old to honour (CLOUD-33).
///
/// `min_batten_version` is the config author's statement of the oldest binary
/// that understands the file. A binary below it cannot honour the policy the
/// file describes — and a gate that runs anyway is worse than one that refuses,
/// because it reports green over rules it silently did not understand.
///
/// This is [`UsageError`] (→ exit `1`), the same class as an unreadable or
/// unsupported-version config: bad *input* for this binary, never a
/// [`crate::ExitCode::Violation`]. A violation is a verdict about the
/// repository; refusing to run is a statement about the invocation, and
/// conflating them would have a harness read "this binary is too old" as
/// "policy denied this call" (§7).
///
/// Equal-or-newer runs. An unparseable version on either side is refused rather
/// than skipped, because "cannot compare" is not "compatible".
fn check_min_version(config: &Config, source: &str) -> Result<()> {
    let Some(required) = config.min_batten_version.as_deref() else {
        return Ok(()); // The file does not speak to a minimum: nothing to gate.
    };
    let required = semver::Version::parse(required).map_err(|err| {
        UsageError::raise(format!(
            "invalid min_batten_version {required:?} in {source}: {err}"
        ))
    })?;
    let running = semver::Version::parse(VERSION)
        .map_err(|err| UsageError::raise(format!("invalid build version {VERSION:?}: {err}")))?;
    if running < required {
        return Err(UsageError::raise(format!(
            "{source} requires batten {required} or newer; this build is {VERSION}"
        )));
    }
    Ok(())
}

/// The JSON Schema for `batten.toml`, derived from [`Config`].
///
/// Derived, never hand-authored (CLOUD-33, `DoR` §1): the schema is generated
/// from the very types `parse` deserializes into, so it cannot describe a
/// config this binary would refuse — nor miss a key it accepts.
///
/// Emitted as byte-stable pretty JSON (§6): `schemars` orders properties
/// deterministically, so identical input yields identical bytes and the drift
/// gate never fails at random.
///
/// # Errors
///
/// Returns an error only if serialization itself fails, which for this
/// data-only tree does not occur in practice.
pub fn schema() -> Result<String> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        Config
    ))?)
}

impl Config {
    /// A config that declares no policy at all.
    ///
    /// Deliberately not a [`Default`] impl. `version` has exactly one accepted
    /// value ([`SUPPORTED_VERSION`]), so a derived default would produce a
    /// `Config` carrying `0` that no loader would accept — a value that looks
    /// like a config and is not one. Written as a literal rather than parsed from
    /// a string constant so it needs no fallible path and no `expect`, and so
    /// that a field added to [`Config`] fails to compile here until someone
    /// decides what "declares nothing" means for it.
    ///
    /// Used where an **absent or unreadable** authority still has to be compared
    /// against a trusted one (CLOUD-243): granting nothing is exactly what an
    /// authority that cannot be read grants, so this is the honest comparand —
    /// every key the trusted side declares then reports as removed.
    #[must_use]
    pub fn declaring_nothing() -> Self {
        Config {
            version: SUPPORTED_VERSION,
            min_batten_version: None,
            strictness: None,
            fail_on_warning: None,
            rules: Vec::new(),
            scope: Vec::new(),
            protected: Vec::new(),
            unlanded: Vec::new(),
            epoch: None,
            verbs: Vec::new(),
            markers: Vec::new(),
            exec_patterns: Vec::new(),
            waivers: Vec::new(),
            // An authority that declares no budget grants no exemption from one
            // either — there is simply no threshold, which is what `None` says.
            budget: None,
            must_land_on: None,
            judge: None,
            ci: None,
            defects: None,
            provisions: Vec::new(),
            // Declaring no transcript is the ordinary case, and it is not the
            // same as pointing at one that is missing: the first says the
            // capability was never claimed, the second that it was claimed and
            // is unavailable. Only the second is worth reporting.
            transcript: None,
        }
    }
}

/// Load and validate the `batten.toml` at `path`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the file is missing, malformed,
/// carries an unknown key, or declares an unsupported version. A non-`NotFound`
/// I/O failure propagates as an internal error (→ exit `3`).
pub fn load(path: &Path) -> Result<Config> {
    parse(&read(path)?, &path.display().to_string())
}

/// Load an *override* layer, without the [`Config::min_batten_version`] gate.
///
/// See [`parse_override`] for why the override layer is ungated.
///
/// # Errors
///
/// As [`load`], minus the version gate.
pub fn load_override(path: &Path) -> Result<OverrideConfig> {
    parse_override(&read(path)?, &path.display().to_string())
}

/// Read a config file, mapping a missing file to a [`UsageError`] and any other
/// I/O failure to an internal error (→ exit `3`).
fn read(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(UsageError::raise(format!(
            "no config found at {}",
            path.display()
        ))),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::error::UsageError;

    /// Tables whose entries are proven well formed at load, and the call in
    /// [`parse_ungated`] that does it. Deleting a call fails the test below.
    const VALIDATED_AT_LOAD: &[(&str, &str)] = &[
        ("verbs", "crate::verbs::validate("),
        ("markers", "crate::markers::validate("),
        ("rules", "crate::rules::validate("),
        ("exec_patterns", "crate::outputs::validate("),
        ("provisions", "crate::provision::validate("),
        ("waivers", "crate::waiver::validate("),
    ];

    /// Tables proven well formed somewhere else, each with the reason. Listing
    /// an exemption is the point: a reader sees the justification rather than
    /// an absence, which is what an orphaned validator looks like.
    const VALIDATED_BY_ITS_RUNNER: &[(&str, &str)] = &[];

    #[test]
    fn every_typed_config_table_has_a_validation_call_site() {
        // The class behind CLOUD-242 and CLOUD-253: a validator whose only
        // caller is its own tests refuses nothing, while a doc comment, a PR
        // body and a passing test all say it does. Both tables shipped in one
        // commit; the first fix wired up one of them, and nothing here noticed
        // the other for a day. One reviewed list per destiny plus this
        // completeness check is the idiom `effect.rs` and `RuleKind::ALL`
        // already use — a new table must be classified or this fails.
        //
        // A `Vec<String>` field is a glob list with no typed entry to validate,
        // so it is exempt by its element type rather than by a third hand-kept
        // list that could itself go stale.
        let source = include_str!("config.rs");
        let struct_body = {
            let start = source
                .find("pub struct Config {")
                .expect("Config is declared here");
            let rest = &source[start..];
            &rest[..rest.find("\n}").expect("the struct closes")]
        };
        let parse_body = {
            let start = source
                .find("fn parse_ungated")
                .expect("the shared parse body is declared here");
            let rest = &source[start..];
            &rest[..rest.find("\n}").expect("the function closes")]
        };

        let mut seen = Vec::new();
        for line in struct_body.lines() {
            let Some(rest) = line.trim().strip_prefix("pub ") else {
                continue;
            };
            let Some((field, element)) = rest.split_once(": Vec<") else {
                continue;
            };
            if element.starts_with("String") {
                continue;
            }
            seen.push(field);

            let at_load = VALIDATED_AT_LOAD.iter().find(|(name, _)| *name == field);
            let by_runner = VALIDATED_BY_ITS_RUNNER
                .iter()
                .any(|(name, _)| *name == field);
            assert!(
                at_load.is_some() != by_runner,
                "config table `{field}` is in neither list (or both). Say where its entries \
                 are proven well formed: at load, or by the runner that evaluates them. A \
                 table nothing validates is a refusal that cannot fire (CLOUD-253)."
            );
            if let Some((_, call)) = at_load {
                assert!(
                    parse_body.contains(call),
                    "config table `{field}` is listed as validated at load, but \
                     `parse_ungated` does not call `{call}`."
                );
            }
        }

        assert!(
            !seen.is_empty(),
            "the struct scan must actually find tables"
        );
        for (name, _) in VALIDATED_AT_LOAD.iter().chain(VALIDATED_BY_ITS_RUNNER) {
            assert!(
                seen.contains(name),
                "`{name}` is listed but is no longer a Config table; drop the stale entry."
            );
        }
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn minimal_config_parses() {
        let config = parse("version = 1\n", "test").unwrap();
        assert_eq!(config.version, 1);
        assert_eq!(config.min_batten_version, None);
    }

    #[test]
    fn optional_fields_round_trip() {
        let config = parse("version = 1\nmin_batten_version = \"0.0.0\"\n", "test").unwrap();
        assert_eq!(config.min_batten_version.as_deref(), Some("0.0.0"));
    }

    #[test]
    fn strictness_orders_weakest_first() {
        // The raise-only clamp is `candidate >= current` over this ordering, so
        // an accidental reordering of the variants would invert "tighten" into
        // "weaken" without any other test noticing.
        assert!(Strictness::Permissive < Strictness::Standard);
        assert!(Strictness::Standard < Strictness::Strict);
        assert_eq!(Strictness::default(), Strictness::Standard);
    }

    #[test]
    fn strictness_round_trips_through_toml() {
        let config = parse("version = 1\nstrictness = \"strict\"\n", "test").unwrap();
        assert_eq!(config.strictness, Some(Strictness::Strict));
    }

    #[test]
    fn unknown_strictness_value_is_a_usage_error() {
        let err = parse("version = 1\nstrictness = \"whatever\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn fail_on_warning_round_trips_through_toml() {
        // The config surface of the one promotion setting (CLOUD-49). Absent is
        // distinct from `false`: only the former lets a later layer claim the key.
        let config = parse("version = 1\nfail_on_warning = true\n", "test").unwrap();
        assert_eq!(config.fail_on_warning, Some(true));
        let off = parse("version = 1\nfail_on_warning = false\n", "test").unwrap();
        assert_eq!(off.fail_on_warning, Some(false));
        assert_eq!(
            parse("version = 1\n", "test").unwrap().fail_on_warning,
            None
        );
    }

    #[test]
    fn a_non_boolean_fail_on_warning_is_a_usage_error() {
        // The key's vocabulary is TOML's own boolean literals; a string that
        // merely looks like one is bad input, not a value to coerce. This is the
        // same typing discipline `version = "1"` is held to above.
        for value in ["\"true\"", "1", "\"yes\""] {
            let err =
                parse(&format!("version = 1\nfail_on_warning = {value}\n"), "test").unwrap_err();
            assert!(
                is_usage_error(&err),
                "fail_on_warning = {value} must be refused"
            );
        }
    }

    #[test]
    fn unknown_key_is_a_usage_error() {
        let err = parse("version = 1\nbogus = true\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "unknown key must be a usage error");
    }

    #[test]
    fn unsupported_version_is_a_usage_error() {
        let err = parse("version = 2\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("unsupported config version 2"));
    }

    #[test]
    fn missing_version_is_a_usage_error() {
        let err = parse("min_batten_version = \"0.0.0\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn malformed_toml_is_a_usage_error() {
        // A syntactic parse failure is bad input (→ exit 1), not an internal error.
        let err = parse("version = = 1\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "malformed TOML must be a usage error");
    }

    #[test]
    fn wrong_value_type_is_a_usage_error() {
        // `version` is a u32; a string must be refused rather than coerced. This
        // pins the parser's typing behaviour — the surface a `toml` bump is most
        // likely to shift silently (see auto-dependabot-land.yml).
        let err = parse("version = \"1\"\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "type mismatch must be a usage error");
    }

    #[test]
    fn duplicate_key_is_a_usage_error() {
        // TOML forbids a key defined twice; ensure that stays a hard error and is
        // not last-wins-silently coerced by a future parser.
        let err = parse("version = 1\nversion = 1\n", "test").unwrap_err();
        assert!(is_usage_error(&err), "duplicate key must be a usage error");
    }

    #[test]
    fn error_message_attributes_the_source() {
        // Parse errors must name their source so a consumer can locate the file.
        let err = parse("version = = 1\n", "some/path/batten.toml").unwrap_err();
        assert!(
            err.to_string().contains("some/path/batten.toml"),
            "parse error must attribute its source, got: {err}"
        );
    }

    #[test]
    fn missing_file_is_a_usage_error() {
        let err = load(Path::new("does/not/exist/batten.toml")).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn the_committed_example_loads() {
        // The shipped batten.example.toml must actually load (DoD: it round-trips).
        let example = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../batten.example.toml");
        let config = load(&example).expect("batten.example.toml loads");
        assert_eq!(config.version, SUPPORTED_VERSION);
    }

    /// A well-formed rule table with the given `severity` and `scope` lines
    /// spliced in, for the explicit-defaults and conflation cases below.
    fn rule_config(severity_line: &str, scope_line: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"r\"\nkind = \"forbid\"\nglob = \"**\"\n\
             pattern = \"x\"\n{severity_line}{scope_line}"
        )
    }

    #[test]
    fn a_rule_with_explicit_severity_and_scope_parses() {
        let config = parse(
            &rule_config("severity = \"warn\"\n", "scope = \"tree\"\n"),
            "test",
        )
        .unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].severity,
            crate::severity::RuleSeverity::Warn
        );
        assert_eq!(config.rules[0].scope, crate::rules::RuleScope::Tree);
    }

    #[test]
    fn a_rule_omitting_severity_is_a_usage_error() {
        // The explicit-defaults discipline (CLOUD-61): a committed rule states
        // its severity or the file does not parse. No implicit fallback exists
        // for the parser to fall into.
        let err = parse(&rule_config("", "scope = \"tree\"\n"), "test").unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("severity"),
            "the refusal must name the missing key, got: {err}"
        );
    }

    #[test]
    fn a_severity_token_in_the_scope_key_is_a_usage_error() {
        // Scope ≠ severity: the two keys' vocabularies never cross, so writing
        // one axis's value into the other key is bad input, not a lenient read.
        for token in ["deny", "warn", "allow"] {
            let err = parse(
                &rule_config("severity = \"deny\"\n", &format!("scope = \"{token}\"\n")),
                "test",
            )
            .unwrap_err();
            assert!(is_usage_error(&err), "scope = \"{token}\" must be refused");
        }
    }

    #[test]
    fn a_scope_token_in_the_severity_key_is_a_usage_error() {
        let err = parse(&rule_config("severity = \"tree\"\n", ""), "test").unwrap_err();
        assert!(is_usage_error(&err), "severity = \"tree\" must be refused");
    }
}
