//! Config resolution: one committed authority plus raise-only overrides (§8).
//!
//! The repo `batten.toml` is the single committed **authority**. Env vars,
//! command-line flags, and a git-ignored [`LOCAL_CONFIG_FILE`] are **overrides**.
//! There is no upward directory walk and no `conf.d` merge — the local file is a
//! single amends-style override, never a merged tree.
//!
//! Two properties are load-bearing:
//!
//! * **Precedence is declared as data.** [`SETTINGS`] states, per key, its env
//!   var and its flag; the resolver *reads that table* rather than hard-coding
//!   the names, so the layering is inspectable
//!   instead of being resolution logic buried in the binary. Order is
//!   `flag > env > local file > repo config > default` — exactly the [`Source`]
//!   declaration order.
//! * **Overrides are raise-only.** For a policy-bearing key an override may only
//!   *tighten*, never weaken: raising [`Strictness`] is accepted, lowering it is
//!   a [`UsageError`] (→ exit `1`), and the local file may only *add* rules —
//!   redefining a committed rule is refused, so the worst an uncommitted file can
//!   do is make a gate stricter — which is what keeps config the trust boundary
//!   even with a local override present.
//!
//!   That monotonicity is the *same shape* §5 states for effects, but this layer
//!   owns it outright rather than inheriting it: §5's `max_effect` — per-flag
//!   effect annotations and a monotone maximum over them — is **specified, not
//!   implemented**. [`crate::effect::Effect`] is declared per command and
//!   carries no ordering, so there is nothing here to take a maximum of; the
//!   implementation rides CLOUD-27's spec work (CLOUD-217 (22)). Read the
//!   raise-only rule above as load-bearing on its own, not as a corollary of
//!   something already in the tree.
//!
//! `batten config show` prints the resolved config **with its sources**, so
//! which layer won a key is an answer the tool gives rather than one a reader
//! has to reconstruct.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use serde::{Serialize, Serializer};

use crate::config::{self, Strictness};
use crate::error::UsageError;
use crate::rules::Rule;

/// The git-ignored local override file, read from the same directory as the
/// committed authority. Optional: absent simply means "no local override".
pub const LOCAL_CONFIG_FILE: &str = "batten.local.toml";

/// A config layer, declared **weakest-first**: the derived `Ord` is the §8
/// precedence order `flag > env > local file > repo config > default`, so the
/// winning source for a key is the greatest layer that set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The compiled-in default, used when no layer speaks to the key.
    Default,
    /// The committed authority, the repo `batten.toml`.
    RepoConfig,
    /// The git-ignored [`LOCAL_CONFIG_FILE`].
    LocalFile,
    /// A `BATTEN_`-prefixed environment variable.
    Env,
    /// A command-line flag.
    Flag,
}

impl Source {
    /// The stable lowercase token used in machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Default => "default",
            Source::RepoConfig => "repo-config",
            Source::LocalFile => "local-file",
            Source::Env => "env",
            Source::Flag => "flag",
        }
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One key's layering, declared as data (§8) rather than implied by code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SettingSpec {
    /// The `batten.toml` key, and the name used in the emitted `sources` map.
    pub key: &'static str,
    /// The environment variable that overrides it, if any.
    pub env: Option<&'static str>,
    /// The command-line flag that overrides it, if any.
    pub long_flag: Option<&'static str>,
}

/// The declared layering for every overridable key.
///
/// The resolver reads the env var and flag names *from here*, so this table is
/// the definition rather than documentation of one.
///
/// Every key here is policy-bearing and so subject to the raise-only clamp;
/// there is deliberately no per-key "is this policy-bearing" flag, because a
/// flag no code path reads is the declared-but-unenforced drift a policy engine
/// exists to prevent. A key that layers by plain precedence reintroduces the
/// distinction in the change that first needs it — together with the branch
/// that consults it.
pub const SETTINGS: &[SettingSpec] = &[
    SettingSpec {
        key: "strictness",
        env: Some("BATTEN_STRICTNESS"),
        long_flag: Some("--strictness"),
    },
    SettingSpec {
        // The one promotion setting (CLOUD-49), exposed three ways that resolve
        // to a single value. Every consumer reads the resolved value; no verb
        // re-declares a promotion knob of its own, and `batten exec` is
        // deliberately not a consumer at all (CLOUD-117).
        key: "fail_on_warning",
        env: Some("BATTEN_FAIL_ON_WARNING"),
        long_flag: Some("--fail-on-warning"),
    },
    SettingSpec {
        // Rules layer additively: the local file may add a rule, never redefine
        // or remove a committed one. There is no env or flag surface — a policy
        // predicate belongs in a reviewable file, not an ambient variable.
        key: "rule",
        env: None,
        long_flag: None,
    },
];

/// Look up a setting's declaration by key, or `None` for a key [`SETTINGS`]
/// does not declare.
///
/// Absence is a value rather than a panic (CLOUD-300). The alternative was an
/// `expect` exempted from the no-panic lint by a doc comment citing a test that
/// pinned "every key reaching here is declared" — and that test did not exist,
/// so the exemption rested on a mechanism nobody had built. Both callers have a
/// "this layer does not speak to the key" answer already, so handing them one
/// more way to reach it costs nothing and leaves nothing needing a pin.
fn setting(key: &str) -> Option<&'static SettingSpec> {
    SETTINGS.iter().find(|spec| spec.key == key)
}

/// The flag layer: values supplied on the command line, highest precedence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--strictness`, when passed.
    pub strictness: Option<Strictness>,
    /// `--fail-on-warning`, when passed. A bare boolean flag has no "off" form,
    /// so this layer is raise-only by construction: `true` raises, absent says
    /// nothing and lets a lower layer keep the key.
    pub fail_on_warning: bool,
    /// `--config-from <ref>`, when passed. Not a *value* override like the two
    /// above: it selects **where the committed authority is read from** (a git
    /// ref instead of the working tree), leaving the §8 precedence chain
    /// untouched — env, flag and local-file overrides still stack on top under
    /// the same raise-only clamp (CLOUD-31).
    pub config_from: Option<String>,
}

/// The effective configuration, plus the layer that won each key.
///
/// Serialized flat so `config show` reads as the config it is, with `sources`
/// alongside (§8: "prints the effective config with sources"). Field order is
/// fixed and the map is sorted, so the output is byte-stable (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// The schema version of the committed authority.
    pub version: u32,
    /// The minimum Batten version the authority permits (enforcement: CLOUD-33).
    ///
    /// Emitted even when absent — as `null`, attributed to `default`. Skipping
    /// it would make the document's key set depend on the config's content, and
    /// "every emitted key carries a source" would then be satisfied by a
    /// document that simply stopped emitting the keys it could not attribute
    /// (CLOUD-30).
    pub min_batten_version: Option<String>,
    /// The effective strictness, after the raise-only clamp.
    pub strictness: Strictness,
    /// Whether a `warn`-severity finding is promoted to a violation, after the
    /// raise-only clamp (CLOUD-49). The checks/advisory pipeline reads this
    /// resolved value; it is the only promotion setting there is.
    pub fail_on_warning: bool,
    /// The effective rule set: the committed rules plus any the local file adds.
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
    /// The scope path set: the authority's list, plus any `!` excludes the
    /// local file added. Raise-only — see [`merge_local_scope`] for why a local
    /// include is refused rather than appended.
    pub scope: Vec<String>,
    /// The protected path set: the authority's paths, plus any the local file
    /// **added**. §8's "add protected paths" verbatim; adding to an include-only
    /// set can only guard more.
    pub protected: Vec<String>,
    /// The unlanded path set, layered exactly as [`Resolved::protected`] is.
    pub unlanded: Vec<String>,
    /// The governing config surface hashed into `config epoch` (CLOUD-32).
    pub epoch: Option<config::Epoch>,
    /// The mutating-verb table, consumer data the authority supplies.
    #[serde(rename = "verb")]
    pub verbs: Vec<crate::verbs::MutatingVerb>,
    /// The suppression-marker table, consumer data the authority supplies.
    #[serde(rename = "marker")]
    pub markers: Vec<crate::markers::Marker>,
    /// The `exec` output predicates (CLOUD-117), authority rows plus any a local
    /// file **added**. Raise-only by construction: a local file can only append,
    /// and a row reusing a committed id is refused rather than merged.
    #[serde(rename = "exec_pattern")]
    pub exec_patterns: Vec<crate::outputs::OutputPattern>,
    /// The waiver table (CLOUD-208), authority rows plus any a local file
    /// **added for a rule the authority does not declare**. A local waiver over a
    /// committed rule is refused rather than merged — see [`merge_local_waivers`].
    #[serde(rename = "waiver")]
    pub waivers: Vec<crate::waiver::Waiver>,
    /// The declared thresholds (CLOUD-50), as the authority states them. Not
    /// layered: a budget is a bar this repository sets for itself, and there is
    /// no raise-only reading of "tighten a threshold" that a local file could
    /// be trusted with — lowering it is the weakening, and `trust.rs` compares
    /// the committed bytes for that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
    /// The ref work must land on (CLOUD-51), as the authority states it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_land_on: Option<String>,
    /// The hook actions (CLOUD-91), as the authority states it. Not layered,
    /// and the one key where that is a security property rather than a
    /// consistency one: an action is a command, so a local file able to add one
    /// could run anything under the agent's own hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<crate::action::HookConfig>,
    /// The worktree pileup threshold (CLOUD-46), as the authority states it.
    /// Not layered, for [`Resolved::budget`]'s reason: it is a threshold, and
    /// two thresholds in one config with opposite layering rules is the drift
    /// this engine exists to refuse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worktree: Option<crate::worktree::WorktreeConfig>,
    /// The judge payload boundary (CLOUD-135), as the authority states it. Not
    /// layered: every field is refusing by default and widening it is the
    /// weakening, so there is no raise-only reading a local file could be
    /// trusted with — `trust.rs` compares the committed bytes instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::judge::Judge>,
    /// The design-evidence audit's per-capture ceiling (CLOUD-53), as the
    /// authority states it. Not layered: for a budget, smaller is stricter, so a
    /// local file could only ever *raise* the ceiling through the ordinary
    /// raise-only reading — which is the weakening. [`crate::design::
    /// effective_cap`] is the tighten-only clamp waiting for a layer that
    /// tightens; until one exists the authority's value stands alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub design: Option<crate::design::Design>,
    /// The derived merge contract (CLOUD-54), as the authority states it. Not
    /// layered: a local file cannot change what the host requires, and a copy
    /// that disagreed with the committed one would be a third answer to a
    /// question that already has one authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci: Option<crate::ci::Ci>,
    /// The defect ledger's declaration (CLOUD-52), as the authority states it.
    /// Not layered: where the ledger lives and what may be in it is a property
    /// of the repository, and a local file that could redirect it would be able
    /// to point the append-only gate at a different file than the one committed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defects: Option<crate::defects::Defects>,
    /// The provisioning manifest (CLOUD-90), as the authority states it.
    #[serde(rename = "provision", skip_serializing_if = "Vec::is_empty")]
    pub provisions: Vec<crate::provision::Provision>,
    /// The transcript the optional `check` input reads (CLOUD-95), as the
    /// authority states it. Not layered: pointing the capability at a different
    /// file changes which evidence the run judges, and there is no raise-only
    /// reading of that — a local file redirecting it would be choosing the
    /// evidence, which is the weakening `trust.rs` compares committed bytes for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<crate::transcript::TranscriptConfig>,
    /// The advisory drain's pacing (CLOUD-79), as the authority states it. Not
    /// layered, and for a reason unlike its neighbours': theirs is that lowering
    /// a bar is the weakening, where **an interval has no direction at all** — a
    /// longer window is quieter and a shorter one is louder, and neither is a
    /// weakening of anything the raise-only clamp could measure. A key with no
    /// monotone reading does not belong in a monotone layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain: Option<crate::drain::DrainConfig>,
    /// The attribution policy (CLOUD-274), as the authority states it. Not
    /// layered, for the same reason `transcript` is not: every value in it is a
    /// deny pattern or the identity commits are accountable to, and a local file
    /// editing either would be *loosening* the policy — the exact weakening
    /// `trust.rs` compares committed bytes for. There is no raise-only reading of
    /// "match fewer things".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<crate::attribution::Attribution>,
    /// Which layer set each **emitted** key.
    ///
    /// Keyed by the serialized key name, and total over the document rather
    /// than over [`SETTINGS`]: `SETTINGS` declares which layers *may* override a
    /// key, which is a strictly smaller set than the keys this struct prints.
    /// Pinning attribution to the overridable subset is what made the printed
    /// "effective config" structurally partial (CLOUD-30).
    ///
    /// Skipped by serde so the document is exactly the config keys; the pairing
    /// happens in [`Resolved::attributed`].
    #[serde(skip_serializing)]
    pub sources: BTreeMap<&'static str, Source>,
}

/// One emitted key: its value, and the layer that set it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Attributed {
    /// The effective value, exactly as the key serializes.
    pub value: serde_json::Value,
    /// The layer token that set it — never a filesystem path or a raw env
    /// value, both of which would break byte-stability across machines and leak
    /// a home directory.
    pub source: Source,
}

impl Resolved {
    /// The effective configuration as `{key: {value, source}}`, sorted.
    ///
    /// Derived from this struct's own serialization rather than composed by
    /// hand, so the emitted key set is the struct's and cannot drift from it —
    /// which is also what makes "every emitted key carries a source" a checkable
    /// property instead of a promise.
    ///
    /// # Errors
    ///
    /// Propagates a serialization failure.
    pub fn attributed(&self) -> anyhow::Result<BTreeMap<String, Attributed>> {
        let document = serde_json::to_value(self)?;
        let serde_json::Value::Object(fields) = document else {
            anyhow::bail!("the resolved configuration did not serialize as an object");
        };
        fields
            .into_iter()
            .map(|(key, value)| {
                let source = *self.sources.get(key.as_str()).ok_or_else(|| {
                    // Unreachable in a build that passes
                    // `tests::every_emitted_key_carries_a_source`; stated as an
                    // error rather than a panic because an unattributed key is
                    // exactly the defect this change removes.
                    anyhow::anyhow!("emitted key {key} carries no source")
                })?;
                Ok((key, Attributed { value, source }))
            })
            .collect()
    }
}

/// A value paired with the layer that set it, so a later layer can name both
/// sides of a rejected weakening.
#[derive(Debug, Clone, Copy)]
struct Layered<T> {
    value: T,
    source: Source,
}

impl<T: Ord + Copy> Layered<T> {
    /// Apply a candidate from a higher layer under the raise-only clamp.
    ///
    /// Tightening (or restating) is accepted and re-attributed to the new layer;
    /// weakening is refused, naming the key, both layers, and both values so the
    /// operator can see exactly which file to fix.
    ///
    /// Generic over the key's type because the clamp *is* the ordering: every
    /// policy-bearing key resolves to a value where "tighten" means `candidate >=
    /// current`, whether that ordering is [`Strictness`]'s three ranks or
    /// `false < true`. One implementation means a second key cannot acquire a
    /// subtly different notion of weakening — `render` supplies the key's own
    /// token vocabulary for the message, and nothing else varies.
    fn raise(
        self,
        candidate: T,
        source: Source,
        origin: &str,
        key: &str,
        render: fn(T) -> String,
    ) -> Result<Self> {
        if candidate < self.value {
            return Err(UsageError::raise(format!(
                "{key}: {origin} would weaken policy ({} → {}); overrides may only tighten, \
                 never weaken a gate (§8)",
                render(self.value),
                render(candidate),
            )));
        }
        Ok(Layered {
            value: candidate,
            source,
        })
    }
}

/// The lowercase token a [`Strictness`] is written as in config, env, and flags.
///
/// Read off the `ValueEnum` derive rather than re-tabulated, so the flag, the
/// env var, the TOML key, and this message can never name a variant differently.
fn token(strictness: Strictness) -> String {
    strictness
        .to_possible_value()
        .map_or_else(|| "unknown".to_owned(), |v| v.get_name().to_owned())
}

/// The env layer for one key: its variable name and the value that variable
/// carries, or `None` when this layer does not speak to the key.
///
/// An **empty** variable is "not set", not a bad value: `FOO= cmd`, and a CI
/// that exports every knob unconditionally, both produce one. Filtering that
/// here rather than in each key's parser is what keeps empty→default (§10) a
/// single rule instead of one every new setting has to remember.
///
/// A key [`SETTINGS`] does not declare joins a key declaring no env var: this
/// layer does not speak to it, which is the answer the `?` chain already gives.
fn env_layer(key: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<(&'static str, String)> {
    let name = setting(key)?.env?;
    let raw = env(name)?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| (name, trimmed.to_owned()))
}

/// The flag that overrides one key, falling back to `default` for a key the
/// table declares no flag for — or does not declare at all, which reaches the
/// same fallback rather than a distinct one.
fn flag_name(key: &str, default: &'static str) -> &'static str {
    setting(key)
        .and_then(|spec| spec.long_flag)
        .unwrap_or(default)
}

/// The token a boolean key is written as in config, env, and messages.
///
/// TOML's own boolean literals, so the `batten.toml` key, the env var, and a
/// refusal message all speak one vocabulary. Nothing else parses: widening the
/// accepted set later stays backward-compatible, narrowing it would not.
fn bool_token(value: bool) -> String {
    if value { "true" } else { "false" }.to_owned()
}

/// Parse a boolean from an override's textual value, accepting exactly the
/// tokens [`bool_token`] emits.
fn parse_bool(raw: &str, origin: &str, key: &str) -> Result<bool> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(UsageError::raise(format!(
            "{key}: {origin} has unknown value {raw:?}; expected one of {}, {}",
            bool_token(false),
            bool_token(true),
        ))),
    }
}

/// Parse a [`Strictness`] from an override's textual value, via the same
/// `ValueEnum` mapping `clap` uses for the flag.
fn parse_strictness(raw: &str, origin: &str) -> Result<Strictness> {
    Strictness::from_str(raw, false).map_err(|_| {
        let expected: Vec<String> = Strictness::value_variants()
            .iter()
            .copied()
            .map(token)
            .collect();
        UsageError::raise(format!(
            "strictness: {origin} has unknown value {raw:?}; expected one of {}",
            expected.join(", ")
        ))
    })
}

/// Resolve the effective config for the repository rooted at `dir`, reading the
/// process environment for the env layer.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the committed authority is
/// missing or invalid, when the local file is invalid, or when any override
/// would weaken a policy-bearing key.
pub fn resolve(dir: &Path, overrides: &Overrides) -> Result<Resolved> {
    resolve_with_env(dir, overrides, &|name| std::env::var(name).ok())
}

/// Load the committed authority — layer 1 of the §8 chain.
///
/// Required: there is no upward walk to fall back on, and a missing authority is
/// bad input, not an empty policy.
///
/// Under `--config-from`, it is read from a git ref rather than the working
/// tree — same layer, same precedence, different source. That is the whole trust
/// mechanism: policy loads out of band of the change under review, so a branch
/// cannot relax the rules it is judged by (CLOUD-31).
fn authority(dir: &Path, config_from: Option<&str>) -> Result<config::Config> {
    match config_from {
        Some(reference) => crate::trust::load_base(dir, reference),
        None => config::load(&dir.join(config::CONFIG_FILE)),
    }
}

/// [`resolve`], with the env layer supplied by `env` so it is testable without
/// mutating the process environment.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_with_env(
    dir: &Path,
    overrides: &Overrides,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Resolved> {
    let repo = authority(dir, overrides.config_from.as_deref())?;

    // Layer 0 — the compiled-in default, overwritten by anything above it.
    let mut strictness = Layered {
        value: Strictness::default(),
        source: Source::Default,
    };
    if let Some(value) = repo.strictness {
        // The authority sets the floor; nothing below it can weaken it, so this
        // is an assignment rather than a clamped raise.
        strictness = Layered {
            value,
            source: Source::RepoConfig,
        };
    }

    // The promotion setting layers by the identical chain and the identical
    // clamp; `false < true` is the ordering "tighten" is defined over.
    let mut fail_on_warning = Layered {
        value: false,
        source: Source::Default,
    };
    if let Some(value) = repo.fail_on_warning {
        fail_on_warning = Layered {
            value,
            source: Source::RepoConfig,
        };
    }

    let mut tables = Tables {
        rules_source: if repo.rules.is_empty() {
            Source::Default
        } else {
            Source::RepoConfig
        },
        rules: repo.rules.clone(),
        exec_patterns: repo.exec_patterns.clone(),
        waivers: repo.waivers.clone(),
    };

    // The three policy-bearing path sets (CLOUD-37), seeded from the authority
    // and narrowable by the local layer below (CLOUD-239).
    let mut paths = Paths::from_authority(&repo);

    // Layer 2 — the git-ignored local file. Optional, and raise-only.
    let local_path = dir.join(LOCAL_CONFIG_FILE);
    if local_path.exists() {
        // Ungated: `min_batten_version` is authority-only, and the refusal in
        // `apply_local` names that specifically. Gating here would replace it
        // with "this build is too old" — true of the value, useless about the
        // mistake (CLOUD-33).
        //
        // `OverrideConfig` IS the override surface (CLOUD-239), so a key this
        // layer cannot honour never reaches here: `deny_unknown_fields` refused
        // it at parse. What used to be a silently dropped tightening — a local
        // `protected` that looked applied and wasn't — is now either applied or
        // a load error, with no third outcome.
        let local = config::load_override(&local_path)?;
        apply_local(
            local,
            &repo,
            &mut strictness,
            &mut fail_on_warning,
            &mut tables,
            &mut paths,
        )?;
    }

    // Layer 3 — the environment. An *empty* variable is "not set", not a bad
    // value: `FOO= cmd`, and a CI that exports every knob unconditionally, both
    // produce one. Distinguishing empty→default from present-but-invalid is the
    // house style's stated position (§10), and the alternative is worse — a
    // harmless empty export would fail every invocation.
    if let Some((name, raw)) = env_layer("strictness", env) {
        let value = parse_strictness(&raw, name)?;
        strictness = strictness.raise(value, Source::Env, name, "strictness", token)?;
    }
    if let Some((name, raw)) = env_layer("fail_on_warning", env) {
        let value = parse_bool(&raw, name, "fail_on_warning")?;
        fail_on_warning =
            fail_on_warning.raise(value, Source::Env, name, "fail_on_warning", bool_token)?;
    }

    // Layer 4 — the command line, highest precedence and still raise-only: a
    // flag may tighten a gate for one run, never disable one for it.
    if let Some(value) = overrides.strictness {
        let flag = flag_name("strictness", "--strictness");
        strictness = strictness.raise(value, Source::Flag, flag, "strictness", token)?;
    }
    if overrides.fail_on_warning {
        // Only the raising direction exists here: a bare boolean flag cannot
        // express "off", so the clamp has nothing to refuse. Routed through
        // `raise` anyway so the attribution to `flag` follows the same path as
        // every other layer rather than a bespoke assignment.
        let flag = flag_name("fail_on_warning", "--fail-on-warning");
        fail_on_warning =
            fail_on_warning.raise(true, Source::Flag, flag, "fail_on_warning", bool_token)?;
    }

    Ok(assemble(&repo, strictness, fail_on_warning, tables, paths))
}

/// The append-only tables, carried as one value through the layering.
///
/// One parameter rather than four, so [`apply_local`] and [`assemble`] both stay
/// inside the argument budget. Each table is merged by its own rule — see the
/// `merge_local_*` helpers and the rule loop — and none may have a committed row
/// redefined by the local layer.
struct Tables {
    rules: Vec<Rule>,
    rules_source: Source,
    exec_patterns: Vec<crate::outputs::OutputPattern>,
    waivers: Vec<crate::waiver::Waiver>,
}

/// Apply the git-ignored local file over the authority's values, raise-only.
///
/// Extracted from [`resolve_with_env`] because that function is the §8
/// precedence chain and has to read as one: five layers in sequence, each a few
/// lines. Inlining a per-key merge for every layered table is what pushed it
/// past the line limit, and the chain is the thing a reader comes here for.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the local file restates
/// `min_batten_version`, lowers a clamped value, redefines a committed row, or
/// writes a `scope` entry that would widen rather than narrow.
fn apply_local(
    local: config::OverrideConfig,
    repo: &config::Config,
    strictness: &mut Layered<Strictness>,
    fail_on_warning: &mut Layered<bool>,
    tables: &mut Tables,
    paths: &mut Paths,
) -> Result<()> {
    if local.min_batten_version.is_some() {
        return Err(UsageError::raise(format!(
            "{LOCAL_CONFIG_FILE}: `min_batten_version` is set by the committed authority ({}) \
             only; an override may not restate it",
            config::CONFIG_FILE,
        )));
    }
    if let Some(value) = local.strictness {
        *strictness = strictness.raise(
            value,
            Source::LocalFile,
            LOCAL_CONFIG_FILE,
            "strictness",
            token,
        )?;
    }
    if let Some(value) = local.fail_on_warning {
        // The raise-only clause §8 names directly: a committed `on` cannot be
        // turned off by an uncommitted file.
        *fail_on_warning = fail_on_warning.raise(
            value,
            Source::LocalFile,
            LOCAL_CONFIG_FILE,
            "fail_on_warning",
            bool_token,
        )?;
    }
    for rule in local.rules {
        if tables.rules.iter().any(|committed| committed.id == rule.id) {
            // Redefining a committed rule could weaken it (a narrower glob, a
            // pattern that no longer matches) and Batten cannot tell tightening
            // from weakening across arbitrary predicates — so the conservative
            // reading refuses rather than guesses.
            return Err(UsageError::raise(format!(
                "rule {}: {LOCAL_CONFIG_FILE} may not redefine a rule from {}; an override may \
                 only add rules, never weaken a committed gate (§8)",
                rule.id,
                config::CONFIG_FILE,
            )));
        }
        tables.rules.push(rule);
        tables.rules_source = Source::LocalFile;
    }
    merge_local_patterns(&mut tables.exec_patterns, local.exec_patterns)?;
    merge_local_waivers(&mut tables.waivers, local.waivers, &repo.rules)?;
    // §8's three policy-bearing path sets, raise-only. Before CLOUD-239 these
    // were parsed and discarded: an author who wrote `protected` here got no
    // complaint from the editor, none from `taplo lint`, none from `batten
    // check` — and no effect. A tightening lost without a word is worse than one
    // refused, because the operator's intent vanishes.
    if merge_local_scope(&mut paths.scope, local.scope)? {
        paths.scope_source = Source::LocalFile;
    }
    if !local.protected.is_empty() {
        // Union: "add protected paths" is §8's own wording, and adding to an
        // include-only set can only guard more paths.
        paths.protected.extend(local.protected);
        paths.protected_source = Source::LocalFile;
    }
    if !local.unlanded.is_empty() {
        paths.unlanded.extend(local.unlanded);
        paths.unlanded_source = Source::LocalFile;
    }
    Ok(())
}

/// The three policy-bearing path sets after layering, with their attribution.
///
/// Grouped so [`assemble`] takes one parameter rather than six. Nothing here
/// derives one set from another — a path's membership in `scope`, `protected`
/// and `unlanded` are three separate answers (CLOUD-37).
struct Paths {
    scope: Vec<String>,
    protected: Vec<String>,
    unlanded: Vec<String>,
    scope_source: Source,
    protected_source: Source,
    unlanded_source: Source,
}

impl Paths {
    /// Seed all three from the committed authority, before any layering.
    ///
    /// Attribution follows the same present-means-`repo-config` rule every
    /// authority key gets, so a set the local layer never touches reads exactly
    /// as it did before these keys became layerable.
    fn from_authority(repo: &config::Config) -> Self {
        let authority_set = |present: bool| {
            if present {
                Source::RepoConfig
            } else {
                Source::Default
            }
        };
        Paths {
            scope_source: authority_set(!repo.scope.is_empty()),
            protected_source: authority_set(!repo.protected.is_empty()),
            unlanded_source: authority_set(!repo.unlanded.is_empty()),
            scope: repo.scope.clone(),
            protected: repo.protected.clone(),
            unlanded: repo.unlanded.clone(),
        }
    }
}

/// Narrow the committed scope with a local file's excludes.
///
/// Returns whether anything was narrowed, so the caller can attribute the key.
///
/// **Excludes only, and a plain include is refused.** `scope` is one ordered
/// include/exclude list whose includes *union*: appending an include can only
/// add paths, so a local include is either a widening — exactly what §8's
/// raise-only clause forbids — or a no-op that reads as policy. Excludes are
/// purely subtractive, so appending them is provably narrowing whatever the
/// authority declared, with no reasoning about entry order required.
///
/// This is deliberately narrower than §8's "narrow scope" read at its widest: an
/// author cannot express "restrict to `src/**`" in one entry, only "exclude what
/// I do not want". The trade is soundness — there is no local `scope` this
/// function accepts that can enlarge the set.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a local entry that is not a `!`
/// exclude, naming the entry.
fn merge_local_scope(scope: &mut Vec<String>, local: Vec<String>) -> Result<bool> {
    if local.is_empty() {
        return Ok(false);
    }
    for entry in &local {
        if !entry.starts_with('!') {
            return Err(UsageError::raise(format!(
                "scope: `{entry}` — {LOCAL_CONFIG_FILE} may only NARROW scope, so every entry must \
                 be a `!` exclude; an include would widen the set an override may not widen (§8)",
            )));
        }
    }
    scope.extend(local);
    Ok(true)
}

/// Append a local file's output predicates to the committed ones.
///
/// The same reading local *rules* get, and for the same reason: a local file may
/// ADD a pattern — tightening, one more way for a wrapped command to be caught
/// lying — but may not redefine a committed one, since a narrowed stream or an
/// altered literal is a weakening Batten cannot distinguish from a fix.
///
/// Extracted rather than inlined because `resolve_with_env` is the §8 chain and
/// reads as one; a second per-table merge loop in its body is the thing that
/// pushed it past the line limit.
///
/// # Errors
///
/// Returns a [`UsageError`] when a local pattern reuses a committed id.
fn merge_local_patterns(
    committed: &mut Vec<crate::outputs::OutputPattern>,
    local: Vec<crate::outputs::OutputPattern>,
) -> Result<()> {
    for pattern in local {
        if committed.iter().any(|row| row.id == pattern.id) {
            return Err(UsageError::raise(format!(
                "exec_pattern {}: {LOCAL_CONFIG_FILE} may not redefine a pattern from {}; an \
                 override may only add patterns, never weaken a committed gate (§8)",
                pattern.id,
                config::CONFIG_FILE,
            )));
        }
        committed.push(pattern);
    }
    Ok(())
}

/// Add a local file's waivers to the committed ones, refusing any that touch a
/// committed rule.
///
/// This is the one place where the local layer *lowers* a bar rather than raising
/// one, so the clamp has to be strict. [`Layered::raise`] cannot express it — it
/// is bounded `T: Ord + Copy` and a waiver has no ordering — so this copies the
/// blunter rule local *rules* already get, on the same stated ground: Batten
/// cannot tell tightening from weakening across arbitrary predicates, and a
/// waiver over a committed gate is the case where guessing wrong switches that
/// gate off from an uncommitted file.
///
/// A waiver for a rule the authority does not declare is accepted, because it
/// suppresses nothing the committed policy asserts. That is what lets a local
/// file waive a rule it also added, without a second mechanism.
///
/// # Errors
///
/// Returns a [`UsageError`] when a local waiver names a committed rule, or when
/// two waivers end up sharing an identity.
fn merge_local_waivers(
    committed: &mut Vec<crate::waiver::Waiver>,
    local: Vec<crate::waiver::Waiver>,
    rules: &[Rule],
) -> Result<()> {
    for waiver in local {
        if rules.iter().any(|rule| rule.id == waiver.rule) {
            return Err(UsageError::raise(format!(
                "waiver {}: {LOCAL_CONFIG_FILE} may not waive a rule declared in {}; a waiver \
                 lowers the bar, so the durable tier is the committed authority alone (§8)",
                waiver.rule,
                config::CONFIG_FILE,
            )));
        }
        committed.push(waiver);
    }
    // Re-validate the merged table: two layers can each be well formed and still
    // duplicate an identity between them, and a duplicate that only exists after
    // layering would otherwise never be refused.
    crate::waiver::validate(committed)
}

/// Build the resolved configuration from the authority plus the layered values.
///
/// Split out so the layering above reads as the §8 chain it is, rather than
/// ending in a field-by-field copy of every key the authority carries.
fn assemble(
    repo: &config::Config,
    strictness: Layered<Strictness>,
    fail_on_warning: Layered<bool>,
    tables: Tables,
    paths: Paths,
) -> Resolved {
    // Sources read off before the lists move, so every layered value is moved
    // into the document rather than cloned beside it.
    let sources = attribution(
        repo,
        strictness.source,
        fail_on_warning.source,
        tables.rules_source,
        &paths,
    );
    Resolved {
        version: repo.version,
        min_batten_version: repo.min_batten_version.clone(),
        strictness: strictness.value,
        fail_on_warning: fail_on_warning.value,
        rules: tables.rules,
        scope: paths.scope,
        protected: paths.protected,
        unlanded: paths.unlanded,
        epoch: repo.epoch.clone(),
        verbs: repo.verbs.clone(),
        markers: repo.markers.clone(),
        exec_patterns: tables.exec_patterns,
        waivers: tables.waivers,
        budget: repo.budget.clone(),
        must_land_on: repo.must_land_on.clone(),
        worktree: repo.worktree.clone(),
        hook: repo.hook.clone(),
        transcript: repo.transcript.clone(),
        attribution: repo.attribution.clone(),
        judge: repo.judge.clone(),
        design: repo.design.clone(),
        ci: repo.ci.clone(),
        defects: repo.defects.clone(),
        provisions: repo.provisions.clone(),
        drain: repo.drain.clone(),
        sources,
    }
}

/// Which layer set each emitted key.
///
/// Every key the authority *can* set but no layer may override is attributed the
/// same way — present in the committed file means `repo-config`, absent means
/// `default` — so the two cannot drift apart by being written out per key.
fn attribution(
    repo: &config::Config,
    strictness: Source,
    fail_on_warning: Source,
    rules: Source,
    paths: &Paths,
) -> BTreeMap<&'static str, Source> {
    let authority_set = |present: bool| {
        if present {
            Source::RepoConfig
        } else {
            Source::Default
        }
    };
    BTreeMap::from([
        // `version` always comes from the authority: the file is required, and
        // the key is required within it.
        ("version", Source::RepoConfig),
        (
            "min_batten_version",
            authority_set(repo.min_batten_version.is_some()),
        ),
        ("strictness", strictness),
        ("fail_on_warning", fail_on_warning),
        ("rule", rules),
        // Layered since CLOUD-239: these three carry the local file's source
        // when it narrowed them, so `config show` names the layer that did.
        ("scope", paths.scope_source),
        ("protected", paths.protected_source),
        ("unlanded", paths.unlanded_source),
        ("epoch", authority_set(repo.epoch.is_some())),
        ("verb", authority_set(!repo.verbs.is_empty())),
        ("marker", authority_set(!repo.markers.is_empty())),
        (
            "exec_pattern",
            authority_set(!repo.exec_patterns.is_empty()),
        ),
        ("waiver", authority_set(!repo.waivers.is_empty())),
        ("budget", authority_set(repo.budget.is_some())),
        ("must_land_on", authority_set(repo.must_land_on.is_some())),
        ("worktree", authority_set(repo.worktree.is_some())),
        ("hook", authority_set(repo.hook.is_some())),
        ("transcript", authority_set(repo.transcript.is_some())),
        ("attribution", authority_set(repo.attribution.is_some())),
        ("judge", authority_set(repo.judge.is_some())),
        ("design", authority_set(repo.design.is_some())),
        ("ci", authority_set(repo.ci.is_some())),
        ("defects", authority_set(repo.defects.is_some())),
        ("provision", authority_set(!repo.provisions.is_empty())),
        ("drain", authority_set(repo.drain.is_some())),
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    /// Write a repo (and optionally a local override) into a fresh temp dir.
    fn repo(name: &str, repo_toml: &str, local_toml: Option<&str>) -> std::path::PathBuf {
        // `CARGO_TARGET_TMPDIR` exists only for integration tests, so a unit
        // test takes its scratch space from the system temp dir instead.
        let dir = std::env::temp_dir().join("batten-resolve-tests").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(config::CONFIG_FILE), repo_toml).unwrap();
        let local = dir.join(LOCAL_CONFIG_FILE);
        match local_toml {
            Some(contents) => fs::write(&local, contents).unwrap(),
            // A leftover file from a prior run would silently change the case.
            None => {
                let _ = fs::remove_file(&local);
            }
        }
        dir
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn source_order_is_the_declared_precedence() {
        // §8: flag > env > local file > repo config > default.
        assert!(Source::Default < Source::RepoConfig);
        assert!(Source::RepoConfig < Source::LocalFile);
        assert!(Source::LocalFile < Source::Env);
        assert!(Source::Env < Source::Flag);
    }

    #[test]
    fn every_emitted_key_carries_a_source() {
        // The identity this replaces was `sources.len() == SETTINGS.len()`,
        // which pinned attribution to the OVERRIDABLE subset — so every key the
        // document emitted outside `SETTINGS` (`version`, `min_batten_version`,
        // the path sets, the consumer tables) printed with no source at all, and
        // the hole widened with every `batten.toml` key that landed (CLOUD-30).
        //
        // The property now is total over the emitted document: `attributed()`
        // errors on an unattributed key, so this asserts it succeeds and that
        // the key set is the struct's own serialization.
        let dir = repo("emitted-keys", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let document = resolved
            .attributed()
            .expect("every emitted key is attributed");

        let serialized = serde_json::to_value(&resolved).unwrap();
        let serde_json::Value::Object(fields) = serialized else {
            panic!("the resolved configuration serializes as an object");
        };
        assert_eq!(
            document.keys().cloned().collect::<Vec<_>>(),
            fields.keys().cloned().collect::<Vec<_>>(),
            "the attributed document must cover exactly the serialized keys"
        );

        // `SETTINGS` keeps its own, narrower job: declaring which layers may
        // override a key. Every key it names must still be emitted.
        for spec in SETTINGS {
            assert!(
                document.contains_key(spec.key),
                "SETTINGS declares {} but the document does not emit it",
                spec.key
            );
        }
    }

    #[test]
    fn a_key_no_layer_set_reads_default_and_an_authority_key_reads_repo_config() {
        let dir = repo(
            "attribution-layers",
            "version = 1\nprotected = [\"a\"]\n",
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let document = resolved.attributed().unwrap();
        assert_eq!(document["protected"].source, Source::RepoConfig);
        assert_eq!(document["unlanded"].source, Source::Default);
        assert_eq!(document["version"].source, Source::RepoConfig);
    }

    #[test]
    fn default_wins_when_no_layer_speaks() {
        let dir = repo("resolve-default", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Standard);
        assert_eq!(resolved.sources["strictness"], Source::Default);
    }

    #[test]
    fn repo_config_beats_default() {
        let dir = repo(
            "resolve-repo",
            "version = 1\nstrictness = \"permissive\"\n",
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Permissive);
        assert_eq!(resolved.sources["strictness"], Source::RepoConfig);
    }

    #[test]
    fn local_file_may_tighten() {
        let dir = repo(
            "resolve-local-tighten",
            "version = 1\nstrictness = \"standard\"\n",
            Some("version = 1\nstrictness = \"strict\"\n"),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"], Source::LocalFile);
    }

    #[test]
    fn local_file_may_not_weaken() {
        // The load-bearing clamp: an uncommitted file cannot lower a gate.
        let dir = repo(
            "resolve-local-weaken",
            "version = 1\nstrictness = \"strict\"\n",
            Some("version = 1\nstrictness = \"permissive\"\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("may only tighten"),
            "the refusal must say why, got: {err}"
        );
    }

    #[test]
    fn local_file_may_add_a_rule() {
        let dir = repo(
            "resolve-local-add-rule",
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"b\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"y\"\nseverity = \"deny\"\n",
            ),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let ids: Vec<&str> = resolved.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"], "an added rule tightens policy");
        assert_eq!(resolved.sources["rule"], Source::LocalFile);
    }

    #[test]
    fn local_file_may_not_redefine_a_committed_rule() {
        let dir = repo(
            "resolve-local-redefine",
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"nothing/**\"\npattern = \"x\"\nseverity = \"deny\"\n",
            ),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not redefine"), "got: {err}");
    }

    /// `batten.toml` text declaring rule `a`, plus whatever else the case needs.
    fn with_rule_a(extra: &str) -> String {
        format!(
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\n\
             pattern = \"x\"\nseverity = \"deny\"\n{extra}"
        )
    }

    fn waiver_row(rule: &str) -> String {
        format!("\n[[waiver]]\nrule = \"{rule}\"\nreason = \"tracked\"\nexpires = \"2099-01-01\"\n")
    }

    #[test]
    fn a_local_waiver_over_a_committed_rule_is_refused() {
        // The one direction where the local layer would LOWER the bar, so the
        // clamp is a flat refusal: `Layered::raise` needs `Ord` and a waiver has
        // none, so there is no "clamp to the tighter one" to fall back on.
        let dir = repo(
            "resolve-local-waiver-committed",
            &with_rule_a(""),
            Some(&format!("version = 1\n{}", waiver_row("a"))),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not waive"), "got: {err}");
    }

    #[test]
    fn a_local_file_may_add_a_waiver_for_an_undeclared_rule() {
        // It suppresses nothing the committed policy asserts, so refusing it would
        // buy no safety and would stop a local file waiving a rule it also added.
        let dir = repo(
            "resolve-local-waiver-unknown",
            &with_rule_a(""),
            Some(&format!("version = 1\n{}", waiver_row("elsewhere"))),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let rules: Vec<&str> = resolved.waivers.iter().map(|w| w.rule.as_str()).collect();
        assert_eq!(rules, vec!["elsewhere"]);
    }

    #[test]
    fn a_committed_waiver_resolves_and_is_attributed_to_the_authority() {
        let dir = repo(
            "resolve-committed-waiver",
            &with_rule_a(&waiver_row("a")),
            None,
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(resolved.waivers.len(), 1);
        assert_eq!(resolved.sources["waiver"], Source::RepoConfig);
    }

    #[test]
    fn a_layered_duplicate_waiver_is_refused_even_though_each_layer_is_clean() {
        // Both files are individually well formed; the duplicate exists only after
        // merging, which is the one case a per-file validator cannot see.
        let dir = repo(
            "resolve-layered-duplicate-waiver",
            &with_rule_a(&waiver_row("elsewhere")),
            Some(&format!("version = 1\n{}", waiver_row("elsewhere"))),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("declared twice"), "got: {err}");
    }

    #[test]
    fn env_beats_the_local_file_and_is_raise_only() {
        let dir = repo(
            "resolve-env",
            "version = 1\nstrictness = \"permissive\"\n",
            Some("version = 1\nstrictness = \"standard\"\n"),
        );
        let strict = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "strict".to_owned())
        })
        .unwrap();
        assert_eq!(strict.strictness, Strictness::Strict);
        assert_eq!(strict.sources["strictness"], Source::Env);

        // …and it still cannot go below the local file's floor.
        let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "permissive".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn an_undeclared_key_has_no_env_layer_and_falls_back_to_the_declared_default() {
        // CLOUD-300. `setting()` used to `expect` its key into existence, under
        // an `#[allow(clippy::expect_used)]` whose `# Panics` comment cited a
        // test that was never written. The panic was unreachable only by
        // coincidence of today's call sites, so this pins the property the
        // citation claimed — from the other end, over the two functions that
        // actually call it, now that absence is a value rather than a panic.
        //
        // The env closure answers EVERY name, so a `None` here can only come
        // from the table lookup; an unset variable cannot produce it.
        assert!(
            env_layer("not_a_declared_key", &|_| Some("loud".to_owned())).is_none(),
            "a key SETTINGS does not declare has no env layer"
        );
        assert_eq!(
            flag_name("not_a_declared_key", "--fallback"),
            "--fallback",
            "an undeclared key falls back exactly as a declared key with no flag does"
        );

        // The declared keys still resolve, so this cannot pass by `setting()`
        // answering `None` to everything.
        assert_eq!(
            env_layer("strictness", &|_| Some("strict".to_owned())),
            Some(("BATTEN_STRICTNESS", "strict".to_owned()))
        );
        assert_eq!(flag_name("strictness", "--fallback"), "--strictness");
        assert!(
            env_layer("rule", &|_| Some("loud".to_owned())).is_none(),
            "a declared key with no env var has no env layer either"
        );
    }

    #[test]
    fn an_empty_env_var_means_unset_not_invalid() {
        // `BATTEN_STRICTNESS= batten check` and a CI that exports every knob
        // unconditionally both produce an empty value. It must fall through to
        // the layer below, not fail the run (§10: empty → default).
        let dir = repo(
            "resolve-env-empty",
            "version = 1\nstrictness = \"strict\"\n",
            None,
        );
        for raw in ["", "   "] {
            let resolved = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_STRICTNESS").then(|| raw.to_owned())
            })
            .expect("an empty env var is not a bad value");
            assert_eq!(resolved.strictness, Strictness::Strict);
            assert_eq!(
                resolved.sources["strictness"],
                Source::RepoConfig,
                "an empty override must not claim the key"
            );
        }
    }

    #[test]
    fn the_local_file_may_not_restate_an_authority_only_key() {
        // The override layer honours strictness and rules; anything else it
        // parses must be refused, never parsed and dropped. A silently ignored
        // `min_batten_version` would read as applied while doing nothing.
        let dir = repo(
            "resolve-local-authority-key",
            "version = 1\nmin_batten_version = \"0.0.0\"\n",
            Some("version = 1\nmin_batten_version = \"9.9.9\"\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("min_batten_version"),
            "the refusal must name the key, got: {err}"
        );
    }

    #[test]
    fn unknown_env_value_is_a_usage_error() {
        let dir = repo("resolve-env-bad", "version = 1\n", None);
        let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "loose".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn flag_beats_env_and_is_raise_only() {
        let dir = repo("resolve-flag", "version = 1\n", None);
        let env = |name: &str| (name == "BATTEN_STRICTNESS").then(|| "standard".to_owned());
        let resolved = resolve_with_env(
            &dir,
            &Overrides {
                strictness: Some(Strictness::Strict),
                ..Overrides::default()
            },
            &env,
        )
        .unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"], Source::Flag);

        let err = resolve_with_env(
            &dir,
            &Overrides {
                strictness: Some(Strictness::Permissive),
                ..Overrides::default()
            },
            &env,
        )
        .unwrap_err();
        assert!(is_usage_error(&err), "a flag may not weaken a gate either");
    }

    #[test]
    fn fail_on_warning_layers_through_the_whole_chain() {
        // The one setting, resolved once, reachable from every layer §8 declares
        // — and attributed to the layer that actually set it.
        let off = repo("fow-default", "version = 1\n", None);
        let resolved = resolve_with_env(&off, &Overrides::default(), &no_env).unwrap();
        assert!(!resolved.fail_on_warning, "unset means off");
        assert_eq!(resolved.sources["fail_on_warning"], Source::Default);

        let committed = repo("fow-repo", "version = 1\nfail_on_warning = true\n", None);
        let resolved = resolve_with_env(&committed, &Overrides::default(), &no_env).unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"], Source::RepoConfig);

        let local = repo(
            "fow-local",
            "version = 1\n",
            Some("version = 1\nfail_on_warning = true\n"),
        );
        let resolved = resolve_with_env(&local, &Overrides::default(), &no_env).unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"], Source::LocalFile);

        let resolved = resolve_with_env(&off, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "true".to_owned())
        })
        .unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"], Source::Env);

        let resolved = resolve_with_env(
            &off,
            &Overrides {
                fail_on_warning: true,
                ..Overrides::default()
            },
            &no_env,
        )
        .unwrap();
        assert!(resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"], Source::Flag);
    }

    #[test]
    fn a_committed_fail_on_warning_may_not_be_turned_off() {
        // The raise-only clause, over every layer that can express "off". The
        // flag cannot: `--fail-on-warning` has no negative form, which is why it
        // is absent from this list rather than missing from it.
        let dir = repo(
            "fow-weaken-local",
            "version = 1\nfail_on_warning = true\n",
            Some("version = 1\nfail_on_warning = false\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("fail_on_warning")
                && err.to_string().contains("may only tighten"),
            "the refusal must name the key and say why, got: {err}"
        );

        let committed = repo(
            "fow-weaken-env",
            "version = 1\nfail_on_warning = true\n",
            None,
        );
        let err = resolve_with_env(&committed, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "false".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err), "env may not turn a committed on off");

        // Restating the committed value is not a weakening: it is accepted and
        // re-attributed, exactly as a restated `strictness` is.
        let resolved = resolve_with_env(&committed, &Overrides::default(), &|name| {
            (name == "BATTEN_FAIL_ON_WARNING").then(|| "true".to_owned())
        })
        .unwrap();
        assert_eq!(resolved.sources["fail_on_warning"], Source::Env);
    }

    #[test]
    fn turning_fail_on_warning_off_below_an_unset_authority_is_allowed() {
        // `false` is the default, so a lower-precedence `false` weakens nothing.
        // Only a *committed on* creates a floor — this is what keeps the clamp a
        // policy rule rather than a blanket ban on writing the key.
        let dir = repo(
            "fow-off-is-not-weakening",
            "version = 1\n",
            Some("version = 1\nfail_on_warning = false\n"),
        );
        let resolved = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert!(!resolved.fail_on_warning);
        assert_eq!(resolved.sources["fail_on_warning"], Source::LocalFile);
    }

    #[test]
    fn an_empty_fail_on_warning_env_var_means_unset_not_invalid() {
        // Same §10 position as strictness: an unconditional CI export of every
        // knob must not fail the run, and must not claim the key either.
        let dir = repo(
            "fow-env-empty",
            "version = 1\nfail_on_warning = true\n",
            None,
        );
        for raw in ["", "   "] {
            let resolved = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_FAIL_ON_WARNING").then(|| raw.to_owned())
            })
            .expect("an empty env var is not a bad value");
            assert!(resolved.fail_on_warning);
            assert_eq!(resolved.sources["fail_on_warning"], Source::RepoConfig);
        }
    }

    #[test]
    fn an_unparseable_fail_on_warning_env_value_is_a_usage_error() {
        // Present-but-invalid is refused, never coerced — a `=1` that silently
        // read as `true` would be a gate whose state nobody can predict.
        let dir = repo("fow-env-bad", "version = 1\n", None);
        for raw in ["1", "0", "yes", "TRUE", "on"] {
            let err = resolve_with_env(&dir, &Overrides::default(), &|name| {
                (name == "BATTEN_FAIL_ON_WARNING").then(|| raw.to_owned())
            })
            .unwrap_err();
            assert!(is_usage_error(&err), "{raw:?} must be refused");
            // Weakest-first, the same order `strictness` lists its variants in.
            assert!(
                err.to_string().contains("false, true"),
                "the refusal must name the accepted tokens, got: {err}"
            );
        }
    }

    #[test]
    fn there_is_no_upward_walk() {
        // §8: no directory walk. A config in the parent must not be found.
        let parent = repo("resolve-no-walk", "version = 1\n", None);
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let err = resolve_with_env(&child, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("no config found"), "got: {err}");
    }

    #[test]
    fn an_invalid_local_file_is_a_usage_error() {
        // The override file is held to the same narrow surface as the authority.
        let dir = repo(
            "resolve-local-invalid",
            "version = 1\n",
            Some("version = 1\nbogus = true\n"),
        );
        let err = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn resolution_is_byte_stable() {
        // §6: the same input yields the same bytes, sources map included.
        let dir = repo("resolve-stable", "version = 1\n", None);
        let first = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        let second = resolve_with_env(&dir, &Overrides::default(), &no_env).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
