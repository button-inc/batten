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
//!   a [`UsageError`] (→ exit `2`), and the local file may only *add* rules —
//!   redefining a committed rule is refused, so the worst an uncommitted file can
//!   do is make a gate stricter. This extends §5's `max_effect` invariant to the
//!   config layer, which is what keeps config the trust boundary even with a
//!   local override present.
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
        // Rules layer additively: the local file may add a rule, never redefine
        // or remove a committed one. There is no env or flag surface — a policy
        // predicate belongs in a reviewable file, not an ambient variable.
        key: "rule",
        env: None,
        long_flag: None,
    },
];

/// Look up a setting's declaration by key.
///
/// # Panics
///
/// Never: [`tests::every_resolved_key_is_declared`] pins that each key the
/// resolver uses is present, so the `expect` below is unreachable in a build
/// that passes its tests.
fn setting(key: &str) -> &'static SettingSpec {
    #[allow(clippy::expect_used)]
    SETTINGS
        .iter()
        .find(|spec| spec.key == key)
        .expect("every resolved key is declared in SETTINGS")
}

/// The flag layer: values supplied on the command line, highest precedence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--strictness`, when passed.
    pub strictness: Option<Strictness>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_batten_version: Option<String>,
    /// The effective strictness, after the raise-only clamp.
    pub strictness: Strictness,
    /// The effective rule set: the committed rules plus any the local file adds.
    #[serde(rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Which layer won each key in [`SETTINGS`].
    pub sources: BTreeMap<&'static str, Source>,
}

/// A value paired with the layer that set it, so a later layer can name both
/// sides of a rejected weakening.
#[derive(Debug, Clone, Copy)]
struct Layered<T> {
    value: T,
    source: Source,
}

impl Layered<Strictness> {
    /// Apply a candidate from a higher layer under the raise-only clamp.
    ///
    /// Tightening (or restating) is accepted and re-attributed to the new layer;
    /// weakening is refused, naming both layers and both values so the operator
    /// can see exactly which file to fix.
    fn raise(self, candidate: Strictness, source: Source, origin: &str) -> Result<Self> {
        if candidate < self.value {
            return Err(UsageError::raise(format!(
                "strictness: {origin} would weaken policy ({} → {}); overrides may only tighten, \
                 never weaken a gate (§8)",
                token(self.value),
                token(candidate),
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
/// Returns a [`UsageError`] (→ exit `2`) when the committed authority is
/// missing or invalid, when the local file is invalid, or when any override
/// would weaken a policy-bearing key.
pub fn resolve(dir: &Path, overrides: Overrides) -> Result<Resolved> {
    resolve_with_env(dir, overrides, &|name| std::env::var(name).ok())
}

/// [`resolve`], with the env layer supplied by `env` so it is testable without
/// mutating the process environment.
///
/// # Errors
///
/// As [`resolve`].
pub fn resolve_with_env(
    dir: &Path,
    overrides: Overrides,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Resolved> {
    // Layer 1 — the committed authority. Required: there is no upward walk to
    // fall back on, and a missing authority is bad input, not an empty policy.
    let repo = config::load(&dir.join(config::CONFIG_FILE))?;

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

    let mut rules = repo.rules.clone();
    let mut rules_source = if rules.is_empty() {
        Source::Default
    } else {
        Source::RepoConfig
    };

    // Layer 2 — the git-ignored local file. Optional, and raise-only.
    let local_path = dir.join(LOCAL_CONFIG_FILE);
    if local_path.exists() {
        let local = config::load(&local_path)?;
        // The override layer honours `strictness` and `rule`; every other key
        // belongs to the committed authority alone. Refuse the ones it cannot
        // honour rather than parsing and dropping them — a setting that looks
        // applied but isn't is the same failure `deny_unknown_fields` exists to
        // prevent, and it is worse here because the key *is* valid in the file
        // it was copied from.
        if local.min_batten_version.is_some() {
            return Err(UsageError::raise(format!(
                "{LOCAL_CONFIG_FILE}: `min_batten_version` is set by the committed authority ({}) \
                 only; an override may not restate it",
                config::CONFIG_FILE,
            )));
        }
        if let Some(value) = local.strictness {
            strictness = strictness.raise(value, Source::LocalFile, LOCAL_CONFIG_FILE)?;
        }
        for rule in local.rules {
            if rules.iter().any(|committed| committed.id == rule.id) {
                // Redefining a committed rule could weaken it (a narrower glob,
                // a pattern that no longer matches) and Batten cannot tell
                // tightening from weakening across arbitrary predicates — so the
                // conservative reading refuses rather than guesses.
                return Err(UsageError::raise(format!(
                    "rule {}: {LOCAL_CONFIG_FILE} may not redefine a rule from {}; an override may \
                     only add rules, never weaken a committed gate (§8)",
                    rule.id,
                    config::CONFIG_FILE,
                )));
            }
            rules.push(rule);
            rules_source = Source::LocalFile;
        }
    }

    // Layer 3 — the environment. An *empty* variable is "not set", not a bad
    // value: `FOO= cmd`, and a CI that exports every knob unconditionally, both
    // produce one. Distinguishing empty→default from present-but-invalid is the
    // house style's stated position (§10), and the alternative is worse — a
    // harmless empty export would fail every invocation.
    if let Some(name) = setting("strictness").env {
        if let Some(raw) = env(name) {
            let raw = raw.trim();
            if !raw.is_empty() {
                let value = parse_strictness(raw, name)?;
                strictness = strictness.raise(value, Source::Env, name)?;
            }
        }
    }

    // Layer 4 — the command line, highest precedence and still raise-only: a
    // flag may tighten a gate for one run, never disable one for it.
    if let Some(value) = overrides.strictness {
        let flag = setting("strictness").long_flag.unwrap_or("--strictness");
        strictness = strictness.raise(value, Source::Flag, flag)?;
    }

    Ok(Resolved {
        version: repo.version,
        min_batten_version: repo.min_batten_version,
        strictness: strictness.value,
        rules,
        sources: BTreeMap::from([("strictness", strictness.source), ("rule", rules_source)]),
    })
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
    fn every_resolved_key_is_declared() {
        // The `sources` map and SETTINGS must agree: a key the resolver reports
        // but does not declare would have undocumented precedence.
        let dir = repo("resolve-keys", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
        for key in resolved.sources.keys() {
            assert!(
                SETTINGS.iter().any(|spec| &spec.key == key),
                "resolved key {key} is missing from SETTINGS"
            );
        }
        assert_eq!(resolved.sources.len(), SETTINGS.len());
    }

    #[test]
    fn default_wins_when_no_layer_speaks() {
        let dir = repo("resolve-default", "version = 1\n", None);
        let resolved = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
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
        let resolved = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
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
        let resolved = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
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
        let err = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap_err();
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
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"b\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"y\"\n",
            ),
        );
        let resolved = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
        let ids: Vec<&str> = resolved.rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"], "an added rule tightens policy");
        assert_eq!(resolved.sources["rule"], Source::LocalFile);
    }

    #[test]
    fn local_file_may_not_redefine_a_committed_rule() {
        let dir = repo(
            "resolve-local-redefine",
            "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"**\"\npattern = \"x\"\n",
            Some(
                "version = 1\n\n[[rule]]\nid = \"a\"\nkind = \"forbid\"\nglob = \"nothing/**\"\npattern = \"x\"\n",
            ),
        );
        let err = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(err.to_string().contains("may not redefine"), "got: {err}");
    }

    #[test]
    fn env_beats_the_local_file_and_is_raise_only() {
        let dir = repo(
            "resolve-env",
            "version = 1\nstrictness = \"permissive\"\n",
            Some("version = 1\nstrictness = \"standard\"\n"),
        );
        let strict = resolve_with_env(&dir, Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "strict".to_owned())
        })
        .unwrap();
        assert_eq!(strict.strictness, Strictness::Strict);
        assert_eq!(strict.sources["strictness"], Source::Env);

        // …and it still cannot go below the local file's floor.
        let err = resolve_with_env(&dir, Overrides::default(), &|name| {
            (name == "BATTEN_STRICTNESS").then(|| "permissive".to_owned())
        })
        .unwrap_err();
        assert!(is_usage_error(&err));
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
            let resolved = resolve_with_env(&dir, Overrides::default(), &|name| {
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
        let err = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
        assert!(
            err.to_string().contains("min_batten_version"),
            "the refusal must name the key, got: {err}"
        );
    }

    #[test]
    fn unknown_env_value_is_a_usage_error() {
        let dir = repo("resolve-env-bad", "version = 1\n", None);
        let err = resolve_with_env(&dir, Overrides::default(), &|name| {
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
            Overrides {
                strictness: Some(Strictness::Strict),
            },
            &env,
        )
        .unwrap();
        assert_eq!(resolved.strictness, Strictness::Strict);
        assert_eq!(resolved.sources["strictness"], Source::Flag);

        let err = resolve_with_env(
            &dir,
            Overrides {
                strictness: Some(Strictness::Permissive),
            },
            &env,
        )
        .unwrap_err();
        assert!(is_usage_error(&err), "a flag may not weaken a gate either");
    }

    #[test]
    fn there_is_no_upward_walk() {
        // §8: no directory walk. A config in the parent must not be found.
        let parent = repo("resolve-no-walk", "version = 1\n", None);
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let err = resolve_with_env(&child, Overrides::default(), &no_env).unwrap_err();
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
        let err = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn resolution_is_byte_stable() {
        // §6: the same input yields the same bytes, sources map included.
        let dir = repo("resolve-stable", "version = 1\n", None);
        let first = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
        let second = resolve_with_env(&dir, Overrides::default(), &no_env).unwrap();
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
