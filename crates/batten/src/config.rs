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
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::Rule;

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
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize, ValueEnum,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The config schema version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// The minimum Batten version permitted to read this file. Parsed now;
    /// enforcement lands with the `min_batten_version` gate (CLOUD-33).
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
    let config: Config = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("invalid config {source}: {err}")))?;
    if config.version != SUPPORTED_VERSION {
        return Err(UsageError::raise(format!(
            "unsupported config version {} in {source}; this build supports version {SUPPORTED_VERSION}",
            config.version
        )));
    }
    Ok(config)
}

/// Load and validate the `batten.toml` at `path`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the file is missing, malformed,
/// carries an unknown key, or declares an unsupported version. A non-`NotFound`
/// I/O failure propagates as an internal error (→ exit `3`).
pub fn load(path: &Path) -> Result<Config> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "no config found at {}",
                path.display()
            )));
        }
        Err(err) => return Err(err.into()),
    };
    parse(&text, &path.display().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::error::UsageError;

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
        assert_eq!(parse("version = 1\n", "test").unwrap().fail_on_warning, None);
    }

    #[test]
    fn a_non_boolean_fail_on_warning_is_a_usage_error() {
        // The key's vocabulary is TOML's own boolean literals; a string that
        // merely looks like one is bad input, not a value to coerce. This is the
        // same typing discipline `version = "1"` is held to above.
        for value in ["\"true\"", "1", "\"yes\""] {
            let err = parse(&format!("version = 1\nfail_on_warning = {value}\n"), "test")
                .unwrap_err();
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
