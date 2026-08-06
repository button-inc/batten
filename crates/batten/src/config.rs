//! The `batten.toml` loader (house-style §8).
//!
//! Configuration is **one committed authority** — the repo `batten.toml` — plus
//! raise-only overrides (env, flags, a git-ignored `batten.local.toml`). This
//! module loads and validates the committed authority; the override layering and
//! the raise-only clamp land on top of it (the clamp's gate is CLOUD-87).
//!
//! The surface is deliberately narrow (non-negotiable rule 6): the config is a
//! typed struct with **no unknown keys** — a typo is an error, not a silently
//! ignored setting — and a required schema `version` so an incompatible file
//! fails loudly rather than being half-understood.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The config schema version this build understands. A file declaring any other
/// version is refused rather than partially interpreted.
pub const SUPPORTED_VERSION: u32 = 1;

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
}

/// Parse and validate a `batten.toml` from `text`, attributing errors to
/// `source` (a path or label) in their messages.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `2`) for a malformed file, an unknown key,
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
/// Returns a [`UsageError`] (→ exit `2`) when the file is missing, malformed,
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
}
