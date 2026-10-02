//! The engine pin: which batten a config needs, read before the config is
//! parsed (CLOUD-2061).
//!
//! # Why a pin and not the floor
//!
//! `min_batten_version` is a minimum, and it is read only once a load has already
//! failed. Measured: a reclaimed container installed the latest release over a
//! branch build, the release refused a config key the branch had added, and every
//! mediated rule failed open for the session. A floor cannot say "this exact
//! engine", and nothing recorded which SOURCE an installed binary came from.
//!
//! # The two identities
//!
//! - **A release** is `v{VERSION}`, which the binary already carries.
//! - **A source** is the SHA-256 of every tracked engine input — each path under
//!   `crates/`, plus the root `Cargo.toml` and `Cargo.lock` — as path, NUL, bytes,
//!   NUL, in sorted order. Tracked, so `target/` and scratch never enter; the
//!   bytes on disk, so an uncommitted edit to a tracked file does. `batten engine
//!   stamp` writes it beside the running binary as `<binary>.source` once
//!   `install:local` has installed it.
//!
//! # Before the parse, and on every load
//!
//! [`check`] runs at the top of [`crate::config::parse`], over the raw text, so a
//! stale engine is named before a key it cannot read can fail the parse. It scans
//! top-level lines up to the first `[` header and parses only the one beginning
//! `engine`, so a config without a pin pays one line scan. A mismatch is a
//! [`UsageError`]; on the hook path that is the `engine-cannot-adjudicate` deny,
//! which names the update — a stale engine refuses rather than deciding silently.
//!
//! **A missing or unreadable stamp is a mismatch.** Could-not-look never buys a
//! pass: a source pin exists to say "this exact build", and a binary that cannot
//! say what it was built from has not said it.

use std::path::{Path, PathBuf};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The engine a config needs: exactly one of a release tag or a source digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// A published release, spelled as its tag (`v0.0.198`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The digest `batten engine digest` prints for the source tree the engine
    /// must be built from (64 hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The suffix of the stamp written beside an installed binary.
pub const STAMP_SUFFIX: &str = "source";

/// This binary's release identity.
#[must_use]
pub fn release() -> String {
    format!("v{}", crate::config::VERSION)
}

/// The stamp file beside `binary`.
#[must_use]
pub fn stamp_path(binary: &Path) -> PathBuf {
    let mut name = binary.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(STAMP_SUFFIX);
    binary.with_file_name(name)
}

/// Whether a tracked path is an engine input.
fn is_input(path: &str) -> bool {
    path.starts_with("crates/") || path == "Cargo.toml" || path == "Cargo.lock"
}

/// The source digest of the tree at `root`.
///
/// # Errors
///
/// A tree that is not a repository, or a tracked input that will not read.
pub fn digest(root: &Path) -> Result<String> {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for path in crate::git::tracked_paths(root)?
        .iter()
        .filter(|path| is_input(path))
    {
        let bytes = std::fs::read(root.join(path))?;
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
        hasher.update([0]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Write `digest` as the stamp beside `binary`.
///
/// # Errors
///
/// The stamp will not write.
pub fn stamp(binary: &Path, digest: &str) -> Result<()> {
    crate::durable::replace(stamp_path(binary), format!("{digest}\n"))?;
    Ok(())
}

/// The pin a config declares, read from its raw text without parsing the rest.
///
/// Top-level keys precede the first table header in TOML, so the scan stops
/// there; an `engine` line past it belongs to some table and is not the pin.
#[must_use]
pub fn declared(text: &str) -> Option<Pin> {
    let line = text
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
        .find(|line| {
            line.trim_start()
                .strip_prefix("engine")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })?;
    let table: toml::Table = toml::from_str(line).ok()?;
    table.get("engine")?.clone().try_into().ok()
}

//MUTANT-SUITE crates/batten/tests/it/engine_pin.rs
//MUTANT pin-unread|s@^    let Some(pin) = declared(text) else {$@    let Some(pin) = None::<Pin> else {@|a_release_pin_naming_another_build_is_refused_with_its_install
//MUTANT stamp-trusted-when-absent|s@^            if stamp.as_deref() != Some(digest) {$@            if stamp.is_some() \&\& stamp.as_deref() != Some(digest) {@|a_source_pin_without_a_stamp_is_refused

/// Refuse a config whose pin this engine does not satisfy.
///
/// `stamp` yields this binary's recorded source digest, or `None` when it has
/// none. It is asked only for a source pin, so a config pinning a release — or
/// nothing — never touches the disk for it.
///
/// # Errors
///
/// A [`UsageError`] naming both identities and the update, when the pin names
/// another release or another source, names both or neither, or names a source
/// this binary carries no stamp for.
pub fn check(text: &str, source: &str, stamp: impl FnOnce() -> Option<String>) -> Result<()> {
    let Some(pin) = declared(text) else {
        return Ok(());
    };
    match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), None) => {
            let running = release();
            if tag != running {
                return Err(UsageError::raise(format!(
                    "{source} pins batten {tag} and this engine is {running}: install the pin \
                     with `BATTEN_VERSION={tag} ./install.sh`"
                )));
            }
            Ok(())
        }
        (None, Some(digest)) => {
            let stamp = stamp();
            if stamp.as_deref() != Some(digest) {
                let running = stamp.as_deref().unwrap_or("unstamped");
                return Err(UsageError::raise(format!(
                    "{source} pins the engine built from source {digest} and this engine is \
                     {running}: build and stamp it with `mise run install:local`"
                )));
            }
            Ok(())
        }
        _ => Err(UsageError::raise(format!(
            "{source}: `engine` names exactly one of `release` or `source`"
        ))),
    }
}

/// This running binary's stamp, or `None` when it carries none.
#[must_use]
pub fn running_stamp() -> Option<String> {
    let binary = std::env::current_exe().ok()?;
    let text = std::fs::read_to_string(stamp_path(&binary)).ok()?;
    let digest = text.trim();
    (!digest.is_empty()).then(|| digest.to_owned())
}
