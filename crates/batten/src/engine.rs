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

/// The engine's own repair for a pin this build does not satisfy (CLOUD-2116).
///
/// One spelling for both halves: [`check`]'s refusal names it, and the hook's
/// floor over an unloadable config admits exactly it. A remedy naming a
/// consumer's installer was one the floor refused, so a skewed container could
/// run nothing at all, including the line its own refusal printed.
pub const REPAIR: &str = "batten engine update";

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
                     with `{REPAIR}`"
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
                     {running}: build and stamp it with `{REPAIR}`"
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

/// The pin, when one is declared and this engine does not satisfy it.
///
/// [`check`]'s question without its refusal, for the caller that would rather
/// update than refuse (CLOUD-2062). `None` covers both "no pin" and "satisfied";
/// a malformed pin is left to [`check`] to name.
#[must_use]
pub fn stale(text: &str, stamp: impl FnOnce() -> Option<String>) -> Option<Pin> {
    let pin = declared(text)?;
    let satisfied = match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), None) => tag == release(),
        (None, Some(digest)) => stamp().as_deref() == Some(digest),
        _ => true,
    };
    (!satisfied).then_some(pin)
}

/// The target triple this binary was built for, from its own compile-time `cfg`.
///
/// The triple the release matrix names (`dist::archive_stem`), so a release
/// update installs the same platform it replaces. Derived from the build itself
/// rather than probed from the host, which is the question a self-update asks:
/// "the release of ME".
#[must_use]
pub fn running_target() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "linux" if cfg!(target_env = "musl") => format!("{arch}-unknown-linux-musl"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "macos" => format!("{arch}-apple-darwin"),
        "windows" if cfg!(target_env = "gnu") => format!("{arch}-pc-windows-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        os => format!("{arch}-unknown-{os}"),
    }
}

/// The release archive's asset name for `tag` on `target`.
#[must_use]
pub fn release_asset(tag: &str, target: &str) -> String {
    let version = tag.trim_start_matches('v');
    format!(
        "{}{}",
        crate::dist::archive_stem("batten", version, target),
        crate::dist::archive_ext(target)
    )
}

/// Where `tag`'s `file` is published, under the engine's own repository.
#[must_use]
pub fn release_url(repository: &str, tag: &str, file: &str) -> String {
    format!(
        "{}/releases/download/{tag}/{file}",
        repository.trim_end_matches('/')
    )
}

/// The digest `sums` (a `SHA256SUMS` body) publishes for `asset`.
#[must_use]
pub fn published_digest(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset).then(|| digest.to_ascii_lowercase())
    })
}

//MUTANT-SUITE crates/batten/src/engine.rs
//MUTANT digest-unchecked|s@^    if got != want {$@    if false {@|an_archive_whose_digest_disagrees_is_refused

/// Refuse an archive whose SHA-256 is not the one its release published.
///
/// # Errors
///
/// A [`UsageError`] when `sums` names no digest for `asset`, or names another
/// one: the downloaded bytes are not the release's, and nothing is installed.
pub fn verify(archive: &[u8], sums: &str, asset: &str) -> Result<()> {
    let want = published_digest(sums, asset).ok_or_else(|| {
        UsageError::raise(format!(
            "engine update: the release publishes no digest for {asset}, so it cannot be verified"
        ))
    })?;
    let got = crate::receipt::hex_sha256(archive);
    if got != want {
        return Err(UsageError::raise(format!(
            "engine update: {asset} hashes {got}, not the {want} its release published; nothing was installed"
        )));
    }
    Ok(())
}

/// The engine binary of release `tag`, fetched from `repository` for this build's
/// own target and checked against that release's `SHA256SUMS` (CLOUD-2062).
///
/// The one network door this module opens, and only `batten engine update` and
/// the startup update off the hook path reach it.
///
/// # Errors
///
/// Either download answering other than 200, a digest that disagrees, or an
/// archive with no binary at its root — in every case nothing is installed.
pub fn fetch_release(repository: &str, tag: &str) -> Result<Vec<u8>> {
    let target = running_target();
    let asset = release_asset(tag, &target);
    let archive = crate::fetch::get(&release_url(repository, tag, &asset), &[])?;
    let sums = crate::fetch::get(&release_url(repository, tag, "SHA256SUMS"), &[])?;
    if archive.status != 200 || sums.status != 200 {
        return Err(UsageError::raise(format!(
            "engine update: {tag} answered {} for {asset} and {} for SHA256SUMS; nothing was installed",
            archive.status, sums.status
        )));
    }
    verify(&archive.body, &String::from_utf8_lossy(&sums.body), &asset)?;
    extract(&archive.body, &crate::dist::binary_file("batten", &target))
}

/// The `bin` entry at the root of a `.tar.gz` release archive.
///
/// # Errors
///
/// An archive that will not read, or one with no `bin` at its root.
pub fn extract(archive: &[u8], bin: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let mut entries = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in entries.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let at_root = path
            .to_str()
            .is_some_and(|name| name.trim_start_matches("./") == bin);
        if at_root {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
    }
    Err(UsageError::raise(format!(
        "engine update: the release archive carries no {bin} at its root"
    )))
}

/// The one config line that declares `pin`.
#[must_use]
pub fn line(pin: &Pin) -> String {
    match (pin.release.as_deref(), pin.source.as_deref()) {
        (Some(tag), _) => format!("engine = {{ release = \"{tag}\" }}"),
        (None, Some(digest)) => format!("engine = {{ source = \"{digest}\" }}"),
        (None, None) => String::from("engine = {}"),
    }
}

/// Whether `line` is the top-level `engine` key.
fn is_pin_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("engine")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// `text` with its top-level pin set to `pin` (CLOUD-2063).
///
/// The existing line is replaced in place. With none, the pin goes directly
/// after the first top-level key, so it stays above every table header — where
/// [`declared`] reads it — and no comment block is separated from its table.
/// Every other byte is kept.
#[must_use]
pub fn rewrite(text: &str, pin: &Pin) -> String {
    let wanted = line(pin);
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let header = lines
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    if let Some(at) = lines[..header].iter().position(|line| is_pin_line(line)) {
        lines[at] = wanted;
    } else {
        let key = lines[..header].iter().position(|line| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        });
        lines.insert(key.map_or(0, |at| at + 1), wanted);
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The `batten` verbs a workflow's command lines invoke (CLOUD-2063).
///
/// A command line is one whose trimmed text, less a YAML `- ` list marker,
/// starts `batten ` or `run: batten `;
/// prose and comments that merely mention a verb are not invocations. The verb
/// is the leading lowercase words after `batten`, at most two, so
/// `batten pr ensure "$PR_NUM"` is `pr ensure`. `mise run batten -- …` builds
/// the engine from source and is not a released-binary call, which the rule
/// excludes by construction: the line does not start with `batten`.
#[must_use]
pub fn invoked_verbs(text: &str) -> std::collections::BTreeSet<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            trimmed
                .strip_prefix("run: batten ")
                .or_else(|| trimmed.strip_prefix("batten "))
        })
        .map(|rest| {
            rest.split_whitespace()
                .take_while(|word| {
                    word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                        && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                })
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|verb| !verb.is_empty())
        .collect()
}

/// Where the pinned release's binary is kept once fetched: under the
/// repository's STATE directory, never inside the checkout.
///
/// It was first under git's common directory, and a consumer's own SBOM scan
/// then catalogued the cached binary's embedded crates as the tree's — measured
/// here, `syft scan dir:.` walked into `.git/` and the lockfile count disagreed.
/// A cache is the engine's state, and state lives outside the tree it judges.
#[must_use]
pub fn cached_release(state_dir: &Path, tag: &str) -> PathBuf {
    state_dir
        .join("engine")
        .join(tag)
        .join(crate::dist::binary_file("batten", &running_target()))
}

/// The pinned release's binary, fetched and verified once and cached after.
///
/// # Errors
///
/// As [`fetch_release`], or a cache that will not write.
pub fn pinned_release(state_dir: &Path, repository: &str, tag: &str) -> Result<PathBuf> {
    let path = cached_release(state_dir, tag);
    if path.is_file() {
        return Ok(path);
    }
    let bytes = fetch_release(repository, tag)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(&path, bytes)?;
    make_executable(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    // Windows has no executable bit; the extension carries it.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_is_rewritten_in_place_or_inserted_above_every_table() {
        let release = Pin {
            release: Some("v0.0.201".into()),
            source: None,
        };
        let pinned = "version = 1\nengine = { source = \"ab\" }\n\n# rows\n[x]\ny = 1\n";
        assert_eq!(
            rewrite(pinned, &release),
            "version = 1\nengine = { release = \"v0.0.201\" }\n\n# rows\n[x]\ny = 1\n"
        );
        let bare = "# head\nversion = 1\n\n# rows\n[x]\nengine = 2\n";
        let inserted = rewrite(bare, &release);
        assert_eq!(
            inserted,
            "# head\nversion = 1\nengine = { release = \"v0.0.201\" }\n\n# rows\n[x]\nengine = 2\n"
        );
        assert_eq!(declared(&inserted), Some(release));
    }

    #[test]
    fn only_command_lines_invoke_a_verb() {
        let workflow = "      # hands them to `batten checks green`, a pure function\n\
                        \x20       run: |\n\
                        \x20         batten pr ensure \"$PR_NUM\"\n\
                        \x20     - run: batten checks green --sha x\n\
                        \x20     - run: mise run batten -- ci step -- true\n";
        let verbs: Vec<_> = invoked_verbs(workflow).into_iter().collect();
        assert_eq!(verbs, ["checks green", "pr ensure"]);
    }

    #[test]
    fn the_release_asset_url_is_the_dist_naming() {
        let asset = release_asset("v0.0.200", "x86_64-unknown-linux-musl");
        assert_eq!(asset, "batten-v0.0.200-x86_64-unknown-linux-musl.tar.gz");
        assert_eq!(
            release_url("https://github.com/o/r/", "v0.0.200", &asset),
            "https://github.com/o/r/releases/download/v0.0.200/batten-v0.0.200-x86_64-unknown-linux-musl.tar.gz"
        );
    }

    #[test]
    fn an_archive_whose_digest_disagrees_is_refused() {
        let archive = b"the release bytes";
        let right = crate::receipt::hex_sha256(archive);
        let sums = format!("{right}  a.tar.gz\n{}  b.tar.gz\n", "0".repeat(64));
        assert!(verify(archive, &sums, "a.tar.gz").is_ok());
        assert!(
            verify(archive, &sums, "b.tar.gz").is_err(),
            "a wrong digest"
        );
        assert!(
            verify(archive, &sums, "c.tar.gz").is_err(),
            "no digest at all"
        );
    }

    #[test]
    fn the_binary_is_extracted_from_a_release_archive() -> Result<()> {
        let mut tarred = tar::Builder::new(Vec::new());
        for (name, body) in [("README", &b"docs"[..]), ("batten", &b"\x7fELF engine"[..])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tarred.append_data(&mut header, name, body)?;
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tarred.into_inner()?)?;
        let archive = gz.finish()?;
        assert_eq!(extract(&archive, "batten")?, b"\x7fELF engine");
        assert!(extract(&archive, "missing").is_err());
        Ok(())
    }

    #[test]
    fn a_satisfied_or_absent_pin_is_not_stale() {
        let tag = release();
        assert!(stale("version = 1\n", || None).is_none());
        assert!(stale(&format!("engine = {{ release = \"{tag}\" }}\n"), || None).is_none());
        assert!(stale("engine = { release = \"v0.0.1\" }\n", || None).is_some());
        assert!(stale("engine = { source = \"ab\" }\n", || Some("ab".into())).is_none());
        assert!(stale("engine = { source = \"ab\" }\n", || None).is_some());
    }
}
