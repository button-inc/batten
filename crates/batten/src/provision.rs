//! The `[[provision]]` manifest (CLOUD-90) — pinned tools, fetched and cached
//! out of tree.
//!
//! One entry per provisioned tool: a pinned version, a URL, a checksum, an
//! unpack behaviour, and the binary it yields. House-style §9's rule is that
//! consumer-specific behaviour is reconstructed through config rather than baked
//! into the core, and this is that surface for binaries.
//!
//! ## The pair, and why it is a pair
//!
//! [`status`] is the freshness gate — a `read` verb — and [`apply`] is the write
//! that fixes it. The split is §9's check/fix duality, and it is what lets a
//! provisioning gate run on the read-only surface at all.
//!
//! **The provisioned binary is never executed**, by either half. That is what
//! keeps `provision status` inside the `read` structural promise: the whole
//! equality test is a checksum, so no path here reaches code the manifest
//! downloaded. A freshness check that ran `--version` would be a `read` verb
//! executing an artifact from the internet.
//!
//! ## Fail-closed, in that order
//!
//! [`apply`] fetches into memory, verifies against the pin, and only then writes
//! anything. A mismatched artifact never touches the cache, so there is no
//! partial install to clean up and no window in which a bad binary is on disk
//! under a good name.
//!
//! ## The cache holds the artifact, not a promise about it
//!
//! Both the exact fetched bytes and the unpacked binary live under the
//! version-encoded cache path, so [`status`] can re-verify the pin against the
//! artifact it actually installed rather than against a receipt it wrote about
//! itself. Nothing provisioned is ever committed: the path comes from
//! [`crate::state`], which resolves outside the repository by construction.
//!
//! ## Why the fetch shells out to `curl`
//!
//! The acceptance requires the host's default TLS stack, so host CA
//! configuration keeps working behind a re-terminating proxy. Measured on this
//! tree: **no** TLS-capable Rust client can be linked here. `mise run
//! macos-link-check` fails any crate declaring `links` or linking an Apple
//! framework — because the macOS release is linked on Linux by zig with no
//! Apple SDK — and `native-tls` and `rustls-native-certs` pull
//! `security-framework`, while even `rustls` with bundled roots fails on
//! `ring`'s `links` key.
//!
//! `curl` is the honest resolution rather than the cheap one: it *is* the host's
//! default TLS stack and CA configuration, not a re-implementation of one, so
//! the acceptance holds in its strongest reading. It is also §9's own posture —
//! name a command already on the operator's PATH, never a downloaded, executed
//! binary. The debt this creates is tracked, not absorbed: see the shell-out
//! inventory issue referenced from `mem:core`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::UsageError;

/// The subdirectory of the repository's out-of-tree state that holds provisioned
/// tools.
const CACHE_DIR: &str = "provision";

/// The file the exact fetched bytes are stored under, so freshness re-verifies
/// the pin against the artifact rather than against a note about it.
const ARTIFACT: &str = "artifact";

/// The subdirectory the unpacked binary lands in.
const BIN_DIR: &str = "bin";

/// The program the `https://` fetch runs. Named once, so the invocation and the
/// missing-tool message cannot disagree about what is needed.
const FETCHER: &str = "curl";

/// One provisioned tool.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provision {
    /// The entry's name, unique within the manifest. Also the first cache path
    /// segment, so two tools never share a directory.
    pub name: String,
    /// The pinned version. Encoded in the cache path, so two pinned versions
    /// coexist and a version change is a cache miss rather than an overwrite.
    pub version: String,
    /// Where the artifact comes from. `https://` or `file://` — see the module
    /// docs for why those two and no others.
    pub url: String,
    /// The SHA-256 of the artifact, lowercase hex. The whole equality test.
    pub sha256: String,
    /// What the artifact is, and therefore how to get the binary out of it.
    #[serde(default)]
    pub unpack: Unpack,
    /// The binary's name inside the artifact, and the name it is cached under.
    pub binary: String,
}

/// How to get the binary out of the fetched artifact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Unpack {
    /// The artifact *is* the binary.
    #[default]
    None,
    /// A gzipped tarball; the entry whose file name is [`Provision::binary`] is
    /// extracted and everything else ignored.
    TarGz,
}

/// Why an entry is not fresh. Three states rather than a boolean, because
/// "never installed" and "installed, and the bytes are not what the pin says"
/// are different facts, and only the second is alarming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Freshness {
    /// Cache matches the manifest.
    Fresh,
    /// Nothing cached at the pinned version.
    Missing,
    /// Cached, but the artifact's digest is not the pinned one.
    Mismatch,
}

impl Freshness {
    /// Whether this entry needs an apply.
    #[must_use]
    pub const fn is_stale(self) -> bool {
        !matches!(self, Freshness::Fresh)
    }

    /// The stable verdict token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Freshness::Fresh => "fresh",
            Freshness::Missing => "missing",
            Freshness::Mismatch => "mismatch",
        }
    }
}

/// One entry's freshness. Pointer-only: a name, a pinned version, a verdict —
/// never a URL's response and never a byte of the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct EntryStatus {
    /// The entry's name.
    pub name: String,
    /// The pinned version.
    pub version: String,
    /// The verdict.
    pub freshness: Freshness,
}

impl EntryStatus {
    /// The report line for a stale entry.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{} {} {}", self.name, self.version, self.freshness.as_str())
    }
}

/// What [`status`] found, in manifest order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Report {
    /// Every entry, in the order the manifest declares them.
    pub entries: Vec<EntryStatus>,
}

impl Report {
    /// Whether any entry needs an apply.
    #[must_use]
    pub fn any_stale(&self) -> bool {
        self.entries.iter().any(|entry| entry.freshness.is_stale())
    }

    /// The stale entries' report lines, in manifest order.
    #[must_use]
    pub fn stale_lines(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.freshness.is_stale())
            .map(EntryStatus::line)
            .collect()
    }
}

/// The cache directory for one entry: `<state>/provision/<name>/<version>/`.
///
/// The version is a path segment rather than part of a file name, so two pinned
/// versions coexist and a version bump is a cache miss instead of an overwrite
/// that cannot be undone.
#[must_use]
pub fn entry_dir(cache_root: &Path, entry: &Provision) -> PathBuf {
    cache_root
        .join(CACHE_DIR)
        .join(&entry.name)
        .join(&entry.version)
}

/// The out-of-tree cache root for the repository at `repo_root`.
///
/// # Errors
///
/// Propagates [`crate::state::repo_state_dir`]'s failures.
pub fn cache_root(repo_root: &Path) -> Result<PathBuf> {
    crate::state::repo_state_dir(repo_root)
}

/// The SHA-256 of `bytes`, lowercase hex.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in out {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// Judge every entry against the cache under `cache_root`.
///
/// Reads two things per entry and executes nothing: the cached artifact's bytes,
/// and whether the binary is present. That is the whole test.
///
/// # Errors
///
/// An I/O failure other than a missing cache entry propagates as an internal
/// error (→ exit `3`). A missing entry is a verdict, not a failure.
pub fn status(entries: &[Provision], cache_root: &Path) -> Result<Report> {
    let mut report = Vec::with_capacity(entries.len());
    for entry in entries {
        report.push(EntryStatus {
            name: entry.name.clone(),
            version: entry.version.clone(),
            freshness: freshness_of(entry, cache_root)?,
        });
    }
    Ok(Report { entries: report })
}

fn freshness_of(entry: &Provision, cache_root: &Path) -> Result<Freshness> {
    let dir = entry_dir(cache_root, entry);
    let binary = dir.join(BIN_DIR).join(&entry.binary);
    if !binary.is_file() {
        return Ok(Freshness::Missing);
    }
    let artifact = match fs::read(dir.join(ARTIFACT)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Freshness::Missing),
        Err(err) => return Err(err).context("read the cached artifact"),
    };
    // Case-insensitive on the hex, so a manifest written in uppercase is not a
    // permanent mismatch nobody can explain.
    Ok(if digest(&artifact).eq_ignore_ascii_case(&entry.sha256) {
        Freshness::Fresh
    } else {
        Freshness::Mismatch
    })
}

/// The outcome of applying one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Applied {
    /// Fetched, verified, and installed.
    Installed,
    /// Already fresh; nothing fetched and nothing written.
    AlreadyFresh,
    /// `--dry-run`: nothing fetched and nothing written.
    Previewed,
}

/// Fetch, verify, and install every stale entry under `cache_root`.
///
/// Order is load-bearing: fetch into memory, compare against the pin, and only
/// then write. A mismatched artifact never reaches the cache, so there is no
/// partial install and no window where a bad binary sits under a good name.
///
/// # Errors
///
/// A checksum mismatch raises a [`Denial`](crate::Denial) (→ exit `2`): it is a
/// verdict about the pin, not a failure of Batten's. An unreachable URL, an
/// absent fetcher, or an I/O failure is an internal error (→ exit `3`) — the
/// apply could not complete, which is a different claim from one it did make. An
/// unsupported URL scheme is a [`UsageError`] (→ exit `1`), since the manifest
/// asked for something this build does not do.
pub fn apply(entry: &Provision, cache_root: &Path, dry_run: bool) -> Result<Applied> {
    if freshness_of(entry, cache_root)? == Freshness::Fresh {
        return Ok(Applied::AlreadyFresh);
    }
    if dry_run {
        // A preview fetches nothing. Reaching the network to report that we
        // would reach the network is not a preview of doing nothing.
        return Ok(Applied::Previewed);
    }

    let bytes = fetch(&entry.url)?;
    let found = digest(&bytes);
    if !found.eq_ignore_ascii_case(&entry.sha256) {
        // Pointer-only: the two digests, never a byte of what was fetched. A
        // mismatched artifact is exactly the thing least safe to echo.
        return Err(crate::Denial::raise(format!(
            "provision {}: artifact does not match the pinned checksum (pinned {}, fetched {}); \
             nothing was installed",
            entry.name, entry.sha256, found
        )));
    }

    install(entry, cache_root, &bytes)?;
    Ok(Applied::Installed)
}

/// Write the verified artifact and its binary into the cache.
///
/// Called only after the checksum matched.
fn install(entry: &Provision, cache_root: &Path, bytes: &[u8]) -> Result<()> {
    let dir = entry_dir(cache_root, entry);
    let bin_dir = dir.join(BIN_DIR);
    fs::create_dir_all(&bin_dir).context("create the provision cache directory")?;

    let binary = match entry.unpack {
        Unpack::None => bytes.to_vec(),
        Unpack::TarGz => extract(bytes, &entry.binary)?,
    };
    fs::write(bin_dir.join(&entry.binary), &binary).context("write the provisioned binary")?;
    make_executable(&bin_dir.join(&entry.binary))?;
    // The artifact is written last, so a crash between the two leaves the entry
    // reading `missing` rather than `fresh` — the direction that re-applies.
    fs::write(dir.join(ARTIFACT), bytes).context("write the cached artifact")?;
    Ok(())
}

/// Extract the entry named `binary` from a gzipped tarball.
///
/// Matches on the archive path's **file name**, so a release tarball that nests
/// its binary under a versioned directory works without the manifest restating
/// that directory — which would be the version pinned in two places.
fn extract(bytes: &[u8], binary: &str) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("read the tar archive")? {
        let mut entry = entry.context("read a tar entry")?;
        let path = entry
            .path()
            .context("decode a tar entry path")?
            .into_owned();
        if path.file_name().and_then(|name| name.to_str()) != Some(binary) {
            continue;
        }
        let mut out = Vec::new();
        entry
            .read_to_end(&mut out)
            .context("read the binary out of the archive")?;
        return Ok(out);
    }
    Err(UsageError::raise(format!(
        "the artifact contains no entry named {binary}"
    )))
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .context("read the provisioned binary's permissions")?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).context("mark the provisioned binary executable")
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    // Windows has no executable bit; the extension carries it.
    Ok(())
}

/// Fetch `url` into memory.
///
/// Two schemes and no others. `file://` is what makes the fixtures hermetic;
/// `https://` goes through [`FETCHER`], which is the host's own TLS stack — see
/// the module docs for why that is a deliberate choice rather than a shortcut.
///
/// Plain `http://` is absent on purpose: a pinned checksum makes tampering
/// detectable, not impossible to attempt, and there is no reason to fetch a
/// pinned artifact over a channel that can be rewritten in flight.
fn fetch(url: &str) -> Result<Vec<u8>> {
    if let Some(path) = url.strip_prefix("file://") {
        return fs::read(path).with_context(|| format!("fetch {url}"));
    }
    if url.starts_with("https://") {
        return fetch_https(url);
    }
    Err(UsageError::raise(format!(
        "provision: unsupported URL scheme in {url}; only https:// and file:// are fetched"
    )))
}

/// Fetch over HTTPS through the host's `curl`.
///
/// Every flag is load-bearing:
///
/// * `--fail` — without it curl exits `0` for a 404 and writes the error page to
///   stdout, which the checksum would then reject as a mismatch. That would
///   report a *tampered artifact* for a *missing* one: exit 2 where exit 3 is
///   correct, and a verdict where there was only a failure.
/// * `--proto '=https'` and `--proto-redir '=https'` — a redirect must not
///   downgrade the transport that was the whole point of choosing the scheme.
/// * `--location` — release URLs redirect, routinely.
/// * `--silent --show-error` — no progress meter on a non-TTY, but errors kept.
///
/// The response body reaches memory and nothing else; curl's stderr is dropped
/// rather than surfaced, since a fetch error's prose is not Batten's output
/// contract and may quote the URL's response.
fn fetch_https(url: &str) -> Result<Vec<u8>> {
    let output = Command::new(FETCHER)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--",
            url,
        ])
        .output()
        .with_context(|| {
            format!("run `{FETCHER}` to fetch over https; install it, or use a file:// URL")
        })?;
    if !output.status.success() {
        anyhow::bail!("could not fetch {url}");
    }
    Ok(output.stdout)
}

/// Validate the manifest at load.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a duplicate name, an empty required
/// field, or a checksum that is not 64 hex characters. A malformed pin is worth
/// refusing at load rather than at fetch time: it can never match, so every
/// apply would fail with a mismatch that blames the artifact for a typo in the
/// config.
pub fn validate(entries: &[Provision]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in entries {
        for (key, value) in [
            ("name", &entry.name),
            ("version", &entry.version),
            ("url", &entry.url),
            ("binary", &entry.binary),
        ] {
            if value.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "provision: `{key}` must not be empty"
                )));
            }
        }
        if seen.contains(&entry.name.as_str()) {
            return Err(UsageError::raise(format!(
                "provision {}: declared twice; each entry owns its own cache path",
                entry.name
            )));
        }
        seen.push(&entry.name);

        if entry.sha256.len() != 64 || !entry.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UsageError::raise(format!(
                "provision {}: `sha256` must be 64 hex characters",
                entry.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(name: &str, sha: &str) -> Provision {
        Provision {
            name: name.to_owned(),
            version: "1.2.3".to_owned(),
            url: "file:///dev/null".to_owned(),
            sha256: sha.to_owned(),
            unpack: Unpack::None,
            binary: "tool".to_owned(),
        }
    }

    #[test]
    fn the_version_is_a_cache_path_segment_so_two_pins_coexist() {
        let root = Path::new("/state");
        let mut old = entry("tool", &"a".repeat(64));
        old.version = "1.0.0".to_owned();
        let mut new = entry("tool", &"b".repeat(64));
        new.version = "2.0.0".to_owned();
        assert_ne!(entry_dir(root, &old), entry_dir(root, &new));
        assert!(entry_dir(root, &new).ends_with("provision/tool/2.0.0"));
    }

    #[test]
    fn a_malformed_pin_is_refused_at_load_not_at_fetch() {
        // It can never match, so every apply would report a mismatch — blaming
        // the artifact for a typo in the config.
        assert!(validate(&[entry("t", "not-hex")]).is_err());
        assert!(validate(&[entry("t", &"a".repeat(63))]).is_err());
        assert!(
            validate(&[entry("t", &"A".repeat(64))]).is_ok(),
            "case is not the test"
        );
    }

    #[test]
    fn a_duplicate_name_is_refused_because_the_cache_path_is_the_name() {
        let entries = [
            entry("tool", &"a".repeat(64)),
            entry("tool", &"b".repeat(64)),
        ];
        assert!(validate(&entries).is_err());
    }

    #[test]
    fn an_unsupported_scheme_is_a_usage_error_and_http_is_not_supported() {
        for url in [
            "http://example.com/x",
            "ftp://example.com/x",
            "example.com/x",
        ] {
            let err = fetch(url).unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{url} must be refused as bad input"
            );
        }
    }

    #[test]
    fn the_digest_is_lowercase_hex_of_the_bytes() {
        // The empty string's SHA-256, so this pins the encoding and not just
        // its own output.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn freshness_distinguishes_never_installed_from_wrong_bytes() {
        assert!(Freshness::Missing.is_stale());
        assert!(Freshness::Mismatch.is_stale());
        assert!(!Freshness::Fresh.is_stale());
        assert_ne!(Freshness::Missing.as_str(), Freshness::Mismatch.as_str());
    }
}
