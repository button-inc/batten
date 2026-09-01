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
//! ## The fetch is in process, and `curl` is gone (CLOUD-745)
//!
//! This module used to spawn `curl`, on a verdict that said **no** TLS-capable
//! Rust client can be linked here. That verdict was measured over three
//! `reqwest` feature presets and generalised past them: all three died at the
//! same two chokepoints — the platform trust store and the crypto provider —
//! and nothing had ever resolved a graph carrying a links-free provider under
//! vendored roots. [`crate::fetch`] is that graph, and it links. The
//! measurement lives beside the dependencies in `Cargo.toml` and in that
//! module's own docs; it is not restated here.
//!
//! Two consequences are this module's rather than the adapter's.
//!
//! **The `--fail` distinction is structural now.** `curl` reports a 404 body as
//! a successful fetch, so the error page reached [`digest`] and came back as a
//! checksum *mismatch* — a tampered artifact reported for a missing one, exit
//! `2` where `3` is correct. [`crate::fetch::Response`] carries the status as a
//! number, so [`fetch_https`] refuses a non-2xx before a byte reaches the
//! digest and the two answers cannot be confused.
//!
//! **Nothing streams to disk.** [`fetch`] returns a `Vec<u8>` and [`apply`]
//! digests the whole body before [`install`] touches the cache. That is what
//! makes an interrupted fetch leave the cache byte-identical, and it is the
//! property the obvious streaming idiom destroys silently.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// One provisioned tool.
///
/// The `oneOf` mirrors [`validate_artifact_spelling`]'s xor into the derived
/// schema, the same way [`crate::rules::Rule`] mirrors its severity conditional:
/// an author editing `batten.toml` against the published schema gets the refusal
/// in their editor rather than on the next run. It is a **second expression of
/// one rule, never a second authority** — the loader's check is what decides, and
/// it is what the error message comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = serde_json::json!([
    { "required": ["url", "sha256"], "not": { "required": ["platforms"] } },
    { "required": ["platforms"], "not": { "anyOf": [
        { "required": ["url"] },
        { "required": ["sha256"] }
    ] } }
])))]
pub struct Provision {
    /// The entry's name, unique within the manifest. Also the first cache path
    /// segment, so two tools never share a directory.
    pub name: String,
    /// The pinned version. Encoded in the cache path, so two pinned versions
    /// coexist and a version change is a cache miss rather than an overwrite.
    pub version: String,
    /// Where the artifact comes from, when one artifact serves every platform.
    /// `https://` or `file://` — see the module docs for why those two and no
    /// others.
    ///
    /// Mutually exclusive with [`Provision::platforms`]; see that field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The SHA-256 of the artifact, lowercase hex. The whole equality test.
    ///
    /// Paired with [`Provision::url`], and refused without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Per-platform artifacts, keyed `<os>-<arch>` — `linux-x86_64`,
    /// `macos-aarch64`, `windows-x86_64`.
    ///
    /// **Exactly one of this and the `url`/`sha256` pair**, refused at load
    /// rather than at fetch. Two spellings exist because two genuinely different
    /// things get pinned: a platform-independent artifact (a script, a jar, a
    /// test fixture) has one URL and gains nothing from a table, while a
    /// compiled tool ships one artifact per target and cannot be expressed
    /// without one. Collapsing them would force every entry to name a platform
    /// it does not have, and the xor is the same shape `RuleKind::Forbid`'s
    /// `pattern`/`regex` predicate already uses.
    ///
    /// The key is `{os}-{arch}` read straight off [`std::env::consts`] rather
    /// than a Rust target triple. That is what the running binary can actually
    /// observe about itself; a triple would need a mapping table, and the arm
    /// that guesses `-gnu` versus `-musl` from `os = "linux"` is a guess that
    /// installs a binary the host cannot run. The granularity is the same one
    /// `mise.lock` uses, and it inherits the same limitation, stated rather than
    /// hidden: glibc and musl share the `linux` key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platforms: BTreeMap<String, Artifact>,
    /// What the artifact is, and therefore how to get the binary out of it.
    #[serde(default)]
    pub unpack: Unpack,
    /// The binary's name inside the artifact, and the name it is cached under.
    pub binary: String,
}

/// One platform's artifact: where it comes from, and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Where the artifact comes from. `https://` or `file://`.
    pub url: String,
    /// The SHA-256 of the artifact, lowercase hex.
    pub sha256: String,
}

impl Provision {
    /// The artifact this host should install.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when the entry declares a platform
    /// table with no row for this host. **Never a silent skip**: an entry that
    /// cannot be installed here is a manifest this host cannot satisfy, and
    /// reporting it as fresh would let a gate depending on the tool pass without
    /// the tool.
    pub fn artifact(&self) -> Result<Artifact> {
        self.artifact_for(platform_key().as_str())
    }

    /// [`Provision::artifact`] for a named platform, so the suite can drive a
    /// platform the test host is not.
    ///
    /// # Errors
    ///
    /// As [`Provision::artifact`].
    pub fn artifact_for(&self, platform: &str) -> Result<Artifact> {
        if let (Some(url), Some(sha256)) = (self.url.as_ref(), self.sha256.as_ref()) {
            return Ok(Artifact {
                url: url.clone(),
                sha256: sha256.clone(),
            });
        }
        self.platforms.get(platform).cloned().ok_or_else(|| {
            // Pointer-only: the platform this host is and the ones the entry
            // names, never a URL and never a byte.
            UsageError::raise(format!(
                "provision {}: no artifact for {platform}; the entry pins {}",
                self.name,
                if self.platforms.is_empty() {
                    "nothing".to_owned()
                } else {
                    self.platforms
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ))
        })
    }
}

/// This host's platform key: `<os>-<arch>`, e.g. `linux-x86_64`.
///
/// Read off [`std::env::consts`], which is what the compiled binary knows about
/// itself. See [`Provision::platforms`] for why this rather than a target triple.
#[must_use]
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
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
    let cached = match fs::read(dir.join(ARTIFACT)) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Freshness::Missing),
        Err(err) => return Err(err).context("read the cached artifact"),
    };
    // The pin is THIS host's artifact, not the entry's whole table: a cache
    // holding the linux tarball is fresh on linux and says nothing about macOS.
    // An entry with no row for this platform is a usage error rather than a
    // freshness verdict, and it propagates — reporting `fresh` for a tool that
    // cannot be installed here would let a gate depending on it pass without it.
    let artifact = entry.artifact()?;
    // Case-insensitive on the hex, so a manifest written in uppercase is not a
    // permanent mismatch nobody can explain.
    Ok(if digest(&cached).eq_ignore_ascii_case(&artifact.sha256) {
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
/// verdict about the pin, not a failure of Batten's. An unreachable URL, a
/// non-2xx status, a timeout, or an I/O failure is an internal error (→ exit
/// `3`) — the apply could not complete, which is a different claim from one it
/// did make. An
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

    let artifact = entry.artifact()?;
    let bytes = fetch(&artifact.url)?;
    let found = digest(&bytes);
    if !found.eq_ignore_ascii_case(&artifact.sha256) {
        // Pointer-only: the two digests, never a byte of what was fetched. A
        // mismatched artifact is exactly the thing least safe to echo.
        return Err(crate::Denial::raise(format!(
            "provision {}: artifact does not match the pinned checksum (pinned {}, fetched {}); \
             nothing was installed",
            entry.name, artifact.sha256, found
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
/// **Into memory, and that is the contract rather than an implementation
/// detail.** [`apply`] digests what this returns and only then calls
/// [`install`], so nothing unverified can reach the cache. A variant that
/// streamed to a file would satisfy the signature's spirit and destroy that.
///
/// Two schemes and no others. `file://` is what makes the fixtures hermetic;
/// `https://` goes through [`crate::fetch`], the crate's one network adapter.
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

/// Fetch over HTTPS, in process.
///
/// Three properties the `curl` invocation this replaced spelled as flags, and
/// which are now the adapter's own shape rather than a list somebody maintains:
///
/// * **HTTPS only, redirect included.** `--proto '=https'` and
///   `--proto-redir '=https'` said a redirect must not downgrade the transport
///   that was the whole point of choosing the scheme. The connector is built
///   `https_only`, so the transport refuses a plain-HTTP URL by construction.
/// * **A status is a value, not an exit code.** `--fail` existed because curl
///   reports a 404 body as a successful fetch. A non-2xx is refused here,
///   before a byte reaches [`digest`], so a *missing* artifact stays exit `3`
///   and can never be reported as the *tampered* one exit `2` means.
/// * **Bounded.** The flag list carried neither `--max-time` nor
///   `--connect-timeout`, so a server that accepted and never answered hung
///   `provision apply` forever. [`crate::fetch`] bounds the connect and the
///   whole exchange.
///
/// Pointer-only on the failure paths: the URL and the status, never a byte of
/// what came back. A fetch error's prose is not Batten's output contract, and a
/// non-2xx body is exactly the content least safe to echo.
fn fetch_https(url: &str) -> Result<Vec<u8>> {
    let response = crate::fetch::get(url, &[]).with_context(|| format!("fetch {url}"))?;
    body_of(url, response)
}

/// The bytes a response yields, or a refusal — the `--fail` decision, extracted.
///
/// **Extracted so it is REACHABLE, which is the whole reason it is its own
/// function** (CLOUD-418). Vendored roots are what let this module link at all,
/// and they also mean no hermetic fixture can stand up an HTTPS endpoint this
/// client will trust — a loopback CA is now correctly untrustable, which is why
/// the `openssl s_server` case retired with `curl`. So the 404-versus-mismatch
/// pair cannot be discriminated end to end over the binary any more, and a
/// function taking the response as a VALUE is where it still can be.
///
/// A careless port returns `response.body` unconditionally and passes every
/// other case in both suites.
fn body_of(url: &str, response: crate::fetch::Response) -> Result<Vec<u8>> {
    if !(200..300).contains(&response.status) {
        // Pointer-only: the URL and the status. Never the body — a non-2xx body
        // is an error page from somewhere the operator did not choose.
        anyhow::bail!("could not fetch {url}: HTTP {}", response.status);
    }
    Ok(response.body)
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

        validate_artifact_spelling(entry)?;
    }
    Ok(())
}

/// The `url`/`sha256`-versus-`platforms` xor, plus every checksum's shape.
///
/// Refused at load for the same reason a malformed checksum is: an entry
/// spelling both, or neither, can never install anything, so every apply would
/// fail with a message about the artifact rather than about the config.
fn validate_artifact_spelling(entry: &Provision) -> Result<()> {
    // `url` and `sha256` are one spelling in two fields, so a half-written pair
    // is its own error — reporting it as "no artifact" would send the author
    // looking for a platform table they never meant to write.
    match (entry.url.as_ref(), entry.sha256.as_ref()) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(UsageError::raise(format!(
                "provision {}: `url` and `sha256` are a pair; declare both or neither",
                entry.name
            )));
        }
        _ => {}
    }

    let single = entry.url.is_some();
    let table = !entry.platforms.is_empty();
    if single && table {
        return Err(UsageError::raise(format!(
            "provision {}: declares both a single `url` and a `[provision.platforms]` table; \
             exactly one, or two pins could disagree about what this host installs",
            entry.name
        )));
    }
    if !single && !table {
        return Err(UsageError::raise(format!(
            "provision {}: declares no artifact; give it a `url` + `sha256`, or a \
             `[provision.platforms]` table keyed `<os>-<arch>` (this host is {})",
            entry.name,
            platform_key()
        )));
    }

    if let (Some(url), Some(sha256)) = (entry.url.as_ref(), entry.sha256.as_ref()) {
        check_url(&entry.name, "url", url)?;
        check_sha256(&entry.name, "sha256", sha256)?;
    }
    for (platform, artifact) in &entry.platforms {
        if platform.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: a platform key must not be empty",
                entry.name
            )));
        }
        check_url(&entry.name, platform, &artifact.url)?;
        check_sha256(&entry.name, platform, &artifact.sha256)?;
    }
    Ok(())
}

fn check_url(name: &str, where_: &str, url: &str) -> Result<()> {
    if url.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "provision {name}: `{where_}` has an empty url"
        )));
    }
    Ok(())
}

fn check_sha256(name: &str, where_: &str, sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(UsageError::raise(format!(
            "provision {name}: `{where_}` sha256 must be 64 hex characters"
        )));
    }
    Ok(())
}

/// Where the provisioned binary for `entry` lives, given the repository root.
///
/// The resolver the manifest shipped without: [`entry_dir`] and [`cache_root`]
/// were public and had no caller outside this module, so nothing could turn a
/// `[[provision]]` row into a path something else could run. A consumer that
/// needs the tool asks here rather than reconstructing the layout, which is what
/// keeps `<name>/<version>/bin/<binary>` a fact of this module.
///
/// **Existence is not checked**, deliberately. This answers "where would it be";
/// whether it is there is [`status`]'s question, and a caller that conflated the
/// two would report a missing tool as a resolution failure. The caller's own
/// missing-binary message is what names `batten provision apply`.
///
/// # Errors
///
/// Propagates [`cache_root`]'s failure to resolve the out-of-tree state
/// directory.
pub fn binary_path(repo_root: &Path, entry: &Provision) -> Result<PathBuf> {
    Ok(entry_dir(&cache_root(repo_root)?, entry)
        .join(BIN_DIR)
        .join(&entry.binary))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A response carrying `status` over a body that would digest cleanly if it
    /// ever reached [`digest`] — which is the point: a case whose body was
    /// obviously junk would pass against an implementation that returned it.
    fn response(status: u16) -> crate::fetch::Response {
        crate::fetch::Response {
            status,
            body: b"<!doctype html><title>404</title>".to_vec(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn a_non_2xx_body_never_reaches_the_digest() {
        // THE `--fail` DISTINCTION, and the whole of what it protects. `curl`
        // reported a 404 body as a successful fetch, so the error page reached
        // the checksum and came back as a MISMATCH — a tampered artifact
        // reported for a missing one, exit 2 where exit 3 is correct.
        for status in [301_u16, 400, 403, 404, 500, 503] {
            let answer = body_of("https://example.invalid/x", response(status));
            assert!(
                answer.is_err(),
                "HTTP {status} must refuse before the body is handed back"
            );
        }
    }

    #[test]
    fn the_refusal_is_a_pointer_and_never_the_body() {
        // Non-negotiable rule 4, on the one path whose payload is content from
        // somewhere the operator did not choose.
        let body = response(404).body;
        let message = body_of("https://example.invalid/x", response(404))
            .expect_err("a 404 is refused")
            .to_string();
        assert!(message.contains("404"), "the status is the pointer");
        assert!(
            !message.contains(&String::from_utf8_lossy(&body).to_string()),
            "no byte of the response body may reach the message"
        );
    }

    #[test]
    fn a_2xx_yields_its_body_unchanged() {
        // The allow half. Without it the case above is satisfied by a function
        // that refuses everything, which would gate nothing and fetch nothing.
        let bytes = b"artifact".to_vec();
        let answer = body_of(
            "https://example.invalid/x",
            crate::fetch::Response {
                status: 200,
                body: bytes.clone(),
                headers: Vec::new(),
            },
        );
        assert_eq!(answer.unwrap(), bytes);
    }

    fn entry(name: &str, sha: &str) -> Provision {
        Provision {
            name: name.to_owned(),
            version: "1.2.3".to_owned(),
            url: Some("file:///dev/null".to_owned()),
            sha256: Some(sha.to_owned()),
            platforms: BTreeMap::new(),
            unpack: Unpack::None,
            binary: "tool".to_owned(),
        }
    }

    /// The same entry spelled as a platform table instead of a single url.
    fn platform_entry(name: &str, rows: &[(&str, &str)]) -> Provision {
        let mut entry = entry(name, &"a".repeat(64));
        entry.url = None;
        entry.sha256 = None;
        entry.platforms = rows
            .iter()
            .map(|(platform, sha)| {
                (
                    (*platform).to_owned(),
                    Artifact {
                        url: format!("file:///dev/null/{platform}"),
                        sha256: (*sha).to_owned(),
                    },
                )
            })
            .collect();
        entry
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
    fn exactly_one_artifact_spelling_is_accepted() {
        // Both is refused because two pins could disagree about what this host
        // installs; neither is refused because it can never install anything.
        let mut both = entry("t", &"a".repeat(64));
        both.platforms = platform_entry("t", &[("linux-x86_64", &"b".repeat(64))]).platforms;
        assert!(validate(&[both]).is_err(), "both spellings must be refused");

        let mut neither = entry("t", &"a".repeat(64));
        neither.url = None;
        neither.sha256 = None;
        assert!(
            validate(&[neither]).is_err(),
            "an entry with no artifact must be refused"
        );

        assert!(validate(&[entry("t", &"a".repeat(64))]).is_ok());
        assert!(validate(&[platform_entry("t", &[("linux-x86_64", &"a".repeat(64))])]).is_ok());
    }

    #[test]
    fn a_half_written_pair_names_the_pair_rather_than_the_missing_table() {
        // `url` without `sha256` is a half-finished single artifact, not an
        // author who meant to write a platform table. Reporting "no artifact"
        // would send them looking for the wrong thing.
        let mut no_sha = entry("t", &"a".repeat(64));
        no_sha.sha256 = None;
        let err = validate(&[no_sha]).unwrap_err().to_string();
        assert!(err.contains("are a pair"), "{err}");

        let mut no_url = entry("t", &"a".repeat(64));
        no_url.url = None;
        assert!(validate(&[no_url]).is_err());
    }

    #[test]
    fn a_per_platform_checksum_is_validated_like_the_single_one() {
        // The xor must not create a hole: a malformed pin is refused at load in
        // both spellings, or the table becomes the way to smuggle a typo past
        // the gate that exists to catch it.
        assert!(validate(&[platform_entry("t", &[("linux-x86_64", "not-hex")])]).is_err());
        assert!(validate(&[platform_entry("t", &[("linux-x86_64", &"a".repeat(63))])]).is_err());

        let mut empty_key = platform_entry("t", &[("linux-x86_64", &"a".repeat(64))]);
        let artifact = empty_key.platforms.remove("linux-x86_64").unwrap();
        empty_key.platforms.insert(String::new(), artifact);
        assert!(validate(&[empty_key]).is_err(), "an empty platform key");
    }

    #[test]
    fn the_artifact_is_selected_by_platform_and_a_missing_row_is_a_usage_error() {
        let entry = platform_entry(
            "t",
            &[
                ("linux-x86_64", &"a".repeat(64)),
                ("macos-aarch64", &"b".repeat(64)),
            ],
        );
        assert_eq!(
            entry.artifact_for("linux-x86_64").unwrap().sha256,
            "a".repeat(64)
        );
        assert_eq!(
            entry.artifact_for("macos-aarch64").unwrap().sha256,
            "b".repeat(64)
        );

        // Never a silent skip: reporting an uninstallable entry as fresh would
        // let a gate depending on the tool pass without the tool.
        let err = entry.artifact_for("windows-x86_64").unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        let text = err.to_string();
        assert!(text.contains("windows-x86_64"), "{text}");
        assert!(
            text.contains("linux-x86_64") && text.contains("macos-aarch64"),
            "the refusal names what the entry does pin: {text}"
        );
    }

    #[test]
    fn a_single_url_entry_serves_every_platform() {
        // The whole reason the second spelling survives: a platform-independent
        // artifact must not have to name a platform it does not have.
        let entry = entry("t", &"a".repeat(64));
        for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
            assert_eq!(entry.artifact_for(platform).unwrap().sha256, "a".repeat(64));
        }
    }

    #[test]
    fn the_platform_key_is_os_dash_arch() {
        let key = platform_key();
        assert_eq!(
            key,
            format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        );
        assert!(key.contains('-'), "the key is two fields: {key}");
    }

    #[test]
    fn the_binary_path_is_the_cache_layout_and_checks_nothing() {
        // A resolver, not a probe: it answers "where would it be", and whether
        // it is there is `status`'s question.
        let entry = entry("tool", &"a".repeat(64));
        let path = binary_path(Path::new("/nowhere/repo"), &entry).unwrap();
        assert!(path.ends_with("provision/tool/1.2.3/bin/tool"), "{path:?}");
        assert!(!path.exists(), "resolution must not depend on existence");
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
