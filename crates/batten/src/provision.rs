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

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config_check::provision::platform_key;
#[cfg(test)]
use crate::config_check::provision::validate;
#[cfg(test)]
use crate::config_check::provision::validate_env;
#[cfg(test)]
use crate::config_check::provision::validate_subtree;
use crate::config_model::Artifact;
#[cfg(test)]
use crate::config_model::Backend;
use crate::config_model::CredentialProbe;
use crate::config_model::Provision;
use crate::config_model::ProvisionEnv;
use crate::config_model::Unpack;
use crate::digest::sha256_hex as digest;
use crate::error::UsageError;
use crate::secret::Secret;

/// The subdirectory of the repository's out-of-tree state that holds provisioned
/// tools.
const CACHE_DIR: &str = "provision";

/// The file the exact fetched bytes are stored under, so freshness re-verifies
/// the pin against the artifact rather than against a note about it.
const ARTIFACT: &str = "artifact";

/// The subdirectory the unpacked binary lands in.
const BIN_DIR: &str = "bin";

/// Whether the credential this container was given actually works.
///
/// **A PAT can be expired or revoked, and stripping the injected one on that
/// assumption strands the session with NOTHING** — which is strictly worse than
/// the scoped credential it replaced. A token that 403s third-party repos still
/// clones, fetches and pushes this one. So every rule that REMOVES something is
/// conditional on this, and the fallback direction is "keep what the host gave
/// us and say so loudly", never "clear it and hope".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// Proved usable against the forge, within the receipt's freshness bound.
    Live,
    /// Absent, rejected, or not checkable right now. Removals are skipped.
    Unusable,
}

/// What a resolved rule does to one variable.
///
/// Two arms rather than an `Option<String>`, because the third state — a rule
/// that resolved to nothing and must leave the variable ALONE — is not the same
/// as one that resolved to a removal, and collapsing them would make a missing
/// credential clear an inherited one.
/// **`Set` CARRIES A [`Secret`], NOT A `String`, AND THAT IS THE WHOLE OF THE
/// FIX.** It carried a `String` for one commit, in a `pub` type deriving
/// `Debug`, so every rendering of a launcher's resolved environment printed the
/// credential it had just resolved — and the environment this resolves is
/// mostly credentials, which is what makes this the worst possible place for
/// that. The derive stays: a struct holding a `Secret` may derive `Debug`
/// freely, which is why the fix is a type rather than a rule about renderings.
///
/// Not every variable here is a credential — `NO_PROXY` is a host list — and
/// they are not split into two arms. Redacting a proxy exemption list costs a
/// reader almost nothing; deciding per-row which values are secret is a
/// judgement, and getting it wrong once is a credential in a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvAction {
    /// Set the variable to this value.
    Set(Secret),
    /// Remove the variable from the child's environment.
    Unset,
}

/// `Provision` behaviour that belongs to this module's layer, not the type's (CLOUD-2793).
pub trait ProvisionExt: Sized {
    /// The name the binary is cached and linked under on this host.
    ///
    /// [`Provision::binary`] plus the platform's executable suffix: `.exe` on
    /// Windows, where a file without it is not a program, and nothing elsewhere,
    /// so every Unix path is the one it always was. It is also the archive
    /// entry an unpack looks for, since a Windows build names its binary so.
    #[must_use]
    fn cached_name(&self) -> String;

    /// The artifact this host should install.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) when the entry declares a platform
    /// table with no row for this host. **Never a silent skip**: an entry that
    /// cannot be installed here is a manifest this host cannot satisfy, and
    /// reporting it as fresh would let a gate depending on the tool pass without
    /// the tool.
    fn artifact(&self) -> Result<Artifact>;

    /// [`Provision::artifact`] for a named platform, so the suite can drive a
    /// platform the test host is not.
    ///
    /// # Errors
    ///
    /// As [`Provision::artifact`].
    fn artifact_for(&self, platform: &str) -> Result<Artifact>;
}

impl ProvisionExt for Provision {
    fn cached_name(&self) -> String {
        format!("{}{}", self.binary, std::env::consts::EXE_SUFFIX)
    }

    fn artifact(&self) -> Result<Artifact> {
        self.artifact_for(platform_key().as_str())
    }

    fn artifact_for(&self, platform: &str) -> Result<Artifact> {
        if let (Some(url), Some(sha256)) = (self.url.as_ref(), self.sha256.as_ref()) {
            return Ok(Artifact {
                url: url.clone(),
                sha256: sha256.clone(),
                unpack: None,
                strip: None,
                bin: None,
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

/// Why an entry is not fresh. Several states rather than a boolean, because
/// "never installed", "installed, and the bytes are not what the pin says"
/// and "another tool holds the name" are different facts, with different fixes.
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
    /// The link's name, in a directory the `PATH` fallback shares with package
    /// managers, holds another tool's binary (CLOUD-2617). Not `Missing`: the
    /// file is there, and no apply may replace it, so the operator's fix is to
    /// move that tool or declare an absolute `link`.
    Foreign,
}

impl Freshness {
    /// Whether this entry is not fresh. For [`Freshness::Foreign`] the apply it
    /// prompts refuses, which is the point: the startup row fails visibly, with
    /// the operator's fix in the refusal.
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
            Freshness::Foreign => "foreign",
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
    status_on(entries, cache_root, Host::isolated(true))
}

/// [`status`], with each declared link judged where [`link_dir`] resolves it
/// on `host` — the same place [`apply_on`] writes it (CLOUD-2617).
///
/// # Errors
///
/// As [`status`].
pub fn status_on(entries: &[Provision], cache_root: &Path, host: Host<'_>) -> Result<Report> {
    let mut report = Vec::with_capacity(entries.len());
    for entry in entries {
        report.push(EntryStatus {
            name: entry.name.clone(),
            version: entry.version.clone(),
            freshness: freshness_of(entry, cache_root, link_of(entry, host)?.as_ref())?,
        });
    }
    Ok(Report { entries: report })
}

/// Whether an engine at `exe` may write the HOST's links for `repo_root`
/// (CLOUD-2124).
///
/// **A build of the checkout it provisions never does.** Such a binary is
/// `cargo`'s output, not an installed engine — the line `engine install` already
/// draws for the same reason (CLOUD-2063). A launcher names its interpreter by
/// absolute path, so a gate running `provision apply` through `cargo run`
/// rewrote `~/.local/bin/mise` to run a debug build: measured 2026-10-07, a
/// scratch clone's `target/debug/batten` became every `mise` call's
/// interpreter for the whole host. The binary installs the binary; once one is
/// installed, it alone provisions the host. The cache is the repository's own,
/// so a build of it still fills it — the scanner a gate needs stays reachable.
#[must_use]
pub fn links_host(exe: &Path, repo_root: &Path) -> bool {
    !exe.starts_with(repo_root)
}

/// What a declared link is resolved against: whether this engine may write the
/// host's links at all ([`links_host`]'s answer), the caller's `PATH`, and how
/// to ask whether a directory is writable.
///
/// One value rather than loose parameters so [`status`] and [`apply`] are
/// handed the same answer: the two must judge and write ONE path, or the row
/// reads green over a link nobody wrote (CLOUD-2617).
#[derive(Debug, Clone, Copy)]
pub struct Host<'a> {
    /// Whether the declared links are judged and written at all.
    pub links: bool,
    /// The caller's `PATH`, in order.
    pub on_path: &'a [PathBuf],
    /// Whether a directory may be written.
    pub writable: fn(&Path) -> bool,
}

impl Host<'static> {
    /// A host with no `PATH` and nothing writable, so every declared link
    /// resolves to the directory it names. What a case wants: a suite run as
    /// root must never reach a real system directory.
    #[must_use]
    pub const fn isolated(links: bool) -> Self {
        const fn never(_: &Path) -> bool {
            false
        }
        Self {
            links,
            on_path: &[],
            writable: never,
        }
    }
}

/// The directory a declared `link` resolves to on `host` (CLOUD-2617).
///
/// **`engine install`'s rule, not a second one.** A link under `~/` is the
/// per-user preference: where it is not on `PATH`, the first conventional system
/// directory that is on `PATH` and writable wins, and otherwise it stands. An
/// absolute link is NAMED, and stands wherever it is — the manifest asked for
/// that directory, as `BATTEN_INSTALL_DIR` does. That is
/// [`crate::install::destination`] exactly, called rather than copied, with
/// `~/` in the per-user seat and an absolute path in the named one.
///
/// A root Setup shell carries `/usr/local/bin` and not `~/.local/bin`:
/// measured on a cold Kilo.ai container, `engine install` put batten in
/// `/usr/local/bin` while this linked the runner into `~/.local/bin`, so
/// `provision status` was fresh, the bare name did not resolve, and every
/// `[[startup]]` row naming it was could-not-look.
///
/// # Errors
///
/// [`expand_home`]'s: a `~` with no `HOME`, or a relative destination.
pub fn link_dir(dest: &str, host: Host<'_>) -> Result<PathBuf> {
    Ok(placed(dest, expand_home(dest)?, host))
}

/// [`link_dir`] over `dest` already expanded to `declared`.
fn placed(dest: &str, declared: PathBuf, host: Host<'_>) -> PathBuf {
    if !dest.starts_with("~/") {
        return declared;
    }
    crate::install::destination(None, declared, host.on_path, host.writable)
}

/// Where one entry's link goes, and whether that directory is SHARED: a system
/// directory the `PATH` fallback chose, rather than the declared one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    /// The directory the link lands in.
    dir: PathBuf,
    /// Whether [`link_dir`] fell back to a directory package managers share.
    shared: bool,
}

impl Link {
    /// Whether this link's name belongs to another tool: only ever true in a
    /// shared directory, where [`claimable`] decides it.
    fn foreign(&self, entry: &Provision, cache_root: &Path) -> bool {
        self.shared && !claimable(&self.dir, entry, cache_root)
    }

    /// The refusal for a [`Link::foreign`] name, naming the file and the two
    /// fixes the operator has.
    fn refusal(&self, entry: &Provision) -> anyhow::Error {
        anyhow::anyhow!(
            "provision: {} is another tool's {}, so batten will not replace it; \
             move that tool, or declare an absolute `link` for this entry",
            self.dir.join(entry.cached_name()).display(),
            entry.binary
        )
    }
}

/// Where `entry`'s link resolves on `host`, or `None` where it declares none
/// or the host's links are not this engine's to write.
///
/// RESOLVED ONCE PER ENTRY, and handed to both the freshness reading and the
/// install, so one call cannot judge one directory and write another.
fn link_of(entry: &Provision, host: Host<'_>) -> Result<Option<Link>> {
    let Some(dest) = entry.link.as_deref().filter(|_| host.links) else {
        return Ok(None);
    };
    let declared = expand_home(dest)?;
    let dir = placed(dest, declared.clone(), host);
    Ok(Some(Link {
        shared: dir != declared,
        dir,
    }))
}

/// Whether a SHARED directory's name is batten's to write: free, a batten
/// launcher, or the very file [`record_link`] recorded writing.
///
/// **A FALLBACK NEVER TAKES A NAME SOMEBODY ELSE OWNS, AND SAYS SO.** The
/// declared `~/` directory is batten's, but `/usr/local/bin` and
/// `/opt/homebrew/bin` are shared with package managers. A foreign name there
/// reads [`Freshness::Foreign`] and the install refuse, so the startup row
/// fails visibly. Quietly linking somewhere off `PATH` instead would be
/// CLOUD-2617's false green again, over somebody else's `mise`.
///
/// RECORDED, NOT INFERRED FROM BYTES, and by IDENTITY as well as path. Bytes
/// cost two whole binaries per status and broke on upgrade (the new version's
/// cache is empty until `install`); a path alone would trust whatever replaced
/// the file later. The record is per entry NAME, so it survives a version bump.
///
/// FREE MEANS NOTHING AT THE NAME, not even a dangling symlink: `exists`
/// follows the link, and a package manager's symlink into a keg it is midway
/// through upgrading is still that package manager's name.
fn claimable(dir: &Path, entry: &Provision, cache_root: &Path) -> bool {
    let linked = dir.join(entry.cached_name());
    fs::symlink_metadata(&linked).is_err()
        || is_launcher(&linked)
        || vouched_stamp(&linked, entry, cache_root).is_some()
}

/// The stamp batten may keep for `linked`, when the link record names it and
/// either `linked`'s present stamp or, as an intent, this entry's own cached
/// bytes vouch for it; `None` when the file is not batten's. Read once, it
/// answers both [`claimable`] and [`record_intent`].
///
/// The record is three lines: the path, the stamp of the file batten last
/// wrote there (empty if none), and [`INTENT`] while a write is under way.
///
/// AN INTENT is what an install that failed or was killed between
/// [`record_intent`] and [`record_written`] leaves. Whichever side of the
/// rename it stopped on, the file is batten's: the earlier copy still carries
/// the stamp the intent kept, or the new one holds the cached bytes, which is
/// all that half-finished run could have put there. Admitting whatever sits at
/// the path would let a crash vouch for a binary another tool installed
/// afterwards. A launcher needs no record, so the byte read is reached only
/// after such an install, and a refused apply ([`forget_link`]) clears an
/// intent that no longer vouches for anything.
///
/// The path is compared as the record wrote it, lossily, so a link path that is
/// not UTF-8 still matches its own record.
fn vouched_stamp(linked: &Path, entry: &Provision, cache_root: &Path) -> Option<String> {
    let record = fs::read_to_string(link_record(cache_root, entry)).ok()?;
    let mut lines = record.lines();
    if lines.next() != Some(&*linked.to_string_lossy()) {
        return None;
    }
    let present = written_stamp(linked);
    if let Some(stamp) = lines.next().filter(|stamp| !stamp.is_empty())
        && present.as_deref() == Some(stamp)
    {
        return Some(stamp.to_owned());
    }
    let cached = entry_dir(cache_root, entry)
        .join(BIN_DIR)
        .join(entry.cached_name());
    (lines.next() == Some(INTENT) && crate::fsio::same_bytes(linked, &cached))
        .then(|| present.unwrap_or_default())
}

/// The link record's third line while a write is under way.
const INTENT: &str = "intent";

/// Where `entry`'s last written link is recorded: beside its versioned cache
/// directories, so a version bump still finds it.
fn link_record(cache_root: &Path, entry: &Provision) -> PathBuf {
    cache_root.join(CACHE_DIR).join(&entry.name).join("linked")
}

/// Record that batten is ABOUT to write `entry`'s link at `linked`, so an
/// install that fails or is killed before [`record_written`] leaves batten's
/// link claimable on either side of its rename.
///
/// KEEPS ONLY A STAMP [`vouched_stamp`] VOUCHES FOR: batten's earlier copy
/// must stay batten's if this write never lands, and a stamp read off whatever
/// file is there now could vouch for one batten never wrote.
fn record_intent(cache_root: &Path, entry: &Provision, linked: &Path) -> Result<()> {
    let kept = vouched_stamp(linked, entry, cache_root).unwrap_or_default();
    write_link_record(
        cache_root,
        entry,
        &format!("{}\n{kept}\n{INTENT}", linked.to_string_lossy()),
    )
}

/// Record that batten WROTE `entry`'s link at `linked`: the path and the
/// written file's [`written_stamp`].
fn record_written(cache_root: &Path, entry: &Provision, linked: &Path) -> Result<()> {
    let stamp = written_stamp(linked).context("stamp the written link")?;
    write_link_record(
        cache_root,
        entry,
        &format!("{}\n{stamp}", linked.to_string_lossy()),
    )
}

/// The one writer of [`link_record`], which may run before `install` has made
/// the entry's cache directory.
fn write_link_record(cache_root: &Path, entry: &Provision, body: &str) -> Result<()> {
    let record = link_record(cache_root, entry);
    if let Some(parent) = record.parent() {
        fs::create_dir_all(parent).context("create the link record's directory")?;
    }
    crate::durable::replace(record, body.as_bytes()).context("record the written link")
}

/// A written file's stamp for [`vouched_stamp`]: [`crate::cache::stamp`]'s
/// identity tuple, whose change time moves on any later write, rename or
/// `touch -d`, so a replacement cannot inherit batten's record.
fn written_stamp(path: &Path) -> Option<String> {
    crate::cache::stamp(path).map(|stamp| stamp.fields)
}

/// Drop `entry`'s link record once its name has read foreign: whatever it
/// recorded no longer vouches for the file there, and an intent left standing
/// would cost every later status two whole-binary reads to answer `false` again.
fn forget_link(cache_root: &Path, entry: &Provision) {
    // Best effort: a record that cannot be removed only keeps that cost.
    let _ = fs::remove_file(link_record(cache_root, entry));
}

/// How much of a file is read to find a launcher's `#!` line, which is short;
/// the name may instead hold a large binary.
const LAUNCHER_HEAD: u64 = 4096;

/// Whether the file at `path` is a batten launcher ([`launcher`]'s shape).
fn is_launcher(path: &Path) -> bool {
    use std::io::Read as _;
    let mut head = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(LAUNCHER_HEAD).read_to_end(&mut head))
        .is_ok()
        && launcher_interpreter(&head).is_some()
}

/// The interpreter a launcher's first line names, or `None` for anything that
/// is not a launcher. The one reader of [`launcher`]'s `#!` line.
fn launcher_interpreter(bytes: &[u8]) -> Option<&str> {
    let first = bytes.split(|byte| *byte == b'\n').next()?;
    let (interpreter, verb) = std::str::from_utf8(first)
        .ok()?
        .strip_prefix("#!")?
        .rsplit_once(' ')?;
    (verb == LAUNCHER_VERB).then_some(interpreter)
}

/// The directory a subtree entry is extracted into, under its entry dir.
const TREE_DIR: &str = "tree";

/// A subtree entry's effective `strip` and `bin` on this host (CLOUD-2682).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Subtree {
    strip: usize,
    bin: PathBuf,
}

/// This host's [`Subtree`], or `None` for a single-file entry. A platform row's
/// `strip` and `bin` override the entry's, as its `unpack` does.
fn subtree_of(entry: &Provision, artifact: &Artifact) -> Option<Subtree> {
    let bin = artifact.bin.as_deref().or(entry.bin.as_deref());
    let strip = artifact.strip.or(entry.strip).unwrap_or(0);
    bin.map(|bin| Subtree {
        strip,
        bin: PathBuf::from(bin),
    })
}

/// Where `entry`'s binary is cached under `dir`: `tree/<bin>` for a subtree,
/// `bin/<name>` otherwise. One answer for `install`, freshness and
/// [`binary_path`].
fn cached_binary(dir: &Path, entry: &Provision) -> PathBuf {
    match entry
        .artifact()
        .ok()
        .and_then(|artifact| subtree_of(entry, &artifact))
    {
        Some(subtree) => dir.join(TREE_DIR).join(subtree.bin),
        None => dir.join(BIN_DIR).join(entry.cached_name()),
    }
}

fn freshness_of(entry: &Provision, cache_root: &Path, link: Option<&Link>) -> Result<Freshness> {
    // A SHARED DIRECTORY'S NAME MUST BE BATTEN'S, and that is asked FIRST: it
    // is the one verdict no apply can change, so a cold cache must not answer
    // `missing` over it. Another tool's `mise` would otherwise also answer the
    // link's `is_file` below and read fresh over a binary the pin does not name.
    if let Some(link) = link
        && link.foreign(entry, cache_root)
    {
        return Ok(Freshness::Foreign);
    }
    let dir = entry_dir(cache_root, entry);
    let binary = cached_binary(&dir, entry);
    if !binary.is_file() {
        return Ok(Freshness::Missing);
    }
    // A DECLARED LINK IS PART OF THE QUESTION, and leaving it out made the
    // bootstrap silently never link (CLOUD-1389). `status` is what
    // `toolchain-runner-present` asks, so an entry reporting `fresh` while its
    // link destination is empty means the startup check PASSES and the repair
    // that would put the runner on PATH never runs — the row reads green over a
    // container that cannot run a single gate.
    //
    // Measured: the first fixture run linked correctly and every run after it
    // failed, because `apply` returns `AlreadyFresh` before reaching `install`
    // once the cache is warm. So the defect needed a second run to appear at all,
    // which is exactly how it would have reached a container — cache preserved,
    // `~/.local/bin` not.
    //
    // `Missing` rather than a fourth verdict: what is missing is the binary at
    // the place this entry declares it must be, which is the same class as
    // nothing cached and takes the same repair.
    if let Some(link) = link {
        let linked = link.dir.join(entry.cached_name());
        if !linked.is_file() {
            return Ok(Freshness::Missing);
        }
        // AND A LAUNCHER NAMING AN INTERPRETER THAT IS NO LONGER THERE IS STALE
        // (CLOUD-1455), which is the one way this seam degrades that a plain copy
        // never could. `launcher` writes an absolute path to the batten that ran
        // `apply`; replace that binary elsewhere and the file on `PATH` is still
        // present, still executable, and refuses to run with the kernel's own
        // ENOENT — which names the interpreter, not the tool, and reads as the
        // tool being broken. Answering `Missing` re-writes it on the next apply.
        if !relaunches_a_present_interpreter(&linked) {
            return Ok(Freshness::Missing);
        }
        // AND THE DECLARED ENVIRONMENT IS PART OF WHAT IS CACHED, which is the
        // other half of CLOUD-1455 and the one a byte-identical artifact hides.
        // Every other input to this verdict lives in the cache — the artifact's
        // digest, the binary's presence — but `[[provision.env]]` reaches the
        // tool only through the launcher's own second line. Edit a row, and a
        // warm cache reports `Fresh`, `apply` returns `AlreadyFresh` before
        // reaching `install`, and the tool keeps running with the environment
        // the manifest USED to declare. That is the same second-run shape the
        // link check above records: the change never appears on the run that
        // makes it.
        //
        // ONLY OF A LAUNCHER (CLOUD-2210): `link_onto_path` writes a PLAIN COPY
        // when the entry declares no env and no subtree, and a copy carries no
        // launcher body, so asking it for one read every such entry `Missing`
        // forever and `apply` never converged. The writer's predicate is asked
        // here too, through `links_a_launcher`, so the two cannot disagree; and a
        // copy entry still holding a LAUNCHER is stale, since that launcher
        // injects an environment the manifest no longer declares.
        if links_a_launcher(entry) {
            if !launcher_declares(&linked, entry, &binary) {
                return Ok(Freshness::Missing);
            }
        } else if is_a_launcher(&linked) {
            return Ok(Freshness::Missing);
        }
    }
    let cached = match crate::fsio::read(dir.join(ARTIFACT)) {
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
///
/// `links_host` is [`links_host`]'s answer: `false` leaves the declared link —
/// the host's, not the repository's — unjudged and unwritten.
pub fn apply(
    entry: &Provision,
    cache_root: &Path,
    dry_run: bool,
    links_host: bool,
) -> Result<Applied> {
    apply_on(entry, cache_root, dry_run, Host::isolated(links_host))
}

/// [`apply`], with each declared link written where [`link_dir`] resolves it
/// on `host` — the same place [`status_on`] judges it (CLOUD-2617).
///
/// # Errors
///
/// As [`apply`].
pub fn apply_on(
    entry: &Provision,
    cache_root: &Path,
    dry_run: bool,
    host: Host<'_>,
) -> Result<Applied> {
    apply_with(entry, cache_root, dry_run, link_of(entry, host)?.as_ref())
}

/// [`apply_on`] for an already resolved `link`.
fn apply_with(
    entry: &Provision,
    cache_root: &Path,
    dry_run: bool,
    link: Option<&Link>,
) -> Result<Applied> {
    // THE ONE FOREIGN CHECK, and BEFORE ANY ARTIFACT IS READ OR FETCHED:
    // `freshness_of` asks it first, from a `stat` and a record, and no download
    // can change it, so a session repeating this repair must not pay for one
    // each time. `install` is reached only past it.
    match (freshness_of(entry, cache_root, link)?, link) {
        (Freshness::Fresh, _) => return Ok(Applied::AlreadyFresh),
        (Freshness::Foreign, Some(link)) => {
            // A preview reports the refusal and changes nothing.
            if !dry_run {
                forget_link(cache_root, entry);
            }
            return Err(link.refusal(entry));
        }
        _ => {}
    }
    if dry_run {
        // A preview fetches nothing. Reaching the network to report that we
        // would reach the network is not a preview of doing nothing.
        return Ok(Applied::Previewed);
    }

    // THE CACHED ARTIFACT IS TRIED BEFORE THE NETWORK, and only when it still
    // matches the pin. The case this serves is a stale entry whose staleness is
    // the LINK rather than the bytes: the artifact on disk is the pinned one, so
    // re-downloading it to copy it two directories over is a fetch that cannot
    // change the answer. Verified against the pin here exactly as a fresh fetch
    // is, so a tampered cache is a mismatch rather than a shortcut past the
    // checksum.
    let artifact = entry.artifact()?;
    let unpack = artifact.unpack.unwrap_or(entry.unpack);
    let subtree = subtree_of(entry, &artifact);
    if let Some(bytes) = cached_artifact_matching_pin(entry, cache_root, &artifact.sha256) {
        install(entry, unpack, subtree.as_ref(), cache_root, &bytes, link)?;
        return Ok(Applied::Installed);
    }
    let bytes = fetch(&artifact.url)?;
    let found = digest(&bytes);
    if !found.eq_ignore_ascii_case(&artifact.sha256) {
        // Pointer-only: the two digests, never a byte of what was fetched. A
        // mismatched artifact is exactly the thing least safe to echo.
        // `provision pin other` (CLOUD-2078): the provision and both digests.
        let subjects = [
            crate::verdict::artifact(&entry.name),
            crate::verdict::artifact(&format!("pinned {}", artifact.sha256)),
            crate::verdict::artifact(&format!("fetched {found}")),
        ];
        let refusal = crate::refusal::Refusal::engine(
            crate::error::Native::ProvisionPinOther,
            &subjects,
            crate::refusal::Fix::None,
        );
        return Err(crate::Denial::raise(&refusal, crate::refusal::Arm::Full));
    }

    install(entry, unpack, subtree.as_ref(), cache_root, &bytes, link)?;
    Ok(Applied::Installed)
}

/// Write the verified artifact and its binary into the cache, and the link
/// into `link` where one was resolved.
///
/// Called only after the checksum matched, and only by [`apply_with`], which
/// has already refused a foreign `link` name (see [`claimable`]). `unpack` is
/// this platform's ([`Artifact::unpack`], else the entry's).
fn install(
    entry: &Provision,
    unpack: Unpack,
    subtree: Option<&Subtree>,
    cache_root: &Path,
    bytes: &[u8],
    link: Option<&Link>,
) -> Result<()> {
    let dir = entry_dir(cache_root, entry);
    // A SUBTREE ENTRY (CLOUD-2682): the tree, then the link, then the artifact
    // last, the same crash order as the single file below.
    if let Some(subtree) = subtree {
        let cached = install_tree(&dir, unpack, subtree, bytes)?;
        // Recorded in a shared directory as the single file's link is below.
        if let Some(link) = link {
            let linked = link.dir.join(entry.cached_name());
            if link.shared {
                record_intent(cache_root, entry, &linked)?;
            }
            link_into(entry, &link.dir, &cached, &[], Some(subtree))?;
            if link.shared {
                record_written(cache_root, entry, &linked)?;
            }
        }
        crate::durable::replace(dir.join(ARTIFACT), bytes).context("write the cached artifact")?;
        return Ok(());
    }
    let bin_dir = dir.join(BIN_DIR);
    fs::create_dir_all(&bin_dir).context("create the provision cache directory")?;

    let name = entry.cached_name();
    let binary = match unpack {
        Unpack::None => bytes.to_vec(),
        Unpack::TarGz => extract(bytes, &name)?,
        Unpack::Zip => extract_zip(bytes, &name)?,
    };
    let cached = bin_dir.join(&name);
    // **STAGED AND RENAMED, NEVER WRITTEN IN PLACE** (CLOUD-1586), which is
    // [`link_into`]'s discipline applied to the site that needed it just as
    // much. Writing over this path returns `ETXTBSY` — "Text file busy" — the
    // moment anything is executing it, and something usually is: the launcher's
    // `#!` line names this exact file, so every `provision-exec` holds it open,
    // and in this repository the adjudicating hook runs on every tool call.
    //
    // A rename does not have that problem, and the reason is worth stating
    // because it looks like luck: the running process holds the old INODE, and
    // rename only moves the name. The old bytes stay valid for whoever is
    // mid-execution, the next execution finds the new ones, and no reader ever
    // observes a half-written binary.
    //
    // Measured on this branch: `batten-check` and two `land` laps died here with
    // `write the provisioned binary / Text file busy`, which reads as a
    // filesystem fault and is really a self-collision.
    //
    // Keyed on the pid and dot-prefixed for `link_into`'s reasons exactly —
    // two provisions running at once must not write each other's staging file.
    let staged = bin_dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = crate::durable::replace(&staged, &binary)
        .context("write the provisioned binary")
        .and_then(|()| make_executable(&staged));
    if let Err(err) = written {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    if let Err(err) = fs::rename(&staged, &cached) {
        let _ = fs::remove_file(&staged);
        return Err(err).context("move the provisioned binary into place");
    }
    // BEFORE the artifact, so the same crash window that leaves the entry
    // reading `missing` also leaves the link unmade. A fresh entry whose link
    // never landed would be the silent half-install this ordering exists to
    // rule out.
    if let Some(link) = link {
        // RECORDED ONLY IN A SHARED DIRECTORY, the one place [`claimable`]
        // reads it. Rewriting it for the declared directory would erase the only
        // evidence that batten's earlier copy in the shared one is batten's, and
        // that copy would read `foreign` for good.
        //
        // INTENT FIRST, crash-only: the record names the path before the link
        // exists, so a run killed in between finds its own file claimable.
        let linked = link.dir.join(entry.cached_name());
        if link.shared {
            record_intent(cache_root, entry, &linked)?;
        }
        link_into(entry, &link.dir, &cached, &binary, None)?;
        if link.shared {
            record_written(cache_root, entry, &linked)?;
        }
    }
    // The artifact is written last, so a crash between the two leaves the entry
    // reading `missing` rather than `fresh` — the direction that re-applies.
    crate::durable::replace(dir.join(ARTIFACT), bytes).context("write the cached artifact")?;
    Ok(())
}

/// The cached artifact's bytes, when they are present and still match the pin.
///
/// `None` for absent, unreadable, or a digest that does not match — every one of
/// which sends the caller to the network, which is the direction a miss must fail
/// in. It never reports an error of its own: a cache this cannot read is not a
/// finding, it is a reason to fetch.
fn cached_artifact_matching_pin(
    entry: &Provision,
    cache_root: &Path,
    pinned: &str,
) -> Option<Vec<u8>> {
    let bytes = crate::fsio::read(entry_dir(cache_root, entry).join(ARTIFACT)).ok()?;
    digest(&bytes).eq_ignore_ascii_case(pinned).then_some(bytes)
}

/// The first line of a launcher, so a reader and [`is_launcher`] agree.
const LAUNCHER_VERB: &str = "provision-exec";

/// Place the verified binary in the declared directory as well as the cache.
///
/// A COPY rather than a symlink, deliberately. The cache is keyed by version, so
/// a symlink would make the `PATH` name follow whatever the manifest says today —
/// which is right for batten's own resolution and wrong here, because the thing on
/// `PATH` is what a shell, a git hook and a session handler get, and those must
/// not change under a running session. A copy also survives the cache being
/// pruned, which [`crate::target`] may do.
///
/// **An entry declaring [`Provision::env`] gets a LAUNCHER instead**, and the
/// copy above is what it launches. See [`launcher`] for the shape and for why the
/// environment cannot be baked in at this point.
/// # WRITTEN BESIDE AND RENAMED OVER, BECAUSE THE TARGET MAY BE RUNNING
///
/// `fs::write` truncates in place, and the kernel refuses that for a file some
/// process is executing: `ETXTBSY`, *"Text file busy"*. The thing on `PATH` is
/// exactly the thing a session runs, so the target being busy is the ORDINARY
/// case here rather than a rare one — a `batten` on `PATH` re-provisioning while
/// a task runs it is a session doing what it is supposed to do.
///
/// This was invisible while `freshness_of` never compared the declared
/// environment: a warm cache answered `Fresh`, `apply` returned `AlreadyFresh`
/// before reaching `install`, and the write that would have failed never
/// happened. Making the launcher's environment part of the freshness verdict
/// (CLOUD-1455) is what made the re-link real, and the re-link is what found
/// this. Both are the same second-run shape the link check records: the failure
/// needs a warm cache to appear at all.
///
/// `rename` over a busy target succeeds — it swaps the directory entry and the
/// running process keeps its own open inode — so the temp file is made
/// executable BEFORE the rename and the file on `PATH` is never a moment
/// non-executable. Same directory, so it cannot cross a filesystem.
///
/// `dir` is already resolved, by [`link_dir`] on the host [`status_on`] judges
/// (CLOUD-2617).
fn link_into(
    entry: &Provision,
    dir: &Path,
    cached: &Path,
    binary: &[u8],
    subtree: Option<&Subtree>,
) -> Result<()> {
    fs::create_dir_all(dir).context("create the linked binary's directory")?;
    let name = entry.cached_name();
    let path = dir.join(&name);
    // Keyed on the PID so two provisions running at once cannot write each
    // other's staging file, and dot-prefixed so a directory listing of `PATH`
    // does not offer it as a command.
    let staged = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    // A SUBTREE IS LAUNCHED, NEVER COPIED (CLOUD-2682): its binary reads the
    // files beside its real path, and a copy on `PATH` has none beside it.
    let written = if launches(entry, subtree.is_some()) {
        launcher(entry, cached).and_then(|bytes| {
            crate::durable::replace(&staged, bytes).context("write the linked launcher")
        })
    } else {
        crate::durable::replace(&staged, binary).context("write the linked binary")
    };
    if let Err(err) = written.and_then(|()| make_executable(&staged)) {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    if let Err(err) = fs::rename(&staged, &path) {
        let _ = fs::remove_file(&staged);
        return Err(err).context("move the linked binary into place");
    }
    Ok(())
}

/// [`link_into`], from the declared `link` string rather than a resolved
/// directory.
///
/// TEST-ONLY SINCE CLOUD-2617: production resolves the directory first, through
/// [`link_dir`]. This keeps the form the unix-only relink case was written
/// against, so that case runs unchanged.
#[cfg(all(test, unix))]
fn link_onto_path(
    entry: &Provision,
    dest: &str,
    cached: &Path,
    binary: &[u8],
    subtree: Option<&Subtree>,
) -> Result<()> {
    link_into(entry, &expand_home(dest)?, cached, binary, subtree)
}

/// The bytes of the launcher that stands in for a tool needing an environment.
///
/// Two lines, and no shell anywhere in them:
///
/// ```text
/// #!/abs/path/to/batten provision-exec
/// {"exec":"/abs/path/to/cache/bin/tool","env":[ … ]}
/// ```
///
/// The kernel's `#!` handling passes the interpreter one argument and then the
/// script's own path, so batten is re-entered as
/// `batten provision-exec <this file> <the caller's arguments>` and reads its
/// instructions out of the file it was handed. That is the whole mechanism: a
/// data file the kernel knows how to run, rather than a program in a language
/// this repository is retiring.
///
/// **The environment is stored as RULES and resolved when the launcher runs,
/// never resolved here.** That is not a refinement, it is the case this exists
/// for: provisioning happens while a container is being built, where there is no
/// session and therefore no session credential, and the tool runs later, in a
/// session that has one. A value captured at this moment would bake in the
/// absence.
///
/// **The interpreter is an absolute path to the batten running right now**
/// (`current_exe`), because a launcher naming a bare `batten` would resolve
/// against the `PATH` of whoever ran it — including the empty-ish one a git hook
/// gets, which is the environment this whole seam exists to survive. The cost is
/// stated rather than hidden: move or delete that binary and the launcher stops
/// working, where a plain copy would have kept running. `provision apply`
/// rewrites it, and [`freshness_of`] treats a launcher naming a missing
/// interpreter as stale so the next apply does.
fn launcher(entry: &Provision, cached: &Path) -> Result<Vec<u8>> {
    let batten = std::env::current_exe().context("locate the running batten for the launcher")?;
    let instructions = serde_json::json!({
        "exec": cached,
        "env": entry.env,
    });
    Ok(format!("#!{} {LAUNCHER_VERB}\n{instructions}\n", batten.display()).into_bytes())
}

/// Become the tool, if this process was started as a launcher's interpreter.
///
/// **Read before batten parses anything of its own, and that ordering is the
/// mechanism rather than an optimisation.** The arguments after the launcher's
/// own path belong to somebody else's program, and batten's parser would claim
/// them: `--help` would print batten's help instead of the tool's, `-v` would
/// raise batten's verbosity instead of reaching the tool, and `--` would be
/// eaten. There is nothing to configure here and nothing to validate — the
/// kernel decided this shape when it read the `#!`.
///
/// `None` means an ordinary invocation, and the caller carries on. `Some` is a
/// launcher run that FAILED, because a successful one never returns.
pub fn launched(argv: impl Iterator<Item = std::ffi::OsString>) -> Option<anyhow::Error> {
    let mut argv = argv.skip(1);
    if argv.next()? != *LAUNCHER_VERB {
        return None;
    }
    let script = PathBuf::from(argv.next()?);
    let rest: Vec<std::ffi::OsString> = argv.collect();
    Some(match exec_launcher(&script, &rest) {
        Err(failure) => failure,
        // Unreachable by type: `Infallible` has no value, so the success arm
        // cannot be constructed. Spelled out rather than `unreachable!()`, which
        // would be a panic on a path the library lints forbid one on.
        Ok(never) => match never {},
    })
}

/// What a launcher file carries, and the whole of what [`exec_launcher`] reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Launch {
    /// The cached binary to become.
    exec: PathBuf,
    /// The rules deciding this process's environment first.
    env: Vec<ProvisionEnv>,
}

/// Whether `linked` is a launcher whose declared interpreter is still present.
///
/// `true` for a plain copy, which has no interpreter to lose — the question does
/// not apply, and answering `false` there would make every ordinary linked
/// binary permanently stale.
fn relaunches_a_present_interpreter(linked: &Path) -> bool {
    let Ok(bytes) = crate::fsio::read(linked) else {
        // Unreadable is not this predicate's finding: the `is_file` check above
        // already answered presence, and a read failure here is a permissions or
        // races question that re-linking would not fix.
        return true;
    };
    launcher_interpreter(&bytes).is_none_or(|interpreter| Path::new(interpreter).is_file())
}

/// Whether `entry`'s link is a launcher rather than a plain copy (CLOUD-2210):
/// it declares environment rows, or it links a subtree (CLOUD-2682). The ONE
/// predicate both the writer (`link_onto_path`) and the reader (`freshness_of`)
/// ask, the reader through [`links_a_launcher`].
const fn launches(entry: &Provision, subtree: bool) -> bool {
    !entry.env.is_empty() || subtree
}

/// [`launches`] for an entry whose subtree is read off this host's artifact.
/// An entry with no artifact for this host links nothing here, so the answer
/// only matters where one exists.
fn links_a_launcher(entry: &Provision) -> bool {
    let subtree = entry
        .artifact()
        .is_ok_and(|artifact| subtree_of(entry, &artifact).is_some());
    launches(entry, subtree)
}

/// Whether the file at `linked` is a launcher: its `#!` line ends in
/// [`LAUNCHER_VERB`]. Unreadable answers `false`; presence was answered by the
/// caller, and re-linking does not fix a permissions failure.
fn is_a_launcher(linked: &Path) -> bool {
    let Ok(bytes) = crate::fsio::read(linked) else {
        return false;
    };
    let first = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    std::str::from_utf8(first)
        .ok()
        .and_then(|line| line.strip_prefix("#!"))
        .and_then(|shebang| shebang.rsplit_once(' '))
        .is_some_and(|(_, verb)| verb == LAUNCHER_VERB)
}

/// Does the launcher at `linked` carry the environment rules `entry` declares?
///
/// The rules only, never the whole file: the `#!` line names the batten that ran
/// the last `apply`, and comparing bytes would call every launcher stale as soon
/// as that binary moved — churn over a question
/// [`relaunches_a_present_interpreter`] already answers on its own terms.
///
/// Unreadable is `true` for the same reason its sibling gives: presence was
/// answered above, and re-linking does not fix a permissions failure. A body
/// that will not parse is `false`, because that is precisely the launcher
/// [`exec_launcher`] refuses and tells the operator to rewrite.
fn launcher_declares(linked: &Path, entry: &Provision, cached: &Path) -> bool {
    let Ok(bytes) = crate::fsio::read(linked) else {
        return true;
    };
    let Some(body) = bytes.split_once_newline() else {
        return false;
    };
    let Ok(carried) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let Ok(declared) = serde_json::to_value(&entry.env) else {
        return false;
    };
    // AND THE BINARY IT NAMES (CLOUD-2682): switching an entry between a single
    // file and a subtree moves the cached binary, and a launcher naming the old
    // one must re-link rather than read fresh.
    let exec_matches = carried
        .get("exec")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|exec| Path::new(exec) == cached);
    carried.get("env") == Some(&declared) && exec_matches
}

/// Become the tool a launcher stands for, with the environment its row declares.
///
/// `script` is the launcher's own path, which the kernel supplies after the `#!`
/// argument; `args` is what the caller actually typed. Nothing about the calling
/// process survives except its environment, which is the point — the tool sees
/// one it can work in, and every other property of the invocation is unchanged.
///
/// # Errors
///
/// A [`UsageError`] when the launcher cannot be read or does not carry the
/// instructions this build knows how to follow — which is a batten and a
/// launcher that disagree, and is repaired by `provision apply`. On Unix a
/// successful `exec` never returns, so a returned error is always a real one.
pub fn exec_launcher(
    script: &Path,
    args: &[std::ffi::OsString],
) -> Result<std::convert::Infallible> {
    let bytes = crate::fsio::read(script).with_context(|| {
        format!(
            "read the launcher at {} — `batten provision apply` rewrites it",
            script.display()
        )
    })?;
    // Everything after the first newline, because the first line is the kernel's
    // and carries no instructions of its own.
    let body = bytes
        .split_once_newline()
        .ok_or_else(|| UsageError::raise("the launcher carries no instructions"))?;
    let launch: Launch = serde_json::from_slice(body).map_err(|err| {
        UsageError::raise(format!(
            "the launcher at {} does not carry instructions this batten understands ({err}); \
             run `batten provision apply` to rewrite it",
            script.display()
        ))
    })?;

    #[expect(
        clippy::disallowed_types,
        reason = "stays: this call IS the tool the operator asked for, and becoming it is the whole verb — there is no in-process form of somebody else's binary (CLOUD-320)"
    )]
    let mut command = std::process::Command::new(&launch.exec);
    // THE NAME IT WAS CALLED BY, NOT THE CACHED FILE'S (CLOUD-2093). The kernel
    // hands this process the path the launcher was invoked by, and a multicall
    // tool picks its personality from `argv[0]`: mise's shims are symlinks to
    // the launcher named `rustc`, `cargo` and the rest. Started as the cached
    // binary's path, every shim ran as a bare `mise` — measured, `rustc
    // --version` answered `2026.9.1 linux-x64`, and the semver gate took
    // `linux-x64` for a toolchain. A launcher called by its own name is unchanged.
    #[cfg(unix)]
    if let Some(name) = script.file_name() {
        use std::os::unix::process::CommandExt as _;
        command.arg0(name);
    }
    command.args(args);
    for (name, action) in resolved_env(&launch.env) {
        match action {
            // The one exposure on this path, and it is the wire: the value is
            // going into a child process's environment, which is the entire
            // purpose of the verb.
            EnvAction::Set(value) => command.env(name, value.expose()),
            // `env_remove` rather than `env("", …)`: the child must not see the
            // name at all. A cleared-to-empty proxy variable is read as "no
            // proxy" by some clients and as a malformed URL by others, which is
            // the ambiguity this arm exists to avoid.
            EnvAction::Unset => command.env_remove(name),
        };
    }
    become_process(command, &launch.exec)
}

/// The environment variables naming a trust bundle, most specific first.
///
/// A list because no single one is universal: a host sets a dozen of these, each
/// for a different tool, and they normally agree. The first that names a
/// readable file is the answer.
const TRUST_BUNDLE_VARS: &[&str] = &["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"];

/// Where the system keeps its trust bundle when the environment names none.
const SYSTEM_TRUST_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Whether the host's trust bundle carries a CA whose subject names `org`.
///
/// **A field match, never a byte search.** The organisation is read out of the
/// parsed subject, so a certificate merely mentioning the name — in a URL, a
/// policy identifier, an extension — does not answer yes. That distinction is
/// the whole reason this costs a parser: the predicate decides whether to route
/// a tool's traffic around a proxy, and a substring standing in for a field is
/// the estimate non-negotiable rule 3 refuses.
///
/// Could-not-look answers **false**, and the direction is deliberate. This
/// condition guards a BYPASS, so failing to read the bundle leaves the host's
/// proxy honoured — the same direction every other unreadable fact in this tree
/// fails in, and the safe one here: the cost of a wrong `false` is a refusal the
/// operator can see, and the cost of a wrong `true` is traffic silently leaving
/// a path they chose.
fn trust_names(org: &str) -> bool {
    let Ok(text) = crate::fsio::read_to_string(trust_bundle()) else {
        return false;
    };
    bundle_names(&text, org)
}

/// The trust bundle this host's tools read.
///
/// A VARIABLE THAT IS SET DECIDES WHICH BUNDLE, EVEN IF IT CANNOT BE READ.
/// Falling through to the system store when the named file is missing would
/// answer this question about a bundle the operator did not choose — and in an
/// intercepting sandbox the system store carries the interceptor too, so the
/// fallback would resurrect the bypass exactly where the operator had pointed
/// the tool somewhere else. The system path is for a host that names none.
fn trust_bundle() -> PathBuf {
    TRUST_BUNDLE_VARS
        .iter()
        .find_map(std::env::var_os)
        .map_or_else(|| PathBuf::from(SYSTEM_TRUST_BUNDLE), PathBuf::from)
}

/// Whether any certificate in the concatenated bundle `text` names `org`.
///
/// Split on the PEM footer rather than feeding the whole file: a bundle is a
/// concatenation, and the parser takes one document at a time.
fn bundle_names(text: &str, org: &str) -> bool {
    text.split_inclusive(PEM_FOOTER)
        .filter(|block| block.contains(PEM_FOOTER))
        .filter_map(|block| organisation_of(block.trim_start()))
        .any(|named| named == org)
}

/// The end of one certificate in a concatenated bundle.
const PEM_FOOTER: &str = "-----END CERTIFICATE-----";

/// The organisation a single PEM certificate's SUBJECT names, if it names one.
///
/// Public so the compiled-binary tier can build a one-certificate bundle out of
/// the host's own and assert both arms against a real authority, rather than
/// against a literal whose shape its author imagined.
#[must_use]
pub fn organisation_of(pem: &str) -> Option<String> {
    use x509_cert::der::DecodePem as _;

    x509_cert::Certificate::from_pem(pem)
        .ok()?
        .tbs_certificate()
        .subject()
        .iter()
        .find(|attribute| attribute.oid == ORGANISATION_NAME)
        .and_then(|attribute| attribute_text(&attribute.value))
}

/// X.520's `organizationName`, the attribute a CA's `O =` is carried in.
///
/// Written as the OID rather than taken from a name database, because the
/// database is a separate feature of a separate crate and this needs exactly one
/// arc. `new_unwrap` is `const`, so a malformed literal is a build failure rather
/// than a runtime one.
const ORGANISATION_NAME: x509_cert::der::asn1::ObjectIdentifier =
    x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.4.10");

/// The text of a distinguished-name attribute, whichever string type it used.
///
/// X.509 lets a `DirectoryString` be any of several ASN.1 string types, and real
/// certificates use more than one: reading only `Utf8String` would answer "no
/// organisation" for a CA that spelled it `PrintableString`, which is a silent
/// false negative on exactly the certificate this predicate is looking for.
fn attribute_text(value: &x509_cert::der::Any) -> Option<String> {
    use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};

    value
        .decode_as::<Utf8StringRef<'_>>()
        .map(|got| got.as_str().to_owned())
        .or_else(|_| {
            value
                .decode_as::<PrintableStringRef<'_>>()
                .map(|got| got.as_str().to_owned())
        })
        .or_else(|_| {
            value
                .decode_as::<Ia5StringRef<'_>>()
                .map(|got| got.as_str().to_owned())
        })
        .or_else(|_| {
            value
                .decode_as::<TeletexStringRef<'_>>()
                .map(|got| got.as_str().to_owned())
        })
        .ok()
}

/// What a credential is proved against and where one is looked for, from the
/// consumer's config.
///
/// **Config rather than engine literals, which is non-negotiable rule 1.** The
/// engine holds the MECHANISM — refuse a known-bad credential, then test the
/// real one — and both facts it needs belong to the repository that holds the
/// credential: the endpoint, because a hostname here would be simply wrong for a
/// consumer on another forge, and the variable NAMES, because a list here is
/// silently dead everywhere the host spells them differently.
/// **Read ONCE, for both.** It was two calls over the same file — one per
/// candidate for the URL, none at all for the names — and a second reader of one
/// config is a place two answers can disagree.
/// **EVERY STEP REPORTS ITS OWN FAILURE.** Written first as one `?` chain over
/// `.ok()`, which collapsed four different could-not-looks into `None` and made
/// the launcher's report say "no probe declared" over a repository that declares
/// one — the same conflation [`Look`] exists to refuse, reintroduced one
/// function up. A caller cannot act on the answer without knowing which step
/// gave it.
fn credential_declaration() -> std::result::Result<CredentialProbe, String> {
    let cwd = std::env::current_dir().map_err(|err| format!("no working directory: {err}"))?;
    credential_declaration_in(&cwd)
}

/// [`credential_declaration`] for a call made at `start`.
///
/// **The worktree's authority, not the shared root's** (CLOUD-2532). From a
/// linked worktree `repo_root` is the MAIN checkout, so `land` → `verify` in a
/// worktree reported `<main checkout>/batten.toml will not load` over a branch
/// whose own file loaded fine.
fn credential_declaration_in(start: &Path) -> std::result::Result<CredentialProbe, String> {
    let root = crate::config::authority_root(start)
        .map_err(|err| format!("{} is in no repository: {err}", start.display()))?;
    // The FILE, not the directory. `load` takes a path to `batten.toml`, and
    // handing it the root read as `Is a directory (os error 21)` — swallowed by
    // the `.ok()` chain this function used to be, and reported to the operator
    // as "no probe declared" over a repository whose `[credential]` table was
    // right there.
    let at = root.join(crate::config_model::CONFIG_FILE);
    let config =
        crate::config::load(&at).map_err(|err| format!("{} will not load: {err}", at.display()))?;
    config
        .credential
        .clone()
        .ok_or_else(|| "no `[credential]` table is declared".to_owned())
}

/// Where a credential verdict is cached, keyed by the credential's DIGEST.
///
/// **The value never reaches disk, which is rule 4 rather than caution.** The
/// receipt's name is a digest and its body is one word, so the store answers
/// "has this exact credential been proved recently" while carrying nothing that
/// could leak it. Keying by digest is also what makes the answer correct when a
/// session's credential is ROTATED mid-run: the new value simply has no receipt
/// and is proved on first use, where a name-keyed one would report the old
/// verdict about a value that no longer exists.
///
/// Under the COMMON git dir, beside every other receipt, so it dies with the
/// checkout and a linked worktree reads what the main one wrote.
fn credential_receipt_path(value: &Secret) -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let common = crate::git::common_dir(&cwd).ok()?;
    let dir = std::path::Path::new(&common).join("batten-receipts");
    Some(dir.join(format!("credential.{}", digest(value.expose().as_bytes()))))
}

/// How long a credential verdict is trusted before it is re-proved.
///
/// **The bound is what makes a mid-session revocation detectable at all.** A
/// verdict cached for the session cannot see a token revoked after boot, and one
/// re-proved per invocation costs a network round trip inside a launcher whose
/// whole budget is ~100 ms. Five minutes bounds the blind window to something a
/// human notices while keeping the probe off all but one call in a burst.
const CREDENTIAL_MAX_AGE: u64 = 300;

/// Whether this exact credential is usable, re-proved when its receipt ages out.
///
/// Failure to look is `false`, and the direction is deliberate: an unprovable
/// candidate is skipped rather than trusted, and if NO candidate proves usable
/// the caller keeps the host's own wiring instead of stripping it.
fn credential_usable(value: &Secret, probe: &str) -> bool {
    let Some(receipt) = credential_receipt_path(value) else {
        return false;
    };
    if let Ok(meta) = std::fs::metadata(&receipt)
        && let Ok(age) = meta
            .modified()
            .and_then(|at| at.elapsed().map_err(std::io::Error::other))
        && age.as_secs() < CREDENTIAL_MAX_AGE
        && let Ok(body) = crate::fsio::read_to_string(&receipt)
    {
        return body.starts_with("live");
    }
    // ORDER IS THE WHOLE DESIGN: establish the route can REFUSE before believing
    // that it accepted. Reversed, a substituting route reports every credential
    // live — including one that has been revoked.
    let verdict = match route_honours_credentials(probe, value, crate::fetch::get_direct) {
        // Nobody could reach it. The reason is already on stderr.
        None => Verdict::Unreachable,
        // The route answered for a token that cannot be this credential, so it
        // is answering with an identity of its own and nothing it says about
        // ours is evidence.
        Some(false) => Verdict::RouteSubstitutes,
        Some(true) => match probe_credential(probe, value, crate::fetch::get_direct) {
            Look::Answered(true) => Verdict::Live,
            Look::Answered(false) => Verdict::Refused,
            Look::CouldNotLook(_) => Verdict::Unreachable,
        },
    };
    let live = verdict == Verdict::Live;
    if let Some(dir) = receipt.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Best effort: a receipt we cannot write costs a probe per call, which is
    // slow rather than wrong. Failing the launch over it would be the opposite
    // of what this exists for.
    let _ = crate::durable::replace(&receipt, if live { "live\n" } else { "unusable\n" });
    if !live {
        // LOUD, AND ON THE RE-PROVE RATHER THAN ONCE, because this is the state
        // where the session silently degrades: the fence is not applied, the
        // host's credential is used, and third-party reads 403. Saying so at the
        // boundary is the difference between that and an unexplained refusal
        // three tasks later. Pointer-only — no value, no digest, no identity.
        crate::config::report(&format!(
            "{} — keeping the host's proxy wiring, so third-party reads will 403. \
             Re-checked every {CREDENTIAL_MAX_AGE}s.",
            verdict.why()
        ));
    }
    live
}

/// Whether ANY declared credential is usable, which is what gates every removal.
///
/// Separate from per-candidate selection because the two ask different
/// questions: selection asks "which value do I write", this asks "have I proved
/// a replacement exists at all" — and only the second may authorise stripping
/// the host's proxy wiring.
///
/// **Every could-not-look is [`Credential::Unusable`] AND IS SAID OUT LOUD.**
/// An undeclared table, an undeclared endpoint and an undeclared name list all
/// reach the same verdict as a revoked token, and they are not the same
/// situation: one is the operator's credential to replace and the others are the
/// consumer's config to write. Reporting the distinction is the only thing
/// separating this from a mechanism that loads clean and decides nothing.
pub(crate) fn credential_health() -> Credential {
    credential_check(true)
}

/// [`credential_health`] without its could-not-look reports (#1276): `doctor
/// egress` asks only whether a live credential would go direct, and its piped
/// run prints nothing but its verdict line. The same decision, so the two
/// never disagree about whether the fence is owed.
pub(crate) fn credential_quiet() -> Credential {
    credential_check(false)
}

/// The credential decision itself, saying its could-not-look reasons where
/// `report` asks.
fn credential_check(report: bool) -> Credential {
    let declaration = match credential_declaration() {
        Ok(declaration) => declaration,
        // No declared table is could-not-look, not health. Reading it as healthy
        // would authorise stripping the host's wiring on a consumer that never
        // said how to check.
        Err(why) => {
            if report {
                crate::config::report(&Verdict::NoProbe(why).why());
            }
            return Credential::Unusable;
        }
    };
    let Some(probe) = declaration.probe_url.as_deref() else {
        if report {
            crate::config::report(
                &Verdict::NoProbe("no `[credential] probe_url` is declared".to_owned()).why(),
            );
        }
        return Credential::Unusable;
    };
    if declaration.names.is_empty() {
        if report {
            crate::config::report(
                &Verdict::NoProbe(
                    "`[credential] names` is empty, so there is no variable to look in".to_owned(),
                )
                .why(),
            );
        }
        return Credential::Unusable;
    }
    if declaration
        .names
        .iter()
        // Into a `Secret` at the READ, which is the only place that keeps the
        // window shut: a value bound to a `String` first is a value some later
        // edit can print, and the whole class this fixes is later edits.
        .filter_map(|name| std::env::var(name).ok().map(Secret::new))
        .filter(|value| !value.is_empty())
        .any(|value| credential_usable(&value, probe))
    {
        Credential::Live
    } else {
        Credential::Unusable
    }
}

/// The direct GET a credential probe is spent through:
/// [`crate::fetch::get_direct`], in every caller but the unit suite.
///
/// **THE SEAM THE CONTROL ARM IS TESTED THROUGH.** Its three answers — refused,
/// substituted, unreachable — are a forge's to give, and no hermetic fixture is
/// a forge. A transport handed in is where a case can answer as each one.
type DirectGet = fn(&str, &[(String, String)]) -> Result<crate::fetch::Response>;

/// Whether the route to `probe` honours the credential we send, at all.
///
/// **THIS IS THE CONTROL ARM, AND WITHOUT IT EVERY VERDICT BELOW IS WORTHLESS.**
/// A success proves our credential worked only on a path that would have REFUSED
/// a bad one. Where the route substitutes — an intercepting proxy answering with
/// its own identity, which is this class of container's whole behaviour — a
/// junk credential succeeds exactly as a real one does, so "it worked" carries
/// no information about what we hold.
///
/// Measured 2026-09-06 on `git` traffic to the forge: a deliberately invalid
/// token was accepted with the proxy variables SET and with them CLEARED, which
/// is why the probe is not a `git` call and why clearing the environment is not
/// evidence of anything. On the API route, the same junk token is refused and a
/// real one is not — so that route can answer and the git route cannot.
/// **`None` IS COULD-NOT-LOOK AND IS NOT `false`.** A route that refused the
/// junk credential and a route nothing could reach are different answers, and
/// collapsing them is what made this mechanism's first live reading unreadable:
/// every candidate resolved unusable, and the report could not say whether the
/// forge had refused the token or the connection had never been made.
///
/// It takes the REAL credential to derive a known-bad one shaped like it — see
/// [`known_bad_like`] — and never to send it. The control arm must be spent per
/// candidate rather than once, because "shaped like it" is only meaningful
/// against a particular credential.
fn route_honours_credentials(probe: &str, real: &Secret, get: DirectGet) -> Option<bool> {
    match probe_credential(probe, &known_bad_like(real), get) {
        Look::Answered(accepted) => Some(!accepted),
        Look::CouldNotLook(why) => {
            crate::config::report(&format!(
                "the credential probe could not reach {probe}: {why}"
            ));
            None
        }
    }
}

/// The character a derived body is filled with, and the one it falls back to.
///
/// Two, because the derivation is only known-bad if it DIFFERS from the value it
/// was derived from — and a credential whose body is already all `0` would
/// derive to itself, making a live route look like a substituting one. That
/// direction is safe (removals are skipped) but it is still a wrong answer, and
/// ruling it out costs one comparison.
const FILL: [char; 2] = ['0', '1'];

/// A credential the route must REFUSE, shaped like the one we are about to test.
///
/// # Why derived rather than a literal
///
/// This was one forge's token prefix followed by a run of zeroes, spelled out in
/// `crates/batten`, for one commit — non-negotiable rule 1 twice over: a forge's
/// token prefix is a consumer identifier, and the literal is simply WRONG off
/// that forge. (The spelling is not repeated here; the gate that now enforces
/// this, `the_engine_names_no_consumer_of_its_own`, reads THIS file, and a
/// scanner whose own corpus carries the shape it hunts is one nobody can trust a
/// negative from. It caught this paragraph's first draft.) The doc it sat under
/// stated the criterion it broke — the token must be *"syntactically plausible
/// so the refusal is about the CREDENTIAL rather than about malformed input,
/// which a route could reject without ever consulting an identity"* — and that
/// prefix **is** malformed input to a GitLab, Gitea or Bitbucket endpoint. There the control
/// arm passes for exactly the reason the criterion rules out, so the route is
/// declared to honour credentials on evidence it has not earned, and every
/// verdict downstream of it rests on a rubber stamp.
///
/// Plausibility is a property of a FORGE, and an agnostic engine holds no
/// forge's grammar. What it does hold is a real credential for that forge, and
/// the shape of a well-formed token is the best available evidence of what a
/// well-formed token looks like there. So the derivation keeps everything up to
/// and including the last structural (non-alphanumeric) character — a prefix
/// like `ghp_` or `glpat-`, whatever this forge spells — and refills the body,
/// preserving length and character class.
///
/// # Why the consumer does not get to name it
///
/// Deliberately not a config field. A consumer that could name the known-bad
/// could name one the route happens to ACCEPT, which turns the control arm into
/// the rubber stamp it exists to prevent. The engine derives it, so the claim
/// "this route refuses a bad credential" is one nothing outside can weaken.
///
/// # What it is not
///
/// Not a guarantee of invalidity. A forge could in principle have issued the
/// derived value, at a probability no operator needs to reason about; if it had,
/// the route would accept it, the verdict would read [`Verdict::RouteSubstitutes`],
/// and removals would be SKIPPED — the safe direction, which is why this is
/// stated rather than defended against.
fn known_bad_like(real: &Secret) -> Secret {
    // `expose` here and nowhere downstream: the derived value is what travels,
    // and it is a `Secret` too, so a report that renders it says `<redacted>`
    // rather than handing a reader a token-shaped string to mistake for ours.
    let real = real.expose();
    let body_from = real
        .char_indices()
        .rfind(|(_, char)| !char.is_alphanumeric())
        .map_or(0, |(at, char)| at + char.len_utf8());
    let mut derived = String::with_capacity(real.len());
    for fill in FILL {
        derived.clear();
        derived.push_str(&real[..body_from]);
        // Length AND class preserved: one filler char per body char, so a route
        // that checks either sees a token it has to consult an identity about.
        derived.extend(real[body_from..].chars().map(|_| fill));
        if derived != real {
            return Secret::new(derived);
        }
    }
    // A value with NO alphanumeric body — every character structural — has
    // nothing to refill, so both fills derive it back. Lengthening it is the one
    // remaining way to differ, and a credential of that shape is not one any
    // forge issued anyway.
    derived.push(FILL[0]);
    Secret::new(derived)
}

/// Why a credential did or did not prove usable.
///
/// **FOUR WAYS TO FAIL, AND THEY HAVE DIFFERENT REMEDIES**, which is the whole
/// reason this is not a boolean. A revoked token is the operator's to replace; a
/// substituting route means the fence is not up and the probe is measuring the
/// proxy; an unreachable endpoint is the network; an undeclared probe is the
/// consumer's own config. Reported as one line each, pointer-only.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Proved against a route that demonstrably refuses a bad credential.
    Live,
    /// The route answered and refused this credential.
    Refused,
    /// The route accepted a token of zeroes, so it answers with its own
    /// identity and says nothing about ours.
    RouteSubstitutes,
    /// Nothing was reached.
    Unreachable,
    /// No endpoint was resolved, carrying which step could not resolve one.
    NoProbe(String),
}

impl Verdict {
    /// The clause the report leads with. Never the credential, never a digest.
    fn why(&self) -> String {
        match self {
            // Never rendered: the report is written only where `live` is false.
            Self::Live => "the session credential authenticated".to_owned(),
            Self::Refused => "a declared session credential did not authenticate".to_owned(),
            Self::RouteSubstitutes => {
                "the route to the credential probe answers for a token of zeroes, so it is \
                 substituting its own identity and no credential can be proved over it"
                    .to_owned()
            }
            Self::Unreachable => "the credential probe could not be reached".to_owned(),
            Self::NoProbe(why) => format!("no credential probe could be resolved: {why}"),
        }
    }
}

/// What a probe found, keeping "the route answered" apart from "nobody could
/// ask".
enum Look {
    /// The route answered, and whether it accepted the credential.
    Answered(bool),
    /// Nothing was reached. Carries the transport's own reason, which
    /// [`crate::fetch`] writes as a pointer rather than a payload.
    CouldNotLook(String),
}

/// Whether `probe` answers 2xx for `token`.
///
/// DIRECT, NEVER THE AMBIENT ROUTE, and this is the correction that makes the
/// whole mechanism able to fire. This function first read `NO_PROXY` through
/// [`crate::fetch::get`], on the reasoning that a second reader of that list is
/// drift — true, and beside the point: the fence is what the verdict AUTHORISES,
/// so routing the proof through the un-fenced environment makes the fence its
/// own precondition and nothing can ever be proven.
///
/// Measured on this container, `api.github.com/rate_limit`, a token of zeroes:
/// `200` through the proxy and `401` direct. Through the proxy the control arm
/// passes, the route is read as substituting, and every credential resolves
/// `Unusable` forever — the mechanism loads clean and decides nothing, which is
/// exactly the dead-gate shape the policy-module rules record one layer up.
///
/// Pointer-only: the verdict is a boolean over a status and no body is read.
fn probe_credential(probe: &str, token: &Secret, get: DirectGet) -> Look {
    // `expose` at the LAST possible moment and into a value that goes straight
    // to the wire. `Call`'s own `Debug` redacts this header, so the credential
    // is out of the type for exactly the length of one request build.
    let headers = [(
        "Authorization".to_owned(),
        format!("Bearer {}", token.expose()),
    )];
    match get(probe, &headers) {
        Ok(response) => Look::Answered((200..300).contains(&response.status)),
        Err(why) => Look::CouldNotLook(why.to_string()),
    }
}

/// Turn a launcher's declared rules into the variables to set, reading the
/// environment this process was started with.
///
/// A rule that resolves to nothing sets nothing, which is what keeps an absent
/// credential absent rather than empty.
fn resolved_env(rules: &[ProvisionEnv]) -> Vec<(String, EnvAction)> {
    // ONLY A ROW THAT REMOVES SOMETHING READS THE VERDICT, so only such a row
    // pays for it. `credential_health` costs a repo-root resolve, a config load
    // and — on a cold or expired receipt — two direct HTTPS round trips, and it
    // sat unconditionally in front of `become_process`. Every landed row
    // declares only `prepend_list` or `from_first_set`, none of which consults
    // `Credential`, so every launcher exec was blocking on the network for an
    // answer nothing read, against a path this file budgets at ~100 ms.
    //
    // `Unusable` is the honest value where nothing asks: it authorises no
    // removal, which is exactly the state a rule set with no removals is in.
    let credential = if rules
        .iter()
        .any(|rule| rule.unset || rule.reject_prefix.is_some() || bypasses(rule))
    {
        credential_health()
    } else {
        Credential::Unusable
    };
    // Into a `Secret` at the READ. The launcher's environment is mostly
    // credentials, so the type starts at the boundary rather than being put on
    // afterwards — a value that is a `String` for three lines is a value three
    // lines can print.
    resolved_env_from(rules, credential, &trust_names, &|name| {
        std::env::var(name).ok().map(Secret::new)
    })
}

/// Whether `rule` routes traffic around the host's proxy: a list row scoped to
/// an interception authority (`when_trust_names` is what marks a bypass, per
/// its own doc). Such a row is a removal and owes a proven credential.
fn bypasses(rule: &ProvisionEnv) -> bool {
    !rule.prepend_list.is_empty() && rule.when_trust_names.is_some()
}

/// [`resolved_env`] over a supplied lookup.
///
/// The environment is process-global, so a test that set it would race every
/// other test in the binary. Taking the reader makes the resolver a pure
/// function of its inputs — which is also what lets a case assert the
/// three-way distinction between set, absent, and removed without touching the
/// process it is running in.
fn resolved_env_from(
    rules: &[ProvisionEnv],
    credential: Credential,
    trusted: &dyn Fn(&str) -> bool,
    lookup: &dyn Fn(&str) -> Option<Secret>,
) -> Vec<(String, EnvAction)> {
    // EVERY REMOVAL IS CONDITIONAL ON A PROVEN REPLACEMENT. With an unusable
    // credential the rows below degrade to the host's own wiring rather than to
    // an empty one: the proxy variables stay, and a placeholder is preferred to
    // nothing. That is the direction `doctor` can still report on; the other one
    // leaves a session that cannot reach the forge at all and cannot say why.
    let removals_allowed = credential == Credential::Live;
    rules
        .iter()
        .filter(|rule| rule.when_trust_names.as_deref().is_none_or(trusted))
        .filter_map(|rule| {
            if rule.unset {
                // Skipped rather than inverted when the credential is unusable:
                // the row says "this variable should be gone", and the honest
                // answer without a replacement is to leave the host's value
                // alone, not to write one of our own.
                return removals_allowed.then(|| (rule.name.clone(), EnvAction::Unset));
            }
            let value = if rule.prepend_list.is_empty() {
                // `reject_prefix` is ignored outright when the credential is
                // unusable, which is what makes the placeholder WIN there. It
                // is a marker rather than a credential, and proxied it is
                // substituted for one that works — so it beats an empty
                // variable, and this is the arm that keeps it. That premise
                // holds only because a bypass row is ALSO withheld then
                // (CLOUD-2122): unfenced, the marker never goes direct.
                let reject = removals_allowed
                    .then_some(rule.reject_prefix.as_deref())
                    .flatten();
                // FIRST SET, AND SELECTION NEVER PROBES. Written first as
                // "first USABLE" — a per-candidate probe here — and that was
                // wrong twice over. It is a SECOND AUTHORITY over the question
                // [`credential_health`] already answers against the same names,
                // so the two can disagree; and it makes a launcher's
                // environment a function of the network, which §6's
                // byte-stability forbids outright. Measured: the launcher tier
                // went red because a fixture's synthetic token was probed
                // against the live forge.
                //
                // The measurement stays where it decides something: `Credential`
                // gates every REMOVAL, so a revoked PAT still costs the session
                // nothing it had, and the loud report says so.
                let real = rule.from_first_set.iter().find_map(|from| {
                    lookup(from)
                        .filter(|got| !got.is_empty())
                        // The predicate travels to the value: `Secret` answers
                        // `starts_with` without ever handing the bytes out.
                        .filter(|got| reject.is_none_or(|bad| !got.starts_with(bad)))
                });
                // NO REAL CANDIDATE. With a `reject_prefix` declared, that is
                // not the same as "nothing to do": the variable may still be
                // carrying the very marker the row rejected, and leaving it is
                // how a fenced request goes out with a placeholder and comes
                // back `Bad credentials`. Clear it instead, so the tool sees an
                // absent credential and says so.
                let Some(value) = real else {
                    let carries_marker = reject.is_some_and(|bad| {
                        lookup(&rule.name).is_some_and(|got| got.starts_with(bad))
                    });
                    return carries_marker.then(|| (rule.name.clone(), EnvAction::Unset));
                };
                value
            } else if bypasses(rule) && !removals_allowed {
                // A BYPASS IS A REMOVAL, ONE HOST AT A TIME (CLOUD-2122). A
                // `NO_PROXY` entry scoped to the interceptor takes those hosts
                // off the proxy exactly as the `unset` arm takes all of them,
                // so it owes the same proven replacement. Fenced with none, the
                // forge sees an anonymous or placeholder call and refuses it;
                // proxied, the host's own credential answers. Measured
                // 2026-10-07 with no PAT injected: `record forge` 403 and
                // `land` 403 inside the wrapper, both 200 from the shell.
                return None;
            } else {
                // A prepend row is a LIST row — `NO_PROXY` and `PATH` — and its
                // current value has to be read to be extended. `expose` here is
                // over a host list rather than a credential, and it goes
                // straight back into a `Secret`, so nothing widens.
                Secret::new(prepended(
                    lookup(&rule.name)
                        .as_ref()
                        .map_or("", |current| current.expose()),
                    &rule.prepend_list,
                ))
            };
            Some((rule.name.clone(), EnvAction::Set(value)))
        })
        .collect()
}

/// Add every entry not already in `current`, in front and in declared order.
///
/// Idempotent, which the launcher needs rather than merely benefits from: a tool
/// that re-invokes itself through the same `PATH` entry would otherwise grow the
/// value once per generation.
fn prepended(current: &str, additions: &[String]) -> String {
    let held: Vec<&str> = current
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    let mut out: Vec<&str> = additions
        .iter()
        .map(String::as_str)
        .filter(|entry| !held.contains(entry))
        .collect();
    out.extend(held);
    out.join(",")
}

/// Replace this process with `command`, or say why it could not be.
#[cfg(unix)]
#[expect(
    clippy::disallowed_types,
    reason = "stays: the parameter IS the tool the operator asked for, already built by the caller — becoming it is the whole verb, and there is no in-process form of somebody else's binary (CLOUD-320)"
)]
fn become_process(
    mut command: std::process::Command,
    exec: &Path,
) -> Result<std::convert::Infallible> {
    use std::os::unix::process::CommandExt as _;
    // `exec` returns only on failure, so reaching the next line IS the error.
    let failed = command.exec();
    Err(UsageError::raise(format!(
        "the launcher could not become {}: {failed}",
        exec.display()
    )))
}

/// The same, where a process cannot be replaced: run it and take its status.
///
/// Stated as a difference rather than hidden behind one name — the child is a
/// real second process here, so a signal aimed at this one does not reach it.
/// Nothing in this repository links on such a host today; the arm exists so the
/// cross-target build is honest about it.
#[cfg(not(unix))]
fn become_process(
    mut command: std::process::Command,
    exec: &Path,
) -> Result<std::convert::Infallible> {
    let status = command.status().map_err(|err| {
        UsageError::raise(format!(
            "the launcher could not run {}: {err}",
            exec.display()
        ))
    })?;
    std::process::exit(status.code().unwrap_or(1));
}

/// A tiny helper so the split above reads as what it is.
trait SplitOnceNewline {
    /// Everything after the first `\n`, or `None` when there is not one.
    fn split_once_newline(&self) -> Option<&[u8]>;
}

impl SplitOnceNewline for [u8] {
    fn split_once_newline(&self) -> Option<&[u8]> {
        let at = self.iter().position(|byte| *byte == b'\n')?;
        self.get(at + 1..)
    }
}

/// Expand a leading `~` and refuse anything that is not then absolute.
///
/// The refusal is the point rather than a validation flourish: a relative
/// destination would resolve against whatever directory the process was launched
/// from, so the same manifest would install to different places depending on the
/// caller — and a `PATH` entry nobody can predict is worse than none.
fn expand_home(dest: &str) -> Result<PathBuf> {
    let expanded = match dest.strip_prefix("~/") {
        Some(rest) => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                UsageError::raise(format!(
                    "the link destination {dest} begins with `~` and HOME is unset, \
                     so there is nothing to expand it against"
                ))
            })?;
            PathBuf::from(home).join(rest)
        }
        None => PathBuf::from(dest),
    };
    if !expanded.is_absolute() {
        return Err(UsageError::raise(format!(
            "the link destination {dest} is relative; name an absolute path or one \
             under `~/`, so the same manifest installs to the same place whatever \
             directory the caller ran from"
        )));
    }
    Ok(expanded)
}

/// Extract a subtree archive into `<dir>/tree/` and return the cached binary
/// (CLOUD-2682).
///
/// Staged beside and renamed in, never written in place: a running process
/// keeps its open files, and a failed extraction leaves the old tree and the
/// artifact as they were.
fn install_tree(dir: &Path, unpack: Unpack, subtree: &Subtree, bytes: &[u8]) -> Result<PathBuf> {
    fs::create_dir_all(dir).context("create the provision cache directory")?;
    let pid = std::process::id();
    let staged = dir.join(format!(".tree.{pid}.tmp"));
    let _ = fs::remove_dir_all(&staged);
    fs::create_dir_all(&staged).context("create the staged tree")?;
    let extracted = match unpack {
        Unpack::TarGz => extract_tree_tar(bytes, &staged, subtree),
        Unpack::Zip => extract_tree_zip(bytes, &staged, subtree),
        _ => Err(UsageError::raise(
            "a subtree needs an archive, and this row unpacks none".to_owned(),
        )),
    }
    .and_then(|()| staged_bin(&staged, subtree));
    if let Err(err) = extracted {
        let _ = fs::remove_dir_all(&staged);
        return Err(err);
    }
    let tree = dir.join(TREE_DIR);
    let aside = dir.join(format!(".tree.{pid}.old"));
    if fs::symlink_metadata(&tree).is_ok() {
        fs::rename(&tree, &aside).context("move the old tree aside")?;
    }
    if let Err(err) = fs::rename(&staged, &tree) {
        let _ = fs::rename(&aside, &tree);
        let _ = fs::remove_dir_all(&staged);
        return Err(err).context("move the extracted tree into place");
    }
    let _ = fs::remove_dir_all(&aside);
    Ok(tree.join(&subtree.bin))
}

/// The staged tree's binary must be a file, and is made executable.
fn staged_bin(staged: &Path, subtree: &Subtree) -> Result<()> {
    let bin = &subtree.bin;
    if !staged.join(bin).is_file() {
        return Err(UsageError::raise(format!(
            "the archive has no file at `bin = \"{}\"` after `strip = {}`",
            bin.display(),
            subtree.strip
        )));
    }
    make_executable(&staged.join(bin))
}

/// What one archive entry is, for [`place`].
enum Kind {
    Dir,
    File { executable: bool },
    Symlink(PathBuf),
}

/// An entry that would land outside the tree: refused, never skipped.
fn climbs_out(path: &Path) -> anyhow::Error {
    UsageError::raise(format!(
        "the archive entry {} climbs out of the tree, so nothing was installed",
        path.display()
    ))
}

/// `path` with its first `strip` components dropped, `None` when nothing is
/// left; a root, prefix or `..` component is refused.
fn stripped(path: &Path, strip: usize) -> Result<Option<PathBuf>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part),
            std::path::Component::CurDir => {}
            _ => return Err(climbs_out(path)),
        }
    }
    Ok((parts.len() > strip).then(|| parts[strip..].iter().collect()))
}

/// Whether `link`, read from the directory `parent` (both relative to the tree
/// root), stays inside the tree.
#[cfg_attr(not(unix), allow(dead_code))]
fn lexically_inside(parent: &Path, link: &Path) -> bool {
    let mut depth = parent
        .components()
        .filter(|part| matches!(part, std::path::Component::Normal(_)))
        .count();
    for part in link.components() {
        match part {
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

/// Write one archive entry under `tree` (CLOUD-2682), the one rule set the tar
/// and zip loops share.
fn place(
    tree: &Path,
    strip: usize,
    bin: &Path,
    raw: &Path,
    kind: Kind,
    reader: &mut dyn Read,
) -> Result<()> {
    let Some(rel) = stripped(raw, strip)? else {
        return Ok(());
    };
    let target = tree.join(&rel);
    let root = crate::git::canonical(tree);
    let Some(parent) = target.parent() else {
        return Err(climbs_out(raw));
    };
    fs::create_dir_all(parent).context("create an archive entry's directory")?;
    let parent = crate::git::canonical(parent);
    if !parent.starts_with(&root) {
        return Err(climbs_out(raw));
    }
    let Some(name) = target.file_name() else {
        return Err(climbs_out(raw));
    };
    let target = parent.join(name);
    // A later entry never writes through an earlier link.
    if fs::symlink_metadata(&target).is_ok_and(|meta| !meta.is_dir()) {
        fs::remove_file(&target).context("replace an archive entry")?;
    }
    match kind {
        Kind::Dir => fs::create_dir_all(&target).context("create an archive directory")?,
        Kind::File { executable } => {
            // stream: an archive entry, committed by the staged tree's rename
            let mut out = fs::File::create(&target).context("write an archive file")?; // stream: tree rename
            crate::stream::pump(reader, &mut [&mut out]).context("write an archive file")?;
            set_mode(&target, executable || rel.as_path() == bin)?;
        }
        Kind::Symlink(link) => {
            let inside = rel.parent().unwrap_or_else(|| Path::new(""));
            place_symlink(inside, &target, &link, raw)?;
        }
    }
    Ok(())
}

/// A symlink whose target stays inside the tree (CLOUD-2682): relative, and
/// resolved lexically from its own directory. A host without symlinks refuses
/// the entry.
///
/// ONE FUNCTION, BOTH HOSTS: two `#[cfg]` twins listed a mutant in the body no
/// build on this host compiles, which no test here could ever kill.
fn place_symlink(parent: &Path, target: &Path, link: &Path, raw: &Path) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (parent, target, link);
        return Err(UsageError::raise(format!(
            "the archive entry {} is a symlink, which this host's tree does not admit",
            raw.display()
        )));
    }
    #[cfg(unix)]
    {
        let link_target = link.to_path_buf();
        if !lexically_inside(parent, &link_target) {
            return Err(climbs_out(raw));
        }
        std::os::unix::fs::symlink(&link_target, target).context("write an archive link")
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .context("set an archive file's mode")
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

/// Extract a gzipped tarball as a subtree (CLOUD-2682).
fn extract_tree_tar(bytes: &[u8], tree: &Path, subtree: &Subtree) -> Result<()> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
    for entry in archive.entries().context("read the tar archive")? {
        let mut entry = entry.context("read a tar entry")?;
        let raw = entry
            .path()
            .context("decode a tar entry path")?
            .into_owned();
        let kind = entry.header().entry_type();
        let kind = match kind {
            tar::EntryType::Directory => Kind::Dir,
            tar::EntryType::Symlink => Kind::Symlink(
                entry
                    .link_name()
                    .context("decode a tar link target")?
                    .ok_or_else(|| climbs_out(&raw))?
                    .into_owned(),
            ),
            tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader
            | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink => continue,
            other if other.is_file() => Kind::File {
                executable: entry.header().mode().is_ok_and(|mode| mode & 0o111 != 0),
            },
            other => {
                return Err(UsageError::raise(format!(
                    "the archive entry {} is a {other:?}, which a provision tree does not admit",
                    raw.display()
                )));
            }
        };
        place(tree, subtree.strip, &subtree.bin, &raw, kind, &mut entry)?;
    }
    Ok(())
}

/// Extract a zip archive as a subtree (CLOUD-2682).
fn extract_tree_zip(bytes: &[u8], tree: &Path, subtree: &Subtree) -> Result<()> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("read the zip archive")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read a zip entry")?;
        let Some(raw) = entry.enclosed_name() else {
            return Err(climbs_out(Path::new(&*entry.name().unwrap_or_default())));
        };
        let kind = if entry.is_dir() {
            Kind::Dir
        } else if entry.is_symlink() {
            let mut link = String::new();
            entry
                .read_to_string(&mut link)
                .context("read a zip link target")?;
            Kind::Symlink(PathBuf::from(link))
        } else {
            Kind::File {
                executable: entry.unix_mode().is_some_and(|mode| mode & 0o111 != 0),
            }
        };
        place(tree, subtree.strip, &subtree.bin, &raw, kind, &mut entry)?;
    }
    Ok(())
}

/// Extract the entry named `binary` from a zip archive, by file name as
/// [`extract`] does for a tarball.
fn extract_zip(bytes: &[u8], binary: &str) -> Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("read the zip archive")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("read a zip entry")?;
        let named = entry
            .enclosed_name()
            .and_then(|path| path.file_name().map(|name| name == binary))
            .unwrap_or(false);
        if !named || entry.is_dir() {
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

fn make_executable(path: &Path) -> Result<()> {
    crate::durable::make_executable(path).context("mark the provisioned binary executable")
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
        return crate::fsio::read(path).with_context(|| format!("fetch {url}"));
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
    Ok(cached_binary(
        &entry_dir(&cache_root(repo_root)?, entry),
        entry,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(test)]
    use std::collections::BTreeMap;

    /// CLOUD-2124: the measured case, a scratch clone's debug build provisioning
    /// the host from inside its own checkout, is refused; an installed engine,
    /// and a build of ANOTHER tree provisioning a fixture, still link.
    #[test]
    fn a_build_of_the_checkout_never_links_the_host() {
        let repo = Path::new("/scratch/ciclone");
        assert!(
            !links_host(Path::new("/scratch/ciclone/target/debug/batten"), repo),
            "cargo's output inside the provisioned checkout is not an installed engine"
        );
        assert!(
            links_host(Path::new("/root/.local/bin/batten"), repo),
            "the installed engine provisions the host"
        );
        assert!(
            links_host(Path::new("/home/user/batten/target/debug/batten"), repo),
            "a build of another tree is not a build of this one"
        );
    }

    /// CLOUD-2617: the measured case, a root Setup shell whose `PATH` carries
    /// `/usr/local/bin` and not the declared `~/.local/bin`, links where
    /// `engine install` put batten; a declared directory `PATH` reaches still
    /// wins, and with nothing writable the declaration stands.
    ///
    /// Fails by: the fallback dropped, so the runner is linked off `PATH`, every
    /// `[[startup]]` row naming it is could-not-look, and `status` reads fresh.
    ///
    /// Compiled and run on every target. The one host fact it needs is `HOME`,
    /// and where that is unset a `~/` link is a usage error rather than a
    /// fallback, which is the contract this case asserts there.
    #[test]
    fn a_declared_link_off_path_follows_engine_installs_fallback() {
        // BOTH ARMS ASSERT, so no host passes this case without a verdict.
        match expand_home(LINK_PER_USER) {
            Ok(declared) => assert_the_fallback(&declared),
            Err(_) => assert!(
                link_dir(LINK_PER_USER, Host::isolated(true)).is_err(),
                "a `~/` link with no HOME to expand is refused, never resolved"
            ),
        }
    }

    /// CLOUD-2617 review: the fallback writes into a directory package managers
    /// share, so it takes a name only where that name is free or batten's own.
    ///
    /// Fails by: the free-name test answering `true` for everything, so
    /// Homebrew's or an image's `mise` is renamed over.
    #[test]
    fn a_fallback_never_takes_a_name_another_tool_owns() {
        let dir = scratch("claimable");
        let cache = dir.join("cache");
        let shared = dir.join("shared-bin");
        fs::create_dir_all(&shared).unwrap();
        let body = b"#!/bin/sh\nexit 0\n".to_vec();
        let entry = entry("tool", &digest(&body));
        let linked = shared.join("tool");

        assert!(claimable(&shared, &entry, &cache), "a free name");

        fs::write(&linked, b"another tool's binary").unwrap();
        assert!(!claimable(&shared, &entry, &cache), "a foreign binary");

        fs::write(&linked, format!("#!/opt/batten {LAUNCHER_VERB}\n{{}}\n")).unwrap();
        assert!(claimable(&shared, &entry, &cache), "batten's own launcher");

        fs::write(&linked, &body).unwrap();
        assert!(
            !claimable(&shared, &entry, &cache),
            "a plain copy nobody recorded"
        );
        // AN INTENT ALONE, the crash between the two record writes: it admits
        // the file only where it holds this entry's own cached bytes.
        record_intent(&cache, &entry, &linked).unwrap();
        assert!(
            !claimable(&shared, &entry, &cache),
            "an intent does not vouch for bytes batten never cached"
        );
        let cached = entry_dir(&cache, &entry).join(BIN_DIR).join("tool");
        fs::create_dir_all(cached.parent().unwrap()).unwrap();
        fs::write(&cached, &body).unwrap();
        assert!(
            claimable(&shared, &entry, &cache),
            "an intent over this entry's own cached bytes is batten's half-finished link"
        );
        // SAME LENGTH IS NOT SAME BYTES: every byte is compared.
        let mut lookalike = body.clone();
        lookalike[0] ^= 1;
        fs::write(&linked, &lookalike).unwrap();
        assert!(
            !claimable(&shared, &entry, &cache),
            "an intent over same-length foreign bytes"
        );
        fs::write(&linked, &body).unwrap();

        record_written(&cache, &entry, &linked).unwrap();
        assert!(
            claimable(&shared, &entry, &cache),
            "the link batten recorded writing"
        );
        // THE COMPLETED RECORD STANDS ON ITS STAMP, not on the cache: after a
        // version bump the new version's cache holds nothing yet, and batten's
        // own copy must still be batten's.
        fs::remove_file(&cached).unwrap();
        assert!(
            claimable(&shared, &entry, &cache),
            "the link batten recorded writing, whatever version wrote it"
        );
        // A RELINK THAT NEVER LANDS: the next version's intent, then a failure
        // before its rename. The earlier copy keeps the stamp the intent kept.
        record_intent(&cache, &entry, &linked).unwrap();
        assert!(
            claimable(&shared, &entry, &cache),
            "batten's earlier copy, under a relink that failed"
        );

        // `shared` IS THE FALLBACK'S, NOT EVERY LINK'S: an absolute link names
        // its own directory, which is never judged for another tool's name.
        let mut declared = entry.clone();
        declared.link = Some(shared.to_string_lossy().into_owned());
        assert_eq!(
            link_of(&declared, Host::isolated(true)).unwrap(),
            Some(Link {
                dir: shared.clone(),
                shared: false,
            }),
            "a declared directory is not a shared one"
        );

        // REPLACED AFTERWARDS by another tool: the path still matches the
        // record, the identity does not, and the name is not batten's again.
        fs::write(&linked, b"a different tool's longer binary").unwrap();
        assert!(
            !claimable(&shared, &entry, &cache),
            "a file another tool put at the recorded path"
        );

        // AND THE APPLY REFUSES rather than renaming over it, leaving it whole
        // and dropping the record that no longer vouches for it.
        let link = Link {
            dir: shared.clone(),
            shared: true,
        };
        assert!(apply_with(&entry, &cache, true, Some(&link)).is_err());
        assert!(
            link_record(&cache, &entry).exists(),
            "a preview refuses and changes nothing"
        );
        assert!(apply_with(&entry, &cache, false, Some(&link)).is_err());
        assert_eq!(
            fs::read(&linked).unwrap(),
            b"a different tool's longer binary"
        );
        assert!(
            !link_record(&cache, &entry).exists(),
            "a refused apply forgets the stale record"
        );
        assert_eq!(
            freshness_of(&entry, &cache, Some(&link)).unwrap(),
            Freshness::Foreign,
            "a foreign name in a shared directory reads foreign, never fresh"
        );
        let unshared = Link {
            dir: shared.clone(),
            shared: false,
        };
        assert_ne!(
            freshness_of(&entry, &cache, Some(&unshared)).unwrap(),
            Freshness::Foreign,
            "only a SHARED directory's name is judged foreign"
        );
    }

    /// The per-user link the fallback case resolves.
    const LINK_PER_USER: &str = "~/.local/bin";

    /// The fallback's six readings, for a host where `~/` expands to `declared`.
    fn assert_the_fallback(declared: &Path) {
        let declared = declared.to_path_buf();
        let system = PathBuf::from(crate::install::SYSTEM_BIN_DIRS[0]);
        let resolve = |dest: &str, on_path: &[PathBuf], writable: fn(&Path) -> bool| {
            let host = Host {
                links: true,
                on_path,
                writable,
            };
            link_dir(dest, host).unwrap()
        };

        let root_setup = [system.clone(), PathBuf::from("/usr/bin")];
        assert_eq!(
            resolve(LINK_PER_USER, &root_setup, |_| true),
            system,
            "off PATH: the fallback"
        );
        assert_eq!(
            resolve(LINK_PER_USER, &[declared.clone(), system], |_| true),
            declared,
            "on PATH: the declaration"
        );
        assert_eq!(
            resolve(LINK_PER_USER, &root_setup, |_| false),
            declared,
            "nothing writable"
        );
        // ABSOLUTE ON EVERY TARGET: `/opt/tools/bin` is relative on Windows,
        // which `expand_home` refuses.
        let named = std::env::temp_dir().join("batten-named-link");
        assert_eq!(
            resolve(&named.to_string_lossy(), &root_setup, |_| true),
            named,
            "an absolute link is named, and stands off PATH"
        );
        assert_eq!(
            link_dir(LINK_PER_USER, Host::isolated(true)).unwrap(),
            declared,
            "an isolated host never reaches a system directory"
        );
        let spliced = Host {
            on_path: &root_setup,
            ..Host::isolated(true)
        };
        assert_eq!(
            link_dir(LINK_PER_USER, spliced).unwrap(),
            declared,
            "an isolated host answers that nothing is writable, whatever PATH it is given"
        );
    }

    // -----------------------------------------------------------------------
    // The control credential is DERIVED, never a forge's literal (CLOUD-1615).
    //
    // Shaped like the value it stands in for, on whatever forge that is, so the
    // route has to consult an identity to refuse it. A case here asserts the
    // three properties that makes checkable — prefix, length, difference —
    // rather than a rendering, because the value never reaches a rendering.
    // -----------------------------------------------------------------------

    /// Distinctive, and DELIBERATELY NOT SHAPED LIKE A REAL CREDENTIAL: every
    /// assertion below is over structure, so a well-formed fixture would buy
    /// nothing and would put a token-shaped string in front of the scanner.
    const CANARY: &str = "xyz_CANARYnotacredential99";

    #[test]
    fn the_control_credential_keeps_the_structural_prefix() {
        let derived = known_bad_like(&Secret::new(CANARY.to_owned()));
        assert!(
            derived.starts_with("xyz_"),
            "the forge's own prefix is what makes the token plausible THERE, and \
             an engine that dropped it would be sending malformed input — which a \
             route can refuse without ever consulting an identity"
        );
    }

    /// The engine holds no forge's grammar, so the case proves the derivation
    /// travels: a prefix it has never seen is carried exactly as `xyz_` is.
    #[test]
    fn it_carries_a_prefix_the_engine_has_never_seen() {
        let derived = known_bad_like(&Secret::new("glpat-AbCdEfGhIjKlMnOp".to_owned()));
        assert!(derived.starts_with("glpat-"), "another forge's prefix");
        assert_eq!(derived.expose().len(), "glpat-AbCdEfGhIjKlMnOp".len());
    }

    #[test]
    fn the_control_credential_preserves_length_and_differs() {
        let real = Secret::new(CANARY.to_owned());
        let derived = known_bad_like(&real);
        assert_eq!(
            derived.expose().len(),
            CANARY.len(),
            "a length check is the cheapest thing a route can reject on without \
             consulting an identity"
        );
        assert_ne!(
            derived.expose(),
            real.expose(),
            "A CONTROL THAT IS THE CREDENTIAL PROVES NOTHING: the route would \
             accept it for the right reason and be read as substituting"
        );
    }

    /// SHOWN ABLE TO FAIL in the degenerate direction (CLOUD-418). A body that
    /// is already the first filler derives to itself unless the fallback fires,
    /// which is the one input where the property above is not free.
    #[test]
    fn a_credential_already_made_of_the_filler_still_differs() {
        for real in ["tok_000000", "0000", "----"] {
            let derived = known_bad_like(&Secret::new(real.to_owned()));
            assert_ne!(derived.expose(), real, "over {real}");
        }
    }

    /// A row that sets `name` from `from_first_set`, rejecting `proxy-`.
    fn credential_row(name: &str) -> ProvisionEnv {
        ProvisionEnv {
            name: name.to_owned(),
            prepend_list: Vec::new(),
            from_first_set: vec!["BATTEN_TEST_PAT".to_owned(), name.to_owned()],
            when_trust_names: None,
            reject_prefix: Some("proxy-".to_owned()),
            unset: false,
        }
    }

    /// A row that removes `name` outright.
    fn unset_row(name: &str) -> ProvisionEnv {
        ProvisionEnv {
            name: name.to_owned(),
            prepend_list: Vec::new(),
            from_first_set: Vec::new(),
            when_trust_names: None,
            reject_prefix: None,
            unset: true,
        }
    }

    /// The environment a case declares, as the resolver's lookup.
    ///
    /// Injected rather than set on the process: the environment is global, so a
    /// case that wrote it would race every other test in this binary — and the
    /// three-way distinction below (set / absent / removed) is exactly what a
    /// racing reader would blur.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<Secret> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| Secret::new(value.clone()))
        }
    }

    /// THE PREMISE CASE. Every assertion below is about a row FIRING; if the
    /// resolver returned nothing for a well-formed row they would all pass over
    /// a mechanism that is absent (CLOUD-249's shape).
    #[test]
    fn a_plain_row_resolves_at_all() {
        let got = resolved_env_from(
            &[credential_row("PROBE_TOKEN")],
            Credential::Live,
            &|_| true,
            &env_of(&[("BATTEN_TEST_PAT", "ghp_real")]),
        );
        assert_eq!(
            got,
            vec![(
                "PROBE_TOKEN".to_owned(),
                EnvAction::Set(Secret::new("ghp_real".to_owned()))
            )]
        );
    }

    #[test]
    fn a_placeholder_loses_to_a_real_credential() {
        let got = resolved_env_from(
            &[credential_row("PROBE_TOKEN")],
            Credential::Live,
            &|_| true,
            &env_of(&[
                ("BATTEN_TEST_PAT", "ghp_real"),
                ("PROBE_TOKEN", "proxy-injected"),
            ]),
        );
        assert_eq!(
            got,
            vec![(
                "PROBE_TOKEN".to_owned(),
                EnvAction::Set(Secret::new("ghp_real".to_owned()))
            )],
            "the `proxy-` value must not win the first-set race"
        );
    }

    /// The arm `from_first_set` alone cannot express: no real credential exists,
    /// so the variable must be CLEARED rather than left carrying a marker that
    /// GitHub answers `Bad credentials` to once the fence is up.
    #[test]
    fn a_placeholder_with_no_replacement_is_unset() {
        let got = resolved_env_from(
            &[credential_row("PROBE_TOKEN")],
            Credential::Live,
            &|_| true,
            &env_of(&[("PROBE_TOKEN", "proxy-injected")]),
        );
        assert_eq!(got, vec![("PROBE_TOKEN".to_owned(), EnvAction::Unset)]);
    }

    /// A real credential under a name we do not reject is left ALONE, not
    /// cleared: the row removes markers, never credentials.
    #[test]
    fn an_unrecognised_value_is_kept() {
        let got = resolved_env_from(
            &[credential_row("PROBE_TOKEN")],
            Credential::Live,
            &|_| true,
            &env_of(&[("PROBE_TOKEN", "ghp_somebody_elses")]),
        );
        assert_eq!(
            got,
            vec![(
                "PROBE_TOKEN".to_owned(),
                EnvAction::Set(Secret::new("ghp_somebody_elses".to_owned()))
            )]
        );
    }

    /// EVEN A PLACEHOLDER BEATS NOTHING. With no usable credential the marker is
    /// preferred: proxied it is substituted for one that works, so clearing it
    /// strands the session where keeping it merely scopes it.
    #[test]
    fn an_unusable_credential_keeps_the_placeholder() {
        let got = resolved_env_from(
            &[credential_row("PROBE_TOKEN")],
            Credential::Unusable,
            &|_| true,
            &env_of(&[("PROBE_TOKEN", "proxy-injected")]),
        );
        assert_eq!(
            got,
            vec![(
                "PROBE_TOKEN".to_owned(),
                EnvAction::Set(Secret::new("proxy-injected".to_owned()))
            )],
            "a marker beats an empty variable when nothing replaces it"
        );
    }

    /// A row that prepends `hosts` to `name`, scoped to an interceptor.
    fn bypass_row(name: &str) -> ProvisionEnv {
        ProvisionEnv {
            name: name.to_owned(),
            prepend_list: vec!["forge.example".to_owned()],
            from_first_set: Vec::new(),
            when_trust_names: Some("Interceptor".to_owned()),
            reject_prefix: None,
            unset: false,
        }
    }

    /// THE FENCE OWES A CREDENTIAL (CLOUD-2122). With none proven, the hosts
    /// stay on the proxy, whose own credential answers; with one, they go
    /// direct and ours is respected. The trust scope is held satisfied so the
    /// case decides the credential arm, not this machine's CA bundle.
    #[test]
    fn a_bypass_waits_for_a_live_credential() {
        let env = env_of(&[("NO_PROXY", "localhost")]);
        let row = bypass_row("NO_PROXY");
        assert_eq!(
            resolved_env_from(
                std::slice::from_ref(&row),
                Credential::Unusable,
                &|_| true,
                &env
            ),
            Vec::new(),
            "no credential, no fence"
        );
        assert_eq!(
            resolved_env_from(&[row], Credential::Live, &|_| true, &env),
            vec![(
                "NO_PROXY".to_owned(),
                EnvAction::Set(Secret::new("forge.example,localhost".to_owned()))
            )]
        );
    }

    /// An UNSCOPED list row (`PATH`) is not a bypass and needs no credential.
    #[test]
    fn an_unscoped_list_row_is_not_a_bypass() {
        let mut row = bypass_row("PATH");
        row.when_trust_names = None;
        assert_eq!(
            resolved_env_from(&[row], Credential::Unusable, &|_| true, &env_of(&[])),
            vec![(
                "PATH".to_owned(),
                EnvAction::Set(Secret::new("forge.example".to_owned()))
            )]
        );
    }

    /// The same rule for the proxy: never strip the host's wiring without a
    /// proven replacement, or the session can reach the forge by no route.
    #[test]
    fn an_unusable_credential_keeps_the_proxy() {
        let env = env_of(&[("HTTPS_PROXY", "http://127.0.0.1:1")]);
        assert_eq!(
            resolved_env_from(
                &[unset_row("HTTPS_PROXY")],
                Credential::Unusable,
                &|_| true,
                &env,
            ),
            Vec::new(),
            "a removal with no replacement proven must be skipped"
        );
        assert_eq!(
            resolved_env_from(
                &[unset_row("HTTPS_PROXY")],
                Credential::Live,
                &|_| true,
                &env,
            ),
            vec![("HTTPS_PROXY".to_owned(), EnvAction::Unset)]
        );
    }

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
            backend: Backend::Native,
            name: name.to_owned(),
            version: "1.2.3".to_owned(),
            url: Some("file:///dev/null".to_owned()),
            sha256: Some(sha.to_owned()),
            platforms: BTreeMap::new(),
            unpack: Unpack::None,
            strip: None,
            bin: None,
            binary: "tool".to_owned(),
            link: None,
            env: Vec::new(),
        }
    }

    /// THE DECLARED ENVIRONMENT IS PART OF WHAT IS CACHED (CLOUD-1455's other
    /// half). It reaches the tool only through the launcher's second line, so a
    /// warm cache holding a byte-identical artifact reported `Fresh` after an
    /// `[[provision.env]]` edit, `apply` returned `AlreadyFresh` before reaching
    /// `install`, and the tool kept running with the environment the manifest
    /// used to declare.
    ///
    /// Over `launcher_declares` rather than through `freshness_of`, because the
    /// premise this asserts is the launcher's own bytes — `rust.md`'s rule that a
    /// test must be shown able to fail rather than depending on a condition the
    /// sandbox cannot create.
    #[test]
    fn a_launcher_carrying_another_environment_is_not_fresh() {
        let rule = |name: &str| ProvisionEnv {
            name: name.to_owned(),
            prepend_list: Vec::new(),
            from_first_set: vec![String::from("SOURCE")],
            when_trust_names: None,
            reject_prefix: None,
            unset: false,
        };
        let mut declared = entry("tool", &"a".repeat(64));
        declared.env = vec![rule("TOKEN")];

        let dir = std::env::temp_dir().join(format!("batten-launcher-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let linked = dir.join("tool");
        std::fs::write(
            &linked,
            launcher(&declared, Path::new("/cache/bin/tool")).expect("bytes"),
        )
        .expect("write the launcher");

        assert!(
            launcher_declares(&linked, &declared, Path::new("/cache/bin/tool")),
            "the launcher this entry just wrote carries this entry's environment"
        );

        let mut edited = declared.clone();
        edited.env = vec![rule("OTHER_TOKEN")];
        assert!(
            !launcher_declares(&linked, &edited, Path::new("/cache/bin/tool")),
            "an edited row must reach the tool, and it only can if the cache reports stale"
        );

        // A body that will not parse is the launcher `exec_launcher` refuses and
        // tells the operator to rewrite, so it is stale rather than fresh.
        std::fs::write(&linked, b"#!/x provision-exec\nnot json\n").expect("write a broken one");
        assert!(!launcher_declares(
            &linked,
            &declared,
            Path::new("/cache/bin/tool")
        ));
    }

    /// THE RE-LINK MUST SURVIVE A TARGET THAT IS IN USE, which is what making
    /// the declared environment part of the freshness verdict made reachable.
    ///
    /// **UNIX-ONLY, BECAUSE THE SUBJECT IS.** `ETXTBSY` is a Unix refusal and
    /// the inode this asserts over is a Unix concept — `std::os::unix` does not
    /// exist on the Windows target at all, so a case reaching for it does not
    /// merely fail there, it does not TYPE-CHECK (`cross-check` caught exactly
    /// that). Windows refuses a busy target too and refuses it differently; the
    /// rename-over remedy is what both want, and asserting the Unix mechanism
    /// is honest about which one is being shown.
    ///
    /// `fs::write` truncates in place and the kernel refuses that for a file
    /// some process is EXECUTING — `ETXTBSY`. The thing on `PATH` is exactly
    /// what a session runs, so a busy target is the ORDINARY case here. It was
    /// unreachable while a warm cache always answered `Fresh`: `apply` returned
    /// `AlreadyFresh` before `install`, and the write that would have failed
    /// never happened.
    ///
    /// **THE INODE IS THE ASSERTION, and it is what makes this testable at
    /// all.** This sandbox cannot make a file execute-busy on demand, so
    /// asserting "the write succeeded over a busy target" would assert a
    /// premise that was never created — `rust.md`'s rule. What CAN be pinned is
    /// the property `ETXTBSY` actually needs: the bytes reach a DIFFERENT inode
    /// and are renamed over. An in-place write leaves the target's own inode
    /// holding them, and would fail the moment that inode were busy.
    #[cfg(unix)]
    #[test]
    fn a_relink_replaces_the_target_rather_than_writing_through_it() {
        let rule = |name: &str| ProvisionEnv {
            name: name.to_owned(),
            prepend_list: Vec::new(),
            from_first_set: vec![String::from("SOURCE")],
            when_trust_names: None,
            reject_prefix: None,
            unset: false,
        };
        let mut declared = entry("tool", &"a".repeat(64));
        declared.env = vec![rule("TOKEN")];

        let dir = std::env::temp_dir().join(format!("batten-relink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let dest = dir.display().to_string();
        link_onto_path(&declared, &dest, Path::new("/cache/bin/tool"), &[], None)
            .expect("first link");

        let linked = dir.join("tool");
        let inode = |path: &Path| {
            std::fs::metadata(path)
                .map(|meta| std::os::unix::fs::MetadataExt::ino(&meta))
                .expect("the target has an inode")
        };
        let before = inode(&linked);

        let mut relinked = declared.clone();
        relinked.env = vec![rule("OTHER_TOKEN")];
        link_onto_path(&relinked, &dest, Path::new("/cache/bin/tool"), &[], None)
            .expect("the re-link");
        assert_ne!(
            before,
            inode(&linked),
            "the bytes went through the target's own inode, so a target being \
             executed would have refused them with ETXTBSY"
        );
        assert!(
            launcher_declares(&linked, &relinked, Path::new("/cache/bin/tool")),
            "and the file on PATH carries what the re-link declared"
        );

        // NOTHING IS LEFT BESIDE IT: the directory is on `PATH`, so a surviving
        // staging file is a command a shell would offer.
        let strays: Vec<String> = std::fs::read_dir(&dir)
            .expect("the directory reads")
            .filter_map(std::result::Result::ok)
            .map(|found| found.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "tool")
            .collect();
        assert!(strays.is_empty(), "staging files left behind: {strays:?}");
        let _ = std::fs::remove_dir_all(&dir);
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
                        unpack: None,
                        strip: None,
                        bin: None,
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

    /// This process's own empty directory, reaped once the process is gone, so
    /// two runs of the suite never share a fixture.
    fn scratch(name: &str) -> PathBuf {
        crate::scratch::scratch(&format!("provision-{name}"))
    }

    #[test]
    fn a_report_names_only_its_stale_entries_one_line_each() {
        let status = |name: &str, freshness| EntryStatus {
            name: name.to_owned(),
            version: "1.0".to_owned(),
            freshness,
        };
        let fresh = Report {
            entries: vec![status("a", Freshness::Fresh)],
        };
        assert!(!fresh.any_stale());
        assert!(fresh.stale_lines().is_empty());
        let stale = Report {
            entries: vec![
                status("a", Freshness::Fresh),
                status("b", Freshness::Missing),
            ],
        };
        assert!(stale.any_stale());
        assert_eq!(stale.stale_lines(), vec!["b 1.0 missing".to_owned()]);
    }

    /// CLOUD-2532: from a linked worktree, the probe is declared by the
    /// WORKTREE's `batten.toml`, never the main checkout's. Measured: `land` →
    /// `verify` in a worktree reported `<main checkout>/batten.toml will not
    /// load` over a branch whose own file loaded fine.
    #[test]
    fn the_credential_declaration_in_a_worktree_is_the_worktrees() {
        let dir = scratch("credential-worktree");
        let main = dir.join("main");
        fs::create_dir_all(&main).unwrap();
        crate::gitwrite::init_on_main(&main).unwrap();
        fs::write(main.join("README.md"), "base\n").unwrap();
        crate::gitwrite::commit_paths(&main, &[String::from("README.md")], "base").unwrap();
        // The main checkout's authority will not load at all: an unknown key.
        fs::write(main.join("batten.toml"), "version = 1\nnot_a_key = true\n").unwrap();
        let linked = crate::gitwrite::link_worktree(&main.join(".git"), &main, "own").unwrap();
        fs::write(
            linked.join("batten.toml"),
            "version = 1\n\n[credential]\nprobe_url = \"https://probe.invalid/\"\n",
        )
        .unwrap();
        let nested = linked.join("src");
        fs::create_dir_all(&nested).unwrap();

        let probe = credential_declaration_in(&nested).expect(
            "a worktree whose own batten.toml declares a probe answers with it, \
             not with the main checkout's load failure",
        );
        assert_eq!(probe.probe_url.as_deref(), Some("https://probe.invalid/"));
    }

    /// An artifact fetched over `file://` installs a runnable binary, reads as
    /// fresh, reinstalls from the cache once the binary is gone, and a pin that
    /// does not match is refused rather than installed.
    #[test]
    fn an_artifact_installs_verified_and_reinstalls_from_the_cache() {
        let dir = scratch("apply");
        let artifact = dir.join("tool.sh");
        let body = b"#!/bin/sh\nexit 0\n".to_vec();
        fs::write(&artifact, &body).unwrap();
        let mut entry = entry("tool", &digest(&body));
        entry.url = Some(format!("file://{}", artifact.display()));
        let cache = dir.join("cache");
        let freshness = |entry: &Provision| status(std::slice::from_ref(entry), &cache).unwrap();

        assert_eq!(freshness(&entry).entries[0].freshness, Freshness::Missing);
        assert_eq!(
            apply(&entry, &cache, true, false).unwrap(),
            Applied::Previewed
        );
        assert_eq!(
            apply(&entry, &cache, false, false).unwrap(),
            Applied::Installed
        );
        let binary = entry_dir(&cache, &entry).join(BIN_DIR).join("tool");
        assert_eq!(crate::fsio::read(&binary).unwrap(), body);
        if cfg!(unix) {
            let ran = crate::exec::piped_argv(
                &dir,
                &[binary.to_string_lossy().into_owned()],
                "",
                crate::exec::Diagnostics::Drop,
                &[],
            );
            assert_eq!(ran.map(|(code, _)| code), Some(0), "installed executable");
        }
        assert_eq!(freshness(&entry).entries[0].freshness, Freshness::Fresh);
        assert_eq!(
            apply(&entry, &cache, false, false).unwrap(),
            Applied::AlreadyFresh
        );

        // The binary gone and the network gone: the cached artifact still pins.
        fs::remove_file(&binary).unwrap();
        fs::remove_file(&artifact).unwrap();
        assert_eq!(
            apply(&entry, &cache, false, false).unwrap(),
            Applied::Installed
        );
        assert_eq!(crate::fsio::read(&binary).unwrap(), body);

        // The binary present and the cached artifact gone is a cache miss.
        fs::remove_file(entry_dir(&cache, &entry).join(ARTIFACT)).unwrap();
        assert_eq!(freshness(&entry).entries[0].freshness, Freshness::Missing);

        let mut wrong = entry.clone();
        wrong.sha256 = Some(digest(b"other bytes"));
        fs::write(&artifact, &body).unwrap();
        let cache = dir.join("other-cache");
        let err = apply(&wrong, &cache, false, false).unwrap_err();
        assert!(err.downcast_ref::<crate::Denial>().is_some(), "{err}");
        assert!(
            !entry_dir(&cache, &wrong)
                .join(BIN_DIR)
                .join("tool")
                .exists()
        );
    }

    /// An entry declaring an environment links a LAUNCHER, and the link is part
    /// of freshness: present, naming a live interpreter and carrying the
    /// declared rules, it is fresh; gone, or carrying other rules, it is not.
    #[test]
    fn a_linked_launcher_is_fresh_only_while_it_carries_what_the_entry_declares() {
        let dir = scratch("linked");
        let artifact = dir.join("tool.sh");
        let body = b"#!/bin/sh\nexit 0\n".to_vec();
        fs::write(&artifact, &body).unwrap();
        let mut entry = entry("tool", &digest(&body));
        entry.url = Some(format!("file://{}", artifact.display()));
        let bin = dir.join("bin");
        entry.link = Some(bin.to_string_lossy().into_owned());
        let mut row = unset_row("TOOL_HOME");
        row.unset = false;
        row.prepend_list = vec!["/opt/tool".to_owned()];
        entry.env = vec![row];
        let cache = dir.join("cache");
        let freshness = |entry: &Provision| {
            status(std::slice::from_ref(entry), &cache).unwrap().entries[0].freshness
        };

        assert_eq!(
            apply(&entry, &cache, false, true).unwrap(),
            Applied::Installed
        );
        let linked = bin.join("tool");
        assert!(
            crate::fsio::read_to_string(&linked)
                .unwrap()
                .contains(LAUNCHER_VERB),
            "an entry with an environment links a launcher"
        );
        assert_eq!(freshness(&entry), Freshness::Fresh);

        let mut other = entry.clone();
        other.env[0].prepend_list = vec!["/opt/elsewhere".to_owned()];
        assert_eq!(freshness(&other), Freshness::Missing, "other rules");

        let launcher = crate::fsio::read_to_string(&linked).unwrap();
        let rest = launcher.split_once('\n').unwrap().1;
        fs::write(
            &linked,
            format!("#!/nowhere/batten {LAUNCHER_VERB}\n{rest}"),
        )
        .unwrap();
        assert_eq!(freshness(&entry), Freshness::Missing, "a gone interpreter");

        fs::remove_file(&linked).unwrap();
        assert_eq!(freshness(&entry), Freshness::Missing, "no link");
    }

    /// CLOUD-2210 / CLOUD-2476: an entry with a `link` and NO env rows links a
    /// plain copy, which carries no launcher body. It reads `Fresh` after one
    /// `apply`, and the second `apply` converges to `AlreadyFresh`; a stale
    /// launcher left on that path (env rows since removed) is not fresh.
    ///
    /// Fails by: the launcher check asked of a copy again (never fresh, never
    /// converges), or a leftover launcher read as a fresh copy.
    #[test]
    fn a_linked_copy_with_no_env_is_fresh_and_converges() {
        let dir = scratch("linked-copy");
        let artifact = dir.join("tool.sh");
        let body = b"#!/bin/sh\nexit 0\n".to_vec();
        fs::write(&artifact, &body).unwrap();
        let mut entry = entry("tool", &digest(&body));
        entry.url = Some(format!("file://{}", artifact.display()));
        let bin = dir.join("bin");
        entry.link = Some(bin.to_string_lossy().into_owned());
        let cache = dir.join("cache");
        let freshness = |entry: &Provision| {
            status(std::slice::from_ref(entry), &cache).unwrap().entries[0].freshness
        };

        assert_eq!(
            apply(&entry, &cache, false, true).unwrap(),
            Applied::Installed
        );
        let linked = bin.join("tool");
        assert_eq!(crate::fsio::read(&linked).unwrap(), body, "a plain copy");
        assert_eq!(freshness(&entry), Freshness::Fresh);
        assert_eq!(
            apply(&entry, &cache, false, true).unwrap(),
            Applied::AlreadyFresh,
            "the second apply converges"
        );

        fs::write(
            &linked,
            format!("#!/usr/bin/batten {LAUNCHER_VERB}\n{{}}\n"),
        )
        .unwrap();
        assert_eq!(
            freshness(&entry),
            Freshness::Missing,
            "a leftover launcher on a copy entry's path is stale"
        );
    }

    #[test]
    fn the_binary_is_found_by_file_name_however_the_tarball_nests_it() {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, bytes) in [
            ("tool-1.0/README", &b"read me"[..]),
            ("tool-1.0/tool", b"ELF"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes).unwrap();
        }
        let tarball = builder.into_inner().unwrap().finish().unwrap();
        assert_eq!(extract(&tarball, "tool").unwrap(), b"ELF");
        assert!(extract(&tarball, "other").is_err());
    }

    #[test]
    fn only_a_launcher_invocation_is_launched() {
        let ordinary = ["batten", "status"].map(std::ffi::OsString::from);
        assert!(launched(ordinary.into_iter()).is_none());
        let launcher = [
            std::ffi::OsString::from("batten"),
            std::ffi::OsString::from(LAUNCHER_VERB),
            std::ffi::OsString::from("/nowhere/launcher"),
        ];
        assert!(
            launched(launcher.into_iter()).is_some(),
            "an unreadable launcher fails rather than running batten"
        );
    }

    /// Only a launcher naming a missing interpreter is stale; a plain file, a
    /// present interpreter and another verb are not.
    #[test]
    fn a_launcher_whose_interpreter_is_gone_is_stale() {
        let dir = scratch("relaunch");
        let file = |name: &str, body: String| {
            let path = dir.join(name);
            fs::write(&path, body).unwrap();
            path
        };
        let me = std::env::current_exe().unwrap();
        assert!(relaunches_a_present_interpreter(&file(
            "plain",
            "ELF".to_owned()
        )));
        assert!(relaunches_a_present_interpreter(&file(
            "present",
            format!("#!{} {LAUNCHER_VERB}\n{{}}\n", me.display())
        )));
        assert!(!relaunches_a_present_interpreter(&file(
            "gone",
            format!("#!/nowhere/batten {LAUNCHER_VERB}\n{{}}\n")
        )));
        assert!(relaunches_a_present_interpreter(&file(
            "other-verb",
            "#!/nowhere/batten other\n{}\n".to_owned()
        )));
    }

    /// ISRG Root X2, a public root, whose subject spells `O` as a
    /// `PrintableString` after a `C`.
    const ISRG_ROOT_X2: &str = "-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
";

    #[test]
    fn the_organisation_is_read_from_the_subject_field() {
        let org = "Internet Security Research Group";
        assert_eq!(organisation_of(ISRG_ROOT_X2).as_deref(), Some(org));
        assert!(organisation_of("not a certificate").is_none());
        let bundle = format!("{ISRG_ROOT_X2}\n{ISRG_ROOT_X2}");
        assert!(bundle_names(&bundle, org));
        assert!(!bundle_names(&bundle, "Some Other Authority"));
    }

    /// The host's own bundle answers for an organisation it carries and not
    /// for one it does not; an unreadable bundle answers for nothing.
    #[test]
    fn the_host_bundle_names_what_it_carries_and_nothing_else() {
        assert!(!trust_names("no authority is named this"));
        let named = TRUST_BUNDLE_VARS.iter().find_map(std::env::var_os);
        assert_eq!(
            trust_bundle(),
            named.map_or_else(|| PathBuf::from(SYSTEM_TRUST_BUNDLE), PathBuf::from),
            "a variable that is set decides, else the system store"
        );
        match crate::fsio::read_to_string(trust_bundle()) {
            Ok(text) => {
                let carried = text
                    .split_inclusive(PEM_FOOTER)
                    .find_map(|block| organisation_of(block.trim_start()));
                assert_eq!(
                    carried.as_deref().is_some_and(trust_names),
                    carried.is_some()
                );
            }
            Err(_) => assert!(!trust_names("Internet Security Research Group")),
        }
    }

    /// A fresh receipt answers without a probe, live or not.
    #[test]
    fn a_fresh_credential_receipt_answers_without_a_probe() {
        // Per process, so an overlapping run of this suite in the same checkout
        // files its receipt under another digest rather than racing this one.
        let credential = format!("batten-provision-test-credential-{}", std::process::id());
        let value = Secret::new(credential.clone());
        let receipt = credential_receipt_path(&value).expect("tests run inside a checkout");
        assert!(receipt.ends_with(format!("credential.{}", digest(credential.as_bytes()))));
        fs::create_dir_all(receipt.parent().unwrap()).unwrap();
        let probe = "https://batten-provision-test.invalid/";
        fs::write(&receipt, "live\n").unwrap();
        assert!(credential_usable(&value, probe));
        fs::write(&receipt, "unusable\n").unwrap();
        assert!(!credential_usable(&value, probe));
        let _ = fs::remove_file(&receipt);
    }

    /// A receipt exactly [`CREDENTIAL_MAX_AGE`] old has aged out: the verdict is
    /// re-proved, and a probe nobody can reach is not usable whatever the
    /// receipt said.
    ///
    /// Fails by: the age compared with `<=`, so a `live` receipt is trusted for
    /// one second past its bound.
    #[test]
    fn a_credential_receipt_at_its_age_bound_is_proved_again() {
        let credential = format!("batten-provision-test-aged-{}", std::process::id());
        let value = Secret::new(credential);
        let receipt = credential_receipt_path(&value).expect("tests run inside a checkout");
        fs::create_dir_all(receipt.parent().unwrap()).unwrap();
        fs::write(&receipt, "live\n").unwrap();
        let aged =
            std::time::SystemTime::now() - std::time::Duration::from_secs(CREDENTIAL_MAX_AGE);
        fs::File::options()
            .write(true)
            .open(&receipt)
            .unwrap()
            .set_modified(aged)
            .unwrap();
        let usable = credential_usable(&value, "https://batten-provision-test.invalid/");
        let _ = fs::remove_file(&receipt);
        assert!(!usable, "an aged-out receipt is not believed");
    }

    #[test]
    fn every_credential_verdict_says_which_failure_it_is() {
        let whys = [
            Verdict::Live,
            Verdict::Refused,
            Verdict::RouteSubstitutes,
            Verdict::Unreachable,
            Verdict::NoProbe("the reason".to_owned()),
        ]
        .map(|verdict| verdict.why());
        assert_eq!(whys[0], "the session credential authenticated");
        assert_eq!(
            whys[1],
            "a declared session credential did not authenticate"
        );
        assert!(whys[2].starts_with("the route to the credential probe answers"));
        assert_eq!(whys[3], "the credential probe could not be reached");
        assert_eq!(whys[4], "no credential probe could be resolved: the reason");
    }

    /// Each env row shape the loader refuses, and each it accepts.
    #[test]
    fn an_env_row_is_exactly_one_rule_for_one_variable() {
        type Change<'a> = &'a dyn Fn(&mut ProvisionEnv);
        let mut list = unset_row("A");
        list.unset = false;
        list.prepend_list = vec!["/x".to_owned()];
        let mut sourced = unset_row("A");
        sourced.unset = false;
        sourced.from_first_set = vec!["B".to_owned()];
        let with = |row: &ProvisionEnv, change: &dyn Fn(&mut ProvisionEnv)| {
            let mut row = row.clone();
            change(&mut row);
            let mut entry = entry("tool", &"a".repeat(64));
            entry.env = vec![row];
            validate_env(&entry)
        };
        for accepted in [&unset_row("A"), &list, &sourced, &credential_row("A")] {
            assert!(with(accepted, &|_| {}).is_ok(), "{accepted:?}");
        }
        let refused: [(&ProvisionEnv, Change); 7] = [
            (&unset_row("A"), &|row| {
                row.prepend_list = vec!["/x".to_owned()];
            }),
            (&unset_row("A"), &|row| {
                row.from_first_set = vec!["B".to_owned()];
            }),
            (&unset_row("A"), &|row| {
                row.reject_prefix = Some("p".to_owned());
            }),
            (&list, &|row| row.reject_prefix = Some("p".to_owned())),
            (&list, &|row| row.from_first_set = vec!["B".to_owned()]),
            (&list, &|row| row.prepend_list.clear()),
            (&list, &|row| row.name = " ".to_owned()),
        ];
        for (row, change) in refused {
            assert!(with(row, change).is_err(), "{row:?}");
        }
        let mut blank = entry("tool", &"a".repeat(64));
        blank.url = Some("  ".to_owned());
        assert!(validate(&[blank]).is_err(), "an empty url is refused");
    }

    /// The control arm's three answers, one transport each: a route that
    /// refuses the known-bad token honours credentials, one that accepts it
    /// substitutes its own, and one nothing reaches decides neither.
    #[test]
    fn the_control_arm_reads_refused_substituted_and_unreachable_apart() {
        let real = Secret::new("tok_0123456789".to_owned());
        let probe = "https://forge.invalid/probe";
        let refusing: DirectGet = |_, _| Ok(response(401));
        let accepting: DirectGet = |_, _| Ok(response(200));
        let unreachable: DirectGet = |_, _| anyhow::bail!("connection refused");
        assert_eq!(
            route_honours_credentials(probe, &real, refusing),
            Some(true)
        );
        assert_eq!(
            route_honours_credentials(probe, &real, accepting),
            Some(false)
        );
        assert_eq!(route_honours_credentials(probe, &real, unreachable), None);
    }

    /// A component a strip may drop is a normal one or `.`; nothing is left
    /// when the strip takes every one.
    #[test]
    fn a_strip_drops_leading_components_and_refuses_a_climb() {
        assert_eq!(
            stripped(Path::new("./tool/bin/x"), 1).unwrap(),
            Some(PathBuf::from("bin/x"))
        );
        assert_eq!(stripped(Path::new("tool"), 1).unwrap(), None);
        assert!(stripped(Path::new("../x"), 0).is_err());
    }

    /// A link stays inside while its `..` never climbs above the tree root.
    #[test]
    fn a_link_is_inside_while_it_never_climbs_past_the_root() {
        if !cfg!(unix) {
            return;
        }
        assert!(lexically_inside(Path::new("a"), Path::new("../b")));
        assert!(!lexically_inside(Path::new("a"), Path::new("../../b")));
        assert!(lexically_inside(Path::new(""), Path::new("./x")));
        assert!(lexically_inside(Path::new("a"), Path::new("x/../../y")));
        assert!(!lexically_inside(Path::new("a/b"), Path::new("/etc")));
    }

    /// An entry is written with the mode its archive gave it, the declared
    /// binary always executable; a later entry replaces a link rather than
    /// writing through it; an in-tree link is made.
    #[test]
    fn an_entry_is_placed_with_its_mode_and_never_through_a_link() {
        if !cfg!(unix) {
            return;
        }
        let tree = crate::scratch::scratch("provision-place");
        let bin = Path::new("bin/tool");
        let mode = |path: &str| mode_of(&tree.join(path));
        let put = |raw: &str, kind: Kind, body: &[u8]| {
            place(&tree, 0, bin, Path::new(raw), kind, &mut &body[..]).unwrap();
        };
        put("bin/tool", Kind::File { executable: false }, b"t");
        put("lib/data", Kind::File { executable: false }, b"d");
        put("lib/run", Kind::File { executable: true }, b"r");
        assert_eq!(mode("bin/tool"), 0o755, "the declared binary");
        assert_eq!(mode("lib/data"), 0o644);
        assert_eq!(mode("lib/run"), 0o755);
        put("lib/link", Kind::Symlink(PathBuf::from("data")), b"");
        assert_eq!(
            fs::read_link(tree.join("lib/link")).unwrap(),
            Path::new("data")
        );
        put("lib/link", Kind::File { executable: false }, b"new");
        assert!(
            !fs::symlink_metadata(tree.join("lib/link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(tree.join("lib/data")).unwrap(),
            b"d",
            "not written through"
        );
    }

    /// A file's permission bits; `0` off unix, whose cases return before
    /// they read one.
    fn mode_of(path: &Path) -> u32 {
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        };
        #[cfg(not(unix))]
        let mode = {
            let _ = path;
            0
        };
        mode
    }

    fn tarball(entries: &[(&str, tar::EntryType, u32, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, kind, mode, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    /// A tar entry is executable only where its mode says so, and an entry
    /// that is neither a file, a directory nor a link is refused.
    #[test]
    fn a_tar_tree_keeps_each_mode_and_refuses_a_device() {
        if !cfg!(unix) {
            return;
        }
        let tree = crate::scratch::scratch("provision-tar-tree");
        let subtree = Subtree {
            strip: 0,
            bin: PathBuf::from("bin/tool"),
        };
        let bytes = tarball(&[
            ("bin/tool", tar::EntryType::Regular, 0o644, b"t"),
            ("lib/run", tar::EntryType::Regular, 0o755, b"r"),
            ("lib/data", tar::EntryType::Regular, 0o644, b"d"),
        ]);
        extract_tree_tar(&bytes, &tree, &subtree).unwrap();
        let mode = |path: &str| mode_of(&tree.join(path));
        assert_eq!((mode("lib/run"), mode("lib/data")), (0o755, 0o644));
        let fifo = tarball(&[("lib/pipe", tar::EntryType::Fifo, 0o644, b"")]);
        assert!(extract_tree_tar(&fifo, &tree, &subtree).is_err());
    }

    #[test]
    fn a_zip_tree_keeps_each_mode() {
        if !cfg!(unix) {
            return;
        }
        let tree = crate::scratch::scratch("provision-zip-tree");
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, mode) in [("lib/run", 0o755), ("lib/data", 0o644)] {
            let options = zip::write::SimpleFileOptions::default().unix_permissions(mode);
            writer.start_file(path, options).unwrap();
            std::io::Write::write_all(&mut writer, b"x").unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        let subtree = Subtree {
            strip: 0,
            bin: PathBuf::from("bin/tool"),
        };
        extract_tree_zip(&bytes, &tree, &subtree).unwrap();
        let mode = |path: &str| mode_of(&tree.join(path));
        assert_eq!((mode("lib/run"), mode("lib/data")), (0o755, 0o644));
    }

    /// A launcher is a file whose `#!` line ends in the launcher verb.
    #[test]
    fn a_launcher_is_known_by_the_verb_its_shebang_ends_in() {
        let dir = crate::scratch::scratch("provision-is-launcher");
        let file = |name: &str, body: &str| {
            let path = dir.join(name);
            fs::write(&path, body).unwrap();
            path
        };
        let verb = format!("#!/opt/batten {LAUNCHER_VERB}\nexec tool\n");
        assert!(is_a_launcher(&file("launcher", &verb)));
        assert!(!is_a_launcher(&file("other", "#!/opt/batten other\n")));
        assert!(!is_a_launcher(&file("shell", "#!/bin/sh\n")));
        assert!(!is_a_launcher(&dir.join("missing")));
    }

    /// A `bin` is a relative path with no `..`: blank, absolute or climbing
    /// is refused, each on its own.
    #[test]
    fn a_subtree_bin_is_a_relative_path_inside_the_archive() {
        let with_bin = |bin: &str| Provision {
            unpack: Unpack::TarGz,
            bin: Some(bin.to_owned()),
            ..entry("tool", "0")
        };
        assert!(validate_subtree(&with_bin("bin/tool")).is_ok());
        for bin in [" ", "/opt/tool", "bin/../../tool"] {
            assert!(validate_subtree(&with_bin(bin)).is_err(), "{bin:?}");
        }
    }
}

// The launcher and probe suite over the compiled binary: its subprocess cases
// reach the credential verdicts and the HTTPS fetch no unit case can.
