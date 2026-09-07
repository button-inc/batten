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
use crate::secret::Secret;

/// The subdirectory of the repository's out-of-tree state that holds provisioned
/// tools.
const CACHE_DIR: &str = "provision";

/// The file the exact fetched bytes are stored under, so freshness re-verifies
/// the pin against the artifact rather than against a note about it.
const ARTIFACT: &str = "artifact";

/// The subdirectory the unpacked binary lands in.
const BIN_DIR: &str = "bin";

/// Which resolver a [`Provision`] row is turned into a cached binary by
/// (CLOUD-970).
///
/// **One variant today, and that is the deliverable rather than a placeholder.**
/// The indirection is what makes a second resolver a row rather than a branch;
/// a real second backend is the row that proves it was worth having, and landing
/// one here would be two changes wearing one commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Backend {
    /// Fetch a pinned URL, verify its SHA-256, unpack it, place the binary.
    ///
    /// The behaviour every committed row already has, named so it can be one of
    /// several rather than the only thing a row can mean.
    #[default]
    Native,
}

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
    /// Which resolver turns this row into a cached binary (CLOUD-970).
    ///
    /// **The row names what it wants; a backend resolves it.** Every entry was
    /// implicitly one resolver — fetch a URL, verify a checksum, unpack, place a
    /// binary — and that shape is right but was not named, so a second one could
    /// not be added without a compatibility branch beside every read of `url`.
    /// mise's answer to the same problem is the backend (`ubi:`, `aqua:`,
    /// `cargo:`), and it is the pinned toolchain here, so this is adopting prior
    /// art rather than expanding the core.
    ///
    /// **Absent is [`Backend::Native`], which is what makes this additive.** Every
    /// committed row keeps its meaning and its bytes; `expand → migrate →
    /// contract` needs no migrate step when the expansion has a default that IS
    /// the old behaviour. An unknown backend is a load-time config error naming
    /// it — never a silent skip, which is the direction a row that resolved to
    /// nothing would fail in.
    ///
    /// Non-negotiable rule 1 draws the boundary: the backend VOCABULARY is
    /// generic and lives here, while which backend a consumer picks and what it
    /// resolves lives in that consumer's `batten.toml`.
    #[serde(default)]
    pub backend: Backend,
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
    /// A directory to ALSO place the binary in, so it reaches `PATH`.
    ///
    /// Absent for every entry batten invokes itself: the cache path is resolved
    /// in-process, so `ripsecrets` needs no `PATH` presence and putting it there
    /// would widen what a consumer's shell can reach for no gain.
    ///
    /// **It exists for the bootstrap case, which is the one entry the cache
    /// cannot serve** (CLOUD-1389). The container's Setup script is one line
    /// that installs batten, so batten is the first thing present and the task
    /// runner is not — and every gate in this repository is a `mise run`. A
    /// runner resolved only inside batten's own process is unreachable from the
    /// session handlers, the git hooks and the agent's own shell, all of which
    /// invoke it by bare name.
    ///
    /// `~` is expanded, and nothing else is: no `$VAR`, no `$(…)`, no glob. The
    /// same bound [`crate::startup::Startup::check`] states for argv, and for
    /// the same reason — an operator reads the declared path and that is the
    /// path. A relative value is refused at load rather than resolved against
    /// whatever directory the process happens to be in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Environment this tool needs in its OWN process before it will work.
    ///
    /// **This is not `[env]` one layer over, and the difference is the whole
    /// reason the key exists** (CLOUD-1455). A task runner applies its own `[env]`
    /// to what it SPAWNS; its own resolver — the HTTP client that fetches what it
    /// is being asked to install — reads the process environment it was started
    /// with, and nothing a manifest says can reach back and change that. Measured
    /// 2026-09-05, the same cold install of one pinned tool, the bypass declared
    /// two ways: through the runner's `[env]` the install 403s, and with the same
    /// two variables in the process environment it succeeds.
    ///
    /// So the environment has to be applied by whatever LAUNCHES the tool, which
    /// is what this field is read by — [`link_onto_path`] for everything that
    /// resolves the tool by bare name, and [`crate::rules::spawn_resolving`]'s
    /// pinned rung for batten's own spawns. Both, because a row that fixed only
    /// one would leave the other silently unfixed.
    ///
    /// Empty for every entry that needs nothing, which is the ordinary case: an
    /// entry declaring no rows is copied onto `PATH` exactly as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<ProvisionEnv>,
}

/// One variable a provisioned tool's launcher sets, and how its value is found.
///
/// **Both spellings are DERIVED rather than literal, and that is deliberate.** A
/// literal value would be wrong twice over here: the two things this exists to
/// carry are a proxy exemption list, which must be added to whatever the host
/// already exempts rather than replacing it, and a credential, which must never
/// be written into a tracked file at all. Neither is expressible as a constant,
/// so the row declares the RULE and the launcher resolves it against the
/// environment it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = serde_json::json!([
    { "required": ["prepend_list"], "not": { "required": ["from_first_set"] } },
    { "required": ["from_first_set"], "not": { "required": ["prepend_list"] } },
    { "required": ["unset"], "not": { "anyOf": [
        { "required": ["prepend_list"] },
        { "required": ["from_first_set"] },
        { "required": ["reject_prefix"] }
    ] } }
])))]
pub struct ProvisionEnv {
    /// The variable to set.
    pub name: String,
    /// Entries to add to the front of a comma-separated list, keeping whatever
    /// the host already had and adding nothing twice.
    ///
    /// Idempotent by construction: an entry already present is not added again,
    /// so a launcher that runs a launcher does not grow the value without bound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prepend_list: Vec<String>,
    /// Set from the first of these variables that is set and non-empty.
    ///
    /// A list rather than one name because the fallback is the point: the same
    /// tool wants a session credential where one exists and the runner's own
    /// where it does not, and a row naming one would be dead in whichever
    /// environment does not have it. **Nothing is written when none is set** —
    /// an empty credential is refused by some tools and accepted as anonymous by
    /// others, and inventing one is a claim this row cannot make.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_first_set: Vec<String>,
    /// Apply this row only where the host's trust bundle carries a certificate
    /// authority whose subject names this ORGANISATION.
    ///
    /// **This is what keeps a bypass from being applied to somebody's working
    /// proxy.** A row without it applies everywhere, which is right for a row
    /// that only ever adds a credential; it is wrong for one that routes traffic
    /// around a proxy, because a proxy is a legitimate part of most networks and
    /// the only one worth going around is one that refuses by policy what it was
    /// asked to carry.
    ///
    /// The condition is the CA rather than the proxy variables, and the
    /// difference is the whole reason the field is spelled this way. Every
    /// intercepting environment sets those variables, so keying on them would
    /// refuse to honour a real proxy the moment somebody configured one. Keying
    /// on the authority in the trust path names the specific interceptor and
    /// goes false the day those variables point at a CA the operator chose.
    ///
    /// Measured 2026-09-05 in this sandbox: the bundle those variables name
    /// carries five interception authorities, presenting three different common
    /// names across the direct and proxied paths, and the ORGANISATION is the
    /// only field common to all five — so a row matching a common name would
    /// silently miss whichever path the author did not test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_trust_names: Option<String>,
    /// Treat a candidate whose value starts with this as if it were not set.
    ///
    /// **A FAST PATH, NEVER THE DECISION.** The authority on whether a
    /// credential is usable is [`Credential`], which is measured against the
    /// forge; this is a cheap syntactic hint that lets an obvious marker lose
    /// without spending a probe on it. A host that stops prefixing its
    /// placeholder tomorrow — which this one can, without warning — degrades to
    /// the measurement rather than to a wrong answer, because the probe is what
    /// actually decides (CLOUD-1569).
    ///
    /// **A placeholder is not a weak credential, it is a MARKER**, and the
    /// difference decides the verdict. This container injects `GITHUB_TOKEN`
    /// and `GH_TOKEN` carrying a literal `proxy-` prefix: proxied, the value
    /// never reaches GitHub because the proxy substitutes its own; fenced, it is
    /// sent verbatim and GitHub answers `Bad credentials`. So `from_first_set`
    /// alone cannot express the intent — the placeholder IS set and IS
    /// non-empty, so it wins the first-set race against nothing (CLOUD-1569).
    ///
    /// Applied to every candidate, including the row's own name where it appears
    /// in the list, which is what lets one row say "prefer a real credential,
    /// and if there is none, leave nothing behind rather than a marker".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_prefix: Option<String>,
    /// Remove the variable from the launched environment entirely.
    ///
    /// **Unset is not "set to empty", and only unset is honest here.** An empty
    /// `HTTPS_PROXY` is read by some clients as "no proxy" and by others as a
    /// malformed URL, and an empty credential is refused by some tools and taken
    /// as anonymous by others — so writing one is a claim this row cannot make.
    /// The distinction already exists one field up, where `from_first_set`
    /// resolving to nothing writes nothing.
    ///
    /// Pair it with `when_trust_names`: clearing a proxy variable is right in a
    /// container whose egress is intercepted by an authority the row names, and
    /// wrong on a machine whose proxy somebody configured deliberately.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unset: bool,
}

/// How a credential is proved usable, declared by the consumer.
///
/// **One field, and the control credential is NOT one of them.** A caller does
/// not get to choose what "known bad" means: the engine sends a syntactically
/// plausible token that must be refused, because a consumer that could name it
/// could name one the route happens to accept and turn the control arm into a
/// rubber stamp.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialProbe {
    /// The endpoint that answers 2xx for a good credential and refuses a bad
    /// one.
    ///
    /// It must be a route the fence sends DIRECT. Pointed at one an intercepting
    /// proxy carries, the control arm fails — the junk credential is accepted —
    /// and the engine reports could-not-look rather than pretending to a verdict
    /// it cannot reach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    /// The variables a session credential may arrive under, most specific first.
    ///
    /// **Declared here rather than listed in the engine, which is non-negotiable
    /// rule 1.** It was two GitHub-shaped literals in `crates/batten` for one
    /// commit, and a consumer on another forge — or on a host that injects under
    /// a third name — has neither: every candidate is then absent,
    /// [`credential_health`] answers [`Credential::Unusable`], and every removal
    /// is silently skipped forever. That failure is INVISIBLE, because skipping
    /// a removal is also the correct behaviour when a credential is genuinely
    /// bad, so the dead path and the working path look identical from outside.
    ///
    /// Which names belong here is a judgement only the consumer can make. A host
    /// may inject a substitutable placeholder under the forge's conventional
    /// names, so probing those would measure the host's credential rather than
    /// one we hold — the exact conflation this mechanism exists to undo, and the
    /// reason this list is deliberately not "every variable that looks like a
    /// token". Naming none is could-not-look, not health: it authorises nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

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
    if let Some(dest) = entry.link.as_deref() {
        let linked = expand_home(dest)?.join(&entry.binary);
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
        if !launcher_declares(&linked, entry) {
            return Ok(Freshness::Missing);
        }
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

    // THE CACHED ARTIFACT IS TRIED BEFORE THE NETWORK, and only when it still
    // matches the pin. The case this serves is a stale entry whose staleness is
    // the LINK rather than the bytes: the artifact on disk is the pinned one, so
    // re-downloading it to copy it two directories over is a fetch that cannot
    // change the answer. Verified against the pin here exactly as a fresh fetch
    // is, so a tampered cache is a mismatch rather than a shortcut past the
    // checksum.
    let artifact = entry.artifact()?;
    if let Some(bytes) = cached_artifact_matching_pin(entry, cache_root, &artifact.sha256) {
        install(entry, cache_root, &bytes)?;
        return Ok(Applied::Installed);
    }
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
    let cached = bin_dir.join(&entry.binary);
    // **STAGED AND RENAMED, NEVER WRITTEN IN PLACE** (CLOUD-1586), which is
    // [`link_onto_path`]'s discipline applied to the site that needed it just as
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
    // Keyed on the pid and dot-prefixed for `link_onto_path`'s reasons exactly —
    // two provisions running at once must not write each other's staging file.
    let staged = bin_dir.join(format!(".{}.{}.tmp", entry.binary, std::process::id()));
    let written = fs::write(&staged, &binary)
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
    if let Some(dest) = entry.link.as_deref() {
        link_onto_path(entry, dest, &cached, &binary)?;
    }
    // The artifact is written last, so a crash between the two leaves the entry
    // reading `missing` rather than `fresh` — the direction that re-applies.
    fs::write(dir.join(ARTIFACT), bytes).context("write the cached artifact")?;
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
    let bytes = fs::read(entry_dir(cache_root, entry).join(ARTIFACT)).ok()?;
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
fn link_onto_path(entry: &Provision, dest: &str, cached: &Path, binary: &[u8]) -> Result<()> {
    let dir = expand_home(dest)?;
    fs::create_dir_all(&dir).context("create the linked binary's directory")?;
    let path = dir.join(&entry.binary);
    // Keyed on the PID so two provisions running at once cannot write each
    // other's staging file, and dot-prefixed so a directory listing of `PATH`
    // does not offer it as a command.
    let staged = dir.join(format!(".{}.{}.tmp", entry.binary, std::process::id()));
    let written = if entry.env.is_empty() {
        fs::write(&staged, binary).context("write the linked binary")
    } else {
        launcher(entry, cached)
            .and_then(|bytes| fs::write(&staged, bytes).context("write the linked launcher"))
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
    let Ok(bytes) = fs::read(linked) else {
        // Unreadable is not this predicate's finding: the `is_file` check above
        // already answered presence, and a read failure here is a permissions or
        // races question that re-linking would not fix.
        return true;
    };
    let Some(first) = bytes.split(|byte| *byte == b'\n').next() else {
        return true;
    };
    let Ok(line) = std::str::from_utf8(first) else {
        return true;
    };
    let Some(shebang) = line.strip_prefix("#!") else {
        return true;
    };
    match shebang.rsplit_once(' ') {
        Some((interpreter, verb)) if verb == LAUNCHER_VERB => Path::new(interpreter).is_file(),
        _ => true,
    }
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
fn launcher_declares(linked: &Path, entry: &Provision) -> bool {
    let Ok(bytes) = fs::read(linked) else {
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
    carried.get("env") == Some(&declared)
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
    let bytes = fs::read(script).with_context(|| {
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
    // A VARIABLE THAT IS SET DECIDES WHICH BUNDLE, EVEN IF IT CANNOT BE READ.
    // Falling through to the system store when the named file is missing would
    // answer this question about a bundle the operator did not choose — and in an
    // intercepting sandbox the system store carries the interceptor too, so the
    // fallback would resurrect the bypass exactly where the operator had pointed
    // the tool somewhere else. The system path is for a host that names none.
    let bundle = TRUST_BUNDLE_VARS
        .iter()
        .find_map(std::env::var_os)
        .map_or_else(|| PathBuf::from(SYSTEM_TRUST_BUNDLE), PathBuf::from);
    let Ok(text) = fs::read_to_string(&bundle) else {
        return false;
    };
    // Split on the PEM footer rather than feeding the whole file: a bundle is a
    // concatenation, and the parser takes one document at a time.
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
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|name| name.0.iter())
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
    let root = crate::git::repo_root(&cwd)
        .map_err(|err| format!("{} is in no repository: {err}", cwd.display()))?;
    // The FILE, not the directory. `load` takes a path to `batten.toml`, and
    // handing it the root read as `Is a directory (os error 21)` — swallowed by
    // the `.ok()` chain this function used to be, and reported to the operator
    // as "no probe declared" over a repository whose `[credential]` table was
    // right there.
    let at = root.join(crate::config::CONFIG_FILE);
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
        && let Ok(body) = std::fs::read_to_string(&receipt)
    {
        return body.starts_with("live");
    }
    // ORDER IS THE WHOLE DESIGN: establish the route can REFUSE before believing
    // that it accepted. Reversed, a substituting route reports every credential
    // live — including one that has been revoked.
    let verdict = match route_honours_credentials(probe, value) {
        // Nobody could reach it. The reason is already on stderr.
        None => Verdict::Unreachable,
        // The route answered for a token that cannot be this credential, so it
        // is answering with an identity of its own and nothing it says about
        // ours is evidence.
        Some(false) => Verdict::RouteSubstitutes,
        Some(true) => match probe_credential(probe, value) {
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
    let _ = std::fs::write(&receipt, if live { "live\n" } else { "unusable\n" });
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
fn credential_health() -> Credential {
    let declaration = match credential_declaration() {
        Ok(declaration) => declaration,
        // No declared table is could-not-look, not health. Reading it as healthy
        // would authorise stripping the host's wiring on a consumer that never
        // said how to check.
        Err(why) => {
            crate::config::report(&Verdict::NoProbe(why).why());
            return Credential::Unusable;
        }
    };
    let Some(probe) = declaration.probe_url.as_deref() else {
        crate::config::report(
            &Verdict::NoProbe("no `[credential] probe_url` is declared".to_owned()).why(),
        );
        return Credential::Unusable;
    };
    if declaration.names.is_empty() {
        crate::config::report(
            &Verdict::NoProbe(
                "`[credential] names` is empty, so there is no variable to look in".to_owned(),
            )
            .why(),
        );
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
fn route_honours_credentials(probe: &str, real: &Secret) -> Option<bool> {
    match probe_credential(probe, &known_bad_like(real)) {
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
fn probe_credential(probe: &str, token: &Secret) -> Look {
    // `expose` at the LAST possible moment and into a value that goes straight
    // to the wire. `Call`'s own `Debug` redacts this header, so the credential
    // is out of the type for exactly the length of one request build.
    let headers = [(
        "Authorization".to_owned(),
        format!("Bearer {}", token.expose()),
    )];
    match crate::fetch::get_direct(probe, &headers) {
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
        .any(|rule| rule.unset || rule.reject_prefix.is_some())
    {
        credential_health()
    } else {
        Credential::Unusable
    };
    // Into a `Secret` at the READ. The launcher's environment is mostly
    // credentials, so the type starts at the boundary rather than being put on
    // afterwards — a value that is a `String` for three lines is a value three
    // lines can print.
    resolved_env_from(rules, credential, &|name| {
        std::env::var(name).ok().map(Secret::new)
    })
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
        .filter(|rule| rule.when_trust_names.as_deref().is_none_or(trust_names))
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
                // variable, and this is the arm that keeps it.
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
    validate_env(entry)
}

/// The `prepend_list`-versus-`from_first_set` xor on every `[[provision.env]]` row.
///
/// Refused at LOAD, on the same argument the artifact xor above is: a row
/// spelling neither sets nothing, and a launcher that silently sets nothing is
/// byte-identical to one that was never written — which is the failure this whole
/// field exists to end rather than to reproduce one layer down. A row spelling
/// both would have two rules for one variable and no stated precedence.
fn validate_env(entry: &Provision) -> Result<()> {
    for rule in &entry.env {
        if rule.name.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: an `[[provision.env]]` row must name a variable",
                entry.name
            )));
        }
        // A REMOVAL IS THE THIRD SHAPE, and it is the one the "declares nothing"
        // arm below would otherwise refuse. `unset` states an outcome rather
        // than a source, so it is complete on its own and pairing it with a
        // source would be two rules for one variable with no order between them
        // — the same fault the first arm names (CLOUD-1569).
        if rule.unset {
            if !rule.prepend_list.is_empty() || !rule.from_first_set.is_empty() {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares `unset` beside a source; a row \
                     either removes the variable or decides its value, and one \
                     carrying both says nothing about which wins",
                    entry.name, rule.name
                )));
            }
            if rule.reject_prefix.is_some() {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares `unset` beside `reject_prefix`; \
                     the prefix filters CANDIDATES, and a row that keeps none has \
                     nothing to filter",
                    entry.name, rule.name
                )));
            }
            continue;
        }
        if rule.reject_prefix.is_some() && rule.from_first_set.is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: env {} declares `reject_prefix` with no \
                 `from_first_set`; the prefix decides which CANDIDATE is real, so a \
                 row with no candidates applies it to nothing",
                entry.name, rule.name
            )));
        }
        match (rule.prepend_list.is_empty(), rule.from_first_set.is_empty()) {
            (false, false) => {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares both `prepend_list` and \
                     `from_first_set`; exactly one, or two rules decide one variable \
                     with no stated order between them",
                    entry.name, rule.name
                )));
            }
            (true, true) => {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares neither `prepend_list`, \
                     `from_first_set` nor `unset`, so it would set nothing — and a \
                     launcher that sets nothing cannot be told from one that was \
                     never written",
                    entry.name, rule.name
                )));
            }
            _ => {}
        }
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

    /// The same rule for the proxy: never strip the host's wiring without a
    /// proven replacement, or the session can reach the forge by no route.
    #[test]
    fn an_unusable_credential_keeps_the_proxy() {
        let env = env_of(&[("HTTPS_PROXY", "http://127.0.0.1:1")]);
        assert_eq!(
            resolved_env_from(&[unset_row("HTTPS_PROXY")], Credential::Unusable, &env,),
            Vec::new(),
            "a removal with no replacement proven must be skipped"
        );
        assert_eq!(
            resolved_env_from(&[unset_row("HTTPS_PROXY")], Credential::Live, &env,),
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
            launcher_declares(&linked, &declared),
            "the launcher this entry just wrote carries this entry's environment"
        );

        let mut edited = declared.clone();
        edited.env = vec![rule("OTHER_TOKEN")];
        assert!(
            !launcher_declares(&linked, &edited),
            "an edited row must reach the tool, and it only can if the cache reports stale"
        );

        // A body that will not parse is the launcher `exec_launcher` refuses and
        // tells the operator to rewrite, so it is stale rather than fresh.
        std::fs::write(&linked, b"#!/x provision-exec\nnot json\n").expect("write a broken one");
        assert!(!launcher_declares(&linked, &declared));
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
        link_onto_path(&declared, &dest, Path::new("/cache/bin/tool"), &[]).expect("first link");

        let linked = dir.join("tool");
        let inode = |path: &Path| {
            std::fs::metadata(path)
                .map(|meta| std::os::unix::fs::MetadataExt::ino(&meta))
                .expect("the target has an inode")
        };
        let before = inode(&linked);

        let mut relinked = declared.clone();
        relinked.env = vec![rule("OTHER_TOKEN")];
        link_onto_path(&relinked, &dest, Path::new("/cache/bin/tool"), &[]).expect("the re-link");
        assert_ne!(
            before,
            inode(&linked),
            "the bytes went through the target's own inode, so a target being \
             executed would have refused them with ETXTBSY"
        );
        assert!(
            launcher_declares(&linked, &relinked),
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
