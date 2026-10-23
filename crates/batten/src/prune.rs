//! The `[prune]` table and the superseded pass (CLOUD-766, CLOUD-1030, CLOUD-2198).
//!
//! # What it reclaims, and what it deliberately will not
//!
//! Cargo keys every artifact on a metadata hash and never reclaims a superseded
//! one. A `land` lap rebases, which mints a new SHA, which changes the hash,
//! which writes a fresh copy of every integration-test binary while all previous
//! copies stay. Growth is monotonic and nothing bounded it. Measured 2026-08-20:
//! `target/` 26 GB, 283 files over 40 MB under `deps` totalling 16.6 GB, ~41
//! distinct stems retaining 6 copies each, 13.2 GB reclaimable at no rebuild
//! cost.
//!
//! **This is not `cargo clean`, and the distinction is the whole task.** The rule
//! is *keep what the next build will read, delete what it will not*. `keep` is 2
//! rather than 1: the newest artifact per stem is what the current build reads,
//! the one before it is what a rebase that reverts would otherwise rebuild.
//!
//! # The group key is `(stem, kind, unit identity)`
//!
//! CLOUD-1157 and CLOUD-1975. The extension must not collapse into the stem, or
//! one group of `.rlib` and `.rmeta` under `keep = 2` can delete the live `.rlib`;
//! and a stem is not an identity, or the third live unit of a name is evicted
//! every lap. See [`UNIT_IDENTITY`].
//!
//! # No floor (CLOUD-2198)
//!
//! This module used to refuse below a measured disk floor — warm and cold, a
//! ratchet over a lap journal, a basis count, and a tiered escalation that
//! dropped `incremental` first. Each lap close escalated and dropped the build it
//! had just paid for (CLOUD-2192). That model is retired: below `[prune]
//! min_free_mb` the collector ([`crate::collect`]) removes superseded units, then
//! least-recently-used ones, until `max_free_mb` is free — on every mediated
//! call, throughout `land` and `mutate sweep`, and on demand through `batten
//! target prune`. What stays here is the table, the superseded pass the
//! collector runs first, the build-lock claim, and the free-space reader.
//!
//! # The effect class
//!
//! `Effect::Destructive` on the verb — what it removes is recoverable only by
//! re-running the work. Pointer-only per non-negotiable rule 4: counts and
//! bytes, never a path listing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;

/// The `[prune]` table: the build tree, what to keep, and the collector's band.
///
/// CONSUMER CONFIG, NOT A CONST (non-negotiable rule 1): which directory a
/// project builds into and how much free space its builds need are facts about
/// THAT project.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prune {
    /// The build directory, relative to the repository root.
    #[serde(default = "default_root")]
    pub root: String,
    /// Copies retained per stem. See the module header for why this is 2.
    ///
    /// The bound is in the SCHEMA as well as in [`Prune::validate`] (raised on
    /// #734): an editor validating against the published schema is the surface
    /// most consumers meet first.
    #[serde(default = "default_keep")]
    #[schemars(range(min = 1))]
    pub keep: usize,
    /// RETIRED (CLOUD-2198): the warm floor. Read and ignored, so a config
    /// written for the floor model still loads while its pin moves; the
    /// collector's band ([`Prune::min_free_mb`]) replaces it.
    #[serde(default, skip_serializing)]
    pub warm: Option<serde_json::Value>,
    /// RETIRED (CLOUD-2198): the cold floor. Read and ignored, as `warm`.
    #[serde(default, skip_serializing)]
    pub cold: Option<serde_json::Value>,
    /// RETIRED (CLOUD-2198): the escalation's regrowable roots. Read and
    /// ignored, as `warm`: the collector never drops a cache whole.
    #[serde(default, skip_serializing)]
    pub regrowable: Option<serde_json::Value>,
    /// Below this much free space, in MB, the disk collector runs (CLOUD-2197):
    /// on every mediated call, and throughout `land` and `mutate sweep`. Nix's
    /// `min-free`. Declared with [`Prune::max_free_mb`] or not at all; absent,
    /// the collector runs at [`DEFAULT_FREE_BAND`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_free_mb: Option<u64>,
    /// Once triggered, the collector frees space until this much is free, in
    /// MB, then stops. Nix's `max-free`; above [`Prune::min_free_mb`], so the
    /// pair is a hysteresis band rather than a threshold that re-fires at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_free_mb: Option<u64>,
}

/// The band a `[prune]` table declaring none collects at, `(min_free_mb,
/// max_free_mb)`: measured on #1132 (2026-10-12), each targeted build consumed
/// 2.6-4.3 GB, so 4096 MB is one build's room and 8192 MB one build of headroom
/// after a collection.
pub const DEFAULT_FREE_BAND: (u64, u64) = (4096, 8192);

fn default_root() -> String {
    String::from("target")
}

const fn default_keep() -> usize {
    2
}

//MUTANT default-band-off|s@            _ => Some(DEFAULT_FREE_BAND),@            _ => None,@|an_undeclared_band_collects_at_the_default
impl Prune {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// `keep = 0`, which deletes the artifact the next build reads, and a band
    /// that is half-declared or has no width.
    pub fn validate(&self) -> Result<()> {
        if self.keep == 0 {
            return Err(UsageError::raise(
                "[prune]: `keep = 0` deletes the artifact the next build reads, which is a clean rather than a prune",
            ));
        }
        match (self.min_free_mb, self.max_free_mb) {
            (None, None) => {}
            (Some(min), Some(max)) if max > min => {}
            (Some(min), Some(max)) => {
                return Err(UsageError::raise(format!(
                    "[prune]: `max_free_mb` ({max}) is not above `min_free_mb` ({min}) — the collector frees space until `max_free_mb` is free once it falls below `min_free_mb`, so a band with no width re-fires on the next call"
                )));
            }
            _ => {
                return Err(UsageError::raise(
                    "[prune]: `min_free_mb` and `max_free_mb` are declared together or not at all — one without the other is a trigger with no stop, or a stop with no trigger",
                ));
            }
        }
        Ok(())
    }

    /// The collector's band (CLOUD-2197): the declared one, or
    /// [`DEFAULT_FREE_BAND`] where `[prune]` declares none.
    ///
    /// **ON BY DEFAULT, because off was measured to fail.** A declared band is
    /// a key the pinned release must read, so a branch carrying the collector
    /// had to hold the keys until a release shipped them — and with them held
    /// the collector it carried never armed, and that branch's own `verify`
    /// filled the disk (2026-10-13, #1132). The band belongs to the code that
    /// collects, so the code carries it; the keys only move it.
    #[must_use]
    pub const fn free_band(&self) -> Option<(u64, u64)> {
        match (self.min_free_mb, self.max_free_mb) {
            (Some(min), Some(max)) => Some((min, max)),
            _ => Some(DEFAULT_FREE_BAND),
        }
    }
}

/// The seam a suite needs to set free space exactly as it sets the tree.
///
/// CLOUD-778, and it is the root override's twin: free space is an INPUT to the
/// floor decision, so without this a suite claims a hermeticity it does not have
/// and every case asserting a successful run is answered by how full the host's
/// disk happens to be. Measured twice — once as a case that flipped across two
/// readings minutes apart with no fixture change, once as nine cases going red in
/// CI at a single floor change.
///
/// **A COMMA-SEPARATED SEQUENCE, not one number, and CLOUD-1030 is why.** A run
/// reads free space up to twice — once before the escalation and once after it —
/// and the whole defect being repaired lives in the gap between those two
/// readings. A single-valued seam makes the second reading equal the first, which
/// is a fixture in which the escalation reclaims nothing: the discriminating case
/// (a lap that clears the warm floor only BECAUSE the reclaim ran, and is then
/// judged against the cold one) is not expressible at all. So the value is the
/// readings this run will see, in order, and the last one repeats — which keeps
/// every single-valued caller meaning exactly what it meant before.
const FREE_MB_VAR: &str = "TARGET_PRUNE_FREE_MB";

/// The free-space readings one run takes, in the order it takes them.
///
/// A struct rather than a function called twice, because "how many readings have
/// been taken" is state, and the only honest place for it is the run that takes
/// them. A thread-local counter would be the same state one scope wider, where a
/// second run in the same process inherits it.
struct Readings {
    /// The declared sequence, or `None` where the volume is the authority.
    declared: Option<Vec<u64>>,
    /// How many readings this run has already taken.
    taken: usize,
}

impl Readings {
    /// Read the declaration, or defer to the volume.
    fn declare() -> Result<Self> {
        let Ok(raw) = std::env::var(FREE_MB_VAR) else {
            return Ok(Readings {
                declared: None,
                taken: 0,
            });
        };
        let declared = raw
            .split(',')
            .map(|field| {
                field.trim().parse::<u64>().with_context(|| {
                    format!("target-prune: {FREE_MB_VAR} is not a comma-separated list of numbers")
                })
            })
            .collect::<Result<Vec<u64>>>()?;
        if declared.is_empty() {
            bail!("target-prune: {FREE_MB_VAR} declares no reading");
        }
        Ok(Readings {
            declared: Some(declared),
            taken: 0,
        })
    }

    /// The next reading, in megabytes.
    fn take(&mut self, path: &Path) -> Result<u64> {
        let Some(declared) = self.declared.as_ref() else {
            return available_megabytes(path);
        };
        // The last reading REPEATS rather than running out. A sequence shorter
        // than the run is a fixture that said "the number stops moving here",
        // which is what a single value has always meant; an error would make
        // every existing one-value caller depend on the reading count.
        let index = self.taken.min(declared.len() - 1);
        self.taken += 1;
        Ok(declared[index])
    }
}

/// Remove every superseded artifact under the root's `deps` directories.
///
/// ONLY UNDER `deps`, and only names cargo hashed. Everything else in the build
/// tree is either a cache that regrows — so deleting it costs the work that wrote
/// it — or a live artifact addressed by a stable name.
///
/// Which kinds are in scope is [`RECLAIMED_KINDS`], and the retention is per kind:
/// see the module header for why the extension cannot collapse into the stem.
///
/// **AN ARTIFACT AND ITS FINGERPRINT GO TOGETHER** (CLOUD-1913). "Superseded" is
/// newest-mtime per `(stem, kind)`, and that is not always a generation: one crate
/// can have several CURRENT variants — two locked versions, the check profile
/// clippy builds beside the test profile, a normal and a build dependency — and
/// cargo never rewrites an artifact it reuses, so a long-lived current variant
/// carries the oldest mtime in its group. Deleting it alone left cargo's
/// `.fingerprint/<crate>-<hash>` behind, still claiming the unit fresh, and the
/// next compile that depended on it failed: `extern location for bstr does not
/// exist`, measured on three of four landing laps in a row, each straight after a
/// lap-open prune.
///
/// Removing the fingerprint with the artifact turns that failure into a rebuild of
/// one unit, which is the cost the prune already accepts for anything it reclaims.
/// It does not try to tell current from stale: cargo keeps every generation's
/// fingerprint, so "has a fingerprint" would mark everything live and reclaim
/// nothing, which is CLOUD-766's disk exhaustion back.
//MUTANT-SUITE crates/batten/tests/it/target_prune.rs
//MUTANT examples-never-pruned|s@\.chain(examples)@.chain(Vec::<PathBuf>::new())@|superseded_example_generations_are_reclaimed_like_deps
pub(crate) fn reclaim_superseded(root: &Path, keep: usize) -> (usize, u64) {
    let mut pruned = 0;
    let mut bytes = 0;
    // `examples` BESIDE `deps` (CLOUD-2047). cargo writes an example target's
    // hashed generations there, `.dwo` sets included, and records each under the
    // same `.fingerprint/<pkg>-<hash>`, so the one pass applies unchanged — and
    // without it every lap that rebuilt the crate left one more generation of
    // every bench: 56 units for 4 examples, 1,082 MB, measured 2026-09-30. Only an
    // `examples` whose parent is a profile (it carries `.fingerprint`) is a cargo
    // output; the name alone is one a fixture under `target/` could spell.
    let examples: Vec<PathBuf> = directories_named(root, "examples")
        .into_iter()
        .filter(|dir| {
            dir.parent()
                .is_some_and(|profile| profile.join(".fingerprint").is_dir())
        })
        .collect();
    for deps in directories_named(root, "deps").into_iter().chain(examples) {
        let Ok(_building) = claim(root, &deps) else {
            continue;
        };
        let fingerprints = deps.parent().map(|profile| profile.join(".fingerprint"));
        for victims in superseded_in(&deps, keep).values() {
            for victim in victims {
                let size = victim.metadata().map_or(0, |meta| meta.len());
                if std::fs::remove_file(victim).is_ok() {
                    pruned += 1;
                    bytes += size;
                    if let Some(fingerprints) = &fingerprints {
                        forget_fingerprint(fingerprints, victim);
                    }
                }
            }
        }
        // AFTER the superseded pass, so a unit it just forgot sheds its debuginfo
        // in the same lap rather than the next one (CLOUD-1293).
        if let Some(fingerprints) = &fingerprints {
            let (orphans, orphan_bytes) = reclaim_orphaned_debuginfo(&deps, fingerprints);
            pruned += orphans;
            bytes += orphan_bytes;
        }
        let (stale, stale_bytes) = reclaim_superseded_debuginfo(&deps);
        pruned += stale;
        bytes += stale_bytes;
    }
    (pruned, bytes)
}

/// Remove every `.dwo` in `deps` whose owning unit has no fingerprint (CLOUD-1293).
///
/// `[profile.dev] split-debuginfo = "unpacked"` moves debuginfo out of the linked
/// binary into `<crate>-<hash>.<cgu>.rcgu.dwo` files beside it, and
/// [`RECLAIMED_KINDS`] is closed, so nothing ever removed them: the superseded
/// pass reclaimed a unit's artifact and fingerprint and left its `.dwo` set
/// behind. Measured 2026-09-29: 48,692 of them, 7,498 MB, every one belonging to
/// a unit whose fingerprint was already gone — the residue that refused the day's
/// lap closes at 83–520 MB under the warm floor.
///
/// **BY OWNERSHIP, NOT BY KIND.** A `.dwo` is never grouped or retained by mtime:
/// it names its owner's hash, and the owner's liveness is already decided by
/// whether `.fingerprint/<crate>-<hash>` exists — the same token
/// [`forget_fingerprint`] matches on. A live unit keeps its fingerprint for as
/// long as the caller's `claim` holds the directory, so this never reaches one.
///
/// Could-not-look reclaims NOTHING: an unreadable fingerprint directory would
/// otherwise read as "no unit is live" and take every `.dwo` in the tree.
///
/// **EVERY HASHED ARTIFACT, NOT ONLY `.dwo`** (2026-10-14). A unit collected by
/// fingerprint left its artifacts behind whenever they did not index to it:
/// measured on #1132, `target/debug/deps` held two `libbatten-<hash>.rlib` of
/// ~300 MB each from two days earlier with no fingerprint naming either, and
/// 875 MB of such residue across two profiles while the collector was taking
/// live units to find space. cargo addresses an artifact only through its
/// fingerprint's hash, so one no fingerprint names is unreachable: removing it
/// costs no rebuild.
fn reclaim_orphaned_debuginfo(deps: &Path, fingerprints: &Path) -> (usize, u64) {
    let Ok(entries) = std::fs::read_dir(fingerprints) else {
        return (0, 0);
    };
    let live: std::collections::BTreeSet<String> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            name.rsplit_once('-').map(|(_, hash)| hash.to_owned())
        })
        .collect();
    let Ok(files) = std::fs::read_dir(deps) else {
        return (0, 0);
    };
    let mut removed = 0;
    let mut bytes = 0;
    for entry in files.flatten() {
        // A FILE BY ITS OWN TYPE, never through a link, for `superseded_in`'s reason.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let name = entry.file_name();
        let Some(hash) = name
            .to_str()
            .and_then(|name| dwo_owner_hash(name).or_else(|| artifact_hash(name)))
        else {
            continue;
        };
        if !live.contains(hash) {
            let size = entry.metadata().map_or(0, |meta| meta.len());
            if std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
                bytes += size;
            }
        }
    }
    (removed, bytes)
}

/// Remove every `.dwo` in `deps` that its LIVE owner's current artifacts no
/// longer name (CLOUD-2105).
///
/// [`reclaim_orphaned_debuginfo`] reaches a unit only once its fingerprint is
/// gone. A live unit rebuilt incrementally gets fresh codegen-unit names on every
/// build, so each rebuild left one more full `.dwo` set beside the current one.
/// Measured 2026-10-03, straight after a lap-close prune: 5,210 MB of 7,786 MB in
/// `target/debug/deps` was `.dwo`, and `batten-74d53bfe8b80e4a5` alone had 8,960
/// files across 9.7 hours while its rlib named exactly 256, all present. That
/// growth put lap close under the warm floor, and the escalation then took
/// `perf*` and `semver*` whole.
///
/// **THE ARTIFACT IS THE AUTHORITY.** An rlib's object members and a linked
/// binary's skeleton units carry each `.dwo` they read by name, so the owner's
/// own `lib<owner>.rlib`, `lib<owner>.so`, `<owner>` and `<owner>.exe` name its
/// live set exactly. An owner with no readable artifact, or whose artifacts name
/// none, keeps every `.dwo`: could-not-look reclaims nothing.
fn reclaim_superseded_debuginfo(deps: &Path) -> (usize, u64) {
    let Ok(files) = std::fs::read_dir(deps) else {
        return (0, 0);
    };
    let mut by_owner: std::collections::BTreeMap<String, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    for entry in files.flatten() {
        // A FILE BY ITS OWN TYPE, never through a link, for `superseded_in`'s reason.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(owner) = name
            .strip_suffix(".dwo")
            .and_then(|stem| stem.split('.').next())
        else {
            continue;
        };
        if artifact_hash(owner).is_none() {
            continue;
        }
        by_owner
            .entry(owner.to_owned())
            .or_default()
            .push(entry.path());
    }
    let mut removed = 0;
    let mut bytes = 0;
    for (owner, debuginfo) in by_owner {
        let named = named_debuginfo(deps, &owner);
        if named.is_empty() {
            continue;
        }
        for dwo in debuginfo {
            let current = dwo
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| named.contains(name));
            if current {
                continue;
            }
            let size = dwo.metadata().map_or(0, |meta| meta.len());
            if std::fs::remove_file(&dwo).is_ok() {
                removed += 1;
                bytes += size;
            }
        }
    }
    (removed, bytes)
}

/// Every `<owner>.….rcgu.dwo` name `owner`'s own artifacts in `deps` carry.
//MUTANT superseded-dwo-kept|s@^            named.extend(@            let _ = (@|a_live_units_superseded_dwo_are_reclaimed_and_its_current_set_kept
fn named_debuginfo(deps: &Path, owner: &str) -> std::collections::BTreeSet<String> {
    let mut named = std::collections::BTreeSet::new();
    let Ok(pattern) = regex::bytes::Regex::new(&format!(
        r"{}\.[A-Za-z0-9_.\-]+?\.rcgu\.dwo",
        regex::escape(owner)
    )) else {
        return named;
    };
    for artifact in [
        format!("lib{owner}.rlib"),
        format!("lib{owner}.so"),
        owner.to_owned(),
        format!("{owner}.exe"),
    ] {
        let path = deps.join(artifact);
        if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
            continue;
        }
        if let Ok(contents) = std::fs::read(&path) {
            named.extend(
                pattern
                    .find_iter(&contents)
                    .filter_map(|found| std::str::from_utf8(found.as_bytes()).ok())
                    .map(str::to_owned),
            );
        }
    }
    named
}

/// The owning unit's hash of a split-debuginfo file: `batten-<hash>.<cgu>.rcgu.dwo`
/// is owned by `batten-<hash>`, read by [`artifact_hash`] so the two parses agree.
fn dwo_owner_hash(name: &str) -> Option<&str> {
    let owner = name.strip_suffix(".dwo")?.split('.').next()?;
    artifact_hash(owner)
}

/// Remove the `.fingerprint/<crate>-<hash>` entry for a reclaimed artifact.
///
/// Matched on the HASH, because the fingerprint directory is named for the
/// package (`sha1-checked`) and the artifact for the crate (`libsha1_checked`),
/// and the hash is the one token both carry. Could-not-look is a no-op: an
/// unreadable directory leaves the fingerprint, which is the state before this
/// function existed rather than a new failure.
fn forget_fingerprint(fingerprints: &Path, victim: &Path) {
    let Some(hash) = victim
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(artifact_hash)
    else {
        return;
    };
    let suffix = format!("-{hash}");
    let Ok(entries) = std::fs::read_dir(fingerprints) else {
        return;
    };
    for entry in entries.flatten() {
        let named_for_it = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(&suffix));
        // A DIRECTORY BY ITS OWN TYPE, never through a link, for `superseded_in`'s
        // reason: removing through a link deletes something outside this tree.
        if named_for_it && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The artifact kinds the superseded pass groups, beside the extension-less one.
///
/// A CLOSED LIST rather than "every extension", and that is the safety property:
/// an unrecognised name is invisible to the pass instead of becoming a group of
/// its own, so a file class nobody has reasoned about is never a deletion
/// candidate. `.d` is deliberately absent — 2.8 MB across 666 files, measured,
/// which is below the noise of everything this reclaims.
const RECLAIMED_KINDS: &[&str] = &["rlib", "rmeta", "so"];

/// The fingerprint fields that say WHICH cargo unit an artifact is (CLOUD-1975).
///
/// A stem is not an identity. `hashbrown` resolves at four versions here, and
/// one crate is built under several profiles at once (a check unit beside a
/// build unit, dev-feature unification, host beside target), and every one of
/// those is live — so grouping by stem alone evicted the third live unit of a
/// name on every lap and cargo rebuilt it on the next.
///
/// `path` separates versions; `profile`, `features` and `compile_kind` separate
/// units that coexist. `rustc`, `rustflags` and `config` are LEFT OUT: a
/// toolchain or flag change is a real new generation of the same unit, and
/// keying on it would leave the old toolchain's output unreclaimable. `local` and
/// `deps` are left out because they are what changes between generations.
//MUTANT-SUITE crates/batten/tests/it/target_prune.rs
//MUTANT supersede-key-drops-path|s@"target", "path", "profile",@"target", "profile",@|three_versions_of_one_crate_all_survive
//MUTANT supersede-key-drops-profile|s@"path", "profile", "features",@"path", "features",@|two_profiles_of_one_crate_both_survive
const UNIT_IDENTITY: &[&str] = &["target", "path", "profile", "features", "compile_kind"];

/// Every unit identity recorded under a profile's `.fingerprint`, by hash.
///
/// ONE WALK PER `deps` DIRECTORY, never one per artifact: a lookup per artifact
/// would re-read the whole fingerprint tree for each of thousands of files.
/// Keyed on the hash suffix for [`forget_fingerprint`]'s reason — the directory
/// carries the package name and the artifact the crate name.
///
/// A directory whose document is absent or unparseable has no entry, and its
/// artifacts keep the stem grouping: cargo cannot reuse an artifact whose
/// fingerprint is unreadable, so it is dead weight, never a unit to protect.
fn unit_identities(fingerprints: &Path) -> BTreeMap<String, String> {
    let mut identities = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(fingerprints) else {
        return identities;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((_, hash)) = name.rsplit_once('-') else {
            continue;
        };
        if let Some(identity) = unit_identity(&entry.path()) {
            identities.insert(hash.to_owned(), identity);
        }
    }
    identities
}

/// The [`UNIT_IDENTITY`] fields of one fingerprint directory's document.
///
/// The document is the directory's `*.json` whose name is not `dep-*`; where
/// there are several, the first by name, so the answer is a function of the
/// directory rather than of `read_dir`'s order.
fn unit_identity(dir: &Path) -> Option<String> {
    let mut documents: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "json")
                && !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dep-"))
        })
        .collect();
    documents.sort();
    let text = std::fs::read_to_string(documents.first()?).ok()?;
    let document: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(
        UNIT_IDENTITY
            .iter()
            .map(|field| {
                document
                    .get(field)
                    .map_or_else(String::new, ToString::to_string)
            })
            .collect::<Vec<_>>()
            .join("\u{1f}"),
    )
}

/// Files grouped by `(stem, kind, unit identity)`, each group holding only what
/// is past `keep`.
///
/// The identity is empty for an artifact with no readable fingerprint, which
/// leaves it grouped by stem exactly as before CLOUD-1975.
///
/// Sorted newest-first by mtime, so the tail is what the next build will not
/// read.
fn superseded_in(deps: &Path, keep: usize) -> BTreeMap<(String, String, String), Vec<PathBuf>> {
    let mut by_key: BTreeMap<(String, String, String), Vec<(std::time::SystemTime, PathBuf)>> =
        BTreeMap::new();
    let identities = deps
        .parent()
        .map(|profile| unit_identities(&profile.join(".fingerprint")))
        .unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(deps) else {
        return BTreeMap::new();
    };
    for entry in entries.flatten() {
        // A REGULAR FILE BY THE ENTRY'S OWN TYPE, never through a link. `find
        // -type f` did not follow either, and removing a link because its target
        // looks superseded deletes something that is not in this tree at all.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((stem, kind)) = artifact_key(name) else {
            continue;
        };
        // THE EXECUTABLE BIT NOW GATES ONE CLASS RATHER THAN ALL OF THEM. For an
        // extension-less name it is the only signal that the file is an artifact
        // and not somebody's scratch, so it stays; for `.rlib`/`.rmeta` the
        // extension already carries that, and requiring the bit there is what
        // made the whole class unreachable while reading as a safety check.
        if kind.is_empty() && !is_executable(&meta) {
            continue;
        }
        let identity = artifact_hash(name)
            .and_then(|hash| identities.get(hash))
            .cloned()
            .unwrap_or_default();
        by_key
            .entry((stem.to_owned(), kind.to_owned(), identity))
            .or_default()
            .push((meta.modified().unwrap_or(std::time::UNIX_EPOCH), path));
    }

    by_key
        .into_iter()
        .map(|(key, mut copies)| {
            copies.sort_by_key(|copy| std::cmp::Reverse(copy.0));
            (
                key,
                copies
                    .into_iter()
                    .skip(keep)
                    .map(|(_, path)| path)
                    .collect(),
            )
        })
        .collect()
}

/// `(stem, kind)` for a name cargo hashed, or `None` where it is not one.
///
/// The kind is stripped BEFORE the hash test and then carried, which is the whole
/// of CLOUD-1157's first half: `libbatten-42061777d57a0311.rlib` otherwise splits
/// to a "hash" of `42061777d57a0311.rlib`, fails on the `.`, and becomes its own
/// stem. An extension-less name has kind `""`.
///
/// `None` rather than "its own stem" for anything else, and the two are not the
/// same claim even though a group of one is never past `keep` today: `None` says
/// this file is not a hashed artifact, which stays true if `keep` ever reaches 0
/// through some other route.
fn artifact_key(name: &str) -> Option<(&str, &str)> {
    split_artifact(name).map(|(stem, _hash, kind)| (stem, kind))
}

/// The metadata hash cargo gave an artifact, by the same parse [`artifact_key`]
/// groups on, so the two cannot disagree about what a name's hash is.
fn artifact_hash(name: &str) -> Option<&str> {
    split_artifact(name).map(|(_stem, hash, _kind)| hash)
}

/// `(stem, hash, kind)` for a name cargo hashed: the one parse both readers use.
fn split_artifact(name: &str) -> Option<(&str, &str, &str)> {
    let (head, kind) = match name.rsplit_once('.') {
        Some((head, kind)) if RECLAIMED_KINDS.contains(&kind) => (head, kind),
        // A KNOWN-SHAPE NAME THIS PASS DOES NOT RECLAIM, `.d` above all. Falling
        // through to the hash test instead would read `cli-aaaaaaaaaaaa.d` as an
        // unhashed name and — under any future rule that grouped those — put a
        // depfile in a deletion candidate's group.
        Some(_) => return None,
        None => (name, ""),
    };
    let (stem, hash) = head.rsplit_once('-')?;
    // A SUFFIX THAT MERELY CONTAINS A DASH MUST NOT BE EATEN, or two unrelated
    // binaries collapse into one group and the newer one deletes the older.
    if hash.len() >= 8 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        Some((stem, hash, kind))
    } else {
        None
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    // No executable bit to read. The stem grouping and the retention still hold,
    // so the pass is correct here and merely wider than on unix.
    true
}

/// Free space for a reader that samples again and again (CLOUD-1937): the volume,
/// or the declared `TARGET_PRUNE_FREE_MB` sequence in order with the last
/// repeating — so a fixture that pins free space for the prune pins it for the
/// lap's disk arm too, rather than letting the arm read the machine's own disk.
///
/// # Errors
///
/// A `TARGET_PRUNE_FREE_MB` that is not a comma-separated list of numbers.
pub fn sampler(path: PathBuf) -> Result<impl FnMut() -> Result<u64> + Send> {
    let mut readings = Readings::declare()?;
    Ok(move || readings.take(&path))
}

/// The committed `[prune]` table in `dir`, read ALONE, or `None` when it cannot
/// be (CLOUD-843).
///
/// # The fallback the task body used to spell in shell
///
/// A consumer's config gains keys between releases, so the binary on `PATH` is
/// routinely older than the table it is asked to read — and `Config` is
/// `deny_unknown_fields`, so that binary refuses the WHOLE file over a key that
/// has nothing to do with reclaiming disk. The retired `target-prune` body
/// answered that by falling through to `cargo run`, which is a build: the one
/// thing this verb exists to make room for, spent on the input that most needs
/// the room. Measured over one session, `protected_readers`, `[prune.cold.basis]`
/// and a new `[[recorder]]` variant each killed a lap that way.
///
/// So the reclaim reads the one table it needs. What stays strict is the table
/// itself: [`Prune`] is `deny_unknown_fields` too, so a `[prune]` key this build
/// predates still refuses rather than being half-understood, and the floors are
/// validated exactly as a whole-file load would validate them.
///
/// **The committed file, never a layered view.** `[prune]` is authority-only, so
/// there is no override for this read to miss.
//MUTANT-SUITE crates/batten/src/prune.rs
//MUTANT prune-table-alone-unread|s@    let declared = table.get("prune")?.as_table()?;@    let declared = table.get("prune-unread")?.as_table()?;@|a_config_this_build_outran_still_yields_its_prune_table
//MUTANT prune-table-alone-unvalidated|s@    prune.validate().ok()?;@    let _ = prune.validate();@|a_prune_table_that_fails_validation_is_not_read_alone
#[must_use]
pub fn declared_alone(dir: &Path) -> Option<Prune> {
    let text = std::fs::read_to_string(dir.join(crate::config::CONFIG_FILE)).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let declared = table.get("prune")?.as_table()?;
    let prune: Prune = toml::from_str(&toml::to_string(declared).ok()?).ok()?;
    prune.validate().ok()?;
    Some(prune)
}

/// The lock cargo holds on a profile directory for the whole of a build.
const BUILD_LOCK: &str = ".cargo-lock";

/// Take the build lock of every profile `path` sits in or holds, or `None` if a
/// build holds any of them.
///
/// **A RUNNING BUILD'S TREE IS NEVER RECLAIMED** (CLOUD-1913). `verify` runs
/// clippy beside `test:bats`, whose `provision:startup` can repair a stale hook
/// binary through `build:release`, which runs this prune first. Measured: the
/// warm tier `remove_dir_all`ed `target/clippy` — a nested build tree — while
/// clippy compiled into it, and clippy failed on `couldn't create a temp dir` in
/// its own `deps/`. The earlier `extern location … does not exist` failures were
/// the same race over a shared `deps/`.
///
/// The guards are HELD ACROSS THE REMOVAL, not just probed: a probe that let go
/// before deleting would leave a build free to start in the gap. Cargo takes the
/// same lock blocking, so a build starting mid-reclaim waits, then finds a tree
/// that is simply colder. A lock that cannot be opened is no lock at all — a tree
/// cargo never built into, which is exactly what the pass already handled.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT reclaim-under-held-lock|s@^            Err(std::fs::TryLockError::WouldBlock) => return Err(profile.join(BUILD_LOCK)),$@            Err(std::fs::TryLockError::WouldBlock) => {}@|a_tree_a_build_holds_is_never_collected
pub(crate) fn claim(root: &Path, path: &Path) -> Result<Vec<std::fs::File>, PathBuf> {
    let enclosing = path.ancestors().take_while(|dir| dir.starts_with(root));
    let nested = PROFILE_DIRS.iter().map(|profile| path.join(profile));
    let mut held = Vec::new();
    for profile in enclosing.map(Path::to_path_buf).chain(nested) {
        let Ok(lock) = std::fs::File::open(profile.join(BUILD_LOCK)) else {
            continue;
        };
        match lock.try_lock() {
            Ok(()) => held.push(lock),
            Err(std::fs::TryLockError::WouldBlock) => return Err(profile.join(BUILD_LOCK)),
            // An error that is not contention says nothing about a build, and
            // refusing on it would let one unreadable lock wedge every reclaim.
            Err(std::fs::TryLockError::Error(_)) => {}
        }
    }
    Ok(held)
}

/// The profile directories cargo lays down inside any build tree.
///
/// Their presence one level in is what makes a directory a build tree rather
/// than something a consumer happened to put under `target/`, and their names at
/// the top level are what makes `target/debug` the HOST's rather than a nested
/// one.
const PROFILE_DIRS: [&str; 2] = ["debug", "release"];

/// Whether a directory entry's own name satisfies a declared one.
///
/// A SINGLE TRAILING `*` IS THE WHOLE WILDCARD LANGUAGE, and `Prune::validate`
/// refuses every other spelling at load rather than here — an unmatched pattern
/// and a refused one are indistinguishable at this depth, and the caller of this
/// function is about to run `remove_dir_all`.
fn name_matches(candidate: &std::ffi::OsStr, declared: &str) -> bool {
    match declared.strip_suffix('*') {
        // `to_str` and not a lossy compare: a name this platform cannot render as
        // UTF-8 is not one a `[prune]` row spelled, and treating it as a match
        // would widen a prefix past what its author could have written.
        Some(prefix) => candidate
            .to_str()
            .is_some_and(|name| name.starts_with(prefix)),
        None => candidate == declared,
    }
}

/// Every directory under `root` matching this declared name, not descending into
/// a match.
///
/// A SYMLINK IS NEVER A DIRECTORY HERE, and that is the whole of this function's
/// safety. `entry.file_type()` comes from the directory entry itself and does not
/// follow, where `Path::is_dir` does — so a link under the build tree pointing at
/// somebody's home directory would otherwise be descended into and, for the
/// escalation, handed to `remove_dir_all`. The predecessor was safe by accident
/// of its instrument (`find -type d` does not follow without `-L`); the port made
/// it a decision, and review caught the window between the two on #734.
pub(crate) fn directories_named(root: &Path, name: &str) -> Vec<PathBuf> {
    directories_named_outside(root, name, &[])
}

/// [`directories_named`], never descending into a directory one of
/// `shielded` names.
fn directories_named_outside(root: &Path, name: &str, shielded: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            let entry_name = entry.file_name();
            if name_matches(&entry_name, name) {
                found.push(path);
                continue;
            }
            if shielded
                .iter()
                .any(|other| name_matches(&entry_name, other))
            {
                continue;
            }
            stack.push(path);
        }
    }
    found
}

/// Free space in MiB, the reading `df -Pm`'s "Available" column gave: the
/// space an unprivileged writer can use, not the filesystem's raw free count.
/// In-process through `fs4` (`statvfs` / `GetDiskFreeSpaceExW`), which was
/// already a dependency, rather than spawning `df` (CLOUD-1924) — and it answers
/// on every platform, where the spawn answered on unix alone.
fn available_megabytes(path: &Path) -> Result<u64> {
    fs4::available_space(path).map(mebibytes).with_context(|| {
        format!(
            "target-prune: could not read free space for {}",
            path.display()
        )
    })
}

/// Whole MiB in `bytes`, a partial one dropped.
const fn mebibytes(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The volume a suite is writing to has room for more than the one MiB a
    /// constant reading would claim.
    ///
    /// Fails by: a constant 0 or 1 MiB reading in place of the volume's.
    #[test]
    fn free_space_is_read_off_the_volume() {
        let Ok(read) = available_megabytes(&std::env::temp_dir()) else {
            panic!("the scratch volume answers");
        };
        assert!(read > 1, "{read} MiB");
    }

    // --- the derived nested build trees (CLOUD-1240) -------------------------
    //
    // `unwrap` and `expect` are denied under `src/`, so the fixtures panic
    // explicitly. A setup failure is still a loud failure; what it is not is a
    // lint waiver this module does not otherwise need.

    fn mkdir(path: &Path) {
        if let Err(why) = std::fs::create_dir_all(path) {
            panic!("fixture: could not create {}: {why}", path.display());
        }
    }

    /// A build root of this test's own, emptied first so a previous run cannot
    /// decide this one. Named per case because the suite runs concurrently.
    fn build_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("batten-prune-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        mkdir(&root);
        root
    }

    // --- the table read alone (CLOUD-843) -------------------------------------

    /// The retired floor-model keys (CLOUD-2198): still read, never used, so a
    /// config written for the floor model loads while its pin moves.
    const RETIRED: &str = "[prune.warm]\nmb = 6000\nworst_mb = 6000\nmultiplier = 1\nmeasured = \"2026-08-22\"\n\n\
                           [prune.cold]\nmb = 14000\nworst_mb = 14000\nmultiplier = 1\nmeasured = \"2026-08-29\"\n";

    /// A directory holding exactly `config` as its committed authority.
    fn authority(name: &str, config: &str) -> PathBuf {
        let root = build_root(name);
        if let Err(why) = std::fs::write(root.join(crate::config::CONFIG_FILE), config) {
            panic!("fixture: could not write the config: {why}");
        }
        root
    }

    /// `#MUTANT prune-table-alone-unread` reddens here. The config carries a key
    /// no build knows — the shape a release meets on every branch that adds one —
    /// and the collector still gets its band.
    #[test]
    fn a_config_this_build_outran_still_yields_its_prune_table() {
        let root = authority(
            "alone-outran",
            &format!(
                "version = 1\nkey_this_build_predates = true\n\n[prune]\nkeep = 3\nmin_free_mb = 100\nmax_free_mb = 200\n\n{RETIRED}"
            ),
        );
        let Some(read) = declared_alone(&root) else {
            panic!("the [prune] table beside an unknown key must still be read")
        };
        assert_eq!(read.keep, 3, "it is the committed table that was read");
        assert_eq!(read.free_band(), Some((100, 200)));
    }

    /// `#MUTANT prune-table-alone-unvalidated` reddens here: reading the table alone
    /// must not skip the check a whole-file load would have refused.
    #[test]
    fn a_prune_table_that_fails_validation_is_not_read_alone() {
        let root = authority(
            "alone-invalid",
            &format!("version = 1\n\n[prune]\nkeep = 0\n\n{RETIRED}"),
        );
        assert!(
            declared_alone(&root).is_none(),
            "`keep = 0` is refused alone exactly as it is refused whole"
        );
    }

    /// The table stays STRICT: a `[prune]` key this build predates is a refusal,
    /// never a table read with the key silently dropped.
    #[test]
    fn a_prune_key_this_build_predates_is_not_read_around() {
        let root = authority(
            "alone-prune-key",
            &format!("version = 1\n\n[prune]\nkeep = 2\nfuture_key = 1\n\n{RETIRED}"),
        );
        assert!(declared_alone(&root).is_none());
    }

    /// A directory declaring no table, or no config at all, has nothing to read.
    #[test]
    fn no_table_and_no_config_read_as_nothing() {
        let bare = authority("alone-no-table", "version = 1\n");
        assert!(declared_alone(&bare).is_none());
        let empty = build_root("alone-no-config");
        assert!(declared_alone(&empty).is_none());
    }

    /// A band declared half, or with no width, is refused at load.
    #[test]
    fn a_band_must_be_whole_and_wide() {
        let table = |min: Option<u64>, max: Option<u64>| Prune {
            root: default_root(),
            keep: 2,
            warm: None,
            cold: None,
            regrowable: None,
            min_free_mb: min,
            max_free_mb: max,
        };
        assert!(table(None, None).validate().is_ok(), "the arm switched off");
        assert!(table(Some(10), Some(20)).validate().is_ok());
        assert!(table(Some(10), None).validate().is_err());
        assert!(table(None, Some(20)).validate().is_err());
        match table(Some(20), Some(20)).validate() {
            Ok(()) => panic!("a band with no width was accepted"),
            Err(why) => assert!(why.to_string().contains("is not above"), "{why}"),
        }
    }

    #[test]
    fn a_live_units_superseded_dwo_are_reclaimed_and_its_current_set_kept() {
        // CLOUD-2105: the owner's artifact names its current set. A `.dwo` it
        // does not name is a past incremental generation's and goes; one it
        // names stays; an owner with no artifact keeps everything.
        let root = build_root("superseded-dwo");
        let deps = root.join("debug/deps");
        mkdir(&deps);
        let write = |name: &str, contents: &[u8]| {
            if let Err(why) = std::fs::write(deps.join(name), contents) {
                panic!("fixture: could not write {name}: {why}");
            }
        };
        let owner = "cli-0123456789abcdef";
        write(
            &format!("lib{owner}.rlib"),
            format!("!<arch>\0{owner}.cli.aaaa-cgu.0.rcgu.dwo\0tail").as_bytes(),
        );
        write(&format!("{owner}.cli.aaaa-cgu.0.rcgu.dwo"), b"current");
        write(&format!("{owner}.cli.bbbb-cgu.0.rcgu.dwo"), b"superseded");
        let unbuilt = "bench-fedcba9876543210";
        write(
            &format!("{unbuilt}.bench.cccc-cgu.0.rcgu.dwo"),
            b"no artifact",
        );

        let (removed, _) = reclaim_superseded_debuginfo(&deps);
        assert_eq!(removed, 1, "only the generation no artifact names");
        assert!(
            deps.join(format!("{owner}.cli.aaaa-cgu.0.rcgu.dwo"))
                .is_file()
        );
        assert!(
            !deps
                .join(format!("{owner}.cli.bbbb-cgu.0.rcgu.dwo"))
                .exists()
        );
        assert!(
            deps.join(format!("{unbuilt}.bench.cccc-cgu.0.rcgu.dwo"))
                .is_file(),
            "could-not-look reclaims nothing"
        );
    }

    #[test]
    fn a_cargo_hash_suffix_groups_the_copies_of_one_binary() {
        // The grouping the whole retention rests on: without it every copy is its
        // own key and nothing is ever superseded.
        assert_eq!(
            artifact_key("batten-1a2b3c4d5e6f7890"),
            Some(("batten", ""))
        );
        assert_eq!(artifact_key("cli-0123456789abcdef"), Some(("cli", "")));
    }

    #[test]
    fn an_extensioned_artifact_groups_under_its_own_kind() {
        // CLOUD-1157's first half. The predecessor split on the last `-`, read
        // `42061777d57a0311.rlib` as the hash, failed on the `.`, and made the
        // whole filename its own stem — so no `.rlib`, `.rmeta` or `.so` was ever
        // past `keep` however many copies accumulated.
        assert_eq!(
            artifact_key("libbatten-42061777d57a0311.rlib"),
            Some(("libbatten", "rlib"))
        );
        assert_eq!(
            artifact_key("libbatten-f8edd060dc0f6832.rmeta"),
            Some(("libbatten", "rmeta"))
        );
        assert_eq!(
            artifact_key("libserde_derive-0123456789abcdef.so"),
            Some(("libserde_derive", "so"))
        );
    }

    #[test]
    fn the_kind_is_part_of_the_key_rather_than_folded_into_the_stem() {
        // THE DATA-LOSS CASE, as an assertion about the key itself. `libbatten`
        // carries 2 `.rlib` and 6 `.rmeta` in a real `deps`; one group of eight
        // under `keep = 2` can retain two `.rmeta` and delete the LIVE `.rlib`,
        // which is the `keep = 0` failure arriving through the grouping.
        let rlib = artifact_key("libbatten-42061777d57a0311.rlib");
        let rmeta = artifact_key("libbatten-42061777d57a0311.rmeta");
        assert_ne!(rlib, rmeta, "same stem, different kind, different group");
        assert_eq!(rlib.map(|key| key.0), rmeta.map(|key| key.0));
    }

    #[test]
    fn a_name_that_is_not_a_hashed_artifact_is_not_grouped_at_all() {
        // The anti-vacuity twin, and the one that keeps the prune from deleting
        // an unrelated binary that happens to share a prefix.
        assert_eq!(artifact_key("target-prune"), None);
        assert_eq!(artifact_key("batten"), None);
        assert_eq!(artifact_key("some-tool-xyz"), None);
        // A kind this pass does not reclaim is invisible rather than its own
        // group — `.d` above all, which is 2.8 MB across 666 files here.
        assert_eq!(artifact_key("cli-0123456789abcdef.d"), None);
        assert_eq!(artifact_key("cli-0123456789abcdef.rcgu.o"), None);
    }

    #[test]
    fn a_trailing_star_is_a_prefix_and_nothing_else_is() {
        use std::ffi::OsStr;
        assert!(name_matches(OsStr::new("flycheck0"), "flycheck*"));
        assert!(name_matches(OsStr::new("flycheck12"), "flycheck*"));
        assert!(name_matches(OsStr::new("flycheck"), "flycheck*"));
        assert!(!name_matches(OsStr::new("fly"), "flycheck*"));
        assert!(name_matches(OsStr::new("incremental"), "incremental"));
        assert!(
            !name_matches(OsStr::new("incremental2"), "incremental"),
            "a name without the star is exact, or every root is a prefix of another"
        );
    }

    // --- an artifact and its fingerprint go together (CLOUD-1913) -------------

    /// Write one `deps` artifact at a controlled age, with the fingerprint cargo
    /// would have left beside it.
    fn variant(profile: &Path, stem: &str, hash: &str, age_seconds: u64) {
        let deps = profile.join("deps");
        mkdir(&deps);
        let file = deps.join(format!("lib{stem}-{hash}.rmeta"));
        if let Err(why) = std::fs::write(&file, b"rmeta") {
            panic!("fixture: could not write {}: {why}", file.display());
        }
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(age_seconds);
        let stamped = std::fs::File::options()
            .write(true)
            .open(&file)
            .and_then(|handle| handle.set_modified(when));
        if let Err(why) = stamped {
            panic!("fixture: could not age {}: {why}", file.display());
        }
        mkdir(&profile.join(".fingerprint").join(format!("{stem}-{hash}")));
    }

    #[test]
    fn a_reclaimed_artifact_takes_its_fingerprint_with_it() {
        // The measured failure, reduced: a fingerprint left claiming a unit fresh
        // after its artifact was reclaimed is what made the next compile report
        // `extern location ... does not exist` instead of rebuilding the unit.
        let root = build_root("fingerprint-with-artifact");
        let profile = root.join("debug");
        variant(&profile, "demo", "a1a1a1a1a1a1a1a1", 3000);
        variant(&profile, "demo", "a2a2a2a2a2a2a2a2", 2000);
        variant(&profile, "demo", "a3a3a3a3a3a3a3a3", 1000);
        variant(&profile, "other", "b1b1b1b1b1b1b1b1", 9000);

        let (pruned, _) = reclaim_superseded(&root, 1);

        let prints = profile.join(".fingerprint");
        assert_eq!(pruned, 2, "keep 1 of three `demo` variants");
        assert!(!prints.join("demo-a1a1a1a1a1a1a1a1").exists());
        assert!(!prints.join("demo-a2a2a2a2a2a2a2a2").exists());
        assert!(
            prints.join("demo-a3a3a3a3a3a3a3a3").is_dir(),
            "the kept variant keeps its fingerprint"
        );
        assert!(
            prints.join("other-b1b1b1b1b1b1b1b1").is_dir(),
            "a unit the pass did not reclaim is not touched, however old"
        );
    }

    #[test]
    fn the_fingerprint_is_matched_by_hash_across_the_crate_and_package_spellings() {
        // The artifact carries the CRATE name (`libsha1_checked`) and the
        // fingerprint the PACKAGE name (`sha1-checked`); the hash is the one token
        // both share, so a name comparison would miss exactly this case.
        let root = build_root("fingerprint-by-hash");
        let prints = root.join("debug/.fingerprint");
        mkdir(&prints.join("sha1-checked-c0ffee00c0ffee00"));
        mkdir(&prints.join("sha1-checked-c0ffee00c0ffee01"));
        forget_fingerprint(
            &prints,
            &root.join("debug/deps/libsha1_checked-c0ffee00c0ffee00.rmeta"),
        );
        assert!(!prints.join("sha1-checked-c0ffee00c0ffee00").exists());
        assert!(prints.join("sha1-checked-c0ffee00c0ffee01").is_dir());
    }

    /// Write `bytes` at `path`, panicking with the path on failure.
    fn put(path: &Path, bytes: &[u8]) {
        if let Err(why) = std::fs::write(path, bytes) {
            panic!("fixture: could not write {}: {why}", path.display());
        }
    }

    /// Fails by: any of the three passes reclaiming the wrong file, or the
    /// count and bytes they report not summing what they removed.
    #[test]
    fn a_reclaim_reports_exactly_what_each_pass_removed() {
        let root = build_root("reclaim-counts");
        let profile = root.join("debug");
        let (old, new) = ("a1a1a1a1a1a1a1a1", "b2b2b2b2b2b2b2b2");
        variant(&profile, "demo", old, 3000);
        variant(&profile, "demo", new, 1000);
        let deps = profile.join("deps");
        put(&deps.join("libgone-c3c3c3c3c3c3c3c3.rlib"), b"orphan!");
        put(&deps.join("gone-c3c3c3c3c3c3c3c3.x.rcgu.dwo"), b"abc");
        let named = format!("demo-{new}.keep.rcgu.dwo");
        put(&deps.join(format!("libdemo-{new}.rlib")), named.as_bytes());
        put(&deps.join(&named), b"k");
        put(&deps.join(format!("demo-{new}.old.rcgu.dwo")), b"gone");
        assert_eq!(
            reclaim_superseded(&root, 1),
            (4, 5 + 7 + 3 + 4),
            "the old generation, two orphans and one superseded dwo"
        );
        assert!(deps.join(&named).is_file(), "the current dwo is kept");
        assert!(deps.join(format!("libdemo-{new}.rlib")).is_file());
    }

    /// Fails by: a name cargo did not hash read as an artifact, a hash read
    /// from a dash-carrying suffix, or a dwo's owner misread.
    #[test]
    fn only_a_hashed_name_is_an_artifact() {
        assert_eq!(
            split_artifact("libbatten-42061777d57a0311.rlib"),
            Some(("libbatten", "42061777d57a0311", "rlib"))
        );
        assert_eq!(
            split_artifact("cli-abcdef12"),
            Some(("cli", "abcdef12", ""))
        );
        assert_eq!(split_artifact("cli-aaaaaaaaaaaa.d"), None);
        assert_eq!(split_artifact("cli-zzzzzzzz"), None);
        assert_eq!(split_artifact("cli-abcdef1"), None);
        assert_eq!(
            dwo_owner_hash("batten-74d53bfe8b80e4a5.cgu.rcgu.dwo"),
            Some("74d53bfe8b80e4a5")
        );
    }

    /// Fails by: a unit's identity read from its `dep-` document, missing a
    /// field, or not keyed by its hash.
    #[test]
    fn a_unit_is_identified_by_its_fingerprint_document() {
        let root = build_root("unit-identity");
        let unit = root.join("demo-d1d1d1d1d1d1d1d1");
        mkdir(&unit);
        put(&unit.join("dep-lib-demo.json"), br#"{"target": "wrong"}"#);
        put(
            &unit.join("lib-demo.json"),
            br#"{"target": 1, "path": 2, "profile": 3, "features": "[]", "compile_kind": 0}"#,
        );
        let identity = "1\u{1f}2\u{1f}3\u{1f}\"[]\"\u{1f}0".to_owned();
        assert_eq!(unit_identity(&unit), Some(identity.clone()));
        assert_eq!(
            unit_identities(&root),
            BTreeMap::from([("d1d1d1d1d1d1d1d1".to_owned(), identity)])
        );
    }

    /// Fails by: a declared reading taken out of order, or the last one not
    /// repeating.
    #[test]
    fn declared_readings_are_taken_in_order_and_the_last_repeats() {
        let mut readings = Readings {
            declared: Some(vec![5, 3]),
            taken: 0,
        };
        let taken: Vec<u64> = (0..3)
            .map(|_| readings.take(Path::new(".")).unwrap_or(0))
            .collect();
        assert_eq!(taken, [5, 3, 3]);
    }

    /// Fails by: an empty table not defaulting its root and its retention, or
    /// a band of real width refused.
    #[test]
    fn an_empty_table_defaults_and_a_wide_band_is_valid() {
        let empty: Prune = match serde_json::from_str("{}") {
            Ok(table) => table,
            Err(why) => panic!("an empty table: {why}"),
        };
        assert_eq!((empty.root.as_str(), empty.keep), ("target", 2));
        let banded = Prune {
            min_free_mb: Some(1),
            max_free_mb: Some(2),
            ..empty
        };
        assert!(banded.validate().is_ok());
        assert_eq!(banded.free_band(), Some((1, 2)));
    }

    /// Fails by: an extension-less generation grouped by its name alone, or an
    /// executable one never grouped at all. Off unix every extension-less file
    /// reads as executable, so both groups give up a generation there.
    #[test]
    fn only_executable_extensionless_generations_are_superseded() {
        let deps = build_root("extensionless").join("deps");
        mkdir(&deps);
        for name in ["cli-a1a1a1a1a1a1a1a1", "cli-b2b2b2b2b2b2b2b2"] {
            let path = deps.join(name);
            put(&path, b"x");
            if let Err(why) = crate::engine::make_executable(&path) {
                panic!("fixture: {why}");
            }
        }
        for name in ["note-c3c3c3c3c3c3c3c3", "note-d4d4d4d4d4d4d4d4"] {
            put(&deps.join(name), b"x");
        }
        let mut stems: Vec<String> = superseded_in(&deps, 1)
            .into_values()
            .flatten()
            .filter_map(|path| {
                let name = path.file_name()?.to_str()?;
                Some(name.split('-').next()?.to_owned())
            })
            .collect();
        stems.sort();
        let expected: &[&str] = if cfg!(unix) {
            &["cli"]
        } else {
            &["cli", "note"]
        };
        assert_eq!(stems, expected);
    }

    /// Fails by: a path statvfs cannot read answering a reading anyway. Windows
    /// reads the volume a missing path would land on, so there it answers.
    #[test]
    fn free_space_at_a_missing_path_refuses_on_unix_alone() {
        let absent = crate::scratch::scratch("prune-no-volume").join("never-made");
        assert_eq!(available_megabytes(&absent).is_err(), cfg!(unix));
    }

    /// Fails by: a free-space reading in other than whole MiB of what the
    /// volume reports available.
    #[test]
    fn free_space_reads_in_whole_mebibytes() {
        assert_eq!(mebibytes(0), 0);
        assert_eq!(mebibytes(1024 * 1024 - 1), 0);
        assert_eq!(mebibytes(1024 * 1024), 1);
        assert_eq!(mebibytes(2 * 1024 * 1024 + 99), 2);
    }

    /// Fails by: the executable bit misread, so an extension-less scratch file
    /// is grouped as a build artifact.
    #[test]
    fn only_an_executable_file_reads_as_one() {
        let root = build_root("executable");
        let plain = root.join("plain");
        put(&plain, b"x");
        let meta = |path: &Path| match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(why) => panic!("fixture: {why}"),
        };
        assert!(is_executable(&meta(
            &std::env::current_exe().unwrap_or_default()
        )));
        if cfg!(unix) {
            assert!(!is_executable(&meta(&plain)), "a 0644 file");
        }
    }

    // --- a running build's tree is never reclaimed (CLOUD-1913) --------------

    /// Hold `profile`'s build lock the way a running cargo does, until dropped.
    fn building(profile: &Path) -> std::fs::File {
        mkdir(profile);
        let lock = profile.join(BUILD_LOCK);
        let held = std::fs::File::create(&lock).and_then(|file| file.lock().map(|()| file));
        match held {
            Ok(file) => file,
            Err(why) => panic!("fixture: could not lock {}: {why}", lock.display()),
        }
    }

    #[test]
    fn superseded_artifacts_under_a_running_build_are_kept() {
        let root = build_root("claim-superseded");
        let profile = root.join("debug");
        variant(&profile, "demo", "d1d1d1d1d1d1d1d1", 3000);
        variant(&profile, "demo", "d2d2d2d2d2d2d2d2", 1000);
        let build = building(&profile);

        assert_eq!(
            reclaim_superseded(&root, 1),
            (0, 0),
            "nothing under a held lock"
        );

        drop(build);
        assert_eq!(reclaim_superseded(&root, 1).0, 1, "released, keep 1 of 2");
    }
}
