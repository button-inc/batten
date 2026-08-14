//! Who the store is: a self-identifying, out-of-tree findings store (CLOUD-164).
//!
//! This module answers exactly one question — *which store belongs to this
//! checkout* — and deliberately holds nothing. What the store contains (findings,
//! instances, dispositions) is a separate concern with a separate lifetime:
//! CLOUD-78 extends the contents, and nothing it adds changes identity.
//!
//! # The identity is minted, never derived
//!
//! A store's identity is a value **minted once** at first write and recorded in
//! `store.json`. Everything observable about the repository — the common git
//! directory, the configured remotes, the directory's own name — is recorded
//! *beside* it as [`KeyMaterial`], and none of it is the key.
//!
//! That asymmetry is the whole design, because every observable fact changes
//! under ordinary work:
//!
//! * the directory **basename** merges same-named strangers and splits worktree
//!   siblings — disqualified outright;
//! * the **common dir** changes when the repository is moved on disk;
//! * the **remotes** change on the first `remote add`, and on any URL change.
//!
//! A store keyed on any of them orphans itself the moment that fact moves, and an
//! orphaned store is not merely lost: it silently resurrects every finding a
//! reviewer had already rejected by design. So a key-material change is a
//! **migration event** — recorded, reported, and never a fresh store.
//!
//! # Location versus identity
//!
//! The basename still decides *where to look first*: the on-disk location comes
//! from [`crate::state::repo_state_dir`], the one out-of-tree path resolution this
//! crate has, and no second path scheme is invented. The basename is recorded in
//! [`KeyMaterial::repo_name`] as a **hint** and is never a match criterion. When
//! two unrelated repositories share a basename, the second one lands in a
//! derived sibling directory — a name that is likewise not authoritative.
//!
//! The reverse direction — repository to store — needs its own pointer, because a
//! moved no-remote checkout changes *both* its basename and its common dir at
//! once. That pointer is a marker file inside the common git directory, the same
//! place [`crate::receipt`] keeps its compatibility store: it moves with the
//! repository, and every linked worktree shares it.
//!
//! # Resolution is total, and only one arm mints
//!
//! [`resolve`] reads and never writes; it returns an [`Opened`] naming what it
//! found. [`Opened::Fresh`] — the only arm that mints — is reachable only after
//! every continuity criterion has been asked and none answered, so a store
//! cannot be freshly minted for a repository that already had one.
//!
//! One criterion is deliberately weaker than the others. A matching root commit
//! or remote URL is identity-bearing: it cannot plausibly be a different
//! repository. A matching common dir alone *can* be — a checkout deleted and
//! another cloned to the same path — so it yields [`Opened::Candidate`], which is
//! reported and bound only by an explicit `batten state adopt`.
//!
//! # Warm-fork restart: this module's half (CLOUD-83)
//!
//! [`crate::state`] states the procedure; the part that belongs here is **why a
//! restart finds the same store rather than a fresh one**. A fork changes no key
//! material at all — same checkout, same common dir, same root commits — so
//! [`resolve`] takes the marker arm and returns [`Opened::Existing`] with no
//! migration to record. Nothing about restart is special-cased, and that is the
//! property worth stating: the machinery that survives a repository being *moved*
//! is strictly stronger than what surviving a *process* needs.
//!
//! The failure this rules out is the one named at the top of this module —
//! minting a fresh store, which silently resurrects every finding a reviewer
//! already rejected by design. A restart is exactly when that would be least
//! visible, because there is no other symptom: the new store is valid, empty and
//! quiet. [`Opened::Fresh`] being reachable only after every criterion has been
//! asked is what makes it unreachable here.
//!
//! Per-session state — the drain's resume position and the sequence kind's
//! session lineage — is [`crate::session`]'s, kept beside the findings rather
//! than in this record: it changes every session, and store identity is stable
//! for the life of a repository.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::{git, identity, state};

/// The on-disk record's schema version.
///
/// Its own number, not `batten.toml`'s config version: the store's format and the
/// config language evolve for unrelated reasons, and one number governing both
/// would force a bump in each whenever either moved.
pub const STORE_SCHEMA: u32 = 1;

/// The file naming the store inside its directory.
const STORE_FILE: &str = "store.json";

/// The marker inside the repository's common git dir that points back at the
/// store. Named like [`crate::receipt`]'s `batten-receipts` sibling, and kept
/// there for the same reason: it travels with the repository.
const MARKER_FILE: &str = "batten-store";

/// A minted store identity: 64 lowercase hex characters.
///
/// Opaque by contract. Nothing may parse structure out of it or reconstruct it
/// from repository facts — a value that could be recomputed from a path would be
/// derived rather than minted, and would move when the path moved.
///
/// 256 bits, rendered as hex, minted through [`identity`]'s framing rather than
/// as an RFC-4122 UUID: no consumer parses a version nibble or reads the variant
/// bits, so the layout would be a promise to future readers that nothing here
/// keeps. A `uuid` dependency would buy 128 bits of opacity that framing already
/// produces. CLOUD-164's scope says "an opaque identifier minted at first
/// write" and deliberately does not specify the rendering (CLOUD-321).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StoreId(String);

impl StoreId {
    /// The identity as its stable hex rendering — a coordinate, safe to print.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The short form used to disambiguate a directory name. A display detail
    /// only: nothing resolves a store by it.
    fn short(&self) -> &str {
        self.0.get(..8).unwrap_or(&self.0)
    }
}

impl std::fmt::Display for StoreId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One configured remote, recorded as metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Remote {
    /// The remote's name (`origin`).
    pub name: String,
    /// The URL exactly as configured, kept verbatim so a report can quote what
    /// the operator actually wrote.
    pub url: String,
    /// The URL folded to `host/owner/repo` for comparison — see
    /// [`canonical_remote_url`].
    #[serde(rename = "canonicalUrl")]
    pub canonical_url: String,
}

/// Everything observed about a repository. Recorded; never keyed on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KeyMaterial {
    /// The shared git directory. Changes when the repository moves on disk.
    #[serde(rename = "commonDir")]
    pub common_dir: String,
    /// The repository's root commits, sorted. The strongest continuity evidence
    /// available: they survive a move, a rename, and a remote change alike.
    #[serde(rename = "rootCommits")]
    pub root_commits: Vec<String>,
    /// The configured remotes, sorted by name.
    pub remotes: Vec<Remote>,
    /// The checkout directory's own name. A **hint** for locating the store and
    /// nothing else — never compared to decide identity, because basename
    /// keying merges same-named strangers and splits worktree siblings.
    #[serde(rename = "repoName")]
    pub repo_name: String,
}

/// Which secondary criterion proved that a store belongs to this repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchCriterion {
    /// The repository's own marker file named the store outright.
    Marker,
    /// A root commit is shared. Identity-bearing.
    RootCommit,
    /// A remote's canonical URL is shared. Identity-bearing.
    RemoteUrl,
    /// Only the common dir matches. **Not** identity-bearing on its own: a
    /// checkout can be deleted and another cloned to the same path.
    CommonDir,
}

impl MatchCriterion {
    /// Every criterion, so anything ranging over the vocabulary is derived
    /// rather than re-typed.
    pub const ALL: &'static [MatchCriterion] = &[
        MatchCriterion::Marker,
        MatchCriterion::RootCommit,
        MatchCriterion::RemoteUrl,
        MatchCriterion::CommonDir,
    ];

    /// The stable lowercase token used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            MatchCriterion::Marker => "marker",
            MatchCriterion::RootCommit => "root-commit",
            MatchCriterion::RemoteUrl => "remote-url",
            MatchCriterion::CommonDir => "common-dir",
        }
    }

    /// Whether this criterion alone proves continuity.
    ///
    /// A shared root commit or remote URL cannot plausibly belong to a different
    /// repository. A shared *path* can, so it never auto-adopts.
    #[must_use]
    pub const fn is_identity_bearing(self) -> bool {
        matches!(
            self,
            MatchCriterion::Marker | MatchCriterion::RootCommit | MatchCriterion::RemoteUrl
        )
    }
}

/// A recorded key-material change. Never a fresh store — that is the point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Migration {
    /// When it was recorded, RFC 3339 UTC.
    pub at: String,
    /// What proved this was still the same repository.
    pub criterion: MatchCriterion,
    /// Which [`KeyMaterial`] fields moved, sorted.
    pub changed: Vec<String>,
}

/// The `store.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRecord {
    /// The on-disk format version ([`STORE_SCHEMA`]).
    pub schema: u32,
    /// The minted identity. The one key.
    pub id: StoreId,
    /// What was observed when the record was last written. Metadata.
    #[serde(rename = "keyMaterial")]
    pub key_material: KeyMaterial,
    /// Every recorded key-material change, oldest first.
    #[serde(default)]
    pub migrations: Vec<Migration>,
}

/// What [`resolve`] found. Total over the five possible answers.
#[derive(Debug)]
pub enum Opened {
    /// The store at the expected location belongs to this repository.
    Existing {
        /// The record as read from disk.
        record: StoreRecord,
        /// Where it lives.
        dir: PathBuf,
        /// What the repository looks like **now**. Carried from [`resolve`]
        /// rather than re-derived at write time: the record's own `commonDir`
        /// is precisely the field a move invalidates, so re-observing through it
        /// would fail exactly when the repository had moved — the one case this
        /// module exists to survive.
        observed: KeyMaterial,
        /// Key-material changes observed since it was last written. Empty is the
        /// ordinary case; non-empty is a migration awaiting a write.
        migrations: Vec<Migration>,
    },
    /// A store found elsewhere proved continuity on an identity-bearing
    /// criterion, so it is this repository's store.
    Adopted {
        /// The record as read from disk.
        record: StoreRecord,
        /// Where it lives.
        dir: PathBuf,
        /// What the repository looks like now — see [`Opened::Existing`].
        observed: KeyMaterial,
        /// What proved it.
        criterion: MatchCriterion,
    },
    /// A store matched only on a criterion that can alias a stranger. Reported,
    /// never auto-bound: `batten state adopt` is what binds it.
    Candidate {
        /// The candidate store's identity.
        id: StoreId,
        /// Where it lives.
        dir: PathBuf,
        /// The weak criterion that matched.
        criterion: MatchCriterion,
    },
    /// No store anywhere belongs to this repository. The only arm that mints,
    /// and reachable only after every criterion has been asked.
    Fresh {
        /// What was observed, ready to be recorded.
        observed: KeyMaterial,
        /// Where the store will live.
        dir: PathBuf,
    },
    /// The expected directory is occupied by a *different* repository's store —
    /// two unrelated repositories with the same basename.
    Stranger {
        /// The occupant's identity, for the report.
        occupant: StoreId,
        /// What was observed, ready to be recorded.
        observed: KeyMaterial,
        /// The occupied directory.
        dir: PathBuf,
    },
}

/// Where a resolved store lives on disk, when one is already bound.
///
/// Read-only by design, and the reason `state list` can exist as a `read` verb:
/// it answers "is there a store, and where" without minting or writing one.
/// [`Opened::Fresh`] and [`Opened::Stranger`] return `None` — neither names an
/// existing store, and a read path must not create one to answer.
#[must_use]
pub fn bound_dir(opened: &Opened) -> Option<PathBuf> {
    match opened {
        Opened::Existing { dir, .. } | Opened::Adopted { dir, .. } => Some(dir.clone()),
        // A candidate is not bound until a human binds it, so a listing that
        // read from it would be reporting a store this repository may not own.
        Opened::Candidate { .. } | Opened::Fresh { .. } | Opened::Stranger { .. } => None,
    }
}

/// Fold a remote URL to `host/owner/repo` for comparison.
///
/// Both spellings of the same remote — `git@host:owner/repo.git` and
/// `https://host/owner/repo` — must compare equal, or `git remote set-url`
/// between them would read as a key-material change when nothing moved. The
/// host is lowercased (DNS is case-insensitive), any userinfo and scheme are
/// dropped, and a trailing `.git` is stripped.
///
/// A URL this does not recognise (a local path, say) folds to itself trimmed, so
/// it still compares equal to itself and never to something else.
#[must_use]
pub fn canonical_remote_url(url: &str) -> String {
    let trimmed = url.trim();
    // Strip a scheme, if any: everything through `://`.
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    // Drop userinfo (`git@`, `user:pass@`) — credentials are not identity, and
    // keeping them here would put a password in a recorded field.
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    // scp-like syntax separates host from path with `:` rather than `/`.
    let slashed = after_userinfo.replacen(':', "/", 1);
    let body = slashed
        .trim_end_matches('/')
        .strip_suffix(".git")
        .unwrap_or_else(|| slashed.trim_end_matches('/'));
    match body.split_once('/') {
        Some((host, path)) => format!("{}/{}", host.to_lowercase(), path),
        None => body.to_lowercase(),
    }
}

/// Observe everything recordable about the repository rooted at `repo_root`.
///
/// # Errors
///
/// Returns an error when `repo_root` is not a readable git repository.
pub fn observe(repo_root: &Path) -> Result<KeyMaterial> {
    let remotes = git::remotes(repo_root)?
        .into_iter()
        .map(|(name, url)| Remote {
            canonical_url: canonical_remote_url(&url),
            name,
            url,
        })
        .collect();
    Ok(KeyMaterial {
        common_dir: git::common_dir(repo_root)?,
        root_commits: git::root_commits(repo_root)?,
        remotes,
        repo_name: state::derive_repo_name(repo_root)?,
    })
}

/// Score `recorded` against `observed`, returning the strongest criterion that
/// proves they are the same repository.
///
/// Ordered strongest-first so the reported reason is the best available one, not
/// merely the first checked.
#[must_use]
pub fn match_criterion(recorded: &KeyMaterial, observed: &KeyMaterial) -> Option<MatchCriterion> {
    let recorded_roots: BTreeSet<&str> = recorded.root_commits.iter().map(String::as_str).collect();
    if observed
        .root_commits
        .iter()
        .any(|commit| recorded_roots.contains(commit.as_str()))
    {
        return Some(MatchCriterion::RootCommit);
    }
    let recorded_urls: BTreeSet<&str> = recorded
        .remotes
        .iter()
        .map(|remote| remote.canonical_url.as_str())
        .collect();
    if observed
        .remotes
        .iter()
        .any(|remote| recorded_urls.contains(remote.canonical_url.as_str()))
    {
        return Some(MatchCriterion::RemoteUrl);
    }
    // Weakest, and never identity-bearing: a path can be reused by a stranger.
    (!recorded.common_dir.is_empty() && recorded.common_dir == observed.common_dir)
        .then_some(MatchCriterion::CommonDir)
}

/// Which [`KeyMaterial`] fields differ, as sorted field names.
///
/// `repo_name` is included: a rename is a real migration event to report, even
/// though the name is never a key.
#[must_use]
fn changed_fields(recorded: &KeyMaterial, observed: &KeyMaterial) -> Vec<String> {
    let mut changed = Vec::new();
    if recorded.common_dir != observed.common_dir {
        changed.push("commonDir".to_owned());
    }
    if recorded.remotes != observed.remotes {
        changed.push("remotes".to_owned());
    }
    if recorded.repo_name != observed.repo_name {
        changed.push("repoName".to_owned());
    }
    if recorded.root_commits != observed.root_commits {
        changed.push("rootCommits".to_owned());
    }
    changed.sort();
    changed
}

/// Read a store record, treating anything unreadable as **absent**.
///
/// Fail-closed, exactly as [`crate::receipt`] reads its statements: a truncated,
/// unparseable, or future-schema record is not partially trusted. Returning
/// `None` routes it through the same path as "no store here", which ends in a
/// loud fresh-mint or a stranger report rather than a silent half-read.
fn read_record(dir: &Path) -> Option<StoreRecord> {
    let text = std::fs::read_to_string(dir.join(STORE_FILE)).ok()?;
    let record: StoreRecord = serde_json::from_str(&text).ok()?;
    (record.schema == STORE_SCHEMA).then_some(record)
}

/// Write a store record atomically.
///
/// Temp file plus rename within the same directory, so a concurrent worktree
/// reading the store never observes a torn record — a half-written `store.json`
/// would read as *absent* under [`read_record`], and a store that vanishes is
/// exactly the orphan this module exists to prevent.
fn write_record(dir: &Path, record: &StoreRecord) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create the store directory {}", dir.display()))?;
    let json = serde_json::to_string_pretty(record)?;
    let temp = dir.join(format!("{STORE_FILE}.{}.tmp", std::process::id()));
    std::fs::write(&temp, format!("{json}\n"))
        .with_context(|| format!("write the store record {}", temp.display()))?;
    std::fs::rename(&temp, dir.join(STORE_FILE))
        .with_context(|| format!("publish the store record in {}", dir.display()))?;
    Ok(())
}

/// Point the repository at its store, so a move can be followed back.
fn write_marker(common_dir: &str, id: &StoreId) -> Result<()> {
    let path = Path::new(common_dir).join(MARKER_FILE);
    std::fs::write(&path, id.as_str())
        .with_context(|| format!("write the store marker {}", path.display()))
}

/// The store id this repository's marker names, if any.
fn read_marker(common_dir: &str) -> Option<StoreId> {
    let text = std::fs::read_to_string(Path::new(common_dir).join(MARKER_FILE)).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| StoreId(trimmed.to_owned()))
}

/// Every store directory under the state root, with its record.
///
/// Sorted by path so a scan's answer — and any report derived from it — does not
/// depend on filesystem `read_dir` order.
fn scan_stores() -> Result<Vec<(PathBuf, StoreRecord)>> {
    let root = state::state_root()?;
    let Ok(entries) = std::fs::read_dir(&root) else {
        // No state root yet is the ordinary first-run case, not a failure.
        return Ok(Vec::new());
    };
    let mut found: Vec<(PathBuf, StoreRecord)> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter_map(|path| read_record(&path).map(|record| (path, record)))
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

/// Resolve the store belonging to the repository rooted at `repo_root`.
///
/// **Reads only.** It mints nothing and writes nothing, so calling it on a read
/// path cannot turn that path into a writer — which is what keeps `check`'s
/// declared `read` effect honest.
///
/// # Errors
///
/// Returns an error when `repo_root` is not a readable git repository, or when
/// the OS state directory cannot be resolved.
pub fn resolve(repo_root: &Path) -> Result<Opened> {
    let observed = observe(repo_root)?;
    let expected = state::repo_state_dir(repo_root)?;

    // 1. The repository's own marker is the most direct answer there is.
    if let Some(marked) = read_marker(&observed.common_dir) {
        if let Some(record) = read_record(&expected).filter(|record| record.id == marked) {
            let migrations = migration_for(&record, &observed, MatchCriterion::Marker);
            return Ok(Opened::Existing {
                record,
                dir: expected,
                observed,
                migrations,
            });
        }
        if let Some((dir, record)) = scan_stores()?
            .into_iter()
            .find(|(_, record)| record.id == marked)
        {
            return Ok(Opened::Adopted {
                record,
                dir,
                observed,
                criterion: MatchCriterion::Marker,
            });
        }
        // The marker names a store that no longer exists. Fall through: the
        // criteria below may still find it, and a dangling marker must not
        // short-circuit into a fresh mint.
    }

    // 2. The store at the expected location — is it ours, or a stranger's?
    if let Some(record) = read_record(&expected) {
        return Ok(match match_criterion(&record.key_material, &observed) {
            Some(criterion) => {
                let migrations = migration_for(&record, &observed, criterion);
                Opened::Existing {
                    record,
                    dir: expected,
                    observed,
                    migrations,
                }
            }
            None => Opened::Stranger {
                occupant: record.id.clone(),
                observed,
                dir: expected,
            },
        });
    }

    // 3. Nothing at the expected path. The repository may have moved, or been
    //    renamed: ask every other store whether it recognises this one.
    let mut candidates: Vec<(PathBuf, StoreRecord, MatchCriterion)> = scan_stores()?
        .into_iter()
        .filter_map(|(dir, record)| {
            match_criterion(&record.key_material, &observed)
                .map(|criterion| (dir, record, criterion))
        })
        .collect();
    // Strongest evidence first, then by path so the choice is deterministic.
    candidates.sort_by(|a, b| {
        b.2.is_identity_bearing()
            .cmp(&a.2.is_identity_bearing())
            .then_with(|| a.0.cmp(&b.0))
    });
    if let Some((dir, record, criterion)) = candidates.into_iter().next() {
        return Ok(if criterion.is_identity_bearing() {
            Opened::Adopted {
                record,
                dir,
                observed,
                criterion,
            }
        } else {
            Opened::Candidate {
                id: record.id,
                dir,
                criterion,
            }
        });
    }

    // 4. Every criterion asked, none answered. Only now is a mint correct.
    Ok(Opened::Fresh {
        observed,
        dir: expected,
    })
}

/// The migration a record needs to catch up with what was observed, if any.
fn migration_for(
    record: &StoreRecord,
    observed: &KeyMaterial,
    criterion: MatchCriterion,
) -> Vec<Migration> {
    let changed = changed_fields(&record.key_material, observed);
    if changed.is_empty() {
        return Vec::new();
    }
    vec![Migration {
        at: now_rfc3339(),
        criterion,
        changed,
    }]
}

/// The current time as RFC 3339 UTC, or the epoch when the clock is unreadable.
///
/// A timestamp here is a recorded annotation, never an invalidator — nothing in
/// this module decides anything by comparing it — so an unreadable clock
/// degrades the annotation rather than failing the write.
fn now_rfc3339() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    crate::receipt::rfc3339_utc(seconds)
}

/// Mint a store identity.
///
/// Seeded with the repository's own facts *and* a clock and process id, so the
/// value cannot be recomputed from a path by anyone — including a later run of
/// this function. That irreproducibility is the property being bought: a derived
/// id would move when the repository moved.
fn mint(observed: &KeyMaterial) -> StoreId {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let entropy = format!("{now}:{}", std::process::id());
    let mut seed: Vec<&str> = vec![&observed.common_dir, &entropy];
    seed.extend(observed.root_commits.iter().map(String::as_str));
    StoreId(identity::store_fingerprint(&seed).to_hex())
}

/// The outcome of binding a store to a repository.
#[derive(Debug)]
pub struct Bound {
    /// The record as it now stands on disk.
    pub record: StoreRecord,
    /// Where it lives.
    pub dir: PathBuf,
    /// What happened, as a pointer-only line for the caller to report.
    pub note: Option<String>,
}

/// Bind `opened` to disk: write the record, refresh the marker, and record any
/// migration.
///
/// The **write half**, deliberately split from [`resolve`] so that resolving is
/// available to read paths without making them writers.
///
/// # Errors
///
/// Returns a [`UsageError`] for [`Opened::Candidate`], which is precisely the
/// case a human must decide: binding it automatically is what would let a
/// stranger's store be adopted on a reused path.
pub fn commit(opened: Opened) -> Result<Bound> {
    match opened {
        Opened::Existing {
            mut record,
            dir,
            observed,
            migrations,
        } => {
            // The marker is refreshed on **every** path, including this one,
            // where nothing moved. A repository meeting an existing store for
            // the first time takes this arm with no migration to record, and
            // without an unconditional write it would never get the pointer that
            // makes the *next* move survivable.
            write_marker(&observed.common_dir, &record.id)?;
            if migrations.is_empty() {
                return Ok(Bound {
                    record,
                    dir,
                    note: None,
                });
            }
            let note = Some(format!(
                "store {} migrated ({})",
                record.id,
                describe(&migrations)
            ));
            record.migrations.extend(migrations);
            record.key_material = observed;
            write_record(&dir, &record)?;
            Ok(Bound { record, dir, note })
        }
        Opened::Adopted {
            mut record,
            dir,
            observed,
            criterion,
        } => {
            let changed = changed_fields(&record.key_material, &observed);
            let note = Some(format!(
                "store {} adopted on {}{}",
                record.id,
                criterion.as_str(),
                if changed.is_empty() {
                    String::new()
                } else {
                    format!("; migrated ({})", changed.join(", "))
                }
            ));
            if !changed.is_empty() {
                record.migrations.push(Migration {
                    at: now_rfc3339(),
                    criterion,
                    changed,
                });
            }
            record.key_material = observed;
            write_record(&dir, &record)?;
            write_marker(&record.key_material.common_dir, &record.id)?;
            Ok(Bound { record, dir, note })
        }
        Opened::Candidate { id, criterion, .. } => Err(UsageError::raise(format!(
            "a store matches only on {}, which can name a different repository; \
             bind it deliberately with `batten state adopt {id}`",
            criterion.as_str()
        ))),
        Opened::Fresh { observed, dir } => {
            let record = StoreRecord {
                schema: STORE_SCHEMA,
                id: mint(&observed),
                key_material: observed,
                migrations: Vec::new(),
            };
            write_record(&dir, &record)?;
            write_marker(&record.key_material.common_dir, &record.id)?;
            let note = Some(format!("store {} minted", record.id));
            Ok(Bound { record, dir, note })
        }
        Opened::Stranger {
            occupant,
            observed,
            dir,
        } => {
            let record = StoreRecord {
                schema: STORE_SCHEMA,
                id: mint(&observed),
                key_material: observed,
                migrations: Vec::new(),
            };
            // The basename is taken by an unrelated repository, so this store
            // lands beside it. The suffix is a display detail — nothing resolves
            // a store by its directory name.
            let sibling = dir.with_file_name(format!(
                "{}-{}",
                record.key_material.repo_name,
                record.id.short()
            ));
            write_record(&sibling, &record)?;
            write_marker(&record.key_material.common_dir, &record.id)?;
            let note = Some(format!(
                "store {} minted beside {occupant} (same directory name, different repository)",
                record.id
            ));
            Ok(Bound {
                record,
                dir: sibling,
                note,
            })
        }
    }
}

/// One line naming what a migration moved. Pointer-only: field names, never
/// values — a recorded remote URL can carry a credential.
fn describe(migrations: &[Migration]) -> String {
    migrations
        .iter()
        .flat_map(|migration| migration.changed.iter())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `batten state adopt [store]` — bind this checkout to its store.
///
/// Resolves, then commits. With no `store` argument it binds whatever resolution
/// found, including a weak [`Opened::Candidate`] — which is the whole purpose of
/// the verb: the human running it *is* the deliberate decision the automatic path
/// refuses to make. With one, it binds that specific store and refuses if it is
/// not there, so a typo cannot silently bind the wrong one.
///
/// # Errors
///
/// Returns a [`UsageError`] when the current directory is not a git repository,
/// or when a named store does not exist.
pub fn run_adopt(store: Option<&str>, err: &mut dyn std::io::Write) -> Result<ExitCode> {
    let root = git::repo_root(Path::new("."))?;
    let opened = resolve(&root)?;

    let opened = match store {
        None => match opened {
            // The verb exists to bind exactly this case, so it is upgraded from
            // "report and refuse" to "adopt" — deliberately, by a human.
            Opened::Candidate { id, dir, criterion } => {
                match read_record(&dir).filter(|record| record.id == id) {
                    Some(record) => Opened::Adopted {
                        record,
                        dir,
                        observed: observe(&root)?,
                        criterion,
                    },
                    None => {
                        return Err(UsageError::raise(format!(
                            "the candidate store {id} is no longer readable"
                        )));
                    }
                }
            }
            other => other,
        },
        Some(named) => {
            let observed = observe(&root)?;
            let Some((dir, record)) = scan_stores()?
                .into_iter()
                .find(|(_, record)| record.id.as_str() == named)
            else {
                return Err(UsageError::raise(format!(
                    "no store with id {named} exists under this user's state directory"
                )));
            };
            // Report the honest reason, which may be "nothing matched" — an
            // operator adopting by id has overridden the criteria on purpose.
            let criterion =
                match_criterion(&record.key_material, &observed).unwrap_or(MatchCriterion::Marker);
            Opened::Adopted {
                record,
                dir,
                observed,
                criterion,
            }
        }
    };

    let bound = commit(opened)?;
    if let Some(note) = bound.note {
        writeln!(err, "batten: {note}")?;
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn material(common: &str, roots: &[&str], remotes: &[(&str, &str)], name: &str) -> KeyMaterial {
        KeyMaterial {
            common_dir: common.to_owned(),
            root_commits: roots.iter().map(|r| (*r).to_owned()).collect(),
            remotes: remotes
                .iter()
                .map(|(n, url)| Remote {
                    name: (*n).to_owned(),
                    url: (*url).to_owned(),
                    canonical_url: canonical_remote_url(url),
                })
                .collect(),
            repo_name: name.to_owned(),
        }
    }

    #[test]
    fn both_spellings_of_one_remote_canonicalize_together() {
        // `git remote set-url` between the scp-like and https forms must not
        // read as a key-material change: nothing about the repository moved.
        let scp = canonical_remote_url("git@github.com:button-inc/batten.git");
        let https = canonical_remote_url("https://github.com/button-inc/batten");
        assert_eq!(scp, https);
        assert_eq!(scp, "github.com/button-inc/batten");
    }

    #[test]
    fn canonicalizing_a_remote_drops_credentials_and_folds_the_host() {
        // Userinfo is not identity, and recording it would put a password in a
        // field this module prints the name of.
        assert_eq!(
            canonical_remote_url("https://user:secret@GitHub.com/owner/repo.git"),
            "github.com/owner/repo"
        );
        // An unrecognised form still compares equal to itself, never to
        // something else.
        assert_eq!(canonical_remote_url("/srv/git/bare"), "/srv/git/bare");
    }

    #[test]
    fn a_shared_root_commit_is_the_strongest_criterion() {
        let recorded = material("/old/.git", &["aaa"], &[], "old-name");
        let observed = material("/new/.git", &["aaa"], &[], "new-name");
        // Everything observable moved; the repository did not.
        assert_eq!(
            match_criterion(&recorded, &observed),
            Some(MatchCriterion::RootCommit)
        );
    }

    #[test]
    fn a_shared_remote_matches_when_no_root_commit_does() {
        let recorded = material("/old/.git", &[], &[("origin", "git@h:o/r.git")], "a");
        let observed = material("/new/.git", &[], &[("origin", "https://h/o/r")], "b");
        assert_eq!(
            match_criterion(&recorded, &observed),
            Some(MatchCriterion::RemoteUrl)
        );
    }

    #[test]
    fn a_shared_path_alone_is_never_identity_bearing() {
        // The disqualified scheme, held shut: a checkout can be deleted and
        // another cloned to the same path, so this must not auto-adopt.
        let recorded = material("/same/.git", &["aaa"], &[], "proj");
        let observed = material("/same/.git", &["bbb"], &[], "proj");
        let criterion = match_criterion(&recorded, &observed);
        assert_eq!(criterion, Some(MatchCriterion::CommonDir));
        assert!(!criterion.unwrap().is_identity_bearing());
    }

    #[test]
    fn a_same_named_stranger_matches_nothing() {
        // Fixture (b): two unrelated repositories sharing a basename. The name
        // is not a criterion, so nothing matches and they cannot share a store.
        let recorded = material("/a/proj/.git", &["aaa"], &[("origin", "h/one")], "proj");
        let observed = material("/b/proj/.git", &["bbb"], &[("origin", "h/two")], "proj");
        assert_eq!(match_criterion(&recorded, &observed), None);
    }

    #[test]
    fn a_rename_and_a_move_are_reported_as_changed_fields() {
        let recorded = material("/old/.git", &["aaa"], &[], "old");
        let observed = material("/new/.git", &["aaa"], &[("origin", "h/o/r")], "new");
        assert_eq!(
            changed_fields(&recorded, &observed),
            vec![
                "commonDir".to_owned(),
                "remotes".to_owned(),
                "repoName".to_owned()
            ]
        );
        // Identical material is not a migration — otherwise every ordinary run
        // would record one.
        assert!(changed_fields(&recorded, &recorded).is_empty());
    }

    #[test]
    fn a_minted_id_is_hex_and_never_repeats() {
        // Minted, not derived: the same repository facts must not reproduce the
        // same id, or the value would move when the repository moved.
        let observed = material("/repo/.git", &["aaa"], &[], "repo");
        let one = mint(&observed);
        let two = mint(&observed);
        assert_ne!(one, two);
        assert_eq!(one.as_str().len(), 64);
        assert!(one.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(one.short().len(), 8);
    }

    #[test]
    fn every_criterion_names_itself_exactly_once() {
        // The vocabulary gate: `ALL` and `as_str` must stay in step, so a new
        // criterion cannot be added without a token.
        let tokens: BTreeSet<&str> = MatchCriterion::ALL
            .iter()
            .map(|criterion| criterion.as_str())
            .collect();
        assert_eq!(tokens.len(), MatchCriterion::ALL.len());
        for criterion in MatchCriterion::ALL {
            assert!(!criterion.as_str().is_empty());
        }
    }

    #[test]
    fn source_keys_on_no_basename() {
        // The disqualified scheme, gated at the source level in the spirit of
        // `state.rs`'s own literal gate: identity is never derived from a
        // directory name, so the matcher must not reach for one. `repo_name` is
        // recorded and reported, which is why the check is on the comparison
        // helpers rather than on the whole module.
        // LINE ENDINGS NORMALIZED AT THE READ (CLOUD-612). `include_str!`
        // embeds the WORKING TREE's bytes, and there is more than one shape
        // those come in: a Windows checkout takes `core.autocrlf=true`, so
        // every line ends `\r\n` and the `"\n}\n"` terminator below matches
        // nothing at all. Measured on the first Windows run this repository
        // ever did — the slice went from 907 characters to 24318, i.e. the
        // whole rest of the file, and this gate then reported `repo_name` in a
        // function that does not mention it. On an LF checkout this is a no-op.
        let source = include_str!("store.rs").replace("\r\n", "\n");
        // The function BODY only — bounded by the first column-zero `}`, which
        // is where an item ends under this crate's formatting. A slice that ran
        // to the next `fn` would swallow that function's doc comment and fail on
        // prose rather than on code; measured, on the first run of this gate.
        //
        // `split_once`, NEVER `split(…).next()`, and that is the property rather
        // than a style preference: `next()` cannot distinguish "found the
        // terminator" from "no terminator, here is the rest of the file", so it
        // answers the second case with a silently widened body. The widening is
        // loud here because this assertion is negative; the same widening makes
        // any "the body must CONTAIN x" gate pass vacuously. Absent terminator
        // is now a panic naming the cause.
        let matcher = source
            .split_once("pub fn match_criterion")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("the matcher is in this file, and its body ends at a column-zero `}`");
        assert!(
            !matcher.contains("repo_name"),
            "match_criterion reads repo_name; basename keying merges same-named \
             strangers and splits worktree siblings (CLOUD-164)"
        );
    }
}
