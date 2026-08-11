//! The findings store's durable plumbing: append shards, a merged log with
//! `(generation, seqno)` cursors, and the store-format version (CLOUD-78).
//!
//! [`crate::store`] answers *which* store; [`crate::findings`] answers *what is
//! in it*. This answers **how it is written and read back safely** when several
//! worktrees and several processes touch it at once.
//!
//! # Shards append, merge folds, and the shards are the authority
//!
//! Every writer appends to **its own shard** (`journal/shards/<id>.jsonl`), so
//! the concurrent path has no shared mutable file and needs no lock at all.
//! Folding shards into the merged log is the only single-writer step, and it
//! takes an **OS advisory lock** — `flock`/`LockFileEx` via `fs4`, never a bare
//! lockfile. That distinction is load-bearing rather than stylistic: an advisory
//! lock is released by the kernel when the process dies, and this repository's
//! ambient ~2-minute foreground kill would otherwise strand a lockfile and brick
//! the store for every worktree, permanently, from one unlucky timeout.
//!
//! A writer that cannot take the lock is [`Merge::Busy`]. It is **not** an
//! error and must never become a deny: losing a race against another honest
//! session says nothing about the mediated call, and the entry is already
//! durable in the writer's own shard, so the next merge picks it up. The house
//! exit table stays total over `0/1/2/3` (non-negotiable rule 5) — busy is a
//! distinct *outcome*, mapped to allow at the boundary, never a fifth exit code.
//!
//! # Persist before emit
//!
//! [`append`] fsyncs before returning, so an entry an agent has been shown is
//! already on disk. The reverse order loses exactly the findings a crash makes
//! most interesting.
//!
//! # Cursors, and why a stale one resyncs rather than guesses
//!
//! A drain cursor is `(generation, seqno)`. GC does not rewrite history in
//! place, it **starts a new generation**, which invalidates every outstanding
//! cursor by construction. A cursor from another generation — or one pointing
//! past the end of this one — cannot be turned into a delta by any amount of
//! arithmetic, so [`since`] answers [`Drain::FullResync`] and hands back the
//! whole live set. Guessing a delta there would silently drop findings.
//!
//! # Versioning: no implicit upgrades
//!
//! The store records which record version it is written in. A binary **writes
//! the store's version, not its own** (`write-old`), and reads any version in
//! its supported window (`read-both`). Upgrading is only ever
//! `batten state migrate`. A binary meeting a store newer than it can write
//! enters [`Access::DegradedReadOnly`]: dedupe still works, emissions are marked
//! `persisted:false`, and the mapping is allow-with-warning — never deny, because
//! an out-of-date binary is an operator problem and refusing the agent's work is
//! not how it gets fixed.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use fs4::TryLockError;
use serde::{Deserialize, Serialize};

use crate::findings::{
    Disposition, FINDINGS_SCHEMA, FINDINGS_SCHEMA_MIN, FindingRecord, Presentation,
};
use crate::identity::Fingerprint;

/// The journal layout's own version, independent of the record schema.
pub const JOURNAL_SCHEMA: u32 = 1;

/// The journal subtree under a bound store.
const JOURNAL_DIR: &str = "journal";
/// One append-only file per writer.
const SHARDS_DIR: &str = "shards";
/// The merged log cursors index into.
const MERGED_FILE: &str = "merged.jsonl";
/// The format record: which record version this store is written in, and where
/// the merged log has got to.
const FORMAT_FILE: &str = "format.json";
/// The file the shard-merge advisory lock is taken on.
const LOCK_FILE: &str = "merge.lock";

/// The journal directory under a bound store.
fn journal_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(JOURNAL_DIR)
}

/// The directory holding one append file per writer.
fn shards_dir(store_dir: &Path) -> PathBuf {
    journal_dir(store_dir).join(SHARDS_DIR)
}

/// Where a store records the version it is written in and its merge position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Format {
    /// The journal layout version ([`JOURNAL_SCHEMA`]).
    pub schema: u32,
    /// The record version this store is **written** in. Never assumed to equal
    /// [`FINDINGS_SCHEMA`]: that is the whole point of explicit migration.
    #[serde(rename = "findingsSchema")]
    pub findings_schema: u32,
    /// The current generation. Changes on GC, invalidating every cursor.
    pub generation: String,
    /// How many entries the merged log holds in this generation.
    pub seqno: u64,
}

impl Format {
    /// The format a store is created with: this binary's record version, a fresh
    /// generation, an empty log.
    fn fresh(store_dir: &Path) -> Self {
        Format {
            schema: JOURNAL_SCHEMA,
            findings_schema: FINDINGS_SCHEMA,
            generation: mint_generation(store_dir, 0),
            seqno: 0,
        }
    }

    /// Whether this binary can write records in the store's version.
    ///
    /// Older is fine — write-old is the rolling window. Newer is not: writing a
    /// version whose fields this binary cannot represent would drop them.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.schema <= JOURNAL_SCHEMA
            && self.findings_schema <= FINDINGS_SCHEMA
            && self.findings_schema >= FINDINGS_SCHEMA_MIN
    }
}

/// A generation id: a fingerprint over the store path and a clock reading.
///
/// Irreproducible on purpose — a generation must never collide with a previous
/// one, or a stale cursor would be accepted as current and skip the resync it
/// exists to force.
fn mint_generation(store_dir: &Path, bump: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let seed = format!("{}:{now}:{}:{bump}", store_dir.display(), std::process::id());
    crate::identity::store_fingerprint(&[&seed]).to_hex()
}

/// How a binary may use this store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// The store's version is one this binary can write.
    Writable(Format),
    /// The store is newer than this binary can write. Reads still work.
    DegradedReadOnly {
        /// The format as read, so a caller can report the two versions.
        format: Format,
        /// A pointer-only reason, safe to print.
        reason: String,
    },
}

impl Access {
    /// The format, whichever access this is.
    #[must_use]
    pub const fn format(&self) -> &Format {
        match self {
            Access::Writable(format) | Access::DegradedReadOnly { format, .. } => format,
        }
    }

    /// Whether writes may be persisted. Drives the `persisted` field on every
    /// emission, so a degraded run is visible to whoever reads the output rather
    /// than looking like a successful record.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Access::Writable(_))
    }
}

/// The format file's path.
fn format_path(store_dir: &Path) -> PathBuf {
    journal_dir(store_dir).join(FORMAT_FILE)
}

/// Read the store's format, creating a fresh one if this store has none.
///
/// A store predating the journal has no format file; it is written in the oldest
/// record version by definition, and saying so is what lets `state migrate` have
/// something to upgrade *from*.
///
/// # Errors
///
/// Returns an error when the journal directory cannot be created or written.
pub fn open(store_dir: &Path) -> Result<Access> {
    let path = format_path(store_dir);
    let format = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<Format>(&text)
            .with_context(|| format!("read the store format {}", path.display()))?,
        Err(_) if legacy_records_exist(store_dir) => Format {
            schema: JOURNAL_SCHEMA,
            findings_schema: FINDINGS_SCHEMA_MIN,
            generation: mint_generation(store_dir, 0),
            seqno: 0,
        },
        Err(_) => {
            let fresh = Format::fresh(store_dir);
            write_format(store_dir, &fresh)?;
            fresh
        }
    };
    if format.is_writable() {
        return Ok(Access::Writable(format));
    }
    let reason = format!(
        "store format {}/{} is newer than this binary writes ({}/{}); run `batten state migrate` with a newer batten",
        format.schema, format.findings_schema, JOURNAL_SCHEMA, FINDINGS_SCHEMA
    );
    Ok(Access::DegradedReadOnly { format, reason })
}

/// Whether this store already holds records written before the journal existed.
fn legacy_records_exist(store_dir: &Path) -> bool {
    crate::findings::load_all(store_dir).is_ok_and(|records| !records.is_empty())
}

/// Write the format record atomically.
fn write_format(store_dir: &Path, format: &Format) -> Result<()> {
    let dir = journal_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the journal directory {}", dir.display()))?;
    let json = serde_json::to_string_pretty(format)?;
    let temp = dir.join(format!("{FORMAT_FILE}.{}.tmp", std::process::id()));
    std::fs::write(&temp, format!("{json}\n"))
        .with_context(|| format!("write the store format {}", temp.display()))?;
    std::fs::rename(&temp, format_path(store_dir))
        .with_context(|| format!("publish the store format in {}", dir.display()))?;
    Ok(())
}

/// One journalled observation of a disposition.
///
/// Pointer-only by construction: a fingerprint, a rule id, the two enum axes.
/// No matched content reaches this file, because the store never holds any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The identity this entry is about, as hex.
    pub identity: String,
    /// The rule that produced it — the key the FP rate aggregates by.
    pub rule: String,
    /// What the agent did, if it has settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    /// Whether it reached the agent.
    pub presentation: Presentation,
}

/// Append `entry` to this writer's shard, fsynced before returning.
///
/// Persist-before-emit: the caller may emit only after this returns. Appending
/// needs no lock — a shard has exactly one writer — which is what keeps the
/// concurrent path free of contention entirely.
///
/// # Errors
///
/// Returns an error when the shard cannot be created, written, or synced.
pub fn append(store_dir: &Path, shard: &str, entry: &Entry) -> Result<()> {
    let dir = shards_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the shard directory {}", dir.display()))?;
    let path = dir.join(format!("{shard}.jsonl"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open the shard {}", path.display()))?;
    let line = serde_json::to_string(entry)?;
    writeln!(file, "{line}").with_context(|| format!("append to the shard {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync the shard {}", path.display()))?;
    Ok(())
}

/// The shard id for this process in this worktree.
///
/// Per **worktree**, not per process: a shard per process would mint a file per
/// invocation and never collect them.
#[must_use]
pub fn shard_id(worktree: &Path) -> String {
    crate::identity::store_fingerprint(&[&worktree.display().to_string()]).to_hex()
}

/// What a merge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merge {
    /// The merge ran. Carries the format as it now stands.
    Merged {
        /// The post-merge format, with the advanced `seqno`.
        format: Format,
        /// How many entries were folded in this round.
        applied: usize,
    },
    /// Another process holds the merge lock.
    ///
    /// Never an error and never a deny: the entries are already durable in their
    /// shards and the next merge folds them.
    Busy,
}

/// Read every shard's entries, in a deterministic order.
fn read_shards(store_dir: &Path) -> Result<Vec<Entry>> {
    let dir = shards_dir(store_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    // Sorted by shard path so a merge is a pure function of the shard contents,
    // never of `read_dir` order (§6 byte-stability).
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    paths.sort();

    let mut all = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read the shard {}", path.display()))?;
        // A torn trailing line is dropped rather than failing the merge: the
        // writer will re-append it, and refusing to merge every other shard over
        // one partial write would make a crash contagious.
        all.extend(text.lines().filter_map(|line| {
            serde_json::from_str::<Entry>(line).ok()
        }));
    }
    Ok(all)
}

/// Fold every shard into the records and the merged log, under an advisory lock.
///
/// Idempotent by the merge rule: replaying the same shards applies the same
/// disposition join and lands the same records, so a merge that raced and lost
/// costs nothing but a repeat.
///
/// # Errors
///
/// Returns an error when the lock file, a shard, a record, or the format cannot
/// be read or written.
pub fn merge(store_dir: &Path) -> Result<Merge> {
    let dir = journal_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the journal directory {}", dir.display()))?;
    let lock_path = dir.join(LOCK_FILE);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open the merge lock {}", lock_path.display()))?;
    // try_lock, never a blocking lock: a caller on the hook path has a latency
    // budget, and waiting on another session's merge would spend it on work that
    // session is already doing. `WouldBlock` is the busy *outcome*; a genuine
    // I/O error on the lock file is still an error, because that is Batten
    // failing rather than another session winning.
    // Fully qualified deliberately: `std::fs::File::try_lock` was stabilized in
    // 1.89 with the same name, and an inherent method would silently win over
    // the trait once the MSRV moves. Naming the trait pins which lock this is.
    match fs4::FileExt::try_lock(&lock) {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(Merge::Busy),
        Err(TryLockError::Error(err)) => {
            return Err(anyhow::Error::from(err))
                .with_context(|| format!("take the merge lock {}", lock_path.display()));
        }
    }

    let entries = read_shards(store_dir)?;
    let mut applied = 0;
    for entry in &entries {
        let Ok(fingerprint) = Fingerprint::from_hex(&entry.identity) else {
            continue;
        };
        let Some(mut record) = crate::findings::load_one(store_dir, fingerprint)? else {
            // An entry for an identity with no record is not an error: the
            // record may be GC'd, or the scan that mints it may not have run
            // here yet. Dropping the entry silently would lose a disposition, so
            // it stays in the shard and is folded when the record appears.
            continue;
        };
        record.merge_disposition(entry.disposition);
        record.presentation = entry.presentation;
        crate::findings::save_one(store_dir, &record)?;
        applied += 1;
    }

    let mut format = match open(store_dir)? {
        Access::Writable(format) => format,
        Access::DegradedReadOnly { format, .. } => {
            // A degraded binary reads and dedupes but must not advance the log.
            drop(lock);
            return Ok(Merge::Merged { format, applied: 0 });
        }
    };
    write_merged(store_dir, &entries)?;
    format.seqno = entries.len() as u64;
    write_format(store_dir, &format)?;
    // Explicit: the lock is released here, after the format is published, so a
    // racing merger never reads a log and a format that disagree.
    drop(lock);
    Ok(Merge::Merged { format, applied })
}

/// The merged log's path.
fn merged_path(store_dir: &Path) -> PathBuf {
    journal_dir(store_dir).join(MERGED_FILE)
}

/// Rewrite the merged log for this generation.
fn write_merged(store_dir: &Path, entries: &[Entry]) -> Result<()> {
    let dir = journal_dir(store_dir);
    let temp = dir.join(format!("{MERGED_FILE}.{}.tmp", std::process::id()));
    let mut body = String::new();
    for entry in entries {
        body.push_str(&serde_json::to_string(entry)?);
        body.push('\n');
    }
    std::fs::write(&temp, body)
        .with_context(|| format!("write the merged log {}", temp.display()))?;
    std::fs::rename(&temp, merged_path(store_dir))
        .with_context(|| format!("publish the merged log in {}", dir.display()))?;
    Ok(())
}

/// A drain position: which generation, and how far into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The generation this cursor was issued in.
    pub generation: String,
    /// How many entries of that generation the holder has seen.
    pub seqno: u64,
}

/// What a drain gets back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drain {
    /// The cursor was current: here is what has happened since.
    Delta {
        /// The entries after the cursor's position.
        entries: Vec<Entry>,
        /// Where the holder now is.
        cursor: Cursor,
    },
    /// The cursor cannot be honoured — wrong generation, or past the end. Here
    /// is the whole live set and a fresh cursor.
    FullResync {
        /// Every entry in the current generation.
        entries: Vec<Entry>,
        /// The cursor to hold from now on.
        cursor: Cursor,
        /// Why the resync happened, as a pointer-only reason.
        reason: String,
    },
}

impl Drain {
    /// The cursor to hold next, whichever answer this is.
    #[must_use]
    pub const fn cursor(&self) -> &Cursor {
        match self {
            Drain::Delta { cursor, .. } | Drain::FullResync { cursor, .. } => cursor,
        }
    }

    /// The entries to act on, whichever answer this is.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        match self {
            Drain::Delta { entries, .. } | Drain::FullResync { entries, .. } => entries,
        }
    }
}

/// Read the merged log's current contents.
fn read_merged(store_dir: &Path) -> Result<Vec<Entry>> {
    let path = merged_path(store_dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .collect())
}

/// Everything after `cursor`, or a full resync when it cannot be honoured.
///
/// `None` is a first drain, which is a resync by definition — a holder with no
/// cursor has seen nothing and must be told everything.
///
/// # Errors
///
/// Returns an error when the format or the merged log cannot be read.
pub fn since(store_dir: &Path, cursor: Option<&Cursor>) -> Result<Drain> {
    let format = open(store_dir)?.format().clone();
    let entries = read_merged(store_dir)?;
    let current = Cursor {
        generation: format.generation.clone(),
        seqno: entries.len() as u64,
    };

    let resync = |reason: &str| Drain::FullResync {
        entries: entries.clone(),
        cursor: current.clone(),
        reason: reason.to_owned(),
    };

    let Some(cursor) = cursor else {
        return Ok(resync("no cursor"));
    };
    if cursor.generation != format.generation {
        // The generation changed under the holder, so no arithmetic on `seqno`
        // means anything. This is the GC handshake.
        return Ok(resync("generation changed"));
    }
    let Ok(seen) = usize::try_from(cursor.seqno) else {
        return Ok(resync("cursor out of range"));
    };
    if seen > entries.len() {
        // Ahead of the log: the log was rewritten shorter. Never a negative
        // delta — resync instead of inventing one.
        return Ok(resync("cursor past the end of the log"));
    }
    Ok(Drain::Delta {
        entries: entries[seen..].to_vec(),
        cursor: current,
    })
}

/// Start a new generation, invalidating every outstanding cursor.
///
/// GC's half of the handshake. Called after records are collected, so a holder
/// that resyncs sees the post-GC world rather than a delta that references
/// records which no longer exist.
///
/// # Errors
///
/// Returns an error when the format or the merged log cannot be written.
pub fn new_generation(store_dir: &Path) -> Result<Format> {
    let mut format = match open(store_dir)? {
        Access::Writable(format) => format,
        // A degraded binary must not rotate a generation it cannot write.
        Access::DegradedReadOnly { format, .. } => return Ok(format),
    };
    format.generation = mint_generation(store_dir, format.seqno.wrapping_add(1));
    format.seqno = 0;
    write_merged(store_dir, &[])?;
    write_format(store_dir, &format)?;
    Ok(format)
}

/// What a migration did, as pointer-only counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Migrated {
    /// Records rewritten into the current version.
    pub records: usize,
    /// The version the store was written in before.
    pub from: u32,
    /// The version it is written in now.
    pub to: u32,
}

/// Upgrade the store to this binary's record version. The **only** upgrade path.
///
/// Explicit because an implicit upgrade on a read path would rewrite a store
/// that an older binary in another worktree is still using, turning a routine
/// `check` into an outage for a sibling session.
///
/// # Errors
///
/// Returns an error when the store is newer than this binary, or when a record
/// or the format cannot be read or written.
pub fn migrate(store_dir: &Path) -> Result<Migrated> {
    let format = match open(store_dir)? {
        Access::Writable(format) => format,
        Access::DegradedReadOnly { reason, .. } => {
            return Err(crate::error::UsageError::raise(reason));
        }
    };
    let from = format.findings_schema;
    if from == FINDINGS_SCHEMA {
        return Ok(Migrated {
            records: 0,
            from,
            to: FINDINGS_SCHEMA,
        });
    }
    let mut records = 0;
    for mut record in crate::findings::load_all(store_dir)? {
        record.schema = FINDINGS_SCHEMA;
        crate::findings::save_one(store_dir, &record)?;
        records += 1;
    }
    let upgraded = Format {
        findings_schema: FINDINGS_SCHEMA,
        ..format
    };
    write_format(store_dir, &upgraded)?;
    Ok(Migrated {
        records,
        from,
        to: FINDINGS_SCHEMA,
    })
}

/// Drop shard files for worktrees that no longer exist.
///
/// Shards are keyed by worktree, and worktrees here are ephemeral; without this
/// the shard directory grows without bound. Entries are already folded into the
/// records by then, so nothing is lost.
///
/// # Errors
///
/// Returns an error when a shard cannot be removed.
pub fn gc_shards(store_dir: &Path, live: &BTreeSet<String>) -> Result<usize> {
    let dir = shards_dir(store_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(0);
    };
    let mut dropped = 0;
    for path in entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
    {
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if live.contains(stem) {
            continue;
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("remove the shard {}", path.display()))?;
        dropped += 1;
    }
    Ok(dropped)
}

/// A pointer line per record: `<identity> <rule> <disposition> <presentation>`.
///
/// Pointer-only (rule 4).
#[must_use]
pub fn disposition_lines(records: &[FindingRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            let disposition = record.disposition.map_or("unsettled", Disposition::as_str);
            let presentation = match record.presentation {
                Presentation::Shown => "shown",
                Presentation::NotShown(_) => "not-shown",
            };
            format!(
                "{} {} {disposition} {presentation}",
                record.identity.fingerprint.to_hex(),
                record.rule
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::findings::{Context, FINDINGS_SCHEMA, Instance, NotShown, Observation};
    use crate::identity::{FindingKind, SpanNormalization, StoredIdentity, code_fingerprint};
    use crate::severity::{AdvisoryTier, RuleSeverity};

    fn store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "batten-journal-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn identity_for(span: &str) -> StoredIdentity {
        StoredIdentity::new(
            FindingKind::Code,
            code_fingerprint("r", "src/a.rs", span, SpanNormalization::Collapsed).unwrap(),
        )
    }

    fn record_for(span: &str) -> FindingRecord {
        FindingRecord {
            schema: FINDINGS_SCHEMA,
            identity: identity_for(span),
            rule: "r".to_owned(),
            severity: RuleSeverity::Deny,
            tier: AdvisoryTier::Warning,
            disposition: None,
            presentation: Presentation::Shown,
            instances: vec![Instance {
                context: Context::new("refs/heads/a"),
                occurrences: Observation::Observed(1),
                observed_at_commit: "0".repeat(40),
                worktree_path: None,
                path: "src/a.rs".to_owned(),
                line: Some(1),
            }],
        }
    }

    fn entry_for(span: &str, disposition: Disposition) -> Entry {
        Entry {
            identity: identity_for(span).fingerprint.to_hex(),
            rule: "r".to_owned(),
            disposition: Some(disposition),
            presentation: Presentation::Shown,
        }
    }

    #[test]
    fn conflicting_shards_converge_in_either_order() {
        // Acceptance (a): the precedence join is commutative, so two worktrees
        // racing to settle one finding land the same store whichever merges
        // first. Driven through the real shard files, not the enum alone.
        let mut settled = Vec::new();
        for order in [
            [Disposition::RejectedWrong, Disposition::Acted],
            [Disposition::Acted, Disposition::RejectedWrong],
        ] {
            let dir = store(&format!("converge-{}", order[0].as_str()));
            crate::findings::save_one(&dir, &record_for("TODO")).unwrap();
            append(&dir, "shard-a", &entry_for("TODO", order[0])).unwrap();
            append(&dir, "shard-b", &entry_for("TODO", order[1])).unwrap();
            assert!(matches!(merge(&dir).unwrap(), Merge::Merged { .. }));
            let records = crate::findings::load_all(&dir).unwrap();
            settled.push(records[0].disposition);
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert_eq!(settled[0], settled[1], "the merge must commute");
        assert_eq!(
            settled[0],
            Some(Disposition::Acted),
            "acted outranks rejected-wrong"
        );
    }

    #[test]
    fn a_second_merge_of_the_same_shards_changes_nothing() {
        // Idempotence, the other half of the join law: a merge that raced and
        // lost is safe to repeat.
        let dir = store("idempotent");
        crate::findings::save_one(&dir, &record_for("TODO")).unwrap();
        append(&dir, "shard-a", &entry_for("TODO", Disposition::RejectedByDesign)).unwrap();
        merge(&dir).unwrap();
        let first = crate::findings::load_all(&dir).unwrap();
        merge(&dir).unwrap();
        let second = crate::findings::load_all(&dir).unwrap();
        assert_eq!(first, second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_lock_reports_busy_and_never_an_error() {
        // Lock contention must be an outcome, not a failure: the entries are
        // already durable, and a hook that turned this into a deny would refuse
        // an honest session over a race.
        let dir = store("busy");
        std::fs::create_dir_all(journal_dir(&dir)).unwrap();
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(journal_dir(&dir).join(LOCK_FILE))
            .unwrap();
        fs4::FileExt::try_lock(&held).unwrap();
        assert_eq!(merge(&dir).unwrap(), Merge::Busy);
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_generation_forces_a_full_resync() {
        // Acceptance (d): a cursor from a dead generation cannot be turned into
        // a delta, so the handshake hands back everything.
        let dir = store("resync");
        crate::findings::save_one(&dir, &record_for("TODO")).unwrap();
        append(&dir, "shard-a", &entry_for("TODO", Disposition::Acted)).unwrap();
        merge(&dir).unwrap();

        let first = since(&dir, None).unwrap();
        assert!(matches!(first, Drain::FullResync { .. }), "no cursor resyncs");
        let cursor = first.cursor().clone();

        // Caught up: nothing new.
        let caught_up = since(&dir, Some(&cursor)).unwrap();
        assert!(matches!(caught_up, Drain::Delta { .. }));
        assert!(caught_up.entries().is_empty());

        // GC rotates the generation, and the same cursor is now unusable.
        new_generation(&dir).unwrap();
        let after = since(&dir, Some(&cursor)).unwrap();
        assert!(
            matches!(after, Drain::FullResync { .. }),
            "a cursor from a dead generation must resync, never delta"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cursor_past_the_end_resyncs_rather_than_underflowing() {
        let dir = store("past-end");
        merge(&dir).unwrap();
        let format = open(&dir).unwrap().format().clone();
        let ahead = Cursor {
            generation: format.generation,
            seqno: 99,
        };
        assert!(matches!(
            since(&dir, Some(&ahead)).unwrap(),
            Drain::FullResync { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_store_is_read_only_never_an_error() {
        // Degraded read-only: dedupe keeps working, writes do not, and nothing
        // on this path denies.
        let dir = store("degraded");
        write_format(
            &dir,
            &Format {
                schema: JOURNAL_SCHEMA,
                findings_schema: FINDINGS_SCHEMA + 1,
                generation: "f".repeat(64),
                seqno: 0,
            },
        )
        .unwrap();
        let access = open(&dir).unwrap();
        assert!(!access.is_writable());
        assert!(matches!(access, Access::DegradedReadOnly { .. }));
        // A merge against it must not advance the log.
        assert!(matches!(
            merge(&dir).unwrap(),
            Merge::Merged { applied: 0, .. }
        ));
        // And migrating down is refused rather than silently truncating fields.
        assert!(migrate(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_upgrades_an_older_store_and_is_the_only_upgrade() {
        let dir = store("migrate");
        // A store written in the oldest version, holding one record.
        let mut old = record_for("TODO");
        old.schema = FINDINGS_SCHEMA_MIN;
        crate::findings::save_one(&dir, &old).unwrap();
        write_format(
            &dir,
            &Format {
                schema: JOURNAL_SCHEMA,
                findings_schema: FINDINGS_SCHEMA_MIN,
                generation: "a".repeat(64),
                seqno: 0,
            },
        )
        .unwrap();

        // Opening does NOT upgrade it — that is the no-implicit-upgrade law.
        assert_eq!(
            open(&dir).unwrap().format().findings_schema,
            FINDINGS_SCHEMA_MIN
        );

        let migrated = migrate(&dir).unwrap();
        assert_eq!(migrated.from, FINDINGS_SCHEMA_MIN);
        assert_eq!(migrated.to, FINDINGS_SCHEMA);
        assert_eq!(migrated.records, 1);
        assert_eq!(open(&dir).unwrap().format().findings_schema, FINDINGS_SCHEMA);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shards_are_dropped_when_their_worktree_dies() {
        let dir = store("shard-gc");
        append(&dir, "alive", &entry_for("TODO", Disposition::Acted)).unwrap();
        append(&dir, "dead", &entry_for("TODO", Disposition::Acted)).unwrap();
        let live: BTreeSet<String> = ["alive".to_owned()].into_iter().collect();
        assert_eq!(gc_shards(&dir, &live).unwrap(), 1);
        assert_eq!(gc_shards(&dir, &live).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_shard_id_is_stable_per_worktree() {
        // Per worktree, not per process: a per-process id would mint a shard
        // file per invocation and GC none of them.
        let path = Path::new("/tmp/wt");
        assert_eq!(shard_id(path), shard_id(path));
        assert_ne!(shard_id(path), shard_id(Path::new("/tmp/other")));
    }

    #[test]
    fn a_not_shown_entry_round_trips_its_reason() {
        let entry = Entry {
            identity: identity_for("TODO").fingerprint.to_hex(),
            rule: "r".to_owned(),
            disposition: None,
            presentation: Presentation::NotShown(NotShown::OverCardinalityCap),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert_eq!(serde_json::from_str::<Entry>(&json).unwrap(), entry);
    }
}
