//! Session lineage and the durable resume point a warm fork reads (CLOUD-83).
//!
//! [`crate::store`] answers *which* store, [`crate::findings`] answers *what is
//! in it*, and [`crate::journal`] answers *how it is written and read back*. This
//! answers the fourth question those three leave open: **who is reading, and how
//! far have they got** — the pair of facts a restart needs and a process cannot
//! keep.
//!
//! # What a warm fork is, and what it costs
//!
//! A warm fork abandons the current trajectory while keeping the working state:
//! the checkout, the findings store, the committed defect ledger. Almost all of
//! that survives for free, because none of it is in the forked process — the
//! store is out of tree ([`crate::state`]), [`crate::journal::append`] fsyncs
//! before returning, and the ledger is a tracked file. Survival is **inherited**,
//! never copied at restart time.
//!
//! Two things are not inherited, and they are what this module records.
//!
//! ## 1. The resume point
//!
//! A drain cursor is a `(generation, seqno)` pair that [`crate::journal::since`]
//! turns into a delta. Nothing persisted one, so every restart began with `None`
//! — which [`crate::journal::since`] correctly answers with
//! [`crate::journal::Drain::FullResync`], re-handing the successor the whole live
//! set. Correct, and exactly the re-emission a fork must not pay for. A cursor
//! stored beside the journal makes the resume a delta again, and a generation
//! rotation still forces the resync, because the stored cursor is checked by the
//! same function that always checked it.
//!
//! ## 2. The sequence kind's session
//!
//! [`crate::identity::sequence_fingerprint`] puts the session **in the tuple by
//! default**, deliberately: a session-less key would fold a second session's
//! deny-then-bypass into a duplicate increment on an open finding, dedup'ing away
//! the alert the kind exists to raise. The cost is that a fork carrying a new
//! session key mints a *different* identity for the same open incident, so the
//! finding does not follow the trajectory that inherited it.
//!
//! The fix is a lineage edge, and the resolution rule CLOUD-83 records as its
//! stated assumption: **a fork continues its parent's session key.** The fork
//! inherits the working state, so it inherits the open sequence findings.
//! [`root`] walks the chain and returns the key every descendant hashes with.
//!
//! The code, log and scope kinds need none of this and must never grow it: their
//! tuples carry no session at all, which is what makes them survive a restart by
//! construction rather than by bookkeeping.
//!
//! # A fork declares itself; nothing infers one
//!
//! Only the thing performing the fork knows a fork happened. Two sessions running
//! one after another in one worktree are indistinguishable from a fork by any
//! observation the store can make, and chaining them would silently carry an open
//! incident into an unrelated trajectory — a false continuation, in the direction
//! that hides an alert.
//!
//! So the parent is **declared**, through [`PARENT_ENV`]. A warm fork inherits its
//! parent's environment — that inheritance is what makes it warm — which makes the
//! environment the honest channel and costs no new command, no new flag, and no
//! change to the hook envelope (CLOUD-83 §3). Absent, a session is its own root
//! and nothing is written: unconfigured is silent, [`crate::transcript`]'s law.
//!
//! These are bare consts rather than a [`crate::resolve`] `SETTINGS` row because
//! they are ambient context, not settings: there is no config-file spelling for
//! "which session is this", so there is no precedence ladder to declare. It is the
//! shape [`crate::hook::BYPASS_ENV`] already takes.
//!
//! # The record, and why it is keyed the way it is
//!
//! One file per session under `sessions/`, named by a fingerprint of the key
//! rather than by the key: a host session id is opaque, arbitrary-length, and
//! chosen by someone else, so using it as a filename would let a host decide this
//! crate's path layout. The raw key is kept *inside* the record, where
//! [`crate::identity::sequence_fingerprint`] needs it.
//!
//! Cursors are keyed on the **lineage root**, which is what makes a fork read its
//! parent's position, and sub-keyed by a `holder` string so two readers of one
//! journal do not share a position. That second key is load-bearing rather than
//! defensive: a shared cursor would let one caller mark entries seen that never
//! reached an agent, and the drain would then skip exactly the findings it exists
//! to emit. `state record` holds [`HOLDER_RECORD`]; the drain (CLOUD-79) declares
//! its own when it lands.
//!
//! # Reads never write, and a parent is never rewritten
//!
//! [`root`] and [`load_cursor`] read only, so a read-effect verb that resolves a
//! session does not become a writer. [`observe`] is the write half. It records a
//! parent on first sight and **never overwrites one**: ancestry is a fact about a
//! fork that already happened, and rewriting it would relink a chain under a
//! reader holding the old root. An unreadable or future-schema record reads as
//! absent, the fail-closed posture [`crate::findings`] and [`crate::store`] take.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::journal::Cursor;

/// The on-disk record's schema version, its own number for the same reason every
/// other store record has one: this shape and the findings shape move for
/// unrelated reasons.
pub const SESSION_SCHEMA: u32 = 1;

/// The host's id for the session this process serves.
pub const SESSION_ENV: &str = "BATTEN_SESSION";

/// The session a warm fork was forked from. Absent means "not a fork".
pub const PARENT_ENV: &str = "BATTEN_SESSION_PARENT";

/// The cursor holder `state record` advances: its own journal-fold position.
///
/// Never the drain's. `state record` folds shards whether or not anything was
/// emitted to an agent, so a cursor it advanced would mark findings seen that
/// nobody saw.
pub const HOLDER_RECORD: &str = "record";

/// The subdirectory holding one file per session.
const SESSIONS_DIR: &str = "sessions";

/// How far [`root`] will walk before it stops and says so.
///
/// A bound rather than a cycle set because both failures want the same answer:
/// stop, report, do not error. A chain this long is a bug in whatever wrote it,
/// and a mutually-referencing pair is the same bug with two rows.
const MAX_LINEAGE: usize = 64;

/// The sessions directory under a bound store.
fn sessions_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(SESSIONS_DIR)
}

/// The file a session's record lives in.
///
/// Named by a fingerprint of the key rather than the key itself: the key is a
/// host's opaque string, and letting it name a file would hand a host control of
/// this crate's path layout — length, separators and all.
fn record_path(store_dir: &Path, session: &str) -> PathBuf {
    let name = crate::identity::store_fingerprint(&["session", session]).to_hex();
    sessions_dir(store_dir).join(format!("{name}.json"))
}

/// Which session this process serves, and which one it forked from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    /// The host's id for this session.
    pub key: String,
    /// The session this one forked from, when it is a fork.
    pub parent: Option<String>,
}

/// The declared session, read from `env`.
///
/// `None` when [`SESSION_ENV`] is unset or empty — a repository whose host does
/// not supply a session is not configured for this, and an empty value is how a
/// CI file clears one (the reading [`crate::output`] already takes).
///
/// A parent that names the session itself is dropped rather than recorded: a
/// self-edge is the one lineage a bounded walk cannot shorten, and it is always a
/// mistake in the caller's environment rather than a fork.
pub fn declared_with_env(env: &dyn Fn(&str) -> Option<String>) -> Option<Declared> {
    let key = env(SESSION_ENV).filter(|value| !value.is_empty())?;
    let parent = env(PARENT_ENV)
        .filter(|value| !value.is_empty())
        .filter(|value| value != &key);
    Some(Declared { key, parent })
}

/// The declared session, read from the process environment.
#[must_use]
pub fn declared() -> Option<Declared> {
    declared_with_env(&|name| std::env::var(name).ok())
}

/// One session's durable record: its ancestry and where its readers have got to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The on-disk format version ([`SESSION_SCHEMA`]).
    pub schema: u32,
    /// The host's key for this session, verbatim — what
    /// [`crate::identity::sequence_fingerprint`] hashes.
    pub session: String,
    /// The session this one forked from. Write-once; see [`observe`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Where each holder has read to, keyed by holder. A `BTreeMap` so the file
    /// is byte-stable whatever order holders write in.
    #[serde(default)]
    pub cursors: BTreeMap<String, Cursor>,
    /// What the drain last told this lineage, and how many cycles it has run
    /// (CLOUD-166).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watermark: Option<Watermark>,
}

/// One drain cycle's durable trace: which cycle it was, and what it said.
///
/// **On the lineage record rather than beside the wake state, and that is the
/// whole point.** The wake state is per session and a warm fork does not inherit
/// it, so a fork would re-emit the set its parent had just shown — the
/// re-listing the short-circuit exists to prevent, at exactly the moment an agent
/// has least context to spare. Stored on the root's record, the resume point is
/// the one CLOUD-83's lineage already carries.
///
/// Pointer-only: an ordinal and a digest, no finding content, so this stays a
/// record about *reports* rather than about findings (rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    /// How many drain cycles this lineage has run.
    ///
    /// Advances on **every** cycle, including one the `resultId` short-circuited
    /// — which is what makes "persistence is never skipped" a fact something can
    /// read rather than a claim. An ordinal that moved only when the payload
    /// moved could not tell a repeated cycle from a cycle that never happened,
    /// and the flap rate CLOUD-165 measures needs the first number as its
    /// denominator.
    pub scan: u64,
    /// The `resultId` that cycle computed, as hex. The short-circuit compares
    /// against this and nothing else, so there is one authority for "what did we
    /// last say".
    #[serde(rename = "resultId")]
    pub result_id: String,
}

impl Watermark {
    /// The watermark a cycle computing `result_id` leaves behind `previous`.
    ///
    /// Saturating rather than wrapping: a lineage that somehow reached `u64::MAX`
    /// cycles should stop counting rather than claim to be its own first drain.
    #[must_use]
    pub fn next(previous: Option<&Watermark>, result_id: String) -> Self {
        Watermark {
            scan: previous.map_or(0, |mark| mark.scan).saturating_add(1),
            result_id,
        }
    }
}

impl SessionRecord {
    /// A record for a session seen for the first time.
    fn fresh(session: &str, parent: Option<&str>) -> Self {
        SessionRecord {
            schema: SESSION_SCHEMA,
            session: session.to_owned(),
            parent: parent.map(ToOwned::to_owned),
            cursors: BTreeMap::new(),
            watermark: None,
        }
    }
}

/// Read one record, treating anything unreadable as **absent**.
///
/// Fail-closed, matching [`crate::findings`] and [`crate::store`]: a truncated or
/// future-schema record is not partially trusted. Absent routes to "this session
/// is its own root, with no cursor", which re-syncs — the safe direction, since a
/// half-read cursor would skip findings.
fn read_record(path: &Path) -> Option<SessionRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: SessionRecord = serde_json::from_str(&text).ok()?;
    (record.schema == SESSION_SCHEMA).then_some(record)
}

/// Write one record atomically, so a concurrent worktree never reads a torn file.
fn write_record(store_dir: &Path, record: &SessionRecord) -> Result<()> {
    let dir = sessions_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the sessions directory {}", dir.display()))?;
    let path = record_path(store_dir, &record.session);
    let json = serde_json::to_string_pretty(record)?;
    let temp = dir.join(format!(
        "{}.{}.tmp",
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("session"),
        std::process::id()
    ));
    std::fs::write(&temp, format!("{json}\n"))
        .with_context(|| format!("write the session record {}", temp.display()))?;
    std::fs::rename(&temp, &path)
        .with_context(|| format!("publish the session record in {}", dir.display()))?;
    Ok(())
}

/// One session's record, or `None` when this store has never seen it.
///
/// # Errors
///
/// Infallible today; the signature matches the rest of the store's readers so a
/// caller handles them the same way.
pub fn load(store_dir: &Path, session: &str) -> Result<Option<SessionRecord>> {
    Ok(read_record(&record_path(store_dir, session)))
}

/// What [`observe`] did, as a pointer-only outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    /// The session had no record; one was written.
    Minted,
    /// The session already had a record and it already said this.
    Unchanged,
    /// A parent was recorded on a session that had none.
    Linked,
    /// A parent was declared that contradicts the recorded one, and the
    /// **recorded one stands**. Reported so the disagreement is visible rather
    /// than silently resolved in either direction.
    ParentConflict,
}

/// Record `declared`'s session and, on first sight, its parent.
///
/// The write half. Idempotent: an unchanged declaration rewrites nothing, so
/// repeated calls in one session cost one read.
///
/// A parent is **write-once**. A second, different parent is
/// [`Observed::ParentConflict`] and changes nothing: the recorded ancestry is what
/// existing cursors and sequence identities were resolved against, and relinking
/// it under them would move findings between trajectories after the fact.
///
/// # Errors
///
/// Returns an error when the record cannot be written or published.
pub fn observe(store_dir: &Path, declared: &Declared) -> Result<Observed> {
    let existing = read_record(&record_path(store_dir, &declared.key));
    match (existing, declared.parent.as_deref()) {
        (None, parent) => {
            write_record(store_dir, &SessionRecord::fresh(&declared.key, parent))?;
            Ok(Observed::Minted)
        }
        (Some(record), None) => {
            let _ = record;
            Ok(Observed::Unchanged)
        }
        (Some(record), Some(parent)) => match record.parent.as_deref() {
            Some(recorded) if recorded == parent => Ok(Observed::Unchanged),
            Some(_) => Ok(Observed::ParentConflict),
            None => {
                let linked = SessionRecord {
                    parent: Some(parent.to_owned()),
                    ..record
                };
                write_record(store_dir, &linked)?;
                Ok(Observed::Linked)
            }
        },
    }
}

/// Where a lineage walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// The key every session in this chain shares — what a sequence identity
    /// hashes and what a cursor is stored under.
    pub key: String,
    /// How many edges were walked to reach it. `0` for a session that is its own
    /// root, which is the ordinary un-forked case.
    pub depth: usize,
    /// Whether the walk stopped at [`MAX_LINEAGE`] rather than at a root.
    ///
    /// A cycle or an absurdly long chain lands here. The key returned is the
    /// deepest one reached, which is deterministic and usable — never an error,
    /// because there is no recovery a caller could perform that this has not
    /// already performed, and never a panic.
    pub truncated: bool,
}

impl Root {
    /// The lineage root as a short pointer, for a report.
    ///
    /// The fingerprint's prefix rather than the key: a host session id is
    /// somebody else's string, and a pointer is what output owes (rule 4).
    #[must_use]
    pub fn short(&self) -> String {
        let hex = crate::identity::store_fingerprint(&["session", &self.key]).to_hex();
        hex.get(..8).unwrap_or(&hex).to_owned()
    }
}

/// Walk `session`'s lineage to its root.
///
/// **Reads only.** A session with no record is its own root, so this answers for
/// a store that has never seen it without writing one.
///
/// # Errors
///
/// Infallible today; the signature matches the rest of the store's readers.
pub fn root(store_dir: &Path, session: &str) -> Result<Root> {
    let mut key = session.to_owned();
    for depth in 0..MAX_LINEAGE {
        let Some(record) = read_record(&record_path(store_dir, &key)) else {
            return Ok(Root {
                key,
                depth,
                truncated: false,
            });
        };
        let Some(parent) = record.parent else {
            return Ok(Root {
                key,
                depth,
                truncated: false,
            });
        };
        if parent == key {
            // A self-edge cannot be shortened. `declared_with_env` drops these,
            // so reaching one means a record was written by something else.
            return Ok(Root {
                key,
                depth,
                truncated: false,
            });
        }
        key = parent;
    }
    Ok(Root {
        key,
        depth: MAX_LINEAGE,
        truncated: true,
    })
}

/// The session key a sequence-kind identity must hash for `session`.
///
/// The lineage root, which is the whole of CLOUD-83's fork-continuity rule: an
/// open deny-then-bypass finding minted by the parent keeps its identity in every
/// descendant, so it follows the trajectory that inherited the working state.
///
/// # Errors
///
/// Propagates [`root`]'s.
pub fn sequence_session(store_dir: &Path, session: &str) -> Result<String> {
    Ok(root(store_dir, session)?.key)
}

/// Where `holder` has read to in `root`'s lineage, if it has read at all.
///
/// **Reads only.** `None` is a first read, which [`crate::journal::since`] answers
/// with a full resync — the correct reading, and the one a fork must avoid paying
/// for by having its parent's cursor to find here.
///
/// # Errors
///
/// Infallible today; the signature matches the rest of the store's readers.
pub fn load_cursor(store_dir: &Path, root: &Root, holder: &str) -> Result<Option<Cursor>> {
    Ok(read_record(&record_path(store_dir, &root.key))
        .and_then(|record| record.cursors.get(holder).cloned()))
}

/// Record that `holder` has read to `cursor` in `root`'s lineage.
///
/// Stored on the **root's** record, never the calling session's, so every
/// descendant of one fork chain shares one position. Mints the root's record when
/// there is none — a store can be asked to remember a position for a session it
/// has not otherwise seen, and refusing would lose the position rather than
/// protect anything.
///
/// # Errors
///
/// Returns an error when the record cannot be written or published.
pub fn save_cursor(store_dir: &Path, root: &Root, holder: &str, cursor: &Cursor) -> Result<()> {
    let mut record = read_record(&record_path(store_dir, &root.key))
        .unwrap_or_else(|| SessionRecord::fresh(&root.key, None));
    record.cursors.insert(holder.to_owned(), cursor.clone());
    write_record(store_dir, &record)
}

/// What the drain last told `root`'s lineage, if it has spoken at all.
///
/// **Reads only.** `None` is a first drain for this lineage, which cannot
/// short-circuit — the honest answer, and the one a fork avoids paying for by
/// finding its parent's watermark here.
///
/// # Errors
///
/// Infallible today; the signature matches the rest of the store's readers.
pub fn load_watermark(store_dir: &Path, root: &Root) -> Result<Option<Watermark>> {
    Ok(read_record(&record_path(store_dir, &root.key)).and_then(|record| record.watermark))
}

/// Record what the drain said this cycle, on `root`'s record.
///
/// Stored on the **root's**, never the calling session's, for the same reason a
/// cursor is: every descendant of one fork chain shares one position, so a fork
/// does not re-emit what its parent already showed. Mints the root's record when
/// there is none.
///
/// # Errors
///
/// Returns an error when the record cannot be written or published.
pub fn save_watermark(store_dir: &Path, root: &Root, watermark: &Watermark) -> Result<()> {
    let mut record = read_record(&record_path(store_dir, &root.key))
        .unwrap_or_else(|| SessionRecord::fresh(&root.key, None));
    record.watermark = Some(watermark.clone());
    write_record(store_dir, &record)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "batten-session-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn declared_of(key: &str, parent: Option<&str>) -> Declared {
        Declared {
            key: key.to_owned(),
            parent: parent.map(ToOwned::to_owned),
        }
    }

    /// Record a chain `keys[0]` <- `keys[1]` <- … , each forked from the one
    /// before it, as separate `observe` calls the way separate processes would.
    fn chain(dir: &Path, keys: &[&str]) {
        for pair in keys.windows(2) {
            observe(dir, &declared_of(pair[1], Some(pair[0]))).unwrap();
        }
    }

    #[test]
    fn an_unset_or_empty_session_is_unconfigured_rather_than_empty() {
        // `transcript.rs`'s law: absent is not empty. A host that supplies no
        // session is a repository not using this, and an empty value is how a CI
        // file clears one — both mean "no session", never a session named "".
        assert_eq!(declared_with_env(&|_| None), None);
        assert_eq!(
            declared_with_env(&|name| (name == SESSION_ENV).then(String::new)),
            None
        );
        assert_eq!(
            declared_with_env(&|name| (name == SESSION_ENV).then(|| "a".to_owned())),
            Some(declared_of("a", None)),
            "a session with no parent is not a fork"
        );
    }

    #[test]
    fn a_parent_naming_the_session_itself_is_dropped() {
        // A self-edge is the one lineage no walk can shorten, and it is always a
        // mis-set environment rather than a fork.
        let env = |name: &str| match name {
            SESSION_ENV | PARENT_ENV => Some("a".to_owned()),
            _ => None,
        };
        assert_eq!(declared_with_env(&env), Some(declared_of("a", None)));
    }

    #[test]
    fn an_unforked_session_is_its_own_root_with_no_record_at_all() {
        // The ordinary case, and it must not require a write: `root` is a read
        // path, so resolving a session the store has never seen answers rather
        // than minting.
        let dir = store("own-root");
        let resolved = root(&dir, "alpha").unwrap();
        assert_eq!(resolved.key, "alpha");
        assert_eq!(resolved.depth, 0);
        assert!(!resolved.truncated);
        assert!(
            !sessions_dir(&dir).exists(),
            "a read must not create the sessions directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fork_chain_resolves_to_the_key_the_parent_minted() {
        // CLOUD-83's fork-continuity rule: every descendant hashes the root's
        // key, so a sequence finding opened by the parent keeps its identity.
        let dir = store("chain");
        chain(&dir, &["alpha", "beta", "gamma"]);
        assert_eq!(sequence_session(&dir, "gamma").unwrap(), "alpha");
        assert_eq!(sequence_session(&dir, "beta").unwrap(), "alpha");
        assert_eq!(root(&dir, "gamma").unwrap().depth, 2);

        // And an unrelated session is NOT folded in — the whole reason the
        // session is in the sequence tuple at all.
        assert_eq!(sequence_session(&dir, "stranger").unwrap(), "stranger");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cycle_stops_at_the_bound_and_says_so_rather_than_hanging() {
        // Written by hand, because `observe`'s write-once parent refuses the
        // second edge — which is itself the guard that makes this unreachable
        // through the ordinary path. The walk must still terminate.
        let dir = store("cycle");
        write_record(&dir, &SessionRecord::fresh("a", Some("b"))).unwrap();
        write_record(&dir, &SessionRecord::fresh("b", Some("a"))).unwrap();
        let resolved = root(&dir, "a").unwrap();
        assert!(resolved.truncated, "a cycle must report, never spin");
        assert_eq!(resolved.depth, MAX_LINEAGE);
        assert!(
            resolved.key == "a" || resolved.key == "b",
            "the deepest key reached is still a usable answer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_recorded_parent_is_never_rewritten() {
        // Ancestry is a fact about a fork that happened. Relinking it would move
        // every already-resolved identity and cursor under readers holding the
        // old root, after the fact.
        let dir = store("write-once");
        assert_eq!(
            observe(&dir, &declared_of("beta", Some("alpha"))).unwrap(),
            Observed::Minted
        );
        assert_eq!(
            observe(&dir, &declared_of("beta", Some("alpha"))).unwrap(),
            Observed::Unchanged,
            "re-declaring the same parent writes nothing"
        );
        assert_eq!(
            observe(&dir, &declared_of("beta", Some("other"))).unwrap(),
            Observed::ParentConflict
        );
        assert_eq!(sequence_session(&dir, "beta").unwrap(), "alpha");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_parent_declared_later_links_a_session_that_had_none() {
        // The ordinary ordering: the parent runs first with no parent of its own,
        // then the fork declares the edge.
        let dir = store("link-later");
        assert_eq!(
            observe(&dir, &declared_of("alpha", None)).unwrap(),
            Observed::Minted
        );
        assert_eq!(
            observe(&dir, &declared_of("alpha", Some("older"))).unwrap(),
            Observed::Linked
        );
        assert_eq!(sequence_session(&dir, "alpha").unwrap(), "older");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fork_reads_the_cursor_its_parent_saved() {
        // The resume point, which is the other half of the fork inheriting the
        // trajectory: the position is stored on the ROOT, so a descendant finds
        // it without knowing it was forked.
        let dir = store("cursor");
        let cursor = Cursor {
            generation: "g".repeat(64),
            seqno: 7,
        };
        save_cursor(&dir, &root(&dir, "alpha").unwrap(), HOLDER_RECORD, &cursor).unwrap();

        chain(&dir, &["alpha", "beta"]);
        let forked = root(&dir, "beta").unwrap();
        assert_eq!(forked.key, "alpha");
        assert_eq!(
            load_cursor(&dir, &forked, HOLDER_RECORD).unwrap(),
            Some(cursor),
            "the fork resumes where its parent stopped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_holders_of_one_lineage_keep_separate_positions() {
        // Load-bearing, not defensive: a shared cursor would let `state record`
        // mark entries seen that never reached an agent, and the drain would skip
        // exactly the findings it exists to emit.
        let dir = store("holders");
        let resolved = root(&dir, "alpha").unwrap();
        let at = |seqno| Cursor {
            generation: "g".repeat(64),
            seqno,
        };
        save_cursor(&dir, &resolved, HOLDER_RECORD, &at(9)).unwrap();
        save_cursor(&dir, &resolved, "drain", &at(2)).unwrap();
        assert_eq!(
            load_cursor(&dir, &resolved, HOLDER_RECORD).unwrap(),
            Some(at(9))
        );
        assert_eq!(load_cursor(&dir, &resolved, "drain").unwrap(), Some(at(2)));
        assert_eq!(
            load_cursor(&dir, &resolved, "never-read").unwrap(),
            None,
            "a holder that has not read has no position, which resyncs"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_a_cursor_does_not_disturb_the_lineage() {
        // The two halves share a file, so a cursor write must not drop the edge
        // that decides which file it is.
        let dir = store("cursor-keeps-lineage");
        chain(&dir, &["alpha", "beta"]);
        let resolved = root(&dir, "beta").unwrap();
        save_cursor(
            &dir,
            &resolved,
            HOLDER_RECORD,
            &Cursor {
                generation: "g".repeat(64),
                seqno: 1,
            },
        )
        .unwrap();
        assert_eq!(sequence_session(&dir, "beta").unwrap(), "alpha");
        assert_eq!(
            load(&dir, "beta").unwrap().unwrap().parent.as_deref(),
            Some("alpha")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_record_reads_as_absent_rather_than_half_trusted() {
        // Fail-closed, matching `findings` and `store`. Absent means "own root,
        // no cursor", which resyncs — a half-read cursor would skip findings.
        let dir = store("unreadable");
        std::fs::create_dir_all(sessions_dir(&dir)).unwrap();
        std::fs::write(record_path(&dir, "alpha"), "{ not json").unwrap();
        assert_eq!(load(&dir, "alpha").unwrap(), None);
        assert_eq!(root(&dir, "alpha").unwrap().key, "alpha");

        // A record from a future schema is absent too: a field this binary
        // cannot see is one it would drop on the next write.
        std::fs::write(
            record_path(&dir, "beta"),
            serde_json::json!({
                "schema": SESSION_SCHEMA + 1,
                "session": "beta",
                "parent": "alpha",
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(load(&dir, "beta").unwrap(), None);
        assert_eq!(
            root(&dir, "beta").unwrap().key,
            "beta",
            "an unreadable edge is not followed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_round_trips_and_is_keyed_by_a_fingerprint_not_the_key() {
        // A host session id is somebody else's string; letting it name a file
        // would hand a host this crate's path layout.
        let dir = store("round-trip");
        let record = SessionRecord {
            cursors: [(
                HOLDER_RECORD.to_owned(),
                Cursor {
                    generation: "a".repeat(64),
                    seqno: 3,
                },
            )]
            .into_iter()
            .collect(),
            ..SessionRecord::fresh("sess/../../etc: weird", Some("alpha"))
        };
        write_record(&dir, &record).unwrap();
        assert_eq!(
            load(&dir, "sess/../../etc: weird").unwrap(),
            Some(record.clone())
        );
        let name = record_path(&dir, &record.session);
        let stem = name.file_stem().and_then(|stem| stem.to_str()).unwrap();
        assert_eq!(stem.len(), 64, "the filename is a fingerprint");
        assert!(stem.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(name.parent(), Some(sessions_dir(&dir).as_path()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_root_reports_itself_as_a_pointer_never_the_host_key() {
        // Rule 4: output is a pointer. A host session id is not this crate's to
        // print, and the fingerprint prefix identifies the lineage just as well.
        let resolved = Root {
            key: "some-host-session-id".to_owned(),
            depth: 0,
            truncated: false,
        };
        let short = resolved.short();
        assert_eq!(short.len(), 8);
        assert!(short.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!short.contains("host"));
    }
}
