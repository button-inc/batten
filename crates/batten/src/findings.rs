//! What the store holds: one finding per identity, many instances per ref
//! (CLOUD-164).
//!
//! [`crate::store`] answers *which* store belongs to a checkout. This answers
//! what is in it. The split is not cosmetic — store identity is stable for the
//! life of a repository, while its contents change on every scan.
//!
//! # One finding, many instances
//!
//! The same defect seen from two git worktrees is **one** finding, and a defect
//! fixed in worktree A while still present in B must not flap open and closed as
//! scans interleave. GitHub code scanning's alert/instance split answers this and
//! is adopted wholesale: a [`FindingRecord`] owns the identity and (later) the
//! disposition, and carries an [`Instance`] per observation context.
//!
//! Instances are keyed by **ref**, never by worktree path. Worktrees here are
//! ephemeral with randomized names, so a path-keyed instance would mint a new
//! one per checkout and GC none of them. The path is recorded as metadata, for a
//! human reading a report.
//!
//! "One finding" is structural rather than a join: instances live *inside* the
//! record, in one file per identity. Two worktrees writing one finding each
//! could not otherwise be prevented from creating two files for it.
//!
//! # Observed zero is not the same as not observed
//!
//! [`Observation`] is the load-bearing type. A rule whose precondition was unmet
//! (skipped) or whose gate errored (internal) reports *nothing* — and reading
//! that silence as "zero occurrences" would resolve every finding the rule
//! covers, turning fail-closed into fail-open at the store layer. The identity
//! module states the law and leaves distinguishing the two cases to this layer,
//! because [`crate::identity::compare_to_anchor`] answers only for a count the
//! caller vouches for. [`Observation::NotObserved`] is how a caller declines to
//! vouch.
//!
//! # Comparisons are per (identity × context)
//!
//! Every temporal comparison — occurrence count, self-clear, and later flap
//! ratio — is computed within one context. Interleaved scans from worktrees at
//! different refs must not read as change, which is exactly what a repo-global
//! count would produce.
//!
//! # What is deliberately absent
//!
//! **No disposition field.** `acted` / `rejected-wrong` / `rejected-by-design`,
//! their precedence-merge, and the effective-false-positive rate are CLOUD-78.
//! This issue supplies the model those attach to; adding a disposition here
//! would be building the thing this exists to make buildable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::identity::{CountChange, Fingerprint, StoredIdentity, compare_to_anchor};
use crate::rules::Finding;
use crate::severity::RuleSeverity;

/// The on-disk record's schema version, versioned independently of the store's
/// own: the ledger's shape and the store's identity evolve for unrelated
/// reasons.
pub const FINDINGS_SCHEMA: u32 = 1;

/// The subdirectory holding one file per identity.
const FINDINGS_DIR: &str = "findings";

/// The context an observation belongs to: a git ref, never a worktree path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Context(String);

impl Context {
    /// A context from a ref name.
    #[must_use]
    pub fn new(reference: impl Into<String>) -> Self {
        Context(reference.into())
    }

    /// The ref name — a coordinate, safe to print.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a scan reported no count for an identity it did not observe.
///
/// Each variant is a rule that **did not run**, so its silence carries no
/// information about whether the defect is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotObserved {
    /// The rule's input precondition was unmet, so it was skipped.
    RuleSkipped,
    /// The gate errored; fail-closed isolation reported Internal.
    RuleErrored,
}

/// How many times an identity occurred in a context — or why that is unknown.
///
/// The distinction this type exists to force is between **observed zero** (the
/// rule ran and found nothing, so the finding resolves) and **not observed** (the
/// rule did not run, so the finding holds). Collapsing them into `0` is how
/// fail-closed becomes fail-open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Observation {
    /// The rule ran in this context and counted this many occurrences.
    Observed(u64),
    /// The rule did not run, so nothing is known.
    NotObserved(NotObserved),
}

impl Observation {
    /// The count, when one was actually observed.
    #[must_use]
    pub const fn count(self) -> Option<u64> {
        match self {
            Observation::Observed(count) => Some(count),
            Observation::NotObserved(_) => None,
        }
    }

    /// How this observation compares to `anchor`.
    ///
    /// `None` when nothing was observed — the caller must **hold**, not resolve.
    /// Returning `Some(CountChange::Resolved)` here would be the fail-open bug.
    #[must_use]
    pub fn compare(self, anchor: u64) -> Option<CountChange> {
        self.count().map(|count| compare_to_anchor(anchor, count))
    }
}

/// One observation of one identity in one context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instance {
    /// The ref this observation belongs to. The instance key.
    pub context: Context,
    /// How many times the identity occurred, or why that is unknown.
    pub occurrences: Observation,
    /// The commit the context was at when observed.
    #[serde(rename = "observedAtCommit")]
    pub observed_at_commit: String,
    /// The worktree the scan ran in. **Metadata only** — never a key, never
    /// compared, never GC'd on; worktrees are ephemeral and randomly named.
    #[serde(rename = "worktreePath", skip_serializing_if = "Option::is_none")]
    pub worktree_path: Option<String>,
    /// Where the finding is, as a pointer.
    pub path: String,
    /// The line, when the kind locates one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// One finding: an identity, and every context it has been observed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    /// The on-disk format version.
    pub schema: u32,
    /// The identity this record is keyed by, with the version that minted it.
    pub identity: StoredIdentity,
    /// The rule that produced it.
    pub rule: String,
    /// The rule's severity at the time of writing. Recorded, never an identity
    /// input — a re-rating must not re-mint.
    pub severity: RuleSeverity,
    /// One instance per context, sorted by context so the file is byte-stable.
    pub instances: Vec<Instance>,
    // No disposition: that is CLOUD-78's, and adding one here would build the
    // thing this model exists to be built on.
}

impl FindingRecord {
    /// The instance for `context`, if this finding has been observed there.
    #[must_use]
    pub fn instance(&self, context: &Context) -> Option<&Instance> {
        self.instances
            .iter()
            .find(|instance| &instance.context == context)
    }

    /// Insert or replace the instance for its context, keeping instances sorted.
    ///
    /// Replace rather than append: an identity has **one** observation per
    /// context, and appending would let a repeated scan of one ref read as
    /// several.
    pub fn upsert(&mut self, instance: Instance) {
        if let Some(existing) = self
            .instances
            .iter_mut()
            .find(|existing| existing.context == instance.context)
        {
            *existing = instance;
        } else {
            self.instances.push(instance);
            self.instances.sort_by(|a, b| a.context.cmp(&b.context));
        }
    }

    /// Drop every instance whose context is not in `live`, and report whether
    /// anything remains.
    ///
    /// Liveness is decided by **ref existence**, never by reachability: this
    /// repository lands by rebase and fast-forward, so a merged branch's commits
    /// are not ancestors of anything and an ancestry test would GC live work.
    /// The caller supplies the live set for that reason.
    pub fn retain_live(&mut self, live: &BTreeSet<Context>) -> bool {
        self.instances
            .retain(|instance| live.contains(&instance.context));
        !self.instances.is_empty()
    }
}

/// The directory holding one file per identity, under a bound store.
fn findings_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(FINDINGS_DIR)
}

/// The file a fingerprint's record lives in.
fn record_path(store_dir: &Path, fingerprint: Fingerprint) -> PathBuf {
    findings_dir(store_dir).join(format!("{}.json", fingerprint.to_hex()))
}

/// Read one record, treating anything unreadable as **absent**.
///
/// Fail-closed, the posture [`crate::store`] and [`crate::receipt`] both take: a
/// truncated or future-schema record is not partially trusted, because a
/// half-read finding would silently lose the instances it could not parse.
fn read_record(path: &Path) -> Option<FindingRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: FindingRecord = serde_json::from_str(&text).ok()?;
    (record.schema == FINDINGS_SCHEMA).then_some(record)
}

/// Write one record atomically, so a concurrent worktree never reads a torn file.
fn write_record(store_dir: &Path, record: &FindingRecord) -> Result<()> {
    let dir = findings_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the findings directory {}", dir.display()))?;
    let json = serde_json::to_string_pretty(record)?;
    let temp = dir.join(format!(
        "{}.{}.tmp",
        record.identity.fingerprint.to_hex(),
        std::process::id()
    ));
    std::fs::write(&temp, format!("{json}\n"))
        .with_context(|| format!("write the finding {}", temp.display()))?;
    std::fs::rename(&temp, record_path(store_dir, record.identity.fingerprint))
        .with_context(|| format!("publish the finding in {}", dir.display()))?;
    Ok(())
}

/// Every stored finding, sorted by fingerprint hex.
///
/// Sorted so `--json` output and every report derived from it are byte-stable
/// and independent of `read_dir` order (§6).
///
/// # Errors
///
/// Returns an error only when the findings directory exists but cannot be read.
pub fn load_all(store_dir: &Path) -> Result<Vec<FindingRecord>> {
    let dir = findings_dir(store_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        // No findings recorded yet is the ordinary first-run case.
        return Ok(Vec::new());
    };
    let mut found: Vec<FindingRecord> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter_map(|path| read_record(&path))
        .collect();
    found.sort_by(|a, b| a.identity.fingerprint.cmp(&b.identity.fingerprint));
    Ok(found)
}

/// What one `record` call changed, as pointer-only counts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// Identities seen for the first time anywhere in this store.
    pub minted: usize,
    /// Identities whose instance in this context was created or updated.
    pub updated: usize,
    /// Identities that previously had an instance here and no longer occur.
    pub resolved: usize,
}

/// Fold one scan's findings into the store as this context's instances.
///
/// The scan is the authority for **this context only**: an identity absent from
/// `findings` but previously recorded here is now observed at zero *in this
/// context*, and its instance is updated to say so. Instances in other contexts
/// are untouched, which is what keeps a defect fixed in one worktree from
/// resolving the finding while another worktree still sees it.
///
/// # Errors
///
/// Returns an error when a record cannot be read or written.
pub fn record(
    store_dir: &Path,
    context: &Context,
    commit: &str,
    worktree: Option<&str>,
    findings: &[Finding],
) -> Result<Recorded> {
    // Fold to a multiset first: identical spans in one file are ONE identity
    // with a count, never several findings.
    let mut counted: BTreeMap<&StoredIdentity, (u64, &Finding)> = BTreeMap::new();
    for finding in findings {
        counted
            .entry(&finding.identity)
            .and_modify(|(count, _)| *count += 1)
            .or_insert((1, finding));
    }

    let mut summary = Recorded::default();
    let mut seen: BTreeSet<Fingerprint> = BTreeSet::new();

    for (identity, (count, finding)) in counted {
        seen.insert(identity.fingerprint);
        let path = record_path(store_dir, identity.fingerprint);
        let mut existing = read_record(&path).unwrap_or_else(|| {
            summary.minted += 1;
            FindingRecord {
                schema: FINDINGS_SCHEMA,
                identity: identity.clone(),
                rule: finding.rule.clone(),
                severity: finding.severity,
                instances: Vec::new(),
            }
        });
        existing.upsert(Instance {
            context: context.clone(),
            occurrences: Observation::Observed(count),
            observed_at_commit: commit.to_owned(),
            worktree_path: worktree.map(ToOwned::to_owned),
            path: finding.path.clone(),
            line: finding.line,
        });
        write_record(store_dir, &existing)?;
        summary.updated += 1;
    }

    // Anything this context recorded before and did not see now is observed at
    // zero HERE. Not deleted: another context may still be seeing it, and the
    // record is what carries that.
    for mut existing in load_all(store_dir)? {
        if seen.contains(&existing.identity.fingerprint) {
            continue;
        }
        let Some(previous) = existing.instance(context) else {
            continue;
        };
        if previous.occurrences == Observation::Observed(0) {
            continue;
        }
        let (path, line) = (previous.path.clone(), previous.line);
        existing.upsert(Instance {
            context: context.clone(),
            occurrences: Observation::Observed(0),
            observed_at_commit: commit.to_owned(),
            worktree_path: worktree.map(ToOwned::to_owned),
            path,
            line,
        });
        write_record(store_dir, &existing)?;
        summary.resolved += 1;
    }

    Ok(summary)
}

/// Drop instances whose ref no longer exists, and findings left with none.
///
/// # Errors
///
/// Returns an error when a record cannot be read, written, or removed.
pub fn gc(store_dir: &Path, live: &BTreeSet<Context>) -> Result<usize> {
    let mut dropped = 0;
    for mut record in load_all(store_dir)? {
        let before = record.instances.len();
        if record.retain_live(live) {
            if record.instances.len() != before {
                write_record(store_dir, &record)?;
                dropped += before - record.instances.len();
            }
            continue;
        }
        // Every context this finding was seen in is gone, so nothing is left to
        // observe it. The record goes with them.
        let path = record_path(store_dir, record.identity.fingerprint);
        std::fs::remove_file(&path)
            .with_context(|| format!("remove the finding {}", path.display()))?;
        dropped += before;
    }
    Ok(dropped)
}

/// A pointer line per instance: `<fingerprint> <rule> <context> <count>`.
///
/// Pointer-only (rule 4): identities, rule ids, ref names and counts. Never the
/// matched content — which the store does not hold in the first place.
#[must_use]
pub fn pointer_lines(records: &[FindingRecord]) -> Vec<String> {
    let mut lines = Vec::new();
    for record in records {
        for instance in &record.instances {
            let count = match instance.occurrences {
                Observation::Observed(count) => count.to_string(),
                Observation::NotObserved(NotObserved::RuleSkipped) => "skipped".to_owned(),
                Observation::NotObserved(NotObserved::RuleErrored) => "errored".to_owned(),
            };
            lines.push(format!(
                "{} {} {} {count}",
                record.identity.fingerprint.to_hex(),
                record.rule,
                instance.context
            ));
        }
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::{FindingKind, SpanNormalization, code_fingerprint};

    fn identity_for(rule: &str, path: &str, span: &str) -> StoredIdentity {
        StoredIdentity::new(
            FindingKind::Code,
            code_fingerprint(rule, path, span, SpanNormalization::Collapsed).unwrap(),
        )
    }

    fn instance(context: &str, occurrences: Observation) -> Instance {
        Instance {
            context: Context::new(context),
            occurrences,
            observed_at_commit: "0".repeat(40),
            worktree_path: None,
            path: "src/a.rs".to_owned(),
            line: Some(1),
        }
    }

    fn record_of(instances: Vec<Instance>) -> FindingRecord {
        FindingRecord {
            schema: FINDINGS_SCHEMA,
            identity: identity_for("r", "src/a.rs", "TODO"),
            rule: "r".to_owned(),
            severity: RuleSeverity::Deny,
            instances,
        }
    }

    #[test]
    fn not_observed_never_resolves_a_finding() {
        // The fail-closed law: a rule that did not run observes nothing, and
        // reading that as zero would clear findings the rule never looked at.
        assert_eq!(
            Observation::Observed(0).compare(3),
            Some(CountChange::Resolved)
        );
        assert_eq!(
            Observation::NotObserved(NotObserved::RuleSkipped).compare(3),
            None,
            "a skipped rule yields no verdict at all — the finding holds"
        );
        assert_eq!(
            Observation::NotObserved(NotObserved::RuleErrored).compare(3),
            None,
            "an errored gate yields no verdict at all — the finding holds"
        );
    }

    #[test]
    fn observed_zero_and_not_observed_are_different_values() {
        // They must not compare equal, or a store could round-trip one into the
        // other and silently change a verdict.
        assert_ne!(
            Observation::Observed(0),
            Observation::NotObserved(NotObserved::RuleSkipped)
        );
        assert_eq!(Observation::Observed(0).count(), Some(0));
        assert_eq!(
            Observation::NotObserved(NotObserved::RuleSkipped).count(),
            None
        );
    }

    #[test]
    fn an_instance_is_replaced_per_context_never_appended() {
        // One observation per context: re-scanning a ref updates its instance
        // rather than making the identity look more frequent than it is.
        let mut record = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        record.upsert(instance("refs/heads/a", Observation::Observed(5)));
        assert_eq!(record.instances.len(), 1);
        assert_eq!(record.instances[0].occurrences, Observation::Observed(5));
    }

    #[test]
    fn instances_stay_sorted_by_context() {
        // Byte-stable output does not depend on insertion order.
        let mut record = record_of(Vec::new());
        for name in ["refs/heads/c", "refs/heads/a", "refs/heads/b"] {
            record.upsert(instance(name, Observation::Observed(1)));
        }
        assert_eq!(
            record
                .instances
                .iter()
                .map(|i| i.context.as_str())
                .collect::<Vec<_>>(),
            vec!["refs/heads/a", "refs/heads/b", "refs/heads/c"]
        );
    }

    #[test]
    fn a_finding_survives_the_death_of_one_of_its_refs() {
        // Acceptance (d), at the model level: GC drops the dead ref's instance
        // and keeps the finding while any context still observes it.
        let mut record = record_of(vec![
            instance("refs/heads/a", Observation::Observed(1)),
            instance("refs/heads/b", Observation::Observed(1)),
        ]);
        let live: BTreeSet<Context> = [Context::new("refs/heads/b")].into_iter().collect();
        assert!(record.retain_live(&live), "the finding survives");
        assert_eq!(record.instances.len(), 1);
        assert_eq!(record.instances[0].context.as_str(), "refs/heads/b");

        // With no live context left there is nothing to observe it.
        assert!(!record.retain_live(&BTreeSet::new()));
    }

    #[test]
    fn a_fix_in_one_context_does_not_touch_another() {
        // Acceptance (a), at the model level: same identity, two refs, one
        // fixed. The other context's count is untouched, so no flap.
        let mut record = record_of(vec![
            instance("refs/heads/a", Observation::Observed(1)),
            instance("refs/heads/b", Observation::Observed(1)),
        ]);
        record.upsert(instance("refs/heads/a", Observation::Observed(0)));
        assert_eq!(
            record
                .instance(&Context::new("refs/heads/a"))
                .unwrap()
                .occurrences,
            Observation::Observed(0)
        );
        assert_eq!(
            record
                .instance(&Context::new("refs/heads/b"))
                .unwrap()
                .occurrences,
            Observation::Observed(1),
            "the other context is not re-evaluated by a scan that never ran there"
        );
    }

    #[test]
    fn a_fingerprint_round_trips_through_its_hex() {
        // The store reads its own keys back, so this has to be exact.
        let identity = identity_for("r", "src/a.rs", "TODO");
        let hex = identity.fingerprint.to_hex();
        assert_eq!(Fingerprint::from_hex(&hex).unwrap(), identity.fingerprint);
        assert!(Fingerprint::from_hex(&hex.to_uppercase()).is_err());
        assert!(Fingerprint::from_hex("abc").is_err());
    }
}
