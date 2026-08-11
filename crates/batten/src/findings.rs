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
//! # Disposition is a join-semilattice, not a workflow (CLOUD-78)
//!
//! [`Disposition`] is three-valued — `acted` / `rejected-by-design` /
//! `rejected-wrong` — and its **precedence doubles as the concurrent-merge
//! rule**: `acted > rejected-by-design > rejected-wrong`, merged with `max`.
//! That single choice buys commutativity, associativity and idempotence, so two
//! worktrees writing conflicting dispositions converge to the same answer in
//! either order, and a migration-merge is computed rather than adjudicated.
//!
//! # Not-shown is not shown-and-ignored
//!
//! [`Presentation`] carries the second axis the effective-false-positive rate
//! needs. A finding Batten itself declined to surface — drain-suppressed, over a
//! cardinality cap, or blocked by an absent host capability — never had the
//! chance to be acted on, so counting it as a false positive would let the
//! engine's own suppression machinery inflate the very number it exists to
//! measure. Only [`Presentation::Shown`] findings enter [`effective_fp_rates`].
//!
//! # Severity is stored once, and a count never escalates it
//!
//! Exactly one severity field is persisted — the [`AdvisoryTier`]. Rule severity
//! and report level are derived through [`crate::severity`]'s rank table at the
//! boundary that needs them. Occurrence count and tier are **independent axes**:
//! observing a finding an Nth time changes [`Instance::occurrences`] and must
//! never change [`FindingRecord::tier`] (CLOUD-80's no-escalation law, which is
//! testable for the first time here because this is what counts duplicates).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::identity::{CountChange, Fingerprint, StoredIdentity, compare_to_anchor};
use crate::rules::Finding;
use crate::severity::{AdvisoryTier, RuleSeverity, row_for_rule};

/// The on-disk record's schema version, versioned independently of the store's
/// own: the ledger's shape and the store's identity evolve for unrelated
/// reasons.
///
/// The newest version this binary can **write**. Reads accept anything from
/// [`FINDINGS_SCHEMA_MIN`] up, which is the read-both half of the rolling
/// window; which version is actually written is the store's recorded format
/// (see [`crate::journal`]), never this constant, so upgrading a binary does not
/// silently upgrade a store.
pub const FINDINGS_SCHEMA: u32 = 2;

/// The oldest record version this binary can still read.
pub const FINDINGS_SCHEMA_MIN: u32 = 1;

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

/// What an agent did about a finding, once.
///
/// Declared **weakest-first**, so the derived [`Ord`] *is* the precedence
/// `acted > rejected-by-design > rejected-wrong`. That is deliberate: [`merge`]
/// is `max`, which makes the concurrent-merge rule a join on a total order —
/// commutative, associative and idempotent — rather than a policy an
/// implementation could get subtly wrong per call site.
///
/// [`merge`]: Disposition::merge
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Surfaced, and the agent judged it a false positive.
    RejectedWrong,
    /// Surfaced, and the agent judged the flagged shape intentional.
    RejectedByDesign,
    /// Surfaced, and the agent changed something in response.
    Acted,
}

impl Disposition {
    /// Every disposition, weakest-first, so coverage tests are total.
    pub const ALL: &'static [Disposition] = &[
        Disposition::RejectedWrong,
        Disposition::RejectedByDesign,
        Disposition::Acted,
    ];

    /// The stable token used in the store and in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Disposition::RejectedWrong => "rejected-wrong",
            Disposition::RejectedByDesign => "rejected-by-design",
            Disposition::Acted => "acted",
        }
    }

    /// Whether the agent acted on it. The **only** non-false-positive outcome:
    /// "a finding the agent does not act on is counted as a false positive
    /// regardless of truth" is the measurement this store exists to make, and
    /// letting `rejected-by-design` off the hook would be exactly the
    /// self-serving exemption that makes the number meaningless.
    #[must_use]
    pub const fn is_acted(self) -> bool {
        matches!(self, Disposition::Acted)
    }

    /// Whether this record must survive GC.
    ///
    /// `rejected-by-design` is GC-exempt: it is a standing decision, and losing
    /// it would re-raise a finding the agent already settled, every time the ref
    /// it was settled on died. The price is unbounded retention for that one
    /// class, accepted and stated rather than discovered later.
    #[must_use]
    pub const fn is_gc_exempt(self) -> bool {
        matches!(self, Disposition::RejectedByDesign)
    }

    /// The converged disposition of two concurrent writes.
    ///
    /// `max` over the declared order. Commutative and associative by
    /// construction, which is what lets two worktrees merge shards in either
    /// order and reach the same store.
    #[must_use]
    pub fn merge(self, other: Disposition) -> Disposition {
        self.max(other)
    }
}

/// Why Batten did not surface a finding it knew about.
///
/// Each variant is a decision the **engine** made, never the agent — which is
/// what disqualifies it from the false-positive rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotShown {
    /// The drain coalesced it away this boundary.
    DrainSuppressed,
    /// Its rule was over the per-rule cardinality cap.
    OverCardinalityCap,
    /// The host does not declare the capability the emission needed.
    CapabilityAbsent,
}

/// Whether a finding ever reached the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Presentation {
    /// Emitted to the agent, so its silence is a judgement.
    Shown,
    /// Withheld by the engine, so its silence says nothing.
    NotShown(NotShown),
}

impl Presentation {
    /// Whether this finding is admissible evidence for a false-positive rate.
    #[must_use]
    pub const fn is_shown(self) -> bool {
        matches!(self, Presentation::Shown)
    }
}

/// The per-check effective false-positive rate, as its two raw counts.
///
/// Counts rather than a bare float so a caller can report `n/m` as a pointer and
/// so the zero-denominator case cannot be silently rendered as `0.0` — a check
/// that has shown nothing has no rate, which is different from a perfect one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpRate {
    /// Findings from this check that reached the agent.
    pub shown: u64,
    /// Of those, the ones not acted on.
    pub ignored: u64,
}

impl FpRate {
    /// The rate, or `None` when nothing was shown.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn rate(self) -> Option<f64> {
        (self.shown > 0).then(|| self.ignored as f64 / self.shown as f64)
    }
}

/// The effective false-positive rate per rule, over every stored record.
///
/// **Per check, never per finding**: acknowledging findings one at a time is the
/// ritual this measurement replaces. Not-shown findings are excluded from both
/// numerator and denominator — see [`Presentation`].
///
/// The result is a rate, deliberately not a verdict: it triggers sampled review,
/// and nothing here can produce an exit code.
#[must_use]
pub fn effective_fp_rates(records: &[FindingRecord]) -> BTreeMap<String, FpRate> {
    let mut rates: BTreeMap<String, FpRate> = BTreeMap::new();
    for record in records {
        if !record.presentation.is_shown() {
            continue;
        }
        let rate = rates.entry(record.rule.clone()).or_default();
        rate.shown += 1;
        if !record.disposition.is_some_and(Disposition::is_acted) {
            rate.ignored += 1;
        }
    }
    rates
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
    /// The **one** persisted severity axis: required response latency.
    ///
    /// Derived from [`FindingRecord::severity`] through the rank table when the
    /// record is minted, then never recomputed — and never touched by an
    /// occurrence count (CLOUD-80's no-escalation law). Defaulted on read so a
    /// schema-1 record loads without a migration having run.
    #[serde(default = "default_tier")]
    pub tier: AdvisoryTier,
    /// What the agent did about it, once it was shown. `None` is "not yet
    /// settled", which is distinct from any of the three settled answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    /// Whether it ever reached the agent. Schema-1 records predate suppression
    /// and were all emitted, so the default is the honest answer for them.
    #[serde(default = "default_presentation")]
    pub presentation: Presentation,
    /// One instance per context, sorted by context so the file is byte-stable.
    pub instances: Vec<Instance>,
}

/// The tier a schema-1 record loads with: the weakest, because a record written
/// before tiers existed carries no evidence for a stronger one, and inventing
/// urgency during a read is how a migration changes verdicts.
fn default_tier() -> AdvisoryTier {
    AdvisoryTier::Advisory
}

/// A record written before suppression existed was, by construction, shown.
fn default_presentation() -> Presentation {
    Presentation::Shown
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
    ///
    /// A `rejected-by-design` record survives with no live instance at all
    /// ([`Disposition::is_gc_exempt`]): the decision outlives the branch it was
    /// made on, and dropping it would re-raise a settled finding.
    pub fn retain_live(&mut self, live: &BTreeSet<Context>) -> bool {
        self.instances
            .retain(|instance| live.contains(&instance.context));
        !self.instances.is_empty() || self.is_gc_exempt()
    }

    /// Whether GC must keep this record even with no live context.
    #[must_use]
    pub fn is_gc_exempt(&self) -> bool {
        self.disposition.is_some_and(Disposition::is_gc_exempt)
    }

    /// Apply a concurrent write's disposition, converging by precedence.
    ///
    /// An unset disposition loses to any set one, and two set ones join with
    /// [`Disposition::merge`], so replaying shards in any order lands the same
    /// record.
    pub fn merge_disposition(&mut self, incoming: Option<Disposition>) {
        self.disposition = match (self.disposition, incoming) {
            (Some(current), Some(new)) => Some(current.merge(new)),
            (current, None) => current,
            (None, new) => new,
        };
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
/// Read-both, deliberately a range rather than an equality: the rolling window
/// is what lets a new binary run against a store it has not migrated. A record
/// from the *future* is still absent — that half stays fail-closed, because a
/// field this binary cannot see is a field it would silently drop on write.
fn read_record(path: &Path) -> Option<FindingRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: FindingRecord = serde_json::from_str(&text).ok()?;
    (FINDINGS_SCHEMA_MIN..=FINDINGS_SCHEMA)
        .contains(&record.schema)
        .then_some(record)
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

/// One record by identity, or `None` when this store has never seen it.
///
/// # Errors
///
/// Infallible today; the signature matches [`load_all`] so a caller can handle
/// both the same way.
pub fn load_one(store_dir: &Path, fingerprint: Fingerprint) -> Result<Option<FindingRecord>> {
    Ok(read_record(&record_path(store_dir, fingerprint)))
}

/// Publish one record.
///
/// The write half, exposed so [`crate::journal`] can fold dispositions in
/// without growing a second writer — one module writes a finding file.
///
/// # Errors
///
/// Returns an error when the record cannot be written or published.
pub fn save_one(store_dir: &Path, record: &FindingRecord) -> Result<()> {
    write_record(store_dir, record)
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
/// `schema` is the version **the store is written in**, supplied by the caller
/// from [`crate::journal::Format`] rather than read from [`FINDINGS_SCHEMA`]
/// here: write-old is what keeps a newer binary from silently upgrading a store
/// an older sibling worktree is still reading.
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
    schema: u32,
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
                schema,
                identity: identity.clone(),
                rule: finding.rule.clone(),
                severity: finding.severity,
                // Derived once, at mint, through the rank table — the one place
                // a tier is decided. Re-deriving it on every observation would
                // let a re-rated rule silently re-tier settled findings.
                tier: row_for_rule(finding.severity).tier,
                disposition: None,
                presentation: Presentation::Shown,
                instances: Vec::new(),
            }
        });
        // The tier is NOT touched here. Observing a finding again changes its
        // count and nothing else (CLOUD-80's no-escalation law).
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
            tier: row_for_rule(RuleSeverity::Deny).tier,
            disposition: None,
            presentation: Presentation::Shown,
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
    fn disposition_precedence_is_a_commutative_join() {
        // Acceptance (a) at the model level: `acted > rejected-by-design >
        // rejected-wrong`, merged with max, so concurrent writers converge
        // regardless of order. Asserted over every ordered pair, not samples —
        // a merge rule that commutes for the cases someone thought of is not a
        // merge rule.
        for &a in Disposition::ALL {
            for &b in Disposition::ALL {
                assert_eq!(a.merge(b), b.merge(a), "merge must commute: {a:?} {b:?}");
                assert_eq!(a.merge(a), a, "merge must be idempotent: {a:?}");
                for &c in Disposition::ALL {
                    assert_eq!(
                        a.merge(b).merge(c),
                        a.merge(b.merge(c)),
                        "merge must be associative"
                    );
                }
            }
        }
        assert_eq!(
            Disposition::Acted.merge(Disposition::RejectedByDesign),
            Disposition::Acted
        );
        assert_eq!(
            Disposition::RejectedByDesign.merge(Disposition::RejectedWrong),
            Disposition::RejectedByDesign
        );
    }

    #[test]
    fn an_unset_disposition_loses_to_any_settled_one() {
        // `None` is "not yet settled", which must never overwrite a decision an
        // agent already made in another worktree.
        let mut record = record_of(Vec::new());
        record.merge_disposition(Some(Disposition::RejectedWrong));
        record.merge_disposition(None);
        assert_eq!(record.disposition, Some(Disposition::RejectedWrong));
        record.merge_disposition(Some(Disposition::Acted));
        assert_eq!(record.disposition, Some(Disposition::Acted));
    }

    #[test]
    fn not_shown_findings_are_excluded_from_the_false_positive_rate() {
        // Acceptance (b): the engine's own suppression must not inflate the
        // number it exists to measure. Two shown-and-ignored out of three shown
        // is 2/3 — the two not-shown records enter neither side of it.
        let shown = |disposition| FindingRecord {
            disposition,
            ..record_of(Vec::new())
        };
        let withheld = |why| FindingRecord {
            presentation: Presentation::NotShown(why),
            disposition: None,
            ..record_of(Vec::new())
        };
        let records = vec![
            shown(Some(Disposition::Acted)),
            shown(Some(Disposition::RejectedWrong)),
            shown(None),
            withheld(NotShown::DrainSuppressed),
            withheld(NotShown::OverCardinalityCap),
        ];
        let rates = effective_fp_rates(&records);
        let rate = rates.get("r").copied().unwrap();
        assert_eq!(
            rate,
            FpRate {
                shown: 3,
                ignored: 2
            },
            "only shown findings count, on both sides of the ratio"
        );
        assert!((rate.rate().unwrap() - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_check_that_showed_nothing_has_no_rate_rather_than_a_perfect_one() {
        // A zero denominator is "unmeasured", and rendering it as 0.0 would let
        // a check that never surfaced anything look flawless.
        assert_eq!(FpRate::default().rate(), None);
        let withheld = FindingRecord {
            presentation: Presentation::NotShown(NotShown::CapabilityAbsent),
            ..record_of(Vec::new())
        };
        assert!(
            effective_fp_rates(&[withheld]).is_empty(),
            "a rule with nothing shown gets no row at all"
        );
    }

    #[test]
    fn rejected_by_design_is_the_only_disposition_that_is_not_a_false_positive_exempt() {
        // "Not acted on is a false positive regardless of truth" — including the
        // agent's own by-design rejection. Letting that off the hook is exactly
        // the self-serving exemption that makes the measurement worthless.
        assert!(Disposition::Acted.is_acted());
        assert!(!Disposition::RejectedByDesign.is_acted());
        assert!(!Disposition::RejectedWrong.is_acted());
    }

    #[test]
    fn an_nth_occurrence_changes_the_count_and_never_the_tier() {
        // Acceptance (c), CLOUD-80's no-escalation law — testable for the first
        // time here, because this is what counts duplicates. Asserted over the
        // STORED tier, not one derived at read time.
        let mut record = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        let minted = record.tier;
        for n in 2..=10 {
            record.upsert(instance("refs/heads/a", Observation::Observed(n)));
            assert_eq!(
                record.tier, minted,
                "observing a finding again must not re-tier it"
            );
        }
        assert_eq!(
            record
                .instance(&Context::new("refs/heads/a"))
                .unwrap()
                .occurrences,
            Observation::Observed(10),
            "the count is the axis that moved"
        );
    }

    #[test]
    fn a_rejected_by_design_record_survives_the_death_of_every_ref() {
        // GC-exempt: the decision outlives the branch it was made on, so a
        // settled finding does not re-raise when that branch is deleted.
        let mut record = FindingRecord {
            disposition: Some(Disposition::RejectedByDesign),
            ..record_of(vec![instance("refs/heads/a", Observation::Observed(1))])
        };
        assert!(
            record.retain_live(&BTreeSet::new()),
            "a by-design rejection is kept with no live context at all"
        );

        // Every other disposition collects normally.
        for disposition in [
            None,
            Some(Disposition::Acted),
            Some(Disposition::RejectedWrong),
        ] {
            let mut other = FindingRecord {
                disposition,
                ..record_of(vec![instance("refs/heads/a", Observation::Observed(1))])
            };
            assert!(
                !other.retain_live(&BTreeSet::new()),
                "{disposition:?} is not GC-exempt"
            );
        }
    }

    #[test]
    fn a_schema_one_record_loads_without_a_migration() {
        // Read-both: the rolling window is what lets a new binary run against a
        // store it has not migrated. The defaults must be the honest reading of
        // a record written before the fields existed.
        // The identity is serialized from the real type rather than hand-written,
        // so this fixture cannot drift from what the store actually writes; the
        // point of the test is the three fields schema 1 does NOT carry.
        let legacy = serde_json::json!({
            "schema": FINDINGS_SCHEMA_MIN,
            "identity": serde_json::to_value(identity_for("r", "src/a.rs", "TODO")).unwrap(),
            "rule": "r",
            "severity": "deny",
            "instances": [],
        });
        let record: FindingRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(record.schema, FINDINGS_SCHEMA_MIN);
        assert_eq!(record.disposition, None, "unsettled, not invented");
        assert_eq!(
            record.presentation,
            Presentation::Shown,
            "records predating suppression were all shown"
        );
        assert_eq!(
            record.tier,
            AdvisoryTier::Advisory,
            "the weakest tier: a legacy record carries no evidence for urgency"
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
