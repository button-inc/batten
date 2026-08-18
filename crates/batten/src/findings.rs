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
//!
//! The law has a second half only a *stored* record can express: severity is not
//! an identity input, so a **re-rated rule** routes its next scan to the same
//! record — and [`record`] reuses that record rather than re-deriving from the
//! rule now firing. Re-rating a rule therefore cannot re-tier the findings it
//! already settled. Both halves are asserted over the bytes on disk, not over an
//! in-memory struct, because a write path that re-derived the tier is invisible
//! to a test that never writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::identity::{CountChange, FindingKind, Fingerprint, StoredIdentity, compare_to_anchor};
use crate::rules::Finding;
use crate::severity::{AdvisoryTier, RuleSeverity, row_for_rule};

/// How a finding settles itself — the predicate whose verdict clears it
/// (CLOUD-81).
///
/// Two variants rather than a required argv column on every rule, because the
/// two rule families answer "is it still there?" in genuinely different ways and
/// forcing one shape onto both would need a shell negation the engine does not
/// offer (§9: a rule names a command on the operator's PATH, run without a
/// shell).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    /// Re-run the producing rule over the finding's context; the engine's own
    /// verdict is the exit code. A `forbid` or `ratchet` finding clears when the
    /// re-evaluation no longer produces it.
    Reevaluate,
    /// Run this argv — never through a shell — and let its exit code settle the
    /// finding: `0` clears, non-zero holds. A `command` rule's `run` is already
    /// exactly this predicate, so it is reused rather than restated.
    Argv(Vec<String>),
}

/// What to do about a finding, or why nothing can be.
///
/// Every stored finding carries one. "No fix exists" is a **stated** answer, not
/// an absent one: a finding with neither is un-actionable, which is the shape a
/// drain refuses to emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Remediation {
    /// The argv that fixes it, run without a shell.
    Fix(Vec<String>),
    /// Why no fix exists. Free text from the rule's author, and a pointer's
    /// worth of it — never the flagged content (rule 4).
    NoFix(String),
}

/// The on-disk record's schema version, versioned independently of the store's
/// own: the ledger's shape and the store's identity evolve for unrelated
/// reasons.
///
/// The newest version this binary can **write**. Reads accept anything from
/// [`FINDINGS_SCHEMA_MIN`] up, which is the read-both half of the rolling
/// window; which version is actually written is the store's recorded format
/// (see [`crate::journal`]), never this constant, so upgrading a binary does not
/// silently upgrade a store.
pub const FINDINGS_SCHEMA: u32 = 3;

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
    /// The identity is flapping and has spent its re-emit budget for this window
    /// (CLOUD-165).
    ///
    /// A statement about the **emission channel only**. The finding's own state
    /// tracked every evaluation truthfully and cleared the instant its check said
    /// so — hysteresis never reaches the state plane, which is CLOUD-81's law kept
    /// as an invariant here rather than traded against. Being a `NotShown` reason
    /// is what keeps the suppression out of both sides of the false-positive rate:
    /// the agent was not shown it, so its silence says nothing.
    FlapSuppressed,
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
    /// The predicate that settles this finding (CLOUD-81).
    ///
    /// `None` **only** for a record written before schema 3, which carries no
    /// evidence of one and where inventing a check during a read would invent a
    /// verdict. A record minted today always has one — [`record`] refuses a
    /// finding without it — so absence is exactly "checkless", and
    /// [`FindingRecord::is_emittable`] is what a drain refuses on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Check>,
    /// The fix, or the stated reason there is none. `None` on the same terms as
    /// [`FindingRecord::check`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
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

    /// Whether a drain may emit this record (CLOUD-81).
    ///
    /// A finding with no check cannot be settled and a finding with no stated
    /// remediation cannot be acted on, so emitting either would spend an agent's
    /// attention on something it has no way to close. [`record`] already refuses
    /// both at ingest; this is the emission-side half, so the drain
    /// (CLOUD-79/82) refuses on the schema rather than re-typing it.
    #[must_use]
    pub fn is_emittable(&self) -> bool {
        self.check.is_some() && self.remediation.is_some()
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

    /// Return this finding to unsettled, and report whether it moved.
    ///
    /// **The one deliberate bypass of the disposition join**, and it needs the
    /// justification the join's own doc gives for being a join: [`Disposition::merge`]
    /// is `max` over a total order precisely so concurrent writers converge, which
    /// means nothing in that algebra can ever *lower* a settled answer. Every
    /// ordinary path wants that. A key-loss orphan is not an ordinary path
    /// (CLOUD-529): it is not a new observation the join could absorb, it is the
    /// loss of the ability to compare this record against a re-scan at all, because
    /// the key that minted its identity is gone. The settled answer was reached by
    /// looking at evidence that can no longer be reproduced, so keeping it would be
    /// asserting a triage nobody can now check.
    ///
    /// Returns `false` when the record was already unsettled, so a caller reports a
    /// count of what actually changed rather than of what it looked at — the same
    /// reason [`crate::drain::record_suppressions`] counts appends.
    ///
    /// Deliberately narrow: it clears the disposition and touches nothing else. The
    /// instances, the tier and the presentation are all still true, and re-deriving
    /// any of them here would make an orphan event a re-mint, which is the exact
    /// thing §7(d) forbids.
    pub fn reopen(&mut self) -> bool {
        let settled = self.disposition.is_some();
        self.disposition = None;
        settled
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

/// Drop one identity's record, if it is there.
///
/// # Not a GC door, and not a way to close a finding
///
/// [`gc`] collects by ref existence and exempts `rejected-by-design`, because a
/// finding disappearing is how a rejected decision would silently come back. This
/// removes one file by identity and is for exactly one caller: a key rotation that
/// has already written the SAME finding under its new identity (CLOUD-529). The
/// record is not being dropped, it is being renamed, and leaving the old file
/// behind would leave the store holding one finding twice — under a fingerprint
/// nothing can re-derive, so nothing would ever clear it.
///
/// Absent is success: an already-applied rotation finds nothing to remove, which is
/// what lets the join ledger be replayed without an "applied" marker.
///
/// # Errors
///
/// Returns an error when the record exists and cannot be removed.
pub fn forget(store_dir: &Path, fingerprint: Fingerprint) -> Result<()> {
    let path = record_path(store_dir, fingerprint);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove the record {}", path.display())),
    }
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
    found.sort_by_key(|a| a.identity.fingerprint);
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
    /// Identities this context recorded before whose rule did **not** evaluate,
    /// so they hold rather than resolving (CLOUD-81).
    pub held: usize,
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
/// # Absence is only a clear when the rule actually looked (CLOUD-81)
///
/// `not_evaluated` names the rules that did **not** run this scan, and why —
/// a rule whose glob matched nothing was skipped, an erroring gate reports
/// Internal. A stored finding whose rule is in that map **holds**: its instance
/// is written as [`Observation::NotObserved`], not resolved to zero.
///
/// This is the fail-closed law at the store layer, and it was the live defect
/// this parameter exists to close. Every unseen identity used to resolve
/// unconditionally, so a rule that never looked cleared every finding it
/// covers — reading a silence as evidence. [`Observation::NotObserved`] had no
/// producer anywhere in the engine until this map.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] (→ exit `1`) for a finding carrying no check
/// or no remediation — a config defect, so the config-error code, never the `2`
/// that is the deny channel. Returns an error when a record cannot be read or
/// written.
pub fn record(
    store_dir: &Path,
    context: &Context,
    commit: &str,
    worktree: Option<&str>,
    findings: &[Finding],
    schema: u32,
    not_evaluated: &BTreeMap<String, NotObserved>,
) -> Result<Recorded> {
    // Ingest refuses an un-settleable finding rather than storing one nothing
    // can close. `rules::validate` already refuses the rule that would produce
    // it, so reaching here means a producer this crate owns skipped a column —
    // and pointer-only (rule id + identity hash), never the finding's content.
    for finding in findings {
        if finding.remediation.is_none() {
            return Err(crate::UsageError::raise(format!(
                "finding {} from rule {}: no `fix` and no `no_fix_reason`; a finding a caller \
                 cannot act on is not storable",
                finding.identity.fingerprint.to_hex(),
                finding.rule
            )));
        }
    }

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
                // What settles it and what to do about it, captured at mint from
                // the rule that produced it — so the store never has to reach
                // back into a config it cannot see, and a later config edit does
                // not silently redefine how a settled finding clears.
                check: Some(finding.check.clone()),
                remediation: finding.remediation.clone(),
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
    // zero HERE — *if its rule looked*. Not deleted: another context may still
    // be seeing it, and the record is what carries that.
    for mut existing in load_all(store_dir)? {
        if seen.contains(&existing.identity.fingerprint) {
            continue;
        }
        // A rule scan says **nothing** about a sequence finding, so its silence
        // is not evidence about one (CLOUD-97). These identities are produced by
        // a detector over the session's event order, not by any `[[rule]]` row,
        // and the pass below would otherwise resolve every one of them on the
        // very next scan — clearing an open incident because something that
        // never looked at it did not see it. That is the same fail-open
        // [`Observation::NotObserved`] exists to prevent, one level up: here the
        // honest answer is not "not observed" but "not this door's to answer",
        // so the record is left exactly as its own detector wrote it.
        //
        // Skipped rather than held, and the difference matters: writing
        // `NotObserved` here would overwrite a live `Observed(1)` with "nobody
        // looked" on every unrelated scan, which loses the raise.
        //
        // An identity whose kind this binary cannot classify is **not** skipped:
        // guessing `Sequence` for a future kind would exempt it from resolution
        // forever, and the pre-existing behaviour is the safer default for
        // everything that is not known to be this detector's.
        if existing.identity.kind() == Some(FindingKind::Sequence) {
            continue;
        }
        let Some(previous) = existing.instance(context) else {
            continue;
        };
        // The fail-closed branch. A rule that did not run reports nothing, and
        // nothing is not zero: resolving here would let a rule whose glob
        // matched no files clear every finding it covers. The instance says so
        // rather than keeping a stale count, because "not looked at" is a real
        // observation and this is the only thing in the engine that makes one.
        if let Some(&why) = not_evaluated.get(&existing.rule) {
            let already =
                matches!(previous.occurrences, Observation::NotObserved(seen) if seen == why);
            if already {
                continue;
            }
            let (path, line) = (previous.path.clone(), previous.line);
            existing.upsert(Instance {
                context: context.clone(),
                occurrences: Observation::NotObserved(why),
                observed_at_commit: commit.to_owned(),
                worktree_path: worktree.map(ToOwned::to_owned),
                path,
                line,
            });
            write_record(store_dir, &existing)?;
            summary.held += 1;
            continue;
        }
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

/// One advisory outcome, on its way into the store (CLOUD-56).
///
/// **The type is the guarantee.** An advisory outcome carries no
/// [`RuleSeverity`], so it cannot be built into a [`Finding`], so
/// [`crate::rules::any_blocking`] and `--fail-on-warning` have nothing to
/// promote. The advisory surface is unable to block because there is no value
/// here that the exit contract knows how to read — not because a branch
/// declined to.
///
/// Two producers, through two doors: a judge row ([`record_advisory`]) and a
/// transcript-substrate detector ([`record_sequence`], CLOUD-97). One value
/// type rather than two near-identical ones, because the guarantee above is
/// exactly what both need and a second copy of it is a second thing to keep
/// true.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Advisory {
    /// The rule or detector that produced it.
    pub rule: String,
    /// The identity this outcome is keyed by.
    pub identity: StoredIdentity,
    /// How fast it must be answered — **declared on the row**, not derived
    /// through the rank table, because the row declares no severity to derive
    /// one from.
    pub tier: AdvisoryTier,
    /// Where it is, as a pointer.
    pub path: String,
    /// The line, when the outcome locates one. A judge judges a file, so
    /// usually `None`.
    pub line: Option<usize>,
    /// What settles it: re-running the judge command.
    pub check: Check,
    /// What to do about it. A judge row's `no_fix_reason`, since a model's
    /// opinion has no mechanical fix.
    pub remediation: Remediation,
}

/// Fold one judge outcome into the store as this context's instance.
///
/// The sibling of [`record`], and the differences are exactly two: the tier
/// comes off the row instead of the rank table, and this door does not resolve
/// anything it did not see. That second one matters — [`record`] is a *scan*, so
/// an identity it did not produce is evidence of absence in that context; a
/// judge invocation is one rule's answer about one row, and reading it as a
/// statement about every other finding would resolve them on a silence nobody
/// asked for. Clearing a judge finding is the judge's own `check` re-running
/// (CLOUD-81), not this.
///
/// # Errors
///
/// Returns an error when the record cannot be read or written.
pub fn record_advisory(
    store_dir: &Path,
    context: &Context,
    commit: &str,
    worktree: Option<&str>,
    advisory: &Advisory,
    schema: u32,
) -> Result<Recorded> {
    let mut summary = Recorded::default();
    let path = record_path(store_dir, advisory.identity.fingerprint);
    let mut existing = read_record(&path).unwrap_or_else(|| {
        summary.minted += 1;
        FindingRecord {
            schema,
            identity: advisory.identity.clone(),
            rule: advisory.rule.clone(),
            // The one field with nothing honest to put in it. `Allow` is the
            // severity a judge row carries (injected by `config::parse`, which
            // refuses the key), and it says the right thing here too: this
            // record's rule denies nothing. The exit contract reads `Finding`s,
            // and this never was one.
            severity: RuleSeverity::Allow,
            tier: advisory.tier,
            disposition: None,
            presentation: Presentation::Shown,
            check: Some(advisory.check.clone()),
            remediation: Some(advisory.remediation.clone()),
            instances: Vec::new(),
        }
    });
    // The tier is NOT touched on an existing record, the same no-escalation law
    // `record` observes (CLOUD-80): seeing a judge raise the same thing twice
    // changes its count, never its deadline.
    existing.upsert(Instance {
        context: context.clone(),
        occurrences: Observation::Observed(1),
        observed_at_commit: commit.to_owned(),
        worktree_path: worktree.map(ToOwned::to_owned),
        path: advisory.path.clone(),
        line: advisory.line,
    });
    write_record(store_dir, &existing)?;
    summary.updated += 1;
    Ok(summary)
}

/// Fold one sequence detector's outcome into the store (CLOUD-97).
///
/// The third door, and the differences from [`record_advisory`] are exactly
/// two — both of them about the fact that this detector answers a **three-way**
/// question rather than only raising:
///
/// * The caller supplies the [`Observation`]. A judge invocation only ever
///   raises, so its door hard-codes `Observed(1)`; a sequence detector
///   re-evaluates one predicate and its answer may be "still there", "gone", or
///   "could not look". Passing the observation in is what makes the finding
///   **self-clearing**: `Observed(0)` on the next evaluation resolves it with no
///   acknowledgement from anybody.
/// * **It mints only on a positive observation.** A clear or a hold over an
///   identity the store has never seen writes nothing at all, because a record
///   whose only instance says "zero" or "not looked at" describes a finding that
///   was never raised — and every consumer counting open findings would have to
///   learn to ignore it.
///
/// Like [`record_advisory`], and unlike [`record`], it resolves nothing it did
/// not look at: one identity in, one identity touched.
///
/// # Errors
///
/// Returns an error when the record cannot be read or written.
pub fn record_sequence(
    store_dir: &Path,
    context: &Context,
    commit: &str,
    worktree: Option<&str>,
    advisory: &Advisory,
    observation: Observation,
    schema: u32,
) -> Result<Recorded> {
    let mut summary = Recorded::default();
    let path = record_path(store_dir, advisory.identity.fingerprint);
    let existing = read_record(&path);
    let raised = matches!(observation, Observation::Observed(count) if count > 0);
    let mut record = match existing {
        Some(record) => record,
        // Nothing stored, and nothing to store: see the doc comment.
        None if !raised => return Ok(summary),
        None => {
            summary.minted += 1;
            FindingRecord {
                schema,
                identity: advisory.identity.clone(),
                rule: advisory.rule.clone(),
                // Nothing honest to put here, the same reading
                // `record_advisory` gives it: this record's producer denies
                // nothing, and the exit contract reads `Finding`s, which this
                // never was.
                severity: RuleSeverity::Allow,
                tier: advisory.tier,
                disposition: None,
                presentation: Presentation::Shown,
                check: Some(advisory.check.clone()),
                remediation: Some(advisory.remediation.clone()),
                instances: Vec::new(),
            }
        }
    };
    // The tier is never touched on an existing record — CLOUD-80's
    // no-escalation law. Re-observing a finding moves its count and never its
    // deadline, and that holds for a re-evaluation as much as for a re-scan.
    record.upsert(Instance {
        context: context.clone(),
        occurrences: observation,
        observed_at_commit: commit.to_owned(),
        worktree_path: worktree.map(ToOwned::to_owned),
        path: advisory.path.clone(),
        line: advisory.line,
    });
    write_record(store_dir, &record)?;
    match observation {
        Observation::Observed(0) => summary.resolved += 1,
        Observation::Observed(_) => summary.updated += 1,
        Observation::NotObserved(_) => summary.held += 1,
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

    /// A scratch store directory, the same idiom [`crate::journal`]'s suite
    /// uses: one convention for one need, rather than two suites inventing two.
    fn store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "batten-findings-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn finding_for(severity: RuleSeverity) -> Finding {
        Finding {
            rule: "r".to_owned(),
            severity,
            path: "src/a.rs".to_owned(),
            line: Some(1),
            identity: identity_for("r", "src/a.rs", "TODO"),
            check: Check::Reevaluate,
            remediation: Some(Remediation::NoFix("fixture".to_owned())),
        }
    }

    /// Every configured rule evaluated — the ordinary scan, where absence really
    /// is a clear. The hold path has its own fixtures.
    fn all_evaluated() -> BTreeMap<String, NotObserved> {
        BTreeMap::new()
    }

    /// The `"tier"` line as it sits in the record file — the *stored* bytes,
    /// which is the thing CLOUD-80 §7 asks to be byte-identical across
    /// observations. A `PartialEq` over a deserialized enum cannot see a write
    /// path that re-serialized the field differently.
    fn stored_tier_bytes(dir: &Path, fingerprint: Fingerprint) -> String {
        let text = std::fs::read_to_string(record_path(dir, fingerprint)).unwrap();
        text.lines()
            .find(|line| line.trim_start().starts_with("\"tier\""))
            .expect("the record persists a tier")
            .to_owned()
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
            check: Some(Check::Reevaluate),
            remediation: Some(Remediation::NoFix("fixture".to_owned())),
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
    fn an_nth_observation_never_re_tiers_the_stored_record() {
        // CLOUD-80 §7, over the STORE rather than over a struct. The in-memory
        // sibling above drives `upsert` directly, so it can never see the two
        // ways a stored tier could actually move: a write path that re-derives
        // it, and a later scan that re-rates the rule. Both need a real store
        // dir, which is why this test exists alongside that one rather than
        // instead of it.
        //
        // Total over the axis: every RuleSeverity, so every one of
        // AdvisoryTier::ALL is exercised — not just the deny/warning rank a
        // single-severity fixture would reach.
        for &severity in RuleSeverity::ALL {
            let dir = store(&format!("no-escalation-{}", severity.as_str()));
            let context = Context::new("refs/heads/a");
            let finding = finding_for(severity);
            let fingerprint = finding.identity.fingerprint;
            let expected = row_for_rule(severity).tier;
            let mut first_bytes = None;

            for n in 1..=5_u64 {
                // The same identity n times in one scan: `record` folds them to
                // one finding with a count, which is what makes n the
                // occurrence count rather than n records.
                let findings = vec![finding.clone(); usize::try_from(n).unwrap()];
                record(
                    &dir,
                    &context,
                    &"0".repeat(40),
                    None,
                    &findings,
                    FINDINGS_SCHEMA,
                    &all_evaluated(),
                )
                .unwrap();

                let stored = load_one(&dir, fingerprint).unwrap().unwrap();
                assert_eq!(
                    stored.tier,
                    expected,
                    "observation {n} re-tiered a finding minted at {}",
                    severity.as_str()
                );
                // Byte-identical to the first observation, not merely equal:
                // the stored bytes are the compatibility surface (§6).
                let bytes = stored_tier_bytes(&dir, fingerprint);
                match &first_bytes {
                    None => first_bytes = Some(bytes),
                    Some(first) => assert_eq!(&bytes, first, "the stored tier bytes moved"),
                }
                // …and the axis that IS supposed to move did, so this cannot
                // pass by the store having recorded nothing at all.
                assert_eq!(
                    stored.instance(&context).unwrap().occurrences,
                    Observation::Observed(n),
                    "the count is the axis that moves"
                );
            }

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_re_rated_rule_never_re_tiers_a_settled_finding() {
        // "Escalation on re-touch is absent" in its sharpest form. Severity is
        // not an identity input, so re-rating a rule routes the next scan to
        // the SAME record — and `record` reuses that record rather than
        // re-deriving from the rule now firing. A refactor that "refreshed" it
        // would silently re-tier every settled finding in the store, and until
        // this test nothing failed when it did.
        let dir = store("re-rated");
        let context = Context::new("refs/heads/a");
        let commit = "0".repeat(40);
        let fingerprint = finding_for(RuleSeverity::Warn).identity.fingerprint;

        record(
            &dir,
            &context,
            &commit,
            None,
            &[finding_for(RuleSeverity::Warn)],
            FINDINGS_SCHEMA,
            &all_evaluated(),
        )
        .unwrap();
        let minted = load_one(&dir, fingerprint).unwrap().unwrap();
        assert_eq!(minted.tier, AdvisoryTier::Caution);

        record(
            &dir,
            &context,
            &commit,
            None,
            &[finding_for(RuleSeverity::Deny)],
            FINDINGS_SCHEMA,
            &all_evaluated(),
        )
        .unwrap();
        let after = load_one(&dir, fingerprint).unwrap().unwrap();
        assert_eq!(
            after.tier,
            AdvisoryTier::Caution,
            "a re-rated rule must not re-tier a finding already in the store"
        );
        assert_eq!(
            after.severity,
            RuleSeverity::Warn,
            "the recorded severity is the one the finding was minted under"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_finding_clears_when_the_rule_looked_and_no_longer_finds_it() {
        // Acceptance (a), CLOUD-81. The rule ran and produced nothing, so its
        // silence IS evidence: the instance resolves to zero, recorded against
        // this identity in this context. This is the self-clear.
        let dir = store("clears");
        let context = Context::new("refs/heads/a");
        let commit = "0".repeat(40);
        let finding = finding_for(RuleSeverity::Deny);
        let fingerprint = finding.identity.fingerprint;

        record(
            &dir,
            &context,
            &commit,
            None,
            &[finding],
            FINDINGS_SCHEMA,
            &all_evaluated(),
        )
        .unwrap();

        // The same rule, evaluated again, finding nothing.
        let after = record(
            &dir,
            &context,
            &commit,
            None,
            &[],
            FINDINGS_SCHEMA,
            &all_evaluated(),
        )
        .unwrap();
        assert_eq!(after.resolved, 1, "an evaluated absence is a clear");
        assert_eq!(after.held, 0);
        assert_eq!(
            load_one(&dir, fingerprint)
                .unwrap()
                .unwrap()
                .instance(&context)
                .unwrap()
                .occurrences,
            Observation::Observed(0),
            "the clear is recorded against the identity, in this context"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rule_that_did_not_evaluate_never_clears_its_findings() {
        // Acceptance (b), and the fail-open this issue exists to close. A rule
        // whose glob matched nothing reports exactly what a clean rule reports —
        // nothing — so absence alone cannot be the clear. Before this, every
        // unseen identity resolved unconditionally, which let a rule that never
        // read a file close every finding it covers.
        //
        // Both non-evaluation reasons, because a caller must not have to know
        // which one it is: "did not evaluate" is the whole predicate.
        for why in [NotObserved::RuleSkipped, NotObserved::RuleErrored] {
            let dir = store(&format!("holds-{why:?}"));
            let context = Context::new("refs/heads/a");
            let commit = "0".repeat(40);
            let finding = finding_for(RuleSeverity::Deny);
            let fingerprint = finding.identity.fingerprint;
            let rule = finding.rule.clone();

            record(
                &dir,
                &context,
                &commit,
                None,
                &[finding],
                FINDINGS_SCHEMA,
                &all_evaluated(),
            )
            .unwrap();

            let not_evaluated = BTreeMap::from([(rule, why)]);
            let after = record(
                &dir,
                &context,
                &commit,
                None,
                &[],
                FINDINGS_SCHEMA,
                &not_evaluated,
            )
            .unwrap();
            assert_eq!(after.resolved, 0, "a silence that is not evidence");
            assert_eq!(after.held, 1);

            let stored = load_one(&dir, fingerprint).unwrap().unwrap();
            let observed = stored.instance(&context).unwrap().occurrences;
            assert_eq!(
                observed,
                Observation::NotObserved(why),
                "the instance says the rule did not look"
            );
            assert_eq!(
                observed.count(),
                None,
                "and so declines to vouch for any count"
            );
            assert!(
                observed.compare(1).is_none(),
                "a caller comparing this must hold, never resolve"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn a_finding_with_no_remediation_is_refused_at_ingest() {
        // Acceptance (c)/(d). `rules::validate` already refuses the rule that
        // would produce one, so reaching the store means a producer inside this
        // crate skipped a column — refused rather than stored, because a finding
        // nothing can close is attention spent for nothing.
        let dir = store("checkless");
        let finding = Finding {
            remediation: None,
            ..finding_for(RuleSeverity::Deny)
        };
        let err = record(
            &dir,
            &Context::new("refs/heads/a"),
            &"0".repeat(40),
            None,
            &[finding],
            FINDINGS_SCHEMA,
            &all_evaluated(),
        )
        .unwrap_err();

        // Exit 1, the config-error code — never the 2 that is the deny channel
        // (house style §7, non-negotiable rule 5). A malformed rule must not be
        // able to deny a call.
        assert!(
            err.downcast_ref::<crate::error::UsageError>().is_some(),
            "a missing remediation is a config error (exit 1), not a policy verdict (exit 2): a \
             malformed rule must not be able to deny a call"
        );
        // Pointer-only: the rule id and the identity hash, never the flagged
        // content (rule 4).
        let message = err.to_string();
        assert!(message.contains("no_fix_reason"), "it names the remedy");
        assert!(
            load_all(&dir).unwrap().is_empty(),
            "and nothing was stored on the way to refusing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_predating_the_check_fields_loads_and_is_not_emittable() {
        // The rolling window's other half: a schema-2 record still loads, and
        // reads as exactly what it is — checkless. Defaulting a check here would
        // invent a verdict during a read, so absence stays absence and the drain
        // (CLOUD-79/82) refuses on this predicate rather than re-typing it.
        let legacy = serde_json::json!({
            "schema": 2,
            "identity": serde_json::to_value(identity_for("r", "src/a.rs", "TODO")).unwrap(),
            "rule": "r",
            "severity": "deny",
            "tier": "warning",
            "presentation": "shown",
            "instances": [],
        });
        let record: FindingRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(record.check, None);
        assert_eq!(record.remediation, None);
        assert!(!record.is_emittable(), "checkless is not emittable");

        // A record minted today is, and both halves are required — either one
        // missing is a finding a caller cannot close.
        assert!(record_of(Vec::new()).is_emittable());
        for stripped in [
            FindingRecord {
                check: None,
                ..record_of(Vec::new())
            },
            FindingRecord {
                remediation: None,
                ..record_of(Vec::new())
            },
        ] {
            assert!(!stripped.is_emittable());
        }
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

    // --- (h) key-loss custody at the store boundary (CLOUD-529) --------------

    // The one bypass of the join, and its whole justification is that `merge` is
    // `max`: nothing in that algebra can lower a settled answer, which is exactly
    // right for concurrent writers and exactly wrong for an orphan. So the bypass
    // has to exist as its own verb, and it has to say whether anything moved — a
    // caller reporting "N re-opened" must count what changed, not what it read.
    #[test]
    fn reopening_a_settled_finding_clears_it_and_says_so() {
        let mut record = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        record.disposition = Some(Disposition::RejectedByDesign);
        assert!(record.reopen(), "a settled record moves");
        assert_eq!(record.disposition, None);
        assert!(
            !record.reopen(),
            "an already-unsettled record is not a second re-open"
        );
        // The join could not have done this: `max` over the precedence order only
        // ever raises, which is the property this bypasses and not one it breaks.
        record.merge_disposition(Some(Disposition::RejectedWrong));
        record.merge_disposition(None);
        assert_eq!(record.disposition, Some(Disposition::RejectedWrong));
    }

    // Re-opening touches the disposition and nothing else. An orphan event is the
    // loss of the ability to compare, not a re-mint — so re-deriving the tier, the
    // instances or the presentation here would be the silent re-mint arriving by
    // another route.
    #[test]
    fn reopening_a_finding_re_mints_nothing_else() {
        let mut record = record_of(vec![instance("refs/heads/a", Observation::Observed(3))]);
        record.disposition = Some(Disposition::Acted);
        record.presentation = Presentation::NotShown(NotShown::DrainSuppressed);
        let before = FindingRecord {
            disposition: None,
            ..record.clone()
        };
        record.reopen();
        assert_eq!(record, before);
    }

    // A rotation writes the same finding under its new identity and then drops the
    // old file. Leaving it would hold one finding twice, the second copy under a
    // fingerprint nothing can re-derive — so nothing would ever clear it.
    #[test]
    fn forgetting_a_record_is_absent_safe_and_leaves_its_siblings() {
        let dir = store("forget");
        let kept = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        let mut dropped = kept.clone();
        dropped.identity = identity_for("r", "src/b.rs", "TODO");
        save_one(&dir, &kept).unwrap();
        save_one(&dir, &dropped).unwrap();

        forget(&dir, dropped.identity.fingerprint).unwrap();
        assert!(
            load_one(&dir, dropped.identity.fingerprint)
                .unwrap()
                .is_none(),
            "the rotated-away identity is gone"
        );
        assert!(
            load_one(&dir, kept.identity.fingerprint).unwrap().is_some(),
            "and only that one"
        );
        forget(&dir, dropped.identity.fingerprint)
            .expect("forgetting an absent record is success, which is what lets a join replay");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A flap suppression is the engine withholding a finding, so it must be
    // excluded from both sides of the false-positive rate for the same reason the
    // other three reasons are: the agent was never shown it, so its silence is not
    // a judgement. Free from being a `NotShown` arm — asserted because "free" is a
    // claim about a type, and a fourth arm added outside `Presentation` would not
    // have been.
    #[test]
    fn a_flap_suppressed_finding_is_excluded_from_the_false_positive_rate() {
        let mut suppressed = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        suppressed.presentation = Presentation::NotShown(NotShown::FlapSuppressed);
        let mut shown = record_of(vec![instance("refs/heads/a", Observation::Observed(1))]);
        shown.identity = identity_for("r", "src/b.rs", "TODO");
        let rates = effective_fp_rates(&[suppressed, shown]);
        assert_eq!(
            rates["r"],
            FpRate {
                shown: 1,
                ignored: 1
            }
        );
    }
}
