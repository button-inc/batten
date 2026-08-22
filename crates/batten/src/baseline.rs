//! The adoption path for a repository that is already dirty (CLOUD-67).
//!
//! Adopting a policy engine should not require a big-bang cleanup. A baseline is
//! the persisted set of finding identities that **already existed** when the
//! repository adopted Batten, so [`crate::rules`]'s existing findings stop
//! failing `check` and anything new still does.
//!
//! # What this must not become
//!
//! A baseline over a dirty repo is a bulk waiver by another name, and the agent
//! running it is both the subject of the findings and the writer of the store —
//! the issue's own adversarial review ranks that the top risk. The likeliest
//! honest error in Batten's threat model is not a lie; it is greening a red gate
//! by baselining instead of fixing. So three properties are structural here
//! rather than promised:
//!
//! * **It is declared and inspectable.** The artifact is one JSON document with a
//!   schema, listing rule ids, hex fingerprints and counts. Nothing is suppressed
//!   that the file does not name.
//! * **It mints only behind a computable predicate** ([`mintable`]) — no model
//!   verdict, no server state, no "is this reasonable".
//! * **Its staleness is loud** — an entry with nothing behind it is an ordinary
//!   [`Finding`] on the `0/1/2/3` table (§7), not a warning line somebody can
//!   scroll past.
//!
//! # The minting predicate: patch identity, never ancestry
//!
//! The issue asks that "the baselined state must be an ancestor of the
//! authoritative ref at its currently-fetched SHA". That claim cannot be spelled
//! as ancestry in this crate, and the refusal is a compiled one:
//! `git::tests::no_ancestry_decides_merged_ness` scans every `src/*.rs` file —
//! including `git.rs` itself, and including this module — for the whole
//! reachability-answer vocabulary, which is why the tokens are named nowhere in
//! this file. (It caught this paragraph's first draft, which spelled them out to
//! explain them. A gate that exempted the prose describing it would be a gate
//! with a hole shaped exactly like a comment.) Merged-ness is decided by **patch
//! identity**, because a rebased or squashed landing is invisible to ancestry
//! and these repositories land by fast-forward, where a landed branch is an
//! ancestor of nothing.
//!
//! So the predicate is the one the tree already has:
//! [`crate::worktree::status`], whose `unlanded` half is `git::landing` — patch
//! identity over the trunk — and whose other halves are the uncommitted and
//! unpushed facts the same question needs. **Any at-risk work refuses the mint.**
//! That is stronger than ancestry on exactly the case that matters, and it needs
//! no new git surface.
//!
//! `Unlanded::NotComputable` — no `must_land_on` and no recorded remote default —
//! is at-risk, so a state that cannot be *proved* landed cannot be baselined.
//! Reading "could not look" as "clean" is the fail-open this module exists on the
//! other side of.
//!
//! # Why the artifact lives under the bound store
//!
//! Beside `findings/` and `journal/`, addressed through [`crate::store`] rather
//! than by a plain join onto [`crate::state::repo_state_dir`] — which is the
//! idiom every *other* store here uses (`captures/`, `decisions/`, receipts).
//! The difference is what this one keys on: **finding identities**, whose records
//! live in the bound store. A baseline under `repo_state_dir` would survive a
//! `batten state adopt` while describing a store the checkout is no longer bound
//! to, which is a second answer to "which store holds this repository's
//! findings" — the question `store.rs` exists to answer exactly once.
//!
//! No bound store means no baseline: [`load`] answers `None` and `check` filters
//! nothing. That direction is safe — findings report — where the inverse would
//! suppress against a store nobody bound.
//!
//! # The clock is an input, and reads nothing
//!
//! `minted_at` is provenance and no predicate consults it: it is passed in at the
//! boundary ([`crate::waiver::today`]'s idiom), so §6 byte-stability survives.
//! The ref and the two SHAs are git facts, which is the same reason
//! `receipt.rs` states its expiry as one. The crate fetches nothing
//! (`git.rs`: "agents fetch, gates decide"), so "currently fetched" is the
//! caller's freshness and this record is what makes it inspectable afterwards.
//!
//! # Counts, and the tier that never moves
//!
//! An entry anchors the occurrence count observed at mint, and drift is judged by
//! [`crate::identity::compare_to_anchor`] — the direction-aware semantics
//! CLOUD-123 decided, reused rather than re-derived. An increase re-raises
//! (new evidence fails), a decrease ratchets and surfaces only as prune
//! staleness (punishing incremental fixing is wrong), zero resolves.
//!
//! **Count drift never moves a severity tier**, the invariant
//! [`crate::severity`] deferred to this command. It holds structurally: [`apply`]
//! only ever *removes* elements from the finding vector and never constructs or
//! mutates one, so a re-raised finding carries the severity its rule declared and
//! resolves the tier it always did. There is no code path here that could move it.
//!
//! # Two holds, both fail-closed
//!
//! * **A rule that did not run holds its entries.** An entry whose rule appears in
//!   [`crate::rules::Scan::not_evaluated`] is held, never reported stale — reading
//!   a skipped or errored rule's silence as "resolved" is
//!   [`crate::findings::Observation`]'s fail-open one level up.
//! * **An identity-version bump holds, it does not unmatch.** The issue is
//!   explicit that a migration must cover baselines "or a bump silently
//!   invalidates every adopter's baseline". An entry minted under a different
//!   [`crate::identity::FindingKind::identity_version`] is held and reported as
//!   `baseline.version-drift`, pointing at `batten state migrate`. Building the
//!   dual-extractor equality join is the store's migration work, not this
//!   module's; refusing to *silently* discard is this module's.
//!
//! Neither hold is ever pruned. Pruning an entry nobody looked at is the same
//! fail-open, moved to write time.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::findings::{Check, NotObserved, Remediation};
use crate::identity::{self, CountChange, FindingKind, StoredIdentity};
use crate::rules::{Finding, Scan};
use crate::severity::RuleSeverity;
use crate::state;
use crate::store;
use crate::waiver::Date;
use crate::worktree;

/// Render `date` as `YYYY-MM-DD`.
///
/// Local to this module rather than a `Display` on [`Date`]: the one spelling
/// that type owns is [`Date::parse`]'s input, and a baseline's provenance field
/// is the only thing that renders one back out today.
fn render_date(date: Date) -> String {
    format!("{:04}-{:02}-{:02}", date.year, date.month, date.day)
}

/// The document's own version, so a future shape change is a migration rather
/// than a misparse. Read-compatible range is a single version today; widening it
/// is the same write-old/read-both discipline [`crate::journal`] documents.
pub const BASELINE_SCHEMA: u32 = 1;

/// The file, under the bound store directory beside `findings/` and `journal/`.
const BASELINE_FILE: &str = "baseline.json";

/// The rule id an unmatched entry reports under.
pub const STALE_RULE: &str = "baseline.stale";

/// The rule id an entry minted under a superseded identity version reports under.
pub const VERSION_DRIFT_RULE: &str = "baseline.version-drift";

/// What the baseline was minted against — git facts, plus a provenance date no
/// predicate reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Minted {
    /// The authoritative ref the state was judged to have landed on, as a full
    /// ref name. `None` is unreachable through [`mint`] — an unresolvable target
    /// refuses — and is accepted on read so a document written by a future shape
    /// is not a parse failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// That ref's commit at mint time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// The `HEAD` commit whose findings were recorded.
    pub commit: String,
    /// The day the mint happened. Provenance only — see the module header.
    pub minted_at: String,
}

/// One baselined identity: what it is, which rule raised it, and how many times
/// it occurred when the anchor was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The finding identity, fingerprint and minting version together. The
    /// version rides beside the hash precisely so a migration can pair two
    /// extractors' output; dropping it here would make a bump indistinguishable
    /// from a fix.
    pub identity: StoredIdentity,
    /// The rule that raised it, carried so a held entry can be recognised from
    /// [`Scan::not_evaluated`] without reaching back into a config.
    pub rule: String,
    /// The occurrence count at mint — the anchor
    /// [`identity::compare_to_anchor`] judges drift against.
    pub count: u64,
}

impl Entry {
    /// The pointer this entry renders as: the rule and the fingerprint, never
    /// content (non-negotiable rule 4). A digest prefix rather than the whole
    /// hash, matching the short-sha convention the rest of the tree reads by eye.
    #[must_use]
    pub fn pointer(&self) -> String {
        let hex = self.identity.fingerprint.to_hex();
        format!("{} {}", self.rule, &hex[..12.min(hex.len())])
    }
}

/// The persisted baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// The document version.
    pub schema: u32,
    /// What it was minted against.
    pub minted: Minted,
    /// The baselined identities, sorted by fingerprint hex so the document is
    /// byte-stable for a given set (§6).
    pub entries: Vec<Entry>,
}

impl Baseline {
    /// The entry for `identity`'s fingerprint, if the baseline holds one.
    #[must_use]
    pub fn entry(&self, identity: &StoredIdentity) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.identity.fingerprint == identity.fingerprint)
    }
}

/// Whether **any** store on this machine holds a baseline at all.
///
/// The short-circuit that keeps [`load`] off `check`'s hot path, and it is exact
/// rather than a heuristic: every directory [`store::bound_dir`] can name is a
/// store directory under [`state::state_root`], so if none of them carries a
/// [`BASELINE_FILE`] there is nothing this checkout could possibly load. A `false`
/// here is a proof, never a guess — which is what lets it stand in front of the
/// resolution instead of merely usually agreeing with it.
///
/// It exists because the resolution behind it is **not** cheap: `store::resolve`
/// spawns git several times (the common dir, the remotes, the root commits) and
/// may walk every store. Measured by `perf-gate` on this change's first draft,
/// which put that on every `check`: p50 went 3.25ms → 24.93ms, a 7.7x regression
/// on the workhorse verb, for a question that is almost always "no". One
/// `read_dir` of the state root answers it with no process spawn.
///
/// An unreadable or absent state root is `false` for the same reason: nothing has
/// been recorded, so nothing can be suppressed. The direction is safe — findings
/// report.
fn any_baseline_exists() -> bool {
    let Ok(root) = state::state_root() else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| entry.path().join(BASELINE_FILE).exists())
}

/// Where the baseline lives for the checkout containing `root`, or `None` when
/// no store is bound to it.
///
/// `root` is re-resolved through [`crate::git::repo_root`] rather than used as
/// given: callers reach here with `lib`'s run anchor, which is `.` whenever the
/// process directory holds a `batten.toml`, and a store is addressed by the
/// checkout's *canonical absolute* root — a relative one names a different tree
/// from each directory it is read in, which [`crate::state::derive_repo_name`]
/// refuses outright.
///
/// **Outside a repository there is no store and therefore no baseline**, which is
/// `None` rather than an error: `batten check` runs in a plain directory holding
/// a config, and turning that into a failure would break a verb that has always
/// worked there. The direction is safe — findings report.
///
/// # Errors
///
/// Propagates a store-resolution failure. Resolution **reads and never writes**,
/// which is what keeps `check`'s declared `read` effect honest.
pub fn path(root: &Path) -> Result<Option<PathBuf>> {
    let Ok(repo) = crate::git::repo_root(root) else {
        return Ok(None);
    };
    let opened = store::resolve(&repo)?;
    Ok(store::bound_dir(&opened).map(|dir| dir.join(BASELINE_FILE)))
}

/// Read the baseline for `root`, or `None` when there is no bound store or no
/// baseline in it.
///
/// A document whose `schema` this build does not know is **not** silently
/// ignored: it raises, because treating an unreadable baseline as an empty one
/// would report every baselined finding as new — loud, but loud about the wrong
/// thing, and it would tempt a re-mint that discards the record.
///
/// [`any_baseline_exists`] guards the resolution, and the guard is on **this**
/// function rather than on [`path`] because the two callers want opposite things
/// from an empty machine: `check` wants to spend nothing discovering there is no
/// baseline, and [`save`] is on its way to writing the first one, so a
/// short-circuit there would make minting impossible.
///
/// # Errors
///
/// Raises when the file exists and cannot be read or parsed, or carries a schema
/// outside this build's range.
pub fn load(root: &Path) -> Result<Option<Baseline>> {
    if !any_baseline_exists() {
        return Ok(None);
    }
    let Some(file) = path(root)? else {
        return Ok(None);
    };
    if !file.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
    let baseline: Baseline = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse the baseline at {}", file.display()))?;
    if baseline.schema != BASELINE_SCHEMA {
        anyhow::bail!(
            "the baseline at {} is schema {} and this build reads {BASELINE_SCHEMA}; run `batten \
             state migrate`",
            file.display(),
            baseline.schema
        );
    }
    Ok(Some(baseline))
}

/// Write `baseline` for `root`, atomically.
///
/// Temp-file plus rename, following [`crate::findings`]'s record writer: a
/// half-written baseline would suppress an arbitrary prefix of the set.
///
/// # Errors
///
/// Raises a [`crate::UsageError`] when no store is bound — there is nowhere
/// honest to put it — and propagates an I/O failure otherwise.
pub fn save(root: &Path, baseline: &Baseline) -> Result<PathBuf> {
    let file = path(root)?.ok_or_else(|| {
        UsageError::raise(
            "no findings store is bound to this checkout; run `batten state adopt` first"
                .to_owned(),
        )
    })?;
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temp = file.with_extension("json.tmp");
    let mut json = serde_json::to_string_pretty(baseline)?;
    json.push('\n');
    std::fs::write(&temp, json).with_context(|| format!("write {}", temp.display()))?;
    std::fs::rename(&temp, &file)
        .with_context(|| format!("install the baseline at {}", file.display()))?;
    Ok(file)
}

/// Why a mint was refused. Pointer-only by construction: every variant carries
/// ids and locations the caller already has, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The checkout carries work that is uncommitted, unpushed, or not landed on
    /// the authoritative ref — including the case where no such ref resolves.
    /// Carries [`worktree::AtRisk`]'s own pointer lines.
    AtRisk(Vec<String>),
}

impl Refusal {
    /// The lines this refusal renders as.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        match self {
            Refusal::AtRisk(lines) => {
                let mut rendered = vec![
                    "baseline refused: only landed, committed state may be baselined".to_owned(),
                ];
                rendered.extend(lines.iter().cloned());
                rendered
            }
        }
    }
}

/// Whether the state in `root` may be baselined.
///
/// The whole minting gate, and a computable predicate rather than a judgement:
/// it resolves to [`worktree::status`] and its exit-bearing `any()`. See the
/// module header for why this is patch identity and not ancestry.
///
/// # Errors
///
/// Propagates `worktree::status`'s errors: a [`crate::UsageError`] when `root` is
/// not a repository or a declared `must_land_on` resolves to no commit.
pub fn mintable(root: &Path, must_land_on: Option<&str>) -> Result<Option<Refusal>> {
    let at_risk = worktree::status(root, must_land_on)?;
    if at_risk.any() {
        return Ok(Some(Refusal::AtRisk(at_risk.lines())));
    }
    Ok(None)
}

/// Fold a scan's findings into `(fingerprint -> occurrences)`.
///
/// [`identity::count_occurrences`] is the one implementation of this; a second
/// fold here would be a second definition of "how many times".
fn occurrences(findings: &[Finding]) -> BTreeMap<identity::Fingerprint, u64> {
    identity::count_occurrences(findings.iter().map(|finding| finding.identity.fingerprint))
}

/// Build the entry set for `findings`, anchored at the counts observed now.
fn entries_for(findings: &[Finding]) -> Vec<Entry> {
    let counts = occurrences(findings);
    let mut seen: BTreeMap<identity::Fingerprint, Entry> = BTreeMap::new();
    for finding in findings {
        let fingerprint = finding.identity.fingerprint;
        seen.entry(fingerprint).or_insert_with(|| Entry {
            identity: finding.identity.clone(),
            rule: finding.rule.clone(),
            count: counts.get(&fingerprint).copied().unwrap_or(0),
        });
    }
    // Sorted by fingerprint, which `BTreeMap` already gives: the same set always
    // serialises to the same bytes.
    seen.into_values().collect()
}

/// Mint a baseline over `scan`, against `commit` on `reference`@`sha`.
///
/// The caller has already run [`mintable`]; this is the construction, kept
/// separate so the predicate is testable without a filesystem and the record is
/// testable without a repository.
#[must_use]
pub fn mint(
    scan: &Scan,
    reference: Option<String>,
    sha: Option<String>,
    commit: String,
    today: Date,
) -> Baseline {
    Baseline {
        schema: BASELINE_SCHEMA,
        minted: Minted {
            reference,
            sha,
            commit,
            minted_at: render_date(today),
        },
        entries: entries_for(&scan.findings),
    }
}

/// What [`apply`] decided about one entry, beyond suppressing findings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Drift {
    /// Nothing backs this entry any more, and its rule did run: stale.
    Unmatched,
    /// The count fell but is not zero: the anchor is high, prune to ratchet it.
    Ratcheted {
        /// The recorded anchor.
        anchor: u64,
        /// What was observed now.
        current: u64,
    },
    /// The entry was minted under a superseded identity version, so it is held
    /// rather than judged.
    VersionDrift,
    /// The entry's rule did not evaluate, so its silence is not evidence.
    Held(NotObserved),
}

/// One entry's outcome, paired with the entry so a report can point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drifted {
    /// The entry this is about.
    pub entry: Entry,
    /// What happened to it.
    pub drift: Drift,
}

impl Drifted {
    /// Whether this outcome is reportable as a finding, as opposed to a hold.
    #[must_use]
    pub fn is_reportable(&self) -> bool {
        matches!(
            self.drift,
            Drift::Unmatched | Drift::Ratcheted { .. } | Drift::VersionDrift
        )
    }

    /// The rule this outcome reports under.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self.drift {
            Drift::VersionDrift => VERSION_DRIFT_RULE,
            _ => STALE_RULE,
        }
    }

    /// This outcome as a [`Finding`], or `None` when it is a hold.
    ///
    /// A real `Finding`, not a bespoke channel — the shape [`crate::budget`] and
    /// [`crate::defects`] already use: staleness then flows through the one funnel
    /// `check` and `enforce` share, inheriting waivers, `-J`, the exit contract and
    /// the store instead of re-implementing each of them.
    ///
    /// [`FindingKind::Scope`] is the honest kind: an unmatched baseline entry is a
    /// whole-repository condition, not a span in a file.
    #[must_use]
    pub fn finding(&self) -> Option<Finding> {
        if !self.is_reportable() {
            return None;
        }
        let rule = self.rule().to_owned();
        // The scope key is the entry's own fingerprint, so one stale entry is one
        // identity however often the report is run, and two stale entries never
        // collapse into one finding.
        let scope = self.entry.identity.fingerprint.to_hex();
        let identity = StoredIdentity::new(
            FindingKind::Scope,
            identity::scope_fingerprint(&rule, &scope),
        );
        Some(Finding {
            rule,
            severity: RuleSeverity::Deny,
            // The pointer is the entry, never a path in the tree: the finding
            // that used to be there is precisely what is gone.
            path: self.entry.pointer(),
            line: None,
            identity,
            check: Check::Reevaluate,
            // One remedy for all three, and it is a real command rather than
            // prose: re-evaluating and rewriting the entry set is what settles
            // every reportable drift, version drift included — the migration that
            // makes a superseded entry comparable again is the store's, and until
            // it exists dropping the entry deliberately is the honest move.
            remediation: Some(Remediation::Fix(vec![
                "batten".to_owned(),
                "baseline".to_owned(),
                "--prune".to_owned(),
            ])),
        })
    }
}

/// Filter `findings` against `baseline`, and report what drifted.
///
/// A pure function of its three inputs — no clock, no filesystem, no config —
/// which is what lets the whole decision be tested without a world.
///
/// Returns the findings that survive, in input order, and one [`Drifted`] per
/// baseline entry that has something to say. See the module header for the
/// direction-aware count rules and the two holds.
#[must_use]
pub fn apply(
    findings: Vec<Finding>,
    baseline: &Baseline,
    not_evaluated: &BTreeMap<String, NotObserved>,
) -> (Vec<Finding>, Vec<Drifted>) {
    let counts = occurrences(&findings);
    let mut suppress: BTreeSet<identity::Fingerprint> = BTreeSet::new();
    let mut drifted = Vec::new();

    for entry in &baseline.entries {
        // A rule that did not run reports nothing, and reading that silence as
        // "resolved" is the fail-open this hold exists for. It is checked first:
        // every judgement below would otherwise be made over an absence nobody
        // established.
        if let Some(reason) = not_evaluated.get(&entry.rule) {
            drifted.push(Drifted {
                entry: entry.clone(),
                drift: Drift::Held(*reason),
            });
            // Held, and therefore still suppressing: the entry was accepted once
            // and nothing has been observed to change it.
            suppress.insert(entry.identity.fingerprint);
            continue;
        }

        // A superseded identity version cannot be compared: the fingerprints two
        // extractor versions produce are not the same function's output, so an
        // absent match means "not comparable", never "fixed". A version this
        // build cannot classify at all takes the same branch — "I do not know"
        // must not resolve to "current".
        let comparable = entry
            .identity
            .kind()
            .is_some_and(|kind| kind.identity_version() == entry.identity.version);
        if !comparable {
            drifted.push(Drifted {
                entry: entry.clone(),
                drift: Drift::VersionDrift,
            });
            suppress.insert(entry.identity.fingerprint);
            continue;
        }

        let current = counts
            .get(&entry.identity.fingerprint)
            .copied()
            .unwrap_or(0);
        match identity::compare_to_anchor(entry.count, current) {
            // At or below the anchor, and still present: this is what a baseline
            // is for.
            CountChange::Unchanged => {
                suppress.insert(entry.identity.fingerprint);
            }
            // Fewer than before. Suppressed — punishing incremental fixing is
            // wrong — and surfaced as prune staleness so the anchor does not stay
            // permanently high.
            CountChange::Ratchet => {
                suppress.insert(entry.identity.fingerprint);
                drifted.push(Drifted {
                    entry: entry.clone(),
                    drift: Drift::Ratcheted {
                        anchor: entry.count,
                        current,
                    },
                });
            }
            // A new occurrence is new evidence. NOT suppressed: every occurrence
            // reports, and the finding keeps the severity its rule declared —
            // which is how "count drift never moves a tier" holds structurally.
            CountChange::ReRaise => {}
            // Nothing backs the entry any more and its rule did look, so the
            // absence is proven rather than assumed.
            CountChange::Resolved => drifted.push(Drifted {
                entry: entry.clone(),
                drift: Drift::Unmatched,
            }),
        }
    }

    let kept = findings
        .into_iter()
        .filter(|finding| !suppress.contains(&finding.identity.fingerprint))
        .collect();
    (kept, drifted)
}

/// The baseline `baseline` becomes after a prune over `scan`.
///
/// Drops entries nothing backs and ratchets reduced anchors down. **Held entries
/// survive untouched**: an entry whose rule did not evaluate, or whose identity
/// version is superseded, has not been shown to be gone, and dropping it would be
/// the same fail-open moved to write time.
///
/// `minted` is carried forward rather than restamped: a prune subtracts from what
/// was minted, so re-dating it would launder the original mint's provenance.
#[must_use]
pub fn prune(baseline: &Baseline, scan: &Scan) -> (Baseline, Vec<Drifted>) {
    let counts = occurrences(&scan.findings);
    let (_, drifted) = apply(scan.findings.clone(), baseline, &scan.not_evaluated);
    let dropped: BTreeSet<identity::Fingerprint> = drifted
        .iter()
        .filter(|item| matches!(item.drift, Drift::Unmatched))
        .map(|item| item.entry.identity.fingerprint)
        .collect();

    let entries = baseline
        .entries
        .iter()
        .filter(|entry| !dropped.contains(&entry.identity.fingerprint))
        .map(|entry| {
            let current = counts
                .get(&entry.identity.fingerprint)
                .copied()
                .unwrap_or(entry.count);
            Entry {
                // Ratchet down, never up: raising the anchor here would baseline
                // an increase nobody minted, which is the bulk-waiver failure.
                count: entry.count.min(current),
                ..entry.clone()
            }
        })
        .collect();

    (
        Baseline {
            schema: baseline.schema,
            minted: baseline.minted.clone(),
            entries,
        },
        drifted,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A `Code`-kind finding for `rule` at `path`, whose identity is a function
    /// of `span` — so two findings with the same span are one identity with a
    /// count of two, which is what every count case below turns on.
    fn finding(rule: &str, path: &str, span: &str) -> Finding {
        let fingerprint =
            identity::code_fingerprint(rule, path, span, identity::SpanNormalization::Collapsed)
                .expect("mint a code identity");
        Finding {
            rule: rule.to_owned(),
            severity: RuleSeverity::Deny,
            path: path.to_owned(),
            line: Some(1),
            identity: StoredIdentity::new(FindingKind::Code, fingerprint),
            check: Check::Reevaluate,
            remediation: Some(Remediation::NoFix("fix it".to_owned())),
        }
    }

    fn scan(findings: Vec<Finding>) -> Scan {
        Scan {
            findings,
            not_evaluated: BTreeMap::new(),
            requested: Vec::new(),
        }
    }

    fn minted_over(findings: Vec<Finding>) -> Baseline {
        mint(
            &scan(findings),
            Some("refs/remotes/origin/main".to_owned()),
            Some("f".repeat(40)),
            "0".repeat(40),
            Date {
                year: 2026,
                month: 8,
                day: 14,
            },
        )
    }

    #[test]
    fn a_baselined_finding_is_suppressed_and_a_new_one_is_not() {
        // The whole acceptance criterion, over values.
        let old = finding("no-todo", "lib.rs", "TODO old");
        let baseline = minted_over(vec![old.clone()]);

        let fresh = finding("no-todo", "other.rs", "TODO new");
        let (kept, drifted) = apply(vec![old, fresh.clone()], &baseline, &BTreeMap::new());

        assert_eq!(kept, vec![fresh], "only the un-baselined finding survives");
        assert!(drifted.is_empty(), "nothing drifted");
    }

    #[test]
    fn a_duplicate_occurrence_re_raises_every_occurrence() {
        // Direction-aware counts: an increase is new evidence, so the identity
        // stops being suppressed rather than reporting only the delta. Reporting
        // the delta alone is the drain's emission model and belongs there; a
        // gate's answer is the whole set it is failing on.
        let one = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![one.clone()]);

        let (kept, _) = apply(vec![one.clone(), one.clone()], &baseline, &BTreeMap::new());
        assert_eq!(kept.len(), 2, "a count above the anchor re-raises");
    }

    #[test]
    fn a_reduced_count_ratchets_rather_than_re_raising() {
        // Punishing incremental fixing is wrong: fewer occurrences stays
        // suppressed, and surfaces only as something to prune.
        let one = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![one.clone(), one.clone()]);
        assert_eq!(baseline.entries[0].count, 2, "the anchor is the mint count");

        let (kept, drifted) = apply(vec![one], &baseline, &BTreeMap::new());
        assert!(kept.is_empty(), "still suppressed");
        assert_eq!(drifted.len(), 1);
        assert!(matches!(
            drifted[0].drift,
            Drift::Ratcheted {
                anchor: 2,
                current: 1
            }
        ));
    }

    #[test]
    fn an_entry_with_nothing_behind_it_is_reportable() {
        let gone = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![gone]);

        let (kept, drifted) = apply(Vec::new(), &baseline, &BTreeMap::new());
        assert!(kept.is_empty());
        assert_eq!(drifted.len(), 1);
        assert!(matches!(drifted[0].drift, Drift::Unmatched));
        let reported = drifted[0].finding().expect("a stale entry is a finding");
        assert_eq!(reported.rule, STALE_RULE);
        assert_eq!(reported.severity, RuleSeverity::Deny);
    }

    #[test]
    fn a_rule_that_did_not_run_holds_its_entries() {
        // The fail-closed half. A skipped rule reports nothing, and reading that
        // silence as "resolved" would report every entry it covers as stale —
        // and, worse, `--prune` would then delete them.
        let held = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![held]);

        let mut not_evaluated = BTreeMap::new();
        not_evaluated.insert("no-todo".to_owned(), NotObserved::RuleSkipped);

        let (kept, drifted) = apply(Vec::new(), &baseline, &not_evaluated);
        assert!(kept.is_empty());
        assert_eq!(drifted.len(), 1);
        assert!(matches!(
            drifted[0].drift,
            Drift::Held(NotObserved::RuleSkipped)
        ));
        assert!(
            !drifted[0].is_reportable(),
            "a hold contributes no verdict — nobody looked"
        );
        assert!(drifted[0].finding().is_none());
    }

    #[test]
    fn a_held_entry_survives_a_prune() {
        // The same fail-open, moved to write time: dropping an entry whose rule
        // never ran would silently un-baseline it the next time the rule does.
        let held = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![held]);
        let mut not_evaluated = BTreeMap::new();
        not_evaluated.insert("no-todo".to_owned(), NotObserved::RuleErrored);

        let (pruned, _) = prune(
            &baseline,
            &Scan {
                findings: Vec::new(),
                not_evaluated,
                requested: Vec::new(),
            },
        );
        assert_eq!(pruned.entries.len(), 1, "a hold is never pruned");
    }

    #[test]
    fn a_superseded_identity_version_holds_rather_than_unmatching() {
        // The issue's explicit requirement: a version bump must not silently
        // invalidate every adopter's baseline. Two extractor versions do not
        // produce the same function's output, so an absent match means "not
        // comparable" and never "fixed".
        let mut entry_source = finding("no-todo", "lib.rs", "TODO fix");
        entry_source.identity.version = "code:1999-01-01".to_owned();
        let baseline = minted_over(vec![entry_source]);

        let (kept, drifted) = apply(Vec::new(), &baseline, &BTreeMap::new());
        assert!(kept.is_empty());
        assert_eq!(drifted.len(), 1);
        assert!(matches!(drifted[0].drift, Drift::VersionDrift));
        assert_eq!(
            drifted[0].finding().expect("reportable").rule,
            VERSION_DRIFT_RULE,
            "it is reported, loudly, under its own rule — not discarded"
        );
    }

    #[test]
    fn a_version_drifted_entry_survives_a_prune() {
        let mut entry_source = finding("no-todo", "lib.rs", "TODO fix");
        entry_source.identity.version = "code:1999-01-01".to_owned();
        let baseline = minted_over(vec![entry_source]);

        let (pruned, _) = prune(&baseline, &scan(Vec::new()));
        assert_eq!(
            pruned.entries.len(),
            1,
            "an entry this build cannot judge is not one it may delete"
        );
    }

    #[test]
    fn prune_drops_the_unmatched_and_ratchets_the_reduced() {
        let gone = finding("no-todo", "gone.rs", "TODO gone");
        let staying = finding("no-todo", "here.rs", "TODO here");
        let baseline = minted_over(vec![gone, staying.clone(), staying.clone()]);
        assert_eq!(baseline.entries.len(), 2);

        let (pruned, _) = prune(&baseline, &scan(vec![staying.clone()]));
        assert_eq!(pruned.entries.len(), 1, "the unmatched entry is dropped");
        assert_eq!(pruned.entries[0].count, 1, "the anchor ratchets down");
        assert_eq!(
            pruned.minted, baseline.minted,
            "a prune subtracts from what was minted; re-dating it would launder \
             the original mint's provenance"
        );
    }

    #[test]
    fn a_prune_never_ratchets_an_anchor_up() {
        // The direction that would be a bulk waiver: raising the anchor would
        // baseline an increase nobody minted.
        let one = finding("no-todo", "lib.rs", "TODO fix");
        let baseline = minted_over(vec![one.clone()]);
        assert_eq!(baseline.entries[0].count, 1);

        let (pruned, _) = prune(&baseline, &scan(vec![one.clone(), one.clone(), one]));
        assert_eq!(
            pruned.entries[0].count, 1,
            "three occurrences do not raise an anchor of one"
        );
    }

    #[test]
    fn the_document_is_byte_stable_for_one_set() {
        // §6, applied to the artifact: the same findings must serialise to the
        // same bytes however the scan ordered them, or every run would rewrite
        // the file and no diff would mean anything.
        let a = finding("no-todo", "a.rs", "TODO a");
        let b = finding("no-todo", "b.rs", "TODO b");
        let forwards = minted_over(vec![a.clone(), b.clone()]);
        let backwards = minted_over(vec![b, a]);
        assert_eq!(
            serde_json::to_string(&forwards).unwrap(),
            serde_json::to_string(&backwards).unwrap()
        );
    }

    #[test]
    fn a_pointer_carries_no_span() {
        // Rule 4 at the value layer, so the property does not depend on the
        // renderer in `lib.rs` remembering it.
        let one = finding("no-todo", "lib.rs", "TODO a distinctive span");
        let baseline = minted_over(vec![one]);
        let pointer = baseline.entries[0].pointer();
        assert!(pointer.starts_with("no-todo "), "got {pointer}");
        assert!(!pointer.contains("distinctive"), "got {pointer}");
        assert!(!pointer.contains("lib.rs"), "got {pointer}");
    }

    #[test]
    fn the_minted_record_renders_its_date_without_reading_a_clock() {
        let baseline = minted_over(vec![finding("no-todo", "lib.rs", "TODO fix")]);
        assert_eq!(baseline.minted.minted_at, "2026-08-14");
        assert_eq!(baseline.schema, BASELINE_SCHEMA);
    }
}
