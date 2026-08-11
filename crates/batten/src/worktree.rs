//! At-risk work detection (CLOUD-51) — `batten worktree status`.
//!
//! Three ways work can exist and not be safe, as one read-effect gate:
//!
//! * **uncommitted** — the working tree is not porcelain-clean.
//! * **unpushed** — the branch carries commits with no patch-equivalent on its
//!   upstream.
//! * **no-upstream** — the branch tracks nothing, *and* the landing target
//!   cannot account for its work. Its own category rather than a flavour of
//!   `unpushed` (§5 names the line): the two have different fixes, and a reader
//!   told only "unpushed" runs `git push` and gets an error. It is conditioned
//!   on the unlanded verdict because absence of an upstream is not safety but is
//!   not danger on its own either — a branch already landed on the trunk has
//!   nothing to lose by tracking nothing, and raising it there would flag every
//!   finished local branch forever.
//! * **unlanded** — no patch-equivalent on the ref work must land on.
//!
//! ## The target, and the third answer
//!
//! [`crate::config::Config::must_land_on`] names the target; absent, the
//! engine resolves the remote's recorded default branch, because work lands on
//! the trunk unless told otherwise. Where **no** target resolves, the verdict is
//! [`Unlanded::NotComputable`] — a third answer an `Option` cannot express,
//! since it could not tell "asked and clean" from "never asked".
//!
//! Not-computable is at-risk work and **never suppresses the facts beside it**.
//! This was a usage error until CLOUD-51's `DoD` audit, which meant a repository
//! with no target got no report at all — not the dirty tree, not the branch
//! tracking nothing. The configuration most likely to be a fresh, at-risk
//! checkout was the one the gate stayed silent about. A target the author *named
//! and got wrong* is still exit 1: that is a config error, a different mistake
//! from naming none.
//!
//! ## Merged-ness is content, never ancestry
//!
//! Every verdict here comes from [`crate::git::landing`], which decides by patch
//! identity. That is the whole point rather than an implementation detail: the
//! consumers this gate exists for land by rebase and fast-forward, so a branch
//! that landed perfectly is **never** an ancestor of the default branch, and an
//! ancestry test reports it as outstanding forever. The landed primitive also
//! covers the squash-merge shape through range-level content comparison, which
//! per-commit patch identity alone under-detects. This module re-derives none of
//! that — it selects the refs and reads the verdict.
//!
//! ## A negative says how far it looked
//!
//! [`crate::git::Verdict::NotLandedWithinWindow`] is a bounded negative, not a
//! proven absence. When the scan filled its window, the rendered line carries
//! [`TRUNCATED`] so a reader can tell "we looked and it is not there" from "we
//! stopped looking". A gate that printed a bare verdict over a truncated scan
//! would be asserting something it did not establish.
//!
//! # The pileup half (CLOUD-46)
//!
//! Everything above is about *this* checkout. [`pileup`] is about the machine:
//! how many **other** worktrees are sitting there dirty, and whether anything
//! will ever reap them. That is the highest realized harm this project has
//! recorded — an agent spawns a linked worktree, leaves uncommitted work in it,
//! and the work is neither landed nor abandoned until the disk is the
//! constraint.
//!
//! A worktree is counted when it is **dirty ∧ unreapable**, and every conjunct
//! is git's own vocabulary rather than a judgement:
//!
//! * **linked** — not the main checkout, which cannot be reclaimed and is what
//!   the three categories above already report on.
//! * **not bare** — no working tree, so nothing can be dirty in it.
//! * **not locked** — a lock is a deliberate "I am keeping this", the opposite
//!   of an unreaped pileup. Locked worktrees are excluded from the count *and*
//!   never touched by [`reclaim`].
//! * **not prunable** — git will clear those itself. This conjunct is what stops
//!   [`reclaim`] and `git worktree prune` fighting over the same set, and it is
//!   what makes "unreapable" mean something rather than decorate the count.
//! * **dirty** — [`crate::git::uncommitted`] is non-zero, which counts staged,
//!   unstaged and untracked entries alike.
//!
//! The verdict is `count >= threshold`, and the threshold is a committed
//! `batten.toml` key. **An absent threshold does not participate at all**: the
//! other three categories still report and the verb does not become exit 1.
//! That is this module's own recorded lesson from CLOUD-51's `DoD` audit —
//! where an absent `must_land_on` used to silence the entire report — restated
//! here so a second absence does not reacquire the first one's bug.
//!
//! ## Snapshot is a precondition of removal, structurally
//!
//! [`reclaim`] is the escape from the count, and its order is the whole safety
//! argument: snapshot, **verify the snapshot ref resolves**, and only then
//! remove. A worktree that yields no snapshot is left exactly where it is and
//! reported. That makes "the abandoned work is recoverable" a property of the
//! code path rather than of a test that happens to check it — and it is load
//! bearing, because `git stash create` captures nothing for a tree dirty only
//! with untracked files, which is a shape an abandoned agent worktree takes
//! routinely.
//!
//! The snapshot ref is **content-addressed** — `refs/batten/snapshot/<sha>` on
//! the snapshot commit itself, following [`crate::capture`]'s "the digest IS the
//! key". No path segment appears in it, so two reclaims of the same directory
//! can never overwrite each other's work.

use std::path::{Path, PathBuf};

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::git;

/// The marker a rendered verdict carries when the scan filled its window, so an
/// unproven absence never reads as a proven one. One spelling, here, so both
/// output channels and every test agree on it.
pub const TRUNCATED: &str = "(window truncated)";

/// The name a detached `HEAD` is reported under.
///
/// Not a branch, and named rather than left blank: a pointer with an empty
/// branch field reads as a bug, and one naming a branch that does not exist is
/// worse.
const DETACHED: &str = "(detached)";

/// One at-risk category's pointer: which branch state, and the commit that
/// identifies it. Never a diff, never file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Pointer {
    /// The branch the work is on, or [`DETACHED`].
    pub branch: String,
    /// The full SHA of the branch's head — the state this verdict is about.
    pub sha: String,
    /// Whether the scan that produced this verdict filled its window, making the
    /// negative unproven rather than proven.
    pub truncated: bool,
}

impl Pointer {
    /// The rendered pointer, with the truncation marker when the scan was
    /// bounded.
    #[must_use]
    pub fn render(&self) -> String {
        if self.truncated {
            format!("{}@{} {TRUNCATED}", self.branch, self.sha)
        } else {
            format!("{}@{}", self.branch, self.sha)
        }
    }
}

/// The unlanded verdict, which has **three** answers rather than two.
///
/// The third is the load-bearing one: when no landing target resolves, the
/// question was never asked, and an `Option` cannot tell "asked and clean" from
/// "never asked" — collapsing them is exactly the silent pass this gate exists
/// to refuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Unlanded {
    /// A target resolved and the branch's work is on it.
    Landed,
    /// A target resolved and the branch carries work it does not have.
    Outstanding {
        /// Where the outstanding work is.
        pointer: Pointer,
        /// The ref it was judged against.
        target: String,
    },
    /// No target resolved, so landedness is **unknown** — never clean.
    NotComputable {
        /// Why, as a pointer-only reason.
        reason: String,
    },
}

impl Unlanded {
    /// Whether this verdict is at-risk work.
    ///
    /// `NotComputable` counts. Work whose landedness nobody can establish is not
    /// work anyone has shown to be safe, and the Ready block is explicit:
    /// not-computable must never read as clean.
    #[must_use]
    pub const fn is_at_risk(&self) -> bool {
        matches!(
            self,
            Unlanded::Outstanding { .. } | Unlanded::NotComputable { .. }
        )
    }
}

/// The `[worktree]` table: what this repository will tolerate on its machine.
///
/// Lives with its module rather than in [`crate::config`], as `[budget]`,
/// `[judge]` and `[defects]` do — the config struct holds the field, the module
/// that reads it owns the type.
///
/// **Authority-only.** It is deliberately absent from
/// [`crate::config::OverrideConfig`], following the landed `[budget]` posture:
/// a threshold is a bar a repository sets for itself, and two thresholds in one
/// config with opposite layering rules is exactly the drift a policy engine
/// exists to refuse. `trust.rs` compares the committed bytes instead. That is
/// strictly stronger than "an override may only tighten", not a relaxation of it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorktreeConfig {
    /// How many dirty, unreapable worktrees constitute a pileup.
    ///
    /// The verdict is `count >= pileup_threshold`, so `1` means "any at all".
    /// Absent means the predicate does not participate — a threshold nobody
    /// wrote down is not a threshold of zero, the same reading `[budget]` gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pileup_threshold: Option<usize>,
}

/// One worktree in the pileup: where it is, and what it is on.
///
/// A path and a commit — a pointer, never a diff and never a byte of the work
/// (non-negotiable rule 4). The path is the whole point of the report: it is
/// what a reader needs to go look, and what [`reclaim`] acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Piled {
    /// The worktree's path, as git reports it.
    pub path: PathBuf,
    /// The commit its `HEAD` is on, when git reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// How many entries its working tree reports as uncommitted. A count, never
    /// a list of paths.
    pub uncommitted: usize,
}

/// The counted pileup predicate: how many worktrees are dirty and unreapable,
/// against the threshold this repository committed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Pileup {
    /// The declared threshold the count is judged against.
    pub threshold: usize,
    /// The offending worktrees, sorted by path so the report is byte-stable.
    pub entries: Vec<Piled>,
}

impl Pileup {
    /// Whether the count has reached the threshold.
    ///
    /// `>=`, exactly as the Ready block specifies, so a threshold of `1` means
    /// "any at all" and there is no off-by-one reading to get wrong.
    #[must_use]
    pub fn violates(&self) -> bool {
        self.entries.len() >= self.threshold
    }

    /// The report lines: the count first, then one pointer per worktree.
    ///
    /// Empty when the threshold is not reached — a pileup under the bar is not
    /// news, and a clean run prints nothing (§6).
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        if !self.violates() {
            return Vec::new();
        }
        let mut lines = vec![format!(
            "pileup: {} worktree(s) dirty and unreapable (threshold {})",
            self.entries.len(),
            self.threshold
        )];
        lines.extend(self.entries.iter().map(|entry| {
            format!(
                "pileup: {}{}",
                entry.path.display(),
                entry
                    .head
                    .as_ref()
                    .map_or_else(String::new, |head| format!("@{head}"))
            )
        }));
        lines
    }
}

/// The worktrees that are dirty **and** unreapable, judged against `threshold`.
///
/// The predicate is the module doc's conjunction, and every conjunct but
/// `dirty` comes straight off git's own porcelain vocabulary. The main checkout
/// is `git worktree list`'s first record and is skipped: it cannot be reclaimed,
/// and [`status`]'s other three categories are already about it.
///
/// # Errors
///
/// Raises a [`crate::UsageError`] (→ exit `1`) when `repo` is not inside a
/// repository. A worktree git lists but whose status cannot be read propagates
/// as an internal error (→ exit `3`) rather than being silently dropped — a
/// worktree that could not be inspected is not a worktree shown to be clean.
pub fn pileup(repo: &Path, threshold: usize) -> Result<Pileup> {
    let listed = git::worktrees(repo)?;
    let mut entries = Vec::new();
    // `skip(1)`: the main checkout is always the first record. Skipping by
    // position rather than by comparing paths avoids a second question about
    // symlinks and canonicalization that git has already answered.
    for entry in listed.into_iter().skip(1) {
        if entry.bare || entry.locked || entry.prunable {
            continue;
        }
        let uncommitted = git::uncommitted(&entry.path)?;
        if uncommitted == 0 {
            continue;
        }
        entries.push(Piled {
            path: entry.path,
            head: entry.head,
            uncommitted,
        });
    }
    // git's listing order is the worktree admin directory's; a byte-stable
    // report cannot inherit it.
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Pileup { threshold, entries })
}

/// The ref namespace every snapshot is written under.
///
/// One spelling, here, so the writer, the reporter and every test agree on it.
pub const SNAPSHOT_NAMESPACE: &str = "refs/batten/snapshot";

/// What one worktree's reclaim did, or refused to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Outcome {
    /// Snapshotted, verified, and removed.
    Reclaimed {
        /// The ref the work is recoverable from.
        snapshot: String,
    },
    /// What `--dry-run` would have done. Nothing was written.
    Previewed,
    /// **Left in place.** Nothing could be captured, so nothing was abandoned.
    ///
    /// The load-bearing outcome: `git stash create` writes no commit for a tree
    /// dirty only with untracked files, and removing on that answer would
    /// destroy the work this verb exists to preserve.
    Refused {
        /// Why, as a pointer-only reason.
        reason: String,
    },
}

/// One line of [`reclaim`]'s report, pairing a worktree with what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Reclaimed {
    /// The worktree acted on.
    pub path: PathBuf,
    /// What was done to it.
    pub outcome: Outcome,
}

impl Reclaimed {
    /// The rendered line. Pointer-only: a path, a ref, and a reason Batten wrote.
    #[must_use]
    pub fn render(&self) -> String {
        let path = self.path.display();
        match &self.outcome {
            Outcome::Reclaimed { snapshot } => format!("reclaimed: {path} -> {snapshot}"),
            Outcome::Previewed => format!("would reclaim: {path}"),
            Outcome::Refused { reason } => format!("refused: {path} ({reason})"),
        }
    }
}

/// Snapshot and abandon every worktree the pileup predicate names.
///
/// The order **is** the safety argument, and it is enforced per worktree rather
/// than per run: [`git::stash_create`], [`git::update_ref`], verify the ref
/// resolves with [`git::resolve_ref`], and only then [`git::worktree_remove`].
/// A worktree that fails any step before the last is left exactly where it is.
///
/// `dry_run` stops after selection: it writes no ref and removes nothing, so the
/// preview is incapable of the mutation it previews rather than trusted not to
/// perform it.
///
/// # Errors
///
/// Raises a [`crate::UsageError`] (→ exit `1`) when `repo` is not a repository.
/// A refusal is **not** an error: it is an [`Outcome`] in the returned report,
/// so the caller renders every line before mapping [`any_refused`] to the exit
/// code. Returning `Err` on the first refusal would discard the report that says
/// which worktrees still hold work — the one thing a reader needs.
pub fn reclaim(repo: &Path, threshold: usize, dry_run: bool) -> Result<Vec<Reclaimed>> {
    let piled = pileup(repo, threshold)?;
    let mut report = Vec::new();

    for entry in piled.entries {
        if dry_run {
            report.push(Reclaimed {
                path: entry.path,
                outcome: Outcome::Previewed,
            });
            continue;
        }

        // Snapshot first. `None` is not an error — it is git saying it captured
        // nothing, which is the one answer that must stop the removal.
        let Some(sha) = git::stash_create(&entry.path)? else {
            report.push(Reclaimed {
                path: entry.path,
                outcome: Outcome::Refused {
                    reason: "nothing could be snapshotted; `git stash create` captures no \
                             untracked-only tree"
                        .to_owned(),
                },
            });
            continue;
        };

        // Content-addressed, so two reclaims of one directory cannot collide.
        let snapshot = format!("{SNAPSHOT_NAMESPACE}/{sha}");
        git::update_ref(repo, &snapshot, &sha)?;

        // Verify rather than assume. `update_ref` succeeding is git's claim
        // about a write; this is the read that makes the claim checkable, and it
        // is what stands between a failed write and a destroyed worktree.
        if git::resolve_ref(repo, &snapshot)?.is_none() {
            report.push(Reclaimed {
                path: entry.path,
                outcome: Outcome::Refused {
                    reason: "the snapshot ref did not resolve after writing it".to_owned(),
                },
            });
            continue;
        }

        git::worktree_remove(repo, &entry.path)?;
        report.push(Reclaimed {
            path: entry.path,
            outcome: Outcome::Reclaimed { snapshot },
        });
    }

    Ok(report)
}

/// Whether any worktree in `report` was left in place holding work.
///
/// The verdict half of [`reclaim`]: a refusal is a statement about this machine
/// — there is work here nothing can make recoverable — which is a policy verdict
/// (exit `2`) rather than a failure of Batten's (§7).
#[must_use]
pub fn any_refused(report: &[Reclaimed]) -> bool {
    report
        .iter()
        .any(|entry| matches!(entry.outcome, Outcome::Refused { .. }))
}

/// What [`status`] found. Byte-stable for identical repository state: every
/// field is derived from refs and content, none from the clock or the
/// environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AtRisk {
    /// How many working-tree entries are not committed.
    pub uncommitted: usize,
    /// Set when the branch carries work its upstream does not have.
    ///
    /// Only ever about a **real upstream**. A branch with none is
    /// [`AtRisk::no_upstream`], its own fact — see that field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpushed: Option<Pointer>,
    /// Set when the branch tracks nothing.
    ///
    /// Its **own** category rather than a flavour of `unpushed` (§5 names the
    /// line `no-upstream <branch>`). The two are different problems with
    /// different fixes — `unpushed` says push, `no-upstream` says set a tracking
    /// branch first — and a reader told only "unpushed" would run `git push` and
    /// get an error rather than a fix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_upstream: Option<String>,
    /// Whether the branch's work is on the landing target, or whether that could
    /// be established at all.
    pub unlanded: Unlanded,
    /// The machine's worktree pileup, when a threshold is declared (CLOUD-46).
    ///
    /// `None` means the repository declared no `[worktree] pileup_threshold`, so
    /// the predicate did not run. That is a different claim from a count of
    /// zero, and it is deliberately **not** an error: an absent threshold must
    /// not silence the three categories beside it, which is the bug CLOUD-51's
    /// own `DoD` audit removed from this module once already.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pileup: Option<Pileup>,
}

impl AtRisk {
    /// Whether any category fired.
    #[must_use]
    pub fn any(&self) -> bool {
        self.uncommitted > 0
            || self.unpushed.is_some()
            || self.no_upstream.is_some()
            || self.unlanded.is_at_risk()
            || self.pileup.as_ref().is_some_and(Pileup::violates)
    }

    /// The report lines, in a fixed order. Counts and pointers only.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.uncommitted > 0 {
            lines.push(format!("uncommitted: {} paths", self.uncommitted));
        }
        if let Some(pointer) = &self.unpushed {
            lines.push(format!("unpushed: {}", pointer.render()));
        }
        if let Some(branch) = &self.no_upstream {
            lines.push(format!("no-upstream: {branch}"));
        }
        match &self.unlanded {
            Unlanded::Landed => {}
            Unlanded::Outstanding { pointer, target } => {
                lines.push(format!("unlanded: {} vs {target}", pointer.render()));
            }
            Unlanded::NotComputable { reason } => {
                lines.push(format!("unlanded: not-computable ({reason})"));
            }
        }
        // Last, and silent below the threshold: the three categories above are
        // about the work in front of the reader, the pileup is about the machine
        // around it.
        if let Some(pileup) = &self.pileup {
            lines.extend(pileup.lines());
        }
        lines
    }
}

/// Judge the work in `repo` against `must_land_on`, and the machine against
/// `pileup_threshold`.
///
/// # Errors
///
/// Raises a [`crate::UsageError`] (→ exit `1`) when `repo` is not inside a
/// repository or `must_land_on` resolves to no commit — a target nobody can
/// resolve is a config error, and answering `0` over it would be a vacuous pass.
/// An absent `pileup_threshold` is **not** such a case: the component simply
/// does not run. An I/O or `git` failure propagates as an internal error (→
/// exit `3`).
pub fn status(
    repo: &Path,
    must_land_on: Option<&str>,
    pileup_threshold: Option<usize>,
) -> Result<AtRisk> {
    let uncommitted = git::uncommitted(repo)?;
    let branch = git::current_branch(repo)?;
    let label = branch.clone().unwrap_or_else(|| DETACHED.to_owned());

    // The landing target: the declared key, else the remote's recorded default.
    // Absent config is not an error — work lands on the trunk unless told
    // otherwise, and charging every consumer a config line for that buys
    // nothing. What it must never become is a *pass*, which is what the third
    // arm below is for.
    let target = match must_land_on {
        Some(declared) => Some(declared.to_owned()),
        None => git::remote_default_branch(repo)?,
    };

    // Computed first, because the upstream half consults it: a branch with no
    // upstream is judged against the target instead.
    let unlanded = match target {
        Some(target) => {
            let landing = git::landing(repo, &target, "HEAD", git::Window::DEFAULT)?;
            match pointer_if_outstanding(&landing, &label) {
                Some(pointer) => Unlanded::Outstanding { pointer, target },
                None => Unlanded::Landed,
            }
        }
        // The honest third answer. Every other fact still reports — losing them
        // because *this* one could not be computed is precisely the "report
        // nothing at all" failure this gate was demoted for.
        None => Unlanded::NotComputable {
            reason: "no `must_land_on` declared and the remote has no recorded default branch"
                .to_owned(),
        },
    };

    // The upstream half, now two distinct facts. A branch that tracks nothing is
    // not "unpushed" — there is nowhere to have pushed it to — and saying so
    // sends a reader to `git push`, which fails. It is its own category.
    let upstream = git::upstream_of_head(repo)?;
    let (unpushed, no_upstream) = match upstream {
        Some(ref upstream) => {
            let landing = git::landing(repo, upstream, "HEAD", git::Window::DEFAULT)?;
            (pointer_if_outstanding(&landing, &label), None)
        }
        // No upstream, for a branch and a detached HEAD alike. Absence of an
        // upstream is not safety — but it is not *danger* either, on its own.
        // What is at risk is work that exists in only one place, so this fires
        // exactly when the target cannot account for the work: a branch whose
        // commits are already landed has nothing to lose by tracking nothing,
        // and raising it there would flag every finished local branch forever.
        // When landedness is not computable the fact fires too, because then
        // nothing can show the work is anywhere else.
        None => (None, unlanded.is_at_risk().then(|| label.clone())),
    };

    // Independent of everything above: the three categories are about the work
    // in this checkout, the pileup is about the other worktrees on the machine.
    // An absent threshold contributes nothing rather than refusing the run.
    let pileup = pileup_threshold
        .map(|threshold| pileup(repo, threshold))
        .transpose()?;

    Ok(AtRisk {
        uncommitted,
        unpushed,
        no_upstream,
        unlanded,
        pileup,
    })
}

/// A pointer when `landing` leaves work outstanding, `None` when it does not.
///
/// [`git::Landing::is_landed`] is the test rather than `Verdict::Landed` alone:
/// a branch with nothing to land — an empty commit, a change and its revert, a
/// branch the target already absorbed — is not outstanding work, and matching
/// only `Landed` would report it as at risk forever.
fn pointer_if_outstanding(landing: &git::Landing, branch: &str) -> Option<Pointer> {
    (!landing.is_landed()).then(|| Pointer {
        branch: branch.to_owned(),
        sha: landing.scanned.head_commit.clone(),
        // Only the target side bounds the answer: the head side filling its
        // window means the branch is long, not that the search was incomplete.
        truncated: landing.scanned.target_truncated,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pointer(truncated: bool) -> Pointer {
        Pointer {
            branch: "feature".to_owned(),
            sha: "a".repeat(40),
            truncated,
        }
    }

    #[test]
    fn a_bounded_negative_says_so_and_a_proven_one_does_not() {
        assert!(pointer(true).render().ends_with(TRUNCATED));
        assert!(!pointer(false).render().contains(TRUNCATED));
        assert!(pointer(false).render().starts_with("feature@aaa"));
    }

    fn outstanding(truncated: bool) -> Unlanded {
        Unlanded::Outstanding {
            pointer: pointer(truncated),
            target: "refs/remotes/origin/main".to_owned(),
        }
    }

    #[test]
    fn any_is_the_disjunction_and_clean_is_silent() {
        let clean = AtRisk {
            uncommitted: 0,
            unpushed: None,
            no_upstream: None,
            unlanded: Unlanded::Landed,
            pileup: None,
        };
        assert!(!clean.any());
        assert!(clean.lines().is_empty(), "a clean run has nothing to say");

        for at_risk in [
            AtRisk {
                uncommitted: 1,
                ..clean.clone()
            },
            AtRisk {
                unpushed: Some(pointer(false)),
                ..clean.clone()
            },
            AtRisk {
                no_upstream: Some("feature".to_owned()),
                ..clean.clone()
            },
            AtRisk {
                unlanded: outstanding(false),
                ..clean.clone()
            },
            AtRisk {
                unlanded: Unlanded::NotComputable {
                    reason: "no target".to_owned(),
                },
                ..clean.clone()
            },
        ] {
            assert!(at_risk.any(), "each category alone is at-risk work");
            assert_eq!(at_risk.lines().len(), 1);
        }
    }

    #[test]
    fn not_computable_is_at_risk_and_never_clean() {
        // The load-bearing third answer. `Option` cannot tell "asked and clean"
        // from "never asked", and collapsing them is the silent pass this gate
        // exists to refuse.
        let unknown = Unlanded::NotComputable {
            reason: "no target".to_owned(),
        };
        assert!(unknown.is_at_risk());
        assert!(!Unlanded::Landed.is_at_risk());
        assert!(outstanding(false).is_at_risk());

        let at_risk = AtRisk {
            uncommitted: 0,
            unpushed: None,
            no_upstream: None,
            unlanded: unknown,
            pileup: None,
        };
        assert!(at_risk.any(), "unknown landedness is not safety");
        assert_eq!(
            at_risk.lines(),
            vec!["unlanded: not-computable (no target)".to_owned()],
            "and it says so, rather than printing nothing"
        );
    }

    #[test]
    fn no_upstream_is_its_own_fact_not_a_flavour_of_unpushed() {
        // §5 names the line `no-upstream <branch>`. Folding it into `unpushed`
        // sends a reader to `git push`, which fails — the two problems have
        // different fixes, so they are different lines.
        let tracking_nothing = AtRisk {
            uncommitted: 0,
            unpushed: None,
            no_upstream: Some("feature".to_owned()),
            unlanded: Unlanded::Landed,
            pileup: None,
        };
        assert_eq!(
            tracking_nothing.lines(),
            vec!["no-upstream: feature".to_owned()]
        );
        assert!(
            !tracking_nothing.lines()[0].contains("unpushed"),
            "the two facts never share a line"
        );
    }

    #[test]
    fn the_report_order_is_fixed() {
        let all = AtRisk {
            uncommitted: 3,
            unpushed: Some(pointer(false)),
            no_upstream: None,
            unlanded: outstanding(true),
            pileup: None,
        };
        assert_eq!(
            all.lines(),
            vec![
                format!("uncommitted: 3 paths"),
                format!("unpushed: feature@{}", "a".repeat(40)),
                format!(
                    "unlanded: feature@{} {TRUNCATED} vs refs/remotes/origin/main",
                    "a".repeat(40)
                ),
            ]
        );
    }

    fn piled(count: usize) -> Vec<Piled> {
        (0..count)
            .map(|index| Piled {
                path: PathBuf::from(format!("/wt/{index}")),
                head: Some("b".repeat(40)),
                uncommitted: 1,
            })
            .collect()
    }

    #[test]
    fn the_pileup_predicate_is_at_or_over_the_threshold() {
        // `>=`, exactly as the Ready block specifies. The boundary is the whole
        // predicate, so it is asserted from both sides rather than once.
        let at = Pileup {
            threshold: 2,
            entries: piled(2),
        };
        assert!(at.violates(), "at the threshold is a pileup");
        assert!(
            !Pileup {
                threshold: 2,
                entries: piled(1),
            }
            .violates(),
            "under the threshold is not"
        );
        // A threshold of one means "any at all", which is the reading a consumer
        // wanting zero tolerance will write.
        assert!(
            Pileup {
                threshold: 1,
                entries: piled(1),
            }
            .violates()
        );
    }

    #[test]
    fn a_pileup_under_the_bar_says_nothing_and_one_over_it_names_every_path() {
        assert!(
            Pileup {
                threshold: 3,
                entries: piled(2),
            }
            .lines()
            .is_empty(),
            "a count nobody has to act on is noise a caller pays for every run"
        );

        let lines = Pileup {
            threshold: 2,
            entries: piled(2),
        }
        .lines();
        assert_eq!(
            lines[0],
            "pileup: 2 worktree(s) dirty and unreapable (threshold 2)"
        );
        // The count, then one pointer each — never a byte of what is in them.
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], format!("pileup: /wt/0@{}", "b".repeat(40)));
        assert_eq!(lines[2], format!("pileup: /wt/1@{}", "b".repeat(40)));
    }

    #[test]
    fn the_pileup_joins_the_disjunction_without_disturbing_it() {
        let clean = AtRisk {
            uncommitted: 0,
            unpushed: None,
            no_upstream: None,
            unlanded: Unlanded::Landed,
            pileup: None,
        };
        // An absent threshold contributes nothing — it is not a count of zero,
        // and it must not make an otherwise clean checkout report.
        assert!(!clean.any());
        assert!(clean.lines().is_empty());

        // Nor does a declared threshold the count has not reached.
        let under = AtRisk {
            pileup: Some(Pileup {
                threshold: 2,
                entries: piled(1),
            }),
            ..clean.clone()
        };
        assert!(!under.any());
        assert!(under.lines().is_empty());

        // A pileup alone is a verdict, with none of the other three categories
        // firing: it is a fact about the machine, not about this checkout.
        let over = AtRisk {
            pileup: Some(Pileup {
                threshold: 1,
                entries: piled(1),
            }),
            ..clean
        };
        assert!(over.any());
        assert_eq!(over.lines().len(), 2);
    }

    #[test]
    fn a_refusal_is_what_makes_the_run_a_verdict() {
        let reclaimed = Reclaimed {
            path: PathBuf::from("/wt/0"),
            outcome: Outcome::Reclaimed {
                snapshot: format!("{SNAPSHOT_NAMESPACE}/{}", "c".repeat(40)),
            },
        };
        let previewed = Reclaimed {
            path: PathBuf::from("/wt/1"),
            outcome: Outcome::Previewed,
        };
        let refused = Reclaimed {
            path: PathBuf::from("/wt/2"),
            outcome: Outcome::Refused {
                reason: "nothing to capture".to_owned(),
            },
        };

        assert!(!any_refused(&[reclaimed.clone(), previewed.clone()]));
        assert!(
            any_refused(&[reclaimed.clone(), refused.clone()]),
            "one worktree left holding work is enough to make the run a verdict"
        );

        // Each outcome renders as its own verb, so a reader never has to infer
        // which of the three happened from the presence of a ref.
        assert!(
            reclaimed
                .render()
                .starts_with("reclaimed: /wt/0 -> refs/batten/snapshot/")
        );
        assert_eq!(previewed.render(), "would reclaim: /wt/1");
        assert_eq!(refused.render(), "refused: /wt/2 (nothing to capture)");
    }
}
