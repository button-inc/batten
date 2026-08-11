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

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

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
}

impl AtRisk {
    /// Whether any category fired.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.uncommitted > 0
            || self.unpushed.is_some()
            || self.no_upstream.is_some()
            || self.unlanded.is_at_risk()
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
        lines
    }
}

/// Judge the work in `repo` against `must_land_on`.
///
/// # Errors
///
/// Raises a [`crate::UsageError`] (→ exit `1`) when `repo` is not inside a
/// repository or `must_land_on` resolves to no commit — a target nobody can
/// resolve is a config error, and answering `0` over it would be a vacuous pass.
/// An I/O or `git` failure propagates as an internal error (→ exit `3`).
pub fn status(repo: &Path, must_land_on: Option<&str>) -> Result<AtRisk> {
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

    Ok(AtRisk {
        uncommitted,
        unpushed,
        no_upstream,
        unlanded,
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
}
