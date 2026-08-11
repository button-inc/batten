//! At-risk work detection (CLOUD-51) — `batten worktree status`.
//!
//! Three ways work can exist and not be safe, as one read-effect gate:
//!
//! * **uncommitted** — the working tree is not porcelain-clean.
//! * **unpushed** — the branch carries commits with no patch-equivalent on its
//!   upstream. A branch with **no upstream at all** counts too, judged against
//!   [`crate::config::Config::must_land_on`]: absence of an upstream is not
//!   safety, and reading it as safety is how a local-only branch disappears with
//!   the container it lived in.
//! * **unlanded** — no patch-equivalent on the ref work must land on.
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

/// What [`status`] found. Byte-stable for identical repository state: every
/// field is derived from refs and content, none from the clock or the
/// environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AtRisk {
    /// How many working-tree entries are not committed.
    pub uncommitted: usize,
    /// Set when the branch carries work its upstream does not — or, with no
    /// upstream, work the target does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpushed: Option<Pointer>,
    /// Set when the branch carries work with no patch-equivalent on the target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlanded: Option<Pointer>,
}

impl AtRisk {
    /// Whether any category fired.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.uncommitted > 0 || self.unpushed.is_some() || self.unlanded.is_some()
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
        if let Some(pointer) = &self.unlanded {
            lines.push(format!("unlanded: {}", pointer.render()));
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
pub fn status(repo: &Path, must_land_on: &str) -> Result<AtRisk> {
    let uncommitted = git::uncommitted(repo)?;
    let branch = git::current_branch(repo)?;
    let label = branch.clone().unwrap_or_else(|| DETACHED.to_owned());

    // Computed unconditionally: this is also what resolves `must_land_on`, and a
    // config error must surface whether or not the tree happens to be dirty.
    // A verdict that depended on an early return would not be byte-stable for
    // identical input either.
    let against_target = git::landing(repo, must_land_on, "HEAD", git::Window::DEFAULT)?;

    // The upstream half. A branch with an upstream is judged against it; a
    // branch with none — including a detached HEAD, which can track nothing —
    // falls back to the target, because "nothing to compare against" must never
    // resolve to "safe".
    let upstream = git::upstream_of_head(repo)?;
    let unpushed = match upstream {
        Some(ref upstream) => {
            let landing = git::landing(repo, upstream, "HEAD", git::Window::DEFAULT)?;
            pointer_if_outstanding(&landing, &label)
        }
        None => pointer_if_outstanding(&against_target, &label),
    };

    Ok(AtRisk {
        uncommitted,
        unpushed,
        unlanded: pointer_if_outstanding(&against_target, &label),
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

    #[test]
    fn any_is_the_disjunction_and_clean_is_silent() {
        let clean = AtRisk {
            uncommitted: 0,
            unpushed: None,
            unlanded: None,
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
                unlanded: Some(pointer(false)),
                ..clean.clone()
            },
        ] {
            assert!(at_risk.any(), "each category alone is at-risk work");
            assert_eq!(at_risk.lines().len(), 1);
        }
    }

    #[test]
    fn the_report_order_is_fixed() {
        let all = AtRisk {
            uncommitted: 3,
            unpushed: Some(pointer(false)),
            unlanded: Some(pointer(true)),
        };
        assert_eq!(
            all.lines(),
            vec![
                format!("uncommitted: 3 paths"),
                format!("unpushed: feature@{}", "a".repeat(40)),
                format!("unlanded: feature@{} {TRUNCATED}", "a".repeat(40)),
            ]
        );
    }
}
