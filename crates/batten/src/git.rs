//! Resolve the repository root through git's common-dir finder.
//!
//! The one `repo_root` primitive (CLOUD-34). Every path resolved against "the
//! repository" derives from this function; a second resolver is a bug, and the
//! single-implementation assertion in this module's tests is the gate that
//! keeps one from landing. The root is the parent of git's *common* directory
//! — never `--show-toplevel` — so a call from inside a linked worktree (agents
//! work in `.claude/worktrees/`) answers with the main repository root, where
//! per-repository config and state live, rather than the worktree's own
//! toplevel.
//!
//! Resolution is in-process (CLOUD-740). [`gix::open::Options::isolated`]
//! declines system, global and environment configuration outright, so an ambient
//! override — a hook context exporting `GIT_DIR`, say — cannot make the answer be
//! about some *other* repository, which is the mis-rooting bug class this module
//! exists to kill. The answer is a function of the (cwd-resolved) `start`
//! argument and on-disk state only.
//!
//! **That scrub is structural, where it used to be a maintained list.** Five
//! environment variables were removed by name from every child — three redirects
//! and two discovery fences — and a sixth arriving in a future git would simply
//! not have been removed. Declining the environment as a class has no such gap,
//! and there is no constant left to keep current.
//!
//! # Merged-ness (CLOUD-36)
//!
//! # Two backends, and where the line is (CLOUD-320's `git.rs` row)
//!
//! Part of this module answers in-process through `gix`, part shells out, and
//! the split is a **decision with measurements behind it** rather than a
//! migration someone abandoned half-done. `gix_is_confined_to_this_module` keeps
//! the in-process half from spreading across the crate.
//!
//! **In-process, because each had a defect a library makes unrepresentable.**
//! [`show`] read a caller's ref out of argv, so `--config-from
//! --output=<path>` made a `read`-effect verb write a file (CLOUD-718).
//! [`count_at_rev`] parsed `ls-tree` under the host's `core.quotePath`, so a
//! ratchet spanning a non-ASCII path reported clean while a test was deleted
//! (CLOUD-749) — CLOUD-328's failure class on a second axis.
//!
//! **NOTHING HERE SPAWNS `git` ANY MORE (CLOUD-740).** The last child was
//! `repo_root`'s, and `no_second_git_invoker_exists` is now the terminal
//! assertion the four slices were sequenced toward: a literal `git` spawn
//! anywhere under `src/` fails it, this file included. That gate used to exempt
//! this module, because this module held the one invoker; the exemption is what
//! went, and the claim is strictly stronger and much simpler for it.
//!
//! Three helpers went with the last of them — `query`, `query_bytes` and
//! `query_optional` — along with `command`, the two discovery-scrub constants and
//! the `queries_spawned` counter. So did a family of hazards that were being
//! *remembered* rather than made impossible: `--end-of-options` on every argv
//! carrying a caller's token, its inverse in `rev-parse`'s ref-PRINTING modes
//! where the flag is echoed as an output line rather than consumed, and
//! `core.quotePath` deciding whether a non-ASCII path arrived readable. A
//! resolver takes no flags and a path is bytes, so none of the three has anywhere
//! left to occur.
//!
//! What did NOT come from gix is worth naming, because two questions were
//! answered by refusing a dependency rather than by taking one. `uncommitted` and
//! `changed_paths` read the index, the `HEAD` tree and the vendored `ignore`
//! walker instead of gix's `status`, and `check_ignore` reads that same walker's
//! rules rather than gix's excludes: both gix features pull the
//! materialise-blobs-to-disk and external-program surface CLOUD-739 declined, and
//! buying it to delete a spawn would be buying the thing the spawn was being
//! deleted for. `working_tree_changes` carries the cost that choice has —
//! clean/smudge filters are not applied — and states why over-reporting is the
//! safe direction there.
//!
//! An earlier revision of this paragraph said *"migrating buys nothing an agent
//! can observe"* and called rewriting patch identity *"risk with no return"*. It
//! was written while all three of those rows sat cancelled, and a later session
//! read it here and restated it as fact. Both halves failed in the same
//! direction, and the migration that has now happened settles it: the risk was
//! **priced** rather than absent, by a differential gate that compares the
//! VERDICT the two implementations give over the same rebase, squash and
//! cherry-pick corpus — never the hashes, which differ by construction and whose
//! agreement would assert the migration did not happen.
//!
//! **What the price is, since a cost must be named as one (CLOUD-320).** These
//! spawns stay under a build strategy rather than a capability limit. `git2` has
//! the APIs — `Diff::patchid()` included — and is barred by `macos-link-check`
//! rule 1 because `libgit2-sys` declares a `links` key, because the Darwin legs
//! cross-build SDK-free under zig, because GitHub bills macOS runners at 10x on
//! a **private** repository. That last clause is the whole of it, and it has an
//! expiry: CLOUD-737 owns the re-decision and waits on CLOUD-585 making this
//! repository public. `provision.rs` documents its own shell-out in this shape,
//! and `every_stays_shelled_out_claim_names_its_price` is what keeps this
//! paragraph here rather than trusting the next author to remember it.
//!
//! **Nothing here is kept because gix cannot do it (CLOUD-780, 2026-08-20).**
//! Two primitives used to be, and the standing strategy decided them the other
//! way: *gix for everything gix can do; where it cannot, implement LESS rather
//! than keep a spawn path.* So they were deleted, and the pileup gate and
//! `worktree reclaim` retired with them — a deliberate capability loss, priced
//! on CLOUD-780's row rather than restated here, and the reason that row is
//! worth reading is that a partial drop would have been worse than either end
//! state: `reclaim` was the crate's only destructive path, and its safety was
//! the very interlock the drop removes.
//!
//! That leaves a property, not just a smaller module. Every spawn left in here
//! is **unported**, never *unportable*, which is what makes the backend
//! swappable at all and what CLOUD-737's re-decision needs to be a real choice.
//! `no_gix_gap_primitive_survives` is the gate that keeps it true: the
//! vocabulary of the two dropped concepts may not reappear anywhere in `src/`,
//! so reinstating one is a visible change rather than a quiet regression.
//!
//! The latency argument for migrating more was measured and does not carry it:
//! the only spawns on the mediated-call path are `key_facts`', and they cost
//! **6.7ms** on a **100ms** budget for the two `requires_key` command shapes
//! alone (`gh pr create`, `gh pr ready`) — a handful of calls per session.
//!
//! This module is also where "did this work land?" is answered, because every
//! `git` process the crate spawns is spawned here — `no_second_git_invoker`
//! below is the gate that keeps a second git-touching module, and therefore a
//! second answer to *landed*, from appearing.
//!
//! **The answer is content, never reachability.** Every reachability test —
//! asking whether a commit is an ancestor of the target, or which branches
//! contain it — keys on the commit SHA, and every one of them answers "not
//! landed" about a branch that was rebased, squashed, or cherry-picked on its
//! way to `main`. On a fast-forward trunk that is the *normal* way work lands.
//! A false *not landed* on work that did land is silently wrong rather than
//! loudly broken, and it is the failure class Batten exists to catch. So
//! [`landing`] compares **patch identity** — [`crate::patch::identity`] over each
//! change — and, for the squash case that per-commit identity cannot see, the
//! patch identity of the branch's cumulative diff.
//!
//! Reachability appears in exactly one role: *selecting* which commits to hash.
//! It never produces a verdict. Every [`Verdict::Landed`] is backed by an
//! [`Evidence`] naming the target commit whose patch identity matched, and the
//! type offers no way to spell a landed verdict while holding no evidence.
//! `policy/ancestry-decides-nothing.rego` is the source-level gate — a
//! registered Rego module over `Fact::Invocations`, which replaced this
//! module's own `no_ancestry_decides_merged_ness` scan (CLOUD-756).
//!
//! Two consequences worth stating, because neither is obvious:
//!
//! * **A negative answer is bounded, and says so.** The target is searched over
//!   a [`Window`] of commits, so the honest negative is
//!   [`Verdict::NotLandedWithinWindow`] with [`Scan::target_truncated`] — never
//!   a bare "no". The type refuses to assert an absence it did not prove,
//!   because *that* absence is the dangerous direction.
//! * **`git cherry` is deliberately not used**, despite being git's own
//!   patch-id equivalence tool. Its upstream limit defaults to the merge base,
//!   so a branch that was cherry-picked to the target and *then* synced with it
//!   has its own landing fall outside the search — and `git cherry` reports the
//!   work as unlanded. It also reports only `+`/`-`, which cannot populate
//!   [`Evidence`]. The technique is adopted; the command is not.
//!

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Serialize;

use crate::error::UsageError;

/// The identity of a change's *content*, independent of the commit that carries
/// it.
///
/// Two commits with the same `PatchId` make the same change to the same paths,
/// whatever their SHA, author, message, date, or parents — which is precisely
/// what makes a rebased, amended, or cherry-picked commit recognisable after it
/// lands under a new SHA.
///
/// **Computed in-process, and the normalisation is ours** (CLOUD-739).
/// [`crate::patch`] is the authority on what that normalisation is and why each
/// part of it was chosen; it is deliberately NOT restated here, because two
/// copies of a definition drift and only one of them can be the one the code
/// implements. The short version a reader needs at this type: line numbers are
/// excluded so a rebase still matches, and whitespace is significant, which
/// diverges from `git patch-id` on purpose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PatchId(String);

impl PatchId {
    /// The one constructor, so a slip in rendering cannot manufacture an
    /// equality (CLOUD-739 §7c).
    ///
    /// Exactly 64 lowercase hex digits: the identity is a SHA-256 over this
    /// crate's own canonical form, so its width is fixed by that and no longer
    /// by the repository's hash. It used to accept 40 as well, because it was
    /// parsing whatever `git patch-id` printed and that followed the repository
    /// — SHA-1 or SHA-256. Nothing prints it now, so the narrower rule is the
    /// honest one, and a 40-hex value reaching here is a defect rather than a
    /// SHA-1 repository.
    fn parse(text: &str) -> Result<Self> {
        let ok = text.len() == 64
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            bail!("a patch identity must be 64 lowercase hex digits, not {text:?}")
        }
    }

    /// The hash in git's own lowercase hex form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PatchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How far back on the target [`landing`] looks for a matching change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Window(NonZeroUsize);

impl Window {
    /// The default search depth: 1000 commits of the target.
    ///
    /// Chosen as "further back than any review cycle, short of a full-history
    /// scan". The two directions are not symmetric — a window that is too small
    /// yields the dangerous verdict, a window that is too large costs one
    /// longer `git log` — so the default is generous and a caller may widen it.
    /// A landing older than the window is reported as
    /// [`Verdict::NotLandedWithinWindow`], never as a proven absence.
    pub const DEFAULT: Self = Self(match NonZeroUsize::new(1000) {
        Some(commits) => commits,
        // Unreachable — 1000 is not zero — but the lints forbid a panicking
        // path, and a const `match` keeps this total.
        None => NonZeroUsize::MIN,
    });

    /// A window of `commits` target commits. Non-zero by type: a zero window
    /// would search nothing and report every branch unlanded.
    #[must_use]
    pub const fn of(commits: NonZeroUsize) -> Self {
        Self(commits)
    }

    /// The depth, as git's `--max-count` takes it.
    #[must_use]
    pub const fn commits(self) -> usize {
        self.0.get()
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What made one change count as landed. Every variant that means "landed"
/// names the target commit that carries it — there is no way to record a
/// landing without the proof of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Evidence {
    /// A commit on the target makes the identical change.
    PatchId {
        /// The target commit carrying it.
        target_commit: String,
        /// The identity both sides share.
        patch_id: PatchId,
    },
    /// A commit on the target makes the branch's *cumulative* change — the
    /// squash-merge shape, where no individual commit survived the merge and
    /// so none of them matches on its own.
    Squash {
        /// The squashed commit on the target.
        target_commit: String,
        /// The identity of the branch's whole diff.
        patch_id: PatchId,
    },
    /// The commit changes nothing, so there is nothing of it to land.
    NoContent,
}

impl Evidence {
    /// The target commit this evidence points at, or `None` for
    /// [`Evidence::NoContent`], which points at nothing.
    #[must_use]
    pub fn target_commit(&self) -> Option<&str> {
        match self {
            Evidence::PatchId { target_commit, .. } | Evidence::Squash { target_commit, .. } => {
                Some(target_commit)
            }
            Evidence::NoContent => None,
        }
    }
}

/// The landing verdict for a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    /// Every commit that changes anything is accounted for on the target.
    Landed,
    /// Some commits landed and some did not.
    PartiallyLanded,
    /// The branch's net change against the target is empty, so there is no
    /// unlanded work — an empty commit, a change and its revert, or a branch
    /// the target has already absorbed entirely.
    NothingToLand,
    /// No match was found **within the window searched**. Named for what it
    /// proves: this is an unproven absence, not an absence. A consumer
    /// rendering it must say so, and [`Scan::target_truncated`] says whether
    /// older history went unexamined.
    NotLandedWithinWindow,
}

/// What [`landing`] actually looked at, so a negative verdict can be read for
/// how much it proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Scan {
    /// The resolved full SHA of the target.
    pub target_commit: String,
    /// The resolved full SHA of the head.
    pub head_commit: String,
    /// How many target commits were hashed.
    pub target_commits_scanned: usize,
    /// The window filled: older target history was **not** examined, so a
    /// negative verdict is unproven rather than false.
    pub target_truncated: bool,
    /// The head-side window filled: the branch has more commits than were
    /// examined.
    pub head_truncated: bool,
    /// The window this scan used.
    pub window: Window,
}

/// One head-side commit and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CommitLanding {
    /// Full SHA on the head side.
    pub commit: String,
    /// `None` for a commit whose diff is empty: `git patch-id` emits nothing
    /// for an empty patch, and an absent identity must never be matched against
    /// another absent identity.
    pub patch_id: Option<PatchId>,
    /// The proof this commit's change is on the target, or `None`.
    pub evidence: Option<Evidence>,
}

/// The result of [`landing`]: pointer-only — SHAs and identities, never file
/// content — and byte-stable for identical repository state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Landing {
    /// The verdict, derived from the evidence below and nothing else.
    pub verdict: Verdict,
    /// Head-side commits, oldest first — the fixed reporting order.
    pub commits: Vec<CommitLanding>,
    /// The patch identity of the whole branch; `None` when its cumulative diff
    /// is empty.
    pub cumulative: Option<PatchId>,
    /// Branch-level proof: `Some` when the branch's whole change is on the
    /// target as a *single* commit.
    ///
    /// That is the squash-merge shape, and it is also trivially true of a
    /// one-commit branch that landed intact — so this is "the whole change is
    /// one commit over there", not "someone ran a squash merge". A consumer
    /// that wants to know whether the individual commits survived should read
    /// [`CommitLanding::evidence`], which answers exactly that.
    pub cumulative_evidence: Option<Evidence>,
    /// What was examined to reach the verdict.
    pub scanned: Scan,
}

impl Landing {
    /// Whether the branch has no unlanded content — [`Verdict::Landed`] or
    /// [`Verdict::NothingToLand`]. A branch with nothing to land is not
    /// unlanded work, and a consumer that only matched `Landed` would report a
    /// fast-forwarded branch as outstanding.
    #[must_use]
    pub const fn is_landed(&self) -> bool {
        matches!(self.verdict, Verdict::Landed | Verdict::NothingToLand)
    }

    /// The head-side commits with no proof on the target — the pointer a
    /// consumer surfaces for a negative verdict.
    #[must_use]
    pub fn unlanded(&self) -> Vec<&str> {
        self.commits
            .iter()
            .filter(|commit| commit.evidence.is_none())
            .map(|commit| commit.commit.as_str())
            .collect()
    }
}

/// Strip Windows' verbatim prefix, so a canonicalised path is comparable with
/// every other path in the crate.
///
/// **This is a regression this migration introduced, caught by CI on Windows and
/// nowhere else.** The shelled-out predecessor answered from
/// `git rev-parse --show-toplevel`, which is a plain path. `Path::canonicalize`
/// is not: on Windows it returns the VERBATIM spelling, `\\?\D:\a\batten`, and
/// nothing else in the crate produces one. `receipt::judgeable` then asks whether
/// a `std::path::absolute` path starts with the root, the two never share a
/// prefix, and the write reads as OUTSIDE the repository — so the claim gate
/// allowed every write on Windows while denying correctly everywhere else.
/// Measured as exactly one red case out of 2288, which is what an answer that is
/// wrong only under a prefix looks like.
///
/// A verbatim UNC path (`\\?\UNC\server\share`) is LEFT ALONE: its plain
/// spelling is not equivalent — verbatim paths skip normalisation — so rewriting
/// one would trade a comparison bug for a resolution bug. On every other platform
/// this is the identity.
fn plain(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    let Some(rest) = text.strip_prefix(r"\\?\") else {
        return path;
    };
    if rest.starts_with("UNC\\") {
        return path;
    }
    PathBuf::from(rest)
}

/// Resolve the root of the repository containing `start`: the working-tree
/// directory whose `.git` is the repository's *common* directory.
///
/// From a nested subdirectory this is the enclosing repository's root; from a
/// linked worktree it is the **main** repository root (the common dir is
/// shared), which is what keeps per-repository config and state stable across
/// worktrees. A relative `start` resolves against the process working
/// directory; the returned path is always absolute, as git reports it.
///
/// # Errors
///
/// Returns a [`UsageError`] (exit `1` at the consumer boundary) when `start`
/// is not a directory, is not inside a git repository, or is inside a layout
/// with no derivable working-tree root (a bare repository, a submodule
/// interior, a separate git dir). Returns an internal error when git itself
/// cannot run or produces undecodable output.
pub fn repo_root(start: &Path) -> Result<PathBuf> {
    // An explicit guard rather than letting git report it: `git -C ""` leaves
    // the cwd unchanged, so an empty or missing path would silently answer for
    // the wrong directory instead of failing.
    if !start.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            start.display()
        )));
    }
    // UNFENCED, and this is the one caller that is. `repo_root`'s contract is
    // that its answer is a function of `start` and the filesystem — every path
    // the crate resolves against "the repository" derives from it, so a ceiling
    // in the ambient environment must not move the root out from under a caller
    // that never asked about it. Every OTHER read goes through `open`, which
    // honours the ceiling, because a caller that fenced discovery on purpose is
    // relying on being refused rather than answered about whatever repository
    // sits further up the tree.
    let repo = open_upwards(start, Vec::new()).map_err(|_| {
        UsageError::raise(format!(
            "{} is not inside a git repository",
            start.display()
        ))
    })?;
    // A bare repository has no working tree to root, and that refusal must stay
    // LOUD rather than deriving a directory that is not a checkout.
    if repo.worktree().is_none() {
        return Err(UsageError::raise(format!(
            "{} is inside a bare repository, which has no working tree to root",
            start.display()
        )));
    }
    // The COMMON dir, never the worktree's own: a linked worktree shares it, and
    // rooting on the per-worktree directory is what would make two siblings
    // resolve to two stores instead of one (CLOUD-164).
    //
    // The `DISCOVERY_FENCES` scrub that used to happen here and only here is gone
    // with the process. `open`'s isolated handle declines the environment
    // outright, so an ambient `GIT_CEILING_DIRECTORIES` cannot shape this answer
    // and no constant has to be maintained for that to stay true.
    let common_dir = repo.common_dir();
    let common_dir = plain(
        common_dir
            .canonicalize()
            .unwrap_or_else(|_| common_dir.to_path_buf()),
    );
    // The parent is the root only when the common dir is a `<root>/.git`. A
    // submodule interior or a separate git dir would "derive" a directory that
    // is not a working tree at all — refuse loudly instead of mis-rooting.
    if common_dir.file_name() != Some(OsStr::new(".git")) {
        return Err(UsageError::raise(format!(
            "cannot derive a repository root from {}: not a `<root>/.git` layout",
            common_dir.display()
        )));
    }
    match common_dir.parent() {
        Some(root) => Ok(root.to_path_buf()),
        // Unreachable given the guard above (an absolute `…/.git` always has a
        // parent), but kept total: the lints forbid panicking on any path.
        None => Err(UsageError::raise(format!(
            "cannot derive a repository root from {}",
            common_dir.display()
        ))),
    }
}

/// The repository's common git directory — shared by the main checkout and
/// every linked worktree, which is what makes worktree siblings resolve to one
/// store rather than one each (CLOUD-164).
///
/// Recorded by [`crate::store`] as *metadata*. It is deliberately not a key: a
/// repository that moves on disk changes this string while remaining the same
/// repository, and a store keyed on it would orphan itself on a `mv`.
///
/// # Errors
///
/// Returns a [`UsageError`] when `dir` is not a directory or not inside a git
/// repository.
pub fn common_dir(dir: &Path) -> Result<String> {
    if !dir.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let repo = open(dir)?;
    // Absolute, as `--path-format=absolute` asked for: the value is recorded as
    // store metadata, and a relative one would be read against whatever
    // directory the reader happens to be in.
    let common = repo.common_dir();
    let absolute = plain(
        common
            .canonicalize()
            .unwrap_or_else(|_| common.to_path_buf()),
    );
    Ok(absolute.to_string_lossy().into_owned())
}

/// Every configured remote as `(name, url)` pairs, sorted by name.
///
/// `git remote -v` is deliberately not used: it prints each remote twice (fetch
/// and push) in a format that has to be re-parsed. `config --get-regexp` names
/// the fetch URL exactly once per remote.
///
/// A repository with no remotes is the *normal* empty case, not a failure —
/// CLOUD-164's fixture (c) is a no-remote repository — so a non-zero exit from
/// `config --get-regexp` (which is how git reports "no matching keys") yields an
/// empty list rather than an error.
///
/// # Errors
///
/// Returns an error only when `git` itself cannot run or emits non-UTF-8.
pub fn remotes(dir: &Path) -> Result<Vec<(String, String)>> {
    // No remotes configured is the normal empty case, and so is a directory this
    // cannot open — both were an empty list under the shell-out, where a
    // non-zero exit could not be told apart from one.
    let Ok(repo) = open(dir) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<(String, String)> = Vec::new();
    for name in repo.remote_names() {
        let name = name.to_string();
        // The FETCH url, exactly once per remote — which is what
        // `config --get-regexp remote.*.url` named and what `git remote -v`
        // would have printed twice in a format needing re-parsing.
        let Ok(remote) = repo.find_remote(name.as_str()) else {
            continue;
        };
        let Some(url) = remote.url(gix::remote::Direction::Fetch) else {
            continue;
        };
        let url = url.to_bstring().to_string();
        if !name.is_empty() && !url.is_empty() {
            found.push((name, url));
        }
    }
    // `read`-order from git config is file order; a recorded value that a gate
    // compares must not depend on it.
    found.sort();
    found.dedup();
    Ok(found)
}

/// The repository's root commits (`rev-list --max-parents=0 --all`), sorted.
///
/// The strongest continuity evidence a store has: a repository keeps its root
/// commits across a move, a rename, and a remote change, and two unrelated
/// repositories sharing one is not a case that arises from ordinary work. This
/// is what lets a moved no-remote checkout be *adopted* rather than orphaned.
///
/// **Selecting commits, not deciding reachability.** `rev-list` ranges are
/// explicitly legal under this module's ancestry gate; what is forbidden is
/// deciding merged-ness from a reachability answer, which this does not do.
///
/// An empty repository has no commits, so an empty list is a normal answer.
///
/// # Errors
///
/// Returns an error only when `git` itself cannot run or emits non-UTF-8.
pub fn root_commits(dir: &Path) -> Result<Vec<String>> {
    // An unborn HEAD with no refs at all: no commits to list, not a failure.
    let Ok(repo) = open(dir) else {
        return Ok(Vec::new());
    };
    let Ok(references) = repo.references() else {
        return Ok(Vec::new());
    };
    let Ok(all) = references.all() else {
        return Ok(Vec::new());
    };
    // `--all`: every ref is a tip, and the walk keeps only the commits with no
    // parents. Selecting commits, never deciding reachability — the distinction
    // this module's ancestry gate draws.
    let tips: Vec<gix::ObjectId> = all
        .filter_map(std::result::Result::ok)
        .filter_map(|reference| reference.into_fully_peeled_id().ok())
        .map(gix::Id::detach)
        .collect();
    let mut found: Vec<String> = Vec::new();
    if let Ok(walk) = repo.rev_walk(tips).all() {
        for info in walk.flatten() {
            if info.parent_ids().count() == 0 {
                found.push(info.id().to_hex().to_string());
            }
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// Open the repository containing `dir`, isolated from the ambient environment.
///
/// The one in-process entry point, so every gix caller in this module gets the
/// same isolation rather than each remembering to ask for it (CLOUD-718).
///
/// **The scrub is structural here, not a maintained list.**
/// [`gix::open::Options::isolated`] declines system, global and environment
/// configuration outright, and discovery runs with default options rather than
/// the environment's — so an ambient `GIT_DIR` or `GIT_CEILING_DIRECTORIES`
/// cannot redirect the answer, and no constant has to be kept current for that
/// to stay true. Do **not** reach for `discover_with_environment_overrides`: it
/// re-admits exactly what the scrub exists to refuse.
///
/// Discovery walks *upwards* from `dir`, deliberately: callers pass a relative
/// `"."` (`receipt.rs`), and a linked worktree must resolve its own `HEAD`
/// rather than the main checkout's.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `dir` is not inside a repository
/// this binary can open.
fn open(dir: &Path) -> Result<gix::Repository> {
    open_upwards(dir, ceiling_dirs())
}

/// `GIT_CEILING_DIRECTORIES`, as discovery ceilings.
///
/// **The one environment variable this module still reads, and the asymmetry is
/// deliberate.** [`gix::open::Options::isolated`] declines the environment as a
/// class, which is right for everything that could REDIRECT an answer: a
/// `GIT_DIR` or `GIT_WORK_TREE` names a different repository, and honouring one
/// is the mis-rooting bug this module exists to kill. A ceiling cannot redirect.
/// It can only stop the walk earlier, so its worst outcome is a refusal — the
/// fail-safe direction — and a caller that fenced discovery on purpose is
/// entitled to have the fence respected rather than walked straight past.
///
/// This is not `gix::discover`'s `_with_environment_overrides`, which re-admits
/// the redirecting variables too. Only the ceiling is read, and only here.
fn ceiling_dirs() -> Vec<PathBuf> {
    std::env::var_os("GIT_CEILING_DIRECTORIES")
        .map(|raw| std::env::split_paths(&raw).collect())
        .unwrap_or_default()
}

/// [`open`], with the discovery ceilings supplied rather than read.
fn open_upwards(dir: &Path, ceilings: Vec<PathBuf>) -> Result<gix::Repository> {
    let discovery = gix::discover::upwards::Options {
        ceiling_dirs: ceilings,
        ..Default::default()
    };
    // ABSOLUTE before discovery, because callers pass a relative `"."`
    // (`receipt.rs` does, for every read) and a ceiling is an absolute path. An
    // upward walk over relative components can never match one, so a fence a
    // caller set would be walked straight past — silently, and only for the
    // callers that pass a relative path. `git -C .` resolved the working
    // directory before comparing; this is that step, made explicit.
    let start = dir.canonicalize();
    let start = start.as_deref().unwrap_or(dir);
    gix::discover_opts(start, discovery, gix::open::Options::isolated())
        .map_err(|_| UsageError::raise(format!("{} is not a git repository", dir.display())))
}

/// Open the repository containing `dir` with git's **resolved** configuration —
/// system, global and repository-local together.
///
/// The one deliberate exception to [`open`], and the distinction it rests on is
/// worth stating because collapsing the two would be a silent behaviour change.
/// [`open`]'s isolation exists to stop the ambient environment deciding **which
/// repository** an answer is about: a stray `GIT_DIR` redirecting discovery is
/// the mis-rooting bug class this module exists to kill. It is not a claim that
/// git's configuration is untrustworthy to READ.
///
/// Two callers ask a question whose subject IS the resolved configuration —
/// [`config_value`] and [`stamped_identity`], both of which feed the attribution
/// decision. "Is there an accountable identity here at all" is answered by an
/// identity inherited from a wider scope just as much as by a local one, so
/// reading these through an isolated handle would report `None` for a developer
/// whose `user.email` is set globally, and the attribution gate would refuse a
/// correctly-configured machine.
///
/// DISCOVERY still runs isolated: the path is found by [`open`] and only then
/// re-opened for its configuration, so the ambient environment picks neither the
/// repository nor the answer — only the config scopes git itself would consult
/// contribute.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `dir` is not inside a repository
/// this binary can open.
fn open_configured(dir: &Path) -> Result<gix::Repository> {
    let isolated = open(dir)?;
    gix::open(isolated.git_dir())
        .map_err(|_| UsageError::raise(format!("{} is not a git repository", dir.display())))
}

/// Read a tracked file's contents at a git ref, without touching the working
/// tree.
///
/// This is the trust boundary behind `--config-from` (CLOUD-31): policy is read
/// from a ref a pull request cannot edit, so a working-tree change that relaxes
/// the rules cannot lower the bar it is judged by. It reads and never writes,
/// which is what keeps the calling verb `read`.
///
/// **In-process, and that is the security property** (CLOUD-718). This used to
/// spell `git show {reference}:{path}`, interpolating a caller's `reference`
/// into argv. `--config-from` is `global: true`, so that string reaches every
/// verb from a flag or `BATTEN_CONFIG_FROM`, and a value of
/// `--output=<path>` made `git show` exit `0`, print nothing, and **write a
/// file** — a `read`-effect verb, in the derived read-only allowlist a mediated
/// agent may call unprompted, induced to write a caller-chosen path. Carrying
/// `--end-of-options` would have made that *refused*; there being no argv makes
/// it *unrepresentable*, which is the right strength for a boundary whose whole
/// job is to be un-influenceable by the change under review.
///
/// Two more defects closed as consequences rather than as separate care. A
/// `reference:directory` printed a tree listing that `[epoch] tracked` would
/// have hashed as file content; a blob lookup cannot return a tree. And "the
/// ref does not resolve" and "the path is absent at that ref" were one message,
/// where they are two answers here — CLOUD-720 needs to tell them apart to
/// build last-known-good, and `the_two_unreadable_states_are_distinct` is what
/// makes that a fact it inherits rather than a promise. This function still
/// renders both as one `Result`; [`read_at`] is the same read with the two
/// states returned as values, and is what a caller that must branch on them
/// calls.
///
/// The scrub is structural too. Where the shell-out removed five environment
/// variables by name, [`gix::open::Options::isolated`] declines system, global
/// and environment config outright, and discovery runs with default options
/// rather than the environment's — so an ambient `GIT_DIR` or
/// `GIT_CEILING_DIRECTORIES` cannot redirect the answer, and no list has to be
/// maintained for that to stay true. Discovery still walks *upwards* from
/// `dir`, because callers pass a relative `"."` (`receipt.rs`) and because a
/// linked worktree must resolve its own `HEAD`, not the main checkout's.
///
/// `path` is repo-relative and `/`-separated, as git addresses blobs.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the ref does not resolve, the
/// path is absent at that ref, the object there is not a file, or its bytes are
/// not UTF-8 — all bad input naming config this binary cannot honour, never a
/// policy verdict. The non-UTF-8 case is exit `1` rather than the internal `3`
/// it used to be: §7 routes unreadable *config* to `1`, and `epoch.rs` already
/// cites this function as the precedent for that.
pub fn show(dir: &Path, reference: &str, path: &str) -> Result<String> {
    match read_at(dir, reference, path)? {
        BaseBlob::Found { text, .. } => Ok(text),
        BaseBlob::RefUnreachable { reference } => Err(UsageError::raise(format!(
            "cannot resolve {reference} in this repository"
        ))),
        BaseBlob::AbsentAtRef { reference, path } => Err(UsageError::raise(format!(
            "{path} is absent at {reference}"
        ))),
    }
}

/// What reading a tracked file at a ref found: the bytes, or which of the two
/// unreadable states it hit.
///
/// [`show`] already told those two states apart, but only inside two different
/// `UsageError` strings — so the distinction existed for a human reading stderr
/// and was destroyed for a caller. CLOUD-720 needs to branch on it: an
/// unreachable *reference* is the one state house style §4 lets degrade to a
/// pinned last-known-good, and a ref that resolves while declaring no config
/// must stay strict, or a branch pointing `--config-from` at a config-less ref
/// picks its own policy.
///
/// Only those two are variants. "The object there is not a blob" and "its bytes
/// are not UTF-8" stay hard errors on [`read_at`]: neither is unreachable and
/// neither is absent — both are an authority this binary found and cannot
/// honour, and degrading on either would serve a pin in place of a config that
/// is *present and broken*.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BaseBlob {
    /// The ref resolved and carried a readable file, at `commit`.
    ///
    /// The commit is the evidence half: a pin minted from these bytes records
    /// which commit it came from, so a served pin can say what it is serving.
    Found { text: String, commit: String },
    /// The revspec does not resolve in this repository — a mistyped ref, or one
    /// this checkout never fetched. The only state that may degrade.
    RefUnreachable { reference: String },
    /// The ref resolves and the path is not there — a branch from before the
    /// config landed. Never degrades, in any configuration.
    AbsentAtRef { reference: String, path: String },
}

/// [`show`], with the two unreadable states returned rather than rendered.
///
/// Every boundary property [`show`] documents is this function's: no argv, so
/// no `reference` can be read as an option; [`gix::open::Options::isolated`],
/// so an ambient `GIT_DIR` cannot redirect the answer; a blob lookup, so a
/// `reference:directory` cannot return a tree listing.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `dir` is not a directory this
/// binary can open as a repository, when the ref resolves to something that is
/// not a tree, when the object at `path` is not a file, or when its bytes are
/// not UTF-8. The two states a caller can act on come back as [`BaseBlob`]
/// variants instead.
pub fn read_at(dir: &Path, reference: &str, path: &str) -> Result<BaseBlob> {
    if !dir.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let repository = open(dir)?;

    // State one: the revspec does not resolve here. gix's error is
    // version-dependent prose in the same way git's stderr was, so it never
    // reaches the caller — the STATE does.
    let Ok(resolved) = repository.rev_parse_single(reference) else {
        return Ok(BaseBlob::RefUnreachable {
            reference: reference.to_owned(),
        });
    };
    let commit = resolved.detach().to_string();
    let tree = resolved
        .object()
        .map_err(|_| UsageError::raise(format!("cannot read the object {reference} names")))?
        .peel_to_tree()
        .map_err(|_| UsageError::raise(format!("cannot resolve {reference} to a tree")))?;

    // State two: the ref is good and the path is not there. A caller can act on
    // the difference — one is a mistyped or unfetched ref, the other a branch
    // from before the config landed.
    let Some(entry) = tree
        .lookup_entry_by_path(path)
        .map_err(|_| UsageError::raise(format!("cannot read {path} at {reference}")))?
    else {
        return Ok(BaseBlob::AbsentAtRef {
            reference: reference.to_owned(),
            path: path.to_owned(),
        });
    };

    // A tree at that path is refused rather than rendered. `config::CONFIG_FILE`
    // cannot reach this, but `[epoch] tracked` can, and the epoch would have
    // hashed a directory listing as though it were the file's content.
    if !entry.mode().is_blob() {
        return Err(UsageError::raise(format!(
            "{path} at {reference} is not a file"
        )));
    }

    let object = entry
        .object()
        .map_err(|_| UsageError::raise(format!("cannot read {path} at {reference}")))?;
    let text = String::from_utf8(object.data.clone())
        .map_err(|_| UsageError::raise(format!("{path} at {reference} is not valid UTF-8")))?;
    Ok(BaseBlob::Found { text, commit })
}

/// The files directly inside `directory` at `reference`, as repo-relative paths.
///
/// [`show`]'s sibling, and it exists for the same reason (CLOUD-833): under
/// `--config-from <ref>` a bundle's MEMBERSHIP has to come from the ref as
/// surely as a module's bytes do. Listing the working tree instead would let an
/// agent add a `.rego` file and change what the BASE policy decides — the
/// influence that flag exists to exclude, arriving through the folder rather
/// than through a file.
///
/// Non-recursive: it returns the blobs one level down, matching what a bundle
/// is. Sub-trees are skipped rather than descended, so "which files am I
/// enabling" stays a question a reader answers from the row.
///
/// It shares [`show`]'s whole boundary posture — no argv, so no path can be
/// read as an option; [`gix::open::Options::isolated`], so an ambient `GIT_DIR`
/// cannot redirect the answer.
///
/// `directory` is repo-relative and `/`-separated, as git addresses trees.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the ref does not resolve, the
/// path is absent at that ref, or the object there is not a directory — bad
/// input naming config this binary cannot honour, never a policy verdict.
pub fn list_tree(dir: &Path, reference: &str, directory: &str) -> Result<Vec<String>> {
    if !dir.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let repository = open(dir)?;
    let resolved = repository
        .rev_parse_single(reference)
        .map_err(|_| UsageError::raise(format!("cannot resolve {reference} in this repository")))?;
    let tree = resolved
        .object()
        .map_err(|_| UsageError::raise(format!("cannot read the object {reference} names")))?
        .peel_to_tree()
        .map_err(|_| UsageError::raise(format!("cannot resolve {reference} to a tree")))?;

    let entry = tree
        .lookup_entry_by_path(directory)
        .map_err(|_| UsageError::raise(format!("cannot read {directory} at {reference}")))?
        .ok_or_else(|| UsageError::raise(format!("{directory} is absent at {reference}")))?;
    if !entry.mode().is_tree() {
        return Err(UsageError::raise(format!(
            "{directory} at {reference} is not a directory"
        )));
    }
    let inner = entry
        .object()
        .map_err(|_| UsageError::raise(format!("cannot read {directory} at {reference}")))?
        .peel_to_tree()
        .map_err(|_| UsageError::raise(format!("cannot read {directory} at {reference}")))?;

    let prefix = directory.trim_end_matches('/');
    let mut paths: Vec<String> = inner
        .iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.mode().is_blob())
        .map(|entry| format!("{prefix}/{}", entry.filename()))
        .collect();
    // Sorted for §6's byte-stability: git's own tree order is stable, but the
    // caller composes these into one engine and a diagnostic naming them must
    // not depend on which reader produced the list.
    paths.sort();
    Ok(paths)
}

/// How many entries the working tree reports as not committed.
///
/// A **count, not a list**, and deliberately so: the report this feeds says
/// `uncommitted: N paths`, and a primitive that cannot return a path cannot leak
/// one (non-negotiable rule 4). It also sidesteps `--porcelain`'s path quoting
/// entirely, which is the only part of that format that is not trivially
/// parseable.
///
/// Counts staged, unstaged, and untracked entries alike — every one of them is
/// work that a reclaimed container would take with it.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository.
pub fn uncommitted(dir: &Path) -> Result<usize> {
    // A COUNT, and the list it counts never leaves this module (non-negotiable
    // rule 4). Sharing `working_tree_changes` with `changed_paths` is what keeps
    // the two from disagreeing about what "changed" means — under the shell-out
    // one counted `status --porcelain` lines and the other unioned `diff HEAD`
    // with `ls-files --others`, which are nearly but not exactly the same set.
    Ok(working_tree_changes(dir, Changes::All)?.len())
}

/// The git blob id `git hash-object` would give this text (CLOUD-1024).
///
/// **Here rather than at the caller, because `gix` lives here.**
/// `gix_is_confined_to_this_module` is the gate, and it is right: a second
/// module reaching for the git implementation is a second place that knows
/// git's object format, and this crate keeps that knowledge in one file. The
/// caller wants an answer about a blob, not a hash function, so what crosses the
/// boundary is the id.
///
/// **The equality with `git hash-object` is the contract.** A gate one layer
/// over recomputes this digest by piping the same text to that command, so any
/// other value — a bare SHA-1 of the content, a SHA-256, a hand-written framing
/// — is a field that exists and never matches. Asking `gix` is what makes the
/// framing bytes, the object kind and the hash git's rather than ours.
///
/// **Takes no directory and opens no repository**, which is why it is not
/// spelled as a method on one: an object id is a pure function of the bytes, so
/// this reads no config, resolves no worktree and is safe on the mediated path.
///
/// `None` where the id cannot be computed, which a caller records as
/// could-not-look rather than as a digest of nothing.
#[must_use]
pub fn blob_id(text: &str) -> Option<String> {
    gix::objs::compute_hash(
        gix::hash::Kind::Sha1,
        gix::object::Kind::Blob,
        text.as_bytes(),
    )
    .ok()
    .map(|id| id.to_string())
}

/// The commit `name` resolves to, or `None` when the ref does not exist.
///
/// Built on [`query_optional`], for which a missing ref is an *answer* rather
/// than a failure — and a caller owes the absent case its own reading:
/// [`crate::baseline`]'s minting path asks for the landing target's commit, and
/// `None` there is "no target resolved", never "clean".
///
/// It DOES carry `--end-of-options`, and the comment in the body says why —
/// `name` is caller-influenced, so this is not the ref-PRINTING exception this
/// module's doc records against `upstream_of_head`.
///
/// # Errors
///
/// Failing to run `git` at all is an internal error (exit `3`).
pub fn resolve_ref(dir: &Path, name: &str) -> Result<Option<String>> {
    // `--end-of-options`, because `name` is caller-influenced: `baseline`'s
    // caller passes `must_land_on` straight from config, which a branch can edit
    // when no `--config-from` is in play. `head_commit` three functions above
    // carries the token with the same `--verify`; this did not, and the omission
    // was an oversight rather than the documented ref-PRINTING exception, which
    // applies to `--abbrev-ref`/`--symbolic-full-name` and not here.
    //
    // Measured before adding it, so the severity is stated honestly rather than
    // implied: this was **latent, not live**. An option-shaped `name` IS parsed
    // as an option — `--local-env-vars` printed env var names — but `--verify`
    // exits non-zero for anything that is not a single rev, and
    // `query_optional` reads non-zero as `None`, so the caller already got the
    // safe answer. `rev-parse` also has no file-writing option, so there is no
    // `show`-shaped write here (CLOUD-718). The token makes that hold by
    // construction instead of by two other functions' behaviour.
    let repo = open(dir)?;
    // `--end-of-options` has nothing to be carried on: `name` is an argument to
    // a resolver, never a token on a command line, so an option-shaped value is
    // a ref that does not resolve rather than a flag. That is the difference
    // between refusing an injection and it being unrepresentable (CLOUD-718).
    Ok(repo
        .rev_parse_single(name)
        .ok()
        .map(|id| id.detach().to_hex().to_string()))
}

/// The repo-relative paths the working tree has changed against `HEAD`.
///
/// The changed-scope set the advisory drain filters code-anchored findings
/// against (CLOUD-79). **A list where [`uncommitted`] is deliberately a count**,
/// and the difference is not an inconsistency: that report says `uncommitted: N
/// paths`, so a primitive that could not return one could not leak one. A
/// scope filter has to name the files it is scoping to, and a repo-relative path
/// is a pointer — the shape rule 4 permits — never the content at it.
///
/// **NUL-delimited, never `--porcelain`.** The quoting in that format is the one
/// part of it that is not trivially parseable, which is exactly what
/// [`uncommitted`] sidesteps by counting lines. `-z` removes the problem instead
/// of parsing around it: a pathname containing a quote, a newline or a non-UTF-8
/// byte arrives verbatim between NULs. A path that is not UTF-8 is **dropped**
/// rather than lossily converted — a mangled path would silently fail to match a
/// stored finding's path and scope-filter it away, which is a false negative
/// wearing a filter's clothes.
///
/// Tracked modifications and untracked files both count: an agent that has just
/// written a new file has changed that scope as surely as one that edited an
/// existing one. Staged and unstaged alike, since `diff HEAD` spans both.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository, or
/// is one with no commits.
pub fn changed_paths(dir: &Path) -> Result<BTreeSet<String>> {
    working_tree_changes(dir, Changes::All)
}

/// Every repo-relative path the INDEX holds differently from `HEAD` — the staged
/// half alone, without the unstaged or untracked ones (CLOUD-519).
///
/// `batten check --staged` is the caller: a pre-commit hook judges what is about
/// to be committed, and an unstaged edit beside it is explicitly not that. So
/// this is a narrower question than [`changed_paths`] rather than a cheaper
/// answer to the same one, which is why it is its own name.
///
/// It is the same walk, taking only its first comparison. Splitting it any other
/// way would give the repository a second opinion on what "staged" means, and
/// `working_tree_changes`'s header records why that walk is hand-rolled at all.
///
/// # Errors
///
/// As [`changed_paths`]: a [`UsageError`] (exit `1`) when `dir` is not inside a
/// repository, or is one whose index or `HEAD` cannot be read.
pub fn staged_paths(dir: &Path) -> Result<BTreeSet<String>> {
    working_tree_changes(dir, Changes::Staged)
}

/// Which comparisons [`working_tree_changes`] folds in.
///
/// An enum rather than a `bool`, so a call site says which question it is asking
/// instead of encoding it as a bare `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Changes {
    /// Staged, unstaged and untracked — "is there uncommitted work".
    All,
    /// The index against `HEAD` alone — "what would this commit contain".
    Staged,
}

/// Every repo-relative path that differs from `HEAD`, staged, unstaged or
/// untracked.
///
/// The one walk behind [`uncommitted`]'s count and [`changed_paths`]' list.
///
/// # Why this is hand-rolled rather than gix's `status`
///
/// gix can answer this, and the feature that does is REFUSED for the reason
/// CLOUD-739 refused `gix-diff/blob`: `status` pulls `blob-diff`, and `dirwalk`
/// pulls `attributes`, which pulls `command`. That is the external-diff-driver,
/// clean/smudge-filter and materialise-blobs-to-disk surface the previous slice
/// declined — a runtime subshell and unmediated filesystem access, arriving
/// through a dependency rather than through this crate's own source. Taking it
/// to delete a spawn would be buying the thing the spawn was being deleted for.
///
/// So the three sources are read from what is already vendored: the INDEX (gix's
/// `index` feature, already on via `revision`), the HEAD tree, and the `ignore`
/// crate's walker for untracked files — the same walker
/// [`crate::rules::tree_files`] uses, so untracked-and-ignored means here what it
/// means there.
///
/// **The cost, stated rather than absorbed: clean/smudge filters are not
/// applied.** A repository that rewrites content on checkout — CRLF conversion,
/// an LFS pointer — can therefore show a file as modified whose committed content
/// is unchanged. That is the OVER-reporting direction, and it is the safe one
/// here: both callers ask "is there uncommitted work", where a false positive is
/// noise and a false negative is work reported as safe to lose. `stop` and
/// `baseline` both read this, and a container reclaim takes what they said was
/// not there.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository, or
/// is one whose index or `HEAD` cannot be read.
fn working_tree_changes(dir: &Path, want: Changes) -> Result<BTreeSet<String>> {
    let repo = open(dir)?;
    let root = repo_root(dir)?;
    let refusal = || {
        UsageError::raise(
            "cannot read the changed paths; this is not a git repository, or it has no commits"
                .to_owned(),
        )
    };
    let index = repo.index().map_err(|_| refusal())?;
    let mut changed = BTreeSet::new();

    // Staged: the index against `HEAD`'s tree. An unborn HEAD has no tree, so
    // every index entry is staged — which is what it is.
    let head_tree = repo
        .head_commit()
        .ok()
        .and_then(|commit| commit.tree().ok());
    let mut tracked = BTreeSet::new();
    for entry in index.entries() {
        // A path is bytes; one that is not UTF-8 is dropped rather than lossily
        // converted, as the `-z` reading this replaces already did.
        let Ok(path) = std::str::from_utf8(entry.path(&index)) else {
            continue;
        };
        tracked.insert(path.to_owned());
        let committed = head_tree
            .as_ref()
            .and_then(|tree| tree.clone().peel_to_entry_by_path(path).ok().flatten())
            .map(|found| found.object_id());
        if committed != Some(entry.id) {
            changed.insert(path.to_owned());
            continue;
        }
        // The staged question is answered by the comparison above and nothing
        // below it: an unstaged edit and an untracked file are both work that
        // would NOT be in the commit.
        if want == Changes::Staged {
            continue;
        }
        // Unstaged: the index entry against the file on disk. Compared by CONTENT
        // hash rather than by stat, because a stat match is a cache hint and this
        // is being asked whether work exists.
        let absolute = root.join(path);
        let Ok(metadata) = std::fs::symlink_metadata(&absolute) else {
            // Tracked and gone is a deletion, which is a change.
            changed.insert(path.to_owned());
            continue;
        };
        let content = if metadata.is_symlink() {
            std::fs::read_link(&absolute)
                .map(|target| target.to_string_lossy().into_owned().into_bytes())
        } else {
            std::fs::read(&absolute)
        };
        let Ok(content) = content else {
            changed.insert(path.to_owned());
            continue;
        };
        let hashed = gix::objs::compute_hash(repo.object_hash(), gix::object::Kind::Blob, &content)
            .map_err(|_| refusal())?;
        if hashed != entry.id {
            changed.insert(path.to_owned());
        }
    }

    // Untracked: the crate's one tree walker, so "ignored" means here exactly
    // what it means to every rule that reads the tree.
    if want == Changes::All {
        for path in crate::rules::tree_files(&root)? {
            if !tracked.contains(&path) {
                changed.insert(path);
            }
        }
    }
    Ok(changed)
}

/// Every path the checkout TRACKS, as repo-relative `/`-separated strings
/// (CLOUD-925).
///
/// **Tracked, not [`changed_paths`]' wider set**, and the difference is the point:
/// this answers "is this a file the repository carries", which is the membership
/// test a reading-manifest ceiling counts against. A token naming a path the tree
/// does not track is naming nothing an agent can be made to read, so a URL, a
/// branch name and a typo drop out by construction rather than through an
/// allowlist somebody has to tune.
///
/// It is also the enumeration the shell guard this replaces used, and matching it
/// is not incidental: CLOUD-312's differential obligation compares the two
/// answers case by case, so a different membership test would diverge on exactly
/// the paths a migration is supposed to preserve.
///
/// `-z` with the same non-UTF-8 handling [`changed_paths`] documents at length: a
/// path is bytes, a name carrying a quote or a newline arrives verbatim between
/// NULs, and one that is not UTF-8 is **dropped** rather than lossily converted —
/// a mangled path would fail to match a tracked entry and silently lower a count,
/// which is the permissive direction.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository. Every
/// caller reads that as could-not-look and allows, so a tree this cannot
/// enumerate is never refused on the strength of a count nobody took.
pub fn tracked_paths(dir: &Path) -> Result<BTreeSet<String>> {
    let repo = open(dir)?;
    // The INDEX is what `ls-files` printed, so this is the same membership test
    // rather than a similar one — which CLOUD-312's differential obligation
    // needs, since a different test would diverge on exactly the paths a
    // migration is supposed to preserve.
    let index = repo.index().map_err(|_| {
        UsageError::raise("cannot read the tracked paths; this is not a git repository".to_owned())
    })?;
    Ok(index
        .entries()
        .iter()
        // A path is bytes. One that is not UTF-8 is DROPPED rather than lossily
        // converted, exactly as the `-z` reading was: a mangled path fails to
        // match a tracked entry and silently lowers a count, and dropping it is
        // the same permissive direction stated out loud.
        .filter_map(|entry| std::str::from_utf8(entry.path(&index)).ok())
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

/// The branch `HEAD` is on, or `None` on a detached `HEAD`.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository.
pub fn current_branch(dir: &Path) -> Result<Option<String>> {
    let repo = open(dir)?;
    let head = repo.head().map_err(|_| {
        UsageError::raise(
            "cannot resolve HEAD; this is not a git repository, or it has no commits".to_owned(),
        )
    })?;
    // A detached HEAD has no referent name at all, where `--abbrev-ref` spelled
    // it as the literal `HEAD` and every caller had to know not to read that as
    // a branch. `None` is the same answer with the trap removed.
    Ok(head.referent_name().map(|name| name.shorten().to_string()))
}

/// Whether this checkout's history is truncated (CLOUD-446).
///
/// The one question that separates "the work names no key" from "I cannot see
/// the work". A shallow clone holds a suffix of history — often a single
/// grafted commit — so a predicate over *the commits on this branch* reads a
/// partial view, and answering "none of them" from it is inferring absence from
/// what was not fetched.
///
/// Measured, not hypothesised: `ci.yml` fetches its ratchet base with `git fetch
/// --depth=1 origin main`, and `actions/checkout` takes the PR head at the same
/// depth, so a `git log origin/main..HEAD` there sees a synthetic merge commit
/// and none of the branch's own. A key check that trusted that view refused
/// every PR in CI.
///
/// # Errors
///
/// Raises when `git` cannot be run at all, or its output is not UTF-8. A
/// non-zero exit is not expected here — `--is-shallow-repository` answers for
/// any repository — so it is read as the conservative `true`: unable to
/// establish that history is complete is not the same as establishing that it
/// is.
pub fn is_shallow(dir: &Path) -> Result<bool> {
    // A directory this cannot open is read as the conservative `true`, matching
    // what an unreadable answer meant before: unable to establish that history
    // is complete is not the same as establishing that it is.
    let Ok(repo) = open(dir) else {
        return Ok(true);
    };
    Ok(repo.is_shallow())
}

/// The commit messages on `base..HEAD`, as one blob (CLOUD-446).
///
/// One string rather than a list because every caller asks the same question of
/// it — does an expression match anywhere in the work's own commits — and a
/// split would invite a caller to *report* an element. Nothing here is printable
/// output: a commit message is content, and the refusal this feeds names the
/// missing key, never the messages it searched (non-negotiable rule 4).
///
/// Built on [`query_optional`], whose absent case is exactly the one this owes a
/// reading: a `base` git cannot resolve is **could not look**, and the mediated
/// call it gates allows. That direction is deliberate and is the same fail-open
/// posture every retiring guard has — a hook that refuses because it is outside
/// a checkout is a hook that has become the reason work cannot proceed.
///
/// # Errors
///
/// Raises when `git` cannot be run at all, or its output is not UTF-8 — only the
/// verdict is optional, never the mechanism.
pub fn log_messages(dir: &Path, base: &str) -> Result<Option<String>> {
    // A `base` this cannot resolve is COULD NOT LOOK, and the mediated call it
    // gates allows — the same fail-open posture the shell-out's non-zero exit
    // carried, now spelled as a value rather than as an exit status.
    let Ok(repo) = open(dir) else {
        return Ok(None);
    };
    let (Ok(base_id), Ok(head_id)) = (repo.rev_parse_single(base), repo.head_id()) else {
        return Ok(None);
    };
    let Ok(walk) = repo
        .rev_walk([head_id.detach()])
        .with_hidden([base_id.detach()])
        .all()
    else {
        return Ok(None);
    };
    let mut messages = String::new();
    for info in walk.flatten() {
        let Ok(commit) = repo.find_commit(info.id) else {
            continue;
        };
        // `%B` is the raw body, and `git log --format=%B` separated records with
        // a newline. Every caller asks whether an expression matches ANYWHERE in
        // the work's own commits, so the join only has to keep two messages from
        // running into one another.
        messages.push_str(&commit.message_raw_sloppy().to_string());
        messages.push('\n');
    }
    Ok(Some(messages))
}

/// One commit's attribution record: who wrote it, who committed it, what it
/// trails, and what it says.
///
/// Four fields as a **struct, not a `splitn`**. The call site that used to do
/// this took each part with `unwrap_or_default()`, so a record that arrived
/// short answered with empty strings — an *answer*, on the module that decides
/// commit attribution, where the honest response is a refusal (CLOUD-742).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitRecord {
    /// `%an <%ae>` — the author identity.
    pub author: String,
    /// `%cn <%ce>` — the committer identity.
    pub committer: String,
    /// `%(trailers:only,unfold)`, as whole `Key: value` lines with blanks
    /// dropped.
    pub trailers: Vec<String>,
    /// `%B` — the raw message body.
    pub body: String,
}

/// Read one commit's attribution record.
///
/// One `git show -s` with the four placeholders joined by [`RECORD_SEPARATOR`],
/// and the split that undoes that join lives here, beside the format string it
/// reverses — a caller holding one half of that pair is a caller that can get
/// it wrong.
///
/// **Exact arity, and that is the behavioural change this carries.** A record
/// that does not split into four fields is refused. Previously each part came
/// off the iterator with `unwrap_or_default()`, so a body containing U+001E
/// produced a shorter split and the missing fields became empty strings — which
/// the attribution decision then judged as though they were what git said. The
/// three surfaces the attribution decision record governs are decided from this
/// value; a blank field is not a safe default there, it is a wrong answer.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the commit cannot be read, or when
/// its record does not carry all four fields — "could not look", never a
/// verdict built out of blanks.
pub fn commit_record(dir: &Path, commit: &str) -> Result<CommitRecord> {
    let repo = open(dir)?;
    let refusal = || UsageError::raise("could not read a commit in the range".to_owned());
    let object = repo
        .rev_parse_single(commit)
        .map_err(|_| refusal())?
        .object()
        .map_err(|_| refusal())?;
    let object = object.peel_to_commit().map_err(|_| refusal())?;
    let author = object.author().map_err(|_| refusal())?;
    let committer = object.committer().map_err(|_| refusal())?;
    // The four fields are read as FIELDS now, so there is no separator to join
    // them with and no record that can arrive short. `RECORD_SEPARATOR`,
    // `record_from` and its arity refusal all existed because one `git show` had
    // to carry four values through one stream, and a body containing U+001E
    // mis-split it (CLOUD-742). Reading the commit object removes that channel
    // rather than defending it, so the three go with it — a defect class with no
    // channel left has nothing for a gate to discriminate (CLOUD-418), which is
    // the same reasoning this row's own §7 used to strike its clauses over
    // deleted functions. `trailer_lines` STAYS: `attribution.rs` reads a pending
    // message's trailers through it, and one implementation is what keeps a
    // committed record and a pending one agreeing on what a trailer line is.
    let message = object.message().map_err(|_| refusal())?;
    let trailers = message
        .body()
        .map(|body| {
            body.trailers()
                .map(|trailer| format!("{}: {}", trailer.token, trailer.value))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(CommitRecord {
        author: format!("{} <{}>", author.name, author.email),
        committer: format!("{} <{}>", committer.name, committer.email),
        trailers,
        body: object.message_raw_sloppy().to_string(),
    })
}

/// Every non-merge commit in `base..head`, as full SHAs.
///
/// The enumeration half of an attribution run: [`commit_record`] is what reads
/// each one. Split from it because the range resolving and a commit reading are
/// different failures with different refusals.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the range does not resolve — "could
/// not look", never a clean pass over commits nobody read.
pub fn commits_in_range(dir: &Path, base: &str, head: &str) -> Result<Vec<String>> {
    let repo = open(dir)?;
    let refused = || UsageError::raise("could not resolve the commit range".to_owned());
    let (base_id, head_id) = (
        repo.rev_parse_single(base).map_err(|_| refused())?,
        repo.rev_parse_single(head).map_err(|_| refused())?,
    );
    let walk = repo
        .rev_walk([head_id.detach()])
        .with_hidden([base_id.detach()])
        .all()
        .map_err(|_| refused())?;
    let mut out = Vec::new();
    for step in walk {
        let info = step.map_err(|_| refused())?;
        // `--no-merges`: a merge has no patch of its own, and the commits it
        // brings in are separately enumerated here.
        if info.parent_ids().count() > 1 {
            continue;
        }
        out.push(info.id().to_hex().to_string());
    }
    Ok(out)
}

/// The trailers of a message that is on disk and not yet committed.
///
/// `git interpret-trailers --parse` applies git's own rules for where the
/// trailer block starts, so nothing here re-derives them and this cannot
/// disagree with what [`commit_record`] reports once the commit exists.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the message cannot be parsed.
pub fn message_trailers(dir: &Path, message: &Path) -> Result<Vec<String>> {
    let _ = dir;
    let body = std::fs::read(message).map_err(|_| {
        UsageError::raise("could not parse the pending message's trailers".to_owned())
    })?;
    // The SAME parser `commit_record` reads a committed message with, which is
    // what the `interpret-trailers` shell-out bought and what would otherwise be
    // re-derived here: where a trailer block starts is git's rule, and a second
    // implementation of it could disagree with what `commit_record` reports once
    // the commit exists.
    let message = gix::objs::commit::MessageRef::from_bytes(&body);
    Ok(message.body().map_or_else(Vec::new, |body| {
        body.trailers()
            .map(|trailer| format!("{}: {}", trailer.token, trailer.value))
            .collect()
    }))
}

/// One config value as git *resolves* it, across every scope.
///
/// Resolved rather than `--local`, because the question a caller asks of this
/// is "is there an identity here at all" — and an accountable one inherited
/// from a wider scope is an answer, not an absence.
///
/// # Errors
///
/// Failing to run `git` at all is an internal error (exit `3`); an unset key is
/// `None`, which is an answer.
pub fn config_value(dir: &Path, key: &str) -> Result<Option<String>> {
    let repo = open_configured(dir)?;
    // RESOLVED across every scope, which is why this reads through
    // `open_configured` rather than `open` — see that function on why the
    // isolation is about which repository, never about whether config is
    // readable.
    Ok(repo
        .config_snapshot()
        .string(key)
        .map(|value| value.to_string()))
}

/// Set one **repo-local** config value.
///
/// Repo-local and never `--global`: the wider scope covers a developer's own
/// unrelated repositories, and nothing in this crate has the standing to change
/// those. The narrowing is spelled here, once, rather than at each caller.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the write fails.
pub fn set_config_local(dir: &Path, key: &str, value: &str) -> Result<()> {
    let repo = open(dir)?;
    let refusal = || UsageError::raise("could not write the repo-local config value".to_owned());
    // `user.name`, or `remote.origin.url` — section, an optional subsection, and
    // the key. The shell-out handed git one dotted string and let it do this
    // split; doing it here is what a typed API costs, and it is the same split.
    let (section, rest) = key.split_once('.').ok_or_else(refusal)?;
    let (subsection, name) = match rest.rsplit_once('.') {
        Some((subsection, name)) => (Some(subsection), name),
        None => (None, rest),
    };
    // THE REPOSITORY'S OWN CONFIG FILE, opened directly rather than through
    // `config_snapshot_mut`. That snapshot spans every scope, and committing it
    // did not REPLACE an existing local value — measured by
    // `a_repo_local_config_write_replaces_an_existing_value`, which read back the
    // value the write was supposed to overwrite. A write primitive that reports
    // success while leaving the old value in place is the worst possible shape
    // for this caller: `attribution identity` uses it to displace a denied
    // committer, so a silent no-op leaves every later commit misattributed while
    // the repair claims to have run.
    //
    // Repo-local is now structural rather than a flag: this is the local file, so
    // there is no `--global` for a caller to reach and no wider scope reachable
    // by omission.
    let path = repo.git_dir().join("config");
    let mut file =
        gix::config::File::from_path_no_includes(path.clone(), gix::config::Source::Local)
            .map_err(|_| refusal())?;
    file.set_raw_value_by(section, subsection.map(gix::bstr::BStr::new), name, value)
        .map_err(|_| refusal())?;
    let mut out = std::fs::File::create(&path).map_err(|_| refusal())?;
    file.write_to(&mut out).map_err(|_| refusal())?;
    Ok(())
}

/// The identity git is about to stamp, without the timestamp it appends.
///
/// `git var` prints `Name <email> <epoch> <tz>`; the time is not identity, and
/// the trim that removes it belongs beside the invocation that knows the format
/// rather than at a caller that has to remember it.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when git cannot resolve an identity.
pub fn stamped_identity(dir: &Path, var: &str) -> Result<String> {
    let repo = open_configured(dir)?;
    let refusal = || UsageError::raise("could not resolve the identity git would stamp".to_owned());
    // `git var GIT_AUTHOR_IDENT` printed `Name <email> <epoch> <tz>` and the
    // caller trimmed the time back off. The identity is read as an identity now,
    // so there is no timestamp to append and none to remove — the trim that used
    // to live beside the invocation has nothing left to do.
    let identity = match var {
        "GIT_AUTHOR_IDENT" => repo.author(),
        "GIT_COMMITTER_IDENT" => repo.committer(),
        _ => return Err(refusal()),
    }
    .ok_or_else(refusal)?
    .map_err(|_| refusal())?;
    Ok(format!("{} <{}>", identity.name, identity.email))
}

/// The absolute git directory for `dir` — **per-worktree**, not the common one.
///
/// The distinction is the whole reason both this and [`common_dir`] exist: a
/// linked worktree has its own `HEAD`, its own index and its own
/// `batten-receipts/`, so a receipt keyed through the common dir would answer
/// about a different checkout than the one being judged.
///
/// A [`PathBuf`], not the text `rev-parse` prints: every caller of this
/// immediately builds a path out of it, and each one of them was trimming the
/// string again first (CLOUD-742).
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository —
/// "could not look", never an answer about a repository that is not there.
pub fn git_dir(dir: &Path) -> Result<PathBuf> {
    let repo = open(dir)?;
    // PER-WORKTREE, which is the whole reason this and `common_dir` both exist:
    // `git_dir()` is the linked worktree's own directory where `common_dir()` is
    // the shared one, and a receipt keyed through the wrong one answers about a
    // different checkout than the one being judged.
    let git_dir = repo.git_dir();
    Ok(plain(
        git_dir
            .canonicalize()
            .unwrap_or_else(|_| git_dir.to_path_buf()),
    ))
}

/// How many commits `range` selects.
///
/// **A count, and nothing about reachability.** CLOUD-36 forbids deciding
/// merged-ness by ancestry — a rebased landing is invisible to it — and leaves
/// range forms legal precisely because selecting which commits to count is a
/// different act from concluding one commit contains another. This counts; it
/// concludes nothing.
///
/// The `usize` is the point: `rev-list --count` prints a number, and a caller
/// handed the text has to parse it, which is a place to get it wrong for no
/// benefit (CLOUD-742).
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the range does not resolve, or when
/// the output is not a number — the second cannot happen with `--count` and is
/// therefore refused rather than defaulted, since it would mean git answered a
/// different question.
pub fn commit_count(dir: &Path, range: &str) -> Result<usize> {
    let repo = open(dir)?;
    let refused = || UsageError::raise("the commit range cannot be counted".to_owned());
    let (exclude, include) = match range.split_once("..") {
        Some((from, to)) => (Some(from), to),
        None => (None, range),
    };
    let tip = repo.rev_parse_single(include).map_err(|_| refused())?;
    let mut walk = repo.rev_walk([tip.detach()]);
    if let Some(from) = exclude {
        walk = walk.with_hidden([repo.rev_parse_single(from).map_err(|_| refused())?.detach()]);
    }
    // A COUNT, and nothing about reachability: selecting which commits to count
    // is a different act from concluding one commit contains another (CLOUD-36).
    // The parse that could answer a different question is gone with the text.
    let mut counted = 0;
    for step in walk.all().map_err(|_| refused())? {
        step.map_err(|_| refused())?;
        counted += 1;
    }
    Ok(counted)
}

/// One commit's subject line, keyed to the commit that carries it.
///
/// A pair rather than a `String` the caller re-splits: the subject is the part
/// after the first space of a `%H %s` line, and a caller that has to know that
/// is a caller that can get it wrong (CLOUD-742).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitSubject {
    /// The commit's full SHA.
    pub commit: String,
    /// Its subject line — git's `%s`, which cannot contain a newline.
    pub subject: String,
}

/// Every non-merge commit's subject in `base..head`.
///
/// One `git log` rather than a `rev-list` followed by a `show` per commit: the
/// subject is available from the same walk that enumerates the range, so the
/// second pass buys nothing.
///
/// `%H %s`, split on the FIRST space: the SHA is fixed-width hex and a subject
/// cannot contain a newline, so one line per commit parses unambiguously. That
/// reading lives here and not at the call site — the format string and the
/// parse that undoes it are one decision, and `commit.rs` held half of it.
///
/// `--end-of-options`, because `base` and `head` are caller-influenced in the
/// same way [`resolve_ref`]'s `name` is.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when the range does not resolve — "could
/// not look", never a clean pass over commits nobody read. A line git emits
/// that carries no space is refused rather than read as a subject-less commit:
/// `%H %s` cannot produce one, so seeing one means the walk answered something
/// other than the question asked.
pub fn subjects_in_range(dir: &Path, base: &str, head: &str) -> Result<Vec<CommitSubject>> {
    let repo = open(dir)?;
    let refused = || UsageError::raise("could not resolve the commit range".to_owned());
    let (base_id, head_id) = (
        repo.rev_parse_single(base).map_err(|_| refused())?,
        repo.rev_parse_single(head).map_err(|_| refused())?,
    );
    let walk = repo
        .rev_walk([head_id.detach()])
        .with_hidden([base_id.detach()])
        .all()
        .map_err(|_| refused())?;
    let mut out = Vec::new();
    for step in walk {
        let info = step.map_err(|_| refused())?;
        if info.parent_ids().count() > 1 {
            continue;
        }
        let commit = repo.find_commit(info.id).map_err(|_| refused())?;
        // The `%H %s` line and the split that undid it are both gone: the
        // subject is a field of the message, so there is no first-space rule to
        // hold half of and no line-without-a-space to refuse. `summary()` is
        // git's own `%s` — the message up to the first blank line, folded.
        out.push(CommitSubject {
            commit: info.id().to_hex().to_string(),
            subject: commit
                .message()
                .map_err(|_| refused())?
                .summary()
                .to_string(),
        });
    }
    Ok(out)
}

/// Whether this repository ignores `path` — the scratch-work question
/// (CLOUD-444).
///
/// # One implementation, and which one (CLOUD-740 §7(e))
///
/// This crate must not carry two answers to "is this path ignored", and it was
/// about to: `ignore` is already vendored and owns the question for
/// [`crate::rules::tree_files`]'s walk, `git check-ignore` owned it here, and
/// gix's own exclude machinery would have been a third. **`ignore` owns it**,
/// for two reasons that both point the same way. It is the implementation whose
/// answers a consumer already depends on, since the walk decides which files
/// every `forbid`, `budget` and marker rule even sees. And gix's excludes arrive
/// only through the `excludes` feature, which pulls `gix-worktree` — part of the
/// same materialise-blobs-to-disk surface CLOUD-739 declined, so taking it here
/// would buy a third answer with the dependency the previous slice refused.
///
/// **The posture is the walk's, deliberately, and it is NARROWER than
/// `check-ignore` was.** `tree_files` sets `git_global(false)` because a
/// developer's global excludes are a property of their machine and a gate whose
/// file set varies per workstation is not one gate. `git check-ignore` consulted
/// `core.excludesFile` and so could answer differently on two machines for the
/// same commit. Matching the walk is what makes the two agree; the cost is that a
/// path ignored ONLY by a developer's global excludes now reads as not ignored,
/// which is the judgeable direction and the same one the walk already took.
///
/// The layering is the repository's own, applied in git's precedence order:
/// `.git/info/exclude` first, then each `.gitignore` from the root down to the
/// path's own directory, so a nearer file overrides a farther one.
///
/// # Errors
///
/// Raises when the repository cannot be opened or its ignore files cannot be
/// read — only the VERDICT is optional, never the mechanism. `false` here means
/// "not ignored", which makes the path judgeable, so an unreadable ignore
/// surface must never quietly produce one.
pub fn check_ignore(dir: &Path, path: &str) -> Result<bool> {
    let repo = open(dir)?;
    let root = repo_root(dir)?;
    let refusal = || UsageError::raise("cannot read the repository's ignore rules".to_owned());
    let mut builder = ignore::gitignore::GitignoreBuilder::new(&root);
    // `.git/info/exclude` first: git's lowest-precedence repository source, and
    // `ignore`'s builder takes later additions as higher precedence.
    let excludes = repo.git_dir().join("info").join("exclude");
    if excludes.is_file() {
        builder.add(&excludes);
    }
    // Then root-down, so a `.gitignore` nearer the path overrides a farther one.
    let mut walked = root.clone();
    builder.add(walked.join(".gitignore"));
    for component in Path::new(path).parent().into_iter().flatten() {
        walked.push(component);
        builder.add(walked.join(".gitignore"));
    }
    let matcher = builder.build().map_err(|_| refusal())?;
    // A path is judged as a FILE unless the caller's own path says otherwise; the
    // matcher needs to know, because a `foo/` rule matches a directory only.
    let is_dir = root.join(path).is_dir();
    Ok(matcher
        .matched_path_or_any_parents(path, is_dir)
        .is_ignore())
}

/// The commit `HEAD` points at, as a full SHA.
///
/// Recorded beside every observation so a stored count says *which tree* it
/// counted, rather than being a number with no anchor.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository or
/// has no commits.
pub fn head_commit(dir: &Path) -> Result<String> {
    let repo = open(dir)?;
    let refusal = || {
        UsageError::raise(
            "cannot resolve HEAD; this is not a git repository, or it has no commits".to_owned(),
        )
    };
    Ok(repo
        .head_id()
        .map_err(|_| refusal())?
        .detach()
        .to_hex()
        .to_string())
}

/// Every local branch and remote-tracking ref, as full ref names.
///
/// The liveness set instance GC is computed against. **Ref existence, never
/// reachability**: these consumers land by rebase and fast-forward, so a landed
/// branch's commits are ancestors of nothing and a reachability test would
/// collect live work. Listing what exists asks a question that has an honest
/// answer.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository.
pub fn refs(dir: &Path) -> Result<Vec<String>> {
    let repo = open(dir)?;
    let refusal = || UsageError::raise("cannot list refs; this is not a git repository".to_owned());
    let references = repo.references().map_err(|_| refusal())?;
    // REF EXISTENCE, never reachability: these consumers land by rebase and
    // fast-forward, so a landed branch's commits are ancestors of nothing and a
    // reachability test would collect live work.
    let mut found: Vec<String> = Vec::new();
    for prefix in ["refs/heads", "refs/remotes"] {
        for reference in references
            .prefixed(prefix)
            .map_err(|_| refusal())?
            .flatten()
        {
            found.push(reference.name().as_bstr().to_string());
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// The upstream `HEAD` tracks, as a full ref name, or `None` when it tracks
/// nothing (including on a detached `HEAD`).
///
/// Two deliberate spellings, both learned the hard way:
///
/// * **`@{upstream}`, not `<branch>@{upstream}`.** The question is only ever
///   asked about the current branch, so interpolating a branch name would put a
///   caller-influenced token in the argv for no gain. There is nothing here to
///   quote wrongly.
/// * **No `--end-of-options`.** Every other query in this module carries it, and
///   this one must not: in ref-printing mode `rev-parse` does not consume the
///   flag, it **echoes it as an output line**, so the answer comes back as
///   `"--end-of-options\nrefs/remotes/origin/main"` and every downstream ref
///   lookup fails on a target nobody configured. It is safe to omit precisely
///   because the argument is a fixed literal.
///
/// # Errors
///
/// Internal only — no upstream is `None`, not a failure.
pub fn upstream_of_head(dir: &Path) -> Result<Option<String>> {
    let Ok(repo) = open(dir) else {
        return Ok(None);
    };
    // The `--end-of-options` trap this function's doc records is GONE with the
    // argv: in ref-printing mode `rev-parse` echoed the token as an output line
    // rather than consuming it, so carrying it here returned the flag itself as
    // the upstream. A resolver takes no flags, so there is nothing to echo.
    let Some(name) = repo
        .head()
        .ok()
        .and_then(|head| head.referent_name().map(std::borrow::ToOwned::to_owned))
    else {
        // A detached HEAD tracks nothing, and neither does a branch with no
        // upstream — both are `None` rather than a failure.
        return Ok(None);
    };
    Ok(repo
        .branch_remote_tracking_ref_name(name.as_ref(), gix::remote::Direction::Fetch)
        .and_then(std::result::Result::ok)
        .map(|tracking| tracking.as_bstr().to_string()))
}

/// Count occurrences of `pattern` across files matching `glob` at `rev`
/// (CLOUD-55).
///
/// The base half of a ratchet. Paths come from `ls-tree`, bytes from `show` —
/// both through this module's one invoker, so a ratchet adds no second way to
/// read git. The working-tree half is the caller's, using the crate's one tree
/// walker; neither side re-implements the other's glob matching.
///
/// **A gitlink is skipped, which is this side's reading of the one selection
/// rule [`crate::rules::tree_files`] states** (CLOUD-328): the walker stops at a
/// nested repository, so this half must not count one either, and the two
/// select the same set for any glob. Skipped *explicitly* rather than by
/// accident — `git show <rev>:<gitlink>` fails with `bad object`, so the
/// read-failure path below already swallowed it, and a silent skip that happens
/// to land on the right answer is the same shape as the defect this fixes.
///
/// `ls-tree`'s long form is read rather than `--name-only`, because the mode is
/// what distinguishes a gitlink from a file and `--name-only` discards it. The
/// long form over `--format`, because it needs no git version floor; path
/// quoting is exactly as `--name-only` had it.
///
/// Byte-level and case-sensitive, matching `forbid`'s discipline: the pattern is
/// a literal a consumer wrote, and a count that silently normalized it would be
/// counting something else.
///
/// A file at `rev` whose bytes are not UTF-8 contributes zero rather than
/// failing the run: a binary blob matching a text pattern is not a fact anyone
/// is asserting, and refusing the whole gate over one would make an unrelated
/// asset able to disable it.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `rev` does not resolve — never a
/// pass. A ratchet that cannot see its baseline has not established that the
/// count held, and reporting zero would read as "nothing was deleted" having
/// looked at nothing.
pub fn count_at_rev(dir: &Path, rev: &str, glob: &str, pattern: &str) -> Result<usize> {
    let mut total = 0;
    for_each_blob_at_rev(dir, rev, glob, |_, text| {
        total += text.matches(pattern).count();
    })?;
    Ok(total)
}

/// Which of `paths` name a blob at `rev` (CLOUD-807).
///
/// The base-side half of `retires_with`'s admission. A declared subject is only
/// evidence that something DIED if it was alive at the base rev: without this,
/// a header naming a path that never existed would report "absent from the
/// working tree" and admit the deletion it was supposed to justify. That is the
/// header rotting into a lie, and it is the case the row's §7(d) names.
///
/// Looked up entry-by-entry rather than by walking the tree, because the caller
/// asks about a handful of declared paths and a subject is a path a consumer
/// typed, never a glob. A path naming a tree rather than a blob answers `false`:
/// a directory is not a subject a suite can be said to cover.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `rev` does not resolve, matching
/// [`count_at_rev`] — a lookup that could not see the baseline must not answer
/// "absent", which is the admitting direction.
pub fn paths_present_at_rev(
    dir: &Path,
    rev: &str,
    paths: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let repository = open(dir)?;
    let unresolved = || {
        UsageError::raise(format!(
            "ratchet base {rev:?} does not resolve to a tree in this repository"
        ))
    };
    let resolved = repository.rev_parse_single(rev).map_err(|_| unresolved())?;
    let tree = resolved
        .object()
        .map_err(|_| unresolved())?
        .peel_to_tree()
        .map_err(|_| unresolved())?;

    let mut present = BTreeSet::new();
    for path in paths {
        // A lookup that fails to read is "not present", the REFUSING direction
        // for an admission: the caller denies a decrease it cannot justify.
        let Ok(Some(entry)) = tree.lookup_entry_by_path(path.as_str()) else {
            continue;
        };
        if entry.mode().is_blob() {
            present.insert(path.clone());
        }
    }
    Ok(present)
}

/// Visit every glob-matching blob at `rev`, handing the callback its path and
/// its UTF-8 text (CLOUD-807).
///
/// The base-tree walk [`count_at_rev`] is a sum over — extracted rather than
/// copied, so the two halves of a ratchet keep ONE authority on which blobs a
/// glob selects at a rev. `retires_with` needs the same walk to read a
/// per-file count and a declared-subject header out of the same pass, and a
/// second traversal beside this one is exactly how the gitlink and
/// `core.quotePath` skews below got in.
///
/// Every selection and skip rule is documented at the site it applies; see
/// [`count_at_rev`] for why each one is a correctness property rather than a
/// convenience.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when `rev` does not resolve, for the
/// reason [`count_at_rev`] gives: a baseline that could not be read is never a
/// pass.
pub fn for_each_blob_at_rev(
    dir: &Path,
    rev: &str,
    glob: &str,
    mut visit: impl FnMut(&str, &str),
) -> Result<()> {
    let repository = open(dir)?;
    walk_blob_ids(&repository, rev, glob, |path, id| {
        // A read that fails is treated as an empty file rather than aborting,
        // for the same reason non-UTF-8 content is: an unrelated asset must not
        // be able to disable the gate.
        let Ok(object) = repository.find_object(id) else {
            return;
        };
        let Ok(text) = std::str::from_utf8(&object.data) else {
            return;
        };
        visit(path, text);
    })
}

/// The walk [`for_each_blob_at_rev`] and [`base_delta`] share, handing back each
/// selected blob's path and its **object id** without decompressing it
/// (CLOUD-1051).
///
/// Extracted rather than copied for the reason [`for_each_blob_at_rev`] itself
/// was extracted from [`count_at_rev`]: every skip below — the gitlink, the
/// non-blob mode, the non-UTF-8 path, the `core.quotePath`-proof byte recorder —
/// is a correctness property that keeps two halves of a comparison selecting the
/// same set, and a second traversal beside this one is how CLOUD-328 and
/// CLOUD-749 got in.
///
/// **The id is the cheap half and that is the point.** A tree traversal reads
/// tree objects only; `find_object` is what pays zlib for a blob's bytes. A
/// caller that only needs to know *whether* a blob changed never has to spend
/// that — see [`base_delta`], which is why this split exists.
fn walk_blob_ids(
    repository: &gix::Repository,
    rev: &str,
    glob: &str,
    mut visit: impl FnMut(&str, gix::ObjectId),
) -> Result<()> {
    let unresolved = || {
        UsageError::raise(format!(
            "ratchet base {rev:?} does not resolve to a tree in this repository"
        ))
    };
    let resolved = repository.rev_parse_single(rev).map_err(|_| unresolved())?;
    let tree = resolved
        .object()
        .map_err(|_| unresolved())?
        .peel_to_tree()
        .map_err(|_| unresolved())?;

    // The same compiled matcher the working-tree half uses, built once for the
    // whole listing rather than re-parsed per entry (CLOUD-214). Sharing the
    // type is what keeps the two halves' answer to "does this glob select this
    // path" a single implementation.
    let selector = crate::rules::Selector::new(glob)?;

    // A recorded traversal rather than parsed `ls-tree` output, which is what
    // fixes CLOUD-749: the recorder hands back the path as BYTES, so
    // `core.quotePath` — git's default, and a legal local setting either way —
    // cannot reach the answer. Under the old read a non-ASCII path arrived as
    // `"caf\303\251.rs"`, quotes and octal escapes included, and the glob
    // silently failed to match it. The working-tree half walks with `ignore` and
    // sees the real path, so the two halves selected different files and the
    // ratchet reported a delta nobody made — CLOUD-328's failure class on a
    // second axis, in the same function.
    let mut recorder = gix::traverse::tree::Recorder::default();
    tree.traverse()
        .breadthfirst(&mut recorder)
        .map_err(|_| UsageError::raise(format!("cannot walk the tree at {rev:?}")))?;

    for entry in recorder.records {
        // A gitlink is skipped, explicitly. `crate::rules::tree_files` stops at a
        // nested repository, so this half must not count one either or the two
        // sides select different sets (CLOUD-328). The mode is a typed value
        // here rather than a string compared against `160000`.
        if entry.mode.is_commit() {
            continue;
        }
        if !entry.mode.is_blob() {
            continue;
        }
        // A path that is not UTF-8 cannot be matched by a glob a consumer wrote
        // as a Rust string, so it contributes zero — the same reading
        // `changed_paths` already gives such a path, rather than a lossy
        // conversion that would match something nobody named.
        let Ok(path) = std::str::from_utf8(&entry.filepath) else {
            continue;
        };
        if !selector.matches(path) {
            continue;
        }
        visit(path, entry.oid);
    }
    Ok(())
}

/// How a declared glob's paths differ between a base rev and the working tree
/// (CLOUD-1059).
///
/// Three disjoint sets of repo-relative paths, never a hunk and never a line —
/// non-negotiable rule 4, the same bound [`changed_paths`] and
/// [`Fact::GitStatus`](crate::facts::Fact::GitStatus) already hold to.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BaseDelta {
    /// Present now, absent at the base rev.
    pub added: Vec<String>,
    /// Present in both, with different content.
    pub edited: Vec<String>,
    /// Present at the base rev, absent now.
    pub deleted: Vec<String>,
    /// Of the paths above, the ones whose **non-comment content** differs
    /// (CLOUD-1051).
    ///
    /// # Why the engine computes this and not the module
    ///
    /// "Which lines of this file are comments" is a lexical fact about the file,
    /// the same class as [`Fact::Uses`](crate::facts::Fact::Uses) — the engine
    /// resolves it, and the module decides over it. The predicate that consumes
    /// it ("nothing but comments moved, and no test did") stays in Rego, where it
    /// can be read and tested.
    ///
    /// # It compares REMAINDERS, not diff lines, and that is the repair
    ///
    /// The shell gate this replaces classified `git diff --unified=0`'s `+`/`-`
    /// lines one at a time. That reads a moved block of code as changed lines on
    /// both sides and a reflowed comment as a code change whenever a line
    /// straddles the boundary. Comparing the two remainders answers the question
    /// directly: strip every comment and blank line from each side and ask
    /// whether what is left is byte-identical.
    ///
    /// A side that does not exist is the empty remainder, which is what makes
    /// added and deleted paths classifiable at all. That is a deliberate
    /// improvement on the shell, which dropped deletions wholesale
    /// (`--diff-filter=d`) because it could not classify them: deleting a module
    /// now differs (its remainder was not empty) while deleting a pure-prose file
    /// does not, where the shell's blanket exclusion had to treat both alike.
    #[serde(rename = "code-changed")]
    pub code_changed: Vec<String>,
    /// When the base rev was committed, as strict ISO-8601 UTC (CLOUD-1051).
    ///
    /// **A property of the base, so it belongs to the fact that resolved one.**
    /// The predicate that needs it asks whether a record predates the branch —
    /// *a deferral of work in the diff you are holding open cannot be a row
    /// written before that diff existed* — which is a question about this
    /// comparison, not a new fact about the repository.
    ///
    /// Fixed-width UTC, deliberately, so a consumer compares it lexicographically
    /// rather than parsing a date. That is the same reading the shell gate needed
    /// `date -d` to avoid, and Rego has no date type to reach for either.
    ///
    /// `None` when the rev resolves to something with no commit time — a tag
    /// object pointing at a tree, say. The three path lists are still answered in
    /// that case, because they were computable and this was not; collapsing the
    /// whole fact to could-not-look over one unreadable field would be the
    /// opposite error.
    #[serde(rename = "base-date")]
    pub base_date: Option<String>,
    /// The lines each EDITED path had at the base rev (CLOUD-1051).
    ///
    /// # The one question the head side cannot answer
    ///
    /// `input.tree.lines` is what a file says NOW. A predicate asking *what did
    /// this edit remove* needs the other side, and nothing else in the input
    /// carries it — so `shell-retirement` could only ever refuse an edit, never
    /// admit one, and the campaign could not delete a retired program's row from
    /// a sibling's declaration table without tripping its own gate.
    ///
    /// # Bounded to `edited`, which is what keeps it affordable
    ///
    /// Not `added` (there is no base side), not `deleted` (the head side is
    /// gone), and not every declared path — only the handful a branch actually
    /// moved. That is the same bound the remainder comparison above already
    /// pays: the blob is fetched for a path that changed, and this reuses the
    /// read rather than adding one.
    ///
    /// A path absent from this map is could-not-look — a non-UTF-8 blob, or one
    /// the object database would not yield — and a consumer must read it as
    /// *cannot tell what was removed* rather than as *nothing was removed*. That
    /// is the difference between admitting an edit and refusing it, so the two
    /// must not collapse.
    #[serde(rename = "base-lines")]
    pub base_lines: BTreeMap<String, Vec<String>>,
}

/// A file's content with its comment and blank lines removed.
///
/// **An unrecognised extension has no comments**, so its remainder is the whole
/// file and any change to it is a code change. The failure direction is
/// deliberate and is the shell gate's: a rule over this ADMITS a branch when it
/// is wrong in one direction and blocks correct work when it is wrong in the
/// other, and only the second is unrecoverable by waiting.
///
/// Block comments are deliberately NOT recognised. A `/* */` run cannot be
/// classified line-by-line without tracking state, and guessing fails in the
/// refusing direction — so a file using them reads as code, which is the safe
/// half.
fn without_comments(path: &str, text: &str) -> String {
    let prefix = match path.rsplit_once('.').map(|(_, ext)| ext) {
        // Markdown is prose end to end; there is no non-comment remainder.
        Some("md") => return String::new(),
        Some("rs") => "//",
        Some("sh" | "bash" | "bats") => "#",
        // `mise-tasks/` programs carry no extension (CLOUD-865 renamed most to
        // `.sh`, but the pattern stays so a re-added extensionless task is still
        // read). The check is on the DIRECTORY, so it cannot claim a file
        // elsewhere that happens to lack a dot.
        _ if path.starts_with("mise-tasks/") => "#",
        _ => return text.to_owned(),
    };
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(prefix))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// Write the tree at `rev` into `dest`, blob by blob (CLOUD-1050).
///
/// **This exists because `git worktree add` is a git spawn and there is no
/// longer anywhere in this crate for one to live.** CLOUD-740's terminal
/// assertion — `no_second_git_invoker_exists` — forbids naming `git` as a
/// literal program anywhere under `src/`, and the `semver` adapter's baseline
/// build needs a source tree at a rev. A traversal that writes what it reads is
/// the whole of what the worktree was providing, and it is strictly better here
/// for two reasons the spawn version paid for in bugs: there is no registration
/// kept elsewhere, so removing the directory cannot strand a stale entry that
/// the next run reports as "already registered"; and the destination is a plain
/// directory rather than a linked worktree, so nothing about the baseline can
/// reach back into the repository it came from.
///
/// **Modes are not reproduced, and that is a stated bound.** Every entry lands
/// as an ordinary file: the one consumer is a `cargo doc` build, which reads
/// manifests and sources and executes nothing out of the tree. A caller needing
/// an executable bit needs a different primitive, not an extra argument here.
///
/// # Errors
///
/// Raises when the repository cannot be opened, when `rev` does not resolve to a
/// tree, when a blob cannot be read, when a write fails — and, deliberately,
/// when the traversal selected **nothing**. An empty destination is the vacuous
/// shape: a doc build over it would fail with a message about a missing
/// manifest, which is a true statement about the wrong question.
pub fn materialize_rev(dir: &Path, rev: &str, dest: &Path) -> Result<()> {
    let repository = open(dir)?;

    // COLLECTED FIRST, because the visitor is `FnMut` and writing inside it
    // would make every filesystem error a value the traversal cannot carry out.
    // The ids are cheap — that is the split `walk_blob_ids` exists for — so
    // holding them costs a map of the tree rather than the tree's contents.
    let mut blobs: Vec<(String, gix::ObjectId)> = Vec::new();
    walk_blob_ids(&repository, rev, "**", |path, id| {
        blobs.push((path.to_owned(), id));
    })?;
    if blobs.is_empty() {
        return Err(UsageError::raise(format!(
            "the tree at {rev:?} selected no file to materialize"
        )));
    }

    for (path, id) in blobs {
        let out = dest.join(&path);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                UsageError::raise(format!("cannot create {}: {err}", parent.display()))
            })?;
        }
        let object = repository.find_object(id).map_err(|err| {
            UsageError::raise(format!("cannot read the blob behind {path:?}: {err}"))
        })?;
        std::fs::write(&out, &object.data)
            .map_err(|err| UsageError::raise(format!("cannot write {}: {err}", out.display())))?;
    }
    Ok(())
}

/// Classify every path a declared glob selects as added, edited or deleted
/// against `base` (CLOUD-1059).
///
/// **Built from [`for_each_blob_at_rev`] and the working tree, never from a
/// spawned `git diff`.** CLOUD-740 is taking the crate to zero `git` spawns, so a
/// new one here would be a regression the same release is removing elsewhere.
/// Every primitive this needs is already gix-backed.
///
/// **The base is a REF, so this is a tip diff rather than a merge-base diff.**
/// Stated as a bound rather than left to be discovered: `mise run verify` asserts
/// the branch is rebased on the current `origin/main`, so on the path that
/// matters the tip and the merge base are the same commit. On a stale branch they
/// are not, and this reports paths `main` moved as though this branch moved them.
/// That is the same reading [`Rule::retires_with`](crate::rules::Rule::retires_with)
/// already takes from its own `base` column, and sharing it is deliberate: two
/// answers to "what did this branch change" is the drift a single column exists
/// to prevent.
///
/// Absent — `None` — when the base rev does not resolve, never an empty delta.
/// "This branch changed nothing" and "I could not read the base" are the two
/// answers a migration gate must keep apart, and Rego reads an undefined path as
/// *does not hold*, so a fabricated empty set would pass the gate on ignorance.
///
/// # Errors
///
/// Raises only when the repository cannot be opened at all.
pub fn base_delta(dir: &Path, base: &str, globs: &[String]) -> Result<Option<BaseDelta>> {
    let repository = open(dir)?;
    let hash = repository.object_hash();

    // IDS, NOT TEXT, and that is the whole cost of this function (CLOUD-1051).
    // The first version stored every selected blob's decompressed text here. With
    // `delta_sources = ["**"]` — which `prose-only` declares, because a
    // prose-only change is a claim about the whole diff — that is the entire
    // repository inflated into a map on every `check`: measured at ~3 min to
    // ~11 min for `mise run batten-check` on a debug build. An id costs a tree
    // read; the blob behind it is fetched below only for a path that actually
    // moved, which is a handful per branch rather than every tracked file.
    let mut at_base: BTreeMap<String, gix::ObjectId> = BTreeMap::new();
    for glob in globs {
        // A base that does not resolve is could-not-look for the WHOLE fact, not
        // for one glob: a partial answer here would report every path the
        // unresolvable glob would have covered as added.
        match walk_blob_ids(&repository, base, glob, |path, id| {
            at_base.insert(path.to_owned(), id);
        }) {
            Ok(()) => {}
            Err(_) => return Ok(None),
        }
    }

    // The base side of a comparison, paid for one path at a time. Unreadable and
    // non-UTF-8 blobs answer with the empty remainder, which is the same reading
    // the text-mapped version gave them by skipping them.
    let base_text = |id: gix::ObjectId| -> String {
        repository
            .find_object(id)
            .ok()
            .and_then(|object| std::str::from_utf8(&object.data).map(str::to_owned).ok())
            .unwrap_or_default()
    };

    // ONE walk for every declared glob, matched against all of them, rather than
    // a walk per glob: the working-tree half is the expensive side and the
    // selectors are cheap, so re-walking would charge the tree once per
    // declaration for an answer that does not change.
    let selectors = globs
        .iter()
        .map(|glob| crate::rules::Selector::new(glob))
        .collect::<Result<Vec<_>>>()?;
    let selects = |path: &str| selectors.iter().any(|selector| selector.matches(path));

    let mut delta = BaseDelta::default();
    let mut present: BTreeSet<String> = BTreeSet::new();
    for path in crate::rules::tree_files(dir)? {
        if !selects(&path) {
            continue;
        }
        present.insert(path.clone());
        let was = at_base.get(&path).copied();

        // CLASSIFY BY BLOB ID, and read nothing further when it matches.
        //
        // The working-tree bytes are hashed as git would hash them, so an
        // unchanged path is settled without decompressing its base blob and
        // without either `without_comments` pass. That is the case for almost
        // every selected file on almost every branch.
        //
        // **Filters are not applied, and the failure direction is the safe one.**
        // `.gitattributes` here is `* text=auto eol=lf`, so the checkout and the
        // index hold identical bytes on every platform and the hashes agree.
        // Where a checkout ever did convert line endings, the ids would differ
        // and the path would fall through to the text comparison below — which is
        // exactly what the previous, always-reading version concluded for it too.
        // So this can cost an extra read; it cannot manufacture a verdict.
        let now = std::fs::read(dir.join(&path)).unwrap_or_default();
        let unchanged = was.is_some_and(|was| {
            gix::objs::compute_hash(hash, gix::object::Kind::Blob, &now).is_ok_and(|now| now == was)
        });
        if unchanged {
            continue;
        }

        let edited = was.is_some();
        if edited {
            delta.edited.push(path.clone());
        } else {
            delta.added.push(path.clone());
        }
        // Only a path this branch touched can have moved its remainder, so the
        // comparison is charged to those alone rather than to every selected
        // file — and the base blob is fetched here, at the one point it is worth
        // paying for. A non-UTF-8 working file reads as the empty remainder, the
        // same lens `base_text` applies to the other side.
        let now = String::from_utf8(now).unwrap_or_default();
        let was = was.map(base_text).unwrap_or_default();
        // THE BASE SIDE, KEPT (CLOUD-1051), and only for a path that moved. The
        // blob was fetched a line above for the remainder comparison, so this is
        // a clone of text already in hand rather than a second read.
        //
        // Only `edited`: an added path has no base side and a deleted one has no
        // head side, so neither can answer *what did this edit remove*.
        if edited {
            delta
                .base_lines
                .insert(path.clone(), was.lines().map(str::to_owned).collect());
        }
        if without_comments(&path, &was) != without_comments(&path, &now) {
            delta.code_changed.push(path.clone());
        }
    }
    // Deleted is decided against the WALK, not against `Path::exists`: the walk
    // honours `.gitignore`, so a path the base tracked and the head ignores is a
    // deletion from the selected set even though a file is still on disk.
    delta.deleted = at_base
        .keys()
        .filter(|path| selects(path) && !present.contains(*path))
        .cloned()
        .collect();
    // A deleted path's head remainder is the empty one, which is what lets a
    // pure-prose deletion differ from a module deletion — see `code_changed`.
    for path in &delta.deleted {
        let was = at_base
            .get(path)
            .copied()
            .map(base_text)
            .unwrap_or_default();
        if !without_comments(path, &was).is_empty() {
            delta.code_changed.push(path.clone());
        }
    }

    delta.added.sort();
    delta.edited.sort();
    delta.deleted.sort();
    delta.code_changed.sort();
    // THE BASE'S OWN TIMESTAMP, resolved here because this is where the base rev
    // has already been resolved. Every failure leaves `None` rather than a
    // fabricated instant: a consumer comparing against could-not-look must skip
    // the comparison, and a zero epoch would silently exempt nothing while
    // reading as an answer.
    delta.base_date = repository
        .rev_parse_single(base)
        .ok()
        .and_then(|resolved| repository.find_object(resolved).ok())
        .and_then(|object| object.try_into_commit().ok())
        .and_then(|commit| commit.time().ok())
        .map(|time| {
            // FIXED-WIDTH UTC, which is what makes a lexicographic compare
            // downstream equal a chronological one. `time.seconds` is the epoch
            // second and the offset is discarded on purpose — two commits written
            // in different zones must still order correctly, and rendering the
            // local offset would break exactly that.
            let seconds = time.seconds;
            let days = seconds.div_euclid(86_400);
            let rest = seconds.rem_euclid(86_400);
            let (year, month, day) = civil_from_days(days);
            format!(
                "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
                rest / 3600,
                (rest % 3600) / 60,
                rest % 60,
            )
        });
    Ok(Some(delta))
}

/// The civil date a count of days since the Unix epoch names.
///
/// Howard Hinnant's `civil_from_days`, which is the algorithm every date library
/// uses for this and is thirty lines rather than a dependency. Vendored instead
/// of reached for because the one caller wants a fixed-width UTC string and
/// nothing else — no parsing, no zones, no formatting vocabulary — and
/// `no-source-built-tool`'s sibling reasoning applies to a crate too: a
/// dependency is worth its supply chain when it answers a question this cannot.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The remote's default branch, as a full remote-tracking ref.
///
/// The fallback landing target when a consumer declares no `must_land_on`
/// (CLOUD-51): work lands on the trunk unless told otherwise, and making every
/// consumer spell that out is a config tax that buys nothing.
///
/// Read from `refs/remotes/<remote>/HEAD`, which is what `git clone` and
/// `git remote set-head` maintain. **Not** guessed from a hardcoded `main` or
/// `master`: a guess that resolves to a ref that happens to exist would answer
/// "not landed" against the wrong trunk, silently, which is the failure mode
/// `landing` was built to avoid on the ancestry axis.
///
/// `None` when the remote has no recorded HEAD, or there is no remote at all —
/// both are ordinary states (a fresh local repository has neither), and the
/// caller owes the absent case its own reading rather than a pass.
///
/// # Errors
///
/// Internal only — an unresolvable default is `None`, not a failure.
pub fn remote_default_branch(dir: &Path) -> Result<Option<String>> {
    let remotes = remotes(dir)?;
    // `origin` when it exists, else the first configured remote in the sorted
    // listing — deterministic, so the answer is byte-stable for a given repo.
    let remote = if remotes.iter().any(|(name, _)| name == "origin") {
        "origin".to_owned()
    } else {
        let Some((name, _)) = remotes.first() else {
            return Ok(None);
        };
        name.clone()
    };
    // A missing HEAD is an absent ref rather than a non-zero exit now, which is
    // the same answer arriving as a value instead of as an exit status.
    let Ok(repo) = open(dir) else {
        return Ok(None);
    };
    let Ok(reference) = repo.find_reference(&format!("refs/remotes/{remote}/HEAD")) else {
        return Ok(None);
    };
    // The SYMBOLIC target, which is what `symbolic-ref` printed: a remote HEAD
    // records which branch is the trunk, and peeling it to an object would answer
    // a different question.
    Ok(match reference.target() {
        gix::refs::TargetRef::Symbolic(name) => Some(name.as_bstr().to_string()),
        gix::refs::TargetRef::Object(_) => None,
    }
    .filter(|found| !found.is_empty()))
}

/// Resolve `rev` to the full SHA of a commit.
///
/// Peeled to a commit deliberately: a tag, tree or blob is refused here rather
/// than going on to diff something meaningless. Reads through
/// [`open`]'s isolated handle, so an ambient `GIT_DIR` cannot redirect it.
fn resolve_commit(dir: &Path, rev: &str, role: &str) -> Result<String> {
    let repo = open(dir)?;
    let refused = || {
        UsageError::raise(format!(
            "{role} {rev:?} does not resolve to a commit in this repository"
        ))
    };
    let object = repo.rev_parse_single(rev).map_err(|_| refused())?;
    let commit = object
        .object()
        .map_err(|_| refused())?
        .peel_to_commit()
        .map_err(|_| refused())?;
    Ok(commit.id().to_string())
}

/// Enumerate commits, newest first, under the fixed selection this module uses
/// everywhere: topological order (commit-date order can reorder commits that
/// share a timestamp), no merges, capped by the window.
///
/// Merges are excluded deliberately, not incidentally: a merge has no patch of
/// its own, and the commits it brings in are separately enumerated here. That
/// stays true only while this stays a full walk — a first-parent walk would make
/// everything merged in invisible, which is a silent false *not landed*.
///
/// `range` is either a single commit (everything reachable from it) or
/// `a..b` (reachable from `b`, not from `a`). **That is range SELECTION, not a
/// reachability answer** — the distinction `no_ancestry_decides_merged_ness`
/// draws, and the reason this is allowed to walk parents at all while nothing
/// here may ask whether one commit contains another.
fn rev_list(dir: &Path, window: Window, range: &str) -> Result<Vec<String>> {
    let repo = open(dir)?;
    let refused = || UsageError::raise(format!("cannot enumerate commits for {range:?}"));
    let (exclude, include) = match range.split_once("..") {
        Some((from, to)) => (Some(from), to),
        None => (None, range),
    };
    let tip = repo
        .rev_parse_single(include)
        .map_err(|_| refused())?
        .detach();
    let mut hidden = Vec::new();
    if let Some(from) = exclude {
        hidden.push(repo.rev_parse_single(from).map_err(|_| refused())?.detach());
    }
    let mut walk = repo
        .rev_walk([tip])
        .sorting(gix::revision::walk::Sorting::BreadthFirst);
    if !hidden.is_empty() {
        walk = walk.with_hidden(hidden);
    }
    let mut out = Vec::new();
    for step in walk.all().map_err(|_| refused())? {
        let info = step.map_err(|_| refused())?;
        // A merge has no patch of its own; its contents are enumerated through
        // the commits it brings in.
        if info.parent_ids().count() > 1 {
            continue;
        }
        out.push(info.id().to_string());
        if out.len() >= window.commits() {
            break;
        }
    }
    Ok(out)
}

/// The changes one commit makes against its first parent, in the canonical form
/// [`crate::patch`] hashes.
///
/// A root commit is diffed against the empty tree, which is what makes its whole
/// content its change rather than leaving it identity-less.
fn commit_changes(repo: &gix::Repository, id: &gix::ObjectId) -> Result<Vec<crate::patch::Change>> {
    let commit = repo.find_object(*id)?.peel_to_commit()?;
    let new_tree = commit.tree()?;
    let old_tree = match commit.parent_ids().next() {
        Some(parent) => repo
            .find_object(parent.detach())?
            .peel_to_commit()?
            .tree()?,
        None => repo.empty_tree(),
    };
    tree_changes(repo, &old_tree, &new_tree)
}

/// The changes between two trees, with no rename detection.
///
/// Rename detection is refused rather than merely unconfigured — see
/// [`crate::patch`]'s module doc: a similarity heuristic inside an identity lets
/// two runs disagree about what counts as the same change.
fn tree_changes(
    repo: &gix::Repository,
    old_tree: &gix::Tree<'_>,
    new_tree: &gix::Tree<'_>,
) -> Result<Vec<crate::patch::Change>> {
    use gix_diff::tree::recorder::Change as Recorded;

    let hash = repo.object_hash();
    let mut recorder = gix_diff::tree::Recorder::default();
    gix_diff::tree(
        gix::objs::TreeRefIter::from_bytes(&old_tree.data, hash),
        gix::objs::TreeRefIter::from_bytes(&new_tree.data, hash),
        gix_diff::tree::State::default(),
        &repo.objects,
        &mut recorder,
    )?;

    let mut out = Vec::new();
    for change in recorder.records {
        // DIRECTORY ENTRIES ARE NOT CHANGES, and skipping them is load-bearing
        // rather than tidy. `gix_diff::tree` records a changed subtree as well as
        // the blobs inside it, and a tree object's id encodes ALL of its
        // siblings — so `src/` has one id on a branch that added `src/b.rs` and a
        // different one on a `main` that also gained `src/other.rs`. Hashing that
        // id makes the identity depend on the base the change sits on, which is
        // the single property patch identity exists NOT to have: the same change
        // replayed elsewhere stops being recognisable, and `completion.unlanded`
        // raises against work that is already on the trunk.
        //
        // The recursion still delivers every blob underneath with its full path,
        // so nothing is lost by dropping the tree row — only the base-dependence
        // is. CLOUD-739's own §7 corpus missed this because every fixture path in
        // it sat at the repository ROOT, where the only tree in the diff is the
        // one being diffed and is never emitted as a change.
        let mode = match &change {
            Recorded::Addition { entry_mode, .. } | Recorded::Deletion { entry_mode, .. } => {
                *entry_mode
            }
            Recorded::Modification { entry_mode, .. } => *entry_mode,
        };
        if mode.is_tree() {
            continue;
        }
        let (path, kind) = match change {
            // `relation` is submodule/rewrite bookkeeping and is deliberately
            // ignored: this identity does no rename tracking, so a rewrite pair
            // is a deletion and an addition, which is what the target either has
            // or does not.
            Recorded::Addition {
                entry_mode,
                oid,
                path,
                relation: _,
            } => (
                path,
                crate::patch::Kind::Added {
                    blob: blob_side(repo, &oid, entry_mode),
                },
            ),
            Recorded::Deletion {
                entry_mode,
                oid,
                path,
                relation: _,
            } => (
                path,
                crate::patch::Kind::Removed {
                    blob: blob_side(repo, &oid, entry_mode),
                },
            ),
            Recorded::Modification {
                previous_entry_mode,
                previous_oid,
                entry_mode,
                oid,
                path,
            } => (
                path,
                crate::patch::Kind::Modified {
                    before: blob_side(repo, &previous_oid, previous_entry_mode),
                    after: blob_side(repo, &oid, entry_mode),
                },
            ),
        };
        out.push(crate::patch::Change {
            path: path.to_string().into_bytes(),
            kind,
        });
    }
    Ok(out)
}

/// One side of a change, with its content read only when it is a text blob.
///
/// A tree entry (a submodule, or a directory the recorder surfaced) carries no
/// content to diff and is identified by its id alone, which is exact.
fn blob_side(
    repo: &gix::Repository,
    oid: &gix::ObjectId,
    mode: gix::objs::tree::EntryMode,
) -> crate::patch::Blob {
    // A read that fails leaves `text` absent, which falls back to identifying
    // the side by its object id — exact, and never a silent empty content that
    // would let two unreadable blobs compare equal.
    let text = if mode.is_blob() {
        repo.find_object(*oid)
            .ok()
            .map(|object| object.data.clone())
            .filter(|bytes| crate::patch::is_text(bytes))
    } else {
        None
    };
    crate::patch::Blob {
        oid: oid.to_string(),
        mode: u32::from(mode.value()),
        text,
    }
}

/// The patch identity of every commit reachable by `range`, keyed for lookup.
///
/// When two commits share an identity — a revert and a re-apply, a change
/// cherry-picked twice — the **oldest** wins, so the evidence names the actual
/// landing rather than a later copy of it. The walk is newest-first, so
/// overwriting on each insert leaves the oldest in place.
///
/// No process, and therefore no host configuration: the twenty `-c` keys and six
/// flags this used to pin existed solely to stop the user's `git config` shaping
/// the diff, and [`open`]'s isolated handle declines that configuration
/// outright.
fn patch_id_index(dir: &Path, window: Window, range: &str) -> Result<BTreeMap<PatchId, String>> {
    let repo = open(dir)?;
    let mut index = BTreeMap::new();
    for commit in rev_list(dir, window, range)? {
        let id = gix::ObjectId::from_hex(commit.as_bytes())
            .map_err(|_| UsageError::raise(format!("cannot read commits for {range:?}")))?;
        let mut changes = commit_changes(&repo, &id)?;
        if let Some(hex) = crate::patch::identity(&mut changes) {
            index.insert(PatchId::parse(&hex)?, commit);
        }
    }
    Ok(index)
}

/// Where this branch and `base_ref` diverged, for RANGE SELECTION.
///
/// The same line [`cumulative_patch_id`] draws, and the reason this is here at
/// all rather than in its caller: `perf::pair` needs the commit to BUILD the
/// comparison arm from, and a shelled-out reachability verb is what
/// `ancestry-decides-nothing` refuses — correctly, since a spawned argv is the
/// surface a merged-ness answer would hide in. Selecting which commit to build
/// is not deciding whether anything landed, and going through `gix` keeps that
/// distinction structural instead of a claim in a comment.
///
/// `None` when the ref does not resolve or the two share no history: both are
/// could-not-look, and the caller says so rather than measuring something else.
///
/// # Errors
///
/// When the repository cannot be opened.
pub fn merge_base(dir: &Path, base_ref: &str) -> Result<Option<String>> {
    let repo = open(dir)?;
    let Some(base) = resolve_ref(dir, base_ref)? else {
        return Ok(None);
    };
    let Ok(base_id) = gix::ObjectId::from_hex(base.as_bytes()) else {
        return Ok(None);
    };
    let Ok(head_id) = gix::ObjectId::from_hex(head_commit(dir)?.as_bytes()) else {
        return Ok(None);
    };
    Ok(repo
        .merge_base(base_id, head_id)
        .ok()
        .map(|found| found.detach().to_string()))
}

/// The patch identity of the branch's whole change: the diff from where the two
/// histories diverged to `head`.
///
/// The merge base is used for RANGE SELECTION and never as a merged-ness answer,
/// which is the line `no_ancestry_decides_merged_ness` draws. Diffing `head`
/// against `target` directly would also carry the *inverse* of everything that
/// landed on the target since the branch left it, so it could never equal a
/// squashed commit no matter how faithfully the work landed.
///
/// `None` when the diff is empty — an absent identity must never compare equal
/// to another absent identity.
fn cumulative_patch_id(dir: &Path, target: &str, head: &str) -> Result<Option<PatchId>> {
    let repo = open(dir)?;
    let refused = || UsageError::raise(format!("cannot diff {target:?} against {head:?}"));
    let target_id = gix::ObjectId::from_hex(target.as_bytes()).map_err(|_| refused())?;
    let head_id = gix::ObjectId::from_hex(head.as_bytes()).map_err(|_| refused())?;
    let base = repo
        .merge_base(target_id, head_id)
        .map_err(|_| UsageError::raise(format!("{target:?} and {head:?} share no history")))?;
    let old_tree = repo
        .find_object(base.detach())
        .map_err(|_| refused())?
        .peel_to_commit()
        .map_err(|_| refused())?
        .tree()
        .map_err(|_| refused())?;
    let new_tree = repo
        .find_object(head_id)
        .map_err(|_| refused())?
        .peel_to_commit()
        .map_err(|_| refused())?
        .tree()
        .map_err(|_| refused())?;
    let mut changes = tree_changes(&repo, &old_tree, &new_tree)?;
    crate::patch::identity(&mut changes)
        .map(|hex| PatchId::parse(&hex))
        .transpose()
}

/// Decide whether the work on `head` has landed on `target`, by the identity of
/// the *changes* rather than by reachability.
///
/// A rebased-and-landed branch, a squash-merged branch, and a cherry-picked
/// commit are all reported as landed, because all three leave the same change
/// on the target under a different SHA with no reachability path back to the
/// original. See the module documentation for why the opposite answer is the
/// one that has to be got right.
///
/// Deterministic and byte-stable for a fixed repository state, target, head,
/// and window: fixed command lines with every diff knob pinned, fixed ordering,
/// no dependence on ambient environment or user config. Reads refs as they are
/// on disk — it writes nothing, prints nothing, and fetches nothing, so a stale
/// `origin/main` is the caller's problem to refresh (agents fetch, gates
/// decide).
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1` at a consumer boundary) when `target` or
/// `head` does not resolve to a commit, when `repo` is not inside a repository,
/// or when the two commits share no history. Returns an internal error when
/// `git` cannot be run or prints output this module cannot parse.
pub fn landing(repo: &Path, target: &str, head: &str, window: Window) -> Result<Landing> {
    let target_commit = resolve_commit(repo, target, "target")?;
    let head_commit = resolve_commit(repo, head, "head")?;

    let target_commits = rev_list(repo, window, &target_commit)?;
    let target_index = patch_id_index(repo, window, &target_commit)?;

    let range = format!("{target_commit}..{head_commit}");
    let head_commits = rev_list(repo, window, &range)?;
    let head_index = patch_id_index(repo, window, &range)?;
    // `patch_id_index` is keyed by identity for target lookups; the head side
    // needs the inverse, and building it here keeps one pipeline per side.
    let head_ids: BTreeMap<&str, &PatchId> = head_index
        .iter()
        .map(|(id, commit)| (commit.as_str(), id))
        .collect();

    // Oldest first: the reporting order is fixed, and `rev-list` walks newest
    // first.
    let commits: Vec<CommitLanding> = head_commits
        .iter()
        .rev()
        .map(|commit| {
            let patch_id = head_ids.get(commit.as_str()).map(|id| (*id).clone());
            let evidence = match &patch_id {
                // An empty diff has nothing to land, and — critically — no
                // identity to match, so it can never pair with another empty
                // commit on the target.
                None => Some(Evidence::NoContent),
                Some(id) => target_index.get(id).map(|target_commit| Evidence::PatchId {
                    target_commit: target_commit.clone(),
                    patch_id: id.clone(),
                }),
            };
            CommitLanding {
                commit: commit.clone(),
                patch_id,
                evidence,
            }
        })
        .collect();

    // Computed unconditionally, never short-circuited: a field whose presence
    // depends on an early return is not byte-stable for identical input.
    let cumulative = cumulative_patch_id(repo, &target_commit, &head_commit)?;
    let cumulative_evidence = cumulative.as_ref().and_then(|id| {
        target_index.get(id).map(|target_commit| Evidence::Squash {
            target_commit: target_commit.clone(),
            patch_id: id.clone(),
        })
    });

    let verdict = verdict(&commits, cumulative.as_ref(), cumulative_evidence.as_ref());
    Ok(Landing {
        verdict,
        commits,
        cumulative,
        cumulative_evidence,
        scanned: Scan {
            target_commit,
            head_commit,
            target_commits_scanned: target_commits.len(),
            target_truncated: target_commits.len() >= window.commits(),
            head_truncated: head_commits.len() >= window.commits(),
            window,
        },
    })
}

/// Derive the verdict from the evidence and nothing else.
///
/// This is the only place a [`Verdict`] is constructed, which is what makes the
/// module-level promise structural rather than aspirational: a landed verdict
/// cannot be reached without an [`Evidence`] value, and every `Evidence` that
/// means landed carries the target commit that proves it.
fn verdict(
    commits: &[CommitLanding],
    cumulative: Option<&PatchId>,
    cumulative_evidence: Option<&Evidence>,
) -> Verdict {
    // Checked first: a branch whose net change is empty has no unlanded work,
    // whether that is an empty commit, a change and its revert, or a branch the
    // target already contains outright.
    if cumulative.is_none() {
        return Verdict::NothingToLand;
    }
    let accounted = commits
        .iter()
        .filter(|commit| commit.evidence.is_some())
        .count();
    if accounted == commits.len() {
        Verdict::Landed
    } else if cumulative_evidence.is_some() {
        // No individual commit survived the merge, but the branch's whole
        // change is on the target as one commit. Per-commit evidence stays
        // `None`, because none of them individually landed — the report must
        // not lie about how.
        Verdict::Landed
    } else if accounted > 0 {
        Verdict::PartiallyLanded
    } else {
        Verdict::NotLandedWithinWindow
    }
}

// --- The git fact family (CLOUD-907) -----------------------------------------
//
// `crates/batten/src/facts.rs` owns WHICH git facts exist and what each costs;
// this section owns HOW each is acquired. Both halves are stated in one place
// each, because the defect the row is named for is a fact that is documented on
// one side and never built on the other (CLOUD-845).
//
// Every function here reuses `query`/`query_optional` above. That is the whole
// of "in-process, not a spawn" in this tree: `no_second_git_invoker` keeps the
// crate to one git entry point, each surviving `std::process::Command` site
// carries its verdict in an `#[expect]` (CLOUD-743), and a new fact family that
// opened its own would be an inventory row nobody decided.
//
// COULD-NOT-LOOK IS NEVER AN EMPTY ANSWER, and the types below are shaped so it
// cannot be written as one. An unresolvable ref is absent from `refs`, not
// present with a `false`; a range whose endpoints do not resolve is absent from
// `ranges`, not present with an empty list; HEAD in an empty repository has
// `commit: None`, not `""`. Rego reads an undefined path as "does not hold", so
// each collapse would be a gate that is silently off — CLOUD-845's measured
// class and CLOUD-251's before it.

/// [`crate::facts::Fact::GitHead`] — where HEAD is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HeadFact {
    /// HEAD's commit, or `None` in a repository with no commits.
    pub commit: Option<String>,
    /// The branch HEAD is on, or `None` when it is detached.
    pub branch: Option<String>,
    /// Whether HEAD is detached. Stated rather than inferred from `branch`
    /// being `None`: an empty repository also has no branch, and a gate asking
    /// "is this a detached checkout" must not answer yes to it.
    pub detached: bool,
}

/// [`crate::facts::Fact::GitStatus`] — how the working tree differs from HEAD.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StatusFact {
    /// Repository-relative paths that differ from HEAD, tracked and untracked.
    pub changed: Vec<String>,
    /// How many entries `git status --porcelain` reports.
    pub uncommitted: usize,
}

/// [`crate::facts::Fact::GitRemote`] — what this checkout is connected to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RemoteFact {
    /// Remote name -> URL, as `.git/config` holds it. Never asked over the
    /// network: that would be `Cost::Effect` and a different fact.
    pub remotes: BTreeMap<String, String>,
    /// HEAD's tracking ref, or `None` when it has no upstream.
    pub upstream: Option<String>,
}

/// One commit of a [`crate::facts::Fact::GitRange`], as a pointer.
///
/// A sha and a subject, and nothing else. A message body or a diff would put
/// tracked content on the policy input, which non-negotiable rule 4 refuses at
/// the boundary rather than at the report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RangeCommit {
    /// The commit's sha.
    pub commit: String,
    /// Its subject line.
    pub subject: String,
}

/// One commit's identity fields, for the policy input (CLOUD-1187).
///
/// **[`CommitRecord`] minus `body`, and the omission is the whole design.**
/// That type carries `%B` because `attribution.rs` judges the message itself;
/// this one reaches Rego, where non-negotiable rule 4 refuses tracked content at
/// the boundary rather than at the report. There is no body FIELD here, so a
/// module cannot read one and a future projection cannot leak one by accident —
/// the guarantee is structural rather than a comment on a serializer.
///
/// What is admissible is stated by shape: an author and a committer are identity
/// strings, and a trailer is a `Key: value` line — the same shape
/// `input.tree.records` already claims. A message body is prose the author wrote
/// and is not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CommitMeta {
    /// The commit's sha.
    pub commit: String,
    /// `%an <%ae>` — the author identity.
    pub author: String,
    /// `%cn <%ce>` — the committer identity.
    pub committer: String,
    /// `%(trailers:only,unfold)`, as whole `Key: value` lines.
    pub trailers: Vec<String>,
}

/// The git fact family as one bundle, each member `None` until a rule declares
/// it (CLOUD-907).
///
/// **`None` is the could-not-look shape, and it covers two conditions on
/// purpose: nobody asked, and the boundary asked and could not see.** That is
/// [`crate::hook::Facts::receipts`]'s existing shape rather than a new one — a
/// rule that did not declare a fact has established nothing about it, which is
/// the same standing as a rule whose read failed. The projection writes `null`
/// for both, so a module reads `input.tree["git-head"] == null` rather than
/// finding the key absent, and CLOUD-251's vacuous pass stays out.
///
/// What must NOT collapse is one level down, and the member types are what keep
/// it apart: an unresolvable ref is absent from `refs`, a detached HEAD has
/// `branch: None` beside `detached: true`, and a range that could not be read is
/// absent from `ranges`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GitFacts {
    /// [`HeadFact`], if a rule declared `git = ["head"]`.
    pub head: Option<HeadFact>,
    /// [`StatusFact`], if a rule declared `git = ["status"]`.
    pub status: Option<StatusFact>,
    /// [`RemoteFact`], if a rule declared `git = ["remote"]`.
    pub remote: Option<RemoteFact>,
    /// The declared refs resolved to the commit each names, if any row declared
    /// one. A ref that does not resolve is ABSENT from the map.
    pub refs: Option<BTreeMap<String, String>>,
    /// The declared ranges, if any row declared one.
    pub ranges: Option<BTreeMap<String, Vec<RangeCommit>>>,
    /// The STAGED bytes of the declared paths, if any row declared one
    /// (CLOUD-1203). A path with no staged entry is ABSENT from the map.
    pub staged: Option<BTreeMap<String, String>>,
    /// The declared metadata ranges, if any row declared one (CLOUD-1187). A
    /// SEPARATE declaration from `ranges`, so a row wanting subjects does not pay
    /// for a per-commit object peel it never asked for. A range that does not
    /// resolve is ABSENT from the map.
    pub metadata: Option<BTreeMap<String, Vec<CommitMeta>>>,
    /// The declared landing targets, if any row declared one (CLOUD-880). A
    /// target that could not be scanned is ABSENT from the map.
    pub landing: Option<BTreeMap<String, LandingFact>>,
    /// How the declared globs differ from the declared base rev, if any row
    /// declared both (CLOUD-1059). `None` when nobody asked AND when the base
    /// did not resolve — the family's own could-not-look shape, one level up
    /// from a range that is absent from `ranges`.
    pub base_delta: Option<BaseDelta>,
}

/// Acquire [`HeadFact`].
///
/// # Errors
///
/// Raises when `dir` is not inside a repository. A repository with no commits is
/// an ANSWER (`commit: None`), never an error: an empty checkout is a state a
/// gate may legitimately decide about.
pub fn head_fact(dir: &Path) -> Result<HeadFact> {
    // REPO-NESS FIRST, because the reads below cannot tell it apart from an
    // answer (CLOUD-480, found on review of #660). This mattered more under the
    // shell-out, where every non-zero git exit became `None` and an out-of-repo
    // call returned a FABRICATED `detached: false` for `git_facts` to project as
    // a real fact. In process the reads below cannot even be attempted without a
    // repository, but the call stays: the doc promises this raises, and the
    // promise should not rest on a later line happening to fail.
    repo_root(dir)?;
    let repo = open(dir)?;
    let head = repo
        .head()
        .map_err(|_| UsageError::raise(format!("{} is not a git repository", dir.display())))?;
    // An unborn HEAD is an ANSWER (`commit: None`), which is the distinction
    // worth keeping: an empty checkout is a state a gate may decide about.
    let commit = head.id().map(|id| id.detach().to_hex().to_string());
    // A detached HEAD has no referent name at all. Under `--abbrev-ref` it was
    // the literal string `HEAD`, and a repository with no commits still answered
    // with the unborn branch's name — which is why `detached` was read off that
    // rather than off `commit`, and why it is read off the referent here.
    let branch = head.referent_name().map(|name| name.shorten().to_string());
    let detached = branch.is_none();
    Ok(HeadFact {
        commit,
        branch,
        detached,
    })
}

/// Acquire [`StatusFact`].
///
/// # Errors
///
/// Raises when the working tree cannot be compared against HEAD.
pub fn status_fact(dir: &Path) -> Result<StatusFact> {
    let changed = changed_paths(dir)?;
    let uncommitted = uncommitted(dir)?;
    Ok(StatusFact {
        changed: changed.into_iter().collect(),
        uncommitted,
    })
}

/// Acquire [`RemoteFact`].
///
/// # Errors
///
/// Raises when the repository's config cannot be read.
pub fn remote_fact(dir: &Path) -> Result<RemoteFact> {
    // The same reason as `head_fact` (CLOUD-480): `remotes` reads a `--get-regexp`
    // failure as "no remotes configured", which is sound INSIDE a repository —
    // the invocation is a fixed literal, so no-match is the only reachable cause
    // there — and outside one it fabricated an empty map that reads as a real
    // answer about a repository nobody looked at. A repository with no remotes
    // stays a valid value.
    repo_root(dir)?;
    Ok(RemoteFact {
        remotes: remotes(dir)?.into_iter().collect(),
        upstream: upstream_of_head(dir)?,
    })
}

/// Acquire the DECLARED refs, skipping every one that does not resolve.
///
/// Skipping is the could-not-look channel and is the whole point: a ref absent
/// from the returned map is one the run could not see, and a module reading
/// `input.tree["git-refs"]["origin/main"]` gets undefined rather than a
/// fabricated answer. `origin/main` missing in a shallow clone is not a fact
/// about where HEAD stands relative to it.
///
/// **THE COMMIT, AND DELIBERATELY NOT WHETHER HEAD DESCENDS FROM IT.** The first
/// version carried an `ancestor_of_head` beside the sha and
/// `no_ancestry_decides_merged_ness` refused it, correctly: CLOUD-36's rule is
/// that merged-ness is decided by PATCH IDENTITY, never by reachability, because
/// a rebased landing is invisible to ancestry. Putting a reachability answer on
/// the policy input would have handed every migrating gate the wrong primitive
/// with the right-sounding name — and the census says exactly one gate-described
/// task asks that question today — `linear-check`, which computes the merge base
/// of `origin/main` and HEAD — so the temptation is real and small. The landing question has an answer
/// already: [`landing`], on patch identity, and CLOUD-880 is the row that makes
/// it a fact family.
///
/// # Errors
///
/// Raises only when `git` cannot be run at all. An unresolvable ref is an
/// answer, not a failure.
pub fn ref_facts(dir: &Path, declared: &[String]) -> Result<BTreeMap<String, String>> {
    let mut facts = BTreeMap::new();
    for name in declared {
        if let Some(commit) = resolve_ref(dir, name)? {
            facts.insert(name.clone(), commit);
        }
    }
    Ok(facts)
}

/// Acquire the DECLARED ranges, skipping every one whose endpoints do not
/// resolve.
///
/// Absent rather than empty, for [`ref_facts`]'s reason one level up: "no
/// commits landed in this range" and "I could not read this range" are the two
/// answers a migration gate most needs kept apart.
///
/// # Errors
///
/// Raises only when `git` cannot be run at all.
pub fn range_facts(dir: &Path, declared: &[String]) -> Result<BTreeMap<String, Vec<RangeCommit>>> {
    let mut facts = BTreeMap::new();
    for range in declared {
        let Some((base, head)) = range.split_once("..") else {
            continue;
        };
        if resolve_ref(dir, base)?.is_none() || resolve_ref(dir, head)?.is_none() {
            continue;
        }
        let commits = subjects_in_range(dir, base, head)?
            .into_iter()
            .map(|subject| RangeCommit {
                commit: subject.commit,
                subject: subject.subject,
            })
            .collect();
        facts.insert(range.clone(), commits);
    }
    Ok(facts)
}

/// The STAGED bytes of the paths a rule set declared (CLOUD-1203, unit A).
///
/// **`git show :<path>` — which [`crate::facts::Fact::Tracked`] explicitly is
/// NOT.** That fact is a `.gitignore`-honouring walk of the WORKING TREE, and
/// its own doc names the trap this function exists to close: a module author
/// writes a predicate about the index and gets an answer about the checkout.
/// `Fact::GitStatus` is no help either — it carries the paths that differ and a
/// count, never the staged content.
///
/// The distinction is load-bearing rather than pedantic. `lock-complete` is the
/// pure "committed bytes only, no network, no write" gate: it judges THE COMMIT,
/// not the developer's working copy, so a successor reading the worktree would
/// answer a different question and pass over a staged-but-unsaved edit. That is
/// a silent wrong answer rather than a missing feature.
///
/// In process via `gix` under the same isolated open the rest of this module
/// uses, so there is no spawn — and deliberately so here rather than through the
/// shelled reader, because the argv would carry a caller-supplied path, which is
/// the class CLOUD-718 moved `show` in-process for.
///
/// A path with no staged entry is ABSENT from the map rather than present with
/// an empty string: "this path is not staged" and "this path is staged empty"
/// are different answers, and a module handed the second for the first decides
/// over a file that is not there.
///
/// # Errors
///
/// Raises when the repository cannot be opened or its index cannot be read —
/// which is could-not-look about the whole family rather than about any one
/// path, and so is the caller's to project as `null`.
pub fn staged_facts(dir: &Path, declared: &[String]) -> Result<BTreeMap<String, String>> {
    let repo = open(dir)?;
    let index = repo
        .index_or_empty()
        .map_err(|_| UsageError::raise("could not read the git index".to_owned()))?;
    let mut facts = BTreeMap::new();
    for path in declared {
        let Some(entry) = index.entry_by_path(path.as_str().into()) else {
            continue;
        };
        let Ok(object) = repo.find_object(entry.id) else {
            continue;
        };
        // NOT UTF-8 IS NOT AN EMPTY FILE. A staged binary blob is skipped, so it
        // is absent rather than present as a lossy string a predicate would then
        // decide over.
        let Ok(text) = String::from_utf8(object.data.clone()) else {
            continue;
        };
        facts.insert(path.clone(), text);
    }
    Ok(facts)
}

/// The commit-metadata facts for the ranges a rule set declared (CLOUD-1187).
///
/// [`range_facts`]' sibling on a separate declaration, deliberately: a row that
/// wants subjects must not be made to pay for a per-commit object peel it never
/// asked for. Same bound as every other git fact — the ranges are declared, and a
/// range no row names resolves nothing.
///
/// **No body reaches this map**, and [`CommitMeta`] is what enforces it: the
/// field does not exist, so rule 4 is decided by the type rather than by this
/// function remembering to drop something.
///
/// A range whose endpoints do not resolve is ABSENT rather than an empty list,
/// matching [`range_facts`]: "no commits in this range" and "I could not read
/// this range" are the two answers a gate over history must keep apart. A single
/// commit the object database cannot peel is skipped rather than failing the
/// whole range — one unreadable commit is not evidence about the others.
///
/// # Errors
///
/// Propagates a ref resolution failure, exactly as [`range_facts`] does.
pub fn metadata_facts(
    dir: &Path,
    declared: &[String],
) -> Result<BTreeMap<String, Vec<CommitMeta>>> {
    let mut facts = BTreeMap::new();
    for range in declared {
        let Some((base, head)) = range.split_once("..") else {
            continue;
        };
        if resolve_ref(dir, base)?.is_none() || resolve_ref(dir, head)?.is_none() {
            continue;
        }
        let mut commits = Vec::new();
        for subject in subjects_in_range(dir, base, head)? {
            // Skipped rather than fatal, and skipped rather than fabricated: a
            // commit whose object cannot be peeled contributes nothing, where an
            // entry with empty identity fields would read to a module as a commit
            // authored by nobody.
            if let Ok(record) = commit_record(dir, &subject.commit) {
                commits.push(CommitMeta {
                    commit: subject.commit,
                    author: record.author,
                    committer: record.committer,
                    trailers: record.trailers,
                });
            }
        }
        facts.insert(range.clone(), commits);
    }
    Ok(facts)
}

/// What one declared target's landing scan answered, projected for a rule to read
/// (CLOUD-880).
///
/// A narrowing of [`Landing`], not a second computation of it. The full struct
/// carries per-commit patch identities and the evidence behind each one, which is
/// what a human diagnosing a landing needs and far more than a predicate does —
/// and putting it all on the policy input would make every landing rule depend on
/// a shape built for a different reader. Three fields answer every landing
/// question a gate has asked so far.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LandingFact {
    /// The verdict, rendered as its serialized token.
    pub verdict: String,
    /// Whether there is no unlanded content — [`Landing::is_landed`], which counts
    /// `NothingToLand` as landed because a branch with nothing to land is not
    /// outstanding work.
    pub landed: bool,
    /// The head-side commits with no proof on the target. Shas only: the subject
    /// belongs to [`RangeCommit`] and a body belongs nowhere on this input.
    pub unlanded: Vec<String>,
}

/// Acquire the DECLARED landing targets, skipping every one that cannot be
/// scanned (CLOUD-880).
///
/// **Absent rather than a negative**, and this is the sharpest instance of the
/// rule [`ref_facts`] and [`range_facts`] already follow. A target that does not
/// resolve, a repository with no commits, and two histories with no merge base all
/// leave the target out of the map — because the alternative is reporting
/// `landed: false`, which a gate reads as *this work is outstanding* with full
/// confidence. Of the two directions that is the one that acts on ignorance.
///
/// The head side is `HEAD`, deliberately not a parameter: a rule asks whether THIS
/// checkout's work is on a target, and a fact that could be pointed at an
/// arbitrary head would let config ask a question about somebody else's branch.
///
/// # Errors
///
/// Raises only when `git` cannot be run at all. Every per-target failure is
/// absence, which is the whole point above.
pub fn landing_facts(dir: &Path, declared: &[String]) -> Result<BTreeMap<String, LandingFact>> {
    let mut facts = BTreeMap::new();
    for target in declared {
        // `landing` raises a UsageError for an unresolvable endpoint or an
        // unrelated history. That is the right shape for a CLI verb, whose caller
        // asked about one target and wants to be told it could not be read — and
        // the wrong shape here, where one bad declaration must not take the whole
        // fact set down with it.
        let Ok(scan) = landing(dir, target, "HEAD", Window::DEFAULT) else {
            continue;
        };
        let Ok(verdict) = serde_json::to_value(scan.verdict) else {
            continue;
        };
        // The verdict serializes as a string; anything else means the enum grew a
        // payload, and guessing a rendering for it would put a shape on the policy
        // input that no schema describes.
        let Some(verdict) = verdict.as_str().map(ToOwned::to_owned) else {
            continue;
        };
        facts.insert(
            target.clone(),
            LandingFact {
                verdict,
                landed: scan.is_landed(),
                unlanded: scan.unlanded().into_iter().map(ToOwned::to_owned).collect(),
            },
        );
    }
    Ok(facts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    /// THE WINDOWS REGRESSION, TESTED AS A DECISION RATHER THAN A CONDITION.
    ///
    /// The failing condition — `canonicalize` returning a verbatim path — is one
    /// this sandbox structurally cannot produce, so asserting over a real
    /// `repo_root` here would assert its own premise and pass for the wrong
    /// reason (`.claude/rules/rust.md`, CLOUD-249). The decision is `plain`, and
    /// it takes a literal, so it is testable on every platform.
    ///
    /// Fails by: making `plain` the identity, which is what the tree carried when
    /// CI went red on Windows and green on the other three.
    #[test]
    fn a_canonicalised_root_is_comparable_with_an_absolute_path() {
        assert_eq!(
            plain(PathBuf::from(r"\\?\D:\a\batten\batten")),
            PathBuf::from(r"D:\a\batten\batten"),
            "a verbatim root never shares a prefix with `std::path::absolute`, \
             so every path reads as outside the repository"
        );
        // A UNC verbatim path keeps its prefix: the plain spelling resolves
        // differently, so rewriting it would trade a comparison bug for a worse
        // one.
        let unc = PathBuf::from(r"\\?\UNC\server\share\repo");
        assert_eq!(plain(unc.clone()), unc);
        // And the identity everywhere else, including the platform this runs on.
        let ordinary = PathBuf::from("/home/user/batten");
        assert_eq!(plain(ordinary.clone()), ordinary);
    }

    /// A fresh scratch directory under the system temp dir. Unit tests cannot
    /// use `CARGO_TARGET_TMPDIR` (integration-only), and the wipe clears a
    /// crashed prior run.
    ///
    /// **The process id is what keeps two RUNS apart, and the test name only
    /// keeps two tests apart** (CLOUD-717). This used to be the name alone, and
    /// its comment claimed "per-test names keep parallel tests apart" — true of
    /// parallel tests inside one binary, false of parallel `cargo test`
    /// processes, which both execute `a_snapshot_captures_a_dirty_tree_and_
    /// nothing_else` and both resolve one path. Whichever reached
    /// `remove_dir_all` second deleted the `.git` the first had just created,
    /// and the red that produced points into production code with no hint that
    /// another process is the cause. Measured twice on 2026-08-19, from both
    /// sides of one collision, when the hk gate's `test:cargo` overlapped an
    /// author's own run.
    ///
    /// `journal.rs` and `findings.rs` already build their scratch names this
    /// way; this adopts their spelling rather than inventing a second.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("batten-git-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn two_test_processes_do_not_share_one_fixture_directory() {
        // CLOUD-717's premise, shown able to fail: a case pinning only that one
        // derivation is stable passes against the defect unchanged, because the
        // defect WAS stable — stably the same path in every process. What has to
        // hold is that the process is in the name, so two runs cannot collide.
        let here = scratch("collision-probe");
        let leaf = here
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a scratch leaf");
        assert!(
            leaf.starts_with("collision-probe-"),
            "the test name still leads the leaf, so a human can find it: {leaf}"
        );
        assert_eq!(
            leaf,
            format!("collision-probe-{}", std::process::id()),
            "the process id is the half that separates two concurrent runs"
        );
        // And it is still stable within one process, or every call would mint a
        // new directory and a fixture built across two calls would vanish.
        assert_eq!(here, scratch("collision-probe"));
    }

    /// Run git in `dir`, hermetically: no global or system config (a dev
    /// machine's `commit.gpgsign` or `core.hooksPath` must not break a
    /// fixture) and the same discovery scrub the resolver applies.
    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: fixtures are built by the reference implementation on purpose — building them with gix would test this module's backend against itself"
    )]
    fn git(dir: &Path, args: &[&str]) {
        let mut command = std::process::Command::new("git");
        command
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.email=t@t", "-c", "user.name=t"])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null");
        // The discovery scrub, inlined now that the module carries no constants
        // for it: `open`'s isolated handle declines the environment structurally,
        // so the only place a NAMED list is still needed is here, where a real
        // `git` process is deliberately being built.
        for var in [
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        ] {
            command.env_remove(var);
        }
        let output = command.output().expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Compare directories after canonicalizing both sides: the system temp
    /// dir may sit behind a symlink (macOS `/tmp`), and git reports resolved
    /// paths.
    fn assert_same_dir(actual: &Path, expected: &Path) {
        assert_eq!(
            fs::canonicalize(actual).unwrap(),
            fs::canonicalize(expected).unwrap()
        );
    }

    #[test]
    fn a_repo_local_config_write_replaces_an_existing_value() {
        // The one write primitive in this module, and it had no round-trip case
        // before CLOUD-740 moved it in process. `attribution identity` is its
        // caller, so a write that silently fails to REPLACE leaves a denied
        // committer in place while reporting success.
        let repo = scratch("config-write");
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "--local", "user.name", "Vendorbot"]);

        set_config_local(&repo, "user.name", "Accountable Human").expect("write the local value");
        assert_eq!(
            config_value(&repo, "user.name")
                .expect("read it back")
                .as_deref(),
            Some("Accountable Human"),
            "an existing value must be REPLACED, not shadowed or appended"
        );

        // And a subsectioned key, which is the other shape callers use.
        set_config_local(&repo, "remote.origin.url", "https://example.test/x")
            .expect("write a subsectioned value");
        assert_eq!(
            config_value(&repo, "remote.origin.url")
                .expect("read it back")
                .as_deref(),
            Some("https://example.test/x")
        );
    }

    #[test]
    fn resolves_the_root_from_a_nested_subdirectory() {
        let repo = scratch("nested");
        git(&repo, &["init", "-q"]);
        let sub = repo.join("sub").join("dir");
        fs::create_dir_all(&sub).unwrap();
        let root = repo_root(&sub).expect("resolve from a nested subdirectory");
        assert!(root.is_absolute(), "the root must come back absolute");
        assert_same_dir(&root, &repo);
        // The root itself resolves to itself.
        assert_same_dir(&repo_root(&repo).expect("resolve at the root"), &repo);
    }

    #[test]
    fn a_linked_worktree_resolves_to_the_main_repository_root() {
        let repo = scratch("worktree");
        git(&repo, &["init", "-q"]);
        git(
            &repo,
            &["commit", "-q", "--allow-empty", "-m", "chore: init"],
        );
        // The worktree lives *inside* the main working tree, mirroring the
        // `.claude/worktrees/` layout this primitive exists to get right.
        let worktree = repo.join("wt").join("agent");
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                worktree.to_str().unwrap(),
                "HEAD",
            ],
        );
        let nested = worktree.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let root = repo_root(&nested).expect("resolve from inside a linked worktree");
        // The main root, via the shared common dir — never the worktree's own
        // toplevel, so state and config stay stable across worktrees.
        assert_same_dir(&root, &repo);
    }

    #[test]
    fn an_option_shaped_ref_name_is_not_parsed_as_an_option() {
        // `resolve_ref`'s `name` reaches it from config (`must_land_on`), which a
        // branch can edit when no `--config-from` is in play. Without
        // `--end-of-options` git parses an option-shaped name AS AN OPTION —
        // measured: `--local-env-vars` printed environment variable names rather
        // than being read as a rev.
        //
        // That was latent rather than live, and the case says so by asserting the
        // property that makes it latent as well as the token that closes it:
        // `--verify` exits non-zero for anything that is not a single rev, and
        // `query_optional` reads non-zero as `None`. Both halves are pinned, so
        // dropping the token alone does not make this go red — losing the `None`
        // reading does, and that is the one that would actually hurt.
        let repo = show_fixture("resolve-ref-option", "tracked.txt", b"x\n");
        for name in ["--local-env-vars", "--git-dir", "--all", "--show-toplevel"] {
            assert_eq!(
                resolve_ref(&repo, name).unwrap(),
                None,
                "an option-shaped ref resolves to nothing, never to an option's output"
            );
        }
        // And an ordinary ref still resolves, so the token did not break the
        // read it protects.
        let head = head_commit(&repo).unwrap();
        assert_eq!(resolve_ref(&repo, "HEAD").unwrap().as_deref(), Some(&*head));
    }

    #[test]
    fn a_path_outside_any_repository_is_a_usage_error() {
        // Rests on nothing above the system temp dir being a repository — the
        // same assumption every bats fixture makes.
        let dir = scratch("outside");
        let err = repo_root(&dir).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "outside a repository is bad input, not an internal failure"
        );
        let err = repo_root(&dir.join("does-not-exist")).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a missing path is bad input, not an internal failure"
        );
    }

    #[test]
    fn a_bare_repository_is_a_usage_error() {
        let dir = scratch("bare");
        git(&dir, &["init", "-q", "--bare"]);
        let err = repo_root(&dir).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a bare repository has no working tree to root"
        );
    }

    #[test]
    fn a_separate_git_dir_layout_is_refused_not_mis_rooted() {
        let base = scratch("separate");
        let tree = base.join("tree");
        fs::create_dir_all(&tree).unwrap();
        git(
            &tree,
            &[
                "init",
                "-q",
                "--separate-git-dir",
                base.join("gitdir").to_str().unwrap(),
            ],
        );
        let err = repo_root(&tree).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a common dir that is not `<root>/.git` must refuse, not mis-root"
        );
    }

    #[test]
    fn no_second_repo_root_resolver_exists() {
        // The single-implementation assertion (CLOUD-34), in the spirit of
        // state.rs's no-baked-literal grep test: the crate contains exactly
        // one repo-root resolver — this module. Shell launcher preambles under
        // mise-tasks/ are process bootstrap owned elsewhere, not the library
        // primitive, so the scan covers the crate's Rust sources only.
        //
        // What is forbidden is *root resolution*, not git access: a module may
        // ask git for a SHA or the git dir (receipt.rs does), and collapsing
        // those onto shared primitives is CLOUD-36's charter. The tokens below
        // are the ways a second root finder gets written — `--show-toplevel`
        // above all, which answers with a linked worktree's own toplevel and
        // is the divergence this issue exists to eliminate.
        //
        // Two predicates with different scopes:
        // - the resolver tokens are forbidden in src/*.rs outside this file
        //   (tests/*.rs may spawn git to build fixtures; a fixture is not a
        //   resolver);
        // - the resolver is defined exactly once across src AND tests (a
        //   test-helper reimplementation is still a second implementation).
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        // Built by concatenation so this test's own source does not count as
        // a definition (the same trick state.rs plays with its baked literal).
        let needle = ["fn repo", "_root"].concat();
        let forbidden = [
            "show-toplevel",
            "show-cdup",
            "git-common-dir",
            "git_common_dir",
            "git2::",
            "gix::",
        ];
        let mut definitions = 0;
        for (dir, scan_tokens) in [("src", true), ("tests", false)] {
            for entry in fs::read_dir(manifest.join(dir)).unwrap() {
                let path = entry.unwrap().path();
                if path.extension() != Some(OsStr::new("rs")) {
                    continue;
                }
                let source = fs::read_to_string(&path).unwrap();
                definitions += source.matches(needle.as_str()).count();
                if !scan_tokens || path.file_name() == Some(OsStr::new("git.rs")) {
                    continue;
                }
                for token in forbidden {
                    assert!(
                        !source.contains(token),
                        "{}: contains {token:?}; repo-root resolution lives only in git.rs — \
                         call git::repo_root instead (CLOUD-34)",
                        path.display()
                    );
                }
            }
        }
        assert_eq!(
            definitions, 1,
            "exactly one repo_root implementation may exist (git.rs)"
        );
    }

    /// Read every `src/*.rs`, optionally skipping this module.
    fn crate_sources(skip_self: bool) -> Vec<(PathBuf, String)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        for entry in fs::read_dir(src).unwrap() {
            let path = entry.unwrap().path();
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }
            if skip_self && path.file_name() == Some(OsStr::new("git.rs")) {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            sources.push((path, source));
        }
        // `read_dir` order is filesystem-defined; a gate's failure message must
        // not depend on it.
        sources.sort_by(|a, b| a.0.cmp(&b.0));
        sources
    }

    // `no_ancestry_decides_merged_ness` MOVED HERE (CLOUD-756), and the property
    // it held is now `policy/ancestry-decides-nothing.rego` — a registered Rego
    // module over `Fact::Invocations`, deleted from this file in the same change
    // so the rule is never held twice and never by nobody.
    //
    // The migration is a fidelity UPGRADE rather than a relocation: the scan
    // matched the token anywhere in a source file, and fired four times on prose
    // in one session — a doc comment describing the gate, and three comments
    // naming an example. Each was "fixed" by rewording English until the scanner
    // stopped noticing, which is the tell that the instrument was wrong. The
    // module reads command position, so a comment is not a decision. The
    // `.concat()` needle obfuscation this file still uses elsewhere exists only
    // because a substring scan is its own corpus; the module needs none.
    //
    // What the module does NOT see, stated so the trade is not silent: a literal
    // bound to a variable before it is passed. The scan's own text already
    // conceded smuggling — "hand-writing a graph walk, which is a different and
    // far more visible change" — so this narrows an evasion rather than opening
    // one.

    /// A repository carrying one committed file, for the `show` cases below.
    fn show_fixture(name: &str, path: &str, contents: &[u8]) -> PathBuf {
        let repo = scratch(name);
        git(&repo, &["init", "-q"]);
        fs::write(repo.join(path), contents).unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "fixture"]);
        repo
    }

    #[test]
    fn an_option_shaped_reference_reads_nothing_and_writes_nothing() {
        // CLOUD-718's measurement, inverted into a gate. As a shell-out this
        // spelled `git show --output=<path>:batten.toml`, which git read as its
        // own `--output` flag: exit 0, empty stdout, and the file CREATED. The
        // caller is `--config-from`, which is `global: true` and reaches every
        // `read`-effect verb, so this wrote a caller-chosen path from inside the
        // derived read-only allowlist.
        let repo = show_fixture("show-injection", "batten.toml", b"version = 1\n");
        let reference = format!("--output={}", repo.join("pwned.toml").display());

        let before = listing(&repo);
        let err = show(&repo, &reference, "batten.toml").unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a ref this binary cannot honour is bad input, not an internal failure"
        );

        // The companion assertion is a directory listing, not a judgement: the
        // defect was a WRITE, so the test that matters asks the filesystem.
        //
        // It compares the WHOLE listing rather than probing one expected name,
        // and that is the difference between a gate and a false green. The old
        // shell-out formatted `{reference}:{path}` into a single token, so the
        // file git created was `pwned.toml:batten.toml` — a probe for
        // `pwned.toml` passes against the very defect this pins. Measured on the
        // old shape, 2026-08-20: rc=0, empty stdout, one new directory entry.
        assert_eq!(
            listing(&repo),
            before,
            "a read-effect call must leave the tree byte-identical"
        );
    }

    /// Every entry in `dir`, sorted — the filesystem's own answer to "did
    /// anything appear", with no guess about what it would have been called.
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read the fixture directory")
            .map(|entry| entry.expect("a directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_two_unreadable_states_are_distinct() {
        // CLOUD-720 builds last-known-good on this distinction, so it is pinned
        // here rather than promised: an unresolvable ref and a resolvable ref
        // carrying no such path must not produce the same error value. The
        // shelled-out form emitted one message for both, deliberately, because
        // git's own stderr told them apart only in version-dependent prose.
        let repo = show_fixture("show-two-states", "batten.toml", b"version = 1\n");

        let no_ref = show(&repo, "refs/heads/does-not-exist", "batten.toml")
            .unwrap_err()
            .to_string();
        let no_path = show(&repo, "HEAD", "absent.toml").unwrap_err().to_string();

        assert_ne!(
            no_ref, no_path,
            "the two states must be separable by the caller"
        );

        // Differing strings are NOT the property — the old shell-out emitted one
        // template for both states and interpolated the caller's own ref and
        // path into it, so the two rendered differently while saying the same
        // undecidable thing ("no such ref, or the path is absent there"). A test
        // asserting only inequality passes against that. What has to hold is
        // that each message commits to ONE state: an unresolvable ref is not
        // discussed in terms of the path, which is not the problem and may be
        // perfectly present.
        assert!(
            no_ref.contains("does-not-exist"),
            "the refusal names the ref: {no_ref}"
        );
        assert!(
            !no_ref.contains("batten.toml"),
            "an unresolvable ref must not hedge about the path: {no_ref}"
        );
        assert!(
            no_path.contains("absent.toml") && no_path.contains("HEAD"),
            "the refusal names the path and the ref it looked at: {no_path}"
        );

        // And the property CLOUD-720 actually consumes: the states are values,
        // not two spellings of one error. A message a caller has to string-match
        // is the distinction surviving for a human reading stderr and being
        // destroyed for the code that has to branch on it.
        assert!(
            matches!(
                read_at(&repo, "refs/heads/does-not-exist", "batten.toml").unwrap(),
                BaseBlob::RefUnreachable { ref reference } if reference == "refs/heads/does-not-exist"
            ),
            "an unresolvable ref is `RefUnreachable`, carrying the ref it could not resolve"
        );
        assert!(
            matches!(
                read_at(&repo, "HEAD", "absent.toml").unwrap(),
                BaseBlob::AbsentAtRef { ref path, .. } if path == "absent.toml"
            ),
            "a resolvable ref with no such path is `AbsentAtRef`, carrying the path"
        );
        let found = read_at(&repo, "HEAD", "batten.toml").unwrap();
        let BaseBlob::Found { text, commit } = found else {
            panic!("a readable file at a resolvable ref is `Found`");
        };
        assert_eq!(text, "version = 1\n");
        assert_eq!(
            commit.len(),
            40,
            "`Found` carries the resolved commit, which is a pin's evidence: {commit}"
        );
        assert!(
            !no_path.contains("resolve"),
            "an absent path must not hedge about the ref, which resolved: {no_path}"
        );
        // And the ordinary read still works, or the two refusals above prove
        // only that everything fails.
        assert_eq!(show(&repo, "HEAD", "batten.toml").unwrap(), "version = 1\n");
    }

    #[test]
    fn a_directory_at_the_ref_is_refused_rather_than_listed() {
        // `git show <ref>:<dir>` prints a TREE LISTING. Unreachable through
        // `config::CONFIG_FILE`, reachable through `[epoch] tracked`, where the
        // listing would have been hashed as though it were the file's content —
        // a stable epoch over a surface nobody had read.
        let repo = show_fixture("show-tree", "batten.toml", b"version = 1\n");
        fs::create_dir_all(repo.join("nested")).unwrap();
        fs::write(repo.join("nested/inner.toml"), "version = 1\n").unwrap();
        git(&repo, &["add", "-A"]);
        git(&repo, &["commit", "-q", "-m", "a directory"]);

        let err = show(&repo, "HEAD", "nested").unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        let text = err.to_string();
        assert!(
            !text.contains("inner.toml"),
            "a refusal must not render the listing it refused: {text}"
        );
        // The file inside it still reads, so the refusal is about the KIND of
        // object and not about the path being unreachable.
        assert_eq!(
            show(&repo, "HEAD", "nested/inner.toml").unwrap(),
            "version = 1\n"
        );
    }

    #[test]
    fn non_utf8_content_at_the_ref_is_a_usage_error() {
        // §7 routes unreadable *config* to exit 1; this was the internal 3,
        // which a harness reads as "batten broke" rather than "your config is
        // not readable". `epoch.rs` already cites this function as the
        // precedent for the 1, so the code and the citation now agree.
        let repo = show_fixture("show-non-utf8", "batten.toml", &[0xff, 0xfe, 0x00, 0x9f]);
        let err = show(&repo, "HEAD", "batten.toml").unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "unreadable config is exit 1, never the internal 3"
        );
        let text = err.to_string();
        assert!(
            !text.contains('\u{fffd}'),
            "a refusal is a pointer, never the bytes it could not decode: {text}"
        );
    }

    #[test]
    fn gix_is_confined_to_this_module() {
        // The successor to `show`'s `--end-of-options` assertion, which the
        // Ready block asked for and which this change makes unspellable: there
        // is no argv left to carry the token. What replaces it is the boundary
        // that matters while `git.rs` is mid-migration (CLOUD-320's row) — two
        // git backends coexist here ON PURPOSE and in ONE module, so the
        // in-process half cannot spread across the crate without deleting the
        // assertion that says it may not.
        for (path, source) in crate_sources(true) {
            if path.file_name().and_then(|n| n.to_str()) == Some("git.rs") {
                continue;
            }
            assert!(
                !source.contains("gix::"),
                "{}: reaches gix directly; the in-process git backend is git.rs's \
                 alone until CLOUD-320's migration finishes (CLOUD-718)",
                path.display()
            );
        }
    }

    #[test]
    fn no_gix_gap_primitive_survives() {
        // CLOUD-780's rule, shipped with its mechanism. Two primitives used to
        // live here for one reason — a concept the in-process backend has no
        // API for — and the standing strategy retired them rather than keep a
        // spawn path nothing could ever replace. What that buys is a property
        // about the whole module (the doc above states it): every remaining
        // spawn is *unported*, never *unportable*. Reinstating one of the two
        // silently would take the property back, and nothing else would notice.
        //
        // Scope is `src/` and includes THIS file, for `no_ancestry_decides_
        // merged_ness`'s reason: the decision lives here, so exempting the
        // decision's home would gut the gate. Tokens are assembled by
        // concatenation so this test's own source is not a match — which is
        // also why the doc above points at the issue for what was dropped
        // instead of re-typing the vocabulary it forbids.
        let forbidden = [
            ["sta", "sh"].concat(),
            ["prun", "able"].concat(),
            ["worktree", "_remove"].concat(),
        ];
        for (path, source) in crate_sources(false) {
            for token in &forbidden {
                assert!(
                    !source.contains(token.as_str()),
                    "{}: names {token:?}; that vocabulary retired with the primitives \
                     built on it, and re-deriving either would put a spawn back that \
                     exists only because gix has no equivalent (CLOUD-780)",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn no_second_git_invoker_exists() {
        // THE TERMINAL ASSERTION (CLOUD-740). This forbade a git spawn OUTSIDE
        // this module, so that the discovery scrub, the pinned diff config and
        // the usage-vs-internal split were decided in one place. There is now no
        // such place to protect: nothing in the crate spawns `git` at all, and
        // the claim is strictly stronger and much simpler for it.
        //
        // `crate_sources(false)` is the change that makes it terminal — the
        // argument selects whether THIS module is exempt, and the whole point is
        // that it no longer is. It was `true` while `git.rs` held the one
        // invoker.
        //
        // SHOWN ABLE TO FAIL (CLOUD-418) by reintroducing a spawn anywhere under
        // `src/`, including here.
        //
        // Precise by construction: rules.rs and hook.rs spawn *user-configured*
        // programs through a variable program name and are untouched by this —
        // what is forbidden is naming `git` as a literal program.
        //
        // SCANNED UP TO `#[cfg(test)]` AND NO FURTHER, which is a real limit and
        // not a convenience. The test module below builds its fixtures with a
        // real `git` on purpose — building them with gix would test this module's
        // backend against itself, so the reference implementation is the only
        // honest fixture builder — and that helper carries its own `#[expect]`
        // saying so. The claim being made is about what the SHIPPED crate does,
        // and truncating here states that scope instead of quietly assembling the
        // needle to dodge a match, which would make the gate lie about its reach.
        let needle = ["Command::new(\"", "git\")"].concat();
        for (path, source) in crate_sources(false) {
            let source = source
                .split_once("\n#[cfg(test)]\n")
                .map_or(source.as_str(), |(shipped, _)| shipped);
            assert!(
                !source.contains(needle.as_str()),
                "{}: spawns `git`. Nothing in this crate does any more (CLOUD-740) — ask gix \
                 through `open`, whose isolated handle declines the ambient environment \
                 structurally rather than by scrubbing a list of variable names",
                path.display()
            );
        }
    }

    #[test]
    fn every_stays_shelled_out_claim_names_its_price() {
        // CLOUD-320's THIRD ACCEPTANCE CLAUSE, made runnable: "where a verdict is
        // 'stays' for a reason that is a cost rather than a constraint, it says
        // so in those words." Prose until now, and unmet in the one file §1 names
        // as its durable home — invisibly, for a day, in the file every reader of
        // this module starts from.
        //
        // What that cost: the doc recorded only the capability half — the two
        // concepts CLOUD-780 retired, which gix has no equivalent for — so a
        // session read it, concluded the split was
        // permanent, and wrote that into CLOUD-742 and a milestone. A false
        // constraint reads exactly like a true one, which is why this is a gate
        // and not a convention.
        //
        // The predicate is deliberately narrow — a claim that a spawn STAYS must
        // appear alongside the issue that owns its price. It cannot check that
        // the reason given is true; it can check that a reason with an owner is
        // present, which is the failure that actually happened.
        let doc: String = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("git.rs"),
        )
        .unwrap()
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
        // CONDITIONAL ON THERE BEING A SPAWN TO PRICE (CLOUD-740, resolution 3),
        // in the same commit as the terminal assertion above because the two are
        // one decision. This gate and that one contradicted each other outright:
        // this demanded the doc keep naming a spawn that stays, and that one
        // requires none to remain. Deleting this gate was the cheap answer and a
        // lossy one — it exists because a session read the module doc, concluded
        // the split was permanent, and wrote that into an issue and a milestone,
        // and a false constraint reads exactly like a true one.
        //
        // So the SUBJECT narrows rather than the predicate: *if* the doc claims a
        // spawn stays, it must name `git2` and the rows that own the price.
        // Vacuously true now, live again the day anything here spawns — which is
        // the resolution that survives the migration instead of being spent by
        // it.
        if !doc.contains("Still spawning") {
            return;
        }
        for owner in ["CLOUD-737", "CLOUD-585"] {
            assert!(
                doc.contains(owner),
                "the module doc explains which half of this module spawns, but not what that \
                 costs or who re-decides it: name {owner} beside the claim, so a reader learns \
                 the split is priced rather than fixed (CLOUD-320)"
            );
        }
        assert!(
            doc.contains("git2"),
            "the module doc must name `git2` as capable-but-barred rather than leaving a reader \
             to infer no library can do this — that inference is the defect CLOUD-320's own \
             correction of 2026-08-19 records (CLOUD-320)"
        );
    }

    #[test]
    fn no_module_assembles_its_own_git_argv() {
        // The gate that ships with CLOUD-742's rule: every git question the
        // crate asks has a NAME, so the argv and the parse that undoes its
        // output are one decision in one place. Sixteen call sites outside this
        // module used to hold both halves — `attribution.rs` split four fields
        // with `unwrap_or_default()`, which turned a short record into an
        // answer on the module that decides commit attribution.
        //
        // Belt to the suspenders `query`/`query_bytes`/`query_optional` being
        // private already provides: a nineteenth ad-hoc caller inside this
        // crate is a compile error rather than a failing test —
        // unrepresentable beats refused — and this states the rule in words
        // for whoever proposes re-widening them.
        //
        // The removal is `function_missing` to `semver`, so the commit that
        // makes it declares the break. That costs the release nothing here:
        // below 0.1.0 every type collapses to a patch, `!` included, which is
        // the bump this row was priced at.
        //
        // `::`-PREFIXED, and that is load-bearing: `defects.rs` has a
        // `run_defects_query(` that shares the spelling and is not a git call —
        // the two-programs-one-spelling trap CLOUD-757 records for `Command`.
        // Assembled by concatenation so this assertion's own source is not a
        // match for the gate it states.
        let forbidden = [
            ["::que", "ry("].concat(),
            ["::que", "ry_bytes("].concat(),
            ["::que", "ry_optional("].concat(),
        ];
        for (path, source) in crate_sources(true) {
            for token in &forbidden {
                assert!(
                    !source.contains(token.as_str()),
                    "{}: assembles its own git argv; give the question a name in git.rs and \
                     return a typed answer, so the parse lives beside the format string it \
                     reverses (CLOUD-742)",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn a_patch_id_is_hex_of_a_hash_length() {
        // CLOUD-739 §7(c). The refusal is the point and is unchanged: a parsing
        // slip must never manufacture an equality between two truncated or
        // non-hex ids. What changed is the WIDTH it accepts.
        assert!(PatchId::parse(&"0".repeat(64)).is_ok());

        // FORTY IS NOW REFUSED, and that is the migration rather than a
        // regression. The old rule accepted 40 or 64 because it was parsing
        // whatever `git patch-id` printed, and that followed the REPOSITORY's
        // hash — SHA-1 or SHA-256. The identity is now a SHA-256 over this
        // crate's own canonical form (CLOUD-739), so the width is fixed by
        // construction and a 40-hex value arriving here is a defect, not a
        // SHA-1 repository.
        assert!(
            PatchId::parse(&"a".repeat(40)).is_err(),
            "the width follows our own hash now, never the repository's"
        );

        assert!(PatchId::parse("").is_err());
        assert!(PatchId::parse(&"a".repeat(63)).is_err(), "truncated");
        assert!(PatchId::parse(&"a".repeat(65)).is_err(), "over-long");
        assert!(PatchId::parse(&"g".repeat(64)).is_err(), "non-hex");
        assert!(PatchId::parse(&"A".repeat(64)).is_err(), "lowercase only");
    }

    #[test]
    fn the_verdict_is_derived_from_evidence_alone() {
        let id = PatchId::parse(&"a".repeat(64)).unwrap();
        let landed = |evidence: Option<Evidence>| CommitLanding {
            commit: "c".repeat(40),
            patch_id: Some(id.clone()),
            evidence,
        };
        let proof = Evidence::PatchId {
            target_commit: "t".repeat(40),
            patch_id: id.clone(),
        };

        // An empty net change is settled before anything else: there is no
        // unlanded work, whatever the individual commits did.
        assert_eq!(verdict(&[], None, None), Verdict::NothingToLand);
        assert_eq!(
            verdict(&[landed(None)], None, None),
            Verdict::NothingToLand,
            "a change and its revert leave nothing to land"
        );

        assert_eq!(
            verdict(&[landed(Some(proof.clone()))], Some(&id), None),
            Verdict::Landed
        );
        assert_eq!(
            verdict(&[landed(None)], Some(&id), None),
            Verdict::NotLandedWithinWindow,
            "a negative names the window it searched, never a proven absence"
        );
        assert_eq!(
            verdict(
                &[landed(Some(proof.clone())), landed(None)],
                Some(&id),
                None
            ),
            Verdict::PartiallyLanded
        );
        // The squash path: no commit matched individually, but the branch's
        // whole change is on the target.
        let squash = Evidence::Squash {
            target_commit: "s".repeat(40),
            patch_id: id.clone(),
        };
        assert_eq!(
            verdict(&[landed(None), landed(None)], Some(&id), Some(&squash)),
            Verdict::Landed
        );
    }

    #[test]
    fn a_window_cannot_be_empty_and_defaults_generously() {
        // The asymmetry, pinned: too small a window is a false "not landed",
        // too large is a slower `git log`.
        assert_eq!(Window::DEFAULT.commits(), 1000);
        assert_eq!(Window::default(), Window::DEFAULT);
        assert_eq!(Window::of(NonZeroUsize::MIN).commits(), 1);
    }

    #[test]
    fn evidence_that_means_landed_always_names_a_target_commit() {
        // The structural half of "no verdict without proof": the only variant
        // that names nothing is the one that means nothing landed.
        let id = PatchId::parse(&"a".repeat(64)).unwrap();
        let target = "t".repeat(40);
        for evidence in [
            Evidence::PatchId {
                target_commit: target.clone(),
                patch_id: id.clone(),
            },
            Evidence::Squash {
                target_commit: target.clone(),
                patch_id: id,
            },
        ] {
            assert_eq!(evidence.target_commit(), Some(target.as_str()));
        }
        assert_eq!(Evidence::NoContent.target_commit(), None);
    }
}
