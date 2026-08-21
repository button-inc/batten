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
//! Resolution shells out to `git rev-parse` with the discovery environment
//! scrubbed: an ambient override — a hook context exporting `GIT_DIR`, say —
//! makes git answer for some *other* repository, which is the exact
//! mis-rooting bug class this module exists to kill. The answer is a function
//! of the (cwd-resolved) `start` argument and on-disk state only.
//!
//! Non-goals, refused loudly rather than answered wrongly: a bare repository,
//! a submodule interior (common dir `<super>/.git/modules/<path>`), and a
//! `--separate-git-dir` layout all raise a [`UsageError`], because deriving a
//! root as the common dir's parent is only sound when that directory is a
//! `<root>/.git`. If a consumer ever needs those layouts, the escalation path
//! is `git worktree list --porcelain`, not more `parent()` arithmetic.
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
//! **Still spawning, and every one of them has an open row that would move it.**
//! The remaining reads take fixed argv with no caller-supplied token, or sit in
//! `rev-parse`'s ref-PRINTING modes where the `--end-of-options` trap below
//! lives and no caller string reaches the command line anyway — so none of this
//! is urgent, and none of it is settled either. CLOUD-738 owns the ref and
//! object reads, and its deliverable is **deleting** that trap rather than
//! documenting it; CLOUD-739 owns `landing` and patch identity, and with them
//! the 26 settings pinned below purely to stop a host's `git config` moving the
//! answer; CLOUD-740 owns `uncommitted`, `changed_paths` and `check_ignore`, and
//! the terminal assertion that this crate spawns `git` nowhere.
//!
//! An earlier revision of this paragraph said *"migrating buys nothing an agent
//! can observe"* and called rewriting patch identity *"risk with no return"*. It
//! was written while all three of those rows sat cancelled, and a later session
//! read it here and restated it as fact. Both halves failed in the same
//! direction: CLOUD-739's own gate is a differential test against the
//! implementation it replaces, so that risk is **priced**, not absent.
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
//! [`landing`] compares **patch identity** — `git patch-id --stable` over each
//! change — and, for the squash case that per-commit identity cannot see, the
//! patch identity of the branch's cumulative diff.
//!
//! Reachability appears in exactly one role: *selecting* which commits to hash.
//! It never produces a verdict. Every [`Verdict::Landed`] is backed by an
//! [`Evidence`] naming the target commit whose patch identity matched, and the
//! type offers no way to spell a landed verdict while holding no evidence.
//! [`no_ancestry_decides_merged_ness`] is the source-level gate.
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
//! [`no_ancestry_decides_merged_ness`]: tests::no_ancestry_decides_merged_ness

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
#[expect(
    clippy::disallowed_types,
    reason = "stays: this module is two-backend BY DECISION (CLOUD-780) — gix where a library makes a defect unrepresentable, spawned `git` where it does not, and every remaining spawn is unported rather than unportable"
)]
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::error::UsageError;

/// Environment variables that point git at a *different* repository. Scrubbed
/// from every child this module spawns, so an ambient `GIT_DIR` — a hook
/// context, a wrapping git command — can never make a query answer about some
/// other checkout than the directory it was handed.
const DISCOVERY_REDIRECTS: [&str; 3] = ["GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE"];

/// Environment variables that *fence* git's upward search rather than
/// redirecting it. [`repo_root`] scrubs these too, because its answer must be a
/// function of `start` and the filesystem alone; a plain [`query`] leaves them
/// in place, since a caller that fenced discovery on purpose (a test pinning a
/// fixture inside a tmpdir) is relying on the fence to fail loudly.
const DISCOVERY_FENCES: [&str; 2] = ["GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM"];

/// Environment variables that change the bytes a diff produces. Scrubbed
/// alongside the discovery redirects, because a patch identity computed under
/// an ambient `GIT_EXTERNAL_DIFF` is not comparable with one computed without.
const DIFF_ENV: [&str; 2] = ["GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS"];

/// Config pinned on every patch-identity computation.
///
/// A patch identity is only comparable against another produced the same way,
/// so nothing that shapes the diff may be left to config. `-c` rather than
/// blanking `GIT_CONFIG_GLOBAL`, because the values that break comparability
/// can also live in the repository's own `.git/config`, which no environment
/// variable neutralises — and blanking global config would disturb credential
/// and transport settings that are none of this module's business.
///
/// `diff.renames` is the load-bearing one: it defaults to *true* for the
/// porcelain `git diff` used on the cumulative side and *false* for plumbing.
/// Unpinned, the two sides silently disagree about any commit that renames a
/// file, and a real landing goes unrecognised.
const DIFF_CONFIG: [&str; 20] = [
    "-c",
    "diff.renames=false",
    "-c",
    "diff.algorithm=myers",
    "-c",
    "diff.indentHeuristic=true",
    "-c",
    "diff.context=3",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.relative=false",
    "-c",
    "diff.ignoreSubmodules=none",
    "-c",
    "core.quotePath=true",
    "-c",
    "color.ui=false",
];

/// Diff flags pinned alongside [`DIFF_CONFIG`].
///
/// `--binary` is not an optimisation: without it a binary change renders as
/// `Binary files a/x and b/x differ` — identical text for *any* two changes to
/// the same path, so two unrelated binary edits would share a patch identity
/// and one would be reported as the other's landing. The cost is that a binary
/// patch body is zlib output, deterministic for a given zlib but not guaranteed
/// across zlib builds; a stability caveat is the right trade against a wrong
/// answer.
const DIFF_FLAGS: [&str; 6] = [
    "--no-ext-diff",
    "--no-textconv",
    "--no-color",
    "--no-renames",
    "-U3",
    "--binary",
];

/// A `git patch-id --stable` hash: the identity of a change's *content*,
/// independent of the commit that carries it.
///
/// Two commits with the same `PatchId` make the same change to the same paths,
/// whatever their SHA, author, message, date, or parents — which is precisely
/// what makes a rebased, amended, or cherry-picked commit recognisable after it
/// lands under a new SHA.
///
/// Not a content address: git's normalisation drops whitespace and hunk line
/// numbers, so a whitespace-only difference collides. That biases toward
/// reporting work as landed, which is the safe direction for a primitive whose
/// failure class is a false *not landed*.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PatchId(String);

impl PatchId {
    /// Parse one lowercase-hex id as `git patch-id` prints it — 40 hex digits
    /// in a SHA-1 repository, 64 in a SHA-256 one. Anything else is refused, so
    /// a parsing slip can never manufacture an equality.
    fn parse(text: &str) -> Result<Self> {
        let ok = matches!(text.len(), 40 | 64)
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            bail!("`git patch-id` printed {text:?}, which is not a patch identity")
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
    let mut command = command(start);
    command
        // Option order is load-bearing twice over: output lines mirror option
        // order, and `--path-format` applies only to the options after it (an
        // unqualified `--git-common-dir` prints a cwd-relative path).
        .args([
            "rev-parse",
            "--is-bare-repository",
            "--path-format=absolute",
            "--git-common-dir",
        ]);
    // The fences are scrubbed here and only here: this answer must be a
    // function of `start` and the filesystem, whereas a caller that fenced
    // discovery on purpose is relying on a plain `query` to fail loudly.
    for var in DISCOVERY_FENCES {
        command.env_remove(var);
    }
    let output = command
        .output()
        .context("run `git rev-parse` to locate the repository common dir")?;
    if !output.status.success() {
        // git's own stderr is version-dependent prose; the caller gets one
        // deterministic message instead.
        return Err(UsageError::raise(format!(
            "{} is not inside a git repository",
            start.display()
        )));
    }
    let stdout =
        String::from_utf8(output.stdout).context("decode `git rev-parse` output as UTF-8")?;
    // A repository path containing a newline would break line-based parsing;
    // `rev-parse` has no NUL-terminated mode for these options, so that
    // pathology is accepted rather than handled.
    let mut lines = stdout.lines();
    match lines.next() {
        Some("false") => {}
        Some("true") => {
            return Err(UsageError::raise(format!(
                "{} is inside a bare repository, which has no working tree to root",
                start.display()
            )));
        }
        _ => bail!("`git rev-parse --is-bare-repository` printed neither true nor false"),
    }
    let Some(common_dir) = lines.next().map(Path::new) else {
        bail!("`git rev-parse --git-common-dir` printed no path");
    };
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
    query(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        &format!("{} is not inside a git repository", dir.display()),
    )
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
    // No remotes configured. `--get-regexp` exits 1 for "no match", which is not
    // distinguishable here from a bad invocation — but the invocation is a fixed
    // literal, so "no match" is the only reachable cause.
    let Ok(listing) = query(
        dir,
        &["config", "--get-regexp", r"^remote\..*\.url$"],
        "read the configured remotes",
    ) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<(String, String)> = listing
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter_map(|(key, url)| {
            let name = key.strip_prefix("remote.")?.strip_suffix(".url")?;
            (!name.is_empty() && !url.is_empty()).then(|| (name.to_owned(), url.to_owned()))
        })
        .collect();
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
    let Ok(listing) = query(
        dir,
        &["rev-list", "--max-parents=0", "--all"],
        "list the repository root commits",
    ) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<String> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();
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
    gix::discover_opts(
        dir,
        gix::discover::upwards::Options::default(),
        gix::open::Options::isolated(),
    )
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
/// makes that a fact it inherits rather than a promise.
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
    if !dir.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let repository = open(dir)?;

    // State one: the revspec does not resolve here. Deliberately its own
    // message — gix's error is version-dependent prose in the same way git's
    // stderr was, so it never reaches the caller, but the DISTINCTION does.
    let resolved = repository
        .rev_parse_single(reference)
        .map_err(|_| UsageError::raise(format!("cannot resolve {reference} in this repository")))?;
    let tree = resolved
        .object()
        .map_err(|_| UsageError::raise(format!("cannot read the object {reference} names")))?
        .peel_to_tree()
        .map_err(|_| UsageError::raise(format!("cannot resolve {reference} to a tree")))?;

    // State two: the ref is good and the path is not there. A caller can act on
    // the difference — one is a mistyped or unfetched ref, the other a branch
    // from before the config landed.
    let entry = tree
        .lookup_entry_by_path(path)
        .map_err(|_| UsageError::raise(format!("cannot read {path} at {reference}")))?
        .ok_or_else(|| UsageError::raise(format!("{path} is absent at {reference}")))?;

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
    String::from_utf8(object.data.clone())
        .map_err(|_| UsageError::raise(format!("{path} at {reference} is not valid UTF-8")))
}

/// The `git` child every query in this module is built from: `-C dir`, with
/// the redirect variables scrubbed so the answer is about the directory it was
/// handed and not about whatever repository the ambient environment names.
#[expect(
    clippy::disallowed_types,
    reason = "stays: the ONE git invoker (`no_second_git_invoker_exists` keeps it one), taking fixed argv with no caller token, measured at 6.7ms of the 100ms mediated-call budget — so nothing measured asks it to move (CLOUD-770)"
)]
fn command(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir);
    for var in DISCOVERY_REDIRECTS {
        command.env_remove(var);
    }
    command
}

/// Run a fixed, read-only `git` query in `dir` and return its trimmed stdout.
///
/// The one git-plumbing entry point for the rest of the crate — `receipt.rs`
/// called a private copy of this before CLOUD-36 collapsed them, and
/// `no_second_git_invoker` is what keeps a third from appearing.
///
/// # Errors
///
/// A non-zero exit is the *expected* bad-checkout condition and raises a
/// [`UsageError`] (exit `1`) carrying `refusal` — git's own stderr is
/// version-dependent prose and never reaches the caller, so the message stays
/// deterministic. Failing to run `git` at all, or output that is not UTF-8, is
/// an internal error (exit `3`).
fn query(dir: &Path, args: &[&str], refusal: &str) -> Result<String> {
    let bytes = query_bytes(dir, args, refusal)?;
    let stdout = String::from_utf8(bytes).map_err(|_| {
        UsageError::raise(format!(
            "`git {}` output is not valid UTF-8",
            args.join(" ")
        ))
    })?;
    Ok(stdout.trim_end_matches(['\r', '\n']).to_owned())
}

/// [`query`] without the UTF-8 requirement, for output that may carry raw
/// pathnames or file content.
///
/// # Errors
///
/// As [`query`], minus the decoding failure.
fn query_bytes(dir: &Path, args: &[&str], refusal: &str) -> Result<Vec<u8>> {
    let output = command(dir)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("run `git {}`", args.join(" ")))?;
    if !output.status.success() {
        return Err(UsageError::raise(refusal));
    }
    Ok(output.stdout)
}

/// [`query`] for a question whose answer may legitimately be "there is none".
///
/// Returns `None` when git exits non-zero, rather than raising. Only for a query
/// where a non-zero exit *is* an answer — `@{upstream}` on a branch that has no
/// upstream is the case this exists for, and there is no ref-existence test that
/// does not itself have to be spelled as a failing lookup. A caller that would
/// treat an absent answer as a *pass* must not use this: absence of an upstream
/// is not safety (CLOUD-51), so the caller owes the absent case its own reading.
///
/// # Errors
///
/// Failing to run `git` at all, or output that is not UTF-8, is still an
/// internal error — only the *verdict* is optional, never the mechanism.
fn query_optional(dir: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = command(dir)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("run `git {}`", args.join(" ")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("decode `git {}` output as UTF-8", args.join(" ")))?;
    Ok(Some(stdout.trim_end_matches(['\r', '\n']).to_owned()))
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
    let status = query(
        dir,
        &["status", "--porcelain"],
        "cannot read the working tree status; this is not a git repository",
    )?;
    Ok(status.lines().filter(|line| !line.is_empty()).count())
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
    query_optional(
        dir,
        &["rev-parse", "--verify", "--quiet", "--end-of-options", name],
    )
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
    let mut changed = BTreeSet::new();
    for args in [
        &["diff", "--name-only", "-z", "--end-of-options", "HEAD"][..],
        &["ls-files", "--others", "--exclude-standard", "-z"][..],
    ] {
        let bytes = query_bytes(
            dir,
            args,
            "cannot read the changed paths; this is not a git repository, or it has no commits",
        )?;
        changed.extend(
            bytes
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
                .filter_map(|path| std::str::from_utf8(path).ok())
                .map(ToOwned::to_owned),
        );
    }
    Ok(changed)
}

/// The branch `HEAD` is on, or `None` on a detached `HEAD`.
///
/// # Errors
///
/// Raises a [`UsageError`] (exit `1`) when `dir` is not inside a repository.
pub fn current_branch(dir: &Path) -> Result<Option<String>> {
    let name = query(
        dir,
        &["rev-parse", "--abbrev-ref", "HEAD"],
        "cannot resolve HEAD; this is not a git repository, or it has no commits",
    )?;
    // git spells a detached HEAD as the literal `HEAD`, which is not a branch
    // name; reporting it as one would name a branch that does not exist.
    Ok((name != "HEAD").then_some(name))
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
    let answer = query_optional(dir, &["rev-parse", "--is-shallow-repository"])?;
    Ok(answer.is_none_or(|answer| answer.trim() != "false"))
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
    let range = format!("{base}..HEAD");
    query_optional(
        dir,
        &["log", "--format=%B", "--end-of-options", &range, "--"],
    )
}

/// The field separator [`commit_record`] joins its four fields with.
///
/// U+001E RECORD SEPARATOR: a control character no identity, trailer or subject
/// carries in practice — and, crucially, one whose *presence* in a body is now
/// an error rather than a silent mis-split (CLOUD-742).
const RECORD_SEPARATOR: &str = "\u{1e}";

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
    let format = format!(
        "%an <%ae>{RECORD_SEPARATOR}%cn <%ce>{RECORD_SEPARATOR}%(trailers:only,unfold)\
         {RECORD_SEPARATOR}%B"
    );
    let shown = query(
        dir,
        &[
            "show",
            "-s",
            &format!("--format={format}"),
            "--end-of-options",
            commit,
        ],
        "could not read a commit in the range",
    )?;
    record_from(&shown, commit)
}

/// The destructure [`commit_record`] performs, separated from the invocation
/// that produces its input.
///
/// Its own function because the failing condition is a *record shape* and not a
/// repository state: a caller cannot easily make `git show` emit a short record
/// on demand, so the decision is extracted and tested directly rather than
/// through a fixture that asserts its own premise (`.claude/rules/rust.md`,
/// CLOUD-249).
fn record_from(shown: &str, commit: &str) -> Result<CommitRecord> {
    let mut parts = shown.splitn(4, RECORD_SEPARATOR);
    let (Some(author), Some(committer), Some(trailers), Some(body)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(UsageError::raise(format!(
            "the record for {} does not carry four fields, so its attribution cannot be read",
            short(commit)
        )));
    };
    Ok(CommitRecord {
        author: author.to_owned(),
        committer: committer.to_owned(),
        trailers: trailer_lines(trailers),
        body: body.to_owned(),
    })
}

/// Split a trailer block into whole `Key: value` lines, dropping blanks.
///
/// `pub(crate)` rather than private because `attribution.rs` reads a *pending*
/// message's trailers through the same shape and asserts this splitting
/// directly; one implementation, so a committed record and a pending one cannot
/// disagree about what a trailer line is.
pub(crate) fn trailer_lines(block: &str) -> Vec<String> {
    block
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// A commit's short form, as every pointer in this repository renders it.
fn short(commit: &str) -> String {
    commit.chars().take(8).collect()
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
    let range = format!("{base}..{head}");
    let listed = query(
        dir,
        &["rev-list", "--no-merges", "--end-of-options", &range, "--"],
        "could not resolve the commit range",
    )?;
    Ok(listed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect())
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
    let path = message.to_string_lossy().into_owned();
    let parsed = query(
        dir,
        &["interpret-trailers", "--parse", "--", &path],
        "could not parse the pending message's trailers",
    )?;
    Ok(trailer_lines(&parsed))
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
    query_optional(dir, &["config", "--get", "--end-of-options", key])
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
    query(
        dir,
        &["config", "--local", "--end-of-options", key, value],
        "could not write the repo-local config value",
    )?;
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
    // No `--end-of-options`: `git var` does not accept the token — it takes
    // `-l` or exactly one variable name — and it does not need it, because the
    // two names this is ever called with are literals in this crate rather than
    // anything a caller supplies.
    let raw = query(
        dir,
        &["var", var],
        "could not resolve the identity git would stamp",
    )?;
    Ok(raw
        .rfind('>')
        .map_or_else(|| raw.trim().to_owned(), |end| raw[..=end].to_owned()))
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
    let printed = query(
        dir,
        &["rev-parse", "--absolute-git-dir"],
        "not a git repository, so there is no git directory to resolve",
    )?;
    Ok(PathBuf::from(printed.trim()))
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
    let printed = query(
        dir,
        &["rev-list", "--count", "--end-of-options", range, "--"],
        "the commit range cannot be counted",
    )?;
    printed.trim().parse().map_err(|_| {
        UsageError::raise("`git rev-list --count` did not answer with a number".to_owned())
    })
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
    let range = format!("{base}..{head}");
    let listed = query(
        dir,
        &[
            "log",
            "--no-merges",
            "--format=%H %s",
            "--end-of-options",
            &range,
            "--",
        ],
        "could not resolve the commit range",
    )?;
    listed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (commit, subject) = line.split_once(' ').ok_or_else(|| {
                UsageError::raise(
                    "a commit line carries no subject field, so the range cannot be read",
                )
            })?;
            Ok(CommitSubject {
                commit: commit.to_owned(),
                subject: subject.to_owned(),
            })
        })
        .collect()
}

/// Whether git ignores `path` — the scratch-work question (CLOUD-444).
///
/// `check-ignore` rather than a reimplementation of the ignore rules: the
/// precedence between a repository's `.gitignore`, its excludes file and its
/// global config is git's own, and a second implementation of it would disagree
/// on exactly the layered cases a consumer relies on.
///
/// Built on [`query_optional`], whose contract this fits exactly: `check-ignore`
/// spells "not ignored" as **exit 1**, an answer rather than a failure. The
/// direction of the absent case is the one to read carefully — here a `false` is
/// "not ignored", which makes the path *judgeable*, so a git that cannot answer
/// must not silently produce `false`; that is why a failure to run git at all
/// still raises rather than returning `Ok(false)`.
///
/// `--` separates the pathspec from the flags, so a path beginning with a dash is
/// asked about rather than parsed as one.
///
/// # Errors
///
/// Raises when `git` cannot be run at all, or its output is not UTF-8 — only the
/// verdict is optional, never the mechanism.
pub fn check_ignore(dir: &Path, path: &str) -> Result<bool> {
    Ok(query_optional(dir, &["check-ignore", "--quiet", "--", path])?.is_some())
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
    query(
        dir,
        &["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
        "cannot resolve HEAD; this is not a git repository, or it has no commits",
    )
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
    let listing = query(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads",
            "refs/remotes",
        ],
        "cannot list refs; this is not a git repository",
    )?;
    let mut found: Vec<String> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();
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
    query_optional(dir, &["rev-parse", "--symbolic-full-name", "@{upstream}"])
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
        // A read that fails is treated as an empty file rather than aborting,
        // for the same reason non-UTF-8 content is: an unrelated asset must not
        // be able to disable the gate.
        let Ok(object) = repository.find_object(entry.oid) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&object.data) else {
            continue;
        };
        visit(path, text);
    }
    Ok(())
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
    // `--quiet` so a missing HEAD is a non-zero exit rather than a message on
    // stderr; `query_optional` reads that exit as the answer.
    Ok(query_optional(
        dir,
        &[
            "symbolic-ref",
            "--quiet",
            &format!("refs/remotes/{remote}/HEAD"),
        ],
    )?
    .filter(|found| !found.is_empty()))
}

/// Resolve `rev` to the full SHA of a commit.
///
/// `--verify` yields exactly one line or a failure; the `^{commit}` peel
/// refuses a tag, tree, or blob rather than going on to diff something
/// meaningless; `--end-of-options` stops a rev that happens to look like a flag
/// from being read as one.
fn resolve_commit(dir: &Path, rev: &str, role: &str) -> Result<String> {
    query(
        dir,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{rev}^{{commit}}"),
        ],
        &format!("{role} {rev:?} does not resolve to a commit in this repository"),
    )
}

/// Enumerate commits, newest first, under the fixed selection this module uses
/// everywhere: topological order (commit-date order can reorder commits that
/// share a timestamp), no merges, capped by the window.
///
/// Merges are excluded deliberately, not incidentally: a merge has no patch of
/// its own, and the commits it brings in are separately enumerated here. That
/// stays true only while this stays a full walk — adding `--first-parent` would
/// make everything merged in invisible, which is a silent false *not landed*.
fn rev_list(dir: &Path, window: Window, range: &str) -> Result<Vec<String>> {
    let max = format!("--max-count={}", window.commits());
    let out = query(
        dir,
        &[
            "rev-list",
            "--topo-order",
            "--no-merges",
            &max,
            "--end-of-options",
            range,
        ],
        &format!("cannot enumerate commits for {range:?}"),
    )?;
    Ok(out.lines().map(ToOwned::to_owned).collect())
}

/// Run a diff-producing `git` command and pipe it through
/// `git patch-id --stable`, returning the `(identity, commit)` pairs in the
/// order git emitted them.
///
/// One pipeline, two processes, whatever the window: `git log -p` labels each
/// patch with its `commit <sha>` line, which is exactly what makes `patch-id`
/// print the commit alongside the identity. The alternative — hashing each
/// commit in its own `git` invocation — is a process per commit for the same
/// answer.
///
/// `--stable` is not the default: `git patch-id` computes an *unstable* id
/// unless asked, and an unstable id depends on the order files appear in the
/// diff.
fn patch_ids(dir: &Path, args: &[&str], refusal: &str) -> Result<Vec<(PatchId, String)>> {
    let mut producer = command(dir);
    producer
        .args(DIFF_CONFIG)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for var in DIFF_ENV {
        producer.env_remove(var);
    }
    let mut producer = producer
        .spawn()
        .with_context(|| format!("run `git {}`", args.join(" ")))?;
    let Some(patches) = producer.stdout.take() else {
        bail!("`git {}` produced no stdout pipe", args.join(" "));
    };
    // Nothing is written to a child's stdin here, so there is no pipe-buffer
    // deadlock to guard against: git writes patches straight into `patch-id`
    // and only the (small) identity list comes back to this process.
    let output = command(dir)
        .args(["patch-id", "--stable"])
        .stdin(Stdio::from(patches))
        .stderr(Stdio::null())
        .output()
        .context("run `git patch-id --stable`")?;
    let diffed = producer.wait().context("wait for the diff to finish")?;
    if !diffed.success() {
        return Err(UsageError::raise(refusal));
    }
    if !output.status.success() {
        bail!("`git patch-id --stable` failed");
    }
    let stdout =
        String::from_utf8(output.stdout).context("decode `git patch-id` output as UTF-8")?;
    let mut ids = Vec::new();
    for line in stdout.lines() {
        let mut fields = line.split_whitespace();
        let (Some(id), Some(commit)) = (fields.next(), fields.next()) else {
            bail!("`git patch-id` printed an unparseable line");
        };
        ids.push((PatchId::parse(id)?, commit.to_owned()));
    }
    Ok(ids)
}

/// The patch identity of every commit reachable by `range`, keyed for lookup.
///
/// When two commits share an identity — a revert and a re-apply, a change
/// cherry-picked twice — the **oldest** wins, so the evidence names the actual
/// landing rather than a later copy of it. `git log` walks newest-first, so
/// overwriting on each insert leaves the oldest in place.
fn patch_id_index(dir: &Path, window: Window, range: &str) -> Result<BTreeMap<PatchId, String>> {
    let max = format!("--max-count={}", window.commits());
    let mut args = vec!["log", "-p", "--topo-order", "--no-merges", "--root", &max];
    args.extend(DIFF_FLAGS);
    args.extend(["--end-of-options", range]);
    let mut index = BTreeMap::new();
    for (id, commit) in patch_ids(dir, &args, &format!("cannot read commits for {range:?}"))? {
        index.insert(id, commit);
    }
    Ok(index)
}

/// The patch identity of the branch's whole change: `git diff target...head`,
/// which diffs the head against the point the two histories diverged.
///
/// Three dots, never two: a two-dot diff also carries the *inverse* of
/// everything that landed on the target since the branch left it, so it could
/// never equal a squashed commit no matter how faithfully the work landed.
///
/// `None` when the diff is empty — `git patch-id` prints nothing for an empty
/// patch, and an absent identity must never compare equal to another absent
/// identity.
fn cumulative_patch_id(dir: &Path, target: &str, head: &str) -> Result<Option<PatchId>> {
    let range = format!("{target}...{head}");
    let mut args = vec!["diff"];
    args.extend(DIFF_FLAGS);
    args.extend(["--end-of-options", &range]);
    let ids = patch_ids(
        dir,
        &args,
        "the target and the head have no common history, so there is no branch content to compare",
    )?;
    Ok(ids.into_iter().next().map(|(id, _)| id))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

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
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.email=t@t", "-c", "user.name=t"])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null");
        for var in DISCOVERY_REDIRECTS.iter().chain(DISCOVERY_FENCES.iter()) {
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

    #[test]
    fn no_ancestry_decides_merged_ness() {
        // The gate that ships with the rule (CLOUD-36): merged-ness is decided
        // by patch identity, never by reachability. Unlike the repo-root gate
        // above, this one scans *this file too* — the decision logic lives
        // here, so exempting it would gut the gate.
        //
        // Scope is `src/` only, deliberately: `tests/primitives.rs` must run a
        // reachability query, because the keystone fixture proves ancestry gets
        // the answer wrong on the exact input where this primitive gets it
        // right.
        //
        // The list forbids precisely the *reachability-answer* surface and
        // leaves every range form (`..`, `...`, `rev-list`, `--not`) legal —
        // selecting which commits to hash is allowed, deciding with the result
        // is not. Smuggling a reachability verdict past this means hand-writing
        // a graph walk, which is a different and far more visible change.
        // Tokens are assembled so this test's own source is not a match, and so
        // that prose may still say "the merge base" with a space.
        let forbidden = [
            ["merge", "-base"].concat(),
            ["merge", "_base"].concat(),
            ["is", "-ancestor"].concat(),
            ["is", "_ancestor"].concat(),
            ["--con", "tains"].concat(),
            ["--ancestry", "-path"].concat(),
        ];
        for (path, source) in crate_sources(false) {
            for token in &forbidden {
                assert!(
                    !source.contains(token),
                    "{}: contains {token:?}; merged-ness is decided by patch identity, never by \
                     reachability (CLOUD-36) — a rebased landing is invisible to ancestry",
                    path.display()
                );
            }
        }
    }

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
        // The gate that makes the receipt.rs migration stick (CLOUD-36): every
        // `git` process the crate spawns is spawned through this module, so
        // there is one place where the discovery scrub, the pinned diff config,
        // and the usage-vs-internal error split are decided.
        //
        // Precise by construction: rules.rs and hook.rs spawn *user-configured*
        // programs through a variable program name and are untouched by this —
        // what is forbidden is naming `git` as a literal program elsewhere.
        let needle = ["Command::new(\"", "git\")"].concat();
        for (path, source) in crate_sources(true) {
            assert!(
                !source.contains(needle.as_str()),
                "{}: spawns git directly; call git::query so the environment scrub and the \
                 usage-vs-internal split stay in one place (CLOUD-36)",
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
    fn a_short_record_is_refused_rather_than_answered() {
        // The one behavioural change CLOUD-742 sanctions, tested where the
        // decision is: a record that does not carry four fields cannot be read
        // as attribution. It used to take each part with `unwrap_or_default()`,
        // so a body carrying U+001E shifted the split and the missing fields
        // arrived as empty strings — judged afterwards as though git had said
        // them.
        //
        // Exercised over the parse rather than over a repository, per
        // `.claude/rules/rust.md`: the failing condition is a record shape, so
        // the assertion is about that shape and not about a fixture that
        // happens to produce it.
        let sep = RECORD_SEPARATOR;
        let commit = "a".repeat(40);

        let whole = format!("Ann <ann@x>{sep}Bo <bo@x>{sep}Refs: CLOUD-742{sep}the body");
        let read = record_from(&whole, &commit).expect("a four-field record reads");
        assert_eq!(read.author, "Ann <ann@x>");
        assert_eq!(read.committer, "Bo <bo@x>");
        assert_eq!(read.trailers, vec!["Refs: CLOUD-742".to_owned()]);
        assert_eq!(read.body, "the body");

        // A body carrying the separator does NOT shift fields, because the
        // split is bounded at four: everything after the third separator is
        // body, separators and all.
        let with_sep = format!("Ann <ann@x>{sep}Bo <bo@x>{sep}{sep}a body with {sep} in it");
        let read = record_from(&with_sep, &commit).expect("the body keeps its own separators");
        assert_eq!(read.author, "Ann <ann@x>");
        assert_eq!(read.body, format!("a body with {sep} in it"));

        // Short: three fields, which used to yield an empty body and an empty
        // trailer block that the attribution decision then judged.
        for short_record in [
            format!("Ann <ann@x>{sep}Bo <bo@x>{sep}Refs: CLOUD-742"),
            format!("Ann <ann@x>{sep}Bo <bo@x>"),
            "Ann <ann@x>".to_owned(),
            String::new(),
        ] {
            let refused = record_from(&short_record, &commit);
            assert!(
                refused.is_err(),
                "a record of {} field(s) must refuse, never answer with blanks",
                short_record.split(sep).count()
            );
        }
    }

    #[test]
    fn a_patch_id_is_hex_of_a_hash_length() {
        assert!(PatchId::parse(&"a".repeat(40)).is_ok(), "SHA-1 repository");
        assert!(
            PatchId::parse(&"0".repeat(64)).is_ok(),
            "SHA-256 repository"
        );
        // A parsing slip must never manufacture an equality between two
        // truncated or non-hex ids.
        assert!(PatchId::parse("").is_err());
        assert!(PatchId::parse(&"a".repeat(39)).is_err());
        assert!(PatchId::parse(&"g".repeat(40)).is_err());
        assert!(PatchId::parse(&"A".repeat(40)).is_err(), "lowercase only");
    }

    #[test]
    fn the_verdict_is_derived_from_evidence_alone() {
        let id = PatchId::parse(&"a".repeat(40)).unwrap();
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
        let id = PatchId::parse(&"a".repeat(40)).unwrap();
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
