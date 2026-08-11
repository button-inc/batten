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

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
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

/// Read a tracked file's contents at a git ref, without touching the working
/// tree (`git show <reference>:<path>`).
///
/// This is the trust boundary behind `--config-from` (CLOUD-31): policy is read
/// from a ref a pull request cannot edit, so a working-tree change that relaxes
/// the rules cannot lower the bar it is judged by. It reads and never writes,
/// which is what keeps the calling verb `read`.
///
/// `path` is repo-relative and `/`-separated, as git addresses blobs. The
/// discovery environment is scrubbed for the same reason [`repo_root`] scrubs
/// it: an ambient `GIT_DIR` would answer from some *other* repository, and a
/// trust boundary that can be redirected by an environment variable is not one.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the ref does not exist, the path
/// is absent at that ref, or the object is not a readable file — all bad input
/// naming a ref this binary cannot honour, never a policy verdict. Returns an
/// internal error when git itself cannot run or emits non-UTF-8.
pub fn show(dir: &Path, reference: &str, path: &str) -> Result<String> {
    if !dir.is_dir() {
        return Err(UsageError::raise(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let mut command = command(dir);
    // `--` is not accepted after a `rev:path` argument; the single token is
    // already unambiguous to git, and refusing a `reference` that looks like an
    // option is the caller's business (a leading `-` simply fails below).
    command.arg("show").arg(format!("{reference}:{path}"));
    // A trust boundary answers about *this* repository or it is not one, so the
    // fences are scrubbed here too — the same rule `repo_root` follows, and a
    // stricter one than a plain `query` needs.
    for var in DISCOVERY_FENCES {
        command.env_remove(var);
    }
    let output = command
        .output()
        .with_context(|| format!("run `git show {reference}:{path}`"))?;
    if !output.status.success() {
        // git's stderr distinguishes "unknown revision" from "path does not
        // exist in that revision" in version-dependent prose. One deterministic
        // message instead, naming both halves so the operator can tell which.
        return Err(UsageError::raise(format!(
            "cannot read {path} at {reference}: no such ref, or the path is absent there"
        )));
    }
    String::from_utf8(output.stdout).with_context(|| format!("decode {reference}:{path} as UTF-8"))
}

/// The `git` child every query in this module is built from: `-C dir`, with
/// the redirect variables scrubbed so the answer is about the directory it was
/// handed and not about whatever repository the ambient environment names.
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
pub fn query(dir: &Path, args: &[&str], refusal: &str) -> Result<String> {
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
pub fn query_bytes(dir: &Path, args: &[&str], refusal: &str) -> Result<Vec<u8>> {
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
pub fn query_optional(dir: &Path, args: &[&str]) -> Result<Option<String>> {
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
    let listing = query(
        dir,
        &["ls-tree", "-r", "--name-only", "--end-of-options", rev],
        &format!("ratchet base {rev:?} does not resolve to a tree in this repository"),
    )?;

    let mut total = 0;
    for path in listing.lines().filter(|path| !path.is_empty()) {
        if !crate::rules::glob_match(glob, path) {
            continue;
        }
        // `show <rev>:<path>`. The path comes from `ls-tree` at the same rev, so
        // it exists by construction; a read that fails anyway is treated as an
        // empty file rather than aborting, for the same reason non-UTF-8 is.
        let Ok(bytes) = query_bytes(
            dir,
            &["show", &format!("{rev}:{path}")],
            "read a file at the ratchet base",
        ) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        total += text.matches(pattern).count();
    }
    Ok(total)
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
    /// use `CARGO_TARGET_TMPDIR` (integration-only); per-test names keep
    /// parallel tests apart, and the wipe clears a crashed prior run.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("batten-git-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Run git in `dir`, hermetically: no global or system config (a dev
    /// machine's `commit.gpgsign` or `core.hooksPath` must not break a
    /// fixture) and the same discovery scrub the resolver applies.
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
