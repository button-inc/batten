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

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::error::UsageError;

/// Environment variables that override git's repository discovery. Scrubbed
/// from the child so resolution depends on `start` and the filesystem, never
/// on ambient state.
const DISCOVERY_OVERRIDES: [&str; 5] = [
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
];

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
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(start)
        // Option order is load-bearing twice over: output lines mirror option
        // order, and `--path-format` applies only to the options after it (an
        // unqualified `--git-common-dir` prints a cwd-relative path).
        .args([
            "rev-parse",
            "--is-bare-repository",
            "--path-format=absolute",
            "--git-common-dir",
        ]);
    for var in DISCOVERY_OVERRIDES {
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
    let mut command = Command::new("git");
    // `--` is not accepted after a `rev:path` argument; the single token is
    // already unambiguous to git, and refusing a `reference` that looks like an
    // option is the caller's business (a leading `-` simply fails below).
    command
        .arg("-C")
        .arg(dir)
        .arg("show")
        .arg(format!("{reference}:{path}"));
    for var in DISCOVERY_OVERRIDES {
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
        for var in DISCOVERY_OVERRIDES {
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
}
