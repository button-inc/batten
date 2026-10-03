//! Decisions the test harness makes about a spawn, kept in the crate so
//! `batten mutate` can show each one red (CLOUD-2059).
//!
//! Test-support rather than product surface, and `#[doc(hidden)]` says so,
//! exactly as [`crate::scratch`] does. `tests/it/common` applies these on every
//! spawn of the binary under test; the decisions live here, where a declared row
//! is swept like any engine module's, rather than in the harness, where a row is
//! a comment whose kill is shown by hand.

use std::path::{Path, PathBuf};

/// The OS data directory THIS process resolves state under, once a test has
/// contained it ([`contain_state`]).
static CONTAINED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Resolve this process's own state under `data_dir` from now on, as a spawned
/// child pointed there by [`state_pins`] resolves its (CLOUD-2059).
///
/// THE IN-PROCESS HALF OF THE PIN. A case that calls the library — an admission
/// issued, a lap verified, a decision appended — resolves the store from its own
/// environment, which no spawn door touches and `unsafe_code = "forbid"` puts out
/// of reach, so those calls wrote the developer's real store: 22 segments in one
/// full run after every door was pinned. Set once per process (nextest runs each
/// case in its own), first value wins, and nothing outside a test can reach it:
/// it reads no environment variable, and the binary never calls it.
#[doc(hidden)]
pub fn contain_state(data_dir: &Path) {
    let _ = CONTAINED.set(data_dir.to_path_buf());
}

/// The contained data directory, if a test set one.
///
/// ONE SUITE FOR EVERY ROW IN THIS FILE: `mutate` reads a source's first
/// `MUTANT-SUITE` only, and a Rust suite selects the runner, not a target — each
/// row's case filter runs over the whole `it` binary, wherever the case lives.
//MUTANT-SUITE crates/batten/tests/it/harness_isolation.rs
//MUTANT in-process-uncontained|s@^    CONTAINED.get().map(PathBuf::as_path)$@    None@|in_process_state_resolves_to_the_cases_own_root
pub(crate) fn contained_data_dir() -> Option<&'static Path> {
    CONTAINED.get().map(PathBuf::as_path)
}

/// The variables that place a child's state root at `<dir>/batten` on every
/// platform: the XDG data home `etcetera` reads on unix and macOS, and the
/// `%APPDATA%` its Windows strategy reads. A redirect spelled for one platform
/// writes the real user's store on the other, which is how CLOUD-113's Windows
/// job found the first copy of this.
///
/// `LOCALAPPDATA` is deliberately absent. Batten keeps nothing there, and mise on
/// Windows keeps its whole toolchain there with no `MISE_DATA_DIR` pinned on that
/// leg, so moving it on every spawn would reinstall the toolchain per case —
/// CLOUD-2021's cost, on every case rather than one.
//MUTANT state-pin-posix-only|s@("APPDATA", dir)@("APPDATA_UNREAD", dir)@|the_ambient_state_root_never_reaches_the_binary_under_test
#[doc(hidden)]
#[must_use]
pub fn state_pins(dir: &Path) -> [(&'static str, &Path); 2] {
    [("XDG_DATA_HOME", dir), ("APPDATA", dir)]
}

/// The variables that place a child's home directory at `dir` on every platform:
/// `HOME` on unix and macOS, and the `USERPROFILE` `std::env::home_dir` reads on
/// Windows. A home overridden for one platform reads the real user's profile on
/// the other, which is how CLOUD-113's Windows job found `wiring_reclaim.rs`.
///
/// What a case's home holds is then the case's business: a developer's
/// `~/.claude`, `~/.gitconfig` or global mise config can no longer move a verdict
/// here that a CI runner, which has none of them, would not reproduce.
//MUTANT home-pin-posix-only|s@("USERPROFILE", dir)@("USERPROFILE_UNREAD", dir)@|every_spawn_of_the_binary_pins_the_home
#[doc(hidden)]
#[must_use]
pub fn home_pins(dir: &Path) -> [(&'static str, &Path); 2] {
    [("HOME", dir), ("USERPROFILE", dir)]
}

/// Whether a spawn whose working directory is `cwd` would FALL THROUGH to an
/// enclosing repository: `cwd` lies at or below `scratch_root`, and the working
/// tree discovery resolves it to lies above `scratch_root`.
///
/// RESOLVED, NOT INFERRED FROM A `.git` THAT EXISTS. An empty or malformed `.git`
/// is not a repository, so discovery walks straight past it to the checkout —
/// the one case a presence test calls owned while the binary falls through. This
/// asks [`crate::git::worktree_root`], the resolver the binary itself uses, and a
/// directory no repository encloses is not judged: the binary refuses there, and
/// nothing reaches a checkout.
///
/// # The defect this refuses
///
/// `git::repo_root` deliberately ignores `GIT_CEILING_DIRECTORIES`, so a fixture
/// under the build's scratch root with no repository of its own resolves to the
/// checkout that holds the build — the real one. A verb run there reads the real
/// configuration, writes the real `.git`, and keys the real state segment, while
/// the case believes it judged its fixture.
///
/// # What it leaves alone, deliberately
///
/// A `cwd` OUTSIDE `scratch_root` is not judged: a suite whose subject is the
/// committed configuration runs at the real root on purpose, and a fixture under
/// the system temp directory falls through to nothing. Only the scratch root sits
/// inside the checkout, so only there is a missing `.git` an accident.
//MUTANT spawn-falls-through|s@^    resolved.is_ok_and.*$@    false@|a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused
//MUTANT verbatim-scratch-root|s@^    let scratch = crate::git::canonical(scratch_root);$@    let scratch = scratch_root.canonicalize().unwrap_or_else(\x7c_\x7c scratch_root.to_path_buf());@|no_engine_file_adds_a_bare_canonicalize
#[doc(hidden)]
#[must_use]
pub fn falls_through(cwd: &Path, scratch_root: &Path) -> bool {
    if !cwd.starts_with(scratch_root) {
        return false;
    }
    // Both sides in the RESOLVER'S spelling, because a scratch root reached
    // through a symlink would otherwise own nothing — and `git::canonical`, not a
    // bare `canonicalize`, whose verbatim Windows answer shares no prefix with the
    // plain root `worktree_root` returns: that read every owned fixture as
    // falling through and refused 2,614 cases on the Windows leg (CLOUD-2059).
    let scratch = crate::git::canonical(scratch_root);
    let resolved = crate::git::worktree_root(cwd);
    resolved.is_ok_and(|owner| !owner.starts_with(&scratch))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// A checkout at `<scratch>/checkout` whose own scratch root is `tmp` inside
    /// it — this build's shape, one level down — with an empty fixture beneath.
    fn checkout(name: &str) -> std::path::PathBuf {
        let dir = crate::scratch::scratch(&format!("testing-{name}")).join("checkout");
        std::fs::create_dir_all(dir.join("tmp/fixture/sub")).expect("create the tree");
        crate::gitwrite::init_on_main(&dir).expect("the enclosing checkout");
        dir
    }

    /// A fixture with no repository of its own resolves to the enclosing checkout.
    #[test]
    fn a_fixture_with_no_repository_under_the_scratch_root_falls_through() {
        let dir = checkout("bare");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// A repository between the fixture and the scratch root owns it.
    #[test]
    fn a_repository_anywhere_up_to_the_scratch_root_owns_the_fixture() {
        let dir = checkout("owned");
        crate::gitwrite::init_on_main(&dir.join("tmp/fixture"))
            .expect("the fixture's own repository");
        assert!(!falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// An empty `.git` is no repository, so ownership is resolved, never inferred
    /// from the entry existing (review of #1089).
    #[test]
    fn a_dot_git_that_is_not_a_repository_owns_nothing() {
        let dir = checkout("hollow");
        std::fs::create_dir_all(dir.join("tmp/fixture/.git")).expect("an empty .git");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    /// Only a directory under the scratch root is judged; the real root is not a
    /// fixture.
    #[test]
    fn a_directory_outside_the_scratch_root_is_not_judged() {
        let dir = checkout("outside");
        assert!(!falls_through(&dir, &dir.join("tmp")));
    }
}
