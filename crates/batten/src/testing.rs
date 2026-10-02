//! Decisions the test harness makes about a spawn, kept in the crate so
//! `batten mutate` can show each one red (CLOUD-2059).
//!
//! Test-support rather than product surface, and `#[doc(hidden)]` says so,
//! exactly as [`crate::scratch`] does. `tests/it/common` applies these on every
//! spawn of the binary under test; the decisions live here, where a declared row
//! is swept like any engine module's, rather than in the harness, where a row is
//! a comment whose kill is shown by hand.

use std::path::Path;

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
//MUTANT-SUITE crates/batten/tests/it/bypass_scrub.rs
//MUTANT state-pin-posix-only|s@("APPDATA", dir)@("APPDATA_UNREAD", dir)@|the_ambient_state_root_never_reaches_the_binary_under_test
#[doc(hidden)]
#[must_use]
pub fn state_pins(dir: &Path) -> [(&'static str, &Path); 2] {
    [("XDG_DATA_HOME", dir), ("APPDATA", dir)]
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
//MUTANT-SUITE crates/batten/tests/it/harness_isolation.rs
//MUTANT spawn-falls-through|s@^    resolved.is_ok_and.*$@    false@|a_spawn_whose_cwd_falls_through_to_the_checkout_is_refused
#[doc(hidden)]
#[must_use]
pub fn falls_through(cwd: &Path, scratch_root: &Path) -> bool {
    if !cwd.starts_with(scratch_root) {
        return false;
    }
    // Both sides canonical, because the resolver answers canonically and a
    // scratch root reached through a symlink would otherwise own nothing.
    let scratch = scratch_root
        .canonicalize()
        .unwrap_or_else(|_| scratch_root.to_path_buf());
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

    #[test]
    fn a_fixture_with_no_repository_under_the_scratch_root_falls_through() {
        let dir = checkout("bare");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

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

    #[test]
    fn a_dot_git_that_is_not_a_repository_owns_nothing() {
        let dir = checkout("hollow");
        std::fs::create_dir_all(dir.join("tmp/fixture/.git")).expect("an empty .git");
        assert!(falls_through(
            &dir.join("tmp/fixture/sub"),
            &dir.join("tmp")
        ));
    }

    #[test]
    fn a_directory_outside_the_scratch_root_is_not_judged() {
        let dir = checkout("outside");
        assert!(!falls_through(&dir, &dir.join("tmp")));
    }
}
