//! Resolve Batten's out-of-tree state directory.
//!
//! State lives under `<data-dir>/<app>/<repo-name>/`, never inside the repo, so a
//! checkout stays clean and state survives a reclone. The per-OS `<data-dir>`
//! follows the CLOUD-23 decision: XDG (`XDG_DATA_HOME`, else `~/.local/share`) on
//! Linux and macOS, and the roaming known folder (`%APPDATA%`) on Windows —
//! resolved through `etcetera`'s base strategy, which selects that rule by OS.
//!
//! The `<repo-name>` segment is derived from the repository at runtime (rule 1):
//! the core bakes in no repository name. `<app>` is the crate name, taken from
//! the manifest rather than a hand-copied string constant.
//!
//! # Warm-fork restart: what survives, and why (CLOUD-83)
//!
//! A warm fork abandons the current trajectory and keeps the working state. The
//! restart procedure is this: **there is nothing to do.** That is the design
//! rather than an omission, and this is where it is written down, because this
//! module is the one that decides where the state lives.
//!
//! Survival is **inherited from the location**, never implemented by a
//! restart-time copier — a copier is a step someone can forget, and a step that
//! runs after a crash has already lost the thing it was going to copy. So:
//!
//! | What                | Where it lives                      | Survives because                     |
//! | ------------------- | ----------------------------------- | ------------------------------------ |
//! | the findings store  | here, out of tree ([`repo_state_dir`]) | it was never in the forked process   |
//! | dispositions        | journal shards under that directory | [`crate::journal::append`] fsyncs before returning |
//! | the defect ledger   | a tracked file in the repository    | it is committed                      |
//! | working papers      | the checkout                        | a warm fork keeps the checkout       |
//!
//! Two things are genuinely lost with the process, and [`crate::session`] is
//! where they are recorded instead: the reader's `(generation, seqno)` position,
//! and the session key an open sequence-kind finding was minted under. See that
//! module for the lineage rule — a fork continues its parent's session key — and
//! for why the parent is declared rather than inferred.
//!
//! What a warm fork does **not** preserve is the trajectory: the abandoned
//! session's plan, its context, its in-flight edits. That is the point of forking.
//! Nothing here tries to keep it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use etcetera::{BaseStrategy, choose_base_strategy};

use crate::error::UsageError;

/// The application namespace under the OS data directory. Taken from the crate
/// name (`CARGO_PKG_NAME`) so it tracks the binary rather than being a literal.
const APP_NAMESPACE: &str = env!("CARGO_PKG_NAME");

/// Batten's OS data directory: `<data-dir>/<app>`, per the CLOUD-23 per-OS rule,
/// resolved via `etcetera` (XDG on Linux/macOS, the roaming known folder on
/// Windows).
///
/// # Errors
///
/// Returns an error when the platform's base directories cannot be resolved (for
/// example, no home directory is set).
pub fn state_root() -> Result<PathBuf> {
    let strategy = choose_base_strategy().context("resolve the OS data directory")?;
    Ok(strategy.data_dir().join(APP_NAMESPACE))
}

/// The state directory for the repository rooted at `repo_root`:
/// `<data-dir>/<app>/<repo-name>/`.
///
/// The `<repo-name>` segment is [`derive_repo_name`] of `repo_root`, so no
/// repository identifier is baked into the core.
///
/// # Errors
///
/// Returns a [`UsageError`] when `repo_root` has no usable final component, or an
/// error when the OS data directory cannot be resolved.
pub fn repo_state_dir(repo_root: &Path) -> Result<PathBuf> {
    let name = derive_repo_name(repo_root)?;
    Ok(state_root()?.join(name))
}

/// Derive the state-directory name for the repository at `repo_root`: its final
/// path component (the repository's own directory name), resolved at runtime.
///
/// # Errors
///
/// Returns a [`UsageError`] when `repo_root` has no final component (it is a
/// filesystem root, empty, or ends in `..`) or that component is not valid UTF-8.
pub fn derive_repo_name(repo_root: &Path) -> Result<String> {
    repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            UsageError::raise(format!(
                "cannot derive a repository name from {}",
                repo_root.display()
            ))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_is_the_final_path_component() {
        assert_eq!(
            derive_repo_name(Path::new("/home/user/my-project")).unwrap(),
            "my-project"
        );
        assert_eq!(
            derive_repo_name(Path::new("/srv/git/other-repo")).unwrap(),
            "other-repo"
        );
    }

    #[test]
    fn repo_name_is_derived_not_constant() {
        // Distinct roots yield distinct names: the segment is resolved from the
        // repository at runtime, never a baked-in literal (rule 1 / CLOUD-38).
        let alpha = derive_repo_name(Path::new("/a/alpha")).unwrap();
        let beta = derive_repo_name(Path::new("/b/beta")).unwrap();
        assert_ne!(alpha, beta);
        assert_eq!((alpha.as_str(), beta.as_str()), ("alpha", "beta"));
    }

    #[test]
    fn root_without_a_final_component_is_a_usage_error() {
        let err = derive_repo_name(Path::new("/")).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a rootless path is bad input, not an internal failure"
        );
    }

    #[test]
    fn state_root_is_absolute_and_namespaced() {
        // The host branch of the per-OS rule, resolved via etcetera. The macOS
        // and Windows branches are asserted by `mise run cross-check` — they
        // compile for those targets through the same `choose_base_strategy` call.
        let root = state_root().expect("resolve state root");
        assert!(
            root.is_absolute(),
            "state root must be absolute: {}",
            root.display()
        );
        assert_eq!(
            root.file_name().and_then(|name| name.to_str()),
            Some(APP_NAMESPACE)
        );
    }

    #[test]
    fn repo_state_dir_is_state_root_joined_with_repo_name() {
        let dir = repo_state_dir(Path::new("/x/demo-repo")).expect("resolve repo state dir");
        let root = state_root().expect("resolve state root");
        assert_eq!(dir.parent(), Some(root.as_path()));
        assert_eq!(
            dir.file_name().and_then(|name| name.to_str()),
            Some("demo-repo")
        );
    }

    #[test]
    fn source_derives_the_repo_name_and_bakes_in_no_literal() {
        // The no-baked-literal gate (CLOUD-38), as a grep over this module's own
        // source: the app namespace must come from CARGO_PKG_NAME and the repo
        // segment from `file_name()` at runtime, and the name of the repository
        // this checkout lives in must not appear as a hardcoded string literal.
        let source = include_str!("state.rs");
        assert!(
            source.contains("env!(\"CARGO_PKG_NAME\")"),
            "the app namespace must derive from CARGO_PKG_NAME, not a literal"
        );
        assert!(
            source.contains("file_name()"),
            "the repo segment must derive from file_name() at runtime"
        );

        // Derive this repository's name the same way the resolver does, then
        // assert that exact token is not baked in as a quoted literal anywhere.
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root is two levels above the crate manifest");
        let this_repo = derive_repo_name(repo_root).expect("derive this repo's name");
        let baked = format!("\"{this_repo}\"");
        assert!(
            !source.contains(&baked),
            "state source hardcodes the repo name {baked}; derive it at runtime"
        );
    }
}
