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

/// How many hex characters of the checkout digest the state segment carries.
///
/// Twelve, matching the short-sha convention this repo already reads by eye. The
/// digest separates checkouts on one machine, so the population it must not
/// collide over is a handful of directories rather than a content-addressed
/// store — and the readable prefix, not the digest, is what a person navigates by.
const CHECKOUT_DIGEST_LEN: usize = 12;

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

/// Derive the state-directory segment for the repository at `repo_root`:
/// `<final path component>-<checkout digest>`, both resolved at runtime.
///
/// # The final component alone is not sufficient, and that is why the digest is here
///
/// It was, until CLOUD-296. The segment was the repository's directory name and
/// nothing else, so `~/work/batten` and `~/scratch/batten` — a worktree, a second
/// clone, a colleague's layout, a CI checkout beside a local one — resolved to one
/// state root, and the second checkout read and wrote the first one's records with
/// nothing detecting it. Survivable for receipts, which are SHA-keyed, so a foreign
/// receipt reads as `stale-head` rather than as an answer. Not survivable for the
/// capture store (CLOUD-162): it is written on every `batten exec`, and a capture
/// handle is part of the finding-identity contract, so a handle could expand to
/// output produced by a command that ran **in a different tree** — misattribution
/// in a pointer whose only purpose is provenance.
///
/// The digest is [`crate::identity::checkout_fingerprint`] of the canonical
/// absolute root, truncated to [`CHECKOUT_DIGEST_LEN`] hex characters. The
/// readable prefix stays first so the directory is still findable by eye and the
/// segment is still *derived* rather than baked in (CLOUD-38).
///
/// **A moved checkout orphans its records, deliberately.** Moving the tree changes
/// the canonical root, so it derives a new segment and the old records stay where
/// they were. The alternative — records following the move — needs a marker file
/// in the checkout or a registry mapping paths to segments, which is durable state
/// *and* a second answer to "which repository is this". One scheme answers that
/// question, and the capture digest goes on answering only "which bytes are these".
///
/// # Errors
///
/// Returns a [`UsageError`] when `repo_root` has no final component (it is a
/// filesystem root, empty, or ends in `..`), that component is not valid UTF-8, or
/// the root is relative — the digest is a statement about *where* this checkout
/// is, which a relative path cannot make.
pub fn derive_repo_name(repo_root: &Path) -> Result<String> {
    let name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            UsageError::raise(format!(
                "cannot derive a repository name from {}",
                repo_root.display()
            ))
        })?;
    let digest = crate::identity::checkout_fingerprint(repo_root)?.to_hex();
    Ok(format!("{name}-{}", &digest[..CHECKOUT_DIGEST_LEN]))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_leads_with_the_final_path_component() {
        // Was `repo_name_is_the_final_path_component` until CLOUD-296. The
        // component leads the segment rather than being the whole of it — see
        // `derive_repo_name` for why the whole of it was a collision.
        for (root, name) in [
            ("/home/user/my-project", "my-project"),
            ("/srv/git/other-repo", "other-repo"),
        ] {
            let segment = derive_repo_name(Path::new(root)).unwrap();
            assert!(
                segment.starts_with(&format!("{name}-")),
                "{root} must derive a segment led by {name}, got {segment}"
            );
        }
    }

    #[test]
    fn a_relative_root_is_a_usage_error() {
        // The digest is a statement about WHERE this checkout is, and a relative
        // path cannot make one: `./batten` names a different tree from each
        // directory it is read in, so a segment derived from it would silently
        // follow the caller's cwd.
        let err = derive_repo_name(Path::new("some/repo")).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a relative root is bad input, not an internal failure"
        );
    }

    #[test]
    fn a_trailing_separator_names_the_same_checkout() {
        // `/a/repo` and `/a/repo/` are one tree, so they must not address two
        // stores. `file_name()` already ignores the trailing slash; this pins
        // that the digest half does too.
        assert_eq!(
            derive_repo_name(Path::new("/a/repo")).unwrap(),
            derive_repo_name(Path::new("/a/repo/")).unwrap()
        );
    }

    #[test]
    fn two_checkouts_sharing_a_directory_name_do_not_share_a_state_root() {
        // CLOUD-296. The segment used to be the final path component and nothing
        // else, so `~/work/batten` and `~/scratch/batten` — a worktree, a second
        // clone, a CI checkout beside a local one — resolved to ONE state root
        // and silently read and wrote each other's records.
        //
        // Asserted as PREFIX-DISJOINTNESS rather than by naming the receipt and
        // capture stores: every store is a plain join onto this one root
        // (`captures`, `receipts`, decisions, secrets, provision), so disjoint
        // roots separate all of them, including any store added later. Naming two
        // would leave the rest unasserted.
        let here = repo_state_dir(Path::new("/work/batten")).expect("resolve one");
        let there = repo_state_dir(Path::new("/scratch/batten")).expect("resolve the other");

        assert_ne!(here, there, "same directory name must not mean same store");
        assert!(
            !here.starts_with(&there) && !there.starts_with(&here),
            "neither root may contain the other, or one checkout's store nests \
             inside the other's: {} vs {}",
            here.display(),
            there.display()
        );
        // And the readable half survives: the directory is still findable by eye.
        for (dir, root) in [(&here, "/work/batten"), (&there, "/scratch/batten")] {
            let segment = dir
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a segment");
            assert!(
                segment.starts_with("batten-"),
                "the segment for {root} must keep the repository's own name as its \
                 prefix, got {segment}"
            );
        }
    }

    #[test]
    fn the_state_root_is_byte_stable_for_one_checkout() {
        // §6's determinism law, applied to a path. Two derivations for the same
        // checkout must be byte-identical — no clock, no counter, no ambient
        // value — or every run would address a different store.
        let root = Path::new("/home/user/project");
        assert_eq!(
            derive_repo_name(root).expect("first derivation"),
            derive_repo_name(root).expect("second derivation")
        );
    }

    #[test]
    fn a_moved_checkout_orphans_its_records_which_is_the_chosen_outcome() {
        // CLOUD-296 left this open with two defensible answers; this is the one
        // taken, pinned so the doc cannot drift from it. Moving a checkout
        // changes the canonical root, so it derives a new segment and the old
        // records stay where they were rather than following.
        //
        // The alternative — records follow — needs a marker file in the checkout
        // or a registry: durable state, and a SECOND answer to "which repository
        // is this", which this issue's acceptance forbids outright.
        let before = derive_repo_name(Path::new("/home/user/project")).expect("before the move");
        let after = derive_repo_name(Path::new("/srv/project")).expect("after the move");
        assert_ne!(
            before, after,
            "a moved checkout addresses a new store; its old records are orphaned, \
             deliberately and not silently"
        );
    }

    #[test]
    fn repo_name_is_derived_not_constant() {
        // Distinct roots yield distinct names: the segment is resolved from the
        // repository at runtime, never a baked-in literal (rule 1 / CLOUD-38).
        let alpha = derive_repo_name(Path::new("/a/alpha")).unwrap();
        let beta = derive_repo_name(Path::new("/b/beta")).unwrap();
        assert_ne!(alpha, beta);
        // The readable prefix is still the repository's own directory name — the
        // digest CLOUD-296 appended separates checkouts, it does not replace the
        // name a person navigates by.
        assert!(alpha.starts_with("alpha-"), "got {alpha}");
        assert!(beta.starts_with("beta-"), "got {beta}");
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
        // One segment under the root, still — CLOUD-296 changed what the segment
        // says, not how many there are, which is what keeps every store beneath
        // it (captures, receipts, decisions) separating by construction.
        assert_eq!(
            dir.file_name().and_then(|name| name.to_str()),
            Some(
                derive_repo_name(Path::new("/x/demo-repo"))
                    .unwrap()
                    .as_str()
            )
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
