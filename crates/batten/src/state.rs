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
    Ok(data_dir()?.join(APP_NAMESPACE))
}

/// The OS data directory this process resolves, per the CLOUD-23 per-OS rule —
/// the directory [`state_root`] places `<app>` under.
///
/// A test that contained this process ([`crate::testing::contain_state`]) gets
/// the directory it named, the one its spawned children are pinned to, so a case
/// that both spawns and calls the library reads and writes one store (CLOUD-2059).
///
/// # Errors
///
/// Returns an error when the platform's base directories cannot be resolved.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(contained) = crate::testing::contained_data_dir() {
        return Ok(contained.to_path_buf());
    }
    let strategy = choose_base_strategy().context("resolve the OS data directory")?;
    Ok(strategy.data_dir())
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

/// [`repo_state_dir`] under a data directory named outright rather than the one
/// this process resolves — for a caller that hands the data directory to a CHILD
/// through the environment and must name a path inside the child's store
/// (CLOUD-2315: `perf`'s posttool arm empties one subtree of it per run).
///
/// # Errors
///
/// As [`derive_repo_name`].
pub fn repo_state_dir_under(data_dir: &Path, repo_root: &Path) -> Result<PathBuf> {
    Ok(data_dir
        .join(APP_NAMESPACE)
        .join(derive_repo_name(repo_root)?))
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

/// The file recording the authority root a session last stood in (CLOUD-2204),
/// under the state root `state`.
///
/// Keyed by a fingerprint of the session id rather than the id itself, for
/// `drain::wake_path`'s reason: the id is host-chosen and must not choose where
/// this writes. Under the state root, never under a checkout, because the whole
/// point is to be readable from a cwd that resolves no checkout.
fn session_authority_file(state: &Path, session: &str) -> PathBuf {
    let key = crate::identity::store_fingerprint(&[session]).to_hex();
    state.join("sessions").join(key).join("authority")
}

/// Record `root` as the authority this session last resolved.
///
/// Written only when it differs from what is recorded, so the hottest path in
/// the binary pays one small read per call and a write only when the session
/// moves between repositories.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be written.
pub fn record_session_authority(session: &str, root: &Path) -> Result<()> {
    let path = session_authority_file(&state_root()?, session);
    let text = root.to_string_lossy();
    if std::fs::read_to_string(&path).is_ok_and(|held| held == text) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    crate::durable::replace(&path, text.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

/// The authority root this session last resolved, if it still carries one.
#[must_use]
pub fn recorded_session_authority(session: &str, file: &str) -> Option<PathBuf> {
    recorded_session_authority_in(&state_root().ok()?, session, file)
}

/// [`recorded_session_authority`] under the state root `state`.
///
/// `None` when nothing is recorded, the record is unreadable, or the recorded
/// root no longer holds `file` — a deleted or moved checkout is never answered
/// for by its ghost. The check is here rather than left to the policy loader's
/// own absence test because every other reader of the authority root (receipts,
/// the capture store, the sighting record) would otherwise write under a
/// directory that no longer governs anything.
//MUTANT-SUITE crates/batten/src/state.rs
//MUTANT session-authority-ghost-admitted|s@^    (root\.is_absolute() && root\.join(file)\.is_file())\.then_some(root)$@    root.is_absolute().then_some(root)@|a_recorded_root_that_lost_its_authority_is_not_used
#[must_use]
pub fn recorded_session_authority_in(state: &Path, session: &str, file: &str) -> Option<PathBuf> {
    let root = PathBuf::from(std::fs::read_to_string(session_authority_file(state, session)).ok()?);
    (root.is_absolute() && root.join(file).is_file()).then_some(root)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_root_that_lost_its_authority_is_not_used() {
        // CLOUD-2204: a ghost root is never handed back as the session's
        // authority, so nothing downstream writes under a dead checkout.
        let base = std::env::temp_dir().join(format!("batten-ghost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (state, root) = (base.join("state"), base.join("repo"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("batten.toml"), "version = 1\n").unwrap();
        let file = session_authority_file(&state, "s");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, root.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(
            recorded_session_authority_in(&state, "s", "batten.toml"),
            Some(root.clone())
        );
        std::fs::remove_file(root.join("batten.toml")).unwrap();
        assert_eq!(
            recorded_session_authority_in(&state, "s", "batten.toml"),
            None
        );
        assert_eq!(
            recorded_session_authority_in(&state, "other", "batten.toml"),
            None
        );
        let _ = std::fs::remove_dir_all(&base);
    }

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

    #[test]
    fn a_named_data_directory_holds_the_same_segment() {
        let repo = Path::new("/x/demo-repo");
        assert_eq!(
            repo_state_dir_under(Path::new("/data"), repo).unwrap(),
            Path::new("/data")
                .join(APP_NAMESPACE)
                .join(derive_repo_name(repo).unwrap())
        );
    }

    /// Fails by: the authority not written, not read back, or not rewritten
    /// when the session moves to another repository.
    #[test]
    fn a_session_authority_follows_the_session_between_repositories() {
        let scratch = crate::scratch::scratch("state-session-authority");
        crate::testing::contain_state(&scratch.join("data"));
        let (first, second) = (scratch.join("first"), scratch.join("second"));
        for root in [&first, &second] {
            std::fs::create_dir_all(root).unwrap();
            std::fs::write(root.join("batten.toml"), "").unwrap();
        }
        assert_eq!(recorded_session_authority("s", "batten.toml"), None);
        record_session_authority("s", &first).unwrap();
        assert_eq!(
            recorded_session_authority("s", "batten.toml"),
            Some(first.clone())
        );
        record_session_authority("s", &second).unwrap();
        assert_eq!(recorded_session_authority("s", "batten.toml"), Some(second));
    }
}
