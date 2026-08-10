//! `config_epoch`: a content hash of the governing config surface (CLOUD-32).
//!
//! Policy changes need to be attributable after the fact. The epoch is a
//! deterministic hash of the files that *govern* a run, so two records carrying
//! the same epoch were produced under provably the same rules, and a record
//! carrying a different one was not.
//!
//! # The tracked set is config, never code
//!
//! Which files govern a repository is that repository's business: an agent
//! settings file, a contributor guide, a hook config — each meaningful in one
//! repository and meaningless in the next. So the set is declared in
//! `batten.toml` as `[epoch] tracked`, and the core carries only the default —
//! `batten.toml` itself, the one file that governs every consumer by definition.
//!
//! That keeps non-negotiable rule 1 true as a *grep*, not merely in spirit: no
//! consumer's identifiers appear anywhere in `crates/batten`, docs included.
//! Batten's own tracked list lives in Batten's own config, as consumer #1 —
//! which is where the worked example belongs.
//!
//! # An unreadable path is a failure, never a skip
//!
//! Skipping a tracked path that cannot be read would compute a *stable* epoch
//! over a surface that changed — the precise failure the value exists to
//! prevent, and a silent one: the hash would still look like a valid answer.
//!
//! It is refused as [`crate::ExitCode::Usage`] (1), naming the path. The
//! `[epoch] tracked` set **is config** — it defaults to `batten.toml` itself —
//! so an unreadable tracked path is unreadable config, which §7 routes to 1.
//! `3` stays for an I/O failure not attributable to the config. The landed
//! precedent is `config_trust`'s unreadable-ref case, which is the same shape:
//! a configured input this binary cannot read, refused by name.
//!
//! # Which authority is hashed
//!
//! The one that actually governed the run. Under `--config-from <ref>`
//! (CLOUD-31) both the tracked list *and* the bytes come from the ref, never
//! from the working tree — an epoch that attributed a run to a config that did
//! not govern it would be worse than none.
//!
//! # Framing
//!
//! [`crate::identity::surface_fingerprint`], not a second hash of the same
//! bytes: one length-prefixed SHA-256 construction serves findings and this
//! alike. Paths are canonicalized, sorted and deduplicated, so authoring order
//! never reaches the value, and the path is hashed as well as the bytes —
//! adding an empty file to the tracked set still moves the epoch, because the
//! *set* is part of what governs.

use std::path::Path;

use anyhow::Result;

use crate::config::Config;
use crate::error::UsageError;
use crate::identity::{canonical_repo_path, surface_fingerprint};
use crate::{git, trust};

/// The tracked path used when a config declares no `[epoch]` table.
///
/// `batten.toml` governs every consumer by definition, so it is the honest
/// floor: an epoch over nothing would be a constant, which attributes nothing.
pub const DEFAULT_TRACKED: &str = crate::config::CONFIG_FILE;

/// The paths whose bytes the epoch covers, canonicalized and sorted.
///
/// # Errors
///
/// Returns a [`crate::UsageError`] when a tracked entry is not a clean
/// repo-relative path — an epoch must never depend on where the repository
/// happens to be checked out.
pub fn tracked_paths(config: &Config) -> Result<Vec<String>> {
    let declared = config
        .epoch
        .as_ref()
        .map(|epoch| epoch.tracked.as_slice())
        .filter(|tracked| !tracked.is_empty());
    let raw: Vec<&str> = match declared {
        Some(tracked) => tracked.iter().map(String::as_str).collect(),
        None => vec![DEFAULT_TRACKED],
    };
    let mut paths: Vec<String> = raw
        .into_iter()
        .map(canonical_repo_path)
        .collect::<Result<_>>()?;
    // Sorted and deduplicated so authoring order — and a path listed twice —
    // cannot change the value. The epoch is a function of the *set*.
    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// The epoch for the authority that governs a run rooted at `dir`.
///
/// `base_ref` selects which authority: `None` reads the working tree, `Some`
/// reads the git ref `--config-from` named — both the tracked list and the
/// bytes, so the value attributes the config that actually governed.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when a tracked path is not a clean
/// repo-relative path, or cannot be read. See the module docs: skipping an
/// unreadable path would forge a stable epoch over a changed surface.
pub fn compute(dir: &Path, base_ref: Option<&str>) -> Result<String> {
    Ok(describe(dir, base_ref)?.0)
}

/// The epoch **and** the surface it covers, from one read of the authority.
///
/// The pair rather than two calls: `config epoch -J` reports both, and resolving
/// the tracked list a second time could read a different authority than the one
/// the digest was taken over — a document whose two halves disagree is worse
/// than either half alone.
///
/// # Errors
///
/// As [`compute`].
pub fn describe(dir: &Path, base_ref: Option<&str>) -> Result<(String, Vec<String>)> {
    let config = authority(dir, base_ref)?;
    let tracked = tracked_paths(&config)?;
    let mut entries = Vec::new();
    for path in &tracked {
        let contents = read_tracked(dir, path, base_ref)?;
        entries.push((path.clone(), contents));
    }
    Ok((surface_fingerprint(&entries).to_hex(), tracked))
}

/// The config whose `[epoch] tracked` list governs, from the same place its
/// bytes will come from.
fn authority(dir: &Path, base_ref: Option<&str>) -> Result<Config> {
    match base_ref {
        Some(reference) => trust::load_base(dir, reference),
        None => crate::config::load(&dir.join(crate::config::CONFIG_FILE)),
    }
}

/// One tracked file's bytes, from the working tree or from the base ref.
///
/// A failure names the path: a refusal the reader cannot act on is barely
/// better than a silent skip.
fn read_tracked(dir: &Path, path: &str, base_ref: Option<&str>) -> Result<Vec<u8>> {
    match base_ref {
        Some(reference) => git::show(dir, reference, path).map(String::into_bytes),
        None => std::fs::read(dir.join(path)).map_err(|err| {
            UsageError::raise(format!(
                "cannot read tracked config-surface path {path}: {err}"
            ))
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::config;

    fn parse(text: &str) -> Config {
        config::parse(text, "test").unwrap()
    }

    /// A scratch repository whose `batten.toml` is `text`.
    fn repo(name: &str, text: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("batten-epoch-tests").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("batten.toml"), text).unwrap();
        dir
    }

    #[test]
    fn the_default_tracked_set_is_the_config_itself() {
        assert_eq!(
            tracked_paths(&parse("version = 1\n")).unwrap(),
            vec!["batten.toml".to_owned()]
        );
    }

    #[test]
    fn an_empty_tracked_list_falls_back_to_the_default() {
        // An epoch over nothing is a constant, which attributes nothing — so an
        // empty list means "unset", not "hash the empty set".
        assert_eq!(
            tracked_paths(&parse("version = 1\n\n[epoch]\ntracked = []\n")).unwrap(),
            vec!["batten.toml".to_owned()]
        );
    }

    #[test]
    fn tracked_paths_are_sorted_and_deduplicated() {
        // Authoring order must not reach the value, or two configs governing the
        // same surface would attribute differently.
        let config = parse("version = 1\n\n[epoch]\ntracked = [\"z\", \"a\", \"z\"]\n");
        assert_eq!(
            tracked_paths(&config).unwrap(),
            vec!["a".to_owned(), "z".to_owned()]
        );
    }

    #[test]
    fn an_absolute_tracked_path_is_refused() {
        // An epoch that depended on a checkout location would differ between two
        // clones of the same commit.
        let config = parse("version = 1\n\n[epoch]\ntracked = [\"/etc/passwd\"]\n");
        assert!(tracked_paths(&config).is_err());
    }

    #[test]
    fn the_same_surface_hashes_the_same_twice() {
        let dir = repo("stable", "version = 1\n");
        assert_eq!(compute(&dir, None).unwrap(), compute(&dir, None).unwrap());
    }

    #[test]
    fn changing_a_tracked_file_changes_the_epoch() {
        let dir = repo("changes", "version = 1\n");
        let before = compute(&dir, None).unwrap();
        fs::write(
            dir.join("batten.toml"),
            "version = 1\nstrictness = \"strict\"\n",
        )
        .unwrap();
        assert_ne!(before, compute(&dir, None).unwrap());
    }

    #[test]
    fn a_line_ending_difference_does_not_change_the_epoch() {
        // The same policy checked out on Windows must attribute identically, or
        // the epoch would distinguish runs governed by the same rules.
        let unix = repo("eol-lf", "version = 1\n");
        let windows = repo("eol-crlf", "version = 1\r\n");
        assert_eq!(
            compute(&unix, None).unwrap(),
            compute(&windows, None).unwrap()
        );
    }

    #[test]
    fn an_unreadable_tracked_path_is_refused_by_name() {
        // The load-bearing refusal: skipping would compute a *stable* epoch over
        // a surface that changed, which looks exactly like a valid answer. It is
        // a Usage error because the tracked set is config.
        let dir = repo(
            "unreadable",
            "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"gone\"]\n",
        );
        let err = compute(&dir, None).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(
            err.to_string().contains("gone"),
            "the refusal must name the path, got: {err}"
        );
    }

    #[test]
    fn the_epoch_is_lowercase_hex_of_the_expected_width() {
        let dir = repo("shape", "version = 1\n");
        let epoch = compute(&dir, None).unwrap();
        assert_eq!(epoch.len(), 64);
        assert!(
            epoch
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
}
