//! The install contract: the path a user installs by resolves the assets a
//! release actually publishes, and no binary is committed.
//!
//! Ported off `mise-tasks/install-check.sh` under CLOUD-1716, for CLOUD-65.
//!
//! # Three statements of one contract, with nothing comparing them
//!
//! `install.sh` resolves an asset name, `[package.metadata.binstall]` resolves a
//! URL, and `mise-tasks/dist.sh` decides what the release is actually called. A
//! rename in `dist` is a build that still passes and an install path that 404s
//! at the only moment anyone would notice, which is on a user's machine.
//!
//! # THE CONTRACT IS PROVED BY ASKING, NOT BY SCRAPING
//!
//! `dist` owns archive naming and `install.sh` owns which targets it installs
//! and what it will ask for, so this asks each of them through the query flags
//! they already publish (`dist --stem`, `install.sh --targets`,
//! `install.sh --asset-name`). The one restatement that cannot be avoided is the
//! binstall manifest — cargo reads TOML, not a shell function — so that template
//! is resolved here and compared against what the release is named.
//!
//! **Spawning those two is a STATED INTERIM.** Both are wave 2's to retire; when
//! they are engine code this asks a function instead of a process, and nothing
//! about the contract changes.
//!
//! # WHY THE VERSION IS PROVED PARAMETRIC RATHER THAN SAMPLED
//!
//! The retired program passed a sample version of `9.9.9` so that a *hardcoded*
//! version in the template could not pass. `dist --stem` reads the crate version
//! from the workspace manifest and takes no version argument — deliberately, so
//! an archive's name cannot lie about its contents — so the sample trick is not
//! available here.
//!
//! What replaces it is stronger rather than weaker: [`parametric`] asks
//! `install.sh` for the same target under two different versions and requires
//! the answers to DIFFER and each to carry its own version. A hardcoded template
//! fails that directly, where the sample only failed it by proxy.
//!
//! # Pointer-only
//!
//! Target names, asset names and paths. Never a byte of a file it judges — which
//! for a committed binary is exactly the payload that must not reach a log.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::Result;
use crate::error::UsageError;

/// One target's expected asset name, as each authority spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    /// The target triple.
    pub target: String,
    /// What `dist` names the archive, extension included.
    pub dist: String,
    /// What `install.sh` will ask the release for.
    pub install: String,
    /// What `[package.metadata.binstall]`'s template resolves to, as a URL.
    pub binstall: String,
}

/// A disagreement between two authorities about one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disagreement {
    /// The release matrix builds it and `install.sh --targets` omits it.
    Unserved(String),
    /// `install.sh --targets` lists it and no matrix leg builds it.
    Unbuilt(String),
    /// `install.sh` asks for a name `dist` does not write.
    AssetName {
        /// The target the two disagree about.
        target: String,
        /// What `dist` writes.
        dist: String,
        /// What `install.sh` asks for.
        install: String,
    },
    /// The binstall template resolves somewhere the release does not publish.
    BinstallUrl {
        /// The target the template was resolved for.
        target: String,
        /// Where the release actually puts it.
        release: String,
        /// Where `cargo binstall` would fetch from.
        binstall: String,
    },
    /// `install.sh` resolves the same name for two different versions.
    NotParametric(String),
    /// An executable binary is committed to the repository.
    CommittedBinary(String),
}

impl Disagreement {
    /// The pointer line this renders as. Rule 4: names and paths, never bytes.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Disagreement::Unserved(target) => {
                format!("{target} — built by the release matrix, absent from install.sh --targets")
            }
            Disagreement::Unbuilt(target) => {
                format!("{target} — listed by install.sh --targets, built by no matrix leg")
            }
            Disagreement::AssetName {
                target,
                dist,
                install,
            } => format!("{target} — dist writes '{dist}', install.sh asks for '{install}'"),
            Disagreement::BinstallUrl {
                target,
                release,
                binstall,
            } => format!("{target} — release has '{release}', binstall would fetch '{binstall}'"),
            Disagreement::NotParametric(target) => format!(
                "{target} — install.sh resolves one name for two versions, so its template does \
                 not carry the version"
            ),
            Disagreement::CommittedBinary(path) => {
                format!("{path} — an executable binary is committed")
            }
        }
    }
}

/// Executable-format magic, judged on bytes rather than on a path convention.
///
/// A convention is what somebody works around. `MZ` carries its third byte
/// because two printable characters alone would fire on ordinary text.
const MAGIC: &[&[u8]] = &[
    &[0x7f, 0x45, 0x4c, 0x46], // ELF
    &[0xfe, 0xed, 0xfa, 0xce], // Mach-O 32, big endian
    &[0xce, 0xfa, 0xed, 0xfe], // Mach-O 32, little endian
    &[0xfe, 0xed, 0xfa, 0xcf], // Mach-O 64, big endian
    &[0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64, little endian
    &[0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
    &[0x4d, 0x5a, 0x90],       // PE
];

/// Whether these opening bytes are an executable's.
#[must_use]
pub fn is_executable(head: &[u8]) -> bool {
    MAGIC.iter().any(|magic| head.starts_with(magic))
}

/// The release matrix, read from the workflow that decides it.
///
/// **One authority, and it is the workflow's.** `release-assets-check` holds the
/// same property: the matrix decides what a release contains, and both gates
/// read it rather than keeping a copy, so a target added there is covered here
/// with no second edit.
///
/// The form is anchored, so a `target:` in prose or under another key cannot
/// widen it.
#[must_use]
pub fn matrix_targets(workflow: &str) -> BTreeSet<String> {
    workflow
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("- target:")?;
            let target = rest.trim();
            let legal = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-');
            (!target.is_empty() && target.chars().all(legal)).then(|| target.to_owned())
        })
        .collect()
}

/// `[package.metadata.binstall]`, read the way cargo-binstall reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binstall {
    /// The `pkg-url` template.
    pub url: String,
    /// The default `pkg-fmt`, or `tgz` where none is declared.
    pub format: String,
    /// Per-target `pkg-fmt` overrides.
    pub overrides: BTreeMap<String, String>,
}

impl Binstall {
    /// The archive suffix a format implies.
    ///
    /// **An unrecognised format is could-not-look, never a guessed suffix.**
    /// Guessing would make the comparison pass over a template nobody checked,
    /// which is the vacuous green this gate exists to prevent.
    #[must_use]
    pub fn suffix(format: &str) -> Option<&'static str> {
        match format {
            "tgz" => Some(".tar.gz"),
            "zip" => Some(".zip"),
            _ => None,
        }
    }

    /// The format that applies to one target.
    #[must_use]
    pub fn format_for(&self, target: &str) -> &str {
        self.overrides
            .get(target)
            .map_or(self.format.as_str(), String::as_str)
    }

    /// Resolve the template for one target and version.
    ///
    /// # Errors
    ///
    /// A `pkg-fmt` this has no suffix rule for.
    pub fn resolve(&self, repo: &str, name: &str, version: &str, target: &str) -> Result<String> {
        let format = self.format_for(target);
        let suffix = Self::suffix(format).ok_or_else(|| {
            UsageError::raise(format!(
                "binstall pkg-fmt '{format}' (target {target}) is one this gate has no suffix rule \
                 for. Add it here in the same change that adds it to the manifest — a guessed \
                 suffix would make the comparison vacuous."
            ))
        })?;
        Ok(self
            .url
            .replace("{ repo }", repo)
            .replace("{ name }", name)
            .replace("{ version }", version)
            .replace("{ target }", target)
            .replace("{ archive-suffix }", suffix))
    }
}

/// Read the binstall table out of a manifest.
///
/// Text rather than a TOML parse, for the reason the retired program gave and
/// which survives the port: the two keys this needs are flat strings, and the
/// override table is read by its own header. A parse would be correct and would
/// also pull the whole manifest shape into a judgement that wants two values.
#[must_use]
pub fn binstall_in(manifest: &str) -> Option<Binstall> {
    let scalar = |key: &str| -> Option<String> {
        manifest.lines().find_map(|line| {
            let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
            Some(rest.trim().trim_matches('"').to_owned())
        })
    };
    let url = scalar("pkg-url")?;

    let mut overrides = BTreeMap::new();
    let mut inside: Option<String> = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(target) = trimmed
            .strip_prefix("[package.metadata.binstall.overrides.")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inside = Some(target.to_owned());
            continue;
        }
        if trimmed.starts_with('[') {
            inside = None;
            continue;
        }
        if let (Some(target), Some(rest)) = (
            inside.as_ref(),
            trimmed
                .strip_prefix("pkg-fmt")
                .and_then(|rest| rest.trim_start().strip_prefix('=')),
        ) {
            overrides.insert(target.clone(), rest.trim().trim_matches('"').to_owned());
        }
    }

    Some(Binstall {
        url,
        format: scalar("pkg-fmt").unwrap_or_else(|| String::from("tgz")),
        overrides,
    })
}

/// One scalar out of a manifest, by key.
#[must_use]
pub fn manifest_scalar(manifest: &str, key: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
        let value = rest.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

/// Whether `install.sh`'s asset template actually carries the version.
///
/// Two versions, one target, and the answers must differ and each carry its own.
/// A template with the version hardcoded — or dropped — fails this directly,
/// where the retired program's sample version only failed it by proxy.
#[must_use]
pub fn parametric(first: (&str, &str), second: (&str, &str)) -> bool {
    let (left_version, left_name) = first;
    let (right_version, right_name) = second;
    left_name != right_name
        && left_name.contains(left_version)
        && right_name.contains(right_version)
}

/// Every tracked path whose opening bytes are an executable's.
///
/// A submodule is a gitlink rather than a file and is that repository's problem,
/// so an unreadable entry is skipped rather than reported: this gate answers
/// "is a binary committed here", and a path it cannot open is not evidence that
/// one is.
#[must_use]
pub fn committed_binaries(root: &Path, tracked: &BTreeSet<String>) -> Vec<String> {
    tracked
        .iter()
        .filter(|path| {
            let Ok(bytes) = std::fs::read(root.join(path)) else {
                return false;
            };
            is_executable(&bytes)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_is_read_from_anchored_entries_only() {
        let workflow = "jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          \
                        - target: x86_64-unknown-linux-gnu\n          - target: aarch64-apple-darwin\n";
        let found = matrix_targets(workflow);
        assert_eq!(found.len(), 2);
        assert!(found.contains("x86_64-unknown-linux-gnu"));
    }

    /// A `target:` in prose or under another key must not widen the matrix.
    #[test]
    fn prose_naming_a_target_does_not_enter_the_matrix() {
        let workflow = "# the - target: key decides what a release contains\n    \
                        description: - target: not-a-leg here\n";
        assert!(matrix_targets(workflow).is_empty());
    }

    #[test]
    fn an_unknown_package_format_has_no_suffix() {
        assert_eq!(Binstall::suffix("tgz"), Some(".tar.gz"));
        assert_eq!(Binstall::suffix("zip"), Some(".zip"));
        assert_eq!(Binstall::suffix("7z"), None);
    }

    #[test]
    fn a_per_target_override_wins_over_the_default() {
        let manifest = "pkg-url = \"{ repo }/x\"\npkg-fmt = \"tgz\"\n\
                        [package.metadata.binstall.overrides.x86_64-pc-windows-msvc]\n\
                        pkg-fmt = \"zip\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert_eq!(table.format_for("x86_64-unknown-linux-gnu"), "tgz");
        assert_eq!(table.format_for("x86_64-pc-windows-msvc"), "zip");
    }

    #[test]
    fn an_override_table_ends_at_the_next_header() {
        let manifest = "pkg-url = \"{ repo }/x\"\n\
                        [package.metadata.binstall.overrides.a]\npkg-fmt = \"zip\"\n\
                        [other]\npkg-fmt = \"7z\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert_eq!(table.format_for("a"), "zip");
        assert_eq!(
            table.overrides.len(),
            1,
            "the `[other]` table is not an override"
        );
    }

    #[test]
    fn the_template_resolves_every_placeholder() {
        let manifest = "pkg-url = \"{ repo }/releases/download/v{ version }/{ name }-{ target }{ archive-suffix }\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        let url = table
            .resolve("https://example/r", "batten", "1.2.3", "t")
            .expect("a known format");
        assert_eq!(
            url,
            "https://example/r/releases/download/v1.2.3/batten-t.tar.gz"
        );
    }

    #[test]
    fn an_unknown_format_refuses_rather_than_guessing() {
        let manifest = "pkg-url = \"{ repo }\"\npkg-fmt = \"7z\"\n";
        let table = binstall_in(manifest).expect("a binstall table");
        assert!(table.resolve("r", "batten", "1.0.0", "t").is_err());
    }

    #[test]
    fn executable_magic_is_recognised_and_text_is_not() {
        assert!(is_executable(&[0x7f, b'E', b'L', b'F', 0x02]));
        assert!(is_executable(&[0x4d, 0x5a, 0x90, 0x00]));
        assert!(!is_executable(b"MZ is how a sentence might start"));
        assert!(!is_executable(b"#!/usr/bin/env bash\n"));
        assert!(!is_executable(b""));
    }

    #[test]
    fn a_version_carrying_template_is_parametric() {
        assert!(parametric(
            ("1.2.3", "batten-1.2.3-t.tar.gz"),
            ("9.9.9", "batten-9.9.9-t.tar.gz")
        ));
    }

    /// The defect the sample version existed to catch, caught directly.
    #[test]
    fn a_hardcoded_version_is_not_parametric() {
        assert!(!parametric(
            ("1.2.3", "batten-0.0.1-t.tar.gz"),
            ("9.9.9", "batten-0.0.1-t.tar.gz")
        ));
    }

    /// And a template that varies but drops the version is caught too — the
    /// names differ, so a difference test alone would pass it.
    #[test]
    fn a_template_that_varies_without_carrying_the_version_is_not_parametric() {
        assert!(!parametric(
            ("1.2.3", "batten-a-t.tar.gz"),
            ("9.9.9", "batten-b-t.tar.gz")
        ));
    }
}
