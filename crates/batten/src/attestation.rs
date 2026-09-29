//! `batten record attestation`: a release's attestation posture and what the
//! verifier says about each archive's binary (CLOUD-583, retiring
//! `[tasks.attestation-record]` under CLOUD-843).
//!
//! # What moved in, and what stays a spawn
//!
//! The retired body did five things: it probed the forge's attestations endpoint
//! with an all-zeros digest, resolved a tag, downloaded the release's archives,
//! unpacked each one, and ran the verifier over the BINARY inside. The probe and
//! the latest-release read are REST reads now, through [`crate::rest`] — the
//! typed status is the whole point of the probe, and the body re-parsed a status
//! line out of `gh api -i` with `awk` to get it. A `.tar.gz` is unpacked in
//! process with the `flate2`/`tar` pair `provision.rs` already uses.
//!
//! Three steps stay spawns, through [`crate::exec::piped_argv`] and so with no
//! `Command` of this module's own: the release download and the verification
//! itself, both the VERIFIER program's (it is the one client that verifies a
//! sigstore bundle, and it downloads through the same credential it verifies
//! with), and a `.zip` unpack, for which this crate carries no reader.
//!
//! # What is NOT here: the decision
//!
//! `posture 404` and an `unverified` archive are READINGS. Whether they refuse a
//! release is the `supply-chain` preset's `attestation-is-verified.rego`. The
//! whole design is the distinction the retired program's header names: the
//! verifier refuses both an artifact with no provenance and every artifact on a
//! platform that offers none, and only the probe tells those apart.
//!
//! # Could-not-look writes nothing
//!
//! No credential (a 404 could not be told from a denial), no forge remote, an
//! unreachable endpoint, a posture that is neither 200 nor 404, no tag, a failed
//! download, an archive that will not unpack, a verifier that will not start:
//! each REMOVES any stale record and answers exit 3. An absent record is the
//! module's silence; a record written over a partial look would be a short
//! archive list the module reads as complete — the defect the body's own
//! "buffered, then recorded" comment was about.
//!
//! # Pointer-only (rule 4)
//!
//! An archive's NAME and one of three closed tokens. The verifier's own report
//! names the attesting workflow and signer, and is dropped at the spawn.
//!
//! # Rule 1
//!
//! The binary's name and the verifier program are the CALLER's (`--binary`,
//! `--verifier`); the record family is this verb's own name for what it writes.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::exec::Diagnostics;
use crate::exit::ExitCode;

// The producer's mutation rows. Each breaks one arm that turns a WORLD fact into
// a recorded reading, and each is caught by the compiled-binary case it names —
// the module deciding over the record cannot see a producer that lied to it.
//MUTANT-SUITE crates/batten/tests/it/attestation.rs
//MUTANT unverified-read-as-verified|s@^                    Some(_) => "unverified",$@                    Some(_) => "verified",@|the_producer_records_an_archive_the_verifier_refuses
//MUTANT gap-probe-unread|s@^        404 => return Produced@        999 => return Produced@|a_platform_gap_is_recorded_as_a_gap_and_judges_nothing
//MUTANT credential-unchecked|s@^    if crate::rest::declared_credential().is_none() {$@    if false {@|no_credential_is_could_not_look_and_removes_a_stale_record

/// The verb, as a could-not-look line names it.
const VERB: &str = "record attestation";

/// The record family this verb writes, projected at
/// `input.tree.records["attestation"]`.
pub const FAMILY: &str = "attestation";

/// The verifier when `--verifier` names none: the forge's own client, which is
/// the one program that verifies the bundles this forge attaches.
const DEFAULT_VERIFIER: &str = "gh";

/// The probe digest. Where attestation IS available an unknown digest answers
/// 200 with an empty list; where it is not, the resource itself answers 404. So
/// this is a question about the REPOSITORY, never about any file.
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The archive suffixes a release publishes, in the order the retired body
/// globbed them: every `.tar.gz`, then every `.zip`.
const ARCHIVES: [&str; 2] = [".tar.gz", ".zip"];

/// What one run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Produced {
    /// The whole record body, closed and complete.
    Recorded(String),
    /// What could not be asked, as a pointer. Nothing is recorded.
    CouldNotLook(String),
}

fn could(why: &str) -> Produced {
    Produced::CouldNotLook(why.to_owned())
}

/// `batten record attestation [<tag>] --binary <name> [--verifier <program>]`.
///
/// # Errors
///
/// A [`crate::UsageError`] for a `--binary` that is not one path component, or a
/// checkout with no branch to key the record on; an internal error when the
/// store cannot be written. Could-not-look is not an error: it removes any stale
/// record, names what could not be asked on `err`, and answers
/// [`ExitCode::Internal`].
pub fn run(
    tag: Option<&str>,
    binary: &str,
    verifier: Option<&str>,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let binary = crate::record::safe_component("binary", binary)?;
    let verifier = verifier
        .map(str::trim)
        .filter(|program| !program.is_empty())
        .unwrap_or(DEFAULT_VERIFIER);
    let root = Path::new(".");
    match produce(root, tag, &binary, verifier) {
        Produced::Recorded(body) => {
            crate::record::store_named(VERB, FAMILY, &body)?;
            Ok(ExitCode::Success)
        }
        Produced::CouldNotLook(why) => {
            crate::record::clear_named(VERB, FAMILY)?;
            writeln!(err, "batten: {VERB}: could not look: {why}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// The reading, from the probe to the last archive's verdict.
fn produce(root: &Path, tag: Option<&str>, binary: &str, verifier: &str) -> Produced {
    // THE CREDENTIAL FIRST, before anything is asked. Unauthenticated, a private
    // repository answers 404 on the probe — which is the platform-gap answer — so
    // a run with no credential would record a gap that is really a denial and
    // silence every finding.
    if crate::rest::declared_credential().is_none() {
        return could(
            "no declared forge credential is set, so a 404 could not be told from a denial",
        );
    }
    let Some(slug) = crate::repo_slug(root) else {
        return could("no forge remote names a repository to ask about");
    };
    let probe = format!("repos/{slug}/attestations/sha256:{ZERO_DIGEST}");
    let Some(answer) = crate::rest::get(&probe, None) else {
        return could("the attestations endpoint could not be reached");
    };
    match answer.status {
        404 => return Produced::Recorded("posture\t404\n".to_owned()),
        200 => {}
        other => {
            return could(&format!(
                "the attestations endpoint answered {other}, neither 200 nor 404, so the \
                 platform's posture is unknown"
            ));
        }
    }
    let tag = match tag.map(str::trim).filter(|tag| !tag.is_empty()) {
        Some(tag) => tag.to_owned(),
        None => match latest_tag(&slug) {
            Some(tag) => tag,
            None => return could("no tag was given and no latest release could be read"),
        },
    };
    let scratch = std::env::temp_dir().join(format!("batten-attestation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    if std::fs::create_dir_all(&scratch).is_err() {
        return could("no scratch directory could be made to download into");
    }
    let verdicts = archive_verdicts(root, &scratch, &slug, &tag, binary, verifier);
    let _ = std::fs::remove_dir_all(&scratch);
    match verdicts {
        Ok(lines) => Produced::Recorded(format!("posture\t200\n{lines}")),
        Err(why) => Produced::CouldNotLook(why),
    }
}

/// The latest release's tag, or `None` where it could not be read.
fn latest_tag(slug: &str) -> Option<String> {
    let answer = crate::rest::get(&format!("repos/{slug}/releases/latest"), None)?;
    if !answer.is_reading() {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_str(&answer.body).ok()?;
    parsed
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
}

/// A path as an argv word.
fn word(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Download the release's archives into `scratch` and judge each one's binary.
///
/// `Err` is could-not-look, and it abandons the WHOLE record rather than the
/// one line: a posture line plus a short archive list is a window the module
/// reads as complete.
fn archive_verdicts(
    root: &Path,
    scratch: &Path,
    slug: &str,
    tag: &str,
    binary: &str,
    verifier: &str,
) -> std::result::Result<String, String> {
    let downloads = scratch.join("download");
    let argv: Vec<String> = vec![
        verifier.to_owned(),
        "release".to_owned(),
        "download".to_owned(),
        tag.to_owned(),
        "--repo".to_owned(),
        slug.to_owned(),
        "--dir".to_owned(),
        word(&downloads),
        "--pattern".to_owned(),
        format!("*{}", ARCHIVES[0]),
        "--pattern".to_owned(),
        format!("*{}", ARCHIVES[1]),
    ];
    match crate::exec::piped_argv(root, &argv, "", Diagnostics::Drop, &[]) {
        Some((0, _)) => {}
        _ => {
            return Err(format!(
                "could not download {tag}'s archives, so their provenance is unread"
            ));
        }
    }
    let listing = std::fs::read_dir(&downloads)
        .map_err(|_| format!("could not list {tag}'s downloaded archives"))?;
    let mut names: Vec<String> = Vec::new();
    for entry in listing.flatten() {
        if !entry.path().is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && ARCHIVES.iter().any(|suffix| name.ends_with(suffix))
        {
            names.push(name.to_owned());
        }
    }
    // Every `.tar.gz` before every `.zip`, each by name: the retired body's two
    // globs, so the record's line order is the one it wrote.
    names.sort_by_key(|name| (name.ends_with(ARCHIVES[1]), name.clone()));

    let mut lines: Vec<String> = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let archive = downloads.join(name);
        let into = scratch.join(format!("x-{index}"));
        std::fs::create_dir_all(&into)
            .map_err(|_| format!("could not make a directory to extract {name} into"))?;
        let found = if name.ends_with(ARCHIVES[1]) {
            unzip(root, &archive, &into, binary)
        } else {
            untar(&archive, &into, binary)
        }
        .map_err(|()| format!("could not extract {name}, so its provenance is unread"))?;
        let verdict = match found {
            None => "no-binary",
            Some(path) => {
                let verify: Vec<String> = vec![
                    verifier.to_owned(),
                    "attestation".to_owned(),
                    "verify".to_owned(),
                    word(&path),
                    "--repo".to_owned(),
                    slug.to_owned(),
                ];
                match crate::exec::piped_argv(root, &verify, "", Diagnostics::Drop, &[]) {
                    Some((0, _)) => "verified",
                    Some(_) => "unverified",
                    None => {
                        return Err(format!(
                            "the verifier could not be run over {name}'s binary"
                        ));
                    }
                }
            }
        };
        lines.push(format!("archive\t{name}\t{verdict}\n"));
    }
    Ok(lines.concat())
}

/// Whether `candidate` is the binary: its bare name, or with Windows' suffix.
fn is_binary(candidate: &str, binary: &str) -> bool {
    candidate == binary || candidate.strip_suffix(".exe") == Some(binary)
}

/// Unpack the binary out of a gzipped tarball, in process.
///
/// `Ok(None)` is an archive that unpacked and carries no binary — a RELEASE
/// verdict. `Err` is an archive that would not unpack, which is could-not-look:
/// the retired body discarded that status with `|| true` once, and a corrupt
/// archive then read as `no-binary`.
fn untar(archive: &Path, into: &Path, binary: &str) -> std::result::Result<Option<PathBuf>, ()> {
    let file = std::fs::File::open(archive).map_err(|_| ())?;
    let mut unpacked = tar::Archive::new(flate2::read::GzDecoder::new(file));
    for entry in unpacked.entries().map_err(|_| ())? {
        let mut entry = entry.map_err(|_| ())?;
        let path = entry.path().map_err(|_| ())?.into_owned();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_binary(name, binary) {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|_| ())?;
        let out = into.join(name);
        std::fs::write(&out, bytes).map_err(|_| ())?;
        return Ok(Some(out));
    }
    Ok(None)
}

/// Unpack a `.zip` with the system's `unzip`, then find the binary in it.
fn unzip(
    root: &Path,
    archive: &Path,
    into: &Path,
    binary: &str,
) -> std::result::Result<Option<PathBuf>, ()> {
    let argv: Vec<String> = vec![
        "unzip".to_owned(),
        "-q".to_owned(),
        "-o".to_owned(),
        word(archive),
        "-d".to_owned(),
        word(into),
    ];
    match crate::exec::piped_argv(root, &argv, "", Diagnostics::Drop, &[]) {
        Some((0, _)) => Ok(find(into, binary)),
        _ => Err(()),
    }
}

/// The first file under `dir` named as the binary, walking in name order so the
/// answer is the same on every run.
fn find(dir: &Path, binary: &str) -> Option<PathBuf> {
    let mut entries: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        entries.push(entry.path());
    }
    entries.sort();
    for path in &entries {
        if path.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| is_binary(name, binary))
        {
            return Some(path.clone());
        }
    }
    entries
        .iter()
        .filter(|path| path.is_dir())
        .find_map(|path| find(path, binary))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{find, is_binary, untar};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("batten-attestation-unit-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A gzipped tarball carrying `entries` as `(path, bytes)`.
    fn tarball(dir: &std::path::Path, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        let path = dir.join("release.tar.gz");
        let file = std::fs::File::create(&path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    #[test]
    fn the_binary_is_matched_bare_or_with_the_windows_suffix_and_nothing_else() {
        assert!(is_binary("tool", "tool"));
        assert!(is_binary("tool.exe", "tool"));
        assert!(!is_binary("tool.sha256", "tool"));
        assert!(!is_binary("tools", "tool"));
    }

    /// THE SUBJECT IS THE BINARY, NOT THE ARCHIVE, found however deep the
    /// archive nests it.
    #[test]
    fn a_nested_binary_is_unpacked_out_of_the_tarball() {
        let dir = scratch("nested");
        let archive = tarball(
            &dir,
            &[
                ("tool-1.0/README", &b"read me"[..]),
                ("tool-1.0/tool", &b"ELF"[..]),
            ],
        );
        let into = dir.join("x");
        std::fs::create_dir_all(&into).unwrap();
        let found = untar(&archive, &into, "tool").unwrap().expect("the binary");
        assert_eq!(std::fs::read(found).unwrap(), b"ELF");
    }

    /// An archive that unpacks and carries no binary is a RELEASE verdict, and
    /// one that will not unpack is could-not-look: the two must not collapse.
    #[test]
    fn no_binary_and_a_corrupt_archive_are_different_answers() {
        let dir = scratch("absent");
        let archive = tarball(&dir, &[("README", &b"read me"[..])]);
        assert_eq!(untar(&archive, &dir, "tool"), Ok(None));
        let corrupt = dir.join("corrupt.tar.gz");
        std::fs::write(&corrupt, b"not a gzip stream").unwrap();
        assert_eq!(untar(&corrupt, &dir, "tool"), Err(()));
    }

    #[test]
    fn find_walks_nested_directories_for_the_binary() {
        let dir = scratch("find");
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/tool.exe"), b"PE").unwrap();
        assert_eq!(find(&dir, "tool"), Some(dir.join("a/b/tool.exe")));
        assert_eq!(find(&dir, "other"), None);
    }
}
