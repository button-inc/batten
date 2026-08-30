//! The programs the project's pin puts on `PATH` (CLOUD-1028).
//!
//! # The defect this fact exists for
//!
//! Measured 2026-08-23: a session reproducing an in-gate failure ran
//! `./tests/bats/bin/bats --filter … tests/land.bats`. That invocation reaches
//! the same binary the declared task reaches, with the same argv — what it drops
//! is the pin's ENVIRONMENT, so `CI_REQUIRED_CHECKS` was unset and sixty runs
//! died on the unset variable rather than on the assertion under test. An
//! unset-variable death under `set -u` is indistinguishable from an assertion
//! failure at the resolution a caller reads, so the tool most likely to be
//! reached for when investigating a flaky gate is the one that manufactures a
//! fake one. Three false claims and one false Urgent row followed.
//!
//! # Why the set is resolved and not written down
//!
//! A `shape` row matches its program token by equality, so covering the defect
//! with rows means one literal per spelling — and the set is not a repository's
//! to state: every consuming project pins different programs, and the set moves
//! whenever the manifest or the lockfile does. So it is asked for.
//!
//! # What "the pin provides" means, measured rather than assumed
//!
//! **Not the install list.** A pin can report the directories of the tools it
//! INSTALLED — 62 program names on the checkout this was measured against, and
//! the runner from the incident above is not one of them, because it is a git
//! submodule the manifest puts on `PATH` rather than a tool the pin installs. A
//! fact built on the install list would have missed the exact invocation that
//! produced the incident.
//!
//! What the pin actually provides is the difference between the `PATH` it
//! composes and the one this process already has: 49 names here, `bats` among
//! them. Names in directories the ambient `PATH` already carries are excluded by
//! construction — a program you would have reached anyway is not one the pin
//! supplies, and `cargo` drops out for exactly that reason (its directory is
//! ambient, and `no-bare-cargo` covers it by name).
//!
//! **Executable regular files only.** An install directory is often an extracted
//! archive root, so `LICENSE`, `README.md`, `docs/` and `man/` sit beside the
//! binary. Six of the 49 were that; a set carrying them would refuse
//! `README.md` as though it were a program.
//!
//! # Two costs, and the split is the whole design
//!
//! Resolving this runs a program, which is [`crate::facts::Cost::Effect`], and
//! an `Effect` fact may not be resolved on the mediated path — that is the fact
//! model's own statement, not a preference. So the answer is resolved ONCE, off
//! the hot path, and the mediated call reads what was recorded:
//!
//! * [`refresh`] asks the pin and records. It spawns.
//! * [`cached`] reads the record and never spawns, which is what makes the fact
//!   [`crate::facts::Cost::Read`] where a call is being adjudicated.
//!
//! # The key is what can invalidate the answer, and THE PIN NAMES IT
//!
//! The record is filed under a digest of the pin's own configuration files, so a
//! session that adds a tool changes one of them, the next read misses, and the
//! next refresh re-resolves. Keying on a timestamp instead would either re-spawn
//! on a clock nobody set or serve a stale set after an install, and both are
//! answers about the wrong thing.
//!
//! **Which files those are is asked, never written down.** Non-negotiable rule 1
//! forbids a consuming project's artifact names inside this crate, and
//! `no_artifact_name_reaches_the_core` is the gate that computes it — so a
//! `const` naming a manifest and a lockfile is unwritable here, and the obvious
//! escape (a `sources` list on the enabling row) is refused one layer down:
//! `rules.rs` denies `sources` on a `scope = "mediated_call"` row at LOAD,
//! because that column is what a tree row hands its bundle. Both refusals point
//! the same way. The pin already knows which files configure it, so [`configs`]
//! asks it, and the answer is recorded beside the set it keys.
//!
//! **Plus their siblings, re-read every time.** A pin's *lockfile* is not one of
//! the files it lists as configuration, and a lockfile moving without its
//! manifest — an install resolving a floating version — is exactly the change
//! this key exists to catch. So each reported config contributes every file
//! beside it sharing its name up to the first `.`, computed at READ time rather
//! than stored: a lockfile that appears after the record was written changes the
//! key, instead of being invisible until the next session.
//!
//! # Every failure is could-not-look, and could-not-look allows
//!
//! No pin, no checkout, a spawn that fails, a record under a different key, a
//! composed `PATH` that adds nothing: all [`Look::CouldNotLook`]. A gate that
//! refuses where it cannot see becomes the reason work cannot proceed, and this
//! one would refuse every program in the project.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::facts::Look;

/// The programs the pin provides, or could-not-look.
///
/// A named alias rather than a bare `Look<BTreeSet<String>>` for the reason
/// [`crate::hook::ReceiptFacts`] carries one: the three-valued answer is the
/// point, and a reader should see it named at every call site.
pub type PinnedFacts = Look<BTreeSet<String>>;

/// The store, beside `batten-receipts/` and deliberately not inside it.
///
/// `pub(crate)` for [`key`]'s reason: [`crate::taskset`] files a second record
/// beside this one, and two spellings of one directory is a second thing to
/// drift.
///
/// A receipt attests that a DECISION was taken and is keyed to the subject it
/// was taken about; this is a memoised reading of the world, keyed to what can
/// change it. Filing the second under the first's name would put a fact where
/// every reader expects a claim.
pub(crate) const STORE: &str = "batten-facts";

/// The record's name inside [`STORE`].
const RECORD: &str = "pinned-programs";

/// The mediator this fact asks. One name, matching [`crate::rules::RequireVia`]'s
/// single variant — a second spelling of "which pin" is a second thing to drift.
const MEDIATOR: &str = "mise";

/// The record, as one writer writes it and one reader reads it.
///
/// A struct rather than a hand-rolled line format for the reason CLOUD-1093
/// measured one layer over: a fixture that spells the bytes itself passes while
/// the real writer and the real reader disagree. Serde owns both directions, so
/// there is one shape and no second parser.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    /// The digest of the pin's configuration at the moment the set was resolved.
    key: String,
    /// The files the pin named as configuring it, so the reader can recompute
    /// the key without asking the pin again.
    configs: Vec<PathBuf>,
    /// The answer.
    programs: BTreeSet<String>,
}

/// Every file that decides the key, given the configs the pin reported.
///
/// Each reported path contributes itself and every file beside it whose name
/// agrees up to the first `.` — the lockfile beside the manifest, and any local
/// overlay beside both. Sorted and deduplicated, because a key that depended on
/// directory order would miss on a tree nothing changed.
pub(crate) fn keyed_paths(configs: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut out: BTreeSet<PathBuf> = configs.iter().cloned().collect();
    for config in configs {
        let (Some(dir), Some(stem)) =
            (config.parent(), config.file_name().and_then(|n| n.to_str()))
        else {
            continue;
        };
        let prefix = stem.split('.').next().unwrap_or(stem);
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.split('.').next() == Some(prefix) && entry.path().is_file() {
                out.insert(entry.path());
            }
        }
    }
    out
}

/// The digest the record is filed under, or `None` where nothing could be read.
///
/// `pub(crate)` because [`crate::taskset`] files its own record under the SAME
/// key (CLOUD-856): both are memoised readings of the toolchain manifest, so two
/// derivations would be two answers to "has the manifest moved" that can
/// disagree — and the one that says "no" wins by being read first.
///
/// An absent member contributes a stable token rather than voiding the key — a
/// project with a manifest and no lockfile is a real project. Every member
/// absent is a different answer, and is `None`: a key over nothing would file
/// every project's set under one name.
pub(crate) fn key(configs: &[PathBuf]) -> Option<String> {
    let mut material: Vec<u8> = Vec::new();
    let mut any = false;
    for path in keyed_paths(configs) {
        material.extend_from_slice(path.to_string_lossy().as_bytes());
        match std::fs::read(&path) {
            Ok(bytes) => {
                any = true;
                material.extend_from_slice(&bytes);
            }
            // An absent member contributes a stable token, so a lockfile that
            // appears LATER changes the key rather than being absorbed by it.
            Err(_) => material.push(b'-'),
        }
    }
    // The crate's one hex spelling, reused rather than re-derived: a second
    // renderer is a second thing to drift, and this digest is compared only
    // against itself.
    any.then(|| crate::provision::digest(&material))
}

/// Where the record lives for `root`'s checkout.
fn record_path(root: &Path) -> Option<PathBuf> {
    crate::git::git_dir(root)
        .ok()
        .map(|dir| dir.join(STORE).join(RECORD))
}

/// The recorded answer, or could-not-look. Never spawns.
///
/// This is the reading the mediated path takes. A record whose key does not
/// match the pin's configuration as it stands NOW is not a stale answer to be
/// trusted a little — it is an answer about a different toolchain, and reading
/// it would be the fact model's own could-not-look-as-a-pass failure.
#[must_use]
pub fn cached(root: &Path) -> PinnedFacts {
    let Some(path) = record_path(root) else {
        return Look::CouldNotLook;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Look::CouldNotLook;
    };
    let Ok(record) = serde_json::from_str::<Record>(&text) else {
        return Look::CouldNotLook;
    };
    // Recomputed from the RECORDED configs rather than by asking the pin again,
    // which is what keeps this function free of the `Effect` its own doc says it
    // may not pay.
    if key(&record.configs).as_ref() != Some(&record.key) {
        return Look::CouldNotLook;
    }
    // An EMPTY recorded set is could-not-look rather than "the pin provides
    // nothing". The only way a real pin adds no program is that the composed
    // PATH matched the ambient one, which `resolve` already refuses to call an
    // answer; a record that says otherwise is one this code did not write.
    if record.programs.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(record.programs)
    }
}

/// Ask the pin, record the answer, and return it. Spawns.
///
/// Called where an `Effect` is admissible — at session start, once — so that
/// every mediated call afterwards pays a file read. A failure to record is not a
/// failure to answer: the caller still gets the resolved set, and the next
/// session resolves again.
#[must_use]
pub fn refresh(root: &Path) -> PinnedFacts {
    let resolved = resolve(root);
    if let Look::Is(programs) = &resolved {
        // Discarded deliberately: a record that could not be written is not a
        // failure to answer. The caller still gets the resolved set, and the next
        // session resolves again — which is the same could-not-look the reader
        // already handles.
        let _recorded = record(root, &configs(root), programs);
    }
    resolved
}

/// Write `programs` as `root`'s record, keyed to `configs` as they stand.
///
/// Public because the alternative is a test that hand-spells the record's
/// format: a fixture writing those bytes itself would pass while the real writer
/// and the real reader disagreed, which is the shape that let a whole suite pass
/// over a receipt no producer could write (CLOUD-1093). One writer, one reader,
/// and the test drives both.
///
/// Returns whether the record was written. A `false` is not an error the caller
/// must handle — the fact simply answers could-not-look next time — but it is the
/// difference between "recorded" and "resolved", and a caller asserting the first
/// should not have to infer it.
#[must_use]
pub fn record(root: &Path, configs: &[PathBuf], programs: &BTreeSet<String>) -> bool {
    let (Some(key), Some(path)) = (key(configs), record_path(root)) else {
        return false;
    };
    let record = Record {
        key,
        configs: configs.to_vec(),
        programs: programs.clone(),
    };
    let Ok(body) = serde_json::to_string(&record) else {
        return false;
    };
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return false;
    }
    std::fs::write(path, body).is_ok()
}

/// The files the pin reports as configuring it. Spawns.
///
/// Asked rather than assumed, which is the whole of this module's answer to
/// non-negotiable rule 1: the core learns which files key the answer from the
/// thing that reads them, so no consuming project's artifact name is written
/// here. An empty answer is a real one — a directory the pin does not configure
/// — and produces no key, hence no record.
#[must_use]
pub fn configs(root: &Path) -> Vec<PathBuf> {
    let Some(out) = mediator(root, &["config", "ls", "--json"]) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return Vec::new();
    };
    parsed
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("path").and_then(serde_json::Value::as_str))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Run the mediator and hand back its stdout, or `None` on any failure.
///
/// One spawn site for both questions this module asks, so the `Cost::Effect`
/// classification has exactly one place to be true of.
fn mediator(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this fact IS Cost::Effect — resolving it runs the mediator, which is the classification rather than an accident of it (CLOUD-1028). It is why `cached` exists and why the mediated path never reaches this function"
    )]
    let spawned = std::process::Command::new(MEDIATOR)
        .args(args)
        .current_dir(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;
    spawned.status.success().then_some(spawned.stdout)
}

/// The composed environment, as the mediator reports it.
fn composed_path(root: &Path) -> Option<String> {
    let parsed: serde_json::Value =
        serde_json::from_slice(&mediator(root, &["env", "--json"])?).ok()?;
    parsed
        .get("PATH")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

/// Resolve the set by asking the mediator.
fn resolve(root: &Path) -> PinnedFacts {
    let Some(composed) = composed_path(root) else {
        return Look::CouldNotLook;
    };
    let ambient = std::env::var("PATH").unwrap_or_default();
    let added = added_directories(&composed, &ambient);
    // NOTHING ADDED IS COULD-NOT-LOOK, NOT AN EMPTY ANSWER. The honest reading
    // of an identical composed and ambient PATH is that this process is already
    // running under the pin, so the difference cannot see what the pin supplies
    // — which is a failure to look, and reporting it as "the pin provides
    // nothing" would silently disarm every predicate built on this fact.
    if added.is_empty() {
        return Look::CouldNotLook;
    }
    let programs = programs_in(&added);
    if programs.is_empty() {
        Look::CouldNotLook
    } else {
        Look::Is(programs)
    }
}

/// The directories the composed `PATH` has and the ambient one does not.
///
/// Pure, and separated from the spawn for that reason: the interesting decision
/// here is the difference, and a test that had to install a toolchain to reach
/// it would be asserting its own premise (`.claude/rules/rust.md`).
fn added_directories(composed: &str, ambient: &str) -> Vec<PathBuf> {
    let already: BTreeSet<&str> = ambient.split(':').filter(|dir| !dir.is_empty()).collect();
    composed
        .split(':')
        .filter(|dir| !dir.is_empty() && !already.contains(dir))
        .map(PathBuf::from)
        .collect()
}

/// The executable regular files in `dirs`, by name.
///
/// The executable bit is read as METADATA, never enforced: this process may well
/// be root, where a permission test decides nothing. What it distinguishes is a
/// program from the `LICENSE` and `README.md` an extracted archive leaves beside
/// one — six of the 49 names on this checkout.
fn programs_in(dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            // A symlink is followed rather than skipped: a shim directory is
            // links to real binaries, and reading the link as "not a file" would
            // empty the set on exactly the layout the pin most often produces.
            if kind.is_dir() {
                continue;
            }
            if !executable(&entry.path()) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

/// Does any execute bit stand on this path?
#[cfg(unix)]
fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

/// Windows has no execute bit; a regular file on a `PATH` directory is the
/// closest honest reading, and the alternative — an extension allowlist — is a
/// second authority over what counts as a program.
#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_difference_is_what_the_pin_adds() {
        let added = added_directories("/pin/bin:/usr/bin:/tests/bats/bin", "/usr/bin");
        assert_eq!(
            added,
            vec![PathBuf::from("/pin/bin"), PathBuf::from("/tests/bats/bin")]
        );
    }

    #[test]
    fn an_ambient_directory_is_never_added() {
        // `cargo`'s directory is on both here, which is why the fact does not
        // carry cargo and `no-bare-cargo` still does.
        assert!(added_directories("/root/.cargo/bin", "/root/.cargo/bin:/usr/bin").is_empty());
    }

    #[test]
    fn an_empty_component_is_not_a_directory() {
        // A trailing or doubled `:` is a real spelling of PATH and means "this
        // directory", which is not something the pin added.
        assert!(added_directories(":", "").is_empty());
        assert_eq!(
            added_directories("/pin/bin::", ""),
            vec![PathBuf::from("/pin/bin")]
        );
    }
}
