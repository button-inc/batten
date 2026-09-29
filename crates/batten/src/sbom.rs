//! `batten sbom`: the SPDX and `CycloneDX` inventories of a tree or of a built
//! binary (CLOUD-262, CLOUD-263, CLOUD-580, CLOUD-628, CLOUD-629, CLOUD-630,
//! CLOUD-664, CLOUD-667), retiring five inline task bodies under CLOUD-843.
//!
//! # It decides nothing
//!
//! Every pass here derives or enriches a document, or reduces one to counts a
//! module decides over. Whether an inventory describes the tree is the
//! consumer's inventory module over `--record`; whether a binary's inventory
//! catalogs something is the `supply-chain` preset over the binary record;
//! whether the document is usable is the consumer's conformance module over
//! `--conformance`. What stays here is **could-not-look**, and every such path is
//! exit 3 with nothing written behind it: no version, a tool that cannot run, a
//! lockfile package absent from the registry cache, an unreadable table.
//!
//! # The two spawns are inventory rows, and why they stay spawns
//!
//! `syft` catalogs the tree and `cargo` resolves the lockfile's metadata and
//! unpacks the pinned sources the copyright statements are read from. Both are
//! the consumer's declared tools, and what each answers IS the inventory — the
//! classification `hk.rs` records for its own pinned tool. Neither is on an
//! evaluation path, and the verb is `write`.
//!
//! # Consumer facts come from `[sbom]`
//!
//! The subject's name, the two output directories, the scan's exclusions, the
//! licence table's path, the tool row `--record` keys under and the conformance
//! checker's family and standards are the consumer's (non-negotiable rule 1). The
//! engine owns the grammar: component identity, the supplier/originator split,
//! the anchored copyright holder line, and the licence spelling.
//!
//! # Component identity (CLOUD-664)
//!
//! The triple `(name, version, purl)`: syft emits a component per REFERENCE
//! SITE, so duplicates merge onto the lexicographically first id and
//! relative-path or `UNKNOWN`-version entries drop. THE SUBJECT IS NEVER MERGED
//! — resolved from the document's own DESCRIBES edge, because since syft 1.50.0
//! it shares its triple with the workspace member, and a naive dedupe eats it.
//!
//! # Supplier, originator, copyright, licence
//!
//! The supplier is the lockfile's resolved source (only the crates.io index
//! maps to `Organization: crates.io`; anything else is NOASSERTION), the
//! originator the first `authors` entry or honestly NOASSERTION, keyed on name
//! and version, never the purl, which percent-encodes `+`. Copyright is read from
//! the bytes `Cargo.lock` pins, so the registry cache's AVAILABILITY is a hard
//! failure rather than a silent NOASSERTION; only an anchored holder line
//! counts, licence files first, then the most frequent line in the tree, and the
//! residue is `NONE`. Licence is `cargo metadata`'s, with the deprecated `/`
//! spelling rewritten to ` OR `. Pinned actions take licence and copyright from
//! the consumer's table.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cli::SbomRequest;
use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::resolve::Overrides;

// THE PRODUCER'S MUTATIONS, carried from `[tasks.sbom]`'s twelve bash rows onto
// the Rust that replaced it, plus the arms the verb added. The normaliser and the
// enrichment are where it can silently stop doing its job, so removing each pass
// is what shows the tier discriminates.
//MUTANT-SUITE crates/batten/tests/it/sbom_producer.rs
//MUTANT sbom-skips-spdx-normalization|s@^    let mut spdx_doc = normalise_spdx.spdx_doc.;$@    let mut spdx_doc = spdx_doc;@|one_action_referenced_twice_yields_one_component
//MUTANT sbom-skips-cdx-normalization|s@^    let mut cdx_doc = normalise_cdx.cdx_doc.;$@    let mut cdx_doc = cdx_doc;@|the_cyclonedx_graph_is_rewritten_too
//MUTANT sbom-dedupes-the-subject|s@^            if id.is_empty.. .. Some.id. == subject.as_str.. .$@            if id.is_empty() {@|the_guard_the_document_still_describes_its_subject
//MUTANT sbom-skips-entity-enrichment|s@^    enrich_spdx.&mut spdx_doc, &entities.;$@@|the_documents_own_subject_carries_the_workspace_supplier
//MUTANT sbom-drops-the-originator|s@^    format!."Organization: .name.".$@    String::from(NOASSERTION)@|a_crate_with_authors_gets_both_and_the_originator_is_the_author
//MUTANT sbom-copyright-residue-is-noassertion|s@^                _ => NONE.to_owned..,$@                _ => NOASSERTION.to_owned(),@|the_boilerplate_trap_an_apache_license_yields_none
//MUTANT sbom-tolerates-an-absent-source|s@^    if missing != 0 .$@    if false {@|a_lockfile_package_absent_from_the_cache_is_a_hard_failure
//MUTANT sbom-keeps-the-slash-license-form|s@^    slash.replace_all.raw, " OR ".\.into_owned..$@    raw.to_owned()@|the_deprecated_slash_spelling_is_rewritten_to_or
//MUTANT sbom-invents-a-missing-license|s@^        return NOASSERTION.to_owned..;$@        return "Apache-2.0".to_owned();@|honest_absence_an_empty_manifest_license_leaves_noassertion
//MUTANT sbom-skips-the-actions-table|s@^        actions_spdx.&mut spdx_doc, actions.;$@@|a_mapped_action_carries_its_license_and_copyright
//MUTANT sbom-reads-a-short-action-row|s@^        if fields.len.. < 3 .$@        if fields.len() < 2 {@|the_producer_reads_only_whole_pinned_rows
//MUTANT sbom-reads-a-short-pin|s@^        let whole_pin = pin.len.. == 40;$@        let whole_pin = !pin.is_empty();@|the_producer_reads_only_whole_pinned_rows
//MUTANT sbom-drift-reads-stable|s@^        stable_form.&spdx_one. == stable_form.&spdx_two.,$@        true,@|two_scans_that_differ_record_an_unstable_inventory
//MUTANT-SUITE crates/batten/tests/it/sbom_binary.rs
//MUTANT sbom-binary-counts-every-artifact|s@^    text.artifact, "type". == "rust-crate"$@    true@|the_count_is_filtered_to_rust_crate_so_a_self_artifact_cannot_pad_it
//MUTANT sbom-binary-stale-record-survives|s@^                    Mode::Binary . .. . => crate::record::clear_named.VERB, BINARY_FAMILY..,$@                    Mode::Binary { .. } => {}@|a_scan_that_cannot_look_removes_the_previous_record
//MUTANT-SUITE crates/batten/tests/it/ntia.rs
//MUTANT conformance-exit-code-dropped|s@^        let code = spawn_code@        let code = 0 * spawn_code@|a_nonconformant_document_fails
// The five `[sbom]` keys that decide, as `config lint --config-from` compares
// them: each comparison removed must leave its key unreported.
//MUTANT-SUITE crates/batten/tests/it/config_trust.rs
//MUTANT sbom-actions-removal-unreported|s@^    if base.actions.is_some.. && working@    if false \&\& working@|the_sbom_keys_that_decide_are_reported_as_weakenings
//MUTANT sbom-checker-swap-unreported|s@^    if checker != base.checker .$@    if false {@|the_sbom_keys_that_decide_are_reported_as_weakenings
//MUTANT sbom-standard-removal-unreported|s@^        if !asked.contains.&standard.as_str... .$@        if false {@|the_sbom_keys_that_decide_are_reported_as_weakenings
//MUTANT sbom-inventory-rename-unreported|s@^        if named != declared .$@        if false {@|the_sbom_keys_that_decide_are_reported_as_weakenings
//MUTANT sbom-record-rename-unreported|s@^    if record != base.record .$@    if false {@|the_sbom_keys_that_decide_are_reported_as_weakenings

/// The verb, as its diagnostics name it.
const VERB: &str = "sbom";

/// The binary scan's record family.
///
/// The verb's own vocabulary rather than a consumer's: it is the contract
/// between this producer and the `supply-chain` preset's module that decides
/// over it, so neither side may rename it alone.
pub const BINARY_FAMILY: &str = "sbom-binary";

/// The one lockfile source the supplier may be named from.
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The purl namespace the cargo pass never reaches and the actions pass does.
const ACTION_PURL: &str = "pkg:github/";

/// Absent, as SPDX spells it.
const NOASSERTION: &str = "NOASSERTION";

/// A holder line that was looked for and is not there.
const NONE: &str = "NONE";

/// The file-name prefixes a copyright statement is looked for in first.
const LICENSE_PREFIXES: [&str; 4] = ["LICENSE", "COPYING", "COPYRIGHT", "NOTICE"];

/// The `[sbom]` table (CLOUD-843).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "SbomDeclared")]
#[non_exhaustive]
pub struct Declared {
    /// The subject's name: the documents' source name, and the stem both the
    /// tree's documents and a binary's asset are named from.
    pub subject: String,
    /// Where the tree's two documents are written, relative to the repository
    /// root unless absolute.
    pub out_dir: String,
    /// Where a binary's asset is written, relative to the repository root unless
    /// absolute.
    pub binary_out_dir: String,
    /// Paths the tree scan skips, passed to the scanner verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
    /// The pinned-actions licence table, repository-relative. Absent skips the
    /// actions pass; declared and unreadable is could-not-look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<String>,
    /// The `[[rule.tools]]` row `--record` keys its reduction under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<String>,
    /// What `--conformance` runs and where it records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conformance: Option<Conformance>,
}

/// The `[sbom.conformance]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "SbomConformance")]
#[non_exhaustive]
pub struct Conformance {
    /// The record family the checker's answers are written under.
    pub record: String,
    /// The checker program, run as `<checker> <document> --comply <standard>
    /// --output json --output-file <report>`.
    pub checker: String,
    /// The standards asked, in order. Never empty.
    pub standards: Vec<String>,
}

impl Declared {
    /// Refuse a table the verb could not act on, naming the key.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a subject or record name that is not one path
    /// component, a blank directory, or a conformance table asking nothing.
    pub fn validate(&self) -> Result<()> {
        crate::record::safe_component("[sbom] subject", &self.subject)?;
        for (key, value) in [
            ("out_dir", &self.out_dir),
            ("binary_out_dir", &self.binary_out_dir),
        ] {
            if value.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "[sbom] {key} is blank, which would write into the repository root"
                )));
            }
        }
        if let Some(conformance) = &self.conformance {
            crate::record::safe_component("[sbom.conformance] record", &conformance.record)?;
            if conformance.checker.trim().is_empty() {
                return Err(UsageError::raise(
                    "[sbom.conformance] checker is blank, so nothing could be asked".to_owned(),
                ));
            }
            if conformance.standards.is_empty()
                || conformance.standards.iter().any(|s| s.trim().is_empty())
            {
                return Err(UsageError::raise(
                    "[sbom.conformance] standards names no standard, so a pass would ask nothing"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// The five `[sbom]` keys that set a bar, compared for `config lint
/// --config-from` (CLOUD-843); `trust::CENSUS` says why the rest of the table
/// does not.
///
/// `[sbom.conformance]`'s checker exit code IS the ntia verdict, so a different
/// checker or a standard no longer asked lowers it; `actions` absent skips the
/// pass that fills the pinned actions' licences. The two names the verb stores
/// under — `inventory` and `conformance.record` — are read back by consumer
/// modules at a FIXED key, and a module finding no record there judges nothing,
/// so a renamed or dropped name is the gate going blind. Only a base that
/// DECLARED a key can lose it: `[sbom]` arriving where the base had none is a
/// new producer, and a standard added is one more question.
#[must_use]
pub(crate) fn weakenings(
    base: Option<&Declared>,
    working: Option<&Declared>,
) -> Vec<crate::trust::Weakening> {
    use crate::trust::{Weakening, WeakeningKind};
    let Some(base) = base else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if base.actions.is_some() && working.and_then(|sbom| sbom.actions.as_ref()).is_none() {
        found.push(Weakening::new(
            WeakeningKind::SbomActionsRemoved,
            "sbom.actions",
            "present",
            "absent",
        ));
    }
    if let Some(declared) = base.inventory.as_deref() {
        let named = working
            .and_then(|sbom| sbom.inventory.as_deref())
            .unwrap_or("absent");
        if named != declared {
            found.push(Weakening::new(
                WeakeningKind::SbomInventoryChanged,
                "sbom.inventory",
                declared,
                named,
            ));
        }
    }
    let Some(base) = base.conformance.as_ref() else {
        return found;
    };
    let working = working.and_then(|sbom| sbom.conformance.as_ref());
    let record = working.map_or("absent", |conformance| conformance.record.as_str());
    if record != base.record {
        found.push(Weakening::new(
            WeakeningKind::SbomRecordChanged,
            "sbom.conformance.record",
            base.record.clone(),
            record,
        ));
    }
    let checker = working.map_or("absent", |conformance| conformance.checker.as_str());
    if checker != base.checker {
        found.push(Weakening::new(
            WeakeningKind::SbomCheckerChanged,
            "sbom.conformance.checker",
            base.checker.clone(),
            checker,
        ));
    }
    let asked: Vec<&str> = working.map_or_else(Vec::new, |conformance| {
        conformance.standards.iter().map(String::as_str).collect()
    });
    for standard in &base.standards {
        if !asked.contains(&standard.as_str()) {
            found.push(Weakening::new(
                WeakeningKind::SbomStandardRemoved,
                format!("sbom.conformance.standards[{standard}]"),
                "present",
                "absent",
            ));
        }
    }
    found
}

/// A reading the verb could not take. Never a verdict and never a pass.
#[derive(Debug)]
struct CouldNotLook(String);

impl std::fmt::Display for CouldNotLook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CouldNotLook {}

/// Raise a could-not-look carrying `why`.
fn unseen<T>(why: impl Into<String>) -> Result<T> {
    Err(anyhow::Error::new(CouldNotLook(why.into())))
}

/// What one invocation was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// Print the tree's two asset paths.
    TreeNames,
    /// Print a binary's asset path.
    BinaryName { target: String },
    /// Derive the tree's two documents.
    Tree,
    /// Scan a built binary.
    Binary { binary: String, target: String },
    /// Derive twice into scratch and record the reduction.
    Record,
    /// Derive into scratch and record the checker's answers.
    Conformance,
}

/// Which mode the flags ask for, or the usage error that says why none.
fn mode_of(request: &SbomRequest) -> Result<Mode> {
    let usage = |why: &str| {
        Err(UsageError::raise(format!(
            "{VERB}: {why}. usage: batten sbom [--names] [--out-dir D] | --binary P --target T | --names --target T | --record | --conformance"
        )))
    };
    if request.record || request.conformance {
        if request.record && request.conformance {
            return usage("--record and --conformance are two producers, run them separately");
        }
        if request.names
            || request.binary.is_some()
            || request.target.is_some()
            || request.out_dir.is_some()
        {
            return usage(
                "--record and --conformance derive the tree into scratch and take no other flag",
            );
        }
        return Ok(if request.record {
            Mode::Record
        } else {
            Mode::Conformance
        });
    }
    match (&request.binary, &request.target, request.names) {
        (_, Some(target), true) => Ok(Mode::BinaryName {
            target: target.clone(),
        }),
        (None, None, true) => Ok(Mode::TreeNames),
        (None, None, false) => Ok(Mode::Tree),
        (Some(binary), Some(target), false) => Ok(Mode::Binary {
            binary: binary.clone(),
            target: target.clone(),
        }),
        (Some(_), None, _) => usage("--binary needs --target, which names its asset"),
        (None, Some(_), false) => {
            usage("--target names a binary's asset, so it needs --binary or --names")
        }
    }
}

/// Run the verb.
///
/// # Errors
///
/// A [`UsageError`] for a bad flag combination or an absent `[sbom]` table; an
/// internal error when a write fails. Could-not-look is exit 3 with a pointer on
/// `err`, and removes the record the invocation would have written.
pub fn run(
    request: &SbomRequest,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let mode = mode_of(request)?;
    // THE WORKTREE'S root, never the repository's: the documents describe the
    // tree this branch carries and `[sbom]` is a file this branch may change, so
    // a linked worktree must not scan or read the main checkout's.
    let root = crate::git::worktree_root(Path::new("."))?;
    let config = crate::resolve::committed(&root, overrides)?;
    let Some(declared) = config.sbom else {
        return Err(UsageError::raise(format!(
            "{VERB}: no [sbom] table declares a subject, so there is nothing to name"
        )));
    };
    let answered = answer(&mode, &declared, request, &root, overrides);
    match answered {
        Ok(lines) => {
            for line in lines {
                writeln!(out, "{line}")?;
            }
            Ok(ExitCode::Success)
        }
        Err(error) => match error.downcast::<CouldNotLook>() {
            Ok(CouldNotLook(why)) => {
                match &mode {
                    Mode::Binary { .. } => crate::record::clear_named(VERB, BINARY_FAMILY)?,
                    Mode::Conformance => {
                        if let Some(conformance) = &declared.conformance {
                            crate::record::clear_named(VERB, &conformance.record)?;
                        }
                    }
                    _ => {}
                }
                writeln!(err, "batten: {VERB}: could not look: {why}")?;
                Ok(ExitCode::Internal)
            }
            Err(other) => Err(other),
        },
    }
}

/// The pointer lines one mode prints, after doing its work.
fn answer(
    mode: &Mode,
    declared: &Declared,
    request: &SbomRequest,
    root: &Path,
    overrides: &Overrides,
) -> Result<Vec<String>> {
    let tree_out = request.out_dir.as_deref().unwrap_or(&declared.out_dir);
    let binary_out = request
        .out_dir
        .as_deref()
        .unwrap_or(&declared.binary_out_dir);
    match mode {
        Mode::TreeNames => {
            let (spdx, cdx) = tree_names(tree_out, &declared.subject);
            Ok(vec![format!("spdx={spdx}"), format!("cdx={cdx}")])
        }
        Mode::BinaryName { target } => {
            let version = manifest_version(root)?;
            Ok(vec![format!(
                "sbom={}",
                binary_asset(binary_out, &declared.subject, &version, target)
            )])
        }
        Mode::Tree => {
            let (spdx, cdx) = tree_names(tree_out, &declared.subject);
            derive_tree(declared, root, &root.join(&spdx), &root.join(&cdx))?;
            Ok(vec![format!("spdx={spdx}"), format!("cdx={cdx}")])
        }
        Mode::Binary { binary, target } => {
            let version = manifest_version_for_binary(root, binary)?;
            let asset = binary_asset(binary_out, &declared.subject, &version, target);
            let count = derive_binary(declared, root, binary, &version, &root.join(&asset))?;
            Ok(vec![format!("sbom={asset}"), format!("packages={count}")])
        }
        Mode::Record => {
            record_inventory(declared, root, overrides)?;
            Ok(Vec::new())
        }
        Mode::Conformance => {
            record_conformance(declared, root)?;
            Ok(Vec::new())
        }
    }
}

/// The tree's two asset paths, as printed.
fn tree_names(out_dir: &str, subject: &str) -> (String, String) {
    let dir = out_dir.trim_end_matches('/');
    (
        format!("{dir}/{subject}.spdx.json"),
        format!("{dir}/{subject}.cdx.json"),
    )
}

/// A binary's asset stem: `<subject>-v<version>-<target>`.
///
/// The release archive's naming contract an installer resolves assets by, in
/// the engine: `pub` so the `dist --stem` body reads this function rather than
/// spelling the contract a second time, and the binary's inventory and its
/// archive cannot race for two names.
#[must_use]
pub fn archive_stem(subject: &str, version: &str, target: &str) -> String {
    format!("{subject}-v{version}-{target}")
}

/// A binary's asset path, as printed.
fn binary_asset(out_dir: &str, subject: &str, version: &str, target: &str) -> String {
    format!(
        "{}/{}.spdx.json",
        out_dir.trim_end_matches('/'),
        archive_stem(subject, version, target)
    )
}

/// The value of the first line of `text` spelled `<key> = "<value>..."`, up to
/// the next quote — the reading the retired bodies' `awk -F'"'` took.
fn first_quoted(text: &str, prefix: &str) -> Option<String> {
    let line = text.lines().find(|line| line.starts_with(prefix))?;
    let after = line.split('"').nth(1)?;
    Some(after.to_owned())
}

/// The manifest's version: the first `version = "…"` line.
fn manifest_version(root: &Path) -> Result<String> {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    match first_quoted(&text, "version = \"") {
        Some(version) if !version.is_empty() => Ok(version),
        _ => unseen("could not read a version from Cargo.toml"),
    }
}

/// The version, after the two readings a binary scan owes first.
fn manifest_version_for_binary(root: &Path, binary: &str) -> Result<String> {
    if !Path::new(binary).is_file() {
        return unseen(format!(
            "no binary at {binary}, so there is nothing to inventory"
        ));
    }
    if !root.join("Cargo.lock").is_file() {
        return unseen(
            "no Cargo.lock, so the recovered crates cannot be held against anything. A gate that checks nothing must not report green",
        );
    }
    manifest_version(root)
}

/// `Organization: <first author>` of the manifest, or NOASSERTION.
fn workspace_supplier(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    match first_quoted(&text, "authors = [") {
        Some(author) if !author.is_empty() => organization(&author),
        _ => NOASSERTION.to_owned(),
    }
}

/// The anchored holder line (CLOUD-629): an optional comment marker, the word,
/// an optional `(c)`, and a year followed by a name. Case-insensitive, and the
/// match runs to the end of the line.
static COPYRIGHT: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)^[[:space:]]*(#|//|\*|;)?[[:space:]]*Copyright[[:space:]]*(\(c\)|©)?[[:space:]]*[0-9][0-9,[:space:]-]*\p{Alphabetic}.*",
    )
    .ok()
});

/// The leading whitespace and comment marker a holder line is read without.
static TIDY: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"^(#|//|\*|;)[[:space:]]*").ok());

/// Every holder line in `text`, tidied, in order.
fn holder_lines(text: &str) -> Vec<String> {
    let (Some(copyright), Some(tidy)) = (COPYRIGHT.as_ref(), TIDY.as_ref()) else {
        return Vec::new();
    };
    text.split('\n')
        .filter_map(|line| copyright.find(line))
        .map(|found| {
            let trimmed = found.as_str().trim_start();
            tidy.replace(trimmed, "").into_owned()
        })
        .collect()
}

/// A file's text, or nothing for one a line scan would call binary.
fn scannable(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The licence-shaped files directly in `dir`, in the retired glob's order:
/// each prefix in turn, case-insensitively, names sorted within it.
fn license_files(dir: &Path) -> Vec<PathBuf> {
    let mut names: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.path().is_file())
                .map(|entry| {
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        entry.path(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut files = Vec::new();
    for prefix in LICENSE_PREFIXES {
        for (name, path) in &names {
            if name.to_ascii_uppercase().starts_with(prefix) {
                files.push(path.clone());
            }
        }
    }
    files
}

/// The first holder line in `files`, in order.
fn first_holder(files: &[PathBuf]) -> Option<String> {
    files
        .iter()
        .filter_map(|file| scannable(file))
        .find_map(|text| holder_lines(&text).into_iter().next())
}

/// Every regular file under `dir`, symlinks not followed.
fn walk(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            walk(&entry.path(), into);
        } else if kind.is_file() {
            into.push(entry.path());
        }
    }
}

/// One unpacked crate's holder line, or empty: licence files first, then the
/// most frequent anchored line in the tree, ties broken on the sorted line so
/// two runs agree.
fn copyright_of(dir: &Path) -> String {
    if let Some(line) = first_holder(&license_files(dir)) {
        return line;
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for file in files {
        if let Some(text) = scannable(&file) {
            for line in holder_lines(&text) {
                *counts.entry(line).or_default() += 1;
            }
        }
    }
    counts
        .into_iter()
        .max_by(|(a_line, a_count), (b_line, b_count)| {
            a_count.cmp(b_count).then_with(|| b_line.cmp(a_line))
        })
        .map(|(line, _)| line)
        .unwrap_or_default()
}

/// The workspace's own statement: root licence files only, never recursive.
fn workspace_copyright(root: &Path) -> String {
    first_holder(&license_files(root)).unwrap_or_else(|| NONE.to_owned())
}

/// A string field, or empty.
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// An SPDX package's first purl, or empty.
fn spdx_purl(package: &Value) -> String {
    package
        .get("externalRefs")
        .and_then(Value::as_array)
        .and_then(|refs| {
            refs.iter()
                .find(|entry| entry.get("referenceType") == Some(&json!("purl")))
        })
        .map(|entry| text(entry, "referenceLocator").to_owned())
        .unwrap_or_default()
}

/// The document's DESCRIBES target, or null.
fn spdx_subject(document: &Value) -> Value {
    document
        .get("relationships")
        .and_then(Value::as_array)
        .and_then(|edges| {
            edges
                .iter()
                .find(|edge| edge.get("relationshipType") == Some(&json!("DESCRIBES")))
        })
        .and_then(|edge| edge.get("relatedSpdxElement").cloned())
        .unwrap_or(Value::Null)
}

/// An array field as a vector, or empty.
fn array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Sort and deduplicate by canonical text, which is total and stable.
fn unique(values: Vec<Value>) -> Vec<Value> {
    let keyed: BTreeMap<String, Value> = values
        .into_iter()
        .map(|value| (value.to_string(), value))
        .collect();
    keyed.into_values().collect()
}

/// The ids to drop and the id each duplicate merges onto.
///
/// `entries` are `(id, identity triple, droppable)` for every entry eligible
/// at all; the subject is excluded by the caller.
fn identity_plan(
    entries: &[(String, [String; 3], bool)],
) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let gone: BTreeSet<String> = entries
        .iter()
        .filter(|(_, _, droppable)| *droppable)
        .map(|(id, _, _)| id.clone())
        .collect();
    let mut groups: BTreeMap<&[String; 3], Vec<&String>> = BTreeMap::new();
    for (id, ident, _) in entries {
        if !gone.contains(id) {
            groups.entry(ident).or_default().push(id);
        }
    }
    let mut merged = BTreeMap::new();
    for ids in groups.values_mut() {
        ids.sort();
        if let Some((first, rest)) = ids.split_first() {
            for id in rest {
                merged.insert((*id).clone(), (*first).clone());
            }
        }
    }
    (gone, merged)
}

/// Whether a component is a reference site rather than a dependency.
fn droppable(name: &str, version: &str) -> bool {
    name.starts_with("./") || version == "UNKNOWN"
}

/// The SPDX normalise pass (CLOUD-664).
#[must_use]
pub fn normalise_spdx(mut document: Value) -> Value {
    let subject = spdx_subject(&document);
    let packages = array(&document, "packages");
    let entries: Vec<(String, [String; 3], bool)> = packages
        .iter()
        .filter_map(|package| {
            let id = text(package, "SPDXID");
            if id.is_empty() || Some(id) == subject.as_str() {
                return None;
            }
            let name = text(package, "name");
            let version = text(package, "versionInfo");
            Some((
                id.to_owned(),
                [name.to_owned(), version.to_owned(), spdx_purl(package)],
                droppable(name, version),
            ))
        })
        .collect();
    let (gone, merged) = identity_plan(&entries);
    let kept: Vec<Value> = packages
        .into_iter()
        .filter(|package| {
            let id = text(package, "SPDXID");
            !gone.contains(id) && merged.get(id).is_none_or(|onto| onto == id)
        })
        .collect();
    let edges: Vec<Value> = array(&document, "relationships")
        .into_iter()
        .filter(|edge| {
            !gone.contains(text(edge, "spdxElementId"))
                && !gone.contains(text(edge, "relatedSpdxElement"))
        })
        .map(|mut edge| {
            for end in ["spdxElementId", "relatedSpdxElement"] {
                if let Some(onto) = merged.get(text(&edge, end)) {
                    edge[end] = json!(onto);
                }
            }
            edge
        })
        .collect();
    if let Some(object) = document.as_object_mut() {
        object.insert("packages".to_owned(), Value::Array(kept));
        object.insert("relationships".to_owned(), Value::Array(unique(edges)));
    }
    document
}

/// The `CycloneDX` normalise pass: `metadata.component` is the subject and is
/// not in `.components`.
#[must_use]
pub fn normalise_cdx(mut document: Value) -> Value {
    let components = array(&document, "components");
    let entries: Vec<(String, [String; 3], bool)> = components
        .iter()
        .filter_map(|component| {
            let id = text(component, "bom-ref");
            if id.is_empty() {
                return None;
            }
            let name = text(component, "name");
            let version = text(component, "version");
            Some((
                id.to_owned(),
                [
                    name.to_owned(),
                    version.to_owned(),
                    text(component, "purl").to_owned(),
                ],
                droppable(name, version),
            ))
        })
        .collect();
    let (gone, merged) = identity_plan(&entries);
    let onto = |id: &str| merged.get(id).cloned().unwrap_or_else(|| id.to_owned());
    let kept: Vec<Value> = components
        .into_iter()
        .filter(|component| {
            let id = text(component, "bom-ref");
            !gone.contains(id) && merged.get(id).is_none_or(|onto| onto == id)
        })
        .collect();
    let dependencies = document.get("dependencies").map(|_| {
        let mut grouped: BTreeMap<String, (Value, Vec<Value>)> = BTreeMap::new();
        for mut dependency in array(&document, "dependencies") {
            let reference = text(&dependency, "ref").to_owned();
            if gone.contains(&reference) {
                continue;
            }
            let reference = onto(&reference);
            dependency["ref"] = json!(reference);
            let on: Vec<Value> = array(&dependency, "dependsOn")
                .into_iter()
                .filter(|target| !gone.contains(target.as_str().unwrap_or("")))
                .map(|target| match target.as_str() {
                    Some(id) => json!(onto(id)),
                    None => target,
                })
                .collect();
            let slot = grouped
                .entry(reference)
                .or_insert_with(|| (dependency.clone(), Vec::new()));
            slot.1.extend(on);
        }
        grouped
            .into_values()
            .map(|(mut first, on)| {
                first["dependsOn"] = Value::Array(unique(on));
                first
            })
            .collect::<Vec<_>>()
    });
    if let Some(object) = document.as_object_mut() {
        object.insert("components".to_owned(), Value::Array(kept));
        if let Some(dependencies) = dependencies {
            object.insert("dependencies".to_owned(), Value::Array(dependencies));
        }
    }
    document
}

/// One cargo package's four entity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    /// `Organization: crates.io`, the workspace's own, or NOASSERTION.
    pub supplier: String,
    /// `Organization: <first author>`, or NOASSERTION.
    pub originator: String,
    /// The manifest's licence expression, or NOASSERTION.
    pub license: String,
    /// The holder line, the workspace's own, or `NONE`.
    pub copyright: String,
}

/// The deprecated `/` spelling, which is not valid SPDX.
static SLASH: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"[[:space:]]*/[[:space:]]*").ok());

/// A manifest licence as SPDX spells it (CLOUD-628).
fn spdx_license(raw: &str) -> String {
    if raw.is_empty() {
        return NOASSERTION.to_owned();
    }
    let Some(slash) = SLASH.as_ref() else {
        return raw.to_owned();
    };
    slash.replace_all(raw, " OR ").into_owned()
}

/// An entity named as SPDX spells one.
fn organization(name: &str) -> String {
    format!("Organization: {name}")
}

/// `name@version` → its entity, for every package `cargo metadata` lists.
///
/// `copyrights` holds the holder line read for each SOURCED package; the
/// workspace's own members take `own_supplier` and `own_copyright`.
#[must_use]
pub fn entities(
    metadata: &Value,
    copyrights: &BTreeMap<String, String>,
    own_supplier: &str,
    own_copyright: &str,
) -> BTreeMap<String, Entity> {
    let mut out = BTreeMap::new();
    for package in array(metadata, "packages") {
        let key = format!("{}@{}", text(&package, "name"), text(&package, "version"));
        let source = package.get("source").filter(|source| !source.is_null());
        let supplier = match source.and_then(Value::as_str) {
            Some(CRATES_IO_SOURCE) => "Organization: crates.io".to_owned(),
            Some(_) => NOASSERTION.to_owned(),
            None if source.is_some() => NOASSERTION.to_owned(),
            None => own_supplier.to_owned(),
        };
        let originator = array(&package, "authors")
            .first()
            .and_then(Value::as_str)
            .map_or_else(|| NOASSERTION.to_owned(), organization);
        let copyright = if source.is_none() {
            own_copyright.to_owned()
        } else {
            match copyrights.get(&key) {
                Some(line) if !line.is_empty() => line.clone(),
                _ => NONE.to_owned(),
            }
        };
        out.insert(
            key,
            Entity {
                supplier,
                originator,
                license: spdx_license(text(&package, "license")),
                copyright,
            },
        );
    }
    out
}

/// Apply the cargo entities to an SPDX document; `pkg:github` entries keep
/// what syft derived.
pub fn enrich_spdx(document: &mut Value, entities: &BTreeMap<String, Entity>) {
    for package in packages_mut(document, "packages") {
        if spdx_purl(package).starts_with(ACTION_PURL) {
            continue;
        }
        let key = format!("{}@{}", text(package, "name"), text(package, "versionInfo"));
        let Some(entity) = entities.get(&key) else {
            continue;
        };
        package["supplier"] = json!(entity.supplier);
        package["originator"] = json!(entity.originator);
        package["copyrightText"] = json!(entity.copyright);
        package["licenseDeclared"] = json!(entity.license);
        package["licenseConcluded"] = json!(entity.license);
    }
}

/// Apply the cargo entities to a `CycloneDX` document.
pub fn enrich_cdx(document: &mut Value, entities: &BTreeMap<String, Entity>) {
    for component in packages_mut(document, "components") {
        if text(component, "purl").starts_with(ACTION_PURL) {
            continue;
        }
        let key = format!("{}@{}", text(component, "name"), text(component, "version"));
        let Some(entity) = entities.get(&key) else {
            continue;
        };
        component["publisher"] = json!(entity.supplier);
        if entity.originator != NOASSERTION {
            component["author"] = json!(
                entity
                    .originator
                    .strip_prefix("Organization: ")
                    .unwrap_or(&entity.originator)
            );
        }
        if entity.copyright != NONE && entity.copyright != NOASSERTION {
            component["copyright"] = json!(entity.copyright);
        }
        if entity.license != NOASSERTION {
            component["licenses"] = json!([{"expression": entity.license}]);
        }
    }
}

/// The array `key` of `document`, mutably, or nothing.
fn packages_mut<'a>(document: &'a mut Value, key: &str) -> Vec<&'a mut Value> {
    document
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .map(|entries| entries.iter_mut().filter(|e| e.is_object()).collect())
        .unwrap_or_default()
}

/// One pinned action's licence and holder line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The licence expression.
    pub license: String,
    /// The holder line, or `NONE`.
    pub copyright: String,
}

/// `owner/repo` → its row, from the table's rows of the right shape only.
///
/// A short row or a key carrying no 40-hex pin is the consumer's table module's
/// refusal; this reads past it rather than writing it into a document.
#[must_use]
pub fn actions_table(text: &str) -> BTreeMap<String, Action> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 {
            continue;
        }
        let key = fields[0];
        let Some((repo, pin)) = key.split_once('@') else {
            continue;
        };
        let whole_pin = pin.len() == 40;
        if repo.is_empty()
            || repo.contains('\t')
            || !whole_pin
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        out.insert(
            repo.to_owned(),
            Action {
                license: fields[1].to_owned(),
                copyright: fields[2].to_owned(),
            },
        );
    }
    out
}

/// Apply the actions table to an SPDX document.
pub fn actions_spdx(document: &mut Value, actions: &BTreeMap<String, Action>) {
    for package in packages_mut(document, "packages") {
        if !spdx_purl(package).starts_with(ACTION_PURL) {
            continue;
        }
        let Some(action) = actions.get(text(package, "name")) else {
            continue;
        };
        package["licenseDeclared"] = json!(action.license);
        package["licenseConcluded"] = json!(action.license);
        package["copyrightText"] = json!(action.copyright);
    }
}

/// Apply the actions table to a `CycloneDX` document.
pub fn actions_cdx(document: &mut Value, actions: &BTreeMap<String, Action>) {
    for component in packages_mut(document, "components") {
        if !text(component, "purl").starts_with(ACTION_PURL) {
            continue;
        }
        let Some(action) = actions.get(text(component, "name")) else {
            continue;
        };
        component["licenses"] = json!([{"expression": action.license}]);
        if action.copyright != NONE {
            component["copyright"] = json!(action.copyright);
        }
    }
}

/// Run a declared inventory tool, in `root`, answering whether it exited 0 and
/// what it printed.
fn spawn(program: &str, args: &[&str], root: &Path, capture: bool) -> Option<(bool, Vec<u8>)> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the inventory IS the declared tool's answer — syft's catalogue, cargo's resolution of the lockfile — so acquiring it runs that tool, `hk.rs`'s classification for its own pinned tool (CLOUD-843)"
    )]
    let spawned = std::process::Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(if capture {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stderr(std::process::Stdio::null())
        .output();
    spawned
        .ok()
        .map(|output| (output.status.success(), output.stdout))
}

/// Read and parse one JSON document.
fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Write one JSON document in place through a temporary, so a failed write never
/// leaves a truncated document where a valid one was.
fn write_json(path: &Path, document: &Value) -> Result<()> {
    let mut rendered = serde_json::to_string_pretty(document)?;
    rendered.push('\n');
    crate::durable::replace(path, rendered)
        .map_err(|error| anyhow::anyhow!("write {}: {error}", path.display()))
}

/// The cargo pass: fetch the pinned sources, read the metadata, and read each
/// sourced package's holder line out of the registry cache.
fn cargo_entities(
    root: &Path,
    own_supplier: &str,
    own_copyright: &str,
) -> Result<(Value, BTreeMap<String, Entity>)> {
    match spawn("cargo", &["fetch", "--locked"], root, false) {
        Some((true, _)) => {}
        _ => {
            return unseen(
                "`cargo fetch --locked` failed, so the pinned sources the copyright statements are read from are not present",
            );
        }
    }
    let metadata = match spawn(
        "cargo",
        &["metadata", "--format-version", "1", "--locked", "--offline"],
        root,
        true,
    ) {
        Some((true, stdout)) => serde_json::from_slice::<Value>(&stdout).ok(),
        _ => None,
    };
    let Some(metadata) = metadata else {
        return unseen(
            "could not read cargo metadata, so supplier and originator are unknown for every cargo component",
        );
    };
    let home = std::env::var_os("CARGO_HOME").map_or_else(
        || {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cargo"))
                .unwrap_or_default()
        },
        PathBuf::from,
    );
    let mut roots: Vec<PathBuf> = std::fs::read_dir(home.join("registry").join("src"))
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .collect()
        })
        .unwrap_or_default();
    roots.sort();
    let mut copyrights = BTreeMap::new();
    let mut missing = 0_usize;
    for package in array(&metadata, "packages") {
        if package.get("source").is_none_or(Value::is_null) {
            continue;
        }
        let name = text(&package, "name");
        let version = text(&package, "version");
        let unpacked = format!("{name}-{version}");
        let Some(dir) = roots
            .iter()
            .map(|root| root.join(&unpacked))
            .find(|dir| dir.is_dir())
        else {
            missing += 1;
            continue;
        };
        copyrights.insert(format!("{name}@{version}"), copyright_of(&dir));
    }
    // Pointer-only: a count, never the crate names.
    if missing != 0 {
        return unseen(format!(
            "{missing} lockfile package(s) have no unpacked source under $CARGO_HOME/registry/src, so their copyright statements could not be read. Run `cargo fetch --locked`; a document that reported NOASSERTION here would depend on this machine's cache rather than on the lockfile"
        ));
    }
    let entities = entities(&metadata, &copyrights, own_supplier, own_copyright);
    Ok((metadata, entities))
}

/// Derive the tree's two documents at `spdx` and `cdx`, returning the cargo
/// metadata the enrichment read.
fn derive_tree(declared: &Declared, root: &Path, spdx: &Path, cdx: &Path) -> Result<Value> {
    let derived = derive_tree_inner(declared, root, spdx, cdx);
    if derived.is_err() {
        // Nothing written behind a refusal: a document the passes never finished
        // would be published as though they had.
        let _ = std::fs::remove_file(spdx);
        let _ = std::fs::remove_file(cdx);
    }
    derived
}

/// [`derive_tree`]'s work, with the cleanup left to the caller.
fn derive_tree_inner(declared: &Declared, root: &Path, spdx: &Path, cdx: &Path) -> Result<Value> {
    // Bound before the scan, so a manifest this cannot read fails before syft
    // spends a minute cataloguing a tree whose subject it could not name.
    let version = manifest_version(root)?;
    let own_supplier = workspace_supplier(root);
    let own_copyright = workspace_copyright(root);
    let actions = match &declared.actions {
        None => None,
        Some(table) => match std::fs::read_to_string(root.join(table)) {
            Ok(text) => Some(actions_table(&text)),
            Err(_) => {
                return unseen(format!(
                    "cannot read {table}, so no pinned action can be given its license or copyright"
                ));
            }
        },
    };
    for path in [spdx, cdx] {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
        }
    }
    let spdx_out = format!("spdx-json={}", spdx.display());
    let cdx_out = format!("cyclonedx-json={}", cdx.display());
    let mut args: Vec<&str> = vec!["scan", "dir:."];
    for exclude in &declared.exclude {
        args.push("--exclude");
        args.push(exclude);
    }
    args.extend([
        "--source-name",
        &declared.subject,
        "--source-version",
        &version,
        "--output",
        &spdx_out,
        "--output",
        &cdx_out,
        "--quiet",
    ]);
    if !matches!(spawn("syft", &args, root, false), Some((true, _))) {
        return unseen("syft could not scan the tree, so no inventory was produced");
    }
    let (Some(spdx_doc), Some(cdx_doc)) = (read_json(spdx), read_json(cdx)) else {
        return unseen("syft wrote a document that does not parse, so no inventory was produced");
    };
    let mut spdx_doc = normalise_spdx(spdx_doc);
    let mut cdx_doc = normalise_cdx(cdx_doc);
    let (metadata, entities) = cargo_entities(root, &own_supplier, &own_copyright)?;
    enrich_spdx(&mut spdx_doc, &entities);
    enrich_cdx(&mut cdx_doc, &entities);
    if let Some(actions) = &actions {
        actions_spdx(&mut spdx_doc, actions);
        actions_cdx(&mut cdx_doc, actions);
    }
    write_json(spdx, &spdx_doc)?;
    write_json(cdx, &cdx_doc)?;
    Ok(metadata)
}

/// A scratch directory that removes itself however its owner leaves.
struct Scratch(PathBuf);

impl Scratch {
    /// A fresh directory under the system temp dir.
    fn new(purpose: &str) -> Result<Self> {
        let dir =
            std::env::temp_dir().join(format!("batten-{VERB}-{purpose}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|error| anyhow::anyhow!("create scratch {}: {error}", dir.display()))?;
        Ok(Self(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best effort: a scratch that will not remove is not a reason to fail a
        // reading that already concluded.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Scan a built binary: write its asset, and record the asset's name and one
/// `crate\t<name> <version>` line per recovered `rust-crate` artifact.
fn derive_binary(
    declared: &Declared,
    root: &Path,
    binary: &str,
    version: &str,
    asset: &Path,
) -> Result<usize> {
    if let Some(parent) = asset.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("create {}: {error}", parent.display()))?;
    }
    let scratch = Scratch::new("binary")?;
    let scan = scratch.0.join("scan.json");
    let binary_path = std::fs::canonicalize(binary).unwrap_or_else(|_| PathBuf::from(binary));
    let args = [
        "scan".to_owned(),
        format!("file:{}", binary_path.display()),
        "--source-name".to_owned(),
        declared.subject.clone(),
        "--source-version".to_owned(),
        version.to_owned(),
        "--output".to_owned(),
        format!("spdx-json={}", asset.display()),
        "--output".to_owned(),
        format!("syft-json={}", scan.display()),
        "--quiet".to_owned(),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if !matches!(spawn("syft", &args, root, false), Some((true, _))) {
        let _ = std::fs::remove_file(asset);
        return unseen(format!(
            "syft could not scan {binary}, so its contents are unverified"
        ));
    }
    let Some(recovered) = read_json(&scan).map(|scan| recovered_crates(&scan)) else {
        let _ = std::fs::remove_file(asset);
        return unseen("could not read the scan's artifact list, so the inventory is unverified");
    };
    let name = asset
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut body = format!("asset\t{name}\n");
    for entry in &recovered {
        let _ = writeln!(body, "crate\t{entry}");
    }
    crate::record::store_named(VERB, BINARY_FAMILY, &body)?;
    Ok(recovered.len())
}

/// `<name> <version>` for every `rust-crate` artifact, in scan order. The type
/// filter is load-bearing: syft reports the FILE itself as an artifact on some
/// inputs, which would pad an empty binary to one.
#[must_use]
pub fn recovered_crates(scan: &Value) -> Vec<String> {
    array(scan, "artifacts")
        .iter()
        .filter(|artifact| is_crate(artifact))
        .map(|artifact| format!("{} {}", text(artifact, "name"), text(artifact, "version")))
        .collect()
}

/// Whether a scan artifact is a crate rather than the file itself.
fn is_crate(artifact: &Value) -> bool {
    text(artifact, "type") == "rust-crate"
}

/// A document with the four leaves two scans of one tree legitimately differ in
/// removed: SPDX's namespace and creation time, `CycloneDX`'s serial number and
/// timestamp.
fn stable_form(document: &Value) -> Value {
    let mut copy = document.clone();
    if let Some(object) = copy.as_object_mut() {
        object.remove("documentNamespace");
        object.remove("serialNumber");
        for (outer, inner) in [("creationInfo", "created"), ("metadata", "timestamp")] {
            if let Some(Value::Object(nested)) = object.get_mut(outer) {
                nested.remove(inner);
            }
        }
    }
    copy
}

/// A string field under `//`'s reading: absent, null or false is `fallback`.
fn or<'a>(value: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    match value.get(key) {
        None | Some(Value::Null | Value::Bool(false)) => fallback,
        Some(other) => other.as_str().unwrap_or(fallback),
    }
}

/// The inventory's counts, as `<name> <count>` lines (CLOUD-1318).
///
/// A REDUCTION, NEVER THE DOCUMENT: the SBOM carries author names, email
/// addresses and copyright holders, so only integers and two yes/no tokens reach
/// the record. The subject is exempt from the component counts — the document
/// root and the workspace member are two roles that share a triple.
#[must_use]
pub fn reduce(spdx: &Value, cdx: &Value, stable: (bool, bool), metadata: &Value) -> String {
    let purls = |package: &Value| -> Vec<String> {
        array(package, "externalRefs")
            .iter()
            .filter(|entry| entry.get("referenceType") == Some(&json!("purl")))
            .map(|entry| text(entry, "referenceLocator").to_owned())
            .collect()
    };
    let packages = array(spdx, "packages");
    let spdx_cargo = packages
        .iter()
        .flat_map(purls)
        .filter(|purl| purl.starts_with("pkg:cargo/"))
        .count();
    let cdx_cargo = array(cdx, "components")
        .iter()
        .filter(|component| text(component, "purl").starts_with("pkg:cargo/"))
        .count();
    let yes = |flag: bool| if flag { "yes" } else { "no" };
    let mut body = format!(
        "spdx-cargo {spdx_cargo}\ncdx-cargo {cdx_cargo}\nspdx-stable {}\ncdx-stable {}\n",
        yes(stable.0),
        yes(stable.1)
    );
    for (name, count) in component_counts(&packages, spdx, metadata) {
        let _ = writeln!(body, "{name} {count}");
    }
    body
}

/// The component counts [`reduce`] records after the four format readings.
fn component_counts(
    packages: &[Value],
    spdx: &Value,
    metadata: &Value,
) -> [(&'static str, usize); 12] {
    let authored: BTreeSet<String> = array(metadata, "packages")
        .iter()
        .filter(|package| !array(package, "authors").is_empty())
        .map(|package| format!("{}@{}", text(package, "name"), text(package, "version")))
        .collect();
    let subject = spdx_subject(spdx);
    let id = |package: &Value| package.get("SPDXID").cloned().unwrap_or(Value::Null);
    let components: Vec<&Value> = packages.iter().filter(|p| id(p) != subject).collect();
    let (gh, cargo): (Vec<&Value>, Vec<&Value>) = components
        .iter()
        .partition(|package| spdx_purl(package).starts_with(ACTION_PURL));
    let distinct: BTreeSet<[String; 3]> = components
        .iter()
        .map(|p| {
            [
                text(p, "name").to_owned(),
                text(p, "versionInfo").to_owned(),
                spdx_purl(p),
            ]
        })
        .collect();
    let unset = |value: &Value, key: &str| {
        or(value, key, NOASSERTION) == NOASSERTION
            || text(value, key).is_empty() && value.get(key).is_some_and(Value::is_string)
    };
    [
        ("subject", usize::from(!subject.is_null())),
        ("entries", components.len()),
        ("distinct", distinct.len()),
        (
            "pathlike",
            components
                .iter()
                .filter(|p| text(p, "name").starts_with("./"))
                .count(),
        ),
        (
            "unversioned",
            components
                .iter()
                .filter(|p| text(p, "versionInfo") == "UNKNOWN")
                .count(),
        ),
        (
            "nosupplier",
            cargo
                .iter()
                .filter(|p| or(p, "supplier", NOASSERTION) == NOASSERTION)
                .count(),
        ),
        (
            "subject-unset",
            packages
                .iter()
                .filter(|p| id(p) == subject)
                .filter(|p| or(p, "supplier", NOASSERTION) == NOASSERTION)
                .count(),
        ),
        (
            "originator-disagrees",
            cargo
                .iter()
                .filter(|p| {
                    let set = or(p, "originator", NOASSERTION) != NOASSERTION;
                    let key = format!("{}@{}", text(p, "name"), text(p, "versionInfo"));
                    set != authored.contains(&key)
                })
                .count(),
        ),
        (
            "copyright-unset",
            cargo.iter().filter(|p| unset(p, "copyrightText")).count(),
        ),
        (
            "license-unset",
            cargo
                .iter()
                .filter(|p| unset(p, "licenseConcluded"))
                .count(),
        ),
        (
            "license-slashed",
            cargo
                .iter()
                .filter(|p| text(p, "licenseConcluded").contains('/'))
                .count(),
        ),
        (
            "action-unset",
            gh.iter()
                .filter(|p| {
                    or(p, "licenseConcluded", NOASSERTION) == NOASSERTION
                        || or(p, "copyrightText", NOASSERTION) == NOASSERTION
                })
                .count(),
        ),
    ]
}

/// Derive the tree twice into scratch, reduce, and record under the declared
/// tool row (retiring `[tasks.record-sbom]`).
fn record_inventory(declared: &Declared, root: &Path, overrides: &Overrides) -> Result<()> {
    let Some(id) = &declared.inventory else {
        return Err(UsageError::raise(format!(
            "{VERB} --record: [sbom] declares no `inventory` tool row to record under"
        )));
    };
    let scratch = Scratch::new("record")?;
    let mut runs = Vec::new();
    for run in ["one", "two"] {
        let (spdx, cdx) = tree_names(
            &scratch.0.join(run).display().to_string(),
            &declared.subject,
        );
        let (spdx, cdx) = (PathBuf::from(spdx), PathBuf::from(cdx));
        let metadata = derive_tree(declared, root, &spdx, &cdx)?;
        let (Some(spdx), Some(cdx)) = (read_json(&spdx), read_json(&cdx)) else {
            return unseen("the derived documents do not read back, so there is nothing to record");
        };
        runs.push((spdx, cdx, metadata));
    }
    let [(spdx_one, cdx_one, metadata), (spdx_two, cdx_two, _)] =
        <[_; 2]>::try_from(runs).map_err(|_| anyhow::anyhow!("two derivations were run"))?;
    let stable = (
        stable_form(&spdx_one) == stable_form(&spdx_two),
        stable_form(&cdx_one) == stable_form(&cdx_two),
    );
    let body = reduce(&spdx_one, &cdx_one, stable, &metadata);
    crate::record::store_tool(id, &body, overrides)
}

/// The checker's report reduced to counts, for a reader only: the module
/// decides on the exit code alone.
fn report_counts(report: &Value) -> String {
    let nonconformant = |key: &str| {
        report
            .get(key)
            .and_then(|section| section.get("nonconformantComponents"))
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    format!(
        "components={} no-supplier={} no-license={} no-copyright={}",
        report
            .get("totalNumberComponents")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        nonconformant("componentSuppliers"),
        nonconformant("componentConcludedLicenses"),
        nonconformant("componentCopyrightTexts"),
    )
}

/// Derive the SPDX document into scratch and record the declared checker's exit
/// code per standard (retiring `[tasks.ntia-record]`).
fn record_conformance(declared: &Declared, root: &Path) -> Result<()> {
    let Some(conformance) = &declared.conformance else {
        return Err(UsageError::raise(format!(
            "{VERB} --conformance: [sbom] declares no `conformance` table"
        )));
    };
    let checker = conformance.checker.as_str();
    match spawn(checker, &["--version"], root, true) {
        Some((true, _)) => {}
        Some((false, _)) => {
            return unseen(format!(
                "{checker} does not answer --version, so no verdict it gave could be trusted"
            ));
        }
        None => {
            return unseen(format!(
                "no checker at '{checker}', so conformance is unverified"
            ));
        }
    }
    let scratch = Scratch::new("conformance")?;
    let (spdx, cdx) = tree_names(
        &scratch.0.join("sbom").display().to_string(),
        &declared.subject,
    );
    let spdx = PathBuf::from(spdx);
    derive_tree(declared, root, &spdx, Path::new(&cdx))?;
    let version = read_json(&spdx)
        .and_then(|document| {
            document
                .get("spdxVersion")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
        .replace(['\t', '\n'], " ");
    let name = spdx
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut body = format!("document\t{name}\nspdx-version\t{version}\n");
    for standard in &conformance.standards {
        let report = scratch.0.join(format!("report-{standard}.json"));
        let document = spdx.display().to_string();
        let output = report.display().to_string();
        let args = [
            document.as_str(),
            "--comply",
            standard,
            "--output",
            "json",
            "--output-file",
            output.as_str(),
        ];
        let code = spawn_code(checker, &args, root);
        let counts = if code == 0 {
            "-".to_owned()
        } else {
            read_json(&report).map_or_else(|| "-".to_owned(), |report| report_counts(&report))
        };
        let _ = writeln!(body, "standard\t{standard}\t{code}\t{counts}");
    }
    crate::record::store_named(VERB, &conformance.record, &body)
}

/// A checker's exit code; a checker that cannot start or dies on a signal
/// answers non-zero, never a pass.
fn spawn_code(program: &str, args: &[&str], root: &Path) -> i32 {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the conformance verdict IS the declared checker's exit code, so acquiring it runs the checker; its report goes to a file and never to a stream (rule 4, CLOUD-843)"
    )]
    let spawned = std::process::Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    spawned.ok().and_then(|status| status.code()).unwrap_or(1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_holder_line_is_anchored_and_tidied() {
        let found = holder_lines(
            "// Copyright 2015, Yuheng Chen.\n   copyright notice that is included in or attached\n# Copyright (c) 2020 Holder\n",
        );
        assert_eq!(
            found,
            vec!["Copyright 2015, Yuheng Chen.", "Copyright (c) 2020 Holder"]
        );
    }

    #[test]
    fn the_slash_spelling_is_rewritten_and_an_empty_license_is_noassertion() {
        assert_eq!(spdx_license("Apache-2.0 / MIT"), "Apache-2.0 OR MIT");
        assert_eq!(spdx_license("MIT/Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(spdx_license(""), NOASSERTION);
    }

    #[test]
    fn the_table_reads_only_whole_pinned_rows() {
        let pin = "3d3c42e5aac5ba805825da76410c181273ba90b1";
        let table = format!(
            "# c\n\nactions/checkout@{pin}\tMIT\tNONE\nshort@{pin}\tMIT\nloose\tMIT\tX\nshortpin@deadbeef\tMIT\tX\nupper@{}\tMIT\tX\n",
            pin.to_uppercase()
        );
        let read = actions_table(&table);
        assert_eq!(read.keys().collect::<Vec<_>>(), vec!["actions/checkout"]);
    }

    #[test]
    fn the_subject_survives_a_shared_triple() {
        let document = json!({
            "packages": [
                {"SPDXID": "root", "name": "x", "versionInfo": "1"},
                {"SPDXID": "b", "name": "x", "versionInfo": "1"},
                {"SPDXID": "a", "name": "x", "versionInfo": "1"},
            ],
            "relationships": [
                {"spdxElementId": "DOC", "relatedSpdxElement": "root", "relationshipType": "DESCRIBES"},
                {"spdxElementId": "root", "relatedSpdxElement": "b", "relationshipType": "CONTAINS"},
                {"spdxElementId": "root", "relatedSpdxElement": "a", "relationshipType": "CONTAINS"},
            ],
        });
        let out = normalise_spdx(document);
        let ids: Vec<&str> = out["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["SPDXID"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["root", "a"]);
        assert_eq!(out["relationships"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_stem_is_subject_version_and_target() {
        assert_eq!(
            archive_stem("tool", "1.2.3", "x86_64-unknown-linux-gnu"),
            "tool-v1.2.3-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn a_blank_standard_list_is_refused_at_load() {
        let declared = Declared {
            subject: "tool".to_owned(),
            out_dir: "sbom".to_owned(),
            binary_out_dir: "dist".to_owned(),
            exclude: Vec::new(),
            actions: None,
            inventory: None,
            conformance: Some(Conformance {
                record: "ntia".to_owned(),
                checker: "checker".to_owned(),
                standards: Vec::new(),
            }),
        };
        assert!(declared.validate().is_err());
    }
}
