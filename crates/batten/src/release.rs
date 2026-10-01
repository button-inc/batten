//! A published release's own assets: hashed into a manifest, recorded for a
//! module, and backfilled into a tracker's release pipeline (CLOUD-843).
//!
//! # What retired into this module
//!
//! Three inline task bodies, each a `gh` pipeline with a `sha256sum`, a
//! `sort -V` or a poll loop around it:
//!
//! * `[tasks.checksums]` (CLOUD-278) is `batten release sums`: download a
//!   release's own assets, hash them in byte order, write the manifest.
//! * `[tasks.release-assets-record]`'s READING half (CLOUD-258/262/278) is
//!   `batten record release`: which assets the release carries, which names its
//!   manifest covers, and which of those disagree on bytes — `sha256sum -c`'s
//!   answer, computed here rather than spawned.
//! * `[tasks.release-backfill]` (CLOUD-618) is `batten release backfill`:
//!   dispatch one workflow per tag, oldest first, waiting on each RUN rather than
//!   on its dispatch, and stopping at the first that does not succeed.
//!
//! # Mechanism only, and the split with the modules that decide
//!
//! **Nothing here decides whether a release is healthy.** The record carries
//! NAMES — the tag, the assets, the manifest, its entries, the entries whose
//! bytes disagree — and the `release-hygiene` preset decides whether the
//! manifest covers the release; which archives and documents a release MUST
//! carry is the consumer's own module, because that list is read off the
//! consumer's own build workflow. The body this replaces derived that list with
//! `sed` and `awk` over the workflow and recorded it beside the release's facts;
//! a derivation from a committed document belongs where the document is already
//! parsed, and the record keeps only what the forge said.
//!
//! Every consumer fact is an argument: the manifest's name, the workflow to
//! dispatch, the branch it runs on and the tag glob. The repository comes from
//! [`crate::repo_slug`], the credential from `[forge] credential_names`
//! (non-negotiable rule 1).
//!
//! # Three answers, kept apart
//!
//! * **recorded / written / swept** — exit 0.
//! * **the invocation cannot run as written** — an empty manifest name, a tag
//!   argument the glob does not select, nothing to sweep: a usage error, exit 1.
//! * **could not look** — no forge remote, a forge that refused or answered
//!   something unparseable, an asset that would not download, a dispatch the
//!   forge refused or a run that did not succeed: exit 3, and `record release`
//!   REMOVES any stale record first, for `record query`'s reason — a module
//!   cannot tell an old reading from a fresh one.
//!
//! # Pointer-only
//!
//! A refusal names an endpoint, a status, an asset NAME or a tag — never a byte
//! of an asset or of a forge body (rule 4). A manifest's bytes are hashed and
//! compared, never echoed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use anyhow::Result;

use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::rest::Answer;

// THE MECHANISM'S OWN DISCRIMINATION, over the compiled binary against the
// fixture forge. Each row removes one property a packager or a gate depends on.
//MUTANT-SUITE crates/batten/tests/it/checksums.rs
//MUTANT sums-hash-the-manifest-itself|s@^    for asset in release.assets.iter().filter(.asset. asset.name != manifest) {$@    for asset in \&release.assets {@|the_manifest_covers_every_asset_never_itself_and_is_byte_stable
//MUTANT sums-written-empty|s@^    if files.is_empty() {$@    if false {@|a_release_with_no_assets_writes_no_manifest
//MUTANT-SUITE crates/batten/tests/it/release_assets.rs
//MUTANT mismatch-never-recorded|s@^            .is_some_and(.bytes. digest(bytes) != .expected)$@            .is_none()@|a_byte_mismatch_is_refused_once_the_names_agree
//MUTANT stale-record-survives-could-not-look|s@^            crate::record::clear_named(RECORD_VERB, FAMILY)?;$@@|an_unreadable_release_is_could_not_look_and_leaves_no_record
//MUTANT-SUITE crates/batten/tests/it/release_backfill.rs
//MUTANT backfill-trusts-the-dispatch|s@^                if conclusion != "success" {$@                if false {@|a_failed_run_stops_the_sweep_naming_the_tag
//MUTANT backfill-lexical-order|s@^        tags.sort_by(.left, right. version_order(left, right));$@        tags.sort();@|the_repository_tags_are_swept_oldest_first_by_version

/// The record family `record release` writes, and the one a module reads.
///
/// The engine's own family name, like every record a batten verb writes: the
/// consumer declares a `[[record]]` row for it, and what it holds is a fact about
/// a release rather than about any one consumer.
pub const FAMILY: &str = "release-assets";

/// The leaf `record release` answers for, as a refusal names it.
const RECORD_VERB: &str = "record release";

/// The leaf `release sums` answers for.
const SUMS_VERB: &str = "release sums";

/// The leaf `release backfill` answers for.
const BACKFILL_VERB: &str = "release backfill";

/// Where `release sums` writes when no `--out-dir` is given.
///
/// A directory NAME, relative to the working directory, and deliberately a
/// generic word: the manifest is a derived artifact a caller uploads and never
/// commits, so where it lands is the caller's to override and nobody's to read
/// back.
const DEFAULT_OUT_DIR: &str = "checksums";

/// One asset a release carries: the id its bytes are fetched by, and its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// The forge's id for the asset, which the download path names.
    pub id: u64,
    /// The asset's file name, as a packager downloads it.
    pub name: String,
}

/// One published release, reduced to what this module reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// The tag the release was cut from.
    pub tag: String,
    /// Its assets, sorted by name in byte order.
    pub assets: Vec<Asset>,
}

/// A JSON read against the forge, as [`crate::rest::get`] answers one.
pub type Get<'a> = &'a dyn Fn(&str) -> Option<Answer>;

/// A byte read against the forge, as [`crate::rest::download`] answers one.
pub type Download<'a> = &'a dyn Fn(&str) -> Option<(u16, Vec<u8>)>;

/// Percent-encode a path SEGMENT: everything but RFC 3986's unreserved bytes.
///
/// A tag names a path segment here, so a `/` in one must not become a path
/// separator on the wire.
fn segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// The endpoint a release is read from: the named tag's, or the latest.
///
/// **An EMPTY tag is "the latest", not a tag named ""** — the workflows pass the
/// tag quoted, so the argument always arrives, and the bodies this replaces read
/// an empty one exactly this way.
fn release_path(slug: &str, tag: Option<&str>) -> String {
    match tag.filter(|tag| !tag.is_empty()) {
        Some(tag) => format!("repos/{slug}/releases/tags/{}", segment(tag)),
        None => format!("repos/{slug}/releases/latest"),
    }
}

/// A release answer's tag and assets, or `None` where the body is not one.
fn parse_release(body: &str) -> Option<Published> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let tag = value.get("tag_name")?.as_str()?.to_owned();
    let mut assets = Vec::new();
    for asset in value.get("assets")?.as_array()? {
        assets.push(Asset {
            id: asset.get("id")?.as_u64()?,
            name: asset.get("name")?.as_str()?.to_owned(),
        });
    }
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    Some(Published { tag, assets })
}

/// Read one release, or say why it could not be read — a POINTER, never a body.
///
/// # Errors
///
/// The could-not-look pointer: the forge did not answer, answered anything but a
/// reading, or answered something that is not a release.
pub fn read_release(slug: &str, tag: Option<&str>, get: Get<'_>) -> Result<Published, String> {
    let path = release_path(slug, tag);
    let Some(answer) = get(&path) else {
        return Err(format!("the forge did not answer for {path}"));
    };
    if !answer.is_reading() {
        return Err(format!("the forge answered {} for {path}", answer.status));
    }
    parse_release(&answer.body).ok_or_else(|| format!("the answer for {path} is not a release"))
}

/// One asset's bytes, or the pointer saying why they could not be had.
fn fetch_asset(slug: &str, asset: &Asset, download: Download<'_>) -> Result<Vec<u8>, String> {
    let path = format!("repos/{slug}/releases/assets/{}", asset.id);
    match download(&path) {
        Some((200, bytes)) => Ok(bytes),
        Some((status, _)) => Err(format!(
            "the asset {} answered {status}, so it cannot be hashed",
            asset.name
        )),
        None => Err(format!(
            "the asset {} could not be downloaded, so it cannot be hashed",
            asset.name
        )),
    }
}

/// The SHA-256 of `bytes`, as lowercase hex — `sha256sum`'s spelling.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// `sha256sum`'s text-mode manifest over named contents, in byte order of name.
///
/// **Byte order, so two runs over one release write identical bytes**: the
/// artifact is a function of the release rather than of who cut it, which is the
/// property `LC_ALL=C sort` bought the body this replaces.
#[must_use]
pub fn manifest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut text = String::new();
    for (name, bytes) in files {
        text.push_str(&digest(bytes));
        text.push_str("  ");
        text.push_str(name);
        text.push('\n');
    }
    text
}

/// The `(hex, name)` entries of a manifest, in file order.
///
/// `sha256sum`'s own line format, ANCHORED: 64 hex digits, one space, a space or
/// `*` for the mode, then a non-empty name. A line of any other shape is no
/// entry, so an unreadable line can neither cover an asset nor orphan one.
#[must_use]
pub fn entries(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for line in text.lines() {
        // THE HEX IS CHECKED BEFORE THE SPLIT: a line whose first 64 bytes are
        // all ASCII has a character boundary at 64, and `split_at` would panic on
        // one that did not.
        let Some(head) = line.as_bytes().get(..64) else {
            continue;
        };
        if line.len() < 67 || !head.iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        let (hex, rest) = line.split_at(64);
        let Some(name) = rest.strip_prefix("  ").or_else(|| rest.strip_prefix(" *")) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        found.push((hex.to_ascii_lowercase(), name.to_owned()));
    }
    found
}

/// What a release's manifest says, checked against the release's own bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checked {
    /// Every name the manifest has an entry for, sorted and unique.
    pub covered: BTreeSet<String>,
    /// Every covered name whose bytes do not hash to its entry — or that the
    /// release does not carry at all, which `sha256sum -c` fails the same way.
    pub mismatched: BTreeSet<String>,
}

/// `sha256sum -c` over a release, in process.
///
/// Every entry is checked against the release's own asset of that name, the
/// manifest itself included when it lists itself: that is what running the check
/// in a directory holding every downloaded asset did, so a self-entry fails as it
/// failed there. An asset is downloaded at most once, and only when an entry
/// names it.
///
/// # Errors
///
/// The could-not-look pointer for an asset an entry names that would not
/// download.
fn check(
    slug: &str,
    release: &Published,
    listed: &[(String, String)],
    manifest_bytes: (&str, &[u8]),
    download: Download<'_>,
) -> Result<Checked, String> {
    let mut checked = Checked::default();
    let mut fetched: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    fetched.insert(manifest_bytes.0.to_owned(), manifest_bytes.1.to_vec());
    for (expected, name) in listed {
        checked.covered.insert(name.clone());
        let Some(asset) = release.assets.iter().find(|asset| asset.name == *name) else {
            checked.mismatched.insert(name.clone());
            continue;
        };
        if !fetched.contains_key(name) {
            let bytes = fetch_asset(slug, asset, download)?;
            fetched.insert(name.clone(), bytes);
        }
        if fetched
            .get(name)
            .is_some_and(|bytes| digest(bytes) != *expected)
        {
            checked.mismatched.insert(name.clone());
        }
    }
    Ok(checked)
}

/// A name the record can carry on one line: no tab and no line break.
fn recordable(name: &str) -> bool {
    !name.is_empty() && !name.contains(['\t', '\n', '\r'])
}

/// Read a release and its manifest's verdict, and compose the record body.
///
/// Everything a run needs is an argument — the slug, the transports — so the
/// whole of it is testable with no network, and [`run_record`] is this with the
/// live ones bound.
///
/// # Errors
///
/// The could-not-look pointer: no slug, a release that could not be read, an
/// asset name the record cannot carry, or an asset that would not download.
pub fn produce_record(
    slug: Option<&str>,
    tag: Option<&str>,
    manifest_name: &str,
    get: Get<'_>,
    download: Download<'_>,
) -> Result<String, String> {
    let Some(slug) = slug else {
        return Err(String::from(
            "no forge remote names the repository the release belongs to",
        ));
    };
    let release = read_release(slug, tag, get)?;
    if !recordable(&release.tag) || release.assets.iter().any(|asset| !recordable(&asset.name)) {
        return Err(String::from(
            "the release carries a name with a tab or a line break, which no record line can hold",
        ));
    }
    let mut checked = Checked::default();
    if let Some(asset) = release
        .assets
        .iter()
        .find(|asset| asset.name == manifest_name)
    {
        let bytes = fetch_asset(slug, asset, download)?;
        let listed = entries(&String::from_utf8_lossy(&bytes));
        // AN EMPTY LISTING IS NOT CHECKED, as the body this replaces did not
        // check it: there is nothing to compare, and the preset decides what a
        // manifest covering nothing means.
        if !listed.is_empty() {
            checked = check(
                slug,
                &release,
                &listed,
                (manifest_name, bytes.as_slice()),
                download,
            )?;
        }
    }
    if checked.covered.iter().any(|name| !recordable(name)) {
        return Err(String::from(
            "the manifest names an entry with a tab or a line break, which no record line can hold",
        ));
    }
    Ok(compose(&release, manifest_name, &checked))
}

/// The record body: one kind-tagged line per fact, then the census.
///
/// **THE KIND IS PREFIXED `release-`, and that is the preset's reading rather
/// than tidiness.** A preset reads every record — the family name is the
/// consumer's to declare — so it narrows on the kind column, and a bare `asset`
/// is a word any recorder might write.
fn compose(release: &Published, manifest_name: &str, checked: &Checked) -> String {
    use std::fmt::Write as _;
    let mut body = String::new();
    let _ = writeln!(body, "release-tag\t{}", release.tag);
    let _ = writeln!(body, "release-manifest\t{manifest_name}");
    for asset in &release.assets {
        let _ = writeln!(body, "release-asset\t{}", asset.name);
    }
    for name in &checked.covered {
        let _ = writeln!(body, "release-covered\t{name}");
    }
    for name in &checked.mismatched {
        let _ = writeln!(body, "release-mismatch\t{name}");
    }
    let _ = writeln!(
        body,
        "release-census\ttag=1\tmanifest=1\tasset={}\tcovered={}\tmismatch={}",
        release.assets.len(),
        checked.covered.len(),
        checked.mismatched.len()
    );
    body
}

/// Hold a manifest name to one path component a record line can carry.
fn manifest_name(verb: &str, name: &str) -> Result<()> {
    if !recordable(name) || name.contains(['/', '\\']) || name == "." || name == ".." {
        return Err(UsageError::raise(format!(
            "{verb}: `--manifest` must be one file name, not empty, a path, or a name carrying a \
             tab or a line break"
        )));
    }
    Ok(())
}

/// `batten record release [tag] --manifest <name>`: record what a release carries
/// and what its manifest says about it.
///
/// # Errors
///
/// A [`UsageError`] for a manifest name that is not one file name, or a checkout
/// with no branch to key the record on; an internal error when the store cannot
/// be written. Could-not-look is not an error: it removes any stale record, names
/// what could not be asked on `err`, and answers [`ExitCode::Internal`].
pub fn run_record(tag: Option<&str>, manifest: &str, err: &mut dyn Write) -> Result<ExitCode> {
    manifest_name(RECORD_VERB, manifest)?;
    let slug = crate::repo_slug(Path::new("."));
    let produced = produce_record(
        slug.as_deref(),
        tag,
        manifest,
        &|path: &str| crate::rest::get(path, None),
        &crate::rest::download,
    );
    match produced {
        Ok(body) => {
            crate::record::store_named(RECORD_VERB, FAMILY, &body)?;
            Ok(ExitCode::Success)
        }
        Err(why) => {
            crate::record::clear_named(RECORD_VERB, FAMILY)?;
            writeln!(err, "batten: {RECORD_VERB}: could not look: {why}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// What `release sums` derived: the tag and the manifest's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sums {
    /// The tag the release was cut from.
    pub tag: String,
    /// How many assets were hashed.
    pub hashed: usize,
    /// The manifest, in `sha256sum`'s text format.
    pub text: String,
}

/// Why `release sums` wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unwritten {
    /// The release carries nothing but, at most, a previous manifest: a manifest
    /// covering nothing is indistinguishable from no manifest.
    Empty,
    /// The forge, the remote or an asset could not be read — a pointer.
    CouldNotLook(String),
}

/// Derive a release's manifest over its own assets, never itself.
///
/// **A manifest must never hash itself.** Re-running against a release that
/// already carries one would otherwise digest the previous run's output, and the
/// file could never be reproduced from the release it describes.
///
/// # Errors
///
/// [`Unwritten::Empty`] for a release with nothing to hash, and
/// [`Unwritten::CouldNotLook`] for anything that could not be read.
pub fn produce_sums(
    slug: Option<&str>,
    tag: Option<&str>,
    manifest: &str,
    get: Get<'_>,
    download: Download<'_>,
) -> Result<Sums, Unwritten> {
    let Some(slug) = slug else {
        return Err(Unwritten::CouldNotLook(String::from(
            "no forge remote names the repository the release belongs to",
        )));
    };
    let release = read_release(slug, tag, get).map_err(Unwritten::CouldNotLook)?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for asset in release.assets.iter().filter(|asset| asset.name != manifest) {
        let bytes = fetch_asset(slug, asset, download).map_err(Unwritten::CouldNotLook)?;
        files.insert(asset.name.clone(), bytes);
    }
    if files.is_empty() {
        return Err(Unwritten::Empty);
    }
    Ok(Sums {
        tag: release.tag,
        hashed: files.len(),
        text: self::manifest(&files),
    })
}

/// `batten release sums [tag] --manifest <name> [--out-dir <dir>] [--names]`.
///
/// Prints `sums=<path>` and nothing else on stdout: the release workflow appends
/// it to its step outputs unchanged, so a second stdout line would be a second
/// output. `--names` answers the path with no tag, no network and no download.
///
/// # Errors
///
/// A [`UsageError`] for a manifest name that is not one file name; an internal
/// error when the manifest cannot be written. A release that could not be read
/// is [`ExitCode::Internal`] with a pointer on `err`, and one with nothing to
/// hash is the same code with nothing written.
pub fn run_sums(
    tag: Option<&str>,
    manifest: &str,
    out_dir: Option<&str>,
    names: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    manifest_name(SUMS_VERB, manifest)?;
    let path = Path::new(out_dir.unwrap_or(DEFAULT_OUT_DIR)).join(manifest);
    if names {
        writeln!(out, "sums={}", path.display())?;
        return Ok(ExitCode::Success);
    }
    let slug = crate::repo_slug(Path::new("."));
    let produced = produce_sums(
        slug.as_deref(),
        tag,
        manifest,
        &|path: &str| crate::rest::get(path, None),
        &crate::rest::download,
    );
    let sums = match produced {
        Ok(sums) => sums,
        Err(Unwritten::Empty) => {
            writeln!(
                err,
                "batten: {SUMS_VERB}: the release carries no asset to hash, and a manifest \
                 covering nothing is indistinguishable from none, so none is written"
            )?;
            return Ok(ExitCode::Internal);
        }
        Err(Unwritten::CouldNotLook(why)) => {
            writeln!(err, "batten: {SUMS_VERB}: could not look: {why}")?;
            return Ok(ExitCode::Internal);
        }
    };
    // WRITTEN WHOLE OR NOT AT ALL: `durable::replace` writes beside the target
    // and renames, so a failed run never leaves a truncated manifest for the
    // upload step to publish.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::durable::replace(&path, sums.text.as_bytes())?;
    writeln!(
        err,
        "{SUMS_VERB}: {} — {} asset(s) hashed",
        sums.tag, sums.hashed
    )?;
    writeln!(out, "sums={}", path.display())?;
    Ok(ExitCode::Success)
}

// --- release backfill -----------------------------------------------------------

/// `sort -V`'s order over two tag names: digit runs compare as numbers, every
/// other run as bytes.
///
/// `v0.0.110` sorts after `v0.0.78` — which byte order gets backwards, and the
/// action a backfill drives derives each release's issues from the tag's commit
/// range, so a wrong order records the wrong ranges.
#[must_use]
pub fn version_order(left: &str, right: &str) -> std::cmp::Ordering {
    let runs = |text: &str| -> Vec<(bool, String)> {
        let mut found: Vec<(bool, String)> = Vec::new();
        for character in text.chars() {
            let digit = character.is_ascii_digit();
            match found.last_mut() {
                Some((kind, run)) if *kind == digit => run.push(character),
                _ => found.push((digit, character.to_string())),
            }
        }
        found
    };
    let (left_runs, right_runs) = (runs(left), runs(right));
    for (one, other) in left_runs.iter().zip(right_runs.iter()) {
        let order = match (one, other) {
            ((true, a), (true, b)) => {
                let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
                a.len().cmp(&b.len()).then_with(|| a.cmp(b))
            }
            ((_, a), (_, b)) => a.cmp(b),
        };
        if order != std::cmp::Ordering::Equal {
            return order;
        }
    }
    left_runs
        .len()
        .cmp(&right_runs.len())
        .then_with(|| left.cmp(right))
}

/// What a backfill is asked to do, every consumer fact an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backfill {
    /// Tags named on the command line, in the order written; empty means every
    /// tag the glob selects, oldest first.
    pub tags: Vec<String>,
    /// The workflow file to dispatch once per tag.
    pub workflow: String,
    /// The branch the dispatched runs execute on.
    pub reference: String,
    /// The glob a release tag matches, as `git tag --list` matches it.
    pub pattern: String,
    /// Print the plan and dispatch nothing.
    pub dry_run: bool,
    /// Seconds between polls; the server's own interval and backoff raise it.
    pub poll_interval: u64,
    /// The COUNT of polls per tag before the run is reported as never finishing.
    pub max_polls: u64,
}

/// A whole number off the command line, or its default.
///
/// # Errors
///
/// A [`UsageError`] naming the flag when the value is not a whole number.
pub fn whole_number(flag: &str, raw: Option<&str>, default: u64) -> Result<u64> {
    match raw {
        None => Ok(default),
        Some(raw) => raw.trim().parse::<u64>().map_err(|_| {
            UsageError::raise(format!(
                "{BACKFILL_VERB}: `--{flag}` must be a whole number"
            ))
        }),
    }
}

/// The tags to sweep: the named ones as written, or the glob's, oldest first.
///
/// # Errors
///
/// A [`UsageError`] when a named tag is not one the glob selects — the whole bad
/// list at once, before any dispatch — or when there is nothing to sweep: nothing
/// here can tell an empty repository from a bad glob, so that is a refusal rather
/// than a clean sweep of nothing. An internal error when the tags cannot be read.
pub fn plan(request: &Backfill, root: &Path) -> Result<Vec<String>> {
    let mut tags = request.tags.clone();
    if tags.is_empty() {
        let listed = crate::git::tag_facts(root, std::slice::from_ref(&request.pattern))?;
        tags = listed
            .get(&request.pattern)
            .map(|facts| facts.iter().map(|fact| fact.tag.clone()).collect())
            .unwrap_or_default();
        tags.sort_by(|left, right| version_order(left, right));
    }
    if tags.is_empty() {
        return Err(UsageError::raise(format!(
            "{BACKFILL_VERB}: no tag to record — nothing here can tell an empty repository from a \
             glob that selects nothing, so this is a refusal rather than a clean sweep of nothing"
        )));
    }
    let bad: Vec<&str> = tags
        .iter()
        .filter(|tag| !crate::git::tag_glob_matches(&request.pattern, tag))
        .map(String::as_str)
        .collect();
    if !bad.is_empty() {
        return Err(UsageError::raise(format!(
            "{BACKFILL_VERB}: {} argument(s) are not release tags under `{}`: {}",
            bad.len(),
            request.pattern,
            bad.join(" ")
        )));
    }
    Ok(tags)
}

/// The newest run of a workflow, by id, or `None` where there is none or the
/// read failed — the body this replaces read both as "nothing yet".
fn newest_run(slug: &str, workflow: &str, get: Get<'_>) -> Option<u64> {
    let path = format!(
        "repos/{slug}/actions/workflows/{}/runs?per_page=1",
        segment(workflow)
    );
    let answer = get(&path)?;
    if !answer.is_reading() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(&answer.body).ok()?;
    value
        .get("workflow_runs")?
        .as_array()?
        .first()?
        .get("id")?
        .as_u64()
}

/// A run's `(status, conclusion)`, with an absent conclusion as the empty word,
/// and the server's asked-for pause.
fn run_state(slug: &str, id: u64, get: Get<'_>) -> (Option<(String, String)>, f64) {
    let Some(answer) = get(&format!("repos/{slug}/actions/runs/{id}")) else {
        return (None, 0.0);
    };
    let floor = crate::pr_watch::wait_for(0, answer.poll_floor, answer.backoff);
    if !answer.is_reading() {
        return (None, floor);
    }
    let state = serde_json::from_str::<serde_json::Value>(&answer.body)
        .ok()
        .and_then(|value| {
            let status = value.get("status")?.as_str()?.to_owned();
            let conclusion = value
                .get("conclusion")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Some((status, conclusion))
        });
    (state, floor)
}

/// The transports and the pause a sweep runs over, so the whole loop is
/// testable offline.
pub struct Forge<'a> {
    /// A JSON read.
    pub get: Get<'a>,
    /// A dispatch: the path and the JSON body, answering the status.
    pub post: &'a dyn Fn(&str, &serde_json::Value) -> Option<u16>,
    /// The wait between polls, in seconds.
    pub pause: &'a dyn Fn(f64),
}

impl std::fmt::Debug for Forge<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Forge").finish_non_exhaustive()
    }
}

/// Dispatch the workflow for ONE tag and wait on the RUN it started.
///
/// **A DISPATCH RETURNING SUCCESS MEANS ACCEPTED, NOT RECORDED**, so the newest
/// run id is read BEFORE the dispatch and the wait is for a DIFFERENT one: the
/// previous tag's completed run is never taken for this one. The poll cap is a
/// COUNT backstop shared across both waits, never a wall clock.
///
/// # Errors
///
/// The pointer naming what stopped this tag: a refused dispatch, a run that
/// never appeared, one that never finished, or one that did not succeed.
fn sweep_one(slug: &str, request: &Backfill, tag: &str, forge: &Forge<'_>) -> Result<u64, String> {
    let before = newest_run(slug, &request.workflow, forge.get);
    let dispatch = format!(
        "repos/{slug}/actions/workflows/{}/dispatches",
        segment(&request.workflow)
    );
    let body = serde_json::json!({"ref": request.reference, "inputs": {"tag": tag}});
    match (forge.post)(&dispatch, &body) {
        Some(status) if (200..300).contains(&status) => {}
        Some(status) => return Err(format!("the dispatch for {tag} was refused ({status})")),
        None => return Err(format!("the dispatch for {tag} could not be sent")),
    }
    let interval = crate::pr_watch::wait_for(request.poll_interval, None, None);
    let mut polls = 0_u64;
    let id = loop {
        polls += 1;
        if polls > request.max_polls {
            return Err(format!(
                "the run dispatched for {tag} never appeared after {} poll(s) — a dispatch the \
                 forge accepted and never scheduled is a platform failure, not a slow run",
                request.max_polls
            ));
        }
        match newest_run(slug, &request.workflow, forge.get) {
            Some(candidate) if Some(candidate) != before => break candidate,
            _ => (forge.pause)(interval),
        }
    };
    loop {
        polls += 1;
        if polls > request.max_polls {
            return Err(format!(
                "run {id} for {tag} did not finish within {} poll(s)",
                request.max_polls
            ));
        }
        let (state, floor) = run_state(slug, id, forge.get);
        match state {
            Some((status, conclusion)) if status == "completed" => {
                if conclusion != "success" {
                    return Err(format!(
                        "{tag} concluded `{conclusion}` in run {id}; read that run before \
                         re-running — a credential the action refuses fails every tag identically"
                    ));
                }
                return Ok(id);
            }
            _ => (forge.pause)(interval.max(floor)),
        }
    }
}

/// Sweep every tag in order over `forge`, stopping at the first that fails.
///
/// **SERIALLY AND STOPPING ON THE FIRST FAILURE**: a refused credential fails
/// every tag identically, and the action's `sync` is create-or-update, so the
/// sweep is resumable exactly where it stopped.
///
/// # Errors
///
/// An internal error when `out` or `err` cannot be written.
pub fn sweep(
    slug: &str,
    request: &Backfill,
    tags: &[String],
    forge: &Forge<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let mut recorded = 0_usize;
    for tag in tags {
        match sweep_one(slug, request, tag, forge) {
            Ok(id) => {
                recorded += 1;
                writeln!(out, "{BACKFILL_VERB}: {tag} recorded (run {id})")?;
            }
            Err(why) => {
                writeln!(
                    err,
                    "batten: {BACKFILL_VERB}: {why}; {recorded} tag(s) were recorded before this, \
                     and re-running costs nothing for them"
                )?;
                return Ok(ExitCode::Internal);
            }
        }
    }
    writeln!(
        out,
        "{BACKFILL_VERB}: {} tag(s) recorded, oldest first",
        tags.len()
    )?;
    Ok(ExitCode::Success)
}

/// `batten release backfill`: plan the tags, then sweep them — or print the plan.
///
/// # Errors
///
/// As [`plan`]; and could-not-look — no forge remote, a refused dispatch, a run
/// that never appeared, never finished or did not succeed — is
/// [`ExitCode::Internal`] with a pointer on `err`.
pub fn run_backfill(
    request: &Backfill,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    let tags = plan(request, root)?;
    if request.dry_run {
        writeln!(
            out,
            "{BACKFILL_VERB}: would dispatch {} for {} tag(s), oldest first:",
            request.workflow,
            tags.len()
        )?;
        for tag in &tags {
            writeln!(out, "  {tag}")?;
        }
        return Ok(ExitCode::Success);
    }
    let Some(slug) = crate::repo_slug(root) else {
        writeln!(
            err,
            "batten: {BACKFILL_VERB}: could not look: no forge remote names the repository to \
             dispatch in"
        )?;
        return Ok(ExitCode::Internal);
    };
    let forge = Forge {
        get: &|path: &str| crate::rest::get(path, None),
        post: &|path: &str, body: &serde_json::Value| {
            crate::rest::post_json(path, body).map(|answer| answer.status)
        },
        pause: &crate::pr_watch::pause,
    };
    sweep(&slug, request, &tags, &forge, out, err)
}

/// Dispatch the `release` sub-verbs this module answers.
///
/// # Errors
///
/// Whatever the chosen sub-verb returns.
pub fn run(
    command: crate::cli::ReleaseCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        crate::cli::ReleaseCommand::Sums {
            tag,
            manifest,
            out_dir,
            names,
        } => run_sums(
            tag.as_deref(),
            &manifest,
            out_dir.as_deref(),
            names,
            out,
            err,
        ),
        crate::cli::ReleaseCommand::Backfill {
            tags,
            workflow,
            reference,
            pattern,
            dry_run,
            poll_interval,
            max_polls,
        } => {
            let request = Backfill {
                tags,
                workflow,
                reference,
                pattern,
                dry_run,
                poll_interval: whole_number("poll-interval", poll_interval.as_deref(), 5)?,
                max_polls: whole_number("max-polls", max_polls.as_deref(), 240)?,
            };
            run_backfill(&request, out, err)
        }
        crate::cli::ReleaseCommand::Install => Err(anyhow::anyhow!(
            "release install is answered by the engine's own dispatch, never here"
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn reading(body: &str) -> Answer {
        Answer {
            status: 200,
            etag: None,
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
            headers: BTreeMap::new(),
        }
    }

    const RELEASE: &str = r#"{"tag_name": "v1.2.3", "assets": [
        {"id": 2, "name": "b.tar.gz"},
        {"id": 1, "name": "a.tar.gz"},
        {"id": 3, "name": "SUMS"}
    ]}"#;

    fn bytes_of(path: &str) -> Vec<u8> {
        format!("bytes of {}\n", path.rsplit('/').next().unwrap()).into_bytes()
    }

    #[test]
    fn an_empty_tag_is_the_latest_and_a_named_one_is_encoded() {
        assert_eq!(release_path("o/r", None), "repos/o/r/releases/latest");
        assert_eq!(release_path("o/r", Some("")), "repos/o/r/releases/latest");
        assert_eq!(
            release_path("o/r", Some("v1/x")),
            "repos/o/r/releases/tags/v1%2Fx"
        );
    }

    #[test]
    fn a_release_parses_sorted_and_a_non_release_is_none() {
        let parsed = parse_release(RELEASE).unwrap();
        assert_eq!(parsed.tag, "v1.2.3");
        let names: Vec<&str> = parsed.assets.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["SUMS", "a.tar.gz", "b.tar.gz"]);
        assert!(parse_release(r#"{"message": "Not Found"}"#).is_none());
    }

    #[test]
    fn the_manifest_is_sha256sums_text_format_in_byte_order() {
        let files = BTreeMap::from([
            (String::from("b"), b"two".to_vec()),
            (String::from("a"), b"one".to_vec()),
        ]);
        let text = manifest(&files);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].ends_with("  a") && lines[1].ends_with("  b"),
            "{text}"
        );
        assert_eq!(
            digest(b"one"),
            "7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed"
        );
    }

    #[test]
    fn only_an_anchored_entry_is_read() {
        let hex = "a".repeat(64);
        let text = format!(
            "{hex}  one\n{hex} *two\n{hex} three\nnot a line\n{}  short\n",
            "a".repeat(63)
        );
        let found = entries(&text);
        let names: Vec<&str> = found.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, ["one", "two"]);
    }

    #[test]
    fn a_record_names_coverage_and_mismatch_and_is_self_consistent() {
        let a = digest(&bytes_of("x/1"));
        let sums = format!(
            "{a}  a.tar.gz\n{}  b.tar.gz\n{}  ghost.zip\n",
            "0".repeat(64),
            "0".repeat(64)
        );
        let get = |_: &str| Some(reading(RELEASE));
        let download = |path: &str| -> Option<(u16, Vec<u8>)> {
            if path.ends_with("/3") {
                Some((200, sums.clone().into_bytes()))
            } else {
                Some((200, bytes_of(path)))
            }
        };
        let body = produce_record(Some("o/r"), Some("v1.2.3"), "SUMS", &get, &download).unwrap();
        assert!(body.contains("release-covered\tghost.zip\n"), "{body}");
        assert!(body.contains("release-mismatch\tb.tar.gz\n"), "{body}");
        assert!(body.contains("release-mismatch\tghost.zip\n"), "{body}");
        assert!(!body.contains("release-mismatch\ta.tar.gz"), "{body}");
        assert!(
            body.ends_with("release-census\ttag=1\tmanifest=1\tasset=3\tcovered=3\tmismatch=2\n"),
            "{body}"
        );
    }

    #[test]
    fn no_slug_and_a_refusing_forge_are_could_not_look() {
        let get = |_: &str| {
            Some(Answer {
                status: 404,
                ..reading("{}")
            })
        };
        let download = |_: &str| None;
        assert!(produce_record(None, None, "SUMS", &get, &download).is_err());
        let why = produce_record(Some("o/r"), None, "SUMS", &get, &download).unwrap_err();
        assert!(why.contains("404"), "{why}");
    }

    #[test]
    fn sums_never_hash_the_manifest_and_refuse_an_empty_release() {
        let get = |_: &str| Some(reading(RELEASE));
        let download = |path: &str| Some((200, bytes_of(path)));
        let sums = produce_sums(Some("o/r"), None, "SUMS", &get, &download).unwrap();
        assert_eq!(sums.hashed, 2);
        assert!(!sums.text.contains("SUMS"), "{}", sums.text);
        let only = |_: &str| {
            Some(reading(
                r#"{"tag_name": "v1", "assets": [{"id": 3, "name": "SUMS"}]}"#,
            ))
        };
        assert_eq!(
            produce_sums(Some("o/r"), None, "SUMS", &only, &download),
            Err(Unwritten::Empty)
        );
    }

    #[test]
    fn version_order_is_numeric_per_run() {
        let mut tags = vec!["v0.0.110", "v0.0.78", "v0.0.9", "v0.1.0"];
        tags.sort_by(|a, b| version_order(a, b));
        assert_eq!(tags, ["v0.0.9", "v0.0.78", "v0.0.110", "v0.1.0"]);
    }

    fn request() -> Backfill {
        Backfill {
            tags: Vec::new(),
            workflow: String::from("backfill.yml"),
            reference: String::from("main"),
            pattern: String::from("v[0-9]*"),
            dry_run: false,
            poll_interval: 0,
            max_polls: 3,
        }
    }

    #[test]
    fn a_dispatch_waits_for_a_new_run_and_its_success() {
        let asked = std::cell::RefCell::new(0_u32);
        let get = |path: &str| {
            if path.contains("/runs?") {
                let mut n = asked.borrow_mut();
                *n += 1;
                // Before the dispatch the newest run is 7; the second read sees 8.
                let id = if *n == 1 { 7 } else { 8 };
                Some(reading(&format!(
                    r#"{{"workflow_runs": [{{"id": {id}}}]}}"#
                )))
            } else {
                Some(reading(
                    r#"{"status": "completed", "conclusion": "success"}"#,
                ))
            }
        };
        let post = |_: &str, _: &serde_json::Value| Some(204_u16);
        let pause = |_: f64| {};
        let forge = Forge {
            get: &get,
            post: &post,
            pause: &pause,
        };
        assert_eq!(sweep_one("o/r", &request(), "v1", &forge), Ok(8));
    }

    #[test]
    fn a_run_that_does_not_succeed_or_never_appears_stops_the_tag() {
        let failed = |path: &str| {
            if path.contains("/runs?") {
                Some(reading(r#"{"workflow_runs": [{"id": 9}]}"#))
            } else {
                Some(reading(
                    r#"{"status": "completed", "conclusion": "failure"}"#,
                ))
            }
        };
        let post = |_: &str, _: &serde_json::Value| Some(204_u16);
        let pause = |_: f64| {};
        // The run never changes from the one read before the dispatch.
        let forge = Forge {
            get: &failed,
            post: &post,
            pause: &pause,
        };
        let why = sweep_one("o/r", &request(), "v1", &forge).unwrap_err();
        assert!(why.contains("never appeared"), "{why}");
        let refused = |_: &str, _: &serde_json::Value| Some(403_u16);
        let forge = Forge {
            get: &failed,
            post: &refused,
            pause: &pause,
        };
        let why = sweep_one("o/r", &request(), "v1", &forge).unwrap_err();
        assert!(why.contains("refused"), "{why}");
    }
}
