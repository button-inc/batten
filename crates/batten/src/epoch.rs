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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config_model::Config;
use crate::error::UsageError;
use crate::identity::{canonical_repo_path, surface_fingerprint};
use crate::{git, trust_pin};

/// The tracked path used when a config declares no `[epoch]` table.
///
/// `batten.toml` governs every consumer by definition, so it is the honest
/// floor: an epoch over nothing would be a constant, which attributes nothing.
pub const DEFAULT_TRACKED: &str = crate::config_model::CONFIG_FILE;

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

/// The epoch and its surface, served from the cache when it revalidates.
///
/// Identical output to [`describe`] or it is a bug — that equality is the whole
/// safety bar, and `--no-cache` exists so a test can assert it rather than argue
/// it. Everything here is an optimization over a value [`describe`] alone
/// already defines; nothing about *what* the epoch is lives in this path.
///
/// # Errors
///
/// As [`compute`]. A cache that cannot be read, parsed, or written is **not**
/// an error: it is derived out-of-tree state, so every such failure degrades to
/// the cold recompute. A cache that can fail a run is worse than no cache.
pub fn describe_cached(dir: &Path, base_ref: Option<&str>) -> Result<(String, Vec<String>)> {
    // Under `--config-from` the epoch covers a git ref, not the working tree, so
    // a filesystem stamp describes the wrong bytes entirely. Cold path only.
    if base_ref.is_some() {
        return describe(dir, base_ref);
    }
    let config = authority(dir, base_ref)?;
    let tracked = tracked_paths(&config)?;

    // A stamp we cannot take is a MISS, never a hit. If a tracked path has gone
    // unreadable, falling through re-reads it and raises the `UsageError` that
    // names it — where returning the cached hash would forge a stable epoch over
    // a surface that changed, and exit 0 doing it. That is the exact false green
    // this module exists to prevent (see the module docs), reintroduced by a
    // shortcut rather than by a skip.
    let stamps = stamp_tracked(dir, &tracked);
    // Resolved once for the read and the write.
    let state = state_dir(dir);
    let path = state.as_deref().and_then(cache_path);

    if let Some(stamps) = stamps.as_ref()
        && let Some(path) = path.as_deref()
        && let Some(epoch) = read_cache(path, &cache_key(&tracked, stamps), stamps)
    {
        return Ok((epoch, tracked));
    }

    let (epoch, tracked) = describe(dir, base_ref)?;
    // Re-stamped AFTER the read, never reusing the pre-read stamps: a file
    // rewritten between the two would otherwise be cached under the mtime it had
    // before the change, and the next run would serve a hash of bytes that are
    // already gone.
    if let Some(stamps) = stamp_tracked(dir, &tracked)
        && let Some(state) = state.as_deref()
        && let Some(path) = path.as_deref()
    {
        write_cache(path, &cache_key(&tracked, &stamps), &epoch);
        // The retired record sat beside the state rather than under `cache/`.
        let _ = std::fs::remove_file(state.join(RETIRED_FILE));
    }
    Ok((epoch, tracked))
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

/// The cache entry's format, through [`crate::cache::key`]: a change to how an
/// entry is written bumps it, which makes every older entry a miss. `2` since
/// the cache moved onto `crate::cache` (CLOUD-2315).
const CACHE_FORMAT: &str = "batten-epoch-2";

/// The entry's name under the repository's cache directory.
const CACHE_FILE: &str = "epoch";

/// The entry's retired name, removed on a write so it does not linger.
const RETIRED_FILE: &str = "epoch.json";

/// Stamp every tracked path, or `None` if any one of them cannot be stamped.
///
/// All-or-nothing on purpose: a partial stamp set would revalidate against the
/// paths that still exist and say nothing about the one that does not, which is
/// the silent-skip failure wearing a different hat.
///
/// THE STAMP IS `crate::cache`'s (CLOUD-2315), not a second one here. This used
/// to stamp size and mtime alone and called the pair strong because "either
/// alone is weak"; the shared stamp adds inode and ctime, which a `touch -r` or
/// a fixed-mtime extraction cannot restore.
fn stamp_tracked(dir: &Path, tracked: &[String]) -> Option<Vec<crate::cache::Stamp>> {
    tracked
        .iter()
        .map(|path| crate::cache::stamp(&dir.join(path)))
        .collect()
}

/// The key the entry is filed under: each tracked PATH and its stamp, so adding
/// or removing a path invalidates even when every surviving file is unchanged.
fn cache_key(tracked: &[String], stamps: &[crate::cache::Stamp]) -> String {
    let mut fields: Vec<&[u8]> = Vec::with_capacity(2 * tracked.len());
    for (path, stamp) in tracked.iter().zip(stamps) {
        fields.push(path.as_bytes());
        fields.push(stamp.fields.as_bytes());
    }
    crate::cache::key(CACHE_FORMAT, &fields)
}

/// This repository's state directory, or `None` when none resolves.
///
/// Canonicalized first, and that is load-bearing rather than tidy: callers reach
/// this with `Path::new(".")`, whose final component is `None`, so
/// [`crate::state::derive_repo_name`] refuses it and every run would silently
/// take the no-cache path. A cache that is never written is not a safe default —
/// it is a feature that reports success and does nothing.
fn state_dir(dir: &Path) -> Option<PathBuf> {
    let absolute = std::fs::canonicalize(dir).ok()?;
    crate::state::repo_state_dir(&absolute).ok()
}

/// The entry under the repository's state directory `state`.
fn cache_path(state: &Path) -> Option<PathBuf> {
    Some(crate::cache::root_under(state)?.join(CACHE_FILE))
}

/// The cached epoch, or `None` for absent, unreadable, torn, another key — or
/// racily clean.
///
/// Every failure is the same answer — recompute — so none of them is
/// distinguished, and a corrupted cache costs a run nothing but the work it was
/// meant to save.
///
/// RACILY CLEAN IS A MISS (CLOUD-2315), git's rule from
/// `Documentation/technical/racy-git`: a tracked file whose change time is not
/// strictly older than the entry's write time may have been rewritten in the
/// same timestamp tick, with every stamped field unchanged, so the entry cannot
/// vouch for it.
fn read_cache(path: &Path, key: &str, stamps: &[crate::cache::Stamp]) -> Option<String> {
    let body = String::from_utf8(crate::cache::read(path, key)?).ok()?;
    let (written, epoch) = body.split_once(' ')?;
    let (secs, nanos) = written.split_once('.')?;
    let written = std::time::Duration::new(secs.parse().ok()?, nanos.parse().ok()?);
    if stamps.iter().any(|stamp| stamp.racily_clean(written)) {
        return None;
    }
    Some(epoch.to_owned())
}

/// Publish the entry, ignoring every failure: `<written> <epoch>`, where the
/// write time is what [`read_cache`]'s racy check compares against.
///
/// Nothing here can fail the run. A read-only state directory, a full disk, or a
/// racing writer all leave the epoch already computed and correct — the cache is
/// an optimization, and an optimization that can refuse the answer is a defect.
fn write_cache(path: &Path, key: &str, epoch: &str) {
    let written = crate::cache::now();
    let body = format!(
        "{}.{:09} {epoch}",
        written.as_secs(),
        written.subsec_nanos()
    );
    crate::cache::write(path, key, body.as_bytes());
}

/// The config whose `[epoch] tracked` list governs, from the same place its
/// bytes will come from.
fn authority(dir: &Path, base_ref: Option<&str>) -> Result<Config> {
    match base_ref {
        Some(reference) => trust_pin::load_base(dir, reference, crate::config::parse_base),
        None => crate::config::load(&dir.join(crate::config_model::CONFIG_FILE)),
    }
}

/// The epoch an admission for `rule`/`verdict` binds (CLOUD-2779).
///
/// **THE SURFACE THAT DECIDES THIS RULE, NOT THE WHOLE CONFIG.** The admission
/// epoch used to be [`describe`]'s, so any `batten.toml` edit — a comment, a
/// pattern only another module reads — unbound every outstanding admission for
/// every rule. Measured on #1276: narrowing one `[[pattern]]` unbound four held
/// admissions, the `filed-row-settled` handler then refused every Edit, and a
/// landing lap refused in tier 1. The property the epoch exists for is
/// [`crate::admission::Binding::epoch`]'s — an admission does not survive the
/// policy change that would have made it unnecessary — and that is a change to
/// what decides THIS rule.
///
/// `batten.toml` enters as a parsed projection ([`project_reading`]): comments
/// and layout dropped, and of the id-keyed rows only this rule's `[[rule]]`,
/// the `[[verdict]]` rows naming this rule or verdict, and — when the rule has
/// a module — the `[[pattern]]` rows that module reads ([`pattern_reads`]):
/// every row when it reads one by a computed id.
///
/// **AN ALLOWLIST WHERE THE MODULE'S READS ARE KNOWN** (CLOUD-2789). A module
/// row compiles from its one file and decides from `data.batten.patterns` and
/// its `input`, so when every `input` path its code reads is a named
/// `input.tree` key ([`TreeReads`]) the projection keeps only the tables that
/// build those keys, and the tracked files only where the row hands it their
/// CONTENT (`documents`, `lines`, `invocations`, `uses`, `units`). Hashed whole,
/// an unrelated `[[verb]]` or `AGENTS.md` edit unbound every held `issue file
/// held` admission. A read it cannot name — `input.call`, `input.facts`, a bare
/// `input.tree`, a computed key — keeps every table but the narrowed rows and
/// every tracked file, as before; a key built from every row's declarations
/// keeps every `[[rule]]` row. A row whose selectors reach `batten.toml` itself
/// reads all of it, so it is hashed whole. The rule's module, which the surface
/// does not track, and the engine version are added.
///
/// # Errors
///
/// As [`compute`], and a `batten.toml` that will not parse as TOML.
pub fn for_rule(dir: &Path, base_ref: Option<&str>, rule: &str, verdict: &str) -> Result<String> {
    let config = authority(dir, base_ref)?;
    let tracked = tracked_paths(&config)?;
    let row = config.rules.iter().find(|row| row.id == rule);
    let reads = match row.and_then(|row| row.module.as_deref()) {
        Some(module) => {
            let path = canonical_repo_path(module)?;
            let source = read_tracked(dir, &path, base_ref)?;
            Some(Reads {
                patterns: pattern_reads(&source),
                input: std::str::from_utf8(&source)
                    .ok()
                    .and_then(|text| crate::policy::module_input_paths(&path, text)),
            })
        }
        None => None,
    };
    // What the row hands its module as file CONTENT, over the tracked set.
    let read_files = match row {
        Some(row) if reads.is_some() => Some(content_paths(row, &tracked)?),
        _ => None,
    };
    let config_read_whole = read_files
        .as_ref()
        .is_some_and(|files| files.contains(crate::config_model::CONFIG_FILE));
    // Narrowed only where nothing the module reads opens a file its row does
    // not name: `traversals`, `shell` and every key built from all rows may.
    let narrowed = reads
        .as_ref()
        .and_then(|reads| reads.input.as_ref())
        .and_then(TreeReads::of)
        .is_some_and(|tree| tree.opens_only_declared_files());
    let mut entries = Vec::new();
    let mut module = None;
    for path in &tracked {
        let is_config = path == crate::config_model::CONFIG_FILE;
        if narrowed
            && !is_config
            && !read_files
                .as_ref()
                .is_some_and(|files| files.contains(path))
        {
            continue;
        }
        let contents = read_tracked(dir, path, base_ref)?;
        if is_config && !config_read_whole {
            let answer = |_: &str| -> Result<Reads> { Ok(reads.clone().unwrap_or_default()) };
            let (projected, declared) = project_reading(&contents, rule, verdict, &answer)?;
            module = declared;
            entries.push((path.clone(), projected));
        } else {
            if is_config {
                module = row.and_then(|row| row.module.clone());
            }
            entries.push((path.clone(), contents));
        }
    }
    if let Some(module) = module {
        let path = canonical_repo_path(&module)?;
        let contents = read_tracked(dir, &path, base_ref)?;
        entries.push((path, contents));
    }
    entries.push((
        String::from("engine"),
        env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
    ));
    Ok(surface_fingerprint(&entries).to_hex())
}

/// [`for_rule`], served from the cache while [`describe_cached`]'s whole-surface
/// epoch is unchanged: the per-rule value is a function of that surface, the
/// rule's module and the engine, so an unchanged surface key with an unchanged
/// module answers the same value. Cold under `--config-from`, as there.
///
/// # Errors
///
/// As [`for_rule`].
pub fn for_rule_cached(
    dir: &Path,
    base_ref: Option<&str>,
    rule: &str,
    verdict: &str,
) -> Result<String> {
    if base_ref.is_some() {
        return for_rule(dir, base_ref, rule, verdict);
    }
    let (surface, _) = describe_cached(dir, None)?;
    let entry = state_dir(dir)
        .as_deref()
        .and_then(crate::cache::root_under)
        .map(|root| {
            let key = surface_fingerprint(&[
                (String::from("surface"), surface.into_bytes()),
                (String::from("rule"), rule.as_bytes().to_vec()),
                (String::from("verdict"), verdict.as_bytes().to_vec()),
                (
                    String::from("engine"),
                    env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
                ),
            ])
            .to_hex();
            root.join("epoch-rule").join(key)
        });
    // THE MODULE IS NOT ON THE SURFACE, so a hit is only as good as the module
    // being unchanged. The surface in the key fixes which module the rule
    // names, so the entry stores that path and the module's digest, and a hit
    // re-reads the module alone — never the config it was projected from.
    if let Some(entry) = entry.as_deref()
        && let Ok(stored) = crate::fsio::read_to_string(entry)
        && let Some((value, rest)) = stored.split_once('\n')
        && let Some((module, digest)) = rest.split_once('\n')
        && module_digest(dir, (!module.is_empty()).then_some(module)) == digest
    {
        return Ok(value.to_owned());
    }
    let value = for_rule(dir, None, rule, verdict)?;
    let module = crate::fsio::read(dir.join(crate::config_model::CONFIG_FILE))
        .ok()
        .and_then(|text| project(&text, rule, verdict, &|_| Ok(None)).ok())
        .and_then(|(_, module)| module);
    if let Some(entry) = entry.as_deref()
        && let Some(parent) = entry.parent()
        && std::fs::create_dir_all(parent).is_ok()
    {
        let text = format!(
            "{value}\n{}\n{}",
            module.as_deref().unwrap_or_default(),
            module_digest(dir, module.as_deref())
        );
        let _ = crate::durable::replace(entry, text);
    }
    Ok(value)
}

/// The digest of the module at `module` in the working tree, or of nothing for
/// a rule with none; an unreadable module digests as absent, which no stored
/// digest of a present one equals.
fn module_digest(dir: &Path, module: Option<&str>) -> String {
    let bytes = module
        .and_then(|module| crate::fsio::read(dir.join(module)).ok())
        .unwrap_or_default();
    surface_fingerprint(&[(String::from("module"), bytes)]).to_hex()
}

/// What a module row's code reads, as [`project_reading`] narrows to it.
/// `Default` is the could-not-look answer: every pattern, unknown input.
#[derive(Clone, Default)]
struct Reads {
    /// The `[[pattern]]` ids it reads ([`pattern_reads`]), `None` for every one.
    patterns: Option<BTreeSet<String>>,
    /// The `input` paths its non-test rules read, dotted without `input.`
    /// ([`crate::policy::module_input_paths`]), `None` when not established.
    input: Option<BTreeSet<String>>,
}

/// The `input.tree` keys a module reads, when every read it makes is one.
struct TreeReads {
    /// Each key, the first segment after `tree.`.
    keys: BTreeSet<String>,
    /// The `input.tree.records` subpaths it reads, `None` when it reads the
    /// family whole (or by a computed name).
    records: Option<BTreeSet<String>>,
}

/// The tree keys whose value a row's OWN declarations and the subject decide:
/// its declared paths (`documents` … `units`, selected per row in
/// `rules::policy_rule`), the walk, the could-not-look channel, and the
/// recorder receipts, which no table names.
const SELF_DECLARED: &[&str] = &[
    "documents",
    "tracked",
    "lines",
    "invocations",
    "uses",
    "units",
    "missing",
    "records-blocked",
];

/// `input.tree.records`: one store per `[[recorder]]`/`[[record]]` row's
/// `record` name (`rules::recorder_records`).
const RECORDS: &str = "records";

/// `input.tree.base-delta`: ONE delta over every row's `delta_sources`, against
/// the one `base` those rows share (`rules::git_facts_within`), so another
/// row's pair decides this module's value too.
const BASE_DELTA: &str = "base-delta";

/// `input.tree.traversals`: walked from `[[traversal]]`, `[[register]]` and the
/// whole pattern table (`rules::walk_traversals`).
const TRAVERSALS: &str = "traversals";

/// `input.tree.shell`: the detector over `[census.shell]`'s homes.
const SHELL: &str = "shell";

impl TreeReads {
    /// `paths` as tree keys, or `None` when one is not a named `input.tree`
    /// key: `input.call`, `input.facts`, a bare `input`, `input.tree[k]`.
    fn of(paths: &BTreeSet<String>) -> Option<Self> {
        let mut keys = BTreeSet::new();
        let mut records = Some(BTreeSet::new());
        for path in paths {
            let rest = path.strip_prefix("tree.")?;
            let (key, sub) = match rest.split_once('.') {
                Some((key, sub)) => (key, Some(sub)),
                None => (rest, None),
            };
            if key.is_empty() {
                return None;
            }
            if key == RECORDS {
                match (sub, records.as_mut()) {
                    (Some(sub), Some(names)) if !sub.is_empty() => {
                        names.insert(sub.to_owned());
                    }
                    _ => records = None,
                }
            }
            keys.insert(key.to_owned());
        }
        Some(Self { keys, records })
    }

    /// Whether a key outside [`SELF_DECLARED`] and the table-built few is read:
    /// one built from every row's declarations (the git family, `forge`,
    /// `state`, `minted` …), or one this reader does not classify.
    fn reads_every_row(&self) -> bool {
        self.keys.iter().any(|key| {
            !SELF_DECLARED.contains(&key.as_str())
                && ![RECORDS, BASE_DELTA, TRAVERSALS, SHELL].contains(&key.as_str())
        })
    }

    /// Whether every file the module's input opens is one its row declares:
    /// `traversals` and `shell` walk files no row names, and a key built from
    /// every row may.
    fn opens_only_declared_files(&self) -> bool {
        !self.reads_every_row() && !self.keys.contains(TRAVERSALS) && !self.keys.contains(SHELL)
    }

    /// Whether a `[[recorder]]`/`[[record]]` row's store is one this reads.
    fn reads_record(&self, row: &toml::Value) -> bool {
        let Some(names) = self.records.as_ref() else {
            return true;
        };
        row.get("record")
            .and_then(toml::Value::as_str)
            .is_none_or(|record| {
                names
                    .iter()
                    .any(|sub| sub == record || sub.starts_with(&format!("{record}.")))
            })
    }
}

/// [`project_reading`] with only the pattern half of a module's reads known:
/// its input is could-not-look, so no table is narrowed past the rows.
fn project(
    contents: &[u8],
    rule: &str,
    verdict: &str,
    reads: &dyn Fn(&str) -> Result<Option<BTreeSet<String>>>,
) -> Result<(Vec<u8>, Option<String>)> {
    let answer = |module: &str| -> Result<Reads> {
        Ok(Reads {
            patterns: reads(module)?,
            input: None,
        })
    };
    project_reading(contents, rule, verdict, &answer)
}

/// `batten.toml` reduced to what decides `rule`/`verdict`, and the rule's
/// module path if it declares one. See [`for_rule`]. `reads` answers what the
/// module reads.
fn project_reading(
    contents: &[u8],
    rule: &str,
    verdict: &str,
    reads: &dyn Fn(&str) -> Result<Reads>,
) -> Result<(Vec<u8>, Option<String>)> {
    let text = std::str::from_utf8(contents)
        .map_err(|err| UsageError::raise(format!("batten.toml is not UTF-8: {err}")))?;
    let mut value: toml::Table = toml::from_str(text)
        .map_err(|err| UsageError::raise(format!("batten.toml will not parse: {err}")))?;
    let id_is = |row: &toml::Value, ids: &[&str]| {
        row.get("id")
            .and_then(toml::Value::as_str)
            .is_some_and(|id| ids.contains(&id))
    };
    let mut module = None;
    if let Some(toml::Value::Array(rows)) = value.get("rule") {
        let own: Vec<&toml::Value> = rows.iter().filter(|row| id_is(row, &[rule])).collect();
        // A `bundle` names a DIRECTORY of modules, which this projection does
        // not enumerate: the whole config stays in, as before CLOUD-2779,
        // rather than a narrower surface that could miss what decides it.
        if own.iter().any(|row| row.get("bundle").is_some()) {
            return Ok((contents.to_vec(), None));
        }
        module = own
            .iter()
            .find_map(|row| row.get("module").and_then(toml::Value::as_str))
            .map(str::to_owned);
    }
    let reads = module.as_deref().map(reads).transpose()?;
    let tree = reads
        .as_ref()
        .and_then(|reads| reads.input.as_ref())
        .and_then(TreeReads::of);
    if let Some(toml::Value::Array(rows)) = value.get_mut("rule") {
        match tree.as_ref() {
            // EVERY ROW DECLARES INTO IT: kept whole.
            Some(tree) if tree.reads_every_row() => {}
            // Every row's `base` and `delta_sources` decide the one delta.
            Some(tree) if tree.keys.contains(BASE_DELTA) => {
                rows.retain_mut(|row| {
                    if id_is(row, &[rule]) {
                        return true;
                    }
                    let declares = row
                        .get("delta_sources")
                        .and_then(toml::Value::as_array)
                        .is_some_and(|sources| !sources.is_empty());
                    if let Some(fields) = row.as_table_mut() {
                        fields.retain(|name, _| ["id", "base", "delta_sources"].contains(&name));
                    }
                    declares
                });
            }
            _ => rows.retain(|row| id_is(row, &[rule])),
        }
    }
    if let Some(toml::Value::Array(rows)) = value.get_mut("verdict") {
        rows.retain(|row| id_is(row, &[rule, verdict]));
    }
    // A RULE WITH NO MODULE READS NEITHER TABLE. `[[pattern]]` rows are read by
    // id from a module, and `[[step]]` rows are the step cache's and the lap
    // graph's, which a module may read as a tree document (`ci-parity.rego`
    // does) and nothing else decides a verdict from. Kept whole, a step row's
    // `ci` mapping unbound every held admission of a `command` rule, and the
    // `filed-row-settled` handler then refused every Edit after it (#1276).
    match reads {
        None => {
            value.remove("pattern");
            value.remove("step");
        }
        // ONLY THE ROWS THE MODULE READS (CLOUD-2779). A module rule compiles
        // from its one file (`policy::load`), so a pattern its code never names
        // cannot decide it: narrowing `admit-asked`, read by `admit-ask.rego`
        // alone, unbound `filed-here.rego`'s held admissions while every row
        // stayed in. A traversal reads the whole table through its registers.
        Some(reads) => {
            let traverses = tree
                .as_ref()
                .is_some_and(|tree| tree.keys.contains(TRAVERSALS));
            if !traverses
                && let Some(ids) = reads.patterns
                && let Some(toml::Value::Array(rows)) = value.get_mut("pattern")
            {
                rows.retain(|row| {
                    row.get("id")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|id| ids.contains(id))
                });
            }
            if let Some(tree) = tree.as_ref() {
                allow(&mut value, tree);
            }
        }
    }
    let projected = serde_json::to_vec(&value)
        .map_err(|err| UsageError::raise(format!("batten.toml will not project: {err}")))?;
    Ok((projected, module))
}

/// Keep, of `value`'s tables, only those that build what `tree` reads.
///
/// THE ALLOWLIST (CLOUD-2789). A module's evaluation is handed
/// `data.batten.patterns` and its `input`, and on the tree surface every
/// `input.tree` key is built from the rows `rules::run` reads: `[[rule]]`
/// (narrowed by the caller), `[[pattern]]`, `[[recorder]]`/`[[record]]` for
/// `records`, `[[traversal]]`/`[[register]]` for `traversals`, and `[census]`
/// for `shell`. `[[verdict]]` is the registry a raised verdict resolves
/// through, and `[[waiver]]`/`[[deferral]]` act on its finding after it is
/// raised, so all three stay. A top-level value that is not a table is a
/// whole-config knob (`strictness`, `scope`, …) and stays. Every other table —
/// `[[verb]]`, `[[mint]]`, `[[startup]]`, `[forge]`, `[hook]`, `[board]`,
/// `[vocabulary]`, `[[step]]` … — is never handed to the module, so editing it
/// cannot change its verdict and no longer moves its epoch.
fn allow(value: &mut toml::Table, tree: &TreeReads) {
    let rows = |item: &toml::Value| match item {
        toml::Value::Table(_) => true,
        toml::Value::Array(items) => !items.is_empty() && items.iter().all(toml::Value::is_table),
        _ => false,
    };
    value.retain(|name, item| {
        !rows(item)
            || match name {
                "rule" | "verdict" | "pattern" | "waiver" | "deferral" => true,
                "recorder" | "record" => tree.keys.contains(RECORDS),
                "traversal" | "register" => tree.keys.contains(TRAVERSALS),
                "census" => tree.keys.contains(SHELL),
                _ => false,
            }
    });
    for table in ["recorder", "record"] {
        if let Some(toml::Value::Array(rows)) = value.get_mut(table) {
            rows.retain(|row| tree.reads_record(row));
        }
    }
}

/// Every path among `tracked` whose content `row` hands its bundle: the
/// literal-plus-glob selections `rules::policy_rule` resolves per row.
fn content_paths(row: &crate::config_model::Rule, tracked: &[String]) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    paths.extend(crate::rules::declared_documents(row, tracked)?);
    paths.extend(crate::rules::declared_lines(row, tracked)?);
    paths.extend(crate::rules::declared_invocations(row, tracked)?);
    paths.extend(crate::rules::declared_uses(row, tracked)?);
    paths.extend(crate::rules::declared_units(row, tracked)?);
    Ok(paths)
}

/// The `[[pattern]]` ids a module's code reads, or `None` when it may read any.
///
/// Each `data.batten.patterns["<id>"]` with a literal id is a read of that row.
/// A path into another `data.batten` package reads no pattern. Every other use
/// of `data` — a computed id, the table bound whole (`with data.batten.patterns
/// as …`), `data` itself — answers `None`, which keeps every row. Comments and
/// string bodies are not code, so an id quoted there is never a read.
fn pattern_reads(source: &[u8]) -> Option<BTreeSet<String>> {
    const TABLE: &str = "data.batten.patterns[\"";
    let code = rego_code(std::str::from_utf8(source).ok()?);
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut ids = BTreeSet::new();
    for (at, _) in code.match_indices("data") {
        let rest = &code[at..];
        let bounded =
            !code[..at].ends_with(|c: char| word(c) || c == '.') && !rest[4..].starts_with(word);
        if !bounded {
            continue;
        }
        if let Some(subscript) = rest.strip_prefix(TABLE) {
            let (id, _) = subscript.split_once("\"]")?;
            if id.is_empty() {
                return None;
            }
            ids.insert(id.to_owned());
            continue;
        }
        let package: String = rest
            .strip_prefix("data.batten.")?
            .chars()
            .take_while(|c| word(*c))
            .collect();
        if package.is_empty() || package == "patterns" {
            return None;
        }
    }
    Some(ids)
}

/// `source` with every comment and every string body blanked, except the
/// literal subscript of a `data.batten.patterns[...]` read, which
/// [`pattern_reads`] needs verbatim. An escape in that subscript blanks it too,
/// so the read no longer parses as literal and every row is kept.
fn rego_code(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars();
    while let Some(c) = chars.next() {
        match c {
            '#' => {
                out.push(' ');
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '"' => {
                let subscript = out.ends_with("data.batten.patterns[");
                let mut body = String::new();
                let mut escaped = false;
                while let Some(inner) = chars.next() {
                    match inner {
                        '\\' => {
                            escaped = true;
                            chars.next();
                        }
                        '"' => break,
                        other => body.push(other),
                    }
                }
                out.push('"');
                if subscript && !escaped {
                    out.push_str(&body);
                }
                out.push('"');
            }
            '`' => {
                out.push_str("``");
                for inner in chars.by_ref() {
                    if inner == '`' {
                        break;
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// One tracked file's bytes, from the working tree or from the base ref.
///
/// A failure names the path: a refusal the reader cannot act on is barely
/// better than a silent skip.
fn read_tracked(dir: &Path, path: &str, base_ref: Option<&str>) -> Result<Vec<u8>> {
    match base_ref {
        Some(reference) => git::show(dir, reference, path).map(String::into_bytes),
        None => crate::fsio::read(dir.join(path)).map_err(|err| {
            UsageError::raise(format!(
                "cannot read tracked config-surface path {path}: {err}"
            ))
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[cfg(test)]
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::config;

    fn parse(text: &str) -> Config {
        config::parse(text, "test").unwrap()
    }

    /// GIT'S RACY RULE, held (CLOUD-2315): an entry vouches only for files whose
    /// change time is strictly older than the entry's write. A file changed at or
    /// after it may differ with every stamped field equal, so it is a miss.
    #[test]
    fn a_tracked_file_changed_after_the_entry_was_written_is_not_served() {
        let dir = crate::scratch::scratch("epoch-racy");
        let path = dir.join("epoch");
        let stamp = |changed: std::time::Duration| crate::cache::Stamp {
            fields: "stat:fixed".to_owned(),
            changed,
        };
        let tracked = vec!["batten.toml".to_owned()];
        let before = crate::cache::now().saturating_sub(std::time::Duration::from_secs(60));
        let key = cache_key(&tracked, &[stamp(before)]);
        write_cache(&path, &key, "the-epoch");
        assert_eq!(
            read_cache(&path, &key, &[stamp(before)]).as_deref(),
            Some("the-epoch"),
            "a file changed well before the write is vouched for"
        );
        let after = crate::cache::now() + std::time::Duration::from_secs(60);
        assert!(
            read_cache(&path, &key, &[stamp(after)]).is_none(),
            "a file changed at or after the write is racily clean: a miss"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Fails by: a key that ignores the stamps or the paths, so an entry written
    /// for one surface answers for another.
    #[test]
    fn the_cache_key_names_each_path_and_its_stamp() {
        let stamp = |fields: &str| crate::cache::Stamp {
            fields: fields.to_owned(),
            changed: std::time::Duration::ZERO,
        };
        let tracked = vec!["batten.toml".to_owned()];
        let key = cache_key(&tracked, &[stamp("stat:a")]);
        assert_ne!(key, cache_key(&tracked, &[stamp("stat:b")]));
        assert_ne!(
            key,
            cache_key(&["other.toml".to_owned()], &[stamp("stat:a")])
        );
    }

    /// Fails by: the cached path answering anything but what an uncached read
    /// of the same surface answers, on the miss that writes and the read after.
    #[test]
    fn the_cached_epoch_is_the_uncached_one() {
        let dir = repo("cached", "version = 1\n");
        crate::testing::contain_state(&dir.join("state"));
        let uncached = describe(&dir, None).unwrap();
        assert_eq!(describe_cached(&dir, None).unwrap(), uncached);
        assert_eq!(describe_cached(&dir, None).unwrap(), uncached);
    }

    /// Fails by: no entry written where the state directory files one, or an
    /// entry that answers for a surface whose file has since changed.
    #[test]
    fn the_cache_is_written_and_never_outlives_its_surface() {
        let dir = repo("cache-written", "version = 1\n");
        crate::testing::contain_state(&dir.join("state"));
        describe_cached(&dir, None).unwrap();
        let entry = cache_path(&state_dir(&dir).unwrap()).unwrap();
        assert!(entry.is_file(), "{}", entry.display());
        // Whichever case contained the process first, the entry lies under it.
        let contained = crate::testing::contained_data_dir().unwrap();
        assert!(entry.starts_with(contained), "{}", entry.display());
        fs::write(
            dir.join("batten.toml"),
            "version = 1\nstrictness = \"strict\"\n",
        )
        .unwrap();
        assert_eq!(
            describe_cached(&dir, None).unwrap(),
            describe(&dir, None).unwrap()
        );
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

/// An admission's epoch moves with what its rule reads and nothing else
/// (CLOUD-2789).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod rule_surface_tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::for_rule;

    const RULE: &str = "issue file other";
    const VERDICT: &str = "issue file held";

    /// A module reading two named tree keys: a record and the base delta.
    const MODULE: &str = "package batten.held\n\nimport rego.v1\n\n\
        rules contains \"issue file held\"\n\n\
        violation contains {\"rule\": \"issue file other\", \"verdict\": \"issue file held\", \
        \"subjects\": []} if {\n\
        \tsome line in input.tree.records[\"board-writes\"]\n\
        \tcount(input.tree[\"base-delta\"]) > 0\n\
        \tline != \"\"\n}\n";

    /// `batten.toml` with `extra` spliced into the rule row and `verb` as the
    /// one `[[verb]]` row's redirect.
    fn config(extra: &str, verb: &str) -> String {
        format!(
            "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"AGENTS.md\"]\n\n\
             [[rule]]\nid = \"{RULE}\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/held.rego\"\nseverity = \"deny\"\n{extra}\n\
             [[rule]]\nid = \"other\"\nkind = \"policy\"\nscope = \"tree\"\n\
             module = \"policy/other.rego\"\nseverity = \"deny\"\n\n\
             [[verb]]\nverb = \"rm\"\neffect = \"destructive\"\nredirect = \"{verb}\"\n"
        )
    }

    /// A scratch repository with `config`, the module and an `AGENTS.md`.
    fn repo(name: &str, config: &str) -> PathBuf {
        let dir = crate::scratch::scratch(name);
        fs::create_dir_all(dir.join("policy")).unwrap();
        fs::write(dir.join("batten.toml"), config).unwrap();
        fs::write(dir.join("policy/held.rego"), MODULE).unwrap();
        fs::write(
            dir.join("policy/other.rego"),
            "package batten.other\n\nimport rego.v1\n\nrules contains \"x\"\n",
        )
        .unwrap();
        fs::write(dir.join("AGENTS.md"), "# guide\n").unwrap();
        dir
    }

    fn epoch(dir: &Path) -> String {
        for_rule(dir, None, RULE, VERDICT).unwrap()
    }

    /// Fails by: a table the module is never handed, or a tracked file its row
    /// hands it no content of, still hashed into its epoch — every unrelated
    /// config edit voiding the held admission (#1276).
    #[test]
    fn an_unrelated_verb_row_or_tracked_file_leaves_the_epoch() {
        let dir = repo("epoch-rule-unrelated", &config("", "restore it"));
        let before = epoch(&dir);
        fs::write(dir.join("batten.toml"), config("", "copy it instead")).unwrap();
        assert_eq!(epoch(&dir), before, "the module reads no `[[verb]]` row");
        fs::write(dir.join("AGENTS.md"), "# guide, edited\n").unwrap();
        assert_eq!(
            epoch(&dir),
            before,
            "the row hands it no `AGENTS.md` content"
        );
    }

    /// Fails by: a `[[recorder]]` row whose store the module never reads kept
    /// in its epoch, or one whose store it does read dropped from it.
    #[test]
    fn only_a_recorder_row_for_a_store_it_reads_moves_the_epoch() {
        let recorder = |name: &str, record: &str| {
            format!(
                "\n[[recorder]]\nname = \"{name}\"\nrecord = \"{record}\"\ntool = \"save_issue\"\n\
                 key = \"branch\"\nrequires = [\"id\"]\n\n[[recorder.columns]]\nname = \"id\"\n\
                 value = {{ result = \"id\" }}\n"
            )
        };
        let with = |unread: &str, read: &str| {
            format!(
                "{}{}{}",
                config("", "restore it"),
                recorder(unread, "other-writes"),
                recorder(read, "board-writes")
            )
        };
        let dir = repo("epoch-rule-recorder", &with("unread", "read"));
        let before = epoch(&dir);
        fs::write(dir.join("batten.toml"), with("unread-renamed", "read")).unwrap();
        assert_eq!(epoch(&dir), before, "the module reads no `other-writes`");
        fs::write(
            dir.join("batten.toml"),
            with("unread-renamed", "read-renamed"),
        )
        .unwrap();
        assert_ne!(epoch(&dir), before, "the module reads `board-writes`");
    }

    /// A rule WITH a module is served from its cache entry while the module is
    /// unchanged: the stored digest is of the module the entry names, and the
    /// hit re-reads that module, not nothing.
    ///
    /// Fails by: the hit digesting no module (`!module.is_empty()` inverted at
    /// `for_rule_cached`), so a module-bearing rule never hits and recomputes
    /// its epoch on every refusal (CLOUD-2789, shard 0/8's survivor).
    #[test]
    fn a_module_rules_cached_epoch_is_served_while_its_module_holds() {
        let dir = repo("epoch-rule-cached", &config("", "restore it"));
        let cold = super::for_rule_cached(&dir, None, RULE, VERDICT).unwrap();
        assert_eq!(cold, epoch(&dir), "the cache answers what `for_rule` does");
        let root = super::state_dir(&dir)
            .as_deref()
            .and_then(crate::cache::root_under)
            .unwrap()
            .join("epoch-rule");
        let entries: Vec<PathBuf> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1, "one entry for one rule");
        let stored = fs::read_to_string(&entries[0]).unwrap();
        let (value, rest) = stored.split_once('\n').unwrap();
        assert_eq!(value, cold);
        assert!(
            rest.starts_with("policy/held.rego\n"),
            "it names its module"
        );
        fs::write(&entries[0], format!("served-from-cache\n{rest}")).unwrap();
        assert_eq!(
            super::for_rule_cached(&dir, None, RULE, VERDICT).unwrap(),
            "served-from-cache",
            "an unchanged module is a hit"
        );
        fs::write(
            dir.join("policy/held.rego"),
            format!("{MODULE}\n# edited\n"),
        )
        .unwrap();
        assert_ne!(
            super::for_rule_cached(&dir, None, RULE, VERDICT).unwrap(),
            "served-from-cache",
            "an edited module is a miss"
        );
    }

    /// Fails by: the narrowing reaching past the unrelated, so the rule's own
    /// row or its module changing leaves an admission bound.
    #[test]
    fn its_own_row_or_module_moves_the_epoch() {
        let dir = repo("epoch-rule-own", &config("", "restore it"));
        let before = epoch(&dir);
        fs::write(
            dir.join("batten.toml"),
            config(
                "base = \"origin/main\"\ndelta_sources = [\"**\"]\n",
                "restore it",
            ),
        )
        .unwrap();
        let moved = epoch(&dir);
        assert_ne!(moved, before, "its own row moved");
        fs::write(
            dir.join("policy/held.rego"),
            format!("{MODULE}\n# edited\n"),
        )
        .unwrap();
        assert_ne!(epoch(&dir), moved, "its module moved");
    }

    /// A row with no module reads no file content, so `batten.toml` is still
    /// projected for it even where its `documents` name the config: another
    /// rule's row is no input to it.
    ///
    /// Fails by: a moduleless row's declared paths read as file content (the
    /// `reads.is_some()` guard on `read_files` taken as `true`), which hashes
    /// the whole config and voids its admissions on any edit (CLOUD-2789).
    #[test]
    fn a_moduleless_row_naming_the_config_keeps_its_projection() {
        let moduleless = |severity: &str| {
            format!(
                "version = 1\n\n[epoch]\ntracked = [\"batten.toml\", \"AGENTS.md\"]\n\n\
                 [[rule]]\nid = \"{RULE}\"\nkind = \"command\"\nscope = \"tree\"\n\
                 glob = \"**\"\ncheck = \"true\"\nseverity = \"deny\"\n\
                 documents = [\"batten.toml\"]\n\n\
                 [[rule]]\nid = \"other\"\nkind = \"policy\"\nscope = \"tree\"\n\
                 module = \"policy/other.rego\"\nseverity = \"{severity}\"\n"
            )
        };
        let dir = repo("epoch-rule-moduleless", &moduleless("deny"));
        let before = epoch(&dir);
        fs::write(dir.join("batten.toml"), moduleless("warn")).unwrap();
        assert_eq!(epoch(&dir), before, "another rule's row is not its input");
    }

    /// Fails by: a read the projection cannot name (`input.facts`) narrowed as
    /// if it were known, or a tracked file the row DOES hand as a document
    /// dropped.
    #[test]
    fn an_unnamed_read_or_a_declared_document_still_moves_the_epoch() {
        let dir = repo("epoch-rule-opaque", &config("", "restore it"));
        fs::write(
            dir.join("policy/held.rego"),
            MODULE.replace("count(input.tree[\"base-delta\"]) > 0", "input.facts.x"),
        )
        .unwrap();
        let before = epoch(&dir);
        fs::write(dir.join("batten.toml"), config("", "copy it instead")).unwrap();
        assert_ne!(epoch(&dir), before, "an unnamed read keeps every table");

        let documents = "documents = [\"AGENTS.md\"]\n";
        let dir = repo("epoch-rule-document", &config(documents, "restore it"));
        let before = epoch(&dir);
        fs::write(dir.join("AGENTS.md"), "# guide, edited\n").unwrap();
        assert_ne!(epoch(&dir), before, "a declared document is an input");
    }

    /// This repository's own `issue file held` module reads only keys the
    /// allowlist names, so the cases above are the shape it takes (#1276).
    ///
    /// Fails by: a read in it the classifier cannot name, which would quietly
    /// put its admissions back on the whole config.
    #[test]
    fn the_filed_here_module_is_narrowed() {
        let path = "policy/filed-here.rego";
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(path),
        )
        .unwrap();
        let paths = crate::policy::module_input_paths(path, &source).unwrap();
        let tree = super::TreeReads::of(&paths).unwrap();
        assert!(!tree.reads_every_row(), "{:?}", tree.keys);
        assert!(tree.opens_only_declared_files(), "{:?}", tree.keys);
    }

    fn reads(paths: &[&str]) -> super::TreeReads {
        super::TreeReads::of(&paths.iter().map(|path| (*path).to_owned()).collect()).unwrap()
    }

    /// Fails by: a named records read widened to the whole family, or an
    /// empty subpath kept as a name.
    #[test]
    fn a_named_records_read_narrows_to_its_names() {
        assert_eq!(
            reads(&["tree.records.lease"]).records,
            Some(std::iter::once("lease".to_owned()).collect())
        );
        assert_eq!(reads(&["tree.records."]).records, None);
        assert_eq!(reads(&["tree.records"]).records, None);
    }

    /// Fails by: a module reading a key built from every row's declarations
    /// read as opening only its own row's files, so its admission narrows to
    /// one row while another row's edit moves its value (CLOUD-2789).
    #[test]
    fn a_whole_config_key_opens_more_than_its_row_declares() {
        assert!(reads(&["tree.documents"]).opens_only_declared_files());
        assert!(!reads(&["tree.git"]).opens_only_declared_files());
        assert!(!reads(&["tree.traversals"]).opens_only_declared_files());
        assert!(!reads(&["tree.shell"]).opens_only_declared_files());
    }

    /// Fails by: a store read by its exact name, or through a field beneath
    /// it, judged unread — or another store judged read.
    #[test]
    fn a_record_row_is_read_by_its_name_or_a_field_beneath_it() {
        let row = |record: &str| {
            let mut table = toml::Table::new();
            table.insert("record".to_owned(), toml::Value::from(record));
            toml::Value::Table(table)
        };
        let exact = reads(&["tree.records.lease"]);
        assert!(exact.reads_record(&row("lease")));
        assert!(!exact.reads_record(&row("other")));
        let field = reads(&["tree.records.lease.holder"]);
        assert!(field.reads_record(&row("lease")));
        assert!(!field.reads_record(&row("lea")));
    }

    /// Fails by: a key no row declares for itself (`forge`, built from every
    /// row) read as self-declared, which narrows a module that reads it to its
    /// own row (CLOUD-2789).
    #[test]
    fn a_key_built_from_every_row_reads_every_row() {
        assert!(reads(&["tree.forge"]).reads_every_row());
        assert!(!reads(&["tree.documents", "tree.records.lease"]).reads_every_row());
    }

    /// Fails by: either walk alone (`traversals` or `shell`) taken for a read
    /// of declared files, which narrows its input past the files it opens.
    #[test]
    fn a_walk_opens_files_no_row_declares() {
        assert!(reads(&["tree.documents"]).opens_only_declared_files());
        assert!(!reads(&["tree.traversals"]).opens_only_declared_files());
        assert!(!reads(&["tree.shell"]).opens_only_declared_files());
        assert!(!reads(&["tree.forge"]).opens_only_declared_files());
    }
}

/// The module half of a rule's digest (#1276).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod module_digest_tests {
    use super::module_digest;

    /// Fails by: two modules, or a module and none, digesting alike.
    #[test]
    fn a_modules_digest_is_its_bytes() {
        let dir = crate::scratch::scratch("epoch-module-digest");
        std::fs::write(dir.join("a.rego"), "package a").unwrap();
        std::fs::write(dir.join("b.rego"), "package b").unwrap();
        let a = module_digest(&dir, Some("a.rego"));
        assert_eq!(a, module_digest(&dir, Some("a.rego")));
        assert_ne!(a, module_digest(&dir, Some("b.rego")));
        assert_ne!(a, module_digest(&dir, None));
        assert_eq!(a.len(), 64, "a hex digest");
    }

    /// A step row's edit leaves a module-less rule's epoch alone, and still
    /// moves a module rule's, which may read the step table as a document.
    ///
    /// Fails by: `[[step]]` kept in a command rule's projection (every edit to
    /// the lap graph unbinding its admissions), or dropped from a module rule's
    /// (an admission outliving a change its module reads).
    #[test]
    fn a_step_row_moves_only_a_module_rules_epoch() {
        let rows = |run: &str| {
            format!(
                "version = 1\n\n[[rule]]\nid = \"plain\"\nkind = \"command\"\n\n\
                 [[rule]]\nid = \"moduled\"\nkind = \"policy\"\nmodule = \"m.rego\"\n\n\
                 [[step]]\nid = \"s\"\nrun = [\"{run}\"]\ngroup = \"g\"\n"
            )
        };
        let (before, _) =
            super::project(rows("a").as_bytes(), "plain", "plain", &|_| Ok(None)).unwrap();
        let (after, _) =
            super::project(rows("b").as_bytes(), "plain", "plain", &|_| Ok(None)).unwrap();
        assert_eq!(before, after, "a command rule does not read the step table");
        let (before, module) =
            super::project(rows("a").as_bytes(), "moduled", "moduled", &|_| Ok(None)).unwrap();
        let (after, _) =
            super::project(rows("b").as_bytes(), "moduled", "moduled", &|_| Ok(None)).unwrap();
        assert_eq!(module.as_deref(), Some("m.rego"));
        assert_ne!(before, after, "a module may read the step table");
    }

    /// A module reading `input.tree.base-delta` keeps every row that declares a
    /// delta (narrowed to its `base` and sources) and drops one that does not;
    /// one reading `input.tree.records.<name>` keeps that store's rows only.
    ///
    /// Fails by: the delta filter inverted, a named record subpath read as
    /// every store, a row's store matched by anything but its name, or the
    /// record tables dropped for a module that reads them.
    #[test]
    fn a_tree_read_keeps_exactly_the_rows_that_build_it() {
        let config = r#"version = 1
[[rule]]
id = "own"
kind = "policy"
module = "m.rego"
[[rule]]
id = "with"
kind = "command"
base = "origin/main"
delta_sources = ["src/**"]
[[rule]]
id = "without"
kind = "command"
[[record]]
id = "r1"
record = "issue"
[[record]]
id = "r2"
record = "other"
"#;
        let ids = |input: &[&str], table: &str| -> Vec<String> {
            let answer = |_: &str| -> super::Result<super::Reads> {
                Ok(super::Reads {
                    patterns: Some(std::collections::BTreeSet::new()),
                    input: Some(input.iter().map(|path| (*path).to_owned()).collect()),
                })
            };
            let (projected, _) =
                super::project_reading(config.as_bytes(), "own", "own", &answer).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&projected).unwrap();
            value[table]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .filter_map(|row| row["id"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(ids(&["tree.base-delta"], "rule"), ["own", "with"]);
        assert_eq!(ids(&["tree.records.issue"], "record"), ["r1"]);
        assert_eq!(ids(&["tree.records.issue.state"], "record"), ["r1"]);
        assert_eq!(ids(&["tree.records"], "record"), ["r1", "r2"]);

        let paths = ["tree.records.issue".to_owned()].into_iter().collect();
        let tree = super::TreeReads::of(&paths).unwrap();
        assert_eq!(
            tree.records,
            Some(["issue".to_owned()].into_iter().collect())
        );
    }

    /// Fails by: an id in a comment or a string read as a read, a computed id
    /// or the table bound whole read as reading nothing, or a path into another
    /// package read as reading every row.
    #[test]
    fn a_modules_pattern_reads_are_its_literal_subscripts() {
        let reads = |text: &str| super::pattern_reads(text.as_bytes());
        let ids = |list: &[&str]| Some(list.iter().map(|id| (*id).to_owned()).collect());
        assert_eq!(
            reads(
                "x if regex.match(data.batten.patterns[\"a\"], y)\n# data.batten.patterns[\"c\"]\n"
            ),
            ids(&["a"])
        );
        assert_eq!(
            reads("x := \"data.batten.patterns[\\\"c\\\"]\"\n"),
            ids(&[])
        );
        assert_eq!(reads("x := data.batten.other.rule\n"), ids(&[]));
        assert_eq!(reads("x := data.batten.patterns[id]\n"), None);
        assert_eq!(reads("t if { v with data.batten.patterns as p }\n"), None);
        assert_eq!(reads("x := data[\"batten\"]\n"), None);
        assert_eq!(reads("x := data.batten.patterns[\"a\\\"b\"]\n"), None);
        assert_eq!(reads("metadata := 1\n"), ids(&[]));
    }

    /// A config with the own rule, another rule declaring a delta, two
    /// recorders and a census table: one of each table [`super::allow`] sorts.
    const PROJECTED: &str = "[[rule]]\nid = \"own\"\nmodule = \"m.rego\"\n\n\
        [[rule]]\nid = \"other\"\nbase = \"main\"\ndelta_sources = [\"x\"]\n\n\
        [[recorder]]\nrecord = \"a\"\n\n[[recorder]]\nrecord = \"b\"\n\n\
        [census.shell]\nexempt = []\n";

    /// The projection of [`PROJECTED`] for a module whose input reads `input`.
    fn projected(input: &[&str]) -> serde_json::Value {
        let answer = |_: &str| -> anyhow::Result<super::Reads> {
            Ok(super::Reads {
                patterns: None,
                input: Some(input.iter().map(|path| (*path).to_owned()).collect()),
            })
        };
        let (bytes, _) =
            super::project_reading(PROJECTED.as_bytes(), "own", "held", &answer).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Fails by: a module reading a key built from every row (`forge`)
    /// narrowed to its own row, which drops the rows that build what it reads
    /// (CLOUD-2789).
    #[test]
    fn a_module_reading_every_row_keeps_every_row_whole() {
        let forge = projected(&["tree.forge"]);
        let rows = forge["rule"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "{forge}");
        assert_eq!(rows[1]["id"], "other", "{forge}");
        assert_eq!(rows[1]["delta_sources"][0], "x", "kept whole: {forge}");
    }

    /// Fails by: another row's delta pair kept for a module that reads no
    /// `base-delta`, a recorder kept whose store the module never reads, or
    /// `[census]` dropped for a module reading `shell`.
    #[test]
    fn a_projection_keeps_only_the_tables_its_tree_reads_build() {
        let documents = projected(&["tree.documents"]);
        assert_eq!(
            documents["rule"].as_array().map(Vec::len),
            Some(1),
            "{documents}"
        );
        assert!(documents.get("census").is_none(), "{documents}");
        let delta = projected(&["tree.base-delta"]);
        assert_eq!(delta["rule"].as_array().map(Vec::len), Some(2), "{delta}");
        let records = projected(&["tree.records.a"]);
        assert_eq!(
            records["recorder"],
            serde_json::json!([{"record": "a"}]),
            "{records}"
        );
        let shell = projected(&["tree.shell"]);
        assert!(shell.get("census").is_some(), "{shell}");
    }

    /// Fails by: a raw string's body left in the code after its first byte,
    /// so an id quoted in backticks would read as a subscript.
    #[test]
    fn a_raw_string_body_is_blanked_whole() {
        assert_eq!(super::rego_code("x := `ab` y"), "x := `` y");
    }

    /// The tree reads of a module reading exactly `paths`.
    fn tree(paths: &[&str]) -> super::TreeReads {
        let paths = paths.iter().map(|path| (*path).to_owned()).collect();
        super::TreeReads::of(&paths).unwrap()
    }

    /// Fails by: a named `records` subpath read as the family whole, or a
    /// recorder row whose store is exactly a read name dropped as unread.
    #[test]
    fn a_named_record_read_keeps_exactly_its_store() {
        let reads = tree(&["tree.records.ledger"]);
        assert_eq!(
            reads.records,
            Some(std::iter::once("ledger".to_owned()).collect())
        );
        let row = |record: &str| {
            let mut table = toml::Table::new();
            table.insert("record".to_owned(), toml::Value::String(record.to_owned()));
            toml::Value::Table(table)
        };
        assert!(reads.reads_record(&row("ledger")));
        assert!(!reads.reads_record(&row("other")));
    }

    /// Fails by: a single-table section (`[forge]`) kept for a module that
    /// reads nothing it builds, or `[[traversal]]` dropped from one that reads
    /// `traversals`.
    #[test]
    fn the_allowlist_keeps_only_tables_the_module_reads() {
        let mut value: toml::Table = toml::from_str(
            "strictness = \"standard\"\n[forge]\nkind = \"x\"\n\
             [[traversal]]\nid = \"t\"\n[[register]]\nid = \"r\"\n",
        )
        .unwrap();
        let mut unread = value.clone();
        super::allow(&mut unread, &tree(&["tree.documents"]));
        assert_eq!(
            unread
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["strictness"])
        );
        super::allow(&mut value, &tree(&["tree.traversals"]));
        assert_eq!(
            value
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["register", "strictness", "traversal"])
        );
    }
}

/// The projection's two text helpers, each against the one input that tells
/// its mutant apart (#1276).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod projection_tests {
    use super::{TreeReads, allow, rego_code};
    use std::collections::BTreeSet;

    /// Fails by: a lone table (`[hook]`) read as a scalar knob, which keeps a
    /// table the module is never handed in its epoch.
    #[test]
    fn a_lone_table_the_module_never_reads_is_dropped() {
        let mut value: toml::Table =
            toml::from_str("strictness = \"strict\"\n[hook]\nx = 1\n").unwrap();
        let tree = TreeReads::of(&BTreeSet::new()).unwrap();
        allow(&mut value, &tree);
        assert_eq!(
            value.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["strictness"]
        );
    }

    /// Fails by: an empty array or an array of scalars read as rows, which
    /// drops a knob the module is handed (`allow`'s `&&`, CLOUD-2789).
    #[test]
    fn an_array_of_scalars_or_none_is_a_knob_not_rows() {
        let mut value: toml::Table =
            toml::from_str("empty = []\nscalars = [1, 2]\n[[hook]]\nx = 1\n").unwrap();
        allow(&mut value, &TreeReads::of(&BTreeSet::new()).unwrap());
        assert_eq!(
            value.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["empty", "scalars"]
        );
    }

    /// Fails by: a raw string closing on its first character, which leaves
    /// the rest of its body in the code text.
    #[test]
    fn a_raw_string_body_is_blanked_to_its_closing_backtick() {
        assert_eq!(rego_code("`ab` x"), "`` x");
    }
}
