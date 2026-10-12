//! The disk collector (CLOUD-2197): unreachable, then least-recently-used, cargo
//! units, whenever free space falls below `[prune] min_free_mb`, until
//! `max_free_mb` is free.
//!
//! **The shape is Nix's automatic GC during builds; the eviction is
//! cargo-sweep's.** A unit is a fingerprint hash; its last use is the newest
//! atime of its `.fingerprint/<unit>/` files; units go oldest first across every
//! `.fingerprint` directory under every tree, the checkout's `target/` and each
//! linked worktree's. cargo-sweep's algorithm rather than its binary, because it
//! has no idea a build might be holding a tree: here a profile whose
//! `.cargo-lock` is held is never touched ([`crate::prune::claim`]).
//!
//! **Superseded first.** The existing retention pass removes what no build can
//! reach any more before a live unit is ranked at all.
//!
//! **Freed bytes count an inode once.** cargo uplifts by hardlink, so unlinking
//! one name of a two-name file frees nothing; a removal counts a file's
//! allocated blocks only when its last name goes. Otherwise the stop would halt
//! short of `max_free_mb` on bytes that are still on disk.
//!
//! **`relatime` is re-armed** after every pass: each surviving fingerprint file's
//! atime is set to its mtime, so the next read by cargo records a fresh one.
//! Without it a unit read all morning keeps the atime of its first read for a
//! day and can rank older than a tree touched once an hour ago.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

/// What one collection did, pointer-only: numbers, never paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collected {
    /// Bytes the collection freed, each inode counted once.
    pub freed_bytes: u64,
    /// Units removed, superseded and live together.
    pub units: usize,
    /// Free space after the collection, in MiB.
    pub free_after_mb: u64,
    /// Wall time the unlinks took, in milliseconds.
    pub wall_ms: u64,
}

impl Collected {
    /// The lap-record lines: `disk-collected <freed_mb> <units> <free_after_mb>`
    /// and the unlink cost (CLOUD-1945's figure).
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!(
                "disk-collected {} {} {}",
                self.freed_bytes / (1024 * 1024),
                self.units,
                self.free_after_mb
            ),
            format!("disk-unlink-ms {}", self.wall_ms),
        ]
    }
}

/// A file that must never be collected: the installed engine, the running
/// executable, and every name hardlinked to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kept {
    dev: u64,
    ino: u64,
}

/// The files no collection removes: the running executable, the `batten` on
/// `PATH`, and every program running on this host, canonicalised (CLOUD-2197 §5).
///
/// EVERY RUNNING PROGRAM, not only this one. A test runner holds no
/// `.cargo-lock` while it executes the binary it built, so its tree reads as
/// idle: measured on #1132, a hook collecting toward `max_free_mb` during a
/// nextest run removed every `it-*` test binary, and the run failed to exec
/// thousands of cases. A unit carrying an executable a process is running is
/// in use, whatever the lock says.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT running-program-collected|s@^        .chain(running_programs())$@        .chain(Vec::<PathBuf>::new())@|a_unit_a_running_program_executes_is_never_collected
#[must_use]
pub fn engine_paths() -> Vec<PathBuf> {
    let running = std::env::current_exe().ok();
    let installed = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(crate::surface::BINARY))
            .find(|candidate| candidate.is_file())
    });
    running
        .into_iter()
        .chain(installed)
        .chain(running_programs())
        .filter(|path| path.exists())
        .map(|path| crate::git::canonical(&path))
        .collect()
}

/// The executable of every process this user can see (`/proc/<pid>/exe`).
/// Empty where `/proc` is not there: the other kept paths still hold.
fn running_programs() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|entry| std::fs::read_link(entry.path().join("exe")).ok())
        .collect()
}

/// The [`Kept`] identities of `paths` that exist.
#[must_use]
pub fn kept(paths: &[PathBuf]) -> Vec<Kept> {
    paths.iter().filter_map(|path| identity(path)).collect()
}

#[cfg(unix)]
fn identity(path: &Path) -> Option<Kept> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).ok()?;
    Some(Kept {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(not(unix))]
fn identity(_path: &Path) -> Option<Kept> {
    None
}

/// One cargo unit: its fingerprint directory, the artifacts that carry its hash,
/// and when it was last used.
#[derive(Debug)]
struct Unit {
    tree: PathBuf,
    profile: PathBuf,
    fingerprint: PathBuf,
    artifacts: Vec<PathBuf>,
    last_use: SystemTime,
}

/// Every unit under `tree`, at any depth: every `.fingerprint` directory, nested
/// target triples and build trees included.
fn units_in(tree: &Path) -> Vec<Unit> {
    let mut units = Vec::new();
    for fingerprints in crate::prune::directories_named(tree, ".fingerprint") {
        let Some(profile) = fingerprints.parent().map(Path::to_path_buf) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&fingerprints) else {
            continue;
        };
        // ONE LISTING PER PROFILE, NOT PER UNIT. Measured on #1132: re-reading
        // `deps/` for each unit was thousands of units times ~7,000 entries,
        // which spent the hook's whole deadline before the first removal, so the
        // collector freed nothing at 6MB free while every call waited on it.
        let index = artifact_index(&profile);
        for entry in entries.filter_map(Result::ok) {
            let fingerprint = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some((_, hash)) = name.rsplit_once('-') else {
                continue;
            };
            units.push(Unit {
                tree: tree.to_path_buf(),
                artifacts: artifacts_of(&index, &profile, &name, hash),
                last_use: last_use(&fingerprint),
                profile: profile.clone(),
                fingerprint,
            });
        }
    }
    units
}

/// The newest atime OR mtime among a fingerprint directory's files: the last
/// time cargo read this unit's fingerprint, or rewrote it.
///
/// BOTH, BECAUSE A REBUILD WRITES WITHOUT READING. [`rearm`] pushes a
/// survivor's atime behind its mtime so the next read refreshes it, and cargo
/// rebuilding a unit under the same hash rewrites the fingerprint files, which
/// moves their mtime and leaves that old atime. Read by atime alone, the
/// freshest build ranked least recently used: measured on #1132, a collection
/// right after `cargo test` built removed the test binary nextest was about to
/// run, and 2,087 cases failed to exec it.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT rebuild-ranked-stale|s@^            let meta = entry.metadata().ok()?;$@            let meta = entry.metadata().ok().filter(\|_\| false)?;@|a_unit_just_rebuilt_is_not_least_recently_used
fn last_use(fingerprint: &Path) -> SystemTime {
    std::fs::read_dir(fingerprint)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            let read = meta.accessed().ok()?;
            Some(meta.modified().map_or(read, |written| read.max(written)))
        })
        .max()
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// A profile's files, keyed by each `-`-separated token of their names (up to
/// the first `.`), so a unit's hash is one lookup.
type ArtifactIndex = std::collections::HashMap<String, Vec<PathBuf>>;

/// List a profile's `deps/`, `examples/` and top-level files once.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT artifacts-unindexed|s@^                    index.entry(token.to_owned()).or_default().push(entry.path());$@@|a_collected_unit_takes_its_artifacts
fn artifact_index(profile: &Path) -> ArtifactIndex {
    let mut index = ArtifactIndex::new();
    for dir in [
        profile.join("deps"),
        profile.join("examples"),
        profile.to_path_buf(),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            let file = entry.file_name().to_string_lossy().into_owned();
            let mut seen = std::collections::HashSet::new();
            for token in file.split('-').skip(1) {
                let token = token.split('.').next().unwrap_or(token);
                if seen.insert(token) {
                    index
                        .entry(token.to_owned())
                        .or_default()
                        .push(entry.path());
                }
            }
        }
    }
    index
}

/// A unit's artifacts: the indexed files whose names carry `-<hash>`, and its
/// `build/<name>` directory.
fn artifacts_of(index: &ArtifactIndex, profile: &Path, name: &str, hash: &str) -> Vec<PathBuf> {
    let mut artifacts = index.get(hash).cloned().unwrap_or_default();
    let build = profile.join("build").join(name);
    if build.is_dir() {
        artifacts.push(build);
    }
    artifacts
}

/// Remove `path`, file or tree, counting a file's blocks only when this was its
/// last name. Returns the bytes actually freed.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT shared-inode-counted-freed|s@^    if links == 1 { allocated } else { 0 }$@    allocated@|a_shared_inode_is_not_counted_until_its_last_name_goes
fn remove_counted(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        let mut freed = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                freed += remove_counted(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
        return freed;
    }
    let (links, allocated) = allocation(&meta);
    if std::fs::remove_file(path).is_err() {
        return 0;
    }
    if links == 1 { allocated } else { 0 }
}

#[cfg(unix)]
fn allocation(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.nlink(), meta.blocks() * 512)
}

#[cfg(not(unix))]
fn allocation(meta: &std::fs::Metadata) -> (u64, u64) {
    (1, meta.len())
}

/// Whether `path` is one of the kept files, by device and inode.
fn is_kept(path: &Path, kept: &[Kept]) -> bool {
    identity(path).is_some_and(|id| kept.contains(&id))
}

/// Take the collector's lock on `tree`: an exclusive `flock` on the directory
/// itself, an existing inode, so taking it writes nothing at 0 bytes free.
/// `None` when another collector holds it.
fn lock_tree(tree: &Path, wait: bool) -> Option<std::fs::File> {
    let dir = std::fs::File::open(tree).ok()?;
    if wait {
        dir.lock().ok()?;
    } else {
        dir.try_lock().ok()?;
    }
    Some(dir)
}

/// Set every fingerprint file's atime to its mtime under `tree`, so the next
/// read by cargo records a fresh atime despite `relatime`.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT rearm-skipped|s@^                let _ = rearm_file(\&entry.path());$@@|a_collection_re_arms_the_survivors
pub fn rearm(tree: &Path) {
    for fingerprints in crate::prune::directories_named(tree, ".fingerprint") {
        let Ok(units) = std::fs::read_dir(&fingerprints) else {
            continue;
        };
        for unit in units.filter_map(Result::ok) {
            let Ok(files) = std::fs::read_dir(unit.path()) else {
                continue;
            };
            for entry in files.filter_map(Result::ok) {
                let _ = rearm_file(&entry.path());
            }
        }
    }
}

fn rearm_file(path: &Path) -> std::io::Result<()> {
    let modified = std::fs::metadata(path)?.modified()?;
    std::fs::File::open(path)?.set_times(std::fs::FileTimes::new().set_accessed(modified))
}

/// Units used this recently are the working set, never collected (CLOUD-2197).
///
/// Collecting toward `max_free_mb` walks oldest first, and with need enough it
/// reaches what was built minutes ago: measured on #1132, a hook collecting
/// during a nextest run removed the `policy_modules` test binary built for that
/// same run, before nextest executed it, and its 20 cases failed to exec. A
/// volume that cannot be brought above the minimum without the working set is
/// the pre-step check's refusal to make, never a deletion of the build in use.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT working-set-collected|s@^        if unit.last_use >= working_set {$@        if false {@|the_working_set_is_never_collected
pub const WORKING_SET: std::time::Duration = std::time::Duration::from_mins(10);

/// How a collection is asked for.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Every tree to rank, the checkout's `target/` first.
    pub trees: &'a [PathBuf],
    /// `[prune] keep`: the superseded pass's retention.
    pub keep_generations: usize,
    /// Files never collected.
    pub kept: &'a [Kept],
    /// Bytes to free before stopping.
    pub need_bytes: u64,
    /// Stop at the first unit boundary past this instant.
    pub deadline: Option<Instant>,
    /// Block on another collector's lock rather than skipping the tree.
    pub wait: bool,
}

/// Collect: superseded units first, then live units oldest first, until
/// `need_bytes` are freed or the deadline passes; then re-arm the survivors.
/// Returns the bytes freed and the units removed.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT reachability-pass-skipped|s@^        let (units, bytes) = crate::prune::reclaim_superseded(tree, request.keep_generations);$@        let (units, bytes) = (0, 0);@|a_superseded_unit_goes_before_an_older_live_one
//MUTANT lru-order-reversed|s@^    live.sort_by_key(\x7cunit\x7c unit.last_use);$@    live.sort_by_key(\x7cunit\x7c std::cmp::Reverse(unit.last_use));@|the_least_recently_used_live_unit_goes_first
//MUTANT collects-past-max-free|s@^        if freed >= request.need_bytes \x7c\x7c past(request.deadline) {$@        if past(request.deadline) {@|collection_stops_at_max_free
//MUTANT held-tree-collected|s@^        let Some(_held) = crate::prune::claim(\&unit.tree, \&unit.profile) else {$@        let Some(_held) = Some(()) else {@|a_tree_a_build_holds_is_never_collected
//MUTANT engine-unit-collected|s@^            .any(\x7cartifact\x7c is_kept(artifact, request.kept))$@            .any(\x7c_\x7c false)@|the_running_engine_is_never_collected
#[must_use]
pub fn collect(request: &Request<'_>) -> (u64, usize) {
    let past = |deadline: Option<Instant>| deadline.is_some_and(|at| Instant::now() >= at);
    let locks: Vec<(PathBuf, std::fs::File)> = request
        .trees
        .iter()
        .filter_map(|tree| lock_tree(tree, request.wait).map(|lock| (tree.clone(), lock)))
        .collect();
    let mut freed: u64 = 0;
    let mut removed = 0usize;
    for (tree, _) in &locks {
        if freed >= request.need_bytes {
            break;
        }
        let (units, bytes) = crate::prune::reclaim_superseded(tree, request.keep_generations);
        removed += units;
        freed += bytes;
    }
    let mut live: Vec<Unit> = locks.iter().flat_map(|(tree, _)| units_in(tree)).collect();
    live.sort_by_key(|unit| unit.last_use);
    let working_set = SystemTime::now()
        .checked_sub(WORKING_SET)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    for unit in live {
        if freed >= request.need_bytes || past(request.deadline) {
            break;
        }
        // THE WORKING SET IS NEVER COLLECTED: units are oldest first, so the
        // first one used inside the window ends the pass.
        if unit.last_use >= working_set {
            break;
        }
        let Some(_held) = crate::prune::claim(&unit.tree, &unit.profile) else {
            continue;
        };
        if unit
            .artifacts
            .iter()
            .any(|artifact| is_kept(artifact, request.kept))
        {
            continue;
        }
        // THE FINGERPRINT FIRST: a collection cut off mid-unit leaves a unit with
        // no fingerprint, which cargo rebuilds rather than trusts.
        freed += remove_counted(&unit.fingerprint);
        for artifact in &unit.artifacts {
            freed += remove_counted(artifact);
        }
        removed += 1;
    }
    for (tree, _) in &locks {
        rearm(tree);
    }
    (freed, removed)
}

/// Collect if free space is below the declared minimum (CLOUD-2197).
///
/// One free-space read, and `None` at once above `min_free_mb` or where the
/// band is undeclared: that is the whole cost on the hook path. Below it, the
/// trees are the checkout's `[prune] root` and each linked worktree's.
pub fn collect_if_pressed(
    repo: &Path,
    prune: &crate::prune::Prune,
    kept: &[Kept],
    free_mb: &mut dyn FnMut() -> anyhow::Result<u64>,
    deadline: Option<Instant>,
    wait: bool,
) -> Option<Collected> {
    let (min, _) = prune.free_band()?;
    let free = free_mb().ok()?;
    if free >= min {
        return None;
    }
    collect_toward_max(repo, prune, kept, free, free_mb, deadline, wait)
}

/// Collect until `[prune] max_free_mb` is free, from a reading of `free` MiB.
///
/// The land watcher calls this on a PROJECTED crossing, when the reading itself
/// may still sit above the minimum (CLOUD-1937's linker writes gigabytes between
/// two samples); the hook calls it through [`collect_if_pressed`]. `None` where
/// the band is undeclared.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT worktree-targets-unseen|s@^        .chain(crate::git::linked_worktree_dirs(repo))$@        .chain(Vec::<PathBuf>::new())@|a_sibling_worktrees_units_are_ranked_with_the_checkouts
pub fn collect_toward_max(
    repo: &Path,
    prune: &crate::prune::Prune,
    kept: &[Kept],
    free: u64,
    free_mb: &mut dyn FnMut() -> anyhow::Result<u64>,
    deadline: Option<Instant>,
    wait: bool,
) -> Option<Collected> {
    let (_, max) = prune.free_band()?;
    let started = Instant::now();
    let trees: Vec<PathBuf> = std::iter::once(repo.to_path_buf())
        .chain(crate::git::linked_worktree_dirs(repo))
        .map(|dir| dir.join(&prune.root))
        .filter(|tree| tree.is_dir())
        .collect();
    let need_bytes = max.saturating_sub(free).saturating_mul(1024 * 1024);
    let (freed_bytes, units) = collect(&Request {
        trees: &trees,
        keep_generations: prune.keep,
        kept,
        need_bytes,
        deadline,
        wait,
    });
    Some(Collected {
        freed_bytes,
        units,
        free_after_mb: free_mb().unwrap_or(free),
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}
