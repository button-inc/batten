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
    /// Why units were passed over: the locks a running build held, and whether
    /// the pass stopped at the working set (CLOUD-2225).
    pub held: Held,
}

/// What stopped a pass short, named so a report never guesses (CLOUD-2225):
/// measured on #1132, a pass passed over 1,026 units whose profile a running
/// build held and stopped at the working set, and reported only that it freed
/// nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Held {
    /// Each `.cargo-lock` or collector lock that declined, once, in order.
    pub locks: Vec<PathBuf>,
    /// The pass reached a unit a live build has used and stopped there.
    pub live: bool,
}

/// What one [`collect`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pass {
    /// Bytes freed, each inode counted once.
    pub freed_bytes: u64,
    /// Units removed, superseded and live together.
    pub removed: usize,
    /// What it passed over, and why.
    pub held: Held,
}

//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT reclaim-unlink-unmeasured|s@^            format!("disk-unlink-ms {}", self.wall_ms),$@@|the_arm_watches_past_the_gate
//MUTANT-SUITE crates/batten/tests/it/target_prune.rs
//MUTANT held-lock-unreported|s@^                .map(\x7clock\x7c format!("disk-held {}", lock.display())),$@                .filter(\x7c_\x7c false).map(\x7clock\x7c format!("disk-held {}", lock.display())),@|a_held_profile_is_reported_by_its_lock
impl Collected {
    /// The lap-record lines: `disk-collected <freed_mb> <units> <free_after_mb>`,
    /// the unlink cost (CLOUD-1945's figure), then one `disk-held <lock>` per
    /// lock that declined and `disk-live` where a live build stopped the pass.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "disk-collected {} {} {}",
                self.freed_bytes / (1024 * 1024),
                self.units,
                self.free_after_mb
            ),
            format!("disk-unlink-ms {}", self.wall_ms),
        ];
        lines.extend(
            self.held
                .locks
                .iter()
                .map(|lock| format!("disk-held {}", lock.display())),
        );
        if self.held.live {
            lines.push("disk-live".to_owned());
        }
        lines
    }
}

/// Whether `BATTEN_DISK_TRACE=1` asks for the sample trace. Here rather than in
/// [`crate::disk_watch`], which reaches this module: the collector is the lower
/// of the two and never reaches its watcher.
#[must_use]
pub fn tracing() -> bool {
    std::env::var_os("BATTEN_DISK_TRACE").is_some_and(|value| value == "1")
}

/// One trace line, the one spelling the watcher, the collector and the hook
/// share.
#[must_use]
pub fn trace_line(kind: &str, fields: &[u64]) -> String {
    let mut line = String::from(kind);
    for field in fields {
        line.push(' ');
        line.push_str(&field.to_string());
    }
    line
}

/// A file that must never be collected: the installed engine, the running
/// executable, and every name hardlinked to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// A file, by device and inode, which names it across its hardlinks.
    File {
        /// The device.
        dev: u64,
        /// The inode.
        ino: u64,
    },
    /// A running program the process table names only by its kernel name
    /// (macOS's `p_comm`, the executable's file name cut to 16 bytes): every
    /// file whose name begins with it. Wider than the one file, never narrower.
    Named(String),
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
///
/// A PROGRAM THE TABLE NAMES ONLY BY NAME IS KEPT BY NAME. macOS gives each
/// process's path only through `kern.procargs2`, which no safe crate reaches
/// (see [`processes`]), so there a running program is [`Kept::Named`].
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT running-program-collected|s@^        .chain(table.iter().filter_map(\x7cprocess\x7c process.exe.clone()))$@@|a_unit_a_running_program_executes_is_never_collected#[must_use]
#[must_use]
pub fn engine_kept() -> Vec<Kept> {
    let table = processes().unwrap_or_default();
    let running = std::env::current_exe().ok();
    let installed = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(crate::surface::BINARY))
            .find(|candidate| candidate.is_file())
    });
    let paths: Vec<PathBuf> = running
        .into_iter()
        .chain(installed)
        .chain(table.iter().filter_map(|process| process.exe.clone()))
        .filter(|path| path.exists())
        .map(|path| crate::git::canonical(&path))
        .collect();
    let mut kept = kept(&paths);
    let named = table
        .into_iter()
        .filter(|process| process.exe.is_none() && !process.name.is_empty())
        .map(|process| Kept::Named(process.name));
    kept.extend(named);
    kept
}

/// A running process: the program it executes and when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    /// Its executable, where the table names one: Linux's `/proc/<pid>/exe`,
    /// Windows' `Path`. macOS's table names none.
    pub exe: Option<PathBuf>,
    /// Its program's name: the executable's file name, or on macOS the
    /// kernel's `p_comm`, that name cut to 16 bytes.
    pub name: String,
    /// When it started.
    pub started: SystemTime,
}

/// The file name of `path`, on either separator: a Windows listing is parsed on
/// every platform's suite.
#[cfg(any(target_os = "linux", target_os = "android", windows, test))]
fn program_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

/// Every process this user can see, from each platform's own process table, or
/// `None` where the table itself could not be read. A process whose executable
/// or start cannot be read (another user's, or one that exited mid-scan)
/// contributes nothing; the other roots still hold.
///
/// Linux and Android read `/proc/<pid>/exe` and field 22 of `/proc/<pid>/stat`,
/// clock ticks since boot, against `/proc/stat`'s `btime`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn processes() -> Option<Vec<Process>> {
    let boot = proc_stat::boot_seconds(&std::fs::read_to_string("/proc/stat").ok()?)?;
    let ticks = rustix::param::clock_ticks_per_second().max(1);
    let entries = std::fs::read_dir("/proc").ok()?;
    let table = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|entry| {
            let exe = std::fs::read_link(entry.path().join("exe")).ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let since_boot = proc_stat::start_ticks(&stat)?;
            let started = SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(boot)
                + std::time::Duration::from_millis(since_boot.saturating_mul(1000) / ticks);
            Some(Process {
                name: program_name(&exe.to_string_lossy()),
                exe: Some(exe),
                started,
            })
        })
        .collect();
    Some(table)
}

/// The two `/proc` layouts [`processes`] reads, as pure functions so every
/// platform's suite checks them.
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT stat-start-misread|s@^        rest.split_whitespace().nth(19)?.parse().ok()$@        rest.split_whitespace().nth(18)?.parse().ok()@|a_stat_line_yields_its_start_ticks
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod proc_stat {
    /// Field 22 of a `/proc/<pid>/stat` line, `starttime`: read after the LAST
    /// `)`, since the command name in field 2 may itself hold spaces and parens.
    pub(super) fn start_ticks(stat: &str) -> Option<u64> {
        let (_, rest) = stat.rsplit_once(')')?;
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    /// `/proc/stat`'s `btime`: the boot instant, in seconds since the epoch.
    pub(super) fn boot_seconds(stat: &str) -> Option<u64> {
        stat.lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()
    }
}

/// macOS reads `kern.proc.all`: every process's start and its `p_comm`.
///
/// BY NAME, AND NOTHING ELSE (measured on #1132's macOS run, which collected a
/// running binary and read every unit live). XNU declares `kern.proc.all` and
/// `kern.procargs2` with no format string (`bsd/kern/kern_sysctl.c`), and
/// `sysctl.oidfmt` answers `ENOENT` for such an oid (`kern_newsysctl.c`); the
/// `sysctl` crate asks `oidfmt` before every read by oid, so both reads failed
/// and the table read as `None`. Its by-name read goes through `sysctlbyname`
/// and asks nothing first, which reaches `kern.proc.all`. It cannot reach
/// `kern.procargs2 <pid>`, the only path source: XNU's name lookup stops at a
/// handler node, so the pid cannot be named (the crate's issue #51), and the
/// FFI that would read it `unsafe_code = "forbid"` puts out of reach. So a
/// process here is its `p_comm`, which [`Kept::Named`] keeps wide.
#[cfg(target_os = "macos")]
fn processes() -> Option<Vec<Process>> {
    use sysctl::Sysctl as _;
    let ctl = sysctl::Ctl::new_with_type("kern.proc.all", sysctl::CtlType::Node, "").ok()?;
    match ctl.value() {
        Ok(sysctl::CtlValue::Node(raw) | sysctl::CtlValue::Struct(raw)) => {
            Some(darwin::processes(&raw))
        }
        _ => None,
    }
}

/// The Darwin layout [`processes`] reads, as a pure function so every
/// platform's suite checks it; only the `sysctl` call is macOS's own.
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT kinfo-pid-misread|s@^                let pid = i32::from_le_bytes(entry.get(P_PID..P_PID + 4)?.try_into().ok()?);$@                let pid = i32::from_le_bytes(entry.get(0..4)?.try_into().ok()?);@|a_kinfo_table_yields_each_process
//MUTANT kinfo-start-misread|s@^                    i64::from_le_bytes(entry.get(P_STARTTIME..P_STARTTIME + 8)?.try_into().ok()?);$@                    i64::from_le_bytes(entry.get(P_PID..P_PID + 8)?.try_into().ok()?);@|a_kinfo_table_yields_each_start
//MUTANT kinfo-comm-misread|s@^                let comm = entry.get(P_COMM..P_COMM + MAXCOMLEN)?;$@                let comm = entry.get(P_COMM - 1..P_COMM - 1 + MAXCOMLEN)?;@|a_kinfo_table_yields_each_process
#[cfg(any(target_os = "macos", test))]
mod darwin {
    use super::Process;
    use std::time::{Duration, SystemTime};

    /// `sizeof(struct kinfo_proc)`, and the offsets in its `kp_proc` (an
    /// `extern_proc`, `<sys/proc.h>`) of `p_starttime` (a `timeval`: `i64`
    /// seconds, `i32` microseconds), `p_pid` and `p_comm`, on both Apple
    /// triples, as Go's `ztypes_darwin_{amd64,arm64}.go` lay them out.
    const KINFO_PROC: usize = 648;
    const P_STARTTIME: usize = 0;
    const P_PID: usize = 40;
    const P_COMM: usize = 243;
    /// `MAXCOMLEN`: `p_comm` is this many bytes and a NUL.
    const MAXCOMLEN: usize = 16;

    /// Every live process in a `kern.proc.all` table, by its `p_comm` and
    /// start; pid 0 is the kernel.
    pub(super) fn processes(table: &[u8]) -> Vec<Process> {
        table
            .as_chunks::<KINFO_PROC>()
            .0
            .iter()
            .filter_map(|entry| {
                let pid = i32::from_le_bytes(entry.get(P_PID..P_PID + 4)?.try_into().ok()?);
                let secs =
                    i64::from_le_bytes(entry.get(P_STARTTIME..P_STARTTIME + 8)?.try_into().ok()?);
                let micros = i32::from_le_bytes(
                    entry
                        .get(P_STARTTIME + 8..P_STARTTIME + 12)?
                        .try_into()
                        .ok()?,
                );
                let started = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(u64::try_from(secs).ok()?)
                    + Duration::from_micros(u64::try_from(micros).ok()?);
                let comm = entry.get(P_COMM..P_COMM + MAXCOMLEN)?;
                let comm = comm.split(|byte| *byte == 0).next()?;
                let name = String::from_utf8_lossy(comm).into_owned();
                (pid > 0).then_some(Process {
                    exe: None,
                    name,
                    started,
                })
            })
            .collect()
    }
}

/// Windows asks PowerShell, which every supported Windows ships: `Get-Process`
/// names each process's path and `StartTime`, printed as a UTC `FILETIME`. A
/// spawn, a few hundred milliseconds, paid only when a collection runs, which
/// is below `min_free_mb`; the Win32 calls themselves are FFI that
/// `unsafe_code = "forbid"` puts out of reach, and the safe wrapper (`sysinfo`)
/// adds eighteen crates to the lockfile for this one listing.
#[cfg(windows)]
fn processes() -> Option<Vec<Process>> {
    let argv: Vec<String> = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        WINDOWS_PROCESSES,
    ]
    .iter()
    .map(|word| (*word).to_owned())
    .collect();
    let root = std::env::temp_dir();
    match crate::exec::piped_argv(&root, &argv, "", crate::exec::Diagnostics::Drop, &[]) {
        Some((0, listing)) => Some(windows_table::parse(&listing)),
        _ => None,
    }
}

/// The listing [`processes`] asks PowerShell for: `<path>\t<FILETIME>`, one
/// process per line. A process whose start this user may not read throws, and
/// is skipped.
#[cfg(windows)]
const WINDOWS_PROCESSES: &str = "Get-Process | ForEach-Object { try { $_.Path + \"`t\" + $_.StartTime.ToFileTimeUtc() } catch {} }";

/// The listing's layout, as a pure function so every platform's suite checks it.
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT filetime-epoch-ignored|s@^                    .checked_sub(FILETIME_TO_UNIX)?;$@                    ;@|a_powershell_listing_yields_each_process
#[cfg(any(windows, test))]
mod windows_table {
    use super::Process;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// 100-nanosecond intervals from 1601-01-01 to the Unix epoch.
    const FILETIME_TO_UNIX: u64 = 116_444_736_000_000_000;

    pub(super) fn parse(listing: &str) -> Vec<Process> {
        listing
            .lines()
            .filter_map(|line| {
                let (path, filetime) = line.trim_end().rsplit_once('\t')?;
                if path.is_empty() {
                    return None;
                }
                let intervals = filetime
                    .trim()
                    .parse::<u64>()
                    .ok()?
                    .checked_sub(FILETIME_TO_UNIX)?;
                Some(Process {
                    exe: Some(PathBuf::from(path)),
                    name: super::program_name(path),
                    started: SystemTime::UNIX_EPOCH + Duration::from_nanos(intervals * 100),
                })
            })
            .collect()
    }
}

/// Elsewhere no process table is read.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn processes() -> Option<Vec<Process>> {
    None
}

/// The programs whose process is a build: cargo and what it runs.
const BUILD_PROGRAMS: [&str; 6] = [
    "cargo",
    "cargo-nextest",
    "cargo-clippy",
    "clippy-driver",
    "rustc",
    "rustdoc",
];

/// The instant from which every unit used is live: the start of the earliest
/// live build (CLOUD-2197). `None` where no build is running.
///
/// A PROCESS TABLE THAT COULD NOT BE READ IS NOT "NO BUILD": every unit is then
/// live, so a pass takes only what no build can reach (the superseded pass) and
/// says a live build stopped it. Could-not-look is never clean.
///
/// NIX'S RULE, NOT AN AGE. Nix never deletes a live path, and liveness is
/// reachability from roots, with no time window. Here the root is a running
/// build: a run's fresh check reads every fingerprint it depends on, so what it
/// used since it started is exactly what it may still need, for exactly as long
/// as it lives. Measured on #1132, the 10-minute window this replaces was wrong
/// both ways: a hook collection during a nextest run removed the
/// `policy_modules` binary built for it (a guess too short for a long run), and
/// under pressure every recent unit was protected, so a pass freed 0 MB with
/// free space below `min_free_mb`.
#[must_use]
pub fn live_since(trees: &[PathBuf]) -> Option<SystemTime> {
    match processes() {
        Some(table) => earliest_build_start(&table, trees),
        None => Some(SystemTime::UNIX_EPOCH),
    }
}

/// The earliest start among `processes` that are builds: a [`BUILD_PROGRAMS`]
/// program, or an executable under one of `trees` (a test binary it runs).
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT root-takes-any-process|s@^        .filter(\x7cprocess\x7c is_build(\&process.exe, \&trees))$@        .filter(\x7c_\x7c true)@|the_earliest_build_is_the_root
#[must_use]
pub fn earliest_build_start(processes: &[Process], trees: &[PathBuf]) -> Option<SystemTime> {
    let trees: Vec<PathBuf> = trees
        .iter()
        .map(|tree| crate::git::canonical(tree))
        .collect();
    processes
        .iter()
        .filter(|process| is_build(process, &trees))
        .map(|process| process.started)
        .min()
}

/// A build: a [`BUILD_PROGRAMS`] name (each under `p_comm`'s 16 bytes, so macOS
/// names them whole), or an executable under one of `trees`.
fn is_build(process: &Process, trees: &[PathBuf]) -> bool {
    let named = Path::new(&process.name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| BUILD_PROGRAMS.contains(&stem));
    named
        || process
            .exe
            .as_ref()
            .is_some_and(|exe| trees.iter().any(|tree| exe.starts_with(tree)))
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
    Some(Kept::File {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

/// Volume serial and file index: Windows' `(dev, ino)`, which names a file
/// across its hardlinks as the unix pair does. `std` keeps it unstable there.
#[cfg(windows)]
fn identity(path: &Path) -> Option<Kept> {
    let file = std::fs::File::open(path).ok()?;
    let info = winapi_util::file::information(&file).ok()?;
    Some(Kept::File {
        dev: info.volume_serial_number(),
        ino: info.file_index(),
    })
}

#[cfg(not(any(unix, windows)))]
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
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT scratch-unit-ranked|s@^        .filter(\x7cfingerprints\x7c !fingerprints.starts_with(\&scratch))$@        .filter(\x7c_\x7c true)@|a_build_inside_fresh_scratch_is_never_collected
fn units_in(tree: &Path) -> Vec<Unit> {
    let mut units = Vec::new();
    // SCRATCH IS ONE UNIT EACH, RANKED BY [`scratch_in`]: a test suite builds
    // whole trees under `tmp/`, and ranking their units one by one reached past
    // the working set that keeps a running suite's fixture whole. Measured on
    // #1132, the session's hook collected a running case's aged fixture unit
    // and the case failed three runs in five.
    let scratch = tree.join("tmp");
    for fingerprints in crate::prune::directories_named(tree, ".fingerprint")
        .into_iter()
        .filter(|fingerprints| !fingerprints.starts_with(&scratch))
    {
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
        units.extend(caches_in(tree, &profile));
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

/// The regrowable caches a profile holds, one unit each: every
/// `incremental/<crate>-<hash>` directory (CLOUD-2197).
///
/// MEASURED ON #1132, THE BYTES WERE HERE: a pass removed 865 units and freed
/// 159MB while `incremental` held 8.1GB across three profiles — a unit took its
/// `deps` artifacts, fingerprint and `build/` directory and never its
/// incremental cache, so the collector could not reach the volume's largest
/// class. Ranked with the units by last use, behind the same profile lock and
/// the same working set, so the edit loop's own cache is never the one taken —
/// the defect the retired escalation had, dropping `incremental` first.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT incremental-unranked|s@^        units.extend(caches_in(tree, \&profile));$@@|a_stale_incremental_cache_is_collected_and_a_fresh_one_kept
fn caches_in(tree: &Path, profile: &Path) -> Vec<Unit> {
    let Ok(entries) = std::fs::read_dir(profile.join("incremental")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| Unit {
            tree: tree.to_path_buf(),
            profile: profile.to_path_buf(),
            last_use: newest_write(&entry.path()),
            fingerprint: entry.path(),
            artifacts: Vec::new(),
        })
        .collect()
}

/// Does a live run read this unit with no build lock held: the test scratch it
/// writes, or an executable it may launch (a file with no extension, or `.exe`)?
/// Libraries, metadata and caches are read only by a compile, under the lock.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT run-root-ignores-executables|s@artifact.is_file() \&\& artifact.extension().is_none_or(\x7cext\x7c ext == "exe")@false@|a_test_binary_a_live_run_built_is_never_collected
fn read_by_a_run(unit: &Unit) -> bool {
    unit.profile == unit.tree.join("tmp")
        || unit.artifacts.iter().any(|artifact| {
            artifact.is_file() && artifact.extension().is_none_or(|ext| ext == "exe")
        })
}

/// The test scratch a tree holds, one unit per entry under `tmp/`: cargo's
/// `CARGO_TARGET_TMPDIR`, which integration suites fill with fixtures and
/// nothing removes until the next run's setup — measured at 4.1GB on #1132.
/// No build lock covers it; the working set keeps a running suite's fixtures.
fn scratch_in(tree: &Path) -> Vec<Unit> {
    let scratch = tree.join("tmp");
    let Ok(entries) = std::fs::read_dir(&scratch) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_symlink()))
        .map(|entry| Unit {
            tree: tree.to_path_buf(),
            profile: scratch.clone(),
            last_use: newest_write(&entry.path()),
            fingerprint: entry.path(),
            artifacts: Vec::new(),
        })
        .collect()
}

/// The newest mtime of `path` and its immediate children: when a cache or a
/// fixture was last written. Shallow on purpose — a session or fixture writes
/// its own directory, and a full walk would spend the hook's deadline.
fn newest_write(path: &Path) -> SystemTime {
    let own = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok()?.modified().ok())
        .fold(own, std::cmp::max)
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
//MUTANT artifacts-unindexed|s@^                        .push(entry.path());$@                        .clear();@|a_collected_unit_takes_its_artifacts
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
    let (links, allocated) = allocation(path, &meta);
    if std::fs::remove_file(path).is_err() {
        return 0;
    }
    if links == 1 { allocated } else { 0 }
}

#[cfg(unix)]
fn allocation(_path: &Path, meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (meta.nlink(), meta.blocks() * 512)
}

/// Windows' link count, from the same file information [`identity`] reads
/// (`std` keeps it unstable there). Measured on #1132's `windows` job: read as
/// a constant 1, a hardlinked file counted as freed and the pass stopped short.
/// The handle is dropped before the caller removes the file, which Windows
/// refuses while one is open; a count that cannot be read is the old 1.
#[cfg(windows)]
fn allocation(path: &Path, meta: &std::fs::Metadata) -> (u64, u64) {
    let links = std::fs::File::open(path)
        .ok()
        .and_then(|file| winapi_util::file::information(&file).ok())
        .map_or(1, |info| info.number_of_links());
    (links, meta.len())
}

#[cfg(not(any(unix, windows)))]
fn allocation(_path: &Path, meta: &std::fs::Metadata) -> (u64, u64) {
    (1, meta.len())
}

/// Whether `path` is one of the kept files: by device and inode, or by a
/// [`Kept::Named`] its file name begins with.
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT kept-name-unmatched|s@^            .is_some_and(\x7cfile\x7c file.starts_with(name.as_str())),$@            .is_some_and(\x7cfile\x7c file == name.as_str()),@|a_program_named_only_keeps_every_file_its_name_begins
fn is_kept(path: &Path, kept: &[Kept]) -> bool {
    let named = kept.iter().any(|kept| match kept {
        Kept::Named(name) => path
            .file_name()
            .and_then(|file| file.to_str())
            .is_some_and(|file| file.starts_with(name.as_str())),
        Kept::File { .. } => false,
    });
    // No identity is read when no file is kept: on Windows each read opens the
    // file, and a pass ranks thousands of artifacts.
    named
        || (kept.iter().any(|kept| matches!(kept, Kept::File { .. }))
            && identity(path).is_some_and(|id| kept.contains(&id)))
}

/// Take the collector's lock on `tree`: an exclusive `flock` on the directory
/// itself, an existing inode, so taking it writes nothing at 0 bytes free.
/// `None` when another collector holds it.
///
/// A LOCK THE PLATFORM REFUSES IS NOT ANOTHER COLLECTOR'S. Only `WouldBlock`
/// says a collector holds the tree; an error from the lock call itself (a
/// filesystem that cannot lock a directory) collects without exclusion, which
/// [`remove_counted`] tolerates, rather than reading every tree as held and
/// freeing nothing.
fn lock_tree(tree: &Path, wait: bool) -> Option<std::fs::File> {
    let dir = open_handle(tree).ok()?;
    let taken = if wait {
        dir.lock().map_err(std::fs::TryLockError::Error)
    } else {
        dir.try_lock()
    };
    match taken {
        Ok(()) | Err(std::fs::TryLockError::Error(_)) => Some(dir),
        Err(std::fs::TryLockError::WouldBlock) => None,
    }
}

/// `path`, file or directory, opened for its lock or its times.
///
/// WINDOWS OPENS A DIRECTORY ONLY WITH BACKUP SEMANTICS and writes times only
/// through a handle opened for writing; measured on #1132's `windows` job, a
/// plain `File::open` read every tree as held and re-armed no survivor (the
/// rule `perf.rs`'s sibling stamp records). Elsewhere a read-only handle does
/// both, and is the only handle a directory takes.
fn open_handle(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(path)
    }
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
    open_handle(path)?.set_times(std::fs::FileTimes::new().set_accessed(modified))
}

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
    /// Every unit used at or after this instant is live: [`live_since`].
    pub live_since: Option<SystemTime>,
}

/// The live units and scratch, in the order a pass takes them.
///
/// A PROFILE IS RANKED BY ITS LAST BUILD BEFORE ITS UNITS BY THEIRS
/// (2026-10-14). A unit's own last use is its fingerprint's atime or mtime, and
/// under `relatime` a read moves neither once the file has been read since it
/// was written: a dependency every build reads looks as old as the day it was
/// built. Measured on #1132, a land lap removed 1,308 of 1,482 units to free
/// 4.1 GB, most of them the stable dependencies of the profiles the next lap
/// built, while `mutate-cargo`, idle for two hours, kept 2 GB. A profile whose
/// newest unit is recent is being built; its units go after every unit of an
/// idle profile, and within a profile the oldest still go first.
///
/// Scratch is not a profile: each fixture keeps its own time, so one fresh
/// fixture does not shield every stale one beside it.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT scratch-unranked|s@^    live.extend(scratch);$@    drop(scratch);@|a_stale_test_scratch_entry_is_collected
//MUTANT profile-unranked|s@^            built.get(\&unit.profile).copied().unwrap_or(unit.last_use),$@            unit.last_use,@|an_idle_profiles_units_go_before_a_built_profiles_older_ones
fn ranked(mut live: Vec<Unit>, scratch: Vec<Unit>) -> Vec<Unit> {
    let mut built: std::collections::HashMap<PathBuf, SystemTime> =
        std::collections::HashMap::new();
    for unit in &live {
        let newest = built.entry(unit.profile.clone()).or_insert(unit.last_use);
        *newest = (*newest).max(unit.last_use);
    }
    live.extend(scratch);
    live.sort_by_key(|unit| {
        (
            built.get(&unit.profile).copied().unwrap_or(unit.last_use),
            unit.last_use,
        )
    });
    live
}

/// Collect: superseded units first, then live units oldest first, until
/// `need_bytes` are freed or the deadline passes; then re-arm the survivors.
/// Returns what it freed and removed, and what stopped it short.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT reachability-pass-skipped|s@^        let (units, bytes) = crate::prune::reclaim_superseded(tree, request.keep_generations);$@        let (units, bytes) = (0, 0);@|a_superseded_unit_goes_before_an_older_live_one
//MUTANT collects-past-max-free|s@^        if freed >= request.need_bytes \x7c\x7c past(request.deadline) {$@        if past(request.deadline) {@|collection_stops_at_max_free
//MUTANT held-tree-collected|s@^        let _building = match crate::prune::claim(\&unit.tree, \&unit.profile) {$@        let _building = match Ok::<(), PathBuf>(()) {@|a_tree_a_build_holds_is_never_collected
//MUTANT engine-unit-collected|s@^            .any(\x7cartifact\x7c is_kept(artifact, request.kept))$@            .any(\x7c_\x7c false)@|the_running_engine_is_never_collected
#[must_use]
pub fn collect(request: &Request<'_>) -> Pass {
    let past = |deadline: Option<Instant>| deadline.is_some_and(|at| Instant::now() >= at);
    let mut held = Held::default();
    let mut locks: Vec<(PathBuf, std::fs::File)> = Vec::new();
    for tree in request.trees {
        match lock_tree(tree, request.wait) {
            Some(lock) => locks.push((tree.clone(), lock)),
            // Another collector holds this tree; its own pass reports it.
            None => held.locks.push(tree.clone()),
        }
    }
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
    let scratch: Vec<Unit> = locks
        .iter()
        .flat_map(|(tree, _)| scratch_in(tree))
        .collect();
    let live = ranked(
        locks.iter().flat_map(|(tree, _)| units_in(tree)).collect(),
        scratch,
    );
    // WHY A PASS REMOVED WHAT IT DID, counted (CLOUD-2197's trace): measured on
    // #1132, a pass over hundreds of units older than the working set removed
    // none, and nothing said which guard stopped it.
    let mut why = Skipped {
        candidates: live.len(),
        ..Skipped::default()
    };
    for unit in live {
        if freed >= request.need_bytes || past(request.deadline) {
            break;
        }
        // A LIVE BUILD'S UNITS ARE NEVER COLLECTED, AND THE ROOT IS CARGO'S OWN
        // LOCK: a build holds its profile's `.cargo-lock` for exactly as long as
        // it may read or write the profile, so a held profile is skipped whole.
        //
        // THE CLOCK ROOTS ONLY WHAT A RUN READS WITH NO LOCK HELD (2026-10-13).
        // "Used since the earliest live cargo started" protected every unit an
        // hour-long `verify` had touched in every tree — `target/clippy` long
        // after clippy exited, the mutate and cross trees — and the pass ended
        // at the first: `land` logged `disk-collected 0 0 0` until the volume
        // was full. A library is read only while a compile holds the lock, so
        // the lock is its root; what a live run still reads unlocked is an
        // executable it may launch (a suite's queued test binary, the measured
        // case) and the scratch it writes.
        let _building = match crate::prune::claim(&unit.tree, &unit.profile) {
            Ok(guards) => guards,
            Err(lock) => {
                why.held += 1;
                why.live |= request
                    .live_since
                    .is_some_and(|since| unit.last_use >= since);
                if !held.locks.contains(&lock) {
                    held.locks.push(lock);
                }
                continue;
            }
        };
        if request
            .live_since
            .is_some_and(|since| unit.last_use >= since)
            && read_by_a_run(&unit)
        {
            why.live = true;
            continue;
        }
        if unit
            .artifacts
            .iter()
            .any(|artifact| is_kept(artifact, request.kept))
        {
            why.kept += 1;
            continue;
        }
        // THE FINGERPRINT FIRST: a collection cut off mid-unit leaves a unit with
        // no fingerprint, which cargo rebuilds rather than trusts.
        freed += remove_counted(&unit.fingerprint);
        for artifact in &unit.artifacts {
            freed += remove_counted(artifact);
        }
        // AN ARTIFACT THE OS REFUSED TO REMOVE is in use: Windows will not unlink
        // a running image. The unit is counted kept, not removed.
        if unit.artifacts.iter().any(|artifact| artifact.exists()) {
            why.kept += 1;
        } else {
            removed += 1;
        }
    }
    for (tree, _) in &locks {
        rearm(tree);
    }
    if tracing() {
        let traced = trace_line(
            "disk-pass",
            &[
                u64::try_from(locks.len()).unwrap_or(u64::MAX),
                u64::try_from(why.candidates).unwrap_or(u64::MAX),
                u64::try_from(why.held).unwrap_or(u64::MAX),
                u64::try_from(why.kept).unwrap_or(u64::MAX),
                u64::from(why.live),
                u64::try_from(removed).unwrap_or(u64::MAX),
                request.need_bytes / (1024 * 1024),
            ],
        );
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("{traced}\n").as_bytes());
    }
    held.live = why.live;
    Pass {
        freed_bytes: freed,
        removed,
        held,
    }
}

/// What a pass passed over, for the trace: `disk-pass <trees> <candidates>
/// <held> <kept> <stopped_at_live_build> <removed> <need_mb>`.
#[derive(Debug, Default)]
struct Skipped {
    candidates: usize,
    held: usize,
    kept: usize,
    live: bool,
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

/// The trees a collection ranks together: the checkout's `[prune] root` and
/// each linked worktree's. Measured 2026-10-11: a sibling worktree's `target/`
/// filled the volume, and nothing the main checkout collected could see it.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT worktree-targets-unseen|s@^        .chain(crate::git::linked_worktree_dirs(repo))$@        .chain(Vec::<PathBuf>::new())@|a_sibling_worktrees_units_are_ranked_with_the_checkouts
#[must_use]
pub fn trees(repo: &Path, prune: &crate::prune::Prune) -> Vec<PathBuf> {
    std::iter::once(repo.to_path_buf())
        .chain(crate::git::linked_worktree_dirs(repo))
        .map(|dir| dir.join(&prune.root))
        .filter(|tree| tree.is_dir())
        .collect()
}

/// Collect until `[prune] max_free_mb` is free, from a reading of `free` MiB.
///
/// The watcher ([`crate::disk_watch::watch`]) calls this below the minimum, on
/// its own collection thread; the hook calls it through [`collect_if_pressed`].
/// `None` where the band is undeclared.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT-SUITE crates/batten/tests/it/target_prune.rs
//MUTANT checkout-build-collected|s@^    kept.extend(crate::engine::checkout_build(repo).and_then(\x7cbuild\x7c identity(\&build)));$@@|the_checkout_build_is_never_collected
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
    let trees = trees(repo, prune);
    let need_bytes = max.saturating_sub(free).saturating_mul(1024 * 1024);
    // THE CHECKOUT'S OWN BUILD IS A ROOT (CLOUD-2232): the installed engine
    // hands every call to it, so collecting it while nothing runs it would leave
    // the hook refusing until a rebuild.
    let mut kept = kept.to_vec();
    kept.extend(crate::engine::checkout_build(repo).and_then(|build| identity(&build)));
    let pass = collect(&Request {
        trees: &trees,
        keep_generations: prune.keep,
        kept: &kept,
        need_bytes,
        deadline,
        wait,
        live_since: live_since(&trees),
    });
    Some(Collected {
        freed_bytes: pass.freed_bytes,
        units: pass.removed,
        free_after_mb: free_mb().unwrap_or(free),
        wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        held: pass.held,
    })
}

#[cfg(test)]
mod tests {
    use super::{Kept, Process, darwin, earliest_build_start, proc_stat};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// One `kinfo_proc`: `p_starttime` at offset 0, `p_pid` at 40, `p_comm` at
    /// 243, the rest filler that must never be read; `p_nice`, the byte before
    /// `p_comm`, is filler too.
    fn kinfo(pid: i32, started: i64, comm: &str) -> Vec<u8> {
        let mut entry = vec![0xAA; 648];
        entry[0..8].copy_from_slice(&started.to_le_bytes());
        entry[8..12].copy_from_slice(&250_000_i32.to_le_bytes());
        entry[40..44].copy_from_slice(&pid.to_le_bytes());
        entry[243..260].fill(0);
        entry[243..243 + comm.len()].copy_from_slice(comm.as_bytes());
        entry
    }

    #[test]
    fn a_kinfo_table_yields_each_process() {
        let table: Vec<u8> = [(0, "kernel_task"), (1, "launchd"), (4242, "cargo-nextest")]
            .into_iter()
            .flat_map(|(pid, comm)| kinfo(pid, 1_700_000_000, comm))
            .collect();
        let names: Vec<String> = darwin::processes(&table)
            .into_iter()
            .map(|process| process.name)
            .collect();
        assert_eq!(
            names,
            vec!["launchd", "cargo-nextest"],
            "pid 0 is the kernel"
        );
        assert!(
            darwin::processes(&table[..647]).is_empty(),
            "a short entry is no process"
        );
        let full = kinfo(9, 1_700_000_000, "runner-555555555");
        assert_eq!(
            darwin::processes(&full)[0].name,
            "runner-555555555",
            "a name of all 16 bytes has no NUL inside the field"
        );
    }

    #[test]
    fn a_kinfo_table_yields_each_start() {
        let table = kinfo(7, 1_700_000_123, "rustc");
        assert_eq!(
            darwin::processes(&table),
            vec![Process {
                exe: None,
                name: "rustc".to_owned(),
                started: at(1_700_000_123) + Duration::from_millis(250),
            }]
        );
    }

    #[test]
    fn a_stat_line_yields_its_start_ticks() {
        // A command name holding a space and a paren, as `(cargo nextest)` and
        // worse can: the fields are read after the LAST `)`.
        let stat =
            "4242 (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(proc_stat::start_ticks(stat), Some(987_654));
        assert_eq!(proc_stat::start_ticks("4242 (cut"), None);
        assert_eq!(
            proc_stat::boot_seconds("cpu  1 2 3\nbtime 1700000000\nprocesses 9\n"),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn a_powershell_listing_yields_each_process() {
        // 2023-11-14T22:13:20Z as a FILETIME, then a pathless system process
        // and a line with no start, both skipped.
        let listing = "C:\\Users\\u\\.cargo\\bin\\cargo.exe\t133444736000000000\r\n\t133444736000000000\r\nC:\\x.exe\t\r\n";
        assert_eq!(
            super::windows_table::parse(listing),
            vec![Process {
                exe: Some(PathBuf::from("C:\\Users\\u\\.cargo\\bin\\cargo.exe")),
                name: "cargo.exe".to_owned(),
                started: at(1_700_000_000),
            }]
        );
    }

    #[test]
    fn the_earliest_build_is_the_root() {
        let tree = PathBuf::from("/nonexistent/repo/target");
        let process = |exe: &str, secs| Process {
            exe: Some(PathBuf::from(exe)),
            name: super::program_name(exe),
            started: at(secs),
        };
        let named = |name: &str, secs| Process {
            exe: None,
            name: name.to_owned(),
            started: at(secs),
        };
        let table = [
            process("/bin/bash", 100),
            process("/home/u/.rustup/toolchains/x/bin/cargo", 300),
            process("/nonexistent/repo/target/debug/deps/it-0123", 200),
            process("/usr/bin/batten", 50),
        ];
        assert_eq!(
            earliest_build_start(&table, std::slice::from_ref(&tree)),
            Some(at(200)),
            "a test binary under the tree is a build; a shell and the engine are not"
        );
        assert_eq!(
            earliest_build_start(&table[..1], std::slice::from_ref(&tree)),
            None
        );
        let macos = [
            named("bash", 100),
            named("cargo-nextest", 400),
            named("batten", 50),
        ];
        assert_eq!(
            earliest_build_start(&macos, &[tree]),
            Some(at(400)),
            "a process the table names only by name is a build by that name"
        );
    }

    /// A PROGRAM KNOWN ONLY BY NAME KEEPS EVERY FILE ITS NAME BEGINS (macOS's
    /// `p_comm`, cut to 16 bytes), and nothing else.
    #[test]
    fn a_program_named_only_keeps_every_file_its_name_begins() {
        let kept = [Kept::Named("runner-555555555".to_owned())];
        assert!(super::is_kept(
            Path::new("/t/debug/deps/runner-5555555555555555"),
            &kept
        ));
        assert!(!super::is_kept(
            Path::new("/t/debug/deps/runner-4444444444444444"),
            &kept
        ));
        assert!(!super::is_kept(
            Path::new("/t/debug/deps/runner-5555555555555555"),
            &[]
        ));
    }

    /// THE HOST'S OWN TABLE, READ (CLOUD-2197). Every case above feeds a layout
    /// by hand; this one reads the real table. Measured on #1132's macOS run:
    /// every read of it failed, the collector kept no running binary and read
    /// every unit live, and no case had read the table.
    #[test]
    fn the_host_table_holds_this_process() {
        let Some(table) = super::processes() else {
            panic!("the host's process table did not read");
        };
        let Ok(me) = std::env::current_exe().and_then(std::fs::canonicalize) else {
            panic!("this test binary has no path");
        };
        let file = me
            .file_name()
            .and_then(|file| file.to_str())
            .unwrap_or_default();
        assert!(
            table.iter().any(|process| match &process.exe {
                Some(exe) => std::fs::canonicalize(exe).is_ok_and(|exe| exe == me),
                None => !process.name.is_empty() && file.starts_with(process.name.as_str()),
            }),
            "{} processes, none running {}",
            table.len(),
            me.display()
        );
    }
}
