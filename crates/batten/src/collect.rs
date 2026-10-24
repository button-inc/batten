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
    asks_trace(std::env::var_os("BATTEN_DISK_TRACE").as_deref())
}

/// Whether a `BATTEN_DISK_TRACE` value asks for the trace: exactly `1`.
fn asks_trace(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
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
    kept.extend(kept_by_name(table));
    kept
}

/// The [`Kept::Named`] of each process `table` names only by its name: one with
/// no executable, and a name to match files by.
fn kept_by_name(table: Vec<Process>) -> impl Iterator<Item = Kept> {
    table
        .into_iter()
        .filter(|process| process.exe.is_none() && !process.name.is_empty())
        .map(|process| Kept::Named(process.name))
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
///
/// macOS reads `kern.proc.all`: every process's start and its `p_comm`.
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
///
/// Windows asks PowerShell, which every supported Windows ships: `Get-Process`
/// names each process's path and `StartTime`, printed as a UTC `FILETIME`. A
/// spawn, a few hundred milliseconds, paid only when a collection runs, which
/// is below `min_free_mb`; the Win32 calls themselves are FFI that
/// `unsafe_code = "forbid"` puts out of reach, and the safe wrapper (`sysinfo`)
/// adds eighteen crates to the lockfile for this one listing.
///
/// Elsewhere no process table is read.
///
/// Only each platform's read is under `cfg`; the layouts are [`darwin`]'s and
/// [`windows_table`]'s pure parsers, which every leg tests (CLOUD-2509).
fn processes() -> Option<Vec<Process>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (boot, ticks, pids) = proc_table()?;
        let table = pids
            .filter_map(|dir| {
                let exe = std::fs::read_link(dir.join("exe")).ok()?;
                let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
                let since_boot = proc_stat::start_ticks(&stat)?;
                Some(Process {
                    name: program_name(&exe.to_string_lossy()),
                    exe: Some(exe),
                    started: proc_stat::started(boot, since_boot, ticks),
                })
            })
            .collect();
        Some(table)
    }
    #[cfg(target_os = "macos")]
    {
        use sysctl::Sysctl as _;
        let ctl = sysctl::Ctl::new_with_type("kern.proc.all", sysctl::CtlType::Node, "").ok()?;
        let (sysctl::CtlValue::Node(raw) | sysctl::CtlValue::Struct(raw)) = ctl.value().ok()?
        else {
            return None;
        };
        Some(darwin::processes(&raw))
    }
    #[cfg(windows)]
    {
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
        let Some((0, listing)) =
            crate::exec::piped_argv(&root, &argv, "", crate::exec::Diagnostics::Drop, &[])
        else {
            return None;
        };
        Some(windows_table::parse(&listing))
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )))]
    {
        None
    }
}

/// The process table both readers walk: `/proc/stat`'s `btime`, the clock rate
/// `starttime` counts in (never zero), and each pid's directory, or `None` where
/// either could not be read.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn proc_table() -> Option<(u64, u64, impl Iterator<Item = PathBuf>)> {
    let boot = proc_stat::boot_seconds(&std::fs::read_to_string("/proc/stat").ok()?)?;
    let ticks = rustix::param::clock_ticks_per_second().max(1);
    let pids = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .map(|entry| entry.path());
    Some((boot, ticks, pids))
}

/// The `/proc` layouts [`processes`] and [`group_orphaned`] read, as pure
/// functions so every platform's suite checks them.
//MUTANT-SUITE crates/batten/src/collect.rs
//MUTANT stat-start-misread|s@^        rest.split_whitespace().nth(19)?.parse().ok()$@        rest.split_whitespace().nth(18)?.parse().ok()@|a_stat_line_yields_its_start_ticks
//MUTANT began-before-tie|s@ 1 < alive_at@ 1 <= alive_at@|a_stat_line_began_before_only_strictly_before
//MUTANT orphan-leader-ignored|s@if pid == group \x7c\x7c pid == registrant {@if pid == registrant {@|an_orphan_needs_its_leader_and_registrant_gone
//MUTANT orphan-registrant-ignored|s@if pid == group \x7c\x7c pid == registrant {@if pid == group {@|an_orphan_needs_its_leader_and_registrant_gone
//MUTANT orphan-unread-pid-absent|s@let Some(pid) = process_id(stat) else {@let Some(pid) = process_id(stat).or(Some(0)) else {@|an_orphan_needs_its_leader_and_registrant_gone
#[cfg(any(target_os = "linux", target_os = "android", test))]
mod proc_stat {
    /// Field 22 of a `/proc/<pid>/stat` line, `starttime`: read after the LAST
    /// `)`, since the command name in field 2 may itself hold spaces and parens.
    pub(super) fn start_ticks(stat: &str) -> Option<u64> {
        let (_, rest) = stat.rsplit_once(')')?;
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    /// The instant a process began: `since_boot` clock ticks at `ticks` per
    /// second (never zero) after the boot second.
    pub(super) fn started(boot: u64, since_boot: u64, ticks: u64) -> std::time::SystemTime {
        std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(boot)
            + std::time::Duration::from_millis(since_boot.saturating_mul(1000) / ticks)
    }

    /// Field 1 of a `/proc/<pid>/stat` line, the pid, which precedes the
    /// command name and so is read before it.
    pub(super) fn process_id(stat: &str) -> Option<i64> {
        stat.split_once(' ')?.0.parse().ok()
    }

    /// Field 5 of a `/proc/<pid>/stat` line, `pgrp`, read after the last `)`
    /// for [`start_ticks`]'s reason.
    pub(super) fn process_group(stat: &str) -> Option<i64> {
        let (_, rest) = stat.rsplit_once(')')?;
        rest.split_whitespace().nth(2)?.parse().ok()
    }

    /// Whether a `/proc/<pid>/stat` line's process began strictly before second
    /// `alive_at`, against the boot instant and the (non-zero) clock rate. One
    /// second of slack absorbs `btime`'s own rounding, so a tie is no.
    pub(super) fn began_before(stat: &str, boot: u64, ticks: u64, alive_at: u64) -> bool {
        start_ticks(stat).is_some_and(|since| boot + since / ticks + 1 < alive_at)
    }

    /// The pure core of [`super::group_orphaned`], over `stats` lines.
    pub(super) fn orphaned<S: AsRef<str>>(
        stats: impl IntoIterator<Item = S>,
        group: i64,
        registrant: i64,
        boot: u64,
        ticks: u64,
        alive_at: u64,
    ) -> bool {
        let mut predates = false;
        for stat in stats {
            let stat = stat.as_ref();
            if process_group(stat) != Some(group) {
                continue;
            }
            // A member whose pid cannot be read might be either: no proof.
            let Some(pid) = process_id(stat) else {
                return false;
            };
            if pid == group || pid == registrant {
                return false;
            }
            predates |= began_before(stat, boot, ticks, alive_at);
        }
        predates
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

/// Whether a recorded group is the orphan its registrant left: the group the
/// record names, with its leader and its registrant both gone from it, and a
/// member left that began before second `alive_at`.
///
/// **AGE PROVES IT IS THE SAME GROUP** (CLOUD-2366). Linux keeps a pid number
/// reserved while any live process still uses it as a process-group id, so the
/// number is reusable only once the group is EMPTY. The registrant was a member
/// and was alive at `alive_at`, its latest stamp, so the original group was not
/// empty then: every member of a reused group began after that second. A member
/// that began before it can only be the original's. Across a reboot every
/// process began after `btime`, so a stale record never qualifies.
///
/// **ABSENCE PROVES NOBODY STILL OWNS IT.** The same group can hold a live
/// launching shell (its leader) or a registrant whose cmdline merely failed to
/// corroborate; signalling either would end work somebody is running. Absence
/// alone is not enough either — a reused group loses its leader as easily as an
/// orphan does (`setsid sh -c 'server &'`) — so it takes both. A zombie leader
/// still has its `/proc` entry and reads as present.
///
/// It does not know who is asking: excluding the caller's own group is the
/// reaper's half (`reapable`). What it misses is safe: an orphan whose every
/// survivor was spawned after the last stamp is not signalled. `false` for a
/// pgid `exec` could not signal (unparseable, or not a positive `i32`), an
/// unparseable registrant, and wherever `/proc` cannot be read: a reap may only
/// proceed on proof.
///
/// Where there is no `/proc` to read a group's members from, none is ever proven
/// the orphan's and nothing is reaped. Only the read is under `cfg` (CLOUD-2509).
//MUTANT-SUITE crates/batten/tests/it/process_group.rs
pub(crate) fn group_orphaned(pgid: &str, registrant: &str, alive_at: u64) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Some((boot, ticks, pids)) = proc_table() else {
            return false;
        };
        let stats = pids.filter_map(|dir| std::fs::read_to_string(dir.join("stat")).ok());
        orphaned_in(stats, pgid, registrant, boot, ticks, alive_at)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (pgid, registrant, alive_at);
        false
    }
}

/// [`group_orphaned`], public so a suite can prove it over a REAL orphan.
///
/// The decision is [`orphaned_in`]'s and its cases pin it over tables they
/// write; what they cannot pin is that the live table is the one read. Only a
/// separate process can leave a group whose leader and registrant are gone, so
/// only a suite that spawns one can show this ever answers `true`.
#[must_use]
pub fn is_orphaned_group(pgid: &str, registrant: &str, alive_at: u64) -> bool {
    group_orphaned(pgid, registrant, alive_at)
}

/// [`group_orphaned`] over a given process table: the record's strings parsed
/// as `exec` would signal them, then [`proc_stat::orphaned`].
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn orphaned_in<S: AsRef<str>>(
    stats: impl IntoIterator<Item = S>,
    pgid: &str,
    registrant: &str,
    boot: u64,
    ticks: u64,
    alive_at: u64,
) -> bool {
    let Some(group) = pgid.parse::<i32>().ok().filter(|group| *group > 0) else {
        return false;
    };
    let Ok(registrant) = registrant.parse::<i32>() else {
        return false;
    };
    proc_stat::orphaned(
        stats,
        i64::from(group),
        i64::from(registrant),
        boot,
        ticks,
        alive_at,
    )
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
//MUTANT root-takes-any-process|s@^        .filter(\x7cprocess\x7c is_build(process, \&trees))$@        .filter(\x7c_\x7c true)@|the_earliest_build_is_the_root
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

/// A file's `(dev, ino)`, which names it across its hardlinks.
///
/// On Windows, volume serial and file index: the same pair, which `std` keeps
/// unstable there. Only each platform's read is under `cfg` (CLOUD-2509).
fn identity(path: &Path) -> Option<Kept> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).ok()?;
        Some(Kept::File {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(windows)]
    {
        let file = std::fs::File::open(path).ok()?;
        let info = winapi_util::file::information(&file).ok()?;
        Some(Kept::File {
            dev: info.volume_serial_number(),
            ino: info.file_index(),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        None
    }
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
    /// A scratch entry or the staged copy, taken whole: a live run reads it
    /// with no build lock held.
    whole: bool,
}

/// Every unit under `tree`, at any depth: every `.fingerprint` directory, nested
/// target triples and build trees included.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT scratch-unit-ranked|s@^        .filter(\x7cfingerprints\x7c !wholes.iter().any(\x7cwhole\x7c fingerprints.starts_with(whole)))$@        .filter(\x7c_\x7c true)@|a_build_inside_fresh_scratch_is_never_collected
fn units_in(tree: &Path, fingerprints: Vec<PathBuf>, wholes: &[PathBuf]) -> Vec<Unit> {
    let mut units = Vec::new();
    // SCRATCH IS ONE UNIT EACH, RANKED BY [`whole_units`]: a test suite builds
    // whole trees under `tmp/`, and ranking their units one by one reached past
    // the working set that keeps a running suite's fixture whole. Measured on
    // #1132, the session's hook collected a running case's aged fixture unit
    // and the case failed three runs in five. The staged copy is one unit for
    // the same reason.
    for fingerprints in fingerprints
        .into_iter()
        .filter(|fingerprints| !wholes.iter().any(|whole| fingerprints.starts_with(whole)))
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
                whole: false,
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
            whole: false,
        })
        .collect()
}

/// Does a live run read this unit with no build lock held: the test scratch it
/// writes, or an executable it may launch (a file with no extension, or `.exe`)?
/// Libraries, metadata and caches are read only by a compile, under the lock.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT run-root-ignores-executables|s@artifact.is_file() \&\& artifact.extension().is_none_or(\x7cext\x7c ext == "exe")@false@|a_test_binary_a_live_run_built_is_never_collected
fn read_by_a_run(unit: &Unit) -> bool {
    unit.whole
        || unit.artifacts.iter().any(|artifact| {
            artifact.is_file() && artifact.extension().is_none_or(|ext| ext == "exe")
        })
}

/// The name cargo's `CARGO_TARGET_TMPDIR` takes inside a build tree.
const SCRATCH: &str = "tmp";

/// The staged repository copy `batten mutate` keeps under the build root
/// (`lib.rs`'s `root.join("target").join("mutate")`): the engine's own path,
/// never a consumer's.
const STAGED: &str = "mutate";

/// The directories a pass takes whole rather than unit by unit (CLOUD-2286):
/// the `tmp/` of `tree` and of every build tree nested in it, outermost only,
/// and the staged copy.
///
/// MEASURED ON #1132, NEITHER WAS RANKED: `target/mutate` held 511 MB idle
/// since the day before and `target/replay/tmp` 555 MB, and neither carries a
/// `.fingerprint` of its own, so no pass could reach them while it removed the
/// dependencies of the profiles the next lap built. A build tree is a
/// fingerprint directory's grandparent — `replay` for `replay/debug` — and its
/// `tmp/` is the scratch cargo gave that build's suites.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT nested-scratch-unseen|s@^                .filter_map(\x7cfound\x7c Some(found.parent()?.parent()?.join(SCRATCH))),$@                .filter_map(\x7c_\x7c None::<PathBuf>),@|a_nested_build_trees_stale_scratch_is_collected
//MUTANT staged-copy-unranked|s@^    if staged.is_dir() {$@    if false \&\& staged.is_dir() {@|an_idle_staged_copy_goes_before_a_built_profiles_units
fn wholes_in(tree: &Path, fingerprints: &[PathBuf]) -> Vec<PathBuf> {
    let mut scratch: Vec<PathBuf> = std::iter::once(tree.join(SCRATCH))
        .chain(
            fingerprints
                .iter()
                .filter_map(|found| Some(found.parent()?.parent()?.join(SCRATCH))),
        )
        .filter(|dir| dir.is_dir())
        .collect();
    scratch.sort();
    scratch.dedup();
    let mut wholes: Vec<PathBuf> = scratch
        .iter()
        .filter(|dir| {
            !scratch
                .iter()
                .any(|outer| outer != *dir && dir.starts_with(outer))
        })
        .cloned()
        .collect();
    let staged = tree.join(STAGED);
    if staged.is_dir() {
        wholes.push(staged);
    }
    wholes
}

/// One unit per entry of each scratch directory, and the staged copy as one:
/// cargo's `CARGO_TARGET_TMPDIR`, which integration suites fill with fixtures
/// and nothing removes until the next run's setup — measured at 4.1GB on
/// #1132. No build lock covers either; the working set keeps a running suite's
/// fixtures, and a running sweep's staged copy, whole.
///
/// THE STAGED COPY IS DATED BY ITS NEWEST WRITE AT ANY DEPTH, because a sweep
/// writes it deep: each row corrupts and restores one source, and a shallow
/// read would date a running sweep's copy by the day it was first staged.
fn whole_units(tree: &Path, wholes: &[PathBuf]) -> Vec<Unit> {
    let mut units = Vec::new();
    for whole in wholes {
        if whole.file_name().is_some_and(|name| name == STAGED) {
            units.push(Unit {
                tree: tree.to_path_buf(),
                profile: whole.clone(),
                last_use: newest_write_within(whole),
                fingerprint: whole.clone(),
                artifacts: Vec::new(),
                whole: true,
            });
            continue;
        }
        let Ok(entries) = std::fs::read_dir(whole) else {
            continue;
        };
        units.extend(
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_symlink()))
                .map(|entry| Unit {
                    tree: tree.to_path_buf(),
                    // EACH ENTRY IS ITS OWN PROFILE: one fresh fixture does not
                    // shield every stale one beside it.
                    profile: entry.path(),
                    last_use: newest_write(&entry.path()),
                    fingerprint: entry.path(),
                    artifacts: Vec::new(),
                    whole: true,
                }),
        );
    }
    units
}

/// The newest mtime anywhere under `path`, never following a link.
fn newest_write_within(path: &Path) -> SystemTime {
    let mut newest = std::fs::symlink_metadata(path)
        .and_then(|meta| meta.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if let Ok(written) = meta.modified() {
                newest = newest.max(written);
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                stack.push(entry.path());
            }
        }
    }
    newest
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
//MUTANT rebuild-ranked-stale|s@^            let meta = entry.metadata().ok()?;$@            let meta = entry.metadata().ok().filter(\x7c_\x7c false)?;@|a_unit_just_rebuilt_is_not_least_recently_used
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

/// A file's link count and the bytes its removal frees once the count is one.
///
/// On Windows, the link count comes from the same file information [`identity`]
/// reads (`std` keeps it unstable there). Measured on #1132's `windows` job:
/// read as a constant 1, a hardlinked file counted as freed and the pass stopped
/// short. The handle is dropped before the caller removes the file, which
/// Windows refuses while one is open; a count that cannot be read is the old 1.
/// Only each platform's read is under `cfg` (CLOUD-2509).
fn allocation(path: &Path, meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let _ = path;
        (meta.nlink(), meta.blocks() * 512)
    }
    #[cfg(windows)]
    {
        let links = std::fs::File::open(path)
            .ok()
            .and_then(|file| winapi_util::file::information(&file).ok())
            .map_or(1, |info| info.number_of_links());
        (links, meta.len())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        (1, meta.len())
    }
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
    let dir = crate::durable::open_handle(tree).ok()?;
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
    crate::durable::open_handle(path)?.set_times(std::fs::FileTimes::new().set_accessed(modified))
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
#[must_use]
pub fn collect(request: &Request<'_>) -> Pass {
    let (pass, traced) = pass_of(request);
    if tracing() {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("{traced}\n").as_bytes());
    }
    pass
}

/// [`collect`]'s pass and its `disk-pass` trace line, composed whether or not
/// the trace is asked for, so a case reads the counts the trace reports.
//MUTANT-SUITE crates/batten/tests/it/prune_watch.rs
//MUTANT reachability-pass-skipped|s@^        let (units, bytes) = crate::prune::reclaim_superseded(tree, request.keep_generations);$@        let (units, bytes) = (0, 0);@|a_superseded_unit_goes_before_an_older_live_one
//MUTANT collects-past-max-free|s@^        if freed >= request.need_bytes \x7c\x7c past(request.deadline) {$@        if past(request.deadline) {@|collection_stops_at_max_free
//MUTANT held-tree-collected|s@^        let _building = match crate::prune::claim(\&unit.tree, \&unit.profile) {$@        let _building = match Ok::<(), PathBuf>(()) {@|a_tree_a_build_holds_is_never_collected
//MUTANT engine-unit-collected|s@^            .any(\x7cartifact\x7c is_kept(artifact, request.kept))$@            .any(\x7c_\x7c false)@|the_running_engine_is_never_collected
fn pass_of(request: &Request<'_>) -> (Pass, String) {
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
    // ONE WALK PER TREE: the fingerprint directories both name the nested
    // build trees whose scratch is taken whole and are the units themselves.
    let mut units = Vec::new();
    let mut scratch = Vec::new();
    for (tree, _) in &locks {
        let fingerprints = crate::prune::directories_named(tree, ".fingerprint");
        let wholes = wholes_in(tree, &fingerprints);
        scratch.extend(whole_units(tree, &wholes));
        units.extend(units_in(tree, fingerprints, &wholes));
    }
    let live = ranked(units, scratch);
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
    held.live = why.live;
    let done = Pass {
        freed_bytes: freed,
        removed,
        held,
    };
    (done, traced)
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

/// Block until each build lock among `held` has been free once, or `bound`
/// passes (CLOUD-2286). `true` when every one was: the build that held it
/// finished, so a second pass may reach what the first passed over.
///
/// THE WAIT IS THE LOCK ITSELF, NEVER A TIMER (CLOUD-1177): a thread takes
/// each `.cargo-lock` blocking, exactly as cargo would, and lets go at once;
/// the caller waits on that thread up to `bound`. A thread still blocked at the
/// bound is left to finish on its own, and it holds the lock for no longer
/// than taking it takes. A collector lock among `held` is another pass, not a
/// build, and is not waited on.
#[must_use]
pub fn await_builds(held: &[PathBuf], bound: std::time::Duration) -> bool {
    let builds: Vec<PathBuf> = held
        .iter()
        .filter(|lock| lock.file_name().is_some_and(|name| name == ".cargo-lock"))
        .cloned()
        .collect();
    if builds.is_empty() {
        return false;
    }
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for lock in &builds {
            if let Ok(file) = std::fs::File::open(lock) {
                let _ = file.lock();
            }
        }
        let _ = done.send(());
    });
    finished.recv_timeout(bound).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// CLOUD-2366: started at `1_700_009_876` (9876 s after boot at 100 Hz); a
    /// process began before only a second it began strictly before.
    #[test]
    fn a_stat_line_began_before_only_strictly_before() {
        let stat =
            "4243 (a) b) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(proc_stat::process_id(stat), Some(4243));
        assert_eq!(proc_stat::process_group(stat), Some(4242));
        let began_before = |at| proc_stat::began_before(stat, 1_700_000_000, 100, at);
        assert!(began_before(1_700_009_878));
        assert!(!began_before(1_700_009_877));
    }

    /// A `/proc/<pid>/stat` line for `pid` in `group`, begun `ticks` after boot.
    fn stat_line(pid: &str, group: u32, ticks: u64) -> String {
        format!(
            "{pid} (x) S 1 {group} {group} 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 {ticks} 1000 100"
        )
    }

    /// CLOUD-2366: the record's strings reach the predicate as `exec` would
    /// signal them. A synthetic orphan (group 42, registrant 43 gone, a member
    /// at second `1_700_000_001` before a stamp at `1_700_000_100`) is proven
    /// only through a positive group and a readable registrant.
    #[test]
    fn a_record_is_read_as_exec_would_signal_it() {
        let survivor = [stat_line("44", 42, 100)];
        let orphaned = |pgid, registrant| {
            super::orphaned_in(
                &survivor,
                pgid,
                registrant,
                1_700_000_000,
                100,
                1_700_000_100,
            )
        };
        assert!(orphaned("42", "43"));
        assert!(orphaned("+42", "43"), "the number exec would signal");
        assert!(!orphaned("42", "not-a-number"), "an unreadable registrant");
        assert!(!orphaned("42", ""), "a record with no pid");
        for nonsense in ["0", "-42", "not-a-number"] {
            assert!(!orphaned(nonsense, "43"), "{nonsense}");
        }
    }

    /// CLOUD-2509: a process began `since_boot` ticks after the boot second.
    /// Fails by: either sum subtracting, or the rate taken as a remainder.
    #[test]
    fn a_start_is_its_ticks_after_boot() {
        let at = |millis| SystemTime::UNIX_EPOCH + Duration::from_millis(millis);
        assert_eq!(proc_stat::started(100, 250, 100), at(102_500));
        assert_eq!(proc_stat::started(0, 0, 100), at(0));
    }

    /// CLOUD-2366: wherever `/proc` is read live, a group its registrant still
    /// runs in is never the orphan.
    #[test]
    fn a_group_its_registrant_runs_in_is_never_orphaned() {
        let me = std::process::id().to_string();
        let own = crate::task::process_group(&me);
        assert!(!super::group_orphaned(&own, &me, u64::MAX));
    }

    /// CLOUD-2366: at 100 Hz from boot `1_700_000_000`, a member at 100 ticks
    /// began at second `1_700_000_001`, before a stamp at `1_700_000_100`. The
    /// group (42) is the orphan only with its leader and registrant (43) gone.
    #[test]
    fn an_orphan_needs_its_leader_and_registrant_gone() {
        let line = |pid: u32, group: u32, ticks: u64| stat_line(&pid.to_string(), group, ticks);
        let orphaned = |stats: &[String]| {
            proc_stat::orphaned(stats, 42, 43, 1_700_000_000, 100, 1_700_000_100)
        };
        let survivor = line(44, 42, 100);
        assert!(orphaned(std::slice::from_ref(&survivor)));
        assert!(
            !orphaned(&[survivor.clone(), line(42, 42, 50)]),
            "its leader lives"
        );
        assert!(
            !orphaned(&[survivor, line(43, 42, 50)]),
            "its registrant lives"
        );
        assert!(
            !orphaned(&[line(44, 42, 10_000)]),
            "every member began after the stamp"
        );
        assert!(!orphaned(&[line(44, 41, 100)]), "another group's member");
        let unread = stat_line("x", 42, 100);
        assert!(
            !orphaned(&[line(44, 42, 100), unread]),
            "a member whose pid cannot be read"
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

    /// A fresh directory for one case under the crate's shared scratch root,
    /// which a later run reaps once this process is gone.
    fn scratch(case: &str) -> PathBuf {
        let dir = crate::scratch::scratch(&format!("collect-{case}"));
        assert!(dir.is_dir(), "scratch");
        dir
    }

    /// Date a file: read `read` and written `written` seconds ago.
    fn aged(path: &Path, read: u64, written: u64) {
        let now = SystemTime::now();
        crate::durable::open_handle(path)
            .expect("open the file to date")
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(now - Duration::from_secs(read))
                    .set_modified(now - Duration::from_secs(written)),
            )
            .expect("date the file");
    }

    /// One cargo unit in `profile`: a fingerprint file read `age` seconds ago and
    /// a `deps/<file>` artifact of `bytes` bytes, whose path it returns.
    fn unit(profile: &Path, name: &str, hash: &str, age: u64, file: &str, bytes: usize) -> PathBuf {
        let fingerprint = profile.join(".fingerprint").join(format!("{name}-{hash}"));
        std::fs::create_dir_all(&fingerprint).expect("create the fingerprint");
        let stamp = fingerprint.join(format!("lib-{name}"));
        std::fs::write(&stamp, b"fingerprint").expect("write the fingerprint");
        aged(&stamp, age, age + 10);
        let deps = profile.join("deps");
        std::fs::create_dir_all(&deps).expect("create deps");
        let artifact = deps.join(file);
        std::fs::write(&artifact, vec![7_u8; bytes]).expect("write the artifact");
        artifact
    }

    /// The bytes the one name of `path` holds on disk.
    fn allocated(path: &Path) -> u64 {
        let meta = std::fs::symlink_metadata(path).expect("read the file");
        super::allocation(path, &meta).1
    }

    /// A request over `trees` asking for `need` bytes, with no deadline and no
    /// live build.
    fn ask<'a>(trees: &'a [PathBuf], kept: &'a [Kept], need: u64) -> super::Request<'a> {
        super::Request {
            trees,
            keep_generations: 2,
            kept,
            need_bytes: need,
            deadline: None,
            wait: false,
            live_since: None,
        }
    }

    /// A `[prune]` table rooted at `target`, with the band `band`.
    fn band(band: Option<(u64, u64)>) -> crate::prune::Prune {
        crate::prune::Prune {
            root: "target".to_owned(),
            keep: 2,
            warm: None,
            cold: None,
            regrowable: None,
            min_free_mb: band.map(|(min, _)| min),
            max_free_mb: band.map(|(_, max)| max),
        }
    }

    /// Fails by: a lap-record line dropped, blanked, or spelled otherwise.
    #[test]
    fn a_collection_records_every_line() {
        let done = super::Collected {
            freed_bytes: 3 * 1024 * 1024 + 5,
            units: 4,
            free_after_mb: 900,
            wall_ms: 12,
            held: super::Held {
                locks: vec![PathBuf::from("/t/debug/.cargo-lock")],
                live: true,
            },
        };
        assert_eq!(
            done.lines(),
            vec![
                "disk-collected 3 4 900".to_owned(),
                "disk-unlink-ms 12".to_owned(),
                format!("disk-held {}", Path::new("/t/debug/.cargo-lock").display()),
                "disk-live".to_owned(),
            ]
        );
    }

    /// Fails by: a trace line blanked, or a value other than exactly `1` read as
    /// asking for it.
    #[test]
    fn a_trace_is_asked_for_by_exactly_one() {
        assert_eq!(super::trace_line("disk-pass", &[1, 22]), "disk-pass 1 22");
        assert_eq!(super::trace_line("disk-sample", &[]), "disk-sample");
        let asks = |value: &str| super::asks_trace(Some(std::ffi::OsStr::new(value)));
        assert!(asks("1"));
        assert!(!asks("0"));
        assert!(!asks("11"));
        assert!(!super::asks_trace(None));
        assert_eq!(
            super::tracing(),
            super::asks_trace(std::env::var_os("BATTEN_DISK_TRACE").as_deref()),
            "the variable is the one input"
        );
    }

    /// Fails by: a process with a path, or with no name, kept by name.
    #[test]
    fn only_a_pathless_named_process_is_kept_by_name() {
        let process = |exe: Option<&str>, name: &str| Process {
            exe: exe.map(PathBuf::from),
            name: name.to_owned(),
            started: at(1),
        };
        let table = vec![
            process(None, "cargo-nextest"),
            process(Some("/usr/bin/rustc"), "rustc"),
            process(None, ""),
        ];
        assert_eq!(
            super::kept_by_name(table).collect::<Vec<_>>(),
            vec![Kept::Named("cargo-nextest".to_owned())]
        );
    }

    /// CLOUD-2366: group 0 is no group `exec` signals, even with a member in it.
    /// Fails by: a pgid of `0` admitted.
    #[test]
    fn a_record_of_group_zero_is_never_orphaned() {
        let member = [stat_line("44", 0, 100)];
        assert!(proc_stat::orphaned(
            &member,
            0,
            43,
            1_700_000_000,
            100,
            1_700_000_100
        ));
        assert!(!super::orphaned_in(
            &member,
            "0",
            "43",
            1_700_000_000,
            100,
            1_700_000_100
        ));
    }

    /// Fails by: an existing file given no identity, or a file kept that only
    /// shares a directory with the kept one.
    #[test]
    fn a_kept_file_is_kept_by_every_name_and_no_other_file() {
        let dir = scratch("identity");
        let (engine, other, alias) = (dir.join("engine"), dir.join("other"), dir.join("alias"));
        std::fs::write(&engine, b"engine").expect("write");
        std::fs::write(&other, b"other").expect("write");
        std::fs::hard_link(&engine, &alias).expect("link");
        let kept = super::kept(&[engine.clone(), dir.join("absent")]);
        let identified = cfg!(any(unix, windows));
        assert_eq!(kept.len(), usize::from(identified), "{kept:?}");
        assert_eq!(super::is_kept(&engine, &kept), identified);
        assert_eq!(super::is_kept(&alias, &kept), identified);
        assert!(!super::is_kept(&other, &kept));
    }

    /// Fails by: a link count or allocation read as a constant, or a removal
    /// counted as freeing nothing, one byte, or a name that is not the last.
    #[test]
    fn a_removal_counts_a_files_blocks_once_its_last_name_goes() {
        let dir = scratch("remove-counted");
        let file = dir.join("file");
        std::fs::write(&file, vec![7_u8; 8192]).expect("write");
        let meta = std::fs::symlink_metadata(&file).expect("stat");
        let (links, bytes) = super::allocation(&file, &meta);
        assert_eq!(links, 1);
        assert!(bytes >= 8192, "{bytes}");
        let alias = dir.join("alias");
        std::fs::hard_link(&file, &alias).expect("link");
        let meta = std::fs::symlink_metadata(&file).expect("stat");
        assert_eq!(super::allocation(&file, &meta).0, 2);
        assert_eq!(
            super::remove_counted(&alias),
            0,
            "a name that is not the last"
        );
        assert!(!alias.exists());
        assert_eq!(super::remove_counted(&file), bytes, "the last name");
        assert!(!file.exists());
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("inner")).expect("mkdir");
        std::fs::write(tree.join("inner/one"), vec![7_u8; 8192]).expect("write");
        let one = allocated(&tree.join("inner/one"));
        assert_eq!(super::remove_counted(&tree), one, "a tree is its files");
        assert!(!tree.exists());
        assert_eq!(super::remove_counted(&tree), 0, "nothing left to remove");
    }

    /// Fails by: a profile's units dropped, or only the units under a whole
    /// ranked one by one.
    #[test]
    fn a_profiles_units_are_ranked_unless_taken_whole() {
        let tree = scratch("units-in").join("target");
        let profile = tree.join("debug");
        let artifact = unit(
            &profile,
            "alpha",
            "1111111111111111",
            60,
            "libalpha-1111111111111111.rlib",
            8,
        );
        let fingerprints = vec![profile.join(".fingerprint")];
        let units = super::units_in(&tree, fingerprints.clone(), &[]);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].artifacts, vec![artifact]);
        assert_eq!(
            units[0].fingerprint,
            profile.join(".fingerprint/alpha-1111111111111111")
        );
        assert!(
            super::units_in(&tree, fingerprints, std::slice::from_ref(&tree)).is_empty(),
            "a fingerprint under a whole is not its own unit"
        );
    }

    /// Fails by: a whole named where the tree has no scratch and no staged copy.
    #[test]
    fn a_tree_with_no_scratch_has_no_wholes() {
        let tree = scratch("wholes-in").join("target");
        std::fs::create_dir_all(&tree).expect("mkdir");
        assert!(super::wholes_in(&tree, &[]).is_empty());
        std::fs::create_dir_all(tree.join("tmp")).expect("mkdir");
        assert_eq!(super::wholes_in(&tree, &[]), vec![tree.join("tmp")]);
    }

    /// Fails by: a wait reported finished with no build lock to wait on.
    #[test]
    fn only_a_build_lock_is_awaited() {
        assert!(!super::await_builds(&[], Duration::ZERO));
        let dir = scratch("await-builds");
        let collector = dir.join("target");
        std::fs::create_dir_all(&collector).expect("mkdir");
        assert!(!super::await_builds(&[collector], Duration::ZERO));
        let free = dir.join(".cargo-lock");
        std::fs::write(&free, b"").expect("write");
        assert!(super::await_builds(&[free], Duration::from_secs(5)));
    }

    /// Fails by: a pass's counts, freed bytes or trace misreported, or either
    /// stop (bytes freed) read the wrong way round. Superseded generation, the
    /// oldest live unit, a kept unit and a held profile, asked for everything.
    #[test]
    fn a_pass_counts_what_it_took_and_what_it_passed_over() {
        let tree = scratch("pass-counts").join("target");
        let debug = tree.join("debug");
        let deps = debug.join("deps");
        std::fs::create_dir_all(&deps).expect("mkdir");
        // An artifact no fingerprint names: the superseded pass's.
        let unreachable = deps.join("libgone-aaaaaaaaaaaa.rlib");
        std::fs::write(&unreachable, b"artifact").expect("write");
        aged(&unreachable, 60, 60);
        let old = unit(
            &debug,
            "old",
            "1111111111111111",
            7200,
            "libold-1111111111111111.rlib",
            4096,
        );
        let engine = unit(
            &debug,
            "engine",
            "2222222222222222",
            3600,
            "libengine-2222222222222222.rlib",
            4096,
        );
        let held = tree.join("held");
        let busy = unit(
            &held,
            "busy",
            "3333333333333333",
            1800,
            "libbusy-3333333333333333.rlib",
            4096,
        );
        let lock = std::fs::File::create(held.join(".cargo-lock")).expect("create the lock");
        lock.lock().expect("hold the build lock");
        let stamp = debug.join(".fingerprint/old-1111111111111111/lib-old");
        let expected = 8 + allocated(&stamp) + allocated(&old);
        let kept = super::kept(std::slice::from_ref(&engine));
        let trees = [tree.clone()];
        let (pass, traced) = super::pass_of(&ask(&trees, &kept, u64::MAX));
        drop(lock);
        assert!(!unreachable.exists(), "superseded");
        assert!(!old.exists(), "the oldest live unit");
        assert!(busy.exists(), "held");
        let kept_count = if cfg!(any(unix, windows)) {
            assert!(engine.exists(), "kept");
            1
        } else {
            0
        };
        assert_eq!(pass.removed, 3 - kept_count);
        assert_eq!(
            pass.held,
            super::Held {
                locks: vec![held.join(".cargo-lock")],
                live: false,
            }
        );
        if kept_count == 1 {
            assert_eq!(pass.freed_bytes, expected);
        }
        assert_eq!(
            traced,
            format!(
                "disk-pass 1 3 1 {kept_count} 0 {} {}",
                pass.removed,
                u64::MAX / (1024 * 1024)
            )
        );

        // Asked for nothing, a pass takes nothing, superseded or live.
        let tree = scratch("pass-nothing").join("target");
        let deps = tree.join("debug/deps");
        std::fs::create_dir_all(&deps).expect("mkdir");
        let unreachable = deps.join("libgone-aaaaaaaaaaaa.rlib");
        std::fs::write(&unreachable, b"artifact").expect("write");
        aged(&unreachable, 60, 60);
        let idle = unit(
            &tree.join("debug"),
            "idle",
            "4444444444444444",
            7200,
            "libidle-4444444444444444.rlib",
            4096,
        );
        let trees = [tree.clone()];
        let (pass, _) = super::pass_of(&ask(&trees, &[], 0));
        assert_eq!(pass.removed, 0);
        assert!(unreachable.exists());
        assert!(idle.exists());
    }

    /// Fails by: the deadline read the wrong way round. Time is the input here:
    /// a deadline an hour off stops nothing, one already reached stops all.
    #[test]
    fn a_pass_stops_at_a_reached_deadline_only() {
        fn removed(case: &str, ahead: Duration) -> usize {
            let tree = scratch(case).join("target");
            unit(
                &tree.join("debug"),
                "due",
                "5555555555555555",
                3600,
                "libdue-5555555555555555.rlib",
                4096,
            );
            let trees = [tree];
            let mut request = ask(&trees, &[], u64::MAX);
            request.deadline = Some(std::time::Instant::now() + ahead);
            super::pass_of(&request).0.removed
        }
        assert_eq!(removed("deadline-ahead", Duration::from_secs(3600)), 1);
        assert_eq!(removed("deadline-reached", Duration::ZERO), 0);
    }

    /// Fails by: a held unit a live build used not reported as the live build
    /// stopping the pass, or one it did not use reported so.
    #[test]
    fn a_held_unit_reports_a_live_build_only_when_one_used_it() {
        fn live(case: &str, since: fn(SystemTime) -> SystemTime) -> bool {
            let tree = scratch(case).join("target");
            let profile = tree.join("debug");
            unit(
                &profile,
                "busy",
                "6666666666666666",
                1800,
                "libbusy-6666666666666666.rlib",
                4096,
            );
            let lock = std::fs::File::create(profile.join(".cargo-lock")).expect("create");
            lock.lock().expect("hold the build lock");
            let trees = [tree];
            let mut request = ask(&trees, &[], u64::MAX);
            request.live_since = Some(since(SystemTime::now()));
            let (pass, _) = super::pass_of(&request);
            drop(lock);
            assert_eq!(pass.removed, 0, "{case}: held");
            pass.held.live
        }
        assert!(live("held-used", |at| at - Duration::from_secs(7200)));
        assert!(!live("held-unused", |at| at + Duration::from_secs(3600)));
    }

    /// Fails by: an executable a live run may launch collected, or one no live
    /// run used kept.
    #[test]
    fn an_executable_a_live_run_used_is_kept_and_one_it_did_not_is_not() {
        fn removed(case: &str, since: fn(SystemTime) -> SystemTime) -> (usize, bool) {
            let tree = scratch(case).join("target");
            unit(
                &tree.join("debug"),
                "runner",
                "7777777777777777",
                3600,
                "runner-7777777777777777",
                4096,
            );
            let trees = [tree];
            let mut request = ask(&trees, &[], u64::MAX);
            request.live_since = Some(since(SystemTime::now()));
            let (pass, _) = super::pass_of(&request);
            (pass.removed, pass.held.live)
        }
        assert_eq!(
            removed("run-used", |at| at - Duration::from_secs(7200)),
            (0, true)
        );
        assert_eq!(
            removed("run-unused", |at| at + Duration::from_secs(3600)),
            (1, false)
        );
    }

    /// Fails by: the checkout's build tree not ranked, or a tree named that is
    /// not there.
    #[test]
    fn the_trees_are_the_build_roots_that_exist() {
        let repo = scratch("trees");
        assert!(super::trees(&repo, &band(None)).is_empty());
        std::fs::create_dir_all(repo.join("target")).expect("mkdir");
        assert_eq!(super::trees(&repo, &band(None)), vec![repo.join("target")]);
    }

    /// Fails by: a reading at the minimum collected, or one below it not.
    #[test]
    fn a_collection_runs_only_below_the_minimum() {
        let repo = scratch("pressed");
        let config = band(Some((10, 20)));
        let pressed = |free: u64| {
            super::collect_if_pressed(&repo, &config, &[], &mut || Ok(free), None, false)
        };
        assert!(pressed(10).is_none(), "at the minimum");
        assert!(pressed(9).is_some(), "below it");
    }

    /// Fails by: the bytes to free misread from the band's MiB. 1 MiB is asked
    /// for, and two 600 KiB units are needed to free it.
    #[test]
    fn a_collection_frees_toward_max_in_mebibytes() {
        let repo = scratch("toward-max");
        let profile = repo.join("target/debug");
        let older = unit(
            &profile,
            "older",
            "8888888888888888",
            7200,
            "libolder-8888888888888888.rlib",
            600 * 1024,
        );
        let newer = unit(
            &profile,
            "newer",
            "9999999999999999",
            3600,
            "libnewer-9999999999999999.rlib",
            600 * 1024,
        );
        let done = super::collect_toward_max(
            &repo,
            &band(Some((0, 1))),
            &[],
            0,
            &mut || Ok(5),
            None,
            false,
        )
        .expect("a declared band collects");
        assert_eq!(done.units, 2);
        assert_eq!(done.free_after_mb, 5);
        assert!(!older.exists());
        assert!(!newer.exists());
    }
}
