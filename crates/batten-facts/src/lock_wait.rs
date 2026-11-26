//! The crate's one way to wait for an advisory file lock (CLOUD-2789).
//!
//! # Why a blocking `flock` is refused
//!
//! A blocked `flock` has no way back: nothing short of the holder's release
//! ends it. `step run` deadlocked on exactly that, waiting on a second handle to
//! a tree its own process already held, and printed its result and never
//! exited. So `clippy.toml` denies `File::lock`, `File::lock_shared` and every
//! lock crate's blocking equivalent, and every lock goes through [`acquire`].
//!
//! # What [`acquire`] waits on, and why it is not a clock
//!
//! `try_lock` first. When the lock is held, the wait is on EVENTS, never an
//! interval:
//!
//! - **The holder's release.** A `flock` is released when its holder's last
//!   descriptor closes, a dead holder's included, and a close of the lock file
//!   is an `IN_CLOSE_*` inotify event on it. The watch is added BEFORE the
//!   second `try_lock`, so a release between the first attempt and the watch is
//!   seen by the second attempt rather than missed. Any wake is only a reason to
//!   try again: a close by a process that did not hold the lock is a spurious
//!   wake and costs one `try_lock`.
//! - **A [`Stop`].** A caller that must be able to give up passes one; raising
//!   it from any thread wakes the wait at once through an `eventfd`.
//! - **Re-entry.** A lock this THREAD already holds through [`acquire`] is
//!   refused as [`Taken::Reentrant`] instead of waited on, because the holder is
//!   the waiter and the release can never come — the `step run` deadlock.
//!
//! # Release: a close is not one, so [`Held`] releases and then announces
//!
//! A close does not order the event after the release. The kernel's last put
//! of a description notifies the close (`fsnotify_close`) BEFORE it drops the
//! flock (`locks_remove_file`), so a waiter woken in between finds the lock
//! still held, drains the event, and parks with no event left to come — a hang
//! that load makes likely (`two_concurrent_consumes_resolve_to_exactly_one_winner`
//! at 1200 s). And a concurrent fork's child shares the description until its
//! exec, so the holder's own close may release nothing at all. So [`Held`]'s
//! drop unlocks explicitly and then opens and closes the file once more: an
//! `IN_CLOSE_NOWRITE` that follows the release. A holder outside this module
//! (cargo, whose lock files the collector waits on) only closes and keeps the
//! kernel's order, so the batten binary, which installs a spawner ([`install`]),
//! never waits on close events: on Linux too it waits through a helper blocked
//! in the kernel's own `flock`, which no release escapes. Close events are the
//! wait only where no spawner is installed, a library or a test harness.
//!
//! # Off Linux: a helper process does the blocking
//!
//! No other platform reports a close that safe code can wait on: kqueue's
//! `NOTE_CLOSE` is FreeBSD's, not macOS's; Windows' overlapped `LockFileEx` is
//! raw FFI under `unsafe_code = "forbid"`; and a signal cannot interrupt a
//! blocked `flock` on a thread, because `signal-hook` installs every handler
//! with `SA_RESTART`. So the blocking call moves to a process the waiter can
//! end ([`wait_with_helper`]): this binary re-entered as `batten __lock-wait
//! <mode> <path>` ([`helped`]), started by the spawner the binary installs
//! ([`install`], `exec`'s placed spawn), blocks on its OWN descriptor and exits 0 the
//! moment it holds the lock, which releases it, and the waiter, woken by that
//! exit, takes `try_lock` again. Losing that race to a third process spawns
//! another helper; nothing waits on a clock.
//!
//! The helper ends on its STDIN closing, read on a thread of its own, and the
//! waiter holds the only write end: [`Stop::raise`] drops it, and so does every
//! return or unwind of the waiter, and so does the waiter's own death. Each
//! helper is reaped before the wait returns, so none outlives its caller.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, TryLockError};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Whether the lock excludes every other holder or only exclusive ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One holder at a time.
    Exclusive,
    /// Any number of shared holders, and no exclusive one.
    Shared,
}

/// What [`acquire`] came back with.
#[derive(Debug)]
pub enum Taken {
    /// The lock is held until the guard drops.
    Held(Held),
    /// The [`Stop`] was raised before the lock came free.
    Stopped,
    /// This THREAD already holds the lock in a conflicting mode, so waiting
    /// would wait on itself.
    Reentrant,
}

/// A held lock: the descriptor that holds it, released when this drops.
#[derive(Debug)]
pub struct Held {
    file: File,
    hold: Option<Hold>,
}

impl Held {
    /// The locked file.
    #[must_use]
    pub const fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // Released HERE, before any close, and then announced: the close alone
        // is not a release a waiter can rely on (module docs, "release").
        if self.file.unlock().is_ok() {
            announce_release(&self.file);
        }
        if let Some(hold) = self.hold {
            release(hold);
        }
    }
}

/// Raise an `IN_CLOSE_NOWRITE` on `file`'s inode AFTER its lock was released,
/// by opening and closing it once more: the event every waiter watches for,
/// now ordered after the release instead of before it.
#[cfg(target_os = "linux")]
fn announce_release(file: &File) {
    use std::os::fd::AsRawFd as _;
    // A failure leaves a waiter to the holder's own close, as before.
    drop(File::open(format!("/proc/self/fd/{}", file.as_raw_fd())));
}

/// Off Linux a waiter's helper blocks in the kernel, so nothing watches for a
/// close and the release needs no announcement.
#[cfg(not(target_os = "linux"))]
const fn announce_release(_: &File) {}

/// A stop any thread can raise to end a wait in [`acquire`].
#[derive(Debug)]
pub struct Stop {
    raised: AtomicBool,
    #[cfg(target_os = "linux")]
    wake: std::os::fd::OwnedFd,
    /// The stdin of each helper waiting on this stop's behalf, by its id:
    /// dropping one ends that helper ([`wait_with_helper`]).
    helpers: Mutex<HashMap<u64, std::process::ChildStdin>>,
    next: AtomicU64,
}

impl Stop {
    /// A stop not yet raised.
    ///
    /// # Errors
    ///
    /// When the wake descriptor cannot be created.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            raised: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            wake: rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?,
            helpers: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
        })
    }

    /// Raise it: every wait on it ends, now and later.
    pub fn raise(&self) {
        self.raised.store(true, Ordering::SeqCst);
        #[cfg(target_os = "linux")]
        {
            // Never read back, so it stays readable for every waiter. A full
            // counter is still readable, which is all a waiter asks.
            let _ = rustix::io::write(&self.wake, &1_u64.to_ne_bytes());
        }
        // Every helper waiting for this stop ends on its stdin closing.
        let ending: Vec<_> = self
            .helpers
            .lock()
            .map(|mut helpers| helpers.drain().collect())
            .unwrap_or_default();
        drop(ending);
    }

    /// Hold `stdin` for a helper until the stop or its release, returning the
    /// id to release it by; already raised, it is dropped at once.
    fn adopt(&self, stdin: std::process::ChildStdin) -> u64 {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut helpers) = self.helpers.lock() {
            helpers.insert(id, stdin);
        }
        // RAISED BETWEEN THE CHECK AND THE ADOPTION: the drain above ran
        // before this insert, so end it here instead.
        if self.is_raised()
            && let Ok(mut helpers) = self.helpers.lock()
        {
            helpers.remove(&id);
        }
        id
    }

    /// Drop the helper `id`'s stdin, ending it if it still runs.
    fn release(&self, id: u64) {
        let stdin = self
            .helpers
            .lock()
            .ok()
            .and_then(|mut helpers| helpers.remove(&id));
        drop(stdin);
    }

    /// Whether it was raised.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        self.raised.load(Ordering::SeqCst)
    }
}

/// A file's identity, so two handles to one file are one lock.
type Key = (u64, u64);

/// One registered hold: which file, which thread took it, in which mode.
#[derive(Debug, Clone, Copy)]
struct Hold {
    key: Key,
    thread: std::thread::ThreadId,
    mode: Mode,
}

/// The locks this process holds through [`acquire`], each with the threads
/// that hold it and their modes.
///
/// RE-ENTRY IS PER THREAD. The deadlock this refuses is a thread waiting on a
/// hold it took itself, which nothing can ever release. Another thread of the
/// same process is a holder like any other process: its own descriptor, its own
/// `flock`, and a release it can see, so it waits rather than being refused.
static HELD: Mutex<Option<Registry>> = Mutex::new(None);

/// Each locked file's holders in this process: the thread and its mode.
type Registry = HashMap<Key, Vec<(std::thread::ThreadId, Mode)>>;

/// Register `key` as held in `mode` by this thread, or `None` when this thread
/// already holds it in a conflicting mode.
fn register(key: Key, mode: Mode) -> Option<Hold> {
    let thread = std::thread::current().id();
    let hold = Hold { key, thread, mode };
    let Ok(mut registry) = HELD.lock() else {
        return Some(hold);
    };
    let holders = registry
        .get_or_insert_with(HashMap::new)
        .entry(key)
        .or_default();
    let conflicts = holders.iter().any(|(holder, theirs)| {
        *holder == thread && (*theirs == Mode::Exclusive || mode == Mode::Exclusive)
    });
    if conflicts {
        return None;
    }
    holders.push((thread, mode));
    Some(hold)
}

/// Drop `hold`, wherever its guard ended up.
fn release(gone: Hold) {
    let Ok(mut registry) = HELD.lock() else {
        return;
    };
    let Some(registry) = registry.as_mut() else {
        return;
    };
    if let Some(holders) = registry.get_mut(&gone.key) {
        if let Some(at) = holders
            .iter()
            .position(|entry| *entry == (gone.thread, gone.mode))
        {
            holders.swap_remove(at);
        }
        if holders.is_empty() {
            registry.remove(&gone.key);
        }
    }
}

/// `file`'s identity, or `None` where the platform has none to read.
fn key_of(file: &File) -> std::io::Result<Option<Key>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta = file.metadata()?;
        Ok(Some((meta.dev(), meta.ino())))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(None)
    }
}

/// One attempt: `Ok(true)` taken, `Ok(false)` held by another.
fn attempt(file: &File, mode: Mode) -> std::io::Result<bool> {
    let tried = match mode {
        Mode::Exclusive => file.try_lock(),
        Mode::Shared => file.try_lock_shared(),
    };
    match tried {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

/// Lock `file`, opened at `path`, in `mode`: at once when it is free, else
/// when its holder releases it, ending early on `stop` (see the module docs).
///
/// # Errors
///
/// When the lock call itself fails (not contention), or the wait cannot be
/// set up: an unreadable identity, or a path inotify cannot watch.
pub fn acquire(file: File, path: &Path, mode: Mode, stop: Option<&Stop>) -> std::io::Result<Taken> {
    acquire_announced(file, path, mode, stop, &mut || {})
}

/// [`acquire`], calling `parked` each time the wait is about to park: where a
/// caller announces that it waits (only contention produces the call), and the
/// event a case raises its stop or releases its holder on, so a wake is shown
/// to come from the wait rather than from a race the waiter never lost.
///
/// # Errors
///
/// As [`acquire`].
pub fn acquire_announced(
    file: File,
    path: &Path,
    mode: Mode,
    stop: Option<&Stop>,
    parked: &mut dyn FnMut(),
) -> std::io::Result<Taken> {
    let registered = match key_of(&file)? {
        Some(key) => match register(key, mode) {
            Some(registered) => Some(registered),
            None => return Ok(Taken::Reentrant),
        },
        None => None,
    };
    // From here an early return releases the registration through the guard.
    let guard = Held {
        file,
        hold: registered,
    };
    if attempt(&guard.file, mode)? {
        return Ok(Taken::Held(guard));
    }
    if wait(&guard.file, path, mode, stop, parked)? {
        Ok(Taken::Held(guard))
    } else {
        Ok(Taken::Stopped)
    }
}

/// One attempt and no wait: `Some` when `file` was free, `None` when another
/// holds it — or this thread does, which a waiter would wait on itself for.
/// For a caller with a per-call budget, where losing a race is an answer.
///
/// # Errors
///
/// When the identity cannot be read or the lock call itself fails.
pub fn try_acquire(file: File, mode: Mode) -> std::io::Result<Option<Held>> {
    let registered = match key_of(&file)? {
        Some(key) => match register(key, mode) {
            Some(registered) => Some(registered),
            None => return Ok(None),
        },
        None => None,
    };
    let guard = Held {
        file,
        hold: registered,
    };
    Ok(attempt(&guard.file, mode)?.then_some(guard))
}

/// Wait for the lock, `true` once taken, `false` on the stop. ONE function on
/// every target, so a Linux run judges the decision every platform makes; only
/// the close-event wait, which exists only on Linux, is behind `cfg`.
fn wait(
    file: &File,
    path: &Path,
    mode: Mode,
    stop: Option<&Stop>,
    parked: &mut dyn FnMut(),
) -> std::io::Result<bool> {
    // THE BINARY WAITS IN THE KERNEL. A close event is not a release (module
    // docs, "release"), and a holder that is not a `Held` — cargo, to the
    // collector's waits on its lock files — never announces one, so its waiter
    // can miss the release and park for good. A helper blocked in `flock` sees
    // every release. Only a process with no spawner (a library, a test harness,
    // whose holders are its own `Held`s) waits on close events, and only on
    // Linux: elsewhere there is none to wait on, so it is the named refusal.
    match installed() {
        Ok(spawn) => wait_with_helper(file, path, mode, stop, &spawn, &mut |_| parked()),
        #[cfg(target_os = "linux")]
        Err(_) => wait_on_close(file, path, mode, stop, parked),
        #[cfg(not(target_os = "linux"))]
        Err(none) => Err(none),
    }
}

/// [`wait`] with no spawner on Linux: on the holder's close and the stop.
#[cfg(target_os = "linux")]
fn wait_on_close(
    file: &File,
    path: &Path,
    mode: Mode,
    stop: Option<&Stop>,
    parked: &mut dyn FnMut(),
) -> std::io::Result<bool> {
    use rustix::event::{PollFd, PollFlags};
    use rustix::fs::inotify;

    let watch = inotify::init(inotify::CreateFlags::CLOEXEC)?;
    inotify::add_watch(
        &watch,
        path,
        inotify::WatchFlags::CLOSE_WRITE
            | inotify::WatchFlags::CLOSE_NOWRITE
            | inotify::WatchFlags::DELETE_SELF
            | inotify::WatchFlags::MOVE_SELF,
    )?;
    let mut events = [0_u8; 4096];
    loop {
        // AFTER the watch is in place, so a release before it is seen here.
        if attempt(file, mode)? {
            return Ok(true);
        }
        if stop.is_some_and(Stop::is_raised) {
            return Ok(false);
        }
        let mut fds = vec![PollFd::new(&watch, PollFlags::IN)];
        if let Some(stop) = stop {
            fds.push(PollFd::new(&stop.wake, PollFlags::IN));
        }
        parked();
        match rustix::event::poll(&mut fds, None) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        let released = fds[0].revents().contains(PollFlags::IN);
        if fds
            .get(1)
            .is_some_and(|fd| fd.revents().contains(PollFlags::IN))
        {
            return Ok(false);
        }
        if released {
            // Drained so the next poll waits for the next close, not this one.
            rustix::io::read(&watch, &mut events)?;
        }
    }
}

/// The argv marker a helper is re-entered on: `batten __lock-wait <mode> <path>`.
pub const HELPER_ARG: &str = "__lock-wait";

impl Mode {
    /// The helper argv's spelling of the mode.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Shared => "shared",
        }
    }
}

/// What starts a helper: given the lock's path and the waiter's mode, a
/// running `batten __lock-wait <mode> <path>` with its stdin piped.
///
/// THIS MODULE SPAWNS NOTHING. The binary installs the spawner at startup
/// ([`install`]) and `exec`, the crate's placed spawn boundary, is what it
/// calls, so the spawn census places it where every other spawn is placed and
/// this module stays a leaf.
pub type Spawner = fn(&Path, Mode) -> std::io::Result<std::process::Child>;

/// The spawner this process waits through, set once by the binary.
static SPAWNER: std::sync::OnceLock<Spawner> = std::sync::OnceLock::new();

/// Install the process's helper spawner. A second install is refused: the
/// spawner is a property of the binary, not of a caller.
///
/// # Errors
///
/// When a spawner was already installed.
pub fn install(spawner: Spawner) -> std::io::Result<()> {
    install_into(&SPAWNER, spawner)
}

/// [`install`] over `slot`.
fn install_into(slot: &std::sync::OnceLock<Spawner>, spawner: Spawner) -> std::io::Result<()> {
    slot.set(spawner).map_err(|_| {
        std::io::Error::other("lock_wait: a helper spawner is already installed in this process")
    })
}

/// The installed spawner, or a NAMED refusal where none was: a library or a
/// test harness, which is not batten and has no helper entry, so it must never
/// spawn itself in batten's place.
fn installed() -> std::io::Result<Spawner> {
    installed_from(&SPAWNER)
}

/// [`installed`] over `slot`.
fn installed_from(slot: &std::sync::OnceLock<Spawner>) -> std::io::Result<Spawner> {
    slot.get().copied().ok_or_else(|| {
        std::io::Error::other(
            "lock_wait: no helper spawner is installed in this process, so a held lock cannot \
             be waited on here",
        )
    })
}

/// As the helper: block for the lock named by the argv, exit 0 once held, and
/// exit 3 the moment stdin closes. `None` when this process is not a helper.
pub fn helped(args: impl Iterator<Item = OsString>) -> Option<std::process::ExitCode> {
    let args: Vec<OsString> = args.skip(1).collect();
    if args.first().and_then(|arg| arg.to_str()) != Some(HELPER_ARG) {
        return None;
    }
    let mode = match args.get(1).and_then(|arg| arg.to_str()) {
        Some("exclusive") => Mode::Exclusive,
        Some("shared") => Mode::Shared,
        _ => return Some(std::process::ExitCode::from(2)),
    };
    let Some(Ok(file)) = args.get(2).map(File::open) else {
        return Some(std::process::ExitCode::from(2));
    };
    // THE WAITER'S HAND ON THIS PROCESS: it holds the only write end of this
    // stdin, and closing it is its stop, its return or its death.
    drop(std::thread::spawn(|| {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut byte = [0_u8; 1];
        while matches!(stdin.read(&mut byte), Ok(read) if read > 0) {}
        std::process::exit(3);
    }));
    #[expect(
        clippy::disallowed_methods,
        reason = "the helper's whole job, and its wait is bounded by an event: the holder's \
                  release, or `stdin` closing, which is its waiter's `Stop`, return or death"
    )]
    let locked = match mode {
        Mode::Exclusive => file.lock(),
        Mode::Shared => file.lock_shared(),
    };
    Some(std::process::ExitCode::from(if locked.is_ok() {
        0
    } else {
        2
    }))
}

/// One running helper: reaped, and its stdin closed, on every way out.
struct Helper<'stop> {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    adopted: Option<(&'stop Stop, u64)>,
    reaped: bool,
}

impl<'stop> Helper<'stop> {
    /// Start a helper for `path` in `mode` through `spawn`, its stdin held by
    /// `stop` when there is one.
    fn spawn(
        spawn: &dyn Fn(&Path, Mode) -> std::io::Result<std::process::Child>,
        path: &Path,
        mode: Mode,
        stop: Option<&'stop Stop>,
    ) -> std::io::Result<Self> {
        let mut child = spawn(path, mode)?;
        let stdin = child.stdin.take();
        let mut helper = Self {
            child,
            stdin: None,
            adopted: None,
            reaped: false,
        };
        match (stop, stdin) {
            (Some(stop), Some(stdin)) => helper.adopted = Some((stop, stop.adopt(stdin))),
            (None, stdin) => helper.stdin = stdin,
            (Some(_), None) => {}
        }
        Ok(helper)
    }

    /// Wait for the helper to exit: it holds the lock and let go, or it was
    /// ended through its stdin.
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for Helper<'_> {
    fn drop(&mut self) {
        // Closing stdin ends a helper still blocked, so the wait below is
        // bounded by that exit.
        drop(self.stdin.take());
        if let Some((stop, id)) = self.adopted {
            stop.release(id);
        }
        if !self.reaped {
            let _ = self.child.wait();
        }
    }
}

/// Wait for the lock on `file` (opened at `path`) through helpers started by
/// `spawn`: `true` once taken, `false` on the stop. `parked` is called with
/// each helper's pid as the wait parks on it.
///
/// # Errors
///
/// When the lock call itself fails, a helper cannot start, or one ends without
/// the lock while no stop was raised.
pub fn wait_with_helper(
    file: &File,
    path: &Path,
    mode: Mode,
    stop: Option<&Stop>,
    spawn: &dyn Fn(&Path, Mode) -> std::io::Result<std::process::Child>,
    parked: &mut dyn FnMut(u32),
) -> std::io::Result<bool> {
    loop {
        if attempt(file, mode)? {
            return Ok(true);
        }
        if stop.is_some_and(Stop::is_raised) {
            return Ok(false);
        }
        let mut helper = Helper::spawn(spawn, path, mode, stop)?;
        parked(helper.child.id());
        let status = helper.wait()?;
        drop(helper);
        if stop.is_some_and(Stop::is_raised) {
            return Ok(false);
        }
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "lock_wait: the helper for {} ended without the lock ({status})",
                path.display()
            )));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn lock_file(name: &str) -> (std::path::PathBuf, File) {
        let dir = std::env::temp_dir().join(format!("lock-wait-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .unwrap();
        (path, file)
    }

    fn reopen(path: &Path) -> File {
        std::fs::OpenOptions::new().write(true).open(path).unwrap()
    }

    /// Fails by: a free lock not taken at once.
    #[test]
    fn a_free_lock_is_taken() {
        let (path, file) = lock_file("free");
        assert!(matches!(
            acquire(file, &path, Mode::Exclusive, None).unwrap(),
            Taken::Held(_)
        ));
    }

    /// Fails by: a wait on a held lock that a raised stop does not end — the
    /// blocking `flock` this module replaces never returns here.
    #[test]
    fn a_raised_stop_ends_the_wait_on_a_held_lock() {
        let (path, file) = lock_file("stopped");
        assert!(
            attempt(&file, Mode::Exclusive).unwrap(),
            "the holder takes it"
        );
        let stop = Stop::new().unwrap();
        stop.raise();
        assert!(matches!(
            acquire(reopen(&path), &path, Mode::Exclusive, Some(&stop)).unwrap(),
            Taken::Stopped
        ));
        drop(file);
    }

    /// Fails by: a stop raised by another thread while the waiter is parked
    /// not waking it. The stop is raised on the waiter's own park event.
    #[test]
    fn a_stop_raised_during_the_wait_wakes_it() {
        let (path, file) = lock_file("woken");
        assert!(attempt(&file, Mode::Exclusive).unwrap());
        let stop = std::sync::Arc::new(Stop::new().unwrap());
        let (ready, parked) = std::sync::mpsc::channel();
        let waiter = {
            let stop = std::sync::Arc::clone(&stop);
            let path = path.clone();
            std::thread::spawn(move || {
                let mut park = move || {
                    let _ = ready.send(());
                };
                acquire_announced(
                    reopen(&path),
                    &path,
                    Mode::Exclusive,
                    Some(&stop),
                    &mut park,
                )
            })
        };
        parked.recv().unwrap();
        stop.raise();
        assert!(matches!(waiter.join().unwrap().unwrap(), Taken::Stopped));
        drop(file);
    }

    /// Fails by: a release by the holder never seen, so the waiter parks for
    /// good. The holder is another descriptor, dropped on the waiter's park
    /// event, so the lock is provably taken by the wake and not the first try.
    #[test]
    fn a_release_by_the_holder_hands_the_lock_over() {
        let (path, holder) = lock_file("handover");
        assert!(attempt(&holder, Mode::Exclusive).unwrap());
        let (ready, parked) = std::sync::mpsc::channel();
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut park = move || {
                    let _ = ready.send(());
                };
                acquire_announced(reopen(&path), &path, Mode::Exclusive, None, &mut park)
            })
        };
        parked.recv().unwrap();
        drop(holder);
        assert!(matches!(waiter.join().unwrap().unwrap(), Taken::Held(_)));
    }

    /// Fails by: a second lock on a file this process holds waited on rather
    /// than refused — the `step run` self-deadlock.
    #[test]
    fn a_lock_this_process_holds_is_refused_not_waited() {
        let (path, file) = lock_file("reentrant");
        let Taken::Held(first) = acquire(file, &path, Mode::Exclusive, None).unwrap() else {
            panic!("the first lock is taken");
        };
        assert!(matches!(
            acquire(reopen(&path), &path, Mode::Exclusive, None).unwrap(),
            Taken::Reentrant
        ));
        drop(first);
        assert!(
            matches!(
                acquire(reopen(&path), &path, Mode::Exclusive, None).unwrap(),
                Taken::Held(_)
            ),
            "the registration is released with the guard"
        );
    }

    /// Fails by: a held lock reported free, or a free one reported held.
    #[test]
    fn a_try_takes_only_a_free_lock() {
        let (path, file) = lock_file("try");
        let held = try_acquire(file, Mode::Exclusive).unwrap();
        assert!(held.is_some(), "a free lock is taken");
        assert!(
            try_acquire(reopen(&path), Mode::Exclusive)
                .unwrap()
                .is_none(),
            "a held one is not, and is not waited on"
        );
        drop(held);
        assert!(
            try_acquire(reopen(&path), Mode::Exclusive)
                .unwrap()
                .is_some()
        );
    }

    /// Fails by: a process with no spawner installed (a library, this test
    /// harness) spawning something anyway rather than refusing by name.
    #[test]
    fn with_no_spawner_installed_a_wait_is_refused_by_name() {
        let refused = installed_from(&std::sync::OnceLock::new())
            .expect_err("nothing was installed in this slot");
        assert!(
            refused
                .to_string()
                .contains("no helper spawner is installed"),
            "{refused}"
        );
        assert!(installed().is_err(), "the test harness installs none");
    }

    /// Fails by: a second spawner replacing the first.
    #[test]
    fn a_second_spawner_is_refused() {
        fn first(_: &Path, _: Mode) -> std::io::Result<std::process::Child> {
            Err(std::io::Error::other("first"))
        }
        fn second(_: &Path, _: Mode) -> std::io::Result<std::process::Child> {
            Err(std::io::Error::other("second"))
        }
        let slot = std::sync::OnceLock::new();
        install_into(&slot, first).expect("the first install");
        assert!(install_into(&slot, second).is_err());
        let kept = installed_from(&slot).expect("installed");
        assert_eq!(
            kept(Path::new("/x"), Mode::Exclusive)
                .unwrap_err()
                .to_string(),
            "first",
            "the first spawner stands"
        );
    }

    /// Fails by: a process that is not a helper taken for one.
    #[test]
    fn only_the_marker_makes_a_helper() {
        let argv = |words: &[&str]| words.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(helped(argv(&["batten", "check"]).into_iter()).is_none());
        assert_eq!(
            helped(argv(&["batten", HELPER_ARG, "sideways", "/x"]).into_iter()),
            Some(std::process::ExitCode::from(2)),
            "an unknown mode is refused, not waited on"
        );
    }

    /// Fails by: a second THREAD of the process refused as re-entry, when it is
    /// a holder like any other and can wait for the first one's release
    /// (admission's two concurrent consumers). The first thread's hold is
    /// dropped on the second's park event.
    #[test]
    fn a_second_thread_waits_for_the_first_rather_than_being_refused() {
        let (path, file) = lock_file("second-thread");
        let Taken::Held(first) = acquire(file, &path, Mode::Exclusive, None).unwrap() else {
            panic!("the first thread takes it");
        };
        let (ready, parked) = std::sync::mpsc::channel();
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut park = move || {
                    let _ = ready.send(());
                };
                acquire_announced(reopen(&path), &path, Mode::Exclusive, None, &mut park)
            })
        };
        parked.recv().unwrap();
        drop(first);
        assert!(matches!(waiter.join().unwrap().unwrap(), Taken::Held(_)));
    }

    /// Fails by: a lock released only at the LAST close of its description.
    /// The twin is a second reference to it, as a concurrent fork's child holds
    /// one until its exec: the guard's drop must release the lock regardless.
    #[test]
    fn a_dropped_guard_releases_even_while_its_description_lives_on() {
        let (path, file) = lock_file("twin-release");
        let Taken::Held(first) = acquire(file, &path, Mode::Exclusive, None).unwrap() else {
            panic!("the first lock is taken");
        };
        let twin = first.file().try_clone().unwrap();
        drop(first);
        assert!(
            attempt(&reopen(&path), Mode::Exclusive).unwrap(),
            "the drop released the lock, not the twin's eventual close"
        );
        drop(twin);
    }

    /// Fails by HANGING: a waiter that saw a close while the lock was still held
    /// (the kernel notifies a close before it releases the lock, and a forked
    /// child's reference outlives the holder's close) parks with no further
    /// event to come. The holder's guard drops on the waiter's park event while
    /// a twin keeps the description open past the join.
    #[test]
    fn a_waiter_wakes_on_a_release_no_close_follows() {
        let (path, file) = lock_file("twin-wake");
        let Taken::Held(first) = acquire(file, &path, Mode::Exclusive, None).unwrap() else {
            panic!("the first lock is taken");
        };
        let twin = first.file().try_clone().unwrap();
        let (ready, parked) = std::sync::mpsc::channel();
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut park = move || {
                    let _ = ready.send(());
                };
                acquire_announced(reopen(&path), &path, Mode::Exclusive, None, &mut park)
            })
        };
        parked.recv().unwrap();
        drop(first);
        assert!(matches!(waiter.join().unwrap().unwrap(), Taken::Held(_)));
        drop(twin);
    }

    /// A thread holding a lock shared that asks for it exclusive is refused as
    /// re-entry, either way round: one exclusive side is a conflict. The stop
    /// is raised, so a wait that should have been a refusal answers `Stopped`
    /// rather than waiting on this thread.
    ///
    /// Fails by: a conflict read only where both sides are exclusive, so the
    /// mixed pair waits on itself (bootstrap shard 7/8 at 34c6e4d1f survived
    /// `||` as `&&` in `register`).
    #[test]
    fn a_shared_and_an_exclusive_hold_in_one_thread_are_reentry() {
        let stop = Stop::new().unwrap();
        stop.raise();
        for (held, asked) in [
            (Mode::Shared, Mode::Exclusive),
            (Mode::Exclusive, Mode::Shared),
        ] {
            let (path, file) = lock_file("mixed");
            let Taken::Held(first) = acquire(file, &path, held, None).unwrap() else {
                panic!("the first lock is taken");
            };
            assert!(
                matches!(
                    acquire(reopen(&path), &path, asked, Some(&stop)).unwrap(),
                    Taken::Reentrant
                ),
                "{held:?} then {asked:?}"
            );
            drop(first);
        }
    }

    /// Fails by: two shared holds in one process refused as re-entry.
    #[test]
    fn two_shared_holds_in_one_process_are_not_reentry() {
        let (path, file) = lock_file("shared");
        let first = acquire(file, &path, Mode::Shared, None).unwrap();
        assert!(matches!(first, Taken::Held(_)));
        assert!(matches!(
            acquire(reopen(&path), &path, Mode::Shared, None).unwrap(),
            Taken::Held(_)
        ));
    }

    /// CLOUD-2789: a helper's stdin, held by the stop it waits on, is let go
    /// when the helper is done with, not kept until the stop is raised.
    ///
    /// Fails by: [`Stop::release`] doing nothing (a mutant missed at
    /// 34c6e4d1f), so each helper a long-lived stop outlives leaks a pipe.
    /// `true` is the helper, so off unix the case returns at once; `cfg!`
    /// rather than `#[cfg]` keeps it compiled, and counted, on every target.
    #[test]
    fn a_finished_helper_is_released_from_its_stop() {
        if !cfg!(unix) {
            return;
        }
        let (path, _file) = lock_file("released");
        let stop = Stop::new().unwrap();
        #[expect(
            clippy::disallowed_types,
            reason = "test-only: the helper is a program that exits 0 at once, spawned so the stop adopts and then releases a real child's stdin"
        )]
        let spawn = |_: &Path, _: Mode| {
            std::process::Command::new("true")
                .stdin(std::process::Stdio::piped())
                .spawn()
        };
        let mut helper = Helper::spawn(&spawn, &path, Mode::Exclusive, Some(&stop)).unwrap();
        assert_eq!(stop.helpers.lock().unwrap().len(), 1, "adopted");
        assert!(helper.wait().unwrap().success());
        drop(helper);
        assert!(stop.helpers.lock().unwrap().is_empty(), "released");
    }
}
