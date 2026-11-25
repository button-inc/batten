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
//! - **Re-entry.** A lock this process already holds through [`acquire`] is
//!   refused as [`Taken::Reentrant`] instead of waited on, because the holder is
//!   the waiter and the release can never come — the `step run` deadlock.
//!
//! A holder that unlocks WITHOUT closing produces no event; every holder in
//! this crate holds its lock for exactly the life of its descriptor ([`Held`]),
//! so release and close are one moment.
//!
//! # Off Linux: a helper process does the blocking
//!
//! No other platform reports a close that safe code can wait on: kqueue's
//! `NOTE_CLOSE` is FreeBSD's, not macOS's; Windows' overlapped `LockFileEx` is
//! raw FFI under `unsafe_code = "forbid"`; and a signal cannot interrupt a
//! blocked `flock` on a thread, because `signal-hook` installs every handler
//! with `SA_RESTART`. So the blocking call moves to a process the waiter can
//! end ([`wait_with_helper`]): this binary re-entered as `batten __lock-wait
//! <mode> <path>` ([`helped`]) blocks on its OWN descriptor and exits 0 the
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
use std::path::{Path, PathBuf};
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
    /// This process already holds the lock in a conflicting mode, so waiting
    /// would wait on itself.
    Reentrant,
}

/// A held lock: the descriptor that holds it, released when this drops.
#[derive(Debug)]
pub struct Held {
    file: File,
    key: Option<Key>,
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
        if let Some(key) = self.key {
            release(key);
        }
    }
}

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

/// The locks this process holds through [`acquire`]: mode and holder count.
static HELD: Mutex<Option<HashMap<Key, (Mode, usize)>>> = Mutex::new(None);

/// Register `key` as held in `mode`, or `false` when that conflicts with a
/// hold this process already has.
fn register(key: Key, mode: Mode) -> bool {
    let Ok(mut held) = HELD.lock() else {
        return true;
    };
    let held = held.get_or_insert_with(HashMap::new);
    match held.get_mut(&key) {
        None => {
            held.insert(key, (mode, 1));
            true
        }
        Some((Mode::Shared, count)) if mode == Mode::Shared => {
            *count += 1;
            true
        }
        Some(_) => false,
    }
}

/// Drop one holder of `key`.
fn release(key: Key) {
    let Ok(mut held) = HELD.lock() else {
        return;
    };
    let Some(held) = held.as_mut() else {
        return;
    };
    if let Some((_, count)) = held.get_mut(&key) {
        *count -= 1;
        if *count == 0 {
            held.remove(&key);
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
    let key = key_of(&file)?;
    if let Some(key) = key
        && !register(key, mode)
    {
        return Ok(Taken::Reentrant);
    }
    // From here an early return releases the registration through the guard.
    let held = Held { file, key };
    if attempt(&held.file, mode)? {
        return Ok(Taken::Held(held));
    }
    if wait(&held.file, path, mode, stop, parked)? {
        Ok(Taken::Held(held))
    } else {
        Ok(Taken::Stopped)
    }
}

/// One attempt and no wait: `Some` when `file` was free, `None` when another
/// holds it — or this process does, which a waiter would wait on itself for.
/// For a caller with a per-call budget, where losing a race is an answer.
///
/// # Errors
///
/// When the identity cannot be read or the lock call itself fails.
pub fn try_acquire(file: File, mode: Mode) -> std::io::Result<Option<Held>> {
    let key = key_of(&file)?;
    if let Some(key) = key
        && !register(key, mode)
    {
        return Ok(None);
    }
    let held = Held { file, key };
    Ok(attempt(&held.file, mode)?.then_some(held))
}

/// Wait for the lock, `true` once taken, `false` on the stop.
#[cfg(target_os = "linux")]
fn wait(
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

/// Off Linux: wait through a helper process ([`wait_with_helper`]) of this
/// binary, resolved by [`helper_program`].
#[cfg(not(target_os = "linux"))]
fn wait(
    file: &File,
    path: &Path,
    mode: Mode,
    stop: Option<&Stop>,
    parked: &mut dyn FnMut(),
) -> std::io::Result<bool> {
    wait_with_helper(file, path, mode, stop, &helper_program()?, &mut |_| {
        parked()
    })
}

/// The argv marker a helper is re-entered on: `batten __lock-wait <mode> <path>`.
pub const HELPER_ARG: &str = "__lock-wait";

impl Mode {
    /// The helper argv's spelling of the mode.
    const fn name(self) -> &'static str {
        match self {
            Self::Exclusive => "exclusive",
            Self::Shared => "shared",
        }
    }
}

/// The program a helper is: this binary, when it IS batten.
///
/// THE TEST HARNESS IS REFUSED BY NAME. A unit test calling a wait in process
/// runs as the harness (`batten-<hash>`), which has no [`helped`] entry, so
/// spawning it would run the suite, not a helper.
///
/// # Errors
///
/// When the running program cannot be named, or is not batten.
pub fn helper_program() -> std::io::Result<PathBuf> {
    let program = std::env::current_exe()?;
    let stem = program.file_stem().and_then(|stem| stem.to_str());
    if stem == Some("batten") {
        Ok(program)
    } else {
        Err(std::io::Error::other(format!(
            "lock_wait: `{}` is not batten, so it cannot wait through a helper of itself",
            program.display()
        )))
    }
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
    /// Start `program` as a helper for `path` in `mode`, its stdin held by
    /// `stop` when there is one.
    #[expect(
        clippy::disallowed_types,
        reason = "the lock-wait helper (CLOUD-2789): this binary re-entered to block on a lock \
                  so the waiter can end it, reaped by `Helper`'s drop on every path"
    )]
    fn spawn(
        program: &Path,
        path: &Path,
        mode: Mode,
        stop: Option<&'stop Stop>,
    ) -> std::io::Result<Self> {
        let mut child = std::process::Command::new(program)
            .arg(HELPER_ARG)
            .arg(mode.name())
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
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

/// Wait for the lock on `file` (opened at `path`) through helpers run as
/// `program`: `true` once taken, `false` on the stop. `parked` is called with
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
    program: &Path,
    parked: &mut dyn FnMut(u32),
) -> std::io::Result<bool> {
    loop {
        if attempt(file, mode)? {
            return Ok(true);
        }
        if stop.is_some_and(Stop::is_raised) {
            return Ok(false);
        }
        let mut helper = Helper::spawn(program, path, mode, stop)?;
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

    /// Fails by: the test harness taken for batten, so a wait off Linux would
    /// spawn the suite as its helper.
    #[test]
    fn the_test_harness_is_refused_as_a_helper_by_name() {
        let refused = helper_program().expect_err("this process is the harness");
        assert!(refused.to_string().contains("is not batten"), "{refused}");
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
}
