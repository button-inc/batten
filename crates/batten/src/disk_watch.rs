//! The disk watcher a long-running batten process hosts (CLOUD-1937, CLOUD-2197).
//!
//! # Reaction, not prediction
//!
//! Below `[prune] min_free_mb` the watcher collects — unreachable, then
//! least-recently-used cargo units ([`crate::collect`]) — until `max_free_mb` is
//! free. Nothing is projected and nothing is learned: bursts between two samples
//! are absorbed by the headroom `min_free_mb` declares, as Nix's `min-free` and
//! kubelet's image GC band absorb them. The arm this replaces projected a burn
//! over a horizon against a floor it learned, and reacted by deleting
//! `incremental` first — the most valuable cache of an edit loop.
//!
//! # It spans the whole run
//!
//! `land` starts it once, around every lap: replay, verify, push and the CI wait.
//! The arm it replaces lived only while a gate ran, so replay, push and the
//! lap-close prune were unwatched. `mutate sweep` hosts the same watcher around
//! its builds. It ends on its stop flag, never when one step returns.
//!
//! # Woken by the volume, and never later than a millisecond
//!
//! The watcher runs on its own current-thread compio runtime (CLOUD-2782). A
//! [`PERIOD`] timer wakes it on every platform; on Linux a fanotify filesystem
//! mark also wakes it on every write to the volume, so a fill is read the moment
//! the kernel reports it. The timer stays on beside the mark: a write through
//! mmap (the linker's output) reports nothing until close, and an unprivileged
//! process gets no mark at all. Which source armed is the watcher's first record
//! line, with the errno when the mark was refused.
//!
//! A collection runs on its own scoped thread, so a pass over a large tree never
//! stops the wakes; one collection runs at a time, and a sample that finds one
//! running does nothing. Its lines go to the record sink the moment it ends.
//! The watcher's first act is to re-arm `relatime` ([`crate::collect::rearm`]),
//! which is what "at lap open" means.
//!
//! # One timer, in the inventory
//!
//! The period is waited on the crate's one clock, [`crate::pr_watch::clock`],
//! whose single inventory row names this floor's bound: the band
//! (`min_free_mb`), not a guess. The arm grows no clock of its own.

use crate::prune::PruneExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// How long the hook may collect before admitting (CLOUD-2197): a sixth of the
/// harness's 60 s default command-hook timeout, so a killed hook is never the
/// bound. Checked at unit boundaries; the next pressed call resumes.
pub const HOOK_COLLECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

use crate::low_water::observe;
#[cfg(test)]
use crate::low_water::read as low_water;
#[cfg(test)]
use crate::low_water::reset as reset_low_water;

/// Where a watcher hands each collection's lines as it ends (CLOUD-2782).
pub type RecordSink<'a> = Box<dyn Fn(&[String]) + Send + Sync + 'a>;

/// How long a watcher waits, once the run it watched has returned, for the
/// collection still running to answer (CLOUD-2789): the stream's drain grace,
/// the crate's bound on waiting for work the run no longer needs.
///
/// A pass that outlives it is ABANDONED, never joined: the watcher records
/// `disk-abandoned <grace_ms>` and returns, and the pass ends at its next unit
/// on the stop flag it was handed, releasing its tree locks as it does. A pass
/// wedged in one system call holds them until the process exits, which is the
/// one release left; joining it was a step that printed its result and never
/// exited.
pub const PASS_GRACE: std::time::Duration = batten_stream::DRAIN_GRACE;

/// What a watcher needs: the repository whose trees it collects, the committed
/// `[prune]` rules, how free space is read, and what is never collected.
///
/// The reading is INJECTED — the volume in production ([`crate::prune::sampler`]),
/// a series in a test — so the trigger and the stop are decidable without
/// filling a disk.
pub struct DiskWatch<'a> {
    /// The repository: its `[prune] root` and each linked worktree's are the trees.
    pub repo: PathBuf,
    /// The committed `[prune]` rules; nothing outside them is touched.
    pub config: &'a crate::config_model::Prune,
    /// Free space on the trees' volume, in MiB.
    pub free_mb: Box<dyn FnMut() -> anyhow::Result<u64> + Send + 'a>,
    /// Files no collection removes ([`crate::collect::kept`]).
    pub kept: Vec<crate::collect::Kept>,
    /// The directory a pass reads cargo-mutants' staged copies from: the
    /// process's temp directory, where cargo-mutants stages them. A case names
    /// one of its own, so it never frees a copy another suite's sweep left
    /// there (CLOUD-2789).
    pub copies: PathBuf,
    /// Where each collection's lines go the moment it ends (CLOUD-2782):
    /// `land` points it at the lap record. `None` keeps them for the join alone.
    pub record: Option<RecordSink<'a>>,
}

impl std::fmt::Debug for DiskWatch<'_> {
    /// The reader is a closure, so it is named rather than printed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiskWatch")
            .field("repo", &self.repo)
            .field("config", &self.config)
            .field("free_mb", &"<reader>")
            .field("copies", &self.copies)
            .field("record", &self.record.as_ref().map(|_| "<sink>"))
            .finish_non_exhaustive()
    }
}

/// The record sink a watcher hands each collection's lines to as it ends.
type Sink<'a> = Arc<dyn Fn(&[String]) + Send + Sync + 'a>;

/// What one wake does, shared by the timer loop and the event loop: read the
/// volume, and start a collection when the reading is below the floor.
struct Sampler<'a> {
    repo: PathBuf,
    config: &'a crate::config_model::Prune,
    kept: Vec<crate::collect::Kept>,
    copies: PathBuf,
    min: u64,
    reader: std::cell::RefCell<Box<dyn FnMut() -> anyhow::Result<u64> + Send + 'a>>,
    lines: std::cell::RefCell<Vec<String>>,
    sink: Option<Sink<'a>>,
    /// The reading the last pass ended on while still below the floor, or
    /// `u64::MAX`: what the next pass must see the volume fall below.
    settled: std::cell::Cell<u64>,
    /// Where the running collection's answer arrives, if one is running.
    pending:
        std::cell::RefCell<Option<std::sync::mpsc::Receiver<Option<crate::collect::Collected>>>>,
    /// The flag every collection ends on, set once the watcher stops.
    halt: Arc<AtomicBool>,
    trace: bool,
    started: std::time::Instant,
    last_wake: std::cell::Cell<Option<std::time::Instant>>,
}

impl Sampler<'_> {
    /// Keep `new` in the watcher's record and hand it to the sink at once.
    fn emit(&self, new: &[String]) {
        if new.is_empty() {
            return;
        }
        self.lines.borrow_mut().extend_from_slice(new);
        if let Some(sink) = &self.sink {
            sink(new);
        }
    }

    /// One reading of the volume, or `None` where it could not be read.
    fn read(&self) -> Option<u64> {
        (self.reader.borrow_mut())().ok()
    }

    /// Take a finished collection's answer, if one has arrived.
    fn reap(&self) {
        let answer = match self
            .pending
            .borrow()
            .as_ref()
            .map(std::sync::mpsc::Receiver::try_recv)
        {
            None | Some(Err(std::sync::mpsc::TryRecvError::Empty)) => return,
            Some(Ok(done)) => done,
            // A pass that panicked answers nothing; the next sample judges.
            Some(Err(std::sync::mpsc::TryRecvError::Disconnected)) => None,
        };
        self.pending.borrow_mut().take();
        self.finish(answer);
    }

    /// Record a collection's lines — AS IT HAPPENS (CLOUD-2782), the sink
    /// getting them when it ends, not when the landing does — and where it
    /// left the volume.
    fn finish(&self, done: Option<crate::collect::Collected>) {
        let after = self.read();
        if let Some(mut done) = done {
            if let Some(after) = after {
                done.free_after_mb = after;
            }
            self.emit(&done.lines());
        }
        // WHERE THIS PASS LEFT THE VOLUME: what the next pass waits to see the
        // volume fall under. A reading at or above the floor needs no case of
        // its own: the next sample there resets it, and any sample below the
        // floor is below it too.
        if let Some(after) = after {
            self.settled.set(after);
        }
    }

    /// Stop every collection, and wait for the running one's answer for at
    /// most [`PASS_GRACE`]; a pass that outlives it is recorded abandoned.
    fn settle(&self) {
        self.halt.store(true, Ordering::Release);
        let Some(answered) = self.pending.borrow_mut().take() else {
            return;
        };
        match answered.recv_timeout(PASS_GRACE) {
            Ok(done) => self.finish(done),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.emit(&[format!("disk-abandoned {}", PASS_GRACE.as_millis())])
            }
        }
    }

    /// One wake: read, record the window's low-water mark, and collect below
    /// the floor.
    fn sample(&self) {
        let now = std::time::Instant::now();
        if self.trace {
            // THE ACHIEVED PERIOD, per wake: the measurement CLOUD-2782's
            // runtime choice is checked against, recorded and never asserted.
            if let Some(last) = self.last_wake.replace(Some(now)) {
                let us = u64::try_from(now.duration_since(last).as_micros()).unwrap_or(u64::MAX);
                trace(&crate::collect::trace_line("disk-wake", &[us]));
            }
        }
        self.reap();
        let Some(free) = self.read() else {
            return;
        };
        observe(free);
        if self.trace {
            let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            trace(&crate::collect::trace_line("disk-sample", &[ms, free]));
        }
        // A VOLUME BACK ABOVE THE FLOOR forgets the last pass's ending.
        if free >= self.min {
            self.settled.set(u64::MAX);
            return;
        }
        // A PASS THAT COULD NOT LIFT THE VOLUME IS NOT REPEATED UNTIL SOMETHING
        // NEW IS WRITTEN (CLOUD-2782). It removed everything it may, so a second
        // pass over the same tree frees nothing; at a 1 ms period that would be
        // a thousand tree walks a second on a volume that stays full. The event
        // that makes another pass worth it is a reading below the one the last
        // pass ended on: new bytes, which are what a pass can collect.
        if free >= self.settled.get() {
            return;
        }
        // ONE COLLECTION AT A TIME: a sample that finds one running does
        // nothing, and the next sample judges what it left.
        if self.pending.borrow().is_some() || self.halt.load(Ordering::Acquire) {
            return;
        }
        let (repo, config, kept) = (self.repo.clone(), self.config.clone(), self.kept.clone());
        let (copies, halt) = (self.copies.clone(), Arc::clone(&self.halt));
        let (answer, answered) = std::sync::mpsc::channel();
        // AN OWNED THREAD, NEVER A SCOPED ONE (CLOUD-2789): a scope joins every
        // thread it spawned at its end, so a pass that would not end held the
        // watched run open after it printed its result. This one is waited on
        // for [`PASS_GRACE`] at most ([`Sampler::settle`]), and it reads nothing
        // the watcher's thread owns: the volume is read there, when it answers.
        let spawned = std::thread::Builder::new()
            .name("disk-collect".to_owned())
            .spawn(move || {
                let mut unread = || {
                    Err(anyhow::anyhow!(
                        "the volume is read on the watcher's thread"
                    ))
                };
                // THE WATCHER WAITS ITS TURN ON A HELD TREE. It is the one
                // collector with no deadline, on a thread of its own; skipping a
                // held tree did not work. Measured on #1276: 292 passes during
                // one `land` lap each logged `disk-held ./target` and freed
                // nothing while 6.9GB of stale scratch sat in that tree, and the
                // lap died at `No space left on device`. It waits on its stop
                // flag, never on the lock itself (CLOUD-2789).
                let done = crate::collect::collect_toward_max_in(
                    &repo,
                    &config,
                    &kept,
                    free,
                    &mut unread,
                    (None, true, Some(&halt)),
                    &copies,
                );
                let _ = answer.send(done);
            });
        if spawned.is_ok() {
            *self.pending.borrow_mut() = Some(answered);
        }
    }
}

/// One trace line to stderr, best effort: tracing never fails the watcher.
fn trace(line: &str) {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("{line}\n").as_bytes());
}

/// How often the watcher samples at the least: every millisecond, on every
/// platform, whether or not an event woke it sooner.
///
/// THE BOUND IS THE BAND (CLOUD-2782). A period longer than the headroom over
/// the volume's peak write rate lets a crossing of `min_free_mb` reach 0 between
/// two samples; at 1 ms that holds for a 2 GiB headroom up to 2 TB/s. One
/// `statvfs` costs about 0.6 µs, so 1,000 a second is 0.06% of one core.
pub const PERIOD: std::time::Duration = std::time::Duration::from_millis(1);

/// Start the watcher in `scope`; it runs until `stop` is set, then returns the
/// record lines it produced: its armed line, then each collection's
/// (`disk-collected …`, `disk-unlink-ms …`).
///
/// A repository with no declared band returns at once with no lines: the arm is
/// off, as it is for a consumer with no `[prune]`.
pub fn watch<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    watch: DiskWatch<'scope>,
    stop: &'scope AtomicBool,
) -> std::thread::ScopedJoinHandle<'scope, Vec<String>> {
    watch_on(scope, watch, stop, None)
}

/// [`watch`] on a runtime built over `driver`, or the platform's choice for
/// `None`: the seam the cases use to run under every driver.
fn watch_on<'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    watch: DiskWatch<'scope>,
    stop: &'scope AtomicBool,
    driver: Option<compio::driver::DriverType>,
) -> std::thread::ScopedJoinHandle<'scope, Vec<String>> {
    scope.spawn(move || {
        let DiskWatch {
            repo,
            config,
            free_mb,
            kept,
            copies,
            record,
        } = watch;
        let Some((min, _)) = config.free_band() else {
            return Vec::new();
        };
        // THE LAP OPENS RE-ARMED: every fingerprint's atime is set to its mtime,
        // so the next read by cargo records a fresh one and the LRU order is
        // this run's use rather than the first read of the day.
        //
        // A STOP ENDS IT TOO (CLOUD-2789): a run shorter than one walk of a
        // large tree is not held open for the rest of the walk.
        for tree in crate::collect::trees(&repo, config) {
            crate::collect::rearm_until(&tree, Some(stop));
        }
        let sampler = Sampler {
            repo,
            config,
            kept,
            copies,
            min,
            reader: std::cell::RefCell::new(free_mb),
            lines: std::cell::RefCell::new(Vec::new()),
            sink: record.map(Sink::from),
            settled: std::cell::Cell::new(u64::MAX),
            pending: std::cell::RefCell::new(None),
            halt: Arc::new(AtomicBool::new(false)),
            trace: crate::collect::tracing(),
            started: std::time::Instant::now(),
            last_wake: std::cell::Cell::new(None),
        };
        run(&sampler, stop, driver);
        sampler.settle();
        sampler.lines.take()
    })
}

/// The floor where no runtime could be built: `tick` once per period on the
/// clock's blocking face until `stop` is set. Its own function so that the
/// stop test is driven directly, since no kernel this suite runs on refuses
/// the runtime.
fn blocking_floor(stop: &AtomicBool, mut tick: impl FnMut()) {
    while !stop.load(Ordering::Relaxed) {
        tick();
        crate::pr_watch::clock::hold(PERIOD, None);
    }
}

/// The watcher's loops, on its own current-thread compio runtime: the timer on
/// every platform, and on Linux the filesystem mark beside it.
///
/// A runtime that cannot be built leaves the timer's floor to the crate's one
/// synchronous pause, so the watcher is never silently off.
fn run(sampler: &Sampler<'_>, stop: &AtomicBool, driver: Option<compio::driver::DriverType>) {
    let mut builder = compio::runtime::RuntimeBuilder::new();
    if let Some(driver) = driver {
        let mut proactor = compio::driver::ProactorBuilder::new();
        proactor.driver_type(driver);
        builder.with_proactor(proactor);
    }
    let runtime = match builder.build() {
        Ok(runtime) => runtime,
        Err(why) => {
            // No runtime, so the floor waits on the clock's blocking face.
            sampler.emit(&[format!(
                "disk-watch-armed source=timer period-us={} errno={:?}",
                PERIOD.as_micros(),
                why.kind()
            )]);
            blocking_floor(stop, || sampler.sample());
            return;
        }
    };
    runtime.block_on(async {
        let events = wake_source(sampler, stop);
        let timer = async {
            // THE CRATE'S ONE CLOCK (`crate::pr_watch::clock`), whose single
            // inventory row names this floor's bound: the band.
            while !stop.load(Ordering::Relaxed) {
                crate::pr_watch::clock::pause_for(PERIOD).await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                sampler.sample();
            }
        };
        until_first(timer, events).await;
    });
}

/// Hand the runtime one turn: `Pending` once, waking itself, then done.
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return std::task::Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await;
}

/// Run `first` to completion while `second` runs beside it; `second` is
/// dropped when `first` ends, and a `second` that ends early leaves `first`
/// alone. Neither wait is ever cancelled mid-flight while `first` runs.
async fn until_first(first: impl Future<Output = ()>, second: impl Future<Output = ()>) {
    let mut first = std::pin::pin!(first);
    let mut second = std::pin::pin!(second);
    let mut second_done = false;
    std::future::poll_fn(|cx| {
        if first.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(());
        }
        if !second_done && second.as_mut().poll(cx).is_ready() {
            second_done = true;
        }
        std::task::Poll::Pending
    })
    .await;
}

/// The event wake: on Linux, a fanotify filesystem mark that reports every
/// write to the repository's volume, awaited on the runtime's driver. It
/// records the armed line either way, naming the errno when the mark was
/// refused.
///
/// THE EVENT LOOP YIELDS AFTER EVERY BATCH AND ENDS ON `stop` (CLOUD-2789): a
/// volume written faster than one batch is read kept the descriptor ready, so
/// a loop that never returned `Pending` starved the timer, the one wait that
/// sees the stop.
#[cfg(target_os = "linux")]
fn wake_source<'a>(
    sampler: &'a Sampler<'_>,
    stop: &'a AtomicBool,
) -> impl Future<Output = ()> + 'a {
    let armed = fanotify::arm(&sampler.repo).and_then(|group| {
        let group = Arc::new(group);
        compio::runtime::fd::PollFd::new(Arc::clone(&group))
            .map(|ready| (group, ready))
            .map_err(|why| format!("{:?}", why.kind()))
    });
    let period = PERIOD.as_micros();
    let source = match &armed {
        Ok(_) => format!("disk-watch-armed source=fanotify period-us={period}"),
        Err(errno) => format!("disk-watch-armed source=timer period-us={period} errno={errno}"),
    };
    sampler.emit(&[source]);
    async move {
        let Ok((group, ready)) = armed else {
            return;
        };
        loop {
            if std::future::poll_fn(|cx| ready.poll_read_ready(cx))
                .await
                .is_err()
            {
                return;
            }
            // COALESCED: one batch of queued events is read, then one sample
            // judges them all. An overflow is a wake like any other.
            fanotify::drain(&group);
            if stop.load(Ordering::Relaxed) {
                return;
            }
            sampler.sample();
            yield_once().await;
        }
    }
}

/// No filesystem mark off Linux: the timer is the whole wake.
#[cfg(not(target_os = "linux"))]
fn wake_source<'a>(
    sampler: &'a Sampler<'_>,
    _stop: &'a AtomicBool,
) -> impl Future<Output = ()> + 'a {
    // The same armed line as Linux's refused branch, from the same `arm`.
    let errno = fanotify::arm(&sampler.repo).err().unwrap_or_default();
    sampler.emit(&[format!(
        "disk-watch-armed source=timer period-us={} errno={errno}",
        PERIOD.as_micros()
    )]);
    std::future::ready(())
}

/// The Linux filesystem mark (CLOUD-2782).
///
/// **FILE IDS, NOT FILE DESCRIPTORS.** Without `FAN_REPORT_FID` every event
/// carries a descriptor the kernel opened on the written file, so a build's
/// flood of writes would fill the process's table. nix 0.31.3 names no such
/// flag, so it is passed through `from_bits_retain`; its `read_events` steps by
/// `event_len` and closes nothing for `FAN_NOFD`.
#[cfg(target_os = "linux")]
mod fanotify {
    use nix::sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags};

    /// A notification group marking the whole filesystem `path` is on, or the
    /// errno that refused it: EPERM without `CAP_SYS_ADMIN`, and EINVAL,
    /// ENODEV, EOPNOTSUPP or EXDEV where the kernel or filesystem lacks FID.
    pub(super) fn arm(path: &std::path::Path) -> Result<Fanotify, String> {
        armed(path).map_err(|errno| format!("{errno:?}"))
    }

    /// [`arm`] in nix's own error.
    fn armed(path: &std::path::Path) -> nix::Result<Fanotify> {
        // `union`, never `|`: the bits are disjoint, so a flipped operator
        // could not be told from this one by any outcome.
        let flags = InitFlags::FAN_CLASS_NOTIF
            .union(InitFlags::FAN_NONBLOCK)
            .union(InitFlags::FAN_CLOEXEC)
            .union(InitFlags::from_bits_retain(nix::libc::FAN_REPORT_FID));
        let group = Fanotify::init(flags, EventFFlags::O_RDONLY)?;
        let dir = crate::durable::open_handle(path)
            .map_err(|why| nix::errno::Errno::from_raw(why.raw_os_error().unwrap_or(0)))?;
        group.mark(
            MarkFlags::FAN_MARK_ADD.union(MarkFlags::FAN_MARK_FILESYSTEM),
            MaskFlags::FAN_MODIFY.union(MaskFlags::FAN_CLOSE_WRITE),
            &dir,
            None::<&std::path::Path>,
        )?;
        Ok(group)
    }

    /// Read ONE batch of queued events; how many it held. One per wake
    /// (CLOUD-2789): draining until the group would block never ended on a
    /// volume written faster than it was read.
    pub(super) fn drain(group: &Fanotify) -> usize {
        group.read_events().map_or(0, |events| events.len())
    }
}

/// No filesystem mark off Linux: the group cannot exist, and arming says why.
/// The same two items as the Linux module, so a case naming them compiles on
/// every target.
#[cfg(not(target_os = "linux"))]
mod fanotify {
    /// A group that cannot be built here.
    pub(super) enum Group {}

    /// Always refused: no platform but Linux has a filesystem mark.
    pub(super) fn arm(_: &std::path::Path) -> Result<Group, String> {
        Err(String::from("ENOSYS"))
    }

    /// Nothing to read from a group that cannot exist; only the cases name it.
    #[cfg(test)]
    pub(super) fn drain(group: &Group) -> usize {
        match *group {}
    }
}

/// Run `body` with a watcher over `repo` alive for its whole duration, and
/// return what it returned together with the watcher's record lines.
///
/// `None` for `watch` runs `body` unwatched: no band, or no readable volume.
pub fn around<T>(watch: Option<DiskWatch<'_>>, body: impl FnOnce() -> T) -> (T, Vec<String>) {
    around_on(None, watch, body)
}

/// [`around`] with the watcher's runtime on `driver`, or the platform's choice
/// for `None`.
fn around_on<T>(
    driver: Option<compio::driver::DriverType>,
    watch: Option<DiskWatch<'_>>,
    body: impl FnOnce() -> T,
) -> (T, Vec<String>) {
    let Some(watch) = watch else {
        return (body(), Vec::new());
    };
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let handle = watch_on(scope, watch, &stop, driver);
        // TWO STATEMENTS, NOT ONE WITH A SPARE. The store is the normal
        // completion point — the body returned, so the watcher's work is over
        // before the join. [`Stop`] covers the OTHER way out, an unwind, which
        // reaches neither this line nor anything after it.
        //
        // Folding the normal path into the guard was tried and is worse twice
        // over: it makes a correct return depend on drop order, and it leaves
        // the guard unprovable — emptying its `drop` then hangs every watched
        // case at once, so the runner reports could-not-look instead of a
        // catch. Separate, the guard's own unit test fails in 0.012s.
        let answer = {
            let _stop = Stop(&stop);
            body()
        };
        stop.store(true, Ordering::Relaxed);
        let lines = handle.join().unwrap_or_default();
        (answer, lines)
    })
}

/// Sets the stop flag when it drops, so the watcher ends on a panic too.
///
/// **A BARE `stop.store` AFTER `body()` IS SKIPPED BY A PANIC (CLOUD-2376),**
/// and [`std::thread::scope`]'s join at unwind then waits on a thread looping
/// `while !stop` — which no longer has any way to become true. The process hangs
/// instead of propagating the panic, and nothing says why.
///
/// Measured on `prune_watch::the_arm_watches_past_the_gate` with the collection
/// mutated away: its own `wait_for` reached its bound and panicked on schedule,
/// and the case then ran past 100s without ever reporting the failure it had
/// already found. `cargo-mutants` killed it and reported `suite-timed-out` —
/// could-not-look (CLOUD-1267) — over a mutant 27 cases in that file do catch.
/// So the bound was never the defect; the un-stoppable watcher was.
///
/// In production the same shape swallows any panic raised inside a watched step.
struct Stop<'a>(&'a AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copies directory no case creates: the pass reads no cargo-mutants
    /// copy, so a case never frees one another suite's sweep staged
    /// (CLOUD-2789).
    fn no_copies() -> PathBuf {
        PathBuf::new()
    }

    /// Fails by: the floor's stop test inverted, so a watcher with no runtime
    /// never samples until it is stopped, and then never ends.
    #[test]
    fn the_blocking_floor_ticks_until_it_is_stopped() {
        let stop = AtomicBool::new(false);
        let mut ticks = 0;
        blocking_floor(&stop, || {
            ticks += 1;
            if ticks == 3 {
                stop.store(true, Ordering::Relaxed);
            }
        });
        assert_eq!(ticks, 3);
    }

    #[cfg(test)]
    /// THE WATCHER'S READING IS THE MEASUREMENT A GATE IS JUDGED BY (CLOUD-2781):
    /// a 0 the loop reads is the window's low-water mark, and a reset opens a new
    /// window with nothing in it.
    ///
    /// The reader signals on its SECOND call, which the loop makes only after it
    /// has observed the first, so the order is an event, never a clock.
    ///
    /// Fails by: the loop's `observe` removed (the mark never moves), or a reset
    /// that does not clear it.
    #[test]
    fn a_reading_the_watcher_takes_is_the_windows_low_water_mark() {
        use std::sync::atomic::AtomicUsize;
        let repo = crate::scratch::scratch("disk-watch-low-water");
        let config = crate::config_model::Prune {
            root: "target".to_owned(),
            keep: 2,
            warm: None,
            cold: None,
            regrowable: None,
            min_free_mb: Some(0),
            max_free_mb: Some(1),
        };
        let (second, observed) = std::sync::mpsc::channel();
        let reads = AtomicUsize::new(0);
        let watch = DiskWatch {
            repo,
            config: &config,
            free_mb: Box::new(move || {
                if reads.fetch_add(1, Ordering::SeqCst) == 1 {
                    let _ = second.send(());
                }
                Ok(0)
            }),
            kept: Vec::new(),
            copies: no_copies(),
            record: None,
        };
        reset_low_water();
        let (seen, _) = around(Some(watch), || {
            // Bounded by the event: the watcher's second reading.
            observed
                .recv_timeout(std::time::Duration::from_secs(30))
                .map(|()| low_water())
        });
        assert_eq!(
            seen.ok().flatten(),
            Some(0),
            "the loop's 0 is the window's mark"
        );
        reset_low_water();
        assert_eq!(low_water(), None, "a reset opens an empty window");
    }

    /// Fails by: a watcher printing nothing of what it watches, or printing its
    /// reader rather than naming it.
    #[test]
    fn a_watcher_debugs_its_repository_and_names_its_reader() {
        let config: crate::config_model::Prune = match serde_json::from_str("{}") {
            Ok(config) => config,
            Err(why) => panic!("an empty table: {why}"),
        };
        let watch = DiskWatch {
            repo: PathBuf::from("/repo"),
            config: &config,
            free_mb: Box::new(|| Ok(0)),
            kept: Vec::new(),
            copies: no_copies(),
            record: None,
        };
        let printed = format!("{watch:?}");
        assert!(printed.starts_with("DiskWatch {"), "{printed}");
        assert!(printed.contains("\"/repo\""), "{printed}");
        assert!(printed.contains("\"<reader>\""), "{printed}");
    }

    /// [`Stop`] sets the flag when it drops, which is what makes a panicking
    /// body end the watcher instead of hanging the join (CLOUD-2376).
    ///
    /// **ASSERTED ON THE GUARD, NOT THROUGH [`around`], AND THAT IS THE POINT.**
    /// A case that panics inside a watched body is the honest end-to-end shape,
    /// and it is unrunnable as a gate: without the guard it does not fail, it
    /// HANGS, so a runner reports could-not-look over the one mutation that
    /// matters. Measured — `drop` replaced with `()` timed the suite out at 42s
    /// rather than failing. The contract is one flag and one drop, so it is
    /// asserted where it can fail fast.
    ///
    /// The end-to-end half is covered by what the fix changed:
    /// `prune_watch::the_arm_watches_past_the_gate` under a mutated collection
    /// went from past 100s and killed, to 21.1s and failed.
    ///
    /// Fails by: a `drop` that does not store, or stores `false`.
    #[test]
    fn the_watcher_is_stopped_however_the_body_leaves() {
        let stop = AtomicBool::new(false);
        drop(Stop(&stop));
        assert!(
            stop.load(Ordering::Relaxed),
            "the guard's drop is what ends the watcher on an unwind"
        );
    }

    /// A tree another collector holds is WAITED FOR, never skipped: the
    /// watcher is the one pass with no deadline, so it is the pass that must
    /// reach the tree (#1276, where 292 skipping passes freed nothing and the
    /// lap filled the volume).
    ///
    /// The other collector's lock is released on the watcher's 200th sample,
    /// two hundred wakes after the first started the collection (CLOUD-2782) —
    /// long, in sample order, after a skipping pass has given up on the tree and
    /// returned.
    ///
    /// Fails by: the watcher's pass taking the tree with `try_lock` and
    /// skipping it when held, which leaves the stale fixture on disk.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_held_tree_is_waited_for_not_skipped() {
        use std::sync::atomic::AtomicUsize;
        let repo = crate::scratch::scratch("disk-watch-held-tree");
        let tree = repo.join("target");
        let stale = tree.join("tmp").join("old-fixture");
        std::fs::create_dir_all(&stale).expect("create the stale fixture");
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        crate::durable::open_handle(&stale)
            .expect("open the fixture")
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(then)
                    .set_modified(then),
            )
            .expect("date the fixture");
        let held = crate::durable::open_handle(&tree).expect("open the tree");
        held.lock()
            .expect("hold the tree as another collector would");
        let held = Arc::new(std::sync::Mutex::new(Some(held)));
        let config = crate::config_model::Prune {
            root: "target".to_owned(),
            keep: 2,
            warm: None,
            cold: None,
            regrowable: None,
            min_free_mb: Some(10),
            max_free_mb: Some(11),
        };
        // READINGS ARE THE EVENTS THE CASE WAITS ON, never a clock. The first
        // starts the collection; the 200th releases the other collector's lock;
        // the first reading after that which finds the fixture gone ends the
        // case, and so does the 5,000th when a skipping pass left it standing.
        let (reached, settled) = std::sync::mpsc::channel();
        let samples = AtomicUsize::new(0);
        let releaser = Arc::clone(&held);
        let probe = stale.clone();
        let watch = DiskWatch {
            repo: repo.clone(),
            config: &config,
            free_mb: Box::new(move || {
                let taken = samples.fetch_add(1, Ordering::SeqCst);
                if taken >= 200 {
                    if let Ok(mut lock) = releaser.lock() {
                        drop(lock.take());
                    }
                    if (taken > 200 && !probe.exists()) || taken == 5000 {
                        let _ = reached.send(());
                    }
                }
                Ok(if taken == 0 { 9 } else { 50 })
            }),
            kept: Vec::new(),
            copies: no_copies(),
            record: None,
        };
        let ((), lines) = around(Some(watch), || {
            // Bounded by the events above; the bound is only a backstop.
            let _ = settled.recv_timeout(std::time::Duration::from_secs(60));
        });
        assert!(!stale.exists(), "the held tree was skipped: {lines:?}");
    }

    /// A band whose floor is 10 MiB, over a scratch repository holding one
    /// stale fixture a collection removes.
    #[allow(clippy::expect_used)]
    fn stale_repo(name: &str) -> (PathBuf, PathBuf, crate::config_model::Prune) {
        let repo = crate::scratch::scratch(name);
        let stale = repo.join("target").join("tmp").join("old-fixture");
        std::fs::create_dir_all(&stale).expect("create the stale fixture");
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        crate::durable::open_handle(&stale)
            .expect("open the fixture")
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(then)
                    .set_modified(then),
            )
            .expect("date the fixture");
        let config = crate::config_model::Prune {
            root: "target".to_owned(),
            keep: 2,
            warm: None,
            cold: None,
            regrowable: None,
            min_free_mb: Some(10),
            max_free_mb: Some(11),
        };
        (repo, stale, config)
    }

    /// Every driver the watcher's runtime can be built on here: the platform's
    /// default, and on Linux the forced polling driver beside `io_uring`.
    fn drivers() -> Vec<Option<compio::driver::DriverType>> {
        if cfg!(target_os = "linux") {
            vec![
                Some(compio::driver::DriverType::IoUring),
                Some(compio::driver::DriverType::Poll),
            ]
        } else {
            vec![None]
        }
    }

    /// A watcher over `repo` whose reader yields `readings` in order, the last
    /// repeating, and whose collections are handed to `sink` as they end.
    fn series<'a>(
        repo: PathBuf,
        config: &'a crate::config_model::Prune,
        readings: Vec<u64>,
        sink: Option<RecordSink<'a>>,
    ) -> DiskWatch<'a> {
        let mut taken = 0_usize;
        DiskWatch {
            repo,
            config,
            free_mb: Box::new(move || {
                let reading = readings[taken.min(readings.len() - 1)];
                taken += 1;
                Ok(reading)
            }),
            kept: Vec::new(),
            copies: no_copies(),
            record: sink,
        }
    }

    /// A READING BELOW THE FLOOR STARTS A COLLECTION ON THAT SAMPLE, and its
    /// lines reach the record sink while the body is still running
    /// (CLOUD-2782), under every driver the runtime can take.
    ///
    /// ORDERED BY EVENTS, NEVER THE CLOCK (`tests/it/wall_clock.rs`): the body
    /// returns only once the sink has been called, so a watcher that hands its
    /// lines over at the join leaves the body waiting out its bound.
    ///
    /// Fails by: a collection whose lines are kept until `around` returns, or a
    /// sample below the floor that starts none.
    #[test]
    fn a_burst_is_collected_on_the_sample_that_crosses_the_floor() {
        for driver in drivers() {
            let (repo, stale, config) = stale_repo(&format!("disk-watch-burst-{driver:?}"));
            let (recorded, arrived) = std::sync::mpsc::channel::<Vec<String>>();
            let recorded = std::sync::Mutex::new(recorded);
            let watch = series(
                repo,
                &config,
                vec![50, 9],
                Some(Box::new(move |lines: &[String]| {
                    if let Ok(sink) = recorded.lock() {
                        let _ = sink.send(lines.to_vec());
                    }
                })),
            );
            // THE ARMED LINE REACHES THE SINK FIRST; the body waits for the
            // batch a collection hands over, the event this case is about.
            // The bound is only a backstop (CLOUD-2789): a collection whose
            // lines never reach the sink fails the case below instead of
            // holding it until the suite's timeout.
            let (live, lines) = around_on(driver, Some(watch), || {
                std::iter::from_fn(|| {
                    arrived
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .ok()
                })
                .find(|batch| batch.iter().any(|line| line.starts_with("disk-collected ")))
            });
            assert!(
                live.is_some(),
                "{driver:?}: no collection reached the record before the body returned: {lines:?}"
            );
            assert!(
                !stale.exists(),
                "{driver:?}: the fixture was not collected: {lines:?}"
            );
        }
    }

    /// A VOLUME ABOVE THE FLOOR IS NEVER COLLECTED, however many samples read it.
    ///
    /// ORDERED BY EVENTS: the reader signals on its 200th reading, and the bound
    /// is only a backstop.
    ///
    /// Fails by: the floor test inverted, so a sample above the floor starts a
    /// collection and the stale fixture goes.
    #[test]
    fn a_volume_above_the_floor_is_never_collected() {
        use std::sync::atomic::AtomicUsize;
        let (repo, stale, config) = stale_repo("disk-watch-above-floor");
        let (reached, settled) = std::sync::mpsc::channel();
        let samples = AtomicUsize::new(0);
        let watch = DiskWatch {
            repo,
            config: &config,
            free_mb: Box::new(move || {
                if samples.fetch_add(1, Ordering::SeqCst) == 200 {
                    let _ = reached.send(());
                }
                Ok(50)
            }),
            kept: Vec::new(),
            copies: no_copies(),
            record: None,
        };
        let (observed, lines) = around(Some(watch), || {
            settled
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok()
        });
        assert!(observed, "THE PREMISE: the watcher sampled: {lines:?}");
        assert!(stale.exists(), "collected above the floor: {lines:?}");
    }

    /// THE WATCHER NAMES HOW IT IS WOKEN (CLOUD-2782): one armed line with the
    /// source and the period, and the errno when the filesystem mark was
    /// refused. It is what a reader of the record checks the wake against.
    ///
    /// Fails by: no armed line, a period other than 1 ms, or a timer-only watcher
    /// on Linux that does not say why the mark was refused.
    #[test]
    fn the_watcher_arms_its_wake_source_and_period() {
        for driver in drivers() {
            let (repo, _stale, config) = stale_repo(&format!("disk-watch-armed-{driver:?}"));
            let watch = series(repo, &config, vec![50], None);
            let ((), lines) = around_on(driver, Some(watch), || ());
            let armed: Vec<&String> = lines
                .iter()
                .filter(|line| line.starts_with("disk-watch-armed "))
                .collect();
            assert_eq!(armed.len(), 1, "{driver:?}: one armed line: {lines:?}");
            let armed = armed[0];
            assert!(armed.contains(" period-us=1000"), "{armed}");
            let fanotify = armed.contains(" source=fanotify");
            let refused = armed.contains(" source=timer") && armed.contains(" errno=");
            if cfg!(target_os = "linux") {
                assert!(fanotify || refused, "{armed}");
            } else {
                assert!(armed.contains(" source=timer"), "{armed}");
            }
        }
    }

    /// THE ACHIEVED PERIOD IS MEASURED ON EVERY LEG THAT RUNS THE SUITE, AND
    /// RECORDED, NEVER ASSERTED (CLOUD-2782; `tests/it/wall_clock.rs`): the p99
    /// gap between a thousand consecutive samples is printed, which is the number
    /// the row's runtime decision is checked against on each platform.
    ///
    /// The assertion is on the count of samples, an event: a watcher that stops
    /// sampling after its first wake never reaches it.
    #[test]
    fn the_achieved_period_is_measured() {
        use std::io::Write as _;
        const SAMPLES: usize = 1000;
        let (repo, _stale, config) = stale_repo("disk-watch-period");
        let stamps = Arc::new(std::sync::Mutex::new(Vec::with_capacity(SAMPLES)));
        let samples = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (full, filled) = std::sync::mpsc::channel();
        let (taken, counted) = (Arc::clone(&stamps), Arc::clone(&samples));
        let watch = DiskWatch {
            repo,
            config: &config,
            free_mb: Box::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut stamps) = taken.lock()
                    && stamps.len() < SAMPLES
                {
                    stamps.push(std::time::Instant::now());
                    if stamps.len() == SAMPLES {
                        let _ = full.send(());
                    }
                }
                Ok(50)
            }),
            kept: Vec::new(),
            copies: no_copies(),
            record: None,
        };
        let ((), _) = around(Some(watch), || {
            let _ = filled.recv_timeout(std::time::Duration::from_secs(120));
        });
        let stamps = stamps
            .lock()
            .map(|stamps| stamps.clone())
            .unwrap_or_default();
        let mut gaps: Vec<u128> = stamps
            .windows(2)
            .map(|pair| pair[1].duration_since(pair[0]).as_micros())
            .collect();
        gaps.sort_unstable();
        let p99 = gaps.get(gaps.len() * 99 / 100).copied().unwrap_or_default();
        let _ = writeln!(
            std::io::stderr(),
            "disk-watch-period samples={} p50-us={} p99-us={p99}",
            stamps.len(),
            gaps.get(gaps.len() / 2).copied().unwrap_or_default()
        );
        let taken = samples.load(Ordering::SeqCst);
        assert!(
            taken >= SAMPLES,
            "the watcher stopped sampling after {taken}"
        );
    }

    /// A FILESYSTEM MARK REPORTS FILE IDS, NOT FILE DESCRIPTORS (CLOUD-2782):
    /// without `FAN_REPORT_FID` every event hands the reader an open descriptor,
    /// and a build's flood of writes would exhaust the table.
    ///
    /// Where the group is refused (no `CAP_SYS_ADMIN`, as on a CI runner), the
    /// refusal is the answer and the errno names it; where it arms, a thousand
    /// writes are drained and the process holds exactly the descriptors it held
    /// before.
    ///
    /// Fails by: a group opened without `FAN_REPORT_FID`, or a drain that never
    /// reads an event.
    ///
    /// COMPILED ON EVERY TARGET: off Linux the mark is refused, and that
    /// refusal is the case's answer there.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_fanotify_wake_leaves_no_descriptor_open() {
        use std::io::Write as _;
        let dir = crate::scratch::scratch("disk-watch-fid");
        // BOTH BRANCHES ASSERT AND NEITHER RETURNS EARLY (`silent_skip`): a
        // refused mark is answered by its errno, an armed one by the drain.
        match fanotify::arm(&dir) {
            // ONLY A HOST'S OWN REFUSAL: no privilege, or no mark. A mark
            // this code built wrong is `EINVAL`, and fails here.
            Err(errno) => assert!(
                ["EPERM", "EACCES", "ENOSYS", "EOPNOTSUPP"].contains(&errno.as_str()),
                "a refusal names the host's errno: {errno}"
            ),
            Ok(group) => {
                let open = || {
                    std::fs::read_dir("/proc/self/fd")
                        .map(Iterator::count)
                        .expect("list fds")
                };
                let before = open();
                for name in ["written", "also"] {
                    let mut file = std::fs::File::create(dir.join(name)).expect("create");
                    for _ in 0..1000 {
                        file.write_all(b"x").expect("write");
                    }
                }
                let drained = fanotify::drain(&group);
                assert!(drained >= 2, "two files, two events at least: {drained}");
                assert_eq!(open(), before, "an event left a descriptor open");
            }
        }
    }

    /// Fails by: the second wait never driven (the first, waiting on it,
    /// never ends), or driven again once it finished.
    #[test]
    fn the_first_wait_ends_it_and_the_second_is_driven_once() {
        use std::cell::Cell;
        let ran = Cell::new(false);
        let polls = Cell::new(0);
        let first = std::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            if ran.get() && polls.get() >= 3 {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        });
        let second = async {
            ran.set(true);
        };
        let mut both = std::pin::pin!(until_first(first, second));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..2 {
            assert!(both.as_mut().poll(&mut cx).is_pending());
        }
        assert!(both.as_mut().poll(&mut cx).is_ready(), "the first ends it");
        assert!(ran.get(), "the second was driven");
    }

    /// Fails by: the done-guard joined by `||`, so the second wait is skipped on
    /// the first poll and then polled again after it finished.
    #[test]
    fn the_second_wait_is_driven_on_the_first_poll_and_never_after() {
        use std::cell::Cell;
        let polled = Cell::new(0);
        let first = std::future::poll_fn(|_| std::task::Poll::<()>::Pending);
        let second = std::future::poll_fn(|_| {
            polled.set(polled.get() + 1);
            std::task::Poll::Ready(())
        });
        let mut both = std::pin::pin!(until_first(first, second));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(both.as_mut().poll(&mut cx).is_pending());
        assert_eq!(polled.get(), 1, "driven on the first poll");
        for _ in 0..3 {
            assert!(both.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(polled.get(), 1, "never driven again once it finished");
    }
}
